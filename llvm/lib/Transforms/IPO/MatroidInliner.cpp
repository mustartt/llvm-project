//===- MatroidInliner.cpp - Matroid-based global inliner ------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// A module-level inliner that uses a partition matroid with per-function growth
// budgets to prevent exponential inlining blowup. Operates on the whole module
// call graph, not per-SCC, so it avoids CG update complexity.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/IPO/Inliner.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/BlockFrequencyInfo.h"
#include "llvm/Analysis/EphemeralValuesCache.h"
#include "llvm/Analysis/InlineCost.h"
#include "llvm/Analysis/OptimizationRemarkEmitter.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/Utils/Cloning.h"

using namespace llvm;

#define DEBUG_TYPE "matroid-inline"

STATISTIC(NumMatroidInlined, "Number of functions inlined by matroid inliner");
STATISTIC(NumMatroidRejected,
          "Number of call sites rejected by matroid budget");

static cl::opt<bool> EnableMatroidInliner(
    "enable-matroid-inliner", cl::init(false), cl::Hidden,
    cl::desc("Enable matroid-based module-level inliner"));

static cl::opt<float> MatroidGrowthFactor(
    "matroid-inline-growth", cl::init(3.0), cl::Hidden, cl::value_desc("x"),
    cl::desc("Per-function growth budget as multiple of original size"));

static cl::opt<int> MatroidInlineThreshold(
    "matroid-inline-threshold", cl::init(225), cl::Hidden, cl::value_desc("N"),
    cl::desc("Inline cost threshold for matroid inliner (independent of "
             "-inline-threshold). Use to keep matroid decisions stable when "
             "adjusting the CGSCC threshold."));

namespace {
struct InlineCandidate {
  CallBase *CB;
  Function *Caller;
  Function *Callee;
  int CostDelta; // Threshold - Cost (from InlineCost)
  unsigned CalleeSize;
  bool AlwaysInline;
};
} // namespace

PreservedAnalyses MatroidInlinerPass::run(Module &M,
                                          ModuleAnalysisManager &MAM) {
  if (!EnableMatroidInliner)
    return PreservedAnalyses::all();

  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto *PSI = MAM.getCachedResult<ProfileSummaryAnalysis>(M);

  // Use our own threshold, independent of -inline-threshold.
  InlineParams Params = getInlineParams();
  Params.DefaultThreshold = MatroidInlineThreshold;

  auto GetAssumptionCache = [&](Function &F) -> AssumptionCache & {
    return FAM.getResult<AssumptionAnalysis>(F);
  };
  auto GetTLI = [&](Function &F) -> const TargetLibraryInfo & {
    return FAM.getResult<TargetLibraryAnalysis>(F);
  };
  auto GetBFI = [&](Function &F) -> BlockFrequencyInfo & {
    return FAM.getResult<BlockFrequencyAnalysis>(F);
  };
  auto GetEVC = [&](Function &F) -> EphemeralValuesCache & {
    return FAM.getResult<EphemeralValuesAnalysis>(F);
  };

  // Step 1: Record original function sizes.
  DenseMap<Function *, unsigned> OriginalSize;
  DenseMap<Function *, unsigned> GrowthSoFar;
  for (Function &F : M) {
    if (!F.isDeclaration()) {
      OriginalSize[&F] = F.getInstructionCount();
      GrowthSoFar[&F] = 0;
    }
  }

  auto GetBudget = [&](Function *F) -> unsigned {
    unsigned Orig = OriginalSize.lookup(F);
    if (Orig == 0) Orig = 1;
    return static_cast<unsigned>(Orig * MatroidGrowthFactor);
  };

  // Step 2: Collect all call sites and evaluate with InlineCost.
  std::vector<InlineCandidate> Candidates;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    for (Instruction &I : instructions(F)) {
      auto *CB = dyn_cast<CallBase>(&I);
      if (!CB)
        continue;
      Function *Callee = CB->getCalledFunction();
      if (!Callee || Callee->isDeclaration())
        continue;

      auto &CalleeTTI = FAM.getResult<TargetIRAnalysis>(*Callee);
      InlineCost IC = getInlineCost(*CB, Callee, Params, CalleeTTI,
                                     GetAssumptionCache, GetTLI, GetBFI,
                                     PSI, nullptr, GetEVC);
      if (IC.isNever())
        continue;

      unsigned CalleeSize = Callee->getInstructionCount();
      int CostDelta;
      bool Always = false;
      if (IC.isAlways()) {
        CostDelta = 100000; // Very high priority
        Always = true;
      } else {
        CostDelta = IC.getCostDelta();
        if (CostDelta <= 0)
          continue;
      }

      Candidates.push_back(
          InlineCandidate{CB, &F, Callee, CostDelta, CalleeSize, Always});
    }
  }

  LLVM_DEBUG(dbgs() << "[MatroidInline] " << Candidates.size()
                    << " candidates across module\n");

  // Step 3: Sort by benefit (CostDelta) descending — greedy order.
  llvm::sort(Candidates, [](const InlineCandidate &A,
                             const InlineCandidate &B) {
    return A.CostDelta > B.CostDelta;
  });

  // Step 4: Greedy with per-function growth budget.
  bool Changed = false;
  SmallPtrSet<Function *, 16> DeadFunctions;

  for (auto &Cand : Candidates) {
    // Skip if callee was deleted.
    if (DeadFunctions.count(Cand.Callee))
      continue;
    // Verify call site still targets expected callee.
    if (Cand.CB->getCalledFunction() != Cand.Callee)
      continue;

    // Per-caller growth budget (partition matroid constraint).
    unsigned Growth = GrowthSoFar.lookup(Cand.Caller);
    unsigned Budget = GetBudget(Cand.Caller);
    if (!Cand.AlwaysInline && Growth + Cand.CalleeSize > Budget) {
      ++NumMatroidRejected;
      auto &ORE = FAM.getResult<OptimizationRemarkEmitterAnalysis>(*Cand.Caller);
      using namespace ore;
      ORE.emit([&]() {
        return OptimizationRemarkMissed(DEBUG_TYPE, "BudgetExceeded", Cand.CB)
               << NV("Callee", Cand.Callee)
               << " not inlined into "
               << NV("Caller", Cand.Caller)
               << " (growth " << NV("Growth", Growth)
               << " + " << NV("CalleeSize", Cand.CalleeSize)
               << " exceeds budget " << NV("Budget", Budget) << ")";
      });
      continue;
    }

    // Inline.
    InlineFunctionInfo IFI(GetAssumptionCache, PSI);
    InlineResult IR = InlineFunction(*Cand.CB, IFI, /*MergeAttributes=*/true);
    if (!IR.isSuccess())
      continue;

    Changed = true;
    GrowthSoFar[Cand.Caller] += Cand.CalleeSize;
    ++NumMatroidInlined;

    {
      auto &ORE = FAM.getResult<OptimizationRemarkEmitterAnalysis>(*Cand.Caller);
      using namespace ore;
      ORE.emit([&]() {
        return OptimizationRemark(DEBUG_TYPE, "Inlined", Cand.Caller)
               << NV("Callee", Cand.Callee)
               << " inlined into "
               << NV("Caller", Cand.Caller)
               << " (cost delta " << NV("CostDelta", Cand.CostDelta)
               << ", size " << NV("CalleeSize", Cand.CalleeSize)
               << ", growth " << NV("Growth", GrowthSoFar[Cand.Caller])
               << "/" << NV("Budget", Budget) << ")";
      });
    }

    LLVM_DEBUG(dbgs() << "[MatroidInline] Inlined " << Cand.Callee->getName()
                      << " into " << Cand.Caller->getName()
                      << " (delta=" << Cand.CostDelta
                      << " size=" << Cand.CalleeSize
                      << " growth=" << GrowthSoFar[Cand.Caller]
                      << "/" << Budget << ")\n");

    // Track dead callees.
    if (Cand.Callee->isDiscardableIfUnused() &&
        Cand.Callee->hasZeroLiveUses()) {
      DeadFunctions.insert(Cand.Callee);
    }
  }

  // Delete dead functions.
  for (Function *F : DeadFunctions) {
    F->eraseFromParent();
  }

  LLVM_DEBUG(dbgs() << "[MatroidInline] Done: " << NumMatroidInlined
                    << " inlined, " << NumMatroidRejected
                    << " rejected by budget\n");

  if (!Changed)
    return PreservedAnalyses::all();

  return PreservedAnalyses::none();
}
