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

  // Step 2-4: Iterative inline rounds.
  // Each round: collect candidates, evaluate InlineCost, sort by benefit,
  // greedily inline within budget. New call sites from inlining become
  // candidates in the next round (with decayed benefit).
  bool Changed = false;
  SmallPtrSet<Function *, 16> DeadFunctions;
  constexpr unsigned MaxRounds = 4;
  constexpr float TransitiveDecay = 0.7f;

  auto CollectCandidates = [&](SmallVectorImpl<Function *> *OnlyFunctions,
                               float BenefitMultiplier)
      -> std::vector<InlineCandidate> {
    std::vector<InlineCandidate> Candidates;
    auto Process = [&](Function &F) {
      if (F.isDeclaration() || DeadFunctions.count(&F))
        return;
      for (Instruction &I : instructions(F)) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (!CB)
          continue;
        Function *Callee = CB->getCalledFunction();
        if (!Callee || Callee->isDeclaration() || DeadFunctions.count(Callee))
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
          CostDelta = 100000;
          Always = true;
        } else {
          CostDelta = IC.getCostDelta();
          if (CostDelta <= 0)
            continue;
        }

        // Submodular growth discount: benefit decreases as caller grows.
        unsigned Growth = GrowthSoFar.lookup(&F);
        unsigned Budget = GetBudget(&F);
        float GrowthPressure =
            1.0f / (1.0f + static_cast<float>(Growth) /
                               static_cast<float>(std::max(Budget, 1u)));
        float Benefit = static_cast<float>(CostDelta) * GrowthPressure *
                        BenefitMultiplier;

        Candidates.push_back(
            InlineCandidate{CB, &F, Callee, CostDelta, CalleeSize, Always});
        // Store adjusted benefit in CostDelta for sorting.
        Candidates.back().CostDelta = static_cast<int>(Benefit);
      }
    };

    if (OnlyFunctions) {
      for (Function *F : *OnlyFunctions)
        Process(*F);
    } else {
      for (Function &F : M)
        Process(F);
    }
    return Candidates;
  };

  auto RunGreedy = [&](std::vector<InlineCandidate> &Candidates) -> unsigned {
    // Sort by adjusted benefit descending.
    llvm::sort(Candidates, [](const InlineCandidate &A,
                               const InlineCandidate &B) {
      return A.CostDelta > B.CostDelta;
    });

    unsigned Inlined = 0;
    SmallVector<Function *, 16> ModifiedCallers;

    for (auto &Cand : Candidates) {
      if (DeadFunctions.count(Cand.Callee))
        continue;
      if (Cand.CB->getCalledFunction() != Cand.Callee)
        continue;

      unsigned Growth = GrowthSoFar.lookup(Cand.Caller);
      unsigned Budget = GetBudget(Cand.Caller);
      if (!Cand.AlwaysInline && Growth + Cand.CalleeSize > Budget) {
        ++NumMatroidRejected;
        continue;
      }

      InlineFunctionInfo IFI(GetAssumptionCache, PSI);
      InlineResult IR =
          InlineFunction(*Cand.CB, IFI, /*MergeAttributes=*/true);
      if (!IR.isSuccess())
        continue;

      Changed = true;
      GrowthSoFar[Cand.Caller] += Cand.CalleeSize;
      ++NumMatroidInlined;
      ++Inlined;

      // Track modified callers for next round's transitive discovery.
      ModifiedCallers.push_back(Cand.Caller);

      LLVM_DEBUG(dbgs() << "[MatroidInline] Inlined " << Cand.Callee->getName()
                        << " into " << Cand.Caller->getName()
                        << " (delta=" << Cand.CostDelta
                        << " size=" << Cand.CalleeSize
                        << " growth=" << GrowthSoFar[Cand.Caller]
                        << "/" << Budget << ")\n");

      if (Cand.Callee->isDiscardableIfUnused() &&
          Cand.Callee->hasZeroLiveUses()) {
        DeadFunctions.insert(Cand.Callee);
      }
    }
    return Inlined;
  };

  // Round 0: All call sites in the module.
  {
    auto Candidates = CollectCandidates(nullptr, 1.0f);
    LLVM_DEBUG(dbgs() << "[MatroidInline] Round 0: " << Candidates.size()
                      << " candidates\n");
    RunGreedy(Candidates);
  }

  // Rounds 1..N: Re-evaluate modified callers for transitive opportunities.
  // After inlining, the caller has new code that may contain new call sites
  // worth inlining. This mimics the CGSCC's worklist re-evaluation.
  for (unsigned Round = 1; Round <= MaxRounds; ++Round) {
    // Collect only from functions that were modified (grew from inlining).
    SmallVector<Function *, 16> ModifiedFuncs;
    for (auto &[F, Growth] : GrowthSoFar) {
      if (Growth > 0 && !DeadFunctions.count(F))
        ModifiedFuncs.push_back(F);
    }
    if (ModifiedFuncs.empty())
      break;

    float Decay = std::pow(TransitiveDecay, static_cast<float>(Round));
    auto Candidates = CollectCandidates(&ModifiedFuncs, Decay);
    if (Candidates.empty())
      break;

    LLVM_DEBUG(dbgs() << "[MatroidInline] Round " << Round << ": "
                      << Candidates.size()
                      << " candidates (decay=" << Decay << ")\n");
    unsigned NewInlines = RunGreedy(Candidates);
    if (NewInlines == 0)
      break;
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
