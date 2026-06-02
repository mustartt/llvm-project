//===- InstrProfToPseudoProbe.cpp - Rewrite InstrProf as PseudoProbes -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This pass rewrites clang-emitted coverage counter intrinsics
// (llvm.instrprof.increment, llvm.instrprof.cover) into llvm.pseudoprobe
// calls so coverage hit data can be derived from sample-based profile sources
// (e.g. llvm-profgen) rather than the InstrProf runtime.
//
// The mapping is:
//   instrprof.increment(@__profn_F, hash, _, idx)
//     -> pseudoprobe(MD5(linkage_name(F)), idx + 1, 0, FullDistributionFactor)
//
// The probe id is `idx + 1` because PseudoProbe ids are 1-based (id 0 is
// reserved). The bijection with the original counter id is preserved.
//
// A llvm.pseudo_probe_desc entry is added for every rewritten function,
// reusing the CFG hash from the increment intrinsic as the function hash.
//
// This pass expects only counter-shaped intrinsics; it asserts on
// value-profile / callsite / timestamp / MCDC variants. Clang under
// -fcoverage-via-pseudo-probe will not emit those.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Instrumentation/InstrProfToPseudoProbe.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PseudoProbe.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"

using namespace llvm;

#define DEBUG_TYPE "instrprof-to-pseudo-probe"

namespace {

/// Resolve the function name to hash into a GUID, matching the convention
/// used by SampleProfileProbe so downstream tooling sees consistent ids.
StringRef getProbeLinkageName(const Function &F) {
  if (auto *SP = F.getSubprogram()) {
    StringRef LN = SP->getLinkageName();
    if (!LN.empty())
      return LN;
    StringRef N = SP->getName();
    if (!N.empty())
      return N;
  }
  return F.getName();
}

/// Pick a debug location for a synthesized probe. Prefer the original
/// intrinsic's location; otherwise synthesize an artificial line attached to
/// the function's subprogram so the probe still gets an inline context.
DebugLoc pickProbeDebugLoc(const CallInst &Orig, const Function &F) {
  if (DebugLoc DL = Orig.getDebugLoc())
    return DL;
  if (auto *SP = F.getSubprogram())
    return DILocation::get(SP->getContext(), 0, 0, SP);
  return DebugLoc();
}

/// Rewrite all instrprof counter intrinsics in F into pseudoprobe calls.
/// Returns true if F was modified. On return, *FunctionHash is set to the
/// CFG hash recovered from the intrinsics (only valid when this returned
/// true).
bool rewriteFunction(Function &F, uint64_t &FunctionHash,
                     SmallPtrSetImpl<GlobalVariable *> &TouchedNameGVs) {
  SmallVector<CallInst *, 16> ToErase;
  uint64_t Hash = 0;
  bool HaveHash = false;

  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {
      auto *Call = dyn_cast<CallInst>(&I);
      if (!Call)
        continue;
      Function *Callee = Call->getCalledFunction();
      if (!Callee || !Callee->isIntrinsic())
        continue;

      switch (Callee->getIntrinsicID()) {
      case Intrinsic::instrprof_increment:
      case Intrinsic::instrprof_increment_step:
      case Intrinsic::instrprof_cover:
        // increment_step carries an extra step value used to count loop
        // iterations. For coverage we only care whether the region executed,
        // so the step is dropped and the call is rewritten the same way as
        // a plain increment.
        ToErase.push_back(Call);
        break;
      case Intrinsic::instrprof_callsite:
      case Intrinsic::instrprof_timestamp:
      case Intrinsic::instrprof_value_profile:
      case Intrinsic::instrprof_mcdc_parameters:
      case Intrinsic::instrprof_mcdc_tvbitmap_update:
        report_fatal_error(
            "InstrProfToPseudoProbe: unexpected instrprof intrinsic; "
            "-fcoverage-via-pseudo-probe should not emit value-profile, "
            "MCDC, callsite, or timestamp intrinsics");
      default:
        break;
      }
    }
  }

  if (ToErase.empty())
    return false;

  uint64_t Guid =
      Function::getGUIDAssumingExternalLinkage(getProbeLinkageName(F));
  Module *M = F.getParent();
  Function *ProbeFn =
      Intrinsic::getOrInsertDeclaration(M, Intrinsic::pseudoprobe);

  for (CallInst *Orig : ToErase) {
    auto *Cntr = cast<InstrProfCntrInstBase>(Orig);
    uint64_t CFGHash = Cntr->getHash()->getZExtValue();
    if (!HaveHash) {
      Hash = CFGHash;
      HaveHash = true;
    } else {
      assert(Hash == CFGHash &&
             "all instrprof intrinsics in a function share the CFG hash");
    }

    if (auto *NameGV =
            dyn_cast<GlobalVariable>(Cntr->getNameValue()))
      TouchedNameGVs.insert(NameGV);

    uint64_t ProbeId = Cntr->getIndex()->getZExtValue() + 1;

    IRBuilder<> B(Orig);
    Value *Args[] = {
        B.getInt64(Guid),
        B.getInt64(ProbeId),
        B.getInt32(0),
        B.getInt64(PseudoProbeFullDistributionFactor),
    };
    CallInst *Probe = B.CreateCall(ProbeFn, Args);
    Probe->setDebugLoc(pickProbeDebugLoc(*Orig, F));
    Orig->eraseFromParent();
  }

  FunctionHash = Hash;
  return true;
}

} // end anonymous namespace

PreservedAnalyses InstrProfToPseudoProbePass::run(Module &M,
                                                  ModuleAnalysisManager &AM) {
  NamedMDNode *ProbeDescNMD =
      M.getOrInsertNamedMetadata(PseudoProbeDescMetadataName);
  MDBuilder MDB(M.getContext());

  SmallPtrSet<GlobalVariable *, 16> TouchedNameGVs;
  bool Changed = false;

  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    uint64_t FunctionHash = 0;
    if (!rewriteFunction(F, FunctionHash, TouchedNameGVs))
      continue;

    Changed = true;
    StringRef FName = getProbeLinkageName(F);
    uint64_t Guid = Function::getGUIDAssumingExternalLinkage(FName);
    ProbeDescNMD->addOperand(
        MDB.createPseudoProbeDesc(Guid, FunctionHash, FName));
  }

  // After rewriting, the @__profn_* globals are typically dead. Erase any
  // that became unused. Leaving them isn't a correctness problem -- they'd
  // be cleaned up by globaldce -- but stripping them here keeps the IR
  // self-contained for the case where we skip InstrProfilingLoweringPass
  // entirely.
  for (GlobalVariable *GV : TouchedNameGVs) {
    if (GV->use_empty())
      GV->eraseFromParent();
  }

  if (!Changed)
    return PreservedAnalyses::all();

  // We only added probe calls and (possibly) a named metadata entry. CFG
  // and analysis caches are unaffected, but we touched the IR, so be
  // conservative.
  return PreservedAnalyses::none();
}
