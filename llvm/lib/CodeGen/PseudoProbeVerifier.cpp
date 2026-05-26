//===- PseudoProbeVerifier.cpp - Verify pseudo probe annotations ----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements PseudoProbeVerifier, a MachineFunctionPass that
// verifies pseudo probe annotations after PseudoProbeInserter has run. Its
// initial purpose is to detect tail-call instructions that are missing an
// associated call probe.
//
//===----------------------------------------------------------------------===//

#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PseudoProbe.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"

#define DEBUG_TYPE "pseudo-probe-verifier"

using namespace llvm;

namespace {

// Returns true if MI is a PSEUDO_PROBE whose type marks it as a call probe
// (DirectCall or IndirectCall).
static bool isCallProbe(const MachineInstr &MI) {
  if (MI.getOpcode() != TargetOpcode::PSEUDO_PROBE)
    return false;
  uint64_t Type = MI.getOperand(2).getImm();
  return Type == static_cast<uint64_t>(PseudoProbeType::DirectCall) ||
         Type == static_cast<uint64_t>(PseudoProbeType::IndirectCall);
}

class PseudoProbeVerifier : public MachineFunctionPass {
public:
  static char ID;

  PseudoProbeVerifier() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override { return "Pseudo Probe Verifier"; }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesAll();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool doInitialization(Module &M) override {
    ShouldRun = M.getNamedMetadata(PseudoProbeDescMetadataName);
    return false;
  }

  bool runOnMachineFunction(MachineFunction &MF) override {
    if (!ShouldRun)
      return false;

    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {
        // Tail-call pseudos (TAILJMP* on X86, TCRETURN* on AArch64) are both
        // calls and returns; that combination uniquely identifies them.
        if (!(MI.isCall() && MI.isReturn()))
          continue;

        // Walk backward, skipping meta instructions other than PSEUDO_PROBE
        // (DBG_VALUE, CFI_INSTRUCTION, etc.). The call probe, if present,
        // should be the immediately preceding PSEUDO_PROBE.
        bool HasCallProbe = false;
        auto It = MI.getIterator();
        while (It != MBB.begin()) {
          --It;
          if (It->getOpcode() == TargetOpcode::PSEUDO_PROBE) {
            HasCallProbe = isCallProbe(*It);
            break;
          }
          // A non-meta instruction means any earlier probe is for a
          // different statement, not this tail call.
          if (!It->isMetaInstruction())
            break;
        }

        if (HasCallProbe)
          continue;

        WithColor::warning(errs())
            << "tail call missing pseudo probe in function '" << MF.getName()
            << "'";
        if (const DebugLoc &DL = MI.getDebugLoc())
          errs() << " at " << DL->getFilename() << ":" << DL->getLine();
        errs() << "\n";
        MBB.print(errs());
      }
    }

    return false;
  }

private:
  bool ShouldRun = false;
};

} // namespace

char PseudoProbeVerifier::ID = 0;
INITIALIZE_PASS_BEGIN(PseudoProbeVerifier, DEBUG_TYPE,
                      "Verify pseudo probe annotations", false, false)
INITIALIZE_PASS_DEPENDENCY(TargetPassConfig)
INITIALIZE_PASS_END(PseudoProbeVerifier, DEBUG_TYPE,
                    "Verify pseudo probe annotations", false, false)

FunctionPass *llvm::createPseudoProbeVerifier() {
  return new PseudoProbeVerifier();
}
