//===- MachineBlockProfileLoader.cpp --------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Reads a MachineBlock-keyed edge-frequency profile from a text file and
// applies it as MBB successor probabilities, so that downstream MIR layout
// passes (MachineBlockPlacement, BranchFolder, TailDuplicate) consume
// frequencies derived from actual post-ISel MBB execution counts.
//
// Profile file format (text, line-based):
//
//   # Comments begin with '#'.
//   func_name:<cfg_hash>:
//     <src_probe_id>:<dst_probe_id>:<freq>
//     <src_probe_id>:<dst_probe_id>:<freq>
//   another_func:<cfg_hash>:
//     ...
//
// Function headers are flush-left, name and decimal CFG hash separated by
// ':' and ending with a trailing ':'. Edge lines are indented. The CFG
// hash is checked against the function's `llvm.pseudo_probe_desc` entry
// (the same hash used by IR-level pseudoprobe staleness detection); on
// mismatch the profile entry for that function is dropped and the pass
// falls back to whatever frequencies the existing analyses computed.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineBlockFrequencyInfo.h"
#include "llvm/CodeGen/MachineBranchProbabilityInfo.h"
#include "llvm/CodeGen/MachineDominators.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineLoopInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PseudoProbe.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/BranchProbability.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

#define DEBUG_TYPE "machine-block-profile-loader"

using namespace llvm;

static cl::opt<std::string> MachineBlockProfileFile(
    "machine-block-profile-file", cl::Hidden, cl::init(""),
    cl::desc("Path to a MachineBlock-keyed text profile applied as MBB "
             "successor probabilities."));

namespace {

struct EdgeCount {
  uint32_t SrcId;
  uint32_t DstId;
  uint64_t Freq;
};

struct FunctionProfile {
  uint64_t CFGHash = 0;
  SmallVector<EdgeCount, 8> Edges;
};

class MachineBlockProfileLoader : public MachineFunctionPass {
public:
  static char ID;

  MachineBlockProfileLoader() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "Machine Block Profile Loader";
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<MachineBranchProbabilityInfoWrapperPass>();
    AU.addRequired<MachineLoopInfoWrapperPass>();
    AU.addRequired<MachineDominatorTreeWrapperPass>();
    AU.addRequired<MachineBlockFrequencyInfoWrapperPass>();
    AU.addPreserved<MachineLoopInfoWrapperPass>();
    AU.addPreserved<MachineDominatorTreeWrapperPass>();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool doInitialization(Module &M) override {
    if (MachineBlockProfileFile.empty())
      return false;
    if (!loadProfile(MachineBlockProfileFile))
      return false;
    // Build name -> MIR CFG hash from llvm.machine_pseudo_probe_desc, which
    // is populated by MachineBlockProbeInserter at probe-insertion time.
    // We deliberately read the MIR-CFG-keyed descriptor (not the IR-level
    // one): MIR-only divergence between builds is exactly what we want
    // staleness detection to catch here. The metadata is populated lazily
    // (per function) by the inserter, so each runOnMachineFunction call
    // re-reads it; nothing to do at module init.
    return false;
  }

  bool runOnMachineFunction(MachineFunction &MF) override {
    if (!Loaded)
      return false;

    auto It = FunctionProfiles.find(MF.getName());
    if (It == FunctionProfiles.end())
      return false;

    // Look up the MIR CFG hash that the inserter recorded for this
    // function. Reading per-call (rather than caching at module init) is
    // intentional: the inserter populates the descriptor lazily as it
    // visits each function, so the named metadata is built up over the
    // course of the pipeline.
    uint64_t ModuleHash = 0;
    if (!findMIRCFGHash(MF, ModuleHash)) {
      // No MachineBlock descriptor for this function — the inserter didn't
      // run on it (e.g. flag was off in this build). Skip rather than
      // apply the profile blindly.
      return false;
    }
    if (ModuleHash != It->second.CFGHash) {
      LLVM_DEBUG(dbgs() << "machine-block-profile-loader: skipping '"
                        << MF.getName() << "' (MIR CFG hash mismatch: profile="
                        << It->second.CFGHash << " module=" << ModuleHash
                        << ")\n");
      return false;
    }

    // Build probe-id -> MBB map by scanning each MBB for a MachineBlock-
    // typed PSEUDO_PROBE. The pass requires MachineBlockProbeInserter to
    // have run earlier in the pipeline.
    DenseMap<uint32_t, MachineBasicBlock *> ProbeIdToMBB;
    for (MachineBasicBlock &MBB : MF) {
      for (MachineInstr &MI : MBB) {
        if (!MI.isPseudoProbe())
          continue;
        // Operand layout: GUID, Index, Type, Attr.
        uint8_t Type = MI.getOperand(2).getImm();
        if (Type != static_cast<uint8_t>(PseudoProbeType::MachineBlock))
          continue;
        uint32_t ProbeId = MI.getOperand(1).getImm();
        ProbeIdToMBB[ProbeId] = &MBB;
        break;
      }
    }

    // Sum profile edge frequencies per (src, dst) MBB pair.
    DenseMap<std::pair<MachineBasicBlock *, MachineBasicBlock *>, uint64_t>
        EdgeFreq;
    for (const EdgeCount &E : It->second.Edges) {
      auto SrcIt = ProbeIdToMBB.find(E.SrcId);
      auto DstIt = ProbeIdToMBB.find(E.DstId);
      if (SrcIt == ProbeIdToMBB.end() || DstIt == ProbeIdToMBB.end())
        continue;
      EdgeFreq[{SrcIt->second, DstIt->second}] += E.Freq;
    }

    // Apply each MBB's successor probabilities from the observed counts.
    bool Changed = false;
    for (MachineBasicBlock &MBB : MF) {
      uint64_t TotalOut = 0;
      for (MachineBasicBlock *Succ : MBB.successors())
        TotalOut += EdgeFreq.lookup({&MBB, Succ});
      if (TotalOut == 0)
        continue;

      for (auto SI = MBB.succ_begin(), SE = MBB.succ_end(); SI != SE; ++SI) {
        uint64_t Count = EdgeFreq.lookup({&MBB, *SI});
        BranchProbability NewProb(Count, TotalOut);
        MBB.setSuccProbability(SI, NewProb);
      }
      Changed = true;
    }

    if (Changed) {
      // Recompute frequencies so MBFI consumers see the profile-derived
      // values rather than the static estimates.
      auto &MBPI =
          getAnalysis<MachineBranchProbabilityInfoWrapperPass>().getMBPI();
      auto &MLI = getAnalysis<MachineLoopInfoWrapperPass>().getLI();
      auto &MBFI =
          getAnalysis<MachineBlockFrequencyInfoWrapperPass>().getMBFI();
      MBFI.calculate(MF, MBPI, MLI);
    }
    return Changed;
  }

private:
  bool Loaded = false;
  StringMap<FunctionProfile> FunctionProfiles;

  // Find the MIR-level CFG hash for MF in llvm.machine_pseudo_probe_desc.
  // Returns true and writes the hash into Out on success.
  static bool findMIRCFGHash(const MachineFunction &MF, uint64_t &Out) {
    const Module *M = MF.getFunction().getParent();
    NamedMDNode *Desc =
        M->getNamedMetadata(MachinePseudoProbeDescMetadataName);
    if (!Desc)
      return false;
    StringRef Name = MF.getName();
    for (const MDNode *MD : Desc->operands()) {
      if (MD->getNumOperands() < 3)
        continue;
      auto *NameMD = dyn_cast<MDString>(MD->getOperand(2));
      if (!NameMD || NameMD->getString() != Name)
        continue;
      auto *HashC = mdconst::dyn_extract<ConstantInt>(MD->getOperand(1));
      if (!HashC)
        return false;
      Out = HashC->getZExtValue();
      return true;
    }
    return false;
  }

  bool loadProfile(StringRef Path) {
    auto BufOrErr = MemoryBuffer::getFile(Path);
    if (!BufOrErr) {
      errs() << "warning: cannot open machine-block-profile-file '" << Path
             << "': " << BufOrErr.getError().message() << "\n";
      return false;
    }

    StringRef Text = (*BufOrErr)->getBuffer();
    FunctionProfile *Current = nullptr;
    size_t LineNo = 0;

    while (!Text.empty()) {
      auto Split = Text.split('\n');
      StringRef Line = Split.first;
      Text = Split.second;
      ++LineNo;

      // Strip carriage return if present.
      if (Line.ends_with("\r"))
        Line = Line.drop_back();

      // Strip trailing comment.
      auto HashPos = Line.find('#');
      if (HashPos != StringRef::npos)
        Line = Line.substr(0, HashPos);

      StringRef Trimmed = Line.trim();
      if (Trimmed.empty())
        continue;

      bool Indented =
          !Line.empty() && (Line.front() == ' ' || Line.front() == '\t');
      if (!Indented) {
        // Function header: "<name>:<cfg_hash>:".
        if (!Trimmed.consume_back(":")) {
          errs() << "warning: machine-block-profile-file:" << LineNo
                 << ": expected trailing ':' on function header\n";
          Current = nullptr;
          continue;
        }
        auto Sep = Trimmed.rfind(':');
        if (Sep == StringRef::npos) {
          errs() << "warning: machine-block-profile-file:" << LineNo
                 << ": expected '<name>:<cfg_hash>:'\n";
          Current = nullptr;
          continue;
        }
        StringRef Name = Trimmed.substr(0, Sep);
        StringRef HashStr = Trimmed.substr(Sep + 1);
        uint64_t Hash;
        if (HashStr.getAsInteger(10, Hash)) {
          errs() << "warning: machine-block-profile-file:" << LineNo
                 << ": malformed CFG hash '" << HashStr << "'\n";
          Current = nullptr;
          continue;
        }
        Current = &FunctionProfiles[Name];
        Current->CFGHash = Hash;
        continue;
      }

      // Edge: "<src>:<dst>:<freq>".
      if (!Current) {
        errs() << "warning: machine-block-profile-file:" << LineNo
               << ": edge entry without enclosing function header\n";
        continue;
      }

      auto FirstColon = Trimmed.split(':');
      auto SecondColon = FirstColon.second.split(':');
      uint32_t SrcId, DstId;
      uint64_t Freq;
      if (FirstColon.first.getAsInteger(10, SrcId) ||
          SecondColon.first.getAsInteger(10, DstId) ||
          SecondColon.second.getAsInteger(10, Freq)) {
        errs() << "warning: machine-block-profile-file:" << LineNo
               << ": malformed edge '" << Trimmed << "'\n";
        continue;
      }
      Current->Edges.push_back({SrcId, DstId, Freq});
    }

    Loaded = true;
    return true;
  }
};

} // namespace

char MachineBlockProfileLoader::ID = 0;

INITIALIZE_PASS_BEGIN(MachineBlockProfileLoader, DEBUG_TYPE,
                      "Apply MachineBlock-keyed edge profile to MBB succ probs",
                      false, false)
INITIALIZE_PASS_DEPENDENCY(MachineBranchProbabilityInfoWrapperPass)
INITIALIZE_PASS_DEPENDENCY(MachineLoopInfoWrapperPass)
INITIALIZE_PASS_DEPENDENCY(MachineDominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(MachineBlockFrequencyInfoWrapperPass)
INITIALIZE_PASS_END(MachineBlockProfileLoader, DEBUG_TYPE,
                    "Apply MachineBlock-keyed edge profile to MBB succ probs",
                    false, false)

FunctionPass *llvm::createMachineBlockProfileLoader() {
  return new MachineBlockProfileLoader();
}
