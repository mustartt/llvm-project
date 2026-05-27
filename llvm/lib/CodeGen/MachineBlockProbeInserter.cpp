//===- MachineBlockProbeInserter.cpp --------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Inserts MachineBlock-typed pseudo probes at the entry of every
// MachineBasicBlock. Runs as the first MIR pass after instruction selection so
// that probes anchor MBB identity before any MIR transformation. Probes share
// the existing PSEUDO_PROBE opcode and lower into the same .pseudo_probe
// section as IR-level Block probes; the new MachineBlock type tag distinguishes
// the two namespaces at the consumer.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PseudoProbe.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/CRC.h"
#include "llvm/Support/CommandLine.h"

#define DEBUG_TYPE "machine-block-probe-inserter"

using namespace llvm;

static cl::opt<bool> EnableMachineBlockProbes(
    "enable-machine-block-probes", cl::Hidden, cl::init(false),
    cl::desc("Insert MachineBlock pseudo probes at every MBB entry"));

namespace {

class MachineBlockProbeInserter : public MachineFunctionPass {
public:
  static char ID;

  MachineBlockProbeInserter() : MachineFunctionPass(ID) {}

  StringRef getPassName() const override {
    return "Machine Block Probe Inserter";
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesAll();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  bool doInitialization(Module &M) override {
    // Gate on pseudoprobe-for-profiling being enabled at IR level. The
    // descriptor section (llvm.pseudo_probe_desc) is the authoritative
    // signal that pseudo probes are in use for this module.
    ShouldRun = EnableMachineBlockProbes &&
                M.getNamedMetadata(PseudoProbeDescMetadataName) != nullptr;
    return false;
  }

  bool runOnMachineFunction(MachineFunction &MF) override {
    if (!ShouldRun)
      return false;

    const Function &F = MF.getFunction();
    // Match the GUID computation used by SampleProfileProbe at IR level so
    // MachineBlock probes share a function GUID with IR-level Block probes
    // and are covered by the existing llvm.pseudo_probe_desc entry.
    StringRef FName = F.getName();
    if (auto *SP = F.getSubprogram()) {
      FName = SP->getLinkageName();
      if (FName.empty())
        FName = SP->getName();
    }
    uint64_t GUID = Function::getGUIDAssumingExternalLinkage(FName);

    const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();
    bool Changed = false;
    uint32_t NextProbeId = 1;

    // Walk MBBs in reverse post order so probe IDs are deterministic given
    // the post-ISel MIR CFG. Probe IDs live in a per-(function, type)
    // namespace; IR Block probes and MachineBlock probes never collide
    // because the type tag distinguishes them.
    ReversePostOrderTraversal<MachineFunction *> RPOT(&MF);
    SmallVector<MachineBasicBlock *, 16> RPOBlocks(RPOT.begin(), RPOT.end());

    DenseMap<MachineBasicBlock *, uint32_t> BlockId;
    for (MachineBasicBlock *MBB : RPOBlocks) {
      uint32_t ProbeId = NextProbeId++;
      BlockId[MBB] = ProbeId;
      // Insert after any PHIs / labels so we don't violate the
      // "PHIs first" MIR invariant. The probe still anchors the MBB entry
      // for trace-attribution purposes — its address falls inside the MBB
      // before any non-PHI real instruction.
      MachineBasicBlock::iterator InsertPt =
          MBB->SkipPHIsLabelsAndDebug(MBB->begin());
      BuildMI(*MBB, InsertPt, DebugLoc(),
              TII->get(TargetOpcode::PSEUDO_PROBE))
          .addImm(GUID)
          .addImm(ProbeId)
          .addImm(static_cast<uint8_t>(PseudoProbeType::MachineBlock))
          .addImm(0 /*Attr*/);
      Changed = true;
    }

    // Compute the MIR-level CFG hash and emit a per-function descriptor in
    // llvm.machine_pseudo_probe_desc. Mirror the IR-level algorithm in
    // SampleProfileProbe::computeCFGHash: walk blocks in stable order and
    // CRC32 the concatenated successor IDs.
    uint64_t MIRCFGHash = computeMIRCFGHash(RPOBlocks, BlockId);
    // The IR module is conceptually const at the MIR layer, but
    // appending a NamedMDNode operand is the same metadata-mutation
    // pattern used throughout the codegen pipeline (e.g. AsmPrinter
    // injecting debug-info entries). const_cast here is intentional and
    // well-established.
    emitMachineProbeDesc(const_cast<Module *>(F.getParent()), GUID,
                         MIRCFGHash, FName);

    return Changed;
  }

private:
  bool ShouldRun = false;

  static uint64_t
  computeMIRCFGHash(ArrayRef<MachineBasicBlock *> RPOBlocks,
                    const DenseMap<MachineBasicBlock *, uint32_t> &BlockId) {
    std::vector<uint8_t> Indexes;
    for (MachineBasicBlock *MBB : RPOBlocks) {
      for (MachineBasicBlock *Succ : MBB->successors()) {
        auto It = BlockId.find(Succ);
        if (It == BlockId.end())
          continue;
        uint32_t Index = It->second;
        for (int J = 0; J < 4; ++J)
          Indexes.push_back((uint8_t)(Index >> (J * 8)));
      }
    }
    JamCRC JC;
    JC.update(Indexes);
    uint64_t Hash =
        ((uint64_t)Indexes.size() << 32) | (uint64_t)JC.getCRC();
    // Reserve the top 4 bits for future use, matching SampleProfileProber.
    Hash &= 0x0FFFFFFFFFFFFFFFULL;
    if (!Hash) {
      // Functions with no edges (single-block, no successors) would hash to
      // zero. Force a non-zero sentinel so the consumer can distinguish
      // "no descriptor" from "descriptor with zero hash."
      Hash = 1;
    }
    return Hash;
  }

  static void emitMachineProbeDesc(Module *M, uint64_t GUID, uint64_t Hash,
                                   StringRef FuncName) {
    LLVMContext &Ctx = M->getContext();
    NamedMDNode *Desc =
        M->getOrInsertNamedMetadata(MachinePseudoProbeDescMetadataName);
    auto *GUIDMD = ConstantAsMetadata::get(
        ConstantInt::get(Type::getInt64Ty(Ctx), GUID));
    auto *HashMD = ConstantAsMetadata::get(
        ConstantInt::get(Type::getInt64Ty(Ctx), Hash));
    auto *NameMD = MDString::get(Ctx, FuncName);
    Desc->addOperand(MDNode::get(Ctx, {GUIDMD, HashMD, NameMD}));
  }
};

} // namespace

char MachineBlockProbeInserter::ID = 0;

INITIALIZE_PASS(MachineBlockProbeInserter, DEBUG_TYPE,
                "Insert MachineBlock pseudo probes at MBB entries", false,
                false)

FunctionPass *llvm::createMachineBlockProbeInserter() {
  return new MachineBlockProbeInserter();
}
