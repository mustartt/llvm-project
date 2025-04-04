#include "llvm/ExecutionEngine/JITLink/ppc.h"
#include "llvm/ADT/bit.h"
#include "llvm/ExecutionEngine/JITLink/JITLink.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FormatVariadic.h"
#include "llvm/Support/MathExtras.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>

#define DEBUG_TYPE "jitlink"

namespace llvm::jitlink::ppc {

const char *getEdgeKindName(Edge::Kind K) {
  switch (K) {
  case Pointer64:
    return "R_POS_64";
  case TOC16:
    return "R_TOC_16";
  case TOCLower16:
    return "R_TOCL_16";
  case TOCUpper16:
    return "R_TOCU_16";
  case RelativeBranch:
    return "R_RBR_26";
  default:
    return getGenericEdgeKindName(K);
  }
}

enum DFormFixupType : uint8_t {
  D_NONE = 0,
  // D-form instructions that can never be modified or fixed up.
  D_NEVER = 7,
  // Target register can be used as temporary.
  D_LOAD = 8,
  // Target register cannot be used as temporary.
  D_NOLOAD = 9,
  D_LOADU = 10,
  D_BR = 11
};

struct ExpandedOp {
  uint8_t OpCode; // Primary opcode
  uint8_t XOBits; // Width of the XO Bits in the instruction
  SmallVector<DFormFixupType, 4> XO;
};

struct DFormFixupInfo {
  DFormFixupType FixupType;
  std::optional<ExpandedOp> ExpandedOp;

  [[nodiscard]] bool isExpandedOp() const { return ExpandedOp.has_value(); }
};

// clang-format off
const std::array<DFormFixupInfo, 64> FixupInfoTable = {
    DFormFixupInfo{D_NONE, std::nullopt},   // 00 INVALID
    DFormFixupInfo{D_NONE, std::nullopt},   // 01 INVALID
    DFormFixupInfo{D_NEVER, std::nullopt},  // 02 "tdi"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 03 "twi"
    DFormFixupInfo{D_NONE, std::nullopt},   // 04 EXPANDED
    DFormFixupInfo{D_NONE, std::nullopt},   // 05 INVALID
    DFormFixupInfo{D_NONE, std::nullopt},   // 06 INVALID
    DFormFixupInfo{D_NEVER, std::nullopt},  // 07 "mulli"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 08 "subfic"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 09 "dozi" OBSOLETE
    DFormFixupInfo{D_NEVER, std::nullopt},  // 10 "cmpli"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 11 "cmpi"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 12 "addic"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 13 "addic."
    DFormFixupInfo{D_LOAD, std::nullopt},   // 14 addi/cal
    DFormFixupInfo{D_LOADU, std::nullopt},  // 15 "addis/cau"
    DFormFixupInfo{D_BR, std::nullopt},     // 16 "bc"
    DFormFixupInfo{D_NONE, std::nullopt},   // 17 "sc"
    DFormFixupInfo{D_NONE, std::nullopt},   // 18 "b"
    DFormFixupInfo{D_NONE, std::nullopt},   // 19 EXPANDED
    DFormFixupInfo{D_NONE, std::nullopt},   // 20 "rlimi"
    DFormFixupInfo{D_NONE, std::nullopt},   // 21 "rlinm"
    DFormFixupInfo{D_NONE, std::nullopt},   // 22 rlmi/OBS
    DFormFixupInfo{D_NONE, std::nullopt},   // 23 "rlnm"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 24 "ori"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 25 "oris"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 26 "xori"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 27 "xoris"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 28 "andi."
    DFormFixupInfo{D_NEVER, std::nullopt},  // 29 "andis."
    DFormFixupInfo{D_NONE, std::nullopt},   // 30 EXPANDED
    DFormFixupInfo{D_NONE, std::nullopt},   // 31 EXPANDED
    DFormFixupInfo{D_LOAD, std::nullopt},   // 32 "lwz"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 33 "lwzu"
    DFormFixupInfo{D_LOAD, std::nullopt},   // 34 "lbz"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 35 "lbzu"
    DFormFixupInfo{D_NOLOAD, std::nullopt}, // 36 "stw"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 37 "stwu"
    DFormFixupInfo{D_NOLOAD, std::nullopt}, // 38 "stb"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 39 "stbu"
    DFormFixupInfo{D_LOAD, std::nullopt},   // 40 "lhz"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 41 "lhzu"
    DFormFixupInfo{D_LOAD, std::nullopt},   // 42 "lha"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 43 "lhau"
    DFormFixupInfo{D_NOLOAD, std::nullopt}, // 44 "sth"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 45 "sthu"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 46 "lmw"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 47 "stmw"
    DFormFixupInfo{D_NOLOAD, std::nullopt}, // 48 "lfs"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 49 "lfsu"
    DFormFixupInfo{D_NOLOAD, std::nullopt}, // 50 "lfd"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 51 "lfdu"
    DFormFixupInfo{D_NOLOAD, std::nullopt}, // 52 "stfs"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 53 "stfsu"
    DFormFixupInfo{D_NOLOAD, std::nullopt}, // 54 "stfd"
    DFormFixupInfo{D_NEVER, std::nullopt},  // 55 "stfdu"
    // 56 EXPANDED DQ form "lq"
    DFormFixupInfo{D_NOLOAD, ExpandedOp{56, 4, {D_NOLOAD}}}, 
    // 57 EXPANDED DS form "lfdp"
    DFormFixupInfo{D_NOLOAD, ExpandedOp{57, 2, {D_NOLOAD, D_NONE, D_NOLOAD, D_NOLOAD}}}, 
    // 58 EXPANDED DS "ld" "ldu" "lwa"
    DFormFixupInfo{D_LOAD, ExpandedOp{58, 2, {D_LOAD, D_NEVER, D_LOAD}}},   
    DFormFixupInfo{D_NONE, std::nullopt},   // 59 EXPANDED FP/DFP
    DFormFixupInfo{D_NONE, std::nullopt},   // 60 EXPANDED VSX
    DFormFixupInfo{D_NONE, std::nullopt},   // 61 EXPANDED DS handled as special case
    // 62 EXPANDED DS "std" "stdu" "stq"
    DFormFixupInfo{D_NOLOAD, ExpandedOp{62, 2, {D_NOLOAD, D_NEVER, D_NOLOAD}}}, 
    DFormFixupInfo{D_NONE, std::nullopt}    // 63 EXPANDED FP/DFP
};
// clang-format on

static Expected<uint16_t> getDFormInstructionXOMask(const char *InstrPtr) {
  assert((reinterpret_cast<uint64_t>(InstrPtr) & 3) == 0 &&
         "Instruction is not 4-byte aligned");
  uint32_t Instruction = support::endian::read32be(InstrPtr);
  uint8_t OpCode = (Instruction >> 26) & 0x3F;
  assert(OpCode < FixupInfoTable.size() && "Invalid OpCode");
  const DFormFixupInfo &FixupInfo = FixupInfoTable[OpCode];

  // Handle opcode 61 has a special case, because some instructions are in
  // DS-Form (stfdp, stxsd, stxssp) and some are in DQ-Form (lxv, stxv).
  if (OpCode == 61) {
    uint8_t DSFormXOBits = Instruction & 0b11;
    if (DSFormXOBits == 1)
      return 0b1111; // Lower 4 bits of DQ-Form ({SX, TX}, XO)
    return 0b111;
  }
  if (FixupInfo.isExpandedOp()) {
    if (FixupInfo.ExpandedOp->OpCode != OpCode)
      return make_error<JITLinkError>("Internal link error");
    return (1 << FixupInfo.ExpandedOp->XOBits) - 1;
  }
  return 0;
}

Error applyFixup(LinkGraph &G, Block &B, const Edge &E,
                 const Symbol *TOCSymbol) {
  char *BlockWorkingMem = B.getAlreadyMutableContent().data();
  char *FixupPtr = BlockWorkingMem + E.getOffset();
  orc::ExecutorAddr FixupAddress = B.getAddress() + E.getOffset();
  int64_t S = E.getTarget().getAddress().getValue();
  int64_t A = E.getAddend();
  int64_t P = FixupAddress.getValue();
  int64_t TOCBase = TOCSymbol ? TOCSymbol->getAddress().getValue() : 0;

  LLVM_DEBUG({
    dbgs() << "    Applying fixup on " << G.getEdgeKindName(E.getKind())
           << " edge, (S, A, P, .TOC.) = (" << formatv("{0:x}", S) << ", "
           << formatv("{0:x}", A) << ", " << formatv("{0:x}", P) << ", "
           << formatv("{0:x}", TOCBase) << ")\n";
  });

  switch (E.getKind()) {
  case Pointer64: {
    uint64_t Value = S + A;
    support::endian::write64<endianness::big>(FixupPtr, Value);
    break;
  }
  case TOCLower16:
  case TOCUpper16:
  case TOC16: {
    // A length of 16 is used to specify the displacement field of a D-, DS-,
    // DQ-, or DX-format instruction. The specified address is the address of
    // the displacement field. The instruction is examined to preserve low-order
    // instructions bits that are not part of the displacement field.
    int64_t Offset = S - TOCBase;
    if (!isInt<16>(Offset))
      return make_error<JITLinkError>("R_TOC_16 target is out of range");

    auto XOMask = getDFormInstructionXOMask(FixupPtr - 2);
    if (auto Err = XOMask.takeError())
      return Err;

    // TODO: If the relocation offset is small enough, we can convert the TOC
    // load to an addi.
    uint16_t InstrLowerHalf = support::endian::read16be(FixupPtr);
    uint16_t MaskedOffset =
        (static_cast<uint16_t>(Offset) & ((1 << 16) - 1)) & (~*XOMask);
    support::endian::write16be(FixupPtr, InstrLowerHalf | MaskedOffset);
    break;
  }
  case RelativeBranchRestoreTOC:
  case RelativeBranch: {
    // TODO: Set AA bit for absolute symbols
    // The instruction can be modified to an absolute branch instruction if the
    // target address is not relocatable. In this case, the AA bit of the
    // instruction is set.

    int64_t Value = E.getTarget().isAbsolute() ? S : S - P + A;
    if (!isInt<26>(Value))
      return make_error<JITLinkError>("R_RBR_26 branch target is out of range");
    if (static_cast<uint64_t>(Value) & 3)
      return make_error<JITLinkError>("R_RBR_26 branch target is not aligned");

    constexpr uint32_t InstMask = 0xFC000001;
    constexpr uint32_t AALKMask = 0x3;
    constexpr uint32_t LIMask = ((1 << 26) - 1) & ~AALKMask;
    uint32_t RawInstr = support::endian::read32be(FixupPtr);
    uint32_t AABit = E.getTarget().isAbsolute() << 1;
    uint32_t TargetImm = static_cast<uint32_t>(Value) & LIMask;
    uint32_t BranchInstr = (RawInstr & InstMask) | TargetImm | AABit;
    support::endian::write32be(FixupPtr, BranchInstr);

    // Inserts restore TOC sequence into the nop slots for cross module call
    // bl Offset -> bl Offset
    // nop       -> ld r2, 40(r1)
    if (E.getKind() == RelativeBranchRestoreTOC) {
      constexpr uint32_t RestoreR2 = 0xE8410028;
      support::endian::write32be(FixupPtr + 4, RestoreR2);
    }

    break;
  }
  default:
    return make_error<JITLinkError>(
        "In graph " + G.getName() + ", section " + B.getSection().getName() +
        " unsupported edge kind " + getEdgeKindName(E.getKind()));
  }

  return Error::success();
}

} // namespace llvm::jitlink::ppc
