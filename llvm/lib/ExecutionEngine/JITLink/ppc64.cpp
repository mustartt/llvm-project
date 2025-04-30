//===----- ppc64.cpp - Generic JITLink ppc64 edge kinds, utilities ------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Generic utilities for graphs representing 64-bit PowerPC objects.
//
//===----------------------------------------------------------------------===//

#include "llvm/ExecutionEngine/JITLink/ppc64.h"
#include "llvm/ExecutionEngine/JITLink/JITLink.h"
#include "llvm/Support/Error.h"

#define DEBUG_TYPE "jitlink"

namespace llvm::jitlink::ppc64 {

const char NullPointerContent[8] = {0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00};

const char PointerJumpStubContent_little[20] = {
    0x18,       0x00, 0x41,       (char)0xf8, // std r2, 24(r1)
    0x00,       0x00, (char)0x82, 0x3d,       // addis r12, r2, OffHa
    0x00,       0x00, (char)0x8c, (char)0xe9, // ld r12, OffLo(r12)
    (char)0xa6, 0x03, (char)0x89, 0x7d,       // mtctr r12
    0x20,       0x04, (char)0x80, 0x4e,       // bctr
};

const char PointerJumpStubContent_big[20] = {
    (char)0xf8, 0x41,       0x00, 0x18,       // std r2, 24(r1)
    0x3d,       (char)0x82, 0x00, 0x00,       // addis r12, r2, OffHa
    (char)0xe9, (char)0x8c, 0x00, 0x00,       // ld r12, OffLo(r12)
    0x7d,       (char)0x89, 0x03, (char)0xa6, // mtctr r12
    0x4e,       (char)0x80, 0x04, 0x20,       // bctr
};

// TODO: We can use prefixed instructions if LLJIT is running on power10.
const char PointerJumpStubNoTOCContent_little[32] = {
    (char)0xa6, 0x02,       (char)0x88, 0x7d,       // mflr 12
    0x05,       (char)0x00, (char)0x9f, 0x42,       // bcl 20,31,.+4
    (char)0xa6, 0x02,       0x68,       0x7d,       // mflr 11
    (char)0xa6, 0x03,       (char)0x88, 0x7d,       // mtlr 12
    0x00,       0x00,       (char)0x8b, 0x3d,       // addis 12,11,OffHa
    0x00,       0x00,       (char)0x8c, (char)0xe9, // ld 12, OffLo(12)
    (char)0xa6, 0x03,       (char)0x89, 0x7d,       // mtctr 12
    0x20,       0x04,       (char)0x80, 0x4e,       // bctr
};

const char PointerJumpStubNoTOCContent_big[32] = {
    0x7d,       (char)0x88, 0x02, (char)0xa6, // mflr 12
    0x42,       (char)0x9f, 0x00, 0x05,       // bcl 20,31,.+4
    0x7d,       0x68,       0x02, (char)0xa6, // mflr 11
    0x7d,       (char)0x88, 0x03, (char)0xa6, // mtlr 12
    0x3d,       (char)0x8b, 0x00, 0x00,       // addis 12,11,OffHa
    (char)0xe9, (char)0x8c, 0x00, 0x00,       // ld 12, OffLo(12)
    0x7d,       (char)0x89, 0x03, (char)0xa6, // mtctr 12
    0x4e,       (char)0x80, 0x04, 0x20,       // bctr
};

const char GLinkCallStubContent[44] = {
    0x3d,       (char)0x82, 0x00,       0x00,       // addis   r12,r2,OffsetHi
    (char)0xe9, (char)0x8c, 0x00,       0x00,       // ld      r12,OffsetLo(r12)
    (char)0xf8, 0x41,       0x00,       0x28,       // std     r2,40(r1)
    (char)0xe8, 0x0c,       0x00,       0x00,       // ld      r0,0(r12)
    (char)0xe8, 0x4c,       0x00,       0x08,       // ld      r2,8(r12)
    0x7c,       0x09,       0x03,       (char)0xa6, // mtctr   r0
    0x4e,       (char)0x80, 0x04,       0x20,       // bctr
    0x00,       0x00,       0x00,       0x00,       // .long 0x0
    0x00,       0x0c,       (char)0xa0, 0x00,       // .long 0x00ca000
    0x00,       0x00,       0x00,       0x00,       // .long 0x0
    0x00,       0x00,       0x00,       0x1c        // .long 0x1c
};

const char *getEdgeKindName(Edge::Kind K) {
  switch (K) {
  case Pointer64:
    return "Pointer64";
  case Pointer32:
    return "Pointer32";
  case Pointer16:
    return "Pointer16";
  case Pointer16DS:
    return "Pointer16DS";
  case Pointer16HA:
    return "Pointer16HA";
  case Pointer16HI:
    return "Pointer16HI";
  case Pointer16HIGH:
    return "Pointer16HIGH";
  case Pointer16HIGHA:
    return "Pointer16HIGHA";
  case Pointer16HIGHER:
    return "Pointer16HIGHER";
  case Pointer16HIGHERA:
    return "Pointer16HIGHERA";
  case Pointer16HIGHEST:
    return "Pointer16HIGHEST";
  case Pointer16HIGHESTA:
    return "Pointer16HIGHESTA";
  case Pointer16LO:
    return "Pointer16LO";
  case Pointer16LODS:
    return "Pointer16LODS";
  case Pointer14:
    return "Pointer14";
  case Delta64:
    return "Delta64";
  case Delta34:
    return "Delta34";
  case Delta32:
    return "Delta32";
  case NegDelta32:
    return "NegDelta32";
  case Delta16:
    return "Delta16";
  case Delta16HA:
    return "Delta16HA";
  case Delta16HI:
    return "Delta16HI";
  case Delta16LO:
    return "Delta16LO";
  case TOC:
    return "TOC";
  case TOCDelta16:
    return "TOCDelta16";
  case TOCDelta16DS:
    return "TOCDelta16DS";
  case TOCDelta16HA:
    return "TOCDelta16HA";
  case TOCDelta16HI:
    return "TOCDelta16HI";
  case TOCDelta16LO:
    return "TOCDelta16LO";
  case TOCDelta16LODS:
    return "TOCDelta16LODS";
  case RequestGOTAndTransformToDelta34:
    return "RequestGOTAndTransformToDelta34";
  case CallBranchDelta:
    return "CallBranchDelta";
  case CallBranchDeltaRestoreTOC:
    return "CallBranchDeltaRestoreTOC";
  case RequestCall:
    return "RequestCall";
  case RequestCallNoTOC:
    return "RequestCallNoTOC";
  case RequestTLSDescInGOTAndTransformToTOCDelta16HA:
    return "RequestTLSDescInGOTAndTransformToTOCDelta16HA";
  case RequestTLSDescInGOTAndTransformToTOCDelta16LO:
    return "RequestTLSDescInGOTAndTransformToTOCDelta16LO";
  case RequestTLSDescInGOTAndTransformToDelta34:
    return "RequestTLSDescInGOTAndTransformToDelta34";
  default:
    return getGenericEdgeKindName(static_cast<Edge::Kind>(K));
  }
}

enum DFormFixupType : uint8_t {
  // Not a D-from instruction.
  NONE = 0,
  // D-form instructions that can never be modified or fixed up.
  NEVER,
  // Target register can be used as temporary.
  LOAD,
  // Target register cannot be used as temporary.
  NOLOAD,
  LOADU,
  BR
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
    DFormFixupInfo{NONE, std::nullopt},   // 00 INVALID
    DFormFixupInfo{NONE, std::nullopt},   // 01 INVALID
    DFormFixupInfo{NEVER, std::nullopt},  // 02 "tdi"
    DFormFixupInfo{NEVER, std::nullopt},  // 03 "twi"
    DFormFixupInfo{NONE, std::nullopt},   // 04 EXPANDED
    DFormFixupInfo{NONE, std::nullopt},   // 05 INVALID
    DFormFixupInfo{NONE, std::nullopt},   // 06 INVALID
    DFormFixupInfo{NEVER, std::nullopt},  // 07 "mulli"
    DFormFixupInfo{NEVER, std::nullopt},  // 08 "subfic"
    DFormFixupInfo{NEVER, std::nullopt},  // 09 "dozi" OBSOLETE
    DFormFixupInfo{NEVER, std::nullopt},  // 10 "cmpli"
    DFormFixupInfo{NEVER, std::nullopt},  // 11 "cmpi"
    DFormFixupInfo{NEVER, std::nullopt},  // 12 "addic"
    DFormFixupInfo{NEVER, std::nullopt},  // 13 "addic."
    DFormFixupInfo{LOAD, std::nullopt},   // 14 addi/cal
    DFormFixupInfo{LOADU, std::nullopt},  // 15 "addis/cau"
    DFormFixupInfo{BR, std::nullopt},     // 16 "bc"
    DFormFixupInfo{NONE, std::nullopt},   // 17 "sc"
    DFormFixupInfo{NONE, std::nullopt},   // 18 "b"
    DFormFixupInfo{NONE, std::nullopt},   // 19 EXPANDED
    DFormFixupInfo{NONE, std::nullopt},   // 20 "rlimi"
    DFormFixupInfo{NONE, std::nullopt},   // 21 "rlinm"
    DFormFixupInfo{NONE, std::nullopt},   // 22 rlmi/OBS
    DFormFixupInfo{NONE, std::nullopt},   // 23 "rlnm"
    DFormFixupInfo{NEVER, std::nullopt},  // 24 "ori"
    DFormFixupInfo{NEVER, std::nullopt},  // 25 "oris"
    DFormFixupInfo{NEVER, std::nullopt},  // 26 "xori"
    DFormFixupInfo{NEVER, std::nullopt},  // 27 "xoris"
    DFormFixupInfo{NEVER, std::nullopt},  // 28 "andi."
    DFormFixupInfo{NEVER, std::nullopt},  // 29 "andis."
    DFormFixupInfo{NONE, std::nullopt},   // 30 EXPANDED
    DFormFixupInfo{NONE, std::nullopt},   // 31 EXPANDED
    DFormFixupInfo{LOAD, std::nullopt},   // 32 "lwz"
    DFormFixupInfo{NEVER, std::nullopt},  // 33 "lwzu"
    DFormFixupInfo{LOAD, std::nullopt},   // 34 "lbz"
    DFormFixupInfo{NEVER, std::nullopt},  // 35 "lbzu"
    DFormFixupInfo{NOLOAD, std::nullopt}, // 36 "stw"
    DFormFixupInfo{NEVER, std::nullopt},  // 37 "stwu"
    DFormFixupInfo{NOLOAD, std::nullopt}, // 38 "stb"
    DFormFixupInfo{NEVER, std::nullopt},  // 39 "stbu"
    DFormFixupInfo{LOAD, std::nullopt},   // 40 "lhz"
    DFormFixupInfo{NEVER, std::nullopt},  // 41 "lhzu"
    DFormFixupInfo{LOAD, std::nullopt},   // 42 "lha"
    DFormFixupInfo{NEVER, std::nullopt},  // 43 "lhau"
    DFormFixupInfo{NOLOAD, std::nullopt}, // 44 "sth"
    DFormFixupInfo{NEVER, std::nullopt},  // 45 "sthu"
    DFormFixupInfo{NEVER, std::nullopt},  // 46 "lmw"
    DFormFixupInfo{NEVER, std::nullopt},  // 47 "stmw"
    DFormFixupInfo{NOLOAD, std::nullopt}, // 48 "lfs"
    DFormFixupInfo{NEVER, std::nullopt},  // 49 "lfsu"
    DFormFixupInfo{NOLOAD, std::nullopt}, // 50 "lfd"
    DFormFixupInfo{NEVER, std::nullopt},  // 51 "lfdu"
    DFormFixupInfo{NOLOAD, std::nullopt}, // 52 "stfs"
    DFormFixupInfo{NEVER, std::nullopt},  // 53 "stfsu"
    DFormFixupInfo{NOLOAD, std::nullopt}, // 54 "stfd"
    DFormFixupInfo{NEVER, std::nullopt},  // 55 "stfdu"
    // 56 EXPANDED DQ form "lq"
    DFormFixupInfo{NOLOAD, ExpandedOp{56, 4, {NOLOAD}}}, 
    // 57 EXPANDED DS form "lfdp"
    DFormFixupInfo{NOLOAD, ExpandedOp{57, 2, {NOLOAD, NONE, NOLOAD, NOLOAD}}}, 
    // 58 EXPANDED DS "ld" "ldu" "lwa"
    DFormFixupInfo{LOAD, ExpandedOp{58, 2, {LOAD, NEVER, LOAD}}},   
    DFormFixupInfo{NONE, std::nullopt},   // 59 EXPANDED FP/DFP
    DFormFixupInfo{NONE, std::nullopt},   // 60 EXPANDED VSX
    DFormFixupInfo{NONE, std::nullopt},   // 61 EXPANDED DS handled as special case
    // 62 EXPANDED DS "std" "stdu" "stq"
    DFormFixupInfo{NOLOAD, ExpandedOp{62, 2, {NOLOAD, NEVER, NOLOAD}}}, 
    DFormFixupInfo{NONE, std::nullopt}    // 63 EXPANDED FP/DFP
};
// clang-format on

Expected<uint16_t> getDFormInstructionXOMask(const char *InstrPtr) {
  assert((reinterpret_cast<uint64_t>(InstrPtr) & 3) == 0 &&
         "Instruction is not 4-byte aligned");
  uint32_t Instruction = support::endian::read32be(InstrPtr);
  uint8_t OpCode = (Instruction >> 26) & 0x3F;
  if (OpCode >= FixupInfoTable.size())
    return make_error<JITLinkError>("Invalid Op Code");
  const DFormFixupInfo &FixupInfo = FixupInfoTable[OpCode];

  // Handle opcode 61 has a special case, because some instructions are in
  // DS-Form (stfdp, stxsd, stxssp) and some are in DQ-Form (lxv, stxv).
  if (OpCode == 61) {
    uint8_t DSFormXOBits = Instruction & 0b11;
    if (DSFormXOBits == 1)
      return 0b1111; // Lower 4 bits of DQ-Form ({SX, TX}, XO)
    return 0b111;
  }
  if (FixupInfo.FixupType == NONE)
    return make_error<JITLinkError>("Not a D*-Form Instruction");
  if (FixupInfo.FixupType == NEVER)
    return make_error<JITLinkError>("Non-modifiable D*-Form Instruction");

  if (FixupInfo.isExpandedOp()) {
    if (FixupInfo.ExpandedOp->OpCode != OpCode)
      return make_error<JITLinkError>("Internal link error");
    return (1 << FixupInfo.ExpandedOp->XOBits) - 1;
  }
  return 0;
}

} // end namespace llvm::jitlink::ppc64
