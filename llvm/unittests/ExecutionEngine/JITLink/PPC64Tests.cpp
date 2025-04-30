#include "llvm/ADT/ArrayRef.h"
#include "llvm/ExecutionEngine/JITLink/JITLink.h"
#include "llvm/ExecutionEngine/Orc/Shared/ExecutorAddress.h"
#include "llvm/ExecutionEngine/Orc/SymbolStringPool.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Testing/Support/Error.h"
#include "gtest/gtest.h"
#include <cstdint>

#include "llvm/ExecutionEngine/JITLink/ppc64.h"

using namespace llvm;
using namespace llvm::jitlink;
using namespace llvm::support;
using namespace llvm::support::endian;

static ArrayRef<char> from(ArrayRef<uint8_t> Content) {
  return {reinterpret_cast<const char *>(Content.data()), Content.size()};
}
static MutableArrayRef<char> fromMutable(MutableArrayRef<uint8_t> Content) {
  return {reinterpret_cast<char *>(Content.data()), Content.size()};
}

class PPC64XCOFFRelocations : public testing::Test {
protected:
  std::unique_ptr<LinkGraph> G;
  Section *DataSection = nullptr;
  Section *TextSection = nullptr;

  const uint8_t Zeros[8] = {0x00};

public:
  static void SetUpTestCase() {}

  void SetUp() override {
    G = std::make_unique<LinkGraph>(
        "foo", std::make_shared<orc::SymbolStringPool>(),
        Triple("powerpc64-ibm-aix"), SubtargetFeatures(),
        ppc64::getEdgeKindName);
    TextSection =
        &G->createSection(".text", orc::MemProt::Read | orc::MemProt::Exec);
    DataSection =
        &G->createSection(".data", orc::MemProt::Read | orc::MemProt::Write);
  }

  void TearDown() override {}

protected:
  Block &createBlock(Section &S, ArrayRef<uint8_t> Content, uint64_t Addr,
                     uint64_t Alignment = 4) {
    return G->createContentBlock(S, from(Content), orc::ExecutorAddr(Addr),
                                 Alignment, 0);
  }

  Block &createMutableBlock(Section &S, MutableArrayRef<uint8_t> Content,
                            uint64_t Addr, uint64_t Alignment = 4) {
    return G->createMutableContentBlock(S, fromMutable(Content),
                                        orc::ExecutorAddr(Addr), Alignment, 0);
  }

  Symbol &createSymbolWithDistance(Block &Origin, int64_t Dist) {
    uint64_t TargetAddr =
        static_cast<int64_t>(Origin.getAddress().getValue()) + Dist;
    return G->addAnonymousSymbol(
        createBlock(Origin.getSection(), Zeros, TargetAddr), 0 /*Offset*/,
        G->getPointerSize(), false, false);
  };
};

TEST_F(PPC64XCOFFRelocations, Pointer64) {
  uint8_t TargetContent[8] = {0x0};

  Block &TargetBlock = createMutableBlock(*DataSection, TargetContent, 0x0);
  Symbol &S = createSymbolWithDistance(TargetBlock, 0x1020304050607080);

  Edge E(ppc64::EdgeKind_ppc64::Pointer64, 0, S, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, TargetBlock, E, nullptr),
                    Succeeded());
  uint8_t ExpectedContent[8] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
  EXPECT_EQ(TargetBlock.getAlreadyMutableContent(),
            fromMutable(ExpectedContent));

  Edge EAddend(ppc64::EdgeKind_ppc64::Pointer64, 0, S, 6);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, TargetBlock, EAddend, nullptr),
                    Succeeded());
  uint8_t ExpectedContentAddend[8] = {0x10, 0x20, 0x30, 0x40,
                                      0x50, 0x60, 0x70, 0x86};
  EXPECT_EQ(TargetBlock.getAlreadyMutableContent(),
            fromMutable(ExpectedContentAddend));
}

TEST_F(PPC64XCOFFRelocations, TOCDelta16) {
  uint8_t Content[] = {
      0xe8, 0x62, 0x00, 0x00, // ld 3, Delta1(2)
      0xe8, 0x62, 0x00, 0x00, // ld 3, Delta2(2)
  };
  Block &B = createMutableBlock(*TextSection, Content, 0x0);
  Block &TOCBlock = createMutableBlock(*DataSection, {}, 0x5000);
  Symbol *TOC = &G->addDefinedSymbol(TOCBlock, 0, "TOC", 0, Linkage::Strong,
                                     Scope::Local, true, false);

  Symbol &Before = createSymbolWithDistance(TOCBlock, -0x100);
  Edge E1(ppc64::EdgeKind_ppc64::TOCDelta16, 2, Before, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, B, E1, TOC), Succeeded());

  Symbol &After = createSymbolWithDistance(TOCBlock, 0x100);
  Edge E2(ppc64::EdgeKind_ppc64::TOCDelta16, 6, After, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, B, E2, TOC), Succeeded());

  uint8_t ExpectedContent[] = {
      0xe8, 0x62, 0xff, 0x00, // ld 3, -256(2)
      0xe8, 0x62, 0x01, 0x00, // ld 3, 256(2)
  };
  EXPECT_EQ(B.getAlreadyMutableContent(), fromMutable(ExpectedContent));

  Symbol &OutOfRange = createSymbolWithDistance(TOCBlock, 0xffffff + 1);
  Edge E3(ppc64::EdgeKind_ppc64::TOCDelta16, 6, OutOfRange, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, B, E3, TOC), Failed());
}

TEST_F(PPC64XCOFFRelocations, TOCDelta16HI_LO) {
  uint8_t Content[] = {
      0x3c, 0x62, 0x00, 0x00, // addis 3, 2, OffsetHI
      0xe8, 0x83, 0x00, 0x00, // ld 4, OffsetLO(3)
      0x3c, 0x62, 0x00, 0x00, // addis 3, 2, OffsetHI
      0xe8, 0x83, 0x00, 0x00, // ld 4, OffsetLO(3)
      0x3c, 0x62, 0x00, 0x00, // addis 3, 2, OffsetHI
      0xe8, 0x83, 0x00, 0x00, // ld 4, OffsetLO(3)
      0x3c, 0x62, 0x00, 0x00, // addis 3, 2, OffsetHI
      0xe8, 0x83, 0x00, 0x00, // ld 4, OffsetLO(3)
  };
  Block &B = createMutableBlock(*TextSection, Content, 0x0);
  Block &TOCBlock = createMutableBlock(*DataSection, {}, 0x5000);
  Symbol *TOC = &G->addDefinedSymbol(TOCBlock, 0, "TOC", 0, Linkage::Strong,
                                     Scope::Local, true, false);

  Symbol &PositiveOffset = createSymbolWithDistance(TOCBlock, 0x12340);
  Edge E1(ppc64::EdgeKind_ppc64::TOCDelta16HA, 2, PositiveOffset, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, B, E1, TOC), Succeeded());
  Edge E2(ppc64::EdgeKind_ppc64::TOCDelta16LO, 6, PositiveOffset, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, B, E2, TOC), Succeeded());

  Symbol &NegativeOffset = createSymbolWithDistance(TOCBlock, -0x12340);
  Edge E3(ppc64::EdgeKind_ppc64::TOCDelta16HA, 10, NegativeOffset, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, B, E3, TOC), Succeeded());
  Edge E4(ppc64::EdgeKind_ppc64::TOCDelta16LO, 14, NegativeOffset, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, B, E4, TOC), Succeeded());

  Symbol &SmallOffset = createSymbolWithDistance(TOCBlock, 0x20);
  Edge E5(ppc64::EdgeKind_ppc64::TOCDelta16HA, 18, SmallOffset, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, B, E5, TOC), Succeeded());
  Edge E6(ppc64::EdgeKind_ppc64::TOCDelta16LO, 22, SmallOffset, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, B, E6, TOC), Succeeded());

  Symbol &SmallNegOffset = createSymbolWithDistance(TOCBlock, -0x20);
  Edge E7(ppc64::EdgeKind_ppc64::TOCDelta16HA, 26, SmallNegOffset, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, B, E7, TOC), Succeeded());
  Edge E8(ppc64::EdgeKind_ppc64::TOCDelta16LO, 30, SmallNegOffset, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, B, E8, TOC), Succeeded());

  uint8_t ExpectedContent[] = {
      0x3c, 0x62, 0x00, 0x01, // addis 3, 2, 1
      0xe8, 0x83, 0x23, 0x40, // ld 4, 9024(3)
      0x3c, 0x62, 0xff, 0xff, // addis 3, 2, -1
      0xe8, 0x83, 0xdc, 0xc0, // ld 4, -9024(3)
      0x3c, 0x62, 0x00, 0x00, // addis 3, 2, 0
      0xe8, 0x83, 0x00, 0x20, // ld 4, 32(3)
      0x3c, 0x62, 0x00, 0x00, // addis 3, 2, 0
      0xe8, 0x83, 0xff, 0xe0, // ld 4, -32(3)
  };
  EXPECT_EQ(B.getAlreadyMutableContent(), fromMutable(ExpectedContent));

  // Overflow for 32 bit displacements
  Symbol &OutOfRange = createSymbolWithDistance(TOCBlock, 0x80000000);
  Edge E9(ppc64::EdgeKind_ppc64::TOCDelta16HA, 2, OutOfRange, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, B, E9, TOC), Failed());
}

TEST_F(PPC64XCOFFRelocations, CallBranchDelta) {
  uint8_t BranchContent[] = {
      0x48, 0x00, 0x00, 0x01, // bl func
      0x60, 0x00, 0x00, 0x00, // nop
  };

  Block &F = createMutableBlock(*TextSection, BranchContent, 0x0);
  Symbol &Func = createSymbolWithDistance(F, 0x1000);

  Edge E(ppc64::EdgeKind_ppc64::CallBranchDelta, 0, Func, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, F, E, nullptr), Succeeded());

  uint8_t ExpectedContent[] = {
      0x48, 0x00, 0x10, 0x01, // bl 4096
      0x60, 0x00, 0x00, 0x00, // nop
  };
  EXPECT_EQ(F.getAlreadyMutableContent(), fromMutable(ExpectedContent));

  Symbol &OutOfRange = createSymbolWithDistance(F, 1 << 26);
  Edge E2(ppc64::EdgeKind_ppc64::CallBranchDelta, 0, OutOfRange, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, F, E2, nullptr), Failed());
}

TEST_F(PPC64XCOFFRelocations, CallBranchDeltaRestoreTOC) {
  uint8_t BranchContent[] = {
      0x48, 0x00, 0x00, 0x01, // bl func
      0x60, 0x00, 0x00, 0x00, // nop
  };

  Block &F = createMutableBlock(*TextSection, BranchContent, 0x0);
  Symbol &Func = createSymbolWithDistance(F, 0x1000);

  Edge E(ppc64::EdgeKind_ppc64::CallBranchDeltaRestoreTOC, 0, Func, 0);
  EXPECT_THAT_ERROR(ppc64::applyXCOFFFixup(*G, F, E, nullptr), Succeeded());

  uint8_t ExpectedContent[] = {
      0x48, 0x00, 0x10, 0x01, // bl 4096
      0xe8, 0x41, 0x00, 0x28, // ld 2, 40(1)
  };
  EXPECT_EQ(F.getAlreadyMutableContent(), fromMutable(ExpectedContent));
}
