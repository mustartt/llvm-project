//===------- XCOFF_ppc64.cpp -JIT linker implementation for XCOFF/ppc64
//-------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// XCOFF/ppc64 jit-link implementation.
//
//===----------------------------------------------------------------------===//

#include "llvm/ExecutionEngine/JITLink/XCOFF_ppc64.h"
#include "JITLinkGeneric.h"
#include "XCOFFLinkGraphBuilder.h"
#include "llvm/ADT/bit.h"
#include "llvm/ExecutionEngine/JITLink/JITLink.h"
#include "llvm/ExecutionEngine/JITLink/TableManager.h"
#include "llvm/ExecutionEngine/JITLink/ppc.h"
#include "llvm/ExecutionEngine/JITLink/ppc64.h"
#include "llvm/ExecutionEngine/Orc/Shared/ExecutorAddress.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/XCOFFObjectFile.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorHandling.h"
#include <system_error>

using namespace llvm;

#define DEBUG_TYPE "jitlink"

namespace llvm {
namespace jitlink {
using ppc::applyFixup;

Expected<std::unique_ptr<LinkGraph>> createLinkGraphFromXCOFFObject_ppc64(
    MemoryBufferRef ObjectBuffer, std::shared_ptr<orc::SymbolStringPool> SSP) {
  LLVM_DEBUG({
    dbgs() << "Building jitlink graph for new input "
           << ObjectBuffer.getBufferIdentifier() << "...\n";
  });

  auto Obj = object::ObjectFile::createObjectFile(ObjectBuffer);
  if (!Obj)
    return Obj.takeError();
  assert((**Obj).isXCOFF() && "Expects and XCOFF Object");

  auto Features = (*Obj)->getFeatures();
  if (!Features)
    return Features.takeError();
  LLVM_DEBUG({
    dbgs() << " Features: ";
    (*Features).print(dbgs());
  });

  return XCOFFLinkGraphBuilder(cast<object::XCOFFObjectFile>(**Obj),
                               std::move(SSP), Triple("powerpc64-ibm-aix"),
                               std::move(*Features), ppc::getEdgeKindName)
      .buildGraph();
}

class XCOFFJITLinker_ppc64 : public JITLinker<XCOFFJITLinker_ppc64> {
  using JITLinkerBase = JITLinker<XCOFFJITLinker_ppc64>;
  friend JITLinkerBase;

public:
  XCOFFJITLinker_ppc64(std::unique_ptr<JITLinkContext> Ctx,
                       std::unique_ptr<LinkGraph> G,
                       PassConfiguration PassConfig)
      : JITLinkerBase(std::move(Ctx), std::move(G), std::move(PassConfig)) {
    // FIXME: Post allocation pass define TOC base, this is temporary to support
    // building until we can build the required toc entries
    defineTOCSymbol(getGraph());
  }

  Error applyFixup(LinkGraph &G, Block &B, const Edge &E) const {
    LLVM_DEBUG(dbgs() << "  Applying fixup for " << G.getName()
                      << ", address = "
                      << B.getAddress()
                      //        << ", target = " << E.getTarget().getName()
                      << ", kind = " << G.getEdgeKindName(E.getKind()) << "\n");
    if (auto Err = ppc::applyFixup(G, B, E, TOCSymbol))
      return make_error<StringError>("Unsupported relocation type",
                                     std::error_code());
    return Error::success();
  }

private:
  void defineTOCSymbol(LinkGraph &G) {
    for (Symbol *S : G.defined_symbols()) {
      if (S->hasName() && *S->getName() == StringRef("TOC")) {
        TOCSymbol = S;
        return;
      }
    }
  }

private:
  Symbol *TOCSymbol = nullptr;
};

const char CallStubContent[] = {
    (char)0xe9, (char)0x82, 0x00,       0x00,       // ld      r12,Offset(r2)
    (char)0xf8, 0x41,       0x00,       0x28,       // std     r2,40(r1)
    (char)0xe8, 0x0c,       0x00,       0x00,       // ld      r0,0(r12)
    (char)0xe8, 0x4c,       0x00,       0x08,       // ld      r2,8(r12)
    0x7c,       0x09,       0x03,       (char)0xa6, // mtctr   r0
    0x4e,       (char)0x80, 0x04,       0x20,       // bctr
    0x00,       0x00,       0x00,       0x00,       // .long 0x0
    0x00,       0x0c,       (char)0xa0, 0x00,       // .long 0x00ca000
    0x00,       0x00,       0x00,       0x00,       // .long 0x0
    0x00,       0x00,       0x00,       0x18        // .long 0x18
};

const char LargeCallStubContent[] = {
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

const char EmptyTOCEntryContent[8] = {0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00};

class StubTableManager : public TableManager<StubTableManager> {
public:
  static StringRef getSectionName() { return "$__STUBS"; }

  bool visitEdge(LinkGraph &G, Block *B, Edge &E) {
    if (!E.getTarget().isExternal())
      return false;
    E.setTarget(this->getEntryForTarget(G, E.getTarget()));
    E.setKind(ppc::RelativeBranchRestoreTOC);
    return true;
  }

  Symbol &createEntry(LinkGraph &G, Symbol &Target) {
    return createCallStub(G, getOrCreateStubsSection(G),
                          getOrCreateDataSection(G), Target);
  }

private:
  Section &getOrCreateStubsSection(LinkGraph &G) {
    StubSection = G.findSectionByName(getSectionName());
    if (!StubSection)
      StubSection = &G.createSection(getSectionName(),
                                     orc::MemProt::Read | orc::MemProt::Exec);
    return *StubSection;
  }

  Section &getOrCreateDataSection(LinkGraph &G) {
    DataSection = G.findSectionByName("$__TOC");
    if (!DataSection) {
      DataSection =
          &G.createSection("$__TOC", orc::MemProt::Read | orc::MemProt::Write);
      DataSection->setOrdinal(1);
    }
    return *DataSection;
  }

  Symbol &createCallStub(LinkGraph &G, Section &StubSection,
                         Section &DataSection, Symbol &Target) {
    Block &StubBlock = G.createContentBlock(StubSection, CallStubContent,
                                            orc::ExecutorAddr(), 4, 0);
    Block &TocEntry = G.createContentBlock(DataSection, EmptyTOCEntryContent,
                                           orc::ExecutorAddr(), 4, 0);

    // TODO: We might want to always use the large glink stub
    // Create the R_TOC relocation for Offset in the glink stub
    // ld r12, Offset(r2)
    StubBlock.addEdge(ppc::TOC16, 2,
                      G.addAnonymousSymbol(TocEntry, 0, 0, false, true), 0);

    StringRef StubTargetName = *Target.getName();
    assert(StubTargetName.starts_with(".") &&
           "Callable stubs must start with .");

    // Create the relocation against the function descriptor in the external
    // module
    Symbol &TargetDescriptor =
        G.addExternalSymbol(StubTargetName.substr(1), 24, false);
    TocEntry.addEdge(ppc::Pointer64, 0, TargetDescriptor, 0);

    return G.addDefinedSymbol(StubBlock, 0, StubTargetName, StubBlock.getSize(),
                              Linkage::Strong, Scope::Local, true, true);
  }

  Section *StubSection = nullptr;
  Section *DataSection = nullptr;
};

Error buildCallStubs(LinkGraph &G) {
  LLVM_DEBUG(dbgs() << "Building Call Stubs in graph: " << G.getName() << "\n");

  StubTableManager Stubs;
  visitExistingEdges(G, Stubs);

  return Error::success();
}

void link_XCOFF_ppc64(std::unique_ptr<LinkGraph> G,
                      std::unique_ptr<JITLinkContext> Ctx) {
  PassConfiguration Config;

  // Pass insertions
  Config.PostPrunePasses.push_back(buildCallStubs);

  if (auto Err = Ctx->modifyPassConfig(*G, Config))
    return Ctx->notifyFailed(std::move(Err));

  XCOFFJITLinker_ppc64::link(std::move(Ctx), std::move(G), std::move(Config));
}

} // namespace jitlink
} // namespace llvm
