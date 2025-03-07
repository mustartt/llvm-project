//===---- llvm-jitlink-xcoff.cpp -- XCOFF support for llvm-jitlink --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// XCOFF parsing support for llvm-jitlink.
//
//===----------------------------------------------------------------------===//

#include "llvm-jitlink.h"

#include "llvm/Support/Error.h"
#include "llvm/Support/Path.h"

#define DEBUG_TYPE "llvm_jitlink"

using namespace llvm;
using namespace llvm::jitlink;

namespace llvm {

Error registerXCOFFGraphInfo(Session &S, jitlink::LinkGraph &G) {
  std::lock_guard<std::mutex> Lock(S.M);

  auto FileName = sys::path::filename(G.getName());
  if (S.FileInfos.count(FileName)) {
    return make_error<StringError>("When -check is passed, file names must be "
                                   "distinct (duplicate: \"" +
                                       FileName + "\")",
                                   inconvertibleErrorCode());
  }

  auto &FileInfo = S.FileInfos[FileName];
  LLVM_DEBUG({
    dbgs() << "Registering XCOFF file info for \"" << FileName << "\"\n";
  });

  for (auto &Sec : G.sections()) {
    LLVM_DEBUG({
      dbgs() << "  Section \"" << Sec.getName() << "\": "
             << (Sec.symbols().empty() ? "empty. skipping." : "processing...")
             << "\n";
    });

    // Skip empty sections.
    if (Sec.symbols().empty())
      continue;

    if (FileInfo.SectionInfos.count(Sec.getName()))
      return make_error<StringError>("Encountered duplicate section name \"" +
                                         Sec.getName() + "\" in \"" + FileName +
                                         "\"",
                                     inconvertibleErrorCode());

    bool SectionContainsContent = false;
    bool SectionContainsZeroFill = false;

    auto *FirstSym = *Sec.symbols().begin();
    auto *LastSym = FirstSym;
    for (auto *Sym : Sec.symbols()) {
      if (Sym->getAddress() < FirstSym->getAddress())
        FirstSym = Sym;
      if (Sym->getAddress() > LastSym->getAddress())
        LastSym = Sym;

      // TODO: register symbol

      if (Sym->hasName()) {
        if (Sym->isSymbolZeroFill()) {
          S.SymbolInfos[Sym->getName()] = {Sym->getSize(),
                                           Sym->getAddress().getValue()};
          SectionContainsZeroFill = true;
        } else {
          S.SymbolInfos[Sym->getName()] = {Sym->getSymbolContent(),
                                           Sym->getAddress().getValue(),
                                           Sym->getTargetFlags()};
          SectionContainsContent = true;
        }
      }
    }

    // Add symbol info for absolute symbols.
    for (auto *Sym : G.absolute_symbols())
      S.SymbolInfos[Sym->getName()] = {Sym->getSize(),
                                       Sym->getAddress().getValue()};

    auto SecAddr = FirstSym->getAddress();
    auto SecSize =
        (LastSym->getBlock().getAddress() + LastSym->getBlock().getSize()) -
        SecAddr;

    if (SectionContainsZeroFill && SectionContainsContent)
      return make_error<StringError>("Mixed zero-fill and content sections not "
                                     "supported yet",
                                     inconvertibleErrorCode());
    if (SectionContainsZeroFill)
      FileInfo.SectionInfos[Sec.getName()] = {SecSize, SecAddr.getValue()};
    else
      FileInfo.SectionInfos[Sec.getName()] = {
          ArrayRef<char>(FirstSym->getBlock().getContent().data(), SecSize),
          SecAddr.getValue(), FirstSym->getTargetFlags()};
  }

  return Error::success();
}

} // namespace llvm
