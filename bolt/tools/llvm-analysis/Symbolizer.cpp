//===- bolt/tools/llvm-analysis/Symbolizer.cpp - Source location lookup ------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "Symbolizer.h"
#include "bolt/Core/BinaryContext.h"
#include "bolt/Core/BinaryFunction.h"
#include "llvm/DebugInfo/DIContext.h"
#include "llvm/Object/ObjectFile.h"
#include <algorithm>

using namespace llvm;
using namespace llvm::match_tool;

// --------------------------------------------------------------------------
// MatchSymbolizer
// --------------------------------------------------------------------------

MatchSymbolizer::MatchSymbolizer(StringRef Path) : BinaryPath(Path.str()) {
  symbolize::LLVMSymbolizer::Options Opts;
  Opts.PrintFunctions = DINameKind::LinkageName;
  Opts.UseSymbolTable = true;
  Opts.Demangle = true;
  Opts.RelativeAddresses = false;
  Sym = std::make_unique<symbolize::LLVMSymbolizer>(Opts);

  // Probe one address to check if debug info exists.
  object::SectionedAddress Probe{0, object::SectionedAddress::UndefSection};
  auto Res = Sym->symbolizeCode(BinaryPath, Probe);
  if (Res) {
    // If the symbolizer returns a non-empty filename for address 0
    // or if it simply doesn't error, debug info is probably present.
    // We'll check properly on the first real resolve.
    HasDebugInfo = true;
  } else {
    consumeError(Res.takeError());
    HasDebugInfo = false;
  }
}

SourceLoc MatchSymbolizer::resolve(uint64_t Address) {
  SourceLoc Loc;
  object::SectionedAddress SA{Address, object::SectionedAddress::UndefSection};
  auto Res = Sym->symbolizeCode(BinaryPath, SA);
  if (!Res) {
    consumeError(Res.takeError());
    return Loc;
  }
  const DILineInfo &Info = *Res;
  if (Info.FileName != "<invalid>" && !Info.FileName.empty()) {
    Loc.File = Info.FileName;
    Loc.Line = Info.Line;
    Loc.Column = Info.Column;
    if (Info.FunctionName != "<invalid>")
      Loc.Function = Info.FunctionName;
    HasDebugInfo = true;
  }
  return Loc;
}

SourceLoc MatchSymbolizer::resolve(const bolt::BinaryContext &BC,
                                   const bolt::BinaryFunction &BF,
                                   const MCInst &Inst) {
  // Try instruction-level offset first.
  auto MaybeOffset = BC.MIB->getOffset(Inst);
  if (MaybeOffset) {
    uint64_t Address = BF.getAddress() + *MaybeOffset;
    return resolve(Address);
  }
  // Fallback: just use the function's start address.
  return resolve(BF.getAddress());
}

// --------------------------------------------------------------------------
// SourceAggregator
// --------------------------------------------------------------------------

void SourceAggregator::record(const SourceLoc &Loc) {
  if (Loc.valid()) {
    ++Resolved;
    ++ByLocation[Loc.str()];
    // Extract directory-less filename for file aggregation.
    StringRef F(Loc.File);
    size_t Slash = F.rfind('/');
    if (Slash != StringRef::npos)
      F = F.substr(Slash + 1);
    ++ByFile[F];
  } else {
    ++Unresolved;
  }
}

/// Helper: sort a StringMap by value descending and print top N.
static void printSorted(raw_ostream &OS, const StringMap<unsigned> &Map,
                        unsigned TopN) {
  SmallVector<std::pair<StringRef, unsigned>, 32> Entries;
  for (const auto &[Key, Val] : Map)
    Entries.push_back({Key, Val});
  llvm::sort(Entries,
             [](const auto &A, const auto &B) { return A.second > B.second; });
  unsigned Printed = 0;
  for (const auto &[Key, Val] : Entries) {
    OS << "    " << Val << "\t" << Key << "\n";
    if (++Printed >= TopN)
      break;
  }
  if (Entries.size() > TopN)
    OS << "    ... (" << (Entries.size() - TopN) << " more locations)\n";
}

void SourceAggregator::printByLocation(raw_ostream &OS, unsigned TopN) const {
  OS << "  By source location (top " << TopN << "):\n";
  printSorted(OS, ByLocation, TopN);
  OS << "  Resolved: " << Resolved << ", Unresolved: " << Unresolved << "\n";
}

void SourceAggregator::printByFile(raw_ostream &OS, unsigned TopN) const {
  OS << "  By source file (top " << TopN << "):\n";
  printSorted(OS, ByFile, TopN);
}
