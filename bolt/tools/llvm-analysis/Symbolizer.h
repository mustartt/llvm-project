//===- bolt/tools/llvm-analysis/Symbolizer.h - Source location lookup --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Resolves instruction addresses to source file:line using DWARF debug info
// and aggregates match results by source location.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MATCH_SYMBOLIZER_H
#define LLVM_TOOLS_LLVM_MATCH_SYMBOLIZER_H

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/DebugInfo/Symbolize/Symbolize.h"
#include "llvm/Support/raw_ostream.h"
#include <string>
#include <vector>

namespace llvm {
namespace bolt {
class BinaryContext;
class BinaryFunction;
class BinaryBasicBlock;
} // namespace bolt

namespace match_tool {

/// A resolved source location for a matched instruction.
struct SourceLoc {
  std::string File;
  unsigned Line = 0;
  unsigned Column = 0;
  std::string Function; // Demangled source function name (from DWARF)

  bool valid() const { return !File.empty() && Line != 0; }

  /// Return "file:line" for display.
  std::string str() const {
    if (!valid())
      return "<unknown>";
    return File + ":" + std::to_string(Line);
  }

  /// Return short form: basename of file + line.
  std::string shortStr() const {
    if (!valid())
      return "<unknown>";
    StringRef F(File);
    size_t Slash = F.rfind('/');
    if (Slash != StringRef::npos)
      F = F.substr(Slash + 1);
    return (F + ":" + Twine(Line)).str();
  }
};

/// Wraps LLVMSymbolizer to resolve addresses in a single binary.
class MatchSymbolizer {
  std::unique_ptr<symbolize::LLVMSymbolizer> Sym;
  std::string BinaryPath;
  bool HasDebugInfo = false;

public:
  /// Initialize with the path to the binary being analyzed.
  explicit MatchSymbolizer(StringRef BinaryPath);

  /// Resolve an address to a source location.
  SourceLoc resolve(uint64_t Address);

  /// Resolve the address of an instruction in a BOLT function.
  /// Uses BF.getAddress() + MIB->getOffset(Inst) to compute the address.
  SourceLoc resolve(const bolt::BinaryContext &BC,
                    const bolt::BinaryFunction &BF,
                    const MCInst &Inst);

  /// Returns true if the binary has debug info.
  bool hasDebugInfo() const { return HasDebugInfo; }
};

/// Accumulates per-pattern match counts aggregated by source location.
struct SourceAggregator {
  /// Key: "file:line", Value: count.
  StringMap<unsigned> ByLocation;
  /// Key: "file", Value: count.
  StringMap<unsigned> ByFile;
  /// Total matches with resolved source locations.
  unsigned Resolved = 0;
  /// Total matches without debug info.
  unsigned Unresolved = 0;

  /// Record a match at the given source location.
  void record(const SourceLoc &Loc);

  /// Print aggregated results sorted by frequency.
  void printByLocation(raw_ostream &OS, unsigned TopN = 20) const;
  void printByFile(raw_ostream &OS, unsigned TopN = 20) const;
};

} // namespace match_tool
} // namespace llvm

#endif // LLVM_TOOLS_LLVM_MATCH_SYMBOLIZER_H
