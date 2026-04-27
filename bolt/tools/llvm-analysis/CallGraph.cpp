//===- bolt/tools/llvm-analysis/CallGraph.cpp - Unified call graph --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "CallGraph.h"
#include "bolt/Core/BinaryBasicBlock.h"
#include "bolt/Core/BinaryContext.h"
#include "bolt/Core/BinaryFunction.h"
#include "bolt/Core/BinaryFunctionCallGraph.h"
#include "bolt/Profile/ProfileYAMLMapping.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/Remarks/Remark.h"
#include "llvm/Remarks/RemarkFormat.h"
#include "llvm/Remarks/RemarkParser.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Program.h"
#include "llvm/Support/Regex.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/raw_ostream.h"
#include <cmath>
#include <deque>
#include <fstream>

using namespace llvm;
using namespace llvm::bolt;

// ===----------------------------------------------------------------------===//
// Callgraph subcommand options
// ===----------------------------------------------------------------------===//

namespace opts {

extern cl::OptionCategory MatchCategory;
extern cl::SubCommand CallGraphCmd;

cl::opt<std::string>
    CGOutput("o",
             cl::desc("Output directory for call graph files"),
             cl::Required, cl::cat(MatchCategory),
             cl::sub(CallGraphCmd));

cl::opt<std::string>
    CGProfile("profile",
              cl::desc("BOLT YAML profile file for hotness data"),
              cl::Optional, cl::cat(MatchCategory),
              cl::sub(CallGraphCmd));

cl::opt<std::string>
    CGRemarks("remarks",
              cl::desc("Optimization remarks file (YAML or bitstream) for inline decisions"),
              cl::Optional, cl::cat(MatchCategory),
              cl::sub(CallGraphCmd));

cl::opt<std::string>
    CGRemarksFormat("remarks-format",
                    cl::desc("Format of remarks file: yaml, bitstream, or auto"),
                    cl::init("auto"), cl::Optional, cl::cat(MatchCategory),
                    cl::sub(CallGraphCmd));

cl::opt<std::string>
    CGFilter("filter",
             cl::desc("Regex filter to restrict output to matching functions and their neighborhood"),
             cl::Optional, cl::cat(MatchCategory),
             cl::sub(CallGraphCmd));

cl::opt<unsigned>
    CGDepth("depth",
            cl::desc("Maximum call depth from filtered functions"),
            cl::init(2), cl::Optional, cl::cat(MatchCategory),
            cl::sub(CallGraphCmd));

cl::opt<bool>
    CGHotOnly("hot-only",
              cl::desc("Only include functions/edges with non-zero execution count"),
              cl::Optional, cl::cat(MatchCategory),
              cl::sub(CallGraphCmd));

cl::opt<unsigned>
    CGTop("top",
          cl::desc("Only include the top N% of functions by sample count"),
          cl::value_desc("percent"), cl::init(0),
          cl::Optional, cl::cat(MatchCategory),
          cl::sub(CallGraphCmd));

cl::opt<std::string>
    CGSamples("samples",
              cl::desc("Text sample profile (from llvm-profdata merge --text)"),
              cl::Optional, cl::cat(MatchCategory),
              cl::sub(CallGraphCmd));

cl::opt<bool>
    CGInlineTable("inline-table",
                  cl::desc("Print inline amplification table (size x inline count)"),
                  cl::Optional, cl::cat(MatchCategory),
                  cl::sub(CallGraphCmd));

extern cl::opt<std::string> InputFilename;

} // namespace opts

// ===----------------------------------------------------------------------===//
// Call graph data model
// ===----------------------------------------------------------------------===//

namespace {

struct InlineInfo {
  std::string Callee;
  std::string Caller;
  std::string PassName;
  uint64_t Hotness = 0;
  bool HasHotness = false;
  bool AlwaysInline = false;
  std::string SourceFile;
  unsigned SourceLine = 0;

  bool operator==(const InlineInfo &O) const {
    return Callee == O.Callee && Caller == O.Caller &&
           PassName == O.PassName && Hotness == O.Hotness &&
           AlwaysInline == O.AlwaysInline;
  }
};

/// A node in the inline tree: a function inlined at a call site, with its own
/// sample count and recursively inlined children.
struct InlineTreeEntry {
  std::string Name;
  uint64_t Samples = 0;
  unsigned CallSiteLine = 0;
  std::vector<InlineTreeEntry> Children;

  bool operator==(const InlineTreeEntry &O) const {
    return Name == O.Name && Samples == O.Samples &&
           CallSiteLine == O.CallSiteLine && Children == O.Children;
  }
};

struct CGNode {
  std::string Name;
  uint32_t Size = 0;
  uint64_t ExecCount = 0;
  uint64_t Samples = 0;
  bool HasProfile = false;
  double Percentile = 1.0; // 0.0 = hottest, 1.0 = coldest (global rank)
  std::vector<InlineInfo> InlinedCallees;
  std::vector<InlineTreeEntry> InlineTree;
};

struct CGEdge {
  uint32_t SrcIdx = 0;
  uint32_t DstIdx = 0;
  double Weight = 0.0;
  uint64_t CallCount = 0;
  double NormalizedWeight = 0.0;
};

struct UnifiedCallGraph {
  static constexpr unsigned Version = 1;
  std::string BinaryName;
  std::vector<CGNode> Nodes;
  std::vector<CGEdge> Edges;
  StringMap<uint32_t> NameToIdx;
  StringMap<uint32_t> MangledToIdx;

  uint32_t getOrCreateNode(StringRef Name) {
    auto It = NameToIdx.find(Name);
    if (It != NameToIdx.end())
      return It->second;
    uint32_t Idx = Nodes.size();
    Nodes.push_back({Name.str()});
    NameToIdx[Name] = Idx;
    return Idx;
  }

  uint32_t lookupByMangled(StringRef Mangled) const {
    auto It = MangledToIdx.find(Mangled);
    if (It != MangledToIdx.end())
      return It->second;
    return UINT32_MAX;
  }

  uint32_t lookupAny(StringRef Name) const {
    auto It = NameToIdx.find(Name);
    if (It != NameToIdx.end())
      return It->second;
    It = MangledToIdx.find(Name);
    if (It != MangledToIdx.end())
      return It->second;
    return UINT32_MAX;
  }
};

} // anonymous namespace

// ===----------------------------------------------------------------------===//
// YAML serialization for the unified call graph
// ===----------------------------------------------------------------------===//

namespace llvm {
namespace yaml {

template <> struct MappingTraits<InlineInfo> {
  static void mapping(IO &YamlIO, InlineInfo &II) {
    YamlIO.mapRequired("callee", II.Callee);
    YamlIO.mapOptional("caller", II.Caller, std::string());
    YamlIO.mapOptional("pass", II.PassName, std::string());
    YamlIO.mapOptional("hotness", II.Hotness, (uint64_t)0);
    YamlIO.mapOptional("has-hotness", II.HasHotness, false);
    YamlIO.mapOptional("always-inline", II.AlwaysInline, false);
    YamlIO.mapOptional("source-file", II.SourceFile, std::string());
    YamlIO.mapOptional("source-line", II.SourceLine, 0u);
  }
};

template <> struct MappingTraits<InlineTreeEntry> {
  static void mapping(IO &YamlIO, InlineTreeEntry &E) {
    YamlIO.mapRequired("name", E.Name);
    YamlIO.mapOptional("samples", E.Samples, (uint64_t)0);
    YamlIO.mapOptional("call-site-line", E.CallSiteLine, 0u);
    YamlIO.mapOptional("children", E.Children,
                       std::vector<InlineTreeEntry>());
  }
};

template <> struct MappingTraits<CGNode> {
  static void mapping(IO &YamlIO, CGNode &N) {
    YamlIO.mapRequired("name", N.Name);
    YamlIO.mapOptional("size", N.Size, (uint32_t)0);
    YamlIO.mapOptional("exec-count", N.ExecCount, (uint64_t)0);
    YamlIO.mapOptional("samples", N.Samples, (uint64_t)0);
    YamlIO.mapOptional("has-profile", N.HasProfile, false);
    YamlIO.mapOptional("inlined-callees", N.InlinedCallees,
                       std::vector<InlineInfo>());
    YamlIO.mapOptional("inline-tree", N.InlineTree,
                       std::vector<InlineTreeEntry>());
  }
};

template <> struct MappingTraits<CGEdge> {
  static void mapping(IO &YamlIO, CGEdge &E) {
    YamlIO.mapRequired("src", E.SrcIdx);
    YamlIO.mapRequired("dst", E.DstIdx);
    YamlIO.mapOptional("weight", E.Weight, 0.0);
    YamlIO.mapOptional("call-count", E.CallCount, (uint64_t)0);
    YamlIO.mapOptional("normalized-weight", E.NormalizedWeight, 0.0);
  }
};

struct SerializedCallGraph {
  unsigned Version = UnifiedCallGraph::Version;
  std::string BinaryName;
  std::vector<CGNode> Nodes;
  std::vector<CGEdge> Edges;
};

template <> struct MappingTraits<SerializedCallGraph> {
  static void mapping(IO &YamlIO, SerializedCallGraph &CG) {
    YamlIO.mapRequired("version", CG.Version);
    YamlIO.mapRequired("binary-name", CG.BinaryName);
    YamlIO.mapRequired("nodes", CG.Nodes);
    YamlIO.mapRequired("edges", CG.Edges);
  }
};

} // namespace yaml
} // namespace llvm

LLVM_YAML_IS_SEQUENCE_VECTOR(InlineInfo)
LLVM_YAML_IS_SEQUENCE_VECTOR(InlineTreeEntry)
LLVM_YAML_IS_SEQUENCE_VECTOR(CGNode)
LLVM_YAML_IS_SEQUENCE_VECTOR(CGEdge)

// ===----------------------------------------------------------------------===//
// Call graph: YAML emission
// ===----------------------------------------------------------------------===//

static void emitCallGraphYaml(const UnifiedCallGraph &UCG, raw_ostream &OS) {
  yaml::SerializedCallGraph SCG;
  SCG.Version = UnifiedCallGraph::Version;
  SCG.BinaryName = UCG.BinaryName;
  SCG.Nodes = UCG.Nodes;
  SCG.Edges = UCG.Edges;

  yaml::Output YamlOut(OS);
  YamlOut << SCG;
}

// ===----------------------------------------------------------------------===//
// Call graph: DOT emission
// ===----------------------------------------------------------------------===//

static std::string cgHtmlEscape(StringRef S) {
  std::string Out;
  Out.reserve(S.size());
  for (char C : S) {
    switch (C) {
    case '&': Out += "&amp;"; break;
    case '<': Out += "&lt;"; break;
    case '>': Out += "&gt;"; break;
    case '"': Out += "&quot;"; break;
    default: Out += C;
    }
  }
  return Out;
}

/// Map a percentile (0.0 = hottest, 1.0 = coldest) to a color using HSL hue.
/// Hue goes from 0 (red) through 60 (yellow), 120 (green), 180 (cyan)
/// to 240 (blue).  Saturation=100%, Lightness=50%.
static std::string cgHeatColor(double T) {
  if (T < 0.0) T = 0.0;
  if (T > 1.0) T = 1.0;
  // Hue: 0° (red) to 240° (blue)
  double Hue = T * 240.0;
  // Convert HSL(Hue, 100%, 50%) to RGB
  double C = 1.0;  // chroma (S=1, L=0.5 => C=1)
  double X = C * (1.0 - std::fabs(std::fmod(Hue / 60.0, 2.0) - 1.0));
  double R1 = 0, G1 = 0, B1 = 0;
  if (Hue < 60)       { R1 = C; G1 = X; }
  else if (Hue < 120) { R1 = X; G1 = C; }
  else if (Hue < 180) { G1 = C; B1 = X; }
  else                 { G1 = X; B1 = C; }
  unsigned R = static_cast<unsigned>(R1 * 255);
  unsigned G = static_cast<unsigned>(G1 * 255);
  unsigned B = static_cast<unsigned>(B1 * 255);
  char Buf[8];
  snprintf(Buf, sizeof(Buf), "#%02x%02x%02x", R, G, B);
  return Buf;
}

static std::string formatSamples(uint64_t S) {
  char Buf[32];
  if (S >= 1000000000) {
    snprintf(Buf, sizeof(Buf), "%.1fB", S / 1.0e9);
  } else if (S >= 1000000) {
    snprintf(Buf, sizeof(Buf), "%.1fM", S / 1.0e6);
  } else if (S >= 1000) {
    snprintf(Buf, sizeof(Buf), "%.1fK", S / 1.0e3);
  } else {
    snprintf(Buf, sizeof(Buf), "%llu", (unsigned long long)S);
  }
  return Buf;
}

static void emitCallGraphDot(const UnifiedCallGraph &UCG, raw_ostream &OS) {
  // Node colors use the pre-computed global Percentile field (set before
  // filtering), so colors reflect absolute hotness across the entire binary.

  // Sort nodes by ExecCount (descending) for legend cutoff values only.
  std::vector<std::pair<uint64_t, uint32_t>> Ranked;
  for (uint32_t I = 0; I < UCG.Nodes.size(); ++I)
    Ranked.push_back({UCG.Nodes[I].ExecCount, I});
  llvm::sort(Ranked,
             [](const auto &A, const auto &B) { return A.first > B.first; });

  // Build legend HTML for use as the graph label (bottom).
  // Compute the min sample count at each cumulative-weight percentile boundary
  // (matching LLVM's ProfileSummary approach).
  uint64_t TotalWeight = 0;
  for (const auto &P : Ranked)
    TotalWeight += P.first;
  auto getCutoff = [&](double Pct) -> uint64_t {
    if (Ranked.empty() || TotalWeight == 0) return 0;
    uint64_t Target = static_cast<uint64_t>(Pct * TotalWeight);
    uint64_t Cum = 0;
    for (const auto &P : Ranked) {
      Cum += P.first;
      if (Cum >= Target)
        return P.first;
    }
    return 0;
  };

  std::string LegendHtml;
  raw_string_ostream LOS(LegendHtml);
  struct LegendEntry { const char *label; double pct; };
  LegendEntry LegendEntries[] = {
    {"Top 0% (hottest)", 0.00},
    {"Top 10%", 0.10},
    {"Top 25%", 0.25},
    {"Top 50%", 0.50},
    {"Top 75%", 0.75},
    {"Top 99% (LLVM hot cutoff)", 0.99},
    {"Top 100% (coldest)", 1.00},
  };
  LOS << "<TABLE BORDER=\"0\" CELLBORDER=\"0\" CELLSPACING=\"0\">"
      << "<TR><TD><B>Call Graph: " << cgHtmlEscape(UCG.BinaryName)
      << "</B></TD></TR>"
      << "<TR><TD><TABLE BORDER=\"1\" CELLBORDER=\"0\" CELLSPACING=\"0\" "
         "CELLPADDING=\"3\" COLOR=\"#888888\">"
      << "<TR><TD COLSPAN=\"3\" ALIGN=\"CENTER\"><B>Hotness</B></TD></TR>";
  for (const auto &LE : LegendEntries) {
    std::string Color = cgHeatColor(LE.pct);
    uint64_t Cutoff = getCutoff(LE.pct);
    LOS << "<TR><TD BGCOLOR=\"" << Color << "\" WIDTH=\"16\"> </TD>"
        << "<TD ALIGN=\"LEFT\"><FONT POINT-SIZE=\"9\">"
        << LE.label << "</FONT></TD>"
        << "<TD ALIGN=\"RIGHT\"><FONT POINT-SIZE=\"9\">"
        << formatSamples(Cutoff) << "</FONT></TD></TR>";
  }
  LOS << "</TABLE></TD></TR></TABLE>";

  OS << "digraph callgraph {\n";
  OS << "  nodesep=0.8;\n";
  OS << "  ranksep=1.2;\n";
  OS << "  overlap=false;\n";
  OS << "  overlap_shrink=false;\n";
  OS << "  splines=true;\n";
  OS << "  K=8.0;\n";
  OS << "  repulsiveforce=24.0;\n";
  OS << "  smoothing=triangle;\n";
  OS << "  node [shape=plaintext, fontname=\"Helvetica\", fontsize=10];\n";
  OS << "  edge [fontname=\"Courier\", fontsize=9];\n";
  OS << "  label=<" << LegendHtml << ">;\n";
  OS << "  labelloc=t; fontsize=14;\n\n";

  // Compute RPO over the call graph for node emission order.
  // This gives dot a caller-before-callee hint for better hierarchical layout.
  DenseMap<uint32_t, SmallVector<uint32_t, 4>> Succs;
  DenseSet<uint32_t> HasIncoming;
  for (const auto &E : UCG.Edges) {
    Succs[E.SrcIdx].push_back(E.DstIdx);
    HasIncoming.insert(E.DstIdx);
  }
  std::vector<uint32_t> RPO;
  DenseSet<uint32_t> Visited;
  std::function<void(uint32_t)> DFS = [&](uint32_t N) {
    if (!Visited.insert(N).second)
      return;
    if (auto It = Succs.find(N); It != Succs.end())
      for (uint32_t S : It->second)
        DFS(S);
    RPO.push_back(N);
  };
  // Start from roots (nodes with no incoming edges), then remaining.
  for (uint32_t I = 0; I < UCG.Nodes.size(); ++I)
    if (!HasIncoming.contains(I))
      DFS(I);
  for (uint32_t I = 0; I < UCG.Nodes.size(); ++I)
    DFS(I);
  std::reverse(RPO.begin(), RPO.end());

  // Helper to shorten display names: truncate .__uniq.HASH suffixes and cap length.
  auto shortenName = [](StringRef Name) -> std::string {
    std::string S = Name.str();
    // Truncate ".__uniq.NNNNN..." to ".__uniq~"
    auto Pos = S.find(".__uniq.");
    if (Pos != std::string::npos)
      S = S.substr(0, Pos) + ".__uniq~";
    if (S.size() > 50)
      S = S.substr(0, 47) + "...";
    return S;
  };

  // Nodes — emitted in RPO
  for (uint32_t I : RPO) {
    const auto &N = UCG.Nodes[I];

    double Pct = N.Percentile;
    std::string Fill = (N.ExecCount == 0 && !N.HasProfile)
                           ? "#f0f0f0"
                           : cgHeatColor(Pct);
    std::string DisplayName = shortenName(N.Name);

    OS << "  n" << I << " [label=<\n";
    OS << "    <TABLE BORDER=\"1\" CELLBORDER=\"0\" CELLSPACING=\"0\" "
          "CELLPADDING=\"3\" BGCOLOR=\"" << Fill << "\">\n";
    OS << "    <TR><TD ALIGN=\"LEFT\"><B>" << cgHtmlEscape(DisplayName)
       << "</B></TD></TR>\n";
    OS << "    <TR><TD ALIGN=\"LEFT\"><FONT POINT-SIZE=\"8\">"
       << "samples=" << formatSamples(N.ExecCount) << " size=" << N.Size
       << "</FONT></TD></TR>\n";
    OS << "    </TABLE>\n  >];\n";
  }
  OS << "\n";

  // Compute edge percentile using cumulative weight (same approach as nodes).
  std::vector<std::pair<double, unsigned>> EdgeRanked;
  for (unsigned EI = 0; EI < UCG.Edges.size(); ++EI)
    EdgeRanked.push_back({UCG.Edges[EI].Weight, EI});
  llvm::sort(EdgeRanked,
             [](const auto &A, const auto &B) { return A.first > B.first; });
  double TotalEdgeWeight = 0;
  for (const auto &P : EdgeRanked)
    TotalEdgeWeight += P.first;
  DenseMap<unsigned, double> EdgePercentile;
  double CumEdgeWeight = 0;
  for (unsigned R = 0; R < EdgeRanked.size(); ++R) {
    double Pct = TotalEdgeWeight > 0
                     ? CumEdgeWeight / TotalEdgeWeight
                     : 0.0;
    EdgePercentile[EdgeRanked[R].second] = Pct;
    CumEdgeWeight += EdgeRanked[R].first;
  }

  // Call edges — thickness 1–10, colored by same hue percentile
  for (unsigned EI = 0; EI < UCG.Edges.size(); ++EI) {
    const auto &E = UCG.Edges[EI];
    double Pct = EdgePercentile.lookup(EI);
    double PenWidth = 1.0 + 9.0 * (1.0 - Pct); // hot=10, cold=1
    std::string Color = cgHeatColor(Pct);
    OS << "  n" << E.SrcIdx << " -> n" << E.DstIdx
       << " [label=\"" << formatSamples(static_cast<uint64_t>(E.Weight)) << "\"";
    OS << ", penwidth=" << format("%.1f", PenWidth);
    OS << ", color=\"" << Color << "\"";
    OS << ", fontcolor=\"#000000\"";
    OS << "];\n";
  }

  // Dashed edges for inlined callees — high weight pulls them close to parent
  for (uint32_t I = 0; I < UCG.Nodes.size(); ++I) {
    for (const auto &II : UCG.Nodes[I].InlinedCallees) {
      auto It = UCG.NameToIdx.find(II.Callee);
      uint32_t DstIdx = UINT32_MAX;
      if (It != UCG.NameToIdx.end())
        DstIdx = It->second;
      else {
        auto Mt = UCG.MangledToIdx.find(II.Callee);
        if (Mt != UCG.MangledToIdx.end())
          DstIdx = Mt->second;
      }
      if (DstIdx == UINT32_MAX)
        continue;
      OS << "  n" << I << " -> n" << DstIdx
         << " [style=dashed, color=\"#2e7d32\", label=\"inlined\""
         << ", fontcolor=\"#2e7d32\"];\n";
    }
  }

  OS << "}\n";
}

// ===----------------------------------------------------------------------===//
// Inline amplification table
// ===----------------------------------------------------------------------===//

static void emitInlineTable(const UnifiedCallGraph &UCG) {
  // Collect (inlinee_name → {count, total_samples}) across all nodes.
  StringMap<std::pair<unsigned, uint64_t>> InlineeStats;

  // Recursive walk of InlineTree entries.
  std::function<void(const std::vector<InlineTreeEntry> &)> walkTree =
      [&](const std::vector<InlineTreeEntry> &Entries) {
        for (const auto &E : Entries) {
          auto &S = InlineeStats[E.Name];
          S.first++;
          S.second += E.Samples;
          walkTree(E.Children);
        }
      };

  for (const auto &N : UCG.Nodes) {
    walkTree(N.InlineTree);
    for (const auto &II : N.InlinedCallees) {
      auto &S = InlineeStats[II.Callee];
      S.first++;
      S.second += II.Hotness;
    }
  }

  if (InlineeStats.empty()) {
    outs() << "No inline data available.\n";
    return;
  }

  // Build sortable table entries.
  struct TableRow {
    std::string Name;
    uint32_t OrigSize;
    unsigned Count;
    uint64_t TotalSamples;
    uint64_t AmplifiedSize;
  };
  std::vector<TableRow> Rows;
  for (const auto &KV : InlineeStats) {
    TableRow R;
    R.Name = KV.first().str();
    R.Count = KV.second.first;
    R.TotalSamples = KV.second.second;
    // Look up original function size if it exists as a node.
    auto It = UCG.NameToIdx.find(R.Name);
    if (It != UCG.NameToIdx.end())
      R.OrigSize = UCG.Nodes[It->second].Size;
    else {
      // Try with Mach-O underscore prefix.
      auto Mt = UCG.NameToIdx.find(("_" + R.Name));
      if (Mt != UCG.NameToIdx.end())
        R.OrigSize = UCG.Nodes[Mt->second].Size;
      else
        R.OrigSize = 0;
    }
    R.AmplifiedSize = static_cast<uint64_t>(R.OrigSize) * R.Count;
    Rows.push_back(std::move(R));
  }

  llvm::sort(Rows, [](const TableRow &A, const TableRow &B) {
    return A.AmplifiedSize > B.AmplifiedSize;
  });

  outs() << "\nInline Amplification Table (sorted by amplified size):\n";
  outs() << format("  %-12s %-10s %-6s %-12s %s\n",
                   "Amplified", "Original", "Count", "Samples", "Inlinee");
  outs() << "  " << std::string(70, '-') << "\n";
  for (const auto &R : Rows) {
    outs() << "  " << format("%-12s ", formatSamples(R.AmplifiedSize).c_str())
           << format("%-10s ", formatSamples(R.OrigSize).c_str())
           << format("%-6u ", R.Count)
           << format("%-12s ", formatSamples(R.TotalSamples).c_str())
           << R.Name << "\n";
  }
  outs() << "  (" << Rows.size() << " inlinee(s) total)\n";
}

// ===----------------------------------------------------------------------===//
// Call graph: build from BOLT + profile + remarks
// ===----------------------------------------------------------------------===//

/// Strip trailing "(N)" disambiguation suffix from BOLT profile names.
static StringRef stripBoltSuffix(StringRef Name) {
  if (Name.ends_with(")")) {
    auto Pos = Name.rfind('(');
    if (Pos != StringRef::npos) {
      StringRef Inner = Name.substr(Pos + 1, Name.size() - Pos - 2);
      unsigned Dummy;
      if (!Inner.getAsInteger(10, Dummy))
        return Name.substr(0, Pos);
    }
  }
  return Name;
}

static void populateFromBoltCG(UnifiedCallGraph &UCG,
                                BinaryContext &BC,
                                BinaryFunctionCallGraph &BoltCG) {
  // Add nodes
  for (CallGraph::NodeId NId = 0; NId < BoltCG.numNodes(); ++NId) {
    const BinaryFunction *BF = BoltCG.nodeIdToFunc(NId);
    std::string PrintName = BF->getPrintName();
    uint32_t Idx = UCG.getOrCreateNode(PrintName);
    UCG.Nodes[Idx].Size = BoltCG.size(NId);
    UCG.Nodes[Idx].Samples = BoltCG.samples(NId);
    UCG.Nodes[Idx].ExecCount = BF->getKnownExecutionCount();
    UCG.Nodes[Idx].HasProfile = BF->hasProfile();
    // Register mangled name for cross-source matching
    for (StringRef SymName : BF->getNames()) {
      UCG.MangledToIdx.try_emplace(SymName, Idx);
      // Mach-O prefixes symbols with '_'; register the stripped name so
      // opt remarks (which use IR names without the prefix) can match.
      if (SymName.starts_with("_"))
        UCG.MangledToIdx.try_emplace(SymName.drop_front(1), Idx);
    }
  }

  // Add edges
  for (const auto &Arc : BoltCG.arcs()) {
    const BinaryFunction *SrcBF = BoltCG.nodeIdToFunc(Arc.src());
    const BinaryFunction *DstBF = BoltCG.nodeIdToFunc(Arc.dst());
    auto SrcIt = UCG.NameToIdx.find(SrcBF->getPrintName());
    auto DstIt = UCG.NameToIdx.find(DstBF->getPrintName());
    if (SrcIt == UCG.NameToIdx.end() || DstIt == UCG.NameToIdx.end())
      continue;
    CGEdge E;
    E.SrcIdx = SrcIt->second;
    E.DstIdx = DstIt->second;
    E.Weight = Arc.weight();
    E.NormalizedWeight = Arc.normalizedWeight();
    UCG.Edges.push_back(E);
  }
}

static void overlayYamlProfile(UnifiedCallGraph &UCG, StringRef ProfilePath) {
  auto BufOrErr = MemoryBuffer::getFile(ProfilePath);
  if (!BufOrErr) {
    errs() << "llvm-analysis: warning: cannot open profile '"
           << ProfilePath << "': " << BufOrErr.getError().message() << "\n";
    return;
  }

  yaml::Input YamlIn((*BufOrErr)->getBuffer());
  yaml::bolt::BinaryProfile BP;
  YamlIn >> BP;
  if (YamlIn.error()) {
    errs() << "llvm-analysis: warning: failed to parse profile '"
           << ProfilePath << "'\n";
    return;
  }

  // Build fid → function name map for resolving CallSiteInfo.DestId
  DenseMap<uint32_t, StringRef> FidToName;
  for (const auto &Func : BP.Functions)
    FidToName[Func.Id] = Func.Name;

  for (const auto &Func : BP.Functions) {
    StringRef Name = stripBoltSuffix(Func.Name);
    // Try mangled name first, then print name
    uint32_t Idx = UCG.lookupByMangled(Func.Name);
    if (Idx == UINT32_MAX)
      Idx = UCG.lookupByMangled(Name);
    if (Idx == UINT32_MAX)
      Idx = UCG.lookupAny(Func.Name);
    if (Idx == UINT32_MAX)
      Idx = UCG.lookupAny(Name);
    if (Idx == UINT32_MAX)
      continue; // Function not in binary

    if (Func.ExecCount > UCG.Nodes[Idx].ExecCount)
      UCG.Nodes[Idx].ExecCount = Func.ExecCount;
    UCG.Nodes[Idx].HasProfile = true;

    // Enrich edge call counts from block-level call sites
    for (const auto &Block : Func.Blocks) {
      for (const auto &CS : Block.CallSites) {
        auto DestIt = FidToName.find(CS.DestId);
        if (DestIt == FidToName.end())
          continue;
        StringRef DestName = stripBoltSuffix(DestIt->second);
        uint32_t DstIdx = UCG.lookupByMangled(DestIt->second);
        if (DstIdx == UINT32_MAX)
          DstIdx = UCG.lookupByMangled(DestName);
        if (DstIdx == UINT32_MAX)
          DstIdx = UCG.lookupAny(DestIt->second);
        if (DstIdx == UINT32_MAX)
          DstIdx = UCG.lookupAny(DestName);
        if (DstIdx == UINT32_MAX)
          continue;
        // Find matching edge and add call count
        for (auto &E : UCG.Edges) {
          if (E.SrcIdx == Idx && E.DstIdx == DstIdx) {
            E.CallCount += CS.Count;
            break;
          }
        }
      }
    }
  }

  outs() << "Overlaid profile with " << BP.Functions.size()
         << " function(s)\n";
}

static void overlayRemarks(UnifiedCallGraph &UCG, StringRef RemarksPath) {
  auto BufOrErr = MemoryBuffer::getFile(RemarksPath);
  if (!BufOrErr) {
    errs() << "llvm-analysis: warning: cannot open remarks '"
           << RemarksPath << "': " << BufOrErr.getError().message() << "\n";
    return;
  }

  // Detect format
  remarks::Format Fmt = remarks::Format::YAML;
  if (opts::CGRemarksFormat != "auto") {
    auto FmtOrErr = remarks::parseFormat(opts::CGRemarksFormat);
    if (!FmtOrErr) {
      errs() << "llvm-analysis: warning: invalid remarks format '"
             << opts::CGRemarksFormat << "'\n";
      consumeError(FmtOrErr.takeError());
      return;
    }
    Fmt = *FmtOrErr;
  } else {
    // Try auto-detect from magic
    StringRef Content = (*BufOrErr)->getBuffer();
    if (Content.size() >= 7) {
      auto DetectedOrErr = remarks::magicToFormat(Content.substr(0, 7));
      if (DetectedOrErr)
        Fmt = *DetectedOrErr;
      else
        consumeError(DetectedOrErr.takeError());
    }
  }

  auto ParserOrErr = remarks::createRemarkParser(Fmt,
                                                  (*BufOrErr)->getBuffer());
  if (!ParserOrErr) {
    errs() << "llvm-analysis: warning: failed to create remark parser: "
           << toString(ParserOrErr.takeError()) << "\n";
    return;
  }
  auto &Parser = **ParserOrErr;

  unsigned InlineCount = 0;
  while (true) {
    auto RemarkOrErr = Parser.next();
    if (auto Err = RemarkOrErr.takeError()) {
      if (Err.isA<remarks::EndOfFileError>()) {
        consumeError(std::move(Err));
        break;
      }
      errs() << "llvm-analysis: warning: remark parse error: "
             << toString(std::move(Err)) << "\n";
      break;
    }
    const remarks::Remark &R = **RemarkOrErr;

    if (R.RemarkType != remarks::Type::Passed)
      continue;
    if (R.RemarkName != "Inlined" && R.RemarkName != "AlwaysInline")
      continue;

    StringRef Callee, Caller;
    for (const auto &Arg : R.Args) {
      if (Arg.Key == "Callee") Callee = Arg.Val;
      if (Arg.Key == "Caller") Caller = Arg.Val;
    }
    if (Callee.empty() || Caller.empty())
      continue;

    // Find the caller node
    uint32_t CallerIdx = UCG.lookupByMangled(Caller);
    if (CallerIdx == UINT32_MAX)
      CallerIdx = UCG.lookupAny(Caller);
    if (CallerIdx == UINT32_MAX) {
      // Create a synthetic node for the caller
      CallerIdx = UCG.getOrCreateNode(Caller);
    }

    InlineInfo II;
    II.Callee = Callee.str();
    II.Caller = Caller.str();
    II.PassName = R.PassName.str();
    if (R.Hotness) {
      II.Hotness = *R.Hotness;
      II.HasHotness = true;
    }
    II.AlwaysInline = (R.RemarkName == "AlwaysInline");
    if (R.Loc) {
      II.SourceFile = R.Loc->SourceFilePath.str();
      II.SourceLine = R.Loc->SourceLine;
    }
    UCG.Nodes[CallerIdx].InlinedCallees.push_back(std::move(II));
    ++InlineCount;
  }

  outs() << "Parsed " << InlineCount << " inline remark(s)\n";
}

/// Parse a text sample profile (produced by `llvm-profdata merge --text`)
/// and overlay total samples and call-site counts onto the unified call graph.
///
/// Format per function:
///   function_name:total_samples:head_samples
///    line: count [callee:count ...]
///    line.disc: count [callee:count ...]
///    line: inlined_callee:total_samples
///     line: count ...
static void overlaySampleProfile(UnifiedCallGraph &UCG,
                                  StringRef SamplesPath) {
  auto BufOrErr = MemoryBuffer::getFile(SamplesPath);
  if (!BufOrErr) {
    errs() << "llvm-analysis: warning: cannot open samples '"
           << SamplesPath << "': " << BufOrErr.getError().message() << "\n";
    return;
  }

  StringRef Content = (*BufOrErr)->getBuffer();
  SmallVector<StringRef, 0> Lines;
  Content.split(Lines, '\n');

  unsigned FuncsMatched = 0;
  unsigned FuncsTotal = 0;
  uint32_t CurrentNodeIdx = UINT32_MAX;

  // Helper: measure indentation (number of leading spaces).
  auto getIndent = [](StringRef S) -> unsigned {
    unsigned N = 0;
    for (char C : S) {
      if (C == ' ') ++N;
      else break;
    }
    return N;
  };

  // Helper: parse an inlined function header line.
  // Format: " N: funcname:total_samples" or " N: funcname:total:head"
  // Returns true if this is an inline header, filling Name, Samples, Line.
  auto parseInlineHeader = [](StringRef Trimmed, std::string &Name,
                              uint64_t &Samples, unsigned &CallLine) -> bool {
    // Must start with a digit (the call-site line number)
    if (Trimmed.empty() || !isDigit(Trimmed[0]))
      return false;
    auto ColonPos = Trimmed.find(':');
    if (ColonPos == StringRef::npos)
      return false;
    StringRef LineNoStr = Trimmed.substr(0, ColonPos);
    StringRef After = Trimmed.substr(ColonPos + 1).ltrim();
    // After the colon+space, should be "funcname:total..." (not a digit —
    // digit means it's a sample line like "N: count callee:count")
    if (After.empty() || isDigit(After[0]))
      return false;
    // Parse funcname:total[:head]  (at least one colon after funcname)
    auto FC = After.rfind(':');
    if (FC == StringRef::npos || FC == 0)
      return false;
    // The last colon-separated token should be a number (total or head samples)
    StringRef LastToken = After.substr(FC + 1);
    uint64_t Total = 0;
    if (LastToken.getAsInteger(10, Total))
      return false;
    // Check if there's a second colon (funcname:total:head format)
    StringRef BeforeLast = After.substr(0, FC);
    auto SC = BeforeLast.rfind(':');
    if (SC != StringRef::npos && SC > 0) {
      // Could be funcname:total:head — check if the middle token is numeric
      StringRef MidToken = BeforeLast.substr(SC + 1);
      uint64_t MidVal = 0;
      if (!MidToken.getAsInteger(10, MidVal)) {
        // funcname:total:head — Total is MidVal, head is Total
        Name = BeforeLast.substr(0, SC).str();
        Samples = MidVal;
        LineNoStr.getAsInteger(10, CallLine);
        return true;
      }
    }
    // funcname:total (two-token form, or funcname contains colons)
    Name = BeforeLast.str();
    Samples = Total;
    unsigned LN = 0;
    LineNoStr.getAsInteger(10, LN);
    CallLine = LN;
    return true;
  };

  for (unsigned I = 0; I < Lines.size(); ++I) {
    StringRef Line = Lines[I].rtrim('\r');
    if (Line.empty())
      continue;

    // Function header: starts at column 0 (no leading space)
    // Format: function_name:total_samples:head_samples
    if (!Line.starts_with(" ") && !Line.starts_with("\t")) {
      auto FirstColon = Line.find(':');
      if (FirstColon == StringRef::npos)
        continue;
      StringRef FuncName = Line.substr(0, FirstColon);
      StringRef Rest = Line.substr(FirstColon + 1);
      auto SecondColon = Rest.find(':');
      if (SecondColon == StringRef::npos)
        continue;
      StringRef TotalStr = Rest.substr(0, SecondColon);

      uint64_t TotalSamples = 0;
      TotalStr.getAsInteger(10, TotalSamples);

      ++FuncsTotal;

      // Match to a node
      CurrentNodeIdx = UCG.lookupByMangled(FuncName);
      if (CurrentNodeIdx == UINT32_MAX)
        CurrentNodeIdx = UCG.lookupAny(FuncName);
      if (CurrentNodeIdx == UINT32_MAX) {
        std::string WithUnderscore = ("_" + FuncName).str();
        CurrentNodeIdx = UCG.lookupByMangled(WithUnderscore);
        if (CurrentNodeIdx == UINT32_MAX)
          CurrentNodeIdx = UCG.lookupAny(WithUnderscore);
      }

      if (CurrentNodeIdx != UINT32_MAX) {
        UCG.Nodes[CurrentNodeIdx].Samples = TotalSamples;
        if (TotalSamples > UCG.Nodes[CurrentNodeIdx].ExecCount)
          UCG.Nodes[CurrentNodeIdx].ExecCount = TotalSamples;
        UCG.Nodes[CurrentNodeIdx].HasProfile = true;
        ++FuncsMatched;

        // Parse the inline tree for this function.
        // Scan ahead for indented inline headers and build the tree.
        // Use a stack to track nesting: (indent_level, pointer_to_children_vec)
        auto &Tree = UCG.Nodes[CurrentNodeIdx].InlineTree;
        // Stack: (indent, children_vector_ptr)
        SmallVector<std::pair<unsigned, std::vector<InlineTreeEntry> *>, 8>
            Stack;
        Stack.push_back({0, &Tree});

        for (unsigned J = I + 1; J < Lines.size(); ++J) {
          StringRef SubLine = Lines[J].rtrim('\r');
          if (SubLine.empty())
            continue;
          // Stop at next top-level function
          if (!SubLine.starts_with(" ") && !SubLine.starts_with("\t"))
            break;

          unsigned Indent = getIndent(SubLine);
          StringRef Trimmed = SubLine.ltrim();

          // Check if this is an inline function header
          std::string InlineName;
          uint64_t InlineSamples = 0;
          unsigned CallLine = 0;
          if (!parseInlineHeader(Trimmed, InlineName, InlineSamples, CallLine))
            continue;

          // Pop stack to find the right parent
          while (Stack.size() > 1 && Stack.back().first >= Indent)
            Stack.pop_back();

          InlineTreeEntry Entry;
          Entry.Name = std::move(InlineName);
          Entry.Samples = InlineSamples;
          Entry.CallSiteLine = CallLine;
          Stack.back().second->push_back(std::move(Entry));
          // Push this new entry so its children vector is the target
          Stack.push_back(
              {Indent, &Stack.back().second->back().Children});
        }
      }
      continue;
    }

    // Sample line inside a function body (starts with space/tab)
    // Format:  line[.disc]: count [callee:count ...]
    // We extract call targets and their counts to enrich edges.
    if (CurrentNodeIdx == UINT32_MAX)
      continue;

    StringRef Trimmed = Line.ltrim();
    if (Trimmed.empty() || !isDigit(Trimmed[0]))
      continue;

    auto ColonPos = Trimmed.find(':');
    if (ColonPos == StringRef::npos)
      continue;
    StringRef AfterLineNo = Trimmed.substr(ColonPos + 1).ltrim();

    // Parse: count [callee:count ...]
    auto SpacePos = AfterLineNo.find(' ');
    if (SpacePos == StringRef::npos)
      continue;

    StringRef CallTargets = AfterLineNo.substr(SpacePos + 1);
    SmallVector<StringRef, 4> Pairs;
    CallTargets.split(Pairs, ' ', -1, false);
    for (StringRef Pair : Pairs) {
      auto LastColon = Pair.rfind(':');
      if (LastColon == StringRef::npos || LastColon == 0)
        continue;
      StringRef CalleeName = Pair.substr(0, LastColon);
      StringRef CountStr = Pair.substr(LastColon + 1);
      uint64_t Count = 0;
      if (CountStr.getAsInteger(10, Count))
        continue;

      uint32_t CalleeIdx = UCG.lookupByMangled(CalleeName);
      if (CalleeIdx == UINT32_MAX)
        CalleeIdx = UCG.lookupAny(CalleeName);
      if (CalleeIdx == UINT32_MAX) {
        std::string WithUnderscore = ("_" + CalleeName).str();
        CalleeIdx = UCG.lookupByMangled(WithUnderscore);
        if (CalleeIdx == UINT32_MAX)
          CalleeIdx = UCG.lookupAny(WithUnderscore);
      }
      if (CalleeIdx == UINT32_MAX)
        continue;

      bool Found = false;
      for (auto &E : UCG.Edges) {
        if (E.SrcIdx == CurrentNodeIdx && E.DstIdx == CalleeIdx) {
          E.CallCount += Count;
          if (Count > E.Weight)
            E.Weight += Count;
          Found = true;
          break;
        }
      }
      if (!Found) {
        CGEdge E;
        E.SrcIdx = CurrentNodeIdx;
        E.DstIdx = CalleeIdx;
        E.Weight = Count;
        E.CallCount = Count;
        UCG.Edges.push_back(E);
      }
    }
  }

  outs() << "Overlaid sample profile: " << FuncsMatched << "/" << FuncsTotal
         << " functions matched\n";
}

/// Remove nodes not in \p Keep from \p UCG and remap all edge indices.
static void filterNodes(UnifiedCallGraph &UCG, const DenseSet<uint32_t> &Keep) {
  DenseMap<uint32_t, uint32_t> OldToNew;
  std::vector<CGNode> NewNodes;
  for (uint32_t I = 0; I < UCG.Nodes.size(); ++I) {
    if (Keep.contains(I)) {
      OldToNew[I] = NewNodes.size();
      NewNodes.push_back(std::move(UCG.Nodes[I]));
    }
  }
  std::vector<CGEdge> NewEdges;
  for (auto &E : UCG.Edges) {
    auto SrcIt = OldToNew.find(E.SrcIdx);
    auto DstIt = OldToNew.find(E.DstIdx);
    if (SrcIt != OldToNew.end() && DstIt != OldToNew.end()) {
      E.SrcIdx = SrcIt->second;
      E.DstIdx = DstIt->second;
      NewEdges.push_back(std::move(E));
    }
  }
  UCG.Nodes = std::move(NewNodes);
  UCG.Edges = std::move(NewEdges);
  UCG.NameToIdx.clear();
  UCG.MangledToIdx.clear();
  for (uint32_t I = 0; I < UCG.Nodes.size(); ++I)
    UCG.NameToIdx[UCG.Nodes[I].Name] = I;
}

static void applyCallGraphFilter(UnifiedCallGraph &UCG) {
  if (!opts::CGFilter.getNumOccurrences())
    return;

  Regex FilterRegex(opts::CGFilter);
  std::string ErrStr;
  if (!FilterRegex.isValid(ErrStr)) {
    errs() << "llvm-analysis: invalid filter regex: " << ErrStr << "\n";
    return;
  }

  // Find root nodes matching the filter
  DenseSet<uint32_t> Included;
  std::deque<std::pair<uint32_t, unsigned>> Worklist; // (nodeIdx, depth)
  for (uint32_t I = 0; I < UCG.Nodes.size(); ++I) {
    if (FilterRegex.match(UCG.Nodes[I].Name)) {
      Included.insert(I);
      Worklist.push_back({I, 0});
    }
  }

  // Build adjacency for BFS
  DenseMap<uint32_t, SmallVector<uint32_t, 4>> Succs, Preds;
  for (const auto &E : UCG.Edges) {
    Succs[E.SrcIdx].push_back(E.DstIdx);
    Preds[E.DstIdx].push_back(E.SrcIdx);
  }

  // BFS to depth
  unsigned MaxDepth = opts::CGDepth;
  while (!Worklist.empty()) {
    uint32_t NodeIdx = Worklist.front().first;
    unsigned Depth = Worklist.front().second;
    Worklist.pop_front();
    if (Depth >= MaxDepth)
      continue;
    auto AddNeighbors = [&](const SmallVector<uint32_t, 4> &Neighbors) {
      for (uint32_t N : Neighbors) {
        if (Included.insert(N).second)
          Worklist.push_back({N, Depth + 1});
      }
    };
    if (auto It = Succs.find(NodeIdx); It != Succs.end())
      AddNeighbors(It->second);
    if (auto It = Preds.find(NodeIdx); It != Preds.end())
      AddNeighbors(It->second);
  }

  filterNodes(UCG, Included);

  outs() << "Filtered to " << UCG.Nodes.size() << " node(s), "
         << UCG.Edges.size() << " edge(s)\n";
}

/// Run `dot -Tsvg` on a DOT file and wrap the resulting SVG in an HTML page
/// with JavaScript tooltip handling.  Tooltip data is embedded as a JS object
/// keyed by node ID (e.g. "n0", "n1"), avoiding reliance on SVG attributes.
static bool emitCallGraphHtml(StringRef DotPath, StringRef HtmlPath,
                              const UnifiedCallGraph &UCG) {
  auto DotExe = sys::findProgramByName("dot");
  if (!DotExe) {
    errs() << "llvm-analysis: warning: 'dot' not found in PATH, "
           << "cannot generate HTML visualization\n";
    return false;
  }

  std::string SvgPath = (HtmlPath + ".tmp.svg").str();
  StringRef Args[] = {*DotExe, "-Tsvg", DotPath, "-o", SvgPath};
  int Ret = sys::ExecuteAndWait(*DotExe, Args);
  if (Ret != 0) {
    errs() << "llvm-analysis: warning: 'dot -Tsvg' failed (exit code "
           << Ret << ")\n";
    return false;
  }

  auto SvgBuf = MemoryBuffer::getFile(SvgPath);
  if (!SvgBuf) {
    errs() << "llvm-analysis: warning: cannot read SVG output\n";
    return false;
  }
  StringRef SvgContent = (*SvgBuf)->getBuffer();

  auto SvgStart = SvgContent.find("<svg");
  if (SvgStart != StringRef::npos)
    SvgContent = SvgContent.substr(SvgStart);

  // Build tooltip data as JSON-like JS object.
  std::string TooltipData;
  raw_string_ostream TDS(TooltipData);

  // Escape a string for use inside a JS string literal.
  auto jsEsc = [](StringRef S) -> std::string {
    std::string R;
    for (char C : S) {
      if (C == '\\') R += "\\\\";
      else if (C == '"') R += "\\\"";
      else if (C == '\n') R += "\\n";
      else R += C;
    }
    return R;
  };

  // Recursive helper to build inline tree text.
  std::function<void(const std::vector<InlineTreeEntry> &, unsigned)>
      buildTree = [&](const std::vector<InlineTreeEntry> &Entries,
                      unsigned Depth) {
        for (const auto &E : Entries) {
          for (unsigned D = 0; D < Depth; ++D)
            TDS << "  ";
          TDS << jsEsc(E.Name);
          if (E.Samples > 0)
            TDS << " (" << formatSamples(E.Samples) << ")";
          TDS << "\\n";
          buildTree(E.Children, Depth + 1);
        }
      };

  TDS << "{\n";
  for (uint32_t I = 0; I < UCG.Nodes.size(); ++I) {
    const auto &N = UCG.Nodes[I];
    if (I > 0) TDS << ",\n";
    TDS << "  \"n" << I << "\": \"";
    TDS << jsEsc(N.Name) << "\\n";
    TDS << "samples=" << formatSamples(N.ExecCount)
        << " size=" << N.Size << "\\n";
    if (!N.InlineTree.empty()) {
      TDS << "inlined:\\n";
      buildTree(N.InlineTree, 1);
    } else if (!N.InlinedCallees.empty()) {
      TDS << "inlined: ";
      for (unsigned J = 0; J < N.InlinedCallees.size(); ++J) {
        if (J > 0) TDS << ", ";
        TDS << jsEsc(N.InlinedCallees[J].Callee);
      }
      TDS << "\\n";
    }
    TDS << "\"";
  }
  TDS << "\n}";

  std::ofstream Ofs(HtmlPath.str());
  if (!Ofs) {
    errs() << "llvm-analysis: cannot open '" << HtmlPath << "'\n";
    return false;
  }

  Ofs << R"(<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Call Graph</title>
<style>
  body { margin: 0; overflow: auto; background: #fafafa; }
  #container { position: relative; }
  #tooltip {
    display: none; position: fixed; z-index: 1000;
    background: #1e1e1e; color: #d4d4d4; padding: 10px 14px;
    border-radius: 6px; font-family: 'Menlo', 'Consolas', monospace;
    font-size: 12px; line-height: 1.5; max-width: 600px;
    white-space: pre-wrap; pointer-events: none;
    box-shadow: 0 4px 16px rgba(0,0,0,0.3);
  }
  #tooltip .fn-name { color: #569cd6; font-weight: bold; font-size: 13px; }
  #tooltip .stats { color: #9cdcfe; }
  #tooltip .inline-hdr { color: #4ec9b0; font-weight: bold; }
  #tooltip .inline-entry { color: #ce9178; }
  #tooltip .samples { color: #b5cea8; }
</style>
</head><body>
<div id="container">
)";
  Ofs << SvgContent.str();
  Ofs << R"(
</div>
<div id="tooltip"></div>
<script>
const TOOLTIP_DATA = )";
  Ofs << TooltipData;
  Ofs << R"(;
const tooltip = document.getElementById('tooltip');
document.querySelectorAll('g.node').forEach(node => {
  const titleEl = node.querySelector('title');
  if (!titleEl) return;
  const nodeId = titleEl.textContent.trim();
  const raw = TOOLTIP_DATA[nodeId];
  if (!raw) return;
  const lines = raw.split('\n');
  let html = '';
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (i === 0) {
      html += '<span class="fn-name">' + esc(l) + '</span>\n';
    } else if (l.startsWith('samples=')) {
      html += '<span class="stats">' + esc(l) + '</span>\n';
    } else if (l.startsWith('inlined')) {
      html += '<span class="inline-hdr">' + esc(l) + '</span>\n';
    } else if (l.match(/\(\d/)) {
      const m = l.match(/^(.*?)(\([\d.]+[BKMG]?\))$/);
      if (m) {
        html += '<span class="inline-entry">' + esc(m[1]) + '</span>';
        html += '<span class="samples">' + esc(m[2]) + '</span>\n';
      } else {
        html += '<span class="inline-entry">' + esc(l) + '</span>\n';
      }
    } else {
      html += esc(l) + '\n';
    }
  }
  node.addEventListener('mouseenter', e => {
    tooltip.innerHTML = html;
    tooltip.style.display = 'block';
  });
  node.addEventListener('mousemove', e => {
    tooltip.style.left = (e.clientX + 16) + 'px';
    tooltip.style.top = (e.clientY + 16) + 'px';
  });
  node.addEventListener('mouseleave', () => {
    tooltip.style.display = 'none';
  });
});
function esc(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
</script>
</body></html>
)";
  Ofs.close();
  sys::fs::remove(SvgPath);
  return true;
}

void processCallGraph(const BinaryContext &ConstBC) {
  // buildCallGraph() takes non-const BinaryContext& due to iterator types,
  // but only reads data. Safe to cast in analysis mode.
  BinaryContext &BC = const_cast<BinaryContext &>(ConstBC);

  // 1. Build BOLT call graph
  BinaryFunctionCallGraph BoltCG = buildCallGraph(
      BC, /*Filter=*/NoFilter, /*CgFromPerfData=*/false,
      /*IncludeSplitCalls=*/true, /*UseFunctionHotSize=*/false,
      /*UseSplitHotSize=*/false, /*UseEdgeCounts=*/true,
      /*IgnoreRecursiveCalls=*/false);

  outs() << "Built call graph: " << BoltCG.numNodes() << " nodes, "
         << BoltCG.numArcs() << " arcs\n";

  // 2. Populate unified call graph
  UnifiedCallGraph UCG;
  UCG.BinaryName = opts::InputFilename;
  populateFromBoltCG(UCG, BC, BoltCG);

  // 3. Overlay YAML profile
  if (opts::CGProfile.getNumOccurrences())
    overlayYamlProfile(UCG, opts::CGProfile);

  // 3b. Overlay text sample profile
  if (opts::CGSamples.getNumOccurrences())
    overlaySampleProfile(UCG, opts::CGSamples);

  // 4. Parse opt remarks
  if (opts::CGRemarks.getNumOccurrences())
    overlayRemarks(UCG, opts::CGRemarks);

  // 4b. Compute global percentile ranks BEFORE any filtering so colors
  //     reflect absolute hotness, not relative rank within the filtered set.
  {
    std::vector<std::pair<uint64_t, uint32_t>> Ranked;
    for (uint32_t I = 0; I < UCG.Nodes.size(); ++I)
      Ranked.push_back({UCG.Nodes[I].ExecCount, I});
    llvm::sort(Ranked,
               [](const auto &A, const auto &B) { return A.first > B.first; });
    // Use cumulative sample weight to match LLVM's ProfileSummary approach.
    // A function's percentile = (cumulative weight of all hotter functions)
    // / total weight.  This means a function covering most of the total
    // samples is red, while functions contributing negligible weight are blue,
    // regardless of how many functions there are.
    uint64_t TotalWeight = 0;
    for (const auto &P : Ranked)
      TotalWeight += P.first;
    uint64_t CumWeight = 0;
    for (unsigned R = 0; R < Ranked.size(); ++R) {
      double Pct = TotalWeight > 0
                       ? static_cast<double>(CumWeight) / TotalWeight
                       : 0.0;
      UCG.Nodes[Ranked[R].second].Percentile = Pct;
      CumWeight += Ranked[R].first;
    }
  }

  // 5. Apply filter
  applyCallGraphFilter(UCG);

  // 6. Apply hot-only filter
  if (opts::CGHotOnly) {
    // Remove nodes with zero exec count (keep nodes that have profile)
    DenseSet<uint32_t> Hot;
    for (uint32_t I = 0; I < UCG.Nodes.size(); ++I) {
      if (UCG.Nodes[I].ExecCount > 0 || UCG.Nodes[I].HasProfile)
        Hot.insert(I);
    }
    // Also keep targets of hot edges
    for (const auto &E : UCG.Edges) {
      if (E.Weight > 0 || E.CallCount > 0) {
        Hot.insert(E.SrcIdx);
        Hot.insert(E.DstIdx);
      }
    }
    filterNodes(UCG, Hot);

    outs() << "Hot-only filter: " << UCG.Nodes.size() << " node(s), "
           << UCG.Edges.size() << " edge(s)\n";
  }

  // 6b. Apply --top N% filter: keep only the top N% by sample count
  if (opts::CGTop > 0 && opts::CGTop < 100) {
    // Sort nodes by ExecCount descending to find the cutoff
    std::vector<std::pair<uint64_t, uint32_t>> Sorted;
    for (uint32_t I = 0; I < UCG.Nodes.size(); ++I)
      Sorted.push_back({UCG.Nodes[I].ExecCount, I});
    llvm::sort(Sorted,
               [](const auto &A, const auto &B) { return A.first > B.first; });

    unsigned Keep = std::max(1u, (unsigned)(Sorted.size() * opts::CGTop / 100));
    DenseSet<uint32_t> TopSet;
    for (unsigned I = 0; I < Keep && I < Sorted.size(); ++I)
      TopSet.insert(Sorted[I].second);

    filterNodes(UCG, TopSet);

    outs() << "Top " << opts::CGTop << "% filter: "
           << UCG.Nodes.size() << " node(s), "
           << UCG.Edges.size() << " edge(s)\n";
  }

  // 7. Create output directory and emit all files into it.
  std::string OutDir = opts::CGOutput;
  std::error_code DirEC = sys::fs::create_directories(OutDir);
  if (DirEC) {
    errs() << "llvm-analysis: cannot create directory '" << OutDir
           << "': " << DirEC.message() << "\n";
    return;
  }

  // Always emit YAML.
  std::string YamlPath = OutDir + "/callgraph.yaml";
  {
    std::error_code EC;
    raw_fd_ostream YamlFile(YamlPath, EC);
    if (EC) {
      errs() << "llvm-analysis: cannot open '" << YamlPath
             << "': " << EC.message() << "\n";
      return;
    }
    emitCallGraphYaml(UCG, YamlFile);
    outs() << "Wrote " << YamlPath << "\n";
  }

  // Always emit DOT.
  std::string DotPath = OutDir + "/callgraph.dot";
  {
    std::error_code EC;
    raw_fd_ostream DotFile(DotPath, EC);
    if (EC) {
      errs() << "llvm-analysis: cannot open '" << DotPath
             << "': " << EC.message() << "\n";
      return;
    }
    emitCallGraphDot(UCG, DotFile);
    DotFile.close();
    outs() << "Wrote " << DotPath << "\n";
  }

  // Always emit HTML (with interactive tooltips).
  std::string HtmlPath = OutDir + "/callgraph.html";
  if (emitCallGraphHtml(DotPath, HtmlPath, UCG))
    outs() << "Wrote " << HtmlPath << "\n";

  // 8. Optionally print inline amplification table
  if (opts::CGInlineTable)
    emitInlineTable(UCG);
}


