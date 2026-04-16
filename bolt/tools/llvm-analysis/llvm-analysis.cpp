//===- bolt/tools/llvm-analysis/llvm-analysis.cpp -------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Loads a binary via BOLT's infrastructure and matches instruction patterns
// across basic blocks using an SSA-style pattern syntax with def-use chain
// tracking.
//
//===----------------------------------------------------------------------===//

#include "bolt/Core/BinaryBasicBlock.h"
#include "bolt/Core/BinaryContext.h"
#include "bolt/Core/BinaryFunction.h"
#include "bolt/Core/MCPlus.h"
#include "bolt/Rewrite/MachORewriteInstance.h"
#include "bolt/Rewrite/RewriteInstance.h"
#include "bolt/Utils/CommandLineOpts.h"
#include "FilterExpr.h"
#include "Symbolizer.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/SmallBitVector.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/CodeGen/MIRPrinter.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Object/Binary.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/MachO.h"
#include "llvm/Object/MachOUniversal.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Program.h"
#include "llvm/Support/Regex.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ThreadPool.h"
#include "llvm/Support/YAMLParser.h"
#include "llvm/Support/Timer.h"
#include "llvm/Target/TargetMachine.h"
#include <triskel/triskel.hpp>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <optional>

#define DEBUG_TYPE "llvm-analysis"

using namespace llvm;
using namespace object;
using namespace bolt;

namespace opts {

static cl::OptionCategory MatchCategory("llvm-analysis options");

// --- subcommands ---
static cl::SubCommand MatchCmd("match",
    "Match instruction patterns across binary functions");
static cl::SubCommand ExtractCmd("extract",
    "Extract functions as MIR files in Machine SSA form");

static cl::opt<std::string> InputFilename(cl::Positional,
                                          cl::desc("<executable>"),
                                          cl::Required,
                                          cl::cat(MatchCategory),
                                          cl::sub(MatchCmd),
                                          cl::sub(ExtractCmd));

static cl::opt<std::string>
    ArchName("arch", cl::desc("architecture slice for universal binaries"),
             cl::Optional, cl::cat(MatchCategory),
             cl::sub(MatchCmd),
             cl::sub(ExtractCmd));

static cl::opt<std::string>
    PatternFilename("pattern", cl::desc("pattern file for matching"),
                    cl::Optional, cl::cat(MatchCategory),
                    cl::sub(MatchCmd));

static cl::opt<std::string>
    SuiteFilename("suite", cl::desc("YAML suite file with multiple patterns"),
                  cl::Optional, cl::cat(MatchCategory),
                  cl::sub(MatchCmd));

static cl::opt<bool>
    DumpLiveness("dump-liveness", cl::desc("dump live-in/live-out per BB"),
                 cl::Optional, cl::cat(MatchCategory),
                 cl::sub(MatchCmd));

static cl::opt<bool>
    DumpFunctions("dump-functions", cl::desc("dump disassembled functions"),
                  cl::Optional, cl::cat(MatchCategory),
                  cl::sub(MatchCmd));

static cl::opt<unsigned>
    ThreadCount("j", cl::desc("number of threads (0 = hardware concurrency)"),
                cl::init(0), cl::Optional, cl::cat(MatchCategory),
                cl::sub(MatchCmd),
                cl::sub(ExtractCmd));

static cl::opt<bool>
    DumpPattern("dump-pattern", cl::desc("print parsed pattern as a graph"),
                cl::Optional, cl::cat(MatchCategory),
                cl::sub(MatchCmd));

static cl::opt<std::string>
    DumpPatternDot("dump-pattern-dot",
                   cl::desc("emit pattern graph as Graphviz DOT to file"),
                   cl::value_desc("filename"),
                   cl::Optional, cl::cat(MatchCategory),
                   cl::sub(MatchCmd));

static cl::opt<std::string>
    DumpGraph("dump-graph",
              cl::desc("emit def-use graph as DOT for functions matching regex"),
              cl::value_desc("regex"),
              cl::Optional, cl::cat(MatchCategory),
              cl::sub(MatchCmd));

static cl::opt<std::string>
    DumpSvg("dump-svg",
            cl::desc("emit CFG as SVG for functions matching regex (uses Triskel SESE layout)"),
            cl::value_desc("regex"),
            cl::Optional, cl::cat(MatchCategory),
            cl::sub(MatchCmd));

enum OutputMode { OM_Count, OM_Summary, OM_Detailed };
static cl::opt<OutputMode> OutputLevel(
    cl::desc("output verbosity (default: count only)"),
    cl::values(clEnumValN(OM_Summary, "summary",
                          "show per-function hit counts sorted by frequency"),
               clEnumValN(OM_Detailed, "detailed",
                          "show every individual match (verbose)")),
    cl::init(OM_Count), cl::cat(MatchCategory),
    cl::sub(MatchCmd));

static cl::opt<bool>
    TimeOpt("time", cl::desc("print timing breakdown"),
            cl::Optional, cl::cat(MatchCategory),
            cl::sub(MatchCmd));

static cl::opt<unsigned>
    ContextLines("context",
                 cl::desc("show N instructions of context around each match"),
                 cl::value_desc("N"), cl::init(0), cl::Optional,
                 cl::cat(MatchCategory), cl::sub(MatchCmd));

static cl::opt<bool>
    SymbolizeOpt("symbolize",
                 cl::desc("resolve matches to source locations (requires debug info)"),
                 cl::Optional, cl::cat(MatchCategory), cl::sub(MatchCmd));

static cl::opt<std::string>
    OutDir("out-dir",
           cl::desc("Output directory for .mir files"),
           cl::Required, cl::cat(MatchCategory),
           cl::sub(ExtractCmd));

static cl::opt<std::string>
    ExtractFilter("filter",
                  cl::desc("Regex filter for function names to extract"),
                  cl::Optional, cl::cat(MatchCategory),
                  cl::sub(ExtractCmd));

} // namespace opts

static StringRef ToolName = "llvm-analysis";

static TimerGroup TG("llvm-analysis", "llvm-analysis timing");
static Timer TBinary("binary", "Binary loading", TG);
static Timer TMatch("match", "Pattern matching", TG);

static void report_error(StringRef Message, std::error_code EC) {
  assert(EC);
  errs() << ToolName << ": '" << Message << "': " << EC.message() << ".\n";
  exit(1);
}

static void report_error(StringRef Message, Error E) {
  assert(E);
  errs() << ToolName << ": '" << Message << "': " << toString(std::move(E))
         << ".\n";
  exit(1);
}

static std::string GetExecutablePath(const char *Argv0) {
  SmallString<256> ExecutablePath(Argv0);
  if (!llvm::sys::fs::exists(ExecutablePath))
    if (llvm::ErrorOr<std::string> P =
            llvm::sys::findProgramByName(ExecutablePath))
      ExecutablePath = *P;
  return std::string(ExecutablePath.str());
}

// Forward declarations.
static SmallVector<StringRef, 4> splitOperands(StringRef S);

// ===----------------------------------------------------------------------===//
// Data structures
// ===----------------------------------------------------------------------===//

/// Parsed assembly operand — either a leaf token or a bracketed group.
struct AsmOperand {
  std::string Text;                        // Leaf text (e.g., "x0", "#8")
  std::vector<AsmOperand> Children;        // Non-empty for memory operands
  bool PreIndex = false;                   // [...]! form

  bool isMem() const { return !Children.empty(); }
};

// Forward declarations needed by InstrNode::ensureParsed.
static AsmOperand parseAsmOperand(StringRef Token);
static void parseAsmText(const BinaryContext &BC, const MCInst &Inst,
                         std::string &Mnemonic,
                         SmallVectorImpl<AsmOperand> &Operands);

struct InstrNode {
  const MCInst *Inst;
  mutable std::string Mnemonic;     // Assembly mnemonic, lazily populated
  mutable SmallVector<AsmOperand, 4> Operands; // Pre-parsed operand tree, lazy
  mutable bool Parsed = false;      // Whether Mnemonic/Operands are populated
  unsigned BBIndex;
  unsigned InstIndex;       // Index within BB
  SmallVector<MCPhysReg, 4> Defs; // Registers defined (explicit + implicit)
  SmallVector<MCPhysReg, 4> Uses; // Registers used (explicit + implicit)

  /// Ensure Mnemonic and Operands are populated (lazy printInst).
  void ensureParsed(const BinaryContext &BC) const {
    if (Parsed)
      return;
    parseAsmText(BC, *Inst, Mnemonic, Operands);
    Parsed = true;
  }
};

struct BBInfo {
  const BinaryBasicBlock *BB;
  std::vector<InstrNode> Nodes;
  BitVector LiveIn;
  BitVector LiveOut;
};

// ===----------------------------------------------------------------------===//
// Def-use graph
// ===----------------------------------------------------------------------===//

using NodeID = unsigned;

struct DefUseEdge {
  NodeID Def;       // The defining instruction (node index in flat vector)
  NodeID Use;       // The using instruction (node index in flat vector)
  MCPhysReg Reg;    // Register connecting them
};

struct DefUseGraph {
  std::vector<InstrNode> Nodes;          // Flat: all BBs concatenated
  std::vector<unsigned> BBStart;         // BBStart[i] = first NodeID of BB i
  std::vector<DefUseEdge> Edges;
  // Per-node adjacency: maps NodeID → indices into Edges
  DenseMap<NodeID, SmallVector<unsigned, 4>> OutEdges; // edges where node is Def
  DenseMap<NodeID, SmallVector<unsigned, 4>> InEdges;  // edges where node is Use
};

static DefUseGraph buildDefUseGraph(const std::vector<BBInfo> &AllBBs,
                                    const BinaryContext &BC) {
  const MCRegisterInfo &MRI = *BC.MRI;
  DefUseGraph G;

  // Step 1: Flatten all InstrNodes, record BB start offsets.
  for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
    G.BBStart.push_back(G.Nodes.size());
    for (const InstrNode &N : AllBBs[BBIdx].Nodes)
      G.Nodes.push_back(N);
  }

  // Precompute callee-saved regunit set for call clobbering.
  unsigned NumRegs = MRI.getNumRegs();
  BitVector CalleeSaved(NumRegs);
  BC.MIB->getCalleeSavedRegs(CalleeSaved);
  // Expand to include sub-registers of callee-saved regs.
  BitVector CalleeSavedExpanded(CalleeSaved);
  for (unsigned Reg : CalleeSaved.set_bits()) {
    for (MCPhysReg Sub : MRI.subregs(Reg))
      CalleeSavedExpanded.set(Sub);
  }
  // Collect callee-saved regunits.
  DenseSet<unsigned> CalleeSavedRUs;
  for (unsigned Reg : CalleeSavedExpanded.set_bits()) {
    for (MCRegUnit RU : MRI.regunits(Reg))
      CalleeSavedRUs.insert(static_cast<unsigned>(RU));
  }

  // Step 2: Within each BB, track last definer per register unit.
  // Using register units instead of MCPhysReg handles aliasing:
  // W0/X0 share a regunit, as do Q0/V0/D0/S0/B0/H0.
  // Store per-BB last-def maps for cross-BB edges.
  std::vector<DenseMap<unsigned, NodeID>> PerBBLastDef(AllBBs.size());

  for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
    unsigned Start = G.BBStart[BBIdx];
    unsigned End = (BBIdx + 1 < AllBBs.size()) ? G.BBStart[BBIdx + 1]
                                                : G.Nodes.size();
    DenseMap<unsigned, NodeID> LastDef;

    for (unsigned NID = Start; NID < End; ++NID) {
      const InstrNode &Node = G.Nodes[NID];

      // Add edges: for each use register, check if any of its regunits
      // has a last definer.  Use a set to avoid duplicate edges to the
      // same definer.
      DenseSet<NodeID> SeenDefs;
      for (MCPhysReg Reg : Node.Uses) {
        for (MCRegUnit RU : MRI.regunits(Reg)) {
          auto It = LastDef.find(static_cast<unsigned>(RU));
          if (It != LastDef.end() && SeenDefs.insert(It->second).second) {
            unsigned EIdx = G.Edges.size();
            G.Edges.push_back({It->second, NID, Reg});
            G.OutEdges[It->second].push_back(EIdx);
            G.InEdges[NID].push_back(EIdx);
          }
        }
      }

      // Update last definer for each regunit of each def.
      for (MCPhysReg Reg : Node.Defs)
        for (MCRegUnit RU : MRI.regunits(Reg))
          LastDef[static_cast<unsigned>(RU)] = NID;

      // Calls clobber all caller-saved registers.  MCInstrDesc only lists LR
      // as an implicit def of BL, but a call actually destroys X0-X17, D0-D31,
      // NZCV, etc.  Kill those LastDef entries so no stale def-use edges cross
      // the call boundary.
      if (BC.MIB->isCall(*Node.Inst)) {
        SmallVector<unsigned, 16> ToErase;
        for (auto &KV : LastDef) {
          if (!CalleeSavedRUs.count(KV.first) && KV.second != NID)
            ToErase.push_back(KV.first);
        }
        for (unsigned RU : ToErase)
          LastDef.erase(RU);
      }
    }

    PerBBLastDef[BBIdx] = std::move(LastDef);
  }

  // Step 3: Cross-BB edges via reaching definitions.
  // For each live-in use in a BB, walk backward through the CFG to find the
  // reaching definition.  This handles cases where a value flows through
  // intermediate blocks that don't redefine the register (e.g., BB0 defines x8,
  // BB1 passes it through, BB2 uses it).  For loops, we also get back-edge
  // connections (a BB can be its own predecessor).
  DenseMap<const BinaryBasicBlock *, unsigned> BBPtrToIdx;
  for (unsigned I = 0; I < AllBBs.size(); ++I)
    BBPtrToIdx[AllBBs[I].BB] = I;

  // Precompute which regunits are killed (redefined) in each BB.
  // A regunit is killed if any instruction in the BB defines a register that
  // covers it, OR if the BB contains a call (which clobbers caller-saved).
  std::vector<DenseSet<unsigned>> BBKilledRUs(AllBBs.size());
  for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
    unsigned Start = G.BBStart[BBIdx];
    unsigned End = (BBIdx + 1 < AllBBs.size()) ? G.BBStart[BBIdx + 1]
                                                : G.Nodes.size();
    for (unsigned NID = Start; NID < End; ++NID) {
      const InstrNode &Node = G.Nodes[NID];
      for (MCPhysReg Reg : Node.Defs)
        for (MCRegUnit RU : MRI.regunits(Reg))
          BBKilledRUs[BBIdx].insert(static_cast<unsigned>(RU));
      if (BC.MIB->isCall(*Node.Inst)) {
        for (unsigned RU = 0, E = MRI.getNumRegUnits(); RU < E; ++RU)
          if (!CalleeSavedRUs.count(RU))
            BBKilledRUs[BBIdx].insert(RU);
      }
    }
  }

  // findReachingDefs: for a given regunit, walk backward from a BB through
  // its predecessors, collecting all NodeIDs that are the last def of that
  // regunit.  Stops at BBs that define (kill) the regunit, or at visited BBs.
  auto findReachingDefs = [&](unsigned StartBBIdx, unsigned RU,
                              SmallVectorImpl<NodeID> &Defs) {
    SmallVector<unsigned, 8> Worklist;
    DenseSet<unsigned> Visited;

    // Seed with direct predecessors.
    for (const BinaryBasicBlock *Pred : AllBBs[StartBBIdx].BB->predecessors()) {
      auto PredIt = BBPtrToIdx.find(Pred);
      if (PredIt != BBPtrToIdx.end())
        Worklist.push_back(PredIt->second);
    }

    while (!Worklist.empty()) {
      unsigned BBIdx = Worklist.pop_back_val();
      if (!Visited.insert(BBIdx).second)
        continue;

      auto DefIt = PerBBLastDef[BBIdx].find(RU);
      if (DefIt != PerBBLastDef[BBIdx].end()) {
        // This BB defines the regunit — record the defining node.
        Defs.push_back(DefIt->second);
        // Don't continue past this BB (the def blocks further search).
      } else {
        // This BB doesn't define the regunit — continue through its preds.
        for (const BinaryBasicBlock *Pred :
             AllBBs[BBIdx].BB->predecessors()) {
          auto PredIt = BBPtrToIdx.find(Pred);
          if (PredIt != BBPtrToIdx.end())
            Worklist.push_back(PredIt->second);
        }
      }
    }
  };

  for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
    unsigned Start = G.BBStart[BBIdx];
    unsigned End = (BBIdx + 1 < AllBBs.size()) ? G.BBStart[BBIdx + 1]
                                                : G.Nodes.size();

    // Find registers used before being defined in this BB (live-in uses).
    DenseSet<unsigned> DefinedSoFar;
    SmallVector<std::pair<MCPhysReg, NodeID>, 8> LiveInUses;

    for (unsigned NID = Start; NID < End; ++NID) {
      const InstrNode &Node = G.Nodes[NID];
      for (MCPhysReg Reg : Node.Uses) {
        bool AllDefined = true;
        for (MCRegUnit RU : MRI.regunits(Reg)) {
          if (!DefinedSoFar.count(static_cast<unsigned>(RU))) {
            AllDefined = false;
            break;
          }
        }
        if (!AllDefined)
          LiveInUses.push_back({Reg, NID});
      }
      for (MCPhysReg Reg : Node.Defs)
        for (MCRegUnit RU : MRI.regunits(Reg))
          DefinedSoFar.insert(static_cast<unsigned>(RU));
      if (BC.MIB->isCall(*Node.Inst)) {
        for (unsigned RU = 0, E = MRI.getNumRegUnits(); RU < E; ++RU) {
          if (!CalleeSavedRUs.count(RU))
            DefinedSoFar.insert(RU);
        }
      }
    }

    // For each live-in use, find all reaching definitions via CFG walk.
    DenseSet<std::pair<NodeID, NodeID>> SeenEdges;
    for (const auto &[Reg, UseNID] : LiveInUses) {
      for (MCRegUnit RU : MRI.regunits(Reg)) {
        SmallVector<NodeID, 4> ReachingDefs;
        findReachingDefs(BBIdx, static_cast<unsigned>(RU), ReachingDefs);
        for (NodeID DefNID : ReachingDefs) {
          if (!SeenEdges.insert({DefNID, UseNID}).second)
            continue;
          unsigned EIdx = G.Edges.size();
          G.Edges.push_back({DefNID, UseNID, Reg});
          G.OutEdges[DefNID].push_back(EIdx);
          G.InEdges[UseNID].push_back(EIdx);
        }
        // Only process the first regunit that has reaching defs.
        if (!ReachingDefs.empty())
          break;
      }
    }
  }

  return G;
}

// ===----------------------------------------------------------------------===//
// Pattern types
// ===----------------------------------------------------------------------===//

// A single operand slot in a pattern line.
struct PatternOperand {
  enum Kind { Literal, Capture, Wildcard, Rest, MemOperand };
  Kind K;
  std::string Name;       // capture name (without %)
  std::string Type;       // wreg, xreg, reg, imm, nzcv, label
  std::string Prefix;     // literal prefix like "#"
  std::string Text;       // literal text or regex pattern
  bool IsRegex = false;
  std::vector<PatternOperand> SubOperands;  // for MemOperand
  bool PreIndex = false;  // [...]! form
};

struct Annotation {
  enum Kind { Defs, Uses, OneUse, HasUse, SameBB, Filter };
  Kind K;
  std::vector<PatternOperand> Operands;  // for @defs/@uses
  std::vector<std::string> Names;        // for @one_use/@has_use/@same_bb
  std::string FilterExpr;               // for @filter: raw expression string
};

struct PatternLine {
  std::string Mnemonic;
  std::string MnemRegex;       // from {{regex}} mnemonic
  std::vector<PatternOperand> Operands;
  std::vector<Annotation> Annotations;
  bool IsAnnotationOnly = false;  // line is just @constraint(s)
  bool IsDefAnchor = false;       // @def(%v) — matches any instruction defining %v
  SmallVector<std::string, 2> DefAnchorNames; // capture names from @def(...)
};

// A bound value from matching.
using Binding = llvm::filter_expr::Binding;
using FilterExprParser = llvm::filter_expr::FilterExprParser;

// ===----------------------------------------------------------------------===//
// Liveness analysis
// ===----------------------------------------------------------------------===//

static void computeInstrDefsUses(const BinaryContext &BC, const MCInst &Inst,
                                 SmallVectorImpl<MCPhysReg> &Defs,
                                 SmallVectorImpl<MCPhysReg> &Uses) {
  const MCInstrDesc &Desc = BC.MII->get(Inst.getOpcode());

  // Explicit operands.
  for (unsigned I = 0, E = Inst.getNumOperands(); I < E; ++I) {
    const MCOperand &Op = Inst.getOperand(I);
    if (!Op.isReg() || Op.getReg() == 0)
      continue;
    if (I < Desc.getNumDefs())
      Defs.push_back(Op.getReg());
    else
      Uses.push_back(Op.getReg());
  }

  // Implicit defs/uses from MCInstrDesc.
  for (MCPhysReg Reg : Desc.implicit_defs())
    Defs.push_back(Reg);
  for (MCPhysReg Reg : Desc.implicit_uses())
    Uses.push_back(Reg);
}

// Parse a single operand token into an AsmOperand, handling brackets recursively.
static AsmOperand parseAsmOperand(StringRef Token) {
  AsmOperand Op;
  Token = Token.trim();

  // Check for bracketed memory operand: [base, offset] or [base, offset]!
  if (Token.starts_with("[")) {
    StringRef Inner = Token;
    if (Inner.ends_with("!")) {
      Op.PreIndex = true;
      Inner = Inner.drop_back(1);
    }
    if (Inner.ends_with("]"))
      Inner = Inner.drop_front(1).drop_back(1);
    else
      Inner = Inner.drop_front(1); // malformed, best-effort

    // Recursively parse sub-operands.
    SmallVector<StringRef, 4> Parts = splitOperands(Inner);
    for (StringRef P : Parts) {
      P = P.trim();
      if (!P.empty())
        Op.Children.push_back(parseAsmOperand(P));
    }
    // Store the full text too for fallback/display.
    Op.Text = Token.str();
    return Op;
  }

  Op.Text = Token.str();
  return Op;
}

// E.g., "ldrb\tw12, [x0, #8]" -> ("ldrb", [AsmOperand("w12"), AsmOperand{Children: ["x0", "#8"]}])
static void parseAsmText(const BinaryContext &BC, const MCInst &Inst,
                         std::string &Mnemonic,
                         SmallVectorImpl<AsmOperand> &Operands) {
  std::string Buf;
  raw_string_ostream OS(Buf);
  BC.InstPrinter->printInst(&Inst, 0, "", *BC.STI, OS);
  StringRef S(Buf);
  S = S.ltrim();

  // Strip trailing BOLT annotation comments (e.g., "# imp-def: NZCV").
  size_t HashPos = S.find("  #");
  if (HashPos != StringRef::npos)
    S = S.substr(0, HashPos);
  S = S.rtrim();

  // Split mnemonic from operands.
  auto [M, Rest] = S.split('\t');
  if (M.empty())
    std::tie(M, Rest) = S.split(' ');
  Mnemonic = M.str();

  // Parse operands into AsmOperand tree.
  if (!Rest.empty()) {
    SmallVector<StringRef, 4> Parts = splitOperands(Rest);
    for (StringRef P : Parts) {
      P = P.trim();
      if (!P.empty())
        Operands.push_back(parseAsmOperand(P));
    }
  }
}

static std::vector<BBInfo> buildBBInfos(const BinaryContext &BC,
                                        const BinaryFunction &BF,
                                        bool ComputeLiveness = true) {
  unsigned NumRegs = BC.MRI->getNumRegs();
  std::vector<BBInfo> Infos;
  Infos.reserve(BF.size());

  unsigned BBIdx = 0;
  for (const BinaryBasicBlock &BB : BF) {
    BBInfo Info;
    Info.BB = &BB;
    if (ComputeLiveness) {
      Info.LiveIn.resize(NumRegs);
      Info.LiveOut.resize(NumRegs);
    }

    unsigned InstIdx = 0;
    for (const MCInst &Inst : BB) {
      InstrNode Node;
      Node.Inst = &Inst;
      Node.BBIndex = BBIdx;
      Node.InstIndex = InstIdx++;

      computeInstrDefsUses(BC, Inst, Node.Defs, Node.Uses);
      Info.Nodes.push_back(std::move(Node));
    }

    Infos.push_back(std::move(Info));
    ++BBIdx;
  }

  // Compute liveness only when needed (linear matcher uses it for cross-BB
  // matching; graph matcher builds its own def-use edges instead).
  if (ComputeLiveness) {
  // First pass: compute local live-in from instructions.
  for (auto &Info : Infos) {
    BitVector Live(NumRegs);
    // Walk backward.
    for (auto It = Info.Nodes.rbegin(), E = Info.Nodes.rend(); It != E; ++It) {
      // Kill defs.
      for (MCPhysReg Reg : It->Defs)
        Live.reset(Reg);
      // Gen uses.
      for (MCPhysReg Reg : It->Uses)
        Live.set(Reg);
    }
    Info.LiveIn = Live;
  }

  // Build BB pointer to index map.
  DenseMap<const BinaryBasicBlock *, unsigned> BBToIdx;
  for (unsigned I = 0, E = Infos.size(); I < E; ++I)
    BBToIdx[Infos[I].BB] = I;

  // Iterative live-out computation: live-out(B) = union of live-in(succ(B)).
  // Then recompute live-in incorporating live-out.
  bool Changed = true;
  while (Changed) {
    Changed = false;
    for (auto &Info : Infos) {
      BitVector NewLiveOut(NumRegs);
      for (const BinaryBasicBlock *Succ : Info.BB->successors()) {
        auto It = BBToIdx.find(Succ);
        if (It != BBToIdx.end())
          NewLiveOut |= Infos[It->second].LiveIn;
      }
      if (NewLiveOut != Info.LiveOut) {
        Info.LiveOut = NewLiveOut;
        // Recompute live-in: start from live-out, walk backward.
        BitVector Live = Info.LiveOut;
        for (auto It = Info.Nodes.rbegin(), E = Info.Nodes.rend(); It != E;
             ++It) {
          for (MCPhysReg Reg : It->Defs)
            Live.reset(Reg);
          for (MCPhysReg Reg : It->Uses)
            Live.set(Reg);
        }
        if (Live != Info.LiveIn) {
          Info.LiveIn = Live;
          Changed = true;
        }
      }
    }
  }
  } // ComputeLiveness

  return Infos;
}

// ===----------------------------------------------------------------------===//
// Pattern parser
// ===----------------------------------------------------------------------===//

// Parse a pattern file into PatternLine structs.
// SSA-style syntax:
//   # comment
//   ldrb %v:wreg, [%base:xreg, #%off:imm]
//   sxtb %s:wreg, %v
//   root cmp %s, #0                        @defs %fl:nzcv
//   {{regex}} ..., ...                      @uses %fl
//
// Types: wreg, xreg, reg, imm, nzcv, label
// Wildcards: _ (any), _:wreg (typed), ... (rest), {{regex}} (mnemonic)
// Annotations: @defs %fl:nzcv, @uses %fl, @one_use(%v), @has_use(%r),
//              @same_bb, @same_bb(%v, %s)
// Addressing: [%b:xreg], [%b:xreg, #%o:imm], [%b, #%o]!, [%b], #%o

// Helper: check if a string contains {{...}} and extract the regex.
static bool extractRegex(StringRef S, std::string &Before, std::string &Regex,
                         std::string &After) {
  size_t Start = S.find("{{");
  if (Start == StringRef::npos)
    return false;
  size_t End = S.find("}}", Start + 2);
  if (End == StringRef::npos)
    return false;
  Before = S.substr(0, Start).str();
  Regex = S.substr(Start + 2, End - Start - 2).str();
  After = S.substr(End + 2).str();
  return true;
}

// Bracket-aware comma splitting. Keeps [%base:xreg, #%off:imm] as one token.
static SmallVector<StringRef, 4> splitOperands(StringRef S) {
  SmallVector<StringRef, 4> Result;
  unsigned Depth = 0;
  unsigned Start = 0;
  for (unsigned I = 0; I < S.size(); ++I) {
    if (S[I] == '[')
      Depth++;
    else if (S[I] == ']')
      Depth--;
    else if (S[I] == ',' && Depth == 0) {
      StringRef Token = S.substr(Start, I - Start).trim();
      if (!Token.empty())
        Result.push_back(Token);
      Start = I + 1;
    }
  }
  StringRef Last = S.substr(Start).trim();
  if (!Last.empty())
    Result.push_back(Last);
  return Result;
}

// Parse a single operand token into a PatternOperand (v2 SSA syntax).
static PatternOperand parseOperandV2(StringRef OpStr) {
  PatternOperand PO;
  OpStr = OpStr.trim();

  // Rest: ...
  if (OpStr == "...") {
    PO.K = PatternOperand::Rest;
    return PO;
  }

  // MemOperand: [...]  or [...]!
  if (OpStr.starts_with("[")) {
    PO.K = PatternOperand::MemOperand;
    StringRef Inner = OpStr;
    // Check for pre-index: [...]!
    if (Inner.ends_with("!")) {
      PO.PreIndex = true;
      Inner = Inner.drop_back(1);
    }
    // Strip brackets.
    if (Inner.ends_with("]"))
      Inner = Inner.drop_back(1);
    Inner = Inner.drop_front(1); // drop '['

    // Recurse for sub-operands.
    SmallVector<StringRef, 4> SubParts = splitOperands(Inner);
    for (StringRef Sub : SubParts)
      PO.SubOperands.push_back(parseOperandV2(Sub));
    return PO;
  }

  // Check for # prefix followed by capture/wildcard.
  std::string Prefix;
  StringRef Rest = OpStr;
  if (Rest.starts_with("#")) {
    Prefix = "#";
    Rest = Rest.drop_front(1);
  }

  // Pure {{regex}} — anonymous wildcard.
  if (Rest.starts_with("{{") && Rest.ends_with("}}")) {
    PO.K = PatternOperand::Wildcard;
    PO.Text = Rest.substr(2, Rest.size() - 4).str();
    PO.IsRegex = true;
    PO.Prefix = Prefix;
    return PO;
  }

  // Capture: %name:type or %name (back-reference)
  if (Rest.starts_with("%")) {
    Rest = Rest.drop_front(1); // drop '%'
    PO.K = PatternOperand::Capture;
    PO.Prefix = Prefix;
    if (Rest.contains(':')) {
      auto [N, T] = Rest.split(':');
      PO.Name = N.str();
      PO.Type = T.str();
    } else {
      PO.Name = Rest.str();
      // Empty type = back-reference or generic capture.
    }
    return PO;
  }

  // Typed wildcard: _:type
  if (Rest.starts_with("_:")) {
    PO.K = PatternOperand::Wildcard;
    PO.Type = Rest.drop_front(2).str();
    PO.Prefix = Prefix;
    return PO;
  }

  // Untyped wildcard: _
  if (Rest == "_") {
    PO.K = PatternOperand::Wildcard;
    PO.Prefix = Prefix;
    return PO;
  }

  // Check for inline {{regex}} within a literal (e.g., "#{{[0-9]+}}")
  std::string Before, Regex, After;
  if (extractRegex(OpStr, Before, Regex, After)) {
    PO.K = PatternOperand::Wildcard;
    PO.Text = Before + "(" + Regex + ")" + After;
    PO.IsRegex = true;
    return PO;
  }

  // Plain literal.
  PO.K = PatternOperand::Literal;
  PO.Text = OpStr.str();
  return PO;
}

// Parse a single annotation like @defs %fl:nzcv, @one_use(%v), etc.
static Annotation parseAnnotation(StringRef S) {
  Annotation A;
  S = S.trim();

  if (S.starts_with("@defs ")) {
    A.K = Annotation::Defs;
    StringRef Rest = S.drop_front(6).trim();
    // Parse operands: %fl:nzcv
    SmallVector<StringRef, 2> Parts = splitOperands(Rest);
    for (StringRef P : Parts)
      A.Operands.push_back(parseOperandV2(P));
  } else if (S.starts_with("@uses ")) {
    A.K = Annotation::Uses;
    StringRef Rest = S.drop_front(6).trim();
    SmallVector<StringRef, 2> Parts = splitOperands(Rest);
    for (StringRef P : Parts)
      A.Operands.push_back(parseOperandV2(P));
  } else if (S.starts_with("@one_use(")) {
    A.K = Annotation::OneUse;
    StringRef Inner = S.drop_front(9);
    if (Inner.ends_with(")"))
      Inner = Inner.drop_back(1);
    SmallVector<StringRef, 4> Names;
    Inner.split(Names, ',');
    for (StringRef N : Names) {
      N = N.trim();
      if (N.starts_with("%"))
        N = N.drop_front(1);
      A.Names.push_back(N.str());
    }
  } else if (S.starts_with("@has_use(")) {
    A.K = Annotation::HasUse;
    StringRef Inner = S.drop_front(9);
    if (Inner.ends_with(")"))
      Inner = Inner.drop_back(1);
    SmallVector<StringRef, 4> Names;
    Inner.split(Names, ',');
    for (StringRef N : Names) {
      N = N.trim();
      if (N.starts_with("%"))
        N = N.drop_front(1);
      A.Names.push_back(N.str());
    }
  } else if (S.starts_with("@same_bb")) {
    A.K = Annotation::SameBB;
    StringRef Rest = S.drop_front(8).trim();
    if (Rest.starts_with("(") && Rest.ends_with(")")) {
      Rest = Rest.drop_front(1).drop_back(1);
      SmallVector<StringRef, 4> Names;
      Rest.split(Names, ',');
      for (StringRef N : Names) {
        N = N.trim();
        if (N.starts_with("%"))
          N = N.drop_front(1);
        A.Names.push_back(N.str());
      }
    }
    // If no parentheses, Names is empty → means all matched nodes same BB.
  } else if (S.starts_with("@filter(")) {
    A.K = Annotation::Filter;
    StringRef Rest = S.drop_front(8); // drop "@filter("
    // Find matching closing paren (handle nested parens like abs(...)).
    unsigned Depth = 1;
    unsigned End = 0;
    for (unsigned I = 0; I < Rest.size(); ++I) {
      if (Rest[I] == '(') ++Depth;
      else if (Rest[I] == ')') { if (--Depth == 0) { End = I; break; } }
    }
    A.FilterExpr = Rest.substr(0, End).str();
  }

  return A;
}

// Parse annotations from the annotation portion of a line (after splitting
// on " @"). Returns a vector of annotations.
static SmallVector<Annotation, 2> parseAnnotations(StringRef S) {
  SmallVector<Annotation, 2> Result;
  // S may contain multiple annotations separated by " @".
  // The first one doesn't have a leading @, since we already split on " @".
  // Actually, S is the part after the first " @", so it starts with the
  // annotation keyword (e.g., "defs %fl:nzcv" or "one_use(%v) @has_use(%r)").
  // Split on " @" to get individual annotations.
  SmallVector<StringRef, 4> Parts;
  // Re-add the @ prefix for uniform parsing.
  std::string WithAt = ("@" + S).str();
  StringRef WS(WithAt);
  // Split on " @" to separate multiple annotations.
  while (!WS.empty()) {
    size_t Next = WS.find(" @", 1);
    if (Next == StringRef::npos) {
      Result.push_back(parseAnnotation(WS.trim()));
      break;
    }
    Result.push_back(parseAnnotation(WS.substr(0, Next).trim()));
    WS = WS.substr(Next + 1);
  }
  return Result;
}

static std::vector<PatternLine> parsePatternFile(StringRef Contents) {
  std::vector<PatternLine> Lines;

  SmallVector<StringRef, 32> RawLines;
  Contents.split(RawLines, '\n');

  for (StringRef RawLine : RawLines) {
    RawLine = RawLine.trim();
    if (RawLine.empty() || RawLine.starts_with("#"))
      continue;

    // Detect old syntax and emit migration error.
    if (RawLine.starts_with("MATCH:") || RawLine.starts_with("MATCH-ROOT:")) {
      errs() << ToolName
             << ": old MATCH:/MATCH-ROOT: syntax is no longer supported.\n"
             << "  Migrate to v2 SSA-style syntax. See docs for details.\n"
             << "  Line: " << RawLine << "\n";
      continue;
    }

    PatternLine PL;

    // Annotation-only line: starts with @ and no mnemonic.
    if (RawLine.starts_with("@")) {
      // Check for @def(...) — a def-anchor that matches any defining instruction.
      if (RawLine.starts_with("@def(")) {
        PatternLine PL;
        PL.IsDefAnchor = true;
        StringRef Inner = RawLine.drop_front(5); // drop "@def("
        if (Inner.ends_with(")"))
          Inner = Inner.drop_back(1);
        // Parse capture names: @def(%v) or @def(%v, %w)
        SmallVector<StringRef, 4> Names;
        Inner.split(Names, ',');
        for (StringRef N : Names) {
          N = N.trim();
          if (N.starts_with("%"))
            N = N.drop_front(1);
          if (!N.empty())
            PL.DefAnchorNames.push_back(N.str());
        }
        if (PL.DefAnchorNames.empty()) {
          errs() << ToolName << ": @def() requires at least one capture name: "
                 << RawLine << "\n";
          continue;
        }
        Lines.push_back(std::move(PL));
        continue;
      }

      if (Lines.empty()) {
        errs() << ToolName
               << ": annotation-only line with no preceding instruction: "
               << RawLine << "\n";
        continue;
      }
      PL.IsAnnotationOnly = true;
      // Strip leading '@' since parseAnnotations re-adds it.
      SmallVector<Annotation, 2> Annots = parseAnnotations(RawLine.drop_front(1));
      // Attach to previous PatternLine.
      for (Annotation &A : Annots)
        Lines.back().Annotations.push_back(std::move(A));
      continue;
    }

    // Split on " @" to separate instruction from inline annotations.
    StringRef InstrPart = RawLine;
    StringRef AnnotPart;
    size_t AtPos = RawLine.find(" @");
    if (AtPos != StringRef::npos) {
      InstrPart = RawLine.substr(0, AtPos);
      AnnotPart = RawLine.substr(AtPos + 2);
    }

    // Parse mnemonic (first token).  Ignore legacy "root" prefix.
    if (InstrPart.starts_with("root "))
      InstrPart = InstrPart.drop_front(5).ltrim();

    auto [Mnemonic, Rest] = InstrPart.split(' ');
    Rest = Rest.ltrim();

    // Check for {{regex}} in mnemonic.
    std::string Before, RegexStr, After;
    if (extractRegex(Mnemonic, Before, RegexStr, After)) {
      // Build full regex for mnemonic matching.
      PL.Mnemonic = Before;
      PL.MnemRegex = RegexStr + After;
    } else {
      PL.Mnemonic = Mnemonic.str();
    }

    // Parse operands with bracket-aware splitting.
    if (!Rest.empty()) {
      SmallVector<StringRef, 4> OpStrs = splitOperands(Rest);
      for (StringRef OpStr : OpStrs)
        PL.Operands.push_back(parseOperandV2(OpStr));
    }

    // Parse annotations.
    if (!AnnotPart.empty()) {
      SmallVector<Annotation, 2> Annots = parseAnnotations(AnnotPart);
      for (Annotation &A : Annots)
        PL.Annotations.push_back(std::move(A));
    }

    Lines.push_back(std::move(PL));
  }

  return Lines;
}

/// A named pattern from a suite YAML file.
struct NamedPattern {
  std::string Name;
  std::vector<PatternLine> Lines;
};

/// Parse a YAML suite file. Format:
///   pattern_name:
///     pattern: |
///       mnemonic operands
///       @annotation
static std::vector<NamedPattern> parseSuiteFile(StringRef Contents) {
  std::vector<NamedPattern> Suite;
  SourceMgr SM;
  yaml::Stream YS(Contents, SM);

  for (yaml::Document &Doc : YS) {
    auto *Root = dyn_cast_or_null<yaml::MappingNode>(Doc.getRoot());
    if (!Root)
      continue;

    for (auto &Entry : *Root) {
      auto *KeyNode = dyn_cast<yaml::ScalarNode>(Entry.getKey());
      if (!KeyNode)
        continue;
      SmallString<64> KeyStorage;
      StringRef Name = KeyNode->getValue(KeyStorage);

      auto *ValMap = dyn_cast<yaml::MappingNode>(Entry.getValue());
      if (!ValMap)
        continue;

      for (auto &Field : *ValMap) {
        auto *FieldKey = dyn_cast<yaml::ScalarNode>(Field.getKey());
        if (!FieldKey)
          continue;
        SmallString<32> FieldStorage;
        if (FieldKey->getValue(FieldStorage) != "pattern")
          continue;

        StringRef PatText;
        SmallString<256> PatStorage;
        if (auto *PatNode = dyn_cast<yaml::ScalarNode>(Field.getValue()))
          PatText = PatNode->getValue(PatStorage);
        else if (auto *BSN = dyn_cast<yaml::BlockScalarNode>(Field.getValue()))
          PatText = BSN->getValue();
        else
          continue;

        auto Lines = parsePatternFile(PatText);
        if (!Lines.empty())
          Suite.push_back({Name.str(), std::move(Lines)});
      }
    }
  }
  return Suite;
}

// ===----------------------------------------------------------------------===//
// Pattern graph dump
// ===----------------------------------------------------------------------===//

static void printOperand(raw_ostream &OS, const PatternOperand &PO) {
  switch (PO.K) {
  case PatternOperand::Literal:
    OS << PO.Text;
    break;
  case PatternOperand::Capture:
    OS << PO.Prefix << "%" << PO.Name;
    if (!PO.Type.empty())
      OS << ":" << PO.Type;
    break;
  case PatternOperand::Wildcard:
    OS << PO.Prefix;
    if (PO.IsRegex)
      OS << "{{" << PO.Text << "}}";
    else if (!PO.Type.empty())
      OS << "_:" << PO.Type;
    else
      OS << "_";
    break;
  case PatternOperand::Rest:
    OS << "...";
    break;
  case PatternOperand::MemOperand:
    OS << "[";
    for (unsigned I = 0; I < PO.SubOperands.size(); ++I) {
      if (I > 0) OS << ", ";
      printOperand(OS, PO.SubOperands[I]);
    }
    OS << "]";
    if (PO.PreIndex)
      OS << "!";
    break;
  }
}

static void printAnnotation(raw_ostream &OS, const Annotation &A) {
  switch (A.K) {
  case Annotation::Defs:
    OS << "@defs";
    for (const PatternOperand &Op : A.Operands) {
      OS << " ";
      printOperand(OS, Op);
    }
    break;
  case Annotation::Uses:
    OS << "@uses";
    for (const PatternOperand &Op : A.Operands) {
      OS << " ";
      printOperand(OS, Op);
    }
    break;
  case Annotation::OneUse:
    OS << "@one_use(";
    for (unsigned I = 0; I < A.Names.size(); ++I) {
      if (I > 0) OS << ", ";
      OS << "%" << A.Names[I];
    }
    OS << ")";
    break;
  case Annotation::HasUse:
    OS << "@has_use(";
    for (unsigned I = 0; I < A.Names.size(); ++I) {
      if (I > 0) OS << ", ";
      OS << "%" << A.Names[I];
    }
    OS << ")";
    break;
  case Annotation::SameBB:
    OS << "@same_bb";
    if (!A.Names.empty()) {
      OS << "(";
      for (unsigned I = 0; I < A.Names.size(); ++I) {
        if (I > 0) OS << ", ";
        OS << "%" << A.Names[I];
      }
      OS << ")";
    }
    break;
  case Annotation::Filter:
    OS << "@filter(" << A.FilterExpr << ")";
    break;
  }
}

static void dumpPatternGraph(const std::vector<PatternLine> &Pattern) {
  outs() << "Pattern (" << Pattern.size() << " lines):\n";

  // Collect all capture names and which lines def/use them.
  // Use the heuristic classifier (no node available).
  struct CaptureInfo {
    SmallVector<unsigned, 2> DefLines;
    SmallVector<unsigned, 2> UseLines;
  };
  StringMap<CaptureInfo> Captures;

  // Since we don't have BC here, use a simple heuristic: position 0 is def
  // unless the mnemonic is a known no-def instruction.
  auto classifySimple = [](const PatternLine &PL,
                           SmallVectorImpl<std::string> &Defs,
                           SmallVectorImpl<std::string> &Uses) {
    static const char *NoDefMnems[] = {"cmp", "cmn", "tst", "str", "stur",
                                       "stp", "b",   "bl",  "ret", "cbz",
                                       "cbnz", "tbz", "tbnz", "nop"};
    bool FirstIsDef = true;
    StringRef Mnem(PL.Mnemonic);
    for (const char *M : NoDefMnems) {
      if (Mnem.equals_insensitive(M) || Mnem.starts_with_insensitive("b.") ||
          Mnem.starts_with_insensitive("str") ||
          Mnem.starts_with_insensitive("stp")) {
        FirstIsDef = false;
        break;
      }
    }

    unsigned Pos = 0;
    for (const PatternOperand &PO : PL.Operands) {
      if (PO.K == PatternOperand::Capture && !PO.Name.empty() &&
          PO.Type != "nzcv") {
        if (Pos == 0 && FirstIsDef)
          Defs.push_back(PO.Name);
        else
          Uses.push_back(PO.Name);
      } else if (PO.K == PatternOperand::MemOperand) {
        for (const PatternOperand &Sub : PO.SubOperands)
          if (Sub.K == PatternOperand::Capture && !Sub.Name.empty())
            Uses.push_back(Sub.Name);
      }
      Pos++;
    }

    for (const Annotation &A : PL.Annotations) {
      if (A.K == Annotation::Defs) {
        for (const PatternOperand &Op : A.Operands)
          if (Op.K == PatternOperand::Capture)
            Defs.push_back(Op.Name);
      } else if (A.K == Annotation::Uses) {
        for (const PatternOperand &Op : A.Operands)
          if (Op.K == PatternOperand::Capture)
            Uses.push_back(Op.Name);
      }
    }
  };

  // Print each line as a node.
  for (unsigned I = 0; I < Pattern.size(); ++I) {
    const PatternLine &PL = Pattern[I];
    outs() << "  [" << I << "] ";
    if (PL.IsAnnotationOnly) {
      outs() << "(annotation-only)";
    } else {
      if (!PL.MnemRegex.empty())
        outs() << PL.Mnemonic << "{{" << PL.MnemRegex << "}}";
      else
        outs() << PL.Mnemonic;
      for (unsigned J = 0; J < PL.Operands.size(); ++J) {
        outs() << (J == 0 ? " " : ", ");
        printOperand(outs(), PL.Operands[J]);
      }
    }
    for (const Annotation &A : PL.Annotations) {
      outs() << "  ";
      printAnnotation(outs(), A);
    }
    outs() << "\n";

    // Classify and print defs/uses.
    if (!PL.IsAnnotationOnly) {
      SmallVector<std::string, 4> Defs, Uses;
      classifySimple(PL, Defs, Uses);
      if (!Defs.empty()) {
        outs() << "        defs:";
        for (const auto &D : Defs) outs() << " %" << D;
        outs() << "\n";
      }
      if (!Uses.empty()) {
        outs() << "        uses:";
        for (const auto &U : Uses) outs() << " %" << U;
        outs() << "\n";
      }

      for (const auto &D : Defs)
        Captures[D].DefLines.push_back(I);
      for (const auto &U : Uses)
        Captures[U].UseLines.push_back(I);
    }
  }

  // Print edges: def → use via shared capture names.
  outs() << "\n  Edges:\n";
  bool AnyEdges = false;
  for (const auto &[Name, Info] : Captures) {
    for (unsigned D : Info.DefLines) {
      for (unsigned U : Info.UseLines) {
        outs() << "    %" << Name << ": [" << D << "] -> [" << U << "]\n";
        AnyEdges = true;
      }
    }
  }
  if (!AnyEdges)
    outs() << "    (none)\n";

  // Print constraints.
  bool AnyConstraints = false;
  for (unsigned I = 0; I < Pattern.size(); ++I) {
    for (const Annotation &A : Pattern[I].Annotations) {
      if (A.K == Annotation::OneUse || A.K == Annotation::HasUse ||
          A.K == Annotation::SameBB) {
        if (!AnyConstraints) {
          outs() << "\n  Constraints:\n";
          AnyConstraints = true;
        }
        outs() << "    [" << I << "] ";
        printAnnotation(outs(), A);
        outs() << "\n";
      }
    }
  }

  outs() << "\n";
}

static void dumpPatternDot(const std::vector<PatternLine> &Pattern,
                           raw_ostream &OS) {
  auto classifySimpleDot = [](const PatternLine &PL,
                              SmallVectorImpl<std::string> &Defs,
                              SmallVectorImpl<std::string> &Uses) {
    static const char *NoDefMnems[] = {"cmp", "cmn", "tst", "str", "stur",
                                       "stp", "b",   "bl",  "ret", "cbz",
                                       "cbnz", "tbz", "tbnz", "nop"};
    bool FirstIsDef = true;
    StringRef Mnem(PL.Mnemonic);
    for (const char *M : NoDefMnems) {
      if (Mnem.equals_insensitive(M) || Mnem.starts_with_insensitive("b.") ||
          Mnem.starts_with_insensitive("str") ||
          Mnem.starts_with_insensitive("stp")) {
        FirstIsDef = false;
        break;
      }
    }
    unsigned Pos = 0;
    for (const PatternOperand &PO : PL.Operands) {
      if (PO.K == PatternOperand::Capture && !PO.Name.empty() &&
          PO.Type != "nzcv") {
        if (Pos == 0 && FirstIsDef)
          Defs.push_back(PO.Name);
        else
          Uses.push_back(PO.Name);
      } else if (PO.K == PatternOperand::MemOperand) {
        for (const PatternOperand &Sub : PO.SubOperands)
          if (Sub.K == PatternOperand::Capture && !Sub.Name.empty())
            Uses.push_back(Sub.Name);
      }
      Pos++;
    }
    for (const Annotation &A : PL.Annotations) {
      if (A.K == Annotation::Defs)
        for (const PatternOperand &Op : A.Operands)
          if (Op.K == PatternOperand::Capture)
            Defs.push_back(Op.Name);
      if (A.K == Annotation::Uses)
        for (const PatternOperand &Op : A.Operands)
          if (Op.K == PatternOperand::Capture)
            Uses.push_back(Op.Name);
    }
  };

  struct CaptureInfo {
    SmallVector<unsigned, 2> DefLines;
    SmallVector<unsigned, 2> UseLines;
  };
  StringMap<CaptureInfo> Captures;

  for (unsigned I = 0; I < Pattern.size(); ++I) {
    if (Pattern[I].IsAnnotationOnly)
      continue;
    SmallVector<std::string, 4> Defs, Uses;
    classifySimpleDot(Pattern[I], Defs, Uses);
    for (const auto &D : Defs)
      Captures[D].DefLines.push_back(I);
    for (const auto &U : Uses)
      Captures[U].UseLines.push_back(I);
  }

  OS << "digraph pattern {\n";
  OS << "  rankdir=TB;\n";
  OS << "  node [shape=record, fontname=\"Courier\", fontsize=11];\n";
  OS << "  edge [fontname=\"Courier\", fontsize=10];\n\n";

  for (unsigned I = 0; I < Pattern.size(); ++I) {
    const PatternLine &PL = Pattern[I];
    if (PL.IsAnnotationOnly)
      continue;

    OS << "  n" << I << " [label=\"";
    if (!PL.MnemRegex.empty())
      OS << PL.Mnemonic << "\\{\\{" << PL.MnemRegex << "\\}\\}";
    else
      OS << PL.Mnemonic;

    for (unsigned J = 0; J < PL.Operands.size(); ++J) {
      OS << (J == 0 ? " " : ", ");
      const PatternOperand &PO = PL.Operands[J];
      switch (PO.K) {
      case PatternOperand::Literal:
        OS << PO.Text;
        break;
      case PatternOperand::Capture:
        OS << PO.Prefix << "%" << PO.Name;
        if (!PO.Type.empty()) OS << ":" << PO.Type;
        break;
      case PatternOperand::Wildcard:
        OS << PO.Prefix;
        if (PO.IsRegex)
          OS << "\\{\\{" << PO.Text << "\\}\\}";
        else if (!PO.Type.empty())
          OS << "_:" << PO.Type;
        else
          OS << "_";
        break;
      case PatternOperand::Rest:
        OS << "...";
        break;
      case PatternOperand::MemOperand:
        OS << "[";
        for (unsigned K = 0; K < PO.SubOperands.size(); ++K) {
          if (K > 0) OS << ", ";
          const PatternOperand &Sub = PO.SubOperands[K];
          if (Sub.K == PatternOperand::Capture) {
            OS << Sub.Prefix << "%" << Sub.Name;
            if (!Sub.Type.empty()) OS << ":" << Sub.Type;
          } else if (Sub.K == PatternOperand::Wildcard) {
            OS << Sub.Prefix;
            if (!Sub.Type.empty()) OS << "_:" << Sub.Type;
            else OS << "_";
          } else if (Sub.K == PatternOperand::Rest) {
            OS << "...";
          } else {
            OS << Sub.Text;
          }
        }
        OS << "]";
        if (PO.PreIndex) OS << "!";
        break;
      }
    }

    for (const Annotation &A : PL.Annotations) {
      OS << "\\l  ";
      switch (A.K) {
      case Annotation::Defs:
        OS << "@defs";
        for (const PatternOperand &Op : A.Operands)
          if (Op.K == PatternOperand::Capture) {
            OS << " %" << Op.Name;
            if (!Op.Type.empty()) OS << ":" << Op.Type;
          }
        break;
      case Annotation::Uses:
        OS << "@uses";
        for (const PatternOperand &Op : A.Operands)
          if (Op.K == PatternOperand::Capture) {
            OS << " %" << Op.Name;
            if (!Op.Type.empty()) OS << ":" << Op.Type;
          }
        break;
      case Annotation::OneUse:
        OS << "@one_use(";
        for (unsigned K = 0; K < A.Names.size(); ++K) {
          if (K > 0) OS << ", ";
          OS << "%" << A.Names[K];
        }
        OS << ")";
        break;
      case Annotation::HasUse:
        OS << "@has_use(";
        for (unsigned K = 0; K < A.Names.size(); ++K) {
          if (K > 0) OS << ", ";
          OS << "%" << A.Names[K];
        }
        OS << ")";
        break;
      case Annotation::SameBB:
        OS << "@same_bb";
        if (!A.Names.empty()) {
          OS << "(";
          for (unsigned K = 0; K < A.Names.size(); ++K) {
            if (K > 0) OS << ", ";
            OS << "%" << A.Names[K];
          }
          OS << ")";
        }
        break;
      case Annotation::Filter:
        OS << "@filter(" << A.FilterExpr << ")";
        break;
      }
    }

    OS << "\"];\n";
  }

  OS << "\n";
  for (const auto &[Name, Info] : Captures) {
    for (unsigned D : Info.DefLines) {
      for (unsigned U : Info.UseLines) {
        OS << "  n" << D << " -> n" << U << " [label=\"%" << Name
               << "\"];\n";
      }
    }
  }

  OS << "}\n";
}


/// Get the bit width of a physical register from its name.
/// AArch64: W=32, X=64, B=8, H=16, S=32, D=64, Q=128, V=128.
static unsigned getRegWidth(const BinaryContext &BC, MCPhysReg Reg) {
  StringRef Name = BC.MRI->getName(Reg);
  if (Name.empty())
    return 0;
  switch (Name[0]) {
  case 'W': case 'w': return 32;
  case 'X': case 'x': return 64;
  case 'B': case 'b': return 8;
  case 'H': case 'h': return 16;
  case 'S': case 's': return 32;
  case 'D': case 'd': return 64;
  case 'Q': case 'q': return 128;
  case 'V': case 'v': return 128;
  default:
    // Try the minimum register class covering this register.
    for (const auto &RC : BC.MRI->regclasses()) {
      if (RC.contains(Reg))
        return RC.RegSizeInBits;
    }
    return 0;
  }
}

// Check if an operand text names a register that aliases the bound register.
// Since printed names may use alternate forms (e.g., "v0" for Q0 on AArch64),
// we resolve the text to an MCPhysReg via the InstrNode's MCInst operands
// and then compare via register units.
static bool regTextMatchesBinding(const BinaryContext &BC, StringRef Text,
                                  MCPhysReg BoundReg,
                                  const InstrNode *Node = nullptr) {
  // Direct name match.
  if (Text.equals_insensitive(BC.MRI->getName(BoundReg)))
    return true;
  // Check sub/super registers by canonical name.
  for (MCPhysReg Sub : BC.MRI->subregs(BoundReg))
    if (Text.equals_insensitive(BC.MRI->getName(Sub)))
      return true;
  for (MCPhysReg Super : BC.MRI->superregs(BoundReg))
    if (Text.equals_insensitive(BC.MRI->getName(Super)))
      return true;

  // If we have the MCInst, resolve the printed text to an MCPhysReg by
  // finding an operand whose printed name matches, then check regunit overlap.
  if (Node && Node->Inst) {
    for (unsigned I = 0, E = Node->Inst->getNumOperands(); I < E; ++I) {
      const MCOperand &Op = Node->Inst->getOperand(I);
      if (!Op.isReg() || Op.getReg() == 0)
        continue;
      MCPhysReg CandReg = Op.getReg();
      if (CandReg == BoundReg)
        return true;
      // Check regunit overlap (covers Q0 == Q0 for v0/q0 alternate names).
      bool Aliases = false;
      for (MCRegUnit RU : BC.MRI->regunits(CandReg)) {
        for (MCRegUnit BRU : BC.MRI->regunits(BoundReg)) {
          if (RU == BRU) {
            Aliases = true;
            break;
          }
        }
        if (Aliases)
          break;
      }
      if (!Aliases)
        continue;
      // CandReg aliases BoundReg. Now verify this is the operand the text
      // refers to by checking if CandReg is the ONLY register operand that
      // could produce this text (or just accept it — the mnemonic + position
      // matching in matchLine already constrains this sufficiently).
      return true;
    }
  }
  return false;
}

// Try to bind a pattern operand against a parsed assembly operand.
// OpIdx is the position of this operand in the instruction (used for
// positional register lookup when name-based lookup fails due to alt names).
static bool tryBindOperand(const BinaryContext &BC, const PatternOperand &PO,
                           const AsmOperand &AsmOp, const InstrNode &Node,
                           StringMap<Binding> &Bindings,
                           unsigned OpIdx = ~0u) {
  if (PO.K == PatternOperand::Literal)
    return true; // Literals are hints, always pass.

  // Rest: accepts all remaining tokens.
  if (PO.K == PatternOperand::Rest)
    return true;

  // For leaf operands, use the text. For mem operands, use the full text.
  StringRef Token = AsmOp.Text;

  // Check and strip prefix (e.g., "#").
  StringRef WorkToken = Token;
  if (!PO.Prefix.empty()) {
    if (!WorkToken.starts_with(PO.Prefix))
      return false;
    WorkToken = WorkToken.drop_front(PO.Prefix.size());
  }

  // MemOperand: match against pre-parsed bracket structure.
  if (PO.K == PatternOperand::MemOperand) {
    if (!AsmOp.isMem())
      return false;

    // Check pre-index agreement.
    if (AsmOp.PreIndex != PO.PreIndex)
      return false;

    // Match sub-operands recursively.
    if (PO.SubOperands.size() > AsmOp.Children.size())
      return false;
    for (unsigned I = 0; I < PO.SubOperands.size(); ++I) {
      if (PO.SubOperands[I].K == PatternOperand::Rest)
        break;
      if (!tryBindOperand(BC, PO.SubOperands[I], AsmOp.Children[I], Node,
                          Bindings))
        return false;
    }
    return true;
  }

  // Anonymous wildcard/regex: {{regex}}, _, _:type
  if (PO.K == PatternOperand::Wildcard) {
    if (PO.IsRegex) {
      Regex Re(PO.Text);
      return Re.match(WorkToken);
    }
    // Typed wildcard: verify type constraint without binding.
    if (!PO.Type.empty()) {
      StringRef T = PO.Type;
      if (T.equals_insensitive("wreg"))
        return WorkToken.starts_with_insensitive("w");
      if (T.equals_insensitive("xreg"))
        return WorkToken.starts_with_insensitive("x");
      if (T.equals_insensitive("reg"))
        return WorkToken.starts_with_insensitive("w") ||
               WorkToken.starts_with_insensitive("x");
      if (T.equals_insensitive("imm")) {
        StringRef Num = WorkToken;
        if (Num.starts_with("#"))
          Num = Num.drop_front(1);
        int64_t Dummy;
        if (Num.starts_with("0x") || Num.starts_with("0X"))
          return !Num.drop_front(2).getAsInteger(16, Dummy);
        return !Num.getAsInteger(10, Dummy);
      }
      // label, nzcv, or unknown type → accept anything for wildcards.
    }
    return true; // Untyped wildcard matches anything.
  }

  if (PO.K == PatternOperand::Capture) {
    // NZCV type: search implicit defs/uses.
    if (PO.Type == "nzcv") {
      MCPhysReg NZCVReg = 0;
      for (MCPhysReg Reg : Node.Defs) {
        StringRef Name = BC.MRI->getName(Reg);
        if (Name == "NZCV" || Name.contains_insensitive("ccr")) {
          NZCVReg = Reg;
          break;
        }
      }
      if (NZCVReg == 0) {
        for (MCPhysReg Reg : Node.Uses) {
          StringRef Name = BC.MRI->getName(Reg);
          if (Name == "NZCV" || Name.contains_insensitive("ccr")) {
            NZCVReg = Reg;
            break;
          }
        }
      }
      if (NZCVReg == 0)
        return false;
      Binding B;
      B.K = Binding::Reg;
      B.RegVal = NZCVReg;
      B.RegWidth = getRegWidth(BC, NZCVReg);
      Bindings[PO.Name] = B;
      return true;
    }

    // IMM type.
    if (PO.Type == "imm") {
      StringRef NumStr = WorkToken;
      if (NumStr.starts_with("#"))
        NumStr = NumStr.substr(1);
      int64_t Val;
      if (NumStr.starts_with("0x") || NumStr.starts_with("0X")) {
        if (NumStr.substr(2).getAsInteger(16, Val))
          return false;
      } else {
        if (NumStr.getAsInteger(10, Val))
          return false;
      }
      auto It = Bindings.find(PO.Name);
      if (It != Bindings.end()) {
        if (It->second.K != Binding::Imm || It->second.ImmVal != Val)
          return false;
      } else {
        Binding B;
        B.K = Binding::Imm;
        B.ImmVal = Val;
        Bindings[PO.Name] = B;
      }
      return true;
    }

    // Label type.
    if (PO.Type == "label") {
      auto It = Bindings.find(PO.Name);
      if (It != Bindings.end()) {
        if (It->second.K != Binding::Label || It->second.LabelVal != WorkToken)
          return false;
      } else {
        Binding B;
        B.K = Binding::Label;
        B.LabelVal = WorkToken.str();
        Bindings[PO.Name] = B;
      }
      return true;
    }

    // Empty type: back-reference if already bound, otherwise capture as label.
    if (PO.Type.empty()) {
      auto It = Bindings.find(PO.Name);
      if (It != Bindings.end()) {
        // Back-reference: verify match.
        const Binding &B = It->second;
        if (B.K == Binding::Reg) {
          return regTextMatchesBinding(BC, WorkToken, B.RegVal, &Node);
        }
        if (B.K == Binding::Imm) {
          StringRef NumStr = WorkToken;
          if (NumStr.starts_with("#"))
            NumStr = NumStr.substr(1);
          int64_t Val;
          if (NumStr.starts_with("0x") || NumStr.starts_with("0X")) {
            if (NumStr.substr(2).getAsInteger(16, Val))
              return false;
          } else {
            if (NumStr.getAsInteger(10, Val))
              return false;
          }
          return Val == B.ImmVal;
        }
        if (B.K == Binding::Label)
          return WorkToken == B.LabelVal;
        return false;
      }
      // Not yet bound — try to capture as register first, then label.
      // First try name-based lookup, then positional MCInst operand lookup
      // (handles alternate names like v0/q0 on AArch64).
      MCPhysReg FoundReg = 0;
      for (unsigned I = 0, E = Node.Inst->getNumOperands(); I < E; ++I) {
        const MCOperand &Op = Node.Inst->getOperand(I);
        if (!Op.isReg() || Op.getReg() == 0)
          continue;
        MCPhysReg CandReg = Op.getReg();
        if (WorkToken.equals_insensitive(BC.MRI->getName(CandReg))) {
          FoundReg = CandReg;
          break;
        }
      }
      // Positional fallback: if the operand index is valid, use the MCInst
      // register at that position directly.
      if (FoundReg == 0 && OpIdx != ~0u && OpIdx < Node.Inst->getNumOperands()) {
        const MCOperand &Op = Node.Inst->getOperand(OpIdx);
        if (Op.isReg() && Op.getReg() != 0)
          FoundReg = Op.getReg();
      }
      if (FoundReg != 0) {
        Binding B;
        B.K = Binding::Reg;
        B.RegVal = FoundReg;
        B.RegWidth = getRegWidth(BC, FoundReg);
        Bindings[PO.Name] = B;
      } else {
        Binding B;
        B.K = Binding::Label;
        B.LabelVal = WorkToken.str();
        Bindings[PO.Name] = B;
      }
      return true;
    }

    // Register type (wreg, xreg, reg).
    StringRef RegName = WorkToken;
    if (PO.Type == "wreg" && !RegName.starts_with_insensitive("w"))
      return false;
    if (PO.Type == "xreg" && !RegName.starts_with_insensitive("x"))
      return false;
    if (PO.Type == "reg" && !RegName.starts_with_insensitive("w") &&
        !RegName.starts_with_insensitive("x"))
      return false;

    auto It = Bindings.find(PO.Name);
    if (It != Bindings.end()) {
      if (It->second.K != Binding::Reg)
        return false;
      if (!regTextMatchesBinding(BC, RegName, It->second.RegVal, &Node))
        return false;
    } else {
      // Look up the register by name in MCInst operands, with positional fallback.
      MCPhysReg FoundReg = 0;
      for (unsigned I = 0, E = Node.Inst->getNumOperands(); I < E; ++I) {
        const MCOperand &Op = Node.Inst->getOperand(I);
        if (!Op.isReg() || Op.getReg() == 0)
          continue;
        if (RegName.equals_insensitive(BC.MRI->getName(Op.getReg()))) {
          FoundReg = Op.getReg();
          break;
        }
      }
      if (FoundReg == 0 && OpIdx != ~0u && OpIdx < Node.Inst->getNumOperands()) {
        const MCOperand &Op = Node.Inst->getOperand(OpIdx);
        if (Op.isReg() && Op.getReg() != 0)
          FoundReg = Op.getReg();
      }
      if (FoundReg == 0)
        return false;
      Binding B;
      B.K = Binding::Reg;
      B.RegVal = FoundReg;
      B.RegWidth = getRegWidth(BC, FoundReg);
      Bindings[PO.Name] = B;
    }
    return true;
  }

  return false;
}

// Check if a register matches a binding (considering sub/super register aliases).
static bool regMatchesBinding(const BinaryContext &BC, MCPhysReg Reg,
                              const Binding &B) {
  if (B.K != Binding::Reg)
    return false;
  if (Reg == B.RegVal)
    return true;
  for (MCPhysReg Super : BC.MRI->superregs(Reg))
    if (Super == B.RegVal)
      return true;
  for (MCPhysReg Sub : BC.MRI->subregs(Reg))
    if (Sub == B.RegVal)
      return true;
  return false;
}


// Try to match a single PatternLine against an InstrNode.
// Updates Bindings on success, returns false on failure.
static bool matchLine(const BinaryContext &BC, const PatternLine &PL,
                      const InstrNode &Node,
                      StringMap<Binding> &Bindings) {
  // Annotation-only lines always match (constraints checked later).
  if (PL.IsAnnotationOnly)
    return true;

  // DefAnchor (@def(%v)): matches any instruction that has at least one
  // explicit def.  Binds each capture name to the corresponding defined
  // register.
  if (PL.IsDefAnchor) {
    if (Node.Defs.empty())
      return false;
    for (unsigned I = 0; I < PL.DefAnchorNames.size(); ++I) {
      const std::string &Name = PL.DefAnchorNames[I];
      // Use the first explicit def register.  For instructions with multiple
      // defs, we could extend this, but one def is the common case.
      MCPhysReg DefReg = 0;
      if (I < Node.Defs.size())
        DefReg = Node.Defs[I];
      else
        DefReg = Node.Defs[0]; // fallback: reuse first def
      auto It = Bindings.find(Name);
      if (It != Bindings.end()) {
        if (It->second.K != Binding::Reg ||
            !regMatchesBinding(BC, DefReg, It->second))
          return false;
      } else {
        Binding B;
        B.K = Binding::Reg;
        B.RegVal = DefReg;
        B.RegWidth = getRegWidth(BC, DefReg);
        Bindings[Name] = B;
      }
    }
    return true;
  }

  // Lazily parse printed assembly on first access.
  Node.ensureParsed(BC);

  // Use pre-parsed mnemonic and operands from InstrNode.
  const std::string &PrintedMnem = Node.Mnemonic;
  const auto &AsmOps = Node.Operands;

  // Mnemonic match: literal prefix + optional regex suffix.
  StringRef PrintedMnemRef(PrintedMnem);
  if (!PrintedMnemRef.starts_with_insensitive(PL.Mnemonic))
    return false;
  if (!PL.MnemRegex.empty()) {
    StringRef Suffix = PrintedMnemRef.substr(PL.Mnemonic.size());
    Regex Re(PL.MnemRegex);
    if (!Re.match(Suffix))
      return false;
  } else if (PrintedMnemRef.size() != PL.Mnemonic.size()) {
    // Exact match required when no regex suffix.
    return false;
  }

  // Count non-NZCV explicit operands in pattern.
  // In v2, NZCV captures are handled via @defs/@uses annotations, but
  // they can also appear inline — we match all operands positionally.
  if (PL.Operands.size() > AsmOps.size()) {
    // Allow if last operand is Rest.
    if (PL.Operands.empty() || PL.Operands.back().K != PatternOperand::Rest)
      return false;
  }

  for (unsigned I = 0; I < PL.Operands.size(); ++I) {
    if (PL.Operands[I].K == PatternOperand::Rest)
      break; // Rest matches remaining operands.
    if (I >= AsmOps.size())
      return false;
    // Skip NZCV captures from positional matching (they're implicit).
    if (PL.Operands[I].K == PatternOperand::Capture &&
        PL.Operands[I].Type == "nzcv")
      continue;
    if (!tryBindOperand(BC, PL.Operands[I], AsmOps[I], Node, Bindings, I))
      return false;
  }

  // Process @defs/@uses annotations.
  for (const Annotation &A : PL.Annotations) {
    if (A.K == Annotation::Defs) {
      for (const PatternOperand &AnnOp : A.Operands) {
        if (AnnOp.K != PatternOperand::Capture)
          continue;
        if (AnnOp.Type == "nzcv") {
          // Search implicit defs for NZCV.
          MCPhysReg NZCVReg = 0;
          for (MCPhysReg Reg : Node.Defs) {
            StringRef Name = BC.MRI->getName(Reg);
            if (Name == "NZCV" || Name.contains_insensitive("ccr")) {
              NZCVReg = Reg;
              break;
            }
          }
          if (NZCVReg == 0)
            return false;
          auto It = Bindings.find(AnnOp.Name);
          if (It != Bindings.end()) {
            if (It->second.K != Binding::Reg ||
                It->second.RegVal != NZCVReg)
              return false;
          } else {
            Binding B;
            B.K = Binding::Reg;
            B.RegVal = NZCVReg;
            B.RegWidth = getRegWidth(BC, NZCVReg);
            Bindings[AnnOp.Name] = B;
          }
        } else {
          // Generic register def annotation — search defs.
          auto It = Bindings.find(AnnOp.Name);
          if (It != Bindings.end() && It->second.K == Binding::Reg) {
            bool Found = false;
            for (MCPhysReg Reg : Node.Defs) {
              if (regMatchesBinding(BC, Reg, It->second)) {
                Found = true;
                break;
              }
            }
            if (!Found)
              return false;
          }
        }
      }
    } else if (A.K == Annotation::Uses) {
      for (const PatternOperand &AnnOp : A.Operands) {
        if (AnnOp.K != PatternOperand::Capture)
          continue;
        auto It = Bindings.find(AnnOp.Name);
        if (It != Bindings.end() && It->second.K == Binding::Reg) {
          bool Found = false;
          for (MCPhysReg Reg : Node.Uses) {
            if (regMatchesBinding(BC, Reg, It->second)) {
              Found = true;
              break;
            }
          }
          if (!Found)
            return false;
        } else if (AnnOp.Type == "nzcv") {
          // Search implicit uses for NZCV.
          MCPhysReg NZCVReg = 0;
          for (MCPhysReg Reg : Node.Uses) {
            StringRef Name = BC.MRI->getName(Reg);
            if (Name == "NZCV" || Name.contains_insensitive("ccr")) {
              NZCVReg = Reg;
              break;
            }
          }
          if (NZCVReg == 0)
            return false;
          Binding B;
          B.K = Binding::Reg;
          B.RegVal = NZCVReg;
          B.RegWidth = getRegWidth(BC, NZCVReg);
          Bindings[AnnOp.Name] = B;
        }
      }
    }
    // OneUse, HasUse, SameBB are validated after full match.
  }

  return true;
}

struct MatchResult {
  std::string FunctionName;
  const BinaryFunction *BF = nullptr;   // For symbolization
  std::vector<std::pair<const BBInfo *, unsigned>> MatchedInstrs; // (BB, idx)
  StringMap<Binding> Bindings;
  SmallVector<NodeID, 8> MatchedNodeIDs; // For graph matcher
};

struct FunctionResults {
  std::vector<BBInfo> AllBBs;       // Keeps BBInfo pointers in Matches valid
  std::vector<MatchResult> Matches;
};

// Try matching the pattern starting from instruction StartIdx in StartBB,
// potentially continuing into successor BBs via live-in.
static bool tryMatch(const BinaryContext &BC,
                     const std::vector<PatternLine> &Pattern,
                     const std::vector<BBInfo> &AllBBs,
                     unsigned StartBBIdx, unsigned StartInstIdx,
                     MatchResult &Result) {
  StringMap<Binding> Bindings;
  std::vector<std::pair<const BBInfo *, unsigned>> Matched;

  unsigned PatIdx = 0;
  unsigned CurBBIdx = StartBBIdx;
  unsigned CurInstIdx = StartInstIdx;

  // Build BB pointer to index map.
  DenseMap<const BinaryBasicBlock *, unsigned> BBToIdx;
  for (unsigned I = 0, E = AllBBs.size(); I < E; ++I)
    BBToIdx[AllBBs[I].BB] = I;

  while (PatIdx < Pattern.size()) {
    bool MatchedThisLine = false;

    // First pattern line must match at the exact start position.
    // Subsequent lines scan forward within the current BB.
    unsigned SearchStart = CurInstIdx;

    // Try current BB from current instruction onward.
    while (CurInstIdx < AllBBs[CurBBIdx].Nodes.size()) {
      // For the first pattern line, only try the exact start position.
      if (PatIdx == 0 && CurInstIdx != SearchStart)
        break;
      StringMap<Binding> TryBindings = Bindings;
      if (matchLine(BC, Pattern[PatIdx], AllBBs[CurBBIdx].Nodes[CurInstIdx],
                    TryBindings)) {
        Bindings = std::move(TryBindings);
        Matched.push_back({&AllBBs[CurBBIdx], CurInstIdx});
        CurInstIdx++;
        PatIdx++;
        MatchedThisLine = true;
        break;
      }
      CurInstIdx++;
    }

    if (MatchedThisLine)
      continue;

    // First pattern line must match at the start position, no cross-BB.
    if (PatIdx == 0)
      return false;

    // Current BB exhausted. Try successor BBs if we have bindings to check
    // against live-in.
    bool FoundInSuccessor = false;
    for (const BinaryBasicBlock *Succ : AllBBs[CurBBIdx].BB->successors()) {
      auto It = BBToIdx.find(Succ);
      if (It == BBToIdx.end())
        continue;
      unsigned SuccIdx = It->second;
      const BBInfo &SuccBB = AllBBs[SuccIdx];

      // Check that any register bindings used in remaining pattern lines
      // are live-in to this successor.
      bool AllLiveIn = true;
      for (const auto &[Name, B] : Bindings) {
        if (B.K == Binding::Reg && B.RegVal != 0) {
          if (B.RegVal < SuccBB.LiveIn.size() && !SuccBB.LiveIn[B.RegVal]) {
            AllLiveIn = false;
            break;
          }
        }
      }
      if (!AllLiveIn)
        continue;

      // Try matching remaining pattern in this successor.
      for (unsigned SI = 0; SI < SuccBB.Nodes.size(); ++SI) {
        StringMap<Binding> TryBindings = Bindings;
        if (matchLine(BC, Pattern[PatIdx], SuccBB.Nodes[SI], TryBindings)) {
          Bindings = std::move(TryBindings);
          Matched.push_back({&SuccBB, SI});
          CurBBIdx = SuccIdx;
          CurInstIdx = SI + 1;
          PatIdx++;
          FoundInSuccessor = true;
          break;
        }
      }
      if (FoundInSuccessor)
        break;
    }

    if (!FoundInSuccessor)
      return false;
  }

  Result.MatchedInstrs = std::move(Matched);
  Result.Bindings = std::move(Bindings);
  return true;
}

// ===----------------------------------------------------------------------===//
// Graph-based matcher (MATCH-ROOT mode)
// ===----------------------------------------------------------------------===//

// Determine which captures in a pattern line are defined vs used.
// Uses MCInstrDesc::getNumDefs() for precise classification when a matched
// node is available, falls back to heuristic for candidate search.
static void classifyCapturePositions(
    const BinaryContext &BC, const PatternLine &PL,
    const InstrNode *Node,
    SmallVectorImpl<std::string> &DefCaptures,
    SmallVectorImpl<std::string> &UseCaptures) {
  // DefAnchor: all names are definitions.
  if (PL.IsDefAnchor) {
    for (const std::string &Name : PL.DefAnchorNames)
      DefCaptures.push_back(Name);
    return;
  }

  // @defs annotations → DefCaptures, @uses → UseCaptures.
  for (const Annotation &A : PL.Annotations) {
    if (A.K == Annotation::Defs) {
      for (const PatternOperand &Op : A.Operands)
        if (Op.K == PatternOperand::Capture)
          DefCaptures.push_back(Op.Name);
    } else if (A.K == Annotation::Uses) {
      for (const PatternOperand &Op : A.Operands)
        if (Op.K == PatternOperand::Capture)
          UseCaptures.push_back(Op.Name);
    }
  }

  // Collect explicit capture names with their positions.
  // For MemOperand, expand sub-operands.
  SmallVector<std::pair<std::string, unsigned>, 4> CapturePositions;
  unsigned Pos = 0;
  for (const PatternOperand &PO : PL.Operands) {
    if (PO.K == PatternOperand::Capture && !PO.Name.empty() &&
        PO.Type != "nzcv") {
      CapturePositions.push_back({PO.Name, Pos});
    } else if (PO.K == PatternOperand::MemOperand) {
      // MemOperand sub-operands are all uses (address components).
      for (const PatternOperand &Sub : PO.SubOperands) {
        if (Sub.K == PatternOperand::Capture && !Sub.Name.empty())
          UseCaptures.push_back(Sub.Name);
      }
    }
    Pos++;
  }

  // Determine def count.
  unsigned NumDefs = 0;
  if (Node) {
    const MCInstrDesc &Desc = BC.MII->get(Node->Inst->getOpcode());
    NumDefs = Desc.getNumDefs();
  } else {
    // Fallback heuristic: first operand is def unless known otherwise.
    static const char *NoExplicitDefMnemonics[] = {
        "cmp", "cmn", "tst", "str", "stur", "stp", "b", "bl", "ret",
        "cbz", "cbnz", "tbz", "tbnz", "nop"};
    bool FirstIsDef = true;
    StringRef Mnem(PL.Mnemonic);
    for (const char *M : NoExplicitDefMnemonics) {
      if (Mnem.equals_insensitive(M) || Mnem.starts_with_insensitive("b.") ||
          Mnem.starts_with_insensitive("str") ||
          Mnem.starts_with_insensitive("stp")) {
        FirstIsDef = false;
        break;
      }
    }
    NumDefs = FirstIsDef ? 1 : 0;
  }

  for (const auto &[Name, P] : CapturePositions) {
    if (P < NumDefs)
      DefCaptures.push_back(Name);
    else
      UseCaptures.push_back(Name);
  }
}


// Validate post-match constraints (@one_use, @has_use, @same_bb, @filter).
static bool validateConstraints(
    const BinaryContext &BC, const std::vector<PatternLine> &Pattern,
    const DefUseGraph &G, const SmallVector<NodeID, 8> &MatchedNodeIDs,
    const StringMap<Binding> &Bindings) {
  // Build a map from capture name → defining NodeID.
  // We need to know which matched node produces each capture.
  StringMap<NodeID> CaptureDefNode;
  for (unsigned I = 0; I < Pattern.size(); ++I) {
    const PatternLine &PL = Pattern[I];
    if (PL.IsAnnotationOnly)
      continue;
    // Find the matching NodeID — MatchedNodeIDs may not align with Pattern
    // indices directly (annotation-only lines don't consume nodes).
    // Build non-annotation pattern index → MatchedNodeIDs index mapping.
  }

  // Build the mapping properly: non-annotation lines → MatchedNodeIDs.
  SmallVector<unsigned, 8> PatToNodeIdx;
  for (unsigned I = 0; I < Pattern.size(); ++I) {
    if (!Pattern[I].IsAnnotationOnly)
      PatToNodeIdx.push_back(I);
  }

  // For each non-annotation pattern line, classify captures and record producers.
  for (unsigned MI = 0; MI < MatchedNodeIDs.size() && MI < PatToNodeIdx.size();
       ++MI) {
    NodeID NID = MatchedNodeIDs[MI];
    unsigned PatIdx = PatToNodeIdx[MI];
    const PatternLine &PL = Pattern[PatIdx];

    SmallVector<std::string, 4> DefCaptures, UseCaptures;
    classifyCapturePositions(BC, PL, &G.Nodes[NID], DefCaptures, UseCaptures);
    for (const std::string &Name : DefCaptures)
      CaptureDefNode[Name] = NID;
  }

  for (const PatternLine &PL : Pattern) {
    for (const Annotation &A : PL.Annotations) {
      if (A.K == Annotation::OneUse) {
        for (const std::string &Name : A.Names) {
          auto DNIt = CaptureDefNode.find(Name);
          if (DNIt == CaptureDefNode.end())
            continue;
          NodeID DefNID = DNIt->second;
          auto BIt = Bindings.find(Name);
          if (BIt == Bindings.end() || BIt->second.K != Binding::Reg)
            continue;
          // Count out-edges from DefNID for this register.
          unsigned UseCount = 0;
          auto EIt = G.OutEdges.find(DefNID);
          if (EIt != G.OutEdges.end()) {
            for (unsigned EIdx : EIt->second) {
              if (regMatchesBinding(BC, G.Edges[EIdx].Reg, BIt->second))
                UseCount++;
            }
          }
          if (UseCount != 1)
            return false;
        }
      } else if (A.K == Annotation::HasUse) {
        for (const std::string &Name : A.Names) {
          auto DNIt = CaptureDefNode.find(Name);
          if (DNIt == CaptureDefNode.end())
            continue;
          NodeID DefNID = DNIt->second;
          auto BIt = Bindings.find(Name);
          if (BIt == Bindings.end() || BIt->second.K != Binding::Reg)
            continue;
          unsigned UseCount = 0;
          auto EIt = G.OutEdges.find(DefNID);
          if (EIt != G.OutEdges.end()) {
            for (unsigned EIdx : EIt->second) {
              if (regMatchesBinding(BC, G.Edges[EIdx].Reg, BIt->second))
                UseCount++;
            }
          }
          if (UseCount < 1)
            return false;
        }
      } else if (A.K == Annotation::SameBB) {
        if (A.Names.empty()) {
          // All matched nodes must be in the same BB.
          if (MatchedNodeIDs.size() > 1) {
            unsigned FirstBB = G.Nodes[MatchedNodeIDs[0]].BBIndex;
            for (unsigned I = 1; I < MatchedNodeIDs.size(); ++I) {
              if (G.Nodes[MatchedNodeIDs[I]].BBIndex != FirstBB)
                return false;
            }
          }
        } else {
          // Named captures must be in same BB.
          std::optional<unsigned> BB;
          for (const std::string &Name : A.Names) {
            auto DNIt = CaptureDefNode.find(Name);
            if (DNIt == CaptureDefNode.end())
              continue;
            unsigned ThisBB = G.Nodes[DNIt->second].BBIndex;
            if (!BB)
              BB = ThisBB;
            else if (*BB != ThisBB)
              return false;
          }
        }
      } else if (A.K == Annotation::Filter) {
        FilterExprParser Parser(A.FilterExpr, Bindings);
        auto Result = Parser.evaluate();
        if (!Result) {
          consumeError(Result.takeError());
          return false;
        }
        if (!*Result)
          return false;
      }
    }
  }
  return true;
}

// ===----------------------------------------------------------------------===//
// DP-based graph matcher
// ===----------------------------------------------------------------------===//
//
// Instead of trying every root candidate and searching per-root, we process
// pattern lines bottom-up in topological order (leaves first).  Each
// instruction is checked at most once per pattern line, and predecessor
// constraints are verified via def-use edges against already-computed labels.
//
// For a pattern like:
//   ldr %base:xreg, _          (p0, leaf)
//   ldr %idx:xreg, _           (p1, leaf)
//   lsl %off:xreg, %idx, _     (p2, depends on p1)
//   root ldr _, [%base, %off]   (p3, depends on p0 and p2)
//
// DP processes p0, p1, p2, p3 in that order.  At p3 it only checks
// instructions whose def-use predecessors already carry p0 and p2 labels.

/// Capture-flow edge in the pattern DAG: line DefLine defines CaptureName
/// which is used by line UseLine.
struct PatternEdge {
  unsigned DefLine;
  unsigned UseLine;
  std::string CaptureName;
};

/// Accumulated label from bottom-up DP.  Stored per (PatIdx, NodeID).
struct DPLabel {
  StringMap<Binding> Bindings;
  /// Which instruction matched each pattern line in this label's subtree.
  SmallDenseMap<unsigned, NodeID, 8> Trace;
};

/// Build the pattern dependency DAG and return edges + topological order.
/// An edge exists from line A to line B when A defines a register capture
/// that B uses.
static void buildPatternDAG(
    const BinaryContext &BC,
    const std::vector<PatternLine> &Pattern,
    SmallVectorImpl<PatternEdge> &Edges,
    SmallVectorImpl<unsigned> &TopoOrder) {

  // For each capture name, which line defines it (first definition wins).
  StringMap<unsigned> CaptureDef;
  for (unsigned I = 0; I < Pattern.size(); ++I) {
    const PatternLine &PL = Pattern[I];
    if (PL.IsAnnotationOnly)
      continue;
    SmallVector<std::string, 4> Defs, Uses;
    classifyCapturePositions(BC, PL, nullptr, Defs, Uses);
    for (const std::string &Name : Defs)
      CaptureDef.try_emplace(Name, I);
  }

  // Build edges: for each line that uses a capture defined by another line.
  // Adjacency for topo sort: InDeg[line] = number of predecessor lines.
  SmallVector<unsigned, 8> InDeg(Pattern.size(), 0);
  SmallVector<SmallVector<unsigned, 4>, 8> Successors(Pattern.size());

  for (unsigned I = 0; I < Pattern.size(); ++I) {
    const PatternLine &PL = Pattern[I];
    if (PL.IsAnnotationOnly)
      continue;
    SmallVector<std::string, 4> Defs, Uses;
    classifyCapturePositions(BC, PL, nullptr, Defs, Uses);

    DenseSet<unsigned> SeenPreds;
    for (const std::string &Name : Uses) {
      auto It = CaptureDef.find(Name);
      if (It == CaptureDef.end() || It->second == I)
        continue;
      unsigned DefLine = It->second;
      Edges.push_back({DefLine, I, Name});
      if (SeenPreds.insert(DefLine).second) {
        Successors[DefLine].push_back(I);
        InDeg[I]++;
      }
    }
  }

  // Kahn's algorithm for topological sort.
  SmallVector<unsigned, 8> Queue;
  for (unsigned I = 0; I < Pattern.size(); ++I) {
    if (!Pattern[I].IsAnnotationOnly && InDeg[I] == 0)
      Queue.push_back(I);
  }
  while (!Queue.empty()) {
    unsigned Cur = Queue.pop_back_val();
    TopoOrder.push_back(Cur);
    for (unsigned Succ : Successors[Cur]) {
      if (--InDeg[Succ] == 0)
        Queue.push_back(Succ);
    }
  }
}

/// Get the byte offset of an instruction within its function.
/// Tries MIB->getOffset() first, then falls back to computing from the
/// BB's input offset + instruction index * 4 (AArch64 fixed-width).
static int64_t getInstOffset(const BinaryContext &BC,
                              const InstrNode &Node,
                              const std::vector<BBInfo> &AllBBs) {
  auto MaybeOff = BC.MIB->getOffset(*Node.Inst);
  if (MaybeOff)
    return static_cast<int64_t>(*MaybeOff);
  // Fallback: BB offset + instruction index * 4.
  if (Node.BBIndex < AllBBs.size()) {
    uint32_t BBOff = AllBBs[Node.BBIndex].BB->getInputOffset();
    return static_cast<int64_t>(BBOff) + Node.InstIndex * 4;
  }
  return -1;
}

/// Stamp bindings with instruction offsets from the matched nodes.
/// For each pattern line, the captures it defines get the offset of the
/// instruction that matched that line. This makes offset() available in @filter.
static void stampBindingOffsets(const BinaryContext &BC,
                                const std::vector<PatternLine> &Pattern,
                                const DefUseGraph &G,
                                const SmallVector<NodeID, 8> &MatchedNodeIDs,
                                const std::vector<BBInfo> &AllBBs,
                                StringMap<Binding> &Bindings) {
  unsigned MI = 0;
  for (unsigned PI = 0; PI < Pattern.size(); ++PI) {
    if (Pattern[PI].IsAnnotationOnly)
      continue;
    if (MI >= MatchedNodeIDs.size())
      break;
    NodeID NID = MatchedNodeIDs[MI++];
    int64_t Off = getInstOffset(BC, G.Nodes[NID], AllBBs);
    if (Off < 0)
      continue;

    // Find which captures this pattern line defines.
    SmallVector<std::string, 4> Defs, Uses;
    classifyCapturePositions(BC, Pattern[PI], &G.Nodes[NID], Defs, Uses);
    for (const std::string &Name : Defs) {
      auto It = Bindings.find(Name);
      if (It != Bindings.end())
        It->second.InstOffset = Off;
    }
  }
}

/// Run DP matching on a single function.  Returns all complete matches.
static void dpMatchFunction(
    const BinaryContext &BC,
    const std::vector<PatternLine> &Pattern,
    const DefUseGraph &G,
    const std::vector<BBInfo> &AllBBs,
    const SmallVectorImpl<PatternEdge> &Edges,
    const SmallVectorImpl<unsigned> &TopoOrder,
    std::vector<MatchResult> &Results) {

  unsigned NumPat = Pattern.size();

  // Build per-line predecessor info: for each pattern line, which edges are
  // incoming (i.e., which captures it uses from which predecessor line).
  SmallVector<SmallVector<const PatternEdge *, 4>, 8> PredEdges(NumPat);
  for (const PatternEdge &E : Edges)
    PredEdges[E.UseLine].push_back(&E);

  // Precompute uppercase mnemonic for each pattern line (for opcode filter).
  SmallVector<std::string, 8> MnemUpper(NumPat);
  for (unsigned I = 0; I < NumPat; ++I)
    if (!Pattern[I].IsAnnotationOnly) {
      StringRef M = Pattern[I].Mnemonic;
      MnemUpper[I] = M.split('.').first.upper();
    }

  // Labels: for each pattern line, a map from NodeID to DPLabel.
  std::vector<DenseMap<NodeID, DPLabel>> Labels(NumPat);

  // Process pattern lines in topological order (leaves first).
  for (unsigned PatIdx : TopoOrder) {
    const PatternLine &PL = Pattern[PatIdx];
    const auto &Preds = PredEdges[PatIdx];
    bool IsLeaf = Preds.empty();

    if (IsLeaf) {
      // Leaf: scan all nodes with opcode filter.  If the filter yields
      // no matches, retry without it (handles instruction aliases like
      // sxtw → SBFMXri where printed mnemonic ≠ tablegen opcode name).
      for (int Pass = 0; Pass < 2; ++Pass) {
        bool UseFilter = (Pass == 0) && !MnemUpper[PatIdx].empty();
        for (NodeID NID = 0; NID < G.Nodes.size(); ++NID) {
          if (UseFilter) {
            StringRef OpName =
                BC.MII->getName(G.Nodes[NID].Inst->getOpcode());
            if (!OpName.starts_with_insensitive(MnemUpper[PatIdx]))
              continue;
          }
          G.Nodes[NID].ensureParsed(BC);
          StringMap<Binding> Bindings;
          if (!matchLine(BC, PL, G.Nodes[NID], Bindings))
            continue;
          DPLabel L;
          L.Bindings = std::move(Bindings);
          L.Trace[PatIdx] = NID;
          Labels[PatIdx][NID] = std::move(L);
        }
        if (!Labels[PatIdx].empty())
          break; // Found matches — don't retry.
      }
    } else {
      // Non-leaf: propagate from labeled predecessors via def-use edges.
      // Pick the predecessor with fewest labels as the "driving" edge,
      // then verify the rest.
      const PatternEdge *DrivingEdge = Preds[0];
      unsigned BestSize = Labels[Preds[0]->DefLine].size();
      for (unsigned I = 1; I < Preds.size(); ++I) {
        unsigned Sz = Labels[Preds[I]->DefLine].size();
        if (Sz < BestSize) {
          BestSize = Sz;
          DrivingEdge = Preds[I];
        }
      }

      // For each labeled node of the driving predecessor, walk OutEdges to
      // find candidate nodes for this pattern line.
      DenseSet<NodeID> Visited;
      for (auto &[PredNID, PredLabel] : Labels[DrivingEdge->DefLine]) {
        // Find the register for the driving capture.
        auto BIt = PredLabel.Bindings.find(DrivingEdge->CaptureName);
        if (BIt == PredLabel.Bindings.end() || BIt->second.K != Binding::Reg)
          continue;

        auto EIt = G.OutEdges.find(PredNID);
        if (EIt == G.OutEdges.end())
          continue;

        for (unsigned EIdx : EIt->second) {
          const DefUseEdge &Edge = G.Edges[EIdx];
          if (!regMatchesBinding(BC, Edge.Reg, BIt->second))
            continue;
          NodeID CandNID = Edge.Use;
          if (!Visited.insert(CandNID).second)
            continue;
          // Already labeled for this pattern line? Skip.
          if (Labels[PatIdx].count(CandNID))
            continue;

          G.Nodes[CandNID].ensureParsed(BC);
          // Seed bindings from the driving predecessor so back-references
          // (e.g., str %acc, _ where %acc was bound by an earlier line) work.
          StringMap<Binding> Bindings = PredLabel.Bindings;
          if (!matchLine(BC, PL, G.Nodes[CandNID], Bindings))
            continue;

          // Verify ALL predecessor edges are satisfied.
          DPLabel NewLabel;
          NewLabel.Bindings = std::move(Bindings);
          NewLabel.Trace[PatIdx] = CandNID;

          bool AllOK = true;
          for (const PatternEdge *PE : Preds) {
            // Find the register for this capture in the new bindings.
            auto CB = NewLabel.Bindings.find(PE->CaptureName);
            if (CB == NewLabel.Bindings.end() ||
                CB->second.K != Binding::Reg) {
              // Non-register capture (imm, label) — no edge check needed.
              continue;
            }

            // Walk InEdges of CandNID to find a predecessor with a label
            // for PE->DefLine.
            bool FoundPred = false;
            auto IE = G.InEdges.find(CandNID);
            if (IE != G.InEdges.end()) {
              for (unsigned EIdx2 : IE->second) {
                const DefUseEdge &E2 = G.Edges[EIdx2];
                if (!regMatchesBinding(BC, E2.Reg, CB->second))
                  continue;
                auto LIt = Labels[PE->DefLine].find(E2.Def);
                if (LIt == Labels[PE->DefLine].end())
                  continue;

                // Check binding consistency: any shared capture names
                // between the predecessor's label and ours must agree.
                bool Consistent = true;
                for (const auto &[Name, Val] : LIt->second.Bindings) {
                  auto MyIt = NewLabel.Bindings.find(Name);
                  if (MyIt == NewLabel.Bindings.end())
                    continue;
                  if (Val.K != MyIt->second.K) {
                    Consistent = false;
                    break;
                  }
                  if (Val.K == Binding::Reg &&
                      Val.RegVal != MyIt->second.RegVal) {
                    Consistent = false;
                    break;
                  }
                  if (Val.K == Binding::Imm &&
                      Val.ImmVal != MyIt->second.ImmVal) {
                    Consistent = false;
                    break;
                  }
                }
                if (!Consistent)
                  continue;

                // Also check trace consistency: if the predecessor's trace
                // overlaps ours, the same NodeID must be used.
                bool TraceOK = true;
                for (const auto &[PI, NI] : LIt->second.Trace) {
                  auto TIt = NewLabel.Trace.find(PI);
                  if (TIt != NewLabel.Trace.end() && TIt->second != NI) {
                    TraceOK = false;
                    break;
                  }
                }
                if (!TraceOK)
                  continue;

                // Merge predecessor's bindings and trace.
                for (const auto &[Name, Val] : LIt->second.Bindings)
                  NewLabel.Bindings.try_emplace(Name, Val);
                for (const auto &[PI, NI] : LIt->second.Trace)
                  NewLabel.Trace.try_emplace(PI, NI);
                FoundPred = true;
                break; // Greedy: first valid predecessor.
              }
            }
            if (!FoundPred) {
              AllOK = false;
              break;
            }
          }

          if (AllOK)
            Labels[PatIdx][CandNID] = std::move(NewLabel);
        }
      }
    }
  }

  // ---- Harvest ----
  // Find terminal pattern lines (no successors in the pattern DAG).
  DenseSet<unsigned> HasSuccessor;
  for (const PatternEdge &E : Edges)
    HasSuccessor.insert(E.DefLine);

  SmallVector<unsigned, 4> Terminals;
  for (unsigned PI : TopoOrder)
    if (!HasSuccessor.count(PI))
      Terminals.push_back(PI);

  // For patterns that are pure chains/trees, there's exactly one terminal
  // whose labels contain the full trace.  For DAGs with multiple terminals
  // (e.g., root has siblings that are both leaves), we need to join labels
  // from different terminals that share compatible traces.
  //
  // Strategy: pick the terminal with the fewest labels as the "primary".
  // For each primary label, find compatible labels in the other terminals
  // by matching on shared trace entries (same predecessor NodeID).
  unsigned PrimaryTerm = Terminals[0];
  for (unsigned I = 1; I < Terminals.size(); ++I) {
    if (Labels[Terminals[I]].size() < Labels[PrimaryTerm].size())
      PrimaryTerm = Terminals[I];
  }

  DenseSet<const MCInst *> Matched;
  for (auto &[PrimNID, PrimLabel] : Labels[PrimaryTerm]) {
    // Start with the primary terminal's trace and bindings.
    SmallDenseMap<unsigned, NodeID, 8> MergedTrace = PrimLabel.Trace;
    StringMap<Binding> MergedBindings = PrimLabel.Bindings;

    // Join with other terminals.
    bool JoinOK = true;
    for (unsigned T : Terminals) {
      if (T == PrimaryTerm)
        continue;

      // Find a label in terminal T that is consistent with MergedTrace.
      bool Found = false;
      for (auto &[TNID, TLabel] : Labels[T]) {
        // Check trace consistency.
        bool Consistent = true;
        for (const auto &[PI, NI] : TLabel.Trace) {
          auto MT = MergedTrace.find(PI);
          if (MT != MergedTrace.end() && MT->second != NI) {
            Consistent = false;
            break;
          }
        }
        if (!Consistent)
          continue;

        // Check binding consistency.
        for (const auto &[Name, Val] : TLabel.Bindings) {
          auto MB = MergedBindings.find(Name);
          if (MB == MergedBindings.end())
            continue;
          if (Val.K != MB->second.K ||
              (Val.K == Binding::Reg && Val.RegVal != MB->second.RegVal) ||
              (Val.K == Binding::Imm && Val.ImmVal != MB->second.ImmVal)) {
            Consistent = false;
            break;
          }
        }
        if (!Consistent)
          continue;

        // Merge.
        for (const auto &[PI, NI] : TLabel.Trace)
          MergedTrace.try_emplace(PI, NI);
        for (const auto &[Name, Val] : TLabel.Bindings)
          MergedBindings.try_emplace(Name, Val);
        Found = true;
        break;
      }
      if (!Found) {
        JoinOK = false;
        break;
      }
    }
    if (!JoinOK)
      continue;

    // Check that no instruction in this match was already used.
    bool Conflict = false;
    for (const auto &[PI, NI] : MergedTrace) {
      if (Matched.count(G.Nodes[NI].Inst)) {
        Conflict = true;
        break;
      }
    }
    if (Conflict)
      continue;

    // Build MatchedNodeIDs in pattern order.
    SmallVector<NodeID, 8> MatchedNodeIDs;
    bool Complete = true;
    DenseSet<NodeID> UsedNodes;
    for (unsigned PI = 0; PI < NumPat; ++PI) {
      if (Pattern[PI].IsAnnotationOnly)
        continue;
      auto TIt = MergedTrace.find(PI);
      if (TIt == MergedTrace.end()) {
        Complete = false;
        break;
      }
      // Each pattern line must match a distinct instruction.
      if (!UsedNodes.insert(TIt->second).second) {
        Complete = false;
        break;
      }
      MatchedNodeIDs.push_back(TIt->second);
    }
    if (!Complete)
      continue;

    // Stamp bindings with instruction offsets before constraint validation
    // so @filter can use offset().
    stampBindingOffsets(BC, Pattern, G, MatchedNodeIDs, AllBBs, MergedBindings);

    // Validate post-match constraints (@one_use, @same_bb, @filter, etc.).
    if (!validateConstraints(BC, Pattern, G, MatchedNodeIDs, MergedBindings))
      continue;

    // Mark all matched instructions.
    for (const auto &[PI, NI] : MergedTrace)
      Matched.insert(G.Nodes[NI].Inst);

    // Build result.
    MatchResult Result;
    Result.Bindings = std::move(MergedBindings);
    Result.MatchedNodeIDs = std::move(MatchedNodeIDs);
    for (NodeID NID : Result.MatchedNodeIDs) {
      const InstrNode &Node = G.Nodes[NID];
      Result.MatchedInstrs.push_back({&AllBBs[Node.BBIndex], Node.InstIndex});
    }
    Results.push_back(std::move(Result));
  }
}


// Print a match result (shared between linear and graph matchers).
static void printMatchResult(const BinaryContext &BC, const MatchResult &Result,
                             unsigned MatchNum) {
  outs() << "=== Match #" << MatchNum << " in " << Result.FunctionName
         << " ===\n";

  unsigned Ctx = opts::ContextLines;

  if (Ctx == 0) {
    // Original compact output — show offset if available.
    for (const auto &[BI, Idx] : Result.MatchedInstrs) {
      outs() << "  " << BI->BB->getName() << ":" << Idx;
      uint32_t BBOff = BI->BB->getInputOffset();
      outs() << " [+" << format_hex(BBOff + Idx * 4, 1) << "]";
      outs() << "  ";
      BC.InstPrinter->printInst(BI->Nodes[Idx].Inst, 0, "", *BC.STI, outs());
      outs() << "\n";
    }
  } else {
    // Context output: show surrounding instructions with matched lines marked.
    // Group matched instructions by BB.
    DenseMap<const BBInfo *, SmallVector<unsigned, 4>> MatchedByBB;
    for (const auto &[BI, Idx] : Result.MatchedInstrs)
      MatchedByBB[BI].push_back(Idx);

    for (auto &[BI, Indices] : MatchedByBB) {
      llvm::sort(Indices);
      unsigned NumInsts = BI->Nodes.size();
      DenseSet<unsigned> MatchedSet(Indices.begin(), Indices.end());

      // Build disjoint display windows: [lo, hi) around each matched index.
      // Merge overlapping windows.
      SmallVector<std::pair<unsigned, unsigned>, 4> Windows;
      for (unsigned Idx : Indices) {
        unsigned Lo = Idx >= Ctx ? Idx - Ctx : 0;
        unsigned Hi = std::min(NumInsts, Idx + Ctx + 1);
        if (!Windows.empty() && Lo <= Windows.back().second)
          Windows.back().second = std::max(Windows.back().second, Hi);
        else
          Windows.push_back({Lo, Hi});
      }

      outs() << "  " << BI->BB->getName() << ":\n";
      for (unsigned W = 0; W < Windows.size(); ++W) {
        if (W > 0)
          outs() << "      ...\n";
        for (unsigned I = Windows[W].first; I < Windows[W].second; ++I) {
          bool IsMatched = MatchedSet.count(I);
        outs() << (IsMatched ? "  >>> " : "      ");
        outs() << I << "\t";
        BC.InstPrinter->printInst(BI->Nodes[I].Inst, 0, "", *BC.STI, outs());

        // Annotate matched instructions with bindings.
        if (IsMatched) {
          SmallVector<std::pair<std::string, std::string>, 4> Annots;
          const InstrNode &Node = BI->Nodes[I];
          Node.ensureParsed(BC);
          for (const auto &[Name, B] : Result.Bindings) {
            if (B.K == Binding::Reg) {
              bool Found = false;
              for (MCPhysReg R : Node.Defs)
                if (regMatchesBinding(BC, R, B)) { Found = true; break; }
              if (!Found)
                for (MCPhysReg R : Node.Uses)
                  if (regMatchesBinding(BC, R, B)) { Found = true; break; }
              if (Found)
                Annots.push_back(
                    {Name.str(),
                     std::string(BC.MRI->getName(B.RegVal))});
            } else if (B.K == Binding::Imm) {
              // Check if the printed instruction contains this immediate.
              std::string Printed;
              raw_string_ostream PS(Printed);
              BC.InstPrinter->printInst(Node.Inst, 0, "", *BC.STI, PS);
              std::string ImmStr = ("#" + Twine(B.ImmVal)).str();
              if (Printed.find(ImmStr) != std::string::npos)
                Annots.push_back({Name.str(), ImmStr});
            }
          }
          if (!Annots.empty()) {
            outs() << "  //";
            for (auto &[N, V] : Annots)
              outs() << " %" << N << "=" << V;
          }
        }
        outs() << "\n";
        }
      }
    }
  }

  if (!Result.Bindings.empty()) {
    outs() << "  Bindings:\n";
    int64_t MinOff = INT64_MAX, MaxOff = INT64_MIN;
    for (const auto &[Name, B] : Result.Bindings) {
      outs() << "    %" << Name << " = ";
      if (B.K == Binding::Reg)
        outs() << BC.MRI->getName(B.RegVal);
      else if (B.K == Binding::Imm)
        outs() << "#" << B.ImmVal;
      else
        outs() << B.LabelVal;
      if (B.InstOffset >= 0) {
        outs() << " @+" << format_hex(B.InstOffset, 1);
        MinOff = std::min(MinOff, B.InstOffset);
        MaxOff = std::max(MaxOff, B.InstOffset);
      }
      outs() << "\n";
    }
    if (MinOff != INT64_MAX && MaxOff != INT64_MIN && MinOff != MaxOff)
      outs() << "  Span: " << (MaxOff - MinOff) << " bytes\n";
  }
  outs() << "\n";
}

/// Collect uppercase mnemonic prefixes from all non-annotation pattern lines.
/// Used for opcode-level pre-filtering: a function must contain at least one
/// instruction whose tablegen opcode name starts with each prefix.
/// Prefixes that don't match any tablegen opcode are dropped (they are
/// printed aliases like cset→CSINCWr that need the two-pass fallback).
static SmallVector<std::string, 4>
collectMnemPrefixes(const BinaryContext &BC,
                    const std::vector<PatternLine> &Pattern) {
  SmallVector<std::string, 4> Prefixes;
  for (const PatternLine &PL : Pattern) {
    if (PL.IsAnnotationOnly || PL.IsDefAnchor || PL.Mnemonic.empty())
      continue;
    // Skip regex mnemonics — can't build a reliable prefix.
    if (!PL.MnemRegex.empty())
      continue;
    // Strip NEON qualifier (e.g., ".4s", ".16b") — tablegen opcode names
    // like "ADDv4i32" don't contain the dot-qualifier.
    StringRef M = PL.Mnemonic;
    M = M.split('.').first;
    std::string Upper = M.upper();

    // Verify this prefix matches at least one tablegen opcode name.
    // If not, it's a printed alias (e.g., "cset" → CSINCWr) and we
    // can't use it for function-level pre-filtering.
    bool Valid = false;
    for (unsigned I = 0, E = BC.MII->getNumOpcodes(); I < E; ++I) {
      if (StringRef(BC.MII->getName(I)).starts_with_insensitive(Upper)) {
        Valid = true;
        break;
      }
    }
    if (Valid)
      Prefixes.push_back(std::move(Upper));
  }
  // Deduplicate.
  llvm::sort(Prefixes);
  Prefixes.erase(llvm::unique(Prefixes), Prefixes.end());
  return Prefixes;
}

/// Check if a function contains at least one instruction matching each prefix.
static bool functionHasAllOpcodes(const BinaryContext &BC,
                                  const BinaryFunction &BF,
                                  const SmallVectorImpl<std::string> &Prefixes) {
  if (Prefixes.empty())
    return true;

  // Bit per prefix: set when we find a matching opcode.
  SmallBitVector Found(Prefixes.size());
  unsigned Remaining = Prefixes.size();

  for (const BinaryBasicBlock &BB : BF) {
    for (const MCInst &Inst : BB) {
      StringRef OpName = BC.MII->getName(Inst.getOpcode());
      for (unsigned I = 0; I < Prefixes.size(); ++I) {
        if (!Found[I] && OpName.starts_with_insensitive(Prefixes[I])) {
          Found.set(I);
          if (--Remaining == 0)
            return true;
        }
      }
    }
  }
  return false;
}

static void runLinearMatcher(const BinaryContext &BC,
                             const std::vector<PatternLine> &Pattern,
                             unsigned &MatchCount,
                             std::vector<std::pair<std::string, unsigned>> &FuncHits,
                             match_tool::MatchSymbolizer *Symbolizer,
                             match_tool::SourceAggregator *Agg) {
  SmallVector<const BinaryFunction *, 0> Functions;
  for (const auto &[Addr, BF] : BC.getBinaryFunctions())
    Functions.push_back(&BF);

  std::vector<FunctionResults> AllResults(Functions.size());
  std::atomic<unsigned> Completed{0};
  unsigned Total = Functions.size();
  bool ShowProgress = errs().is_displayed();

  // Collect all pattern mnemonic prefixes for function-level pre-filter.
  SmallVector<std::string, 4> Prefixes = collectMnemPrefixes(BC, Pattern);

  DefaultThreadPool Pool(hardware_concurrency(opts::ThreadCount));
  for (unsigned FIdx = 0; FIdx < Functions.size(); ++FIdx) {
    Pool.async([&BC, &Pattern, &Functions, &AllResults, &Completed, Total,
                ShowProgress, FIdx, &Prefixes] {
      const BinaryFunction &BF = *Functions[FIdx];

      // Skip functions that don't contain all required opcodes.
      if (!functionHasAllOpcodes(BC, BF, Prefixes)) {
        if (ShowProgress) {
          unsigned Done = ++Completed;
          fprintf(stderr, "\rMatching: %u/%u functions (%u%%)", Done, Total,
                  Done * 100 / Total);
          fflush(stderr);
        }
        return;
      }

      std::vector<BBInfo> AllBBs = buildBBInfos(BC, BF);
      DenseSet<const MCInst *> LocalMatched;

      // Pre-compute first pattern line mnemonic (uppercased) for fast opcode
      // filtering. Empty if it's a printed alias (no tablegen opcode match).
      const PatternLine &FirstPL = Pattern[0];
      std::string FirstMnemUpper;
      if (!FirstPL.MnemRegex.empty() || FirstPL.IsDefAnchor) {
        // Regex or @def — no prefix filter possible.
      } else {
        std::string Cand = StringRef(FirstPL.Mnemonic).split('.').first.upper();
        // Only use as filter if it matches a real tablegen opcode.
        for (unsigned I = 0, E = BC.MII->getNumOpcodes(); I < E; ++I) {
          if (StringRef(BC.MII->getName(I)).starts_with_insensitive(Cand)) {
            FirstMnemUpper = std::move(Cand);
            break;
          }
        }
      }

      for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
        for (unsigned InstIdx = 0; InstIdx < AllBBs[BBIdx].Nodes.size();
             ++InstIdx) {
          if (LocalMatched.count(AllBBs[BBIdx].Nodes[InstIdx].Inst))
            continue;

          // Fast opcode-level pre-filter: tablegen name starts with uppercase mnem.
          const InstrNode &CandNode = AllBBs[BBIdx].Nodes[InstIdx];
          if (!FirstMnemUpper.empty()) {
            StringRef OpName = BC.MII->getName(CandNode.Inst->getOpcode());
            if (!OpName.starts_with_insensitive(FirstMnemUpper))
              continue;
          }

          MatchResult Result;
          if (tryMatch(BC, Pattern, AllBBs, BBIdx, InstIdx, Result)) {
            const auto &[FirstBI, FirstIdx] = Result.MatchedInstrs.front();
            LocalMatched.insert(FirstBI->Nodes[FirstIdx].Inst);
            Result.FunctionName = BF.getPrintName();
            Result.BF = &BF;
            AllResults[FIdx].Matches.push_back(std::move(Result));
          }
        }
      }

      AllResults[FIdx].AllBBs = std::move(AllBBs);

      if (ShowProgress) {
        unsigned Done = ++Completed;
        fprintf(stderr, "\rMatching: %u/%u functions (%u%%)", Done, Total,
                Done * 100 / Total);
        fflush(stderr);
      }
    });
  }
  Pool.wait();
  if (ShowProgress)
    fprintf(stderr, "\r\033[K");

  for (const auto &FR : AllResults) {
    for (const auto &Result : FR.Matches) {
      ++MatchCount;
      if (opts::OutputLevel == opts::OM_Detailed)
        printMatchResult(BC, Result, MatchCount);
      if (Agg && Symbolizer && Result.BF && !Result.MatchedInstrs.empty()) {
        const auto &[BI, Idx] = Result.MatchedInstrs.back();
        auto Loc = Symbolizer->resolve(BC, *Result.BF, *BI->Nodes[Idx].Inst);
        Agg->record(Loc);
      }
    }
    if (!FR.Matches.empty())
      FuncHits.emplace_back(FR.Matches.front().FunctionName,
                            FR.Matches.size());
  }
}

static void runGraphMatcher(const BinaryContext &BC,
                            const std::vector<PatternLine> &Pattern,
                            unsigned &MatchCount,
                            std::vector<std::pair<std::string, unsigned>> &FuncHits,
                            match_tool::MatchSymbolizer *Symbolizer,
                            match_tool::SourceAggregator *Agg) {
  SmallVector<const BinaryFunction *, 0> Functions;
  for (const auto &[Addr, BF] : BC.getBinaryFunctions())
    Functions.push_back(&BF);

  std::vector<FunctionResults> AllResults(Functions.size());
  std::atomic<unsigned> Completed{0};
  unsigned Total = Functions.size();
  bool ShowProgress = errs().is_displayed();

  // Collect all pattern mnemonic prefixes for function-level pre-filter.
  SmallVector<std::string, 4> Prefixes = collectMnemPrefixes(BC, Pattern);

  // Build pattern DAG once (shared across all threads — read-only).
  SmallVector<PatternEdge, 8> PatEdges;
  SmallVector<unsigned, 8> TopoOrder;
  buildPatternDAG(BC, Pattern, PatEdges, TopoOrder);

  DefaultThreadPool Pool(hardware_concurrency(opts::ThreadCount));
  for (unsigned FIdx = 0; FIdx < Functions.size(); ++FIdx) {
    Pool.async([&BC, &Pattern, &Functions, &AllResults, &Completed,
                Total, ShowProgress, FIdx, &Prefixes, &PatEdges, &TopoOrder] {
      const BinaryFunction &BF = *Functions[FIdx];

      // Skip functions that don't contain all required opcodes.
      if (!functionHasAllOpcodes(BC, BF, Prefixes)) {
        if (ShowProgress) {
          unsigned Done = ++Completed;
          fprintf(stderr, "\rMatching: %u/%u functions (%u%%)", Done, Total,
                  Done * 100 / Total);
          fflush(stderr);
        }
        return;
      }

      std::vector<BBInfo> AllBBs = buildBBInfos(BC, BF, /*ComputeLiveness=*/false);
      DefUseGraph G = buildDefUseGraph(AllBBs, BC);

      // Run DP matcher for this function.
      std::vector<MatchResult> FuncMatches;
      dpMatchFunction(BC, Pattern, G, AllBBs, PatEdges, TopoOrder,
                      FuncMatches);
      for (auto &R : FuncMatches) {
        R.FunctionName = BF.getPrintName();
        R.BF = &BF;
        AllResults[FIdx].Matches.push_back(std::move(R));
      }

      AllResults[FIdx].AllBBs = std::move(AllBBs);

      if (ShowProgress) {
        unsigned Done = ++Completed;
        fprintf(stderr, "\rMatching: %u/%u functions (%u%%)", Done, Total,
                Done * 100 / Total);
        fflush(stderr);
      }
    });
  }
  Pool.wait();
  if (ShowProgress)
    fprintf(stderr, "\r\033[K");

  for (const auto &FR : AllResults) {
    for (const auto &Result : FR.Matches) {
      ++MatchCount;
      if (opts::OutputLevel == opts::OM_Detailed)
        printMatchResult(BC, Result, MatchCount);
      if (Agg && Symbolizer && Result.BF && !Result.MatchedInstrs.empty()) {
        const auto &[BI, Idx] = Result.MatchedInstrs.back();
        auto Loc = Symbolizer->resolve(BC, *Result.BF, *BI->Nodes[Idx].Inst);
        Agg->record(Loc);
      }
    }
    if (!FR.Matches.empty())
      FuncHits.emplace_back(FR.Matches.front().FunctionName,
                            FR.Matches.size());
  }
}

static void runMatcher(const BinaryContext &BC,
                       const std::vector<PatternLine> &Pattern) {
  if (Pattern.empty())
    return;

  // Detect graph patterns: at least one capture name appears in more than
  // one non-annotation line (i.e., there are def-use dependencies between
  // pattern lines).
  bool IsGraphPattern = false;
  {
    StringMap<SmallVector<unsigned, 2>> CaptureLines;
    for (unsigned I = 0; I < Pattern.size(); ++I) {
      if (Pattern[I].IsAnnotationOnly)
        continue;
      auto CollectCaptures = [&](const PatternOperand &PO) {
        if (PO.K == PatternOperand::Capture && !PO.Name.empty())
          CaptureLines[PO.Name].push_back(I);
        if (PO.K == PatternOperand::MemOperand)
          for (const PatternOperand &Sub : PO.SubOperands)
            if (Sub.K == PatternOperand::Capture && !Sub.Name.empty())
              CaptureLines[Sub.Name].push_back(I);
      };
      for (const PatternOperand &PO : Pattern[I].Operands)
        CollectCaptures(PO);
      for (const Annotation &A : Pattern[I].Annotations)
        for (const PatternOperand &Op : A.Operands)
          CollectCaptures(Op);
      // DefAnchor names are capture definitions.
      for (const std::string &Name : Pattern[I].DefAnchorNames)
        CaptureLines[Name].push_back(I);
    }

    for (const auto &[Name, Lines] : CaptureLines) {
      SmallVector<unsigned, 2> Unique(Lines.begin(), Lines.end());
      llvm::sort(Unique);
      Unique.erase(llvm::unique(Unique), Unique.end());
      if (Unique.size() > 1) {
        IsGraphPattern = true;
        break;
      }
    }
  }

  // Also treat any pattern with @def or @filter as a graph pattern
  // (the linear matcher doesn't evaluate post-match constraints).
  for (const PatternLine &PL : Pattern) {
    if (PL.IsDefAnchor)
      IsGraphPattern = true;
    for (const Annotation &A : PL.Annotations)
      if (A.K == Annotation::Filter || A.K == Annotation::OneUse ||
          A.K == Annotation::HasUse)
        IsGraphPattern = true;
  }

  // Create symbolizer for source-level aggregation (if requested).
  std::unique_ptr<match_tool::MatchSymbolizer> Symbolizer;
  match_tool::SourceAggregator Agg;
  match_tool::MatchSymbolizer *SymPtr = nullptr;
  match_tool::SourceAggregator *AggPtr = nullptr;
  if (opts::SymbolizeOpt) {
    Symbolizer = std::make_unique<match_tool::MatchSymbolizer>(
        opts::InputFilename);
    SymPtr = Symbolizer.get();
    AggPtr = &Agg;
  }

  unsigned MatchCount = 0;
  std::vector<std::pair<std::string, unsigned>> FuncHits;
  if (IsGraphPattern) {
    outs() << "Using graph-based DP matcher\n";
    runGraphMatcher(BC, Pattern, MatchCount, FuncHits, SymPtr, AggPtr);
  } else {
    runLinearMatcher(BC, Pattern, MatchCount, FuncHits, SymPtr, AggPtr);
  }

  if (opts::OutputLevel == opts::OM_Summary) {
    // Sort by hit count descending.
    llvm::sort(FuncHits, [](const auto &A, const auto &B) {
      if (A.second != B.second)
        return A.second > B.second;
      return A.first < B.first;
    });
    for (const auto &[Name, Count] : FuncHits)
      outs() << "  " << Count << "\t" << Name << "\n";
  }

  outs() << "Total matches: " << MatchCount << "\n";

  // Print source-level aggregation if --symbolize was requested.
  if (AggPtr) {
    if (Agg.Resolved > 0) {
      outs() << "\nSource aggregation:\n";
      Agg.printByFile(outs(), 15);
      Agg.printByLocation(outs(), 20);
    } else {
      outs() << "\nNo source locations resolved (" << Agg.Unresolved
             << " unresolved). Binary may lack debug info.\n"
             << "  Hint: on macOS, run `dsymutil <binary>` to generate a .dSYM\n";
    }
  }
}

// ===----------------------------------------------------------------------===//
// Dump helpers
// ===----------------------------------------------------------------------===//

static void printLiveness(const BinaryContext &BC, const BinaryFunction &BF) {
  std::vector<BBInfo> AllBBs = buildBBInfos(BC, BF);

  outs() << "Function: " << BF.getPrintName() << "\n";
  for (const auto &Info : AllBBs) {
    outs() << "  BB " << Info.BB->getName() << "\n";
    outs() << "    Live-in: ";
    for (unsigned I = 0, E = Info.LiveIn.size(); I < E; ++I)
      if (Info.LiveIn[I])
        outs() << " " << BC.MRI->getName(I);
    outs() << "\n";
    outs() << "    Live-out:";
    for (unsigned I = 0, E = Info.LiveOut.size(); I < E; ++I)
      if (Info.LiveOut[I])
        outs() << " " << BC.MRI->getName(I);
    outs() << "\n";
  }
}

static void printFunctions(const BinaryContext &BC) {
  for (const auto &[Addr, BF] : BC.getBinaryFunctions()) {
    outs() << "Function: " << BF.getPrintName() << "\n";
    for (const BinaryBasicBlock &BB : BF) {
      outs() << "  BB " << BB.getName() << " (" << BB.size()
             << " instrs)\n";
      for (const MCInst &Inst : BB) {
        outs() << "    ";
        BC.InstPrinter->printInst(&Inst, 0, "", *BC.STI, outs());

        const MCInstrDesc &Desc = BC.MII->get(Inst.getOpcode());
        ArrayRef<MCPhysReg> ImpDefs = Desc.implicit_defs();
        ArrayRef<MCPhysReg> ImpUses = Desc.implicit_uses();
        if (!ImpDefs.empty() || !ImpUses.empty()) {
          outs() << "  #";
          if (!ImpDefs.empty()) {
            outs() << " imp-def:";
            for (MCPhysReg Reg : ImpDefs)
              outs() << " " << BC.MRI->getName(Reg);
            if (!ImpUses.empty())
              outs() << ",";
          }
          if (!ImpUses.empty()) {
            outs() << " imp-use:";
            for (MCPhysReg Reg : ImpUses)
              outs() << " " << BC.MRI->getName(Reg);
          }
        }
        outs() << "\n";
      }
    }
  }
}

/// Escape a string for use inside a DOT label.
static std::string dotEscape(StringRef S) {
  std::string R;
  R.reserve(S.size());
  for (char C : S) {
    switch (C) {
    case '"':  R += "\\\""; break;
    case '\\': R += "\\\\"; break;
    case '<':  R += "\\<"; break;
    case '>':  R += "\\>"; break;
    case '{':  R += "\\{"; break;
    case '}':  R += "\\}"; break;
    case '|':  R += "\\|"; break;
    case '\n': R += "\\n"; break;
    default:   R += C; break;
    }
  }
  return R;
}

/// Get single-line assembly text for an instruction.
static std::string getInstText(const BinaryContext &BC, const MCInst &Inst) {
  std::string Buf;
  raw_string_ostream OS(Buf);
  BC.InstPrinter->printInst(&Inst, 0, "", *BC.STI, OS);
  // Trim leading whitespace and collapse tab to space.
  StringRef S(Buf);
  S = S.ltrim();
  std::string R;
  R.reserve(S.size());
  for (char C : S)
    R += (C == '\t') ? ' ' : C;
  return R;
}

/// Escape a string for use inside an HTML label (Graphviz <<...>> labels).
static std::string htmlEscape(StringRef S) {
  std::string R;
  R.reserve(S.size());
  for (char C : S) {
    switch (C) {
    case '&':  R += "&amp;"; break;
    case '<':  R += "&lt;"; break;
    case '>':  R += "&gt;"; break;
    case '"':  R += "&quot;"; break;
    default:   R += C; break;
    }
  }
  return R;
}

/// Pick an instruction background color string (HTML hex).
static const char *instrColor(const BinaryContext &BC, const MCInst &Inst) {
  if (BC.MIB->isCall(Inst))
    return "#fff3cd"; // light yellow
  if (BC.MII->get(Inst.getOpcode()).isReturn())
    return "#f8d7da"; // light red
  if (BC.MII->get(Inst.getOpcode()).isBranch())
    return "#cfe2ff"; // light blue
  return "#ffffff";   // white
}

/// Emit a function's def-use graph as Graphviz DOT.
static void emitFunctionDot(const BinaryContext &BC,
                            const BinaryFunction &BF,
                            raw_ostream &OS) {
  std::vector<BBInfo> AllBBs = buildBBInfos(BC, BF, /*ComputeLiveness=*/false);
  DefUseGraph G = buildDefUseGraph(AllBBs, BC);
  const MCRegisterInfo &MRI = *BC.MRI;

  // Detect argument live-ins: find uses of ABI parameter registers that
  // have no in-function definer (no incoming def-use edge for that regunit).
  BitVector ParamRegs = BC.MIB->getRegsUsedAsParams();

  struct ArgLiveIn {
    MCPhysReg Reg;
    NodeID FirstUse;
  };
  SmallVector<ArgLiveIn, 8> ArgLiveIns;

  {
    DenseMap<unsigned, std::pair<MCPhysReg, NodeID>> FirstArgUse;

    for (unsigned NID = 0; NID < G.Nodes.size(); ++NID) {
      const InstrNode &Node = G.Nodes[NID];
      for (MCPhysReg Reg : Node.Uses) {
        if (!ParamRegs.test(Reg))
          continue;
        for (MCRegUnit RU : MRI.regunits(Reg)) {
          unsigned U = static_cast<unsigned>(RU);
          if (FirstArgUse.count(U))
            continue;
          // Check if this use has an in-graph def via InEdges.
          // Skip self-edges (e.g. post-indexed ldr defines and uses the
          // same base register) — the first iteration still needs the arg.
          bool HasDef = false;
          auto EIt = G.InEdges.find(NID);
          if (EIt != G.InEdges.end()) {
            for (unsigned EIdx : EIt->second) {
              if (G.Edges[EIdx].Def == NID)
                continue; // self-edge
              for (MCRegUnit ERU : MRI.regunits(G.Edges[EIdx].Reg)) {
                if (static_cast<unsigned>(ERU) == U) {
                  HasDef = true;
                  break;
                }
              }
              if (HasDef)
                break;
            }
          }
          if (!HasDef) {
            // Also skip if this regunit is defined by any earlier node
            // (in program order) — means it's locally produced, not an arg.
            bool DefinedEarlier = false;
            for (unsigned D = 0; D < NID; ++D) {
              for (MCPhysReg DReg : G.Nodes[D].Defs) {
                for (MCRegUnit DRU : MRI.regunits(DReg)) {
                  if (static_cast<unsigned>(DRU) == U) {
                    DefinedEarlier = true;
                    break;
                  }
                }
                if (DefinedEarlier)
                  break;
              }
              if (DefinedEarlier)
                break;
            }
            if (!DefinedEarlier)
              FirstArgUse[U] = {Reg, NID};
          }
        }
      }
    }

    DenseSet<unsigned> SeenRegs;
    for (auto &KV : FirstArgUse) {
      if (SeenRegs.insert(KV.second.first).second)
        ArgLiveIns.push_back({KV.second.first, KV.second.second});
    }
    llvm::sort(ArgLiveIns, [&](const ArgLiveIn &A, const ArgLiveIn &B) {
      return MRI.getName(A.Reg) < MRI.getName(B.Reg);
    });
  }

  // Count non-empty BBs to decide layout strategy.
  unsigned NonEmptyBBs = 0;
  for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
    unsigned Start = G.BBStart[BBIdx];
    unsigned End = (BBIdx + 1 < AllBBs.size()) ? G.BBStart[BBIdx + 1]
                                                : G.Nodes.size();
    if (Start < End)
      NonEmptyBBs++;
  }
  bool IsSmall = NonEmptyBBs <= 8;

  OS << "digraph \"" << dotEscape(BF.getPrintName()) << "\" {\n";
  OS << "  rankdir=TB;\n";
  OS << "  compound=true;\n";
  OS << "  node [shape=plaintext, fontname=\"Courier\", fontsize=10];\n";
  OS << "  edge [fontname=\"Courier\", fontsize=9];\n";
  OS << "  newrank=true;\n";
  // Graph title.
  std::string FuncTitle = BF.getPrintName();
  if (FuncTitle.size() > 60)
    FuncTitle = FuncTitle.substr(0, 57) + "...";
  OS << "  label=<<B>" << htmlEscape(FuncTitle) << "</B>>;\n";
  OS << "  labelloc=t; fontname=\"Helvetica\"; fontsize=14;\n\n";

  // ---- Left panel: linear disassembly listing ----
  OS << "  listing [shape=plaintext, label=<\n";
  OS << "    <TABLE BORDER=\"1\" CELLBORDER=\"0\" CELLSPACING=\"0\" "
        "CELLPADDING=\"4\" BGCOLOR=\"#f8f9fa\">\n";

  if (!ArgLiveIns.empty()) {
    OS << "    <TR><TD COLSPAN=\"2\" BGCOLOR=\"#d1ecf1\" ALIGN=\"LEFT\">"
          "<I>args: ";
    for (unsigned I = 0; I < ArgLiveIns.size(); ++I) {
      if (I > 0)
        OS << ", ";
      OS << MRI.getName(ArgLiveIns[I].Reg);
    }
    OS << "</I></TD></TR>\n";
  }

  for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
    unsigned Start = G.BBStart[BBIdx];
    unsigned End = (BBIdx + 1 < AllBBs.size()) ? G.BBStart[BBIdx + 1]
                                                : G.Nodes.size();
    if (Start == End)
      continue;
    OS << "    <TR><TD COLSPAN=\"2\" BGCOLOR=\"#e2e3e5\" ALIGN=\"LEFT\">"
          "<B>" << htmlEscape(AllBBs[BBIdx].BB->getName()) << ":</B>"
          "</TD></TR>\n";
    for (unsigned NID = Start; NID < End; ++NID) {
      std::string Text = getInstText(BC, *G.Nodes[NID].Inst);
      const char *Color = instrColor(BC, *G.Nodes[NID].Inst);
      OS << "    <TR><TD PORT=\"p" << NID << "\" BGCOLOR=\"" << Color
         << "\" ALIGN=\"LEFT\"><FONT POINT-SIZE=\"9\" COLOR=\"#6c757d\">"
         << NID << "</FONT></TD>"
         << "<TD BGCOLOR=\"" << Color << "\" ALIGN=\"LEFT\">"
         << htmlEscape(Text) << "</TD></TR>\n";
    }
  }
  OS << "    </TABLE>\n  >];\n\n";

  // ---- Argument live-in nodes (small functions only) ----
  if (IsSmall && !ArgLiveIns.empty()) {
    for (unsigned I = 0; I < ArgLiveIns.size(); ++I) {
      OS << "  arg" << I << " [label=\""
         << MRI.getName(ArgLiveIns[I].Reg) << "\""
         << ", shape=ellipse, style=\"filled,bold\""
         << ", fillcolor=\"#d1ecf1\", color=\"#0c5460\""
         << ", fontname=\"Courier\", fontsize=10];\n";
    }
    OS << "\n";
  }

  // ---- Graph: individual instruction nodes inside BB clusters ----
  DenseMap<const BinaryBasicBlock *, unsigned> BBPtrToIdx;
  for (unsigned I = 0; I < AllBBs.size(); ++I)
    BBPtrToIdx[AllBBs[I].BB] = I;

  for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
    unsigned Start = G.BBStart[BBIdx];
    unsigned End = (BBIdx + 1 < AllBBs.size()) ? G.BBStart[BBIdx + 1]
                                                : G.Nodes.size();
    if (Start == End)
      continue;

    OS << "  subgraph cluster_bb" << BBIdx << " {\n";
    OS << "    label=<<B>" << htmlEscape(AllBBs[BBIdx].BB->getName())
       << "</B>>;\n";
    OS << "    style=bold; color=\"#495057\"; penwidth=2; "
          "fontname=\"Helvetica\"; fontsize=11;\n";
    OS << "    labeljust=l;\n";

    for (unsigned NID = Start; NID < End; ++NID) {
      std::string Text = getInstText(BC, *G.Nodes[NID].Inst);
      const char *Color = instrColor(BC, *G.Nodes[NID].Inst);
      OS << "    n" << NID
         << " [label=<<FONT>" << htmlEscape(Text) << "</FONT>>"
         << ", shape=box, style=filled"
         << ", fillcolor=\"" << Color << "\"];\n";
    }

    // Invisible chain for instruction ordering.
    if (End - Start > 1) {
      OS << "    ";
      for (unsigned NID = Start; NID < End; ++NID) {
        if (NID > Start)
          OS << " -> ";
        OS << "n" << NID;
      }
      OS << " [style=invis, weight=10];\n";
    }

    OS << "  }\n\n";
  }

  // ---- Layout ----
  if (IsSmall) {
    // Side-by-side: all BB heads + listing on the same rank.
    OS << "  { rank=same; listing;";
    for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
      unsigned Start = G.BBStart[BBIdx];
      unsigned End = (BBIdx + 1 < AllBBs.size()) ? G.BBStart[BBIdx + 1]
                                                  : G.Nodes.size();
      if (Start < End)
        OS << " n" << Start << ";";
    }
    OS << " }\n";
    if (!ArgLiveIns.empty())
      OS << "  arg0 -> n0 [style=invis];\n";
  } else {
    // Free layout: pin listing next to first node.
    if (!G.Nodes.empty())
      OS << "  { rank=same; listing; n0; }\n";
  }
  OS << "\n";

  // ---- Control flow edges ----
  for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
    unsigned Start = G.BBStart[BBIdx];
    unsigned End = (BBIdx + 1 < AllBBs.size()) ? G.BBStart[BBIdx + 1]
                                                : G.Nodes.size();
    if (Start == End)
      continue;
    unsigned LastNID = End - 1;

    for (const BinaryBasicBlock *Succ : AllBBs[BBIdx].BB->successors()) {
      auto It = BBPtrToIdx.find(Succ);
      if (It == BBPtrToIdx.end())
        continue;
      unsigned SuccIdx = It->second;
      unsigned SuccStart = G.BBStart[SuccIdx];
      unsigned SuccEnd = (SuccIdx + 1 < AllBBs.size())
                             ? G.BBStart[SuccIdx + 1]
                             : G.Nodes.size();
      if (SuccStart == SuccEnd)
        continue;

      OS << "  n" << LastNID << " -> n" << SuccStart
         << " [style=bold, penwidth=2, color=\"#343a40\""
         << ", arrowsize=1.2";
      if (IsSmall)
        OS << ", constraint=false, weight=0";
      if (SuccIdx != BBIdx) {
        OS << ", lhead=cluster_bb" << SuccIdx
           << ", ltail=cluster_bb" << BBIdx;
      }
      OS << "];\n";
    }
  }
  OS << "\n";

  // ---- Argument live-in edges (small functions only) ----
  if (IsSmall) {
    for (unsigned I = 0; I < ArgLiveIns.size(); ++I) {
      OS << "  arg" << I << " -> n" << ArgLiveIns[I].FirstUse
         << " [label=\"" << MRI.getName(ArgLiveIns[I].Reg) << "\""
         << ", color=\"#0c5460\", style=bold, penwidth=1.5];\n";
    }
  }

  // ---- All def-use edges ----
  for (const auto &E : G.Edges) {
    OS << "  n" << E.Def << " -> n" << E.Use
       << " [label=\"" << BC.MRI->getName(E.Reg) << "\"";
    if (G.Nodes[E.Def].BBIndex != G.Nodes[E.Use].BBIndex)
      OS << ", style=dashed, color=red";
    else
      OS << ", color=\"#0d6efd\"";
    OS << "];\n";
  }

  OS << "}\n";
}

// ===----------------------------------------------------------------------===//
// SVG CFG output (via Triskel SESE layout)
// ===----------------------------------------------------------------------===//

namespace {

/// Lightweight SVG renderer implementing the triskel::ExportingRenderer
/// interface.  Accumulates SVG elements into a string buffer — no Cairo or
/// any other external rendering library needed.
class SvgRenderer : public triskel::ExportingRenderer {
  std::string Buf;
  float Width = 0, Height = 0;

  static std::string colorStr(triskel::Color C) {
    char Hex[8];
    snprintf(Hex, sizeof(Hex), "#%02x%02x%02x", C.r, C.g, C.b);
    return Hex;
  }

public:
  void begin(float W, float H) override {
    Width = W + 2 * PADDING;
    Height = H + 2 * PADDING;
    Buf.clear();
    // Apply PADDING translation via an SVG group transform (matching Cairo
    // renderer behavior).
    Buf += "<g transform=\"translate(" + std::to_string(PADDING) + "," +
           std::to_string(PADDING) + ")\">\n";
  }

  void end() override { Buf += "</g>\n"; }

  void draw_line(triskel::Point S, triskel::Point E,
                 const StrokeStyle &St) override {
    Buf += "<line x1=\"" + std::to_string(S.x) + "\" y1=\"" +
           std::to_string(S.y) + "\" x2=\"" + std::to_string(E.x) +
           "\" y2=\"" + std::to_string(E.y) + "\" stroke=\"" +
           colorStr(St.color) + "\" stroke-width=\"" +
           std::to_string(St.thickness) + "\"/>\n";
  }

  void draw_triangle(triskel::Point V1, triskel::Point V2, triskel::Point V3,
                     triskel::Color Fill) override {
    Buf += "<polygon points=\"" + std::to_string(V1.x) + "," +
           std::to_string(V1.y) + " " + std::to_string(V2.x) + "," +
           std::to_string(V2.y) + " " + std::to_string(V3.x) + "," +
           std::to_string(V3.y) + "\" fill=\"" + colorStr(Fill) + "\"/>\n";
  }

  void draw_rectangle(triskel::Point TL, float W, float H,
                      triskel::Color Fill) override {
    Buf += "<rect x=\"" + std::to_string(TL.x) + "\" y=\"" +
           std::to_string(TL.y) + "\" width=\"" + std::to_string(W) +
           "\" height=\"" + std::to_string(H) + "\" fill=\"" +
           colorStr(Fill) + "\"/>\n";
  }

  void draw_rectangle_border(triskel::Point TL, float W, float H,
                             const StrokeStyle &St) override {
    Buf += "<rect x=\"" + std::to_string(TL.x) + "\" y=\"" +
           std::to_string(TL.y) + "\" width=\"" + std::to_string(W) +
           "\" height=\"" + std::to_string(H) + "\" fill=\"none\" stroke=\"" +
           colorStr(St.color) + "\" stroke-width=\"" +
           std::to_string(St.thickness) + "\"/>\n";
  }

  void draw_text(triskel::Point TL, const std::string &Text,
                 const TextStyle &St) override {
    // Offset by BLOCK_PADDING (matching Cairo renderer) so text sits inside
    // the basic-block rectangle.
    float X = TL.x + BLOCK_PADDING;
    float Y = TL.y + BLOCK_PADDING + STYLE_TEXT.line_height;
    size_t Pos = 0;
    while (Pos < Text.size()) {
      size_t NL = Text.find('\n', Pos);
      if (NL == std::string::npos)
        NL = Text.size();
      std::string Line = htmlEscape(StringRef(Text).slice(Pos, NL));
      Buf += "<text x=\"" + std::to_string(X) + "\" y=\"" +
             std::to_string(Y) +
             "\" font-family=\"Courier,monospace\" font-size=\"" +
             std::to_string(St.size) + "\" fill=\"" + colorStr(St.color) +
             "\">" + Line + "</text>\n";
      Y += St.line_height;
      Pos = NL + 1;
    }
  }

  auto measure_text(const std::string &Text,
                    const TextStyle &St) const -> triskel::Point override {
    // Estimate dimensions for monospace font.
    float CharW = St.size * 0.6f;
    unsigned MaxCols = 0, Lines = 0;
    unsigned Col = 0;
    for (char C : Text) {
      if (C == '\n') {
        MaxCols = std::max(MaxCols, Col);
        Col = 0;
        ++Lines;
      } else {
        ++Col;
      }
    }
    if (Col > 0)
      ++Lines;
    MaxCols = std::max(MaxCols, Col);
    float W = MaxCols * CharW + 2 * BLOCK_PADDING;
    float H = Lines * St.line_height + 2 * BLOCK_PADDING;
    return {W, H};
  }

  void save(const std::filesystem::path &Path) override {
    std::string Svg;
    Svg += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    Svg += "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"" +
           std::to_string(Width) + "\" height=\"" + std::to_string(Height) +
           "\">\n";
    Svg += "<rect width=\"100%\" height=\"100%\" fill=\"white\"/>\n";
    Svg += Buf;
    Svg += "</svg>\n";

    std::ofstream Ofs(Path);
    Ofs << Svg;
  }
};

} // anonymous namespace

/// Emit a function's CFG as SVG using Triskel SESE-aware layout.
static void emitFunctionSvg(const BinaryContext &BC, const BinaryFunction &BF,
                             const std::filesystem::path &OutPath) {
  std::vector<BBInfo> AllBBs = buildBBInfos(BC, BF, /*ComputeLiveness=*/false);

  SvgRenderer Renderer;
  auto Builder = triskel::make_layout_builder();

  // Map BB index → triskel node ID.
  std::vector<size_t> NodeIDs;
  NodeIDs.reserve(AllBBs.size());

  for (const BBInfo &BI : AllBBs) {
    std::string Label;
    // BB header line.
    Label += ("BB#" + Twine(BI.Nodes.empty() ? 0 : BI.Nodes[0].BBIndex)).str();
    if (BI.BB->isEntryPoint())
      Label += " (entry)";
    Label += "\n";
    for (const InstrNode &N : BI.Nodes) {
      Label += getInstText(BC, *N.Inst);
      Label += "\n";
    }
    if (!Label.empty() && Label.back() == '\n')
      Label.pop_back();
    NodeIDs.push_back(Builder->make_node(Renderer, Label));
  }

  // Add CFG edges.
  for (unsigned I = 0; I < AllBBs.size(); ++I) {
    const BinaryBasicBlock *BB = AllBBs[I].BB;
    const BinaryBasicBlock *CondSucc = BB->getConditionalSuccessor(false);
    for (BinaryBasicBlock *Succ : BB->successors()) {
      // Find successor's index in AllBBs.
      unsigned TargetIdx = 0;
      for (unsigned J = 0; J < AllBBs.size(); ++J) {
        if (AllBBs[J].BB == Succ) {
          TargetIdx = J;
          break;
        }
      }
      auto ET = triskel::LayoutBuilder::EdgeType::Default;
      if (BB->succ_size() == 2) {
        ET = (Succ == CondSucc)
                 ? triskel::LayoutBuilder::EdgeType::True
                 : triskel::LayoutBuilder::EdgeType::False;
      }
      Builder->make_edge(NodeIDs[I], NodeIDs[TargetIdx], ET);
    }
  }

  auto Layout = Builder->build();
  Layout->render_and_save(Renderer, OutPath);
}

/// Dump CFG SVGs for all functions matching the given regex.
static void dumpSvgGraphs(const BinaryContext &BC, StringRef RegexStr) {
  Regex RE(RegexStr);
  std::string Err;
  if (!RE.isValid(Err)) {
    errs() << ToolName << ": invalid regex '" << RegexStr << "': " << Err
           << "\n";
    return;
  }

  unsigned Count = 0;
  for (const auto &[Addr, BF] : BC.getBinaryFunctions()) {
    if (!RE.match(BF.getPrintName()))
      continue;

    std::string Filename = ("graph_" + Twine(Count++) + ".svg").str();
    emitFunctionSvg(BC, BF, Filename);
    outs() << "Wrote " << BF.getPrintName() << " -> " << Filename << " ("
           << BF.size() << " BBs)\n";
  }

  if (Count == 0)
    outs() << "No functions matched '" << RegexStr << "'\n";
  else
    outs() << Count << " SVG(s) written.\n";
}

/// Dump def-use graphs for all functions matching the given regex.
static void dumpGraphs(const BinaryContext &BC, StringRef RegexStr) {
  Regex RE(RegexStr);
  std::string Err;
  if (!RE.isValid(Err)) {
    errs() << ToolName << ": invalid regex '" << RegexStr << "': " << Err
           << "\n";
    return;
  }

  unsigned Count = 0;
  for (const auto &[Addr, BF] : BC.getBinaryFunctions()) {
    if (!RE.match(BF.getPrintName()))
      continue;

    std::string Filename =
        ("graph_" + Twine(Count++) + ".dot").str();
    std::error_code EC;
    raw_fd_ostream File(Filename, EC);
    if (EC) {
      report_error(Filename, EC);
      continue;
    }

    emitFunctionDot(BC, BF, File);
    outs() << "Wrote " << BF.getPrintName() << " → " << Filename
           << " (" << BF.size() << " BBs)\n";
  }

  if (Count == 0)
    outs() << "No functions matched '" << RegexStr << "'\n";
  else
    outs() << Count << " graph(s) written.\n";
}

// ===----------------------------------------------------------------------===//
// MIR extraction — convert BinaryFunction to MachineFunction in SSA form
// ===----------------------------------------------------------------------===//

/// Sanitize a function name for use as a filename.
static std::string sanitizeFilename(StringRef Name) {
  std::string Result;
  Result.reserve(Name.size());
  for (char C : Name) {
    if (C == '/' || C == '\\' || C == '<' || C == '>' || C == ':' ||
        C == '"' || C == '|' || C == '?' || C == '*' || C == ' ')
      Result.push_back('_');
    else
      Result.push_back(C);
  }
  // Truncate overly long names.
  if (Result.size() > 200)
    Result.resize(200);
  return Result;
}

/// Convert a single BinaryFunction to a MachineFunction in Machine SSA form
/// and write it as a .mir file.
static bool extractFunctionToMIR(const BinaryContext &BC,
                                 const BinaryFunction &BF,
                                 TargetMachine &TM,
                                 MachineModuleInfo &MMI,
                                 Module &IRMod,
                                 const std::string &OutDir) {
  LLVMContext &Ctx = IRMod.getContext();

  // Skip functions with no basic blocks.
  if (BF.empty())
    return false;

  // Create a dummy IR function for this binary function.
  auto *FuncTy = FunctionType::get(Type::getVoidTy(Ctx), false);
  std::string FuncName = BF.getPrintName();
  auto *IRFunc = Function::Create(FuncTy, GlobalValue::ExternalLinkage,
                                  FuncName, &IRMod);

  // Get or create the MachineFunction.
  MachineFunction &MF = MMI.getOrCreateMachineFunction(*IRFunc);
  MachineRegisterInfo &MRI = MF.getRegInfo();
  const TargetSubtargetInfo &STI = MF.getSubtarget();
  const TargetInstrInfo *TII = STI.getInstrInfo();
  const TargetRegisterInfo *TRI = STI.getRegisterInfo();

  // Safe wrapper: getMinimalPhysRegClass asserts for registers with no class.
  auto safeGetRC = [&](MCPhysReg Reg) -> const TargetRegisterClass * {
    for (const TargetRegisterClass *RC : TRI->regclasses())
      if (RC->contains(Reg))
        return TRI->getMinimalPhysRegClass(Reg);
    return nullptr;
  };

  // Mark as SSA with tracked liveness.
  MF.getProperties().setIsSSA();
  MF.getProperties().setTracksLiveness();

  // Build BB infos and def-use graph from BOLT.
  std::vector<BBInfo> AllBBs = buildBBInfos(BC, BF, /*ComputeLiveness=*/false);
  if (AllBBs.empty()) {
    MMI.deleteMachineFunctionFor(*IRFunc);
    IRFunc->eraseFromParent();
    return false;
  }
  DefUseGraph DUG = buildDefUseGraph(AllBBs, BC);

  // Create MachineBasicBlocks and record mapping.
  std::vector<MachineBasicBlock *> MBBs;
  MBBs.reserve(AllBBs.size());
  DenseMap<const BinaryBasicBlock *, MachineBasicBlock *> BBMap;
  for (unsigned I = 0; I < AllBBs.size(); ++I) {
    MachineBasicBlock *MBB = MF.CreateMachineBasicBlock();
    MF.push_back(MBB);
    MBBs.push_back(MBB);
    BBMap[AllBBs[I].BB] = MBB;
  }

  // Set up CFG successor edges.
  for (unsigned I = 0; I < AllBBs.size(); ++I) {
    const BinaryBasicBlock *BB = AllBBs[I].BB;
    for (const BinaryBasicBlock *Succ : BB->successors()) {
      auto It = BBMap.find(Succ);
      if (It != BBMap.end())
        MBBs[I]->addSuccessor(It->second);
    }
  }

  // --- SSA Construction ---
  // For each instruction def in the DefUseGraph, allocate a virtual register.
  // Use the register class from the instruction's operand descriptor rather
  // than getMinimalPhysRegClass, so we get natural classes (e.g. GPR32 instead
  // of matrixindexgpr32_8_11).
  // Map: (NodeID, PhysReg) → VReg
  DenseMap<std::pair<NodeID, MCPhysReg>, Register> DefToVReg;

  for (unsigned NID = 0; NID < DUG.Nodes.size(); ++NID) {
    const InstrNode &Node = DUG.Nodes[NID];
    const MCInst &Inst = *Node.Inst;
    if (BC.MIB->isPseudo(Inst))
      continue;
    const MCInstrDesc &MCID = BC.MII->get(Inst.getOpcode());
    unsigned NumPrimeOps = MCPlus::getNumPrimeOperands(Inst);

    // Explicit def operands — use the register class from the MCInstrDesc.
    for (unsigned I = 0; I < NumPrimeOps && I < MCID.getNumDefs(); ++I) {
      const MCOperand &MCOp = Inst.getOperand(I);
      if (!MCOp.isReg() || MCOp.getReg() == 0)
        continue;
      MCPhysReg PReg = MCOp.getReg();

      const TargetRegisterClass *RC = nullptr;
      if (I < MCID.getNumOperands()) {
        int16_t RCIdx = MCID.operands()[I].RegClass;
        if (RCIdx >= 0)
          RC = TRI->getRegClass(RCIdx);
      }
      // Fallback to getMinimalPhysRegClass if no operand info available.
      if (!RC)
        RC = safeGetRC(PReg);
      if (!RC || !RC->isAllocatable())
        continue;
      Register VReg = MRI.createVirtualRegister(RC);
      DefToVReg[{NID, PReg}] = VReg;
    }

    // Implicit defs — these don't have operand descriptors, use
    // getMinimalPhysRegClass.
    for (MCPhysReg Reg : Node.Defs) {
      if (DefToVReg.count({NID, Reg}))
        continue; // Already handled as explicit def.
      const TargetRegisterClass *RC = safeGetRC(Reg);
      if (!RC || !RC->isAllocatable())
        continue;
      Register VReg = MRI.createVirtualRegister(RC);
      DefToVReg[{NID, Reg}] = VReg;
    }
  }

  // --- Function live-ins: COPY physical arg registers to vregs ---
  // Identify physical registers used without a def in the graph (arguments,
  // callee-saved regs like LR/FP).  COPY each to a vreg at the entry block
  // so every subsequent use references a vreg, satisfying SSA.
  DenseMap<MCPhysReg, Register> LiveInVReg; // PhysReg → VReg from entry COPY
  // Build BB index map for predecessor lookup (used here and in PHI building).
  DenseMap<const BinaryBasicBlock *, unsigned> BBIdxMap;
  for (unsigned I = 0; I < AllBBs.size(); ++I)
    BBIdxMap[AllBBs[I].BB] = I;
  {
    DenseSet<MCPhysReg> LiveIns;

    for (unsigned NID = 0; NID < DUG.Nodes.size(); ++NID) {
      for (MCPhysReg Reg : DUG.Nodes[NID].Uses) {
        // Check if any in-edge provides a def for this register.
        bool HasDef = false;
        auto InIt = DUG.InEdges.find(NID);
        if (InIt != DUG.InEdges.end()) {
          for (unsigned EIdx : InIt->second) {
            const DefUseEdge &E = DUG.Edges[EIdx];
            for (MCRegUnit RU1 : BC.MRI->regunits(Reg))
              for (MCRegUnit RU2 : BC.MRI->regunits(E.Reg))
                if (RU1 == RU2)
                  HasDef = true;
          }
        }
        if (!HasDef) {
          LiveIns.insert(Reg);
          continue;
        }

        // Even if a def exists in the DUG, the register is still a live-in
        // if any predecessor of the use's BB doesn't provide a def (e.g.,
        // loop-carried values where the first iteration uses a function arg).
        unsigned UseBBIdx = DUG.Nodes[NID].BBIndex;
        // Only check for cross-BB edges (live-in uses).
        bool IsCrossBBUse = false;
        if (InIt != DUG.InEdges.end()) {
          for (unsigned EIdx : InIt->second) {
            const DefUseEdge &E = DUG.Edges[EIdx];
            bool RegMatch = false;
            for (MCRegUnit RU1 : BC.MRI->regunits(Reg))
              for (MCRegUnit RU2 : BC.MRI->regunits(E.Reg))
                if (RU1 == RU2) RegMatch = true;
            if (RegMatch && DUG.Nodes[E.Def].BBIndex != UseBBIdx)
              IsCrossBBUse = true;
            // Also check same-BB back-edge (def after use in same BB).
            if (RegMatch && DUG.Nodes[E.Def].BBIndex == UseBBIdx &&
                E.Def >= NID)
              IsCrossBBUse = true; // Self-loop via back-edge.
          }
        }

        if (IsCrossBBUse) {
          DenseSet<unsigned> DefBBs;
          if (InIt != DUG.InEdges.end()) {
            for (unsigned EIdx : InIt->second) {
              const DefUseEdge &E = DUG.Edges[EIdx];
              bool RegMatch = false;
              for (MCRegUnit RU1 : BC.MRI->regunits(Reg))
                for (MCRegUnit RU2 : BC.MRI->regunits(E.Reg))
                  if (RU1 == RU2) RegMatch = true;
              if (RegMatch)
                DefBBs.insert(DUG.Nodes[E.Def].BBIndex);
            }
          }
          for (const BinaryBasicBlock *Pred :
               AllBBs[UseBBIdx].BB->predecessors()) {
            auto PIt = BBIdxMap.find(Pred);
            if (PIt != BBIdxMap.end() && !DefBBs.count(PIt->second)) {
              LiveIns.insert(Reg);
              break;
            }
          }
        }
      }
    }

    MachineBasicBlock *EntryMBB = MBBs[0];
    for (MCPhysReg Reg : LiveIns) {
      const TargetRegisterClass *RC = safeGetRC(Reg);
      if (!RC || !RC->isAllocatable()) {
        // Non-allocatable live-ins (SP, NZCV, etc.) stay physical.
        EntryMBB->addLiveIn(Reg);
        continue;
      }
      Register VReg = MRI.createVirtualRegister(RC);
      LiveInVReg[Reg] = VReg;
      EntryMBB->addLiveIn(Reg);
      BuildMI(*EntryMBB, EntryMBB->begin(), DebugLoc(),
              TII->get(TargetOpcode::COPY), VReg)
          .addReg(Reg);
    }
    EntryMBB->sortUniqueLiveIns();
  }

  // --- Helper: resolve a vreg for a use, inserting subreg conversions ---
  // Given a (NID, UsePhysReg) pair, find the vreg from DefToVReg or
  // LiveInVReg.  When the def's register differs in width from the use's
  // register (e.g. W8 def → X8 use), insert SUBREG_TO_REG or EXTRACT_SUBREG.
  //
  // Insert a SUBREG_TO_REG or EXTRACT_SUBREG when a use expects a different
  // register width than the def provides.  Returns the converted vreg.
  auto resolveVReg = [&](MCPhysReg UseReg, Register SrcVReg,
                         MCPhysReg DefPhysReg,
                         const TargetRegisterClass *DstRC,
                         MachineBasicBlock *InsertMBB,
                         MachineBasicBlock::iterator InsertPt) -> Register {
    if (UseReg == DefPhysReg)
      return SrcVReg; // Same register, no conversion needed.

    if (!DstRC || !DstRC->isAllocatable())
      return SrcVReg;

    // Check if DefPhysReg is a sub-register of UseReg (need widening).
    unsigned SubIdx = TRI->getSubRegIndex(UseReg, DefPhysReg);
    if (SubIdx) {
      Register Wide = MRI.createVirtualRegister(DstRC);
      BuildMI(*InsertMBB, InsertPt, DebugLoc(),
              TII->get(TargetOpcode::SUBREG_TO_REG), Wide)
          .addReg(SrcVReg)
          .addImm(SubIdx);
      return Wide;
    }

    // Check if UseReg is a sub-register of DefPhysReg (need narrowing).
    SubIdx = TRI->getSubRegIndex(DefPhysReg, UseReg);
    if (SubIdx) {
      Register Narrow = MRI.createVirtualRegister(DstRC);
      BuildMI(*InsertMBB, InsertPt, DebugLoc(),
              TII->get(TargetOpcode::COPY), Narrow)
          .addReg(SrcVReg, RegState{}, SubIdx);
      return Narrow;
    }

    return SrcVReg;
  };

  // --- Helper: find the DefToVReg entry for a (DefNID, UseReg) pair,
  // handling aliased registers. Returns {VReg, DefPhysReg} or {0, 0}. ---
  auto findDefVReg = [&](NodeID DefNID, MCPhysReg UseReg)
      -> std::pair<Register, MCPhysReg> {
    // Direct match first.
    auto VIt = DefToVReg.find({DefNID, UseReg});
    if (VIt != DefToVReg.end())
      return {VIt->second, UseReg};
    // Try aliased registers.
    for (MCPhysReg DefReg : DUG.Nodes[DefNID].Defs) {
      bool Aliases = false;
      for (MCRegUnit RU1 : BC.MRI->regunits(UseReg))
        for (MCRegUnit RU2 : BC.MRI->regunits(DefReg))
          if (RU1 == RU2)
            Aliases = true;
      if (Aliases) {
        VIt = DefToVReg.find({DefNID, DefReg});
        if (VIt != DefToVReg.end())
          return {VIt->second, DefReg};
      }
    }
    return {Register(), MCPhysReg(0)};
  };

  // --- Helper: find a live-in vreg for UseReg, handling aliases. ---
  auto findLiveInVReg = [&](MCPhysReg UseReg)
      -> std::pair<Register, MCPhysReg> {
    auto It = LiveInVReg.find(UseReg);
    if (It != LiveInVReg.end())
      return {It->second, UseReg};
    // Check aliases (e.g. X1 live-in but W1 used, or vice versa).
    for (auto &[LIReg, LIVReg] : LiveInVReg) {
      for (MCRegUnit RU1 : BC.MRI->regunits(UseReg))
        for (MCRegUnit RU2 : BC.MRI->regunits(LIReg))
          if (RU1 == RU2)
            return {LIVReg, LIReg};
    }
    return {Register(), MCPhysReg(0)};
  };

  // --- Build reaching-definition map: for each (BBIdx, PhysReg alias group),
  // record the last DefNID in that BB.  This allows us to find the definition
  // that reaches the exit of any block. ---
  // Key: (BBIdx, canonical PhysReg from DUG def) → last DefNID in that BB.
  DenseMap<std::pair<unsigned, MCPhysReg>, NodeID> LastDefInBB;
  for (unsigned NID = 0; NID < DUG.Nodes.size(); ++NID) {
    const InstrNode &Node = DUG.Nodes[NID];
    for (MCPhysReg Reg : Node.Defs) {
      if (!DefToVReg.count({NID, Reg}))
        continue; // Skip non-allocatable defs.
      auto Key = std::make_pair(Node.BBIndex, Reg);
      auto It = LastDefInBB.find(Key);
      if (It == LastDefInBB.end() || NID > It->second)
        LastDefInBB[Key] = NID;
    }
  }

  // Helper: given a BBIdx and a UseReg, find the last def (NodeID) in that BB
  // for any register that aliases UseReg.  Returns {DefNID, DefPhysReg} or
  // {UINT_MAX, 0} if no def found.
  auto findLastDefInBB = [&](unsigned BBIdx, MCPhysReg UseReg)
      -> std::pair<NodeID, MCPhysReg> {
    // Direct match first.
    auto It = LastDefInBB.find({BBIdx, UseReg});
    if (It != LastDefInBB.end())
      return {It->second, UseReg};
    // Try aliases.
    NodeID BestNID = UINT_MAX;
    MCPhysReg BestReg = 0;
    for (auto &[Key, NID] : LastDefInBB) {
      if (Key.first != BBIdx)
        continue;
      bool Aliases = false;
      for (MCRegUnit RU1 : BC.MRI->regunits(UseReg))
        for (MCRegUnit RU2 : BC.MRI->regunits(Key.second))
          if (RU1 == RU2)
            Aliases = true;
      if (Aliases && (BestNID == UINT_MAX || NID > BestNID)) {
        BestNID = NID;
        BestReg = Key.second;
      }
    }
    if (BestNID != UINT_MAX)
      return {BestNID, BestReg};
    return {UINT_MAX, MCPhysReg(0)};
  };

  // Helper: find the reaching definition for UseReg at the exit of PredBBIdx.
  // Walks backwards through the CFG until a block with a def is found, or the
  // entry block is reached (meaning the value comes from a function live-in).
  // Returns {DefNID, DefPhysReg} where DefNID==UINT_MAX means live-in.
  //
  // IMPORTANT: This function must explore ALL paths, not just the first one.
  // When multiple paths converge at a block, each predecessor path may have
  // a different reaching def. If they differ, we return UINT_MAX-1 as a
  // sentinel meaning "ambiguous — needs intermediate PHI".
  static constexpr NodeID AmbiguousDef = UINT_MAX - 1;
  auto findReachingDef = [&](unsigned PredBBIdx, MCPhysReg UseReg)
      -> std::pair<NodeID, MCPhysReg> {
    // First check if PredBBIdx itself has a def.
    auto [DefNID, DefPhys] = findLastDefInBB(PredBBIdx, UseReg);
    if (DefNID != UINT_MAX)
      return {DefNID, DefPhys};

    // BFS backwards. Track the reaching def found for each visited block.
    // A block's reaching def is determined by its predecessors:
    //   - If the block itself has a def, that's the reaching def.
    //   - Otherwise, if all predecessors agree on the same reaching def,
    //     that's the reaching def for this block.
    //   - If predecessors disagree, this block needs a PHI (ambiguous).
    DenseMap<unsigned, std::pair<NodeID, MCPhysReg>> ReachingAt;
    SmallVector<unsigned, 8> Worklist;
    DenseSet<unsigned> InWorklist;

    // Start with PredBBIdx's predecessors.
    for (const BinaryBasicBlock *Pred :
         AllBBs[PredBBIdx].BB->predecessors()) {
      auto PIt = BBIdxMap.find(Pred);
      if (PIt == BBIdxMap.end())
        continue;
      unsigned PPIdx = PIt->second;
      auto [DN, DP] = findLastDefInBB(PPIdx, UseReg);
      if (DN != UINT_MAX) {
        ReachingAt[PPIdx] = {DN, DP};
      } else {
        if (AllBBs[PPIdx].BB->pred_size() == 0) {
          // Entry block with no def → live-in.
          ReachingAt[PPIdx] = {UINT_MAX, MCPhysReg(0)};
        } else {
          Worklist.push_back(PPIdx);
          InWorklist.insert(PPIdx);
        }
      }
    }

    // Process worklist: for each unresolved block, check its predecessors.
    unsigned Iterations = 0;
    while (!Worklist.empty() && Iterations < 1000) {
      ++Iterations;
      unsigned CurBBIdx = Worklist.pop_back_val();
      InWorklist.erase(CurBBIdx);

      // Check if all predecessors of CurBBIdx are resolved.
      bool AllResolved = true;
      NodeID UnifiedNID = UINT_MAX;
      MCPhysReg UnifiedPhys = 0;
      bool First = true;
      bool Ambiguous = false;

      for (const BinaryBasicBlock *PP :
           AllBBs[CurBBIdx].BB->predecessors()) {
        auto PPIt = BBIdxMap.find(PP);
        if (PPIt == BBIdxMap.end())
          continue;
        unsigned PPIdx = PPIt->second;

        // Check if PPIdx has a def itself.
        auto [DN, DP] = findLastDefInBB(PPIdx, UseReg);
        if (DN != UINT_MAX) {
          ReachingAt[PPIdx] = {DN, DP};
        }

        auto RIt = ReachingAt.find(PPIdx);
        if (RIt == ReachingAt.end()) {
          // PPIdx not yet resolved.
          if (AllBBs[PPIdx].BB->pred_size() == 0) {
            ReachingAt[PPIdx] = {UINT_MAX, MCPhysReg(0)};
          } else {
            AllResolved = false;
            if (!InWorklist.count(PPIdx)) {
              Worklist.push_back(PPIdx);
              InWorklist.insert(PPIdx);
            }
            continue;
          }
          RIt = ReachingAt.find(PPIdx);
        }

        if (First) {
          UnifiedNID = RIt->second.first;
          UnifiedPhys = RIt->second.second;
          First = true; // Keep First=true until we find a second.
          First = false;
        } else if (RIt->second.first != UnifiedNID) {
          Ambiguous = true;
        }
      }

      if (AllResolved) {
        if (Ambiguous)
          ReachingAt[CurBBIdx] = {AmbiguousDef, MCPhysReg(0)};
        else
          ReachingAt[CurBBIdx] = {UnifiedNID, UnifiedPhys};
      } else {
        // Re-add to worklist if not all predecessors resolved.
        if (!InWorklist.count(CurBBIdx)) {
          Worklist.push_back(CurBBIdx);
          InWorklist.insert(CurBBIdx);
        }
      }
    }

    // Now combine results from PredBBIdx's predecessors.
    NodeID ResultNID = UINT_MAX;
    MCPhysReg ResultPhys = 0;
    bool ResultFirst = true;
    for (const BinaryBasicBlock *Pred :
         AllBBs[PredBBIdx].BB->predecessors()) {
      auto PIt = BBIdxMap.find(Pred);
      if (PIt == BBIdxMap.end())
        continue;
      auto RIt = ReachingAt.find(PIt->second);
      if (RIt == ReachingAt.end()) {
        // Couldn't resolve → treat as live-in.
        if (ResultFirst) {
          ResultNID = UINT_MAX;
          ResultFirst = false;
        } else if (ResultNID != UINT_MAX) {
          return {AmbiguousDef, MCPhysReg(0)};
        }
        continue;
      }
      if (ResultFirst) {
        ResultNID = RIt->second.first;
        ResultPhys = RIt->second.second;
        ResultFirst = false;
      } else if (RIt->second.first != ResultNID) {
        return {AmbiguousDef, MCPhysReg(0)};
      }
    }
    return {ResultNID, ResultPhys};
  };

  // Build a map from (UseNodeID, PhysReg) → the VReg it should use.
  // For intra-BB edges this is straightforward. For cross-BB edges where
  // a use has defs from multiple predecessors, we need PHI nodes.
  struct PhiCandidate {
    NodeID UseNID;
    MCPhysReg Reg;
    unsigned UseBBIdx;
  };

  DenseMap<std::pair<NodeID, MCPhysReg>, Register> UseVReg;
  std::vector<PhiCandidate> PhiCandidates;

  for (unsigned NID = 0; NID < DUG.Nodes.size(); ++NID) {
    const InstrNode &Node = DUG.Nodes[NID];
    for (MCPhysReg Reg : Node.Uses) {
      // Find all def-use edges feeding this (NID, Reg).
      SmallVector<std::pair<NodeID, unsigned>, 2> Sources;
      auto InIt = DUG.InEdges.find(NID);
      if (InIt != DUG.InEdges.end()) {
        for (unsigned EIdx : InIt->second) {
          const DefUseEdge &E = DUG.Edges[EIdx];
          bool Matches = false;
          for (MCRegUnit RU1 : BC.MRI->regunits(Reg))
            for (MCRegUnit RU2 : BC.MRI->regunits(E.Reg))
              if (RU1 == RU2)
                Matches = true;
          if (Matches) {
            unsigned DefBBIdx = DUG.Nodes[E.Def].BBIndex;
            Sources.push_back({E.Def, DefBBIdx});
          }
        }
      }

      if (Sources.empty())
        continue; // Function live-in — handled via LiveInVReg + resolveVReg.

      unsigned UseBBIdx = Node.BBIndex;

      // Single source in the same BB and not a back-edge → simple, no PHI.
      if (Sources.size() == 1 && Sources[0].second == UseBBIdx &&
          Sources[0].first < NID) {
        auto [SrcVReg, DefPhysReg] = findDefVReg(Sources[0].first, Reg);
        if (SrcVReg)
          UseVReg[{NID, Reg}] = SrcVReg;
        continue;
      }

      // If this is the entry block (no predecessors), just use the single def.
      if (AllBBs[UseBBIdx].BB->pred_size() == 0) {
        if (Sources.size() >= 1) {
          auto [SrcVReg, DefPhysReg] = findDefVReg(Sources[0].first, Reg);
          if (SrcVReg)
            UseVReg[{NID, Reg}] = SrcVReg;
        }
        continue;
      }

      // For cross-BB uses or multi-source uses, use reaching-definition
      // analysis to determine whether a PHI is needed.

      // Collect the reaching def for each predecessor.
      DenseMap<unsigned, std::pair<NodeID, MCPhysReg>> PredDefs;
      bool AllSame = true;
      NodeID FirstDefNID = UINT_MAX;
      bool HasLiveIn = false;
      bool FirstSet = false;

      for (const BinaryBasicBlock *Pred :
           AllBBs[UseBBIdx].BB->predecessors()) {
        auto PIt = BBIdxMap.find(Pred);
        if (PIt == BBIdxMap.end())
          continue;
        unsigned PredIdx = PIt->second;
        auto [DN, DP] = findReachingDef(PredIdx, Reg);
        PredDefs[PredIdx] = {DN, DP};

        if (DN == UINT_MAX || DN == AmbiguousDef)
          HasLiveIn = true;

        if (!FirstSet) {
          FirstDefNID = DN;
          FirstSet = true;
        } else if (DN != FirstDefNID) {
          AllSame = false;
        }
      }

      // If all predecessors agree on the same non-live-in def, no PHI needed.
      if (AllSame && !HasLiveIn && FirstSet) {
        auto [SrcVReg, DefPhysReg] = findDefVReg(FirstDefNID, Reg);
        if (SrcVReg)
          UseVReg[{NID, Reg}] = SrcVReg;
        continue;
      }

      // Need a PHI.
      PhiCandidates.push_back({NID, Reg, UseBBIdx});
    }
  }

  // --- Determine the expected register class for a use operand ---
  auto getUseRC = [&](const InstrNode &UseNode, MCPhysReg UseReg)
      -> const TargetRegisterClass * {
    if (BC.MIB->isPseudo(*UseNode.Inst))
      return nullptr;
    const MCInstrDesc &UseMCID = BC.MII->get(UseNode.Inst->getOpcode());
    unsigned NumPrimeOps = MCPlus::getNumPrimeOperands(*UseNode.Inst);
    // Skip def operands — only look at use operands for the register class.
    for (unsigned I = UseMCID.getNumDefs(); I < NumPrimeOps; ++I) {
      const MCOperand &MCOp = UseNode.Inst->getOperand(I);
      if (!MCOp.isReg())
        continue;
      // Match by exact register or alias.
      bool Match = (MCOp.getReg() == UseReg);
      if (!Match) {
        for (MCRegUnit RU1 : BC.MRI->regunits(UseReg))
          for (MCRegUnit RU2 : BC.MRI->regunits(MCOp.getReg()))
            if (RU1 == RU2)
              Match = true;
      }
      if (Match && I < UseMCID.getNumOperands()) {
        int16_t RCIdx = UseMCID.operands()[I].RegClass;
        if (RCIdx >= 0)
          return TRI->getRegClass(RCIdx);
      }
    }
    return nullptr;
  };

  // Pre-allocate PHI vregs so UseVReg is populated during instruction emission.
  // Actual PHI MachineInstrs are built after instruction emission so that
  // predecessor defs exist for subreg conversion insertion.
  struct PhiInfo {
    Register PhiVReg;
    const TargetRegisterClass *RC;
    unsigned UseBBIdx;
    MCPhysReg Reg;
  };
  std::vector<PhiInfo> Phis;
  for (auto &Phi : PhiCandidates) {
    const TargetRegisterClass *RC =
        getUseRC(DUG.Nodes[Phi.UseNID], Phi.Reg);
    if (!RC)
      RC = safeGetRC(Phi.Reg);
    if (!RC || !RC->isAllocatable())
      continue;
    Register PhiVReg = MRI.createVirtualRegister(RC);
    UseVReg[{Phi.UseNID, Phi.Reg}] = PhiVReg;
    Phis.push_back({PhiVReg, RC, Phi.UseBBIdx, Phi.Reg});
  }

  // --- Convert MCInst → MachineInstr ---
  for (unsigned NID = 0; NID < DUG.Nodes.size(); ++NID) {
    const InstrNode &Node = DUG.Nodes[NID];
    const MCInst &Inst = *Node.Inst;
    unsigned BBIdx = Node.BBIndex;
    MachineBasicBlock *MBB = MBBs[BBIdx];

    // Skip pseudo instructions (BOLT annotations like CFI).
    if (BC.MIB->isPseudo(Inst))
      continue;

    unsigned Opcode = Inst.getOpcode();
    const MCInstrDesc &MCID = BC.MII->get(Opcode);

    // Build the MachineInstr.
    auto MIB = BuildMI(*MBB, MBB->end(), DebugLoc(), MCID);
    // Conversion instructions must be inserted before this instruction.
    MachineBasicBlock::iterator ConvPt(MIB.getInstr());

    // Get the expected register class for each use operand.
    auto getOpRC = [&](unsigned OpIdx) -> const TargetRegisterClass * {
      if (OpIdx < MCID.getNumOperands()) {
        int16_t RCIdx = MCID.operands()[OpIdx].RegClass;
        if (RCIdx >= 0)
          return TRI->getRegClass(RCIdx);
      }
      return nullptr;
    };

    // Process explicit operands (skip BOLT annotation operands).
    unsigned NumPrimeOps = MCPlus::getNumPrimeOperands(Inst);
    for (unsigned I = 0; I < NumPrimeOps; ++I) {
      const MCOperand &MCOp = Inst.getOperand(I);

      if (MCOp.isReg()) {
        MCPhysReg PReg = MCOp.getReg();
        bool IsDef = (I < MCID.getNumDefs());

        if (PReg == 0) {
          MIB.addReg(0, IsDef ? RegState::Define : RegState{});
          continue;
        }

        if (IsDef) {
          auto VIt = DefToVReg.find({NID, PReg});
          if (VIt != DefToVReg.end())
            MIB.addDef(VIt->second);
          else
            MIB.addDef(PReg);
        } else {
          // Try UseVReg (from def-use graph or PHI).
          auto VIt = UseVReg.find({NID, PReg});
          if (VIt != UseVReg.end()) {
            Register Resolved = VIt->second;
            // Check if subreg conversion is needed.
            // If the resolved vreg came from a PHI, do conversion from the
            // PHI vreg (not the raw def) to avoid cross-block references.
            bool IsPhi = false;
            for (auto &PI : Phis) {
              if (PI.PhiVReg == Resolved) {
                IsPhi = true;
                break;
              }
            }

            if (!IsPhi) {
              // Direct def (not through PHI) — use the original def for
              // subreg conversion.
              auto InIt = DUG.InEdges.find(NID);
              if (InIt != DUG.InEdges.end()) {
                for (unsigned EIdx : InIt->second) {
                  const DefUseEdge &E = DUG.Edges[EIdx];
                  bool Match = false;
                  for (MCRegUnit RU1 : BC.MRI->regunits(PReg))
                    for (MCRegUnit RU2 : BC.MRI->regunits(E.Reg))
                      if (RU1 == RU2) Match = true;
                  if (Match) {
                    auto [DefVReg, DefPhys] = findDefVReg(E.Def, PReg);
                    if (DefVReg && DefPhys != PReg) {
                      const TargetRegisterClass *UseRC = getOpRC(I);
                      if (!UseRC)
                        UseRC = safeGetRC(PReg);
                      Resolved = resolveVReg(PReg, DefVReg, DefPhys,
                                             UseRC, MBB, ConvPt);
                    }
                    break;
                  }
                }
              }
            }
            // else: PHI vreg — conversion was already done in the
            // predecessor blocks during PHI building.
            // Ensure the vreg's register class is compatible with what the
            // instruction operand expects. If not, COPY to a new vreg with
            // the right class (e.g., gpr32 → gpr32sp for SUBSWri).
            if (Resolved.isVirtual()) {
              const TargetRegisterClass *ExpRC = getOpRC(I);
              if (ExpRC) {
                const TargetRegisterClass *CurRC = MRI.getRegClass(Resolved);
                if (CurRC != ExpRC && !ExpRC->hasSubClassEq(CurRC)) {
                  Register Fixed = MRI.createVirtualRegister(ExpRC);
                  BuildMI(*MBB, ConvPt, DebugLoc(),
                          TII->get(TargetOpcode::COPY), Fixed)
                      .addReg(Resolved);
                  Resolved = Fixed;
                }
              }
            }
            MIB.addUse(Resolved);
          } else {
            // Try live-in vreg (function arguments, callee-saved regs).
            auto [LIVReg, LIPhys] = findLiveInVReg(PReg);
            if (LIVReg) {
              Register Resolved = LIVReg;
              if (LIPhys != PReg) {
                const TargetRegisterClass *UseRC = getOpRC(I);
                if (!UseRC)
                  UseRC = safeGetRC(PReg);
                Resolved = resolveVReg(PReg, LIVReg, LIPhys,
                                       UseRC, MBB, ConvPt);
              }
              MIB.addUse(Resolved);
            } else {
              // No UseVReg or LiveInVReg found. If the register is allocatable,
              // lazily create a live-in COPY to avoid undefined phys reg errors.
              const TargetRegisterClass *RC = safeGetRC(PReg);
              if (RC && RC->isAllocatable()) {
                MachineBasicBlock *EntryMBB = MBBs[0];
                Register NewVReg = MRI.createVirtualRegister(RC);
                LiveInVReg[PReg] = NewVReg;
                EntryMBB->addLiveIn(PReg);
                BuildMI(*EntryMBB, EntryMBB->begin(), DebugLoc(),
                        TII->get(TargetOpcode::COPY), NewVReg)
                    .addReg(PReg);
                EntryMBB->sortUniqueLiveIns();
                Register Resolved = NewVReg;
                const TargetRegisterClass *UseRC = getOpRC(I);
                if (UseRC && UseRC != RC && !UseRC->hasSubClassEq(RC)) {
                  Register Fixed = MRI.createVirtualRegister(UseRC);
                  BuildMI(*MBB, ConvPt, DebugLoc(),
                          TII->get(TargetOpcode::COPY), Fixed)
                      .addReg(NewVReg);
                  Resolved = Fixed;
                }
                MIB.addUse(Resolved);
              } else {
                MIB.addUse(PReg); // Truly physical (SP, NZCV, etc.).
              }
            }
          }
        }
      } else if (MCOp.isImm()) {
        MIB.addImm(MCOp.getImm());
      } else if (MCOp.isExpr()) {
        bool Resolved = false;
        if (MCOp.getExpr()->getKind() == MCExpr::SymbolRef) {
          const MCSymbolRefExpr *SRE =
              cast<MCSymbolRefExpr>(MCOp.getExpr());
          const MCSymbol &Sym = SRE->getSymbol();
          for (unsigned J = 0; J < AllBBs.size(); ++J) {
            if (AllBBs[J].BB->getLabel() == &Sym) {
              MIB.addMBB(MBBs[J]);
              Resolved = true;
              break;
            }
          }
          if (!Resolved) {
            // External symbol on a branch/terminator would crash the verifier
            // (isMBB assertion). For tail calls to external functions, skip
            // the symbol operand and let the branch target be left empty.
            // For non-branch instructions, use addExternalSymbol normally.
            if (MCID.isTerminator() || MCID.isBranch()) {
              // Create a dummy exit MBB for tail-call branches.
              MachineBasicBlock *ExitMBB = MF.CreateMachineBasicBlock();
              MF.push_back(ExitMBB);
              MBB->addSuccessor(ExitMBB);
              MIB.addMBB(ExitMBB);
            } else {
              MIB.addExternalSymbol(Sym.getName().data());
            }
            Resolved = true;
          }
        }
        if (!Resolved)
          MIB.addImm(0);
      } else if (MCOp.isSFPImm()) {
        MIB.addImm(bit_cast<int32_t>(MCOp.getSFPImm()));
      } else if (MCOp.isDFPImm()) {
        MIB.addImm(bit_cast<int64_t>(MCOp.getDFPImm()));
      }
    }
  }

  // --- Build PHI MachineInstrs (after all defs are emitted) ---
  // For each PHI, iterate over CFG predecessors and use findReachingDef to
  // determine the definition that reaches each predecessor's exit.
  for (auto &PI : Phis) {
    MachineBasicBlock *UseMBB = MBBs[PI.UseBBIdx];
    MachineInstrBuilder PhiMIB =
        BuildMI(*UseMBB, UseMBB->begin(), DebugLoc(),
                TII->get(TargetOpcode::PHI), PI.PhiVReg);

    for (const BinaryBasicBlock *Pred :
         AllBBs[PI.UseBBIdx].BB->predecessors()) {
      auto PIt = BBIdxMap.find(Pred);
      if (PIt == BBIdxMap.end())
        continue;
      unsigned PredIdx = PIt->second;
      MachineBasicBlock *PredMBB = MBBs[PredIdx];

      auto [DefNID, DefPhys] = findReachingDef(PredIdx, PI.Reg);

      Register SrcVReg;
      MCPhysReg DefPhysReg = 0;
      if (DefNID == UINT_MAX || DefNID == AmbiguousDef) {
        // Function live-in (or ambiguous merge — fall back to live-in).
        auto [LIV, LIP] = findLiveInVReg(PI.Reg);
        SrcVReg = LIV;
        DefPhysReg = LIP;
        // If no live-in vreg exists yet, create one lazily.
        if (!SrcVReg) {
          const TargetRegisterClass *RC = safeGetRC(PI.Reg);
          if (RC && RC->isAllocatable()) {
            MachineBasicBlock *EntryMBB = MBBs[0];
            Register NewVReg = MRI.createVirtualRegister(RC);
            LiveInVReg[PI.Reg] = NewVReg;
            EntryMBB->addLiveIn(PI.Reg);
            BuildMI(*EntryMBB, EntryMBB->begin(), DebugLoc(),
                    TII->get(TargetOpcode::COPY), NewVReg)
                .addReg(PI.Reg);
            EntryMBB->sortUniqueLiveIns();
            SrcVReg = NewVReg;
            DefPhysReg = PI.Reg;
          }
        }
      } else {
        std::tie(SrcVReg, DefPhysReg) = findDefVReg(DefNID, PI.Reg);
      }
      if (!SrcVReg)
        continue;
      if (DefPhysReg && DefPhysReg != PI.Reg) {
        auto InsertPt = PredMBB->getFirstTerminator();
        SrcVReg = resolveVReg(PI.Reg, SrcVReg, DefPhysReg,
                              PI.RC, PredMBB, InsertPt);
      }
      // Ensure register class compatibility.
      if (SrcVReg.isVirtual()) {
        const TargetRegisterClass *CurRC = MRI.getRegClass(SrcVReg);
        if (CurRC != PI.RC && !PI.RC->hasSubClassEq(CurRC)) {
          Register Fixed = MRI.createVirtualRegister(PI.RC);
          auto InsertPt = PredMBB->getFirstTerminator();
          BuildMI(*PredMBB, InsertPt, DebugLoc(),
                  TII->get(TargetOpcode::COPY), Fixed)
              .addReg(SrcVReg);
          SrcVReg = Fixed;
        }
      }
      PhiMIB.addReg(SrcVReg).addMBB(PredMBB);
    }
  }

  // --- Add physical register live-ins to non-entry blocks ---
  // The verifier requires that any physical register used in a block must
  // be either defined in the block or in the block's live-in list.
  // Scan each block for physical register uses and add missing live-ins.
  for (auto &MBB : MF) {
    DenseSet<MCPhysReg> PhysDefs;
    DenseSet<MCPhysReg> PhysUses;

    for (const MachineInstr &MI : MBB) {
      // Process uses BEFORE defs — a use on the same instruction as a def
      // reads the value from before the instruction (e.g., CCMPWr reads
      // NZCV and then writes NZCV).
      for (const MachineOperand &MO : MI.operands()) {
        if (!MO.isReg() || !MO.getReg().isPhysical() || MO.getReg() == 0)
          continue;
        if (MO.isUse() && !PhysDefs.count(MO.getReg()))
          PhysUses.insert(MO.getReg());
      }
      for (const MachineOperand &MO : MI.operands()) {
        if (!MO.isReg() || !MO.getReg().isPhysical() || MO.getReg() == 0)
          continue;
        if (MO.isDef())
          PhysDefs.insert(MO.getReg());
      }
    }

    for (MCPhysReg PReg : PhysUses) {
      if (!MBB.isLiveIn(PReg))
        MBB.addLiveIn(PReg);
    }
    MBB.sortUniqueLiveIns();
  }

  // Write the .mir file.
  std::string Filename = sanitizeFilename(FuncName) + ".mir";
  std::filesystem::path OutPath =
      std::filesystem::path(OutDir) / Filename;
  std::error_code EC;
  raw_fd_ostream OS(OutPath.string(), EC);
  if (EC) {
    errs() << ToolName << ": cannot open '" << OutPath.string()
           << "': " << EC.message() << "\n";
    MMI.deleteMachineFunctionFor(*IRFunc);
    IRFunc->eraseFromParent();
    return false;
  }

  printMIR(OS, IRMod);
  printMIR(OS, MMI, MF);

  // Clean up the MachineFunction so the next function can reuse the module.
  MMI.deleteMachineFunctionFor(*IRFunc);
  IRFunc->eraseFromParent();

  return true;
}

/// Extract all functions from a BinaryContext as .mir files.
static void processExtract(const BinaryContext &BC,
                           const std::string &OutDir) {
  // Create output directory if it doesn't exist.
  std::error_code EC = sys::fs::create_directories(OutDir);
  if (EC) {
    errs() << ToolName << ": cannot create directory '" << OutDir
           << "': " << EC.message() << "\n";
    return;
  }

  // Construct a normalized triple. BOLT's TheTriple may have empty vendor/OS
  // fields (e.g., "aarch64---macho"). Fill them in for readable MIR output.
  Triple NormalizedTriple(*BC.TheTriple);
  if (NormalizedTriple.getVendor() == Triple::UnknownVendor &&
      NormalizedTriple.getOS() == Triple::UnknownOS &&
      NormalizedTriple.isOSBinFormatMachO()) {
    NormalizedTriple.setVendor(Triple::Apple);
    NormalizedTriple.setOS(Triple::Darwin);
  }

  // Optional regex filter.
  std::unique_ptr<Regex> Filter;
  if (opts::ExtractFilter.getNumOccurrences()) {
    std::string Err;
    Filter = std::make_unique<Regex>(opts::ExtractFilter);
    if (!Filter->isValid(Err)) {
      errs() << ToolName << ": invalid filter regex '"
             << opts::ExtractFilter << "': " << Err << "\n";
      return;
    }
  }

  // Collect functions to extract.
  SmallVector<const BinaryFunction *, 0> Functions;
  unsigned Skipped = 0;
  for (const auto &[Addr, BF] : BC.getBinaryFunctions()) {
    if (Filter && !Filter->match(BF.getPrintName())) {
      ++Skipped;
      continue;
    }
    Functions.push_back(&BF);
  }

  // Determine thread count.
  unsigned NumThreads = opts::ThreadCount;
  if (NumThreads == 0)
    NumThreads = std::thread::hardware_concurrency();
  if (NumThreads == 0)
    NumThreads = 1;
  // Don't use more threads than functions.
  NumThreads = std::min(NumThreads, (unsigned)Functions.size());

  std::atomic<unsigned> Count{0};
  std::atomic<unsigned> ExtractSkipped{0};
  const unsigned Total = Functions.size();

  // Progress bar helper — updates a single line on stderr.
  // In multi-threaded mode, throttle to avoid interleaved output.
  std::mutex ProgressMtx;
  auto printProgress = [&]() {
    unsigned Done = Count.load(std::memory_order_relaxed) +
                    ExtractSkipped.load(std::memory_order_relaxed);
    // Throttle: only update every 1% or at completion.
    unsigned Step = std::max(1u, Total / 100);
    if (Done % Step != 0 && Done != Total)
      return;
    std::lock_guard<std::mutex> Lock(ProgressMtx);
    unsigned Pct = Total ? (Done * 100 / Total) : 100;
    const unsigned BarWidth = 40;
    unsigned Filled = Total ? (Done * BarWidth / Total) : BarWidth;
    errs() << "\r[";
    for (unsigned I = 0; I < BarWidth; ++I)
      errs() << (I < Filled ? '=' : ' ');
    errs() << "] " << Pct << "% (" << Done << "/" << Total << ")";
    errs().flush();
  };

  if (NumThreads <= 1) {
    // Single-threaded path — no overhead.
    std::unique_ptr<TargetMachine> TM(BC.TheTarget->createTargetMachine(
        *BC.TheTriple, "", "", TargetOptions(), std::nullopt));
    if (!TM) {
      errs() << ToolName << ": failed to create TargetMachine\n";
      return;
    }
    LLVMContext Ctx;
    Module IRMod("llvm-analysis-extract", Ctx);
    IRMod.setTargetTriple(NormalizedTriple);
    IRMod.setDataLayout(TM->createDataLayout());
    MachineModuleInfo MMI(TM.get());

    for (const BinaryFunction *BF : Functions) {
      if (extractFunctionToMIR(BC, *BF, *TM, MMI, IRMod, OutDir))
        ++Count;
      else
        ++ExtractSkipped;
      printProgress();
    }
  } else {
    // Multi-threaded path.
    // Each worker thread gets its own {TargetMachine, LLVMContext, Module, MMI}
    // stored in a thread-local-like structure. Individual functions are submitted
    // as tasks so the pool naturally load-balances (work-stealing).
    struct ThreadState {
      std::unique_ptr<TargetMachine> TM;
      std::unique_ptr<LLVMContext> Ctx;
      std::unique_ptr<Module> IRMod;
      std::unique_ptr<MachineModuleInfo> MMI;
    };
    std::mutex StateMtx;
    DenseMap<uint64_t, std::unique_ptr<ThreadState>> States;

    auto getState = [&]() -> ThreadState & {
      uint64_t TID = llvm::get_threadid();
      std::lock_guard<std::mutex> Lock(StateMtx);
      auto &Ptr = States[TID];
      if (!Ptr) {
        Ptr = std::make_unique<ThreadState>();
        Ptr->TM.reset(BC.TheTarget->createTargetMachine(
            *BC.TheTriple, "", "", TargetOptions(), std::nullopt));
        Ptr->Ctx = std::make_unique<LLVMContext>();
        Ptr->IRMod =
            std::make_unique<Module>("llvm-analysis-extract", *Ptr->Ctx);
        Ptr->IRMod->setTargetTriple(NormalizedTriple);
        Ptr->IRMod->setDataLayout(Ptr->TM->createDataLayout());
        Ptr->MMI = std::make_unique<MachineModuleInfo>(Ptr->TM.get());
      }
      return *Ptr;
    };

    StdThreadPool Pool(hardware_concurrency(NumThreads));
    for (const BinaryFunction *BF : Functions) {
      Pool.async([&, BF]() {
        auto &S = getState();
        if (extractFunctionToMIR(BC, *BF, *S.TM, *S.MMI, *S.IRMod, OutDir))
          Count.fetch_add(1, std::memory_order_relaxed);
        else
          ExtractSkipped.fetch_add(1, std::memory_order_relaxed);
        printProgress();
      });
    }
    Pool.wait();
  }

  Skipped += ExtractSkipped.load();
  errs() << "\n"; // Finish progress bar line.
  outs() << "Extracted " << Count.load() << " function(s) to " << OutDir;
  if (Skipped)
    outs() << " (" << Skipped << " skipped)";
  outs() << "\n";
}

// ===----------------------------------------------------------------------===//
// Binary loading (reused from previous implementation)
// ===----------------------------------------------------------------------===//

static void processBinaryContext(const BinaryContext &BC,
                                 const std::vector<PatternLine> &Pattern,
                                 const std::vector<NamedPattern> &Suite) {
  if (opts::DumpFunctions)
    printFunctions(BC);

  if (opts::DumpLiveness) {
    for (const auto &[Addr, BF] : BC.getBinaryFunctions())
      printLiveness(BC, BF);
  }

  if (opts::DumpGraph.getNumOccurrences())
    dumpGraphs(BC, opts::DumpGraph);

  if (opts::DumpSvg.getNumOccurrences())
    dumpSvgGraphs(BC, opts::DumpSvg);

  if (!Pattern.empty())
    runMatcher(BC, Pattern);

  for (const auto &NP : Suite) {
    outs() << "--- " << NP.Name << " ---\n";
    runMatcher(BC, NP.Lines);
    outs() << "\n";
  }
}

static auto makeProgressCallback() {
  bool Show = errs().is_displayed();
  return [Show](StringRef Phase, unsigned Current, unsigned Total) {
    if (!Show)
      return;
    fprintf(stderr, "\r%s: %u/%u functions (%u%%)", Phase.data(), Current,
            Total, Total ? Current * 100 / Total : 0);
    fflush(stderr);
  };
}

static void clearProgress() {
  if (errs().is_displayed())
    fprintf(stderr, "\r\033[K");
}

static void processMachO(MachOObjectFile *MachOObj, StringRef ToolPath,
                          bool IsExtract,
                          const std::vector<PatternLine> &Pattern,
                          const std::vector<NamedPattern> &Suite) {
  auto MachORIOrErr = MachORewriteInstance::create(MachOObj, ToolPath);
  if (Error E = MachORIOrErr.takeError())
    report_error(opts::InputFilename, std::move(E));
  MachORewriteInstance &MachORI = *MachORIOrErr.get();
  MachORI.setProgressCallback(makeProgressCallback());
  {
    TimeRegion TR(opts::TimeOpt ? &TBinary : nullptr);
    MachORI.run();
  }
  clearProgress();
  if (errs().is_displayed())
    fprintf(stderr, "Loaded %zu functions\n",
            MachORI.getBinaryContext().getBinaryFunctions().size());
  if (IsExtract) {
    processExtract(MachORI.getBinaryContext(), opts::OutDir);
  } else {
    TimeRegion TR(opts::TimeOpt ? &TMatch : nullptr);
    processBinaryContext(MachORI.getBinaryContext(), Pattern, Suite);
  }
}

int main(int argc, char **argv) {
  sys::PrintStackTraceOnErrorSignal(argv[0]);
  PrettyStackTraceProgram X(argc, argv);

  std::string ToolPath = GetExecutablePath(argv[0]);

  llvm_shutdown_obj Y;

  // Initialize targets and assembly printers/parsers.
#define BOLT_TARGET(target)                                                    \
  LLVMInitialize##target##TargetInfo();                                        \
  LLVMInitialize##target##TargetMC();                                          \
  LLVMInitialize##target##AsmParser();                                         \
  LLVMInitialize##target##Disassembler();                                      \
  LLVMInitialize##target##Target();                                            \
  LLVMInitialize##target##AsmPrinter();

#include "bolt/Core/TargetConfig.def"

  cl::HideUnrelatedOptions(opts::MatchCategory);
  cl::ParseCommandLineOptions(argc, argv,
                              "llvm-analysis - binary function matching tool\n");

  // Require a subcommand.
  bool IsExtract = static_cast<bool>(opts::ExtractCmd);
  bool IsMatch = static_cast<bool>(opts::MatchCmd);
  if (!IsExtract && !IsMatch) {
    errs() << ToolName
           << ": please specify a subcommand: 'match' or 'extract'\n";
    cl::PrintHelpMessage(false, true);
    return EXIT_FAILURE;
  }

  // Use BinaryAnalysisMode so run() returns after CFG building without
  // attempting to rewrite the binary.
  opts::BinaryAnalysisMode = true;

  // Parse pattern file if provided (match subcommand only).
  std::vector<PatternLine> Pattern;
  if (IsMatch && !opts::PatternFilename.empty()) {
    auto BufOrErr = MemoryBuffer::getFile(opts::PatternFilename);
    if (!BufOrErr)
      report_error(opts::PatternFilename, BufOrErr.getError());
    Pattern = parsePatternFile((*BufOrErr)->getBuffer());
    if (Pattern.empty()) {
      errs() << ToolName << ": no pattern lines found in '"
             << opts::PatternFilename << "'\n";
      return EXIT_FAILURE;
    }
    outs() << "Loaded " << Pattern.size() << " pattern line(s)\n";
    if (opts::DumpPattern)
      dumpPatternGraph(Pattern);
    if (opts::DumpPatternDot.getNumOccurrences()) {
      std::error_code EC;
      raw_fd_ostream DotFile(opts::DumpPatternDot, EC);
      if (EC)
        report_error(opts::DumpPatternDot, EC);
      dumpPatternDot(Pattern, DotFile);
      outs() << "Wrote pattern graph to " << opts::DumpPatternDot << "\n";
    }
  }

  // Parse suite file if provided (match subcommand only).
  std::vector<NamedPattern> Suite;
  if (IsMatch && !opts::SuiteFilename.empty()) {
    auto BufOrErr = MemoryBuffer::getFile(opts::SuiteFilename);
    if (!BufOrErr)
      report_error(opts::SuiteFilename, BufOrErr.getError());
    Suite = parseSuiteFile((*BufOrErr)->getBuffer());
    if (Suite.empty()) {
      errs() << ToolName << ": no patterns found in suite '"
             << opts::SuiteFilename << "'\n";
      return EXIT_FAILURE;
    }
    outs() << "Loaded suite with " << Suite.size() << " pattern(s):";
    for (const auto &NP : Suite)
      outs() << " " << NP.Name;
    outs() << "\n";
  }

  // If no action specified in match mode, default to dump-functions.
  if (IsMatch && !opts::DumpFunctions && !opts::DumpLiveness &&
      Pattern.empty() && Suite.empty() &&
      !opts::DumpGraph.getNumOccurrences() &&
      !opts::DumpSvg.getNumOccurrences())
    opts::DumpFunctions = true;

  if (!sys::fs::exists(opts::InputFilename))
    report_error(opts::InputFilename, errc::no_such_file_or_directory);

  Expected<OwningBinary<Binary>> BinaryOrErr =
      createBinary(opts::InputFilename);
  if (Error E = BinaryOrErr.takeError())
    report_error(opts::InputFilename, std::move(E));
  Binary &Binary = *BinaryOrErr.get().getBinary();

  if (auto *ELFObj = dyn_cast<ELFObjectFileBase>(&Binary)) {
    auto RIOrErr = RewriteInstance::create(ELFObj, argc, argv, ToolPath);
    if (Error E = RIOrErr.takeError())
      report_error(opts::InputFilename, std::move(E));
    RewriteInstance &RI = *RIOrErr.get();
    RI.setProgressCallback(makeProgressCallback());
    {
      TimeRegion TR(opts::TimeOpt ? &TBinary : nullptr);
      if (Error E = RI.run())
        report_error(opts::InputFilename, std::move(E));
    }
    clearProgress();
    if (errs().is_displayed())
      fprintf(stderr, "Loaded %zu functions\n",
              RI.getBinaryContext().getBinaryFunctions().size());
    if (IsExtract) {
      processExtract(RI.getBinaryContext(), opts::OutDir);
    } else {
      TimeRegion TR(opts::TimeOpt ? &TMatch : nullptr);
      processBinaryContext(RI.getBinaryContext(), Pattern, Suite);
    }
  } else if (auto *MachOObj = dyn_cast<MachOObjectFile>(&Binary)) {
    processMachO(MachOObj, ToolPath, IsExtract, Pattern, Suite);
  } else if (auto *FatBin = dyn_cast<MachOUniversalBinary>(&Binary)) {
    StringRef Arch = opts::ArchName;
    if (Arch.empty()) {
      errs() << ToolName << ": universal binary, use -arch to select a slice. "
             << "Available architectures:";
      for (const auto &Obj : FatBin->objects())
        errs() << " " << Obj.getArchFlagName();
      errs() << "\n";
      return EXIT_FAILURE;
    }
    auto ObjOrErr = FatBin->getMachOObjectForArch(Arch);
    if (Error E = ObjOrErr.takeError())
      report_error(opts::InputFilename, std::move(E));
    processMachO(ObjOrErr->get(), ToolPath, IsExtract, Pattern, Suite);
  } else {
    report_error(opts::InputFilename, object_error::invalid_file_type);
  }

  return EXIT_SUCCESS;
}
