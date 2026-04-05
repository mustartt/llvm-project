//===- bolt/tools/llvm-match/llvm-match.cpp -------------------------------===//
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
#include "bolt/Rewrite/MachORewriteInstance.h"
#include "bolt/Rewrite/RewriteInstance.h"
#include "bolt/Utils/CommandLineOpts.h"
#include "llvm/ADT/BitVector.h"
#include "llvm/ADT/SmallBitVector.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/StringMap.h"
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
#include <atomic>
#include <optional>

#define DEBUG_TYPE "llvm-match"

using namespace llvm;
using namespace object;
using namespace bolt;

namespace opts {

static cl::OptionCategory MatchCategory("llvm-match options");

static cl::opt<std::string> InputFilename(cl::Positional,
                                          cl::desc("<executable>"),
                                          cl::Required,
                                          cl::cat(MatchCategory),
                                          cl::sub(cl::SubCommand::getAll()));

static cl::opt<std::string>
    ArchName("arch", cl::desc("architecture slice for universal binaries"),
             cl::Optional, cl::cat(MatchCategory));

static cl::opt<std::string>
    PatternFilename("pattern", cl::desc("pattern file for matching"),
                    cl::Optional, cl::cat(MatchCategory));

static cl::opt<std::string>
    SuiteFilename("suite", cl::desc("YAML suite file with multiple patterns"),
                  cl::Optional, cl::cat(MatchCategory));

static cl::opt<bool>
    DumpLiveness("dump-liveness", cl::desc("dump live-in/live-out per BB"),
                 cl::Optional, cl::cat(MatchCategory));

static cl::opt<bool>
    DumpFunctions("dump-functions", cl::desc("dump disassembled functions"),
                  cl::Optional, cl::cat(MatchCategory));

static cl::opt<unsigned>
    ThreadCount("j", cl::desc("number of threads (0 = hardware concurrency)"),
                cl::init(0), cl::Optional, cl::cat(MatchCategory));

static cl::opt<bool>
    DumpPattern("dump-pattern", cl::desc("print parsed pattern as a graph"),
                cl::Optional, cl::cat(MatchCategory));

static cl::opt<std::string>
    DumpPatternDot("dump-pattern-dot",
                   cl::desc("emit pattern graph as Graphviz DOT to file"),
                   cl::value_desc("filename"),
                   cl::Optional, cl::cat(MatchCategory));

static cl::opt<std::string>
    DumpGraph("dump-graph",
              cl::desc("emit def-use graph as DOT for functions matching regex"),
              cl::value_desc("regex"),
              cl::Optional, cl::cat(MatchCategory));

enum OutputMode { OM_Count, OM_Summary, OM_Detailed };
static cl::opt<OutputMode> OutputLevel(
    cl::desc("output verbosity (default: count only)"),
    cl::values(clEnumValN(OM_Summary, "summary",
                          "show per-function hit counts sorted by frequency"),
               clEnumValN(OM_Detailed, "detailed",
                          "show every individual match (verbose)")),
    cl::init(OM_Count), cl::cat(MatchCategory));

static cl::opt<bool>
    TimeOpt("time", cl::desc("print timing breakdown"),
            cl::Optional, cl::cat(MatchCategory));

} // namespace opts

static StringRef ToolName = "llvm-match";

static TimerGroup TG("llvm-match", "llvm-match timing");
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

  // Step 3: Cross-BB edges.
  DenseMap<const BinaryBasicBlock *, unsigned> BBPtrToIdx;
  for (unsigned I = 0; I < AllBBs.size(); ++I)
    BBPtrToIdx[AllBBs[I].BB] = I;

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
      // Calls clobber caller-saved regunits — mark them as defined so that
      // later uses in this BB don't appear as live-in.
      if (BC.MIB->isCall(*Node.Inst)) {
        for (unsigned RU = 0, E = MRI.getNumRegUnits(); RU < E; ++RU) {
          if (!CalleeSavedRUs.count(RU))
            DefinedSoFar.insert(RU);
        }
      }
    }

    // For each live-in use, find definer in predecessor BBs via regunits.
    for (const auto &[Reg, UseNID] : LiveInUses) {
      for (const BinaryBasicBlock *Pred : AllBBs[BBIdx].BB->predecessors()) {
        auto PredIt = BBPtrToIdx.find(Pred);
        if (PredIt == BBPtrToIdx.end())
          continue;
        unsigned PredIdx = PredIt->second;
        for (MCRegUnit RU : MRI.regunits(Reg)) {
          auto DefIt = PerBBLastDef[PredIdx].find(static_cast<unsigned>(RU));
          if (DefIt != PerBBLastDef[PredIdx].end()) {
            unsigned EIdx = G.Edges.size();
            G.Edges.push_back({DefIt->second, UseNID, Reg});
            G.OutEdges[DefIt->second].push_back(EIdx);
            G.InEdges[UseNID].push_back(EIdx);
            break; // One edge per (pred, use) pair is enough.
          }
        }
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
  enum Kind { Defs, Uses, OneUse, HasUse, SameBB };
  Kind K;
  std::vector<PatternOperand> Operands;  // for @defs/@uses
  std::vector<std::string> Names;        // for @one_use/@has_use/@same_bb
};

struct PatternLine {
  std::string Mnemonic;
  std::string MnemRegex;       // from {{regex}} mnemonic
  std::vector<PatternOperand> Operands;
  std::vector<Annotation> Annotations;
  bool IsRoot = false;
  bool IsAnnotationOnly = false;  // line is just @constraint(s)
};

// A bound value from matching.
struct Binding {
  enum Kind { Reg, Imm, Label };
  Kind K;
  MCPhysReg RegVal = 0;
  int64_t ImmVal = 0;
  std::string LabelVal;
};

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

    // Parse "root " prefix.
    if (InstrPart.starts_with("root ")) {
      PL.IsRoot = true;
      InstrPart = InstrPart.drop_front(5).ltrim();
    }

    // Parse mnemonic (first token).
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
    if (PL.IsRoot)
      outs() << "root ";
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
    if (PL.IsRoot)
      OS << "root ";
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
      }
    }

    OS << "\"";
    if (PL.IsRoot)
      OS << ", style=bold, penwidth=2";
    OS << "];\n";
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


// Validate post-match constraints (@one_use, @has_use, @same_bb).
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
    for (unsigned PI = 0; PI < NumPat; ++PI) {
      if (Pattern[PI].IsAnnotationOnly)
        continue;
      auto TIt = MergedTrace.find(PI);
      if (TIt == MergedTrace.end()) {
        Complete = false;
        break;
      }
      MatchedNodeIDs.push_back(TIt->second);
    }
    if (!Complete)
      continue;

    // Validate post-match constraints (@one_use, @same_bb, etc.).
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

  for (const auto &[BI, Idx] : Result.MatchedInstrs) {
    outs() << "  " << BI->BB->getName() << ":" << Idx << "  ";
    BC.InstPrinter->printInst(BI->Nodes[Idx].Inst, 0, "", *BC.STI, outs());
    outs() << "\n";
  }

  if (!Result.Bindings.empty()) {
    outs() << "  Bindings:\n";
    for (const auto &[Name, B] : Result.Bindings) {
      outs() << "    %" << Name << " = ";
      if (B.K == Binding::Reg)
        outs() << BC.MRI->getName(B.RegVal);
      else if (B.K == Binding::Imm)
        outs() << "#" << B.ImmVal;
      else
        outs() << B.LabelVal;
      outs() << "\n";
    }
  }
  outs() << "\n";
}

/// Collect uppercase mnemonic prefixes from all non-annotation pattern lines.
/// Used for opcode-level pre-filtering: a function must contain at least one
/// instruction whose tablegen opcode name starts with each prefix.
static SmallVector<std::string, 4>
collectMnemPrefixes(const std::vector<PatternLine> &Pattern) {
  SmallVector<std::string, 4> Prefixes;
  for (const PatternLine &PL : Pattern) {
    if (PL.IsAnnotationOnly || PL.Mnemonic.empty())
      continue;
    // Strip NEON qualifier (e.g., ".4s", ".16b") — tablegen opcode names
    // like "ADDv4i32" don't contain the dot-qualifier.
    StringRef M = PL.Mnemonic;
    M = M.split('.').first;
    Prefixes.push_back(M.upper());
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
                             std::vector<std::pair<std::string, unsigned>> &FuncHits) {
  SmallVector<const BinaryFunction *, 0> Functions;
  for (const auto &[Addr, BF] : BC.getBinaryFunctions())
    Functions.push_back(&BF);

  std::vector<FunctionResults> AllResults(Functions.size());
  std::atomic<unsigned> Completed{0};
  unsigned Total = Functions.size();
  bool ShowProgress = errs().is_displayed();

  // Collect all pattern mnemonic prefixes for function-level pre-filter.
  SmallVector<std::string, 4> Prefixes = collectMnemPrefixes(Pattern);

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

      // Pre-compute first pattern line mnemonic (uppercased) for fast opcode filtering.
      const PatternLine &FirstPL = Pattern[0];
      std::string FirstMnemUpper = StringRef(FirstPL.Mnemonic).split('.').first.upper();

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
    }
    if (!FR.Matches.empty())
      FuncHits.emplace_back(FR.Matches.front().FunctionName,
                            FR.Matches.size());
  }
}

static void runGraphMatcher(const BinaryContext &BC,
                            const std::vector<PatternLine> &Pattern,
                            unsigned &MatchCount,
                            std::vector<std::pair<std::string, unsigned>> &FuncHits) {
  SmallVector<const BinaryFunction *, 0> Functions;
  for (const auto &[Addr, BF] : BC.getBinaryFunctions())
    Functions.push_back(&BF);

  std::vector<FunctionResults> AllResults(Functions.size());
  std::atomic<unsigned> Completed{0};
  unsigned Total = Functions.size();
  bool ShowProgress = errs().is_displayed();

  // Collect all pattern mnemonic prefixes for function-level pre-filter.
  SmallVector<std::string, 4> Prefixes = collectMnemPrefixes(Pattern);

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

  // Also treat any pattern with an explicit 'root' as a graph pattern.
  for (const PatternLine &PL : Pattern)
    if (PL.IsRoot)
      IsGraphPattern = true;

  unsigned MatchCount = 0;
  std::vector<std::pair<std::string, unsigned>> FuncHits;
  if (IsGraphPattern) {
    outs() << "Using graph-based DP matcher\n";
    runGraphMatcher(BC, Pattern, MatchCount, FuncHits);
  } else {
    runLinearMatcher(BC, Pattern, MatchCount, FuncHits);
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
  {
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
                              "llvm-match - binary function matching tool\n");

  // Use BinaryAnalysisMode so run() returns after CFG building without
  // attempting to rewrite the binary.
  opts::BinaryAnalysisMode = true;

  // Parse pattern file if provided.
  std::vector<PatternLine> Pattern;
  if (!opts::PatternFilename.empty()) {
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

  // Parse suite file if provided.
  std::vector<NamedPattern> Suite;
  if (!opts::SuiteFilename.empty()) {
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

  // If no action specified, default to dump-functions.
  if (!opts::DumpFunctions && !opts::DumpLiveness && Pattern.empty() &&
      Suite.empty() && !opts::DumpGraph.getNumOccurrences())
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
    {
      TimeRegion TR(opts::TimeOpt ? &TMatch : nullptr);
      processBinaryContext(RI.getBinaryContext(), Pattern, Suite);
    }
  } else if (auto *MachOObj = dyn_cast<MachOObjectFile>(&Binary)) {
    processMachO(MachOObj, ToolPath, Pattern, Suite);
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
    processMachO(ObjOrErr->get(), ToolPath, Pattern, Suite);
  } else {
    report_error(opts::InputFilename, object_error::invalid_file_type);
  }

  return EXIT_SUCCESS;
}
