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

} // namespace opts

static StringRef ToolName = "llvm-match";

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

// ===----------------------------------------------------------------------===//
// Data structures
// ===----------------------------------------------------------------------===//

struct InstrNode {
  const MCInst *Inst;
  std::string Mnemonic;     // Assembly mnemonic (e.g., "cmp")
  unsigned BBIndex;
  unsigned InstIndex;       // Index within BB
  SmallVector<MCPhysReg, 4> Defs; // Registers defined (explicit + implicit)
  SmallVector<MCPhysReg, 4> Uses; // Registers used (explicit + implicit)
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

static DefUseGraph buildDefUseGraph(const std::vector<BBInfo> &AllBBs) {
  DefUseGraph G;

  // Step 1: Flatten all InstrNodes, record BB start offsets.
  for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
    G.BBStart.push_back(G.Nodes.size());
    for (const InstrNode &N : AllBBs[BBIdx].Nodes)
      G.Nodes.push_back(N);
  }

  // Step 2: Within each BB, track last definer per register.
  // Store per-BB last-def maps for cross-BB edges.
  std::vector<DenseMap<MCPhysReg, NodeID>> PerBBLastDef(AllBBs.size());

  for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
    unsigned Start = G.BBStart[BBIdx];
    unsigned End = (BBIdx + 1 < AllBBs.size()) ? G.BBStart[BBIdx + 1]
                                                : G.Nodes.size();
    DenseMap<MCPhysReg, NodeID> LastDef;

    for (unsigned NID = Start; NID < End; ++NID) {
      const InstrNode &Node = G.Nodes[NID];

      // Add edges: for each use, if there's a last definer, add edge.
      for (MCPhysReg Reg : Node.Uses) {
        auto It = LastDef.find(Reg);
        if (It != LastDef.end()) {
          unsigned EIdx = G.Edges.size();
          G.Edges.push_back({It->second, NID, Reg});
          G.OutEdges[It->second].push_back(EIdx);
          G.InEdges[NID].push_back(EIdx);
        }
      }

      // Update last definer for each def.
      for (MCPhysReg Reg : Node.Defs)
        LastDef[Reg] = NID;
    }

    PerBBLastDef[BBIdx] = std::move(LastDef);
  }

  // Step 3: Cross-BB edges. For each BB, for each predecessor, if a register
  // is used in this BB before being defined (i.e., live-in), connect from
  // the predecessor's last definer.
  // Build BB pointer → index map.
  DenseMap<const BinaryBasicBlock *, unsigned> BBPtrToIdx;
  for (unsigned I = 0; I < AllBBs.size(); ++I)
    BBPtrToIdx[AllBBs[I].BB] = I;

  for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
    unsigned Start = G.BBStart[BBIdx];
    unsigned End = (BBIdx + 1 < AllBBs.size()) ? G.BBStart[BBIdx + 1]
                                                : G.Nodes.size();

    // Find registers used before being defined in this BB (live-in uses).
    DenseSet<MCPhysReg> DefinedSoFar;
    SmallVector<std::pair<MCPhysReg, NodeID>, 8> LiveInUses;

    for (unsigned NID = Start; NID < End; ++NID) {
      const InstrNode &Node = G.Nodes[NID];
      for (MCPhysReg Reg : Node.Uses) {
        if (!DefinedSoFar.count(Reg))
          LiveInUses.push_back({Reg, NID});
      }
      for (MCPhysReg Reg : Node.Defs)
        DefinedSoFar.insert(Reg);
    }

    // For each live-in use, find definer in predecessor BBs.
    for (const auto &[Reg, UseNID] : LiveInUses) {
      for (const BinaryBasicBlock *Pred : AllBBs[BBIdx].BB->predecessors()) {
        auto PredIt = BBPtrToIdx.find(Pred);
        if (PredIt == BBPtrToIdx.end())
          continue;
        unsigned PredIdx = PredIt->second;
        auto DefIt = PerBBLastDef[PredIdx].find(Reg);
        if (DefIt != PerBBLastDef[PredIdx].end()) {
          unsigned EIdx = G.Edges.size();
          G.Edges.push_back({DefIt->second, UseNID, Reg});
          G.OutEdges[DefIt->second].push_back(EIdx);
          G.InEdges[UseNID].push_back(EIdx);
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

static std::vector<BBInfo> buildBBInfos(const BinaryContext &BC,
                                        const BinaryFunction &BF) {
  unsigned NumRegs = BC.MRI->getNumRegs();
  std::vector<BBInfo> Infos;
  Infos.reserve(BF.size());

  unsigned BBIdx = 0;
  for (const BinaryBasicBlock &BB : BF) {
    BBInfo Info;
    Info.BB = &BB;
    Info.LiveIn.resize(NumRegs);
    Info.LiveOut.resize(NumRegs);

    unsigned InstIdx = 0;
    for (const MCInst &Inst : BB) {
      InstrNode Node;
      Node.Inst = &Inst;
      Node.BBIndex = BBIdx;
      Node.InstIndex = InstIdx++;

      // Get the printed mnemonic by printing to a string and extracting the
      // first token. Some instructions may not be printable; fall back to
      // MCInstrInfo::getName() (which gives the tablegen opcode name).
      {
        std::string Buf;
        raw_string_ostream OS(Buf);
        BC.InstPrinter->printInst(&Inst, 0, "", *BC.STI, OS);
        StringRef S(Buf);
        S = S.ltrim();
        Node.Mnemonic = S.substr(0, S.find_first_of(" \t")).str();
      }

      computeInstrDefsUses(BC, Inst, Node.Defs, Node.Uses);
      Info.Nodes.push_back(std::move(Node));
    }

    Infos.push_back(std::move(Info));
    ++BBIdx;
  }

  // Compute liveness: backward scan per BB.
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

// E.g., "ldrb\tw12, [x0, #8]" -> ("ldrb", ["w12", "[x0, #8]"])
static void parseAsmText(const BinaryContext &BC, const MCInst &Inst,
                         std::string &Mnemonic,
                         SmallVectorImpl<std::string> &OpTokens) {
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

  // Bracket-aware operand splitting.
  if (!Rest.empty()) {
    SmallVector<StringRef, 4> Parts = splitOperands(Rest);
    for (StringRef P : Parts) {
      P = P.trim();
      if (!P.empty())
        OpTokens.push_back(P.str());
    }
  }
}

// Try to bind a pattern operand against a printed assembly operand token.
// Returns false if binding fails.
static bool tryBindOperand(const BinaryContext &BC, const PatternOperand &PO,
                           StringRef Token, const InstrNode &Node,
                           StringMap<Binding> &Bindings) {
  if (PO.K == PatternOperand::Literal)
    return true; // Literals are hints, always pass.

  // Rest: accepts all remaining tokens.
  if (PO.K == PatternOperand::Rest)
    return true;

  // Check and strip prefix (e.g., "#").
  StringRef WorkToken = Token;
  if (!PO.Prefix.empty()) {
    if (!WorkToken.starts_with(PO.Prefix))
      return false;
    WorkToken = WorkToken.drop_front(PO.Prefix.size());
  }

  // MemOperand: token is bracket group from parseAsmText.
  if (PO.K == PatternOperand::MemOperand) {
    StringRef Inner = WorkToken;
    // Strip brackets and optional ! suffix.
    if (Inner.ends_with("!")) {
      if (!PO.PreIndex)
        return false;
      Inner = Inner.drop_back(1);
    } else if (PO.PreIndex) {
      return false; // Pattern expects pre-index but token doesn't have it.
    }
    if (Inner.starts_with("[") && Inner.ends_with("]"))
      Inner = Inner.drop_front(1).drop_back(1);
    else
      return false;

    // Split sub-tokens and bind recursively.
    SmallVector<StringRef, 4> SubTokens = splitOperands(Inner);
    if (PO.SubOperands.size() > SubTokens.size())
      return false;
    for (unsigned I = 0; I < PO.SubOperands.size(); ++I) {
      if (PO.SubOperands[I].K == PatternOperand::Rest)
        break;
      if (!tryBindOperand(BC, PO.SubOperands[I], SubTokens[I], Node, Bindings))
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
          StringRef BoundName = BC.MRI->getName(B.RegVal);
          return WorkToken.equals_insensitive(BoundName);
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
      MCPhysReg FoundReg = 0;
      for (unsigned I = 0, E = Node.Inst->getNumOperands(); I < E; ++I) {
        const MCOperand &Op = Node.Inst->getOperand(I);
        if (Op.isReg() && Op.getReg() != 0) {
          if (WorkToken.equals_insensitive(BC.MRI->getName(Op.getReg()))) {
            FoundReg = Op.getReg();
            break;
          }
        }
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
      StringRef BoundName = BC.MRI->getName(It->second.RegVal);
      if (!RegName.equals_insensitive(BoundName))
        return false;
    } else {
      // Look up the register by name in MCInst operands.
      MCPhysReg FoundReg = 0;
      for (unsigned I = 0, E = Node.Inst->getNumOperands(); I < E; ++I) {
        const MCOperand &Op = Node.Inst->getOperand(I);
        if (Op.isReg() && Op.getReg() != 0) {
          if (RegName.equals_insensitive(BC.MRI->getName(Op.getReg()))) {
            FoundReg = Op.getReg();
            break;
          }
        }
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

  // Parse the printed assembly.
  std::string PrintedMnem;
  SmallVector<std::string, 4> OpTokens;
  parseAsmText(BC, *Node.Inst, PrintedMnem, OpTokens);

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
  if (PL.Operands.size() > OpTokens.size()) {
    // Allow if last operand is Rest.
    if (PL.Operands.empty() || PL.Operands.back().K != PatternOperand::Rest)
      return false;
  }

  for (unsigned I = 0; I < PL.Operands.size(); ++I) {
    if (PL.Operands[I].K == PatternOperand::Rest)
      break; // Rest matches remaining operands.
    if (I >= OpTokens.size())
      return false;
    // Skip NZCV captures from positional matching (they're implicit).
    if (PL.Operands[I].K == PatternOperand::Capture &&
        PL.Operands[I].Type == "nzcv")
      continue;
    if (!tryBindOperand(BC, PL.Operands[I], OpTokens[I], Node, Bindings))
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

// Find candidate NodeIDs for a pattern line by walking def-use edges.
static SmallVector<NodeID, 8> findGraphCandidates(
    const BinaryContext &BC, const DefUseGraph &G, const PatternLine &PL,
    const StringMap<Binding> &Bindings,
    const StringMap<SmallVector<NodeID, 2>> &CaptureProducers,
    const StringMap<SmallVector<NodeID, 2>> &CaptureConsumers,
    const DenseSet<NodeID> &AlreadyMatchedNodes) {
  SmallVector<NodeID, 8> Candidates;
  DenseSet<NodeID> Seen;

  SmallVector<std::string, 4> DefCaptures, UseCaptures;
  classifyCapturePositions(BC, PL, nullptr, DefCaptures, UseCaptures);

  LLVM_DEBUG({
    dbgs() << "    findGraphCandidates: DefCaptures:";
    for (const auto &N : DefCaptures) dbgs() << " '" << N << "'";
    dbgs() << " UseCaptures:";
    for (const auto &N : UseCaptures) dbgs() << " '" << N << "'";
    dbgs() << "\n";
  });

  // For each bound capture that appears in a DEF position of this pattern line,
  // this instruction produces the capture → walk backward from consumers.
  for (const std::string &Name : DefCaptures) {
    auto BIt = Bindings.find(Name);
    if (BIt == Bindings.end())
      continue;
    const Binding &B = BIt->second;
    if (B.K != Binding::Reg)
      continue;

    // Walk backward: find nodes that are Def endpoints of InEdges of consumers.
    auto CIt = CaptureConsumers.find(Name);
    if (CIt == CaptureConsumers.end())
      continue;
    for (NodeID ConsumerNID : CIt->second) {
      auto EIt = G.InEdges.find(ConsumerNID);
      if (EIt == G.InEdges.end())
        continue;
      for (unsigned EIdx : EIt->second) {
        const DefUseEdge &E = G.Edges[EIdx];
        if (regMatchesBinding(BC, E.Reg, B) &&
            !AlreadyMatchedNodes.count(E.Def) && Seen.insert(E.Def).second)
          Candidates.push_back(E.Def);
      }
    }
  }

  // For each bound capture that appears in a USE position of this pattern line,
  // this instruction consumes the capture → walk forward from producers.
  for (const std::string &Name : UseCaptures) {
    auto BIt = Bindings.find(Name);
    if (BIt == Bindings.end())
      continue;
    const Binding &B = BIt->second;
    if (B.K != Binding::Reg)
      continue;

    auto PIt = CaptureProducers.find(Name);
    if (PIt == CaptureProducers.end())
      continue;
    for (NodeID ProducerNID : PIt->second) {
      auto EIt = G.OutEdges.find(ProducerNID);
      if (EIt == G.OutEdges.end())
        continue;
      for (unsigned EIdx : EIt->second) {
        const DefUseEdge &E = G.Edges[EIdx];
        if (regMatchesBinding(BC, E.Reg, B) &&
            !AlreadyMatchedNodes.count(E.Use) && Seen.insert(E.Use).second)
          Candidates.push_back(E.Use);
      }
    }
  }

  // Fallback: if no candidates found via edges (e.g., no bound captures
  // connect this line to already-matched nodes), try all unmatched nodes.
  if (Candidates.empty()) {
    for (NodeID NID = 0; NID < G.Nodes.size(); ++NID) {
      if (!AlreadyMatchedNodes.count(NID))
        Candidates.push_back(NID);
    }
  }

  return Candidates;
}

// Update CaptureProducers and CaptureConsumers after matching a pattern line.
static void updateCaptureTracking(
    const BinaryContext &BC, const PatternLine &PL,
    NodeID MatchedNID, const InstrNode *MatchedNode,
    const StringMap<Binding> &Bindings,
    StringMap<SmallVector<NodeID, 2>> &CaptureProducers,
    StringMap<SmallVector<NodeID, 2>> &CaptureConsumers) {
  SmallVector<std::string, 4> DefCaptures, UseCaptures;
  classifyCapturePositions(BC, PL, MatchedNode, DefCaptures, UseCaptures);

  for (const std::string &Name : DefCaptures) {
    auto BIt = Bindings.find(Name);
    if (BIt != Bindings.end() && BIt->second.K == Binding::Reg)
      CaptureProducers[BIt->first()].push_back(MatchedNID);
  }
  for (const std::string &Name : UseCaptures) {
    auto BIt = Bindings.find(Name);
    if (BIt != Bindings.end() && BIt->second.K == Binding::Reg)
      CaptureConsumers[BIt->first()].push_back(MatchedNID);
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

// Graph-based pattern matching using root as anchor.
static bool tryGraphMatch(const BinaryContext &BC,
                           const std::vector<PatternLine> &Pattern,
                           unsigned RootPatIdx,
                           const DefUseGraph &G,
                           const std::vector<BBInfo> &AllBBs,
                           NodeID RootNID,
                           MatchResult &Result) {
  StringMap<Binding> Bindings;

  // Try matching the root pattern line against the root node.
  if (!matchLine(BC, Pattern[RootPatIdx], G.Nodes[RootNID], Bindings))
    return false;

  // Map from pattern index → matched NodeID (pattern-order aligned).
  DenseMap<unsigned, NodeID> PatIdxToNodeID;
  PatIdxToNodeID[RootPatIdx] = RootNID;
  DenseSet<NodeID> AlreadyMatchedNodes;
  AlreadyMatchedNodes.insert(RootNID);

  // Initialize capture tracking from root.
  StringMap<SmallVector<NodeID, 2>> CaptureProducers;
  StringMap<SmallVector<NodeID, 2>> CaptureConsumers;
  updateCaptureTracking(BC, Pattern[RootPatIdx], RootNID,
                        &G.Nodes[RootNID], Bindings,
                        CaptureProducers, CaptureConsumers);

  // Match remaining pattern lines in order.
  for (unsigned PatIdx = 0; PatIdx < Pattern.size(); ++PatIdx) {
    if (PatIdx == RootPatIdx)
      continue;

    const PatternLine &PL = Pattern[PatIdx];

    // Annotation-only lines don't need candidate search.
    if (PL.IsAnnotationOnly)
      continue;

    // Find candidates via def-use graph.
    SmallVector<NodeID, 8> Candidates = findGraphCandidates(
        BC, G, PL, Bindings, CaptureProducers, CaptureConsumers,
        AlreadyMatchedNodes);

    LLVM_DEBUG({
      dbgs() << "  Pattern line " << PatIdx << " ('" << PL.Mnemonic
             << "'): " << Candidates.size() << " candidates\n";
      for (NodeID C : Candidates)
        dbgs() << "    candidate NID=" << C << " mnem='"
               << G.Nodes[C].Mnemonic << "'\n";
    });

    bool Matched = false;
    for (NodeID CandNID : Candidates) {
      StringMap<Binding> TryBindings = Bindings;
      if (matchLine(BC, PL, G.Nodes[CandNID], TryBindings)) {
        Bindings = std::move(TryBindings);
        PatIdxToNodeID[PatIdx] = CandNID;
        AlreadyMatchedNodes.insert(CandNID);
        updateCaptureTracking(BC, PL, CandNID, &G.Nodes[CandNID],
                              Bindings, CaptureProducers, CaptureConsumers);
        Matched = true;
        break;
      }
    }

    if (!Matched)
      return false;
  }

  // Build MatchedNodeIDs in pattern order (non-annotation lines only).
  SmallVector<NodeID, 8> MatchedNodeIDs;
  for (unsigned PatIdx = 0; PatIdx < Pattern.size(); ++PatIdx) {
    auto It = PatIdxToNodeID.find(PatIdx);
    if (It != PatIdxToNodeID.end())
      MatchedNodeIDs.push_back(It->second);
  }

  // Validate post-match constraints.
  if (!validateConstraints(BC, Pattern, G, MatchedNodeIDs, Bindings))
    return false;

  // Build MatchResult from matched NodeIDs.
  Result.Bindings = std::move(Bindings);
  Result.MatchedNodeIDs = std::move(MatchedNodeIDs);

  // Convert NodeIDs to (BBInfo*, InstIdx) pairs for display.
  for (NodeID NID : Result.MatchedNodeIDs) {
    const InstrNode &Node = G.Nodes[NID];
    Result.MatchedInstrs.push_back({&AllBBs[Node.BBIndex], Node.InstIndex});
  }

  return true;
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

static void runLinearMatcher(const BinaryContext &BC,
                             const std::vector<PatternLine> &Pattern,
                             unsigned &MatchCount) {
  SmallVector<const BinaryFunction *, 0> Functions;
  for (const auto &[Addr, BF] : BC.getBinaryFunctions())
    Functions.push_back(&BF);

  std::vector<FunctionResults> AllResults(Functions.size());
  std::atomic<unsigned> Completed{0};
  unsigned Total = Functions.size();
  bool ShowProgress = errs().is_displayed();

  DefaultThreadPool Pool(hardware_concurrency(opts::ThreadCount));
  for (unsigned FIdx = 0; FIdx < Functions.size(); ++FIdx) {
    Pool.async([&BC, &Pattern, &Functions, &AllResults, &Completed, Total,
                ShowProgress, FIdx] {
      const BinaryFunction &BF = *Functions[FIdx];
      std::vector<BBInfo> AllBBs = buildBBInfos(BC, BF);
      DenseSet<const MCInst *> LocalMatched;

      for (unsigned BBIdx = 0; BBIdx < AllBBs.size(); ++BBIdx) {
        for (unsigned InstIdx = 0; InstIdx < AllBBs[BBIdx].Nodes.size();
             ++InstIdx) {
          if (LocalMatched.count(AllBBs[BBIdx].Nodes[InstIdx].Inst))
            continue;
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

  for (const auto &FR : AllResults)
    for (const auto &Result : FR.Matches)
      printMatchResult(BC, Result, ++MatchCount);
}

static void runGraphMatcher(const BinaryContext &BC,
                            const std::vector<PatternLine> &Pattern,
                            unsigned RootPatIdx,
                            unsigned &MatchCount) {
  SmallVector<const BinaryFunction *, 0> Functions;
  for (const auto &[Addr, BF] : BC.getBinaryFunctions())
    Functions.push_back(&BF);

  std::vector<FunctionResults> AllResults(Functions.size());
  std::atomic<unsigned> Completed{0};
  unsigned Total = Functions.size();
  bool ShowProgress = errs().is_displayed();

  DefaultThreadPool Pool(hardware_concurrency(opts::ThreadCount));
  for (unsigned FIdx = 0; FIdx < Functions.size(); ++FIdx) {
    Pool.async([&BC, &Pattern, RootPatIdx, &Functions, &AllResults, &Completed,
                Total, ShowProgress, FIdx] {
      const BinaryFunction &BF = *Functions[FIdx];
      std::vector<BBInfo> AllBBs = buildBBInfos(BC, BF);
      DefUseGraph G = buildDefUseGraph(AllBBs);
      DenseSet<const MCInst *> LocalMatched;

      for (NodeID NID = 0; NID < G.Nodes.size(); ++NID) {
        if (LocalMatched.count(G.Nodes[NID].Inst))
          continue;

        MatchResult Result;
        if (tryGraphMatch(BC, Pattern, RootPatIdx, G, AllBBs, NID, Result)) {
          for (const auto &[BI, Idx] : Result.MatchedInstrs)
            LocalMatched.insert(BI->Nodes[Idx].Inst);
          Result.FunctionName = BF.getPrintName();
          AllResults[FIdx].Matches.push_back(std::move(Result));
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

  for (const auto &FR : AllResults)
    for (const auto &Result : FR.Matches)
      printMatchResult(BC, Result, ++MatchCount);
}

static void runMatcher(const BinaryContext &BC,
                       const std::vector<PatternLine> &Pattern) {
  if (Pattern.empty())
    return;

  // Check if any pattern line is an explicit root.
  int RootPatIdx = -1;
  for (unsigned I = 0; I < Pattern.size(); ++I) {
    if (Pattern[I].IsRoot) {
      RootPatIdx = I;
      break;
    }
  }

  // Auto-detect: if no explicit root but shared captures exist, pick the best
  // root and use the graph matcher. A "graph pattern" is one where at least one
  // capture name appears in more than one non-annotation line.
  bool IsGraphPattern = false;
  if (RootPatIdx < 0) {
    // Collect capture names per line.
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
      // A shared capture: appears in >1 distinct lines.
      SmallVector<unsigned, 2> Unique(Lines.begin(), Lines.end());
      llvm::sort(Unique);
      Unique.erase(llvm::unique(Unique), Unique.end());
      if (Unique.size() > 1) {
        IsGraphPattern = true;
        break;
      }
    }

    if (IsGraphPattern) {
      // Score each line: higher = better root candidate.
      //   +4  exact mnemonic (not regex, not empty)
      //   +2  per typed capture (wreg/xreg/reg/imm)
      //   +1  per shared capture (appears in another line)
      //   -10 annotation-only line
      //   -5  wildcard-only mnemonic ({{.*}})
      int BestScore = -100;
      for (unsigned I = 0; I < Pattern.size(); ++I) {
        const PatternLine &PL = Pattern[I];
        if (PL.IsAnnotationOnly)
          continue;
        int Score = 0;
        if (!PL.Mnemonic.empty() && PL.MnemRegex.empty())
          Score += 4;
        else if (PL.Mnemonic.empty() && !PL.MnemRegex.empty())
          Score -= 5;
        for (const PatternOperand &PO : PL.Operands) {
          if (PO.K == PatternOperand::Capture && !PO.Name.empty()) {
            if (!PO.Type.empty() && PO.Type != "nzcv")
              Score += 2;
            auto It = CaptureLines.find(PO.Name);
            if (It != CaptureLines.end()) {
              SmallVector<unsigned, 2> U(It->second.begin(), It->second.end());
              llvm::sort(U);
              U.erase(llvm::unique(U), U.end());
              if (U.size() > 1)
                Score += 1;
            }
          } else if (PO.K == PatternOperand::MemOperand) {
            for (const PatternOperand &Sub : PO.SubOperands)
              if (Sub.K == PatternOperand::Capture && !Sub.Type.empty())
                Score += 2;
          }
        }
        if (Score > BestScore) {
          BestScore = Score;
          RootPatIdx = I;
        }
      }
    }
  }

  unsigned MatchCount = 0;
  if (RootPatIdx >= 0) {
    bool Explicit = Pattern[RootPatIdx].IsRoot;
    outs() << "Using graph-based matcher ("
           << (Explicit ? "explicit" : "auto-detected") << " root at line "
           << RootPatIdx << ": " << Pattern[RootPatIdx].Mnemonic << ")\n";
    runGraphMatcher(BC, Pattern, static_cast<unsigned>(RootPatIdx), MatchCount);
  } else {
    runLinearMatcher(BC, Pattern, MatchCount);
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

// ===----------------------------------------------------------------------===//
// Binary loading (reused from previous implementation)
// ===----------------------------------------------------------------------===//

static void processBinaryContext(const BinaryContext &BC,
                                 const std::vector<PatternLine> &Pattern) {
  if (opts::DumpFunctions)
    printFunctions(BC);

  if (opts::DumpLiveness) {
    for (const auto &[Addr, BF] : BC.getBinaryFunctions())
      printLiveness(BC, BF);
  }

  if (!Pattern.empty())
    runMatcher(BC, Pattern);
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
                          const std::vector<PatternLine> &Pattern) {
  auto MachORIOrErr = MachORewriteInstance::create(MachOObj, ToolPath);
  if (Error E = MachORIOrErr.takeError())
    report_error(opts::InputFilename, std::move(E));
  MachORewriteInstance &MachORI = *MachORIOrErr.get();
  MachORI.setProgressCallback(makeProgressCallback());
  MachORI.run();
  clearProgress();
  if (errs().is_displayed())
    fprintf(stderr, "Loaded %zu functions\n",
            MachORI.getBinaryContext().getBinaryFunctions().size());
  processBinaryContext(MachORI.getBinaryContext(), Pattern);
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

  // If no action specified, default to dump-functions.
  if (!opts::DumpFunctions && !opts::DumpLiveness && Pattern.empty())
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
    if (Error E = RI.run())
      report_error(opts::InputFilename, std::move(E));
    clearProgress();
    if (errs().is_displayed())
      fprintf(stderr, "Loaded %zu functions\n",
              RI.getBinaryContext().getBinaryFunctions().size());
    processBinaryContext(RI.getBinaryContext(), Pattern);
  } else if (auto *MachOObj = dyn_cast<MachOObjectFile>(&Binary)) {
    processMachO(MachOObj, ToolPath, Pattern);
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
    processMachO(ObjOrErr->get(), ToolPath, Pattern);
  } else {
    report_error(opts::InputFilename, object_error::invalid_file_type);
  }

  return EXIT_SUCCESS;
}
