//===- bolt/tools/llvm-match/llvm-match.cpp -------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Loads a binary via BOLT's infrastructure and dumps disassembled functions
// with their basic blocks and instructions.
//
//===----------------------------------------------------------------------===//

#include "bolt/Core/BinaryBasicBlock.h"
#include "bolt/Core/BinaryContext.h"
#include "bolt/Core/BinaryFunction.h"
#include "bolt/Rewrite/MachORewriteInstance.h"
#include "bolt/Rewrite/RewriteInstance.h"
#include "bolt/Utils/CommandLineOpts.h"
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
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Program.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/TargetSelect.h"

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

static void printFunctions(const BinaryContext &BC) {
  for (const auto &[Addr, BF] : BC.getBinaryFunctions()) {
    outs() << "Function: " << BF.getPrintName() << "\n";
    for (const BinaryBasicBlock &BB : BF) {
      outs() << "  BB " << BB.getName() << " (" << BB.size()
             << " instrs)\n";
      for (const MCInst &Inst : BB) {
        outs() << "    ";
        BC.InstPrinter->printInst(&Inst, 0, "", *BC.STI, outs());

        // Print implicit register defs/uses.
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

static void processMachO(MachOObjectFile *MachOObj, StringRef ToolPath) {
  auto MachORIOrErr = MachORewriteInstance::create(MachOObj, ToolPath);
  if (Error E = MachORIOrErr.takeError())
    report_error(opts::InputFilename, std::move(E));
  MachORewriteInstance &MachORI = *MachORIOrErr.get();
  MachORI.run();
  printFunctions(MachORI.getBinaryContext());
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
    if (Error E = RI.run())
      report_error(opts::InputFilename, std::move(E));
    printFunctions(RI.getBinaryContext());
  } else if (auto *MachOObj = dyn_cast<MachOObjectFile>(&Binary)) {
    processMachO(MachOObj, ToolPath);
  } else if (auto *FatBin = dyn_cast<MachOUniversalBinary>(&Binary)) {
    // Fat binary — extract the requested arch slice.
    StringRef Arch = opts::ArchName;
    if (Arch.empty()) {
      // List available slices and bail.
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
    processMachO(ObjOrErr->get(), ToolPath);
  } else {
    report_error(opts::InputFilename, object_error::invalid_file_type);
  }

  return EXIT_SUCCESS;
}
