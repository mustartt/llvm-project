//===- Transforms/Instrumentation/InstrProfToPseudoProbe.h ------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
/// \file
/// Rewrite clang-emitted coverage counter increment intrinsics
/// (\c llvm.instrprof.increment, \c llvm.instrprof.cover) into
/// \c llvm.pseudoprobe calls so coverage hit data can be derived from sampled
/// profile sources instead of the InstrProf runtime.
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_INSTRPROFTOPSEUDOPROBE_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_INSTRPROFTOPSEUDOPROBE_H

#include "llvm/IR/PassManager.h"
#include "llvm/Support/Compiler.h"

namespace llvm {

class Module;

class InstrProfToPseudoProbePass
    : public PassInfoMixin<InstrProfToPseudoProbePass> {
public:
  LLVM_ABI PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

} // end namespace llvm

#endif // LLVM_TRANSFORMS_INSTRUMENTATION_INSTRPROFTOPSEUDOPROBE_H
