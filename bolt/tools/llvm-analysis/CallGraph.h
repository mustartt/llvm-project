//===- bolt/tools/llvm-analysis/CallGraph.h - Unified call graph ----------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Builds a unified call graph from BOLT's internal call graph, YAML profiles,
// text sample profiles, and optimization remarks.  Always emits serialized
// YAML; optionally emits DOT for visualization.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_ANALYSIS_CALLGRAPH_H
#define LLVM_TOOLS_LLVM_ANALYSIS_CALLGRAPH_H

#include "llvm/Support/CommandLine.h"

namespace llvm {
namespace bolt {
class BinaryContext;
} // namespace bolt
} // namespace llvm

namespace opts {
extern llvm::cl::SubCommand CallGraphCmd;
} // namespace opts

/// Build a unified call graph and emit YAML (+ optional DOT).
void processCallGraph(const llvm::bolt::BinaryContext &BC);

#endif // LLVM_TOOLS_LLVM_ANALYSIS_CALLGRAPH_H
