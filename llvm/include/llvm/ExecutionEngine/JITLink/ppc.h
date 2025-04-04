//===--- ppc64.h - Generic JITLink ppc64 edge kinds, utilities --*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Generic utilities for graphs representing 64-bit PowerPC objects.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_EXECUTIONENGINE_JITLINK_PPC_H
#define LLVM_EXECUTIONENGINE_JITLINK_PPC_H

#include "llvm/ExecutionEngine/JITLink/JITLink.h"

namespace llvm::jitlink::ppc {

enum EdgeKind_ppc : Edge::Kind {
  R_POS_64 = Edge::FirstRelocation,

  // Specifies a relocation that is relative to TOC.
  R_TOC_16,

  R_RBR_26,
};

Error applyFixup(LinkGraph &G, Block &B, const Edge &E,
                        const Symbol *TOCSymobl);

const char *getEdgeKindName(Edge::Kind K);

} // namespace llvm::jitlink::ppc

#endif // LLVM_EXECUTIONENGINE_JITLINK_PPC64_H
