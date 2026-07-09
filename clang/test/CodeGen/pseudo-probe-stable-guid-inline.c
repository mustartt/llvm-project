// Check that with -fpseudo-probe-use-stable-guid the inline-tree caller GUIDs
// emitted by PseudoProbePrinter stay consistent with the callee's own probe
// GUID: the prober now identifies functions by their stable GUID, and the
// inline tree reads that same GUID back from the probe descriptor rather than
// recomputing MD5(name).

// REQUIRES: x86-registered-target
// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -O2 \
// RUN:   -fpseudo-probe-for-profiling -fpseudo-probe-use-stable-guid \
// RUN:   -debug-info-kind=line-tables-only -S -o - %s | FileCheck %s

// "caller" has external linkage, so its stable GUID is MD5("caller") =
// 16677772384402303968 (no file prefix).
// CHECK: .pseudoprobe 16677772384402303968 {{[0-9]+}} 0 0 caller

// "callee" is a static inlined into "caller". Its probe carries callee's own
// (file-folded, i.e. != MD5("callee")) GUID, and its inline stack references
// the caller by caller's GUID -- the same value as caller's own probe above.
// CHECK: .pseudoprobe {{[0-9]+}} {{[0-9]+}} 0 0 @ 16677772384402303968:{{[0-9]+}} caller

static int __attribute__((always_inline)) callee(int x) { return x + 1; }
int caller(int x) { return callee(x); }
