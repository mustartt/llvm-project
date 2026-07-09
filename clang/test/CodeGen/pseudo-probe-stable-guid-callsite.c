// Check that with -fpseudo-probe-use-stable-guid a function's callsite probes
// carry the same stable GUID as its block probes. PseudoProbeInserter must read
// the owner GUID from the function's own block probe, not recompute MD5(name).

// REQUIRES: x86-registered-target
// RUN: %clang_cc1 -triple x86_64-pc-linux-gnu -O2 -debug-info-kind=limited \
// RUN:   -fpseudo-probe-for-profiling -fpseudo-probe-use-stable-guid \
// RUN:   -S -o - %s | FileCheck %s

// "mid" is a static function with a non-inlined call, so it gets both a block
// probe (type 0) and a callsite probe (type 2). Both must carry mid's stable
// GUID; the callsite probe must not fall back to MD5("mid").
// CHECK: .pseudoprobe [[MID:[0-9]+]] 1 0 0 mid
// CHECK: .pseudoprobe [[MID]] {{[0-9]+}} 2 0 mid

static int __attribute__((noinline)) target(int x) { return x * 3; }
static int __attribute__((noinline)) mid(int x) { return target(x) + 1; }
int top(int x) { return mid(x); }
