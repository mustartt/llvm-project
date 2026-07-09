// Check that under ThinLTO the inline-tree caller GUID for a cross-module,
// inlined-away local function (mid) is the callee's stable GUID -- read from
// its own imported probe -- and not a recomputed MD5(name). Without the fix the
// mid frame in inner's inline stack would be MD5("mid"), disagreeing with mid's
// own probe GUID.

// REQUIRES: x86-registered-target

// RUN: %clang_cc1 -triple x86_64-pc-linux-gnu -O2 -debug-info-kind=limited \
// RUN:   -dwarf-version=4 -fpseudo-probe-for-profiling -fpseudo-probe-use-stable-guid \
// RUN:   -flto=thin -emit-llvm-bc -o %t-b.bc %S/Inputs/pseudo-probe-stable-guid-thinlto.c
// RUN: %clang_cc1 -triple x86_64-pc-linux-gnu -O2 -debug-info-kind=limited \
// RUN:   -dwarf-version=4 -fpseudo-probe-for-profiling -fpseudo-probe-use-stable-guid \
// RUN:   -flto=thin -emit-llvm-bc -o %t-a.bc %s
// RUN: llvm-lto -thinlto-action=thinlink -o %t-combined.thinlto.bc %t-a.bc %t-b.bc
// RUN: %clang_cc1 -triple x86_64-pc-linux-gnu -O2 -debug-info-kind=limited \
// RUN:   -dwarf-version=4 -fpseudo-probe-for-profiling -fpseudo-probe-use-stable-guid \
// RUN:   -x ir %t-a.bc -fthinlto-index=%t-combined.thinlto.bc -S -o - | FileCheck %s

// After importing outer into bar and inlining, the emitted probes for bar
// include mid's own probe (inline stack: outer, bar -> two frames) and inner's
// probe (inline stack: mid, outer, bar -> three frames). Capture mid's own GUID
// and require inner's innermost caller frame (mid) to match it.
// CHECK: .pseudoprobe [[MID:[0-9]+]] {{[0-9]+}} 0 0 @ {{[0-9]+}}:{{[0-9]+}} @ {{[0-9]+}}:{{[0-9]+}} bar
// CHECK: .pseudoprobe {{[0-9]+}} {{[0-9]+}} 0 0 @ {{[0-9]+}}:{{[0-9]+}} @ {{[0-9]+}}:{{[0-9]+}} @ [[MID]]:{{[0-9]+}} bar

int outer(int x);
int bar(int x) { return outer(x); }
