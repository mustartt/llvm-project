// Coverage-via-pseudo-probe driver flag validation.

// -fcoverage-via-pseudo-probe alone implies -fcoverage-mapping and does NOT
// require -fprofile-instr-generate.
// RUN: %clang -### -S -fcoverage-via-pseudo-probe %s 2>&1 | FileCheck -check-prefix=CHECK-IMPLIES %s

// Mutually exclusive with -fprofile-instr-generate / -fprofile-generate.
// RUN: not %clang -### -S -fcoverage-via-pseudo-probe -fprofile-instr-generate %s 2>&1 | FileCheck -check-prefix=CHECK-VS-INSTR %s
// RUN: not %clang -### -S -fcoverage-via-pseudo-probe -fprofile-generate %s 2>&1 | FileCheck -check-prefix=CHECK-VS-IR %s

// Mutually exclusive with -fcoverage-mcdc.
// RUN: not %clang -### -S -fcoverage-via-pseudo-probe -fcoverage-mcdc %s 2>&1 | FileCheck -check-prefix=CHECK-VS-MCDC %s

// CHECK-IMPLIES: "-fcoverage-via-pseudo-probe"
// CHECK-IMPLIES-SAME: "-fcoverage-mapping"

// CHECK-VS-INSTR: '-fcoverage-via-pseudo-probe' not allowed with '-fprofile-instr-generate'
// CHECK-VS-IR: '-fcoverage-via-pseudo-probe' not allowed with '-fprofile-generate'
// CHECK-VS-MCDC: '-fcoverage-via-pseudo-probe' not allowed with '-fcoverage-mcdc'
