// Check that -fpseudo-probe-use-stable-guid schedules AssignGUIDPass before the
// pseudo-probe instrumentation (so functions get stable !guid metadata), and
// that it is a no-op unless requested (backwards compatible).

// Stable GUID requested: AssignGUIDPass runs right before the prober, and
// functions get !guid metadata.
// RUN: %clang_cc1 -O2 -fpseudo-probe-for-profiling -fpseudo-probe-use-stable-guid \
// RUN:   -fdebug-pass-manager -emit-llvm -o - %s 2>&1 | FileCheck %s --check-prefix=STABLE
// RUN: %clang_cc1 -O0 -fpseudo-probe-for-profiling -fpseudo-probe-use-stable-guid \
// RUN:   -fdebug-pass-manager -emit-llvm -o - %s 2>&1 | FileCheck %s --check-prefix=STABLE

// STABLE: Running pass: AssignGUIDPass
// STABLE: Running pass: SampleProfileProbePass
// STABLE: @foo({{.*}}!guid

// Default (no stable GUID): the pipeline is unchanged and no !guid is attached.
// RUN: %clang_cc1 -O2 -fpseudo-probe-for-profiling \
// RUN:   -fdebug-pass-manager -emit-llvm -o - %s 2>&1 | FileCheck %s --check-prefix=DEFAULT
// RUN: %clang_cc1 -O0 -fpseudo-probe-for-profiling \
// RUN:   -fdebug-pass-manager -emit-llvm -o - %s 2>&1 | FileCheck %s --check-prefix=DEFAULT

// DEFAULT-NOT: Running pass: AssignGUIDPass
// DEFAULT-NOT: !guid

void foo(void) {}
