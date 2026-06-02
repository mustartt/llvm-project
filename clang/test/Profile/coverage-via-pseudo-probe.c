// Verify that -fcoverage-via-pseudo-probe lowers counter increments to
// llvm.pseudoprobe, leaves @__llvm_coverage_mapping intact, and does NOT
// emit any of the InstrProf runtime sections.

// RUN: %clang_cc1 -triple x86_64-unknown-linux-gnu -main-file-name probe-coverage.c %s \
// RUN:   -O0 -debug-info-kind=line-tables-only -fcoverage-via-pseudo-probe \
// RUN:   -emit-llvm -o - | FileCheck %s

// The coverage mapping table must be preserved -- llvm-cov consumes it.
// CHECK: @__llvm_coverage_mapping {{.*}} section "{{[^"]*}}__llvm_covmap"

// No InstrProf runtime globals.
// CHECK-NOT: @__profc_
// CHECK-NOT: @__profd_
// CHECK-NOT: @__llvm_prf_nm

int g;

// CHECK-LABEL: define {{.*}} @classify
// CHECK-NOT:     call void @llvm.instrprof.
// CHECK:         call void @llvm.pseudoprobe(i64 [[CLASSIFY_GUID:-?[0-9]+]], i64 1, i32 0, i64 -1)
int classify(int x) {
  if (x < 0)
    return -1;
  if (x == 0)
    return 0;
  return 1;
}

// CHECK-LABEL: define {{.*}} @bump
// CHECK:         call void @llvm.pseudoprobe(i64 [[BUMP_GUID:-?[0-9]+]], i64 1, i32 0, i64 -1)
// CHECK-NOT:     call void @llvm.instrprof.
void bump(int n) { g += n; }

// Probe descriptors: (Guid, FunctionHash, Name).
// CHECK: !llvm.pseudo_probe_desc = !{
// CHECK-DAG: !{i64 [[CLASSIFY_GUID]], i64 {{[0-9]+}}, !"classify"}
// CHECK-DAG: !{i64 [[BUMP_GUID]], i64 {{[0-9]+}}, !"bump"}
