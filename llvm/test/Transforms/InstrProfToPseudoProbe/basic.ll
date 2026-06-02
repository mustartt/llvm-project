; RUN: opt < %s -passes=instrprof-to-pseudo-probe -S | FileCheck %s

;; Two clang-style coverage functions: one plain, one with both an increment
;; and a cover intrinsic. Verify the rewrite, the descriptor metadata, and
;; the cleanup of __profn_* name globals.

;; The __profn_* globals carry function names that
;; Function::getGUIDAssumingExternalLinkage hashes into the probe GUID.

; CHECK-NOT: @__profn_classify
; CHECK-NOT: @__profn_sum_to

;; @__llvm_coverage_mapping must be preserved -- llvm-cov needs it.
; CHECK: @__llvm_coverage_mapping = private constant
@__profn_classify = private constant [8 x i8] c"classify"
@__profn_sum_to = private constant [6 x i8] c"sum_to"

@__llvm_coverage_mapping = private constant [4 x i8] c"abcd", section "__LLVM_COV,__llvm_covmap", align 8

define i32 @classify(i32 %x) !dbg !6 {
; CHECK-LABEL: define i32 @classify(
; CHECK-NOT:     call void @llvm.instrprof.increment
;; Probe id == counter index + 1 (PseudoProbe ids are 1-based).
; CHECK:         call void @llvm.pseudoprobe(i64 [[CLASSIFY_GUID:-?[0-9]+]], i64 1, i32 0, i64 -1)
entry:
  call void @llvm.instrprof.increment(ptr @__profn_classify, i64 1234, i32 3, i32 0), !dbg !10
  %cmp = icmp slt i32 %x, 0
  br i1 %cmp, label %neg, label %nonneg, !dbg !10

neg:
; CHECK:         call void @llvm.pseudoprobe(i64 [[CLASSIFY_GUID]], i64 2, i32 0, i64 -1)
  call void @llvm.instrprof.increment(ptr @__profn_classify, i64 1234, i32 3, i32 1), !dbg !11
  ret i32 -1

nonneg:
; CHECK:         call void @llvm.pseudoprobe(i64 [[CLASSIFY_GUID]], i64 3, i32 0, i64 -1)
  call void @llvm.instrprof.increment(ptr @__profn_classify, i64 1234, i32 3, i32 2), !dbg !12
  ret i32 1
}

define i32 @sum_to(i32 %n) !dbg !7 {
; CHECK-LABEL: define i32 @sum_to(
;; instrprof.cover and instrprof.increment.step get rewritten the same way
;; as instrprof.increment. The step value on increment.step is dropped --
;; coverage only needs to know the region executed.
; CHECK:         call void @llvm.pseudoprobe(i64 [[SUM_GUID:-?[0-9]+]], i64 1, i32 0, i64 -1)
; CHECK:         call void @llvm.pseudoprobe(i64 [[SUM_GUID]], i64 2, i32 0, i64 -1)
entry:
  call void @llvm.instrprof.cover(ptr @__profn_sum_to, i64 5678, i32 2, i32 0), !dbg !13
  br label %loop

loop:
  call void @llvm.instrprof.increment.step(ptr @__profn_sum_to, i64 5678, i32 2, i32 1, i64 7), !dbg !14
  ret i32 %n
}

;; Probe descriptor metadata for the two rewritten functions: the (Guid, Hash,
;; Name) tuple. Hash should be the CFG hash from operand 1 of the increment.
; CHECK: !llvm.pseudo_probe_desc = !{![[CLASSIFY_DESC:[0-9]+]], ![[SUM_DESC:[0-9]+]]}
; CHECK-DAG: ![[CLASSIFY_DESC]] = !{i64 [[CLASSIFY_GUID]], i64 1234, !"classify"}
; CHECK-DAG: ![[SUM_DESC]] = !{i64 [[SUM_GUID]], i64 5678, !"sum_to"}

declare void @llvm.instrprof.increment(ptr, i64, i32, i32)
declare void @llvm.instrprof.increment.step(ptr, i64, i32, i32, i64)
declare void @llvm.instrprof.cover(ptr, i64, i32, i32)

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3, !4}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug)
!1 = !DIFile(filename: "t.c", directory: "/")
!3 = !{i32 2, !"Dwarf Version", i32 4}
!4 = !{i32 2, !"Debug Info Version", i32 3}
!5 = !DISubroutineType(types: !{})
!6 = distinct !DISubprogram(name: "classify", scope: !1, file: !1, line: 1, type: !5, scopeLine: 1, spFlags: DISPFlagDefinition, unit: !0)
!7 = distinct !DISubprogram(name: "sum_to", scope: !1, file: !1, line: 5, type: !5, scopeLine: 5, spFlags: DISPFlagDefinition, unit: !0)
!10 = !DILocation(line: 1, column: 1, scope: !6)
!11 = !DILocation(line: 2, column: 1, scope: !6)
!12 = !DILocation(line: 3, column: 1, scope: !6)
!13 = !DILocation(line: 5, column: 1, scope: !7)
!14 = !DILocation(line: 6, column: 1, scope: !7)
