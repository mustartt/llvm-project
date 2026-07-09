; Check that when a function carries stable !guid metadata (as attached by
; AssignGUIDPass / -fpseudo-probe-use-stable-guid), the pseudo-probe prober
; identifies it by that GUID in both the probe intrinsic and the descriptor,
; instead of hashing the debug name.

; RUN: opt < %s -passes=pseudo-probe -S -o - | FileCheck %s

; The probe intrinsic uses the assigned GUID (1234567890), not MD5("foo").
; CHECK: call void @llvm.pseudoprobe(i64 1234567890, i64 1, i32 0, i64 -1)
; The descriptor carries the same GUID, keyed by the debug name "foo".
; CHECK: !{i64 1234567890, i64 {{[0-9]+}}, !"foo"}
; CHECK-NOT: !{i64 6699318081062747564,

define dso_local void @foo() !dbg !4 !guid !10 {
entry:
  ret void, !dbg !9
}

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "clang", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug)
!1 = !DIFile(filename: "test.c", directory: "")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "foo", scope: !1, file: !1, line: 1, type: !5, scopeLine: 1, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !8)
!5 = !DISubroutineType(types: !6)
!6 = !{null}
!8 = !{}
!9 = !DILocation(line: 1, column: 13, scope: !4)
!10 = !{i64 1234567890}
