; RUN: opt -S -passes=assign-guid %s | FileCheck %s

@G = global i32 0
; CHECK: @G = global i32 0, !guid ![[GGUID:[0-9]+]]
@G_EXT = external global i32

declare external void @f_ext()

@A = alias i32, ptr @G
@A_EXT = external alias i32, ptr @G

define void @f() {
; CHECK: define void @f() !guid ![[FGUID:[0-9]+]] {
  ret void
}

; A function with debug info gets its GUID mirrored onto its DISubprogram's
; guid: field (matching the !guid metadata value), so inlined callee frames can
; be identified by GUID after the function itself is gone.
define void @dbg() !dbg !4 {
; CHECK: define void @dbg() !dbg ![[#]] !guid ![[DBGGUID:[0-9]+]] {
  ret void
}

; CHECK-DAG: ![[GGUID]] = !{i64 -6455552227143004193}
; CHECK-DAG: ![[FGUID]] = !{i64 -3706093650706652785}
; CHECK-DAG: ![[DBGGUID]] = !{i64 [[#DBGVAL:]]}
; The DISubprogram carries the same GUID value.
; CHECK-DAG: !DISubprogram(name: "dbg",{{.*}} guid: [[#DBGVAL]])

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, emissionKind: FullDebug)
!1 = !DIFile(filename: "test.c", directory: "")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "dbg", scope: !1, file: !1, line: 1, type: !5, scopeLine: 1, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0)
!5 = !DISubroutineType(types: !6)
!6 = !{null}

