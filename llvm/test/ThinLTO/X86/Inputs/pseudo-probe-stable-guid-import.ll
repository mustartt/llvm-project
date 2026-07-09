; Importing module for pseudo-probe-stable-guid-import.ll: calls @get so that
; ThinLTO imports @get (and inlines @callee's body into it).

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define i32 @main(i32 %argc) !dbg !10 {
  %r = call i32 @get(i32 %argc), !dbg !12
  ret i32 %r, !dbg !13
}

declare i32 @get(i32)

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, emissionKind: FullDebug)
!1 = !DIFile(filename: "main.c", directory: "/x")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !DISubroutineType(types: !5)
!5 = !{null}
!10 = distinct !DISubprogram(name: "main", scope: !1, file: !1, line: 1, type: !4, unit: !0, spFlags: DISPFlagDefinition)
!12 = !DILocation(line: 1, column: 5, scope: !10)
!13 = !DILocation(line: 1, column: 1, scope: !10)
