; Verify that a DISubprogram's stable `guid` survives ThinLTO import. `callee`
; is an internal function that is imported/inlined across modules; ThinLTO
; promotes/renames it (callee.llvm.N) but its DISubprogram must retain the
; original stable guid so the sample loader still identifies the frame by GUID
; rather than by the (renamed) name. The guid is the authoritative identity that
; a same-named static in another TU could not be confused with.

; RUN: opt -module-summary %s -o %t1.bc
; RUN: opt -module-summary %p/Inputs/pseudo-probe-stable-guid-import.ll -o %t2.bc
; RUN: llvm-lto -thinlto-action=thinlink -o %t.index.bc %t1.bc %t2.bc
; RUN: llvm-lto -thinlto-action=import %t2.bc -thinlto-index=%t.index.bc -o - \
; RUN:   | llvm-dis -o - | FileCheck %s

; The callee is imported (possibly promoted/renamed), and its DISubprogram keeps
; the original stable guid unchanged.
; CHECK: !DISubprogram(name: "callee",{{.*}} guid: 1122334455667788990)

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define i32 @get(i32 %x) !dbg !10 {
  %r = call i32 @callee(i32 %x), !dbg !13
  ret i32 %r, !dbg !14
}

define internal i32 @callee(i32 %x) !dbg !11 !guid !15 {
  call void @llvm.pseudoprobe(i64 1122334455667788990, i64 1, i32 0, i64 -1), !dbg !12
  %a = add i32 %x, 1, !dbg !12
  ret i32 %a, !dbg !12
}

declare void @llvm.pseudoprobe(i64, i64, i32, i64)

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}
!llvm.pseudo_probe_desc = !{!16}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, emissionKind: FullDebug)
!1 = !DIFile(filename: "lib.c", directory: "/x")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !DISubroutineType(types: !5)
!5 = !{null}
!10 = distinct !DISubprogram(name: "get", scope: !1, file: !1, line: 2, type: !4, unit: !0, spFlags: DISPFlagDefinition)
!11 = distinct !DISubprogram(name: "callee", scope: !1, file: !1, line: 1, type: !4, unit: !0, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, guid: 1122334455667788990)
!12 = !DILocation(line: 1, column: 1, scope: !11)
!13 = !DILocation(line: 2, column: 5, scope: !10)
!14 = !DILocation(line: 2, column: 1, scope: !10)
!15 = !{i64 1122334455667788990}
!16 = !{i64 1122334455667788990, i64 4294967295, !"callee"}
