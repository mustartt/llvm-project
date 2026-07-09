; FullLTO: two same-named internal-linkage functions ("helper" from a.c and b.c,
; renamed helper/helper.1 by the linker) carry distinct stable guids on their
; DISubprograms. After the post-link O2 inline, each caller's inlined body must
; carry ITS OWN callee's guid on the pseudo probes -- proving same-named statics
; stay disambiguated by GUID through cross-module inlining (where name-based
; identity would collapse them).

; RUN: opt -passes='default<O2>' %s -S -o - | FileCheck %s

; Both same-named statics are inlined and each inlined body keeps ITS OWN guid on
; the pseudo probes (111 for a.c's helper, 222 for b.c's helper) -- the two are
; never conflated, which name-based identity could not guarantee.
; CHECK-DAG: call void @llvm.pseudoprobe(i64 111,
; CHECK-DAG: call void @llvm.pseudoprobe(i64 222,

target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define i32 @use_a(i32 %x) !dbg !10 {
  call void @llvm.pseudoprobe(i64 100, i64 1, i32 0, i64 -1), !dbg !13
  %r = call i32 @helper(i32 %x), !dbg !13
  ret i32 %r, !dbg !14
}
define i32 @use_b(i32 %x) !dbg !20 {
  call void @llvm.pseudoprobe(i64 200, i64 1, i32 0, i64 -1), !dbg !23
  %r = call i32 @helper.1(i32 %x), !dbg !23
  ret i32 %r, !dbg !24
}
define internal i32 @helper(i32 %x) !dbg !11 !guid !15 {
  call void @llvm.pseudoprobe(i64 111, i64 1, i32 0, i64 -1), !dbg !12
  %a = add i32 %x, 1, !dbg !12
  ret i32 %a, !dbg !12
}
define internal i32 @helper.1(i32 %x) !dbg !21 !guid !25 {
  call void @llvm.pseudoprobe(i64 222, i64 1, i32 0, i64 -1), !dbg !22
  %a = mul i32 %x, 2, !dbg !22
  ret i32 %a, !dbg !22
}
declare void @llvm.pseudoprobe(i64, i64, i32, i64)

!llvm.dbg.cu = !{!0, !2}
!llvm.module.flags = !{!3, !4}
!llvm.pseudo_probe_desc = !{!30, !31, !32, !33}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, emissionKind: FullDebug)
!1 = !DIFile(filename: "a.c", directory: "/x")
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !5, emissionKind: FullDebug)
!5 = !DIFile(filename: "b.c", directory: "/x")
!3 = !{i32 7, !"Dwarf Version", i32 5}
!4 = !{i32 2, !"Debug Info Version", i32 3}
!6 = !DISubroutineType(types: !7)
!7 = !{null}
!10 = distinct !DISubprogram(name: "use_a", scope: !1, file: !1, line: 2, type: !6, unit: !0, spFlags: DISPFlagDefinition)
!11 = distinct !DISubprogram(name: "helper", scope: !1, file: !1, line: 1, type: !6, unit: !0, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, guid: 111)
!12 = !DILocation(line: 1, column: 1, scope: !11)
!13 = !DILocation(line: 2, column: 5, scope: !10)
!14 = !DILocation(line: 2, column: 1, scope: !10)
!15 = !{i64 111}
!20 = distinct !DISubprogram(name: "use_b", scope: !5, file: !5, line: 2, type: !6, unit: !2, spFlags: DISPFlagDefinition)
!21 = distinct !DISubprogram(name: "helper", scope: !5, file: !5, line: 1, type: !6, unit: !2, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, guid: 222)
!22 = !DILocation(line: 1, column: 1, scope: !21)
!23 = !DILocation(line: 2, column: 5, scope: !20)
!24 = !DILocation(line: 2, column: 1, scope: !20)
!25 = !{i64 222}
!30 = !{i64 100, i64 4294967295, !"use_a"}
!31 = !{i64 111, i64 4294967295, !"helper"}
!32 = !{i64 200, i64 4294967295, !"use_b"}
!33 = !{i64 222, i64 4294967295, !"helper"}
