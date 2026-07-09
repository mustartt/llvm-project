; Stale-profile matching of an *inlined* internal-linkage callee via the callee's
; stable GUID carried on its DISubprogram. `helper` is fully inlined into
; `caller` (its standalone Function is gone), and the profile's CFGChecksum is
; deliberately wrong (stale). The matcher must still recover the inlined callsite
; anchor by reading helper's DISubprogram guid (MD5("cnt2.c;helper") =
; 5490067855611408819) -- the case where M->getFunction("helper") returns null
; and a name hash (MD5("helper") = 13097714543182145021) would not match.

; REQUIRES: asserts && x86-registered-target
; RUN: llvm-profdata merge --sample --extbinary --use-md5 --stable-guid \
; RUN:   %S/Inputs/pseudo-probe-stable-guid-stale-inline.prof -o %t.extbin
; RUN: opt < %s -passes=sample-profile -sample-profile-file=%t.extbin \
; RUN:   --salvage-stale-profile --debug-only=sample-profile-matcher -S 2>&1 | FileCheck %s

; CHECK: Run stale profile matching for caller
; CHECK: Callsite with callee:5490067855611408819 is matched from 2 to 2

source_filename = "cnt2.c"
target triple = "x86_64-unknown-linux-gnu"

define i32 @caller(i32 noundef %n) #0 !dbg !15 !guid !21 {
entry:
  call void @llvm.pseudoprobe(i64 -1768971689307247648, i64 1, i32 0, i64 -1), !dbg !23
  call void @llvm.pseudoprobe(i64 5490067855611408819, i64 1, i32 0, i64 -1), !dbg !30
  %cmp.i = icmp sgt i32 %n, 10, !dbg !32
  %mul.i = shl nuw nsw i32 %n, 1, !dbg !33
  %add.i = add nsw i32 %n, 1, !dbg !33
  %retval.0.i = select i1 %cmp.i, i32 %mul.i, i32 %add.i, !dbg !33
  call void @llvm.pseudoprobe(i64 5490067855611408819, i64 4, i32 0, i64 -1), !dbg !34
  ret i32 %retval.0.i, !dbg !35
}

declare void @llvm.pseudoprobe(i64, i64, i32, i64) #1

attributes #0 = { "use-sample-profile" }
attributes #1 = { mustprogress nocallback nofree nosync nounwind willreturn memory(inaccessiblemem: readwrite) }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}
!llvm.pseudo_probe_desc = !{!13, !14}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "clang", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "cnt2.c", directory: "/tmp")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!13 = !{i64 -1768971689307247648, i64 281479271677951, !"caller"}
!14 = !{i64 5490067855611408819, i64 72617220756, !"helper"}
!15 = distinct !DISubprogram(name: "caller", scope: !1, file: !1, line: 5, type: !16, scopeLine: 5, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !19)
!16 = !DISubroutineType(types: !17)
!17 = !{!18, !18}
!18 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!19 = !{!20}
!20 = !DILocalVariable(name: "n", arg: 1, scope: !15, file: !1, line: 5, type: !18)
!21 = !{i64 -1768971689307247648}
!22 = !DILocation(line: 0, scope: !15)
!23 = !DILocation(line: 5, column: 35, scope: !15)
!24 = !DILocalVariable(name: "x", arg: 1, scope: !25, file: !1, line: 1, type: !18)
!25 = distinct !DISubprogram(name: "helper", scope: !1, file: !1, line: 1, type: !16, scopeLine: 1, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !26, guid: 5490067855611408819)
!26 = !{!24}
!27 = !DILocation(line: 0, scope: !25, inlinedAt: !28)
!28 = distinct !DILocation(line: 5, column: 28, scope: !29)
!29 = !DILexicalBlockFile(scope: !15, file: !1, discriminator: 455082007)
!30 = !DILocation(line: 2, column: 7, scope: !31, inlinedAt: !28)
!31 = distinct !DILexicalBlock(scope: !25, file: !1, line: 2, column: 7)
!32 = !DILocation(line: 2, column: 9, scope: !31, inlinedAt: !28)
!33 = !DILocation(line: 2, column: 9, scope: !31, inlinedAt: !28)
!34 = !DILocation(line: 4, column: 1, scope: !25, inlinedAt: !28)
!35 = !DILocation(line: 5, column: 21, scope: !15)
