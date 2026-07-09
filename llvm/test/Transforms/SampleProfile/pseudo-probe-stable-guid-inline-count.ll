; Check that in stable-GUID mode the sample loader attributes counts to the
; probes of an *inlined* internal-linkage callee by resolving the inlined frame
; via the callee's stable GUID (read from its own block probe), not by hashing
; the debug name. The profile's inlined "helper" node is keyed by helper's stable
; GUID MD5("cnt2.c;helper") = 5490067855611408819, which differs from
; MD5("helper") = 13097714543182145021, so a name-based lookup would miss and no
; samples would be applied to the inlined body.

; REQUIRES: x86-registered-target
; RUN: llvm-profdata merge --sample --extbinary --use-md5 --stable-guid \
; RUN:   %S/Inputs/pseudo-probe-stable-guid-inline-count.prof -o %t.extbin
; RUN: opt < %s -passes=sample-profile -sample-profile-file=%t.extbin \
; RUN:   -pass-remarks-output=%t.yaml -S -o /dev/null
; RUN: FileCheck %s < %t.yaml

; caller's own probe 1 gets the head samples...
; CHECK:      Name:            AppliedSamples
; CHECK:      Function:        caller
; CHECK:        - NumSamples:      '1000'
; CHECK:        - ProbeId:         '1'
; ...and the inlined helper's probes 1 and 4 get their samples, proving the
; inlined frame matched by GUID.
; CHECK:      Name:            AppliedSamples
; CHECK:      Function:        caller
; CHECK:        - NumSamples:      '200'
; CHECK:        - ProbeId:         '1'
; CHECK:      Name:            AppliedSamples
; CHECK:      Function:        caller
; CHECK:        - NumSamples:      '200'
; CHECK:        - ProbeId:         '4'

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
