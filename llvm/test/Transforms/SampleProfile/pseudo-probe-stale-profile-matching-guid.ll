; Check that stale-profile matching uses stable GUIDs as callsite anchors so a
; same-named internal-linkage callee (static "helper") is matched even though
; the profile is stale (checksum mismatch). Without GUID anchors the callee
; anchor would be MD5("helper") and would not match the profile's GUID.

; REQUIRES: asserts && x86-registered-target
; RUN: llvm-profdata merge --sample --extbinary --use-md5 --stable-guid \
; RUN:   %S/Inputs/pseudo-probe-stale-profile-matching-guid.prof -o %t.extbin
; RUN: opt < %s -passes=sample-profile -sample-profile-file=%t.extbin \
; RUN:   --salvage-stale-profile --debug-only=sample-profile-matcher -S 2>&1 | FileCheck %s

; The profile is keyed by stable GUIDs; helper (static) has GUID
; MD5("stale.c;helper") = 12134428303565701041. Its callsite (probe 5) is
; matched as an anchor via that GUID.
; CHECK: Run stale profile matching for caller
; CHECK: Callsite with callee:12134428303565701041 is matched from 5 to 5

source_filename = "stale.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

define dso_local i32 @caller(i32 noundef %x) local_unnamed_addr #0 !dbg !12 {
entry:
  call void @llvm.pseudoprobe(i64 -1768971689307247648, i64 1, i32 0, i64 -1), !dbg !24
  call void @llvm.pseudoprobe(i64 -1768971689307247648, i64 2, i32 0, i64 -1), !dbg !26
  %cmp4 = icmp sgt i32 %x, 0, !dbg !28
  br i1 %cmp4, label %for.body, label %for.cond.cleanup, !dbg !29

for.cond.cleanup:                                 ; preds = %for.body, %entry
  %s.0.lcssa = phi i32 [ 0, %entry ], [ %add, %for.body ], !dbg !23
  call void @llvm.pseudoprobe(i64 -1768971689307247648, i64 3, i32 0, i64 -1), !dbg !23
  call void @llvm.pseudoprobe(i64 -1768971689307247648, i64 7, i32 0, i64 -1), !dbg !30
  ret i32 %s.0.lcssa, !dbg !31

for.body:                                         ; preds = %entry, %for.body
  %i.06 = phi i32 [ %inc, %for.body ], [ 0, %entry ]
  %s.05 = phi i32 [ %add, %for.body ], [ 0, %entry ]
  call void @llvm.pseudoprobe(i64 -1768971689307247648, i64 4, i32 0, i64 -1), !dbg !32
  %call = tail call fastcc i32 @helper(i32 noundef %i.06), !dbg !33
  %add = add nsw i32 %call, %s.05, !dbg !35
  call void @llvm.pseudoprobe(i64 -1768971689307247648, i64 6, i32 0, i64 -1), !dbg !36
  %inc = add nuw nsw i32 %i.06, 1, !dbg !36
  call void @llvm.pseudoprobe(i64 -1768971689307247648, i64 2, i32 0, i64 -1), !dbg !26
  %exitcond.not = icmp eq i32 %inc, %x, !dbg !28
  br i1 %exitcond.not, label %for.cond.cleanup, label %for.body, !dbg !29, !llvm.loop !37
}

define internal fastcc i32 @helper(i32 noundef %x) unnamed_addr #1 !dbg !40 {
entry:
  call void @llvm.pseudoprobe(i64 8793926584754069449, i64 1, i32 0, i64 -1), !dbg !45
  %add = add nsw i32 %x, 1, !dbg !46
  ret i32 %add, !dbg !47
}

declare void @llvm.pseudoprobe(i64, i64, i32, i64) #2

attributes #0 = { "use-sample-profile" nofree norecurse nosync nounwind memory(none) }
attributes #1 = { "use-sample-profile" mustprogress nofree noinline norecurse nosync nounwind willreturn memory(none) }
attributes #2 = { mustprogress nocallback nofree nosync nounwind willreturn memory(inaccessiblemem: readwrite) }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}
!llvm.pseudo_probe_desc = !{!10, !11}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "clang", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "stale.c", directory: "")
!2 = !{i32 2, !"Debug Info Version", i32 3}
!3 = !{i32 7, !"debug-info-assignment-tracking", i1 true}
!10 = !{i64 -1768971689307247648, i64 281582264815352, !"caller"}
!11 = !{i64 8793926584754069449, i64 4294967295, !"helper"}
!12 = distinct !DISubprogram(name: "caller", scope: !13, file: !13, line: 2, type: !14, scopeLine: 2, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !17)
!13 = !DIFile(filename: "stale.c", directory: "")
!14 = !DISubroutineType(types: !15)
!15 = !{!16, !16}
!16 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!17 = !{!18, !19, !20}
!18 = !DILocalVariable(name: "x", arg: 1, scope: !12, file: !13, line: 2, type: !16)
!19 = !DILocalVariable(name: "s", scope: !12, file: !13, line: 3, type: !16)
!20 = !DILocalVariable(name: "i", scope: !21, file: !13, line: 4, type: !16)
!21 = distinct !DILexicalBlock(scope: !12, file: !13, line: 4, column: 3)
!23 = !DILocation(line: 0, scope: !12)
!24 = !DILocation(line: 3, column: 7, scope: !12)
!25 = !DILocation(line: 0, scope: !21)
!26 = !DILocation(line: 4, column: 19, scope: !27)
!27 = distinct !DILexicalBlock(scope: !21, file: !13, line: 4, column: 3)
!28 = !DILocation(line: 4, column: 21, scope: !27)
!29 = !DILocation(line: 4, column: 3, scope: !21)
!30 = !DILocation(line: 5, column: 10, scope: !12)
!31 = !DILocation(line: 5, column: 3, scope: !12)
!32 = !DILocation(line: 4, column: 43, scope: !27)
!33 = !DILocation(line: 4, column: 36, scope: !34)
!34 = !DILexicalBlockFile(scope: !27, file: !13, discriminator: 455082031)
!35 = !DILocation(line: 4, column: 33, scope: !27)
!36 = !DILocation(line: 4, column: 27, scope: !27)
!37 = distinct !{!37, !29, !38, !39}
!38 = !DILocation(line: 4, column: 44, scope: !21)
!39 = !{!"llvm.loop.mustprogress"}
!40 = distinct !DISubprogram(name: "helper", scope: !13, file: !13, line: 1, type: !14, scopeLine: 1, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !41)
!41 = !{!42}
!42 = !DILocalVariable(name: "x", arg: 1, scope: !40, file: !13, line: 1, type: !16)
!45 = !DILocation(line: 1, column: 61, scope: !40)
!46 = !DILocation(line: 1, column: 63, scope: !40)
!47 = !DILocation(line: 1, column: 54, scope: !40)
