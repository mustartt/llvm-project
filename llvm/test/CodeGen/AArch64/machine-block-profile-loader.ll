; Verifies that the MachineBlockProfileLoader updates MBB successor
; probabilities based on a MachineBlock-keyed text profile keyed by the
; MIR CFG hash, and falls back to the static probabilities when the
; hash mismatches.

; RUN: rm -rf %t && mkdir -p %t

; The MIR CFG hash below is the value MachineBlockProbeInserter computes
; for this function at -O2 on AArch64. If ISel or pre-MBP MIR transforms
; change the post-ISel CFG, this constant will need to be regenerated:
;   llc -mtriple=arm64-apple-macos -enable-machine-block-probes -O2 \
;     -stop-after=machine-block-probe-inserter test.ll | \
;     grep machine_pseudo_probe_desc

; Probe IDs (RPO order): 1=entry, 2=loop.head, 3=loop.exit, 4=loop.body.

; Write a hot-edge-flipped profile: loop.head→exit hot, loop.head→body cold.
; RUN: echo 'loop:71729178078:'  > %t/p.txt
; RUN: echo '  1:2:1010'         >> %t/p.txt
; RUN: echo '  2:4:10'           >> %t/p.txt
; RUN: echo '  2:3:1000'         >> %t/p.txt
; RUN: echo '  4:2:10'           >> %t/p.txt

; Same edges with the wrong MIR CFG hash to exercise staleness fallback.
; RUN: echo 'loop:9999999999:'   > %t/stale.txt
; RUN: echo '  1:2:1010'         >> %t/stale.txt
; RUN: echo '  2:4:10'           >> %t/stale.txt
; RUN: echo '  2:3:1000'         >> %t/stale.txt
; RUN: echo '  4:2:10'           >> %t/stale.txt

; Apply the matching-hash profile and check that the loop.head block
; now favours the exit edge.
; RUN: llc -mtriple=arm64-apple-macos -enable-machine-block-probes -O2 \
; RUN:    -machine-block-profile-file=%t/p.txt \
; RUN:    -stop-after=machine-block-profile-loader %s -o - \
; RUN:  | FileCheck %s --check-prefix=APPLIED

; APPLIED-LABEL: name: loop
; APPLIED:       bb.1.loop.head:
; APPLIED:         successors: %bb.2(0x0{{[0-9a-f]+}}), %bb.3(0x7{{[0-9a-f]+}})

; With a stale hash, the static probabilities (loop.head→loop.body hot)
; remain in place.
; RUN: llc -mtriple=arm64-apple-macos -enable-machine-block-probes -O2 \
; RUN:    -machine-block-profile-file=%t/stale.txt \
; RUN:    -stop-after=machine-block-profile-loader %s -o - \
; RUN:  | FileCheck %s --check-prefix=STALE

; STALE-LABEL: name: loop
; STALE:       bb.1.loop.head:
; STALE:         successors: %bb.2(0x7{{[0-9a-f]+}}), %bb.3(0x0{{[0-9a-f]+}})

define i32 @loop(i32 %n) !dbg !6 {
entry:
  br label %loop.head, !dbg !9
loop.head:
  %i = phi i32 [ 0, %entry ], [ %i.next, %loop.body.tail ], !dbg !9
  %sum = phi i32 [ 0, %entry ], [ %sum.next, %loop.body.tail ], !dbg !9
  %cond = icmp slt i32 %i, %n, !dbg !9
  br i1 %cond, label %loop.body, label %loop.exit, !dbg !9
loop.body:
  %is.even = and i32 %i, 1, !dbg !9
  %even.cmp = icmp eq i32 %is.even, 0, !dbg !9
  br i1 %even.cmp, label %even.case, label %odd.case, !dbg !9
even.case:
  %s.even = add i32 %sum, %i, !dbg !9
  br label %loop.body.tail, !dbg !9
odd.case:
  %s.odd = sub i32 %sum, %i, !dbg !9
  br label %loop.body.tail, !dbg !9
loop.body.tail:
  %sum.next = phi i32 [ %s.even, %even.case ], [ %s.odd, %odd.case ], !dbg !9
  %i.next = add i32 %i, 1, !dbg !9
  br label %loop.head, !dbg !9
loop.exit:
  ret i32 %sum, !dbg !9
}

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}
!llvm.pseudo_probe_desc = !{!10}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang", emissionKind: FullDebug)
!1 = !DIFile(filename: "test.c", directory: "/tmp")
!2 = !{i32 7, !"Dwarf Version", i32 4}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!6 = distinct !DISubprogram(name: "loop", linkageName: "loop", scope: !1, file: !1, line: 1, type: !7, scopeLine: 1, spFlags: DISPFlagDefinition, unit: !0)
!7 = !DISubroutineType(types: !8)
!8 = !{}
!9 = !DILocation(line: 2, column: 1, scope: !6)
!10 = !{i64 4301832329306344420, i64 4242, !"loop"}
