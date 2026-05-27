; Verifies that the MachineBlockProbeInserter pass inserts one PSEUDO_PROBE
; of type 3 (MachineBlock) at every MachineBasicBlock entry, and that
; switch lowering produces additional MBBs that all receive a probe.

; RUN: llc -mtriple=arm64-apple-macos -enable-machine-block-probes -O0 \
; RUN:   -stop-after=machine-block-probe-inserter %s -o - | FileCheck %s

; RUN: llc -mtriple=arm64-apple-macos -O0 \
; RUN:   -stop-after=machine-block-probe-inserter %s -o - | FileCheck %s --check-prefix=DISABLED

; The pass emits a per-function descriptor with the MIR CFG hash so
; the loader can detect staleness. The declaration appears before the
; definition in the dumped MIR, so check in that order.
; CHECK: !llvm.machine_pseudo_probe_desc = !{![[DESC:[0-9]+]]}
; CHECK: ![[DESC]] = !{i64 [[GUID:[0-9]+]], i64 {{[0-9]+}}, !"sw"}

; Each MBB starts with a PSEUDO_PROBE of type 3 (MachineBlock). The switch
; lowers into multiple MBBs at -O0; each of them is anchored. The function
; produces 9 MBBs (1 entry + 3 split MBBs from the switch comparison chain
; + 5 case-body MBBs), and we expect exactly 9 MachineBlock probes
; sharing one GUID.
; CHECK-LABEL: name: sw
; CHECK-COUNT-9: PSEUDO_PROBE [[GUID]], {{[0-9]+}}, 3, 0
; CHECK-NOT: PSEUDO_PROBE {{[0-9]+}}, {{[0-9]+}}, 3, 0

; Without the flag, no MachineBlock probes (type 3) are emitted, and no
; machine descriptor is created.
; DISABLED-NOT: PSEUDO_PROBE {{.*}}, 3, 0
; DISABLED-NOT: llvm.machine_pseudo_probe_desc

define i32 @sw(i32 %x) !dbg !6 {
entry:
  switch i32 %x, label %def [
    i32 0, label %c0
    i32 1, label %c1
    i32 2, label %c2
    i32 3, label %c3
  ], !dbg !9
c0:
  ret i32 10, !dbg !9
c1:
  ret i32 20, !dbg !9
c2:
  ret i32 30, !dbg !9
c3:
  ret i32 40, !dbg !9
def:
  ret i32 -1, !dbg !9
}

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}
!llvm.pseudo_probe_desc = !{!10}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang", emissionKind: FullDebug)
!1 = !DIFile(filename: "test.c", directory: "/tmp")
!2 = !{i32 7, !"Dwarf Version", i32 4}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!6 = distinct !DISubprogram(name: "sw", linkageName: "sw", scope: !1, file: !1, line: 1, type: !7, scopeLine: 1, spFlags: DISPFlagDefinition, unit: !0)
!7 = !DISubroutineType(types: !8)
!8 = !{}
!9 = !DILocation(line: 2, column: 1, scope: !6)
!10 = !{i64 1234, i64 0, !"sw"}
