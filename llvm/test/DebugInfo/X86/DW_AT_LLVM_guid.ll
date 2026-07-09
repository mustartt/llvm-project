;; Check that DW_AT_LLVM_guid is emitted onto subprogram DIEs of internal-
;; linkage functions when a module is built with pseudo probes (i.e. it has an
;; !llvm.pseudo_probe_desc), and that the value matches the function's !guid
;; metadata. External-linkage functions do not get the attribute (their GUID is
;; MD5(name) and is recomputable from the name).

; RUN: llc -mtriple=x86_64-unknown-linux-gnu -filetype=obj -o %t %s
; RUN: llvm-dwarfdump -debug-info %t | FileCheck %s

;; Without the pseudo-probe marker the attribute is not emitted.
; RUN: sed '/llvm.pseudo_probe_desc/d' %s \
; RUN:   | llc -mtriple=x86_64-unknown-linux-gnu -filetype=obj -o %t.noprobe
; RUN: llvm-dwarfdump -debug-info %t.noprobe | FileCheck %s --check-prefix=NOPROBE

;; The internal-linkage function "foo" carries the attribute.
; CHECK: DW_TAG_subprogram
;; 0xa1b2c104aa3a9718 == -6795156661968660712 (the !guid below).
; CHECK: DW_AT_LLVM_guid (0xa1b2c104aa3a9718)
; CHECK: DW_AT_name{{.*}}"foo"

;; The external-linkage function "bar" does not.
; CHECK: DW_TAG_subprogram
; CHECK-NOT: DW_AT_LLVM_guid (
; CHECK: DW_AT_name{{.*}}"bar"

; NOPROBE-NOT: DW_AT_LLVM_guid (

define internal void @foo() !dbg !8 !guid !13 {
entry:
  ret void, !dbg !12
}

define dso_local void @bar() !dbg !14 !guid !15 {
entry:
  ret void, !dbg !16
}

!llvm.dbg.cu = !{!0}
!llvm.pseudo_probe_desc = !{}
!llvm.module.flags = !{!2, !3, !4}
!llvm.ident = !{!7}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "clang", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "test.c", directory: "")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = !{i32 1, !"wchar_size", i32 4}
!7 = !{!"clang"}
!8 = distinct !DISubprogram(name: "foo", scope: !1, file: !1, line: 1, type: !9, scopeLine: 1, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, retainedNodes: !11)
!9 = !DISubroutineType(types: !10)
!10 = !{null}
!11 = !{}
!12 = !DILocation(line: 1, column: 13, scope: !8)
!13 = !{i64 -6795156661968660712}
!14 = distinct !DISubprogram(name: "bar", scope: !1, file: !1, line: 2, type: !9, scopeLine: 2, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !11)
!15 = !{i64 1234567890}
!16 = !DILocation(line: 2, column: 13, scope: !14)
