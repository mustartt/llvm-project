; This test verifies that the guid attribute in a DISubprogram (the stable GUID
; stamped by AssignGUIDPass for pseudo-probe/AutoFDO builds) is
; assembled/disassembled correctly and survives a bitcode round-trip. A large
; value exercises the full 64-bit range.
;
; RUN: llvm-as < %s | llvm-dis | llvm-as | llvm-dis | FileCheck %s
;
; CHECK: !DISubprogram(name: "foo",{{.*}}, guid: 12345678901234567890)

define internal void @foo() !dbg !4 {
  ret void, !dbg !9
}

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, emissionKind: FullDebug)
!1 = !DIFile(filename: "test.c", directory: "")
!2 = !{i32 7, !"Dwarf Version", i32 5}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "foo", scope: !1, file: !1, line: 1, type: !5, scopeLine: 1, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !0, guid: 12345678901234567890)
!5 = !DISubroutineType(types: !6)
!6 = !{null}
!9 = !DILocation(line: 1, column: 1, scope: !4)
