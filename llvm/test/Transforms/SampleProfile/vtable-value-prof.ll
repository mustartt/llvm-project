; Verify that the sample profile loader attaches IPVK_VTableTarget (value kind 2)
; value profile metadata to the vtable-load instruction feeding a virtual call,
; derived from the "vtables" type samples in the profile. The annotation is the
; producer side of sample-PGO vtable devirtualization; the downstream ICP pass
; consumes it.

; RUN: opt < %s -passes=sample-profile \
; RUN:   -sample-profile-file=%S/Inputs/vtable-value-prof.prof \
; RUN:   -enable-vtable-profile-use -S | FileCheck %s

; Without -enable-vtable-profile-use, no vtable value profile is attached.
; RUN: opt < %s -passes=sample-profile \
; RUN:   -sample-profile-file=%S/Inputs/vtable-value-prof.prof -S \
; RUN:   | FileCheck %s --check-prefix=DISABLED

; CHECK-LABEL: define void @_Z3fooP4Base(
; The vtable load gets IPVK_VTableTarget (i32 2) value profile metadata, with
; the hotter vtable annotated first and the total count as the second operand.
; CHECK: %vtable = load ptr, ptr %o{{.*}}, !prof ![[VP:[0-9]+]]
; CHECK: ![[VP]] = !{!"VP", i32 2, i64 1000, i64 {{-?[0-9]+}}, i64 980, i64 {{-?[0-9]+}}, i64 20}

; DISABLED-LABEL: define void @_Z3fooP4Base(
; DISABLED-NOT: !"VP", i32 2

define void @_Z3fooP4Base(ptr %o) #0 !dbg !4 {
entry:
  %vtable = load ptr, ptr %o, !dbg !5
  %vfn = getelementptr inbounds ptr, ptr %vtable, i64 1, !dbg !5
  %0 = load ptr, ptr %vfn, !dbg !5
  tail call void %0(ptr %o), !dbg !5
  ret void
}

attributes #0 = { "use-sample-profile" }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2}

!0 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus, file: !1, producer: "clang", isOptimized: true, runtimeVersion: 0, emissionKind: LineTablesOnly)
!1 = !DIFile(filename: "vtable.cc", directory: "/tmp")
!2 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "foo", scope: !1, file: !1, line: 1, type: !6, scopeLine: 1, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0)
!5 = !DILocation(line: 2, column: 3, scope: !4)
!6 = !DISubroutineType(types: !7)
!7 = !{null}
