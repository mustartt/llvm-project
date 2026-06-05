; RUN: opt -passes='require<profile-summary>,function(codegenprepare)' -mtriple=aarch64 -S < %s \
; RUN:   | FileCheck %s --check-prefix=OFF
; RUN: opt -passes='require<profile-summary>,function(codegenprepare)' -mtriple=aarch64 \
; RUN:   -cgp-sink-diamond-loads -cgp-sink-diamond-loads-force -S < %s \
; RUN:   | FileCheck %s --check-prefix=FORCE
; RUN: opt -passes='require<profile-summary>,function(codegenprepare)' -mtriple=aarch64 \
; RUN:   -cgp-sink-diamond-loads -S < %s | FileCheck %s --check-prefix=HEUR

; The load %v in for.body dominates a diamond and is consumed in both arms
; (the store in %then and the reduction chain in %els). SimplifyCFG hoisted it
; up here, stretching its live range across the branch. With
; -cgp-sink-diamond-loads it is cloned into each arm and erased from for.body.
; The default heuristic additionally requires a loop and a deep consumer chain
; (present here); -force skips the heuristic.

define double @reduce(ptr %p, i32 %n) {
; OFF-LABEL: @reduce(
; OFF:       for.body:
; OFF:         load double, ptr %p
; OFF:       then:
; OFF-NOT:     load double
; OFF:       els:
; OFF-NOT:     load double
;
; FORCE-LABEL: @reduce(
; FORCE:       for.body:
; FORCE-NOT:     %v = load double
; FORCE:       then:
; FORCE:         load double, ptr %p
; FORCE:       els:
; FORCE:         load double, ptr %p
;
; HEUR-LABEL:  @reduce(
; HEUR:        for.body:
; HEUR-NOT:      %v = load double
; HEUR:        then:
; HEUR:          load double, ptr %p
; HEUR:        els:
; HEUR:          load double, ptr %p
entry:
  br label %for.body

for.body:
  %i = phi i32 [ 0, %entry ], [ %i.next, %latch ]
  %v = load double, ptr %p, align 8
  %c = icmp eq i32 %i, 7
  br i1 %c, label %then, label %els

then:
  store double %v, ptr %p, align 8
  br label %latch

els:
  %a = fadd double %v, 1.000000e+00
  %b = fadd double %a, 1.000000e+00
  %d = fadd double %b, 1.000000e+00
  %e = fadd double %d, 1.000000e+00
  store double %e, ptr %p, align 8
  br label %latch

latch:
  %i.next = add i32 %i, 1
  %cmp = icmp slt i32 %i.next, %n
  br i1 %cmp, label %for.body, label %exit

exit:
  ret double 0.000000e+00
}
