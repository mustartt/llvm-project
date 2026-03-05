; RUN: llc -mtriple=arm64-apple-macos -o - %s | FileCheck %s

; Test that tail duplication works correctly in the presence of EH edges.
; The TailDuplicator should allow duplication into predecessors that have
; EH pad successors (landing pads), since the EH edge should not prevent
; profitable tail duplication.

declare void @bar()
declare void @baz()
declare void @__clang_call_terminate(ptr)
declare i32 @__gxx_personality_v0(...)

;; Test 1: Basic noexcept tail duplication
;; Source:
;;   void bar();
;;   bool foo(int num) noexcept {
;;       if (num > 10) { bar(); return false; }
;;       return true;
;;   }
;;
;; The return block should be tail-duplicated into invoke.cont, even though
;; if.then has an EH successor (terminate.lpad). This eliminates the branch
;; from invoke.cont to return.

; CHECK-LABEL: _tail_dup_noexcept:
; CHECK:         cmp w0, #11
; CHECK-NEXT:    b.lt [[RET_TRUE:LBB0_[0-9]+]]
; CHECK:         bl _bar
;; After bl _bar, the return block is tail-duplicated: we get ret directly
;; without branching to a shared return block.
; CHECK:         mov w0, wzr
; CHECK-NEXT:    ldp x29, x30, [sp], #16
; CHECK-NEXT:    ret
; CHECK:       [[RET_TRUE]]:
; CHECK:         mov w0, #1
; CHECK:         ret

define i1 @tail_dup_noexcept(i32 %num) personality ptr @__gxx_personality_v0 {
entry:
  %cmp = icmp sgt i32 %num, 10
  br i1 %cmp, label %if.then, label %return

if.then:
  invoke void @bar()
    to label %invoke.cont unwind label %terminate.lpad

invoke.cont:
  br label %return

return:
  %retval = phi i1 [ false, %invoke.cont ], [ true, %entry ]
  ret i1 %retval

terminate.lpad:
  %lp = landingpad { ptr, i32 }
    catch ptr null
  %exn = extractvalue { ptr, i32 } %lp, 0
  call void @__clang_call_terminate(ptr %exn)
  unreachable
}

;; Test 2: Multiple invoke predecessors
;; Two invoke call sites both unwind to the same landing pad, with normal
;; successors that fall through to a shared tail block. The shared tail
;; block should be duplicated into both normal-return paths.

; CHECK-LABEL: _tail_dup_multi_invoke:
; CHECK:         bl _bar
;; After bl _bar, the return block is tail-duplicated with retval=1.
; CHECK:         mov w0, #1
; CHECK-NEXT:    ldp x29, x30, [sp], #16
; CHECK-NEXT:    ret
; CHECK:         bl _baz
;; After bl _baz, the return block is tail-duplicated with retval=2.
; CHECK:         mov w0, #2
; CHECK-NEXT:    ldp x29, x30, [sp], #16
; CHECK-NEXT:    ret

define i32 @tail_dup_multi_invoke(i32 %n) personality ptr @__gxx_personality_v0 {
entry:
  %cmp = icmp sgt i32 %n, 0
  br i1 %cmp, label %call.bar, label %call.baz

call.bar:
  invoke void @bar()
    to label %bar.cont unwind label %terminate.lpad

bar.cont:
  br label %return

call.baz:
  invoke void @baz()
    to label %baz.cont unwind label %terminate.lpad

baz.cont:
  br label %return

return:
  %retval = phi i32 [ 1, %bar.cont ], [ 2, %baz.cont ]
  ret i32 %retval

terminate.lpad:
  %lp = landingpad { ptr, i32 }
    catch ptr null
  %exn = extractvalue { ptr, i32 } %lp, 0
  call void @__clang_call_terminate(ptr %exn)
  unreachable
}

;; Test 3: EH pad blocks are NOT duplicated
;; The landing pad block itself has multiple predecessors (two invokes unwind
;; to it). Verify that the isEHPad() guard in shouldTailDuplicate prevents
;; the landing pad from being tail-duplicated.

; CHECK-LABEL: _no_dup_eh_pad_tail:
;; Both invoke paths get their own ret (done block duplicated).
; CHECK:         bl _bar
; CHECK:         ret
; CHECK:         bl _baz
; CHECK:         ret
;; The landing pad appears only once — it was NOT duplicated.
; CHECK:         bl ___clang_call_terminate
; CHECK-NOT:     bl ___clang_call_terminate

define void @no_dup_eh_pad_tail(i1 %cond) personality ptr @__gxx_personality_v0 {
entry:
  br i1 %cond, label %invoke1, label %invoke2

invoke1:
  invoke void @bar()
    to label %done unwind label %lpad

invoke2:
  invoke void @baz()
    to label %done unwind label %lpad

lpad:
  %lp = landingpad { ptr, i32 }
    catch ptr null
  %exn = extractvalue { ptr, i32 } %lp, 0
  call void @__clang_call_terminate(ptr %exn)
  unreachable

done:
  ret void
}
