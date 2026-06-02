; RUN: llc -verify-machineinstrs -enable-machine-outliner -mtriple=aarch64-apple-darwin < %s | FileCheck %s --check-prefix=UNIQ
; RUN: llc -verify-machineinstrs -enable-machine-outliner -mtriple=aarch64-apple-darwin < %s --mattr=+v8a -o - | FileCheck %s --check-prefix=UNIQ

; Without the module flag, the outlined function name has no `.__uniq.` suffix.
; RUN: sed 's/!"unique-internal-linkage-names"/!"some-unrelated-flag"/' %s \
; RUN:   | llc -verify-machineinstrs -enable-machine-outliner -mtriple=aarch64-apple-darwin \
; RUN:   | FileCheck %s --check-prefix=NOUNIQ

source_filename = "/some/path/foo.c"

define i32 @foo(i32 %a, i32 %b, i32 %c) #0 {
  %1 = add i32 %a, %b
  %2 = mul i32 %1, %c
  %3 = sub i32 %2, %a
  %4 = xor i32 %3, %b
  %5 = and i32 %4, %c
  %6 = or i32 %5, %a
  ret i32 %6
}

define i32 @bar(i32 %a, i32 %b, i32 %c) #0 {
  %1 = add i32 %a, %b
  %2 = mul i32 %1, %c
  %3 = sub i32 %2, %a
  %4 = xor i32 %3, %b
  %5 = and i32 %4, %c
  %6 = or i32 %5, %a
  ret i32 %6
}

define i32 @baz(i32 %a, i32 %b, i32 %c) #0 {
  %1 = add i32 %a, %b
  %2 = mul i32 %1, %c
  %3 = sub i32 %2, %a
  %4 = xor i32 %3, %b
  %5 = and i32 %4, %c
  %6 = or i32 %5, %a
  ret i32 %6
}

attributes #0 = { noinline nounwind }

!llvm.module.flags = !{!0}
!0 = !{i32 1, !"unique-internal-linkage-names", i32 1}

; UNIQ:   OUTLINED_FUNCTION_0.__uniq.{{[0-9]+}}:
; NOUNIQ: OUTLINED_FUNCTION_0:
; NOUNIQ-NOT: __uniq
