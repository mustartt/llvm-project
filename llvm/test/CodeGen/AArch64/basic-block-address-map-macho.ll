;; Check emission of the __LLVM,__llvm_bbaddrmap section on MachO targets.
; RUN: llc < %s -mtriple=arm64-apple-darwin -basic-block-address-map | FileCheck %s
; RUN: llc < %s -mtriple=arm64-apple-darwin -basic-block-address-map -pgo-analysis-map=all | FileCheck %s --check-prefixes=CHECK,PGO

define void @f(i1 %c) {
  br i1 %c, label %then, label %else
then:
  ret void
else:
  ret void
}

; CHECK-LABEL:  Lfunc_begin0:
;; The MachO section name is limited to 16 bytes, so the section is named
;; __llvm_bbaddrmap rather than the ELF/COFF .llvm_bb_addr_map.
; CHECK:        .section        __LLVM,__llvm_bbaddrmap
; CHECK-NEXT:   .byte   5                               ; version
; CHECK-NEXT:   .short  {{[0-9]+}}                      ; feature
; CHECK-NEXT:   .quad   Lfunc_begin0                    ; function address
; CHECK-NEXT:   .byte   {{[0-9]+}}                      ; number of basic blocks
; CHECK-NEXT:   .byte   0                               ; BB id
; PGO:          ; function entry count
; PGO:          ; basic block frequency
