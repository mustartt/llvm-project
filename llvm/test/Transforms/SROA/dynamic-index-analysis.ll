; REQUIRES: asserts
; RUN: opt < %s -passes=sroa -sroa-dynamic-index -debug-only=sroa -stats -disable-output 2>&1 | FileCheck %s

target datalayout = "e-p:64:64:64-i64:64-n32:64"

declare void @use(ptr)

; int S[2]; return S[p];
; CHECK-LABEL: Dynamically indexed alloca:   %S = alloca [2 x i32]
; CHECK-NEXT:    Legal:   %v = load i32, ptr %gep, align 4
; CHECK-NEXT:      candidates: 0 4
define i32 @array_load(i32 %a, i32 %b, i64 %p) {
  %S = alloca [2 x i32], align 4
  store i32 %a, ptr %S, align 4
  %S1 = getelementptr inbounds [2 x i32], ptr %S, i64 0, i64 1
  store i32 %b, ptr %S1, align 4
  %gep = getelementptr inbounds [2 x i32], ptr %S, i64 0, i64 %p
  %v = load i32, ptr %gep, align 4
  ret i32 %v
}

; S[p] = a; return S[0];
; CHECK-LABEL: Dynamically indexed alloca:   %S2 = alloca [2 x i32]
; CHECK-NEXT:    Legal:   store i32 %a, ptr %gep, align 4
; CHECK-NEXT:      candidates: 0 4
define i32 @array_store(i32 %a, i64 %p) {
  %S2 = alloca [2 x i32], align 4
  call void @llvm.memset.p0.i64(ptr %S2, i8 0, i64 8, i1 false)
  %gep = getelementptr inbounds [2 x i32], ptr %S2, i64 0, i64 %p
  store i32 %a, ptr %gep, align 4
  %v = load i32, ptr %S2, align 4
  ret i32 %v
}

; struct { int a[2]; int b; } s; return s.a[p];
; s.a[2] aliases s.b and is not UB in IR, so offset 8 is a candidate.
; CHECK-LABEL: Dynamically indexed alloca:   %s = alloca { [2 x i32], i32 }
; CHECK-NEXT:    Legal:   %v = load i32, ptr %gep, align 4
; CHECK-NEXT:      candidates: 0 4 8
define i32 @struct_array_field(i64 %p) {
  %s = alloca { [2 x i32], i32 }, align 4
  call void @llvm.memset.p0.i64(ptr %s, i8 0, i64 12, i1 false)
  %gep = getelementptr inbounds { [2 x i32], i32 }, ptr %s, i64 0, i32 0, i64 %p
  %v = load i32, ptr %gep, align 4
  ret i32 %v
}

; struct { int x, y; } S[2]; return S[p].y;
; CHECK-LABEL: Dynamically indexed alloca:   %aos = alloca [2 x { i32, i32 }]
; CHECK-NEXT:    Legal:   %v = load i32, ptr %gep, align 4
; CHECK-NEXT:      candidates: 4 12
define i32 @array_of_struct(i64 %p) {
  %aos = alloca [2 x { i32, i32 }], align 4
  call void @llvm.memset.p0.i64(ptr %aos, i8 0, i64 16, i1 false)
  %gep = getelementptr inbounds [2 x { i32, i32 }], ptr %aos, i64 0, i64 %p, i32 1
  %v = load i32, ptr %gep, align 4
  ret i32 %v
}

; Chained GEPs: int S[2][2]; return S[i][j];
; CHECK-LABEL: Dynamically indexed alloca:   %m = alloca [2 x [2 x i32]]
; CHECK-NEXT:    Legal:   %v = load i32, ptr %gep1, align 4
; CHECK-NEXT:      candidates: 0 4 8 12
define i32 @array_2d(i64 %i, i64 %j) {
  %m = alloca [2 x [2 x i32]], align 4
  call void @llvm.memset.p0.i64(ptr %m, i8 0, i64 16, i1 false)
  %gep0 = getelementptr inbounds [2 x [2 x i32]], ptr %m, i64 0, i64 %i
  %gep1 = getelementptr inbounds [2 x i32], ptr %gep0, i64 0, i64 %j
  %v = load i32, ptr %gep1, align 4
  ret i32 %v
}

; Canonicalized i8 GEP whose index is known to be a multiple of 4.
; CHECK-LABEL: Dynamically indexed alloca:   %shl = alloca [4 x i16]
; CHECK-NEXT:    Legal:   %v = load i16, ptr %gep, align 2
; CHECK-NEXT:      candidates: 0 4
define i16 @i8_gep_known_bits(i64 %p) {
  %shl = alloca [4 x i16], align 4
  call void @llvm.memset.p0.i64(ptr %shl, i8 0, i64 8, i1 false)
  %off = shl i64 %p, 2
  %gep = getelementptr inbounds i8, ptr %shl, i64 %off
  %v = load i16, ptr %gep, align 2
  ret i16 %v
}

; i8 GEP with an arbitrary index is pruned by the access alignment.
; CHECK-LABEL: Dynamically indexed alloca:   %al = alloca [2 x i32]
; CHECK-NEXT:    Legal:   %v = load i32, ptr %gep, align 4
; CHECK-NEXT:      candidates: 0 4
define i32 @i8_gep_alignment(i64 %p) {
  %al = alloca [2 x i32], align 4
  call void @llvm.memset.p0.i64(ptr %al, i8 0, i64 8, i1 false)
  %gep = getelementptr inbounds i8, ptr %al, i64 %p
  %v = load i32, ptr %gep, align 4
  ret i32 %v
}

; Without nusw, a stride of 12 only guarantees a congruence modulo 4.
; CHECK-LABEL: Dynamically indexed alloca:   %wrap = alloca [2 x { i32, i32, i32 }]
; CHECK-NEXT:    Legal:   %v = load i32, ptr %gep, align 4
; CHECK-NEXT:      candidates: 0 4 8 12 16 20
define i32 @may_wrap(i64 %p) {
  %wrap = alloca [2 x { i32, i32, i32 }], align 4
  call void @llvm.memset.p0.i64(ptr %wrap, i8 0, i64 24, i1 false)
  %gep = getelementptr [2 x { i32, i32, i32 }], ptr %wrap, i64 0, i64 %p, i32 0
  %v = load i32, ptr %gep, align 4
  ret i32 %v
}

; CHECK-LABEL: Dynamically indexed alloca:   %wrap.nusw = alloca [2 x { i32, i32, i32 }]
; CHECK-NEXT:    Legal:   %v = load i32, ptr %gep, align 4
; CHECK-NEXT:      candidates: 0 12
define i32 @no_wrap(i64 %p) {
  %wrap.nusw = alloca [2 x { i32, i32, i32 }], align 4
  call void @llvm.memset.p0.i64(ptr %wrap.nusw, i8 0, i64 24, i1 false)
  %gep = getelementptr nusw [2 x { i32, i32, i32 }], ptr %wrap.nusw, i64 0, i64 %p, i32 0
  %v = load i32, ptr %gep, align 4
  ret i32 %v
}

; CHECK-LABEL: Dynamically indexed alloca:   %big = alloca [32 x i32]
; CHECK-NEXT:    Rejected: too many candidates
define i32 @too_many_candidates(i64 %p) {
  %big = alloca [32 x i32], align 4
  call void @llvm.memset.p0.i64(ptr %big, i8 0, i64 128, i1 false)
  %gep = getelementptr inbounds [32 x i32], ptr %big, i64 0, i64 %p
  %v = load i32, ptr %gep, align 4
  ret i32 %v
}

; CHECK-LABEL: Dynamically indexed alloca:   %vol = alloca [2 x i32]
; CHECK-NEXT:    Rejected: unsupported use   %v = load volatile i32, ptr %gep, align 4
define i32 @volatile_load(i64 %p) {
  %vol = alloca [2 x i32], align 4
  call void @llvm.memset.p0.i64(ptr %vol, i8 0, i64 8, i1 false)
  %gep = getelementptr inbounds [2 x i32], ptr %vol, i64 0, i64 %p
  %v = load volatile i32, ptr %gep, align 4
  ret i32 %v
}

; CHECK-LABEL: Dynamically indexed alloca:   %ms = alloca [2 x i32]
; CHECK-NEXT:    Rejected: unsupported use   call void @llvm.memset
define i32 @dynamic_memset(i64 %p) {
  %ms = alloca [2 x i32], align 4
  %gep = getelementptr inbounds [2 x i32], ptr %ms, i64 0, i64 %p
  call void @llvm.memset.p0.i64(ptr %gep, i8 0, i64 4, i1 false)
  %v = load i32, ptr %ms, align 4
  ret i32 %v
}

; CHECK-LABEL: Dynamically indexed alloca:   %esc = alloca [2 x i32]
; CHECK-NEXT:    Rejected: escapes
define i32 @escape(i64 %p) {
  %esc = alloca [2 x i32], align 4
  %gep = getelementptr inbounds [2 x i32], ptr %esc, i64 0, i64 %p
  store i32 0, ptr %gep, align 4
  call void @use(ptr %esc)
  %v = load i32, ptr %esc, align 4
  ret i32 %v
}

; CHECK-LABEL: Dynamically indexed alloca:   %ro = alloca [2 x i32]
; CHECK-NEXT:    Rejected: escapes into read-only use
define i32 @readonly_escape(i64 %p) {
  %ro = alloca [2 x i32], align 4
  %gep = getelementptr inbounds [2 x i32], ptr %ro, i64 0, i64 %p
  store i32 0, ptr %gep, align 4
  call void @use(ptr readonly captures(none) %ro) memory(read)
  %v = load i32, ptr %ro, align 4
  ret i32 %v
}

; CHECK-DAG: 14 sroa - Number of allocas blocked by dynamically indexed accesses
; CHECK-DAG:  9 sroa - Number of dynamically indexed allocas that are legal to rewrite with selects
; CHECK-DAG:  8 sroa - Number of dynamically indexed loads in legal allocas
; CHECK-DAG:  1 sroa - Number of dynamically indexed stores in legal allocas
; CHECK-DAG: 25 sroa - Total number of candidate offsets of dynamically indexed accesses in legal allocas
; CHECK-DAG:  6 sroa - Maximum number of candidate offsets of a dynamically indexed access
; CHECK-DAG:  1 sroa - Number of dynamically indexed accesses through a GEP that may wrap
; CHECK-DAG:  1 sroa - Number of dynamically indexed allocas rejected because the alloca escapes
; CHECK-DAG:  1 sroa - Number of dynamically indexed allocas rejected because the alloca escapes into a read-only use
; CHECK-DAG:  2 sroa - Number of dynamically indexed allocas rejected because a dynamically indexed pointer has a use other than a simple load or store
; CHECK-DAG:  1 sroa - Number of dynamically indexed allocas rejected because an access has too many candidate offsets
