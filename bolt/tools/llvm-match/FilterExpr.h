//===- bolt/tools/llvm-match/FilterExpr.h - Filter expression eval --------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Recursive-descent parser and evaluator for @filter() expressions.
//
// Grammar:
//   expr     → compare (('&&' | '||') compare)*
//   compare  → additive (('==' | '!=' | '<=' | '>=' | '<' | '>') additive)?
//   additive → multiplicative (('+' | '-') multiplicative)*
//   multiplicative → unary (('*' | '/' | '%') unary)*
//   unary    → '-' unary | atom
//   atom     → integer | '%' name | '(' expr ')' | func '(' args ')'
//
// Functions: abs(x), min(x,y), max(x,y)
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_MATCH_FILTEREXPR_H
#define LLVM_TOOLS_LLVM_MATCH_FILTEREXPR_H

#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Error.h"
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string>

namespace llvm {
namespace filter_expr {

/// A bound value from pattern matching.
struct Binding {
  enum Kind { Reg, Imm, Label };
  Kind K;
  unsigned RegVal = 0; // MCPhysReg
  int64_t ImmVal = 0;
  std::string LabelVal;
  unsigned RegWidth = 0; // Register width in bits (32, 64, 128, etc.)
};

/// Evaluator for @filter() expressions over captured bindings.
class FilterExprParser {
  StringRef S;
  unsigned Pos = 0;
  const StringMap<Binding> &Bindings;

  void skipSpaces() {
    while (Pos < S.size() && S[Pos] == ' ')
      ++Pos;
  }

  bool atEnd() const { return Pos >= S.size(); }
  char peek() const { return atEnd() ? '\0' : S[Pos]; }

  Expected<int64_t> parseAtom() {
    skipSpaces();
    if (atEnd())
      return make_error<StringError>("unexpected end of expression",
                                     inconvertibleErrorCode());

    // Parenthesized sub-expression.
    if (peek() == '(') {
      ++Pos;
      auto V = parseExpr();
      if (!V)
        return V.takeError();
      skipSpaces();
      if (peek() != ')')
        return make_error<StringError>("expected ')'",
                                       inconvertibleErrorCode());
      ++Pos;
      return *V;
    }

    // abs(expr)
    if (S.substr(Pos).starts_with("abs(")) {
      Pos += 4;
      auto V = parseExpr();
      if (!V)
        return V.takeError();
      skipSpaces();
      if (peek() != ')')
        return make_error<StringError>("expected ')' after abs(",
                                       inconvertibleErrorCode());
      ++Pos;
      return std::abs(*V);
    }

    // min(a, b)
    if (S.substr(Pos).starts_with("min(")) {
      Pos += 4;
      auto A = parseExpr();
      if (!A)
        return A.takeError();
      skipSpaces();
      if (peek() != ',')
        return make_error<StringError>("expected ',' in min()",
                                       inconvertibleErrorCode());
      ++Pos;
      auto B = parseExpr();
      if (!B)
        return B.takeError();
      skipSpaces();
      if (peek() != ')')
        return make_error<StringError>("expected ')' after min(",
                                       inconvertibleErrorCode());
      ++Pos;
      return std::min(*A, *B);
    }

    // max(a, b)
    if (S.substr(Pos).starts_with("max(")) {
      Pos += 4;
      auto A = parseExpr();
      if (!A)
        return A.takeError();
      skipSpaces();
      if (peek() != ',')
        return make_error<StringError>("expected ',' in max()",
                                       inconvertibleErrorCode());
      ++Pos;
      auto B = parseExpr();
      if (!B)
        return B.takeError();
      skipSpaces();
      if (peek() != ')')
        return make_error<StringError>("expected ')' after max(",
                                       inconvertibleErrorCode());
      ++Pos;
      return std::max(*A, *B);
    }

    // width(%name) — returns the register width in bits.
    if (S.substr(Pos).starts_with("width(")) {
      Pos += 6;
      skipSpaces();
      if (peek() != '%')
        return make_error<StringError>("width() expects a capture reference",
                                       inconvertibleErrorCode());
      ++Pos;
      unsigned Start = Pos;
      while (Pos < S.size() && (isAlnum(S[Pos]) || S[Pos] == '_'))
        ++Pos;
      StringRef Name = S.substr(Start, Pos - Start);
      skipSpaces();
      if (peek() != ')')
        return make_error<StringError>("expected ')' after width(",
                                       inconvertibleErrorCode());
      ++Pos;
      auto It = Bindings.find(Name);
      if (It == Bindings.end())
        return make_error<StringError>("unbound capture '%" + Name.str() + "'",
                                       inconvertibleErrorCode());
      if (It->second.K != Binding::Reg)
        return make_error<StringError>(
            "width() requires a register capture, '%" + Name.str() +
                "' is not a register",
            inconvertibleErrorCode());
      return static_cast<int64_t>(It->second.RegWidth);
    }

    // is_gpr(%name) — true (1) if the register is a GPR (W/X).
    if (S.substr(Pos).starts_with("is_gpr(")) {
      Pos += 7;
      skipSpaces();
      if (peek() != '%')
        return make_error<StringError>("is_gpr() expects a capture reference",
                                       inconvertibleErrorCode());
      ++Pos;
      unsigned Start = Pos;
      while (Pos < S.size() && (isAlnum(S[Pos]) || S[Pos] == '_'))
        ++Pos;
      StringRef Name = S.substr(Start, Pos - Start);
      skipSpaces();
      if (peek() != ')')
        return make_error<StringError>("expected ')' after is_gpr(",
                                       inconvertibleErrorCode());
      ++Pos;
      auto It = Bindings.find(Name);
      if (It == Bindings.end())
        return make_error<StringError>("unbound capture '%" + Name.str() + "'",
                                       inconvertibleErrorCode());
      if (It->second.K != Binding::Reg)
        return 0;
      unsigned W = It->second.RegWidth;
      // GPRs are 32 or 64 bits (W/X regs). FP/NEON are 8,16,32,64,128.
      // Use RegClass info if available; fallback to width heuristic.
      return (W == 32 || W == 64) ? 1 : 0;
    }

    // is_fp(%name) — true (1) if the register is FP/NEON (B/H/S/D/Q/V).
    if (S.substr(Pos).starts_with("is_fp(")) {
      Pos += 6;
      skipSpaces();
      if (peek() != '%')
        return make_error<StringError>("is_fp() expects a capture reference",
                                       inconvertibleErrorCode());
      ++Pos;
      unsigned Start = Pos;
      while (Pos < S.size() && (isAlnum(S[Pos]) || S[Pos] == '_'))
        ++Pos;
      StringRef Name = S.substr(Start, Pos - Start);
      skipSpaces();
      if (peek() != ')')
        return make_error<StringError>("expected ')' after is_fp(",
                                       inconvertibleErrorCode());
      ++Pos;
      auto It = Bindings.find(Name);
      if (It == Bindings.end())
        return make_error<StringError>("unbound capture '%" + Name.str() + "'",
                                       inconvertibleErrorCode());
      if (It->second.K != Binding::Reg)
        return 0;
      unsigned W = It->second.RegWidth;
      return (W == 128 || W == 16 || W == 8) ? 1 : 0;
    }

    // Capture reference: %name
    if (peek() == '%') {
      ++Pos;
      unsigned Start = Pos;
      while (Pos < S.size() && (isAlnum(S[Pos]) || S[Pos] == '_'))
        ++Pos;
      StringRef Name = S.substr(Start, Pos - Start);
      auto It = Bindings.find(Name);
      if (It == Bindings.end())
        return make_error<StringError>("unbound capture '%" + Name.str() + "'",
                                       inconvertibleErrorCode());
      if (It->second.K != Binding::Imm)
        return make_error<StringError>(
            "capture '%" + Name.str() + "' is not an immediate",
            inconvertibleErrorCode());
      return It->second.ImmVal;
    }

    // Integer literal (decimal or hex).
    if (isDigit(peek()) ||
        (peek() == '-' && Pos + 1 < S.size() && isDigit(S[Pos + 1]))) {
      unsigned Start = Pos;
      if (peek() == '-')
        ++Pos;
      if (Pos + 1 < S.size() && S[Pos] == '0' &&
          (S[Pos + 1] == 'x' || S[Pos + 1] == 'X')) {
        Pos += 2;
        while (Pos < S.size() && isHexDigit(S[Pos]))
          ++Pos;
      } else {
        while (Pos < S.size() && isDigit(S[Pos]))
          ++Pos;
      }
      StringRef NumStr = S.substr(Start, Pos - Start);
      int64_t Val;
      if (NumStr.starts_with("0x") || NumStr.starts_with("0X")) {
        if (NumStr.drop_front(2).getAsInteger(16, Val))
          return make_error<StringError>("bad hex literal",
                                         inconvertibleErrorCode());
      } else {
        if (NumStr.getAsInteger(10, Val))
          return make_error<StringError>("bad integer literal",
                                         inconvertibleErrorCode());
      }
      return Val;
    }

    return make_error<StringError>(
        std::string("unexpected character '") + peek() + "'",
        inconvertibleErrorCode());
  }

  Expected<int64_t> parseUnary() {
    skipSpaces();
    if (peek() == '-') {
      ++Pos;
      auto V = parseUnary();
      if (!V)
        return V.takeError();
      return -*V;
    }
    return parseAtom();
  }

  Expected<int64_t> parseMultiplicative() {
    auto LHS = parseUnary();
    if (!LHS)
      return LHS.takeError();
    while (true) {
      skipSpaces();
      char C = peek();
      if (C != '*' && C != '/' && C != '%')
        break;
      ++Pos;
      auto RHS = parseUnary();
      if (!RHS)
        return RHS.takeError();
      if (C == '*')
        *LHS *= *RHS;
      else if (C == '/') {
        if (*RHS == 0)
          return make_error<StringError>("division by zero",
                                         inconvertibleErrorCode());
        *LHS /= *RHS;
      } else {
        if (*RHS == 0)
          return make_error<StringError>("modulo by zero",
                                         inconvertibleErrorCode());
        *LHS %= *RHS;
      }
    }
    return LHS;
  }

  Expected<int64_t> parseAdditive() {
    auto LHS = parseMultiplicative();
    if (!LHS)
      return LHS.takeError();
    while (true) {
      skipSpaces();
      char C = peek();
      if (C != '+' && C != '-')
        break;
      ++Pos;
      auto RHS = parseMultiplicative();
      if (!RHS)
        return RHS.takeError();
      if (C == '+')
        *LHS += *RHS;
      else
        *LHS -= *RHS;
    }
    return LHS;
  }

  Expected<int64_t> parseCompare() {
    auto LHS = parseAdditive();
    if (!LHS)
      return LHS.takeError();
    skipSpaces();
    // Two-char operators first.
    if (Pos + 1 < S.size()) {
      StringRef Op2 = S.substr(Pos, 2);
      if (Op2 == "==") {
        Pos += 2;
        auto R = parseAdditive();
        if (!R) return R.takeError();
        return (*LHS == *R) ? 1 : 0;
      }
      if (Op2 == "!=") {
        Pos += 2;
        auto R = parseAdditive();
        if (!R) return R.takeError();
        return (*LHS != *R) ? 1 : 0;
      }
      if (Op2 == "<=") {
        Pos += 2;
        auto R = parseAdditive();
        if (!R) return R.takeError();
        return (*LHS <= *R) ? 1 : 0;
      }
      if (Op2 == ">=") {
        Pos += 2;
        auto R = parseAdditive();
        if (!R) return R.takeError();
        return (*LHS >= *R) ? 1 : 0;
      }
    }
    // Single-char operators.
    if (peek() == '<') {
      ++Pos;
      auto R = parseAdditive();
      if (!R) return R.takeError();
      return (*LHS < *R) ? 1 : 0;
    }
    if (peek() == '>') {
      ++Pos;
      auto R = parseAdditive();
      if (!R) return R.takeError();
      return (*LHS > *R) ? 1 : 0;
    }
    return LHS;
  }

  Expected<int64_t> parseExpr() { return parseCompare(); }

public:
  FilterExprParser(StringRef Expr, const StringMap<Binding> &B)
      : S(Expr), Bindings(B) {}

  /// Evaluate the expression. Returns true if the result is non-zero.
  Expected<bool> evaluate() {
    auto V = parseExpr();
    if (!V)
      return V.takeError();
    skipSpaces();
    // Support && and || for chaining.
    while (!atEnd()) {
      skipSpaces();
      if (Pos + 1 < S.size() && S.substr(Pos, 2) == "&&") {
        Pos += 2;
        if (*V == 0)
          return false; // short-circuit
        auto R = parseExpr();
        if (!R)
          return R.takeError();
        *V = (*R != 0) ? 1 : 0;
      } else if (Pos + 1 < S.size() && S.substr(Pos, 2) == "||") {
        Pos += 2;
        if (*V != 0)
          return true; // short-circuit
        auto R = parseExpr();
        if (!R)
          return R.takeError();
        *V = (*R != 0) ? 1 : 0;
      } else {
        break;
      }
    }
    return *V != 0;
  }
};

} // namespace filter_expr
} // namespace llvm

#endif // LLVM_TOOLS_LLVM_MATCH_FILTEREXPR_H
