//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

// <locale>

// class num_put<charT, OutputIterator>

// iter_type put(iter_type s, ios_base& iob, char_type fill, double v) const;

// XFAIL: win32-broken-printf-g-precision

#include <locale>
#include <ios>
#include <cassert>
#include <streambuf>
#include <cmath>
#include "test_macros.h"
#include "test_iterators.h"

typedef std::num_put<char, cpp17_output_iterator<char*> > F;

class my_facet : public F {
public:
  explicit my_facet(std::size_t refs = 0) : F(refs) {}
};

class my_numpunct : public std::numpunct<char> {
public:
  my_numpunct() : std::numpunct<char>() {}

protected:
  virtual char_type do_decimal_point() const { return ';'; }
  virtual char_type do_thousands_sep() const { return '_'; }
  virtual std::string do_grouping() const { return std::string("\1\2\3"); }
};

void test1() {
  char str[200];
  std::locale lc = std::locale::classic();
  std::locale lg(lc, new my_numpunct);
  const my_facet f(1);
  {
    double v = +0.;
    std::ios ios(0);
    // %g
    {
      ios.precision(0);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************+0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********************0.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************+0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********************0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************+0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********************0.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************+0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********************0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(1);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************+0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********************0.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************+0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********************0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************+0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********************0.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************+0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********************0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(6);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.00000******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************0.00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************0.00000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;00000******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************0;00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************0;00000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.00000*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************+0.00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*****************0.00000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;00000*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************+0;00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*****************0;00000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.00000******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************0.00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************0.00000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;00000******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************0;00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************0;00000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.00000*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************+0.00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*****************0.00000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;00000*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************+0;00000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*****************0;00000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(16);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********0.000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********0.000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********0;000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********0;000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******+0.000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******0.000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******+0;000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******0;000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********0.000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********0.000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********0;000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********0;000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******+0.000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******0.000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******+0;000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******0;000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(60);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;00000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
    }
  }
}

void test2() {
  char str[200];
  std::locale lc = std::locale::classic();
  std::locale lg(lc, new my_numpunct);
  const my_facet f(1);
  {
    double v = 1234567890.125;
    std::ios ios(0);
    // %g
    {
      ios.precision(0);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1e+09********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1e+09********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1e+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.e+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1.e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1.e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;e+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1;e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1;e+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1e+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************+1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******************1e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1e+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************+1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******************1e+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.e+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************+1.e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******************1.e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;e+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************+1;e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******************1;e+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1E+09********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1E+09********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1E+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.E+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1.E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1.E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;E+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1;E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1;E+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1E+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************+1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******************1E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1E+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************+1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******************1E+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.E+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************+1.E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******************1.E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;E+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************+1;E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******************1;E+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(1);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1e+09********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1e+09********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1e+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.e+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1.e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1.e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;e+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1;e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1;e+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1e+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************+1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******************1e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1e+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************+1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******************1e+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.e+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************+1.e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******************1.e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;e+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************+1;e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******************1;e+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1E+09********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1E+09********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1E+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.E+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1.E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1.E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;E+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1;E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1;E+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1E+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************+1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******************1E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1E+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************+1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******************1E+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.E+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************+1.E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******************1.E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;E+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************+1;E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******************1;E+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(6);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.23457e+09**************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1.23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1.23457e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;23457e+09**************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1;23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1;23457e+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.23457e+09**************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1.23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1.23457e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;23457e+09**************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1;23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1;23457e+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.23457e+09*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************+1.23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*************1.23457e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;23457e+09*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************+1;23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*************1;23457e+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.23457e+09*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************+1.23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*************1.23457e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;23457e+09*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************+1;23457e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*************1;23457e+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.23457E+09**************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1.23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1.23457E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;23457E+09**************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1;23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1;23457E+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.23457E+09**************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1.23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1.23457E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;23457E+09**************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1;23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1;23457E+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.23457E+09*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************+1.23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*************1.23457E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;23457E+09*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************+1;23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*************1;23457E+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.23457E+09*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************+1.23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*************1.23457E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;23457E+09*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************+1;23457E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*************1;23457E+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(16);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125***********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********1234567890.125");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125000********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********1234567890.125000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125000****");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125**********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********+1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********1234567890.125");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******+1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******+1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******1234567890.125000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125000***");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***+1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125***********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********1234567890.125");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125000********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********1234567890.125000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125000****");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125**********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********+1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********1234567890.125");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******+1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******+1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******1234567890.125000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125000***");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***+1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(60);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125***********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********1234567890.125");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125**********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********+1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********1234567890.125");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******+1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125***********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********1234567890.125");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125**********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********+1234567890.125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********1234567890.125");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******+1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******1_234_567_89_0;125");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;12500000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
    }
  }
}

void test3() {
  char str[200];
  std::locale lc = std::locale::classic();
  std::locale lg(lc, new my_numpunct);
  const my_facet f(1);
  {
    double v = +0.;
    std::ios ios(0);
    std::fixed(ios);
    // %f
    {
      ios.precision(0);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************+0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********************0.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************+0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********************0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0************************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0***********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********************+0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***********************0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************+0.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********************0.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************+0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********************0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(1);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0.0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0;0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0.0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0;0");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0*********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********************+0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*********************0.0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0*********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********************+0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*********************0;0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0*********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********************+0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*********************0.0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0*********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********************+0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*********************0;0");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0.0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0;0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0.0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0**********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********************0;0");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0*********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********************+0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*********************0.0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0*********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********************+0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*********************0;0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0*********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********************+0.0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*********************0.0");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0*********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********************+0;0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*********************0;0");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(6);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0.000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0;000000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0.000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0;000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****************+0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+****************0.000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****************+0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+****************0;000000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****************+0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+****************0.000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****************+0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+****************0;000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0.000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0;000000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0.000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************0;000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****************+0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+****************0.000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****************+0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+****************0;000000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****************+0.000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+****************0.000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****************+0;000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+****************0;000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(16);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0000000000000000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0.0000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0000000000000000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0;0000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0000000000000000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0.0000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0000000000000000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0;0000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0000000000000000******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******+0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******0.0000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0000000000000000******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******+0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******0;0000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0000000000000000******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******+0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******0.0000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0000000000000000******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******+0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******0;0000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0000000000000000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0.0000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0000000000000000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0;0000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.0000000000000000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0.0000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;0000000000000000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******0;0000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0000000000000000******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******+0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******0.0000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0000000000000000******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******+0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******0;0000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.0000000000000000******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******+0.0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******0.0000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;0000000000000000******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******+0;0000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******0;0000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(60);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0.000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+0;000000000000000000000000000000000000000000000000000000000000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
    }
  }
}

void test4() {
  char str[200];
  std::locale lc = std::locale::classic();
  std::locale lg(lc, new my_numpunct);
  const my_facet f(1);
  {
    double v = 1234567890.125;
    std::ios ios(0);
    std::fixed(ios);
    // %f
    {
      ios.precision(0);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890***************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***************1234567890");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***************1234567890");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0***********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********1_234_567_89_0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********1_234_567_89_0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.**************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1234567890.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1234567890.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;**********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********1_234_567_89_0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********1_234_567_89_0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890**************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************+1234567890");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**************1234567890");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0**********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********+1_234_567_89_0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********1_234_567_89_0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************+1234567890.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*************1234567890.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;*********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********+1_234_567_89_0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*********1_234_567_89_0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890***************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***************1234567890");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***************1234567890");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0***********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********1_234_567_89_0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***********1_234_567_89_0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.**************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1234567890.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************1234567890.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;**********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********1_234_567_89_0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********1_234_567_89_0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890**************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**************+1234567890");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**************1234567890");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0**********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "**********+1_234_567_89_0");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+**********1_234_567_89_0");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************+1234567890.");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*************1234567890.");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;*********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********+1_234_567_89_0;");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*********1_234_567_89_0;");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(1);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.1*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************1234567890.1");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;1*********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.1*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************1234567890.1");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;1*********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.1************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************+1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+************1234567890.1");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;1********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********+1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+********1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.1************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************+1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+************1234567890.1");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;1********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********+1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+********1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.1*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************1234567890.1");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;1*********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.1*************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*************1234567890.1");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;1*********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*********1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.1************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************+1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+************1234567890.1");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;1********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********+1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+********1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.1************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************+1234567890.1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+************1234567890.1");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;1********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********+1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+********1_234_567_89_0;1");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(6);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125000********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********1234567890.125000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125000****");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125000********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********1234567890.125000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125000****");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******+1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******1234567890.125000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125000***");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***+1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******+1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******1234567890.125000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125000***");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***+1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125000********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********1234567890.125000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125000****");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1234567890.125000********");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********1234567890.125000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1_234_567_89_0;125000****");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "****1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******+1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******1234567890.125000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125000***");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***+1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1234567890.125000*******");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******+1234567890.125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******1234567890.125000");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1_234_567_89_0;125000***");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "***+1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+***1_234_567_89_0;125000");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(16);
      {
      }
      ios.precision(60);
      {
      }
    }
  }
}

void test5() {
  char str[200];
  std::locale lc = std::locale::classic();
  std::locale lg(lc, new my_numpunct);
  const my_facet f(1);
  {
    double v = -0.;
    std::ios ios(0);
    std::scientific(ios);
    // %e
    {
      ios.precision(0);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0e+00*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************-0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*******************0e+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0e+00*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************-0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*******************0e+00");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.e+00******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************-0.e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-******************0.e+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;e+00******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************-0;e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-******************0;e+00");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0e+00*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************-0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*******************0e+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0e+00*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************-0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*******************0e+00");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.e+00******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************-0.e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-******************0.e+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;e+00******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************-0;e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-******************0;e+00");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0E+00*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************-0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*******************0E+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0E+00*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************-0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*******************0E+00");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.E+00******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************-0.E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-******************0.E+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;E+00******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************-0;E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-******************0;E+00");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0E+00*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************-0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*******************0E+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0E+00*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************-0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*******************0E+00");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.E+00******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************-0.E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-******************0.E+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;E+00******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************-0;E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-******************0;E+00");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(1);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0e+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0.0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0.0e+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0e+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0;0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0;0e+00");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0e+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0.0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0.0e+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0e+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0;0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0;0e+00");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0e+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0.0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0.0e+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0e+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0;0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0;0e+00");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0e+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0.0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0.0e+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0e+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0;0e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0;0e+00");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0E+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0.0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0.0E+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0E+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0;0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0;0E+00");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0E+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0.0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0.0E+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0E+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0;0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0;0E+00");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0E+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0.0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0.0E+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0E+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0;0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0;0E+00");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.0E+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0.0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0.0E+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;0E+00*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************-0;0E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-*****************0;0E+00");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(6);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000e+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0.000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0.000000e+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000e+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0;000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0;000000e+00");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000e+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0.000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0.000000e+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000e+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0;000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0;000000e+00");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000e+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0.000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0.000000e+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000e+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0;000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0;000000e+00");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000e+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0.000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0.000000e+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000e+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0;000000e+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0;000000e+00");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000E+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0.000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0.000000E+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000E+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0;000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0;000000E+00");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000E+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0.000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0.000000E+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000E+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0;000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0;000000E+00");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000E+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0.000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0.000000E+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000E+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0;000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0;000000E+00");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0.000000E+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0.000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0.000000E+00");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-0;000000E+00************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "************-0;000000E+00");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "-************0;000000E+00");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(16);
      {
      }
      ios.precision(60);
      {
      }
    }
  }
}

void test6() {
  char str[200];
  std::locale lc = std::locale::classic();
  std::locale lg(lc, new my_numpunct);
  const my_facet f(1);
  {
    double v = 1234567890.125;
    std::ios ios(0);
    std::scientific(ios);
    // %e
    {
      ios.precision(0);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1e+09********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1e+09********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1e+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.e+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1.e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1.e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;e+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1;e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1;e+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1e+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************+1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******************1e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1e+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************+1e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******************1e+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.e+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************+1.e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******************1.e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;e+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************+1;e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******************1;e+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1E+09********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1E+09********************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "********************1E+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.E+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1.E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1.E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;E+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1;E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************1;E+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1E+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************+1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******************1E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1E+09*******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*******************+1E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*******************1E+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.E+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************+1.E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******************1.E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;E+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************+1;E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+******************1;E+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(1);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.2e+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1.2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1.2e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;2e+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1;2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1;2e+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.2e+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1.2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1.2e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;2e+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1;2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1;2e+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.2e+09*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************+1.2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*****************1.2e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;2e+09*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************+1;2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*****************1;2e+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.2e+09*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************+1.2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*****************1.2e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;2e+09*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************+1;2e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*****************1;2e+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.2E+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1.2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1.2E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;2E+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1;2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1;2E+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.2E+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1.2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1.2E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;2E+09******************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1;2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "******************1;2E+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.2E+09*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************+1.2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*****************1.2E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;2E+09*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************+1;2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*****************1;2E+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.2E+09*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************+1.2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*****************1.2E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;2E+09*****************");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "*****************+1;2E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+*****************1;2E+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
      ios.precision(6);
      {
      }
      ios.precision(16);
      {
      }
      ios.precision(60);
      {
        std::nouppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000e+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
        std::uppercase(ios);
        {
          std::noshowpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
          std::showpos(ios);
          {
            std::noshowpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
              }
            }
            std::showpoint(ios);
            {
              ios.imbue(lc);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1.234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
              }
              ios.imbue(lg);
              {
                ios.width(0);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::left(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::right(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
                ios.width(25);
                std::internal(ios);
                {
                  cpp17_output_iterator<char*> iter = f.put(cpp17_output_iterator<char*>(str), ios, '*', v);
                  std::string ex(str, base(iter));
                  assert(ex == "+1;234567890125000000000000000000000000000000000000000000000000E+09");
                  assert(ios.width() == 0);
                }
              }
            }
          }
        }
      }
    }
  }
}

int main(int, char**) {
  test1();
  test2();
  test3();
  test4();
  test5();
  test6();

  return 0;
}
