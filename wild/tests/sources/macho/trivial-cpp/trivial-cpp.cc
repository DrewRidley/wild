//#LinkerDriver:clang++
//#DiffIgnore:section.__unwind_info
// Remove this once wild builds __unwind_info from __compact_unwind.
//#ExpectWarningWild:no __unwind_info

#include <iostream>

struct Foo {
  static int foo() { return 42; }
};

int main() {
  std::cout << "hello world\n" << std::endl;
  return Foo::foo();
}
