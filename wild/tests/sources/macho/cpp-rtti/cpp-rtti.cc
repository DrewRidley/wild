//#Config:default
//#LinkerDriver:clang++

// C++ with virtual functions and RTTI, which puts two things in initialised data that plain C
// never produces.
//
// libc++ marks a `type_info` whose name isn't unique across images by setting the top bit of the
// name pointer, so the slot holds a tagged pointer rather than an address. A chained rebase keeps
// the top byte in its own `high8` field for exactly this reason - fold it into the offset instead
// and the value is far too large to encode, which fails the link outright.
//
// The vtable of a class with a base is also reached as `&vtable + 0x10`, skipping the two header
// words, and that vtable is imported from libc++. A displacement from an imported symbol can't be
// applied here, because the address isn't known until dyld binds it - it has to travel in the
// bind's own addend field.

#include <iostream>
#include <typeinfo>
#include <string>

struct Base {
  virtual ~Base() = default;
  virtual int value() const { return 1; }
};

struct Derived : Base {
  int value() const override { return 41; }
};

int main() {
  Derived d;
  Base *b = &d;

  // Forces the typeinfo comparison path that reads the tagged name pointer.
  if (typeid(*b) != typeid(Derived)) {
    std::cout << "typeid mismatch\n";
    return 1;
  }
  if (typeid(*b) == typeid(Base)) {
    return 2;
  }

  Base *plain = new Base();
  int total = b->value() + plain->value();
  delete plain;

  std::cout << "total=" << total << "\n";
  return total;
}
