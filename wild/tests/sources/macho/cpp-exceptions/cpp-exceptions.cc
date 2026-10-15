//#Config:default
//#LinkerDriver:clang++

// Throwing across a frame, which needs `__TEXT,__unwind_info` to exist and be right.
//
// Nothing references that table - libunwind finds it from the section name - and it isn't in the
// input either: it's built from the `__LD,__compact_unwind` entries the compiler emits, one per
// function. Without it libunwind can't find the personality routine or the landing pads, and the
// throw calls `terminate` instead of unwinding, so this test is a crash rather than a wrong answer.

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

struct Tracked {
  std::string name;
  static int live;
  explicit Tracked(std::string n) : name(std::move(n)) { ++live; }
  ~Tracked() { --live; }
};

int Tracked::live = 0;

static int deep(int depth) {
  Tracked guard("depth-" + std::to_string(depth));
  if (depth == 0) {
    throw std::runtime_error("bottom");
  }
  return deep(depth - 1);
}

int main() {
  try {
    deep(4);
    return 1;
  } catch (const std::exception& e) {
    // Every frame between the throw and here must have been unwound, running each destructor.
    if (Tracked::live != 0) {
      std::cout << "leaked " << Tracked::live << " frames\n";
      return 2;
    }
    if (std::string(e.what()) != "bottom") {
      return 3;
    }
  }

  // Rethrow, and catch by base class, which goes through the personality routine again.
  try {
    try {
      throw std::out_of_range("inner");
    } catch (...) {
      throw;
    }
  } catch (const std::logic_error&) {
    return 42;
  }

  return 4;
}
