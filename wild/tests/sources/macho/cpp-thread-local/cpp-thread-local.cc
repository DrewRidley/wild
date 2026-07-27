//#Config:default
//#LinkerDriver:clang++
//#DiffIgnore:section.__unwind_info
//#ExpectWarningWild:no __unwind_info

// A thread-local with a non-trivial constructor, which needs three things a plain `_Thread_local
// int` doesn't.
//
// The constructor runs from a function clang puts in `__TEXT,__StaticInit` rather than `__text`.
// A section we don't recognise goes to `__DATA`, and code in `__DATA` faults on the first
// instruction fetched - so an unrecognised *code* section is a crash, not a size difference.
//
// The destructor is registered with `__cxa_thread_atexit`, which takes `___dso_handle` to say which
// image it belongs to. That symbol is defined by the linker, not by any object.
//
// And the variable's address is an offset into the block dyld copies per thread, so nothing may
// come between `__thread_data` and `__thread_bss` - otherwise the offsets run past the end of what
// dyld allocated and it refuses to load the image at all.

#include <cstdio>
#include <string>
#include <thread>

thread_local std::string label = "abc";
thread_local int counter = 4;

static int total;

int main() {
  total += (int)label.size() + counter;

  std::thread worker([] {
    // A second thread gets its own copy, constructed on first use.
    total += (int)label.size() + counter;
  });
  worker.join();

  printf("%d\n", total);
  return total == 14 ? 42 : 1;
}
