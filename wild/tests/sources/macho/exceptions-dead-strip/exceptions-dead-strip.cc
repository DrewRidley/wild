//#Config:default
//#LinkerDriver:clang++
//#LinkArgs:-Wl,-dead_strip
//#NoSym:_never_called
//#DiffIgnore:section.__gcc_except_tab

// Dropping unwind data without dropping what unwinding needs.
//
// `__unwind_info` is sized from the functions that survive, and `__gcc_except_tab` is no longer
// kept whole - a landing pad stays only because a `__compact_unwind` entry for a live function
// still names it. That naming is by section and offset rather than by symbol, so it is followed
// separately from the ordinary symbol walk, and getting it wrong is quiet: the link succeeds, the
// tables are merely too small, and the program aborts the first time it actually throws.
//
// So the assertion that matters is behavioural. These exceptions have to be thrown across a
// non-inlined call and caught, which needs the landing pad to have survived; `never_called` is here
// to confirm that something unreachable still goes.

#include <cstdio>
#include <stdexcept>
#include <string>

__attribute__((noinline)) int deep(int n) {
    if (n > 2) throw std::runtime_error("boom " + std::to_string(n));
    return n;
}

__attribute__((noinline)) int mid(int n) { return deep(n) + 1; }

int never_called(int n) { throw std::logic_error("never"); return n; }

int main(int argc, char **) {
    int caught = 0;

    try {
        mid(argc + 4);
    } catch (const std::exception &e) {
        printf("caught: %s\n", e.what());
        caught = 1;
    }

    try {
        throw 7;
    } catch (int v) {
        printf("caught int %d\n", v);
        caught += v;
    }

    return caught == 8 ? 42 : 1;
}
