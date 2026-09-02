//#Config:default
//#LinkerDriver:clang
//#ExpectSym:_pointers

// Zerofill must come after every chained fixup in the file, which is a segment-ordering rule:
// `__DATA` ends in `__bss`, so its memory footprint runs past its file bytes, and dyld's kernel
// page-in linking sizes each segment's file claim by memory. A fixup-bearing segment placed after
// `__DATA` starts inside the file range the kernel attributes to `__DATA`, and the fixups on the
// contested page are silently never applied - the program then dereferences a raw
// `dyld_chained_ptr_64` encoding and dies. ld64's order - `__DATA_CONST` first, `__DATA` with its
// zerofill last - keeps file and memory congruent for every segment that has fixups, and this test
// holds wild to it.
//
// The ingredients: enough `__bss` that `__DATA`'s memory rounds to more pages than its file, and a
// fixup on the first page of `__DATA_CONST` that the program can't run without. The struct below
// pins both a bind (an imported function) and a rebase (a local one) onto that page; the bss array
// is static so it lands in `__bss` rather than becoming a tentative definition.

#include <unistd.h>

static char lots_of_zeroes[100000];

static int forty_two(void) { return 42; }

struct table {
    pid_t (*imported)(void);
    int (*local)(void);
};

const struct table pointers = {getpid, forty_two};

// A mutable pointer, so `__DATA` itself carries a fixup: a segment contributes a
// `dyld_chained_starts_in_segment` record - and therefore a page-in region whose page count can be
// wrong - only when at least one fixup lands in it.
int (*mutable_pointer)(void) = forty_two;

int main(void) {
    if (pointers.imported() <= 0) {
        return 1;
    }

    for (unsigned i = 0; i < sizeof(lots_of_zeroes); i++) {
        if (lots_of_zeroes[i] != 0) {
            return 1;
        }
    }

    if (mutable_pointer() != 42) {
        return 1;
    }

    return pointers.local();
}
