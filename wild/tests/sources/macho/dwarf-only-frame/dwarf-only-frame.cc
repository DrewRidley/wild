//#Config:default
//#LinkerDriver:clang++
//#Object:dwarf-only-trampoline.s
//#ExpectSym:_trampoline

// Unwinding through a function that only DWARF describes.
//
// `__unwind_info` has no gaps: an entry's reach ends where the next entry begins, so a function
// the table doesn't mention is claimed by its neighbour's entry, and unwinding through it restores
// registers by the wrong function's rules - the catch then runs with corrupted callee-saved
// registers, or the search misses the handler altogether. A compiler that describes unwinding only
// in `__eh_frame` - Cranelift emits nothing else, and it's how surrealdb's dev builds found this -
// contributes exactly such functions, so every FDE whose function has no `__compact_unwind` entry
// has to get a table entry deferring to it, the way ld64 synthesizes one.
//
// The trampoline in the accompanying assembly is such a function. The throw below unwinds through
// its frame on the way to the catch, and the catch proves the registers came back intact by using
// state it held across the throw.

extern "C" int trampoline(int (*callee)());
extern "C" int decoy();

namespace {

int thrower() { throw 7; }

} // namespace

int main() {
    // State the catching frame keeps alive across the throw, so a bad register restore during
    // unwinding has something to visibly destroy. The decoy's answer is part of it, which is also
    // what keeps the decoy - and the wrong unwind rules it supplies - in the image.
    int kept = 14 + decoy();

    try {
        return trampoline(thrower);
    } catch (int value) {
        return kept + value;
    }
}

namespace {

int twenty_one() { return 21; }

} // namespace

// Defined last so its code sits at the end of this object, right before the trampoline's: it is
// the neighbour whose compact frame-pointer encoding the trampoline's addresses fall to when the
// table has no entry of their own. The call is what obliges it to have a frame.
extern "C" int decoy() { return twenty_one(); }
