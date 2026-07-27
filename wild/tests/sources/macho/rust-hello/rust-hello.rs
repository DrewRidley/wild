//#Config:default
//#DiffIgnore:section.__eh_frame
//#DiffIgnore:section.__const

// Linking a Rust program end to end. This is the only thing in the corpus that exercises an object
// produced by something other than the C toolchain, and it covers two things nothing else can:
//
// Symbol ID 0 is the linker's "undefined" sentinel, so no real symbol may occupy it. rustc
// synthesises its exported-symbols object with the `object` crate rather than an assembler, so -
// uniquely - that object has no local symbols, which puts a genuine undefined external at nlist
// index 0. Every compiler-generated object starts with an `ltmp0` local instead, so nothing else
// here would notice the first symbol being dropped.
//
// It also pulls in `libstd`, which brings sections a C object never produces: constant pools,
// `__common`, embedded bitcode and DWARF - plus threads, which need `__thread_vars` to be right.

use std::collections::HashMap;

fn main() {
    let mut counts: HashMap<&str, u32> = HashMap::new();
    for word in ["a", "b", "a", "c", "a"] {
        *counts.entry(word).or_insert(0) += 1;
    }

    let mut keys: Vec<_> = counts.keys().copied().collect();
    keys.sort_unstable();
    for k in keys {
        println!("{k} = {}", counts[k]);
    }

    let handle = std::thread::spawn(|| (1..=10).sum::<u32>());
    println!("sum = {}", handle.join().unwrap());

    std::process::exit(if counts["a"] == 3 { 42 } else { 1 });
}
