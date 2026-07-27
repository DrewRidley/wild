//#Config:default

// Rust unwinding, which needs `__unwind_info` like C++ does but reaches it differently.
//
// Most of libstd's functions can't be described by a compact encoding - over 900 of them - so their
// entries say `UNWIND_ARM64_MODE_DWARF` and name a frame in `__eh_frame` by its offset. That means
// `__eh_frame` has to be emitted as well, and the offsets rewritten: each entry's offset is into
// the object it came from, and the output holds every object's frames concatenated.
//
// Rust's personality routine is also defined in the image rather than imported from a dylib, which
// is why the table's personality array needs a GOT slot for a locally defined symbol.

fn risky(n: i32) -> i32 {
    if n < 0 {
        panic!("negative: {n}");
    }
    n * 2
}

struct Guard;

static mut DROPPED: bool = false;

impl Drop for Guard {
    fn drop(&mut self) {
        unsafe { DROPPED = true };
    }
}

fn main() {
    let ok = std::panic::catch_unwind(|| risky(21)).ok();

    // Silence the panic messages so the test's stderr is stable.
    std::panic::set_hook(Box::new(|_| {}));

    let caught = std::panic::catch_unwind(|| {
        let _guard = Guard;
        risky(-1)
    })
    .is_err();

    // A panic has to unwind out of a thread and be delivered through the join handle.
    let thread_err = std::thread::spawn(|| risky(-5)).join().is_err();

    let dropped = unsafe { DROPPED };
    println!("ok={ok:?} caught={caught} thread_err={thread_err} dropped={dropped}");

    std::process::exit(if ok == Some(42) && caught && thread_err && dropped {
        42
    } else {
        1
    });
}
