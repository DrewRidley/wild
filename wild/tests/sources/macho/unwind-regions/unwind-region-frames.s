// One symbol, two unwind regions. Hand-written assembly - aws-lc's curve code is the live example
// - describes stretches of a single function separately: each region gets its own
// `__compact_unwind` entry and, when the shape is one the compact encoding can't express, its own
// FDE. Every one of those FDEs names the same symbol, because the region boundaries are local
// labels that don't survive assembly; where the region starts is carried in the pc-begin field's
// addend instead. Pairing FDEs with `__compact_unwind` entries by symbol address alone collapses
// them all onto the function's start, and every region after the first loses its frame.
//
// The frame records are saved away from the standard `stp x29, x30, [sp, #-16]!` spot on purpose,
// which is what forces DWARF mode.

.text

.p2align 2
.globl _regions
_regions:
    .cfi_startproc
    sub sp, sp, #64
    .cfi_def_cfa_offset 64
    stp x29, x30, [sp, #40]
    .cfi_offset w30, -16
    .cfi_offset w29, -24
    ldp x29, x30, [sp, #40]
    add sp, sp, #64
    .cfi_def_cfa_offset 0
    b Lsecond
    .cfi_endproc

Lsecond:
    .cfi_startproc
    sub sp, sp, #32
    .cfi_def_cfa_offset 32
    stp x29, x30, [sp, #8]
    .cfi_offset w30, -16
    .cfi_offset w29, -24
    mov w0, #42
    ldp x29, x30, [sp, #8]
    add sp, sp, #32
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc

.subsections_via_symbols
