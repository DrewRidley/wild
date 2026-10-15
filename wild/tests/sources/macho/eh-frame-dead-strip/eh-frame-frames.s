// Two functions whose unwind rules the compact encoding can't express, so the assembler describes
// them with DWARF instead: an FDE in `__eh_frame`, and a `__compact_unwind` entry that says to go
// and read it. What makes them uncompactable is where the frame record is saved - the compact
// encodings assume the standard `stp x29, x30, [sp, #-16]!` shape and these deliberately don't
// use it.

.text

.p2align 2
.globl _frame_used
_frame_used:
    .cfi_startproc
    sub sp, sp, #64
    .cfi_def_cfa_offset 64
    stp x29, x30, [sp, #40]
    .cfi_offset w30, -16
    .cfi_offset w29, -24
    mov w0, #42
    ldp x29, x30, [sp, #40]
    add sp, sp, #64
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc

// Nothing refers to this one. Its FDE names it, which used to be enough to keep it: `__eh_frame`
// was kept whole and every function an FDE mentioned came with it. Now the FDE follows the
// function rather than the other way round, so both go.
.p2align 2
.globl _frame_unused
_frame_unused:
    .cfi_startproc
    sub sp, sp, #64
    .cfi_def_cfa_offset 64
    stp x29, x30, [sp, #40]
    .cfi_offset w30, -16
    .cfi_offset w29, -24
    mov w0, #99
    ldp x29, x30, [sp, #40]
    add sp, sp, #64
    .cfi_def_cfa_offset 0
    ret
    .cfi_endproc

.subsections_via_symbols
