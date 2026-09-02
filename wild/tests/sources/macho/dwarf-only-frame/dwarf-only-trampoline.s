// A function whose unwinding is described only by a hand-written `__eh_frame` FDE - no
// `.cfi_*` directives, so the assembler emits no `__compact_unwind` entry for it. This is the
// shape Cranelift emits for every function: its objects carry FDEs and nothing else.

.text

// Frameless on purpose: x29 stays the caller's, and the return address lives on the stack rather
// than staying in lr, so no compact encoding of a neighbouring function's describes this one. The
// function laid out just before this comes from the C++ side, carries an ordinary frame-pointer
// encoding, and a compact encoding is applied on trust - only the DWARF mode carries anything an
// unwinder can cross-check - so inheriting the neighbour's entry walks a frame-pointer chain this
// function never maintained, and the failure is deterministic rather than depending on luck.
.globl _trampoline
.p2align 2
_trampoline:
Lfunc_begin:
    sub sp, sp, #32
    str x30, [sp, #24]
    blr x0
    ldr x30, [sp, #24]
    add sp, sp, #32
    ret
Lfunc_end:

// The frame descriptions, written out longhand. The section is exactly what clang would emit for
// the same CFI; the point of writing it by hand is that nothing else gets emitted with it. The
// anchor at the start must survive assembly, because the pair of relocations that carry the
// cross-section pc-begin difference need a symbol on each side - so not an `L` name, which the
// assembler folds away, but a lowercase-`l` one, which stays in the object and is the linker's to
// drop, like the `ltmpN` anchors clang generates.
.section __TEXT,__eh_frame,coalesced,no_toc+strip_static_syms+live_support
.p2align 3
ltmp_eh_anchor:

LCIE:
    .long LCIE_end - LCIE_start   // length
LCIE_start:
    .long 0                        // this record is a CIE
    .byte 1                        // version
    .ascii "zR"                    // augmentation: has an FDE pointer encoding
    .byte 0
    .byte 1                        // code alignment factor
    .byte 0x78                     // data alignment factor: -8
    .byte 30                       // return address register: lr
    .byte 1                        // augmentation data length
    .byte 0x1b                     // FDE pointers are pcrel sdata4
    .byte 0x0c, 31, 0              // DW_CFA_def_cfa sp, 0
    .byte 0, 0                     // DW_CFA_nop padding to a 4-byte length
LCIE_end:

LFDE:
    .long LFDE_end - LFDE_start   // length
LFDE_start:
    .long LFDE_start - LCIE       // how far back the CIE is
Lpc_field:
    .long Lfunc_begin - Lpc_field  // the function, as a distance from this very field
    .long Lfunc_end - Lfunc_begin  // how much code the FDE covers
    .byte 0                        // augmentation data length
    .byte 0x44                     // DW_CFA_advance_loc 4: past the sub
    .byte 0x0e, 32                 // DW_CFA_def_cfa_offset 32
    .byte 0x44                     // DW_CFA_advance_loc 4: past the str
    .byte 0x9e, 1                  // DW_CFA_offset x30, [CFA-8]
    .byte 0, 0                     // DW_CFA_nop padding to a 4-byte length
LFDE_end:

.subsections_via_symbols
