// Sections that exercise the placement paths: a constant pool, a section wild has no built-in ID
// for, and the two zerofill sections. Written by hand because the compiler picks which of these to
// emit and won't reliably produce all four from one translation unit.

.section __TEXT,__literal16,16byte_literals
.p2align 4
.globl _literal16
_literal16:
    .quad 0x1122334455667788
    .quad 0x99aabbccddeeff00

.section __DATA,__mystuff
.p2align 3
.globl _mystuff
_mystuff:
    .quad 0x0f0f0f0f0f0f0f0f

.section __DATA,__bss,zerofill
.p2align 3
.globl _zeroed
_zeroed:
    .space 8

.section __DATA,__common,zerofill
.p2align 3
.globl _common_value
_common_value:
    .space 8
