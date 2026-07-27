// The assembler turns a difference between two symbols into an ARM64_RELOC_SUBTRACTOR naming the
// symbol to subtract, immediately followed by an ARM64_RELOC_UNSIGNED naming the other one.

.section __DATA,__data
.p2align 3
.globl _distance
_distance:
    .quad _target_b - _target_a

.globl _anchor
_anchor:
    .long 1
    .long 2
    .long 3
    .long 4

.globl _displaced
_displaced:
    .quad _anchor + 8

.section __TEXT,__text
.p2align 2
.globl _target_a
_target_a:
    ret
.globl _target_b
_target_b:
    ret
