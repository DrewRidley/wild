// The branch target, placed last so that everything above pushes it out of reach.
.section __TEXT,__text
.p2align 2
.globl _far_target
_far_target:
    mov w0, #42
    ret
