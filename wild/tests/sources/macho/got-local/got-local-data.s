// `@GOT` produces ARM64_RELOC_POINTER_TO_GOT: the value is the address of the GOT entry for
// `_target`, not the address of `_target`. It's stored as a 4-byte PC-relative delta, which is the
// form an `__eh_frame` CIE uses to name its personality routine.

.section __TEXT,__text
.p2align 2
.globl _target
_target:
    mov w0, #7
    ret

.section __DATA,__data
.p2align 2
.globl _got_delta
_got_delta:
    .long _target@GOT - _got_delta
