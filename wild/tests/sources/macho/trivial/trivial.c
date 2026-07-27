//#Object:runtime.c
//#ExpectSym:_main
//#TestUpdateInPlace:true
//#TestRelinkAfterExec:true

#include "../common/runtime.h"

void main(void) { exit_syscall(42); }
