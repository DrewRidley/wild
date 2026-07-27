// Second input for thread-local.c. Kept in a separate object so that the reference to `elsewhere`
// from the main object has to be resolved to a definition that the referencing object never saw.
_Thread_local int elsewhere = 7;

int bump_elsewhere(void) { return ++elsewhere; }
