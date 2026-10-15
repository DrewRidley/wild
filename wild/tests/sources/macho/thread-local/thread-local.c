//#Object:thread-local-other.c
// Linked through the compiler driver so that libSystem, which provides __tlv_bootstrap and
// pthreads, is on the link line - otherwise the link fails earlier on those undefined symbols.
//#LinkerDriver:clang

// A thread-local on Mach-O is reached through a `tlv_descriptor` in `__DATA,__thread_vars` holding
// a thunk, a key and the variable's offset within the thread-local block. The linker fills in the
// offset and binds the thunk to `__tlv_bootstrap`; dyld overwrites the thunk and the key at load
// time, but only for images whose header carries MH_HAS_TLV_DESCRIPTORS.
//
// `counter` lands in `__thread_data` because it has a non-zero initialiser and `zeroed` lands in
// `__thread_bss`, which occupies address space at the end of the template block without occupying
// any of the file. Both are addressed off the same block base, so getting either offset wrong shows
// up here.
_Thread_local int counter = 41;
_Thread_local int zeroed;

// Defined in the other input, so this only works if a thread-local is recognised as one when
// referenced from an object other than the one defining it.
extern _Thread_local int elsewhere;
int bump_elsewhere(void);

static void* worker(void* arg) {
  (void)arg;
  // A second thread gets its own copy of each of these. If it doesn't, the checks in `main` below
  // see the worker's writes and fail.
  counter += 100;
  zeroed += 100;
  bump_elsewhere();
  return 0;
}

// Declared rather than included so that the test doesn't depend on the SDK headers.
int pthread_create(void** thread, const void* attr, void* (*start)(void*), void* arg);
int pthread_join(void* thread, void** retval);

int main(void) {
  void* thread;
  if (pthread_create(&thread, 0, worker, 0) != 0) {
    return 1;
  }
  if (pthread_join(thread, 0) != 0) {
    return 2;
  }

  counter++;
  zeroed += 3;
  bump_elsewhere();

  if (zeroed != 3) {
    return 3;
  }
  if (elsewhere != 8) {
    return 4;
  }
  return counter;
}
