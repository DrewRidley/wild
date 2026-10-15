// Built into a dylib by wild, then linked against.
int lib_value = 40;

int lib_add(int n) { return n + lib_value; }

static int secret(int n) { return n * 2; }

int lib_uses_hidden(int n) { return secret(n); }

// Only visible inside the dylib, so nothing outside it may bind to this name.
__attribute__((visibility("hidden"))) int lib_hidden(int n) { return n - 1; }
