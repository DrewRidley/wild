// Reached from main, so it and what it calls must survive.
static int helper(int n) { return n + 21; }
int actually_called(int n) { return helper(n) - 21 + 21; }

// Nothing refers to these. They are only reachable if the linker keeps whole sections.
int never_called_a(int n) { return n * 3; }
int never_called_b(int n) { return never_called_a(n) + 7; }
int never_referenced_data[64] = {1, 2, 3};
