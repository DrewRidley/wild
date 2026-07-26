extern int c_val;

int b_val = 4;
int* b_p = &b_val;
int* b_cross = &c_val;

// Present so that this object contributes a __text section as well as __data.
// A Mach-O input object with no code currently makes wild panic - that case is
// covered separately by the `data-only-object` test.
int b_sum(void) { return *b_p + *b_cross; }
