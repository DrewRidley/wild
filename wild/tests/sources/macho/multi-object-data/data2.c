extern int main_a;

int c_val = 5;
int* c_p = &c_val;
int* c_cross = &main_a;

// See the comment in data1.c.
int c_sum(void) { return *c_p + *c_cross; }
