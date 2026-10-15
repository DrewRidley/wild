int level1(int x);

static int helper_base = 15;

int helper_value(void) { return level1(helper_base) - 6; }
