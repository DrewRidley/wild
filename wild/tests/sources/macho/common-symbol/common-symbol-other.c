int shared_counters[8];
char aligned_buf[64] __attribute__((aligned(64), visibility("hidden")));

int* other_counters(void) { return shared_counters; }
char* other_aligned_buf(void) { return aligned_buf; }

int other_sum(void) {
  int total = 0;
  for (int i = 0; i < 8; i++) {
    total += shared_counters[i];
  }
  return total;
}
