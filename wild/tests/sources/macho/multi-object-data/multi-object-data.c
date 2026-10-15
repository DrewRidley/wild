//#Config:default
//#LinkerDriver:clang
//#Object:data1.c
//#Object:data2.c
//#ExpectSym:_main

// Pointers in initialised data spread across three input objects, including
// pointers that cross object boundaries in both directions. Each object
// contributes its own __data slots, so the resulting rebases are scattered over
// the whole __DATA segment - this is what exercises page-chain construction
// rather than the single-slot case in ptr-in-data.

#include <stdio.h>

extern int b_val;
extern int* b_p;
extern int* b_cross;
extern int c_val;
extern int* c_p;
extern int* c_cross;

int main_a = 3;
int* main_p = &main_a;
int* main_cross = &b_val;

int main(void) {
  int total = *main_p + *main_cross + *b_p + *b_cross + *c_p + *c_cross;
  if (total != 24) {
    printf("bad total: %d\n", total);
    return 1;
  }
  if (main_cross != &b_val || b_cross != &c_val || c_cross != &main_a) {
    return 2;
  }
  printf("total=%d\n", total);
  return 42;
}
