#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "../src/libdft_cmd.h"

// A few nops makes it easier to find the inline asm snippet
#define NOPS "nop; nop; nop;"
#define BANNER "================================\n"
# define barrier() __asm__ __volatile__("": : :"memory")

void __attribute__((noinline)) __libdft_set_taint(void *p, unsigned int v, size_t n) { barrier(); }
void __attribute__((noinline)) __libdft_get_taint(void *p) { barrier(); }
void __attribute__((noinline)) __libdft_getval_taint(uint64_t v) { barrier(); }

void test_mov_32bit_extend(uint64_t tainted) {
  asm(	NOPS
	"mov %[atainted], %%rdi;"	// rdi = should be tainted
	"mov $0, %%edi;" 		// rdi = should be untainted
	"mov %%rdi, %%rdi;"
	"call __libdft_getval_taint;"
	NOPS
	: : [atainted] "r" (tainted) : "rdi");
}

int main(int argc, char** argv) {
  uint64_t tainted = 1; __libdft_set_taint(&tainted, 34, 8);

  printf(BANNER "Expected output: No taint.\n"); test_mov_32bit_extend(tainted);
  // TODO: Test e.g., "mov $0, %%di;" to make sure only the lower 2 bytes propagate taint

  return 0;
}
