#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "../src/libdft_cmd.h"

// A few nops makes it easier to find the inline asm snippet
#define NOPS "nop; nop; nop;"
#define BANNER "================================\n"
#define EXP "[EXPECTED] "
# define barrier() __asm__ __volatile__("": : :"memory")

void __attribute__((noinline)) __libdft_set_taint(void *p, unsigned int v, size_t n) { barrier(); }
void __attribute__((noinline)) __libdft_get_taint(void *p) { barrier(); }
void __attribute__((noinline)) __libdft_getval_taint(uint64_t v) { barrier(); }
void __attribute__((noinline)) __libdft_getvaln_taint(uint64_t v) { barrier(); }

void test_mov_32bit_extend(uint64_t tainted) {
  asm(	NOPS
	"mov %[atainted], %%rdi;"	// rdi = should be tainted
	"mov $0, %%edi;" 		// rdi = should be untainted
	"call __libdft_getval_taint;"
	NOPS
	: : [atainted] "r" (tainted) : "rdi");
}

void test_movsx_8u_to_16(uint8_t tainted) {
  asm(	NOPS
	"xor %%rax, %%rax;"		// clear rax
	"xor %%rdi, %%rdi;"		// clear rdi
	"mov %[atainted], %%ah;"	// ah = should be tainted (upper 8 of rax)
	"movsx %%ah, %%di;" 		// dil = should be tainted, dih = should be cleared
	"call __libdft_getvaln_taint;"
	NOPS
	: : [atainted] "r" (tainted) : "rdi", "rax");
}

int main(int argc, char** argv) {
  uint64_t tainted64 = 1; __libdft_set_taint(&tainted64, 34, 8);
  uint8_t tainted8 = 1; __libdft_set_taint(&tainted8, 34, 1);

  printf(BANNER EXP "v: 0, lbl: 0, ...\n");
  test_mov_32bit_extend(tainted64);

  printf(BANNER);
  printf(EXP "byte: 0, v: 1, lbl: 34, ...\n");
  printf(EXP "byte: 1, v: 0, lbl: 0, ...\n");
  printf(EXP "byte: 2, v: 0, lbl: 0, ...\n");
  test_movsx_8u_to_16(tainted8);

  // TODO: Test e.g., "mov $0, %%di;" to make sure only the lower 2 bytes propagate taint

  return 0;
}
