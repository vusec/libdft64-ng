#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "../src/libdft_cmd.h"

#define TAINTED8 uint8_t tainted8 = 1; __libdft_set_taint(&tainted8, 34, 1)
#define TAINTED16 uint64_t tainted16 = 1; __libdft_set_taint(&tainted16, 34, 2)
#define TAINTED32 uint64_t tainted32 = 1; __libdft_set_taint(&tainted32, 34, 4)
#define TAINTED64 uint64_t tainted64 = 1; __libdft_set_taint(&tainted64, 34, 8)
// A few nops makes it easier to find the inline asm snippet
#define NOPS "nop; nop; nop;"
#define BANNER "================================"
#define TEST_BANNER(...) printf(BANNER " Running " __VA_ARGS__); printf("...\n")
#define EXP "[EXPECTED]    "
# define barrier() __asm__ __volatile__("": : :"memory")

void __attribute__((noinline)) __libdft_set_taint(void *p, unsigned int v, size_t n) { barrier(); }
void __attribute__((noinline)) __libdft_get_taint(void *p) { barrier(); }
void __attribute__((noinline)) __libdft_getval_taint(uint64_t v) { barrier(); }
void __attribute__((noinline)) __libdft_set_tag_print_decimal(bool b) { barrier(); }
void __attribute__((noinline)) __libdft_set_val_print_decimal(bool b) { barrier(); }

// =====================================================================

void test_mov_32bit_extend_const(uint64_t tainted) {
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
	"call __libdft_getval_taint;"
	NOPS
	: : [atainted] "r" (tainted) : "rdi", "rax");
}

void test_mov_32bit_extend_reg(uint64_t tainted, uint32_t untainted) {
  asm(	NOPS
	"mov %[atainted], %%rdi;"	// rdi = tainted
	"mov %[auntainted], %%edi;"	// rdi = should be completely untainted
	"call __libdft_getval_taint;"
	NOPS
	: : [atainted] "r" (tainted), [auntainted] "r" (untainted) : "rdi");
}

void test_signextend() {
  TAINTED64; TAINTED8;
  __libdft_set_val_print_decimal(true);

  TEST_BANNER("test_mov_32bit_extend_const");
  printf(EXP "val: 0, taint: [[], [], [], [], [], [], [], []]\n");
  test_mov_32bit_extend_const(tainted64);

  TEST_BANNER("test_movsx_8u_to_16");
  printf(EXP "val: 1, taint: [[+34], [], [], [], [], [], [], []]\n");
  test_movsx_8u_to_16(tainted8);

  TEST_BANNER("test_mov_32bit_extend_reg");
  printf(EXP "val: 1234, taint: [[], [], [], [], [], [], [], []]\n");
  test_mov_32bit_extend_reg(tainted64, 1234);
}

// =====================================================================

void test_push_var(uint64_t tainted64, uint16_t tainted16) {
  // Note: 4-byte pushes/pops are not supported by x86-64
  asm(	NOPS
	"push %[atainted64];"
	"pop %%rdi;"
	"call __libdft_getval_taint;" // rdi (all 8) = should be tainted
	"pushq $22;"
	"pop %%rdi;"
	"call __libdft_getval_taint;" // rdi (all 8) = should be untainted
	"push %[atainted16];"
	"pop %%di;"
	"call __libdft_getval_taint;" // di (lower 2) = should be tainted
	NOPS
	: : [atainted64] "r" (tainted64), [atainted16] "r" (tainted16) : "rdi");
}

void test_push() {
  TAINTED64; TAINTED16;
  __libdft_set_val_print_decimal(true);

  TEST_BANNER("test_push");
  printf(EXP "val: 1, taint: [[+34], [+34], [+34], [+34], [+34], [+34], [+34], [+34]]\n");
  printf(EXP "val: 22, taint: [[], [], [], [], [], [], [], []]\n");
  printf(EXP "val: 1, taint: [[+34], [+34], [], [], [], [], [], []]\n");
  test_push_var(tainted64, tainted16);
}

// =====================================================================

void test_mul_r2r(uint64_t tainted) {
  asm(	NOPS
	// Start from cleared vals/taint
	"xor %%rax, %%rax;"
	"xor %%rdx, %%rdx;"
	"xor %%rdi, %%rdi;"
	// Mul
	"mov $1234, %%rax;"		// rax = should be untainted
	"mov %[atainted], %%rdi;"	// rdi = should be tainted
	"mulq %%rdi;" 			// rdx:rax = 1234 * rdi = tainted
	// Eval result
	"push %%rdx;"
	"push %%rax;"
	"pop %%rdi;"
	"call __libdft_getval_taint;"	// Testing result's lower bits (rax)
	"pop %%rdi;"
	"call __libdft_getval_taint;"	// Testing result's upper bits (rdx)
	NOPS
	: : [atainted] "r" (tainted) : "rax", "rdx", "rdi");
}

void test_mul_m2r(uint64_t *tainted) {
  asm(	NOPS
	// Start from cleared vals/taint
	"xor %%rax, %%rax;"
	"xor %%rdx, %%rdx;"
	"xor %%rdi, %%rdi;"
	// Mul
	"mov $1234, %%rax;"		// rax = should be untainted
	"mov %[atainted], %%rdi;"	// rdi = should be tainted
	"mulq (%%rdi);" 		// rdx:rax = 1234 * [rdi] = tainted
	// Eval result
	"push %%rdx;"
	"push %%rax;"
	"pop %%rdi;"
	"call __libdft_getval_taint;"	// Testing result's lower bits (rax)
	"pop %%rdi;"
	"call __libdft_getval_taint;"	// Testing result's upper bits (rdx)
	NOPS
	: : [atainted] "m" (tainted) : "rax", "rdx", "rdi", "memory");
}

void test_mul() {
  TAINTED64;
  __libdft_set_val_print_decimal(true);

  TEST_BANNER("test_mul_r2r");
  printf(EXP "val: 1234, taint: [[+34], [+34], [+34], [+34], [+34], [+34], [+34], [+34]]\n");
  printf(EXP "val: 0, taint: [[+34], [+34], [+34], [+34], [+34], [+34], [+34], [+34]]\n");
  test_mul_r2r(tainted64);

  TEST_BANNER("test_mul_m2r");
  printf(EXP "val: 1234, taint: [[+34], [+34], [+34], [+34], [+34], [+34], [+34], [+34]]\n");
  printf(EXP "val: 0, taint: [[+34], [+34], [+34], [+34], [+34], [+34], [+34], [+34]]\n");
  test_mul_m2r(&tainted64);
}

// =====================================================================

void test_masking_and64_i2r(uint64_t tainted64) {
  asm(	NOPS
	"mov %[atainted64], %%rdi;"		// rdi = all bytes (i.e., 0--7) should be tainted
	"and $0xffffffffff00ff00, %%rdi;" 	// rdi = all bytes except 0 and 2 should be tainted
	"call __libdft_getval_taint;"
	NOPS
	: : [atainted64] "r" (tainted64) : "rdi");
}

void test_masking_and64_i2m(uint64_t *tainted64) {
  asm(	NOPS
	"mov %[atainted64], %%rdi;"		// rax = all bytes (i.e., 0--7) should be tainted
	"andq $0x00ff00ff, (%%rdi);" 		// rax = bytes 0 and 2 should be tainted
	"call __libdft_get_taint;"
	NOPS
	: [atainted64] "+m" (tainted64) : : "rdi", "memory");
}

void test_masking_and64_r2r(uint64_t tainted32) {
  asm(	NOPS
	"mov %[atainted32], %%rdi;"		// rdi = bytes 0, 1, 2, and 3 should be tainted
	"mov $0xffff0000ff0000ff, %%rax;"
	"and %%rax, %%rdi;" 			// rdi = bytes 0 and 3 should be tainted
	"call __libdft_getval_taint;"
	NOPS
	: : [atainted32] "r" (tainted32) : "rdi", "rax");
}

void test_masking_or16_m2r(uint16_t* tainted16) {
  asm(	NOPS
	"mov $0x000000000000ff00, %%rdi;"
	"mov %[atainted16], %%rax;"
	"or (%%rax), %%di;"
	"call __libdft_getval_taint;"
	NOPS
	: : [atainted16] "m" (tainted16) : "rdi", "rax");
}

void test_masking_or32_r2m(uint64_t* tainted32) {
  asm(	NOPS
	"mov $0x00ff00ff, %%eax;"
	"mov %[atainted32], %%rdi;"
	"or %%eax, (%%rdi);"
	"call __libdft_get_taint;"
	NOPS
	: [atainted32] "+m" (tainted32) : : "rdi", "rax", "memory");
}

void test_masking() {
  __libdft_set_val_print_decimal(false);
  TEST_BANNER("test_masking_and64_i2r");
  uint64_t tainted64and = 0x12345678deadbeef; __libdft_set_taint(&tainted64and, 34, 8);
  printf(EXP "val: 0x12345678de00be00, taint: [[], [+34], [], [+34], [+34], [+34], [+34], [+34]]\n");
  test_masking_and64_i2r(tainted64and);

  TEST_BANNER("test_masking_and64_i2m");
  tainted64and = 0x12345678deadbeef; __libdft_set_taint(&tainted64and, 34, 8);
  printf(EXP "addr: %p, val: 0xad00ef, taint: [[+34], [], [+34], [], [], [], [], []]\n", &tainted64and);
  test_masking_and64_i2m(&tainted64and);

  TEST_BANNER("test_masking_and64_r2r");
  uint64_t tainted32and = 0x12345678deadbeef; __libdft_set_taint(&tainted32and, 34, 4);
  printf(EXP "val: 0x12340000de0000ef, taint: [[+34], [], [], [+34], [], [], [], []]\n");
  test_masking_and64_r2r(tainted32and);

  TEST_BANNER("test_masking_or16_m2r");
  uint16_t tainted16 = 0x1234; __libdft_set_taint(&tainted16, 34, 2);
  printf(EXP "val: 0xff34, taint: [[+34], [], [], [], [], [], [], []]\n");
  test_masking_or16_m2r(&tainted16);

  TEST_BANNER("test_masking_or32_r2m");
  uint64_t tainted32 = 0x0000000012345678; __libdft_set_taint(&tainted32, 34, 4);
  printf(EXP "addr: %p, val: 0x12ff56ff, taint: [[], [+34], [], [+34], [], [], [], []]\n", &tainted32);
  test_masking_or32_r2m(&tainted32);
}

// =====================================================================

void test_loadptrprop64(uint64_t *tainted64) {
  asm(	NOPS
	"mov %[atainted64], %%rax;"
	"movq (%%rax), %%rdi;"
	"call __libdft_getval_taint;"
	NOPS
	: : [atainted64] "m" (tainted64) : "rdi", "rax");
}

void test_loadptrprop32(uint32_t *tainted32) {
  asm(	NOPS
	"xor %%rdi, %%rdi;"		// clear rdi
	"mov %[atainted32], %%rax;"
	"mov (%%rax), %%edi;"
	"call __libdft_getval_taint;"
	NOPS
	: : [atainted32] "m" (tainted32) : "rdi", "rax");
}

void test_loadptrprop() {
  size_t i;
  __libdft_set_val_print_decimal(false);

  TEST_BANNER("test_loadptrprop64");
  uint64_t tainted64_lpp = 0x12345678deadbeef; __libdft_set_taint(&tainted64_lpp, 34, 8);
  uint64_t *ptainted64_lpp = &tainted64_lpp;
  for (i = 0; i < 4; i++) __libdft_set_taint((uint32_t*)((uint64_t)&ptainted64_lpp+i), 100+i, 1); // Taint the lower 4 bytes of the pointer differently
  printf(EXP "TBD, depending on how we want to implement load pointer propagation...\n");
  test_loadptrprop64(ptainted64_lpp);

  TEST_BANNER("test_loadptrprop32");
  uint32_t tainted32_lpp = 0x12345678; __libdft_set_taint(&tainted32_lpp, 34, 4);
  uint32_t *ptainted32_lpp = &tainted32_lpp;
  for (i = 0; i < 8; i++) __libdft_set_taint((uint32_t*)((uint64_t)&ptainted32_lpp+i), 100+i, 1); // Taint all 8 bytes of the pointer differently
  printf(EXP "TBD, depending on how we want to implement load pointer propagation...\n");
  //__libdft_getval_taint((uint64_t)ptainted32_lpp);
  test_loadptrprop32(ptainted32_lpp);
}


// =====================================================================

int main(int argc, char** argv) {
  __libdft_set_tag_print_decimal(true);

  test_signextend();
  test_push();
  test_mul();
  test_masking();
  test_loadptrprop();
  // TODO: Test e.g., "mov $0, %%di;" to make sure only the lower 2 bytes propagate taint

  printf(BANNER "\n*** TODO: Make a script to check whether the expected output and the actual output are the same ***\n");
  return 0;
}
