#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "../src/libdft_cmd.h"

/*
 * Build entire project with (required for [calculated] test only):
 * - CPPFLAGS=-DLIBDFT_TAG_PTR make clean all #or -DLIBDFT_TAG_PTR_32
 */
int main(int argc, char** argv)
{
	int fd;
	ssize_t count;
	int a = argc, b = argc%2, c = argc/2, d;

	/* Taint all memory */
	printf("\n[tainting all memory]\n");
	__libdft_taint_mem_all();

	/*
	 * Test pointer label propagation.
	 * Note: __libdft_taint_mem_all taints each byte with its own address.
	 */
	c = a+b;

	/*
	 * Test stdin file offset label propagation.
	 * Note: file offsets start at 0x1, 0 is reserved.
	 */
	close(0);
	fd = open("Makefile", O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}
	count = read(fd, &d, 4);
	if (count <= 0) {
		perror("read");
		exit(2);
	}

	/* Dump. */
	printf("[calculated] c @%p = a @%p + b @%p\n", &c, &a, &b);
	__libdft_taint_dump(&a);
	__libdft_taint_dump(&b);
	__libdft_taint_dump(&c);

	printf("\n[stdin-read] %ld bytes into d @%p\n", count, &d);
	__libdft_taint_dump(&count);
	__libdft_taint_dump(&d);

	/*
	 * Sample expected output:
	 * [calculated] c @0x7fffffffe1f8 = a @0x7fffffffe1f0 + b @0x7fffffffe1f4
	 * [taint_dump] addr = 0x7fffffffe1f0, tags = {0x7fffffffe1f0}
	 * [taint_dump] addr = 0x7fffffffe1f4, tags = {0x7fffffffe1f4}
	 * [taint_dump] addr = 0x7fffffffe1f8, tags = {0x7fffffffe1f4, 0x7fffffffe1f0}
	 *
	 * [stdin-read] 4 bytes into d @0x7fffffffe1fc
	 * [taint_dump] addr = 0x7fffffffe200, tags = {LEN}
	 * [taint_dump] addr = 0x7fffffffe1fc, tags = {+0x00000001}
	 */

	/***************************************************************************/
	/***************************************************************************/
	/* Re-taint all memory */
	printf("\n[retainting all memory]\n");
	__libdft_taint_mem_all();

	/* Dump. */
	c += a;
	printf("[calculated] c @%p += a @%p\n", &c, &a);
	__libdft_taint_dump(&a);
	__libdft_taint_dump(&b);
	__libdft_taint_dump(&c);
	__libdft_taint_dump(&count);
	__libdft_taint_dump(&d);

	/*
	 * Sample expected output:
	 * [taint_dump] addr = 0x7fffffffe1f0, tags = {0x7fffffffe1f0}
	 * [taint_dump] addr = 0x7fffffffe1f4, tags = {0x7fffffffe1f4}
	 * [taint_dump] addr = 0x7fffffffe1f8, tags = {0x7fffffffe1f8, 0x7fffffffe1f0} <-- different
	 * [taint_dump] addr = 0x7fffffffe200, tags = {0x7fffffffe200} <-- different
	 * [taint_dump] addr = 0x7fffffffe1fc, tags = {0x7fffffffe1fc} <-- different
	 */

	return 0;
}
