/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tagmap.h"
#include "debug.h"
#include "memory_map.h"
#include "def.h"

#include <inttypes.h>
#include <sys/types.h>
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/wait.h>

// =====================================================================
// Globals and helpers
// =====================================================================

#ifdef LIBDFT_TAG_PTR

#define PAGE_SIZE 4096

#ifndef __NR_userfaultfd
#define __NR_userfaultfd 323
#endif

#define errExit(msg)        \
	do                      \
	{                       \
		LOG_ERR(msg);        \
		exit(EXIT_FAILURE); \
	} while (0)

#ifdef DEBUG_MEMTAINT
#define LOG_MEMTAINT(...) LOG_OUT("[memtaint] " __VA_ARGS__)
#else
#define LOG_MEMTAINT(...)
#endif

static int tagmap_all_tainted = 0;
static void *shadow_addr, *reserved_addr;
static size_t shadow_size, reserved_size;
static bool addr_is_kernel(void * addr) { return addr > (void*)0x7fffffffffff; }
static bool addr_is_shadow(void * addr) { return (addr >= shadow_addr) && (addr < (uint8_t*)shadow_addr + shadow_size); }
static bool addr_is_reserved(void * addr) { return (addr >= reserved_addr) && (addr < (uint8_t*)reserved_addr + reserved_size); }

static int
do_ioctl(int fd, unsigned long request, void *p)
{
	return syscall(__NR_ioctl, fd, request, p);
}

static int
do_madvise(void *addr, size_t length, int advice)
{
	return syscall(__NR_madvise, addr, length, advice);
}

static int
do_execve(const char *pathname, char *const argv[], char *const envp[])
{
	return syscall(__NR_execve, pathname, argv, envp);
}

static int
do_fork(void)
{
	return syscall(__NR_fork);
}

#define	SHELL_PATH	"/bin/sh"	/* Path of the shell.  */
#define	SHELL_NAME	"sh"		/* Name to give it.  */
static int
my_system(std::string s) {
	LOG_DBG("%s:%d: Running cmd: %s -c '%s'...\n", __FILE__, __LINE__, SHELL_NAME, s.c_str());
	pid_t pid = do_fork();
	if (pid == 0) {
		// Child
		const char *new_argv[4];
		new_argv[0] = SHELL_NAME;
		new_argv[1] = "-c";
		new_argv[2] = s.c_str();
		new_argv[3] = NULL;
		const char *new_envp[1];
		new_envp[0] = NULL;
		do_execve(SHELL_PATH, (char *const *) new_argv, (char *const *) new_envp);
		exit(0);
	}
	else if (pid < 0) {
		// Fork failed
		LOG_DBG("%s:%d: fork failed!\n", __FILE__, __LINE__);
		exit(-1);
	} else {
		// Parent
		int status;
		if (TEMP_FAILURE_RETRY (waitpid (pid, &status, 0)) != pid) status = -1;
	}
	LOG_DBG("%s:%d: Done running cmd!\n", __FILE__, __LINE__);
	return 0;
}

// =====================================================================
// Page checking
// =====================================================================

static procmap::memory_map * memmap = NULL;
static bool taint_nonwritable_mem = true; // By default, taint non-writable memory
static bool taint_stack_mem = true; // By default, taint stack memory

void memtaint_dont_taint_nonwritable_mem(void) { taint_nonwritable_mem = false; }
void memtaint_dont_taint_stack_mem(void) { taint_stack_mem = false; }


static void memmap_init(void) {
	if (memmap != NULL) delete memmap;
	memmap = new procmap::memory_map();
#ifdef DEBUG_MEMTAINT
	memmap->print();
#endif
}

static bool page_is_taintable(void * addr)
{
	if (addr_is_kernel(addr) || addr_is_shadow(addr) || addr_is_reserved(addr)) return false;
	for (auto &segment : *memmap) {
		if (segment.contains_addr(addr)) {
			if (!taint_nonwritable_mem && !segment.isWriteable()) return false;
			if (!taint_stack_mem && segment.isStack()) return false;
			return true;
		}
	}
	return true;
}

// =====================================================================
// Snapshotting
// =====================================================================

void exclude_non_taintable_pages_from_snapshot() {
	for (auto &segment : *memmap) {
		// Don't call madvise for kernel addresses
		if (addr_is_kernel(segment.endAddress())) continue;

		// May exclude this segment from the snapshot if it's: writeable, stack, the tagmap, or the reserved region
		if ((!taint_nonwritable_mem && !segment.isWriteable()) ||
				(!taint_stack_mem && segment.isStack()) ||
				(segment.contains_addr(shadow_addr)) ||
				(segment.contains_addr(reserved_addr))) {
			LOG_DBG("%p--%p: MADV_DONTNEED\n", segment.startAddress(), segment.endAddress());
			if (do_madvise(segment.startAddress(), segment.length(), MADV_DONTDUMP) == -1) LOG_OUT("%s:%d: WARNING: madvise(%p, %lu, MADV_DONTDUMP) returned an error: '%s'\n", __FILE__, __LINE__, segment.startAddress(), segment.length(), strerror(errno));
		}
		// Otherwise, include this segment in the snapshot
		else {
			LOG_DBG("%p--%p: MADV_DODUMP\n", segment.startAddress(), segment.endAddress());
			if (do_madvise(segment.startAddress(), segment.length(), MADV_DODUMP) == -1) LOG_OUT("%s:%d: WARNING: madvise(%p, %lu, MADV_DODUMP) returned an error: '%s'\n", __FILE__, __LINE__, segment.startAddress(), segment.length(), strerror(errno));
		}
	}
}

static bool snapshot_enabled = false; // By default, don't take a snapshot
static std::string snapshot_path;
static std::string snapshot_path_real = "";

void memtaint_enable_snapshot(std::string filename) {
	assert(!filename.empty()); // TODO: We should also assert that filename's directory exists
	snapshot_path = filename;
	snapshot_enabled = true;
}

static void memtaint_snapshot(void) {
	exclude_non_taintable_pages_from_snapshot();
	my_system("/usr/bin/gcore -o " + snapshot_path + "-" + std::to_string(tagmap_all_tainted+1) + " " + std::to_string(PIN_GetPid()));
	// Contrary to its docs, it looks like gcore appends a PID to the filename even if only one PID is given
	snapshot_path_real = snapshot_path + "-" + std::to_string(tagmap_all_tainted+1) + "." + std::to_string(PIN_GetPid());
}

//static void memtaint_log_syms(void) {
//	my_system("lldb --attach-pid " + std::to_string(PIN_GetPid()) + " --one-line 'target modules dump symtab' --batch --source-quietly --no-lldbinit > " + snapshot_path_real + ".symtab");
//}

std::string memtaint_get_snapshot_path(void) { return snapshot_path_real; }
int memtaint_get_snapshot_num(void) { return tagmap_all_tainted; }

// =====================================================================
// Memory tainting
// =====================================================================

static void
memtaint_spfh_thread(void *arg)
{
	struct uffd_msg msg; /* Data read from userfaultfd */
	long uffd;			 /* userfaultfd file descriptor */
	char *page = NULL;
	struct uffdio_copy uffdio_copy;
	ssize_t nread;
	uffd = (long)arg;
	size_t page_size = PAGE_SIZE;

	LOG_MEMTAINT("    **** Creating a page that will be copied into the faulting region...\n");
	/* Create a page that will be copied into the faulting region. */
	page = (char *)mmap(NULL, page_size, PROT_READ | PROT_WRITE,
						MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
	if (page == MAP_FAILED)
		errExit("mmap");

	/* Loop, handling incoming events on the userfaultfd
       file descriptor. */
	for (;;)
	{
		/* See what poll() tells us about the userfaultfd. */
		struct pollfd pollfd;
		int nready;
		pollfd.fd = uffd;
		pollfd.events = POLLIN;
		nready = poll(&pollfd, 1, -1);
		if (nready == -1)
			errExit("poll");

		/* Read an event from the userfaultfd. */
		nread = read(uffd, &msg, sizeof(msg));
		if (nread == 0)
		{
			LOG_OUT("EOF on userfaultfd!\n");
			exit(EXIT_FAILURE);
		}

		if (nread == -1)
			errExit("read");
		/* We expect only one kind of event; verify that assumption. */
		if (msg.event != UFFD_EVENT_PAGEFAULT)
		{
			LOG_ERR("Unexpected event on userfaultfd\n");
			exit(EXIT_FAILURE);
		}

		/* Display info about the page-fault event. */
		LOG_MEMTAINT("UFFD_EVENT_PAGEFAULT event: ");
		LOG_MEMTAINT("flags = %llu; ", msg.arg.pagefault.flags);
		LOG_MEMTAINT("address = %p\n", (void *)msg.arg.pagefault.address);

		/* Copy the page pointed to by 'page' into the faulting region. */
		uffdio_copy.src = (unsigned long)page;
		char *paddr = (char *)(msg.arg.pagefault.address & ~(page_size - 1));
		if (tagmap_all_tainted && page_is_taintable(shadow_to_addr((tag_t *)(paddr)))) {
			/* Create identity page rather than the zero page. */
			LOG_MEMTAINT("    Filling identify page: shadow_addr=%p, main_addr=%p, first_tag=%p\n", paddr, shadow_to_addr((tag_t *)paddr), (void*)(uint64_t) ptr_to_tag(shadow_to_addr((tag_t *)paddr)));
			for (unsigned i = 0; i < page_size; i += TAG_SIZE) {
				tag_t *t = (tag_t *)&page[i];
				void *addr = shadow_to_addr((tag_t *)(paddr + i));
				*t = tag_alloc<tag_t>(ptr_to_tag(addr));
			}
		} else {
			/* Create zero page. */
			LOG_MEMTAINT("    Filling zero page: shadow_addr=%p, main_addr=%p, first_tag=(empty)\n", paddr, shadow_to_addr((tag_t *)paddr));
			//for (unsigned i = 0; i < page_size; i += TAG_SIZE) *((tag_t *)&page[i]) = tag_traits<tag_t>::cleared_val;
			memset(page, 0, page_size);
		}

		/* We need to handle page faults in units of pages(!).
           So, round faulting address down to page boundary. */
		uffdio_copy.dst = (unsigned long)paddr;
		uffdio_copy.len = page_size;
		uffdio_copy.mode = 0;
		uffdio_copy.copy = 0;
		if (do_ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
			errExit("ioctl-UFFDIO_COPY");
	}
}

void memtaint_spfh_init()
{
	long uffd; /* userfaultfd file descriptor */
	struct uffdio_api uffdio_api;
	struct uffdio_register uffdio_register;

	/* Create and enable userfaultfd object. */
	uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd == -1)
		errExit("userfaultfd");

	uffdio_api.api = UFFD_API;
	uffdio_api.features = 0;
	if (do_ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
		errExit("ioctl-UFFDIO_API");

	/* Register the memory range for handling by the userfaultfd object. */
	uffdio_register.range.start = (unsigned long)shadow_addr;
	uffdio_register.range.len = shadow_size;
	uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (do_ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
		errExit("ioctl-UFFDIO_REGISTER");

	/* Create a thread that will process the userfaultfd events. */
	PIN_SpawnInternalThread(memtaint_spfh_thread, (void *)uffd, 0, NULL);
}

void memtaint_init(void *saddr, size_t slen, void *raddr, size_t rlen)
{
	shadow_addr = saddr;
	shadow_size = slen;
	reserved_addr = raddr;
	reserved_size = rlen;
}

// No callback by default
static bool memtaint_only_do_callback = false;
static void nop() { }
static void(*__memtaint_callback)() = nop;
static void memtaint_callback(void) { __memtaint_callback(); }
void memtaint_set_callback(void(*new_callback)()) { __memtaint_callback = new_callback; }
void memtaint_set_only_do_callback(bool b) { memtaint_only_do_callback = b; }

void memtaint_taint_all()
{
	if (memtaint_only_do_callback) {
		memtaint_callback();
		return;
	}

	LOG_OUT("%s:%d: Tainting memory x%d...\n", __FILE__, __LINE__, tagmap_all_tainted+1);

	memmap_init();
	memtaint_callback();

	if (snapshot_enabled) {
		// We should take the snapshot after memtaint_callback() so that we capture any memory changes it may make
		LOG_OUT("%s:%d: Taking memory snapshot x%d...\n", __FILE__, __LINE__, tagmap_all_tainted+1);
		memtaint_snapshot();
		//memtaint_log_syms();
	}

	/* Initialize shadow page fault handler */
	if (tagmap_all_tainted == 0) memtaint_spfh_init();

	/* Throw away all the existing shadow memory pages. */
	if (do_madvise(shadow_addr, shadow_size, MADV_DONTNEED) == -1) errExit("MADV_DONTNEED");

	/* Clear registers' taint */
	THREADID tid = PIN_ThreadId();
	for (int regnum = 0; regnum < GRP_NUM; regnum++) tagmap_setn_reg(tid, regnum, TAGS_PER_GPR, tag_traits<tag_t>::cleared_val);

	/* Demand-page identity pages from now on. */
	tagmap_all_tainted++;

	LOG_OUT("%s:%d: Done tainting memory.\n", __FILE__, __LINE__);
}
#endif /* LIBDFT_TAG_PTR */
