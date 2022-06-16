/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Georgios Portokalidis <porto@cs.columbia.edu> contributed to the
 * optimized implementation of tagmap_setn() and tagmap_clrn()
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
#include "tagmap.h"
#include "branch_pred.h"
#include "debug.h"
#include "libdft_api.h"
#include "pin.H"
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

tag_dir_t tag_dir;
extern thread_ctx_t *threads_ctx;

#ifdef LIBDFT_SHADOW

int tagmap_alloc(void)
{
#ifdef LIBDFT_TAG_PTR
	extern void memtaint_init(void *addr, size_t len);
#endif
  int mmap_prot = PROT_READ | PROT_WRITE;
  int mmap_flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE;

#ifdef DEBUG_SHADOW
  LOG_ERR("USER_START=%p, RESERVED_BYTES=%p, USER_END=%p, MAIN32_START=%p, BIN_START=%p, USER_SIZE=%p, SHADOW_START=%p, _SHADOW_SIZE=%p, SHADOW_SIZE=%p, SHADOW_END=%p, MAIN_START=%p, MAIN_SIZE=%p, MAIN_END=%p, PTR_BASE=%p\n", (void *)USER_START, (void *)RESERVED_BYTES, (void *)USER_END, (void *)MAIN32_START, (void *)BIN_START, (void *)USER_SIZE, (void *)SHADOW_START, (void *)_SHADOW_SIZE, (void *)SHADOW_SIZE, (void *)SHADOW_END, (void *)MAIN_START, (void *)MAIN_SIZE, (void *)MAIN_END, (void*)PTR_BASE);
#endif

  /* Map most of the address space for use as shadow memory. */
  if (mmap((void *)(SHADOW_START + RESERVED_BYTES), SHADOW_SIZE - RESERVED_BYTES, mmap_prot, mmap_flags, -1, 0) == (void *)-1)
  {
    const char *err = strerror(errno);
    PIN_ERROR(std::string("Failed to mmap shadow region: ") + err + std::string("\n"));
    return 1;
  }

  /* Reserve RESERVED_BYTES at the beginning of the main address space. */
  if (mmap((void *)MAIN_START, RESERVED_BYTES, PROT_NONE, mmap_flags, -1, 0) == (void *)-1)
  {
    const char *err = strerror(errno);
    PIN_ERROR(std::string("Failed to mmap (main) reserved region: ") + err + std::string("\n"));
    return 1;
  }

#ifdef LIBDFT_TAG_PTR
	/* Initialize memtaint. */
	memtaint_init((void *)(SHADOW_START + RESERVED_BYTES), SHADOW_SIZE - RESERVED_BYTES);
#endif

  return 0;
}

void tagmap_free(void)
{
  /* Get rid of the shadow memory and reserved mappings. */
  munmap((void *)(SHADOW_START + RESERVED_BYTES), SHADOW_SIZE - RESERVED_BYTES);
  munmap((void *)MAIN_START, RESERVED_BYTES);
}

inline void tag_dir_setb(UNUSED tag_dir_t &dir, ADDRINT addr, tag_t const &tag)
{
  tag_t *tagp = addr_to_shadow((void *)addr);
  *tagp = tag;
}

inline tag_t const *tag_dir_getb_as_ptr(UNUSED tag_dir_t const &dir, ADDRINT addr)
{
  return addr_to_shadow((void *)addr);
}

#ifdef LIBDFT_TAG_PTR
bool tag_is_file_offset(ptroff_t v) {
#ifdef LIBDFT_PTR_32
  return v >= 1 && v < (ptroff_t) RESERVED_BYTES;
#else
  return v < (ptroff_t) (MAIN_START+RESERVED_BYTES);
#endif
}

void* tag_to_ptr(ptroff_t v) {
  return (void*) (((uint64_t)v) + PTR_BASE);
}

ptroff_t ptr_to_tag(void *p) {
  return (ptroff_t) (((uint64_t)p) - PTR_BASE);
}
#endif

#else /* End of LIBDFT_SHADOW */

int tagmap_alloc(void) {
  return 0;
}

void tagmap_free(void) {}

inline void tag_dir_setb(tag_dir_t &dir, ADDRINT addr, tag_t const &tag) {
  if (addr > 0x7fffffffffff) {
    return;
  }
  // LOG_OUT("Setting tag "+hexstr(addr)+"\n");
  if (dir.table[VIRT2PAGETABLE(addr)] == NULL) {
    //  LOG_OUT("No tag table for "+hexstr(addr)+" allocating new table\n");
    tag_table_t *new_table = new (std::nothrow) tag_table_t();
    if (new_table == NULL) {
      LOG_ERR("Failed to allocate tag table!\n");
      libdft_die();
    }
    dir.table[VIRT2PAGETABLE(addr)] = new_table;
  }

  tag_table_t *table = dir.table[VIRT2PAGETABLE(addr)];
  if ((*table).page[VIRT2PAGE(addr)] == NULL) {
    //    LOG_OUT("No tag page for "+hexstr(addr)+" allocating new page\n");
    tag_page_t *new_page = new (std::nothrow) tag_page_t();
    if (new_page == NULL) {
      LOG_ERR("Failed to allocate tag page!\n");
      libdft_die();
    }
    std::fill(new_page->tag, new_page->tag + PAGE_SIZE,
              tag_traits<tag_t>::cleared_val);
    (*table).page[VIRT2PAGE(addr)] = new_page;
  }

  tag_page_t *page = (*table).page[VIRT2PAGE(addr)];
  (*page).tag[VIRT2OFFSET(addr)] = tag;
  /*
  if (!tag_is_empty(tag)) {
    LOG_DBG("[!]Writing tag for %p \n", (void *)addr);
  }
  */
}

inline tag_t const *tag_dir_getb_as_ptr(tag_dir_t const &dir, ADDRINT addr) {
  if (addr > 0x7fffffffffff) {
    return NULL;
  }
  if (dir.table[VIRT2PAGETABLE(addr)]) {
    tag_table_t *table = dir.table[VIRT2PAGETABLE(addr)];
    if ((*table).page[VIRT2PAGE(addr)]) {
      tag_page_t *page = (*table).page[VIRT2PAGE(addr)];
      if (page != NULL)
        return &(*page).tag[VIRT2OFFSET(addr)];
    }
  }
  return &tag_traits<tag_t>::cleared_val;
}

#endif /* End of !LIBDFT_SHADOW */

// PIN_FAST_ANALYSIS_CALL
void tagmap_setb(ADDRINT addr, tag_t const &tag) {
  tag_dir_setb(tag_dir, addr, tag);
}

void tagmap_setb_reg(THREADID tid, unsigned int reg_idx, unsigned int off,
                     tag_t const &tag) {
  threads_ctx[tid].vcpu.gpr[reg_idx][off] = tag;
}

tag_t tagmap_getb(ADDRINT addr) { return *tag_dir_getb_as_ptr(tag_dir, addr); }

tag_t tagmap_getb_reg(THREADID tid, unsigned int reg_idx, unsigned int off) {
  return threads_ctx[tid].vcpu.gpr[reg_idx][off];
}

void PIN_FAST_ANALYSIS_CALL tagmap_clrb(ADDRINT addr) {
  tagmap_setb(addr, tag_traits<tag_t>::cleared_val);
}

void PIN_FAST_ANALYSIS_CALL tagmap_clrn(ADDRINT addr, UINT32 n) {
  ADDRINT i;
  for (i = addr; i < addr + n; i++) {
    tagmap_clrb(i);
  }
}

tag_t tagmap_getn(ADDRINT addr, unsigned int n) {
  tag_t ts = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < n; i++) {
    const tag_t t = tagmap_getb(addr + i);
    if (tag_is_empty(t))
      continue;
    // LOG_DBG("[tagmap_getn] %lu, ts: %d, %s\n", i, ts, tag_sprint(t).c_str());
    ts = tag_combine(ts, t);
    // LOG_DBG("t: %d, ts:%d\n", t, ts);
  }
  return ts;
}

tag_t tagmap_getn_reg(THREADID tid, unsigned int reg_idx, unsigned int n) {
  tag_t ts = tag_traits<tag_t>::cleared_val;
  for (size_t i = 0; i < n; i++) {
    const tag_t t = tagmap_getb_reg(tid, reg_idx, i);
    if (tag_is_empty(t))
      continue;
    // LOG_DBG("[tagmap_getn] %lu, ts: %d, %s\n", i, ts, tag_sprint(t).c_str());
    ts = tag_combine(ts, t);
    // LOG_DBG("t: %d, ts:%d\n", t, ts);
  }
  return ts;
}

void taint_dump(ADDRINT addr) {
  const tag_t t = tagmap_getb(addr);
  LOG_ERR("[taint_dump] addr = %p, tags = %s\n",
          (void *)addr, tag_sprint(t).c_str());
}

void taint_dump_reg(THREADID tid, unsigned int reg_idx, unsigned int n) {
  const tag_t t = tagmap_getb_reg(tid, reg_idx, n);
  LOG_ERR("[taint_dump] reg_num = %u, offset = %u, tags = %s\n",
          reg_idx, n, tag_sprint(t).c_str());
}