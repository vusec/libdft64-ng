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

#ifndef __TAGMAP_H__
#define __TAGMAP_H__

#include "pin.H"
#include "tag_traits.h"
#include <utility>

#define PAGE_SIZE 4096
#define PAGE_BITS 12

#ifdef LIBDFT_SHADOW

/*
 * Use a shadow memory organization for the tagmap.
 *
 * Notes and requirements:
 * - Linux x86_64 PIE binary: stack, mmap_base at the end of the address space.
 * - Binary `prelinked -r BIN_START` (or using utils/relink.py).
 * - BIN_START selected to support 32-bit addressing and randomized stack.
 * - RESERVED_BYTES selected to comply with mmap_min_addr. Also maximum
 *   range allowed for file offset labels when using -DLIBDFT_PTR_32.
 * - SHADOW_END calculated based on TAG_SIZE.
 * - To enforce 32-bit addressing (for encoding addresses in 32-bit tags):
 *   - Libdft compiled with -DLIBDFT_PTR_32.
 *   - PIN started with `setarch -R` (or ASLR off).
 *
 * Address space layout:
 * ==== 0x000000000000: SHADOW_START
 * ...
 * ==== 0x000000100000: SHADOW_START+RESERVED_BYTES
 * ...
 * ...
 * ...
 * ==== 0x............: SHADOW_END, MAIN_START
 * ...
 * ==== 0x............: MAIN_START+RESERVED_BYTES
 * ...
 * ...
 * ==== 0x7fff00101000: BIN_START
 * ...
 * ==== 0x800000000000: MAIN_END
*/
#ifndef RESERVED_BYTES
#define RESERVED_BYTES  (0x100000UL)
#endif
#define USER_START      (0x0)
#define USER_END        (1UL << 47)
#define MAIN32_START    (USER_END-(1UL<<32)+PAGE_SIZE)
#define BIN_START       (MAIN32_START+RESERVED_BYTES)
#define USER_SIZE       (USER_END-USER_START)

#define SHADOW_START    USER_START
#define __SHADOW_SIZE   ((USER_SIZE/(TAG_SIZE+1)) * TAG_SIZE)
#define _SHADOW_SIZE    (((__SHADOW_SIZE>>PAGE_BITS)+1)<<PAGE_BITS)

#if SHADOW_START+_SHADOW_SIZE > MAIN32_START
#error "Cannot fit minimum 32-bit main address space. tag_t too large?"
#endif

#ifdef LIBDFT_PTR_32
#define SHADOW_SIZE     (MAIN32_START-SHADOW_START)
#define PTR_BASE        (MAIN32_START)
#else
#define SHADOW_SIZE     _SHADOW_SIZE
#define PTR_BASE        (0x0)
#endif
#define SHADOW_END      (SHADOW_START+SHADOW_SIZE)
#define MAIN_START      SHADOW_END
#define MAIN_END        USER_END
#define MAIN_SIZE       (MAIN_END-MAIN_START)

static inline tag_t *addr_to_shadow(const void *addr)
{
#ifdef DEBUG_SHADOW
  if (addr < (void *)MAIN_START || addr >= (void *)MAIN_END) {
    fprintf(stderr, "Invalid addr: %p\n", addr);
    exit(1);
  }
#endif

  /*
   * Notes:
   * - Program accesses to shadow memory will land in kernel memory.
   * - Program accesses to kernel memory trap anyway.
   * - The second (optimized) version below replaces the subtraction
   *   with an addition (allowing PIN to generate better code) by
   *   exploiting user address space wraparound arithmetic. However,
   *   shadow memory accesses are no longer guaranteed to trap with it.
   */
#ifndef SHADOW_OPT
  return (tag_t *)(((((uint64_t)addr) - MAIN_START) * TAG_SIZE) + SHADOW_START);
#else
  return (tag_t *)(((((uint64_t)addr) + MAIN_SIZE) * TAG_SIZE) & (USER_END - 1));
#endif
}

static inline void *shadow_to_addr(tag_t *saddr)
{
  return (void *)(((((uint64_t)saddr) - SHADOW_START) / TAG_SIZE) + MAIN_START);
}

typedef int tag_dir_t; /* Dummy type, unused. */

#else /* End of LIBDFT_SHADOW */

/*
 * Use a page table organization for the tagmap.
 */
#define TOP_DIR_SZ 0x800000
#define PAGETABLE_SZ 0X1000
#define PAGETABLE_BITS 24
#define OFFSET_MASK 0x00000FFFU
#define PAGETABLE_OFFSET_MASK 0x00FFFFFFU

#define VIRT2PAGETABLE(addr) ((addr) >> PAGETABLE_BITS)
#define VIRT2PAGETABLE_OFFSET(addr)                                            \
  (((addr)&PAGETABLE_OFFSET_MASK) >> PAGE_BITS)

#define VIRT2PAGE(addr) VIRT2PAGETABLE_OFFSET(addr)
#define VIRT2OFFSET(addr) ((addr)&OFFSET_MASK)

#define ALIGN_OFF_MAX 8 /* max alignment offset */
#define ASSERT_FAST 32  /* used in comparisons  */

/* XXX: Latest Intel Pin(3.7) does not support std::array :( */
// typedef std::array<tag_t, PAGE_SIZE> tag_page_t;
// typedef std::array<tag_page_t*, PAGETABLE_SZ> tag_table_t;
// typedef std::array<tag_table_t*, TOP_DIR_SZ> tag_dir_t;
/* For file taint */
typedef struct {
  tag_t tag[PAGE_SIZE];
} tag_page_t;
typedef struct {
  tag_page_t *page[PAGETABLE_SZ];
} tag_table_t;
typedef struct {
  tag_table_t *table[TOP_DIR_SZ];
} tag_dir_t;

#endif /* End of !LIBDFT_SHADOW */

extern void libdft_die();

int tagmap_alloc(void);
void tagmap_free(void);
void tagmap_setb(ADDRINT addr, tag_t const &tag);
void tagmap_setb_reg(THREADID tid, unsigned int reg_idx, unsigned int off,
                     tag_t const &tag);
tag_t tagmap_getb(ADDRINT addr);
tag_t tagmap_getb_reg(THREADID tid, unsigned int reg_idx, unsigned int off);
tag_t tagmap_getn(ADDRINT addr, unsigned int size);
tag_t tagmap_getn_reg(THREADID tid, unsigned int reg_idx, unsigned int n);
void tagmap_clrb(ADDRINT addr);
void tagmap_clrn(ADDRINT, UINT32);

#endif /* __TAGMAP_H__ */
