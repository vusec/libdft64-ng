#include "debug.h"
#include "libdft_api.h"
#include "ins_helper.h"

typedef struct {
    ADDRINT taddr;
    tag_t tag[sizeof(ADDRINT)];
} stored_tag_t;
#define MAX_THREADS 256
static stored_tag_t stored_tags[MAX_THREADS];

static void memop_deref_before(THREADID tid, ADDRINT taddr, UINT32 base_reg, UINT32 indx_reg, ADDRINT rip, ADDRINT rsp) {
  tag_t base_tag, indx_tag, data_tag;

  // 1a. Get the tag of the base
  int libdft_base_reg = REG_INDX((REG) base_reg);
  if (base_reg == REG_RIP) {
    // It's okay if the base_reg is RIP (this is very common)
    base_tag = tag_traits<tag_t>::cleared_val;
  }
  else if (libdft_base_reg == GRP_NUM) {
    // FIXME: Reported a lot with reg 0
    //LOG_ERR("==== %s:%d: PIN to libdft reg indx conversion not supported for reg %u\n", __FILE__, __LINE__, base_reg);
    return;
  }
  else {
    // The base_reg is a normal GPR
    base_tag = tagmap_getn_reg(tid, libdft_base_reg, sizeof(ADDRINT));
  }

  // 1b. Get the tag of the index
  int libdft_indx_reg = REG_INDX((REG) indx_reg);
  if (indx_reg == REG_INVALID()) {
    // It's okay if the indx_reg is invalid (this is very common, because it may be an immediate)
    indx_tag = tag_traits<tag_t>::cleared_val;
  }
  else if (libdft_indx_reg == GRP_NUM) {
    LOG_ERR("==== %s:%d: PIN to libdft reg indx conversion not supported for reg %u\n", __FILE__, __LINE__, indx_reg);
    return;
  }
  else {
    // The indx_reg is a normal GPR
    indx_tag = tagmap_getn_reg(tid, libdft_indx_reg, sizeof(ADDRINT));
  }

  // 1c. Get the tag of the data
  data_tag = tagmap_getn(taddr, sizeof(ADDRINT));

  // 2. If the data tag is already full, skip (because adding taint to it wouldn't do anything)
  if (tag_is_full(data_tag)) return;

  // FIXME: If the base+indx's and/or the data's tag is empty, can we skip (at least skip some steps?)

  // 3. Save the taddr's current tag so that we can restore it later
  stored_tag_t *stored_tag = &stored_tags[tid % MAX_THREADS];
  if (stored_tag->taddr) {
    LOG_ERR("Slot already in use, could not store tag\n");
    return;
  }
  stored_tag->taddr = taddr;

  // 4. Combine taddr's tag to taddr+base+indx
  for (unsigned i = 0; i < sizeof(ADDRINT); i++){
    // Save the tag for this byte of data
    tag_t tag = tagmap_getb(taddr + i);
    stored_tag->tag[i] = tag;

    // FIXME: It doesn't make sense to do this byte-by-byte. E.g., if base==0x7fff1234, it doesn't make sense
    //    to only combine tagof(0x34) (i.e., byte 0 of base) with tagof(*0x7fff1234) (i.e., byte 0 of the data).
    //    Instead tagof(*0x7fff1234) depends on the ENTIRE pointer, not just the lowest byte of it.
    //    Similarly, tagof(*0x7fff1235) depends on the ENTIRE pointer, not just the second-lowest byte of it.
    // Combine the base+indx's tag with the data's tag
    if (libdft_base_reg) tag = tag_combine(tag, tagmap_getb_reg(tid, libdft_base_reg, i)); // COMBINING with base
    if (libdft_indx_reg) tag = tag_combine(tag, tagmap_getb_reg(tid, libdft_indx_reg, i)); // COMBINING with indx

    tagmap_setb(taddr + i, tag);
  }
}

static void memop_deref_after(THREADID tid, ADDRINT rip) {
  stored_tag_t *stored_tag = &stored_tags[tid % MAX_THREADS];
  if (!stored_tag->taddr) return;

  // restoring taint
  for (unsigned i = 0; i < sizeof(ADDRINT); i++) {
    tag_t tag = stored_tag->tag[i];
    tagmap_setb(stored_tag->taddr + i, tag);
  }

  // no longer using this slot
  stored_tag->taddr = 0;
}

void instrument_load_ptr_prop(TRACE trace, VOID *v) {
  BBL bbl;
  INS ins;

  for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for (ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      REG base_reg = REG_INVALID();
      REG indx_reg = REG_INVALID();

      int read_memopidx = -1;
      for (unsigned i = 0; i < INS_MemoryOperandCount(ins); i++) {
        if (INS_MemoryOperandIsRead(ins, i) &&
          INS_MemoryOperandSize  (ins, i) == sizeof(ADDRINT)) {
          if (read_memopidx != -1) {
            /* Found a second memory read operand. For example:
            *    rep cmpsb byte ptr [esi], byte ptr [edi]
            * This implicitly taints a bit in EFLAGS: skip these instructions */
            continue;
          }
          read_memopidx = i;
          base_reg = INS_OperandMemoryBaseReg(ins,
              INS_MemoryOperandIndexToOperandIndex(ins, i));
          indx_reg = INS_OperandMemoryIndexReg(ins,
              INS_MemoryOperandIndexToOperandIndex(ins, i));
        }
      }

      if (read_memopidx == -1)
        continue; // no memory read operand was found, nothing to do

      /* We are at an instruction that has exactly one memory-read operand
      * of size 8 bytes. We should instrument this instruction so that taint propagates
      * from the base and index register to the target operand (may it be a register or
      * may it be a memory value) */

      // FIXME: This keep some stack ops e.g., 'ret'
      // FIXME: Why does the mem operand have to be 8 bytes...? What about e.g., a 'mov edx, dword ptr [rbx]'.

      //LOG_OUT("ins with 1 memory read operand: addr = %p, base_reg = %u, indx_reg = %u, ins = '%s'\n",
      //        (void *) INS_Address(ins), base_reg, indx_reg, INS_Disassemble(ins).c_str());

      /* Instrument this instruction so that:
      * 1. compute target address for memory operand, say taddr
      * 2. store taint for taddr
      * 3. propagate taint from base_reg/indx_reg to taddr
      * 4. let libdft propagate taint from taddr to destination operand
      * 5. execute instruction
      * 6. restore taint for taddr
      */

      if (INS_HasFallThrough(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(memop_deref_before),
            IARG_CALL_ORDER, CALL_ORDER_FIRST, // we need to go before libdft
            IARG_THREAD_ID,
            IARG_MEMORYOP_EA, read_memopidx,
            IARG_UINT32, base_reg,
            IARG_UINT32, indx_reg,
            IARG_INST_PTR,
            IARG_REG_VALUE, LEVEL_BASE::REG_RSP,
            IARG_END);

        INS_InsertCall(ins, IPOINT_AFTER,
            AFUNPTR(memop_deref_after),
            IARG_CALL_ORDER, CALL_ORDER_LAST,
            IARG_THREAD_ID,
            IARG_INST_PTR,
            IARG_END);
      }
    }
  }
}