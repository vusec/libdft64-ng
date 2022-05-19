#include "debug.h"

static void memop_deref_before(THREADID tid, thread_ctx_t *thread_ctx, ADDRINT taddr,
  UINT32 base_reg, UINT32 indx_reg, ADDRINT eip, ADDRINT esp) {

  int vcpu_base_reg = 0;
  switch(base_reg) {
    case  0: break; // invalid
    case  1: break;
    case  2: break;
    case  3: vcpu_base_reg = GPR_EDI; break;
    case  4: vcpu_base_reg = GPR_ESI; break;
    case  5: vcpu_base_reg = GPR_EBP; break;
    case  6: vcpu_base_reg = 0; break;  // GPR_ESP does not seem to work?
    case  7: vcpu_base_reg = GPR_EBX; break;
    case  8: vcpu_base_reg = GPR_EDX; break;
    case  9: vcpu_base_reg = GPR_ECX; break;
    case 10: vcpu_base_reg = GPR_EAX; break;
    default: break;
  }

  int vcpu_indx_reg = 0;
  switch(indx_reg) {
    case  0: break; // invalid
    case  1: break;
    case  2: break;
    case  3: vcpu_indx_reg = GPR_EDI; break;
    case  4: vcpu_indx_reg = GPR_ESI; break;
    case  5: vcpu_indx_reg = GPR_EBP; break;
    case  6: vcpu_indx_reg = GPR_ESP; break; // GPR_ESP is probably never used?
    case  7: vcpu_indx_reg = GPR_EBX; break;
    case  8: vcpu_indx_reg = GPR_EDX; break;
    case  9: vcpu_indx_reg = GPR_ECX; break;
    case 10: vcpu_indx_reg = GPR_EAX; break;
    default: break;
  }

  for (unsigned i = 0; i < sizeof(ADDRINT); i++) {
    tag_t tag = tagmap_getb(taddr + i);
    if (tag.size()) return; // already tainted
  }

  // taddr is not tainted yet. record it somewhere so that we can restore this later
  stored_tag_t *stored_tag = &stored_tags[tid % MAX_THREADS];

  if (stored_tag->taddr) {
    LOG_OUT("Slot already in use, could not store tag\n");
    return;
  }
  stored_tag->taddr = taddr;

  for (unsigned i = 0; i < sizeof(ADDRINT); i++){
    tag_t tag = tagmap_getb(taddr + i);
    stored_tag->tag[i] = tag;

    if (vcpu_base_reg) tag = tag_combine(tag, thread_ctx->vcpu.gpr[vcpu_base_reg][i]); // COMBINING with base
    if (vcpu_indx_reg) tag = tag_combine(tag, thread_ctx->vcpu.gpr[vcpu_indx_reg][i]); // COMBINING with indx

    tag_dir_setb(tag_dir, taddr + i, tag);
  }
}


static void memop_deref_after(THREADID tid, ADDRINT eip) {
  stored_tag_t *stored_tag = &stored_tags[tid % MAX_THREADS];
  if (!stored_tag->taddr) {
    return;

  // restoring taint
  for (unsigned i = 0; i < sizeof(ADDRINT); i++) {
    tag_t tag = stored_tag->tag[i];
    tag_dir_setb(tag_dir, stored_tag->taddr + i, tag);
  }

  // no longer using this slot
  stored_tag->taddr = 0;
}

void instrument_load_ptr_prop(TRACE trace, VOID *v) {
  BBL bbl;
  INS ins;

  for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)){
    for (ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
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
      * of size 4 bytes. We should instrument this instruction so that taint propagates
      * from the base and index register to the target operand (may it be a register or
      * may it be a memory value) */

      /*
      _pLog->log("ins with 1 memory read operand at %p: %s\n",
                  (void *) INS_Address(ins),
                      INS_Disassemble(ins).c_str());
      _pLog->log("- base_reg: %u\n", base_reg);
      _pLog->log("- indx_reg: %u\n", indx_reg);
      */

      /* Instrument this instruction so that:
      * 1. compute target address for memory operand, say taddr
      * 2. store taint for taddr
      * 3. propagate taint from base_reg/indx_reg to taddr
      * 4. let libdft propagate taint from taddr to destination operand
      * 5. execute instruction
      * 6. restore taint for taddr
      */

      /*
      if (INS_HasFallThrough(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(memop_deref_before),
            IARG_FAST_ANALYSIS_CALL,
            IARG_CALL_ORDER, CALL_ORDER_FIRST, // we need to go before libdft
            IARG_THREAD_ID,
            IARG_REG_VALUE, thread_ctx_ptr,
            IARG_MEMORYOP_EA, read_memopidx,
            IARG_UINT32, base_reg,
            IARG_UINT32, indx_reg,
            IARG_INST_PTR,
            IARG_REG_VALUE, LEVEL_BASE::REG_ESP,
            IARG_END);

        INS_InsertCall(ins, IPOINT_AFTER,
            AFUNPTR(memop_deref_after),
            IARG_FAST_ANALYSIS_CALL,
            IARG_CALL_ORDER, CALL_ORDER_LAST,
            IARG_THREAD_ID,
            IARG_INST_PTR,
            IARG_END);
      }
      */
      LOG_OUT("%s: memread with base_reg=%d, indx_reg=%d\n", __func__, base_reg, indx_reg);
    }
  }
}