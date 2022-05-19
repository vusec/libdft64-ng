#include "debug.h"

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