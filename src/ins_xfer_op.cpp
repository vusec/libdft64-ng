#include "ins_xfer_op.h"
#include "ins_clear_op.h"
#include "ins_helper.h"
#include "ins_movsx_op.h"
#include "libdft_core.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_ul(THREADID tid, uint32_t dst,
                                            uint32_t src) {
  tag_t src_tag = RTAG[src][0];

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_lu(THREADID tid, uint32_t dst,
                                            uint32_t src) {
  tag_t src_tag = RTAG[src][1];

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][1];

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][0];

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opw(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 2; i++) {
    RTAG[dst][i] = RTAG[src][i];
    /*
    if (!tag_is_empty(RTAG[src][i]))
      LOG_DBG("[xfer_w] i%ld: src: %d (%d) -> dst: %d (%d)\n", i, src,
           RTAG[src][i], dst, RTAG[dst][i]);
           */
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opl(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 4; i++) {
    RTAG[dst][i] = RTAG[src][i];
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opq(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 8; i++) {
    RTAG[dst][i] = RTAG[src][i];
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opq_h(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 8; i++) {
    RTAG[dst][i + 8] = RTAG[src][i + 8];
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opx(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 16; i++)
    RTAG[dst][i] = RTAG[src][i];
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opy(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  for (size_t i = 0; i < 32; i++)
    RTAG[dst][i] = RTAG[src][i];
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  tag_t src_tag = MTAG(src);

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  tag_t src_tag = MTAG(src);

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 2; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 4; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opx(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 16; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opy(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  for (size_t i = 0; i < 32; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_u(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][1];

  tagmap_setb(dst, src_tag);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_l(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  tag_t src_tag = RTAG[src][0];

  tagmap_setb(dst, src_tag);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  tagmap_setb(dst, src_tags[0]);
  tagmap_setb(dst + 1, src_tags[1]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opx(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 16; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opy(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 32; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opb(ADDRINT dst, ADDRINT src) {
  tag_t src_tag = MTAG(src);

  tagmap_setb(dst, src_tag);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opw(ADDRINT dst, ADDRINT src) {
  for (size_t i = 0; i < 2; i++)
    tagmap_setb(dst + i, MTAG(src + i));
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opl(ADDRINT dst, ADDRINT src) {
  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, MTAG(src + i));
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opq(ADDRINT dst, ADDRINT src) {
  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, MTAG(src + i));
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_h(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i + 8] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_h(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, src_tags[i + 8]);
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opx_lq_to_hq(THREADID tid, uint32_t dst, uint32_t src) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i + 8] = RTAG[src][i];
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opbn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag = RTAG[DFT_REG_RAX][0];
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < count; i++) {
      tagmap_setb(dst + i, src_tag);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < count; i++) {
      size_t dst_addr = dst - count + 1 + i;
      tagmap_setb(dst_addr, src_tag);
    }
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opwn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag[] = R16TAG(DFT_REG_RAX);
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 1); i++) {
      tagmap_setb(dst + i, src_tag[i % 2]);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 1); i++) {
      size_t dst_addr = dst - (count << 1) + 1 + i;
      tagmap_setb(dst_addr, src_tag[i % 2]);
    }
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opln(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag[] = R32TAG(DFT_REG_RAX);
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 2); i++) {
      tagmap_setb(dst + i, src_tag[i % 4]);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 2); i++) {
      size_t dst_addr = dst - (count << 2) + 1 + i;
      tagmap_setb(dst_addr, src_tag[i % 4]);
    }
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opqn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  tag_t src_tag[] = R64TAG(DFT_REG_RAX);
  if (likely(EFLAGS_DF(eflags) == 0)) {
    /* EFLAGS.DF = 0 */
    for (size_t i = 0; i < (count << 2); i++) {
      tagmap_setb(dst + i, src_tag[i % 8]);
    }
  } else {
    /* EFLAGS.DF = 1 */
    for (size_t i = 0; i < (count << 2); i++) {
      size_t dst_addr = dst - (count << 2) + 1 + i;
      tagmap_setb(dst_addr, src_tag[i % 8]);
    }
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL rep_predicate(BOOL first_iteration) {
  /* return the flag; typically this is true only once */
  return first_iteration;
}

static void PIN_FAST_ANALYSIS_CALL _lea_opw(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  for (size_t i = 0; i < 2; i++)
    RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
}

static void PIN_FAST_ANALYSIS_CALL _lea_opl(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  for (size_t i = 0; i < 4; i++)
    RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
}

static void PIN_FAST_ANALYSIS_CALL _lea_opq(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
}

void ins_xfer_op(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(_movsx_r2r_opql, reg_dst, reg_src); // Sign extend 32-bit operand to 64-bit
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_xfer_opw, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {
      R2R_CALL(r2r_xfer_opx, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {
      R2R_CALL(r2r_xfer_opy, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_src);
    } else {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src)) {
        R2R_CALL(r2r_xfer_opb_l, reg_dst, reg_src);
      } else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src)) {
        R2R_CALL(r2r_xfer_opb_u, reg_dst, reg_src);
      } else if (REG_is_Lower8(reg_dst)) {
        R2R_CALL(r2r_xfer_opb_lu, reg_dst, reg_src);
      } else {
        R2R_CALL(r2r_xfer_opb_ul, reg_dst, reg_src);
      }
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(_movsx_m2r_opql, reg_dst); // Sign extend 32-bit operand to 64-bit
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_xfer_opw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) { // TODO: Something similar might be needed for other instructions and operand sizes (e.g., YMM, GR64, GR32, etc.?)
      // Prevents incorrect tainting when src reg size does not match XMM size
      switch (INS_MemoryOperandSize(ins, 0)) { // TODO: Its the first memory operand but not the first operand in general?? Is this correct?
        case 4:
          M2R_CALL(_movsx_m2r_opql, reg_dst); // Sign extend 32-bit operand to 64-bit
          break;
        case 8:
          M2R_CALL(m2r_xfer_opq, reg_dst);
          break;
        case 16:
          M2R_CALL(m2r_xfer_opx, reg_dst);
          break;
        default:
          LOG_ERR("%s:%d: Unimplemented instruction '%s'\n", __FILE__, __LINE__, INS_Disassemble(ins).c_str());
          return; //abort();
      }
      M2R_CALL(m2r_xfer_opx, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      M2R_CALL(m2r_xfer_opy, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_Upper8(reg_dst)) {
      M2R_CALL(m2r_xfer_opb_u, reg_dst);
    } else {
      M2R_CALL(m2r_xfer_opb_l, reg_dst);
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl, reg_src); // TODO: Sign extend 32-bit operand to 64-bit?
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_xfer_opw, reg_src);
    } else if (REG_is_xmm(reg_src) || REG_is_ymm(reg_src)) { // TODO: Something similar might be needed for other instructions and operand sizes (e.g., YMM, GR64, GR32, etc.?)
    // Prevents incorrect tainting when dst reg size does not match XMM size
      switch (INS_MemoryOperandSize(ins, 0)) { // TODO: not sure if some of these cases are actually possible. Will get performance benefit if we remove impossible cases.
        case 2:
          R2M_CALL(r2m_xfer_opw, reg_src);
          break;
        case 4:
          R2M_CALL(r2m_xfer_opl, reg_src); // TODO: Sign extend 32-bit operand to 64-bit?
          break;
        case 8:
          R2M_CALL(r2m_xfer_opq, reg_src);
          break;
        case 16:
          R2M_CALL(r2m_xfer_opx, reg_src);
          break;
        case 32:
          R2M_CALL(r2m_xfer_opy, reg_src);
          break;
        default:
          ins_uninstrumented(ins);
          break;

      }
    } else if (REG_is_ymm(reg_src)) {
      R2M_CALL(r2m_xfer_opy, reg_src);
    } else if (REG_is_mm(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL(r2m_xfer_opb_u, reg_src);
    } else {
      R2M_CALL(r2m_xfer_opb_l, reg_src);
    }
  }
}

void ins_xfer_op_predicated(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_P(r2r_xfer_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_P(_movsx_r2r_opql, reg_dst, reg_src); // Sign extend 32-bit operand to 64-bit
    } else {
      R2R_CALL_P(r2r_xfer_opw, reg_dst, reg_src);
    }
  } else {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL_P(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL_P(_movsx_m2r_opql, reg_dst); // Sign extend 32-bit operand to 64-bit
    } else {
      M2R_CALL_P(m2r_xfer_opw, reg_dst);
    }
  }
}

void ins_push_op(INS ins) {
  REG reg_src;
  if (INS_OperandIsReg(ins, OP_0)) {
    // E.g., "push rax"
    reg_src = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      // TODO: Pretty sure a 32-bit push doesn't exist for x86-64
      R2M_CALL(r2m_xfer_opl, reg_src); // TODO: Sign extend 32-bit operand to 64-bit?
    } else {
      R2M_CALL(r2m_xfer_opw, reg_src);
    }
  } else if (INS_OperandIsMemory(ins, OP_0)) {
    // E.g., "push [rax]"
    assert(INS_MemoryOperandIsWritten(ins, MEMOP_1));
    USIZE n = INS_MemoryOperandSize(ins, MEMOP_1);
    if (n == BIT2BYTE(MEM_64BIT_LEN)) {
      M2M_CALL(m2m_xfer_opq);
    } else if (n == BIT2BYTE(MEM_LONG_LEN)) {
      // TODO: Pretty sure a 32-bit push doesn't exist for x86-64
      M2M_CALL(m2m_xfer_opl); // TODO: Sign extend 32-bit operand to 64-bit?
    } else {
      M2M_CALL(m2m_xfer_opw);
    }
  } else {
    // E.g., "push 0x0"
    assert(INS_MemoryOperandIsWritten(ins, MEMOP_0));
    USIZE n = INS_MemoryOperandSize(ins, MEMOP_0);
    M_CLEAR_N(n);
  }
}

void ins_pop_op(INS ins) {
  REG reg_dst;
  if (INS_OperandIsReg(ins, OP_0)) {
    // E.g., "pop rax"
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      // TODO: Pretty sure a 32-bit pop doesn't exist for x86-64
      M2R_CALL(m2r_xfer_opl, reg_dst); // TODO: Sign extend 32-bit operand to 64-bit?
    } else {
      M2R_CALL(m2r_xfer_opw, reg_dst);
    }
  } else if (INS_OperandIsMemory(ins, OP_0)) {
    // E.g., "pop [rax]"
    assert(INS_MemoryOperandIsWritten(ins, MEMOP_0));
    USIZE n = INS_MemoryOperandSize(ins, MEMOP_0);
    if (n == BIT2BYTE(MEM_64BIT_LEN)) {
      M2M_CALL(m2m_xfer_opq);
    } else if (n == BIT2BYTE(MEM_LONG_LEN)) {
      // TODO: Pretty sure a 32-bit pop doesn't exist for x86-64
      M2M_CALL(m2m_xfer_opl); // TODO: Sign extend 32-bit operand to 64-bit?
    } else {
      M2M_CALL(m2m_xfer_opw);
    }
  }
}

void ins_stos_ins(INS ins, AFUNPTR fn) {
  INS_InsertIfPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)rep_predicate,
                             IARG_FAST_ANALYSIS_CALL, IARG_FIRST_REP_ITERATION,
                             IARG_END);
  INS_InsertThenPredicatedCall(
      ins, IPOINT_BEFORE, fn, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
      IARG_MEMORYWRITE_EA, IARG_REG_VALUE, INS_RepCountRegister(ins),
      IARG_REG_VALUE, INS_OperandReg(ins, OP_4), IARG_END);
}

void ins_stosb(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opbn);
  } else {
    R2M_CALL(r2m_xfer_opb_l, REG_AL);
  }
}

void ins_stosw(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opwn);
  } else {
    R2M_CALL(r2m_xfer_opw, REG_AX);
  }
}

void ins_stosd(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opln); // TODO: Sign extend 32-bit operand to 64-bit?
  } else {
    R2M_CALL(r2m_xfer_opw, REG_EAX);
  }
}

void ins_stosq(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opqn);
  } else {
    R2M_CALL(r2m_xfer_opw, REG_RAX);
  }
}

void ins_movlp(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    R2M_CALL(r2m_xfer_opq, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    M2R_CALL(m2r_xfer_opq, reg_dst);
  }
}

void ins_movhp(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    R2M_CALL(r2m_xfer_opq_h, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    M2R_CALL(m2r_xfer_opq_h, reg_dst);
  }
}

void ins_movlhps(INS ins) { // TODO check if correct
  if (INS_OperandIsMemory(ins, OP_0) || INS_OperandIsMemory(ins, OP_1)) {
    LOG_ERR("%s:%d: Unimplemented instruction '%s'\n", __FILE__, __LINE__, INS_Disassemble(ins).c_str());
    return; //abort();
  }

  REG reg_dst = INS_OperandReg(ins, OP_0);
  REG reg_src = INS_OperandReg(ins, OP_1);

  R2R_CALL(r2r_xfer_opx_lq_to_hq, reg_dst, reg_src);
}

void ins_punpcklqdq(INS ins) { // TODO check if correct
  if (INS_OperandIsMemory(ins, OP_0)) {
    LOG_ERR("%s:%d: Unimplemented instruction '%s'\n", __FILE__, __LINE__, INS_Disassemble(ins).c_str());
    return; //abort();
  }

  REG reg_dst = INS_OperandReg(ins, OP_0);

  if (INS_OperandIsMemory(ins, OP_1)) {
    M2R_CALL(m2r_xfer_opq_h, reg_dst);
  } else {
    REG reg_src = INS_OperandReg(ins, OP_1); // We are assuming this only takes xmm regs

    R2R_CALL(r2r_xfer_opx_lq_to_hq, reg_dst, reg_src);
  }
}

void ins_vmovsd_op(INS ins) {
  if (INS_OperandCount(ins) == 3) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    REG reg_src_h = INS_OperandReg(ins, OP_1);
    REG reg_src_l = INS_OperandReg(ins, OP_2);
    R2R_CALL(r2r_xfer_opq, reg_dst, reg_src_l); // DEST[63:0] := SRC2[63:0]
    R2R_CALL(r2r_xfer_opq_h, reg_dst, reg_src_h); // DEST[127:64] := SRC1[127:64]
    // TODO: DEST[MAXVL-1:128] := 0
    return;
  }
  else if (INS_OperandCount(ins) == 2) {
    if (INS_OperandIsMemory(ins, OP_0)) {
      REG reg_src = INS_OperandReg(ins, OP_1);
      R2M_CALL(r2m_xfer_opq, reg_src);
      return;
    }
    else if (INS_OperandIsMemory(ins, OP_1)) {
      REG reg_dst = INS_OperandReg(ins, OP_0);
      M2R_CALL(m2r_xfer_opq, reg_dst);
      return;
    }
  }
  LOG_ERR("%s:%d: Unimplemented instruction '%s'\n", __FILE__, __LINE__, INS_Disassemble(ins).c_str());
}

void ins_lea(INS ins) {
  REG reg_base = INS_MemoryBaseReg(ins);
  REG reg_indx = INS_MemoryIndexReg(ins);
  REG reg_dst = INS_OperandReg(ins, OP_0);
  if (reg_base == REG_INVALID() && reg_indx == REG_INVALID()) {
    ins_clear_op(ins);
  }
  if (reg_base != REG_INVALID() && reg_indx == REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_base);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_xfer_opl, reg_dst, reg_base); // TODO: Sign extend 32-bit operand to 64-bit?
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_xfer_opw, reg_dst, reg_base);
    }
  }
  if (reg_base == REG_INVALID() && reg_indx != REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_indx);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_xfer_opl, reg_dst, reg_indx); // TODO: Sign extend 32-bit operand to 64-bit?
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_xfer_opw, reg_dst, reg_indx);
    }
  }
  if (reg_base != REG_INVALID() && reg_indx != REG_INVALID()) {
    if (REG_is_gr64(reg_dst)) {
      RR2R_CALL(_lea_opq, reg_dst, reg_base, reg_indx);
    } else if (REG_is_gr32(reg_dst)) {
      RR2R_CALL(_lea_opl, reg_dst, reg_base, reg_indx);
    } else if (REG_is_gr16(reg_dst)) {
      RR2R_CALL(_lea_opw, reg_dst, reg_base, reg_indx);
    }
  }
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
  for (size_t i = 0; i < 2; i++)
    RTAG[dst][i] = MTAG(src + (1 - i));
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
  for (size_t i = 0; i < 4; i++)
    RTAG[dst][i] = MTAG(src + (3 - i));
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_rev(THREADID tid, uint32_t dst,
                                             ADDRINT src) {
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i] = MTAG(src + (7 - i));
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tagmap_setb(dst, src_tags[1]);
  tagmap_setb(dst + 1, src_tags[0]);
}

// TODO: Sign extend 32-bit operand to 64-bit?
void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + (3 - i), src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_rev(THREADID tid, ADDRINT dst,
                                             uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + (7 - i), src_tags[i]);
}

void ins_movbe_op(INS ins) {
  if (INS_OperandIsMemory(ins, OP_1)) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq_rev, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl_rev, reg_dst); // TODO: Sign extend 32-bit operand to 64-bit?
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_xfer_opw_rev, reg_dst);
    }
  } else {
    REG reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq_rev, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl_rev, reg_src); // TODO: Sign extend 32-bit operand to 64-bit?
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_xfer_opw_rev, reg_src);
    }
  }
}