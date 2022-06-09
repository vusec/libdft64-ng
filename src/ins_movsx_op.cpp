#include "ins_movsx_op.h"
#include "ins_helper.h"
#include "ins_xfer_op.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit
 * register and an 8-bit register as t[dst] = t[upper(src)]
 *
 * NOTE: special case for MOVSX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opwb_u(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  /* temporary tag value */
  tag_t src_tag = RTAG[src][1];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tag;
  rtag_dst[1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opwb_l(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  /* temporary tag value */
  tag_t src_tag = RTAG[src][0];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tag;
  rtag_dst[1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_oplb_u(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  /* temporary tag value */
  tag_t src_tag = RTAG[src][1];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  for (size_t i = 0; i < 4; i++)
    rtag_dst[i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_oplb_l(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  /* temporary tag value */
  tag_t src_tag = RTAG[src][0];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  for (size_t i = 0; i < 4; i++)
    rtag_dst[i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opqb_u(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  /* temporary tag value */
  tag_t src_tag = RTAG[src][1];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  for (size_t i = 0; i < 8; i++)
    rtag_dst[i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opqb_l(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  /* temporary tag value */
  tag_t src_tag = RTAG[src][0];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  for (size_t i = 0; i < 8; i++)
    rtag_dst[i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_oplw(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
  /* temporary tag values */
  tag_t *rtag_src = RTAG[src];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  for (size_t i = 0; i < 4; i++)
    rtag_dst[i] = rtag_src[i % 2];
}

static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opqw(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
  /* temporary tag values */
  tag_t *rtag_src = RTAG[src];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  for (size_t i = 0; i < 8; i++)
    rtag_dst[i] = rtag_src[i % 2];
}

static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opql(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
  /* temporary tag values */
  tag_t *rtag_src = RTAG[src];
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  for (size_t i = 0; i < 8; i++)
    rtag_dst[i] = rtag_src[i % 4];
}

static void PIN_FAST_ANALYSIS_CALL _movsx_m2r_opwb(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t src_tag = MTAG(src);
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  rtag_dst[0] = src_tag;
  rtag_dst[1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL _movsx_m2r_oplb(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t src_tag = MTAG(src);
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  for (size_t i = 0; i < 4; i++)
    rtag_dst[i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL _movsx_m2r_opqb(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t src_tag = MTAG(src);
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  for (size_t i = 0; i < 8; i++)
    rtag_dst[i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL _movsx_m2r_oplw(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t src_tags[] = M16TAG(src);
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  for (size_t i = 0; i < 4; i++)
    rtag_dst[i] = src_tags[i % 2];
}

static void PIN_FAST_ANALYSIS_CALL _movsx_m2r_opqw(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t src_tags[] = M16TAG(src);
  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  for (size_t i = 0; i < 8; i++)
    rtag_dst[i] = src_tags[i % 2];
}

static void PIN_FAST_ANALYSIS_CALL _movsx_m2r_opql(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t src_tags[] = M32TAG(src);

  tag_t *rtag_dst = RTAG[dst];

  /* update the destination (xfer) */
  for (size_t i = 0; i < 8; i++)
    rtag_dst[i] = src_tags[i % 4];
}

static const unsigned int bruh_id = BRUH_ID;

static void PIN_FAST_ANALYSIS_CALL r2_bruh(THREADID tid, uint32_t src, void *src_content, char *ins_dasm) {
  tag_t src_tag = RTAG[src][0]; //TODO should this loop like in the others?

  if (tag_to_id(src_tag) == bruh_id || src_content == (void *)BRUH_CONTENT) {
    LOG_DBG("[REG BRUH %d] %s ; src content = %p\n", tag_to_id(src_tag), ins_dasm, src_content);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2_bruh(THREADID tid, ADDRINT src, char *ins_dasm) {
  tag_t src_tag = MTAG(src);

  if (tag_to_id(src_tag) == bruh_id || *((void **)src) == (void *)BRUH_CONTENT) {
    LOG_DBG("[MEM BRUH %d] %s ; src content = %p ; src addr = %p\n", tag_to_id(src_tag), ins_dasm, *((void **)src), (void *)src);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_bruh(THREADID tid,  uint32_t src, ADDRINT dest, void *src_content, char *ins_dasm) {
  tag_t src_tag = RTAG[src][0]; //TODO should this loop like in the others?

  if (tag_to_id(src_tag) == bruh_id || (void *)dest == (void *)BRUH_ADDR || src_content == (void *)BRUH_CONTENT) {
    LOG_DBG("[REG BRUH %d] %s ; src content = %p ; dest addr = %p\n", tag_to_id(src_tag), ins_dasm, src_content, (void *)dest);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2m_bruh(THREADID tid, ADDRINT src, ADDRINT dest, char *ins_dasm) {
  tag_t src_tag = MTAG(src);

  if (tag_to_id(src_tag) == bruh_id || (void *)dest == (void *)BRUH_ADDR || *((void **)src) == (void *)BRUH_CONTENT) {
    LOG_DBG("[MEM BRUH %d] %s ; src addr = %p ; src content = %p ; dest addr = %p ; dest content = %p\n", tag_to_id(src_tag), ins_dasm, (void *)src, *((void **)src), (void *)dest, *((void **)dest));
  }
}

static void insert_r2_bruh(INS ins, REG reg_src)
{
  char *cstr;
  cstr = new char[INS_Disassemble(ins).size() + 1];
  strcpy(cstr, INS_Disassemble(ins).c_str());
  if (INS_IsMemoryWrite(ins)) {
    if (REG_is_gr_type(reg_src) || REG_is_gr32(reg_src)) {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_bruh, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, REG_INDX(reg_src), IARG_MEMORYWRITE_EA, IARG_REG_VALUE, reg_src, IARG_PTR, cstr, IARG_END);
    } else {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_bruh, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, REG_INDX(reg_src), IARG_MEMORYWRITE_EA, IARG_PTR, NULL, IARG_PTR, cstr, IARG_END);
    }
  } else {
    if (REG_is_gr_type(reg_src) || REG_is_gr32(reg_src)) {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2_bruh, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, REG_INDX(reg_src), IARG_REG_VALUE, reg_src, IARG_PTR, cstr, IARG_END);
    } else {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2_bruh, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, REG_INDX(reg_src), IARG_PTR, NULL, IARG_PTR, cstr, IARG_END);
    }
  }
}

static void insert_m2_bruh(INS ins)
{
  char *cstr;
  cstr = new char[INS_Disassemble(ins).size() + 1];
  strcpy(cstr, INS_Disassemble(ins).c_str());

  if (INS_IsMemoryWrite(ins)) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2m_bruh, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_MEMORYREAD_EA, IARG_MEMORYWRITE_EA, IARG_PTR, cstr, IARG_END);
  } else {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2_bruh, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_MEMORYREAD_EA, IARG_PTR, cstr, IARG_END);
  }
}

void ins_movsx_op(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);

    insert_r2_bruh(ins, reg_src);

    if (REG_is_gr16(reg_dst)) {
      if (REG_is_Upper8(reg_src))
        R2R_CALL(_movsx_r2r_opwb_u, reg_dst, reg_src);
      else
        R2R_CALL(_movsx_r2r_opwb_l, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      if (REG_is_gr64(reg_dst))
        R2R_CALL(_movsx_r2r_opqw, reg_dst, reg_src);
      else if (REG_is_gr32(reg_dst))
        R2R_CALL(_movsx_r2r_oplw, reg_dst, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      if (REG_is_gr64(reg_dst))
        R2R_CALL(_movsx_r2r_opqb_u, reg_dst, reg_src);
      else if (REG_is_gr32(reg_dst))
        R2R_CALL(_movsx_r2r_oplb_u, reg_dst, reg_src);
    } else { // lower8
      if (REG_is_gr64(reg_dst))
        R2R_CALL(_movsx_r2r_opqb_l, reg_dst, reg_src);
      else if (REG_is_gr32(reg_dst))
        R2R_CALL(_movsx_r2r_oplb_l, reg_dst, reg_src);
    }
  } else {
    reg_dst = INS_OperandReg(ins, OP_0);

    insert_m2_bruh(ins);

    if (REG_is_gr16(reg_dst)) {
      M2R_CALL(_movsx_m2r_opwb, reg_dst);
    } else if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_WORD_LEN)) {
      if (REG_is_gr64(reg_dst)) {
        M2R_CALL(_movsx_m2r_opqw, reg_dst);
      } else if (REG_is_gr32(reg_dst)) {
        M2R_CALL(_movsx_m2r_oplw, reg_dst);
      }
    } else {
      if (REG_is_gr64(reg_dst)) {
        M2R_CALL(_movsx_m2r_opqb, reg_dst);
      } else if (REG_is_gr32(reg_dst)) {
        M2R_CALL(_movsx_m2r_oplb, reg_dst);
      }
    }
  }
}

void ins_movsxd_op(INS ins) {
  REG reg_dst, reg_src;
  reg_dst = INS_OperandReg(ins, OP_0);
  if (!REG_is_gr64(reg_dst)) {
    ins_xfer_op(ins);
  }
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_src = INS_OperandReg(ins, OP_1);

    insert_r2_bruh(ins, reg_src);

    R2R_CALL(_movsx_r2r_opql, reg_dst, reg_src);
  } else {

    insert_m2_bruh(ins);

    M2R_CALL(_movsx_m2r_opql, reg_dst);
  }
}