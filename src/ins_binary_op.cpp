#include "ins_binary_op.h"
#include "ins_helper.h"

extern unsigned int dont_instrument;

/* threads context */
extern thread_ctx_t *threads_ctx;

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_ul(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_lu(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_u(THREADID tid, uint32_t dst,
                                                    uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_l(THREADID tid, uint32_t dst,
                                                    uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opw(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 2; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opl(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 4; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opq(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 8; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opx(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 16; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opy(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");

  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 32; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opb_u(THREADID tid, uint32_t dst,
                                                    ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(src_tag, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opb_l(THREADID tid, uint32_t dst,
                                                    ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(src_tag, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opw(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 2; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opl(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 4; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opq(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 8; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opx(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 16; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opy(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 32; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opb_u(THREADID tid, ADDRINT dst,
                                                    uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = MTAG(dst);

  tag_t res_tag = tag_combine(dst_tag, src_tag);
  tagmap_setb(dst, res_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opb_l(THREADID tid, ADDRINT dst,
                                                    uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = MTAG(dst);

  tag_t res_tag = tag_combine(dst_tag, src_tag);
  tagmap_setb(dst, res_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opw(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 2; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opl(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opq(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opx(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 16; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opy(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 32; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static const unsigned int bruh_id = BRUH_ID;

static void PIN_FAST_ANALYSIS_CALL r2_bruh(THREADID tid, uint32_t src, void *src_content, char *ins_dasm) {
  tag_t src_tag = RTAG[src][0]; //TODO should this loop like in the others?

  if (tag_to_id(src_tag) == bruh_id || src_content == (void *)BRUH_CONTENT) {
    LOGD("[REG BRUH %d] %s ; src content = %p\n", tag_to_id(src_tag), ins_dasm, src_content);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2_bruh(THREADID tid, ADDRINT src, char *ins_dasm) {
  tag_t src_tag = MTAG(src);

  if (tag_to_id(src_tag) == bruh_id || *((void **)src) == (void *)BRUH_CONTENT) {
    LOGD("[MEM BRUH %d] %s ; src content = %p ; src addr = %p\n", tag_to_id(src_tag), ins_dasm, *((void **)src), (void *)src);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_bruh(THREADID tid,  uint32_t src, ADDRINT dest, void *src_content, char *ins_dasm) {
  tag_t src_tag = RTAG[src][0]; //TODO should this loop like in the others?

  if (tag_to_id(src_tag) == bruh_id || (void *)dest == (void *)BRUH_ADDR || src_content == (void *)BRUH_CONTENT) {
    LOGD("[REG BRUH %d] %s ; src content = %p ; dest addr = %p\n", tag_to_id(src_tag), ins_dasm, src_content, (void *)dest);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2m_bruh(THREADID tid, ADDRINT src, ADDRINT dest, char *ins_dasm) {
  tag_t src_tag = MTAG(src);

  if (tag_to_id(src_tag) == bruh_id || (void *)dest == (void *)BRUH_ADDR || *((void **)src) == (void *)BRUH_CONTENT) {
    LOGD("[MEM BRUH %d] %s ; src addr = %p ; src content = %p ; dest addr = %p ; dest content = %p\n", tag_to_id(src_tag), ins_dasm, (void *)src, *((void **)src), (void *)dest, *((void **)dest));
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

void ins_binary_op(INS ins) {
  if (INS_OperandIsImmediate(ins, OP_1))
    return;
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);

    insert_r2_bruh(ins, reg_src);

    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_binary_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_binary_opl, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_binary_opw, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {
      R2R_CALL(r2r_binary_opx, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {
      R2R_CALL(r2r_binary_opy, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {
      R2R_CALL(r2r_binary_opq, reg_dst, reg_src);
    } else {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src))
        R2R_CALL(r2r_binary_opb_l, reg_dst, reg_src);
      else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src))
        R2R_CALL(r2r_binary_opb_u, reg_dst, reg_src);
      else if (REG_is_Lower8(reg_dst))
        R2R_CALL(r2r_binary_opb_lu, reg_dst, reg_src);
      else
        R2R_CALL(r2r_binary_opb_ul, reg_dst, reg_src);
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    reg_dst = INS_OperandReg(ins, OP_0);

    insert_m2_bruh(ins);

    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_binary_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_binary_opl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_binary_opw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      M2R_CALL(m2r_binary_opx, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      M2R_CALL(m2r_binary_opy, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      M2R_CALL(m2r_binary_opq, reg_dst);
    } else if (REG_is_Upper8(reg_dst)) {
      M2R_CALL(m2r_binary_opb_u, reg_dst);
    } else {
      M2R_CALL(m2r_binary_opb_l, reg_dst);
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);

    insert_r2_bruh(ins, reg_src);

    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_binary_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_binary_opl, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_binary_opw, reg_src);
    } else if (REG_is_xmm(reg_src)) {
      R2M_CALL(r2m_binary_opx, reg_src);
    } else if (REG_is_ymm(reg_src)) {
      R2M_CALL(r2m_binary_opy, reg_src);
    } else if (REG_is_mm(reg_src)) {
      R2M_CALL(r2m_binary_opq, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL(r2m_binary_opb_u, reg_src);
    } else {
      R2M_CALL(r2m_binary_opb_l, reg_src);
    }
  }
}
