#include "ins_xfer_op.h"
#include "ins_clear_op.h"
#include "ins_helper.h"

extern unsigned int dont_instrument;

/* threads context */
extern thread_ctx_t *threads_ctx;

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_ul(THREADID tid, uint32_t dst,
                                            uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t src_tag = RTAG[src][0];

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_lu(THREADID tid, uint32_t dst,
                                            uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t src_tag = RTAG[src][1];

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t src_tag = RTAG[src][1];

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t src_tag = RTAG[src][0];

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opw(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
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
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  for (size_t i = 0; i < 4; i++) {
    RTAG[dst][i] = RTAG[src][i];
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opq(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  for (size_t i = 0; i < 8; i++) {
    RTAG[dst][i] = RTAG[src][i];
  }
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opx(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  for (size_t i = 0; i < 16; i++)
    RTAG[dst][i] = RTAG[src][i];
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opy(THREADID tid, uint32_t dst,
                                         uint32_t src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  for (size_t i = 0; i < 32; i++)
    RTAG[dst][i] = RTAG[src][i];
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_u(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t src_tag = MTAG(src);

  RTAG[dst][1] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opb_l(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  tag_t src_tag = MTAG(src);

  RTAG[dst][0] = src_tag;
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opw(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  for (size_t i = 0; i < 2; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opl(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  for (size_t i = 0; i < 4; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opx(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  for (size_t i = 0; i < 16; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opy(THREADID tid, uint32_t dst,
                                         ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  for (size_t i = 0; i < 32; i++)
    RTAG[dst][i] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_u(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t src_tag = RTAG[src][1];

  tagmap_setb(dst, src_tag);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opb_l(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t src_tag = RTAG[src][0];

  tagmap_setb(dst, src_tag);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opw(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t *src_tags = RTAG[src];

  tagmap_setb(dst, src_tags[0]);
  tagmap_setb(dst + 1, src_tags[1]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opl(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opx(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 16; i++)
    tagmap_setb(dst + i, src_tags[i]);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opy(THREADID tid, ADDRINT dst,
                                         uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 32; i++) {
    //printf("%ld\n", i);
    tagmap_setb(dst + i, src_tags[i]);
  }
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opb(ADDRINT dst, ADDRINT src) {
  //if (dont_instrument != 0) return;
  tag_t src_tag = MTAG(src);

  tagmap_setb(dst, src_tag);
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opw(ADDRINT dst, ADDRINT src) {
  //if (dont_instrument != 0) return;
  for (size_t i = 0; i < 2; i++)
    tagmap_setb(dst + i, MTAG(src + i));
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opl(ADDRINT dst, ADDRINT src) {
  //if (dont_instrument != 0) return;
  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, MTAG(src + i));
}

void PIN_FAST_ANALYSIS_CALL m2m_xfer_opq(ADDRINT dst, ADDRINT src) {
  //if (dont_instrument != 0) return;
  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, MTAG(src + i));
}

void PIN_FAST_ANALYSIS_CALL m2r_xfer_opq_h(THREADID tid, uint32_t dst,
                                           ADDRINT src) {
  //if (dont_instrument != 0) return;
  if ((REG)dst == BRUH_DFT_REG) puts("[BRUH REG]");
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i + 8] = MTAG(src + i);
}

void PIN_FAST_ANALYSIS_CALL r2m_xfer_opq_h(THREADID tid, ADDRINT dst,
                                           uint32_t src) {
  //if (dont_instrument != 0) return;
  tag_t *src_tags = RTAG[src];

  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, src_tags[i + 8]);
}

void PIN_FAST_ANALYSIS_CALL r2r_xfer_opx_lq_to_hq(THREADID tid, uint32_t dst, uint32_t src) { //UAVUZZ TODO check if correct
  //if (dont_instrument != 0) return;

  for (size_t i = 0 ; i < 8 ; i++) {
    RTAG[dst][i + 8] = RTAG[src][i];
  }
}

//This function is exactly same as m2r_xfer_opq_h XD
void PIN_FAST_ANALYSIS_CALL m2r_xfer_opx_lq_to_hq(THREADID tid, uint32_t dst, ADDRINT src) { //UAVUZZ TODO check if correct
  //if (dont_instrument != 0) return;

  for (size_t i = 0 ; i < 8 ; i++) {
    RTAG[dst][i + 8] = MTAG(src + i);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_xfer_opbn(THREADID tid, ADDRINT dst,
                                                 ADDRINT count,
                                                 ADDRINT eflags) {
  //if (dont_instrument != 0) return;
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
  //if (dont_instrument != 0) return;
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
  //if (dont_instrument != 0) return;
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
  //if (dont_instrument != 0) return;
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
  //if (dont_instrument != 0) return;
  for (size_t i = 0; i < 2; i++)
    RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
}

static void PIN_FAST_ANALYSIS_CALL _lea_opl(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  //if (dont_instrument != 0) return;
  for (size_t i = 0; i < 4; i++)
    RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
}

static void PIN_FAST_ANALYSIS_CALL _lea_opq(THREADID tid, uint32_t dst,
                                            uint32_t base, uint32_t index) {
  //if (dont_instrument != 0) return;
  for (size_t i = 0; i < 8; i++)
    RTAG[dst][i] = tag_combine(RTAG[base][i], RTAG[index][i]);
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

static void PIN_FAST_ANALYSIS_CALL r2m_bruh(THREADID tid, uint32_t src, ADDRINT dest, void *src_content, char *ins_dasm) {
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

void ins_xfer_op(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);

    insert_r2_bruh(ins, reg_src);

    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_xfer_opl, reg_dst, reg_src);
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

    insert_m2_bruh(ins);

    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_xfer_opw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) { //TODO this switch is for movq but maybe this invalidates some other instructions??? Maybe make seperate handler for movq? But then can reoccur at other ins....
      switch (INS_MemoryOperandSize(ins, 0)) { //TODO Its the first memory operand but not the first operand in general?? Is this correct?
        case 4:
          M2R_CALL(m2r_xfer_opl, reg_dst);
          break;
        case 8:
          M2R_CALL(m2r_xfer_opq, reg_dst);
          break;
        case 16:
          M2R_CALL(m2r_xfer_opx, reg_dst);
          break;
        default:
          printf("unsupported | %s | src memory operand size: %ld\n", INS_Disassemble(ins).c_str(), INS_MemoryOperandSize(ins, 0));
          abort();
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

    insert_r2_bruh(ins, reg_src);

    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_xfer_opw, reg_src);
    } else if (REG_is_xmm(reg_src) || REG_is_ymm(reg_src)) { //UAVUZZ
      switch (INS_MemoryOperandSize(ins, 0)) { //TODO not sure if some of these cases are actually possible. Will get performance benefit if we remove impossible cases.
        case 2:
          R2M_CALL(r2m_xfer_opw, reg_src);
          break;
        case 4:
          R2M_CALL(r2m_xfer_opl, reg_src);
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
          puts("unsupported");
          abort();
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

    insert_r2_bruh(ins, reg_src);

    if (REG_is_gr64(reg_dst)) {
      R2R_CALL_P(r2r_xfer_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL_P(r2r_xfer_opl, reg_dst, reg_src);
    } else {
      R2R_CALL_P(r2r_xfer_opw, reg_dst, reg_src);
    }
  } else {
    reg_dst = INS_OperandReg(ins, OP_0);

    insert_m2_bruh(ins);

    if (REG_is_gr64(reg_dst)) {
      M2R_CALL_P(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL_P(m2r_xfer_opl, reg_dst);
    } else {
      M2R_CALL_P(m2r_xfer_opw, reg_dst);
    }
  }
}

void ins_push_op(INS ins) {
  REG reg_src;
  if (INS_OperandIsReg(ins, OP_0)) {
    reg_src = INS_OperandReg(ins, OP_0);

    insert_r2_bruh(ins, reg_src);

    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl, reg_src);
    } else {
      R2M_CALL(r2m_xfer_opw, reg_src);
    }
  } else if (INS_OperandIsMemory(ins, OP_0)) {

    insert_m2_bruh(ins);

    if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_64BIT_LEN)) {
      M2M_CALL(m2m_xfer_opq);
    } else if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_LONG_LEN)) {
      M2M_CALL(m2m_xfer_opl);
    } else {
      M2M_CALL(m2m_xfer_opw);
    }
  } else {
    INT32 n = INS_OperandWidth(ins, OP_0) / 8;
    M_CLEAR_N(n);
  }
}

void ins_pop_op(INS ins) {
  REG reg_dst;
  if (INS_OperandIsReg(ins, OP_0)) {
    reg_dst = INS_OperandReg(ins, OP_0);

    insert_m2_bruh(ins);

    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl, reg_dst);
    } else {
      M2R_CALL(m2r_xfer_opw, reg_dst);
    }
  } else if (INS_OperandIsMemory(ins, OP_0)) {

    insert_m2_bruh(ins);

    if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_64BIT_LEN)) {
      M2M_CALL(m2m_xfer_opq);
    } else if (INS_MemoryWriteSize(ins) == BIT2BYTE(MEM_LONG_LEN)) {
      M2M_CALL(m2m_xfer_opl);
    } else {
      M2M_CALL(m2m_xfer_opw);
    }
  }
}

void ins_stos_ins(INS ins, AFUNPTR fn) { //TODO BRUH PRINTS
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

    insert_r2_bruh(ins, REG_AL);

    R2M_CALL(r2m_xfer_opb_l, REG_AL);
  }
}

void ins_stosw(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opwn);
  } else {

    insert_r2_bruh(ins, REG_AX);

    R2M_CALL(r2m_xfer_opw, REG_AX);
  }
}

void ins_stosd(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opln);
  } else {

    insert_r2_bruh(ins, REG_EAX);

    R2M_CALL(r2m_xfer_opw, REG_EAX);
  }
}

void ins_stosq(INS ins) {
  if (INS_RepPrefix(ins)) {
    ins_stos_ins(ins, (AFUNPTR)r2m_xfer_opqn);
  } else {

    insert_r2_bruh(ins, REG_RAX);

    R2M_CALL(r2m_xfer_opw, REG_RAX);
  }
}

void ins_movlp(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);

    insert_r2_bruh(ins, reg_src);

    R2M_CALL(r2m_xfer_opq, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);

    insert_m2_bruh(ins);

    M2R_CALL(m2r_xfer_opq, reg_dst);
  }
}

void ins_movhp(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);

    insert_r2_bruh(ins, reg_src);

    R2M_CALL(r2m_xfer_opq_h, reg_src);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);

    insert_m2_bruh(ins);

    M2R_CALL(m2r_xfer_opq_h, reg_dst);
  }
}

void ins_movlhp(INS ins) { //UAVUZZ TODO check if correct
  if (INS_OperandIsMemory(ins, OP_0) || INS_OperandIsMemory(ins, OP_1)) {
    puts("ins_movlhp illegal / unimplemented");
    abort();
  }

  REG reg_dst = INS_OperandReg(ins, OP_0);
  REG reg_src = INS_OperandReg(ins, OP_1);

  R2R_CALL(r2r_xfer_opx_lq_to_hq, reg_dst, reg_src);
}

void ins_punpcklqdq(INS ins) { //UAVUZZ TODO check if correct
  if (INS_OperandIsMemory(ins, OP_0)) {
    puts("ins_movlhp illegal / unimplemented");
    abort();
  }

  REG reg_dst = INS_OperandReg(ins, OP_0);

  if (INS_OperandIsMemory(ins, OP_1)) {
    M2R_CALL(m2r_xfer_opx_lq_to_hq, reg_dst);
  } else {
    REG reg_src = INS_OperandReg(ins, OP_1); //We are assuming this only takes xmm regs

    R2R_CALL(r2r_xfer_opx_lq_to_hq, reg_dst, reg_src);
  }
}

void ins_vmovsd_op(INS ins) {
  if (INS_OperandCount(ins) != 2) {
    puts("ins_vmovsd_op ternary unimplemented");
    abort();
  }

  if (INS_OperandIsMemory(ins, OP_0)) {
    REG reg_src = INS_OperandReg(ins, OP_1);

    M2R_CALL(r2m_xfer_opq, reg_src);
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    REG reg_dst = INS_OperandReg(ins, OP_0);

    M2R_CALL(m2r_xfer_opq, reg_dst);
  } else {
    puts("ins_vmovsd_op unexpected format");
    abort();
  }
}

void ins_lea(INS ins) {
  REG reg_base = INS_MemoryBaseReg(ins);
  REG reg_indx = INS_MemoryIndexReg(ins);
  REG reg_dst = INS_OperandReg(ins, OP_0);
  if (reg_base == REG_INVALID() && reg_indx == REG_INVALID()) {
    ins_clear_op(ins);
  }
  if (reg_base != REG_INVALID() && reg_indx == REG_INVALID()) {
    insert_r2_bruh(ins, reg_base);

    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_base);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_xfer_opl, reg_dst, reg_base);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_xfer_opw, reg_dst, reg_base);
    }
  }
  if (reg_base == REG_INVALID() && reg_indx != REG_INVALID()) {
    insert_r2_bruh(ins, reg_indx);

    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_xfer_opq, reg_dst, reg_indx);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_xfer_opl, reg_dst, reg_indx);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_xfer_opw, reg_dst, reg_indx);
    }
  }
  if (reg_base != REG_INVALID() && reg_indx != REG_INVALID()) {

    insert_r2_bruh(ins, reg_base);
    insert_r2_bruh(ins, reg_indx);

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

    insert_m2_bruh(ins);

    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_xfer_opq_rev, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_xfer_opl_rev, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_xfer_opw_rev, reg_dst);
    }
  } else {
    REG reg_src = INS_OperandReg(ins, OP_1);

    insert_r2_bruh(ins, reg_src);

    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_xfer_opq_rev, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_xfer_opl_rev, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_xfer_opw_rev, reg_src);
    }
  }
}