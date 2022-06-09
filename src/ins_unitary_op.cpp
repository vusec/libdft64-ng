#include "ins_unitary_op.h"
#include "ins_helper.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opb_u(THREADID tid,
                                                     uint32_t src) {
  tag_t tmp_tag = RTAG[src][1];

  RTAG[DFT_REG_RAX][0] = tag_combine(RTAG[DFT_REG_RAX][0], tmp_tag);
  RTAG[DFT_REG_RAX][1] = tag_combine(RTAG[DFT_REG_RAX][1], tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opb_l(THREADID tid,
                                                     uint32_t src) {
  tag_t tmp_tag = RTAG[src][0];

  RTAG[DFT_REG_RAX][0] = tag_combine(RTAG[DFT_REG_RAX][0], tmp_tag);
  RTAG[DFT_REG_RAX][1] = tag_combine(RTAG[DFT_REG_RAX][1], tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opw(THREADID tid, uint32_t src) {
  tag_t tmp_tag[] = {RTAG[src][0], RTAG[src][1]};
  tag_t dst1_tag[] = {RTAG[DFT_REG_RDX][0], RTAG[DFT_REG_RDX][1]};
  tag_t dst2_tag[] = {RTAG[DFT_REG_RAX][0], RTAG[DFT_REG_RAX][1]};

  RTAG[DFT_REG_RDX][0] = tag_combine(dst1_tag[0], tmp_tag[0]);
  RTAG[DFT_REG_RDX][1] = tag_combine(dst1_tag[1], tmp_tag[1]);

  RTAG[DFT_REG_RAX][0] = tag_combine(dst2_tag[0], tmp_tag[0]);
  RTAG[DFT_REG_RAX][1] = tag_combine(dst2_tag[1], tmp_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opq(THREADID tid, uint32_t src) {
  tag_t tmp_tag[] = R64TAG(src);
  tag_t dst1_tag[] = R64TAG(DFT_REG_RDX);
  tag_t dst2_tag[] = R64TAG(DFT_REG_RAX);

  for (size_t i = 0; i < 8; i++) {
    RTAG[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
    RTAG[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_unitary_opl(THREADID tid, uint32_t src) {
  tag_t tmp_tag[] = R32TAG(src);
  tag_t dst1_tag[] = R32TAG(DFT_REG_RDX);
  tag_t dst2_tag[] = R32TAG(DFT_REG_RAX);

  for (size_t i = 0; i < 4; i++) {
    RTAG[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
    RTAG[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opb(THREADID tid, ADDRINT src) {
  tag_t tmp_tag = MTAG(src);
  tag_t dst_tag[] = R16TAG(DFT_REG_RAX);

  RTAG[DFT_REG_RAX][0] = tag_combine(dst_tag[0], tmp_tag);
  RTAG[DFT_REG_RAX][1] = tag_combine(dst_tag[1], tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opw(THREADID tid, ADDRINT src) {
  tag_t tmp_tag[] = M16TAG(src);
  tag_t dst1_tag[] = R16TAG(DFT_REG_RDX);
  tag_t dst2_tag[] = R16TAG(DFT_REG_RAX);

  for (size_t i = 0; i < 2; i++) {
    RTAG[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
    RTAG[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opq(THREADID tid, ADDRINT src) {
  tag_t tmp_tag[] = M64TAG(src);
  tag_t dst1_tag[] = R64TAG(DFT_REG_RDX);
  tag_t dst2_tag[] = R64TAG(DFT_REG_RAX);

  for (size_t i = 0; i < 8; i++) {
    RTAG[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
    RTAG[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_unitary_opl(THREADID tid, ADDRINT src) {
  tag_t tmp_tag[] = M32TAG(src);
  tag_t dst1_tag[] = R32TAG(DFT_REG_RDX);
  tag_t dst2_tag[] = R32TAG(DFT_REG_RAX);

  for (size_t i = 0; i < 4; i++) {
    RTAG[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
    RTAG[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
  }
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

void ins_unitary_op(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {

    insert_m2_bruh(ins);

    switch (INS_MemoryWriteSize(ins)) {
    case BIT2BYTE(MEM_64BIT_LEN):
      M_CALL_R(m2r_unitary_opq);
      break;
    case BIT2BYTE(MEM_LONG_LEN):
      M_CALL_R(m2r_unitary_opl);
      break;
    case BIT2BYTE(MEM_WORD_LEN):
      M_CALL_R(m2r_unitary_opw);
      break;
    case BIT2BYTE(MEM_BYTE_LEN):
    default:
      M_CALL_R(m2r_unitary_opb);
      break;
    }
  } else {
    REG reg_src = INS_OperandReg(ins, OP_0);

    insert_r2_bruh(ins, reg_src);

    if (REG_is_gr64(reg_src))
      R_CALL(r2r_unitary_opq, reg_src);
    else if (REG_is_gr32(reg_src))
      R_CALL(r2r_unitary_opl, reg_src);
    else if (REG_is_gr16(reg_src))
      R_CALL(r2r_unitary_opw, reg_src);
    else if (REG_is_Upper8(reg_src))
      R_CALL(r2r_unitary_opb_u, reg_src);
    else
      R_CALL(r2r_unitary_opb_l, reg_src);
  }
}