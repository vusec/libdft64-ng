#include "ins_clear_op.h"
#include "ins_helper.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

static void PIN_FAST_ANALYSIS_CALL r_clrl4(THREADID tid) {
  for (size_t i = 0; i < 8; i++) {
    RTAG[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RCX][i] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RBX][i] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clrl2(THREADID tid) {
  for (size_t i = 0; i < 8; i++) {
    RTAG[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clrb_l(THREADID tid, uint32_t reg) {
  RTAG[reg][0] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL r_clrb_u(THREADID tid, uint32_t reg) {
  RTAG[reg][1] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL r_clrw(THREADID tid, uint32_t reg) {
  for (size_t i = 0; i < 2; i++) {
    RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clrl(THREADID tid, uint32_t reg) {
  for (size_t i = 0; i < 4; i++) {
    RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clrq(THREADID tid, uint32_t reg) {
  for (size_t i = 0; i < 8; i++) {
    RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clrx(THREADID tid, uint32_t reg) {
  for (size_t i = 0; i < 16; i++) {
    RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clry(THREADID tid, uint32_t reg) {
  for (size_t i = 0; i < 32; i++) { //UAVUZZ ; was 16 but actually has to be 32 ; TODO IS THIS CORRECT????
    RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clry_upper_all(THREADID tid) { //UAVUZZ
  //TODO check if correct
  for (uint32_t reg = DFT_REG_XMM0 ; reg <= DFT_REG_XMM15 ; reg++) {
    for (size_t i = 16 ; i < 32 ; i++) {
      RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
    }
  }
}

static const unsigned int bruh_id = BRUH_ID;

static void PIN_FAST_ANALYSIS_CALL r2_clear_bruh(THREADID tid, uint32_t dest, char *ins_dasm) {
  tag_t dest_tag = RTAG[dest][0]; //TODO should this loop like in the others?

  if (tag_to_id(dest_tag) == bruh_id) {
    LOG_DBG("[REG CLEAR BRUH %d] %s\n", bruh_id, ins_dasm);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2_clear_bruh(THREADID tid, ADDRINT dest, char *ins_dasm) {
  tag_t dest_tag = MTAG(dest);

  if (tag_to_id(dest_tag) == bruh_id || (void *)dest == (void *)BRUH_ADDR) {
    LOG_DBG("[MEM CLEAR BRUH %d] %s\n", tag_to_id(dest_tag), ins_dasm);
  }
}

static void insert_r2_clear_bruh(INS ins, REG reg_dest)
{
  char *cstr;
  cstr = new char[INS_Disassemble(ins).size() + 1];
  strcpy(cstr, INS_Disassemble(ins).c_str());
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2_clear_bruh, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, REG_INDX(reg_dest), IARG_PTR, cstr, IARG_END);
}

static void insert_m2_clear_bruh(INS ins)
{
  char *cstr;
  cstr = new char[INS_Disassemble(ins).size() + 1];
  strcpy(cstr, INS_Disassemble(ins).c_str());
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2_clear_bruh, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_MEMORYWRITE_EA, IARG_PTR, cstr, IARG_END);
}

void ins_clear_op(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {

    insert_m2_clear_bruh(ins);

    INT32 n = INS_OperandWidth(ins, OP_0) / 8;
    M_CLEAR_N(n);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);

    insert_r2_clear_bruh(ins, reg_dst);

    if (REG_is_gr64(reg_dst)) {
      R_CALL(r_clrq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      R_CALL(r_clrl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      R_CALL(r_clrw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      R_CALL(r_clrx, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      R_CALL(r_clrq, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      R_CALL(r_clry, reg_dst);
    } else {
      if (REG_is_Upper8(reg_dst))
        R_CALL(r_clrb_u, reg_dst);
      else
        R_CALL(r_clrb_l, reg_dst);
    }
  }
}

void ins_clear_op_predicated(INS ins) {
  // one byte
  if (INS_MemoryOperandCount(ins) == 0) {
    REG reg_dst = INS_OperandReg(ins, OP_0);

    insert_r2_clear_bruh(ins, reg_dst);

    if (REG_is_Upper8(reg_dst))
      INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)r_clrb_u,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst), IARG_END);
    else
      INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)r_clrb_l,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst), IARG_END);
  } else
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)tagmap_clrn,
                             IARG_FAST_ANALYSIS_CALL, IARG_MEMORYWRITE_EA,
                             IARG_UINT32, 1, IARG_END);
}

void ins_clear_op_l2(INS ins) {
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_clrl2, IARG_FAST_ANALYSIS_CALL,
                 IARG_THREAD_ID, IARG_END);
}

void ins_clear_op_l4(INS ins) {
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_clrl4, IARG_FAST_ANALYSIS_CALL,
                 IARG_THREAD_ID, IARG_END);
}

void ins_vzeroupper_op(INS ins) { //UAVUZZ
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_clry_upper_all, IARG_FAST_ANALYSIS_CALL,
                 IARG_THREAD_ID, IARG_END);
}