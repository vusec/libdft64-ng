#include "ins_binary_op.h"
#include "ins_helper.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

static void PIN_FAST_ANALYSIS_CALL i2m_masking_and(THREADID tid, uint32_t size, ADDRINT dst_addr, uint64_t imm) {
  for (size_t i = 0; i < size; i++, imm >>= 8) {
    // If the imm equals 0, then clear taint on the output
    if ((imm & 0xff) == 0) tagmap_setb(dst_addr + i, tag_traits<tag_t>::cleared_val);
  }
}

static void PIN_FAST_ANALYSIS_CALL i2r_masking_and(THREADID tid, uint32_t size, uint32_t dst_reg, uint64_t imm) {
  tag_t *dst_tags = RTAG[dst_reg];
  for (size_t i = 0; i < size; i++, imm >>= 8) {
    // If the imm equals 0, then clear taint on the output
    if ((imm & 0xff) == 0) dst_tags[i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_masking_and(THREADID tid, uint32_t size, uint32_t dst_reg, uint32_t src_reg, uint64_t src_val) {
  tag_t *src_tags = RTAG[src_reg];
  tag_t *dst_tags = RTAG[dst_reg];
  for (size_t i = 0; i < size; i++, src_val >>= 8) {
    // If the src is untainted and equals 0, then clear taint on the output
    if (tag_is_empty(src_tags[i]) && (src_val & 0xff) == 0) dst_tags[i] = tag_traits<tag_t>::cleared_val;
    else dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_masking_and(THREADID tid, uint32_t size, uint32_t dst_reg, ADDRINT src_addr) {
  tag_t *dst_tags = RTAG[dst_reg];
  for (size_t i = 0; i < size; i++) {
    // If the src is untainted and equals 0, then clear taint on the output
    if (tag_is_empty(tagmap_getb(src_addr + i)) && (*(UINT8*)(src_addr + i) == 0)) dst_tags[i] = tag_traits<tag_t>::cleared_val;
    else dst_tags[i] = tag_combine(dst_tags[i], MTAG(src_addr + i));
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_masking_and(THREADID tid, uint32_t size, ADDRINT dst_addr, uint32_t src_reg, uint64_t src_val) {
  tag_t *src_tags = RTAG[src_reg];
  for (size_t i = 0; i < size; i++, src_val >>= 8) {
    // If the src is untainted and equals 0, then clear taint on the output
    if (tag_is_empty(src_tags[i]) && (src_val & 0xff) == 0) tagmap_setb(dst_addr + i, tag_traits<tag_t>::cleared_val);
    else tagmap_setb(dst_addr + i, tag_combine(MTAG(dst_addr + i), src_tags[i]));
  }
}

void ins_masking_and(INS ins) {
  if (INS_OperandIsImmediate(ins, OP_1) && INS_OperandIsMemory(ins, OP_0)) {
    // Immediate to memory
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)i2m_masking_and, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, INS_OperandSize(ins, OP_0),
              IARG_MEMORYWRITE_EA,
              IARG_UINT64, INS_OperandImmediate(ins, OP_1),
              IARG_END);
  }
  else if (INS_OperandIsImmediate(ins, OP_1) && !INS_OperandIsMemory(ins, OP_0)) {
    // Immediate to register
    REG reg_dst = INS_OperandReg(ins, OP_0);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)i2r_masking_and, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, INS_OperandSize(ins, OP_0),
              IARG_UINT32, REG_INDX(reg_dst),
              IARG_UINT64, INS_OperandImmediate(ins, OP_1),
              IARG_END);
  }
  else if (INS_MemoryOperandCount(ins) == 0) {
    // Register to register
    REG reg_dst = INS_OperandReg(ins, OP_0);
    REG reg_src = INS_OperandReg(ins, OP_1);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_masking_and, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, INS_OperandSize(ins, OP_0),
                  IARG_UINT32, REG_INDX(reg_dst),
                  IARG_UINT32, REG_INDX(reg_src),
                  IARG_REG_VALUE, reg_src,
                  IARG_END);
  }
  else if (INS_OperandIsMemory(ins, OP_1)) {
    // Memory to register
    REG reg_dst = INS_OperandReg(ins, OP_0);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2r_masking_and, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, INS_OperandSize(ins, OP_0),
                  IARG_UINT32, REG_INDX(reg_dst),
                  IARG_MEMORYREAD_EA,
                  IARG_END);
  }
  else if (INS_OperandIsMemory(ins, OP_0)) {
    // Register to memory
    REG reg_src = INS_OperandReg(ins, OP_1);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_masking_and, IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, INS_OperandSize(ins, OP_0),
                  IARG_MEMORYWRITE_EA,
                  IARG_UINT32, REG_INDX(reg_src),
                  IARG_REG_VALUE, reg_src,
                  IARG_END);
  }
  else {
    LOG_ERR("%s:%d: Error: Unhandled 'and' instruction type: %s\n", __FILE__, __LINE__, INS_Disassemble(ins).c_str());
    ins_binary_op(ins);
  }
}