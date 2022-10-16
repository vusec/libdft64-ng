#include "ins_movsx_op.h"
#include "ins_helper.h"
#include "ins_xfer_op.h"
#include "libdft_core.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

/*
 * tag propagation (analysis function)
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */

// 8 (upper) --> 16
static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opwb_u(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  r2r_xfer_opb_lu(tid, dst, src);
  RTAG[dst][1] = tag_traits<tag_t>::cleared_val;
}

// 8 (lower) --> 16
static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opwb_l(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  r2r_xfer_opb_l(tid, dst, src);
  RTAG[dst][1] = tag_traits<tag_t>::cleared_val;
}

// 8 (upper) --> 32
static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_oplb_u(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  r2r_xfer_opb_lu(tid, dst, src);
  RTAG[dst][1] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][2] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][3] = tag_traits<tag_t>::cleared_val;
}

// 8 (lower) --> 32
static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_oplb_l(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  r2r_xfer_opb_l(tid, dst, src);
  RTAG[dst][1] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][2] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][3] = tag_traits<tag_t>::cleared_val;
}

// 8 (upper) --> 64
static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opqb_u(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  r2r_xfer_opb_lu(tid, dst, src);
  RTAG[dst][1] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][2] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][3] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][4] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][5] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][6] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][7] = tag_traits<tag_t>::cleared_val;
}

// 8 (lower) --> 64
static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opqb_l(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  r2r_xfer_opb_l(tid, dst, src);
  RTAG[dst][1] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][2] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][3] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][4] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][5] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][6] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][7] = tag_traits<tag_t>::cleared_val;
}

// 16 --> 32
static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_oplw(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
  r2r_xfer_opw(tid, dst, src);
  RTAG[dst][2] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][3] = tag_traits<tag_t>::cleared_val;
}

// 16 --> 64
static void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opqw(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
  r2r_xfer_opw(tid, dst, src);
  RTAG[dst][2] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][3] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][4] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][5] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][6] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][7] = tag_traits<tag_t>::cleared_val;
}

// 32 --> 64
void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opql(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
  r2r_xfer_opl(tid, dst, src);
  RTAG[dst][4] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][5] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][6] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][7] = tag_traits<tag_t>::cleared_val;
}

// [8] --> 16
static void PIN_FAST_ANALYSIS_CALL _movsx_m2r_opwb(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  m2r_xfer_opb_l(tid, dst, src);
  RTAG[dst][1] = tag_traits<tag_t>::cleared_val;
}

// [8] --> 32
static void PIN_FAST_ANALYSIS_CALL _movsx_m2r_oplb(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  m2r_xfer_opb_l(tid, dst, src);
  RTAG[dst][1] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][2] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][3] = tag_traits<tag_t>::cleared_val;
}

// [8] --> 64
static void PIN_FAST_ANALYSIS_CALL _movsx_m2r_opqb(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  m2r_xfer_opb_l(tid, dst, src);
  RTAG[dst][1] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][2] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][3] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][4] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][5] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][6] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][7] = tag_traits<tag_t>::cleared_val;
}

// [16] --> 32
static void PIN_FAST_ANALYSIS_CALL _movsx_m2r_oplw(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  m2r_xfer_opw(tid, dst, src);
  RTAG[dst][2] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][3] = tag_traits<tag_t>::cleared_val;
}

// [16] --> 64
static void PIN_FAST_ANALYSIS_CALL _movsx_m2r_opqw(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  m2r_xfer_opw(tid, dst, src);
  RTAG[dst][2] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][3] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][4] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][5] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][6] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][7] = tag_traits<tag_t>::cleared_val;
}

// [32] --> 64
void PIN_FAST_ANALYSIS_CALL _movsx_m2r_opql(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  m2r_xfer_opl(tid, dst, src);
  RTAG[dst][4] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][5] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][6] = tag_traits<tag_t>::cleared_val;
  RTAG[dst][7] = tag_traits<tag_t>::cleared_val;
}

void ins_movsx_op(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr16(reg_dst)) {
      if (REG_is_Upper8(reg_src)) {
        R2R_CALL(_movsx_r2r_opwb_u, reg_dst, reg_src); // 8 (upper) --> 16
        return;
      } else {
        R2R_CALL(_movsx_r2r_opwb_l, reg_dst, reg_src); // 8 (lower) --> 16
        return;
      }
    } else if (REG_is_gr16(reg_src)) {
      if (REG_is_gr64(reg_dst)) {
        R2R_CALL(_movsx_r2r_opqw, reg_dst, reg_src); // 16 --> 64
        return;
      } else if (REG_is_gr32(reg_dst)) {
        R2R_CALL(_movsx_r2r_oplw, reg_dst, reg_src); // 16 --> 32
        return;
      }
    } else if (REG_is_Upper8(reg_src)) {
      if (REG_is_gr64(reg_dst)) {
        R2R_CALL(_movsx_r2r_opqb_u, reg_dst, reg_src); // 8 (upper) --> 64
        return;
      } else if (REG_is_gr32(reg_dst)) {
        R2R_CALL(_movsx_r2r_oplb_u, reg_dst, reg_src); // 8 (upper) --> 32
        return;
      }
    } else { // lower8
      if (REG_is_gr64(reg_dst)) {
        R2R_CALL(_movsx_r2r_opqb_l, reg_dst, reg_src); // 8 (lower) --> 64
        return;
      } else if (REG_is_gr32(reg_dst)) {
        R2R_CALL(_movsx_r2r_oplb_l, reg_dst, reg_src); // 8 (lower) --> 32
        return;
      }
    }
  } else {
    reg_dst = INS_OperandReg(ins, OP_0);
    assert(INS_MemoryOperandIsRead(ins, MEMOP_0));
    USIZE n = INS_MemoryOperandSize(ins, MEMOP_0);
    if (REG_is_gr16(reg_dst)) {
      M2R_CALL(_movsx_m2r_opwb, reg_dst);   // [8] --> 16
      return;
    } else if (n == BIT2BYTE(MEM_WORD_LEN)) {
      if (REG_is_gr64(reg_dst)) {
        M2R_CALL(_movsx_m2r_opqw, reg_dst); // [16] --> 64
        return;
      } else if (REG_is_gr32(reg_dst)) {
        M2R_CALL(_movsx_m2r_oplw, reg_dst); // [16] --> 32
        return;
      }
    } else {
      if (REG_is_gr64(reg_dst)) {
        M2R_CALL(_movsx_m2r_opqb, reg_dst); // [8] --> 64
        return;
      } else if (REG_is_gr32(reg_dst)) {
        M2R_CALL(_movsx_m2r_oplb, reg_dst); // [8] --> 32
        return;
      }
    }
  }
  ins_uninstrumented(ins);
}

void ins_movsxd_op(INS ins) {
  REG reg_dst, reg_src;
  reg_dst = INS_OperandReg(ins, OP_0);
  if (!REG_is_gr64(reg_dst)) {
    // TODO: If 32 --> 32, should we actually sign extend to 64-bit?
    ins_xfer_op(ins); // 16 --> 16; 32 --> 32
  }
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_src = INS_OperandReg(ins, OP_1);
    R2R_CALL(_movsx_r2r_opql, reg_dst, reg_src);  // 32 --> 64
  } else {
    M2R_CALL(_movsx_m2r_opql, reg_dst);           // [32] --> 64
  }
}