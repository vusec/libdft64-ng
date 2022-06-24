#ifndef __INS_MOVSX_OP_H__
#define __INS_MOVSX_OP_H__
#include "pin.H"

void PIN_FAST_ANALYSIS_CALL _movsx_r2r_opql(THREADID tid, uint32_t dst, uint32_t src);
void PIN_FAST_ANALYSIS_CALL _movsx_m2r_opql(THREADID tid, uint32_t dst, ADDRINT src);

void ins_movsx_op(INS ins);
void ins_movsxd_op(INS ins);

#endif