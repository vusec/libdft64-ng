#ifndef __INS_CLEAR_OP_H__
#define __INS_CLEAR_OP_H__
#include "pin.H"

void ins_clear_op(INS ins);

void ins_clear_op_predicated(INS ins);
void ins_clear_op_l2(INS ins);
void ins_clear_op_l4(INS ins);
void ins_vzeroupper_op(INS ins);
void ins_clear_reg_byteat(INS ins, REG reg_dst, UINT32 b);
void ins_clear_mem_byteat(INS ins, UINT32 b);

#endif