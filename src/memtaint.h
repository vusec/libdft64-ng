#ifndef __MEMTAINT_H__
#define __MEMTAINT_H__

#include "config.h"

void memtaint_taint_all(void);
void memtaint_set_callback(void(*new_callback)());
void memtaint_set_only_do_callback(bool b);
void memtaint_dont_taint_nonwritable_mem(void);
void memtaint_dont_taint_stack_mem(void);
void memtaint_enable_snapshot(std::string filename);

#endif /* __MEMTAINT_H__ */