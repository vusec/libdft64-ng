#ifndef MEMTAINT_H
#define MEMTAINT_H

typedef void (*memtaint_callback)();

void memtaint_add_callback(memtaint_callback fun);

#endif
