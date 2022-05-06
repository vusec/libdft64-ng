
#ifndef __DEBUG_H__
#define __DEBUG_H__

#include "def.h"

#define DEBUG_INFO 1

#define DUMP_ALL_INS // set dump_all_ins = 1 in your pintool to start dumping all ins and set it to 0 when you dumped enough (to prevent 20gb files )
#define DUMP_TAGMAP_SETB_ID 552
#define BRUH_ID 552
#define BRUH_ADDR 0x1337c0de
#define BRUH_CONTENT 0x1337c0de
#define BRUH_DFT_REG 63

#ifdef DEBUG_INFO
// #define DEBUG_PRINTF printf
#define LOGD(...)                                                              \
  do {                                                                         \
    printf(__VA_ARGS__);                                                       \
  } while (0)
#else
#define LOGD(...)
#endif

#define LOGE(...)                                                              \
  do {                                                                         \
    fprintf(stderr, __VA_ARGS__);                                              \
  } while (0)
#else

#endif