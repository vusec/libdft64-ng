
#ifndef __DEBUG_H__
#define __DEBUG_H__
#include "pin_log.h"

#include "def.h"

#define DEBUG_INFO 1

#define DUMP_ALL_INS // set dump_all_ins = 1 in your pintool to start dumping all ins and set it to 0 when you dumped enough (to prevent 20gb files )
#define DUMP_TAGMAP_SETB_ID 552
#define BRUH_ID 552
#define BRUH_ADDR 0x1337c0de
#define BRUH_CONTENT 0x1337c0de
#define BRUH_DFT_REG 63

/* log variables */
extern PinLog *_libdft_out;
extern PinLog *_libdft_err;
extern PinLog *_libdft_dbg;
extern bool _log_to_std;

// TODO: Refactor
#define LOGD LOG_DBG

#define LOG_OUT(...)             \
  do {                               \
    if (_log_to_std) {               \
      fprintf(stdout, __VA_ARGS__);  \
      fflush(stdout);                \
    } else {                         \
      _libdft_out->lock();           \
      _libdft_out->log(__VA_ARGS__); \
      _libdft_out->unlock();         \
  }} while (0)
#define LOG_ERR(...)             \
  do {                               \
    if (_log_to_std) {               \
      fprintf(stderr, __VA_ARGS__);  \
      fflush(stderr);                \
    } else {                         \
      _libdft_err->lock();           \
      _libdft_err->log(__VA_ARGS__); \
      _libdft_err->unlock();         \
  }} while (0)

#ifdef DEBUG_INFO
#define LOG_DBG(...)             \
  do {                               \
    if (_log_to_std) {               \
      fprintf(stdout, __VA_ARGS__);  \
      fflush(stdout);                \
    } else {                         \
      _libdft_dbg->lock();           \
      _libdft_dbg->log(__VA_ARGS__); \
      _libdft_dbg->unlock();         \
  }} while (0)
#else
#define LOG_DBG(...)
#endif



#endif