
#ifndef __DEBUG_H__
#define __DEBUG_H__
#include "pin_log.h"

// #define DEBUG_INFO 1

/* log variables */
extern PinLog *_libdft_out;
extern PinLog *_libdft_err;
extern PinLog *_libdft_dbg;
extern bool _log_to_std;

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