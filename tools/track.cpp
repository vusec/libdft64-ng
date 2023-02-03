#include "branch_pred.h"
#include "debug.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_hook.h"
#include <iostream>

VOID TestGetHandler(void *p) {
  uint64_t val = *((uint64_t *)p);
  tagqarr_t tarr = tagmap_getqarr((ADDRINT)p);
  printf("[PIN][GET] addr: %p, val: %lu, taint: %s\n", p, val, tagqarr_sprint(tarr).c_str());
}

VOID TestGetValHandler(THREADID tid, uint64_t v) {
  tagqarr_t tarr = tagmap_getqarr_reg(tid, X64_ARG0_REG, 8);
  printf("[PIN][GETVAL] val: %lu, taint: %s\n", v, tagqarr_sprint(tarr).c_str());
}

VOID TestSetHandler(void *p, unsigned int v, size_t n) {
  tag_t t = tag_alloc<tag_t>((ptroff_t) v);
  for (size_t i = 0; i < n; i++) {
    tagmap_setb((ADDRINT)p + i, t);
  }
  printf("[PIN][SET] addr: %p, taint: %s\n", p, tagn_sprint((ADDRINT)p,n).c_str());
}

VOID EntryPoint(VOID *v) {

  for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
    RTN test_get_rtn = RTN_FindByName(img, "__libdft_get_taint");
    if (RTN_Valid(test_get_rtn)) {
      RTN_Open(test_get_rtn);
      RTN_InsertCall(test_get_rtn, IPOINT_BEFORE, (AFUNPTR)TestGetHandler,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
      RTN_Close(test_get_rtn);
    }

    RTN test_set_rtn = RTN_FindByName(img, "__libdft_set_taint");
    if (RTN_Valid(test_set_rtn)) {
      RTN_Open(test_set_rtn);
      RTN_InsertCall(test_set_rtn, IPOINT_BEFORE, (AFUNPTR)TestSetHandler,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
      RTN_Close(test_set_rtn);
    }

    RTN test_getval_rtn = RTN_FindByName(img, "__libdft_getval_taint");
    if (RTN_Valid(test_getval_rtn)) {
      RTN_Open(test_getval_rtn);

      RTN_InsertCall(test_getval_rtn, IPOINT_BEFORE, (AFUNPTR)TestGetValHandler,
                     IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_END);
      RTN_Close(test_getval_rtn);
    }
  }
}

int main(int argc, char *argv[]) {

  PIN_InitSymbols();

  if (unlikely(PIN_Init(argc, argv))) {
    std::cerr
        << "Sth error in PIN_Init. Plz use the right command line options."
        << std::endl;
    return -1;
  }

  if (unlikely(libdft_init() != 0)) {
    std::cerr << "Sth error libdft_init." << std::endl;
    return -1;
  }

  PIN_AddApplicationStartFunction(EntryPoint, 0);

  hook_file_syscall();

  void tag_trait_set_print_decimal(void);
  tag_trait_set_print_decimal();

  PIN_StartProgram();

  return 0;
}
