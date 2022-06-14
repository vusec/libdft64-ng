/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "libdft_api.h"
#include "branch_pred.h"
#include "debug.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "syscall_hook.h"
#include "libdft_cmd.h"
#include "load_ptr_prop.h"

/* threads context counter */
static size_t tctx_ct = 0;
/* threads context */
thread_ctx_t *threads_ctx = NULL;

/* ins descriptors */
ins_desc_t ins_desc[XED_ICLASS_LAST];

/* log variables */
PinLog *_libdft_out = NULL;
PinLog *_libdft_err = NULL;
PinLog *_libdft_dbg = NULL;
bool _log_to_std = true;

/*
 * thread start callback (analysis function)
 *
 * allocate space for the syscall context and VCPUs (i.e., thread context)
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @flags:	OS specific flags for the new thread
 * @v:		callback value
 */
static void thread_alloc(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v) {
  /* store the old threads context */
  thread_ctx_t *tctx_prev = threads_ctx;

  /*
   * we need more thread contexts; optimized branch (not so frequent);
   *
   * NOTE: in case the tid is greater than tctx_ct + THREAD_CTX_BLK we
   * need to loop in order to allocate enough thread contexts
   */
  while (unlikely(tid >= tctx_ct)) {
    /* reallocate space; optimized branch */
    if (unlikely((threads_ctx = (thread_ctx_t *)realloc(
                      threads_ctx, (tctx_ct + THREAD_CTX_BLK) *
                                       sizeof(thread_ctx_t))) == NULL)) {
      /* failed; this is fatal we need to terminate */

      /* cleanup */
      free(tctx_prev);

      /* error message */
      LOG_ERR("%s:%u", __func__, __LINE__);

      /* die */
      libdft_die();
    }

    /* success; patch the counter */
    tctx_ct += THREAD_CTX_BLK;
  }
}

// thread_free?

static tag_t sysenter_get_arg_taint(THREADID tid, unsigned arg_num) {
  switch (arg_num) {
  case SYSCALL_ARG0: // ARG0 in RDI
    return tagmap_getn_reg(tid, DFT_REG_RDI, sizeof(ADDRINT));
  case SYSCALL_ARG1: // ARG1 in RSI
    return tagmap_getn_reg(tid, DFT_REG_RSI, sizeof(ADDRINT));
  case SYSCALL_ARG2: // ARG2 in RDX
    return tagmap_getn_reg(tid, DFT_REG_RDX, sizeof(ADDRINT));
  case SYSCALL_ARG3: // ARG3 in R10
    return tagmap_getn_reg(tid, DFT_REG_R10, sizeof(ADDRINT));
  case SYSCALL_ARG4: // ARG4 in R8
    return tagmap_getn_reg(tid, DFT_REG_R8, sizeof(ADDRINT));
  case SYSCALL_ARG5: // ARG5 in R9
    return tagmap_getn_reg(tid, DFT_REG_R9, sizeof(ADDRINT));
  }
  assert(false); // Unexpected number of args. Should never be reached.
}

/*
 * syscall enter notification (analysis function)
 *
 * save the system call context and invoke any pre-syscall callback
 * functions that have been registered
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @std:	syscall standard (e.g., Linux IA-32, IA-64, etc)
 * @v:		callback value
 */
static void sysenter_save(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std,
                          VOID *v) {
  /* get the syscall number */
  size_t syscall_nr = PIN_GetSyscallNumber(ctx, std);
  // LOG_DBG("[syscall] %ld\n", syscall_nr);
  /* unknown syscall; optimized branch */
  if (unlikely(syscall_nr >= SYSCALL_MAX)) {
    LOG_ERR("%s:%u: unknown syscall(num=%lu)", __func__, __LINE__,
            syscall_nr);
    /* syscall number is set to -1; hint for the sysexit_save() */
    threads_ctx[tid].syscall_ctx.nr = -1;
    /* no context save and no pre-syscall callback invocation */
    return;
  }

  /* pass the system call number to sysexit_save() */
  threads_ctx[tid].syscall_ctx.nr = syscall_nr;

  /* save the arguments and arguments' taint */
  memset(&threads_ctx[tid].syscall_ctx.arg[0], 0, SYSCALL_ARG_NUM*sizeof(ADDRINT));
  memset(&threads_ctx[tid].syscall_ctx.arg_taint[0], 0, SYSCALL_ARG_NUM*sizeof(tag_t));
  for (size_t i = 0; i < syscall_desc[syscall_nr].nargs; i++) {
    ADDRINT this_arg = PIN_GetSyscallArgument(ctx, std, i);
    threads_ctx[tid].syscall_ctx.arg[i] = this_arg;
    threads_ctx[tid].syscall_ctx.arg_taint[i] = sysenter_get_arg_taint(tid, i);
  }

  /*
   * dump the architectural state of the processor;
   * saved as "auxiliary" data
   */
  threads_ctx[tid].syscall_ctx.aux = ctx;

  /* call the pre-syscall callback (if any); optimized branch */
  if (unlikely(syscall_desc[syscall_nr].pre != NULL))
    syscall_desc[syscall_nr].pre(tid, &threads_ctx[tid].syscall_ctx);
}

/*
 * syscall exit notification (analysis function)
 *
 * save the system call context and invoke any post-syscall callback
 * functions that have been registered
 *
 * NOTE: it performs tag cleanup for the syscalls that have side-effects in
 * their arguments
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @std:	syscall standard (e.g., Linux IA-32, IA-64, etc)
 * @v:		callback value
 */
static void sysexit_save(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std,
                         VOID *v) {
  /* iterator */
  size_t i;

  /* get the syscall number */
  int syscall_nr = threads_ctx[tid].syscall_ctx.nr;

  /* unknown syscall; optimized branch */
  if (unlikely(syscall_nr < 0)) {
    LOG_ERR("%s:%u: unknown syscall(num=%d)", __func__, __LINE__,
            syscall_nr);
    /* no context save and no pre-syscall callback invocation */
    return;
  }

  /*
   * return value of a syscall is store in EAX, usually it is not a pointer
   * So need to clean the tag of EAX, if it is, the post function should
   * retag EAX
   */

  /*
   * check if we need to save the arguments for that syscall
   *
   * we save only when we have a callback registered or the syscall
   * returns a value in the arguments
   */
  if (syscall_desc[syscall_nr].save_args |
      syscall_desc[syscall_nr].retval_args) {
    /* dump only the appropriate number of arguments */
    threads_ctx[tid].syscall_ctx.ret = PIN_GetSyscallReturn(ctx, std);

    /*
     * dump the architectural state of the processor;
     * saved as "auxiliary" data
     */
    threads_ctx[tid].syscall_ctx.aux = ctx;

    /* thread_ctx[tid].syscall_ctx.errno =
       PIN_GetSyscallErrno(ctx, std); */

    /* call the post-syscall callback (if any) */
    if (syscall_desc[syscall_nr].post != NULL) {
      syscall_desc[syscall_nr].post(tid, &threads_ctx[tid].syscall_ctx);
    } else {
      /* default post-syscall handling */

      /*
       * the syscall failed; typically 0 and positive
       * return values indicate success
       */
      if (threads_ctx[tid].syscall_ctx.ret < 0)
        /* no need to do anything */
        return;

      /* traverse the arguments map */
      for (i = 0; i < syscall_desc[syscall_nr].nargs; i++)
        /* analyze each argument */
        if (unlikely(syscall_desc[syscall_nr].map_args[i] > 0))
          /* sanity check -- probably non needed */
          if (likely((void *)threads_ctx[tid].syscall_ctx.arg[i] != NULL))
            /*
             * argument i is changed by the system call;
             * the length of the change is given by
             * map_args[i]
             */
            tagmap_clrn(threads_ctx[tid].syscall_ctx.arg[i],
                        syscall_desc[syscall_nr].map_args[i]);
    }
  }
}

/*
 * trace inspection (instrumentation function)
 *
 * traverse the basic blocks (BBLs) on the trace and
 * inspect every instruction for instrumenting it
 * accordingly
 *
 * @trace:      instructions trace; given by PIN
 */
static void trace_inspect(TRACE trace, VOID *v) {
  /* iterators */
  BBL bbl;
  INS ins;
  xed_iclass_enum_t ins_indx;

  /* traverse all the BBLs in the trace */
  for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    /* traverse all the instructions in the BBL */
    for (ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      // if (!is_tainted())
      //  continue;
      /*
       * use XED to decode the instruction and
       * extract its opcode
       */
      ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

      /*
       * invoke the pre-ins insrumentation callback;
       * optimized branch
       */
      if (unlikely(ins_desc[ins_indx].pre != NULL))
        ins_desc[ins_indx].pre(ins);

      /* analyze the instruction */
      /*
      if (is_tainted())
        LOG_DBG("[ins] %s\n", INS_Disassemble(ins).c_str());
      */
      ins_inspect(ins);
      /*
       * invoke the post-ins insrumentation callback;
       * optimized branch
       */
      if (unlikely(ins_desc[ins_indx].post != NULL))
        ins_desc[ins_indx].post(ins);
    }
  }
}

/*
 * initialize thread contexts
 *
 * allocate space for the thread contexts and
 * register a thread start callback
 *
 * returns: 0 on success, 1 on error
 */
static inline int thread_ctx_init(void) {
  /* allocate space for the thread contexts; optimized branch
   *
   * NOTE: allocation is performed in blocks of THREAD_CTX_BLK
   */
  threads_ctx = new thread_ctx_t[THREAD_CTX_BLK]();

  if (unlikely(threads_ctx == NULL)) {
    LOG_ERR("%s:%u", __func__, __LINE__);
    /* failed */
    libdft_die();
    return 1;
  }

  /* initialize the context counter */
  tctx_ct = THREAD_CTX_BLK;

  /*
   * thread start hook;
   * keep track of the threads and allocate space for the per-thread
   * logistics (i.e., syscall context, VCPU, etc)
   */
  PIN_AddThreadStartFunction(thread_alloc, NULL);

  /* success */
  return 0;
}

static void
libdft_cmd_handler(ADDRINT cmd, ADDRINT arg1, const CONTEXT *ctxt)
{
	switch (cmd)
	{
	case CMD_TAINT_DUMP:
		extern void taint_dump(ADDRINT);
		taint_dump(arg1);
		break;
#ifdef LIBDFT_TAG_PTR
	case CMD_TAINT_MEM_ALL:
		extern void memtaint_taint_all();
		memtaint_taint_all();
		break;
#endif
	default:
		LOG_ERR("Invalid libdft command: %lu\n", cmd);
		break;
	}
}

static void
libdft_cmd_img(IMG img, void *v)
{
	RTN rtn = RTN_FindByName(img, "__libdft_cmd");
	if (RTN_Valid(rtn))
	{
		RTN_Open(rtn);
		// Instrument __libdft_cmd() to process the command.
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)libdft_cmd_handler,
					   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
					   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
					   IARG_CONTEXT,
					   IARG_END);
		RTN_Close(rtn);
	}
}

/*
 * initialization of the core tagging engine;
 * it must be called before using everything else
 *
 * @argc:	argc passed in main
 * @argv:	argv passed in main
 *
 * returns: 0 on success, 1 on error
 */
int libdft_init() {

  // std::ios::sync_with_stdio(false);

  /* initialize symbol processing */
  PIN_InitSymbolsAlt(IFUNC_SYMBOLS);

  /* initialize thread contexts; optimized branch */
  if (unlikely(thread_ctx_init()))
    /* thread contexts failed */
    return 1;

  /* initialize the tagmap; optimized branch */
  if (unlikely(tagmap_alloc()))
    /* tagmap initialization failed */
    return 1;

  /*
   * syscall hooks; store the context of every syscall
   * and invoke registered callbacks (if any)
   */

  /* register sysenter_save() to be called before every syscall */
  PIN_AddSyscallEntryFunction(sysenter_save, NULL);

  /* register sysexit_save() to be called after every syscall */
  PIN_AddSyscallExitFunction(sysexit_save, NULL);

  /* initialize the ins descriptors */
  (void)memset(ins_desc, 0, sizeof(ins_desc));

  /* register trace_ins() to be called for every trace */
  TRACE_AddInstrumentFunction(trace_inspect, NULL);

	/* register libdft command server */
	IMG_AddInstrumentFunction(libdft_cmd_img, NULL);

  /* success */
  return 0;
}

int libdft_set_log_dir(std::string path) {
  // Write log files to specified directory
  std::string path_out = path + "/libdft.%s.out";
  std::string path_err = path + "/libdft.%s.err";
  std::string path_dbg = path + "/libdft.%s.dbg";
  _libdft_out = new PinLogPerThread(path_out.c_str());
  _libdft_err = new PinLogPerThread(path_err.c_str());
  _libdft_dbg = new PinLogPerThread(path_dbg.c_str());
  _log_to_std = false; // No longer logging to stdout/stderr
  return 0;
}

void libdft_enable_load_ptr_prop(void) {
  TRACE_AddInstrumentFunction(instrument_load_ptr_prop, NULL);
}

/*
 * stop the execution of the application inside the
 * tag-aware VM; the execution of the application
 * is not interrupted
 *
 * NOTE: it also performs the appropriate cleanup
 */
void libdft_die(void) {
  /*
   * deallocate the resources needed for the tagmap
   * and threads context
   */
  //	delete[] threads_ctx;
  free(threads_ctx);
  tagmap_free();
  /*
   * detach PIN from the application;
   * the application will continue to execute natively
   */
  PIN_Detach();
}

/*
 * add a new pre-ins callback into an instruction descriptor
 *
 * @desc:       the ins descriptor
 * @pre:        function pointer to the pre-ins handler
 *
 * returns:     0 on success, 1 on error
 */
int ins_set_pre(ins_desc_t *desc, void (*pre)(INS)) {
  /* sanity checks */
  if (unlikely((desc == NULL) | (pre == NULL)))
    /* return with failure */
    return 1;

  /* update the pre-ins callback */
  desc->pre = pre;

  /* success */
  return 0;
}

/*
 * add a new post-ins callback into an instruction descriptor
 *
 * @desc:       the ins descriptor
 * @pre:        function pointer to the post-ins handler
 *
 * returns:     0 on success, 1 on error
 */
int ins_set_post(ins_desc_t *desc, void (*post)(INS)) {
  /* sanity checks */
  if (unlikely((desc == NULL) | (post == NULL)))
    /* return with failure */
    return 1;

  /* update the post-ins callback */
  desc->post = post;

  /* success */
  return 0;
}

/*
 * remove the pre-ins callback from an instruction descriptor
 *
 * @desc:       the ins descriptor
 *
 * returns:     0 on success, 1 on error
 */
int ins_clr_pre(ins_desc_t *desc) {
  /* sanity check */
  if (unlikely(desc == NULL))
    /* return with failure */
    return 1;

  /* clear the pre-ins callback */
  desc->pre = NULL;

  /* return with success */
  return 0;
}

/*
 * remove the post-ins callback from an instruction descriptor
 *
 * @desc:       the ins descriptor
 *
 * returns:     0 on success, 1 on error
 */
int ins_clr_post(syscall_desc_t *desc) {
  /* sanity check */
  if (unlikely(desc == NULL))
    /* return with failure */
    return 1;

  /* clear the post-ins callback */
  desc->post = NULL;

  /* return with success */
  return 0;
}
