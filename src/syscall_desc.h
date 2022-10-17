#ifndef __SYSCALL_DESC_H__
#define __SYSCALL_DESC_H__

#include "libdft_api.h"

////////////////////////////////////////////////////////////////////////////////
/* Defining these here because they're undefined in Pin 3.24's crt. See defs in:
 * PIN_ROOT/extras/crt/include/kernel/uapi/asm-x86/asm/unistd_64.h
 */
#define __NR_renameat2 316
#define __NR_seccomp 317
#define __NR_getrandom 318
#define __NR_memfd_create 319
#define __NR_kexec_file_load 320
#define __NR_bpf 321
#define __NR_execveat 322
#define __NR_userfaultfd 323
#define __NR_membarrier 324
#define __NR_mlock2 325
#define __NR_copy_file_range 326
#define __NR_preadv2 327
#define __NR_pwritev2 328
#define __NR_pkey_mprotect 329
#define __NR_pkey_alloc 330
#define __NR_pkey_free 331
#define __NR_statx 332
#define __NR_io_pgetevents 333
#define __NR_rseq 334
#define __NR_pidfd_send_signal 424
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426
#define __NR_io_uring_register 427
#define __NR_open_tree 428
#define __NR_move_mount 429
#define __NR_fsopen 430
#define __NR_fsconfig 431
#define __NR_fsmount 432
#define __NR_fspick 433
#define __NR_pidfd_open 434
#define __NR_clone3 435
#define __NR_close_range 436
#define __NR_openat2 437
#define __NR_pidfd_getfd 438
#define __NR_faccessat2 439
#define __NR_process_madvise 440
#define __NR_epoll_pwait2 441
#define __NR_mount_setattr 442
#define __NR_quotactl_fd 443
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#define __NR_memfd_secret 447
#define __NR_process_mrelease 448
////////////////////////////////////////////////////////////////////////////////

#define SYSCALL_MAX __NR_process_mrelease + 1 /* max syscall number */

/* system call descriptor */
typedef struct {
  size_t nargs;                           /* number of arguments */
  size_t save_args;                       /* flag; save arguments */
  size_t retval_args;                     /* flag; returns value in arguments */
  size_t map_args[SYSCALL_ARG_NUM];       /* arguments map */
  void (*pre)(THREADID, syscall_ctx_t *); /* pre-syscall callback */
  void (*post)(THREADID, syscall_ctx_t *); /* post-syscall callback */
} syscall_desc_t;

extern syscall_desc_t syscall_desc[SYSCALL_MAX];
void syscall_desc_init(void);
bool is_valid_syscall_nr(size_t nr);

/* syscall API */
int syscall_set_pre(syscall_desc_t *, void (*)(THREADID, syscall_ctx_t *));
int syscall_clr_pre(syscall_desc_t *);
int syscall_set_post(syscall_desc_t *, void (*)(THREADID, syscall_ctx_t *));
int syscall_clr_post(syscall_desc_t *);

#endif /* __SYSCALL_DESC_H__ */
