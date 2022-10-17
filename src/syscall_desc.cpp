#include "syscall_desc.h"
#include "branch_pred.h"
#include "syscall_struct.h"
#include "tagmap.h"

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timex.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>

//#include <asm/fcntl.h>
//#include <asm/stat.h>
#include <linux/kexec.h>
#include <linux/mempolicy.h>
#include <linux/sysctl.h>

#include <err.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

// Linux:  /usr/include/x86_64-linux-gnu/asm/unistd_64.h

/* callbacks declaration */
static void post_read_hook(THREADID tid, syscall_ctx_t *);
static void post_fcntl_hook(THREADID tid, syscall_ctx_t *);
static void post_mmap_hook(THREADID tid, syscall_ctx_t *);
static void post_syslog_hook(THREADID tid, syscall_ctx_t *);
static void post_modify_ldt_hook(THREADID tid, syscall_ctx_t *);
static void post_quotactl_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_readv_hook(THREADID tid, syscall_ctx_t *);
static void post__sysctl_hook(THREADID tid, syscall_ctx_t *);
static void post_poll_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_rt_sigpending_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_getcwd_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_getgroups_hook(THREADID tid, syscall_ctx_t *);
static void post_mincore_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_getdents_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_getxattr_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_listxattr_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_io_getevents_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_get_mempolicy_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_lookup_dcookie_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_mq_timedreceive_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_readlinkat_hook(THREADID tid, syscall_ctx_t *);
static void post_epoll_wait_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_recvmmsg_hook(THREADID tid, syscall_ctx_t *ctx);

static void post_shmctl_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_accept_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_recvfrom_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_recvmsg_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_getsockopt_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_semctl_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_msgrcv_hook(THREADID tid, syscall_ctx_t *ctx);
static void post_msgctl_hook(THREADID tid, syscall_ctx_t *ctx);

/* syscall descriptors */
syscall_desc_t syscall_desc[SYSCALL_MAX] = {{0}};

void syscall_desc_init(void) {
  memset(syscall_desc, 0, sizeof(syscall_desc)); // Just to be certain
  syscall_desc[__NR_read] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_read_hook}; // 0
  syscall_desc[__NR_write] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 1
  syscall_desc[__NR_open] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 2
  syscall_desc[__NR_close] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 3
  syscall_desc[__NR_stat] = {2, 0, 1, {0, sizeof(struct stat), 0, 0, 0, 0}, NULL, NULL}; // 4
  syscall_desc[__NR_fstat] = {2, 0, 1, {0, sizeof(struct stat), 0, 0, 0, 0}, NULL, NULL}; // 5
  syscall_desc[__NR_lstat] = {2, 0, 1, {0, sizeof(struct stat), 0, 0, 0, 0}, NULL, NULL}; // 6
  syscall_desc[__NR_poll] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_poll_hook}; // 7
  syscall_desc[__NR_lseek] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 8
  syscall_desc[__NR_mmap] = {6, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_mmap_hook}; // 9
  syscall_desc[__NR_mprotect] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 10
  syscall_desc[__NR_munmap] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 11
  syscall_desc[__NR_brk] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 12
  syscall_desc[__NR_rt_sigaction] = {3, 0, 1, {0, 0, sizeof(struct sigaction), 0, 0, 0}, NULL, NULL}; // 13
  syscall_desc[__NR_rt_sigprocmask] = {4, 0, 1, {0, sizeof(sigset_t), sizeof(sigset_t), 0, 0, 0}, NULL, NULL}; // 14
  syscall_desc[__NR_rt_sigreturn] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 15
  syscall_desc[__NR_ioctl] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 16
  syscall_desc[__NR_pread64] = {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_read_hook}; // 17
  syscall_desc[__NR_pwrite64] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 18
  syscall_desc[__NR_readv] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_readv_hook}; // 19
  syscall_desc[__NR_writev] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 20
  syscall_desc[__NR_access] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 21
  syscall_desc[__NR_pipe] = {1, 0, 1, {sizeof(int) * 2, 0, 0, 0, 0, 0}, NULL, NULL}; // 22
  syscall_desc[__NR_select] = {5, 0, 1, {0, sizeof(fd_set), sizeof(fd_set), sizeof(fd_set), sizeof(struct timeval), 0}, NULL, NULL}; // 23
  syscall_desc[__NR_sched_yield] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 24
  syscall_desc[__NR_mremap] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 25
  syscall_desc[__NR_msync] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 26
  syscall_desc[__NR_mincore] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_mincore_hook}; // 27
  syscall_desc[__NR_madvise] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 28
  syscall_desc[__NR_shmget] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 29
  syscall_desc[__NR_shmat] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 30
  syscall_desc[__NR_shmctl] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_shmctl_hook}; // 31
  syscall_desc[__NR_dup] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 32
  syscall_desc[__NR_dup2] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 33
  syscall_desc[__NR_pause] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 34
  syscall_desc[__NR_nanosleep] = {2, 0, 1, {sizeof(struct timespec), sizeof(struct timespec), 0, 0, 0, 0}, NULL, NULL}; // 35
  syscall_desc[__NR_getitimer] = {2, 0, 1, {0, sizeof(struct itimerval), 0, 0, 0, 0}, NULL, NULL}; // 36
  syscall_desc[__NR_alarm] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 37
  syscall_desc[__NR_setitimer] = {3, 0, 1, {0, 0, sizeof(struct itimerval), 0, 0, 0}, NULL, NULL}; // 38
  syscall_desc[__NR_getpid] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 39
  syscall_desc[__NR_sendfile] = {4, 0, 1, {0, 0, sizeof(off_t), 0, 0, 0}, NULL, NULL}; // 40
  syscall_desc[__NR_socket] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 41
  syscall_desc[__NR_connect] = {3, 0, 1, {0, sizeof(struct sockaddr), 0, 0, 0, 0}, NULL, NULL}; // 42
  syscall_desc[__NR_accept] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_accept_hook}; // 43
  syscall_desc[__NR_sendto] = {6, 0, 1, {0, 0, 0, 0, sizeof(struct sockaddr), 0}, NULL, NULL}; // 44
  syscall_desc[__NR_recvfrom] = {6, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_recvfrom_hook}; // 45
  syscall_desc[__NR_sendmsg] = {3, 0, 1, {0, sizeof(struct msghdr), 0, 0, 0, 0}, NULL, NULL}; // 46
  syscall_desc[__NR_recvmsg] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_recvmsg_hook}; // 47
  syscall_desc[__NR_shutdown] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 48
  syscall_desc[__NR_bind] = {3, 0, 1, {0, sizeof(struct sockaddr), 0, 0, 0, 0}, NULL, NULL}; // 49
  syscall_desc[__NR_listen] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 50
  syscall_desc[__NR_getsockname] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_accept_hook}; // 51
  syscall_desc[__NR_getpeername] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_accept_hook}; // 52
  syscall_desc[__NR_socketpair] = {4, 0, 1, {0, 0, 0, sizeof(int) * 2, 0, 0}, NULL, NULL}; // 53
  syscall_desc[__NR_setsockopt] = {5, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 54
  syscall_desc[__NR_getsockopt] = {5, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getsockopt_hook}; // 55
  syscall_desc[__NR_clone] = {4, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 56
  syscall_desc[__NR_fork] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 57
  syscall_desc[__NR_vfork] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 58
  syscall_desc[__NR_execve] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 59
  syscall_desc[__NR_exit] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 60
  syscall_desc[__NR_wait4] = {4, 0, 1, {0, sizeof(int), 0, sizeof(struct rusage), 0, 0}, NULL, NULL}; // 61
  syscall_desc[__NR_kill] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 62
  syscall_desc[__NR_uname] = {1, 0, 1, {sizeof(struct utsname), 0, 0, 0, 0, 0}, NULL, NULL}; // 63
  syscall_desc[__NR_semget] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 64
  syscall_desc[__NR_semop] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 65
  syscall_desc[__NR_semctl] = {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_semctl_hook}; // 66
  syscall_desc[__NR_shmdt] = {1, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 67
  syscall_desc[__NR_msgget] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 68
  syscall_desc[__NR_msgsnd] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 69
  syscall_desc[__NR_msgrcv] = {5, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_msgrcv_hook}; // 70
  syscall_desc[__NR_msgctl] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_msgctl_hook}; // 71
  syscall_desc[__NR_fcntl] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_fcntl_hook}; // 72
  syscall_desc[__NR_flock] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 73
  syscall_desc[__NR_fsync] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 74
  syscall_desc[__NR_fdatasync] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 75
  syscall_desc[__NR_truncate] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 76
  syscall_desc[__NR_ftruncate] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 77
  syscall_desc[__NR_getdents] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getdents_hook}; // 78
  syscall_desc[__NR_getcwd] = {2, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getcwd_hook}; // 79
  syscall_desc[__NR_chdir] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 80
  syscall_desc[__NR_fchdir] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 81
  syscall_desc[__NR_rename] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 82
  syscall_desc[__NR_mkdir] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 83
  syscall_desc[__NR_rmdir] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 84
  syscall_desc[__NR_creat] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 85
  syscall_desc[__NR_link] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 86
  syscall_desc[__NR_unlink] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 87
  syscall_desc[__NR_symlink] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 88
  syscall_desc[__NR_readlink] = {3, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 89
  syscall_desc[__NR_chmod] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 90
  syscall_desc[__NR_fchmod] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 91
  syscall_desc[__NR_chown] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 92
  syscall_desc[__NR_fchown] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 93
  syscall_desc[__NR_lchown] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 94
  syscall_desc[__NR_umask] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 95
  syscall_desc[__NR_gettimeofday] = {2, 0, 1, {sizeof(struct timeval), sizeof(struct timezone), 0, 0, 0, 0}, NULL, NULL}; // 96
  syscall_desc[__NR_getrlimit] = {2, 0, 1, {0, sizeof(struct rlimit), 0, 0, 0, 0}, NULL, NULL}; // 97
  syscall_desc[__NR_getrusage] = {2, 0, 1, {0, sizeof(struct rusage), 0, 0, 0, 0}, NULL, NULL}; // 98
  syscall_desc[__NR_sysinfo] = {1, 0, 1, {sizeof(struct sysinfo), 0, 0, 0, 0, 0}, NULL, NULL}; // 99
  syscall_desc[__NR_times] = {1, 0, 1, {sizeof(struct sysinfo), 0, 0, 0, 0, 0}, NULL, NULL}; // 100
  syscall_desc[__NR_ptrace] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 101
  syscall_desc[__NR_getuid] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 102
  syscall_desc[__NR_syslog] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_syslog_hook}; // 103
  syscall_desc[__NR_getgid] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 104
  syscall_desc[__NR_setuid] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 105
  syscall_desc[__NR_setgid] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 106
  syscall_desc[__NR_geteuid] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 107
  syscall_desc[__NR_getegid] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 108
  syscall_desc[__NR_setpgid] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 109
  syscall_desc[__NR_getppid] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 110
  syscall_desc[__NR_getpgrp] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 111
  syscall_desc[__NR_setsid] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 112
  syscall_desc[__NR_setreuid] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 113
  syscall_desc[__NR_setregid] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 114
  syscall_desc[__NR_getgroups] = {2, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getgroups_hook}; // 115
  syscall_desc[__NR_setgroups] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 116
  syscall_desc[__NR_setresuid] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 117
  syscall_desc[__NR_getresuid] = {3, 0, 1, {sizeof(uid_t), sizeof(uid_t), sizeof(uid_t), 0, 0, 0}, NULL, NULL}; // 118
  syscall_desc[__NR_setresgid] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 119
  syscall_desc[__NR_getresgid] = {3, 0, 1, {sizeof(git_t), sizeof(git_t), sizeof(git_t), 0, 0, 0}, NULL, NULL}; // 120
  syscall_desc[__NR_getpgid] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 121
  syscall_desc[__NR_setfsuid] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 122
  syscall_desc[__NR_setfsgid] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 123
  syscall_desc[__NR_getsid] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 124
  syscall_desc[__NR_capget] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 125
  syscall_desc[__NR_capset] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 126
  syscall_desc[__NR_rt_sigpending] = {2, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_rt_sigpending_hook}; // 127
  syscall_desc[__NR_rt_sigtimedwait] = {4, 0, 1, {0, sizeof(siginfo_t), 0, 0, 0, 0}, NULL, NULL}; // 128
  syscall_desc[__NR_rt_sigqueueinfo] = {3, 0, 1, {0, 0, sizeof(siginfo_t), 0, 0, 0}, NULL, NULL}; // 129
  syscall_desc[__NR_rt_sigsuspend] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 130
  syscall_desc[__NR_sigaltstack] = {2, 0, 1, {0, sizeof(stack_t), 0, 0, 0, 0}, NULL, NULL}; // 131
  syscall_desc[__NR_utime] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 132
  syscall_desc[__NR_mknod] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 133
  syscall_desc[__NR_uselib] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 134
  syscall_desc[__NR_personality] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 135
  syscall_desc[__NR_ustat] = {2, 0, 1, {0, sizeof(struct ustat), 0, 0, 0, 0}, NULL, NULL}; // 136
  syscall_desc[__NR_statfs] = {2, 0, 1, {0, sizeof(struct statfs), 0, 0, 0, 0}, NULL, NULL}; // 137
  syscall_desc[__NR_fstatfs] = {2, 0, 1, {0, sizeof(struct statfs), 0, 0, 0, 0}, NULL, NULL}; // 138
  syscall_desc[__NR_sysfs] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 139
  syscall_desc[__NR_getpriority] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 140
  syscall_desc[__NR_setpriority] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 141
  syscall_desc[__NR_sched_setparam] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 142
  syscall_desc[__NR_sched_getparam] = {2, 0, 1, {0, sizeof(struct sched_param), 0, 0, 0, 0}, NULL, NULL}; // 143
  syscall_desc[__NR_sched_setscheduler] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 144
  syscall_desc[__NR_sched_getscheduler] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 145
  syscall_desc[__NR_sched_get_priority_max] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 146
  syscall_desc[__NR_sched_get_priority_min] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 147
  syscall_desc[__NR_sched_rr_get_interval] = {2, 0, 1, {0, sizeof(struct timespec), 0, 0, 0, 0}, NULL, NULL}; // 148
  syscall_desc[__NR_mlock] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 149
  syscall_desc[__NR_munlock] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 150
  syscall_desc[__NR_mlockall] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 151
  syscall_desc[__NR_munlockall] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 152
  syscall_desc[__NR_vhangup] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 153
  syscall_desc[__NR_modify_ldt] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_modify_ldt_hook}; // 154
  syscall_desc[__NR_pivot_root] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 155
  syscall_desc[__NR__sysctl] = {1, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post__sysctl_hook}; // 156
  syscall_desc[__NR_prctl] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 157
  syscall_desc[__NR_arch_prctl] = {2, 0, 1, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 158
  syscall_desc[__NR_adjtimex] = {1, 0, 1, {sizeof(struct timex), 0, 0, 0, 0, 0}, NULL, NULL}; // 159
  syscall_desc[__NR_setrlimit] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 160
  syscall_desc[__NR_chroot] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 161
  syscall_desc[__NR_sync] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 162
  syscall_desc[__NR_acct] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 163
  syscall_desc[__NR_settimeofday] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 164
  syscall_desc[__NR_mount] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 165
  syscall_desc[__NR_umount2] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 166
  syscall_desc[__NR_swapon] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 167
  syscall_desc[__NR_swapoff] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 168
  syscall_desc[__NR_reboot] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 169
  syscall_desc[__NR_sethostname] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 170
  syscall_desc[__NR_setdomainname] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 171
  syscall_desc[__NR_iopl] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 172
  syscall_desc[__NR_ioperm] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 173
  syscall_desc[__NR_create_module] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 174
  syscall_desc[__NR_init_module] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 175
  syscall_desc[__NR_delete_module] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 176
  syscall_desc[__NR_get_kernel_syms] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 177
  syscall_desc[__NR_query_module] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 178
  syscall_desc[__NR_quotactl] = {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_quotactl_hook}; // 179
  syscall_desc[__NR_nfsservctl] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 180
  syscall_desc[__NR_getpmsg] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 181
  syscall_desc[__NR_putpmsg] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 182
  syscall_desc[__NR_afs_syscall] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 183
  syscall_desc[__NR_tuxcall] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 184
  syscall_desc[__NR_security] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 185
  syscall_desc[__NR_gettid] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 186
  syscall_desc[__NR_readahead] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 187
  syscall_desc[__NR_setxattr] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 188
  syscall_desc[__NR_lsetxattr] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 189
  syscall_desc[__NR_fsetxattr] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 190
  syscall_desc[__NR_getxattr] = {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getxattr_hook}; // 191
  syscall_desc[__NR_lgetxattr] = {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getxattr_hook}; // 192
  syscall_desc[__NR_fgetxattr] = {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getxattr_hook}; // 193
  syscall_desc[__NR_listxattr] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_listxattr_hook}; // 194
  syscall_desc[__NR_llistxattr] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_listxattr_hook}; // 195
  syscall_desc[__NR_flistxattr] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_listxattr_hook}; // 196
  syscall_desc[__NR_removexattr] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 197
  syscall_desc[__NR_lremovexattr] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 198
  syscall_desc[__NR_fremovexattr] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 199
  syscall_desc[__NR_tkill] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 200
  syscall_desc[__NR_time] = {1, 0, 1, {sizeof(time_t), 0, 0, 0, 0, 0}, NULL, NULL}; // 201
  syscall_desc[__NR_futex] = {6, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 202
  syscall_desc[__NR_sched_setaffinity] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 203
  syscall_desc[__NR_sched_getaffinity] = {3, 0, 1, {0, 0, sizeof(cpu_set_t), 0, 0, 0}, NULL, NULL}; // 204
  syscall_desc[__NR_set_thread_area] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 205
  syscall_desc[__NR_io_setup] = {2, 0, 1, {0, sizeof(aio_context_t), 0, 0, 0, 0}, NULL, NULL}; // 206
  syscall_desc[__NR_io_destroy] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 207
  syscall_desc[__NR_io_getevents] = {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_io_getevents_hook}; // 208
  syscall_desc[__NR_io_submit] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 209
  syscall_desc[__NR_io_cancel] = {3, 0, 1, {0, 0, sizeof(struct io_event), 0, 0, 0}, NULL, NULL}; // 210
  syscall_desc[__NR_get_thread_area] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 211
  syscall_desc[__NR_lookup_dcookie] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_lookup_dcookie_hook}; // 212
  syscall_desc[__NR_epoll_create] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 213
  syscall_desc[__NR_epoll_ctl_old] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 214
  syscall_desc[__NR_epoll_wait_old] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 215
  syscall_desc[__NR_remap_file_pages] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 216
  syscall_desc[__NR_getdents64] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_getdents_hook}; // 217
  syscall_desc[__NR_set_tid_address] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 218
  syscall_desc[__NR_restart_syscall] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 219
  syscall_desc[__NR_semtimedop] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 220
  syscall_desc[__NR_fadvise64] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 221
  syscall_desc[__NR_timer_create] = {3, 0, 1, {0, 0, sizeof(timer_t), 0, 0, 0}, NULL, NULL}; // 222
  syscall_desc[__NR_timer_settime] = {4, 0, 1, {0, 0, 0, sizeof(struct itimerspec), 0, 0}, NULL, NULL}; // 223
  syscall_desc[__NR_timer_gettime] = {2, 0, 1, {0, sizeof(struct itimerspec), 0, 0, 0, 0}, NULL, NULL}; // 224
  syscall_desc[__NR_timer_getoverrun] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 225
  syscall_desc[__NR_timer_delete] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 226
  syscall_desc[__NR_clock_settime] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 227
  syscall_desc[__NR_clock_gettime] = {2, 0, 1, {0, sizeof(struct timespec), 0, 0, 0, 0}, NULL, NULL}; // 228
  syscall_desc[__NR_clock_getres] = {2, 0, 1, {0, sizeof(struct timespec), 0, 0, 0, 0}, NULL, NULL}; // 229
  syscall_desc[__NR_clock_nanosleep] = {4, 0, 1, {0, 0, 0, sizeof(struct timespec), 0, 0}, NULL, NULL}; // 230
  syscall_desc[__NR_exit_group] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 231
  syscall_desc[__NR_epoll_wait] = {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_epoll_wait_hook}; // 232
  syscall_desc[__NR_epoll_ctl] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 233
  syscall_desc[__NR_tgkill] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 234
  syscall_desc[__NR_utimes] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 235
  syscall_desc[__NR_vserver] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 236
  syscall_desc[__NR_mbind] = {6, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 237
  syscall_desc[__NR_set_mempolicy] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 238
  syscall_desc[__NR_get_mempolicy] = {5, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_get_mempolicy_hook}; // 239
  syscall_desc[__NR_mq_open] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 240
  syscall_desc[__NR_mq_unlink] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 241
  syscall_desc[__NR_mq_timedsend] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 242
  syscall_desc[__NR_mq_timedreceive] = {5, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_mq_timedreceive_hook}; // 243
  syscall_desc[__NR_mq_notify] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 244
  syscall_desc[__NR_mq_getsetattr] = {3, 0, 1, {0, 0, sizeof(struct mq_attr), 0, 0, 0}, NULL, NULL}; // 245
  syscall_desc[__NR_kexec_load] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 246
  syscall_desc[__NR_waitid] = {5, 0, 1, {0, 0, sizeof(siginfo_t), 0, sizeof(struct rusage), 0}, NULL, NULL}; // 247
  syscall_desc[__NR_add_key] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 248
  syscall_desc[__NR_request_key] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 249
  syscall_desc[__NR_keyctl] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 250
  syscall_desc[__NR_ioprio_set] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 251
  syscall_desc[__NR_ioprio_get] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 252
  syscall_desc[__NR_inotify_init] = {0, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 253
  syscall_desc[__NR_inotify_add_watch] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 254
  syscall_desc[__NR_inotify_rm_watch] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 255
  syscall_desc[__NR_migrate_pages] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 256
  syscall_desc[__NR_openat] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 257
  syscall_desc[__NR_mkdirat] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 258
  syscall_desc[__NR_mknodat] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 259
  syscall_desc[__NR_fchownat] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 260
  syscall_desc[__NR_futimesat] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 261
  syscall_desc[__NR_newfstatat] = {4, 0, 1, {0, 0, sizeof(struct stat), 0, 0, 0}, NULL, NULL}; // 262
  syscall_desc[__NR_unlinkat] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 263
  syscall_desc[__NR_renameat] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 264
  syscall_desc[__NR_linkat] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 265
  syscall_desc[__NR_symlinkat] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 266
  syscall_desc[__NR_readlinkat] = {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_readlinkat_hook}; // 267
  syscall_desc[__NR_fchmodat] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 268
  syscall_desc[__NR_faccessat] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 269
  syscall_desc[__NR_pselect6] = {6, 0, 1, {0, sizeof(fd_set), sizeof(fd_set), sizeof(fd_set), 0, 0}, NULL, NULL}; // 270
  syscall_desc[__NR_ppoll] = {5, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_poll_hook}; // 271
  syscall_desc[__NR_unshare] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 272
  syscall_desc[__NR_set_robust_list] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 273
  syscall_desc[__NR_get_robust_list] = {3, 0, 1, {0, sizeof(struct robust_list_head *), sizeof(size_t), 0, 0, 0}, NULL, NULL}; // 274
  syscall_desc[__NR_splice] = {6, 0, 1, {0, sizeof(loff_t), 0, sizeof(loff_t), 0, 0}, NULL, NULL}; // 275
  syscall_desc[__NR_tee] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 276
  syscall_desc[__NR_sync_file_range] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 277
  syscall_desc[__NR_vmsplice] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 278
  syscall_desc[__NR_move_pages] = {6, 0, 1, {0, 0, 0, 0, sizeof(int), 0}, NULL, NULL}; // 279
  syscall_desc[__NR_utimensat] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 280
  syscall_desc[__NR_epoll_pwait] = {6, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 281
  syscall_desc[__NR_signalfd] = {3, 0, 1, {0, sizeof(sigset_t), 0, 0, 0, 0}, NULL, post_epoll_wait_hook}; // 282
  syscall_desc[__NR_timerfd_create] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 283
  syscall_desc[__NR_eventfd] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 284
  syscall_desc[__NR_fallocate] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 285
  syscall_desc[__NR_timerfd_settime] = {4, 0, 1, {0, 0, 0, sizeof(struct itimerspec), 0, 0}, NULL, NULL}; // 286
  syscall_desc[__NR_timerfd_gettime] = {2, 0, 1, {0, sizeof(struct itimerspec), 0, 0, 0, 0}, NULL, NULL}; // 287
  syscall_desc[__NR_accept4] = {4, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_accept_hook}; // 288
  syscall_desc[__NR_signalfd4] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 289
  syscall_desc[__NR_eventfd2] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 290
  syscall_desc[__NR_epoll_create1] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 291
  syscall_desc[__NR_dup3] = {3, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 292
  syscall_desc[__NR_pipe2] = {2, 0, 1, {sizeof(int) * 2, 0, 0, 0, 0, 0}, NULL, NULL}; // 293
  syscall_desc[__NR_inotify_init1] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 294
  syscall_desc[__NR_preadv] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 295
  syscall_desc[__NR_pwritev] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 296
  syscall_desc[__NR_rt_tgsigqueueinfo] = {4, 0, 1, {0, 0, 0, sizeof(siginfo_t), 0, 0}, NULL, NULL}; // 297
  syscall_desc[__NR_perf_event_open] = {5, 0, 1, {sizeof(struct perf_event_attr), 0, 0, 0, 0, 0}, NULL, NULL}; // 298
  syscall_desc[__NR_recvmmsg] = {5, 1, 0, {0, 0, 0, 0, 0, 0}, NULL, post_recvmmsg_hook}; // 299
  syscall_desc[__NR_fanotify_init] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 300
  syscall_desc[__NR_fanotify_mark] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 301
  syscall_desc[__NR_prlimit64] = {4, 0, 1, {0, 0, 0, sizeof(struct rlimit), 0, 0}, NULL, NULL}; // 302
  syscall_desc[__NR_name_to_handle_at] = {5, 0, 1, {0, 0, sizeof(struct file_handle), sizeof(int), 0, 0}, NULL, NULL}; // 303
  syscall_desc[__NR_open_by_handle_at] = {3, 0, 1, {0, 0, sizeof(struct file_handle), 0, 0, 0}, NULL, NULL}; // 304
  syscall_desc[__NR_clock_adjtime] = {2, 0, 1, {0, sizeof(struct timex), 0, 0, 0, 0}, NULL, NULL}; // 305
  syscall_desc[__NR_syncfs] = {1, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 306
  syscall_desc[__NR_sendmmsg] = {4, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 307
  syscall_desc[__NR_setns] = {2, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 308
  syscall_desc[__NR_getcpu] = {3, 0, 1, {sizeof(unsigned), sizeof(unsigned), sizeof(struct getcpu_cache), 0, 0, 0}, NULL, NULL}; // 309
  syscall_desc[__NR_process_vm_readv] = {6, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 310
  syscall_desc[__NR_process_vm_writev] = {6, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 311
  syscall_desc[__NR_kcmp] = {5, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 312
  syscall_desc[__NR_finit_module] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 313
  syscall_desc[__NR_sched_setattr] = {3, 0, 0, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 314
  syscall_desc[__NR_sched_getattr] = {4, 0, 1, {0, sizeof(struct sched_attr), 0, 0, 0, 0}, NULL, NULL}; // 315
#define SYSCALL_DESC_TODO 0
  syscall_desc[__NR_renameat2] = {5, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 316
  syscall_desc[__NR_seccomp] = {3, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 317
  syscall_desc[__NR_getrandom] = {3, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 318
  syscall_desc[__NR_memfd_create] = {2, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 319
  syscall_desc[__NR_kexec_file_load] = {5, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 320
  syscall_desc[__NR_bpf] = {3, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 321
  syscall_desc[__NR_execveat] = {5, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 322
  syscall_desc[__NR_userfaultfd] = {1, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 323
  syscall_desc[__NR_membarrier] = {2, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 324
  syscall_desc[__NR_mlock2] = {3, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 325
  syscall_desc[__NR_copy_file_range] = {6, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 326
  syscall_desc[__NR_preadv2] = {6, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 327
  syscall_desc[__NR_pwritev2] = {6, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 328
  syscall_desc[__NR_pkey_mprotect] = {4, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 329
  syscall_desc[__NR_pkey_alloc] = {2, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 330
  syscall_desc[__NR_pkey_free] = {1, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 331
  syscall_desc[__NR_statx] = {5, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 332
  syscall_desc[__NR_io_pgetevents] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 333
  syscall_desc[__NR_rseq] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 334
  // Gap from 334 to 424
  syscall_desc[__NR_pidfd_send_signal] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 424
  syscall_desc[__NR_io_uring_setup] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 425
  syscall_desc[__NR_io_uring_enter] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 426
  syscall_desc[__NR_io_uring_register] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 427
  syscall_desc[__NR_open_tree] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 428
  syscall_desc[__NR_move_mount] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 429
  syscall_desc[__NR_fsopen] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 430
  syscall_desc[__NR_fsconfig] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 431
  syscall_desc[__NR_fsmount] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 432
  syscall_desc[__NR_fspick] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 433
  syscall_desc[__NR_pidfd_open] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 434
  syscall_desc[__NR_clone3] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 435
  syscall_desc[__NR_close_range] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 436
  syscall_desc[__NR_openat2] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 437
  syscall_desc[__NR_pidfd_getfd] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 438
  syscall_desc[__NR_faccessat2] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 439
  syscall_desc[__NR_process_madvise] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 440
  syscall_desc[__NR_epoll_pwait2] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 441
  syscall_desc[__NR_mount_setattr] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 442
  syscall_desc[__NR_quotactl_fd] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 443
  syscall_desc[__NR_landlock_create_ruleset] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 444
  syscall_desc[__NR_landlock_add_rule] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 445
  syscall_desc[__NR_landlock_restrict_self] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 446
  syscall_desc[__NR_memfd_secret] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 447
  syscall_desc[__NR_process_mrelease] = {SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, SYSCALL_DESC_TODO, {0, 0, 0, 0, 0, 0}, NULL, NULL}; // 448
};

bool is_valid_syscall_nr(size_t nr) {
  // Valid if between [0, __NR_rseq] or [__NR_pidfd_send_signal, __NR_process_mrelease]
  return (nr >= 0 && nr <= __NR_rseq) || (nr >= __NR_pidfd_send_signal && nr <= __NR_process_mrelease);
}
/*
 * add a new pre-syscall callback into a syscall descriptor
 *
 * @desc:	the syscall descriptor
 * @pre:	function pointer to the pre-syscall handler
 *
 * returns:	0 on success, 1 on error
 */
int syscall_set_pre(syscall_desc_t *desc,
                    void (*pre)(THREADID, syscall_ctx_t *)) {
  /* sanity checks */
  if (unlikely((desc == NULL) | (pre == NULL)))
    /* return with failure */
    return 1;

  /* update the pre-syscall callback */
  desc->pre = pre;

  /* set the save arguments flag */
  desc->save_args = 1;

  /* success */
  return 0;
}

/*
 * add a new post-syscall callback into a syscall descriptor
 *
 * @desc:	the syscall descriptor
 * @pre:	function pointer to the post-syscall handler
 *
 * returns:	0 on success, 1 on error
 */
int syscall_set_post(syscall_desc_t *desc,
                     void (*post)(THREADID, syscall_ctx_t *)) {
  /* sanity checks */
  if (unlikely((desc == NULL) | (post == NULL)))
    /* return with failure */
    return 1;

  /* update the post-syscall callback */
  desc->post = post;

  /* set the save arguments flag */
  desc->save_args = 1;

  /* success */
  return 0;
}

/*
 * remove the pre-syscall callback from a syscall descriptor
 *
 * @desc:       the syscall descriptor
 *
 * returns:     0 on success, 1 on error
 */
int syscall_clr_pre(syscall_desc_t *desc) {
  /* sanity check */
  if (unlikely(desc == NULL))
    /* return with failure */
    return 1;

  /* clear the pre-syscall callback */
  desc->pre = NULL;

  /* check if we need to clear the save arguments flag */
  if (desc->post == NULL)
    /* clear */
    desc->save_args = 0;

  /* return with success */
  return 0;
}

/*
 * remove the post-syscall callback from a syscall descriptor
 *
 * @desc:       the syscall descriptor
 *
 * returns:     0 on success, 1 on error
 */
int syscall_clr_post(syscall_desc_t *desc) {
  /* sanity check */
  if (unlikely(desc == NULL))
    /* return with failure */
    return 1;

  /* clear the post-syscall callback */
  desc->post = NULL;

  /* check if we need to clear the save arguments flag */
  if (desc->pre == NULL)
    /* clear */
    desc->save_args = 0;

  /* return with success */
  return 0;
}

/* __NR_(p)read(64) and __NR_readlink post syscall hook */
static void post_read_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* read()/readlink() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_getgroups post syscall_hook */
static void post_getgroups_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* getgroups() was not successful */
  if ((long)ctx->ret <= 0 || (gid_t *)ctx->arg[SYSCALL_ARG1] == NULL)
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (sizeof(gid_t) * (size_t)ctx->ret));
}

/* __NR_readlinkat post syscall hook */
static void post_readlinkat_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* readlinkat() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG2], (size_t)ctx->ret);
}

/* __NR_mmap post syscall hook */
static void post_mmap_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* the map offset */
  size_t offset = (size_t)ctx->arg[SYSCALL_ARG1];

  /* mmap() was not successful; optimized branch */
  if (unlikely((void *)ctx->ret == MAP_FAILED))
    return;

  /* estimate offset; optimized branch */
  if (unlikely(offset < PAGE_SZ))
    offset = PAGE_SZ;
  else
    offset = offset + PAGE_SZ - (offset % PAGE_SZ);

  /* grow downwards; optimized branch */
  if (unlikely((int)ctx->arg[SYSCALL_ARG3] & MAP_GROWSDOWN))
    /* fix starting address */
    ctx->ret = ctx->ret - offset;

  /* emulate the clear_tag() call */
  tagmap_clrn((size_t)ctx->ret, offset);
}

/* __NR_readv and __NR_preadv post syscall hook */
static void post_readv_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* iterators */
  int i;
  struct iovec *iov;

  /* bytes copied in a iovec structure */
  size_t iov_tot;

  /* total bytes copied */
  size_t tot = (size_t)ctx->ret;

  /* (p)readv() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* iterate the iovec structures */
  for (i = 0; i < (int)ctx->arg[SYSCALL_ARG2] && tot > 0; i++) {
    /* get an iovec  */
    iov = ((struct iovec *)ctx->arg[SYSCALL_ARG1]) + i;

    /* get the length of the iovec */
    iov_tot = (tot >= (size_t)iov->iov_len) ? (size_t)iov->iov_len : tot;

    /* clear the tag bits */
    tagmap_clrn((size_t)iov->iov_base, iov_tot);

    /* housekeeping */
    tot -= iov_tot;
  }
}

/* __NR_epoll_pwait post syscall hook */
static void post_epoll_wait_hook(THREADID tid, syscall_ctx_t *ctx) {

  /* epoll_pwait() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1],
              sizeof(struct epoll_event) * (size_t)ctx->ret);
}

/* __NR_poll and __NR_ppoll post syscall hook */
static void post_poll_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* iterators */
  size_t i;
  struct pollfd *pfd;

  /* (p)poll() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* iterate the pollfd structures */
  for (i = 0; i < (size_t)ctx->arg[SYSCALL_ARG1]; i++) {
    /* get pollfd */
    pfd = ((struct pollfd *)ctx->arg[SYSCALL_ARG0]) + i;

    /* clear the tag bits */
    tagmap_clrn((size_t)&pfd->revents, sizeof(short));
  }
}

/* __NR_mq_timedreceive post syscall hook */
static void post_mq_timedreceive_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* mq_timedreceive() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);

  /* priority argument is supplied */
  if ((size_t *)ctx->arg[SYSCALL_ARG3] != NULL)
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG3], sizeof(size_t));
}

/* __NR_get_mempolicy */
static void post_get_mempolicy_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* get_mempolicy() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* flags is zero */
  if ((unsigned long)ctx->arg[SYSCALL_ARG4] == 0) {
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG0], sizeof(int));
    tagmap_clrn(ctx->arg[SYSCALL_ARG1], sizeof(unsigned long));
    /* done */
    return;
  }

  /* MPOL_F_MEMS_ALLOWED is set on flags */
  if (((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_MEMS_ALLOWED) != 0) {
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG1], sizeof(unsigned long));
    /* done */
    return;
  }

  /* MPOL_F_ADDR is set on flags */
  if (((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_ADDR) != 0 &&
      ((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_NODE) == 0) {
    /* mode is provided */
    if ((int *)ctx->arg[SYSCALL_ARG0] != NULL)
      /* clear the tag bits */
      tagmap_clrn(ctx->arg[SYSCALL_ARG0], sizeof(int));

    /* nodemask is provided */
    if ((unsigned long *)ctx->arg[SYSCALL_ARG1] != NULL)
      /* clear the tag bits */
      tagmap_clrn(ctx->arg[SYSCALL_ARG1], sizeof(unsigned long));
    /* done */
    return;
  }

  /* MPOL_F_NODE & MPOL_F_ADDR is set on flags */
  if (((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_ADDR) != 0 &&
      ((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_NODE) != 0) {
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG0], sizeof(int));
    /* done */
    return;
  }

  /* MPOL_F_NODE is set on flags */
  if (((unsigned long)ctx->arg[SYSCALL_ARG4] & MPOL_F_NODE) != 0) {
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG0], sizeof(int));
    /* done */
    return;
  }
}

/* __NR_lookup_dcookie post syscall hook */
static void post_lookup_dcookie_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* lookup_dcookie() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_io_getevents post syscall hook */
static void post_io_getevents_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* io_getevents() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG3],
              sizeof(struct io_event) * (size_t)ctx->ret);

  /* timespec is specified */
  if ((struct timespec *)ctx->arg[SYSCALL_ARG4] != NULL)
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG4], sizeof(struct timespec));
}

/* __NR_(f, l)listxattr post syscall hook */
static void post_listxattr_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* *listxattr() was not successful; optimized branch */
  if ((long)ctx->ret <= 0 || (void *)ctx->arg[SYSCALL_ARG1] == NULL)
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_(f, l)getxattr post syscall hook */
static void post_getxattr_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* *getxattr() was not successful; optimized branch */
  if ((long)ctx->ret <= 0 || (void *)ctx->arg[SYSCALL_ARG2] == NULL)
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG2], (size_t)ctx->ret);
}

/* __NR_getdents post syscall hook */
static void post_getdents_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* getdents() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_mincore post syscall hook */
static void post_mincore_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* mincore() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG2],
              (((size_t)ctx->arg[SYSCALL_ARG1] + PAGE_SZ - 1) / PAGE_SZ));
}

/* __NR_getcwd post syscall hook */
static void post_getcwd_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* getcwd() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG0], (size_t)ctx->ret);
}

/* __NR_rt_sigpending post syscall hook */
static void post_rt_sigpending_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* rt_sigpending() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG0], (size_t)ctx->arg[SYSCALL_ARG1]);
}

/* __NR_quotactl post syscall hook */
static void post_quotactl_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* offset */
  size_t off;

  /* quotactl() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* different offset ranges */
  switch ((int)ctx->arg[SYSCALL_ARG0]) {
  case Q_GETFMT:
    off = sizeof(__u32);
    break;
  case Q_GETINFO:
    off = sizeof(struct if_dqinfo);
    break;
  case Q_GETQUOTA:
    off = sizeof(struct if_dqblk);
    break;
  case Q_XGETQSTAT:
    off = sizeof(struct fs_quota_stat);
    break;
  case Q_XGETQUOTA:
    off = sizeof(struct fs_disk_quota);
    break;
  default:
    /* nothing to do */
    return;
  }

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG3], off);
}

/* __NR_modify_ldt post syscall hook */
static void post_modify_ldt_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* modify_ldt() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
}

/* __NR_fcntl post syscall hook */
static void post_fcntl_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* fcntl() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* differentiate based on the cmd argument */
  switch ((int)ctx->arg[SYSCALL_ARG1]) {
  /* F_GETLK */
  case F_GETLK:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct flock));
    break;
  /* F_GETLK64 */
  /*
  case F_GETLK64:
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct flock64));
    break;
  */
  /* F_GETOWN_EX */
  case F_GETOWN_EX:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct f_owner_ex));
    break;
  default:
    /* nothing to do */
    break;
  }
}

/*
 * __NR_syslog post syscall hook
 *
 * NOTE: this is not related to syslog(3)
 * see klogctl(3)/syslog(2)
 */
static void post_syslog_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* syslog() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* differentiate based on the type */
  switch ((int)ctx->arg[SYSCALL_ARG0]) {
  case 2:
  case 3:
  case 4:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);
    break;
  default:
    /* nothing to do */
    return;
  }
}

/* __NR__sysctl post syscall hook */
static void post__sysctl_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* _sysctl arguments */
  struct __sysctl_args *sa;

  /* _sysctl() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* _sysctl arguments */
  sa = (struct __sysctl_args *)ctx->arg[SYSCALL_ARG0];

  /* clear the tag bits */
  tagmap_clrn((size_t)sa->newval, sa->newlen);

  /* save old value is specified */
  if (sa->oldval != NULL) {
    /* clear the tag bits */
    tagmap_clrn((size_t)sa->oldval, *sa->oldlenp);

    /* clear the tag bits */
    tagmap_clrn((size_t)sa->oldlenp, sizeof(size_t));
  }
}

/* __NR_recvmmsg post syscall hook */
static void post_recvmmsg_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* message headers; recvmsg(2) recvmmsg(2) */
  struct mmsghdr *msg;
  struct msghdr *m;

  /* iov bytes copied; recvmsg(2) */
  size_t iov_tot;

  /* iterators */
  size_t i, j;
  struct iovec *iov;

  /* total bytes received */
  size_t tot;

  /* recvmmsg() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* iterate the mmsghdr structures */
  for (i = 0; i < (size_t)ctx->ret; i++) {
    /* get the next mmsghdr structure */
    msg = ((struct mmsghdr *)ctx->arg[SYSCALL_ARG1]) + i;

    /* extract the message header */
    m = &msg->msg_hdr;

    /* source address specified */
    if (m->msg_name != NULL) {
      /* clear the tag bits */
      tagmap_clrn((size_t)m->msg_name, m->msg_namelen);

      /* clear the tag bits */
      tagmap_clrn((size_t)&m->msg_namelen, sizeof(int));
    }

    /* ancillary data specified */
    if (m->msg_control != NULL) {
      /* clear the tag bits */
      tagmap_clrn((size_t)m->msg_control, m->msg_controllen);

      /* clear the tag bits */
      tagmap_clrn((size_t)&m->msg_controllen, sizeof(int));
    }

    /* flags; clear the tag bits */
    tagmap_clrn((size_t)&m->msg_flags, sizeof(int));

    /* total bytes received; clear the tag bits */
    tot = (size_t)msg->msg_len;
    tagmap_clrn((size_t)&msg->msg_len, sizeof(unsigned));

    /* iterate the iovec structures */
    for (j = 0; j < m->msg_iovlen && tot > 0; j++) {
      /* get the next I/O vector */
      iov = &m->msg_iov[j];

      /* get the length of the iovec */
      iov_tot = (tot > (size_t)iov->iov_len) ? (size_t)iov->iov_len : tot;

      /* clear the tag bits */
      tagmap_clrn((size_t)iov->iov_base, iov_tot);

      /* housekeeping */
      tot -= iov_tot;
    }
  }

  /* timespec structure specified */
  if ((struct timespec *)ctx->arg[SYSCALL_ARG4] != NULL)
    ;
  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG4], sizeof(struct timespec));
}

static void post_msgctl_hook(THREADID tid, syscall_ctx_t *ctx) {
  if (unlikely((long)ctx->ret < 0))
    return;

  /* fix the cmd parameter */
  // ctx->arg[SYSCALL_ARG2] -= IPC_FIX;

  /* differentiate based on the cmd */
  switch ((int)ctx->arg[SYSCALL_ARG1]) {
  case IPC_STAT:
  case MSG_STAT:
    // case MSG_STAT_ANY:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct msqid_ds));
    break;
  case IPC_INFO:
  case MSG_INFO:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct msginfo));
    break;
  default:
    /* nothing to do */
    return;
  }
}

static void post_shmctl_hook(THREADID tid, syscall_ctx_t *ctx) {
  if (unlikely((long)ctx->ret < 0))
    return;

  /* fix the cmd parameter */
  // FIXME:
  // ctx->arg[SYSCALL_ARG2] -= IPC_FIX;

  /* differentiate based on the cmd */
  switch ((int)ctx->arg[SYSCALL_ARG1]) {
  case IPC_STAT:
  case SHM_STAT:
    // case SHM_STAT_ANY:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct shmid_ds));
    break;
  case IPC_INFO:
  case SHM_INFO:
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(struct shminfo));
    break;
  default:
    /* nothing to do */
    return;
  }
}

static void post_semctl_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* semctl() was not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* get the semun structure */
  union semun *su;
  su = (union semun *)ctx->arg[SYSCALL_ARG4];

  /* fix the cmd parameter */
  // ctx->arg[SYSCALL_ARG2] -= IPC_FIX;

  /* differentiate based on the cmd */
  switch ((int)ctx->arg[SYSCALL_ARG2]) {
  case IPC_STAT:
  case SEM_STAT:
    // case SEM_STAT_ANY:
    /* clear the tag bits */
    tagmap_clrn((size_t)su->buf, sizeof(struct semid_ds));
    break;
  case IPC_INFO:
  case SEM_INFO:
    /* clear the tag bits */
    tagmap_clrn((size_t)su->buf, sizeof(struct seminfo));
    break;
  default:
    /* nothing to do */
    return;
  }
}

static void post_msgrcv_hook(THREADID tid, syscall_ctx_t *ctx) {
  if (unlikely((long)ctx->ret <= 0))
    return;
  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret + sizeof(long));
}

static void post_accept_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* addr argument is provided */
  if ((void *)ctx->arg[SYSCALL_ARG1] != NULL) {
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG1], *((int *)ctx->arg[SYSCALL_ARG2]));

    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG2], sizeof(int));
  }
}

static void post_recvfrom_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG1], (size_t)ctx->ret);

  /* sockaddr argument is specified */
  if ((void *)ctx->arg[SYSCALL_ARG4] != NULL) {
    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG4], *((int *)ctx->arg[SYSCALL_ARG5]));

    /* clear the tag bits */
    tagmap_clrn(ctx->arg[SYSCALL_ARG5], sizeof(int));
  }
}

static void post_getsockopt_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* not successful; optimized branch */
  if (unlikely((long)ctx->ret < 0))
    return;

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG3], *((int *)ctx->arg[SYSCALL_ARG4]));

  /* clear the tag bits */
  tagmap_clrn(ctx->arg[SYSCALL_ARG4], sizeof(int));
}

static void post_recvmsg_hook(THREADID tid, syscall_ctx_t *ctx) {
  /* not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;
  /* message header; recvmsg(2) */
  struct msghdr *msg;

  /* iov bytes copied; recvmsg(2) */
  size_t iov_tot;

  /* iterators */
  size_t i;
  struct iovec *iov;

  /* total bytes received */
  size_t tot;

  /* extract the message header */
  msg = (struct msghdr *)ctx->arg[SYSCALL_ARG1];

  /* source address specified */
  if (msg->msg_name != NULL) {
    /* clear the tag bits */
    tagmap_clrn((size_t)msg->msg_name, msg->msg_namelen);

    /* clear the tag bits */
    tagmap_clrn((size_t)&msg->msg_namelen, sizeof(int));
  }

  /* ancillary data specified */
  if (msg->msg_control != NULL) {
    /* clear the tag bits */
    tagmap_clrn((size_t)msg->msg_control, msg->msg_controllen);

    /* clear the tag bits */
    tagmap_clrn((size_t)&msg->msg_controllen, sizeof(int));
  }

  /* flags; clear the tag bits */
  tagmap_clrn((size_t)&msg->msg_flags, sizeof(int));

  /* total bytes received */
  tot = (size_t)ctx->ret;

  /* iterate the iovec structures */
  for (i = 0; i < msg->msg_iovlen && tot > 0; i++) {
    /* get the next I/O vector */
    iov = &msg->msg_iov[i];

    /* get the length of the iovec */
    iov_tot = (tot > (size_t)iov->iov_len) ? (size_t)iov->iov_len : tot;

    /* clear the tag bits */
    tagmap_clrn((size_t)iov->iov_base, iov_tot);

    /* housekeeping */
    tot -= iov_tot;
  }
}