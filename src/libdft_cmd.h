#ifndef __LIBDFT_CMD_H__
#define __LIBDFT_CMD_H__

/* Available commands. */
#define CMD_TAINT_DUMP        0
#define CMD_TAINT_MEM_ALL     1

/* APIs for the target. */
static __attribute__((noinline)) void __libdft_cmd(int cmd, void *arg1)
{
	/* Forwarded to PIN / libdft */
	asm("");
}

static inline void __libdft_taint_mem_all()
{
	__libdft_cmd(CMD_TAINT_MEM_ALL, NULL);
}

static inline void __libdft_taint_dump(void *addr)
{
	__libdft_cmd(CMD_TAINT_DUMP, addr);
}

#endif /* __LIBDFT_CMD_H__ */
