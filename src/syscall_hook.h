
#ifndef __SYSCALL_HOOK_H__
#define __SYSCALL_HOOK_H__

bool is_tainted();
void hook_file_syscall_set_filename(const char * new_filename);
void hook_file_syscall();

#endif