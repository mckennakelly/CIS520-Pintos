#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void syscall_exit (void);

int sys_exit (int status);

#endif /* userprog/syscall.h */
