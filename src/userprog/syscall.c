#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
 
 
static int sys_halt (void);
static int sys_exec (const char *ufile);
static int sys_wait (tid_t);
static int sys_create (const char *ufile, unsigned initial_size);
static int sys_remove (const char *ufile);
static int sys_open (const char *ufile);
static int sys_filesize (int handle);
static int sys_read (int handle, void *udst_, unsigned size);
static int sys_write (int handle, void *usrc_, unsigned size);
static int sys_seek (int handle, unsigned position);
static int sys_tell (int handle);
static int sys_close (int handle);
 
static void syscall_handler (struct intr_frame *);
static void copy_in (void *, const void *, size_t);
 
typedef int (f_ptr)(uint32_t,uint32_t, uint32_t);

/* Serializes file system operations. */
static struct lock fs_lock;

/* A system call. */ 
static struct syscall 
{ 
  size_t arg_cnt;  /* Number of arguments. */ 
  f_ptr *func;      /* Implementation. */ 
}; 

/* Table of system calls. */ 
static const struct syscall syscall_table[] = 
{ 
  {0, (void *) sys_halt}, 
  {1, (void *) sys_exit}, 
  {1, (void *) sys_exec}, 
  {1, (void *) sys_wait}, 
  {2, (void *) sys_create}, 
  {1, (void *) sys_remove}, 
  {1, (void *) sys_open}, 
  {1, (void *) sys_filesize},
  {3, (void *) sys_read},
  {3, (void *) sys_write},
  {2, (void *) sys_seek},
  {1, (void *) sys_tell},
  {1, (void *) sys_close}
};
 
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}
 
/* System call handler. */

static void
syscall_handler( struct intr_frame *f )
{
  const struct syscall *sc;
  unsigned call_nr;
  int args[3];

  /* Get the system call. */
  copy_in( &call_nr, f->esp, sizeof call_nr );
  if( call_nr >= sizeof syscall_table /sizeof *syscall_table )
    sys_exit(-1);
  sc = syscall_table + call_nr;
  
  /* Get the system call arguments. */
  ASSERT (sc->arg_cnt <= sizeof args / sizeof *args );
  memset( args, 0, sizeof args );
  copy_in( args, (uint32_t*) f->esp+1, sizeof *args * sc->arg_cnt );
  
  /* Execute the system call, and set the return value. */
  f->eax = sc->func( args[0], args[1], args[2] );
}

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool
verify_user (const void *uaddr) 
{ 
  if (uaddr != NULL )
    return (uaddr < PHYS_BASE
          && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}
 
/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  if( !verify_user( (void*)usrc ) ) sys_exit(-1);
  
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
  if (!verify_user( (void*)udst ) ) sys_exit(-1);

  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}
 
/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size) 
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++) 
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc))
      sys_exit(-1);
}
 
/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us) 
{
  char *ks;
  size_t length;
 
  ks = palloc_get_page (0);
  if (ks == NULL)
    sys_exit(-1);
  
  for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
        {
          palloc_free_page (ks);
          sys_exit(-1); 
        }
      if (ks[length] == '\0')
        return ks;
    }
  ks[PGSIZE - 1] = '\0';
  return ks;
}
 
/* Halt system call. */
static int
sys_halt (void)
{
  shutdown_power_off ();
}
 
/* Exit system call. */
int
sys_exit (int exit_code) 
{
  thread_current ()->wait_status->exit_code = exit_code;
  printf ("%s: exit(%d)\n", thread_current()->name, thread_current()->wait_status->exit_code);
  thread_exit();
  return( exit_code );
}
 
/* Exec system call. */
static int
sys_exec (const char *ufile) 
{
  int ret = -1;
  if( ufile != NULL && verify_user( (void*)ufile ))
  {
    lock_acquire( &fs_lock);
    ret = process_execute(ufile);
    lock_release (&fs_lock);
  }
  return ret;
}
 
/* Wait system call. */
static int
sys_wait (tid_t child) 
{
  return process_wait( child );
}
 
/* Create system call. */
static int
sys_create (const char *ufile, unsigned initial_size) 
{
  if( !verify_user( (void*)ufile) )
    sys_exit(-1);

  lock_acquire (&fs_lock);
  int ret = 0;
  if( ufile != NULL && *ufile && filesys_create(ufile, initial_size) )
    ret = 1;
  lock_release (&fs_lock);

  return ret;
}
 
/* Remove system call. */
static int
sys_remove (const char *ufile) 
{
  if( !verify_user( (void*)ufile ))
    sys_exit(-1);

  lock_acquire (&fs_lock);
  int ret = 0;
  if( ufile != NULL && *ufile && filesys_remove(ufile) )
    ret = 1;
  lock_release (&fs_lock);

  return ret;
}
 
/* A file descriptor, for binding a file handle to a file. */
struct file_descriptor
  {
    struct list_elem elem;      /* List element. */
    struct file *file;          /* File. */
    int handle;                 /* File handle. */
  };
 
/* Open system call. */
static int
sys_open (const char *ufile) 
{ 
  if( !ufile ) sys_exit(-1);
  
  char *kfile = copy_in_string (ufile);
  struct file_descriptor *fd;
  int handle = -1;
   
  fd = malloc (sizeof *fd);
  if (fd != NULL && ufile!=NULL)
  {
    lock_acquire (&fs_lock);
    fd->file = filesys_open (kfile);
    if (fd->file != NULL)
    {
      struct thread *cur = thread_current ();
      handle = fd->handle = cur->next_handle++;
      list_push_front (&cur->fds, &fd->elem);
    }
    else 
      free (fd);
    lock_release (&fs_lock);
  }
  
  palloc_free_page (kfile);
  return handle;
}
 
/* Returns the file descriptor associated with the given handle.
   Terminates the process if HANDLE is not associated with an
   open file. */
static struct file_descriptor *
lookup_fd (int handle)
{
  /* Add code to lookup file descriptor in the current thread's fds */
  struct list_elem *f;
  struct list file_list = thread_current ()->fds;

  if( handle == STDOUT_FILENO || handle == STDIN_FILENO
	|| handle > thread_current ()->next_handle || handle < 1)
    sys_exit(-1);

  for (f = list_begin (&file_list); f != list_end (&file_list); f = f->next)
  {
    struct file_descriptor *fd = list_entry (f, struct file_descriptor, elem);
	if( fd != NULL && fd->handle == handle ) 
      return fd;
  }
  sys_exit(-1);
}
 
/* Filesize system call. */
static int
sys_filesize (int handle) 
{
  struct file_descriptor *fd = lookup_fd(handle);
  int ret = -1;
  lock_acquire (&fs_lock);
  if (fd != NULL)
    ret =  file_length (fd->file);
  lock_release (&fs_lock);
  return ret;
}
 
/* Read system call. */
static int
sys_read (int handle, void *udst_, unsigned size) 
{
  if( !verify_user( udst_) || !verify_user (udst_ + size) )
    return sys_exit( -1 );
  
  lock_acquire (&fs_lock);
  int ret = -1;
  struct file_descriptor *fd = lookup_fd (handle);
  if (fd != NULL)
    ret = file_read (fd->file, udst_, size);
  lock_release (&fs_lock);
  return ret;
}
 
/* Write system call. */
static int
sys_write (int handle, void *usrc_, unsigned size) 
{
  uint8_t *usrc = usrc_;
  struct file_descriptor *fd = NULL;
  int bytes_written = 0;
  
  if( handle == STDIN_FILENO )
    return -1;
  /* Lookup up file descriptor. */
  if (handle != STDOUT_FILENO)
  {
    fd = lookup_fd (handle);
    if (fd == NULL)
      return -1;
  }
  lock_acquire (&fs_lock);
  while (size > 0) 
    {
      /* How much bytes to write to this page? */
      size_t page_left = PGSIZE - pg_ofs (usrc);
      size_t write_amt = size < page_left ? size : page_left;
      off_t retval;

      /* Check that we can touch this user page. */
      if (!verify_user (usrc)) 
        {
          lock_release (&fs_lock);
          sys_exit(-1);
        }

      /* Do the write. */
      if (handle == STDOUT_FILENO)
        {
          putbuf (usrc, write_amt);
          retval = write_amt;
        }
      else
        retval = file_write (fd->file, usrc, write_amt);
      if (retval < 0) 
        {
          if (bytes_written == 0)
            bytes_written = -1;
          break;
        }
      bytes_written += retval;

      /* If it was a short write we're done. */
      if (retval != (off_t) write_amt)
        break;

      /* Advance. */
      usrc += retval;
      size -= retval;
    }
  lock_release (&fs_lock);
 
  return bytes_written;
}
 
/* Seek system call. */
static int
sys_seek (int handle, unsigned position) 
{
  struct file_descriptor *fd = lookup_fd (handle);
  int ret = -1;
  if (fd != NULL)
  {
    file_seek (fd->file, position);
	ret = 0;
  }
  return ret;
}
 
/* Tell system call. */
static int
sys_tell (int handle) 
{
  struct file_descriptor *fd = lookup_fd (handle);
  if (fd != NULL)
  {
    struct file *f = fd->file;
	return file_tell (f);
  }
  return -1;
}
 
/* Close system call. */
static int
sys_close (int handle) 
{
  struct file_descriptor *fd = lookup_fd (handle);
  int ret = -1;
  if (fd != NULL)
  {
    lock_acquire (&fs_lock);
    struct file *f = fd->file;
    file_close (f);
    list_remove( &fd->elem );
    free( fd );
    lock_release (&fs_lock);
    ret = 0;
  }
  return ret;
}
 
/* On thread exit, close all open files. */
void
syscall_exit (void) 
{
  while (!list_empty (&thread_current ()->fds))
  {
    struct file_descriptor *fd = list_entry (list_begin (&thread_current ()->fds),
						struct file_descriptor, elem);
    sys_close (fd->handle);
  }
}
