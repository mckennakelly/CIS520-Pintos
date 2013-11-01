#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

static void sys_halt( void );
static int sys_exit( int );
static int sys_exec( const char* );
static int sys_wait( int pid );
static bool sys_create( const char*, unsigned );
static bool sys_remove( const char* );
static int sys_open( const char* );
static int sys_filesize( int );
static int sys_read( int, void*, unsigned );
static int sys_write( int, const void*, unsigned );
static void sys_seek( int, unsigned );
static unsigned sys_tell( int );
static void sys_close( int );

void syscall_exit (void);
static bool verify_user (const void *uaddr);
static bool get_user(uint8_t *dst, const uint8_t *usrc);
static bool put_user(uint8_t *udst, uint8_t byte);
static void copy_in (void *dst_, const void *usrc_, size_t size);
static char * copy_in_string (const char *us);

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
}

/* System call handler. */
static void
syscall_handler (struct intr_frame *f)
{
  const struct syscall *sc;
  int *args;
  
  args = f->esp;
  if(!is_user_vaddr(args) || *args < 0)
	sys_exit(-1);
  sc = syscall_table + *args;
  f->eax = sc->func(args[1], args[2], args[3]);
}

static void
sys_halt( void )
{
  shutdown_power_off();
}

static int
sys_exit( int status )
{
  syscall_exit();
  thread_current ()->wait_status->exit_code = status;
  printf("%s: exit(%d)", thread_current ()->name, status);
  thread_exit ();
  return( status );
}

static int
sys_exec( const char* cmd_line )
{
  if (!cmd_line) return -1;
    return process_execute(cmd_line);
}

static int
sys_wait( int pid )
{

}

static bool
sys_create( const char* file, unsigned initial_size )
{
  if (!file && is_user_vaddr(file))
  {
    bool was_created = filesys_create(file, initial_size);
	if (was_created) return 0;
  }
  return -1;
}

static bool
sys_remove( const char* file )
{
  if (!file && is_user_vaddr(file))
  {
    bool was_removed = filesys_remove(file);
	if (was_removed) return 0;
  }
  return -1;
}

/* A file descriptor, for binding a file handle to a file. */
struct file_descriptor
{
  struct list_elem elem;      /* List element. */
  struct file *file;          /* File. */
  int handle;                 /* File handle. */
};
  
static int
sys_open( const char* file )
{
  char *kfile = copy_in_string (file);
  struct file_descriptor *fd;
  int handle = -1;
 
  fd = malloc (sizeof *fd);
  if (fd != NULL)
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
  for (f = list_begin (&file_list); f != list_end (&file_list); f = list_next (f))
  {
    struct file_descriptor *fd = list_entry (f, struct file_descriptor, elem);
    if (fd->handle == handle) return fd;
  }
  return NULL;
}

static int
sys_filesize( int handle )
{
  struct file_descriptor *fd = lookup_fd(handle);
  if (fd != NULL)
  {
    struct file *f= fd->file;
	return file_length (f);
  }
  return -1;
}

static int
sys_read( int handle, void* udst_, unsigned size )
{
  struct file_descriptor *fd = lookup_fd (handle);
  if (fd != NULL)
  {
    struct file *f = fd->file;
    return file_read (f, udst_, size);
  }
  return -1;
}

static int
sys_write( int handle, const void* usrc_, unsigned size )
{
  uint8_t *usrc = usrc_;
  struct file_descriptor *fd = NULL;
  int bytes_written = 0;

  /* Lookup up file descriptor. */
  if (handle != STDOUT_FILENO)
    fd = lookup_fd (handle);

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
          thread_exit ();
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

static void
sys_seek( int handle, unsigned position )
{
  struct file_descriptor *fd = lookup_fd (handle);
  if (!fd)
  {
    struct file *f = fd->file;
	file_seek (f, position);
  }
}

static unsigned
sys_tell( int handle )
{
  struct file_descriptor *fd = lookup_fd (handle);
  if (fd != NULL)
  {
    struct file *f = fd->file;
	return file_tell (f);
  }
  return -1;
}

static void
sys_close( int handle )
{
  struct file_descriptor *fd = lookup_fd (handle);
  if (fd != NULL)
  {
    struct file *f = fd->file;
	file_close (f);
  }
}

/* On thread exit, close all open files. */
void
syscall_exit (void) 
{
/* Add code */
  struct list_elem *f;
  struct list file_list = thread_current ()->fds;
  for (f = list_begin (&file_list); f != list_end (&file_list); f = list_next (f))
  {
    struct file_descriptor *fd = list_entry (f, struct file_descriptor, elem);
    struct file *f_ptr = fd->file;
	file_close (f_ptr);
  }
}

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool
verify_user (const void *uaddr) 
{
  return (uaddr < PHYS_BASE
          && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}

/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
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
      thread_exit ();
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
    thread_exit ();
 
  for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
        {
          palloc_free_page (ks);
          thread_exit (); 
        }
      if (ks[length] == '\0')
        return ks;
    }
  ks[PGSIZE - 1] = '\0';
  return ks;
}

