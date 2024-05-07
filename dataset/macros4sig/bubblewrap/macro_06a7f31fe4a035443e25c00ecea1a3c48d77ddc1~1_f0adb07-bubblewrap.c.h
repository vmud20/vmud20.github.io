#include<grp.h>
#include<assert.h>
#include<sys/stat.h>
#include<dirent.h>
#include<sys/eventfd.h>
#include<linux/filter.h>
#include<fcntl.h>
#include<sys/wait.h>
#include<stdarg.h>
#include<stdio.h>
#include<sys/fsuid.h>
#include<linux/sched.h>
#include<linux/seccomp.h>
#include<stdlib.h>
#include<sched.h>

#include<sys/prctl.h>
#include<poll.h>
#include<errno.h>
#include<string.h>
#include<sys/mount.h>
#include<sys/types.h>
#include<sys/signalfd.h>
#include<pwd.h>

#include<unistd.h>
#include<sys/socket.h>
#define FALSE 0
#define N_ELEMENTS(arr) (sizeof (arr) / sizeof ((arr)[0]))
#define PIPE_READ_END 0
#define PIPE_WRITE_END 1
#define TRUE 1
#define UNUSED __attribute__((__unused__))

#define cleanup_fd __attribute__((cleanup (cleanup_fdp)))
#define cleanup_free __attribute__((cleanup (cleanup_freep)))
#define cleanup_strv __attribute__((cleanup (cleanup_strvp)))
#define steal_pointer(pp) \
  (0 ? (*(pp)) : (steal_pointer) (pp))
