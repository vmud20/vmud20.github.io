#include<sys/stat.h>
#include<linux/magic.h>
#include<grp.h>
#include<sys/epoll.h>
#include<sys/types.h>
#include<sys/xattr.h>
#include<unistd.h>
#include<string.h>
#include<time.h>
#include<fcntl.h>
#include<pwd.h>
#include<sys/un.h>
#include<stdarg.h>
#include<sys/wait.h>
#include<sys/sysmacros.h>
#include<sys/signalfd.h>
#include<sys/socket.h>
#include<sys/syscall.h>

#include<sys/vfs.h>
#include<sys/time.h>
# define LIKELY(x) __builtin_expect((x),1)
#  define TEMP_FAILURE_RETRY(expression)                                \
  (__extension__                                                        \
   ({ long int __result;                                                \
     do __result = (long int) (expression);                             \
     while (__result < 0 && errno == EINTR);                            \
     __result; }))
# define UNLIKELY(x) __builtin_expect((x),0)
# define UTILS_H
# define arg_unused __attribute__((unused))
# define cleanup_close __attribute__((cleanup (cleanup_closep)))
# define cleanup_close_vec __attribute__((cleanup (cleanup_close_vecp)))
# define cleanup_dir __attribute__((cleanup (cleanup_dirp)))
# define cleanup_file __attribute__((cleanup (cleanup_filep)))
# define cleanup_free __attribute__((cleanup (cleanup_freep)))
