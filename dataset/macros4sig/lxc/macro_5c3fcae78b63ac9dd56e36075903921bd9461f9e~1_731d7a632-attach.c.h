#include<sched.h>
#include<netinet/in.h>
#include<sys/mount.h>
#include<linux/unistd.h>
#include<stddef.h>
#include<malloc.h>
#include<sys/param.h>

#include<sys/file.h>
#include<signal.h>
#include<errno.h>

#include<sys/wait.h>
#include<sys/prctl.h>
#include<sys/stat.h>
#include<grp.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<time.h>
#include<stdio.h>
#include<strings.h>

#include<stdarg.h>
#include<sys/personality.h>
#include<sys/syscall.h>
#include<sys/time.h>
#include<stdbool.h>
#include<fcntl.h>
#include<net/if.h>
#include<stdint.h>
#include<sys/socket.h>
#include<semaphore.h>
#include<sys/types.h>


#include<pwd.h>

#define LXC_ATTACH_LSM (LXC_ATTACH_LSM_EXEC | LXC_ATTACH_LSM_NOW)
#define LXC_ATTACH_OPTIONS_DEFAULT \
	{ \
		   LXC_ATTACH_DEFAULT, \
		     -1, \
		    -1, \
		    NULL, \
		            (uid_t)-1, \
		            (gid_t)-1, \
		     LXC_ATTACH_KEEP_ENV, \
		 NULL, \
		 NULL, \
		       0, 1, 2 \
	}


#define LXC_CLONE_KEEPBDEVTYPE    (1 << 3) 
#define LXC_CLONE_KEEPMACADDR     (1 << 1) 
#define LXC_CLONE_KEEPNAME        (1 << 0) 
#define LXC_CLONE_MAXFLAGS        (1 << 5) 
#define LXC_CLONE_MAYBE_SNAPSHOT  (1 << 4) 
#define LXC_CLONE_SNAPSHOT        (1 << 2) 
#define LXC_CREATE_MAXFLAGS       (1 << 1) 
#define LXC_CREATE_QUIET          (1 << 0) 



#define subgidfile "/etc/subgid"
#define subuidfile "/etc/subuid"

#  define CLONE_FS                0x00000200
#  define CLONE_NEWIPC            0x08000000
#  define CLONE_NEWNET            0x40000000
#  define CLONE_NEWNS             0x00020000
#  define CLONE_NEWPID            0x20000000
#  define CLONE_NEWUSER           0x10000000
#  define CLONE_NEWUTS            0x04000000



#define lxc_init_list(l) { .next = l, .prev = l }
#define lxc_list_for_each(__iterator, __list)				\
	for (__iterator = (__list)->next;				\
	     __iterator != __list;					\
	     __iterator = __iterator->next)
#define lxc_list_for_each_safe(__iterator, __list, __next)		\
	for (__iterator = (__list)->next, __next = __iterator->next;	\
	     __iterator != __list;					\
	     __iterator = __next, __next = __next->next)
#define LXC_LOCK_ANON_SEM 1 
#define LXC_LOCK_FLOCK    2 


#define INT_TO_PTR(n) ((void *) (long) (n))
#define LXC_CMD_DATA_MAX (MAXPATHLEN*2)
#define PTR_TO_INT(p) ((int) (long) (p))

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define FNV1A_64_INIT ((uint64_t)0xcbf29ce484222325ULL)
#define SHA_DIGEST_LENGTH 20

#      define __NR_signalfd 321
#      define __NR_signalfd4 327

#define DEFAULT_THIN_POOL "lxc"
#define DEFAULT_VG "lxc"
#define DEFAULT_ZFSROOT "lxc"


#define lxc_priv(__lxc_function)			\
	({						\
		__label__ out;				\
		int __ret, __ret2, ___errno = 0;		\
		__ret = lxc_caps_up();			\
		if (__ret)				\
			goto out;			\
		__ret = __lxc_function;			\
		if (__ret)				\
			___errno = errno;		\
		__ret2 = lxc_caps_down();		\
	out:	__ret ? errno = ___errno,__ret : __ret2;	\
	})
#define lxc_unpriv(__lxc_function)			\
	({						\
		__label__ out;				\
		int __ret, __ret2, ___errno = 0;		\
		__ret = lxc_caps_down();		\
		if (__ret)				\
			goto out;			\
		__ret = __lxc_function;			\
		if (__ret)				\
			___errno = errno;		\
		__ret2 = lxc_caps_up();			\
	out:	__ret ? errno = ___errno,__ret : __ret2;	\
	})

#define ALERT(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_ALERT(&locinfo, format, ##__VA_ARGS__);			\
} while (0)
#define ATTR_UNUSED __attribute__ ((unused))
#define CRIT(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_CRIT(&locinfo, format, ##__VA_ARGS__);			\
} while (0)
#define DEBUG(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_DEBUG(&locinfo, format, ##__VA_ARGS__);			\
} while (0)
#define ERROR(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_ERROR(&locinfo, format, ##__VA_ARGS__);			\
} while (0)
#define FATAL(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_FATAL(&locinfo, format, ##__VA_ARGS__);			\
} while (0)
#define F_DUPFD_CLOEXEC 1030
#define INFO(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_INFO(&locinfo, format, ##__VA_ARGS__);			\
} while (0)
#define NOTICE(format, ...) do {					\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_NOTICE(&locinfo, format, ##__VA_ARGS__);			\
} while (0)
#define O_CLOEXEC 02000000
#define SYSERROR(format, ...) do {				    	\
	ERROR("%s - " format, strerror(errno), ##__VA_ARGS__);		\
} while (0)
#define TRACE(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_TRACE(&locinfo, format, ##__VA_ARGS__);			\
} while (0)
#define WARN(format, ...) do {						\
	struct lxc_log_locinfo locinfo = LXC_LOG_LOCINFO_INIT;		\
	LXC_WARN(&locinfo, format, ##__VA_ARGS__);			\
} while (0)

#define lxc_log_category_define(name, parent)				\
	extern struct lxc_log_category lxc_log_category_##parent;	\
	struct lxc_log_category lxc_log_category_##name = {		\
		#name,							\
		LXC_LOG_PRIORITY_NOTSET,				\
		NULL,							\
		&lxc_log_category_##parent				\
	};
#define lxc_log_category_priority(name) 				\
	(lxc_log_priority_to_string(lxc_log_category_##name.priority))
#define lxc_log_define(name, parent)					\
	lxc_log_category_define(name, parent)				\
									\
	lxc_log_priority_define(&lxc_log_category_##name, TRACE)	\
	lxc_log_priority_define(&lxc_log_category_##name, DEBUG)	\
	lxc_log_priority_define(&lxc_log_category_##name, INFO)		\
	lxc_log_priority_define(&lxc_log_category_##name, NOTICE)	\
	lxc_log_priority_define(&lxc_log_category_##name, WARN)		\
	lxc_log_priority_define(&lxc_log_category_##name, ERROR)	\
	lxc_log_priority_define(&lxc_log_category_##name, CRIT)		\
	lxc_log_priority_define(&lxc_log_category_##name, ALERT)	\
	lxc_log_priority_define(&lxc_log_category_##name, FATAL)
#define lxc_log_priority_define(acategory, PRIORITY)			\
									\
ATTR_UNUSED static inline void LXC_##PRIORITY(struct lxc_log_locinfo *,		\
	const char *, ...) __attribute__ ((format (printf, 2, 3)));	\
									\
ATTR_UNUSED static inline void LXC_##PRIORITY(struct lxc_log_locinfo* locinfo,	\
				  const char* format, ...)		\
{									\
	if (lxc_log_priority_is_enabled(acategory, 			\
					LXC_LOG_PRIORITY_##PRIORITY)) {	\
		struct lxc_log_event evt = {				\
			.category	= (acategory)->name,		\
			.priority	= LXC_LOG_PRIORITY_##PRIORITY,	\
			.fmt		= format,			\
			.locinfo	= locinfo			\
		};							\
		va_list va_ref;						\
									\
		gettimeofday(&evt.timestamp, NULL);			\
									\
		va_start(va_ref, format);				\
		evt.vap = &va_ref;					\
		__lxc_log(acategory, &evt);				\
		va_end(va_ref);						\
	}								\
}
