
#include<asm/socket.h>

#include<linux/socket.h>
#include<linux/aio_abi.h>

#include<linux/limits.h>



#include<linux/sched.h>



#include<linux/resource.h>






#include<asm/stat.h>




#include<linux/wait.h>
#include<linux/sem.h>


#include<linux/time.h>
#include<asm/ipcbuf.h>




#include<linux/auxvec.h>
#include<asm/posix_types.h>

#include<asm/fcntl.h>


#include<linux/stddef.h>

#include<linux/string.h>


#include<linux/fs.h>
#include<asm/ptrace.h>



#include<asm/types.h>




#include<linux/capability.h>
#include<asm/ioctl.h>




#include<linux/in.h>

#include<asm/errno.h>

#include<linux/sysctl.h>




#include<asm/resource.h>
#include<asm/param.h>


#include<asm/sockios.h>

#include<linux/types.h>
#include<linux/timex.h>
#include<asm/byteorder.h>
#include<linux/ipc.h>









#include<stdarg.h>




#include<asm/signal.h>

#include<linux/signal.h>




#include<asm/shmbuf.h>
#include<linux/uio.h>
#include<linux/sunrpc/debug.h>
#include<asm/siginfo.h>
#include<linux/stat.h>
#include<linux/quota.h>

#include<linux/nfs.h>



#include<asm/auxvec.h>
#include<linux/errno.h>
#include<asm/sembuf.h>

#include<linux/kernel.h>
#include<asm/msgbuf.h>


#define NFS_ADDR(inode)			(RPC_PEERADDR(NFS_CLIENT(inode)))
#define NFS_ATTRTIMEO(inode)		(NFS_I(inode)->attrtimeo)
#define NFS_ATTRTIMEO_UPDATE(inode)	(NFS_I(inode)->attrtimeo_timestamp)
#define NFS_CHANGE_ATTR(inode)		(NFS_I(inode)->change_attr)
#define NFS_CLIENT(inode)		(NFS_SERVER(inode)->client)
#define NFS_COOKIEVERF(inode)		(NFS_I(inode)->cookieverf)
# define NFS_DEBUG
#define NFS_FH(inode)			(&NFS_I(inode)->fh)
#define NFS_FILEID(inode)		(NFS_I(inode)->fileid)
#define NFS_FLAGS(inode)		(NFS_I(inode)->flags)
#define NFS_JUKEBOX_RETRY_TIME (5 * HZ)
#define NFS_MAXATTRTIMEO(inode) \
	(S_ISDIR(inode->i_mode)? NFS_SERVER(inode)->acdirmax \
			       : NFS_SERVER(inode)->acregmax)
#define NFS_MINATTRTIMEO(inode) \
	(S_ISDIR(inode->i_mode)? NFS_SERVER(inode)->acdirmin \
			       : NFS_SERVER(inode)->acregmin)
#define NFS_PROTO(inode)		(NFS_SERVER(inode)->rpc_ops)
#define NFS_READTIME(inode)		(NFS_I(inode)->read_cache_jiffies)
#define NFS_SB(s)		((struct nfs_server *)(s->s_fs_info))
#define NFS_SERVER(inode)		(NFS_SB(inode->i_sb))
#define NFS_STALE(inode)		(test_bit(NFS_INO_STALE, &NFS_FLAGS(inode)))

#  define ifdebug(fac)		if (unlikely(nfs_debug & NFSDBG_##fac))
# define nfs3_getxattr NULL
# define nfs3_listxattr NULL
# define nfs3_removexattr NULL
# define nfs3_setxattr NULL
#define nfs_wait_event(clnt, wq, condition)				\
({									\
	int __retval = 0;						\
	if (clnt->cl_intr) {						\
		sigset_t oldmask;					\
		rpc_clnt_sigmask(clnt, &oldmask);			\
		__retval = wait_event_interruptible(wq, condition);	\
		rpc_clnt_sigunmask(clnt, &oldmask);			\
	} else								\
		wait_event(wq, condition);				\
	__retval;							\
})

#define DECLARE_WAITQUEUE(name, tsk)					\
	wait_queue_t name = __WAITQUEUE_INITIALIZER(name, tsk)
#define DECLARE_WAIT_QUEUE_HEAD(name) \
	wait_queue_head_t name = __WAIT_QUEUE_HEAD_INITIALIZER(name)
#define DEFINE_WAIT(name)						\
	wait_queue_t name = {						\
		.private	= current,				\
		.func		= autoremove_wake_function,		\
		.task_list	= LIST_HEAD_INIT((name).task_list),	\
	}
#define DEFINE_WAIT_BIT(name, word, bit)				\
	struct wait_bit_queue name = {					\
		.key = __WAIT_BIT_KEY_INITIALIZER(word, bit),		\
		.wait	= {						\
			.private	= current,			\
			.func		= wake_bit_function,		\
			.task_list	=				\
				LIST_HEAD_INIT((name).wait.task_list),	\
		},							\
	}

#define __WAITQUEUE_INITIALIZER(name, tsk) {				\
	.private	= tsk,						\
	.func		= default_wake_function,			\
	.task_list	= { NULL, NULL } }
#define __WAIT_BIT_KEY_INITIALIZER(word, bit)				\
	{ .flags = word, .bit_nr = bit, }
#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {				\
	.lock		= SPIN_LOCK_UNLOCKED,				\
	.task_list	= { &(name).task_list, &(name).task_list } }
#define __wait_event(wq, condition) 					\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		schedule();						\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define __wait_event_interruptible(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define __wait_event_interruptible_exclusive(wq, condition, ret)	\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait_exclusive(&wq, &__wait,			\
					TASK_INTERRUPTIBLE);		\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_INTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define __wait_event_timeout(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);	\
		if (condition)						\
			break;						\
		ret = schedule_timeout(ret);				\
		if (!ret)						\
			break;						\
	}								\
	finish_wait(&wq, &__wait);					\
} while (0)
#define init_wait(wait)							\
	do {								\
		(wait)->private = current;				\
		(wait)->func = autoremove_wake_function;		\
		INIT_LIST_HEAD(&(wait)->task_list);			\
	} while (0)
#define is_sync_wait(wait)	(!(wait) || ((wait)->private))
#define wait_event(wq, condition) 					\
do {									\
	if (condition)	 						\
		break;							\
	__wait_event(wq, condition);					\
} while (0)
#define wait_event_interruptible(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible(wq, condition, __ret);	\
	__ret;								\
})
#define wait_event_interruptible_exclusive(wq, condition)		\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_interruptible_exclusive(wq, condition, __ret);\
	__ret;								\
})
#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})
#define wait_event_timeout(wq, condition, timeout)			\
({									\
	long __ret = timeout;						\
	if (!(condition)) 						\
		__wait_event_timeout(wq, condition, __ret);		\
	__ret;								\
})
#define wake_up(x)			__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_all(x)			__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible(x)	__wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible_nr(x, nr)	__wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_sync(x)   __wake_up_sync((x),TASK_INTERRUPTIBLE, 1)
#define wake_up_nr(x, nr)		__wake_up(x, TASK_UNINTERRUPTIBLE | TASK_INTERRUPTIBLE, nr, NULL)
#define LOCK_SECTION_END                        \
        ".previous\n\t"
#define LOCK_SECTION_NAME                       \
        ".text.lock." __stringify(KBUILD_BASENAME)
#define LOCK_SECTION_START(extra)               \
        ".subsection 1\n\t"                     \
        extra                                   \
        ".ifndef " LOCK_SECTION_NAME "\n\t"     \
        LOCK_SECTION_NAME ":\n\t"               \
        ".endif\n"

#define __lockfunc fastcall __attribute__((section(".spinlock.text")))
# define _raw_read_lock(rwlock)		__raw_read_lock(&(rwlock)->raw_lock)
# define _raw_read_trylock(rwlock)	__raw_read_trylock(&(rwlock)->raw_lock)
# define _raw_read_unlock(rwlock)	__raw_read_unlock(&(rwlock)->raw_lock)
# define _raw_spin_lock(lock)		__raw_spin_lock(&(lock)->raw_lock)
# define _raw_spin_lock_flags(lock, flags) \
		__raw_spin_lock_flags(&(lock)->raw_lock, *(flags))
# define _raw_spin_trylock(lock)	__raw_spin_trylock(&(lock)->raw_lock)
# define _raw_spin_unlock(lock)		__raw_spin_unlock(&(lock)->raw_lock)
# define _raw_write_lock(rwlock)	__raw_write_lock(&(rwlock)->raw_lock)
# define _raw_write_trylock(rwlock)	__raw_write_trylock(&(rwlock)->raw_lock)
# define _raw_write_unlock(rwlock)	__raw_write_unlock(&(rwlock)->raw_lock)
#define atomic_dec_and_lock(atomic, lock) \
		__cond_lock(_atomic_dec_and_lock(atomic, lock))
#define read_can_lock(rwlock)		__raw_read_can_lock(&(rwlock)->raw_lock)
#define read_lock(lock)			_read_lock(lock)
#define read_lock_bh(lock)		_read_lock_bh(lock)
#define read_lock_irq(lock)		_read_lock_irq(lock)
#define read_lock_irqsave(lock, flags)	flags = _read_lock_irqsave(lock)
#define read_trylock(lock)		__cond_lock(_read_trylock(lock))
# define read_unlock(lock)		_read_unlock(lock)
#define read_unlock_bh(lock)		_read_unlock_bh(lock)
# define read_unlock_irq(lock)		_read_unlock_irq(lock)
#define read_unlock_irqrestore(lock, flags) \
					_read_unlock_irqrestore(lock, flags)
#define rwlock_init(lock)	do { *(lock) = RW_LOCK_UNLOCKED; } while (0)
#define spin_can_lock(lock)	(!spin_is_locked(lock))
#define spin_is_locked(lock)	__raw_spin_is_locked(&(lock)->raw_lock)
#define spin_lock(lock)			_spin_lock(lock)
#define spin_lock_bh(lock)		_spin_lock_bh(lock)
#define spin_lock_init(lock)	do { *(lock) = SPIN_LOCK_UNLOCKED; } while (0)
#define spin_lock_irq(lock)		_spin_lock_irq(lock)
#define spin_lock_irqsave(lock, flags)	flags = _spin_lock_irqsave(lock)
#define spin_trylock(lock)		__cond_lock(_spin_trylock(lock))
#define spin_trylock_bh(lock)		__cond_lock(_spin_trylock_bh(lock))
#define spin_trylock_irq(lock) \
({ \
	local_irq_disable(); \
	_spin_trylock(lock) ? \
	1 : ({ local_irq_enable(); 0;  }); \
})
#define spin_trylock_irqsave(lock, flags) \
({ \
	local_irq_save(flags); \
	_spin_trylock(lock) ? \
	1 : ({ local_irq_restore(flags); 0; }); \
})
# define spin_unlock(lock)		_spin_unlock(lock)
#define spin_unlock_bh(lock)		_spin_unlock_bh(lock)
# define spin_unlock_irq(lock)		_spin_unlock_irq(lock)
#define spin_unlock_irqrestore(lock, flags) \
					_spin_unlock_irqrestore(lock, flags)
#define spin_unlock_wait(lock)	__raw_spin_unlock_wait(&(lock)->raw_lock)
#define write_can_lock(rwlock)		__raw_write_can_lock(&(rwlock)->raw_lock)
#define write_lock(lock)		_write_lock(lock)
#define write_lock_bh(lock)		_write_lock_bh(lock)
#define write_lock_irq(lock)		_write_lock_irq(lock)
#define write_lock_irqsave(lock, flags)	flags = _write_lock_irqsave(lock)
#define write_trylock(lock)		__cond_lock(_write_trylock(lock))
# define write_unlock(lock)		_write_unlock(lock)
#define write_unlock_bh(lock)		_write_unlock_bh(lock)
# define write_unlock_irq(lock)		_write_unlock_irq(lock)
#define write_unlock_irqrestore(lock, flags) \
					_write_unlock_irqrestore(lock, flags)
#define DEFINE_RWLOCK(x)	rwlock_t x = RW_LOCK_UNLOCKED
#define DEFINE_SPINLOCK(x)	spinlock_t x = SPIN_LOCK_UNLOCKED
#define RW_LOCK_UNLOCKED \
	(rwlock_t)	{	.raw_lock = __RAW_RW_LOCK_UNLOCKED }
# define SPIN_LOCK_UNLOCKED \
	(spinlock_t)	{	.raw_lock = __RAW_SPIN_LOCK_UNLOCKED }


#define __stringify(x)		__stringify_1(x)
#define __stringify_1(x)	#x
#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define HIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#define NIP6(addr) \
	ntohs((addr).s6_addr16[0]), \
	ntohs((addr).s6_addr16[1]), \
	ntohs((addr).s6_addr16[2]), \
	ntohs((addr).s6_addr16[3]), \
	ntohs((addr).s6_addr16[4]), \
	ntohs((addr).s6_addr16[5]), \
	ntohs((addr).s6_addr16[6]), \
	ntohs((addr).s6_addr16[7])
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define __FUNCTION__ (__func__)
#define abs(x) ({				\
		int __x = (x);			\
		(__x < 0) ? -__x : __x;		\
	})
#define console_loglevel (console_printk[0])
#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})
#define default_console_loglevel (console_printk[3])
#define default_message_loglevel (console_printk[1])
#define labs(x) ({				\
		long __x = (x);			\
		(__x < 0) ? -__x : __x;		\
	})
#define max(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x > _y ? _x : _y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })
# define might_resched() cond_resched()
# define might_sleep() \
	do { __might_sleep("__FILE__", "__LINE__"); might_resched(); } while (0)
#define might_sleep_if(cond) do { if (unlikely(cond)) might_sleep(); } while (0)
#define min(x,y) ({ \
	typeof(x) _x = (x);	\
	typeof(y) _y = (y);	\
	(void) (&_x == &_y);		\
	_x < _y ? _x : _y; })
#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define minimum_console_loglevel (console_printk[2])
#define pr_debug(fmt,arg...) \
	printk(KERN_DEBUG fmt,##arg)
#define pr_info(fmt,arg...) \
	printk(KERN_INFO fmt,##arg)
#define randomize_va_space 1
#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})

# define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })

# define __acquire(x)	__context__(1)
# define __acquires(x)	__attribute__((context(0,1)))
#define __always_inline inline
# define __builtin_warning(x, y...) (1)
# define __chk_io_ptr(x) (void)0
# define __chk_user_ptr(x) (void)0
# define __cond_lock(x)	((x) ? ({ __context__(1); 1; }) : 0)
#define __deprecated_for_modules __deprecated
# define __force
# define __iomem
# define __kernel

# define __nocast
# define __release(x)	__context__(-1)
# define __releases(x)	__attribute__((context(1,0)))
# define __safe
# define __user
# define barrier() __memory_barrier()
#define likely(x)	__builtin_expect(!!(x), 1)

#define unlikely(x)	__builtin_expect(!!(x), 0)
#define BITS_TO_LONGS(bits) \
	(((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]








#define __bitwise __bitwise__
#define __bitwise__ __attribute__((bitwise))
#define aligned_u64 unsigned long long __attribute__((aligned(8)))
#define pgoff_t unsigned long

#define NULL ((void *)0)

#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)

#define ALIGN_STR __ALIGN_STR
#define ATTRIB_NORET  __attribute__((noreturn))
#define CPP_ASMLINKAGE extern "C"
#define ENTRY(name) \
  .globl name; \
  ALIGN; \
  name:
#define FASTCALL(x)	x
#define KPROBE_ENTRY(name) \
  .section .kprobes.text, "ax"; \
  .globl name; \
  ALIGN; \
  name:
#define NORET_AND     noreturn,
#define NORET_TYPE    

#define asmlinkage CPP_ASMLINKAGE

# define prevent_tail_call(ret) do { } while (0)


# define add_preempt_count(val)	do { preempt_count() += (val); } while (0)
#define dec_preempt_count() sub_preempt_count(1)
#define inc_preempt_count() add_preempt_count(1)
#define preempt_check_resched() \
do { \
	if (unlikely(test_thread_flag(TIF_NEED_RESCHED))) \
		preempt_schedule(); \
} while (0)
#define preempt_count()	(current_thread_info()->preempt_count)
#define preempt_disable() \
do { \
	inc_preempt_count(); \
	barrier(); \
} while (0)
#define preempt_enable() \
do { \
	preempt_enable_no_resched(); \
	preempt_check_resched(); \
} while (0)
#define preempt_enable_no_resched() \
do { \
	barrier(); \
	dec_preempt_count(); \
} while (0)
# define sub_preempt_count(val)	do { preempt_count() -= (val); } while (0)
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define HLIST_HEAD_INIT { .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
#define INIT_HLIST_NODE(ptr) ((ptr)->next = NULL, (ptr)->pprev = NULL)
#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)
#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

#define __list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)
#define __list_for_each_rcu(pos, head) \
	for (pos = (head)->next; \
		rcu_dereference(pos) != (head); \
        	pos = pos->next)
#define hlist_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos && ({ prefetch(pos->next); 1; }); \
	     pos = pos->next)
#define hlist_for_each_entry(tpos, pos, head, member)			 \
	for (pos = (head)->first;					 \
	     pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_for_each_entry_continue(tpos, pos, member)		 \
	for (pos = (pos)->next;						 \
	     pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_for_each_entry_from(tpos, pos, member)			 \
	for (; pos && ({ prefetch(pos->next); 1;}) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_for_each_entry_rcu(tpos, pos, head, member)		 \
	for (pos = (head)->first;					 \
	     rcu_dereference(pos) && ({ prefetch(pos->next); 1;}) &&	 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_for_each_entry_safe(tpos, pos, n, head, member) 		 \
	for (pos = (head)->first;					 \
	     pos && ({ n = pos->next; 1; }) && 				 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)
#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)
#define list_for_each(pos, head) \
	for (pos = (head)->next; prefetch(pos->next), pos != (head); \
        	pos = pos->next)
#define list_for_each_continue_rcu(pos, head) \
	for ((pos) = (pos)->next; \
		prefetch(rcu_dereference((pos))->next), (pos) != (head); \
        	(pos) = (pos)->next)
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_entry(pos->member.next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_rcu(pos, head, member) \
	for (pos = list_entry((head)->next, typeof(*pos), member); \
		prefetch(rcu_dereference(pos)->member.next), \
			&pos->member != (head); \
		pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, typeof(*pos), member);	\
	     prefetch(pos->member.prev), &pos->member != (head); 	\
	     pos = list_entry(pos->member.prev, typeof(*pos), member))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#define list_for_each_entry_safe_continue(pos, n, head, member) 		\
	for (pos = list_entry(pos->member.next, typeof(*pos), member), 		\
		n = list_entry(pos->member.next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; prefetch(pos->prev), pos != (head); \
        	pos = pos->prev)
#define list_for_each_rcu(pos, head) \
	for (pos = (head)->next; \
		prefetch(rcu_dereference(pos)->next), pos != (head); \
        	pos = pos->next)
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
#define list_for_each_safe_rcu(pos, n, head) \
	for (pos = (head)->next; \
		n = rcu_dereference(pos)->next, pos != (head); \
		pos = n)
#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))
#define PREFETCH_STRIDE (4*L1_CACHE_BYTES)

#define spin_lock_prefetch(x) prefetchw(x)
#define RWSEM_DEBUG 0


#define DECLARE_RWSEM(name) \
	struct rw_semaphore name = __RWSEM_INITIALIZER(name)

#define __RWSEM_DEBUG_INIT      , 0
#define __RWSEM_INITIALIZER(name) \
{ 0, SPIN_LOCK_UNLOCKED, LIST_HEAD_INIT((name).wait_list) __RWSEM_DEBUG_INIT }
#define NFS_CALL(op, inode, args)	NFS_PROTO(inode)->op args


#define FOREACH_ACL_ENTRY(pa, acl, pe) \
	for(pa=(acl)->a_entries, pe=pa+(acl)->a_count; pa<pe; pa++)

#define CACHE(x) \
		if (size <= x) \
			goto found; \
		else \
			i++;

#define __cpuexit __exit


#define __cpuinitdata __initdata
#define __define_initcall(level,fn) \
	static initcall_t __initcall_##fn __attribute_used__ \
	__attribute__((__section__(".initcall" level ".init"))) = fn
#define __devexit __exit
#define __devexit_p(x) x
#define __devexitdata __exitdata
#define __devinit __init
#define __devinitdata __initdata
#define __exit_p(x) x
#define __exitcall(fn) \
	static exitcall_t __exitcall_##fn __exit_call = fn
#define __init_or_module __init
#define __initcall(fn) device_initcall(fn)
#define __initdata_or_module __initdata
#define __nosavedata __attribute__ ((__section__ (".data.nosave")))
#define __obsolete_setup(str)					\
	__setup_null_param(str, "__LINE__")
#define __setup(str, fn)					\
	__setup_param(str, fn, fn, 0)
#define __setup_null_param(str, unique_id)			\
	__setup_param(str, unique_id, NULL, 0)
#define __setup_param(str, unique_id, fn, early)			\
	static char __setup_str_##unique_id[] __initdata = str;	\
	static struct obs_kernel_param __setup_##unique_id	\
		__attribute_used__				\
		__attribute__((__section__(".init.setup")))	\
		__attribute__((aligned((sizeof(long)))))	\
		= { __setup_str_##unique_id, fn, early }
#define arch_initcall(fn)		module_init(fn)
#define console_initcall(fn) \
	static initcall_t __initcall_##fn \
	__attribute_used__ __attribute__((__section__(".con_initcall.init")))=fn
#define core_initcall(fn)		module_init(fn)
#define device_initcall(fn)		module_init(fn)
#define early_param(str, fn)					\
	__setup_param(str, fn, fn, 1)
#define fs_initcall(fn)			module_init(fn)
#define late_initcall(fn)		module_init(fn)
#define module_exit(x)	__exitcall(x);
#define module_init(x)	__initcall(x);
#define postcore_initcall(fn)		module_init(fn)
#define security_initcall(fn) \
	static initcall_t __initcall_##fn \
	__attribute_used__ __attribute__((__section__(".security_initcall.init"))) = fn
#define subsys_initcall(fn)		module_init(fn)
#define GFP_LEVEL_MASK (__GFP_WAIT|__GFP_HIGH|__GFP_IO|__GFP_FS| \
			__GFP_COLD|__GFP_NOWARN|__GFP_REPEAT| \
			__GFP_NOFAIL|__GFP_NORETRY|__GFP_NO_GROW|__GFP_COMP| \
			__GFP_NOMEMALLOC|__GFP_NORECLAIM|__GFP_HARDWALL)
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
#define __GFP_BITS_SHIFT 20	
#define __GFP_HARDWALL   ((__force gfp_t)0x40000u) 
#define __GFP_NOMEMALLOC ((__force gfp_t)0x10000u) 
#define __GFP_NORECLAIM  ((__force gfp_t)0x20000u) 

#define __free_page(page) __free_pages((page), 0)
#define __get_dma_pages(gfp_mask, order) \
		__get_free_pages((gfp_mask) | GFP_DMA,(order))
#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask),0)
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)
#define alloc_page_vma(gfp_mask, vma, addr) alloc_pages(gfp_mask, 0)
#define alloc_pages(gfp_mask, order) \
		alloc_pages_node(numa_node_id(), gfp_mask, order)
#define free_page(addr) free_pages((addr),0)
#define gfp_zone(mask) ((__force int)((mask) & (__force gfp_t)GFP_ZONEMASK))
#define DEF_PRIORITY 12
#define MAX_ORDER 11
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map
#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define ZONE_PADDING(name)	struct zone_padding name;

#define early_pfn_in_nid(pfn, nid)	(early_pfn_to_nid(pfn) == (nid))
#define early_pfn_to_nid(nid)  (0UL)
#define early_pfn_valid(pfn)	pfn_valid(pfn)
#define for_each_pgdat(pgdat) \
	for (pgdat = pgdat_list; pgdat; pgdat = pgdat->pgdat_next)
#define for_each_zone(zone) \
	for (zone = pgdat_list->node_zones; zone; zone = next_zone(zone))
#define kvaddr_to_nid(kaddr)	pfn_to_nid(__pa(kaddr) >> PAGE_SHIFT)
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))
#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#define numa_node_id()		(cpu_to_node(raw_smp_processor_id()))
#define page_to_pfn(page)						\
({									\
	page - __section_mem_map_addr(__nr_to_section(			\
		page_to_section(page)));				\
})
#define pfn_to_nid(pfn)		(0)
#define pfn_to_page(pfn) 						\
({ 									\
	unsigned long __pfn = (pfn);					\
	__section_mem_map_addr(__pfn_to_section(__pfn)) + __pfn;	\
})
#define pfn_to_pgdat(pfn)						\
({									\
	NODE_DATA(pfn_to_nid(pfn));					\
})
#define pfn_to_section_nr(pfn) ((pfn) >> PFN_SECTION_SHIFT)
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#define section_nr_to_pfn(sec) ((sec) << PFN_SECTION_SHIFT)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define sparse_init()	do {} while (0)
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)
#define zone_pcp(__z, __cpu) ((__z)->pageset[(__cpu)])

#define SD_ALLNODES_INIT (struct sched_domain) {	\
	.span			= CPU_MASK_NONE,	\
	.parent			= NULL,			\
	.groups			= NULL,			\
	.min_interval		= 64,			\
	.max_interval		= 64*num_online_cpus(),	\
	.busy_factor		= 128,			\
	.imbalance_pct		= 133,			\
	.cache_hot_time		= (10*1000000),		\
	.cache_nice_tries	= 1,			\
	.busy_idx		= 3,			\
	.idle_idx		= 3,			\
	.newidle_idx		= 0, 	\
	.wake_idx		= 0, 	\
	.forkexec_idx		= 0, 	\
	.per_cpu_gain		= 100,			\
	.flags			= SD_LOAD_BALANCE,	\
	.last_balance		= jiffies,		\
	.balance_interval	= 64,			\
	.nr_balance_failed	= 0,			\
}
#define SD_CPU_INIT (struct sched_domain) {		\
	.span			= CPU_MASK_NONE,	\
	.parent			= NULL,			\
	.groups			= NULL,			\
	.min_interval		= 1,			\
	.max_interval		= 4,			\
	.busy_factor		= 64,			\
	.imbalance_pct		= 125,			\
	.cache_hot_time		= (5*1000000/2),	\
	.cache_nice_tries	= 1,			\
	.per_cpu_gain		= 100,			\
	.busy_idx		= 2,			\
	.idle_idx		= 1,			\
	.newidle_idx		= 2,			\
	.wake_idx		= 1,			\
	.forkexec_idx		= 1,			\
	.flags			= SD_LOAD_BALANCE	\
				| SD_BALANCE_NEWIDLE	\
				| SD_BALANCE_EXEC	\
				| SD_WAKE_AFFINE,	\
	.last_balance		= jiffies,		\
	.balance_interval	= 1,			\
	.nr_balance_failed	= 0,			\
}
#define SD_SIBLING_INIT (struct sched_domain) {		\
	.span			= CPU_MASK_NONE,	\
	.parent			= NULL,			\
	.groups			= NULL,			\
	.min_interval		= 1,			\
	.max_interval		= 2,			\
	.busy_factor		= 8,			\
	.imbalance_pct		= 110,			\
	.cache_hot_time		= 0,			\
	.cache_nice_tries	= 0,			\
	.per_cpu_gain		= 25,			\
	.busy_idx		= 0,			\
	.idle_idx		= 0,			\
	.newidle_idx		= 1,			\
	.wake_idx		= 0,			\
	.forkexec_idx		= 0,			\
	.flags			= SD_LOAD_BALANCE	\
				| SD_BALANCE_NEWIDLE	\
				| SD_BALANCE_EXEC	\
				| SD_WAKE_AFFINE	\
				| SD_WAKE_IDLE		\
				| SD_SHARE_CPUPOWER,	\
	.last_balance		= jiffies,		\
	.balance_interval	= 1,			\
	.nr_balance_failed	= 0,			\
}

#define for_each_node_with_cpus(node)						\
	for_each_online_node(node)						\
		if (nr_cpus_node(node))
#define node_distance(from,to)	((from) == (to) ? LOCAL_DISTANCE : REMOTE_DISTANCE)
#define node_has_online_mem(nid) (1)
#define nr_cpus_node(node)							\
	({									\
		cpumask_t __tmp__;						\
		__tmp__ = node_to_cpumask(node);				\
		cpus_weight(__tmp__);						\
	})
#define MSG_CALL_FUNCTION       0x0004  

#define get_cpu()		({ preempt_disable(); smp_processor_id(); })
#define hard_smp_processor_id()			0
#define num_booting_cpus()			1
#define on_each_cpu(func,info,retry,wait)	({ func(info); 0; })
#define put_cpu()		preempt_enable()
#define put_cpu_no_resched()	preempt_enable_no_resched()
#define raw_smp_processor_id()			0
#define smp_call_function(func,info,retry,wait)	({ 0; })
#define smp_prepare_boot_cpu()			do {} while (0)
# define smp_processor_id() debug_smp_processor_id()
#define CPU_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(NR_CPUS)

#define any_online_cpu(mask)			\
({						\
	int cpu;				\
	for_each_cpu_mask(cpu, (mask))		\
		if (cpu_online(cpu))		\
			break;			\
	cpu;					\
})
#define cpu_clear(cpu, dst) __cpu_clear((cpu), &(dst))
#define cpu_isset(cpu, cpumask) test_bit((cpu), (cpumask).bits)
#define cpu_online(cpu)		cpu_isset((cpu), cpu_online_map)
#define cpu_possible(cpu)	cpu_isset((cpu), cpu_possible_map)
#define cpu_present(cpu)	cpu_isset((cpu), cpu_present_map)
#define cpu_remap(oldbit, old, new) \
		__cpu_remap((oldbit), &(old), &(new), NR_CPUS)
#define cpu_set(cpu, dst) __cpu_set((cpu), &(dst))
#define cpu_test_and_set(cpu, cpumask) __cpu_test_and_set((cpu), &(cpumask))
#define cpulist_parse(buf, dst) __cpulist_parse((buf), &(dst), NR_CPUS)
#define cpulist_scnprintf(buf, len, src) \
			__cpulist_scnprintf((buf), (len), &(src), NR_CPUS)
#define cpumask_of_cpu(cpu)						\
({									\
	typeof(_unused_cpumask_arg_) m;					\
	if (sizeof(m) == sizeof(unsigned long)) {			\
		m.bits[0] = 1UL<<(cpu);					\
	} else {							\
		cpus_clear(m);						\
		cpu_set((cpu), m);					\
	}								\
	m;								\
})
#define cpumask_parse(ubuf, ulen, dst) \
			__cpumask_parse((ubuf), (ulen), &(dst), NR_CPUS)
#define cpumask_scnprintf(buf, len, src) \
			__cpumask_scnprintf((buf), (len), &(src), NR_CPUS)
#define cpus_addr(src) ((src).bits)
#define cpus_and(dst, src1, src2) __cpus_and(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_andnot(dst, src1, src2) \
				__cpus_andnot(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_clear(dst) __cpus_clear(&(dst), NR_CPUS)
#define cpus_complement(dst, src) __cpus_complement(&(dst), &(src), NR_CPUS)
#define cpus_empty(src) __cpus_empty(&(src), NR_CPUS)
#define cpus_equal(src1, src2) __cpus_equal(&(src1), &(src2), NR_CPUS)
#define cpus_full(cpumask) __cpus_full(&(cpumask), NR_CPUS)
#define cpus_intersects(src1, src2) __cpus_intersects(&(src1), &(src2), NR_CPUS)
#define cpus_or(dst, src1, src2) __cpus_or(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_remap(dst, src, old, new) \
		__cpus_remap(&(dst), &(src), &(old), &(new), NR_CPUS)
#define cpus_setall(dst) __cpus_setall(&(dst), NR_CPUS)
#define cpus_shift_left(dst, src, n) \
			__cpus_shift_left(&(dst), &(src), (n), NR_CPUS)
#define cpus_shift_right(dst, src, n) \
			__cpus_shift_right(&(dst), &(src), (n), NR_CPUS)
#define cpus_subset(src1, src2) __cpus_subset(&(src1), &(src2), NR_CPUS)
#define cpus_weight(cpumask) __cpus_weight(&(cpumask), NR_CPUS)
#define cpus_xor(dst, src1, src2) __cpus_xor(&(dst), &(src1), &(src2), NR_CPUS)
#define first_cpu(src) __first_cpu(&(src), NR_CPUS)
#define for_each_cpu(cpu)	  for_each_cpu_mask((cpu), cpu_possible_map)
#define for_each_cpu_mask(cpu, mask)		\
	for ((cpu) = first_cpu(mask);		\
		(cpu) < NR_CPUS;		\
		(cpu) = next_cpu((cpu), (mask)))
#define for_each_online_cpu(cpu)  for_each_cpu_mask((cpu), cpu_online_map)
#define for_each_present_cpu(cpu) for_each_cpu_mask((cpu), cpu_present_map)
#define highest_possible_processor_id() \
({ \
	unsigned int cpu, highest = 0; \
	for_each_cpu_mask(cpu, cpu_possible_map) \
		highest = cpu; \
	highest; \
})
#define next_cpu(n, src) __next_cpu((n), &(src), NR_CPUS)
#define num_online_cpus()	cpus_weight(cpu_online_map)
#define num_possible_cpus()	cpus_weight(cpu_possible_map)
#define num_present_cpus()	cpus_weight(cpu_present_map)
#define BITMAP_LAST_WORD_MASK(nbits)					\
(									\
	((nbits) % BITS_PER_LONG) ?					\
		(1UL<<((nbits) % BITS_PER_LONG))-1 : ~0UL		\
)


#define MIN_THREADS_LEFT_FOR_ROOT 4
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))


#define NETDEV_REGISTER 0x0005

#define ERESTART_RESTARTBLOCK 516 

#define SEQCNT_ZERO { 0 }
#define SEQLOCK_UNLOCKED { 0, SPIN_LOCK_UNLOCKED }

#define read_seqbegin_irqsave(lock, flags)				\
	({ local_irq_save(flags);   read_seqbegin(lock); })
#define read_seqretry_irqrestore(lock, iv, flags)			\
	({								\
		int ret = read_seqretry(lock, iv);			\
		local_irq_restore(flags);				\
		ret;							\
	})
#define seqcount_init(x)	do { *(x) = (seqcount_t) SEQCNT_ZERO; } while (0)
#define seqlock_init(x)	do { *(x) = (seqlock_t) SEQLOCK_UNLOCKED; } while (0)
#define write_seqlock_bh(lock)						\
        do { local_bh_disable();    write_seqlock(lock); } while (0)
#define write_seqlock_irq(lock)						\
	do { local_irq_disable();   write_seqlock(lock); } while (0)
#define write_seqlock_irqsave(lock, flags)				\
	do { local_irq_save(flags); write_seqlock(lock); } while (0)
#define write_sequnlock_bh(lock)					\
	do { write_sequnlock(lock); local_bh_enable(); } while(0)
#define write_sequnlock_irq(lock)					\
	do { write_sequnlock(lock); local_irq_enable(); } while(0)
#define write_sequnlock_irqrestore(lock, flags)				\
	do { write_sequnlock(lock); local_irq_restore(flags); } while(0)
#define MAX_NUMNODES    (1 << NODES_SHIFT)
#define NODES_SHIFT     0

#define L1_CACHE_ALIGN(x) ALIGN(x, L1_CACHE_BYTES)
#define SMP_CACHE_BYTES L1_CACHE_BYTES

#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#define ____cacheline_maxaligned_in_smp \
	__attribute__((__aligned__(1 << (L1_CACHE_SHIFT_MAX))))
#define __cacheline_aligned_in_smp __cacheline_aligned
#define __read_mostly __attribute__((__section__(".data.read_mostly")))

#define XDR_QUADLEN(l)		(((l) + 3) >> 2)


#define RPC_ASSASSINATED(t)	((t)->tk_flags & RPC_TASK_KILLED)
#define RPC_DO_CALLBACK(t)	((t)->tk_callback != NULL)
#define RPC_DO_ROOTOVERRIDE(t)	((t)->tk_flags & RPC_TASK_ROOTCREDS)
#define RPC_IS_ACTIVATED(t)	((t)->tk_active)
#define RPC_IS_ASYNC(t)		((t)->tk_flags & RPC_TASK_ASYNC)
#define RPC_IS_CHILD(t)		((t)->tk_flags & RPC_TASK_CHILD)
#define RPC_IS_PRIORITY(q)		((q)->maxpriority > 0)
#define RPC_IS_QUEUED(t)	(test_bit(RPC_TASK_QUEUED, &(t)->tk_runstate))
#define RPC_IS_RUNNING(t)	(test_bit(RPC_TASK_RUNNING, &(t)->tk_runstate))
#define RPC_IS_SOFT(t)		((t)->tk_flags & RPC_TASK_SOFT)
#define RPC_IS_SWAPPER(t)	((t)->tk_flags & RPC_TASK_SWAPPER)
#define RPC_TASK_UNINTERRUPTIBLE(t) ((t)->tk_flags & RPC_TASK_NOINTR)
# define RPC_WAITQ(var,qname)      struct rpc_wait_queue var = RPC_WAITQ_INIT(var,qname)
# define RPC_WAITQ_INIT(var,qname) { \
		.lock = SPIN_LOCK_UNLOCKED, \
		.tasks = { \
			[0] = LIST_HEAD_INIT(var.tasks[0]), \
			[1] = LIST_HEAD_INIT(var.tasks[1]), \
			[2] = LIST_HEAD_INIT(var.tasks[2]), \
		}, \
	}

#define rpc_clear_queued(t)	\
	do { \
		smp_mb__before_clear_bit(); \
		clear_bit(RPC_TASK_QUEUED, &(t)->tk_runstate); \
		smp_mb__after_clear_bit(); \
	} while (0)
#define rpc_clear_running(t)	\
	do { \
		smp_mb__before_clear_bit(); \
		clear_bit(RPC_TASK_RUNNING, &(t)->tk_runstate); \
		smp_mb__after_clear_bit(); \
	} while (0)
#define rpc_finish_wakeup(t) \
	do { \
		smp_mb__before_clear_bit(); \
		clear_bit(RPC_TASK_WAKEUP, &(t)->tk_runstate); \
		smp_mb__after_clear_bit(); \
	} while (0)
#define rpc_set_queued(t)	(set_bit(RPC_TASK_QUEUED, &(t)->tk_runstate))
#define rpc_set_running(t)	(set_bit(RPC_TASK_RUNNING, &(t)->tk_runstate))
#define rpc_start_wakeup(t) \
	(test_and_set_bit(RPC_TASK_WAKEUP, &(t)->tk_runstate) == 0)
#define rpc_test_and_set_running(t) \
				(test_and_set_bit(RPC_TASK_RUNNING, &(t)->tk_runstate))
#define DECLARE_WORK(n, f, d)					\
	struct work_struct n = __WORK_INITIALIZER(n, f, d)
#define INIT_WORK(_work, _func, _data)				\
	do {							\
		INIT_LIST_HEAD(&(_work)->entry);		\
		(_work)->pending = 0;				\
		PREPARE_WORK((_work), (_func), (_data));	\
		init_timer(&(_work)->timer);			\
	} while (0)
#define PREPARE_WORK(_work, _func, _data)			\
	do {							\
		(_work)->func = _func;				\
		(_work)->data = _data;				\
	} while (0)

#define __WORK_INITIALIZER(n, f, d) {				\
        .entry	= { &(n).entry, &(n).entry },			\
	.func = (f),						\
	.data = (d),						\
	.timer = TIMER_INITIALIZER(NULL, 0, 0),			\
	}
#define create_singlethread_workqueue(name) __create_workqueue((name), 1)
#define create_workqueue(name) __create_workqueue((name), 0)
#define DEFINE_TIMER(_name, _function, _expires, _data)		\
	struct timer_list _name =				\
		TIMER_INITIALIZER(_function, _expires, _data)
#define TIMER_INITIALIZER(_function, _expires, _data) {		\
		.function = (_function),			\
		.expires = (_expires),				\
		.data = (_data),				\
		.base = &__init_timer_base,			\
	}

#define del_singleshot_timer_sync(t) del_timer_sync(t)
# define del_timer_sync(t)		del_timer(t)
# define try_to_del_timer_sync(t)	del_timer(t)

#define signalled()		(signal_pending(current))
#define  RPC_DEBUG
# define RPC_IFDEBUG(x)		x

# define dfprintk(fac, args...)	do { ifdebug(fac) printk(args); } while(0)
#define dprintk(args...)	dfprintk(FACILITY, ## args)
# define pprintk(args...)	printk(## args)
#define BADCLASS(x)	(((x) & htonl(0xf0000000)) == htonl(0xf0000000))
#define GROUP_FILTER_SIZE(numsrc) \
	(sizeof(struct group_filter) - sizeof(struct __kernel_sockaddr_storage) \
	+ (numsrc) * sizeof(struct __kernel_sockaddr_storage))
#define INADDR_ALLHOSTS_GROUP 	0xe0000001U	
#define INADDR_ALLRTRS_GROUP    0xe0000002U	
#define INADDR_MAX_LOCAL_GROUP  0xe00000ffU	
#define INADDR_UNSPEC_GROUP   	0xe0000000U	
#define IP_DEFAULT_MULTICAST_LOOP       1
#define IP_DEFAULT_MULTICAST_TTL        1
#define IP_MSFILTER_SIZE(numsrc) \
	(sizeof(struct ip_msfilter) - sizeof(__u32) \
	+ (numsrc) * sizeof(__u32))
#define IP_MULTICAST_LOOP 		34
#define IP_MULTICAST_TTL 		33
#define LOCAL_MCAST(x)	(((x) & htonl(0xFFFFFF00)) == htonl(0xE0000000))
#define LOOPBACK(x)	(((x) & htonl(0xff000000)) == htonl(0x7f000000))
#define MULTICAST(x)	(((x) & htonl(0xf0000000)) == htonl(0xe0000000))
#define ZERONET(x)	(((x) & htonl(0xff000000)) == htonl(0x00000000))

#define CMSG_ALIGN(len) ( ((len)+sizeof(long)-1) & ~(sizeof(long)-1) )
#define CMSG_DATA(cmsg)	((void *)((char *)(cmsg) + CMSG_ALIGN(sizeof(struct cmsghdr))))
#define CMSG_FIRSTHDR(msg)	__CMSG_FIRSTHDR((msg)->msg_control, (msg)->msg_controllen)
#define CMSG_LEN(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#define CMSG_NXTHDR(mhdr, cmsg) cmsg_nxthdr((mhdr), (cmsg))
#define CMSG_OK(mhdr, cmsg) ((cmsg)->cmsg_len >= sizeof(struct cmsghdr) && \
			     (cmsg)->cmsg_len <= (unsigned long) \
			     ((mhdr)->msg_controllen - \
			      ((char *)(cmsg) - (char *)(mhdr)->msg_control)))
#define CMSG_SPACE(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(len))
#define MSG_EOF         MSG_FIN
#define MSG_EOR         0x80	
#define MSG_FIN         0x200
#define MSG_TRYHARD     4       
#define SCM_CREDENTIALS 0x02		
#define SOL_IRDA        266

#define __CMSG_FIRSTHDR(ctl,len) ((len) >= sizeof(struct cmsghdr) ? \
				  (struct cmsghdr *)(ctl) : \
				  (struct cmsghdr *)NULL)
#define __CMSG_NXTHDR(ctl, len, cmsg) __cmsg_nxthdr((ctl),(len),(cmsg))
#define __KINLINE static inline
#define sockaddr_storage __kernel_sockaddr_storage
#define SIOCBONDCHANGEACTIVE   0x8995   
#define SIOCBONDINFOQUERY      0x8994	
#define SIOCBONDRELEASE 0x8991		
#define SIOCBONDSETHWADDR      0x8992	
#define SIOCBONDSLAVEINFOQUERY 0x8993   
#define SIOCBRADDBR     0x89a0		
#define SIOCBRDELBR     0x89a1		
#define SIOCPROTOPRIVATE 0x89E0 

#define ACL4_SUPPORT_ALARM_ACL 0x08
#define ACL4_SUPPORT_ALLOW_ACL 0x01
#define ACL4_SUPPORT_AUDIT_ACL 0x04
#define ACL4_SUPPORT_DENY_ACL  0x02
#define FATTR4_WORD0_ACL                (1UL << 12)
#define FATTR4_WORD0_ACLSUPPORT         (1UL << 13)
#define FATTR4_WORD0_ARCHIVE            (1UL << 14)
#define FATTR4_WORD0_CANSETTIME         (1UL << 15)
#define FATTR4_WORD0_CASE_INSENSITIVE   (1UL << 16)
#define FATTR4_WORD0_CASE_PRESERVING    (1UL << 17)
#define FATTR4_WORD0_CHANGE             (1UL << 3)
#define FATTR4_WORD0_CHOWN_RESTRICTED   (1UL << 18)
#define FATTR4_WORD0_FH_EXPIRE_TYPE     (1UL << 2)
#define FATTR4_WORD0_FILEHANDLE         (1UL << 19)
#define FATTR4_WORD0_FILEID             (1UL << 20)
#define FATTR4_WORD0_FILES_AVAIL        (1UL << 21)
#define FATTR4_WORD0_FILES_FREE         (1UL << 22)
#define FATTR4_WORD0_FILES_TOTAL        (1UL << 23)
#define FATTR4_WORD0_FSID               (1UL << 8)
#define FATTR4_WORD0_FS_LOCATIONS       (1UL << 24)
#define FATTR4_WORD0_HIDDEN             (1UL << 25)
#define FATTR4_WORD0_HOMOGENEOUS        (1UL << 26)
#define FATTR4_WORD0_LEASE_TIME         (1UL << 10)
#define FATTR4_WORD0_LINK_SUPPORT       (1UL << 5)
#define FATTR4_WORD0_MAXFILESIZE        (1UL << 27)
#define FATTR4_WORD0_MAXLINK            (1UL << 28)
#define FATTR4_WORD0_MAXNAME            (1UL << 29)
#define FATTR4_WORD0_MAXREAD            (1UL << 30)
#define FATTR4_WORD0_MAXWRITE           (1UL << 31)
#define FATTR4_WORD0_NAMED_ATTR         (1UL << 7)
#define FATTR4_WORD0_RDATTR_ERROR       (1UL << 11)
#define FATTR4_WORD0_SIZE               (1UL << 4)
#define FATTR4_WORD0_SUPPORTED_ATTRS    (1UL << 0)
#define FATTR4_WORD0_SYMLINK_SUPPORT    (1UL << 6)
#define FATTR4_WORD0_TYPE               (1UL << 1)
#define FATTR4_WORD0_UNIQUE_HANDLES     (1UL << 9)
#define FATTR4_WORD1_MIMETYPE           (1UL << 0)
#define FATTR4_WORD1_MODE               (1UL << 1)
#define FATTR4_WORD1_MOUNTED_ON_FILEID  (1UL << 23)
#define FATTR4_WORD1_NO_TRUNC           (1UL << 2)
#define FATTR4_WORD1_NUMLINKS           (1UL << 3)
#define FATTR4_WORD1_OWNER              (1UL << 4)
#define FATTR4_WORD1_OWNER_GROUP        (1UL << 5)
#define FATTR4_WORD1_QUOTA_HARD         (1UL << 6)
#define FATTR4_WORD1_QUOTA_SOFT         (1UL << 7)
#define FATTR4_WORD1_QUOTA_USED         (1UL << 8)
#define FATTR4_WORD1_RAWDEV             (1UL << 9)
#define FATTR4_WORD1_SPACE_AVAIL        (1UL << 10)
#define FATTR4_WORD1_SPACE_FREE         (1UL << 11)
#define FATTR4_WORD1_SPACE_TOTAL        (1UL << 12)
#define FATTR4_WORD1_SPACE_USED         (1UL << 13)
#define FATTR4_WORD1_SYSTEM             (1UL << 14)
#define FATTR4_WORD1_TIME_ACCESS        (1UL << 15)
#define FATTR4_WORD1_TIME_ACCESS_SET    (1UL << 16)
#define FATTR4_WORD1_TIME_BACKUP        (1UL << 17)
#define FATTR4_WORD1_TIME_CREATE        (1UL << 18)
#define FATTR4_WORD1_TIME_DELTA         (1UL << 19)
#define FATTR4_WORD1_TIME_METADATA      (1UL << 20)
#define FATTR4_WORD1_TIME_MODIFY        (1UL << 21)
#define FATTR4_WORD1_TIME_MODIFY_SET    (1UL << 22)
#define NFS4_ACCESS_DELETE      0x0010
#define NFS4_ACCESS_EXECUTE     0x0020
#define NFS4_ACCESS_EXTEND      0x0008
#define NFS4_ACCESS_LOOKUP      0x0002
#define NFS4_ACCESS_MODIFY      0x0004
#define NFS4_ACCESS_READ        0x0001
#define NFS4_ACE_ACCESS_ALLOWED_ACE_TYPE 0
#define NFS4_ACE_ACCESS_DENIED_ACE_TYPE  1
#define NFS4_ACE_ADD_FILE                     0x00000002
#define NFS4_ACE_ADD_SUBDIRECTORY             0x00000004
#define NFS4_ACE_APPEND_DATA                  0x00000004
#define NFS4_ACE_DELETE                       0x00010000
#define NFS4_ACE_DELETE_CHILD                 0x00000040
#define NFS4_ACE_DIRECTORY_INHERIT_ACE        0x00000002
#define NFS4_ACE_EVERYONE                     0x00000200
#define NFS4_ACE_EXECUTE                      0x00000020
#define NFS4_ACE_FAILED_ACCESS_ACE_FLAG       0x00000020
#define NFS4_ACE_FILE_INHERIT_ACE             0x00000001
#define NFS4_ACE_GENERIC_EXECUTE              0x001200A0
#define NFS4_ACE_GENERIC_READ                 0x00120081
#define NFS4_ACE_GENERIC_WRITE                0x00160106
#define NFS4_ACE_GROUP                        0x00000100
#define NFS4_ACE_IDENTIFIER_GROUP             0x00000040
#define NFS4_ACE_INHERIT_ONLY_ACE             0x00000008
#define NFS4_ACE_LIST_DIRECTORY               0x00000001
#define NFS4_ACE_MASK_ALL                     0x001F01FF
#define NFS4_ACE_NO_PROPAGATE_INHERIT_ACE     0x00000004
#define NFS4_ACE_OWNER                        0x00000080
#define NFS4_ACE_READ_ACL                     0x00020000
#define NFS4_ACE_READ_ATTRIBUTES              0x00000080
#define NFS4_ACE_READ_DATA                    0x00000001
#define NFS4_ACE_READ_NAMED_ATTRS             0x00000008
#define NFS4_ACE_SUCCESSFUL_ACCESS_ACE_FLAG   0x00000010
#define NFS4_ACE_SYNCHRONIZE                  0x00100000
#define NFS4_ACE_SYSTEM_ALARM_ACE_TYPE   3
#define NFS4_ACE_SYSTEM_AUDIT_ACE_TYPE   2
#define NFS4_ACE_WRITE_ACL                    0x00040000
#define NFS4_ACE_WRITE_ATTRIBUTES             0x00000100
#define NFS4_ACE_WRITE_DATA                   0x00000002
#define NFS4_ACE_WRITE_NAMED_ATTRS            0x00000010
#define NFS4_ACE_WRITE_OWNER                  0x00080000
#define NFS4_DEBUG 1
#define NFS4_MINOR_VERSION 0
#define NFS4_OPEN_RESULT_CONFIRM 0x0002
#define NFS4_OPEN_RESULT_LOCKTYPE_POSIX 0x0004
#define NFSPROC4_COMPOUND 1
#define NFSPROC4_NULL 0




#define RPC_VERSION 2

#define RPC_CONGESTED(clnt)	(RPCXPRT_CONGESTED((clnt)->cl_xprt))
#define RPC_PEERADDR(clnt)	(&(clnt)->cl_xprt->addr)



#define proc_net_rpc NULL
#define FIRST_PROCESS_ENTRY 256
#define PROC_SUPER_MAGIC 0x9fa0

#define proc_bus NULL
#define proc_net NULL
#define proc_net_create(name, mode, info)	({ (void)(mode), NULL; })
#define proc_net_fops_create(name, mode, fops)  ({ (void)(mode), NULL; })
#define proc_root_driver NULL
#define remove_proc_entry(name, parent) do {} while (0)
#define BLKBSZGET  _IOR(0x12,112,size_t)
#define BLKBSZSET  _IOW(0x12,113,size_t)
#define BLKFLSBUF  _IO(0x12,97)	
#define BLKFRAGET  _IO(0x12,101)
#define BLKFRASET  _IO(0x12,100)
#define BLKGETSIZE _IO(0x12,96)	
#define BLKGETSIZE64 _IOR(0x12,114,size_t)	
#define BLKRAGET   _IO(0x12,99)	
#define BLKRASET   _IO(0x12,98)	
#define BLKROGET   _IO(0x12,94)	
#define BLKROSET   _IO(0x12,93)	
#define BLKRRPART  _IO(0x12,95)	
#define BLKSECTGET _IO(0x12,103)
#define BLKSECTSET _IO(0x12,102)
#define BLKSSZGET  _IO(0x12,104)
#define BLOCK_SIZE (1<<BLOCK_SIZE_BITS)
#define BLOCK_SIZE_BITS 10
#define BMAP_IOCTL 1		
#define DEFINE_SIMPLE_ATTRIBUTE(__fops, __get, __set, __fmt)		\
static int __fops ## _open(struct inode *inode, struct file *file)	\
{									\
	__simple_attr_check_format(__fmt, 0ull);			\
	return simple_attr_open(inode, file, __get, __set, __fmt);	\
}									\
static struct file_operations __fops = {				\
	.owner	 = THIS_MODULE,						\
	.open	 = __fops ## _open,					\
	.release = simple_attr_close,					\
	.read	 = simple_attr_read,					\
	.write	 = simple_attr_write,					\
};
#define FASYNC_MAGIC 0x4601
#define FIGETBSZ   _IO(0x00,2)	
#define FLOCK_VERIFY_READ  1
#define FLOCK_VERIFY_WRITE 2
#define FMODE_READ 1
#define FMODE_WRITE 2
#define FS_BINARY_MOUNTDATA 2
#define FS_REQUIRES_DEV 1 
#define HAVE_COMPAT_IOCTL 1
#define HAVE_UNLOCKED_IOCTL 1
#define INR_OPEN 1024		
#define INT_LIMIT(x)	(~((x)1 << (sizeof(x)*8 - 1)))
#define IS_APPEND(inode)	((inode)->i_flags & S_APPEND)
#define IS_DEADDIR(inode)	((inode)->i_flags & S_DEAD)
#define IS_DIRSYNC(inode)	(__IS_FLG(inode, MS_SYNCHRONOUS|MS_DIRSYNC) || \
					((inode)->i_flags & (S_SYNC|S_DIRSYNC)))
#define IS_IMMUTABLE(inode)	((inode)->i_flags & S_IMMUTABLE)
#define IS_MANDLOCK(inode)	__IS_FLG(inode, MS_MANDLOCK)
#define IS_NOATIME(inode)	(__IS_FLG(inode, MS_NOATIME) || ((inode)->i_flags & S_NOATIME))
#define IS_NOCMTIME(inode)	((inode)->i_flags & S_NOCMTIME)
#define IS_NODIRATIME(inode)	__IS_FLG(inode, MS_NODIRATIME)
#define IS_NOQUOTA(inode)	((inode)->i_flags & S_NOQUOTA)
#define IS_POSIXACL(inode)	__IS_FLG(inode, MS_POSIXACL)
#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)
#define IS_RDONLY(inode) ((inode)->i_sb->s_flags & MS_RDONLY)
#define IS_SWAPFILE(inode)	((inode)->i_flags & S_SWAPFILE)
#define IS_SYNC(inode)		(__IS_FLG(inode, MS_SYNCHRONOUS) || \
					((inode)->i_flags & S_SYNC))
#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)
#define MANDATORY_LOCK(inode) \
	(IS_MANDLOCK(inode) && ((inode)->i_mode & (S_ISGID | S_IXGRP)) == S_ISGID)
#define MAX_LFS_FILESIZE 	0x7fffffffffffffffUL
#define MAY_APPEND 8
#define MAY_EXEC 1
#define MAY_READ 4
#define MAY_WRITE 2
#define MS_MGC_MSK 0xffff0000
#define MS_MGC_VAL 0xC0ED0000
#define NR_FILE  8192	
#define NR_OPEN (1024*1024)	
#define RA_FLAG_INCACHE 0x02	
#define RA_FLAG_MISS 0x01	
#define READ 0
#define READA 2		
#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - sizeof(struct simple_transaction_argresp))
#define SPECIAL 4	
#define SWRITE 3	
#define S_BIAS (1<<30)
#define WRITE 1

#define __IS_FLG(inode,flg) ((inode)->i_sb->s_flags & (flg))

#define __getname()	kmem_cache_alloc(names_cachep, SLAB_KERNEL)
#define __putname(name) kmem_cache_free(names_cachep, (void *)(name))
#define bio_data_dir(bio)	((bio)->bi_rw & 1)
#define bio_rw(bio)		((bio)->bi_rw & (RW_MASK | RWA_MASK))
#define file_count(x)	atomic_read(&(x)->f_count)
#define file_list_lock() spin_lock(&files_lock);
#define file_list_unlock() spin_unlock(&files_lock);
#define fops_get(fops) \
	(((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
#define fops_put(fops) \
	do { if (fops) module_put((fops)->owner); } while(0)
#define get_file(x)	rcuref_inc(&(x)->f_count)
#define i_size_ordered_init(inode) seqcount_init(&inode->i_size_seqcount)
#define putname(name)   __putname(name)
#define sb_entry(list)	list_entry((list), struct super_block, s_list)
#define special_file(m) (S_ISCHR(m)||S_ISBLK(m)||S_ISFIFO(m)||S_ISSOCK(m))
#define vfs_check_frozen(sb, level) \
	wait_event((sb)->s_wait_unfrozen, ((sb)->s_frozen < (level)))
#define IS_ERR_VALUE(x) unlikely((x) > (unsigned long)-1000L)

#define IS_GETLK(cmd)	(IS_GETLK32(cmd)  || IS_GETLK64(cmd))
#define IS_GETLK32(cmd)		((cmd) == F_GETLK)
#define IS_GETLK64(cmd)		((cmd) == F_GETLK64)
#define IS_SETLK(cmd)	(IS_SETLK32(cmd)  || IS_SETLK64(cmd))
#define IS_SETLK32(cmd)		((cmd) == F_SETLK)
#define IS_SETLK64(cmd)		((cmd) == F_SETLK64)
#define IS_SETLKW(cmd)	(IS_SETLKW32(cmd) || IS_SETLKW64(cmd))
#define IS_SETLKW32(cmd)	((cmd) == F_SETLKW)
#define IS_SETLKW64(cmd)	((cmd) == F_SETLKW64)

#define force_o_largefile() (BITS_PER_LONG != 32)

#define DQF_INFO_DIRTY (1 << DQF_INFO_DIRTY_B)	
#define DQF_INFO_DIRTY_B 16
#define DQF_MASK 0xffff		
#define DQUOT_DEL_ALLOC max(V1_DEL_ALLOC, V2_DEL_ALLOC)
#define DQUOT_DEL_REWRITE max(V1_DEL_REWRITE, V2_DEL_REWRITE)
#define DQUOT_INIT_ALLOC max(V1_INIT_ALLOC, V2_INIT_ALLOC)
#define DQUOT_INIT_REWRITE max(V1_INIT_REWRITE, V2_INIT_REWRITE)
#define GRPQUOTA  1		
#define INITQFNAMES { \
	"user",     \
	"group",    \
	"undefined", \
};
#define INIT_QUOTA_MODULE_NAMES {\
	{QFMT_VFS_OLD, "quota_v1",\
	{QFMT_VFS_V0, "quota_v2",\
	{0, NULL}}
#define MAXQUOTAS 2
#define NODQUOT (struct dquot *)NULL
#define NO_QUOTA          1
#define QCMD(cmd, type)  (((cmd) << SUBCMDSHIFT) | ((type) & SUBCMDMASK))
#define QUOTABLOCK_BITS 10
#define QUOTABLOCK_SIZE (1 << QUOTABLOCK_BITS)
#define QUOTA_OK          0
#define Q_GETFMT   0x800004	
#define Q_GETINFO  0x800005	
#define Q_GETQUOTA 0x800007	
#define Q_QUOTAOFF 0x800003	
#define Q_QUOTAON  0x800002	
#define Q_SETINFO  0x800006	
#define Q_SETQUOTA 0x800008	
#define Q_SYNC     0x800001	
#define SUBCMDMASK  0x00ff
#define SUBCMDSHIFT 8
#define USRQUOTA  0		

#define dquot_dirty(dquot) test_bit(DQ_MOD_B, &(dquot)->dq_flags)
#define info_any_dirty(info) (info_dirty(info) || info_any_dquot_dirty(info))
#define info_any_dquot_dirty(info) (!list_empty(&(info)->dqi_dirty_list))
#define info_dirty(info) test_bit(DQF_INFO_DIRTY_B, &(info)->dqi_flags)
#define kb2qb(x) ((x) >> (QUOTABLOCK_BITS-10))
#define qb2kb(x) ((x) << (QUOTABLOCK_BITS-10))
#define sb_any_quota_enabled(sb) (sb_has_quota_enabled(sb, USRQUOTA) | \
				  sb_has_quota_enabled(sb, GRPQUOTA))
#define sb_dqinfo(sb, type) (sb_dqopt(sb)->info+(type))
#define sb_dqopt(sb) (&(sb)->s_dquot)
#define sb_has_quota_enabled(sb, type) ((type)==USRQUOTA ? \
	(sb_dqopt(sb)->flags & DQUOT_USR_ENABLED) : (sb_dqopt(sb)->flags & DQUOT_GRP_ENABLED))
#define toqb(x) (((x) + QUOTABLOCK_SIZE - 1) >> QUOTABLOCK_BITS)
#define QFMT_VFS_V0 2
#define V2_DEL_ALLOC 0
#define V2_DEL_REWRITE 6
#define V2_INIT_ALLOC 4
#define V2_INIT_REWRITE 2

#define QFMT_VFS_OLD 1
#define V1_DEL_ALLOC 0
#define V1_DEL_REWRITE 2
#define V1_DQF_RSQUASH 1
#define V1_INIT_ALLOC 1
#define V1_INIT_REWRITE 1

#define FS_DQ_BHARD 	(1<<3)
#define FS_DQ_RTBTIMER 	(1<<8)
#define XQM_CMD(x)	(('X'<<8)+(x))	
#define XQM_COMMAND(x)	(((x) & (0xff<<8)) == ('X'<<8))	

#define CALC_LOAD(load,exp,n) \
	load *= exp; \
	load += n*(FIXED_1-exp); \
	load >>= FSHIFT;
#define GROUP_AT(gi, i) \
    ((gi)->blocks[(i)/NGROUPS_PER_BLOCK][(i)%NGROUPS_PER_BLOCK])
#define INIT_USER (&root_user)
#define PF_LESS_THROTTLE 0x00100000	
#define REMOVE_LINKS(p) do {					\
	if (thread_group_leader(p))				\
		list_del_init(&(p)->tasks);			\
	remove_parent(p);					\
	} while (0)
#define SEND_SIG_NOINFO ((struct siginfo *) 0)
#define SET_LINKS(p) do {					\
	if (thread_group_leader(p))				\
		list_add_tail(&(p)->tasks,&init_task.tasks);	\
	add_parent(p, (p)->parent);				\
	} while (0)
#define TASK_COMM_LEN 16

# define __ARCH_WANT_UNLOCKED_CTXSW
#define __set_current_state(state_value)			\
	do { current->state = (state_value); } while (0)
#define __set_task_state(tsk, state_value)		\
	do { (tsk)->state = (state_value); } while (0)
#define add_mm_counter(mm, member, value) atomic64_add(value, &(mm)->_##member)
#define add_parent(p, parent)	list_add_tail(&(p)->sibling,&(parent)->children)
#define clear_stopped_child_used_math(child) do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define clear_used_math() clear_stopped_child_used_math(current)
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition) \
	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
#define dec_mm_counter(mm, member) atomic64_dec(&(mm)->_##member)
#define delay_group_leader(p) \
		(thread_group_leader(p) && !thread_group_empty(p))
#define do_each_thread(g, t) \
	for (g = t = &init_task ; (g = t = next_task(g)) != &init_task ; ) do
#define find_task_by_pid(nr)	find_task_by_pid_type(PIDTYPE_PID, nr)
#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )
#define get_group_info(group_info) do { \
	atomic_inc(&(group_info)->usage); \
} while (0)
#define get_mm_counter(mm, member) ((unsigned long)atomic64_read(&(mm)->_##member))
#define get_mm_rss(mm)					\
	(get_mm_counter(mm, file_rss) + get_mm_counter(mm, anon_rss))
#define get_task_struct(tsk) do { atomic_inc(&(tsk)->usage); } while(0)
#define inc_mm_counter(mm, member) atomic64_inc(&(mm)->_##member)
# define need_lockbreak(lock) ((lock)->break_lock)
#define next_task(p)	list_entry((p)->tasks.next, struct task_struct, tasks)
#define prev_task(p)	list_entry((p)->tasks.prev, struct task_struct, tasks)
#define put_group_info(group_info) do { \
	if (atomic_dec_and_test(&(group_info)->usage)) \
		groups_free(group_info); \
} while (0)
#define put_task_struct(tsk) \
do { if (atomic_dec_and_test(&(tsk)->usage)) __put_task_struct(tsk); } while(0)
#define remove_parent(p)	list_del_init(&(p)->sibling)
#define rt_task(p)		(unlikely((p)->prio < MAX_RT_PRIO))
#define sched_exec()   {}
#define set_current_state(state_value)		\
	set_mb(current->state, (state_value))
#define set_mm_counter(mm, member, value) atomic64_set(&(mm)->_##member, value)
#define set_stopped_child_used_math(child) do { (child)->flags |= PF_USED_MATH; } while (0)
#define set_task_state(tsk, state_value)		\
	set_mb((tsk)->state, (state_value))
#define set_used_math() set_stopped_child_used_math(current)
#define thread_group_leader(p)	(p->pid == p->tgid)
#define tsk_used_math(p) ((p)->flags & PF_USED_MATH)
#define update_hiwater_rss(mm)	do {			\
	unsigned long _rss = get_mm_rss(mm);		\
	if ((mm)->hiwater_rss < _rss)			\
		(mm)->hiwater_rss = _rss;		\
} while (0)
#define update_hiwater_vm(mm)	do {			\
	if ((mm)->hiwater_vm < (mm)->total_vm)		\
		(mm)->hiwater_vm = (mm)->total_vm;	\
} while (0)
#define used_math() tsk_used_math(current)
#define wait_task_inactive(p)	do { } while (0)
#define while_each_thread(g, t) \
	while ((t = next_thread(t)) != g)

#define aio_ring_avail(info, ring)	(((ring)->head + (info)->nr - 1 - (ring)->tail) % (info)->nr)
#define get_ioctx(kioctx)	do { if (unlikely(atomic_read(&(kioctx)->users) <= 0)) BUG(); atomic_inc(&(kioctx)->users); } while (0)
#define in_aio() !is_sync_wait(current->io_wait)
#define init_sync_kiocb(x, filp)			\
	do {						\
		struct task_struct *tsk = current;	\
		(x)->ki_flags = 0;			\
		(x)->ki_users = 1;			\
		(x)->ki_key = KIOCB_SYNC_KEY;		\
		(x)->ki_filp = (filp);			\
		(x)->ki_ctx = &tsk->active_mm->default_kioctx;	\
		(x)->ki_cancel = NULL;			\
		(x)->ki_dtor = NULL;			\
		(x)->ki_obj.tsk = tsk;			\
		(x)->ki_user_data = 0;                  \
		init_wait((&(x)->ki_wait));             \
	} while (0)
#define io_wait_to_kiocb(wait) container_of(wait, struct kiocb, ki_wait)
#define is_retried_kiocb(iocb) ((iocb)->ki_retried > 1)
#define is_sync_kiocb(iocb)	((iocb)->ki_key == KIOCB_SYNC_KEY)
#define kiocbClearCancelled(iocb)	clear_bit(KIF_CANCELLED, &(iocb)->ki_flags)
#define kiocbClearKicked(iocb)	clear_bit(KIF_KICKED, &(iocb)->ki_flags)
#define kiocbClearLocked(iocb)	clear_bit(KIF_LOCKED, &(iocb)->ki_flags)
#define kiocbIsCancelled(iocb)	test_bit(KIF_CANCELLED, &(iocb)->ki_flags)
#define kiocbIsKicked(iocb)	test_bit(KIF_KICKED, &(iocb)->ki_flags)
#define kiocbIsLocked(iocb)	test_bit(KIF_LOCKED, &(iocb)->ki_flags)
#define kiocbSetCancelled(iocb)	set_bit(KIF_CANCELLED, &(iocb)->ki_flags)
#define kiocbSetKicked(iocb)	set_bit(KIF_KICKED, &(iocb)->ki_flags)
#define kiocbSetLocked(iocb)	set_bit(KIF_LOCKED, &(iocb)->ki_flags)
#define kiocbTryKick(iocb)	test_and_set_bit(KIF_KICKED, &(iocb)->ki_flags)
#define kiocbTryLock(iocb)	test_and_set_bit(KIF_LOCKED, &(iocb)->ki_flags)
#define put_ioctx(kioctx)	do { if (unlikely(atomic_dec_and_test(&(kioctx)->users))) __put_ioctx(kioctx); else if (unlikely(atomic_read(&(kioctx)->users) < 0)) BUG(); } while (0)
#define warn_if_async()							\
do {									\
	if (in_aio()) {							\
		printk(KERN_ERR "%s(%s:%d) called in async context!\n",	\
			__FUNCTION__, "__FILE__", "__LINE__");		\
		dump_stack();						\
	}								\
} while (0)
#define PADDED(x,y)	x, y


#define CLOCKS_MASK  (CLOCK_REALTIME | CLOCK_MONOTONIC | \
                     CLOCK_REALTIME_HR | CLOCK_MONOTONIC_HR)
#define CLOCKS_MONO (CLOCK_MONOTONIC & CLOCK_MONOTONIC_HR)
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_SGI_CYCLE 10
#define CURRENT_TIME (current_kernel_time())
#define CURRENT_TIME_SEC ((struct timespec) { xtime.tv_sec, 0 })
#define FD_CLR(fd,fdsetp)	__FD_CLR(fd,fdsetp)
#define FD_ISSET(fd,fdsetp)	__FD_ISSET(fd,fdsetp)
#define FD_SET(fd,fdsetp)	__FD_SET(fd,fdsetp)
#define FD_ZERO(fdsetp)		__FD_ZERO(fdsetp)
#define MAX_CLOCKS 16
#define MSEC_PER_SEC (1000L)
#define NSEC_PER_SEC (1000000000L)
#define NSEC_PER_USEC (1000L)
#define TIMER_ABSTIME 0x01
#define USEC_PER_SEC (1000000L)



#define AT_BASE   7	
#define AT_CLKTCK 17	
#define AT_EGID   14	
#define AT_ENTRY  9	
#define AT_EUID   12	
#define AT_EXECFD 2	
#define AT_FLAGS  8	
#define AT_GID    13	
#define AT_HWCAP  16    
#define AT_IGNORE 1	
#define AT_NOTELF 10	
#define AT_NULL   0	
#define AT_PAGESZ 6	
#define AT_PHDR   3	
#define AT_PHENT  4	
#define AT_PHNUM  5	
#define AT_PLATFORM 15  
#define AT_SECURE 23   
#define AT_UID    11	
#define AT_VECTOR_SIZE  42 

#define NR_SECCOMP_MODES 1

#define secure_computing(x) do { } while (0)
#define PERCPU_ENOUGH_ROOM 32768

#define alloc_percpu(type) \
	((type *)(__alloc_percpu(sizeof(type), __alignof__(type))))
#define get_cpu_var(var) (*({ preempt_disable(); &__get_cpu_var(var); }))
#define per_cpu_ptr(ptr, cpu)                   \
({                                              \
        struct percpu_data *__p = (struct percpu_data *)~(unsigned long)(ptr); \
        (__typeof__(ptr))__p->ptrs[(cpu)];	\
})
#define put_cpu_var(var) preempt_enable()

#define do_each_task_pid(who, type, task)				\
	if ((task = find_task_by_pid_type(type, who))) {		\
		prefetch((task)->pids[type].pid_list.next);		\
		do {
#define pid_task(elem, type) \
	list_entry(elem, struct task_struct, pids[type].pid_list)
#define while_each_task_pid(who, type, task)				\
		} while (task = pid_task((task)->pids[type].pid_list.next,\
						type),			\
			prefetch((task)->pids[type].pid_list.next),	\
			hlist_unhashed(&(task)->pids[type].pid_chain));	\
	}								\

#define COMPLETION_INITIALIZER(work) \
	{ 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }
#define DECLARE_COMPLETION(work) \
	struct completion work = COMPLETION_INITIALIZER(work)
#define INIT_COMPLETION(x)	((x).done = 0)

#define INIT_FS {				\
	.count		= ATOMIC_INIT(1),	\
	.lock		= RW_LOCK_UNLOCKED,	\
	.umask		= 0022, \
}

#define SECUREBITS_DEFAULT 0x00000000
#define SECURE_NOROOT            0
#define SECURE_NO_SETUID_FIXUP   2
#define _LINUX_SECUREBITS_H 1
#define issecure(X) ( (1 << (X+1)) & SECUREBITS_DEFAULT ? 	\
		      (1 << (X)) & SECUREBITS_DEFAULT :		\
		      (1 << (X)) & securebits )

#define _SIG_SET_BINOP(name, op)					\
static inline void name(sigset_t *r, const sigset_t *a, const sigset_t *b) \
{									\
	extern void _NSIG_WORDS_is_unsupported_size(void);		\
	unsigned long a0, a1, a2, a3, b0, b1, b2, b3;			\
									\
	switch (_NSIG_WORDS) {						\
	    case 4:							\
		a3 = a->sig[3]; a2 = a->sig[2];				\
		b3 = b->sig[3]; b2 = b->sig[2];				\
		r->sig[3] = op(a3, b3);					\
		r->sig[2] = op(a2, b2);					\
	    case 2:							\
		a1 = a->sig[1]; b1 = b->sig[1];				\
		r->sig[1] = op(a1, b1);					\
	    case 1:							\
		a0 = a->sig[0]; b0 = b->sig[0];				\
		r->sig[0] = op(a0, b0);					\
		break;							\
	    default:							\
		_NSIG_WORDS_is_unsupported_size();			\
	}								\
}
#define _SIG_SET_OP(name, op)						\
static inline void name(sigset_t *set)					\
{									\
	extern void _NSIG_WORDS_is_unsupported_size(void);		\
									\
	switch (_NSIG_WORDS) {						\
	    case 4: set->sig[3] = op(set->sig[3]);			\
		    set->sig[2] = op(set->sig[2]);			\
	    case 2: set->sig[1] = op(set->sig[1]);			\
	    case 1: set->sig[0] = op(set->sig[0]);			\
		    break;						\
	    default:							\
		_NSIG_WORDS_is_unsupported_size();			\
	}								\
}
#define _sig_and(x,y)	((x) & (y))
#define _sig_nand(x,y)	((x) & ~(y))
#define _sig_not(x)	(~(x))
#define _sig_or(x,y)	((x) | (y))
#define sigmask(sig)	(1UL << ((sig) - 1))
#define GETALL  13       
#define GETNCNT 14       
#define GETPID  11       
#define GETVAL  12       
#define GETZCNT 15       
#define SEMAEM  SEMVMX          
#define SEMMAP  SEMMNS          
#define SEMMNI  128             
#define SEMMNS  (SEMMNI*SEMMSL) 
#define SEMMNU  SEMMNS          
#define SEMMSL  250             
#define SEMOPM  32	        
#define SEMUME  SEMOPM          
#define SEMUSZ  20		
#define SEMVMX  32767           
#define SEM_INFO 19
#define SEM_STAT 18
#define SEM_UNDO        0x1000  
#define SETALL  17       
#define SETVAL  16       

#define IPCMNI 32768  
#define IPC_64  0x0100  
#define IPC_CREAT  00001000   
#define IPC_DIPC 00010000  
#define IPC_EXCL   00002000   
#define IPC_INFO 3     
#define IPC_NOWAIT 00004000   
#define IPC_OLD 0	
#define IPC_OWN  00020000  
#define IPC_PRIVATE ((__kernel_key_t) 0)  
#define IPC_RMID 0     
#define IPC_SET  1     
#define IPC_STAT 2     

#define NODE_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(MAX_NUMNODES)

#define any_online_node(mask)			\
({						\
	int node;				\
	for_each_node_mask(node, (mask))	\
		if (node_online(node))		\
			break;			\
	node;					\
})
#define first_node(src) __first_node(&(src))
#define first_unset_node(mask) __first_unset_node(&(mask))
#define for_each_node(node)	   for_each_node_mask((node), node_possible_map)
#define for_each_node_mask(node, mask)			\
	for ((node) = first_node(mask);			\
		(node) < MAX_NUMNODES;			\
		(node) = next_node((node), (mask)))
#define for_each_online_node(node) for_each_node_mask((node), node_online_map)
#define next_node(n, src) __next_node((n), &(src))
#define node_clear(node, dst) __node_clear((node), &(dst))
#define node_isset(node, nodemask) test_bit((node), (nodemask).bits)
#define node_online(node)	node_isset((node), node_online_map)
#define node_possible(node)	node_isset((node), node_possible_map)
#define node_remap(oldbit, old, new) \
		__node_remap((oldbit), &(old), &(new), MAX_NUMNODES)
#define node_set(node, dst) __node_set((node), &(dst))
#define node_set_offline(node)	   clear_bit((node), node_online_map.bits)
#define node_set_online(node)	   set_bit((node), node_online_map.bits)
#define node_test_and_set(node, nodemask) \
			__node_test_and_set((node), &(nodemask))
#define nodelist_parse(buf, dst) __nodelist_parse((buf), &(dst), MAX_NUMNODES)
#define nodelist_scnprintf(buf, len, src) \
			__nodelist_scnprintf((buf), (len), &(src), MAX_NUMNODES)
#define nodemask_of_node(node)						\
({									\
	typeof(_unused_nodemask_arg_) m;				\
	if (sizeof(m) == sizeof(unsigned long)) {			\
		m.bits[0] = 1UL<<(node);				\
	} else {							\
		nodes_clear(m);						\
		node_set((node), m);					\
	}								\
	m;								\
})
#define nodemask_parse(ubuf, ulen, dst) \
			__nodemask_parse((ubuf), (ulen), &(dst), MAX_NUMNODES)
#define nodemask_scnprintf(buf, len, src) \
			__nodemask_scnprintf((buf), (len), &(src), MAX_NUMNODES)
#define nodes_addr(src) ((src).bits)
#define nodes_and(dst, src1, src2) \
			__nodes_and(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_andnot(dst, src1, src2) \
			__nodes_andnot(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_clear(dst) __nodes_clear(&(dst), MAX_NUMNODES)
#define nodes_complement(dst, src) \
			__nodes_complement(&(dst), &(src), MAX_NUMNODES)
#define nodes_empty(src) __nodes_empty(&(src), MAX_NUMNODES)
#define nodes_equal(src1, src2) \
			__nodes_equal(&(src1), &(src2), MAX_NUMNODES)
#define nodes_full(nodemask) __nodes_full(&(nodemask), MAX_NUMNODES)
#define nodes_intersects(src1, src2) \
			__nodes_intersects(&(src1), &(src2), MAX_NUMNODES)
#define nodes_or(dst, src1, src2) \
			__nodes_or(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define nodes_remap(dst, src, old, new) \
		__nodes_remap(&(dst), &(src), &(old), &(new), MAX_NUMNODES)
#define nodes_setall(dst) __nodes_setall(&(dst), MAX_NUMNODES)
#define nodes_shift_left(dst, src, n) \
			__nodes_shift_left(&(dst), &(src), (n), MAX_NUMNODES)
#define nodes_shift_right(dst, src, n) \
			__nodes_shift_right(&(dst), &(src), (n), MAX_NUMNODES)
#define nodes_subset(src1, src2) \
			__nodes_subset(&(src1), &(src2), MAX_NUMNODES)
#define nodes_weight(nodemask) __nodes_weight(&(nodemask), MAX_NUMNODES)
#define nodes_xor(dst, src1, src2) \
			__nodes_xor(&(dst), &(src1), &(src2), MAX_NUMNODES)
#define num_online_nodes()	nodes_weight(node_online_map)
#define num_possible_nodes()	nodes_weight(node_possible_map)
#define ACTHZ (SH_DIV (CLOCK_TICK_RATE, LATCH, 8))
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))
#define LATCH  ((CLOCK_TICK_RATE + HZ/2) / HZ)	
#define MAX_JIFFY_OFFSET ((~0UL >> 1)-1)
# define MAX_SEC_IN_JIFFIES \
	(long)((u64)((u64)MAX_JIFFY_OFFSET * TICK_NSEC) / NSEC_PER_SEC)
#define NSEC_CONVERSION ((unsigned long)((((u64)1 << NSEC_JIFFIE_SC) +\
                                        TICK_NSEC -1) / (u64)TICK_NSEC))
#define NSEC_JIFFIE_SC (SEC_JIFFIE_SC + 29)
#define SEC_CONVERSION ((unsigned long)((((u64)NSEC_PER_SEC << SEC_JIFFIE_SC) +\
                                TICK_NSEC -1) / (u64)TICK_NSEC))
#define SEC_JIFFIE_SC (31 - SHIFT_HZ)
#define SH_DIV(NOM,DEN,LSH) (   ((NOM / DEN) << LSH)                    \
                             + (((NOM % DEN) << LSH) + DEN / 2) / DEN)
#define TICK_NSEC (SH_DIV (1000000UL * 1000, ACTHZ, 8))
#define TICK_USEC ((1000000UL + USER_HZ/2) / USER_HZ)
#define TICK_USEC_TO_NSEC(TUSEC) (SH_DIV (TUSEC * USER_HZ * 1000, ACTHZ, 8))
#define USEC_CONVERSION  \
                    ((unsigned long)((((u64)NSEC_PER_USEC << USEC_JIFFIE_SC) +\
                                        TICK_NSEC -1) / (u64)TICK_NSEC))
#define USEC_JIFFIE_SC (SEC_JIFFIE_SC + 19)
#define USEC_ROUND (u64)(((u64)1 << USEC_JIFFIE_SC) - 1)

#define __jiffy_data  __attribute__((section(".data")))
#define div_long_long_rem(dividend,divisor,remainder) \
({							\
	u64 result = dividend;				\
	*remainder = do_div(result,divisor);		\
	result;						\
})
#define time_after(a,b)		\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(b) - (long)(a) < 0))
#define time_after_eq(a,b)	\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(a) - (long)(b) >= 0))
#define time_before(a,b)	time_after(b,a)
#define time_before_eq(a,b)	time_after_eq(b,a)
#define FINENSEC (1L << (SHIFT_SCALE - 10)) 
#define MAXFREQ (512L << SHIFT_USEC)  
#define MAXGLITCH 30		
#define MAXPHASE 512000L        
#define MAXSEC 1200L            
#define MAXTC 6			
#define MAXTIME (200L << PPS_AVG) 
#define MINSEC 16L              
#define PPS_AVG 2		
#define PPS_SHIFT 2		
#define PPS_SHIFTMAX 8		
#define PPS_VALID 120		
#define SHIFT_KF 16		
#define SHIFT_KG 6		
#define SHIFT_KH 2		
#define SHIFT_SCALE 22		
#define SHIFT_UPDATE (SHIFT_KG + MAXTC) 
#define SHIFT_USEC 16		
#define STA_RONLY (STA_PPSSIGNAL | STA_PPSJITTER | STA_PPSWANDER | \
    STA_PPSERROR | STA_CLOCKERR) 
#define TIME_SOURCE_CPU 0
#define TIME_SOURCE_FUNCTION 3
#define TIME_SOURCE_MMIO32 2
#define TIME_SOURCE_MMIO64 1

#define shift_right(x, s) ({	\
	__typeof__(x) __x = (x);	\
	__typeof__(s) __s = (s);	\
	__x < 0 ? -(-__x >> __s) : __x >> __s;	\
})
#define CAP_AUDIT_CONTROL    30
#define CAP_AUDIT_WRITE      29
#define CAP_CHOWN            0
#define CAP_DAC_OVERRIDE     1
#define CAP_DAC_READ_SEARCH  2
#define CAP_EMPTY_SET       to_cap_t(0)
#define CAP_FOWNER           3
#define CAP_FSETID           4
#define CAP_FS_MASK          0x1f
#define CAP_FULL_SET        to_cap_t(~0)
#define CAP_INIT_EFF_SET    to_cap_t(~0 & ~CAP_TO_MASK(CAP_SETPCAP))
#define CAP_INIT_INH_SET    to_cap_t(0)
#define CAP_IPC_LOCK         14
#define CAP_IPC_OWNER        15
#define CAP_KILL             5
#define CAP_LEASE            28
#define CAP_LINUX_IMMUTABLE  9
#define CAP_MKNOD            27
#define CAP_NET_ADMIN        12
#define CAP_NET_BIND_SERVICE 10
#define CAP_NET_BROADCAST    11
#define CAP_NET_RAW          13
#define CAP_SETGID           6
#define CAP_SETPCAP          8
#define CAP_SETUID           7
#define CAP_SYS_ADMIN        21
#define CAP_SYS_BOOT         22
#define CAP_SYS_CHROOT       18
#define CAP_SYS_MODULE       16
#define CAP_SYS_NICE         23
#define CAP_SYS_PACCT        20
#define CAP_SYS_PTRACE       19
#define CAP_SYS_RAWIO        17
#define CAP_SYS_RESOURCE     24
#define CAP_SYS_TIME         25
#define CAP_SYS_TTY_CONFIG   26
#define CAP_TO_MASK(x) (1 << (x))
#define _KERNEL_CAP_T_SIZE     (sizeof(kernel_cap_t))

#define _LINUX_CAPABILITY_VERSION  0x19980330
#define _USER_CAP_HEADER_SIZE  (2*sizeof(__u32))
#define cap_clear(c)         do { cap_t(c) =  0; } while(0)
#define cap_is_fs_cap(c)     (CAP_TO_MASK(c) & CAP_FS_MASK)
#define cap_isclear(c)       (!cap_t(c))
#define cap_issubset(a,set)  (!(cap_t(a) & ~cap_t(set)))
#define cap_lower(c, flag)   (cap_t(c) &= ~CAP_TO_MASK(flag))
#define cap_mask(c,mask)     do { cap_t(c) &= cap_t(mask); } while(0)
#define cap_raise(c, flag)   (cap_t(c) |=  CAP_TO_MASK(flag))
#define cap_raised(c, flag)  (cap_t(c) & CAP_TO_MASK(flag))
#define cap_set_full(c)      do { cap_t(c) = ~0; } while(0)
#define cap_t(x) (x).cap
#define to_cap_t(x) { x }
#define INIT_PRIO_TREE_ITER(ptr)	\
do {					\
	(ptr)->cur = NULL;		\
	(ptr)->mask = 0UL;		\
	(ptr)->value = 0UL;		\
	(ptr)->size_level = 0;		\
} while (0)
#define INIT_PRIO_TREE_NODE(ptr)				\
do {								\
	(ptr)->left = (ptr)->right = (ptr)->parent = (ptr);	\
} while (0)
#define INIT_PRIO_TREE_ROOT(ptr)	__INIT_PRIO_TREE_ROOT(ptr, 0)
#define INIT_RAW_PRIO_TREE_ROOT(ptr)	__INIT_PRIO_TREE_ROOT(ptr, 1)

#define __INIT_PRIO_TREE_ROOT(ptr, _raw)	\
do {					\
	(ptr)->prio_tree_node = NULL;	\
	(ptr)->index_bits = 1;		\
	(ptr)->raw = (_raw);		\
} while (0)
#define prio_tree_entry(ptr, type, member) \
       ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))
#define raw_prio_tree_insert(root, node) \
	prio_tree_insert(root, (struct prio_tree_node *) (node))
#define raw_prio_tree_remove(root, node) \
	prio_tree_remove(root, (struct prio_tree_node *) (node))
#define raw_prio_tree_replace(root, old, node) \
	prio_tree_replace(root, (struct prio_tree_node *) (old), \
	    (struct prio_tree_node *) (node))
#define INIT_RADIX_TREE(root, mask)					\
do {									\
	(root)->height = 0;						\
	(root)->gfp_mask = (mask);					\
	(root)->rnode = NULL;						\
} while (0)
#define RADIX_TREE(name, mask) \
	struct radix_tree_root name = RADIX_TREE_INIT(mask)
#define RADIX_TREE_INIT(mask)	{					\
	.height = 0,							\
	.gfp_mask = (mask),						\
	.rnode = NULL,							\
}


#define decl_subsys(_name,_type,_hotplug_ops) \
struct subsystem _name##_subsys = { \
	.kset = { \
		.kobj = { .name = __stringify(_name) }, \
		.ktype = _type, \
		.hotplug_ops =_hotplug_ops, \
	} \
}
#define decl_subsys_name(_varname,_name,_type,_hotplug_ops) \
struct subsystem _varname##_subsys = { \
	.kset = { \
		.kobj = { .name = __stringify(_name) }, \
		.ktype = _type, \
		.hotplug_ops =_hotplug_ops, \
	} \
}
#define kobj_set_kset_s(obj,subsys) \
	(obj)->kobj.kset = &(subsys).kset
#define kset_set_kset_s(obj,subsys) \
	(obj)->kset.kobj.kset = &(subsys).kset
#define set_kset_name(str)	.kset = { .kobj = { .name = str } }
#define subsys_set_kset(obj,_subsys) \
	(obj)->subsys.kset.kobj.kset = &(_subsys).kset


#define SYSFS_KOBJ_ATTR 	0x0004
#define SYSFS_KOBJ_LINK 	0x0020

#define __ATTR(_name,_mode,_show,_store) { \
	.attr = {.name = __stringify(_name), .mode = _mode, .owner = THIS_MODULE },	\
	.show	= _show,					\
	.store	= _store,					\
}
#define __ATTR_NULL { .attr = { .name = NULL } }
#define __ATTR_RO(_name) { \
	.attr	= { .name = __stringify(_name), .mode = 0444, .owner = THIS_MODULE },	\
	.show	= _name##_show,	\
}
#define attr_name(_attr) (_attr).attr.name
#define S_IFBLK  0060000
#define S_IFCHR  0020000
#define S_IFDIR  0040000
#define S_IFIFO  0010000
#define S_IFMT  00170000
#define S_IFREG  0100000
#define S_IFSOCK 0140000
#define S_IRGRP 00040
#define S_IROTH 00004
#define S_IRUSR 00400
#define S_IRWXG 00070
#define S_IRWXO 00007
#define S_IRWXU 00700
#define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#define S_ISGID  0002000
#define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)
#define S_ISUID  0004000
#define S_ISVTX  0001000
#define S_IWGRP 00020
#define S_IWOTH 00002
#define S_IWUSR 00200
#define S_IXGRP 00010
#define S_IXOTH 00001
#define S_IXUSR 00100

#define DCACHE_AUTOFS_PENDING 0x0001    
#define DCACHE_NFSFS_RENAMED  0x0002    
#define DNAME_INLINE_LEN_MIN 36
#define IS_ROOT(x) ((x) == (x)->d_parent)

#define init_name_hash()		0
#define INIT_RCU_HEAD(ptr) do { \
       (ptr)->next = NULL; (ptr)->func = NULL; \
} while (0)
#define RCU_HEAD(head) struct rcu_head head = RCU_HEAD_INIT
#define RCU_HEAD_INIT 	{ .next = NULL, .func = NULL }

#define rcu_assign_pointer(p, v)	({ \
						smp_wmb(); \
						(p) = (v); \
					})
#define rcu_dereference(p)     ({ \
				typeof(p) _________p1 = p; \
				smp_read_barrier_depends(); \
				(_________p1); \
				})
#define rcu_read_lock()		preempt_disable()
#define rcu_read_lock_bh()	local_bh_disable()
#define rcu_read_unlock()	preempt_enable()
#define rcu_read_unlock_bh()	local_bh_enable()
#define synchronize_sched() synchronize_rcu()
#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))
#define MKDEV(ma,mi)	(((ma) << MINORBITS) | (mi))

#define format_dev_t(buffer, dev)					\
	({								\
		sprintf(buffer, "%u:%u", MAJOR(dev), MINOR(dev));	\
		buffer;							\
	})
#define print_dev_t(buffer, dev)					\
	sprintf((buffer), "%u:%u\n", MAJOR(dev), MINOR(dev))
#define RCUREF_HASH(k) \
	(&__rcuref_hash[(((unsigned long)k)>>8) & (RCUREF_HASH_SIZE-1)])

#define DECLARE_TASKLET(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }
#define DECLARE_TASKLET_DISABLED(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }
#define IRQ_RETVAL(x)	((x) != 0)

#define __local_bh_enable() \
		do { barrier(); sub_preempt_count(SOFTIRQ_OFFSET); } while (0)
#define __raise_softirq_irqoff(nr) do { or_softirq_pending(1UL << (nr)); } while (0)
#define local_bh_disable() \
		do { add_preempt_count(SOFTIRQ_OFFSET); barrier(); } while (0)
#define or_softirq_pending(x)  (local_softirq_pending() |= (x))
#define save_and_cli(x)	save_and_cli(&x)
#define save_flags(x) save_flags(&x);
#define set_softirq_pending(x) (local_softirq_pending() = (x))
#define tasklet_trylock(t) 1
#define tasklet_unlock(t) do { } while (0)
#define tasklet_unlock_wait(t) do { } while (0)
# define IRQ_EXIT_OFFSET (HARDIRQ_OFFSET-1)

#define __IRQ_MASK(x)	((1UL << (x))-1)
#define hardirq_count()	(preempt_count() & HARDIRQ_MASK)
# define in_atomic()	((preempt_count() & ~PREEMPT_ACTIVE) != kernel_locked())
#define in_interrupt()		(irq_count())
#define in_irq()		(hardirq_count())
#define in_softirq()		(softirq_count())
#define irq_count()	(preempt_count() & (HARDIRQ_MASK | SOFTIRQ_MASK))
#define irq_enter()					\
	do {						\
		account_system_vtime(current);		\
		add_preempt_count(HARDIRQ_OFFSET);	\
	} while (0)
#define nmi_enter()		irq_enter()
#define nmi_exit()		sub_preempt_count(HARDIRQ_OFFSET)
# define preemptible()	(preempt_count() == 0 && !irqs_disabled())
#define softirq_count()	(preempt_count() & SOFTIRQ_MASK)
# define synchronize_irq(irq)	barrier()

#define kernel_locked()		(current->lock_depth >= 0)
#define lock_kernel()				do { } while(0)
#define reacquire_kernel_lock(task)		0
#define release_kernel_lock(tsk) do { 		\
	if (unlikely((tsk)->lock_depth >= 0))	\
		__release_kernel_lock();	\
} while (0)
# define return_value_on_smp return
#define unlock_kernel()				do { } while(0)

#define ARG_MAX       131072	
#define CHILD_MAX        999    
#define LINK_MAX         127	
#define MAX_CANON        255	
#define MAX_INPUT        255	
#define NAME_MAX         255	
#define NGROUPS_MAX    65536	
#define OPEN_MAX         256	
#define PATH_MAX        4096	
#define PIPE_BUF        4096	
#define XATTR_LIST_MAX 65536	
#define XATTR_NAME_MAX   255	
#define XATTR_SIZE_MAX 65536	

#define RPC_MAX_AUTH_SIZE (400)


#define BDI_CAP_VMFLAGS \
	(BDI_CAP_READ_MAP | BDI_CAP_WRITE_MAP | BDI_CAP_EXEC_MAP)

#define bdi_cap_account_dirty(bdi) \
	(!((bdi)->capabilities & BDI_CAP_NO_ACCT_DIRTY))
#define bdi_cap_writeback_dirty(bdi) \
	(!((bdi)->capabilities & BDI_CAP_NO_WRITEBACK))
#define mapping_cap_account_dirty(mapping) \
	bdi_cap_account_dirty((mapping)->backing_dev_info)
#define mapping_cap_writeback_dirty(mapping) \
	bdi_cap_writeback_dirty((mapping)->backing_dev_info)
#define PAGECACHE_ACCT_THRESHOLD        max(16, NR_CPUS * 2)
#define PAGE_CACHE_ALIGN(addr)	(((addr)+PAGE_CACHE_SIZE-1)&PAGE_CACHE_MASK)

#define page_cache_get(page)		get_page(page)
#define page_cache_release(page)	put_page(page)

#define kmap_atomic(page, idx)		page_address(page)
#define kmap_atomic_pfn(pfn, idx)	page_address(pfn_to_page(pfn))
#define kmap_atomic_to_page(ptr)	virt_to_page(ptr)
#define kunmap(page) do { (void) (page); } while (0)
#define kunmap_atomic(addr, idx)	do { } while (0)
#define DEFAULT_SEEKS 2

#define OOM_DISABLE -17
#define PFN_SECTION_SHIFT 0
#define VM_ClearReadHint(v)		(v)->vm_flags &= ~VM_READHINTMASK
#define VM_IO           0x00004000	
#define VM_MAX_CACHE_HIT    	256	
#define VM_NormalReadHint(v)		(!((v)->vm_flags & VM_READHINTMASK))
#define VM_RandomReadHint(v)		((v)->vm_flags & VM_RAND_READ)
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#define VM_SequentialReadHint(v)	((v)->vm_flags & VM_SEQ_READ)

#define __pte_lockptr(page)	&((page)->u.ptl)
#define __put_page(p)		atomic_dec(&(p)->_count)
#define get_page_testone(p)	atomic_inc_and_test(&(p)->_count)
#define in_gate_area(task, addr) ({(void)task; in_gate_area_no_task(addr);})
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
#define page_address(page) ((page)->virtual)
#define page_address_init()  do { } while(0)
#define page_count(p)		(atomic_read(&(p)->_count) + 1)
#define page_private(page)		((page)->u.private)
#define pte_alloc_kernel(pmd, address)			\
	((unlikely(!pmd_present(*(pmd))) && __pte_alloc_kernel(pmd, address))? \
		NULL: pte_offset_kernel(pmd, address))
#define pte_alloc_map(mm, pmd, address)			\
	((unlikely(!pmd_present(*(pmd))) && __pte_alloc(mm, pmd, address))? \
		NULL: pte_offset_map(pmd, address))
#define pte_alloc_map_lock(mm, pmd, address, ptlp)	\
	((unlikely(!pmd_present(*(pmd))) && __pte_alloc(mm, pmd, address))? \
		NULL: pte_offset_map_lock(mm, pmd, address, ptlp))
#define pte_lock_deinit(page)	((page)->mapping = NULL)
#define pte_lock_init(_page)	do {					\
	spin_lock_init(__pte_lockptr(_page));				\
} while (0)
#define pte_lockptr(mm, pmd)	({(void)(mm); __pte_lockptr(pmd_page(*(pmd)));})
#define pte_offset_map_lock(mm, pmd, address, ptlp)	\
({							\
	spinlock_t *__ptl = pte_lockptr(mm, pmd);	\
	pte_t *__pte = pte_offset_map(pmd, address);	\
	*(ptlp) = __ptl;				\
	spin_lock(__ptl);				\
	__pte;						\
})
#define pte_unmap_unlock(pte, ptl)	do {		\
	spin_unlock(ptl);				\
	pte_unmap(pte);					\
} while (0)
#define put_page_testzero(p)				\
	({						\
		BUG_ON(page_count(p) == 0);		\
		atomic_add_negative(-1, &(p)->_count);	\
	})
#define set_page_address(page, address)			\
	do {						\
		(page)->virtual = (address);		\
	} while(0)
#define set_page_count(p,v) 	atomic_set(&(p)->_count, v - 1)
#define set_page_private(page, v)	((page)->u.private = (v))
#define shmem_get_policy(a, b)	(NULL)
#define shmem_lock(a, b, c) 	({0;})	
#define shmem_nopage filemap_nopage
#define shmem_set_policy(a, b)	(0)
#define sysctl_legacy_va_layout 0
#define vma_prio_tree_foreach(vma, iter, root, begin, end)	\
	for (prio_tree_iter_init(iter, root, begin, end), vma = NULL;	\
		(vma = vma_prio_tree_next(vma, iter)); )
#define ClearPageActive(page)	clear_bit(PG_active, &(page)->flags)
#define ClearPageChecked(page)	clear_bit(PG_checked, &(page)->flags)
#define ClearPageCompound(page)	clear_bit(PG_compound, &(page)->flags)
#define ClearPageDirty(page)	clear_bit(PG_dirty, &(page)->flags)
#define ClearPageError(page)	clear_bit(PG_error, &(page)->flags)
#define ClearPageLocked(page)		\
		clear_bit(PG_locked, &(page)->flags)
#define ClearPageMappedToDisk(page) clear_bit(PG_mappedtodisk, &(page)->flags)
#define ClearPageNosave(page)		clear_bit(PG_nosave, &(page)->flags)
#define ClearPageNosaveFree(page)		clear_bit(PG_nosave_free, &(page)->flags)
#define ClearPagePrivate(page)	clear_bit(PG_private, &(page)->flags)
#define ClearPageReclaim(page)	clear_bit(PG_reclaim, &(page)->flags)
#define ClearPageReferenced(page)	clear_bit(PG_referenced, &(page)->flags)
#define ClearPageReserved(page)	clear_bit(PG_reserved, &(page)->flags)
#define ClearPageSlab(page)	clear_bit(PG_slab, &(page)->flags)
#define ClearPageSwapCache(page) clear_bit(PG_swapcache, &(page)->flags)
#define ClearPageUncached(page)	clear_bit(PG_uncached, &(page)->flags)
#define ClearPageUptodate(page)	clear_bit(PG_uptodate, &(page)->flags)
#define ClearPageWriteback(page)					\
	do {								\
		if (test_and_clear_bit(PG_writeback,			\
				&(page)->flags))			\
			dec_page_state(nr_writeback);			\
	} while (0)
#define GET_PAGE_STATE_LAST nr_slab

#define PageActive(page)	test_bit(PG_active, &(page)->flags)
#define PageChecked(page)	test_bit(PG_checked, &(page)->flags)
#define PageCompound(page)	test_bit(PG_compound, &(page)->flags)
#define PageDirty(page)		test_bit(PG_dirty, &(page)->flags)
#define PageError(page)		test_bit(PG_error, &(page)->flags)
#define PageHighMem(page)	is_highmem(page_zone(page))
#define PageLRU(page)		test_bit(PG_lru, &(page)->flags)
#define PageLocked(page)		\
		test_bit(PG_locked, &(page)->flags)
#define PageMappedToDisk(page)	test_bit(PG_mappedtodisk, &(page)->flags)
#define PageNosave(page)	test_bit(PG_nosave, &(page)->flags)
#define PageNosaveFree(page)	test_bit(PG_nosave_free, &(page)->flags)
#define PagePrivate(page)	test_bit(PG_private, &(page)->flags)
#define PageReclaim(page)	test_bit(PG_reclaim, &(page)->flags)
#define PageReferenced(page)	test_bit(PG_referenced, &(page)->flags)
#define PageReserved(page)	test_bit(PG_reserved, &(page)->flags)
#define PageSlab(page)		test_bit(PG_slab, &(page)->flags)
#define PageSwapCache(page)	test_bit(PG_swapcache, &(page)->flags)
#define PageUncached(page)	test_bit(PG_uncached, &(page)->flags)
#define PageUptodate(page)	test_bit(PG_uptodate, &(page)->flags)
#define PageWriteback(page)	test_bit(PG_writeback, &(page)->flags)
#define SetPageActive(page)	set_bit(PG_active, &(page)->flags)
#define SetPageChecked(page)	set_bit(PG_checked, &(page)->flags)
#define SetPageCompound(page)	set_bit(PG_compound, &(page)->flags)
#define SetPageDirty(page)	set_bit(PG_dirty, &(page)->flags)
#define SetPageError(page)	set_bit(PG_error, &(page)->flags)
#define SetPageLRU(page)	set_bit(PG_lru, &(page)->flags)
#define SetPageLocked(page)		\
		set_bit(PG_locked, &(page)->flags)
#define SetPageMappedToDisk(page) set_bit(PG_mappedtodisk, &(page)->flags)
#define SetPageNosave(page)	set_bit(PG_nosave, &(page)->flags)
#define SetPageNosaveFree(page)	set_bit(PG_nosave_free, &(page)->flags)
#define SetPagePrivate(page)	set_bit(PG_private, &(page)->flags)
#define SetPageReclaim(page)	set_bit(PG_reclaim, &(page)->flags)
#define SetPageReferenced(page)	set_bit(PG_referenced, &(page)->flags)
#define SetPageReserved(page)	set_bit(PG_reserved, &(page)->flags)
#define SetPageSlab(page)	set_bit(PG_slab, &(page)->flags)
#define SetPageSwapCache(page)	set_bit(PG_swapcache, &(page)->flags)
#define SetPageUncached(page)	set_bit(PG_uncached, &(page)->flags)
#define SetPageUptodate(page)	set_bit(PG_uptodate, &(page)->flags)
#define SetPageWriteback(page)						\
	do {								\
		if (!test_and_set_bit(PG_writeback,			\
				&(page)->flags))			\
			inc_page_state(nr_writeback);			\
	} while (0)
#define TestClearPageActive(page) test_and_clear_bit(PG_active, &(page)->flags)
#define TestClearPageDirty(page) test_and_clear_bit(PG_dirty, &(page)->flags)
#define TestClearPageLRU(page)	test_and_clear_bit(PG_lru, &(page)->flags)
#define TestClearPageLocked(page)	\
		test_and_clear_bit(PG_locked, &(page)->flags)
#define TestClearPageNosave(page)	test_and_clear_bit(PG_nosave, &(page)->flags)
#define TestClearPageReclaim(page) test_and_clear_bit(PG_reclaim, &(page)->flags)
#define TestClearPageReferenced(page) test_and_clear_bit(PG_referenced, &(page)->flags)
#define TestClearPageSlab(page)	test_and_clear_bit(PG_slab, &(page)->flags)
#define TestClearPageWriteback(page)					\
	({								\
		int ret;						\
		ret = test_and_clear_bit(PG_writeback,			\
				&(page)->flags);			\
		if (ret)						\
			dec_page_state(nr_writeback);			\
		ret;							\
	})
#define TestSetPageActive(page) test_and_set_bit(PG_active, &(page)->flags)
#define TestSetPageDirty(page)	test_and_set_bit(PG_dirty, &(page)->flags)
#define TestSetPageLRU(page)	test_and_set_bit(PG_lru, &(page)->flags)
#define TestSetPageLocked(page)		\
		test_and_set_bit(PG_locked, &(page)->flags)
#define TestSetPageNosave(page)	test_and_set_bit(PG_nosave, &(page)->flags)
#define TestSetPageSlab(page)	test_and_set_bit(PG_slab, &(page)->flags)
#define TestSetPageWriteback(page)					\
	({								\
		int ret;						\
		ret = test_and_set_bit(PG_writeback,			\
					&(page)->flags);		\
		if (!ret)						\
			inc_page_state(nr_writeback);			\
		ret;							\
	})
#define __ClearPageDirty(page)	__clear_bit(PG_dirty, &(page)->flags)
#define __ClearPagePrivate(page) __clear_bit(PG_private, &(page)->flags)
#define __ClearPageReserved(page)	__clear_bit(PG_reserved, &(page)->flags)
#define __SetPagePrivate(page)  __set_bit(PG_private, &(page)->flags)
#define add_page_state(member,delta) mod_page_state(member, (delta))
#define dec_page_state(member)	mod_page_state(member, 0UL - 1)
#define inc_page_state(member)	mod_page_state(member, 1UL)
#define mod_page_state(member, delta)	\
	__mod_page_state(offsetof(struct page_state, member), (delta))
#define mod_page_state_zone(zone, member, delta)				\
	do {									\
		unsigned offset;						\
		if (is_highmem(zone))						\
			offset = offsetof(struct page_state, member##_high);	\
		else if (is_normal(zone))					\
			offset = offsetof(struct page_state, member##_normal);	\
		else								\
			offset = offsetof(struct page_state, member##_dma);	\
		__mod_page_state(offset, (delta));				\
	} while (0)
#define read_page_state(member) \
	__read_page_state(offsetof(struct page_state, member))
#define sub_page_state(member,delta) mod_page_state(member, 0UL - (delta))


#define __install_session_keyring(tsk, keyring)			\
({								\
	struct key *old_session = tsk->signal->session_keyring;	\
	tsk->signal->session_keyring = keyring;			\
	old_session;						\
})
#define alloc_uid_keyring(u)		0
#define copy_keys(f,t)			0
#define copy_thread_group_keys(t)	0
#define exec_keys(t)			do { } while(0)
#define exit_keys(t)			do { } while(0)
#define exit_thread_group_keys(tg)	do { } while(0)
#define is_key_possessed(k)		0
#define key_fsgid_changed(t)		do { } while(0)
#define key_fsuid_changed(t)		do { } while(0)
#define key_get(k) 			({ NULL; })
#define key_init()			do { } while(0)
#define key_put(k)			do { } while(0)
#define key_ref_put(k)			do { } while(0)
#define key_ref_to_ptr(k)		({ NULL; })
#define key_serial(key) ((key) ? (key)->serial : 0)
#define key_validate(k)			0
#define make_key_ref(k)			({ NULL; })
#define suid_keys(t)			do { } while(0)
#define switch_uid_keyring(u)		do { } while(0)

#define INITRD_MINOR 250 

#define MSGMAP  MSGMNB            
#define MSGMAX  8192      
#define MSGMNB 16384      
#define MSGMNI    16        
#define MSGPOOL (MSGMNI*MSGMNB/1024)  
#define MSGSEG (__MSGSEG <= 0xffff ? __MSGSEG : 0xffff)
#define MSGSSZ  16                
#define MSGTQL  MSGMNB            
#define MSG_EXCEPT      020000  
#define MSG_INFO 12
#define MSG_NOERROR     010000  
#define MSG_STAT 11

#define __MSGSEG ((MSGPOOL*1024)/ MSGSSZ) 
#define SHMALL (SHMMAX/PAGE_SIZE*(SHMMNI/16)) 
#define SHMMAX 0x2000000		 
#define SHMMIN 1			 
#define SHMMNI 4096			 
#define SHMSEG SHMMNI			 
#define SHM_HUGETLB     04000   
#define SHM_INFO 	14
#define SHM_LOCK 	11
#define SHM_LOCKED      02000   
#define SHM_NORESERVE   010000  
#define SHM_STAT 	13
#define SHM_UNLOCK 	12

#define BINPRM_BUF_SIZE 128
#define BINPRM_FLAGS_ENFORCE_NONDUMP (1 << BINPRM_FLAGS_ENFORCE_NONDUMP_BIT)
#define BINPRM_FLAGS_ENFORCE_NONDUMP_BIT 0
#define BINPRM_FLAGS_EXECFD (1 << BINPRM_FLAGS_EXECFD_BIT)
#define BINPRM_FLAGS_EXECFD_BIT 1
#define EXSTACK_DEFAULT   0	
#define EXSTACK_DISABLE_X 1	
#define EXSTACK_ENABLE_X  2	
#define MAX_ARG_PAGES 32


#define alloc_huge_page()			({ NULL; })
#define copy_hugetlb_page_range(src, dst, vma)	({ BUG(); 0; })
#define follow_huge_addr(mm, addr, write)	ERR_PTR(-EINVAL)
#define follow_huge_pmd(mm, addr, pmd, write)	NULL
#define follow_hugetlb_page(m,v,p,vs,a,b,i)	({ BUG(); 0; })
#define free_huge_page(p)			({ (void)(p); BUG(); })
#define huge_ptep_get_and_clear(mm, addr, ptep) ptep_get_and_clear(mm, addr, ptep)
#define hugetlb_fault(mm, vma, addr, write)	({ BUG(); 0; })
#define hugetlb_free_pgd_range(tlb, addr, end, floor, ceiling) \
						do { } while (0)
#define hugetlb_prefault(mapping, vma)		({ BUG(); 0; })
#define hugetlb_prefault_arch_hook(mm)		do { } while (0)
#define hugetlb_report_meminfo(buf)		0
#define hugetlb_report_node_meminfo(n, buf)	0
#define hugetlb_zero_setup(size)	ERR_PTR(-ENOSYS)
#define is_aligned_hugepage_range(addr, len)	0
#define is_file_hugepages(file)		0
#define is_hugepage_mem_enough(size)		0
#define is_hugepage_only_range(mm, addr, len)	0
#define pmd_huge(x)	0
#define prepare_hugepage_range(addr, len)	\
	is_aligned_hugepage_range(addr, len)
#define set_file_hugepages(file)	BUG()
#define set_huge_pte_at(mm, addr, ptep, pte)	set_pte_at(mm, addr, ptep, pte)
#define unmap_hugepage_range(vma, start, end)	BUG()
#define MPOL_MAX MPOL_INTERLEAVE
#define _LINUX_MEMPOLICY_H 1
#define mpol_set_vma_default(vma) ((vma)->vm_policy = NULL)
#define vma_mpol_equal(a,b) mpol_equal(vma_policy(a), vma_policy(b))
#define vma_policy(vma) NULL
#define vma_set_policy(vma, pol) do {} while(0)

#define current_is_pdflush()	task_is_pdflush(current)
#define SET_GID(var, gid) do { (var) = __convert_gid(sizeof(var), (gid)); } while (0)
#define SET_UID(var, uid) do { (var) = __convert_uid(sizeof(var), (uid)); } while (0)

#define __convert_gid(size, gid) \
	(size >= sizeof(gid) ? (gid) : high2lowgid(gid))
#define __convert_uid(size, uid) \
	(size >= sizeof(uid) ? (uid) : high2lowuid(uid))
#define fs_high2lowgid(gid) ((gid) & ~0xFFFF ? (gid16_t)fs_overflowgid : (gid16_t)(gid))
#define fs_high2lowuid(uid) ((uid) & ~0xFFFF ? (uid16_t)fs_overflowuid : (uid16_t)(uid))
#define high2lowgid(gid) ((gid) & ~0xFFFF ? (old_gid_t)overflowgid : (old_gid_t)(gid))
#define high2lowuid(uid) ((uid) & ~0xFFFF ? (old_uid_t)overflowuid : (old_uid_t)(uid))
#define high_16_bits(x)	(((x) & 0xFFFF0000) >> 16)
#define low2highgid(gid) ((gid) == (old_gid_t)-1 ? (gid_t)-1 : (gid_t)(gid))
#define low2highuid(uid) ((uid) == (old_uid_t)-1 ? (uid_t)-1 : (uid_t)(uid))
#define low_16_bits(x)	((x) & 0xFFFF)
#define register_sysrq_key(ig,nore) __reterr()
#define unregister_sysrq_key(ig,nore) __reterr()
#define MODULE_ALIAS_NETPROTO(proto) \
	MODULE_ALIAS("net-pf-" __stringify(proto))
#define MODULE_ALIAS_NET_PF_PROTO(pf, proto) \
	MODULE_ALIAS("net-pf-" __stringify(pf) "-proto-" __stringify(proto))
#define SOCKCALL_UWRAP(name, call, parms, args)		\
static unsigned int __lock_##name##_##call  parms	\
{							\
	int ret;					\
	lock_kernel();					\
	ret = __unlocked_##name##_ops.call  args ;\
	unlock_kernel();				\
	return ret;					\
}
#define SOCKCALL_WRAP(name, call, parms, args)		\
static int __lock_##name##_##call  parms		\
{							\
	int ret;					\
	lock_kernel();					\
	ret = __unlocked_##name##_ops.call  args ;\
	unlock_kernel();				\
	return ret;					\
}
#define SOCKOPS_WRAP(name, fam)
#define SOCKOPS_WRAPPED(name) name
#define SOCK_MAX (SOCK_PACKET + 1)

#define		     sockfd_put(sock) fput(sock->file)
#define CTL_MAXNAME 10		


#define __NEW_UTS_LEN 64
#define __OLD_UTS_LEN 8

#define __ismask(x) (_ctype[(int)(unsigned char)(x)])
#define isalnum(c)	((__ismask(c)&(_U|_L|_D)) != 0)
#define isalpha(c)	((__ismask(c)&(_U|_L)) != 0)
#define isascii(c) (((unsigned char)(c))<=0x7f)
#define iscntrl(c)	((__ismask(c)&(_C)) != 0)
#define isdigit(c)	((__ismask(c)&(_D)) != 0)
#define isgraph(c)	((__ismask(c)&(_P|_U|_L|_D)) != 0)
#define islower(c)	((__ismask(c)&(_L)) != 0)
#define isprint(c)	((__ismask(c)&(_P|_U|_L|_D|_SP)) != 0)
#define ispunct(c)	((__ismask(c)&(_P)) != 0)
#define isspace(c)	((__ismask(c)&(_S)) != 0)
#define isupper(c)	((__ismask(c)&(_U)) != 0)
#define isxdigit(c)	((__ismask(c)&(_D|_X)) != 0)
#define toascii(c) (((unsigned char)(c))&0x7f)
#define tolower(c) __tolower(c)
#define toupper(c) __toupper(c)
#define MAX_SWAP_BADPAGES \
	((__swapoffset(magic.magic) - __swapoffset(info.badpages)) / sizeof(int))
#define SWAP_CLUSTER_MAX 32

#define __delete_from_swap_cache(p)		
#define __swapoffset(x) ((unsigned long)&((union swap_header *)0)->x)
#define can_share_swap_page(p)			0
#define delete_from_swap_cache(p)		
#define free_page_and_swap_cache(page) \
	page_cache_release(page)
#define free_pages_and_swap_cache(pages, nr) \
	release_pages((pages), (nr), 0);
#define free_swap_and_cache(swp)		
#define grab_swap_token()  do { } while(0)
#define has_swap_token(x) 0
#define lookup_swap_cache(swp)			NULL
#define move_from_swap_cache(p, i, m)		1
#define move_to_swap_cache(p, swp)		1
#define put_swap_token(x) do { } while(0)
#define read_swap_cache_async(swp,vma,addr)	NULL
#define show_swap_cache_info()			
#define si_swapinfo(val) \
	do { (val)->freeswap = (val)->totalswap = 0; } while (0)
#define swap_duplicate(swp)			
#define swap_free(swp)				
#define total_swapcache_pages  swapper_space.nrpages
#define valid_swaphandles(swp, off)		0
#define vm_swap_full() (nr_swap_pages*2 < total_swap_pages)
#define EXPORT_SYMBOL(sym)					\
	__EXPORT_SYMBOL(sym, "")
#define EXPORT_SYMBOL_GPL(sym)					\
	__EXPORT_SYMBOL(sym, "_gpl")

#define MODULE_ALIAS(_alias) MODULE_INFO(alias, _alias)
#define MODULE_AUTHOR(_author) MODULE_INFO(author, _author)
#define MODULE_DESCRIPTION(_description) MODULE_INFO(description, _description)
#define MODULE_DEVICE_TABLE(type,name)		\
  MODULE_GENERIC_TABLE(type##_device,name)
#define MODULE_GENERIC_TABLE(gtype,name)			\
extern const struct gtype##_id __mod_##gtype##_table		\
  __attribute__ ((unused, alias(__stringify(name))))
#define MODULE_INFO(tag, info) __MODULE_INFO(tag, tag, info)
#define MODULE_LICENSE(_license) MODULE_INFO(license, _license)
#define MODULE_NAME_LEN (64 - sizeof(unsigned long))
#define MODULE_PARM(var,type)						    \
extern struct obsolete_modparm __parm_##var \
__attribute__((section("__obsparm"))); \
struct obsolete_modparm __parm_##var = \
{ __stringify(var), type, &MODULE_PARM_ }; \
__MODULE_PARM_TYPE(var, type);
#define MODULE_PARM_DESC(_parm, desc) \
	__MODULE_INFO(parm, _parm, #_parm ":" desc)
#define MODULE_SECT_NAME_LEN 32

#define MODULE_SYMBOL_PREFIX ""
#define MODULE_VERSION(_version) MODULE_INFO(version, _version)
#define THIS_MODULE (&__this_module)

#define __CRC_SYMBOL(sym, sec)					\
	extern void *__crc_##sym __attribute__((weak));		\
	static const unsigned long __kcrctab_##sym		\
	__attribute_used__					\
	__attribute__((section("__kcrctab" sec), unused))	\
	= (unsigned long) &__crc_##sym;
#define __EXPORT_SYMBOL(sym, sec)				\
	__CRC_SYMBOL(sym, sec)					\
	static const char __kstrtab_##sym[]			\
	__attribute__((section("__ksymtab_strings")))		\
	= MODULE_SYMBOL_PREFIX #sym;                    	\
	static const struct kernel_symbol __ksymtab_##sym	\
	__attribute_used__					\
	__attribute__((section("__ksymtab" sec), unused))	\
	= { (unsigned long)&sym, __kstrtab_##sym }
#define __MODULE_STRING(x) __stringify(x)
#define __unsafe(mod)							     \
do {									     \
	if (mod && !(mod)->unsafe) {					     \
		printk(KERN_WARNING					     \
		       "Module %s cannot be unloaded due to unsafe usage in" \
		       " %s:%u\n", (mod)->name, "__FILE__", "__LINE__");	     \
		(mod)->unsafe = 1;					     \
	}								     \
} while(0)
#define module_name(mod)			\
({						\
	struct module *__mod = (mod);		\
	__mod ? __mod->name : "kernel";		\
})
#define module_put_and_exit(code) __module_put_and_exit(THIS_MODULE, code);
#define symbol_get(x) ((typeof(&x))(__symbol_get(MODULE_SYMBOL_PREFIX #x)))
#define symbol_put(x) __symbol_put(MODULE_SYMBOL_PREFIX #x)
#define symbol_put_addr(p) do { } while(0)
#define symbol_request(x) try_then_request_module(symbol_get(x), "symbol:" #x)
#define MODULE_PARAM_PREFIX 

#define __MODULE_INFO(tag, name, info)					  \
static const char __module_cat(name,"__LINE__")[]				  \
  __attribute_used__							  \
  __attribute__((section(".modinfo"),unused)) = __stringify(tag) "=" info
#define __MODULE_PARM_TYPE(name, _type)					  \
  __MODULE_INFO(parmtype, name##type, #name ":" _type)
#define ___module_cat(a,b) __mod_ ## a ## b
#define __module_cat(a,b) ___module_cat(a,b)
#define __module_param_call(prefix, name, set, get, arg, perm)		\
	static char __param_str_##name[] = prefix #name;		\
	static struct kernel_param const __param_##name			\
	__attribute_used__						\
    __attribute__ ((unused,__section__ ("__param"),aligned(sizeof(void *)))) \
	= { __param_str_##name, perm, set, get, arg }
#define __param_check(name, p, type) \
	static inline type *__check_##name(void) { return(p); }
#define module_param(name, type, perm)				\
	module_param_named(name, name, type, perm)
#define module_param_array(name, type, nump, perm)		\
	module_param_array_named(name, name, type, nump, perm)
#define module_param_array_named(name, array, type, nump, perm)		\
	static struct kparam_array __param_arr_##name			\
	= { ARRAY_SIZE(array), nump, param_set_##type, param_get_##type,\
	    sizeof(array[0]), array };					\
	module_param_call(name, param_array_set, param_array_get, 	\
			  &__param_arr_##name, perm);			\
	__MODULE_PARM_TYPE(name, "array of " #type)
#define module_param_call(name, set, get, arg, perm)			      \
	__module_param_call(MODULE_PARAM_PREFIX, name, set, get, arg, perm)
#define module_param_named(name, value, type, perm)			   \
	param_check_##type(name, &(value));				   \
	module_param_call(name, param_set_##type, param_get_##type, &value, perm); \
	__MODULE_PARM_TYPE(name, #type)
#define module_param_string(name, string, len, perm)			\
	static struct kparam_string __param_string_##name		\
		= { len, string };					\
	module_param_call(name, param_set_copystring, param_get_string,	\
		   &__param_string_##name, perm);			\
	__MODULE_PARM_TYPE(name, "string")
#define param_check_bool(name, p) __param_check(name, p, int)
#define param_check_byte(name, p) __param_check(name, p, unsigned char)
#define param_check_charp(name, p) __param_check(name, p, char *)
#define param_check_int(name, p) __param_check(name, p, int)
#define param_check_invbool(name, p) __param_check(name, p, int)
#define param_check_long(name, p) __param_check(name, p, long)
#define param_check_short(name, p) __param_check(name, p, short)
#define param_check_uint(name, p) __param_check(name, p, unsigned int)
#define param_check_ulong(name, p) __param_check(name, p, unsigned long)
#define param_check_ushort(name, p) __param_check(name, p, unsigned short)
#define DT_RPATH 	15
#define ELF32_R_SYM(x) ((x) >> 8)
#define ELF32_R_TYPE(x) ((x) & 0xff)
#define ELF32_ST_BIND(x)	ELF_ST_BIND(x)
#define ELF32_ST_TYPE(x)	ELF_ST_TYPE(x)
#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)
#define ELF64_ST_BIND(x)	ELF_ST_BIND(x)
#define ELF64_ST_TYPE(x)	ELF_ST_TYPE(x)
#define ELF_OSABI ELFOSABI_NONE
#define ELF_ST_BIND(x)		((x) >> 4)
#define ELF_ST_TYPE(x)		(((unsigned int) x) & 0xf)
#define EM_386   3
#define EM_486   6   
#define EM_68K   4
#define EM_860   7
#define EM_88K   5
#define EM_CRIS         76      
#define EM_H8_300       46      
#define EM_M32   1
#define EM_MIPS_RS4_BE 10	
#define EM_NONE  0
#define EM_PARISC      15	
#define EM_PPC64       21       
#define EM_S390_OLD     0xA390
#define EM_SPARC 2
#define EM_SPARC32PLUS 18	
#define EM_SPARCV9     43	
#define ET_CORE   4
#define ET_DYN    3
#define ET_EXEC   2
#define ET_HIPROC 0xffff
#define ET_LOPROC 0xff00
#define ET_NONE   0
#define ET_REL    1
#define NT_PRXFPREG     0x46e62b7f      
#define PT_DYNAMIC 2
#define PT_HIOS    0x6fffffff      
#define PT_HIPROC  0x7fffffff
#define PT_INTERP  3
#define PT_LOAD    1
#define PT_LOOS    0x60000000      
#define PT_LOPROC  0x70000000
#define PT_NOTE    4
#define PT_NULL    0
#define PT_PHDR    6
#define PT_SHLIB   5
#define PT_TLS     7               
#define STB_GLOBAL 1
#define STB_LOCAL  0
#define STB_WEAK   2
#define STT_FILE    4
#define STT_FUNC    2
#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_SECTION 3

# define elf_read_implies_exec(ex, have_pt_gnu_stack)	0
#define KMOD_PATH_LEN 256

#define try_then_request_module(x, mod...) ((x) ?: (request_module(mod), (x)))
