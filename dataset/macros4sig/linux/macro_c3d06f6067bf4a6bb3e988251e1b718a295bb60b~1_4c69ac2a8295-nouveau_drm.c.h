





#include<stdarg.h>


#include<asm/param.h>

#include<asm/auxvec.h>





#include<asm/ptrace.h>

#include<linux/uuid.h>

#include<asm/types.h>

#include<signal.h>









#include<linux/blkzoned.h>




#include<stdint.h>

#include<unistd.h>







#include<linux/dqblk_xfs.h>


#include<linux/i2c.h>




#include<asm/errno.h>





#include<asm/ipcbuf.h>



#include<linux/module.h>













#include<linux/capability.h>


#include<linux/resource.h>

#include<linux/wait.h>


#include<linux/ipc.h>




#include<linux/kdev_t.h>


#include<asm/poll.h>







#include<linux/rseq.h>




#include<linux/reboot.h>

#include<linux/sched.h>

#include<asm/sembuf.h>








#include<linux/fcntl.h>


#include<asm/bitsperlong.h>















#include<linux/errno.h>






































#include<linux/string.h>


#include<linux/mount.h>
#include<time.h>



#include<linux/bpf_common.h>







#include<asm/siginfo.h>














#include<linux/stat.h>


#include<linux/media-bus-format.h>






#include<asm/resource.h>






#include<stdlib.h>
#include<asm/ioctl.h>






#include<linux/time_types.h>





#include<linux/cgroupstats.h>
#include<linux/pci_regs.h>










#include<linux/stddef.h>















#include<linux/fb.h>
















#include<asm/stat.h>


#include<string.h>













#include<asm-generic/hugetlb_encode.h>





#include<asm/byteorder.h>

#include<errno.h>


#include<stdio.h>


#include<linux/time.h>

#include<linux/sysinfo.h>


#include<linux/sysctl.h>







#include<drm/drm.h>





#include<drm/drm_mode.h>




#include<sys/types.h>

#include<linux/posix_types.h>




#include<asm/signal.h>

#include<linux/major.h>
#include<fcntl.h>
#include<linux/ioctl.h>




#include<linux/elf-em.h>




#include<linux/fs.h>




#include<linux/types.h>
#include<linux/limits.h>



#include<linux/param.h>

#include<linux/seccomp.h>

#include<asm/shmbuf.h>

#include<linux/kernel.h>

#include<ctype.h>

#include<linux/const.h>






#include<asm/swab.h>














#include<asm/fcntl.h>




#include<linux/pci.h>





#define ERESTART_RESTARTBLOCK 516 



#define ATOMIC_INIT_NOTIFIER_HEAD(name) do {	\
		spin_lock_init(&(name)->lock);	\
		(name)->head = NULL;		\
	} while (0)
#define ATOMIC_NOTIFIER_HEAD(name)				\
	struct atomic_notifier_head name =			\
		ATOMIC_NOTIFIER_INIT(name)
#define ATOMIC_NOTIFIER_INIT(name) {				\
		.lock = __SPIN_LOCK_UNLOCKED(name.lock),	\
		.head = NULL }
#define BLOCKING_INIT_NOTIFIER_HEAD(name) do {	\
		init_rwsem(&(name)->rwsem);	\
		(name)->head = NULL;		\
	} while (0)
#define BLOCKING_NOTIFIER_HEAD(name)				\
	struct blocking_notifier_head name =			\
		BLOCKING_NOTIFIER_INIT(name)
#define BLOCKING_NOTIFIER_INIT(name) {				\
		.rwsem = __RWSEM_INITIALIZER((name).rwsem),	\
		.head = NULL }
#define RAW_INIT_NOTIFIER_HEAD(name) do {	\
		(name)->head = NULL;		\
	} while (0)
#define RAW_NOTIFIER_HEAD(name)					\
	struct raw_notifier_head name =				\
		RAW_NOTIFIER_INIT(name)
#define RAW_NOTIFIER_INIT(name)	{				\
		.head = NULL }
#define SRCU_NOTIFIER_HEAD(name)				\
	_SRCU_NOTIFIER_HEAD(name, )
#define SRCU_NOTIFIER_HEAD_STATIC(name)				\
	_SRCU_NOTIFIER_HEAD(name, static)
#define SRCU_NOTIFIER_INIT(name, pcpu)				\
	{							\
		.mutex = __MUTEX_INITIALIZER(name.mutex),	\
		.head = NULL,					\
		.srcu = __SRCU_STRUCT_INIT(name.srcu, pcpu),	\
	}

#define _SRCU_NOTIFIER_HEAD(name, mod)				\
	static DEFINE_PER_CPU(struct srcu_data, name##_head_srcu_data); \
	mod struct srcu_notifier_head name =			\
			SRCU_NOTIFIER_INIT(name, name##_head_srcu_data)
#define srcu_cleanup_notifier_head(name)	\
		cleanup_srcu_struct(&(name)->srcu);

#define __SRCU_DEP_MAP_INIT(srcu_name)	.dep_map = { .name = #srcu_name },
#define init_srcu_struct(ssp) \
({ \
	static struct lock_class_key __srcu_key; \
	\
	__init_srcu_struct((ssp), #ssp, &__srcu_key); \
})
#define srcu_dereference(p, ssp) srcu_dereference_check((p), (ssp), 0)
#define srcu_dereference_check(p, ssp, c) \
	__rcu_dereference_check((p), (c) || srcu_read_lock_held(ssp), __rcu)
#define srcu_dereference_notrace(p, ssp) srcu_dereference_check((p), (ssp), 1)
#define DEFINE_SRCU(name)		__DEFINE_SRCU(name, )
#define DEFINE_STATIC_SRCU(name)	__DEFINE_SRCU(name, static)

# define __DEFINE_SRCU(name, is_static)					\
	is_static struct srcu_struct name;				\
	struct srcu_struct * const __srcu_struct_##name			\
		__section("___srcu_struct_ptrs") = &name
#define __SRCU_STRUCT_INIT(name, pcpu_name)				\
{									\
	.sda = &pcpu_name,						\
	.lock = __SPIN_LOCK_UNLOCKED(name.lock),			\
	.srcu_gp_seq_needed = -1UL,					\
	.work = __DELAYED_WORK_INITIALIZER(name.work, NULL, 0),		\
	__SRCU_DEP_MAP_INIT(name)					\
}
#define COMPLETION_INITIALIZER(work) \
	{ 0, __SWAIT_QUEUE_HEAD_INITIALIZER((work).wait) }
#define COMPLETION_INITIALIZER_ONSTACK(work) \
	(*({ init_completion(&work); &work; }))
#define COMPLETION_INITIALIZER_ONSTACK_MAP(work, map) \
	(*({ init_completion_map(&(work), &(map)); &(work); }))
#define DECLARE_COMPLETION(work) \
	struct completion work = COMPLETION_INITIALIZER(work)
# define DECLARE_COMPLETION_ONSTACK(work) \
	struct completion work = COMPLETION_INITIALIZER_ONSTACK(work)
# define DECLARE_COMPLETION_ONSTACK_MAP(work, map) \
	struct completion work = COMPLETION_INITIALIZER_ONSTACK_MAP(work, map)

#define init_completion_map(x, m) init_completion(x)
#define DECLARE_SWAITQUEUE(name)					\
	struct swait_queue name = __SWAITQUEUE_INITIALIZER(name)
#define DECLARE_SWAIT_QUEUE_HEAD(name)					\
	struct swait_queue_head name = __SWAIT_QUEUE_HEAD_INITIALIZER(name)
# define DECLARE_SWAIT_QUEUE_HEAD_ONSTACK(name)			\
	struct swait_queue_head name = __SWAIT_QUEUE_HEAD_INIT_ONSTACK(name)

#define __SWAITQUEUE_INITIALIZER(name) {				\
	.task		= current,					\
	.task_list	= LIST_HEAD_INIT((name).task_list),		\
}
#define __SWAIT_QUEUE_HEAD_INITIALIZER(name) {				\
	.lock		= __RAW_SPIN_LOCK_UNLOCKED(name.lock),		\
	.task_list	= LIST_HEAD_INIT((name).task_list),		\
}
# define __SWAIT_QUEUE_HEAD_INIT_ONSTACK(name)			\
	({ init_swait_queue_head(&name); name; })
#define ___swait_event(wq, condition, state, ret, cmd)			\
({									\
	__label__ __out;						\
	struct swait_queue __wait;					\
	long __ret = ret;						\
									\
	INIT_LIST_HEAD(&__wait.task_list);				\
	for (;;) {							\
		long __int = prepare_to_swait_event(&wq, &__wait, state);\
									\
		if (condition)						\
			break;						\
									\
		if (___wait_is_interruptible(state) && __int) {		\
			__ret = __int;					\
			goto __out;					\
		}							\
									\
		cmd;							\
	}								\
	finish_swait(&wq, &__wait);					\
__out:	__ret;								\
})
#define __swait_event(wq, condition)					\
	(void)___swait_event(wq, condition, TASK_UNINTERRUPTIBLE, 0,	\
			    schedule())
#define __swait_event_idle(wq, condition)				\
	(void)___swait_event(wq, condition, TASK_IDLE, 0, schedule())
#define __swait_event_idle_timeout(wq, condition, timeout)		\
	___swait_event(wq, ___wait_cond_timeout(condition),		\
		       TASK_IDLE, timeout,				\
		       __ret = schedule_timeout(__ret))
#define __swait_event_interruptible(wq, condition)			\
	___swait_event(wq, condition, TASK_INTERRUPTIBLE, 0,		\
		      schedule())
#define __swait_event_interruptible_timeout(wq, condition, timeout)	\
	___swait_event(wq, ___wait_cond_timeout(condition),		\
		      TASK_INTERRUPTIBLE, timeout,			\
		      __ret = schedule_timeout(__ret))
#define __swait_event_timeout(wq, condition, timeout)			\
	___swait_event(wq, ___wait_cond_timeout(condition),		\
		      TASK_UNINTERRUPTIBLE, timeout,			\
		      __ret = schedule_timeout(__ret))
#define init_swait_queue_head(q)				\
	do {							\
		static struct lock_class_key __key;		\
		__init_swait_queue_head((q), #q, &__key);	\
	} while (0)
#define swait_event_exclusive(wq, condition)				\
do {									\
	if (condition)							\
		break;							\
	__swait_event(wq, condition);					\
} while (0)
#define swait_event_idle_exclusive(wq, condition)			\
do {									\
	if (condition)							\
		break;							\
	__swait_event_idle(wq, condition);				\
} while (0)
#define swait_event_idle_timeout_exclusive(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout(condition))				\
		__ret = __swait_event_idle_timeout(wq,			\
						   condition, timeout);	\
	__ret;								\
})
#define swait_event_interruptible_exclusive(wq, condition)		\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__ret = __swait_event_interruptible(wq, condition);	\
	__ret;								\
})
#define swait_event_interruptible_timeout_exclusive(wq, condition, timeout)\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout(condition))				\
		__ret = __swait_event_interruptible_timeout(wq,		\
						condition, timeout);	\
	__ret;								\
})
#define swait_event_timeout_exclusive(wq, condition, timeout)		\
({									\
	long __ret = timeout;						\
	if (!___wait_cond_timeout(condition))				\
		__ret = __swait_event_timeout(wq, condition, timeout);	\
	__ret;								\
})
#define DECLARE_WAITQUEUE(name, tsk)						\
	struct wait_queue_entry name = __WAITQUEUE_INITIALIZER(name, tsk)
#define DECLARE_WAIT_QUEUE_HEAD(name) \
	struct wait_queue_head name = __WAIT_QUEUE_HEAD_INITIALIZER(name)
# define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) \
	struct wait_queue_head name = __WAIT_QUEUE_HEAD_INIT_ONSTACK(name)
#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)
#define DEFINE_WAIT_FUNC(name, function)					\
	struct wait_queue_entry name = {					\
		.private	= current,					\
		.func		= function,					\
		.entry		= LIST_HEAD_INIT((name).entry),			\
	}

#define __WAITQUEUE_INITIALIZER(name, tsk) {					\
	.private	= tsk,							\
	.func		= default_wake_function,				\
	.entry		= { NULL, NULL } }
#define __WAIT_QUEUE_HEAD_INITIALIZER(name) {					\
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),			\
	.head		= LIST_HEAD_INIT(name.head) }
# define __WAIT_QUEUE_HEAD_INIT_ONSTACK(name) \
	({ init_waitqueue_head(&name); name; })
#define ___wait_cond_timeout(condition)						\
({										\
	bool __cond = (condition);						\
	if (__cond && !__ret)							\
		__ret = 1;							\
	__cond || !__ret;							\
})
#define ___wait_event(wq_head, condition, state, exclusive, ret, cmd)		\
({										\
	__label__ __out;							\
	struct wait_queue_entry __wq_entry;					\
	long __ret = ret;					\
										\
	init_wait_entry(&__wq_entry, exclusive ? WQ_FLAG_EXCLUSIVE : 0);	\
	for (;;) {								\
		long __int = prepare_to_wait_event(&wq_head, &__wq_entry, state);\
										\
		if (condition)							\
			break;							\
										\
		if (___wait_is_interruptible(state) && __int) {			\
			__ret = __int;						\
			goto __out;						\
		}								\
										\
		cmd;								\
	}									\
	finish_wait(&wq_head, &__wq_entry);					\
__out:	__ret;									\
})
#define ___wait_is_interruptible(state)						\
	(!__builtin_constant_p(state) ||					\
		state == TASK_INTERRUPTIBLE || state == TASK_KILLABLE)		\

#define __io_wait_event(wq_head, condition)					\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    io_schedule())
#define __wait_event(wq_head, condition)					\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    schedule())
#define __wait_event_cmd(wq_head, condition, cmd1, cmd2)			\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    cmd1; schedule(); cmd2)
#define __wait_event_exclusive_cmd(wq_head, condition, cmd1, cmd2)		\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 1, 0,	\
			    cmd1; schedule(); cmd2)
#define __wait_event_freezable(wq_head, condition)				\
	___wait_event(wq_head, condition, TASK_INTERRUPTIBLE, 0, 0,		\
			    freezable_schedule())
#define __wait_event_freezable_exclusive(wq, condition)				\
	___wait_event(wq, condition, TASK_INTERRUPTIBLE, 1, 0,			\
			freezable_schedule())
#define __wait_event_freezable_timeout(wq_head, condition, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_INTERRUPTIBLE, 0, timeout,				\
		      __ret = freezable_schedule_timeout(__ret))
#define __wait_event_hrtimeout(wq_head, condition, timeout, state)		\
({										\
	int __ret = 0;								\
	struct hrtimer_sleeper __t;						\
										\
	hrtimer_init_sleeper_on_stack(&__t, CLOCK_MONOTONIC,			\
				      HRTIMER_MODE_REL);			\
	if ((timeout) != KTIME_MAX)						\
		hrtimer_start_range_ns(&__t.timer, timeout,			\
				       current->timer_slack_ns,			\
				       HRTIMER_MODE_REL);			\
										\
	__ret = ___wait_event(wq_head, condition, state, 0, 0,			\
		if (!__t.task) {						\
			__ret = -ETIME;						\
			break;							\
		}								\
		schedule());							\
										\
	hrtimer_cancel(&__t.timer);						\
	destroy_hrtimer_on_stack(&__t.timer);					\
	__ret;									\
})
#define __wait_event_idle_exclusive_timeout(wq_head, condition, timeout)	\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_IDLE, 1, timeout,					\
		      __ret = schedule_timeout(__ret))
#define __wait_event_idle_timeout(wq_head, condition, timeout)			\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_IDLE, 0, timeout,					\
		      __ret = schedule_timeout(__ret))
#define __wait_event_interruptible(wq_head, condition)				\
	___wait_event(wq_head, condition, TASK_INTERRUPTIBLE, 0, 0,		\
		      schedule())
#define __wait_event_interruptible_exclusive(wq, condition)			\
	___wait_event(wq, condition, TASK_INTERRUPTIBLE, 1, 0,			\
		      schedule())
#define __wait_event_interruptible_lock_irq(wq_head, condition, lock, cmd)	\
	___wait_event(wq_head, condition, TASK_INTERRUPTIBLE, 0, 0,		\
		      spin_unlock_irq(&lock);					\
		      cmd;							\
		      schedule();						\
		      spin_lock_irq(&lock))
#define __wait_event_interruptible_locked(wq, condition, exclusive, fn)		\
({										\
	int __ret;								\
	DEFINE_WAIT(__wait);							\
	if (exclusive)								\
		__wait.flags |= WQ_FLAG_EXCLUSIVE;				\
	do {									\
		__ret = fn(&(wq), &__wait);					\
		if (__ret)							\
			break;							\
	} while (!(condition));							\
	__remove_wait_queue(&(wq), &__wait);					\
	__set_current_state(TASK_RUNNING);					\
	__ret;									\
})
#define __wait_event_interruptible_timeout(wq_head, condition, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_INTERRUPTIBLE, 0, timeout,				\
		      __ret = schedule_timeout(__ret))
#define __wait_event_killable(wq, condition)					\
	___wait_event(wq, condition, TASK_KILLABLE, 0, 0, schedule())
#define __wait_event_killable_exclusive(wq, condition)				\
	___wait_event(wq, condition, TASK_KILLABLE, 1, 0,			\
		      schedule())
#define __wait_event_killable_timeout(wq_head, condition, timeout)		\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_KILLABLE, 0, timeout,				\
		      __ret = schedule_timeout(__ret))
#define __wait_event_lock_irq(wq_head, condition, lock, cmd)			\
	(void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			    spin_unlock_irq(&lock);				\
			    cmd;						\
			    schedule();						\
			    spin_lock_irq(&lock))
#define __wait_event_lock_irq_timeout(wq_head, condition, lock, timeout, state)	\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      state, 0, timeout,					\
		      spin_unlock_irq(&lock);					\
		      __ret = schedule_timeout(__ret);				\
		      spin_lock_irq(&lock));
#define __wait_event_timeout(wq_head, condition, timeout)			\
	___wait_event(wq_head, ___wait_cond_timeout(condition),			\
		      TASK_UNINTERRUPTIBLE, 0, timeout,				\
		      __ret = schedule_timeout(__ret))
#define init_wait(wait)								\
	do {									\
		(wait)->private = current;					\
		(wait)->func = autoremove_wake_function;			\
		INIT_LIST_HEAD(&(wait)->entry);					\
		(wait)->flags = 0;						\
	} while (0)
#define init_waitqueue_head(wq_head)						\
	do {									\
		static struct lock_class_key __key;				\
										\
		__init_waitqueue_head((wq_head), #wq_head, &__key);		\
	} while (0)
#define io_wait_event(wq_head, condition)					\
do {										\
	might_sleep();								\
	if (condition)								\
		break;								\
	__io_wait_event(wq_head, condition);					\
} while (0)
#define key_to_poll(m) ((__force __poll_t)(uintptr_t)(void *)(m))
#define poll_to_key(m) ((void *)(__force uintptr_t)(__poll_t)(m))
#define wait_event(wq_head, condition)						\
do {										\
	might_sleep();								\
	if (condition)								\
		break;								\
	__wait_event(wq_head, condition);					\
} while (0)
#define wait_event_cmd(wq_head, condition, cmd1, cmd2)				\
do {										\
	if (condition)								\
		break;								\
	__wait_event_cmd(wq_head, condition, cmd1, cmd2);			\
} while (0)
#define wait_event_exclusive_cmd(wq_head, condition, cmd1, cmd2)		\
do {										\
	if (condition)								\
		break;								\
	__wait_event_exclusive_cmd(wq_head, condition, cmd1, cmd2);		\
} while (0)
#define wait_event_freezable(wq_head, condition)				\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_freezable(wq_head, condition);		\
	__ret;									\
})
#define wait_event_freezable_exclusive(wq, condition)				\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_freezable_exclusive(wq, condition);	\
	__ret;									\
})
#define wait_event_freezable_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_freezable_timeout(wq_head, condition, timeout); \
	__ret;									\
})
#define wait_event_hrtimeout(wq_head, condition, timeout)			\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_hrtimeout(wq_head, condition, timeout,	\
					       TASK_UNINTERRUPTIBLE);		\
	__ret;									\
})
#define wait_event_idle(wq_head, condition)					\
do {										\
	might_sleep();								\
	if (!(condition))							\
		___wait_event(wq_head, condition, TASK_IDLE, 0, 0, schedule());	\
} while (0)
#define wait_event_idle_exclusive(wq_head, condition)				\
do {										\
	might_sleep();								\
	if (!(condition))							\
		___wait_event(wq_head, condition, TASK_IDLE, 1, 0, schedule());	\
} while (0)
#define wait_event_idle_exclusive_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_idle_exclusive_timeout(wq_head, condition, timeout);\
	__ret;									\
})
#define wait_event_idle_timeout(wq_head, condition, timeout)			\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_idle_timeout(wq_head, condition, timeout);	\
	__ret;									\
})
#define wait_event_interruptible(wq_head, condition)				\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_interruptible(wq_head, condition);		\
	__ret;									\
})
#define wait_event_interruptible_exclusive(wq, condition)			\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_interruptible_exclusive(wq, condition);	\
	__ret;									\
})
#define wait_event_interruptible_exclusive_locked(wq, condition)		\
	((condition)								\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, do_wait_intr))
#define wait_event_interruptible_exclusive_locked_irq(wq, condition)		\
	((condition)								\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, do_wait_intr_irq))
#define wait_event_interruptible_hrtimeout(wq, condition, timeout)		\
({										\
	long __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_hrtimeout(wq, condition, timeout,		\
					       TASK_INTERRUPTIBLE);		\
	__ret;									\
})
#define wait_event_interruptible_lock_irq(wq_head, condition, lock)		\
({										\
	int __ret = 0;								\
	if (!(condition))							\
		__ret = __wait_event_interruptible_lock_irq(wq_head,		\
						condition, lock,);		\
	__ret;									\
})
#define wait_event_interruptible_lock_irq_cmd(wq_head, condition, lock, cmd)	\
({										\
	int __ret = 0;								\
	if (!(condition))							\
		__ret = __wait_event_interruptible_lock_irq(wq_head,		\
						condition, lock, cmd);		\
	__ret;									\
})
#define wait_event_interruptible_lock_irq_timeout(wq_head, condition, lock,	\
						  timeout)			\
({										\
	long __ret = timeout;							\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_lock_irq_timeout(				\
					wq_head, condition, lock, timeout,	\
					TASK_INTERRUPTIBLE);			\
	__ret;									\
})
#define wait_event_interruptible_locked(wq, condition)				\
	((condition)								\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, do_wait_intr))
#define wait_event_interruptible_locked_irq(wq, condition)			\
	((condition)								\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, do_wait_intr_irq))
#define wait_event_interruptible_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_interruptible_timeout(wq_head,		\
						condition, timeout);		\
	__ret;									\
})
#define wait_event_killable(wq_head, condition)					\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_killable(wq_head, condition);		\
	__ret;									\
})
#define wait_event_killable_exclusive(wq, condition)				\
({										\
	int __ret = 0;								\
	might_sleep();								\
	if (!(condition))							\
		__ret = __wait_event_killable_exclusive(wq, condition);		\
	__ret;									\
})
#define wait_event_killable_timeout(wq_head, condition, timeout)		\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_killable_timeout(wq_head,			\
						condition, timeout);		\
	__ret;									\
})
#define wait_event_lock_irq(wq_head, condition, lock)				\
do {										\
	if (condition)								\
		break;								\
	__wait_event_lock_irq(wq_head, condition, lock, );			\
} while (0)
#define wait_event_lock_irq_cmd(wq_head, condition, lock, cmd)			\
do {										\
	if (condition)								\
		break;								\
	__wait_event_lock_irq(wq_head, condition, lock, cmd);			\
} while (0)
#define wait_event_lock_irq_timeout(wq_head, condition, lock, timeout)		\
({										\
	long __ret = timeout;							\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_lock_irq_timeout(				\
					wq_head, condition, lock, timeout,	\
					TASK_UNINTERRUPTIBLE);			\
	__ret;									\
})
#define wait_event_timeout(wq_head, condition, timeout)				\
({										\
	long __ret = timeout;							\
	might_sleep();								\
	if (!___wait_cond_timeout(condition))					\
		__ret = __wait_event_timeout(wq_head, condition, timeout);	\
	__ret;									\
})
#define wake_up(x)			__wake_up(x, TASK_NORMAL, 1, NULL)
#define wake_up_all(x)			__wake_up(x, TASK_NORMAL, 0, NULL)
#define wake_up_all_locked(x)		__wake_up_locked((x), TASK_NORMAL, 0)
#define wake_up_interruptible(x)	__wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible_nr(x, nr)	__wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_poll(x, m)					\
	__wake_up(x, TASK_INTERRUPTIBLE, 1, poll_to_key(m))
#define wake_up_interruptible_sync(x)	__wake_up_sync((x), TASK_INTERRUPTIBLE)
#define wake_up_interruptible_sync_poll(x, m)					\
	__wake_up_sync_key((x), TASK_INTERRUPTIBLE, poll_to_key(m))
#define wake_up_interruptible_sync_poll_locked(x, m)				\
	__wake_up_locked_sync_key((x), TASK_INTERRUPTIBLE, poll_to_key(m))
#define wake_up_locked(x)		__wake_up_locked((x), TASK_NORMAL, 1)
#define wake_up_locked_poll(x, m)						\
	__wake_up_locked_key((x), TASK_NORMAL, poll_to_key(m))
#define wake_up_nr(x, nr)		__wake_up(x, TASK_NORMAL, nr, NULL)
#define wake_up_poll(x, m)							\
	__wake_up(x, TASK_NORMAL, 1, poll_to_key(m))

#define LOCK_SECTION_END                        \
        ".previous\n\t"
#define LOCK_SECTION_NAME ".text..lock."KBUILD_BASENAME
#define LOCK_SECTION_START(extra)               \
        ".subsection 1\n\t"                     \
        extra                                   \
        ".ifndef " LOCK_SECTION_NAME "\n\t"     \
        LOCK_SECTION_NAME ":\n\t"               \
        ".endif\n"

#define __lockfunc __section(".spinlock.text")
#define alloc_bucket_spinlocks(locks, lock_mask, max_size, cpu_mult, gfp)    \
	({								     \
		static struct lock_class_key key;			     \
		int ret;						     \
									     \
		ret = __alloc_bucket_spinlocks(locks, lock_mask, max_size,   \
					       cpu_mult, gfp, #locks, &key); \
		ret;							     \
	})
#define arch_spin_lock_flags(lock, flags)	arch_spin_lock(lock)
#define assert_spin_locked(lock)	assert_raw_spin_locked(&(lock)->rlock)
#define atomic_dec_and_lock(atomic, lock) \
		__cond_lock(lock, _atomic_dec_and_lock(atomic, lock))
#define atomic_dec_and_lock_irqsave(atomic, lock, flags) \
		__cond_lock(lock, _atomic_dec_and_lock_irqsave(atomic, lock, &(flags)))
#define do_raw_spin_lock_flags(lock, flags) do_raw_spin_lock(lock)
#define raw_spin_is_contended(lock)	arch_spin_is_contended(&(lock)->raw_lock)
#define raw_spin_is_locked(lock)	arch_spin_is_locked(&(lock)->raw_lock)
#define raw_spin_lock(lock)	_raw_spin_lock(lock)
#define raw_spin_lock_bh(lock)		_raw_spin_lock_bh(lock)
# define raw_spin_lock_init(lock)					\
do {									\
	static struct lock_class_key __key;				\
									\
	__raw_spin_lock_init((lock), #lock, &__key, LD_WAIT_SPIN);	\
} while (0)
#define raw_spin_lock_irq(lock)		_raw_spin_lock_irq(lock)
#define raw_spin_lock_irqsave(lock, flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = _raw_spin_lock_irqsave(lock);	\
	} while (0)
#define raw_spin_lock_irqsave_nested(lock, flags, subclass)		\
	do {								\
		typecheck(unsigned long, flags);			\
		flags = _raw_spin_lock_irqsave_nested(lock, subclass);	\
	} while (0)
# define raw_spin_lock_nest_lock(lock, nest_lock)			\
	 do {								\
		 typecheck(struct lockdep_map *, &(nest_lock)->dep_map);\
		 _raw_spin_lock_nest_lock(lock, &(nest_lock)->dep_map);	\
	 } while (0)
# define raw_spin_lock_nested(lock, subclass) \
	_raw_spin_lock_nested(lock, subclass)
#define raw_spin_trylock(lock)	__cond_lock(lock, _raw_spin_trylock(lock))
#define raw_spin_trylock_bh(lock) \
	__cond_lock(lock, _raw_spin_trylock_bh(lock))
#define raw_spin_trylock_irq(lock) \
({ \
	local_irq_disable(); \
	raw_spin_trylock(lock) ? \
	1 : ({ local_irq_enable(); 0;  }); \
})
#define raw_spin_trylock_irqsave(lock, flags) \
({ \
	local_irq_save(flags); \
	raw_spin_trylock(lock) ? \
	1 : ({ local_irq_restore(flags); 0; }); \
})
#define raw_spin_unlock(lock)		_raw_spin_unlock(lock)
#define raw_spin_unlock_bh(lock)	_raw_spin_unlock_bh(lock)
#define raw_spin_unlock_irq(lock)	_raw_spin_unlock_irq(lock)
#define raw_spin_unlock_irqrestore(lock, flags)		\
	do {							\
		typecheck(unsigned long, flags);		\
		_raw_spin_unlock_irqrestore(lock, flags);	\
	} while (0)
#define smp_mb__after_spinlock()	do { } while (0)
# define spin_lock_init(lock)					\
do {								\
	static struct lock_class_key __key;			\
								\
	__raw_spin_lock_init(spinlock_check(lock),		\
			     #lock, &__key, LD_WAIT_CONFIG);	\
} while (0)
#define spin_lock_irqsave(lock, flags)				\
do {								\
	raw_spin_lock_irqsave(spinlock_check(lock), flags);	\
} while (0)
#define spin_lock_irqsave_nested(lock, flags, subclass)			\
do {									\
	raw_spin_lock_irqsave_nested(spinlock_check(lock), flags, subclass); \
} while (0)
#define spin_lock_nest_lock(lock, nest_lock)				\
do {									\
	raw_spin_lock_nest_lock(spinlock_check(lock), nest_lock);	\
} while (0)
#define spin_lock_nested(lock, subclass)			\
do {								\
	raw_spin_lock_nested(spinlock_check(lock), subclass);	\
} while (0)
#define spin_trylock_irqsave(lock, flags)			\
({								\
	raw_spin_trylock_irqsave(spinlock_check(lock), flags); \
})

#define __atomic_op_acquire(op, args...)				\
({									\
	typeof(op##_relaxed(args)) __ret  = op##_relaxed(args);		\
	__atomic_acquire_fence();					\
	__ret;								\
})
#define __atomic_op_fence(op, args...)					\
({									\
	typeof(op##_relaxed(args)) __ret;				\
	__atomic_pre_full_fence();					\
	__ret = op##_relaxed(args);					\
	__atomic_post_full_fence();					\
	__ret;								\
})
#define __atomic_op_release(op, args...)				\
({									\
	__atomic_release_fence();					\
	op##_relaxed(args);						\
})
#define atomic64_cond_read_acquire(v, c) smp_cond_load_acquire(&(v)->counter, (c))
#define atomic64_cond_read_relaxed(v, c) smp_cond_load_relaxed(&(v)->counter, (c))
#define atomic_cond_read_acquire(v, c) smp_cond_load_acquire(&(v)->counter, (c))
#define atomic_cond_read_relaxed(v, c) smp_cond_load_relaxed(&(v)->counter, (c))

#define cmpxchg(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg64(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg64(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg64_acquire(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg64_acquire(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg64_local(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg64_local(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg64_relaxed(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg64_relaxed(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg64_release(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg64_release(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg_acquire(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg_acquire(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg_double(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, 2 * sizeof(*__ai_ptr)); \
	arch_cmpxchg_double(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg_double_local(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, 2 * sizeof(*__ai_ptr)); \
	arch_cmpxchg_double_local(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg_local(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg_local(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg_relaxed(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg_relaxed(__ai_ptr, __VA_ARGS__); \
})
#define cmpxchg_release(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_cmpxchg_release(__ai_ptr, __VA_ARGS__); \
})
#define sync_cmpxchg(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_sync_cmpxchg(__ai_ptr, __VA_ARGS__); \
})
#define try_cmpxchg(ptr, oldp, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	typeof(oldp) __ai_oldp = (oldp); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
	arch_try_cmpxchg(__ai_ptr, __ai_oldp, __VA_ARGS__); \
})
#define try_cmpxchg_acquire(ptr, oldp, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	typeof(oldp) __ai_oldp = (oldp); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
	arch_try_cmpxchg_acquire(__ai_ptr, __ai_oldp, __VA_ARGS__); \
})
#define try_cmpxchg_relaxed(ptr, oldp, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	typeof(oldp) __ai_oldp = (oldp); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
	arch_try_cmpxchg_relaxed(__ai_ptr, __ai_oldp, __VA_ARGS__); \
})
#define try_cmpxchg_release(ptr, oldp, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	typeof(oldp) __ai_oldp = (oldp); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	instrument_atomic_write(__ai_oldp, sizeof(*__ai_oldp)); \
	arch_try_cmpxchg_release(__ai_ptr, __ai_oldp, __VA_ARGS__); \
})
#define xchg(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_xchg(__ai_ptr, __VA_ARGS__); \
})
#define xchg_acquire(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_xchg_acquire(__ai_ptr, __VA_ARGS__); \
})
#define xchg_relaxed(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_xchg_relaxed(__ai_ptr, __VA_ARGS__); \
})
#define xchg_release(ptr, ...) \
({ \
	typeof(ptr) __ai_ptr = (ptr); \
	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr)); \
	arch_xchg_release(__ai_ptr, __VA_ARGS__); \
})

#define ATOMIC_INIT(i) { (i) }
#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]








#define pgoff_t unsigned long
#define rcu_head callback_head

#define __aligned_be64 __be64 __attribute__((aligned(8)))
#define __aligned_le64 __le64 __attribute__((aligned(8)))
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#define __bitwise __bitwise__
#define __bitwise__ __attribute__((bitwise))
#define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
#define ASSERT_EXCLUSIVE_ACCESS_SCOPED(var)                                    \
	__ASSERT_EXCLUSIVE_SCOPED(var, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT, __COUNTER__)
#define ASSERT_EXCLUSIVE_BITS(var, mask)                                       \
	do {                                                                   \
		kcsan_set_access_mask(mask);                                   \
		__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT);\
		kcsan_set_access_mask(0);                                      \
		kcsan_atomic_next(1);                                          \
	} while (0)
#define ASSERT_EXCLUSIVE_WRITER(var)                                           \
	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
#define ASSERT_EXCLUSIVE_WRITER_SCOPED(var)                                    \
	__ASSERT_EXCLUSIVE_SCOPED(var, KCSAN_ACCESS_ASSERT, __COUNTER__)

#define __ASSERT_EXCLUSIVE_SCOPED(var, type, id)                               \
	struct kcsan_scoped_access __kcsan_scoped_name(id, _)                  \
		__kcsan_cleanup_scoped;                                        \
	struct kcsan_scoped_access *__kcsan_scoped_name(id, _dummy_p)          \
		__maybe_unused = kcsan_begin_scoped_access(                    \
			&(var), sizeof(var), KCSAN_ACCESS_SCOPED | (type),     \
			&__kcsan_scoped_name(id, _))
#define __kcsan_check_read(ptr, size) __kcsan_check_access(ptr, size, 0)
#define __kcsan_check_read_write(ptr, size)                                    \
	__kcsan_check_access(ptr, size, KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE)
#define __kcsan_check_write(ptr, size)                                         \
	__kcsan_check_access(ptr, size, KCSAN_ACCESS_WRITE)
#define __kcsan_cleanup_scoped                                                 \
	__maybe_unused __attribute__((__cleanup__(kcsan_end_scoped_access)))
#define __kcsan_disable_current kcsan_disable_current
#define __kcsan_enable_current kcsan_enable_current_nowarn
#define __kcsan_scoped_name(c, suffix) __kcsan_scoped_##c##suffix
#define kcsan_check_access __kcsan_check_access
#define kcsan_check_atomic_read(...)		do { } while (0)
#define kcsan_check_atomic_read_write(...)	do { } while (0)
#define kcsan_check_atomic_write(...)		do { } while (0)
#define kcsan_check_read(ptr, size) kcsan_check_access(ptr, size, 0)
#define kcsan_check_read_write(ptr, size)                                      \
	kcsan_check_access(ptr, size, KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE)
#define kcsan_check_write(ptr, size)                                           \
	kcsan_check_access(ptr, size, KCSAN_ACCESS_WRITE)

#define __alias(symbol)                 __attribute__((__alias__(#symbol)))
#define __aligned(x)                    __attribute__((__aligned__(x)))
#define __aligned_largest               __attribute__((__aligned__))
#define __always_inline                 inline __attribute__((__always_inline__))
#define __always_unused                 __attribute__((__unused__))
# define __assume_aligned(a, ...)       __attribute__((__assume_aligned__(a, ## __VA_ARGS__)))
#define __attribute_const__             __attribute__((__const__))
#define __cold                          __attribute__((__cold__))
# define __compiletime_error(msg)       __attribute__((__error__(msg)))
# define __compiletime_warning(msg)     __attribute__((__warning__(msg)))
# define __copy(symbol)                 __attribute__((__copy__(symbol)))

# define __designated_init              __attribute__((__designated_init__))
#define __gnu_inline                    __attribute__((__gnu_inline__))
#define __malloc                        __attribute__((__malloc__))
#define __maybe_unused                  __attribute__((__unused__))
#define __mode(x)                       __attribute__((__mode__(x)))
#define __must_check                    __attribute__((__warn_unused_result__))
# define __no_caller_saved_registers
# define __no_profile                  __attribute__((__no_profile_instrument_function__))
# define __noclone                      __attribute__((__noclone__))
# define __nonstring                    __attribute__((__nonstring__))
#define __noreturn                      __attribute__((__noreturn__))
#define __packed                        __attribute__((__packed__))
#define __printf(a, b)                  __attribute__((__format__(printf, a, b)))
#define __pure                          __attribute__((__pure__))
#define __scanf(a, b)                   __attribute__((__format__(scanf, a, b)))
#define __section(section)              __attribute__((__section__(section)))
#define __used                          __attribute__((__used__))
# define __visible                      __attribute__((__externally_visible__))
#define __weak                          __attribute__((__weak__))
# define fallthrough                    __attribute__((__fallthrough__))
#define   noinline                      __attribute__((__noinline__))

#define kasan_check_read __kasan_check_read
#define kasan_check_write __kasan_check_write
# define ASM_UNREACHABLE
# define KENTRY(sym)						\
	extern typeof(sym) sym;					\
	static const unsigned long __kentry_##sym		\
	__used							\
	__attribute__((__section__("___kentry+" #sym)))		\
	= (unsigned long)&sym;
#define OPTIMIZER_HIDE_VAR(var)						\
	__asm__ ("" : "=r" (var) : "0" (var))
# define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })
#define __ADDRESSABLE(sym) \
	static void * __section(".discard.addressable") __used \
		__UNIQUE_ID(__PASTE(__addressable_,sym)) = (void *)&sym;


#define __annotate_jump_table __section(".rodata..c_jump_table")
#define __annotate_reachable(c) ({					\
	asm volatile(__stringify_label(c) ":\n\t"			\
		     ".pushsection .discard.reachable\n\t"		\
		     ".long " __stringify_label(c) "b - .\n\t"		\
		     ".popsection\n\t");				\
})
#define __annotate_unreachable(c) ({					\
	asm volatile(__stringify_label(c) ":\n\t"			\
		     ".pushsection .discard.unreachable\n\t"		\
		     ".long " __stringify_label(c) "b - .\n\t"		\
		     ".popsection\n\t");				\
})
#define __branch_check__(x, expect, is_constant) ({			\
			long ______r;					\
			static struct ftrace_likely_data		\
				__aligned(4)				\
				__section("_ftrace_annotated_branch")	\
				______f = {				\
				.data.func = __func__,			\
				.data.file = "__FILE__",			\
				.data.line = "__LINE__",			\
			};						\
			______r = __builtin_expect(!!(x), expect);	\
			ftrace_likely_update(&______f, ______r,		\
					     expect, is_constant);	\
			______r;					\
		})
#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
#define __stringify_label(n) #n
#define __trace_if_value(cond) ({			\
	static struct ftrace_branch_data		\
		__aligned(4)				\
		__section("_ftrace_branch")		\
		__if_trace = {				\
			.func = __func__,		\
			.file = "__FILE__",		\
			.line = "__LINE__",		\
		};					\
	(cond) ?					\
		(__if_trace.miss_hit[1]++,1) :		\
		(__if_trace.miss_hit[0]++,0);		\
})
#define __trace_if_var(cond) (__builtin_constant_p(cond) ? (cond) : __trace_if_value(cond))
#define absolute_pointer(val)	RELOC_HIDE((void *)(val), 0)
#define annotate_reachable() __annotate_reachable(__COUNTER__)
#define annotate_unreachable() __annotate_unreachable(__COUNTER__)
# define barrier() __asm__ __volatile__("": : :"memory")
# define barrier_before_unreachable() do { } while (0)
# define barrier_data(ptr) __asm__ __volatile__("": :"r"(ptr) :"memory")
#define data_race(expr)							\
({									\
	__unqual_scalar_typeof(({ expr; })) __v = ({			\
		__kcsan_disable_current();				\
		expr;							\
	});								\
	__kcsan_enable_current();					\
	__v;								\
})
#define function_nocfi(x) (x)
#define if(cond, ...) if ( __trace_if_var( !!(cond , ## __VA_ARGS__) ) )
#  define likely(x)	(__branch_check__(x, 1, __builtin_constant_p(x)))
# define likely_notrace(x)	likely(x)
#define prevent_tail_call_optimization()	mb()
#  define unlikely(x)	(__branch_check__(x, 0, __builtin_constant_p(x)))
# define unlikely_notrace(x)	unlikely(x)
# define unreachable() do {		\
	annotate_unreachable();		\
	__builtin_unreachable();	\
} while (0)
# define ACCESS_PRIVATE(p, member) (*((typeof((p)->member) __force *) &(p)->member))

#define __PASTE(a,b) ___PASTE(a,b)
#define ___PASTE(a,b) a##b
# define __acquire(x)	__context__(x,1)
# define __acquires(x)	__attribute__((context(x,0,1)))
# define __builtin_warning(x, y...) (1)
# define __cficanonical
# define __chk_io_ptr(x)	(void)0
# define __chk_user_ptr(x)	(void)0
#define __compiler_offsetof(a, b)	__builtin_offsetof(a, b)
# define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)
# define __compiletime_object_size(obj) -1
# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)

#define __diag_GCC(version, severity, string)
#define __diag_error(compiler, version, option, comment) \
	__diag_ ## compiler(version, error, option)
#define __diag_ignore(compiler, version, option, comment) \
	__diag_ ## compiler(version, ignore, option)
#define __diag_pop()	__diag(pop)
#define __diag_push()	__diag(push)
#define __diag_warn(compiler, version, option, comment) \
	__diag_ ## compiler(version, warn, option)
# define __force
#define __has_builtin(x) (0)
#define __inline__ inline
#define __inline_maybe_unused __maybe_unused
# define __iomem
# define __kernel
# define __latent_entropy
# define __must_hold(x)	__attribute__((context(x,1,1)))
#define __native_word(t) \
	(sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || \
	 sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))
# define __no_kasan_or_inline __no_sanitize_address notrace __maybe_unused
#define __no_kcsan __no_sanitize_thread
# define __no_randomize_layout
# define __no_sanitize_or_inline __no_kasan_or_inline
# define __nocast
# define __nocfi
# define __noscs
# define __percpu
# define __private
# define __randomize_layout __designated_init
# define __rcu
# define __release(x)	__context__(x,-1)
# define __releases(x)	__attribute__((context(x,1,0)))
# define __safe
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define __scalar_type_to_expr_cases(type)				\
		unsigned type:	(unsigned type)0,			\
		signed type:	(signed type)0
#define __unqual_scalar_typeof(x) typeof(				\
		_Generic((x),						\
			 char:	(char)0,				\
			 __scalar_type_to_expr_cases(char),		\
			 __scalar_type_to_expr_cases(short),		\
			 __scalar_type_to_expr_cases(int),		\
			 __scalar_type_to_expr_cases(long),		\
			 __scalar_type_to_expr_cases(long long),	\
			 default: (x)))
#  define __user
#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)
#define asm_inline asm __inline
#define asm_volatile_goto(x...) asm goto(x)
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
#define compiletime_assert_atomic_type(t)				\
	compiletime_assert(__native_word(t),				\
		"Need native word sized stores/loads for atomicity.")
#define inline inline __gnu_inline __inline_maybe_unused notrace
#define noinline_for_stack noinline
# define randomized_struct_fields_end
# define randomized_struct_fields_start
#define GCC_VERSION ("__GNUC__" * 10000		\
		     + "__GNUC_MINOR__" * 100	\
		     + "__GNUC_PATCHLEVEL__")
#define KASAN_ABI_VERSION 5



#define __diag_GCC_8(s)		__diag(s)
#define __diag_str(s)		__diag_str1(s)
#define __diag_str1(s)		#s
#define __no_sanitize_address __attribute__((no_sanitize_address))
#define __no_sanitize_coverage __attribute__((no_sanitize_coverage))
#define __no_sanitize_thread __attribute__((no_sanitize_thread))
#define __no_sanitize_undefined __attribute__((no_sanitize_undefined))
#define __noretpoline __attribute__((__indirect_branch__("keep")))
#define __builtin_bswap16 _bswap16


#define BUILD_BUG() BUILD_BUG_ON_MSG(1, "BUILD_BUG failed")
#define BUILD_BUG_ON(condition) \
	BUILD_BUG_ON_MSG(condition, "BUILD_BUG_ON failed: " #condition)
#define BUILD_BUG_ON_INVALID(e) ((void)(sizeof((__force long)(e))))
#define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)
#define BUILD_BUG_ON_NOT_POWER_OF_2(n)			\
	BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))
#define BUILD_BUG_ON_ZERO(e) ((int)(sizeof(struct { int:(-!!(e)); })))

#define __BUILD_BUG_ON_NOT_POWER_OF_2(n)	\
	BUILD_BUG_ON(((n) & ((n) - 1)) != 0)
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#define ATOMIC_LONG_INIT(i)		ATOMIC64_INIT(i)


#define arch_atomic64_add_negative arch_atomic64_add_negative
#define arch_atomic64_add_return arch_atomic64_add_return
#define arch_atomic64_add_return_acquire arch_atomic64_add_return
#define arch_atomic64_add_return_relaxed arch_atomic64_add_return
#define arch_atomic64_add_return_release arch_atomic64_add_return
#define arch_atomic64_add_unless arch_atomic64_add_unless
#define arch_atomic64_andnot arch_atomic64_andnot
#define arch_atomic64_cmpxchg arch_atomic64_cmpxchg
#define arch_atomic64_cmpxchg_acquire arch_atomic64_cmpxchg
#define arch_atomic64_cmpxchg_relaxed arch_atomic64_cmpxchg
#define arch_atomic64_cmpxchg_release arch_atomic64_cmpxchg
#define arch_atomic64_dec arch_atomic64_dec
#define arch_atomic64_dec_and_test arch_atomic64_dec_and_test
#define arch_atomic64_dec_if_positive arch_atomic64_dec_if_positive
#define arch_atomic64_dec_return arch_atomic64_dec_return
#define arch_atomic64_dec_return_acquire arch_atomic64_dec_return
#define arch_atomic64_dec_return_relaxed arch_atomic64_dec_return
#define arch_atomic64_dec_return_release arch_atomic64_dec_return
#define arch_atomic64_dec_unless_positive arch_atomic64_dec_unless_positive
#define arch_atomic64_fetch_add arch_atomic64_fetch_add
#define arch_atomic64_fetch_add_acquire arch_atomic64_fetch_add
#define arch_atomic64_fetch_add_relaxed arch_atomic64_fetch_add
#define arch_atomic64_fetch_add_release arch_atomic64_fetch_add
#define arch_atomic64_fetch_add_unless arch_atomic64_fetch_add_unless
#define arch_atomic64_fetch_and arch_atomic64_fetch_and
#define arch_atomic64_fetch_and_acquire arch_atomic64_fetch_and
#define arch_atomic64_fetch_and_relaxed arch_atomic64_fetch_and
#define arch_atomic64_fetch_and_release arch_atomic64_fetch_and
#define arch_atomic64_fetch_andnot arch_atomic64_fetch_andnot
#define arch_atomic64_fetch_andnot_acquire arch_atomic64_fetch_andnot
#define arch_atomic64_fetch_andnot_relaxed arch_atomic64_fetch_andnot
#define arch_atomic64_fetch_andnot_release arch_atomic64_fetch_andnot
#define arch_atomic64_fetch_dec arch_atomic64_fetch_dec
#define arch_atomic64_fetch_dec_acquire arch_atomic64_fetch_dec
#define arch_atomic64_fetch_dec_relaxed arch_atomic64_fetch_dec
#define arch_atomic64_fetch_dec_release arch_atomic64_fetch_dec
#define arch_atomic64_fetch_inc arch_atomic64_fetch_inc
#define arch_atomic64_fetch_inc_acquire arch_atomic64_fetch_inc
#define arch_atomic64_fetch_inc_relaxed arch_atomic64_fetch_inc
#define arch_atomic64_fetch_inc_release arch_atomic64_fetch_inc
#define arch_atomic64_fetch_or arch_atomic64_fetch_or
#define arch_atomic64_fetch_or_acquire arch_atomic64_fetch_or
#define arch_atomic64_fetch_or_relaxed arch_atomic64_fetch_or
#define arch_atomic64_fetch_or_release arch_atomic64_fetch_or
#define arch_atomic64_fetch_sub arch_atomic64_fetch_sub
#define arch_atomic64_fetch_sub_acquire arch_atomic64_fetch_sub
#define arch_atomic64_fetch_sub_relaxed arch_atomic64_fetch_sub
#define arch_atomic64_fetch_sub_release arch_atomic64_fetch_sub
#define arch_atomic64_fetch_xor arch_atomic64_fetch_xor
#define arch_atomic64_fetch_xor_acquire arch_atomic64_fetch_xor
#define arch_atomic64_fetch_xor_relaxed arch_atomic64_fetch_xor
#define arch_atomic64_fetch_xor_release arch_atomic64_fetch_xor
#define arch_atomic64_inc arch_atomic64_inc
#define arch_atomic64_inc_and_test arch_atomic64_inc_and_test
#define arch_atomic64_inc_not_zero arch_atomic64_inc_not_zero
#define arch_atomic64_inc_return arch_atomic64_inc_return
#define arch_atomic64_inc_return_acquire arch_atomic64_inc_return
#define arch_atomic64_inc_return_relaxed arch_atomic64_inc_return
#define arch_atomic64_inc_return_release arch_atomic64_inc_return
#define arch_atomic64_inc_unless_negative arch_atomic64_inc_unless_negative
#define arch_atomic64_read_acquire arch_atomic64_read_acquire
#define arch_atomic64_set_release arch_atomic64_set_release
#define arch_atomic64_sub_and_test arch_atomic64_sub_and_test
#define arch_atomic64_sub_return arch_atomic64_sub_return
#define arch_atomic64_sub_return_acquire arch_atomic64_sub_return
#define arch_atomic64_sub_return_relaxed arch_atomic64_sub_return
#define arch_atomic64_sub_return_release arch_atomic64_sub_return
#define arch_atomic64_try_cmpxchg arch_atomic64_try_cmpxchg
#define arch_atomic64_try_cmpxchg_acquire arch_atomic64_try_cmpxchg
#define arch_atomic64_try_cmpxchg_relaxed arch_atomic64_try_cmpxchg
#define arch_atomic64_try_cmpxchg_release arch_atomic64_try_cmpxchg
#define arch_atomic64_xchg arch_atomic64_xchg
#define arch_atomic64_xchg_acquire arch_atomic64_xchg
#define arch_atomic64_xchg_relaxed arch_atomic64_xchg
#define arch_atomic64_xchg_release arch_atomic64_xchg
#define arch_atomic_add_negative arch_atomic_add_negative
#define arch_atomic_add_return arch_atomic_add_return
#define arch_atomic_add_return_acquire arch_atomic_add_return
#define arch_atomic_add_return_relaxed arch_atomic_add_return
#define arch_atomic_add_return_release arch_atomic_add_return
#define arch_atomic_add_unless arch_atomic_add_unless
#define arch_atomic_andnot arch_atomic_andnot
#define arch_atomic_cmpxchg arch_atomic_cmpxchg
#define arch_atomic_cmpxchg_acquire arch_atomic_cmpxchg
#define arch_atomic_cmpxchg_relaxed arch_atomic_cmpxchg
#define arch_atomic_cmpxchg_release arch_atomic_cmpxchg
#define arch_atomic_dec arch_atomic_dec
#define arch_atomic_dec_and_test arch_atomic_dec_and_test
#define arch_atomic_dec_if_positive arch_atomic_dec_if_positive
#define arch_atomic_dec_return arch_atomic_dec_return
#define arch_atomic_dec_return_acquire arch_atomic_dec_return
#define arch_atomic_dec_return_relaxed arch_atomic_dec_return
#define arch_atomic_dec_return_release arch_atomic_dec_return
#define arch_atomic_dec_unless_positive arch_atomic_dec_unless_positive
#define arch_atomic_fetch_add arch_atomic_fetch_add
#define arch_atomic_fetch_add_acquire arch_atomic_fetch_add
#define arch_atomic_fetch_add_relaxed arch_atomic_fetch_add
#define arch_atomic_fetch_add_release arch_atomic_fetch_add
#define arch_atomic_fetch_add_unless arch_atomic_fetch_add_unless
#define arch_atomic_fetch_and arch_atomic_fetch_and
#define arch_atomic_fetch_and_acquire arch_atomic_fetch_and
#define arch_atomic_fetch_and_relaxed arch_atomic_fetch_and
#define arch_atomic_fetch_and_release arch_atomic_fetch_and
#define arch_atomic_fetch_andnot arch_atomic_fetch_andnot
#define arch_atomic_fetch_andnot_acquire arch_atomic_fetch_andnot
#define arch_atomic_fetch_andnot_relaxed arch_atomic_fetch_andnot
#define arch_atomic_fetch_andnot_release arch_atomic_fetch_andnot
#define arch_atomic_fetch_dec arch_atomic_fetch_dec
#define arch_atomic_fetch_dec_acquire arch_atomic_fetch_dec
#define arch_atomic_fetch_dec_relaxed arch_atomic_fetch_dec
#define arch_atomic_fetch_dec_release arch_atomic_fetch_dec
#define arch_atomic_fetch_inc arch_atomic_fetch_inc
#define arch_atomic_fetch_inc_acquire arch_atomic_fetch_inc
#define arch_atomic_fetch_inc_relaxed arch_atomic_fetch_inc
#define arch_atomic_fetch_inc_release arch_atomic_fetch_inc
#define arch_atomic_fetch_or arch_atomic_fetch_or
#define arch_atomic_fetch_or_acquire arch_atomic_fetch_or
#define arch_atomic_fetch_or_relaxed arch_atomic_fetch_or
#define arch_atomic_fetch_or_release arch_atomic_fetch_or
#define arch_atomic_fetch_sub arch_atomic_fetch_sub
#define arch_atomic_fetch_sub_acquire arch_atomic_fetch_sub
#define arch_atomic_fetch_sub_relaxed arch_atomic_fetch_sub
#define arch_atomic_fetch_sub_release arch_atomic_fetch_sub
#define arch_atomic_fetch_xor arch_atomic_fetch_xor
#define arch_atomic_fetch_xor_acquire arch_atomic_fetch_xor
#define arch_atomic_fetch_xor_relaxed arch_atomic_fetch_xor
#define arch_atomic_fetch_xor_release arch_atomic_fetch_xor
#define arch_atomic_inc arch_atomic_inc
#define arch_atomic_inc_and_test arch_atomic_inc_and_test
#define arch_atomic_inc_not_zero arch_atomic_inc_not_zero
#define arch_atomic_inc_return arch_atomic_inc_return
#define arch_atomic_inc_return_acquire arch_atomic_inc_return
#define arch_atomic_inc_return_relaxed arch_atomic_inc_return
#define arch_atomic_inc_return_release arch_atomic_inc_return
#define arch_atomic_inc_unless_negative arch_atomic_inc_unless_negative
#define arch_atomic_read_acquire arch_atomic_read_acquire
#define arch_atomic_set_release arch_atomic_set_release
#define arch_atomic_sub_and_test arch_atomic_sub_and_test
#define arch_atomic_sub_return arch_atomic_sub_return
#define arch_atomic_sub_return_acquire arch_atomic_sub_return
#define arch_atomic_sub_return_relaxed arch_atomic_sub_return
#define arch_atomic_sub_return_release arch_atomic_sub_return
#define arch_atomic_try_cmpxchg arch_atomic_try_cmpxchg
#define arch_atomic_try_cmpxchg_acquire arch_atomic_try_cmpxchg_acquire
#define arch_atomic_try_cmpxchg_relaxed arch_atomic_try_cmpxchg_relaxed
#define arch_atomic_try_cmpxchg_release arch_atomic_try_cmpxchg_release
#define arch_atomic_xchg arch_atomic_xchg
#define arch_atomic_xchg_acquire arch_atomic_xchg
#define arch_atomic_xchg_relaxed arch_atomic_xchg
#define arch_atomic_xchg_release arch_atomic_xchg
#define arch_cmpxchg(...) \
	__atomic_op_fence(arch_cmpxchg, __VA_ARGS__)
#define arch_cmpxchg64(...) \
	__atomic_op_fence(arch_cmpxchg64, __VA_ARGS__)
#define arch_cmpxchg64_acquire arch_cmpxchg64
#define arch_cmpxchg64_relaxed arch_cmpxchg64
#define arch_cmpxchg64_release arch_cmpxchg64
#define arch_cmpxchg_acquire arch_cmpxchg
#define arch_cmpxchg_relaxed arch_cmpxchg
#define arch_cmpxchg_release arch_cmpxchg
#define arch_try_cmpxchg(...) \
	__atomic_op_fence(arch_try_cmpxchg, __VA_ARGS__)
#define arch_try_cmpxchg_acquire arch_try_cmpxchg
#define arch_try_cmpxchg_relaxed arch_try_cmpxchg
#define arch_try_cmpxchg_release arch_try_cmpxchg
#define arch_xchg(...) \
	__atomic_op_fence(arch_xchg, __VA_ARGS__)
#define arch_xchg_acquire arch_xchg
#define arch_xchg_relaxed arch_xchg
#define arch_xchg_release arch_xchg
#define ATOMIC64_FETCH_OP(op)						\
extern s64 generic_atomic64_fetch_##op(s64 a, atomic64_t *v);
#define ATOMIC64_INIT(i)	{ (i) }
#define ATOMIC64_OP(op)							\
extern void generic_atomic64_##op(s64 a, atomic64_t *v);
#define ATOMIC64_OPS(op)	ATOMIC64_OP(op) ATOMIC64_OP_RETURN(op) ATOMIC64_FETCH_OP(op)
#define ATOMIC64_OP_RETURN(op)						\
extern s64 generic_atomic64_##op##_return(s64 a, atomic64_t *v);


# define arch_read_lock_flags(lock, flags)	arch_read_lock(lock)
# define arch_write_lock_flags(lock, flags)	arch_write_lock(lock)
# define do_raw_read_lock(rwlock)	do {__acquire(lock); arch_read_lock(&(rwlock)->raw_lock); } while (0)
# define do_raw_read_lock_flags(lock, flags) \
		do {__acquire(lock); arch_read_lock_flags(&(lock)->raw_lock, *(flags)); } while (0)
# define do_raw_read_trylock(rwlock)	arch_read_trylock(&(rwlock)->raw_lock)
# define do_raw_read_unlock(rwlock)	do {arch_read_unlock(&(rwlock)->raw_lock); __release(lock); } while (0)
# define do_raw_write_lock(rwlock)	do {__acquire(lock); arch_write_lock(&(rwlock)->raw_lock); } while (0)
# define do_raw_write_lock_flags(lock, flags) \
		do {__acquire(lock); arch_write_lock_flags(&(lock)->raw_lock, *(flags)); } while (0)
# define do_raw_write_trylock(rwlock)	arch_write_trylock(&(rwlock)->raw_lock)
# define do_raw_write_unlock(rwlock)	do {arch_write_unlock(&(rwlock)->raw_lock); __release(lock); } while (0)
#define read_lock(lock)		_raw_read_lock(lock)
#define read_lock_bh(lock)		_raw_read_lock_bh(lock)
#define read_lock_irq(lock)		_raw_read_lock_irq(lock)
#define read_lock_irqsave(lock, flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = _raw_read_lock_irqsave(lock);	\
	} while (0)
#define read_trylock(lock)	__cond_lock(lock, _raw_read_trylock(lock))
#define read_unlock(lock)		_raw_read_unlock(lock)
#define read_unlock_bh(lock)		_raw_read_unlock_bh(lock)
#define read_unlock_irq(lock)		_raw_read_unlock_irq(lock)
#define read_unlock_irqrestore(lock, flags)			\
	do {							\
		typecheck(unsigned long, flags);		\
		_raw_read_unlock_irqrestore(lock, flags);	\
	} while (0)
# define rwlock_init(lock)					\
do {								\
	static struct lock_class_key __key;			\
								\
	__rwlock_init((lock), #lock, &__key);			\
} while (0)
#define rwlock_is_contended(lock) \
	 arch_rwlock_is_contended(&(lock)->raw_lock)
#define write_lock(lock)	_raw_write_lock(lock)
#define write_lock_bh(lock)		_raw_write_lock_bh(lock)
#define write_lock_irq(lock)		_raw_write_lock_irq(lock)
#define write_lock_irqsave(lock, flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = _raw_write_lock_irqsave(lock);	\
	} while (0)
#define write_trylock(lock)	__cond_lock(lock, _raw_write_trylock(lock))
#define write_trylock_irqsave(lock, flags) \
({ \
	local_irq_save(flags); \
	write_trylock(lock) ? \
	1 : ({ local_irq_restore(flags); 0; }); \
})
#define write_unlock(lock)		_raw_write_unlock(lock)
#define write_unlock_bh(lock)		_raw_write_unlock_bh(lock)
#define write_unlock_irq(lock)		_raw_write_unlock_irq(lock)
#define write_unlock_irqrestore(lock, flags)		\
	do {						\
		typecheck(unsigned long, flags);	\
		_raw_write_unlock_irqrestore(lock, flags);	\
	} while (0)
#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
# define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))

#define __LOCAL_SPIN_LOCK_UNLOCKED(name)			\
	{							\
		.lock = __RT_MUTEX_BASE_INITIALIZER(name.lock),	\
		LOCAL_SPIN_DEP_MAP_INIT(name)			\
	}
#define __SPIN_LOCK_INITIALIZER(lockname) \
	{ { .rlock = ___SPIN_LOCK_INITIALIZER(lockname) } }
#define __SPIN_LOCK_UNLOCKED(lockname) \
	(spinlock_t) __SPIN_LOCK_INITIALIZER(lockname)
#define ___SPIN_LOCK_INITIALIZER(lockname)	\
	{					\
	.raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,	\
	SPIN_DEBUG_INIT(lockname)		\
	SPIN_DEP_MAP_INIT(lockname) }
#define DEFINE_RWLOCK(x)	rwlock_t x = __RW_LOCK_UNLOCKED(x)
# define RW_DEP_MAP_INIT(lockname)

#define __RWLOCK_RT_INITIALIZER(name)					\
{									\
	.rwbase = __RWBASE_INITIALIZER(name),				\
	RW_DEP_MAP_INIT(name)						\
}
#define __RW_LOCK_UNLOCKED(lockname)					\
	(rwlock_t)	{	.raw_lock = __ARCH_RW_LOCK_UNLOCKED,	\
				.magic = RWLOCK_MAGIC,			\
				.owner = SPINLOCK_OWNER_INIT,		\
				.owner_cpu = -1,			\
				RW_DEP_MAP_INIT(lockname) }

#define __RWBASE_INITIALIZER(name)				\
{								\
	.readers = ATOMIC_INIT(READER_BIAS),			\
	.rtmutex = __RT_MUTEX_BASE_INITIALIZER(name.rtmutex),	\
}
#define init_rwbase_rt(rwbase)					\
	do {							\
		rt_mutex_base_init(&(rwbase)->rtmutex);		\
		atomic_set(&(rwbase)->readers, READER_BIAS);	\
	} while (0)
#define DEFINE_RT_MUTEX(mutexname) \
	struct rt_mutex mutexname = __RT_MUTEX_INITIALIZER(mutexname)
#define __DEP_MAP_RT_MUTEX_INITIALIZER(mutexname)	\
	.dep_map = {					\
		.name = #mutexname,			\
		.wait_type_inner = LD_WAIT_SLEEP,	\
	}

#define __RT_MUTEX_BASE_INITIALIZER(rtbasename)				\
{									\
	.wait_lock = __RAW_SPIN_LOCK_UNLOCKED(rtbasename.wait_lock),	\
	.waiters = RB_ROOT_CACHED,					\
	.owner = NULL							\
}
#define __RT_MUTEX_INITIALIZER(mutexname)				\
{									\
	.rtmutex = __RT_MUTEX_BASE_INITIALIZER(mutexname.rtmutex),	\
	__DEP_MAP_RT_MUTEX_INITIALIZER(mutexname)			\
}
#define rt_mutex_init(mutex) \
do { \
	static struct lock_class_key __key; \
	__rt_mutex_init(mutex, __func__, &__key); \
} while (0)
#define rt_mutex_lock(lock) rt_mutex_lock_nested(lock, 0)
#define rt_mutex_lock_nested(lock, subclass) rt_mutex_lock(lock)
#define DEFINE_RAW_SPINLOCK(x)  raw_spinlock_t x = __RAW_SPIN_LOCK_UNLOCKED(x)
# define LOCAL_SPIN_DEP_MAP_INIT(lockname)		\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_CONFIG,	\
		.lock_type = LD_LOCK_PERCPU,		\
	}
# define RAW_SPIN_DEP_MAP_INIT(lockname)		\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_SPIN,	\
	}
# define SPIN_DEBUG_INIT(lockname)		\
	.magic = SPINLOCK_MAGIC,		\
	.owner_cpu = -1,			\
	.owner = SPINLOCK_OWNER_INIT,
# define SPIN_DEP_MAP_INIT(lockname)			\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_CONFIG,	\
	}

#define __RAW_SPIN_LOCK_INITIALIZER(lockname)	\
{						\
	.raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,	\
	SPIN_DEBUG_INIT(lockname)		\
	RAW_SPIN_DEP_MAP_INIT(lockname) }
#define __RAW_SPIN_LOCK_UNLOCKED(lockname)	\
	(raw_spinlock_t) __RAW_SPIN_LOCK_INITIALIZER(lockname)

#define RB_ROOT (struct rb_root) { NULL, }
#define RB_ROOT_CACHED (struct rb_root_cached) { {NULL, }, NULL }

#define ALIGN __ALIGN
#define ALIGN_STR __ALIGN_STR
#define CPP_ASMLINKAGE extern "C"
#define END(name) \
	.size name, .-name
#define ENDPROC(name) \
	SYM_FUNC_END(name)
#define ENTRY(name) \
	SYM_FUNC_START(name)
#define GLOBAL(name) \
	.globl name ASM_NL \
	name:
#define SYM_CODE_END(name)				\
	SYM_END(name, SYM_T_NONE)
#define SYM_CODE_START(name)				\
	SYM_START(name, SYM_L_GLOBAL, SYM_A_ALIGN)
#define SYM_CODE_START_LOCAL(name)			\
	SYM_START(name, SYM_L_LOCAL, SYM_A_ALIGN)
#define SYM_CODE_START_LOCAL_NOALIGN(name)		\
	SYM_START(name, SYM_L_LOCAL, SYM_A_NONE)
#define SYM_CODE_START_NOALIGN(name)			\
	SYM_START(name, SYM_L_GLOBAL, SYM_A_NONE)
#define SYM_DATA(name, data...)				\
	SYM_DATA_START(name) ASM_NL				\
	data ASM_NL						\
	SYM_DATA_END(name)
#define SYM_DATA_END(name)				\
	SYM_END(name, SYM_T_OBJECT)
#define SYM_DATA_END_LABEL(name, linkage, label)	\
	linkage(label) ASM_NL				\
	.type label SYM_T_OBJECT ASM_NL			\
	label:						\
	SYM_END(name, SYM_T_OBJECT)
#define SYM_DATA_LOCAL(name, data...)			\
	SYM_DATA_START_LOCAL(name) ASM_NL			\
	data ASM_NL						\
	SYM_DATA_END(name)
#define SYM_DATA_START(name)				\
	SYM_START(name, SYM_L_GLOBAL, SYM_A_NONE)
#define SYM_DATA_START_LOCAL(name)			\
	SYM_START(name, SYM_L_LOCAL, SYM_A_NONE)
#define SYM_END(name, sym_type)				\
	.type name sym_type ASM_NL			\
	.size name, .-name
#define SYM_ENTRY(name, linkage, align...)		\
	linkage(name) ASM_NL				\
	align ASM_NL					\
	name:
#define SYM_FUNC_END(name)				\
	SYM_END(name, SYM_T_FUNC)
#define SYM_FUNC_END_ALIAS(name)			\
	SYM_END(name, SYM_T_FUNC)
#define SYM_FUNC_START(name)				\
	SYM_START(name, SYM_L_GLOBAL, SYM_A_ALIGN)
#define SYM_FUNC_START_ALIAS(name)			\
	SYM_START(name, SYM_L_GLOBAL, SYM_A_ALIGN)
#define SYM_FUNC_START_LOCAL(name)			\
	SYM_START(name, SYM_L_LOCAL, SYM_A_ALIGN)
#define SYM_FUNC_START_LOCAL_ALIAS(name)		\
	SYM_START(name, SYM_L_LOCAL, SYM_A_ALIGN)
#define SYM_FUNC_START_LOCAL_NOALIGN(name)		\
	SYM_START(name, SYM_L_LOCAL, SYM_A_NONE)
#define SYM_FUNC_START_NOALIGN(name)			\
	SYM_START(name, SYM_L_GLOBAL, SYM_A_NONE)
#define SYM_FUNC_START_WEAK(name)			\
	SYM_START(name, SYM_L_WEAK, SYM_A_ALIGN)
#define SYM_FUNC_START_WEAK_NOALIGN(name)		\
	SYM_START(name, SYM_L_WEAK, SYM_A_NONE)
#define SYM_INNER_LABEL(name, linkage)		\
	.type name SYM_T_NONE ASM_NL			\
	SYM_ENTRY(name, linkage, SYM_A_NONE)
#define SYM_INNER_LABEL_ALIGN(name, linkage)	\
	.type name SYM_T_NONE ASM_NL			\
	SYM_ENTRY(name, linkage, SYM_A_ALIGN)
#define SYM_L_GLOBAL(name)			.globl name
#define SYM_L_WEAK(name)			.weak name
#define SYM_START(name, linkage, align...)		\
	SYM_ENTRY(name, linkage, align)
#define SYSCALL_ALIAS(alias, name) asm(			\
	".globl " __stringify(alias) "\n\t"		\
	".set   " __stringify(alias) ","		\
		  __stringify(name))
#define WEAK(name)	   \
	SYM_FUNC_START_WEAK(name)

#define asmlinkage CPP_ASMLINKAGE
# define asmlinkage_protect(n, ret, args...)	do { } while (0)
#define cond_syscall(x)	asm(				\
	".weak " __stringify(x) "\n\t"			\
	".set  " __stringify(x) ","			\
		 __stringify(sys_ni_syscall))
#define EXPORT_SYMBOL(sym)		_EXPORT_SYMBOL(sym, "")
#define EXPORT_SYMBOL_GPL(sym)		_EXPORT_SYMBOL(sym, "_gpl")
#define EXPORT_SYMBOL_NS(sym, ns)	__EXPORT_SYMBOL(sym, "", #ns)
#define EXPORT_SYMBOL_NS_GPL(sym, ns)	__EXPORT_SYMBOL(sym, "_gpl", #ns)
#define THIS_MODULE (&__this_module)
#define _EXPORT_SYMBOL(sym, sec)	__EXPORT_SYMBOL(sym, sec, __stringify(DEFAULT_SYMBOL_NAMESPACE))

#define __CRC_SYMBOL(sym, sec)						\
	asm("	.section \"___kcrctab" sec "+" #sym "\", \"a\"	\n"	\
	    "	.weak	__crc_" #sym "				\n"	\
	    "	.long	__crc_" #sym " - .			\n"	\
	    "	.previous					\n")
#define __EXPORT_SYMBOL(sym, sec, ns)
#define __KSYMTAB_ENTRY(sym, sec)					\
	__ADDRESSABLE(sym)						\
	asm("	.section \"___ksymtab" sec "+" #sym "\", \"a\"	\n"	\
	    "	.balign	4					\n"	\
	    "__ksymtab_" #sym ":				\n"	\
	    "	.long	" #sym "- .				\n"	\
	    "	.long	__kstrtab_" #sym "- .			\n"	\
	    "	.long	__kstrtabns_" #sym "- .			\n"	\
	    "	.previous					\n")
#define ___EXPORT_SYMBOL(sym, sec, ns)	__GENKSYMS_EXPORT_SYMBOL(sym)
#define ___cond_export_sym(sym, sec, ns, enabled)			\
	__cond_export_sym_##enabled(sym, sec, ns)
#define __cond_export_sym(sym, sec, ns, conf)				\
	___cond_export_sym(sym, sec, ns, conf)
#define __cond_export_sym_0(sym, sec, ns) __GENKSYMS_EXPORT_SYMBOL(sym)
#define __cond_export_sym_1(sym, sec, ns) ___EXPORT_SYMBOL(sym, sec, ns)
#define __ksym_marker(sym)	\
	static int __ksym_marker_##sym[0] __section(".discard.ksym") __used

#define __stringify(x...)	__stringify_1(x)
#define __stringify_1(x...)	#x
#define LOCK_CONTENDED(_lock, try, lock)			\
do {								\
	if (!try(_lock)) {					\
		lock_contended(&(_lock)->dep_map, _RET_IP_);	\
		lock(_lock);					\
	}							\
	lock_acquired(&(_lock)->dep_map, _RET_IP_);			\
} while (0)
#define LOCK_CONTENDED_FLAGS(_lock, try, lock, lockfl, flags) \
	LOCK_CONTENDED((_lock), (try), (lock))
#define LOCK_CONTENDED_RETURN(_lock, try, lock)			\
({								\
	int ____err = 0;					\
	if (!try(_lock)) {					\
		lock_contended(&(_lock)->dep_map, _RET_IP_);	\
		____err = lock(_lock);				\
	}							\
	if (!____err)						\
		lock_acquired(&(_lock)->dep_map, _RET_IP_);	\
	____err;						\
})
#define NIL_COOKIE (struct pin_cookie){ .val = 0U, }
#define STATIC_LOCKDEP_MAP_INIT(_name, _key) \
	{ .name = (_name), .key = (void *)(_key), }

#define force_read_lock_recursive 0
# define lock_acquire(l, s, t, r, c, n, i)	do { } while (0)
#define lock_acquire_exclusive(l, s, t, n, i)		lock_acquire(l, s, t, 0, 1, n, i)
#define lock_acquire_shared(l, s, t, n, i)		lock_acquire(l, s, t, 1, 1, n, i)
#define lock_acquire_shared_recursive(l, s, t, n, i)	lock_acquire(l, s, t, 2, 1, n, i)
#define lock_acquired(lockdep_map, ip) do {} while (0)
#define lock_contended(lockdep_map, ip) do {} while (0)
# define lock_downgrade(l, i)			do { } while (0)
#define lock_map_acquire(l)			lock_acquire_exclusive(l, 0, 0, NULL, _THIS_IP_)
#define lock_map_acquire_read(l)		lock_acquire_shared_recursive(l, 0, 0, NULL, _THIS_IP_)
#define lock_map_acquire_tryread(l)		lock_acquire_shared_recursive(l, 0, 1, NULL, _THIS_IP_)
#define lock_map_release(l)			lock_release(l, _THIS_IP_)
# define lock_release(l, i)			do { } while (0)
# define lock_set_class(l, n, k, s, i)		do { } while (0)
# define lock_set_subclass(l, s, i)		do { } while (0)
#define lockdep_assert(cond)		\
	do { WARN_ON(debug_locks && !(cond)); } while (0)
# define lockdep_assert_RT_in_threaded_ctx() do {			\
		WARN_ONCE(debug_locks && !current->lockdep_recursion &&	\
			  lockdep_hardirq_context() &&			\
			  !(current->hardirq_threaded || current->irq_config),	\
			  "Not in threaded context on PREEMPT_RT as expected\n");	\
} while (0)
#define lockdep_assert_held(l)		\
	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
#define lockdep_assert_held_once(l)		\
	lockdep_assert_once(lockdep_is_held(l) != LOCK_STATE_NOT_HELD)
#define lockdep_assert_held_read(l)	\
	lockdep_assert(lockdep_is_held_type(l, 1))
#define lockdep_assert_held_write(l)	\
	lockdep_assert(lockdep_is_held_type(l, 0))
# define lockdep_assert_in_irq() do { } while (0)
# define lockdep_assert_in_softirq() do { } while (0)
# define lockdep_assert_irqs_disabled() do { } while (0)
# define lockdep_assert_irqs_enabled() do { } while (0)
#define lockdep_assert_none_held_once()		\
	lockdep_assert_once(!current->lockdep_depth)
#define lockdep_assert_not_held(l)	\
	lockdep_assert(lockdep_is_held(l) != LOCK_STATE_HELD)
#define lockdep_assert_once(cond)	\
	do { WARN_ON_ONCE(debug_locks && !(cond)); } while (0)
# define lockdep_assert_preemption_disabled() do { } while (0)
# define lockdep_assert_preemption_enabled() do { } while (0)
#define lockdep_depth(tsk)	(debug_locks ? (tsk)->lockdep_depth : 0)
# define lockdep_free_key_range(start, size)	do { } while (0)
# define lockdep_init()				do { } while (0)
# define lockdep_init_map(lock, name, key, sub) \
		do { (void)(name); (void)(key); } while (0)
#define lockdep_init_map_crosslock(m, n, k, s) do {} while (0)
# define lockdep_init_map_type(lock, name, key, sub, inner, outer, type) \
		do { (void)(name); (void)(key); } while (0)
# define lockdep_init_map_wait(lock, name, key, sub, inner) \
		do { (void)(name); (void)(key); } while (0)
# define lockdep_init_map_waits(lock, name, key, sub, inner, outer) \
		do { (void)(name); (void)(key); } while (0)
#define lockdep_is_held(lock)		lock_is_held(&(lock)->dep_map)
#define lockdep_is_held_type(lock, r)	lock_is_held_type(&(lock)->dep_map, (r))
#define lockdep_match_class(lock, key) lockdep_match_key(&(lock)->dep_map, key)
#define lockdep_off()					\
do {							\
	current->lockdep_recursion += LOCKDEP_OFF;	\
} while (0)
#define lockdep_on()					\
do {							\
	current->lockdep_recursion -= LOCKDEP_OFF;	\
} while (0)
#define lockdep_pin_lock(l)	lock_pin_lock(&(l)->dep_map)
#define lockdep_recursing(tsk)	((tsk)->lockdep_recursion)
#define lockdep_repin_lock(l,c)	lock_repin_lock(&(l)->dep_map, (c))
# define lockdep_reset()		do { debug_locks = 1; } while (0)
# define lockdep_set_class(lock, key)		do { (void)(key); } while (0)
# define lockdep_set_class_and_name(lock, key, name) \
		do { (void)(key); (void)(name); } while (0)
#define lockdep_set_class_and_subclass(lock, key, sub)		\
	lockdep_init_map_waits(&(lock)->dep_map, #key, key, sub,\
			       (lock)->dep_map.wait_type_inner,	\
			       (lock)->dep_map.wait_type_outer)
#define lockdep_set_novalidate_class(lock) \
	lockdep_set_class_and_name(lock, &__lockdep_no_validate__, #lock)
#define lockdep_set_subclass(lock, sub)					\
	lockdep_init_map_waits(&(lock)->dep_map, #lock, (lock)->dep_map.key, sub,\
			       (lock)->dep_map.wait_type_inner,		\
			       (lock)->dep_map.wait_type_outer)
# define lockdep_sys_exit() 			do { } while (0)
#define lockdep_unpin_lock(l,c)	lock_unpin_lock(&(l)->dep_map, (c))
# define might_lock(lock)						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 0, 1, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, _THIS_IP_);			\
} while (0)
# define might_lock_nested(lock, subclass)				\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, subclass, 0, 1, 1, NULL,		\
		     _THIS_IP_);					\
	lock_release(&(lock)->dep_map, _THIS_IP_);			\
} while (0)
# define might_lock_read(lock)						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 1, 1, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, _THIS_IP_);			\
} while (0)
#define mutex_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define mutex_acquire_nest(l, s, t, n, i)	lock_acquire_exclusive(l, s, t, n, i)
#define mutex_release(l, i)			lock_release(l, i)
#define read_lock_is_recursive() 0
#define rwlock_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define rwlock_acquire_read(l, s, t, i)					\
do {									\
	if (read_lock_is_recursive())					\
		lock_acquire_shared_recursive(l, s, t, NULL, i);	\
	else								\
		lock_acquire_shared(l, s, t, NULL, i);			\
} while (0)
#define rwlock_release(l, i)			lock_release(l, i)
#define rwsem_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define rwsem_acquire_nest(l, s, t, n, i)	lock_acquire_exclusive(l, s, t, n, i)
#define rwsem_acquire_read(l, s, t, i)		lock_acquire_shared(l, s, t, NULL, i)
#define rwsem_release(l, i)			lock_release(l, i)
#define seqcount_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define seqcount_acquire_read(l, s, t, i)	lock_acquire_shared_recursive(l, s, t, NULL, i)
#define seqcount_release(l, i)			lock_release(l, i)
#define spin_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define spin_acquire_nest(l, s, t, n, i)	lock_acquire_exclusive(l, s, t, n, i)
#define spin_release(l, i)			lock_release(l, i)

#define DEBUG_LOCKS_WARN_ON(c)						\
({									\
	int __ret = 0;							\
									\
	if (!oops_in_progress && unlikely(c)) {				\
		instrumentation_begin();				\
		if (debug_locks_off() && !debug_locks_silent)		\
			WARN(1, "DEBUG_LOCKS_WARN_ON(%s)", #c);		\
		instrumentation_end();					\
		__ret = 1;						\
	}								\
	__ret;								\
})
# define SMP_DEBUG_LOCKS_WARN_ON(c)			DEBUG_LOCKS_WARN_ON(c)

# define locking_selftest()	do { } while (0)
#define INTERNODE_CACHE_SHIFT L1_CACHE_SHIFT
#define L1_CACHE_ALIGN(x) __ALIGN_KERNEL(x, L1_CACHE_BYTES)
#define SMP_CACHE_BYTES L1_CACHE_BYTES

#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#define ____cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))
#define __cacheline_aligned_in_smp __cacheline_aligned

#define __ro_after_init __section(".data..ro_after_init")
#define cache_line_size()	L1_CACHE_BYTES


#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))
#define UL(x)		(_UL(x))
#define ULL(x)		(_ULL(x))

#define _AC(X,Y)	X
#define _AT(T,X)	X
#define _BITUL(x)	(_UL(1) << (x))
#define _BITULL(x)	(_ULL(1) << (x))

#define _UL(x)		(_AC(x, UL))
#define _ULL(x)		(_AC(x, ULL))
#define __AC(X,Y)	(X##Y)
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define HLIST_HEAD_INIT { .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)
#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define hlist_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
	})
#define hlist_for_each(pos, head) \
	for (pos = (head)->first; pos ; pos = pos->next)
#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))
#define hlist_for_each_entry_continue(pos, member)			\
	for (pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member);\
	     pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))
#define hlist_for_each_entry_from(pos, member)				\
	for (; pos;							\
	     pos = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))
#define hlist_for_each_entry_safe(pos, n, head, member) 		\
	for (pos = hlist_entry_safe((head)->first, typeof(*pos), member);\
	     pos && ({ n = pos->member.next; 1; });			\
	     pos = hlist_entry_safe(n, typeof(*pos), member))
#define hlist_for_each_safe(pos, n, head) \
	for (pos = (head)->first; pos && ({ n = pos->next; 1; }); \
	     pos = n)
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)
#define list_entry_is_head(pos, head, member)				\
	(&pos->member == (head))
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#define list_first_entry_or_null(ptr, type, member) ({ \
	struct list_head *head__ = (ptr); \
	struct list_head *pos__ = READ_ONCE(head__->next); \
	pos__ != head__ ? list_entry(pos__, type, member) : NULL; \
})
#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_continue(pos, head) \
	for (pos = pos->next; pos != (head); pos = pos->next)
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_next_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_continue_reverse(pos, head, member)		\
	for (pos = list_prev_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_from(pos, head, member) 			\
	for (; !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_from_reverse(pos, head, member)		\
	for (; !list_entry_is_head(pos, head, member);			\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_last_entry(head, typeof(*pos), member);		\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_continue(pos, n, head, member) 		\
	for (pos = list_next_entry(pos, member), 				\
		n = list_next_entry(pos, member);				\
	     !list_entry_is_head(pos, head, member);				\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_from(pos, n, head, member) 			\
	for (n = list_next_entry(pos, member);					\
	     !list_entry_is_head(pos, head, member);				\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_last_entry(head, typeof(*pos), member),		\
		n = list_prev_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = n, n = list_prev_entry(n, member))
#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)
#define list_for_each_prev_safe(pos, n, head) \
	for (pos = (head)->prev, n = pos->prev; \
	     pos != (head); \
	     pos = n, n = pos->prev)
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))
#define list_prev_entry(pos, member) \
	list_entry((pos)->member.prev, typeof(*(pos)), member)
#define list_safe_reset_next(pos, n, member)				\
	n = list_next_entry(pos, member)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define CONCATENATE(a, b) __CONCAT(a, b)
#define COUNT_ARGS(X...) __COUNT_ARGS(, ##X, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define PTR_IF(cond, ptr)	((cond) ? (ptr) : NULL)
# define REBUILD_DUE_TO_FTRACE_MCOUNT_RECORD
#define REPEAT_BYTE(x)	((~0ul / 0xff) * (x))
#define VERIFY_OCTAL_PERMISSIONS(perms)						\
	(BUILD_BUG_ON_ZERO((perms) < 0) +					\
	 BUILD_BUG_ON_ZERO((perms) > 0777) +					\
	 		\
	 BUILD_BUG_ON_ZERO((((perms) >> 6) & 4) < (((perms) >> 3) & 4)) +	\
	 BUILD_BUG_ON_ZERO((((perms) >> 3) & 4) < ((perms) & 4)) +		\
	 					\
	 BUILD_BUG_ON_ZERO((((perms) >> 6) & 2) < (((perms) >> 3) & 2)) +	\
	 		\
	 BUILD_BUG_ON_ZERO((perms) & 2) +					\
	 (perms))

#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })
#define __CONCAT(a, b) a ## b
#define __COUNT_ARGS(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _n, X...) _n
#define __trace_printk_check_format(fmt, args...)			\
do {									\
	if (0)								\
		____trace_printk_check_format(fmt, ##args);		\
} while (0)
# define cant_migrate()							\
	do {								\
		if (IS_ENABLED(CONFIG_SMP))				\
			__cant_migrate("__FILE__", "__LINE__");		\
	} while (0)
# define cant_sleep() \
	do { __cant_sleep("__FILE__", "__LINE__", 0); } while (0)
#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			 !__same_type(*(ptr), void),			\
			 "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })
#define container_of_safe(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			 !__same_type(*(ptr), void),			\
			 "pointer type mismatch in container_of()");	\
	IS_ERR_OR_NULL(__mptr) ? ERR_CAST(__mptr) :			\
		((type *)(__mptr - offsetof(type, member))); })
#define do_trace_printk(fmt, args...)					\
do {									\
	static const char *trace_printk_fmt __used			\
		__section("__trace_printk_fmt") =			\
		__builtin_constant_p(fmt) ? fmt : NULL;			\
									\
	__trace_printk_check_format(fmt, ##args);			\
									\
	if (__builtin_constant_p(fmt))					\
		__trace_bprintk(_THIS_IP_, trace_printk_fmt, ##args);	\
	else								\
		__trace_printk(_THIS_IP_, fmt, ##args);			\
} while (0)
#define ftrace_vprintk(fmt, vargs)					\
do {									\
	if (__builtin_constant_p(fmt)) {				\
		static const char *trace_printk_fmt __used		\
		  __section("__trace_printk_fmt") =			\
			__builtin_constant_p(fmt) ? fmt : NULL;		\
									\
		__ftrace_vbprintk(_THIS_IP_, trace_printk_fmt, vargs);	\
	} else								\
		__ftrace_vprintk(_THIS_IP_, fmt, vargs);		\
} while (0)
#define hex_asc_hi(x)	hex_asc[((x) & 0xf0) >> 4]
#define hex_asc_lo(x)	hex_asc[((x) & 0x0f)]
#define hex_asc_upper_hi(x)	hex_asc_upper[((x) & 0xf0) >> 4]
#define hex_asc_upper_lo(x)	hex_asc_upper[((x) & 0x0f)]
#define lower_16_bits(n) ((u16)((n) & 0xffff))
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))
#define might_fault() __might_fault("__FILE__", "__LINE__")
# define might_resched() do { } while (0)
# define might_sleep() \
	do { __might_sleep("__FILE__", "__LINE__", 0); might_resched(); } while (0)
#define might_sleep_if(cond) do { if (cond) might_sleep(); } while (0)
# define non_block_end() WARN_ON(current->non_block_count-- == 0)
# define non_block_start() (current->non_block_count++)
# define sched_annotate_sleep()	(current->task_state_change = 0)
#define trace_printk(fmt, ...)				\
do {							\
	char _______STR[] = __stringify((__VA_ARGS__));	\
	if (sizeof(_______STR) > 3)			\
		do_trace_printk(fmt, ##__VA_ARGS__);	\
	else						\
		trace_puts(fmt);			\
} while (0)
#define trace_puts(str) ({						\
	static const char *trace_printk_fmt __used			\
		__section("__trace_printk_fmt") =			\
		__builtin_constant_p(str) ? str : NULL;			\
									\
	if (__builtin_constant_p(str))					\
		__trace_bputs(_THIS_IP_, trace_printk_fmt);		\
	else								\
		__trace_puts(_THIS_IP_, str, strlen(str));		\
})
#define typeof_member(T, m)	typeof(((T*)0)->m)
#define u64_to_user_ptr(x) (		\
{					\
	typecheck(u64, (x));		\
	(void __user *)(uintptr_t)(x);	\
}					\
)
#define upper_16_bits(n) ((u16)((n) >> 16))
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define DECLARE_STATIC_CALL(name, func)					\
	extern struct static_call_key STATIC_CALL_KEY(name);		\
	extern typeof(func) STATIC_CALL_TRAMP(name);
#define STATIC_CALL_KEY(name)		__PASTE(STATIC_CALL_KEY_PREFIX, name)
#define STATIC_CALL_KEY_STR(name)	__stringify(STATIC_CALL_KEY(name))
#define STATIC_CALL_SITE_FLAGS 3UL
#define STATIC_CALL_SITE_INIT 2UL	
#define STATIC_CALL_SITE_TAIL 1UL	
#define STATIC_CALL_TRAMP(name)		__PASTE(STATIC_CALL_TRAMP_PREFIX, name)
#define STATIC_CALL_TRAMP_STR(name)	__stringify(STATIC_CALL_TRAMP(name))

#define __STATIC_CALL_ADDRESSABLE(name) \
	__ADDRESSABLE(STATIC_CALL_KEY(name))

#define __raw_static_call(name)	(&STATIC_CALL_TRAMP(name))
#define __static_call(name)						\
({									\
	__STATIC_CALL_ADDRESSABLE(name);				\
	__raw_static_call(name);					\
})
#define static_call(name)	__static_call(name)
#define static_call_mod(name)	__raw_static_call(name)
#define CONSOLE_LOGLEVEL_DEFAULT CONFIG_CONSOLE_LOGLEVEL_DEFAULT
#define CONSOLE_LOGLEVEL_MOTORMOUTH 15	
#define CONSOLE_LOGLEVEL_SILENT  0 
#define DEVKMSG_STR_MAX_SIZE 10
#define MESSAGE_LOGLEVEL_DEFAULT CONFIG_MESSAGE_LOGLEVEL_DEFAULT
#define PRINTK_MAX_SINGLE_HEADER_LEN 2

#define __printk_index_emit(_fmt, _level, _subsys_fmt_prefix)		\
	do {								\
		if (__builtin_constant_p(_fmt) && __builtin_constant_p(_level)) { \
									\
			static const struct pi_entry _entry		\
			__used = {					\
				.fmt = __builtin_constant_p(_fmt) ? (_fmt) : NULL, \
				.func = __func__,			\
				.file = "__FILE__",			\
				.line = "__LINE__",			\
				.level = __builtin_constant_p(_level) ? (_level) : NULL, \
				.subsys_fmt_prefix = _subsys_fmt_prefix,\
			};						\
			static const struct pi_entry *_entry_ptr	\
			__used __section(".printk_index") = &_entry;	\
		}							\
	} while (0)
#define console_loglevel (console_printk[0])
#define default_console_loglevel (console_printk[3])
#define default_message_loglevel (console_printk[1])
#define minimum_console_loglevel (console_printk[2])
#define no_printk(fmt, ...)				\
({							\
	if (0)						\
		printk(fmt, ##__VA_ARGS__);		\
	0;						\
})
#define pr_alert(fmt, ...) \
	printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert_once(fmt, ...)					\
	printk_once(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_cont(fmt, ...) \
	printk(KERN_CONT fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...) \
	printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_once(fmt, ...)					\
	printk_once(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug(fmt, ...)			\
	dynamic_pr_debug(fmt, ##__VA_ARGS__)
#define pr_debug_once(fmt, ...)					\
	printk_once(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug_ratelimited(fmt, ...)					\
do {									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, pr_fmt(fmt));		\
	if (DYNAMIC_DEBUG_BRANCH(descriptor) &&				\
	    __ratelimit(&_rs))						\
		__dynamic_pr_debug(&descriptor, pr_fmt(fmt), ##__VA_ARGS__);	\
} while (0)
#define pr_devel(fmt, ...) \
	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_devel_once(fmt, ...)					\
	printk_once(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_devel_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_emerg(fmt, ...) \
	printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_emerg_once(fmt, ...)					\
	printk_once(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_emerg_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...) \
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err_once(fmt, ...)					\
	printk_once(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_fmt(fmt) fmt
#define pr_info(fmt, ...) \
	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info_once(fmt, ...)					\
	printk_once(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice(fmt, ...) \
	printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice_once(fmt, ...)				\
	printk_once(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn(fmt, ...) \
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn_once(fmt, ...)					\
	printk_once(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define print_hex_dump_bytes(prefix_str, prefix_type, buf, len)	\
	print_hex_dump_debug(prefix_str, prefix_type, 16, 1, buf, len, true)
#define print_hex_dump_debug(prefix_str, prefix_type, rowsize,	\
			     groupsize, buf, len, ascii)	\
	dynamic_hex_dump(prefix_str, prefix_type, rowsize,	\
			 groupsize, buf, len, ascii)
#define printk(fmt, ...) printk_index_wrap(_printk, fmt, ##__VA_ARGS__)
#define printk_cpu_lock_irqsave(flags)		\
	for (;;) {				\
		local_irq_save(flags);		\
		if (__printk_cpu_trylock())	\
			break;			\
		local_irq_restore(flags);	\
		__printk_wait_on_cpu_lock();	\
	}
#define printk_cpu_unlock_irqrestore(flags)	\
	do {					\
		__printk_cpu_unlock();		\
		local_irq_restore(flags);	\
	} while (0)				\

#define printk_deferred(fmt, ...)					\
	printk_index_wrap(_printk_deferred, fmt, ##__VA_ARGS__)
#define printk_deferred_enter __printk_safe_enter
#define printk_deferred_exit __printk_safe_exit
#define printk_deferred_once(fmt, ...)				\
	DO_ONCE_LITE(printk_deferred, fmt, ##__VA_ARGS__)
#define printk_index_subsys_emit(subsys_fmt_prefix, level, fmt, ...) \
	__printk_index_emit(fmt, level, subsys_fmt_prefix)
#define printk_index_wrap(_p_func, _fmt, ...)				\
	({								\
		__printk_index_emit(_fmt, NULL, NULL);			\
		_p_func(_fmt, ##__VA_ARGS__);				\
	})
#define printk_once(fmt, ...)					\
	DO_ONCE_LITE(printk, fmt, ##__VA_ARGS__)
#define printk_ratelimit() __printk_ratelimit(__func__)
#define printk_ratelimited(fmt, ...)					\
({									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
									\
	if (__ratelimit(&_rs))						\
		printk(fmt, ##__VA_ARGS__);				\
})
#define DEFINE_DYNAMIC_DEBUG_METADATA(name, fmt)		\
	static struct _ddebug  __aligned(8)			\
	__section("__dyndbg") name = {				\
		.modname = KBUILD_MODNAME,			\
		.function = __func__,				\
		.filename = "__FILE__",				\
		.format = (fmt),				\
		.lineno = "__LINE__",				\
		.flags = _DPRINTK_FLAGS_DEFAULT,		\
		_DPRINTK_KEY_INIT				\
	}
#define DYNAMIC_DEBUG_BRANCH(descriptor) \
	static_branch_likely(&descriptor.key.dd_key_true)
#define _DPRINTK_FLAGS_DEFAULT _DPRINTK_FLAGS_PRINT
#define _DPRINTK_KEY_INIT .key.dd_key_true = (STATIC_KEY_TRUE_INIT)

#define __dynamic_func_call(id, fmt, func, ...) do {	\
	DEFINE_DYNAMIC_DEBUG_METADATA(id, fmt);		\
	if (DYNAMIC_DEBUG_BRANCH(id))			\
		func(&id, ##__VA_ARGS__);		\
} while (0)
#define __dynamic_func_call_no_desc(id, fmt, func, ...) do {	\
	DEFINE_DYNAMIC_DEBUG_METADATA(id, fmt);			\
	if (DYNAMIC_DEBUG_BRANCH(id))				\
		func(__VA_ARGS__);				\
} while (0)
#define _dynamic_func_call(fmt, func, ...)				\
	__dynamic_func_call(__UNIQUE_ID(ddebug), fmt, func, ##__VA_ARGS__)
#define _dynamic_func_call_no_desc(fmt, func, ...)	\
	__dynamic_func_call_no_desc(__UNIQUE_ID(ddebug), fmt, func, ##__VA_ARGS__)
#define dynamic_dev_dbg(dev, fmt, ...)				\
	_dynamic_func_call(fmt,__dynamic_dev_dbg, 		\
			   dev, fmt, ##__VA_ARGS__)
#define dynamic_hex_dump(prefix_str, prefix_type, rowsize,		\
			 groupsize, buf, len, ascii)			\
	_dynamic_func_call_no_desc(__builtin_constant_p(prefix_str) ? prefix_str : "hexdump", \
				   print_hex_dump,			\
				   KERN_DEBUG, prefix_str, prefix_type,	\
				   rowsize, groupsize, buf, len, ascii)
#define dynamic_ibdev_dbg(dev, fmt, ...)			\
	_dynamic_func_call(fmt, __dynamic_ibdev_dbg,		\
			   dev, fmt, ##__VA_ARGS__)
#define dynamic_netdev_dbg(dev, fmt, ...)			\
	_dynamic_func_call(fmt, __dynamic_netdev_dbg,		\
			   dev, fmt, ##__VA_ARGS__)
#define dynamic_pr_debug(fmt, ...)				\
	_dynamic_func_call(fmt,	__dynamic_pr_debug,		\
			   pr_fmt(fmt), ##__VA_ARGS__)

#define __FORTIFY_INLINE extern __always_inline __attribute__((gnu_inline))
#define __RENAME(x) __asm__(#x)
#define memcat_p(a, b) ({					\
	BUILD_BUG_ON_MSG(!__same_type(*(a), *(b)),		\
			 "type mismatch in memcat_p()");	\
	(typeof(*a) *)__memcat_p((void **)(a), (void **)(b));	\
})
#define sysfs_match_string(_a, _s) __sysfs_match_string(_a, ARRAY_SIZE(_a), _s)



#define va_arg(v, T)	__builtin_va_arg(v, T)
#define va_copy(d, s)	__builtin_va_copy(d, s)
#define va_end(v)	__builtin_va_end(v)
#define va_start(v, l)	__builtin_va_start(v, l)
#define NULL ((void *)0)

#define offsetof(TYPE, MEMBER)	__compiler_offsetof(TYPE, MEMBER)
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof_field(TYPE, MEMBER))
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#define DECLARE_STATIC_KEY_FALSE(name)	\
	extern struct static_key_false name
#define DECLARE_STATIC_KEY_MAYBE(cfg, name)			\
	__PASTE(_DECLARE_STATIC_KEY_, IS_ENABLED(cfg))(name)
#define DECLARE_STATIC_KEY_TRUE(name)	\
	extern struct static_key_true name
#define DEFINE_STATIC_KEY_ARRAY_FALSE(name, count)		\
	struct static_key_false name[count] = {			\
		[0 ... (count) - 1] = STATIC_KEY_FALSE_INIT,	\
	}
#define DEFINE_STATIC_KEY_ARRAY_TRUE(name, count)		\
	struct static_key_true name[count] = {			\
		[0 ... (count) - 1] = STATIC_KEY_TRUE_INIT,	\
	}
#define DEFINE_STATIC_KEY_FALSE(name)	\
	struct static_key_false name = STATIC_KEY_FALSE_INIT
#define DEFINE_STATIC_KEY_FALSE_RO(name)	\
	struct static_key_false name __ro_after_init = STATIC_KEY_FALSE_INIT
#define DEFINE_STATIC_KEY_MAYBE(cfg, name)			\
	__PASTE(_DEFINE_STATIC_KEY_, IS_ENABLED(cfg))(name)
#define DEFINE_STATIC_KEY_MAYBE_RO(cfg, name)			\
	__PASTE(_DEFINE_STATIC_KEY_RO_, IS_ENABLED(cfg))(name)
#define DEFINE_STATIC_KEY_TRUE(name)	\
	struct static_key_true name = STATIC_KEY_TRUE_INIT
#define DEFINE_STATIC_KEY_TRUE_RO(name)	\
	struct static_key_true name __ro_after_init = STATIC_KEY_TRUE_INIT
#define STATIC_KEY_CHECK_USE(key) WARN(!static_key_initialized,		      \
				    "%s(): static key '%pS' used before call to jump_label_init()", \
				    __func__, (key))
#define STATIC_KEY_FALSE_INIT (struct static_key_false){ .key = STATIC_KEY_INIT_FALSE, }
#define STATIC_KEY_INIT STATIC_KEY_INIT_FALSE
#define STATIC_KEY_TRUE_INIT  (struct static_key_true) { .key = STATIC_KEY_INIT_TRUE,  }
#define _DECLARE_STATIC_KEY_0(name)	DECLARE_STATIC_KEY_FALSE(name)
#define _DECLARE_STATIC_KEY_1(name)	DECLARE_STATIC_KEY_TRUE(name)
#define _DEFINE_STATIC_KEY_0(name)	DEFINE_STATIC_KEY_FALSE(name)
#define _DEFINE_STATIC_KEY_1(name)	DEFINE_STATIC_KEY_TRUE(name)
#define _DEFINE_STATIC_KEY_RO_0(name)	DEFINE_STATIC_KEY_FALSE_RO(name)
#define _DEFINE_STATIC_KEY_RO_1(name)	DEFINE_STATIC_KEY_TRUE_RO(name)

#define jump_label_enabled static_key_enabled
#define static_branch_dec(x)		static_key_slow_dec(&(x)->key)
#define static_branch_dec_cpuslocked(x)	static_key_slow_dec_cpuslocked(&(x)->key)
#define static_branch_disable(x)		static_key_disable(&(x)->key)
#define static_branch_disable_cpuslocked(x)	static_key_disable_cpuslocked(&(x)->key)
#define static_branch_enable(x)			static_key_enable(&(x)->key)
#define static_branch_enable_cpuslocked(x)	static_key_enable_cpuslocked(&(x)->key)
#define static_branch_inc(x)		static_key_slow_inc(&(x)->key)
#define static_branch_inc_cpuslocked(x)	static_key_slow_inc_cpuslocked(&(x)->key)
#define static_branch_likely(x)							\
({										\
	bool branch;								\
	if (__builtin_types_compatible_p(typeof(*x), struct static_key_true))	\
		branch = !arch_static_branch(&(x)->key, true);			\
	else if (__builtin_types_compatible_p(typeof(*x), struct static_key_false)) \
		branch = !arch_static_branch_jump(&(x)->key, true);		\
	else									\
		branch = ____wrong_branch_error();				\
	likely_notrace(branch);								\
})
#define static_branch_maybe(config, x)					\
	(IS_ENABLED(config) ? static_branch_likely(x)			\
			    : static_branch_unlikely(x))
#define static_branch_unlikely(x)						\
({										\
	bool branch;								\
	if (__builtin_types_compatible_p(typeof(*x), struct static_key_true))	\
		branch = arch_static_branch_jump(&(x)->key, false);		\
	else if (__builtin_types_compatible_p(typeof(*x), struct static_key_false)) \
		branch = arch_static_branch(&(x)->key, false);			\
	else									\
		branch = ____wrong_branch_error();				\
	unlikely_notrace(branch);							\
})
#define static_key_disable_cpuslocked(k)	static_key_disable((k))
#define static_key_enable_cpuslocked(k)		static_key_enable((k))
#define static_key_enabled(x)							\
({										\
	if (!__builtin_types_compatible_p(typeof(*x), struct static_key) &&	\
	    !__builtin_types_compatible_p(typeof(*x), struct static_key_true) &&\
	    !__builtin_types_compatible_p(typeof(*x), struct static_key_false))	\
		____wrong_branch_error();					\
	static_key_count((struct static_key *)x) > 0;				\
})
#define static_key_slow_dec_cpuslocked(key) static_key_slow_dec(key)
#define static_key_slow_inc_cpuslocked(key) static_key_slow_inc(key)
#define CHECK_DATA_CORRUPTION(condition, fmt, ...)			 \
	check_data_corruption(({					 \
		bool corruption = unlikely(condition);			 \
		if (corruption) {					 \
			if (IS_ENABLED(CONFIG_BUG_ON_DATA_CORRUPTION)) { \
				pr_err(fmt, ##__VA_ARGS__);		 \
				BUG();					 \
			} else						 \
				WARN(1, fmt, ##__VA_ARGS__);		 \
		}							 \
		corruption;						 \
	}))
#define MAYBE_BUILD_BUG_ON(cond) (0)

#define BUG() do {} while (1)
#define BUGFLAG_TAINT(taint)	((taint) << 8)
#define BUG_GET_TAINT(bug)	((bug)->flags >> 8)
#define BUG_ON(condition) do { if (unlikely(condition)) BUG(); } while (0)
#define WARN(condition, format...) ({					\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN_printf(TAINT_WARN, format);			\
	unlikely(__ret_warn_on);					\
})
#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN();						\
	unlikely(__ret_warn_on);					\
})
#define WARN_ONCE(condition, format...)				\
	DO_ONCE_LITE_IF(condition, WARN, 1, format)
# define WARN_ON_FUNCTION_MISMATCH(x, fn) ({ 0; })
#define WARN_ON_ONCE(condition) ({				\
	int __ret_warn_on = !!(condition);			\
	if (unlikely(__ret_warn_on))				\
		__WARN_FLAGS(BUGFLAG_ONCE |			\
			     BUGFLAG_TAINT(TAINT_WARN));	\
	unlikely(__ret_warn_on);				\
})
# define WARN_ON_SMP(x)			WARN_ON(x)
#define WARN_TAINT(condition, taint, format...) ({			\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN_printf(taint, format);				\
	unlikely(__ret_warn_on);					\
})
#define WARN_TAINT_ONCE(condition, taint, format...)		\
	DO_ONCE_LITE_IF(condition, WARN_TAINT, 1, taint, format)

#define __WARN()		__WARN_printf(TAINT_WARN, NULL)
#define __WARN_printf(taint, arg...) do {				\
		instrumentation_begin();				\
		warn_slowpath_fmt("__FILE__", "__LINE__", taint, arg);	\
		instrumentation_end();					\
	} while (0)

#define sysctl_oops_all_cpu_backtrace 0
#define DO_ONCE_LITE(func, ...)						\
	DO_ONCE_LITE_IF(true, func, ##__VA_ARGS__)
#define DO_ONCE_LITE_IF(condition, func, ...)				\
	({								\
		static bool __section(".data.once") __already_done;	\
		bool __ret_do_once = !!(condition);			\
									\
		if (unlikely(__ret_do_once && !__already_done)) {	\
			__already_done = true;				\
			func(__VA_ARGS__);				\
		}							\
		unlikely(__ret_do_once);				\
	})


#define __instrumentation_begin(c) ({					\
	asm volatile(__stringify(c) ": nop\n\t"				\
		     ".pushsection .discard.instr_begin\n\t"		\
		     ".long " __stringify(c) "b - .\n\t"		\
		     ".popsection\n\t");				\
})
#define __instrumentation_end(c) ({					\
	asm volatile(__stringify(c) ": nop\n\t"				\
		     ".pushsection .discard.instr_end\n\t"		\
		     ".long " __stringify(c) "b - .\n\t"		\
		     ".popsection\n\t");				\
})
# define instrumentation_begin()	do { } while(0)
# define instrumentation_end()		do { } while(0)
#define DEFINE_RATELIMIT_STATE(name, interval_init, burst_init)		\
									\
	struct ratelimit_state name =					\
		RATELIMIT_STATE_INIT(name, interval_init, burst_init)	\

#define RATELIMIT_STATE_INIT(name, interval_init, burst_init) {		\
		.lock		= __RAW_SPIN_LOCK_UNLOCKED(name.lock),	\
		.interval	= interval_init,			\
		.burst		= burst_init,				\
	}

#define __ratelimit(state) ___ratelimit(state, __func__)
#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_ULL(nr)		(ULL(1) << (nr))
#define BIT_ULL_MASK(nr)	(ULL(1) << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define GENMASK(h, l) \
	(GENMASK_INPUT_CHECK(h, l) + __GENMASK(h, l))
#define GENMASK_INPUT_CHECK(h, l) \
	(BUILD_BUG_ON_ZERO(__builtin_choose_expr( \
		__is_constexpr((l) > (h)), (l) > (h), 0)))
#define GENMASK_ULL(h, l) \
	(GENMASK_INPUT_CHECK(h, l) + __GENMASK_ULL(h, l))
#define __GENMASK(h, l) \
	(((~UL(0)) - (UL(1) << (l)) + 1) & \
	 (~UL(0) >> (BITS_PER_LONG - 1 - (h))))
#define __GENMASK_ULL(h, l) \
	(((~ULL(0)) - (ULL(1) << (l)) + 1) & \
	 (~ULL(0) >> (BITS_PER_LONG_LONG - 1 - (h))))

#define BIT(nr)			(UL(1) << (nr))



#define __MEMINIT        .section	".meminit.text", "ax"
#define __MEMINITDATA    .section	".meminit.data", "aw"
#define __MEMINITRODATA  .section	".meminit.rodata", "a"
#define __REF            .section       ".ref.text", "ax"
#define __REFCONST       .section       ".ref.rodata", "a"
#define __REFDATA        .section       ".ref.data", "aw"
#define ____define_initcall(fn, __stub, __name, __sec)		\
	__define_initcall_stub(__stub, fn)			\
	asm(".section	\"" __sec "\", \"a\"		\n"	\
	    __stringify(__name) ":			\n"	\
	    ".long	" __stringify(__stub) " - .	\n"	\
	    ".previous					\n");	\
	static_assert(__same_type(initcall_t, &fn));
#define ___define_initcall(fn, id, __sec)			\
	__unique_initcall(fn, id, __sec, __initcall_id(fn))
#define __define_initcall(fn, id) ___define_initcall(fn, id, .initcall##id)
#define __define_initcall_stub(__stub, fn)			\
	int __init __cficanonical __stub(void);			\
	int __init __cficanonical __stub(void)			\
	{ 							\
		return fn();					\
	}							\
	__ADDRESSABLE(__stub)
#define __exit          __section(".exit.text") __exitused __cold notrace
#define __exit_p(x) x
#define __exitcall(fn)						\
	static exitcall_t __exitcall_##fn __exit_call = fn
#define __exitused  __used
#define __initcall(fn) device_initcall(fn)
#define __initcall_id(fn)					\
	__PASTE(__KBUILD_MODNAME,				\
	__PASTE(__,						\
	__PASTE(__COUNTER__,					\
	__PASTE(_,						\
	__PASTE("__LINE__",					\
	__PASTE(_, fn))))))
#define __initcall_name(prefix, __iid, id)			\
	__PASTE(__,						\
	__PASTE(prefix,						\
	__PASTE(__,						\
	__PASTE(__iid, id))))
#define __initcall_section(__sec, __iid)			\
	#__sec ".init.." #__iid
#define __initcall_stub(fn, __iid, id)				\
	__initcall_name(initstub, __iid, id)
#define __memexit        __section(".memexit.text") __exitused __cold notrace
#define __memexitconst   __section(".memexit.rodata")
#define __memexitdata    __section(".memexit.data")
#define __meminit        __section(".meminit.text") __cold notrace \
						  __latent_entropy
#define __meminitconst   __section(".meminit.rodata")
#define __meminitdata    __section(".meminit.data")
#define __noinitretpoline __noretpoline
#define __nosavedata __section(".data..nosave")
#define __ref            __section(".ref.text") noinline
#define __refconst       __section(".ref.rodata")
#define __refdata        __section(".ref.data")
#define __setup(str, fn)						\
	__setup_param(str, fn, fn, 0)
#define __setup_param(str, unique_id, fn, early)			\
	static const char __setup_str_##unique_id[] __initconst		\
		__aligned(1) = str; 					\
	static struct obs_kernel_param __setup_##unique_id		\
		__used __section(".init.setup")				\
		__aligned(__alignof__(struct obs_kernel_param))		\
		= { __setup_str_##unique_id, fn, early }
#define __unique_initcall(fn, id, __sec, __iid)			\
	____define_initcall(fn,					\
		__initcall_stub(fn, __iid, id),			\
		__initcall_name(initcall, __iid, id),		\
		__initcall_section(__sec, __iid))
#define arch_initcall(fn)		__define_initcall(fn, 3)
#define arch_initcall_sync(fn)		__define_initcall(fn, 3s)
#define console_initcall(fn)	___define_initcall(fn, con, .con_initcall)
#define core_initcall(fn)		__define_initcall(fn, 1)
#define core_initcall_sync(fn)		__define_initcall(fn, 1s)
#define device_initcall(fn)		__define_initcall(fn, 6)
#define device_initcall_sync(fn)	__define_initcall(fn, 6s)
#define early_initcall(fn)		__define_initcall(fn, early)
#define early_param(str, fn)						\
	__setup_param(str, fn, fn, 1)
#define early_param_on_off(str_on, str_off, var, config)		\
									\
	int var = IS_ENABLED(config);					\
									\
	static int __init parse_##var##_on(char *arg)			\
	{								\
		var = 1;						\
		return 0;						\
	}								\
	early_param(str_on, parse_##var##_on);				\
									\
	static int __init parse_##var##_off(char *arg)			\
	{								\
		var = 0;						\
		return 0;						\
	}								\
	early_param(str_off, parse_##var##_off)
#define fs_initcall(fn)			__define_initcall(fn, 5)
#define fs_initcall_sync(fn)		__define_initcall(fn, 5s)
#define late_initcall(fn)		__define_initcall(fn, 7)
#define late_initcall_sync(fn)		__define_initcall(fn, 7s)
#define postcore_initcall(fn)		__define_initcall(fn, 2)
#define postcore_initcall_sync(fn)	__define_initcall(fn, 2s)
#define pure_initcall(fn)		__define_initcall(fn, 0)
#define rootfs_initcall(fn)		__define_initcall(fn, rootfs)
#define subsys_initcall(fn)		__define_initcall(fn, 4)
#define subsys_initcall_sync(fn)	__define_initcall(fn, 4s)

#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})
#define typecheck_fn(type,function) \
({	typeof(type) __tmp = function; \
	(void)__tmp; \
})
#define typecheck_pointer(x) \
({	typeof(x) __dummy; \
	(void)sizeof(*__dummy); \
	1; \
})

#define __careful_cmp(x, y, op) \
	__builtin_choose_expr(__safe_cmp(x, y), \
		__cmp(x, y, op), \
		__cmp_once(x, y, __UNIQUE_ID(__x), __UNIQUE_ID(__y), op))
#define __cmp(x, y, op)	((x) op (y) ? (x) : (y))
#define __cmp_once(x, y, unique_x, unique_y, op) ({	\
		typeof(x) unique_x = (x);		\
		typeof(y) unique_y = (y);		\
		__cmp(unique_x, unique_y, op); })
#define __no_side_effects(x, y) \
		(__is_constexpr(x) && __is_constexpr(y))
#define __safe_cmp(x, y) \
		(__typecheck(x, y) && __no_side_effects(x, y))
#define __typecheck(x, y) \
	(!!(sizeof((typeof(x) *)1 == (typeof(y) *)1)))
#define clamp(val, lo, hi) min((typeof(val))max(val, lo), hi)
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)
#define clamp_val(val, lo, hi) clamp_t(typeof(val), val, lo, hi)
#define max(x, y)	__careful_cmp(x, y, >)
#define max3(x, y, z) max((typeof(x))max(x, y), z)
#define max_t(type, x, y)	__careful_cmp((type)(x), (type)(y), >)
#define min(x, y)	__careful_cmp(x, y, <)
#define min3(x, y, z) min((typeof(x))min(x, y), z)
#define min_not_zero(x, y) ({			\
	typeof(x) __x = (x);			\
	typeof(y) __y = (y);			\
	__x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y)); })
#define min_t(type, x, y)	__careful_cmp((type)(x), (type)(y), <)
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
#define DIV_ROUND_CLOSEST(x, divisor)(			\
{							\
	typeof(x) __x = x;				\
	typeof(divisor) __d = divisor;			\
	(((typeof(x))-1) > 0 ||				\
	 ((typeof(divisor))-1) > 0 ||			\
	 (((__x) > 0) == ((__d) > 0))) ?		\
		(((__x) + ((__d) / 2)) / (__d)) :	\
		(((__x) - ((__d) / 2)) / (__d));	\
}							\
)
#define DIV_ROUND_CLOSEST_ULL(x, divisor)(		\
{							\
	typeof(divisor) __d = divisor;			\
	unsigned long long _tmp = (x) + (__d) / 2;	\
	do_div(_tmp, __d);				\
	_tmp;						\
}							\
)
#define DIV_ROUND_DOWN_ULL(ll, d) \
	({ unsigned long long _tmp = (ll); do_div(_tmp, d); _tmp; })
#define DIV_ROUND_UP __KERNEL_DIV_ROUND_UP
# define DIV_ROUND_UP_SECTOR_T(ll,d) DIV_ROUND_UP_ULL(ll, d)
#define DIV_ROUND_UP_ULL(ll, d) \
	DIV_ROUND_DOWN_ULL((unsigned long long)(ll) + (d) - 1, (d))

#define __abs_choose_expr(x, type, other) __builtin_choose_expr(	\
	__builtin_types_compatible_p(typeof(x),   signed type) ||	\
	__builtin_types_compatible_p(typeof(x), unsigned type),		\
	({ signed type __x = (x); __x < 0 ? -__x : __x; }), other)
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define abs(x)	__abs_choose_expr(x, long long,				\
		__abs_choose_expr(x, long,				\
		__abs_choose_expr(x, int,				\
		__abs_choose_expr(x, short,				\
		__abs_choose_expr(x, char,				\
		__builtin_choose_expr(					\
			__builtin_types_compatible_p(typeof(x), char),	\
			(char)({ signed char __x = (x); __x<0?-__x:__x; }), \
			((void)0)))))))
#define mult_frac(x, numer, denom)(			\
{							\
	typeof(x) quot = (x) / (denom);			\
	typeof(x) rem  = (x) % (denom);			\
	(quot * (numer)) + ((rem * (numer)) / (denom));	\
}							\
)
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define rounddown(x, y) (				\
{							\
	typeof(x) __x = (x);				\
	__x - (__x % (y));				\
}							\
)
#define roundup(x, y) (					\
{							\
	typeof(y) __y = y;				\
	(((x) + (__y - 1)) / __y) * __y;		\
}							\
)
#define sector_div(a, b) do_div(a, b)

#define bits_per(n)				\
(						\
	__builtin_constant_p(n) ? (		\
		((n) == 0 || (n) == 1)		\
			? 1 : ilog2(n) + 1	\
	) :					\
	__bits_per(n)				\
)
#define const_ilog2(n)				\
(						\
	__builtin_constant_p(n) ? (		\
		(n) < 2 ? 0 :			\
		(n) & (1ULL << 63) ? 63 :	\
		(n) & (1ULL << 62) ? 62 :	\
		(n) & (1ULL << 61) ? 61 :	\
		(n) & (1ULL << 60) ? 60 :	\
		(n) & (1ULL << 59) ? 59 :	\
		(n) & (1ULL << 58) ? 58 :	\
		(n) & (1ULL << 57) ? 57 :	\
		(n) & (1ULL << 56) ? 56 :	\
		(n) & (1ULL << 55) ? 55 :	\
		(n) & (1ULL << 54) ? 54 :	\
		(n) & (1ULL << 53) ? 53 :	\
		(n) & (1ULL << 52) ? 52 :	\
		(n) & (1ULL << 51) ? 51 :	\
		(n) & (1ULL << 50) ? 50 :	\
		(n) & (1ULL << 49) ? 49 :	\
		(n) & (1ULL << 48) ? 48 :	\
		(n) & (1ULL << 47) ? 47 :	\
		(n) & (1ULL << 46) ? 46 :	\
		(n) & (1ULL << 45) ? 45 :	\
		(n) & (1ULL << 44) ? 44 :	\
		(n) & (1ULL << 43) ? 43 :	\
		(n) & (1ULL << 42) ? 42 :	\
		(n) & (1ULL << 41) ? 41 :	\
		(n) & (1ULL << 40) ? 40 :	\
		(n) & (1ULL << 39) ? 39 :	\
		(n) & (1ULL << 38) ? 38 :	\
		(n) & (1ULL << 37) ? 37 :	\
		(n) & (1ULL << 36) ? 36 :	\
		(n) & (1ULL << 35) ? 35 :	\
		(n) & (1ULL << 34) ? 34 :	\
		(n) & (1ULL << 33) ? 33 :	\
		(n) & (1ULL << 32) ? 32 :	\
		(n) & (1ULL << 31) ? 31 :	\
		(n) & (1ULL << 30) ? 30 :	\
		(n) & (1ULL << 29) ? 29 :	\
		(n) & (1ULL << 28) ? 28 :	\
		(n) & (1ULL << 27) ? 27 :	\
		(n) & (1ULL << 26) ? 26 :	\
		(n) & (1ULL << 25) ? 25 :	\
		(n) & (1ULL << 24) ? 24 :	\
		(n) & (1ULL << 23) ? 23 :	\
		(n) & (1ULL << 22) ? 22 :	\
		(n) & (1ULL << 21) ? 21 :	\
		(n) & (1ULL << 20) ? 20 :	\
		(n) & (1ULL << 19) ? 19 :	\
		(n) & (1ULL << 18) ? 18 :	\
		(n) & (1ULL << 17) ? 17 :	\
		(n) & (1ULL << 16) ? 16 :	\
		(n) & (1ULL << 15) ? 15 :	\
		(n) & (1ULL << 14) ? 14 :	\
		(n) & (1ULL << 13) ? 13 :	\
		(n) & (1ULL << 12) ? 12 :	\
		(n) & (1ULL << 11) ? 11 :	\
		(n) & (1ULL << 10) ? 10 :	\
		(n) & (1ULL <<  9) ?  9 :	\
		(n) & (1ULL <<  8) ?  8 :	\
		(n) & (1ULL <<  7) ?  7 :	\
		(n) & (1ULL <<  6) ?  6 :	\
		(n) & (1ULL <<  5) ?  5 :	\
		(n) & (1ULL <<  4) ?  4 :	\
		(n) & (1ULL <<  3) ?  3 :	\
		(n) & (1ULL <<  2) ?  2 :	\
		1) :				\
	-1)
#define ilog2(n) \
( \
	__builtin_constant_p(n) ?	\
	((n) < 2 ? 0 :			\
	 63 - __builtin_clzll(n)) :	\
	(sizeof(n) <= 4) ?		\
	__ilog2_u32(n) :		\
	__ilog2_u64(n)			\
 )
#define order_base_2(n)				\
(						\
	__builtin_constant_p(n) ? (		\
		((n) == 0 || (n) == 1) ? 0 :	\
		ilog2((n) - 1) + 1) :		\
	__order_base_2(n)			\
)
#define rounddown_pow_of_two(n)			\
(						\
	__builtin_constant_p(n) ? (		\
		(1UL << ilog2(n))) :		\
	__rounddown_pow_of_two(n)		\
 )
#define roundup_pow_of_two(n)			\
(						\
	__builtin_constant_p(n) ? (		\
		((n) == 1) ? 1 :		\
		(1UL << (ilog2((n) - 1) + 1))	\
				   ) :		\
	__roundup_pow_of_two(n)			\
 )
#define BITS_PER_TYPE(type)	(sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_BYTES(nr)	__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(char))
#define BITS_TO_LONGS(nr)	__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(long))
#define BITS_TO_U32(nr)		__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(u32))
#define BITS_TO_U64(nr)		__KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(u64))

#define __ptr_clear_bit(nr, addr)                         \
	({                                                \
		typecheck_pointer(*(addr));               \
		__clear_bit(nr, (unsigned long *)(addr)); \
	})
#define __ptr_set_bit(nr, addr)                         \
	({                                              \
		typecheck_pointer(*(addr));             \
		__set_bit(nr, (unsigned long *)(addr)); \
	})
#define __ptr_test_bit(nr, addr)                       \
	({                                             \
		typecheck_pointer(*(addr));            \
		test_bit(nr, (unsigned long *)(addr)); \
	})
#  define aligned_byte_mask(n) ((1UL << 8*(n))-1)
#define bit_clear_unless(ptr, clear, test)	\
({								\
	const typeof(*(ptr)) clear__ = (clear), test__ = (test);\
	typeof(*(ptr)) old__, new__;				\
								\
	do {							\
		old__ = READ_ONCE(*(ptr));			\
		new__ = old__ & ~clear__;			\
	} while (!(old__ & test__) &&				\
		 cmpxchg(ptr, old__, new__) != old__);		\
								\
	!(old__ & test__);					\
})
#define for_each_clear_bit(bit, addr, size) \
	for ((bit) = find_first_zero_bit((addr), (size));	\
	     (bit) < (size);					\
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))
#define for_each_clear_bit_from(bit, addr, size) \
	for ((bit) = find_next_zero_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_zero_bit((addr), (size), (bit) + 1))
#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));		\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
#define for_each_set_bit_from(bit, addr, size) \
	for ((bit) = find_next_bit((addr), (size), (bit));	\
	     (bit) < (size);					\
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
#define for_each_set_clump8(start, clump, bits, size) \
	for ((start) = find_first_clump8(&(clump), (bits), (size)); \
	     (start) < (size); \
	     (start) = find_next_clump8(&(clump), (bits), (size), (start) + 8))
#define set_mask_bits(ptr, mask, bits)	\
({								\
	const typeof(*(ptr)) mask__ = (mask), bits__ = (bits);	\
	typeof(*(ptr)) old__, new__;				\
								\
	do {							\
		old__ = READ_ONCE(*(ptr));			\
		new__ = (old__ & ~mask__) | bits__;		\
	} while (cmpxchg(ptr, old__, new__) != old__);		\
								\
	old__;							\
})



#define ARG_MAX       131072	
#define LINK_MAX         127	
#define MAX_CANON        255	
#define MAX_INPUT        255	
#define NAME_MAX         255	
#define NGROUPS_MAX    65536	
#define PATH_MAX        4096	
#define PIPE_BUF        4096	
#define XATTR_LIST_MAX 65536	
#define XATTR_NAME_MAX   255	
#define XATTR_SIZE_MAX 65536	

#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))
#define PTR_ALIGN_DOWN(p, a)	((typeof(p))ALIGN_DOWN((unsigned long)(p), (a)))

#define __ALIGN_MASK(x, mask)	__ALIGN_KERNEL_MASK((x), (mask))
#define LIST_POISON1  ((void *) 0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void *) 0x122 + POISON_POINTER_DELTA)
#define PAGE_POISON 0xaa
# define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)

#define CSD_INIT(_func, _info) \
	(struct __call_single_data){ .func = (_func), .info = (_info), }
#define INIT_CSD(_csd, _func, _info)		\
do {						\
	*(_csd) = CSD_INIT((_func), (_info));	\
} while (0)

#define __smp_processor_id(x) raw_smp_processor_id(x)
#define generic_smp_call_function_interrupt \
	generic_smp_call_function_single_interrupt
#define get_cpu()		({ preempt_disable(); __smp_processor_id(); })
#define put_cpu()		preempt_enable()
#define raw_smp_processor_id()			0
#define smp_call_function(func, info, wait) \
			(up_smp_call_function(func, info))
#define smp_call_function_many(mask, func, info, wait) \
			(up_smp_call_function(func, info))
#define smp_prepare_boot_cpu()			do {} while (0)
# define smp_processor_id() debug_smp_processor_id()
#define SYSCALL_WORK_SYSCALL_USER_DISPATCH BIT(SYSCALL_WORK_BIT_SYSCALL_USER_DISPATCH)

#define arch_set_restart_data(restart) do { } while (0)
#define clear_syscall_work(fl) \
	clear_bit(SYSCALL_WORK_BIT_##fl, &current_thread_info()->syscall_work)
#define clear_task_syscall_work(t, fl) \
	clear_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
#define clear_thread_flag(flag) \
	clear_ti_thread_flag(current_thread_info(), flag)
#define current_thread_info() ((struct thread_info *)current)
#define set_syscall_work(fl) \
	set_bit(SYSCALL_WORK_BIT_##fl, &current_thread_info()->syscall_work)
#define set_task_syscall_work(t, fl) \
	set_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
#define set_thread_flag(flag) \
	set_ti_thread_flag(current_thread_info(), flag)
#define test_and_clear_thread_flag(flag) \
	test_and_clear_ti_thread_flag(current_thread_info(), flag)
#define test_and_set_thread_flag(flag) \
	test_and_set_ti_thread_flag(current_thread_info(), flag)
#define test_syscall_work(fl) \
	test_bit(SYSCALL_WORK_BIT_##fl, &current_thread_info()->syscall_work)
#define test_task_syscall_work(t, fl) \
	test_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
#define test_thread_flag(flag) \
	test_ti_thread_flag(current_thread_info(), flag)
#define tif_need_resched() test_thread_flag(TIF_NEED_RESCHED)
#define update_thread_flag(flag, value) \
	update_ti_thread_flag(current_thread_info(), flag, value)





#define DIV64_U64_ROUND_CLOSEST(dividend, divisor)	\
	({ u64 _tmp = (divisor); div64_u64((dividend) + _tmp / 2, _tmp); })
#define DIV64_U64_ROUND_UP(ll, d)	\
	({ u64 _tmp = (d); div64_u64((ll) + _tmp - 1, _tmp); })
#define DIV_S64_ROUND_CLOSEST(dividend, divisor)(	\
{							\
	s64 __x = (dividend);				\
	s32 __d = (divisor);				\
	((__x > 0) == (__d > 0)) ?			\
		div_s64((__x + (__d / 2)), __d) :	\
		div_s64((__x - (__d / 2)), __d);	\
}							\
)

#define div64_long(x, y) div64_s64((x), (y))
#define div64_ul(x, y)   div64_u64((x), (y))

#define SOFTIRQ_LOCK_OFFSET (SOFTIRQ_DISABLE_OFFSET + PREEMPT_LOCK_OFFSET)
#define __IRQ_MASK(x)	((1UL << (x))-1)

#define __preempt_count_dec() __preempt_count_sub(1)
#define __preempt_count_inc() __preempt_count_add(1)
#define hardirq_count()	(preempt_count() & HARDIRQ_MASK)
#define in_atomic()	(preempt_count() != 0)
#define in_atomic_preempt_off() (preempt_count() != PREEMPT_DISABLE_OFFSET)
#define in_hardirq()		(hardirq_count())
#define in_interrupt()		(irq_count())
#define in_irq()		(hardirq_count())
#define in_nmi()		(nmi_count())
#define in_serving_softirq()	(softirq_count() & SOFTIRQ_OFFSET)
#define in_softirq()		(softirq_count())
#define in_task()		(!(in_nmi() | in_hardirq() | in_serving_softirq()))
#define irq_count()	(nmi_count() | hardirq_count() | softirq_count())
#define nmi_count()	(preempt_count() & NMI_MASK)
#define preempt_check_resched() \
do { \
	if (should_resched(0)) \
		__preempt_schedule(); \
} while (0)
#define preempt_count_add(val)	__preempt_count_add(val)
#define preempt_count_dec() preempt_count_sub(1)
#define preempt_count_dec_and_test() \
	({ preempt_count_sub(1); should_resched(0); })
#define preempt_count_inc() preempt_count_add(1)
#define preempt_count_sub(val)	__preempt_count_sub(val)
#define preempt_disable() \
do { \
	preempt_count_inc(); \
	barrier(); \
} while (0)
#define preempt_disable_notrace() \
do { \
	__preempt_count_inc(); \
	barrier(); \
} while (0)
#define preempt_enable() \
do { \
	barrier(); \
	if (unlikely(preempt_count_dec_and_test())) \
		__preempt_schedule(); \
} while (0)
#define preempt_enable_no_resched() sched_preempt_enable_no_resched()
#define preempt_enable_no_resched_notrace() \
do { \
	barrier(); \
	__preempt_count_dec(); \
} while (0)
#define preempt_enable_notrace() \
do { \
	barrier(); \
	if (unlikely(__preempt_count_dec_and_test())) \
		__preempt_schedule_notrace(); \
} while (0)
#define preempt_fold_need_resched() \
do { \
	if (tif_need_resched()) \
		set_preempt_need_resched(); \
} while (0)
#define preempt_set_need_resched() \
do { \
	set_preempt_need_resched(); \
} while (0)
#define preemptible()	(preempt_count() == 0 && !irqs_disabled())
#define sched_preempt_enable_no_resched() \
do { \
	barrier(); \
	preempt_count_dec(); \
} while (0)
# define softirq_count()	(current->softirq_disable_cnt & SOFTIRQ_MASK)


#define LLIST_HEAD(name)	struct llist_head name = LLIST_HEAD_INIT(name)
#define LLIST_HEAD_INIT(name)	{ NULL }
#define llist_entry(ptr, type, member)		\
	container_of(ptr, type, member)
#define llist_for_each(pos, node)			\
	for ((pos) = (node); pos; (pos) = (pos)->next)
#define llist_for_each_entry(pos, node, member)				\
	for ((pos) = llist_entry((node), typeof(*(pos)), member);	\
	     member_address_is_nonnull(pos, member);			\
	     (pos) = llist_entry((pos)->member.next, typeof(*(pos)), member))
#define llist_for_each_entry_safe(pos, n, node, member)			       \
	for (pos = llist_entry((node), typeof(*pos), member);		       \
	     member_address_is_nonnull(pos, member) &&			       \
	        (n = llist_entry(pos->member.next, typeof(*n), member), true); \
	     pos = n)
#define llist_for_each_safe(pos, n, node)			\
	for ((pos) = (node); (pos) && ((n) = (pos)->next, true); (pos) = (n))
#define member_address_is_nonnull(ptr, member)	\
	((uintptr_t)(ptr) + offsetof(typeof(*(ptr)), member) != 0)


#define cpu_active_mask   ((const struct cpumask *)&__cpu_active_mask)
#define cpu_all_mask to_cpumask(cpu_all_bits)
#define cpu_dying_mask    ((const struct cpumask *)&__cpu_dying_mask)
#define cpu_is_offline(cpu)	unlikely(!cpu_online(cpu))
#define cpu_none_mask to_cpumask(cpu_bit_bitmap[0])
#define cpu_online_mask   ((const struct cpumask *)&__cpu_online_mask)
#define cpu_possible_mask ((const struct cpumask *)&__cpu_possible_mask)
#define cpu_present_mask  ((const struct cpumask *)&__cpu_present_mask)
#define cpumask_any(srcp) cpumask_first(srcp)
#define cpumask_any_and(mask1, mask2) cpumask_first_and((mask1), (mask2))
#define cpumask_bits(maskp) ((maskp)->bits)
#define cpumask_first_and(src1p, src2p) cpumask_next_and(-1, (src1p), (src2p))
#define cpumask_of(cpu) (get_cpu_mask(cpu))
#define cpumask_pr_args(maskp)		nr_cpu_ids, cpumask_bits(maskp)
#define for_each_cpu(cpu, mask)			\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_cpu_and(cpu, mask1, mask2)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask1, (void)mask2)
#define for_each_cpu_not(cpu, mask)		\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_cpu_wrap(cpu, mask, start)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask, (void)(start))
#define for_each_online_cpu(cpu)   for_each_cpu((cpu), cpu_online_mask)
#define for_each_possible_cpu(cpu) for_each_cpu((cpu), cpu_possible_mask)
#define for_each_present_cpu(cpu)  for_each_cpu((cpu), cpu_present_mask)
#define num_active_cpus()	cpumask_weight(cpu_active_mask)
#define num_online_cpus()	1U
#define num_possible_cpus()	cpumask_weight(cpu_possible_mask)
#define num_present_cpus()	cpumask_weight(cpu_present_mask)
#define this_cpu_cpumask_var_ptr(x)	this_cpu_read(x)
#define to_cpumask(bitmap)						\
	((struct cpumask *)(1 ? (bitmap)				\
			    : (void *)sizeof(__check_is_bitmap(bitmap))))
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_FROM_U64(n) (n)
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))
#define BITMAP_MEM_ALIGNMENT 8
#define BITMAP_MEM_MASK (BITMAP_MEM_ALIGNMENT - 1)

#define bitmap_copy_le bitmap_copy
#define bitmap_for_each_clear_region(bitmap, rs, re, start, end)	     \
	for ((rs) = (start),						     \
	     bitmap_next_clear_region((bitmap), &(rs), &(re), (end));	     \
	     (rs) < (re);						     \
	     (rs) = (re) + 1,						     \
	     bitmap_next_clear_region((bitmap), &(rs), &(re), (end)))
#define bitmap_for_each_set_region(bitmap, rs, re, start, end)		     \
	for ((rs) = (start),						     \
	     bitmap_next_set_region((bitmap), &(rs), &(re), (end));	     \
	     (rs) < (re);						     \
	     (rs) = (re) + 1,						     \
	     bitmap_next_set_region((bitmap), &(rs), &(re), (end)))
#define bitmap_from_arr32(bitmap, buf, nbits)			\
	bitmap_copy_clear_tail((unsigned long *) (bitmap),	\
			(const unsigned long *) (buf), (nbits))
#define bitmap_to_arr32(buf, bitmap, nbits)			\
	bitmap_copy_clear_tail((unsigned long *) (buf),		\
			(const unsigned long *) (bitmap), (nbits))
#define MIN_THREADS_LEFT_FOR_ROOT 4
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))



#define irqs_disabled()					\
	({						\
		unsigned long _flags;			\
		raw_local_save_flags(_flags);		\
		raw_irqs_disabled_flags(_flags);	\
	})
#define irqs_disabled_flags(flags) raw_irqs_disabled_flags(flags)
#define local_irq_disable()				\
	do {						\
		bool was_disabled = raw_irqs_disabled();\
		raw_local_irq_disable();		\
		if (!was_disabled)			\
			trace_hardirqs_off();		\
	} while (0)
#define local_irq_enable()				\
	do {						\
		trace_hardirqs_on();			\
		raw_local_irq_enable();			\
	} while (0)
#define local_irq_restore(flags)			\
	do {						\
		if (!raw_irqs_disabled_flags(flags))	\
			trace_hardirqs_on();		\
		raw_local_irq_restore(flags);		\
	} while (0)
#define local_irq_save(flags)				\
	do {						\
		raw_local_irq_save(flags);		\
		if (!raw_irqs_disabled_flags(flags))	\
			trace_hardirqs_off();		\
	} while (0)
#define local_save_flags(flags)	raw_local_save_flags(flags)
# define lockdep_hardirq_context()		0
# define lockdep_hardirq_enter()		do { } while (0)
# define lockdep_hardirq_exit()			do { } while (0)
# define lockdep_hardirq_threaded()		do { } while (0)
# define lockdep_hardirqs_enabled()		0
# define lockdep_hrtimer_enter(__hrtimer)	false
# define lockdep_hrtimer_exit(__context)	do { } while (0)
# define lockdep_irq_work_enter(_flags)					\
	  do {								\
		  if (!((_flags) & IRQ_WORK_HARD_IRQ))			\
			current->irq_config = 1;			\
	  } while (0)
# define lockdep_irq_work_exit(_flags)					\
	  do {								\
		  if (!((_flags) & IRQ_WORK_HARD_IRQ))			\
			current->irq_config = 0;			\
	  } while (0)
# define lockdep_posixtimer_enter()				\
	  do {							\
		  current->irq_config = 1;			\
	  } while (0)
# define lockdep_posixtimer_exit()				\
	  do {							\
		  current->irq_config = 0;			\
	  } while (0)
# define lockdep_softirq_context(p)		0
# define lockdep_softirq_enter()		do { } while (0)
# define lockdep_softirq_exit()			do { } while (0)
# define lockdep_softirqs_enabled(p)		0
#define raw_check_bogus_irq_restore()			\
	do {						\
		if (unlikely(!arch_irqs_disabled()))	\
			warn_bogus_irq_restore();	\
	} while (0)
#define raw_irqs_disabled()		(arch_irqs_disabled())
#define raw_irqs_disabled_flags(flags)			\
	({						\
		typecheck(unsigned long, flags);	\
		arch_irqs_disabled_flags(flags);	\
	})
#define raw_local_irq_disable()		arch_local_irq_disable()
#define raw_local_irq_enable()		arch_local_irq_enable()
#define raw_local_irq_restore(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		raw_check_bogus_irq_restore();		\
		arch_local_irq_restore(flags);		\
	} while (0)
#define raw_local_irq_save(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = arch_local_irq_save();		\
	} while (0)
#define raw_local_save_flags(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		flags = arch_local_save_flags();	\
	} while (0)
#define raw_safe_halt()			arch_safe_halt()
#define safe_halt()				\
	do {					\
		trace_hardirqs_on();		\
		raw_safe_halt();		\
	} while (0)
# define start_critical_timings() do { } while (0)
# define stop_critical_timings() do { } while (0)
# define trace_hardirqs_off()			do { } while (0)
# define trace_hardirqs_off_finish()		do { } while (0)
# define trace_hardirqs_on()			do { } while (0)
# define trace_hardirqs_on_prepare()		do { } while (0)
#  define NUM_RCU_LVL_INIT    { NUM_RCU_LVL_0 }
# define RCU_FANOUT 64
#define RCU_FANOUT_LEAF CONFIG_RCU_FANOUT_LEAF
#  define RCU_FQS_NAME_INIT   { "rcu_node_fqs_0" }
#  define RCU_NODE_NAME_INIT  { "rcu_node_0" }


#define RCU_CBLIST_INITIALIZER(n) { .head = NULL, .tail = &n.head }
#define RCU_SEGCBLIST_INITIALIZER(n) \
{ \
	.head = NULL, \
	.tails[RCU_DONE_TAIL] = &n.head, \
	.tails[RCU_WAIT_TAIL] = &n.head, \
	.tails[RCU_NEXT_READY_TAIL] = &n.head, \
	.tails[RCU_NEXT_TAIL] = &n.head, \
}

#define DECLARE_DEFERRABLE_WORK(n, f)					\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f, TIMER_DEFERRABLE)
#define DECLARE_DELAYED_WORK(n, f)					\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f, 0)
#define DECLARE_WORK(n, f)						\
	struct work_struct n = __WORK_INITIALIZER(n, f)
#define INIT_DEFERRABLE_WORK(_work, _func)				\
	__INIT_DELAYED_WORK(_work, _func, TIMER_DEFERRABLE)
#define INIT_DEFERRABLE_WORK_ONSTACK(_work, _func)			\
	__INIT_DELAYED_WORK_ONSTACK(_work, _func, TIMER_DEFERRABLE)
#define INIT_DELAYED_WORK(_work, _func)					\
	__INIT_DELAYED_WORK(_work, _func, 0)
#define INIT_DELAYED_WORK_ONSTACK(_work, _func)				\
	__INIT_DELAYED_WORK_ONSTACK(_work, _func, 0)
#define INIT_RCU_WORK(_work, _func)					\
	INIT_WORK(&(_work)->work, (_func))
#define INIT_RCU_WORK_ONSTACK(_work, _func)				\
	INIT_WORK_ONSTACK(&(_work)->work, (_func))
#define INIT_WORK(_work, _func)						\
	__INIT_WORK((_work), (_func), 0)
#define INIT_WORK_ONSTACK(_work, _func)					\
	__INIT_WORK((_work), (_func), 1)
#define WORK_DATA_INIT()	ATOMIC_LONG_INIT((unsigned long)WORK_STRUCT_NO_POOL)
#define WORK_DATA_STATIC_INIT()	\
	ATOMIC_LONG_INIT((unsigned long)(WORK_STRUCT_NO_POOL | WORK_STRUCT_STATIC))

#define __DELAYED_WORK_INITIALIZER(n, f, tflags) {			\
	.work = __WORK_INITIALIZER((n).work, (f)),			\
	.timer = __TIMER_INITIALIZER(delayed_work_timer_fn,\
				     (tflags) | TIMER_IRQSAFE),		\
	}
#define __INIT_DELAYED_WORK(_work, _func, _tflags)			\
	do {								\
		INIT_WORK(&(_work)->work, (_func));			\
		__init_timer(&(_work)->timer,				\
			     delayed_work_timer_fn,			\
			     (_tflags) | TIMER_IRQSAFE);		\
	} while (0)
#define __INIT_DELAYED_WORK_ONSTACK(_work, _func, _tflags)		\
	do {								\
		INIT_WORK_ONSTACK(&(_work)->work, (_func));		\
		__init_timer_on_stack(&(_work)->timer,			\
				      delayed_work_timer_fn,		\
				      (_tflags) | TIMER_IRQSAFE);	\
	} while (0)
#define __INIT_WORK(_work, _func, _onstack)				\
	do {								\
		static struct lock_class_key __key;			\
									\
		__init_work((_work), _onstack);				\
		(_work)->data = (atomic_long_t) WORK_DATA_INIT();	\
		lockdep_init_map(&(_work)->lockdep_map, "(work_completion)"#_work, &__key, 0); \
		INIT_LIST_HEAD(&(_work)->entry);			\
		(_work)->func = (_func);				\
	} while (0)
#define __WORK_INITIALIZER(n, f) {					\
	.data = WORK_DATA_STATIC_INIT(),				\
	.entry	= { &(n).entry, &(n).entry },				\
	.func = (f),							\
	__WORK_INIT_LOCKDEP_MAP(#n, &(n))				\
	}
#define __WORK_INIT_LOCKDEP_MAP(n, k) \
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(n, k),
#define alloc_ordered_workqueue(fmt, flags, args...)			\
	alloc_workqueue(fmt, WQ_UNBOUND | __WQ_ORDERED |		\
			__WQ_ORDERED_EXPLICIT | (flags), 1, ##args)
#define create_freezable_workqueue(name)				\
	alloc_workqueue("%s", __WQ_LEGACY | WQ_FREEZABLE | WQ_UNBOUND |	\
			WQ_MEM_RECLAIM, 1, (name))
#define create_singlethread_workqueue(name)				\
	alloc_ordered_workqueue("%s", __WQ_LEGACY | WQ_MEM_RECLAIM, name)
#define create_workqueue(name)						\
	alloc_workqueue("%s", __WQ_LEGACY | WQ_MEM_RECLAIM, 1, (name))
#define delayed_work_pending(w) \
	work_pending(&(w)->work)
#define work_data_bits(work) ((unsigned long *)(&(work)->data))
#define work_pending(work) \
	test_bit(WORK_STRUCT_PENDING_BIT, work_data_bits(work))
#define KVFREE_GET_MACRO(_1, _2, NAME, ...) NAME
#define RCU_INITIALIZER(v) (typeof(*(v)) __force __rcu *)(v)
#define RCU_INIT_POINTER(p, v) \
	do { \
		rcu_check_sparse(p, __rcu); \
		WRITE_ONCE(p, RCU_INITIALIZER(v)); \
	} while (0)
#define RCU_LOCKDEP_WARN(c, s)						\
	do {								\
		static bool __section(".data.unlikely") __warned;	\
		if ((c) && debug_lockdep_rcu_enabled() && !__warned) {	\
			__warned = true;				\
			lockdep_rcu_suspicious("__FILE__", "__LINE__", s);	\
		}							\
	} while (0)
#define RCU_NONIDLE(a) \
	do { \
		rcu_irq_enter_irqson(); \
		do { a; } while (0); \
		rcu_irq_exit_irqson(); \
	} while (0)
#define RCU_POINTER_INITIALIZER(p, v) \
		.p = RCU_INITIALIZER(v)
#define ULONG_CMP_GE(a, b)	(ULONG_MAX / 2 >= (a) - (b))
#define ULONG_CMP_LT(a, b)	(ULONG_MAX / 2 < (a) - (b))
#define USHORT_CMP_GE(a, b)	(USHRT_MAX / 2 >= (unsigned short)((a) - (b)))
#define USHORT_CMP_LT(a, b)	(USHRT_MAX / 2 < (unsigned short)((a) - (b)))

#define __is_kvfree_rcu_offset(offset) ((offset) < 4096)
#define __rcu_access_pointer(p, space) \
({ \
	typeof(*p) *_________p1 = (typeof(*p) *__force)READ_ONCE(p); \
	rcu_check_sparse(p, space); \
	((typeof(*p) __force __kernel *)(_________p1)); \
})
#define __rcu_dereference_check(p, c, space) \
({ \
	 \
	typeof(*p) *________p1 = (typeof(*p) *__force)READ_ONCE(p); \
	RCU_LOCKDEP_WARN(!(c), "suspicious rcu_dereference_check() usage"); \
	rcu_check_sparse(p, space); \
	((typeof(*p) __force __kernel *)(________p1)); \
})
#define __rcu_dereference_protected(p, c, space) \
({ \
	RCU_LOCKDEP_WARN(!(c), "suspicious rcu_dereference_protected() usage"); \
	rcu_check_sparse(p, space); \
	((typeof(*p) __force __kernel *)(p)); \
})
# define call_rcu_tasks call_rcu
#define cond_resched_tasks_rcu_qs() \
do { \
	rcu_tasks_qs(current, false); \
	cond_resched(); \
} while (0)
#define kfree_rcu(ptr, rhf...) kvfree_rcu(ptr, ## rhf)
#define kvfree_rcu(...) KVFREE_GET_MACRO(__VA_ARGS__,		\
	kvfree_rcu_arg_2, kvfree_rcu_arg_1)(__VA_ARGS__)
#define kvfree_rcu_arg_1(ptr)					\
do {								\
	typeof(ptr) ___p = (ptr);				\
								\
	if (___p)						\
		kvfree_call_rcu(NULL, (rcu_callback_t) (___p));	\
} while (0)
#define kvfree_rcu_arg_2(ptr, rhf)					\
do {									\
	typeof (ptr) ___p = (ptr);					\
									\
	if (___p) {									\
		BUILD_BUG_ON(!__is_kvfree_rcu_offset(offsetof(typeof(*(ptr)), rhf)));	\
		kvfree_call_rcu(&((___p)->rhf), (rcu_callback_t)(unsigned long)		\
			(offsetof(typeof(*(ptr)), rhf)));				\
	}										\
} while (0)
#define rcu_access_pointer(p) __rcu_access_pointer((p), __rcu)
#define rcu_assign_pointer(p, v)					      \
do {									      \
	uintptr_t _r_a_p__v = (uintptr_t)(v);				      \
	rcu_check_sparse(p, __rcu);					      \
									      \
	if (__builtin_constant_p(v) && (_r_a_p__v) == (uintptr_t)NULL)	      \
		WRITE_ONCE((p), (typeof(p))(_r_a_p__v));		      \
	else								      \
		smp_store_release(&p, RCU_INITIALIZER((typeof(p))_r_a_p__v)); \
} while (0)
#define rcu_check_sparse(p, space) \
	((void)(((typeof(*p) space *)p) == p))
#define rcu_dereference(p) rcu_dereference_check(p, 0)
#define rcu_dereference_bh(p) rcu_dereference_bh_check(p, 0)
#define rcu_dereference_bh_check(p, c) \
	__rcu_dereference_check((p), (c) || rcu_read_lock_bh_held(), __rcu)
#define rcu_dereference_check(p, c) \
	__rcu_dereference_check((p), (c) || rcu_read_lock_held(), __rcu)
#define rcu_dereference_protected(p, c) \
	__rcu_dereference_protected((p), (c), __rcu)
#define rcu_dereference_raw(p) \
({ \
	 \
	typeof(p) ________p1 = READ_ONCE(p); \
	((typeof(*p) __force __kernel *)(________p1)); \
})
#define rcu_dereference_raw_check(p) __rcu_dereference_check((p), 1, __rcu)
#define rcu_dereference_sched(p) rcu_dereference_sched_check(p, 0)
#define rcu_dereference_sched_check(p, c) \
	__rcu_dereference_check((p), (c) || rcu_read_lock_sched_held(), \
				__rcu)
# define rcu_lock_acquire(a)		do { } while (0)
# define rcu_lock_release(a)		do { } while (0)
#define rcu_note_voluntary_context_switch(t) rcu_tasks_qs(t, false)
#define rcu_pointer_handoff(p) (p)
#define rcu_preempt_depth() READ_ONCE(current->rcu_read_lock_nesting)
#define rcu_read_unlock_strict() do { } while (0)
#define rcu_replace_pointer(rcu_ptr, ptr, c)				\
({									\
	typeof(ptr) __tmp = rcu_dereference_protected((rcu_ptr), (c));	\
	rcu_assign_pointer((rcu_ptr), (ptr));				\
	__tmp;								\
})
#define rcu_sleep_check()						\
	do {								\
		rcu_preempt_sleep_check();				\
		if (!IS_ENABLED(CONFIG_PREEMPT_RT))			\
		    RCU_LOCKDEP_WARN(lock_is_held(&rcu_bh_lock_map),	\
				 "Illegal context switch in RCU-bh read-side critical section"); \
		RCU_LOCKDEP_WARN(lock_is_held(&rcu_sched_lock_map),	\
				 "Illegal context switch in RCU-sched read-side critical section"); \
	} while (0)
# define rcu_tasks_classic_qs(t, preempt)				\
	do {								\
		if (!(preempt) && READ_ONCE((t)->rcu_tasks_holdout))	\
			WRITE_ONCE((t)->rcu_tasks_holdout, false);	\
	} while (0)
#define rcu_tasks_qs(t, preempt)					\
do {									\
	rcu_tasks_classic_qs((t), (preempt));				\
	rcu_tasks_trace_qs((t));					\
} while (0)
# define rcu_tasks_trace_qs(t)						\
	do {								\
		if (!likely(READ_ONCE((t)->trc_reader_checked)) &&	\
		    !unlikely(READ_ONCE((t)->trc_reader_nesting))) {	\
			smp_store_release(&(t)->trc_reader_checked, true); \
			smp_mb(); 	\
		}							\
	} while (0)
#define smp_mb__after_unlock_lock()	smp_mb()  
# define synchronize_rcu_tasks synchronize_rcu
#define ulong2long(a)		(*(long *)(&(a)))
#define unrcu_pointer(p)						\
({									\
	typeof(*p) *_________p1 = (typeof(*p) *__force)(p);		\
	rcu_check_sparse(p, __rcu);					\
	((typeof(*p) __force __kernel *)(_________p1)); 		\
})

#define rcu_is_idle_cpu(cpu) \
	(is_idle_task(current) && !in_nmi() && !in_irq() && !in_serving_softirq())
#define rcu_note_context_switch(preempt) \
	do { \
		rcu_qs(); \
		rcu_tasks_qs(current, (preempt)); \
	} while (0)
#define rcutree_dead_cpu         NULL
#define rcutree_dying_cpu        NULL
#define rcutree_offline_cpu      NULL
#define rcutree_online_cpu       NULL
#define rcutree_prepare_cpu      NULL

#define DEFINE_TIMER(_name, _function)				\
	struct timer_list _name =				\
		__TIMER_INITIALIZER(_function, 0)

#define __TIMER_INITIALIZER(_function, _flags) {		\
		.entry = { .next = TIMER_ENTRY_STATIC },	\
		.function = (_function),			\
		.flags = (_flags),				\
		__TIMER_LOCKDEP_MAP_INITIALIZER(		\
			"__FILE__" ":" __stringify("__LINE__"))	\
	}
#define __TIMER_LOCKDEP_MAP_INITIALIZER(_kn)				\
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(_kn, &_kn),
#define __init_timer(_timer, _fn, _flags)				\
	do {								\
		static struct lock_class_key __key;			\
		init_timer_key((_timer), (_fn), (_flags), #_timer, &__key);\
	} while (0)
#define __init_timer_on_stack(_timer, _fn, _flags)			\
	do {								\
		static struct lock_class_key __key;			\
		init_timer_on_stack_key((_timer), (_fn), (_flags),	\
					#_timer, &__key);		 \
	} while (0)
#define del_singleshot_timer_sync(t) del_timer_sync(t)
# define del_timer_sync(t)		del_timer(t)
#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)
#define timer_setup(timer, callback, flags)			\
	__init_timer((timer), (callback), (flags))
#define timer_setup_on_stack(timer, callback, flags)		\
	__init_timer_on_stack((timer), (callback), (flags))


#define ktime_add(lhs, rhs)	((lhs) + (rhs))
#define ktime_add_ns(kt, nsval)		((kt) + (nsval))
#define ktime_add_unsafe(lhs, rhs)	((u64) (lhs) + (rhs))
#define ktime_sub(lhs, rhs)	((lhs) - (rhs))
#define ktime_sub_ns(kt, nsval)		((kt) - (nsval))
#define ktime_to_timespec64(kt)		ns_to_timespec64((kt))

#define TICK_NSEC ((NSEC_PER_SEC+HZ/2)/HZ)

#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))
#define LATCH ((CLOCK_TICK_RATE + HZ/2) / HZ)	
#define MAX_JIFFY_OFFSET ((LONG_MAX >> 1)-1)
# define MAX_SEC_IN_JIFFIES \
	(long)((u64)((u64)MAX_JIFFY_OFFSET * TICK_NSEC) / NSEC_PER_SEC)
#define NSEC_CONVERSION ((unsigned long)((((u64)1 << NSEC_JIFFIE_SC) +\
                                        TICK_NSEC -1) / (u64)TICK_NSEC))
#define NSEC_JIFFIE_SC (SEC_JIFFIE_SC + 29)
#define SEC_CONVERSION ((unsigned long)((((u64)NSEC_PER_SEC << SEC_JIFFIE_SC) +\
                                TICK_NSEC -1) / (u64)TICK_NSEC))
#define SEC_JIFFIE_SC (31 - SHIFT_HZ)
#define SH_DIV(NOM,DEN,LSH) (   (((NOM) / (DEN)) << (LSH))              \
                             + ((((NOM) % (DEN)) << (LSH)) + (DEN) / 2) / (DEN))
#define TICK_USEC ((USEC_PER_SEC + HZ/2) / HZ)
#define USER_TICK_USEC ((1000000UL + USER_HZ/2) / USER_HZ)


#define time_after(a,b)		\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)((b) - (a)) < 0))
#define time_after64(a,b)	\
	(typecheck(__u64, a) &&	\
	 typecheck(__u64, b) && \
	 ((__s64)((b) - (a)) < 0))
#define time_after_eq(a,b)	\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)((a) - (b)) >= 0))
#define time_after_eq64(a,b)	\
	(typecheck(__u64, a) && \
	 typecheck(__u64, b) && \
	 ((__s64)((a) - (b)) >= 0))
#define time_before(a,b)	time_after(b,a)
#define time_before64(a,b)	time_after64(b,a)
#define time_before_eq(a,b)	time_after_eq(b,a)
#define time_before_eq64(a,b)	time_after_eq64(b,a)
#define time_in_range(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before_eq(a,c))
#define time_in_range64(a, b, c) \
	(time_after_eq64(a, b) && \
	 time_before_eq64(a, c))
#define time_in_range_open(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before(a,c))
#define time_is_after_eq_jiffies(a) time_before_eq(jiffies, a)
#define time_is_after_eq_jiffies64(a) time_before_eq64(get_jiffies_64(), a)
#define time_is_after_jiffies(a) time_before(jiffies, a)
#define time_is_after_jiffies64(a) time_before64(get_jiffies_64(), a)
#define time_is_before_eq_jiffies(a) time_after_eq(jiffies, a)
#define time_is_before_eq_jiffies64(a) time_after_eq64(get_jiffies_64(), a)
#define time_is_before_jiffies(a) time_after(jiffies, a)
#define time_is_before_jiffies64(a) time_after64(get_jiffies_64(), a)
#define MAXFREQ 500000		
#define MAXFREQ_SCALED ((s64)MAXFREQ << NTP_SCALE_SHIFT)
#define MAXPHASE 500000000L	
#define MAXSEC 2048		
#define MINSEC 256		
#define NTP_INTERVAL_FREQ  (HZ)
#define NTP_INTERVAL_LENGTH (NSEC_PER_SEC/NTP_INTERVAL_FREQ)
#define NTP_PHASE_LIMIT ((MAXPHASE / NSEC_PER_USEC) << 5) 
#define PIT_TICK_RATE 1193182ul
#define PPM_SCALE ((s64)NSEC_PER_USEC << (NTP_SCALE_SHIFT - SHIFT_USEC))
#define PPM_SCALE_INV ((1LL << (PPM_SCALE_INV_SHIFT + NTP_SCALE_SHIFT)) / \
		       PPM_SCALE + 1)
#define PPM_SCALE_INV_SHIFT 19
#define SHIFT_USEC 16		

#define random_get_entropy()	get_cycles()
#define shift_right(x, s) ({	\
	__typeof__(x) __x = (x);	\
	__typeof__(s) __s = (s);	\
	__x < 0 ? -(-__x >> __s) : __x >> __s;	\
})
#define STA_RONLY (STA_PPSSIGNAL | STA_PPSJITTER | STA_PPSWANDER | \
	STA_PPSERROR | STA_CLOCKERR | STA_NANO | STA_MODE | STA_CLK)


#define time_after32(a, b)	((s32)((u32)(b) - (u32)(a)) < 0)
#define time_before32(b, a)	time_after32(a, b)
#define time_between32(t, l, h) ((u32)(h) - (u32)(l) >= (u32)(t) - (u32)(l))
#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)
# define __DEBUG_MUTEX_INITIALIZER(lockname)
# define __DEP_MAP_MUTEX_INITIALIZER(lockname)			\
		, .dep_map = {					\
			.name = #lockname,			\
			.wait_type_inner = LD_WAIT_SLEEP,	\
		}

#define __MUTEX_INITIALIZER(lockname) \
		{ .owner = ATOMIC_LONG_INIT(0) \
		, .wait_lock = __RAW_SPIN_LOCK_UNLOCKED(lockname.wait_lock) \
		, .wait_list = LIST_HEAD_INIT(lockname.wait_list) \
		__DEBUG_MUTEX_INITIALIZER(lockname) \
		__DEP_MAP_MUTEX_INITIALIZER(lockname) }
#define __mutex_init(mutex, name, key)			\
do {							\
	rt_mutex_base_init(&(mutex)->rtmutex);		\
	__mutex_rt_init((mutex), name, key);		\
} while (0)
#define mutex_init(mutex)						\
do {									\
	static struct lock_class_key __key;				\
									\
	__mutex_init((mutex), #mutex, &__key);				\
} while (0)
#define mutex_is_locked(l)	rt_mutex_base_is_locked(&(l)->rtmutex)
#define mutex_lock(lock) mutex_lock_nested(lock, 0)
#define mutex_lock_interruptible(lock) mutex_lock_interruptible_nested(lock, 0)
# define mutex_lock_interruptible_nested(lock, subclass) mutex_lock_interruptible(lock)
#define mutex_lock_io(lock) mutex_lock_io_nested(lock, 0)
# define mutex_lock_io_nested(lock, subclass) mutex_lock_io(lock)
#define mutex_lock_killable(lock) mutex_lock_killable_nested(lock, 0)
# define mutex_lock_killable_nested(lock, subclass) mutex_lock_killable(lock)
# define mutex_lock_nest_lock(lock, nest_lock) mutex_lock(lock)
# define mutex_lock_nested(lock, subclass) mutex_lock(lock)
#define OSQ_LOCK_UNLOCKED { ATOMIC_INIT(OSQ_UNLOCKED_VAL) }
#define OSQ_UNLOCKED_VAL (0)

#define DECLARE_RWSEM(name) \
	struct rw_semaphore name = __RWSEM_INITIALIZER(name)

#define __RWSEM_COUNT_INIT(name)	.count = ATOMIC_LONG_INIT(RWSEM_UNLOCKED_VALUE)
# define __RWSEM_DEBUG_INIT(lockname) .magic = &lockname,
# define __RWSEM_DEP_MAP_INIT(lockname)			\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_SLEEP,	\
	},
#define __RWSEM_INITIALIZER(name)				\
	{							\
		.rwbase = __RWBASE_INITIALIZER(name),		\
		__RWSEM_DEP_MAP_INIT(name)			\
	}
#define __RWSEM_OPT_INIT(lockname) .osq = OSQ_LOCK_UNLOCKED,
# define down_read_killable_nested(sem, subclass)	down_read_killable(sem)
# define down_read_nested(sem, subclass)		down_read(sem)
# define down_read_non_owner(sem)		down_read(sem)
# define down_write_killable_nested(sem, subclass)	down_write_killable(sem)
# define down_write_nest_lock(sem, nest_lock)			\
do {								\
	typecheck(struct lockdep_map *, &(nest_lock)->dep_map);	\
	_down_write_nest_lock(sem, &(nest_lock)->dep_map);	\
} while (0);
# define down_write_nested(sem, subclass)	down_write(sem)
#define init_rwsem(sem)						\
do {								\
	static struct lock_class_key __key;			\
								\
	__init_rwsem((sem), #sem, &__key);			\
} while (0)
# define up_read_non_owner(sem)			up_read(sem)
#define IS_ERR_VALUE(x) unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

#define TEGRA_FUSE_USB_CALIB_EXT_0 0x250


#define APR_MODULE_PREFIX "apr:"
#define AUXILIARY_MODULE_PREFIX "auxiliary:"
#define AUXILIARY_NAME_SIZE 32
#define BCMA_CORE(_manuf, _id, _rev, _class)  \
	{ .manuf = _manuf, .id = _id, .rev = _rev, .class = _class, }
#define DMI_EXACT_MATCH(a, b)	{ .slot = a, .substr = b, .exact_match = 1 }
#define DMI_MATCH(a, b)	{ .slot = a, .substr = b }
#define EISA_DEVICE_MODALIAS_FMT "eisa:s%s"
#define EISA_SIG_LEN   8
#define I2C_MODULE_PREFIX "i2c:"
#define IPACK_ANY_FORMAT 0xff
#define IPACK_ANY_ID (~0)

#define MDIO_ID_ARGS(_id) \
	((_id)>>31) & 1, ((_id)>>30) & 1, ((_id)>>29) & 1, ((_id)>>28) & 1, \
	((_id)>>27) & 1, ((_id)>>26) & 1, ((_id)>>25) & 1, ((_id)>>24) & 1, \
	((_id)>>23) & 1, ((_id)>>22) & 1, ((_id)>>21) & 1, ((_id)>>20) & 1, \
	((_id)>>19) & 1, ((_id)>>18) & 1, ((_id)>>17) & 1, ((_id)>>16) & 1, \
	((_id)>>15) & 1, ((_id)>>14) & 1, ((_id)>>13) & 1, ((_id)>>12) & 1, \
	((_id)>>11) & 1, ((_id)>>10) & 1, ((_id)>>9) & 1, ((_id)>>8) & 1, \
	((_id)>>7) & 1, ((_id)>>6) & 1, ((_id)>>5) & 1, ((_id)>>4) & 1, \
	((_id)>>3) & 1, ((_id)>>2) & 1, ((_id)>>1) & 1, (_id) & 1
#define MDIO_ID_FMT "%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u"
#define MEI_CL_MODULE_PREFIX "mei:"
#define MEI_CL_NAME_SIZE 32
#define MEI_CL_VERSION_ANY 0xff
#define MHI_DEVICE_MODALIAS_FMT "mhi:%s"
#define MHI_NAME_SIZE 32
#define PCI_ANY_ID (~0)
#define SDIO_ANY_ID (~0)
#define SPI_MODULE_PREFIX "spi:"
#define SPMI_MODULE_PREFIX "spmi:"
#define SSB_DEVICE(_vendor, _coreid, _revision)  \
	{ .vendor = _vendor, .coreid = _coreid, .revision = _revision, }
#define X86_FAMILY_ANY 0
#define X86_FEATURE_ANY 0	
#define X86_MODEL_ANY  0
#define X86_STEPPING_ANY 0
#define X86_VENDOR_ANY 0xffff
#define dmi_device_id dmi_system_id
#define x86cpu_device_id x86_cpu_id
#define UUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)			\
((uuid_t)								\
{{ ((a) >> 24) & 0xff, ((a) >> 16) & 0xff, ((a) >> 8) & 0xff, (a) & 0xff, \
   ((b) >> 8) & 0xff, (b) & 0xff,					\
   ((c) >> 8) & 0xff, (c) & 0xff,					\
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})
#define UUID_SIZE 16

#define GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)			\
((guid_t)								\
{{ (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
   (b) & 0xff, ((b) >> 8) & 0xff,					\
   (c) & 0xff, ((c) >> 8) & 0xff,					\
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})
#define UUID_LE(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)		\
	GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)

#define MAX_PHANDLE_ARGS 16
#define OF_DECLARE_1(table, name, compat, fn) \
		_OF_DECLARE(table, name, compat, fn, of_init_fn_1)
#define OF_DECLARE_1_RET(table, name, compat, fn) \
		_OF_DECLARE(table, name, compat, fn, of_init_fn_1_ret)
#define OF_DECLARE_2(table, name, compat, fn) \
		_OF_DECLARE(table, name, compat, fn, of_init_fn_2)
#define OF_IS_DYNAMIC(x) test_bit(OF_DYNAMIC, &x->_flags)
#define OF_MARK_DYNAMIC(x) set_bit(OF_DYNAMIC, &x->_flags)

#define _OF_DECLARE(table, name, compat, fn, fn_type)			\
	static const struct of_device_id __of_table_##name		\
		__used __section("__" #table "_of_table")		\
		__aligned(__alignof__(struct of_device_id))		\
		 = { .compatible = compat,				\
		     .data = (fn == (fn_type)NULL) ? fn : fn  }
#define _OF_DECLARE_STUB(table, name, compat, fn, fn_type)		\
	static const struct of_device_id __of_table_##name		\
		__attribute__((unused))					\
		 = { .compatible = compat,				\
		     .data = (fn == (fn_type)NULL) ? fn : fn }
#define for_each_available_child_of_node(parent, child) \
	for (child = of_get_next_available_child(parent, NULL); child != NULL; \
	     child = of_get_next_available_child(parent, child))
#define for_each_child_of_node(parent, child) \
	for (child = of_get_next_child(parent, NULL); child != NULL; \
	     child = of_get_next_child(parent, child))
#define for_each_compatible_node(dn, type, compatible) \
	for (dn = of_find_compatible_node(NULL, type, compatible); dn; \
	     dn = of_find_compatible_node(dn, type, compatible))
#define for_each_matching_node(dn, matches) \
	for (dn = of_find_matching_node(NULL, matches); dn; \
	     dn = of_find_matching_node(dn, matches))
#define for_each_matching_node_and_match(dn, matches, match) \
	for (dn = of_find_matching_node_and_match(NULL, matches, match); \
	     dn; dn = of_find_matching_node_and_match(dn, matches, match))
#define for_each_node_by_name(dn, name) \
	for (dn = of_find_node_by_name(NULL, name); dn; \
	     dn = of_find_node_by_name(dn, name))
#define for_each_node_by_type(dn, type) \
	for (dn = of_find_node_by_type(NULL, type); dn; \
	     dn = of_find_node_by_type(dn, type))
#define for_each_node_with_property(dn, prop_name) \
	for (dn = of_find_node_with_property(NULL, prop_name); dn; \
	     dn = of_find_node_with_property(dn, prop_name))
#define for_each_of_allnodes(dn) for_each_of_allnodes_from(NULL, dn)
#define for_each_of_allnodes_from(from, dn) \
	for (dn = __of_find_all_nodes(from); dn; dn = __of_find_all_nodes(dn))
#define for_each_of_cpu_node(cpu) \
	for (cpu = of_get_next_cpu_node(NULL); cpu != NULL; \
	     cpu = of_get_next_cpu_node(cpu))
#define for_each_property_of_node(dn, pp) \
	for (pp = dn->properties; pp != NULL; pp = pp->next)
#define of_compat_cmp(s1, s2, l)	strcasecmp((s1), (s2))
#define of_for_each_phandle(it, err, np, ln, cn, cc)			\
	for (of_phandle_iterator_init((it), (np), (ln), (cn), (cc)),	\
	     err = of_phandle_iterator_next(it);			\
	     err == 0;							\
	     err = of_phandle_iterator_next(it))
#define of_fwnode_handle(node)						\
	({								\
		typeof(node) __of_fwnode_handle_node = (node);		\
									\
		__of_fwnode_handle_node ?				\
			&__of_fwnode_handle_node->fwnode : NULL;	\
	})
#define of_match_node(_matches, _node)	NULL
#define of_match_ptr(_ptr)	NULL
#define of_node_cmp(s1, s2)		strcasecmp((s1), (s2))
#define of_node_kobj(n) (&(n)->kobj)
#define of_prop_cmp(s1, s2)		strcmp((s1), (s2))
#define of_property_for_each_string(np, propname, prop, s)	\
	for (prop = of_find_property(np, propname, NULL),	\
		s = of_prop_next_string(prop, NULL);		\
		s;						\
		s = of_prop_next_string(prop, s))
#define of_property_for_each_u32(np, propname, prop, p, u)	\
	for (prop = of_find_property(np, propname, NULL),	\
		p = of_prop_next_u32(prop, NULL, &u);		\
		p;						\
		p = of_prop_next_u32(prop, p, &u))
#define to_of_node(__fwnode)						\
	({								\
		typeof(__fwnode) __to_of_node_fwnode = (__fwnode);	\
									\
		is_of_node(__to_of_node_fwnode) ?			\
			container_of(__to_of_node_fwnode,		\
				     struct device_node, fwnode) :	\
			NULL;						\
	})
#define PROPERTY_ENTRY_BOOL(_name_)		\
(struct property_entry) {			\
	.name = _name_,				\
	.is_inline = true,			\
}
#define PROPERTY_ENTRY_REF(_name_, _ref_, ...)				\
(struct property_entry) {						\
	.name = _name_,							\
	.length = sizeof(struct software_node_ref_args),		\
	.type = DEV_PROP_REF,						\
	{ .pointer = &SOFTWARE_NODE_REFERENCE(_ref_, ##__VA_ARGS__), },	\
}
#define PROPERTY_ENTRY_REF_ARRAY(_name_, _val_)			\
	PROPERTY_ENTRY_REF_ARRAY_LEN(_name_, _val_, ARRAY_SIZE(_val_))
#define PROPERTY_ENTRY_REF_ARRAY_LEN(_name_, _val_, _len_)		\
	__PROPERTY_ENTRY_ARRAY_ELSIZE_LEN(_name_,			\
				sizeof(struct software_node_ref_args),	\
				REF, _val_, _len_)
#define PROPERTY_ENTRY_STRING(_name_, _val_)				\
	__PROPERTY_ENTRY_ELEMENT(_name_, str, STRING, _val_)
#define PROPERTY_ENTRY_STRING_ARRAY(_name_, _val_)			\
	PROPERTY_ENTRY_STRING_ARRAY_LEN(_name_, _val_, ARRAY_SIZE(_val_))
#define PROPERTY_ENTRY_STRING_ARRAY_LEN(_name_, _val_, _len_)		\
	__PROPERTY_ENTRY_ARRAY_LEN(_name_, str, STRING, _val_, _len_)
#define PROPERTY_ENTRY_U16(_name_, _val_)				\
	__PROPERTY_ENTRY_ELEMENT(_name_, u16_data, U16, _val_)
#define PROPERTY_ENTRY_U16_ARRAY(_name_, _val_)				\
	PROPERTY_ENTRY_U16_ARRAY_LEN(_name_, _val_, ARRAY_SIZE(_val_))
#define PROPERTY_ENTRY_U16_ARRAY_LEN(_name_, _val_, _len_)		\
	__PROPERTY_ENTRY_ARRAY_LEN(_name_, u16_data, U16, _val_, _len_)
#define PROPERTY_ENTRY_U32(_name_, _val_)				\
	__PROPERTY_ENTRY_ELEMENT(_name_, u32_data, U32, _val_)
#define PROPERTY_ENTRY_U32_ARRAY(_name_, _val_)				\
	PROPERTY_ENTRY_U32_ARRAY_LEN(_name_, _val_, ARRAY_SIZE(_val_))
#define PROPERTY_ENTRY_U32_ARRAY_LEN(_name_, _val_, _len_)		\
	__PROPERTY_ENTRY_ARRAY_LEN(_name_, u32_data, U32, _val_, _len_)
#define PROPERTY_ENTRY_U64(_name_, _val_)				\
	__PROPERTY_ENTRY_ELEMENT(_name_, u64_data, U64, _val_)
#define PROPERTY_ENTRY_U64_ARRAY(_name_, _val_)				\
	PROPERTY_ENTRY_U64_ARRAY_LEN(_name_, _val_, ARRAY_SIZE(_val_))
#define PROPERTY_ENTRY_U64_ARRAY_LEN(_name_, _val_, _len_)		\
	__PROPERTY_ENTRY_ARRAY_LEN(_name_, u64_data, U64, _val_, _len_)
#define PROPERTY_ENTRY_U8(_name_, _val_)				\
	__PROPERTY_ENTRY_ELEMENT(_name_, u8_data, U8, _val_)
#define PROPERTY_ENTRY_U8_ARRAY(_name_, _val_)				\
	PROPERTY_ENTRY_U8_ARRAY_LEN(_name_, _val_, ARRAY_SIZE(_val_))
#define PROPERTY_ENTRY_U8_ARRAY_LEN(_name_, _val_, _len_)		\
	__PROPERTY_ENTRY_ARRAY_LEN(_name_, u8_data, U8, _val_, _len_)
#define SOFTWARE_NODE_REFERENCE(_ref_, ...)			\
(const struct software_node_ref_args) {				\
	.node = _ref_,						\
	.nargs = ARRAY_SIZE(((u64[]){ 0, ##__VA_ARGS__ })) - 1,	\
	.args = { __VA_ARGS__ },				\
}

#define __PROPERTY_ENTRY_ARRAY_ELSIZE_LEN(_name_, _elsize_, _Type_,	\
					  _val_, _len_)			\
(struct property_entry) {						\
	.name = _name_,							\
	.length = (_len_) * (_elsize_),					\
	.type = DEV_PROP_##_Type_,					\
	{ .pointer = _val_ },						\
}
#define __PROPERTY_ENTRY_ARRAY_LEN(_name_, _elem_, _Type_, _val_, _len_)\
	__PROPERTY_ENTRY_ARRAY_ELSIZE_LEN(_name_,			\
				__PROPERTY_ENTRY_ELEMENT_SIZE(_elem_),	\
				_Type_, _val_, _len_)
#define __PROPERTY_ENTRY_ELEMENT(_name_, _elem_, _Type_, _val_)		\
(struct property_entry) {						\
	.name = _name_,							\
	.length = __PROPERTY_ENTRY_ELEMENT_SIZE(_elem_),		\
	.is_inline = true,						\
	.type = DEV_PROP_##_Type_,					\
	{ .value = { ._elem_[0] = _val_ } },				\
}
#define __PROPERTY_ENTRY_ELEMENT_SIZE(_elem_)				\
	sizeof(((struct property_entry *)NULL)->value._elem_[0])
#define device_for_each_child_node(dev, child)				\
	for (child = device_get_next_child_node(dev, NULL); child;	\
	     child = device_get_next_child_node(dev, child))
#define fwnode_for_each_available_child_node(fwnode, child)		       \
	for (child = fwnode_get_next_available_child_node(fwnode, NULL); child;\
	     child = fwnode_get_next_available_child_node(fwnode, child))
#define fwnode_for_each_child_node(fwnode, child)			\
	for (child = fwnode_get_next_child_node(fwnode, NULL); child;	\
	     child = fwnode_get_next_child_node(fwnode, child))
#define fwnode_graph_for_each_endpoint(fwnode, child)			\
	for (child = NULL;						\
	     (child = fwnode_graph_get_next_endpoint(fwnode, child)); )

#define fwnode_call_bool_op(fwnode, op, ...)		\
	(fwnode_has_op(fwnode, op) ?			\
	 (fwnode)->ops->op(fwnode, ## __VA_ARGS__) : false)
#define fwnode_call_int_op(fwnode, op, ...)				\
	(fwnode ? (fwnode_has_op(fwnode, op) ?				\
		   (fwnode)->ops->op(fwnode, ## __VA_ARGS__) : -ENXIO) : \
	 -EINVAL)
#define fwnode_call_ptr_op(fwnode, op, ...)		\
	(fwnode_has_op(fwnode, op) ?			\
	 (fwnode)->ops->op(fwnode, ## __VA_ARGS__) : NULL)
#define fwnode_call_void_op(fwnode, op, ...)				\
	do {								\
		if (fwnode_has_op(fwnode, op))				\
			(fwnode)->ops->op(fwnode, ## __VA_ARGS__);	\
	} while (false)
#define fwnode_has_op(fwnode, op)				\
	((fwnode) && (fwnode)->ops && (fwnode)->ops->op)
#define get_dev_from_fwnode(fwnode)	get_device((fwnode)->dev)
#define DISTANCE_BITS           8
#define RECLAIM_DISTANCE 30

#define for_each_node_with_cpus(node)			\
	for_each_online_node(node)			\
		if (nr_cpus_node(node))
#define node_distance(from,to)	((from) == (to) ? LOCAL_DISTANCE : REMOTE_DISTANCE)
#define nr_cpus_node(node) cpumask_weight(cpumask_of_node(node))
#define topology_core_cpumask(cpu)		cpumask_of(cpu)
#define topology_core_id(cpu)			((void)(cpu), 0)
#define topology_die_cpumask(cpu)		cpumask_of(cpu)
#define topology_die_id(cpu)			((void)(cpu), -1)
#define topology_physical_package_id(cpu)	((void)(cpu), -1)
#define topology_sibling_cpumask(cpu)		cpumask_of(cpu)

#define alloc_percpu(type)						\
	(typeof(type) __percpu *)__alloc_percpu(sizeof(type),		\
						__alignof__(type))
#define alloc_percpu_gfp(type, gfp)					\
	(typeof(type) __percpu *)__alloc_percpu_gfp(sizeof(type),	\
						__alignof__(type), gfp)
#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)
#define PHYS_PFN(x)	((unsigned long)((x) >> PAGE_SHIFT))

#define LINUX_MM_DEBUG_H 1
#define VIRTUAL_BUG_ON(cond) BUG_ON(cond)
#define VM_BUG_ON(cond) BUG_ON(cond)
#define VM_BUG_ON_MM(cond, mm)						\
	do {								\
		if (unlikely(cond)) {					\
			dump_mm(mm);					\
			BUG();						\
		}							\
	} while (0)
#define VM_BUG_ON_PAGE(cond, page)					\
	do {								\
		if (unlikely(cond)) {					\
			dump_page(page, "VM_BUG_ON_PAGE(" __stringify(cond)")");\
			BUG();						\
		}							\
	} while (0)
#define VM_BUG_ON_PGFLAGS(cond, page) VM_BUG_ON_PAGE(cond, page)
#define VM_BUG_ON_VMA(cond, vma)					\
	do {								\
		if (unlikely(cond)) {					\
			dump_vma(vma);					\
			BUG();						\
		}							\
	} while (0)
#define VM_WARN(cond, format...) (void)WARN(cond, format)
#define VM_WARN_ON(cond) (void)WARN_ON(cond)
#define VM_WARN_ONCE(cond, format...) (void)WARN_ONCE(cond, format)
#define VM_WARN_ON_ONCE(cond) (void)WARN_ON_ONCE(cond)
#define VM_WARN_ON_ONCE_PAGE(cond, page)	({			\
	static bool __section(".data.once") __warned;			\
	int __ret_warn_once = !!(cond);					\
									\
	if (unlikely(__ret_warn_once && !__warned)) {			\
		dump_page(page, "VM_WARN_ON_ONCE_PAGE(" __stringify(cond)")");\
		__warned = true;					\
		WARN_ON(1);						\
	}								\
	unlikely(__ret_warn_once);					\
})
#define ANON_AND_FILE 2
#define ASYNC_AND_SYNC 2
#define DEF_PRIORITY 12
#define LRU_ACTIVE 1
#define LRU_BASE 0
#define LRU_FILE 2
#define MAX_ORDER 11
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)
#define MIGRATETYPE_MASK ((1UL << PB_migratetype_bits) - 1)
#define NODE_MEM_MAP(nid)	mem_map
#define NR_PCP_LISTS (MIGRATE_PCPTYPES * (PAGE_ALLOC_COSTLY_ORDER + 1 + NR_PCP_THP))
#define NR_PCP_ORDER_MASK ((1<<NR_PCP_ORDER_WIDTH) - 1)
#define NR_PCP_ORDER_WIDTH 8
#define NR_PCP_THP 1
#define NR_VM_NUMA_EVENT_ITEMS 0
#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define PAGES_PER_SUBSECTION (1UL << PFN_SUBSECTION_SHIFT)
#define PAGE_ALLOC_COSTLY_ORDER 3
#define PAGE_SUBSECTION_MASK (~(PAGES_PER_SUBSECTION-1))
#define PFN_SUBSECTION_SHIFT (SUBSECTION_SHIFT - PAGE_SHIFT)
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#define SECTION_ALIGN_DOWN(pfn)	((pfn) & PAGE_SECTION_MASK)
#define SECTION_ALIGN_UP(pfn)	(((pfn) + PAGES_PER_SECTION - 1) & PAGE_SECTION_MASK)
#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)
#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define SUBSECTIONS_PER_SECTION (1UL << (SECTION_SIZE_BITS - SUBSECTION_SHIFT))
#define SUBSECTION_ALIGN_DOWN(pfn) ((pfn) & PAGE_SUBSECTION_MASK)
#define SUBSECTION_ALIGN_UP(pfn) ALIGN((pfn), PAGES_PER_SUBSECTION)
#define SUBSECTION_SHIFT 21
#define SUBSECTION_SIZE (1UL << SUBSECTION_SHIFT)
#define ZONE_PADDING(name)	struct zone_padding name;

#define for_each_evictable_lru(lru) for (lru = 0; lru <= LRU_ACTIVE_FILE; lru++)
#define for_each_lru(lru) for (lru = 0; lru < NR_LRU_LISTS; lru++)
#define for_each_migratetype_order(order, type) \
	for (order = 0; order < MAX_ORDER; order++) \
		for (type = 0; type < MIGRATE_TYPES; type++)
#define for_each_online_pgdat(pgdat)			\
	for (pgdat = first_online_pgdat();		\
	     pgdat;					\
	     pgdat = next_online_pgdat(pgdat))
#define for_each_populated_zone(zone)		        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))			\
		if (!populated_zone(zone))		\
			; 		\
		else
#define for_each_zone(zone)			        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))
#define for_each_zone_zonelist(zone, z, zlist, highidx) \
	for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, NULL)
#define for_each_zone_zonelist_nodemask(zone, z, zlist, highidx, nodemask) \
	for (z = first_zones_zonelist(zlist, highidx, nodemask), zone = zonelist_zone(z);	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))
#define for_next_zone_zonelist_nodemask(zone, z, highidx, nodemask) \
	for (zone = z->zone;	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))
#define get_pageblock_migratetype(page)					\
	get_pfnblock_flags_mask(page, page_to_pfn(page), MIGRATETYPE_MASK)
#define high_wmark_pages(z) (z->_watermark[WMARK_HIGH] + z->watermark_boost)
#  define is_migrate_cma(migratetype) unlikely((migratetype) == MIGRATE_CMA)
#  define is_migrate_cma_page(_page) (get_pageblock_migratetype(_page) == MIGRATE_CMA)
#define low_wmark_pages(z) (z->_watermark[WMARK_LOW] + z->watermark_boost)
#define min_wmark_pages(z) (z->_watermark[WMARK_MIN] + z->watermark_boost)
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))
#define node_end_pfn(nid) pgdat_end_pfn(NODE_DATA(nid))
#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#define node_start_pfn(nid)	(NODE_DATA(nid)->node_start_pfn)
#define pfn_in_present_section pfn_valid
#define pfn_to_nid(pfn)		(0)
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define sparse_init()	do {} while (0)
#define subsection_map_init(_pfn, _nr_pages) do {} while (0)
#define wmark_pages(z, i) (z->_watermark[i] + z->watermark_boost)
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)
#define MHP_MEMMAP_ON_MEMORY   ((__force mhp_t)BIT(1))

#define arch_alloc_nodedata(nid)	generic_alloc_nodedata(nid)
#define arch_free_nodedata(pgdat)	generic_free_nodedata(pgdat)
#define generic_alloc_nodedata(nid)				\
({								\
	kzalloc(sizeof(pg_data_t), GFP_KERNEL);			\
})
#define generic_free_nodedata(pgdat)	kfree(pgdat)
#define pfn_to_online_page(pfn)			\
({						\
	struct page *___page = NULL;		\
	if (pfn_valid(pfn))			\
		___page = pfn_to_page(pfn);	\
	___page;				\
 })

#define local_lock(lock)		__local_lock(lock)
#define local_lock_init(lock)		__local_lock_init(lock)
#define local_lock_irq(lock)		__local_lock_irq(lock)
#define local_lock_irqsave(lock, flags)				\
	__local_lock_irqsave(lock, flags)
#define local_unlock(lock)		__local_unlock(lock)
#define local_unlock_irq(lock)		__local_unlock_irq(lock)
#define local_unlock_irqrestore(lock, flags)			\
	__local_unlock_irqrestore(lock, flags)
#define INIT_LOCAL_LOCK(lockname) __LOCAL_SPIN_LOCK_UNLOCKED((lockname))
# define LOCAL_LOCK_DEBUG_INIT(lockname)		\
	.dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_CONFIG,	\
		.lock_type = LD_LOCK_PERCPU,		\
	},						\
	.owner = NULL,
#define __local_lock(__lock)					\
	do {							\
		migrate_disable();				\
		spin_lock(this_cpu_ptr((__lock)));		\
	} while (0)
#define __local_lock_init(l)					\
	do {							\
		local_spin_lock_init((l));			\
	} while (0)
#define __local_lock_irq(lock)			__local_lock(lock)
#define __local_lock_irqsave(lock, flags)			\
	do {							\
		typecheck(unsigned long, flags);		\
		flags = 0;					\
		__local_lock(lock);				\
	} while (0)
#define __local_unlock(__lock)					\
	do {							\
		spin_unlock(this_cpu_ptr((__lock)));		\
		migrate_enable();				\
	} while (0)
#define __local_unlock_irq(lock)		__local_unlock(lock)
#define __local_unlock_irqrestore(lock, flags)	__local_unlock(lock)
#define DECLARE_PER_CPU(type, name)					\
	DECLARE_PER_CPU_SECTION(type, name, "")
#define DECLARE_PER_CPU_ALIGNED(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_ALIGNED_SECTION)	\
	____cacheline_aligned
#define DECLARE_PER_CPU_DECRYPTED(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, "..decrypted")
#define DECLARE_PER_CPU_FIRST(type, name)				\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_FIRST_SECTION)
#define DECLARE_PER_CPU_PAGE_ALIGNED(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, "..page_aligned")		\
	__aligned(PAGE_SIZE)
#define DECLARE_PER_CPU_READ_MOSTLY(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, "..read_mostly")
#define DECLARE_PER_CPU_SECTION(type, name, sec)			\
	extern __PCPU_ATTRS(sec) __typeof__(type) name
#define DECLARE_PER_CPU_SHARED_ALIGNED(type, name)			\
	DECLARE_PER_CPU_SECTION(type, name, PER_CPU_SHARED_ALIGNED_SECTION) \
	____cacheline_aligned_in_smp
#define DEFINE_PER_CPU(type, name)					\
	DEFINE_PER_CPU_SECTION(type, name, "")
#define DEFINE_PER_CPU_ALIGNED(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_ALIGNED_SECTION)	\
	____cacheline_aligned
#define DEFINE_PER_CPU_DECRYPTED(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, "..decrypted")
#define DEFINE_PER_CPU_FIRST(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_FIRST_SECTION)
#define DEFINE_PER_CPU_PAGE_ALIGNED(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, "..page_aligned")		\
	__aligned(PAGE_SIZE)
#define DEFINE_PER_CPU_READ_MOSTLY(type, name)				\
	DEFINE_PER_CPU_SECTION(type, name, "..read_mostly")
#define DEFINE_PER_CPU_SECTION(type, name, sec)				\
	__PCPU_ATTRS(sec) __typeof__(type) name
#define DEFINE_PER_CPU_SHARED_ALIGNED(type, name)			\
	DEFINE_PER_CPU_SECTION(type, name, PER_CPU_SHARED_ALIGNED_SECTION) \
	____cacheline_aligned_in_smp
#define EXPORT_PER_CPU_SYMBOL(var) EXPORT_SYMBOL(var)
#define EXPORT_PER_CPU_SYMBOL_GPL(var) EXPORT_SYMBOL_GPL(var)
#define PER_CPU_ALIGNED_SECTION ""
#define PER_CPU_FIRST_SECTION "..first"
#define PER_CPU_SHARED_ALIGNED_SECTION ""
#define SHIFT_PERCPU_PTR(__p, __offset)					\
	RELOC_HIDE((typeof(*(__p)) __kernel __force *)(__p), (__offset))
#define VERIFY_PERCPU_PTR(__p)						\
({									\
	__verify_pcpu_ptr(__p);						\
	(typeof(*(__p)) __kernel __force *)(__p);			\
})

#define __PCPU_ATTRS(sec)						\
	__percpu __attribute__((section(PER_CPU_BASE_SECTION sec)))	\
	PER_CPU_ATTRIBUTES
#define __pcpu_double_call_return_bool(stem, pcp1, pcp2, ...)		\
({									\
	bool pdcrb_ret__;						\
	__verify_pcpu_ptr(&(pcp1));					\
	BUILD_BUG_ON(sizeof(pcp1) != sizeof(pcp2));			\
	VM_BUG_ON((unsigned long)(&(pcp1)) % (2 * sizeof(pcp1)));	\
	VM_BUG_ON((unsigned long)(&(pcp2)) !=				\
		  (unsigned long)(&(pcp1)) + sizeof(pcp1));		\
	switch(sizeof(pcp1)) {						\
	case 1: pdcrb_ret__ = stem##1(pcp1, pcp2, __VA_ARGS__); break;	\
	case 2: pdcrb_ret__ = stem##2(pcp1, pcp2, __VA_ARGS__); break;	\
	case 4: pdcrb_ret__ = stem##4(pcp1, pcp2, __VA_ARGS__); break;	\
	case 8: pdcrb_ret__ = stem##8(pcp1, pcp2, __VA_ARGS__); break;	\
	default:							\
		__bad_size_call_parameter(); break;			\
	}								\
	pdcrb_ret__;							\
})
#define __pcpu_size_call(stem, variable, ...)				\
do {									\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
		case 1: stem##1(variable, __VA_ARGS__);break;		\
		case 2: stem##2(variable, __VA_ARGS__);break;		\
		case 4: stem##4(variable, __VA_ARGS__);break;		\
		case 8: stem##8(variable, __VA_ARGS__);break;		\
		default: 						\
			__bad_size_call_parameter();break;		\
	}								\
} while (0)
#define __pcpu_size_call_return(stem, variable)				\
({									\
	typeof(variable) pscr_ret__;					\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
	case 1: pscr_ret__ = stem##1(variable); break;			\
	case 2: pscr_ret__ = stem##2(variable); break;			\
	case 4: pscr_ret__ = stem##4(variable); break;			\
	case 8: pscr_ret__ = stem##8(variable); break;			\
	default:							\
		__bad_size_call_parameter(); break;			\
	}								\
	pscr_ret__;							\
})
#define __pcpu_size_call_return2(stem, variable, ...)			\
({									\
	typeof(variable) pscr2_ret__;					\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
	case 1: pscr2_ret__ = stem##1(variable, __VA_ARGS__); break;	\
	case 2: pscr2_ret__ = stem##2(variable, __VA_ARGS__); break;	\
	case 4: pscr2_ret__ = stem##4(variable, __VA_ARGS__); break;	\
	case 8: pscr2_ret__ = stem##8(variable, __VA_ARGS__); break;	\
	default:							\
		__bad_size_call_parameter(); break;			\
	}								\
	pscr2_ret__;							\
})
#define __this_cpu_add(pcp, val)					\
({									\
	__this_cpu_preempt_check("add");				\
	raw_cpu_add(pcp, val);						\
})
#define __this_cpu_add_return(pcp, val)					\
({									\
	__this_cpu_preempt_check("add_return");				\
	raw_cpu_add_return(pcp, val);					\
})
#define __this_cpu_and(pcp, val)					\
({									\
	__this_cpu_preempt_check("and");				\
	raw_cpu_and(pcp, val);						\
})
#define __this_cpu_cmpxchg(pcp, oval, nval)				\
({									\
	__this_cpu_preempt_check("cmpxchg");				\
	raw_cpu_cmpxchg(pcp, oval, nval);				\
})
#define __this_cpu_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2) \
({	__this_cpu_preempt_check("cmpxchg_double");			\
	raw_cpu_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2);	\
})
#define __this_cpu_dec(pcp)		__this_cpu_sub(pcp, 1)
#define __this_cpu_dec_return(pcp)	__this_cpu_add_return(pcp, -1)
#define __this_cpu_inc(pcp)		__this_cpu_add(pcp, 1)
#define __this_cpu_inc_return(pcp)	__this_cpu_add_return(pcp, 1)
#define __this_cpu_or(pcp, val)						\
({									\
	__this_cpu_preempt_check("or");					\
	raw_cpu_or(pcp, val);						\
})
#define __this_cpu_read(pcp)						\
({									\
	__this_cpu_preempt_check("read");				\
	raw_cpu_read(pcp);						\
})
#define __this_cpu_sub(pcp, val)	__this_cpu_add(pcp, -(typeof(pcp))(val))
#define __this_cpu_sub_return(pcp, val)	__this_cpu_add_return(pcp, -(typeof(pcp))(val))
#define __this_cpu_write(pcp, val)					\
({									\
	__this_cpu_preempt_check("write");				\
	raw_cpu_write(pcp, val);					\
})
#define __this_cpu_xchg(pcp, nval)					\
({									\
	__this_cpu_preempt_check("xchg");				\
	raw_cpu_xchg(pcp, nval);					\
})
#define __verify_pcpu_ptr(ptr)						\
do {									\
	const void __percpu *__vpp_verify = (typeof((ptr) + 0))NULL;	\
	(void)__vpp_verify;						\
} while (0)
#define get_cpu_ptr(var)						\
({									\
	preempt_disable();						\
	this_cpu_ptr(var);						\
})
#define get_cpu_var(var)						\
(*({									\
	preempt_disable();						\
	this_cpu_ptr(&var);						\
}))
#define per_cpu(var, cpu)	(*per_cpu_ptr(&(var), cpu))
#define per_cpu_ptr(ptr, cpu)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	SHIFT_PERCPU_PTR((ptr), per_cpu_offset((cpu)));			\
})
#define put_cpu_ptr(var)						\
do {									\
	(void)(var);							\
	preempt_enable();						\
} while (0)
#define put_cpu_var(var)						\
do {									\
	(void)&(var);							\
	preempt_enable();						\
} while (0)
#define raw_cpu_add(pcp, val)		__pcpu_size_call(raw_cpu_add_, pcp, val)
#define raw_cpu_add_return(pcp, val)	__pcpu_size_call_return2(raw_cpu_add_return_, pcp, val)
#define raw_cpu_and(pcp, val)		__pcpu_size_call(raw_cpu_and_, pcp, val)
#define raw_cpu_cmpxchg(pcp, oval, nval) \
	__pcpu_size_call_return2(raw_cpu_cmpxchg_, pcp, oval, nval)
#define raw_cpu_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	__pcpu_double_call_return_bool(raw_cpu_cmpxchg_double_, pcp1, pcp2, oval1, oval2, nval1, nval2)
#define raw_cpu_dec(pcp)		raw_cpu_sub(pcp, 1)
#define raw_cpu_dec_return(pcp)		raw_cpu_add_return(pcp, -1)
#define raw_cpu_inc(pcp)		raw_cpu_add(pcp, 1)
#define raw_cpu_inc_return(pcp)		raw_cpu_add_return(pcp, 1)
#define raw_cpu_or(pcp, val)		__pcpu_size_call(raw_cpu_or_, pcp, val)
#define raw_cpu_ptr(ptr)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	arch_raw_cpu_ptr(ptr);						\
})
#define raw_cpu_read(pcp)		__pcpu_size_call_return(raw_cpu_read_, pcp)
#define raw_cpu_sub(pcp, val)		raw_cpu_add(pcp, -(val))
#define raw_cpu_sub_return(pcp, val)	raw_cpu_add_return(pcp, -(typeof(pcp))(val))
#define raw_cpu_write(pcp, val)		__pcpu_size_call(raw_cpu_write_, pcp, val)
#define raw_cpu_xchg(pcp, nval)		__pcpu_size_call_return2(raw_cpu_xchg_, pcp, nval)
#define this_cpu_add(pcp, val)		__pcpu_size_call(this_cpu_add_, pcp, val)
#define this_cpu_add_return(pcp, val)	__pcpu_size_call_return2(this_cpu_add_return_, pcp, val)
#define this_cpu_and(pcp, val)		__pcpu_size_call(this_cpu_and_, pcp, val)
#define this_cpu_cmpxchg(pcp, oval, nval) \
	__pcpu_size_call_return2(this_cpu_cmpxchg_, pcp, oval, nval)
#define this_cpu_cmpxchg_double(pcp1, pcp2, oval1, oval2, nval1, nval2) \
	__pcpu_double_call_return_bool(this_cpu_cmpxchg_double_, pcp1, pcp2, oval1, oval2, nval1, nval2)
#define this_cpu_dec(pcp)		this_cpu_sub(pcp, 1)
#define this_cpu_dec_return(pcp)	this_cpu_add_return(pcp, -1)
#define this_cpu_inc(pcp)		this_cpu_add(pcp, 1)
#define this_cpu_inc_return(pcp)	this_cpu_add_return(pcp, 1)
#define this_cpu_or(pcp, val)		__pcpu_size_call(this_cpu_or_, pcp, val)
#define this_cpu_ptr(ptr)						\
({									\
	__verify_pcpu_ptr(ptr);						\
	SHIFT_PERCPU_PTR(ptr, my_cpu_offset);				\
})
#define this_cpu_read(pcp)		__pcpu_size_call_return(this_cpu_read_, pcp)
#define this_cpu_sub(pcp, val)		this_cpu_add(pcp, -(typeof(pcp))(val))
#define this_cpu_sub_return(pcp, val)	this_cpu_add_return(pcp, -(typeof(pcp))(val))
#define this_cpu_write(pcp, val)	__pcpu_size_call(this_cpu_write_, pcp, val)
#define this_cpu_xchg(pcp, nval)	__pcpu_size_call_return2(this_cpu_xchg_, pcp, nval)
#define CLEARPAGEFLAG(uname, lname, policy)				\
static __always_inline void ClearPage##uname(struct page *page)		\
	{ clear_bit(PG_##lname, &policy(page, 1)->flags); }
#define CLEARPAGEFLAG_NOOP(uname)					\
static inline void ClearPage##uname(struct page *page) {  }
#define PAGEFLAG(uname, lname, policy)					\
	TESTPAGEFLAG(uname, lname, policy)				\
	SETPAGEFLAG(uname, lname, policy)				\
	CLEARPAGEFLAG(uname, lname, policy)
#define PAGEFLAG_FALSE(uname) TESTPAGEFLAG_FALSE(uname)			\
	SETPAGEFLAG_NOOP(uname) CLEARPAGEFLAG_NOOP(uname)

#define PAGE_TYPE_OPS(uname, lname)					\
static __always_inline int Page##uname(struct page *page)		\
{									\
	return PageType(page, PG_##lname);				\
}									\
static __always_inline void __SetPage##uname(struct page *page)		\
{									\
	VM_BUG_ON_PAGE(!PageType(page, 0), page);			\
	page->page_type &= ~PG_##lname;					\
}									\
static __always_inline void __ClearPage##uname(struct page *page)	\
{									\
	VM_BUG_ON_PAGE(!Page##uname(page), page);			\
	page->page_type |= PG_##lname;					\
}
#define PF_ANY(page, enforce)	PF_POISONED_CHECK(page)
#define PF_HEAD(page, enforce)	PF_POISONED_CHECK(compound_head(page))
#define PF_NO_COMPOUND(page, enforce) ({				\
		VM_BUG_ON_PGFLAGS(enforce && PageCompound(page), page);	\
		PF_POISONED_CHECK(page); })
#define PF_NO_TAIL(page, enforce) ({					\
		VM_BUG_ON_PGFLAGS(enforce && PageTail(page), page);	\
		PF_POISONED_CHECK(compound_head(page)); })
#define PF_ONLY_HEAD(page, enforce) ({					\
		VM_BUG_ON_PGFLAGS(PageTail(page), page);		\
		PF_POISONED_CHECK(page); })
#define PF_POISONED_CHECK(page) ({					\
		VM_BUG_ON_PGFLAGS(PagePoisoned(page), page);		\
		page; })
#define PF_SECOND(page, enforce) ({					\
		VM_BUG_ON_PGFLAGS(!PageHead(page), page);		\
		PF_POISONED_CHECK(&page[1]); })
#define PG_head_mask ((1UL << PG_head))
#define PageHighMem(__p) is_highmem_idx(page_zonenum(__p))
#define PageType(page, flag)						\
	((page->page_type & (PAGE_TYPE_BASE | flag)) == PAGE_TYPE_BASE)
#define SETPAGEFLAG(uname, lname, policy)				\
static __always_inline void SetPage##uname(struct page *page)		\
	{ set_bit(PG_##lname, &policy(page, 1)->flags); }
#define SETPAGEFLAG_NOOP(uname)						\
static inline void SetPage##uname(struct page *page) {  }
#define TESTCLEARFLAG(uname, lname, policy)				\
static __always_inline int TestClearPage##uname(struct page *page)	\
	{ return test_and_clear_bit(PG_##lname, &policy(page, 1)->flags); }
#define TESTCLEARFLAG_FALSE(uname)					\
static inline int TestClearPage##uname(struct page *page) { return 0; }
#define TESTPAGEFLAG(uname, lname, policy)				\
static __always_inline int Page##uname(struct page *page)		\
	{ return test_bit(PG_##lname, &policy(page, 0)->flags); }
#define TESTPAGEFLAG_FALSE(uname)					\
static inline int Page##uname(const struct page *page) { return 0; }
#define TESTSCFLAG(uname, lname, policy)				\
	TESTSETFLAG(uname, lname, policy)				\
	TESTCLEARFLAG(uname, lname, policy)
#define TESTSCFLAG_FALSE(uname)						\
	TESTSETFLAG_FALSE(uname) TESTCLEARFLAG_FALSE(uname)
#define TESTSETFLAG(uname, lname, policy)				\
static __always_inline int TestSetPage##uname(struct page *page)	\
	{ return test_and_set_bit(PG_##lname, &policy(page, 1)->flags); }
#define TESTSETFLAG_FALSE(uname)					\
static inline int TestSetPage##uname(struct page *page) { return 0; }
#define __CLEARPAGEFLAG(uname, lname, policy)				\
static __always_inline void __ClearPage##uname(struct page *page)	\
	{ __clear_bit(PG_##lname, &policy(page, 1)->flags); }
#define __CLEARPAGEFLAG_NOOP(uname)					\
static inline void __ClearPage##uname(struct page *page) {  }
#define __PAGEFLAG(uname, lname, policy)				\
	TESTPAGEFLAG(uname, lname, policy)				\
	__SETPAGEFLAG(uname, lname, policy)				\
	__CLEARPAGEFLAG(uname, lname, policy)
#define __PG_HWPOISON (1UL << PG_hwpoison)
#define __SETPAGEFLAG(uname, lname, policy)				\
static __always_inline void __SetPage##uname(struct page *page)		\
	{ __set_bit(PG_##lname, &policy(page, 1)->flags); }
#define compound_head(page)	((typeof(page))_compound_head(page))
#define test_set_page_writeback(page)			\
	__test_set_page_writeback(page, false)
#define test_set_page_writeback_keepwrite(page)	\
	__test_set_page_writeback(page, true)
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))
#define AT_VECTOR_SIZE_ARCH 0
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) { NULL, })
#define VM_FAULT_ERROR (VM_FAULT_OOM | VM_FAULT_SIGBUS |	\
			VM_FAULT_SIGSEGV | VM_FAULT_HWPOISON |	\
			VM_FAULT_HWPOISON_LARGE | VM_FAULT_FALLBACK)
#define VM_FAULT_GET_HINDEX(x) (((__force unsigned int)(x) >> 16) & 0xf)
#define VM_FAULT_RESULT_TRACE \
	{ VM_FAULT_OOM,                 "OOM" },	\
	{ VM_FAULT_SIGBUS,              "SIGBUS" },	\
	{ VM_FAULT_MAJOR,               "MAJOR" },	\
	{ VM_FAULT_WRITE,               "WRITE" },	\
	{ VM_FAULT_HWPOISON,            "HWPOISON" },	\
	{ VM_FAULT_HWPOISON_LARGE,      "HWPOISON_LARGE" },	\
	{ VM_FAULT_SIGSEGV,             "SIGSEGV" },	\
	{ VM_FAULT_NOPAGE,              "NOPAGE" },	\
	{ VM_FAULT_LOCKED,              "LOCKED" },	\
	{ VM_FAULT_RETRY,               "RETRY" },	\
	{ VM_FAULT_FALLBACK,            "FALLBACK" },	\
	{ VM_FAULT_DONE_COW,            "DONE_COW" },	\
	{ VM_FAULT_NEEDDSYNC,           "NEEDDSYNC" }
#define VM_FAULT_SET_HINDEX(x) ((__force vm_fault_t)((x) << 16))


#define page_private(page)		((page)->private)
#define DEFINE_SEQLOCK(sl) \
		seqlock_t sl = __SEQLOCK_UNLOCKED(sl)
#define KCSAN_SEQLOCK_REGION_MAX 1000
#define SEQCNT_LATCH_ZERO(seq_name) {					\
	.seqcount		= SEQCNT_ZERO(seq_name.seqcount),	\
}
#define SEQCNT_MUTEX_ZERO(name, lock)		SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_RAW_SPINLOCK_ZERO(name, lock)	SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_RWLOCK_ZERO(name, lock)		SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_SPINLOCK_ZERO(name, lock)	SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_WW_MUTEX_ZERO(name, lock) 	SEQCOUNT_LOCKNAME_ZERO(name, lock)
#define SEQCNT_ZERO(name) { .sequence = 0, SEQCOUNT_DEP_MAP_INIT(name) }
# define SEQCOUNT_DEP_MAP_INIT(lockname)
#define SEQCOUNT_LOCKNAME(lockname, locktype, preemptible, lockmember, lockbase, lock_acquire) \
typedef struct seqcount_##lockname {					\
	seqcount_t		seqcount;				\
	__SEQ_LOCK(locktype	*lock);					\
} seqcount_##lockname##_t;						\
									\
static __always_inline seqcount_t *					\
__seqprop_##lockname##_ptr(seqcount_##lockname##_t *s)			\
{									\
	return &s->seqcount;						\
}									\
									\
static __always_inline unsigned						\
__seqprop_##lockname##_sequence(const seqcount_##lockname##_t *s)	\
{									\
	unsigned seq = READ_ONCE(s->seqcount.sequence);			\
									\
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))				\
		return seq;						\
									\
	if (preemptible && unlikely(seq & 1)) {				\
		__SEQ_LOCK(lock_acquire);				\
		__SEQ_LOCK(lockbase##_unlock(s->lock));			\
									\
									\
		seq = READ_ONCE(s->seqcount.sequence);			\
	}								\
									\
	return seq;							\
}									\
									\
static __always_inline bool						\
__seqprop_##lockname##_preemptible(const seqcount_##lockname##_t *s)	\
{									\
	if (!IS_ENABLED(CONFIG_PREEMPT_RT))				\
		return preemptible;					\
									\
			\
	return false;							\
}									\
									\
static __always_inline void						\
__seqprop_##lockname##_assert(const seqcount_##lockname##_t *s)		\
{									\
	__SEQ_LOCK(lockdep_assert_held(lockmember));			\
}
#define SEQCOUNT_LOCKNAME_ZERO(seq_name, assoc_lock) {			\
	.seqcount		= SEQCNT_ZERO(seq_name.seqcount),	\
	__SEQ_LOCK(.lock	= (assoc_lock))				\
}

#define __SEQLOCK_UNLOCKED(lockname)					\
	{								\
		.seqcount = SEQCNT_SPINLOCK_ZERO(lockname, &(lockname).lock), \
		.lock =	__SPIN_LOCK_UNLOCKED(lockname)			\
	}
#define __SEQ_LOCK(expr)	expr
#define __read_seqcount_begin(s)					\
({									\
	unsigned __seq;							\
									\
	while ((__seq = seqprop_sequence(s)) & 1)			\
		cpu_relax();						\
									\
	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);			\
	__seq;								\
})
#define __read_seqcount_retry(s, start)					\
	do___read_seqcount_retry(seqprop_ptr(s), start)
#define __seqprop(s, prop) _Generic(*(s),				\
	seqcount_t:		__seqprop_##prop((void *)(s)),		\
	__seqprop_case((s),	raw_spinlock,	prop),			\
	__seqprop_case((s),	spinlock,	prop),			\
	__seqprop_case((s),	rwlock,		prop),			\
	__seqprop_case((s),	mutex,		prop),			\
	__seqprop_case((s),	ww_mutex,	prop))
#define __seqprop_case(s, lockname, prop)				\
	seqcount_##lockname##_t: __seqprop_##lockname##_##prop((void *)(s))
#define raw_read_seqcount(s)						\
({									\
	unsigned __seq = seqprop_sequence(s);				\
									\
	smp_rmb();							\
	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);			\
	__seq;								\
})
#define raw_read_seqcount_begin(s)					\
({									\
	unsigned _seq = __read_seqcount_begin(s);			\
									\
	smp_rmb();							\
	_seq;								\
})
#define raw_seqcount_begin(s)						\
({									\
									\
	raw_read_seqcount(s) & ~1;					\
})
#define raw_write_seqcount_barrier(s)					\
	do_raw_write_seqcount_barrier(seqprop_ptr(s))
#define raw_write_seqcount_begin(s)					\
do {									\
	if (seqprop_preemptible(s))					\
		preempt_disable();					\
									\
	do_raw_write_seqcount_begin(seqprop_ptr(s));			\
} while (0)
#define raw_write_seqcount_end(s)					\
do {									\
	do_raw_write_seqcount_end(seqprop_ptr(s));			\
									\
	if (seqprop_preemptible(s))					\
		preempt_enable();					\
} while (0)
#define read_seqcount_begin(s)						\
({									\
	seqcount_lockdep_reader_access(seqprop_ptr(s));			\
	raw_read_seqcount_begin(s);					\
})
#define read_seqcount_retry(s, start)					\
	do_read_seqcount_retry(seqprop_ptr(s), start)
#define read_seqlock_excl_irqsave(lock, flags)				\
	do { flags = __read_seqlock_excl_irqsave(lock); } while (0)
#define seqcount_LOCKNAME_init(s, _lock, lockname)			\
	do {								\
		seqcount_##lockname##_t *____s = (s);			\
		seqcount_init(&____s->seqcount);			\
		__SEQ_LOCK(____s->lock = (_lock));			\
	} while (0)
# define seqcount_init(s) __seqcount_init(s, NULL, NULL)
#define seqcount_latch_init(s) seqcount_init(&(s)->seqcount)
# define seqcount_lockdep_reader_access(x)
#define seqcount_mutex_init(s, lock)		seqcount_LOCKNAME_init(s, lock, mutex)
#define seqcount_raw_spinlock_init(s, lock)	seqcount_LOCKNAME_init(s, lock, raw_spinlock)
#define seqcount_rwlock_init(s, lock)		seqcount_LOCKNAME_init(s, lock, rwlock)
#define seqcount_spinlock_init(s, lock)		seqcount_LOCKNAME_init(s, lock, spinlock)
#define seqcount_ww_mutex_init(s, lock)		seqcount_LOCKNAME_init(s, lock, ww_mutex)
#define seqlock_init(sl)						\
	do {								\
		spin_lock_init(&(sl)->lock);				\
		seqcount_spinlock_init(&(sl)->seqcount, &(sl)->lock);	\
	} while (0)
#define seqprop_assert(s)		__seqprop(s, assert)
#define seqprop_preemptible(s)		__seqprop(s, preemptible)
#define seqprop_ptr(s)			__seqprop(s, ptr)
#define seqprop_sequence(s)		__seqprop(s, sequence)
#define write_seqcount_begin(s)						\
do {									\
	seqprop_assert(s);						\
									\
	if (seqprop_preemptible(s))					\
		preempt_disable();					\
									\
	do_write_seqcount_begin(seqprop_ptr(s));			\
} while (0)
#define write_seqcount_begin_nested(s, subclass)			\
do {									\
	seqprop_assert(s);						\
									\
	if (seqprop_preemptible(s))					\
		preempt_disable();					\
									\
	do_write_seqcount_begin_nested(seqprop_ptr(s), subclass);	\
} while (0)
#define write_seqcount_end(s)						\
do {									\
	do_write_seqcount_end(seqprop_ptr(s));				\
									\
	if (seqprop_preemptible(s))					\
		preempt_enable();					\
} while (0)
#define write_seqcount_invalidate(s)					\
	do_write_seqcount_invalidate(seqprop_ptr(s))
#define write_seqlock_irqsave(lock, flags)				\
	do { flags = __write_seqlock_irqsave(lock); } while (0)

#define DEFINE_WD_CLASS(classname) \
	struct ww_class classname = __WW_CLASS_INITIALIZER(classname, 1)
#define DEFINE_WW_CLASS(classname) \
	struct ww_class classname = __WW_CLASS_INITIALIZER(classname, 0)

#define __WW_CLASS_INITIALIZER(ww_class, _is_wait_die)	    \
		{ .stamp = ATOMIC_LONG_INIT(0) \
		, .acquire_name = #ww_class "_acquire" \
		, .mutex_name = #ww_class "_mutex" \
		, .is_wait_die = _is_wait_die }
#define ww_mutex_base_init(l,n,k)	__mutex_init(l,n,k)
#define ww_mutex_base_is_locked(b)	mutex_is_locked((b))
#define ww_mutex_base_trylock(l)	mutex_trylock(l)
#define KASAN_TAG_WIDTH 8

#define LAST_CPUPID_SHIFT (LAST__PID_SHIFT+LAST__CPU_SHIFT)
#define LAST_CPUPID_WIDTH LAST_CPUPID_SHIFT
#define LAST__CPU_MASK  ((1 << LAST__CPU_SHIFT)-1)
#define LAST__CPU_SHIFT NR_CPUS_BITS
#define LAST__PID_MASK  ((1 << LAST__PID_SHIFT)-1)
#define LAST__PID_SHIFT 8

#define ZONES_SHIFT 0
#define MAX_NUMNODES    (1 << NODES_SHIFT)
#define NODES_SHIFT     CONFIG_NODES_SHIFT

#define __initdata_or_meminfo __initdata

#define uprobe_get_trap_addr(regs)	instruction_pointer(regs)
#define RB_CLEAR_NODE(node)  \
	((node)->__rb_parent_color = (unsigned long)(node))
#define RB_EMPTY_NODE(node)  \
	((node)->__rb_parent_color == (unsigned long)(node))
#define RB_EMPTY_ROOT(root)  (READ_ONCE((root)->rb_node) == NULL)
#define rb_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry(____ptr, type, member) : NULL; \
	})
#define rb_first_cached(root) (root)->rb_leftmost
#define rb_for_each(node, key, tree, cmp) \
	for ((node) = rb_find_first((key), (tree), (cmp)); \
	     (node); (node) = rb_next_match((key), (node), (cmp)))
#define rb_parent(r)   ((struct rb_node *)((r)->__rb_parent_color & ~3))
#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
	for (pos = rb_entry_safe(rb_first_postorder(root), typeof(*pos), field); \
	     pos && ({ n = rb_entry_safe(rb_next_postorder(&pos->field), \
			typeof(*pos), field); 1; }); \
	     pos = n)
#define AT_VECTOR_SIZE_BASE 20 

#define AT_BASE   7	
#define AT_BASE_PLATFORM 24	
#define AT_CLKTCK 17	
#define AT_EGID   14	
#define AT_ENTRY  9	
#define AT_EUID   12	
#define AT_EXECFD 2	
#define AT_EXECFN  31	
#define AT_FLAGS  8	
#define AT_GID    13	
#define AT_HWCAP  16    
#define AT_HWCAP2 26	
#define AT_IGNORE 1	
#define AT_NOTELF 10	
#define AT_NULL   0	
#define AT_PAGESZ 6	
#define AT_PHDR   3	
#define AT_PHENT  4	
#define AT_PHNUM  5	
#define AT_PLATFORM 15  
#define AT_RANDOM 25	
#define AT_SECURE 23   
#define AT_UID    11	


#define VMACACHE_BITS 2
#define VMACACHE_MASK (VMACACHE_SIZE - 1)
#define VMACACHE_SIZE (1U << VMACACHE_BITS)


#define PB_migratetype_bits 3
#define clear_pageblock_skip(page) \
	set_pfnblock_flags_mask(page, 0, page_to_pfn(page),	\
			(1 << PB_migrate_skip))
#define get_pageblock_skip(page) \
	get_pfnblock_flags_mask(page, page_to_pfn(page),	\
			(1 << (PB_migrate_skip)))
#define set_pageblock_skip(page) \
	set_pfnblock_flags_mask(page, (1 << PB_migrate_skip),	\
			page_to_pfn(page),			\
			(1 << PB_migrate_skip))
#define NODEMASK_ALLOC(type, name, gfp_flags)	\
			type *name = kmalloc(sizeof(*name), gfp_flags)
#define NODEMASK_FREE(m)			kfree(m)
#define NODEMASK_SCRATCH(x)						\
			NODEMASK_ALLOC(struct nodemask_scratch, x,	\
					GFP_KERNEL | __GFP_NORETRY)
#define NODEMASK_SCRATCH_FREE(x)	NODEMASK_FREE(x)
#define NODE_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(MAX_NUMNODES)

#define first_node(src) __first_node(&(src))
#define first_unset_node(mask) __first_unset_node(&(mask))
#define for_each_node(node)	   for_each_node_state(node, N_POSSIBLE)
#define for_each_node_mask(node, mask)			\
	for ((node) = first_node(mask);			\
		(node) < MAX_NUMNODES;			\
		(node) = next_node((node), (mask)))
#define for_each_node_state(__node, __state) \
	for_each_node_mask((__node), node_states[__state])
#define for_each_online_node(node) for_each_node_state(node, N_ONLINE)
#define next_node(n, src) __next_node((n), &(src))
#define next_node_in(n, src) __next_node_in((n), &(src))
#define next_online_node(nid)	(MAX_NUMNODES)
#define node_clear(node, dst) __node_clear((node), &(dst))
#define node_isset(node, nodemask) test_bit((node), (nodemask).bits)
#define node_online(node)	node_state((node), N_ONLINE)
#define node_online_map 	node_states[N_ONLINE]
#define node_possible(node)	node_state((node), N_POSSIBLE)
#define node_possible_map 	node_states[N_POSSIBLE]
#define node_remap(oldbit, old, new) \
		__node_remap((oldbit), &(old), &(new), MAX_NUMNODES)
#define node_set(node, dst) __node_set((node), &(dst))
#define node_set_offline(node)	   node_clear_state((node), N_ONLINE)
#define node_set_online(node)	   node_set_state((node), N_ONLINE)
#define node_test_and_set(node, nodemask) \
			__node_test_and_set((node), &(nodemask))
#define nodelist_parse(buf, dst) __nodelist_parse((buf), &(dst), MAX_NUMNODES)
#define nodemask_of_node(node)						\
({									\
	typeof(_unused_nodemask_arg_) m;				\
	if (sizeof(m) == sizeof(unsigned long)) {			\
		m.bits[0] = 1UL << (node);				\
	} else {							\
		init_nodemask_of_node(&m, (node));			\
	}								\
	m;								\
})
#define nodemask_parse_user(ubuf, ulen, dst) \
		__nodemask_parse_user((ubuf), (ulen), &(dst), MAX_NUMNODES)
#define nodemask_pr_args(maskp)	__nodemask_pr_numnodes(maskp), \
				__nodemask_pr_bits(maskp)
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
#define nodes_fold(dst, orig, sz) \
		__nodes_fold(&(dst), &(orig), sz, MAX_NUMNODES)
#define nodes_full(nodemask) __nodes_full(&(nodemask), MAX_NUMNODES)
#define nodes_intersects(src1, src2) \
			__nodes_intersects(&(src1), &(src2), MAX_NUMNODES)
#define nodes_onto(dst, orig, relmap) \
		__nodes_onto(&(dst), &(orig), &(relmap), MAX_NUMNODES)
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
#define num_online_nodes()	num_node_state(N_ONLINE)
#define num_possible_nodes()	num_node_state(N_POSSIBLE)

#define topology_llc_cpumask(cpu)	(&cpu_topology[cpu].llc_sibling)

#define GLOBAL_ROOT_GID KGIDT_INIT(0)
#define GLOBAL_ROOT_UID KUIDT_INIT(0)
#define INVALID_GID KGIDT_INIT(-1)
#define INVALID_UID KUIDT_INIT(-1)
#define KGIDT_INIT(value) (kgid_t){ value }
#define KUIDT_INIT(value) (kuid_t){ value }

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

#define KREF_INIT(n)	{ .refcount = REFCOUNT_INIT(n), }

#define REFCOUNT_INIT(n)	{ .refs = ATOMIC_INIT(n), }

#define ATTRIBUTE_GROUPS(_name)					\
static const struct attribute_group _name##_group = {		\
	.attrs = _name##_attrs,					\
};								\
__ATTRIBUTE_GROUPS(_name)
#define BIN_ATTR(_name, _mode, _read, _write, _size)			\
struct bin_attribute bin_attr_##_name = __BIN_ATTR(_name, _mode, _read,	\
					_write, _size)
#define BIN_ATTRIBUTE_GROUPS(_name)				\
static const struct attribute_group _name##_group = {		\
	.bin_attrs = _name##_attrs,				\
};								\
__ATTRIBUTE_GROUPS(_name)
#define BIN_ATTR_RO(_name, _size)					\
struct bin_attribute bin_attr_##_name = __BIN_ATTR_RO(_name, _size)
#define BIN_ATTR_RW(_name, _size)					\
struct bin_attribute bin_attr_##_name = __BIN_ATTR_RW(_name, _size)
#define BIN_ATTR_WO(_name, _size)					\
struct bin_attribute bin_attr_##_name = __BIN_ATTR_WO(_name, _size)
#define SYSFS_PREALLOC 010000

#define __ATTR(_name, _mode, _show, _store) {				\
	.attr = {.name = __stringify(_name),				\
		 .mode = VERIFY_OCTAL_PERMISSIONS(_mode) },		\
	.show	= _show,						\
	.store	= _store,						\
}
#define __ATTRIBUTE_GROUPS(_name)				\
static const struct attribute_group *_name##_groups[] = {	\
	&_name##_group,						\
	NULL,							\
}
#define __ATTR_IGNORE_LOCKDEP(_name, _mode, _show, _store) {	\
	.attr = {.name = __stringify(_name), .mode = _mode,	\
			.ignore_lockdep = true },		\
	.show		= _show,				\
	.store		= _store,				\
}
#define __ATTR_NULL { .attr = { .name = NULL } }
#define __ATTR_PREALLOC(_name, _mode, _show, _store) {			\
	.attr = {.name = __stringify(_name),				\
		 .mode = SYSFS_PREALLOC | VERIFY_OCTAL_PERMISSIONS(_mode) },\
	.show	= _show,						\
	.store	= _store,						\
}
#define __ATTR_RO(_name) {						\
	.attr	= { .name = __stringify(_name), .mode = 0444 },		\
	.show	= _name##_show,						\
}
#define __ATTR_RO_MODE(_name, _mode) {					\
	.attr	= { .name = __stringify(_name),				\
		    .mode = VERIFY_OCTAL_PERMISSIONS(_mode) },		\
	.show	= _name##_show,						\
}
#define __ATTR_RW(_name) __ATTR(_name, 0644, _name##_show, _name##_store)
#define __ATTR_RW_MODE(_name, _mode) {					\
	.attr	= { .name = __stringify(_name),				\
		    .mode = VERIFY_OCTAL_PERMISSIONS(_mode) },		\
	.show	= _name##_show,						\
	.store	= _name##_store,					\
}
#define __ATTR_WO(_name) {						\
	.attr	= { .name = __stringify(_name), .mode = 0200 },		\
	.store	= _name##_store,					\
}
#define __BIN_ATTR(_name, _mode, _read, _write, _size) {		\
	.attr = { .name = __stringify(_name), .mode = _mode },		\
	.read	= _read,						\
	.write	= _write,						\
	.size	= _size,						\
}
#define __BIN_ATTR_NULL __ATTR_NULL
#define __BIN_ATTR_RO(_name, _size) {					\
	.attr	= { .name = __stringify(_name), .mode = 0444 },		\
	.read	= _name##_read,						\
	.size	= _size,						\
}
#define __BIN_ATTR_RW(_name, _size)					\
	__BIN_ATTR(_name, 0644, _name##_read, _name##_write, _size)
#define __BIN_ATTR_WO(_name, _size) {					\
	.attr	= { .name = __stringify(_name), .mode = 0200 },		\
	.write	= _name##_write,					\
	.size	= _size,						\
}
#define sysfs_attr_init(attr)				\
do {							\
	static struct lock_class_key __key;		\
							\
	(attr)->key = &__key;				\
} while (0)
#define sysfs_bin_attr_init(bin_attr) sysfs_attr_init(&(bin_attr)->attr)

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


#define DEFINE_IDA(name)	struct ida name = IDA_INIT(name)
#define DEFINE_IDR(name)	struct idr name = IDR_INIT(name)
#define IDA_BITMAP_BITS 	(IDA_BITMAP_LONGS * sizeof(long) * 8)
#define IDA_INIT(name)	{						\
	.xa = XARRAY_INIT(name, IDA_INIT_FLAGS)				\
}
#define IDR_INIT(name)	IDR_INIT_BASE(name, 0)
#define IDR_INIT_BASE(name, base) {					\
	.idr_rt = RADIX_TREE_INIT(name, IDR_RT_MARKER),			\
	.idr_base = (base),						\
	.idr_next = 0,							\
}

#define ida_simple_get(ida, start, end, gfp)	\
			ida_alloc_range(ida, start, (end) - 1, gfp)
#define ida_simple_remove(ida, id)	ida_free(ida, id)
#define idr_for_each_entry(idr, entry, id)			\
	for (id = 0; ((entry) = idr_get_next(idr, &(id))) != NULL; id += 1U)
#define idr_for_each_entry_continue(idr, entry, id)			\
	for ((entry) = idr_get_next((idr), &(id));			\
	     entry;							\
	     ++id, (entry) = idr_get_next((idr), &(id)))
#define idr_for_each_entry_continue_ul(idr, entry, tmp, id)		\
	for (tmp = id;							\
	     tmp <= id && ((entry) = idr_get_next_ul(idr, &(id))) != NULL; \
	     tmp = id, ++id)
#define idr_for_each_entry_ul(idr, entry, tmp, id)			\
	for (tmp = 0, id = 0;						\
	     tmp <= id && ((entry) = idr_get_next_ul(idr, &(id))) != NULL; \
	     tmp = id, ++id)
#define idr_lock(idr)		xa_lock(&(idr)->idr_rt)
#define idr_lock_bh(idr)	xa_lock_bh(&(idr)->idr_rt)
#define idr_lock_irq(idr)	xa_lock_irq(&(idr)->idr_rt)
#define idr_lock_irqsave(idr, flags) \
				xa_lock_irqsave(&(idr)->idr_rt, flags)
#define idr_unlock(idr)		xa_unlock(&(idr)->idr_rt)
#define idr_unlock_bh(idr)	xa_unlock_bh(&(idr)->idr_rt)
#define idr_unlock_irq(idr)	xa_unlock_irq(&(idr)->idr_rt)
#define idr_unlock_irqrestore(idr, flags) \
				xa_unlock_irqrestore(&(idr)->idr_rt, flags)
#define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)
#define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)
#define GFP_MOVABLE_SHIFT 3
#define GFP_ZONES_SHIFT 2
#define GFP_ZONE_BAD ( \
	1 << (___GFP_DMA | ___GFP_HIGHMEM)				      \
	| 1 << (___GFP_DMA | ___GFP_DMA32)				      \
	| 1 << (___GFP_DMA32 | ___GFP_HIGHMEM)				      \
	| 1 << (___GFP_DMA | ___GFP_DMA32 | ___GFP_HIGHMEM)		      \
	| 1 << (___GFP_MOVABLE | ___GFP_HIGHMEM | ___GFP_DMA)		      \
	| 1 << (___GFP_MOVABLE | ___GFP_DMA32 | ___GFP_DMA)		      \
	| 1 << (___GFP_MOVABLE | ___GFP_DMA32 | ___GFP_HIGHMEM)		      \
	| 1 << (___GFP_MOVABLE | ___GFP_DMA32 | ___GFP_DMA | ___GFP_HIGHMEM)  \
)
#define GFP_ZONE_TABLE ( \
	(ZONE_NORMAL << 0 * GFP_ZONES_SHIFT)				       \
	| (OPT_ZONE_DMA << ___GFP_DMA * GFP_ZONES_SHIFT)		       \
	| (OPT_ZONE_HIGHMEM << ___GFP_HIGHMEM * GFP_ZONES_SHIFT)	       \
	| (OPT_ZONE_DMA32 << ___GFP_DMA32 * GFP_ZONES_SHIFT)		       \
	| (ZONE_NORMAL << ___GFP_MOVABLE * GFP_ZONES_SHIFT)		       \
	| (OPT_ZONE_DMA << (___GFP_MOVABLE | ___GFP_DMA) * GFP_ZONES_SHIFT)    \
	| (ZONE_MOVABLE << (___GFP_MOVABLE | ___GFP_HIGHMEM) * GFP_ZONES_SHIFT)\
	| (OPT_ZONE_DMA32 << (___GFP_MOVABLE | ___GFP_DMA32) * GFP_ZONES_SHIFT)\
)
#define OPT_ZONE_DMA ZONE_DMA
#define OPT_ZONE_DMA32 ZONE_DMA32
#define OPT_ZONE_HIGHMEM ZONE_HIGHMEM
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
#define __GFP_HARDWALL   ((__force gfp_t)___GFP_HARDWALL)
#define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
#define __GFP_NOMEMALLOC ((__force gfp_t)___GFP_NOMEMALLOC)
#define __GFP_RECLAIM ((__force gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))
#define __GFP_RECLAIMABLE ((__force gfp_t)___GFP_RECLAIMABLE)

#define __free_page(page) __free_pages((page), 0)
#define __get_dma_pages(gfp_mask, order) \
		__get_free_pages((gfp_mask) | GFP_DMA, (order))
#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask), 0)
#define alloc_hugepage_vma(gfp_mask, vma, addr, order) \
	alloc_pages_vma(gfp_mask, order, vma, addr, numa_node_id(), true)
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)
#define alloc_page_vma(gfp_mask, vma, addr)			\
	alloc_pages_vma(gfp_mask, 0, vma, addr, numa_node_id(), false)
#define alloc_pages_vma(gfp_mask, order, vma, addr, node, false)\
	alloc_pages(gfp_mask, order)
#define free_page(addr) free_pages((addr), 0)
#define INIT_RADIX_TREE(root, mask) xa_init_flags(root, mask)
#define RADIX_TREE(name, mask) \
	struct radix_tree_root name = RADIX_TREE_INIT(name, mask)
#define RADIX_TREE_INDEX_BITS  (8  * sizeof(unsigned long))
#define RADIX_TREE_INIT(name, mask)	XARRAY_INIT(name, mask)
#define RADIX_TREE_MAX_PATH (DIV_ROUND_UP(RADIX_TREE_INDEX_BITS, \
					  RADIX_TREE_MAP_SHIFT))

#define radix_tree_for_each_slot(slot, root, iter, start)		\
	for (slot = radix_tree_iter_init(iter, start) ;			\
	     slot || (slot = radix_tree_next_chunk(root, iter, 0)) ;	\
	     slot = radix_tree_next_slot(slot, iter, 0))
#define radix_tree_for_each_tagged(slot, root, iter, start, tag)	\
	for (slot = radix_tree_iter_init(iter, start) ;			\
	     slot || (slot = radix_tree_next_chunk(root, iter,		\
			      RADIX_TREE_ITER_TAGGED | tag)) ;		\
	     slot = radix_tree_next_slot(slot, iter,			\
				RADIX_TREE_ITER_TAGGED | tag))
#define DEFINE_XARRAY(name) DEFINE_XARRAY_FLAGS(name, 0)
#define DEFINE_XARRAY_ALLOC(name) DEFINE_XARRAY_FLAGS(name, XA_FLAGS_ALLOC)
#define DEFINE_XARRAY_ALLOC1(name) DEFINE_XARRAY_FLAGS(name, XA_FLAGS_ALLOC1)
#define DEFINE_XARRAY_FLAGS(name, flags)				\
	struct xarray name = XARRAY_INIT(name, flags)
#define XARRAY_INIT(name, flags) {				\
	.xa_lock = __SPIN_LOCK_UNLOCKED(name.xa_lock),		\
	.xa_flags = flags,					\
	.xa_head = NULL,					\
}
#define XA_BUG_ON(xa, x) do {					\
		if (x) {					\
			xa_dump(xa);				\
			BUG();					\
		}						\
	} while (0)
#define XA_ERROR(errno) ((struct xa_node *)(((unsigned long)errno << 2) | 2UL))
#define XA_FLAGS_MARK(mark)	((__force gfp_t)((1U << __GFP_BITS_SHIFT) << \
						(__force unsigned)(mark)))
#define XA_LIMIT(_min, _max) (struct xa_limit) { .min = _min, .max = _max }
#define XA_NODE_BUG_ON(node, x) do {				\
		if (x) {					\
			if (node) xa_dump_node(node);		\
			BUG();					\
		}						\
	} while (0)
#define XA_STATE(name, array, index)				\
	struct xa_state name = __XA_STATE(array, index, 0, 0)
#define XA_STATE_ORDER(name, array, index, order)		\
	struct xa_state name = __XA_STATE(array,		\
			(index >> order) << order,		\
			order - (order % XA_CHUNK_SHIFT),	\
			(1U << (order % XA_CHUNK_SHIFT)) - 1)

#define __XA_STATE(array, index, shift, sibs)  {	\
	.xa = array,					\
	.xa_index = index,				\
	.xa_shift = shift,				\
	.xa_sibs = sibs,				\
	.xa_offset = 0,					\
	.xa_pad = 0,					\
	.xa_node = XAS_RESTART,				\
	.xa_alloc = NULL,				\
	.xa_update = NULL				\
}
#define xa_for_each(xa, index, entry) \
	xa_for_each_start(xa, index, entry, 0)
#define xa_for_each_marked(xa, index, entry, filter) \
	for (index = 0, entry = xa_find(xa, &index, ULONG_MAX, filter); \
	     entry; entry = xa_find_after(xa, &index, ULONG_MAX, filter))
#define xa_for_each_range(xa, index, entry, start, last)		\
	for (index = start,						\
	     entry = xa_find(xa, &index, last, XA_PRESENT);		\
	     entry;							\
	     entry = xa_find_after(xa, &index, last, XA_PRESENT))
#define xa_for_each_start(xa, index, entry, start) \
	xa_for_each_range(xa, index, entry, start, ULONG_MAX)
#define xa_lock(xa)		spin_lock(&(xa)->xa_lock)
#define xa_lock_bh(xa)		spin_lock_bh(&(xa)->xa_lock)
#define xa_lock_bh_nested(xa, subclass) \
				spin_lock_bh_nested(&(xa)->xa_lock, subclass)
#define xa_lock_irq(xa)		spin_lock_irq(&(xa)->xa_lock)
#define xa_lock_irq_nested(xa, subclass) \
				spin_lock_irq_nested(&(xa)->xa_lock, subclass)
#define xa_lock_irqsave(xa, flags) \
				spin_lock_irqsave(&(xa)->xa_lock, flags)
#define xa_lock_irqsave_nested(xa, flags, subclass) \
		spin_lock_irqsave_nested(&(xa)->xa_lock, flags, subclass)
#define xa_lock_nested(xa, subclass) \
				spin_lock_nested(&(xa)->xa_lock, subclass)
#define xa_trylock(xa)		spin_trylock(&(xa)->xa_lock)
#define xa_unlock(xa)		spin_unlock(&(xa)->xa_lock)
#define xa_unlock_bh(xa)	spin_unlock_bh(&(xa)->xa_lock)
#define xa_unlock_irq(xa)	spin_unlock_irq(&(xa)->xa_lock)
#define xa_unlock_irqrestore(xa, flags) \
				spin_unlock_irqrestore(&(xa)->xa_lock, flags)
#define xas_for_each(xas, entry, max) \
	for (entry = xas_find(xas, max); entry; \
	     entry = xas_next_entry(xas, max))
#define xas_for_each_conflict(xas, entry) \
	while ((entry = xas_find_conflict(xas)))
#define xas_for_each_marked(xas, entry, max, mark) \
	for (entry = xas_find_marked(xas, max, mark); entry; \
	     entry = xas_next_marked(xas, max, mark))
#define xas_lock(xas)		xa_lock((xas)->xa)
#define xas_lock_bh(xas)	xa_lock_bh((xas)->xa)
#define xas_lock_irq(xas)	xa_lock_irq((xas)->xa)
#define xas_lock_irqsave(xas, flags) \
				xa_lock_irqsave((xas)->xa, flags)
#define xas_marked(xas, mark)	xa_marked((xas)->xa, (mark))
#define xas_trylock(xas)	xa_trylock((xas)->xa)
#define xas_unlock(xas)		xa_unlock((xas)->xa)
#define xas_unlock_bh(xas)	xa_unlock_bh((xas)->xa)
#define xas_unlock_irq(xas)	xa_unlock_irq((xas)->xa)
#define xas_unlock_irqrestore(xas, flags) \
				xa_unlock_irqrestore((xas)->xa, flags)
#define IS_BUILTIN(option) __is_defined(option)
#define IS_ENABLED(option) __or(IS_BUILTIN(option), IS_MODULE(option))
#define IS_MODULE(option) __is_defined(option##_MODULE)
#define IS_REACHABLE(option) __or(IS_BUILTIN(option), \
				__and(IS_MODULE(option), __is_defined(MODULE)))
#define __ARG_PLACEHOLDER_1 0,
#define __BIG_ENDIAN 4321

#define __LITTLE_ENDIAN 1234
#define ____and(arg1_or_junk, y)	__take_second_arg(arg1_or_junk y, 0)
#define ____is_defined(arg1_or_junk)	__take_second_arg(arg1_or_junk 1, 0)
#define ____or(arg1_or_junk, y)		__take_second_arg(arg1_or_junk 1, y)
#define ___and(x, y)			____and(__ARG_PLACEHOLDER_##x, y)
#define ___is_defined(val)		____is_defined(__ARG_PLACEHOLDER_##val)
#define ___or(x, y)			____or(__ARG_PLACEHOLDER_##x, y)
#define __and(x, y)			___and(x, y)
#define __is_defined(x)			___is_defined(x)
#define __or(x, y)			___or(x, y)
#define __take_second_arg(__ignored, val, ...) val
#define OF_DEV_AUXDATA(_compat,_phys,_name,_pdata) \
	{ .compatible = _compat, .phys_addr = _phys, .name = _name, \
	  .platform_data = _pdata }

#define USE_PLATFORM_PM_SLEEP_OPS \
	.suspend = platform_pm_suspend, \
	.resume = platform_pm_resume, \
	.freeze = platform_pm_freeze, \
	.thaw = platform_pm_thaw, \
	.poweroff = platform_pm_poweroff, \
	.restore = platform_pm_restore,

#define builtin_platform_driver(__platform_driver) \
	builtin_driver(__platform_driver, platform_driver_register)
#define builtin_platform_driver_probe(__platform_driver, __platform_probe) \
static int __init __platform_driver##_init(void) \
{ \
	return platform_driver_probe(&(__platform_driver), \
				     __platform_probe);    \
} \
device_initcall(__platform_driver##_init); \

#define dev_is_platform(dev) ((dev)->bus == &platform_bus_type)
#define module_platform_driver(__platform_driver) \
	module_driver(__platform_driver, platform_driver_register, \
			platform_driver_unregister)
#define module_platform_driver_probe(__platform_driver, __platform_probe) \
static int __init __platform_driver##_init(void) \
{ \
	return platform_driver_probe(&(__platform_driver), \
				     __platform_probe);    \
} \
module_init(__platform_driver##_init); \
static void __exit __platform_driver##_exit(void) \
{ \
	platform_driver_unregister(&(__platform_driver)); \
} \
module_exit(__platform_driver##_exit);
#define platform_create_bundle(driver, probe, res, n_res, data, size) \
	__platform_create_bundle(driver, probe, res, n_res, data, size, THIS_MODULE)
#define platform_driver_probe(drv, probe) \
	__platform_driver_probe(drv, probe, THIS_MODULE)
#define platform_driver_register(drv) \
	__platform_driver_register(drv, THIS_MODULE)
#define platform_get_device_id(pdev)	((pdev)->id_entry)
#define platform_register_drivers(drivers, count) \
	__platform_register_drivers(drivers, count, THIS_MODULE)
#define to_platform_device(x) container_of((x), struct platform_device, dev)
#define to_platform_driver(drv)	(container_of((drv), struct platform_driver, \
				 driver))
#define DEVICE_ATTR(_name, _mode, _show, _store) \
	struct device_attribute dev_attr_##_name = __ATTR(_name, _mode, _show, _store)
#define DEVICE_ATTR_ADMIN_RO(_name) \
	struct device_attribute dev_attr_##_name = __ATTR_RO_MODE(_name, 0400)
#define DEVICE_ATTR_ADMIN_RW(_name) \
	struct device_attribute dev_attr_##_name = __ATTR_RW_MODE(_name, 0600)
#define DEVICE_ATTR_IGNORE_LOCKDEP(_name, _mode, _show, _store) \
	struct device_attribute dev_attr_##_name =		\
		__ATTR_IGNORE_LOCKDEP(_name, _mode, _show, _store)
#define DEVICE_ATTR_PREALLOC(_name, _mode, _show, _store) \
	struct device_attribute dev_attr_##_name = \
		__ATTR_PREALLOC(_name, _mode, _show, _store)
#define DEVICE_ATTR_RO(_name) \
	struct device_attribute dev_attr_##_name = __ATTR_RO(_name)
#define DEVICE_ATTR_RW(_name) \
	struct device_attribute dev_attr_##_name = __ATTR_RW(_name)
#define DEVICE_ATTR_WO(_name) \
	struct device_attribute dev_attr_##_name = __ATTR_WO(_name)
#define DEVICE_BOOL_ATTR(_name, _mode, _var) \
	struct dev_ext_attribute dev_attr_##_name = \
		{ __ATTR(_name, _mode, device_show_bool, device_store_bool), &(_var) }
#define DEVICE_INT_ATTR(_name, _mode, _var) \
	struct dev_ext_attribute dev_attr_##_name = \
		{ __ATTR(_name, _mode, device_show_int, device_store_int), &(_var) }
#define DEVICE_ULONG_ATTR(_name, _mode, _var) \
	struct dev_ext_attribute dev_attr_##_name = \
		{ __ATTR(_name, _mode, device_show_ulong, device_store_ulong), &(_var) }
#define MODULE_ALIAS_CHARDEV(major,minor) \
	MODULE_ALIAS("char-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_CHARDEV_MAJOR(major) \
	MODULE_ALIAS("char-major-" __stringify(major) "-*")

#define devm_alloc_percpu(dev, type)      \
	((typeof(type) __percpu *)__devm_alloc_percpu((dev), sizeof(type), \
						      __alignof__(type)))
#define devres_alloc(release, size, gfp) \
	__devres_alloc_node(release, size, gfp, NUMA_NO_NODE, #release)
#define devres_alloc_node(release, size, gfp, nid) \
	__devres_alloc_node(release, size, gfp, nid, #release)
#define root_device_register(name) \
	__root_device_register(name, THIS_MODULE)
#define sysfs_deprecated 0

#define for_each_wakeup_source(ws) \
	for ((ws) = wakeup_sources_walk_start();	\
	     (ws);					\
	     (ws) = wakeup_sources_walk_next((ws)))
#define DRIVER_ATTR_RO(_name) \
	struct driver_attribute driver_attr_##_name = __ATTR_RO(_name)
#define DRIVER_ATTR_RW(_name) \
	struct driver_attribute driver_attr_##_name = __ATTR_RW(_name)
#define DRIVER_ATTR_WO(_name) \
	struct driver_attribute driver_attr_##_name = __ATTR_WO(_name)

#define builtin_driver(__driver, __register, ...) \
static int __init __driver##_init(void) \
{ \
	return __register(&(__driver) , ##__VA_ARGS__); \
} \
device_initcall(__driver##_init);
#define module_driver(__driver, __register, __unregister, ...) \
static int __init __driver##_init(void) \
{ \
	return __register(&(__driver) , ##__VA_ARGS__); \
} \
module_init(__driver##_init); \
static void __exit __driver##_exit(void) \
{ \
	__unregister(&(__driver) , ##__VA_ARGS__); \
} \
module_exit(__driver##_exit);
#define BUS_ATTR_RO(_name) \
	struct bus_attribute bus_attr_##_name = __ATTR_RO(_name)
#define BUS_ATTR_RW(_name) \
	struct bus_attribute bus_attr_##_name = __ATTR_RW(_name)
#define BUS_ATTR_WO(_name) \
	struct bus_attribute bus_attr_##_name = __ATTR_WO(_name)

#define PMSG_IS_AUTO(msg)	(((msg).event & PM_EVENT_AUTO) != 0)
#define PM_EVENT_PRETHAW PM_EVENT_QUIESCE
#define SET_LATE_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	.suspend_late = suspend_fn, \
	.resume_early = resume_fn, \
	.freeze_late = suspend_fn, \
	.thaw_early = resume_fn, \
	.poweroff_late = suspend_fn, \
	.restore_early = resume_fn,
#define SET_NOIRQ_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	.suspend_noirq = suspend_fn, \
	.resume_noirq = resume_fn, \
	.freeze_noirq = suspend_fn, \
	.thaw_noirq = resume_fn, \
	.poweroff_noirq = suspend_fn, \
	.restore_noirq = resume_fn,
#define SET_RUNTIME_PM_OPS(suspend_fn, resume_fn, idle_fn) \
	.runtime_suspend = suspend_fn, \
	.runtime_resume = resume_fn, \
	.runtime_idle = idle_fn,
#define SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	.suspend = suspend_fn, \
	.resume = resume_fn, \
	.freeze = suspend_fn, \
	.thaw = resume_fn, \
	.poweroff = suspend_fn, \
	.restore = resume_fn,
#define SIMPLE_DEV_PM_OPS(name, suspend_fn, resume_fn) \
const struct dev_pm_ops __maybe_unused name = { \
	SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
}
#define UNIVERSAL_DEV_PM_OPS(name, suspend_fn, resume_fn, idle_fn) \
const struct dev_pm_ops __maybe_unused name = { \
	SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	SET_RUNTIME_PM_OPS(suspend_fn, resume_fn, idle_fn) \
}

#define device_pm_lock() do {} while (0)
#define device_pm_unlock() do {} while (0)
#define pm_ptr(_ptr) (_ptr)
#define suspend_report_result(fn, ret)					\
	do {								\
		__suspend_report_result(__func__, fn, ret);		\
	} while (0)

# define __hrtimer_clock_base_align


#define DEFINE_KLIST(_name, _get, _put)					\
	struct klist _name = KLIST_INIT(_name, _get, _put)
#define KLIST_INIT(_name, _get, _put)					\
	{ .k_lock	= __SPIN_LOCK_UNLOCKED(_name.k_lock),		\
	  .k_list	= LIST_HEAD_INIT(_name.k_list),			\
	  .get		= _get,						\
	  .put		= _put, }

#define CLASS_ATTR_RO(_name) \
	struct class_attribute class_attr_##_name = __ATTR_RO(_name)
#define CLASS_ATTR_RW(_name) \
	struct class_attribute class_attr_##_name = __ATTR_RW(_name)
#define CLASS_ATTR_STRING(_name, _mode, _str) \
	struct class_attribute_string class_attr_##_name = \
		_CLASS_ATTR_STRING(_name, _mode, _str)
#define CLASS_ATTR_WO(_name) \
	struct class_attribute class_attr_##_name = __ATTR_WO(_name)
#define _CLASS_ATTR_STRING(_name, _mode, _str) \
	{ __ATTR(_name, _mode, show_class_attr_string, NULL), _str }

#define class_create(owner, name)		\
({						\
	static struct lock_class_key __key;	\
	__class_create(owner, name, &__key);	\
})
#define class_register(class)			\
({						\
	static struct lock_class_key __key;	\
	__class_register(class, &__key);	\
})

#define __type_half_max(type) ((type)1 << (8*sizeof(type) - 1 - is_signed_type(type)))
#define check_add_overflow(a, b, d) __must_check_overflow(({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	__builtin_add_overflow(__a, __b, __d);	\
}))
#define check_mul_overflow(a, b, d) __must_check_overflow(({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	__builtin_mul_overflow(__a, __b, __d);	\
}))
#define check_shl_overflow(a, s, d) __must_check_overflow(({		\
	typeof(a) _a = a;						\
	typeof(s) _s = s;						\
	typeof(d) _d = d;						\
	u64 _a_full = _a;						\
	unsigned int _to_shift =					\
		is_non_negative(_s) && _s < 8 * sizeof(*d) ? _s : 0;	\
	*_d = (_a_full << _to_shift);					\
	(_to_shift != _s || is_negative(*_d) || is_negative(_a) ||	\
	(*_d >> _to_shift) != _a);					\
}))
#define check_sub_overflow(a, b, d) __must_check_overflow(({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	__builtin_sub_overflow(__a, __b, __d);	\
}))
#define flex_array_size(p, member, count)				\
	array_size(count,						\
		    sizeof(*(p)->member) + __must_be_array((p)->member))
#define is_negative(a) (!(is_non_negative(a)))
#define is_non_negative(a) ((a) > 0 || (a) == 0)
#define is_signed_type(type)       (((type)(-1)) < (type)1)
#define struct_size(p, member, count)					\
	__ab_c_size(count,						\
		    sizeof(*(p)->member) + __must_be_array((p)->member),\
		    sizeof(*(p)))
#define type_max(T) ((T)((__type_half_max(T) - 1) + __type_half_max(T)))
#define type_min(T) ((T)((T)-type_max(T)-(T)1))
#define DEFINE_RES_DMA(_dma)						\
	DEFINE_RES_DMA_NAMED((_dma), NULL)
#define DEFINE_RES_DMA_NAMED(_dma, _name)				\
	DEFINE_RES_NAMED((_dma), 1, (_name), IORESOURCE_DMA)
#define DEFINE_RES_IO(_start, _size)					\
	DEFINE_RES_IO_NAMED((_start), (_size), NULL)
#define DEFINE_RES_IO_NAMED(_start, _size, _name)			\
	DEFINE_RES_NAMED((_start), (_size), (_name), IORESOURCE_IO)
#define DEFINE_RES_IRQ(_irq)						\
	DEFINE_RES_IRQ_NAMED((_irq), NULL)
#define DEFINE_RES_IRQ_NAMED(_irq, _name)				\
	DEFINE_RES_NAMED((_irq), 1, (_name), IORESOURCE_IRQ)
#define DEFINE_RES_MEM(_start, _size)					\
	DEFINE_RES_MEM_NAMED((_start), (_size), NULL)
#define DEFINE_RES_MEM_NAMED(_start, _size, _name)			\
	DEFINE_RES_NAMED((_start), (_size), (_name), IORESOURCE_MEM)
#define DEFINE_RES_NAMED(_start, _size, _name, _flags)			\
	{								\
		.start = (_start),					\
		.end = (_start) + (_size) - 1,				\
		.name = (_name),					\
		.flags = (_flags),					\
		.desc = IORES_DESC_NONE,				\
	}
#define IORESOURCE_EXT_TYPE_BITS 0x01000000	
#define IORESOURCE_IRQ_OPTIONAL 	(1<<5)

#define __request_mem_region(start,n,name, excl) __request_region(&iomem_resource, (start), (n), (name), excl)
#define devm_release_mem_region(dev, start, n) \
	__devm_release_region(dev, &iomem_resource, (start), (n))
#define devm_release_region(dev, start, n) \
	__devm_release_region(dev, &ioport_resource, (start), (n))
#define devm_request_mem_region(dev,start,n,name) \
	__devm_request_region(dev, &iomem_resource, (start), (n), (name))
#define devm_request_region(dev,start,n,name) \
	__devm_request_region(dev, &ioport_resource, (start), (n), (name))
#define release_mem_region(start,n)	__release_region(&iomem_resource, (start), (n))
#define release_region(start,n)	__release_region(&ioport_resource, (start), (n))
#define rename_region(region, newname) do { (region)->name = (newname); } while (0)
#define request_mem_region(start,n,name) __request_region(&iomem_resource, (start), (n), (name), 0)
#define request_mem_region_exclusive(start,n,name) \
	__request_region(&iomem_resource, (start), (n), (name), IORESOURCE_EXCLUSIVE)
#define request_muxed_region(start,n,name)	__request_region(&ioport_resource, (start), (n), (name), IORESOURCE_MUXED)
#define request_region(start,n,name)		__request_region(&ioport_resource, (start), (n), (name), 0)
#define EM_DATA_CB(_active_power_cb) { }
#define EM_MAX_POWER 0xFFFF

#define em_scale_power(p) ((p) * 1000)
#define em_span_cpus(em) (to_cpumask((em)->cpus))
#define SD_FLAG(name, mflags) __##name,
# define SD_INIT_NAME(type)		.name = #type

#define SDF_NEEDS_GROUPS       0x4
#define SDF_SHARED_CHILD       0x1
#define SDF_SHARED_PARENT      0x2

#define TASK_PFA_CLEAR(name, func)					\
	static inline void task_clear_##func(struct task_struct *p)	\
	{ clear_bit(PFA_##name, &p->atomic_flags); }
#define TASK_PFA_SET(name, func)					\
	static inline void task_set_##func(struct task_struct *p)	\
	{ set_bit(PFA_##name, &p->atomic_flags); }
#define TASK_PFA_TEST(name, func)					\
	static inline bool task_##func(struct task_struct *p)		\
	{ return test_bit(PFA_##name, &p->atomic_flags); }
#define TASK_SIZE_OF(tsk)	TASK_SIZE
#define UCLAMP_BUCKETS CONFIG_UCLAMP_BUCKETS_COUNT

#define __set_current_state(state_value)				\
	do {								\
		debug_normal_state_change((state_value));		\
		WRITE_ONCE(current->__state, (state_value));		\
	} while (0)
#define clear_stopped_child_used_math(child)	do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define clear_used_math()			clear_stopped_child_used_math(current)
#define cond_resched() ({			\
	___might_sleep("__FILE__", "__LINE__", 0);	\
	_cond_resched();			\
})
#define cond_resched_lock(lock) ({				\
	___might_sleep("__FILE__", "__LINE__", PREEMPT_LOCK_OFFSET);\
	__cond_resched_lock(lock);				\
})
#define cond_resched_rwlock_read(lock) ({			\
	__might_sleep("__FILE__", "__LINE__", PREEMPT_LOCK_OFFSET);	\
	__cond_resched_rwlock_read(lock);			\
})
#define cond_resched_rwlock_write(lock) ({			\
	__might_sleep("__FILE__", "__LINE__", PREEMPT_LOCK_OFFSET);	\
	__cond_resched_rwlock_write(lock);			\
})
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition)	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
#define current_restore_rtlock_saved_state()				\
	do {								\
		lockdep_assert_irqs_disabled();				\
		raw_spin_lock(&current->pi_lock);			\
		debug_rtlock_wait_restore_state();			\
		WRITE_ONCE(current->__state, current->saved_state);	\
		current->saved_state = TASK_RUNNING;			\
		raw_spin_unlock(&current->pi_lock);			\
	} while (0);
#define current_save_and_set_rtlock_wait_state()			\
	do {								\
		lockdep_assert_irqs_disabled();				\
		raw_spin_lock(&current->pi_lock);			\
		current->saved_state = current->__state;		\
		debug_rtlock_wait_set_state();				\
		WRITE_ONCE(current->__state, TASK_RTLOCK_WAIT);		\
		raw_spin_unlock(&current->pi_lock);			\
	} while (0);
# define debug_normal_state_change(state_value)				\
	do {								\
		WARN_ON_ONCE(is_special_task_state(state_value));	\
		current->task_state_change = _THIS_IP_;			\
	} while (0)
# define debug_rtlock_wait_restore_state()				\
	do {								 \
		current->task_state_change = current->saved_state_change;\
	} while (0)
# define debug_rtlock_wait_set_state()					\
	do {								 \
		current->saved_state_change = current->task_state_change;\
		current->task_state_change = _THIS_IP_;			 \
	} while (0)
# define debug_special_state_change(state_value)			\
	do {								\
		WARN_ON_ONCE(!is_special_task_state(state_value));	\
		current->task_state_change = _THIS_IP_;			\
	} while (0)
#define get_current_state()	READ_ONCE(current->__state)
#define get_task_comm(buf, tsk) ({			\
	BUILD_BUG_ON(sizeof(buf) != TASK_COMM_LEN);	\
	__get_task_comm(buf, sizeof(buf), tsk);		\
})
#define is_special_task_state(state)				\
	((state) & (__TASK_STOPPED | __TASK_TRACED | TASK_PARKED | TASK_DEAD))
#define set_current_state(state_value)					\
	do {								\
		debug_normal_state_change((state_value));		\
		smp_store_mb(current->__state, (state_value));		\
	} while (0)
#define set_special_state(state_value)					\
	do {								\
		unsigned long flags; 			\
									\
		raw_spin_lock_irqsave(&current->pi_lock, flags);	\
		debug_special_state_change((state_value));		\
		WRITE_ONCE(current->__state, (state_value));		\
		raw_spin_unlock_irqrestore(&current->pi_lock, flags);	\
	} while (0)
#define set_stopped_child_used_math(child)	do { (child)->flags |= PF_USED_MATH; } while (0)
#define set_used_math()				set_stopped_child_used_math(current)
#define task_is_running(task)		(READ_ONCE((task)->__state) == TASK_RUNNING)
#define task_is_stopped(task)		((READ_ONCE(task->__state) & __TASK_STOPPED) != 0)
#define task_is_stopped_or_traced(task)	((READ_ONCE(task->__state) & (__TASK_STOPPED | __TASK_TRACED)) != 0)
#define task_is_traced(task)		((READ_ONCE(task->__state) & __TASK_TRACED) != 0)
# define task_thread_info(task)	((struct thread_info *)(task)->stack)
#define tsk_used_math(p)			((p)->flags & PF_USED_MATH)
#define used_math()				tsk_used_math(current)

#define CPUCLOCK_PERTHREAD(clock) \
	(((clock) & (clockid_t) CPUCLOCK_PERTHREAD_MASK) != 0)
#define CPUCLOCK_PID(clock)		((pid_t) ~((clock) >> 3))
#define CPUCLOCK_WHICH(clock)	((clock) & (clockid_t) CPUCLOCK_CLOCK_MASK)
#define INIT_CPU_TIMERBASE(b) {						\
	.nextevt	= U64_MAX,					\
}
#define INIT_CPU_TIMERBASES(b) {					\
	INIT_CPU_TIMERBASE(b[0]),					\
	INIT_CPU_TIMERBASE(b[1]),					\
	INIT_CPU_TIMERBASE(b[2]),					\
}
#define INIT_CPU_TIMERS(s)						\
	.posix_cputimers = {						\
		.bases = INIT_CPU_TIMERBASES(s.posix_cputimers.bases),	\
	},
#define REQUEUE_PENDING 1




#define clear_syscall_work_syscall_user_dispatch(tsk) \
	clear_task_syscall_work(tsk, SYSCALL_USER_DISPATCH)
#define UAPI_SA_FLAGS                                                          \
	(SA_NOCLDSTOP | SA_NOCLDWAIT | SA_SIGINFO | SA_ONSTACK | SA_RESTART |  \
	 SA_NODEFER | SA_RESETHAND | SA_EXPOSE_TAGBITS | __ARCH_UAPI_SA_FLAGS)



#define NICE_TO_PRIO(nice)	((nice) + DEFAULT_PRIO)
#define PRIO_TO_NICE(prio)	((prio) - DEFAULT_PRIO)




#define SECCOMP_NOTIFY_ADDFD_SIZE_LATEST SECCOMP_NOTIFY_ADDFD_SIZE_VER0
#define SECCOMP_NOTIFY_ADDFD_SIZE_VER0 24

#define SECCOMP_IO(nr)			_IO(SECCOMP_IOC_MAGIC, nr)
#define SECCOMP_IOR(nr, type)		_IOR(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOW(nr, type)		_IOW(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOWR(nr, type)		_IOWR(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_RET_KILL_PROCESS 0x80000000U 
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)

#define PLIST_HEAD(head) \
	struct plist_head head = PLIST_HEAD_INIT(head)
#define PLIST_HEAD_INIT(head)				\
{							\
	.node_list = LIST_HEAD_INIT((head).node_list)	\
}
#define PLIST_NODE_INIT(node, __prio)			\
{							\
	.prio  = (__prio),				\
	.prio_list = LIST_HEAD_INIT((node).prio_list),	\
	.node_list = LIST_HEAD_INIT((node).node_list),	\
}

# define plist_first_entry(head, type, member)	\
({ \
	WARN_ON(plist_head_empty(head)); \
	container_of(plist_first(head), type, member); \
})
#define plist_for_each(pos, head)	\
	 list_for_each_entry(pos, &(head)->node_list, node_list)
#define plist_for_each_continue(pos, head)	\
	 list_for_each_entry_continue(pos, &(head)->node_list, node_list)
#define plist_for_each_entry(pos, head, mem)	\
	 list_for_each_entry(pos, &(head)->node_list, mem.node_list)
#define plist_for_each_entry_continue(pos, head, m)	\
	list_for_each_entry_continue(pos, &(head)->node_list, m.node_list)
#define plist_for_each_entry_safe(pos, n, head, m)	\
	list_for_each_entry_safe(pos, n, &(head)->node_list, m.node_list)
#define plist_for_each_safe(pos, n, head)	\
	 list_for_each_entry_safe(pos, n, &(head)->node_list, node_list)
# define plist_last_entry(head, type, member)	\
({ \
	WARN_ON(plist_head_empty(head)); \
	container_of(plist_last(head), type, member); \
})
#define plist_next(pos) \
	list_next_entry(pos, node_list)
#define plist_prev(pos) \
	list_prev_entry(pos, node_list)

#define shm_init_task(task) INIT_LIST_HEAD(&(task)->sysvshm.shm_clist)
#define SHMALL (ULONG_MAX - (1UL << 24)) 
#define SHMMAX (ULONG_MAX - (1UL << 24)) 
#define SHMMIN 1			 
#define SHMMNI 4096			 
#define SHMSEG SHMMNI			 
#define SHM_LOCK 	11
#define SHM_STAT_ANY    15
#define SHM_UNLOCK 	12


#define DIPC            25
#define IPCCALL(version,op)	((version)<<16 | (op))
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



#define GETALL  13       
#define GETNCNT 14       
#define GETPID  11       
#define GETVAL  12       
#define GETZCNT 15       
#define SEMAEM  SEMVMX          
#define SEMMAP  SEMMNS          
#define SEMMNI  32000           
#define SEMMNS  (SEMMNI*SEMMSL) 
#define SEMMNU  SEMMNS          
#define SEMMSL  32000           
#define SEMOPM  500	        
#define SEMUME  SEMOPM          
#define SEMUSZ  20		
#define SEMVMX  32767           
#define SEM_INFO 19
#define SEM_STAT 18
#define SEM_STAT_ANY 20
#define SEM_UNDO        0x1000  
#define SETALL  17       
#define SETVAL  16       


#define do_each_pid_task(pid, type, task)				\
	do {								\
		if ((pid) != NULL)					\
			hlist_for_each_entry_rcu((task),		\
				&(pid)->tasks[type], pid_links[type]) {
#define do_each_pid_thread(pid, type, task)				\
	do_each_pid_task(pid, type, task) {				\
		struct task_struct *tg___ = task;			\
		for_each_thread(tg___, task) {
#define while_each_pid_task(pid, type, task)				\
				if (type == PIDTYPE_PID)		\
					break;				\
			}						\
	} while (0)
#define while_each_pid_thread(pid, type, task)				\
		}							\
		task = tg___;						\
	} while_each_pid_task(pid, type, task)

#define __hlist_for_each_rcu(pos, head)				\
	for (pos = rcu_dereference(hlist_first_rcu(head));	\
	     pos;						\
	     pos = rcu_dereference(hlist_next_rcu(pos)))
#define __list_check_rcu(dummy, cond, extra...)				\
	({								\
	check_arg_count_one(extra);					\
	RCU_LOCKDEP_WARN(!(cond) && !rcu_read_lock_any_held(),		\
			 "RCU-list traversed in non-reader section!");	\
	})
#define __list_check_srcu(cond)					 \
	({								 \
	RCU_LOCKDEP_WARN(!(cond),					 \
		"RCU-list traversed without holding the required lock!");\
	})

#define hlist_first_rcu(head)	(*((struct hlist_node __rcu **)(&(head)->first)))
#define hlist_for_each_entry_continue_rcu(pos, member)			\
	for (pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu( \
			&(pos)->member)), typeof(*(pos)), member);	\
	     pos;							\
	     pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(	\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_for_each_entry_continue_rcu_bh(pos, member)		\
	for (pos = hlist_entry_safe(rcu_dereference_bh(hlist_next_rcu(  \
			&(pos)->member)), typeof(*(pos)), member);	\
	     pos;							\
	     pos = hlist_entry_safe(rcu_dereference_bh(hlist_next_rcu(	\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_for_each_entry_from_rcu(pos, member)			\
	for (; pos;							\
	     pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(	\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_for_each_entry_rcu(pos, head, member, cond...)		\
	for (__list_check_rcu(dummy, ## cond, 0),			\
	     pos = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_for_each_entry_rcu_bh(pos, head, member)			\
	for (pos = hlist_entry_safe(rcu_dereference_bh(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_bh(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_for_each_entry_rcu_notrace(pos, head, member)			\
	for (pos = hlist_entry_safe(rcu_dereference_raw_check(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw_check(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_for_each_entry_srcu(pos, head, member, cond)		\
	for (__list_check_srcu(cond),					\
	     pos = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(head)),\
			typeof(*(pos)), member);			\
		pos;							\
		pos = hlist_entry_safe(rcu_dereference_raw(hlist_next_rcu(\
			&(pos)->member)), typeof(*(pos)), member))
#define hlist_next_rcu(node)	(*((struct hlist_node __rcu **)(&(node)->next)))
#define hlist_pprev_rcu(node)	(*((struct hlist_node __rcu **)((node)->pprev)))
#define list_entry_lockless(ptr, type, member) \
	container_of((typeof(ptr))READ_ONCE(ptr), type, member)
#define list_entry_rcu(ptr, type, member) \
	container_of(READ_ONCE(ptr), type, member)
#define list_first_or_null_rcu(ptr, type, member) \
({ \
	struct list_head *__ptr = (ptr); \
	struct list_head *__next = READ_ONCE(__ptr->next); \
	likely(__ptr != __next) ? list_entry_rcu(__next, type, member) : NULL; \
})
#define list_for_each_entry_continue_rcu(pos, head, member) 		\
	for (pos = list_entry_rcu(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head);	\
	     pos = list_entry_rcu(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_from_rcu(pos, head, member)			\
	for (; &(pos)->member != (head);					\
		pos = list_entry_rcu(pos->member.next, typeof(*(pos)), member))
#define list_for_each_entry_lockless(pos, head, member) \
	for (pos = list_entry_lockless((head)->next, typeof(*pos), member); \
	     &pos->member != (head); \
	     pos = list_entry_lockless(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_rcu(pos, head, member, cond...)		\
	for (__list_check_rcu(dummy, ## cond, 0),			\
	     pos = list_entry_rcu((head)->next, typeof(*pos), member);	\
		&pos->member != (head);					\
		pos = list_entry_rcu(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_srcu(pos, head, member, cond)		\
	for (__list_check_srcu(cond),					\
	     pos = list_entry_rcu((head)->next, typeof(*pos), member);	\
		&pos->member != (head);					\
		pos = list_entry_rcu(pos->member.next, typeof(*pos), member))
#define list_next_or_null_rcu(head, ptr, type, member) \
({ \
	struct list_head *__head = (head); \
	struct list_head *__ptr = (ptr); \
	struct list_head *__next = READ_ONCE(__ptr->next); \
	likely(__next != __head) ? list_entry_rcu(__next, type, \
						  member) : NULL; \
})
#define list_next_rcu(list)	(*((struct list_head __rcu **)(&(list)->next)))
#define list_tail_rcu(head)	(*((struct list_head __rcu **)(&(head)->prev)))
#define CLONE_ARGS_SIZE_VER0 64 
#define CLONE_ARGS_SIZE_VER1 80 
#define CLONE_ARGS_SIZE_VER2 88 
#define CLONE_CLEAR_SIGHAND 0x100000000ULL 
#define CLONE_INTO_CGROUP 0x200000000ULL 
#define SCHED_RESET_ON_FORK     0x40000000



#define dev_WARN(dev, format, arg...) \
	WARN(1, "%s %s: " format, dev_driver_string(dev), dev_name(dev), ## arg)
#define dev_WARN_ONCE(dev, condition, format, arg...) \
	WARN_ONCE(condition, "%s %s: " format, \
			dev_driver_string(dev), dev_name(dev), ## arg)
#define dev_alert(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_alert, KERN_ALERT, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_alert_once(dev, fmt, ...)					\
	dev_level_once(dev_alert, dev, fmt, ##__VA_ARGS__)
#define dev_alert_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_alert, dev, fmt, ##__VA_ARGS__)
#define dev_crit(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_crit, KERN_CRIT, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_crit_once(dev, fmt, ...)					\
	dev_level_once(dev_crit, dev, fmt, ##__VA_ARGS__)
#define dev_crit_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_crit, dev, fmt, ##__VA_ARGS__)
#define dev_dbg(dev, fmt, ...)						\
	dynamic_dev_dbg(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_dbg_once(dev, fmt, ...)					\
	dev_level_once(dev_dbg, dev, fmt, ##__VA_ARGS__)
#define dev_dbg_ratelimited(dev, fmt, ...)				\
do {									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);			\
	if (DYNAMIC_DEBUG_BRANCH(descriptor) &&				\
	    __ratelimit(&_rs))						\
		__dynamic_dev_dbg(&descriptor, dev, dev_fmt(fmt),	\
				  ##__VA_ARGS__);			\
} while (0)
#define dev_emerg(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_emerg, KERN_EMERG, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_emerg_once(dev, fmt, ...)					\
	dev_level_once(dev_emerg, dev, fmt, ##__VA_ARGS__)
#define dev_emerg_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_emerg, dev, fmt, ##__VA_ARGS__)
#define dev_err(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_err, KERN_ERR, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_err_once(dev, fmt, ...)					\
	dev_level_once(dev_err, dev, fmt, ##__VA_ARGS__)
#define dev_err_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_err, dev, fmt, ##__VA_ARGS__)
#define dev_fmt(fmt) fmt
#define dev_info(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_info, KERN_INFO, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_info_once(dev, fmt, ...)					\
	dev_level_once(dev_info, dev, fmt, ##__VA_ARGS__)
#define dev_info_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_info, dev, fmt, ##__VA_ARGS__)
#define dev_level_once(dev_level, dev, fmt, ...)			\
do {									\
	static bool __print_once __read_mostly;				\
									\
	if (!__print_once) {						\
		__print_once = true;					\
		dev_level(dev, fmt, ##__VA_ARGS__);			\
	}								\
} while (0)
#define dev_level_ratelimited(dev_level, dev, fmt, ...)			\
do {									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
	if (__ratelimit(&_rs))						\
		dev_level(dev, fmt, ##__VA_ARGS__);			\
} while (0)
#define dev_notice(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_notice, KERN_NOTICE, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_notice_once(dev, fmt, ...)					\
	dev_level_once(dev_notice, dev, fmt, ##__VA_ARGS__)
#define dev_notice_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_notice, dev, fmt, ##__VA_ARGS__)
#define dev_printk(level, dev, fmt, ...)				\
	({								\
		dev_printk_index_emit(level, fmt);			\
		_dev_printk(level, dev, fmt, ##__VA_ARGS__);		\
	})
#define dev_printk_index_emit(level, fmt, ...) \
	printk_index_subsys_emit("%s %s: ", level, fmt)
#define dev_printk_index_wrap(_p_func, level, dev, fmt, ...)		\
	({								\
		dev_printk_index_emit(level, fmt);			\
		_p_func(dev, fmt, ##__VA_ARGS__);			\
	})
#define dev_vdbg(dev, fmt, ...)						\
({									\
	if (0)								\
		dev_printk(KERN_DEBUG, dev, dev_fmt(fmt), ##__VA_ARGS__); \
})
#define dev_warn(dev, fmt, ...) \
	dev_printk_index_wrap(_dev_warn, KERN_WARNING, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_warn_once(dev, fmt, ...)					\
	dev_level_once(dev_warn, dev, fmt, ##__VA_ARGS__)
#define dev_warn_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_warn, dev, fmt, ##__VA_ARGS__)
#define WARN_ON_RATELIMIT(condition, state)	({		\
	bool __rtn_cond = !!(condition);			\
	WARN_ON(__rtn_cond && __ratelimit(state));		\
	__rtn_cond;						\
})
#define WARN_RATELIMIT(condition, format, ...)			\
({								\
	static DEFINE_RATELIMIT_STATE(_rs,			\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);	\
	int rtn = !!(condition);				\
								\
	if (unlikely(rtn && __ratelimit(&_rs)))			\
		WARN(rtn, format, ##__VA_ARGS__);		\
								\
	rtn;							\
})




#define to_node(device) container_of(device, struct node, dev)

#define IOMMU_CACHE_INVALIDATE_INFO_VERSION_1 1

#define DECLARE_IOASID_SET(name) struct ioasid_set name = { 0 }
#define INVALID_IOASID ((ioasid_t)-1)


#define for_each_sg(sglist, sg, nr, __i)	\
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))
#define for_each_sg_dma_page(sglist, dma_iter, dma_nents, pgoffset)            \
	for (__sg_page_iter_start(&(dma_iter)->base, sglist, dma_nents,        \
				  pgoffset);                                   \
	     __sg_page_iter_dma_next(dma_iter);)
#define for_each_sg_page(sglist, piter, nents, pgoffset)		   \
	for (__sg_page_iter_start((piter), (sglist), (nents), (pgoffset)); \
	     __sg_page_iter_next(piter);)
#define for_each_sgtable_dma_page(sgt, dma_iter, pgoffset)	\
	for_each_sg_dma_page((sgt)->sgl, dma_iter, (sgt)->nents, pgoffset)
#define for_each_sgtable_dma_sg(sgt, sg, i)	\
	for_each_sg((sgt)->sgl, sg, (sgt)->nents, i)
#define for_each_sgtable_page(sgt, piter, pgoffset)	\
	for_each_sg_page((sgt)->sgl, piter, (sgt)->orig_nents, pgoffset)
#define for_each_sgtable_sg(sgt, sg, i)		\
	for_each_sg((sgt)->sgl, sg, (sgt)->orig_nents, i)
#define sg_chain_ptr(sg)	\
	((struct scatterlist *) ((sg)->page_link & ~(SG_CHAIN | SG_END)))
#define sg_dma_address(sg)	((sg)->dma_address)
#define sg_dma_len(sg)		((sg)->dma_length)
#define sg_is_chain(sg)		((sg)->page_link & SG_CHAIN)
#define sg_is_last(sg)		((sg)->page_link & SG_END)
#define FAULT_FLAG_DEFAULT  (FAULT_FLAG_ALLOW_RETRY | \
			     FAULT_FLAG_KILLABLE | \
			     FAULT_FLAG_INTERRUPTIBLE)
#define FAULT_FLAG_TRACE \
	{ FAULT_FLAG_WRITE,		"WRITE" }, \
	{ FAULT_FLAG_MKWRITE,		"MKWRITE" }, \
	{ FAULT_FLAG_ALLOW_RETRY,	"ALLOW_RETRY" }, \
	{ FAULT_FLAG_RETRY_NOWAIT,	"RETRY_NOWAIT" }, \
	{ FAULT_FLAG_KILLABLE,		"KILLABLE" }, \
	{ FAULT_FLAG_TRIED,		"TRIED" }, \
	{ FAULT_FLAG_USER,		"USER" }, \
	{ FAULT_FLAG_REMOTE,		"REMOTE" }, \
	{ FAULT_FLAG_INSTRUCTION,	"INSTRUCTION" }, \
	{ FAULT_FLAG_INTERRUPTIBLE,	"INTERRUPTIBLE" }
#define GUP_PIN_COUNTING_BIAS (1U << 10)

#define  MM_CP_DIRTY_ACCT                  (1UL << 0)
#define  MM_CP_PROT_NUMA                   (1UL << 1)
#define  MM_CP_UFFD_WP                     (1UL << 2) 
#define  MM_CP_UFFD_WP_ALL                 (MM_CP_UFFD_WP | \
					    MM_CP_UFFD_WP_RESOLVE)
#define  MM_CP_UFFD_WP_RESOLVE             (1UL << 3) 
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)

#define TASK_EXEC ((current->personality & READ_IMPLIES_EXEC) ? VM_EXEC : 0)
#define TLB_FLUSH_VMA(mm,flags) { .vm_mm = (mm), .vm_flags = (flags) }
#define VM_ACCESS_FLAGS (VM_READ | VM_WRITE | VM_EXEC)
#define VM_DATA_DEFAULT_FLAGS  VM_DATA_FLAGS_EXEC
#define VM_IO           0x00004000	
#define VM_NO_KHUGEPAGED (VM_SPECIAL | VM_HUGETLB)
# define VM_PKEY_BIT4  VM_HIGH_ARCH_4
#define VM_SPECIAL (VM_IO | VM_DONTEXPAND | VM_PFNMAP | VM_MIXEDMAP)
#define VM_STACK_DEFAULT_FLAGS VM_DATA_DEFAULT_FLAGS
#define VM_UNMAPPED_AREA_TOPDOWN 1

#define __pa_symbol(x)  __pa(RELOC_HIDE((unsigned long)(x), 0))
#define anon_vma_interval_tree_foreach(avc, root, start, last)		 \
	for (avc = anon_vma_interval_tree_iter_first(root, start, last); \
	     avc; avc = anon_vma_interval_tree_iter_next(avc, start, last))
#define cpupid_match_pid(task, cpupid) __cpupid_match_pid(task->pid, cpupid)
  #define expand_upwards(vma, address) (0)
#define free_highmem_page(page) free_reserved_page(page)
#define is_ioremap_addr(x) is_vmalloc_addr(x)
#define lm_alias(x)	__va(__pa_symbol(x))
#define lru_to_page(head) (list_entry((head)->prev, struct page, lru))
#define mm_forbids_zeropage(X)	(0)
#define mm_zero_struct_page(pp)  ((void)memset((pp), 0, sizeof(struct page)))
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
#define offset_in_thp(page, p)	((unsigned long)(p) & (thp_size(page) - 1))
#define page_address(page) lowmem_page_address(page)
#define page_address_init()  do { } while(0)
#define page_ref_zero_or_close_to_overflow(page) \
	((unsigned int) page_ref_count(page) + 127u <= 127u)
#define page_to_virt(x)	__va(PFN_PHYS(page_to_pfn(x)))
#define pmd_huge_pte(mm, pmd) (pmd_to_page(pmd)->pmd_huge_pte)
#define pte_alloc(mm, pmd) (unlikely(pmd_none(*(pmd))) && __pte_alloc(mm, pmd))
#define pte_alloc_kernel(pmd, address)			\
	((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd))? \
		NULL: pte_offset_kernel(pmd, address))
#define pte_alloc_map(mm, pmd, address)			\
	(pte_alloc(mm, pmd) ? NULL : pte_offset_map(pmd, address))
#define pte_alloc_map_lock(mm, pmd, address, ptlp)	\
	(pte_alloc(mm, pmd) ?			\
		 NULL : pte_offset_map_lock(mm, pmd, address, ptlp))
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
#define randomize_va_space 0
#define set_page_address(page, address)  do { } while(0)
#define sysctl_legacy_va_layout 0
#define untagged_addr(addr) (addr)
#define vma_interval_tree_foreach(vma, root, start, last)		\
	for (vma = vma_interval_tree_iter_first(root, start, last);	\
	     vma; vma = vma_interval_tree_iter_next(vma, start, last))
#define DISABLE_NUMA_STAT   0
#define ENABLE_NUMA_STAT   1

#define __count_zid_vm_events(item, zid, delta) \
	__count_vm_events(item##_NORMAL - ZONE_NORMAL + zid, delta)
#define count_vm_numa_event(x)     count_vm_event(x)
#define count_vm_numa_events(x, y) count_vm_events(x, y)
#define count_vm_tlb_event(x)	   count_vm_event(x)
#define count_vm_tlb_events(x, y)  count_vm_events(x, y)
#define count_vm_vmacache_event(x) count_vm_event(x)
#define dec_node_page_state __dec_node_page_state
#define dec_zone_page_state __dec_zone_page_state
#define dec_zone_state __dec_zone_state
#define inc_node_page_state __inc_node_page_state
#define inc_node_state __inc_node_state
#define inc_zone_page_state __inc_zone_page_state
#define inc_zone_state __inc_zone_state
#define mod_node_page_state __mod_node_page_state
#define mod_zone_page_state __mod_zone_page_state
#define node_page_state(node, item) global_node_page_state(item)
#define node_page_state_pages(node, item) global_node_page_state_pages(item)
#define set_pgdat_percpu_threshold(pgdat, callback) { }
#define sum_zone_node_page_state(node, item) global_zone_page_state(item)
#define DMA32_ZONE(xx) xx##_DMA32,
#define DMA_ZONE(xx) xx##_DMA,
#define FOR_ALL_ZONES(xx) DMA_ZONE(xx) DMA32_ZONE(xx) xx##_NORMAL, HIGHMEM_ZONE(xx) xx##_MOVABLE
#define HIGHMEM_ZONE(xx) xx##_HIGH,
#define THP_FILE_ALLOC ({ BUILD_BUG(); 0; })
#define THP_FILE_FALLBACK ({ BUILD_BUG(); 0; })
#define THP_FILE_FALLBACK_CHARGE ({ BUILD_BUG(); 0; })
#define THP_FILE_MAPPED ({ BUILD_BUG(); 0; })

#define HPAGE_PMD_MASK ({ BUILD_BUG(); 0; })
#define HPAGE_PMD_NR (1<<HPAGE_PMD_ORDER)
#define HPAGE_PMD_ORDER (HPAGE_PMD_SHIFT-PAGE_SHIFT)
#define HPAGE_PMD_SHIFT PMD_SHIFT
#define HPAGE_PMD_SIZE ({ BUILD_BUG(); 0; })
#define HPAGE_PUD_MASK ({ BUILD_BUG(); 0; })
#define HPAGE_PUD_SHIFT PUD_SHIFT
#define HPAGE_PUD_SIZE ({ BUILD_BUG(); 0; })

#define mk_huge_pmd(page, prot) pmd_mkhuge(mk_pmd(page, prot))
#define split_huge_pmd(__vma, __pmd, __address)				\
	do {								\
		pmd_t *____pmd = (__pmd);				\
		if (is_swap_pmd(*____pmd) || pmd_trans_huge(*____pmd)	\
					|| pmd_devmap(*____pmd))	\
			__split_huge_pmd(__vma, __pmd, __address,	\
						false, NULL);		\
	}  while (0)
#define split_huge_pud(__vma, __pud, __address)				\
	do {								\
		pud_t *____pud = (__pud);				\
		if (pud_trans_huge(*____pud)				\
					|| pud_devmap(*____pud))	\
			__split_huge_pud(__vma, __pud, __address);	\
	}  while (0)
#define transparent_hugepage_flags 0UL
#define transparent_hugepage_use_zero_page()				\
	(transparent_hugepage_flags &					\
	 (1<<TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_FLAG))
#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
#define ACL_DONT_CACHE ((void *)(-3))
#define ACL_NOT_CACHED ((void *)(-1))
#define CHRDEV_MAJOR_DYN_END 234
#define CHRDEV_MAJOR_DYN_EXT_END 384
#define CHRDEV_MAJOR_DYN_EXT_START 511
#define CHRDEV_MAJOR_MAX 512
#define DEFINE_SIMPLE_ATTRIBUTE(__fops, __get, __set, __fmt)		\
static int __fops ## _open(struct inode *inode, struct file *file)	\
{									\
	__simple_attr_check_format(__fmt, 0ull);			\
	return simple_attr_open(inode, file, __get, __set, __fmt);	\
}									\
static const struct file_operations __fops = {				\
	.owner	 = THIS_MODULE,						\
	.open	 = __fops ## _open,					\
	.release = simple_attr_release,					\
	.read	 = simple_attr_read,					\
	.write	 = simple_attr_write,					\
	.llseek	 = generic_file_llseek,					\
}
#define FASYNC_MAGIC 0x4601
#define FILESYSTEM_MAX_STACK_DEPTH 2
#define FILE_LOCK_DEFERRED 1
#define FL_CLOSE_POSIX (FL_POSIX | FL_CLOSE)
#define FMODE_32BITHASH         ((__force fmode_t)0x200)
#define FMODE_64BITHASH         ((__force fmode_t)0x400)
#define FMODE_CAN_READ          ((__force fmode_t)0x20000)
#define FMODE_CAN_WRITE         ((__force fmode_t)0x40000)
#define FS_ALLOW_IDMAP         32      
#define INT_LIMIT(x)	(~((x)1 << (sizeof(x)*8 - 1)))
#define IS_APPEND(inode)	((inode)->i_flags & S_APPEND)
#define IS_AUTOMOUNT(inode)	((inode)->i_flags & S_AUTOMOUNT)
#define IS_CASEFOLDED(inode)	((inode)->i_flags & S_CASEFOLD)
#define IS_DAX(inode)		((inode)->i_flags & S_DAX)
#define IS_DEADDIR(inode)	((inode)->i_flags & S_DEAD)
#define IS_DIRSYNC(inode)	(__IS_FLG(inode, SB_SYNCHRONOUS|SB_DIRSYNC) || \
					((inode)->i_flags & (S_SYNC|S_DIRSYNC)))
#define IS_ENCRYPTED(inode)	((inode)->i_flags & S_ENCRYPTED)
#define IS_IMA(inode)		((inode)->i_flags & S_IMA)
#define IS_IMMUTABLE(inode)	((inode)->i_flags & S_IMMUTABLE)
#define IS_I_VERSION(inode)	__IS_FLG(inode, SB_I_VERSION)
#define IS_MANDLOCK(inode)	__IS_FLG(inode, SB_MANDLOCK)
#define IS_NOATIME(inode)	__IS_FLG(inode, SB_RDONLY|SB_NOATIME)
#define IS_NOCMTIME(inode)	((inode)->i_flags & S_NOCMTIME)
#define IS_NOQUOTA(inode)	((inode)->i_flags & S_NOQUOTA)
#define IS_NOSEC(inode)		((inode)->i_flags & S_NOSEC)
#define IS_POSIXACL(inode)	__IS_FLG(inode, SB_POSIXACL)
#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)
#define IS_RDONLY(inode)	sb_rdonly((inode)->i_sb)
#define IS_SWAPFILE(inode)	((inode)->i_flags & S_SWAPFILE)
#define IS_SYNC(inode)		(__IS_FLG(inode, SB_SYNCHRONOUS) || \
					((inode)->i_flags & S_SYNC))
#define IS_VERITY(inode)	((inode)->i_flags & S_VERITY)
#define IS_WHITEOUT(inode)	(S_ISCHR(inode->i_mode) && \
				 (inode)->i_rdev == WHITEOUT_DEV)
#define I_DIRTY (I_DIRTY_INODE | I_DIRTY_PAGES)
#define I_DIRTY_ALL (I_DIRTY | I_DIRTY_TIME)
#define I_DIRTY_INODE (I_DIRTY_SYNC | I_DIRTY_DATASYNC)
#define MAX_LFS_FILESIZE 	((loff_t)LLONG_MAX)
#define MAX_RW_COUNT (INT_MAX & PAGE_MASK)
#define MODULE_ALIAS_FS(NAME) MODULE_ALIAS("fs-" NAME)
#define NOMMU_VMFLAGS \
	(NOMMU_MAP_READ | NOMMU_MAP_WRITE | NOMMU_MAP_EXEC)
#define OPEN_FMODE(flag) ((__force fmode_t)(((flag + 1) & O_ACCMODE) | \
					    (flag & __FMODE_NONOTIFY)))
#define SB_FORCE    	(1<<27)
#define SB_FREEZE_LEVELS (SB_FREEZE_COMPLETE - 1)
#define SB_I_STABLE_WRITES 0x00000008	
#define SB_SUBMOUNT     (1<<26)
#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - sizeof(struct simple_transaction_argresp))
#define WHITEOUT_DEV 0
#define WHITEOUT_MODE 0

#define __IS_FLG(inode, flg)	((inode)->i_sb->s_flags & (flg))

#define __getname()		kmem_cache_alloc(names_cachep, GFP_KERNEL)
#define __putname(name)		kmem_cache_free(names_cachep, (void *)(name))
#define __sb_writers_acquired(sb, lev)	\
	percpu_rwsem_acquire(&(sb)->s_writers.rw_sem[(lev)-1], 1, _THIS_IP_)
#define __sb_writers_release(sb, lev)	\
	percpu_rwsem_release(&(sb)->s_writers.rw_sem[(lev)-1], 1, _THIS_IP_)
#define buffer_migrate_page NULL
#define buffer_migrate_page_norefs NULL
#define compat_ptr_ioctl NULL
#define file_count(x)	atomic_long_read(&(x)->f_count)
#define fops_get(fops) \
	(((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
#define fops_put(fops) \
	do { if (fops) module_put((fops)->owner); } while(0)
#define get_file_rcu(x) get_file_rcu_many((x), 1)
#define get_file_rcu_many(x, cnt)	\
	atomic_long_add_unless(&(x)->f_count, (cnt), 0)
#define i_size_ordered_init(inode) seqcount_init(&inode->i_size_seqcount)
#define locks_inode(f) file_inode(f)
#define replace_fops(f, fops) \
	do {	\
		struct file *__file = (f); \
		fops_put(__file->f_op); \
		BUG_ON(!(__file->f_op = (fops))); \
	} while(0)
#define sb_has_strict_encoding(sb) \
	(sb->s_encoding_flags & SB_ENC_STRICT_MODE_FL)
#define special_file(m) (S_ISCHR(m)||S_ISBLK(m)||S_ISFIFO(m)||S_ISSOCK(m))

#define DQF_GETINFO_MASK (DQF_ROOT_SQUASH | DQF_SYS_FILE)
#define DQF_INFO_DIRTY (1 << DQF_INFO_DIRTY_B)	
#define DQF_SETINFO_MASK DQF_ROOT_SQUASH
#define DQUOT_DEL_ALLOC max(V1_DEL_ALLOC, V2_DEL_ALLOC)
#define DQUOT_DEL_REWRITE max(V1_DEL_REWRITE, V2_DEL_REWRITE)
#define DQUOT_INIT_ALLOC max(V1_INIT_ALLOC, V2_INIT_ALLOC)
#define DQUOT_INIT_REWRITE max(V1_INIT_REWRITE, V2_INIT_REWRITE)
#define INIT_QUOTA_MODULE_NAMES {\
	{QFMT_VFS_OLD, "quota_v1",\
	{QFMT_VFS_V0, "quota_v2",\
	{QFMT_VFS_V1, "quota_v2",\
	{0, NULL}}
#define QC_ACCT_MASK (QC_SPACE | QC_INO_COUNT | QC_RT_SPACE)
#define QC_LIMIT_MASK (QC_INO_SOFT | QC_INO_HARD | QC_SPC_SOFT | QC_SPC_HARD | \
		       QC_RT_SPC_SOFT | QC_RT_SPC_HARD)
#define QC_TIMER_MASK (QC_SPC_TIMER | QC_INO_TIMER | QC_RT_SPC_TIMER)
#define QC_WARNS_MASK (QC_SPC_WARNS | QC_INO_WARNS | QC_RT_SPC_WARNS)
#define QTYPE_MASK_GRP (1 << GRPQUOTA)
#define QTYPE_MASK_PRJ (1 << PRJQUOTA)
#define QTYPE_MASK_USR (1 << USRQUOTA)

#define GRPQUOTA  1		
#define INITQFNAMES { \
	"user",     \
	"group",    \
	"project",  \
	"undefined", \
};
#define MAXQUOTAS 3
#define PRJQUOTA  2		
#define QCMD(cmd, type)  (((cmd) << SUBCMDSHIFT) | ((type) & SUBCMDMASK))
#define QFMT_OCFS2 3
#define QIF_DQBLKSIZE (1 << QIF_DQBLKSIZE_BITS)
#define QIF_DQBLKSIZE_BITS 10
#define QUOTA_NL_A_MAX (__QUOTA_NL_A_MAX - 1)
#define QUOTA_NL_BHARDBELOW 9		
#define QUOTA_NL_BHARDWARN 4		
#define QUOTA_NL_BSOFTBELOW 10		
#define QUOTA_NL_BSOFTLONGWARN 5	
#define QUOTA_NL_BSOFTWARN 6		
#define QUOTA_NL_C_MAX (__QUOTA_NL_C_MAX - 1)
#define QUOTA_NL_IHARDBELOW 7		
#define QUOTA_NL_IHARDWARN 1		
#define QUOTA_NL_ISOFTBELOW 8		
#define QUOTA_NL_ISOFTLONGWARN 2 	
#define QUOTA_NL_ISOFTWARN 3		
#define QUOTA_NL_NOWARN 0
#define Q_GETFMT   0x800004	
#define Q_GETINFO  0x800005	
#define Q_GETNEXTQUOTA 0x800009	
#define Q_GETQUOTA 0x800007	
#define Q_QUOTAOFF 0x800003	
#define Q_QUOTAON  0x800002	
#define Q_SETINFO  0x800006	
#define Q_SETQUOTA 0x800008	
#define Q_SYNC     0x800001	
#define SUBCMDMASK  0x00ff
#define SUBCMDSHIFT 8
#define USRQUOTA  0		

#define INVALID_PROJID KPROJIDT_INIT(-1)
#define KPROJIDT_INIT(value) (kprojid_t){ value }
#define OVERFLOW_PROJID 65534

#define V2_DEL_ALLOC QTREE_DEL_ALLOC
#define V2_DEL_REWRITE QTREE_DEL_REWRITE
#define V2_INIT_ALLOC QTREE_INIT_ALLOC
#define V2_INIT_REWRITE QTREE_INIT_REWRITE

#define QTREE_DEL_ALLOC 0
#define QTREE_DEL_REWRITE 6
#define QTREE_INIT_ALLOC 4
#define QTREE_INIT_REWRITE 2

#define V1_DEL_ALLOC 0
#define V1_DEL_REWRITE 2
#define V1_INIT_ALLOC 1
#define V1_INIT_REWRITE 1


#define percpu_counter_init(fbc, value, gfp)				\
	({								\
		static struct lock_class_key __key;			\
									\
		__percpu_counter_init(fbc, value, gfp, &__key);		\
	})
#define BLKALIGNOFF _IO(0x12,122)
#define BLKBSZGET  _IOR(0x12,112,size_t)
#define BLKBSZSET  _IOW(0x12,113,size_t)
#define BLKDISCARD _IO(0x12,119)
#define BLKDISCARDZEROES _IO(0x12,124)
#define BLKFLSBUF  _IO(0x12,97)	
#define BLKFRAGET  _IO(0x12,101)
#define BLKFRASET  _IO(0x12,100)
#define BLKGETDISKSEQ _IOR(0x12,128,__u64)
#define BLKGETSIZE _IO(0x12,96)	
#define BLKGETSIZE64 _IOR(0x12,114,size_t)	
#define BLKIOMIN _IO(0x12,120)
#define BLKIOOPT _IO(0x12,121)
#define BLKPBSZGET _IO(0x12,123)
#define BLKRAGET   _IO(0x12,99)	
#define BLKRASET   _IO(0x12,98)	
#define BLKROGET   _IO(0x12,94)	
#define BLKROSET   _IO(0x12,93)	
#define BLKROTATIONAL _IO(0x12,126)
#define BLKRRPART  _IO(0x12,95)	
#define BLKSECDISCARD _IO(0x12,125)
#define BLKSECTGET _IO(0x12,103)
#define BLKSECTSET _IO(0x12,102)
#define BLKSSZGET  _IO(0x12,104)
#define BLKTRACESETUP _IOWR(0x12,115,struct blk_user_trace_setup)
#define BLKTRACESTART _IO(0x12,116)
#define BLKTRACESTOP _IO(0x12,117)
#define BLKTRACETEARDOWN _IO(0x12,118)
#define BLKZEROOUT _IO(0x12,127)
#define BLOCK_SIZE (1<<BLOCK_SIZE_BITS)
#define BLOCK_SIZE_BITS 10
#define BMAP_IOCTL 1		
#define FIGETBSZ   _IO(0x00,2)	
#define FSLABEL_MAX 256	
#define INR_OPEN_CUR 1024	
#define INR_OPEN_MAX 4096	
#define NR_FILE  8192	

#define MNT_ATIME_MASK (MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME )
#define MNT_INTERNAL_FLAGS (MNT_SHARED | MNT_WRITE_HOLD | MNT_INTERNAL | \
			    MNT_DOOMED | MNT_SYNC_UMOUNT | MNT_MARKED | \
			    MNT_CURSOR)
#define MNT_USER_SETTABLE_MASK  (MNT_NOSUID | MNT_NODEV | MNT_NOEXEC \
				 | MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME \
				 | MNT_READONLY | MNT_NOSYMFOLLOW)

#define FSTR_INIT(n, l)		{ .name = n, .len = l }
#define FSTR_TO_QSTR(f)		QSTR_INIT((f)->name, (f)->len)
#define FS_CFLG_OWN_PAGES (1U << 1)

#define fname_len(p)		((p)->disk_name.len)
#define fname_name(p)		((p)->disk_name.name)
#define FSCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF   0x00000001

#define ARCH_KMALLOC_MINALIGN ARCH_DMA_MINALIGN
#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
#define KMALLOC_MIN_SIZE ARCH_DMA_MINALIGN
#define KMALLOC_SHIFT_LOW ilog2(ARCH_DMA_MINALIGN)
#define KMEM_CACHE(__struct, __flags)					\
		kmem_cache_create(#__struct, sizeof(struct __struct),	\
			__alignof__(struct __struct), (__flags), NULL)
#define KMEM_CACHE_USERCOPY(__struct, __flags, __field)			\
		kmem_cache_create_usercopy(#__struct,			\
			sizeof(struct __struct),			\
			__alignof__(struct __struct), (__flags),	\
			offsetof(struct __struct, __field),		\
			sizeof_field(struct __struct, __field), NULL)
#define SLAB_OBJ_MIN_SIZE      (KMALLOC_MIN_SIZE < 16 ? \
                               (KMALLOC_MIN_SIZE) : 16)
#define ZERO_OR_NULL_PTR(x) ((unsigned long)(x) <= \
				(unsigned long)ZERO_SIZE_PTR)
#define ZERO_SIZE_PTR ((void *)16)
#define __assume_kmalloc_alignment __assume_aligned(ARCH_KMALLOC_MINALIGN)
#define __assume_page_alignment __assume_aligned(PAGE_SIZE)
#define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MINALIGN)
#define kmalloc_index(s) __kmalloc_index(s, true)
#define kmalloc_node_track_caller(size, flags, node) \
	__kmalloc_node_track_caller(size, flags, node, \
			_RET_IP_)
#define kmalloc_track_caller(size, flags) \
	__kmalloc_track_caller(size, flags, _RET_IP_)
#define KASAN_SHADOW_INIT 0xFE
#define PTE_HWTABLE_PTRS 0

#define MAX_POSSIBLE_PHYSMEM_BITS 32
#define MAX_PTRS_PER_P4D PTRS_PER_P4D
#define MAX_PTRS_PER_PMD PTRS_PER_PMD
#define MAX_PTRS_PER_PTE PTRS_PER_PTE
#define MAX_PTRS_PER_PUD PTRS_PER_PUD
# define PAGE_KERNEL_EXEC PAGE_KERNEL
# define PAGE_KERNEL_RO PAGE_KERNEL


#define arch_enter_lazy_mmu_mode()	do {} while (0)
#define arch_flush_lazy_mmu_mode()	do {} while (0)
#define arch_leave_lazy_mmu_mode()	do {} while (0)
#define arch_needs_pgtable_deposit() (false)
#define arch_start_context_switch(prev)	do {} while (0)
#define flush_pmd_tlb_range(vma, addr, end)	flush_tlb_range(vma, addr, end)
#define flush_pud_tlb_range(vma, addr, end)	flush_tlb_range(vma, addr, end)
#define flush_tlb_fix_spurious_fault(vma, address) flush_tlb_page(vma, address)
#define has_transparent_hugepage() 1
#define mm_p4d_folded(mm)	__is_defined(__PAGETABLE_P4D_FOLDED)
#define mm_pmd_folded(mm)	__is_defined(__PAGETABLE_PMD_FOLDED)
#define mm_pud_folded(mm)	__is_defined(__PAGETABLE_PUD_FOLDED)
#define move_pte(pte, prot, old_addr, new_addr)	(pte)
#define my_zero_pfn(addr)	page_to_pfn(ZERO_PAGE(addr))
#define p4d_access_permitted(p4d, write) \
	(p4d_present(p4d) && (!(write) || p4d_write(p4d)))
#define p4d_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + P4D_SIZE) & P4D_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#define p4d_clear_bad(p4d)        do { } while (0)
#define p4d_leaf(x)	0
#define p4d_leaf_size(x) P4D_SIZE
#define p4d_offset_lockless(pgdp, pgd, address) p4d_offset(&(pgd), address)
#define pgd_access_permitted(pgd, write) \
	(pgd_present(pgd) && (!(write) || pgd_write(pgd)))
#define pgd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PGDIR_SIZE) & PGDIR_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pgd_leaf(x)	0
#define pgd_leaf_size(x) (1ULL << PGDIR_SHIFT)
#define pgd_offset(mm, address)		pgd_offset_pgd((mm)->pgd, (address))
#define pgd_offset_gate(mm, addr)	pgd_offset(mm, addr)
#define pgd_offset_k(address)		pgd_offset(&init_mm, (address))
#define pgprot_decrypted(prot)	(prot)
#define pgprot_device pgprot_noncached
#define pgprot_encrypted(prot)	(prot)
#define pgprot_mhp(prot)	(prot)
#define pgprot_modify pgprot_modify
#define pgprot_noncached(prot)	(prot)
#define pgprot_nx(prot)	(prot)
#define pgprot_writecombine pgprot_noncached
#define pgprot_writethrough pgprot_noncached
#define pmd_access_permitted(pmd, write) \
	(pmd_present(pmd) && (!(write) || pmd_write(pmd)))
#define pmd_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PMD_SIZE) & PMD_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#define pmd_clear_savedwrite pmd_wrprotect
#define pmd_index pmd_index
#define pmd_leaf(x)	0
#define pmd_leaf_size(x) PMD_SIZE
#define pmd_mk_savedwrite pmd_mkwrite
#define pmd_offset pmd_offset
#define pmd_offset_lockless(pudp, pud, address) pmd_offset(&(pud), address)
#define pmd_pgtable(pmd) pmd_page(pmd)
#define pmd_savedwrite pmd_write
#define pmdp_collapse_flush pmdp_collapse_flush
#define pte_access_permitted(pte, write) \
	(pte_present(pte) && (!(write) || pte_write(pte)))
# define pte_accessible(mm, pte)	((void)(pte), 1)
#define pte_clear_savedwrite pte_wrprotect
#define pte_leaf_size(x) PAGE_SIZE
#define pte_mk_savedwrite pte_mkwrite
#define pte_offset_kernel pte_offset_kernel
#define pte_offset_map(dir, address)	pte_offset_kernel((dir), (address))
#define pte_savedwrite pte_write
#define pte_unmap(pte) ((void)(pte))	
#define pud_access_permitted(pud, write) \
	(pud_present(pud) && (!(write) || pud_write(pud)))
#define pud_addr_end(addr, end)						\
({	unsigned long __boundary = ((addr) + PUD_SIZE) & PUD_MASK;	\
	(__boundary - 1 < (end) - 1)? __boundary: (end);		\
})
#define pud_clear_bad(p4d)        do { } while (0)
#define pud_index pud_index
#define pud_leaf(x)	0
#define pud_leaf_size(x) PUD_SIZE
#define pud_offset pud_offset
#define pud_offset_lockless(p4dp, p4d, address) pud_offset(&(p4d), address)
#define set_p4d_safe(p4dp, p4d) \
({ \
	WARN_ON_ONCE(p4d_present(*p4dp) && !p4d_same(*p4dp, p4d)); \
	set_p4d(p4dp, p4d); \
})
#define set_pgd_safe(pgdp, pgd) \
({ \
	WARN_ON_ONCE(pgd_present(*pgdp) && !pgd_same(*pgdp, pgd)); \
	set_pgd(pgdp, pgd); \
})
#define set_pmd_safe(pmdp, pmd) \
({ \
	WARN_ON_ONCE(pmd_present(*pmdp) && !pmd_same(*pmdp, pmd)); \
	set_pmd(pmdp, pmd); \
})
#define set_pte_safe(ptep, pte) \
({ \
	WARN_ON_ONCE(pte_present(*ptep) && !pte_same(*ptep, pte)); \
	set_pte(ptep, pte); \
})
#define set_pud_safe(pudp, pud) \
({ \
	WARN_ON_ONCE(pud_present(*pudp) && !pud_same(*pudp, pud)); \
	set_pud(pudp, pud); \
})



#define __task_cred(task)	\
	rcu_dereference((task)->real_cred)
#define current_cap()		(current_cred_xxx(cap_effective))
#define current_cred() \
	rcu_dereference_protected(current->cred, 1)
#define current_cred_xxx(xxx)			\
({						\
	current_cred()->xxx;			\
})
#define current_egid()		(current_cred_xxx(egid))
#define current_euid()		(current_cred_xxx(euid))
#define current_euid_egid(_euid, _egid)		\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_euid) = __cred->euid;		\
	*(_egid) = __cred->egid;		\
} while(0)
#define current_fsgid() 	(current_cred_xxx(fsgid))
#define current_fsuid() 	(current_cred_xxx(fsuid))
#define current_fsuid_fsgid(_fsuid, _fsgid)	\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_fsuid) = __cred->fsuid;		\
	*(_fsgid) = __cred->fsgid;		\
} while(0)
#define current_gid()		(current_cred_xxx(gid))
#define current_real_cred() \
	rcu_dereference_protected(current->real_cred, 1)
#define current_sgid()		(current_cred_xxx(sgid))
#define current_suid()		(current_cred_xxx(suid))
#define current_ucounts()	(current_cred_xxx(ucounts))
#define current_uid()		(current_cred_xxx(uid))
#define current_uid_gid(_uid, _gid)		\
do {						\
	const struct cred *__cred;		\
	__cred = current_cred();		\
	*(_uid) = __cred->uid;			\
	*(_gid) = __cred->gid;			\
} while(0)
#define current_user()		(current_cred_xxx(user))
#define current_user_ns()	(current_cred_xxx(user_ns))
#define get_current_cred()				\
	(get_cred(current_cred()))
#define get_current_groups()				\
({							\
	struct group_info *__groups;			\
	const struct cred *__cred;			\
	__cred = current_cred();			\
	__groups = get_group_info(__cred->group_info);	\
	__groups;					\
})
#define get_current_user()				\
({							\
	struct user_struct *__u;			\
	const struct cred *__cred;			\
	__cred = current_cred();			\
	__u = get_uid(__cred->user);			\
	__u;						\
})
#define put_group_info(group_info)			\
do {							\
	if (atomic_dec_and_test(&(group_info)->usage))	\
		groups_free(group_info);		\
} while (0)
#define task_cred_xxx(task, xxx)			\
({							\
	__typeof__(((struct cred *)NULL)->xxx) ___val;	\
	rcu_read_lock();				\
	___val = __task_cred((task))->xxx;		\
	rcu_read_unlock();				\
	___val;						\
})
#define task_euid(task)		(task_cred_xxx((task), euid))
#define task_ucounts(task)	(task_cred_xxx((task), ucounts))
#define task_uid(task)		(task_cred_xxx((task), uid))
#define validate_creds(cred)				\
do {							\
	__validate_creds((cred), "__FILE__", "__LINE__");	\
} while(0)
#define validate_process_creds()				\
do {								\
	__validate_process_creds(current, "__FILE__", "__LINE__");	\
} while(0)
#define INIT_USER (&root_user)


#define dereference_key_locked(KEY)					\
	(rcu_dereference_protected((KEY)->payload.rcu_data0,		\
				   rwsem_is_locked(&((struct key *)(KEY))->sem)))
#define dereference_key_rcu(KEY)					\
	(rcu_dereference((KEY)->payload.rcu_data0))
#define is_key_possessed(k)		0
#define key_free_user_ns(ns)		do { } while(0)
#define key_fsgid_changed(c)		do { } while(0)
#define key_fsuid_changed(c)		do { } while(0)
#define key_get(k) 			({ NULL; })
#define key_init()			do { } while(0)
#define key_invalidate(k)		do { } while(0)
#define key_put(k)			do { } while(0)
#define key_ref_put(k)			do { } while(0)
#define key_ref_to_ptr(k)		NULL
#define key_remove_domain(d)		do { } while(0)
#define key_revoke(k)			do { } while(0)
#define key_serial(k)			0
#define key_validate(k)			0
#define make_key_ref(k, p)		NULL
#define rcu_assign_keypointer(KEY, PAYLOAD)				\
do {									\
	rcu_assign_pointer((KEY)->payload.rcu_data0, (PAYLOAD));	\
} while (0)
#define request_key_net(type, description, net, callout_info) \
	request_key_tag(type, description, net->key_domain, callout_info)
#define request_key_net_rcu(type, description, net) \
	request_key_rcu(type, description, net->key_domain)
#define ASSOC_ARRAY_KEY_CHUNK_SIZE BITS_PER_LONG 

#define DEFINE_CTL_TABLE_POLL(name)					\
	struct ctl_table_poll name = __CTL_TABLE_POLL_INITIALIZER(name)

#define __CTL_TABLE_POLL_INITIALIZER(name) {				\
	.event = ATOMIC_INIT(0),					\
	.wait = __WAIT_QUEUE_HEAD_INITIALIZER(name.wait) }
#define CTL_MAXNAME 10		

#define CAP_BOP_ALL(c, a, b, OP)                                    \
do {                                                                \
	unsigned __capi;                                            \
	CAP_FOR_EACH_U32(__capi) {                                  \
		c.cap[__capi] = a.cap[__capi] OP b.cap[__capi];     \
	}                                                           \
} while (0)
# define CAP_EMPTY_SET    ((kernel_cap_t){{ 0, 0 }})
#define CAP_FOR_EACH_U32(__capi)  \
	for (__capi = 0; __capi < _KERNEL_CAPABILITY_U32S; ++__capi)
# define CAP_FS_MASK_B0     (CAP_TO_MASK(CAP_CHOWN)		\
			    | CAP_TO_MASK(CAP_MKNOD)		\
			    | CAP_TO_MASK(CAP_DAC_OVERRIDE)	\
			    | CAP_TO_MASK(CAP_DAC_READ_SEARCH)	\
			    | CAP_TO_MASK(CAP_FOWNER)		\
			    | CAP_TO_MASK(CAP_FSETID))
# define CAP_FS_MASK_B1     (CAP_TO_MASK(CAP_MAC_OVERRIDE))
# define CAP_FS_SET       ((kernel_cap_t){{ CAP_FS_MASK_B0 \
				    | CAP_TO_MASK(CAP_LINUX_IMMUTABLE), \
				    CAP_FS_MASK_B1 } })
# define CAP_FULL_SET     ((kernel_cap_t){{ ~0, CAP_LAST_U32_VALID_MASK }})
# define CAP_NFSD_SET     ((kernel_cap_t){{ CAP_FS_MASK_B0 \
				    | CAP_TO_MASK(CAP_SYS_RESOURCE), \
				    CAP_FS_MASK_B1 } })
#define CAP_UOP_ALL(c, a, OP)                                       \
do {                                                                \
	unsigned __capi;                                            \
	CAP_FOR_EACH_U32(__capi) {                                  \
		c.cap[__capi] = OP a.cap[__capi];                   \
	}                                                           \
} while (0)
#define _KERNEL_CAPABILITY_U32S    _LINUX_CAPABILITY_U32S_3
#define _KERNEL_CAPABILITY_VERSION _LINUX_CAPABILITY_VERSION_3
#define _KERNEL_CAP_T_SIZE     (sizeof(kernel_cap_t))

#define _USER_CAP_HEADER_SIZE  (sizeof(struct __user_cap_header_struct))
# define cap_clear(c)         do { (c) = __cap_empty_set; } while (0)
#define cap_lower(c, flag)  ((c).cap[CAP_TO_INDEX(flag)] &= ~CAP_TO_MASK(flag))
#define cap_raise(c, flag)  ((c).cap[CAP_TO_INDEX(flag)] |= CAP_TO_MASK(flag))
#define cap_raised(c, flag) ((c).cap[CAP_TO_INDEX(flag)] & CAP_TO_MASK(flag))
#define CAP_AUDIT_CONTROL    30
#define CAP_AUDIT_WRITE      29
#define CAP_BLOCK_SUSPEND    36
#define CAP_CHOWN            0
#define CAP_DAC_OVERRIDE     1
#define CAP_DAC_READ_SEARCH  2
#define CAP_FOWNER           3
#define CAP_FSETID           4
#define CAP_IPC_LOCK         14
#define CAP_IPC_OWNER        15
#define CAP_KILL             5
#define CAP_LAST_CAP         CAP_CHECKPOINT_RESTORE
#define CAP_LEASE            28
#define CAP_LINUX_IMMUTABLE  9
#define CAP_MAC_ADMIN        33
#define CAP_MAC_OVERRIDE     32
#define CAP_MKNOD            27
#define CAP_NET_ADMIN        12
#define CAP_NET_BIND_SERVICE 10
#define CAP_NET_BROADCAST    11
#define CAP_NET_RAW          13
#define CAP_SETGID           6
#define CAP_SETPCAP          8
#define CAP_SETUID           7
#define CAP_SYSLOG           34
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
#define CAP_TO_INDEX(x)     ((x) >> 5)        
#define CAP_TO_MASK(x)      (1 << ((x) & 31)) 
#define CAP_WAKE_ALARM            35
#define VFS_CAP_U32             VFS_CAP_U32_3
#define VFS_CAP_U32_1           1
#define VFS_CAP_U32_2           2
#define VFS_CAP_U32_3           2
#define XATTR_CAPS_SZ           XATTR_CAPS_SZ_3
#define XATTR_CAPS_SZ_1         (sizeof(__le32)*(1 + 2*VFS_CAP_U32_1))
#define XATTR_CAPS_SZ_2         (sizeof(__le32)*(1 + 2*VFS_CAP_U32_2))
#define XATTR_CAPS_SZ_3         (sizeof(__le32)*(2 + 2*VFS_CAP_U32_3))
#define _LINUX_CAPABILITY_U32S     _LINUX_CAPABILITY_U32S_1
#define _LINUX_CAPABILITY_U32S_1     1
#define _LINUX_CAPABILITY_U32S_2     2
#define _LINUX_CAPABILITY_U32S_3     2
#define _LINUX_CAPABILITY_VERSION  _LINUX_CAPABILITY_VERSION_1
#define _LINUX_CAPABILITY_VERSION_1  0x19980330
#define _LINUX_CAPABILITY_VERSION_2  0x20071026  
#define _LINUX_CAPABILITY_VERSION_3  0x20080522

#define cap_valid(x) ((x) >= 0 && (x) <= CAP_LAST_CAP)
#define S_DT(mode)	(((mode) & S_IFMT) >> S_DT_SHIFT)


#define IOPRIO_PRIO_CLASS(ioprio)	\
	(((ioprio) >> IOPRIO_CLASS_SHIFT) & IOPRIO_CLASS_MASK)
#define IOPRIO_PRIO_DATA(ioprio)	((ioprio) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data)	\
	((((class) & IOPRIO_CLASS_MASK) << IOPRIO_CLASS_SHIFT) | \
	 ((data) & IOPRIO_PRIO_MASK))



# define rt_mutex_adjust_pi(p)		do { } while (0)

#define DEFINE_DELAYED_CALL(name) struct delayed_call name = {NULL, NULL}

#define DEFINE_PERCPU_RWSEM(name)		\
	__DEFINE_PERCPU_RWSEM(name, )
#define DEFINE_STATIC_PERCPU_RWSEM(name)	\
	__DEFINE_PERCPU_RWSEM(name, static)

#define __DEFINE_PERCPU_RWSEM(name, is_static)				\
static DEFINE_PER_CPU(unsigned int, __percpu_rwsem_rc_##name);		\
is_static struct percpu_rw_semaphore name = {				\
	.rss = __RCU_SYNC_INITIALIZER(name.rss),			\
	.read_count = &__percpu_rwsem_rc_##name,			\
	.writer = __RCUWAIT_INITIALIZER(name.writer),			\
	.waiters = __WAIT_QUEUE_HEAD_INITIALIZER(name.waiters),		\
	.block = ATOMIC_INIT(0),					\
	__PERCPU_RWSEM_DEP_MAP_INIT(name)				\
}
#define __PERCPU_RWSEM_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname },
#define percpu_init_rwsem(sem)					\
({								\
	static struct lock_class_key rwsem_key;			\
	__percpu_init_rwsem(sem, #sem, &rwsem_key);		\
})
#define percpu_rwsem_assert_held(sem)	lockdep_assert_held(sem)
#define percpu_rwsem_is_held(sem)	lockdep_is_held(sem)

#define __RCU_SYNC_INITIALIZER(name) {					\
		.gp_state = 0,						\
		.gp_count = 0,						\
		.gp_wait = __WAIT_QUEUE_HEAD_INITIALIZER(name.gp_wait),	\
	}

#define __RCUWAIT_INITIALIZER(name)		\
	{ .task = NULL, }
#define rcuwait_wait_event(w, condition, state)				\
({									\
	int __ret = 0;							\
	prepare_to_rcuwait(w);						\
	for (;;) {							\
									\
		set_current_state(state);				\
		if (condition)						\
			break;						\
									\
		if (signal_pending_state(state, current)) {		\
			__ret = -EINTR;					\
			break;						\
		}							\
									\
		schedule();						\
	}								\
	finish_rcuwait(w);						\
	__ret;								\
})
#define INIT_CPUTIME_ATOMIC \
	(struct task_cputime_atomic) {				\
		.utime = ATOMIC64_INIT(0),			\
		.stime = ATOMIC64_INIT(0),			\
		.sum_exec_runtime = ATOMIC64_INIT(0),		\
	}
#define SEND_SIG_NOINFO ((struct kernel_siginfo *) 0)
#define SIGNAL_STOP_MASK (SIGNAL_CLD_MASK | SIGNAL_STOP_STOPPED | \
			  SIGNAL_STOP_CONTINUED)

# define ___ARCH_SI_IA64(_a1, _a2, _a3) , _a1, _a2, _a3
#define __for_each_thread(signal, t)	\
	list_for_each_entry_rcu(t, &(signal)->thread_head, thread_node)
#define delay_group_leader(p) \
		(thread_group_leader(p) && !thread_group_empty(p))
#define do_each_thread(g, t) \
	for (g = t = &init_task ; (g = t = next_task(g)) != &init_task ; ) do
#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )
#define for_each_process_thread(p, t)	\
	for_each_process(p) for_each_thread(p, t)
#define for_each_thread(p, t)		\
	__for_each_thread((p)->signal, t)
#define next_task(p) \
	list_entry_rcu((p)->tasks.next, struct task_struct, tasks)
#define tasklist_empty() \
	list_empty(&init_task.tasks)
#define while_each_thread(g, t) \
	while ((t = next_thread(t)) != g)
#define CLONE_LEGACY_FLAGS 0xffffffffULL

# define arch_task_struct_size (sizeof(struct task_struct))
#define sched_exec()   {}

#define faulthandler_disabled() (pagefault_disabled() || in_atomic())
#define get_kernel_nofault(val, ptr) ({				\
	const typeof(val) *__gk_ptr = (ptr);			\
	copy_from_kernel_nofault(&(val), __gk_ptr, sizeof(val));\
})
#define uaccess_kernel()		(false)
#define unsafe_copy_from_user(d,s,l,e) unsafe_op_wrap(__copy_from_user(d,s,l),e)
#define unsafe_copy_to_user(d,s,l,e) unsafe_op_wrap(__copy_to_user(d,s,l),e)
#define unsafe_get_user(x,p,e) unsafe_op_wrap(__get_user(x,p),e)
#define unsafe_op_wrap(op, err) do { if (unlikely(op)) goto err; } while (0)
#define unsafe_put_user(x,p,e) unsafe_op_wrap(__put_user(x,p),e)
#define user_access_begin(ptr,len) access_ok(ptr, len)
#define user_access_end() do { } while (0)
#define user_addr_max()			(TASK_SIZE_MAX)
#define user_read_access_begin user_access_begin
#define user_read_access_end user_access_end
#define user_write_access_begin user_access_begin
#define user_write_access_end user_access_end

#define JOBCTL_STOP_DEQUEUED_BIT 16	

#define SIG_KERNEL_COREDUMP_MASK (\
        rt_sigmask(SIGQUIT)   |  rt_sigmask(SIGILL)    | \
	rt_sigmask(SIGTRAP)   |  rt_sigmask(SIGABRT)   | \
        rt_sigmask(SIGFPE)    |  rt_sigmask(SIGSEGV)   | \
	rt_sigmask(SIGBUS)    |  rt_sigmask(SIGSYS)    | \
        rt_sigmask(SIGXCPU)   |  rt_sigmask(SIGXFSZ)   | \
	SIGEMT_MASK				       )
#define SIG_KERNEL_IGNORE_MASK (\
        rt_sigmask(SIGCONT)   |  rt_sigmask(SIGCHLD)   | \
	rt_sigmask(SIGWINCH)  |  rt_sigmask(SIGURG)    )
#define SIG_KERNEL_ONLY_MASK (\
	rt_sigmask(SIGKILL)   |  rt_sigmask(SIGSTOP))
#define SIG_KERNEL_STOP_MASK (\
	rt_sigmask(SIGSTOP)   |  rt_sigmask(SIGTSTP)   | \
	rt_sigmask(SIGTTIN)   |  rt_sigmask(SIGTTOU)   )
#define SIG_KTHREAD ((__force __sighandler_t)2)
#define SIG_KTHREAD_KERNEL ((__force __sighandler_t)3)
#define SIG_SPECIFIC_SICODES_MASK (\
	rt_sigmask(SIGILL)    |  rt_sigmask(SIGFPE)    | \
	rt_sigmask(SIGSEGV)   |  rt_sigmask(SIGBUS)    | \
	rt_sigmask(SIGTRAP)   |  rt_sigmask(SIGCHLD)   | \
	rt_sigmask(SIGPOLL)   |  rt_sigmask(SIGSYS)    | \
	SIGEMT_MASK                                    )
#define SI_EXPANSION_SIZE (sizeof(struct siginfo) - sizeof(struct kernel_siginfo))

#define _SIG_SET_BINOP(name, op)					\
static inline void name(sigset_t *r, const sigset_t *a, const sigset_t *b) \
{									\
	unsigned long a0, a1, a2, a3, b0, b1, b2, b3;			\
									\
	switch (_NSIG_WORDS) {						\
	case 4:								\
		a3 = a->sig[3]; a2 = a->sig[2];				\
		b3 = b->sig[3]; b2 = b->sig[2];				\
		r->sig[3] = op(a3, b3);					\
		r->sig[2] = op(a2, b2);					\
		fallthrough;						\
	case 2:								\
		a1 = a->sig[1]; b1 = b->sig[1];				\
		r->sig[1] = op(a1, b1);					\
		fallthrough;						\
	case 1:								\
		a0 = a->sig[0]; b0 = b->sig[0];				\
		r->sig[0] = op(a0, b0);					\
		break;							\
	default:							\
		BUILD_BUG();						\
	}								\
}
#define _SIG_SET_OP(name, op)						\
static inline void name(sigset_t *set)					\
{									\
	switch (_NSIG_WORDS) {						\
	case 4:	set->sig[3] = op(set->sig[3]);				\
		set->sig[2] = op(set->sig[2]);				\
		fallthrough;						\
	case 2:	set->sig[1] = op(set->sig[1]);				\
		fallthrough;						\
	case 1:	set->sig[0] = op(set->sig[0]);				\
		    break;						\
	default:							\
		BUILD_BUG();						\
	}								\
}
#define _sig_and(x,y)	((x) & (y))
#define _sig_andn(x,y)	((x) & ~(y))
#define _sig_not(x)	(~(x))
#define _sig_or(x,y)	((x) | (y))
#define rt_sigmask(sig)	(1ULL << ((sig)-1))
#define sig_fatal(t, signr) \
	(!siginmask(signr, SIG_KERNEL_IGNORE_MASK|SIG_KERNEL_STOP_MASK) && \
	 (t)->sighand->action[(signr)-1].sa.sa_handler == SIG_DFL)
#define sig_kernel_coredump(sig)	siginmask(sig, SIG_KERNEL_COREDUMP_MASK)
#define sig_kernel_ignore(sig)		siginmask(sig, SIG_KERNEL_IGNORE_MASK)
#define sig_kernel_only(sig)		siginmask(sig, SIG_KERNEL_ONLY_MASK)
#define sig_kernel_stop(sig)		siginmask(sig, SIG_KERNEL_STOP_MASK)
#define sig_specific_sicodes(sig)	siginmask(sig, SIG_SPECIFIC_SICODES_MASK)
#define siginmask(sig, mask) \
	((sig) > 0 && (sig) < SIGRTMIN && (rt_sigmask(sig) & (mask)))
#define sigmask(sig)	(1UL << ((sig) - 1))
#define unsafe_save_altstack(uss, sp, label) do { \
	stack_t __user *__uss = uss; \
	struct task_struct *t = current; \
	unsafe_put_user((void __user *)t->sas_ss_sp, &__uss->ss_sp, label); \
	unsafe_put_user(t->sas_ss_flags, &__uss->ss_flags, label); \
	unsafe_put_user(t->sas_ss_size, &__uss->ss_size, label); \
} while (0);

#define DEFAULT_SEEKS 2 
#define SHRINK_EMPTY (~0UL - 1)
#define SHRINK_STOP (~0UL)


#define hlist_bl_for_each_entry_rcu(tpos, pos, head, member)		\
	for (pos = hlist_bl_first_rcu(head);				\
		pos &&							\
		({ tpos = hlist_bl_entry(pos, typeof(*tpos), member); 1; }); \
		pos = rcu_dereference_raw(pos->next))
#define INIT_HLIST_BL_HEAD(ptr) \
	((ptr)->first = NULL)
#define LIST_BL_BUG_ON(x) BUG_ON(x)

#define hlist_bl_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_bl_for_each_entry(tpos, pos, head, member)		\
	for (pos = hlist_bl_first(head);				\
	     pos &&							\
		({ tpos = hlist_bl_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_bl_for_each_entry_safe(tpos, pos, n, head, member)	 \
	for (pos = hlist_bl_first(head);				 \
	     pos && ({ n = pos->next; 1; }) && 				 \
		({ tpos = hlist_bl_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = n)

#define IS_GETLK(cmd)	(IS_GETLK32(cmd)  || IS_GETLK64(cmd))
#define IS_GETLK32(cmd)		((cmd) == F_GETLK)
#define IS_GETLK64(cmd)		((cmd) == F_GETLK64)
#define IS_SETLK(cmd)	(IS_SETLK32(cmd)  || IS_SETLK64(cmd))
#define IS_SETLK32(cmd)		((cmd) == F_SETLK)
#define IS_SETLK64(cmd)		((cmd) == F_SETLK64)
#define IS_SETLKW(cmd)	(IS_SETLKW32(cmd) || IS_SETLKW64(cmd))
#define IS_SETLKW32(cmd)	((cmd) == F_SETLKW)
#define IS_SETLKW64(cmd)	((cmd) == F_SETLKW64)
#define VALID_OPEN_FLAGS \
	(O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | \
	 O_APPEND | O_NDELAY | O_NONBLOCK | __O_SYNC | O_DSYNC | \
	 FASYNC	| O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | \
	 O_NOATIME | O_CLOEXEC | O_PATH | __O_TMPFILE)
#define VALID_RESOLVE_FLAGS \
	(RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | \
	 RESOLVE_BENEATH | RESOLVE_IN_ROOT | RESOLVE_CACHED)

#define force_o_largefile() (!IS_ENABLED(CONFIG_ARCH_32BIT_OFF_T))

#define DEFINE_SEMAPHORE(name)	\
	struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)

#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.lock		= __RAW_SPIN_LOCK_UNLOCKED((name).lock),	\
	.count		= n,						\
	.wait_list	= LIST_HEAD_INIT((name).wait_list),		\
}

#define list_lru_init(lru)				\
	__list_lru_init((lru), false, NULL, NULL)
#define list_lru_init_key(lru, key)			\
	__list_lru_init((lru), false, (key), NULL)
#define list_lru_init_memcg(lru, shrinker)		\
	__list_lru_init((lru), true, NULL, shrinker)

#define DCACHE_MANAGED_DENTRY \
	(DCACHE_MOUNTED|DCACHE_NEED_AUTOMOUNT|DCACHE_MANAGE_TRANSIT)
#  define DNAME_INLINE_LEN 36 
 #define HASH_LEN_DECLARE u32 hash; u32 len
#define IS_ROOT(x) ((x) == (x)->d_parent)
#define QSTR_INIT(n,l) { { { .len = l } }, .name = n }

 #define bytemask_from_count(cnt)	(~(~0ul << (cnt)*8))

#define hashlen_create(hash, len) ((u64)(len)<<32 | (u32)(hash))
#define hashlen_hash(hashlen) ((u32)(hashlen))
#define hashlen_len(hashlen)  ((u32)((hashlen) >> 32))
#define init_name_hash(salt)		(unsigned long)(salt)
#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_32

#define __hash_32 __hash_32_generic
#define hash_32 hash_32_generic
#define hash_64 hash_64_generic
#define hash_long(val, bits) hash_32(val, bits)
#define USE_CMPXCHG_LOCKREF \
	(IS_ENABLED(CONFIG_ARCH_USE_CMPXCHG_LOCKREF) && \
	 IS_ENABLED(CONFIG_SMP) && SPINLOCK_SIZE <= 4)

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

#define DEFINE_WAIT_BIT(name, word, bit)					\
	struct wait_bit_queue_entry name = {					\
		.key = __WAIT_BIT_KEY_INITIALIZER(word, bit),			\
		.wq_entry = {							\
			.private	= current,				\
			.func		= wake_bit_function,			\
			.entry		=					\
				LIST_HEAD_INIT((name).wq_entry.entry),		\
		},								\
	}

#define __WAIT_BIT_KEY_INITIALIZER(word, bit)					\
	{ .flags = word, .bit_nr = bit, }
#define ___wait_var_event(var, condition, state, exclusive, ret, cmd)	\
({									\
	__label__ __out;						\
	struct wait_queue_head *__wq_head = __var_waitqueue(var);	\
	struct wait_bit_queue_entry __wbq_entry;			\
	long __ret = ret; 				\
									\
	init_wait_var_entry(&__wbq_entry, var,				\
			    exclusive ? WQ_FLAG_EXCLUSIVE : 0);		\
	for (;;) {							\
		long __int = prepare_to_wait_event(__wq_head,		\
						   &__wbq_entry.wq_entry, \
						   state);		\
		if (condition)						\
			break;						\
									\
		if (___wait_is_interruptible(state) && __int) {		\
			__ret = __int;					\
			goto __out;					\
		}							\
									\
		cmd;							\
	}								\
	finish_wait(__wq_head, &__wbq_entry.wq_entry);			\
__out:	__ret;								\
})
#define __wait_var_event(var, condition)				\
	___wait_var_event(var, condition, TASK_UNINTERRUPTIBLE, 0, 0,	\
			  schedule())
#define __wait_var_event_interruptible(var, condition)			\
	___wait_var_event(var, condition, TASK_INTERRUPTIBLE, 0, 0,	\
			  schedule())
#define __wait_var_event_killable(var, condition)			\
	___wait_var_event(var, condition, TASK_KILLABLE, 0, 0,		\
			  schedule())
#define __wait_var_event_timeout(var, condition, timeout)		\
	___wait_var_event(var, ___wait_cond_timeout(condition),		\
			  TASK_UNINTERRUPTIBLE, 0, timeout,		\
			  __ret = schedule_timeout(__ret))
#define wait_var_event(var, condition)					\
do {									\
	might_sleep();							\
	if (condition)							\
		break;							\
	__wait_var_event(var, condition);				\
} while (0)
#define wait_var_event_interruptible(var, condition)			\
({									\
	int __ret = 0;							\
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_var_event_interruptible(var, condition);	\
	__ret;								\
})
#define wait_var_event_killable(var, condition)				\
({									\
	int __ret = 0;							\
	might_sleep();							\
	if (!(condition))						\
		__ret = __wait_var_event_killable(var, condition);	\
	__ret;								\
})
#define wait_var_event_timeout(var, condition, timeout)			\
({									\
	long __ret = timeout;						\
	might_sleep();							\
	if (!___wait_cond_timeout(condition))				\
		__ret = __wait_var_event_timeout(var, condition, timeout); \
	__ret;								\
})
#define MMF_DUMPABLE_BITS 2
#define MMF_DUMPABLE_MASK ((1 << MMF_DUMPABLE_BITS) - 1)
#define MMF_DUMP_FILTER_DEFAULT \
	((1 << MMF_DUMP_ANON_PRIVATE) |	(1 << MMF_DUMP_ANON_SHARED) |\
	 (1 << MMF_DUMP_HUGETLB_PRIVATE) | MMF_DUMP_MASK_DEFAULT_ELF)
#define MMF_DUMP_FILTER_MASK \
	(((1 << MMF_DUMP_FILTER_BITS) - 1) << MMF_DUMP_FILTER_SHIFT)
#define MMF_DUMP_HUGETLB_PRIVATE 7
#define MMF_DUMP_HUGETLB_SHARED  8



#define MAX_RESOURCE ((resource_size_t)~0)


#define page_ref_tracepoint_active(t) tracepoint_enabled(t)
#define DECLARE_TRACEPOINT(tp) \
	extern struct tracepoint __tracepoint_##tp
#define TRACEPOINT_DEFS_H 1
# define tracepoint_enabled(tp) \
	static_key_false(&(__tracepoint_##tp).key)


#define MMAP_LOCK_INITIALIZER(name) \
	.mmap_lock = __RWSEM_INITIALIZER((name).mmap_lock),


#define AGP_NORMAL_MEMORY 0
#define AGP_USER_CACHED_MEMORY (AGP_USER_TYPES + 1)
#define AGP_USER_MEMORY (AGP_USER_TYPES)
#define AGP_USER_TYPES (1 << 16)
#define _AGP_BACKEND_H 1


#define __pm_pr_dbg(defer, fmt, ...) \
	no_printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#define pm_deferred_pr_dbg(fmt, ...) \
	__pm_pr_dbg(true, fmt, ##__VA_ARGS__)
#define pm_notifier(fn, pri) {				\
	static struct notifier_block fn##_nb =			\
		{ .notifier_call = fn, .priority = pri };	\
	register_pm_notifier(&fn##_nb);			\
}
#define pm_pr_dbg(fmt, ...) \
	__pm_pr_dbg(false, fmt, ##__VA_ARGS__)

#define freezable_schedule()  schedule()
#define freezable_schedule_hrtimeout_range(expires, delta, mode)	\
	schedule_hrtimeout_range(expires, delta, mode)
#define freezable_schedule_timeout(timeout)  schedule_timeout(timeout)
#define freezable_schedule_timeout_interruptible(timeout)		\
	schedule_timeout_interruptible(timeout)
#define freezable_schedule_timeout_interruptible_unsafe(timeout)	\
	schedule_timeout_interruptible(timeout)
#define freezable_schedule_timeout_killable(timeout)			\
	schedule_timeout_killable(timeout)
#define freezable_schedule_timeout_killable_unsafe(timeout)		\
	schedule_timeout_killable(timeout)
#define freezable_schedule_unsafe()  schedule()
#define wait_event_freezekillable_unsafe(wq, condition)			\
({									\
	int __retval;							\
	freezer_do_not_count();						\
	__retval = wait_event_killable(wq, (condition));		\
	freezer_count_unsafe();						\
	__retval;							\
})
#define CLUSTER_FLAG_FREE 1 
#define CLUSTER_FLAG_HUGE 4 
#define CLUSTER_FLAG_NEXT_NULL 2 
#define COMPACT_CLUSTER_MAX SWAP_CLUSTER_MAX
#define MAX_SWAPFILES \
	((1 << MAX_SWAPFILES_SHIFT) - SWP_DEVICE_NUM - \
	SWP_MIGRATION_NUM - SWP_HWPOISON_NUM)
#define MAX_SWAP_BADPAGES \
	((offsetof(union swap_header, magic.magic) - \
	  offsetof(union swap_header, info.badpages)) / sizeof(int))
#define SWAP_BATCH 64
#define SWAP_CLUSTER_MAX 32UL
#define SWAP_FLAG_DISCARD_PAGES 0x40000 
#define SWP_DEVICE_EXCLUSIVE_READ (MAX_SWAPFILES+SWP_HWPOISON_NUM+SWP_MIGRATION_NUM+3)
#define SWP_DEVICE_EXCLUSIVE_WRITE (MAX_SWAPFILES+SWP_HWPOISON_NUM+SWP_MIGRATION_NUM+2)
#define SWP_DEVICE_NUM 4
#define SWP_DEVICE_READ (MAX_SWAPFILES+SWP_HWPOISON_NUM+SWP_MIGRATION_NUM+1)
#define SWP_DEVICE_WRITE (MAX_SWAPFILES+SWP_HWPOISON_NUM+SWP_MIGRATION_NUM)
#define SWP_HWPOISON_NUM 1
#define SWP_MIGRATION_NUM 2

#define free_page_and_swap_cache(page) \
	put_page(page)
#define free_pages_and_swap_cache(pages, nr) \
	release_pages((pages), (nr));
#define free_swap_and_cache(e) is_pfn_swap_entry(e)
#define get_nr_swap_pages()			0L
#define mapping_set_update(xas, mapping) do {				\
	if (!dax_mapping(mapping) && !shmem_mapping(mapping))		\
		xas_set_update(xas, workingset_update_node);		\
} while (0)
#define node_reclaim_mode 0
#define nr_free_pages() global_zone_page_state(NR_FREE_PAGES)
#define reuse_swap_page(page, total_map_swapcount) \
	(page_trans_huge_mapcount(page, total_map_swapcount) == 1)
#define si_swapinfo(val) \
	do { (val)->freeswap = (val)->totalswap = 0; } while (0)
#define swap_address_space(entry)			    \
	(&swapper_spaces[swp_type(entry)][swp_offset(entry) \
		>> SWAP_ADDRESS_SPACE_SHIFT])
#define total_swapcache_pages()			0UL
#define vm_swap_full()				0
#define BIO_ISSUE_RES_BITS      1
#define BIO_ISSUE_RES_MASK      (~((1ULL << BIO_ISSUE_RES_SHIFT) - 1))
#define BIO_ISSUE_RES_SHIFT     (64 - BIO_ISSUE_RES_BITS)
#define BIO_ISSUE_SIZE_BITS     12
#define BIO_ISSUE_SIZE_MASK     \
	(((1ULL << BIO_ISSUE_SIZE_BITS) - 1) << BIO_ISSUE_SIZE_SHIFT)
#define BIO_ISSUE_SIZE_SHIFT    (BIO_ISSUE_RES_SHIFT - BIO_ISSUE_SIZE_BITS)
#define BIO_ISSUE_THROTL_SKIP_LATENCY (1ULL << 63)
#define BIO_ISSUE_TIME_MASK     ((1ULL << BIO_ISSUE_SIZE_SHIFT) - 1)
#define BLK_STS_DM_REQUEUE    ((__force blk_status_t)11)
#define REQ_FAILFAST_MASK \
	(REQ_FAILFAST_DEV | REQ_FAILFAST_TRANSPORT | REQ_FAILFAST_DRIVER)
#define REQ_NOMERGE_FLAGS \
	(REQ_NOMERGE | REQ_PREFLUSH | REQ_FUA)

#define bdev_kobj(_bdev) \
	(&((_bdev)->bd_device.kobj))
#define bdev_whole(_bdev) \
	((_bdev)->bd_disk->part0)
#define bio_op(bio) \
	((bio)->bi_opf & REQ_OP_MASK)
#define dev_to_bdev(device) \
	container_of((device), struct block_device, bd_device)
#define req_op(req) \
	((req)->cmd_flags & REQ_OP_MASK)
#define BVEC_ITER_ALL_INIT (struct bvec_iter)				\
{									\
	.bi_sector	= 0,						\
	.bi_size	= UINT_MAX,					\
	.bi_idx		= 0,						\
	.bi_bvec_done	= 0,						\
}

#define __bvec_iter_bvec(bvec, iter)	(&(bvec)[(iter).bi_idx])
#define bvec_iter_bvec(bvec, iter)				\
((struct bio_vec) {						\
	.bv_page	= bvec_iter_page((bvec), (iter)),	\
	.bv_len		= bvec_iter_len((bvec), (iter)),	\
	.bv_offset	= bvec_iter_offset((bvec), (iter)),	\
})
#define bvec_iter_len(bvec, iter)				\
	min_t(unsigned, mp_bvec_iter_len((bvec), (iter)),		\
	      PAGE_SIZE - bvec_iter_offset((bvec), (iter)))
 #define bvec_iter_offset(bvec, iter)				\
	(mp_bvec_iter_offset((bvec), (iter)) % PAGE_SIZE)
#define bvec_iter_page(bvec, iter)				\
	(mp_bvec_iter_page((bvec), (iter)) +			\
	 mp_bvec_iter_page_idx((bvec), (iter)))
#define for_each_bvec(bvl, bio_vec, iter, start)			\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = bvec_iter_bvec((bio_vec), (iter))), 1);	\
	     bvec_iter_advance_single((bio_vec), &(iter), (bvl).bv_len))
#define mp_bvec_iter_bvec(bvec, iter)				\
((struct bio_vec) {						\
	.bv_page	= mp_bvec_iter_page((bvec), (iter)),	\
	.bv_len		= mp_bvec_iter_len((bvec), (iter)),	\
	.bv_offset	= mp_bvec_iter_offset((bvec), (iter)),	\
})
#define mp_bvec_iter_len(bvec, iter)				\
	min((iter).bi_size,					\
	    __bvec_iter_bvec((bvec), (iter))->bv_len - (iter).bi_bvec_done)
#define mp_bvec_iter_offset(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_offset + (iter).bi_bvec_done)
#define mp_bvec_iter_page(bvec, iter)				\
	(__bvec_iter_bvec((bvec), (iter))->bv_page)
#define mp_bvec_iter_page_idx(bvec, iter)			\
	(mp_bvec_iter_offset((bvec), (iter)) / PAGE_SIZE)


#define __irq_enter()					\
	do {						\
		preempt_count_add(HARDIRQ_OFFSET);	\
		lockdep_hardirq_enter();		\
		account_hardirq_enter(current);		\
	} while (0)
#define __irq_enter_raw()				\
	do {						\
		preempt_count_add(HARDIRQ_OFFSET);	\
		lockdep_hardirq_enter();		\
	} while (0)
#define __irq_exit()					\
	do {						\
		account_hardirq_exit(current);		\
		lockdep_hardirq_exit();			\
		preempt_count_sub(HARDIRQ_OFFSET);	\
	} while (0)
#define __irq_exit_raw()				\
	do {						\
		lockdep_hardirq_exit();			\
		preempt_count_sub(HARDIRQ_OFFSET);	\
	} while (0)
#define __nmi_enter()						\
	do {							\
		lockdep_off();					\
		arch_nmi_enter();				\
		BUG_ON(in_nmi() == NMI_MASK);			\
		__preempt_count_add(NMI_OFFSET + HARDIRQ_OFFSET);	\
	} while (0)
#define __nmi_exit()						\
	do {							\
		BUG_ON(!in_nmi());				\
		__preempt_count_sub(NMI_OFFSET + HARDIRQ_OFFSET);	\
		arch_nmi_exit();				\
		lockdep_on();					\
	} while (0)
#define arch_nmi_enter()	do { } while (0)
#define arch_nmi_exit()		do { } while (0)
#define nmi_enter()						\
	do {							\
		__nmi_enter();					\
		lockdep_hardirq_enter();			\
		rcu_nmi_enter();				\
		instrumentation_begin();			\
		ftrace_nmi_enter();				\
		instrumentation_end();				\
	} while (0)
#define nmi_exit()						\
	do {							\
		instrumentation_begin();			\
		ftrace_nmi_exit();				\
		instrumentation_end();				\
		rcu_nmi_exit();					\
		lockdep_hardirq_exit();				\
		__nmi_exit();					\
	} while (0)



#define MPOL_F_MEMS_ALLOWED (1<<2) 
#define MPOL_F_SHARED  (1 << 0)	
#define MPOL_MF_INTERNAL (1<<4)	
#define MPOL_MF_MOVE_ALL (1<<2)	

#define DEFINE_READAHEAD(ractl, f, r, m, i)				\
	struct readahead_control ractl = {				\
		.file = f,						\
		.mapping = m,						\
		.ra = r,						\
		._index = i,						\
	}

#define readahead_page_batch(rac, array)				\
	__readahead_batch(rac, array, ARRAY_SIZE(array))

#define MEMCG_CHARGE_BATCH 32U
#define MEMCG_DATA_FLAGS_MASK (__NR_MEMCG_DATA_FLAGS - 1)
#define MEMCG_PADDING(name)      struct memcg_padding name

#define for_each_memcg_cache_index(_idx)	\
	for ((_idx) = 0; (_idx) < memcg_nr_cache_ids; (_idx)++)
#define mem_cgroup_from_counter(counter, member)	\
	container_of(counter, struct mem_cgroup, member)
#define mem_cgroup_sockets_enabled static_branch_unlikely(&memcg_sockets_enabled_key)



#define BIO_POOL_SIZE 2

#define __bio_for_each_bvec(bvl, bio, iter, start)		\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = mp_bvec_iter_bvec((bio)->bi_io_vec, (iter))), 1); \
	     bio_advance_iter_single((bio), &(iter), (bvl).bv_len))
#define __bio_for_each_segment(bvl, bio, iter, start)			\
	for (iter = (start);						\
	     (iter).bi_size &&						\
		((bvl = bio_iter_iovec((bio), (iter))), 1);		\
	     bio_advance_iter_single((bio), &(iter), (bvl).bv_len))
#define bio_copy_dev(dst, src)			\
do {						\
	bio_clear_flag(dst, BIO_REMAPPED);		\
	(dst)->bi_bdev = (src)->bi_bdev;	\
	bio_clone_blkg_association(dst, src);	\
} while (0)
#define bio_data_dir(bio) \
	(op_is_write(bio_op(bio)) ? WRITE : READ)
#define bio_dev(bio) \
	disk_devt((bio)->bi_bdev->bd_disk)
#define bio_end_sector(bio)	bvec_iter_end_sector((bio)->bi_iter)
#define bio_for_each_bvec(bvl, bio, iter)			\
	__bio_for_each_bvec(bvl, bio, iter, (bio)->bi_iter)
#define bio_for_each_bvec_all(bvl, bio, i)		\
	for (i = 0, bvl = bio_first_bvec_all(bio);	\
	     i < (bio)->bi_vcnt; i++, bvl++)		\

#define bio_for_each_integrity_vec(_bvl, _bio, _iter)			\
	for_each_bio(_bio)						\
		bip_for_each_vec(_bvl, _bio->bi_integrity, _iter)
#define bio_for_each_segment(bvl, bio, iter)				\
	__bio_for_each_segment(bvl, bio, iter, (bio)->bi_iter)
#define bio_for_each_segment_all(bvl, bio, iter) \
	for (bvl = bvec_init_iter_all(&iter); bio_next_segment((bio), &iter); )
#define bio_iovec(bio)		bio_iter_iovec((bio), (bio)->bi_iter)
#define bio_iter_iovec(bio, iter)				\
	bvec_iter_bvec((bio)->bi_io_vec, (iter))
#define bio_iter_last(bvec, iter) ((iter).bi_size == (bvec).bv_len)
#define bio_iter_len(bio, iter)					\
	bvec_iter_len((bio)->bi_io_vec, (iter))
#define bio_iter_offset(bio, iter)				\
	bvec_iter_offset((bio)->bi_io_vec, (iter))
#define bio_iter_page(bio, iter)				\
	bvec_iter_page((bio)->bi_io_vec, (iter))
#define bio_list_for_each(bio, bl) \
	for (bio = (bl)->head; bio; bio = bio->bi_next)
#define bio_offset(bio)		bio_iter_offset((bio), (bio)->bi_iter)
#define bio_page(bio)		bio_iter_page((bio), (bio)->bi_iter)
#define bio_prio(bio)			(bio)->bi_ioprio
#define bio_sectors(bio)	bvec_iter_sectors((bio)->bi_iter)
#define bio_set_dev(bio, bdev) 				\
do {							\
	bio_clear_flag(bio, BIO_REMAPPED);		\
	if ((bio)->bi_bdev != (bdev))			\
		bio_clear_flag(bio, BIO_THROTTLED);	\
	(bio)->bi_bdev = (bdev);			\
	bio_associate_blkg(bio);			\
} while (0)
#define bio_set_prio(bio, prio)		((bio)->bi_ioprio = prio)
#define bip_for_each_vec(bvl, bip, iter)				\
	for_each_bvec(bvl, (bip)->bip_vec, iter, (bip)->bip_iter)
#define bvec_iter_end_sector(iter) ((iter).bi_sector + bvec_iter_sectors((iter)))
#define bvec_iter_sectors(iter)	((iter).bi_size >> 9)

#define _copy_from_iter_flushcache _copy_from_iter_nocache
#define _copy_mc_to_iter _copy_to_iter


#define SUBSYS(_x) extern struct cgroup_subsys _x ## _cgrp_subsys;

#define cgroup_subsys_enabled(ss)						\
	static_branch_likely(&ss ## _enabled_key)
#define cgroup_subsys_on_dfl(ss)						\
	static_branch_likely(&ss ## _on_dfl_key)
#define cgroup_taskset_for_each(task, dst_css, tset)			\
	for ((task) = cgroup_taskset_first((tset), &(dst_css));		\
	     (task);							\
	     (task) = cgroup_taskset_next((tset), &(dst_css)))
#define cgroup_taskset_for_each_leader(leader, dst_css, tset)		\
	for ((leader) = cgroup_taskset_first((tset), &(dst_css));	\
	     (leader);							\
	     (leader) = cgroup_taskset_next((tset), &(dst_css)))	\
		if ((leader) != (leader)->group_leader)			\
			;						\
		else
#define css_for_each_child(pos, parent)					\
	for ((pos) = css_next_child(NULL, (parent)); (pos);		\
	     (pos) = css_next_child((pos), (parent)))
#define css_for_each_descendant_post(pos, css)				\
	for ((pos) = css_next_descendant_post(NULL, (css)); (pos);	\
	     (pos) = css_next_descendant_post((pos), (css)))
#define css_for_each_descendant_pre(pos, css)				\
	for ((pos) = css_next_descendant_pre(NULL, (css)); (pos);	\
	     (pos) = css_next_descendant_pre((pos), (css)))
#define task_css_check(task, subsys_id, __c)				\
	task_css_set_check((task), (__c))->subsys[(subsys_id)]
#define task_css_set_check(task, __c)					\
	rcu_dereference_check((task)->cgroups,				\
		lockdep_is_held(&cgroup_mutex) ||			\
		lockdep_is_held(&css_set_lock) ||			\
		((task)->flags & PF_EXITING) || (__c))
#define CGROUP_SUBSYS_COUNT 0
#define MAX_CGROUP_ROOT_NAMELEN 64
#define MAX_CGROUP_TYPE_NAMELEN 32


#define DEFINE_KTHREAD_DELAYED_WORK(dwork, fn)				\
	struct kthread_delayed_work dwork =				\
		KTHREAD_DELAYED_WORK_INIT(dwork, fn)
#define DEFINE_KTHREAD_WORK(work, fn)					\
	struct kthread_work work = KTHREAD_WORK_INIT(work, fn)
#define DEFINE_KTHREAD_WORKER(worker)					\
	struct kthread_worker worker = KTHREAD_WORKER_INIT(worker)
# define DEFINE_KTHREAD_WORKER_ONSTACK(worker)				\
	struct kthread_worker worker = KTHREAD_WORKER_INIT_ONSTACK(worker)
#define KTHREAD_DELAYED_WORK_INIT(dwork, fn) {				\
	.work = KTHREAD_WORK_INIT((dwork).work, (fn)),			\
	.timer = __TIMER_INITIALIZER(kthread_delayed_work_timer_fn,\
				     TIMER_IRQSAFE),			\
	}
#define KTHREAD_WORKER_INIT(worker)	{				\
	.lock = __RAW_SPIN_LOCK_UNLOCKED((worker).lock),		\
	.work_list = LIST_HEAD_INIT((worker).work_list),		\
	.delayed_work_list = LIST_HEAD_INIT((worker).delayed_work_list),\
	}
# define KTHREAD_WORKER_INIT_ONSTACK(worker)				\
	({ kthread_init_worker(&worker); worker; })
#define KTHREAD_WORK_INIT(work, fn)	{				\
	.node = LIST_HEAD_INIT((work).node),				\
	.func = (fn),							\
	}

#define kthread_create(threadfn, data, namefmt, arg...) \
	kthread_create_on_node(threadfn, data, NUMA_NO_NODE, namefmt, ##arg)
#define kthread_init_delayed_work(dwork, fn)				\
	do {								\
		kthread_init_work(&(dwork)->work, (fn));		\
		timer_setup(&(dwork)->timer,				\
			     kthread_delayed_work_timer_fn,		\
			     TIMER_IRQSAFE);				\
	} while (0)
#define kthread_init_work(work, fn)					\
	do {								\
		memset((work), 0, sizeof(struct kthread_work));		\
		INIT_LIST_HEAD(&(work)->node);				\
		(work)->func = (fn);					\
	} while (0)
#define kthread_init_worker(worker)					\
	do {								\
		static struct lock_class_key __key;			\
		__kthread_init_worker((worker), "("#worker")->lock", &__key); \
	} while (0)
#define kthread_run(threadfn, data, namefmt, ...)			   \
({									   \
	struct task_struct *__k						   \
		= kthread_create(threadfn, data, namefmt, ## __VA_ARGS__); \
	if (!IS_ERR(__k))						   \
		wake_up_process(__k);					   \
	__k;								   \
})
#define BPF_CGROUP_GETSOCKOPT_MAX_OPTLEN(optlen)			       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(CGROUP_GETSOCKOPT))			       \
		get_user(__ret, optlen);				       \
	__ret;								       \
})
#define BPF_CGROUP_PRE_CONNECT_ENABLED(sk)				       \
	((cgroup_bpf_enabled(CGROUP_INET4_CONNECT) ||		       \
	  cgroup_bpf_enabled(CGROUP_INET6_CONNECT)) &&		       \
	 (sk)->sk_prot->pre_connect)
#define BPF_CGROUP_RUN_PROG_DEVICE_CGROUP(atype, major, minor, access)	      \
({									      \
	int __ret = 0;							      \
	if (cgroup_bpf_enabled(CGROUP_DEVICE))			      \
		__ret = __cgroup_bpf_check_dev_permission(atype, major, minor, \
							  access,	      \
							  CGROUP_DEVICE); \
									      \
	__ret;								      \
})
#define BPF_CGROUP_RUN_PROG_GETSOCKOPT(sock, level, optname, optval, optlen,   \
				       max_optlen, retval)		       \
({									       \
	int __ret = retval;						       \
	if (cgroup_bpf_enabled(CGROUP_GETSOCKOPT))			       \
		if (!(sock)->sk_prot->bpf_bypass_getsockopt ||		       \
		    !INDIRECT_CALL_INET_1((sock)->sk_prot->bpf_bypass_getsockopt, \
					tcp_bpf_bypass_getsockopt,	       \
					level, optname))		       \
			__ret = __cgroup_bpf_run_filter_getsockopt(	       \
				sock, level, optname, optval, optlen,	       \
				max_optlen, retval);			       \
	__ret;								       \
})
#define BPF_CGROUP_RUN_PROG_GETSOCKOPT_KERN(sock, level, optname, optval,      \
					    optlen, retval)		       \
({									       \
	int __ret = retval;						       \
	if (cgroup_bpf_enabled(CGROUP_GETSOCKOPT))			       \
		__ret = __cgroup_bpf_run_filter_getsockopt_kern(	       \
			sock, level, optname, optval, optlen, retval);	       \
	__ret;								       \
})
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG(sk, uaddr, CGROUP_INET4_CONNECT)
#define BPF_CGROUP_RUN_PROG_INET4_CONNECT_LOCK(sk, uaddr)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_INET4_CONNECT, NULL)
#define BPF_CGROUP_RUN_PROG_INET4_POST_BIND(sk)				       \
	BPF_CGROUP_RUN_SK_PROG(sk, CGROUP_INET4_POST_BIND)
#define BPF_CGROUP_RUN_PROG_INET6_CONNECT(sk, uaddr)			       \
	BPF_CGROUP_RUN_SA_PROG(sk, uaddr, CGROUP_INET6_CONNECT)
#define BPF_CGROUP_RUN_PROG_INET6_CONNECT_LOCK(sk, uaddr)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_INET6_CONNECT, NULL)
#define BPF_CGROUP_RUN_PROG_INET6_POST_BIND(sk)				       \
	BPF_CGROUP_RUN_SK_PROG(sk, CGROUP_INET6_POST_BIND)
#define BPF_CGROUP_RUN_PROG_INET_BIND_LOCK(sk, uaddr, atype, bind_flags)	       \
({									       \
	u32 __flags = 0;						       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(atype))	{				       \
		lock_sock(sk);						       \
		__ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, atype,     \
							  NULL, &__flags);     \
		release_sock(sk);					       \
		if (__flags & BPF_RET_BIND_NO_CAP_NET_BIND_SERVICE)	       \
			*bind_flags |= BIND_NO_CAP_NET_BIND_SERVICE;	       \
	}								       \
	__ret;								       \
})
#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sk, skb)			       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(CGROUP_INET_EGRESS) && sk && sk == skb->sk) { \
		typeof(sk) __sk = sk_to_full_sk(sk);			       \
		if (sk_fullsock(__sk))					       \
			__ret = __cgroup_bpf_run_filter_skb(__sk, skb,	       \
						      CGROUP_INET_EGRESS); \
	}								       \
	__ret;								       \
})
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk, skb)			      \
({									      \
	int __ret = 0;							      \
	if (cgroup_bpf_enabled(CGROUP_INET_INGRESS))		      \
		__ret = __cgroup_bpf_run_filter_skb(sk, skb,		      \
						    CGROUP_INET_INGRESS); \
									      \
	__ret;								      \
})
#define BPF_CGROUP_RUN_PROG_INET_SOCK(sk)				       \
	BPF_CGROUP_RUN_SK_PROG(sk, CGROUP_INET_SOCK_CREATE)
#define BPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE(sk)			       \
	BPF_CGROUP_RUN_SK_PROG(sk, CGROUP_INET_SOCK_RELEASE)
#define BPF_CGROUP_RUN_PROG_SETSOCKOPT(sock, level, optname, optval, optlen,   \
				       kernel_optval)			       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(CGROUP_SETSOCKOPT))			       \
		__ret = __cgroup_bpf_run_filter_setsockopt(sock, level,	       \
							   optname, optval,    \
							   optlen,	       \
							   kernel_optval);     \
	__ret;								       \
})
#define BPF_CGROUP_RUN_PROG_SOCK_OPS(sock_ops)				       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(CGROUP_SOCK_OPS) && (sock_ops)->sk) {       \
		typeof(sk) __sk = sk_to_full_sk((sock_ops)->sk);	       \
		if (__sk && sk_fullsock(__sk))				       \
			__ret = __cgroup_bpf_run_filter_sock_ops(__sk,	       \
								 sock_ops,     \
							 CGROUP_SOCK_OPS); \
	}								       \
	__ret;								       \
})
#define BPF_CGROUP_RUN_PROG_SOCK_OPS_SK(sock_ops, sk)			\
({									\
	int __ret = 0;							\
	if (cgroup_bpf_enabled(CGROUP_SOCK_OPS))			\
		__ret = __cgroup_bpf_run_filter_sock_ops(sk,		\
							 sock_ops,	\
							 CGROUP_SOCK_OPS); \
	__ret;								\
})
#define BPF_CGROUP_RUN_PROG_SYSCTL(head, table, write, buf, count, pos)  \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(CGROUP_SYSCTL))			       \
		__ret = __cgroup_bpf_run_filter_sysctl(head, table, write,     \
						       buf, count, pos,        \
						       CGROUP_SYSCTL);     \
	__ret;								       \
})
#define BPF_CGROUP_RUN_PROG_UDP4_RECVMSG_LOCK(sk, uaddr)			\
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_UDP4_RECVMSG, NULL)
#define BPF_CGROUP_RUN_PROG_UDP4_SENDMSG_LOCK(sk, uaddr, t_ctx)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_UDP4_SENDMSG, t_ctx)
#define BPF_CGROUP_RUN_PROG_UDP6_RECVMSG_LOCK(sk, uaddr)			\
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_UDP6_RECVMSG, NULL)
#define BPF_CGROUP_RUN_PROG_UDP6_SENDMSG_LOCK(sk, uaddr, t_ctx)		       \
	BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, CGROUP_UDP6_SENDMSG, t_ctx)
#define BPF_CGROUP_RUN_SA_PROG(sk, uaddr, atype)				       \
({									       \
	u32 __unused_flags;						       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(atype))					       \
		__ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, atype,     \
							  NULL,		       \
							  &__unused_flags);    \
	__ret;								       \
})
#define BPF_CGROUP_RUN_SA_PROG_LOCK(sk, uaddr, atype, t_ctx)		       \
({									       \
	u32 __unused_flags;						       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(atype))	{				       \
		lock_sock(sk);						       \
		__ret = __cgroup_bpf_run_filter_sock_addr(sk, uaddr, atype,     \
							  t_ctx,	       \
							  &__unused_flags);    \
		release_sock(sk);					       \
	}								       \
	__ret;								       \
})
#define BPF_CGROUP_RUN_SK_PROG(sk, atype)				       \
({									       \
	int __ret = 0;							       \
	if (cgroup_bpf_enabled(atype)) {					       \
		__ret = __cgroup_bpf_run_filter_sk(sk, atype);		       \
	}								       \
	__ret;								       \
})
#define CGROUP_ATYPE(type) \
	case BPF_##type: return type

#define cgroup_bpf_enabled(atype) (0)
#define for_each_cgroup_storage_type(stype) for (; false; )
#define BPF_BUILD_ID_SIZE 20
#define BPF_F_ADJ_ROOM_ENCAP_L2(len)	(((__u64)len & \
					  BPF_ADJ_ROOM_ENCAP_L2_MASK) \
					 << BPF_ADJ_ROOM_ENCAP_L2_SHIFT)
#define BPF_LINE_INFO_LINE_COL(line_col)	((line_col) & 0x3ff)
#define BPF_LINE_INFO_LINE_NUM(line_col)	((line_col) >> 10)
#define BPF_OBJ_NAME_LEN 16U
#define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE
#define XDP_PACKET_HEADROOM 256

#define __BPF_ENUM_FN(x) BPF_FUNC_ ## x
#define __BPF_FUNC_MAPPER(FN)		\
	FN(unspec),			\
	FN(map_lookup_elem),		\
	FN(map_update_elem),		\
	FN(map_delete_elem),		\
	FN(probe_read),			\
	FN(ktime_get_ns),		\
	FN(trace_printk),		\
	FN(get_prandom_u32),		\
	FN(get_smp_processor_id),	\
	FN(skb_store_bytes),		\
	FN(l3_csum_replace),		\
	FN(l4_csum_replace),		\
	FN(tail_call),			\
	FN(clone_redirect),		\
	FN(get_current_pid_tgid),	\
	FN(get_current_uid_gid),	\
	FN(get_current_comm),		\
	FN(get_cgroup_classid),		\
	FN(skb_vlan_push),		\
	FN(skb_vlan_pop),		\
	FN(skb_get_tunnel_key),		\
	FN(skb_set_tunnel_key),		\
	FN(perf_event_read),		\
	FN(redirect),			\
	FN(get_route_realm),		\
	FN(perf_event_output),		\
	FN(skb_load_bytes),		\
	FN(get_stackid),		\
	FN(csum_diff),			\
	FN(skb_get_tunnel_opt),		\
	FN(skb_set_tunnel_opt),		\
	FN(skb_change_proto),		\
	FN(skb_change_type),		\
	FN(skb_under_cgroup),		\
	FN(get_hash_recalc),		\
	FN(get_current_task),		\
	FN(probe_write_user),		\
	FN(current_task_under_cgroup),	\
	FN(skb_change_tail),		\
	FN(skb_pull_data),		\
	FN(csum_update),		\
	FN(set_hash_invalid),		\
	FN(get_numa_node_id),		\
	FN(skb_change_head),		\
	FN(xdp_adjust_head),		\
	FN(probe_read_str),		\
	FN(get_socket_cookie),		\
	FN(get_socket_uid),		\
	FN(set_hash),			\
	FN(setsockopt),			\
	FN(skb_adjust_room),		\
	FN(redirect_map),		\
	FN(sk_redirect_map),		\
	FN(sock_map_update),		\
	FN(xdp_adjust_meta),		\
	FN(perf_event_read_value),	\
	FN(perf_prog_read_value),	\
	FN(getsockopt),			\
	FN(override_return),		\
	FN(sock_ops_cb_flags_set),	\
	FN(msg_redirect_map),		\
	FN(msg_apply_bytes),		\
	FN(msg_cork_bytes),		\
	FN(msg_pull_data),		\
	FN(bind),			\
	FN(xdp_adjust_tail),		\
	FN(skb_get_xfrm_state),		\
	FN(get_stack),			\
	FN(skb_load_bytes_relative),	\
	FN(fib_lookup),			\
	FN(sock_hash_update),		\
	FN(msg_redirect_hash),		\
	FN(sk_redirect_hash),		\
	FN(lwt_push_encap),		\
	FN(lwt_seg6_store_bytes),	\
	FN(lwt_seg6_adjust_srh),	\
	FN(lwt_seg6_action),		\
	FN(rc_repeat),			\
	FN(rc_keydown),			\
	FN(skb_cgroup_id),		\
	FN(get_current_cgroup_id),	\
	FN(get_local_storage),		\
	FN(sk_select_reuseport),	\
	FN(skb_ancestor_cgroup_id),	\
	FN(sk_lookup_tcp),		\
	FN(sk_lookup_udp),		\
	FN(sk_release),			\
	FN(map_push_elem),		\
	FN(map_pop_elem),		\
	FN(map_peek_elem),		\
	FN(msg_push_data),		\
	FN(msg_pop_data),		\
	FN(rc_pointer_rel),		\
	FN(spin_lock),			\
	FN(spin_unlock),		\
	FN(sk_fullsock),		\
	FN(tcp_sock),			\
	FN(skb_ecn_set_ce),		\
	FN(get_listener_sock),		\
	FN(skc_lookup_tcp),		\
	FN(tcp_check_syncookie),	\
	FN(sysctl_get_name),		\
	FN(sysctl_get_current_value),	\
	FN(sysctl_get_new_value),	\
	FN(sysctl_set_new_value),	\
	FN(strtol),			\
	FN(strtoul),			\
	FN(sk_storage_get),		\
	FN(sk_storage_delete),		\
	FN(send_signal),		\
	FN(tcp_gen_syncookie),		\
	FN(skb_output),			\
	FN(probe_read_user),		\
	FN(probe_read_kernel),		\
	FN(probe_read_user_str),	\
	FN(probe_read_kernel_str),	\
	FN(tcp_send_ack),		\
	FN(send_signal_thread),		\
	FN(jiffies64),			\
	FN(read_branch_records),	\
	FN(get_ns_current_pid_tgid),	\
	FN(xdp_output),			\
	FN(get_netns_cookie),		\
	FN(get_current_ancestor_cgroup_id),	\
	FN(sk_assign),			\
	FN(ktime_get_boot_ns),		\
	FN(seq_printf),			\
	FN(seq_write),			\
	FN(sk_cgroup_id),		\
	FN(sk_ancestor_cgroup_id),	\
	FN(ringbuf_output),		\
	FN(ringbuf_reserve),		\
	FN(ringbuf_submit),		\
	FN(ringbuf_discard),		\
	FN(ringbuf_query),		\
	FN(csum_level),			\
	FN(skc_to_tcp6_sock),		\
	FN(skc_to_tcp_sock),		\
	FN(skc_to_tcp_timewait_sock),	\
	FN(skc_to_tcp_request_sock),	\
	FN(skc_to_udp6_sock),		\
	FN(get_task_stack),		\
	FN(load_hdr_opt),		\
	FN(store_hdr_opt),		\
	FN(reserve_hdr_opt),		\
	FN(inode_storage_get),		\
	FN(inode_storage_delete),	\
	FN(d_path),			\
	FN(copy_from_user),		\
	FN(snprintf_btf),		\
	FN(seq_printf_btf),		\
	FN(skb_cgroup_classid),		\
	FN(redirect_neigh),		\
	FN(per_cpu_ptr),		\
	FN(this_cpu_ptr),		\
	FN(redirect_peer),		\
	FN(task_storage_get),		\
	FN(task_storage_delete),	\
	FN(get_current_task_btf),	\
	FN(bprm_opts_set),		\
	FN(ktime_get_coarse_ns),	\
	FN(ima_inode_hash),		\
	FN(sock_from_file),		\
	FN(check_mtu),			\
	FN(for_each_map_elem),		\
	FN(snprintf),			\
	FN(sys_bpf),			\
	FN(btf_find_by_name_kind),	\
	FN(sys_close),			\
	FN(timer_init),			\
	FN(timer_set_callback),		\
	FN(timer_start),		\
	FN(timer_cancel),		\
	FN(get_func_ip),		\
	FN(get_attach_cookie),		\
	FN(task_pt_regs),		\
	
#define __bpf_md_ptr(type, name)	\
union {					\
	type name;			\
	__u64 :64;			\
} __attribute__((aligned(8)))
#define BPF_COMPLEXITY_LIMIT_INSNS      1000000 
#define BPF_DISPATCHER_FUNC(name) bpf_dispatcher_##name##_func
#define BPF_DISPATCHER_INIT(_name) {				\
	.mutex = __MUTEX_INITIALIZER(_name.mutex),		\
	.func = &_name##_func,					\
	.progs = {},						\
	.num_progs = 0,						\
	.image = NULL,						\
	.image_off = 0,						\
	.ksym = {						\
		.name  = #_name,				\
		.lnode = LIST_HEAD_INIT(_name.ksym.lnode),	\
	},							\
}
#define BPF_DISPATCHER_MAX 48 
#define BPF_DISPATCHER_PTR(name) (&bpf_dispatcher_##name)
#define BPF_ITER_CTX_ARG_MAX 2
#define BPF_ITER_FUNC_PREFIX "bpf_iter_"
#define BPF_LINK_TYPE(_id, _name)
#define BPF_MAP_TYPE(_id, _ops) \
	extern const struct bpf_map_ops _ops;
#define BPF_MAX_TRAMP_PROGS 38
#define BPF_MODULE_OWNER ((void *)((0xeB9FUL << 2) + POISON_POINTER_DELTA))
#define BPF_PROG_CGROUP_INET_EGRESS_RUN_ARRAY(array, ctx, func)		\
	({						\
		u32 _flags = 0;				\
		bool _cn;				\
		u32 _ret;				\
		_ret = BPF_PROG_RUN_ARRAY_CG_FLAGS(array, ctx, func, &_flags); \
		_cn = _flags & BPF_RET_SET_CN;		\
		if (_ret)				\
			_ret = (_cn ? NET_XMIT_CN : NET_XMIT_SUCCESS);	\
		else					\
			_ret = (_cn ? NET_XMIT_DROP : -EPERM);		\
		_ret;					\
	})
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
	extern const struct bpf_prog_ops _name ## _prog_ops; \
	extern const struct bpf_verifier_ops _name ## _verifier_ops;
#define BPF_STRUCT_OPS_MAX_NR_MEMBERS 64
#define DECLARE_BPF_DISPATCHER(name)					\
	unsigned int bpf_dispatcher_##name##_func(			\
		const void *ctx,					\
		const struct bpf_insn *insnsi,				\
		unsigned int (*bpf_func)(const void *,			\
					 const struct bpf_insn *));	\
	extern struct bpf_dispatcher bpf_dispatcher_##name;
#define DEFINE_BPF_DISPATCHER(name)					\
	noinline __nocfi unsigned int bpf_dispatcher_##name##_func(	\
		const void *ctx,					\
		const struct bpf_insn *insnsi,				\
		unsigned int (*bpf_func)(const void *,			\
					 const struct bpf_insn *))	\
	{								\
		return bpf_func(ctx, insnsi);				\
	}								\
	EXPORT_SYMBOL(bpf_dispatcher_##name##_func);			\
	struct bpf_dispatcher bpf_dispatcher_##name =			\
		BPF_DISPATCHER_INIT(bpf_dispatcher_##name);
#define DEFINE_BPF_ITER_FUNC(target, args...)			\
	extern int bpf_iter_ ## target(args);			\
	int __init bpf_iter_ ## target(args) { return 0; }
#define MAX_BPF_CGROUP_STORAGE_TYPE __BPF_CGROUP_STORAGE_MAX
#define MAX_BPF_FUNC_ARGS 12
#define MAX_BPF_FUNC_REG_ARGS 5
#define MAX_TAIL_CALL_CNT 32
#define _LINUX_BPF_H 1




#define KSYM_NAME_LEN 128
#define KSYM_SYMBOL_LEN (sizeof("%s+%#lx/%#lx [%s %s]") + \
			(KSYM_NAME_LEN - 1) + \
			2*(BITS_PER_LONG*3/10) + (MODULE_NAME_LEN - 1) + \
			(BUILD_ID_SIZE_MAX * 2) + 1)

#define MODULE_ALIAS(_alias) MODULE_INFO(alias, _alias)
#define MODULE_ARCH_INIT {}
#define MODULE_AUTHOR(_author) MODULE_INFO(author, _author)
#define MODULE_DESCRIPTION(_description) MODULE_INFO(description, _description)
#define MODULE_DEVICE_TABLE(type, name)					\
extern typeof(name) __mod_##type##__##name##_device_table		\
  __attribute__ ((unused, alias(__stringify(name))))

#define MODULE_FIRMWARE(_firmware) MODULE_INFO(firmware, _firmware)
#define MODULE_IMPORT_NS(ns) MODULE_INFO(import_ns, #ns)
#define MODULE_INFO(tag, info) __MODULE_INFO(tag, tag, info)
#define MODULE_LICENSE(_license) MODULE_FILE MODULE_INFO(license, _license)
#define MODULE_NAME_LEN MAX_PARAM_PREFIX_LEN
#define MODULE_SOFTDEP(_softdep) MODULE_INFO(softdep, _softdep)
#define MODULE_VERSION(_version) MODULE_INFO(version, _version)

#define __INITDATA_OR_MODULE __INITDATA
#define __INITRODATA_OR_MODULE __INITRODATA
#define __INIT_OR_MODULE __INIT
#define __MODULE_STRING(x) __stringify(x)
#define __init_or_module __init
#define __initconst_or_module __initconst
#define __initdata_or_module __initdata
#define __module_layout_align ____cacheline_aligned
#define arch_initcall(fn)		module_init(fn)
#define console_initcall(fn)		module_init(fn)
#define core_initcall(fn)		module_init(fn)
#define core_initcall_sync(fn)		module_init(fn)
#define device_initcall(fn)		module_init(fn)
#define device_initcall_sync(fn)	module_init(fn)
#define early_initcall(fn)		module_init(fn)
#define fs_initcall(fn)			module_init(fn)
#define fs_initcall_sync(fn)		module_init(fn)
#define late_initcall(fn)		module_init(fn)
#define late_initcall_sync(fn)		module_init(fn)
#define module_exit(x)	__exitcall(x);
#define module_init(initfn)					\
	static inline initcall_t __maybe_unused __inittest(void)		\
	{ return initfn; }					\
	int init_module(void) __copy(initfn)			\
		__attribute__((alias(#initfn)));		\
	__CFI_ADDRESSABLE(init_module, __initdata);
#define module_name(mod)			\
({						\
	struct module *__mod = (mod);		\
	__mod ? __mod->name : "kernel";		\
})
#define module_put_and_exit(code) __module_put_and_exit(THIS_MODULE, code)
#define postcore_initcall(fn)		module_init(fn)
#define postcore_initcall_sync(fn)	module_init(fn)
#define rootfs_initcall(fn)		module_init(fn)
#define subsys_initcall(fn)		module_init(fn)
#define subsys_initcall_sync(fn)	module_init(fn)
#define symbol_get(x) ((typeof(&x))(__symbol_get(__stringify(x))))
#define symbol_put(x) __symbol_put(__stringify(x))
#define symbol_put_addr(p) do { } while (0)
#define symbol_request(x) try_then_request_module(symbol_get(x), "symbol:" #x)

#define __CFI_ADDRESSABLE(fn, __attr) \
	const void *__cfi_jt_ ## fn __visible __attr = (void *)&fn

#define ALLOW_ERROR_INJECTION(fname, _etype)				\
static struct error_injection_entry __used				\
	__section("_error_injection_whitelist")				\
	_eil_addr_##fname = {						\
		.addr = (unsigned long)fname,				\
		.etype = EI_ETYPE_##_etype,				\
	};


#define MAX_PARAM_PREFIX_LEN (64 - sizeof(unsigned long))
#define MODULE_PARAM_PREFIX 
#define MODULE_PARM_DESC(_parm, desc) \
	__MODULE_INFO(parm, _parm, #_parm ":" desc)

#define __MODULE_INFO(tag, name, info)					  \
	static const char __UNIQUE_ID(name)[]				  \
		__used __section(".modinfo") __aligned(1)		  \
		= __MODULE_INFO_PREFIX __stringify(tag) "=" info
#define __MODULE_INFO_PREFIX 
#define __MODULE_PARM_TYPE(name, _type)					  \
	__MODULE_INFO(parmtype, name##type, #name ":" _type)
#define __level_param_cb(name, ops, arg, perm, level)			\
	__module_param_call(MODULE_PARAM_PREFIX, name, ops, arg, perm, level, 0)
#define __module_param_call(prefix, name, ops, arg, perm, level, flags)	\
				\
	static const char __param_str_##name[] = prefix #name;		\
	static struct kernel_param __moduleparam_const __param_##name	\
	__used __section("__param")					\
	__aligned(__alignof__(struct kernel_param))			\
	= { __param_str_##name, THIS_MODULE, ops,			\
	    VERIFY_OCTAL_PERMISSIONS(perm), level, flags, { arg } }
#define __moduleparam_const const
#define __param_check(name, p, type) \
	static inline type __always_unused *__check_##name(void) { return(p); }
#define arch_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 3)
#define core_param(name, var, type, perm)				\
	param_check_##type(name, &(var));				\
	__module_param_call("", name, &param_ops_##type, &var, perm, -1, 0)
#define core_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 1)
#define core_param_unsafe(name, var, type, perm)		\
	param_check_##type(name, &(var));				\
	__module_param_call("", name, &param_ops_##type, &var, perm,	\
			    -1, KERNEL_PARAM_FL_UNSAFE)
#define device_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 6)
#define fs_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 5)
#define late_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 7)
#define module_param(name, type, perm)				\
	module_param_named(name, name, type, perm)
#define module_param_array(name, type, nump, perm)		\
	module_param_array_named(name, name, type, nump, perm)
#define module_param_array_named(name, array, type, nump, perm)		\
	param_check_##type(name, &(array)[0]);				\
	static const struct kparam_array __param_arr_##name		\
	= { .max = ARRAY_SIZE(array), .num = nump,                      \
	    .ops = &param_ops_##type,					\
	    .elemsize = sizeof(array[0]), .elem = array };		\
	__module_param_call(MODULE_PARAM_PREFIX, name,			\
			    &param_array_ops,				\
			    .arr = &__param_arr_##name,			\
			    perm, -1, 0);				\
	__MODULE_PARM_TYPE(name, "array of " #type)
#define module_param_call(name, _set, _get, arg, perm)			\
	static const struct kernel_param_ops __param_ops_##name =	\
		{ .flags = 0, .set = _set, .get = _get };		\
	__module_param_call(MODULE_PARAM_PREFIX,			\
			    name, &__param_ops_##name, arg, perm, -1, 0)
#define module_param_cb(name, ops, arg, perm)				      \
	__module_param_call(MODULE_PARAM_PREFIX, name, ops, arg, perm, -1, 0)
#define module_param_cb_unsafe(name, ops, arg, perm)			      \
	__module_param_call(MODULE_PARAM_PREFIX, name, ops, arg, perm, -1,    \
			    KERNEL_PARAM_FL_UNSAFE)
#define module_param_hw(name, type, hwtype, perm)		\
	module_param_hw_named(name, name, type, hwtype, perm)
#define module_param_hw_array(name, type, hwtype, nump, perm)		\
	param_check_##type(name, &(name)[0]);				\
	static const struct kparam_array __param_arr_##name		\
	= { .max = ARRAY_SIZE(name), .num = nump,			\
	    .ops = &param_ops_##type,					\
	    .elemsize = sizeof(name[0]), .elem = name };		\
	__module_param_call(MODULE_PARAM_PREFIX, name,			\
			    &param_array_ops,				\
			    .arr = &__param_arr_##name,			\
			    perm, -1,					\
			    KERNEL_PARAM_FL_HWPARAM | (hwparam_##hwtype & 0));	\
	__MODULE_PARM_TYPE(name, "array of " #type)
#define module_param_hw_named(name, value, type, hwtype, perm)		\
	param_check_##type(name, &(value));				\
	__module_param_call(MODULE_PARAM_PREFIX, name,			\
			    &param_ops_##type, &value,			\
			    perm, -1,					\
			    KERNEL_PARAM_FL_HWPARAM | (hwparam_##hwtype & 0));	\
	__MODULE_PARM_TYPE(name, #type)
#define module_param_named(name, value, type, perm)			   \
	param_check_##type(name, &(value));				   \
	module_param_cb(name, &param_ops_##type, &value, perm);		   \
	__MODULE_PARM_TYPE(name, #type)
#define module_param_named_unsafe(name, value, type, perm)		\
	param_check_##type(name, &(value));				\
	module_param_cb_unsafe(name, &param_ops_##type, &value, perm);	\
	__MODULE_PARM_TYPE(name, #type)
#define module_param_string(name, string, len, perm)			\
	static const struct kparam_string __param_string_##name		\
		= { len, string };					\
	__module_param_call(MODULE_PARAM_PREFIX, name,			\
			    &param_ops_string,				\
			    .str = &__param_string_##name, perm, -1, 0);\
	__MODULE_PARM_TYPE(name, "string")
#define module_param_unsafe(name, type, perm)			\
	module_param_named_unsafe(name, name, type, perm)
#define param_check_bint param_check_int
#define param_check_bool(name, p) __param_check(name, p, bool)
#define param_check_bool_enable_only param_check_bool
#define param_check_byte(name, p) __param_check(name, p, unsigned char)
#define param_check_charp(name, p) __param_check(name, p, char *)
#define param_check_hexint(name, p) param_check_uint(name, p)
#define param_check_int(name, p) __param_check(name, p, int)
#define param_check_invbool(name, p) __param_check(name, p, bool)
#define param_check_long(name, p) __param_check(name, p, long)
#define param_check_short(name, p) __param_check(name, p, short)
#define param_check_uint(name, p) __param_check(name, p, unsigned int)
#define param_check_ullong(name, p) __param_check(name, p, unsigned long long)
#define param_check_ulong(name, p) __param_check(name, p, unsigned long)
#define param_check_ushort(name, p) __param_check(name, p, unsigned short)
#define param_get_bint param_get_int
#define postcore_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 2)
#define subsys_param_cb(name, ops, arg, perm)		\
	__level_param_cb(name, ops, arg, perm, 4)
#define ARCH_SETUP_ADDITIONAL_PAGES(bprm, ex, interpreter) \
	arch_setup_additional_pages(bprm, interpreter)
#define SET_PERSONALITY(ex) \
	set_personality(PER_LINUX | (current->personality & (~PER_MASK)))
#define SET_PERSONALITY2(ex, state) \
	SET_PERSONALITY(ex)
#define START_THREAD(elf_ex, regs, elf_entry, start_stack)	\
	start_thread(regs, elf_entry, start_stack)

# define elf_read_implies_exec(ex, have_pt_gnu_stack)	0
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
#define ET_CORE   4
#define ET_DYN    3
#define ET_EXEC   2
#define ET_HIPROC 0xffff
#define ET_LOPROC 0xff00
#define ET_NONE   0
#define ET_REL    1
#define NT_FILE         0x46494c45
#define NT_PRXFPREG     0x46e62b7f      
#define NT_SIGINFO      0x53494749
#define OLD_DT_HIOS     0x6fffffff
#define PN_XNUM 0xffff
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
#define STT_COMMON  5
#define STT_FILE    4
#define STT_FUNC    2
#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_SECTION 3
#define STT_TLS     6

#define KMOD_PATH_LEN 256

#define request_module(mod...) __request_module(true, mod)
#define request_module_nowait(mod...) __request_module(false, mod)
#define try_then_request_module(x, mod...) \
	((x) ?: (__request_module(true, mod), (x)))

#define BUILD_ID_SIZE_MAX 20

#define FDPUT_FPUT       1
#define FDPUT_POS_UNLOCK 2


#define u64_stats_init(syncp)	seqcount_init(&(syncp)->seq)

#define kcpustat_cpu(cpu) per_cpu(kernel_cpustat, cpu)
#define kcpustat_this_cpu this_cpu_ptr(&kernel_cpustat)
#define kstat_cpu(cpu) per_cpu(kstat, cpu)
#define kstat_this_cpu this_cpu_ptr(&kstat)
#define DECLARE_TASKLET(name, _callback)		\
struct tasklet_struct name = {				\
	.count = ATOMIC_INIT(0),			\
	.callback = _callback,				\
	.use_callback = true,				\
}
#define DECLARE_TASKLET_DISABLED(name, _callback)	\
struct tasklet_struct name = {				\
	.count = ATOMIC_INIT(1),			\
	.callback = _callback,				\
	.use_callback = true,				\
}
#define DECLARE_TASKLET_DISABLED_OLD(name, _func)	\
struct tasklet_struct name = {				\
	.count = ATOMIC_INIT(1),			\
	.func = _func,					\
}
#define DECLARE_TASKLET_OLD(name, _func)		\
struct tasklet_struct name = {				\
	.count = ATOMIC_INIT(0),			\
	.func = _func,					\
}
#define SOFTIRQ_STOP_IDLE_MASK (~(1 << RCU_SOFTIRQ))

#define __softirq_entry  __section(".softirqentry.text")
#  define force_irqthreads()	(true)
#define from_tasklet(var, callback_tasklet, tasklet_fieldname)	\
	container_of(callback_tasklet, typeof(*var), tasklet_fieldname)
#define hard_irq_disable()	do { } while(0)
# define local_irq_enable_in_hardirq()	do { } while (0)
#define local_softirq_pending()	(__this_cpu_read(local_softirq_pending_ref))
#define local_softirq_pending_ref irq_stat.__softirq_pending
#define or_softirq_pending(x)	(__this_cpu_or(local_softirq_pending_ref, (x)))
#define set_softirq_pending(x)	(__this_cpu_write(local_softirq_pending_ref, (x)))

# define for_each_active_irq(irq)			\
	for (irq = irq_get_next_irq(0); irq < nr_irqs;	\
	     irq = irq_get_next_irq(irq + 1))
# define for_each_irq_desc(irq, desc)					\
	for (irq = 0, desc = irq_to_desc(irq); irq < nr_irqs;		\
	     irq++, desc = irq_to_desc(irq))				\
		if (!desc)						\
			;						\
		else
# define for_each_irq_desc_reverse(irq, desc)				\
	for (irq = nr_irqs - 1, desc = irq_to_desc(irq); irq >= 0;	\
	     irq--, desc = irq_to_desc(irq))				\
		if (!desc)						\
			;						\
		else
#define for_each_irq_nr(irq)                   \
       for (irq = 0; irq < nr_irqs; irq++)
#define IRQ_RETVAL(x)	((x) ? IRQ_HANDLED : IRQ_NONE)

#define MAX_PER_NAMESPACE_UCOUNTS UCOUNT_RLIMIT_NPROC
#define UID_GID_MAP_MAX_BASE_EXTENTS 5
#define UID_GID_MAP_MAX_EXTENTS 340
#define USERNS_INIT_FLAGS USERNS_SETGROUPS_ALLOWED
#define USERNS_SETGROUPS_ALLOWED 1UL



#define DEFINE_PROC_SHOW_ATTRIBUTE(__name)				\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, PDE_DATA(inode));	\
}									\
									\
static const struct proc_ops __name ## _proc_ops = {			\
	.proc_open	= __name ## _open,				\
	.proc_read	= seq_read,					\
	.proc_lseek	= seq_lseek,					\
	.proc_release	= single_release,				\
}
#define DEFINE_SEQ_ATTRIBUTE(__name)					\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	int ret = seq_open(file, &__name ## _sops);			\
	if (!ret && inode->i_private) {					\
		struct seq_file *seq_f = file->private_data;		\
		seq_f->private = inode->i_private;			\
	}								\
	return ret;							\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.owner		= THIS_MODULE,					\
	.open		= __name ## _open,				\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= seq_release,					\
}
#define DEFINE_SHOW_ATTRIBUTE(__name)					\
static int __name ## _open(struct inode *inode, struct file *file)	\
{									\
	return single_open(file, __name ## _show, inode->i_private);	\
}									\
									\
static const struct file_operations __name ## _fops = {			\
	.owner		= THIS_MODULE,					\
	.open		= __name ## _open,				\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= single_release,				\
}
#define SEQ_SKIP 1
#define SEQ_START_TOKEN ((void *)1)

#define seq_show_option_n(m, name, value, length) {	\
	char val_buf[length + 1];			\
	strncpy(val_buf, value, length);		\
	val_buf[length] = '\0';				\
	seq_show_option(m, name, val_buf);		\
}
#define FC_APPID_LEN              129

#define blk_queue_for_each_rl(rl, q)	\
	for ((rl) = &(q)->root_rl; (rl); (rl) = NULL)
#define blkg_for_each_descendant_post(d_blkg, pos_css, p_blkg)		\
	css_for_each_descendant_post((pos_css), &(p_blkg)->blkcg->css)	\
		if (((d_blkg) = __blkg_lookup(css_to_blkcg(pos_css),	\
					      (p_blkg)->q, false)))
#define blkg_for_each_descendant_pre(d_blkg, pos_css, p_blkg)		\
	css_for_each_descendant_pre((pos_css), &(p_blkg)->blkcg->css)	\
		if (((d_blkg) = __blkg_lookup(css_to_blkcg(pos_css),	\
					      (p_blkg)->q, false)))
#define BLK_ALL_ZONES  ((unsigned int)-1)
#define BLK_MQ_POLL_CLASSIC -1
#define BLK_MQ_POLL_STATS_BKTS 16
#define BLK_TAG_ALLOC_FIFO 0 
#define BLK_TAG_ALLOC_RR 1 
#define MODULE_ALIAS_BLOCKDEV(major,minor) \
	MODULE_ALIAS("block-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_BLOCKDEV_MAJOR(major) \
	MODULE_ALIAS("block-major-" __stringify(major) "-*")
#define QUEUE_FLAG_NOMERGES     3	
#define QUEUE_FLAG_NOWAIT       29	
#define QUEUE_FLAG_RQ_ALLOC_TIME 27	
#define QUEUE_FLAG_SCSI_PASSTHROUGH 23	
#define QUEUE_FLAG_STABLE_WRITES 15	
#define QUEUE_FLAG_ZONE_RESETALL 26	
#define RQF_NOMERGE_FLAGS \
	(RQF_STARTED | RQF_SOFTBARRIER | RQF_FLUSH_SEQ | RQF_SPECIAL_PAYLOAD)
#define SECTOR_SHIFT 9
#define SECTOR_SIZE (1 << SECTOR_SHIFT)

#define __rq_for_each_bio(_bio, rq)	\
	if ((rq->bio))			\
		for (_bio = (rq)->bio; _bio; _bio = _bio->bi_next)
#define blk_noretry_request(rq) \
	((rq)->cmd_flags & (REQ_FAILFAST_DEV|REQ_FAILFAST_TRANSPORT| \
			     REQ_FAILFAST_DRIVER))
#define blk_queue_add_random(q)	test_bit(QUEUE_FLAG_ADD_RANDOM, &(q)->queue_flags)
#define blk_queue_dax(q)	test_bit(QUEUE_FLAG_DAX, &(q)->queue_flags)
#define blk_queue_dead(q)	test_bit(QUEUE_FLAG_DEAD, &(q)->queue_flags)
#define blk_queue_discard(q)	test_bit(QUEUE_FLAG_DISCARD, &(q)->queue_flags)
#define blk_queue_dying(q)	test_bit(QUEUE_FLAG_DYING, &(q)->queue_flags)
#define blk_queue_fua(q)	test_bit(QUEUE_FLAG_FUA, &(q)->queue_flags)
#define blk_queue_init_done(q)	test_bit(QUEUE_FLAG_INIT_DONE, &(q)->queue_flags)
#define blk_queue_io_stat(q)	test_bit(QUEUE_FLAG_IO_STAT, &(q)->queue_flags)
#define blk_queue_nomerges(q)	test_bit(QUEUE_FLAG_NOMERGES, &(q)->queue_flags)
#define blk_queue_nonrot(q)	test_bit(QUEUE_FLAG_NONROT, &(q)->queue_flags)
#define blk_queue_nowait(q)	test_bit(QUEUE_FLAG_NOWAIT, &(q)->queue_flags)
#define blk_queue_noxmerges(q)	\
	test_bit(QUEUE_FLAG_NOXMERGES, &(q)->queue_flags)
#define blk_queue_pci_p2pdma(q)	\
	test_bit(QUEUE_FLAG_PCI_P2PDMA, &(q)->queue_flags)
#define blk_queue_pm_only(q)	atomic_read(&(q)->pm_only)
#define blk_queue_quiesced(q)	test_bit(QUEUE_FLAG_QUIESCED, &(q)->queue_flags)
#define blk_queue_registered(q)	test_bit(QUEUE_FLAG_REGISTERED, &(q)->queue_flags)
#define blk_queue_rq_alloc_time(q)	\
	test_bit(QUEUE_FLAG_RQ_ALLOC_TIME, &(q)->queue_flags)
#define blk_queue_scsi_passthrough(q)	\
	test_bit(QUEUE_FLAG_SCSI_PASSTHROUGH, &(q)->queue_flags)
#define blk_queue_secure_erase(q) \
	(test_bit(QUEUE_FLAG_SECERASE, &(q)->queue_flags))
#define blk_queue_stable_writes(q) \
	test_bit(QUEUE_FLAG_STABLE_WRITES, &(q)->queue_flags)
#define blk_queue_stopped(q)	test_bit(QUEUE_FLAG_STOPPED, &(q)->queue_flags)
#define blk_queue_zone_resetall(q)	\
	test_bit(QUEUE_FLAG_ZONE_RESETALL, &(q)->queue_flags)
#define blkdev_compat_ptr_ioctl NULL
#define dma_map_bvec(dev, bv, dir, attrs) \
	dma_map_page_attrs(dev, (bv)->bv_page, (bv)->bv_offset, (bv)->bv_len, \
	(dir), (attrs))
#define for_each_bio(_bio)		\
	for (; _bio; _bio = _bio->bi_next)
#define list_entry_rq(ptr)	list_entry((ptr), struct request, queuelist)
#define rq_data_dir(rq)		(op_is_write(req_op(rq)) ? WRITE : READ)
#define rq_dma_dir(rq) \
	(op_is_write(req_op(rq)) ? DMA_TO_DEVICE : DMA_FROM_DEVICE)
#define rq_for_each_bvec(bvl, _rq, _iter)			\
	__rq_for_each_bio(_iter.bio, _rq)			\
		bio_for_each_bvec(bvl, _iter.bio, _iter.iter)
#define rq_for_each_segment(bvl, _rq, _iter)			\
	__rq_for_each_bio(_iter.bio, _rq)			\
		bio_for_each_segment(bvl, _iter.bio, _iter.iter)
#define rq_iter_last(bvec, _iter)				\
		(_iter.bio->bi_next == NULL &&			\
		 bio_iter_last(bvec, _iter.iter))
#define ELV_HASH_BITS 6

#define rb_entry_rq(node)	rb_entry((node), struct request, rb_node)
#define rq_end_sector(rq)	(blk_rq_pos(rq) + blk_rq_sectors(rq))
#define rq_entry_fifo(ptr)	list_entry((ptr), struct request, queuelist)
#define rq_fifo_clear(rq)	list_del_init(&(rq)->queuelist)
#define DECLARE_HASHTABLE(name, bits)                                   	\
	struct hlist_head name[1 << (bits)]
#define DEFINE_HASHTABLE(name, bits)						\
	struct hlist_head name[1 << (bits)] =					\
			{ [0 ... ((1 << (bits)) - 1)] = HLIST_HEAD_INIT }
#define DEFINE_READ_MOSTLY_HASHTABLE(name, bits)				\
	struct hlist_head name[1 << (bits)] __read_mostly =			\
			{ [0 ... ((1 << (bits)) - 1)] = HLIST_HEAD_INIT }
#define HASH_BITS(name) ilog2(HASH_SIZE(name))
#define HASH_SIZE(name) (ARRAY_SIZE(name))

#define hash_add(hashtable, node, key)						\
	hlist_add_head(node, &hashtable[hash_min(key, HASH_BITS(hashtable))])
#define hash_add_rcu(hashtable, node, key)					\
	hlist_add_head_rcu(node, &hashtable[hash_min(key, HASH_BITS(hashtable))])
#define hash_empty(hashtable) __hash_empty(hashtable, HASH_SIZE(hashtable))
#define hash_for_each(name, bkt, obj, member)				\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_entry(obj, &name[bkt], member)
#define hash_for_each_possible(name, obj, member, key)			\
	hlist_for_each_entry(obj, &name[hash_min(key, HASH_BITS(name))], member)
#define hash_for_each_possible_rcu(name, obj, member, key, cond...)	\
	hlist_for_each_entry_rcu(obj, &name[hash_min(key, HASH_BITS(name))],\
		member, ## cond)
#define hash_for_each_possible_rcu_notrace(name, obj, member, key) \
	hlist_for_each_entry_rcu_notrace(obj, \
		&name[hash_min(key, HASH_BITS(name))], member)
#define hash_for_each_possible_safe(name, obj, tmp, member, key)	\
	hlist_for_each_entry_safe(obj, tmp,\
		&name[hash_min(key, HASH_BITS(name))], member)
#define hash_for_each_rcu(name, bkt, obj, member)			\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_entry_rcu(obj, &name[bkt], member)
#define hash_for_each_safe(name, bkt, tmp, obj, member)			\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_entry_safe(obj, tmp, &name[bkt], member)
#define hash_init(hashtable) __hash_init(hashtable, HASH_SIZE(hashtable))
#define hash_min(val, bits)							\
	(sizeof(val) <= 4 ? hash_32(val, bits) : hash_long(val, bits))
#define DEFINE_SBQ_WAIT(name)							\
	struct sbq_wait name = {						\
		.sbq = NULL,							\
		.wait = {							\
			.private	= current,				\
			.func		= autoremove_wake_function,		\
			.entry		= LIST_HEAD_INIT((name).wait.entry),	\
		}								\
	}
#define SBQ_WAIT_QUEUES 8
#define SBQ_WAKE_BATCH 8
#define SB_NR_TO_BIT(sb, bitnr) ((bitnr) & ((1U << (sb)->shift) - 1U))
#define SB_NR_TO_INDEX(sb, bitnr) ((bitnr) >> (sb)->shift)


#define blk_alloc_disk(node_id)						\
({									\
	static struct lock_class_key __key;				\
									\
	__blk_alloc_disk(node_id, &__key);				\
})
#define dev_to_disk(device) \
	(dev_to_bdev(device)->bd_disk)
#define disk_to_cdi(disk)	((disk)->cdi)
#define disk_to_dev(disk) \
	(&((disk)->part0->bd_device))
#define register_blkdev(major, name) \
	__register_blkdev(major, name, NULL)

#define DEFINE_WB_COMPLETION(cmpl, bdi)	\
	struct wb_completion cmpl = WB_COMPLETION_INIT(bdi)
#define WB_COMPLETION_INIT(bdi)		__WB_COMPLETION_INIT(&(bdi)->wb_waitq)
#define WB_STAT_BATCH (8*(1+ilog2(nr_cpu_ids)))

#define __WB_COMPLETION_INIT(_waitq)	\
	(struct wb_completion){ .cnt = ATOMIC_INIT(1), .waitq = (_waitq) }
#define FPROP_FRAC_BASE (1UL << FPROP_FRAC_SHIFT)
#define FPROP_FRAC_SHIFT 10
#define INIT_FPROP_LOCAL_SINGLE(name)			\
{	.lock = __RAW_SPIN_LOCK_UNLOCKED(name.lock),	\
}

#define EFD_CLOEXEC O_CLOEXEC
#define EFD_FLAGS_SET (EFD_SHARED_FCNTL_FLAGS | EFD_SEMAPHORE)
#define EFD_NONBLOCK O_NONBLOCK
#define EFD_SEMAPHORE (1 << 0)
#define EFD_SHARED_FCNTL_FLAGS (O_CLOEXEC | O_NONBLOCK)


#define PAGE_COUNTER_MAX LONG_MAX


#define POWER_SUPPLY_OCV_TEMP_MAX 20

#define to_power_supply(device) container_of(device, struct power_supply, dev)
#define DEFINE_LED_TRIGGER(x)		static struct led_trigger *x;
#define DEFINE_LED_TRIGGER_GLOBAL(x)	struct led_trigger *x;
#define LED_BLINK_BRIGHTNESS_CHANGE 	4
#define LED_INIT_DEFAULT_TRIGGER BIT(23)
#define TRIG_NAME_MAX 50

#define led_trigger_get_drvdata(dev)	(led_get_trigger_data(led_trigger_get_led(dev)))
#define led_trigger_get_led(dev)	((struct led_classdev *)dev_get_drvdata((dev)))
#define module_led_trigger(__led_trigger) \
	module_driver(__led_trigger, led_trigger_register, \
		      led_trigger_unregister)
#define LED_FUNCTION_ACTIVITY "activity"
#define LED_FUNCTION_ALARM "alarm"
#define LED_FUNCTION_BACKLIGHT "backlight"
#define LED_FUNCTION_BLUETOOTH "bluetooth"
#define LED_FUNCTION_BOOT "boot"
#define LED_FUNCTION_CAPSLOCK "capslock"
#define LED_FUNCTION_CHARGING "charging"
#define LED_FUNCTION_CPU "cpu"
#define LED_FUNCTION_DEBUG "debug"
#define LED_FUNCTION_DISK "disk"
#define LED_FUNCTION_DISK_ACTIVITY "disk-activity"
#define LED_FUNCTION_DISK_ERR "disk-err"
#define LED_FUNCTION_DISK_READ "disk-read"
#define LED_FUNCTION_DISK_WRITE "disk-write"
#define LED_FUNCTION_FAULT "fault"
#define LED_FUNCTION_FLASH "flash"
#define LED_FUNCTION_HEARTBEAT "heartbeat"
#define LED_FUNCTION_INDICATOR "indicator"
#define LED_FUNCTION_KBD_BACKLIGHT "kbd_backlight"
#define LED_FUNCTION_LAN "lan"
#define LED_FUNCTION_MAIL "mail"
#define LED_FUNCTION_MICMUTE "micmute"
#define LED_FUNCTION_MTD "mtd"
#define LED_FUNCTION_MUTE "mute"
#define LED_FUNCTION_NUMLOCK "numlock"
#define LED_FUNCTION_PANIC "panic"
#define LED_FUNCTION_POWER "power"
#define LED_FUNCTION_PROGRAMMING "programming"
#define LED_FUNCTION_RX "rx"
#define LED_FUNCTION_SCROLLLOCK "scrolllock"
#define LED_FUNCTION_SD "sd"
#define LED_FUNCTION_STANDBY "standby"
#define LED_FUNCTION_STATUS "status"
#define LED_FUNCTION_TORCH "torch"
#define LED_FUNCTION_TX "tx"
#define LED_FUNCTION_USB "usb"
#define LED_FUNCTION_WAN "wan"
#define LED_FUNCTION_WLAN "wlan"
#define LED_FUNCTION_WPS "wps"



#define dmi_available 0
#define ARCH_PAGE_TABLE_SYNC_MASK 0
#define VMALLOC_TOTAL (VMALLOC_END - VMALLOC_START)

#define ACPI_COMPANION(dev)		to_acpi_device_node((dev)->fwnode)
#define ACPI_COMPANION_SET(dev, adev)	set_primary_fwnode(dev, (adev) ? \
	acpi_fwnode_handle(adev) : NULL)
#define ACPI_DECLARE_PROBE_ENTRY(table, name, table_id, subtable,	\
				 valid, data, fn)			\
	static const struct acpi_probe_entry __acpi_probe_##name	\
		__used __section("__" #table "_acpi_probe_table") = {	\
			.id = table_id,					\
			.type = subtable,				\
			.subtable_valid = valid,			\
			.probe_table = fn,				\
			.driver_data = data,				\
		}
#define ACPI_DECLARE_SUBTABLE_PROBE_ENTRY(table, name, table_id,	\
					  subtable, valid, data, fn)	\
	static const struct acpi_probe_entry __acpi_probe_##name	\
		__used __section("__" #table "_acpi_probe_table") = {	\
			.id = table_id,					\
			.type = subtable,				\
			.subtable_valid = valid,			\
			.probe_subtbl = fn,				\
			.driver_data = data,				\
		}
#define ACPI_DEVICE_CLASS(_cls, _msk)	.cls = (0), .cls_msk = (0),
#define ACPI_GSB_ACCESS_ATTRIB_SEND_RCV         0x00000004
#define ACPI_HANDLE(dev)		acpi_device_handle(ACPI_COMPANION(dev))
#define ACPI_HANDLE_FWNODE(fwnode)	\
				acpi_device_handle(to_acpi_device_node(fwnode))

#define ACPI_PROBE_TABLE(name)		__##name##_acpi_probe_table
#define ACPI_PROBE_TABLE_END(name)	__##name##_acpi_probe_table_end
#define ACPI_PTR(_ptr)	(_ptr)
#define BAD_MADT_ENTRY(entry, end) (					    \
		(!entry) || (unsigned long)entry + sizeof(*entry) > end ||  \
		((struct acpi_subtable_header *)entry)->length < sizeof(*entry))
#define PHYS_CPUID_INVALID (phys_cpuid_t)(-1)


#define acpi_disabled 1
#define acpi_handle_alert(handle, fmt, ...)				\
	acpi_handle_printk(KERN_ALERT, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_crit(handle, fmt, ...)				\
	acpi_handle_printk(KERN_CRIT, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_debug(handle, fmt, ...)				\
	acpi_handle_printk(KERN_DEBUG, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_emerg(handle, fmt, ...)				\
	acpi_handle_printk(KERN_EMERG, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_err(handle, fmt, ...)				\
	acpi_handle_printk(KERN_ERR, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_info(handle, fmt, ...)				\
	acpi_handle_printk(KERN_INFO, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_notice(handle, fmt, ...)				\
	acpi_handle_printk(KERN_NOTICE, handle, fmt, ##__VA_ARGS__)
#define acpi_handle_warn(handle, fmt, ...)				\
	acpi_handle_printk(KERN_WARNING, handle, fmt, ##__VA_ARGS__)
#define acpi_os_set_prepare_sleep(func, pm1a_ctrl, pm1b_ctrl) do { } while (0)
#define acpi_probe_device_table(t)					\
	({ 								\
		extern struct acpi_probe_entry ACPI_PROBE_TABLE(t),	\
			                       ACPI_PROBE_TABLE_END(t);	\
		__acpi_probe_device_table(&ACPI_PROBE_TABLE(t),		\
					  (&ACPI_PROBE_TABLE_END(t) -	\
					   &ACPI_PROBE_TABLE(t)));	\
	})
#define MAX_PXM_DOMAINS MAX_NUMNODES


#define IOMEM_ERR_PTR(err) (__force void __iomem *)ERR_PTR(err)

#define arch_has_dev_port()     (1)
#define arch_phys_wc_add arch_phys_wc_add
#define arch_phys_wc_index arch_phys_wc_index
#define pci_remap_cfgspace pci_remap_cfgspace


#define acpi_device_adr(d)	((d)->pnp.bus_address)
#define acpi_device_bid(d)	((d)->pnp.bus_id)
#define acpi_device_class(d)	((d)->pnp.device_class)
#define acpi_device_dir(d)	((d)->dir.entry)
#define acpi_device_name(d)	((d)->pnp.device_name)
#define acpi_device_uid(d)	((d)->pnp.unique_id)
#define for_each_acpi_dev_match(adev, hid, uid, hrv)			\
	for (adev = acpi_dev_get_first_match_dev(hid, uid, hrv);	\
	     adev;							\
	     adev = acpi_dev_get_next_match_dev(adev, hid, uid, hrv))
#define module_acpi_driver(__acpi_driver) \
	module_driver(__acpi_driver, acpi_bus_register_driver, \
		      acpi_bus_unregister_driver)
#define to_acpi_data_node(__fwnode)					\
	({								\
		typeof(__fwnode) __to_acpi_data_node_fwnode = __fwnode;	\
									\
		is_acpi_data_node(__to_acpi_data_node_fwnode) ?		\
			container_of(__to_acpi_data_node_fwnode,	\
				     struct acpi_data_node, fwnode) :	\
			NULL;						\
	})
#define to_acpi_device(d)	container_of(d, struct acpi_device, dev)
#define to_acpi_device_node(__fwnode)					\
	({								\
		typeof(__fwnode) __to_acpi_device_node_fwnode = __fwnode; \
									\
		is_acpi_device_node(__to_acpi_device_node_fwnode) ?	\
			container_of(__to_acpi_device_node_fwnode,	\
				     struct acpi_device, fwnode) :	\
			NULL;						\
	})
#define to_acpi_driver(d)	container_of(d, struct acpi_driver, drv)

#define ACPI_APP_DEPENDENT_RETURN_VOID(prototype) \
	prototype;
#define ACPI_CA_VERSION                 0x20210730
#define ACPI_DBG_DEPENDENT_RETURN_VOID(prototype) \
	prototype;
#define ACPI_DBR_DEPENDENT_RETURN_OK(prototype) \
	ACPI_EXTERNAL_RETURN_OK(prototype)
#define ACPI_DBR_DEPENDENT_RETURN_VOID(prototype) \
	ACPI_EXTERNAL_RETURN_VOID(prototype)
#define ACPI_EXTERNAL_RETURN_OK(prototype) \
	prototype;
#define ACPI_EXTERNAL_RETURN_PTR(prototype) \
	prototype;
#define ACPI_EXTERNAL_RETURN_STATUS(prototype) \
	prototype;
#define ACPI_EXTERNAL_RETURN_UINT32(prototype) \
	prototype;
#define ACPI_EXTERNAL_RETURN_VOID(prototype) \
	prototype;
#define ACPI_GLOBAL(type,name) \
	extern type name; \
	type name
#define ACPI_HW_DEPENDENT_RETURN_OK(prototype) \
	ACPI_EXTERNAL_RETURN_OK(prototype)
#define ACPI_HW_DEPENDENT_RETURN_STATUS(prototype) \
	ACPI_EXTERNAL_RETURN_STATUS(prototype)
#define ACPI_HW_DEPENDENT_RETURN_UINT32(prototype) \
	ACPI_EXTERNAL_RETURN_UINT32(prototype)
#define ACPI_HW_DEPENDENT_RETURN_VOID(prototype) \
	ACPI_EXTERNAL_RETURN_VOID(prototype)
#define ACPI_INIT_GLOBAL(type,name,value) \
	type name=value
#define ACPI_MSG_DEPENDENT_RETURN_VOID(prototype) \
	prototype;

#define ACPI_PLD_BUFFER_SIZE                    20	
#define ACPI_PLD_GET_BAY(dword)                 ACPI_GET_BITS (dword, 31, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_BLUE(dword)                ACPI_GET_BITS (dword, 24, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_CABINET(dword)             ACPI_GET_BITS (dword, 2, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_CARD_CAGE(dword)           ACPI_GET_BITS (dword, 10, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_DOCK(dword)                ACPI_GET_BITS (dword, 1, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_EJECTABLE(dword)           ACPI_GET_BITS (dword, 0, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_GREEN(dword)               ACPI_GET_BITS (dword, 16, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_HEIGHT(dword)              ACPI_GET_BITS (dword, 16, ACPI_16BIT_MASK)
#define ACPI_PLD_GET_HORIZONTAL(dword)          ACPI_GET_BITS (dword, 8, ACPI_2BIT_MASK)
#define ACPI_PLD_GET_HORIZ_OFFSET(dword)        ACPI_GET_BITS (dword, 16, ACPI_16BIT_MASK)
#define ACPI_PLD_GET_IGNORE_COLOR(dword)        ACPI_GET_BITS (dword, 7, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_LID(dword)                 ACPI_GET_BITS (dword, 2, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_ORDER(dword)               ACPI_GET_BITS (dword, 23, ACPI_5BIT_MASK)
#define ACPI_PLD_GET_ORIENTATION(dword)         ACPI_GET_BITS (dword, 14, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_OSPM_EJECT(dword)          ACPI_GET_BITS (dword, 1, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_PANEL(dword)               ACPI_GET_BITS (dword, 3, ACPI_3BIT_MASK)
#define ACPI_PLD_GET_POSITION(dword)            ACPI_GET_BITS (dword, 23, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_RED(dword)                 ACPI_GET_BITS (dword, 8, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_REFERENCE(dword)           ACPI_GET_BITS (dword, 18, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_REVISION(dword)            ACPI_GET_BITS (dword, 0, ACPI_7BIT_MASK)
#define ACPI_PLD_GET_ROTATION(dword)            ACPI_GET_BITS (dword, 19, ACPI_4BIT_MASK)
#define ACPI_PLD_GET_SHAPE(dword)               ACPI_GET_BITS (dword, 10, ACPI_4BIT_MASK)
#define ACPI_PLD_GET_TOKEN(dword)               ACPI_GET_BITS (dword, 15, ACPI_8BIT_MASK)
#define ACPI_PLD_GET_USER_VISIBLE(dword)        ACPI_GET_BITS (dword, 0, ACPI_1BIT_MASK)
#define ACPI_PLD_GET_VERTICAL(dword)            ACPI_GET_BITS (dword, 6, ACPI_2BIT_MASK)
#define ACPI_PLD_GET_VERT_OFFSET(dword)         ACPI_GET_BITS (dword, 0, ACPI_16BIT_MASK)
#define ACPI_PLD_GET_WIDTH(dword)               ACPI_GET_BITS (dword, 0, ACPI_16BIT_MASK)
#define ACPI_PLD_PANEL_BACK     5
#define ACPI_PLD_PANEL_BOTTOM   1
#define ACPI_PLD_PANEL_FRONT    4
#define ACPI_PLD_PANEL_LEFT     2
#define ACPI_PLD_PANEL_RIGHT    3
#define ACPI_PLD_PANEL_TOP      0
#define ACPI_PLD_PANEL_UNKNOWN  6
#define ACPI_PLD_REV1_BUFFER_SIZE               16	
#define ACPI_PLD_REV2_BUFFER_SIZE               20	
#define ACPI_PLD_SET_BAY(dword,value)           ACPI_SET_BITS (dword, 31, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_BLUE(dword,value)          ACPI_SET_BITS (dword, 24, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_CABINET(dword,value)       ACPI_SET_BITS (dword, 2, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_CARD_CAGE(dword,value)     ACPI_SET_BITS (dword, 10, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_DOCK(dword,value)          ACPI_SET_BITS (dword, 1, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_EJECTABLE(dword,value)     ACPI_SET_BITS (dword, 0, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_GREEN(dword,value)         ACPI_SET_BITS (dword, 16, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_HEIGHT(dword,value)        ACPI_SET_BITS (dword, 16, ACPI_16BIT_MASK, value)	
#define ACPI_PLD_SET_HORIZONTAL(dword,value)    ACPI_SET_BITS (dword, 8, ACPI_2BIT_MASK, value)	
#define ACPI_PLD_SET_HORIZ_OFFSET(dword,value)  ACPI_SET_BITS (dword, 16, ACPI_16BIT_MASK, value)	
#define ACPI_PLD_SET_IGNORE_COLOR(dword,value)  ACPI_SET_BITS (dword, 7, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_LID(dword,value)           ACPI_SET_BITS (dword, 2, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_ORDER(dword,value)         ACPI_SET_BITS (dword, 23, ACPI_5BIT_MASK, value)	
#define ACPI_PLD_SET_ORIENTATION(dword,value)   ACPI_SET_BITS (dword, 14, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_OSPM_EJECT(dword,value)    ACPI_SET_BITS (dword, 1, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_PANEL(dword,value)         ACPI_SET_BITS (dword, 3, ACPI_3BIT_MASK, value)	
#define ACPI_PLD_SET_POSITION(dword,value)      ACPI_SET_BITS (dword, 23, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_RED(dword,value)           ACPI_SET_BITS (dword, 8, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_REFERENCE(dword,value)     ACPI_SET_BITS (dword, 18, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_REVISION(dword,value)      ACPI_SET_BITS (dword, 0, ACPI_7BIT_MASK, value)	
#define ACPI_PLD_SET_ROTATION(dword,value)      ACPI_SET_BITS (dword, 19, ACPI_4BIT_MASK, value)	
#define ACPI_PLD_SET_SHAPE(dword,value)         ACPI_SET_BITS (dword, 10, ACPI_4BIT_MASK, value)	
#define ACPI_PLD_SET_TOKEN(dword,value)         ACPI_SET_BITS (dword, 15, ACPI_8BIT_MASK, value)	
#define ACPI_PLD_SET_USER_VISIBLE(dword,value)  ACPI_SET_BITS (dword, 0, ACPI_1BIT_MASK, value)	
#define ACPI_PLD_SET_VERTICAL(dword,value)      ACPI_SET_BITS (dword, 6, ACPI_2BIT_MASK, value)	
#define ACPI_PLD_SET_VERT_OFFSET(dword,value)   ACPI_SET_BITS (dword, 0, ACPI_16BIT_MASK, value)	
#define ACPI_PLD_SET_WIDTH(dword,value)         ACPI_SET_BITS (dword, 0, ACPI_16BIT_MASK, value)	

#define ACPI_FACS_64BIT_ENVIRONMENT (1)	
#define ACPI_FACS_64BIT_WAKE        (1<<1)	
#define ACPI_FACS_S4_BIOS_PRESENT   (1)	
#define ACPI_FADT_32BIT_TIMER       (1<<8)	
#define ACPI_FADT_8042              (1<<1)	
#define ACPI_FADT_APIC_CLUSTER      (1<<18)	
#define ACPI_FADT_APIC_PHYSICAL     (1<<19)	
#define ACPI_FADT_C1_SUPPORTED      (1<<2)	
#define ACPI_FADT_C2_MP_SUPPORTED   (1<<3)	
#define ACPI_FADT_CONFORMANCE   "ACPI 6.1 (FADT version 6)"
#define ACPI_FADT_DOCKING_SUPPORTED (1<<9)	
#define ACPI_FADT_FIXED_RTC         (1<<6)	
#define ACPI_FADT_HEADLESS          (1<<12)	
#define ACPI_FADT_HW_REDUCED        (1<<20)	
#define ACPI_FADT_LEGACY_DEVICES    (1)  	
#define ACPI_FADT_LOW_POWER_S0      (1<<21)	
#define ACPI_FADT_NO_ASPM           (1<<4)	
#define ACPI_FADT_NO_CMOS_RTC       (1<<5)	
#define ACPI_FADT_NO_MSI            (1<<3)	
#define ACPI_FADT_NO_VGA            (1<<2)	
#define ACPI_FADT_OFFSET(f)             (u16) ACPI_OFFSET (struct acpi_table_fadt, f)
#define ACPI_FADT_PCI_EXPRESS_WAKE  (1<<14)	
#define ACPI_FADT_PLATFORM_CLOCK    (1<<15)	
#define ACPI_FADT_POWER_BUTTON      (1<<4)	
#define ACPI_FADT_PSCI_COMPLIANT    (1)	
#define ACPI_FADT_PSCI_USE_HVC      (1<<1)	
#define ACPI_FADT_REMOTE_POWER_ON   (1<<17)	
#define ACPI_FADT_RESET_REGISTER    (1<<10)	
#define ACPI_FADT_S4_RTC_VALID      (1<<16)	
#define ACPI_FADT_S4_RTC_WAKE       (1<<7)	
#define ACPI_FADT_SEALED_CASE       (1<<11)	
#define ACPI_FADT_SLEEP_BUTTON      (1<<5)	
#define ACPI_FADT_SLEEP_TYPE        (1<<13)	
#define ACPI_FADT_V1_SIZE       (u32) (ACPI_FADT_OFFSET (flags) + 4)
#define ACPI_FADT_V2_SIZE       (u32) (ACPI_FADT_OFFSET (minor_revision) + 1)
#define ACPI_FADT_V3_SIZE       (u32) (ACPI_FADT_OFFSET (sleep_control))
#define ACPI_FADT_V5_SIZE       (u32) (ACPI_FADT_OFFSET (hypervisor_id))
#define ACPI_FADT_V6_SIZE       (u32) (sizeof (struct acpi_table_fadt))
#define ACPI_FADT_WBINVD            (1)	
#define ACPI_FADT_WBINVD_FLUSH      (1<<1)	
#define ACPI_GLOCK_OWNED            (1<<1)	
#define ACPI_GLOCK_PENDING          (1)	
#define ACPI_MAX_TABLE_VALIDATIONS          ACPI_UINT16_MAX
#define ACPI_OEM_NAME           "OEM"	
#define ACPI_RSDP_NAME          "RSDP"	
#define ACPI_RSDT_ENTRY_SIZE        (sizeof (u32))
#define ACPI_SIG_DSDT           "DSDT"	
#define ACPI_SIG_FACS           "FACS"	
#define ACPI_SIG_FADT           "FACP"	
#define ACPI_SIG_OSDT           "OSDT"	
#define ACPI_SIG_PSDT           "PSDT"	
#define ACPI_SIG_RSDP           "RSD PTR "	
#define ACPI_SIG_RSDT           "RSDT"	
#define ACPI_SIG_SSDT           "SSDT"	
#define ACPI_SIG_XSDT           "XSDT"	
#define ACPI_TABLE_IS_LOADED                (8)
#define ACPI_TABLE_IS_VERIFIED              (4)
#define ACPI_TABLE_ORIGIN_EXTERNAL_VIRTUAL  (0)	
#define ACPI_TABLE_ORIGIN_INTERNAL_PHYSICAL (1)	
#define ACPI_TABLE_ORIGIN_INTERNAL_VIRTUAL  (2)	
#define ACPI_TABLE_ORIGIN_MASK              (3)
#define ACPI_XSDT_ENTRY_SIZE        (sizeof (u64))
#define ACPI_X_SLEEP_ENABLE         0x20
#define ACPI_X_SLEEP_TYPE_MASK      0x1C
#define ACPI_X_SLEEP_TYPE_POSITION  0x02
#define ACPI_X_WAKE_STATUS          0x80
#define FADT2_REVISION_ID               3

#define ACPI_SIG_SLIC           "SLIC"	
#define ACPI_SIG_SLIT           "SLIT"	
#define ACPI_SIG_SPCR           "SPCR"	
#define ACPI_SIG_SPMI           "SPMI"	
#define ACPI_SIG_SRAT           "SRAT"	
#define ACPI_SIG_STAO           "STAO"	
#define ACPI_SIG_TCPA           "TCPA"	
#define ACPI_SIG_TPM2           "TPM2"	
#define ACPI_SIG_UEFI           "UEFI"	
#define ACPI_SIG_VIOT           "VIOT"	
#define ACPI_SIG_WAET           "WAET"	
#define ACPI_SIG_WDAT           "WDAT"	
#define ACPI_SIG_WDDT           "WDDT"	
#define ACPI_SIG_WDRT           "WDRT"	
#define ACPI_SIG_WPBT           "WPBT"	
#define ACPI_SIG_WSMT           "WSMT"	
#define ACPI_SIG_XENV           "XENV"	
#define ACPI_SIG_XXXX           "XXXX"	
#define ACPI_SPCR_DO_NOT_DISABLE    (1)
#define ACPI_SRAT_ARCHITECTURAL_TRANSACTIONS   (1<<1)	
#define ACPI_SRAT_CPU_ENABLED       (1)	
#define ACPI_SRAT_CPU_USE_AFFINITY  (1)	
#define ACPI_SRAT_GENERIC_AFFINITY_ENABLED     (1)	
#define ACPI_SRAT_GICC_ENABLED     (1)	
#define ACPI_SRAT_MEM_ENABLED       (1)	
#define ACPI_SRAT_MEM_HOT_PLUGGABLE (1<<1)	
#define ACPI_SRAT_MEM_NON_VOLATILE  (1<<2)	
#define ACPI_TCPA_ADDRESS_VALID         (1<<2)
#define ACPI_TCPA_BUS_PNP               (1<<1)
#define ACPI_TCPA_CLIENT_TABLE          0
#define ACPI_TCPA_GLOBAL_INTERRUPT      (1<<3)
#define ACPI_TCPA_INTERRUPT_MODE        (1)
#define ACPI_TCPA_INTERRUPT_POLARITY    (1<<1)
#define ACPI_TCPA_PCI_DEVICE            (1)
#define ACPI_TCPA_SCI_VIA_GPE           (1<<2)
#define ACPI_TCPA_SERVER_TABLE          1
#define ACPI_TPM23_ACPI_START_METHOD                 2
#define ACPI_TPM2_COMMAND_BUFFER                    7
#define ACPI_TPM2_COMMAND_BUFFER_WITH_ARM_SMC       11	
#define ACPI_TPM2_COMMAND_BUFFER_WITH_START_METHOD  8
#define ACPI_TPM2_IDLE_SUPPORT          (1)
#define ACPI_TPM2_INTERRUPT_SUPPORT     (1)
#define ACPI_TPM2_MEMORY_MAPPED                     6
#define ACPI_TPM2_NOT_ALLOWED                       0
#define ACPI_TPM2_RESERVED                          12
#define ACPI_TPM2_RESERVED1                         1
#define ACPI_TPM2_RESERVED10                        10
#define ACPI_TPM2_RESERVED3                         3
#define ACPI_TPM2_RESERVED4                         4
#define ACPI_TPM2_RESERVED5                         5
#define ACPI_TPM2_RESERVED9                         9
#define ACPI_TPM2_START_METHOD                      2
#define ACPI_WAET_RTC_NO_ACK        (1)	
#define ACPI_WAET_TIMER_ONE_READ    (1<<1)	
#define ACPI_WDAT_ENABLED           (1)
#define ACPI_WDAT_STOPPED           0x80
#define ACPI_WDDT_ACTIVE        (1<<1)
#define ACPI_WDDT_ALERT_SUPPORT (1<<1)
#define ACPI_WDDT_AUTO_RESET    (1)
#define ACPI_WDDT_AVAILABLE     (1)
#define ACPI_WDDT_POWER_FAIL    (1<<13)
#define ACPI_WDDT_TCO_OS_OWNED  (1<<2)
#define ACPI_WDDT_UNKNOWN_RESET (1<<14)
#define ACPI_WDDT_USER_RESET    (1<<11)
#define ACPI_WDDT_WDT_RESET     (1<<12)
#define ACPI_WSMT_COMM_BUFFER_NESTED_PTR_PROTECTION (2)
#define ACPI_WSMT_FIXED_COMM_BUFFERS                (1)
#define ACPI_WSMT_SYSTEM_RESOURCE_PROTECTION        (4)

#define ACPI_AEST_CACHE_DATA                0
#define ACPI_AEST_CACHE_INSTRUCTION         1
#define ACPI_AEST_CACHE_RESERVED            3	
#define ACPI_AEST_CACHE_RESOURCE            0
#define ACPI_AEST_CACHE_UNIFIED             2
#define ACPI_AEST_GENERIC_RESOURCE          2
#define ACPI_AEST_GIC_CPU                   0
#define ACPI_AEST_GIC_DISTRIBUTOR           1
#define ACPI_AEST_GIC_ERROR_NODE            4
#define ACPI_AEST_GIC_ITS                   3
#define ACPI_AEST_GIC_REDISTRIBUTOR         2
#define ACPI_AEST_GIC_RESERVED              4	
#define ACPI_AEST_MEMORY_ERROR_NODE         1
#define ACPI_AEST_NODE_ERROR_RECOVERY       1
#define ACPI_AEST_NODE_FAULT_HANDLING       0
#define ACPI_AEST_NODE_MEMORY_MAPPED        1
#define ACPI_AEST_NODE_SYSTEM_REGISTER      0
#define ACPI_AEST_NODE_TYPE_RESERVED        5	
#define ACPI_AEST_PROCESSOR_ERROR_NODE      0
#define ACPI_AEST_RESOURCE_RESERVED         3	
#define ACPI_AEST_SMMU_ERROR_NODE           2
#define ACPI_AEST_TLB_RESOURCE              1
#define ACPI_AEST_VENDOR_ERROR_NODE         3
#define ACPI_AEST_XFACE_RESERVED            2	
#define ACPI_AEST_XRUPT_RESERVED            2	
#define ACPI_IORT_ATS_SUPPORTED         (1)	
#define ACPI_IORT_HT_OVERRIDE           (1<<3)
#define ACPI_IORT_HT_READ               (1<<2)
#define ACPI_IORT_HT_TRANSIENT          (1)
#define ACPI_IORT_HT_WRITE              (1<<1)
#define ACPI_IORT_ID_SINGLE_MAPPING (1)
#define ACPI_IORT_MF_ATTRIBUTES         (1<<1)
#define ACPI_IORT_MF_COHERENCY          (1)
#define ACPI_IORT_NC_PASID_BITS         (31<<1)
#define ACPI_IORT_NC_STALL_SUPPORTED    (1)
#define ACPI_IORT_NODE_COHERENT         0x00000001	
#define ACPI_IORT_NODE_NOT_COHERENT     0x00000000	
#define ACPI_IORT_PASID_FWD_SUPPORTED   (1<<2)	
#define ACPI_IORT_PRI_SUPPORTED         (1<<1)	
#define ACPI_IORT_SMMU_CAVIUM_THUNDERX  0x00000005	
#define ACPI_IORT_SMMU_COHERENT_WALK    (1<<1)
#define ACPI_IORT_SMMU_CORELINK_MMU400  0x00000002	
#define ACPI_IORT_SMMU_CORELINK_MMU401  0x00000004	
#define ACPI_IORT_SMMU_CORELINK_MMU500  0x00000003	
#define ACPI_IORT_SMMU_DVM_SUPPORTED    (1)
#define ACPI_IORT_SMMU_V1               0x00000000	
#define ACPI_IORT_SMMU_V2               0x00000001	
#define ACPI_IORT_SMMU_V3_CAVIUM_CN99XX     0x00000002	
#define ACPI_IORT_SMMU_V3_COHACC_OVERRIDE   (1)
#define ACPI_IORT_SMMU_V3_GENERIC           0x00000000	
#define ACPI_IORT_SMMU_V3_HISILICON_HI161X  0x00000001	
#define ACPI_IORT_SMMU_V3_HTTU_OVERRIDE     (3<<1)
#define ACPI_IORT_SMMU_V3_PXM_VALID         (1<<3)
#define ACPI_IVHD_ATS_DISABLED      (1<<31)
#define ACPI_IVHD_EINT_PASS         (1<<1)
#define ACPI_IVHD_ENTRY_LENGTH      0xC0
#define ACPI_IVHD_HPET              2
#define ACPI_IVHD_INIT_PASS         (1)
#define ACPI_IVHD_IOAPIC            1
#define ACPI_IVHD_IOTLB             (1<<4)
#define ACPI_IVHD_ISOC              (1<<3)
#define ACPI_IVHD_LINT0_PASS        (1<<6)
#define ACPI_IVHD_LINT1_PASS        (1<<7)
#define ACPI_IVHD_MSI_NUMBER_MASK   0x001F	
#define ACPI_IVHD_NMI_PASS          (1<<2)
#define ACPI_IVHD_PASS_PW           (1<<1)
#define ACPI_IVHD_RES_PASS_PW       (1<<2)
#define ACPI_IVHD_SYSTEM_MGMT       (3<<4)
#define ACPI_IVHD_TT_ENABLE         (1)
#define ACPI_IVHD_UNIT_ID_MASK      0x1F00	
#define ACPI_IVMD_EXCLUSION_RANGE   (1<<3)
#define ACPI_IVMD_READ              (1<<1)
#define ACPI_IVMD_UNITY             (1)
#define ACPI_IVMD_WRITE             (1<<2)
#define ACPI_IVRS_ATS_RESERVED      0x00400000	
#define ACPI_IVRS_PHYSICAL_SIZE     0x00007F00	
#define ACPI_IVRS_UID_IS_INTEGER    1
#define ACPI_IVRS_UID_IS_STRING     2
#define ACPI_IVRS_UID_NOT_PRESENT   0
#define ACPI_IVRS_VIRTUAL_SIZE      0x003F8000	
#define ACPI_LPIT_NO_COUNTER        (1<<1)
#define ACPI_LPIT_STATE_DISABLED    (1)
#define ACPI_MADT_CPEI_OVERRIDE     (1)
#define ACPI_MADT_DUAL_PIC          1
#define ACPI_MADT_ENABLED           (1)	
#define ACPI_MADT_MULTIPLE_APIC     0
#define ACPI_MADT_OVERRIDE_SPI_VALUES   (1)
#define ACPI_MADT_PCAT_COMPAT       (1)	
#define ACPI_MADT_PERFORMANCE_IRQ_MODE  (1<<1)	
#define ACPI_MADT_POLARITY_ACTIVE_HIGH    1
#define ACPI_MADT_POLARITY_ACTIVE_LOW     3
#define ACPI_MADT_POLARITY_CONFORMS       0
#define ACPI_MADT_POLARITY_MASK     (3)	
#define ACPI_MADT_POLARITY_RESERVED       2
#define ACPI_MADT_TRIGGER_CONFORMS        (0)
#define ACPI_MADT_TRIGGER_EDGE            (1<<2)
#define ACPI_MADT_TRIGGER_LEVEL           (3<<2)
#define ACPI_MADT_TRIGGER_MASK      (3<<2)	
#define ACPI_MADT_TRIGGER_RESERVED        (2<<2)
#define ACPI_MADT_VGIC_IRQ_MODE         (1<<2)	
#define ACPI_MPST_AUTOENTRY             2
#define ACPI_MPST_AUTOEXIT              4
#define ACPI_MPST_CHANNEL_INFO \
	u8                              channel_id; \
	u8                              reserved1[3]; \
	u16                             power_node_count; \
	u16                             reserved2;
#define ACPI_MPST_ENABLED               1
#define ACPI_MPST_HOT_PLUG_CAPABLE      4
#define ACPI_MPST_POWER_MANAGED         2
#define ACPI_MPST_PRESERVE              1
#define ACPI_MP_WAKE_COMMAND_WAKEUP    1
#define ACPI_NFIT_ADD_ONLINE_ONLY       (1)	
#define ACPI_NFIT_BUILD_DEVICE_HANDLE(dimm, channel, memory, socket, node) \
	((dimm)                                         | \
	((channel) << ACPI_NFIT_CHANNEL_NUMBER_OFFSET)  | \
	((memory)  << ACPI_NFIT_MEMORY_ID_OFFSET)       | \
	((socket)  << ACPI_NFIT_SOCKET_ID_OFFSET)       | \
	((node)    << ACPI_NFIT_NODE_ID_OFFSET))
#define ACPI_NFIT_CAPABILITY_CACHE_FLUSH       (1)	
#define ACPI_NFIT_CAPABILITY_MEM_FLUSH         (1<<1)	
#define ACPI_NFIT_CAPABILITY_MEM_MIRRORING     (1<<2)	
#define ACPI_NFIT_CHANNEL_NUMBER_MASK           0x000000F0
#define ACPI_NFIT_CHANNEL_NUMBER_OFFSET         4
#define ACPI_NFIT_CONTROL_BUFFERED          (1)	
#define ACPI_NFIT_CONTROL_MFG_INFO_VALID    (1)	
#define ACPI_NFIT_DIMM_NUMBER_MASK              0x0000000F
#define ACPI_NFIT_DIMM_NUMBER_OFFSET            0
#define ACPI_NFIT_GET_CHANNEL_NUMBER(handle) \
	(((handle) & ACPI_NFIT_CHANNEL_NUMBER_MASK) >> ACPI_NFIT_CHANNEL_NUMBER_OFFSET)
#define ACPI_NFIT_GET_DIMM_NUMBER(handle) \
	((handle) & ACPI_NFIT_DIMM_NUMBER_MASK)
#define ACPI_NFIT_GET_MEMORY_ID(handle) \
	(((handle) & ACPI_NFIT_MEMORY_ID_MASK)      >> ACPI_NFIT_MEMORY_ID_OFFSET)
#define ACPI_NFIT_GET_NODE_ID(handle) \
	(((handle) & ACPI_NFIT_NODE_ID_MASK)        >> ACPI_NFIT_NODE_ID_OFFSET)
#define ACPI_NFIT_GET_SOCKET_ID(handle) \
	(((handle) & ACPI_NFIT_SOCKET_ID_MASK)      >> ACPI_NFIT_SOCKET_ID_OFFSET)
#define ACPI_NFIT_LOCATION_COOKIE_VALID (1<<2)	
#define ACPI_NFIT_MEMORY_ID_MASK                0x00000F00
#define ACPI_NFIT_MEMORY_ID_OFFSET              8
#define ACPI_NFIT_MEM_FLUSH_FAILED      (1<<2)	
#define ACPI_NFIT_MEM_HEALTH_ENABLED    (1<<5)	
#define ACPI_NFIT_MEM_HEALTH_OBSERVED   (1<<4)	
#define ACPI_NFIT_MEM_MAP_FAILED        (1<<6)	
#define ACPI_NFIT_MEM_NOT_ARMED         (1<<3)	
#define ACPI_NFIT_MEM_RESTORE_FAILED    (1<<1)	
#define ACPI_NFIT_MEM_SAVE_FAILED       (1)	
#define ACPI_NFIT_NODE_ID_MASK                  0x0FFF0000
#define ACPI_NFIT_NODE_ID_OFFSET                16
#define ACPI_NFIT_PROXIMITY_VALID       (1<<1)	
#define ACPI_NFIT_SOCKET_ID_MASK                0x0000F000
#define ACPI_NFIT_SOCKET_ID_OFFSET              12
#define ACPI_PCCT_DOORBELL              1
#define ACPI_PCCT_INTERRUPT_MODE        (1<<1)
#define ACPI_PCCT_INTERRUPT_POLARITY    (1)
#define ACPI_PDTT_RUNTIME_TRIGGER           (1)
#define ACPI_PDTT_TRIGGER_ORDER             (1<<2)
#define ACPI_PDTT_WAIT_COMPLETION           (1<<1)
#define ACPI_PHAT_ADVISORY              3
#define ACPI_PHAT_ERRORS_FOUND          0
#define ACPI_PHAT_NO_ERRORS             1
#define ACPI_PHAT_TYPE_FW_HEALTH_DATA   1
#define ACPI_PHAT_TYPE_FW_VERSION_DATA  0
#define ACPI_PHAT_TYPE_RESERVED         2	
#define ACPI_PHAT_UNKNOWN_ERRORS        2
#define ACPI_PMTT_MEMORY_TYPE           0x000C
#define ACPI_PMTT_PHYSICAL              0x0002
#define ACPI_PMTT_TOP_LEVEL             0x0001
#define ACPI_PMTT_TYPE_CONTROLLER       1
#define ACPI_PMTT_TYPE_DIMM             2
#define ACPI_PMTT_TYPE_RESERVED         3	
#define ACPI_PMTT_TYPE_SOCKET           0
#define ACPI_PMTT_TYPE_VENDOR           0xFF
#define ACPI_PPTT_ACPI_IDENTICAL            (1<<4)	
#define ACPI_PPTT_ACPI_LEAF_NODE            (1<<3)	
#define ACPI_PPTT_ACPI_PROCESSOR_ID_VALID   (1<<1)
#define ACPI_PPTT_ACPI_PROCESSOR_IS_THREAD  (1<<2)	
#define ACPI_PPTT_ALLOCATION_TYPE_VALID     (1<<3)	
#define ACPI_PPTT_ASSOCIATIVITY_VALID       (1<<2)	
#define ACPI_PPTT_CACHE_ID_VALID            (1<<7)	
#define ACPI_PPTT_CACHE_POLICY_WB           (0x0)	
#define ACPI_PPTT_CACHE_POLICY_WT           (1<<4)	
#define ACPI_PPTT_CACHE_READ_ALLOCATE       (0x0)	
#define ACPI_PPTT_CACHE_RW_ALLOCATE         (0x02)	
#define ACPI_PPTT_CACHE_RW_ALLOCATE_ALT     (0x03)	
#define ACPI_PPTT_CACHE_TYPE_DATA           (0x0)	
#define ACPI_PPTT_CACHE_TYPE_INSTR          (1<<2)	
#define ACPI_PPTT_CACHE_TYPE_UNIFIED        (2<<2)	
#define ACPI_PPTT_CACHE_TYPE_UNIFIED_ALT    (3<<2)	
#define ACPI_PPTT_CACHE_TYPE_VALID          (1<<4)	
#define ACPI_PPTT_CACHE_WRITE_ALLOCATE      (0x01)	
#define ACPI_PPTT_LINE_SIZE_VALID           (1<<6)	
#define ACPI_PPTT_MASK_ALLOCATION_TYPE      (0x03)	
#define ACPI_PPTT_MASK_CACHE_TYPE           (0x0C)	
#define ACPI_PPTT_MASK_WRITE_POLICY         (0x10)	
#define ACPI_PPTT_NUMBER_OF_SETS_VALID      (1<<1)	
#define ACPI_PPTT_PHYSICAL_PACKAGE          (1)
#define ACPI_PPTT_SIZE_PROPERTY_VALID       (1)	
#define ACPI_PPTT_WRITE_POLICY_VALID        (1<<5)	
#define ACPI_RASF_COMMAND_COMPLETE      (1)
#define ACPI_RASF_ERROR                 (1<<2)
#define ACPI_RASF_GENERATE_SCI          (1<<15)
#define ACPI_RASF_SCI_DOORBELL          (1<<1)
#define ACPI_RASF_SCRUBBER_RUNNING      1
#define ACPI_RASF_SPEED                 (7<<1)
#define ACPI_RASF_SPEED_FAST            (7<<1)
#define ACPI_RASF_SPEED_MEDIUM          (4<<1)
#define ACPI_RASF_SPEED_SLOW            (0<<1)
#define ACPI_RASF_STATUS                (0x1F<<3)
#define ACPI_SDEV_HANDOFF_TO_UNSECURE_OS    (1)
#define ACPI_SDEV_SECURE_COMPONENTS_PRESENT (1<<1)
#define ACPI_SIG_BDAT           "BDAT"	
#define ACPI_SIG_IORT           "IORT"	
#define ACPI_SIG_IVRS           "IVRS"	
#define ACPI_SIG_LPIT           "LPIT"	
#define ACPI_SIG_MADT           "APIC"	
#define ACPI_SIG_MCFG           "MCFG"	
#define ACPI_SIG_MCHI           "MCHI"	
#define ACPI_SIG_MPST           "MPST"	
#define ACPI_SIG_MSCT           "MSCT"	
#define ACPI_SIG_MSDM           "MSDM"	
#define ACPI_SIG_NFIT           "NFIT"	
#define ACPI_SIG_NHLT           "NHLT"	
#define ACPI_SIG_PCCT           "PCCT"	
#define ACPI_SIG_PDTT           "PDTT"	
#define ACPI_SIG_PHAT           "PHAT"	
#define ACPI_SIG_PMTT           "PMTT"	
#define ACPI_SIG_PPTT           "PPTT"	
#define ACPI_SIG_PRMT           "PRMT"	
#define ACPI_SIG_RASF           "RASF"	
#define ACPI_SIG_RGRT           "RGRT"	
#define ACPI_SIG_SBST           "SBST"	
#define ACPI_SIG_SDEI           "SDEI"	
#define ACPI_SIG_SDEV           "SDEV"	
#define ACPI_SIG_SVKL           "SVKL"	

#define ACPI_ASF_SMBUS_PROTOCOLS    (1)
#define ACPI_BERT_CORRECTABLE               (1<<1)
#define ACPI_BERT_ERROR_ENTRY_COUNT         (0xFF<<4)	
#define ACPI_BERT_MULTIPLE_CORRECTABLE      (1<<3)
#define ACPI_BERT_MULTIPLE_UNCORRECTABLE    (1<<2)
#define ACPI_BERT_UNCORRECTABLE             (1)
#define ACPI_BGRT_DISPLAYED                 (1)
#define ACPI_BGRT_ORIENTATION_OFFSET        (3 << 1)
#define ACPI_CEDT_CHBS_LENGTH_CXL11     (0x2000)
#define ACPI_CEDT_CHBS_LENGTH_CXL20     (0x10000)
#define ACPI_CEDT_CHBS_VERSION_CXL11    (0)
#define ACPI_CEDT_CHBS_VERSION_CXL20    (1)
#define ACPI_CSRT_DMA_CHANNEL       0x0000
#define ACPI_CSRT_DMA_CONTROLLER    0x0001
#define ACPI_CSRT_TIMER             0x0000
#define ACPI_CSRT_TYPE_DMA          0x0003
#define ACPI_CSRT_TYPE_INTERRUPT    0x0001
#define ACPI_CSRT_TYPE_TIMER        0x0002
#define ACPI_CSRT_XRUPT_CONTROLLER  0x0001
#define ACPI_CSRT_XRUPT_LINE        0x0000
#define ACPI_DBG2_1394_PORT         0x8001
#define ACPI_DBG2_1394_STANDARD     0x0000
#define ACPI_DBG2_16550_COMPATIBLE  0x0000
#define ACPI_DBG2_16550_NVIDIA      0x0005
#define ACPI_DBG2_16550_SUBSET      0x0001
#define ACPI_DBG2_16550_WITH_GAS    0x0012
#define ACPI_DBG2_APM88XXXX         0x0008
#define ACPI_DBG2_ARM_DCC           0x000F
#define ACPI_DBG2_ARM_PL011         0x0003
#define ACPI_DBG2_ARM_SBSA_32BIT    0x000D
#define ACPI_DBG2_ARM_SBSA_GENERIC  0x000E
#define ACPI_DBG2_BCM2835           0x0010
#define ACPI_DBG2_IMX6              0x000C
#define ACPI_DBG2_INTEL_LPSS        0x0014
#define ACPI_DBG2_INTEL_USIF        0x000B
#define ACPI_DBG2_MAX311XE_SPI      0x0002
#define ACPI_DBG2_MSM8974           0x0009
#define ACPI_DBG2_MSM8X60           0x0004
#define ACPI_DBG2_NET_PORT          0x8003
#define ACPI_DBG2_SAM5250           0x000A
#define ACPI_DBG2_SDM845_1_8432MHZ  0x0011
#define ACPI_DBG2_SDM845_7_372MHZ   0x0013
#define ACPI_DBG2_SERIAL_PORT       0x8000
#define ACPI_DBG2_TI_OMAP           0x0006
#define ACPI_DBG2_USB_EHCI          0x0001
#define ACPI_DBG2_USB_PORT          0x8002
#define ACPI_DBG2_USB_XHCI          0x0000
#define ACPI_DMAR_ALLOW_ALL         (1)
#define ACPI_DMAR_ALL_PORTS         (1)
#define ACPI_DMAR_INCLUDE_ALL       (1)
#define ACPI_DMAR_INTR_REMAP        (1)
#define ACPI_DMAR_X2APIC_MODE       (1<<2)
#define ACPI_DMAR_X2APIC_OPT_OUT    (1<<1)
#define ACPI_DRTM_ACCESS_ALLOWED            (1)
#define ACPI_DRTM_AUTHORITY_ORDER           (1<<3)
#define ACPI_DRTM_ENABLE_GAP_CODE           (1<<1)
#define ACPI_DRTM_INCOMPLETE_MEASUREMENTS   (1<<2)
#define ACPI_EINJ_MEMORY_CORRECTABLE        (1<<3)
#define ACPI_EINJ_MEMORY_FATAL              (1<<5)
#define ACPI_EINJ_MEMORY_UNCORRECTABLE      (1<<4)
#define ACPI_EINJ_PCIX_CORRECTABLE          (1<<6)
#define ACPI_EINJ_PCIX_FATAL                (1<<8)
#define ACPI_EINJ_PCIX_UNCORRECTABLE        (1<<7)
#define ACPI_EINJ_PLATFORM_CORRECTABLE      (1<<9)
#define ACPI_EINJ_PLATFORM_FATAL            (1<<11)
#define ACPI_EINJ_PLATFORM_UNCORRECTABLE    (1<<10)
#define ACPI_EINJ_PRESERVE          (1)
#define ACPI_EINJ_PROCESSOR_CORRECTABLE     (1)
#define ACPI_EINJ_PROCESSOR_FATAL           (1<<2)
#define ACPI_EINJ_PROCESSOR_UNCORRECTABLE   (1<<1)
#define ACPI_EINJ_VENDOR_DEFINED            (1<<31)
#define ACPI_ERST_PRESERVE          (1)
#define ACPI_GTDT_ALWAYS_ON             (1<<2)
#define ACPI_GTDT_GT_ALWAYS_ON              (1<<1)
#define ACPI_GTDT_GT_IRQ_MODE               (1)
#define ACPI_GTDT_GT_IRQ_POLARITY           (1<<1)
#define ACPI_GTDT_GT_IS_SECURE_TIMER        (1)
#define ACPI_GTDT_INTERRUPT_MODE        (1)
#define ACPI_GTDT_INTERRUPT_POLARITY    (1<<1)
#define ACPI_GTDT_WATCHDOG_IRQ_MODE         (1)
#define ACPI_GTDT_WATCHDOG_IRQ_POLARITY     (1<<1)
#define ACPI_GTDT_WATCHDOG_SECURE           (1<<2)
#define ACPI_HEST_BUS(bus)              ((bus) & 0xFF)
#define ACPI_HEST_CORRECTABLE               (1<<1)
#define ACPI_HEST_ERROR_ENTRY_COUNT         (0xFF<<4)	
#define ACPI_HEST_ERR_THRESHOLD_VALUE   (1<<4)
#define ACPI_HEST_ERR_THRESHOLD_WINDOW  (1<<5)
#define ACPI_HEST_FIRMWARE_FIRST        (1)
#define ACPI_HEST_GEN_ERROR_CORRECTED       2
#define ACPI_HEST_GEN_ERROR_FATAL           1
#define ACPI_HEST_GEN_ERROR_NONE            3
#define ACPI_HEST_GEN_ERROR_RECOVERABLE     0
#define ACPI_HEST_GEN_VALID_FRU_ID          (1)
#define ACPI_HEST_GEN_VALID_FRU_STRING      (1<<1)
#define ACPI_HEST_GEN_VALID_TIMESTAMP       (1<<2)
#define ACPI_HEST_GHES_ASSIST           (1<<2)
#define ACPI_HEST_GLOBAL                (1<<1)
#define ACPI_HEST_MULTIPLE_CORRECTABLE      (1<<3)
#define ACPI_HEST_MULTIPLE_UNCORRECTABLE    (1<<2)
#define ACPI_HEST_POLL_INTERVAL         (1<<1)
#define ACPI_HEST_POLL_THRESHOLD_VALUE  (1<<2)
#define ACPI_HEST_POLL_THRESHOLD_WINDOW (1<<3)
#define ACPI_HEST_SEGMENT(bus)          (((bus) >> 8) & 0xFFFF)
#define ACPI_HEST_TYPE                  (1)
#define ACPI_HEST_UNCORRECTABLE             (1)
#define ACPI_HMAT_1ST_LEVEL_CACHE   2
#define ACPI_HMAT_2ND_LEVEL_CACHE   3
#define ACPI_HMAT_3RD_LEVEL_CACHE   4
#define ACPI_HMAT_ACCESS_BANDWIDTH  3
#define ACPI_HMAT_ACCESS_LATENCY    0
#define ACPI_HMAT_CACHE_ASSOCIATIVITY   (0x00000F00)
#define ACPI_HMAT_CACHE_LEVEL           (0x000000F0)
#define ACPI_HMAT_CACHE_LINE_SIZE       (0xFFFF0000)
#define ACPI_HMAT_CA_COMPLEX_CACHE_INDEXING   (2)
#define ACPI_HMAT_CA_DIRECT_MAPPED            (1)
#define ACPI_HMAT_CA_NONE                     (0)
#define ACPI_HMAT_CP_NONE   (0)
#define ACPI_HMAT_CP_WB     (1)
#define ACPI_HMAT_CP_WT     (2)
#define ACPI_HMAT_LAST_LEVEL_CACHE  1
#define ACPI_HMAT_MEMORY            0
#define ACPI_HMAT_MEMORY_HIERARCHY  (0x0F)     
#define ACPI_HMAT_MEMORY_PD_VALID       (1<<1)	
#define ACPI_HMAT_MINIMUM_XFER_SIZE 0x10       
#define ACPI_HMAT_NON_SEQUENTIAL_XFERS 0x20    
#define ACPI_HMAT_PROCESSOR_PD_VALID    (1)	
#define ACPI_HMAT_READ_BANDWIDTH    4
#define ACPI_HMAT_READ_LATENCY      1
#define ACPI_HMAT_RESERVATION_HINT      (1<<2)	
#define ACPI_HMAT_TOTAL_CACHE_LEVEL     (0x0000000F)
#define ACPI_HMAT_WRITE_BANDWIDTH   5
#define ACPI_HMAT_WRITE_LATENCY     2
#define ACPI_HMAT_WRITE_POLICY          (0x0000F000)
#define ACPI_HPET_PAGE_PROTECT_MASK (3)
#define ACPI_SIG_AEST           "AEST"	
#define ACPI_SIG_ASF            "ASF!"	
#define ACPI_SIG_ATKG           "ATKG"
#define ACPI_SIG_BERT           "BERT"	
#define ACPI_SIG_BGRT           "BGRT"	
#define ACPI_SIG_BOOT           "BOOT"	
#define ACPI_SIG_CEDT           "CEDT"	
#define ACPI_SIG_CPEP           "CPEP"	
#define ACPI_SIG_CSRT           "CSRT"	
#define ACPI_SIG_DBG2           "DBG2"	
#define ACPI_SIG_DBGP           "DBGP"	
#define ACPI_SIG_DMAR           "DMAR"	
#define ACPI_SIG_DRTM           "DRTM"	
#define ACPI_SIG_ECDT           "ECDT"	
#define ACPI_SIG_EINJ           "EINJ"	
#define ACPI_SIG_ERST           "ERST"	
#define ACPI_SIG_FPDT           "FPDT"	
#define ACPI_SIG_GSCI           "GSCI"	
#define ACPI_SIG_GTDT           "GTDT"	
#define ACPI_SIG_HEST           "HEST"	
#define ACPI_SIG_HMAT           "HMAT"	
#define ACPI_SIG_HPET           "HPET"	
#define ACPI_SIG_IBFT           "IBFT"	
#define ACPI_SIG_IEIT           "IEIT"
#define ACPI_SIG_MATR           "MATR"	
#define ACPI_SIG_PCCS           "PCC"	
#define ACPI_SIG_S3PT           "S3PT"	

#define ACPI_100NSEC_PER_MSEC           10000L
#define ACPI_100NSEC_PER_SEC            10000000L
#define ACPI_100NSEC_PER_USEC           10L
#define ACPI_ACCESS_BIT_WIDTH(size)     (1 << ((size) + 2))
#define ACPI_ACCESS_BYTE_WIDTH(size)    (1 << ((size) - 1))
#define ACPI_ADD_PTR(t, a, b)           ACPI_CAST_PTR (t, (ACPI_CAST_PTR (u8, (a)) + (acpi_size)(b)))
#define ACPI_ADR_SPACE_CMOS             (acpi_adr_space_type) 5
#define ACPI_ADR_SPACE_DATA_TABLE       (acpi_adr_space_type) 0x7E	
#define ACPI_ADR_SPACE_EC               (acpi_adr_space_type) 3
#define ACPI_ADR_SPACE_FIXED_HARDWARE   (acpi_adr_space_type) 0x7F
#define ACPI_ADR_SPACE_GPIO             (acpi_adr_space_type) 8
#define ACPI_ADR_SPACE_GSBUS            (acpi_adr_space_type) 9
#define ACPI_ADR_SPACE_IPMI             (acpi_adr_space_type) 7
#define ACPI_ADR_SPACE_PCI_BAR_TARGET   (acpi_adr_space_type) 6
#define ACPI_ADR_SPACE_PCI_CONFIG       (acpi_adr_space_type) 2
#define ACPI_ADR_SPACE_PLATFORM_COMM    (acpi_adr_space_type) 10
#define ACPI_ADR_SPACE_PLATFORM_RT      (acpi_adr_space_type) 11
#define ACPI_ADR_SPACE_SMBUS            (acpi_adr_space_type) 4
#define ACPI_ADR_SPACE_SYSTEM_IO        (acpi_adr_space_type) 1
#define ACPI_ADR_SPACE_SYSTEM_MEMORY    (acpi_adr_space_type) 0
#define ACPI_ALLOCATE(a)                NULL
#define ACPI_ALLOCATE_BUFFER        (acpi_size) (0)
#define ACPI_ALLOCATE_LOCAL_BUFFER  (acpi_size) (0)
#define ACPI_ALLOCATE_ZEROED(a)         NULL
#define ACPI_ALL_NOTIFY                 (ACPI_SYSTEM_NOTIFY | ACPI_DEVICE_NOTIFY)
#define ACPI_ARRAY_LENGTH(x)            (sizeof(x) / sizeof((x)[0]))
#define ACPI_ASCII_MAX                  0x7F
#define ACPI_BITREG_ARB_DISABLE                 0x13
#define ACPI_BITREG_BUS_MASTER_RLD              0x0F
#define ACPI_BITREG_BUS_MASTER_STATUS           0x01
#define ACPI_BITREG_GLOBAL_LOCK_ENABLE          0x09
#define ACPI_BITREG_GLOBAL_LOCK_RELEASE         0x10
#define ACPI_BITREG_GLOBAL_LOCK_STATUS          0x02
#define ACPI_BITREG_MAX                         0x13
#define ACPI_BITREG_PCIEXP_WAKE_DISABLE         0x0D
#define ACPI_BITREG_PCIEXP_WAKE_STATUS          0x07
#define ACPI_BITREG_POWER_BUTTON_ENABLE         0x0A
#define ACPI_BITREG_POWER_BUTTON_STATUS         0x03
#define ACPI_BITREG_RT_CLOCK_ENABLE             0x0C
#define ACPI_BITREG_RT_CLOCK_STATUS             0x05
#define ACPI_BITREG_SCI_ENABLE                  0x0E
#define ACPI_BITREG_SLEEP_BUTTON_ENABLE         0x0B
#define ACPI_BITREG_SLEEP_BUTTON_STATUS         0x04
#define ACPI_BITREG_SLEEP_ENABLE                0x12
#define ACPI_BITREG_SLEEP_TYPE                  0x11
#define ACPI_BITREG_TIMER_ENABLE                0x08
#define ACPI_BITREG_TIMER_STATUS                0x00
#define ACPI_BITREG_WAKE_STATUS                 0x06
#define ACPI_CAST_INDIRECT_PTR(t, p)    ((t **) (acpi_uintptr_t) (p))
#define ACPI_CAST_PTR(t, p)             ((t *) (acpi_uintptr_t) (p))
#define ACPI_CLEAR_BIT(target,bit)      ((target) &= ~(bit))
#define ACPI_CLEAR_STATUS                       1
#define ACPI_COMPARE_NAMESEG(a,b)       (*ACPI_CAST_PTR (u32, (a)) == *ACPI_CAST_PTR (u32, (b)))
#define ACPI_COPY_NAMESEG(dest,src)     (*ACPI_CAST_PTR (u32, (dest)) = *ACPI_CAST_PTR (u32, (src)))
#define ACPI_C_STATES_MAX               ACPI_STATE_C3
#define ACPI_C_STATE_COUNT              4

#define ACPI_DEFAULT_HANDLER            NULL
#define ACPI_DEVICE_HANDLER_LIST        1	
#define ACPI_DEVICE_NOTIFY              0x2
#define ACPI_DISABLE_ALL_FEATURE_STRINGS    (ACPI_DISABLE_INTERFACES | ACPI_FEATURE_STRINGS)
#define ACPI_DISABLE_ALL_STRINGS            (ACPI_DISABLE_INTERFACES | ACPI_VENDOR_STRINGS | ACPI_FEATURE_STRINGS)
#define ACPI_DISABLE_ALL_VENDOR_STRINGS     (ACPI_DISABLE_INTERFACES | ACPI_VENDOR_STRINGS)
#define ACPI_DISABLE_EVENT                      0
#define ACPI_DISABLE_INTERFACES             0x04
#define ACPI_DO_NOT_WAIT                0
#define ACPI_D_STATES_MAX               ACPI_STATE_D3
#define ACPI_D_STATE_COUNT              5
#define ACPI_EISAID_STRING_SIZE         8	
#define ACPI_ENABLE_ALL_FEATURE_STRINGS     (ACPI_ENABLE_INTERFACES | ACPI_FEATURE_STRINGS)
#define ACPI_ENABLE_ALL_STRINGS             (ACPI_ENABLE_INTERFACES | ACPI_VENDOR_STRINGS | ACPI_FEATURE_STRINGS)
#define ACPI_ENABLE_ALL_VENDOR_STRINGS      (ACPI_ENABLE_INTERFACES | ACPI_VENDOR_STRINGS)
#define ACPI_ENABLE_EVENT                       1
#define ACPI_ENABLE_INTERFACES              0x00
#define ACPI_EVENT_FLAG_DISABLED        (acpi_event_status) 0x00
#define ACPI_EVENT_FLAG_ENABLED         (acpi_event_status) 0x01
#define ACPI_EVENT_FLAG_ENABLE_SET      (acpi_event_status) 0x08
#define ACPI_EVENT_FLAG_HAS_HANDLER     (acpi_event_status) 0x10
#define ACPI_EVENT_FLAG_MASKED          (acpi_event_status) 0x20
#define ACPI_EVENT_FLAG_SET             ACPI_EVENT_FLAG_STATUS_SET
#define ACPI_EVENT_FLAG_STATUS_SET      (acpi_event_status) 0x04
#define ACPI_EVENT_FLAG_WAKE_ENABLED    (acpi_event_status) 0x02
#define ACPI_EVENT_GLOBAL               1
#define ACPI_EVENT_MAX                  4
#define ACPI_EVENT_PMTIMER              0
#define ACPI_EVENT_POWER_BUTTON         2
#define ACPI_EVENT_RTC                  4
#define ACPI_EVENT_SLEEP_BUTTON         3
#define ACPI_EVENT_TYPE_FIXED       1
#define ACPI_EVENT_TYPE_GPE         0


#define ACPI_FALLTHROUGH do {} while(0)
#define ACPI_FEATURE_STRINGS                0x02

#define ACPI_FULL_INITIALIZATION        0x0000
#define ACPI_FULL_PATHNAME              0
#define ACPI_FULL_PATHNAME_NO_TRAILING  2
#define ACPI_GENERIC_NOTIFY_MAX         0x0F
#define ACPI_GPE_AUTO_ENABLED           (u8) 0x20
#define ACPI_GPE_CAN_WAKE               (u8) 0x10
#define ACPI_GPE_CONDITIONAL_ENABLE     2
#define ACPI_GPE_DISABLE                1
#define ACPI_GPE_DISPATCH_HANDLER       (u8) 0x02
#define ACPI_GPE_DISPATCH_MASK          (u8) 0x07
#define ACPI_GPE_DISPATCH_METHOD        (u8) 0x01
#define ACPI_GPE_DISPATCH_NONE          (u8) 0x00
#define ACPI_GPE_DISPATCH_NOTIFY        (u8) 0x03
#define ACPI_GPE_DISPATCH_RAW_HANDLER   (u8) 0x04
#define ACPI_GPE_DISPATCH_TYPE(flags)   ((u8) ((flags) & ACPI_GPE_DISPATCH_MASK))
#define ACPI_GPE_EDGE_TRIGGERED         (u8) 0x00
#define ACPI_GPE_ENABLE                 0
#define ACPI_GPE_INITIALIZED            (u8) 0x40
#define ACPI_GPE_LEVEL_TRIGGERED        (u8) 0x08
#define ACPI_GPE_REGISTER_WIDTH         8
#define ACPI_GPE_XRUPT_TYPE_MASK        (u8) 0x08
#define ACPI_HIBYTE(integer)            ((u8) (((u16)(integer)) >> 8))
#define ACPI_HIDWORD(integer64)         ((u32)(((u64)(integer64)) >> 32))
#define ACPI_HIWORD(integer)            ((u16)(((u32)(integer)) >> 16))
#define ACPI_INITIALIZED_OK             0x02
#define ACPI_INIT_DEVICE_INI        1
#define ACPI_INTEGER_BIT_SIZE           64
#define ACPI_INTEGER_MAX                ACPI_UINT64_MAX
#define ACPI_INTERRUPT_HANDLED          0x01
#define ACPI_INTERRUPT_NOT_HANDLED      0x00
#define ACPI_IO_MASK                    1
#define ACPI_ISR                        0x0
#define ACPI_IS_OEM_SIG(a)        (!strncmp (ACPI_CAST_PTR (char, (a)), ACPI_OEM_NAME, 3) &&\
	 strnlen (a, ACPI_NAMESEG_SIZE) == ACPI_NAMESEG_SIZE)
#define ACPI_LOBYTE(integer)            ((u8)   (u16)(integer))
#define ACPI_LODWORD(integer64)         ((u32)  (u64)(integer64))
#define ACPI_LOWORD(integer)            ((u16)  (u32)(integer))
#define ACPI_MAKE_RSDP_SIG(dest)        (memcpy (ACPI_CAST_PTR (char, (dest)), ACPI_SIG_RSDP, 8))
#define ACPI_MAX(a,b)                   (((a)>(b))?(a):(b))
#define ACPI_MAX16_DECIMAL_DIGITS        5
#define ACPI_MAX32_DECIMAL_DIGITS       10
#define ACPI_MAX64_DECIMAL_DIGITS       20
#define ACPI_MAX8_DECIMAL_DIGITS         3
#define ACPI_MAX_DECIMAL_DIGITS         20	
#define ACPI_MAX_DEVICE_SPECIFIC_NOTIFY 0xBF
#define ACPI_MAX_GPE_BLOCKS             2
#define ACPI_MAX_NOTIFY_HANDLER_TYPE    0x3
#define ACPI_MAX_PTR                    ACPI_UINT64_MAX
#define ACPI_MAX_SYS_NOTIFY             0x7F
#define ACPI_MEM_PARAMETERS             _COMPONENT, _acpi_module_name, "__LINE__"

#define ACPI_MIN(a,b)                   (((a)<(b))?(a):(b))

#define ACPI_MSEC_PER_SEC               1000L
#define ACPI_NAMESEG_SIZE               4	
#define ACPI_NAME_TYPE_MAX              2
#define ACPI_NOTIFY_AFFINITY_UPDATE     (u8) 0x0D
#define ACPI_NOTIFY_BUS_CHECK           (u8) 0x00
#define ACPI_NOTIFY_BUS_MODE_MISMATCH   (u8) 0x06
#define ACPI_NOTIFY_CAPABILITIES_CHECK  (u8) 0x08
#define ACPI_NOTIFY_DEVICE_CHECK        (u8) 0x01
#define ACPI_NOTIFY_DEVICE_CHECK_LIGHT  (u8) 0x04
#define ACPI_NOTIFY_DEVICE_PLD_CHECK    (u8) 0x09
#define ACPI_NOTIFY_DEVICE_WAKE         (u8) 0x02
#define ACPI_NOTIFY_DISCONNECT_RECOVER  (u8) 0x0F
#define ACPI_NOTIFY_EJECT_REQUEST       (u8) 0x03
#define ACPI_NOTIFY_FREQUENCY_MISMATCH  (u8) 0x05
#define ACPI_NOTIFY_LOCALITY_UPDATE     (u8) 0x0B
#define ACPI_NOTIFY_MEMORY_UPDATE       (u8) 0x0E
#define ACPI_NOTIFY_POWER_FAULT         (u8) 0x07
#define ACPI_NOTIFY_RESERVED            (u8) 0x0A
#define ACPI_NOTIFY_SHUTDOWN_REQUEST    (u8) 0x0C
#define ACPI_NOT_ISR                    0x1
#define ACPI_NO_ACPI_ENABLE             0x0002
#define ACPI_NO_ADDRESS_SPACE_INIT      0x0080
#define ACPI_NO_BUFFER              0
#define ACPI_NO_DEVICE_INIT             0x0040
#define ACPI_NO_EVENT_INIT              0x0008
#define ACPI_NO_FACS_INIT               0x0001
#define ACPI_NO_HANDLER_INIT            0x0010
#define ACPI_NO_HARDWARE_INIT           0x0004
#define ACPI_NO_OBJECT_INIT             0x0020
#define ACPI_NSEC_PER_MSEC              1000000L
#define ACPI_NSEC_PER_SEC               1000000000L
#define ACPI_NSEC_PER_USEC              1000L
#define ACPI_NUM_BITREG                         ACPI_BITREG_MAX + 1
#define ACPI_NUM_FIXED_EVENTS           ACPI_EVENT_MAX + 1
#define ACPI_NUM_NOTIFY_TYPES           2
#define ACPI_NUM_NS_TYPES               (ACPI_TYPE_INVALID + 1)
#define ACPI_NUM_PREDEFINED_REGIONS     12
#define ACPI_NUM_TABLE_EVENTS           4
#define ACPI_NUM_TYPES                  (ACPI_TYPE_EXTERNAL_MAX + 1)
#define ACPI_OEM_ID_SIZE                6
#define ACPI_OEM_TABLE_ID_SIZE          8
#define ACPI_OFFSET(d, f)               ACPI_PTR_DIFF (&(((d *) 0)->f), (void *) 0)
#define ACPI_OPT_END                    -1
#define ACPI_OSI_WINSRV_2003            0x04
#define ACPI_OSI_WINSRV_2003_SP1        0x06
#define ACPI_OSI_WINSRV_2008            0x08
#define ACPI_OSI_WIN_10                 0x0E
#define ACPI_OSI_WIN_10_19H1            0x14
#define ACPI_OSI_WIN_10_RS1             0x0F
#define ACPI_OSI_WIN_10_RS2             0x10
#define ACPI_OSI_WIN_10_RS3             0x11
#define ACPI_OSI_WIN_10_RS4             0x12
#define ACPI_OSI_WIN_10_RS5             0x13
#define ACPI_OSI_WIN_2000               0x01
#define ACPI_OSI_WIN_7                  0x0B
#define ACPI_OSI_WIN_8                  0x0C
#define ACPI_OSI_WIN_8_1                0x0D
#define ACPI_OSI_WIN_VISTA              0x07
#define ACPI_OSI_WIN_VISTA_SP1          0x09
#define ACPI_OSI_WIN_VISTA_SP2          0x0A
#define ACPI_OSI_WIN_XP                 0x02
#define ACPI_OSI_WIN_XP_SP1             0x03
#define ACPI_OSI_WIN_XP_SP2             0x05
#define ACPI_OWNER_ID_MAX               0xFFF	
#define ACPI_PATH_SEGMENT_LENGTH        5	
#define ACPI_PATH_SEPARATOR             '.'
#define ACPI_PCICLS_STRING_SIZE         7	
#define ACPI_PCI_ROOT_BRIDGE            0x01
#define ACPI_PHYSADDR_TO_PTR(i)         ACPI_TO_POINTER(i)
#define ACPI_PM1_REGISTER_WIDTH         16
#define ACPI_PM2_REGISTER_WIDTH         8
#define ACPI_PM_TIMER_FREQUENCY         3579545
#define ACPI_PM_TIMER_WIDTH             32

#define ACPI_PTR_DIFF(a, b)             ((acpi_size) (ACPI_CAST_PTR (u8, (a)) - ACPI_CAST_PTR (u8, (b))))
#define ACPI_PTR_TO_PHYSADDR(i)         ACPI_TO_INTEGER(i)
#define ACPI_READ                       0
#define ACPI_REENABLE_GPE               0x80
#define ACPI_REGION_ACTIVATE    0
#define ACPI_REGION_DEACTIVATE  1
#define ACPI_REG_CONNECT                1
#define ACPI_REG_DISCONNECT             0
#define ACPI_RESET_REGISTER_WIDTH       8
#define ACPI_ROOT_OBJECT                ((acpi_handle) ACPI_TO_POINTER (ACPI_MAX_PTR))
#define ACPI_SET_BIT(target,bit)        ((target) |= (bit))
#define ACPI_SINGLE_NAME                1
#define ACPI_SIZE_MAX                   ACPI_UINT64_MAX
#define ACPI_SLEEP_TYPE_INVALID         0xFF
#define ACPI_SLEEP_TYPE_MAX             0x7
#define ACPI_SPECIFIC_NOTIFY_MAX        0x84
#define ACPI_STATE_C0                   (u8) 0
#define ACPI_STATE_C1                   (u8) 1
#define ACPI_STATE_C2                   (u8) 2
#define ACPI_STATE_C3                   (u8) 3
#define ACPI_STATE_D0                   (u8) 0
#define ACPI_STATE_D1                   (u8) 1
#define ACPI_STATE_D2                   (u8) 2
#define ACPI_STATE_D3                   (u8) 4
#define ACPI_STATE_D3_COLD              ACPI_STATE_D3
#define ACPI_STATE_D3_HOT               (u8) 3
#define ACPI_STATE_S0                   (u8) 0
#define ACPI_STATE_S1                   (u8) 1
#define ACPI_STATE_S2                   (u8) 2
#define ACPI_STATE_S3                   (u8) 3
#define ACPI_STATE_S4                   (u8) 4
#define ACPI_STATE_S5                   (u8) 5
#define ACPI_STATE_UNKNOWN              (u8) 0xFF
#define ACPI_STA_BATTERY_PRESENT        0x10
#define ACPI_STA_DEVICE_ENABLED         0x02
#define ACPI_STA_DEVICE_FUNCTIONING     0x08
#define ACPI_STA_DEVICE_OK              0x08	
#define ACPI_STA_DEVICE_PRESENT         0x01
#define ACPI_STA_DEVICE_UI              0x04
#define ACPI_SUBSYSTEM_INITIALIZE       0x01
#define ACPI_SUB_PTR(t, a, b)           ACPI_CAST_PTR (t, (ACPI_CAST_PTR (u8, (a)) - (acpi_size)(b)))
#define ACPI_SYSTEM_HANDLER_LIST        0	
#define ACPI_SYSTEM_NOTIFY              0x1
#define ACPI_SYS_MODES_MASK             0x0003
#define ACPI_SYS_MODE_ACPI              0x0001
#define ACPI_SYS_MODE_LEGACY            0x0002
#define ACPI_SYS_MODE_UNKNOWN           0x0000
#define ACPI_S_STATES_MAX               ACPI_STATE_S5
#define ACPI_S_STATE_COUNT              6
#define ACPI_TABLE_EVENT_INSTALL        0x2
#define ACPI_TABLE_EVENT_LOAD           0x0
#define ACPI_TABLE_EVENT_UNINSTALL      0x3
#define ACPI_TABLE_EVENT_UNLOAD         0x1
#define ACPI_TIME_AFTER(a, b)           ((s64)((b) - (a)) < 0)
#define ACPI_TOTAL_TYPES                (ACPI_TYPE_NS_NODE_MAX + 1)
#define ACPI_TO_INTEGER(p)              ACPI_PTR_DIFF (p, (void *) 0)
#define ACPI_TO_POINTER(i)              ACPI_CAST_PTR (void, (acpi_size) (i))
#define ACPI_TYPE_ANY                   0x00
#define ACPI_TYPE_BUFFER                0x03
#define ACPI_TYPE_BUFFER_FIELD          0x0E
#define ACPI_TYPE_DDB_HANDLE            0x0F
#define ACPI_TYPE_DEBUG_OBJECT          0x10
#define ACPI_TYPE_DEVICE                0x06	
#define ACPI_TYPE_EVENT                 0x07
#define ACPI_TYPE_EXTERNAL_MAX          0x10
#define ACPI_TYPE_FIELD_UNIT            0x05
#define ACPI_TYPE_INTEGER               0x01	
#define ACPI_TYPE_INVALID               0x1E
#define ACPI_TYPE_LOCAL_ADDRESS_HANDLER 0x18
#define ACPI_TYPE_LOCAL_ALIAS           0x15
#define ACPI_TYPE_LOCAL_BANK_FIELD      0x12
#define ACPI_TYPE_LOCAL_DATA            0x1D
#define ACPI_TYPE_LOCAL_EXTRA           0x1C
#define ACPI_TYPE_LOCAL_INDEX_FIELD     0x13
#define ACPI_TYPE_LOCAL_MAX             0x1D
#define ACPI_TYPE_LOCAL_METHOD_ALIAS    0x16
#define ACPI_TYPE_LOCAL_NOTIFY          0x17
#define ACPI_TYPE_LOCAL_REFERENCE       0x14	
#define ACPI_TYPE_LOCAL_REGION_FIELD    0x11
#define ACPI_TYPE_LOCAL_RESOURCE        0x19
#define ACPI_TYPE_LOCAL_RESOURCE_FIELD  0x1A
#define ACPI_TYPE_LOCAL_SCOPE           0x1B	
#define ACPI_TYPE_METHOD                0x08	
#define ACPI_TYPE_MUTEX                 0x09
#define ACPI_TYPE_NOT_FOUND             0xFF
#define ACPI_TYPE_NS_NODE_MAX           0x1B	
#define ACPI_TYPE_PACKAGE               0x04	
#define ACPI_TYPE_POWER                 0x0B	
#define ACPI_TYPE_PROCESSOR             0x0C	
#define ACPI_TYPE_REGION                0x0A
#define ACPI_TYPE_STRING                0x02
#define ACPI_TYPE_THERMAL               0x0D	
#define ACPI_UINT16_MAX                 (u16)(~((u16) 0))	
#define ACPI_UINT32_MAX                 (u32)(~((u32) 0))	
#define ACPI_UINT64_MAX                 (u64)(~((u64) 0))	
#define ACPI_UINT8_MAX                  (u8) (~((u8)  0))	

#define ACPI_USEC_PER_MSEC              1000L
#define ACPI_USEC_PER_SEC               1000000L
#define ACPI_UUID_LENGTH                16
#define ACPI_VALIDATE_RSDP_SIG(a)       (!strncmp (ACPI_CAST_PTR (char, (a)), ACPI_SIG_RSDP, 8))
#define ACPI_VALID_ADR                  0x0002
#define ACPI_VALID_CID                  0x0020
#define ACPI_VALID_CLS                  0x0040
#define ACPI_VALID_HID                  0x0004
#define ACPI_VALID_SXDS                 0x0100
#define ACPI_VALID_SXWS                 0x0200
#define ACPI_VALID_UID                  0x0008
#define ACPI_VENDOR_STRINGS                 0x01
#define ACPI_WAIT_FOREVER               0xFFFF	
#define ACPI_WRITE                      1
#define FALSE                           (1 == 0)
#define NULL                            (void *) 0
#define PCI_EXPRESS_ROOT_HID_STRING     "PNP0A08"
#define PCI_ROOT_HID_STRING             "PNP0A03"
#define TRUE                            (1 == 1)

#define acpi_cache_t                    struct acpi_memory_list
#define acpi_mutex                      acpi_semaphore
#define acpi_os_acquire_mutex(handle,time) acpi_os_wait_semaphore (handle, 1, time)
#define acpi_os_create_mutex(out_handle) acpi_os_create_semaphore (1, 1, out_handle)
#define acpi_os_delete_mutex(handle)    (void) acpi_os_delete_semaphore (handle)
#define acpi_os_release_mutex(handle)   (void) acpi_os_signal_semaphore (handle, 1)
#define acpi_semaphore                  void *
#define acpi_spinlock                   void *
#define acpi_thread_id                  u64
#define acpi_uintptr_t                  void *
#define ACPI_ADDRESS_RANGE_MAX          2
#define ACPI_CA_SUPPORT_LEVEL           5
#define ACPI_CHECKSUM_ABORT             FALSE
#define ACPI_DB_LINE_BUFFER_SIZE        512
#define ACPI_DEBUGGER_COMMAND_PROMPT    '-'
#define ACPI_DEBUGGER_EXECUTE_PROMPT    '%'
#define ACPI_DEBUGGER_MAX_ARGS          ACPI_METHOD_NUM_ARGS + 4	
#define ACPI_DEFAULT_PAGE_SIZE          4096	
#define ACPI_EBDA_PTR_LENGTH            2
#define ACPI_EBDA_PTR_LOCATION          0x0000040E	
#define ACPI_EBDA_WINDOW_SIZE           1024
#define ACPI_HI_RSDP_WINDOW_BASE        0x000E0000	
#define ACPI_HI_RSDP_WINDOW_SIZE        0x00020000
#define ACPI_IPMI_BUFFER_SIZE           ACPI_SERIAL_HEADER_SIZE + ACPI_IPMI_DATA_SIZE
#define ACPI_IPMI_DATA_SIZE             64
#define ACPI_MAX_ADDRESS_SPACE          255
#define ACPI_MAX_COMMENT_CACHE_DEPTH    96	
#define ACPI_MAX_EXTPARSE_CACHE_DEPTH   96	
#define ACPI_MAX_GSBUS_BUFFER_SIZE      ACPI_SERIAL_HEADER_SIZE + ACPI_MAX_GSBUS_DATA_SIZE
#define ACPI_MAX_GSBUS_DATA_SIZE        255
#define ACPI_MAX_LOOP_TIMEOUT           30
#define ACPI_MAX_MATCH_OPCODE           5
#define ACPI_MAX_NAMESPACE_CACHE_DEPTH  96	
#define ACPI_MAX_OBJECT_CACHE_DEPTH     96	
#define ACPI_MAX_PARSE_CACHE_DEPTH      96	
#define ACPI_MAX_REFERENCE_COUNT        0x4000
#define ACPI_MAX_SEMAPHORE_COUNT        256
#define ACPI_MAX_SLEEP                  2000	
#define ACPI_MAX_STATE_CACHE_DEPTH      96	
#define ACPI_METHOD_MAX_ARG             6
#define ACPI_METHOD_MAX_LOCAL           7
#define ACPI_METHOD_NUM_ARGS            7
#define ACPI_METHOD_NUM_LOCALS          8
#define ACPI_NUM_DEFAULT_SPACES         4
#define ACPI_NUM_OWNERID_MASKS          128
#define ACPI_NUM_sx_d_METHODS           4
#define ACPI_NUM_sx_w_METHODS           5
#define ACPI_OBJ_MAX_OPERAND            7
#define ACPI_OBJ_NUM_OPERANDS           8
#define ACPI_OS_NAME                    "Microsoft Windows NT"
#define ACPI_PRM_INPUT_BUFFER_SIZE      26
#define ACPI_REDUCED_HARDWARE           FALSE
#define ACPI_RESULTS_FRAME_OBJ_NUM      8
#define ACPI_RESULTS_OBJ_NUM_MAX        255
#define ACPI_ROOT_TABLE_SIZE_INCREMENT  4
#define ACPI_RSDP_CHECKSUM_LENGTH       20
#define ACPI_RSDP_SCAN_STEP             16
#define ACPI_RSDP_XCHECKSUM_LENGTH      36
#define ACPI_SERIAL_HEADER_SIZE         2	
#define ACPI_SMBUS_BUFFER_SIZE          ACPI_SERIAL_HEADER_SIZE + ACPI_SMBUS_DATA_SIZE
#define ACPI_SMBUS_DATA_SIZE            32
#define ACPI_USER_REGION_BEGIN          0x80
#define UUID_BUFFER_LENGTH          16	
#define UUID_HYPHEN1_OFFSET         8
#define UUID_HYPHEN2_OFFSET         13
#define UUID_HYPHEN3_OFFSET         18
#define UUID_HYPHEN4_OFFSET         23
#define UUID_STRING_LENGTH          36	

#define ACPI_MUTEX_SEM              1
#define ACPI_NO_UNIT_LIMIT          ((u32) -1)
#define ACPI_SIGNAL_BREAKPOINT      1
#define ACPI_SIGNAL_FATAL           0
#define REQUEST_DIR_ONLY                    1
#define REQUEST_FILE_ONLY                   0

# define acpi_os_acquire_raw_lock(handle)	acpi_os_acquire_lock(handle)
# define acpi_os_create_raw_lock(out_handle)	acpi_os_create_lock(out_handle)
# define acpi_os_delete_raw_lock(handle)	acpi_os_delete_lock(handle)
# define acpi_os_release_raw_lock(handle, flags)	\
	acpi_os_release_lock(handle, flags)

#define ACPI_ACQUIRE_GLOBAL_LOCK(Glptr, acquired) acquired = 1

#define ACPI_BINARY_SEMAPHORE       0



#define ACPI_DEBUGGER 1

#define ACPI_DISASSEMBLER 1

#define ACPI_FILE              FILE *
#define ACPI_FILE_ERR          stderr
#define ACPI_FILE_OUT          stdout








#define ACPI_MUTEX_TYPE             ACPI_BINARY_SEMAPHORE

#define ACPI_OSL_MUTEX              1
#define ACPI_RELEASE_GLOBAL_LOCK(Glptr, pending) pending = 0

#define ACPI_SRC_OS_LF_ONLY 0
#define ACPI_STRUCT_INIT(field, value)  value




#define COMPILER_DEPENDENT_INT64   long long
#define COMPILER_DEPENDENT_UINT64  unsigned long long
#define DEBUGGER_MULTI_THREADED     1
#define DEBUGGER_SINGLE_THREADED    0
#define DEBUGGER_THREADING          DEBUGGER_MULTI_THREADED


#define ACPI_CAST_PTHREAD_T(pthread) ((acpi_thread_id) (pthread))
#define ACPI_DEBUG_DEFAULT          (ACPI_LV_INFO | ACPI_LV_REPAIR)


#define ACPI_MACHINE_WIDTH          BITS_PER_LONG
#define ACPI_MSG_BIOS_ERROR     KERN_ERR "ACPI BIOS Error (bug): "
#define ACPI_MSG_BIOS_WARNING   KERN_WARNING "ACPI BIOS Warning (bug): "
#define ACPI_MSG_ERROR          KERN_ERR "ACPI Error: "
#define ACPI_MSG_EXCEPTION      KERN_ERR "ACPI Exception: "
#define ACPI_MSG_INFO           KERN_INFO "ACPI: "
#define ACPI_MSG_WARNING        KERN_WARNING "ACPI Warning: "




































#define acpi_cpu_flags                      unsigned long
#define acpi_raw_spinlock                   raw_spinlock_t *
#define strtoul                     simple_strtoul

#define __ismask(x) (_ctype[(int)(unsigned char)(x)])
#define isalnum(c)	((__ismask(c)&(_U|_L|_D)) != 0)
#define isalpha(c)	((__ismask(c)&(_U|_L)) != 0)
#define isascii(c) (((unsigned char)(c))<=0x7f)
#define iscntrl(c)	((__ismask(c)&(_C)) != 0)
#define  isdigit(c) __builtin_isdigit(c)
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

#define ACPI_GET_FUNCTION_NAME          __func__
#define COMPILER_VA_MACRO               1

#define __has_attribute(x) 0
#define va_arg(v, l)            __builtin_va_arg(v, l)
#define va_copy(d, s)           __builtin_va_copy(d, s)
#define va_end(v)               __builtin_va_end(v)
#define va_start(v, l)          __builtin_va_start(v, l)
#define ACPI_ACTUAL_DEBUG(level, line, filename, modulename, component, ...) \
	ACPI_DO_DEBUG_PRINT (acpi_debug_print, level, line, \
		filename, modulename, component, __VA_ARGS__)
#define ACPI_ACTUAL_DEBUG_RAW(level, line, filename, modulename, component, ...) \
	ACPI_DO_DEBUG_PRINT (acpi_debug_print_raw, level, line, \
		filename, modulename, component, __VA_ARGS__)
#define ACPI_ALL_COMPONENTS         0x0001FFFF
#define ACPI_ALL_DRIVERS            0xFFFF0000
#define ACPI_BIOS_ERROR(plist)          acpi_bios_error plist
#define ACPI_BIOS_EXCEPTION(plist)      acpi_bios_exception plist
#define ACPI_BIOS_WARNING(plist)        acpi_bios_warning plist
#define ACPI_CA_DEBUGGER            0x00000200
#define ACPI_CA_DISASSEMBLER        0x00000800
#define ACPI_COMPILER               0x00001000
#define ACPI_COMPONENT_DEFAULT      (ACPI_ALL_COMPONENTS)
#define ACPI_DB_ALL                 ACPI_DEBUG_LEVEL (ACPI_LV_ALL)
#define ACPI_DB_ALLOCATIONS         ACPI_DEBUG_LEVEL (ACPI_LV_ALLOCATIONS)
#define ACPI_DB_ALL_EXCEPTIONS      ACPI_DEBUG_LEVEL (ACPI_LV_ALL_EXCEPTIONS)
#define ACPI_DB_BFIELD              ACPI_DEBUG_LEVEL (ACPI_LV_BFIELD)
#define ACPI_DB_DEBUG_OBJECT        ACPI_DEBUG_LEVEL (ACPI_LV_DEBUG_OBJECT)
#define ACPI_DB_DISPATCH            ACPI_DEBUG_LEVEL (ACPI_LV_DISPATCH)
#define ACPI_DB_EVALUATION          ACPI_DEBUG_LEVEL (ACPI_LV_EVALUATION)
#define ACPI_DB_EVENTS              ACPI_DEBUG_LEVEL (ACPI_LV_EVENTS)
#define ACPI_DB_EXEC                ACPI_DEBUG_LEVEL (ACPI_LV_EXEC)
#define ACPI_DB_FUNCTIONS           ACPI_DEBUG_LEVEL (ACPI_LV_FUNCTIONS)
#define ACPI_DB_INFO                ACPI_DEBUG_LEVEL (ACPI_LV_INFO)
#define ACPI_DB_INIT                ACPI_DEBUG_LEVEL (ACPI_LV_INIT)
#define ACPI_DB_INIT_NAMES          ACPI_DEBUG_LEVEL (ACPI_LV_INIT_NAMES)
#define ACPI_DB_INTERRUPTS          ACPI_DEBUG_LEVEL (ACPI_LV_INTERRUPTS)
#define ACPI_DB_IO                  ACPI_DEBUG_LEVEL (ACPI_LV_IO)
#define ACPI_DB_LOAD                ACPI_DEBUG_LEVEL (ACPI_LV_LOAD)
#define ACPI_DB_MUTEX               ACPI_DEBUG_LEVEL (ACPI_LV_MUTEX)
#define ACPI_DB_NAMES               ACPI_DEBUG_LEVEL (ACPI_LV_NAMES)
#define ACPI_DB_OBJECTS             ACPI_DEBUG_LEVEL (ACPI_LV_OBJECTS)
#define ACPI_DB_OPREGION            ACPI_DEBUG_LEVEL (ACPI_LV_OPREGION)
#define ACPI_DB_OPTIMIZATIONS       ACPI_DEBUG_LEVEL (ACPI_LV_OPTIMIZATIONS)
#define ACPI_DB_PACKAGE             ACPI_DEBUG_LEVEL (ACPI_LV_PACKAGE)
#define ACPI_DB_PARSE               ACPI_DEBUG_LEVEL (ACPI_LV_PARSE)
#define ACPI_DB_PARSE_TREES         ACPI_DEBUG_LEVEL (ACPI_LV_PARSE_TREES)
#define ACPI_DB_REPAIR              ACPI_DEBUG_LEVEL (ACPI_LV_REPAIR)
#define ACPI_DB_RESOURCES           ACPI_DEBUG_LEVEL (ACPI_LV_RESOURCES)
#define ACPI_DB_TABLES              ACPI_DEBUG_LEVEL (ACPI_LV_TABLES)
#define ACPI_DB_THREADS             ACPI_DEBUG_LEVEL (ACPI_LV_THREADS)
#define ACPI_DB_TRACE_POINT         ACPI_DEBUG_LEVEL (ACPI_LV_TRACE_POINT)
#define ACPI_DB_USER_REQUESTS       ACPI_DEBUG_LEVEL (ACPI_LV_USER_REQUESTS)
#define ACPI_DB_VALUES              ACPI_DEBUG_LEVEL (ACPI_LV_VALUES)
#define ACPI_DEBUG_ALL              (ACPI_LV_AML_DISASSEMBLE | ACPI_LV_ALL_EXCEPTIONS | ACPI_LV_ALL)
#define ACPI_DEBUG_DEFAULT          (ACPI_LV_INIT | ACPI_LV_DEBUG_OBJECT | ACPI_LV_EVALUATION | ACPI_LV_REPAIR)
#define ACPI_DEBUG_EXEC(a)              a
#define ACPI_DEBUG_LEVEL(dl)        (u32) dl,ACPI_DEBUG_PARAMETERS
#define ACPI_DEBUG_OBJECT(obj,l,i)      acpi_ex_do_debug_object(obj,l,i)
#define ACPI_DEBUG_ONLY_MEMBERS(a)      a
#define ACPI_DEBUG_PARAMETERS \
	"__LINE__", ACPI_GET_FUNCTION_NAME, _acpi_module_name, _COMPONENT
#define ACPI_DEBUG_PRINT(plist)         acpi_debug_print plist
#define ACPI_DEBUG_PRINT_RAW(plist)     acpi_debug_print_raw plist
#define ACPI_DISPATCHER             0x00000040
#define ACPI_DO_DEBUG_PRINT(function, level, line, filename, modulename, component, ...) \
	ACPI_DO_WHILE0 ({ \
		if (ACPI_IS_DEBUG_ENABLED (level, component)) \
		{ \
			function (level, line, filename, modulename, component, __VA_ARGS__); \
		} \
	})
#define ACPI_DO_WHILE0(a)               do a while(0)
#define ACPI_DRIVER                 0x00008000
#define ACPI_DUMP_BUFFER(a, b)          acpi_ut_debug_dump_buffer((u8 *) a, b, DB_BYTE_DISPLAY, _COMPONENT)
#define ACPI_DUMP_ENTRY(a, b)           acpi_ns_dump_entry (a, b)
#define ACPI_DUMP_OPERANDS(a, b ,c)     acpi_ex_dump_operands(a, b, c)
#define ACPI_DUMP_PATHNAME(a, b, c, d)  acpi_ns_dump_pathname(a, b, c, d)
#define ACPI_DUMP_STACK_ENTRY(a)        acpi_ex_dump_operand((a), 0)
#define ACPI_ERROR(plist)               acpi_error plist
#define ACPI_EVENTS                 0x00000004
#define ACPI_EXAMPLE                0x00004000
#define ACPI_EXCEPTION(plist)           acpi_exception plist
#define ACPI_EXECUTER               0x00000080
#define ACPI_FUNCTION_ENTRY() \
	acpi_ut_track_stack_ptr()
#define ACPI_FUNCTION_NAME(name)        static const char _acpi_function_name[] = #name;
#define ACPI_FUNCTION_TRACE(name) \
	ACPI_FUNCTION_NAME(name) \
	acpi_ut_trace (ACPI_DEBUG_PARAMETERS)
#define ACPI_FUNCTION_TRACE_PTR(name, pointer) \
	ACPI_TRACE_ENTRY (name, acpi_ut_trace_ptr, void *, pointer)
#define ACPI_FUNCTION_TRACE_STR(name, string) \
	ACPI_TRACE_ENTRY (name, acpi_ut_trace_str, const char *, string)
#define ACPI_FUNCTION_TRACE_U32(name, value) \
	ACPI_TRACE_ENTRY (name, acpi_ut_trace_u32, u32, value)
#define ACPI_GET_FUNCTION_NAME          _acpi_function_name
#define ACPI_HARDWARE               0x00000002
#define ACPI_INFO(plist)                acpi_info plist
#define ACPI_IS_DEBUG_ENABLED(level, component) \
	((level & acpi_dbg_level) && (component & acpi_dbg_layer))
#define ACPI_LV_ALL                 ACPI_LV_VERBOSITY2
#define ACPI_LV_ALLOCATIONS         0x00100000
#define ACPI_LV_ALL_EXCEPTIONS      0x0000001F
#define ACPI_LV_AML_DISASSEMBLE     0x10000000
#define ACPI_LV_BFIELD              0x00001000
#define ACPI_LV_DEBUG_OBJECT        0x00000002
#define ACPI_LV_DISPATCH            0x00000100
#define ACPI_LV_EVALUATION          0x00080000
#define ACPI_LV_EVENTS              0x80000000
#define ACPI_LV_EXEC                0x00000200
#define ACPI_LV_FULL_TABLES         0x40000000
#define ACPI_LV_FUNCTIONS           0x00200000
#define ACPI_LV_INFO                0x00000004
#define ACPI_LV_INIT                0x00000001
#define ACPI_LV_INIT_NAMES          0x00000020
#define ACPI_LV_INTERRUPTS          0x08000000
#define ACPI_LV_IO                  0x04000000
#define ACPI_LV_LOAD                0x00000080
#define ACPI_LV_MUTEX               0x01000000
#define ACPI_LV_NAMES               0x00000400
#define ACPI_LV_OBJECTS             0x00008000
#define ACPI_LV_OPREGION            0x00000800
#define ACPI_LV_OPTIMIZATIONS       0x00400000
#define ACPI_LV_PACKAGE             0x00040000
#define ACPI_LV_PARSE               0x00000040
#define ACPI_LV_PARSE_TREES         0x00800000
#define ACPI_LV_REPAIR              0x00000008
#define ACPI_LV_RESOURCES           0x00010000
#define ACPI_LV_TABLES              0x00002000
#define ACPI_LV_THREADS             0x02000000
#define ACPI_LV_TRACE_POINT         0x00000010
#define ACPI_LV_USER_REQUESTS       0x00020000
#define ACPI_LV_VALUES              0x00004000
#define ACPI_LV_VERBOSE             0xF0000000
#define ACPI_LV_VERBOSE_INFO        0x20000000
#define ACPI_LV_VERBOSITY1          0x000FFF40 | ACPI_LV_ALL_EXCEPTIONS
#define ACPI_LV_VERBOSITY2          0x00F00000 | ACPI_LV_VERBOSITY1
#define ACPI_LV_VERBOSITY3          0x0F000000 | ACPI_LV_VERBOSITY2
#define ACPI_MODULE_NAME(name)          static const char ACPI_UNUSED_VAR _acpi_module_name[] = name;
#define ACPI_NAMESPACE              0x00000010
#define ACPI_NORMAL_DEFAULT         (ACPI_LV_INIT | ACPI_LV_DEBUG_OBJECT | ACPI_LV_REPAIR)
#define ACPI_OS_SERVICES            0x00000400
#define ACPI_PARSER                 0x00000020
#define ACPI_RESOURCES              0x00000100
#define ACPI_TABLES                 0x00000008
#define ACPI_TOOLS                  0x00002000
#define ACPI_TRACE_ENABLED          ((u32) 4)
#define ACPI_TRACE_ENTRY(name, function, type, param) \
	ACPI_FUNCTION_NAME (name) \
	function (ACPI_DEBUG_PARAMETERS, (type) (param))
#define ACPI_TRACE_EXIT(function, type, param) \
	ACPI_DO_WHILE0 ({ \
		register type _param = (type) (param); \
		function (ACPI_DEBUG_PARAMETERS, _param); \
		return (_param); \
	})
#define ACPI_TRACE_LAYER_ALL        0x000001FF
#define ACPI_TRACE_LAYER_DEFAULT    ACPI_EXECUTER
#define ACPI_TRACE_LEVEL_ALL        ACPI_LV_ALL
#define ACPI_TRACE_LEVEL_DEFAULT    ACPI_LV_TRACE_POINT
#define ACPI_TRACE_ONESHOT          ((u32) 2)
#define ACPI_TRACE_OPCODE           ((u32) 1)
#define ACPI_TRACE_POINT(a, b, c, d)    acpi_trace_point (a, b, c, d)
#define ACPI_UTILITIES              0x00000001
#define ACPI_WARNING(plist)             acpi_warning plist
#define AE_INFO                         _acpi_module_name, "__LINE__"
#define ASL_PREPROCESSOR            0x00020000
#define DT_COMPILER                 0x00010000


#define _acpi_module_name ""
#define return_ACPI_STATUS(status) \
	ACPI_TRACE_EXIT (acpi_ut_status_exit, acpi_status, status)
#define return_PTR(pointer) \
	ACPI_TRACE_EXIT (acpi_ut_ptr_exit, void *, pointer)
#define return_STR(string) \
	ACPI_TRACE_EXIT (acpi_ut_str_exit, const char *, string)
#define return_UINT32(value) \
	ACPI_TRACE_EXIT (acpi_ut_value_exit, u32, value)
#define return_UINT8(value) \
	ACPI_TRACE_EXIT (acpi_ut_value_exit, u8, value)
#define return_VALUE(value) \
	ACPI_TRACE_EXIT (acpi_ut_value_exit, u64, value)
#define return_VOID \
	ACPI_DO_WHILE0 ({ \
		acpi_ut_exit (ACPI_DEBUG_PARAMETERS); \
		return; \
	})

#define ACPI_DIV_64_BY_32(n_hi, n_lo, d32, q32, r32) \
	do { \
		u64 (__n) = ((u64) n_hi) << 32 | (n_lo); \
		(r32) = do_div ((__n), (d32)); \
		(q32) = (u32) (__n); \
	} while (0)
#define ACPI_SHIFT_RIGHT_64(n_hi, n_lo) \
	do { \
		(n_lo) >>= 1; \
		(n_lo) |= (((n_hi) & 1) << 31); \
		(n_hi) >>= 1; \
	} while (0)

#define acpi_os_create_lock(__handle) \
	({ \
		spinlock_t *lock = ACPI_ALLOCATE(sizeof(*lock)); \
		if (lock) { \
			*(__handle) = lock; \
			spin_lock_init(*(__handle)); \
		} \
		lock ? AE_OK : AE_NO_MEMORY; \
	})
#define ACPI_ACCEPTABLE_CONFIGURATION   (u8) 0x01
#define ACPI_ACTIVE_BOTH                (u8) 0x02
#define ACPI_ACTIVE_HIGH                (u8) 0x00
#define ACPI_ACTIVE_LOW                 (u8) 0x01
#define ACPI_ADDRESS_FIXED              (u8) 0x01
#define ACPI_ADDRESS_NOT_FIXED          (u8) 0x00
#define ACPI_BUS_MASTER                 (u8) 0x01
#define ACPI_BUS_NUMBER_RANGE           (u8) 0x02
#define ACPI_CACHABLE_MEMORY            (u8) 0x01
#define ACPI_COMPATIBILITY              (u8) 0x00
#define ACPI_CONSUMER                   (u8) 0x01
#define ACPI_CONTROLLER_INITIATED               0
#define ACPI_DECODE_10                  (u8) 0x00	
#define ACPI_DECODE_16                  (u8) 0x01	
#define ACPI_DEVICE_INITIATED                   1
#define ACPI_DMA_WIDTH128                       4
#define ACPI_DMA_WIDTH16                        1
#define ACPI_DMA_WIDTH256                       5
#define ACPI_DMA_WIDTH32                        2
#define ACPI_DMA_WIDTH64                        3
#define ACPI_DMA_WIDTH8                         0
#define ACPI_EDGE_SENSITIVE             (u8) 0x01
#define ACPI_ENTIRE_RANGE               (ACPI_NON_ISA_ONLY_RANGES | ACPI_ISA_ONLY_RANGES)
#define ACPI_EXCLUSIVE                  (u8) 0x00
#define ACPI_GOOD_CONFIGURATION         (u8) 0x00
#define ACPI_I2C_10BIT_MODE                     1
#define ACPI_I2C_7BIT_MODE                      0
#define ACPI_IO_RANGE                   (u8) 0x01
#define ACPI_IO_RESTRICT_INPUT                  1
#define ACPI_IO_RESTRICT_NONE                   0
#define ACPI_IO_RESTRICT_NONE_PRESERVE          3
#define ACPI_IO_RESTRICT_OUTPUT                 2
#define ACPI_ISA_ONLY_RANGES            (u8) 0x02
#define ACPI_LEVEL_SENSITIVE            (u8) 0x00
#define ACPI_MEMORY_RANGE               (u8) 0x00
#define ACPI_NEXT_RESOURCE(res) \
	ACPI_ADD_PTR (struct acpi_resource, (res), (res)->length)
#define ACPI_NON_CACHEABLE_MEMORY       (u8) 0x00
#define ACPI_NON_ISA_ONLY_RANGES        (u8) 0x01
#define ACPI_NOT_BUS_MASTER             (u8) 0x00
#define ACPI_NOT_WAKE_CAPABLE           (u8) 0x00
#define ACPI_PIN_CONFIG_BIAS_BUS_HOLD           6
#define ACPI_PIN_CONFIG_BIAS_DEFAULT            3
#define ACPI_PIN_CONFIG_BIAS_DISABLE            4
#define ACPI_PIN_CONFIG_BIAS_HIGH_IMPEDANCE     5
#define ACPI_PIN_CONFIG_BIAS_PULL_DOWN          2
#define ACPI_PIN_CONFIG_BIAS_PULL_UP            1
#define ACPI_PIN_CONFIG_DEFAULT                 0
#define ACPI_PIN_CONFIG_DRIVE_OPEN_DRAIN        7
#define ACPI_PIN_CONFIG_DRIVE_OPEN_SOURCE       8
#define ACPI_PIN_CONFIG_DRIVE_PUSH_PULL         9
#define ACPI_PIN_CONFIG_DRIVE_STRENGTH          10
#define ACPI_PIN_CONFIG_INPUT_DEBOUNCE          12
#define ACPI_PIN_CONFIG_INPUT_SCHMITT_TRIGGER   13
#define ACPI_PIN_CONFIG_NOPULL                  3
#define ACPI_PIN_CONFIG_PULLDOWN                2
#define ACPI_PIN_CONFIG_PULLUP                  1
#define ACPI_PIN_CONFIG_SLEW_RATE               11
#define ACPI_POS_DECODE                 (u8) 0x00
#define ACPI_PREFETCHABLE_MEMORY        (u8) 0x03
#define ACPI_PRODUCER                   (u8) 0x00
#define ACPI_READ_ONLY_MEMORY           (u8) 0x00
#define ACPI_READ_WRITE_MEMORY          (u8) 0x01
#define ACPI_RESOURCE_ADDRESS_COMMON \
	u8                                      resource_type; \
	u8                                      producer_consumer; \
	u8                                      decode; \
	u8                                      min_address_fixed; \
	u8                                      max_address_fixed; \
	union acpi_resource_attribute           info;
#define ACPI_RESOURCE_GPIO_TYPE_INT             0
#define ACPI_RESOURCE_GPIO_TYPE_IO              1
#define ACPI_RESOURCE_SERIAL_COMMON \
	u8                                      revision_id; \
	u8                                      type; \
	u8                                      producer_consumer;   \
	u8                                      slave_mode; \
	u8                                      connection_sharing; \
	u8                                      type_revision_id; \
	u16                                     type_data_length; \
	u16                                     vendor_length; \
	struct acpi_resource_source             resource_source; \
	u8                                      *vendor_data;
#define ACPI_RESOURCE_SERIAL_TYPE_CSI2          4
#define ACPI_RESOURCE_SERIAL_TYPE_I2C           1
#define ACPI_RESOURCE_SERIAL_TYPE_SPI           2
#define ACPI_RESOURCE_SERIAL_TYPE_UART          3
#define ACPI_RESOURCE_TYPE_ADDRESS16            11
#define ACPI_RESOURCE_TYPE_ADDRESS32            12
#define ACPI_RESOURCE_TYPE_ADDRESS64            13
#define ACPI_RESOURCE_TYPE_DMA                  1
#define ACPI_RESOURCE_TYPE_END_DEPENDENT        3
#define ACPI_RESOURCE_TYPE_END_TAG              7
#define ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64   14	
#define ACPI_RESOURCE_TYPE_EXTENDED_IRQ         15
#define ACPI_RESOURCE_TYPE_FIXED_DMA            18	
#define ACPI_RESOURCE_TYPE_FIXED_IO             5
#define ACPI_RESOURCE_TYPE_FIXED_MEMORY32       10
#define ACPI_RESOURCE_TYPE_GENERIC_REGISTER     16
#define ACPI_RESOURCE_TYPE_GPIO                 17	
#define ACPI_RESOURCE_TYPE_IO                   4
#define ACPI_RESOURCE_TYPE_IRQ                  0
#define ACPI_RESOURCE_TYPE_MAX                  24
#define ACPI_RESOURCE_TYPE_MEMORY24             8
#define ACPI_RESOURCE_TYPE_MEMORY32             9
#define ACPI_RESOURCE_TYPE_PIN_CONFIG           21	
#define ACPI_RESOURCE_TYPE_PIN_FUNCTION         20	
#define ACPI_RESOURCE_TYPE_PIN_GROUP            22	
#define ACPI_RESOURCE_TYPE_PIN_GROUP_CONFIG     24	
#define ACPI_RESOURCE_TYPE_PIN_GROUP_FUNCTION   23	
#define ACPI_RESOURCE_TYPE_SERIAL_BUS           19	
#define ACPI_RESOURCE_TYPE_START_DEPENDENT      2
#define ACPI_RESOURCE_TYPE_VENDOR               6
#define ACPI_RS_SIZE(type)                  (u32) (ACPI_RS_SIZE_NO_DATA + sizeof (type))
#define ACPI_RS_SIZE_MIN                    (u32) ACPI_ROUND_UP_TO_NATIVE_WORD (12)
#define ACPI_RS_SIZE_NO_DATA                8	
#define ACPI_SHARED                     (u8) 0x01
#define ACPI_SPARSE_TRANSLATION         (u8) 0x01
#define ACPI_SPI_3WIRE_MODE                     1
#define ACPI_SPI_4WIRE_MODE                     0
#define ACPI_SPI_ACTIVE_HIGH                    1
#define ACPI_SPI_ACTIVE_LOW                     0
#define ACPI_SPI_FIRST_PHASE                    0
#define ACPI_SPI_SECOND_PHASE                   1
#define ACPI_SPI_START_HIGH                     1
#define ACPI_SPI_START_LOW                      0
#define ACPI_SUB_DECODE                 (u8) 0x01
#define ACPI_SUB_OPTIMAL_CONFIGURATION  (u8) 0x02
#define ACPI_TRANSFER_16                (u8) 0x02
#define ACPI_TRANSFER_8                 (u8) 0x00
#define ACPI_TRANSFER_8_16              (u8) 0x01
#define ACPI_TYPE_A                     (u8) 0x01
#define ACPI_TYPE_B                     (u8) 0x02
#define ACPI_TYPE_F                     (u8) 0x03
#define ACPI_UART_1P5_STOP_BITS                 2
#define ACPI_UART_1_STOP_BIT                    1
#define ACPI_UART_2_STOP_BITS                   3
#define ACPI_UART_5_DATA_BITS                   0
#define ACPI_UART_6_DATA_BITS                   1
#define ACPI_UART_7_DATA_BITS                   2
#define ACPI_UART_8_DATA_BITS                   3
#define ACPI_UART_9_DATA_BITS                   4
#define ACPI_UART_BIG_ENDIAN                    1
#define ACPI_UART_CARRIER_DETECT                (1<<2)
#define ACPI_UART_CLEAR_TO_SEND                 (1<<6)
#define ACPI_UART_DATA_SET_READY                (1<<4)
#define ACPI_UART_DATA_TERMINAL_READY           (1<<5)
#define ACPI_UART_FLOW_CONTROL_HW               1
#define ACPI_UART_FLOW_CONTROL_NONE             0
#define ACPI_UART_FLOW_CONTROL_XON_XOFF         2
#define ACPI_UART_LITTLE_ENDIAN                 0
#define ACPI_UART_NO_STOP_BITS                  0
#define ACPI_UART_PARITY_EVEN                   1
#define ACPI_UART_PARITY_MARK                   3
#define ACPI_UART_PARITY_NONE                   0
#define ACPI_UART_PARITY_ODD                    2
#define ACPI_UART_PARITY_SPACE                  4
#define ACPI_UART_REQUEST_TO_SEND               (1<<7)
#define ACPI_UART_RING_INDICATOR                (1<<3)
#define ACPI_WAKE_CAPABLE               (u8) 0x01
#define ACPI_WRITE_COMBINING_MEMORY     (u8) 0x02

#define ACPI_AML_EXCEPTION(status)      (((status) & AE_CODE_MASK) == AE_CODE_AML)
#define ACPI_CNTL_EXCEPTION(status)     (((status) & AE_CODE_MASK) == AE_CODE_CONTROL)
#define ACPI_ENV_EXCEPTION(status)      (((status) & AE_CODE_MASK) == AE_CODE_ENVIRONMENTAL)
#define ACPI_FAILURE(a)                 (a)
#define ACPI_PROG_EXCEPTION(status)     (((status) & AE_CODE_MASK) == AE_CODE_PROGRAMMER)
#define ACPI_SUCCESS(a)                 (!(a))
#define ACPI_TABLE_EXCEPTION(status)    (((status) & AE_CODE_MASK) == AE_CODE_ACPI_TABLES)
#define AE_ABORT_METHOD                 EXCEP_ENV (0x0018)
#define AE_ACCESS                       EXCEP_ENV (0x001D)
#define AE_ACQUIRE_DEADLOCK             EXCEP_ENV (0x0012)
#define AE_ALREADY_ACQUIRED             EXCEP_ENV (0x0015)
#define AE_ALREADY_EXISTS               EXCEP_ENV (0x0007)
#define AE_AML_ALIGNMENT                EXCEP_AML (0x001B)
#define AE_AML_BAD_NAME                 EXCEP_AML (0x000D)
#define AE_AML_BAD_OPCODE               EXCEP_AML (0x0001)
#define AE_AML_BAD_RESOURCE_LENGTH      EXCEP_AML (0x001F)
#define AE_AML_BAD_RESOURCE_VALUE       EXCEP_AML (0x001D)
#define AE_AML_BUFFER_LENGTH            EXCEP_AML (0x0025)
#define AE_AML_BUFFER_LIMIT             EXCEP_AML (0x000A)
#define AE_AML_CIRCULAR_REFERENCE       EXCEP_AML (0x001E)
#define AE_AML_DIVIDE_BY_ZERO           EXCEP_AML (0x000C)
#define AE_AML_ILLEGAL_ADDRESS          EXCEP_AML (0x0020)
#define AE_AML_INTERNAL                 EXCEP_AML (0x000F)
#define AE_AML_INVALID_INDEX            EXCEP_AML (0x0018)
#define AE_AML_INVALID_RESOURCE_TYPE    EXCEP_AML (0x0017)
#define AE_AML_INVALID_SPACE_ID         EXCEP_AML (0x0010)
#define AE_AML_LOOP_TIMEOUT             EXCEP_AML (0x0021)
#define AE_AML_METHOD_LIMIT             EXCEP_AML (0x0013)
#define AE_AML_MUTEX_NOT_ACQUIRED       EXCEP_AML (0x0016)
#define AE_AML_MUTEX_ORDER              EXCEP_AML (0x0015)
#define AE_AML_NAME_NOT_FOUND           EXCEP_AML (0x000E)
#define AE_AML_NOT_OWNER                EXCEP_AML (0x0014)
#define AE_AML_NO_OPERAND               EXCEP_AML (0x0002)
#define AE_AML_NO_RESOURCE_END_TAG      EXCEP_AML (0x001C)
#define AE_AML_NO_RETURN_VALUE          EXCEP_AML (0x0012)
#define AE_AML_NO_WHILE                 EXCEP_AML (0x001A)
#define AE_AML_NUMERIC_OVERFLOW         EXCEP_AML (0x0008)
#define AE_AML_OPERAND_TYPE             EXCEP_AML (0x0003)
#define AE_AML_OPERAND_VALUE            EXCEP_AML (0x0004)
#define AE_AML_PACKAGE_LIMIT            EXCEP_AML (0x000B)
#define AE_AML_PROTOCOL                 EXCEP_AML (0x0024)
#define AE_AML_REGION_LIMIT             EXCEP_AML (0x0009)
#define AE_AML_REGISTER_LIMIT           EXCEP_AML (0x0019)
#define AE_AML_STRING_LIMIT             EXCEP_AML (0x0011)
#define AE_AML_TARGET_TYPE              EXCEP_AML (0x0023)
#define AE_AML_UNINITIALIZED_ARG        EXCEP_AML (0x0006)
#define AE_AML_UNINITIALIZED_ELEMENT    EXCEP_AML (0x0007)
#define AE_AML_UNINITIALIZED_LOCAL      EXCEP_AML (0x0005)
#define AE_AML_UNINITIALIZED_NODE       EXCEP_AML (0x0022)
#define AE_BAD_ADDRESS                  EXCEP_PGM (0x0009)
#define AE_BAD_CHARACTER                EXCEP_PGM (0x0002)
#define AE_BAD_CHECKSUM                 EXCEP_TBL (0x0003)
#define AE_BAD_DATA                     EXCEP_PGM (0x0004)
#define AE_BAD_DECIMAL_CONSTANT         EXCEP_PGM (0x0007)
#define AE_BAD_HEADER                   EXCEP_TBL (0x0002)
#define AE_BAD_HEX_CONSTANT             EXCEP_PGM (0x0005)
#define AE_BAD_OCTAL_CONSTANT           EXCEP_PGM (0x0006)
#define AE_BAD_PARAMETER                EXCEP_PGM (0x0001)
#define AE_BAD_PATHNAME                 EXCEP_PGM (0x0003)
#define AE_BAD_SIGNATURE                EXCEP_TBL (0x0001)
#define AE_BAD_VALUE                    EXCEP_TBL (0x0004)
#define AE_BUFFER_OVERFLOW              EXCEP_ENV (0x000B)
#define AE_CODE_ACPI_TABLES             0x2000	
#define AE_CODE_AML                     0x3000	
#define AE_CODE_AML_MAX                 0x0025
#define AE_CODE_CONTROL                 0x4000	
#define AE_CODE_CTRL_MAX                0x000C
#define AE_CODE_ENVIRONMENTAL           0x0000	
#define AE_CODE_ENV_MAX                 0x0023
#define AE_CODE_MASK                    0xF000
#define AE_CODE_MAX                     0x4000
#define AE_CODE_PGM_MAX                 0x0009
#define AE_CODE_PROGRAMMER              0x1000	
#define AE_CODE_TBL_MAX                 0x0005
#define AE_CTRL_BREAK                   EXCEP_CTL (0x0009)
#define AE_CTRL_CONTINUE                EXCEP_CTL (0x000A)
#define AE_CTRL_DEPTH                   EXCEP_CTL (0x0006)
#define AE_CTRL_END                     EXCEP_CTL (0x0007)
#define AE_CTRL_FALSE                   EXCEP_CTL (0x0005)
#define AE_CTRL_PARSE_CONTINUE          EXCEP_CTL (0x000B)
#define AE_CTRL_PARSE_PENDING           EXCEP_CTL (0x000C)
#define AE_CTRL_PENDING                 EXCEP_CTL (0x0002)
#define AE_CTRL_RETURN_VALUE            EXCEP_CTL (0x0001)
#define AE_CTRL_TERMINATE               EXCEP_CTL (0x0003)
#define AE_CTRL_TRANSFER                EXCEP_CTL (0x0008)
#define AE_CTRL_TRUE                    EXCEP_CTL (0x0004)
#define AE_DECIMAL_OVERFLOW             EXCEP_ENV (0x0021)
#define AE_END_OF_TABLE                 EXCEP_ENV (0x0023)
#define AE_ERROR                        EXCEP_ENV (0x0001)
#define AE_HEX_OVERFLOW                 EXCEP_ENV (0x0020)
#define AE_INVALID_TABLE_LENGTH         EXCEP_TBL (0x0005)
#define AE_IO_ERROR                     EXCEP_ENV (0x001E)
#define AE_LIMIT                        EXCEP_ENV (0x0010)
#define AE_MISSING_ARGUMENTS            EXCEP_PGM (0x0008)
#define AE_NOT_ACQUIRED                 EXCEP_ENV (0x0014)
#define AE_NOT_CONFIGURED               EXCEP_ENV (0x001C)
#define AE_NOT_EXIST                    EXCEP_ENV (0x0006)
#define AE_NOT_FOUND                    EXCEP_ENV (0x0005)
#define AE_NOT_IMPLEMENTED              EXCEP_ENV (0x000E)
#define AE_NO_ACPI_TABLES               EXCEP_ENV (0x0002)
#define AE_NO_GLOBAL_LOCK               EXCEP_ENV (0x0017)
#define AE_NO_HANDLER                   EXCEP_ENV (0x001A)
#define AE_NO_HARDWARE_RESPONSE         EXCEP_ENV (0x0016)
#define AE_NO_MEMORY                    EXCEP_ENV (0x0004)
#define AE_NO_NAMESPACE                 EXCEP_ENV (0x0003)
#define AE_NULL_ENTRY                   EXCEP_ENV (0x000A)
#define AE_NULL_OBJECT                  EXCEP_ENV (0x0009)
#define AE_NUMERIC_OVERFLOW             EXCEP_ENV (0x001F)
#define AE_OCTAL_OVERFLOW               EXCEP_ENV (0x0022)
#define AE_OK                           (acpi_status) 0x0000
#define AE_OWNER_ID_LIMIT               EXCEP_ENV (0x001B)
#define AE_RELEASE_DEADLOCK             EXCEP_ENV (0x0013)
#define AE_SAME_HANDLER                 EXCEP_ENV (0x0019)
#define AE_STACK_OVERFLOW               EXCEP_ENV (0x000C)
#define AE_STACK_UNDERFLOW              EXCEP_ENV (0x000D)
#define AE_SUPPORT                      EXCEP_ENV (0x000F)
#define AE_TIME                         EXCEP_ENV (0x0011)
#define AE_TYPE                         EXCEP_ENV (0x0008)
#define EXCEP_AML(code)                 ((acpi_status) (code | AE_CODE_AML))
#define EXCEP_CTL(code)                 ((acpi_status) (code | AE_CODE_CONTROL))
#define EXCEP_ENV(code)                 ((acpi_status) (code | AE_CODE_ENVIRONMENTAL))
#define EXCEP_PGM(code)                 ((acpi_status) (code | AE_CODE_PROGRAMMER))
#define EXCEP_TBL(code)                 ((acpi_status) (code | AE_CODE_ACPI_TABLES))
#define EXCEP_TXT(name,description)     {name, description}

#define ACPI_NAMESPACE_ROOT     "Namespace Root"
#define ACPI_NS_ROOT_PATH       "\\"
#define ACPI_PREFIX_LOWER       (u32) 0x69706361	
#define ACPI_PREFIX_MIXED       (u32) 0x69706341	
#define ACPI_ROOT_NAME          (u32) 0x5F5F5F5C	
#define ACPI_ROOT_PATHNAME      "\\___"
#define ACPI_UNKNOWN_NAME       (u32) 0x3F3F3F3F	
#define METHOD_NAME__ADR        "_ADR"
#define METHOD_NAME__AEI        "_AEI"
#define METHOD_NAME__BBN        "_BBN"
#define METHOD_NAME__CBA        "_CBA"
#define METHOD_NAME__CID        "_CID"
#define METHOD_NAME__CLS        "_CLS"
#define METHOD_NAME__CRS        "_CRS"
#define METHOD_NAME__DDN        "_DDN"
#define METHOD_NAME__DIS        "_DIS"
#define METHOD_NAME__DMA        "_DMA"
#define METHOD_NAME__DSD        "_DSD"
#define METHOD_NAME__HID        "_HID"
#define METHOD_NAME__INI        "_INI"
#define METHOD_NAME__PLD        "_PLD"
#define METHOD_NAME__PRS        "_PRS"
#define METHOD_NAME__PRT        "_PRT"
#define METHOD_NAME__PRW        "_PRW"
#define METHOD_NAME__PS0        "_PS0"
#define METHOD_NAME__PS1        "_PS1"
#define METHOD_NAME__PS2        "_PS2"
#define METHOD_NAME__PS3        "_PS3"
#define METHOD_NAME__REG        "_REG"
#define METHOD_NAME__SB_        "_SB_"
#define METHOD_NAME__SEG        "_SEG"
#define METHOD_NAME__SRS        "_SRS"
#define METHOD_NAME__STA        "_STA"
#define METHOD_NAME__SUB        "_SUB"
#define METHOD_NAME__UID        "_UID"
#define METHOD_PATHNAME__PTS    "\\_PTS"
#define METHOD_PATHNAME__SST    "\\_SI._SST"
#define METHOD_PATHNAME__WAK    "\\_WAK"


#define resource_list_for_each_entry(entry, list)	\
	list_for_each_entry((entry), (list), node)
#define resource_list_for_each_entry_safe(entry, tmp, list)	\
	list_for_each_entry_safe((entry), (tmp), (list), node)
#define IRQ_DOMAIN_IRQ_SPEC_PARAMS 16




#define mdelay(n) (\
	(__builtin_constant_p(n) && (n)<=MAX_UDELAY_MS) ? udelay((n)*1000) : \
	({unsigned long __ms=(n); while (__ms--) udelay(1000);}))
#define ndelay(x) ndelay(x)

#define I2C_ADDRS(addr, addrs...) \
	((const unsigned short []){ addr, ## addrs, I2C_CLIENT_END })
#define I2C_BOARD_INFO(dev_type, dev_addr) \
	.type = dev_type, .addr = (dev_addr)
#define I2C_DEVICE_ID_ANALOG_DEVICES                    5
#define I2C_DEVICE_ID_ATMEL                            13
#define I2C_DEVICE_ID_ESPROS_PHOTONICS_AG               9
#define I2C_DEVICE_ID_FLIR                             11
#define I2C_DEVICE_ID_FUJITSU_SEMICONDUCTOR            10
#define I2C_DEVICE_ID_NONE                         0xffff
#define I2C_DEVICE_ID_NXP_SEMICONDUCTORS                0
#define I2C_DEVICE_ID_NXP_SEMICONDUCTORS_1              1
#define I2C_DEVICE_ID_NXP_SEMICONDUCTORS_2              2
#define I2C_DEVICE_ID_NXP_SEMICONDUCTORS_3              3
#define I2C_DEVICE_ID_O2MICRO                          12
#define I2C_DEVICE_ID_ON_SEMICONDUCTOR                  7
#define I2C_DEVICE_ID_RAMTRON_INTERNATIONAL             4
#define I2C_DEVICE_ID_SPRINTEK_CORPORATION              8
#define I2C_DEVICE_ID_STMICROELECTRONICS                6
#define I2C_LOCK_ROOT_ADAPTER BIT(0)
#define I2C_LOCK_SEGMENT      BIT(1)

#define builtin_i2c_driver(__i2c_driver) \
	builtin_driver(__i2c_driver, i2c_add_driver)
#define i2c_add_driver(driver) \
	i2c_register_driver(THIS_MODULE, driver)
#define module_i2c_driver(__i2c_driver) \
	module_driver(__i2c_driver, i2c_add_driver, \
			i2c_del_driver)
#define to_i2c_adapter(d) container_of(d, struct i2c_adapter, dev)
#define to_i2c_client(d) container_of(d, struct i2c_client, dev)
#define to_i2c_driver(d) container_of(d, struct i2c_driver, driver)
#define I2C_FUNC_SMBUS_WRITE_BLOCK_DATA 0x02000000
#define I2C_SMBUS_BLOCK_PROC_CALL   7		
#define I2C_SMBUS_I2C_BLOCK_BROKEN  6
#define I2C_SMBUS_I2C_BLOCK_DATA    8


# define swab __swab
# define swab16 __swab16
# define swab16p __swab16p
# define swab16s __swab16s
# define swab32 __swab32
# define swab32p __swab32p
# define swab32s __swab32s
# define swab64 __swab64
# define swab64p __swab64p
# define swab64s __swab64s
# define swahb32 __swahb32
# define swahb32p __swahb32p
# define swahb32s __swahb32s
# define swahw32 __swahw32
# define swahw32p __swahw32p
# define swahw32s __swahw32s

#define ___constant_swab16(x) ((__u16)(				\
	(((__u16)(x) & (__u16)0x00ffU) << 8) |			\
	(((__u16)(x) & (__u16)0xff00U) >> 8)))
#define ___constant_swab32(x) ((__u32)(				\
	(((__u32)(x) & (__u32)0x000000ffUL) << 24) |		\
	(((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |		\
	(((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |		\
	(((__u32)(x) & (__u32)0xff000000UL) >> 24)))
#define ___constant_swab64(x) ((__u64)(				\
	(((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) |	\
	(((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40) |	\
	(((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) |	\
	(((__u64)(x) & (__u64)0x00000000ff000000ULL) <<  8) |	\
	(((__u64)(x) & (__u64)0x000000ff00000000ULL) >>  8) |	\
	(((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) |	\
	(((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40) |	\
	(((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56)))
#define ___constant_swahb32(x) ((__u32)(			\
	(((__u32)(x) & (__u32)0x00ff00ffUL) << 8) |		\
	(((__u32)(x) & (__u32)0xff00ff00UL) >> 8)))
#define ___constant_swahw32(x) ((__u32)(			\
	(((__u32)(x) & (__u32)0x0000ffffUL) << 16) |		\
	(((__u32)(x) & (__u32)0xffff0000UL) >> 16)))
#define __swab16(x) (__u16)__builtin_bswap16((__u16)(x))
#define __swab32(x) (__u32)__builtin_bswap32((__u32)(x))
#define __swab64(x) (__u64)__builtin_bswap64((__u64)(x))
#define __swahb32(x)				\
	(__builtin_constant_p((__u32)(x)) ?	\
	___constant_swahb32(x) :		\
	__fswahb32(x))
#define __swahw32(x)				\
	(__builtin_constant_p((__u32)(x)) ?	\
	___constant_swahw32(x) :		\
	__fswahw32(x))
#define DECLARE_BUILTIN_FIRMWARE(name, blob)				     \
	DECLARE_BUILTIN_FIRMWARE_SIZE(name, &(blob), sizeof(blob))
#define DECLARE_BUILTIN_FIRMWARE_SIZE(name, blob, size)			     \
	static const struct builtin_fw __fw_concat(__builtin_fw,__COUNTER__) \
	__used __section(".builtin_fw") = { name, blob, size }
#define FW_ACTION_NOUEVENT 0
#define FW_ACTION_UEVENT 1

#define __fw_concat(x, y) __fw_concat1(x, y)
#define __fw_concat1(x, y) x##y
#define DECLARE_PCI_FIXUP_CLASS_EARLY(vendor, device, class,		\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_early,			\
		hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_ENABLE(vendor, device, class,		\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_enable,			\
		hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_FINAL(vendor, device, class,		\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_final,			\
		hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_HEADER(vendor, device, class,		\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_header,			\
		hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_RESUME(vendor, device, class,		\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_resume,			\
		resume##hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_RESUME_EARLY(vendor, device, class,	\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_resume_early,		\
		resume_early##hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_SUSPEND(vendor, device, class,		\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_suspend,			\
		suspend##hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_CLASS_SUSPEND_LATE(vendor, device, class,	\
					 class_shift, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_suspend_late,		\
		suspend_late##hook, vendor, device, class, class_shift, hook)
#define DECLARE_PCI_FIXUP_EARLY(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_early,			\
		hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_ENABLE(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_enable,			\
		hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_FINAL(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_final,			\
		hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_HEADER(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_header,			\
		hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_RESUME(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_resume,			\
		resume##hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_RESUME_EARLY(vendor, device, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_resume_early,		\
		resume_early##hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_SECTION(sec, name, vendor, device, class,	\
				  class_shift, hook)			\
	__DECLARE_PCI_FIXUP_SECTION(sec, name, vendor, device, class,	\
				  class_shift, hook, __UNIQUE_ID(hook))
#define DECLARE_PCI_FIXUP_SUSPEND(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_suspend,			\
		suspend##hook, vendor, device, PCI_ANY_ID, 0, hook)
#define DECLARE_PCI_FIXUP_SUSPEND_LATE(vendor, device, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_suspend_late,		\
		suspend_late##hook, vendor, device, PCI_ANY_ID, 0, hook)

#define PCI_BRIDGE_RESOURCE_NUM 4
#define PCI_BUS_NUM(x) (((x) >> 8) & 0xff)
#define PCI_DEVICE(vend,dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#define PCI_DEVICE_CLASS(dev_class,dev_class_mask) \
	.class = (dev_class), .class_mask = (dev_class_mask), \
	.vendor = PCI_ANY_ID, .device = PCI_ANY_ID, \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID
#define PCI_DEVICE_DATA(vend, dev, data) \
	.vendor = PCI_VENDOR_ID_##vend, .device = PCI_DEVICE_ID_##vend##_##dev, \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID, 0, 0, \
	.driver_data = (kernel_ulong_t)(data)
#define PCI_DEVICE_DRIVER_OVERRIDE(vend, dev, driver_override) \
	.vendor = (vend), .device = (dev), .subvendor = PCI_ANY_ID, \
	.subdevice = PCI_ANY_ID, .override_only = (driver_override)
#define PCI_DEVICE_SUB(vend, dev, subvend, subdev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = (subvend), .subdevice = (subdev)
#define PCI_DEVID(bus, devfn)	((((u16)(bus)) << 8) | (devfn))
#define PCI_DOMAIN_NR_NOT_SET (-1)
#define PCI_DRIVER_OVERRIDE_DEVICE_VFIO(vend, dev) \
	PCI_DEVICE_DRIVER_OVERRIDE(vend, dev, PCI_ID_F_VFIO_DRIVER_OVERRIDE)
#define PCI_IRQ_ALL_TYPES \
	(PCI_IRQ_LEGACY | PCI_IRQ_MSI | PCI_IRQ_MSIX)
#define PCI_NUM_RESET_METHODS 7
#define PCI_STATUS_ERROR_BITS (PCI_STATUS_DETECTED_PARITY  | \
			       PCI_STATUS_SIG_SYSTEM_ERROR | \
			       PCI_STATUS_REC_MASTER_ABORT | \
			       PCI_STATUS_REC_TARGET_ABORT | \
			       PCI_STATUS_SIG_TARGET_ABORT | \
			       PCI_STATUS_PARITY)
#define PCI_VDEVICE(vend, dev) \
	.vendor = PCI_VENDOR_ID_##vend, .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID, 0, 0
#define PCI_VGA_STATE_CHANGE_BRIDGE (1 << 0)
#define PCI_VGA_STATE_CHANGE_DECODES (1 << 1)
#define PCI_VPD_LRDT_ID(x)		((x) | PCI_VPD_LRDT)
#define _PCI_NOP(o, s, t) \
	static inline int pci_##o##_config_##s(struct pci_dev *dev, \
						int where, t val) \
		{ return PCIBIOS_FUNC_NOT_SUPPORTED; }
#define _PCI_NOP_ALL(o, x)	_PCI_NOP(o, byte, u8 x) \
				_PCI_NOP(o, word, u16 x) \
				_PCI_NOP(o, dword, u32 x)
#define __DECLARE_PCI_FIXUP_SECTION(sec, name, vendor, device, class,	\
				  class_shift, hook, stub)		\
	void __cficanonical stub(struct pci_dev *dev);			\
	void __cficanonical stub(struct pci_dev *dev)			\
	{ 								\
		hook(dev); 						\
	}								\
	___DECLARE_PCI_FIXUP_SECTION(sec, name, vendor, device, class,	\
				  class_shift, stub)
#define ___DECLARE_PCI_FIXUP_SECTION(sec, name, vendor, device, class,	\
				    class_shift, hook)			\
	__ADDRESSABLE(hook)						\
	asm(".section "	#sec ", \"a\"				\n"	\
	    ".balign	16					\n"	\
	    ".short "	#vendor ", " #device "			\n"	\
	    ".long "	#class ", " #class_shift "		\n"	\
	    ".long "	#hook " - .				\n"	\
	    ".previous						\n");
#define arch_can_pci_mmap_io()		0
#define arch_can_pci_mmap_wc()		0
#define builtin_pci_driver(__pci_driver) \
	builtin_driver(__pci_driver, pci_register_driver)
#define dev_is_pci(d) ((d)->bus == &pci_bus_type)
#define dev_is_pf(d) ((dev_is_pci(d) ? to_pci_dev(d)->is_physfn : false))
#define for_each_pci_bridge(dev, bus)				\
	list_for_each_entry(dev, &bus->devices, bus_list)	\
		if (!pci_is_bridge(dev)) {} else
#define for_each_pci_dev(d) while ((d = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, d)) != NULL)
#define module_pci_driver(__pci_driver) \
	module_driver(__pci_driver, pci_register_driver, pci_unregister_driver)
#define no_pci_devices()	(1)
#define pci_WARN(pdev, condition, fmt, arg...) \
	WARN(condition, "%s %s: " fmt, \
	     dev_driver_string(&(pdev)->dev), pci_name(pdev), ##arg)
#define pci_WARN_ONCE(pdev, condition, fmt, arg...) \
	WARN_ONCE(condition, "%s %s: " fmt, \
		  dev_driver_string(&(pdev)->dev), pci_name(pdev), ##arg)
#define pci_alert(pdev, fmt, arg...)	dev_alert(&(pdev)->dev, fmt, ##arg)
#define pci_bus_for_each_resource(bus, res, i)				\
	for (i = 0;							\
	    (res = pci_bus_resource_n(bus, i)) || i < PCI_BRIDGE_RESOURCE_NUM; \
	     i++)
#define pci_crit(pdev, fmt, arg...)	dev_crit(&(pdev)->dev, fmt, ##arg)
#define pci_dbg(pdev, fmt, arg...)	dev_dbg(&(pdev)->dev, fmt, ##arg)
#define pci_dev_present(ids)	(0)
#define pci_dev_put(dev)	do { } while (0)
#define pci_emerg(pdev, fmt, arg...)	dev_emerg(&(pdev)->dev, fmt, ##arg)
#define pci_err(pdev, fmt, arg...)	dev_err(&(pdev)->dev, fmt, ##arg)
#define pci_info(pdev, fmt, arg...)	dev_info(&(pdev)->dev, fmt, ##arg)
#define pci_info_ratelimited(pdev, fmt, arg...) \
	dev_info_ratelimited(&(pdev)->dev, fmt, ##arg)
#define pci_iobar_pfn(pdev, bar, vma) (-EINVAL)
#define pci_notice(pdev, fmt, arg...)	dev_notice(&(pdev)->dev, fmt, ##arg)
#define pci_notice_ratelimited(pdev, fmt, arg...) \
	dev_notice_ratelimited(&(pdev)->dev, fmt, ##arg)
#define pci_pool_create(name, pdev, size, align, allocation) \
		dma_pool_create(name, &pdev->dev, size, align, allocation)
#define pci_printk(level, pdev, fmt, arg...) \
	dev_printk(level, &(pdev)->dev, fmt, ##arg)
#define pci_register_driver(driver)		\
	__pci_register_driver(driver, THIS_MODULE, KBUILD_MODNAME)
#define pci_resource_end(dev, bar)	((dev)->resource[(bar)].end)
#define pci_resource_flags(dev, bar)	((dev)->resource[(bar)].flags)
#define pci_resource_len(dev,bar) \
	((pci_resource_end((dev), (bar)) == 0) ? 0 :	\
							\
	 (pci_resource_end((dev), (bar)) -		\
	  pci_resource_start((dev), (bar)) + 1))
#define pci_resource_start(dev, bar)	((dev)->resource[(bar)].start)
#define pci_root_bus_fwnode(bus)	NULL
#define pci_warn(pdev, fmt, arg...)	dev_warn(&(pdev)->dev, fmt, ##arg)
#define to_pci_bus(n)	container_of(n, struct pci_bus, dev)

#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)        dma_addr_t ADDR_NAME
#define DEFINE_DMA_UNMAP_LEN(LEN_NAME)          __u32 LEN_NAME
#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))

#define dma_get_sgtable(d, t, v, h, s) dma_get_sgtable_attrs(d, t, v, h, s, 0)
#define dma_map_page(d, p, o, s, r) dma_map_page_attrs(d, p, o, s, r, 0)
#define dma_map_sg(d, s, n, r) dma_map_sg_attrs(d, s, n, r, 0)
#define dma_map_single(d, a, s, r) dma_map_single_attrs(d, a, s, r, 0)
#define dma_mmap_coherent(d, v, c, h, s) dma_mmap_attrs(d, v, c, h, s, 0)
#define dma_unmap_addr(PTR, ADDR_NAME)           ((PTR)->ADDR_NAME)
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  (((PTR)->ADDR_NAME) = (VAL))
#define dma_unmap_len(PTR, LEN_NAME)             ((PTR)->LEN_NAME)
#define dma_unmap_len_set(PTR, LEN_NAME, VAL)    (((PTR)->LEN_NAME) = (VAL))
#define dma_unmap_page(d, a, s, r) dma_unmap_page_attrs(d, a, s, r, 0)
#define dma_unmap_sg(d, s, n, r) dma_unmap_sg_attrs(d, s, n, r, 0)
#define dma_unmap_single(d, a, s, r) dma_unmap_single_attrs(d, a, s, r, 0)

#define __sme_clr(x)		((x) & ~sme_me_mask)
#define __sme_set(x)		((x) | sme_me_mask)

#define PCIE_DEVICE_ID_NEO_4_IBM        0x00F4
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6200_ALT1 0x00f3
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6600_ALT1 0x00f1
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6600_ALT2 0x00f2
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6800_ALT1 0x00f0
#define PCIE_DEVICE_ID_NVIDIA_GEFORCE_6800_GT   0x00f9
#define PCI_BASE_CLASS_SIGNAL_PROCESSING 0x11
#define PCI_CLASS_COMMUNICATION_MULTISERIAL 0x0702
#define PCI_CLASS_COMMUNICATION_PARALLEL 0x0701
#define PCI_DEVICE_ID_ABOCOM_2BD1       0x2BD1
#define PCI_DEVICE_ID_ADAPTEC2_OBSIDIAN   0x0500
#define PCI_DEVICE_ID_ADDIDATA_APCI7300        0x7002
#define PCI_DEVICE_ID_ADDIDATA_APCI7300_2      0x700B
#define PCI_DEVICE_ID_ADDIDATA_APCI7300_3      0x700E
#define PCI_DEVICE_ID_ADDIDATA_APCI7420        0x7001
#define PCI_DEVICE_ID_ADDIDATA_APCI7420_2      0x700A
#define PCI_DEVICE_ID_ADDIDATA_APCI7420_3      0x700D
#define PCI_DEVICE_ID_ADDIDATA_APCI7500        0x7000
#define PCI_DEVICE_ID_ADDIDATA_APCI7500_2      0x7009
#define PCI_DEVICE_ID_ADDIDATA_APCI7500_3      0x700C
#define PCI_DEVICE_ID_ADDIDATA_APCI7800_3      0x700F
#define PCI_DEVICE_ID_ADDIDATA_APCIe7300       0x7010
#define PCI_DEVICE_ID_ADDIDATA_APCIe7420       0x7011
#define PCI_DEVICE_ID_ADDIDATA_APCIe7500       0x7012
#define PCI_DEVICE_ID_ADDIDATA_APCIe7800       0x7013
#define PCI_DEVICE_ID_AMD_15H_M30H_NB_F3 0x141d
#define PCI_DEVICE_ID_AMD_15H_M30H_NB_F4 0x141e
#define PCI_DEVICE_ID_AMD_15H_M60H_NB_F3 0x1573
#define PCI_DEVICE_ID_AMD_15H_M60H_NB_F4 0x1574
#define PCI_DEVICE_ID_AMD_16H_M30H_NB_F3 0x1583
#define PCI_DEVICE_ID_AMD_16H_M30H_NB_F4 0x1584
#define PCI_DEVICE_ID_AMD_17H_M10H_DF_F3 0x15eb
#define PCI_DEVICE_ID_AMD_17H_M30H_DF_F3 0x1493
#define PCI_DEVICE_ID_AMD_17H_M60H_DF_F3 0x144b
#define PCI_DEVICE_ID_AMD_17H_M70H_DF_F3 0x1443
#define PCI_DEVICE_ID_AMD_19H_M40H_DF_F3 0x167c
#define PCI_DEVICE_ID_AMD_19H_M50H_DF_F3 0x166d
#define PCI_DEVICE_ID_AMD_CS5535_IDE    0x208F
#define PCI_DEVICE_ID_AMD_CS5536_AUDIO  0x2093
#define PCI_DEVICE_ID_AMD_CS5536_DEV_IDE    0x2092
#define PCI_DEVICE_ID_AMD_CS5536_EHC    0x2095
#define PCI_DEVICE_ID_AMD_CS5536_FLASH  0x2091
#define PCI_DEVICE_ID_AMD_CS5536_IDE    0x209A
#define PCI_DEVICE_ID_AMD_CS5536_ISA    0x2090
#define PCI_DEVICE_ID_AMD_CS5536_OHC    0x2094
#define PCI_DEVICE_ID_AMD_CS5536_UDC    0x2096
#define PCI_DEVICE_ID_AMD_CS5536_UOC    0x2097
#define PCI_DEVICE_ID_AMD_KERNCZ_SMBUS  0x790b
#define PCI_DEVICE_ID_AMD_LX_AES    0x2082
#define PCI_DEVICE_ID_AMD_LX_VIDEO  0x2081
#define PCI_DEVICE_ID_APPLE_SH_ATA      0x0050
#define PCI_DEVICE_ID_APPLE_SH_SUNGEM   0x0051
#define PCI_DEVICE_ID_APPLICOM_PCI2000IBS_CAN 0x0002
#define PCI_DEVICE_ID_APPLICOM_PCI2000PFB 0x0003
#define PCI_DEVICE_ID_APPLICOM_PCIGENERIC 0x0001
#define PCI_DEVICE_ID_ATI_IXP300_SATA   0x436e
#define PCI_DEVICE_ID_ATI_IXP400_SATA   0x4379
#define PCI_DEVICE_ID_ATI_RAGE128_MF    0x4d46
#define PCI_DEVICE_ID_ATI_RAGE128_ML    0x4d4c
#define PCI_DEVICE_ID_ATI_RS350_100     0x7830
#define PCI_DEVICE_ID_ATI_RS350_133     0x7831
#define PCI_DEVICE_ID_ATI_RS350_166     0x7832
#define PCI_DEVICE_ID_ATI_RS350_200     0x7833
#define PCI_DEVICE_ID_ATI_RS400_100     0x5a30
#define PCI_DEVICE_ID_ATI_RS400_133     0x5a31
#define PCI_DEVICE_ID_ATI_RS400_166     0x5a32
#define PCI_DEVICE_ID_ATI_RS400_200     0x5a33
#define PCI_DEVICE_ID_ATI_RS480         0x5950
#define PCI_DEVICE_ID_BUSLOGIC_FLASHPOINT     0x8130
#define PCI_DEVICE_ID_BUSLOGIC_MULTIMASTER    0x1040
#define PCI_DEVICE_ID_BUSLOGIC_MULTIMASTER_NC 0x0140
#define PCI_DEVICE_ID_COMPAQ_TRIFLEX_IDE 0xae33
#define PCI_DEVICE_ID_ESDGMBH_CPCIASIO4 0x0111
#define PCI_DEVICE_ID_FARSITE_T1U       0x0610
#define PCI_DEVICE_ID_FARSITE_T2P       0x0400
#define PCI_DEVICE_ID_FARSITE_T2U       0x0620
#define PCI_DEVICE_ID_FARSITE_T4P       0x0440
#define PCI_DEVICE_ID_FARSITE_T4U       0x0640
#define PCI_DEVICE_ID_FARSITE_TE1       0x1610
#define PCI_DEVICE_ID_FARSITE_TE1C      0x1612
#define PCI_DEVICE_ID_GEFORCE_6800A             0x00c1
#define PCI_DEVICE_ID_GEFORCE_6800A_LE          0x00c2
#define PCI_DEVICE_ID_GEFORCE_GO_6800           0x00c8
#define PCI_DEVICE_ID_GEFORCE_GO_6800_ULTRA     0x00c9
#define PCI_DEVICE_ID_HINT_VXPROII_IDE 0x8013
#define PCI_DEVICE_ID_IBM_ICOM_V2_ONE_PORT_RVX_ONE_PORT_MDM_PCIE 0x0361
#define PCI_DEVICE_ID_INTEL_82454NX     0x84cb
#define PCI_DEVICE_ID_INTEL_82801DB_12  0x24cc
#define PCI_DEVICE_ID_INTEL_ALPINE_RIDGE_2C_BRIDGE  0x1576
#define PCI_DEVICE_ID_INTEL_ALPINE_RIDGE_2C_NHI     0x1575 
#define PCI_DEVICE_ID_INTEL_ALPINE_RIDGE_4C_BRIDGE  0x1578
#define PCI_DEVICE_ID_INTEL_ALPINE_RIDGE_4C_NHI     0x1577
#define PCI_DEVICE_ID_INTEL_CACTUS_RIDGE_2C         0x1548
#define PCI_DEVICE_ID_INTEL_CACTUS_RIDGE_4C         0x1547 
#define PCI_DEVICE_ID_INTEL_EAGLE_RIDGE             0x151a
#define PCI_DEVICE_ID_INTEL_FALCON_RIDGE_2C_BRIDGE  0x156b
#define PCI_DEVICE_ID_INTEL_FALCON_RIDGE_2C_NHI     0x156a 
#define PCI_DEVICE_ID_INTEL_FALCON_RIDGE_4C_BRIDGE  0x156d
#define PCI_DEVICE_ID_INTEL_FALCON_RIDGE_4C_NHI     0x156c
#define PCI_DEVICE_ID_INTEL_I7300_MCH_ERR 0x360c
#define PCI_DEVICE_ID_INTEL_I7300_MCH_FB0 0x360f
#define PCI_DEVICE_ID_INTEL_I7300_MCH_FB1 0x3610
#define PCI_DEVICE_ID_INTEL_I7_MC_CH0_ADDR  0x2c21
#define PCI_DEVICE_ID_INTEL_I7_MC_CH0_CTRL  0x2c20
#define PCI_DEVICE_ID_INTEL_I7_MC_CH0_RANK  0x2c22
#define PCI_DEVICE_ID_INTEL_I7_MC_CH0_TC    0x2c23
#define PCI_DEVICE_ID_INTEL_I7_MC_CH1_ADDR  0x2c29
#define PCI_DEVICE_ID_INTEL_I7_MC_CH1_CTRL  0x2c28
#define PCI_DEVICE_ID_INTEL_I7_MC_CH1_RANK  0x2c2a
#define PCI_DEVICE_ID_INTEL_I7_MC_CH1_TC    0x2c2b
#define PCI_DEVICE_ID_INTEL_I7_MC_CH2_ADDR  0x2c31
#define PCI_DEVICE_ID_INTEL_I7_MC_CH2_CTRL  0x2c30
#define PCI_DEVICE_ID_INTEL_I7_MC_CH2_RANK  0x2c32
#define PCI_DEVICE_ID_INTEL_I7_MC_CH2_TC    0x2c33
#define PCI_DEVICE_ID_INTEL_I7_NONCORE_ALT 0x2c40
#define PCI_DEVICE_ID_INTEL_LIGHT_PEAK              0x151b
#define PCI_DEVICE_ID_INTEL_LIGHT_RIDGE             0x1513 
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MCR         0x2c98
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MCR_REV2          0x2d98
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_ADDR 0x2ca1
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_ADDR_REV2  0x2da1
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_CTRL 0x2ca0
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_CTRL_REV2  0x2da0
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_RANK 0x2ca2
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_RANK_REV2  0x2da2
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_TC   0x2ca3
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH0_TC_REV2    0x2da3
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_ADDR 0x2ca9
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_ADDR_REV2  0x2da9
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_CTRL 0x2ca8
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_CTRL_REV2  0x2da8
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_RANK 0x2caa
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_RANK_REV2  0x2daa
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_TC   0x2cab
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH1_TC_REV2    0x2dab
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH2_ADDR_REV2  0x2db1
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH2_CTRL_REV2  0x2db0
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH2_RANK_REV2  0x2db2
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_CH2_TC_REV2    0x2db3
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_RAS_REV2       0x2d9a
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_TAD      0x2c99
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_TAD_REV2       0x2d99
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_TEST     0x2c9C
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_MC_TEST_REV2      0x2d9c
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_NONCORE     0x2c50
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_NONCORE_ALT 0x2c51
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_NONCORE_REV2 0x2c70
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_QPI_LINK0   0x2c90
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_QPI_PHY0    0x2c91
#define PCI_DEVICE_ID_INTEL_LYNNFIELD_SAD         0x2c81
#define PCI_DEVICE_ID_INTEL_PORT_RIDGE              0x1549
#define PCI_DEVICE_ID_INTEL_REDWOOD_RIDGE_2C_BRIDGE 0x1567
#define PCI_DEVICE_ID_INTEL_REDWOOD_RIDGE_2C_NHI    0x1566 
#define PCI_DEVICE_ID_INTEL_REDWOOD_RIDGE_4C_BRIDGE 0x1569
#define PCI_DEVICE_ID_INTEL_REDWOOD_RIDGE_4C_NHI    0x1568
#define PCI_DEVICE_ID_INTEL_X58_HUB_MGMT 0x342e
#define PCI_DEVICE_ID_JMICRON_JMB388_ESD 0x2392
#define PCI_DEVICE_ID_JMICRON_JMB38X_MMC 0x2382
#define PCI_DEVICE_ID_MELLANOX_CONNECTX_EN_5_GEN2 0x6746
#define PCI_DEVICE_ID_MELLANOX_CONNECTX_EN_T_GEN2 0x675a
#define PCI_DEVICE_ID_NEC_PC9821CS01    0x800c 
#define PCI_DEVICE_ID_NEC_PC9821NRB06   0x800d 
#define PCI_DEVICE_ID_NEC_VRC5476       0x009b
#define PCI_DEVICE_ID_NEC_VRC5477_AC97  0x00a6
#define PCI_DEVICE_ID_NEOMAGIC_NM256AV_AUDIO 0x8005
#define PCI_DEVICE_ID_NEOMAGIC_NM256XL_PLUS_AUDIO 0x8016
#define PCI_DEVICE_ID_NEOMAGIC_NM256ZX_AUDIO 0x8006
#define PCI_DEVICE_ID_NEO_2DB9          0x00C8
#define PCI_DEVICE_ID_NEO_2DB9PRI       0x00C9
#define PCI_DEVICE_ID_NEO_2RJ45         0x00CA
#define PCI_DEVICE_ID_NEO_2RJ45PRI      0x00CB
#define PCI_DEVICE_ID_NS_GX_HOST_BRIDGE  0x0028
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_410_GO_M16 0x017D
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_4200_GO       0x0286
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_420_GO_M32 0x0176
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_440_GO_M64 0x0179
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_448_GO    0x0186
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_460_GO    0x0177
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_488_GO    0x0187
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_4000   0x0185
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_420_8X 0x0183
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_440SE_8X 0x0182
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_440_8X 0x0181
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_MX_MAC    0x0189
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_TI_4800SE     0x0282
#define PCI_DEVICE_ID_NVIDIA_GEFORCE4_TI_4800_8X    0x0281
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_320M           0x08A0
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6200_TURBOCACHE 0x0161
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800       0x0041
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800B      0x0211
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800B_GT   0x0215
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800B_LE   0x0212
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800_GT    0x0045
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800_LE    0x0042
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_6800_ULTRA 0x0040
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_7800_GT   0x0090
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5100        0x0327
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5200        0x0320
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5200SE      0x0323
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5200_1      0x0322
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5200_ULTRA  0x0321
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5500        0x0326
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5600        0x0312
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5600SE      0x0314
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5600_ULTRA  0x0311
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5700        0x0342
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5700LE      0x0343
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5700VE      0x0344
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5700_ULTRA  0x0341
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5800        0x0302
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5800_ULTRA  0x0301
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5900        0x0331
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5900XT      0x0332
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5900ZT      0x0334
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5900_ULTRA  0x0330
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_5950_ULTRA  0x0333
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5100      0x032D
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5200      0x0324
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5250      0x0325
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5250_32   0x0328
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5300      0x032C
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5600      0x031A
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5650      0x031B
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5700_1    0x0347
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_FX_GO5700_2    0x0348
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_6200    0x0164
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_6200_1  0x0167
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_6250    0x0166
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_6250_1  0x0168
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_7800   0x0098
#define PCI_DEVICE_ID_NVIDIA_GEFORCE_GO_7800_GTX 0x0099
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP61_IDE       0x03EC
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP61_SATA      0x03E7
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP61_SATA2     0x03F6
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP61_SATA3     0x03F7
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP67_IDE       0x0560
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP67_SMBUS     0x0542
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP73_IDE       0x056C
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP73_SMBUS     0x07D8
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP77_IDE       0x0759
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP78S_SMBUS    0x0752
#define PCI_DEVICE_ID_NVIDIA_NFORCE_MCP79_SMBUS     0x0AA2
#define PCI_DEVICE_ID_NVIDIA_NVENET_15              0x0373
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_280_NVS    0x018A
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_380_XGL    0x018B
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_580_XGL    0x0188
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_700_GOGL       0x028C
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_780_XGL        0x0289
#define PCI_DEVICE_ID_NVIDIA_QUADRO4_980_XGL        0x0288
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_1000         0x0309
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_1100         0x034E
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_2000         0x0308
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_3000         0x0338
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_4000     0x004E
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_500          0x032B
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_700          0x033F
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_GO1000       0x034C
#define PCI_DEVICE_ID_NVIDIA_QUADRO_FX_GO700        0x031C
#define PCI_DEVICE_ID_NVIDIA_QUADRO_NVS_280_PCI     0x032A
#define PCI_DEVICE_ID_NVIDIA_SGS_RIVA128 0x0018
#define PCI_DEVICE_ID_NVIDIA_TNT_UNKNOWN        0x002a
#define PCI_DEVICE_ID_PCTECH_SAMURAI_IDE 0x3020
#define PCI_DEVICE_ID_PLX_9030          0x9030
#define PCI_DEVICE_ID_QUADRO_FX_1400            0x00ce
#define PCI_DEVICE_ID_QUADRO_FX_GO1400          0x00cc
#define PCI_DEVICE_ID_QUATECH_SPPXP_100 0x0278
#define PCI_DEVICE_ID_RME_DIGI96_8_PAD_OR_PST 0x3fc3
#define PCI_DEVICE_ID_SERVERWORKS_CSB5IDE 0x0212
#define PCI_DEVICE_ID_SERVERWORKS_CSB6    0x0203
#define PCI_DEVICE_ID_SERVERWORKS_CSB6IDE 0x0213
#define PCI_DEVICE_ID_SERVERWORKS_CSB6IDE2 0x0217
#define PCI_DEVICE_ID_SERVERWORKS_CSB6LPC 0x0227
#define PCI_DEVICE_ID_SERVERWORKS_GCNB_LE 0x0017
#define PCI_DEVICE_ID_SERVERWORKS_HT1000IDE 0x0214
#define PCI_DEVICE_ID_SERVERWORKS_HT1000SB 0x0205
#define PCI_DEVICE_ID_SERVERWORKS_HT1100LD 0x0408
#define PCI_DEVICE_ID_SERVERWORKS_OSB4IDE 0x0211
#define PCI_DEVICE_ID_SIEMENS_DSCC4     0x2102
#define PCI_DEVICE_ID_STMICRO_AUDIO_ROUTER_MSPS 0xCC10
#define PCI_DEVICE_ID_STMICRO_AUDIO_ROUTER_SRCS 0xCC0F
#define PCI_DEVICE_ID_STMICRO_SDIO_EMMC 0xCC0A
#define PCI_DEVICE_ID_STMICRO_UART_HWFC 0xCC03
#define PCI_DEVICE_ID_TDI_EHCI          0x0101
#define PCI_DEVICE_ID_TOSHIBA_SPIDER_NET 0x01b3
#define PCI_DEVICE_ID_UNISYS_DMA_DIRECTOR 0x001C
#define PCI_DEVICE_ID_XILINX_HAMMERFALL_DSP 0x3fc5
#define PCI_DEVICE_ID_XILINX_HAMMERFALL_DSP_MADI 0x3fc6
#define PCI_SUBDEVICE_ID_PCI_RAS4       0xf001
#define PCI_SUBDEVICE_ID_PCI_RAS8       0xf010
#define PCI_SUBDEVICE_ID_QEMU            0x1100
#define PCI_SUBDEVICE_ID_SPECIALIX_SPEED4 0xa004
#define PCI_SUBVENDOR_ID_PERLE          0x155f
#define PCI_SUBVENDOR_ID_REDHAT_QUMRANET 0x1af4
#define PCI_VENDOR_ID_ADDIDATA                 0x15B8
#define PCI_VENDOR_ID_BCM_GVC          0x14a4
#define PCI_VENDOR_ID_ELECTRONICDESIGNGMBH 0x12f8
#define PCI_VENDOR_ID_FARSITE           0x1619
#define PCI_VENDOR_ID_HINT             0x3388
#define PCI_VENDOR_ID_REDHAT_QUMRANET    0x1af4
#define PCI_VENDOR_ID_SIEMENS           0x110A
#define PCI_VENDOR_ID_TDI               0x192E

#define PCI_DEVFN(slot, func)	((((slot) & 0x1f) << 3) | ((func) & 0x07))
#define PCI_FUNC(devfn)		((devfn) & 0x07)
#define PCI_SLOT(devfn)		(((devfn) >> 3) & 0x1f)


#define MMU_NOTIFIER_RANGE_BLOCKABLE (1 << 0)

#define mmu_notifier_range_init(range,event,flags,vma,mm,start,end)  \
	_mmu_notifier_range_init(range, start, end)
#define mmu_notifier_range_init_owner(range, event, flags, vma, mm, start, \
					end, owner) \
	_mmu_notifier_range_init(range, start, end)
#define mmu_notifier_range_update_to_read_only(r) false
#define pmdp_clear_flush_young_notify pmdp_clear_flush_young
#define pmdp_clear_young_notify pmdp_test_and_clear_young
#define pmdp_huge_clear_flush_notify pmdp_huge_clear_flush
#define ptep_clear_flush_young_notify ptep_clear_flush_young
#define ptep_clear_young_notify ptep_test_and_clear_young
#define pudp_huge_clear_flush_notify pudp_huge_clear_flush
#define set_pte_at_notify set_pte_at


#define NV_ATOMIC(drm,f,a...) do {                                             \
	if (drm_debug_enabled(DRM_UT_ATOMIC))                                  \
		NV_PRINTK(info, &(drm)->client, f, ##a);                       \
} while(0)
#define NV_DEBUG(drm,f,a...) do {                                              \
	if (drm_debug_enabled(DRM_UT_DRIVER))                                  \
		NV_PRINTK(info, &(drm)->client, f, ##a);                       \
} while(0)
#define NV_ERROR(drm,f,a...) NV_PRINTK(err, &(drm)->client, f, ##a)
#define NV_ERROR_ONCE(drm,f,a...) NV_PRINTK_ONCE(err, &(drm)->client, f, ##a)
#define NV_FATAL(drm,f,a...) NV_PRINTK(crit, &(drm)->client, f, ##a)
#define NV_INFO(drm,f,a...) NV_PRINTK(info, &(drm)->client, f, ##a)
#define NV_INFO_ONCE(drm,f,a...) NV_PRINTK_ONCE(info, &(drm)->client, f, ##a)
#define NV_PRINTK(l,c,f,a...) do {                                             \
	struct nouveau_cli *_cli = (c);                                        \
	dev_##l(_cli->drm->dev->dev, "%s: "f, _cli->name, ##a);                \
} while(0)
#define NV_PRINTK_ONCE(l,c,f,a...) NV_PRINTK(l##_once,c,f, ##a)
#define NV_WARN(drm,f,a...) NV_PRINTK(warn, &(drm)->client, f, ##a)
#define NV_WARN_ONCE(drm,f,a...) NV_PRINTK_ONCE(warn, &(drm)->client, f, ##a)



#define NVIF_MD32(p,A...) DRF_MD(NVIF_RD32_, NVIF_WR32_, u32, (p), 0, ##A)
#define NVIF_MR32(p,A...) DRF_MR(NVIF_RD32_, NVIF_WR32_, u32, (p), 0, ##A)
#define NVIF_MV32(p,A...) DRF_MV(NVIF_RD32_, NVIF_WR32_, u32, (p), 0, ##A)
#define NVIF_RD32(p,A...) DRF_RD(NVIF_RD32_,                  (p), 0, ##A)
#define NVIF_RD32_(p,o,dr)   nvif_rd32((p), (o) + (dr))
#define NVIF_RV32(p,A...) DRF_RV(NVIF_RD32_,                  (p), 0, ##A)
#define NVIF_TD32(p,A...) DRF_TD(NVIF_RD32_,                  (p), 0, ##A)
#define NVIF_TV32(p,A...) DRF_TV(NVIF_RD32_,                  (p), 0, ##A)
#define NVIF_WD32(p,A...) DRF_WD(            NVIF_WR32_,      (p), 0, ##A)
#define NVIF_WR32(p,A...) DRF_WR(            NVIF_WR32_,      (p), 0, ##A)
#define NVIF_WR32_(p,o,dr,f) nvif_wr32((p), (o) + (dr), (f))
#define NVIF_WV32(p,A...) DRF_WV(            NVIF_WR32_,      (p), 0, ##A)

#define nvif_handle(a) (unsigned long)(void *)(a)
#define nvif_mask(a,b,c,d) ({                                                  \
	struct nvif_object *__object = (a);                                    \
	u32 _addr = (b), _data = nvif_rd32(__object, _addr);                   \
	nvif_wr32(__object, _addr, (_data & ~(c)) | (d));                      \
	_data;                                                                 \
})
#define nvif_mclass(o,m) ({                                                    \
	struct nvif_object *object = (o);                                      \
	struct nvif_sclass *sclass;                                            \
	typeof(m[0]) *mclass = (m);                                            \
	int ret = -ENODEV;                                                     \
	int cnt, i, j;                                                         \
                                                                               \
	cnt = nvif_object_sclass_get(object, &sclass);                         \
	if (cnt >= 0) {                                                        \
		for (i = 0; ret < 0 && mclass[i].oclass; i++) {                \
			for (j = 0; j < cnt; j++) {                            \
				if (mclass[i].oclass  == sclass[j].oclass &&   \
				    mclass[i].version >= sclass[j].minver &&   \
				    mclass[i].version <= sclass[j].maxver) {   \
					ret = i;                               \
					break;                                 \
				}                                              \
			}                                                      \
		}                                                              \
		nvif_object_sclass_put(&sclass);                               \
	}                                                                      \
	ret;                                                                   \
})
#define nvif_mthd(a,b,c,d) nvif_object_mthd((a), (b), (c), (d))
#define nvif_object(a) (a)->object
#define nvif_rd(a,f,b,c) ({                                                    \
	struct nvif_object *_object = (a);                                     \
	u32 _data;                                                             \
	if (likely(_object->map.ptr))                                          \
		_data = f((u8 __iomem *)_object->map.ptr + (c));               \
	else                                                                   \
		_data = nvif_object_rd(_object, (b), (c));                     \
	_data;                                                                 \
})
#define nvif_rd08(a,b) ({ ((u8)nvif_rd((a), ioread8, 1, (b))); })
#define nvif_rd16(a,b) ({ ((u16)nvif_rd((a), ioread16_native, 2, (b))); })
#define nvif_rd32(a,b) ({ ((u32)nvif_rd((a), ioread32_native, 4, (b))); })
#define nvif_sclass(o,m,u) ({                                                  \
	const typeof(m[0]) *_mclass = (m);                                     \
	s32 _oclass = (u);                                                     \
	int _cid;                                                              \
	if (_oclass) {                                                         \
		for (_cid = 0; _mclass[_cid].oclass; _cid++) {                 \
			if (_mclass[_cid].oclass == _oclass)                   \
				break;                                         \
		}                                                              \
		_cid = _mclass[_cid].oclass ? _cid : -ENOSYS;                  \
	} else {                                                               \
		_cid = nvif_mclass((o), _mclass);                              \
	}                                                                      \
	_cid;                                                                  \
})
#define nvif_wr(a,f,b,c,d) ({                                                  \
	struct nvif_object *_object = (a);                                     \
	if (likely(_object->map.ptr))                                          \
		f((d), (u8 __iomem *)_object->map.ptr + (c));                  \
	else                                                                   \
		nvif_object_wr(_object, (b), (c), (d));                        \
})
#define nvif_wr08(a,b,c) nvif_wr((a), iowrite8, 1, (b), (u8)(c))
#define nvif_wr16(a,b,c) nvif_wr((a), iowrite16_native, 2, (b), (u16)(c))
#define nvif_wr32(a,b,c) nvif_wr((a), iowrite32_native, 4, (b), (u32)(c))
#define nvxx_object(a) ({                                                      \
	struct nvif_object *_object = (a);                                     \
	(struct nvkm_object *)_object->priv;                                   \
})


#define DCB_LOC_ON_CHIP 0
#define DCB_MAX_NUM_CONNECTOR_ENTRIES 16
#define DCB_MAX_NUM_ENTRIES 16
#define DCB_MAX_NUM_GPIO_ENTRIES 32
#define DCB_MAX_NUM_I2C_ENTRIES 16
#define ROM16(x) get_unaligned_le16(&(x))
#define ROM32(x) get_unaligned_le32(&(x))
#define ROMPTR(d,x) ({            \
	struct nouveau_drm *drm = nouveau_drm((d)); \
	ROM16(x) ? &drm->vbios.data[ROM16(x)] : NULL; \
})


#define nouveau_fence(drm) ((struct nouveau_fence_priv *)(drm)->fence)
#define NVIF_NOTIFY_DROP 0
#define NVIF_NOTIFY_KEEP 1
#define NVIF_NOTIFY_USER 0
#define NVIF_NOTIFY_WORK 1

#define DMA_FENCE_ERR(f, fmt, args...) \
	do {								\
		struct dma_fence *__ff = (f);				\
		pr_err("f %llu#%llu: " fmt, __ff->context, __ff->seqno,	\
			##args);					\
	} while (0)
#define DMA_FENCE_TRACE(f, fmt, args...) \
	do {								\
		struct dma_fence *__ff = (f);				\
		if (IS_ENABLED(CONFIG_DMA_FENCE_TRACE))			\
			pr_info("f %llu#%llu: " fmt,			\
				__ff->context, __ff->seqno, ##args);	\
	} while (0)
#define DMA_FENCE_WARN(f, fmt, args...) \
	do {								\
		struct dma_fence *__ff = (f);				\
		pr_warn("f %llu#%llu: " fmt, __ff->context, __ff->seqno,\
			 ##args);					\
	} while (0)

#define DRM_IOCTL_NOUVEAU_GEM_CPU_FINI       DRM_IOW (DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_CPU_FINI, struct drm_nouveau_gem_cpu_fini)
#define DRM_IOCTL_NOUVEAU_GEM_CPU_PREP       DRM_IOW (DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_CPU_PREP, struct drm_nouveau_gem_cpu_prep)
#define DRM_IOCTL_NOUVEAU_GEM_INFO           DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_INFO, struct drm_nouveau_gem_info)
#define DRM_IOCTL_NOUVEAU_GEM_NEW            DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_NEW, struct drm_nouveau_gem_new)
#define DRM_IOCTL_NOUVEAU_GEM_PUSHBUF        DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_PUSHBUF, struct drm_nouveau_gem_pushbuf)
#define DRM_IOCTL_NOUVEAU_SVM_BIND           DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_SVM_BIND, struct drm_nouveau_svm_bind)
#define DRM_IOCTL_NOUVEAU_SVM_INIT           DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_SVM_INIT, struct drm_nouveau_svm_init)
#define DRM_NOUVEAU_CHANNEL_ALLOC      0x02 
#define DRM_NOUVEAU_CHANNEL_FREE       0x03 
#define DRM_NOUVEAU_EVENT_NVIF                                       0x80000000
#define DRM_NOUVEAU_GEM_CPU_FINI       0x43
#define DRM_NOUVEAU_GEM_CPU_PREP       0x42
#define DRM_NOUVEAU_GEM_INFO           0x44
#define DRM_NOUVEAU_GEM_NEW            0x40
#define DRM_NOUVEAU_GEM_PUSHBUF        0x41
#define DRM_NOUVEAU_GETPARAM           0x00 
#define DRM_NOUVEAU_GPUOBJ_FREE        0x06 
#define DRM_NOUVEAU_GROBJ_ALLOC        0x04 
#define DRM_NOUVEAU_NOTIFIEROBJ_ALLOC  0x05 
#define DRM_NOUVEAU_NVIF               0x07
#define DRM_NOUVEAU_SETPARAM           0x01 
#define DRM_NOUVEAU_SVM_BIND           0x09
#define DRM_NOUVEAU_SVM_INIT           0x08
#define NOUVEAU_GEM_CPU_PREP_NOWAIT                                  0x00000001
#define NOUVEAU_GEM_CPU_PREP_WRITE                                   0x00000004
#define NOUVEAU_GEM_DOMAIN_COHERENT  (1 << 4)
#define NOUVEAU_GEM_DOMAIN_CPU       (1 << 0)
#define NOUVEAU_GEM_DOMAIN_GART      (1 << 2)
#define NOUVEAU_GEM_DOMAIN_MAPPABLE  (1 << 3)
#define NOUVEAU_GEM_DOMAIN_VRAM      (1 << 1)
#define NOUVEAU_GEM_MAX_BUFFERS 1024
#define NOUVEAU_GEM_MAX_PUSH 512
#define NOUVEAU_GEM_MAX_RELOCS 1024
#define NOUVEAU_GEM_PUSHBUF_SYNC                                    (1ULL << 0)
#define NOUVEAU_GEM_RELOC_HIGH (1 << 1)
#define NOUVEAU_GEM_RELOC_LOW  (1 << 0)
#define NOUVEAU_GEM_RELOC_OR   (1 << 2)
#define NOUVEAU_GEM_TILE_16BPP       0x00000001
#define NOUVEAU_GEM_TILE_32BPP       0x00000002
#define NOUVEAU_GEM_TILE_COMP        0x00030000 
#define NOUVEAU_GEM_TILE_LAYOUT_MASK 0x0000ff00
#define NOUVEAU_GEM_TILE_NONCONTIG   0x00000008
#define NOUVEAU_GEM_TILE_ZETA        0x00000004
#define NOUVEAU_SVM_BIND_COMMAND_BITS           8
#define NOUVEAU_SVM_BIND_COMMAND_MASK           ((1 << 8) - 1)
#define NOUVEAU_SVM_BIND_COMMAND_SHIFT          0
#define NOUVEAU_SVM_BIND_COMMAND__MIGRATE               0
#define NOUVEAU_SVM_BIND_PRIORITY_BITS          8
#define NOUVEAU_SVM_BIND_PRIORITY_MASK          ((1 << 8) - 1)
#define NOUVEAU_SVM_BIND_PRIORITY_SHIFT         8
#define NOUVEAU_SVM_BIND_TARGET_BITS            32
#define NOUVEAU_SVM_BIND_TARGET_MASK            0xffffffff
#define NOUVEAU_SVM_BIND_TARGET_SHIFT           16
#define NOUVEAU_SVM_BIND_TARGET__GPU_VRAM               (1UL << 31)
#define NOUVEAU_SVM_BIND_VALID_BITS     48
#define NOUVEAU_SVM_BIND_VALID_MASK     ((1ULL << NOUVEAU_SVM_BIND_VALID_BITS) - 1)


#define TTM_PL_FLAG_CONTIGUOUS  (1 << 0)
#define TTM_PL_FLAG_TEMPORARY   (1 << 2)
#define TTM_PL_FLAG_TOPDOWN     (1 << 1)
#define TTM_PL_PRIV             3
#define TTM_PL_SYSTEM           0
#define TTM_PL_TT               1
#define TTM_PL_VRAM             2


#define TTM_NUM_MEM_TYPES 8





#define DRM_DEBUG(fmt, ...)						\
	__drm_dbg(DRM_UT_CORE, fmt, ##__VA_ARGS__)
#define DRM_DEBUG_ATOMIC(fmt, ...)					\
	__drm_dbg(DRM_UT_ATOMIC, fmt, ##__VA_ARGS__)
#define DRM_DEBUG_DP(fmt, ...)						\
	__drm_dbg(DRM_UT_DP, fmt, ## __VA_ARGS__)
#define DRM_DEBUG_DRIVER(fmt, ...)					\
	__drm_dbg(DRM_UT_DRIVER, fmt, ##__VA_ARGS__)
#define DRM_DEBUG_KMS(fmt, ...)						\
	__drm_dbg(DRM_UT_KMS, fmt, ##__VA_ARGS__)
#define DRM_DEBUG_KMS_RATELIMITED(fmt, ...) drm_dbg_kms_ratelimited(NULL, fmt, ## __VA_ARGS__)
#define DRM_DEBUG_LEASE(fmt, ...)					\
	__drm_dbg(DRM_UT_LEASE, fmt, ##__VA_ARGS__)
#define DRM_DEBUG_PRIME(fmt, ...)					\
	__drm_dbg(DRM_UT_PRIME, fmt, ##__VA_ARGS__)
#define DRM_DEBUG_VBL(fmt, ...)						\
	__drm_dbg(DRM_UT_VBL, fmt, ##__VA_ARGS__)
#define DRM_DEV_DEBUG(dev, fmt, ...)					\
	drm_dev_dbg(dev, DRM_UT_CORE, fmt, ##__VA_ARGS__)
#define DRM_DEV_DEBUG_DRIVER(dev, fmt, ...)				\
	drm_dev_dbg(dev, DRM_UT_DRIVER,	fmt, ##__VA_ARGS__)
#define DRM_DEV_DEBUG_KMS(dev, fmt, ...)				\
	drm_dev_dbg(dev, DRM_UT_KMS, fmt, ##__VA_ARGS__)
#define DRM_DEV_ERROR(dev, fmt, ...)					\
	drm_dev_printk(dev, KERN_ERR, "*ERROR* " fmt, ##__VA_ARGS__)
#define DRM_DEV_ERROR_RATELIMITED(dev, fmt, ...)			\
({									\
	static DEFINE_RATELIMIT_STATE(_rs,				\
				      DEFAULT_RATELIMIT_INTERVAL,	\
				      DEFAULT_RATELIMIT_BURST);		\
									\
	if (__ratelimit(&_rs))						\
		DRM_DEV_ERROR(dev, fmt, ##__VA_ARGS__);			\
})
#define DRM_DEV_INFO(dev, fmt, ...)				\
	drm_dev_printk(dev, KERN_INFO, fmt, ##__VA_ARGS__)
#define DRM_DEV_INFO_ONCE(dev, fmt, ...)				\
({									\
	static bool __print_once __read_mostly;				\
	if (!__print_once) {						\
		__print_once = true;					\
		DRM_DEV_INFO(dev, fmt, ##__VA_ARGS__);			\
	}								\
})
#define DRM_ERROR(fmt, ...)						\
	__drm_err(fmt, ##__VA_ARGS__)
#define DRM_ERROR_RATELIMITED(fmt, ...)					\
	DRM_DEV_ERROR_RATELIMITED(NULL, fmt, ##__VA_ARGS__)
#define DRM_INFO(fmt, ...)						\
	_DRM_PRINTK(, INFO, fmt, ##__VA_ARGS__)
#define DRM_INFO_ONCE(fmt, ...)						\
	_DRM_PRINTK(_once, INFO, fmt, ##__VA_ARGS__)
#define DRM_NOTE(fmt, ...)						\
	_DRM_PRINTK(, NOTICE, fmt, ##__VA_ARGS__)
#define DRM_NOTE_ONCE(fmt, ...)						\
	_DRM_PRINTK(_once, NOTICE, fmt, ##__VA_ARGS__)

#define DRM_WARN(fmt, ...)						\
	_DRM_PRINTK(, WARNING, fmt, ##__VA_ARGS__)
#define DRM_WARN_ONCE(fmt, ...)						\
	_DRM_PRINTK(_once, WARNING, fmt, ##__VA_ARGS__)
#define _DRM_PRINTK(once, level, fmt, ...)				\
	printk##once(KERN_##level "[" DRM_NAME "] " fmt, ##__VA_ARGS__)
#define __DRM_DEFINE_DBG_RATELIMITED(category, drm, fmt, ...)					\
({												\
	static DEFINE_RATELIMIT_STATE(rs_, DEFAULT_RATELIMIT_INTERVAL, DEFAULT_RATELIMIT_BURST);\
	const struct drm_device *drm_ = (drm);							\
												\
	if (drm_debug_enabled(DRM_UT_ ## category) && __ratelimit(&rs_))			\
		drm_dev_printk(drm_ ? drm_->dev : NULL, KERN_DEBUG, fmt, ## __VA_ARGS__);	\
})
#define __drm_printk(drm, level, type, fmt, ...)			\
	dev_##level##type((drm)->dev, "[drm] " fmt, ##__VA_ARGS__)
#define drm_WARN(drm, condition, format, arg...)			\
	WARN(condition, "%s %s: " format,				\
			dev_driver_string((drm)->dev),			\
			dev_name((drm)->dev), ## arg)
#define drm_WARN_ON(drm, x)						\
	drm_WARN((drm), (x), "%s",					\
		 "drm_WARN_ON(" __stringify(x) ")")
#define drm_WARN_ONCE(drm, condition, format, arg...)			\
	WARN_ONCE(condition, "%s %s: " format,				\
			dev_driver_string((drm)->dev),			\
			dev_name((drm)->dev), ## arg)
#define drm_WARN_ON_ONCE(drm, x)					\
	drm_WARN_ONCE((drm), (x), "%s",					\
		      "drm_WARN_ON_ONCE(" __stringify(x) ")")
#define drm_dbg(drm, fmt, ...)						\
	drm_dev_dbg((drm) ? (drm)->dev : NULL, DRM_UT_DRIVER, fmt, ##__VA_ARGS__)
#define drm_dbg_atomic(drm, fmt, ...)					\
	drm_dev_dbg((drm) ? (drm)->dev : NULL, DRM_UT_ATOMIC, fmt, ##__VA_ARGS__)
#define drm_dbg_core(drm, fmt, ...)					\
	drm_dev_dbg((drm) ? (drm)->dev : NULL, DRM_UT_CORE, fmt, ##__VA_ARGS__)
#define drm_dbg_dp(drm, fmt, ...)					\
	drm_dev_dbg((drm) ? (drm)->dev : NULL, DRM_UT_DP, fmt, ##__VA_ARGS__)
#define drm_dbg_drmres(drm, fmt, ...)					\
	drm_dev_dbg((drm) ? (drm)->dev : NULL, DRM_UT_DRMRES, fmt, ##__VA_ARGS__)
#define drm_dbg_kms(drm, fmt, ...)					\
	drm_dev_dbg((drm) ? (drm)->dev : NULL, DRM_UT_KMS, fmt, ##__VA_ARGS__)
#define drm_dbg_kms_ratelimited(drm, fmt, ...) \
	__DRM_DEFINE_DBG_RATELIMITED(KMS, drm, fmt, ## __VA_ARGS__)
#define drm_dbg_lease(drm, fmt, ...)					\
	drm_dev_dbg((drm) ? (drm)->dev : NULL, DRM_UT_LEASE, fmt, ##__VA_ARGS__)
#define drm_dbg_prime(drm, fmt, ...)					\
	drm_dev_dbg((drm) ? (drm)->dev : NULL, DRM_UT_PRIME, fmt, ##__VA_ARGS__)
#define drm_dbg_state(drm, fmt, ...)					\
	drm_dev_dbg((drm) ? (drm)->dev : NULL, DRM_UT_STATE, fmt, ##__VA_ARGS__)
#define drm_dbg_vbl(drm, fmt, ...)					\
	drm_dev_dbg((drm) ? (drm)->dev : NULL, DRM_UT_VBL, fmt, ##__VA_ARGS__)
#define drm_err(drm, fmt, ...)					\
	__drm_printk((drm), err,, "*ERROR* " fmt, ##__VA_ARGS__)
#define drm_err_once(drm, fmt, ...)				\
	__drm_printk((drm), err, _once, "*ERROR* " fmt, ##__VA_ARGS__)
#define drm_err_ratelimited(drm, fmt, ...)				\
	__drm_printk((drm), err, _ratelimited, "*ERROR* " fmt, ##__VA_ARGS__)
#define drm_info(drm, fmt, ...)					\
	__drm_printk((drm), info,, fmt, ##__VA_ARGS__)
#define drm_info_once(drm, fmt, ...)				\
	__drm_printk((drm), info, _once, fmt, ##__VA_ARGS__)
#define drm_notice(drm, fmt, ...)				\
	__drm_printk((drm), notice,, fmt, ##__VA_ARGS__)
#define drm_notice_once(drm, fmt, ...)				\
	__drm_printk((drm), notice, _once, fmt, ##__VA_ARGS__)
#define drm_printf_indent(printer, indent, fmt, ...) \
	drm_printf((printer), "%.*s" fmt, (indent), "\t\t\t\t\tX", ##__VA_ARGS__)
#define drm_warn(drm, fmt, ...)					\
	__drm_printk((drm), warn,, fmt, ##__VA_ARGS__)
#define drm_warn_once(drm, fmt, ...)				\
	__drm_printk((drm), warn, _once, fmt, ##__VA_ARGS__)
#define DEFINE_DEBUGFS_ATTRIBUTE(__fops, __get, __set, __fmt)		\
static int __fops ## _open(struct inode *inode, struct file *file)	\
{									\
	__simple_attr_check_format(__fmt, 0ull);			\
	return simple_attr_open(inode, file, __get, __set, __fmt);	\
}									\
static const struct file_operations __fops = {				\
	.owner	 = THIS_MODULE,						\
	.open	 = __fops ## _open,					\
	.release = simple_attr_release,					\
	.read	 = debugfs_attr_read,					\
	.write	 = debugfs_attr_write,					\
	.llseek  = no_llseek,						\
}

#define debugfs_remove_recursive debugfs_remove
#define DMA_BUF_MAP_INIT_VADDR(vaddr_) \
	{ \
		.vaddr = (vaddr_), \
		.is_iomem = false, \
	}


#define dma_resv_assert_held(obj) lockdep_assert_held(&(obj)->lock.base)
#define dma_resv_held(obj) lockdep_is_held(&(obj)->lock.base)
#define DRM_FILE_PAGE_OFFSET_SIZE ((0xFFFFFFFFUL >> PAGE_SHIFT) * 256)
#define DRM_FILE_PAGE_OFFSET_START ((0xFFFFFFFFUL >> PAGE_SHIFT) + 1)

#define DRM_MM_BUG_ON(expr) BUG_ON(expr)

#define drm_mm_for_each_hole(pos, mm, hole_start, hole_end) \
	for (pos = list_first_entry(&(mm)->hole_stack, \
				    typeof(*pos), hole_stack); \
	     &pos->hole_stack != &(mm)->hole_stack ? \
	     hole_start = drm_mm_hole_node_start(pos), \
	     hole_end = hole_start + pos->hole_size, \
	     1 : 0; \
	     pos = list_next_entry(pos, hole_stack))
#define drm_mm_for_each_node(entry, mm) \
	list_for_each_entry(entry, drm_mm_nodes(mm), node_list)
#define drm_mm_for_each_node_in_range(node__, mm__, start__, end__)	\
	for (node__ = __drm_mm_interval_first((mm__), (start__), (end__)-1); \
	     node__->start < (end__);					\
	     node__ = list_next_entry(node__, node_list))
#define drm_mm_for_each_node_safe(entry, next, mm) \
	list_for_each_entry_safe(entry, next, drm_mm_nodes(mm), node_list)
#define drm_mm_nodes(mm) (&(mm)->head_node.node_list)
#define TTM_BO_MAP_IOMEM_MASK 0x80
#define TTM_BO_VM_NUM_PREFAULT 16


#define drm_hash_entry(_ptr, _type, _member) container_of(_ptr, _type, _member)
#define drm_ht_find_item_rcu drm_ht_find_item
#define drm_ht_insert_item_rcu drm_ht_insert_item
#define drm_ht_just_insert_please_rcu drm_ht_just_insert_please
#define drm_ht_remove_item_rcu drm_ht_remove_item
#define drm_ht_remove_key_rcu drm_ht_remove_key
#define DEFINE_DRM_GEM_FOPS(name) \
	static const struct file_operations name = {\
		.owner		= THIS_MODULE,\
		.open		= drm_open,\
		.release	= drm_release,\
		.unlocked_ioctl	= drm_ioctl,\
		.compat_ioctl	= drm_compat_ioctl,\
		.poll		= drm_poll,\
		.read		= drm_read,\
		.llseek		= noop_llseek,\
		.mmap		= drm_gem_mmap,\
	}



#define DRM_CLIENT_CAP_ASPECT_RATIO    4
#define DRM_CLIENT_CAP_UNIVERSAL_PLANES  2
#define DRM_CLOEXEC O_CLOEXEC
#define DRM_COMMAND_BASE                0x40
#define DRM_EVENT_FLIP_COMPLETE 0x02
#define DRM_EVENT_VBLANK 0x01
#define DRM_IO(nr)			_IO(DRM_IOCTL_BASE,nr)
#define DRM_IOCTL_DROP_MASTER           DRM_IO(0x1f)
#define DRM_IOCTL_GET_CLIENT            DRM_IOWR(0x05, struct drm_client)
#define DRM_IOCTL_GET_MAP               DRM_IOWR(0x04, struct drm_map)
#define DRM_IOCTL_GET_SAREA_CTX 	DRM_IOWR(0x1d, struct drm_ctx_priv_map)
#define DRM_IOCTL_GET_STATS             DRM_IOR( 0x06, struct drm_stats)
#define DRM_IOCTL_MODESET_CTL           DRM_IOW(0x08, struct drm_modeset_ctl)
#define DRM_IOCTL_MODE_CREATE_DUMB DRM_IOWR(0xB2, struct drm_mode_create_dumb)
#define DRM_IOCTL_MODE_DESTROY_DUMB    DRM_IOWR(0xB4, struct drm_mode_destroy_dumb)
#define DRM_IOCTL_MODE_GETPLANERESOURCES DRM_IOWR(0xB5, struct drm_mode_get_plane_res)
#define DRM_IOCTL_MODE_MAP_DUMB    DRM_IOWR(0xB3, struct drm_mode_map_dumb)
#define DRM_IOCTL_PRIME_FD_TO_HANDLE    DRM_IOWR(0x2e, struct drm_prime_handle)
#define DRM_IOCTL_PRIME_HANDLE_TO_FD    DRM_IOWR(0x2d, struct drm_prime_handle)
#define DRM_IOCTL_SET_MASTER            DRM_IO(0x1e)
#define DRM_IOR(nr,type)		_IOR(DRM_IOCTL_BASE,nr,type)
#define DRM_IOW(nr,type)		_IOW(DRM_IOCTL_BASE,nr,type)
#define DRM_IOWR(nr,type)		_IOWR(DRM_IOCTL_BASE,nr,type)
#define DRM_RAM_PERCENT 10	  
#define DRM_RDWR O_RDWR
#define DRM_SYNCOBJ_CREATE_SIGNALED (1 << 0)
#define DRM_SYNCOBJ_FD_TO_HANDLE_FLAGS_IMPORT_SYNC_FILE (1 << 0)
#define DRM_SYNCOBJ_HANDLE_TO_FD_FLAGS_EXPORT_SYNC_FILE (1 << 0)
#define DRM_SYNCOBJ_QUERY_FLAGS_LAST_SUBMITTED (1 << 0) 
#define DRM_SYNCOBJ_WAIT_FLAGS_WAIT_ALL (1 << 0)
#define DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE (1 << 2) 
#define DRM_SYNCOBJ_WAIT_FLAGS_WAIT_FOR_SUBMIT (1 << 1)

#define _DRM_LOCKING_CONTEXT(lock) ((lock) & ~(_DRM_LOCK_HELD|_DRM_LOCK_CONT))
#define _DRM_LOCK_IS_CONT(lock)	   ((lock) & _DRM_LOCK_CONT)
#define _DRM_LOCK_IS_HELD(lock)	   ((lock) & _DRM_LOCK_HELD)
#define _DRM_POST_MODESET 2
#define _DRM_PRE_MODESET 1
#define _DRM_VBLANK_FLAGS_MASK (_DRM_VBLANK_EVENT | _DRM_VBLANK_SIGNAL | \
				_DRM_VBLANK_SECONDARY | _DRM_VBLANK_NEXTONMISS)
#define _DRM_VBLANK_HIGH_CRTC_SHIFT 1
#define _DRM_VBLANK_TYPES_MASK (_DRM_VBLANK_ABSOLUTE | _DRM_VBLANK_RELATIVE)

#define devm_drm_dev_alloc(parent, driver, type, member) \
	((type *) __devm_drm_dev_alloc(parent, driver, sizeof(type), \
				       offsetof(type, member)))


#define DRM_MODESET_ACQUIRE_INTERRUPTIBLE BIT(0)
#define DRM_MODESET_LOCK_ALL_BEGIN(dev, ctx, flags, ret)		\
	if (!drm_drv_uses_atomic_modeset(dev))				\
		mutex_lock(&dev->mode_config.mutex);			\
	drm_modeset_acquire_init(&ctx, flags);				\
modeset_lock_retry:							\
	ret = drm_modeset_lock_all_ctx(dev, &ctx);			\
	if (ret)							\
		goto modeset_lock_fail;
#define DRM_MODESET_LOCK_ALL_END(dev, ctx, ret)				\
modeset_lock_fail:							\
	if (ret == -EDEADLK) {						\
		ret = drm_modeset_backoff(&ctx);			\
		if (!ret)						\
			goto modeset_lock_retry;			\
	}								\
	drm_modeset_drop_locks(&ctx);					\
	drm_modeset_acquire_fini(&ctx);					\
	if (!drm_drv_uses_atomic_modeset(dev))				\
		mutex_unlock(&dev->mode_config.mutex);

#define DRM_CONNECTOR_POLL_CONNECT (1 << 1)
#define DRM_CONNECTOR_POLL_DISCONNECT (1 << 2)
#define DRM_CONNECTOR_POLL_HPD (1 << 0)

#define drm_connector_for_each_possible_encoder(connector, encoder) \
	drm_for_each_encoder_mask(encoder, (connector)->dev, \
				  (connector)->possible_encoders)
#define drm_for_each_connector_iter(connector, iter) \
	while ((connector = drm_connector_list_iter_next(iter)))
#define obj_to_connector(x) container_of(x, struct drm_connector, base)
#define DRM_MODE_ATOMIC_ALLOW_MODESET 0x0400
#define DRM_MODE_ATOMIC_FLAGS (\
		DRM_MODE_PAGE_FLIP_EVENT |\
		DRM_MODE_PAGE_FLIP_ASYNC |\
		DRM_MODE_ATOMIC_TEST_ONLY |\
		DRM_MODE_ATOMIC_NONBLOCK |\
		DRM_MODE_ATOMIC_ALLOW_MODESET)
#define DRM_MODE_ATOMIC_NONBLOCK  0x0200
#define DRM_MODE_ATOMIC_TEST_ONLY 0x0100
#define DRM_MODE_CONNECTOR_VIRTUAL      15
#define DRM_MODE_CONTENT_PROTECTION_DESIRED     1
#define DRM_MODE_CONTENT_PROTECTION_ENABLED     2
#define DRM_MODE_DIRTY_ANNOTATE 2
#define DRM_MODE_DIRTY_OFF      0
#define DRM_MODE_DIRTY_ON       1
#define DRM_MODE_DITHERING_AUTO 2
#define DRM_MODE_ENCODER_VIRTUAL 5
#define DRM_MODE_FB_DIRTY_ANNOTATE_COPY 0x01
#define DRM_MODE_FB_DIRTY_ANNOTATE_FILL 0x02
#define DRM_MODE_FB_DIRTY_FLAGS         0x03
#define DRM_MODE_FB_DIRTY_MAX_CLIPS     256
#define  DRM_MODE_FLAG_PIC_AR_16_9 \
			(DRM_MODE_PICTURE_ASPECT_16_9<<19)
#define  DRM_MODE_FLAG_PIC_AR_256_135 \
			(DRM_MODE_PICTURE_ASPECT_256_135<<19)
#define  DRM_MODE_FLAG_PIC_AR_4_3 \
			(DRM_MODE_PICTURE_ASPECT_4_3<<19)
#define  DRM_MODE_FLAG_PIC_AR_64_27 \
			(DRM_MODE_PICTURE_ASPECT_64_27<<19)
#define  DRM_MODE_FLAG_PIC_AR_NONE \
			(DRM_MODE_PICTURE_ASPECT_NONE<<19)
#define DRM_MODE_OBJECT_ANY 0
#define DRM_MODE_OBJECT_BLOB 0xbbbbbbbb
#define DRM_MODE_OBJECT_CONNECTOR 0xc0c0c0c0
#define DRM_MODE_OBJECT_CRTC 0xcccccccc
#define DRM_MODE_OBJECT_ENCODER 0xe0e0e0e0
#define DRM_MODE_OBJECT_FB 0xfbfbfbfb
#define DRM_MODE_OBJECT_MODE 0xdededede
#define DRM_MODE_OBJECT_PLANE 0xeeeeeeee
#define DRM_MODE_OBJECT_PROPERTY 0xb0b0b0b0
#define DRM_MODE_PAGE_FLIP_ASYNC 0x02
#define DRM_MODE_PAGE_FLIP_EVENT 0x01
#define DRM_MODE_PAGE_FLIP_FLAGS (DRM_MODE_PAGE_FLIP_EVENT | \
				  DRM_MODE_PAGE_FLIP_ASYNC | \
				  DRM_MODE_PAGE_FLIP_TARGET)
#define DRM_MODE_PAGE_FLIP_TARGET (DRM_MODE_PAGE_FLIP_TARGET_ABSOLUTE | \
				   DRM_MODE_PAGE_FLIP_TARGET_RELATIVE)
#define DRM_MODE_PAGE_FLIP_TARGET_ABSOLUTE 0x4
#define DRM_MODE_PAGE_FLIP_TARGET_RELATIVE 0x8
#define DRM_MODE_PROP_ATOMIC        0x80000000
#define DRM_MODE_PROP_LEGACY_TYPE  ( \
		DRM_MODE_PROP_RANGE | \
		DRM_MODE_PROP_ENUM | \
		DRM_MODE_PROP_BLOB | \
		DRM_MODE_PROP_BITMASK)
#define DRM_MODE_PROP_TYPE(n)		((n) << 6)
#define DRM_MODE_REFLECT_MASK (\
		DRM_MODE_REFLECT_X | \
		DRM_MODE_REFLECT_Y)
#define DRM_MODE_REFLECT_X      (1<<4)
#define DRM_MODE_REFLECT_Y      (1<<5)
#define DRM_MODE_ROTATE_0       (1<<0)
#define DRM_MODE_ROTATE_180     (1<<2)
#define DRM_MODE_ROTATE_270     (1<<3)
#define DRM_MODE_ROTATE_90      (1<<1)
#define DRM_MODE_ROTATE_MASK (\
		DRM_MODE_ROTATE_0  | \
		DRM_MODE_ROTATE_90  | \
		DRM_MODE_ROTATE_180 | \
		DRM_MODE_ROTATE_270)
#define FORMAT_BLOB_CURRENT 1

#define EXPORT_SYMBOL_FOR_TESTS_ONLY(x) EXPORT_SYMBOL(x)

#define for_each_if(condition) if (!(condition)) {} else
#define DBG_MAX_REG_NUM 0


#define in_dbg_master() \
	(irqs_disabled() && (smp_processor_id() == atomic_read(&kgdb_active)))
#define DEFINE_INSN_CACHE_OPS(__name)					\
extern struct kprobe_insn_cache kprobe_##__name##_slots;		\
									\
static inline kprobe_opcode_t *get_##__name##_slot(void)		\
{									\
	return __get_insn_slot(&kprobe_##__name##_slots);		\
}									\
									\
static inline void free_##__name##_slot(kprobe_opcode_t *slot, int dirty)\
{									\
	__free_insn_slot(&kprobe_##__name##_slots, slot, dirty);	\
}									\
									\
static inline bool is_kprobe_##__name##_slot(unsigned long addr)	\
{									\
	return __is_insn_slot_addr(&kprobe_##__name##_slots, addr);	\
}

# define NOKPROBE_SYMBOL(fname)	__NOKPROBE_SYMBOL(fname)

# define __NOKPROBE_SYMBOL(fname)				\
static unsigned long __used					\
	__section("_kprobe_blacklist")				\
	_kbl_addr_##fname = (unsigned long)fname;
# define __kprobes

#define REFS_ON_FREELIST 0x80000000
#define ARCH_SUPPORTS_FTRACE_OPS 0
#define CALLER_ADDR0 ((unsigned long)ftrace_return_address0)
#define CALLER_ADDR1 ((unsigned long)ftrace_return_address(1))
#define CALLER_ADDR2 ((unsigned long)ftrace_return_address(2))
#define CALLER_ADDR3 ((unsigned long)ftrace_return_address(3))
#define CALLER_ADDR4 ((unsigned long)ftrace_return_address(4))
#define CALLER_ADDR5 ((unsigned long)ftrace_return_address(5))
#define CALLER_ADDR6 ((unsigned long)ftrace_return_address(6))
#define FTRACE_ADDR ((unsigned long)ftrace_caller)
# define FTRACE_FORCE_LIST_FUNC 1
#define FTRACE_GRAPH_ADDR ((unsigned long)ftrace_graph_caller)
#define FTRACE_GRAPH_TRAMP_ADDR ((unsigned long) 0)
# define FTRACE_REGS_ADDR ((unsigned long)ftrace_regs_caller)
#define FTRACE_RETFUNC_DEPTH 50
#define FTRACE_RETSTACK_ALLOC_SIZE 32


#define arch_ftrace_get_regs(fregs) (&(fregs)->regs)
#define do_for_each_ftrace_op(op, list)			\
	op = rcu_dereference_raw_check(list);			\
	do
#define for_ftrace_rec_iter(iter)		\
	for (iter = ftrace_rec_iter_start();	\
	     iter;				\
	     iter = ftrace_rec_iter_next(iter))
# define ftrace_direct_func_count 0
#define ftrace_free_filter(ops) do { } while (0)
#define ftrace_instruction_pointer_set(fregs, ip) do { } while (0)
#define ftrace_need_init_nop() (!__is_defined(CC_USING_NOP_MCOUNT))
#define ftrace_ops_set_global_filter(ops) do { } while (0)
#define ftrace_rec_count(rec)	((rec)->flags & FTRACE_REF_MAX)
#define ftrace_regex_open(ops, flag, inod, file) ({ -ENODEV; })
#  define ftrace_return_address(n) __builtin_return_address(n)
# define ftrace_return_address0 __builtin_return_address(0)
#define ftrace_set_early_filter(ops, buf, enable) do { } while (0)
#define ftrace_set_filter(ops, buf, len, reset) ({ -ENODEV; })
#define ftrace_set_filter_ip(ops, ip, remove, reset) ({ -ENODEV; })
#define ftrace_set_notrace(ops, buf, len, reset) ({ -ENODEV; })
#define register_ftrace_function(ops) ({ 0; })
#define register_ftrace_graph(ops) ({ -1; })
# define trace_preempt_off(a0, a1) do { } while (0)
# define trace_preempt_on(a0, a1) do { } while (0)
#define unregister_ftrace_function(ops) ({ 0; })
#define unregister_ftrace_graph(ops) do { } while (0)
#define while_for_each_ftrace_op(op)				\
	while (likely(op = rcu_dereference_raw_check((op)->next)) &&	\
	       unlikely((op) != &ftrace_list_end))
#define PTRACE_MODE_ATTACH_FSCREDS (PTRACE_MODE_ATTACH | PTRACE_MODE_FSCREDS)
#define PTRACE_MODE_ATTACH_REALCREDS (PTRACE_MODE_ATTACH | PTRACE_MODE_REALCREDS)
#define PTRACE_MODE_READ_FSCREDS (PTRACE_MODE_READ | PTRACE_MODE_FSCREDS)
#define PTRACE_MODE_READ_REALCREDS (PTRACE_MODE_READ | PTRACE_MODE_REALCREDS)
#define PT_EVENT_FLAG(event)	(1 << (PT_OPT_FLAG_SHIFT + (event)))

#define arch_has_block_step()		(0)
#define arch_has_single_step()		(0)
#define arch_ptrace_stop(code, info)		do { } while (0)
#define arch_ptrace_stop_needed(code, info)	(0)
#define current_pt_regs() task_pt_regs(current)
#define current_user_stack_pointer() user_stack_pointer(current_pt_regs())
#define force_successful_syscall_return() do { } while (0)
#define is_syscall_success(regs) (!IS_ERR_VALUE((unsigned long)(regs_return_value(regs))))
#define signal_pt_regs() task_pt_regs(current)

#define MAX_PID_NS_LEVEL 32
#define PIDNS_ADDING (1U << 31)



# define do_ftrace_record_recursion(ip, pip)				\
	do {								\
		if (!trace_recursion_test(TRACE_RECORD_RECURSION_BIT)) { \
			trace_recursion_set(TRACE_RECORD_RECURSION_BIT); \
			ftrace_record_recursion(ip, pip);		\
			trace_recursion_clear(TRACE_RECORD_RECURSION_BIT); \
		}							\
	} while (0)
#define trace_recursion_clear(bit)	do { (current)->trace_recursion &= ~(1<<(bit)); } while (0)
#define trace_recursion_depth() \
	(((current)->trace_recursion >> TRACE_GRAPH_DEPTH_START_BIT) & 3)
#define trace_recursion_set(bit)	do { (current)->trace_recursion |= (1<<(bit)); } while (0)
#define trace_recursion_set_depth(depth) \
	do {								\
		current->trace_recursion &=				\
			~(3 << TRACE_GRAPH_DEPTH_START_BIT);		\
		current->trace_recursion |=				\
			((depth) & 3) << TRACE_GRAPH_DEPTH_START_BIT;	\
	} while (0)
#define trace_recursion_test(bit)	((current)->trace_recursion & (1<<(bit)))
#define DRM_ENUM_NAME_FN(fnname, list)				\
	const char *fnname(int val)				\
	{							\
		int i;						\
		for (i = 0; i < ARRAY_SIZE(list); i++) {	\
			if (list[i].type == val)		\
				return list[i].name;		\
		}						\
		return "(unknown)";				\
	}
#define DRM_OBJECT_MAX_PROPERTY 24


#define HDMI_AUDIO_INFOFRAME_SIZE  10
#define HDMI_AVI_INFOFRAME_SIZE    13
#define HDMI_DRM_INFOFRAME_SIZE    26
#define HDMI_FORUM_IEEE_OUI 0xc45dd8
#define HDMI_IEEE_OUI 0x000c03
#define HDMI_INFOFRAME_HEADER_SIZE  4
#define HDMI_INFOFRAME_SIZE(type)	\
	(HDMI_INFOFRAME_HEADER_SIZE + HDMI_ ## type ## _INFOFRAME_SIZE)
#define HDMI_SPD_INFOFRAME_SIZE    25
#define HDMI_VENDOR_INFOFRAME_SIZE  4

#define NVIF_MEM_COHERENT                                                  0x40
#define NVIF_MEM_COMP                                                      0x04
#define NVIF_MEM_DISP                                                      0x08
#define NVIF_MEM_HOST                                                      0x02
#define NVIF_MEM_KIND                                                      0x10
#define NVIF_MEM_MAPPABLE                                                  0x20
#define NVIF_MEM_UNCACHED                                                  0x80
#define NVIF_MEM_VRAM                                                      0x01

#define NVIF_IOCTL_MAP_V0_IO                                               0x00
#define NVIF_IOCTL_MAP_V0_VA                                               0x01
#define NVIF_IOCTL_V0_DEL                                                  0x03
#define NVIF_IOCTL_V0_MAP                                                  0x07
#define NVIF_IOCTL_V0_MTHD                                                 0x04
#define NVIF_IOCTL_V0_NEW                                                  0x02
#define NVIF_IOCTL_V0_NOP                                                  0x00
#define NVIF_IOCTL_V0_NTFY_DEL                                             0x0a
#define NVIF_IOCTL_V0_NTFY_GET                                             0x0b
#define NVIF_IOCTL_V0_NTFY_NEW                                             0x09
#define NVIF_IOCTL_V0_NTFY_PUT                                             0x0c
#define NVIF_IOCTL_V0_OWNER_ANY                                            0xff
#define NVIF_IOCTL_V0_OWNER_NVIF                                           0x00
#define NVIF_IOCTL_V0_RD                                                   0x05
#define NVIF_IOCTL_V0_ROUTE_HIDDEN                                         0xff
#define NVIF_IOCTL_V0_ROUTE_NVIF                                           0x00
#define NVIF_IOCTL_V0_SCLASS                                               0x01
#define NVIF_IOCTL_V0_UNMAP                                                0x08
#define NVIF_IOCTL_V0_WR                                                   0x06
#define NVIF_VERSION_LATEST                               0x0000000000000100ULL


#define nvxx_bios(a) nvxx_device(a)->bios
#define nvxx_clk(a) nvxx_device(a)->clk
#define nvxx_device(a) ({                                                      \
	struct nvif_device *_device = (a);                                     \
	struct {                                                               \
		struct nvkm_object object;                                     \
		struct nvkm_device *device;                                    \
	} *_udevice = _device->object.priv;                                    \
	_udevice->device;                                                      \
})
#define nvxx_fb(a) nvxx_device(a)->fb
#define nvxx_gpio(a) nvxx_device(a)->gpio
#define nvxx_gr(a) nvxx_device(a)->gr
#define nvxx_i2c(a) nvxx_device(a)->i2c
#define nvxx_iccsense(a) nvxx_device(a)->iccsense
#define nvxx_therm(a) nvxx_device(a)->therm
#define nvxx_volt(a) nvxx_device(a)->volt

#define NV_DEVICE_HOST(n)                          ((n) | (0x00000001ULL << 32))
#define NV_DEVICE_HOST_CHANNELS                       NV_DEVICE_HOST(0x00000001)
#define NV_DEVICE_HOST_RUNLISTS                       NV_DEVICE_HOST(0x00000000)
#define NV_DEVICE_HOST_RUNLIST_ENGINES                NV_DEVICE_HOST(0x00000100)
#define NV_DEVICE_HOST_RUNLIST_ENGINES_BSP                           0x00000020
#define NV_DEVICE_HOST_RUNLIST_ENGINES_CE                            0x00000080
#define NV_DEVICE_HOST_RUNLIST_ENGINES_CIPHER                        0x00000010
#define NV_DEVICE_HOST_RUNLIST_ENGINES_GR                            0x00000002
#define NV_DEVICE_HOST_RUNLIST_ENGINES_ME                            0x00000008
#define NV_DEVICE_HOST_RUNLIST_ENGINES_MPEG                          0x00000004
#define NV_DEVICE_HOST_RUNLIST_ENGINES_MSENC                         0x00001000
#define NV_DEVICE_HOST_RUNLIST_ENGINES_MSPDEC                        0x00000400
#define NV_DEVICE_HOST_RUNLIST_ENGINES_MSPPP                         0x00000800
#define NV_DEVICE_HOST_RUNLIST_ENGINES_MSVLD                         0x00000200
#define NV_DEVICE_HOST_RUNLIST_ENGINES_NVDEC                         0x00008000
#define NV_DEVICE_HOST_RUNLIST_ENGINES_NVENC                         0x00010000
#define NV_DEVICE_HOST_RUNLIST_ENGINES_SEC                           0x00000100
#define NV_DEVICE_HOST_RUNLIST_ENGINES_SEC2                          0x00004000
#define NV_DEVICE_HOST_RUNLIST_ENGINES_SW                            0x00000001
#define NV_DEVICE_HOST_RUNLIST_ENGINES_VIC                           0x00002000
#define NV_DEVICE_HOST_RUNLIST_ENGINES_VP                            0x00000040
#define NV_DEVICE_INFO(n)                          ((n) | (0x00000000ULL << 32))
#define NV_DEVICE_INFO_INVALID                                           ~0ULL
#define NV_DEVICE_INFO_UNIT                               (0xffffffffULL << 32)
#define NV_DEVICE_INFO_V0_AGP                                              0x02
#define NV_DEVICE_INFO_V0_AMPERE                                           0x0d
#define NV_DEVICE_INFO_V0_CELSIUS                                          0x02
#define NV_DEVICE_INFO_V0_CURIE                                            0x05
#define NV_DEVICE_INFO_V0_FERMI                                            0x07
#define NV_DEVICE_INFO_V0_IGP                                              0x00
#define NV_DEVICE_INFO_V0_KELVIN                                           0x03
#define NV_DEVICE_INFO_V0_KEPLER                                           0x08
#define NV_DEVICE_INFO_V0_MAXWELL                                          0x09
#define NV_DEVICE_INFO_V0_PASCAL                                           0x0a
#define NV_DEVICE_INFO_V0_PCI                                              0x01
#define NV_DEVICE_INFO_V0_PCIE                                             0x03
#define NV_DEVICE_INFO_V0_RANKINE                                          0x04
#define NV_DEVICE_INFO_V0_SOC                                              0x04
#define NV_DEVICE_INFO_V0_TESLA                                            0x06
#define NV_DEVICE_INFO_V0_TNT                                              0x01
#define NV_DEVICE_INFO_V0_TURING                                           0x0c
#define NV_DEVICE_INFO_V0_VOLTA                                            0x0b
#define NV_DEVICE_V0_INFO                                                  0x00
#define NV_DEVICE_V0_TIME                                                  0x01


#define nvxx_client(a) ({                                                      \
	struct nvif_client *_client = (a);                                     \
	(struct nvkm_client *)_client->object.priv;                            \
})

#define nouveau_conn_atom(p)                                                   \
	container_of((p), struct nouveau_conn_atom, state)
#define nouveau_for_each_non_mst_connector_iter(connector, iter) \
	drm_for_each_connector_iter(connector, iter) \
		for_each_if(!nouveau_connector_is_mst(connector))
#define NV_DPMS_CLEARED 0x80




#define drm_for_each_fb(fb, dev) \
	for (WARN_ON(!mutex_is_locked(&(dev)->mode_config.fb_lock)),		\
	     fb = list_first_entry(&(dev)->mode_config.fb_list,	\
					  struct drm_framebuffer, head);	\
	     &fb->head != (&(dev)->mode_config.fb_list);			\
	     fb = list_next_entry(fb, head))
#define fb_to_afbc_fb(x) container_of(x, struct drm_afbc_framebuffer, base)
#define obj_to_fb(x) container_of(x, struct drm_framebuffer, base)
# define DRM_FORMAT_HOST_ARGB8888     DRM_FORMAT_BGRA8888
# define DRM_FORMAT_HOST_RGB565       (DRM_FORMAT_RGB565           |	\
				       DRM_FORMAT_BIG_ENDIAN)
# define DRM_FORMAT_HOST_XRGB1555     (DRM_FORMAT_XRGB1555         |	\
				       DRM_FORMAT_BIG_ENDIAN)
# define DRM_FORMAT_HOST_XRGB8888     DRM_FORMAT_BGRX8888

#define AFBC_FORMAT_MOD_BCH     (1ULL << 11)
#define AFBC_FORMAT_MOD_BLOCK_SIZE_16x16     (1ULL)
#define AFBC_FORMAT_MOD_BLOCK_SIZE_32x8      (2ULL)
#define AFBC_FORMAT_MOD_BLOCK_SIZE_32x8_64x4 (4ULL)
#define AFBC_FORMAT_MOD_BLOCK_SIZE_64x4      (3ULL)
#define AFBC_FORMAT_MOD_BLOCK_SIZE_MASK      0xf
#define AFBC_FORMAT_MOD_CBR     (1ULL <<  7)
#define AFBC_FORMAT_MOD_DB      (1ULL << 10)
#define AFBC_FORMAT_MOD_SC      (1ULL <<  9)
#define AFBC_FORMAT_MOD_SPARSE  (1ULL <<  6)
#define AFBC_FORMAT_MOD_SPLIT   (1ULL <<  5)
#define AFBC_FORMAT_MOD_TILED   (1ULL <<  8)
#define AFBC_FORMAT_MOD_YTR     (1ULL <<  4)
#define AFRC_FORMAT_MOD_CU_SIZE_16 (1ULL)
#define AFRC_FORMAT_MOD_CU_SIZE_24 (2ULL)
#define AFRC_FORMAT_MOD_CU_SIZE_32 (3ULL)
#define AFRC_FORMAT_MOD_CU_SIZE_MASK 0xf
#define AFRC_FORMAT_MOD_CU_SIZE_P0(__afrc_cu_size) (__afrc_cu_size)
#define AFRC_FORMAT_MOD_CU_SIZE_P12(__afrc_cu_size) ((__afrc_cu_size) << 4)
#define AFRC_FORMAT_MOD_LAYOUT_SCAN (1ULL << 8)
#define AMD_FMT_MOD fourcc_mod_code(AMD, 0)
#define AMD_FMT_MOD_BANK_XOR_BITS_MASK 0x7
#define AMD_FMT_MOD_BANK_XOR_BITS_SHIFT 24
#define AMD_FMT_MOD_CLEAR(field) \
	(~((uint64_t)AMD_FMT_MOD_##field##_MASK << AMD_FMT_MOD_##field##_SHIFT))
#define AMD_FMT_MOD_DCC_BLOCK_128B 1
#define AMD_FMT_MOD_DCC_BLOCK_256B 2
#define AMD_FMT_MOD_DCC_BLOCK_64B 0
#define AMD_FMT_MOD_DCC_CONSTANT_ENCODE_MASK 0x1
#define AMD_FMT_MOD_DCC_CONSTANT_ENCODE_SHIFT 20
#define AMD_FMT_MOD_DCC_INDEPENDENT_128B_MASK 0x1
#define AMD_FMT_MOD_DCC_INDEPENDENT_128B_SHIFT 17
#define AMD_FMT_MOD_DCC_INDEPENDENT_64B_MASK 0x1
#define AMD_FMT_MOD_DCC_INDEPENDENT_64B_SHIFT 16
#define AMD_FMT_MOD_DCC_MASK 0x1
#define AMD_FMT_MOD_DCC_MAX_COMPRESSED_BLOCK_MASK 0x3
#define AMD_FMT_MOD_DCC_MAX_COMPRESSED_BLOCK_SHIFT 18
#define AMD_FMT_MOD_DCC_PIPE_ALIGN_MASK 0x1
#define AMD_FMT_MOD_DCC_PIPE_ALIGN_SHIFT 15
#define AMD_FMT_MOD_DCC_RETILE_MASK 0x1
#define AMD_FMT_MOD_DCC_RETILE_SHIFT 14
#define AMD_FMT_MOD_DCC_SHIFT 13
#define AMD_FMT_MOD_GET(field, value) \
	(((value) >> AMD_FMT_MOD_##field##_SHIFT) & AMD_FMT_MOD_##field##_MASK)
#define AMD_FMT_MOD_PACKERS_MASK 0x7
#define AMD_FMT_MOD_PACKERS_SHIFT 27
#define AMD_FMT_MOD_PIPE_MASK 0x7
#define AMD_FMT_MOD_PIPE_SHIFT 33
#define AMD_FMT_MOD_PIPE_XOR_BITS_MASK 0x7
#define AMD_FMT_MOD_PIPE_XOR_BITS_SHIFT 21
#define AMD_FMT_MOD_RB_MASK 0x7
#define AMD_FMT_MOD_RB_SHIFT 30
#define AMD_FMT_MOD_SET(field, value) \
	((uint64_t)(value) << AMD_FMT_MOD_##field##_SHIFT)
#define AMD_FMT_MOD_TILE_GFX9_64K_D 10
#define AMD_FMT_MOD_TILE_GFX9_64K_D_X 26
#define AMD_FMT_MOD_TILE_GFX9_64K_R_X 27
#define AMD_FMT_MOD_TILE_GFX9_64K_S 9
#define AMD_FMT_MOD_TILE_GFX9_64K_S_X 25
#define AMD_FMT_MOD_TILE_MASK 0x1F
#define AMD_FMT_MOD_TILE_SHIFT 8
#define AMD_FMT_MOD_TILE_VERSION_MASK 0xFF
#define AMD_FMT_MOD_TILE_VERSION_SHIFT 0
#define AMD_FMT_MOD_TILE_VER_GFX10 2
#define AMD_FMT_MOD_TILE_VER_GFX10_RBPLUS 3
#define AMD_FMT_MOD_TILE_VER_GFX9 1
#define DRM_FORMAT_ABGR16161616F fourcc_code('A', 'B', '4', 'H') 
#define DRM_FORMAT_ARGB16161616F fourcc_code('A', 'R', '4', 'H') 
#define DRM_FORMAT_AXBXGXRX106106106106 fourcc_code('A', 'B', '1', '0') 
#define DRM_FORMAT_BIG_ENDIAN (1U<<31) 
#define DRM_FORMAT_MOD_ALLWINNER_TILED fourcc_mod_code(ALLWINNER, 1)
#define DRM_FORMAT_MOD_AMLOGIC_FBC(__layout, __options) \
	fourcc_mod_code(AMLOGIC, \
			((__layout) & __fourcc_mod_amlogic_layout_mask) | \
			(((__options) & __fourcc_mod_amlogic_options_mask) \
			 << __fourcc_mod_amlogic_options_shift))
#define DRM_FORMAT_MOD_ARM_16X16_BLOCK_U_INTERLEAVED \
	DRM_FORMAT_MOD_ARM_CODE(DRM_FORMAT_MOD_ARM_TYPE_MISC, 1ULL)
#define DRM_FORMAT_MOD_ARM_AFBC(__afbc_mode) \
	DRM_FORMAT_MOD_ARM_CODE(DRM_FORMAT_MOD_ARM_TYPE_AFBC, __afbc_mode)
#define DRM_FORMAT_MOD_ARM_AFRC(__afrc_mode) \
	DRM_FORMAT_MOD_ARM_CODE(DRM_FORMAT_MOD_ARM_TYPE_AFRC, __afrc_mode)
#define DRM_FORMAT_MOD_ARM_CODE(__type, __val) \
	fourcc_mod_code(ARM, ((__u64)(__type) << 52) | ((__val) & 0x000fffffffffffffULL))
#define DRM_FORMAT_MOD_ARM_TYPE_AFBC 0x00
#define DRM_FORMAT_MOD_ARM_TYPE_AFRC 0x02
#define DRM_FORMAT_MOD_ARM_TYPE_MISC 0x01
#define DRM_FORMAT_MOD_BROADCOM_SAND128 \
	DRM_FORMAT_MOD_BROADCOM_SAND128_COL_HEIGHT(0)
#define DRM_FORMAT_MOD_BROADCOM_SAND128_COL_HEIGHT(v) \
	fourcc_mod_broadcom_code(4, v)
#define DRM_FORMAT_MOD_BROADCOM_SAND256 \
	DRM_FORMAT_MOD_BROADCOM_SAND256_COL_HEIGHT(0)
#define DRM_FORMAT_MOD_BROADCOM_SAND256_COL_HEIGHT(v) \
	fourcc_mod_broadcom_code(5, v)
#define DRM_FORMAT_MOD_BROADCOM_SAND32 \
	DRM_FORMAT_MOD_BROADCOM_SAND32_COL_HEIGHT(0)
#define DRM_FORMAT_MOD_BROADCOM_SAND32_COL_HEIGHT(v) \
	fourcc_mod_broadcom_code(2, v)
#define DRM_FORMAT_MOD_BROADCOM_SAND64 \
	DRM_FORMAT_MOD_BROADCOM_SAND64_COL_HEIGHT(0)
#define DRM_FORMAT_MOD_BROADCOM_SAND64_COL_HEIGHT(v) \
	fourcc_mod_broadcom_code(3, v)
#define DRM_FORMAT_MOD_BROADCOM_UIF fourcc_mod_code(BROADCOM, 6)
#define DRM_FORMAT_MOD_BROADCOM_VC4_T_TILED fourcc_mod_code(BROADCOM, 1)
#define DRM_FORMAT_MOD_GENERIC_16_16_TILE DRM_FORMAT_MOD_SAMSUNG_16_16_TILE
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(v) \
	DRM_FORMAT_MOD_NVIDIA_BLOCK_LINEAR_2D(0, 0, 0, 0, (v))
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK_EIGHT_GOB \
	DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(3)
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK_FOUR_GOB \
	DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(2)
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK_ONE_GOB \
	DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(0)
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK_SIXTEEN_GOB \
	DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(4)
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK_THIRTYTWO_GOB \
	DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(5)
#define DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK_TWO_GOB \
	DRM_FORMAT_MOD_NVIDIA_16BX2_BLOCK(1)
#define DRM_FORMAT_MOD_NVIDIA_BLOCK_LINEAR_2D(c, s, g, k, h) \
	fourcc_mod_code(NVIDIA, (0x10 | \
				 ((h) & 0xf) | \
				 (((k) & 0xff) << 12) | \
				 (((g) & 0x3) << 20) | \
				 (((s) & 0x1) << 22) | \
				 (((c) & 0x7) << 23)))
#define DRM_FORMAT_MOD_NVIDIA_TEGRA_TILED fourcc_mod_code(NVIDIA, 1)
#define DRM_FORMAT_MOD_VENDOR_ALLWINNER 0x09
#define DRM_FORMAT_MOD_VENDOR_AMD     0x02
#define DRM_FORMAT_MOD_VENDOR_AMLOGIC 0x0a
#define DRM_FORMAT_MOD_VENDOR_ARM     0x08
#define DRM_FORMAT_MOD_VENDOR_BROADCOM 0x07
#define DRM_FORMAT_MOD_VENDOR_INTEL   0x01
#define DRM_FORMAT_MOD_VENDOR_NONE    0
#define DRM_FORMAT_MOD_VENDOR_NVIDIA  0x03
#define DRM_FORMAT_MOD_VENDOR_QCOM    0x05
#define DRM_FORMAT_MOD_VENDOR_SAMSUNG 0x04
#define DRM_FORMAT_MOD_VENDOR_VIVANTE 0x06
#define DRM_FORMAT_MOD_VIVANTE_SPLIT_SUPER_TILED fourcc_mod_code(VIVANTE, 4)
#define DRM_FORMAT_XBGR16161616F fourcc_code('X', 'B', '4', 'H') 
#define DRM_FORMAT_XRGB16161616F fourcc_code('X', 'R', '4', 'H') 
#define DRM_FORMAT_Y210         fourcc_code('Y', '2', '1', '0') 
#define DRM_FORMAT_Y212         fourcc_code('Y', '2', '1', '2') 
#define DRM_FORMAT_Y216         fourcc_code('Y', '2', '1', '6') 
#define DRM_FORMAT_Y410         fourcc_code('Y', '4', '1', '0') 
#define DRM_FORMAT_Y412         fourcc_code('Y', '4', '1', '2') 
#define DRM_FORMAT_Y416         fourcc_code('Y', '4', '1', '6') 

#define I915_FORMAT_MOD_Y_TILED_GEN12_MC_CCS fourcc_mod_code(INTEL, 7)
#define I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS fourcc_mod_code(INTEL, 6)
#define I915_FORMAT_MOD_Y_TILED_GEN12_RC_CCS_CC fourcc_mod_code(INTEL, 8)
#define I915_FORMAT_MOD_Yf_TILED fourcc_mod_code(INTEL, 3)
#define IS_AMD_FMT_MOD(val) (((val) >> 56) == DRM_FORMAT_MOD_VENDOR_AMD)
#define __fourcc_mod_amlogic_layout_mask 0xff
#define __fourcc_mod_amlogic_options_mask 0xff
#define __fourcc_mod_amlogic_options_shift 8
#define __fourcc_mod_broadcom_param_bits 48
#define __fourcc_mod_broadcom_param_shift 8
#define fourcc_code(a, b, c, d) ((__u32)(a) | ((__u32)(b) << 8) | \
				 ((__u32)(c) << 16) | ((__u32)(d) << 24))
#define fourcc_mod_broadcom_code(val, params) \
	fourcc_mod_code(BROADCOM, ((((__u64)params) << __fourcc_mod_broadcom_param_shift) | val))
#define fourcc_mod_broadcom_mod(m) \
	((m) & ~(((1ULL << __fourcc_mod_broadcom_param_bits) - 1) <<	\
		 __fourcc_mod_broadcom_param_shift))
#define fourcc_mod_broadcom_param(m) \
	((int)(((m) >> __fourcc_mod_broadcom_param_shift) &	\
	       ((1ULL << __fourcc_mod_broadcom_param_bits) - 1)))
#define fourcc_mod_code(vendor, val) \
	((((__u64)DRM_FORMAT_MOD_VENDOR_## vendor) << 56) | ((val) & 0x00ffffffffffffffULL))

#define DP_MAX_PAYLOAD (sizeof(unsigned long) * 8)
#define DP_PAYLOAD_DELETE_LOCAL 3
#define DP_PAYLOAD_LOCAL 1
#define DP_PAYLOAD_REMOTE 2
#define DP_REMOTE_I2C_READ_MAX_TRANSACTIONS 4
#define DRM_DP_MAX_SDP_STREAMS 16
#define DRM_DP_SIDEBAND_TX_QUEUED 0
#define DRM_DP_SIDEBAND_TX_RX 3
#define DRM_DP_SIDEBAND_TX_SENT 2
#define DRM_DP_SIDEBAND_TX_START_SEND 1
#define DRM_DP_SIDEBAND_TX_TIMEOUT 4

#define for_each_new_mst_mgr_in_state(__state, mgr, new_state, __i) \
	for ((__i) = 0; (__i) < (__state)->num_private_objs; (__i)++) \
		for_each_if(__drm_dp_mst_state_iter_get((__state), &(mgr), NULL, &(new_state), (__i)))
#define for_each_old_mst_mgr_in_state(__state, mgr, old_state, __i) \
	for ((__i) = 0; (__i) < (__state)->num_private_objs; (__i)++) \
		for_each_if(__drm_dp_mst_state_iter_get((__state), &(mgr), &(old_state), NULL, (__i)))
#define for_each_oldnew_mst_mgr_in_state(__state, mgr, old_state, new_state, __i) \
	for ((__i) = 0; (__i) < (__state)->num_private_objs; (__i)++) \
		for_each_if(__drm_dp_mst_state_iter_get((__state), &(mgr), &(old_state), &(new_state), (__i)))
#define to_dp_mst_topology_mgr(x) container_of(x, struct drm_dp_mst_topology_mgr, base)
#define to_dp_mst_topology_state(x) container_of(x, struct drm_dp_mst_topology_state, base)



#define drm_for_each_privobj(privobj, dev) \
	list_for_each_entry(privobj, &(dev)->mode_config.privobj_list, head)
#define for_each_new_connector_in_state(__state, connector, new_connector_state, __i) \
	for ((__i) = 0;								\
	     (__i) < (__state)->num_connector;					\
	     (__i)++)								\
		for_each_if ((__state)->connectors[__i].ptr &&			\
			     ((connector) = (__state)->connectors[__i].ptr,	\
			     (void)(connector) , \
			     (new_connector_state) = (__state)->connectors[__i].new_state, \
			     (void)(new_connector_state) , 1))
#define for_each_new_crtc_in_state(__state, crtc, new_crtc_state, __i)	\
	for ((__i) = 0;							\
	     (__i) < (__state)->dev->mode_config.num_crtc;		\
	     (__i)++)							\
		for_each_if ((__state)->crtcs[__i].ptr &&		\
			     ((crtc) = (__state)->crtcs[__i].ptr,	\
			     (void)(crtc) , \
			     (new_crtc_state) = (__state)->crtcs[__i].new_state, \
			     (void)(new_crtc_state) , 1))
#define for_each_new_plane_in_state(__state, plane, new_plane_state, __i) \
	for ((__i) = 0;							\
	     (__i) < (__state)->dev->mode_config.num_total_plane;	\
	     (__i)++)							\
		for_each_if ((__state)->planes[__i].ptr &&		\
			     ((plane) = (__state)->planes[__i].ptr,	\
			      (void)(plane) , \
			      (new_plane_state) = (__state)->planes[__i].new_state, \
			      (void)(new_plane_state) , 1))
#define for_each_new_plane_in_state_reverse(__state, plane, new_plane_state, __i) \
	for ((__i) = ((__state)->dev->mode_config.num_total_plane - 1);	\
	     (__i) >= 0;						\
	     (__i)--)							\
		for_each_if ((__state)->planes[__i].ptr &&		\
			     ((plane) = (__state)->planes[__i].ptr,	\
			      (new_plane_state) = (__state)->planes[__i].new_state, 1))
#define for_each_new_private_obj_in_state(__state, obj, new_obj_state, __i) \
	for ((__i) = 0; \
	     (__i) < (__state)->num_private_objs && \
		     ((obj) = (__state)->private_objs[__i].ptr, \
		      (new_obj_state) = (__state)->private_objs[__i].new_state, 1); \
	     (__i)++)
#define for_each_old_connector_in_state(__state, connector, old_connector_state, __i) \
	for ((__i) = 0;								\
	     (__i) < (__state)->num_connector;					\
	     (__i)++)								\
		for_each_if ((__state)->connectors[__i].ptr &&			\
			     ((connector) = (__state)->connectors[__i].ptr,	\
			     (void)(connector) , \
			     (old_connector_state) = (__state)->connectors[__i].old_state, 1))
#define for_each_old_crtc_in_state(__state, crtc, old_crtc_state, __i)	\
	for ((__i) = 0;							\
	     (__i) < (__state)->dev->mode_config.num_crtc;		\
	     (__i)++)							\
		for_each_if ((__state)->crtcs[__i].ptr &&		\
			     ((crtc) = (__state)->crtcs[__i].ptr,	\
			     (void)(crtc) , \
			     (old_crtc_state) = (__state)->crtcs[__i].old_state, 1))
#define for_each_old_plane_in_state(__state, plane, old_plane_state, __i) \
	for ((__i) = 0;							\
	     (__i) < (__state)->dev->mode_config.num_total_plane;	\
	     (__i)++)							\
		for_each_if ((__state)->planes[__i].ptr &&		\
			     ((plane) = (__state)->planes[__i].ptr,	\
			      (old_plane_state) = (__state)->planes[__i].old_state, 1))
#define for_each_old_private_obj_in_state(__state, obj, old_obj_state, __i) \
	for ((__i) = 0; \
	     (__i) < (__state)->num_private_objs && \
		     ((obj) = (__state)->private_objs[__i].ptr, \
		      (old_obj_state) = (__state)->private_objs[__i].old_state, 1); \
	     (__i)++)
#define for_each_oldnew_connector_in_state(__state, connector, old_connector_state, new_connector_state, __i) \
	for ((__i) = 0;								\
	     (__i) < (__state)->num_connector;					\
	     (__i)++)								\
		for_each_if ((__state)->connectors[__i].ptr &&			\
			     ((connector) = (__state)->connectors[__i].ptr,	\
			     (void)(connector) , \
			     (old_connector_state) = (__state)->connectors[__i].old_state,	\
			     (new_connector_state) = (__state)->connectors[__i].new_state, 1))
#define for_each_oldnew_crtc_in_state(__state, crtc, old_crtc_state, new_crtc_state, __i) \
	for ((__i) = 0;							\
	     (__i) < (__state)->dev->mode_config.num_crtc;		\
	     (__i)++)							\
		for_each_if ((__state)->crtcs[__i].ptr &&		\
			     ((crtc) = (__state)->crtcs[__i].ptr,	\
			      (void)(crtc) , \
			     (old_crtc_state) = (__state)->crtcs[__i].old_state, \
			     (void)(old_crtc_state) , \
			     (new_crtc_state) = (__state)->crtcs[__i].new_state, \
			     (void)(new_crtc_state) , 1))
#define for_each_oldnew_plane_in_state(__state, plane, old_plane_state, new_plane_state, __i) \
	for ((__i) = 0;							\
	     (__i) < (__state)->dev->mode_config.num_total_plane;	\
	     (__i)++)							\
		for_each_if ((__state)->planes[__i].ptr &&		\
			     ((plane) = (__state)->planes[__i].ptr,	\
			      (void)(plane) , \
			      (old_plane_state) = (__state)->planes[__i].old_state,\
			      (new_plane_state) = (__state)->planes[__i].new_state, 1))
#define for_each_oldnew_plane_in_state_reverse(__state, plane, old_plane_state, new_plane_state, __i) \
	for ((__i) = ((__state)->dev->mode_config.num_total_plane - 1);	\
	     (__i) >= 0;						\
	     (__i)--)							\
		for_each_if ((__state)->planes[__i].ptr &&		\
			     ((plane) = (__state)->planes[__i].ptr,	\
			      (old_plane_state) = (__state)->planes[__i].old_state,\
			      (new_plane_state) = (__state)->planes[__i].new_state, 1))
#define for_each_oldnew_private_obj_in_state(__state, obj, old_obj_state, new_obj_state, __i) \
	for ((__i) = 0; \
	     (__i) < (__state)->num_private_objs && \
		     ((obj) = (__state)->private_objs[__i].ptr, \
		      (old_obj_state) = (__state)->private_objs[__i].old_state,	\
		      (new_obj_state) = (__state)->private_objs[__i].new_state, 1); \
	     (__i)++)

#define drm_for_each_crtc(crtc, dev) \
	list_for_each_entry(crtc, &(dev)->mode_config.crtc_list, head)
#define drm_for_each_crtc_reverse(crtc, dev) \
	list_for_each_entry_reverse(crtc, &(dev)->mode_config.crtc_list, head)
#define drmm_crtc_alloc_with_planes(dev, type, member, primary, cursor, funcs, name, ...) \
	((type *)__drmm_crtc_alloc_with_planes(dev, sizeof(type), \
					       offsetof(type, member), \
					       primary, cursor, funcs, \
					       name, ##__VA_ARGS__))
#define obj_to_crtc(x) container_of(x, struct drm_crtc, base)



#define obj_to_blob(x) container_of(x, struct drm_property_blob, base)
#define obj_to_property(x) container_of(x, struct drm_property, base)


#define drm_for_each_legacy_plane(plane, dev) \
	list_for_each_entry(plane, &(dev)->mode_config.plane_list, head) \
		for_each_if (plane->type == DRM_PLANE_TYPE_OVERLAY)
#define drm_for_each_plane(plane, dev) \
	list_for_each_entry(plane, &(dev)->mode_config.plane_list, head)
#define drm_for_each_plane_mask(plane, dev, plane_mask) \
	list_for_each_entry((plane), &(dev)->mode_config.plane_list, head) \
		for_each_if ((plane_mask) & drm_plane_mask(plane))
#define drmm_universal_plane_alloc(dev, type, member, possible_crtcs, funcs, formats, \
				   format_count, format_modifiers, plane_type, name, ...) \
	((type *)__drmm_universal_plane_alloc(dev, sizeof(type), \
					      offsetof(type, member), \
					      possible_crtcs, funcs, formats, \
					      format_count, format_modifiers, \
					      plane_type, name, ##__VA_ARGS__))
#define obj_to_plane(x) container_of(x, struct drm_plane, base)
#define DRM_RECT_ARG(r) drm_rect_width(r), drm_rect_height(r), (r)->x1, (r)->y1
#define DRM_RECT_FMT    "%dx%d%+d%+d"
#define DRM_RECT_FP_ARG(r) \
		drm_rect_width(r) >> 16, ((drm_rect_width(r) & 0xffff) * 15625) >> 10, \
		drm_rect_height(r) >> 16, ((drm_rect_height(r) & 0xffff) * 15625) >> 10, \
		(r)->x1 >> 16, (((r)->x1 & 0xffff) * 15625) >> 10, \
		(r)->y1 >> 16, (((r)->y1 & 0xffff) * 15625) >> 10
#define DRM_RECT_FP_FMT "%d.%06ux%d.%06u%+d.%06u%+d.%06u"

#define DDC_ADDR 0x50
#define DDC_ADDR2 0x52 
#define DISPLAYID_EXT 0x70
#define DRM_EDID_CVT_SUPPORT_FLAG           0x04
#define DRM_EDID_DEFAULT_GTF_SUPPORT_FLAG   0x00
#define DRM_EDID_DIGITAL_DEPTH_10      (3 << 4) 
#define DRM_EDID_DIGITAL_DEPTH_12      (4 << 4) 
#define DRM_EDID_DIGITAL_DEPTH_14      (5 << 4) 
#define DRM_EDID_DIGITAL_DEPTH_16      (6 << 4) 
#define DRM_EDID_DIGITAL_DEPTH_6       (1 << 4) 
#define DRM_EDID_DIGITAL_DEPTH_8       (2 << 4) 
#define DRM_EDID_DIGITAL_DEPTH_MASK    (7 << 4) 
#define DRM_EDID_DIGITAL_DEPTH_RSVD    (7 << 4) 
#define DRM_EDID_DIGITAL_DEPTH_UNDEF   (0 << 4) 
#define DRM_EDID_DIGITAL_DFP_1_X       (1 << 0) 
#define DRM_EDID_DIGITAL_TYPE_DP       (5 << 0) 
#define DRM_EDID_DIGITAL_TYPE_DVI      (1 << 0) 
#define DRM_EDID_DIGITAL_TYPE_HDMI_A   (2 << 0) 
#define DRM_EDID_DIGITAL_TYPE_HDMI_B   (3 << 0) 
#define DRM_EDID_DIGITAL_TYPE_MASK     (7 << 0) 
#define DRM_EDID_DIGITAL_TYPE_MDDI     (4 << 0) 
#define DRM_EDID_DIGITAL_TYPE_UNDEF    (0 << 0) 
#define DRM_EDID_FEATURE_DEFAULT_GTF      (1 << 0)
#define DRM_EDID_FEATURE_DISPLAY_TYPE     (3 << 3) 
#define DRM_EDID_FEATURE_PM_ACTIVE_OFF    (1 << 5)
#define DRM_EDID_FEATURE_PM_STANDBY       (1 << 7)
#define DRM_EDID_FEATURE_PM_SUSPEND       (1 << 6)
#define DRM_EDID_FEATURE_PREFERRED_TIMING (1 << 1)
#define DRM_EDID_FEATURE_STANDARD_COLOR   (1 << 2)
#define DRM_EDID_HDMI_DC_30               (1 << 4)
#define DRM_EDID_HDMI_DC_36               (1 << 5)
#define DRM_EDID_HDMI_DC_48               (1 << 6)
#define DRM_EDID_HDMI_DC_Y444             (1 << 3)
#define DRM_EDID_INPUT_BLANK_TO_BLACK  (1 << 4)
#define DRM_EDID_INPUT_COMPOSITE_SYNC  (1 << 2)
#define DRM_EDID_INPUT_DIGITAL         (1 << 7)
#define DRM_EDID_INPUT_SEPARATE_SYNCS  (1 << 3)
#define DRM_EDID_INPUT_SERRATION_VSYNC (1 << 0)
#define DRM_EDID_INPUT_SYNC_ON_GREEN   (1 << 1)
#define DRM_EDID_INPUT_VIDEO_LEVEL     (3 << 5)
#define DRM_EDID_PT_HSYNC_POSITIVE (1 << 1)
#define DRM_EDID_PT_INTERLACED     (1 << 7)
#define DRM_EDID_PT_SEPARATE_SYNC  (3 << 3)
#define DRM_EDID_PT_STEREO         (1 << 5)
#define DRM_EDID_PT_VSYNC_POSITIVE (1 << 2)
#define DRM_EDID_RANGE_LIMITS_ONLY_FLAG     0x01
#define DRM_EDID_SECONDARY_GTF_SUPPORT_FLAG 0x02
#define DRM_EDID_YCBCR420_DC_MASK (DRM_EDID_YCBCR420_DC_48 | \
				    DRM_EDID_YCBCR420_DC_36 | \
				    DRM_EDID_YCBCR420_DC_30)
#define DRM_ELD_CEA_SAD(mnl, sad)	(20 + (mnl) + 3 * (sad))
#define EDID_DETAIL_COLOR_MGMT_DATA 0xf9
#define EDID_DETAIL_CVT_3BYTE 0xf8
#define EDID_DETAIL_EST_TIMINGS 0xf7
#define EDID_DETAIL_MONITOR_CPDATA 0xfb
#define EDID_DETAIL_MONITOR_NAME 0xfc
#define EDID_DETAIL_MONITOR_RANGE 0xfd
#define EDID_DETAIL_MONITOR_SERIAL 0xff
#define EDID_DETAIL_MONITOR_STRING 0xfe
#define EDID_DETAIL_STD_MODES 0xfa
#define EDID_LENGTH 128
#define EDID_PRODUCT_ID(e) ((e)->prod_code[0] | ((e)->prod_code[1] << 8))
#define EDID_TIMING_ASPECT_MASK  (0x3 << EDID_TIMING_ASPECT_SHIFT)
#define EDID_TIMING_ASPECT_SHIFT 6
#define EDID_TIMING_VFREQ_MASK   (0x3f << EDID_TIMING_VFREQ_SHIFT)
#define EDID_TIMING_VFREQ_SHIFT  0

#define DRM_MODE(nm, t, c, hd, hss, hse, ht, hsk, vd, vss, vse, vt, vs, f) \
	.name = nm, .status = 0, .type = (t), .clock = (c), \
	.hdisplay = (hd), .hsync_start = (hss), .hsync_end = (hse), \
	.htotal = (ht), .hskew = (hsk), .vdisplay = (vd), \
	.vsync_start = (vss), .vsync_end = (vse), .vtotal = (vt), \
	.vscan = (vs), .flags = (f)
#define DRM_MODE_ARG(m) \
	(m)->name, drm_mode_vrefresh(m), (m)->clock, \
	(m)->hdisplay, (m)->hsync_start, (m)->hsync_end, (m)->htotal, \
	(m)->vdisplay, (m)->vsync_start, (m)->vsync_end, (m)->vtotal, \
	(m)->type, (m)->flags
#define DRM_MODE_FMT    "\"%s\": %d %d %d %d %d %d %d %d %d %d 0x%x 0x%x"
#define DRM_MODE_MATCH_3D_FLAGS (1 << 3)
#define DRM_MODE_MATCH_ASPECT_RATIO (1 << 4)
#define DRM_MODE_MATCH_CLOCK (1 << 1)
#define DRM_MODE_MATCH_FLAGS (1 << 2)
#define DRM_MODE_MATCH_TIMINGS (1 << 0)
#define DRM_SIMPLE_MODE(hd, vd, hd_mm, vd_mm) \
	.type = DRM_MODE_TYPE_DRIVER, .clock = 1 , \
	.hdisplay = (hd), .hsync_start = (hd), .hsync_end = (hd), \
	.htotal = (hd), .vdisplay = (vd), .vsync_start = (vd), \
	.vsync_end = (vd), .vtotal = (vd), .width_mm = (hd_mm), \
	.height_mm = (vd_mm)

#define obj_to_mode(x) container_of(x, struct drm_display_mode, base)
#define DMT_SIZE 0x50
#define FBINFO_BE_MATH  0x100000
#define FBINFO_HIDE_SMEM_START  0x200000
#define FBINFO_MISC_ALWAYS_SETPAR   0x40000
#define FBINFO_MISC_FIRMWARE        0x80000
#define FBINFO_MISC_TILEBLITTING       0x20000 
#define FBIO_CURSOR            _IOWR('F', 0x08, struct fb_cursor_user)
#define FB_EVENT_BLANK                  0x09
#define FB_EVENT_FB_REGISTERED          0x05
#define FB_EVENT_FB_UNREGISTERED        0x06
#define FB_LEFT_POS(p, bpp)          (fb_be_math(p) ? (32 - (bpp)) : 0)
#define FB_MODE_IS_FROM_VAR     32
#define FB_PIXMAP_DEFAULT 1     
#define FB_PIXMAP_IO      4     
#define FB_PIXMAP_SYNC    256   
#define FB_PIXMAP_SYSTEM  2     
#define FB_SHIFT_HIGH(p, val, bits)  (fb_be_math(p) ? (val) >> (bits) : \
						      (val) << (bits))
#define FB_SHIFT_LOW(p, val, bits)   (fb_be_math(p) ? (val) << (bits) : \
						      (val) >> (bits))
#define FB_TILE_CURSOR_BLOCK       5
#define FB_TILE_CURSOR_LOWER_HALF  3
#define FB_TILE_CURSOR_LOWER_THIRD 2
#define FB_TILE_CURSOR_NONE        0
#define FB_TILE_CURSOR_TWO_THIRDS  4
#define FB_TILE_CURSOR_UNDERLINE   1

#define VESA_MODEDB_SIZE 43

#define fb_dbg(fb_info, fmt, ...)					\
	pr_debug("fb%d: " fmt, (fb_info)->node, ##__VA_ARGS__)
#define fb_err(fb_info, fmt, ...)					\
	pr_err("fb%d: " fmt, (fb_info)->node, ##__VA_ARGS__)
#define fb_info(fb_info, fmt, ...)					\
	pr_info("fb%d: " fmt, (fb_info)->node, ##__VA_ARGS__)
#define fb_memcpy_fromfb sbus_memcpy_fromio
#define fb_memcpy_tofb sbus_memcpy_toio
#define fb_memset sbus_memset_io
#define fb_notice(info, fmt, ...)					\
	pr_notice("fb%d: " fmt, (fb_info)->node, ##__VA_ARGS__)
#define fb_readb sbus_readb
#define fb_readl sbus_readl
#define fb_readq sbus_readq
#define fb_readw sbus_readw
#define fb_warn(fb_info, fmt, ...)					\
	pr_warn("fb%d: " fmt, (fb_info)->node, ##__VA_ARGS__)
#define fb_writeb sbus_writeb
#define fb_writel sbus_writel
#define fb_writeq sbus_writeq
#define fb_writew sbus_writew
#define for_each_registered_fb(i)		\
	for (i = 0; i < FB_MAX; i++)		\
		if (!registered_fb[i]) {} else

#define to_backlight_device(obj) container_of(obj, struct backlight_device, dev)
#define FBIOGET_DISPINFO        0x4618
#define FBIOGET_GLYPH           0x4615
#define FBIOGET_HWCINFO         0x4616
#define FBIOPUT_MODEINFO        0x4617
#define FBIO_ALLOC              0x4613
#define FBIO_FREE               0x4614
#define FB_ACCEL_3DLABS_PERMEDIA2 15	
#define FB_ACCEL_3DLABS_PERMEDIA3 37	
#define FB_ACCEL_CIRRUS_ALPINE   53	
#define FB_ACCEL_I810           39      
#define FB_ACCEL_I830           42      
#define FB_ACCEL_MATROX_MGA1064SG 17	
#define FB_ACCEL_MATROX_MGA2064W 16	
#define FB_ACCEL_MATROX_MGA2164W 18	
#define FB_ACCEL_MATROX_MGA2164W_AGP 19	
#define FB_ACCEL_NEOMAGIC_NM2070 90	
#define FB_ACCEL_NEOMAGIC_NM2090 91	
#define FB_ACCEL_NEOMAGIC_NM2093 92	
#define FB_ACCEL_NEOMAGIC_NM2097 93	
#define FB_ACCEL_NEOMAGIC_NM2160 94	
#define FB_ACCEL_NEOMAGIC_NM2200 95	
#define FB_ACCEL_NEOMAGIC_NM2230 96	
#define FB_ACCEL_NEOMAGIC_NM2360 97	
#define FB_ACCEL_NEOMAGIC_NM2380 98	
#define FB_ACCEL_NV_10          43      
#define FB_ACCEL_NV_20          44      
#define FB_ACCEL_NV_30          45      
#define FB_ACCEL_NV_40          46      
#define FB_ACCEL_PROSAVAGE_DDR  0x8d	
#define FB_ACCEL_PROSAVAGE_DDRK 0x8e	
#define FB_ACCEL_PROSAVAGE_KM   0x89	
#define FB_ACCEL_PROSAVAGE_PM   0x88	
#define FB_ACCEL_S3TWISTER_K    0x8b	
#define FB_ACCEL_S3TWISTER_P    0x8a	
#define FB_ACCEL_SAVAGE2000     0x83	
#define FB_ACCEL_SAVAGE3D       0x81	
#define FB_ACCEL_SAVAGE3D_MV    0x82	
#define FB_ACCEL_SAVAGE4        0x80	
#define FB_ACCEL_SAVAGE_IX      0x87	
#define FB_ACCEL_SAVAGE_IX_MV   0x86	
#define FB_ACCEL_SAVAGE_MX      0x85	
#define FB_ACCEL_SAVAGE_MX_MV   0x84	
#define FB_ACCEL_SIS_GLAMOUR    36	
#define FB_ACCEL_SIS_GLAMOUR_2  40	
#define FB_ACCEL_SIS_XABRE      41	
#define FB_ACCEL_SUPERSAVAGE    0x8c    
#define FB_ACCEL_TRIDENT_3DIMAGE 51	
#define FB_ACCEL_TRIDENT_BLADE3D 52	
#define FB_ACCEL_TRIDENT_BLADEXP 53	
#define FB_ACTIVATE_FORCE     128	
#define FB_ACTIVATE_INV_MODE  256       
#define FB_ACTIVATE_KD_TEXT   512       
#define FB_ACTIVATE_MASK       15
#define FB_CHANGE_CMAP_VBL     32	
#define FB_CUR_SETALL   0xFF
#define FB_CUR_SETCMAP  0x08
#define FB_CUR_SETHOT   0x04
#define FB_CUR_SETIMAGE 0x01
#define FB_CUR_SETPOS   0x02
#define FB_CUR_SETSHAPE 0x10
#define FB_ROTATE_CCW     3
#define FB_ROTATE_CW      1
#define FB_ROTATE_UD      2
#define FB_ROTATE_UR      0
#define FB_VMODE_NONINTERLACED  0	
#define KHZ2PICOS(a) (1000000000UL/(a))
#define PICOS2KHZ(a) (1000000000UL/(a))
#define ROP_COPY 0
#define ROP_XOR  1
#define VESA_HSYNC_SUSPEND      2
#define VESA_NO_BLANKING        0
#define VESA_POWERDOWN          3
#define VESA_VSYNC_SUSPEND      1

# define CONNECTED_OFF_ENTRY_REQUESTED       (1 << 4)
#define DP_128B132B_SUPPORTED_LINK_RATES       0x2215 
#define DP_128B132B_TRAINING_AUX_RD_INTERVAL   0x2216 
# define DP_128B132B_TRAINING_AUX_RD_INTERVAL_MASK 0x7f
# define DP_ADAPTER_CTRL_FORCE_LOAD_SENSE   (1 << 0)
# define DP_ADJUST_POST_CURSOR2_LANE0_MASK  0x03
# define DP_ADJUST_POST_CURSOR2_LANE0_SHIFT 0
# define DP_ADJUST_POST_CURSOR2_LANE1_MASK  0x0c
# define DP_ADJUST_POST_CURSOR2_LANE1_SHIFT 2
# define DP_ADJUST_POST_CURSOR2_LANE2_MASK  0x30
# define DP_ADJUST_POST_CURSOR2_LANE2_SHIFT 4
# define DP_ADJUST_POST_CURSOR2_LANE3_MASK  0xc0
# define DP_ADJUST_POST_CURSOR2_LANE3_SHIFT 6
# define DP_ADJUST_PRE_EMPHASIS_LANE0_MASK   0x0c
# define DP_ADJUST_PRE_EMPHASIS_LANE0_SHIFT  2
# define DP_ADJUST_PRE_EMPHASIS_LANE1_MASK   0xc0
# define DP_ADJUST_PRE_EMPHASIS_LANE1_SHIFT  6
#define DP_ADJUST_REQUEST_POST_CURSOR2      0x20c
# define DP_ADJUST_TX_FFE_PRESET_LANE0_MASK  (0xf << 0)
# define DP_ADJUST_TX_FFE_PRESET_LANE0_SHIFT 0
# define DP_ADJUST_TX_FFE_PRESET_LANE1_MASK  (0xf << 4)
# define DP_ADJUST_TX_FFE_PRESET_LANE1_SHIFT 4
# define DP_ADJUST_VOLTAGE_SWING_LANE0_MASK  0x03
# define DP_ADJUST_VOLTAGE_SWING_LANE0_SHIFT 0
# define DP_ADJUST_VOLTAGE_SWING_LANE1_MASK  0x30
# define DP_ADJUST_VOLTAGE_SWING_LANE1_SHIFT 4
# define DP_ALPM_LOCK_ERROR_IRQ_HPD_ENABLE  (1 << 1)
# define DP_ALTERNATE_SCRAMBLER_RESET_CAP   (1 << 0)
# define DP_ALTERNATE_SCRAMBLER_RESET_ENABLE (1 << 0)
# define DP_ASSOCIATED_TO_PRECEDING_PORT    (1 << 2)
#define DP_AUX_HDCP_V_PRIME(h)		(0x68014 + h * 4)
# define DP_BLACK_AND_WHITE_VERTICAL_LINES  0x2
#define DP_BRANCH_HW_REV                    0x509
#define DP_BRANCH_ID                        0x503
#define DP_BRANCH_REVISION_START            0x509
#define DP_BRANCH_SW_REV                    0x50A
# define DP_CAP_ANSI_128B132B               (1 << 1) 
# define DP_CEC_IRQ                          (1 << 2)
# define DP_CEC_LOGICAL_ADDRESS_0               (1 << 0)
# define DP_CEC_LOGICAL_ADDRESS_1               (1 << 1)
# define DP_CEC_LOGICAL_ADDRESS_10              (1 << 2)
# define DP_CEC_LOGICAL_ADDRESS_11              (1 << 3)
# define DP_CEC_LOGICAL_ADDRESS_12              (1 << 4)
# define DP_CEC_LOGICAL_ADDRESS_13              (1 << 5)
# define DP_CEC_LOGICAL_ADDRESS_14              (1 << 6)
# define DP_CEC_LOGICAL_ADDRESS_15              (1 << 7)
# define DP_CEC_LOGICAL_ADDRESS_2               (1 << 2)
# define DP_CEC_LOGICAL_ADDRESS_3               (1 << 3)
# define DP_CEC_LOGICAL_ADDRESS_4               (1 << 4)
# define DP_CEC_LOGICAL_ADDRESS_5               (1 << 5)
# define DP_CEC_LOGICAL_ADDRESS_6               (1 << 6)
# define DP_CEC_LOGICAL_ADDRESS_7               (1 << 7)
# define DP_CEC_LOGICAL_ADDRESS_8               (1 << 0)
# define DP_CEC_LOGICAL_ADDRESS_9               (1 << 1)
#define DP_CEC_LOGICAL_ADDRESS_MASK            0x300E 
#define DP_CEC_LOGICAL_ADDRESS_MASK_2          0x300F 
#define DP_CEC_MESSAGE_BUFFER_LENGTH             0x10
# define DP_CEC_MULTIPLE_LA_CAPABLE             (1 << 2)
# define DP_CEC_RX_MESSAGE_ACKED                (1 << 6)
#define DP_CEC_RX_MESSAGE_BUFFER               0x3010
# define DP_CEC_RX_MESSAGE_ENDED                (1 << 7)
# define DP_CEC_RX_MESSAGE_HPD_LOST             (1 << 5)
# define DP_CEC_RX_MESSAGE_HPD_STATE            (1 << 4)
#define DP_CEC_RX_MESSAGE_INFO                 0x3002
# define DP_CEC_RX_MESSAGE_INFO_VALID           (1 << 0)
# define DP_CEC_RX_MESSAGE_LEN_MASK             (0xf << 0)
# define DP_CEC_RX_MESSAGE_LEN_SHIFT            0
# define DP_CEC_RX_MESSAGE_OVERFLOW             (1 << 1)
# define DP_CEC_SNOOPING_CAPABLE                (1 << 1)
# define DP_CEC_SNOOPING_ENABLE                 (1 << 1)
#define DP_CEC_TUNNELING_CAPABILITY            0x3000
# define DP_CEC_TUNNELING_CAPABLE               (1 << 0)
#define DP_CEC_TUNNELING_CONTROL               0x3001
# define DP_CEC_TUNNELING_ENABLE                (1 << 0)
#define DP_CEC_TUNNELING_IRQ_FLAGS             0x3004
# define DP_CEC_TX_ADDRESS_NACK_ERROR           (1 << 6)
# define DP_CEC_TX_DATA_NACK_ERROR              (1 << 7)
# define DP_CEC_TX_LINE_ERROR                   (1 << 5)
#define DP_CEC_TX_MESSAGE_BUFFER               0x3020
#define DP_CEC_TX_MESSAGE_INFO                 0x3003
# define DP_CEC_TX_MESSAGE_LEN_MASK             (0xf << 0)
# define DP_CEC_TX_MESSAGE_LEN_SHIFT            0
# define DP_CEC_TX_MESSAGE_SEND                 (1 << 7)
# define DP_CEC_TX_MESSAGE_SENT                 (1 << 4)
# define DP_CEC_TX_RETRY_COUNT_MASK             (0x7 << 4)
# define DP_CEC_TX_RETRY_COUNT_SHIFT            4
#define DP_CHANNEL_EQ_BITS (DP_LANE_CR_DONE |		\
			    DP_LANE_CHANNEL_EQ_DONE |	\
			    DP_LANE_SYMBOL_LOCKED)
# define DP_COLOR_FORMAT_RGB                (0 << 1)
# define DP_COLOR_FORMAT_YCbCr422           (1 << 1)
# define DP_COLOR_FORMAT_YCbCr444           (2 << 1)
# define DP_COLOR_RAMP                      0x1
# define DP_COLOR_SQUARE                    0x3
# define DP_CONVERSION_BT2020_RGB_YCBCR_ENABLE (1 << 6)
# define DP_CONVERSION_BT601_RGB_YCBCR_ENABLE  (1 << 4)
# define DP_CONVERSION_BT709_RGB_YCBCR_ENABLE  (1 << 5)
# define DP_DECOMPRESSION_EN                (1 << 0)
#define DP_DEVICE_SERVICE_IRQ_VECTOR_ESI0   0x2003   
#define DP_DEVICE_SERVICE_IRQ_VECTOR_ESI1   0x2004   
#define DP_DOWNSTREAMPORT_PRESENT           0x005
#define DP_DOWNSTREAM_PORT_STATUS_CHANGED   (1 << 6)
#define DP_DP13_DPCD_REV                    0x2200
# define DP_DPCD_DISPLAY_CONTROL_CAPABLE     (1 << 3) 
#define DP_DPCD_REV                         0x000
# define DP_DPCD_REV_10                     0x10
# define DP_DPCD_REV_11                     0x11
# define DP_DPCD_REV_12                     0x12
# define DP_DPCD_REV_13                     0x13
# define DP_DPCD_REV_14                     0x14
#define DP_DPRX_FEATURE_ENUMERATION_LIST    0x2210  
# define DP_DSC_10_BPC                      (1 << 2)
# define DP_DSC_10_PER_DP_DSC_SINK          (1 << 6)
# define DP_DSC_12_BPC                      (1 << 3)
# define DP_DSC_12_PER_DP_DSC_SINK          (1 << 7)
# define DP_DSC_16_PER_DP_DSC_SINK          (1 << 0)
# define DP_DSC_1_PER_DP_DSC_SINK           (1 << 0)
# define DP_DSC_20_PER_DP_DSC_SINK          (1 << 1)
# define DP_DSC_24_PER_DP_DSC_SINK          (1 << 2)
# define DP_DSC_2_PER_DP_DSC_SINK           (1 << 1)
# define DP_DSC_4_PER_DP_DSC_SINK           (1 << 3)
# define DP_DSC_6_PER_DP_DSC_SINK           (1 << 4)
# define DP_DSC_8_BPC                       (1 << 1)
# define DP_DSC_8_PER_DP_DSC_SINK           (1 << 5)
# define DP_DSC_BITS_PER_PIXEL_1            0x4
# define DP_DSC_BITS_PER_PIXEL_1_16         0x0
# define DP_DSC_BITS_PER_PIXEL_1_2          0x3
# define DP_DSC_BITS_PER_PIXEL_1_4          0x2
# define DP_DSC_BITS_PER_PIXEL_1_8          0x1
#define DP_DSC_BITS_PER_PIXEL_INC           0x06F
# define DP_DSC_BLK_PREDICTION_IS_SUPPORTED (1 << 0)
#define DP_DSC_BLK_PREDICTION_SUPPORT       0x066
#define DP_DSC_BRANCH_MAX_LINE_WIDTH        0x0a2
#define DP_DSC_BRANCH_OVERALL_THROUGHPUT_0  0x0a0   
#define DP_DSC_BRANCH_OVERALL_THROUGHPUT_1  0x0a1
# define DP_DSC_DECOMPRESSION_IS_SUPPORTED  (1 << 0)
#define DP_DSC_DEC_COLOR_DEPTH_CAP          0x06A
#define DP_DSC_DEC_COLOR_FORMAT_CAP         0x069
#define DP_DSC_ENABLE                       0x160   
#define DP_DSC_LINE_BUF_BIT_DEPTH           0x065
# define DP_DSC_LINE_BUF_BIT_DEPTH_10       0x1
# define DP_DSC_LINE_BUF_BIT_DEPTH_11       0x2
# define DP_DSC_LINE_BUF_BIT_DEPTH_12       0x3
# define DP_DSC_LINE_BUF_BIT_DEPTH_13       0x4
# define DP_DSC_LINE_BUF_BIT_DEPTH_14       0x5
# define DP_DSC_LINE_BUF_BIT_DEPTH_15       0x6
# define DP_DSC_LINE_BUF_BIT_DEPTH_16       0x7
# define DP_DSC_LINE_BUF_BIT_DEPTH_8        0x8
# define DP_DSC_LINE_BUF_BIT_DEPTH_9        0x0
# define DP_DSC_LINE_BUF_BIT_DEPTH_MASK     (0xf << 0)
# define DP_DSC_MAJOR_MASK                  (0xf << 0)
# define DP_DSC_MAJOR_SHIFT                 0
#define DP_DSC_MAX_BITS_PER_PIXEL_HI        0x068   
# define DP_DSC_MAX_BITS_PER_PIXEL_HI_MASK  (0x3 << 0)
# define DP_DSC_MAX_BITS_PER_PIXEL_HI_SHIFT 8
#define DP_DSC_MAX_BITS_PER_PIXEL_LOW       0x067   
#define DP_DSC_MAX_SLICE_WIDTH              0x06C
# define DP_DSC_MINOR_MASK                  (0xf << 4)
# define DP_DSC_MINOR_SHIFT                 4
#define DP_DSC_MIN_SLICE_WIDTH_VALUE        2560
#define DP_DSC_PEAK_THROUGHPUT              0x06B
#define DP_DSC_RC_BUF_BLK_SIZE              0x062
# define DP_DSC_RC_BUF_BLK_SIZE_1           0x0
# define DP_DSC_RC_BUF_BLK_SIZE_16          0x2
# define DP_DSC_RC_BUF_BLK_SIZE_4           0x1
# define DP_DSC_RC_BUF_BLK_SIZE_64          0x3
#define DP_DSC_RC_BUF_SIZE                  0x063
#define DP_DSC_RECEIVER_CAP_SIZE        0xf
#define DP_DSC_REV                          0x061
# define DP_DSC_RGB                         (1 << 0)
#define DP_DSC_SLICE_CAP_1                  0x064
#define DP_DSC_SLICE_CAP_2                  0x06D
#define DP_DSC_SLICE_WIDTH_MULTIPLIER       320
#define DP_DSC_SUPPORT                      0x060   
# define DP_DSC_THROUGHPUT_MODE_0_1000      (14 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_170       (15 << 0) 
# define DP_DSC_THROUGHPUT_MODE_0_340       (1 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_400       (2 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_450       (3 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_500       (4 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_550       (5 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_600       (6 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_650       (7 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_700       (8 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_750       (9 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_800       (10 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_850       (11 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_900       (12 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_950       (13 << 0)
# define DP_DSC_THROUGHPUT_MODE_0_MASK      (0xf << 0)
# define DP_DSC_THROUGHPUT_MODE_0_SHIFT     0
# define DP_DSC_THROUGHPUT_MODE_0_UNSUPPORTED 0
# define DP_DSC_THROUGHPUT_MODE_1_1000      (14 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_170       (15 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_340       (1 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_400       (2 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_450       (3 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_500       (4 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_550       (5 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_600       (6 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_650       (7 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_700       (8 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_750       (9 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_800       (10 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_850       (11 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_900       (12 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_950       (13 << 4)
# define DP_DSC_THROUGHPUT_MODE_1_MASK      (0xf << 4)
# define DP_DSC_THROUGHPUT_MODE_1_SHIFT     4
# define DP_DSC_THROUGHPUT_MODE_1_UNSUPPORTED 0
# define DP_DSC_YCbCr420_Native             (1 << 4)
# define DP_DSC_YCbCr422_Native             (1 << 3)
# define DP_DSC_YCbCr422_Simple             (1 << 2)
# define DP_DSC_YCbCr444                    (1 << 1)
# define DP_DS_HDMI_BT2020_RGB_YCBCR_CONV   (1 << 7)
# define DP_DS_HDMI_BT601_RGB_YCBCR_CONV    (1 << 5)
# define DP_DS_HDMI_BT709_RGB_YCBCR_CONV    (1 << 6)
# define DP_DS_HDMI_FRAME_SEQ_TO_FRAME_PACK (1 << 0)
# define DP_DS_HDMI_YCBCR420_PASS_THROUGH   (1 << 2)
# define DP_DS_HDMI_YCBCR422_PASS_THROUGH   (1 << 1)
# define DP_DS_HDMI_YCBCR444_TO_420_CONV    (1 << 4)
# define DP_DS_HDMI_YCBCR444_TO_422_CONV    (1 << 3)
# define DP_DS_PORT_TYPE_DP_DUALMODE        5
# define DP_DS_PORT_TYPE_WIRELESS           6
# define DP_DWN_STRM_PORT_PRESENT           (1 << 0)
# define DP_DWN_STRM_PORT_TYPE_ANALOG       (1 << 1)
# define DP_DWN_STRM_PORT_TYPE_DP           (0 << 1)
# define DP_DWN_STRM_PORT_TYPE_MASK         0x06
# define DP_DWN_STRM_PORT_TYPE_OTHER        (3 << 1)
# define DP_DWN_STRM_PORT_TYPE_TMDS         (2 << 1)
# define DP_EDP_14a                         0x04    
# define DP_EDP_14b                         0x05    
#define DP_EDP_BACKLIGHT_ADJUSTMENT_CAP     0x702
#define DP_EDP_BACKLIGHT_BRIGHTNESS_LSB     0x723
#define DP_EDP_BACKLIGHT_BRIGHTNESS_MSB     0x722
#define DP_EDP_BACKLIGHT_CONTROL_STATUS     0x727
# define DP_EDP_BACKLIGHT_FREQ_BASE_KHZ     27000
#define DP_EDP_BACKLIGHT_FREQ_CAP_MAX_LSB   0x72f
#define DP_EDP_BACKLIGHT_FREQ_CAP_MAX_MID   0x72e
#define DP_EDP_BACKLIGHT_FREQ_CAP_MAX_MSB   0x72d
#define DP_EDP_BACKLIGHT_FREQ_CAP_MIN_LSB   0x72c
#define DP_EDP_BACKLIGHT_FREQ_CAP_MIN_MID   0x72b
#define DP_EDP_BACKLIGHT_FREQ_CAP_MIN_MSB   0x72a
#define DP_EDP_BACKLIGHT_FREQ_SET           0x728
#define DP_EDP_BACKLIGHT_MODE_SET_REGISTER  0x721
#define DP_EDP_CONFIGURATION_CAP            0x00d   
#define DP_EDP_CONFIGURATION_SET            0x10a   
#define DP_EDP_DBC_MAXIMUM_BRIGHTNESS_SET   0x733
#define DP_EDP_DBC_MINIMUM_BRIGHTNESS_SET   0x732
#define DP_EDP_DISPLAY_CONTROL_REGISTER     0x720
# define DP_EDP_MSO_INDEPENDENT_LINK_BIT    (1 << 3)
#define DP_EDP_MSO_LINK_CAPABILITIES        0x7a4    
# define DP_EDP_MSO_NUMBER_OF_LINKS_MASK    (7 << 0)
# define DP_EDP_MSO_NUMBER_OF_LINKS_SHIFT   0
#define DP_EDP_PWMGEN_BIT_COUNT             0x724
#define DP_EDP_PWMGEN_BIT_COUNT_CAP_MAX     0x726
#define DP_EDP_PWMGEN_BIT_COUNT_CAP_MIN     0x725
# define DP_EDP_PWMGEN_BIT_COUNT_MASK       (0x1f << 0)
#define DP_EDP_REGIONAL_BACKLIGHT_BASE      0x740    
# define DP_FALLBACK_1024x768_60HZ_24BPP    (1 << 0)
# define DP_FALLBACK_1280x720_60HZ_24BPP    (1 << 1)
# define DP_FALLBACK_1920x1080_60HZ_24BPP   (1 << 2)
#define DP_FEC_BASE(dp_phy) \
	(__DP_FEC1_BASE + ((__DP_FEC2_BASE - __DP_FEC1_BASE) * \
			   ((dp_phy) - DP_PHY_LTTPR1)))
#define DP_FEC_CAPABILITY_PHY_REPEATER1                     0xf0294 
# define DP_FEC_CORR_BLK_ERROR_COUNT_CAP    (1 << 2)
#define DP_FEC_ERROR_COUNT_PHY_REPEATER1                    0xf0291 
#define DP_FEC_REG(dp_phy, fec1_reg) \
	(DP_FEC_BASE(dp_phy) - DP_FEC_BASE(DP_PHY_LTTPR1) + fec1_reg)
#define DP_FEC_STATUS_PHY_REPEATER(dp_phy) \
	DP_FEC_REG(dp_phy, DP_FEC_STATUS_PHY_REPEATER1)
# define DP_FEC_UNCORR_BLK_ERROR_COUNT_CAP  (1 << 1)
# define DP_FORMAT_CONVERSION               (1 << 3)
# define DP_GET_SINK_COUNT(x)		    ((((x) & 0x80) >> 1) | ((x) & 0x3f))
#define DP_HDCP_2_2_AKE_SEND_PAIRING_INFO_OFFSET \
						DP_HDCP_2_2_REG_EKH_KM_RD_OFFSET
# define DP_LANE02_MAX_POST_CURSOR2_REACHED (1 << 2)
# define DP_LANE02_POST_CURSOR2_SET_MASK    (3 << 0)
#define DP_LANE0_1_STATUS_ESI                  0x200c 
#define DP_LANE0_1_STATUS_PHY_REPEATER(dp_phy) \
	DP_LTTPR_REG(dp_phy, DP_LANE0_1_STATUS_PHY_REPEATER1)
# define DP_LANE13_MAX_POST_CURSOR2_REACHED (1 << 6)
# define DP_LANE13_POST_CURSOR2_SET_MASK    (3 << 4)
#define DP_LANE2_3_STATUS_ESI                  0x200d 
#define DP_LANE_ALIGN_STATUS_UPDATED_ESI       0x200e 
# define DP_LANE_COUNT_ENHANCED_FRAME_EN    (1 << 7)
# define DP_LINK_BW_10                      0x01    
# define DP_LINK_BW_13_5                    0x04    
# define DP_LINK_BW_20                      0x02    
#define DP_LINK_CONSTANT_N_VALUE 0x8000
# define DP_LINK_QUAL_PATTERN_11_DISABLE    (0 << 2)
# define DP_LINK_QUAL_PATTERN_11_ERROR_RATE (2 << 2)
# define DP_LINK_QUAL_PATTERN_128B132B_TPS1 0x08
# define DP_LINK_QUAL_PATTERN_128B132B_TPS2 0x10
# define DP_LINK_QUAL_PATTERN_80BIT_CUSTOM  4
# define DP_LINK_QUAL_PATTERN_CP2520_PAT_1  5
# define DP_LINK_QUAL_PATTERN_CP2520_PAT_2  6
# define DP_LINK_QUAL_PATTERN_CP2520_PAT_3  7
# define DP_LINK_QUAL_PATTERN_CUSTOM        0x40
# define DP_LINK_QUAL_PATTERN_ERROR_RATE    2
# define DP_LINK_QUAL_PATTERN_PRSBS11       0x20
# define DP_LINK_QUAL_PATTERN_PRSBS15       0x28
# define DP_LINK_QUAL_PATTERN_PRSBS23       0x30
# define DP_LINK_QUAL_PATTERN_PRSBS31       0x38
# define DP_LINK_QUAL_PATTERN_PRSBS9        0x18
# define DP_LINK_QUAL_PATTERN_SQUARE        0x48
#define DP_LINK_SERVICE_IRQ_VECTOR_ESI0     0x2005   
# define DP_LOCK_ACQUISITION_REQUEST         (1 << 1)
#define DP_LTTPR_BASE(dp_phy) \
	(__DP_LTTPR1_BASE + (__DP_LTTPR2_BASE - __DP_LTTPR1_BASE) * \
		((dp_phy) - DP_PHY_LTTPR1))
#define DP_LTTPR_REG(dp_phy, lttpr1_reg) \
	(DP_LTTPR_BASE(dp_phy) - DP_LTTPR_BASE(DP_PHY_LTTPR1) + (lttpr1_reg))
#define DP_LT_TUNABLE_PHY_REPEATER_FIELD_DATA_STRUCTURE_REV 0xf0000 
#define DP_MAIN_LINK_CHANNEL_CODING         0x006
#define DP_MAX_DOWNSPREAD                   0x003
#define DP_MAX_LANE_COUNT                   0x002
#define DP_MAX_LINK_RATE                    0x001
#define DP_MST_LOGICAL_PORT_0 8
#define DP_MST_PHYSICAL_PORT_0 0
#define DP_NORP                             0x004
# define DP_NO_AUX_HANDSHAKE_LINK_TRAINING  (1 << 6)
# define DP_NO_TEST_PATTERN                 0x0
# define DP_PAYLOAD_ACT_HANDLED             (1 << 1)
#define DP_PAYLOAD_ALLOCATE_START_TIME_SLOT 0x1c1
#define DP_PAYLOAD_ALLOCATE_TIME_SLOT_COUNT 0x1c2
# define DP_PAYLOAD_TABLE_UPDATED           (1 << 0)
#define DP_PAYLOAD_TABLE_UPDATE_STATUS      0x2c0   
# define DP_PCON_DSC_10_PER_DSC_ENC    (0x1 << 6)
# define DP_PCON_DSC_12_PER_DSC_ENC    (0x1 << 7)
# define DP_PCON_DSC_1_PER_DSC_ENC     (0x1 << 0)
# define DP_PCON_DSC_20_PER_DSC_ENC         (0x1 << 1)
# define DP_PCON_DSC_24_PER_DSC_ENC         (0x1 << 2)
# define DP_PCON_DSC_2_PER_DSC_ENC     (0x1 << 1)
# define DP_PCON_DSC_4_PER_DSC_ENC     (0x1 << 3)
# define DP_PCON_DSC_6_PER_DSC_ENC     (0x1 << 4)
# define DP_PCON_DSC_8_PER_DSC_ENC     (0x1 << 5)
#define DP_PCON_DSC_ENCODER                 0x092
#define DP_PCON_DSC_ENCODER_CAP_SIZE        0xC	
# define DP_PCON_DSC_ENCODER_SUPPORTED      (1 << 0)
# define DP_PCON_DSC_PPS_ENC_OVERRIDE       (1 << 1)
#define DP_PCON_DSC_SLICE_CAP_2             0x09C
#define DP_PCON_DSC_VERSION                 0x093
# define DP_PCON_ENABLE_CONCURRENT_LINK       (1 << 4)
# define DP_PCON_ENABLE_HDMI_LINK             (1 << 7)
# define DP_PCON_ENABLE_LINK_FRL_MODE         (1 << 5)
# define DP_PCON_ENABLE_MAX_FRL_BW             (7 << 0)
# define DP_PCON_ENABLE_SEQUENTIAL_LINK       (0 << 4)
# define DP_PCON_ENABLE_SOURCE_CTL_MODE       (1 << 3)
# define DP_PCON_ENC_PPS_OVERRIDE_DISABLED      0
# define DP_PCON_ENC_PPS_OVERRIDE_EN_BUFFER     2
# define DP_PCON_ENC_PPS_OVERRIDE_EN_PARAMS     1
# define DP_PCON_FRL_BW_MASK_18GBPS           (1 << 1)
# define DP_PCON_FRL_BW_MASK_24GBPS           (1 << 2)
# define DP_PCON_FRL_BW_MASK_32GBPS           (1 << 3)
# define DP_PCON_FRL_BW_MASK_40GBPS           (1 << 4)
# define DP_PCON_FRL_BW_MASK_48GBPS           (1 << 5)
# define DP_PCON_FRL_BW_MASK_9GBPS            (1 << 0)
# define DP_PCON_FRL_LINK_TRAIN_EXTENDED      (1 << 6)
# define DP_PCON_FRL_LINK_TRAIN_NORMAL        (0 << 6)
# define DP_PCON_HDMI_ERROR_COUNT_HUNDRED_PLUS (1 << 2)
# define DP_PCON_HDMI_ERROR_COUNT_MASK         (0x7 << 0)
# define DP_PCON_HDMI_ERROR_COUNT_TEN_PLUS     (1 << 1)
# define DP_PCON_HDMI_ERROR_COUNT_THREE_PLUS   (1 << 0)
#define DP_PCON_HDMI_ERROR_STATUS_LN0          0x3037
#define DP_PCON_HDMI_ERROR_STATUS_LN1          0x3038
#define DP_PCON_HDMI_ERROR_STATUS_LN2          0x3039
#define DP_PCON_HDMI_ERROR_STATUS_LN3          0x303A
# define DP_PCON_HDMI_FRL_TRAINED_BW          (0x3F << 1)
#define DP_PCON_HDMI_LINK_CONFIG_1             0x305A
#define DP_PCON_HDMI_LINK_CONFIG_2            0x305B
# define DP_PCON_HDMI_LINK_MODE               (1 << 0)
# define DP_PCON_HDMI_MODE_FRL                1
# define DP_PCON_HDMI_MODE_TMDS               0
#define DP_PCON_HDMI_POST_FRL_STATUS          0x3036
#define DP_PCON_HDMI_PPS_OVERRIDE_BASE        0x3100
#define DP_PCON_HDMI_PPS_OVRD_SLICE_HEIGHT    0x3180
#define DP_PCON_HDMI_PPS_OVRD_SLICE_WIDTH    0x3182
# define DP_PCON_HDMI_TX_LINK_ACTIVE          (1 << 0)
#define DP_PCON_HDMI_TX_LINK_STATUS           0x303B
# define DP_PCON_MAX_0GBPS                  (0 << 2)
# define DP_PCON_MAX_18GBPS                 (2 << 2)
# define DP_PCON_MAX_24GBPS                 (3 << 2)
# define DP_PCON_MAX_32GBPS                 (4 << 2)
# define DP_PCON_MAX_40GBPS                 (5 << 2)
# define DP_PCON_MAX_48GBPS                 (6 << 2)
# define DP_PCON_MAX_9GBPS                  (1 << 2)
# define DP_PCON_MAX_FRL_BW                 (7 << 2)
# define DP_PCON_MAX_LINK_BW_MASK             (0x3F << 0)
# define DP_PCON_SOURCE_CTL_MODE            (1 << 5)
#define DP_PHY_LTTPR(i)					    (DP_PHY_LTTPR1 + (i))
#define DP_PHY_TEST_PATTERN                 0x248
# define DP_PHY_TEST_PATTERN_80BIT_CUSTOM   0x4
# define DP_PHY_TEST_PATTERN_CP2520         0x5
# define DP_PHY_TEST_PATTERN_D10_2          0x1
# define DP_PHY_TEST_PATTERN_ERROR_COUNT    0x2
# define DP_PHY_TEST_PATTERN_NONE           0x0
# define DP_PHY_TEST_PATTERN_PRBS7          0x3
# define DP_PHY_TEST_PATTERN_SEL_MASK       0x7
# define DP_PSR2_SU_GRANULARITY_REQUIRED    (1 << 5)  
# define DP_PSR2_SU_Y_COORDINATE_REQUIRED   (1 << 4)  
# define DP_PSR2_WITH_Y_COORD_IS_SUPPORTED  3	    
#define DP_PSR_CAPS                         0x071   
# define DP_PSR_CAPS_CHANGE                 (1 << 0)
#define DP_PSR_ERROR_STATUS                 0x2006  
#define DP_PSR_ESI                          0x2007  
# define DP_PSR_IS_SUPPORTED                1
# define DP_PSR_LINK_CRC_ERROR              (1 << 0)
# define DP_PSR_NO_TRAIN_ON_EXIT            1
# define DP_PSR_RFB_STORAGE_ERROR           (1 << 1)
# define DP_PSR_SETUP_TIME_0                (6 << 1)
# define DP_PSR_SETUP_TIME_110              (4 << 1)
# define DP_PSR_SETUP_TIME_165              (3 << 1)
# define DP_PSR_SETUP_TIME_220              (2 << 1)
# define DP_PSR_SETUP_TIME_275              (1 << 1)
# define DP_PSR_SETUP_TIME_330              (0 << 1)
# define DP_PSR_SETUP_TIME_55               (5 << 1)
# define DP_PSR_SETUP_TIME_MASK             (7 << 1)
# define DP_PSR_SETUP_TIME_SHIFT            1
# define DP_PSR_SINK_ACTIVE_RESYNC          4
# define DP_PSR_SINK_ACTIVE_RFB             2
# define DP_PSR_SINK_ACTIVE_SINK_SYNCED     3
# define DP_PSR_SINK_ACTIVE_SRC_SYNCED      1
# define DP_PSR_SINK_INACTIVE               0
# define DP_PSR_SINK_INTERNAL_ERROR         7
# define DP_PSR_SINK_STATE_MASK             0x07
#define DP_PSR_STATUS                       0x2008  
#define DP_PSR_SUPPORT                      0x070   
# define DP_PSR_VSC_SDP_UNCORRECTABLE_ERROR (1 << 2) 
#define DP_RECEIVE_PORT_1_BUFFER_SIZE       0x00b
# define DP_REMOTE_CONTROL_COMMAND_PENDING  (1 << 0)
# define DP_RX_GTC_MSTR_REQ_STATUS_CHANGE    (1 << 0)
#define DP_SDP_CAMERA_GENERIC(i)	(0x08 + (i)) 
#define DP_SDP_PPS_HEADER_PAYLOAD_BYTES_MINUS_1 0x7F
# define DP_SET_ANSI_128B132B               (1 << 1)
#define DP_SET_POWER                        0x600
# define DP_SET_POWER_D0                    0x1
# define DP_SET_POWER_D3                    0x2
# define DP_SET_POWER_D3_AUX_ON             0x5
# define DP_SET_POWER_MASK                  0x3
# define DP_SINGLE_STREAM_SIDEBAND_MSG      (1 << 1) 
# define DP_SINK_COUNT_CP_READY             (1 << 6)
#define DP_SINK_DEVICE_AUX_FRAME_SYNC_CAP   0x02f   
#define DP_SINK_DEVICE_AUX_FRAME_SYNC_CONF  0x117   
#define DP_SINK_STATUS_ESI                     0x200f 
#define DP_SINK_VIDEO_FALLBACK_FORMATS      0x020   
# define DP_STREAM_REGENERATION_STATUS      (1 << 2) 
# define DP_STREAM_REGENERATION_STATUS_CAP  (1 << 1) 
# define DP_SYMBOL_ERROR_COUNT_DISPARITY    (1 << 6)
#define DP_TEST_80BIT_CUSTOM_PATTERN_7_0    0x250
# define DP_TEST_BIT_DEPTH_10               (2 << 5)
# define DP_TEST_BIT_DEPTH_12               (3 << 5)
# define DP_TEST_BIT_DEPTH_16               (4 << 5)
# define DP_TEST_BIT_DEPTH_6                (0 << 5)
# define DP_TEST_BIT_DEPTH_8                (1 << 5)
# define DP_TEST_BIT_DEPTH_MASK             (7 << 5)
# define DP_TEST_BIT_DEPTH_SHIFT            5
# define DP_TEST_COLOR_FORMAT_MASK          (3 << 1)
# define DP_TEST_COLOR_FORMAT_SHIFT         1
# define DP_TEST_DYNAMIC_RANGE_CEA          (1 << 3)
# define DP_TEST_DYNAMIC_RANGE_VESA         (0 << 3)
#define DP_TEST_HBR2_SCRAMBLER_RESET        0x24A
#define DP_TEST_HSYNC_HI                    0x22A
# define DP_TEST_HSYNC_POLARITY             (1 << 7)
# define DP_TEST_HSYNC_WIDTH_HI_MASK        (127 << 0)
#define DP_TEST_HSYNC_WIDTH_LO              0x22B
#define DP_TEST_H_START_HI                  0x226
#define DP_TEST_H_START_LO                  0x227
#define DP_TEST_H_TOTAL_HI                  0x222
#define DP_TEST_H_TOTAL_LO                  0x223
#define DP_TEST_H_WIDTH_HI                  0x22E
#define DP_TEST_H_WIDTH_LO                  0x22F
# define DP_TEST_INTERLACED                 (1 << 1)
# define DP_TEST_LINK_AUDIO_DISABLED_VIDEO  (1 << 6) 
# define DP_TEST_LINK_AUDIO_PATTERN         (1 << 5) 
#define DP_TEST_MISC0                       0x232
#define DP_TEST_MISC1                       0x233
# define DP_TEST_REFRESH_DENOMINATOR        (1 << 0)
#define DP_TEST_REFRESH_RATE_NUMERATOR      0x234
# define DP_TEST_SYNC_CLOCK                 (1 << 0)
#define DP_TEST_VSYNC_HI                    0x22C
# define DP_TEST_VSYNC_POLARITY             (1 << 7)
# define DP_TEST_VSYNC_WIDTH_HI_MASK        (127 << 0)
#define DP_TEST_VSYNC_WIDTH_LO              0x22D
#define DP_TEST_V_HEIGHT_HI                 0x230
#define DP_TEST_V_HEIGHT_LO                 0x231
#define DP_TEST_V_START_HI                  0x228
#define DP_TEST_V_START_LO                  0x229
#define DP_TEST_V_TOTAL_HI                  0x224
#define DP_TEST_V_TOTAL_LO                  0x225
# define DP_TEST_YCBCR_COEFFICIENTS         (1 << 4)
# define DP_TPS4_SUPPORTED                  (1 << 7)
#define DP_TRAINING_AUX_RD_INTERVAL             0x00e   
#define DP_TRAINING_AUX_RD_INTERVAL_PHY_REPEATER(dp_phy)	\
	DP_LTTPR_REG(dp_phy, DP_TRAINING_AUX_RD_INTERVAL_PHY_REPEATER1)
# define DP_TRAINING_AUX_RD_MASK                0x7F    
#define DP_TRAINING_LANE0_SET_PHY_REPEATER(dp_phy) \
	DP_LTTPR_REG(dp_phy, DP_TRAINING_LANE0_SET_PHY_REPEATER1)
# define DP_TRAINING_PATTERN_4              7       
#define DP_TRAINING_PATTERN_SET_PHY_REPEATER(dp_phy) \
	DP_LTTPR_REG(dp_phy, DP_TRAINING_PATTERN_SET_PHY_REPEATER1)
# define DP_TRAIN_MAX_PRE_EMPHASIS_REACHED  (1 << 5)
# define DP_TRAIN_VOLTAGE_SWING_LEVEL_0 (0 << 0)
# define DP_TRAIN_VOLTAGE_SWING_LEVEL_1 (1 << 0)
# define DP_TRAIN_VOLTAGE_SWING_LEVEL_2 (2 << 0)
# define DP_TRAIN_VOLTAGE_SWING_LEVEL_3 (3 << 0)
# define DP_TX_FFE_PRESET_VALUE_MASK        (0xf << 0) 
# define DP_UHBR10                             (1 << 0)
# define DP_UHBR13_5                           (1 << 2)
# define DP_UHBR20                             (1 << 1)
#define DP_VC_PAYLOAD_ID_SLOT_1             0x2c1   
# define DP_YCBCR_COEFFICIENTS_ITU601       (0 << 4)
# define DP_YCBCR_COEFFICIENTS_ITU709       (1 << 4)
#define HDCP_2_2_DP_RXSTATUS_H_PRIME(x)		((x) & BIT(1))
#define HDCP_2_2_DP_RXSTATUS_LINK_FAILED(x)	((x) & BIT(4))
#define HDCP_2_2_DP_RXSTATUS_PAIRING(x)		((x) & BIT(2))
#define HDCP_2_2_DP_RXSTATUS_READY(x)		((x) & BIT(0))
#define HDCP_2_2_DP_RXSTATUS_REAUTH_REQ(x)	((x) & BIT(3))
# define HDMI_LINK_STATUS_CHANGED            (1 << 3)
# define LINK_STATUS_CHANGED                 (1 << 1)
# define RX_CAP_CHANGED                      (1 << 0)
# define STREAM_STATUS_CHANGED               (1 << 2)
#define _DP_MSA_MISC_COLOR(misc1_7, misc0_21, misc0_3, misc0_4) \
	((misc1_7) << 15 | (misc0_4) << 4 | (misc0_3) << 3 | ((misc0_21) << 1))


#define to_drm_i2c_encoder_driver(x) container_of((x),			\
						  struct drm_i2c_encoder_driver, \
						  i2c_driver)
#define to_encoder_slave(x) container_of((x), struct drm_encoder_slave, base)

#define drm_for_each_encoder(encoder, dev) \
	list_for_each_entry(encoder, &(dev)->mode_config.encoder_list, head)
#define drm_for_each_encoder_mask(encoder, dev, encoder_mask) \
	list_for_each_entry((encoder), &(dev)->mode_config.encoder_list, head) \
		for_each_if ((encoder_mask) & drm_encoder_mask(encoder))
#define drmm_encoder_alloc(dev, type, member, funcs, encoder_type, name, ...) \
	((type *)__drmm_encoder_alloc(dev, sizeof(type), \
				      offsetof(type, member), funcs, \
				      encoder_type, name, ##__VA_ARGS__))
#define drmm_plain_encoder_alloc(dev, funcs, encoder_type, name, ...) \
	((struct drm_encoder *) \
	 __drmm_encoder_alloc(dev, sizeof(struct drm_encoder), \
			      0, funcs, encoder_type, name, ##__VA_ARGS__))
#define obj_to_encoder(x) container_of(x, struct drm_encoder, base)

#define DRF_BITS(drf)  (DRF_HI(drf) - DRF_LO(drf) + 1)
#define DRF_HI(drf)    (1 ? drf)
#define DRF_HW_BITS(o,drf)  (DRF_HW_HI((o),drf) - DRF_HW_LO((o),drf) + 1)
#define DRF_HW_CLR(o,drf)   ((o)[DRF_HW_IDX((o),drf)] & ~DRF_HW_SMASK((o),drf))
#define DRF_HW_GET(o,drf)   ((o)[DRF_HW_IDX(o,drf)] & DRF_HW_SMASK((o),drf))
#define DRF_HW_HI(o,drf)    (DRF_HI(DRF_MW(drf)) % DRF_MW_SIZE(o))
#define DRF_HW_IDX(o,drf)   (DRF_HI(DRF_MW(drf)) / DRF_MW_SIZE(o))
#define DRF_HW_LO(o,drf)    0
#define DRF_HW_MASK(o,drf)  (~0ULL >> (64 - DRF_HW_BITS((o),drf)))
#define DRF_HW_SET(o,drf,v) (DRF_HW_CLR((o),drf) | DRF_HW_VAL((o),drf,(v)))
#define DRF_HW_SMASK(o,drf) (DRF_HW_MASK((o),drf) << DRF_HW_LO((o),drf))
#define DRF_HW_VAL(o,drf,v) (((long long)(v) >> DRF_LW_BITS((o),drf)) & DRF_HW_SMASK((o),drf))
#define DRF_LO(drf)    (0 ? drf)
#define DRF_LW_BITS(o,drf)  (DRF_LW_HI((o),drf) - DRF_LW_LO((o),drf) + 1)
#define DRF_LW_CLR(o,drf)   ((o)[DRF_LW_IDX((o),drf)] & ~DRF_LW_SMASK((o),drf))
#define DRF_LW_GET(o,drf)   (((o)[DRF_LW_IDX((o),drf)] >> DRF_LW_LO((o),drf)) & DRF_LW_MASK((o),drf))
#define DRF_LW_HI(o,drf)    (DRF_MW_SPANS((o),drf) ? (DRF_MW_SIZE(o) - 1) : DRF_HW_HI((o),drf))
#define DRF_LW_IDX(o,drf)   (DRF_LO(DRF_MW(drf)) / DRF_MW_SIZE(o))
#define DRF_LW_LO(o,drf)    (DRF_LO(DRF_MW(drf)) % DRF_MW_SIZE(o))
#define DRF_LW_MASK(o,drf)  (~0ULL >> (64 - DRF_LW_BITS((o),drf)))
#define DRF_LW_SET(o,drf,v) (DRF_LW_CLR((o),drf) | DRF_LW_VAL((o),drf,(v)))
#define DRF_LW_SMASK(o,drf) (DRF_LW_MASK((o),drf) << DRF_LW_LO((o),drf))
#define DRF_LW_VAL(o,drf,v) (((v) & DRF_LW_MASK((o),drf)) << DRF_LW_LO((o),drf))
#define DRF_MASK(drf)  (~0ULL >> (64 - DRF_BITS(drf)))
#define DRF_MD(A...) DRF_MD_(X, ##A, DRF_MD_I, DRF_MD_N)(X, ##A)
#define DRF_MD_(X,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,IMPL,...) IMPL
#define DRF_MD_I(X,er,ew,ty,p,o,d,r,i,f,v)                                               \
	NVVAL_GET_X(DRF_MR_X(er, ew, ty, (p), (o), d##_##r(i), DRF_SMASK(d##_##r##_##f), \
		    NVVAL_X(d##_##r##_##f, d##_##r##_##f##_##v)), d##_##r##_##f)
#define DRF_MD_N(X,er,ew,ty,p,o,d,r,  f,v)                                               \
	NVVAL_GET_X(DRF_MR_X(er, ew, ty, (p), (o), d##_##r   , DRF_SMASK(d##_##r##_##f), \
		    NVVAL_X(d##_##r##_##f, d##_##r##_##f##_##v)), d##_##r##_##f)
#define DRF_MR(A...) DRF_MR_(X, ##A, DRF_MR_I, DRF_MR_N)(X, ##A)
#define DRF_MR_(X,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,IMPL,...) IMPL
#define DRF_MR_I(X,er,ew,ty,p,o,d,r,i,m,v) DRF_MR_X(er, ew, ty, (p), (o), d##_##r(i), (m), (v))
#define DRF_MR_N(X,er,ew,ty,p,o,d,r  ,m,v) DRF_MR_X(er, ew, ty, (p), (o), d##_##r   , (m), (v))
#define DRF_MR_X(er,ew,ty,p,o,dr,m,v) ({               \
	ty _t = DRF_RD_X(er, (p), (o), dr);            \
	DRF_WR_X(ew, (p), (o), dr, (_t & ~(m)) | (v)); \
	_t;                                            \
})
#define DRF_MV(A...) DRF_MV_(X, ##A, DRF_MV_I, DRF_MV_N)(X, ##A)
#define DRF_MV_(X,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,IMPL,...) IMPL
#define DRF_MV_I(X,er,ew,ty,p,o,d,r,i,f,v)                                               \
	NVVAL_GET_X(DRF_MR_X(er, ew, ty, (p), (o), d##_##r(i), DRF_SMASK(d##_##r##_##f), \
		    NVVAL_X(d##_##r##_##f, (v))), d##_##r##_##f)
#define DRF_MV_N(X,er,ew,ty,p,o,d,r,  f,v)                                               \
	NVVAL_GET_X(DRF_MR_X(er, ew, ty, (p), (o), d##_##r   , DRF_SMASK(d##_##r##_##f), \
		    NVVAL_X(d##_##r##_##f, (v))), d##_##r##_##f)
#define DRF_MW(drf)         DRF_MX(drf)
#define DRF_MW_SIZE(o)      (sizeof((o)[0]) * 8)
#define DRF_MW_SPANS(o,drf) (DRF_LW_IDX((o),drf) != DRF_HW_IDX((o),drf))
#define DRF_MX(drf)         DRF_MX_##drf
#define DRF_MX_MW(drf)      drf
#define DRF_RD(A...) DRF_RD_(X, ##A, DRF_RD_I, DRF_RD_N)(X, ##A)
#define DRF_RD_(X,_1,_2,_3,_4,_5,_6,IMPL,...) IMPL
#define DRF_RD_I(X,e,p,o,d,r,i) DRF_RD_X(e, (p), (o), d##_##r(i))
#define DRF_RD_N(X,e,p,o,d,r  ) DRF_RD_X(e, (p), (o), d##_##r)
#define DRF_RD_X(e,p,o,dr) e((p), (o), dr)
#define DRF_RV(A...) DRF_RV_(X, ##A, DRF_RV_I, DRF_RV_N)(X, ##A)
#define DRF_RV_(X,_1,_2,_3,_4,_5,_6,_7,IMPL,...) IMPL
#define DRF_RV_I(X,e,p,o,d,r,i,f) DRF_RV_X(e, (p), (o), d##_##r(i), d##_##r##_##f)
#define DRF_RV_N(X,e,p,o,d,r,  f) DRF_RV_X(e, (p), (o), d##_##r   , d##_##r##_##f)
#define DRF_RV_X(e,p,o,dr,drf) NVVAL_GET_X(DRF_RD_X(e, (p), (o), dr), drf)
#define DRF_SMASK(drf) (DRF_MASK(drf) << DRF_LO(drf))
#define DRF_TD(A...) DRF_TD_(X, ##A, DRF_TD_I, DRF_TD_N)(X, ##A)
#define DRF_TD_(X,_1,_2,_3,_4,_5,_6,_7,_8,_9,IMPL,...) IMPL
#define DRF_TD_I(X,e,p,o,d,r,i,f,cmp,v)                                                          \
	NVVAL_TEST_X(DRF_RD_X(e, (p), (o), d##_##r(i)), d##_##r##_##f, cmp, d##_##r##_##f##_##v)
#define DRF_TD_N(X,e,p,o,d,r,  f,cmp,v)                                                          \
	NVVAL_TEST_X(DRF_RD_X(e, (p), (o), d##_##r   ), d##_##r##_##f, cmp, d##_##r##_##f##_##v)
#define DRF_TV(A...) DRF_TV_(X, ##A, DRF_TV_I, DRF_TV_N)(X, ##A)
#define DRF_TV_(X,_1,_2,_3,_4,_5,_6,_7,_8,_9,IMPL,...) IMPL
#define DRF_TV_I(X,e,p,o,d,r,i,f,cmp,v)                                          \
	NVVAL_TEST_X(DRF_RD_X(e, (p), (o), d##_##r(i)), d##_##r##_##f, cmp, (v))
#define DRF_TV_N(X,e,p,o,d,r,  f,cmp,v)                                          \
	NVVAL_TEST_X(DRF_RD_X(e, (p), (o), d##_##r   ), d##_##r##_##f, cmp, (v))
#define DRF_WD(A...) DRF_WD_(X, ##A, DRF_WD_I, DRF_WD_N)(X, ##A)
#define DRF_WD_(X,_1,_2,_3,_4,_5,_6,_7,_8,IMPL,...) IMPL
#define DRF_WD_I(X,e,p,o,d,r,i,f,v)                                                    \
	DRF_WR_X(e, (p), (o), d##_##r(i), NVVAL_X(d##_##r##_##f, d##_##r##_##f##_##v))
#define DRF_WD_N(X,e,p,o,d,r,  f,v)                                                    \
	DRF_WR_X(e, (p), (o), d##_##r   , NVVAL_X(d##_##r##_##f, d##_##r##_##f##_##v))
#define DRF_WR(A...) DRF_WR_(X, ##A, DRF_WR_I, DRF_WR_N)(X, ##A)
#define DRF_WR_(X,_1,_2,_3,_4,_5,_6,_7,IMPL,...) IMPL
#define DRF_WR_I(X,e,p,o,d,r,i,v) DRF_WR_X(e, (p), (o), d##_##r(i), (v))
#define DRF_WR_N(X,e,p,o,d,r,  v) DRF_WR_X(e, (p), (o), d##_##r   , (v))
#define DRF_WR_X(e,p,o,dr,v) e((p), (o), dr, (v))
#define DRF_WV(A...) DRF_WV_(X, ##A, DRF_WV_I, DRF_WV_N)(X, ##A)
#define DRF_WV_(X,_1,_2,_3,_4,_5,_6,_7,_8,IMPL,...) IMPL
#define DRF_WV_I(X,e,p,o,d,r,i,f,v)                                    \
	DRF_WR_X(e, (p), (o), d##_##r(i), NVVAL_X(d##_##r##_##f, (v)))
#define DRF_WV_N(X,e,p,o,d,r,  f,v)                                    \
	DRF_WR_X(e, (p), (o), d##_##r   , NVVAL_X(d##_##r##_##f, (v)))
#define NVDEF(A...) NVDEF_(X, ##A, NVDEF_I, NVDEF_N)(X, ##A)
#define NVDEF_(X,_1,_2,_3,_4,_5,IMPL,...) IMPL
#define NVDEF_I(X,d,r,f,i,v) NVVAL_X(d##_##r##_##f(i), d##_##r##_##f##_##v)
#define NVDEF_MW_SET(A...) NVDEF_MW_SET_(X, ##A, NVDEF_MW_SET_I, NVDEF_MW_SET_N)(X, ##A)
#define NVDEF_MW_SET_(X,_1,_2,_3,_4,_5,_6,IMPL,...) IMPL
#define NVDEF_MW_SET_I(X,o,d,r,f,i,v) NVVAL_MW_SET_X(o, d##_##r##_##f(i), d##_##r##_##f##_##v)
#define NVDEF_MW_SET_N(X,o,d,r,f,  v) NVVAL_MW_SET_X(o, d##_##r##_##f,    d##_##r##_##f##_##v)
#define NVDEF_N(X,d,r,f,  v) NVVAL_X(d##_##r##_##f, d##_##r##_##f##_##v)
#define NVDEF_SET(A...) NVDEF_SET_(X, ##A, NVDEF_SET_I, NVDEF_SET_N)(X, ##A)
#define NVDEF_SET_(X,_1,_2,_3,_4,_5,_6,IMPL,...) IMPL
#define NVDEF_SET_I(X,o,d,r,f,i,v) NVVAL_SET_X(o, d##_##r##_##f(i), d##_##r##_##f##_##v)
#define NVDEF_SET_N(X,o,d,r,f,  v) NVVAL_SET_X(o, d##_##r##_##f,    d##_##r##_##f##_##v)
#define NVDEF_TEST(A...) NVDEF_TEST_(X, ##A, NVDEF_TEST_I, NVDEF_TEST_N)(X, ##A)
#define NVDEF_TEST_(X,_1,_2,_3,_4,_5,_6,_7,IMPL,...) IMPL
#define NVDEF_TEST_I(X,o,d,r,f,i,cmp,v) NVVAL_TEST_X(o, d##_##r##_##f(i), cmp, d##_##r##_##f##_##v)
#define NVDEF_TEST_N(X,o,d,r,f,  cmp,v) NVVAL_TEST_X(o, d##_##r##_##f   , cmp, d##_##r##_##f##_##v)
#define NVVAL(A...) NVVAL_(X, ##A, NVVAL_I, NVVAL_N)(X, ##A)
#define NVVAL_(X,_1,_2,_3,_4,_5,IMPL,...) IMPL
#define NVVAL_GET(A...) NVVAL_GET_(X, ##A, NVVAL_GET_I, NVVAL_GET_N)(X, ##A)
#define NVVAL_GET_(X,_1,_2,_3,_4,_5,IMPL,...) IMPL
#define NVVAL_GET_I(X,o,d,r,f,i) NVVAL_GET_X(o, d##_##r##_##f(i))
#define NVVAL_GET_N(X,o,d,r,f  ) NVVAL_GET_X(o, d##_##r##_##f)
#define NVVAL_GET_X(o,drf) (((o) >> DRF_LO(drf)) & DRF_MASK(drf))
#define NVVAL_I(X,d,r,f,i,v) NVVAL_X(d##_##r##_##f(i), (v))
#define NVVAL_MW_GET(A...) NVVAL_MW_GET_(X, ##A, NVVAL_MW_GET_I, NVVAL_MW_GET_N)(X, ##A)
#define NVVAL_MW_GET_(X,_1,_2,_3,_4,_5,IMPL,...) IMPL
#define NVVAL_MW_GET_I(X,o,d,r,f,i) NVVAL_MW_GET_X((o), d##_##r##_##f(i))
#define NVVAL_MW_GET_N(X,o,d,r,f  ) NVVAL_MW_GET_X((o), d##_##r##_##f)
#define NVVAL_MW_GET_X(o,drf)                                                       \
	((DRF_MW_SPANS((o),drf) ?                                                   \
	  (DRF_HW_GET((o),drf) << DRF_LW_BITS((o),drf)) : 0) | DRF_LW_GET((o),drf))
#define NVVAL_MW_SET(A...) NVVAL_MW_SET_(X, ##A, NVVAL_MW_SET_I, NVVAL_MW_SET_N)(X, ##A)
#define NVVAL_MW_SET_(X,_1,_2,_3,_4,_5,_6,IMPL,...) IMPL
#define NVVAL_MW_SET_I(X,o,d,r,f,i,v) NVVAL_MW_SET_X((o), d##_##r##_##f(i), (v))
#define NVVAL_MW_SET_N(X,o,d,r,f,  v) NVVAL_MW_SET_X((o), d##_##r##_##f, (v))
#define NVVAL_MW_SET_X(o,drf,v) do {                                           \
	(o)[DRF_LW_IDX((o),drf)] = DRF_LW_SET((o),drf,(v));                    \
	if (DRF_MW_SPANS((o),drf))                                             \
		(o)[DRF_HW_IDX((o),drf)] = DRF_HW_SET((o),drf,(v));            \
} while(0)
#define NVVAL_N(X,d,r,f,  v) NVVAL_X(d##_##r##_##f, (v))
#define NVVAL_SET(A...) NVVAL_SET_(X, ##A, NVVAL_SET_I, NVVAL_SET_N)(X, ##A)
#define NVVAL_SET_(X,_1,_2,_3,_4,_5,_6,IMPL,...) IMPL
#define NVVAL_SET_I(X,o,d,r,f,i,v) NVVAL_SET_X(o, d##_##r##_##f(i), (v))
#define NVVAL_SET_N(X,o,d,r,f,  v) NVVAL_SET_X(o, d##_##r##_##f, (v))
#define NVVAL_SET_X(o,drf,v) (((o) & ~DRF_SMASK(drf)) | NVVAL_X(drf, (v)))
#define NVVAL_TEST(A...) NVVAL_TEST_(X, ##A, NVVAL_TEST_I, NVVAL_TEST_N)(X, ##A)
#define NVVAL_TEST_(X,_1,_2,_3,_4,_5,_6,_7,IMPL,...) IMPL
#define NVVAL_TEST_I(X,o,d,r,f,i,cmp,v) NVVAL_TEST_X(o, d##_##r##_##f(i), cmp, (v))
#define NVVAL_TEST_N(X,o,d,r,f,  cmp,v) NVVAL_TEST_X(o, d##_##r##_##f   , cmp, (v))
#define NVVAL_TEST_X(o,drf,cmp,drfv) (NVVAL_GET_X((o), drf) cmp drfv)
#define NVVAL_X(drf,v) (((v) & DRF_MASK(drf)) << DRF_LO(drf))

#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_4                                       0x00000004
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_4_DONE                                  0:0
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_4_DONE_FALSE                            0x00000000
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_4_DONE_TRUE                             0x00000001
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20                             0x00000014
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DP_A                        24:24
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DP_A_FALSE                  0x00000000
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DP_A_TRUE                   0x00000001
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DP_B                        25:25
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DP_B_FALSE                  0x00000000
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DP_B_TRUE                   0x00000001
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DP_INTERLACE                26:26
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DP_INTERLACE_FALSE          0x00000000
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DP_INTERLACE_TRUE           0x00000001
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DUAL_LVDS18                 2:2
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DUAL_LVDS18_FALSE           0x00000000
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DUAL_LVDS18_TRUE            0x00000001
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DUAL_LVDS24                 3:3
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DUAL_LVDS24_FALSE           0x00000000
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DUAL_LVDS24_TRUE            0x00000001
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DUAL_TMDS                   11:11
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DUAL_TMDS_FALSE             0x00000000
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_DUAL_TMDS_TRUE              0x00000001
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_R0                          7:4
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_R1                          10:10
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_R2                          12:12
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_R3                          15:14
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_R4                          19:17
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_R5                          23:20
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_R6                          31:27
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_SINGLE_LVDS18               0:0
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_SINGLE_LVDS18_FALSE         0x00000000
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_SINGLE_LVDS18_TRUE          0x00000001
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_SINGLE_LVDS24               1:1
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_SINGLE_LVDS24_FALSE         0x00000000
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_SINGLE_LVDS24_TRUE          0x00000001
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_SINGLE_TMDS_A               8:8
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_SINGLE_TMDS_A_FALSE         0x00000000
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_SINGLE_TMDS_A_TRUE          0x00000001
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_SINGLE_TMDS_B               9:9
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_SINGLE_TMDS_B_FALSE         0x00000000
#define NV907D_CORE_NOTIFIER_3_CAPABILITIES_CAP_SOR0_20_SINGLE_TMDS_B_TRUE          0x00000001
#define NV907D_DAC_SET_CONTROL(a)                                               (0x00000180 + (a)*0x00000020)
#define NV907D_DAC_SET_CONTROL_OWNER_MASK                                       3:0
#define NV907D_DAC_SET_CONTROL_OWNER_MASK_HEAD0                                 (0x00000001)
#define NV907D_DAC_SET_CONTROL_OWNER_MASK_HEAD1                                 (0x00000002)
#define NV907D_DAC_SET_CONTROL_OWNER_MASK_HEAD2                                 (0x00000004)
#define NV907D_DAC_SET_CONTROL_OWNER_MASK_HEAD3                                 (0x00000008)
#define NV907D_DAC_SET_CONTROL_OWNER_MASK_NONE                                  (0x00000000)
#define NV907D_DAC_SET_CONTROL_PROTOCOL                                         12:8
#define NV907D_DAC_SET_CONTROL_PROTOCOL_RGB_CRT                                 (0x00000000)
#define NV907D_DAC_SET_CONTROL_PROTOCOL_YUV_CRT                                 (0x00000013)
#define NV907D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS(a)                            (0x000004D0 + (a)*0x00000300)
#define NV907D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_PIXEL_DEPTH                   11:8
#define NV907D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_PIXEL_DEPTH_BPP_16            (0x00000001)
#define NV907D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_PIXEL_DEPTH_BPP_32            (0x00000003)
#define NV907D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_PIXEL_DEPTH_BPP_64            (0x00000005)
#define NV907D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_PIXEL_DEPTH_BPP_8             (0x00000000)
#define NV907D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_SUPER_SAMPLE                  13:12
#define NV907D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_SUPER_SAMPLE_X1_AA            (0x00000000)
#define NV907D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_SUPER_SAMPLE_X4_AA            (0x00000002)
#define NV907D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_USABLE                        0:0
#define NV907D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_USABLE_FALSE                  (0x00000000)
#define NV907D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_USABLE_TRUE                   (0x00000001)
#define NV907D_HEAD_SET_CONTEXT_DMAS_ISO(a)                                     (0x00000474 + (a)*0x00000300)
#define NV907D_HEAD_SET_CONTEXT_DMAS_ISO_HANDLE                                 31:0
#define NV907D_HEAD_SET_CONTEXT_DMA_CRC(a)                                      (0x00000438 + (a)*0x00000300)
#define NV907D_HEAD_SET_CONTEXT_DMA_CRC_HANDLE                                  31:0
#define NV907D_HEAD_SET_CONTEXT_DMA_CURSOR(a)                                   (0x0000048C + (a)*0x00000300)
#define NV907D_HEAD_SET_CONTEXT_DMA_CURSOR_HANDLE                               31:0
#define NV907D_HEAD_SET_CONTEXT_DMA_LUT(a)                                      (0x0000045C + (a)*0x00000300)
#define NV907D_HEAD_SET_CONTEXT_DMA_LUT_HANDLE                                  31:0
#define NV907D_HEAD_SET_CONTROL(a)                                              (0x00000408 + (a)*0x00000300)
#define NV907D_HEAD_SET_CONTROL_CURSOR(a)                                       (0x00000480 + (a)*0x00000300)
#define NV907D_HEAD_SET_CONTROL_CURSOR_COMPOSITION                              29:28
#define NV907D_HEAD_SET_CONTROL_CURSOR_COMPOSITION_ALPHA_BLEND                  (0x00000000)
#define NV907D_HEAD_SET_CONTROL_CURSOR_COMPOSITION_PREMULT_ALPHA_BLEND          (0x00000001)
#define NV907D_HEAD_SET_CONTROL_CURSOR_COMPOSITION_XOR                          (0x00000002)
#define NV907D_HEAD_SET_CONTROL_CURSOR_ENABLE                                   31:31
#define NV907D_HEAD_SET_CONTROL_CURSOR_ENABLE_DISABLE                           (0x00000000)
#define NV907D_HEAD_SET_CONTROL_CURSOR_ENABLE_ENABLE                            (0x00000001)
#define NV907D_HEAD_SET_CONTROL_CURSOR_FORMAT                                   25:24
#define NV907D_HEAD_SET_CONTROL_CURSOR_FORMAT_A1R5G5B5                          (0x00000000)
#define NV907D_HEAD_SET_CONTROL_CURSOR_FORMAT_A8R8G8B8                          (0x00000001)
#define NV907D_HEAD_SET_CONTROL_CURSOR_HOT_SPOT_X                               13:8
#define NV907D_HEAD_SET_CONTROL_CURSOR_HOT_SPOT_Y                               21:16
#define NV907D_HEAD_SET_CONTROL_CURSOR_SIZE                                     26:26
#define NV907D_HEAD_SET_CONTROL_CURSOR_SIZE_W32_H32                             (0x00000000)
#define NV907D_HEAD_SET_CONTROL_CURSOR_SIZE_W64_H64                             (0x00000001)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE(a)                              (0x00000404 + (a)*0x00000300)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_CRC_MODE                        1:0
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_CRC_MODE_ACTIVE_RASTER          (0x00000000)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_CRC_MODE_COMPLETE_RASTER        (0x00000001)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_CRC_MODE_NON_ACTIVE_RASTER      (0x00000002)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_HSYNC_POLARITY                  3:3
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_HSYNC_POLARITY_NEGATIVE_TRUE    (0x00000001)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_HSYNC_POLARITY_POSITIVE_TRUE    (0x00000000)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_PIXEL_DEPTH                     9:6
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_PIXEL_DEPTH_BPP_16_422          (0x00000001)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_PIXEL_DEPTH_BPP_18_444          (0x00000002)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_PIXEL_DEPTH_BPP_20_422          (0x00000003)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_PIXEL_DEPTH_BPP_24_422          (0x00000004)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_PIXEL_DEPTH_BPP_24_444          (0x00000005)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_PIXEL_DEPTH_BPP_30_444          (0x00000006)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_PIXEL_DEPTH_BPP_32_422          (0x00000007)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_PIXEL_DEPTH_BPP_36_444          (0x00000008)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_PIXEL_DEPTH_BPP_48_444          (0x00000009)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_PIXEL_DEPTH_DEFAULT             (0x00000000)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_VSYNC_POLARITY                  4:4
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_VSYNC_POLARITY_NEGATIVE_TRUE    (0x00000001)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_RESOURCE_VSYNC_POLARITY_POSITIVE_TRUE    (0x00000000)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER(a)                                (0x00000494 + (a)*0x00000300)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER_HORIZONTAL_TAPS                   4:3
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER_HORIZONTAL_TAPS_TAPS_1            (0x00000000)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER_HORIZONTAL_TAPS_TAPS_2            (0x00000001)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER_HORIZONTAL_TAPS_TAPS_8            (0x00000002)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER_HRESPONSE_BIAS                    23:16
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER_VERTICAL_TAPS                     2:0
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER_VERTICAL_TAPS_TAPS_1              (0x00000000)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER_VERTICAL_TAPS_TAPS_2              (0x00000001)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER_VERTICAL_TAPS_TAPS_3              (0x00000002)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER_VERTICAL_TAPS_TAPS_3_ADAPTIVE     (0x00000003)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER_VERTICAL_TAPS_TAPS_5              (0x00000004)
#define NV907D_HEAD_SET_CONTROL_OUTPUT_SCALER_VRESPONSE_BIAS                    31:24
#define NV907D_HEAD_SET_CONTROL_STRUCTURE                                       0:0
#define NV907D_HEAD_SET_CONTROL_STRUCTURE_INTERLACED                            (0x00000001)
#define NV907D_HEAD_SET_CONTROL_STRUCTURE_PROGRESSIVE                           (0x00000000)
#define NV907D_HEAD_SET_CRC_CONTROL(a)                                          (0x00000430 + (a)*0x00000300)
#define NV907D_HEAD_SET_CRC_CONTROL_CONTROLLING_CHANNEL                         1:0
#define NV907D_HEAD_SET_CRC_CONTROL_CONTROLLING_CHANNEL_BASE                    (0x00000001)
#define NV907D_HEAD_SET_CRC_CONTROL_CONTROLLING_CHANNEL_CORE                    (0x00000000)
#define NV907D_HEAD_SET_CRC_CONTROL_CONTROLLING_CHANNEL_OVERLAY                 (0x00000002)
#define NV907D_HEAD_SET_CRC_CONTROL_CRC_DURING_SNOOZE                           5:5
#define NV907D_HEAD_SET_CRC_CONTROL_CRC_DURING_SNOOZE_DISABLE                   (0x00000000)
#define NV907D_HEAD_SET_CRC_CONTROL_CRC_DURING_SNOOZE_ENABLE                    (0x00000001)
#define NV907D_HEAD_SET_CRC_CONTROL_EXPECT_BUFFER_COLLAPSE                      2:2
#define NV907D_HEAD_SET_CRC_CONTROL_EXPECT_BUFFER_COLLAPSE_FALSE                (0x00000000)
#define NV907D_HEAD_SET_CRC_CONTROL_EXPECT_BUFFER_COLLAPSE_TRUE                 (0x00000001)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT                              19:8
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_DAC(i)                       (0x00000FF0 +(i))
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_DAC0                         (0x00000FF0)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_DAC1                         (0x00000FF1)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_DAC2                         (0x00000FF2)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_DAC3                         (0x00000FF3)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_DAC__SIZE_1                  4
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_NONE                         (0x00000FFF)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_PIOR(i)                      (0x000000FF +(i)*256)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_PIOR0                        (0x000000FF)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_PIOR1                        (0x000001FF)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_PIOR2                        (0x000002FF)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_PIOR3                        (0x000003FF)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_PIOR4                        (0x000004FF)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_PIOR5                        (0x000005FF)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_PIOR6                        (0x000006FF)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_PIOR7                        (0x000007FF)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_PIOR__SIZE_1                 8
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_RG(i)                        (0x00000FF8 +(i))
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_RG0                          (0x00000FF8)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_RG1                          (0x00000FF9)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_RG2                          (0x00000FFA)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_RG3                          (0x00000FFB)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_RG__SIZE_1                   4
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SF(i)                        (0x00000F8F +(i)*16)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SF0                          (0x00000F8F)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SF1                          (0x00000F9F)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SF2                          (0x00000FAF)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SF3                          (0x00000FBF)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SF__SIZE_1                   4
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SOR(i)                       (0x00000F0F +(i)*16)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SOR0                         (0x00000F0F)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SOR1                         (0x00000F1F)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SOR2                         (0x00000F2F)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SOR3                         (0x00000F3F)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SOR4                         (0x00000F4F)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SOR5                         (0x00000F5F)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SOR6                         (0x00000F6F)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SOR7                         (0x00000F7F)
#define NV907D_HEAD_SET_CRC_CONTROL_PRIMARY_OUTPUT_SOR__SIZE_1                  8
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT                            31:20
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_DAC(i)                     (0x00000FF0 +(i))
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_DAC0                       (0x00000FF0)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_DAC1                       (0x00000FF1)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_DAC2                       (0x00000FF2)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_DAC3                       (0x00000FF3)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_DAC__SIZE_1                4
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_NONE                       (0x00000FFF)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_PIOR(i)                    (0x000000FF +(i)*256)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_PIOR0                      (0x000000FF)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_PIOR1                      (0x000001FF)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_PIOR2                      (0x000002FF)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_PIOR3                      (0x000003FF)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_PIOR4                      (0x000004FF)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_PIOR5                      (0x000005FF)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_PIOR6                      (0x000006FF)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_PIOR7                      (0x000007FF)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_PIOR__SIZE_1               8
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_RG(i)                      (0x00000FF8 +(i))
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_RG0                        (0x00000FF8)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_RG1                        (0x00000FF9)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_RG2                        (0x00000FFA)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_RG3                        (0x00000FFB)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_RG__SIZE_1                 4
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SF(i)                      (0x00000F8F +(i)*16)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SF0                        (0x00000F8F)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SF1                        (0x00000F9F)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SF2                        (0x00000FAF)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SF3                        (0x00000FBF)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SF__SIZE_1                 4
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SOR(i)                     (0x00000F0F +(i)*16)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SOR0                       (0x00000F0F)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SOR1                       (0x00000F1F)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SOR2                       (0x00000F2F)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SOR3                       (0x00000F3F)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SOR4                       (0x00000F4F)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SOR5                       (0x00000F5F)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SOR6                       (0x00000F6F)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SOR7                       (0x00000F7F)
#define NV907D_HEAD_SET_CRC_CONTROL_SECONDARY_OUTPUT_SOR__SIZE_1                8
#define NV907D_HEAD_SET_CRC_CONTROL_TIMESTAMP_MODE                              3:3
#define NV907D_HEAD_SET_CRC_CONTROL_TIMESTAMP_MODE_FALSE                        (0x00000000)
#define NV907D_HEAD_SET_CRC_CONTROL_TIMESTAMP_MODE_TRUE                         (0x00000001)
#define NV907D_HEAD_SET_DEFAULT_BASE_COLOR(a)                                   (0x0000042C + (a)*0x00000300)
#define NV907D_HEAD_SET_DEFAULT_BASE_COLOR_BLUE                                 29:20
#define NV907D_HEAD_SET_DEFAULT_BASE_COLOR_GREEN                                19:10
#define NV907D_HEAD_SET_DEFAULT_BASE_COLOR_RED                                  9:0
#define NV907D_HEAD_SET_DITHER_CONTROL(a)                                       (0x00000490 + (a)*0x00000300)
#define NV907D_HEAD_SET_DITHER_CONTROL_BITS                                     2:1
#define NV907D_HEAD_SET_DITHER_CONTROL_BITS_DITHER_TO_10_BITS                   (0x00000002)
#define NV907D_HEAD_SET_DITHER_CONTROL_BITS_DITHER_TO_6_BITS                    (0x00000000)
#define NV907D_HEAD_SET_DITHER_CONTROL_BITS_DITHER_TO_8_BITS                    (0x00000001)
#define NV907D_HEAD_SET_DITHER_CONTROL_ENABLE                                   0:0
#define NV907D_HEAD_SET_DITHER_CONTROL_ENABLE_DISABLE                           (0x00000000)
#define NV907D_HEAD_SET_DITHER_CONTROL_ENABLE_ENABLE                            (0x00000001)
#define NV907D_HEAD_SET_DITHER_CONTROL_MODE                                     6:3
#define NV907D_HEAD_SET_DITHER_CONTROL_MODE_DYNAMIC_2X2                         (0x00000002)
#define NV907D_HEAD_SET_DITHER_CONTROL_MODE_DYNAMIC_ERR_ACC                     (0x00000000)
#define NV907D_HEAD_SET_DITHER_CONTROL_MODE_STATIC_2X2                          (0x00000003)
#define NV907D_HEAD_SET_DITHER_CONTROL_MODE_STATIC_ERR_ACC                      (0x00000001)
#define NV907D_HEAD_SET_DITHER_CONTROL_MODE_TEMPORAL                            (0x00000004)
#define NV907D_HEAD_SET_DITHER_CONTROL_PHASE                                    8:7
#define NV907D_HEAD_SET_OFFSET(a)                                               (0x00000460 + (a)*0x00000300)
#define NV907D_HEAD_SET_OFFSET_CURSOR(a)                                        (0x00000484 + (a)*0x00000300)
#define NV907D_HEAD_SET_OFFSET_CURSOR_ORIGIN                                    31:0
#define NV907D_HEAD_SET_OFFSET_ORIGIN                                           31:0
#define NV907D_HEAD_SET_OUTPUT_LUT_HI(a)                                        (0x0000044C + (a)*0x00000300)
#define NV907D_HEAD_SET_OUTPUT_LUT_HI_ORIGIN                                    31:0
#define NV907D_HEAD_SET_OUTPUT_LUT_LO(a)                                        (0x00000448 + (a)*0x00000300)
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_ENABLE                                    31:31
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_ENABLE_DISABLE                            (0x00000000)
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_ENABLE_ENABLE                             (0x00000001)
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_MODE                                      27:24
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_MODE_HIRES                                (0x00000001)
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_MODE_INDEX_1025_UNITY_RANGE               (0x00000003)
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_MODE_INTERPOLATE_1025_UNITY_RANGE         (0x00000004)
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_MODE_INTERPOLATE_1025_XRBIAS_RANGE        (0x00000005)
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_MODE_INTERPOLATE_1025_XVYCC_RANGE         (0x00000006)
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_MODE_INTERPOLATE_257_LEGACY_RANGE         (0x00000008)
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_MODE_INTERPOLATE_257_UNITY_RANGE          (0x00000007)
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_MODE_LORES                                (0x00000000)
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_NEVER_YIELD_TO_BASE                       20:20
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_NEVER_YIELD_TO_BASE_DISABLE               (0x00000000)
#define NV907D_HEAD_SET_OUTPUT_LUT_LO_NEVER_YIELD_TO_BASE_ENABLE                (0x00000001)
#define NV907D_HEAD_SET_OVERLAY_USAGE_BOUNDS(a)                                 (0x000004D4 + (a)*0x00000300)
#define NV907D_HEAD_SET_OVERLAY_USAGE_BOUNDS_PIXEL_DEPTH                        11:8
#define NV907D_HEAD_SET_OVERLAY_USAGE_BOUNDS_PIXEL_DEPTH_BPP_16                 (0x00000001)
#define NV907D_HEAD_SET_OVERLAY_USAGE_BOUNDS_PIXEL_DEPTH_BPP_32                 (0x00000003)
#define NV907D_HEAD_SET_OVERLAY_USAGE_BOUNDS_PIXEL_DEPTH_BPP_64                 (0x00000005)
#define NV907D_HEAD_SET_OVERLAY_USAGE_BOUNDS_USABLE                             0:0
#define NV907D_HEAD_SET_OVERLAY_USAGE_BOUNDS_USABLE_FALSE                       (0x00000000)
#define NV907D_HEAD_SET_OVERLAY_USAGE_BOUNDS_USABLE_TRUE                        (0x00000001)
#define NV907D_HEAD_SET_OVERSCAN_COLOR(a)                                       (0x00000410 + (a)*0x00000300)
#define NV907D_HEAD_SET_OVERSCAN_COLOR_BLU                                      29:20
#define NV907D_HEAD_SET_OVERSCAN_COLOR_GRN                                      19:10
#define NV907D_HEAD_SET_OVERSCAN_COLOR_RED                                      9:0
#define NV907D_HEAD_SET_PARAMS(a)                                               (0x00000470 + (a)*0x00000300)
#define NV907D_HEAD_SET_PARAMS_FORMAT                                           15:8
#define NV907D_HEAD_SET_PARAMS_FORMAT_A1R5G5B5                                  (0x000000E9)
#define NV907D_HEAD_SET_PARAMS_FORMAT_A2B10G10R10                               (0x000000D1)
#define NV907D_HEAD_SET_PARAMS_FORMAT_A8B8G8R8                                  (0x000000D5)
#define NV907D_HEAD_SET_PARAMS_FORMAT_A8R8G8B8                                  (0x000000CF)
#define NV907D_HEAD_SET_PARAMS_FORMAT_I8                                        (0x0000001E)
#define NV907D_HEAD_SET_PARAMS_FORMAT_R16_G16_B16_A16                           (0x000000C6)
#define NV907D_HEAD_SET_PARAMS_FORMAT_R16_G16_B16_A16_NVBIAS                    (0x00000023)
#define NV907D_HEAD_SET_PARAMS_FORMAT_R5G6B5                                    (0x000000E8)
#define NV907D_HEAD_SET_PARAMS_FORMAT_RF16_GF16_BF16_AF16                       (0x000000CA)
#define NV907D_HEAD_SET_PARAMS_FORMAT_VOID16                                    (0x0000001F)
#define NV907D_HEAD_SET_PARAMS_FORMAT_VOID32                                    (0x0000002E)
#define NV907D_HEAD_SET_PARAMS_FORMAT_X2BL10GL10RL10_XRBIAS                     (0x00000022)
#define NV907D_HEAD_SET_PARAMS_GAMMA                                            2:2
#define NV907D_HEAD_SET_PARAMS_GAMMA_LINEAR                                     (0x00000000)
#define NV907D_HEAD_SET_PARAMS_GAMMA_SRGB                                       (0x00000001)
#define NV907D_HEAD_SET_PARAMS_SUPER_SAMPLE                                     1:0
#define NV907D_HEAD_SET_PARAMS_SUPER_SAMPLE_X1_AA                               (0x00000000)
#define NV907D_HEAD_SET_PARAMS_SUPER_SAMPLE_X4_AA                               (0x00000002)
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION(a)                            (0x00000454 + (a)*0x00000300)
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_ENABLE_HOPPING                25:25
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_ENABLE_HOPPING_FALSE          (0x00000000)
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_ENABLE_HOPPING_TRUE           (0x00000001)
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_HOPPING_MODE                  26:26
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_HOPPING_MODE_HBLANK           (0x00000001)
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_HOPPING_MODE_VBLANK           (0x00000000)
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_MODE                          21:20
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_MODE_CLK_25                   (0x00000000)
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_MODE_CLK_28                   (0x00000001)
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_MODE_CLK_CUSTOM               (0x00000002)
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_NOT_DRIVER                    24:24
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_NOT_DRIVER_FALSE              (0x00000000)
#define NV907D_HEAD_SET_PIXEL_CLOCK_CONFIGURATION_NOT_DRIVER_TRUE               (0x00000001)
#define NV907D_HEAD_SET_PIXEL_CLOCK_FREQUENCY(a)                                (0x00000450 + (a)*0x00000300)
#define NV907D_HEAD_SET_PIXEL_CLOCK_FREQUENCY_ADJ1000DIV1001                    31:31
#define NV907D_HEAD_SET_PIXEL_CLOCK_FREQUENCY_ADJ1000DIV1001_FALSE              (0x00000000)
#define NV907D_HEAD_SET_PIXEL_CLOCK_FREQUENCY_ADJ1000DIV1001_TRUE               (0x00000001)
#define NV907D_HEAD_SET_PIXEL_CLOCK_FREQUENCY_HERTZ                             30:0
#define NV907D_HEAD_SET_PIXEL_CLOCK_FREQUENCY_MAX(a)                            (0x00000458 + (a)*0x00000300)
#define NV907D_HEAD_SET_PIXEL_CLOCK_FREQUENCY_MAX_ADJ1000DIV1001                31:31
#define NV907D_HEAD_SET_PIXEL_CLOCK_FREQUENCY_MAX_ADJ1000DIV1001_FALSE          (0x00000000)
#define NV907D_HEAD_SET_PIXEL_CLOCK_FREQUENCY_MAX_ADJ1000DIV1001_TRUE           (0x00000001)
#define NV907D_HEAD_SET_PIXEL_CLOCK_FREQUENCY_MAX_HERTZ                         30:0
#define NV907D_HEAD_SET_PROCAMP(a)                                              (0x00000498 + (a)*0x00000300)
#define NV907D_HEAD_SET_PROCAMP_CHROMA_LPF                                      2:2
#define NV907D_HEAD_SET_PROCAMP_CHROMA_LPF_AUTO                                 (0x00000000)
#define NV907D_HEAD_SET_PROCAMP_CHROMA_LPF_ON                                   (0x00000001)
#define NV907D_HEAD_SET_PROCAMP_COLOR_SPACE                                     1:0
#define NV907D_HEAD_SET_PROCAMP_COLOR_SPACE_RGB                                 (0x00000000)
#define NV907D_HEAD_SET_PROCAMP_COLOR_SPACE_YUV_601                             (0x00000001)
#define NV907D_HEAD_SET_PROCAMP_COLOR_SPACE_YUV_709                             (0x00000002)
#define NV907D_HEAD_SET_PROCAMP_DYNAMIC_RANGE                                   5:5
#define NV907D_HEAD_SET_PROCAMP_DYNAMIC_RANGE_CEA                               (0x00000001)
#define NV907D_HEAD_SET_PROCAMP_DYNAMIC_RANGE_VESA                              (0x00000000)
#define NV907D_HEAD_SET_PROCAMP_RANGE_COMPRESSION                               6:6
#define NV907D_HEAD_SET_PROCAMP_RANGE_COMPRESSION_DISABLE                       (0x00000000)
#define NV907D_HEAD_SET_PROCAMP_RANGE_COMPRESSION_ENABLE                        (0x00000001)
#define NV907D_HEAD_SET_PROCAMP_SAT_COS                                         19:8
#define NV907D_HEAD_SET_PROCAMP_SAT_SINE                                        31:20
#define NV907D_HEAD_SET_RASTER_BLANK_END(a)                                     (0x0000041C + (a)*0x00000300)
#define NV907D_HEAD_SET_RASTER_BLANK_END_X                                      14:0
#define NV907D_HEAD_SET_RASTER_BLANK_END_Y                                      30:16
#define NV907D_HEAD_SET_RASTER_BLANK_START(a)                                   (0x00000420 + (a)*0x00000300)
#define NV907D_HEAD_SET_RASTER_BLANK_START_X                                    14:0
#define NV907D_HEAD_SET_RASTER_BLANK_START_Y                                    30:16
#define NV907D_HEAD_SET_RASTER_SIZE(a)                                          (0x00000414 + (a)*0x00000300)
#define NV907D_HEAD_SET_RASTER_SIZE_HEIGHT                                      30:16
#define NV907D_HEAD_SET_RASTER_SIZE_WIDTH                                       14:0
#define NV907D_HEAD_SET_RASTER_SYNC_END(a)                                      (0x00000418 + (a)*0x00000300)
#define NV907D_HEAD_SET_RASTER_SYNC_END_X                                       14:0
#define NV907D_HEAD_SET_RASTER_SYNC_END_Y                                       30:16
#define NV907D_HEAD_SET_RASTER_VERT_BLANK2(a)                                   (0x00000424 + (a)*0x00000300)
#define NV907D_HEAD_SET_RASTER_VERT_BLANK2_YEND                                 30:16
#define NV907D_HEAD_SET_RASTER_VERT_BLANK2_YSTART                               14:0
#define NV907D_HEAD_SET_SIZE(a)                                                 (0x00000468 + (a)*0x00000300)
#define NV907D_HEAD_SET_SIZE_HEIGHT                                             31:16
#define NV907D_HEAD_SET_SIZE_WIDTH                                              15:0
#define NV907D_HEAD_SET_STORAGE(a)                                              (0x0000046C + (a)*0x00000300)
#define NV907D_HEAD_SET_STORAGE_BLOCK_HEIGHT                                    3:0
#define NV907D_HEAD_SET_STORAGE_BLOCK_HEIGHT_EIGHT_GOBS                         (0x00000003)
#define NV907D_HEAD_SET_STORAGE_BLOCK_HEIGHT_FOUR_GOBS                          (0x00000002)
#define NV907D_HEAD_SET_STORAGE_BLOCK_HEIGHT_ONE_GOB                            (0x00000000)
#define NV907D_HEAD_SET_STORAGE_BLOCK_HEIGHT_SIXTEEN_GOBS                       (0x00000004)
#define NV907D_HEAD_SET_STORAGE_BLOCK_HEIGHT_THIRTYTWO_GOBS                     (0x00000005)
#define NV907D_HEAD_SET_STORAGE_BLOCK_HEIGHT_TWO_GOBS                           (0x00000001)
#define NV907D_HEAD_SET_STORAGE_MEMORY_LAYOUT                                   24:24
#define NV907D_HEAD_SET_STORAGE_MEMORY_LAYOUT_BLOCKLINEAR                       (0x00000000)
#define NV907D_HEAD_SET_STORAGE_MEMORY_LAYOUT_PITCH                             (0x00000001)
#define NV907D_HEAD_SET_STORAGE_PITCH                                           20:8
#define NV907D_HEAD_SET_VIEWPORT_POINT_IN(a)                                    (0x000004B0 + (a)*0x00000300)
#define NV907D_HEAD_SET_VIEWPORT_POINT_IN_X                                     14:0
#define NV907D_HEAD_SET_VIEWPORT_POINT_IN_Y                                     30:16
#define NV907D_HEAD_SET_VIEWPORT_SIZE_IN(a)                                     (0x000004B8 + (a)*0x00000300)
#define NV907D_HEAD_SET_VIEWPORT_SIZE_IN_HEIGHT                                 30:16
#define NV907D_HEAD_SET_VIEWPORT_SIZE_IN_WIDTH                                  14:0
#define NV907D_HEAD_SET_VIEWPORT_SIZE_OUT(a)                                    (0x000004C0 + (a)*0x00000300)
#define NV907D_HEAD_SET_VIEWPORT_SIZE_OUT_HEIGHT                                30:16
#define NV907D_HEAD_SET_VIEWPORT_SIZE_OUT_MAX(a)                                (0x000004C8 + (a)*0x00000300)
#define NV907D_HEAD_SET_VIEWPORT_SIZE_OUT_MAX_HEIGHT                            30:16
#define NV907D_HEAD_SET_VIEWPORT_SIZE_OUT_MAX_WIDTH                             14:0
#define NV907D_HEAD_SET_VIEWPORT_SIZE_OUT_MIN(a)                                (0x000004C4 + (a)*0x00000300)
#define NV907D_HEAD_SET_VIEWPORT_SIZE_OUT_MIN_HEIGHT                            30:16
#define NV907D_HEAD_SET_VIEWPORT_SIZE_OUT_MIN_WIDTH                             14:0
#define NV907D_HEAD_SET_VIEWPORT_SIZE_OUT_WIDTH                                 14:0
#define NV907D_SOR_SET_CONTROL(a)                                               (0x00000200 + (a)*0x00000020)
#define NV907D_SOR_SET_CONTROL_DE_SYNC_POLARITY                                 14:14
#define NV907D_SOR_SET_CONTROL_DE_SYNC_POLARITY_NEGATIVE_TRUE                   (0x00000001)
#define NV907D_SOR_SET_CONTROL_DE_SYNC_POLARITY_POSITIVE_TRUE                   (0x00000000)
#define NV907D_SOR_SET_CONTROL_OWNER_MASK                                       3:0
#define NV907D_SOR_SET_CONTROL_OWNER_MASK_HEAD0                                 (0x00000001)
#define NV907D_SOR_SET_CONTROL_OWNER_MASK_HEAD1                                 (0x00000002)
#define NV907D_SOR_SET_CONTROL_OWNER_MASK_HEAD2                                 (0x00000004)
#define NV907D_SOR_SET_CONTROL_OWNER_MASK_HEAD3                                 (0x00000008)
#define NV907D_SOR_SET_CONTROL_OWNER_MASK_NONE                                  (0x00000000)
#define NV907D_SOR_SET_CONTROL_PIXEL_REPLICATE_MODE                             21:20
#define NV907D_SOR_SET_CONTROL_PIXEL_REPLICATE_MODE_OFF                         (0x00000000)
#define NV907D_SOR_SET_CONTROL_PIXEL_REPLICATE_MODE_X2                          (0x00000001)
#define NV907D_SOR_SET_CONTROL_PIXEL_REPLICATE_MODE_X4                          (0x00000002)
#define NV907D_SOR_SET_CONTROL_PROTOCOL                                         11:8
#define NV907D_SOR_SET_CONTROL_PROTOCOL_CUSTOM                                  (0x0000000F)
#define NV907D_SOR_SET_CONTROL_PROTOCOL_DP_A                                    (0x00000008)
#define NV907D_SOR_SET_CONTROL_PROTOCOL_DP_B                                    (0x00000009)
#define NV907D_SOR_SET_CONTROL_PROTOCOL_DUAL_TMDS                               (0x00000005)
#define NV907D_SOR_SET_CONTROL_PROTOCOL_LVDS_CUSTOM                             (0x00000000)
#define NV907D_SOR_SET_CONTROL_PROTOCOL_SINGLE_TMDS_A                           (0x00000001)
#define NV907D_SOR_SET_CONTROL_PROTOCOL_SINGLE_TMDS_B                           (0x00000002)

#define NV507D_DAC_SET_CONTROL(a)                                               (0x00000400 + (a)*0x00000080)
#define NV507D_DAC_SET_CONTROL_INVALIDATE_FIRST_FIELD                           14:14
#define NV507D_DAC_SET_CONTROL_INVALIDATE_FIRST_FIELD_FALSE                     (0x00000000)
#define NV507D_DAC_SET_CONTROL_INVALIDATE_FIRST_FIELD_TRUE                      (0x00000001)
#define NV507D_DAC_SET_CONTROL_OWNER                                            3:0
#define NV507D_DAC_SET_CONTROL_OWNER_HEAD0                                      (0x00000001)
#define NV507D_DAC_SET_CONTROL_OWNER_HEAD1                                      (0x00000002)
#define NV507D_DAC_SET_CONTROL_OWNER_NONE                                       (0x00000000)
#define NV507D_DAC_SET_CONTROL_PROTOCOL                                         13:8
#define NV507D_DAC_SET_CONTROL_PROTOCOL_COMP_1080I_50                           (0x00000011)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_COMP_1080I_60                           (0x00000012)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_COMP_480P_60                            (0x0000000D)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_COMP_576P_50                            (0x0000000E)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_COMP_720P_50                            (0x0000000F)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_COMP_720P_60                            (0x00000010)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_COMP_NTSC_J                             (0x00000008)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_COMP_NTSC_M                             (0x00000007)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_COMP_PAL_BDGHI                          (0x00000009)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_COMP_PAL_CN                             (0x0000000C)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_COMP_PAL_M                              (0x0000000A)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_COMP_PAL_N                              (0x0000000B)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_CPST_NTSC_J                             (0x00000002)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_CPST_NTSC_M                             (0x00000001)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_CPST_PAL_BDGHI                          (0x00000003)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_CPST_PAL_CN                             (0x00000006)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_CPST_PAL_M                              (0x00000004)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_CPST_PAL_N                              (0x00000005)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_CUSTOM                                  (0x0000003F)
#define NV507D_DAC_SET_CONTROL_PROTOCOL_RGB_CRT                                 (0x00000000)
#define NV507D_DAC_SET_CONTROL_SUB_OWNER                                        5:4
#define NV507D_DAC_SET_CONTROL_SUB_OWNER_BOTH                                   (0x00000003)
#define NV507D_DAC_SET_CONTROL_SUB_OWNER_NONE                                   (0x00000000)
#define NV507D_DAC_SET_CONTROL_SUB_OWNER_SUBHEAD0                               (0x00000001)
#define NV507D_DAC_SET_CONTROL_SUB_OWNER_SUBHEAD1                               (0x00000002)
#define NV507D_DAC_SET_POLARITY(a)                                              (0x00000404 + (a)*0x00000080)
#define NV507D_DAC_SET_POLARITY_HSYNC                                           0:0
#define NV507D_DAC_SET_POLARITY_HSYNC_NEGATIVE_TRUE                             (0x00000001)
#define NV507D_DAC_SET_POLARITY_HSYNC_POSITIVE_TRUE                             (0x00000000)
#define NV507D_DAC_SET_POLARITY_RESERVED                                        31:2
#define NV507D_DAC_SET_POLARITY_VSYNC                                           1:1
#define NV507D_DAC_SET_POLARITY_VSYNC_NEGATIVE_TRUE                             (0x00000001)
#define NV507D_DAC_SET_POLARITY_VSYNC_POSITIVE_TRUE                             (0x00000000)
#define NV507D_GET_CAPABILITIES                                                 (0x0000008C)
#define NV507D_GET_CAPABILITIES_DUMMY                                           31:0
#define NV507D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS(a)                            (0x00000900 + (a)*0x00000400)
#define NV507D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_PIXEL_DEPTH                   11:8
#define NV507D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_PIXEL_DEPTH_BPP_16            (0x00000001)
#define NV507D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_PIXEL_DEPTH_BPP_32            (0x00000003)
#define NV507D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_PIXEL_DEPTH_BPP_64            (0x00000005)
#define NV507D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_PIXEL_DEPTH_BPP_8             (0x00000000)
#define NV507D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_SUPER_SAMPLE                  13:12
#define NV507D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_SUPER_SAMPLE_X1_AA            (0x00000000)
#define NV507D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_SUPER_SAMPLE_X4_AA            (0x00000002)
#define NV507D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_USABLE                        0:0
#define NV507D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_USABLE_FALSE                  (0x00000000)
#define NV507D_HEAD_SET_BASE_CHANNEL_USAGE_BOUNDS_USABLE_TRUE                   (0x00000001)
#define NV507D_HEAD_SET_BASE_LUT_HI(a)                                          (0x00000844 + (a)*0x00000400)
#define NV507D_HEAD_SET_BASE_LUT_HI_ORIGIN                                      31:0
#define NV507D_HEAD_SET_BASE_LUT_LO(a)                                          (0x00000840 + (a)*0x00000400)
#define NV507D_HEAD_SET_BASE_LUT_LO_ENABLE                                      31:31
#define NV507D_HEAD_SET_BASE_LUT_LO_ENABLE_DISABLE                              (0x00000000)
#define NV507D_HEAD_SET_BASE_LUT_LO_ENABLE_ENABLE                               (0x00000001)
#define NV507D_HEAD_SET_BASE_LUT_LO_MODE                                        30:30
#define NV507D_HEAD_SET_BASE_LUT_LO_MODE_HIRES                                  (0x00000001)
#define NV507D_HEAD_SET_BASE_LUT_LO_MODE_LORES                                  (0x00000000)
#define NV507D_HEAD_SET_BASE_LUT_LO_ORIGIN                                      7:2
#define NV507D_HEAD_SET_CONTEXT_DMA_ISO(a)                                      (0x00000874 + (a)*0x00000400)
#define NV507D_HEAD_SET_CONTEXT_DMA_ISO_HANDLE                                  31:0
#define NV507D_HEAD_SET_CONTROL(a)                                              (0x00000808 + (a)*0x00000400)
#define NV507D_HEAD_SET_CONTROL_CURSOR(a)                                       (0x00000880 + (a)*0x00000400)
#define NV507D_HEAD_SET_CONTROL_CURSOR_COMPOSITION                              29:28
#define NV507D_HEAD_SET_CONTROL_CURSOR_COMPOSITION_ALPHA_BLEND                  (0x00000000)
#define NV507D_HEAD_SET_CONTROL_CURSOR_COMPOSITION_PREMULT_ALPHA_BLEND          (0x00000001)
#define NV507D_HEAD_SET_CONTROL_CURSOR_COMPOSITION_XOR                          (0x00000002)
#define NV507D_HEAD_SET_CONTROL_CURSOR_ENABLE                                   31:31
#define NV507D_HEAD_SET_CONTROL_CURSOR_ENABLE_DISABLE                           (0x00000000)
#define NV507D_HEAD_SET_CONTROL_CURSOR_ENABLE_ENABLE                            (0x00000001)
#define NV507D_HEAD_SET_CONTROL_CURSOR_FORMAT                                   25:24
#define NV507D_HEAD_SET_CONTROL_CURSOR_FORMAT_A1R5G5B5                          (0x00000000)
#define NV507D_HEAD_SET_CONTROL_CURSOR_FORMAT_A8R8G8B8                          (0x00000001)
#define NV507D_HEAD_SET_CONTROL_CURSOR_HOT_SPOT_X                               13:8
#define NV507D_HEAD_SET_CONTROL_CURSOR_HOT_SPOT_Y                               21:16
#define NV507D_HEAD_SET_CONTROL_CURSOR_SIZE                                     26:26
#define NV507D_HEAD_SET_CONTROL_CURSOR_SIZE_W32_H32                             (0x00000000)
#define NV507D_HEAD_SET_CONTROL_CURSOR_SIZE_W64_H64                             (0x00000001)
#define NV507D_HEAD_SET_CONTROL_CURSOR_SUB_OWNER                                5:4
#define NV507D_HEAD_SET_CONTROL_CURSOR_SUB_OWNER_BOTH                           (0x00000003)
#define NV507D_HEAD_SET_CONTROL_CURSOR_SUB_OWNER_NONE                           (0x00000000)
#define NV507D_HEAD_SET_CONTROL_CURSOR_SUB_OWNER_SUBHEAD0                       (0x00000001)
#define NV507D_HEAD_SET_CONTROL_CURSOR_SUB_OWNER_SUBHEAD1                       (0x00000002)
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER(a)                                (0x000008A4 + (a)*0x00000400)
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER_HORIZONTAL_TAPS                   4:3
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER_HORIZONTAL_TAPS_TAPS_1            (0x00000000)
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER_HORIZONTAL_TAPS_TAPS_2            (0x00000001)
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER_HORIZONTAL_TAPS_TAPS_8            (0x00000002)
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER_HRESPONSE_BIAS                    23:16
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER_VERTICAL_TAPS                     2:0
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER_VERTICAL_TAPS_TAPS_1              (0x00000000)
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER_VERTICAL_TAPS_TAPS_2              (0x00000001)
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER_VERTICAL_TAPS_TAPS_3              (0x00000002)
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER_VERTICAL_TAPS_TAPS_3_ADAPTIVE     (0x00000003)
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER_VERTICAL_TAPS_TAPS_5              (0x00000004)
#define NV507D_HEAD_SET_CONTROL_OUTPUT_SCALER_VRESPONSE_BIAS                    31:24
#define NV507D_HEAD_SET_CONTROL_STRUCTURE                                       2:1
#define NV507D_HEAD_SET_CONTROL_STRUCTURE_INTERLACED                            (0x00000001)
#define NV507D_HEAD_SET_CONTROL_STRUCTURE_PROGRESSIVE                           (0x00000000)
#define NV507D_HEAD_SET_DEFAULT_BASE_COLOR(a)                                   (0x0000082C + (a)*0x00000400)
#define NV507D_HEAD_SET_DEFAULT_BASE_COLOR_BLUE                                 29:20
#define NV507D_HEAD_SET_DEFAULT_BASE_COLOR_GREEN                                19:10
#define NV507D_HEAD_SET_DEFAULT_BASE_COLOR_RED                                  9:0
#define NV507D_HEAD_SET_DITHER_CONTROL(a)                                       (0x000008A0 + (a)*0x00000400)
#define NV507D_HEAD_SET_DITHER_CONTROL_BITS                                     2:1
#define NV507D_HEAD_SET_DITHER_CONTROL_BITS_DITHER_TO_6_BITS                    (0x00000000)
#define NV507D_HEAD_SET_DITHER_CONTROL_BITS_DITHER_TO_8_BITS                    (0x00000001)
#define NV507D_HEAD_SET_DITHER_CONTROL_ENABLE                                   0:0
#define NV507D_HEAD_SET_DITHER_CONTROL_ENABLE_DISABLE                           (0x00000000)
#define NV507D_HEAD_SET_DITHER_CONTROL_ENABLE_ENABLE                            (0x00000001)
#define NV507D_HEAD_SET_DITHER_CONTROL_MODE                                     6:3
#define NV507D_HEAD_SET_DITHER_CONTROL_MODE_DYNAMIC_2X2                         (0x00000002)
#define NV507D_HEAD_SET_DITHER_CONTROL_MODE_DYNAMIC_ERR_ACC                     (0x00000000)
#define NV507D_HEAD_SET_DITHER_CONTROL_MODE_STATIC_2X2                          (0x00000003)
#define NV507D_HEAD_SET_DITHER_CONTROL_MODE_STATIC_ERR_ACC                      (0x00000001)
#define NV507D_HEAD_SET_DITHER_CONTROL_PHASE                                    8:7
#define NV507D_HEAD_SET_OFFSET(a,b)                                             (0x00000860 + (a)*0x00000400 + (b)*0x00000004)
#define NV507D_HEAD_SET_OFFSET_CURSOR(a)                                        (0x00000884 + (a)*0x00000400)
#define NV507D_HEAD_SET_OFFSET_CURSOR_ORIGIN                                    31:0
#define NV507D_HEAD_SET_OFFSET_ORIGIN                                           31:0
#define NV507D_HEAD_SET_OVERLAY_USAGE_BOUNDS(a)                                 (0x00000904 + (a)*0x00000400)
#define NV507D_HEAD_SET_OVERLAY_USAGE_BOUNDS_PIXEL_DEPTH                        11:8
#define NV507D_HEAD_SET_OVERLAY_USAGE_BOUNDS_PIXEL_DEPTH_BPP_16                 (0x00000001)
#define NV507D_HEAD_SET_OVERLAY_USAGE_BOUNDS_PIXEL_DEPTH_BPP_32                 (0x00000003)
#define NV507D_HEAD_SET_OVERLAY_USAGE_BOUNDS_USABLE                             0:0
#define NV507D_HEAD_SET_OVERLAY_USAGE_BOUNDS_USABLE_FALSE                       (0x00000000)
#define NV507D_HEAD_SET_OVERLAY_USAGE_BOUNDS_USABLE_TRUE                        (0x00000001)
#define NV507D_HEAD_SET_OVERSCAN_COLOR(a)                                       (0x00000810 + (a)*0x00000400)
#define NV507D_HEAD_SET_OVERSCAN_COLOR_BLU                                      29:20
#define NV507D_HEAD_SET_OVERSCAN_COLOR_GRN                                      19:10
#define NV507D_HEAD_SET_OVERSCAN_COLOR_RED                                      9:0
#define NV507D_HEAD_SET_PARAMS(a)                                               (0x00000870 + (a)*0x00000400)
#define NV507D_HEAD_SET_PARAMS_FORMAT                                           15:8
#define NV507D_HEAD_SET_PARAMS_FORMAT_A1R5G5B5                                  (0x000000E9)
#define NV507D_HEAD_SET_PARAMS_FORMAT_A2B10G10R10                               (0x000000D1)
#define NV507D_HEAD_SET_PARAMS_FORMAT_A8B8G8R8                                  (0x000000D5)
#define NV507D_HEAD_SET_PARAMS_FORMAT_A8R8G8B8                                  (0x000000CF)
#define NV507D_HEAD_SET_PARAMS_FORMAT_I8                                        (0x0000001E)
#define NV507D_HEAD_SET_PARAMS_FORMAT_R5G6B5                                    (0x000000E8)
#define NV507D_HEAD_SET_PARAMS_FORMAT_RF16_GF16_BF16_AF16                       (0x000000CA)
#define NV507D_HEAD_SET_PARAMS_FORMAT_VOID16                                    (0x0000001F)
#define NV507D_HEAD_SET_PARAMS_FORMAT_VOID32                                    (0x0000002E)
#define NV507D_HEAD_SET_PARAMS_KIND                                             22:16
#define NV507D_HEAD_SET_PARAMS_KIND_FROM_PTE                                    (0x0000007F)
#define NV507D_HEAD_SET_PARAMS_KIND_KIND_C128_MS4                               (0x0000007E)
#define NV507D_HEAD_SET_PARAMS_KIND_KIND_C32_MS4                                (0x00000078)
#define NV507D_HEAD_SET_PARAMS_KIND_KIND_C32_MS4_BANKSWIZ                       (0x0000007A)
#define NV507D_HEAD_SET_PARAMS_KIND_KIND_C32_MS8                                (0x00000079)
#define NV507D_HEAD_SET_PARAMS_KIND_KIND_C32_MS8_BANKSWIZ                       (0x0000007B)
#define NV507D_HEAD_SET_PARAMS_KIND_KIND_C64_MS4                                (0x0000007C)
#define NV507D_HEAD_SET_PARAMS_KIND_KIND_C64_MS8                                (0x0000007D)
#define NV507D_HEAD_SET_PARAMS_KIND_KIND_GENERIC_16BX1                          (0x00000074)
#define NV507D_HEAD_SET_PARAMS_KIND_KIND_GENERIC_16BX1_BANKSWIZ                 (0x00000076)
#define NV507D_HEAD_SET_PARAMS_KIND_KIND_GENERIC_8BX2                           (0x00000070)
#define NV507D_HEAD_SET_PARAMS_KIND_KIND_GENERIC_8BX2_BANKSWIZ                  (0x00000072)
#define NV507D_HEAD_SET_PARAMS_KIND_KIND_PITCH                                  (0x00000000)
#define NV507D_HEAD_SET_PARAMS_PART_STRIDE                                      24:24
#define NV507D_HEAD_SET_PARAMS_PART_STRIDE_PARTSTRIDE_1024                      (0x00000001)
#define NV507D_HEAD_SET_PARAMS_PART_STRIDE_PARTSTRIDE_256                       (0x00000000)
#define NV507D_HEAD_SET_PIXEL_CLOCK(a)                                          (0x00000804 + (a)*0x00000400)
#define NV507D_HEAD_SET_PIXEL_CLOCK_ADJ1000DIV1001                              24:24
#define NV507D_HEAD_SET_PIXEL_CLOCK_ADJ1000DIV1001_FALSE                        (0x00000000)
#define NV507D_HEAD_SET_PIXEL_CLOCK_ADJ1000DIV1001_TRUE                         (0x00000001)
#define NV507D_HEAD_SET_PIXEL_CLOCK_FREQUENCY                                   21:0
#define NV507D_HEAD_SET_PIXEL_CLOCK_MODE                                        23:22
#define NV507D_HEAD_SET_PIXEL_CLOCK_MODE_CLK_25                                 (0x00000000)
#define NV507D_HEAD_SET_PIXEL_CLOCK_MODE_CLK_28                                 (0x00000001)
#define NV507D_HEAD_SET_PIXEL_CLOCK_MODE_CLK_CUSTOM                             (0x00000002)
#define NV507D_HEAD_SET_PIXEL_CLOCK_NOT_DRIVER                                  25:25
#define NV507D_HEAD_SET_PIXEL_CLOCK_NOT_DRIVER_FALSE                            (0x00000000)
#define NV507D_HEAD_SET_PIXEL_CLOCK_NOT_DRIVER_TRUE                             (0x00000001)
#define NV507D_HEAD_SET_PROCAMP(a)                                              (0x000008A8 + (a)*0x00000400)
#define NV507D_HEAD_SET_PROCAMP_CHROMA_LPF                                      2:2
#define NV507D_HEAD_SET_PROCAMP_CHROMA_LPF_AUTO                                 (0x00000000)
#define NV507D_HEAD_SET_PROCAMP_CHROMA_LPF_ON                                   (0x00000001)
#define NV507D_HEAD_SET_PROCAMP_COLOR_SPACE                                     1:0
#define NV507D_HEAD_SET_PROCAMP_COLOR_SPACE_RGB                                 (0x00000000)
#define NV507D_HEAD_SET_PROCAMP_COLOR_SPACE_YUV_601                             (0x00000001)
#define NV507D_HEAD_SET_PROCAMP_COLOR_SPACE_YUV_709                             (0x00000002)
#define NV507D_HEAD_SET_PROCAMP_SAT_COS                                         19:8
#define NV507D_HEAD_SET_PROCAMP_SAT_SINE                                        31:20
#define NV507D_HEAD_SET_PROCAMP_TRANSITION                                      4:3
#define NV507D_HEAD_SET_PROCAMP_TRANSITION_HARD                                 (0x00000000)
#define NV507D_HEAD_SET_PROCAMP_TRANSITION_NTSC                                 (0x00000001)
#define NV507D_HEAD_SET_PROCAMP_TRANSITION_PAL                                  (0x00000002)
#define NV507D_HEAD_SET_RASTER_BLANK_END(a)                                     (0x0000081C + (a)*0x00000400)
#define NV507D_HEAD_SET_RASTER_BLANK_END_X                                      14:0
#define NV507D_HEAD_SET_RASTER_BLANK_END_Y                                      30:16
#define NV507D_HEAD_SET_RASTER_BLANK_START(a)                                   (0x00000820 + (a)*0x00000400)
#define NV507D_HEAD_SET_RASTER_BLANK_START_X                                    14:0
#define NV507D_HEAD_SET_RASTER_BLANK_START_Y                                    30:16
#define NV507D_HEAD_SET_RASTER_SIZE(a)                                          (0x00000814 + (a)*0x00000400)
#define NV507D_HEAD_SET_RASTER_SIZE_HEIGHT                                      30:16
#define NV507D_HEAD_SET_RASTER_SIZE_WIDTH                                       14:0
#define NV507D_HEAD_SET_RASTER_SYNC_END(a)                                      (0x00000818 + (a)*0x00000400)
#define NV507D_HEAD_SET_RASTER_SYNC_END_X                                       14:0
#define NV507D_HEAD_SET_RASTER_SYNC_END_Y                                       30:16
#define NV507D_HEAD_SET_RASTER_VERT_BLANK2(a)                                   (0x00000824 + (a)*0x00000400)
#define NV507D_HEAD_SET_RASTER_VERT_BLANK2_YEND                                 30:16
#define NV507D_HEAD_SET_RASTER_VERT_BLANK2_YSTART                               14:0
#define NV507D_HEAD_SET_RASTER_VERT_BLANK_DMI(a)                                (0x00000828 + (a)*0x00000400)
#define NV507D_HEAD_SET_RASTER_VERT_BLANK_DMI_DURATION                          11:0
#define NV507D_HEAD_SET_SIZE(a)                                                 (0x00000868 + (a)*0x00000400)
#define NV507D_HEAD_SET_SIZE_HEIGHT                                             30:16
#define NV507D_HEAD_SET_SIZE_WIDTH                                              14:0
#define NV507D_HEAD_SET_STORAGE(a)                                              (0x0000086C + (a)*0x00000400)
#define NV507D_HEAD_SET_STORAGE_BLOCK_HEIGHT                                    3:0
#define NV507D_HEAD_SET_STORAGE_BLOCK_HEIGHT_EIGHT_GOBS                         (0x00000003)
#define NV507D_HEAD_SET_STORAGE_BLOCK_HEIGHT_FOUR_GOBS                          (0x00000002)
#define NV507D_HEAD_SET_STORAGE_BLOCK_HEIGHT_ONE_GOB                            (0x00000000)
#define NV507D_HEAD_SET_STORAGE_BLOCK_HEIGHT_SIXTEEN_GOBS                       (0x00000004)
#define NV507D_HEAD_SET_STORAGE_BLOCK_HEIGHT_THIRTYTWO_GOBS                     (0x00000005)
#define NV507D_HEAD_SET_STORAGE_BLOCK_HEIGHT_TWO_GOBS                           (0x00000001)
#define NV507D_HEAD_SET_STORAGE_MEMORY_LAYOUT                                   20:20
#define NV507D_HEAD_SET_STORAGE_MEMORY_LAYOUT_BLOCKLINEAR                       (0x00000000)
#define NV507D_HEAD_SET_STORAGE_MEMORY_LAYOUT_PITCH                             (0x00000001)
#define NV507D_HEAD_SET_STORAGE_PITCH                                           17:8
#define NV507D_HEAD_SET_VIEWPORT_POINT_IN(a,b)                                  (0x000008C0 + (a)*0x00000400 + (b)*0x00000004)
#define NV507D_HEAD_SET_VIEWPORT_POINT_IN_X                                     14:0
#define NV507D_HEAD_SET_VIEWPORT_POINT_IN_Y                                     30:16
#define NV507D_HEAD_SET_VIEWPORT_SIZE_IN(a)                                     (0x000008C8 + (a)*0x00000400)
#define NV507D_HEAD_SET_VIEWPORT_SIZE_IN_HEIGHT                                 30:16
#define NV507D_HEAD_SET_VIEWPORT_SIZE_IN_WIDTH                                  14:0
#define NV507D_HEAD_SET_VIEWPORT_SIZE_OUT(a)                                    (0x000008D8 + (a)*0x00000400)
#define NV507D_HEAD_SET_VIEWPORT_SIZE_OUT_HEIGHT                                30:16
#define NV507D_HEAD_SET_VIEWPORT_SIZE_OUT_MIN(a)                                (0x000008DC + (a)*0x00000400)
#define NV507D_HEAD_SET_VIEWPORT_SIZE_OUT_MIN_HEIGHT                            30:16
#define NV507D_HEAD_SET_VIEWPORT_SIZE_OUT_MIN_WIDTH                             14:0
#define NV507D_HEAD_SET_VIEWPORT_SIZE_OUT_WIDTH                                 14:0
#define NV507D_PIOR_SET_CONTROL(a)                                              (0x00000700 + (a)*0x00000040)
#define NV507D_PIOR_SET_CONTROL_DE_SYNC_POLARITY                                14:14
#define NV507D_PIOR_SET_CONTROL_DE_SYNC_POLARITY_NEGATIVE_TRUE                  (0x00000001)
#define NV507D_PIOR_SET_CONTROL_DE_SYNC_POLARITY_POSITIVE_TRUE                  (0x00000000)
#define NV507D_PIOR_SET_CONTROL_HSYNC_POLARITY                                  12:12
#define NV507D_PIOR_SET_CONTROL_HSYNC_POLARITY_NEGATIVE_TRUE                    (0x00000001)
#define NV507D_PIOR_SET_CONTROL_HSYNC_POLARITY_POSITIVE_TRUE                    (0x00000000)
#define NV507D_PIOR_SET_CONTROL_OWNER                                           3:0
#define NV507D_PIOR_SET_CONTROL_OWNER_HEAD0                                     (0x00000001)
#define NV507D_PIOR_SET_CONTROL_OWNER_HEAD1                                     (0x00000002)
#define NV507D_PIOR_SET_CONTROL_OWNER_NONE                                      (0x00000000)
#define NV507D_PIOR_SET_CONTROL_PROTOCOL                                        11:8
#define NV507D_PIOR_SET_CONTROL_PROTOCOL_EXT_TMDS_ENC                           (0x00000000)
#define NV507D_PIOR_SET_CONTROL_PROTOCOL_EXT_TV_ENC                             (0x00000001)
#define NV507D_PIOR_SET_CONTROL_SUB_OWNER                                       5:4
#define NV507D_PIOR_SET_CONTROL_SUB_OWNER_BOTH                                  (0x00000003)
#define NV507D_PIOR_SET_CONTROL_SUB_OWNER_NONE                                  (0x00000000)
#define NV507D_PIOR_SET_CONTROL_SUB_OWNER_SUBHEAD0                              (0x00000001)
#define NV507D_PIOR_SET_CONTROL_SUB_OWNER_SUBHEAD1                              (0x00000002)
#define NV507D_PIOR_SET_CONTROL_VSYNC_POLARITY                                  13:13
#define NV507D_PIOR_SET_CONTROL_VSYNC_POLARITY_NEGATIVE_TRUE                    (0x00000001)
#define NV507D_PIOR_SET_CONTROL_VSYNC_POLARITY_POSITIVE_TRUE                    (0x00000000)
#define NV507D_SET_CONTEXT_DMA_NOTIFIER                                         (0x00000088)
#define NV507D_SET_CONTEXT_DMA_NOTIFIER_HANDLE                                  31:0
#define NV507D_SET_NOTIFIER_CONTROL                                             (0x00000084)
#define NV507D_SET_NOTIFIER_CONTROL_MODE                                        30:30
#define NV507D_SET_NOTIFIER_CONTROL_MODE_WRITE                                  (0x00000000)
#define NV507D_SET_NOTIFIER_CONTROL_MODE_WRITE_AWAKEN                           (0x00000001)
#define NV507D_SET_NOTIFIER_CONTROL_NOTIFY                                      31:31
#define NV507D_SET_NOTIFIER_CONTROL_NOTIFY_DISABLE                              (0x00000000)
#define NV507D_SET_NOTIFIER_CONTROL_NOTIFY_ENABLE                               (0x00000001)
#define NV507D_SET_NOTIFIER_CONTROL_OFFSET                                      11:2
#define NV507D_SOR_SET_CONTROL(a)                                               (0x00000600 + (a)*0x00000040)
#define NV507D_SOR_SET_CONTROL_DE_SYNC_POLARITY                                 14:14
#define NV507D_SOR_SET_CONTROL_DE_SYNC_POLARITY_NEGATIVE_TRUE                   (0x00000001)
#define NV507D_SOR_SET_CONTROL_DE_SYNC_POLARITY_POSITIVE_TRUE                   (0x00000000)
#define NV507D_SOR_SET_CONTROL_HSYNC_POLARITY                                   12:12
#define NV507D_SOR_SET_CONTROL_HSYNC_POLARITY_NEGATIVE_TRUE                     (0x00000001)
#define NV507D_SOR_SET_CONTROL_HSYNC_POLARITY_POSITIVE_TRUE                     (0x00000000)
#define NV507D_SOR_SET_CONTROL_OWNER                                            3:0
#define NV507D_SOR_SET_CONTROL_OWNER_HEAD0                                      (0x00000001)
#define NV507D_SOR_SET_CONTROL_OWNER_HEAD1                                      (0x00000002)
#define NV507D_SOR_SET_CONTROL_OWNER_NONE                                       (0x00000000)
#define NV507D_SOR_SET_CONTROL_PROTOCOL                                         11:8
#define NV507D_SOR_SET_CONTROL_PROTOCOL_CUSTOM                                  (0x0000000F)
#define NV507D_SOR_SET_CONTROL_PROTOCOL_DDI_OUT                                 (0x00000007)
#define NV507D_SOR_SET_CONTROL_PROTOCOL_DUAL_SINGLE_TMDS                        (0x00000004)
#define NV507D_SOR_SET_CONTROL_PROTOCOL_DUAL_TMDS                               (0x00000005)
#define NV507D_SOR_SET_CONTROL_PROTOCOL_LVDS_CUSTOM                             (0x00000000)
#define NV507D_SOR_SET_CONTROL_PROTOCOL_SINGLE_TMDS_A                           (0x00000001)
#define NV507D_SOR_SET_CONTROL_PROTOCOL_SINGLE_TMDS_AB                          (0x00000003)
#define NV507D_SOR_SET_CONTROL_PROTOCOL_SINGLE_TMDS_B                           (0x00000002)
#define NV507D_SOR_SET_CONTROL_SUB_OWNER                                        5:4
#define NV507D_SOR_SET_CONTROL_SUB_OWNER_BOTH                                   (0x00000003)
#define NV507D_SOR_SET_CONTROL_SUB_OWNER_NONE                                   (0x00000000)
#define NV507D_SOR_SET_CONTROL_SUB_OWNER_SUBHEAD0                               (0x00000001)
#define NV507D_SOR_SET_CONTROL_SUB_OWNER_SUBHEAD1                               (0x00000002)
#define NV507D_SOR_SET_CONTROL_VSYNC_POLARITY                                   13:13
#define NV507D_SOR_SET_CONTROL_VSYNC_POLARITY_NEGATIVE_TRUE                     (0x00000001)
#define NV507D_SOR_SET_CONTROL_VSYNC_POLARITY_POSITIVE_TRUE                     (0x00000000)
#define NV507D_UPDATE                                                           (0x00000080)
#define NV507D_UPDATE_INHIBIT_INTERRUPTS                                        29:29
#define NV507D_UPDATE_INHIBIT_INTERRUPTS_FALSE                                  (0x00000000)
#define NV507D_UPDATE_INHIBIT_INTERRUPTS_TRUE                                   (0x00000001)
#define NV507D_UPDATE_INTERLOCK_WITH_BASE0                                      1:1
#define NV507D_UPDATE_INTERLOCK_WITH_BASE0_DISABLE                              (0x00000000)
#define NV507D_UPDATE_INTERLOCK_WITH_BASE0_ENABLE                               (0x00000001)
#define NV507D_UPDATE_INTERLOCK_WITH_BASE1                                      9:9
#define NV507D_UPDATE_INTERLOCK_WITH_BASE1_DISABLE                              (0x00000000)
#define NV507D_UPDATE_INTERLOCK_WITH_BASE1_ENABLE                               (0x00000001)
#define NV507D_UPDATE_INTERLOCK_WITH_CURSOR0                                    0:0
#define NV507D_UPDATE_INTERLOCK_WITH_CURSOR0_DISABLE                            (0x00000000)
#define NV507D_UPDATE_INTERLOCK_WITH_CURSOR0_ENABLE                             (0x00000001)
#define NV507D_UPDATE_INTERLOCK_WITH_CURSOR1                                    8:8
#define NV507D_UPDATE_INTERLOCK_WITH_CURSOR1_DISABLE                            (0x00000000)
#define NV507D_UPDATE_INTERLOCK_WITH_CURSOR1_ENABLE                             (0x00000001)
#define NV507D_UPDATE_INTERLOCK_WITH_OVERLAY0                                   2:2
#define NV507D_UPDATE_INTERLOCK_WITH_OVERLAY0_DISABLE                           (0x00000000)
#define NV507D_UPDATE_INTERLOCK_WITH_OVERLAY0_ENABLE                            (0x00000001)
#define NV507D_UPDATE_INTERLOCK_WITH_OVERLAY1                                   10:10
#define NV507D_UPDATE_INTERLOCK_WITH_OVERLAY1_DISABLE                           (0x00000000)
#define NV507D_UPDATE_INTERLOCK_WITH_OVERLAY1_ENABLE                            (0x00000001)
#define NV507D_UPDATE_INTERLOCK_WITH_OVERLAY_IMM0                               3:3
#define NV507D_UPDATE_INTERLOCK_WITH_OVERLAY_IMM0_DISABLE                       (0x00000000)
#define NV507D_UPDATE_INTERLOCK_WITH_OVERLAY_IMM0_ENABLE                        (0x00000001)
#define NV507D_UPDATE_INTERLOCK_WITH_OVERLAY_IMM1                               11:11
#define NV507D_UPDATE_INTERLOCK_WITH_OVERLAY_IMM1_DISABLE                       (0x00000000)
#define NV507D_UPDATE_INTERLOCK_WITH_OVERLAY_IMM1_ENABLE                        (0x00000001)
#define NV507D_UPDATE_NOT_DRIVER_FRIENDLY                                       31:31
#define NV507D_UPDATE_NOT_DRIVER_FRIENDLY_FALSE                                 (0x00000000)
#define NV507D_UPDATE_NOT_DRIVER_FRIENDLY_TRUE                                  (0x00000001)
#define NV507D_UPDATE_NOT_DRIVER_UNFRIENDLY                                     30:30
#define NV507D_UPDATE_NOT_DRIVER_UNFRIENDLY_FALSE                               (0x00000000)
#define NV507D_UPDATE_NOT_DRIVER_UNFRIENDLY_TRUE                                (0x00000001)
#define NV_DISP_CORE_NOTIFIER_1                                                      0x00000000
#define NV_DISP_CORE_NOTIFIER_1_CAPABILITIES_1                                       0x00000001
#define NV_DISP_CORE_NOTIFIER_1_CAPABILITIES_1_DONE                                  0:0
#define NV_DISP_CORE_NOTIFIER_1_CAPABILITIES_1_DONE_FALSE                            0x00000000
#define NV_DISP_CORE_NOTIFIER_1_CAPABILITIES_1_DONE_TRUE                             0x00000001
#define NV_DISP_CORE_NOTIFIER_1_COMPLETION_0                                         0x00000000
#define NV_DISP_CORE_NOTIFIER_1_COMPLETION_0_DONE                                    0:0
#define NV_DISP_CORE_NOTIFIER_1_COMPLETION_0_DONE_FALSE                              0x00000000
#define NV_DISP_CORE_NOTIFIER_1_COMPLETION_0_DONE_TRUE                               0x00000001
#define NV_DISP_CORE_NOTIFIER_1_COMPLETION_0_R0                                      15:1
#define NV_DISP_CORE_NOTIFIER_1_COMPLETION_0_TIMESTAMP                               29:16
#define NV_DISP_CORE_NOTIFIER_1_SIZEOF                                               0x00000054





#define DRM_FB_HELPER_DEFAULT_OPS \
	.fb_check_var	= drm_fb_helper_check_var, \
	.fb_set_par	= drm_fb_helper_set_par, \
	.fb_setcmap	= drm_fb_helper_setcmap, \
	.fb_blank	= drm_fb_helper_blank, \
	.fb_pan_display	= drm_fb_helper_pan_display, \
	.fb_debug_enter = drm_fb_helper_debug_enter, \
	.fb_debug_leave = drm_fb_helper_debug_leave, \
	.fb_ioctl	= drm_fb_helper_ioctl


#define drm_client_for_each_connector_iter(connector, iter) \
	drm_for_each_connector_iter(connector, iter) \
		if (connector->connector_type != DRM_MODE_CONNECTOR_WRITEBACK)
#define drm_client_for_each_modeset(modeset, client) \
	for (({ lockdep_assert_held(&(client)->modeset_mutex); }), \
	     modeset = (client)->modesets; modeset->crtc; modeset++)
#define ABI16_IOCTL_ARGS                                                       \
	struct drm_device *dev, void *data, struct drm_file *file_priv
#define DRM_IOCTL_NOUVEAU_CHANNEL_ALLOC      DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_CHANNEL_ALLOC, struct drm_nouveau_channel_alloc)
#define DRM_IOCTL_NOUVEAU_CHANNEL_FREE       DRM_IOW (DRM_COMMAND_BASE + DRM_NOUVEAU_CHANNEL_FREE, struct drm_nouveau_channel_free)
#define DRM_IOCTL_NOUVEAU_GETPARAM           DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_GETPARAM, struct drm_nouveau_getparam)
#define DRM_IOCTL_NOUVEAU_GPUOBJ_FREE        DRM_IOW (DRM_COMMAND_BASE + DRM_NOUVEAU_GPUOBJ_FREE, struct drm_nouveau_gpuobj_free)
#define DRM_IOCTL_NOUVEAU_GROBJ_ALLOC        DRM_IOW (DRM_COMMAND_BASE + DRM_NOUVEAU_GROBJ_ALLOC, struct drm_nouveau_grobj_alloc)
#define DRM_IOCTL_NOUVEAU_NOTIFIEROBJ_ALLOC  DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_NOTIFIEROBJ_ALLOC, struct drm_nouveau_notifierobj_alloc)
#define DRM_IOCTL_NOUVEAU_SETPARAM           DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_SETPARAM, struct drm_nouveau_setparam)
#define NOUVEAU_GEM_DOMAIN_GART      (1 << 2)
#define NOUVEAU_GEM_DOMAIN_VRAM      (1 << 1)
#define NOUVEAU_GETPARAM_AGP_SIZE        9
#define NOUVEAU_GETPARAM_BUS_TYPE        5
#define NOUVEAU_GETPARAM_CHIPSET_ID      11
#define NOUVEAU_GETPARAM_FB_SIZE         8
#define NOUVEAU_GETPARAM_GRAPH_UNITS     13
#define NOUVEAU_GETPARAM_HAS_BO_USAGE    15
#define NOUVEAU_GETPARAM_HAS_PAGEFLIP    16
#define NOUVEAU_GETPARAM_PCI_DEVICE      4
#define NOUVEAU_GETPARAM_PCI_VENDOR      3
#define NOUVEAU_GETPARAM_PTIMER_TIME     14
#define NOUVEAU_GETPARAM_VM_VRAM_BASE    12


#define ROM_BIOS_PAGE 4096





#define NVBO_MD32(A...) DRF_MD(NVBO_RD32_, NVBO_WR32_, u32, ##A)
#define NVBO_MR32(A...) DRF_MR(NVBO_RD32_, NVBO_WR32_, u32, ##A)
#define NVBO_MV32(A...) DRF_MV(NVBO_RD32_, NVBO_WR32_, u32, ##A)
#define NVBO_RD32(A...) DRF_RD(NVBO_RD32_,                  ##A)
#define NVBO_RD32_(b,o,dr)   nouveau_bo_rd32((b), (o)/4 + (dr))
#define NVBO_RV32(A...) DRF_RV(NVBO_RD32_,                  ##A)
#define NVBO_TD32(A...) DRF_TD(NVBO_RD32_,                  ##A)
#define NVBO_TV32(A...) DRF_TV(NVBO_RD32_,                  ##A)
#define NVBO_WD32(A...) DRF_WD(            NVBO_WR32_,      ##A)
#define NVBO_WR32(A...) DRF_WR(            NVBO_WR32_,      ##A)
#define NVBO_WR32_(b,o,dr,f) nouveau_bo_wr32((b), (o)/4 + (dr), (f))
#define NVBO_WV32(A...) DRF_WV(            NVBO_WR32_,      ##A)


#define NOUVEAU_DMA_SKIPS (128 / 4)
#define NV_SW_DMA_VBLSEM                                             0x0000018c
#define NV_SW_PAGE_FLIP                                              0x00000500
#define NV_SW_VBLSEM_OFFSET                                          0x00000400
#define NV_SW_VBLSEM_RELEASE                                         0x00000408
#define NV_SW_VBLSEM_RELEASE_VALUE                                   0x00000404
#define WRITE_PUT(val) do {                                                    \
	mb();                                                   \
	nouveau_bo_rd32(chan->push.buffer, 0);                                 \
	nvif_wr32(&chan->user, chan->user_put, ((val) << 2) + chan->push.addr);\
} while (0)


#define PUSH(A...) PUSH_(A, PUSH_10P, PUSH_10D,          \
			    PUSH_9P , PUSH_9D,           \
			    PUSH_8P , PUSH_8D,           \
			    PUSH_7P , PUSH_7D,           \
			    PUSH_6P , PUSH_6D,           \
			    PUSH_5P , PUSH_5D,           \
			    PUSH_4P , PUSH_4D,           \
			    PUSH_3P , PUSH_3D,           \
			    PUSH_2P , PUSH_2D,           \
			    PUSH_1P , PUSH_1D)(, ##A)
#define PUSH_(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,IMPL,...) IMPL
#define PUSH_1(X,f,ds,n,o,p,s,mA,dA) do {                             \
	PUSH_##o##_HDR((p), s, mA, (ds)+(n));                         \
	PUSH_##f(X, (p), X##mA, 1, o, (dA), ds, "");                  \
} while(0)
#define PUSH_10(X,f,ds,n,o,p,s,mB,dB,mA,dA,a...) do {                 \
	PUSH_ASSERT((mB) - (mA) == (0?PUSH_##o##_INC), "mthd9");      \
	PUSH_9(X, DATA_, 1, (ds) + (n), o, (p), s, X##mA, (dA), ##a); \
	PUSH_##f(X, (p), X##mB, 0, o, (dB), ds, "");                  \
} while(0)
#define PUSH_10D(X,o,p,s,mA,dA,mB,dB,mC,dC,mD,dD,mE,dE,mF,dF,mG,dG,mH,dH,mI,dI,mJ,dJ) \
	PUSH_10(X, DATA_, 1, 0, o, (p), s, X##mJ, (dJ),                               \
					   X##mI, (dI),                               \
					   X##mH, (dH),                               \
					   X##mG, (dG),                               \
					   X##mF, (dF),                               \
					   X##mE, (dE),                               \
					   X##mD, (dD),                               \
					   X##mC, (dC),                               \
					   X##mB, (dB),                               \
					   X##mA, (dA))
#define PUSH_1D(X,o,p,s,mA,dA)                         \
	PUSH_1(X, DATA_, 1, 0, o, (p), s, X##mA, (dA))
#define PUSH_1INC(A...) PUSH_NV(NV1I, ##A)
#define PUSH_1P(X,o,p,s,mA,dp,ds)                       \
	PUSH_1(X, DATAp, ds, 0, o, (p), s, X##mA, (dp))
#define PUSH_2(X,f,ds,n,o,p,s,mB,dB,mA,dA,a...) do {                  \
	PUSH_ASSERT((mB) - (mA) == (1?PUSH_##o##_INC), "mthd1");      \
	PUSH_1(X, DATA_, 1, (ds) + (n), o, (p), s, X##mA, (dA), ##a); \
	PUSH_##f(X, (p), X##mB, 0, o, (dB), ds, "");                  \
} while(0)
#define PUSH_2D(X,o,p,s,mA,dA,mB,dB)                   \
	PUSH_2(X, DATA_, 1, 0, o, (p), s, X##mB, (dB), \
					  X##mA, (dA))
#define PUSH_2P(X,o,p,s,mA,dA,mB,dp,ds)                 \
	PUSH_2(X, DATAp, ds, 0, o, (p), s, X##mB, (dp), \
					   X##mA, (dA))
#define PUSH_3(X,f,ds,n,o,p,s,mB,dB,mA,dA,a...) do {                  \
	PUSH_ASSERT((mB) - (mA) == (0?PUSH_##o##_INC), "mthd2");      \
	PUSH_2(X, DATA_, 1, (ds) + (n), o, (p), s, X##mA, (dA), ##a); \
	PUSH_##f(X, (p), X##mB, 0, o, (dB), ds, "");                  \
} while(0)
#define PUSH_3D(X,o,p,s,mA,dA,mB,dB,mC,dC)             \
	PUSH_3(X, DATA_, 1, 0, o, (p), s, X##mC, (dC), \
					  X##mB, (dB), \
					  X##mA, (dA))
#define PUSH_3P(X,o,p,s,mA,dA,mB,dB,mC,dp,ds)           \
	PUSH_3(X, DATAp, ds, 0, o, (p), s, X##mC, (dp), \
					   X##mB, (dB), \
					   X##mA, (dA))
#define PUSH_4(X,f,ds,n,o,p,s,mB,dB,mA,dA,a...) do {                  \
	PUSH_ASSERT((mB) - (mA) == (0?PUSH_##o##_INC), "mthd3");      \
	PUSH_3(X, DATA_, 1, (ds) + (n), o, (p), s, X##mA, (dA), ##a); \
	PUSH_##f(X, (p), X##mB, 0, o, (dB), ds, "");                  \
} while(0)
#define PUSH_4D(X,o,p,s,mA,dA,mB,dB,mC,dC,mD,dD)       \
	PUSH_4(X, DATA_, 1, 0, o, (p), s, X##mD, (dD), \
					  X##mC, (dC), \
					  X##mB, (dB), \
					  X##mA, (dA))
#define PUSH_5(X,f,ds,n,o,p,s,mB,dB,mA,dA,a...) do {                  \
	PUSH_ASSERT((mB) - (mA) == (0?PUSH_##o##_INC), "mthd4");      \
	PUSH_4(X, DATA_, 1, (ds) + (n), o, (p), s, X##mA, (dA), ##a); \
	PUSH_##f(X, (p), X##mB, 0, o, (dB), ds, "");                  \
} while(0)
#define PUSH_5D(X,o,p,s,mA,dA,mB,dB,mC,dC,mD,dD,mE,dE) \
	PUSH_5(X, DATA_, 1, 0, o, (p), s, X##mE, (dE), \
					  X##mD, (dD), \
					  X##mC, (dC), \
					  X##mB, (dB), \
					  X##mA, (dA))
#define PUSH_6(X,f,ds,n,o,p,s,mB,dB,mA,dA,a...) do {                  \
	PUSH_ASSERT((mB) - (mA) == (0?PUSH_##o##_INC), "mthd5");      \
	PUSH_5(X, DATA_, 1, (ds) + (n), o, (p), s, X##mA, (dA), ##a); \
	PUSH_##f(X, (p), X##mB, 0, o, (dB), ds, "");                  \
} while(0)
#define PUSH_6D(X,o,p,s,mA,dA,mB,dB,mC,dC,mD,dD,mE,dE,mF,dF) \
	PUSH_6(X, DATA_, 1, 0, o, (p), s, X##mF, (dF),       \
					  X##mE, (dE),       \
					  X##mD, (dD),       \
					  X##mC, (dC),       \
					  X##mB, (dB),       \
					  X##mA, (dA))
#define PUSH_7(X,f,ds,n,o,p,s,mB,dB,mA,dA,a...) do {                  \
	PUSH_ASSERT((mB) - (mA) == (0?PUSH_##o##_INC), "mthd6");      \
	PUSH_6(X, DATA_, 1, (ds) + (n), o, (p), s, X##mA, (dA), ##a); \
	PUSH_##f(X, (p), X##mB, 0, o, (dB), ds, "");                  \
} while(0)
#define PUSH_7D(X,o,p,s,mA,dA,mB,dB,mC,dC,mD,dD,mE,dE,mF,dF,mG,dG) \
	PUSH_7(X, DATA_, 1, 0, o, (p), s, X##mG, (dG),             \
					  X##mF, (dF),             \
					  X##mE, (dE),             \
					  X##mD, (dD),             \
					  X##mC, (dC),             \
					  X##mB, (dB),             \
					  X##mA, (dA))
#define PUSH_8(X,f,ds,n,o,p,s,mB,dB,mA,dA,a...) do {                  \
	PUSH_ASSERT((mB) - (mA) == (0?PUSH_##o##_INC), "mthd7");      \
	PUSH_7(X, DATA_, 1, (ds) + (n), o, (p), s, X##mA, (dA), ##a); \
	PUSH_##f(X, (p), X##mB, 0, o, (dB), ds, "");                  \
} while(0)
#define PUSH_8D(X,o,p,s,mA,dA,mB,dB,mC,dC,mD,dD,mE,dE,mF,dF,mG,dG,mH,dH) \
	PUSH_8(X, DATA_, 1, 0, o, (p), s, X##mH, (dH),                   \
					  X##mG, (dG),                   \
					  X##mF, (dF),                   \
					  X##mE, (dE),                   \
					  X##mD, (dD),                   \
					  X##mC, (dC),                   \
					  X##mB, (dB),                   \
					  X##mA, (dA))
#define PUSH_9(X,f,ds,n,o,p,s,mB,dB,mA,dA,a...) do {                  \
	PUSH_ASSERT((mB) - (mA) == (0?PUSH_##o##_INC), "mthd8");      \
	PUSH_8(X, DATA_, 1, (ds) + (n), o, (p), s, X##mA, (dA), ##a); \
	PUSH_##f(X, (p), X##mB, 0, o, (dB), ds, "");                  \
} while(0)
#define PUSH_9D(X,o,p,s,mA,dA,mB,dB,mC,dC,mD,dD,mE,dE,mF,dF,mG,dG,mH,dH,mI,dI) \
	PUSH_9(X, DATA_, 1, 0, o, (p), s, X##mI, (dI),                         \
					  X##mH, (dH),                         \
					  X##mG, (dG),                         \
					  X##mF, (dF),                         \
					  X##mE, (dE),                         \
					  X##mD, (dD),                         \
					  X##mC, (dC),                         \
					  X##mB, (dB),                         \
					  X##mA, (dA))
#define PUSH_ASSERT(a,b) do {                                             \
	static_assert(                                                    \
		__builtin_choose_expr(__builtin_constant_p(a), (a), 1), b \
	);                                                                \
	PUSH_ASSERT_ON(!(a), b);                                          \
} while(0)
#define PUSH_ASSERT_ON(a,b) WARN((a), b)
#define PUSH_DATA(p,d) PUSH_DATA__((p), (d), " data - %s", __func__)
#define PUSH_DATA_(X,p,m,i0,i1,d,s,f,a...) PUSH_DATA__((p), (d), "-> "#m f, ##a)
#define PUSH_DATA__(p,d,f,a...) do {                       \
	struct nvif_push *_p = (p);                        \
	u32 _d = (d);                                      \
	PUSH_ASSERT(_p->cur < _p->seg, "segment overrun"); \
	PUSH_ASSERT(_p->cur < _p->end, "pushbuf overrun"); \
	PUSH_PRINTF(_p, "%08x"f, _d, ##a);                 \
	*_p->cur++ = _d;                                   \
} while(0)
#define PUSH_DATAp(X,p,m,i,o,d,s,f,a...) do {                                     \
	struct nvif_push *_pp = (p);                                              \
	const u32 *_dd = (d);                                                     \
	u32 _s = (s), _i = (i?PUSH_##o##_INC);                                    \
	if (_s--) {                                                               \
		PUSH_DATA_(X, _pp, X##m, i0, i1, *_dd++, 1, "+0x%x", 0);          \
		while (_s--) {                                                    \
			PUSH_DATA_(X, _pp, X##m, i0, i1, *_dd++, 1, "+0x%x", _i); \
			_i += (0?PUSH_##o##_INC);                                 \
		}                                                                 \
	}                                                                         \
} while(0)
#define PUSH_IMMD(A...) PUSH_NV(NVIM, ##A)
#define PUSH_MTHD(A...) PUSH_NV(NVSQ, ##A)
#define PUSH_NINC(A...) PUSH_NV(NVNI, ##A)
#define PUSH_NV(A...) PUSH_NV_(A, PUSH_NV_10, PUSH_NV_10,       \
				  PUSH_NV_9 , PUSH_NV_9,        \
				  PUSH_NV_8 , PUSH_NV_8,        \
				  PUSH_NV_7 , PUSH_NV_7,        \
				  PUSH_NV_6 , PUSH_NV_6,        \
				  PUSH_NV_5 , PUSH_NV_5,        \
				  PUSH_NV_4 , PUSH_NV_4,        \
				  PUSH_NV_3 , PUSH_NV_3,        \
				  PUSH_NV_2 , PUSH_NV_2,        \
				  PUSH_NV_1 , PUSH_NV_1)(, ##A)
#define PUSH_NV1I(A...) PUSH(1INC, ##A)
#define PUSH_NVIM(p,c,m,d) do {             \
	struct nvif_push *__p = (p);        \
	u32 __d = (d);                      \
	PUSH_IMMD_HDR(__p, c, m, __d);      \
	__p->cur--;                         \
	PUSH_PRINTF(__p, "%08x-> "#m, __d); \
	__p->cur++;                         \
} while(0)
#define PUSH_NVNI(A...) PUSH(NINC, ##A)
#define PUSH_NVSQ(A...) PUSH(MTHD, ##A)
#define PUSH_NV_(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,IMPL,...) IMPL
#define PUSH_NV_1(X,o,p,c,mA,d...) \
       PUSH_##o(p,c,c##_##mA,d)
#define PUSH_NV_10(X,o,p,c,mA,dA,mB,dB,mC,dC,mD,dD,mE,dE,mF,dF,mG,dG,mH,dH,mI,dI,mJ,d...) \
       PUSH_##o(p,c,c##_##mA,dA,                                                          \
		    c##_##mB,dB,                                                          \
		    c##_##mC,dC,                                                          \
		    c##_##mD,dD,                                                          \
		    c##_##mE,dE,                                                          \
		    c##_##mF,dF,                                                          \
		    c##_##mG,dG,                                                          \
		    c##_##mH,dH,                                                          \
		    c##_##mI,dI,                                                          \
		    c##_##mJ,d)
#define PUSH_NV_2(X,o,p,c,mA,dA,mB,d...) \
       PUSH_##o(p,c,c##_##mA,dA,         \
		    c##_##mB,d)
#define PUSH_NV_3(X,o,p,c,mA,dA,mB,dB,mC,d...) \
       PUSH_##o(p,c,c##_##mA,dA,               \
		    c##_##mB,dB,               \
		    c##_##mC,d)
#define PUSH_NV_4(X,o,p,c,mA,dA,mB,dB,mC,dC,mD,d...) \
       PUSH_##o(p,c,c##_##mA,dA,                     \
		    c##_##mB,dB,                     \
		    c##_##mC,dC,                     \
		    c##_##mD,d)
#define PUSH_NV_5(X,o,p,c,mA,dA,mB,dB,mC,dC,mD,dD,mE,d...) \
       PUSH_##o(p,c,c##_##mA,dA,                           \
		    c##_##mB,dB,                           \
		    c##_##mC,dC,                           \
		    c##_##mD,dD,                           \
		    c##_##mE,d)
#define PUSH_NV_6(X,o,p,c,mA,dA,mB,dB,mC,dC,mD,dD,mE,dE,mF,d...) \
       PUSH_##o(p,c,c##_##mA,dA,                                 \
		    c##_##mB,dB,                                 \
		    c##_##mC,dC,                                 \
		    c##_##mD,dD,                                 \
		    c##_##mE,dE,                                 \
		    c##_##mF,d)
#define PUSH_NV_7(X,o,p,c,mA,dA,mB,dB,mC,dC,mD,dD,mE,dE,mF,dF,mG,d...) \
       PUSH_##o(p,c,c##_##mA,dA,                                       \
		    c##_##mB,dB,                                       \
		    c##_##mC,dC,                                       \
		    c##_##mD,dD,                                       \
		    c##_##mE,dE,                                       \
		    c##_##mF,dF,                                       \
		    c##_##mG,d)
#define PUSH_NV_8(X,o,p,c,mA,dA,mB,dB,mC,dC,mD,dD,mE,dE,mF,dF,mG,dG,mH,d...) \
       PUSH_##o(p,c,c##_##mA,dA,                                             \
		    c##_##mB,dB,                                             \
		    c##_##mC,dC,                                             \
		    c##_##mD,dD,                                             \
		    c##_##mE,dE,                                             \
		    c##_##mF,dF,                                             \
		    c##_##mG,dG,                                             \
		    c##_##mH,d)
#define PUSH_NV_9(X,o,p,c,mA,dA,mB,dB,mC,dC,mD,dD,mE,dE,mF,dF,mG,dG,mH,dH,mI,d...) \
       PUSH_##o(p,c,c##_##mA,dA,                                                   \
		    c##_##mB,dB,                                                   \
		    c##_##mC,dC,                                                   \
		    c##_##mD,dD,                                                   \
		    c##_##mE,dE,                                                   \
		    c##_##mF,dF,                                                   \
		    c##_##mG,dG,                                                   \
		    c##_##mH,dH,                                                   \
		    c##_##mI,d)
#define PUSH_PRINTF(p,f,a...) do {                              \
	struct nvif_push *_ppp = (p);                           \
	u32 __o = _ppp->cur - (u32 *)_ppp->mem.object.map.ptr;  \
	NVIF_DEBUG(&_ppp->mem.object, "%08x: "f, __o * 4, ##a); \
	(void)__o;                                              \
} while(0)
#define PUSH_RSVD(p,d) do {          \
	struct nvif_push *__p = (p); \
	__p->seg++;                  \
	__p->end++;                  \
	d;                           \
} while(0)

#define NVIF_DEBUG(o,f,a...) NVIF_PRINT(debugf, (o), f, ##a)
#define NVIF_ERROR(o,f,a...) NVIF_PRINT(errorf, (o), f, ##a)
#define NVIF_PRINT(l,o,f,a...) do {                                                                \
	struct nvif_object *_o = (o);                                                              \
	struct nvif_parent *_p = _o->parent;                                                       \
	_p->func->l(_o, "[%s/%08x:%s] "f"\n", _o->client->object.name, _o->handle, _o->name, ##a); \
} while(0)


#define NVA06F_V0_NTFY_KILLED                                              0x01
#define NVA06F_V0_NTFY_NON_STALL_INTERRUPT                                 0x00

#define GF100_DMA_V0_KIND_PITCH                                            0x00
#define GF100_DMA_V0_KIND_VM                                               0xff
#define GF100_DMA_V0_PRIV_US                                               0x01
#define GF100_DMA_V0_PRIV_VM                                               0x00
#define GF100_DMA_V0_PRIV__S                                               0x02
#define GF119_DMA_V0_KIND_PITCH                                            0x00
#define GF119_DMA_V0_KIND_VM                                               0xff
#define GF119_DMA_V0_PAGE_LP                                               0x00
#define GF119_DMA_V0_PAGE_SP                                               0x01
#define NV50_DMA_V0_COMP_1                                                 0x01
#define NV50_DMA_V0_COMP_2                                                 0x02
#define NV50_DMA_V0_COMP_NONE                                              0x00
#define NV50_DMA_V0_COMP_VM                                                0x03
#define NV50_DMA_V0_KIND_PITCH                                             0x00
#define NV50_DMA_V0_KIND_VM                                                0x7f
#define NV50_DMA_V0_PART_1KB                                               0x02
#define NV50_DMA_V0_PART_256                                               0x01
#define NV50_DMA_V0_PART_VM                                                0x00
#define NV50_DMA_V0_PRIV_US                                                0x01
#define NV50_DMA_V0_PRIV_VM                                                0x00
#define NV50_DMA_V0_PRIV__S                                                0x02
#define NV_DMA_V0_ACCESS_RD                                                0x01
#define NV_DMA_V0_ACCESS_RDWR                 (NV_DMA_V0_ACCESS_RD | NV_DMA_V0_ACCESS_WR)
#define NV_DMA_V0_ACCESS_VM                                                0x00
#define NV_DMA_V0_ACCESS_WR                                                0x02
#define NV_DMA_V0_TARGET_AGP                                               0x04
#define NV_DMA_V0_TARGET_PCI                                               0x02
#define NV_DMA_V0_TARGET_PCI_US                                            0x03
#define NV_DMA_V0_TARGET_VM                                                0x00
#define NV_DMA_V0_TARGET_VRAM                                              0x01

#define AMPERE_CHANNEL_GPFIFO_B                        0x0000c76f
#define AMPERE_DMA_COPY_B                                            0x0000c7b5
#define FERMI_A                                        0x00009097
#define FERMI_B                                        0x00009197
#define FERMI_C                                        0x00009297
#define FERMI_CHANNEL_GPFIFO                           0x0000906f
#define FERMI_COMPUTE_A                                              0x000090c0
#define FERMI_COMPUTE_B                                              0x000091c0
#define FERMI_DECOMPRESS                                             0x000090b8
#define FERMI_DMA                                                    0x000090b5
#define FERMI_MEMORY_TO_MEMORY_FORMAT_A                              0x00009039
#define FERMI_TWOD_A                                                 0x0000902d
#define G82_CHANNEL_GPFIFO                             0x0000826f
#define G82_DISP                                       0x00008270
#define G82_DISP_BASE_CHANNEL_DMA                      0x0000827c
#define G82_DISP_CORE_CHANNEL_DMA                      0x0000827d
#define G82_DISP_CURSOR                                0x0000827a
#define G82_DISP_OVERLAY                               0x0000827b
#define G82_DISP_OVERLAY_CHANNEL_DMA                   0x0000827e
#define G82_MPEG                                                     0x00008274
#define G82_TESLA                                                    0x00008297
#define G98_MSPDEC                                                   0x000088b2
#define G98_MSPPP                                                    0x000088b3
#define G98_MSVLD                                                    0x000088b1
#define G98_SEC                                                      0x000088b4
#define GA102_DISP                                     0x0000c670
#define GA102_DISP_CORE_CHANNEL_DMA                    0x0000c67d
#define GA102_DISP_CURSOR                              0x0000c67a
#define GA102_DISP_WINDOW_CHANNEL_DMA                  0x0000c67e
#define GA102_DISP_WINDOW_IMM_CHANNEL_DMA              0x0000c67b
#define GF100_MSPDEC                                                 0x000090b2
#define GF100_MSPPP                                                  0x000090b3
#define GF100_MSVLD                                                  0x000090b1
#define GF110_DISP                                     0x00009070
#define GF110_DISP_BASE_CHANNEL_DMA                    0x0000907c
#define GF110_DISP_CORE_CHANNEL_DMA                    0x0000907d
#define GF110_DISP_CURSOR                              0x0000907a
#define GF110_DISP_OVERLAY                             0x0000907b
#define GF110_DISP_OVERLAY_CONTROL_DMA                 0x0000907e
#define GK104_DISP                                     0x00009170
#define GK104_DISP_BASE_CHANNEL_DMA                    0x0000917c
#define GK104_DISP_CORE_CHANNEL_DMA                    0x0000917d
#define GK104_DISP_CURSOR                              0x0000917a
#define GK104_DISP_OVERLAY                             0x0000917b
#define GK104_DISP_OVERLAY_CONTROL_DMA                 0x0000917e
#define GK104_MSPDEC                                                 0x000095b2
#define GK104_MSVLD                                                  0x000095b1
#define GK110_DISP                                     0x00009270
#define GK110_DISP_BASE_CHANNEL_DMA                    0x0000927c
#define GK110_DISP_CORE_CHANNEL_DMA                    0x0000927d
#define GM107_DISP                                     0x00009470
#define GM107_DISP_CORE_CHANNEL_DMA                    0x0000947d
#define GM200_DISP                                     0x00009570
#define GM200_DISP_CORE_CHANNEL_DMA                    0x0000957d
#define GP100_DISP                                     0x00009770
#define GP100_DISP_CORE_CHANNEL_DMA                    0x0000977d
#define GP102_DISP                                     0x00009870
#define GP102_DISP_CORE_CHANNEL_DMA                    0x0000987d
#define GT200_DISP                                     0x00008370
#define GT200_DISP_BASE_CHANNEL_DMA                    0x0000837c
#define GT200_DISP_CORE_CHANNEL_DMA                    0x0000837d
#define GT200_DISP_OVERLAY_CHANNEL_DMA                 0x0000837e
#define GT200_TESLA                                                  0x00008397
#define GT206_DISP                                     0x00008870
#define GT206_DISP_CORE_CHANNEL_DMA                    0x0000887d
#define GT212_DMA                                                    0x000085b5
#define GT212_MSPDEC                                                 0x000085b2
#define GT212_MSPPP                                                  0x000085b3
#define GT212_MSVLD                                                  0x000085b1
#define GT214_COMPUTE                                                0x000085c0
#define GT214_DISP                                     0x00008570
#define GT214_DISP_BASE_CHANNEL_DMA                    0x0000857c
#define GT214_DISP_CORE_CHANNEL_DMA                    0x0000857d
#define GT214_DISP_CURSOR                              0x0000857a
#define GT214_DISP_OVERLAY                             0x0000857b
#define GT214_DISP_OVERLAY_CHANNEL_DMA                 0x0000857e
#define GT214_TESLA                                                  0x00008597
#define GT21A_TESLA                                                  0x00008697
#define GV100_DISP                                     0x0000c370
#define GV100_DISP_CAPS                                              0x0000c373
#define GV100_DISP_CORE_CHANNEL_DMA                    0x0000c37d
#define GV100_DISP_CURSOR                              0x0000c37a
#define GV100_DISP_WINDOW_CHANNEL_DMA                  0x0000c37e
#define GV100_DISP_WINDOW_IMM_CHANNEL_DMA              0x0000c37b
#define IGT21A_MSVLD                                                 0x000086b1
#define KEPLER_A                                       0x0000a097
#define KEPLER_B                                       0x0000a197
#define KEPLER_C                                       0x0000a297
#define KEPLER_CHANNEL_GPFIFO_A                        0x0000a06f
#define KEPLER_CHANNEL_GPFIFO_B                        0x0000a16f
#define KEPLER_COMPUTE_A                                             0x0000a0c0
#define KEPLER_COMPUTE_B                                             0x0000a1c0
#define KEPLER_DMA_COPY_A                                            0x0000a0b5
#define KEPLER_INLINE_TO_MEMORY_A                                    0x0000a040
#define KEPLER_INLINE_TO_MEMORY_B                                    0x0000a140
#define MAXWELL_A                                      0x0000b097
#define MAXWELL_B                                      0x0000b197
#define MAXWELL_CHANNEL_GPFIFO_A                       0x0000b06f
#define MAXWELL_COMPUTE_A                                            0x0000b0c0
#define MAXWELL_COMPUTE_B                                            0x0000b1c0
#define MAXWELL_DMA_COPY_A                                           0x0000b0b5
#define MAXWELL_FAULT_BUFFER_A                         0x0000b069
#define NV03_CHANNEL_DMA                               0x0000006b
#define NV04_DISP                                      0x00000046
#define NV10_CHANNEL_DMA                               0x0000006e
#define NV17_CHANNEL_DMA                               0x0000176e
#define NV31_MPEG                                                    0x00003174
#define NV40_CHANNEL_DMA                               0x0000406e
#define NV50_CHANNEL_GPFIFO                            0x0000506f
#define NV50_COMPUTE                                                 0x000050c0
#define NV50_DISP                                      0x00005070
#define NV50_DISP_BASE_CHANNEL_DMA                     0x0000507c
#define NV50_DISP_CORE_CHANNEL_DMA                     0x0000507d
#define NV50_DISP_CURSOR                               0x0000507a
#define NV50_DISP_OVERLAY                              0x0000507b
#define NV50_DISP_OVERLAY_CHANNEL_DMA                  0x0000507e
#define NV50_MEMORY_TO_MEMORY_FORMAT                                 0x00005039
#define NV50_TESLA                                                   0x00005097
#define NV50_TWOD                                                    0x0000502d
#define NV74_BSP                                                     0x000074b0
#define NV74_CIPHER                                                  0x000074c1
#define NV74_VP2                                                     0x00007476
#define NVIF_CLASS_CLIENT                             -0x00000000
#define NVIF_CLASS_CONTROL                            -0x00000001
#define NVIF_CLASS_MEM                                 0x8000000a
#define NVIF_CLASS_MEM_GF100                           0x8000900b
#define NVIF_CLASS_MEM_NV04                            0x8000000b
#define NVIF_CLASS_MEM_NV50                            0x8000500b
#define NVIF_CLASS_MMU                                 0x80000008
#define NVIF_CLASS_MMU_GF100                           0x80009009
#define NVIF_CLASS_MMU_NV04                            0x80000009
#define NVIF_CLASS_MMU_NV50                            0x80005009
#define NVIF_CLASS_PERFDOM                            -0x00000003
#define NVIF_CLASS_PERFMON                            -0x00000002
#define NVIF_CLASS_SW_GF100                           -0x00000007
#define NVIF_CLASS_SW_NV04                            -0x00000004
#define NVIF_CLASS_SW_NV10                            -0x00000005
#define NVIF_CLASS_SW_NV50                            -0x00000006
#define NVIF_CLASS_VMM                                 0x8000000c
#define NVIF_CLASS_VMM_GF100                           0x8000900d
#define NVIF_CLASS_VMM_GM200                           0x8000b00d
#define NVIF_CLASS_VMM_GP100                           0x8000c00d
#define NVIF_CLASS_VMM_NV04                            0x8000000d
#define NVIF_CLASS_VMM_NV50                            0x8000500d
#define NV_DEVICE                                      0x00000080
#define NV_DMA_FROM_MEMORY                             0x00000002
#define NV_DMA_IN_MEMORY                               0x0000003d
#define NV_DMA_TO_MEMORY                               0x00000003
#define NV_NULL_CLASS                                                0x00000030
#define PASCAL_A                                       0x0000c097
#define PASCAL_B                                       0x0000c197
#define PASCAL_CHANNEL_GPFIFO_A                        0x0000c06f
#define PASCAL_COMPUTE_A                                             0x0000c0c0
#define PASCAL_COMPUTE_B                                             0x0000c1c0
#define PASCAL_DMA_COPY_A                                            0x0000c0b5
#define PASCAL_DMA_COPY_B                                            0x0000c1b5
#define TU102_DISP                                     0x0000c570
#define TU102_DISP_CORE_CHANNEL_DMA                    0x0000c57d
#define TU102_DISP_CURSOR                              0x0000c57a
#define TU102_DISP_WINDOW_CHANNEL_DMA                  0x0000c57e
#define TU102_DISP_WINDOW_IMM_CHANNEL_DMA              0x0000c57b
#define TURING_A                                       0x0000c597
#define TURING_CHANNEL_GPFIFO_A                        0x0000c46f
#define TURING_COMPUTE_A                                             0x0000c5c0
#define TURING_DMA_COPY_A                                            0x0000c5b5
#define VOLTA_A                                        0x0000c397
#define VOLTA_CHANNEL_GPFIFO_A                         0x0000c36f
#define VOLTA_COMPUTE_A                                              0x0000c3c0
#define VOLTA_DMA_COPY_A                                             0x0000c3b5
#define VOLTA_FAULT_BUFFER_A                           0x0000c369
#define VOLTA_USERMODE_A                                             0x0000c361

#define PUSH_HDR(p,o,n,s,m,c) do {                                        \
        PUSH_ASSERT(!((s) & ~DRF_MASK(NV06C_METHOD_SUBCHANNEL)), "subc"); \
        PUSH_ASSERT(!((m) & ~DRF_SMASK(NV06C_METHOD_ADDRESS)), "mthd");   \
        PUSH_ASSERT(!((c) & ~DRF_MASK(NV06C_METHOD_COUNT)), "count");     \
        PUSH_DATA__((p), NVVAL_X(NV06C_METHOD_ADDRESS, (m) >> 2) |        \
			 NVVAL_X(NV06C_METHOD_SUBCHANNEL, (s)) |          \
			 NVVAL_X(NV06C_METHOD_COUNT, (c)) |               \
			 NVVAL_X(NV06C_OPCODE, NV06C_OPCODE_##o),         \
		    " "n" subc %d mthd 0x%04x size %d - %s",              \
		    (u32)(s), (u32)(m), (u32)(c), __func__);              \
} while(0)
#define PUSH_JUMP(p,o) do {                                         \
        PUSH_ASSERT(!((o) & ~0x1fffffffcULL), "offset");            \
	PUSH_DATA__((p), NVVAL_X(NV06C_OPCODE, NV06C_OPCODE_JUMP) | \
			 NVVAL_X(NV06C_JUMP_OFFSET, (o) >> 2),      \
		    " jump 0x%08x - %s", (u32)(o), __func__);       \
} while(0)
#define PUSH_MTHD_HDR(p,c,m,n) PUSH_HDR(p, METHOD, "incr", PUSH006C_SUBC_##c, m, n)
#define PUSH_MTHD_INC 4:4
#define PUSH_NINC_HDR(p,c,m,n) PUSH_HDR(p, NONINC_METHOD, "ninc", PUSH006C_SUBC_##c, m, n)
#define PUSH_NINC_INC 0:0

#define NV06C_DATA                                                 31:0
#define NV06C_GET                                                  (0x00000044)
#define NV06C_GET_PTR                                              31:2
#define NV06C_JUMP_OFFSET                                          28:2
#define NV06C_METHOD_ADDRESS                                       12:2
#define NV06C_METHOD_COUNT                                         28:18
#define NV06C_METHOD_SUBCHANNEL                                    15:13
#define NV06C_OPCODE                                               31:29
#define NV06C_OPCODE_JUMP                                          (0x00000001)
#define NV06C_OPCODE_METHOD                                        (0x00000000)
#define NV06C_OPCODE_NONINC_METHOD                                 (0x00000002)
#define NV06C_PUT                                                  (0x00000040)
#define NV06C_PUT_PTR                                              31:2




#define DEFAULT_POLLMASK (EPOLLIN | EPOLLOUT | EPOLLRDNORM | EPOLLWRNORM)
#define M(X) __MAP(v, (__force __u16)EPOLL##X, POLL##X)
#define MAX_INT64_SECONDS (((s64)(~((u64)0)>>1)/HZ)-1)
#define MAX_STACK_ALLOC 768

#define __MAP(v, from, to) \
	(from < to ? (v & from) * (to/from) : (v & from) / (from/to))
#define EPOLL_CLOEXEC O_CLOEXEC
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
#define EPOLL_PACKED __attribute__((packed))

#define DRM_IOCTL_DEF_DRV(ioctl, _func, _flags)				\
	[DRM_IOCTL_NR(DRM_IOCTL_##ioctl) - DRM_COMMAND_BASE] = {	\
		.cmd = DRM_IOCTL_##ioctl,				\
		.func = _func,						\
		.flags = _flags,					\
		.name = #ioctl						\
	}
#define DRM_IOCTL_NR(n)                _IOC_NR(n)
#define DRM_IOCTL_TYPE(n)              _IOC_TYPE(n)
#define DRM_MAJOR       226

#define drm_compat_ioctl NULL

#define drm_gem_ttm_of_gem(gem_obj) \
	container_of(gem_obj, struct ttm_buffer_object, base)





#define CM_DRAW     (1)
#define CM_ERASE    (2)
#define CM_MOVE     (3)
#define VESA_HSYNC_SUSPEND      2
#define VESA_NO_BLANKING        0
#define VESA_POWERDOWN          3
#define VESA_VSYNC_SUSPEND      1
#define WARN_CONSOLE_UNLOCKED()						\
	WARN_ON(!atomic_read(&ignore_console_lock_warning) &&		\
		!is_console_locked() && !oops_in_progress)
#define _LINUX_CONSOLE_H_ 1
#define for_each_console(con) \
	for (con = console_drivers; con != NULL; con = con->next)
