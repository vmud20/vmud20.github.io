
#include<linux/fs.h>
#include<asm/types.h>




#include<asm/poll.h>

#include<linux/resource.h>


#include<asm/stat.h>






#include<stdarg.h>





#include<asm/fcntl.h>


#include<linux/time_types.h>




#include<linux/time.h>



#include<linux/stddef.h>










#include<linux/posix_types.h>





#include<asm/param.h>


#include<linux/errno.h>
#include<asm/byteorder.h>











#include<asm-generic/hugetlb_encode.h>

#include<linux/fcntl.h>

#include<asm/bitsperlong.h>





#include<linux/sched.h>

#include<linux/types.h>

#include<asm/auxvec.h>



#include<linux/rseq.h>

#include<linux/kernel.h>



#include<linux/string.h>



#include<linux/ipc.h>




#include<linux/param.h>

#include<asm/ptrace.h>


#include<asm/signal.h>






#include<linux/uuid.h>

#include<linux/pci_regs.h>

#include<string.h>
#include<asm/siginfo.h>

#include<asm/sembuf.h>






#include<linux/fiemap.h>
#include<linux/capability.h>


#include<linux/ioctl.h>
#include<linux/stat.h>






#include<linux/const.h>

#include<linux/limits.h>


#include<asm/errno.h>






#include<unistd.h>

#include<asm/shmbuf.h>





#include<asm/ipcbuf.h>



#include<linux/sysinfo.h>





#include<asm/resource.h>







#include<linux/dqblk_xfs.h>
#include<linux/sysctl.h>
#include<linux/pci.h>






#include<linux/wait.h>


#define VFIO_PCI_INDEX_TO_OFFSET(index)	((u64)(index) << VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_OFFSET_SHIFT   40
#define VFIO_PCI_OFFSET_TO_INDEX(off)	(off >> VFIO_PCI_OFFSET_SHIFT)

#define irq_is(vdev, type) (vdev->irq_type == type)
#define is_intx(vdev) (vdev->irq_type == VFIO_PCI_INTX_IRQ_INDEX)
#define is_irq_none(vdev) (!(is_intx(vdev) || is_msi(vdev) || is_msix(vdev)))
#define is_msi(vdev) (vdev->irq_type == VFIO_PCI_MSI_IRQ_INDEX)
#define is_msix(vdev) (vdev->irq_type == VFIO_PCI_MSIX_IRQ_INDEX)
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

#define init_completion(x) __init_completion(x)
#define init_completion_map(x, m) __init_completion(x)
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
	.head		= { &(name).head, &(name).head } }
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

#define __lockfunc __attribute__((section(".spinlock.text")))
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
# define raw_spin_lock_init(lock)				\
	do { *(lock) = __RAW_SPIN_LOCK_UNLOCKED(lock); } while (0)
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
#define ATOMIC_LONG_INIT(i)		ATOMIC64_INIT(i)


#define atomic64_add_negative atomic64_add_negative
#define atomic64_add_return atomic64_add_return
#define atomic64_add_return_acquire atomic64_add_return
#define atomic64_add_return_relaxed atomic64_add_return
#define atomic64_add_return_release atomic64_add_return
#define atomic64_add_unless atomic64_add_unless
#define atomic64_andnot atomic64_andnot
#define atomic64_cmpxchg atomic64_cmpxchg
#define atomic64_cmpxchg_acquire atomic64_cmpxchg
#define atomic64_cmpxchg_relaxed atomic64_cmpxchg
#define atomic64_cmpxchg_release atomic64_cmpxchg
#define atomic64_cond_read_acquire(v, c) smp_cond_load_acquire(&(v)->counter, (c))
#define atomic64_cond_read_relaxed(v, c) smp_cond_load_relaxed(&(v)->counter, (c))
#define atomic64_dec atomic64_dec
#define atomic64_dec_and_test atomic64_dec_and_test
#define atomic64_dec_if_positive atomic64_dec_if_positive
#define atomic64_dec_return atomic64_dec_return
#define atomic64_dec_return_acquire atomic64_dec_return
#define atomic64_dec_return_relaxed atomic64_dec_return
#define atomic64_dec_return_release atomic64_dec_return
#define atomic64_dec_unless_positive atomic64_dec_unless_positive
#define atomic64_fetch_add atomic64_fetch_add
#define atomic64_fetch_add_acquire atomic64_fetch_add
#define atomic64_fetch_add_relaxed atomic64_fetch_add
#define atomic64_fetch_add_release atomic64_fetch_add
#define atomic64_fetch_add_unless atomic64_fetch_add_unless
#define atomic64_fetch_and atomic64_fetch_and
#define atomic64_fetch_and_acquire atomic64_fetch_and
#define atomic64_fetch_and_relaxed atomic64_fetch_and
#define atomic64_fetch_and_release atomic64_fetch_and
#define atomic64_fetch_andnot atomic64_fetch_andnot
#define atomic64_fetch_andnot_acquire atomic64_fetch_andnot
#define atomic64_fetch_andnot_relaxed atomic64_fetch_andnot
#define atomic64_fetch_andnot_release atomic64_fetch_andnot
#define atomic64_fetch_dec atomic64_fetch_dec
#define atomic64_fetch_dec_acquire atomic64_fetch_dec
#define atomic64_fetch_dec_relaxed atomic64_fetch_dec
#define atomic64_fetch_dec_release atomic64_fetch_dec
#define atomic64_fetch_inc atomic64_fetch_inc
#define atomic64_fetch_inc_acquire atomic64_fetch_inc
#define atomic64_fetch_inc_relaxed atomic64_fetch_inc
#define atomic64_fetch_inc_release atomic64_fetch_inc
#define atomic64_fetch_or atomic64_fetch_or
#define atomic64_fetch_or_acquire atomic64_fetch_or
#define atomic64_fetch_or_relaxed atomic64_fetch_or
#define atomic64_fetch_or_release atomic64_fetch_or
#define atomic64_fetch_sub atomic64_fetch_sub
#define atomic64_fetch_sub_acquire atomic64_fetch_sub
#define atomic64_fetch_sub_relaxed atomic64_fetch_sub
#define atomic64_fetch_sub_release atomic64_fetch_sub
#define atomic64_fetch_xor atomic64_fetch_xor
#define atomic64_fetch_xor_acquire atomic64_fetch_xor
#define atomic64_fetch_xor_relaxed atomic64_fetch_xor
#define atomic64_fetch_xor_release atomic64_fetch_xor
#define atomic64_inc atomic64_inc
#define atomic64_inc_and_test atomic64_inc_and_test
#define atomic64_inc_not_zero atomic64_inc_not_zero
#define atomic64_inc_return atomic64_inc_return
#define atomic64_inc_return_acquire atomic64_inc_return
#define atomic64_inc_return_relaxed atomic64_inc_return
#define atomic64_inc_return_release atomic64_inc_return
#define atomic64_inc_unless_negative atomic64_inc_unless_negative
#define atomic64_read_acquire atomic64_read_acquire
#define atomic64_set_release atomic64_set_release
#define atomic64_sub_and_test atomic64_sub_and_test
#define atomic64_sub_return atomic64_sub_return
#define atomic64_sub_return_acquire atomic64_sub_return
#define atomic64_sub_return_relaxed atomic64_sub_return
#define atomic64_sub_return_release atomic64_sub_return
#define atomic64_try_cmpxchg atomic64_try_cmpxchg
#define atomic64_try_cmpxchg_acquire atomic64_try_cmpxchg
#define atomic64_try_cmpxchg_relaxed atomic64_try_cmpxchg
#define atomic64_try_cmpxchg_release atomic64_try_cmpxchg
#define atomic64_xchg atomic64_xchg
#define atomic64_xchg_acquire atomic64_xchg
#define atomic64_xchg_relaxed atomic64_xchg
#define atomic64_xchg_release atomic64_xchg
#define atomic_add_negative atomic_add_negative
#define atomic_add_return atomic_add_return
#define atomic_add_return_acquire atomic_add_return_acquire
#define atomic_add_return_relaxed atomic_add_return
#define atomic_add_return_release atomic_add_return_release
#define atomic_add_unless atomic_add_unless
#define atomic_andnot atomic_andnot
#define atomic_cmpxchg atomic_cmpxchg
#define atomic_cmpxchg_acquire atomic_cmpxchg
#define atomic_cmpxchg_relaxed atomic_cmpxchg
#define atomic_cmpxchg_release atomic_cmpxchg
#define atomic_cond_read_acquire(v, c) smp_cond_load_acquire(&(v)->counter, (c))
#define atomic_cond_read_relaxed(v, c) smp_cond_load_relaxed(&(v)->counter, (c))
#define atomic_dec atomic_dec
#define atomic_dec_and_test atomic_dec_and_test
#define atomic_dec_if_positive atomic_dec_if_positive
#define atomic_dec_return atomic_dec_return
#define atomic_dec_return_acquire atomic_dec_return
#define atomic_dec_return_relaxed atomic_dec_return
#define atomic_dec_return_release atomic_dec_return
#define atomic_dec_unless_positive atomic_dec_unless_positive
#define atomic_fetch_add atomic_fetch_add
#define atomic_fetch_add_acquire atomic_fetch_add
#define atomic_fetch_add_relaxed atomic_fetch_add
#define atomic_fetch_add_release atomic_fetch_add
#define atomic_fetch_add_unless atomic_fetch_add_unless
#define atomic_fetch_and atomic_fetch_and
#define atomic_fetch_and_acquire atomic_fetch_and
#define atomic_fetch_and_relaxed atomic_fetch_and
#define atomic_fetch_and_release atomic_fetch_and
#define atomic_fetch_andnot atomic_fetch_andnot
#define atomic_fetch_andnot_acquire atomic_fetch_andnot
#define atomic_fetch_andnot_relaxed atomic_fetch_andnot
#define atomic_fetch_andnot_release atomic_fetch_andnot
#define atomic_fetch_dec atomic_fetch_dec
#define atomic_fetch_dec_acquire atomic_fetch_dec
#define atomic_fetch_dec_relaxed atomic_fetch_dec
#define atomic_fetch_dec_release atomic_fetch_dec
#define atomic_fetch_inc atomic_fetch_inc
#define atomic_fetch_inc_acquire atomic_fetch_inc
#define atomic_fetch_inc_relaxed atomic_fetch_inc
#define atomic_fetch_inc_release atomic_fetch_inc
#define atomic_fetch_or atomic_fetch_or
#define atomic_fetch_or_acquire atomic_fetch_or
#define atomic_fetch_or_relaxed atomic_fetch_or
#define atomic_fetch_or_release atomic_fetch_or
#define atomic_fetch_sub atomic_fetch_sub
#define atomic_fetch_sub_acquire atomic_fetch_sub
#define atomic_fetch_sub_relaxed atomic_fetch_sub
#define atomic_fetch_sub_release atomic_fetch_sub
#define atomic_fetch_xor atomic_fetch_xor
#define atomic_fetch_xor_acquire atomic_fetch_xor
#define atomic_fetch_xor_relaxed atomic_fetch_xor
#define atomic_fetch_xor_release atomic_fetch_xor
#define atomic_inc atomic_inc
#define atomic_inc_and_test atomic_inc_and_test
#define atomic_inc_not_zero atomic_inc_not_zero
#define atomic_inc_return atomic_inc_return
#define atomic_inc_return_acquire atomic_inc_return
#define atomic_inc_return_relaxed atomic_inc_return
#define atomic_inc_return_release atomic_inc_return
#define atomic_inc_unless_negative atomic_inc_unless_negative
#define atomic_read_acquire atomic_read_acquire
#define atomic_set_release atomic_set_release
#define atomic_sub_and_test atomic_sub_and_test
#define atomic_sub_return atomic_sub_return
#define atomic_sub_return_acquire atomic_sub_return
#define atomic_sub_return_relaxed atomic_sub_return
#define atomic_sub_return_release atomic_sub_return
#define atomic_try_cmpxchg atomic_try_cmpxchg
#define atomic_try_cmpxchg_acquire atomic_try_cmpxchg
#define atomic_try_cmpxchg_relaxed atomic_try_cmpxchg
#define atomic_try_cmpxchg_release atomic_try_cmpxchg
#define atomic_xchg atomic_xchg
#define atomic_xchg_acquire atomic_xchg
#define atomic_xchg_relaxed atomic_xchg
#define atomic_xchg_release atomic_xchg
#define cmpxchg(...) \
	__atomic_op_fence(cmpxchg, __VA_ARGS__)
#define cmpxchg64(...) \
	__atomic_op_fence(cmpxchg64, __VA_ARGS__)
#define cmpxchg64_acquire(...) \
	__atomic_op_acquire(cmpxchg64, __VA_ARGS__)
#define cmpxchg64_release(...) \
	__atomic_op_release(cmpxchg64, __VA_ARGS__)
#define cmpxchg_acquire(...) \
	__atomic_op_acquire(cmpxchg, __VA_ARGS__)
#define cmpxchg_release(...) \
	__atomic_op_release(cmpxchg, __VA_ARGS__)
#define xchg(...) \
	__atomic_op_fence(xchg, __VA_ARGS__)
#define xchg_acquire(...) \
	__atomic_op_acquire(xchg, __VA_ARGS__)
#define xchg_release(...) \
	__atomic_op_release(xchg, __VA_ARGS__)
#define ATOMIC64_FETCH_OP(op)						\
extern s64 atomic64_fetch_##op(s64 a, atomic64_t *v);
#define ATOMIC64_INIT(i)	{ (i) }
#define ATOMIC64_OP(op)							\
extern void	 atomic64_##op(s64 a, atomic64_t *v);
#define ATOMIC64_OPS(op)	ATOMIC64_OP(op) ATOMIC64_OP_RETURN(op) ATOMIC64_FETCH_OP(op)
#define ATOMIC64_OP_RETURN(op)						\
extern s64 atomic64_##op##_return(s64 a, atomic64_t *v);

#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]








#define pgoff_t unsigned long
#define rcu_head callback_head

#define __aligned_be64 __be64 __attribute__((aligned(8)))
#define __aligned_le64 __le64 __attribute__((aligned(8)))
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#define __bitwise __bitwise__
#define __bitwise__ __attribute__((bitwise))

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
#define DEFINE_RAW_SPINLOCK(x)	raw_spinlock_t x = __RAW_SPIN_LOCK_UNLOCKED(x)
#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
# define LOCK_PADSIZE (offsetof(struct raw_spinlock, dep_map))
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
	{					\
	.raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,	\
	SPIN_DEBUG_INIT(lockname)		\
	RAW_SPIN_DEP_MAP_INIT(lockname) }
#define __RAW_SPIN_LOCK_UNLOCKED(lockname)	\
	(raw_spinlock_t) __RAW_SPIN_LOCK_INITIALIZER(lockname)
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
# define RW_DEP_MAP_INIT(lockname)					\
	.dep_map = {							\
		.name = #lockname,					\
		.wait_type_inner = LD_WAIT_CONFIG,			\
	}

#define __RW_LOCK_UNLOCKED(lockname)					\
	(rwlock_t)	{	.raw_lock = __ARCH_RW_LOCK_UNLOCKED,	\
				.magic = RWLOCK_MAGIC,			\
				.owner = SPINLOCK_OWNER_INIT,		\
				.owner_cpu = -1,			\
				RW_DEP_MAP_INIT(lockname) }
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
# define lockdep_assert_RT_in_threaded_ctx() do {			\
		WARN_ONCE(debug_locks && !current->lockdep_recursion &&	\
			  current->hardirq_context &&			\
			  !(current->hardirq_threaded || current->irq_config),	\
			  "Not in threaded context on PREEMPT_RT as expected\n");	\
} while (0)
#define lockdep_assert_held(l)	do {				\
		WARN_ON(debug_locks && !lockdep_is_held(l));	\
	} while (0)
#define lockdep_assert_held_once(l)	do {				\
		WARN_ON_ONCE(debug_locks && !lockdep_is_held(l));	\
	} while (0)
#define lockdep_assert_held_read(l)	do {				\
		WARN_ON(debug_locks && !lockdep_is_held_type(l, 1));	\
	} while (0)
#define lockdep_assert_held_write(l)	do {			\
		WARN_ON(debug_locks && !lockdep_is_held_type(l, 0));	\
	} while (0)
# define lockdep_assert_in_irq() do { } while (0)
# define lockdep_assert_irqs_disabled() do { } while (0)
# define lockdep_assert_irqs_enabled() do { } while (0)
#define lockdep_depth(tsk)	(debug_locks ? (tsk)->lockdep_depth : 0)
# define lockdep_free_key_range(start, size)	do { } while (0)
# define lockdep_init()				do { } while (0)
# define lockdep_init_map(lock, name, key, sub) \
		do { (void)(name); (void)(key); } while (0)
#define lockdep_init_map_crosslock(m, n, k, s) do {} while (0)
# define lockdep_init_map_wait(lock, name, key, sub, inner) \
		do { (void)(name); (void)(key); } while (0)
# define lockdep_init_map_waits(lock, name, key, sub, inner, outer) \
		do { (void)(name); (void)(key); } while (0)
#define lockdep_is_held(lock)		lock_is_held(&(lock)->dep_map)
#define lockdep_is_held_type(lock, r)	lock_is_held_type(&(lock)->dep_map, (r))
#define lockdep_match_class(lock, key) lockdep_match_key(&(lock)->dep_map, key)
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
# define might_lock(lock) 						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 0, 1, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, _THIS_IP_);			\
} while (0)
# define might_lock_nested(lock, subclass) 				\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, subclass, 0, 1, 1, NULL,		\
		     _THIS_IP_);					\
	lock_release(&(lock)->dep_map, _THIS_IP_);			\
} while (0)
# define might_lock_read(lock) 						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 1, 1, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, _THIS_IP_);			\
} while (0)
#define mutex_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define mutex_acquire_nest(l, s, t, n, i)	lock_acquire_exclusive(l, s, t, n, i)
#define mutex_release(l, i)			lock_release(l, i)
#define rwlock_acquire(l, s, t, i)		lock_acquire_exclusive(l, s, t, NULL, i)
#define rwlock_acquire_read(l, s, t, i)		lock_acquire_shared_recursive(l, s, t, NULL, i)
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
		if (debug_locks_off() && !debug_locks_silent)		\
			WARN(1, "DEBUG_LOCKS_WARN_ON(%s)", #c);		\
		__ret = 1;						\
	}								\
	__ret;								\
})
# define SMP_DEBUG_LOCKS_WARN_ON(c)			DEBUG_LOCKS_WARN_ON(c)

# define locking_selftest()	do { } while (0)
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
#define WARN_ONCE(condition, format...)	({			\
	static bool __section(.data.once) __warned;		\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once && !__warned)) {		\
		__warned = true;				\
		WARN(1, format);				\
	}							\
	unlikely(__ret_warn_once);				\
})
#define WARN_ON_ONCE(condition)	({				\
	static bool __section(.data.once) __warned;		\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once && !__warned)) {		\
		__warned = true;				\
		WARN_ON(1);					\
	}							\
	unlikely(__ret_warn_once);				\
})
# define WARN_ON_SMP(x)			WARN_ON(x)
#define WARN_TAINT(condition, taint, format...) ({			\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN_printf(taint, format);				\
	unlikely(__ret_warn_on);					\
})
#define WARN_TAINT_ONCE(condition, taint, format...)	({	\
	static bool __section(.data.once) __warned;		\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once && !__warned)) {		\
		__warned = true;				\
		WARN_TAINT(1, taint, format);			\
	}							\
	unlikely(__ret_warn_once);				\
})

#define __WARN()		__WARN_printf(TAINT_WARN, NULL)
#define __WARN_printf(taint, arg...)					\
	warn_slowpath_fmt("__FILE__", "__LINE__", taint, arg)
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ALIGN_DOWN(x, a)	__ALIGN_KERNEL((x) - ((a) - 1), (a))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define CONCATENATE(a, b) __CONCAT(a, b)
#define COUNT_ARGS(X...) __COUNT_ARGS(, ##X, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
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
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))
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
#define __ALIGN_MASK(x, mask)	__ALIGN_KERNEL_MASK((x), (mask))
#define __CONCAT(a, b) a ## b
#define __COUNT_ARGS(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _n, X...) _n
#define __abs_choose_expr(x, type, other) __builtin_choose_expr(	\
	__builtin_types_compatible_p(typeof(x),   signed type) ||	\
	__builtin_types_compatible_p(typeof(x), unsigned type),		\
	({ signed type __x = (x); __x < 0 ? -__x : __x; }), other)
#define __careful_cmp(x, y, op) \
	__builtin_choose_expr(__safe_cmp(x, y), \
		__cmp(x, y, op), \
		__cmp_once(x, y, __UNIQUE_ID(__x), __UNIQUE_ID(__y), op))
#define __cmp(x, y, op)	((x) op (y) ? (x) : (y))
#define __cmp_once(x, y, unique_x, unique_y, op) ({	\
		typeof(x) unique_x = (x);		\
		typeof(y) unique_y = (y);		\
		__cmp(unique_x, unique_y, op); })
#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))
#define __no_side_effects(x, y) \
		(__is_constexpr(x) && __is_constexpr(y))
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define __safe_cmp(x, y) \
		(__typecheck(x, y) && __no_side_effects(x, y))
#define __trace_printk_check_format(fmt, args...)			\
do {									\
	if (0)								\
		____trace_printk_check_format(fmt, ##args);		\
} while (0)
#define __typecheck(x, y) \
		(!!(sizeof((typeof(x) *)1 == (typeof(y) *)1)))
#define abs(x)	__abs_choose_expr(x, long long,				\
		__abs_choose_expr(x, long,				\
		__abs_choose_expr(x, int,				\
		__abs_choose_expr(x, short,				\
		__abs_choose_expr(x, char,				\
		__builtin_choose_expr(					\
			__builtin_types_compatible_p(typeof(x), char),	\
			(char)({ signed char __x = (x); __x<0?-__x:__x; }), \
			((void)0)))))))
# define cant_migrate()		cant_sleep()
# define cant_sleep() \
	do { __cant_sleep("__FILE__", "__LINE__", 0); } while (0)
#define clamp(val, lo, hi) min((typeof(val))max(val, lo), hi)
#define clamp_t(type, val, lo, hi) min_t(type, max_t(type, val, lo), hi)
#define clamp_val(val, lo, hi) clamp_t(typeof(val), val, lo, hi)
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
		__attribute__((section("__trace_printk_fmt"))) =	\
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
		  __attribute__((section("__trace_printk_fmt"))) =	\
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
#define lower_32_bits(n) ((u32)(n))
#define max(x, y)	__careful_cmp(x, y, >)
#define max3(x, y, z) max((typeof(x))max(x, y), z)
#define max_t(type, x, y)	__careful_cmp((type)(x), (type)(y), >)
#define might_fault() __might_fault("__FILE__", "__LINE__")
# define might_resched() _cond_resched()
# define might_sleep() \
	do { __might_sleep("__FILE__", "__LINE__", 0); might_resched(); } while (0)
#define might_sleep_if(cond) do { if (cond) might_sleep(); } while (0)
#define min(x, y)	__careful_cmp(x, y, <)
#define min3(x, y, z) min((typeof(x))min(x, y), z)
#define min_not_zero(x, y) ({			\
	typeof(x) __x = (x);			\
	typeof(y) __y = (y);			\
	__x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y)); })
#define min_t(type, x, y)	__careful_cmp((type)(x), (type)(y), <)
#define mult_frac(x, numer, denom)(			\
{							\
	typeof(x) quot = (x) / (denom);			\
	typeof(x) rem  = (x) % (denom);			\
	(quot * (numer)) + ((rem * (numer)) / (denom));	\
}							\
)
# define non_block_end() WARN_ON(current->non_block_count-- == 0)
# define non_block_start() (current->non_block_count++)
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
# define sched_annotate_sleep()	(current->task_state_change = 0)
#define sector_div(a, b) do_div(a, b)
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
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
		__attribute__((section("__trace_printk_fmt"))) =	\
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
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))

#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
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
# define ASM_UNREACHABLE
# define KENTRY(sym)						\
	extern typeof(sym) sym;					\
	static const unsigned long __kentry_##sym		\
	__used							\
	__section("___kentry" "+" #sym )			\
	= (unsigned long)&sym;
#define OPTIMIZER_HIDE_VAR(var)						\
	__asm__ ("" : "=r" (var) : "0" (var))
#define READ_ONCE(x) __READ_ONCE(x, 1)
#define READ_ONCE_NOCHECK(x) __READ_ONCE(x, 0)
# define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })
#define WRITE_ONCE(x, val) \
({							\
	union { typeof(x) __val; char __c[1]; } __u =	\
		{ .__val = (__force typeof(x)) (val) }; \
	__write_once_size(&(x), __u.__c, sizeof(x));	\
	__u.__val;					\
})
#define __ADDRESSABLE(sym) \
	static void * __section(.discard.addressable) __used \
		__PASTE(__addressable_##sym, "__LINE__") = (void *)&sym;

#define __READ_ONCE(x, check)						\
({									\
	union { typeof(x) __val; char __c[1]; } __u;			\
	if (check)							\
		__read_once_size(&(x), __u.__c, sizeof(x));		\
	else								\
		__read_once_size_nocheck(&(x), __u.__c, sizeof(x));	\
	smp_read_barrier_depends();  \
	__u.__val;							\
})

#define __annotate_jump_table __section(.rodata..c_jump_table)
#define __branch_check__(x, expect, is_constant) ({			\
			long ______r;					\
			static struct ftrace_likely_data		\
				__aligned(4)				\
				__section(_ftrace_annotated_branch)	\
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
# define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)
# define __compiletime_error(message)
# define __compiletime_object_size(obj) -1
# define __compiletime_warning(message)
#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))
# define __no_kasan_or_inline __no_sanitize_address notrace __maybe_unused
#define __trace_if_value(cond) ({			\
	static struct ftrace_branch_data		\
		__aligned(4)				\
		__section(_ftrace_branch)		\
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
#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)
#define annotate_reachable() ({						\
	asm volatile("%c0:\n\t"						\
		     ".pushsection .discard.reachable\n\t"		\
		     ".long %c0b - .\n\t"				\
		     ".popsection\n\t" : : "i" (__COUNTER__));		\
})
#define annotate_unreachable() ({					\
	asm volatile("%c0:\n\t"						\
		     ".pushsection .discard.unreachable\n\t"		\
		     ".long %c0b - .\n\t"				\
		     ".popsection\n\t" : : "i" (__COUNTER__));		\
})
# define barrier() __memory_barrier()
# define barrier_before_unreachable() do { } while (0)
# define barrier_data(ptr) barrier()
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
#define compiletime_assert_atomic_type(t)				\
	compiletime_assert(__native_word(t),				\
		"Need native word sized stores/loads for atomicity.")
#define if(cond, ...) if ( __trace_if_var( !!(cond , ## __VA_ARGS__) ) )
#  define likely(x)	(__branch_check__(x, 1, __builtin_constant_p(x)))
#define likely_notrace(x)	__builtin_expect(!!(x), 1)
#define prevent_tail_call_optimization()	mb()
#  define unlikely(x)	(__branch_check__(x, 0, __builtin_constant_p(x)))
#define unlikely_notrace(x)	__builtin_expect(!!(x), 0)
# define unreachable() do {		\
	annotate_unreachable();		\
	__builtin_unreachable();	\
} while (0)

#define kasan_check_read __kasan_check_read
#define kasan_check_write __kasan_check_write
# define ACCESS_PRIVATE(p, member) (*((typeof((p)->member) __force *) &(p)->member))

#define __PASTE(a,b) ___PASTE(a,b)
#define ___PASTE(a,b) a##b
# define __acquire(x)	__context__(x,1)
# define __acquires(x)	__attribute__((context(x,0,1)))
# define __builtin_warning(x, y...) (1)
# define __chk_io_ptr(x) (void)0
# define __chk_user_ptr(x) (void)0
#define __compiler_offsetof(a, b)	__builtin_offsetof(a, b)
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
#define __inline__ inline
#define __inline_maybe_unused __maybe_unused
# define __iomem
# define __kernel
# define __latent_entropy

# define __must_hold(x)	__attribute__((context(x,1,1)))
#define __native_word(t) \
	(sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || \
	 sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))
# define __no_fgcse
# define __no_randomize_layout
# define __nocast
# define __percpu
# define __private
# define __randomize_layout __designated_init
# define __rcu
# define __release(x)	__context__(x,-1)
# define __releases(x)	__attribute__((context(x,1,0)))
# define __safe
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#  define __user __attribute__((user))
#define asm_inline asm __inline
#define asm_volatile_goto(x...) asm goto(x)
#define inline inline __gnu_inline __inline_maybe_unused notrace
#define noinline_for_stack noinline
# define randomized_struct_fields_end
# define randomized_struct_fields_start
#define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
#define GCC_VERSION ("__GNUC__" * 10000		\
		     + "__GNUC_MINOR__" * 100	\
		     + "__GNUC_PATCHLEVEL__")
#define KASAN_ABI_VERSION 5



#define __diag_GCC_8(s)		__diag(s)
#define __diag_str(s)		__diag_str1(s)
#define __diag_str1(s)		#s
#define __no_sanitize_address __attribute__((no_sanitize_address))
#define __noretpoline __attribute__((__indirect_branch__("keep")))
#define uninitialized_var(x) x = x
#define __builtin_bswap16 _bswap16

# define __GCC4_has_attribute___assume_aligned__      ("__GNUC_MINOR__" >= 9)
# define __GCC4_has_attribute___copy__                0
# define __GCC4_has_attribute___designated_init__     0
# define __GCC4_has_attribute___externally_visible__  1
# define __GCC4_has_attribute___fallthrough__         0
# define __GCC4_has_attribute___no_sanitize_address__ ("__GNUC_MINOR__" >= 8)
# define __GCC4_has_attribute___noclone__             1
# define __GCC4_has_attribute___nonstring__           0

#define __alias(symbol)                 __attribute__((__alias__(#symbol)))
#define __aligned(x)                    __attribute__((__aligned__(x)))
#define __aligned_largest               __attribute__((__aligned__))
#define __always_inline                 inline __attribute__((__always_inline__))
#define __always_unused                 __attribute__((__unused__))
# define __assume_aligned(a, ...)       __attribute__((__assume_aligned__(a, ## __VA_ARGS__)))
#define __attribute_const__             __attribute__((__const__))
#define __cold                          __attribute__((__cold__))
# define __copy(symbol)                 __attribute__((__copy__(symbol)))

# define __designated_init              __attribute__((__designated_init__))
#define __gnu_inline                    __attribute__((__gnu_inline__))
# define __has_attribute(x) __GCC4_has_attribute_##x
#define __malloc                        __attribute__((__malloc__))
#define __maybe_unused                  __attribute__((__unused__))
#define __mode(x)                       __attribute__((__mode__(x)))
# define __noclone                      __attribute__((__noclone__))
# define __nonstring                    __attribute__((__nonstring__))
#define __noreturn                      __attribute__((__noreturn__))
#define __packed                        __attribute__((__packed__))
#define __printf(a, b)                  __attribute__((__format__(printf, a, b)))
#define __pure                          __attribute__((__pure__))
#define __scanf(a, b)                   __attribute__((__format__(scanf, a, b)))
#define __section(S)                    __attribute__((__section__(#S)))
#define __used                          __attribute__((__used__))
# define __visible                      __attribute__((__externally_visible__))
#define __weak                          __attribute__((__weak__))
# define fallthrough                    __attribute__((__fallthrough__))
#define   noinline                      __attribute__((__noinline__))
#define CONSOLE_LOGLEVEL_DEFAULT CONFIG_CONSOLE_LOGLEVEL_DEFAULT
#define CONSOLE_LOGLEVEL_MOTORMOUTH 15	
#define CONSOLE_LOGLEVEL_SILENT  0 
#define DEVKMSG_STR_MAX_SIZE 10
#define MESSAGE_LOGLEVEL_DEFAULT CONFIG_MESSAGE_LOGLEVEL_DEFAULT
#define PRINTK_MAX_SINGLE_HEADER_LEN 2

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
#define pr_cont_once(fmt, ...)					\
	printk_once(KERN_CONT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit(fmt, ...) \
	printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_once(fmt, ...)					\
	printk_once(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_ratelimited(fmt, ...)					\
	printk_ratelimited(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug(fmt, ...) \
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
#define printk_deferred_once(fmt, ...)				\
({								\
	static bool __section(.data.once) __print_once;		\
	bool __ret_print_once = !__print_once;			\
								\
	if (!__print_once) {					\
		__print_once = true;				\
		printk_deferred(fmt, ##__VA_ARGS__);		\
	}							\
	unlikely(__ret_print_once);				\
})
#define printk_once(fmt, ...)					\
({								\
	static bool __section(.data.once) __print_once;		\
	bool __ret_print_once = !__print_once;			\
								\
	if (!__print_once) {					\
		__print_once = true;				\
		printk(fmt, ##__VA_ARGS__);			\
	}							\
	unlikely(__ret_print_once);				\
})
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
	__attribute__((section("__verbose"))) name = {		\
		.modname = KBUILD_MODNAME,			\
		.function = __func__,				\
		.filename = "__FILE__",				\
		.format = (fmt),				\
		.lineno = "__LINE__",				\
		.flags = _DPRINTK_FLAGS_DEFAULT,		\
		_DPRINTK_KEY_INIT				\
	}
#define DYNAMIC_DEBUG_BRANCH(descriptor) \
	static_branch_unlikely(&descriptor.key.dd_key_false)
#define _DPRINTK_FLAGS_DEFAULT _DPRINTK_FLAGS_PRINT
#define _DPRINTK_KEY_INIT .key.dd_key_false = (STATIC_KEY_FALSE_INIT)

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
#define ERESTART_RESTARTBLOCK 516 


#define __FORTIFY_INLINE extern __always_inline __attribute__((gnu_inline))
#define __RENAME(x) __asm__(#x)
#define memcat_p(a, b) ({					\
	BUILD_BUG_ON_MSG(!__same_type(*(a), *(b)),		\
			 "type mismatch in memcat_p()");	\
	(typeof(*a) *)__memcat_p((void **)(a), (void **)(b));	\
})
#define sysfs_match_string(_a, _s) __sysfs_match_string(_a, ARRAY_SIZE(_a), _s)

#define NULL ((void *)0)

#define offsetof(TYPE, MEMBER)	__compiler_offsetof(TYPE, MEMBER)
#define offsetofend(TYPE, MEMBER) \
	(offsetof(TYPE, MEMBER)	+ sizeof_field(TYPE, MEMBER))
#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))
#define DECLARE_STATIC_KEY_FALSE(name)	\
	extern struct static_key_false name
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
	likely(branch);								\
})
#define static_branch_unlikely(x)						\
({										\
	bool branch;								\
	if (__builtin_types_compatible_p(typeof(*x), struct static_key_true))	\
		branch = arch_static_branch_jump(&(x)->key, false);		\
	else if (__builtin_types_compatible_p(typeof(*x), struct static_key_false)) \
		branch = arch_static_branch(&(x)->key, false);			\
	else									\
		branch = ____wrong_branch_error();				\
	unlikely(branch);							\
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
#define INTERNODE_CACHE_SHIFT L1_CACHE_SHIFT
#define L1_CACHE_ALIGN(x) __ALIGN_KERNEL(x, L1_CACHE_BYTES)
#define SMP_CACHE_BYTES L1_CACHE_BYTES

#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#define ____cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))
#define __cacheline_aligned_in_smp __cacheline_aligned

#define __ro_after_init __attribute__((__section__(".data..ro_after_init")))
#define cache_line_size()	L1_CACHE_BYTES
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
#define EXPORT_SYMBOL_GPL_FUTURE(sym)	_EXPORT_SYMBOL(sym, "_gpl_future")
#define EXPORT_SYMBOL_NS(sym, ns)	__EXPORT_SYMBOL(sym, "", #ns)
#define EXPORT_SYMBOL_NS_GPL(sym, ns)	__EXPORT_SYMBOL(sym, "_gpl", #ns)
#define EXPORT_UNUSED_SYMBOL(sym)	_EXPORT_SYMBOL(sym, "_unused")
#define EXPORT_UNUSED_SYMBOL_GPL(sym)	_EXPORT_SYMBOL(sym, "_unused_gpl")
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
#define __cond_export_sym_1(sym, sec, ns) ___EXPORT_SYMBOL(sym, sec, ns)
#define __ksym_marker(sym)	\
	static int __ksym_marker_##sym[0] __section(".discard.ksym") __used

#define __stringify(x...)	__stringify_1(x)
#define __stringify_1(x...)	#x


#define __MEMINIT        .section	".meminit.text", "ax"
#define __MEMINITDATA    .section	".meminit.data", "aw"
#define __MEMINITRODATA  .section	".meminit.rodata", "a"
#define __REF            .section       ".ref.text", "ax"
#define __REFCONST       .section       ".ref.rodata", "a"
#define __REFDATA        .section       ".ref.data", "aw"
#define ___define_initcall(fn, id, __sec)			\
	__ADDRESSABLE(fn)					\
	asm(".section	\"" #__sec ".init\", \"a\"	\n"	\
	"__initcall_" #fn #id ":			\n"	\
	    ".long	" #fn " - .			\n"	\
	    ".previous					\n");
#define __define_initcall(fn, id) ___define_initcall(fn, id, .initcall##id)
#define __exit          __section(.exit.text) __exitused __cold notrace
#define __exit_p(x) x
#define __exitcall(fn)						\
	static exitcall_t __exitcall_##fn __exit_call = fn
#define __exitused  __used
#define __initcall(fn) device_initcall(fn)
#define __memexit        __section(.memexit.text) __exitused __cold notrace
#define __memexitconst   __section(.memexit.rodata)
#define __memexitdata    __section(.memexit.data)
#define __meminit        __section(.meminit.text) __cold notrace \
						  __latent_entropy
#define __meminitconst   __section(.meminit.rodata)
#define __meminitdata    __section(.meminit.data)
#define __noinitretpoline __noretpoline
#define __nosavedata __section(.data..nosave)
#define __ref            __section(.ref.text) noinline
#define __refconst       __section(.ref.rodata)
#define __refdata        __section(.ref.data)
#define __setup(str, fn)						\
	__setup_param(str, fn, fn, 0)
#define __setup_param(str, unique_id, fn, early)			\
	static const char __setup_str_##unique_id[] __initconst		\
		__aligned(1) = str; 					\
	static struct obs_kernel_param __setup_##unique_id		\
		__used __section(.init.setup)				\
		__attribute__((aligned((sizeof(long)))))		\
		= { __setup_str_##unique_id, fn, early }
#define arch_initcall(fn)		__define_initcall(fn, 3)
#define arch_initcall_sync(fn)		__define_initcall(fn, 3s)
#define console_initcall(fn)	___define_initcall(fn,, .con_initcall)
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
	__setup_param(str_on, parse_##var##_on, parse_##var##_on, 1);	\
									\
	static int __init parse_##var##_off(char *arg)			\
	{								\
		var = 0;						\
		return 0;						\
	}								\
	__setup_param(str_off, parse_##var##_off, parse_##var##_off, 1)
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
	const_ilog2(n) :		\
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
		(n == 1) ? 1 :			\
		(1UL << (ilog2((n) - 1) + 1))	\
				   ) :		\
	__roundup_pow_of_two(n)			\
 )
#define BITS_PER_TYPE(type)	(sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_BYTES(nr)	DIV_ROUND_UP(nr, BITS_PER_TYPE(char))
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_TYPE(long))
#define BITS_TO_U32(nr)		DIV_ROUND_UP(nr, BITS_PER_TYPE(u32))
#define BITS_TO_U64(nr)		DIV_ROUND_UP(nr, BITS_PER_TYPE(u64))

#  define aligned_byte_mask(n) (~0xffUL << (BITS_PER_LONG - 8 - 8*(n)))
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
#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_ULL(nr)		(ULL(1) << (nr))
#define BIT_ULL_MASK(nr)	(ULL(1) << ((nr) % BITS_PER_LONG_LONG))
#define BIT_ULL_WORD(nr)	((nr) / BITS_PER_LONG_LONG)
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)
#define GENMASK(h, l) \
	(GENMASK_INPUT_CHECK(h, l) + __GENMASK(h, l))
#define GENMASK_INPUT_CHECK(h, l) \
	(BUILD_BUG_ON_ZERO(__builtin_choose_expr( \
		__builtin_constant_p((l) > (h)), (l) > (h), 0)))
#define GENMASK_ULL(h, l) \
	(GENMASK_INPUT_CHECK(h, l) + __GENMASK_ULL(h, l))
#define __GENMASK(h, l) \
	(((~UL(0)) - (UL(1) << (l)) + 1) & \
	 (~UL(0) >> (BITS_PER_LONG - 1 - (h))))
#define __GENMASK_ULL(h, l) \
	(((~ULL(0)) - (ULL(1) << (l)) + 1) & \
	 (~ULL(0) >> (BITS_PER_LONG_LONG - 1 - (h))))

#define BIT(nr)			(UL(1) << (nr))

#define UL(x)		(_UL(x))
#define ULL(x)		(_ULL(x))

#define _AC(X,Y)	X
#define _AT(T,X)	X
#define _BITUL(x)	(_UL(1) << (x))
#define _BITULL(x)	(_ULL(1) << (x))

#define _UL(x)		(_AC(x, UL))
#define _ULL(x)		(_AC(x, ULL))
#define __AC(X,Y)	(X##Y)



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
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_next_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_continue_reverse(pos, head, member)		\
	for (pos = list_prev_entry(pos, member);			\
	     &pos->member != (head);					\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_from(pos, head, member) 			\
	for (; &pos->member != (head);					\
	     pos = list_next_entry(pos, member))
#define list_for_each_entry_from_reverse(pos, head, member)		\
	for (; &pos->member != (head);					\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_last_entry(head, typeof(*pos), member);		\
	     &pos->member != (head); 					\
	     pos = list_prev_entry(pos, member))
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     &pos->member != (head); 					\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_continue(pos, n, head, member) 		\
	for (pos = list_next_entry(pos, member), 				\
		n = list_next_entry(pos, member);				\
	     &pos->member != (head);						\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_from(pos, n, head, member) 			\
	for (n = list_next_entry(pos, member);					\
	     &pos->member != (head);						\
	     pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_last_entry(head, typeof(*pos), member),		\
		n = list_prev_entry(pos, member);			\
	     &pos->member != (head); 					\
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
#define LIST_POISON1  ((void *) 0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void *) 0x122 + POISON_POINTER_DELTA)
#define PAGE_POISON 0x00
# define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)


#define SOFTIRQ_LOCK_OFFSET (SOFTIRQ_DISABLE_OFFSET + PREEMPT_LOCK_OFFSET)
#define __IRQ_MASK(x)	((1UL << (x))-1)

#define __preempt_count_dec() __preempt_count_sub(1)
#define __preempt_count_inc() __preempt_count_add(1)
#define hardirq_count()	(preempt_count() & HARDIRQ_MASK)
#define in_atomic()	(preempt_count() != 0)
#define in_atomic_preempt_off() (preempt_count() != PREEMPT_DISABLE_OFFSET)
#define in_interrupt()		(irq_count())
#define in_irq()		(hardirq_count())
#define in_nmi()		(preempt_count() & NMI_MASK)
#define in_serving_softirq()	(softirq_count() & SOFTIRQ_OFFSET)
#define in_softirq()		(softirq_count())
#define in_task()		(!(preempt_count() & \
				   (NMI_MASK | HARDIRQ_MASK | SOFTIRQ_OFFSET)))
#define irq_count()	(preempt_count() & (HARDIRQ_MASK | SOFTIRQ_MASK \
				 | NMI_MASK))
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
#define softirq_count()	(preempt_count() & SOFTIRQ_MASK)

#define clear_thread_flag(flag) \
	clear_ti_thread_flag(current_thread_info(), flag)
#define current_thread_info() ((struct thread_info *)current)
#define set_thread_flag(flag) \
	set_ti_thread_flag(current_thread_info(), flag)
#define test_and_clear_thread_flag(flag) \
	test_and_clear_ti_thread_flag(current_thread_info(), flag)
#define test_and_set_thread_flag(flag) \
	test_and_set_ti_thread_flag(current_thread_info(), flag)
#define test_thread_flag(flag) \
	test_ti_thread_flag(current_thread_info(), flag)
#define tif_need_resched() test_thread_flag(TIF_NEED_RESCHED)
#define update_thread_flag(flag, value) \
	update_ti_thread_flag(current_thread_info(), flag, value)





#define DIV64_U64_ROUND_CLOSEST(dividend, divisor)	\
	({ u64 _tmp = (divisor); div64_u64((dividend) + _tmp / 2, _tmp); })
#define DIV64_U64_ROUND_UP(ll, d)	\
	({ u64 _tmp = (d); div64_u64((ll) + _tmp - 1, _tmp); })

#define div64_long(x, y) div64_s64((x), (y))
#define div64_ul(x, y)   div64_u64((x), (y))


#define irqs_disabled()					\
	({						\
		unsigned long _flags;			\
		raw_local_save_flags(_flags);		\
		raw_irqs_disabled_flags(_flags);	\
	})
#define irqs_disabled_flags(flags) raw_irqs_disabled_flags(flags)
#define local_irq_disable() \
	do { raw_local_irq_disable(); trace_hardirqs_off(); } while (0)
#define local_irq_enable() \
	do { trace_hardirqs_on(); raw_local_irq_enable(); } while (0)
#define local_irq_restore(flags)			\
	do {						\
		if (raw_irqs_disabled_flags(flags)) {	\
			raw_local_irq_restore(flags);	\
			trace_hardirqs_off();		\
		} else {				\
			trace_hardirqs_on();		\
			raw_local_irq_restore(flags);	\
		}					\
	} while (0)
#define local_irq_save(flags)				\
	do {						\
		raw_local_irq_save(flags);		\
		trace_hardirqs_off();			\
	} while (0)
#define local_save_flags(flags)	raw_local_save_flags(flags)
# define lockdep_hardirq_context(p)	0
# define lockdep_hardirq_enter()	do { } while (0)
# define lockdep_hardirq_exit()		do { } while (0)
# define lockdep_hardirq_threaded()	do { } while (0)
# define lockdep_hardirqs_enabled(p)	0
# define lockdep_hrtimer_enter(__hrtimer)	false
# define lockdep_hrtimer_exit(__context)	do { } while (0)
# define lockdep_irq_work_enter(__work)		do { } while (0)
# define lockdep_irq_work_exit(__work)		do { } while (0)
# define lockdep_posixtimer_enter()		do { } while (0)
# define lockdep_posixtimer_exit()		do { } while (0)
# define lockdep_softirq_context(p)	0
# define lockdep_softirq_enter()	do { } while (0)
# define lockdep_softirq_exit()		do { } while (0)
# define lockdep_softirqs_enabled(p)	0
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
# define trace_hardirqs_off()		do { } while (0)
# define trace_hardirqs_on()		do { } while (0)
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
#define RCU_INITIALIZER(v) (typeof(*(v)) __force __rcu *)(v)
#define RCU_INIT_POINTER(p, v) \
	do { \
		rcu_check_sparse(p, __rcu); \
		WRITE_ONCE(p, RCU_INITIALIZER(v)); \
	} while (0)
#define RCU_LOCKDEP_WARN(c, s)						\
	do {								\
		static bool __section(.data.unlikely) __warned;		\
		if (debug_lockdep_rcu_enabled() && !__warned && (c)) {	\
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

#define __is_kfree_rcu_offset(offset) ((offset) < 4096)
#define __kfree_rcu(head, offset) \
	do { \
		BUILD_BUG_ON(!__is_kfree_rcu_offset(offset)); \
		kfree_call_rcu(head, (rcu_callback_t)(unsigned long)(offset)); \
	} while (0)
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
#define call_rcu_tasks call_rcu
#define cond_resched_tasks_rcu_qs() \
do { \
	rcu_tasks_qs(current); \
	cond_resched(); \
} while (0)
#define kfree_rcu(ptr, rhf)						\
do {									\
	typeof (ptr) ___p = (ptr);					\
									\
	if (___p)							\
		__kfree_rcu(&((___p)->rhf), offsetof(typeof(*(ptr)), rhf)); \
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
#define rcu_note_voluntary_context_switch(t) rcu_tasks_qs(t)
#define rcu_pointer_handoff(p) (p)
#define rcu_preempt_depth() (current->rcu_read_lock_nesting)
#define rcu_replace_pointer(rcu_ptr, ptr, c)				\
({									\
	typeof(ptr) __tmp = rcu_dereference_protected((rcu_ptr), (c));	\
	rcu_assign_pointer((rcu_ptr), (ptr));				\
	__tmp;								\
})
#define rcu_sleep_check()						\
	do {								\
		rcu_preempt_sleep_check();				\
		RCU_LOCKDEP_WARN(lock_is_held(&rcu_bh_lock_map),	\
				 "Illegal context switch in RCU-bh read-side critical section"); \
		RCU_LOCKDEP_WARN(lock_is_held(&rcu_sched_lock_map),	\
				 "Illegal context switch in RCU-sched read-side critical section"); \
	} while (0)
#define rcu_tasks_qs(t) \
	do { \
		if (READ_ONCE((t)->rcu_tasks_holdout)) \
			WRITE_ONCE((t)->rcu_tasks_holdout, false); \
	} while (0)
#define smp_mb__after_unlock_lock()	smp_mb()  
#define synchronize_rcu_tasks synchronize_rcu
#define ulong2long(a)		(*(long *)(&(a)))

#define rcu_note_context_switch(preempt) \
	do { \
		rcu_qs(); \
		rcu_tasks_qs(current); \
	} while (0)
#define rcutree_dead_cpu         NULL
#define rcutree_dying_cpu        NULL
#define rcutree_offline_cpu      NULL
#define rcutree_online_cpu       NULL
#define rcutree_prepare_cpu      NULL



#define cpu_active(cpu)		cpumask_test_cpu((cpu), cpu_active_mask)
#define cpu_active_mask   ((const struct cpumask *)&__cpu_active_mask)
#define cpu_all_mask to_cpumask(cpu_all_bits)
#define cpu_is_offline(cpu)	unlikely(!cpu_online(cpu))
#define cpu_none_mask to_cpumask(cpu_bit_bitmap[0])
#define cpu_online(cpu)		cpumask_test_cpu((cpu), cpu_online_mask)
#define cpu_online_mask   ((const struct cpumask *)&__cpu_online_mask)
#define cpu_possible(cpu)	cpumask_test_cpu((cpu), cpu_possible_mask)
#define cpu_possible_mask ((const struct cpumask *)&__cpu_possible_mask)
#define cpu_present(cpu)	cpumask_test_cpu((cpu), cpu_present_mask)
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
#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG && (nbits) > 0)
#define MIN_THREADS_LEFT_FOR_ROOT 4
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))

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
		, .wait_lock = __SPIN_LOCK_UNLOCKED(lockname.wait_lock) \
		, .wait_list = LIST_HEAD_INIT(lockname.wait_list) \
		__DEBUG_MUTEX_INITIALIZER(lockname) \
		__DEP_MAP_MUTEX_INITIALIZER(lockname) }
#define mutex_init(mutex)						\
do {									\
	static struct lock_class_key __key;				\
									\
	__mutex_init((mutex), #mutex, &__key);				\
} while (0)
#define mutex_lock(lock) mutex_lock_nested(lock, 0)
#define mutex_lock_interruptible(lock) mutex_lock_interruptible_nested(lock, 0)
# define mutex_lock_interruptible_nested(lock, subclass) mutex_lock_interruptible(lock)
#define mutex_lock_io(lock) mutex_lock_io_nested(lock, 0)
# define mutex_lock_io_nested(lock, subclass) mutex_lock(lock)
#define mutex_lock_killable(lock) mutex_lock_killable_nested(lock, 0)
# define mutex_lock_killable_nested(lock, subclass) mutex_lock_killable(lock)
# define mutex_lock_nest_lock(lock, nest_lock) mutex_lock(lock)
# define mutex_lock_nested(lock, subclass) mutex_lock(lock)
#define OSQ_LOCK_UNLOCKED { ATOMIC_INIT(OSQ_UNLOCKED_VAL) }
#define OSQ_UNLOCKED_VAL (0)

#define DECLARE_RWSEM(name) \
	struct rw_semaphore name = __RWSEM_INITIALIZER(name)

# define __DEBUG_RWSEM_INITIALIZER(lockname) , .magic = &lockname
# define __RWSEM_DEP_MAP_INIT(lockname)			\
	, .dep_map = {					\
		.name = #lockname,			\
		.wait_type_inner = LD_WAIT_SLEEP,	\
	}
#define __RWSEM_INITIALIZER(name)				\
	{ __RWSEM_INIT_COUNT(name),				\
	  .owner = ATOMIC_LONG_INIT(0),				\
	  .wait_list = LIST_HEAD_INIT((name).wait_list),	\
	  .wait_lock = __RAW_SPIN_LOCK_UNLOCKED(name.wait_lock)	\
	  __RWSEM_OPT_INIT(name)				\
	  __DEBUG_RWSEM_INITIALIZER(name)			\
	  __RWSEM_DEP_MAP_INIT(name) }
#define __RWSEM_INIT_COUNT(name)	.count = ATOMIC_LONG_INIT(RWSEM_UNLOCKED_VALUE)
#define __RWSEM_OPT_INIT(lockname) , .osq = OSQ_LOCK_UNLOCKED
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

#define UUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)			\
((uuid_t)								\
{{ ((a) >> 24) & 0xff, ((a) >> 16) & 0xff, ((a) >> 8) & 0xff, (a) & 0xff, \
   ((b) >> 8) & 0xff, (b) & 0xff,					\
   ((c) >> 8) & 0xff, (c) & 0xff,					\
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})
#define UUID_SIZE 16

#define uuid_le_to_bin(guid, u)	guid_parse(guid, u)
#define GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)			\
((guid_t)								\
{{ (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, \
   (b) & 0xff, ((b) >> 8) & 0xff,					\
   (c) & 0xff, ((c) >> 8) & 0xff,					\
   (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }})
#define UUID_LE(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)		\
	GUID_INIT(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7)


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
				  class_shift, hook)
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
#define PCI_DEVICE_SUB(vend, dev, subvend, subdev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = (subvend), .subdevice = (subdev)
#define PCI_DEVID(bus, devfn)	((((u16)(bus)) << 8) | (devfn))
#define PCI_IRQ_ALL_TYPES \
	(PCI_IRQ_LEGACY | PCI_IRQ_MSI | PCI_IRQ_MSIX)
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
	((pci_resource_start((dev), (bar)) == 0 &&	\
	  pci_resource_end((dev), (bar)) ==		\
	  pci_resource_start((dev), (bar))) ? 0 :	\
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

#define dma_alloc_from_dev_coherent(dev, size, handle, ret) (0)
#define dma_get_sgtable(d, t, v, h, s) dma_get_sgtable_attrs(d, t, v, h, s, 0)
#define dma_map_page(d, p, o, s, r) dma_map_page_attrs(d, p, o, s, r, 0)
#define dma_map_sg(d, s, n, r) dma_map_sg_attrs(d, s, n, r, 0)
#define dma_map_single(d, a, s, r) dma_map_single_attrs(d, a, s, r, 0)
#define dma_mmap_coherent(d, v, c, h, s) dma_mmap_attrs(d, v, c, h, s, 0)
#define dma_mmap_from_dev_coherent(dev, vma, vaddr, order, ret) (0)
#define dma_release_from_dev_coherent(dev, order, vaddr) (0)
#define dma_unmap_addr(PTR, ADDR_NAME)           ((PTR)->ADDR_NAME)
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  (((PTR)->ADDR_NAME) = (VAL))
#define dma_unmap_len(PTR, LEN_NAME)             ((PTR)->LEN_NAME)
#define dma_unmap_len_set(PTR, LEN_NAME, VAL)    (((PTR)->LEN_NAME) = (VAL))
#define dma_unmap_page(d, a, s, r) dma_unmap_page_attrs(d, a, s, r, 0)
#define dma_unmap_sg(d, s, n, r) dma_unmap_sg_attrs(d, s, n, r, 0)
#define dma_unmap_single(d, a, s, r) dma_unmap_single_attrs(d, a, s, r, 0)

#define __sme_clr(x)		((x) & ~sme_me_mask)
#define __sme_set(x)		((x) | sme_me_mask)
#define SCATTERLIST_MAX_SEGMENT (UINT_MAX & PAGE_MASK)

#define for_each_sg(sglist, sg, nr, __i)	\
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))
#define for_each_sg_dma_page(sglist, dma_iter, dma_nents, pgoffset)            \
	for (__sg_page_iter_start(&(dma_iter)->base, sglist, dma_nents,        \
				  pgoffset);                                   \
	     __sg_page_iter_dma_next(dma_iter);)
#define for_each_sg_page(sglist, piter, nents, pgoffset)		   \
	for (__sg_page_iter_start((piter), (sglist), (nents), (pgoffset)); \
	     __sg_page_iter_next(piter);)
#define sg_chain_ptr(sg)	\
	((struct scatterlist *) ((sg)->page_link & ~(SG_CHAIN | SG_END)))
#define sg_dma_address(sg)	((sg)->dma_address)
#define sg_dma_len(sg)		((sg)->dma_length)
#define sg_is_chain(sg)		((sg)->page_link & SG_CHAIN)
#define sg_is_last(sg)		((sg)->page_link & SG_END)
#define FAULT_FLAG_DEFAULT  (FAULT_FLAG_ALLOW_RETRY | \
			     FAULT_FLAG_KILLABLE | \
			     FAULT_FLAG_INTERRUPTIBLE)
#define FAULT_FLAG_INSTRUCTION  		0x100
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
#define is_ioremap_addr(x) is_vmalloc_addr(x)
#define lm_alias(x)	__va(__pa_symbol(x))
#define lru_to_page(head) (list_entry((head)->prev, struct page, lru))
#define mm_forbids_zeropage(X)	(0)
#define mm_zero_struct_page(pp)  ((void)memset((pp), 0, sizeof(struct page)))
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
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
#define put_hwpoison_page(page)	put_page(page)
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

#define DEF_PRIORITY 12
#define LRU_ACTIVE 1
#define LRU_BASE 0
#define LRU_FILE 2
#define MAX_ORDER 11
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)
#define MIGRATETYPE_MASK ((1UL << NR_MIGRATETYPE_BITS) - 1)
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map
#define NR_MIGRATETYPE_BITS (PB_migrate_end - PB_migrate + 1)
#define NR_VM_NUMA_STAT_ITEMS 0
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

#define early_pfn_valid(pfn)	pfn_valid(pfn)
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
#define for_next_zone_zonelist_nodemask(zone, z, zlist, highidx, nodemask) \
	for (zone = z->zone;	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask),	\
			zone = zonelist_zone(z))
#define get_pageblock_migratetype(page)					\
	get_pfnblock_flags_mask(page, page_to_pfn(page),		\
			PB_migrate_end, MIGRATETYPE_MASK)
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
#define pfn_valid_within(pfn) pfn_valid(pfn)
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define sparse_init()	do {} while (0)
#define subsection_map_init(_pfn, _nr_pages) do {} while (0)
#define wmark_pages(z, i) (z->_watermark[i] + z->watermark_boost)
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)

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
#define set_page_private(page, v)	((page)->private = (v))
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
#define RB_ROOT_CACHED (struct rb_root_cached) { {NULL, }, NULL }
#define rb_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry(____ptr, type, member) : NULL; \
	})
#define rb_first_cached(root) (root)->rb_leftmost
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

#define PB_migratetype_bits 3
#define clear_pageblock_skip(page) \
			set_pageblock_flags_group(page, 0, PB_migrate_skip,  \
							PB_migrate_skip)
#define get_pageblock_flags_group(page, start_bitidx, end_bitidx) \
	get_pfnblock_flags_mask(page, page_to_pfn(page),		\
			end_bitidx,					\
			(1 << (end_bitidx - start_bitidx + 1)) - 1)
#define get_pageblock_skip(page) \
			get_pageblock_flags_group(page, PB_migrate_skip,     \
							PB_migrate_skip)
#define set_pageblock_flags_group(page, flags, start_bitidx, end_bitidx) \
	set_pfnblock_flags_mask(page, flags, page_to_pfn(page),		\
			end_bitidx,					\
			(1 << (end_bitidx - start_bitidx + 1)) - 1)
#define set_pageblock_skip(page) \
			set_pageblock_flags_group(page, 1, PB_migrate_skip,  \
							PB_migrate_skip)
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
#define DEFINE_SEQLOCK(x) \
		seqlock_t x = __SEQLOCK_UNLOCKED(x)
#define SEQCNT_ZERO(lockname) { .sequence = 0, SEQCOUNT_DEP_MAP_INIT(lockname)}
# define SEQCOUNT_DEP_MAP_INIT(lockname) \
		.dep_map = { .name = #lockname } \


#define __SEQLOCK_UNLOCKED(lockname)			\
	{						\
		.seqcount = SEQCNT_ZERO(lockname),	\
		.lock =	__SPIN_LOCK_UNLOCKED(lockname)	\
	}
#define read_seqlock_excl_irqsave(lock, flags)				\
	do { flags = __read_seqlock_excl_irqsave(lock); } while (0)
# define seqcount_init(s)				\
	do {						\
		static struct lock_class_key __key;	\
		__seqcount_init((s), #s, &__key);	\
	} while (0)
# define seqcount_lockdep_reader_access(x)
#define seqlock_init(x)					\
	do {						\
		seqcount_init(&(x)->seqcount);		\
		spin_lock_init(&(x)->lock);		\
	} while (0)
#define write_seqlock_irqsave(lock, flags)				\
	do { flags = __write_seqlock_irqsave(lock); } while (0)

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
#define HPAGE_CACHE_INDEX_MASK (HPAGE_PMD_NR - 1)
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
#define transparent_hugepage_debug_cow()				\
	(transparent_hugepage_flags &					\
	 (1<<TRANSPARENT_HUGEPAGE_DEBUG_COW_FLAG))
#define transparent_hugepage_flags 0UL
#define transparent_hugepage_use_zero_page()				\
	(transparent_hugepage_flags &					\
	 (1<<TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_FLAG))
#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
#define ACL_DONT_CACHE ((void *)(-3))
#define ACL_NOT_CACHED ((void *)(-1))
#define CHECK_IOVEC_ONLY -1
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
#define HAVE_COMPAT_IOCTL 1
#define HAVE_UNLOCKED_IOCTL 1
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
#define SB_SUBMOUNT     (1<<26)
#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - sizeof(struct simple_transaction_argresp))
#define WHITEOUT_DEV 0
#define WHITEOUT_MODE 0

#define __IS_FLG(inode, flg)	((inode)->i_sb->s_flags & (flg))

#define __fid_enumify(ENUM, dummy) READING_ ## ENUM,
#define __fid_stringify(dummy, str) #str,
#define __getname()		kmem_cache_alloc(names_cachep, GFP_KERNEL)
#define __kernel_read_file_id(id) \
	id(UNKNOWN, unknown)		\
	id(FIRMWARE, firmware)		\
	id(FIRMWARE_PREALLOC_BUFFER, firmware)	\
	id(FIRMWARE_EFI_EMBEDDED, firmware)	\
	id(MODULE, kernel-module)		\
	id(KEXEC_IMAGE, kexec-image)		\
	id(KEXEC_INITRAMFS, kexec-initramfs)	\
	id(POLICY, security-policy)		\
	id(X509_CERTIFICATE, x509-certificate)	\
	id(MAX_ID, )
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
#define __GFP_BITS_SHIFT (23 + IS_ENABLED(CONFIG_LOCKDEP))
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
#define alloc_page_vma_node(gfp_mask, vma, addr, node)		\
	alloc_pages_vma(gfp_mask, 0, vma, addr, node, false)
#define alloc_pages(gfp_mask, order) \
		alloc_pages_node(numa_node_id(), gfp_mask, order)
#define alloc_pages_vma(gfp_mask, order, vma, addr, node, false)\
	alloc_pages(gfp_mask, order)
#define free_page(addr) free_pages((addr), 0)
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

#define topology_llc_cpumask(cpu)	(&cpu_topology[cpu].llc_sibling)
#define BLKALIGNOFF _IO(0x12,122)
#define BLKBSZGET  _IOR(0x12,112,size_t)
#define BLKBSZSET  _IOW(0x12,113,size_t)
#define BLKDISCARD _IO(0x12,119)
#define BLKDISCARDZEROES _IO(0x12,124)
#define BLKFLSBUF  _IO(0x12,97)	
#define BLKFRAGET  _IO(0x12,101)
#define BLKFRASET  _IO(0x12,100)
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
			    MNT_DOOMED | MNT_SYNC_UMOUNT | MNT_MARKED)
#define MNT_USER_SETTABLE_MASK  (MNT_NOSUID | MNT_NODEV | MNT_NOEXEC \
				 | MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME \
				 | MNT_READONLY)

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
#define kmalloc_node_track_caller(size, flags, node) \
	__kmalloc_node_track_caller(size, flags, node, \
			_RET_IP_)
#define kmalloc_track_caller(size, flags) \
	__kmalloc_track_caller(size, flags, _RET_IP_)
#define KASAN_SHADOW_INIT 0



#define __signed_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (u64)__a + (u64)__b;		\
	(((~(__a ^ __b)) & (*__d ^ __a))	\
		& type_min(typeof(__a))) != 0;	\
})
#define __signed_mul_overflow(a, b, d) ({				\
	typeof(a) __a = (a);						\
	typeof(b) __b = (b);						\
	typeof(d) __d = (d);						\
	typeof(a) __tmax = type_max(typeof(a));				\
	typeof(a) __tmin = type_min(typeof(a));				\
	(void) (&__a == &__b);						\
	(void) (&__a == __d);						\
	*__d = (u64)__a * (u64)__b;					\
	(__b > 0   && (__a > __tmax/__b || __a < __tmin/__b)) ||	\
	(__b < (typeof(__b))-1  && (__a > __tmin/__b || __a < __tmax/__b)) || \
	(__b == (typeof(__b))-1 && __a == __tmin);			\
})
#define __signed_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = (u64)__a - (u64)__b;		\
	((((__a ^ __b)) & (*__d ^ __a))		\
		& type_min(typeof(__a))) != 0;	\
})
#define __type_half_max(type) ((type)1 << (8*sizeof(type) - 1 - is_signed_type(type)))
#define __unsigned_add_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a + __b;			\
	*__d < __a;				\
})
#define __unsigned_mul_overflow(a, b, d) ({		\
	typeof(a) __a = (a);				\
	typeof(b) __b = (b);				\
	typeof(d) __d = (d);				\
	(void) (&__a == &__b);				\
	(void) (&__a == __d);				\
	*__d = __a * __b;				\
	__builtin_constant_p(__b) ?			\
	  __b > 0 && __a > type_max(typeof(__a)) / __b : \
	  __a > 0 && __b > type_max(typeof(__b)) / __a;	 \
})
#define __unsigned_sub_overflow(a, b, d) ({	\
	typeof(a) __a = (a);			\
	typeof(b) __b = (b);			\
	typeof(d) __d = (d);			\
	(void) (&__a == &__b);			\
	(void) (&__a == __d);			\
	*__d = __a - __b;			\
	__a < __b;				\
})
#define check_add_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_add_overflow(a, b, d),			\
			__unsigned_add_overflow(a, b, d))
#define check_mul_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_mul_overflow(a, b, d),			\
			__unsigned_mul_overflow(a, b, d))
#define check_shl_overflow(a, s, d) ({					\
	typeof(a) _a = a;						\
	typeof(s) _s = s;						\
	typeof(d) _d = d;						\
	u64 _a_full = _a;						\
	unsigned int _to_shift =					\
		is_non_negative(_s) && _s < 8 * sizeof(*d) ? _s : 0;	\
	*_d = (_a_full << _to_shift);					\
	(_to_shift != _s || is_negative(*_d) || is_negative(_a) ||	\
	(*_d >> _to_shift) != _a);					\
})
#define check_sub_overflow(a, b, d)					\
	__builtin_choose_expr(is_signed_type(typeof(a)),		\
			__signed_sub_overflow(a, b, d),			\
			__unsigned_sub_overflow(a, b, d))
#define is_negative(a) (!(is_non_negative(a)))
#define is_non_negative(a) ((a) > 0 || (a) == 0)
#define is_signed_type(type)       (((type)(-1)) < (type)1)
#define struct_size(p, member, n)					\
	__ab_c_size(n,							\
		    sizeof(*(p)->member) + __must_be_array((p)->member),\
		    sizeof(*(p)))
#define type_max(T) ((T)((__type_half_max(T) - 1) + __type_half_max(T)))
#define type_min(T) ((T)((T)-type_max(T)-(T)1))
#define S_DT(mode)	(((mode) & S_IFMT) >> S_DT_SHIFT)


#define IOPRIO_PRIO_CLASS(mask)	((mask) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(mask)	((mask) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data)	(((class) << IOPRIO_CLASS_SHIFT) | data)
#define ioprio_valid(mask)	(IOPRIO_PRIO_CLASS((mask)) != IOPRIO_CLASS_NONE)

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

# define rt_mutex_adjust_pi(p)		do { } while (0)
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

#define __set_current_state(state_value)			\
	do {							\
		WARN_ON_ONCE(is_special_task_state(state_value));\
		current->task_state_change = _THIS_IP_;		\
		current->state = (state_value);			\
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
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition)	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
#define get_task_comm(buf, tsk) ({			\
	BUILD_BUG_ON(sizeof(buf) != TASK_COMM_LEN);	\
	__get_task_comm(buf, sizeof(buf), tsk);		\
})
#define is_special_task_state(state)				\
	((state) & (__TASK_STOPPED | __TASK_TRACED | TASK_PARKED | TASK_DEAD))
#define set_current_state(state_value)				\
	do {							\
		WARN_ON_ONCE(is_special_task_state(state_value));\
		current->task_state_change = _THIS_IP_;		\
		smp_store_mb(current->state, (state_value));	\
	} while (0)
#define set_special_state(state_value)					\
	do {								\
		unsigned long flags; 			\
		WARN_ON_ONCE(!is_special_task_state(state_value));	\
		raw_spin_lock_irqsave(&current->pi_lock, flags);	\
		current->task_state_change = _THIS_IP_;			\
		current->state = (state_value);				\
		raw_spin_unlock_irqrestore(&current->pi_lock, flags);	\
	} while (0)
#define set_stopped_child_used_math(child)	do { (child)->flags |= PF_USED_MATH; } while (0)
#define set_used_math()				set_stopped_child_used_math(current)
#define task_contributes_to_load(task)	((task->state & TASK_UNINTERRUPTIBLE) != 0 && \
					 (task->flags & PF_FROZEN) == 0 && \
					 (task->state & TASK_NOLOAD) == 0)
#define task_is_stopped(task)		((task->state & __TASK_STOPPED) != 0)
#define task_is_stopped_or_traced(task)	((task->state & (__TASK_STOPPED | __TASK_TRACED)) != 0)
#define task_is_traced(task)		((task->state & __TASK_TRACED) != 0)
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




# define __hrtimer_clock_base_align




#define NICE_TO_PRIO(nice)	((nice) + DEFAULT_PRIO)
#define PRIO_TO_NICE(prio)	((prio) - DEFAULT_PRIO)
#define TASK_USER_PRIO(p)	USER_PRIO((p)->static_prio)
#define USER_PRIO(p)		((p)-MAX_RT_PRIO)




#define REFCOUNT_INIT(n)	{ .refs = ATOMIC_INIT(n), }


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

#define kcov_finish_switch(t)			\
do {						\
	(t)->kcov_mode &= ~KCOV_IN_CTXSW;	\
} while (0)
#define kcov_prepare_switch(t)			\
do {						\
	(t)->kcov_mode |= KCOV_IN_CTXSW;	\
} while (0)
#define KCOV_CMP_CONST          (1 << 0)
#define KCOV_CMP_MASK           KCOV_CMP_SIZE(3)
#define KCOV_CMP_SIZE(n)        ((n) << 1)


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
	rcu_assign_pointer((w)->task, current);				\
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
									\
	WRITE_ONCE((w)->task, NULL);					\
	__set_current_state(TASK_RUNNING);				\
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
# define ___ARCH_SI_TRAPNO(_a1) , _a1
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

#define DEFINE_RATELIMIT_STATE(name, interval_init, burst_init)		\
									\
	struct ratelimit_state name =					\
		RATELIMIT_STATE_INIT(name, interval_init, burst_init)	\

#define RATELIMIT_STATE_INIT(name, interval_init, burst_init) {		\
		.lock		= __RAW_SPIN_LOCK_UNLOCKED(name.lock),	\
		.interval	= interval_init,			\
		.burst		= burst_init,				\
	}
#define WARN_ON_RATELIMIT(condition, state)			\
	WARN_ON(condition)
#define WARN_RATELIMIT(condition, format, ...)			\
({								\
	int rtn = WARN(condition, format, ##__VA_ARGS__);	\
	rtn;							\
})

#define __ratelimit(state) ___ratelimit(state, __func__)

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
	request_key_tag(type, description, net->key_domain, callout_info);
#define request_key_net_rcu(type, description, net) \
	request_key_rcu(type, description, net->key_domain);
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
#define CAP_LAST_CAP         CAP_AUDIT_READ
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
#define CLONE_LEGACY_FLAGS 0xffffffffULL

# define arch_task_struct_size (sizeof(struct task_struct))
#define sched_exec()   {}

#define faulthandler_disabled() (pagefault_disabled() || in_atomic())
#define probe_kernel_address(addr, retval)		\
	probe_kernel_read(&retval, addr, sizeof(retval))
#define uaccess_kernel() segment_eq(get_fs(), KERNEL_DS)
#define unsafe_copy_to_user(d,s,l,e) unsafe_op_wrap(__copy_to_user(d,s,l),e)
#define unsafe_get_user(x,p,e) unsafe_op_wrap(__get_user(x,p),e)
#define unsafe_op_wrap(op, err) do { if (unlikely(op)) goto err; } while (0)
#define unsafe_put_user(x,p,e) unsafe_op_wrap(__put_user(x,p),e)
#define user_access_begin(ptr,len) access_ok(ptr, len)
#define user_access_end() do { } while (0)
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
							\
	case 2:								\
		a1 = a->sig[1]; b1 = b->sig[1];				\
		r->sig[1] = op(a1, b1);					\
							\
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
							\
	case 2:	set->sig[1] = op(set->sig[1]);				\
							\
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
	if (t->sas_ss_flags & SS_AUTODISARM) \
		sas_ss_reset(t); \
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
	 O_APPEND | O_NDELAY | O_NONBLOCK | O_NDELAY | __O_SYNC | O_DSYNC | \
	 FASYNC	| O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW | \
	 O_NOATIME | O_CLOEXEC | O_PATH | __O_TMPFILE)
#define VALID_RESOLVE_FLAGS \
	(RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | \
	 RESOLVE_BENEATH | RESOLVE_IN_ROOT)
#define VALID_UPGRADE_FLAGS \
	(UPGRADE_NOWRITE | UPGRADE_NOREAD)

#define force_o_largefile() (!IS_ENABLED(CONFIG_ARCH_32BIT_OFF_T))

#define KSTAT_QUERY_FLAGS (AT_STATX_SYNC_TYPE)

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

#define page_ref_tracepoint_active(t) static_key_false(&(t).key)
#define TRACEPOINT_DEFS_H 1


#define MAX_RESOURCE ((resource_size_t)~0)



#define DEVICE_ATTR(_name, _mode, _show, _store) \
	struct device_attribute dev_attr_##_name = __ATTR(_name, _mode, _show, _store)
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
const struct dev_pm_ops name = { \
	SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
}
#define UNIVERSAL_DEV_PM_OPS(name, suspend_fn, resume_fn, idle_fn) \
const struct dev_pm_ops name = { \
	SET_SYSTEM_SLEEP_PM_OPS(suspend_fn, resume_fn) \
	SET_RUNTIME_PM_OPS(suspend_fn, resume_fn, idle_fn) \
}

#define device_pm_lock() do {} while (0)
#define device_pm_unlock() do {} while (0)
#define suspend_report_result(fn, ret)					\
	do {								\
		__suspend_report_result(__func__, fn, ret);		\
	} while (0)
#define DEFINE_KLIST(_name, _get, _put)					\
	struct klist _name = KLIST_INIT(_name, _get, _put)
#define KLIST_INIT(_name, _get, _put)					\
	{ .k_lock	= __SPIN_LOCK_UNLOCKED(_name.k_lock),		\
	  .k_list	= LIST_HEAD_INIT(_name.k_list),			\
	  .get		= _get,						\
	  .put		= _put, }

#define KREF_INIT(n)	{ .refcount = REFCOUNT_INIT(n), }



#define ATTRIBUTE_GROUPS(_name)					\
static const struct attribute_group _name##_group = {		\
	.attrs = _name##_attrs,					\
};								\
__ATTRIBUTE_GROUPS(_name)
#define BIN_ATTR(_name, _mode, _read, _write, _size)			\
struct bin_attribute bin_attr_##_name = __BIN_ATTR(_name, _mode, _read,	\
					_write, _size)
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

#define dev_WARN(dev, format, arg...) \
	WARN(1, "%s %s: " format, dev_driver_string(dev), dev_name(dev), ## arg);
#define dev_WARN_ONCE(dev, condition, format, arg...) \
	WARN_ONCE(condition, "%s %s: " format, \
			dev_driver_string(dev), dev_name(dev), ## arg)
#define dev_alert(dev, fmt, ...)					\
	_dev_alert(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_alert_once(dev, fmt, ...)					\
	dev_level_once(dev_alert, dev, fmt, ##__VA_ARGS__)
#define dev_alert_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_alert, dev, fmt, ##__VA_ARGS__)
#define dev_crit(dev, fmt, ...)						\
	_dev_crit(dev, dev_fmt(fmt), ##__VA_ARGS__)
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
#define dev_emerg(dev, fmt, ...)					\
	_dev_emerg(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_emerg_once(dev, fmt, ...)					\
	dev_level_once(dev_emerg, dev, fmt, ##__VA_ARGS__)
#define dev_emerg_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_emerg, dev, fmt, ##__VA_ARGS__)
#define dev_err(dev, fmt, ...)						\
	_dev_err(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_err_once(dev, fmt, ...)					\
	dev_level_once(dev_err, dev, fmt, ##__VA_ARGS__)
#define dev_err_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_err, dev, fmt, ##__VA_ARGS__)
#define dev_fmt(fmt) fmt
#define dev_info(dev, fmt, ...)						\
	_dev_info(dev, dev_fmt(fmt), ##__VA_ARGS__)
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
#define dev_notice(dev, fmt, ...)					\
	_dev_notice(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_notice_once(dev, fmt, ...)					\
	dev_level_once(dev_notice, dev, fmt, ##__VA_ARGS__)
#define dev_notice_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_notice, dev, fmt, ##__VA_ARGS__)
#define dev_vdbg(dev, fmt, ...)						\
({									\
	if (0)								\
		dev_printk(KERN_DEBUG, dev, dev_fmt(fmt), ##__VA_ARGS__); \
})
#define dev_warn(dev, fmt, ...)						\
	_dev_warn(dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_warn_once(dev, fmt, ...)					\
	dev_level_once(dev_warn, dev, fmt, ##__VA_ARGS__)
#define dev_warn_ratelimited(dev, fmt, ...)				\
	dev_level_ratelimited(dev_warn, dev, fmt, ##__VA_ARGS__)
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
#define PCI_DEVICE_ID_AMD_17H_M70H_DF_F3 0x1443
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


#define resource_list_for_each_entry(entry, list)	\
	list_for_each_entry((entry), (list), node)
#define resource_list_for_each_entry_safe(entry, tmp, list)	\
	list_for_each_entry_safe((entry), (tmp), (list), node)
#define IOMEM_ERR_PTR(err) (__force void __iomem *)ERR_PTR(err)

#define arch_has_dev_port()     (1)
#define arch_phys_wc_add arch_phys_wc_add
#define arch_phys_wc_index arch_phys_wc_index
#define pci_remap_cfgspace pci_remap_cfgspace
#define DECLARE_TASKLET(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }
#define DECLARE_TASKLET_DISABLED(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }
#define SOFTIRQ_STOP_IDLE_MASK (~(1 << RCU_SOFTIRQ))

#define __softirq_entry  \
	__attribute__((__section__(".softirqentry.text")))
#define hard_irq_disable()	do { } while(0)
# define local_irq_enable_in_hardirq()	do { } while (0)
#define local_softirq_pending()	(__this_cpu_read(local_softirq_pending_ref))
#define local_softirq_pending_ref irq_stat.__softirq_pending
#define or_softirq_pending(x)	(__this_cpu_or(local_softirq_pending_ref, (x)))
#define set_softirq_pending(x)	(__this_cpu_write(local_softirq_pending_ref, (x)))
#define tasklet_trylock(t) 1
#define tasklet_unlock(t) do { } while (0)
#define tasklet_unlock_wait(t) do { } while (0)

#define __irq_enter()					\
	do {						\
		account_irq_enter_time(current);	\
		preempt_count_add(HARDIRQ_OFFSET);	\
		lockdep_hardirq_enter();		\
	} while (0)
#define __irq_exit()					\
	do {						\
		lockdep_hardirq_exit();			\
		account_irq_exit_time(current);		\
		preempt_count_sub(HARDIRQ_OFFSET);	\
	} while (0)
#define arch_nmi_enter()	do { } while (0)
#define arch_nmi_exit()		do { } while (0)
#define nmi_enter()						\
	do {							\
		arch_nmi_enter();				\
		printk_nmi_enter();				\
		lockdep_off();					\
		ftrace_nmi_enter();				\
		BUG_ON(in_nmi());				\
		preempt_count_add(NMI_OFFSET + HARDIRQ_OFFSET);	\
		rcu_nmi_enter();				\
		lockdep_hardirq_enter();			\
	} while (0)
#define nmi_exit()						\
	do {							\
		lockdep_hardirq_exit();				\
		rcu_nmi_exit();					\
		BUG_ON(!in_nmi());				\
		preempt_count_sub(NMI_OFFSET + HARDIRQ_OFFSET);	\
		ftrace_nmi_exit();				\
		lockdep_on();					\
		printk_nmi_exit();				\
		arch_nmi_exit();				\
	} while (0)




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

#define APR_MODULE_PREFIX "apr:"
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
#define X86_VENDOR_ANY 0xffff
#define dmi_device_id dmi_system_id
#define x86cpu_device_id x86_cpu_id

#define VGA_DEFAULT_DEVICE     (NULL)
#define VGA_RSRC_LEGACY_IO     0x01
#define VGA_RSRC_LEGACY_MASK   (VGA_RSRC_LEGACY_IO | VGA_RSRC_LEGACY_MEM)
#define VGA_RSRC_LEGACY_MEM    0x02
#define VGA_RSRC_NORMAL_IO     0x04
#define VGA_RSRC_NORMAL_MEM    0x08
#define vga_put(pdev, rsrc)
#define VGA_ATT_C   	0x15	
#define VGA_ATT_IW  	0x3C0	
#define VGA_ATT_R   	0x3C1	
#define VGA_ATT_W   	0x3C0	
#define VGA_CR17_H_V_SIGNALS_ENABLED 0x80
#define VGA_CRT_C   	0x19	
#define VGA_CRT_DC  	0x3D5	
#define VGA_CRT_DM  	0x3B5	
#define VGA_CRT_IC  	0x3D4	
#define VGA_CRT_IM  	0x3B4	
#define VGA_GFX_C   	0x09	
#define VGA_GFX_D   	0x3CF	
#define VGA_GFX_I   	0x3CE	
#define VGA_IS1_RC  	0x3DA	
#define VGA_IS1_RM  	0x3BA	
#define VGA_MIS_C   	0x01	
#define VGA_MIS_R   	0x3CC	
#define VGA_MIS_W   	0x3C2	
#define VGA_OUT16VAL(v, r)       (((v) << 8) | (r))

#define VGA_PEL_D   	0x3C9	
#define VGA_PEL_IR  	0x3C7	
#define VGA_PEL_IW  	0x3C8	
#define VGA_PEL_MSK 	0x3C6	
#define VGA_SAVE_CMAP  16 
#define VGA_SAVE_FONT0 1  
#define VGA_SAVE_FONT1 2  
#define VGA_SAVE_FONTS 7  
#define VGA_SAVE_MODE  8  
#define VGA_SAVE_TEXT  4  
#define VGA_SEQ_C   	0x05	
#define VGA_SEQ_D   	0x3C5	
#define VGA_SEQ_I   	0x3C4	


#define VFIO_DEVICE_FLAGS_AMBA  (1 << 3)	
#define VFIO_DEVICE_FLAGS_PLATFORM (1 << 2)	
#define VFIO_DEVICE_GET_GFX_DMABUF _IO(VFIO_TYPE, VFIO_BASE + 15)
#define VFIO_DEVICE_GFX_LINK_STATE_DOWN  2
#define VFIO_DEVICE_GFX_LINK_STATE_UP    1
#define VFIO_DEVICE_QUERY_GFX_PLANE _IO(VFIO_TYPE, VFIO_BASE + 14)
#define VFIO_DMA_MAP_FLAG_READ (1 << 0)		
#define VFIO_DMA_MAP_FLAG_WRITE (1 << 1)	
#define VFIO_GFX_PLANE_TYPE_DMABUF (1 << 1)
#define VFIO_GFX_PLANE_TYPE_PROBE (1 << 0)
#define VFIO_GFX_PLANE_TYPE_REGION (1 << 2)
#define VFIO_IOMMU_GET_INFO _IO(VFIO_TYPE, VFIO_BASE + 12)
#define VFIO_IOMMU_INFO_PGSIZES (1 << 0)	
#define VFIO_IOMMU_MAP_DMA _IO(VFIO_TYPE, VFIO_BASE + 13)
#define VFIO_IOMMU_TYPE1_INFO_CAP_IOVA_RANGE  1
#define VFIO_IOMMU_UNMAP_DMA _IO(VFIO_TYPE, VFIO_BASE + 14)
#define VFIO_REGION_SUBTYPE_GFX_EDID            (1)
#define VFIO_REGION_TYPE_GFX                    (1)

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


#define iommu_device_set_ops(iommu, ops)				\
do {									\
	struct iommu_ops *__ops = (struct iommu_ops *)(ops);		\
	__ops->owner = THIS_MODULE;					\
	__iommu_device_set_ops(iommu, __ops);				\
} while (0)
#define IOMMU_CACHE_INVALIDATE_INFO_VERSION_1 1

#define DECLARE_IOASID_SET(name) struct ioasid_set name = { 0 }
#define INVALID_IOASID ((ioasid_t)-1)

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
		__used __section(__##table##_of_table)			\
		 = { .compatible = compat,				\
		     .data = (fn == (fn_type)NULL) ? fn : fn  }
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
#define of_match_ptr(_ptr)	(_ptr)
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
	{ .pointer = &(const struct software_node_ref_args) {		\
		.node = _ref_,						\
		.nargs = ARRAY_SIZE(((u64[]){ 0, ##__VA_ARGS__ })) - 1,	\
		.args = { __VA_ARGS__ },				\
	} },								\
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
