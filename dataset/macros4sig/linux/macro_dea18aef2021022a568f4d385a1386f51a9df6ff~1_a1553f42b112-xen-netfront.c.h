


#include<linux/resource.h>

#include<linux/dcbnl.h>












#include<limits.h>

#include<asm/resource.h>



#include<linux/if_link.h>



#include<asm/shmbuf.h>
#include<asm/socket.h>
#include<linux/sysctl.h>


#include<linux/pkt_sched.h>

#include<linux/kdev_t.h>







#include<linux/module.h>
#include<linux/cgroupstats.h>


#include<linux/sysinfo.h>



#include<linux/tcp.h>



#include<linux/pkt_cls.h>
#include<linux/errno.h>
#include<linux/bpf_common.h>





















#include<linux/netdevice.h>


#include<linux/aio_abi.h>
#include<linux/in_route.h>
#include<linux/mount.h>

#include<linux/in6.h>


#include<linux/net_tstamp.h>
#include<linux/udp.h>
#include<linux/bpf.h>

#include<asm/auxvec.h>


#include<linux/stddef.h>
#include<unistd.h>









#include<linux/gen_stats.h>








#include<asm/param.h>





#include<asm/byteorder.h>






#include<asm/fcntl.h>

#include<linux/netlink.h>


#include<linux/if_addr.h>

#include<linux/dqblk_xfs.h>


#include<linux/ip.h>

#include<net/route.h>












#include<asm/perf_regs.h>


#include<linux/const.h>











#include<linux/lwtunnel.h>
#include<linux/xfrm.h>






#include<linux/poll.h>






#include<linux/limits.h>


#include<linux/netfilter/nf_conntrack_tuple_common.h>
#include<asm/ptrace.h>
#include<linux/snmp.h>
#include<asm/errno.h>
#include<linux/kernel.h>


#include<linux/seccomp.h>
#include<linux/time_types.h>


#include<linux/string.h>


#include<linux/if_arp.h>



#include<asm/types.h>



#include<linux/libc-compat.h>
#include<linux/posix_types.h>
#include<linux/irqnr.h>








#include<linux/sem.h>
#include<linux/in.h>
#include<linux/fcntl.h>



#include<linux/time.h>



#include<linux/stat.h>




#include<linux/capability.h>

#include<asm/poll.h>






#include<asm/sembuf.h>

#include<linux/socket.h>






#include<linux/ioctl.h>


#include<linux/rseq.h>







#include<linux/blkzoned.h>












#include<linux/sockios.h>









#include<linux/unistd.h>
#include<linux/ipc.h>

#include<linux/magic.h>





#include<linux/param.h>
#include<linux/if_ether.h>
#include<linux/fs.h>
#include<linux/rtnetlink.h>

#include<linux/if.h>


#include<linux/random.h>

#include<asm/siginfo.h>
#include<asm-generic/hugetlb_encode.h>

#include<linux/sched.h>


#include<asm/hw_breakpoint.h>
#include<linux/uuid.h>
#include<linux/neighbour.h>

#include<linux/route.h>




#include<linux/if_vlan.h>
#include<linux/types.h>


#include<asm/signal.h>



#include<string.h>

#include<asm/stat.h>

#include<linux/ipv6.h>




#include<linux/uio.h>
#include<linux/wait.h>





#include<linux/net.h>

#include<linux/elf-em.h>

#include<linux/major.h>






#include<asm/bpf_perf_event.h>


#include<linux/filter.h>













#include<linux/fib_rules.h>



#include<asm/bitsperlong.h>



#include<asm/ipcbuf.h>








#include<linux/if_packet.h>
#define GNTCOPY_dest_gref         (1<<_GNTCOPY_dest_gref)
#define GNTCOPY_source_gref       (1<<_GNTCOPY_source_gref)
#define GNTMAP_application_map  (1<<_GNTMAP_application_map)
#define GNTMAP_contains_pte     (1<<_GNTMAP_contains_pte)
#define GNTMAP_device_map       (1<<_GNTMAP_device_map)
#define GNTMAP_guest_avail_mask ((uint32_t)~0 << _GNTMAP_guest_avail0)
#define GNTMAP_host_map         (1<<_GNTMAP_host_map)
#define GNTMAP_readonly         (1<<_GNTMAP_readonly)
#define GNTST_address_too_big (-11) 
#define GNTST_bad_copy_arg    (-10) 
#define GNTST_bad_dev_addr     (-6) 
#define GNTST_bad_domain       (-2) 
#define GNTST_bad_gntref       (-3) 
#define GNTST_bad_handle       (-4) 
#define GNTST_bad_page         (-9) 
#define GNTST_bad_virt_addr    (-5) 
#define GNTST_eagain          (-12) 
#define GNTST_general_error    (-1) 
#define GNTST_no_device_space  (-7) 
#define GNTST_okay             (0)  
#define GNTST_permission_denied (-8) 
#define GNTTABOP_cache_flush          12
#define GNTTABOP_copy                 5
#define GNTTABOP_dump_table           3
#define GNTTABOP_error_msgs {                   \
    "okay",                                     \
    "undefined error",                          \
    "unrecognised domain id",                   \
    "invalid grant reference",                  \
    "invalid mapping handle",                   \
    "invalid virtual address",                  \
    "invalid device address",                   \
    "no spare translation slot in the I/O MMU", \
    "permission denied",                        \
    "bad page",                                 \
    "copy arguments cross page boundary",       \
    "page address size too large",              \
    "operation not done; try again"             \
}
#define GNTTABOP_get_status_frames     9
#define GNTTABOP_get_version          10
#define GNTTABOP_map_grant_ref        0
#define GNTTABOP_query_size           6
#define GNTTABOP_set_version          8
#define GNTTABOP_setup_table          2
#define GNTTABOP_transfer                4
#define GNTTABOP_unmap_and_replace    7
#define GNTTABOP_unmap_grant_ref      1
#define GNTTAB_CACHE_CLEAN          (1<<0)
#define GNTTAB_CACHE_INVAL          (1<<1)
#define GNTTAB_CACHE_SOURCE_GREF    (1<<31)
#define GTF_accept_transfer (2U<<0)
#define GTF_invalid         (0U<<0)
#define GTF_permit_access   (1U<<0)
#define GTF_reading         (1U<<_GTF_reading)
#define GTF_readonly        (1U<<_GTF_readonly)
#define GTF_sub_page        (1U<<_GTF_sub_page)
#define GTF_transfer_committed  (1U<<_GTF_transfer_committed)
#define GTF_transfer_completed  (1U<<_GTF_transfer_completed)
#define GTF_transitive      (3U<<0)
#define GTF_type_mask       (3U<<0)
#define GTF_writing         (1U<<_GTF_writing)
#define _GNTCOPY_dest_gref        (1)
#define _GNTCOPY_source_gref      (0)
#define _GNTMAP_application_map (3)
#define _GNTMAP_contains_pte    (4)
#define _GNTMAP_device_map      (0)
#define _GNTMAP_guest_avail0    (16)
#define _GNTMAP_host_map        (1)
#define _GNTMAP_readonly        (2)
#define _GTF_reading        (3)
#define _GTF_readonly       (2)
#define _GTF_sub_page       (8)
#define _GTF_transfer_committed (2)
#define _GTF_transfer_completed (3)
#define _GTF_writing        (4)

#define CONSOLEIO_read          1
#define CONSOLEIO_write         0
#define DOMID_COW  (0x7FF3U)
#define DOMID_FIRST_RESERVED (0x7FF0U)
#define DOMID_IDLE (0x7FFFU)
#define DOMID_INVALID (0x7FF4U)
#define DOMID_IO   (0x7FF1U)
#define DOMID_SELF (0x7FF0U)
#define DOMID_XEN  (0x7FF2U)
#define MAX_GUEST_CMDLINE 1024
#define MAX_VMASST_TYPE 5
#define MMUEXT_CLEAR_PAGE       16
#define MMUEXT_COPY_PAGE        17
#define MMUEXT_FLUSH_CACHE      12
#define MMUEXT_FLUSH_CACHE_GLOBAL 18
#define MMUEXT_INVLPG_ALL       11
#define MMUEXT_INVLPG_LOCAL      7
#define MMUEXT_INVLPG_MULTI      9
#define MMUEXT_MARK_SUPER       19
#define MMUEXT_NEW_BASEPTR       5
#define MMUEXT_NEW_USER_BASEPTR 15
#define MMUEXT_PIN_L1_TABLE      0
#define MMUEXT_PIN_L2_TABLE      1
#define MMUEXT_PIN_L3_TABLE      2
#define MMUEXT_PIN_L4_TABLE      3
#define MMUEXT_SET_LDT          13
#define MMUEXT_TLB_FLUSH_ALL    10
#define MMUEXT_TLB_FLUSH_LOCAL   6
#define MMUEXT_TLB_FLUSH_MULTI   8
#define MMUEXT_UNMARK_SUPER     20
#define MMUEXT_UNPIN_TABLE       4
#define MMU_MACHPHYS_UPDATE        1 
#define MMU_NORMAL_PT_UPDATE       0 
#define MMU_PT_UPDATE_NO_TRANSLATE 3 
#define MMU_PT_UPDATE_PRESERVE_AD  2 
#define NR_VIRQS       24
#define SIF_INITDOMAIN      (1<<1)  
#define SIF_MOD_START_PFN   (1<<3)  
#define SIF_MULTIBOOT_MOD   (1<<2)  
#define SIF_PM_MASK       (0xFF<<8) 
#define SIF_PRIVILEGED      (1<<0)  
#define SIF_VIRT_P2M_4TOOLS (1<<4)  
#define TMEM_SPEC_VERSION 1
#define UVMF_ALL                (1UL<<2) 
#define UVMF_FLUSHTYPE_MASK     (3UL<<0)
#define UVMF_INVLPG             (2UL<<0) 
#define UVMF_LOCAL              (0UL<<2) 
#define UVMF_MULTI              (0UL<<2) 
#define UVMF_NONE               (0UL<<0) 
#define UVMF_TLB_FLUSH          (1UL<<0) 
#define VIRQ_ARCH_0    16
#define VIRQ_ARCH_1    17
#define VIRQ_ARCH_2    18
#define VIRQ_ARCH_3    19
#define VIRQ_ARCH_4    20
#define VIRQ_ARCH_5    21
#define VIRQ_ARCH_6    22
#define VIRQ_ARCH_7    23
#define VIRQ_CONSOLE    2  
#define VIRQ_CON_RING   8  
#define VIRQ_DEBUG      1  
#define VIRQ_DEBUGGER   6  
#define VIRQ_DOM_EXC    3  
#define VIRQ_ENOMEM     12 
#define VIRQ_MEM_EVENT  10 
#define VIRQ_PCPU_STATE 9  
#define VIRQ_TBUF       4  
#define VIRQ_TIMER      0  
#define VIRQ_XC_RESERVED 11 
#define VIRQ_XENOPROF   7  
#define VIRQ_XENPMU     13  
#define VMASST_CMD_disable               1
#define VMASST_CMD_enable                0
#define VMASST_TYPE_4gb_segments         0
#define VMASST_TYPE_4gb_segments_notify  1
#define VMASST_TYPE_architectural_iopl   4
#define VMASST_TYPE_pae_extended_cr3     3
#define VMASST_TYPE_runstate_update_flag 5
#define VMASST_TYPE_writable_pagetables  2
#define XEN_VGATYPE_EFI_LFB     0x70
#define XEN_VGATYPE_TEXT_MODE_3 0x03
#define XEN_VGATYPE_VESA_LFB    0x23
#define __HYPERVISOR_arch_0               48
#define __HYPERVISOR_arch_1               49
#define __HYPERVISOR_arch_2               50
#define __HYPERVISOR_arch_3               51
#define __HYPERVISOR_arch_4               52
#define __HYPERVISOR_arch_5               53
#define __HYPERVISOR_arch_6               54
#define __HYPERVISOR_arch_7               55
#define __HYPERVISOR_callback_op          30
#define __HYPERVISOR_console_io           18
#define __HYPERVISOR_dm_op                41
#define __HYPERVISOR_domctl               36
#define __HYPERVISOR_event_channel_op     32
#define __HYPERVISOR_event_channel_op_compat 16
#define __HYPERVISOR_fpu_taskswitch        5
#define __HYPERVISOR_get_debugreg          9
#define __HYPERVISOR_grant_table_op       20
#define __HYPERVISOR_hvm_op               34
#define __HYPERVISOR_iret                 23 
#define __HYPERVISOR_kexec_op             37
#define __HYPERVISOR_memory_op            12
#define __HYPERVISOR_mmu_update            1
#define __HYPERVISOR_mmuext_op            26
#define __HYPERVISOR_multicall            13
#define __HYPERVISOR_nmi_op               28
#define __HYPERVISOR_physdev_op           33
#define __HYPERVISOR_physdev_op_compat    19
#define __HYPERVISOR_platform_op           7
#define __HYPERVISOR_sched_op             29
#define __HYPERVISOR_sched_op_compat       6
#define __HYPERVISOR_set_callbacks         4
#define __HYPERVISOR_set_debugreg          8
#define __HYPERVISOR_set_gdt               2
#define __HYPERVISOR_set_segment_base     25 
#define __HYPERVISOR_set_timer_op         15
#define __HYPERVISOR_set_trap_table        0
#define __HYPERVISOR_stack_switch          3
#define __HYPERVISOR_sysctl               35
#define __HYPERVISOR_tmem_op              38
#define __HYPERVISOR_update_descriptor    10
#define __HYPERVISOR_update_va_mapping    14
#define __HYPERVISOR_update_va_mapping_otherdomain 22
#define __HYPERVISOR_vcpu_op              24
#define __HYPERVISOR_vm_assist            21
#define __HYPERVISOR_xc_reserved_op       39 
#define __HYPERVISOR_xen_version          17
#define __HYPERVISOR_xenoprof_op          31
#define __HYPERVISOR_xenpmu_op            40
#define __HYPERVISOR_xsm_op               27

#define __mk_unsigned_long(x) x ## UL
#define mk_unsigned_long(x) __mk_unsigned_long(x)
#define XENMAPSPACE_dev_mmio     5 
#define XENMAPSPACE_gmfn         2 
#define XENMAPSPACE_gmfn_foreign 4 
#define XENMAPSPACE_gmfn_range   3 
#define XENMAPSPACE_grant_table  1 
#define XENMAPSPACE_shared_info  0 
#define XENMEM_acquire_resource 28
#define XENMEM_add_to_physmap      7
#define XENMEM_add_to_physmap_range 23
#define XENMEM_current_reservation  3
#define XENMEM_decrease_reservation 1
#define XENMEM_exchange             11
#define XENMEM_increase_reservation 0
#define XENMEM_machine_memory_map   10
#define XENMEM_machphys_mapping     12
#define XENMEM_machphys_mfn_list    5
#define XENMEM_maximum_ram_page     2
#define XENMEM_maximum_reservation  4
#define XENMEM_memory_map           9
#define XENMEM_populate_physmap     6
#define XENMEM_remove_from_physmap      15
#define XENMEM_resource_grant_table 1
#define XENMEM_resource_grant_table_id_shared 0
#define XENMEM_resource_grant_table_id_status 1
#define XENMEM_resource_ioreq_server 0
#define XENMEM_resource_ioreq_server_frame_bufioreq 0
#define XENMEM_resource_ioreq_server_frame_ioreq(n) (1 + (n))
#define XENMEM_rsrc_acq_caller_owned (1u << _XENMEM_rsrc_acq_caller_owned)
#define _XENMEM_rsrc_acq_caller_owned 0

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
# define ASM_REACHABLE
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
#define __annotate_unreachable(c) ({					\
	asm volatile(__stringify_label(c) ":\n\t"			\
		     ".pushsection .discard.unreachable\n\t"		\
		     ".long " __stringify_label(c) "b - .\n\t"		\
		     ".popsection\n\t" : : "i" (c));			\
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
#define ERESTART_RESTARTBLOCK 516 


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
		     ".popsection\n\t" : : "i" (c));			\
})
#define __instrumentation_end(c) ({					\
	asm volatile(__stringify(c) ": nop\n\t"				\
		     ".pushsection .discard.instr_end\n\t"		\
		     ".long " __stringify(c) "b - .\n\t"		\
		     ".popsection\n\t" : : "i" (c));			\
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
#define XEN_NETIF_CTRL_HASH_ALGORITHM_NONE 0
#define XEN_NETIF_CTRL_HASH_ALGORITHM_TOEPLITZ 1
#define XEN_NETIF_CTRL_HASH_TYPE_IPV4 \
	(1 << _XEN_NETIF_CTRL_HASH_TYPE_IPV4)
#define XEN_NETIF_CTRL_HASH_TYPE_IPV4_TCP \
	(1 << _XEN_NETIF_CTRL_HASH_TYPE_IPV4_TCP)
#define XEN_NETIF_CTRL_HASH_TYPE_IPV6 \
	(1 << _XEN_NETIF_CTRL_HASH_TYPE_IPV6)
#define XEN_NETIF_CTRL_HASH_TYPE_IPV6_TCP \
	(1 << _XEN_NETIF_CTRL_HASH_TYPE_IPV6_TCP)
#define XEN_NETIF_CTRL_STATUS_BUFFER_OVERFLOW   3
#define XEN_NETIF_CTRL_STATUS_INVALID_PARAMETER 2
#define XEN_NETIF_CTRL_STATUS_NOT_SUPPORTED     1
#define XEN_NETIF_CTRL_STATUS_SUCCESS           0
#define XEN_NETIF_CTRL_TYPE_GET_HASH_FLAGS        1
#define XEN_NETIF_CTRL_TYPE_GET_HASH_MAPPING_SIZE 4
#define XEN_NETIF_CTRL_TYPE_INVALID               0
#define XEN_NETIF_CTRL_TYPE_SET_HASH_ALGORITHM    7
#define XEN_NETIF_CTRL_TYPE_SET_HASH_FLAGS        2
#define XEN_NETIF_CTRL_TYPE_SET_HASH_KEY          3
#define XEN_NETIF_CTRL_TYPE_SET_HASH_MAPPING      6
#define XEN_NETIF_CTRL_TYPE_SET_HASH_MAPPING_SIZE 5
#define XEN_NETIF_EXTRA_FLAG_MORE  (1U<<_XEN_NETIF_EXTRA_FLAG_MORE)
#define XEN_NETIF_EXTRA_TYPE_GSO       (1)	
#define XEN_NETIF_EXTRA_TYPE_HASH      (4)	
#define XEN_NETIF_EXTRA_TYPE_MAX       (6)
#define XEN_NETIF_EXTRA_TYPE_MCAST_ADD (2)	
#define XEN_NETIF_EXTRA_TYPE_MCAST_DEL (3)	
#define XEN_NETIF_EXTRA_TYPE_NONE      (0)	
#define XEN_NETIF_EXTRA_TYPE_XDP       (5)	
#define XEN_NETIF_GSO_TYPE_NONE         (0)
#define XEN_NETIF_GSO_TYPE_TCPV4        (1)
#define XEN_NETIF_GSO_TYPE_TCPV6        (2)
#define XEN_NETIF_MAX_TX_SIZE 0xFFFF
#define XEN_NETIF_MAX_XDP_HEADROOM 0x7FFF
#define XEN_NETIF_NR_SLOTS_MIN 18
#define XEN_NETIF_RSP_DROPPED         -2
#define XEN_NETIF_RSP_ERROR           -1
#define XEN_NETIF_RSP_NULL             1
#define XEN_NETIF_RSP_OKAY             0
#define  XEN_NETRXF_csum_blank     (1U<<_XEN_NETRXF_csum_blank)
#define  XEN_NETRXF_data_validated (1U<<_XEN_NETRXF_data_validated)
#define  XEN_NETRXF_extra_info     (1U<<_XEN_NETRXF_extra_info)
#define  XEN_NETRXF_gso_prefix     (1U<<_XEN_NETRXF_gso_prefix)
#define  XEN_NETRXF_more_data      (1U<<_XEN_NETRXF_more_data)
#define  XEN_NETTXF_csum_blank     (1U<<_XEN_NETTXF_csum_blank)
#define  XEN_NETTXF_data_validated (1U<<_XEN_NETTXF_data_validated)
#define  XEN_NETTXF_extra_info     (1U<<_XEN_NETTXF_extra_info)
#define  XEN_NETTXF_more_data      (1U<<_XEN_NETTXF_more_data)
#define _XEN_NETIF_CTRL_HASH_TYPE_IPV4 0
#define _XEN_NETIF_CTRL_HASH_TYPE_IPV4_TCP 1
#define _XEN_NETIF_CTRL_HASH_TYPE_IPV6 2
#define _XEN_NETIF_CTRL_HASH_TYPE_IPV6_TCP 3
#define _XEN_NETIF_EXTRA_FLAG_MORE (0)
#define _XEN_NETRXF_csum_blank     (1)
#define _XEN_NETRXF_data_validated (0)
#define _XEN_NETRXF_extra_info     (3)
#define _XEN_NETRXF_gso_prefix     (4)
#define _XEN_NETRXF_more_data      (2)
#define _XEN_NETTXF_csum_blank     (0)
#define _XEN_NETTXF_data_validated (1)
#define _XEN_NETTXF_extra_info     (3)
#define _XEN_NETTXF_more_data      (2)

#define GNTTAB_RESERVED_XENSTORE 1
#define INVALID_GRANT_HANDLE       ((grant_handle_t)-1)
#define INVALID_GRANT_REF          ((grant_ref_t)-1)
#define NR_GRANT_FRAMES 4

#define gnttab_map_vaddr(map) ((void *)(map.host_virt_addr))
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
#define XEN_EXTRA_MEM_MAX_REGIONS 128 
#define XEN_PFN_DOWN(x)	((x) >> XEN_PAGE_SHIFT)
#define XEN_PFN_UP(x)	(((x) + XEN_PAGE_SIZE-1) >> XEN_PAGE_SHIFT)

#define page_to_xen_pfn(page)		\
	((page_to_pfn(page)) << (PAGE_SHIFT - XEN_PAGE_SHIFT))
#define xen_offset_in_page(p)	((unsigned long)(p) & ~XEN_PAGE_MASK)
#define xen_pfn_to_page(xen_pfn)	\
	(pfn_to_page((unsigned long)(xen_pfn) >> (PAGE_SHIFT - XEN_PAGE_SHIFT)))

#define XENFEAT_ARM_SMCCC_supported       14
#define XENFEAT_NR_SUBMAPS 1
#define XENFEAT_auto_translated_physmap    2
#define XENFEAT_direct_mapped             17
#define XENFEAT_dom0                      11
#define XENFEAT_gnttab_map_avail_bits      7
#define XENFEAT_highmem_assist             6
#define XENFEAT_hvm_callback_vector        8
#define XENFEAT_hvm_pirqs           10
#define XENFEAT_hvm_safe_pvclock           9
#define XENFEAT_linux_rsdp_unrestricted   15
#define XENFEAT_memory_op_vnode_supported 13
#define XENFEAT_mmu_pt_update_preserve_ad  5
#define XENFEAT_not_direct_mapped         16
#define XENFEAT_pae_pgdir_above_4gb        4
#define XENFEAT_supervisor_mode_kernel     3
#define XENFEAT_writable_descriptor_tables 1
#define XENFEAT_writable_page_tables       0

#define XEN_IOPORT_BASE 0x10
#define XEN_IOPORT_LINUX_DRVVER  0x0001
#define XEN_IOPORT_LINUX_PRODNUM 0x0003
#define XEN_IOPORT_MAGIC_VAL 0x49d2
#define XEN_UNPLUG_UNNECESSARY 		(1<<16)

#define XEN_IRQ_PRIORITY_DEFAULT EVTCHN_FIFO_PRIORITY_DEFAULT
#define XEN_IRQ_PRIORITY_MAX     EVTCHN_FIFO_PRIORITY_MAX
#define XEN_IRQ_PRIORITY_MIN     EVTCHN_FIFO_PRIORITY_MIN

#define BIND_PIRQ__WILL_SHARE 1
#define EVTCHNOP_bind_interdomain 0
#define EVTCHNOP_expand_array    12
#define EVTCHNOP_init_control    11
#define EVTCHNOP_set_priority    13
#define EVTCHN_2L_NR_CHANNELS (sizeof(xen_ulong_t) * sizeof(xen_ulong_t) * 64)
#define EVTCHN_FIFO_BUSY    28
#define EVTCHN_FIFO_LINKED  29
#define EVTCHN_FIFO_LINK_BITS 17
#define EVTCHN_FIFO_LINK_MASK ((1 << EVTCHN_FIFO_LINK_BITS) - 1)
#define EVTCHN_FIFO_MASKED  30
#define EVTCHN_FIFO_MAX_QUEUES (EVTCHN_FIFO_PRIORITY_MIN + 1)
#define EVTCHN_FIFO_NR_CHANNELS (1 << EVTCHN_FIFO_LINK_BITS)
#define EVTCHN_FIFO_PENDING 31
#define EVTCHN_FIFO_PRIORITY_DEFAULT 7
#define EVTCHN_FIFO_PRIORITY_MAX     0
#define EVTCHN_FIFO_PRIORITY_MIN     15


#define dev_to_msi_list(dev)		(&(dev)->msi_list)
#define first_msi_entry(dev)		\
	list_first_entry(dev_to_msi_list((dev)), struct msi_desc, list)
#define first_pci_msi_entry(pdev)	first_msi_entry(&(pdev)->dev)
#define for_each_msi_entry(desc, dev)	\
	list_for_each_entry((desc), dev_to_msi_list((dev)), list)
#define for_each_msi_entry_safe(desc, tmp, dev)	\
	list_for_each_entry_safe((desc), (tmp), dev_to_msi_list((dev)), list)
#define for_each_msi_vector(desc, __irq, dev)				\
	for_each_msi_entry((desc), (dev))				\
		if ((desc)->irq)					\
			for (__irq = (desc)->irq;			\
			     __irq < ((desc)->irq + (desc)->nvec_used);	\
			     __irq++)
#define for_each_pci_msi_entry(desc, pdev)	\
	for_each_msi_entry((desc), &(pdev)->dev)
#define msi_desc_to_dev(desc)		((desc)->dev)
#define platform_msi_create_device_domain(dev, nvec, write, ops, data)	\
	__platform_msi_create_device_domain(dev, nvec, false, write, ops, data)
#define platform_msi_create_device_tree_domain(dev, nvec, write, ops, data) \
	__platform_msi_create_device_domain(dev, nvec, true, write, ops, data)


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
#define IRQ_MSK(n) (u32)((n) < 32 ? ((1 << (n)) - 1) : UINT_MAX)
# define NR_IRQS_LEGACY 0

#define __irqd_to_state(d) ACCESS_PRIVATE((d)->common, state_use_accessors)
#define devm_irq_alloc_desc(dev, node)				\
	devm_irq_alloc_descs(dev, -1, 1, 1, node)
#define devm_irq_alloc_desc_at(dev, at, node)			\
	devm_irq_alloc_descs(dev, at, at, 1, node)
#define devm_irq_alloc_desc_from(dev, from, node)		\
	devm_irq_alloc_descs(dev, -1, from, 1, node)
#define devm_irq_alloc_descs(dev, irq, from, cnt, node)		\
	__devm_irq_alloc_descs(dev, irq, from, cnt, node, THIS_MODULE, NULL)
#define devm_irq_alloc_descs_from(dev, from, cnt, node)		\
	devm_irq_alloc_descs(dev, -1, from, cnt, node)
#define irq_alloc_desc(node)			\
	irq_alloc_descs(-1, 1, 1, node)
#define irq_alloc_desc_at(at, node)		\
	irq_alloc_descs(at, at, 1, node)
#define irq_alloc_desc_from(from, node)		\
	irq_alloc_descs(-1, from, 1, node)
#define irq_alloc_descs(irq, from, cnt, node)	\
	__irq_alloc_descs(irq, from, cnt, node, THIS_MODULE, NULL)
#define irq_alloc_descs_from(from, cnt, node)	\
	irq_alloc_descs(-1, from, cnt, node)
#define irq_alloc_domain_generic_chips(d, irqs_per_chip, num_ct, name,	\
				       handler,	clr, set, flags)	\
({									\
	MAYBE_BUILD_BUG_ON(irqs_per_chip > 32);				\
	__irq_alloc_domain_generic_chips(d, irqs_per_chip, num_ct, name,\
					 handler, clr, set, flags);	\
})
#define irq_gc_lock_irqsave(gc, flags)	\
	raw_spin_lock_irqsave(&(gc)->lock, flags)
#define irq_gc_unlock_irqrestore(gc, flags)	\
	raw_spin_unlock_irqrestore(&(gc)->lock, flags)
#define set_handle_irq(handle_irq)		\
	do {					\
		(void)handle_irq;		\
		WARN_ON(1);			\
	} while (0)

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
#define pte_index pte_index
#define pte_leaf_size(x) PAGE_SIZE
#define pte_mk_savedwrite pte_mkwrite
#define pte_offset_kernel pte_offset_kernel
#define pte_offset_map(dir, address)	pte_offset_kernel((dir), (address))
#define pte_savedwrite pte_write
#define pte_unmap(pte) kunmap_atomic((pte))
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
#define IOMEM_ERR_PTR(err) (__force void __iomem *)ERR_PTR(err)

#define arch_has_dev_port()     (1)
#define arch_phys_wc_add arch_phys_wc_add
#define arch_phys_wc_index arch_phys_wc_index
#define pci_remap_cfgspace pci_remap_cfgspace

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

# define __hrtimer_clock_base_align



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



#define XBT_NIL ((struct xenbus_transaction) { 0 })
#define XENBUS_EXIST_ERR(err) ((err) == -ENOENT || (err) == -ERANGE)
#define XENBUS_IS_ERR_READ(str) ({			\
	if (!IS_ERR(str) && strlen(str) == 0) {		\
		kfree(str);				\
		str = ERR_PTR(-ERANGE);			\
	}						\
	IS_ERR(str);					\
})
#define XENBUS_MAX_RING_GRANTS      (1U << XENBUS_MAX_RING_GRANT_ORDER)
#define XENBUS_MAX_RING_GRANT_ORDER 4

#define xenbus_register_backend(drv) \
	__xenbus_register_backend(drv, THIS_MODULE, KBUILD_MODNAME)
#define xenbus_register_frontend(drv) \
	__xenbus_register_frontend(drv, THIS_MODULE, KBUILD_MODNAME)
#define MASK_XENSTORE_IDX(idx) ((idx) & (XENSTORE_RING_SIZE-1))
#define XENSTORE_PAYLOAD_MAX 4096
#define XENSTORE_RING_SIZE 1024
#define XSD_ERROR(x) { x, #x }
#define XS_WRITE_CREATE "CREATE"
#define XS_WRITE_CREATE_EXCL "CREATE|EXCL"
#define XS_WRITE_NONE "NONE"


#define DEFINE_SEMAPHORE(name)	\
	struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)

#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.lock		= __RAW_SPIN_LOCK_UNLOCKED((name).lock),	\
	.count		= n,						\
	.wait_list	= LIST_HEAD_INIT((name).wait_list),		\
}
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
#define MAX_RESOURCE ((resource_size_t)~0)


#define page_ref_tracepoint_active(t) tracepoint_enabled(t)
#define DECLARE_TRACEPOINT(tp) \
	extern struct tracepoint __tracepoint_##tp
#define TRACEPOINT_DEFS_H 1
# define tracepoint_enabled(tp) \
	static_key_false(&(__tracepoint_##tp).key)


#define DEFAULT_SEEKS 2 
#define SHRINK_EMPTY (~0UL - 1)
#define SHRINK_STOP (~0UL)


#define MMAP_LOCK_INITIALIZER(name) \
	.mmap_lock = __RWSEM_INITIALIZER((name).mmap_lock),


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
#define EM_DATA_CB(_active_power_cb) { }
#define EM_MAX_POWER 0xFFFF

#define em_scale_power(p) ((p) * 1000)
#define em_span_cpus(em) (to_cpumask((em)->cpus))
#define SD_FLAG(name, mflags) __##name,
# define SD_INIT_NAME(type)		.name = #type

#define SDF_NEEDS_GROUPS       0x4
#define SDF_SHARED_CHILD       0x1
#define SDF_SHARED_PARENT      0x2



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

#define xen_alloc_unpopulated_pages alloc_xenballooned_pages
#define xen_domain()		(xen_domain_type != XEN_NATIVE)
#define xen_free_unpopulated_pages free_xenballooned_pages
#define xen_hvm_domain()	(xen_domain_type == XEN_HVM_DOMAIN)
#define xen_initial_domain()	(xen_domain() && \
				 (xen_start_flags & SIF_INITDOMAIN))
#define xen_pv_domain()		(xen_domain_type == XEN_PV_DOMAIN)
#define xen_pvh_domain()	(xen_pvh)

#define XEN_HVM_MEMMAP_TYPE_ACPI      3
#define XEN_HVM_MEMMAP_TYPE_DISABLED  6
#define XEN_HVM_MEMMAP_TYPE_NVS       4
#define XEN_HVM_MEMMAP_TYPE_PMEM      7
#define XEN_HVM_MEMMAP_TYPE_RAM       1
#define XEN_HVM_MEMMAP_TYPE_RESERVED  2
#define XEN_HVM_MEMMAP_TYPE_UNUSABLE  5
#define XEN_HVM_START_MAGIC_VALUE 0x336ec578


#define TRACE_SYSTEM xdp


#define __MEM_TYPE_MAP(FN)	\
	FN(PAGE_SHARED)		\
	FN(PAGE_ORDER0)		\
	FN(PAGE_POOL)		\
	FN(XSK_BUFF_POOL)
#define __MEM_TYPE_SYM_FN(x)	\
	{ MEM_TYPE_##x, #x },
#define __MEM_TYPE_TP_FN(x)	\
	TRACE_DEFINE_ENUM(MEM_TYPE_##x);
#define __XDP_ACT_MAP(FN)	\
	FN(ABORTED)		\
	FN(DROP)		\
	FN(PASS)		\
	FN(TX)			\
	FN(REDIRECT)
#define __XDP_ACT_SYM_FN(x)	\
	{ XDP_##x, #x },
#define __XDP_ACT_TP_FN(x)	\
	TRACE_DEFINE_ENUM(XDP_##x);
#define _trace_xdp_redirect(dev, xdp, to)						\
	 trace_xdp_redirect(dev, xdp, NULL, 0, BPF_MAP_TYPE_UNSPEC, INT_MAX, to)
#define _trace_xdp_redirect_err(dev, xdp, to, err)					\
	 trace_xdp_redirect_err(dev, xdp, NULL, err, BPF_MAP_TYPE_UNSPEC, INT_MAX, to)
#define _trace_xdp_redirect_map(dev, xdp, to, map_type, map_id, index) \
	 trace_xdp_redirect(dev, xdp, to, 0, map_type, map_id, index)
#define _trace_xdp_redirect_map_err(dev, xdp, to, map_type, map_id, index, err) \
	 trace_xdp_redirect_err(dev, xdp, to, err, map_type, map_id, index)

#define DECLARE_TRACE(name, proto, args)	\
	DEFINE_TRACE(name, PARAMS(proto), PARAMS(args))
#define DEFINE_EVENT(template, name, proto, args) \
	DEFINE_TRACE(name, PARAMS(proto), PARAMS(args))
#define DEFINE_EVENT_CONDITION(template, name, proto, args, cond) \
	DEFINE_EVENT(template, name, PARAMS(proto), PARAMS(args))
#define DEFINE_EVENT_FN(template, name, proto, args, reg, unreg) \
	DEFINE_TRACE_FN(name, reg, unreg, PARAMS(proto), PARAMS(args))
#define DEFINE_EVENT_NOP(template, name, proto, args)
#define DEFINE_EVENT_PRINT(template, name, proto, args, print)	\
	DEFINE_TRACE(name, PARAMS(proto), PARAMS(args))
#define TRACE_EVENT(name, proto, args, tstruct, assign, print)	\
	DEFINE_TRACE(name, PARAMS(proto), PARAMS(args))
#define TRACE_EVENT_CONDITION(name, proto, args, cond, tstruct, assign, print) \
	TRACE_EVENT(name,						\
		PARAMS(proto),						\
		PARAMS(args),						\
		PARAMS(tstruct),					\
		PARAMS(assign),						\
		PARAMS(print))
#define TRACE_EVENT_FN(name, proto, args, tstruct,		\
		assign, print, reg, unreg)			\
	DEFINE_TRACE_FN(name, reg, unreg, PARAMS(proto), PARAMS(args))
#define TRACE_EVENT_FN_COND(name, proto, args, cond, tstruct,		\
		assign, print, reg, unreg)			\
	DEFINE_TRACE_FN(name, reg, unreg, PARAMS(proto), PARAMS(args))
#define TRACE_EVENT_NOP(name, proto, args, struct, assign, print)

# define TRACE_INCLUDE(system) __TRACE_INCLUDE(system)
# define TRACE_INCLUDE_FILE TRACE_SYSTEM
# define UNDEF_TRACE_INCLUDE_FILE
# define UNDEF_TRACE_INCLUDE_PATH
# define __TRACE_INCLUDE(system) <trace/events/system.h>
#define CAST_TO_U64(...) CONCATENATE(__CAST, COUNT_ARGS(__VA_ARGS__))(__VA_ARGS__)
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
	__BPF_DECLARE_TRACE(call, PARAMS(proto), PARAMS(args))
#define DEFINE_EVENT_WRITABLE(template, call, proto, args, size)	\
static inline void bpf_test_buffer_##call(void)				\
{									\
									\
	FIRST(proto);							\
	(void)BUILD_BUG_ON_ZERO(size != sizeof(*FIRST(args)));		\
}									\
__DEFINE_EVENT(template, call, PARAMS(proto), PARAMS(args), size)
#define FIRST(x, ...) x
#define UINTTYPE(size) \
	__typeof__(__builtin_choose_expr(size == 1,  (u8)1, \
		   __builtin_choose_expr(size == 2, (u16)2, \
		   __builtin_choose_expr(size == 4, (u32)3, \
		   __builtin_choose_expr(size == 8, (u64)4, \
					 (void)5)))))
#define __BPF_DECLARE_TRACE(call, proto, args)				\
static notrace void							\
__bpf_trace_##call(void *__data, proto)					\
{									\
	struct bpf_prog *prog = __data;					\
	CONCATENATE(bpf_trace_run, COUNT_ARGS(args))(prog, CAST_TO_U64(args));	\
}
#define __CAST1(a,...) __CAST_TO_U64(a)
#define __CAST10(a,...) __CAST_TO_U64(a), __CAST9(__VA_ARGS__)
#define __CAST11(a,...) __CAST_TO_U64(a), __CAST10(__VA_ARGS__)
#define __CAST12(a,...) __CAST_TO_U64(a), __CAST11(__VA_ARGS__)
#define __CAST2(a,...) __CAST_TO_U64(a), __CAST1(__VA_ARGS__)
#define __CAST3(a,...) __CAST_TO_U64(a), __CAST2(__VA_ARGS__)
#define __CAST4(a,...) __CAST_TO_U64(a), __CAST3(__VA_ARGS__)
#define __CAST5(a,...) __CAST_TO_U64(a), __CAST4(__VA_ARGS__)
#define __CAST6(a,...) __CAST_TO_U64(a), __CAST5(__VA_ARGS__)
#define __CAST7(a,...) __CAST_TO_U64(a), __CAST6(__VA_ARGS__)
#define __CAST8(a,...) __CAST_TO_U64(a), __CAST7(__VA_ARGS__)
#define __CAST9(a,...) __CAST_TO_U64(a), __CAST8(__VA_ARGS__)
#define __CAST_TO_U64(x) ({ \
	typeof(x) __src = (x); \
	UINTTYPE(sizeof(x)) __dst; \
	memcpy(&__dst, &__src, sizeof(__dst)); \
	(u64)__dst; })
#define __DEFINE_EVENT(template, call, proto, args, size)		\
static inline void bpf_test_probe_##call(void)				\
{									\
	check_trace_callback_type_##call(__bpf_trace_##template);	\
}									\
typedef void (*btf_trace_##call)(void *__data, proto);			\
static union {								\
	struct bpf_raw_event_map event;					\
	btf_trace_##call handler;					\
} __bpf_trace_tp_map_##call __used					\
__section("__bpf_raw_tp_map") = {					\
	.event = {							\
		.tp		= &__tracepoint_##call,			\
		.bpf_func	= __bpf_trace_##template,		\
		.num_args	= COUNT_ARGS(args),			\
		.writable_size	= size,					\
	},								\
};
#define __entry entry
#define __get_bitmask(field) (char *)__get_dynamic_array(field)
#define __get_dynamic_array(field)	\
		((void *)__entry + (__entry->__data_loc_##field & 0xffff))
#define __get_dynamic_array_len(field)	\
		((__entry->__data_loc_##field >> 16) & 0xffff)
#define __get_str(field) ((char *)__get_dynamic_array(field))
#define __perf_count(c)	(c)
#define __perf_task(t)	(t)
#define TP_STRUCT__entry(args...) args
#define TP_fast_assign(args...) args
#define TP_printk(fmt, args...) fmt "\n", args


#define TRACE_EVENT_FLAGS(name, value)					\
	__TRACE_EVENT_FLAGS(name, value)
#define TRACE_EVENT_PERF_PERM(name, expr...)				\
	__TRACE_EVENT_PERF_PERM(name, expr)
#define TRACE_MAKE_SYSTEM_STR()				\
	static const char TRACE_SYSTEM_STRING[] =	\
		__stringify(TRACE_SYSTEM)
#define TRACE_SYSTEM_STRING __app(TRACE_SYSTEM_VAR,__trace_system_name)
#define TRACE_SYSTEM_VAR TRACE_SYSTEM
#define _TRACE_PERF_INIT(call)						\
	.perf_probe		= perf_trace_##call,
#define _TRACE_PERF_PROTO(call, proto)					\
	static notrace void						\
	perf_trace_##call(void *__data, proto);
#define __app(x, y) __app__(x, y)
#define __app__(x, y) str__##x##y
#define __array(type, item, len)
#define __assign_bitmask(dst, src, nr_bits)					\
	memcpy(__get_bitmask(dst), (src), __bitmask_size_in_bytes(nr_bits))
#define __assign_str(dst, src)						\
	strcpy(__get_str(dst), (src) ? (const char *)(src) : "(null)");
#define __assign_str_len(dst, src, len)					\
	do {								\
		memcpy(__get_str(dst), (src), (len));			\
		__get_str(dst)[len] = '\0';				\
	} while(0)
#define __bitmask(item, nr_bits) __dynamic_array(char, item, -1)
#define __bitmask_size_in_bytes(nr_bits)				\
	(__bitmask_size_in_longs(nr_bits) * (BITS_PER_LONG / 8))
#define __bitmask_size_in_bytes_raw(nr_bits)	\
	(((nr_bits) + 7) / 8)
#define __bitmask_size_in_longs(nr_bits)			\
	((__bitmask_size_in_bytes_raw(nr_bits) +		\
	  ((BITS_PER_LONG / 8) - 1)) / (BITS_PER_LONG / 8))
#define __dynamic_array(type, item, len) u32 __data_loc_##item;
#define __field(type, item)
#define __field_ext(type, item, filter_type)
#define __field_struct(type, item)
#define __field_struct_ext(type, item, filter_type)
#define __print_array(array, count, el_size)				\
	({								\
		BUILD_BUG_ON(el_size != 1 && el_size != 2 &&		\
			     el_size != 4 && el_size != 8);		\
		trace_print_array_seq(p, array, count, el_size);	\
	})
#define __print_flags(flag, delim, flag_array...)			\
	({								\
		static const struct trace_print_flags __flags[] =	\
			{ flag_array, { -1, NULL }};			\
		trace_print_flags_seq(p, delim, flag, __flags);	\
	})
#define __print_flags_u64(flag, delim, flag_array...)			\
	({								\
		static const struct trace_print_flags_u64 __flags[] =	\
			{ flag_array, { -1, NULL } };			\
		trace_print_flags_seq_u64(p, delim, flag, __flags);	\
	})
#define __print_hex(buf, buf_len)					\
	trace_print_hex_seq(p, buf, buf_len, false)
#define __print_hex_dump(prefix_str, prefix_type,			\
			 rowsize, groupsize, buf, len, ascii)		\
	trace_print_hex_dump_seq(p, prefix_str, prefix_type,		\
				 rowsize, groupsize, buf, len, ascii)
#define __print_hex_str(buf, buf_len)					\
	trace_print_hex_seq(p, buf, buf_len, true)
#define __print_ns_to_secs(value)			\
	({						\
		u64 ____val = (u64)(value);		\
		do_div(____val, NSEC_PER_SEC);		\
		____val;				\
	})
#define __print_ns_without_secs(value)			\
	({						\
		u64 ____val = (u64)(value);		\
		(u32) do_div(____val, NSEC_PER_SEC);	\
	})
#define __print_symbolic(value, symbol_array...)			\
	({								\
		static const struct trace_print_flags symbols[] =	\
			{ symbol_array, { -1, NULL }};			\
		trace_print_symbols_seq(p, value, symbols);		\
	})
#define __print_symbolic_u64(value, symbol_array...)			\
	({								\
		static const struct trace_print_flags_u64 symbols[] =	\
			{ symbol_array, { -1, NULL } };			\
		trace_print_symbols_seq_u64(p, value, symbols);	\
	})
#define __string(item, src) __dynamic_array(char, item, -1)
#define __string_len(item, src, len) __dynamic_array(char, item, -1)
#define TRACE_EVENT_FL_UKPROBE (TRACE_EVENT_FL_KPROBE | TRACE_EVENT_FL_UPROBE)
#define TRACE_FUNCTION_TYPE ((const char *)~0UL)

#define __TRACE_EVENT_FLAGS(name, value)				\
	static int __init trace_init_flags_##name(void)			\
	{								\
		event_##name.flags |= value;				\
		return 0;						\
	}								\
	early_initcall(trace_init_flags_##name);
#define __TRACE_EVENT_PERF_PERM(name, expr...)				\
	static int perf_perm_##name(struct trace_event_call *tp_event, \
				    struct perf_event *p_event)		\
	{								\
		return ({ expr; });					\
	}								\
	static int __init trace_init_perf_perm_##name(void)		\
	{								\
		event_##name.perf_perm = &perf_perm_##name;		\
		return 0;						\
	}								\
	early_initcall(trace_init_perf_perm_##name);
#define event_trace_printk(ip, fmt, args...)				\
do {									\
	__trace_printk_check_format(fmt, ##args);			\
	tracing_record_cmdline(current);				\
	if (__builtin_constant_p(fmt)) {				\
		static const char *trace_printk_fmt			\
		  __section("__trace_printk_fmt") =			\
			__builtin_constant_p(fmt) ? fmt : NULL;		\
									\
		__trace_bprintk(ip, trace_printk_fmt, ##args);		\
	} else								\
		__trace_printk(ip, fmt, ##args);			\
} while (0)
#define kprobe_event_add_field(cmd, field)	\
	__kprobe_event_add_fields(cmd, field, NULL)
#define kprobe_event_add_fields(cmd, ...)	\
	__kprobe_event_add_fields(cmd, ## __VA_ARGS__, NULL)
#define kprobe_event_gen_cmd_end(cmd)		\
	dynevent_create(cmd)
#define kprobe_event_gen_cmd_start(cmd, name, loc, ...)			\
	__kprobe_event_gen_cmd_start(cmd, false, name, loc, ## __VA_ARGS__, NULL)
#define kretprobe_event_gen_cmd_end(cmd)	\
	dynevent_create(cmd)
#define kretprobe_event_gen_cmd_start(cmd, name, loc, ...)		\
	__kprobe_event_gen_cmd_start(cmd, true, name, loc, ## __VA_ARGS__, NULL)
#define synth_event_gen_cmd_end(cmd)	\
	dynevent_create(cmd)
#define synth_event_gen_cmd_start(cmd, name, mod, ...)	\
	__synth_event_gen_cmd_start(cmd, name, mod, ## __VA_ARGS__, NULL)
#define DECLARE_EVENT_CLASS_NOP(name, proto, args, tstruct, assign, print)
#define DECLARE_EVENT_NOP(name, proto, args)				\
	static inline void trace_##name(proto)				\
	{ }								\
	static inline bool trace_##name##_enabled(void)			\
	{								\
		return false;						\
	}
#define DECLARE_TRACE_CONDITION(name, proto, args, cond)		\
	__DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
			cpu_online(raw_smp_processor_id()) && (PARAMS(cond)), \
			PARAMS(void *__data, proto))
#define DEFINE_TRACE(name, proto, args)		\
	DEFINE_TRACE_FN(name, NULL, NULL, PARAMS(proto), PARAMS(args));
#define DEFINE_TRACE_FN(_name, _reg, _unreg, proto, args)		\
	static const char __tpstrtab_##_name[]				\
	__section("__tracepoints_strings") = #_name;			\
	extern struct static_call_key STATIC_CALL_KEY(tp_func_##_name);	\
	int __traceiter_##_name(void *__data, proto);			\
	struct tracepoint __tracepoint_##_name	__used			\
	__section("__tracepoints") = {					\
		.name = __tpstrtab_##_name,				\
		.key = STATIC_KEY_INIT_FALSE,				\
		.static_call_key = &STATIC_CALL_KEY(tp_func_##_name),	\
		.static_call_tramp = STATIC_CALL_TRAMP_ADDR(tp_func_##_name), \
		.iterator = &__traceiter_##_name,			\
		.regfunc = _reg,					\
		.unregfunc = _unreg,					\
		.funcs = NULL };					\
	__TRACEPOINT_ENTRY(_name);					\
	int __traceiter_##_name(void *__data, proto)			\
	{								\
		struct tracepoint_func *it_func_ptr;			\
		void *it_func;						\
									\
		it_func_ptr =						\
			rcu_dereference_raw((&__tracepoint_##_name)->funcs); \
		if (it_func_ptr) {					\
			do {						\
				it_func = READ_ONCE((it_func_ptr)->func); \
				__data = (it_func_ptr)->data;		\
				((void(*)(void *, proto))(it_func))(__data, args); \
			} while ((++it_func_ptr)->func);		\
		}							\
		return 0;						\
	}								\
	DEFINE_STATIC_CALL(tp_func_##_name, __traceiter_##_name);
#define EXPORT_TRACEPOINT_SYMBOL(name)					\
	EXPORT_SYMBOL(__tracepoint_##name);				\
	EXPORT_SYMBOL(__traceiter_##name);				\
	EXPORT_STATIC_CALL(tp_func_##name)
#define EXPORT_TRACEPOINT_SYMBOL_GPL(name)				\
	EXPORT_SYMBOL_GPL(__tracepoint_##name);				\
	EXPORT_SYMBOL_GPL(__traceiter_##name);				\
	EXPORT_STATIC_CALL_GPL(tp_func_##name)
#define PARAMS(args...) args
#define TP_ARGS(args...)	args
#define TP_CONDITION(args...)	args
#define TP_PROTO(args...)	args


#define __DECLARE_TRACE(name, proto, args, cond, data_proto)		\
	extern int __traceiter_##name(data_proto);			\
	DECLARE_STATIC_CALL(tp_func_##name, __traceiter_##name);	\
	extern struct tracepoint __tracepoint_##name;			\
	static inline void trace_##name(proto)				\
	{								\
		if (static_key_false(&__tracepoint_##name.key))		\
			__DO_TRACE(name,				\
				TP_ARGS(args),				\
				TP_CONDITION(cond), 0);			\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {		\
			rcu_read_lock_sched_notrace();			\
			rcu_dereference_sched(__tracepoint_##name.funcs);\
			rcu_read_unlock_sched_notrace();		\
		}							\
	}								\
	__DECLARE_TRACE_RCU(name, PARAMS(proto), PARAMS(args),		\
			    PARAMS(cond))				\
	static inline int						\
	register_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_register(&__tracepoint_##name,	\
						(void *)probe, data);	\
	}								\
	static inline int						\
	register_trace_prio_##name(void (*probe)(data_proto), void *data,\
				   int prio)				\
	{								\
		return tracepoint_probe_register_prio(&__tracepoint_##name, \
					      (void *)probe, data, prio); \
	}								\
	static inline int						\
	unregister_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_unregister(&__tracepoint_##name,\
						(void *)probe, data);	\
	}								\
	static inline void						\
	check_trace_callback_type_##name(void (*cb)(data_proto))	\
	{								\
	}								\
	static inline bool						\
	trace_##name##_enabled(void)					\
	{								\
		return static_key_false(&__tracepoint_##name.key);	\
	}
#define __DECLARE_TRACE_RCU(name, proto, args, cond)			\
	static inline void trace_##name##_rcuidle(proto)		\
	{								\
		if (static_key_false(&__tracepoint_##name.key))		\
			__DO_TRACE(name,				\
				TP_ARGS(args),				\
				TP_CONDITION(cond), 1);			\
	}
#define __DO_TRACE(name, args, cond, rcuidle)				\
	do {								\
		int __maybe_unused __idx = 0;				\
									\
		if (!(cond))						\
			return;						\
									\
					\
		WARN_ON_ONCE(rcuidle && in_nmi());			\
									\
				\
		preempt_disable_notrace();				\
									\
									\
		if (rcuidle) {						\
			__idx = srcu_read_lock_notrace(&tracepoint_srcu);\
			rcu_irq_enter_irqson();				\
		}							\
									\
		__DO_TRACE_CALL(name, TP_ARGS(args));			\
									\
		if (rcuidle) {						\
			rcu_irq_exit_irqson();				\
			srcu_read_unlock_notrace(&tracepoint_srcu, __idx);\
		}							\
									\
		preempt_enable_notrace();				\
	} while (0)
#define __DO_TRACE_CALL(name, args)					\
	do {								\
		struct tracepoint_func *it_func_ptr;			\
		void *__data;						\
		it_func_ptr =						\
			rcu_dereference_raw((&__tracepoint_##name)->funcs); \
		if (it_func_ptr) {					\
			__data = (it_func_ptr)->data;			\
			static_call(tp_func_##name)(__data, args);	\
		}							\
	} while (0)
#define __TRACEPOINT_ENTRY(name)					\
	asm("	.section \"__tracepoints_ptrs\", \"a\"		\n"	\
	    "	.balign 4					\n"	\
	    "	.long 	__tracepoint_" #name " - .		\n"	\
	    "	.previous					\n")
# define __tracepoint_string
# define tracepoint_string(str) str
#define DEFINE_STATIC_CALL(name, _func)					\
	__DEFINE_STATIC_CALL(name, _func, _func)
#define DEFINE_STATIC_CALL_NULL(name, _func)				\
	DECLARE_STATIC_CALL(name, _func);				\
	struct static_call_key STATIC_CALL_KEY(name) = {		\
		.func = NULL,						\
		.type = 1,						\
	};								\
	ARCH_DEFINE_STATIC_CALL_NULL_TRAMP(name)
#define DEFINE_STATIC_CALL_RET0(name, _func)				\
	__DEFINE_STATIC_CALL(name, _func, __static_call_return0)
#define EXPORT_STATIC_CALL(name)					\
	EXPORT_SYMBOL(STATIC_CALL_KEY(name));				\
	EXPORT_SYMBOL(STATIC_CALL_TRAMP(name))
#define EXPORT_STATIC_CALL_GPL(name)					\
	EXPORT_SYMBOL_GPL(STATIC_CALL_KEY(name));			\
	EXPORT_SYMBOL_GPL(STATIC_CALL_TRAMP(name))
#define EXPORT_STATIC_CALL_TRAMP(name)					\
	EXPORT_SYMBOL(STATIC_CALL_TRAMP(name));				\
	ARCH_ADD_TRAMP_KEY(name)
#define EXPORT_STATIC_CALL_TRAMP_GPL(name)				\
	EXPORT_SYMBOL_GPL(STATIC_CALL_TRAMP(name));			\
	ARCH_ADD_TRAMP_KEY(name)
#define STATIC_CALL_TRAMP_ADDR(name) &STATIC_CALL_TRAMP(name)

#define __DEFINE_STATIC_CALL(name, _func, _func_init)			\
	DECLARE_STATIC_CALL(name, _func);				\
	struct static_call_key STATIC_CALL_KEY(name) = {		\
		.func = _func_init,					\
		.type = 1,						\
	};								\
	ARCH_DEFINE_STATIC_CALL_TRAMP(name, _func_init)
#define __static_call_cond(name)					\
({									\
	void *func = READ_ONCE(STATIC_CALL_KEY(name).func);		\
	if (!func)							\
		func = &__static_call_nop;				\
	(typeof(STATIC_CALL_TRAMP(name))*)func;				\
})
#define static_call_cond(name)	(void)__static_call(name)
#define static_call_query(name) (READ_ONCE(STATIC_CALL_KEY(name).func))
#define static_call_update(name, func)					\
({									\
	typeof(&STATIC_CALL_TRAMP(name)) __F = (func);			\
	__static_call_update(&STATIC_CALL_KEY(name),			\
			     STATIC_CALL_TRAMP_ADDR(name), __F);	\
})



#define to_node(device) container_of(device, struct node, dev)
#define PERF_MEM_NA (PERF_MEM_S(OP, NA)   |\
		    PERF_MEM_S(LVL, NA)   |\
		    PERF_MEM_S(SNOOP, NA) |\
		    PERF_MEM_S(LOCK, NA)  |\
		    PERF_MEM_S(TLB, NA))
#define PERF_PMU_TXN_ADD  0x1		
#define PERF_PMU_TXN_READ 0x2		
#define PMU_EVENT_ATTR(_name, _var, _id, _show)				\
static struct perf_pmu_events_attr _var = {				\
	.attr = __ATTR(_name, 0444, _show, NULL),			\
	.id   =  _id,							\
};
#define PMU_EVENT_ATTR_ID(_name, _show, _id)				\
	(&((struct perf_pmu_events_attr[]) {				\
		{ .attr = __ATTR(_name, 0444, _show, NULL),		\
		  .id = _id, }						\
	})[0].attr.attr)
#define PMU_EVENT_ATTR_STRING(_name, _var, _str)			    \
static struct perf_pmu_events_attr _var = {				    \
	.attr		= __ATTR(_name, 0444, perf_event_sysfs_show, NULL), \
	.id		= 0,						    \
	.event_str	= _str,						    \
};
#define PMU_FORMAT_ATTR(_name, _format)					\
static ssize_t								\
_name##_show(struct device *dev,					\
			       struct device_attribute *attr,		\
			       char *page)				\
{									\
	BUILD_BUG_ON(sizeof(_format) >= PAGE_SIZE);			\
	return sprintf(page, _format "\n");				\
}									\
									\
static struct device_attribute format_attr_##_name = __ATTR_RO(_name)

#define for_each_sibling_event(sibling, event)			\
	if ((event)->group_leader == (event))			\
		list_for_each_entry((sibling), &(event)->sibling_list, sibling_list)
# define perf_arch_bpf_user_pt_regs(regs) regs
# define perf_instruction_pointer(regs)	instruction_pointer(regs)
# define perf_misc_flags(regs) \
		(user_mode(regs) ? PERF_RECORD_MISC_USER : PERF_RECORD_MISC_KERNEL)
#define perf_output_put(handle, x) perf_output_copy((handle), &(x), sizeof(x))
#define CAP_OPT_INSETID BIT(2)
#define CAP_OPT_NOAUDIT BIT(1)
#define CAP_OPT_NONE 0x0
#define LSM_PRLIMIT_READ  1
#define LSM_PRLIMIT_WRITE 2

#define __data_id_enumify(ENUM, dummy) LOADING_ ## ENUM,
#define __data_id_stringify(dummy, str) #str,

#define __fid_enumify(ENUM, dummy) READING_ ## ENUM,
#define __fid_stringify(dummy, str) #str,
#define __kernel_read_file_id(id) \
	id(UNKNOWN, unknown)		\
	id(FIRMWARE, firmware)		\
	id(MODULE, kernel-module)		\
	id(KEXEC_IMAGE, kexec-image)		\
	id(KEXEC_INITRAMFS, kexec-initramfs)	\
	id(POLICY, security-policy)		\
	id(X509_CERTIFICATE, x509-certificate)	\
	id(MAX_ID, )
#define FDPUT_FPUT       1
#define FDPUT_POS_UNLOCK 2

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


#define u64_stats_init(syncp)	seqcount_init(&(syncp)->seq)

#define kcpustat_cpu(cpu) per_cpu(kernel_cpustat, cpu)
#define kcpustat_this_cpu this_cpu_ptr(&kernel_cpustat)
#define kstat_cpu(cpu) per_cpu(kstat, cpu)
#define kstat_this_cpu this_cpu_ptr(&kstat)
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


#define setup_thread_stack(new,old)	do { } while(0)
#define task_stack_end_corrupted(task) \
		(*(end_of_stack(task)) != STACK_END_MAGIC)
#define task_stack_page(task)	((void *)(task)->stack)
#define DEFINE_STATIC_KEY_DEFERRED_FALSE(name, rl)			\
	struct static_key_false_deferred name = {			\
		.key =		{ STATIC_KEY_INIT_FALSE },		\
		.timeout =	(rl),					\
		.work =	__DELAYED_WORK_INITIALIZER((name).work,		\
						   jump_label_update_timeout, \
						   0),			\
	}
#define DEFINE_STATIC_KEY_DEFERRED_TRUE(name, rl)			\
	struct static_key_true_deferred name = {			\
		.key =		{ STATIC_KEY_INIT_TRUE },		\
		.timeout =	(rl),					\
		.work =	__DELAYED_WORK_INITIALIZER((name).work,		\
						   jump_label_update_timeout, \
						   0),			\
	}

#define static_branch_deferred_inc(x)	static_branch_inc(&(x)->key)
#define static_branch_slow_dec_deferred(x)				\
	__static_key_slow_dec_deferred(&(x)->key.key, &(x)->work, (x)->timeout)
#define static_key_deferred_flush(x)					\
	__static_key_deferred_flush((x), &(x)->work)
#define static_key_slow_dec_deferred(x)					\
	__static_key_slow_dec_deferred(&(x)->key, &(x)->work, (x)->timeout)
#define DEFINE_IRQ_WORK(name, _f)				\
	struct irq_work name = IRQ_WORK_INIT(_f)
#define IRQ_WORK_INIT(_func) __IRQ_WORK_INIT(_func, 0)
#define IRQ_WORK_INIT_HARD(_func) __IRQ_WORK_INIT(_func, IRQ_WORK_HARD_IRQ)
#define IRQ_WORK_INIT_LAZY(_func) __IRQ_WORK_INIT(_func, IRQ_WORK_LAZY)

#define __IRQ_WORK_INIT(_func, _flags) (struct irq_work){	\
	.node = { .u_flags = (_flags), },			\
	.func = (_func),					\
}
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

#define PERF_MEM_LVLNUM_ANY_CACHE 0x0b 
#define PERF_MEM_S(a, s) \
	(((__u64)PERF_MEM_##a##_##s) << PERF_MEM_##a##_SHIFT)
#define PERF_MEM_SNOOPX_SHIFT  38
#define PERF_SAMPLE_BRANCH_PLM_ALL \
	(PERF_SAMPLE_BRANCH_USER|\
	 PERF_SAMPLE_BRANCH_KERNEL|\
	 PERF_SAMPLE_BRANCH_HV)



#define RING_BUFFER_ALL_CPUS -1

#define ring_buffer_alloc(size, flags)			\
({							\
	static struct lock_class_key __key;		\
	__ring_buffer_alloc((size), (flags), &__key);	\
})
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


#define INIT_RHT_NULLS_HEAD(ptr)	\
	((ptr) = NULL)

#define rhl_for_each_entry_rcu(tpos, pos, list, member)			\
	for (pos = list; pos && rht_entry(tpos, pos, member);		\
	     pos = rcu_dereference_raw(pos->next))
#define rhl_for_each_rcu(pos, list)					\
	for (pos = list; pos; pos = rcu_dereference_raw(pos->next))
#define rht_dereference(p, ht) \
	rcu_dereference_protected(p, lockdep_rht_mutex_is_held(ht))
#define rht_dereference_bucket(p, tbl, hash) \
	rcu_dereference_protected(p, lockdep_rht_bucket_is_held(tbl, hash))
#define rht_dereference_bucket_rcu(p, tbl, hash) \
	rcu_dereference_check(p, lockdep_rht_bucket_is_held(tbl, hash))
#define rht_dereference_rcu(p, ht) \
	rcu_dereference_check(p, lockdep_rht_mutex_is_held(ht))
#define rht_entry(tpos, pos, member) \
	({ tpos = container_of(pos, typeof(*tpos), member); 1; })
#define rht_for_each(pos, tbl, hash) \
	rht_for_each_from(pos, rht_ptr(rht_bucket(tbl, hash), tbl, hash),  \
			  tbl, hash)
#define rht_for_each_entry(tpos, pos, tbl, hash, member)		\
	rht_for_each_entry_from(tpos, pos,				\
				rht_ptr(rht_bucket(tbl, hash), tbl, hash), \
				tbl, hash, member)
#define rht_for_each_entry_from(tpos, pos, head, tbl, hash, member)	\
	for (pos = head;						\
	     (!rht_is_a_nulls(pos)) && rht_entry(tpos, pos, member);	\
	     pos = rht_dereference_bucket((pos)->next, tbl, hash))
#define rht_for_each_entry_rcu(tpos, pos, tbl, hash, member)		   \
	rht_for_each_entry_rcu_from(tpos, pos,				   \
				    rht_ptr_rcu(rht_bucket(tbl, hash)),	   \
				    tbl, hash, member)
#define rht_for_each_entry_rcu_from(tpos, pos, head, tbl, hash, member) \
	for (({barrier(); }),						    \
	     pos = head;						    \
	     (!rht_is_a_nulls(pos)) && rht_entry(tpos, pos, member);	    \
	     pos = rht_dereference_bucket_rcu(pos->next, tbl, hash))
#define rht_for_each_entry_safe(tpos, pos, next, tbl, hash, member)	      \
	for (pos = rht_ptr(rht_bucket(tbl, hash), tbl, hash),		      \
	     next = !rht_is_a_nulls(pos) ?				      \
		       rht_dereference_bucket(pos->next, tbl, hash) : NULL;   \
	     (!rht_is_a_nulls(pos)) && rht_entry(tpos, pos, member);	      \
	     pos = next,						      \
	     next = !rht_is_a_nulls(pos) ?				      \
		       rht_dereference_bucket(pos->next, tbl, hash) : NULL)
#define rht_for_each_from(pos, head, tbl, hash) \
	for (pos = head;			\
	     !rht_is_a_nulls(pos);		\
	     pos = rht_dereference_bucket((pos)->next, tbl, hash))
#define rht_for_each_rcu(pos, tbl, hash)			\
	for (({barrier(); }),					\
	     pos = rht_ptr_rcu(rht_bucket(tbl, hash));		\
	     !rht_is_a_nulls(pos);				\
	     pos = rcu_dereference_raw(pos->next))
#define rht_for_each_rcu_from(pos, head, tbl, hash)			\
	for (({barrier(); }),						\
	     pos = head;						\
	     !rht_is_a_nulls(pos);					\
	     pos = rcu_dereference_raw(pos->next))
#define INIT_HLIST_NULLS_HEAD(ptr, nulls) \
	((ptr)->first = (struct hlist_nulls_node *) NULLS_MARKER(nulls))
#define NULLS_MARKER(value) (1UL | (((long)value) << 1))

#define hlist_nulls_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_nulls_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   !is_a_nulls(____ptr) ? hlist_nulls_entry(____ptr, type, member) : NULL; \
	})
#define hlist_nulls_for_each_entry(tpos, pos, head, member)		       \
	for (pos = (head)->first;					       \
	     (!is_a_nulls(pos)) &&					       \
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_nulls_for_each_entry_from(tpos, pos, member)	\
	for (; (!is_a_nulls(pos)) && 				\
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}
#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}
#define jhash_mask(n)   (jhash_size(n)-1)
#define jhash_size(n)   ((u32)1<<(n))

#define BPF_ALU32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })
#define BPF_ALU64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })
#define BPF_ANCILLARY(CODE)	case SKF_AD_OFF + SKF_AD_##CODE:	\
				return BPF_ANC | SKF_AD_##CODE
#define BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = OP })
#define BPF_CALL_0(name, ...)	BPF_CALL_x(0, name, __VA_ARGS__)
#define BPF_CALL_1(name, ...)	BPF_CALL_x(1, name, __VA_ARGS__)
#define BPF_CALL_2(name, ...)	BPF_CALL_x(2, name, __VA_ARGS__)
#define BPF_CALL_3(name, ...)	BPF_CALL_x(3, name, __VA_ARGS__)
#define BPF_CALL_4(name, ...)	BPF_CALL_x(4, name, __VA_ARGS__)
#define BPF_CALL_5(name, ...)	BPF_CALL_x(5, name, __VA_ARGS__)
#define BPF_CALL_REL(TGT)					\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_CALL,			\
		.dst_reg = 0,					\
		.src_reg = BPF_PSEUDO_CALL,			\
		.off   = 0,					\
		.imm   = TGT })
#define BPF_CALL_x(x, name, ...)					       \
	static __always_inline						       \
	u64 ____##name(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__));   \
	typedef u64 (*btf_##name)(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__)); \
	u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__));	       \
	u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__))	       \
	{								       \
		return ((btf_##name)____##name)(__BPF_MAP(x,__BPF_CAST,__BPF_N,__VA_ARGS__));\
	}								       \
	static __always_inline						       \
	u64 ____##name(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__))
#define BPF_CAST_CALL(x)					\
		((u64 (*)(u64, u64, u64, u64, u64))(x))
#define BPF_EMIT_CALL(FUNC)					\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_CALL,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((FUNC) - __bpf_call_base) })
#define BPF_ENDIAN(TYPE, DST, LEN)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_END | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = LEN })
#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })
#define BPF_FIELD_SIZEOF(type, field)				\
	({							\
		const int __size = bytes_to_bpf_size(sizeof_field(type, field)); \
		BUILD_BUG_ON(__size < 0);			\
		__size;						\
	})
#define BPF_IMAGE_ALIGNMENT 8
#define BPF_JMP32_IMM(OP, DST, IMM, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })
#define BPF_JMP32_REG(OP, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })
#define BPF_JMP_A(OFF)						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_JA,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = 0 })
#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })
#define BPF_JMP_REG(OP, DST, SRC, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })
#define BPF_LDST_BYTES(insn)					\
	({							\
		const int __size = bpf_size_to_bytes(BPF_SIZE((insn)->code)); \
		WARN_ON(__size < 0);				\
		__size;						\
	})
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })
#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_LD_IMM64(DST, IMM)					\
	BPF_LD_IMM64_RAW(DST, 0, IMM)
#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = (__u32) (IMM) }),			\
	((struct bpf_insn) {					\
		.code  = 0, 	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (IMM)) >> 32 })
#define BPF_LD_IND(SIZE, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND,	\
		.dst_reg = 0,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)
#define BPF_MOV32_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_MOV32_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_MOV32_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })
#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_MOV64_RAW(TYPE, DST, SRC, IMM)			\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_SRC(TYPE),	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = IMM })
#define BPF_MOV64_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })
#define BPF_PROG_SK_LOOKUP_RUN_ARRAY(array, ctx, func)			\
	({								\
		struct bpf_sk_lookup_kern *_ctx = &(ctx);		\
		struct bpf_prog_array_item *_item;			\
		struct sock *_selected_sk = NULL;			\
		bool _no_reuseport = false;				\
		struct bpf_prog *_prog;					\
		bool _all_pass = true;					\
		u32 _ret;						\
									\
		migrate_disable();					\
		_item = &(array)->items[0];				\
		while ((_prog = READ_ONCE(_item->prog))) {		\
					\
			_ctx->selected_sk = _selected_sk;		\
			_ctx->no_reuseport = _no_reuseport;		\
									\
			_ret = func(_prog, _ctx);			\
			if (_ret == SK_PASS && _ctx->selected_sk) {	\
					\
				_selected_sk = _ctx->selected_sk;	\
				_no_reuseport = _ctx->no_reuseport;	\
			} else if (_ret == SK_DROP && _all_pass) {	\
				_all_pass = false;			\
			}						\
			_item++;					\
		}							\
		_ctx->selected_sk = _selected_sk;			\
		_ctx->no_reuseport = _no_reuseport;			\
		migrate_enable();					\
		_all_pass || _selected_sk ? SK_PASS : SK_DROP;		\
	 })
#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code  = CODE,					\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = IMM })
#define BPF_SIZEOF(type)					\
	({							\
		const int __size = bytes_to_bpf_size(sizeof(type)); \
		BUILD_BUG_ON(__size < 0);			\
		__size;						\
	})
#define BPF_SKB_CB_LEN QDISC_CB_PRIV_LEN
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })
#define BPF_STX_XADD(SIZE, DST, SRC, OFF) BPF_ATOMIC_OP(SIZE, BPF_ADD, DST, SRC, OFF)
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })
#define BPF_ST_NOSPEC()						\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_NOSPEC,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })
#define BPF_ZEXT_REG(DST)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = DST,					\
		.off   = 0,					\
		.imm   = 1 })
#define __BPF_CAST(t, a)						       \
	(__force t)							       \
	(__force							       \
	 typeof(__builtin_choose_expr(sizeof(t) == sizeof(unsigned long),      \
				      (unsigned long)0, (t)0))) a
#define __BPF_DECL_ARGS(t, a) t   a
#define __BPF_DECL_REGS(t, a) u64 a
#define __BPF_JUMP(CODE, K, JT, JF)				\
	((struct sock_filter) BPF_JUMP(CODE, K, JT, JF))
#define __BPF_MAP(n, ...) __BPF_MAP_##n(__VA_ARGS__)
#define __BPF_MAP_0(m, v, ...) v
#define __BPF_MAP_1(m, v, t, a, ...) m(t, a)
#define __BPF_MAP_2(m, v, t, a, ...) m(t, a), __BPF_MAP_1(m, v, __VA_ARGS__)
#define __BPF_MAP_3(m, v, t, a, ...) m(t, a), __BPF_MAP_2(m, v, __VA_ARGS__)
#define __BPF_MAP_4(m, v, t, a, ...) m(t, a), __BPF_MAP_3(m, v, __VA_ARGS__)
#define __BPF_MAP_5(m, v, t, a, ...) m(t, a), __BPF_MAP_4(m, v, __VA_ARGS__)

#define __BPF_PAD(n)							       \
	__BPF_MAP(n, __BPF_DECL_ARGS, __BPF_N, u64, __ur_1, u64, __ur_2,       \
		  u64, __ur_3, u64, __ur_4, u64, __ur_5)
#define __BPF_REG(n, ...) __BPF_REG_##n(__VA_ARGS__)
#define __BPF_REG_0(...) __BPF_PAD(5)
#define __BPF_REG_1(...) __BPF_MAP(1, __VA_ARGS__), __BPF_PAD(4)
#define __BPF_REG_2(...) __BPF_MAP(2, __VA_ARGS__), __BPF_PAD(3)
#define __BPF_REG_3(...) __BPF_MAP(3, __VA_ARGS__), __BPF_PAD(2)
#define __BPF_REG_4(...) __BPF_MAP(4, __VA_ARGS__), __BPF_PAD(1)
#define __BPF_REG_5(...) __BPF_MAP(5, __VA_ARGS__)
#define __BPF_STMT(CODE, K)					\
	((struct sock_filter) BPF_STMT(CODE, K))
#define __BPF_V void

#define __bpf_call_base_args \
	((u64 (*)(u64, u64, u64, u64, u64, const struct bpf_insn *)) \
	 (void *)__bpf_call_base)
#define bpf_classic_proglen(fprog) (fprog->len * sizeof(fprog->filter[0]))
#define bpf_ctx_range(TYPE, MEMBER)						\
	offsetof(TYPE, MEMBER) ... offsetofend(TYPE, MEMBER) - 1
# define bpf_ctx_range_ptr(TYPE, MEMBER)					\
	offsetof(TYPE, MEMBER) ... offsetofend(TYPE, MEMBER) - 1
#define bpf_ctx_range_till(TYPE, MEMBER1, MEMBER2)				\
	offsetof(TYPE, MEMBER1) ... offsetofend(TYPE, MEMBER2) - 1
#define bpf_ctx_wide_access_ok(off, size, type, field)			\
	(size == sizeof(__u64) &&					\
	off >= offsetof(type, field) &&					\
	off + sizeof(__u64) <= offsetofend(type, field) &&		\
	off % sizeof(__u64) == 0)
#define bpf_size_to_bytes(bpf_size)				\
({								\
	int bytes = -EINVAL;					\
								\
	if (bpf_size == BPF_B)					\
		bytes = sizeof(u8);				\
	else if (bpf_size == BPF_H)				\
		bytes = sizeof(u16);				\
	else if (bpf_size == BPF_W)				\
		bytes = sizeof(u32);				\
	else if (bpf_size == BPF_DW)				\
		bytes = sizeof(u64);				\
								\
	bytes;							\
})
#define bpf_target_off(TYPE, MEMBER, SIZE, PTR_SIZE)				\
	({									\
		BUILD_BUG_ON(sizeof_field(TYPE, MEMBER) != (SIZE));		\
		*(PTR_SIZE) = (SIZE);						\
		offsetof(TYPE, MEMBER);						\
	})
#define bytes_to_bpf_size(bytes)				\
({								\
	int bpf_size = -EINVAL;					\
								\
	if (bytes == sizeof(u8))				\
		bpf_size = BPF_B;				\
	else if (bytes == sizeof(u16))				\
		bpf_size = BPF_H;				\
	else if (bytes == sizeof(u32))				\
		bpf_size = BPF_W;				\
	else if (bytes == sizeof(u64))				\
		bpf_size = BPF_DW;				\
								\
	bpf_size;						\
})
#define xdp_do_flush_map xdp_do_flush
#define         BPF_A           0x10
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#define BPF_MAJOR_VERSION 1
#define BPF_MEMWORDS 16
#define BPF_MINOR_VERSION 1
#define BPF_MISCOP(code) ((code) & 0xf8)
#define BPF_RVAL(code)  ((code) & 0x18)
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#define         BPF_TAX         0x00
#define         BPF_TXA         0x80
#define SKF_AD_IFINDEX 	8
#define SKF_AD_MARK 	20
#define SKF_AD_OFF    (-0x1000)
#define SKF_AD_PKTTYPE 	4
#define SKF_AD_PROTOCOL 0
#define SKF_AD_VLAN_TAG_PRESENT 48

#define QDISC_CB_PRIV_LEN 20

#define net_xmit_drop_count(e)	((e) & __NET_XMIT_STOLEN ? 0 : 1)
#define tcf_chain_dereference(p, chain)					\
	rcu_dereference_protected(p, lockdep_tcf_chain_is_locked(chain))
#define tcf_proto_dereference(p, tp)					\
	rcu_dereference_protected(p, lockdep_tcf_proto_is_locked(tp))

#define flow_action_for_each(__i, __act, __actions)			\
        for (__i = 0, __act = &(__actions)->entries[0];			\
	     __i < (__actions)->num_entries;				\
	     __act = &(__actions)->entries[++__i])
#define FLOW_DIS_MPLS_MAX 7
#define FLOW_DIS_TUN_OPTS_MAX 255
#define FLOW_KEYS_HASH_START_FIELD basic

#define ETH_P_AF_IUCV   0xFBFB		
#define ETH_P_CUST      0x6006          
#define ETH_P_DDCMP     0x0006          
#define ETH_P_DEC       0x6000          
#define ETH_P_DIAG      0x6005          
#define ETH_P_DNA_DL    0x6001          
#define ETH_P_DNA_RC    0x6002          
#define ETH_P_DNA_RT    0x6003          
#define ETH_P_IEEE802154 0x00F6		
#define ETH_P_LAT       0x6004          
#define ETH_P_LOCALTALK 0x0009		
#define ETH_P_PPP_MP    0x0008          
#define ETH_P_RARP      0x8035		
#define ETH_P_SCA       0x6007          
#define ETH_P_WAN_PPP   0x0007          

#define HSIPHASH_ALIGNMENT __alignof__(unsigned long)
#define SIPHASH_ALIGNMENT __alignof__(u64)

#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define IN6ADDR_INTERFACELOCAL_ALLNODES_INIT \
		{ { { 0xff,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
#define IN6ADDR_INTERFACELOCAL_ALLROUTERS_INIT \
		{ { { 0xff,1,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }
#define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
		{ { { 0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }
#define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
#define IN6ADDR_SITELOCAL_ALLROUTERS_INIT \
		{ { { 0xff,5,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }

#define IPV6_ORIGDSTADDR        74
#define IPV6_RECVORIGDSTADDR    IPV6_ORIGDSTADDR
#define IPV6_TRANSPARENT        75
#define IPV6_UNICAST_IF         76

#define NETLINK_CB(skb)		(*(struct netlink_skb_parms*)&((skb)->cb))
#define NETLINK_CREDS(skb)	(&NETLINK_CB((skb)).creds)
#define NLMSG_DEFAULT_SIZE (NLMSG_GOODSIZE - NLMSG_HDRLEN)
#define NL_SET_BAD_ATTR(extack, attr) NL_SET_BAD_ATTR_POLICY(extack, attr, NULL)
#define NL_SET_BAD_ATTR_POLICY(extack, attr, pol) do {	\
	if ((extack)) {					\
		(extack)->bad_attr = (attr);		\
		(extack)->policy = (pol);		\
	}						\
} while (0)
#define NL_SET_ERR_MSG(extack, msg) do {		\
	static const char __msg[] = msg;		\
	struct netlink_ext_ack *__extack = (extack);	\
							\
	do_trace_netlink_extack(__msg);			\
							\
	if (__extack)					\
		__extack->_msg = __msg;			\
} while (0)
#define NL_SET_ERR_MSG_ATTR(extack, attr, msg)		\
	NL_SET_ERR_MSG_ATTR_POL(extack, attr, NULL, msg)
#define NL_SET_ERR_MSG_ATTR_POL(extack, attr, pol, msg) do {	\
	static const char __msg[] = msg;			\
	struct netlink_ext_ack *__extack = (extack);		\
								\
	do_trace_netlink_extack(__msg);				\
								\
	if (__extack) {						\
		__extack->_msg = __msg;				\
		__extack->bad_attr = (attr);			\
		__extack->policy = (pol);			\
	}							\
} while (0)
#define NL_SET_ERR_MSG_MOD(extack, msg)			\
	NL_SET_ERR_MSG((extack), KBUILD_MODNAME ": " msg)

#define MAX_LINKS 32		
#define NET_MAJOR 36		
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_DATA(nlh)  ((void *)(((char *)nlh) + NLMSG_HDRLEN))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
				  (struct nlmsghdr *)(((char *)(nlh)) + \
				  NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len <= (len))
#define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NL_MMAP_MSG_ALIGN(sz)		__ALIGN_KERNEL(sz, NL_MMAP_MSG_ALIGNMENT)

#define CMSG_ALIGN(len) ( ((len)+sizeof(long)-1) & ~(sizeof(long)-1) )
#define CMSG_DATA(cmsg) \
	((void *)(cmsg) + sizeof(struct cmsghdr))
#define CMSG_FIRSTHDR(msg)	__CMSG_FIRSTHDR((msg)->msg_control, (msg)->msg_controllen)
#define CMSG_LEN(len) (sizeof(struct cmsghdr) + (len))
#define CMSG_NXTHDR(mhdr, cmsg) cmsg_nxthdr((mhdr), (cmsg))
#define CMSG_OK(mhdr, cmsg) ((cmsg)->cmsg_len >= sizeof(struct cmsghdr) && \
			     (cmsg)->cmsg_len <= (unsigned long) \
			     ((mhdr)->msg_controllen - \
			      ((char *)(cmsg) - (char *)(mhdr)->msg_control)))
#define CMSG_SPACE(len) (sizeof(struct cmsghdr) + CMSG_ALIGN(len))
#define CMSG_USER_DATA(cmsg) \
	((void __user *)(cmsg) + sizeof(struct cmsghdr))
#define MSG_CMSG_CLOEXEC 0x40000000	
#define MSG_EOF         MSG_FIN
#define MSG_EOR         0x80	
#define MSG_FIN         0x200
#define MSG_NO_SHARED_FRAGS 0x80000 
#define MSG_SENDPAGE_NOPOLICY 0x10000 
#define MSG_SENDPAGE_NOTLAST 0x20000 
#define MSG_TRYHARD     4       
#define SCM_CREDENTIALS 0x02		
#define SOL_IRDA        266

#define __CMSG_FIRSTHDR(ctl,len) ((len) >= sizeof(struct cmsghdr) ? \
				  (struct cmsghdr *)(ctl) : \
				  (struct cmsghdr *)NULL)
#define __CMSG_NXTHDR(ctl, len, cmsg) __cmsg_nxthdr((ctl),(len),(cmsg))
#define __sockaddr_check_size(size)	\
	BUILD_BUG_ON(((size) > sizeof(struct __kernel_sockaddr_storage)))
#define for_each_cmsghdr(cmsg, msg) \
	for (cmsg = CMSG_FIRSTHDR(msg); \
	     cmsg; \
	     cmsg = CMSG_NXTHDR(msg, cmsg))
#define sockaddr_storage __kernel_sockaddr_storage
#define SOCK_BUF_LOCK_MASK (SOCK_SNDBUF_LOCK | SOCK_RCVBUF_LOCK)


#define _copy_from_iter_flushcache _copy_from_iter_nocache
#define _copy_mc_to_iter _copy_to_iter


#define DECLARE_SOCKADDR(type, dst, src)	\
	type dst = ({ __sockaddr_check_size(sizeof(*dst)); (type) src; })
#define MODULE_ALIAS_NETPROTO(proto) \
	MODULE_ALIAS("net-pf-" __stringify(proto))
#define MODULE_ALIAS_NET_PF_PROTO(pf, proto) \
	MODULE_ALIAS("net-pf-" __stringify(pf) "-proto-" __stringify(proto))
#define MODULE_ALIAS_NET_PF_PROTO_NAME(pf, proto, name) \
	MODULE_ALIAS("net-pf-" __stringify(pf) "-proto-" __stringify(proto) \
		     name)
#define MODULE_ALIAS_NET_PF_PROTO_TYPE(pf, proto, type) \
	MODULE_ALIAS("net-pf-" __stringify(pf) "-proto-" __stringify(proto) \
		     "-type-" __stringify(type))
#define SOCK_MAX (SOCK_PACKET + 1)
#define SOCK_TYPE_MASK 0xf

#define net_alert_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_alert, fmt, ##__VA_ARGS__)
#define net_crit_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_crit, fmt, ##__VA_ARGS__)
#define net_dbg_ratelimited(fmt, ...)					\
do {									\
	DEFINE_DYNAMIC_DEBUG_METADATA(descriptor, fmt);			\
	if (DYNAMIC_DEBUG_BRANCH(descriptor) &&				\
	    net_ratelimit())						\
		__dynamic_pr_debug(&descriptor, pr_fmt(fmt),		\
		                   ##__VA_ARGS__);			\
} while (0)
#define net_emerg_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_emerg, fmt, ##__VA_ARGS__)
#define net_err_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_err, fmt, ##__VA_ARGS__)
#define net_get_random_once(buf, nbytes)			\
	get_random_once((buf), (nbytes))
#define net_get_random_once_wait(buf, nbytes)			\
	get_random_once_wait((buf), (nbytes))
#define net_info_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_info, fmt, ##__VA_ARGS__)
#define net_notice_ratelimited(fmt, ...)			\
	net_ratelimited_function(pr_notice, fmt, ##__VA_ARGS__)
#define net_ratelimited_function(function, ...)			\
do {								\
	if (net_ratelimit())					\
		function(__VA_ARGS__);				\
} while (0)
#define net_warn_ratelimited(fmt, ...)				\
	net_ratelimited_function(pr_warn, fmt, ##__VA_ARGS__)
#define		     sockfd_put(sock) fput(sock->file)

#define DO_ONCE(func, ...)						     \
	({								     \
		bool ___ret = false;					     \
		static bool ___done = false;				     \
		static DEFINE_STATIC_KEY_TRUE(___once_key);		     \
		if (static_branch_unlikely(&___once_key)) {		     \
			unsigned long ___flags;				     \
			___ret = __do_once_start(&___done, &___flags);	     \
			if (unlikely(___ret)) {				     \
				func(__VA_ARGS__);			     \
				__do_once_done(&___done, &___once_key,	     \
					       &___flags, THIS_MODULE);	     \
			}						     \
		}							     \
		___ret;							     \
	})

#define get_random_once(buf, nbytes)					     \
	DO_ONCE(get_random_bytes, (buf), (nbytes))
#define get_random_once_wait(buf, nbytes)                                    \
	DO_ONCE(get_random_bytes_wait, (buf), (nbytes))                      \

#  define CANARY_MASK 0xffffffffffffff00UL

#define declare_get_random_var_wait(var) \
	static inline int get_random_ ## var ## _wait(var *out) { \
		int ret = wait_for_random_bytes(); \
		if (unlikely(ret)) \
			return ret; \
		*out = get_random_ ## var(); \
		return 0; \
	}
#define PRANDOM_ADD_NOISE(a, b, c, d) \
	prandom_u32_add_noise((unsigned long)(a), (unsigned long)(b), \
			      (unsigned long)(c), (unsigned long)(d))
#define PRND_K0 (0x736f6d6570736575 ^ 0x6c7967656e657261)
#define PRND_K1 (0x646f72616e646f6d ^ 0x7465646279746573)
#define PRND_SIPROUND(v0, v1, v2, v3) ( \
	v0 += v1, v1 = rol64(v1, 13),  v2 += v3, v3 = rol64(v3, 16), \
	v1 ^= v0, v0 = rol64(v0, 32),  v3 ^= v2,                     \
	v0 += v3, v3 = rol64(v3, 21),  v2 += v1, v1 = rol64(v1, 17), \
	v3 ^= v0,                      v1 ^= v2, v2 = rol64(v2, 32)  \
)

#define prandom_init_once(pcpu_state)			\
	DO_ONCE(prandom_seed_full_state, (pcpu_state))

#define CHECKSUM_BREAK 76
#define CLONED_OFFSET()		offsetof(struct sk_buff, __cloned_offset)

#define MAX_SKB_FRAGS 16UL
#define NET_SKBUFF_DATA_USES_OFFSET 1
#define PKT_TYPE_OFFSET()	offsetof(struct sk_buff, __pkt_type_offset)
#define PKT_VLAN_PRESENT_OFFSET()	offsetof(struct sk_buff, __pkt_vlan_present_offset)
#define SKB_DATAREF_MASK ((1 << SKB_DATAREF_SHIFT) - 1)
#define SKB_DATAREF_SHIFT 16
#define SKB_DATA_ALIGN(X)	ALIGN(X, SMP_CACHE_BYTES)
#define SKB_GSO_CB(skb) ((struct skb_gso_cb *)((skb)->cb + SKB_GSO_CB_OFFSET))
#define SKB_LINEAR_ASSERT(skb)  BUG_ON(skb_is_nonlinear(skb))
#define SKB_MAX_HEAD(X)		(SKB_MAX_ORDER((X), 0))
#define SKB_MAX_ORDER(X, ORDER) \
	SKB_WITH_OVERHEAD((PAGE_SIZE << (ORDER)) - (X))
#define SKB_TRUESIZE(X) ((X) +						\
			 SKB_DATA_ALIGN(sizeof(struct sk_buff)) +	\
			 SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
#define SKB_WITH_OVERHEAD(X)	\
	((X) - SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

#define __it(x, op) (x -= sizeof(u##op))
#define __it_diff(a, b, op) (*(u##op *)__it(a, op)) ^ (*(u##op *)__it(b, op))
#define __skb_checksum_validate(skb, proto, complete,			\
				zero_okay, check, compute_pseudo)	\
({									\
	__sum16 __ret = 0;						\
	skb->csum_valid = 0;						\
	if (__skb_checksum_validate_needed(skb, zero_okay, check))	\
		__ret = __skb_checksum_validate_complete(skb,		\
				complete, compute_pseudo(skb, proto));	\
	__ret;								\
})
#define dev_kfree_skb(a)	consume_skb(a)
#define rb_to_skb(rb) rb_entry_safe(rb, struct sk_buff, rbnode)
#define skb_checksum_init(skb, proto, compute_pseudo)			\
	__skb_checksum_validate(skb, proto, false, false, 0, compute_pseudo)
#define skb_checksum_init_zero_check(skb, proto, check, compute_pseudo)	\
	__skb_checksum_validate(skb, proto, false, true, check, compute_pseudo)
#define skb_checksum_simple_validate(skb)				\
	__skb_checksum_validate(skb, 0, true, false, 0, null_compute_pseudo)
#define skb_checksum_try_convert(skb, proto, compute_pseudo)	\
do {									\
	if (__skb_checksum_convert_check(skb))				\
		__skb_checksum_convert(skb, compute_pseudo(skb, proto)); \
} while (0)
#define skb_checksum_validate(skb, proto, compute_pseudo)		\
	__skb_checksum_validate(skb, proto, true, false, 0, compute_pseudo)
#define skb_checksum_validate_zero_check(skb, proto, check,		\
					 compute_pseudo)		\
	__skb_checksum_validate(skb, proto, true, true, check, compute_pseudo)
#define skb_frag_foreach_page(f, f_off, f_len, p, p_off, p_len, copied)	\
	for (p = skb_frag_page(f) + ((f_off) >> PAGE_SHIFT),		\
	     p_off = (f_off) & (PAGE_SIZE - 1),				\
	     p_len = skb_frag_must_loop(p) ?				\
	     min_t(u32, f_len, PAGE_SIZE - p_off) : f_len,		\
	     copied = 0;						\
	     copied < f_len;						\
	     copied += p_len, p++, p_off = 0,				\
	     p_len = min_t(u32, f_len - copied, PAGE_SIZE))		\

#define skb_list_walk_safe(first, skb, next_skb)                               \
	for ((skb) = (first), (next_skb) = (skb) ? (skb)->next : NULL; (skb);  \
	     (skb) = (next_skb), (next_skb) = (skb) ? (skb)->next : NULL)
#define skb_queue_reverse_walk(queue, skb) \
		for (skb = (queue)->prev;					\
		     skb != (struct sk_buff *)(queue);				\
		     skb = skb->prev)
#define skb_queue_reverse_walk_from_safe(queue, skb, tmp)			\
		for (tmp = skb->prev;						\
		     skb != (struct sk_buff *)(queue);				\
		     skb = tmp, tmp = skb->prev)
#define skb_queue_reverse_walk_safe(queue, skb, tmp)				\
		for (skb = (queue)->prev, tmp = skb->prev;			\
		     skb != (struct sk_buff *)(queue);				\
		     skb = tmp, tmp = skb->prev)
#define skb_queue_walk(queue, skb) \
		for (skb = (queue)->next;					\
		     skb != (struct sk_buff *)(queue);				\
		     skb = skb->next)
#define skb_queue_walk_from(queue, skb)						\
		for (; skb != (struct sk_buff *)(queue);			\
		     skb = skb->next)
#define skb_queue_walk_from_safe(queue, skb, tmp)				\
		for (tmp = skb->next;						\
		     skb != (struct sk_buff *)(queue);				\
		     skb = tmp, tmp = skb->next)
#define skb_queue_walk_safe(queue, skb, tmp)					\
		for (skb = (queue)->next, tmp = skb->next;			\
		     skb != (struct sk_buff *)(queue);				\
		     skb = tmp, tmp = skb->next)
#define skb_rb_first(root) rb_to_skb(rb_first(root))
#define skb_rb_last(root)  rb_to_skb(rb_last(root))
#define skb_rb_next(skb)   rb_to_skb(rb_next(&(skb)->rbnode))
#define skb_rb_prev(skb)   rb_to_skb(rb_prev(&(skb)->rbnode))
#define skb_rbtree_walk(skb, root)						\
		for (skb = skb_rb_first(root); skb != NULL;			\
		     skb = skb_rb_next(skb))
#define skb_rbtree_walk_from(skb)						\
		for (; skb != NULL;						\
		     skb = skb_rb_next(skb))
#define skb_rbtree_walk_from_safe(skb, tmp)					\
		for (; tmp = skb ? skb_rb_next(skb) : NULL, (skb != NULL);	\
		     skb = tmp)
#define skb_shinfo(SKB)	((struct skb_shared_info *)(skb_end_pointer(SKB)))
#define skb_uarg(SKB)	((struct ubuf_info *)(skb_shinfo(SKB)->destructor_arg))
#define skb_walk_frags(skb, iter)	\
	for (iter = skb_shinfo(skb)->frag_list; iter; iter = iter->next)

#define NF_CT_STATE_BIT(ctinfo)			(1 << ((ctinfo) % IP_CT_IS_REPLY + 1))



#define PTR_RING_PEEK_CALL(r, f) ({ \
	typeof((f)(NULL)) __PTR_RING_PEEK_CALL_v; \
	\
	spin_lock(&(r)->consumer_lock); \
	__PTR_RING_PEEK_CALL_v = __PTR_RING_PEEK_CALL(r, f); \
	spin_unlock(&(r)->consumer_lock); \
	__PTR_RING_PEEK_CALL_v; \
})
#define PTR_RING_PEEK_CALL_ANY(r, f) ({ \
	typeof((f)(NULL)) __PTR_RING_PEEK_CALL_v; \
	unsigned long __PTR_RING_PEEK_CALL_f;\
	\
	spin_lock_irqsave(&(r)->consumer_lock, __PTR_RING_PEEK_CALL_f); \
	__PTR_RING_PEEK_CALL_v = __PTR_RING_PEEK_CALL(r, f); \
	spin_unlock_irqrestore(&(r)->consumer_lock, __PTR_RING_PEEK_CALL_f); \
	__PTR_RING_PEEK_CALL_v; \
})
#define PTR_RING_PEEK_CALL_BH(r, f) ({ \
	typeof((f)(NULL)) __PTR_RING_PEEK_CALL_v; \
	\
	spin_lock_bh(&(r)->consumer_lock); \
	__PTR_RING_PEEK_CALL_v = __PTR_RING_PEEK_CALL(r, f); \
	spin_unlock_bh(&(r)->consumer_lock); \
	__PTR_RING_PEEK_CALL_v; \
})
#define PTR_RING_PEEK_CALL_IRQ(r, f) ({ \
	typeof((f)(NULL)) __PTR_RING_PEEK_CALL_v; \
	\
	spin_lock_irq(&(r)->consumer_lock); \
	__PTR_RING_PEEK_CALL_v = __PTR_RING_PEEK_CALL(r, f); \
	spin_unlock_irq(&(r)->consumer_lock); \
	__PTR_RING_PEEK_CALL_v; \
})
#define _LINUX_PTR_RING_H 1
#define __PTR_RING_PEEK_CALL(r, f) ((f)(__ptr_ring_peek(r)))

#define SPLICE_F_ALL (SPLICE_F_MOVE|SPLICE_F_NONBLOCK|SPLICE_F_MORE|SPLICE_F_GIFT)
#define SPLICE_F_NONBLOCK (0x02) 



#define NETIF_F_ALL_TSO 	(NETIF_F_TSO | NETIF_F_TSO6 | \
				 NETIF_F_TSO_ECN | NETIF_F_TSO_MANGLEID)
#define NETIF_F_GSO_TUNNEL_REMCSUM __NETIF_F(GSO_TUNNEL_REMCSUM)
#define NETIF_F_GSO_UDP_TUNNEL_CSUM __NETIF_F(GSO_UDP_TUNNEL_CSUM)
#define NETIF_F_HW_VLAN_CTAG_FILTER __NETIF_F(HW_VLAN_CTAG_FILTER)
#define NETIF_F_HW_VLAN_STAG_FILTER __NETIF_F(HW_VLAN_STAG_FILTER)

#define __NETIF_F(name)		__NETIF_F_BIT(NETIF_F_##name##_BIT)
#define __NETIF_F_BIT(bit)	((netdev_features_t)1 << (bit))
#define for_each_netdev_feature(mask_addr, bit)				\
	for ((bit) = find_next_netdev_feature((mask_addr),		\
					      NETDEV_FEATURE_COUNT);	\
	     (bit) >= 0;						\
	     (bit) = find_next_netdev_feature((mask_addr), (bit) - 1))
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
#define CSUM_MANGLED_0 ((__force __sum16)0xffff)

#define TS_PRIV_ALIGN(len) (((len) + TS_PRIV_ALIGNTO-1) & ~(TS_PRIV_ALIGNTO-1))

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

#define MODULE_ALIAS_RTNL_LINK(kind) MODULE_ALIAS("rtnl-link-" kind)

#define NLA_ENSURE_INT_OR_BINARY_TYPE(tp)		\
	(__NLA_ENSURE(__NLA_IS_UINT_TYPE(tp) ||		\
		      __NLA_IS_SINT_TYPE(tp) ||		\
		      tp == NLA_MSECS ||		\
		      tp == NLA_BINARY) + tp)
#define NLA_ENSURE_NO_VALIDATION_PTR(tp)		\
	(__NLA_ENSURE(tp != NLA_BITFIELD32 &&		\
		      tp != NLA_REJECT &&		\
		      tp != NLA_NESTED &&		\
		      tp != NLA_NESTED_ARRAY) + tp)
#define NLA_ENSURE_SINT_TYPE(tp)			\
	(__NLA_ENSURE(__NLA_IS_SINT_TYPE(tp)) + tp)
#define NLA_ENSURE_UINT_OR_BINARY_TYPE(tp)		\
	(__NLA_ENSURE(__NLA_IS_UINT_TYPE(tp) ||	\
		      tp == NLA_MSECS ||		\
		      tp == NLA_BINARY) + tp)
#define NLA_ENSURE_UINT_TYPE(tp)			\
	(__NLA_ENSURE(__NLA_IS_UINT_TYPE(tp)) + tp)
#define NLA_POLICY_BITFIELD32(valid) \
	{ .type = NLA_BITFIELD32, .bitfield32_valid = valid }
#define NLA_POLICY_EXACT_LEN(_len)	NLA_POLICY_RANGE(NLA_BINARY, _len, _len)
#define NLA_POLICY_EXACT_LEN_WARN(_len) {			\
	.type = NLA_BINARY,					\
	.validation_type = NLA_VALIDATE_RANGE_WARN_TOO_LONG,	\
	.min = _len,						\
	.max = _len						\
}
#define NLA_POLICY_FULL_RANGE(tp, _range) {		\
	.type = NLA_ENSURE_UINT_OR_BINARY_TYPE(tp),	\
	.validation_type = NLA_VALIDATE_RANGE_PTR,	\
	.range = _range,				\
}
#define NLA_POLICY_FULL_RANGE_SIGNED(tp, _range) {	\
	.type = NLA_ENSURE_SINT_TYPE(tp),		\
	.validation_type = NLA_VALIDATE_RANGE_PTR,	\
	.range_signed = _range,				\
}
#define NLA_POLICY_MASK(tp, _mask) {			\
	.type = NLA_ENSURE_UINT_TYPE(tp),		\
	.validation_type = NLA_VALIDATE_MASK,		\
	.mask = _mask,					\
}
#define NLA_POLICY_MAX(tp, _max) {			\
	.type = NLA_ENSURE_INT_OR_BINARY_TYPE(tp),	\
	.validation_type = NLA_VALIDATE_MAX,		\
	.max = _max,					\
}
#define NLA_POLICY_MIN(tp, _min) {			\
	.type = NLA_ENSURE_INT_OR_BINARY_TYPE(tp),	\
	.validation_type = NLA_VALIDATE_MIN,		\
	.min = _min,					\
}
#define NLA_POLICY_MIN_LEN(_len)	NLA_POLICY_MIN(NLA_BINARY, _len)
#define NLA_POLICY_NESTED(policy) \
	_NLA_POLICY_NESTED(ARRAY_SIZE(policy) - 1, policy)
#define NLA_POLICY_NESTED_ARRAY(policy) \
	_NLA_POLICY_NESTED_ARRAY(ARRAY_SIZE(policy) - 1, policy)
#define NLA_POLICY_RANGE(tp, _min, _max) {		\
	.type = NLA_ENSURE_INT_OR_BINARY_TYPE(tp),	\
	.validation_type = NLA_VALIDATE_RANGE,		\
	.min = _min,					\
	.max = _max					\
}
#define NLA_POLICY_VALIDATE_FN(tp, fn, ...) {		\
	.type = NLA_ENSURE_NO_VALIDATION_PTR(tp),	\
	.validation_type = NLA_VALIDATE_FUNCTION,	\
	.validate = fn,					\
	.len = __VA_ARGS__ + 0,				\
}
#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)
#define NL_VALIDATE_DEPRECATED_STRICT (NL_VALIDATE_TRAILING |\
				       NL_VALIDATE_MAXTYPE)
#define NL_VALIDATE_STRICT (NL_VALIDATE_TRAILING |\
			    NL_VALIDATE_MAXTYPE |\
			    NL_VALIDATE_UNSPEC |\
			    NL_VALIDATE_STRICT_ATTRS |\
			    NL_VALIDATE_NESTED)
#define _NLA_POLICY_NESTED(maxattr, policy) \
	{ .type = NLA_NESTED, .nested_policy = policy, .len = maxattr }
#define _NLA_POLICY_NESTED_ARRAY(maxattr, policy) \
	{ .type = NLA_NESTED_ARRAY, .nested_policy = policy, .len = maxattr }

#define __NLA_ENSURE(condition) BUILD_BUG_ON_ZERO(!(condition))
#define __NLA_IS_SINT_TYPE(tp)						\
	(tp == NLA_S8 || tp == NLA_S16 || tp == NLA_S32 || tp == NLA_S64)
#define __NLA_IS_UINT_TYPE(tp)						\
	(tp == NLA_U8 || tp == NLA_U16 || tp == NLA_U32 || tp == NLA_U64)
#define nla_for_each_attr(pos, head, len, rem) \
	for (pos = head, rem = len; \
	     nla_ok(pos, rem); \
	     pos = nla_next(pos, &(rem)))
#define nla_for_each_nested(pos, nla, rem) \
	nla_for_each_attr(pos, nla_data(nla), nla_len(nla), rem)
#define nlmsg_for_each_attr(pos, nlh, hdrlen, rem) \
	nla_for_each_attr(pos, nlmsg_attrdata(nlh, hdrlen), \
			  nlmsg_attrlen(nlh, hdrlen), rem)
#define nlmsg_for_each_msg(pos, head, len, rem) \
	for (pos = head, rem = len; \
	     nlmsg_ok(pos, rem); \
	     pos = nlmsg_next(pos, &(rem)))
#define ASSERT_RTNL() \
	WARN_ONCE(!rtnl_is_locked(), \
		  "RTNL: assertion failed at %s (%d)\n", "__FILE__",  "__LINE__")

#define rcu_dereference_bh_rtnl(p)				\
	rcu_dereference_bh_check(p, lockdep_rtnl_is_held())
#define rcu_dereference_rtnl(p)					\
	rcu_dereference_check(p, lockdep_rtnl_is_held())
#define rtnl_dereference(p)					\
	rcu_dereference_protected(p, lockdep_rtnl_is_held())
#define RTAX_ADVMSS RTAX_ADVMSS
#define RTAX_CC_ALGO RTAX_CC_ALGO
#define RTAX_CWND RTAX_CWND
#define RTAX_FASTOPEN_NO_COOKIE RTAX_FASTOPEN_NO_COOKIE
#define RTAX_FEATURES RTAX_FEATURES
#define RTAX_HOPLIMIT RTAX_HOPLIMIT
#define RTAX_INITCWND RTAX_INITCWND
#define RTAX_INITRWND RTAX_INITRWND
#define RTAX_LOCK RTAX_LOCK
#define RTAX_MAX (__RTAX_MAX - 1)
#define RTAX_MTU RTAX_MTU
#define RTAX_QUICKACK RTAX_QUICKACK
#define RTAX_REORDERING RTAX_REORDERING
#define RTAX_RTO_MIN RTAX_RTO_MIN
#define RTAX_RTT RTAX_RTT
#define RTAX_RTTVAR RTAX_RTTVAR
#define RTAX_SSTHRESH RTAX_SSTHRESH
#define RTAX_UNSPEC RTAX_UNSPEC
#define RTAX_WINDOW RTAX_WINDOW
#define RTA_ALIGN(len) ( ((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1) )
#define RTA_DATA(rta)   ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_LENGTH(len)	(RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_MAX (__RTA_MAX - 1)
#define RTA_NEXT(rta,attrlen)	((attrlen) -= RTA_ALIGN((rta)->rta_len), \
				 (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_OK(rta,len) ((len) >= (int)sizeof(struct rtattr) && \
			 (rta)->rta_len >= sizeof(struct rtattr) && \
			 (rta)->rta_len <= (len))
#define RTA_PAYLOAD(rta) ((int)((rta)->rta_len) - RTA_LENGTH(0))
#define RTA_SPACE(len)	RTA_ALIGN(RTA_LENGTH(len))
#define RTMGRP_DECnet_IFADDR    0x1000
#define RTMGRP_DECnet_ROUTE     0x4000
#define RTM_DELACTION   RTM_DELACTION
#define RTM_DELADDRLABEL RTM_DELADDRLABEL
#define RTM_DELCHAIN RTM_DELCHAIN
#define RTM_DELMDB RTM_DELMDB
#define RTM_DELNETCONF RTM_DELNETCONF
#define RTM_DELNSID RTM_DELNSID
#define RTM_FAM(cmd)	(((cmd) - RTM_BASE) >> 2)
#define RTM_GETACTION   RTM_GETACTION
#define RTM_GETADDRLABEL RTM_GETADDRLABEL
#define RTM_GETCHAIN RTM_GETCHAIN
#define RTM_GETDCB RTM_GETDCB
#define RTM_GETMDB RTM_GETMDB
#define RTM_GETMULTICAST RTM_GETMULTICAST
#define RTM_GETNETCONF RTM_GETNETCONF
#define RTM_GETNSID RTM_GETNSID
#define RTM_GETSTATS RTM_GETSTATS
#define RTM_NEWACTION   RTM_NEWACTION
#define RTM_NEWADDRLABEL RTM_NEWADDRLABEL
#define RTM_NEWCACHEREPORT RTM_NEWCACHEREPORT
#define RTM_NEWCHAIN RTM_NEWCHAIN
#define RTM_NEWMDB RTM_NEWMDB
#define RTM_NEWNDUSEROPT RTM_NEWNDUSEROPT
#define RTM_NEWNETCONF RTM_NEWNETCONF
#define RTM_NEWNSID RTM_NEWNSID
#define RTM_NEWSTATS RTM_NEWSTATS
#define RTM_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct rtmsg))
#define RTM_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct rtmsg))))
#define RTM_SETDCB RTM_SETDCB
#define RTNETLINK_HAVE_PEERINFO 1
#define RTNH_ALIGN(len) ( ((len)+RTNH_ALIGNTO-1) & ~(RTNH_ALIGNTO-1) )
#define RTNH_DATA(rtnh)   ((struct rtattr*)(((char*)(rtnh)) + RTNH_LENGTH(0)))
#define RTNH_LENGTH(len) (RTNH_ALIGN(sizeof(struct rtnexthop)) + (len))
#define RTNH_NEXT(rtnh)	((struct rtnexthop*)(((char*)(rtnh)) + RTNH_ALIGN((rtnh)->rtnh_len)))
#define RTNH_OK(rtnh,len) ((rtnh)->rtnh_len >= sizeof(struct rtnexthop) && \
			   ((int)(rtnh)->rtnh_len) <= (len))
#define RTNH_SPACE(len)	RTNH_ALIGN(RTNH_LENGTH(len))
#define RTN_MAX (__RTN_MAX - 1)
#define TA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct tcamsg))
#define TA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcamsg))))
#define TCAA_MAX TCA_ROOT_TAB
#define TCA_ACT_TAB TCA_ROOT_TAB
#define TCA_DUMP_FLAGS_TERSE (1 << 0) 
#define TCA_MAX (__TCA_MAX - 1)
#define TCA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct tcmsg))
#define TCA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcmsg))))
#define TCM_IFINDEX_MAGIC_BLOCK (0xFFFFFFFFU)

#define tcm_block_index tcm_parent

#define IFLA_BAREUDP_MAX (__IFLA_BAREUDP_MAX - 1)
#define IFLA_BRPORT_MAX (__IFLA_BRPORT_MAX - 1)
#define IFLA_COST IFLA_COST
#define IFLA_GTP_MAX (__IFLA_GTP_MAX - 1)
#define IFLA_HSR_MAX (__IFLA_HSR_MAX - 1)
#define IFLA_INET_MAX (__IFLA_INET_MAX - 1)
#define IFLA_IPOIB_MAX (__IFLA_IPOIB_MAX - 1)
#define IFLA_IPVLAN_MAX (__IFLA_IPVLAN_MAX - 1)
#define IFLA_LINKINFO IFLA_LINKINFO
#define IFLA_MACSEC_MAX (__IFLA_MACSEC_MAX - 1)
#define IFLA_MACVLAN_MAX (__IFLA_MACVLAN_MAX - 1)
#define IFLA_MAP IFLA_MAP
#define IFLA_MASTER IFLA_MASTER
#define IFLA_MAX (__IFLA_MAX - 1)
#define IFLA_MCTP_MAX (__IFLA_MCTP_MAX - 1)
#define IFLA_OFFLOAD_XSTATS_MAX (__IFLA_OFFLOAD_XSTATS_MAX - 1)
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
#define IFLA_PORT_MAX (__IFLA_PORT_MAX - 1)
#define IFLA_PPP_MAX (__IFLA_PPP_MAX - 1)
#define IFLA_PRIORITY IFLA_PRIORITY
#define IFLA_PROMISCUITY IFLA_PROMISCUITY
#define IFLA_PROTINFO IFLA_PROTINFO
#define IFLA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#define IFLA_STATS_FILTER_BIT(ATTR)	(1 << (ATTR - 1))
#define IFLA_STATS_MAX (__IFLA_STATS_MAX - 1)
#define IFLA_TUN_MAX (__IFLA_TUN_MAX - 1)
#define IFLA_TXQLEN IFLA_TXQLEN
#define IFLA_VF_INFO_MAX (__IFLA_VF_INFO_MAX - 1)
#define IFLA_VF_MAX (__IFLA_VF_MAX - 1)
#define IFLA_VF_PORT_MAX (__IFLA_VF_PORT_MAX - 1)
#define IFLA_VF_STATS_MAX (__IFLA_VF_STATS_MAX - 1)
#define IFLA_VF_VLAN_INFO_MAX (__IFLA_VF_VLAN_INFO_MAX - 1)
#define IFLA_VRF_MAX (__IFLA_VRF_MAX - 1)
#define IFLA_VRF_PORT_MAX (__IFLA_VRF_PORT_MAX - 1)
#define IFLA_WEIGHT IFLA_WEIGHT
#define IFLA_WIRELESS IFLA_WIRELESS
#define IFLA_XDP_MAX (__IFLA_XDP_MAX - 1)
#define IFLA_XFRM_MAX (__IFLA_XFRM_MAX - 1)
#define LINK_XSTATS_TYPE_MAX (__LINK_XSTATS_TYPE_MAX - 1)
#define MAX_VLAN_LIST_LEN 1
#define RMNET_FLAGS_EGRESS_MAP_CKSUMV4            (1U << 3)
#define RMNET_FLAGS_EGRESS_MAP_CKSUMV5            (1U << 5)
#define RMNET_FLAGS_INGRESS_DEAGGREGATION         (1U << 0)
#define RMNET_FLAGS_INGRESS_MAP_CKSUMV4           (1U << 2)
#define RMNET_FLAGS_INGRESS_MAP_CKSUMV5           (1U << 4)
#define RMNET_FLAGS_INGRESS_MAP_COMMANDS          (1U << 1)

#define GRO_RECURSION_LIMIT 15
#define HARD_TX_LOCK(dev, txq, cpu) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_lock(txq, cpu);		\
	} else {					\
		__netif_tx_acquire(txq);		\
	}						\
}
#define HARD_TX_TRYLOCK(dev, txq)			\
	(((dev->features & NETIF_F_LLTX) == 0) ?	\
		__netif_tx_trylock(txq) :		\
		__netif_tx_acquire(txq))
#define HARD_TX_UNLOCK(dev, txq) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_unlock(txq);			\
	} else {					\
		__netif_tx_release(txq);		\
	}						\
}
#define HH_DATA_ALIGN(__len) \
	(((__len)+(HH_DATA_MOD-1))&~(HH_DATA_MOD - 1))
#define HH_DATA_OFF(__len) \
	(HH_DATA_MOD - (((__len - 1) & (HH_DATA_MOD - 1)) + 1))
#  define LL_MAX_HEADER 128
#define LL_RESERVED_SPACE(dev) \
	((((dev)->hard_header_len+(dev)->needed_headroom)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) \
	((((dev)->hard_header_len+(dev)->needed_headroom+(extra))&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define MAX_HEADER LL_MAX_HEADER
#define MAX_NEST_DEV 8
#define MAX_PHYS_ITEM_ID_LEN 32
#define MODULE_ALIAS_NETDEV(device) \
	MODULE_ALIAS("netdev-" device)
#define NAPI_GRO_CB(skb) ((struct napi_gro_cb *)(skb)->cb)
#define NAPI_GRO_FREE_STOLEN_HEAD 2
#define NAPI_POLL_WEIGHT 64
#define NETDEV_FCOE_WWNN 0
#define NETDEV_FCOE_WWPN 1
#define NETDEV_RSS_KEY_LEN 52
#define QUEUE_STATE_ANY_XOFF_OR_FROZEN (QUEUE_STATE_ANY_XOFF | \
					QUEUE_STATE_FROZEN)
#define QUEUE_STATE_DRV_XOFF_OR_FROZEN (QUEUE_STATE_DRV_XOFF | \
					QUEUE_STATE_FROZEN)
#define RPS_DEV_FLOW_TABLE_SIZE(_num) (sizeof(struct rps_dev_flow_table) + \
    ((_num) * sizeof(struct rps_dev_flow)))
#define RPS_MAP_SIZE(_num) (sizeof(struct rps_map) + ((_num) * sizeof(u16)))
#define RPS_NO_CPU 0xffff
#define RPS_NO_FILTER 0xffff
#define SET_NETDEV_DEV(net, pdev)	((net)->dev.parent = (pdev))
#define SET_NETDEV_DEVTYPE(net, devtype)	((net)->dev.type = (devtype))
#define XDP_WAKEUP_RX (1 << 0)
#define XDP_WAKEUP_TX (1 << 1)
#define XPS_CPU_DEV_MAPS_SIZE(_tcs) (sizeof(struct xps_dev_maps) +	\
	(nr_cpu_ids * (_tcs) * sizeof(struct xps_map *)))
#define XPS_MAP_SIZE(_num) (sizeof(struct xps_map) + ((_num) * sizeof(u16)))
#define XPS_MIN_MAP_ALLOC ((L1_CACHE_ALIGN(offsetof(struct xps_map, queues[1])) \
       - sizeof(struct xps_map)) / sizeof(u16))
#define XPS_RXQ_DEV_MAPS_SIZE(_tcs, _rxqs) (sizeof(struct xps_dev_maps) +\
	(_rxqs * (_tcs) * sizeof(struct xps_map *)))

#define __NESTED_SYNC(name)	__NESTED_SYNC_BIT(NESTED_SYNC_ ## name ## _BIT)
#define __NESTED_SYNC_BIT(bit)	((u32)1 << (bit))
#define __NETIF_MSG(name)	__NETIF_MSG_BIT(NETIF_MSG_ ## name ## _BIT)
#define __NETIF_MSG_BIT(bit)	((u32)1 << (bit))
#define __netdev_alloc_pcpu_stats(type, gfp)				\
({									\
	typeof(type) __percpu *pcpu_stats = alloc_percpu_gfp(type, gfp);\
	if (pcpu_stats)	{						\
		int __cpu;						\
		for_each_possible_cpu(__cpu) {				\
			typeof(type) *stat;				\
			stat = per_cpu_ptr(pcpu_stats, __cpu);		\
			u64_stats_init(&stat->syncp);			\
		}							\
	}								\
	pcpu_stats;							\
})
#define __skb_gro_checksum_validate(skb, proto, zero_okay, check,	\
				    compute_pseudo)			\
({									\
	__sum16 __ret = 0;						\
	if (__skb_gro_checksum_validate_needed(skb, zero_okay, check))	\
		__ret = __skb_gro_checksum_validate_complete(skb,	\
				compute_pseudo(skb, proto));		\
	if (!__ret)							\
		skb_gro_incr_csum_unnecessary(skb);			\
	__ret;								\
})
#define alloc_netdev(sizeof_priv, name, name_assign_type, setup) \
	alloc_netdev_mqs(sizeof_priv, name, name_assign_type, setup, 1, 1)
#define alloc_netdev_mq(sizeof_priv, name, name_assign_type, setup, count) \
	alloc_netdev_mqs(sizeof_priv, name, name_assign_type, setup, count, \
			 count)
#define dev_proc_init() 0
#define devm_netdev_alloc_pcpu_stats(dev, type)				\
({									\
	typeof(type) __percpu *pcpu_stats = devm_alloc_percpu(dev, type);\
	if (pcpu_stats) {						\
		int __cpu;						\
		for_each_possible_cpu(__cpu) {				\
			typeof(type) *stat;				\
			stat = per_cpu_ptr(pcpu_stats, __cpu);		\
			u64_stats_init(&stat->syncp);			\
		}							\
	}								\
	pcpu_stats;							\
})
#define for_each_dev_addr(dev, ha) \
		list_for_each_entry_rcu(ha, &dev->dev_addrs.list, list)
#define for_each_netdev(net, d)		\
		list_for_each_entry(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_continue(net, d)		\
		list_for_each_entry_continue(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_continue_rcu(net, d)		\
	list_for_each_entry_continue_rcu(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_continue_reverse(net, d)		\
		list_for_each_entry_continue_reverse(d, &(net)->dev_base_head, \
						     dev_list)
#define for_each_netdev_in_bond_rcu(bond, slave)	\
		for_each_netdev_rcu(&init_net, slave)	\
			if (netdev_master_upper_dev_get_rcu(slave) == (bond))
#define for_each_netdev_rcu(net, d)		\
		list_for_each_entry_rcu(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_reverse(net, d)	\
		list_for_each_entry_reverse(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_safe(net, d, n)	\
		list_for_each_entry_safe(d, n, &(net)->dev_base_head, dev_list)
#define net_device_entry(lh)	list_entry(lh, struct net_device, dev_list)
#define net_xmit_errno(e)	((e) != NET_XMIT_CN ? -ENOBUFS : 0)
#define net_xmit_eval(e)	((e) == NET_XMIT_CN ? 0 : (e))
#define netdev_WARN(dev, format, args...)			\
	WARN(1, "netdevice: %s%s: " format, netdev_name(dev),	\
	     netdev_reg_state(dev), ##args)
#define netdev_WARN_ONCE(dev, format, args...)				\
	WARN_ONCE(1, "netdevice: %s%s: " format, netdev_name(dev),	\
		  netdev_reg_state(dev), ##args)
#define netdev_alert_once(dev, fmt, ...) \
	netdev_level_once(KERN_ALERT, dev, fmt, ##__VA_ARGS__)
#define netdev_alloc_pcpu_stats(type)					\
	__netdev_alloc_pcpu_stats(type, GFP_KERNEL)
#define netdev_crit_once(dev, fmt, ...) \
	netdev_level_once(KERN_CRIT, dev, fmt, ##__VA_ARGS__)
#define netdev_dbg(__dev, format, args...)			\
do {								\
	dynamic_netdev_dbg(__dev, format, ##args);		\
} while (0)
#define netdev_emerg_once(dev, fmt, ...) \
	netdev_level_once(KERN_EMERG, dev, fmt, ##__VA_ARGS__)
#define netdev_err_once(dev, fmt, ...) \
	netdev_level_once(KERN_ERR, dev, fmt, ##__VA_ARGS__)
#define netdev_for_each_lower_dev(dev, ldev, iter) \
	for (iter = (dev)->adj_list.lower.next, \
	     ldev = netdev_lower_get_next(dev, &(iter)); \
	     ldev; \
	     ldev = netdev_lower_get_next(dev, &(iter)))
#define netdev_for_each_lower_private(dev, priv, iter) \
	for (iter = (dev)->adj_list.lower.next, \
	     priv = netdev_lower_get_next_private(dev, &(iter)); \
	     priv; \
	     priv = netdev_lower_get_next_private(dev, &(iter)))
#define netdev_for_each_lower_private_rcu(dev, priv, iter) \
	for (iter = &(dev)->adj_list.lower, \
	     priv = netdev_lower_get_next_private_rcu(dev, &(iter)); \
	     priv; \
	     priv = netdev_lower_get_next_private_rcu(dev, &(iter)))
#define netdev_for_each_mc_addr(ha, dev) \
	netdev_hw_addr_list_for_each(ha, &(dev)->mc)
#define netdev_for_each_uc_addr(ha, dev) \
	netdev_hw_addr_list_for_each(ha, &(dev)->uc)
#define netdev_for_each_upper_dev_rcu(dev, updev, iter) \
	for (iter = &(dev)->adj_list.upper, \
	     updev = netdev_upper_get_next_dev_rcu(dev, &(iter)); \
	     updev; \
	     updev = netdev_upper_get_next_dev_rcu(dev, &(iter)))
#define netdev_hw_addr_list_count(l) ((l)->count)
#define netdev_hw_addr_list_empty(l) (netdev_hw_addr_list_count(l) == 0)
#define netdev_hw_addr_list_for_each(ha, l) \
	list_for_each_entry(ha, &(l)->list, list)
#define netdev_info_once(dev, fmt, ...) \
	netdev_level_once(KERN_INFO, dev, fmt, ##__VA_ARGS__)
#define netdev_level_once(level, dev, fmt, ...)			\
do {								\
	static bool __print_once __read_mostly;			\
								\
	if (!__print_once) {					\
		__print_once = true;				\
		netdev_printk(level, dev, fmt, ##__VA_ARGS__);	\
	}							\
} while (0)
#define netdev_lockdep_set_classes(dev)				\
{								\
	static struct lock_class_key qdisc_tx_busylock_key;	\
	static struct lock_class_key qdisc_running_key;		\
	static struct lock_class_key qdisc_xmit_lock_key;	\
	static struct lock_class_key dev_addr_list_lock_key;	\
	unsigned int i;						\
								\
	(dev)->qdisc_tx_busylock = &qdisc_tx_busylock_key;	\
	(dev)->qdisc_running_key = &qdisc_running_key;		\
	lockdep_set_class(&(dev)->addr_list_lock,		\
			  &dev_addr_list_lock_key);		\
	for (i = 0; i < (dev)->num_tx_queues; i++)		\
		lockdep_set_class(&(dev)->_tx[i]._xmit_lock,	\
				  &qdisc_xmit_lock_key);	\
}
#define netdev_mc_count(dev) netdev_hw_addr_list_count(&(dev)->mc)
#define netdev_mc_empty(dev) netdev_hw_addr_list_empty(&(dev)->mc)
#define netdev_notice_once(dev, fmt, ...) \
	netdev_level_once(KERN_NOTICE, dev, fmt, ##__VA_ARGS__)
#define netdev_uc_count(dev) netdev_hw_addr_list_count(&(dev)->uc)
#define netdev_uc_empty(dev) netdev_hw_addr_list_empty(&(dev)->uc)
#define netdev_vdbg(dev, format, args...)			\
({								\
	if (0)							\
		netdev_printk(KERN_DEBUG, dev, format, ##args);	\
	0;							\
})
#define netdev_warn_once(dev, fmt, ...) \
	netdev_level_once(KERN_WARNING, dev, fmt, ##__VA_ARGS__)
#define netif_alert(priv, type, dev, fmt, args...)		\
	netif_level(alert, priv, type, dev, fmt, ##args)
#define netif_cond_dbg(priv, type, netdev, cond, level, fmt, args...)     \
	do {                                                              \
		if (cond)                                                 \
			netif_dbg(priv, type, netdev, fmt, ##args);       \
		else                                                      \
			netif_ ## level(priv, type, netdev, fmt, ##args); \
	} while (0)
#define netif_crit(priv, type, dev, fmt, args...)		\
	netif_level(crit, priv, type, dev, fmt, ##args)
#define netif_dbg(priv, type, netdev, format, args...)		\
do {								\
	if (netif_msg_##type(priv))				\
		dynamic_netdev_dbg(netdev, format, ##args);	\
} while (0)
#define netif_emerg(priv, type, dev, fmt, args...)		\
	netif_level(emerg, priv, type, dev, fmt, ##args)
#define netif_err(priv, type, dev, fmt, args...)		\
	netif_level(err, priv, type, dev, fmt, ##args)
#define netif_info(priv, type, dev, fmt, args...)		\
	netif_level(info, priv, type, dev, fmt, ##args)
#define netif_level(level, priv, type, dev, fmt, args...)	\
do {								\
	if (netif_msg_##type(priv))				\
		netdev_##level(dev, fmt, ##args);		\
} while (0)
#define netif_msg_drv(p)	((p)->msg_enable & NETIF_MSG_DRV)
#define netif_msg_hw(p)		((p)->msg_enable & NETIF_MSG_HW)
#define netif_msg_ifdown(p)	((p)->msg_enable & NETIF_MSG_IFDOWN)
#define netif_msg_ifup(p)	((p)->msg_enable & NETIF_MSG_IFUP)
#define netif_msg_intr(p)	((p)->msg_enable & NETIF_MSG_INTR)
#define netif_msg_link(p)	((p)->msg_enable & NETIF_MSG_LINK)
#define netif_msg_pktdata(p)	((p)->msg_enable & NETIF_MSG_PKTDATA)
#define netif_msg_probe(p)	((p)->msg_enable & NETIF_MSG_PROBE)
#define netif_msg_rx_err(p)	((p)->msg_enable & NETIF_MSG_RX_ERR)
#define netif_msg_rx_status(p)	((p)->msg_enable & NETIF_MSG_RX_STATUS)
#define netif_msg_timer(p)	((p)->msg_enable & NETIF_MSG_TIMER)
#define netif_msg_tx_done(p)	((p)->msg_enable & NETIF_MSG_TX_DONE)
#define netif_msg_tx_err(p)	((p)->msg_enable & NETIF_MSG_TX_ERR)
#define netif_msg_tx_queued(p)	((p)->msg_enable & NETIF_MSG_TX_QUEUED)
#define netif_msg_wol(p)	((p)->msg_enable & NETIF_MSG_WOL)
#define netif_notice(priv, type, dev, fmt, args...)		\
	netif_level(notice, priv, type, dev, fmt, ##args)
#define netif_printk(priv, type, level, dev, fmt, args...)	\
do {					  			\
	if (netif_msg_##type(priv))				\
		netdev_printk(level, (dev), fmt, ##args);	\
} while (0)
#define netif_vdbg(priv, type, dev, format, args...)		\
({								\
	if (0)							\
		netif_printk(priv, type, KERN_DEBUG, dev, format, ##args); \
	0;							\
})
#define netif_warn(priv, type, dev, fmt, args...)		\
	netif_level(warn, priv, type, dev, fmt, ##args)
#define skb_gro_checksum_simple_validate(skb)				\
	__skb_gro_checksum_validate(skb, 0, false, 0, null_compute_pseudo)
#define skb_gro_checksum_try_convert(skb, proto, compute_pseudo)	\
do {									\
	if (__skb_gro_checksum_convert_check(skb))			\
		__skb_gro_checksum_convert(skb, 			\
					   compute_pseudo(skb, proto));	\
} while (0)
#define skb_gro_checksum_validate(skb, proto, compute_pseudo)		\
	__skb_gro_checksum_validate(skb, proto, false, 0, compute_pseudo)
#define skb_gro_checksum_validate_zero_check(skb, proto, check,		\
					     compute_pseudo)		\
	__skb_gro_checksum_validate(skb, proto, true, check, compute_pseudo)
#define to_net_dev(d) container_of(d, struct net_device, dev)
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
#define TCA_ACT_BPF 13
#define TCA_ACT_CONNMARK 14
#define TCA_ACT_CSUM 16
#define TCA_ACT_FLAGS_NO_PERCPU_STATS 1 
#define TCA_ACT_GACT 5
#define TCA_ACT_HW_STATS_DELAYED (1 << 1) 
#define TCA_ACT_HW_STATS_IMMEDIATE (1 << 0) 
#define TCA_ACT_IFE 25
#define TCA_ACT_IPT 6
#define TCA_ACT_MAX __TCA_ACT_MAX
#define TCA_ACT_MAX_PRIO 32
#define TCA_ACT_MIRRED 8
#define TCA_ACT_NAT 9
#define TCA_ACT_PEDIT 7
#define TCA_ACT_SAMPLE 26
#define TCA_ACT_SIMP 22
#define TCA_ACT_SKBEDIT 11
#define TCA_ACT_SKBMOD 15
#define TCA_ACT_TUNNEL_KEY 17
#define TCA_ACT_VLAN 12
#define TCA_ACT_XT 10
#define TCA_BASIC_MAX (__TCA_BASIC_MAX - 1)
#define TCA_BPF_MAX (__TCA_BPF_MAX - 1)
#define TCA_CGROUP_MAX (__TCA_CGROUP_MAX - 1)
#define TCA_CLS_FLAGS_NOT_IN_HW (1 << 3) 
#define TCA_EMATCH_TREE_MAX (__TCA_EMATCH_TREE_MAX - 1)
#define TCA_FLOWER_KEY_ENC_OPTS_MAX (__TCA_FLOWER_KEY_ENC_OPTS_MAX - 1)
#define TCA_FLOWER_KEY_ENC_OPT_ERSPAN_MAX \
		(__TCA_FLOWER_KEY_ENC_OPT_ERSPAN_MAX - 1)
#define TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX \
		(__TCA_FLOWER_KEY_ENC_OPT_GENEVE_MAX - 1)
#define TCA_FLOWER_KEY_ENC_OPT_VXLAN_MAX \
		(__TCA_FLOWER_KEY_ENC_OPT_VXLAN_MAX - 1)
#define TCA_FLOWER_KEY_MPLS_OPTS_MAX (__TCA_FLOWER_KEY_MPLS_OPTS_MAX - 1)
#define TCA_FLOWER_KEY_MPLS_OPT_LSE_MAX \
		(__TCA_FLOWER_KEY_MPLS_OPT_LSE_MAX - 1)
#define TCA_FLOWER_MAX (__TCA_FLOWER_MAX - 1)
#define TCA_FW_MAX (__TCA_FW_MAX - 1)
#define TCA_ID_MAX __TCA_ID_MAX
#define TCA_MATCHALL_MAX (__TCA_MATCHALL_MAX - 1)
#define TCA_OLD_COMPAT (TCA_ACT_MAX+1)
#define TCA_POLICE_MAX (__TCA_POLICE_MAX - 1)
#define TCA_POLICE_RESULT TCA_POLICE_RESULT
#define TCA_ROUTE4_MAX (__TCA_ROUTE4_MAX - 1)
#define TCA_RSVP_MAX (__TCA_RSVP_MAX - 1 )
#define TCA_TCINDEX_MAX     (__TCA_TCINDEX_MAX - 1)
#define TCA_U32_MAX (__TCA_U32_MAX - 1)
#define TCF_EM_REL_VALID(v) (((v) & TCF_EM_REL_MASK) != TCF_EM_REL_MASK)
#define TCF_LAYER_MAX (__TCF_LAYER_MAX - 1)
#define TC_ACT_EXT_CMP(combined, opcode) (TC_ACT_EXT_OPCODE(combined) == opcode)
#define TC_ACT_EXT_OPCODE(combined) ((combined) & (~TC_ACT_EXT_VAL_MASK))
#define TC_ACT_EXT_VAL_MASK ((1 << __TC_ACT_EXT_SHIFT) - 1)
#define TC_ACT_GOTO_CHAIN __TC_ACT_EXT(2)
#define TC_ACT_JUMP __TC_ACT_EXT(1)
#define TC_COOKIE_MAX_SIZE 16
#define TC_U32_HASH(h) (((h)>>12)&0xFF)
#define TC_U32_HTID(h) ((h)&0xFFF00000)
#define TC_U32_KEY(h) ((h)&0xFFFFF)
#define TC_U32_MAXDEPTH 8
#define TC_U32_NODE(h) ((h)&0xFFF)
#define TC_U32_USERHTID(h) (TC_U32_HTID(h)>>20)

#define __TC_ACT_EXT(local) ((local) << __TC_ACT_EXT_SHIFT)
#define __TC_ACT_EXT_SHIFT 28
#define tc_gen \
	__u32                 index; \
	__u32                 capab; \
	int                   action; \
	int                   refcnt; \
	int                   bindcnt
#define BOND_3AD_STAT_MAX (__BOND_3AD_STAT_MAX - 1)
#define BOND_ABI_VERSION 2
#define BOND_DEFAULT_MAX_BONDS  1   
#define BOND_DEFAULT_TX_QUEUES 16   
#define BOND_LINK_BACK  3           
#define BOND_LINK_DOWN  2           
#define BOND_LINK_FAIL  1           
#define BOND_LINK_UP    0           
#define BOND_MODE_8023AD        4
#define BOND_MODE_TLB           5
#define BOND_STATE_ACTIVE       0   
#define BOND_STATE_BACKUP       1   
#define BOND_XSTATS_MAX (__BOND_XSTATS_MAX - 1)
#define LACP_STATE_AGGREGATION     0x4
#define LACP_STATE_COLLECTING      0x10
#define LACP_STATE_DEFAULTED       0x40
#define LACP_STATE_DISTRIBUTING    0x20
#define LACP_STATE_EXPIRED         0x80
#define LACP_STATE_LACP_ACTIVITY   0x1
#define LACP_STATE_LACP_TIMEOUT    0x2
#define LACP_STATE_SYNCHRONIZATION 0x8



#define DEV_MAP_BULK_SIZE XDP_BULK_QUEUE_SIZE
#define XDP_WARN(msg) xdp_warn(msg, __func__, "__LINE__")

#define xdp_data_hard_end(xdp)				\
	((xdp)->data_hard_start + (xdp)->frame_sz -	\
	 SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))


#define NETDEV_HASHBITS    8
#define NETDEV_HASHENTRIES (1 << NETDEV_HASHBITS)





#define for_each_net(VAR)				\
	list_for_each_entry(VAR, &net_namespace_list, list)
#define for_each_net_continue_reverse(VAR)		\
	list_for_each_entry_continue_reverse(VAR, &net_namespace_list, list)
#define for_each_net_rcu(VAR)				\
	list_for_each_entry_rcu(VAR, &net_namespace_list, list)


#define net_drop_ns NULL









#define DST_PERCPU_COUNTER_BATCH 32







#define IP_CT_EXP_CHALLENGE_ACK 		0x40


#define NF_ARP_NUMHOOKS 3
#define NF_DN_NUMHOOKS 7

#define NF_ACCEPT 1
#define NF_DROP 0
#define NF_DROP_ERR(x) (((-x) << 16) | NF_DROP)
#define NF_MAX_VERDICT NF_STOP
#define NF_QUEUE 3
#define NF_QUEUE_NR(x) ((((x) << 16) & NF_VERDICT_QMASK) | NF_QUEUE)
#define NF_REPEAT 4
#define NF_STOLEN 2
#define NF_STOP 5	
#define NF_VERDICT_BITS 16
#define NF_VERDICT_MASK 0x000000ff
#define NF_VERDICT_QBITS 16
#define NF_VERDICT_QMASK 0xffff0000


#define GROUP_FILTER_SIZE(numsrc) \
	(sizeof(struct group_filter) - sizeof(struct __kernel_sockaddr_storage) \
	+ (numsrc) * sizeof(struct __kernel_sockaddr_storage))
#define IP_DEFAULT_MULTICAST_LOOP       1
#define IP_DEFAULT_MULTICAST_TTL        1
#define IP_MINTTL       21
#define IP_MSFILTER_SIZE(numsrc) \
	(sizeof(struct ip_msfilter) - sizeof(__u32) \
	+ (numsrc) * sizeof(__u32))
#define IP_MULTICAST_LOOP 		34
#define IP_MULTICAST_TTL 		33
#define IP_NODEFRAG     22
#define IP_ORIGDSTADDR       20
#define IP_RECVORIGDSTADDR   IP_ORIGDSTADDR






#define ICMPV6_ERRMSG_MAX       127
#define ICMPV6_MGM_REDUCTION    	132
#define ICMPV6_MGM_REPORT       	131
#define ICMPV6_MSG_MAX          255
#define MLD2_ALL_MCR_INIT { { { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x16 } } }





#define DECLARE_SNMP_STAT(type, name)	\
	extern __typeof__(type) __percpu *name
#define DEFINE_SNMP_STAT(type, name)	\
	__typeof__(type) __percpu *name
#define DEFINE_SNMP_STAT_ATOMIC(type, name)	\
	__typeof__(type) *name
#define ICMP6MSG_MIB_MAX  __ICMP6MSG_MIB_MAX
#define SNMP_ADD_STATS(mib, field, addend)	\
			this_cpu_add(mib->mibs[field], addend)
#define SNMP_ADD_STATS64(mib, field, addend) 				\
	do {								\
		local_bh_disable();					\
		__SNMP_ADD_STATS64(mib, field, addend);			\
		local_bh_enable();				\
	} while (0)
#define SNMP_DEC_STATS(mib, field)	\
			this_cpu_dec(mib->mibs[field])
#define SNMP_DEC_STATS64(mib, field)		SNMP_DEC_STATS(mib, field)
#define SNMP_INC_STATS(mib, field)	\
			this_cpu_inc(mib->mibs[field])
#define SNMP_INC_STATS64(mib, field) SNMP_ADD_STATS64(mib, field, 1)
#define SNMP_INC_STATS_ATOMIC_LONG(mib, field)	\
			atomic_long_inc(&mib->mibs[field])
#define SNMP_MIB_ITEM(_name,_entry)	{	\
	.name = _name,				\
	.entry = _entry,			\
}
#define SNMP_MIB_SENTINEL {	\
	.name = NULL,		\
	.entry = 0,		\
}
#define SNMP_UPD_PO_STATS(mib, basefield, addend)	\
	do { \
		__typeof__((mib->mibs) + 0) ptr = mib->mibs;	\
		this_cpu_inc(ptr[basefield##PKTS]);		\
		this_cpu_add(ptr[basefield##OCTETS], addend);	\
	} while (0)
#define SNMP_UPD_PO_STATS64(mib, basefield, addend)			\
	do {								\
		local_bh_disable();					\
		__SNMP_UPD_PO_STATS64(mib, basefield, addend);		\
		local_bh_enable();				\
	} while (0)

#define __SNMP_ADD_STATS(mib, field, addend)	\
			__this_cpu_add(mib->mibs[field], addend)
#define __SNMP_ADD_STATS64(mib, field, addend) 				\
	do {								\
		__typeof__(*mib) *ptr = raw_cpu_ptr(mib);		\
		u64_stats_update_begin(&ptr->syncp);			\
		ptr->mibs[field] += addend;				\
		u64_stats_update_end(&ptr->syncp);			\
	} while (0)
#define __SNMP_INC_STATS(mib, field)	\
			__this_cpu_inc(mib->mibs[field])
#define __SNMP_INC_STATS64(mib, field) SNMP_ADD_STATS64(mib, field, 1)
#define __SNMP_UPD_PO_STATS(mib, basefield, addend)	\
	do { \
		__typeof__((mib->mibs) + 0) ptr = mib->mibs;	\
		__this_cpu_inc(ptr[basefield##PKTS]);		\
		__this_cpu_add(ptr[basefield##OCTETS], addend);	\
	} while (0)
#define __SNMP_UPD_PO_STATS64(mib, basefield, addend)			\
	do {								\
		__typeof__(*mib) *ptr;				\
		ptr = raw_cpu_ptr((mib));				\
		u64_stats_update_begin(&ptr->syncp);			\
		ptr->mibs[basefield##PKTS]++;				\
		ptr->mibs[basefield##OCTETS] += addend;			\
		u64_stats_update_end(&ptr->syncp);			\
	} while (0)

#define DQL_MAX_LIMIT ((UINT_MAX / 2) - DQL_MAX_OBJECT)
#define DQL_MAX_OBJECT (UINT_MAX / 16)

#define PREFETCH_STRIDE (4*L1_CACHE_BYTES)

#define prefetch(x) __builtin_prefetch(x)
#define prefetchw(x) __builtin_prefetch(x,1)
#define spin_lock_prefetch(x) prefetchw(x)

#define mdelay(n) (\
	(__builtin_constant_p(n) && (n)<=MAX_UDELAY_MS) ? udelay((n)*1000) : \
	({unsigned long __ms=(n); while (__ms--) udelay(1000);}))
#define ndelay(x) ndelay(x)

#define SHA1_BLOCK_SIZE         64
#define SHA1_DIGEST_SIZE        20

#define ARCH_PAGE_TABLE_SYNC_MASK 0
#define VMALLOC_TOTAL (VMALLOC_END - VMALLOC_START)


#define skb_vlan_tag_get(__skb)		((__skb)->vlan_tci)
#define skb_vlan_tag_get_cfi(__skb)	(!!((__skb)->vlan_tci & VLAN_CFI_MASK))
#define skb_vlan_tag_get_id(__skb)	((__skb)->vlan_tci & VLAN_VID_MASK)
#define skb_vlan_tag_get_prio(__skb)	(((__skb)->vlan_tci & VLAN_PRIO_MASK) >> VLAN_PRIO_SHIFT)
#define skb_vlan_tag_present(__skb)	((__skb)->vlan_present)


#define alloc_etherdev(sizeof_priv) alloc_etherdev_mq(sizeof_priv, 1)
#define alloc_etherdev_mq(sizeof_priv, count) alloc_etherdev_mqs(sizeof_priv, count, count)
#define devm_alloc_etherdev(dev, sizeof_priv) devm_alloc_etherdev_mqs(dev, sizeof_priv, 1, 1)
#define eth_stp_addr eth_reserved_addr_base
#define random_ether_addr(addr) eth_random_addr(addr)

#define crc32(seed, data, length)  crc32_le(seed, (unsigned char const *)(data), length)
#define ether_crc(length, data)    bitrev32(crc32_le(~0, data, length))
#define ether_crc_le(length, data) crc32_le(~0, data, length)

#define __bitrev16 __arch_bitrev16
#define __bitrev32 __arch_bitrev32
#define __bitrev8 __arch_bitrev8
#define __bitrev8x4(x)	(__bitrev32(swab32(x)))
#define __constant_bitrev16(x)	\
({					\
	u16 ___x = x;			\
	___x = (___x >> 8) | (___x << 8);	\
	___x = ((___x & (u16)0xF0F0U) >> 4) | ((___x & (u16)0x0F0FU) << 4);	\
	___x = ((___x & (u16)0xCCCCU) >> 2) | ((___x & (u16)0x3333U) << 2);	\
	___x = ((___x & (u16)0xAAAAU) >> 1) | ((___x & (u16)0x5555U) << 1);	\
	___x;								\
})
#define __constant_bitrev32(x)	\
({					\
	u32 ___x = x;			\
	___x = (___x >> 16) | (___x << 16);	\
	___x = ((___x & (u32)0xFF00FF00UL) >> 8) | ((___x & (u32)0x00FF00FFUL) << 8);	\
	___x = ((___x & (u32)0xF0F0F0F0UL) >> 4) | ((___x & (u32)0x0F0F0F0FUL) << 4);	\
	___x = ((___x & (u32)0xCCCCCCCCUL) >> 2) | ((___x & (u32)0x33333333UL) << 2);	\
	___x = ((___x & (u32)0xAAAAAAAAUL) >> 1) | ((___x & (u32)0x55555555UL) << 1);	\
	___x;								\
})
#define __constant_bitrev8(x)	\
({					\
	u8 ___x = x;			\
	___x = (___x >> 4) | (___x << 4);	\
	___x = ((___x & (u8)0xCCU) >> 2) | ((___x & (u8)0x33U) << 2);	\
	___x = ((___x & (u8)0xAAU) >> 1) | ((___x & (u8)0x55U) << 1);	\
	___x;								\
})
#define __constant_bitrev8x4(x) \
({			\
	u32 ___x = x;	\
	___x = ((___x & (u32)0xF0F0F0F0UL) >> 4) | ((___x & (u32)0x0F0F0F0FUL) << 4);	\
	___x = ((___x & (u32)0xCCCCCCCCUL) >> 2) | ((___x & (u32)0x33333333UL) << 2);	\
	___x = ((___x & (u32)0xAAAAAAAAUL) >> 1) | ((___x & (u32)0x55555555UL) << 1);	\
	___x;								\
})
#define bitrev16(x) \
({			\
	u16 __x = x;	\
	__builtin_constant_p(__x) ?	\
	__constant_bitrev16(__x) :			\
	__bitrev16(__x);				\
 })
#define bitrev32(x) \
({			\
	u32 __x = x;	\
	__builtin_constant_p(__x) ?	\
	__constant_bitrev32(__x) :			\
	__bitrev32(__x);				\
})
#define bitrev8(x) \
({			\
	u8 __x = x;	\
	__builtin_constant_p(__x) ?	\
	__constant_bitrev8(__x) :			\
	__bitrev8(__x)	;			\
 })
#define bitrev8x4(x) \
({			\
	u32 __x = x;	\
	__builtin_constant_p(__x) ?	\
	__constant_bitrev8x4(__x) :			\
	__bitrev8x4(__x);				\
 })

#define can_set_direct_map can_set_direct_map
#define BITS_PER_COMPAT_LONG    (8*sizeof(compat_long_t))
#define BITS_TO_COMPAT_LONGS(bits) DIV_ROUND_UP(bits, BITS_PER_COMPAT_LONG)
#define COMPAT_SYSCALL_DEFINE0(name) \
	asmlinkage long compat_sys_##name(void); \
	ALLOW_ERROR_INJECTION(compat_sys_##name, ERRNO); \
	asmlinkage long compat_sys_##name(void)
#define COMPAT_SYSCALL_DEFINE1(name, ...) \
        COMPAT_SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE2(name, ...) \
	COMPAT_SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE3(name, ...) \
	COMPAT_SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE4(name, ...) \
	COMPAT_SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE5(name, ...) \
	COMPAT_SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE6(name, ...) \
	COMPAT_SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINEx(x, name, ...)					\
	__diag_push();								\
	__diag_ignore(GCC, 8, "-Wattribute-alias",				\
		      "Type aliasing is used to sanitize syscall arguments");\
	asmlinkage long compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))	\
		__attribute__((alias(__stringify(__se_compat_sys##name))));	\
	ALLOW_ERROR_INJECTION(compat_sys##name, ERRNO);				\
	static inline long __do_compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	asmlinkage long __se_compat_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	asmlinkage long __se_compat_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{									\
		long ret = __do_compat_sys##name(__MAP(x,__SC_DELOUSE,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);					\
		return ret;							\
	}									\
	__diag_pop();								\
	static inline long __do_compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))
#define COMPAT_USE_64BIT_TIME 0

#define __COMPAT_ADDR_BND_PKEY_PAD  (__alignof__(compat_uptr_t) < sizeof(short) ? \
				     sizeof(short) : __alignof__(compat_uptr_t))
#define __SC_DELOUSE(t,v) ((__force t)(unsigned long)(v))
#define compat_jiffies_to_clock_t(x)	\
		(((unsigned long)(x) * COMPAT_USER_HZ) / HZ)
#define compat_need_64bit_alignment_fixup()		false
#define compat_user_stack_pointer() current_user_stack_pointer()
#define copy_siginfo_to_user32 __copy_siginfo_to_user32
#define in_compat_syscall in_compat_syscall
#define is_compat_task() (0)
#define unsafe_compat_save_altstack(uss, sp, label) do { \
	compat_stack_t __user *__uss = uss; \
	struct task_struct *t = current; \
	unsafe_put_user(ptr_to_compat((void __user *)t->sas_ss_sp), \
			&__uss->ss_sp, label); \
	unsafe_put_user(t->sas_ss_flags, &__uss->ss_flags, label); \
	unsafe_put_user(t->sas_ss_size, &__uss->ss_size, label); \
} while (0);
#define unsafe_get_compat_sigset(set, compat, label) do {		\
	const compat_sigset_t __user *__c = compat;			\
	compat_sigset_word hi, lo;					\
	sigset_t *__s = set;						\
									\
	switch (_NSIG_WORDS) {						\
	case 4:								\
		unsafe_get_user(lo, &__c->sig[7], label);		\
		unsafe_get_user(hi, &__c->sig[6], label);		\
		__s->sig[3] = hi | (((long)lo) << 32);			\
		fallthrough;						\
	case 3:								\
		unsafe_get_user(lo, &__c->sig[5], label);		\
		unsafe_get_user(hi, &__c->sig[4], label);		\
		__s->sig[2] = hi | (((long)lo) << 32);			\
		fallthrough;						\
	case 2:								\
		unsafe_get_user(lo, &__c->sig[3], label);		\
		unsafe_get_user(hi, &__c->sig[2], label);		\
		__s->sig[1] = hi | (((long)lo) << 32);			\
		fallthrough;						\
	case 1:								\
		unsafe_get_user(lo, &__c->sig[1], label);		\
		unsafe_get_user(hi, &__c->sig[0], label);		\
		__s->sig[0] = hi | (((long)lo) << 32);			\
	}								\
} while (0)
#define unsafe_put_compat_sigset(compat, set, label) do {		\
	compat_sigset_t __user *__c = compat;				\
	const sigset_t *__s = set;					\
									\
	switch (_NSIG_WORDS) {						\
	case 4:								\
		unsafe_put_user(__s->sig[3] >> 32, &__c->sig[7], label);	\
		unsafe_put_user(__s->sig[3], &__c->sig[6], label);	\
		fallthrough;						\
	case 3:								\
		unsafe_put_user(__s->sig[2] >> 32, &__c->sig[5], label);	\
		unsafe_put_user(__s->sig[2], &__c->sig[4], label);	\
		fallthrough;						\
	case 2:								\
		unsafe_put_user(__s->sig[1] >> 32, &__c->sig[3], label);	\
		unsafe_put_user(__s->sig[1], &__c->sig[2], label);	\
		fallthrough;						\
	case 1:								\
		unsafe_put_user(__s->sig[0] >> 32, &__c->sig[1], label);	\
		unsafe_put_user(__s->sig[0], &__c->sig[0], label);	\
	}								\
} while (0)
#define IP4_REPLY_MARK(net, mark) \
	((net)->ipv4.sysctl_fwmark_reflect ? (mark) : 0)
#define IPCB(skb) ((struct inet_skb_parm*)((skb)->cb))
#define IP_ADD_STATS(net, field, val)	SNMP_ADD_STATS64((net)->mib.ip_statistics, field, val)
#define IP_INC_STATS(net, field)	SNMP_INC_STATS64((net)->mib.ip_statistics, field)
#define IP_REPLY_ARG_NOSRCCHECK 1
#define IP_UPD_PO_STATS(net, field, val) SNMP_UPD_PO_STATS64((net)->mib.ip_statistics, field, val)
#define NET_ADD_STATS(net, field, adnd)	SNMP_ADD_STATS((net)->mib.net_statistics, field, adnd)
#define NET_INC_STATS(net, field)	SNMP_INC_STATS((net)->mib.net_statistics, field)
#define PKTINFO_SKB_CB(skb) ((struct in_pktinfo *)((skb)->cb))

#define __IP_ADD_STATS(net, field, val) __SNMP_ADD_STATS64((net)->mib.ip_statistics, field, val)
#define __IP_INC_STATS(net, field)	__SNMP_INC_STATS64((net)->mib.ip_statistics, field)
#define __IP_UPD_PO_STATS(net, field, val) __SNMP_UPD_PO_STATS64((net)->mib.ip_statistics, field, val)
#define __NET_ADD_STATS(net, field, adnd) __SNMP_ADD_STATS((net)->mib.net_statistics, field, adnd)
#define __NET_INC_STATS(net, field)	__SNMP_INC_STATS((net)->mib.net_statistics, field)
#define snmp_get_cpu_field64_batch(buff64, stats_list, mib_statistic, offset) \
{ \
	int i, c; \
	for_each_possible_cpu(c) { \
		for (i = 0; stats_list[i].name; i++) \
			buff64[i] += snmp_get_cpu_field64( \
					mib_statistic, \
					c, stats_list[i].entry, \
					offset); \
	} \
}
#define snmp_get_cpu_field_batch(buff, stats_list, mib_statistic) \
{ \
	int i, c; \
	for_each_possible_cpu(c) { \
		for (i = 0; stats_list[i].name; i++) \
			buff[i] += snmp_get_cpu_field( \
						mib_statistic, \
						c, stats_list[i].entry); \
	} \
}
#define IP6CB(skb)	((struct inet6_skb_parm*)((skb)->cb))
#define IP6CBMTU(skb)	((struct ip6_mtuinfo *)((skb)->cb))
#define IP6SKB_FRAGMENTED      16
#define IP6SKB_HOPBYHOP        32
#define IP6SKB_JUMBOGRAM      128
#define IP6SKB_L3SLAVE         64

#define __ipv6_only_sock(sk)	(sk->sk_ipv6only)
#define inet6_rcv_saddr(__sk)	NULL
#define inet_v6_ipv6only(__sk)		0
#define ipv6_authlen(p) (((p)->hdrlen+2) << 2)
#define ipv6_only_sock(sk)	(__ipv6_only_sock(sk))
#define ipv6_optlen(p)  (((p)->hdrlen+1) << 3)
#define ipv6_sk_rxinfo(sk)	((sk)->sk_family == PF_INET6 && \
				 inet6_sk(sk)->rxopt.bits.rxinfo)
#define tcp_twsk_ipv6only(__sk)		0

#define L3MDEV_TYPE_MAX (__L3MDEV_TYPE_MAX - 1)

#define FRA_GENERIC_POLICY \
	[FRA_UNSPEC]	= { .strict_start_type = FRA_DPORT_RANGE + 1 }, \
	[FRA_IIFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 }, \
	[FRA_OIFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 }, \
	[FRA_PRIORITY]	= { .type = NLA_U32 }, \
	[FRA_FWMARK]	= { .type = NLA_U32 }, \
	[FRA_TUN_ID]	= { .type = NLA_U64 }, \
	[FRA_FWMASK]	= { .type = NLA_U32 }, \
	[FRA_TABLE]     = { .type = NLA_U32 }, \
	[FRA_SUPPRESS_PREFIXLEN] = { .type = NLA_U32 }, \
	[FRA_SUPPRESS_IFGROUP] = { .type = NLA_U32 }, \
	[FRA_GOTO]	= { .type = NLA_U32 }, \
	[FRA_L3MDEV]	= { .type = NLA_U8 }, \
	[FRA_UID_RANGE]	= { .len = sizeof(struct fib_rule_uid_range) }, \
	[FRA_PROTOCOL]  = { .type = NLA_U8 }, \
	[FRA_IP_PROTO]  = { .type = NLA_U8 }, \
	[FRA_SPORT_RANGE] = { .len = sizeof(struct fib_rule_port_range) }, \
	[FRA_DPORT_RANGE] = { .len = sizeof(struct fib_rule_port_range) }

#define EXPORT_INDIRECT_CALLABLE(f)	EXPORT_SYMBOL(f)
#define INDIRECT_CALLABLE_DECLARE(f)	f

#define INDIRECT_CALL_1(f, f1, ...)					\
	({								\
		likely(f == f1) ? f1(__VA_ARGS__) : f(__VA_ARGS__);	\
	})
#define INDIRECT_CALL_2(f, f2, f1, ...)					\
	({								\
		likely(f == f2) ? f2(__VA_ARGS__) :			\
				  INDIRECT_CALL_1(f, f1, __VA_ARGS__);	\
	})
#define INDIRECT_CALL_3(f, f3, f2, f1, ...)					\
	({									\
		likely(f == f3) ? f3(__VA_ARGS__) :				\
				  INDIRECT_CALL_2(f, f2, f1, __VA_ARGS__);	\
	})
#define INDIRECT_CALL_4(f, f4, f3, f2, f1, ...)					\
	({									\
		likely(f == f4) ? f4(__VA_ARGS__) :				\
				  INDIRECT_CALL_3(f, f3, f2, f1, __VA_ARGS__);	\
	})
#define INDIRECT_CALL_INET(f, f2, f1, ...) \
	INDIRECT_CALL_2(f, f2, f1, __VA_ARGS__)
#define INDIRECT_CALL_INET_1(f, f1, ...) INDIRECT_CALL_1(f, f1, __VA_ARGS__)


#define DST_METRICS_PTR(X)	__DST_METRICS_PTR((X)->_metrics)

#define __DST_METRICS_PTR(Y)	\
	((u32 *)((Y) & ~DST_METRICS_FLAGS))
#define LOCALLY_ENQUEUED 0x1
#define NEIGH_CACHE_STAT_INC(tbl, field) this_cpu_inc((tbl)->stats->field)
#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)
#define NEIGH_ENTRY_SIZE(size)	ALIGN((size), NEIGH_PRIV_ALIGN)
#define NEIGH_VAR(p, attr) ((p)->data[NEIGH_VAR_ ## attr])
#define NEIGH_VAR_DATA_MAX (NEIGH_VAR_LOCKTIME + 1)
#define NEIGH_VAR_INIT(p, attr, val) (NEIGH_VAR(p, attr) = val)
#define NEIGH_VAR_SET(p, attr, val) neigh_var_set(p, NEIGH_VAR_ ## attr, val)

#define neigh_hold(n)	refcount_inc(&(n)->refcnt)



#define FLAGS_TS_OR_DROPS ((1UL << SOCK_RXQ_OVFL)			| \
			   (1UL << SOCK_RCVTSTAMP))
#define SK_ALLOC_PERCPU_COUNTER_BATCH 16
#define SK_DEFAULT_STAMP (-1L * NSEC_PER_SEC)
#define SK_FLAGS_TIMESTAMP ((1UL << SOCK_TIMESTAMP) | (1UL << SOCK_TIMESTAMPING_RX_SOFTWARE))
#define SK_MEM_QUANTUM 4096
#define SK_MEM_QUANTUM_SHIFT ilog2(SK_MEM_QUANTUM)
#define SOCK_DEBUG(sk, msg...) do { if ((sk) && sock_flag((sk), SOCK_DBG)) \
					printk(KERN_DEBUG msg); } while (0)

#define SOCK_DESTROY_TIME (10*HZ)
#define SOCK_SKB_CB(__skb) ((struct sock_skb_cb *)((__skb)->cb + \
			    SOCK_SKB_CB_OFFSET))
#define SOCK_SKB_CB_OFFSET ((sizeof_field(struct sk_buff, cb) - \
			    sizeof(struct sock_skb_cb)))

#define __sk_user_data(sk) ((*((void __rcu **)&(sk)->sk_user_data)))
#define bh_lock_sock(__sk)	spin_lock(&((__sk)->sk_lock.slock))
#define bh_lock_sock_nested(__sk) \
				spin_lock_nested(&((__sk)->sk_lock.slock), \
				SINGLE_DEPTH_NESTING)
#define bh_unlock_sock(__sk)	spin_unlock(&((__sk)->sk_lock.slock))
#define rcu_assign_sk_user_data(sk, ptr)				\
({									\
	uintptr_t __tmp = (uintptr_t)(ptr);				\
	WARN_ON_ONCE(__tmp & ~SK_USER_DATA_PTRMASK);			\
	rcu_assign_pointer(__sk_user_data((sk)), __tmp);		\
})
#define rcu_assign_sk_user_data_nocopy(sk, ptr)				\
({									\
	uintptr_t __tmp = (uintptr_t)(ptr);				\
	WARN_ON_ONCE(__tmp & ~SK_USER_DATA_PTRMASK);			\
	rcu_assign_pointer(__sk_user_data((sk)),			\
			   __tmp | SK_USER_DATA_NOCOPY);		\
})
#define rcu_dereference_sk_user_data(sk)				\
({									\
	void *__tmp = rcu_dereference(__sk_user_data((sk)));		\
	(void *)((uintptr_t)__tmp & SK_USER_DATA_PTRMASK);		\
})
#define sk_del_node_init_rcu(sk)	sk_del_node_init(sk)
#define sk_for_each(__sk, list) \
	hlist_for_each_entry(__sk, list, sk_node)
#define sk_for_each_bound(__sk, list) \
	hlist_for_each_entry(__sk, list, sk_bind_node)
#define sk_for_each_entry_offset_rcu(tpos, pos, head, offset)		       \
	for (pos = rcu_dereference(hlist_first_rcu(head));		       \
	     pos != NULL &&						       \
		({ tpos = (typeof(*tpos) *)((void *)pos - offset); 1;});       \
	     pos = rcu_dereference(hlist_next_rcu(pos)))
#define sk_for_each_from(__sk) \
	hlist_for_each_entry_from(__sk, sk_node)
#define sk_for_each_rcu(__sk, list) \
	hlist_for_each_entry_rcu(__sk, list, sk_node)
#define sk_for_each_safe(__sk, tmp, list) \
	hlist_for_each_entry_safe(__sk, tmp, list, sk_node)
#define sk_nulls_for_each(__sk, node, list) \
	hlist_nulls_for_each_entry(__sk, node, list, sk_nulls_node)
#define sk_nulls_for_each_from(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_nulls_node; 1; })) \
		hlist_nulls_for_each_entry_from(__sk, node, sk_nulls_node)
#define sk_nulls_for_each_rcu(__sk, node, list) \
	hlist_nulls_for_each_entry_rcu(__sk, node, list, sk_nulls_node)
#define sk_refcnt_debug_dec(sk) do { } while (0)
#define sk_refcnt_debug_inc(sk) do { } while (0)
#define sk_refcnt_debug_release(sk) do { } while (0)
#define sk_rmem_alloc sk_backlog.rmem_alloc
#define sk_wait_event(__sk, __timeo, __condition, __wait)		\
	({	int __rc;						\
		release_sock(__sk);					\
		__rc = __condition;					\
		if (!__rc) {						\
			*(__timeo) = wait_woken(__wait,			\
						TASK_INTERRUPTIBLE,	\
						*(__timeo));		\
		}							\
		sched_annotate_sleep();					\
		lock_sock(__sk);					\
		__rc = __condition;					\
		__rc;							\
	})
#define sock_edemux sock_efree
#define sock_lock_init_class_and_name(sk, sname, skey, name, key)	\
do {									\
	sk->sk_lock.owned = 0;						\
	init_waitqueue_head(&sk->sk_lock.wq);				\
	spin_lock_init(&(sk)->sk_lock.slock);				\
	debug_check_no_locks_freed((void *)&(sk)->sk_lock,		\
			sizeof((sk)->sk_lock));				\
	lockdep_set_class_and_name(&(sk)->sk_lock.slock,		\
				(skey), (sname));				\
	lockdep_init_map(&(sk)->sk_lock.dep_map, (name), (key), 0);	\
} while (0)
#define sock_skb_cb_check_size(size) \
	BUILD_BUG_ON((size) > SOCK_SKB_CB_OFFSET)

#define hlist_nulls_first_rcu(head) \
	(*((struct hlist_nulls_node __rcu __force **)&(head)->first))
#define hlist_nulls_for_each_entry_rcu(tpos, pos, head, member)			\
	for (({barrier();}),							\
	     pos = rcu_dereference_raw(hlist_nulls_first_rcu(head));		\
		(!is_a_nulls(pos)) &&						\
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1; }); \
		pos = rcu_dereference_raw(hlist_nulls_next_rcu(pos)))
#define hlist_nulls_for_each_entry_safe(tpos, pos, head, member)		\
	for (({barrier();}),							\
	     pos = rcu_dereference_raw(hlist_nulls_first_rcu(head));		\
		(!is_a_nulls(pos)) &&						\
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member);	\
		   pos = rcu_dereference_raw(hlist_nulls_next_rcu(pos)); 1; });)
#define hlist_nulls_next_rcu(node) \
	(*((struct hlist_nulls_node __rcu __force **)&(node)->next))
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

#define IS_UDPLITE(__sk) (__sk->sk_protocol == IPPROTO_UDPLITE)
#define UDPLITE_BIT      0x1  		
#define UDPLITE_RECV_CC  0x4		
#define UDPLITE_SEND_CC  0x2  		

#define udp_portaddr_for_each_entry(__sk, list) \
	hlist_for_each_entry(__sk, list, __sk_common.skc_portaddr_node)
#define udp_portaddr_for_each_entry_rcu(__sk, list) \
	hlist_for_each_entry_rcu(__sk, list, __sk_common.skc_portaddr_node)
#define UDP_NO_CHECK6_RX 102	
#define UDP_NO_CHECK6_TX 101	

#define BPF_SOCK_OPS_TEST_FLAG(TP, ARG) (TP->bpf_sock_ops_cb_flags & ARG)
#define TCP_DSACK_SEEN    (1 << 2)   
#define TCP_FASTOPEN_COOKIE_SIZE 8	
#define TCP_NUM_SACKS 4
#define TCP_RACK_RECOVERY_THRESH 16
#define TCP_SACK_SEEN     (1 << 0)   

#define tw_rcv_nxt tw_sk.__tw_common.skc_tw_rcv_nxt
#define tw_snd_nxt tw_sk.__tw_common.skc_tw_snd_nxt
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
#define TCP_RECEIVE_ZEROCOPY_FLAG_TLB_CLEAN_HINT 0x1
#define TCP_THIN_LINEAR_TIMEOUTS 16	

#define tcp_flag_word(tp) (((union tcp_word_hdr *)(tp))->words[3])

#define tw_daddr        	__tw_common.skc_daddr
#define tw_rcv_saddr    	__tw_common.skc_rcv_saddr
#define tw_tclass tw_tos
#define tw_v6_rcv_saddr    	__tw_common.skc_v6_rcv_saddr




#define ipv6_destopt_hdr ipv6_opt_hdr
#define ipv6_hopopt_hdr  ipv6_opt_hdr
#define LWTUNNEL_HASH_BITS   7
#define LWTUNNEL_HASH_SIZE   (1 << LWTUNNEL_HASH_BITS)
#define MODULE_ALIAS_RTNL_LWT(encap_type) MODULE_ALIAS("rtnl-lwt-" __stringify(encap_type))
#define __NET_LWTUNNEL_H 1
#define RT_CONN_FLAGS(sk)   (RT_TOS(inet_sk(sk)->tos) | sock_flag(sk, SOCK_LOCALROUTE))
#define RT_CONN_FLAGS_TOS(sk,tos)   (RT_TOS(tos) | sock_flag(sk, SOCK_LOCALROUTE))


#define IPOPT_EOL IPOPT_END
#define IPOPT_MINOFF 4
#define IPOPT_NOP IPOPT_NOOP
#define IPOPT_OFFSET 2
#define IPOPT_OLEN   1
#define IPOPT_OPTVAL 0
#define IPOPT_TS  IPOPT_TIMESTAMP
#define IPTOS_PREC(tos)		((tos)&IPTOS_PREC_MASK)
#define IPTOS_PREC_CRITIC_ECP           0xa0
#define IPTOS_PREC_FLASH                0x60
#define IPTOS_PREC_FLASHOVERRIDE        0x80
#define IPTOS_PREC_IMMEDIATE            0x40
#define IPTOS_PREC_INTERNETCONTROL      0xc0
#define IPTOS_PREC_NETCONTROL           0xe0
#define IPTOS_PREC_PRIORITY             0x20
#define IPTOS_PREC_ROUTINE              0x00
#define IPTOS_TOS(tos)		((tos)&IPTOS_TOS_MASK)
#define IPV4_BEET_PHMAXLEN 8
#define IPV4_DEVCONF_MAX (__IPV4_DEVCONF_MAX - 1)
#define MAX_IPOPTLEN 40

#define NDISC_OPT_SPACE(len) (((len)+2+7)&~7)
#define ND_DEBUG 1
#define ND_PRINTK(val, level, fmt, ...)				\
do {								\
	if (val <= ND_DEBUG)					\
		net_##level##_ratelimited(fmt, ##__VA_ARGS__);	\
} while (0)


#define ARPHRD_BIF      775             
#define ARPHRD_DDCMP    517		
#define ARPHRD_ETHER 	1		
#define ARPHRD_IEEE80211 801		
#define ARPHRD_IEEE80211_PRISM 802	
#define ARPHRD_IEEE80211_RADIOTAP 803	
#define ARPHRD_IEEE802154_MONITOR 805	
#define ARPHRD_IEEE802_TR 800		
#define ARPHRD_INFINIBAND 32		
#define ARPHRD_IRDA 	783		
#define ARPHRD_LOCALTLK 773		
#define ARPHRD_PHONET_PIPE 821		
#define ARPHRD_RAWIP    519		
#define ATF_NETMASK     0x20            




#define FIB_RES_DEV(res)	(FIB_RES_NHC(res)->nhc_dev)
#define FIB_RES_NHC(res)		((res).nhc)
#define FIB_RES_OIF(res)	(FIB_RES_NHC(res)->nhc_oif)
#define FIB_TABLE_HASHSZ 256

#define fib_advmss fib_metrics->metrics[RTAX_ADVMSS-1]
#define fib_mtu fib_metrics->metrics[RTAX_MTU-1]
#define fib_rtt fib_metrics->metrics[RTAX_RTT-1]
#define fib_window fib_metrics->metrics[RTAX_WINDOW-1]
#define INETPEER_MAXKEYSZ   (sizeof(struct in6_addr) / sizeof(u32))

#define ICMP6MSGIN_INC_STATS(net, idev, field)	\
	_DEVINC_ATOMIC_ATOMIC(net, icmpv6msg, idev, field)
#define ICMP6MSGOUT_INC_STATS(net, idev, field)		\
	_DEVINC_ATOMIC_ATOMIC(net, icmpv6msg, idev, field +256)
#define ICMP6_INC_STATS(net, idev, field)	\
		_DEVINCATOMIC(net, icmpv6, , idev, field)
#define IP6_ADD_STATS(net, idev,field,val)	\
		_DEVADD(net, ipv6, , idev, field, val)
#define IP6_INC_STATS(net, idev,field)		\
		_DEVINC(net, ipv6, , idev, field)
#define IP6_REPLY_MARK(net, mark) \
	((net)->ipv6.sysctl.fwmark_reflect ? (mark) : 0)
#define IP6_UPD_PO_STATS(net, idev,field,val)   \
		_DEVUPD(net, ipv6, , idev, field, val)
#define IPV6_ADDR_MC_FLAG_PREFIX(a)	\
	((a)->s6_addr[1] & 0x20)
#define IPV6_ADDR_MC_FLAG_RENDEZVOUS(a)	\
	((a)->s6_addr[1] & 0x40)
#define IPV6_ADDR_MC_FLAG_TRANSIENT(a)	\
	((a)->s6_addr[1] & 0x10)
#define IPV6_ADDR_MC_SCOPE(a)	\
	((a)->s6_addr[1] & 0x0f)	
#define IPV6_DEFAULT_HOPLIMIT   64
#define IPV6_TCLASS_MASK (IPV6_FLOWINFO_MASK & ~IPV6_FLOWLABEL_MASK)
#define _DEVADD(net, statname, mod, idev, field, val)			\
({									\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		mod##SNMP_ADD_STATS((_idev)->stats.statname, (field), (val)); \
	mod##SNMP_ADD_STATS((net)->mib.statname##_statistics, (field), (val));\
})
#define _DEVINC(net, statname, mod, idev, field)			\
({									\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		mod##SNMP_INC_STATS64((_idev)->stats.statname, (field));\
	mod##SNMP_INC_STATS64((net)->mib.statname##_statistics, (field));\
})
#define _DEVINCATOMIC(net, statname, mod, idev, field)			\
({									\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		SNMP_INC_STATS_ATOMIC_LONG((_idev)->stats.statname##dev, (field)); \
	mod##SNMP_INC_STATS((net)->mib.statname##_statistics, (field));\
})
#define _DEVINC_ATOMIC_ATOMIC(net, statname, idev, field)		\
({									\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		SNMP_INC_STATS_ATOMIC_LONG((_idev)->stats.statname##dev, (field)); \
	SNMP_INC_STATS_ATOMIC_LONG((net)->mib.statname##_statistics, (field));\
})
#define _DEVUPD(net, statname, mod, idev, field, val)			\
({									\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		mod##SNMP_UPD_PO_STATS((_idev)->stats.statname, field, (val)); \
	mod##SNMP_UPD_PO_STATS((net)->mib.statname##_statistics, field, (val));\
})

#define __ICMP6_INC_STATS(net, idev, field)	\
		_DEVINCATOMIC(net, icmpv6, __, idev, field)
#define __IP6_ADD_STATS(net, idev,field,val)	\
		_DEVADD(net, ipv6, __, idev, field, val)
#define __IP6_INC_STATS(net, idev,field)	\
		_DEVINC(net, ipv6, __, idev, field)
#define __IP6_UPD_PO_STATS(net, idev,field,val)   \
		_DEVUPD(net, ipv6, __, idev, field, val)

#define FASTRETRANS_DEBUG 1
#define MAX_TCP_OPTION_SPACE 40
#define MODULE_ALIAS_TCP_ULP(name)				\
	__MODULE_INFO(alias, alias_userspace, name);		\
	__MODULE_INFO(alias, alias_tcp_ulp, "tcp-ulp-" name)
#define TCPHDR_ACK 0x10
#define TCPHDR_CWR 0x80
#define TCPHDR_ECE 0x40
#define TCPHDR_FIN 0x01
#define TCPHDR_PSH 0x08
#define TCPHDR_RST 0x04
#define TCPHDR_SYN 0x02
#define TCPHDR_URG 0x20
#define TCPOLEN_EXP_FASTOPEN_BASE  4
#define TCPOLEN_EXP_SMC_BASE   6
#define TCPOLEN_FASTOPEN_BASE  2
#define TCPOLEN_MD5SIG         18
#define TCPOLEN_MSS            4
#define TCPOLEN_SACK_PERM      2
#define TCPOLEN_TIMESTAMP      10
#define TCPOLEN_WINDOW         3
#define TCPOPT_SACK             5       
#define TCPOPT_SACK_PERM        4       
#define TCP_ADD_STATS(net, field, val)	SNMP_ADD_STATS((net)->mib.tcp_statistics, field, val)
#define TCP_CONG_NON_RESTRICTED 0x1
#define TCP_DEC_STATS(net, field)	SNMP_DEC_STATS((net)->mib.tcp_statistics, field)
#define TCP_FASTOPEN_KEY_BUF_LENGTH \
	(TCP_FASTOPEN_KEY_LENGTH * TCP_FASTOPEN_KEY_MAX)
#define TCP_FASTOPEN_KEY_LENGTH sizeof(siphash_key_t)
#define TCP_FASTOPEN_KEY_MAX 2
#define TCP_FASTRETRANS_THRESH 3
#define TCP_FIN_TIMEOUT_MAX (120 * HZ) 
#define TCP_INC_STATS(net, field)	SNMP_INC_STATS((net)->mib.tcp_statistics, field)
#define TCP_RACK_LOSS_DETECTION  0x1 
#define TCP_RACK_NO_DUPTHRESH    0x4 
#define TCP_RACK_STATIC_REO_WND  0x2 
#define TCP_RESOURCE_PROBE_INTERVAL ((unsigned)(HZ/2U)) 
#define TCP_SKB_CB(__skb)	((struct tcp_skb_cb *)&((__skb)->cb[0]))
#define TCP_SYNACK_RETRIES 5	
#define TCP_THIN_LINEAR_RETRIES 6       
#define TCP_TIMEOUT_FALLBACK ((unsigned)(3*HZ))	
#define TCP_TIMEOUT_INIT ((unsigned)(1*HZ))	
#define TCP_TIMEWAIT_LEN (60*HZ) 

#define __TCP_INC_STATS(net, field)	__SNMP_INC_STATS((net)->mib.tcp_statistics, field)
#define after(seq2, seq1) 	before(seq1, seq2)
#define tcp_flag_byte(th) (((u_int8_t *)th)[13])
#define tcp_for_write_queue_from_safe(skb, tmp, sk)			\
	skb_queue_walk_from_safe(&(sk)->sk_write_queue, skb, tmp)
#define tcp_jiffies32 ((u32)jiffies)
#define tcp_skb_tsorted_restore(skb)		\
	skb->_skb_refdst = _save;		\
}
#define tcp_skb_tsorted_save(skb) {		\
	unsigned long _save = skb->_skb_refdst;	\
	skb->_skb_refdst = 0UL;
#define tcp_twsk_md5_key(twsk)	((twsk)->tw_md5_key)
#define tcp_verify_left_out(tp)	WARN_ON(tcp_left_out(tp) > tp->packets_out)

#define IP6_ECN_flow_init(label) do {		\
      (label) &= ~htonl(INET_ECN_MASK << 20);	\
    } while (0)



#define INET_ADDR_COOKIE(__name, __saddr, __daddr) \
	const __addrpair __name = (__force __addrpair) ( \
				   (((__force __u64)(__be32)(__saddr)) << 32) | \
				   ((__force __u64)(__be32)(__daddr)))
#define INET_COMBINED_PORTS(__sport, __dport) \
	((__force __portpair)(((__force __u32)(__be16)(__sport) << 16) | (__u32)(__dport)))
#define INET_MATCH(__sk, __net, __cookie, __saddr, __daddr, __ports, __dif, __sdif) \
	(((__sk)->sk_portpair == (__ports))			&&	\
	 ((__sk)->sk_addrpair == (__cookie))			&&	\
	 (((__sk)->sk_bound_dev_if == (__dif))			||	\
	  ((__sk)->sk_bound_dev_if == (__sdif)))		&&	\
	 net_eq(sock_net(__sk), (__net)))
#define LISTENING_NULLS_BASE (1U << 29)

#define inet_bind_bucket_for_each(tb, head) \
	hlist_for_each_entry(tb, head, node)
#define inet_lhash2_for_each_icsk(__icsk, list) \
	hlist_for_each_entry(__icsk, list, icsk_listen_portaddr_node)
#define inet_lhash2_for_each_icsk_continue(__icsk) \
	hlist_for_each_entry_continue(__icsk, icsk_listen_portaddr_node)
#define inet_lhash2_for_each_icsk_rcu(__icsk, list) \
	hlist_for_each_entry_rcu(__icsk, list, icsk_listen_portaddr_node)

#define __ETHTOOL_DECLARE_LINK_MODE_MASK(name)		\
	DECLARE_BITMAP(name, __ETHTOOL_LINK_MODE_MASK_NBITS)
#define __ETH_RSS_HASH(name)	__ETH_RSS_HASH_BIT(ETH_RSS_HASH_##name##_BIT)
#define __ETH_RSS_HASH_BIT(bit)	((u32)1 << (bit))
#define ethtool_link_ksettings_add_link_mode(ptr, name, mode)		\
	__set_bit(ETHTOOL_LINK_MODE_ ## mode ## _BIT, (ptr)->link_modes.name)
#define ethtool_link_ksettings_del_link_mode(ptr, name, mode)		\
	__clear_bit(ETHTOOL_LINK_MODE_ ## mode ## _BIT, (ptr)->link_modes.name)
#define ethtool_link_ksettings_test_link_mode(ptr, name, mode)		\
	test_bit(ETHTOOL_LINK_MODE_ ## mode ## _BIT, (ptr)->link_modes.name)
#define ethtool_link_ksettings_zero_link_mode(ptr, name)		\
	bitmap_zero((ptr)->link_modes.name, __ETHTOOL_LINK_MODE_MASK_NBITS)
#define ETHTOOL_F_COMPAT        (1 << ETHTOOL_F_COMPAT__BIT)
#define ETHTOOL_F_UNSUPPORTED   (1 << ETHTOOL_F_UNSUPPORTED__BIT)
#define ETHTOOL_F_WISH          (1 << ETHTOOL_F_WISH__BIT)
#define ETHTOOL_RX_FLOW_SPEC_RING_VF_OFF 32
#define ETH_FW_DUMP_DISABLE 0
#define ETH_MODULE_SFF_8436_MAX_LEN     640
#define ETH_MODULE_SFF_8636_MAX_LEN     640

#define __ETHTOOL_LINK_MODE_LEGACY_MASK(base_name)	\
	(1UL << (ETHTOOL_LINK_MODE_ ## base_name ## _BIT))
