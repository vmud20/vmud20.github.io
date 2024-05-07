

#include<sys/fcntl.h>




#include<sys/cdefs.h>
#include<sys/types.h>

#include<sys/signal.h>



#include<sys/queue.h>









#include<sys/param.h>





#include<sys/time.h>

#include<sys/select.h>









#include<sys/uio.h>







#include<sys/resource.h>














#define UMA_SMALLEST_UNIT       (PAGE_SIZE / 256) 
#define	UMA_STREAM_VERSION	0x00000001
#define	UMA_ZONE_CACHESPREAD	0x1000	
#define	UMA_ZONE_HASH		0x0100	
#define	UMA_ZONE_INHERIT						\
    (UMA_ZONE_OFFPAGE | UMA_ZONE_MALLOC | UMA_ZONE_HASH |		\
    UMA_ZONE_REFCNT | UMA_ZONE_VTOSLAB)
#define	UMA_ZONE_MAXBUCKET	0x0800	
#define	UMA_ZONE_REFCNT		0x0400	
#define	UMA_ZONE_SECONDARY	0x0200	
#define	UMA_ZONE_VM		0x0080	
#define	UMA_ZONE_VTOSLAB	0x2000	
#define	UTH_MAX_NAME	32
#define	UTH_ZONE_SECONDARY	0x00000001

#define	MALLOC_MAX_NAME	32
#define	MALLOC_TYPE_STREAM_VERSION	0x00000001
#define	MINALLOCSIZE	UMA_SMALLEST_UNIT
#define	M_MAGIC		877983977	
#define	M_NOVM		0x0200		
#define	M_NOWAIT	0x0001		
#define	M_USE_RESERVE	0x0400		
#define	M_WAITOK	0x0002		
#define	M_ZERO		0x0100		
#define LIST_SWAP(head1, head2, type, field) do {			\
	struct type *swap_tmp = LIST_FIRST((head1));			\
	LIST_FIRST((head1)) = LIST_FIRST((head2));			\
	LIST_FIRST((head2)) = swap_tmp;					\
	if ((swap_tmp = LIST_FIRST((head1))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head1));		\
	if ((swap_tmp = LIST_FIRST((head2))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head2));		\
} while (0)
#define SLIST_REMOVE_AFTER(elm, field) do {				\
	SLIST_NEXT(elm, field) =					\
	    SLIST_NEXT(SLIST_NEXT(elm, field), field);			\
} while (0)
#define SLIST_SWAP(head1, head2, type) do {				\
	struct type *swap_first = SLIST_FIRST(head1);			\
	SLIST_FIRST(head1) = SLIST_FIRST(head2);			\
	SLIST_FIRST(head2) = swap_first;				\
} while (0)
#define STAILQ_REMOVE_AFTER(head, elm, field) do {			\
	if ((STAILQ_NEXT(elm, field) =					\
	     STAILQ_NEXT(STAILQ_NEXT(elm, field), field)) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
} while (0)
#define STAILQ_SWAP(head1, head2, type) do {				\
	struct type *swap_first = STAILQ_FIRST(head1);			\
	struct type **swap_last = (head1)->stqh_last;			\
	STAILQ_FIRST(head1) = STAILQ_FIRST(head2);			\
	(head1)->stqh_last = (head2)->stqh_last;			\
	STAILQ_FIRST(head2) = swap_first;				\
	(head2)->stqh_last = swap_last;					\
	if (STAILQ_EMPTY(head1))					\
		(head1)->stqh_last = &STAILQ_FIRST(head1);		\
	if (STAILQ_EMPTY(head2))					\
		(head2)->stqh_last = &STAILQ_FIRST(head2);		\
} while (0)
#define TAILQ_SWAP(head1, head2, type, field) do {			\
	struct type *swap_first = (head1)->tqh_first;			\
	struct type **swap_last = (head1)->tqh_last;			\
	(head1)->tqh_first = (head2)->tqh_first;			\
	(head1)->tqh_last = (head2)->tqh_last;				\
	(head2)->tqh_first = swap_first;				\
	(head2)->tqh_last = swap_last;					\
	if ((swap_first = (head1)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head1)->tqh_first;	\
	else								\
		(head1)->tqh_last = &(head1)->tqh_first;		\
	if ((swap_first = (head2)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head2)->tqh_first;	\
	else								\
		(head2)->tqh_last = &(head2)->tqh_first;		\
} while (0)
#define	TRACEBUF	struct qm_trace trace;
#define	_POSIX_C_SOURCE		199009
#define	__BEGIN_DECLS	extern "C" {
#define	__BSD_VISIBLE		0
#define __CC_SUPPORTS_DYNAMIC_ARRAY_INIT 1
#define __CC_SUPPORTS_INLINE 1
#define __CC_SUPPORTS_VARADIC_XXX 1 
#define __CC_SUPPORTS_WARNING 1
#define __CC_SUPPORTS___FUNC__ 1
#define __CC_SUPPORTS___INLINE 1
#define __CC_SUPPORTS___INLINE__ 1
#define	__END_DECLS	}
#define __GNUCLIKE_ASM 3
#define __GNUCLIKE_BUILTIN_CONSTANT_P 1
#define __GNUCLIKE_BUILTIN_MEMCPY 1
# define __GNUCLIKE_BUILTIN_NEXT_ARG 1
# define __GNUCLIKE_BUILTIN_STDARG 1
# define __GNUCLIKE_BUILTIN_VAALIST 1
# define __GNUCLIKE_BUILTIN_VARARGS 1
# define __GNUCLIKE_CTOR_SECTION_HANDLING 1

# define __GNUCLIKE_MATH_BUILTIN_RELOPS
#define __GNUCLIKE___OFFSETOF 1
#define __GNUCLIKE___SECTION 1
#define __GNUCLIKE___TYPEOF 1
# define __GNUC_VA_LIST_COMPATIBILITY 1
#define	__ISO_C_VISIBLE		1999
#define	__POSIX_VISIBLE		200809
#define	__XSI_VISIBLE		700
#define __aligned(x)	__attribute__((__aligned__(x)))
#define	__always_inline	__attribute__((__always_inline__))
#define	__const		const		
#define	__dead2		__attribute__((__noreturn__))
#define	__exported	__attribute__((__visibility__("default")))
#define	__func__	NULL
#define	__hidden	__attribute__((__visibility__("hidden")))
#define	__inline	inline		
#define	__malloc_like	__attribute__((__malloc__))
#define	__noinline	__attribute__ ((__noinline__))
#define __nonnull(x)	__attribute__((__nonnull__(x)))
#define __offsetof(type, field)	 __builtin_offsetof(type, field)
#define	__packed	__attribute__((__packed__))
#define __predict_false(exp)    __builtin_expect((exp), 0)
#define __predict_true(exp)     __builtin_expect((exp), 1)
#define	__pure		__attribute__((__pure__))
#define	__pure2		__attribute__((__const__))
#define	__restrict	restrict
#define __section(x)	__attribute__((__section__(x)))
#define	__signed	signed
#define	__unused	__attribute__((__unused__))
#define	__used		__attribute__((__used__))
#define	__volatile	volatile
#define	const				
#define BLKDEV_IOSIZE  PAGE_SIZE	
#define	BSD	199506		
#define	CMASK	022		
#define	DEV_BSHIFT	9		
#define	DEV_BSIZE	(1<<DEV_BSHIFT)
#define	FALSE	0
#define	FSHIFT	11		
#define	MAXCOMLEN	19		
#define	MAXINTERP	PATH_MAX	
#define	MAXLOGNAME	17		
#define	MAXPATHLEN	PATH_MAX
#define	MAXUPRC		CHILD_MAX	
#define	MJUM16BYTES	(16 * 1024)	
#define	MJUM9BYTES	(9 * 1024)	
#define	MJUMPAGESIZE	MCLBYTES
#define	NBBY	8		
#define	NBPW	sizeof(int)	
#define	NCARGS		ARG_MAX		
#define	NGROUPS		(NGROUPS_MAX+1)	
#define	NODEV	(dev_t)(-1)	
#define	NOFILE		OPEN_MAX	
#define	NOGROUP		65535		
#define	NZERO	0		
#define	PBDRY	0x400	
#define	PCATCH	0x100		
#define	PDROP	0x200	
#define	PRIMASK	0x0ff
#define	P_OSREL_MAP_ANON	800104
#define	P_OSREL_SIGSEGV		700004
#define	TRUE	1

#define __FreeBSD_version 1000000	
#define __PAST_END(array, offset) (((typeof(*(array)) *)(array))[offset])
#define btoc(x)	(((vm_offset_t)(x)+PAGE_MASK)>>PAGE_SHIFT)
#define btodb(bytes)	 		 \
	(sizeof (bytes) > sizeof(long) \
	 ? (daddr_t)((unsigned long long)(bytes) >> DEV_BSHIFT) \
	 : (daddr_t)((unsigned long)(bytes) >> DEV_BSHIFT))
#define ctob(x)	((x)<<PAGE_SHIFT)
#define ctodb(db)			 \
	((db) << (PAGE_SHIFT - DEV_BSHIFT))
#define dbtob(db)			 \
	((off_t)(db) << DEV_BSHIFT)
#define dbtoc(db)			 \
	((db + (ctodb(1) - 1)) >> (PAGE_SHIFT - DEV_BSHIFT))
#define powerof2(x)	((((x)-1)&(x))==0)
#define	CHAR_BIT	__CHAR_BIT	
#define	CHAR_MAX	UCHAR_MAX	
#define	CHAR_MIN	0		
#define	GID_MAX		UINT_MAX	
#define	INT_MAX		__INT_MAX	
#define	INT_MIN		__INT_MIN	
#define	LLONG_MAX	__LLONG_MAX	
#define	LLONG_MIN	__LLONG_MIN	
#define	LONG_BIT	__LONG_BIT
#define	LONG_MAX	__LONG_MAX	
#define	LONG_MIN	__LONG_MIN	
#define	MQ_PRIO_MAX	64
#define	OFF_MAX		__OFF_MAX	
#define	OFF_MIN		__OFF_MIN	
#define	QUAD_MAX	(__QUAD_MAX)	
#define	QUAD_MIN	(__QUAD_MIN)	
#define	SCHAR_MAX	__SCHAR_MAX	
#define	SCHAR_MIN	__SCHAR_MIN	
#define	SHRT_MAX	__SHRT_MAX	
#define	SHRT_MIN	__SHRT_MIN	
#define	SIZE_T_MAX	__SIZE_T_MAX	
#define	SSIZE_MAX	__SSIZE_MAX	
#define	UCHAR_MAX	__UCHAR_MAX	
#define	UID_MAX		UINT_MAX	
#define	UINT_MAX	__UINT_MAX	
#define	ULLONG_MAX	__ULLONG_MAX	
#define	ULONG_MAX	__ULONG_MAX	
#define	UQUAD_MAX	(__UQUAD_MAX)	
#define	USHRT_MAX	__USHRT_MAX	
#define	WORD_BIT	__WORD_BIT
#define	BADSIG		SIG_ERR
#define ILL_BADSTK 	8	
#define ILL_COPROC 	7	
#define ILL_ILLADR 	3	
#define ILL_ILLOPC 	1	
#define ILL_ILLOPN 	2	
#define ILL_ILLTRP 	4	
#define ILL_PRVOPC 	5	
#define ILL_PRVREG 	6	
#define	MINSIGSTKSZ	__MINSIGSTKSZ		
#define	NSIG		32	
#define	SA_NOCLDSTOP	0x0008	
#define	SA_NOCLDWAIT	0x0020	
#define	SA_NODEFER	0x0010	
#define	SA_ONSTACK	0x0001	
#define	SA_RESETHAND	0x0004	
#define	SA_RESTART	0x0002	
#define	SA_SIGINFO	0x0040	
#define	SIGABRT		6	
#define	SIGALRM		14	
#define	SIGBUS		10	
#define	SIGCHLD		20	
#define	SIGCONT		19	
#define	SIGEMT		7	
#define	SIGEV_KEVENT	3		
#define	SIGEV_NONE	0		
#define	SIGEV_SIGNAL	1		
#define	SIGEV_THREAD	2		
#define	SIGEV_THREAD_ID	4		
#define	SIGFPE		8	
#define	SIGHUP		1	
#define	SIGILL		4	
#define	SIGINFO		29	
#define	SIGINT		2	
#define	SIGIO		23	
#define	SIGIOT		SIGABRT	
#define	SIGKILL		9	
#define	SIGLWP		SIGTHR
#define	SIGPIPE		13	
#define	SIGPROF		27	
#define	SIGQUIT		3	
#define	SIGRTMAX	126
#define	SIGRTMIN	65
#define	SIGSEGV		11	
#define	SIGSTKSZ	(MINSIGSTKSZ + 32768)	
#define	SIGSTOP		17	
#define	SIGSYS		12	
#define	SIGTERM		15	
#define	SIGTHR		32	
#define	SIGTRAP		5	
#define	SIGTSTP		18	
#define	SIGTTIN		21	
#define	SIGTTOU		22	
#define	SIGURG		16	
#define	SIGUSR1		30	
#define	SIGUSR2		31	
#define	SIGVTALRM	26	
#define	SIGWINCH	28	
#define	SIGXCPU		24	
#define	SIGXFSZ		25	
#define	SIG_BLOCK	1	
#define	SIG_DFL		((__sighandler_t *)0)
#define	SIG_ERR		((__sighandler_t *)-1)
#define SIG_HOLD        ((__sighandler_t *)3)
#define	SIG_IGN		((__sighandler_t *)1)
#define	SIG_SETMASK	3	
#define	SIG_UNBLOCK	2	
#define	SI_ASYNCIO	0x10004		
#define	SI_KERNEL	0x10006
#define	SI_LWP		0x10007		
#define	SI_MESGQ	0x10005		
#define	SI_NOINFO	0		
#define	SI_QUEUE	0x10002		
#define	SI_TIMER	0x10003		
#define	SI_UNDEFINED	0
#define	SI_USER		0x10001		
#define	SS_DISABLE	0x0004	
#define	SS_ONSTACK	0x0001	
#define	SV_INTERRUPT	SA_RESTART	
#define	SV_NOCLDSTOP	SA_NOCLDSTOP
#define	SV_NODEFER	SA_NODEFER
#define	SV_ONSTACK	SA_ONSTACK
#define	SV_RESETHAND	SA_RESETHAND
#define	SV_SIGINFO	SA_SIGINFO
#define	TRAP_DTRACE	3	
#define	sa_handler	__sigaction_u.__sa_handler
#define	sa_sigaction	__sigaction_u.__sa_sigaction
#define	sigev_notify_attributes		_sigev_un._sigev_thread._attribute
#define	sigev_notify_function		_sigev_un._sigev_thread._function
#define	sigev_notify_kqueue		sigev_signo
#define	sigev_notify_thread_id		_sigev_un._threadid
#define	sv_onstack	sv_flags	
#define	_SIG_MAXSIG	128
#define	_SIG_WORDS	4

#define	PINOD			(PRI_MIN_KERN + 8)
#define	PI_AV			(PRI_MIN_ITHD + 4)
#define	PI_DISK			(PRI_MIN_ITHD + 12)
#define	PI_DULL			(PRI_MIN_ITHD + 20)
#define	PI_NET			(PRI_MIN_ITHD + 8)
#define	PI_REALTIME		(PRI_MIN_ITHD + 0)
#define	PI_SOFT			(PRI_MIN_ITHD + 24)
#define	PI_TTY			(PRI_MIN_ITHD + 16)
#define	PLOCK			(PRI_MIN_KERN + 32)
#define	PPAUSE			(PRI_MIN_KERN + 36)
#define	PRIBIO			(PRI_MIN_KERN + 12)
#define	PRI_FIFO		(PRI_FIFO_BIT | PRI_REALTIME)
#define	PRI_FIFO_BIT		8
#define	PRI_IDLE		4	
#define	PRI_ITHD		1	
#define	PRI_MAX			(255)		
#define	PRI_MAX_IDLE		(PRI_MAX)
#define	PRI_MAX_ITHD		(PRI_MIN_REALTIME - 1)
#define	PRI_MAX_KERN		(PRI_MIN_TIMESHARE - 1)
#define	PRI_MAX_REALTIME	(PRI_MIN_KERN - 1)
#define	PRI_MAX_TIMESHARE	(PRI_MIN_IDLE - 1)
#define	PRI_MIN			(0)		
#define	PRI_MIN_IDLE		(224)
#define	PRI_MIN_ITHD		(PRI_MIN)
#define	PRI_MIN_KERN		(80)
#define	PRI_MIN_REALTIME	(48)
#define	PRI_MIN_TIMESHARE	(120)
#define	PRI_REALTIME		2	
#define	PRI_TIMESHARE		3	
#define	PRI_UNCHANGED	-1	
#define	PRI_USER	-2	
#define	PSOCK			(PRI_MIN_KERN + 24)
#define	PSWP			(PRI_MIN_KERN + 0)
#define	PUSER			(PRI_MIN_TIMESHARE)
#define	PVFS			(PRI_MIN_KERN + 16)
#define	PVM			(PRI_MIN_KERN + 4)
#define	PWAIT			(PRI_MIN_KERN + 28)
#define	PZERO			(PRI_MIN_KERN + 20)

#define	DST_AUST	2	
#define	DST_CAN		6	
#define	DST_EET		5	
#define	DST_MET		4	
#define	DST_NONE	0	
#define	DST_USA		1	
#define	DST_WET		3	
#define	ITIMER_PROF	2
#define	ITIMER_REAL	0
#define	ITIMER_VIRTUAL	1

#define timeradd(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;	\
		if ((vvp)->tv_usec >= 1000000) {			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_usec -= 1000000;			\
		}							\
	} while (0)
#define timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)
#define timespecadd(vvp, uvp)						\
	do {								\
		(vvp)->tv_sec += (uvp)->tv_sec;				\
		(vvp)->tv_nsec += (uvp)->tv_nsec;			\
		if ((vvp)->tv_nsec >= 1000000000) {			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_nsec -= 1000000000;			\
		}							\
	} while (0)
#define timespecsub(vvp, uvp)						\
	do {								\
		(vvp)->tv_sec -= (uvp)->tv_sec;				\
		(vvp)->tv_nsec -= (uvp)->tv_nsec;			\
		if ((vvp)->tv_nsec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_nsec += 1000000000;			\
		}							\
	} while (0)
#define	FD_SETSIZE	1024U
#define	NFDBITS		_NFDBITS
#define	_NFDBITS	(sizeof(__fd_mask) * 8)	
#define	fds_bits	__fds_bits


#define offsetof(type, field) __offsetof(type, field)


#define	E2BIG		7		
#define	EACCES		13		
#define	EADDRINUSE	48		
#define	EADDRNOTAVAIL	49		
#define	EAFNOSUPPORT	47		
#define	EAGAIN		35		
#define	EALREADY	37		
#define	EAUTH		80		
#define	EBADF		9		
#define	EBADMSG		89		
#define	EBADRPC		72		
#define	EBUSY		16		
#define	ECANCELED	85		
#define	ECAPMODE	94		
#define	ECHILD		10		
#define	ECONNABORTED	53		
#define	ECONNREFUSED	61		
#define	ECONNRESET	54		
#define	EDEADLK		11		
#define	EDESTADDRREQ	39		
#define	EDIRIOCTL	(-4)		
#define	EDOM		33		
#define	EDOOFUS		88		
#define	EDQUOT		69		
#define	EEXIST		17		
#define	EFAULT		14		
#define	EFBIG		27		
#define	EFTYPE		79		
#define	EHOSTDOWN	64		
#define	EHOSTUNREACH	65		
#define	EIDRM		82		
#define	EILSEQ		86		
#define	EINPROGRESS	36		
#define	EINTR		4		
#define	EINVAL		22		
#define	EIO		5		
#define	EISCONN		56		
#define	EISDIR		21		
#define	EJUSTRETURN	(-2)		
#define	ELAST		94		
#define	ELOOP		62		
#define	EMFILE		24		
#define	EMLINK		31		
#define	EMSGSIZE	40		
#define	EMULTIHOP	90		
#define	ENAMETOOLONG	63		
#define	ENEEDAUTH	81		
#define	ENETDOWN	50		
#define	ENETRESET	52		
#define	ENETUNREACH	51		
#define	ENFILE		23		
#define	ENOATTR		87		
#define	ENOBUFS		55		
#define	ENODEV		19		
#define	ENOENT		2		
#define	ENOEXEC		8		
#define	ENOIOCTL	(-3)		
#define	ENOLCK		77		
#define	ENOLINK		91		
#define	ENOMEM		12		
#define	ENOMSG		83		
#define	ENOPROTOOPT	42		
#define	ENOSPC		28		
#define	ENOSYS		78		
#define	ENOTBLK		15		
#define	ENOTCAPABLE	93		
#define	ENOTCONN	57		
#define	ENOTDIR		20		
#define	ENOTEMPTY	66		
#define	ENOTSOCK	38		
#define	ENOTSUP		EOPNOTSUPP	
#define	ENOTTY		25		
#define	ENXIO		6		
#define	EOPNOTSUPP	45		
#define	EOVERFLOW	84		
#define	EPERM		1		
#define	EPFNOSUPPORT	46		
#define	EPIPE		32		
#define	EPROCLIM	67		
#define	EPROCUNAVAIL	76		
#define	EPROGMISMATCH	75		
#define	EPROGUNAVAIL	74		
#define	EPROTO		92		
#define	EPROTONOSUPPORT	43		
#define	EPROTOTYPE	41		
#define	ERANGE		34		
#define	EREMOTE		71		
#define	ERESTART	(-1)		
#define	EROFS		30		
#define	ERPCMISMATCH	73		
#define	ESHUTDOWN	58		
#define	ESOCKTNOSUPPORT	44		
#define	ESPIPE		29		
#define	ESRCH		3		
#define	ESTALE		70		
#define	ETIMEDOUT	60		
#define	ETOOMANYREFS	59		
#define	ETXTBSY		26		
#define	EUSERS		68		
#define	EWOULDBLOCK	EAGAIN		
#define	EXDEV		18		

#define	errno		(* __error())
#define	ARG_MAX			262144	
#define	CHILD_MAX		   40	
#define	IOV_MAX			 1024	
#define	LINK_MAX		32767	
#define	MAX_CANON		  255	
#define	MAX_INPUT		  255	
#define	NAME_MAX		  255	
#define	NGROUPS_MAX	 	 1023	
#define	OPEN_MAX		   64	
#define	PATH_MAX		 1024	
#define	PIPE_BUF		  512	

#define	NULL	((void *)0)
#define	ACL_ADD_FILE		0x00000010
#define	ACL_ADD_SUBDIRECTORY	0x00000020
#define	ACL_APPEND_DATA		0x00000020
#define	ACL_BRAND_NFS4		2
#define	ACL_BRAND_POSIX		1
#define	ACL_BRAND_UNKNOWN	0
#define	ACL_DELETE		0x00000800
#define	ACL_DELETE_CHILD	0x00000100
#define	ACL_ENTRY_DIRECTORY_INHERIT	0x0002
#define	ACL_ENTRY_FAILED_ACCESS		0x0020
#define	ACL_ENTRY_FILE_INHERIT		0x0001
#define	ACL_ENTRY_INHERIT_ONLY		0x0008
#define	ACL_ENTRY_NO_PROPAGATE_INHERIT	0x0004
#define	ACL_ENTRY_SUCCESSFUL_ACCESS	0x0010
#define	ACL_ENTRY_TYPE_ALARM	0x0800
#define	ACL_ENTRY_TYPE_ALLOW	0x0100
#define	ACL_ENTRY_TYPE_AUDIT	0x0400
#define	ACL_ENTRY_TYPE_DENY	0x0200
#define	ACL_EVERYONE		0x00000040
#define	ACL_EXECUTE		0x0001
#define	ACL_FIRST_ENTRY		0
#define	ACL_FLAGS_BITS			(ACL_ENTRY_FILE_INHERIT | \
    ACL_ENTRY_DIRECTORY_INHERIT | ACL_ENTRY_NO_PROPAGATE_INHERIT | \
    ACL_ENTRY_INHERIT_ONLY | ACL_ENTRY_SUCCESSFUL_ACCESS | \
    ACL_ENTRY_FAILED_ACCESS)
#define	ACL_FULL_SET		(ACL_READ_DATA | ACL_WRITE_DATA | \
    ACL_APPEND_DATA | ACL_READ_NAMED_ATTRS | ACL_WRITE_NAMED_ATTRS | \
    ACL_EXECUTE | ACL_DELETE_CHILD | ACL_READ_ATTRIBUTES | \
    ACL_WRITE_ATTRIBUTES | ACL_DELETE | ACL_READ_ACL | ACL_WRITE_ACL | \
    ACL_WRITE_OWNER | ACL_SYNCHRONIZE)
#define	ACL_GROUP		0x00000008
#define	ACL_GROUP_OBJ		0x00000004
#define	ACL_LIST_DIRECTORY	0x00000008
#define	ACL_MASK		0x00000010
#define	ACL_MAX_ENTRIES				254
#define	ACL_MODIFY_SET		(ACL_FULL_SET & \
    ~(ACL_WRITE_ACL | ACL_WRITE_OWNER))
#define	ACL_NEXT_ENTRY		1
#define	ACL_NFS4_PERM_BITS	ACL_FULL_SET
#define	ACL_OTHER		0x00000020
#define	ACL_OTHER_OBJ		ACL_OTHER
#define	ACL_OVERRIDE_MASK	(S_IRWXU | S_IRWXG | S_IRWXO)
#define	ACL_PERM_BITS		(ACL_EXECUTE | ACL_WRITE | ACL_READ)
#define	ACL_PERM_NONE		0x0000
#define	ACL_POSIX1E_BITS	(ACL_EXECUTE | ACL_WRITE | ACL_READ)
#define	ACL_PRESERVE_MASK	(~ACL_OVERRIDE_MASK)
#define	ACL_READ		0x0004
#define	ACL_READ_ACL		0x00001000
#define	ACL_READ_ATTRIBUTES	0x00000200
#define	ACL_READ_DATA		0x00000008
#define	ACL_READ_NAMED_ATTRS	0x00000040
#define	ACL_READ_SET		(ACL_READ_DATA | ACL_READ_NAMED_ATTRS | \
    ACL_READ_ATTRIBUTES | ACL_READ_ACL)
#define	ACL_SYNCHRONIZE		0x00008000
#define	ACL_TEXT_APPEND_ID	0x04
#define	ACL_TEXT_NUMERIC_IDS	0x02
#define	ACL_TEXT_VERBOSE	0x01
#define	ACL_TYPE_ACCESS		0x00000002
#define	ACL_TYPE_ACCESS_OLD	0x00000000
#define	ACL_TYPE_DEFAULT	0x00000003
#define	ACL_TYPE_DEFAULT_OLD	0x00000001
#define	ACL_TYPE_NFS4		0x00000004
#define	ACL_UNDEFINED_ID	((uid_t)-1)
#define	ACL_UNDEFINED_TAG	0x00000000
#define	ACL_USER		0x00000002
#define	ACL_USER_OBJ		0x00000001
#define	ACL_WRITE		0x0002
#define	ACL_WRITE_ACL		0x00002000
#define	ACL_WRITE_ATTRIBUTES	0x00000400
#define	ACL_WRITE_DATA		0x00000010
#define	ACL_WRITE_NAMED_ATTRS	0x00000080
#define	ACL_WRITE_OWNER		0x00004000
#define	ACL_WRITE_SET		(ACL_WRITE_DATA | ACL_APPEND_DATA | \
    ACL_WRITE_NAMED_ATTRS | ACL_WRITE_ATTRIBUTES)
#define	NFS4_ACL_EXTATTR_NAME			"nfs4.acl"
#define	NFS4_ACL_EXTATTR_NAMESPACE		EXTATTR_NAMESPACE_SYSTEM
#define	OLDACL_MAX_ENTRIES			32
#define	POSIX1E_ACL_ACCESS_EXTATTR_NAME		"posix1e.acl_access"
#define	POSIX1E_ACL_ACCESS_EXTATTR_NAMESPACE	EXTATTR_NAMESPACE_SYSTEM
#define	POSIX1E_ACL_DEFAULT_EXTATTR_NAME	"posix1e.acl_default"
#define	POSIX1E_ACL_DEFAULT_EXTATTR_NAMESPACE	EXTATTR_NAMESPACE_SYSTEM
#define	CS_MORE		0x2	
#define	CS_OWN		0x1	
#define	CS_SET_DOT	0x100	
#define DB_ALIAS(alias_name, func_name) \
	_DB_SET(_cmd, alias_name, func_name, db_cmd_table, 0, NULL)
#define	DB_CALL	db_fncall_generic
#define DB_COMMAND(cmd_name, func_name) \
	_DB_FUNC(_cmd, cmd_name, func_name, db_cmd_table, 0, NULL)
#define DB_FUNC(_name, _func, list, _flag, _more)		\
	_DB_FUNC(_cmd, _name, _func, list, _flag, _more)
#define	DB_MAXARGS	10
#define	DB_MAXLINE	120
#define	DB_MAXSCRIPTLEN	128
#define	DB_MAXSCRIPTNAME	32
#define	DB_MAXSCRIPTRECURSION	3
#define	DB_MAXSCRIPTS	8
#define DB_SHOW_ALIAS(alias_name, func_name) \
	_DB_SET(_show, alias_name, func_name, db_show_table, 0, NULL)
#define DB_SHOW_ALL_ALIAS(alias_name, func_name) \
	_DB_SET(_show_all, alias_name, func_name, db_show_all_table, 0, NULL)
#define DB_SHOW_ALL_COMMAND(cmd_name, func_name) \
	_DB_FUNC(_show_all, cmd_name, func_name, db_show_all_table, 0, NULL)
#define DB_SHOW_COMMAND(cmd_name, func_name) \
	_DB_FUNC(_show, cmd_name, func_name, db_show_table, 0, NULL)
#define	TEXTDUMP_BLOCKSIZE	512
#define _DB_FUNC(_suffix, _name, _func, list, _flag, _more)	\
static db_cmdfcn_t _func;					\
_DB_SET(_suffix, _name, _func, list, _flag, _more);		\
static void							\
_func(db_expr_t addr, boolean_t have_addr, db_expr_t count, char *modif)
#define _DB_SET(_suffix, _name, _func, list, _flag, _more)	\
static struct command __CONCAT(_name,_suffix) = {		\
	.name	= __STRING(_name),				\
	.fcn	= _func,					\
	.flag	= _flag,					\
	.more	= _more						\
};								\

    { db_command_register(&list, &__CONCAT(_name,_suffix)); }	\
SYSINIT(__CONCAT(_name,_suffix), SI_SUB_KLD, SI_ORDER_ANY,	\


    { db_command_unregister(&list, &__CONCAT(_name,_suffix)); }	\
SYSUNINIT(__CONCAT(_name,_suffix), SI_SUB_KLD, SI_ORDER_ANY,	\

#define ABS_SET(set, sym)	__MAKE_SET(set, sym)
#define BSS_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_SET(set, sym)	__MAKE_SET(set, sym)
#define SET_BEGIN(set)							\
	(&__CONCAT(__start_set_,set))
#define SET_COUNT(set)							\
	(SET_LIMIT(set) - SET_BEGIN(set))
#define SET_DECLARE(set, ptype)						\
	extern ptype *__CONCAT(__start_set_,set);			\
	extern ptype *__CONCAT(__stop_set_,set)
#define SET_ENTRY(set, sym)	__MAKE_SET(set, sym)
#define SET_FOREACH(pvar, set)						\
	for (pvar = SET_BEGIN(set); pvar < SET_LIMIT(set); pvar++)
#define SET_ITEM(set, i)						\
	((SET_BEGIN(set))[i])
#define SET_LIMIT(set)							\
	(&__CONCAT(__stop_set_,set))
#define TEXT_SET(set, sym)	__MAKE_SET(set, sym)

#define __MAKE_SET(set, sym)						\
	__GLOBL(__CONCAT(__start_set_,set));				\
	__GLOBL(__CONCAT(__stop_set_,set));				\
	static void const * const __set_##set##_sym_##sym 		\
	__section("set_" #set) __used = &sym
#define VNET_GLOBAL_EVENTHANDLER_REGISTER(name, func, arg, priority)	\
do {									\
	if (IS_DEFAULT_VNET(curvnet)) {					\
		vimage_eventhandler_register(NULL, #name, func,		\
		    arg, priority,					\
		    vnet_global_eventhandler_iterator_func);		\
	}								\
} while(0)
#define VNET_GLOBAL_EVENTHANDLER_REGISTER_TAG(tag, name, func, arg, priority) \
do {									\
	if (IS_DEFAULT_VNET(curvnet)) {					\
		(tag) = vimage_eventhandler_register(NULL, #name, func,	\
		    arg, priority,					\
		    vnet_global_eventhandler_iterator_func);		\
	}								\
} while(0)
#define	VNET_MAGIC_N	0x3e0d8f29
#define	VNET_SETNAME		"set_vnet"
#define	VNET_START	(uintptr_t)&__start_set_vnet
#define	VNET_STOP	(uintptr_t)&__stop_set_vnet
#define	VNET_SYMPREFIX		"vnet_entry_"
#define	curvnet	curthread->td_vnet
#define	EHE_DEAD_PRIORITY	(-1)
#define EVENTHANDLER_DECLARE(name, type)				\
struct eventhandler_entry_ ## name 					\
{									\
	struct eventhandler_entry	ee;				\
	type				eh_func;			\
};									\
struct __hack
#define EVENTHANDLER_DEFINE(name, func, arg, priority)			\
	static eventhandler_tag name ## _tag;				\
	static void name ## _evh_init(void *ctx)			\
	{								\
		name ## _tag = EVENTHANDLER_REGISTER(name, func, ctx,	\
		    priority);						\
	}								\
	SYSINIT(name ## _evh_init, SI_SUB_CONFIGURE, SI_ORDER_ANY,	\
	    name ## _evh_init, arg);					\
	struct __hack
#define EVENTHANDLER_DEREGISTER(name, tag) 				\
do {									\
	struct eventhandler_list *_el;					\
									\
	if ((_el = eventhandler_find_list(#name)) != NULL)		\
		eventhandler_deregister(_el, tag);			\
} while(0)
#define EVENTHANDLER_INVOKE(name, ...)					\
do {									\
	struct eventhandler_list *_el;					\
									\
	if ((_el = eventhandler_find_list(#name)) != NULL) 		\
		_EVENTHANDLER_INVOKE(name, _el , ## __VA_ARGS__);	\
} while (0)
#define	EVENTHANDLER_PRI_ANY	10000
#define	EVENTHANDLER_PRI_FIRST	0
#define	EVENTHANDLER_PRI_LAST	20000
#define EVENTHANDLER_REGISTER(name, func, arg, priority)		\
	eventhandler_register(NULL, #name, func, arg, priority)
#define	LOWMEM_PRI_DEFAULT	EVENTHANDLER_PRI_FIRST
#define	SHUTDOWN_PRI_DEFAULT	EVENTHANDLER_PRI_ANY
#define	SHUTDOWN_PRI_FIRST	EVENTHANDLER_PRI_FIRST
#define	SHUTDOWN_PRI_LAST	EVENTHANDLER_PRI_LAST

#define _EVENTHANDLER_INVOKE(name, list, ...) do {			\
	struct eventhandler_entry *_ep;					\
	struct eventhandler_entry_ ## name *_t;				\
									\
	KASSERT((list)->el_flags & EHL_INITTED,				\
 	   ("eventhandler_invoke: running non-inited list"));		\
	EHL_LOCK_ASSERT((list), MA_OWNED);				\
	(list)->el_runcount++;						\
	KASSERT((list)->el_runcount > 0,				\
	    ("eventhandler_invoke: runcount overflow"));		\
	CTR0(KTR_EVH, "eventhandler_invoke(\"" __STRING(name) "\")");	\
	TAILQ_FOREACH(_ep, &((list)->el_entries), ee_link) {		\
		if (_ep->ee_priority != EHE_DEAD_PRIORITY) {		\
			EHL_UNLOCK((list));				\
			_t = (struct eventhandler_entry_ ## name *)_ep;	\
			CTR1(KTR_EVH, "eventhandler_invoke: executing %p", \
 			    (void *)_t->eh_func);			\
			_t->eh_func(_ep->ee_arg , ## __VA_ARGS__);	\
			EHL_LOCK((list));				\
		}							\
	}								\
	KASSERT((list)->el_runcount > 0,				\
	    ("eventhandler_invoke: runcount underflow"));		\
	(list)->el_runcount--;						\
	if ((list)->el_runcount == 0)					\
		eventhandler_prune_list(list);				\
	EHL_UNLOCK((list));						\
} while (0)
#define DROP_GIANT()							\
do {									\
	int _giantcnt = 0;						\
	WITNESS_SAVE_DECL(Giant);					\
									\
	if (mtx_owned(&Giant)) {					\
		WITNESS_SAVE(&Giant.lock_object, Giant);		\
		for (_giantcnt = 0; mtx_owned(&Giant); _giantcnt++)	\
			mtx_unlock(&Giant);				\
	}

#define	MTX_CONTESTED	0x00000002	
#define	MTX_DEF		0x00000000	 
#define	MTX_DESTROYED	(MTX_CONTESTED | MTX_UNOWNED)
#define	MTX_DUPOK	LOP_DUPOK	
#define	MTX_FLAGMASK	(MTX_RECURSED | MTX_CONTESTED | MTX_UNOWNED)
#define	MTX_NETWORK_LOCK	"network driver"
#define MTX_NOPROFILE   0x00000020	
#define	MTX_NOWITNESS	0x00000008	
#define	MTX_QUIET	LOP_QUIET	
#define	MTX_RECURSED	0x00000001	
#define PARTIAL_PICKUP_GIANT()						\
	mtx_assert(&Giant, MA_NOTOWNED);				\
	if (_giantcnt > 0) {						\
		while (_giantcnt--)					\
			mtx_lock(&Giant);				\
		WITNESS_RESTORE(&Giant.lock_object, Giant);		\
	}
#define PICKUP_GIANT()							\
	PARTIAL_PICKUP_GIANT();						\
} while (0)

#define __mtx_lock(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
									\
	if (!_mtx_obtain_lock((mp), _tid))				\
		_mtx_lock_sleep((mp), _tid, (opts), (file), (line));	\
	else								\
              	LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(LS_MTX_LOCK_ACQUIRE, \
		    mp, 0, 0, (file), (line));				\
} while (0)
#define __mtx_lock_spin(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
									\
	spinlock_enter();						\
	if (!_mtx_obtain_lock((mp), _tid)) {				\
		if ((mp)->mtx_lock == _tid)				\
			(mp)->mtx_recurse++;				\
		else							\
			_mtx_lock_spin((mp), _tid, (opts), (file), (line)); \
	} else 								\
              	LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(LS_MTX_SPIN_LOCK_ACQUIRE, \
		    mp, 0, 0, (file), (line));				\
} while (0)
#define __mtx_unlock(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
									\
	if (!_mtx_release_lock((mp), _tid))				\
		_mtx_unlock_sleep((mp), (opts), (file), (line));	\
} while (0)
#define __mtx_unlock_spin(mp) do {					\
	if (mtx_recursed((mp)))						\
		(mp)->mtx_recurse--;					\
	else {								\
		LOCKSTAT_PROFILE_RELEASE_LOCK(LS_MTX_SPIN_UNLOCK_RELEASE, \
			mp);						\
		_mtx_release_lock_quick((mp));				\
	}                                                               \
	spinlock_exit();				                \
} while (0)
#define _mtx_obtain_lock(mp, tid)					\
	atomic_cmpset_acq_ptr(&(mp)->mtx_lock, MTX_UNOWNED, (tid))
#define _mtx_release_lock(mp, tid)					\
	atomic_cmpset_rel_ptr(&(mp)->mtx_lock, (tid), MTX_UNOWNED)
#define _mtx_release_lock_quick(mp)					\
	atomic_store_rel_ptr(&(mp)->mtx_lock, MTX_UNOWNED)
#define mtx_assert(m, what)	(void)0
#define mtx_lock(m)		mtx_lock_flags((m), 0)
#define mtx_lock_spin(m)	mtx_lock_spin_flags((m), 0)
#define mtx_name(m)	((m)->lock_object.lo_name)
#define mtx_owned(m)	(((m)->mtx_lock & ~MTX_FLAGMASK) == (uintptr_t)curthread)
#define mtx_pool_lock(pool, ptr)					\
	mtx_lock(mtx_pool_find((pool), (ptr)))
#define mtx_pool_lock_spin(pool, ptr)					\
	mtx_lock_spin(mtx_pool_find((pool), (ptr)))
#define mtx_pool_unlock(pool, ptr)					\
	mtx_unlock(mtx_pool_find((pool), (ptr)))
#define mtx_pool_unlock_spin(pool, ptr)					\
	mtx_unlock_spin(mtx_pool_find((pool), (ptr)))
#define	mtx_recurse	lock_object.lo_data
#define mtx_recursed(m)	((m)->mtx_recurse != 0)
#define mtx_trylock(m)		mtx_trylock_flags((m), 0)
#define mtx_trylock_flags(m, opts)					\
	_mtx_trylock((m), (opts), LOCK_FILE, LOCK_LINE)
#define mtx_unlock(m)		mtx_unlock_flags((m), 0)
#define mtx_unlock_spin(m)	mtx_unlock_spin_flags((m), 0)
#define	LSA_ACQUIRE			(LS_TYPE_ADAPTIVE "-" LS_ACQUIRE)
#define	LSA_BLOCK			(LS_TYPE_ADAPTIVE "-" LS_BLOCK)
#define	LSA_RELEASE			(LS_TYPE_ADAPTIVE "-" LS_RELEASE)
#define	LSA_SPIN			(LS_TYPE_ADAPTIVE "-" LS_SPIN)
#define	LSR_ACQUIRE			(LS_TYPE_RW "-" LS_ACQUIRE)
#define	LSR_BLOCK			(LS_TYPE_RW "-" LS_BLOCK)
#define	LSR_DOWNGRADE			(LS_TYPE_RW "-" LS_DOWNGRADE)
#define	LSR_RELEASE			(LS_TYPE_RW "-" LS_RELEASE)
#define	LSR_SPIN			(LS_TYPE_RW "-" LS_SPIN)
#define	LSR_UPGRADE			(LS_TYPE_RW "-" LS_UPGRADE)
#define	LSS_ACQUIRE			(LS_TYPE_SPIN "-" LS_ACQUIRE)
#define	LSS_RELEASE			(LS_TYPE_SPIN "-" LS_RELEASE)
#define	LSS_SPIN			(LS_TYPE_SPIN "-" LS_SPIN)
#define	LST_SPIN			(LS_TYPE_THREAD "-" LS_SPIN)
#define	LSX_ACQUIRE			(LS_TYPE_SX "-" LS_ACQUIRE)
#define	LSX_BLOCK			(LS_TYPE_SX "-" LS_BLOCK)
#define	LSX_DOWNGRADE			(LS_TYPE_SX "-" LS_DOWNGRADE)
#define	LSX_RELEASE			(LS_TYPE_SX "-" LS_RELEASE)
#define	LSX_SPIN			(LS_TYPE_SX "-" LS_SPIN)
#define	LSX_UPGRADE			(LS_TYPE_SX "-" LS_UPGRADE)
#define	LS_ACQUIRE			"acquire"
#define	LS_BLOCK			"block"
#define	LS_DOWNGRADE			"downgrade"
#define	LS_MTX_LOCK			"mtx_lock"
#define	LS_MTX_LOCK_ACQUIRE		3
#define	LS_MTX_LOCK_BLOCK		6
#define	LS_MTX_LOCK_SPIN		5
#define	LS_MTX_SPIN_LOCK		"mtx_lock_spin"
#define	LS_MTX_SPIN_LOCK_ACQUIRE	0
#define	LS_MTX_SPIN_LOCK_SPIN		2
#define	LS_MTX_SPIN_UNLOCK		"mtx_unlock_spin"
#define	LS_MTX_SPIN_UNLOCK_RELEASE	1
#define	LS_MTX_TRYLOCK			"mtx_trylock"
#define	LS_MTX_TRYLOCK_ACQUIRE		7
#define	LS_MTX_UNLOCK			"mtx_unlock"
#define	LS_MTX_UNLOCK_RELEASE		4
#define	LS_NPROBES			29
#define	LS_RELEASE			"release"
#define	LS_RW_DOWNGRADE			"rw_downgrade"
#define	LS_RW_DOWNGRADE_DOWNGRADE	17
#define	LS_RW_RLOCK			"rw_rlock"
#define	LS_RW_RLOCK_ACQUIRE		8
#define	LS_RW_RLOCK_BLOCK		13
#define	LS_RW_RLOCK_SPIN		12
#define	LS_RW_RUNLOCK			"rw_runlock"
#define	LS_RW_RUNLOCK_RELEASE		9	
#define	LS_RW_TRYUPGRADE		"rw_try_upgrade"
#define	LS_RW_TRYUPGRADE_UPGRADE	16
#define	LS_RW_WLOCK			"rw_wlock"
#define	LS_RW_WLOCK_ACQUIRE		10
#define	LS_RW_WLOCK_BLOCK		15
#define	LS_RW_WLOCK_SPIN		14
#define	LS_RW_WUNLOCK			"rw_wunlock"
#define	LS_RW_WUNLOCK_RELEASE		11
#define	LS_SPIN				"spin"
#define	LS_SX_DOWNGRADE			"sx_downgrade"
#define	LS_SX_DOWNGRADE_DOWNGRADE	27
#define	LS_SX_SLOCK			"sx_slock"
#define	LS_SX_SLOCK_ACQUIRE		18
#define	LS_SX_SLOCK_BLOCK		23
#define	LS_SX_SLOCK_SPIN		22
#define	LS_SX_SUNLOCK			"sx_sunlock"
#define	LS_SX_SUNLOCK_RELEASE		19
#define	LS_SX_TRYUPGRADE		"sx_try_upgrade"
#define	LS_SX_TRYUPGRADE_UPGRADE	26
#define	LS_SX_XLOCK			"sx_xlock"
#define	LS_SX_XLOCK_ACQUIRE		20
#define	LS_SX_XLOCK_BLOCK		25
#define	LS_SX_XLOCK_SPIN		24
#define	LS_SX_XUNLOCK			"sx_xunlock"
#define	LS_SX_XUNLOCK_RELEASE		21
#define	LS_THREAD_LOCK			"thread_lock"
#define	LS_THREAD_LOCK_SPIN		28
#define	LS_TYPE_ADAPTIVE		"adaptive"
#define	LS_TYPE_RW			"rw"
#define	LS_TYPE_SPIN			"spin"
#define	LS_TYPE_SX			"sx"
#define	LS_TYPE_THREAD			"thread"
#define	LS_UPGRADE			"upgrade"

#define lock_profile_obtain_lock_failed(lo, contested, waittime)	(void)0
#define lock_profile_obtain_lock_success(lo, contested, waittime, file, line)	(void)0
#define	LA_LOCKED	0x00000001	
#define	LA_MASKASSERT	0x000000ff	
#define	LA_NOTRECURSED	0x00000010	
#define	LA_RECURSED	0x00000008	
#define	LA_SLOCKED	0x00000002	
#define	LA_UNLOCKED	0x00000000	
#define	LA_XLOCKED	0x00000004	
#define	LC_RECURSABLE	0x00000008	
#define	LC_SLEEPABLE	0x00000004	
#define	LC_SLEEPLOCK	0x00000001	
#define	LC_SPINLOCK	0x00000002	
#define	LC_UPGRADABLE	0x00000010	
#define	LOCK_CLASS_MAX		(LO_CLASSMASK >> LO_CLASSSHIFT)
#define	LOCK_DEBUG	1
#define	LOCK_FILE	"__FILE__"
#define	LOCK_LINE	"__LINE__"
#define	LOP_DUPOK	0x00000010	
#define	LOP_EXCLUSIVE	0x00000008	
#define	LOP_NEWORDER	0x00000001	
#define	LOP_QUIET	0x00000002	
#define	LOP_TRYLOCK	0x00000004	
#define	LO_CLASSFLAGS	0x0000ffff	
#define	LO_CLASSMASK	0x0f000000	
#define	LO_CLASSSHIFT		24
#define	LO_DUPOK	0x00400000	
#define	LO_INITIALIZED	0x00010000	
#define LO_NOPROFILE    0x10000000      
#define	LO_QUIET	0x00040000	
#define	LO_RECURSABLE	0x00080000	
#define	LO_SLEEPABLE	0x00100000	
#define	LO_UPGRADABLE	0x00200000	
#define	LO_WITNESS	0x00020000	
#define MPASS(ex)		MPASS4(ex, #ex, "__FILE__", "__LINE__")
#define MPASS2(ex, what)	MPASS4(ex, what, "__FILE__", "__LINE__")
#define MPASS3(ex, file, line)	MPASS4(ex, #ex, file, line)
#define MPASS4(ex, what, file, line)					\
	KASSERT((ex), ("Assertion %s failed at %s:%d", what, file, line))
#define	WARN_GIANTOK	0x01	
#define	WARN_PANIC	0x02	
#define	WARN_SLEEPOK	0x04	
#define WITNESS_DESTROY(lock)						\
	witness_destroy(lock)

#define	DPCPU_BYTES		(DPCPU_STOP - DPCPU_START)
#define	DPCPU_MODMIN		2048
#define	DPCPU_MODSIZE		(DPCPU_SIZE - (DPCPU_BYTES - DPCPU_MODMIN))
#define	DPCPU_SETNAME		"set_pcpu"
#define	DPCPU_SIZE		roundup2(DPCPU_BYTES, PAGE_SIZE)
#define	DPCPU_START		((uintptr_t)&__start_set_pcpu)
#define	DPCPU_STOP		((uintptr_t)&__stop_set_pcpu)
#define	DPCPU_SYMPREFIX		"pcpu_entry_"
#define	curcpu		PCPU_GET(cpuid)
#define	curproc		(curthread->td_proc)
#define	curthread	PCPU_GET(curthread)
#define	curvidata	PCPU_GET(vidata)
#define	CPUSTATES	5
#define	CP_IDLE		4
#define	CP_INTR		3
#define	CP_NICE		1
#define	CP_SYS		2
#define	CP_USER		0
#define	PRIO_MAX	20
#define	PRIO_MIN	-20
#define	PRIO_PGRP	1
#define	PRIO_PROCESS	0
#define	PRIO_USER	2
#define	RLIMIT_AS	RLIMIT_VMEM	
#define	RLIMIT_CORE	4		
#define	RLIMIT_CPU	0		
#define	RLIMIT_DATA	2		
#define	RLIMIT_FSIZE	1		
#define	RLIMIT_MEMLOCK	6		
#define	RLIMIT_NOFILE	8		
#define	RLIMIT_NPROC	7		
#define	RLIMIT_NPTS	11		
#define	RLIMIT_RSS	5		
#define	RLIMIT_SBSIZE	9		
#define	RLIMIT_STACK	3		
#define	RLIMIT_SWAP	12		
#define	RLIMIT_VMEM	10		
#define	RLIM_INFINITY	((rlim_t)(((uint64_t)1 << 63) - 1))
#define	RLIM_NLIMITS	13		
#define	RUSAGE_CHILDREN	-1
#define	RUSAGE_SELF	0
#define	RUSAGE_THREAD	1
#define	ru_first	ru_ixrss
#define	ru_last		ru_nivcsw
#define	MAXSLP			20

#define	CPU_MAXSIZE	128
#define	CPU_SETSIZE	MAXCPU
#define	_NCPUBITS	(sizeof(long) * NBBY)	
#define	_NCPUWORDS	howmany(CPU_SETSIZE, _NCPUBITS)
#define CTR0(m, format)			CTR6(m, format, 0, 0, 0, 0, 0, 0)
#define CTR1(m, format, p1)		CTR6(m, format, p1, 0, 0, 0, 0, 0)
#define CTR6(m, format, p1, p2, p3, p4, p5, p6) do {			\
	if (KTR_COMPILE & (m))						\
		ktr_tracepoint((m), "__FILE__", "__LINE__", format,		\
		    (u_long)(p1), (u_long)(p2), (u_long)(p3),		\
		    (u_long)(p4), (u_long)(p5), (u_long)(p6));		\
	} while(0)
#define	KTR_ALL		0x7fffffff
#define	KTR_ATTR_LINKED	"linkedto:\"%s\""
#define	KTR_BUF		0x40000000		
#define	KTR_BUSDMA	0x08000000		
#define	KTR_CALLOUT	0x02000000		
#define	KTR_COMPILE	(KTR_ALL)
#define	KTR_CONTENTION	0x00800000		
#define	KTR_DEV		0x00000004		
#define	KTR_EVH		0x00020000		
#define	KTR_GEN		0x00000001		
#define	KTR_GEOM	0x04000000		
#define	KTR_INET	0x00200000		
#define	KTR_INET6	0x10000000		
#define	KTR_INIT	0x00004000		
#define	KTR_INTR	0x00000200		
#define	KTR_LOCK	0x00000008		
#define	KTR_MALLOC	0x00000080		
#define	KTR_NET		0x00000002		
#define	KTR_PARMS	6
#define	KTR_PMAP	0x00000040		
#define	KTR_PROC	0x00001000		
#define	KTR_RUNQ	0x00400000		
#define	KTR_SCHED	0x20000000		
#define	KTR_SIG		0x00000400		
#define	KTR_SMP		0x00000010		
#define	KTR_SPARE2	0x00000800		
#define	KTR_SPARE3	0x00008000		
#define	KTR_SPARE4	0x00010000		
#define KTR_STATE0(m, egroup, ident, state)				\
	KTR_EVENT0(m, egroup, ident, "state:\"%s\"", state)
#define KTR_STATE1(m, egroup, ident, state, a0, v0)			\
	KTR_EVENT1(m, egroup, ident, "state:\"%s\"", state, a0, (v0))
#define KTR_STATE2(m, egroup, ident, state, a0, v0, a1, v1)		\
	KTR_EVENT2(m, egroup, ident, "state:\"%s\"", state, a0, (v0), a1, (v1))
#define KTR_STATE3(m, egroup, ident, state, a0, v0, a1, v1, a2, v2)	\
	KTR_EVENT3(m, egroup, ident, "state:\"%s\"",			\
	    state, a0, (v0), a1, (v1), a2, (v2))
#define KTR_STATE4(m, egroup, ident, state, a0, v0, a1, v1, a2, v2, a3, v3)\
	KTR_EVENT4(m, egroup, ident, "state:\"%s\"",			\
	    state, a0, (v0), a1, (v1), a2, (v2), a3, (v3))
#define	KTR_SUBSYS	0x00000020		
#define	KTR_SYSC	0x00002000		
#define	KTR_TRAP	0x00000100		
#define	KTR_UMA		0x01000000		
#define	KTR_VERSION	2
#define	KTR_VFS		0x00040000		
#define	KTR_VM		0x00100000		
#define	KTR_VOP		0x00080000		

#define	SA_LOCKED		LA_LOCKED
#define	SA_NOTRECURSED		LA_NOTRECURSED
#define	SA_RECURSED		LA_RECURSED
#define	SA_SLOCKED		LA_SLOCKED
#define	SA_UNLOCKED		LA_UNLOCKED
#define	SA_XLOCKED		LA_XLOCKED
#define	SX_DUPOK		0x01
#define	SX_INTERRUPTIBLE	0x40
#define	SX_LOCKED		LA_LOCKED
#define	SX_LOCK_DESTROYED						\
	(SX_LOCK_SHARED_WAITERS | SX_LOCK_EXCLUSIVE_WAITERS)
#define	SX_LOCK_EXCLUSIVE_WAITERS	0x04
#define	SX_LOCK_FLAGMASK						\
	(SX_LOCK_SHARED | SX_LOCK_SHARED_WAITERS |			\
	SX_LOCK_EXCLUSIVE_WAITERS | SX_LOCK_RECURSED)
#define	SX_LOCK_RECURSED		0x08
#define	SX_LOCK_SHARED			0x01
#define	SX_LOCK_SHARED_WAITERS		0x02
#define	SX_LOCK_UNLOCKED		SX_SHARERS_LOCK(0)
#define	SX_NOADAPTIVE		0x10
#define	SX_NOPROFILE		0x02
#define	SX_NOTRECURSED		LA_NOTRECURSED
#define	SX_NOWITNESS		0x04
#define	SX_ONE_SHARER			(1 << SX_SHARERS_SHIFT)
#define	SX_QUIET		0x08
#define	SX_RECURSE		0x20
#define	SX_RECURSED		LA_RECURSED
#define	SX_SHARERS_SHIFT		4
#define	SX_SLOCKED		LA_SLOCKED
#define	SX_UNLOCKED		LA_UNLOCKED
#define	SX_XLOCKED		LA_XLOCKED
#define	RA_LOCKED		LA_LOCKED
#define	RA_NOTRECURSED		LA_NOTRECURSED
#define	RA_RECURSED		LA_RECURSED
#define	RA_RLOCKED		LA_SLOCKED
#define	RA_UNLOCKED		LA_UNLOCKED
#define	RA_WLOCKED		LA_XLOCKED
#define	RW_DESTROYED		(RW_LOCK_READ_WAITERS | RW_LOCK_WRITE_WAITERS)
#define	RW_DUPOK	0x01
#define	RW_LOCK_FLAGMASK						\
	(RW_LOCK_READ | RW_LOCK_READ_WAITERS | RW_LOCK_WRITE_WAITERS |	\
	RW_LOCK_WRITE_SPINNER)
#define	RW_LOCK_READ		0x01
#define	RW_LOCK_READ_WAITERS	0x02
#define	RW_LOCK_WAITERS		(RW_LOCK_READ_WAITERS | RW_LOCK_WRITE_WAITERS)
#define	RW_LOCK_WRITE_SPINNER	0x08
#define	RW_LOCK_WRITE_WAITERS	0x04
#define	RW_NOPROFILE	0x02
#define	RW_NOWITNESS	0x04
#define	RW_ONE_READER		(1 << RW_READERS_SHIFT)
#define	RW_QUIET	0x08
#define	RW_READERS_SHIFT	4
#define	RW_RECURSE	0x10
#define	RW_UNLOCKED		RW_READERS_LOCK(0)

#define	rw_recurse	lock_object.lo_data
#define	NOCPU	0xff		
#define	NO_PID		100000
#define	PID_MAX		99999
#define PROC_ASSERT_HELD(p) do {					\
	KASSERT((p)->p_lock > 0, ("process not held"));			\
} while (0)
#define PROC_ASSERT_NOT_HELD(p) do {					\
	KASSERT((p)->p_lock == 0, ("process held"));			\
} while (0)
#define	P_ADVLOCK	0x00001	
#define	P_CONTINUED	0x10000	
#define	P_CONTROLT	0x00002	
#define	P_EXEC		0x04000	
#define	P_FOLLOWFORK	0x00008	
#define	P_HADTHREADS	0x00080	
#define	P_HWPMC		0x800000 
#define	P_INEXEC	0x4000000 
#define	P_INMEM		0x10000000 
#define	P_JAILED	0x1000000 
#define	P_KTHREAD	0x00004	
#define	P_MAGIC		0xbeefface
#define	P_PPWAIT	0x00010	
#define	P_PROFIL	0x00020	
#define	P_PROTECTED	0x100000 
#define	P_SIGEVENT	0x200000 
#define	P_SINGLE_EXIT	0x00400	
#define	P_STATCHILD	0x8000000 
#define	P_STOPPED	(P_STOPPED_SIG|P_STOPPED_SINGLE|P_STOPPED_TRACE)
#define	P_STOPPED_SIG	0x20000	
#define	P_STOPPED_TRACE	0x40000	
#define	P_STOPPROF	0x00040	
#define	P_SUGID		0x00100	
#define	P_SWAPPINGIN	0x40000000 
#define	P_SWAPPINGOUT	0x20000000 
#define	P_SYSTEM	0x00200	
#define	P_TRACED	0x00800	
#define	P_WAITED	0x01000	
#define	P_WEXIT		0x02000	
#define	P_WKILLED	0x08000	
#define	SIDL	1		
#define	SINGLE_BOUNDARY	2
#define	SINGLE_EXIT	1
#define	SINGLE_NO_EXIT	0
#define	SLOCK	7		
#define	SRUN	2		
#define	SSLEEP	3		
#define	SSTOP	4		
#define	SWAIT	6		
#define	SWT_COUNT		13	
#define	SWT_IDLE		8	
#define	SWT_IWAIT		9	
#define	SWT_NEEDRESCHED		7	
#define	SWT_NONE		0	
#define	SWT_OWEPREEMPT		2	
#define	SWT_PREEMPT		1	
#define	SWT_RELINQUISH		6	
#define	SWT_REMOTEPREEMPT	11	
#define	SWT_REMOTEWAKEIDLE	12	
#define	SWT_SLEEPQ		4	
#define	SWT_SLEEPQTIMO		5	
#define	SWT_SUSPEND		10	
#define	SWT_TURNSTILE		3	
#define	SW_INVOL	0x0200		
#define	SW_TYPE_MASK		0xff	
#define	SW_VOL		0x0100		
#define	SZOMB	5		
#define	TDB_EXEC	0x00000020 
#define	TDB_FORK	0x00000040 
#define	TDB_SCE		0x00000008 
#define	TDB_SCX		0x00000010 
#define	TDB_STOPATFORK	0x00000080 
#define	TDB_SUSPEND	0x00000001 
#define	TDB_USERWR	0x00000004 
#define	TDB_XSIG	0x00000002 
#define	TDF_ALRMPEND	0x10000000 
#define	TDF_ASTPENDING	0x00000800 
#define	TDF_BORROWING	0x00000001 
#define	TDF_BOUNDARY	0x00000400 
#define	TDF_CANSWAP	0x00000040 
#define	TDF_IDLETD	0x00000020 
#define	TDF_INMEM	0x00000004 
#define	TDF_INPANIC	0x00000002 
#define	TDF_KTH_SUSP	0x00000100 
#define	TDF_MACPEND	0x40000000 
#define	TDF_NEEDRESCHED	0x00010000 
#define	TDF_NEEDSIGCHK	0x00020000 
#define	TDF_NEEDSUSPCHK	0x00008000 
#define	TDF_NOLOAD	0x00040000 
#define	TDF_PROFPEND	0x20000000 
#define	TDF_SBDRY	0x00002000 
#define	TDF_SCHED0	0x01000000 
#define	TDF_SCHED1	0x02000000 
#define	TDF_SCHED2	0x04000000 
#define	TDF_SCHED3	0x08000000 
#define	TDF_SINTR	0x00000008 
#define	TDF_SLEEPABORT	0x00000080 
#define	TDF_SWAPINREQ	0x00400000 
#define	TDF_THRWAKEUP	0x00100000 
#define	TDF_TIMEOUT	0x00000010 
#define	TDF_TIMOFAIL	0x00001000 
#define	TDF_UNUSED09	0x00000200 
#define	TDF_UNUSED19	0x00080000 
#define	TDF_UNUSED21	0x00200000 
#define	TDF_UNUSED23	0x00800000 
#define	TDF_UPIBLOCKED	0x00004000 
#define	TDI_IWAIT	0x0010	
#define	TDI_LOCK	0x0008	
#define	TDI_SLEEPING	0x0002	
#define	TDI_SUSPENDED	0x0001	
#define	TDI_SWAPPED	0x0004	
#define	TDP_ALTSTACK	0x00000020 
#define	TDP_AUDITREC	0x01000000 
#define	TDP_BUFNEED	0x00000008 
#define	TDP_CALLCHAIN	0x00400000 
#define	TDP_DEADLKTREAT	0x00000040 
#define	TDP_GEOM	0x00010000 
#define	TDP_IGNSUSP	0x00800000 
#define	TDP_INBDFLUSH	0x00100000 
#define	TDP_INKTR	0x00000002 
#define	TDP_INKTRACE	0x00000004 
#define	TDP_ITHREAD	0x00000400 
#define	TDP_KTHREAD	0x00200000 
#define	TDP_NOFAULTING	0x00000080 
#define	TDP_NOSLEEPING	0x00000100 
#define	TDP_OLDMASK	0x00000001 
#define	TDP_OWEUPC	0x00000200 
#define	TDP_SCHED1	0x00001000 
#define	TDP_SCHED2	0x00002000 
#define	TDP_SCHED3	0x00004000 
#define	TDP_SCHED4	0x00008000 
#define	TDP_SOFTDEP	0x00020000 
#define	TDP_UNUSED800	0x00000800 
#define	TDP_WAKEUP	0x00080000 
#define TD_IS_IDLETHREAD(td)	((td)->td_flags & TDF_IDLETD)
#define	p_endcopy	p_xstat
#define	p_endzero	p_magic
#define	p_pgid		p_pgrp->pg_id
#define	p_session	p_pgrp->pg_session
#define	p_startcopy	p_endzero
#define	p_startzero	p_oppid
#define	td_siglist	td_sigqueue.sq_signals
#define	CRED_FLAG_CAPMODE	0x00000001	
#define	FSCRED	((struct ucred *)-1)	
#define	NOCRED	((struct ucred *)0)	
#define	XUCRED_VERSION	0
#define	XU_NGROUPS	16
#define	cr_endcopy	cr_label
#define	AQ_BUFSZ	MAXAUDITDATA
#define	AQ_HIWATER	100
#define	AQ_LOWATER	10
#define	AQ_MAXBUFSZ	1048576
#define	AQ_MAXHIGH	10000
#define	AT_IPC_MSG	((u_char)1)	
#define	AT_IPC_SEM	((u_char)2)	
#define	AT_IPC_SHM	((u_char)3)	
#define	AUC_AUDITING		1
#define	AUC_DISABLED		-1
#define	AUC_NOAUDIT		2
#define	AUC_UNSET		0
#define	AUDITDEV_FILENAME	"audit"
#define	AUDIT_AHLT	0x0002
#define	AUDIT_ARGE	0x0008
#define	AUDIT_ARGV	0x0004
#define	AUDIT_CNT	0x0001
#define	AUDIT_GROUP	0x0080
#define	AUDIT_HARD_LIMIT_FREE_BLOCKS	4
#define	AUDIT_PATH	0x0200
#define	AUDIT_PERZONE	0x2000
#define	AUDIT_PUBLIC	0x0800
#define	AUDIT_RECORD_MAGIC	0x828a0f1b
#define	AUDIT_SCNT	0x0400
#define	AUDIT_SEQ	0x0010
#define	AUDIT_TRAIL	0x0100
#define	AUDIT_TRIGGER_CLOSE_AND_DIE	4	
#define	AUDIT_TRIGGER_EXPIRE_TRAILS	8	
#define	AUDIT_TRIGGER_FILE	("/dev/" AUDITDEV_FILENAME)
#define	AUDIT_TRIGGER_INITIALIZE	7	
#define	AUDIT_TRIGGER_LOW_SPACE		1	
#define	AUDIT_TRIGGER_MAX		8
#define	AUDIT_TRIGGER_MIN		1
#define	AUDIT_TRIGGER_NO_SPACE		5	
#define	AUDIT_TRIGGER_READ_FILE		3	
#define	AUDIT_TRIGGER_ROTATE_KERNEL	2	
#define	AUDIT_TRIGGER_ROTATE_USER	6	
#define	AUDIT_USER	0x0040
#define	AUDIT_WINDATA	0x0020
#define	AUDIT_ZONENAME	0x1000
#define	AU_ASSIGN_ASID	-1
#define	AU_DEFAUDITID	(uid_t)(-1)
#define	AU_DEFAUDITSID	 0
#define	AU_FS_MINFREE	20
#define	AU_IPv4		4
#define	AU_IPv6		16
#define	A_GETCAR	9
#define	A_GETCLASS	22
#define	A_GETCOND	37
#define	A_GETCWD	8
#define	A_GETFSIZE	27
#define	A_GETKAUDIT	29
#define	A_GETKMASK	4
#define	A_GETPINFO	24
#define	A_GETPINFO_ADDR	28
#define	A_GETPOLICY	33
#define	A_GETQCTRL	35
#define	A_GETSINFO_ADDR	32
#define	A_GETSTAT	12
#define	A_OLDGETCOND	20
#define	A_OLDGETPOLICY	2
#define	A_OLDGETQCTRL	6
#define	A_OLDSETCOND	21
#define	A_OLDSETPOLICY	3
#define	A_OLDSETQCTRL	7
#define	A_SENDTRIGGER	31
#define	A_SETCLASS	23
#define	A_SETCOND	38
#define	A_SETFSIZE	26
#define	A_SETKAUDIT	30
#define	A_SETKMASK	5
#define	A_SETPMASK	25
#define	A_SETPOLICY	34
#define	A_SETQCTRL	36
#define	A_SETSMASK	15
#define	A_SETSTAT	13
#define	A_SETUMASK	14
#define	MAXAUDITDATA		(0x8000 - 1)
#define	MAX_AUDIT_RECORDS	20
#define	MAX_AUDIT_RECORD_SIZE	MAXAUDITDATA
#define	MIN_AUDIT_FILE_SIZE	(512 * 1024)
#define	UCF_SWAPPED	0x00000001	
#define ucontext4 ucontext
#define	KSI_COPYMASK	(KSI_TRAP|KSI_SIGQ)
#define	KSI_EXT		0x02	
#define	KSI_HEAD	0x10	
#define	KSI_INS		0x04	
#define	KSI_SIGQ	0x08	
#define	KSI_TRAP	0x01	
#define	PS_CLDSIGIGN	0x0004	
#define	PS_NOCLDSTOP	0x0002	
#define	PS_NOCLDWAIT	0x0001	
#define	SIGPROCMASK_OLD		0x0001
#define	SIGPROCMASK_PROC_LOCKED	0x0002
#define	SIGPROCMASK_PS_LOCKED	0x0004
#define	SIG_CATCH	((__sighandler_t *)2)
#define	SIG_STOP_ALLOWED	100
#define	SIG_STOP_NOT_ALLOWED	101
#define	SQ_INIT	0x01
#define	ksi_band	ksi_info.si_band
#define	ksi_code	ksi_info.si_code
#define	ksi_errno	ksi_info.si_errno
#define	ksi_mqd		ksi_info.si_mqd
#define	ksi_overrun	ksi_info.si_overrun
#define	ksi_pid		ksi_info.si_pid
#define	ksi_signo	ksi_info.si_signo
#define	ksi_timerid	ksi_info.si_timerid
#define	ksi_trapno	ksi_info.si_trapno
#define	ksi_uid		ksi_info.si_uid
#define	ksi_value	ksi_info.si_value
#define	sigcantmask	(sigmask(SIGKILL) | sigmask(SIGSTOP))

#define	sio_pgrp	sio_u.siu_pgrp
#define	sio_proc	sio_u.siu_proc
#define	RQ_NQS		(64)		
#define	RQ_PPQ		(4)		
#define RTP_PRIO_BASE(P)	PRI_BASE(P)
#define RTP_PRIO_IS_REALTIME(P) PRI_IS_REALTIME(P)
#define RTP_PRIO_NEED_RR(P)	PRI_NEED_RR(P)

#define	OSD_FIRST	OSD_THREAD
#define	OSD_JAIL	1
#define	OSD_KHELP	2
#define	OSD_LAST	OSD_KHELP
#define	OSD_THREAD	0

#define EV_SET(kevp_, a, b, c, d, e, f) do {	\
	struct kevent *kevp = (kevp_);		\
	(kevp)->ident = (a);			\
	(kevp)->filter = (b);			\
	(kevp)->flags = (c);			\
	(kevp)->fflags = (d);			\
	(kevp)->data = (e);			\
	(kevp)->udata = (f);			\
} while(0)
#define	KNF_LISTLOCKED	0x0001			
#define	KNF_NOKQLOCK	0x0002			
#define KNOTE(list, hist, flags)	knote(list, hist, flags)
#define KNOTE_LOCKED(list, hint)	knote(list, hint, KNF_LISTLOCKED)
#define KNOTE_UNLOCKED(list, hint)	knote(list, hint, 0)
#define	NOTE_ATTRIB	0x0008			
#define	NOTE_CHILD	0x00000004		
#define	NOTE_DELETE	0x0001			
#define	NOTE_EXEC	0x20000000		
#define	NOTE_EXIT	0x80000000		
#define	NOTE_EXTEND	0x0004			
#define	NOTE_FORK	0x40000000		
#define	NOTE_LINK	0x0010			
#define	NOTE_PCTRLMASK	0xf0000000		
#define	NOTE_PDATAMASK	0x000fffff		
#define	NOTE_RENAME	0x0020			
#define	NOTE_REVOKE	0x0040			
#define	NOTE_TRACK	0x00000001		
#define	NOTE_TRACKERR	0x00000002		
#define	NOTE_WRITE	0x0002			

#define knlist_clear(knl, islocked)				\
		knlist_cleardel((knl), NULL, (islocked), 0)
#define knlist_delete(knl, td, islocked)			\
		knlist_cleardel((knl), (td), (islocked), 1)
#define cv_broadcast(cvp)	cv_broadcastpri(cvp, 0)
#define	CALLOUT_ACTIVE		0x0002 
#define	CALLOUT_LOCAL_ALLOC	0x0001 
#define	CALLOUT_MPSAFE		0x0008 
#define	CALLOUT_PENDING		0x0004 
#define	CALLOUT_RETURNUNLOCKED	0x0010 
#define	CALLOUT_SHAREDLOCK	0x0020 

#define	DOCLOSE		0x0008	
#define	FORCECLOSE	0x0002	
#define	IO_APPEND	0x0002		
#define	IO_ASYNC	0x0010		
#define	IO_BUFLOCKED	0x2000		
#define	IO_DIRECT	0x0100		
#define	IO_EXT		0x0400		
#define	IO_INVAL	0x0040		
#define	IO_NDELAY	0x0004		
#define	IO_NODELOCKED	0x0008		
#define	IO_NOMACCHECK	0x1000		
#define	IO_NORMAL	0x0800		
#define	IO_SYNC		0x0080		
#define	IO_UNIT		0x0001		
#define	IO_VMIO		0x0020		
#define	NULLVP	((struct vnode *)NULL)
#define	REVOKEALL	0x0001	
#define	SKIPSYSTEM	0x0001	
#define	VADMIN			000000010000 
#define	VAPPEND			000000040000 
#define	VA_EXCLUSIVE	0x02		
#define	VA_UTIMES_NULL	0x01		
#define VCALL(c) ((c)->a_desc->vdesc_call(c))
#define	VDELETE		 	000010000000
#define	VDELETE_CHILD	 	000001000000
#define	VDESC_MAX_VPS		16
#define	VDESC_NOMAP_VPP		0x0100
#define VDESC_NO_OFFSET -1
#define	VDESC_VP0_WILLRELE	0x0001
#define	VDESC_VP1_WILLRELE	0x0002
#define	VDESC_VP2_WILLRELE	0x0004
#define	VDESC_VP3_WILLRELE	0x0008
#define	VDESC_VPP_WILLRELE	0x0200
#define	VEXEC			000000000100 
#define	VEXPLICIT_DENY		000000100000
#define	VI_AGE		0x0040	
#define	VI_DOINGINACT	0x0800	
#define	VI_DOOMED	0x0080	
#define	VI_FREE		0x0100	
#define	VI_MOUNT	0x0020	
#define	VI_OWEINACT	0x1000	
#define	VNOVAL	(-1)
#define VN_KNOTE(vp, b, a)					\
	do {							\
		if (!VN_KNLIST_EMPTY(vp))			\
			KNOTE(&vp->v_pollinfo->vpi_selinfo.si_note, (b), \
			    (a) | KNF_NOKQLOCK);		\
	} while (0)
#define	VN_OPEN_NOAUDIT		0x00000001
#define VOP_LOCK(vp, flags) VOP_LOCK1(vp, flags, "__FILE__", "__LINE__")
#define VOP_WRITE_POST(ap, ret)						\
	noffset = (ap)->a_uio->uio_offset;				\
	if (noffset > ooffset && !VN_KNLIST_EMPTY((ap)->a_vp)) {	\
		VFS_KNOTE_LOCKED((ap)->a_vp, NOTE_WRITE			\
		    | (noffset > osize ? NOTE_EXTEND : 0));		\
	}
#define	VREAD			000000000400 
#define	VREAD_ACL	 	000020000000 
#define	VSYNCHRONIZE	 	000200000000 
#define	VV_CACHEDLABEL	0x0010	
#define	VV_COPYONWRITE	0x0040	
#define	VV_DELETED	0x0400	
#define	VV_ETERNALDEV	0x0008	
#define	VV_FORCEINSMQ	0x1000	
#define	VV_ISTTY	0x0002	
#define	VV_MD		0x0800	
#define	VV_NOKNOTE	0x0200	
#define	VV_NOSYNC	0x0004	
#define	VV_PROCDEP	0x0100	
#define	VV_ROOT		0x0001	
#define	VV_SYSTEM	0x0080	
#define	VV_TEXT		0x0020	
#define	VWRITE			000000000200 
#define	VWRITE_ACL	 	000040000000 
#define	VWRITE_OWNER	 	000100000000 
#define	V_ALT		0x0002	
#define	V_NORMAL	0x0004	
#define	V_NOWAIT	0x0002	
#define	V_SAVE		0x0001	
#define	V_WAIT		0x0001	
#define	V_XSLEEP	0x0004	
#define	WRITECLOSE	0x0004	
#define textvp_fullpath(p, rb, rfb) \
	vn_fullpath(FIRST_THREAD_IN_PROC(p), (p)->p_textvp, rb, rfb)
#define	v_fifoinfo	v_un.vu_fifoinfo
#define	v_mountedhere	v_un.vu_mount
#define	v_rdev		v_un.vu_cdev
#define	v_socket	v_un.vu_socket
#define vn_lock(vp, flags) _vn_lock(vp, flags, "__FILE__", "__LINE__")
#define vprint(label, vp) vn_printf((vp), "%s\n", (label))
#define	KA_LOCKED	LA_LOCKED
#define	KA_NOTRECURSED	LA_NOTRECURSED
#define	KA_RECURSED	LA_RECURSED
#define	KA_SLOCKED	LA_SLOCKED
#define	KA_UNLOCKED	LA_UNLOCKED
#define	KA_XLOCKED	LA_XLOCKED
#define	LK_ADAPTIVE	0x000040
#define	LK_ALL_WAITERS							\
	(LK_SHARED_WAITERS | LK_EXCLUSIVE_WAITERS)
#define	LK_CANRECURSE	0x000001
#define	LK_DOWNGRADE	0x010000
#define	LK_DRAIN	0x020000
#define	LK_EATTR_MASK	0x00FF00
#define	LK_EXCLOTHER	0x040000
#define	LK_EXCLUSIVE	0x080000
#define	LK_EXCLUSIVE_SPINNERS		0x08
#define	LK_EXCLUSIVE_WAITERS		0x04
#define	LK_FLAGMASK							\
	(LK_SHARE | LK_ALL_WAITERS | LK_EXCLUSIVE_SPINNERS)
#define	LK_INIT_MASK	0x0000FF
#define	LK_INTERLOCK	0x000100
#define	LK_KERNPROC			((uintptr_t)(-1) & ~LK_FLAGMASK)
#define	LK_NODUP	0x000002
#define	LK_NOPROFILE	0x000004
#define	LK_NOSHARE	0x000008
#define	LK_NOWAIT	0x000200
#define	LK_NOWITNESS	0x000010
#define	LK_ONE_SHARER			(1 << LK_SHARERS_SHIFT)
#define	LK_PRIO_DEFAULT		(0)
#define	LK_QUIET	0x000020
#define	LK_RELEASE	0x100000
#define	LK_RETRY	0x000400
#define	LK_SHARE			0x01
#define	LK_SHARED	0x200000
#define	LK_SHARED_WAITERS		0x02
#define	LK_SHARERS_SHIFT		4
#define	LK_SLEEPFAIL	0x000800
#define	LK_TIMELOCK	0x001000
#define	LK_TIMO_DEFAULT		(0)
#define	LK_TOTAL_MASK	(LK_INIT_MASK | LK_EATTR_MASK | LK_TYPE_MASK)
#define	LK_TYPE_MASK	0xFF0000
#define	LK_UNLOCKED			LK_SHARERS_LOCK(0)
#define	LK_UPGRADE	0x400000
#define	LK_WMESG_DEFAULT	(NULL)
#define	lk_recurse	lock_object.lo_data
#define	STACK_MAX	18	
#define BO_BDFLUSH(bo, bp)	((bo)->bo_ops->bop_bdflush((bo), (bp)))
#define	BO_NEEDSGIANT	(1 << 2)	
#define	BO_ONWORKLST	(1 << 0)	
#define BO_STRATEGY(bo, bp)	((bo)->bo_ops->bop_strategy((bo), (bp)))
#define BO_SYNC(bo, w)		((bo)->bo_ops->bop_sync((bo), (w)))
#define BO_WRITE(bo, bp)	((bo)->bo_ops->bop_write((bp)))
#define	BO_WWAIT	(1 << 1)	

#define	UNPGC_DEAD			0x2	
#define	UNPGC_REF			0x1	
#define	UNPGC_SCANNED			0x4	
#define	UNP_BINDING			0x020	
#define	UNP_CONNECTING			0x010	
#define	UNP_CONNWAIT			0x008	
#define	UNP_WANTCRED			0x004	

#define	xu_addr	xu_au.xuu_addr
#define	LOCAL_CONNWAIT		0x004	
#define	LOCAL_CREDS		0x002	
#define	LOCAL_PEERCRED		0x001	
#define SUN_LEN(su) \
	(sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))

#define TASKQUEUE_DECLARE(name)			\
extern struct taskqueue *taskqueue_##name
#define TASKQUEUE_DEFINE(name, enqueue, context, init)			\
									\
struct taskqueue *taskqueue_##name;					\
									\
static void								\
taskqueue_define_##name(void *arg)					\
{									\
	taskqueue_##name =						\
	    taskqueue_create(#name, M_WAITOK, (enqueue), (context));	\
	init;								\
}									\
									\
SYSINIT(taskqueue_##name, SI_SUB_CONFIGURE, SI_ORDER_SECOND,		\
	taskqueue_define_##name, NULL);					\
									\
struct __hack
#define TASKQUEUE_DEFINE_THREAD(name)					\
TASKQUEUE_DEFINE(name, taskqueue_thread_enqueue, &taskqueue_##name,	\
	taskqueue_start_threads(&taskqueue_##name, 1, PWAIT,		\
	"%s taskq", #name))
#define TASKQUEUE_FAST_DEFINE(name, enqueue, context, init)		\
									\
struct taskqueue *taskqueue_##name;					\
									\
static void								\
taskqueue_define_##name(void *arg)					\
{									\
	taskqueue_##name =						\
	    taskqueue_create_fast(#name, M_WAITOK, (enqueue),		\
	    (context));							\
	init;								\
}									\
									\
SYSINIT(taskqueue_##name, SI_SUB_CONFIGURE, SI_ORDER_SECOND,		\
	taskqueue_define_##name, NULL);					\
									\
struct __hack
#define TASKQUEUE_FAST_DEFINE_THREAD(name)				\
TASKQUEUE_FAST_DEFINE(name, taskqueue_thread_enqueue,			\
	&taskqueue_##name, taskqueue_start_threads(&taskqueue_##name	\
	1, PWAIT, "%s taskq", #name))
#define TASK_INIT(task, priority, func, context) do {	\
	(task)->ta_pending = 0;				\
	(task)->ta_priority = (priority);		\
	(task)->ta_func = (func);			\
	(task)->ta_context = (context);			\
} while (0)


#define CALLOUT_HANDLE_INITIALIZER(handle)	\
	{ NULL }
#define	HASH_NOWAIT	0x00000001
#define	HASH_WAITOK	0x00000002
#define	HD_COLUMN_MASK	0xff
#define	HD_DELIM_MASK	0xff00
#define	HD_OMIT_CHARS	(1 << 18)
#define	HD_OMIT_COUNT	(1 << 16)
#define	HD_OMIT_HEX	(1 << 17)
#define ovbcopy(f, t, l) bcopy((f), (t), (l))
#define	FNM_CASEFOLD	0x10	
#define	FNM_FILE_NAME	FNM_PATHNAME
#define	FNM_IGNORECASE	FNM_CASEFOLD
#define	FNM_LEADING_DIR	0x08	
#define	FNM_NOESCAPE	0x01	
#define	FNM_NOMATCH	1	
#define	FNM_PATHNAME	0x02	
#define	FNM_PERIOD	0x04	
#define	GETS_ECHO	1	
#define	GETS_ECHOPASS	2	
#define	GETS_NOECHO	0	

#define	CTLFLAG_DYING	0x00010000	
#define	CTLTYPE_INT	2	
#define	CTLTYPE_LONG	7	
#define	CTLTYPE_NODE	1	
#define	CTLTYPE_OPAQUE	5	
#define	CTLTYPE_S64	4	
#define	CTLTYPE_STRING	3	
#define	CTLTYPE_STRUCT	CTLTYPE_OPAQUE	
#define	CTLTYPE_U64	9	
#define	CTLTYPE_UINT	6	
#define	CTLTYPE_ULONG	8	
#define	CTL_DEBUG	5		
#define	CTL_HW		6		
#define CTL_HW_NAMES { \
	{ 0, 0 }, \
	{ "machine", CTLTYPE_STRING }, \
	{ "model", CTLTYPE_STRING }, \
	{ "ncpu", CTLTYPE_INT }, \
	{ "byteorder", CTLTYPE_INT }, \
	{ "physmem", CTLTYPE_ULONG }, \
	{ "usermem", CTLTYPE_ULONG }, \
	{ "pagesize", CTLTYPE_INT }, \
	{ "disknames", CTLTYPE_STRUCT }, \
	{ "diskstats", CTLTYPE_STRUCT }, \
	{ "floatingpoint", CTLTYPE_INT }, \
	{ "machine_arch", CTLTYPE_STRING }, \
	{ "realmem", CTLTYPE_ULONG }, \
}
#define	CTL_KERN	1		
#define CTL_KERN_NAMES { \
	{ 0, 0 }, \
	{ "ostype", CTLTYPE_STRING }, \
	{ "osrelease", CTLTYPE_STRING }, \
	{ "osrevision", CTLTYPE_INT }, \
	{ "version", CTLTYPE_STRING }, \
	{ "maxvnodes", CTLTYPE_INT }, \
	{ "maxproc", CTLTYPE_INT }, \
	{ "maxfiles", CTLTYPE_INT }, \
	{ "argmax", CTLTYPE_INT }, \
	{ "securelevel", CTLTYPE_INT }, \
	{ "hostname", CTLTYPE_STRING }, \
	{ "hostid", CTLTYPE_UINT }, \
	{ "clockrate", CTLTYPE_STRUCT }, \
	{ "vnode", CTLTYPE_STRUCT }, \
	{ "proc", CTLTYPE_STRUCT }, \
	{ "file", CTLTYPE_STRUCT }, \
	{ "profiling", CTLTYPE_NODE }, \
	{ "posix1version", CTLTYPE_INT }, \
	{ "ngroups", CTLTYPE_INT }, \
	{ "job_control", CTLTYPE_INT }, \
	{ "saved_ids", CTLTYPE_INT }, \
	{ "boottime", CTLTYPE_STRUCT }, \
	{ "nisdomainname", CTLTYPE_STRING }, \
	{ "update", CTLTYPE_INT }, \
	{ "osreldate", CTLTYPE_INT }, \
	{ "ntp_pll", CTLTYPE_NODE }, \
	{ "bootfile", CTLTYPE_STRING }, \
	{ "maxfilesperproc", CTLTYPE_INT }, \
	{ "maxprocperuid", CTLTYPE_INT }, \
	{ "ipc", CTLTYPE_NODE }, \
	{ "dummy", CTLTYPE_INT }, \
	{ "ps_strings", CTLTYPE_INT }, \
	{ "usrstack", CTLTYPE_INT }, \
	{ "logsigexit", CTLTYPE_INT }, \
	{ "iov_max", CTLTYPE_INT }, \
	{ "hostuuid", CTLTYPE_STRING }, \
	{ "arc4rand", CTLTYPE_OPAQUE }, \
}
#define	CTL_MACHDEP	7		
#define	CTL_MAXID	10		
#define CTL_NAMES { \
	{ 0, 0 }, \
	{ "kern", CTLTYPE_NODE }, \
	{ "vm", CTLTYPE_NODE }, \
	{ "vfs", CTLTYPE_NODE }, \
	{ "net", CTLTYPE_NODE }, \
	{ "debug", CTLTYPE_NODE }, \
	{ "hw", CTLTYPE_NODE }, \
	{ "machdep", CTLTYPE_NODE }, \
	{ "user", CTLTYPE_NODE }, \
	{ "p1003_1b", CTLTYPE_NODE }, \
}
#define	CTL_NET		4		
#define	CTL_P1003_1B	9		
#define	CTL_UNSPEC	0		
#define	CTL_USER	8		
#define	CTL_VFS		3		
#define CTL_VFS_NAMES { \
	{ "vfsconf", CTLTYPE_STRUCT }, \
}
#define	CTL_VM		2		
#define	HW_BYTEORDER	 4		
#define	HW_DISKNAMES	 8		
#define	HW_DISKSTATS	 9		
#define	HW_MACHINE	 1		
#define	HW_MAXID	13		
#define	HW_MODEL	 2		
#define	HW_NCPU		 3		
#define	HW_PAGESIZE	 7		
#define	HW_PHYSMEM	 5		
#define	HW_REALMEM	12		
#define	HW_USERMEM	 6		
#define	KERN_ARGMAX	 	 8	
#define	KERN_ARND		37	
#define	KERN_BOOTFILE		26	
#define	KERN_BOOTTIME		21	
#define	KERN_CLOCKRATE		12	
#define	KERN_DUMMY		31	
#define	KERN_FILE		15	
#define	KERN_HOSTID		11	
#define	KERN_HOSTNAME		10	
#define	KERN_HOSTUUID		36	
#define	KERN_IOV_MAX		35	
#define	KERN_IPC		30	
#define	KERN_JOB_CONTROL	19	
#define	KERN_LOGSIGEXIT		34	
#define	KERN_MAXFILES	 	 7	
#define	KERN_MAXFILESPERPROC	27	
#define	KERN_MAXID		38	
#define	KERN_MAXPROC	 	 6	
#define	KERN_MAXVNODES	 	 5	
#define	KERN_NGROUPS		18	
#define	KERN_OSRELEASE	 	 2	
#define	KERN_OSREV	 	 3	
#define	KERN_OSTYPE	 	 1	
#define	KERN_POSIX1		17	
#define	KERN_PROC		14	
#define	KERN_PROC_ARGS		7	
#define	KERN_PROC_FILEDESC	33	
#define	KERN_PROC_GID		11	
#define	KERN_PROC_GROUPS	34	
#define	KERN_PROC_INC_THREAD	0x10	
#define	KERN_PROC_KSTACK	15	
#define	KERN_PROC_OFILEDESC	14	
#define	KERN_PROC_OVMMAP	13	
#define	KERN_PROC_PATHNAME	12	
#define	KERN_PROC_PGRP		2	
#define	KERN_PROC_PID		1	
#define	KERN_PROC_PROC		8	
#define	KERN_PROC_RGID		10	
#define	KERN_PROC_RUID		6	
#define	KERN_PROC_SESSION	3	
#define	KERN_PROC_SV_NAME	9	
#define	KERN_PROC_TTY		4	
#define	KERN_PROC_UID		5	
#define	KERN_PROC_VMMAP		32	
#define	KERN_PROF		16	
#define	KERN_PS_STRINGS		32	
#define	KERN_SAVED_IDS		20	
#define	KERN_SECURELVL	 	 9	
#define	KERN_USRSTACK		33	
#define	KERN_VERSION	 	 4	
#define	KERN_VNODE		13	
#define	KIPC_MAX_DATALEN	7	
#define	KIPC_MAX_HDR		6	
#define	KIPC_MAX_LINKHDR	4	
#define	KIPC_MAX_PROTOHDR	5	
#define	KIPC_SOCKBUF_WASTE	2	
#define	KIPC_SOMAXCONN		3	
#define	REQ_UNWIRED	1
#define	REQ_WIRED	2
#define	SCTL_MASK32	1	
#define SYSCTL_ADD_NODE(ctx, parent, nbr, name, access, handler, descr)	    \
	sysctl_add_oid(ctx, parent, nbr, name, CTLTYPE_NODE|(access),	    \
	NULL, 0, handler, "N", __DESCR(descr))
#define SYSCTL_ADD_OID(ctx, parent, nbr, name, kind, a1, a2, handler, fmt, descr) \
	sysctl_add_oid(ctx, parent, nbr, name, kind, a1, a2, handler, fmt, __DESCR(descr))
#define SYSCTL_ADD_OPAQUE(ctx, parent, nbr, name, access, ptr, len, fmt, descr)\
	sysctl_add_oid(ctx, parent, nbr, name, CTLTYPE_OPAQUE|(access),	    \
	ptr, len, sysctl_handle_opaque, fmt, __DESCR(descr))
#define SYSCTL_ADD_PROC(ctx, parent, nbr, name, access, ptr, arg, handler, fmt, descr) \
	sysctl_add_oid(ctx, parent, nbr, name, (access),			    \
	ptr, arg, handler, fmt, __DESCR(descr))
#define SYSCTL_ADD_STRING(ctx, parent, nbr, name, access, arg, len, descr)  \
	sysctl_add_oid(ctx, parent, nbr, name, CTLTYPE_STRING|(access),	    \
	arg, len, sysctl_handle_string, "A", __DESCR(descr))
#define SYSCTL_ADD_STRUCT(ctx, parent, nbr, name, access, ptr, type, descr) \
	sysctl_add_oid(ctx, parent, nbr, name, CTLTYPE_OPAQUE|(access),	    \
	ptr, sizeof(struct type), sysctl_handle_opaque, "S," #type, __DESCR(descr))
#define SYSCTL_DECL(name)					\
	extern struct sysctl_oid_list sysctl_##name##_children
#define SYSCTL_HANDLER_ARGS struct sysctl_oid *oidp, void *arg1,	\
	intptr_t arg2, struct sysctl_req *req
#define SYSCTL_IN(r, p, l) (r->newfunc)(r, p, l)
#define SYSCTL_NODE(parent, nbr, name, access, handler, descr)		    \
	struct sysctl_oid_list SYSCTL_NODE_CHILDREN(parent, name);	    \
	SYSCTL_OID(parent, nbr, name, CTLTYPE_NODE|(access),		    \
	    (void*)&SYSCTL_NODE_CHILDREN(parent, name), 0, handler, "N", descr)
#define SYSCTL_NODE_CHILDREN(parent, name) \
	sysctl_##parent##_##name##_children
#define SYSCTL_OID(parent, nbr, name, kind, a1, a2, handler, fmt, descr) \
	static struct sysctl_oid sysctl__##parent##_##name = {		 \
		&sysctl_##parent##_children, { NULL }, nbr, kind,	 \
		a1, a2, #name, handler, fmt, 0, 0, __DESCR(descr) };	 \
	DATA_SET(sysctl_set, sysctl__##parent##_##name)
#define SYSCTL_OPAQUE(parent, nbr, name, access, ptr, len, fmt, descr) \
	SYSCTL_OID(parent, nbr, name, CTLTYPE_OPAQUE|(access), \
		ptr, len, sysctl_handle_opaque, fmt, descr)
#define SYSCTL_OUT(r, p, l) (r->oldfunc)(r, p, l)
#define SYSCTL_PROC(parent, nbr, name, access, ptr, arg, handler, fmt, descr) \
	CTASSERT(((access) & CTLTYPE) != 0);				\
	SYSCTL_OID(parent, nbr, name, (access), \
		ptr, arg, handler, fmt, descr)
#define SYSCTL_STRING(parent, nbr, name, access, arg, len, descr) \
	SYSCTL_OID(parent, nbr, name, CTLTYPE_STRING|(access), \
		arg, len, sysctl_handle_string, "A", descr)
#define SYSCTL_STRUCT(parent, nbr, name, access, ptr, type, descr) \
	SYSCTL_OID(parent, nbr, name, CTLTYPE_OPAQUE|(access), \
		ptr, sizeof(struct type), sysctl_handle_opaque, \
		"S," #type, descr)
#define	USER_BC_BASE_MAX	 2	
#define	USER_BC_DIM_MAX		 3	
#define	USER_BC_SCALE_MAX	 4	
#define	USER_BC_STRING_MAX	 5	
#define	USER_COLL_WEIGHTS_MAX	 6	
#define	USER_CS_PATH		 1	
#define	USER_EXPR_NEST_MAX	 7	
#define	USER_LINE_MAX		 8	
#define	USER_MAXID		21	
#define	USER_POSIX2_CHAR_TERM	13	
#define	USER_POSIX2_C_BIND	11	
#define	USER_POSIX2_C_DEV	12	
#define	USER_POSIX2_FORT_DEV	14	
#define	USER_POSIX2_FORT_RUN	15	
#define	USER_POSIX2_LOCALEDEF	16	
#define	USER_POSIX2_SW_DEV	17	
#define	USER_POSIX2_UPE		18	
#define	USER_POSIX2_VERSION	10	
#define	USER_RE_DUP_MAX		 9	
#define	USER_STREAM_MAX		19	
#define	USER_TZNAME_MAX		20	
#define __DESCR(d) d
#define	ACCESSPERMS	(S_IRWXU|S_IRWXG|S_IRWXO)	
#define	ALLPERMS	(S_ISUID|S_ISGID|S_ISTXT|S_IRWXU|S_IRWXG|S_IRWXO)
#define	APPEND		(UF_APPEND | SF_APPEND)
#define	DEFFILEMODE	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)
#define	IMMUTABLE	(UF_IMMUTABLE | SF_IMMUTABLE)
#define	NOUNLINK	(UF_NOUNLINK | SF_NOUNLINK)
#define	OPAQUE		(UF_OPAQUE)
#define	SF_APPEND	0x00040000	
#define	SF_ARCHIVED	0x00010000	
#define	SF_IMMUTABLE	0x00020000	
#define	SF_NOUNLINK	0x00100000	
#define	SF_SETTABLE	0xffff0000	
#define	SF_SNAPSHOT	0x00200000	
#define	S_IEXEC		S_IXUSR
#define	S_IFBLK	 0060000		
#define	S_IFCHR	 0020000		
#define	S_IFDIR	 0040000		
#define	S_IFIFO	 0010000		
#define	S_IFLNK	 0120000		
#define	S_IFMT	 0170000		
#define	S_IFREG	 0100000		
#define	S_IREAD		S_IRUSR
#define	S_IRGRP	0000040			
#define	S_IROTH	0000004			
#define	S_IRUSR	0000400			
#define	S_IRWXG	0000070			
#define	S_IRWXO	0000007			
#define	S_IRWXU	0000700			
#define	S_ISGID	0002000			
#define	S_ISTXT	0001000			
#define	S_ISUID	0004000			
#define	S_ISVTX	 0001000		
#define	S_IWGRP	0000020			
#define	S_IWOTH	0000002			
#define	S_IWRITE	S_IWUSR
#define	S_IWUSR	0000200			
#define	S_IXGRP	0000010			
#define	S_IXOTH	0000001			
#define	S_IXUSR	0000100			
#define	UF_APPEND	0x00000004	
#define	UF_IMMUTABLE	0x00000002	
#define	UF_NODUMP	0x00000001	
#define	UF_SETTABLE	0x0000ffff	
#define	st_atime		st_atim.tv_sec
#define	st_atimespec		st_atim
#define	st_birthtime		st_birthtim.tv_sec
#define	st_birthtimespec	st_birthtim
#define	st_ctime		st_ctim.tv_sec
#define	st_ctimespec		st_ctim
#define	st_mtime		st_mtim.tv_sec
#define	st_mtimespec		st_mtim
#define	SBL_NOINTR	0x00000002	
#define	SBL_VALID	(SBL_WAIT | SBL_NOINTR)
#define	SBL_WAIT	0x00000001	
#define	SO_RCV		1
#define	SO_SND		2
#define	SQ_COMP			0x1000	
#define	SQ_INCOMP		0x0800	
#define	SU_ISCONNECTED	1
#define	SU_OK		0


#define	SBS_CANTRCVMORE		0x0020	
#define	SBS_CANTSENDMORE	0x0010	
#define	SBS_RCVATMARK		0x0040	
#define	SS_ASYNC		0x0200	
#define	SS_ISCONFIRMING		0x0400	
#define	SS_ISCONNECTED		0x0002	
#define	SS_ISCONNECTING		0x0004	
#define	SS_ISDISCONNECTED	0x2000	
#define	SS_ISDISCONNECTING	0x0008	
#define	SS_NBIO			0x0100	
#define	SS_NOFDREF		0x0001	
#define	SS_PROTOREF		0x4000	

#define	SB_AIO		0x80		
#define	SB_ASYNC	0x10		
#define	SB_AUTOSIZE	0x800		
#define SB_EMPTY_FIXUP(sb) do {						\
	if ((sb)->sb_mb == NULL) {					\
		(sb)->sb_mbtail = NULL;					\
		(sb)->sb_lastrecord = NULL;				\
	}								\
} while (0)
#define	SB_IN_TOE	0x400		
#define	SB_KNOTE	0x100		
#define	SB_MAX		(2*1024*1024)	
#define	SB_NOCOALESCE	0x200		
#define	SB_NOINTR	0x40		
#define	SB_SEL		0x08		
#define	SB_UPCALL	0x20		
#define	SB_WAIT		0x04		

#define	sb_startzero	sb_mb
#define	AF_APPLETALK	16		
#define	AF_ARP		35
#define	AF_ATM		30		
#define	AF_BLUETOOTH	36		
#define	AF_CCITT	10		
#define	AF_CHAOS	5		
#define	AF_CNT		21		
#define	AF_COIP		20		
#define	AF_DATAKIT	9		
#define	AF_E164		AF_ISDN		
#define	AF_ECMA		8		
#define	AF_HYLINK	15		
#define	AF_IEEE80211	37		
#define	AF_IMPLINK	3		
#define	AF_INET		2		
#define	AF_INET6	28		
#define	AF_IPX		23		
#define	AF_ISDN		26		
#define	AF_ISO		7		
#define	AF_LINK		18		
#define	AF_LOCAL	AF_UNIX		
#define	AF_MAX		38
#define	AF_NATM		29		
#define	AF_NETBIOS	6		
#define	AF_NETGRAPH	32		
#define	AF_OSI		AF_ISO
#define	AF_PUP		4		
#define	AF_ROUTE	17		
#define	AF_SCLUSTER	34		
#define	AF_SIP		24		
#define	AF_SLOW		33		
#define	AF_SNA		11		
#define	AF_UNIX		1		
#define	AF_UNSPEC	0		
#define AF_VENDOR00 39
#define AF_VENDOR01 41
#define AF_VENDOR02 43
#define AF_VENDOR03 45
#define AF_VENDOR04 47
#define AF_VENDOR05 49
#define AF_VENDOR06 51
#define AF_VENDOR07 53
#define AF_VENDOR08 55
#define AF_VENDOR09 57
#define AF_VENDOR10 59
#define AF_VENDOR11 61
#define AF_VENDOR12 63
#define AF_VENDOR13 65
#define AF_VENDOR14 67
#define AF_VENDOR15 69
#define AF_VENDOR16 71
#define AF_VENDOR17 73
#define AF_VENDOR18 75
#define AF_VENDOR19 77
#define AF_VENDOR20 79
#define AF_VENDOR21 81
#define AF_VENDOR22 83
#define AF_VENDOR23 85
#define AF_VENDOR24 87
#define AF_VENDOR25 89
#define AF_VENDOR26 91
#define AF_VENDOR27 93
#define AF_VENDOR28 95
#define AF_VENDOR29 97
#define AF_VENDOR30 99
#define AF_VENDOR31 101
#define AF_VENDOR32 103
#define AF_VENDOR33 105
#define AF_VENDOR34 107
#define AF_VENDOR35 109
#define AF_VENDOR36 111
#define AF_VENDOR37 113
#define AF_VENDOR38 115
#define AF_VENDOR39 117
#define AF_VENDOR40 119
#define AF_VENDOR41 121
#define AF_VENDOR42 123
#define AF_VENDOR43 125
#define AF_VENDOR44 127
#define AF_VENDOR45 129
#define AF_VENDOR46 131
#define AF_VENDOR47 133
#define CMGROUP_MAX 16
#define CTL_NET_NAMES { \
	{ 0, 0 }, \
	{ "unix", CTLTYPE_NODE }, \
	{ "inet", CTLTYPE_NODE }, \
	{ "implink", CTLTYPE_NODE }, \
	{ "pup", CTLTYPE_NODE }, \
	{ "chaos", CTLTYPE_NODE }, \
	{ "xerox_ns", CTLTYPE_NODE }, \
	{ "iso", CTLTYPE_NODE }, \
	{ "emca", CTLTYPE_NODE }, \
	{ "datakit", CTLTYPE_NODE }, \
	{ "ccitt", CTLTYPE_NODE }, \
	{ "ibm_sna", CTLTYPE_NODE }, \
	{ "decnet", CTLTYPE_NODE }, \
	{ "dec_dli", CTLTYPE_NODE }, \
	{ "lat", CTLTYPE_NODE }, \
	{ "hylink", CTLTYPE_NODE }, \
	{ "appletalk", CTLTYPE_NODE }, \
	{ "route", CTLTYPE_NODE }, \
	{ "link_layer", CTLTYPE_NODE }, \
	{ "xtp", CTLTYPE_NODE }, \
	{ "coip", CTLTYPE_NODE }, \
	{ "cnt", CTLTYPE_NODE }, \
	{ "rtip", CTLTYPE_NODE }, \
	{ "ipx", CTLTYPE_NODE }, \
	{ "sip", CTLTYPE_NODE }, \
	{ "pip", CTLTYPE_NODE }, \
	{ "isdn", CTLTYPE_NODE }, \
	{ "key", CTLTYPE_NODE }, \
	{ "inet6", CTLTYPE_NODE }, \
	{ "natm", CTLTYPE_NODE }, \
	{ "atm", CTLTYPE_NODE }, \
	{ "hdrcomplete", CTLTYPE_NODE }, \
	{ "netgraph", CTLTYPE_NODE }, \
	{ "snp", CTLTYPE_NODE }, \
	{ "scp", CTLTYPE_NODE }, \
}
#define CTL_NET_RT_NAMES { \
	{ 0, 0 }, \
	{ "dump", CTLTYPE_STRUCT }, \
	{ "flags", CTLTYPE_STRUCT }, \
	{ "iflist", CTLTYPE_STRUCT }, \
	{ "ifmalist", CTLTYPE_STRUCT }, \
}
#define	MSG_CTRUNC	0x20		
#define	MSG_DONTROUTE	0x4		
#define	MSG_DONTWAIT	0x80		
#define	MSG_EOF		0x100		
#define	MSG_EOR		0x8		
#define	MSG_NBIO	0x4000		
#define	MSG_NOSIGNAL	0x20000		
#define MSG_NOTIFICATION 0x2000         
#define	MSG_OOB		0x1		
#define	MSG_PEEK	0x2		
#define	MSG_TRUNC	0x10		
#define	MSG_WAITALL	0x40		
#define	NET_RT_IFMALIST	4		
#define	NET_RT_MAXID	5
#define	PF_APPLETALK	AF_APPLETALK
#define	PF_ARP		AF_ARP
#define	PF_ATM		AF_ATM
#define	PF_BLUETOOTH	AF_BLUETOOTH
#define	PF_CCITT	AF_CCITT
#define	PF_CHAOS	AF_CHAOS
#define	PF_CNT		AF_CNT
#define	PF_COIP		AF_COIP
#define	PF_DATAKIT	AF_DATAKIT
#define	PF_ECMA		AF_ECMA
#define	PF_HYLINK	AF_HYLINK
#define	PF_IMPLINK	AF_IMPLINK
#define	PF_INET		AF_INET
#define	PF_INET6	AF_INET6
#define	PF_IPX		AF_IPX
#define	PF_ISDN		AF_ISDN
#define	PF_ISO		AF_ISO
#define	PF_KEY		pseudo_AF_KEY
#define	PF_LINK		AF_LINK
#define	PF_LOCAL	AF_LOCAL
#define	PF_MAX		AF_MAX
#define	PF_NATM		AF_NATM
#define	PF_NETBIOS	AF_NETBIOS
#define	PF_NETGRAPH	AF_NETGRAPH
#define	PF_OSI		AF_ISO
#define	PF_PUP		AF_PUP
#define	PF_ROUTE	AF_ROUTE
#define	PF_SIP		AF_SIP
#define	PF_SLOW		AF_SLOW
#define	PF_SNA		AF_SNA
#define	PF_UNIX		PF_LOCAL	
#define	PF_UNSPEC	AF_UNSPEC
#define	PF_XTP		pseudo_AF_XTP	
#define PRU_FLUSH_RD     SHUT_RD
#define PRU_FLUSH_RDWR   SHUT_RDWR
#define PRU_FLUSH_WR     SHUT_WR
#define	SCM_BINTIME	0x04		
#define	SCM_CREDS	0x03		
#define	SCM_RIGHTS	0x01		
#define	SCM_TIMESTAMP	0x02		
#define	SF_MNOWAIT	0x00000002
#define	SF_SYNC		0x00000004
#define	SHUT_RD		0		
#define	SHUT_RDWR	2		
#define	SHUT_WR		1		
#define	SOCK_DGRAM	2		
#define	SOCK_MAXADDRLEN	255		
#define	SOCK_RAW	3		
#define	SOCK_RDM	4		
#define	SOCK_SEQPACKET	5		
#define	SOCK_STREAM	1		
#define	SOL_SOCKET	0xffff		
#define	SOMAXCONN	128
#define	SO_ACCEPTCONN	0x0002		
#define	SO_ACCEPTFILTER	0x1000		
#define	SO_BINTIME	0x2000		
#define	SO_BROADCAST	0x0020		
#define	SO_DEBUG	0x0001		
#define	SO_DONTROUTE	0x0010		
#define	SO_ERROR	0x1007		
#define	SO_KEEPALIVE	0x0008		
#define	SO_LABEL	0x1009		
#define	SO_LINGER	0x0080		
#define	SO_LISTENINCQLEN	0x1013	
#define	SO_LISTENQLEN	0x1012		
#define	SO_LISTENQLIMIT	0x1011		
#define	SO_NOSIGPIPE	0x0800		
#define	SO_NO_DDP	0x8000		
#define	SO_NO_OFFLOAD	0x4000		
#define	SO_OOBINLINE	0x0100		
#define	SO_PEERLABEL	0x1010		
#define	SO_RCVBUF	0x1002		
#define	SO_RCVLOWAT	0x1004		
#define	SO_RCVTIMEO	0x1006		
#define	SO_REUSEADDR	0x0004		
#define	SO_REUSEPORT	0x0200		
#define	SO_SETFIB	0x1014		
#define	SO_SNDBUF	0x1001		
#define	SO_SNDLOWAT	0x1003		
#define	SO_SNDTIMEO	0x1005		
#define	SO_TIMESTAMP	0x0400		
#define	SO_TYPE		0x1008		
#define	SO_USELOOPBACK	0x0040		
#define	SO_USER_COOKIE	0x1015		
#define pseudo_AF_HDRCMPLT 31		
#define	pseudo_AF_KEY	27		
#define	pseudo_AF_PIP	25		
#define	pseudo_AF_XTP	19		
#define	_SS_ALIGNSIZE	(sizeof(__int64_t))
#define	_SS_MAXSIZE	128U
#define	_SS_PAD1SIZE	(_SS_ALIGNSIZE - sizeof(unsigned char) - \
			    sizeof(sa_family_t))
#define	_SS_PAD2SIZE	(_SS_MAXSIZE - sizeof(unsigned char) - \
			    sizeof(sa_family_t) - _SS_PAD1SIZE - _SS_ALIGNSIZE)
#define	pstat_endcopy	p_start
#define	pstat_endzero	pstat_startcopy
#define	pstat_startcopy	p_prof
#define	pstat_startzero	p_cru
#define	PRCO_GETOPT	0
#define	PRCO_NCMDS	2
#define	PRCO_SETOPT	1
#define	PRC_HOSTDEAD		6	
#define	PRC_HOSTUNREACH		7	
#define	PRC_IFDOWN		0	
#define	PRC_IFUP		2 	
#define	PRC_MSGSIZE		5	
#define	PRC_NCMDS		22
#define	PRC_PARAMPROB		20	
#define	PRC_QUENCH		4	
#define	PRC_QUENCH2		3	
#define	PRC_REDIRECT_HOST	15	
#define	PRC_REDIRECT_NET	14	
#define	PRC_REDIRECT_TOSHOST	17	
#define	PRC_REDIRECT_TOSNET	16	
#define	PRC_ROUTEDEAD		1	
#define	PRC_TIMXCEED_INTRANS	18	
#define	PRC_TIMXCEED_REASS	19	
#define	PRC_UNREACH_ADMIN_PROHIB	21	
#define	PRC_UNREACH_HOST	9	
#define	PRC_UNREACH_NET		8	
#define	PRC_UNREACH_PORT	11	
#define	PRC_UNREACH_PROTOCOL	10	
#define	PRC_UNREACH_SRCFAIL	13	
#define	PROTO_SPACER	32767		
#define	PRUS_EOF	0x2
#define	PRUS_MORETOCOME	0x4
#define	PRUS_OOB	0x1
#define	PRU_ABORT		10	
#define	PRU_ACCEPT		5	
#define	PRU_ATTACH		0	
#define	PRU_BIND		2	
#define	PRU_CLOSE		24	
#define	PRU_CONNECT		4	
#define	PRU_CONNECT2		17	
#define	PRU_CONTROL		11	
#define	PRU_DETACH		1	
#define	PRU_DISCONNECT		6	
#define	PRU_FASTTIMO		18	
#define	PRU_FLUSH		25	
#define	PRU_LISTEN		3	
#define	PRU_NREQ		25
#define	PRU_PEERADDR		16	
#define	PRU_PROTORCV		20	
#define	PRU_PROTOSEND		21	
#define	PRU_RCVD		8	
#define	PRU_RCVOOB		13	
#define	PRU_SEND		9	
#define	PRU_SENDOOB		14	
#define	PRU_SENSE		12	
#define	PRU_SHUTDOWN		7	
#define	PRU_SLOWTIMO		19	
#define	PRU_SOCKADDR		15	
#define	PRU_SOSETLABEL		23	
#define	PR_ADDR		0x02		
#define	PR_ATOMIC	0x01		
#define	PR_CONNREQUIRED	0x04		
#define	PR_FASTHZ	5		
#define	PR_LASTHDR	0x40		
#define	PR_RIGHTS	0x10		
#define	PR_SLOWHZ	2		
#define	PR_WANTRCVD	0x08		

#define	AUDITVNODE1	0x04000000 
#define	CREATE		1	
#define	DELETE		2	
#define	DOWHITEOUT	0x00040000 
#define	FOLLOW		0x0040	
#define	GIANTHELD	0x02000000 
#define	HASBUF		0x00000400 
#define	ISDOTDOT	0x00002000 
#define	ISLASTCN	0x00008000 
#define	ISOPEN		0x00200000 
#define	ISSYMLINK	0x00010000 
#define	ISUNICODE	0x00100000 
#define	ISWHITEOUT	0x00020000 
#define	LOCKLEAF	0x0004	
#define	LOCKPARENT	0x0008	
#define	LOCKSHARED	0x0100	
#define	LOOKUP		0	
#define	MAKEENTRY	0x00004000 
#define	MODMASK		0x01fc	
#define	MPSAFE		0x01000000 
#define	NOCACHE		0x0020	
#define	NOCROSSMOUNT	0x00400000 
#define	NOFOLLOW	0x0000	
#define	NOMACCHECK	0x00800000 
#define	OPMASK		3	
#define	PARAMASK	0x1ffffe00 
#define	RDONLY		0x00000200 
#define	RENAME		3	
#define	SAVENAME	0x00000800 
#define	SAVESTART	0x00001000 
#define	TRAILINGSLASH	0x10000000 
#define	WANTPARENT	0x0010	
#define	WILLBEDIR	0x00080000 
#define	MAXFIDSZ	16
#define	MAXSECFLAVORS	5
#define	MBF_MASK	(MBF_NOWAIT | MBF_MNTLSTLOCK)
#define	MBF_MNTLSTLOCK	0x02
#define	MBF_NOWAIT	0x01
#define	MFSNAMELEN	16		
#define	MNAMELEN	88		
#define	MNTK_DRAINING	0x00000010	
#define	MNTK_MPSAFE	0x20000000	
#define	MNTK_MWAIT	0x02000000	
#define	MNTK_NOKNOTE	0x80000000	
#define	MNTK_REFEXPIRE	0x00000020	
#define	MNTK_SHARED_WRITES	0x00000080 
#define	MNTK_SUSPEND	0x08000000	
#define	MNTK_SUSPEND2	0x04000000	
#define	MNTK_SUSPENDED	0x10000000	
#define	MNT_ACLS	0x0000000008000000ULL 
#define	MNT_ASYNC	0x0000000000000040ULL 
#define	MNT_BYFSID	0x0000000008000000ULL 
#define MNT_CMDFLAGS   (MNT_UPDATE	| MNT_DELEXPORT	| MNT_RELOAD	| \
			MNT_FORCE	| MNT_SNAPSHOT	| MNT_BYFSID)
#define	MNT_DEFEXPORTED	0x0000000000000200ULL	
#define	MNT_DELEXPORT	0x0000000000020000ULL 
#define	MNT_EXKERB	0x0000000000000800ULL	
#define	MNT_EXPORTANON	0x0000000000000400ULL	
#define	MNT_EXPORTED	0x0000000000000100ULL	
#define	MNT_EXPUBLIC	0x0000000020000000ULL	
#define	MNT_EXRDONLY	0x0000000000000080ULL	
#define	MNT_FORCE	0x0000000000080000ULL 
#define	MNT_GJOURNAL	0x0000000002000000ULL 
#define	MNT_IGNORE	0x0000000000800000ULL 
#define	MNT_LOCAL	0x0000000000001000ULL 
#define	MNT_MULTILABEL	0x0000000004000000ULL 
#define	MNT_NFS4ACLS	0x0000000000000010ULL 
#define	MNT_NOATIME	0x0000000010000000ULL 
#define	MNT_NOCLUSTERR	0x0000000040000000ULL 
#define	MNT_NOCLUSTERW	0x0000000080000000ULL 
#define	MNT_NOEXEC	0x0000000000000004ULL 
#define	MNT_NOSUID	0x0000000000000008ULL 
#define	MNT_NOSYMFOLLOW	0x0000000000400000ULL 
#define	MNT_QUOTA	0x0000000000002000ULL 
#define	MNT_RDONLY	0x0000000000000001ULL 
#define	MNT_RELOAD	0x0000000000040000ULL 
#define	MNT_ROOTFS	0x0000000000004000ULL 
#define	MNT_SNAPSHOT	0x0000000001000000ULL 
#define	MNT_SOFTDEP	0x0000000000200000ULL 
#define	MNT_SUIDDIR	0x0000000000100000ULL 
#define	MNT_SUJ		0x0000000100000000ULL 
#define	MNT_SYNCHRONOUS	0x0000000000000002ULL 
#define	MNT_UNION	0x0000000000000020ULL 
#define	MNT_UPDATE	0x0000000000010000ULL 
#define	MNT_USER	0x0000000000008000ULL 
#define	MNT_VISFLAGMASK	(MNT_RDONLY	| MNT_SYNCHRONOUS | MNT_NOEXEC	| \
			MNT_NOSUID	| MNT_UNION	| MNT_SUJ	| \
			MNT_ASYNC	| MNT_EXRDONLY	| MNT_EXPORTED	| \
			MNT_DEFEXPORTED	| MNT_EXPORTANON| MNT_EXKERB	| \
			MNT_LOCAL	| MNT_USER	| MNT_QUOTA	| \
			MNT_ROOTFS	| MNT_NOATIME	| MNT_NOCLUSTERR| \
			MNT_NOCLUSTERW	| MNT_SUIDDIR	| MNT_SOFTDEP	| \
			MNT_IGNORE	| MNT_EXPUBLIC	| MNT_NOSYMFOLLOW | \
			MNT_GJOURNAL	| MNT_MULTILABEL | MNT_ACLS	| \
			MNT_NFS4ACLS)
#define MNT_VNODE_FOREACH(vp, mp, mvp) \
	for (vp = __mnt_vnode_first(&(mvp), (mp)); \
		(vp) != NULL; vp = __mnt_vnode_next(&(mvp), (mp)))
#define MNT_VNODE_FOREACH_ABORT(mp, mvp)				\
        do {								\
	  MNT_ILOCK(mp);						\
          MNT_VNODE_FOREACH_ABORT_ILOCKED(mp, mvp);			\
	  MNT_IUNLOCK(mp);						\
	} while (0)
#define MNT_VNODE_FOREACH_ABORT_ILOCKED(mp, mvp)			\
	__mnt_vnode_markerfree(&(mvp), (mp))
#define	OMFSNAMELEN	16	
#define	OMNAMELEN	(88 - 2 * sizeof(long))	
#define	STATFS_VERSION	0x20030518	
#define VCTLTOREQ(vc, req)						\
	do {								\
		(req)->newptr = (vc)->vc_ptr;				\
		(req)->newlen = (vc)->vc_len;				\
		(req)->newidx = 0;					\
	} while (0)
#define	VFCF_DELEGADMIN	0x00800000	
#define	VFCF_JAIL	0x00400000	
#define	VFCF_LOOPBACK	0x00100000	
#define	VFCF_NETWORK	0x00020000	
#define	VFCF_READONLY	0x00040000	
#define	VFCF_STATIC	0x00010000	
#define	VFCF_SYNTHETIC	0x00080000	
#define	VFCF_UNICODE	0x00200000	
#define VFS_CHECKEXP(MP, NAM, EXFLG, CRED, NUMSEC, SEC)	\
	(*(MP)->mnt_op->vfs_checkexp)(MP, NAM, EXFLG, CRED, NUMSEC, SEC)
#define VFS_FHTOVP(MP, FIDP, FLAGS, VPP) \
	(*(MP)->mnt_op->vfs_fhtovp)(MP, FIDP, FLAGS, VPP)
#define	VFS_GENERIC		0	
#define VFS_KNOTE_LOCKED(vp, hint) do					\
{									\
	if (((vp)->v_vflag & VV_NOKNOTE) == 0)				\
		VN_KNOTE((vp), (hint), KNF_LISTLOCKED);			\
} while (0)
#define VFS_KNOTE_UNLOCKED(vp, hint) do					\
{									\
	if (((vp)->v_vflag & VV_NOKNOTE) == 0)				\
		VN_KNOTE((vp), (hint), 0);				\
} while (0)
#define VFS_SET(vfsops, fsname, flags) \
	static struct vfsconf fsname ## _vfsconf = {		\
		.vfc_version = VFS_VERSION,			\
		.vfc_name = #fsname,				\
		.vfc_vfsops = &vfsops,				\
		.vfc_typenum = -1,				\
		.vfc_flags = flags,				\
	};							\
	static moduledata_t fsname ## _mod = {			\
		#fsname,					\
		vfs_modevent,					\
		& fsname ## _vfsconf				\
	};							\
	DECLARE_MODULE(fsname, fsname ## _mod, SI_SUB_VFS, SI_ORDER_MIDDLE)
#define VFS_SYSCTL(MP, OP, REQ) \
	(*(MP)->mnt_op->vfs_sysctl)(MP, OP, REQ)
#define	VFS_VFSCONF		0	
#define VFS_VGET(MP, INO, FLAGS, VPP) \
	(*(MP)->mnt_op->vfs_vget)(MP, INO, FLAGS, VPP)

#define	mnt_endzero	mnt_gjprovider
#define	mnt_startzero	mnt_list
#define	MAXMODNAME	32
#define	MDT_DEPEND	1		
#define	MDT_MODULE	2		
#define	MDT_SETNAME	"modmetadata_set"
#define	MDT_STRUCT_VERSION	1	
#define	MDT_VERSION	3		
#define	MODULE_KERNEL_MAXVER	(roundup(__FreeBSD_version, 100000) - 1)
#define	MOD_DEBUG_REFS	1
#define	MOD_LOCK_ASSERT	sx_assert(&modules_sx, SX_LOCKED)
#define	MOD_SLOCK	sx_slock(&modules_sx)
#define	MOD_SUNLOCK	sx_sunlock(&modules_sx)
#define	MOD_XLOCK	sx_xlock(&modules_sx)
#define	MOD_XLOCK_ASSERT	sx_assert(&modules_sx, SX_XLOCKED)
#define	MOD_XUNLOCK	sx_xunlock(&modules_sx)

#define	CSUM_DATA_VALID		0x0400		
#define	CSUM_DELAY_DATA		(CSUM_TCP | CSUM_UDP)
#define	CSUM_DELAY_IP		(CSUM_IP)	
#define	CSUM_FRAGMENT		0x0010		
#define	CSUM_IP			0x0001		
#define	CSUM_IP_CHECKED		0x0100		
#define	CSUM_IP_FRAGS		0x0008		
#define	CSUM_IP_VALID		0x0200		
#define	CSUM_PSEUDO_HDR		0x0800		
#define	CSUM_SCTP		0x0040		
#define	CSUM_SCTP_VALID		0x1000		
#define	CSUM_TCP		0x0002		
#define	CSUM_TSO		0x0020		
#define	CSUM_UDP		0x0004		
#define	EXT_CLUSTER	1	
#define	EXT_DISPOSABLE	300	
#define	EXT_EXTREF	400	
#define	EXT_JUMBO16	5	
#define	EXT_JUMBO9	4	
#define	EXT_JUMBOP	3	
#define	EXT_MBUF	7	
#define	EXT_MOD_TYPE	200	
#define	EXT_NET_DRV	100	
#define	EXT_PACKET	6	
#define	EXT_SFBUF	2	
#define	MBUF_CLUSTER_MEM_NAME	"mbuf_cluster"
#define	MBUF_EXTREFCNT_MEM_NAME	"mbuf_ext_refcnt"
#define	MBUF_JUMBO16_MEM_NAME	"mbuf_jumbo_16k"
#define	MBUF_JUMBO9_MEM_NAME	"mbuf_jumbo_9k"
#define	MBUF_JUMBOP_MEM_NAME	"mbuf_jumbo_page"
#define	MBUF_MEM_NAME		"mbuf"
#define	MBUF_PACKET_MEM_NAME	"mbuf_packet"
#define	MBUF_TAG_MEM_NAME	"mbuf_tag"
#define	MHLEN		(MLEN - sizeof(struct pkthdr))	
#define	MINCLSIZE	(MHLEN + 1)	
#define	MLEN		(MSIZE - sizeof(struct m_hdr))	
#define	MTAG_ABI_COMPAT		0		
#define	MTAG_PERSISTENT				0x800
#define	MT_CONTROL	14	
#define	MT_DATA		1	
#define	MT_HEADER	MT_DATA	
#define	MT_NOINIT	255	
#define	MT_NOTMBUF	0	
#define	MT_NTYPES	16	
#define	MT_OOBDATA	15	
#define	MT_SONAME	8	
#define	M_BCAST		0x00000200 
#define	M_COPYALL	1000000000
#define	M_DONTWAIT	M_NOWAIT
#define	M_EOR		0x00000004 
#define	M_EXT		0x00000001 
#define	M_FIB		0xF0000000 
#define M_FIBSHIFT    28
#define	M_FIRSTFRAG	0x00001000 
#define	M_FLOWID	0x00400000 
#define	M_FRAG		0x00000800 
#define	M_FREELIST	0x00008000 
#define M_GETFIB(_m) \
    ((((_m)->m_flags & M_FIB) >> M_FIBSHIFT) & M_FIBMASK)
#define	M_HASHTYPEBITS	0x0F000000 
#define	M_HASHTYPE_NONE			0x0
#define	M_HASHTYPE_OPAQUE		0xf	
#define	M_HASHTYPE_RSS_IPV4		0x1	
#define	M_HASHTYPE_RSS_IPV6		0x3	
#define	M_HASHTYPE_RSS_IPV6_EX		0x5	
#define	M_HASHTYPE_RSS_TCP_IPV4		0x2	
#define	M_HASHTYPE_RSS_TCP_IPV6		0x4	
#define	M_HASHTYPE_RSS_TCP_IPV6_EX	0x6	
#define	M_HASHTYPE_SHIFT		24
#define M_HDR_PAD    6
#define	M_LASTFRAG	0x00002000 
#define	M_MAXCOMPRESS	(MHLEN / 2)	
#define	M_MCAST		0x00000400 
#define	M_NOFREE	0x00040000 
#define	M_NOTIFICATION	M_PROTO5    
#define	M_PKTHDR	0x00000002 
 #define M_PROFILE(m) m_profile(m)
#define	M_PROMISC	0x00020000 
#define	M_PROTO1	0x00000010 
#define	M_PROTO2	0x00000020 
#define	M_PROTO3	0x00000040 
#define	M_PROTO4	0x00000080 
#define	M_PROTO5	0x00000100 
#define	M_PROTO6	0x00080000 
#define	M_PROTO7	0x00100000 
#define	M_PROTO8	0x00200000 
#define	M_RDONLY	0x00000008 
#define M_SETFIB(_m, _fib) do {						\
	_m->m_flags &= ~M_FIB;					   	\
	_m->m_flags |= (((_fib) << M_FIBSHIFT) & M_FIB);  \
} while (0) 
#define	M_SKIP_FIREWALL	0x00004000 
#define	M_TRYWAIT	M_WAITOK
#define	M_VLANTAG	0x00010000 
#define	M_WAIT		M_WAITOK
#define	PACKET_TAG_BRIDGE			7  
#define	PACKET_TAG_CARP				28 
#define	PACKET_TAG_DIVERT			17 
#define	PACKET_TAG_DUMMYNET			15 
#define	PACKET_TAG_ENCAP			11 
#define	PACKET_TAG_GIF				8  
#define	PACKET_TAG_GRE				9  
#define	PACKET_TAG_IN_PACKET_CHECKSUM		10 
#define	PACKET_TAG_IPFORWARD			18 
#define	PACKET_TAG_IPOPTIONS			27 
#define	PACKET_TAG_IPSEC_HISTORY		13 
#define	PACKET_TAG_IPSEC_IN_COULD_DO_CRYPTO	5  
#define	PACKET_TAG_IPSEC_IN_CRYPTO_DONE		3  
#define	PACKET_TAG_IPSEC_IN_DONE		1  
#define	PACKET_TAG_IPSEC_NAT_T_PORTS		29 
#define	PACKET_TAG_IPSEC_OUT_CRYPTO_NEEDED	4  
#define	PACKET_TAG_IPSEC_OUT_DONE		2  
#define	PACKET_TAG_IPSEC_PENDING_TDB		6  
#define	PACKET_TAG_IPSEC_SOCKET			12 
#define	PACKET_TAG_IPV6_INPUT			14 
#define	PACKET_TAG_MACLABEL	(19 | MTAG_PERSISTENT) 
#define	PACKET_TAG_ND_OUTGOING			30 
#define	PACKET_TAG_NONE				0  
#define	PACKET_TAG_PF				21 
#define	PACKET_TAG_RTSOCKFAM			25 
#define	m_act		m_nextpkt
#define	m_dat		M_dat.M_databuf
#define	m_data		m_hdr.mh_data
#define	m_ext		M_dat.MH.MH_dat.MH_ext
#define	m_flags		m_hdr.mh_flags
#define	m_len		m_hdr.mh_len
#define	m_next		m_hdr.mh_next
#define	m_nextpkt	m_hdr.mh_nextpkt
#define	m_pktdat	M_dat.MH.MH_dat.MH_databuf
#define	m_pkthdr	M_dat.MH.MH_pkthdr
#define	m_type		m_hdr.mh_type
#define	DTYPE_CAPABILITY	12	
#define	DTYPE_CRYPTO	6	
#define	DTYPE_DEV	11	
#define	DTYPE_FIFO	4	
#define	DTYPE_KQUEUE	5	
#define	DTYPE_MQUEUE	7	
#define	DTYPE_PIPE	3	
#define	DTYPE_PROCDESC	13	
#define	DTYPE_PTS	10	
#define	DTYPE_SEM	9	
#define	DTYPE_SHM	8	
#define	DTYPE_SOCKET	2	
#define	DTYPE_VNODE	1	
#define	FOF_OFFSET	1	

#define	F_OK		0	
#define	L_INCR		SEEK_CUR
#define	L_SET		SEEK_SET
#define	L_XTND		SEEK_END
#define	RFCENVG		(1<<11)	
#define	RFCFDG		(1<<12)	
#define	RFCNAMEG	(1<<10)	
#define	RFENVG		(1<<1)	
#define	RFFDG		(1<<2)	
#define	RFFLAGS		(RFFDG | RFPROC | RFMEM | RFNOWAIT | RFCFDG | \
    RFTHREAD | RFSIGSHARE | RFLINUXTHPN | RFSTOPPED | RFHIGHPID | RFTSIGZMB | \
    RFPROCDESC | RFPPWAIT)
#define	RFHIGHPID	(1<<18)	
#define	RFKERNELONLY	(RFSTOPPED | RFHIGHPID | RFPPWAIT | RFPROCDESC)
#define	RFLINUXTHPN	(1<<16)	
#define	RFMEM		(1<<5)	
#define	RFNAMEG		(1<<0)	
#define	RFNOTEG		(1<<3)	
#define	RFNOWAIT	(1<<6)	
#define	RFPPWAIT	(1<<31)	
#define	RFPROC		(1<<4)	
#define	RFPROCDESC	(1<<28)	
#define	RFSIGSHARE	(1<<14)	
#define	RFSTOPPED	(1<<17)	
#define	RFTHREAD	(1<<13)	
#define	RFTSIGMASK	0xFF
#define	RFTSIGSHIFT	20	
#define	RFTSIGZMB	(1<<19)	
#define	R_OK		0x04	
#define	SEEK_CUR	1	
#define	SEEK_DATA	3	
#define	SEEK_END	2	
#define	SEEK_HOLE	4	
#define	SEEK_SET	0	
#define	W_OK		0x02	
#define	X_OK		0x01	
#define	_PC_ACL_EXTENDED	59
#define	_PC_ACL_NFS4		64
#define	_PC_ACL_PATH_MAX	60
#define	_PC_ALLOC_SIZE_MIN	10
#define	_PC_ASYNC_IO		53
#define	_PC_CAP_PRESENT		61
#define	_PC_CHOWN_RESTRICTED	 7
#define	_PC_FILESIZEBITS	12
#define	_PC_INF_PRESENT		62
#define	_PC_LINK_MAX		 1
#define	_PC_MAC_PRESENT		63
#define	_PC_MAX_CANON		 2
#define	_PC_MAX_INPUT		 3
#define	_PC_MIN_HOLE_SIZE	21
#define	_PC_NAME_MAX		 4
#define	_PC_NO_TRUNC		 8
#define	_PC_PATH_MAX		 5
#define	_PC_PIPE_BUF		 6
#define	_PC_PRIO_IO		54
#define	_PC_REC_INCR_XFER_SIZE	14
#define	_PC_REC_MAX_XFER_SIZE	15
#define	_PC_REC_MIN_XFER_SIZE	16
#define	_PC_REC_XFER_ALIGN	17
#define	_PC_SYMLINK_MAX		18
#define	_PC_SYNC_IO		55
#define	_PC_VDISABLE		 9
#define	_POSIX_ADVISORY_INFO		-1
#define	_POSIX_ASYNCHRONOUS_IO		0
#define	_POSIX_CHOWN_RESTRICTED		1
#define	_POSIX_CLOCK_SELECTION		-1
#define	_POSIX_CPUTIME			-1
#define	_POSIX_FSYNC			200112L
#define	_POSIX_IPV6			0
#define	_POSIX_JOB_CONTROL		1
#define	_POSIX_MAPPED_FILES		200112L
#define	_POSIX_MEMLOCK			-1
#define	_POSIX_MEMLOCK_RANGE		200112L
#define	_POSIX_MEMORY_PROTECTION	200112L
#define	_POSIX_MESSAGE_PASSING		200112L
#define	_POSIX_MONOTONIC_CLOCK		200112L
#define	_POSIX_NO_TRUNC			1
#define	_POSIX_PRIORITIZED_IO		-1
#define	_POSIX_PRIORITY_SCHEDULING	200112L
#define	_POSIX_RAW_SOCKETS		200112L
#define	_POSIX_REALTIME_SIGNALS		200112L
#define	_POSIX_SAVED_IDS	1 
#define	_POSIX_SEMAPHORES		200112L
#define	_POSIX_SHARED_MEMORY_OBJECTS	200112L
#define	_POSIX_SPORADIC_SERVER		-1
#define	_POSIX_SYNCHRONIZED_IO		-1
#define	_POSIX_TIMEOUTS			200112L
#define	_POSIX_TIMERS			200112L
#define	_POSIX_TYPED_MEMORY_OBJECTS	-1
#define	_POSIX_VDISABLE			0xff
#define	_POSIX_VERSION		200112L
#define	_XOPEN_SHM			1
#define	_XOPEN_STREAMS			-1
#define	AT_EACCESS		0x100	
#define	AT_FDCWD		-100
#define	AT_REMOVEDIR		0x800	
#define	AT_SYMLINK_FOLLOW	0x400	
#define	AT_SYMLINK_NOFOLLOW	0x200   
#define	FAPPEND		O_APPEND	
#define	FASYNC		O_ASYNC		
#define	FCNTLFLAGS	(FAPPEND|FASYNC|FFSYNC|FNONBLOCK|FRDAHEAD|O_DIRECT)
#define	FD_CLOEXEC	1		
#define	FEXEC		O_EXEC
#define	FFSYNC		O_FSYNC		
#define	FHASLOCK	0x4000		
#define	FMASK	(FREAD|FWRITE|FAPPEND|FASYNC|FFSYNC|FNONBLOCK|O_DIRECT|FEXEC)
#define	FNDELAY		O_NONBLOCK	
#define	FNONBLOCK	O_NONBLOCK	
#define	FPOSIXSHM	O_NOFOLLOW
#define	FRDAHEAD	O_CREAT
#define	FREAD		0x0001
#define	FWRITE		0x0002
#define	F_CANCEL	5		
#define	F_DUP2FD	10		
#define	F_DUPFD		0		
#define	F_FLOCK		0x020	 	
#define	F_GETFD		1		
#define	F_GETFL		3		
#define	F_GETLK		11		
#define	F_GETOWN	5		
#define	F_OGETLK	7		
#define	F_OSETLK	8		
#define	F_OSETLKW	9		
#define	F_POSIX		0x040	 	
#define	F_RDAHEAD	16		
#define	F_RDLCK		1		
#define	F_READAHEAD	15		
#define	F_REMOTE	0x080		
#define	F_SETFD		2		
#define	F_SETFL		4		
#define	F_SETLK		12		
#define	F_SETLKW	13		
#define	F_SETLK_REMOTE	14		
#define	F_UNLCK		2		
#define	F_UNLCKSYS	4		 
#define	F_WAIT		0x010		
#define	F_WRLCK		3		
#define	LOCK_EX		0x02		
#define	LOCK_NB		0x04		
#define	LOCK_SH		0x01		
#define	LOCK_UN		0x08		
#define	O_ACCMODE	0x0003		
#define	O_APPEND	0x0008		
#define	O_ASYNC		0x0040		
#define	O_CLOEXEC	0x00100000
#define	O_CREAT		0x0200		
#define	O_DIRECTORY	0x00020000	
#define	O_EXCL		0x0800		
#define	O_EXEC		0x00040000	
#define	O_EXLOCK	0x0020		
#define	O_FSYNC		0x0080		
#define	O_NDELAY	O_NONBLOCK	
#define	O_NOCTTY	0x8000		
#define	O_NOFOLLOW	0x0100		
#define	O_NONBLOCK	0x0004		
#define	O_RDONLY	0x0000		
#define	O_RDWR		0x0002		
#define	O_SHLOCK	0x0010		
#define	O_SYNC		0x0080		
#define	O_TRUNC		0x0400		
#define	O_TTY_INIT	0x00080000	
#define	O_WRONLY	0x0001		

