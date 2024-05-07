

#include<linux/socket.h>

#include<linux/sched.h>
#include<asm/stat.h>
#include<asm/msgbuf.h>






#include<linux/in.h>

#include<linux/fs.h>



#include<asm/fcntl.h>



#include<linux/auxvec.h>



#include<asm/socket.h>




#include<asm/resource.h>
#include<linux/time.h>




#include<asm/ioctl.h>
#include<asm/types.h>
#include<linux/rtnetlink.h>


#include<linux/wait.h>



#include<asm/poll.h>

#include<linux/stat.h>
#include<asm/signal.h>




#include<linux/timex.h>

#include<linux/capability.h>


#include<linux/sem.h>

#include<linux/ipv6.h>

#include<linux/netdevice.h>
#include<linux/poll.h>
#include<asm/sembuf.h>
#include<linux/sysctl.h>


#include<linux/ipc.h>



#include<asm/ipcbuf.h>
#include<linux/errno.h>

#include<asm/posix_types.h>
#include<asm/param.h>
#include<asm/siginfo.h>
#include<linux/in6.h>

#include<asm/termios.h>
#include<linux/aio_abi.h>



#include<asm/shmbuf.h>


#include<linux/icmpv6.h>

#include<asm/byteorder.h>


#include<linux/kernel.h>
#include<linux/resource.h>

#include<linux/if.h>
#include<linux/uio.h>

#include<asm/errno.h>
#include<linux/module.h>


#include<stdarg.h>




#include<linux/string.h>





#include<asm/ptrace.h>
#include<linux/sctp.h>

#include<asm/auxvec.h>



#include<linux/fcntl.h>






#include<linux/types.h>
#include<linux/stddef.h>


#include<linux/signal.h>

#include<linux/ip.h>




#include<asm/sockios.h>








#define SCTP_ASSERT(expr, str, func) \
	if (!(expr)) { \
		SCTP_DEBUG_PRINTK("Assertion Failed: %s(%s) at %s:%s:%d\n", \
			str, (#expr), "__FILE__", __FUNCTION__, "__LINE__"); \
		func; \
	}
#define SCTP_DBG_OBJCNT(name) \
atomic_t sctp_dbg_objcnt_## name = ATOMIC_INIT(0)
#define SCTP_DBG_OBJCNT_DEC(name) \
atomic_dec(&sctp_dbg_objcnt_## name)
#define SCTP_DBG_OBJCNT_ENTRY(name) \
{.label= #name, .counter= &sctp_dbg_objcnt_## name}
#define SCTP_DBG_OBJCNT_INC(name) \
atomic_inc(&sctp_dbg_objcnt_## name)
#define SCTP_DEBUG      0
#define SCTP_DEBUG_PRINTK(whatever...) \
	((void) (sctp_debug_flag && printk(KERN_DEBUG whatever)))
#define SCTP_DEBUG_PRINTK_IPADDR(lead, trail, leadparm, saddr, otherparms...) \
	if (sctp_debug_flag) { \
		if (saddr->sa.sa_family == AF_INET6) { \
			printk(KERN_DEBUG \
			       lead NIP6_FMT trail, \
			       leadparm, \
			       NIP6(saddr->v6.sin6_addr), \
			       otherparms); \
		} else { \
			printk(KERN_DEBUG \
			       lead NIPQUAD_FMT trail, \
			       leadparm, \
			       NIPQUAD(saddr->v4.sin_addr.s_addr), \
			       otherparms); \
		} \
	}
#define SCTP_DEC_STATS(field)      SNMP_DEC_STATS(sctp_statistics, field)
#define SCTP_DISABLE_DEBUG { sctp_debug_flag = 0; }
#define SCTP_ENABLE_DEBUG { sctp_debug_flag = 1; }
#define SCTP_INC_STATS(field)      SNMP_INC_STATS(sctp_statistics, field)
#define SCTP_INC_STATS_BH(field)   SNMP_INC_STATS_BH(sctp_statistics, field)
#define SCTP_INC_STATS_USER(field) SNMP_INC_STATS_USER(sctp_statistics, field)
#define SCTP_PROTOSW_FLAG 0
#define SCTP_SAT_LEN(x) (sizeof(struct sctp_paramhdr) + (x) * sizeof(__u16))
#define SCTP_SOCK_SLEEP_POST(sk) SOCK_SLEEP_POST(sk)
#define SCTP_SOCK_SLEEP_PRE(sk)  SOCK_SLEEP_PRE(sk)
#define SCTP_STATIC static
#define TIMEVAL_ADD(tv1, tv2) \
({ \
        suseconds_t usecs = (tv2).tv_usec + (tv1).tv_usec; \
        time_t secs = (tv2).tv_sec + (tv1).tv_sec; \
\
        if (usecs >= 1000000) { \
                usecs -= 1000000; \
                secs++; \
        } \
        (tv2).tv_sec = secs; \
        (tv2).tv_usec = usecs; \
})
#define WORD_ROUND(s) (((s)+3)&~3)

#define _sctp_walk_errors(err, chunk_hdr, end)\
for (err = (sctp_errhdr_t *)((void *)chunk_hdr + \
	    sizeof(sctp_chunkhdr_t));\
     (void *)err <= (void *)chunk_hdr + end - sizeof(sctp_errhdr_t) &&\
     (void *)err <= (void *)chunk_hdr + end - ntohs(err->length) &&\
     ntohs(err->length) >= sizeof(sctp_errhdr_t); \
     err = (sctp_errhdr_t *)((void *)err + WORD_ROUND(ntohs(err->length))))
#define _sctp_walk_fwdtsn(pos, chunk, end)\
for (pos = chunk->subh.fwdtsn_hdr->skip;\
     (void *)pos <= (void *)chunk->subh.fwdtsn_hdr->skip + end - sizeof(struct sctp_fwdtsn_skip);\
     pos++)
#define _sctp_walk_params(pos, chunk, end, member)\
for (pos.v = chunk->member;\
     pos.v <= (void *)chunk + end - sizeof(sctp_paramhdr_t) &&\
     pos.v <= (void *)chunk + end - ntohs(pos.p->length) &&\
     ntohs(pos.p->length) >= sizeof(sctp_paramhdr_t);\
     pos.v += WORD_ROUND(ntohs(pos.p->length)))
#define sctp_bh_lock_sock(sk)    bh_lock_sock(sk)
#define sctp_bh_unlock_sock(sk)  bh_unlock_sock(sk)
#define sctp_crypto_alloc_tfm crypto_alloc_tfm
#define sctp_crypto_free_tfm crypto_free_tfm
#define sctp_crypto_hmac crypto_hmac
#define sctp_local_bh_disable() local_bh_disable()
#define sctp_local_bh_enable()  local_bh_enable()
#define sctp_lock_sock(sk)       lock_sock(sk)
#define sctp_read_lock(lock)    read_lock(lock)
#define sctp_read_unlock(lock)  read_unlock(lock)
#define sctp_release_sock(sk)    release_sock(sk)
#define sctp_skb_for_each(pos, head, tmp) \
for (pos = (head)->next;\
     tmp = (pos)->next, pos != ((struct sk_buff *)(head));\
     pos = tmp)
#define sctp_spin_lock(lock)    spin_lock(lock)
#define sctp_spin_lock_irqsave(lock, flags) spin_lock_irqsave(lock, flags)
#define sctp_spin_unlock(lock)  spin_unlock(lock)
#define sctp_spin_unlock_irqrestore(lock, flags)  \
       spin_unlock_irqrestore(lock, flags)
#define sctp_sstate(sk, state) __sctp_sstate((sk), (SCTP_SS_##state))
#define sctp_state(asoc, state) __sctp_state((asoc), (SCTP_STATE_##state))
#define sctp_style(sk, style) __sctp_style((sk), (SCTP_SOCKET_##style))
#define sctp_walk_errors(err, chunk_hdr)\
_sctp_walk_errors((err), (chunk_hdr), ntohs((chunk_hdr)->length))
#define sctp_walk_fwdtsn(pos, chunk)\
_sctp_walk_fwdtsn((pos), (chunk), ntohs((chunk)->chunk_hdr->length) - sizeof(struct sctp_fwdtsn_chunk))
#define sctp_walk_params(pos, chunk, member)\
_sctp_walk_params((pos), (chunk), ntohs((chunk)->chunk_hdr.length), member)
#define sctp_write_lock(lock)   write_lock(lock)
#define sctp_write_unlock(lock) write_unlock(lock)
#define t_new(type, flags)	(type *)kmalloc(sizeof(type), flags)
#define tv_lt(s, t) \
   (s.tv_sec < t.tv_sec || (s.tv_sec == t.tv_sec && s.tv_usec < t.tv_usec))
#define IS_IPV4_LINK_ADDRESS(a) \
	((((unsigned char *)(a))[0] == 169) && \
	(((unsigned char *)(a))[1] == 254))
#define IS_IPV4_PRIVATE_ADDRESS(a) \
	((((unsigned char *)(a))[0] == 10) || \
	((((unsigned char *)(a))[0] == 172) && \
	(((unsigned char *)(a))[1] >= 16) && \
	(((unsigned char *)(a))[1] < 32)) || \
	((((unsigned char *)(a))[0] == 192) && \
	(((unsigned char *)(a))[1] == 168)))
#define IS_IPV4_UNUSABLE_ADDRESS(a) \
	((INADDR_BROADCAST == *a) || \
	(MULTICAST(*a)) || \
	(((unsigned char *)(a))[0] == 0) || \
	((((unsigned char *)(a))[0] == 198) && \
	(((unsigned char *)(a))[1] == 18) && \
	(((unsigned char *)(a))[2] == 0)) || \
	((((unsigned char *)(a))[0] == 192) && \
	(((unsigned char *)(a))[1] == 88) && \
	(((unsigned char *)(a))[2] == 99)))
#define SCTP_COOKIE_HMAC_ALG "md5"
#define SCTP_COOKIE_MULTIPLE 32 
#define SCTP_DATA_SNDSIZE(c) ((int)((unsigned long)(c->chunk_end)\
		       		- (unsigned long)(c->chunk_hdr)\
				- sizeof(sctp_data_chunk_t)))
#define SCTP_DEFAULT_MAXSEGMENT 1500	
#define SCTP_DEFAULT_MINSEGMENT 512	
#define SCTP_DEF_MAX_INIT 6
#define SCTP_DEF_MAX_SEND 10
#define SCTP_EVENT_T_MAX SCTP_EVENT_T_PRIMITIVE
#define SCTP_EVENT_T_NUM (SCTP_EVENT_T_MAX + 1)
#define SCTP_HOW_LONG_COOKIE_LIVE 3600	
#define SCTP_HOW_MANY_SECRETS 2		
#define SCTP_MAX_ERROR_CAUSE  SCTP_ERROR_NONEXIST_IP
#define SCTP_NUM_ERROR_CAUSE  10
#define SCTP_RTO_ALPHA          3   
#define SCTP_RTO_BETA           2   
#define SCTP_SECRET_SIZE 32		
#define SCTP_SIGNATURE_SIZE 20	        
#define SCTP_SUBTYPE_CONSTRUCTOR(_name, _type, _elt) \
static inline sctp_subtype_t	\
SCTP_ST_## _name (_type _arg)		\
{ sctp_subtype_t _retval; _retval._elt = _arg; return _retval; }
#define SCTP_TSN_MAP_SIZE 2048
#define SCTP_TSN_MAX_GAP  65535

#define sctp_chunk_is_control(a) (a->chunk_hdr->type != SCTP_CID_DATA)
#define sctp_chunk_is_data(a) (a->chunk_hdr->type == SCTP_CID_DATA)

#define MSG_NOTIFICATION MSG_NOTIFICATION
#define SCTP_ADAPTION_LAYER SCTP_ADAPTION_LAYER
#define SCTP_ASSOCINFO SCTP_ASSOCINFO
#define SCTP_AUTOCLOSE SCTP_AUTOCLOSE
#define SCTP_BINDX_ADD_ADDR 0x01
#define SCTP_BINDX_REM_ADDR 0x02
#define SCTP_DEFAULT_SEND_PARAM SCTP_DEFAULT_SEND_PARAM
#define SCTP_DELAYED_ACK_TIME SCTP_DELAYED_ACK_TIME
#define SCTP_DISABLE_FRAGMENTS SCTP_DISABLE_FRAGMENTS
#define SCTP_EVENTS SCTP_EVENTS
#define SCTP_GET_PEER_ADDR_INFO SCTP_GET_PEER_ADDR_INFO
#define SCTP_INITMSG SCTP_INITMSG
#define SCTP_I_WANT_MAPPED_V4_ADDR SCTP_I_WANT_MAPPED_V4_ADDR
#define SCTP_MAXSEG 	SCTP_MAXSEG
#define SCTP_PEER_ADDR_PARAMS SCTP_PEER_ADDR_PARAMS
#define SCTP_PRIMARY_ADDR SCTP_PRIMARY_ADDR
#define SCTP_RTOINFO SCTP_RTOINFO
#define SCTP_SET_PEER_PRIMARY_ADDR SCTP_SET_PEER_PRIMARY_ADDR
#define SCTP_STATUS SCTP_STATUS

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
#define BITS_PER_BYTE 8
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

#define SIOCBONDCHANGEACTIVE   0x8995   
#define SIOCBONDINFOQUERY      0x8994	
#define SIOCBONDRELEASE 0x8991		
#define SIOCBONDSETHWADDR      0x8992	
#define SIOCBONDSLAVEINFOQUERY 0x8993   
#define SIOCBRADDBR     0x89a0		
#define SIOCBRDELBR     0x89a1		
#define SIOCPROTOPRIVATE 0x89E0 

#define INET6_MATCH(__sk, __hash, __saddr, __daddr, __ports, __dif)\
	(((__sk)->sk_hash == (__hash))				&& \
	 ((*((__u32 *)&(inet_sk(__sk)->dport))) == (__ports))  	&& \
	 ((__sk)->sk_family		== AF_INET6)		&& \
	 ipv6_addr_equal(&inet6_sk(__sk)->daddr, (__saddr))	&& \
	 ipv6_addr_equal(&inet6_sk(__sk)->rcv_saddr, (__daddr))	&& \
	 (!((__sk)->sk_bound_dev_if) || ((__sk)->sk_bound_dev_if == (__dif))))
#define IP6CB(skb)	((struct inet6_skb_parm*)((skb)->cb))

#define __inet6_rcv_saddr(__sk)	NULL
#define __ipv6_only_sock(sk)	(inet6_sk(sk)->ipv6only)
#define inet6_rcv_saddr(__sk)	NULL
#define inet_v6_ipv6only(__sk)		0
#define ipv6_destopt_hdr ipv6_opt_hdr
#define ipv6_hopopt_hdr  ipv6_opt_hdr
#define ipv6_only_sock(sk)	((sk)->sk_family == PF_INET6 && __ipv6_only_sock(sk))
#define ipv6_optlen(p)  (((p)->hdrlen+1) << 3)
#define tcp_twsk_ipv6only(__sk)		0

#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)

#define LIMIT_NETDEBUG(fmt, args...) do { if (net_ratelimit()) printk(fmt,##args); } while(0)
#define NETDEBUG(fmt, args...)	printk(fmt,##args)
#define SK_STREAM_MEM_QUANTUM ((int)PAGE_SIZE)
#define SOCK_DEBUG(sk, msg...) do { if ((sk) && sock_flag((sk), SOCK_DBG)) \
					printk(KERN_DEBUG msg); } while (0)

#define SOCK_DESTROY_TIME (10*HZ)
#define SOCK_MIN_RCVBUF 256
#define SOCK_MIN_SNDBUF 2048
#define SOCK_SLEEP_POST(sk)	tsk->state = TASK_RUNNING; \
				remove_wait_queue((sk)->sk_sleep, &wait); \
				lock_sock(sk); \
				}
#define SOCK_SLEEP_PRE(sk) 	{ struct task_struct *tsk = current; \
				DECLARE_WAITQUEUE(wait, tsk); \
				tsk->state = TASK_INTERRUPTIBLE; \
				add_wait_queue((sk)->sk_sleep, &wait); \
				release_sock(sk);

#define bh_lock_sock(__sk)	spin_lock(&((__sk)->sk_lock.slock))
#define bh_lock_sock_nested(__sk) \
				spin_lock_nested(&((__sk)->sk_lock.slock), \
				SINGLE_DEPTH_NESTING)
#define bh_unlock_sock(__sk)	spin_unlock(&((__sk)->sk_lock.slock))
#define sk_for_each(__sk, node, list) \
	hlist_for_each_entry(__sk, node, list, sk_node)
#define sk_for_each_bound(__sk, node, list) \
	hlist_for_each_entry(__sk, node, list, sk_bind_node)
#define sk_for_each_continue(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_node; 1; })) \
		hlist_for_each_entry_continue(__sk, node, sk_node)
#define sk_for_each_from(__sk, node) \
	if (__sk && ({ node = &(__sk)->sk_node; 1; })) \
		hlist_for_each_entry_from(__sk, node, sk_node)
#define sk_for_each_safe(__sk, node, tmp, list) \
	hlist_for_each_entry_safe(__sk, node, tmp, list, sk_node)
#define sk_refcnt_debug_dec(sk) do { } while (0)
#define sk_refcnt_debug_inc(sk) do { } while (0)
#define sk_refcnt_debug_release(sk) do { } while (0)
#define sk_stream_for_retrans_queue(skb, sk)				\
		for (skb = (sk)->sk_write_queue.next;			\
		     (skb != (sk)->sk_send_head) &&			\
		     (skb != (struct sk_buff *)&(sk)->sk_write_queue);	\
		     skb = skb->next)
#define sk_stream_for_retrans_queue_from(skb, sk)			\
		for (; (skb != (sk)->sk_send_head) &&                   \
		     (skb != (struct sk_buff *)&(sk)->sk_write_queue);	\
		     skb = skb->next)
#define sk_wait_event(__sk, __timeo, __condition)		\
({	int rc;							\
	release_sock(__sk);					\
	rc = __condition;					\
	if (!rc) {						\
		*(__timeo) = schedule_timeout(*(__timeo));	\
	}							\
	lock_sock(__sk);					\
	rc = __condition;					\
	rc;							\
})
#define sock_owned_by_user(sk)	((sk)->sk_lock.owner)

#define ERESTART_RESTARTBLOCK 516 

#define DST_BALANCED            0x10

#define LOCALLY_ENQUEUED 0x1
#define NEIGH_CACHE_STAT_INC(tbl, field)				\
	do {								\
		preempt_disable();					\
		(per_cpu_ptr((tbl)->stats, smp_processor_id())->field)++; \
		preempt_enable();					\
	} while (0)
#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)
#define CTL_MAXNAME 10		

#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define HLIST_HEAD_INIT { .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)
#define LIST_HEAD_INIT(name) { &(name), &(name) }

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
#define list_for_each_entry_from(pos, head, member) 			\
	for (; prefetch(pos->member.next), &pos->member != (head);	\
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
#define list_for_each_entry_safe_from(pos, n, head, member) 			\
	for (n = list_entry(pos->member.next, typeof(*pos), member);		\
	     &pos->member != (head);						\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_entry((head)->prev, typeof(*pos), member),	\
		n = list_entry(pos->member.prev, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.prev, typeof(*n), member))
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
#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

#define ALIGN(x,a) (((x)+(a)-1)&~((a)-1))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define BUILD_BUG_ON_ZERO(e) (sizeof(char[1 - 2 * !!(e)]) - 1)
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
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
#define NIP6_FMT "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x"
#define NIP6_SEQFMT "%04x%04x%04x%04x%04x%04x%04x%04x"
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

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
#define might_sleep_if(cond) do { if (cond) might_sleep(); } while (0)
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
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
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

#define ALIGN_STR __ALIGN_STR
#define ATTRIB_NORET  __attribute__((noreturn))
#define CPP_ASMLINKAGE extern "C"
#define END(name) \
  .size name, .-name
#define ENDPROC(name) \
  .type name, @function; \
  END(name)
#define ENTRY(name) \
  .globl name; \
  ALIGN; \
  name:
#define FASTCALL(x)	x
#define KPROBE_ENTRY(name) \
  .section .kprobes.text, "ax"; \
  ENTRY(name)
#define NORET_AND     noreturn,
#define NORET_TYPE    

#define asmlinkage CPP_ASMLINKAGE

# define prevent_tail_call(ret) do { } while (0)
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

#define SEQ_START_TOKEN ((void *)1)

#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)
# define __DEBUG_MUTEX_INITIALIZER(lockname)
# define __DEP_MAP_MUTEX_INITIALIZER(lockname) \
		, .dep_map = { .name = #lockname }

#define __MUTEX_INITIALIZER(lockname) \
		{ .count = ATOMIC_INIT(1) \
		, .wait_lock = SPIN_LOCK_UNLOCKED \
		, .wait_list = LIST_HEAD_INIT(lockname.wait_list) \
		__DEBUG_MUTEX_INITIALIZER(lockname) \
		__DEP_MAP_MUTEX_INITIALIZER(lockname) }
# define mutex_destroy(mutex)				do { } while (0)
# define mutex_init(mutex) \
do {							\
	static struct lock_class_key __key;		\
							\
	__mutex_init((mutex), #mutex, &__key);		\
} while (0)
# define mutex_lock_nested(lock, subclass) mutex_lock(lock)
# define INIT_LOCKDEP
#define LOCKF_ENABLED_IRQS (LOCKF_ENABLED_HARDIRQS | LOCKF_ENABLED_SOFTIRQS)
#define LOCKF_ENABLED_IRQS_READ \
		(LOCKF_ENABLED_HARDIRQS_READ | LOCKF_ENABLED_SOFTIRQS_READ)
#define LOCKF_USED_IN_IRQ (LOCKF_USED_IN_HARDIRQ | LOCKF_USED_IN_SOFTIRQ)
#define LOCKF_USED_IN_IRQ_READ \
		(LOCKF_USED_IN_HARDIRQ_READ | LOCKF_USED_IN_SOFTIRQ_READ)

# define early_boot_irqs_off()			do { } while (0)
# define early_boot_irqs_on()			do { } while (0)
# define early_init_irq_lock_class()		do { } while (0)
# define lock_acquire(l, s, t, r, c, i)		do { } while (0)
# define lock_release(l, n, i)			do { } while (0)
# define lockdep_free_key_range(start, size)	do { } while (0)
# define lockdep_info()				do { } while (0)
# define lockdep_init()				do { } while (0)
# define lockdep_init_map(lock, name, key)	do { (void)(key); } while (0)
# define lockdep_reset()		do { debug_locks = 1; } while (0)
# define lockdep_set_class(lock, key)		do { (void)(key); } while (0)
# define lockdep_set_class_and_name(lock, key, name) \
		do { (void)(key); } while (0)
#  define mutex_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, i)
# define mutex_release(l, n, i)			lock_release(l, n, i)
#  define rwlock_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, i)
#  define rwlock_acquire_read(l, s, t, i)	lock_acquire(l, s, t, 2, 2, i)
# define rwlock_release(l, n, i)		lock_release(l, n, i)
#  define rwsem_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, i)
#  define rwsem_acquire_read(l, s, t, i)	lock_acquire(l, s, t, 1, 2, i)
# define rwsem_release(l, n, i)			lock_release(l, n, i)
#  define spin_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, i)
# define spin_release(l, n, i)			lock_release(l, n, i)

# define print_stack_trace(trace)			do { } while (0)
# define save_stack_trace(trace, task, all, skip)	do { } while (0)
#define DEBUG_LOCKS_WARN_ON(c)						\
({									\
	int __ret = 0;							\
									\
	if (unlikely(c)) {						\
		if (debug_locks_off())					\
			WARN_ON(1);					\
		__ret = 1;						\
	}								\
	__ret;								\
})
# define SMP_DEBUG_LOCKS_WARN_ON(c)			DEBUG_LOCKS_WARN_ON(c)
#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })

# define locking_selftest()	do { } while (0)
#define DEFINE_RWLOCK(x)	rwlock_t x = __RW_LOCK_UNLOCKED(x)
#define DEFINE_SPINLOCK(x)	spinlock_t x = __SPIN_LOCK_UNLOCKED(x)
# define RW_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }
# define SPIN_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }

#define __RW_LOCK_UNLOCKED(lockname)					\
	(rwlock_t)	{	.raw_lock = __RAW_RW_LOCK_UNLOCKED,	\
				.magic = RWLOCK_MAGIC,			\
				.owner = SPINLOCK_OWNER_INIT,		\
				.owner_cpu = -1,			\
				RW_DEP_MAP_INIT(lockname) }
# define __SPIN_LOCK_UNLOCKED(lockname)					\
	(spinlock_t)	{	.raw_lock = __RAW_SPIN_LOCK_UNLOCKED,	\
				.magic = SPINLOCK_MAGIC,		\
				.owner = SPINLOCK_OWNER_INIT,		\
				.owner_cpu = -1,			\
				SPIN_DEP_MAP_INIT(lockname) }

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
#define rcu_read_lock() \
	do { \
		preempt_disable(); \
		__acquire(RCU); \
	} while(0)
#define rcu_read_lock_bh() \
	do { \
		local_bh_disable(); \
		__acquire(RCU_BH); \
	} while(0)
#define rcu_read_unlock() \
	do { \
		__release(RCU); \
		preempt_enable(); \
	} while(0)
#define rcu_read_unlock_bh() \
	do { \
		__release(RCU_BH); \
		local_bh_enable(); \
	} while(0)
#define synchronize_sched() synchronize_rcu()
#define DEFINE_SEQLOCK(x) \
		seqlock_t x = __SEQLOCK_UNLOCKED(x)
#define SEQCNT_ZERO { 0 }
#define SEQLOCK_UNLOCKED \
		 __SEQLOCK_UNLOCKED(old_style_seqlock_init)

#define __SEQLOCK_UNLOCKED(lockname) \
		 { 0, __SPIN_LOCK_UNLOCKED(lockname) }
#define read_seqbegin_irqsave(lock, flags)				\
	({ local_irq_save(flags);   read_seqbegin(lock); })
#define read_seqretry_irqrestore(lock, iv, flags)			\
	({								\
		int ret = read_seqretry(lock, iv);			\
		local_irq_restore(flags);				\
		ret;							\
	})
#define seqcount_init(x)	do { *(x) = (seqcount_t) SEQCNT_ZERO; } while (0)
#define seqlock_init(x) \
		do { *(x) = (seqlock_t) __SEQLOCK_UNLOCKED(x); } while (0)
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
	barrier(); \
	preempt_check_resched(); \
} while (0)
#define preempt_enable_no_resched() \
do { \
	barrier(); \
	dec_preempt_count(); \
} while (0)
# define sub_preempt_count(val)	do { preempt_count() -= (val); } while (0)

#define clear_need_resched()	clear_thread_flag(TIF_NEED_RESCHED)
#define clear_thread_flag(flag) \
	clear_ti_thread_flag(current_thread_info(), flag)
#define set_need_resched()	set_thread_flag(TIF_NEED_RESCHED)
#define set_thread_flag(flag) \
	set_ti_thread_flag(current_thread_info(), flag)
#define test_and_clear_thread_flag(flag) \
	test_and_clear_ti_thread_flag(current_thread_info(), flag)
#define test_and_set_thread_flag(flag) \
	test_and_set_ti_thread_flag(current_thread_info(), flag)
#define test_thread_flag(flag) \
	test_ti_thread_flag(current_thread_info(), flag)
#define LOCK_SECTION_END                        \
        ".previous\n\t"
#define LOCK_SECTION_NAME ".text.lock."KBUILD_BASENAME
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
# define rwlock_init(lock)					\
do {								\
	static struct lock_class_key __key;			\
								\
	__rwlock_init((lock), #lock, &__key);			\
} while (0)
#define spin_can_lock(lock)	(!spin_is_locked(lock))
#define spin_is_locked(lock)	__raw_spin_is_locked(&(lock)->raw_lock)
#define spin_lock(lock)			_spin_lock(lock)
#define spin_lock_bh(lock)		_spin_lock_bh(lock)
# define spin_lock_init(lock)					\
	do { *(lock) = SPIN_LOCK_UNLOCKED; } while (0)
#define spin_lock_irq(lock)		_spin_lock_irq(lock)
#define spin_lock_irqsave(lock, flags)	flags = _spin_lock_irqsave(lock)
# define spin_lock_nested(lock, subclass) _spin_lock_nested(lock, subclass)
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

#define __stringify(x)		__stringify_1(x)
#define __stringify_1(x)	#x
#define CPU_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(NR_CPUS)

#define any_online_cpu(mask) __any_online_cpu(&(mask))
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
#define first_cpu(src) __first_cpu(&(src))
#define for_each_cpu_mask(cpu, mask)		\
	for ((cpu) = first_cpu(mask);		\
		(cpu) < NR_CPUS;		\
		(cpu) = next_cpu((cpu), (mask)))
#define for_each_online_cpu(cpu)  for_each_cpu_mask((cpu), cpu_online_map)
#define for_each_possible_cpu(cpu)  for_each_cpu_mask((cpu), cpu_possible_map)
#define for_each_present_cpu(cpu) for_each_cpu_mask((cpu), cpu_present_map)
#define highest_possible_processor_id()	0
#define next_cpu(n, src) __next_cpu((n), &(src))
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

#define PERCPU_ENOUGH_ROOM 32768

#define alloc_percpu(type)	((type *)(__alloc_percpu(sizeof(type))))
#define get_cpu_var(var) (*({ preempt_disable(); &__get_cpu_var(var); }))
#define per_cpu_ptr(ptr, cpu)                   \
({                                              \
        struct percpu_data *__p = (struct percpu_data *)~(unsigned long)(ptr); \
        (__typeof__(ptr))__p->ptrs[(cpu)];	\
})
#define put_cpu_var(var) preempt_enable()
#define MSG_CALL_FUNCTION       0x0004  

#define get_cpu()		({ preempt_disable(); smp_processor_id(); })
#define hard_smp_processor_id()			0
#define num_booting_cpus()			1
#define on_each_cpu(func,info,retry,wait)	\
	({					\
		local_irq_disable();		\
		func(info);			\
		local_irq_enable();		\
		0;				\
	})
#define put_cpu()		preempt_enable()
#define put_cpu_no_resched()	preempt_enable_no_resched()
#define raw_smp_processor_id()			0
#define smp_call_function(func,info,retry,wait)	(up_smp_call_function())
#define smp_prepare_boot_cpu()			do {} while (0)
# define smp_processor_id() debug_smp_processor_id()
#define CACHE(x) \
		if (size <= x) \
			goto found; \
		else \
			i++;
#define ____kmalloc kmalloc
#define kmalloc_node(s, f, n) kmalloc(s, f)
#define kmem_cache_alloc_node(c, f, n) kmem_cache_alloc(c, f)

#define kmem_cache_shrink(d) (0)
#define kmem_ptr_validate(a, b) (0)
#define kzalloc(s, f) __kzalloc(s, f)

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
#define __memexit __exit


#define __meminitdata __initdata
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
			__GFP_NOMEMALLOC|__GFP_HARDWALL)
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
#define __GFP_BITS_SHIFT 20	
#define __GFP_HARDWALL   ((__force gfp_t)0x20000u) 
#define __GFP_NOMEMALLOC ((__force gfp_t)0x10000u) 

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
#define DEF_PRIORITY 12
#define GFP_ZONETYPES  ((GFP_ZONEMASK + 1) / 2 + 1)            
#define MAX_ORDER 11
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map
#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define ZONE_PADDING(name)	struct zone_padding name;

#define early_pfn_to_nid(nid)  (0UL)
#define early_pfn_valid(pfn)	pfn_valid(pfn)
#define for_each_online_pgdat(pgdat)			\
	for (pgdat = first_online_pgdat();		\
	     pgdat;					\
	     pgdat = next_online_pgdat(pgdat))
#define for_each_zone(zone)			        \
	for (zone = (first_online_pgdat())->node_zones; \
	     zone;					\
	     zone = next_zone(zone))
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))
#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#define numa_node_id()		(cpu_to_node(raw_smp_processor_id()))
#define pfn_to_nid(pfn)		(0)
#define pfn_to_section_nr(pfn) ((pfn) >> PFN_SECTION_SHIFT)
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#define section_nr_to_pfn(sec) ((sec) << PFN_SECTION_SHIFT)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define sparse_init()	do {} while (0)
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)
#define zone_pcp(__z, __cpu) ((__z)->pageset[(__cpu)])

#define RECLAIM_DISTANCE 20
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
				| SD_WAKE_AFFINE	\
				| BALANCE_FOR_POWER,	\
	.last_balance		= jiffies,		\
	.balance_interval	= 1,			\
	.nr_balance_failed	= 0,			\
}
#define SD_MC_INIT   SD_CPU_INIT
#define SD_SIBLING_INIT (struct sched_domain) {		\
	.span			= CPU_MASK_NONE,	\
	.parent			= NULL,			\
	.groups			= NULL,			\
	.min_interval		= 1,			\
	.max_interval		= 2,			\
	.busy_factor		= 8,			\
	.imbalance_pct		= 110,			\
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

#define arch_alloc_nodedata(nid)	generic_alloc_nodedata(nid)
#define arch_free_nodedata(pgdat)	generic_free_nodedata(pgdat)
#define generic_alloc_nodedata(nid)				\
({								\
	kzalloc(sizeof(pg_data_t), GFP_KERNEL);			\
})
#define generic_free_nodedata(pgdat)	kfree(pgdat)
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
#define NETDEV_REGISTER 0x0005
#define RAW_INIT_NOTIFIER_HEAD(name) do {	\
		(name)->head = NULL;		\
	} while (0)
#define RAW_NOTIFIER_HEAD(name)					\
	struct raw_notifier_head name =				\
		RAW_NOTIFIER_INIT(name)
#define RAW_NOTIFIER_INIT(name)	{				\
		.head = NULL }


# define down_read_nested(sem, subclass)		down_read(sem)
# define down_read_non_owner(sem)		down_read(sem)
# define down_write_nested(sem, subclass)	down_write(sem)
# define up_read_non_owner(sem)			up_read(sem)
#define DECLARE_RWSEM(name) \
	struct rw_semaphore name = __RWSEM_INITIALIZER(name)

# define __RWSEM_DEP_MAP_INIT(lockname) , .dep_map = { .name = #lockname }
#define __RWSEM_INITIALIZER(name) \
{ 0, SPIN_LOCK_UNLOCKED, LIST_HEAD_INIT((name).wait_list) __RWSEM_DEP_MAP_INIT(name) }
#define init_rwsem(sem)						\
do {								\
	static struct lock_class_key __key;			\
								\
	__init_rwsem((sem), #sem, &__key);			\
} while (0)
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
#define next_online_node(nid)	next_node((nid), node_online_map)
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
#define MAX_NUMNODES    (1 << NODES_SHIFT)
#define NODES_SHIFT     CONFIG_NODES_SHIFT

#define INTERNODE_CACHE_SHIFT L1_CACHE_SHIFT
#define L1_CACHE_ALIGN(x) ALIGN(x, L1_CACHE_BYTES)
#define SMP_CACHE_BYTES L1_CACHE_BYTES

#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#define ____cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))
#define __cacheline_aligned_in_smp __cacheline_aligned

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
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),		\
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
#define CHECKSUM_HW 1
#define CHECKSUM_NONE 0
#define CHECKSUM_UNNECESSARY 2
#define MAX_SKB_FRAGS (65536/PAGE_SIZE + 2)
#define SKB_DATAREF_MASK ((1 << SKB_DATAREF_SHIFT) - 1)
#define SKB_DATAREF_SHIFT 16
#define SKB_DATA_ALIGN(X)	(((X) + (SMP_CACHE_BYTES - 1)) & \
				 ~(SMP_CACHE_BYTES - 1))
#define SKB_FRAG_ASSERT(skb) 	BUG_ON(skb_shinfo(skb)->frag_list)
#define SKB_LINEAR_ASSERT(skb)  BUG_ON(skb_is_nonlinear(skb))
#define SKB_MAX_HEAD(X)		(SKB_MAX_ORDER((X), 0))
#define SKB_MAX_ORDER(X, ORDER)	(((PAGE_SIZE << (ORDER)) - (X) - \
				  sizeof(struct skb_shared_info)) & \
				  ~(SMP_CACHE_BYTES - 1))
#define SKB_PAGE_ASSERT(skb) 	BUG_ON(skb_shinfo(skb)->nr_frags)

#define dev_kfree_skb(a)	kfree_skb(a)
#define skb_queue_reverse_walk(queue, skb) \
		for (skb = (queue)->prev;					\
		     prefetch(skb->prev), (skb != (struct sk_buff *)(queue));	\
		     skb = skb->prev)
#define skb_queue_walk(queue, skb) \
		for (skb = (queue)->next;					\
		     prefetch(skb->next), (skb != (struct sk_buff *)(queue));	\
		     skb = skb->next)
#define skb_shinfo(SKB)		((struct skb_shared_info *)((SKB)->end))

#define dma_submit_error(cookie) ((cookie) < 0 ? 1 : 0)
#define COMPLETION_INITIALIZER(work) \
	{ 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }
#define COMPLETION_INITIALIZER_ONSTACK(work) \
	({ init_completion(&work); work; })
#define DECLARE_COMPLETION(work) \
	struct completion work = COMPLETION_INITIALIZER(work)
# define DECLARE_COMPLETION_ONSTACK(work) \
	struct completion work = COMPLETION_INITIALIZER_ONSTACK(work)
#define INIT_COMPLETION(x)	((x).done = 0)


#define BUS_ATTR(_name,_mode,_show,_store)	\
struct bus_attribute bus_attr_##_name = __ATTR(_name,_mode,_show,_store)
#define CLASS_ATTR(_name,_mode,_show,_store)			\
struct class_attribute class_attr_##_name = __ATTR(_name,_mode,_show,_store) 
#define CLASS_DEVICE_ATTR(_name,_mode,_show,_store)		\
struct class_device_attribute class_device_attr_##_name = 	\
	__ATTR(_name,_mode,_show,_store)
#define DEVICE_ATTR(_name,_mode,_show,_store) \
struct device_attribute dev_attr_##_name = __ATTR(_name,_mode,_show,_store)
#define DRIVER_ATTR(_name,_mode,_show,_store)	\
struct driver_attribute driver_attr_##_name = __ATTR(_name,_mode,_show,_store)
#define MODULE_ALIAS_CHARDEV(major,minor) \
	MODULE_ALIAS("char-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_CHARDEV_MAJOR(major) \
	MODULE_ALIAS("char-major-" __stringify(major) "-*")

#define dev_dbg(dev, format, arg...)		\
	dev_printk(KERN_DEBUG , dev , format , ## arg)
#define dev_err(dev, format, arg...)		\
	dev_printk(KERN_ERR , dev , format , ## arg)
#define dev_info(dev, format, arg...)		\
	dev_printk(KERN_INFO , dev , format , ## arg)
#define dev_notice(dev, format, arg...)		\
	dev_printk(KERN_NOTICE , dev , format , ## arg)
#define dev_printk(level, dev, format, arg...)	\
	printk(level "%s %s: " format , dev_driver_string(dev) , (dev)->bus_id , ## arg)
#define dev_warn(dev, format, arg...)		\
	dev_printk(KERN_WARNING , dev , format , ## arg)
#define PM_EVENT_FREEZE 1
#define PM_EVENT_ON 0
#define PM_EVENT_SUSPEND 2
#define PM_PCI_ID(dev) ((dev)->bus->number << 16 | (dev)->devfn)

#define device_can_wakeup(dev) \
	((dev)->power.can_wakeup)
#define device_init_wakeup(dev,val) \
	do { \
		device_can_wakeup(dev) = !!(val); \
		device_set_wakeup_enable(dev,val); \
	} while(0)
#define device_may_wakeup(dev) \
	(device_can_wakeup(dev) && (dev)->power.should_wakeup)
#define device_set_wakeup_enable(dev,val) \
	((dev)->power.should_wakeup = !!(val))
#define suspend_report_result(fn, ret)					\
	do {								\
		__suspend_report_result(__FUNCTION__, fn, ret);		\
	} while (0)
#define EXPORT_SYMBOL(sym)					\
	__EXPORT_SYMBOL(sym, "")
#define EXPORT_SYMBOL_GPL(sym)					\
	__EXPORT_SYMBOL(sym, "_gpl")
#define EXPORT_SYMBOL_GPL_FUTURE(sym)				\
	__EXPORT_SYMBOL(sym, "_gpl_future")
#define EXPORT_UNUSED_SYMBOL(sym) __EXPORT_SYMBOL(sym, "_unused")
#define EXPORT_UNUSED_SYMBOL_GPL(sym) __EXPORT_SYMBOL(sym, "_unused_gpl")
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
	extern typeof(sym) sym;					\
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

#define decl_subsys(_name,_type,_uevent_ops) \
struct subsystem _name##_subsys = { \
	.kset = { \
		.kobj = { .name = __stringify(_name) }, \
		.ktype = _type, \
		.uevent_ops =_uevent_ops, \
	} \
}
#define decl_subsys_name(_varname,_name,_type,_uevent_ops) \
struct subsystem _varname##_subsys = { \
	.kset = { \
		.kobj = { .name = __stringify(_name) }, \
		.ktype = _type, \
		.uevent_ops =_uevent_ops, \
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
#define STT_COMMON  5
#define STT_FILE    4
#define STT_FUNC    2
#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_SECTION 3
#define STT_TLS     6

# define elf_read_implies_exec(ex, have_pt_gnu_stack)	0

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
#define AT_VECTOR_SIZE  44 

#define KMOD_PATH_LEN 256

#define try_then_request_module(x, mod...) ((x) ?: (request_module(mod), (x)))
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

#define FD_CLR(fd,fdsetp)	__FD_CLR(fd,fdsetp)
#define FD_ISSET(fd,fdsetp)	__FD_ISSET(fd,fdsetp)
#define FD_SET(fd,fdsetp)	__FD_SET(fd,fdsetp)
#define FD_ZERO(fdsetp)		__FD_ZERO(fdsetp)


#define do_posix_clock_monotonic_gettime(ts) ktime_get_ts(ts)
#define timespec_valid(ts) \
	(((ts)->tv_sec >= 0) && (((unsigned long) (ts)->tv_nsec) < NSEC_PER_SEC))
#define CALC_LOAD(load,exp,n) \
	load *= exp; \
	load += n*(FIXED_1-exp); \
	load >>= FSHIFT;
#define GROUP_AT(gi, i) \
    ((gi)->blocks[(i)/NGROUPS_PER_BLOCK][(i)%NGROUPS_PER_BLOCK])
#define INIT_USER (&root_user)
# define MAX_LOCK_DEPTH 30UL
#define PF_LESS_THROTTLE 0x00100000	
#define SEND_SIG_NOINFO ((struct siginfo *) 0)
#define TASK_COMM_LEN 16

# define __ARCH_WANT_UNLOCKED_CTXSW
#define __set_current_state(state_value)			\
	do { current->state = (state_value); } while (0)
#define __set_task_state(tsk, state_value)		\
	do { (tsk)->state = (state_value); } while (0)
#define add_mm_counter(mm, member, value) atomic_long_add(value, &(mm)->_##member)
#define add_parent(p)		list_add_tail(&(p)->sibling,&(p)->parent->children)
#define batch_task(p)		(unlikely((p)->policy == SCHED_BATCH))
#define clear_stopped_child_used_math(child) do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define clear_used_math() clear_stopped_child_used_math(current)
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition) \
	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
#define dec_mm_counter(mm, member) atomic_long_dec(&(mm)->_##member)
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
#define get_mm_counter(mm, member) ((unsigned long)atomic_long_read(&(mm)->_##member))
#define get_mm_rss(mm)					\
	(get_mm_counter(mm, file_rss) + get_mm_counter(mm, anon_rss))
#define get_task_struct(tsk) do { atomic_inc(&(tsk)->usage); } while(0)
#define has_rt_policy(p) \
	unlikely((p)->policy != SCHED_NORMAL && (p)->policy != SCHED_BATCH)
#define inc_mm_counter(mm, member) atomic_long_inc(&(mm)->_##member)
# define need_lockbreak(lock) ((lock)->break_lock)
#define next_task(p)	list_entry(rcu_dereference((p)->tasks.next), struct task_struct, tasks)
#define put_group_info(group_info) do { \
	if (atomic_dec_and_test(&(group_info)->usage)) \
		groups_free(group_info); \
} while (0)
#define remove_parent(p)	list_del_init(&(p)->sibling)
# define rt_mutex_adjust_pi(p)		do { } while (0)
#define rt_prio(prio)		unlikely((prio) < MAX_RT_PRIO)
#define rt_task(p)		rt_prio((p)->prio)
#define sched_exec()   {}
#define set_current_state(state_value)		\
	set_mb(current->state, (state_value))
#define set_mm_counter(mm, member, value) atomic_long_set(&(mm)->_##member, value)
#define set_stopped_child_used_math(child) do { (child)->flags |= PF_USED_MATH; } while (0)
#define set_task_state(tsk, state_value)		\
	set_mb((tsk)->state, (state_value))
#define set_used_math() set_stopped_child_used_math(current)
#define task_stack_page(task) ((void*)((task)->thread_info))
#define task_thread_info(task) (task)->thread_info
#define thread_group_leader(p)	(p == p->group_leader)
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
#define SYSDEV_ATTR(_name,_mode,_show,_store) 		\
struct sysdev_attribute attr_##_name = { 			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.show	= _show,					\
	.store	= _store,					\
};
#define SYSDEV_CLASS_ATTR(_name,_mode,_show,_store) 		\
struct sysdev_class_attribute attr_##_name = { 			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.show	= _show,					\
	.store	= _store,					\
};


#define aio_ring_avail(info, ring)	(((ring)->head + (info)->nr - 1 - (ring)->tail) % (info)->nr)
#define get_ioctx(kioctx) do {						\
	BUG_ON(unlikely(atomic_read(&(kioctx)->users) <= 0));		\
	atomic_inc(&(kioctx)->users);					\
} while (0)
#define in_aio() !is_sync_wait(current->io_wait)
#define init_sync_kiocb(x, filp)			\
	do {						\
		struct task_struct *tsk = current;	\
		(x)->ki_flags = 0;			\
		(x)->ki_users = 1;			\
		(x)->ki_key = KIOCB_SYNC_KEY;		\
		(x)->ki_filp = (filp);			\
		(x)->ki_ctx = NULL;			\
		(x)->ki_cancel = NULL;			\
		(x)->ki_retry = NULL;			\
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
#define put_ioctx(kioctx) do {						\
	BUG_ON(unlikely(atomic_read(&(kioctx)->users) <= 0));		\
	if (unlikely(atomic_dec_and_test(&(kioctx)->users))) 		\
		__put_ioctx(kioctx);					\
} while (0)
#define warn_if_async()							\
do {									\
	if (in_aio()) {							\
		printk(KERN_ERR "%s(%s:%d) called in async context!\n",	\
			__FUNCTION__, "__FILE__", "__LINE__");		\
		dump_stack();						\
	}								\
} while (0)
#define PADDED(x,y)	x, y

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
		.base = &boot_tvec_bases,			\
	}

#define del_singleshot_timer_sync(t) del_timer_sync(t)
# define del_timer_sync(t)		del_timer(t)
# define try_to_del_timer_sync(t)	del_timer(t)

#define clock_was_set()		do { } while (0)
#define hrtimer_restart(timer) hrtimer_start((timer), (timer)->expires, HRTIMER_ABS)

#define ktime_add(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 + (rhs).tv64 }; })
#define ktime_add_ns(kt, nsval) \
		({ (ktime_t){ .tv64 = (kt).tv64 + (nsval) }; })
#define ktime_get_real_ts(ts)	getnstimeofday(ts)
#define ktime_sub(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 - (rhs).tv64 }; })
#define ktime_to_ns(kt)			((kt).tv64)
#define ktime_to_timespec(kt)		ns_to_timespec((kt).tv64)
#define ktime_to_timeval(kt)		ns_to_timeval((kt).tv64)
#define ACTHZ (SH_DIV (CLOCK_TICK_RATE, LATCH, 8))
#define ACTHZ_HPET (SH_DIV (HPET_TICK_RATE, LATCH_HPET, 8))
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))
#define LATCH  ((CLOCK_TICK_RATE + HZ/2) / HZ)	
#define LATCH_HPET ((HPET_TICK_RATE + HZ/2) / HZ)
#define MAX_JIFFY_OFFSET ((~0UL >> 1)-1)
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
#define TICK_NSEC (SH_DIV (1000000UL * 1000, ACTHZ, 8))
#define TICK_NSEC_HPET (SH_DIV(1000000UL * 1000, ACTHZ_HPET, 8))
#define TICK_USEC ((1000000UL + USER_HZ/2) / USER_HZ)
#define TICK_USEC_TO_NSEC(TUSEC) (SH_DIV (TUSEC * USER_HZ * 1000, ACTHZ, 8))
#define USEC_CONVERSION  \
                    ((unsigned long)((((u64)NSEC_PER_USEC << USEC_JIFFIE_SC) +\
                                        TICK_NSEC -1) / (u64)TICK_NSEC))
#define USEC_JIFFIE_SC (SEC_JIFFIE_SC + 19)
#define USEC_ROUND (u64)(((u64)1 << USEC_JIFFIE_SC) - 1)

#define __jiffy_data  __attribute__((section(".data")))
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
#define MAXPHASE 512000L        
#define MAXSEC 1200L            
#define MAXTC 6			
#define MINSEC 16L              
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

#define div_long_long_rem(dividend, divisor, remainder)	\
	do_div_llr((dividend), divisor, remainder)
#define RB_CLEAR_NODE(node)	(rb_set_parent(node, node))
#define RB_EMPTY_NODE(node)	(rb_parent(node) != node)
#define RB_EMPTY_ROOT(root)	((root)->rb_node == NULL)
#define rb_color(r)   ((r)->rb_parent_color & 1)
#define rb_is_black(r) rb_color(r)
#define rb_is_red(r)   (!rb_color(r))
#define rb_parent(r)   ((struct rb_node *)((r)->rb_parent_color & ~3))
#define rb_set_black(r)  do { (r)->rb_parent_color |= 1; } while (0)
#define rb_set_red(r)  do { (r)->rb_parent_color &= ~1; } while (0)


#define DEFINE_RT_MUTEX(mutexname) \
	struct rt_mutex mutexname = __RT_MUTEX_INITIALIZER(mutexname)
# define INIT_RT_MUTEXES(tsk)						\
	.pi_waiters	= PLIST_HEAD_INIT(tsk.pi_waiters, tsk.pi_lock),	\
	INIT_RT_MUTEX_DEBUG(tsk)
# define __DEBUG_RT_MUTEX_INITIALIZER(mutexname) \
	, .name = #mutexname, .file = "__FILE__", .line = "__LINE__"

#define __RT_MUTEX_INITIALIZER(mutexname) \
	{ .wait_lock = SPIN_LOCK_UNLOCKED \
	, .wait_list = PLIST_HEAD_INIT(mutexname.wait_list, mutexname.wait_lock) \
	, .owner = NULL \
	__DEBUG_RT_MUTEX_INITIALIZER(mutexname)}
# define rt_mutex_debug_check_no_locks_held(task)	do { } while (0)
# define rt_mutex_debug_task_free(t)			do { } while (0)
# define rt_mutex_init(mutex)			__rt_mutex_init(mutex, __FUNCTION__)
#define PLIST_HEAD_INIT(head, _lock)			\
{							\
	.prio_list = LIST_HEAD_INIT((head).prio_list),	\
	.node_list = LIST_HEAD_INIT((head).node_list),	\
	PLIST_HEAD_LOCK_INIT(&(_lock))			\
}
# define PLIST_HEAD_LOCK_INIT(_lock)	.lock = _lock
#define PLIST_NODE_INIT(node, __prio)			\
{							\
	.prio  = (__prio),				\
	.plist = PLIST_HEAD_INIT((node).plist, NULL),	\
}

# define plist_first_entry(head, type, member)	\
({ \
	WARN_ON(plist_head_empty(head)); \
	container_of(plist_first(head), type, member); \
})
#define plist_for_each(pos, head)	\
	 list_for_each_entry(pos, &(head)->node_list, plist.node_list)
#define plist_for_each_entry(pos, head, mem)	\
	 list_for_each_entry(pos, &(head)->node_list, mem.plist.node_list)
#define plist_for_each_entry_safe(pos, n, head, m)	\
	list_for_each_entry_safe(pos, n, &(head)->node_list, m.plist.node_list)
#define plist_for_each_safe(pos, n, head)	\
	 list_for_each_entry_safe(pos, n, &(head)->node_list, plist.node_list)
#define FUTEX_OP(op, oparg, cmp, cmparg) \
  (((op & 0xf) << 28) | ((cmp & 0xf) << 24)		\
   | ((oparg & 0xfff) << 12) | (cmparg & 0xfff))

#define NR_SECCOMP_MODES 1

#define secure_computing(x) do { } while (0)

#define do_each_task_pid(who, type, task)				\
	if ((task = find_task_by_pid_type(type, who))) {		\
		prefetch(pid_next(task, type));				\
		do {
#define pid_next(task, type)					\
	((task)->pids[(type)].node.next)
#define pid_next_task(task, type) 				\
	hlist_entry(pid_next(task, type), struct task_struct,	\
			pids[(type)].node)
#define while_each_task_pid(who, type, task)				\
		} while (pid_next(task, type) &&  ({			\
				task = pid_next_task(task, type);	\
				rcu_dereference(task);			\
				prefetch(pid_next(task, type));		\
				1; }) );				\
	}
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


#define check_mem_region(start,n)	__check_region(&iomem_resource, (start), (n))
#define release_mem_region(start,n)	__release_region(&iomem_resource, (start), (n))
#define release_region(start,n)	__release_region(&ioport_resource, (start), (n))
#define rename_region(region, newname) do { (region)->name = (newname); } while (0)
#define request_mem_region(start,n,name) __request_region(&iomem_resource, (start), (n), (name))
#define request_region(start,n,name)	__request_region(&ioport_resource, (start), (n), (name))
#define TS_PRIV_ALIGN(len) (((len) + TS_PRIV_ALIGNTO-1) & ~(TS_PRIV_ALIGNTO-1))

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
#define FDS_BYTES(nr)	(FDS_LONGS(nr)*sizeof(long))
#define FDS_LONGS(nr)	(((nr)+FDS_BITPERLONG-1)/FDS_BITPERLONG)
#define MAX_INT64_SECONDS (((s64)(~((u64)0)>>1)/HZ)-1)
#define MAX_STACK_ALLOC 832

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

#define __pte_lockptr(page)	&((page)->ptl)
#define in_gate_area(task, addr) ({(void)task; in_gate_area_no_task(addr);})
#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)
#define page_address(page) ((page)->virtual)
#define page_address_init()  do { } while(0)
#define page_private(page)		((page)->private)
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
#define randomize_va_space 0
#define set_page_address(page, address)			\
	do {						\
		(page)->virtual = (address);		\
	} while(0)
#define set_page_private(page, v)	((page)->private = (v))
#define shmem_nopage filemap_nopage
#define sysctl_legacy_va_layout 0
#define vma_prio_tree_foreach(vma, iter, root, begin, end)	\
	for (prio_tree_iter_init(iter, root, begin, end), vma = NULL;	\
		(vma = vma_prio_tree_next(vma, iter)); )
#define FOR_ALL_ZONES(x) x##_DMA, x##_DMA32, x##_NORMAL, x##_HIGH

#define __add_zone_page_state(__z, __i, __d)	\
		__mod_zone_page_state(__z, __i, __d)
#define __count_vm_event(e)	do { } while (0)
#define __count_vm_events(e,d)	do { } while (0)
#define __count_zone_vm_events(item, zone, delta) \
			__count_vm_events(item##_DMA + zone_idx(zone), delta)
#define __sub_zone_page_state(__z, __i, __d)	\
		__mod_zone_page_state(__z, __i,-(__d))
#define add_zone_page_state(__z, __i, __d) mod_zone_page_state(__z, __i, __d)
#define count_vm_event(e)	do { } while (0)
#define count_vm_events(e,d)	do { } while (0)
#define dec_zone_page_state __dec_zone_page_state
#define get_cpu_vm_events(e)	0L
#define inc_zone_page_state __inc_zone_page_state
#define mod_zone_page_state __mod_zone_page_state
#define node_page_state(node, item) global_page_state(item)
#define sub_zone_page_state(__z, __i, __d) mod_zone_page_state(__z, __i, -(__d))
#define vm_events_fold_cpu(x)	do { } while (0)
#define zone_statistics(_zl,_z) do { } while (0)

#define ClearPageActive(page)	clear_bit(PG_active, &(page)->flags)
#define ClearPageChecked(page)	clear_bit(PG_checked, &(page)->flags)
#define ClearPageDirty(page)	clear_bit(PG_dirty, &(page)->flags)
#define ClearPageError(page)	clear_bit(PG_error, &(page)->flags)
#define ClearPageLRU(page)	clear_bit(PG_lru, &(page)->flags)
#define ClearPageLocked(page)		\
		clear_bit(PG_locked, &(page)->flags)
#define ClearPageMappedToDisk(page) clear_bit(PG_mappedtodisk, &(page)->flags)
#define ClearPageNosave(page)		clear_bit(PG_nosave, &(page)->flags)
#define ClearPageNosaveFree(page)		clear_bit(PG_nosave_free, &(page)->flags)
#define ClearPagePrivate(page)	clear_bit(PG_private, &(page)->flags)
#define ClearPageReclaim(page)	clear_bit(PG_reclaim, &(page)->flags)
#define ClearPageReferenced(page)	clear_bit(PG_referenced, &(page)->flags)
#define ClearPageReserved(page)	clear_bit(PG_reserved, &(page)->flags)
#define ClearPageSwapCache(page) clear_bit(PG_swapcache, &(page)->flags)
#define ClearPageUncached(page)	clear_bit(PG_uncached, &(page)->flags)
#define ClearPageUptodate(page)	clear_bit(PG_uptodate, &(page)->flags)
#define ClearPageWriteback(page)					\
	do {								\
		if (test_and_clear_bit(PG_writeback,			\
				&(page)->flags))			\
			dec_zone_page_state(page, NR_WRITEBACK);	\
	} while (0)

#define PageActive(page)	test_bit(PG_active, &(page)->flags)
#define PageBuddy(page)		test_bit(PG_buddy, &(page)->flags)
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
#define SetPageSwapCache(page)	set_bit(PG_swapcache, &(page)->flags)
#define SetPageUncached(page)	set_bit(PG_uncached, &(page)->flags)
#define SetPageUptodate(_page) \
	do {								      \
		struct page *__page = (_page);				      \
		if (!test_and_set_bit(PG_uptodate, &__page->flags))	      \
			page_test_and_clear_dirty(_page);		      \
	} while (0)
#define SetPageWriteback(page)						\
	do {								\
		if (!test_and_set_bit(PG_writeback,			\
				&(page)->flags))			\
			inc_zone_page_state(page, NR_WRITEBACK);	\
	} while (0)
#define TestClearPageDirty(page) test_and_clear_bit(PG_dirty, &(page)->flags)
#define TestClearPageLocked(page)	\
		test_and_clear_bit(PG_locked, &(page)->flags)
#define TestClearPageNosave(page)	test_and_clear_bit(PG_nosave, &(page)->flags)
#define TestClearPageReclaim(page) test_and_clear_bit(PG_reclaim, &(page)->flags)
#define TestClearPageReferenced(page) test_and_clear_bit(PG_referenced, &(page)->flags)
#define TestClearPageWriteback(page)					\
	({								\
		int ret;						\
		ret = test_and_clear_bit(PG_writeback,			\
				&(page)->flags);			\
		if (ret)						\
			dec_zone_page_state(page, NR_WRITEBACK);	\
		ret;							\
	})
#define TestSetPageDirty(page)	test_and_set_bit(PG_dirty, &(page)->flags)
#define TestSetPageLocked(page)		\
		test_and_set_bit(PG_locked, &(page)->flags)
#define TestSetPageNosave(page)	test_and_set_bit(PG_nosave, &(page)->flags)
#define TestSetPageWriteback(page)					\
	({								\
		int ret;						\
		ret = test_and_set_bit(PG_writeback,			\
					&(page)->flags);		\
		if (!ret)						\
			inc_zone_page_state(page, NR_WRITEBACK);	\
		ret;							\
	})
#define __ClearPageActive(page)	__clear_bit(PG_active, &(page)->flags)
#define __ClearPageBuddy(page)	__clear_bit(PG_buddy, &(page)->flags)
#define __ClearPageCompound(page) __clear_bit(PG_compound, &(page)->flags)
#define __ClearPageDirty(page)	__clear_bit(PG_dirty, &(page)->flags)
#define __ClearPageLRU(page)	__clear_bit(PG_lru, &(page)->flags)
#define __ClearPagePrivate(page) __clear_bit(PG_private, &(page)->flags)
#define __ClearPageReserved(page)	__clear_bit(PG_reserved, &(page)->flags)
#define __ClearPageSlab(page)	__clear_bit(PG_slab, &(page)->flags)
#define __SetPageBuddy(page)	__set_bit(PG_buddy, &(page)->flags)
#define __SetPageCompound(page)	__set_bit(PG_compound, &(page)->flags)
#define __SetPagePrivate(page)  __set_bit(PG_private, &(page)->flags)
#define __SetPageSlab(page)	__set_bit(PG_slab, &(page)->flags)
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
#define BLKTRACESETUP _IOWR(0x12,115,struct blk_user_trace_setup)
#define BLKTRACESTART _IO(0x12,116)
#define BLKTRACESTOP _IO(0x12,117)
#define BLKTRACETEARDOWN _IO(0x12,118)
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
#define IS_NOCMTIME(inode)	((inode)->i_flags & S_NOCMTIME)
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
#define bd_claim_by_disk(bdev, holder, disk)	bd_claim(bdev, holder)
#define bd_release_from_disk(bdev, disk)	bd_release(bdev)
#define bio_data_dir(bio)	((bio)->bi_rw & 1)
#define bio_rw(bio)		((bio)->bi_rw & (RW_MASK | RWA_MASK))
#define buffer_migrate_page NULL
#define file_count(x)	atomic_read(&(x)->f_count)
#define file_list_lock() spin_lock(&files_lock);
#define file_list_unlock() spin_unlock(&files_lock);
#define fops_get(fops) \
	(((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
#define fops_put(fops) \
	do { if (fops) module_put((fops)->owner); } while(0)
#define get_file(x)	atomic_inc(&(x)->f_count)
#define i_size_ordered_init(inode) seqcount_init(&inode->i_size_seqcount)
#define putname(name)   __putname(name)
#define sb_entry(list)	list_entry((list), struct super_block, s_list)
#define special_file(m) (S_ISCHR(m)||S_ISBLK(m)||S_ISFIFO(m)||S_ISSOCK(m))
#define vfs_check_frozen(sb, level) \
	wait_event((sb)->s_wait_unfrozen, ((sb)->s_frozen < (level)))
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


#define RPC_VERSION 2

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
#define RADIX_TREE_MAX_TAGS 2

#define DCACHE_AUTOFS_PENDING 0x0001    
#define DCACHE_NFSFS_RENAMED  0x0002    
#define DNAME_INLINE_LEN_MIN 36
#define IS_ROOT(x) ((x) == (x)->d_parent)

#define init_name_hash()		0
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


#define kmap_atomic(page, idx)		page_address(page)
#define kmap_atomic_pfn(pfn, idx)	page_address(pfn_to_page(pfn))
#define kmap_atomic_to_page(ptr)	virt_to_page(ptr)
#define kunmap(page) do { (void) (page); } while (0)
#define kunmap_atomic(addr, idx)	do { } while (0)



#define HAVE_NETIF_MSG 1

#define HAVE_NETIF_RECEIVE_SKB 1
#define HAVE_NETIF_RX 1


#define HAVE_SET_MAC_ADDR  		 

#define HH_DATA_ALIGN(__len) \
	(((__len)+(HH_DATA_MOD-1))&~(HH_DATA_MOD - 1))
#define HH_DATA_OFF(__len) \
	(HH_DATA_MOD - (((__len - 1) & (HH_DATA_MOD - 1)) + 1))
#define LL_RESERVED_SPACE(dev) \
	(((dev)->hard_header_len&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) \
	((((dev)->hard_header_len+extra)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define MAX_HEADER (LL_MAX_HEADER + 48)
#define NETDEV_BOOT_SETUP_MAX 8
#define NETDEV_TX_BUSY 1	
#define NETDEV_TX_LOCKED -1	
#define NETDEV_TX_OK 0		
#define SET_ETHTOOL_OPS(netdev,ops) \
	( (netdev)->ethtool_ops = (ops) )
#define SET_MODULE_OWNER(dev) do { } while (0)
#define SET_NETDEV_DEV(net, pdev)	((net)->class_dev.dev = (pdev))

#define net_xmit_errno(e)	((e) != NET_XMIT_CN ? -ENOBUFS : 0)
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
#define DECLARE_TASKLET(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }
#define DECLARE_TASKLET_DISABLED(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }

#define __raise_softirq_irqoff(nr) do { or_softirq_pending(1UL << (nr)); } while (0)
#  define disable_irq_lockdep(irq)		disable_irq(irq)
#  define disable_irq_nosync_lockdep(irq)	disable_irq_nosync(irq)
#  define enable_irq_lockdep(irq)		enable_irq(irq)
# define local_irq_enable_in_hardirq()	do { } while (0)
#define or_softirq_pending(x)  (local_softirq_pending() |= (x))
#define save_and_cli(x)	save_and_cli(&x)
#define save_flags(x) save_flags(&x)
#define set_softirq_pending(x) (local_softirq_pending() = (x))
#define tasklet_trylock(t) 1
#define tasklet_unlock(t) do { } while (0)
#define tasklet_unlock_wait(t) do { } while (0)
# define INIT_TRACE_IRQFLAGS

#define irqs_disabled()						\
({								\
	unsigned long flags;					\
								\
	raw_local_save_flags(flags);				\
	raw_irqs_disabled_flags(flags);				\
})
#define irqs_disabled_flags(flags)	raw_irqs_disabled_flags(flags)
#define local_irq_disable() \
	do { raw_local_irq_disable(); trace_hardirqs_off(); } while (0)
#define local_irq_enable() \
	do { trace_hardirqs_on(); raw_local_irq_enable(); } while (0)
#define local_irq_restore(flags)				\
	do {							\
		if (raw_irqs_disabled_flags(flags)) {		\
			raw_local_irq_restore(flags);		\
			trace_hardirqs_off();			\
		} else {					\
			trace_hardirqs_on();			\
			raw_local_irq_restore(flags);		\
		}						\
	} while (0)
#define local_irq_save(flags) \
	do { raw_local_irq_save(flags); trace_hardirqs_off(); } while (0)
#define local_save_flags(flags)		raw_local_save_flags(flags)
# define raw_local_irq_disable()	local_irq_disable()
# define raw_local_irq_enable()		local_irq_enable()
# define raw_local_irq_restore(flags)	local_irq_restore(flags)
# define raw_local_irq_save(flags)	local_irq_save(flags)
#define safe_halt()						\
	do {							\
		trace_hardirqs_on();				\
		raw_safe_halt();				\
	} while (0)
# define trace_hardirq_context(p)	((p)->hardirq_context)
# define trace_hardirq_enter()	do { current->hardirq_context++; } while (0)
# define trace_hardirq_exit()	do { current->hardirq_context--; } while (0)
# define trace_hardirqs_enabled(p)	((p)->hardirqs_enabled)
# define trace_hardirqs_off()		do { } while (0)
# define trace_hardirqs_on()		do { } while (0)
# define trace_softirq_context(p)	((p)->softirq_context)
# define trace_softirq_enter()	do { current->softirq_context++; } while (0)
# define trace_softirq_exit()	do { current->softirq_context--; } while (0)
# define trace_softirqs_enabled(p)	((p)->softirqs_enabled)
# define trace_softirqs_off(ip)		do { } while (0)
# define trace_softirqs_on(ip)		do { } while (0)
# define IRQ_EXIT_OFFSET (HARDIRQ_OFFSET-1)

#define __IRQ_MASK(x)	((1UL << (x))-1)
#define __irq_exit()					\
	do {						\
		trace_hardirq_exit();			\
		account_system_vtime(current);		\
		sub_preempt_count(HARDIRQ_OFFSET);	\
	} while (0)
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
		trace_hardirq_enter();			\
	} while (0)
#define nmi_enter()		do { lockdep_off(); irq_enter(); } while (0)
#define nmi_exit()		do { __irq_exit(); lockdep_on(); } while (0)
# define preemptible()	(preempt_count() == 0 && !irqs_disabled())
#define softirq_count()	(preempt_count() & SOFTIRQ_MASK)
# define synchronize_irq(irq)	barrier()

#define kernel_locked()				1
#define lock_kernel()				do { } while(0)
#define reacquire_kernel_lock(task)		0
#define release_kernel_lock(tsk) do { 		\
	if (unlikely((tsk)->lock_depth >= 0))	\
		__release_kernel_lock();	\
} while (0)
# define return_value_on_smp return
#define unlock_kernel()				do { } while(0)
#define IRQ_RETVAL(x)	((x) != 0)

#define TPACKET_ALIGN(x)	(((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))

#define ETH_P_CUST      0x6006          
#define ETH_P_DDCMP     0x0006          
#define ETH_P_DEC       0x6000          
#define ETH_P_DIAG      0x6005          
#define ETH_P_DNA_DL    0x6001          
#define ETH_P_DNA_RC    0x6002          
#define ETH_P_DNA_RT    0x6003          
#define ETH_P_LAT       0x6004          
#define ETH_P_LOCALTALK 0x0009		
#define ETH_P_PPP_MP    0x0008          
#define ETH_P_RARP      0x8035		
#define ETH_P_SCA       0x6007          
#define ETH_P_WAN_PPP   0x0007          

#define IFF_802_1Q_VLAN 0x1             
#define IF_IFACE_SYNC_SERIAL 0x1005	
#define IF_IFACE_X21D   0x1006          
#define IF_PROTO_FR_ADD_ETH_PVC 0x2008	
#define IF_PROTO_FR_ADD_PVC 0x2004	
#define IF_PROTO_FR_DEL_ETH_PVC 0x2009	
#define IF_PROTO_FR_DEL_PVC 0x2005	
#define IF_PROTO_FR_ETH_PVC 0x200B
#define IF_PROTO_HDLC_ETH 0x2007	
#define IF_PROTO_RAW    0x200C          


#define ASSERT_RTNL() do { \
	if (unlikely(rtnl_trylock())) { \
		rtnl_unlock(); \
		printk(KERN_ERR "RTNL: assertion failed at %s (%d)\n", \
		       "__FILE__",  "__LINE__"); \
		dump_stack(); \
	} \
} while(0)
#define BUG_TRAP(x) do { \
	if (unlikely(!(x))) { \
		printk(KERN_ERR "KERNEL: assertion (%s) failed at %s (%d)\n", \
			#x,  "__FILE__" , "__LINE__"); \
	} \
} while(0)
#define IFA_MAX (__IFA_MAX - 1)
#define IFA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifaddrmsg))
#define IFA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))
#define IFLA_COST IFLA_COST
#define IFLA_MAP IFLA_MAP
#define IFLA_MASTER IFLA_MASTER
#define IFLA_MAX (__IFLA_MAX - 1)
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
#define IFLA_PRIORITY IFLA_PRIORITY
#define IFLA_PROTINFO IFLA_PROTINFO
#define IFLA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#define IFLA_TXQLEN IFLA_TXQLEN
#define IFLA_WEIGHT IFLA_WEIGHT
#define IFLA_WIRELESS IFLA_WIRELESS
#define NDA_MAX (__NDA_MAX - 1)
#define NDA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndmsg))
#define NDA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#define NDTA_MAX (__NDTA_MAX - 1)
#define NDTA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ndtmsg))
#define NDTA_RTA(r) ((struct rtattr*)(((char*)(r)) + \
		     NLMSG_ALIGN(sizeof(struct ndtmsg))))
#define NDTPA_MAX (__NDTPA_MAX - 1)
#define RTAX_ADVMSS RTAX_ADVMSS
#define RTAX_CWND RTAX_CWND
#define RTAX_FEATURES RTAX_FEATURES
#define RTAX_HOPLIMIT RTAX_HOPLIMIT
#define RTAX_INITCWND RTAX_INITCWND
#define RTAX_LOCK RTAX_LOCK
#define RTAX_MAX (__RTAX_MAX - 1)
#define RTAX_MTU RTAX_MTU
#define RTAX_REORDERING RTAX_REORDERING
#define RTAX_RTT RTAX_RTT
#define RTAX_RTTVAR RTAX_RTTVAR
#define RTAX_SSTHRESH RTAX_SSTHRESH
#define RTAX_UNSPEC RTAX_UNSPEC
#define RTAX_WINDOW RTAX_WINDOW
#define RTA_ALIGN(len) ( ((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1) )
#define RTA_APPEND(skb, attrlen, data) \
({	if (unlikely(skb_tailroom(skb) < (int)(attrlen))) \
		goto rtattr_failure; \
	memcpy(skb_put(skb, attrlen), data, attrlen); })
#define RTA_DATA(rta)   ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_GET_FLAG(rta) (!!(rta))
#define RTA_GET_MSECS(rta) (msecs_to_jiffies((unsigned long) RTA_GET_U64(rta)))
#define RTA_GET_SECS(rta) ((unsigned long) RTA_GET_U64(rta) * HZ)
#define RTA_GET_U16(rta) \
({	if (!rta || RTA_PAYLOAD(rta) < sizeof(u16)) \
		goto rtattr_failure; \
	*(u16 *) RTA_DATA(rta); })
#define RTA_GET_U32(rta) \
({	if (!rta || RTA_PAYLOAD(rta) < sizeof(u32)) \
		goto rtattr_failure; \
	*(u32 *) RTA_DATA(rta); })
#define RTA_GET_U64(rta) \
({	u64 _tmp; \
	if (!rta || RTA_PAYLOAD(rta) < sizeof(u64)) \
		goto rtattr_failure; \
	memcpy(&_tmp, RTA_DATA(rta), sizeof(_tmp)); \
	_tmp; })
#define RTA_GET_U8(rta) \
({	if (!rta || RTA_PAYLOAD(rta) < sizeof(u8)) \
		goto rtattr_failure; \
	*(u8 *) RTA_DATA(rta); })
#define RTA_LENGTH(len)	(RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_MAX (__RTA_MAX - 1)
#define RTA_NEST(skb, type) \
({	struct rtattr *__start = (struct rtattr *) (skb)->tail; \
	RTA_PUT(skb, type, 0, NULL); \
	__start;  })
#define RTA_NEST_CANCEL(skb, start) \
({	if (start) \
		skb_trim(skb, (unsigned char *) (start) - (skb)->data); \
	-1; })
#define RTA_NEST_END(skb, start) \
({	(start)->rta_len = ((skb)->tail - (unsigned char *) (start)); \
	(skb)->len; })
#define RTA_NEXT(rta,attrlen)	((attrlen) -= RTA_ALIGN((rta)->rta_len), \
				 (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_OK(rta,len) ((len) >= (int)sizeof(struct rtattr) && \
			 (rta)->rta_len >= sizeof(struct rtattr) && \
			 (rta)->rta_len <= (len))
#define RTA_PAYLOAD(rta) ((int)((rta)->rta_len) - RTA_LENGTH(0))
#define RTA_PUT(skb, attrtype, attrlen, data) \
({	if (unlikely(skb_tailroom(skb) < (int)RTA_SPACE(attrlen))) \
		 goto rtattr_failure; \
   	__rta_fill(skb, attrtype, attrlen, data); }) 
#define RTA_PUT_FLAG(skb, attrtype) \
	RTA_PUT(skb, attrtype, 0, NULL);
#define RTA_PUT_MSECS(skb, attrtype, value) \
	RTA_PUT_U64(skb, attrtype, jiffies_to_msecs(value))
#define RTA_PUT_NOHDR(skb, attrlen, data) \
({	RTA_APPEND(skb, RTA_ALIGN(attrlen), data); \
	memset(skb->tail - (RTA_ALIGN(attrlen) - attrlen), 0, \
	       RTA_ALIGN(attrlen) - attrlen); })
#define RTA_PUT_SECS(skb, attrtype, value) \
	RTA_PUT_U64(skb, attrtype, (value) / HZ)
#define RTA_PUT_STRING(skb, attrtype, value) \
	RTA_PUT(skb, attrtype, strlen(value) + 1, value)
#define RTA_PUT_U16(skb, attrtype, value) \
({	u16 _tmp = (value); \
	RTA_PUT(skb, attrtype, sizeof(u16), &_tmp); })
#define RTA_PUT_U32(skb, attrtype, value) \
({	u32 _tmp = (value); \
	RTA_PUT(skb, attrtype, sizeof(u32), &_tmp); })
#define RTA_PUT_U64(skb, attrtype, value) \
({	u64 _tmp = (value); \
	RTA_PUT(skb, attrtype, sizeof(u64), &_tmp); })
#define RTA_PUT_U8(skb, attrtype, value) \
({	u8 _tmp = (value); \
	RTA_PUT(skb, attrtype, sizeof(u8), &_tmp); })
#define RTA_SPACE(len)	RTA_ALIGN(RTA_LENGTH(len))
#define RTMGRP_DECnet_IFADDR    0x1000
#define RTMGRP_DECnet_ROUTE     0x4000
#define RTM_DELACTION   RTM_DELACTION
#define RTM_FAM(cmd)	(((cmd) - RTM_BASE) >> 2)
#define RTM_GETACTION   RTM_GETACTION
#define RTM_GETMULTICAST RTM_GETMULTICAST
#define RTM_NEWACTION   RTM_NEWACTION
#define RTM_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct rtmsg))
#define RTM_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct rtmsg))))
#define RTNETLINK_HAVE_PEERINFO 1
#define RTNH_ALIGN(len) ( ((len)+RTNH_ALIGNTO-1) & ~(RTNH_ALIGNTO-1) )
#define RTNH_DATA(rtnh)   ((struct rtattr*)(((char*)(rtnh)) + RTNH_LENGTH(0)))
#define RTNH_LENGTH(len) (RTNH_ALIGN(sizeof(struct rtnexthop)) + (len))
#define RTNH_NEXT(rtnh)	((struct rtnexthop*)(((char*)(rtnh)) + RTNH_ALIGN((rtnh)->rtnh_len)))
#define RTNH_OK(rtnh,len) ((rtnh)->rtnh_len >= sizeof(struct rtnexthop) && \
			   ((int)(rtnh)->rtnh_len) <= (len))
#define RTNH_SPACE(len)	RTNH_ALIGN(RTNH_LENGTH(len))
#define RTN_MAX (__RTN_MAX - 1)
#define RT_TABLE_MAX (__RT_TABLE_MAX - 1)
#define TA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct tcamsg))
#define TA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcamsg))))
#define TCAA_MAX 1
#define TCA_ACT_TAB 1 	
#define TCA_MAX (__TCA_MAX - 1)
#define TCA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct tcmsg))
#define TCA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcmsg))))

#define __RTA_PUT(skb, attrtype, attrlen) \
({ 	if (unlikely(skb_tailroom(skb) < (int)RTA_SPACE(attrlen))) \
		goto rtattr_failure; \
   	__rta_reserve(skb, attrtype, attrlen); })
#define rtattr_parse_nested(tb, max, rta) \
	rtattr_parse((tb), (max), RTA_DATA((rta)), RTA_PAYLOAD((rta)))
#define MAX_LINKS 32		
#define NETLINK_CB(skb)		(*(struct netlink_skb_parms*)&((skb)->cb))
#define NETLINK_CREDS(skb)	(&NETLINK_CB((skb)).creds)
#define NET_MAJOR 36		
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_CANCEL(skb, nlh) \
({	skb_trim(skb, (unsigned char *) (nlh) - (skb)->data); \
	-1; })
#define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
#define NLMSG_END(skb, nlh) \
({	(nlh)->nlmsg_len = (skb)->tail - (unsigned char *) (nlh); \
	(skb)->len; })
#define NLMSG_GOODORDER 0
#define NLMSG_GOODSIZE (SKB_MAX_ORDER(0, NLMSG_GOODORDER))
#define NLMSG_LENGTH(len) ((len)+NLMSG_ALIGN(NLMSG_HDRLEN))
#define NLMSG_NEW(skb, pid, seq, type, len, flags) \
({	if (skb_tailroom(skb) < (int)NLMSG_SPACE(len)) \
		goto nlmsg_failure; \
	__nlmsg_put(skb, pid, seq, type, len, flags); })
#define NLMSG_NEW_ANSWER(skb, cb, type, len, flags) \
	NLMSG_NEW(skb, NETLINK_CB((cb)->skb).pid, \
		  (cb)->nlh->nlmsg_seq, type, len, flags)
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
				  (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
#define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len <= (len))
#define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))
#define NLMSG_PUT(skb, pid, seq, type, len) \
	NLMSG_NEW(skb, pid, seq, type, len, 0)
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
#define NL_NONROOT_RECV 0x1
#define NL_NONROOT_SEND 0x2

#define         BPF_A           0x10
#define         BPF_ABS         0x20
#define         BPF_ADD         0x00
#define         BPF_ALU         0x04
#define         BPF_AND         0x50
#define         BPF_B           0x10
#define BPF_CLASS(code) ((code) & 0x07)
#define         BPF_DIV         0x30
#define         BPF_H           0x08
#define         BPF_IMM         0x00
#define         BPF_IND         0x40
#define         BPF_JA          0x00
#define         BPF_JEQ         0x10
#define         BPF_JGE         0x30
#define         BPF_JGT         0x20
#define         BPF_JMP         0x05
#define         BPF_JSET        0x40
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#define         BPF_K           0x00
#define         BPF_LD          0x00
#define         BPF_LDX         0x01
#define         BPF_LEN         0x80
#define         BPF_LSH         0x60
#define BPF_MAJOR_VERSION 1
#define BPF_MAXINSNS 4096
#define         BPF_MEM         0x60
#define BPF_MEMWORDS 16
#define BPF_MINOR_VERSION 1
#define         BPF_MISC        0x07
#define BPF_MISCOP(code) ((code) & 0xf8)
#define BPF_MODE(code)  ((code) & 0xe0)
#define         BPF_MSH         0xa0
#define         BPF_MUL         0x20
#define         BPF_NEG         0x80
#define BPF_OP(code)    ((code) & 0xf0)
#define         BPF_OR          0x40
#define         BPF_RET         0x06
#define         BPF_RSH         0x70
#define BPF_RVAL(code)  ((code) & 0x18)
#define BPF_SIZE(code)  ((code) & 0x18)
#define BPF_SRC(code)   ((code) & 0x08)
#define         BPF_ST          0x02
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#define         BPF_STX         0x03
#define         BPF_SUB         0x10
#define         BPF_TAX         0x00
#define         BPF_TXA         0x80
#define         BPF_W           0x00
#define         BPF_X           0x08
#define SKF_AD_IFINDEX 	8
#define SKF_AD_MAX 	12
#define SKF_AD_OFF    (-0x1000)
#define SKF_AD_PKTTYPE 	4
#define SKF_AD_PROTOCOL 0
#define SKF_LL_OFF    (-0x200000)
#define SKF_NET_OFF   (-0x100000)



#define __install_session_keyring(tsk, keyring)			\
({								\
	struct key *old_session = tsk->signal->session_keyring;	\
	tsk->signal->session_keyring = keyring;			\
	old_session;						\
})
#define alloc_uid_keyring(u,c)		0
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

#define FLOWI_FLAG_MULTIPATHOLDROUTE 0x01

#define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }

#define IP6_SFLSIZE(count)	(sizeof(struct ip6_sf_socklist) + \
	(count) * sizeof(struct in6_addr))

#define DECLARE_SNMP_STAT(type, name)	\
	extern __typeof__(type) *name[2]
#define DEFINE_SNMP_STAT(type, name)	\
	__typeof__(type) *name[2]
#define SNMP_ADD_STATS_BH(mib, field, addend) 	\
	(per_cpu_ptr(mib[0], raw_smp_processor_id())->mibs[field] += addend)
#define SNMP_ADD_STATS_USER(mib, field, addend) 	\
	(per_cpu_ptr(mib[1], raw_smp_processor_id())->mibs[field] += addend)
#define SNMP_DEC_STATS(mib, field) 	\
	(per_cpu_ptr(mib[!in_softirq()], raw_smp_processor_id())->mibs[field]--)
#define SNMP_INC_STATS(mib, field) 	\
	(per_cpu_ptr(mib[!in_softirq()], raw_smp_processor_id())->mibs[field]++)
#define SNMP_INC_STATS_BH(mib, field) 	\
	(per_cpu_ptr(mib[0], raw_smp_processor_id())->mibs[field]++)
#define SNMP_INC_STATS_OFFSET_BH(mib, field, offset)	\
	(per_cpu_ptr(mib[0], raw_smp_processor_id())->mibs[field + (offset)]++)
#define SNMP_INC_STATS_USER(mib, field) \
	(per_cpu_ptr(mib[1], raw_smp_processor_id())->mibs[field]++)
#define SNMP_MIB_ITEM(_name,_entry)	{	\
	.name = _name,				\
	.entry = _entry,			\
}
#define SNMP_MIB_SENTINEL {	\
	.name = NULL,		\
	.entry = 0,		\
}
#define SNMP_STAT_BHPTR(name)	(name[0])
#define SNMP_STAT_USRPTR(name)	(name[1])



#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 
#define INET_TIMEWAIT_ADDRCMP_ALIGN_BYTES 8
# define INET_TWDR_RECYCLE_TICK (5 + 2 - INET_TWDR_RECYCLE_SLOTS_LOG)
#define INET_TWDR_TWKILL_QUOTA 100

#define inet_twsk_for_each(tw, node, head) \
	hlist_for_each_entry(tw, node, head, tw_node)
#define inet_twsk_for_each_inmate(tw, node, jail) \
	hlist_for_each_entry(tw, node, jail, tw_death_node)
#define inet_twsk_for_each_inmate_safe(tw, node, safe, jail) \
	hlist_for_each_entry_safe(tw, node, safe, jail, tw_death_node)

#define INET_CSK_DEBUG 1

#define ICMPV6_MGM_REDUCTION    	132
#define ICMPV6_MGM_REPORT       	131
#define MLD2_ALL_MCR_INIT { { { 0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x16 } } }


#define sctp_test_T_bit(c)    ((c)->chunk_hdr->flags & SCTP_CHUNK_FLAG_T)
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





#define sctp_tsnmap_storage_size(count) (sizeof(__u8) * (count) * 2)

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
#define MAX_IPOPTLEN 40


#define IPV6_DECODE_PREF(pref)	((pref) ^ 2)	
#define IPV6_EXTRACT_PREF(flag)	(((flag) & RTF_PREF_MASK) >> 27)
#define RTF_PREF(pref)	((pref) << 27)

#define ICMP6_INC_STATS(idev, field)		({			\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		SNMP_INC_STATS(idev->stats.icmpv6, field); 		\
	SNMP_INC_STATS(icmpv6_statistics, field);			\
})
#define ICMP6_INC_STATS_BH(idev, field)		({			\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		SNMP_INC_STATS_BH((_idev)->stats.icmpv6, field);	\
	SNMP_INC_STATS_BH(icmpv6_statistics, field);			\
})
#define ICMP6_INC_STATS_OFFSET_BH(idev, field, offset)	({			\
	struct inet6_dev *_idev = idev;						\
	__typeof__(offset) _offset = (offset);					\
	if (likely(_idev != NULL))						\
		SNMP_INC_STATS_OFFSET_BH(_idev->stats.icmpv6, field, _offset);	\
	SNMP_INC_STATS_OFFSET_BH(icmpv6_statistics, field, _offset);    	\
})
#define ICMP6_INC_STATS_USER(idev, field) 	({			\
	struct inet6_dev *_idev = (idev);				\
	if (likely(_idev != NULL))					\
		SNMP_INC_STATS_USER(_idev->stats.icmpv6, field);	\
	SNMP_INC_STATS_USER(icmpv6_statistics, field);			\
})
#define IP6_INC_STATS(field)		SNMP_INC_STATS(ipv6_statistics, field)
#define IP6_INC_STATS_BH(field)		SNMP_INC_STATS_BH(ipv6_statistics, field)
#define IP6_INC_STATS_USER(field) 	SNMP_INC_STATS_USER(ipv6_statistics, field)
#define IPV6_ADDR_MC_SCOPE(a)	\
	((a)->s6_addr[1] & 0x0f)	
#define IPV6_ADDR_MULTICAST    	0x0002U	
#define IPV6_ADDR_UNICAST      	0x0001U	
#define IPV6_DEFAULT_HOPLIMIT   64
#define UDP6_INC_STATS(field)		SNMP_INC_STATS(udp_stats_in6, field)
#define UDP6_INC_STATS_BH(field)	SNMP_INC_STATS_BH(udp_stats_in6, field)
#define UDP6_INC_STATS_USER(field) 	SNMP_INC_STATS_USER(udp_stats_in6, field)


#define DEFINE_IDR(name)	struct idr name = IDR_INIT(name)
# define IDR_BITS 5
#define IDR_FREE_MAX MAX_LEVEL + MAX_LEVEL
# define IDR_FULL 0xfffffffful
#define IDR_INIT(name)						\
{								\
	.top		= NULL,					\
	.id_free	= NULL,					\
	.layers 	= 0,					\
	.id_free_cnt	= 0,					\
	.lock		= __SPIN_LOCK_UNLOCKED(name.lock),	\
}
#define IDR_MASK ((1 << IDR_BITS)-1)
#define IDR_SIZE (1 << IDR_BITS)
#define MAX_ID_BIT (1U << MAX_ID_SHIFT)
#define MAX_ID_MASK (MAX_ID_BIT - 1)
#define MAX_ID_SHIFT (sizeof(int)*8 - 1)
#define MAX_LEVEL (MAX_ID_SHIFT + IDR_BITS - 1) / IDR_BITS
# define TOP_LEVEL_FULL (IDR_FULL >> 30)

#define FIRST_PROCESS_ENTRY 256
#define PROC_SUPER_MAGIC 0x9fa0

#define proc_bus NULL
#define proc_net NULL
#define proc_net_create(name, mode, info)	({ (void)(mode), NULL; })
#define proc_net_fops_create(name, mode, fops)  ({ (void)(mode), NULL; })
#define proc_root_driver NULL
#define remove_proc_entry(name, parent) do {} while (0)
#define C_BAUD(tty)	_C_FLAG((tty),CBAUD)
#define C_CIBAUD(tty)	_C_FLAG((tty),CIBAUD)
#define C_CLOCAL(tty)	_C_FLAG((tty),CLOCAL)
#define C_CREAD(tty)	_C_FLAG((tty),CREAD)
#define C_CRTSCTS(tty)	_C_FLAG((tty),CRTSCTS)
#define C_CSIZE(tty)	_C_FLAG((tty),CSIZE)
#define C_CSTOPB(tty)	_C_FLAG((tty),CSTOPB)
#define C_HUPCL(tty)	_C_FLAG((tty),HUPCL)
#define C_PARENB(tty)	_C_FLAG((tty),PARENB)
#define C_PARODD(tty)	_C_FLAG((tty),PARODD)
#define DISCARD_CHAR(tty) ((tty)->termios->c_cc[VDISCARD])
#define EOF_CHAR(tty) ((tty)->termios->c_cc[VEOF])
#define EOL2_CHAR(tty) ((tty)->termios->c_cc[VEOL2])
#define EOL_CHAR(tty) ((tty)->termios->c_cc[VEOL])
#define ERASE_CHAR(tty) ((tty)->termios->c_cc[VERASE])
#define INTR_CHAR(tty) ((tty)->termios->c_cc[VINTR])
#define I_BRKINT(tty)	_I_FLAG((tty),BRKINT)
#define I_ICRNL(tty)	_I_FLAG((tty),ICRNL)
#define I_IGNBRK(tty)	_I_FLAG((tty),IGNBRK)
#define I_IGNCR(tty)	_I_FLAG((tty),IGNCR)
#define I_IGNPAR(tty)	_I_FLAG((tty),IGNPAR)
#define I_IMAXBEL(tty)	_I_FLAG((tty),IMAXBEL)
#define I_INLCR(tty)	_I_FLAG((tty),INLCR)
#define I_INPCK(tty)	_I_FLAG((tty),INPCK)
#define I_ISTRIP(tty)	_I_FLAG((tty),ISTRIP)
#define I_IUCLC(tty)	_I_FLAG((tty),IUCLC)
#define I_IUTF8(tty)	_I_FLAG((tty),IUTF8)
#define I_IXANY(tty)	_I_FLAG((tty),IXANY)
#define I_IXOFF(tty)	_I_FLAG((tty),IXOFF)
#define I_IXON(tty)	_I_FLAG((tty),IXON)
#define I_PARMRK(tty)	_I_FLAG((tty),PARMRK)
#define KILL_CHAR(tty) ((tty)->termios->c_cc[VKILL])
#define LNEXT_CHAR(tty)	((tty)->termios->c_cc[VLNEXT])
#define L_ECHO(tty)	_L_FLAG((tty),ECHO)
#define L_ECHOCTL(tty)	_L_FLAG((tty),ECHOCTL)
#define L_ECHOE(tty)	_L_FLAG((tty),ECHOE)
#define L_ECHOK(tty)	_L_FLAG((tty),ECHOK)
#define L_ECHOKE(tty)	_L_FLAG((tty),ECHOKE)
#define L_ECHONL(tty)	_L_FLAG((tty),ECHONL)
#define L_ECHOPRT(tty)	_L_FLAG((tty),ECHOPRT)
#define L_FLUSHO(tty)	_L_FLAG((tty),FLUSHO)
#define L_ICANON(tty)	_L_FLAG((tty),ICANON)
#define L_IEXTEN(tty)	_L_FLAG((tty),IEXTEN)
#define L_ISIG(tty)	_L_FLAG((tty),ISIG)
#define L_NOFLSH(tty)	_L_FLAG((tty),NOFLSH)
#define L_PENDIN(tty)	_L_FLAG((tty),PENDIN)
#define L_TOSTOP(tty)	_L_FLAG((tty),TOSTOP)
#define L_XCASE(tty)	_L_FLAG((tty),XCASE)
#define MIN_CHAR(tty) ((tty)->termios->c_cc[VMIN])
#define N_TTY_BUF_SIZE 4096
#define O_BSDLY(tty)	_O_FLAG((tty),BSDLY)
#define O_CRDLY(tty)	_O_FLAG((tty),CRDLY)
#define O_FFDLY(tty)	_O_FLAG((tty),FFDLY)
#define O_NLDLY(tty)	_O_FLAG((tty),NLDLY)
#define O_OCRNL(tty)	_O_FLAG((tty),OCRNL)
#define O_OFDEL(tty)	_O_FLAG((tty),OFDEL)
#define O_OFILL(tty)	_O_FLAG((tty),OFILL)
#define O_OLCUC(tty)	_O_FLAG((tty),OLCUC)
#define O_ONLCR(tty)	_O_FLAG((tty),ONLCR)
#define O_ONLRET(tty)	_O_FLAG((tty),ONLRET)
#define O_ONOCR(tty)	_O_FLAG((tty),ONOCR)
#define O_OPOST(tty)	_O_FLAG((tty),OPOST)
#define O_TABDLY(tty)	_O_FLAG((tty),TABDLY)
#define O_VTDLY(tty)	_O_FLAG((tty),VTDLY)
#define QUIT_CHAR(tty) ((tty)->termios->c_cc[VQUIT])
#define REPRINT_CHAR(tty) ((tty)->termios->c_cc[VREPRINT])
#define START_CHAR(tty) ((tty)->termios->c_cc[VSTART])
#define STOP_CHAR(tty) ((tty)->termios->c_cc[VSTOP])
#define SUSP_CHAR(tty) ((tty)->termios->c_cc[VSUSP])
#define SWTC_CHAR(tty) ((tty)->termios->c_cc[VSWTC])
#define TIME_CHAR(tty) ((tty)->termios->c_cc[VTIME])
#define TTY_CLOSING 		7	
#define TTY_DEBUG 		4	
#define TTY_DO_WRITE_WAKEUP 	5	
#define TTY_EXCLUSIVE 		3	
#define TTY_FLIPBUF_SIZE 512
#define TTY_HUPPED 		18	
#define TTY_HW_COOK_IN 		15	
#define TTY_HW_COOK_OUT 	14	
#define TTY_IO_ERROR 		1	
#define TTY_LDISC 		9	
#define TTY_NO_WRITE_SPLIT 	17	
#define TTY_OTHER_CLOSED 	2	
#define TTY_PTY_LOCK 		16	
#define TTY_PUSH 		6	
#define TTY_THROTTLED 		0	
#define TTY_WRITE_FLUSH(tty) tty_write_flush((tty))
#define WERASE_CHAR(tty) ((tty)->termios->c_cc[VWERASE])
#define _C_FLAG(tty,f)	((tty)->termios->c_cflag & (f))
#define _I_FLAG(tty,f)	((tty)->termios->c_iflag & (f))

#define _L_FLAG(tty,f)	((tty)->termios->c_lflag & (f))
#define _O_FLAG(tty,f)	((tty)->termios->c_oflag & (f))
#define __DISABLED_CHAR '\0'
#define MODULE_ALIAS_LDISC(ldisc) \
	MODULE_ALIAS("tty-ldisc-" __stringify(ldisc))




#define COMPAQ_CISS_MAJOR2      106
#define COMPAQ_CISS_MAJOR3      107
#define COMPAQ_CISS_MAJOR4      108
#define COMPAQ_CISS_MAJOR5      109
#define COMPAQ_CISS_MAJOR6      110
#define COMPAQ_CISS_MAJOR7      111
#define SCSI_CHANGER_MAJOR      86

#define SCTP_ARG_CONSTRUCTOR(name, type, elt) \
static inline sctp_arg_t	\
SCTP_## name (type arg)		\
{ sctp_arg_t retval = {.zero = 0UL}; retval.elt = arg; return retval; }
#define SCTP_MAX_NUM_COMMANDS 14


#define RT_CONN_FLAGS(sk)   (RT_TOS(inet_sk(sk)->tos) | sock_flag(sk, SOCK_LOCALROUTE))


#define RTCF_DOREDIRECT 0x01000000
#define RTCF_NOPMTUDISC RTM_F_NOPMTUDISC
#define RT_TOS(tos)	((tos)&IPTOS_TOS_MASK)


#define ICMP_INC_STATS(field)		SNMP_INC_STATS(icmp_statistics, field)
#define ICMP_INC_STATS_BH(field)	SNMP_INC_STATS_BH(icmp_statistics, field)
#define ICMP_INC_STATS_USER(field) 	SNMP_INC_STATS_USER(icmp_statistics, field)
#define IPCB(skb) ((struct inet_skb_parm*)((skb)->cb))
#define IP_INC_STATS(field)		SNMP_INC_STATS(ip_statistics, field)
#define IP_INC_STATS_BH(field)		SNMP_INC_STATS_BH(ip_statistics, field)
#define IP_INC_STATS_USER(field) 	SNMP_INC_STATS_USER(ip_statistics, field)
#define NET_ADD_STATS_BH(field, adnd)	SNMP_ADD_STATS_BH(net_statistics, field, adnd)
#define NET_ADD_STATS_USER(field, adnd)	SNMP_ADD_STATS_USER(net_statistics, field, adnd)
#define NET_INC_STATS(field)		SNMP_INC_STATS(net_statistics, field)
#define NET_INC_STATS_BH(field)		SNMP_INC_STATS_BH(net_statistics, field)
#define NET_INC_STATS_USER(field) 	SNMP_INC_STATS_USER(net_statistics, field)

#define CRYPTO_TFM_RES_BAD_BLOCK_LEN 	0x00800000
#define CRYPTO_TFM_RES_BAD_FLAGS 	0x01000000
#define CRYPTO_TFM_RES_BAD_KEY_LEN   	0x00200000
#define CRYPTO_TFM_RES_BAD_KEY_SCHED 	0x00400000

