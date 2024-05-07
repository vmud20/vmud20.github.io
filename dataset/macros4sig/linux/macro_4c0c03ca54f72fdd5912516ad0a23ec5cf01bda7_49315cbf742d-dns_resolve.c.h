






#include<asm/fcntl.h>


#include<linux/resource.h>
#include<asm/param.h>


#include<linux/ipc.h>

#include<asm/auxvec.h>
#include<asm/posix_types.h>





#include<asm/errno.h>
#include<linux/in.h>




#include<asm/shmbuf.h>

#include<asm/types.h>




#include<asm/ioctl.h>




#include<asm/socket.h>



#include<linux/sched.h>

#include<asm/ipcbuf.h>

#include<asm/sembuf.h>

#include<linux/fcntl.h>








#include<linux/stat.h>
#include<linux/neighbour.h>
#include<unistd.h>

#include<linux/stddef.h>
#include<asm/msgbuf.h>
#include<linux/if_link.h>

#include<asm/siginfo.h>

#include<asm/resource.h>

#include<stdarg.h>
#include<linux/xfrm.h>







#include<linux/module.h>
#include<linux/uio.h>


#include<linux/irqnr.h>


#include<asm/hw_breakpoint.h>





#include<asm/poll.h>


#include<asm/byteorder.h>










#include<linux/if.h>

#include<linux/wait.h>




#include<linux/sysctl.h>



#include<linux/fs.h>
#include<linux/param.h>
#include<linux/types.h>

#include<linux/signal.h>
#include<asm/stat.h>
#include<asm/ptrace.h>
#include<linux/time.h>




#include<asm/sockios.h>

#include<linux/ioctl.h>




#include<linux/netlink.h>
#include<linux/string.h>








#include<linux/rtnetlink.h>

#include<string.h>
#include<linux/net.h>
#include<linux/sem.h>
#include<linux/errno.h>


#include<linux/timex.h>
#include<asm/signal.h>
#include<linux/netdevice.h>


#include<linux/kernel.h>

#include<linux/capability.h>
#include<linux/socket.h>
#include<linux/in6.h>

#define CIFS_RC  	0x02
#define DBG2 2

#define cERROR(set, fmt, arg...)		\
do {						\
	if (set)				\
		cifserror(fmt, ##arg);		\
} while (0)
#define cEVENT(fmt, arg...)						\
do {									\
	if (cifsERROR)							\
		printk(KERN_EVENT "%s: " fmt "\n", "__FILE__", ##arg);	\
} while (0)
#define cFYI(set, fmt, arg...)			\
do {						\
	if (set)				\
		cifsfyi(fmt, ##arg);		\
} while (0)
#define cifserror(fmt, arg...)					\
do {								\
	if (cifsERROR)						\
		printk(KERN_ERR "CIFS VFS: " fmt "\n", ##arg);	\
} while (0)
#define cifsfyi(fmt, arg...)						\
do {									\
	if (cifsFYI & CIFS_INFO)					\
		printk(KERN_DEBUG "%s: " fmt "\n", "__FILE__", ##arg);	\
} while (0)
#define cifswarn(fmt, arg...)			\
	printk(KERN_WARNING fmt "\n", ##arg)
#define FreeXid(curr_xid)					\
do {								\
	_FreeXid(curr_xid);					\
	cFYI(1, "CIFS VFS: leaving %s (xid = %d) rc = %d",	\
	     __func__, curr_xid, (int)rc);			\
} while (0)
#define GetXid()						\
({								\
	int __xid = (int)_GetXid();				\
	cFYI(1, "CIFS VFS: in %s as Xid: %d with uid: %d",	\
	     __func__, __xid, current_fsuid());			\
	__xid;							\
})

#define MODULE_ALIAS_NLS(name)	MODULE_ALIAS("nls_" __stringify(name))
#define NLS_MAX_CHARSET_SIZE 6 


#define __CPUINIT        .section	".cpuinit.text", "ax"
#define __CPUINITDATA    .section	".cpuinit.data", "aw"
#define __CPUINITRODATA  .section	".cpuinit.rodata", "a"
#define __DEVINIT        .section	".devinit.text", "ax"
#define __DEVINITDATA    .section	".devinit.data", "aw"
#define __DEVINITRODATA  .section	".devinit.rodata", "a"
#define __INITDATA_OR_MODULE __INITDATA
#define __INITRODATA_OR_MODULE __INITRODATA
#define __INIT_OR_MODULE __INIT
#define __MEMINIT        .section	".meminit.text", "ax"
#define __MEMINITDATA    .section	".meminit.data", "aw"
#define __MEMINITRODATA  .section	".meminit.rodata", "a"
#define __REF            .section       ".ref.text", "ax"
#define __REFCONST       .section       ".ref.rodata", "a"
#define __REFDATA        .section       ".ref.data", "aw"
#define __cpuexit        __section(.cpuexit.text) __exitused __cold
#define __cpuexitconst   __section(.cpuexit.rodata)
#define __cpuexitdata    __section(.cpuexit.data)
#define __cpuinit        __section(.cpuinit.text) __cold
#define __cpuinitconst   __section(.cpuinit.rodata)
#define __cpuinitdata    __section(.cpuinit.data)
#define __define_initcall(level,fn,id) \
	static initcall_t __initcall_##fn##id __used \
	__attribute__((__section__(".initcall" level ".init"))) = fn
#define __devexit        __section(.devexit.text) __exitused __cold
#define __devexit_p(x) x
#define __devexitconst   __section(.devexit.rodata)
#define __devexitdata    __section(.devexit.data)
#define __devinit        __section(.devinit.text) __cold
#define __devinitconst   __section(.devinit.rodata)
#define __devinitdata    __section(.devinit.data)
#define __exit          __section(.exit.text) __exitused __cold
#define __exit_p(x) x
#define __exit_refok     __ref
#define __exitcall(fn) \
	static exitcall_t __exitcall_##fn __exit_call = fn
#define __exitused  __used
#define __init_or_module __init
#define __init_refok     __ref
#define __initcall(fn) device_initcall(fn)
#define __initconst_or_module __initconst
#define __initdata_or_module __initdata
#define __initdata_refok __refdata
#define __memexit        __section(.memexit.text) __exitused __cold
#define __memexitconst   __section(.memexit.rodata)
#define __memexitdata    __section(.memexit.data)
#define __meminit        __section(.meminit.text) __cold
#define __meminitconst   __section(.meminit.rodata)
#define __meminitdata    __section(.meminit.data)
#define __nosavedata __section(.data..nosave)
#define __ref            __section(.ref.text) noinline
#define __refconst       __section(.ref.rodata)
#define __refdata        __section(.ref.data)
#define __setup(str, fn)					\
	__setup_param(str, fn, fn, 0)
#define __setup_param(str, unique_id, fn, early)			\
	static const char __setup_str_##unique_id[] __initconst	\
		__aligned(1) = str; \
	static struct obs_kernel_param __setup_##unique_id	\
		__used __section(.init.setup)			\
		__attribute__((aligned((sizeof(long)))))	\
		= { __setup_str_##unique_id, fn, early }
#define arch_initcall(fn)		__define_initcall("3",fn,3)
#define arch_initcall_sync(fn)		__define_initcall("3s",fn,3s)
#define console_initcall(fn) \
	static initcall_t __initcall_##fn \
	__used __section(.con_initcall.init) = fn
#define core_initcall(fn)		__define_initcall("1",fn,1)
#define core_initcall_sync(fn)		__define_initcall("1s",fn,1s)
#define device_initcall(fn)		__define_initcall("6",fn,6)
#define device_initcall_sync(fn)	__define_initcall("6s",fn,6s)
#define early_initcall(fn)		__define_initcall("early",fn,early)
#define early_param(str, fn)					\
	__setup_param(str, fn, fn, 1)
#define fs_initcall(fn)			__define_initcall("5",fn,5)
#define fs_initcall_sync(fn)		__define_initcall("5s",fn,5s)
#define late_initcall(fn)		__define_initcall("7",fn,7)
#define late_initcall_sync(fn)		__define_initcall("7s",fn,7s)
#define module_exit(x)	__exitcall(x);
#define module_init(x)	__initcall(x);
#define postcore_initcall(fn)		__define_initcall("2",fn,2)
#define postcore_initcall_sync(fn)	__define_initcall("2s",fn,2s)
#define pure_initcall(fn)		__define_initcall("0",fn,0)
#define rootfs_initcall(fn)		__define_initcall("rootfs",fn,rootfs)
#define security_initcall(fn) \
	static initcall_t __initcall_##fn \
	__used __section(.security_initcall.init) = fn
#define subsys_initcall(fn)		__define_initcall("4",fn,4)
#define subsys_initcall_sync(fn)	__define_initcall("4s",fn,4s)
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
# define RELOC_HIDE(ptr, off)					\
  ({ unsigned long __ptr;					\
     __ptr = (unsigned long) (ptr);				\
    (typeof(ptr)) (__ptr + (off)); })

# define __acquire(x)	__context__(x,1)
# define __acquires(x)	__attribute__((context(x,0,1)))
#define __always_inline inline
#define __branch_check__(x, expect) ({					\
			int ______r;					\
			static struct ftrace_branch_data		\
				__attribute__((__aligned__(4)))		\
				__attribute__((section("_ftrace_annotated_branch"))) \
				______f = {				\
				.func = __func__,			\
				.file = "__FILE__",			\
				.line = "__LINE__",			\
			};						\
			______r = likely_notrace(x);			\
			ftrace_likely_update(&______f, ______r, expect); \
			______r;					\
		})
# define __builtin_warning(x, y...) (1)
# define __chk_io_ptr(x) (void)0
# define __chk_user_ptr(x) (void)0

# define __compiletime_error(message)
# define __compiletime_object_size(obj) -1
# define __compiletime_warning(message)
# define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)

#define __deprecated_for_modules __deprecated
# define __force
# define __iomem
# define __kernel

# define __nocast
# define __percpu
# define __release(x)	__context__(x,-1)
# define __releases(x)	__attribute__((context(x,1,0)))
# define __safe
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
# define __section(S) __attribute__ ((__section__(#S)))
#define __trace_if(cond) \
	if (__builtin_constant_p((cond)) ? !!(cond) :			\
	({								\
		int ______r;						\
		static struct ftrace_branch_data			\
			__attribute__((__aligned__(4)))			\
			__attribute__((section("_ftrace_branch")))	\
			______f = {					\
				.func = __func__,			\
				.file = "__FILE__",			\
				.line = "__LINE__",			\
			};						\
		______r = !!(cond);					\
		______f.miss_hit[______r]++;					\
		______r;						\
	}))
# define __user
# define barrier() __memory_barrier()
#define if(cond, ...) __trace_if( (cond , ## __VA_ARGS__) )
#  define likely(x)	(__builtin_constant_p(x) ? !!(x) : __branch_check__(x, 1))
#define likely_notrace(x)	__builtin_expect(!!(x), 1)

#define noinline_for_stack noinline
#define notrace __attribute__((no_instrument_function))
#  define unlikely(x)	(__builtin_constant_p(x) ? !!(x) : __branch_check__(x, 0))
#define unlikely_notrace(x)	__builtin_expect(!!(x), 0)
# define unreachable() do { } while (1)
#define __aligned(x)			__attribute__((aligned(x)))
#define __gcc_header(x) #x
#define __must_be_array(a) \
  BUILD_BUG_ON_ZERO(__builtin_types_compatible_p(typeof(a), typeof(&a[0])))
#define __printf(a,b)			__attribute__((format(printf,a,b)))
#define _gcc_header(x) __gcc_header(linux/compiler-gcc##x.h)
#define gcc_header(x) _gcc_header(x)
#define   CIFSSEC_AUTH_MASK (CIFSSEC_MAY_NTLM | CIFSSEC_MAY_NTLMV2 | CIFSSEC_MAY_LANMAN | CIFSSEC_MAY_PLNTXT | CIFSSEC_MAY_KRB5 | CIFSSEC_MAY_NTLMSSP)
#define   CIFSSEC_DEF (CIFSSEC_MAY_SIGN | CIFSSEC_MAY_NTLM | CIFSSEC_MAY_NTLMV2)
#define	  CIFSSEC_MASK          0x87087 
#define   CIFSSEC_MAX (CIFSSEC_MUST_SIGN | CIFSSEC_MUST_NTLMV2)
#define   CIFSSEC_MAY_LANMAN    0
#define   CIFSSEC_MAY_PLNTXT    0
#define   CIFS_ASYNC_OP         8    
#define   CIFS_BLOCKING_OP      4    
#define   CIFS_IOVEC            4    
#define   CIFS_LARGE_BUFFER     2
#define   CIFS_LARGE_BUF_OP 0x020    
#define   CIFS_LOG_ERROR    0x010    
#define   CIFS_LONG_OP          1    
#define CIFS_MAX_REQ 50
#define CIFS_MIN_RCV_POOL 4
#define   CIFS_NO_BUFFER        0    
#define   CIFS_NO_RESP      0x040    
#define CIFS_SES_LANMAN 8
#define CIFS_SES_NT4 1
#define CIFS_SES_OS2 2
#define CIFS_SES_W9X 4
#define   CIFS_SMALL_BUFFER     1
#define   CIFS_TIMEOUT_MASK 0x00F    
#define   CIFS_VLONG_OP         2    
#define GLOBAL_EXTERN extern
#define MAX_NAME 514
#define MAX_PASSWORD_SIZE 16
#define MAX_SERVER_SIZE 15
#define MAX_SES_INFO 2
#define MAX_SHARE_SIZE  64	
#define MAX_TCON_INFO 4
#define MAX_TREE_SIZE (2 + MAX_SERVER_SIZE + 1 + MAX_SHARE_SIZE + 1)
#define MAX_UID_INFO 16
#define MAX_USERNAME_SIZE 32	
#define   MID_FREE 0
#define   MID_NO_RESP_NEEDED 0x10
#define   MID_REQUEST_ALLOCATED 1
#define   MID_REQUEST_SUBMITTED 2
#define   MID_RESPONSE_RECEIVED 4
#define   MID_RETRY_NEEDED      8 
#define RFC1001_NAME_LEN 15
#define RFC1001_NAME_LEN_WITH_NULL (RFC1001_NAME_LEN + 1)
#define SERVER_NAME_LENGTH 40
#define SERVER_NAME_LEN_WITH_NULL     (SERVER_NAME_LENGTH + 1)
#define UID_HASH (16)
#define XATTR_DOS_ATTRIB "user.DOSATTRIB"
#define  cifs_stats_bytes_read(tcon, bytes) do {} while (0)
#define  cifs_stats_bytes_written(tcon, bytes) do {} while (0)
#define  cifs_stats_inc(field) do {} while (0)
#define ASCII_NULL 0x00
#define ATTR_ARCHIVE   0x0020
#define ATTR_BACKUP_SEMANTICS 0x02000000
#define ATTR_COMPRESSED 0x0800
#define ATTR_DELETE_ON_CLOSE 0x04000000
#define ATTR_DEVICE    0x0040
#define ATTR_DIRECTORY 0x0010
#define ATTR_ENCRYPTED  0x4000
#define ATTR_HIDDEN    0x0002
#define ATTR_NORMAL    0x0080
#define ATTR_NOT_CONTENT_INDEXED 0x2000
#define ATTR_NO_BUFFERING    0x20000000
#define ATTR_OFFLINE    0x1000	
#define ATTR_POSIX_SEMANTICS 0x01000000
#define ATTR_RANDOM_ACCESS   0x10000000
#define ATTR_READONLY  0x0001
#define ATTR_REPARSE   0x0400
#define ATTR_SEQUENTIAL_SCAN 0x08000000
#define ATTR_SPARSE    0x0200
#define ATTR_SYSTEM    0x0004
#define ATTR_TEMPORARY 0x0100
#define ATTR_VOLUME    0x0008
#define ATTR_WRITE_THROUGH   0x80000000
#define BAD_PROT 0xFFFF
#define BCC(smb_var) (*(__u16 *)((char *)(smb_var) + sizeof(struct smb_hdr) + (2 * (smb_var)->WordCount)))
#define BCC_LE(smb_var) (*(__le16 *)((char *)(smb_var) + sizeof(struct smb_hdr) + (2 * (smb_var)->WordCount)))
#define CAP_BULK_TRANSFER      0x20000000
#define CAP_COMPRESSED_DATA    0x02000000
#define CAP_DFS                0x00001000
#define CAP_DYNAMIC_REAUTH     0x20000000
#define CAP_EXTENDED_SECURITY  0x80000000
#define CAP_INFOLEVEL_PASSTHRU 0x00002000
#define CAP_LARGE_FILES        0x00000008
#define CAP_LARGE_READ_X       0x00004000
#define CAP_LARGE_WRITE_X      0x00008000
#define CAP_LEVEL_II_OPLOCKS   0x00000080
#define CAP_LOCK_AND_READ      0x00000100
#define CAP_LWIO               0x00010000 
#define CAP_MPX_MODE           0x00000002
#define CAP_NT_FIND            0x00000200
#define CAP_NT_SMBS            0x00000010	
#define CAP_PERSISTENT_HANDLES 0x40000000
#define CAP_RAW_MODE           0x00000001
#define CAP_RPC_REMOTE_APIS    0x00000020
#define CAP_STATUS32           0x00000040
#define CAP_UNICODE            0x00000004
#define CAP_UNIX               0x00800000
#define CIFS_ACL_DACL  4
#define CIFS_ACL_GROUP 2
#define CIFS_ACL_OWNER 1
#define CIFS_ACL_SACL  8
#define CIFS_ACL_VERSION 1
#define CIFS_ALIAS_TYPE_FILE 0x0001
#define CIFS_COPY_OP 1
#define CIFS_CREATE_ACTION 0x20000 
#define CIFS_CRYPTO_KEY_SIZE (8)
#define CIFS_DFT_PID  0x1234
#define CIFS_ENCPWD_SIZE (16)
#define CIFS_IPC_RESOURCE "\x49\x50\x43\x24"
#define CIFS_IPC_UNICODE_RESOURCE "\x00\x49\x00\x50\x00\x43\x00\x24\x00\x00"
#define CIFS_MAX_MSGSIZE (4*4096)
#define CIFS_NETWORK_OPSYS "CIFS VFS Client for Linux"
#define CIFS_NO_HANDLE        0xFFFF
#define CIFS_POSIX_EXTENSIONS           0x00000010 
#define CIFS_PROT   2
#define CIFS_RENAME_OP 2
#define CIFS_SEARCH_BACKUP_SEARCH 0x0010
#define CIFS_SEARCH_CLOSE_ALWAYS  0x0001
#define CIFS_SEARCH_CLOSE_AT_END  0x0002
#define CIFS_SEARCH_CONTINUE_FROM_LAST 0x0008
#define CIFS_SEARCH_RETURN_RESUME 0x0004
#define CIFS_SESS_KEY_SIZE (24)
#define CIFS_SHARE_TYPE_FILE 0x0000
#define CIFS_SMALL_PATH 120 
#define CIFS_SMB_RESUME_KEY_SIZE 4
#define CIFS_SV_TYPE_BACKDC 0x00000010
#define CIFS_SV_TYPE_DC     0x00000008
#define CIFS_UNIX_CAP_MASK              0x000000db
#define CIFS_UNIX_EXTATTR_CAP           0x00000008 
#define CIFS_UNIX_FCNTL_CAP             0x00000001 
#define CIFS_UNIX_LARGE_READ_CAP        0x00000040 
#define CIFS_UNIX_LARGE_WRITE_CAP       0x00000080
#define CIFS_UNIX_MAJOR_VERSION 1
#define CIFS_UNIX_MINOR_VERSION 0
#define CIFS_UNIX_POSIX_ACL_CAP         0x00000002 
#define CIFS_UNIX_POSIX_PATHNAMES_CAP   0x00000010 
#define CIFS_UNIX_POSIX_PATH_OPS_CAP    0x00000020 
#define CIFS_UNIX_PROXY_CAP             0x00000400 
#define CIFS_UNIX_TRANSPORT_ENCRYPTION_CAP 0x00000100 
#define CIFS_UNIX_TRANSPORT_ENCRYPTION_MANDATORY_CAP  0x00000200 
#define CIFS_UNIX_XATTR_CAP             0x00000004 
#define CIFS_UNLCK      2
#define CIFS_UNLEN (20)
#define CNLEN 15
#define COPY_MUST_BE_DIR       0x0002
#define COPY_MUST_BE_FILE      0x0001
#define COPY_SOURCE_MODE_ASCII 0x0008 
#define COPY_TARGET_MODE_ASCII 0x0004 
#define COPY_TREE              0x0020
#define COPY_VERIFY_WRITES     0x0010
#define CREATE_ASYNC_ALERT      0x00000020	
#define CREATE_COMPLETE_IF_OPLK 0x00000100	
#define CREATE_EIGHT_DOT_THREE  0x00000400	
#define CREATE_NO_BUFFER        0x00000008      
#define CREATE_NO_COMPRESSION   0x00008000
#define CREATE_NO_EA_KNOWLEDGE  0x00000200
#define CREATE_OPEN_BACKUP_INTENT 0x00004000
#define CREATE_OPEN_BY_ID       0x00002000
#define CREATE_OPEN_FOR_RECOVERY 0x00000400
#define CREATE_OPTIONS_MASK     0x007FFFFF
#define CREATE_OPTION_SPECIAL   0x20000000   
#define CREATE_RESERVE_OPFILTER 0x00100000	
#define CREATE_SEQUENTIAL       0x00000004
#define CREATE_SYNC_ALERT       0x00000010	
#define CREATE_TREE_CONNECTION  0x00000080	
#define DELETE                0x00010000  
#define DFSREF_REFERRAL_SERVER  0x00000001 
#define DFSREF_STORAGE_SERVER   0x00000002 
#define DFSREF_TARGET_FAILBACK  0x00000004 
#define DFS_NAME_LIST_REF 0x0200 
#define DFS_TARGET_SET_BOUNDARY 0x0400 
#define DFS_TYPE_LINK 0x0000  
#define DFS_TYPE_ROOT 0x0001
#define DFS_VERSION cpu_to_le16(0x0003)
#define DISCONNECT_TID          0x0001
#define FEA_NEEDEA         0x80	
#define FILE_APPEND_DATA      0x00000004  
#define FILE_CREATE       0x00000002
#define FILE_DELETE_CHILD     0x00000040
#define FILE_DEVICE_CD_ROM              0x00000002
#define FILE_DEVICE_CD_ROM_FILE_SYSTEM  0x00000003
#define FILE_DEVICE_DFS                 0x00000006
#define FILE_DEVICE_DISK                0x00000007
#define FILE_DEVICE_DISK_FILE_SYSTEM    0x00000008
#define FILE_DEVICE_FILE_SYSTEM         0x00000009
#define FILE_DEVICE_NAMED_PIPE          0x00000011
#define FILE_DEVICE_NETWORK             0x00000012
#define FILE_DEVICE_NETWORK_FILE_SYSTEM 0x00000014
#define FILE_DEVICE_NETWORK_REDIRECTOR  0x00000028
#define FILE_DEVICE_NULL                0x00000015
#define FILE_DEVICE_PARALLEL_PORT       0x00000016
#define FILE_DEVICE_PRINTER             0x00000018
#define FILE_DEVICE_SERIAL_PORT         0x0000001b
#define FILE_DEVICE_STREAMS             0x0000001e
#define FILE_DEVICE_TAPE                0x0000001f
#define FILE_DEVICE_TAPE_FILE_SYSTEM    0x00000020
#define FILE_DEVICE_VIRTUAL_DISK        0x00000024
#define FILE_EXECUTE          0x00000020  
#define FILE_EXEC_RIGHTS (FILE_EXECUTE)
#define FILE_NOTIFY_CHANGE_ATTRIBUTES   0x00000004
#define FILE_NOTIFY_CHANGE_CREATION     0x00000040
#define FILE_NOTIFY_CHANGE_DIR_NAME     0x00000002
#define FILE_NOTIFY_CHANGE_EA           0x00000080
#define FILE_NOTIFY_CHANGE_FILE_NAME    0x00000001
#define FILE_NOTIFY_CHANGE_LAST_ACCESS  0x00000020
#define FILE_NOTIFY_CHANGE_LAST_WRITE   0x00000010
#define FILE_NOTIFY_CHANGE_NAME         0x00000003
#define FILE_NOTIFY_CHANGE_SECURITY     0x00000100
#define FILE_NOTIFY_CHANGE_SIZE         0x00000008
#define FILE_NOTIFY_CHANGE_STREAM_NAME  0x00000200
#define FILE_NOTIFY_CHANGE_STREAM_SIZE  0x00000400
#define FILE_NOTIFY_CHANGE_STREAM_WRITE 0x00000800
#define FILE_NO_SHARE     0x00000000
#define FILE_OPEN         0x00000001
#define FILE_OPEN_IF      0x00000003
#define FILE_OVERWRITE    0x00000004
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_READ_ATTRIBUTES  0x00000080  
#define FILE_READ_DATA        0x00000001  
#define FILE_READ_EA          0x00000008  
#define FILE_READ_RIGHTS (FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES)
#define FILE_SHARE_ALL    0x00000007
#define FILE_SHARE_DELETE 0x00000004
#define FILE_SHARE_READ   0x00000001
#define FILE_SHARE_WRITE  0x00000002
#define FILE_SUPERSEDE    0x00000000
#define FILE_WRITE_ATTRIBUTES 0x00000100  
#define FILE_WRITE_DATA       0x00000002  
#define FILE_WRITE_EA         0x00000010  
#define FILE_WRITE_RIGHTS (FILE_WRITE_DATA | FILE_APPEND_DATA \
				| FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES)
#define GENERIC_ALL           0x10000000
#define GENERIC_EXECUTE       0x20000000
#define GENERIC_READ          0x80000000
#define GENERIC_WRITE         0x40000000
#define GETU16(var)  (*((__u16 *)var))	
#define GETU32(var)  (*((__u32 *)var))	
#define GUEST_LOGIN 1
#define LANMAN2_PROT 1
#define LANMAN_PROT 0
#define LOCKING_ANDX_CANCEL_LOCK     0x08
#define LOCKING_ANDX_CHANGE_LOCKTYPE 0x04
#define LOCKING_ANDX_LARGE_FILES     0x10	
#define LOCKING_ANDX_OPLOCK_RELEASE  0x02
#define LOCKING_ANDX_SHARED_LOCK     0x01
#define MAXCOMMENTLEN 40
#define MAX_CIFS_HDR_SIZE 0x58 
#define MAX_CIFS_SMALL_BUFFER_SIZE 448 
#define MAX_PATHCONF 256
#define MIN_TZ_ADJ (15 * 60) 
#define NO_CHANGE_32          0xFFFFFFFFUL
#define NO_CHANGE_64          0xFFFFFFFFFFFFFFFFULL
#define NT_TRANSACT_CREATE            0x01
#define NT_TRANSACT_GET_USER_QUOTA    0x07
#define NT_TRANSACT_IOCTL             0x02
#define NT_TRANSACT_NOTIFY_CHANGE     0x04
#define NT_TRANSACT_QUERY_SECURITY_DESC 0x06
#define NT_TRANSACT_RENAME            0x05
#define NT_TRANSACT_SET_SECURITY_DESC 0x03
#define NT_TRANSACT_SET_USER_QUOTA    0x08
#define OPEN_FREE_SPACE_QUERY   0x00800000	
#define OPEN_NO_RECALL          0x00400000
#define OPLOCK_EXCLUSIVE 1
#define OPLOCK_NONE  	 0
#define POSIX_PROT  (CIFS_PROT+1)
#define RAW_ENABLE (READ_RAW_ENABLE | WRITE_RAW_ENABLE)
#define READ_CONTROL          0x00020000  
#define READ_RAW_ENABLE 1
#define REQ_BATCHOPLOCK    0x00000004
#define REQ_EXTENDED_INFO  0x00000010
#define REQ_MORE_INFO      0x00000001  
#define REQ_OPENDIRONLY    0x00000008
#define REQ_OPLOCK         0x00000002
#define SECMODE_PW_ENCRYPT    0x02
#define SECMODE_SIGN_ENABLED  0x04	
#define SECMODE_SIGN_REQUIRED 0x08	
#define SECMODE_USER          0x01	
#define SECURITY_ANONYMOUS      0
#define SECURITY_CONTEXT_TRACKING 0x01
#define SECURITY_DELEGATION     3
#define SECURITY_EFFECTIVE_ONLY   0x02
#define SECURITY_IDENTIFICATION 1
#define SECURITY_IMPERSONATION  2
#define SET_FILE_EXEC_RIGHTS (FILE_READ_EA | FILE_WRITE_EA | FILE_EXECUTE \
				| FILE_READ_ATTRIBUTES \
				| FILE_WRITE_ATTRIBUTES \
				| DELETE | READ_CONTROL | WRITE_DAC \
				| WRITE_OWNER | SYNCHRONIZE)
#define SET_FILE_READ_RIGHTS (FILE_READ_DATA | FILE_READ_EA | FILE_WRITE_EA \
				| FILE_READ_ATTRIBUTES \
				| FILE_WRITE_ATTRIBUTES \
				| DELETE | READ_CONTROL | WRITE_DAC \
				| WRITE_OWNER | SYNCHRONIZE)
#define SET_FILE_WRITE_RIGHTS (FILE_WRITE_DATA | FILE_APPEND_DATA \
				| FILE_READ_EA | FILE_WRITE_EA \
				| FILE_DELETE_CHILD | FILE_READ_ATTRIBUTES \
				| FILE_WRITE_ATTRIBUTES \
				| DELETE | READ_CONTROL | WRITE_DAC \
				| WRITE_OWNER | SYNCHRONIZE)
#define SET_MINIMUM_RIGHTS (FILE_READ_EA | FILE_READ_ATTRIBUTES \
				| READ_CONTROL | SYNCHRONIZE)
#define SMBFLG2_COMPRESSED (8)
#define SMBFLG2_DFS cpu_to_le16(0x1000)
#define SMBFLG2_ERR_STATUS cpu_to_le16(0x4000)
#define SMBFLG2_EXT_SEC cpu_to_le16(0x800)
#define SMBFLG2_IS_LONG_NAME cpu_to_le16(0x40)
#define SMBFLG2_KNOWS_EAS cpu_to_le16(2)
#define SMBFLG2_KNOWS_LONG_NAMES cpu_to_le16(1)	
#define SMBFLG2_PAGING_IO cpu_to_le16(0x2000)
#define SMBFLG2_REPARSE_PATH (0x400)
#define SMBFLG2_SECURITY_SIGNATURE cpu_to_le16(4)
#define SMBFLG2_SECURITY_SIGNATURE_REQUIRED (0x10)
#define SMBFLG2_UNICODE cpu_to_le16(0x8000)
#define SMBFLG_CANONICAL_PATH_FORMAT 0x10	
#define SMBFLG_CASELESS 0x08	
#define SMBFLG_EXTD_LOCK 0x01	
#define SMBFLG_OLD_OPLOCK 0x20	
#define SMBFLG_OLD_OPLOCK_NOTIFY 0x40	
#define SMBFLG_RCV_POSTED 0x02	
#define SMBFLG_RESPONSE 0x80	
#define SMBFLG_RSVD 0x04
#define SMBOPEN_DENY_ALL      0x0010
#define SMBOPEN_DENY_NONE     0x0040
#define SMBOPEN_DENY_READ     0x0030
#define SMBOPEN_DENY_WRITE    0x0020
#define SMBOPEN_EXECUTE       0x0003
#define SMBOPEN_OAPPEND       0x0001
#define SMBOPEN_OCREATE       0x0010
#define SMBOPEN_OTRUNC        0x0002
#define SMBOPEN_READ          0x0000
#define SMBOPEN_READWRITE     0x0002
#define SMBOPEN_WRITE         0x0001
#define SMBOPEN_WRITE_THROUGH 0x4000
#define SMB_COM_CLOSE                 0x04 
#define SMB_COM_COPY                  0x29 
#define SMB_COM_CREATE_DIRECTORY      0x00 
#define SMB_COM_DELETE                0x06 
#define SMB_COM_DELETE_DIRECTORY      0x01 
#define SMB_COM_FIND_CLOSE2           0x34 
#define SMB_COM_FLUSH                 0x05 
#define SMB_COM_LOCKING_ANDX          0x24 
#define SMB_COM_LOGOFF_ANDX           0x74 
#define SMB_COM_NEGOTIATE             0x72
#define SMB_COM_NT_CANCEL             0xA4 
#define SMB_COM_NT_CREATE_ANDX        0xA2
#define SMB_COM_NT_RENAME             0xA5 
#define SMB_COM_NT_TRANSACT           0xA0
#define SMB_COM_NT_TRANSACT_SECONDARY 0xA1
#define SMB_COM_OPEN_ANDX             0x2D 
#define SMB_COM_QUERY_INFORMATION     0x08 
#define SMB_COM_READ_ANDX             0x2E
#define SMB_COM_RENAME                0x07 
#define SMB_COM_SESSION_SETUP_ANDX    0x73
#define SMB_COM_SETATTR               0x09 
#define SMB_COM_TRANSACTION2          0x32
#define SMB_COM_TRANSACTION2_SECONDARY 0x33
#define SMB_COM_TREE_CONNECT_ANDX     0x75
#define SMB_COM_TREE_DISCONNECT       0x71 
#define SMB_COM_WRITE_ANDX            0x2F
#define SMB_CSC_CACHE_AUTO_REINT   0x0004
#define SMB_CSC_CACHE_MANUAL_REINT 0x0000
#define SMB_CSC_CACHE_VDO          0x0008
#define SMB_CSC_MASK               0x000C
#define SMB_CSC_NO_CACHING         0x000C
#define SMB_EXTENDED_SIGNATURES 0x0020
#define SMB_FILE_ALL_INFO2              0x3fa
#define SMB_FILE_MAXIMUM_INFO           0x40d
#define SMB_FILE_MOVE_CLUSTER_INFO      0x407
#define SMB_FILE_QUOTA_INFO             0x408
#define SMB_FILE_REPARSEPOINT_INFO      0x409
#define SMB_FIND_FILE_BOTH_DIRECTORY_INFO 0x104
#define SMB_FIND_FILE_DIRECTORY_INFO      0x101
#define SMB_FIND_FILE_FULL_DIRECTORY_INFO 0x102
#define SMB_FIND_FILE_ID_BOTH_DIR_INFO    0x106
#define SMB_FIND_FILE_ID_FULL_DIR_INFO    0x105
#define SMB_FIND_FILE_INFO_STANDARD       0x001
#define SMB_FIND_FILE_NAMES_INFO          0x103
#define SMB_FIND_FILE_QUERY_EAS_FROM_LIST 0x003
#define SMB_FIND_FILE_QUERY_EA_SIZE       0x002
#define SMB_FIND_FILE_UNIX                0x202
#define SMB_INFO_ALLOCATION         1
#define SMB_INFO_IS_NAME_VALID              6
#define SMB_INFO_QUERY_ALL_EAS              4
#define SMB_INFO_QUERY_EAS_FROM_LIST        3
#define SMB_INFO_STANDARD                   1
#define SMB_INFO_VOLUME             2
#define SMB_O_APPEND 	0x80
#define SMB_O_CREAT 	0x10
#define SMB_O_DIRECT 	0x800
#define SMB_O_DIRECTORY 0x200
#define SMB_O_EXCL 	0x20
#define SMB_O_NOFOLLOW 	0x400
#define SMB_O_RDONLY 	 0x1
#define SMB_O_RDWR 	0x4
#define SMB_O_SYNC 	0x100
#define SMB_O_TRUNC 	0x40
#define SMB_O_WRONLY 	0x2
#define SMB_POSIX_OPEN                  0x209
#define SMB_POSIX_UNLINK                0x20a
#define SMB_QUERY_ALT_NAME_INFO         0x108
#define SMB_QUERY_ATTR_FLAGS            0x206  
#define SMB_QUERY_CIFS_UNIX_INFO    0x200
#define SMB_QUERY_FILE_ACCESS_INFO      0x3f0
#define SMB_QUERY_FILE_ALGN_INFO        0x3f9
#define SMB_QUERY_FILE_ALLOCATION_INFO  0x105
#define SMB_QUERY_FILE_ALL_INFO         0x107
#define SMB_QUERY_FILE_BASIC_INFO       0x101
#define SMB_QUERY_FILE_COMPRESSION_INFO 0x10B
#define SMB_QUERY_FILE_EA_INFO          0x103
#define SMB_QUERY_FILE_EA_SIZE              2
#define SMB_QUERY_FILE_END_OF_FILEINFO  0x106
#define SMB_QUERY_FILE_INTERNAL_INFO    0x3ee
#define SMB_QUERY_FILE_MODE_INFO        0x3f8
#define SMB_QUERY_FILE_NAME_INFO        0x104
#define SMB_QUERY_FILE_NAME_INFO2       0x3f1 
#define SMB_QUERY_FILE_POSITION_INFO    0x3f6
#define SMB_QUERY_FILE_STANDARD_INFO    0x102
#define SMB_QUERY_FILE_STREAM_INFO      0x109
#define SMB_QUERY_FILE_UNIX_BASIC       0x200
#define SMB_QUERY_FILE_UNIX_LINK        0x201
#define SMB_QUERY_FILE__UNIX_INFO2      0x20b
#define SMB_QUERY_FS_ATTRIBUTE_INFO 0x105
#define SMB_QUERY_FS_DEVICE_INFO    0x104
#define SMB_QUERY_FS_FULL_SIZE_INFO 0x3ef
#define SMB_QUERY_FS_PROXY          0x204 
#define SMB_QUERY_FS_QUOTA_INFO     0x3ee
#define SMB_QUERY_FS_SIZE_INFO      0x103
#define SMB_QUERY_FS_VOLUME_INFO    0x102
#define SMB_QUERY_LABEL_INFO        0x3ea
#define SMB_QUERY_OBJECTID_INFO     0x3f0
#define SMB_QUERY_POSIX_ACL             0x204
#define SMB_QUERY_POSIX_FS_INFO     0x201
#define SMB_QUERY_POSIX_LOCK            0x208
#define SMB_QUERY_POSIX_PERMISSION      0x207
#define SMB_QUERY_POSIX_WHO_AM_I    0x202
#define SMB_QUERY_XATTR                 0x205  
#define SMB_REQUEST_TRANSPORT_ENCRYPTION 0x203
#define SMB_SET_ATTR_FLAGS              0x206  
#define SMB_SET_CIFS_UNIX_INFO    0x200
#define SMB_SET_FILE_ALLOCATION_INFO    0x103
#define SMB_SET_FILE_ALLOCATION_INFO2   0x3fb
#define SMB_SET_FILE_BASIC_INFO2        0x3ec
#define SMB_SET_FILE_DISPOSITION_INFO   0x102
#define SMB_SET_FILE_EA                     2
#define SMB_SET_FILE_END_OF_FILE_INFO   0x104
#define SMB_SET_FILE_END_OF_FILE_INFO2  0x3fc
#define SMB_SET_FILE_RENAME_INFORMATION 0x3f2 
#define SMB_SET_FILE_UNIX_BASIC         0x200
#define SMB_SET_FILE_UNIX_HLINK         0x203
#define SMB_SET_FILE_UNIX_INFO2         0x20b
#define SMB_SET_FILE_UNIX_LINK          0x201
#define SMB_SET_POSIX_ACL               0x204
#define SMB_SET_POSIX_LOCK              0x208
#define SMB_SET_XATTR                   0x205
#define SMB_SHARE_IS_IN_DFS     0x0002
#define SMB_SUPPORT_SEARCH_BITS 0x0001	
#define SMB_UNIQUE_FILE_NAME    0x0010
#define SYNCHRONIZE           0x00100000  
#define TCON_EXTENDED_SECINFO   0x0008
#define TCON_EXTENDED_SIGNATURES 0x0004
#define TRANS2_FIND_FIRST             0x01
#define TRANS2_FIND_NEXT              0x02
#define TRANS2_GET_DFS_REFERRAL       0x10
#define TRANS2_OPEN                   0x00
#define TRANS2_QUERY_FILE_INFORMATION 0x07
#define TRANS2_QUERY_FS_INFORMATION   0x03
#define TRANS2_QUERY_PATH_INFORMATION 0x05
#define TRANS2_REPORT_DFS_INCOSISTENCY 0x11
#define TRANS2_SET_FILE_INFORMATION   0x08
#define TRANS2_SET_FS_INFORMATION     0x04
#define TRANS2_SET_PATH_INFORMATION   0x06
#define TRANS_CALL_NMPIPE           0x0054
#define TRANS_PEEK_NMPIPE           0x0023
#define TRANS_QUERY_NMPIPE_INFO     0x0022
#define TRANS_QUERY_NMPIPE_STATE    0x0021
#define TRANS_RAW_READ_NMPIPE       0x0011
#define TRANS_RAW_WRITE_NMPIPE      0x0031
#define TRANS_READ_NMPIPE           0x0036
#define TRANS_SET_NMPIPE_STATE      0x0001
#define TRANS_TRANSACT_NMPIPE       0x0026
#define TRANS_WAIT_NMPIPE           0x0053
#define TRANS_WRITE_NMPIPE          0x0037
#define UNICODE_NULL "\x00\x00"
#define UNIX_BLOCKDEV  4
#define UNIX_CHARDEV   3
#define UNIX_DIR       1
#define UNIX_FIFO      5
#define UNIX_FILE      0
#define UNIX_SOCKET    6
#define UNIX_SYMLINK   2
#define WRITE_DAC             0x00040000  
#define WRITE_OWNER           0x00080000  
#define WRITE_RAW_ENABLE 2

#define pByteArea(smb_var) ((unsigned char *)(smb_var) + sizeof(struct smb_hdr) + (2 * (smb_var)->WordCount) + 2)
#define FSCTL_ALLOW_EXTENDED_DASD_IO 0x00090083 
#define FSCTL_CREATE_OR_GET_OBJECT_ID 0x000900C0 
#define FSCTL_DELETE_OBJECT_ID       0x000900A0 
#define FSCTL_DELETE_REPARSE_POINT   0x000900AC 
#define FSCTL_ENCRYPTION_FSCTL_IO    0x000900DB 
#define FSCTL_FILESYSTEM_GET_STATS   0x00090060 
#define FSCTL_FIND_FILES_BY_SID      0x0009008F 
#define FSCTL_GET_COMPRESSION        0x0009003C 
#define FSCTL_GET_NTFS_VOLUME_DATA   0x00090064 
#define FSCTL_GET_OBJECT_ID          0x0009009C 
#define FSCTL_GET_REPARSE_POINT      0x000900A8 
#define FSCTL_GET_RETRIEVAL_POINTERS 0x00090073 
#define FSCTL_IS_PATHNAME_VALID      0x0009002C 
#define FSCTL_IS_VOLUME_DIRTY        0x00090078 
#define FSCTL_LMR_GET_LINK_TRACK_INF 0x001400E8 
#define FSCTL_LMR_SET_LINK_TRACK_INF 0x001400EC 
#define FSCTL_LOCK_VOLUME            0x00090018
#define FSCTL_PIPE_PEEK              0x0011400C 
#define FSCTL_PIPE_TRANSCEIVE        0x0011C017 
#define FSCTL_PIPE_WAIT              0x00110018 
#define FSCTL_QUERY_ALLOCATED_RANGES 0x000940CF 
#define FSCTL_QUERY_FAT_BPB          0x00090058 
#define FSCTL_QUERY_SPARING_INFO     0x00090138 
#define FSCTL_READ_FILE_USN_DATA     0x000900EB 
#define FSCTL_READ_RAW_ENCRYPTED     0x000900E3 
#define FSCTL_RECALL_FILE            0x00090117 
#define FSCTL_REQUEST_BATCH_OPLOCK   0x00090008
#define FSCTL_REQUEST_FILTER_OPLOCK  0x0009008C
#define FSCTL_REQUEST_OPLOCK_LEVEL_1 0x00090000
#define FSCTL_REQUEST_OPLOCK_LEVEL_2 0x00090004
#define FSCTL_SET_COMPRESSION        0x0009C040 
#define FSCTL_SET_DEFECT_MANAGEMENT  0x00098134 
#define FSCTL_SET_ENCRYPTION         0x000900D7 
#define FSCTL_SET_OBJECT_ID          0x00090098 
#define FSCTL_SET_OBJECT_ID_EXTENDED 0x000900BC 
#define FSCTL_SET_REPARSE_POINT      0x000900A4 
#define FSCTL_SET_SHORT_NAME_BEHAVIOR 0x000901B4 
#define FSCTL_SET_SPARSE             0x000900C4 
#define FSCTL_SET_ZERO_DATA          0x000900C8 
#define FSCTL_SET_ZERO_ON_DEALLOC    0x00090194 
#define FSCTL_SIS_COPYFILE           0x00090100 
#define FSCTL_SIS_LINK_FILES         0x0009C104
#define FSCTL_UNLOCK_VOLUME          0x0009001C
#define FSCTL_WRITE_RAW_ENCRYPTED    0x000900DF 
#define FSCTL_WRITE_USN_CLOSE_RECORD 0x000900EF 
#define IO_REPARSE_TAG_HSM           0xC0000004
#define IO_REPARSE_TAG_MOUNT_POINT   0xA0000003
#define IO_REPARSE_TAG_SIS           0x80000007
#define FLAGS_TS_OR_DROPS ((1UL << SOCK_RXQ_OVFL)			| \
			   (1UL << SOCK_RCVTSTAMP)			| \
			   (1UL << SOCK_TIMESTAMPING_RX_SOFTWARE)	| \
			   (1UL << SOCK_TIMESTAMPING_SOFTWARE)		| \
			   (1UL << SOCK_TIMESTAMPING_RAW_HARDWARE) 	| \
			   (1UL << SOCK_TIMESTAMPING_SYS_HARDWARE))
#define LIMIT_NETDEBUG(fmt, args...) \
	do { if (net_msg_warn && net_ratelimit()) printk(fmt,##args); } while(0)
#define NETDEBUG(fmt, args...) \
	do { if (net_msg_warn) printk(fmt,##args); } while (0)
#define SK_MEM_QUANTUM ((int)PAGE_SIZE)
#define SK_MEM_QUANTUM_SHIFT ilog2(SK_MEM_QUANTUM)
#define SOCK_DEBUG(sk, msg...) do { if ((sk) && sock_flag((sk), SOCK_DBG)) \
					printk(KERN_DEBUG msg); } while (0)

#define SOCK_DESTROY_TIME (10*HZ)
#define SOCK_MIN_RCVBUF 256
#define SOCK_MIN_SNDBUF 2048

#define bh_lock_sock(__sk)	spin_lock(&((__sk)->sk_lock.slock))
#define bh_lock_sock_nested(__sk) \
				spin_lock_nested(&((__sk)->sk_lock.slock), \
				SINGLE_DEPTH_NESTING)
#define bh_unlock_sock(__sk)	spin_unlock(&((__sk)->sk_lock.slock))
#define sk_del_node_init_rcu(sk)	sk_del_node_init(sk)
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
#define sk_for_each_rcu(__sk, node, list) \
	hlist_for_each_entry_rcu(__sk, node, list, sk_node)
#define sk_for_each_safe(__sk, node, tmp, list) \
	hlist_for_each_entry_safe(__sk, node, tmp, list, sk_node)
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
#define sk_wait_event(__sk, __timeo, __condition)			\
	({	int __rc;						\
		release_sock(__sk);					\
		__rc = __condition;					\
		if (!__rc) {						\
			*(__timeo) = schedule_timeout(*(__timeo));	\
		}							\
		lock_sock(__sk);					\
		__rc = __condition;					\
		__rc;							\
	})
#define sock_lock_init_class_and_name(sk, sname, skey, name, key) 	\
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
#define sock_owned_by_user(sk)	((sk)->sk_lock.owned)
#define CSUM_MANGLED_0 ((__force __sum16)0xffff)

#define ERESTART_RESTARTBLOCK 516 


#define LOCALLY_ENQUEUED 0x1
#define NEIGH_CACHE_STAT_INC(tbl, field) this_cpu_inc((tbl)->stats->field)
#define NEIGH_CB(skb)	((struct neighbour_cb *)(skb)->cb)

#define neigh_hold(n)	atomic_inc(&(n)->refcnt)
#define MODULE_ALIAS_RTNL_LINK(kind) MODULE_ALIAS("rtnl-link-" kind)

#define NLA_PUT(skb, attrtype, attrlen, data) \
	do { \
		if (unlikely(nla_put(skb, attrtype, attrlen, data) < 0)) \
			goto nla_put_failure; \
	} while(0)
#define NLA_PUT_BE16(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, __be16, attrtype, value)
#define NLA_PUT_BE32(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, __be32, attrtype, value)
#define NLA_PUT_BE64(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, __be64, attrtype, value)
#define NLA_PUT_FLAG(skb, attrtype) \
	NLA_PUT(skb, attrtype, 0, NULL)
#define NLA_PUT_LE16(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, __le16, attrtype, value)
#define NLA_PUT_MSECS(skb, attrtype, jiffies) \
	NLA_PUT_U64(skb, attrtype, jiffies_to_msecs(jiffies))
#define NLA_PUT_STRING(skb, attrtype, value) \
	NLA_PUT(skb, attrtype, strlen(value) + 1, value)
#define NLA_PUT_TYPE(skb, type, attrtype, value) \
	do { \
		type __tmp = value; \
		NLA_PUT(skb, attrtype, sizeof(type), &__tmp); \
	} while(0)
#define NLA_PUT_U16(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, u16, attrtype, value)
#define NLA_PUT_U32(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, u32, attrtype, value)
#define NLA_PUT_U64(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, u64, attrtype, value)
#define NLA_PUT_U8(skb, attrtype, value) \
	NLA_PUT_TYPE(skb, u8, attrtype, value)
#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)

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
#define ACTHZ (SH_DIV (CLOCK_TICK_RATE, LATCH, 8))
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))
#define LATCH  ((CLOCK_TICK_RATE + HZ/2) / HZ)	
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
#define TICK_NSEC (SH_DIV (1000000UL * 1000, ACTHZ, 8))
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
#define time_after64(a,b)	\
	(typecheck(__u64, a) &&	\
	 typecheck(__u64, b) && \
	 ((__s64)(b) - (__s64)(a) < 0))
#define time_after_eq(a,b)	\
	(typecheck(unsigned long, a) && \
	 typecheck(unsigned long, b) && \
	 ((long)(a) - (long)(b) >= 0))
#define time_after_eq64(a,b)	\
	(typecheck(__u64, a) && \
	 typecheck(__u64, b) && \
	 ((__s64)(a) - (__s64)(b) >= 0))
#define time_before(a,b)	time_after(b,a)
#define time_before64(a,b)	time_after64(b,a)
#define time_before_eq(a,b)	time_after_eq(b,a)
#define time_before_eq64(a,b)	time_after_eq64(b,a)
#define time_in_range(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before_eq(a,c))
#define time_in_range_open(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before(a,c))
#define time_is_after_eq_jiffies(a) time_before_eq(jiffies, a)
#define time_is_after_jiffies(a) time_before(jiffies, a)
#define time_is_before_eq_jiffies(a) time_after_eq(jiffies, a)
#define time_is_before_jiffies(a) time_after(jiffies, a)
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
#define STA_RONLY (STA_PPSSIGNAL | STA_PPSJITTER | STA_PPSWANDER | \
	STA_PPSERROR | STA_CLOCKERR | STA_NANO | STA_MODE | STA_CLK)

#define shift_right(x, s) ({	\
	__typeof__(x) __x = (x);	\
	__typeof__(s) __s = (s);	\
	__x < 0 ? -(-__x >> __s) : __x >> __s;	\
})

#define DECLARE_BITMAP(name,bits) \
	unsigned long name[BITS_TO_LONGS(bits)]








#define __bitwise __bitwise__
#define __bitwise__ __attribute__((bitwise))
#define aligned_be64 __be64 __attribute__((aligned(8)))
#define aligned_le64 __le64 __attribute__((aligned(8)))
#define aligned_u64 __u64 __attribute__((aligned(8)))
#define pgoff_t unsigned long

#define NULL ((void *)0)

#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#define FD_CLR(fd,fdsetp)	__FD_CLR(fd,fdsetp)
#define FD_ISSET(fd,fdsetp)	__FD_ISSET(fd,fdsetp)
#define FD_SET(fd,fdsetp)	__FD_SET(fd,fdsetp)
#define FD_ZERO(fdsetp)		__FD_ZERO(fdsetp)


#define do_posix_clock_monotonic_gettime(ts) ktime_get_ts(ts)
#define timespec_valid(ts) \
	(((ts)->tv_sec >= 0) && (((unsigned long) (ts)->tv_nsec) < NSEC_PER_SEC))
#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#define BUILD_BUG_ON(condition) ((void)BUILD_BUG_ON_ZERO(condition))
#define BUILD_BUG_ON_NOT_POWER_OF_2(n)			\
	BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))
#define BUILD_BUG_ON_NULL(e) ((void *)sizeof(struct { int:-!!(e); }))
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); }))
#define DIV_ROUND_CLOSEST(x, divisor)(			\
{							\
	typeof(divisor) __divisor = divisor;		\
	(((x) + ((__divisor) / 2)) / (__divisor));	\
}							\
)
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))
#define IS_ALIGNED(x, a)		(((x) & ((typeof(x))(a) - 1)) == 0)
#define MAYBE_BUILD_BUG_ON(cond) ((void)sizeof(char[1 - 2 * !!(cond)]))
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NUMA_BUILD 1
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))
# define REBUILD_DUE_TO_FTRACE_MCOUNT_RECORD

#define _THIS_IP_  ({ __label__ __here; __here: (unsigned long)&&__here; })
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
#define __ALIGN_MASK(x, mask)	__ALIGN_KERNEL_MASK((x), (mask))
#define __FUNCTION__ (__func__)
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define __trace_printk_check_format(fmt, args...)			\
do {									\
	if (0)								\
		____trace_printk_check_format(fmt, ##args);		\
} while (0)
#define abs(x) ({				\
		long __x = (x);			\
		(__x < 0) ? -__x : __x;		\
	})
#define clamp(val, min, max) ({			\
	typeof(val) __val = (val);		\
	typeof(min) __min = (min);		\
	typeof(max) __max = (max);		\
	(void) (&__val == &__min);		\
	(void) (&__val == &__max);		\
	__val = __val < __min ? __min: __val;	\
	__val > __max ? __max: __val; })
#define clamp_t(type, val, min, max) ({		\
	type __val = (val);			\
	type __min = (min);			\
	type __max = (max);			\
	__val = __val < __min ? __min: __val;	\
	__val > __max ? __max: __val; })
#define clamp_val(val, min, max) ({		\
	typeof(val) __val = (val);		\
	typeof(val) __min = (min);		\
	typeof(val) __max = (max);		\
	__val = __val < __min ? __min: __val;	\
	__val > __max ? __max: __val; })
#define console_loglevel (console_printk[0])
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#define default_console_loglevel (console_printk[3])
#define default_message_loglevel (console_printk[1])
#define ftrace_vprintk(fmt, vargs)					\
do {									\
	if (__builtin_constant_p(fmt)) {				\
		static const char *trace_printk_fmt			\
		  __attribute__((section("__trace_printk_fmt"))) =	\
			__builtin_constant_p(fmt) ? fmt : NULL;		\
									\
		__ftrace_vbprintk(_THIS_IP_, trace_printk_fmt, vargs);	\
	} else								\
		__ftrace_vprintk(_THIS_IP_, fmt, vargs);		\
} while (0)
#define hex_asc_hi(x)	hex_asc[((x) & 0xf0) >> 4]
#define hex_asc_lo(x)	hex_asc[((x) & 0x0f)]
#define lower_32_bits(n) ((u32)(n))
#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })
#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1: __max2; })
# define might_resched() _cond_resched()
# define might_sleep() \
	do { __might_sleep("__FILE__", "__LINE__", 0); might_resched(); } while (0)
#define might_sleep_if(cond) do { if (cond) might_sleep(); } while (0)
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })
#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })
#define minimum_console_loglevel (console_printk[2])
#define pr_alert(fmt, ...) \
        printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_alert_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_cont(fmt, ...) \
	printk(KERN_CONT fmt, ##__VA_ARGS__)
#define pr_crit(fmt, ...) \
        printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_crit_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug(fmt, ...) \
	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_devel(fmt, ...) \
	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_emerg(fmt, ...) \
        printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_emerg_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...) \
        printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_fmt(fmt) fmt
#define pr_info(fmt, ...) \
        printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice(fmt, ...) \
        printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn pr_warning
#define pr_warn_ratelimited pr_warning_ratelimited
#define pr_warning(fmt, ...) \
        printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warning_ratelimited(fmt, ...) \
	printk_ratelimited(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define printk_once(x...) ({			\
	static bool __print_once;		\
						\
	if (!__print_once) {			\
		__print_once = true;		\
		printk(x);			\
	}					\
})
#define printk_ratelimit() __printk_ratelimit(__func__)
#define printk_ratelimited printk
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
# define sector_div(a, b) do_div(a, b)
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
#define trace_printk(fmt, args...)					\
do {									\
	__trace_printk_check_format(fmt, ##args);			\
	if (__builtin_constant_p(fmt)) {				\
		static const char *trace_printk_fmt			\
		  __attribute__((section("__trace_printk_fmt"))) =	\
			__builtin_constant_p(fmt) ? fmt : NULL;		\
									\
		__trace_bprintk(_THIS_IP_, trace_printk_fmt, ##args);	\
	} else								\
		__trace_printk(_THIS_IP_, fmt, ##args);		\
} while (0)
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define _DPRINTK_FLAGS_DEFAULT 0
#define _DPRINTK_FLAGS_PRINT   (1<<0)  

#define __dynamic_dbg_enabled(dd)  ({	     \
	int __ret = 0;							     \
	if (unlikely((dynamic_debug_enabled & (1LL << DEBUG_HASH)) &&	     \
			(dynamic_debug_enabled2 & (1LL << DEBUG_HASH2))))   \
				if (unlikely(dd.flags))			     \
					__ret = 1;			     \
	__ret; })
#define dynamic_dev_dbg(dev, fmt, ...) do {				\
	static struct _ddebug descriptor				\
	__used								\
	__attribute__((section("__verbose"), aligned(8))) =		\
	{ KBUILD_MODNAME, __func__, "__FILE__", fmt, DEBUG_HASH,	\
		DEBUG_HASH2, "__LINE__", _DPRINTK_FLAGS_DEFAULT };	\
	if (__dynamic_dbg_enabled(descriptor))				\
		dev_printk(KERN_DEBUG, dev, fmt, ##__VA_ARGS__);	\
	} while (0)
#define dynamic_pr_debug(fmt, ...) do {					\
	static struct _ddebug descriptor				\
	__used								\
	__attribute__((section("__verbose"), aligned(8))) =		\
	{ KBUILD_MODNAME, __func__, "__FILE__", fmt, DEBUG_HASH,	\
		DEBUG_HASH2, "__LINE__", _DPRINTK_FLAGS_DEFAULT };	\
	if (__dynamic_dbg_enabled(descriptor))				\
		printk(KERN_DEBUG pr_fmt(fmt),	##__VA_ARGS__);		\
	} while (0)

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

#define ilog2(n)				\
(						\
	__builtin_constant_p(n) ? (		\
		(n) < 1 ? ____ilog2_NaN() :	\
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
		(n) & (1ULL <<  1) ?  1 :	\
		(n) & (1ULL <<  0) ?  0 :	\
		____ilog2_NaN()			\
				   ) :		\
	(sizeof(n) <= 4) ?			\
	__ilog2_u32(n) :			\
	__ilog2_u64(n)				\
 )
#define order_base_2(n) ilog2(roundup_pow_of_two(n))
#define rounddown_pow_of_two(n)			\
(						\
	__builtin_constant_p(n) ? (		\
		(n == 1) ? 0 :			\
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
#define BIT(nr)			(1UL << (nr))
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)

#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size)); \
	     (bit) < (size); \
	     (bit) = find_next_bit((addr), (size), (bit) + 1))
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
#define NORET_AND     noreturn,
#define NORET_TYPE    
#define WEAK(name)	   \
	.weak name;	   \
	name:

#define asmlinkage CPP_ASMLINKAGE
# define asmlinkage_protect(n, ret, args...)	do { } while (0)
# define asmregparm

#define MAX_LINKS 32		
#define NETLINK_CB(skb)		(*(struct netlink_skb_parms*)&((skb)->cb))
#define NETLINK_CREDS(skb)	(&NETLINK_CB((skb)).creds)
#define NET_MAJOR 36		
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
#define NLMSG_DEFAULT_SIZE (NLMSG_GOODSIZE - NLMSG_HDRLEN)
#define NLMSG_LENGTH(len) ((len)+NLMSG_ALIGN(NLMSG_HDRLEN))
#define NLMSG_NEW(skb, pid, seq, type, len, flags) \
({	if (unlikely(skb_tailroom(skb) < (int)NLMSG_SPACE(len))) \
		goto nlmsg_failure; \
	__nlmsg_put(skb, pid, seq, type, len, flags); })
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

#define CHECKSUM_COMPLETE 2
#define CHECKSUM_NONE 0
#define CHECKSUM_PARTIAL 3
#define CHECKSUM_UNNECESSARY 1

#define MAX_SKB_FRAGS (65536/PAGE_SIZE + 2)
#define NET_SKBUFF_DATA_USES_OFFSET 1
#define SKB_DATAREF_MASK ((1 << SKB_DATAREF_SHIFT) - 1)
#define SKB_DATAREF_SHIFT 16
#define SKB_DATA_ALIGN(X)	(((X) + (SMP_CACHE_BYTES - 1)) & \
				 ~(SMP_CACHE_BYTES - 1))
#define SKB_FRAG_ASSERT(skb) 	BUG_ON(skb_has_frags(skb))
#define SKB_LINEAR_ASSERT(skb)  BUG_ON(skb_is_nonlinear(skb))
#define SKB_MAX_HEAD(X)		(SKB_MAX_ORDER((X), 0))
#define SKB_MAX_ORDER(X, ORDER) \
	SKB_WITH_OVERHEAD((PAGE_SIZE << (ORDER)) - (X))
#define SKB_PAGE_ASSERT(skb) 	BUG_ON(skb_shinfo(skb)->nr_frags)
#define SKB_WITH_OVERHEAD(X)	\
	((X) - SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))

#define dev_kfree_skb(a)	consume_skb(a)
#define skb_queue_reverse_walk(queue, skb) \
		for (skb = (queue)->prev;					\
		     prefetch(skb->prev), (skb != (struct sk_buff *)(queue));	\
		     skb = skb->prev)
#define skb_queue_walk(queue, skb) \
		for (skb = (queue)->next;					\
		     prefetch(skb->next), (skb != (struct sk_buff *)(queue));	\
		     skb = skb->next)
#define skb_queue_walk_from(queue, skb)						\
		for (; prefetch(skb->next), (skb != (struct sk_buff *)(queue));	\
		     skb = skb->next)
#define skb_queue_walk_from_safe(queue, skb, tmp)				\
		for (tmp = skb->next;						\
		     skb != (struct sk_buff *)(queue);				\
		     skb = tmp, tmp = skb->next)
#define skb_queue_walk_safe(queue, skb, tmp)					\
		for (skb = (queue)->next, tmp = skb->next;			\
		     skb != (struct sk_buff *)(queue);				\
		     skb = tmp, tmp = skb->next)
#define skb_shinfo(SKB)	((struct skb_shared_info *)(skb_end_pointer(SKB)))
#define skb_walk_frags(skb, iter)	\
	for (iter = skb_shinfo(skb)->frag_list; iter; iter = iter->next)
#define KMEM_CACHE(__struct, __flags) kmem_cache_create(#__struct,\
		sizeof(struct __struct), __alignof__(struct __struct),\
		(__flags), NULL)
#define ZERO_OR_NULL_PTR(x) ((unsigned long)(x) <= \
				(unsigned long)ZERO_SIZE_PTR)
#define ZERO_SIZE_PTR ((void *)16)
#define kmalloc_node_track_caller(size, flags, node) \
	__kmalloc_node_track_caller(size, flags, node, \
			_RET_IP_)
#define kmalloc_track_caller(size, flags) \
	__kmalloc_track_caller(size, flags, _RET_IP_)
#define ARCH_KMALLOC_MINALIGN __alignof__(unsigned long long)
#define ARCH_SLAB_MINALIGN 0
#define CACHE(x) \
		if (size <= x) \
			goto found; \
		else \
			i++;

#define TRACE_SYSTEM kmem

#define show_gfp_flags(flags)						\
	(flags) ? __print_flags(flags, "|",				\
	{(unsigned long)GFP_HIGHUSER_MOVABLE,	"GFP_HIGHUSER_MOVABLE", \
	{(unsigned long)GFP_HIGHUSER,		"GFP_HIGHUSER",	\
	{(unsigned long)GFP_USER,		"GFP_USER",		\
	{(unsigned long)GFP_TEMPORARY,		"GFP_TEMPORARY",	\
	{(unsigned long)GFP_KERNEL,		"GFP_KERNEL",		\
	{(unsigned long)GFP_NOFS,		"GFP_NOFS",		\
	{(unsigned long)GFP_ATOMIC,		"GFP_ATOMIC",		\
	{(unsigned long)GFP_NOIO,		"GFP_NOIO",		\
	{(unsigned long)__GFP_HIGH,		"GFP_HIGH",		\
	{(unsigned long)__GFP_WAIT,		"GFP_WAIT",		\
	{(unsigned long)__GFP_IO,		"GFP_IO",		\
	{(unsigned long)__GFP_COLD,		"GFP_COLD",		\
	{(unsigned long)__GFP_NOWARN,		"GFP_NOWARN",		\
	{(unsigned long)__GFP_REPEAT,		"GFP_REPEAT",		\
	{(unsigned long)__GFP_NOFAIL,		"GFP_NOFAIL",		\
	{(unsigned long)__GFP_NORETRY,		"GFP_NORETRY",		\
	{(unsigned long)__GFP_COMP,		"GFP_COMP",		\
	{(unsigned long)__GFP_ZERO,		"GFP_ZERO",		\
	{(unsigned long)__GFP_NOMEMALLOC,	"GFP_NOMEMALLOC",	\
	{(unsigned long)__GFP_HARDWALL,		"GFP_HARDWALL",	\
	{(unsigned long)__GFP_THISNODE,		"GFP_THISNODE",	\
	{(unsigned long)__GFP_RECLAIMABLE,	"GFP_RECLAIMABLE",	\
	{(unsigned long)__GFP_MOVABLE,		"GFP_MOVABLE"		\
	) : "GFP_NOWAIT"

#define DECLARE_TRACE(name, proto, args)	\
	DEFINE_TRACE(name)
#define DEFINE_EVENT(template, name, proto, args) \
	DEFINE_TRACE(name)
#define DEFINE_EVENT_PRINT(template, name, proto, args, print)	\
	DEFINE_TRACE(name)
#define TRACE_EVENT(name, proto, args, tstruct, assign, print)	\
	DEFINE_TRACE(name)
#define TRACE_EVENT_FN(name, proto, args, tstruct,		\
		assign, print, reg, unreg)			\
	DEFINE_TRACE_FN(name, reg, unreg)

# define TRACE_INCLUDE(system) __TRACE_INCLUDE(system)
# define TRACE_INCLUDE_FILE TRACE_SYSTEM
# define UNDEF_TRACE_INCLUDE_FILE
# define UNDEF_TRACE_INCLUDE_PATH
# define __TRACE_INCLUDE(system) <trace/events/system.h>
#define DECLARE_EVENT_CLASS(call, proto, args, tstruct, assign, print)	\
	struct ftrace_data_offsets_##call {				\
		tstruct;						\
	};
#define TP_STRUCT__entry(args...) args
#define TP_fast_assign(args...) args

#define TP_printk(fmt, args...) fmt "\n", args
#define _TRACE_PERF_INIT(call)						\
	.perf_probe		= perf_trace_##call,
#define _TRACE_PERF_PROTO(call, proto)					\
	static notrace void						\
	perf_trace_##call(void *__data, proto);
#define __array(type, item, len)
#define __assign_str(dst, src)						\
	strcpy(__get_str(dst), src);
#define __cpparg(arg...) arg
#define __dynamic_array(type, item, len)	u32 item;
#define __entry field
#define __field(type, item)
#define __field_ext(type, item, filter_type)
#define __get_dynamic_array(field)	\
		((void *)__entry + (__entry->__data_loc_##field & 0xffff))
#define __get_str(field) (char *)__get_dynamic_array(field)
#define __perf_addr(a) __addr = (a)
#define __perf_count(c) __count = (c)
#define __print_flags(flag, delim, flag_array...)			\
	({								\
		static const struct trace_print_flags __flags[] =	\
			{ flag_array, { -1, NULL }};			\
		ftrace_print_flags_seq(p, delim, flag, __flags);	\
	})
#define __print_hex(buf, buf_len) ftrace_print_hex_seq(p, buf, buf_len)
#define __print_symbolic(value, symbol_array...)			\
	({								\
		static const struct trace_print_flags symbols[] =	\
			{ symbol_array, { -1, NULL }};			\
		ftrace_print_symbols_seq(p, value, symbols);		\
	})
#define __string(item, src) __dynamic_array(char, item, -1)

#define event_trace_printk(ip, fmt, args...)				\
do {									\
	__trace_printk_check_format(fmt, ##args);			\
	tracing_record_cmdline(current);				\
	if (__builtin_constant_p(fmt)) {				\
		static const char *trace_printk_fmt			\
		  __attribute__((section("__trace_printk_fmt"))) =	\
			__builtin_constant_p(fmt) ? fmt : NULL;		\
									\
		__trace_bprintk(ip, trace_printk_fmt, ##args);		\
	} else								\
		__trace_printk(ip, fmt, ##args);			\
} while (0)
#define is_signed_type(type)	(((type)(-1)) < 0)
#define PERF_EVENT_TXN_STARTED 1

#define perf_cpu_notifier(fn)					\
do {								\
	static struct notifier_block fn##_nb __cpuinitdata =	\
		{ .notifier_call = fn, .priority = 20 };	\
	fn(&fn##_nb, (unsigned long)CPU_UP_PREPARE,		\
		(void *)(unsigned long)smp_processor_id());	\
	fn(&fn##_nb, (unsigned long)CPU_STARTING,		\
		(void *)(unsigned long)smp_processor_id());	\
	fn(&fn##_nb, (unsigned long)CPU_ONLINE,			\
		(void *)(unsigned long)smp_processor_id());	\
	register_cpu_notifier(&fn##_nb);			\
} while (0)
#define perf_instruction_pointer(regs)	instruction_pointer(regs)
#define perf_misc_flags(regs)	(user_mode(regs) ? PERF_RECORD_MISC_USER : \
				 PERF_RECORD_MISC_KERNEL)
#define perf_output_put(handle, x) \
	perf_output_copy((handle), &(x), sizeof(x))

#define cpu_notifier(fn, pri) {					\
	static struct notifier_block fn##_nb __cpuinitdata =	\
		{ .notifier_call = fn, .priority = pri };	\
	register_cpu_notifier(&fn##_nb);			\
}
#define get_online_cpus()	do { } while (0)
#define hotcpu_notifier(fn, pri)	cpu_notifier(fn, pri)
#define put_online_cpus()	do { } while (0)
#define register_hotcpu_notifier(nb)	register_cpu_notifier(nb)
#define unregister_hotcpu_notifier(nb)	unregister_cpu_notifier(nb)
#define CPU_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(NR_CPUS)

#define any_online_cpu(mask)	0
#define cpu_active(cpu)		((cpu) == 0)
#define cpu_all_mask to_cpumask(cpu_all_bits)
#define cpu_clear(cpu, dst) __cpu_clear((cpu), &(dst))
#define cpu_is_offline(cpu)	unlikely(!cpu_online(cpu))
#define cpu_isset(cpu, cpumask) test_bit((cpu), (cpumask).bits)
#define cpu_none_mask to_cpumask(cpu_bit_bitmap[0])
#define cpu_online(cpu)		cpumask_test_cpu((cpu), cpu_online_mask)
#define cpu_possible(cpu)	cpumask_test_cpu((cpu), cpu_possible_mask)
#define cpu_present(cpu)	cpumask_test_cpu((cpu), cpu_present_mask)
#define cpu_set(cpu, dst) __cpu_set((cpu), &(dst))
#define cpu_test_and_set(cpu, cpumask) __cpu_test_and_set((cpu), &(cpumask))
#define cpumask_any(srcp) cpumask_first(srcp)
#define cpumask_any_and(mask1, mask2) cpumask_first_and((mask1), (mask2))
#define cpumask_bits(maskp) ((maskp)->bits)
#define cpumask_first_and(src1p, src2p) cpumask_next_and(-1, (src1p), (src2p))
#define cpumask_of(cpu) (get_cpu_mask(cpu))
#define cpumask_of_cpu(cpu) (*get_cpu_mask(cpu))
#define cpumask_test_cpu(cpu, cpumask) \
	test_bit(cpumask_check(cpu), cpumask_bits((cpumask)))
#define cpus_addr(src) ((src).bits)
#define cpus_and(dst, src1, src2) __cpus_and(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_andnot(dst, src1, src2) \
				__cpus_andnot(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_clear(dst) __cpus_clear(&(dst), NR_CPUS)
#define cpus_empty(src) __cpus_empty(&(src), NR_CPUS)
#define cpus_equal(src1, src2) __cpus_equal(&(src1), &(src2), NR_CPUS)
#define cpus_intersects(src1, src2) __cpus_intersects(&(src1), &(src2), NR_CPUS)
#define cpus_or(dst, src1, src2) __cpus_or(&(dst), &(src1), &(src2), NR_CPUS)
#define cpus_setall(dst) __cpus_setall(&(dst), NR_CPUS)
#define cpus_shift_left(dst, src, n) \
			__cpus_shift_left(&(dst), &(src), (n), NR_CPUS)
#define cpus_subset(src1, src2) __cpus_subset(&(src1), &(src2), NR_CPUS)
#define cpus_weight(cpumask) __cpus_weight(&(cpumask), NR_CPUS)
#define cpus_xor(dst, src1, src2) __cpus_xor(&(dst), &(src1), &(src2), NR_CPUS)
#define first_cpu(src)		({ (void)(src); 0; })
#define for_each_cpu(cpu, mask)			\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_cpu_and(cpu, mask, and)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask, (void)and)
#define for_each_cpu_mask(cpu, mask)	\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_cpu_mask_nr(cpu, mask)	for_each_cpu_mask(cpu, mask)
#define for_each_cpu_not(cpu, mask)		\
	for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#define for_each_online_cpu(cpu)   for_each_cpu((cpu), cpu_online_mask)
#define for_each_possible_cpu(cpu) for_each_cpu((cpu), cpu_possible_mask)
#define for_each_present_cpu(cpu)  for_each_cpu((cpu), cpu_present_mask)
#define next_cpu(n, src)	({ (void)(src); 1; })
#define num_active_cpus()	cpumask_weight(cpu_active_mask)
#define num_online_cpus()	cpumask_weight(cpu_online_mask)
#define num_possible_cpus()	cpumask_weight(cpu_possible_mask)
#define num_present_cpus()	cpumask_weight(cpu_present_mask)
#define to_cpumask(bitmap)						\
	((struct cpumask *)(1 ? (bitmap)				\
			    : (void *)sizeof(__check_is_bitmap(bitmap))))
#define BITMAP_LAST_WORD_MASK(nbits)					\
(									\
	((nbits) % BITS_PER_LONG) ?					\
		(1UL<<((nbits) % BITS_PER_LONG))-1 : ~0UL		\
)

#define small_const_nbits(nbits) \
	(__builtin_constant_p(nbits) && (nbits) <= BITS_PER_LONG)

#define MIN_THREADS_LEFT_FOR_ROOT 4
#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)
#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
	(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))


#define to_node(sys_device) container_of(sys_device, struct node, sysdev)
#define DECLARE_DELAYED_WORK(n, f)				\
	struct delayed_work n = __DELAYED_WORK_INITIALIZER(n, f)
#define DECLARE_WORK(n, f)					\
	struct work_struct n = __WORK_INITIALIZER(n, f)
#define INIT_DELAYED_WORK(_work, _func)				\
	do {							\
		INIT_WORK(&(_work)->work, (_func));		\
		init_timer(&(_work)->timer);			\
	} while (0)
#define INIT_DELAYED_WORK_DEFERRABLE(_work, _func)		\
	do {							\
		INIT_WORK(&(_work)->work, (_func));		\
		init_timer_deferrable(&(_work)->timer);		\
	} while (0)
#define INIT_DELAYED_WORK_ON_STACK(_work, _func)		\
	do {							\
		INIT_WORK_ON_STACK(&(_work)->work, (_func));	\
		init_timer_on_stack(&(_work)->timer);		\
	} while (0)
#define INIT_WORK(_work, _func)					\
	do {							\
		__INIT_WORK((_work), (_func), 0);		\
	} while (0)
#define INIT_WORK_ON_STACK(_work, _func)			\
	do {							\
		__INIT_WORK((_work), (_func), 1);		\
	} while (0)
#define PREPARE_DELAYED_WORK(_work, _func)			\
	PREPARE_WORK(&(_work)->work, (_func))
#define PREPARE_WORK(_work, _func)				\
	do {							\
		(_work)->func = (_func);			\
	} while (0)
#define WORK_DATA_INIT()	ATOMIC_LONG_INIT(0)
#define WORK_DATA_STATIC_INIT()	ATOMIC_LONG_INIT(2)
#define WORK_STRUCT_FLAG_MASK (3UL)
#define WORK_STRUCT_PENDING 0		
#define WORK_STRUCT_STATIC  1		
#define WORK_STRUCT_WQ_DATA_MASK (~WORK_STRUCT_FLAG_MASK)

#define __DELAYED_WORK_INITIALIZER(n, f) {			\
	.work = __WORK_INITIALIZER((n).work, (f)),		\
	.timer = TIMER_INITIALIZER(NULL, 0, 0),			\
	}
#define __INIT_WORK(_work, _func, _onstack)				\
	do {								\
		static struct lock_class_key __key;			\
									\
		__init_work((_work), _onstack);				\
		(_work)->data = (atomic_long_t) WORK_DATA_INIT();	\
		lockdep_init_map(&(_work)->lockdep_map, #_work, &__key, 0);\
		INIT_LIST_HEAD(&(_work)->entry);			\
		PREPARE_WORK((_work), (_func));				\
	} while (0)
#define __WORK_INITIALIZER(n, f) {				\
	.data = WORK_DATA_STATIC_INIT(),			\
	.entry	= { &(n).entry, &(n).entry },			\
	.func = (f),						\
	__WORK_INIT_LOCKDEP_MAP(#n, &(n))			\
	}
#define __WORK_INIT_LOCKDEP_MAP(n, k) \
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(n, k),
#define __create_workqueue(name, singlethread, freezeable, rt)	\
({								\
	static struct lock_class_key __key;			\
	const char *__lock_name;				\
								\
	if (__builtin_constant_p(name))				\
		__lock_name = (name);				\
	else							\
		__lock_name = #name;				\
								\
	__create_workqueue_key((name), (singlethread),		\
			       (freezeable), (rt), &__key,	\
			       __lock_name);			\
})
#define create_freezeable_workqueue(name) __create_workqueue((name), 1, 1, 0)
#define create_rt_workqueue(name) __create_workqueue((name), 0, 0, 1)
#define create_singlethread_workqueue(name) __create_workqueue((name), 1, 0, 0)
#define create_workqueue(name) __create_workqueue((name), 0, 0, 0)
#define delayed_work_pending(w) \
	work_pending(&(w)->work)
#define work_clear_pending(work) \
	clear_bit(WORK_STRUCT_PENDING, work_data_bits(work))
#define work_data_bits(work) ((unsigned long *)(&(work)->data))
#define work_pending(work) \
	test_bit(WORK_STRUCT_PENDING, work_data_bits(work))
# define INIT_LOCKDEP
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
#define STATIC_LOCKDEP_MAP_INIT(_name, _key) \
	{ .name = (_name), .key = (void *)(_key), }

# define lock_acquire(l, s, t, r, c, n, i)	do { } while (0)
#define lock_acquired(lockdep_map, ip) do {} while (0)
#define lock_contended(lockdep_map, ip) do {} while (0)
#  define lock_map_acquire(l)		lock_acquire(l, 0, 0, 0, 2, NULL, _THIS_IP_)
# define lock_map_release(l)			lock_release(l, 1, _THIS_IP_)
# define lock_release(l, n, i)			do { } while (0)
# define lock_set_class(l, n, k, s, i)		do { } while (0)
# define lock_set_subclass(l, s, i)		do { } while (0)
#define lockdep_assert_held(l)	WARN_ON(debug_locks && !lockdep_is_held(l))
# define lockdep_clear_current_reclaim_state()	do { } while (0)
#define lockdep_depth(tsk)	(debug_locks ? (tsk)->lockdep_depth : 0)
# define lockdep_free_key_range(start, size)	do { } while (0)
# define lockdep_info()				do { } while (0)
# define lockdep_init()				do { } while (0)
# define lockdep_init_map(lock, name, key, sub) \
		do { (void)(name); (void)(key); } while (0)
#define lockdep_is_held(lock)	lock_is_held(&(lock)->dep_map)
#define lockdep_match_class(lock, key) lockdep_match_key(&(lock)->dep_map, key)
# define lockdep_reset()		do { debug_locks = 1; } while (0)
# define lockdep_set_class(lock, key)		do { (void)(key); } while (0)
# define lockdep_set_class_and_name(lock, key, name) \
		do { (void)(key); (void)(name); } while (0)
#define lockdep_set_class_and_subclass(lock, key, sub) \
		lockdep_init_map(&(lock)->dep_map, #key, key, sub)
# define lockdep_set_current_reclaim_state(g)	do { } while (0)
#define lockdep_set_novalidate_class(lock) \
	lockdep_set_class(lock, &__lockdep_no_validate__)
#define lockdep_set_subclass(lock, sub)	\
		lockdep_init_map(&(lock)->dep_map, #lock, \
				 (lock)->dep_map.key, sub)
# define lockdep_sys_exit() 			do { } while (0)
# define lockdep_trace_alloc(g)			do { } while (0)
# define might_lock(lock) 						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 0, 2, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, 0, _THIS_IP_);			\
} while (0)
# define might_lock_read(lock) 						\
do {									\
	typecheck(struct lockdep_map *, &(lock)->dep_map);		\
	lock_acquire(&(lock)->dep_map, 0, 0, 1, 2, NULL, _THIS_IP_);	\
	lock_release(&(lock)->dep_map, 0, _THIS_IP_);			\
} while (0)
#  define mutex_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, NULL, i)
# define mutex_release(l, n, i)			lock_release(l, n, i)
#  define rwlock_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, NULL, i)
#  define rwlock_acquire_read(l, s, t, i)	lock_acquire(l, s, t, 2, 2, NULL, i)
# define rwlock_release(l, n, i)		lock_release(l, n, i)
#  define rwsem_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, NULL, i)
#  define rwsem_acquire_read(l, s, t, i)	lock_acquire(l, s, t, 1, 2, NULL, i)
# define rwsem_release(l, n, i)			lock_release(l, n, i)
#  define spin_acquire(l, s, t, i)		lock_acquire(l, s, t, 0, 2, NULL, i)
#  define spin_acquire_nest(l, s, t, n, i)	lock_acquire(l, s, t, 0, 2, n, i)
# define spin_release(l, n, i)			lock_release(l, n, i)

# define print_stack_trace(trace, spaces)		do { } while (0)
# define save_stack_trace(trace)			do { } while (0)
# define save_stack_trace_tsk(tsk, trace)		do { } while (0)
# define save_stack_trace_user(trace)              do { } while (0)
#define DEBUG_LOCKS_WARN_ON(c)						\
({									\
	int __ret = 0;							\
									\
	if (!oops_in_progress && unlikely(c)) {				\
		if (debug_locks_off() && !debug_locks_silent)		\
			WARN_ON(1);					\
		__ret = 1;						\
	}								\
	__ret;								\
})
# define SMP_DEBUG_LOCKS_WARN_ON(c)			DEBUG_LOCKS_WARN_ON(c)

# define locking_selftest()	do { } while (0)
#define HLIST_HEAD(name) struct hlist_head name = {  .first = NULL }
#define HLIST_HEAD_INIT { .first = NULL }
#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)
#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define __list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)
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
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#define list_for_each(pos, head) \
	for (pos = (head)->next; prefetch(pos->next), pos != (head); \
        	pos = pos->next)
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_continue(pos, head, member) 		\
	for (pos = list_entry(pos->member.next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_continue_reverse(pos, head, member)		\
	for (pos = list_entry(pos->member.prev, typeof(*pos), member);	\
	     prefetch(pos->member.prev), &pos->member != (head);	\
	     pos = list_entry(pos->member.prev, typeof(*pos), member))
#define list_for_each_entry_from(pos, head, member) 			\
	for (; prefetch(pos->member.next), &pos->member != (head);	\
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
#define list_for_each_prev_safe(pos, n, head) \
	for (pos = (head)->prev, n = pos->prev; \
	     prefetch(pos->prev), pos != (head); \
	     pos = n, n = pos->prev)
#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)
#define list_prepare_entry(pos, head, member) \
	((pos) ? : list_entry(head, typeof(*pos), member))
#define list_safe_reset_next(pos, n, member)				\
	n = list_entry(pos->member.next, typeof(*pos), member)
#define PREFETCH_STRIDE (4*L1_CACHE_BYTES)

#define prefetch(x) __builtin_prefetch(x)
#define prefetchw(x) __builtin_prefetch(x,1)
#define spin_lock_prefetch(x) prefetchw(x)
#define LIST_POISON1  ((void *) 0x00100100 + POISON_POINTER_DELTA)
#define LIST_POISON2  ((void *) 0x00200200 + POISON_POINTER_DELTA)
#define PAGE_POISON 0xaa
# define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)

#define DEFINE_TIMER(_name, _function, _expires, _data)		\
	struct timer_list _name =				\
		TIMER_INITIALIZER(_function, _expires, _data)
#define TIMER_INITIALIZER(_function, _expires, _data) {		\
		.entry = { .prev = TIMER_ENTRY_STATIC },	\
		.function = (_function),			\
		.expires = (_expires),				\
		.data = (_data),				\
		.base = &boot_tvec_bases,			\
		__TIMER_LOCKDEP_MAP_INITIALIZER(		\
			"__FILE__" ":" __stringify("__LINE__"))	\
	}

#define __TIMER_LOCKDEP_MAP_INITIALIZER(_kn)				\
	.lockdep_map = STATIC_LOCKDEP_MAP_INIT(_kn, &_kn),
#define del_singleshot_timer_sync(t) del_timer_sync(t)
# define del_timer_sync(t)		del_timer(t)
#define init_timer(timer)\
	init_timer_key((timer), NULL, NULL)
#define init_timer_deferrable(timer)\
	init_timer_deferrable_key((timer), NULL, NULL)
#define init_timer_on_stack(timer)\
	init_timer_on_stack_key((timer), NULL, NULL)
#define setup_timer(timer, fn, data)\
	setup_timer_key((timer), NULL, NULL, (fn), (data))
#define setup_timer_on_stack(timer, fn, data)\
	setup_timer_on_stack_key((timer), NULL, NULL, (fn), (data))
# define try_to_del_timer_sync(t)	del_timer(t)

#define __stringify(x...)	__stringify_1(x)
#define __stringify_1(x...)	#x

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
#define atomic_dec_and_lock(atomic, lock) \
		__cond_lock(lock, _atomic_dec_and_lock(atomic, lock))
#define do_raw_spin_lock_flags(lock, flags) do_raw_spin_lock(lock)
#define raw_spin_can_lock(lock)	(!raw_spin_is_locked(lock))
#define raw_spin_is_contended(lock) ((lock)->break_lock)
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
#define raw_spin_unlock_wait(lock)	arch_spin_unlock_wait(&(lock)->raw_lock)
#define spin_lock_init(_lock)				\
do {							\
	spinlock_check(_lock);				\
	raw_spin_lock_init(&(_lock)->rlock);		\
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
#define read_can_lock(rwlock)		arch_read_can_lock(&(rwlock)->raw_lock)
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
#define write_can_lock(rwlock)		arch_write_can_lock(&(rwlock)->raw_lock)
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
# define SPIN_DEBUG_INIT(lockname)		\
	.magic = SPINLOCK_MAGIC,		\
	.owner_cpu = -1,			\
	.owner = SPINLOCK_OWNER_INIT,
# define SPIN_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }

#define __RAW_SPIN_LOCK_INITIALIZER(lockname)	\
	{					\
	.raw_lock = __ARCH_SPIN_LOCK_UNLOCKED,	\
	SPIN_DEBUG_INIT(lockname)		\
	SPIN_DEP_MAP_INIT(lockname) }
#define __RAW_SPIN_LOCK_UNLOCKED(lockname)	\
	(raw_spinlock_t) __RAW_SPIN_LOCK_INITIALIZER(lockname)
#define __SPIN_LOCK_INITIALIZER(lockname) \
	{ { .rlock = __RAW_SPIN_LOCK_INITIALIZER(lockname) } }
#define __SPIN_LOCK_UNLOCKED(lockname) \
	(spinlock_t ) __SPIN_LOCK_INITIALIZER(lockname)
#define DEFINE_RWLOCK(x)	rwlock_t x = __RW_LOCK_UNLOCKED(x)
# define RW_DEP_MAP_INIT(lockname)	.dep_map = { .name = #lockname }

#define __RW_LOCK_UNLOCKED(lockname)					\
	(rwlock_t)	{	.raw_lock = __ARCH_RW_LOCK_UNLOCKED,	\
				.magic = RWLOCK_MAGIC,			\
				.owner = SPINLOCK_OWNER_INIT,		\
				.owner_cpu = -1,			\
				RW_DEP_MAP_INIT(lockname) }


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

# define add_preempt_count(val)	do { preempt_count() += (val); } while (0)
#define add_preempt_count_notrace(val)			\
	do { preempt_count() += (val); } while (0)
#define dec_preempt_count() sub_preempt_count(1)
#define dec_preempt_count_notrace() sub_preempt_count_notrace(1)
#define inc_preempt_count() add_preempt_count(1)
#define inc_preempt_count_notrace() add_preempt_count_notrace(1)
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
#define preempt_disable_notrace() \
do { \
	inc_preempt_count_notrace(); \
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
#define preempt_enable_no_resched_notrace() \
do { \
	barrier(); \
	dec_preempt_count_notrace(); \
} while (0)
#define preempt_enable_notrace() \
do { \
	preempt_enable_no_resched_notrace(); \
	barrier(); \
	preempt_check_resched(); \
} while (0)
# define sub_preempt_count(val)	do { preempt_count() -= (val); } while (0)
#define sub_preempt_count_notrace(val)			\
	do { preempt_count() -= (val); } while (0)

#define ktime_add(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 + (rhs).tv64 }; })
#define ktime_add_ns(kt, nsval) \
		({ (ktime_t){ .tv64 = (kt).tv64 + (nsval) }; })
#define ktime_get_real_ts(ts)	getnstimeofday(ts)
#define ktime_sub(lhs, rhs) \
		({ (ktime_t){ .tv64 = (lhs).tv64 - (rhs).tv64 }; })
#define ktime_sub_ns(kt, nsval) \
		({ (ktime_t){ .tv64 = (kt).tv64 - (nsval) }; })
#define ktime_to_ns(kt)			((kt).tv64)
#define ktime_to_timespec(kt)		ns_to_timespec((kt).tv64)
#define ktime_to_timeval(kt)		ns_to_timeval((kt).tv64)
#define SYSDEV_ATTR(_name, _mode, _show, _store)		\
	struct sysdev_attribute attr_##_name =			\
		_SYSDEV_ATTR(_name, _mode, _show, _store);
#define SYSDEV_CLASS_ATTR(_name,_mode,_show,_store) 		\
	struct sysdev_class_attribute attr_##_name = 		\
		_SYSDEV_CLASS_ATTR(_name,_mode,_show,_store)
#define SYSDEV_INT_ATTR(_name, _mode, _var)			\
	struct sysdev_ext_attribute attr_##_name = 		\
		_SYSDEV_INT_ATTR(_name, _mode, _var);
#define SYSDEV_ULONG_ATTR(_name, _mode, _var)			\
	struct sysdev_ext_attribute attr_##_name = 		\
		_SYSDEV_ULONG_ATTR(_name, _mode, _var);
#define _SYSDEV_ATTR(_name, _mode, _show, _store)		\
{								\
	.attr = { .name = __stringify(_name), .mode = _mode },	\
	.show	= _show,					\
	.store	= _store,					\
}
#define _SYSDEV_CLASS_ATTR(_name,_mode,_show,_store) 		\
{					 			\
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.show	= _show,					\
	.store	= _store,					\
}

#define _SYSDEV_INT_ATTR(_name, _mode, _var)				\
	{ _SYSDEV_ATTR(_name, _mode, sysdev_show_int, sysdev_store_int), \
	  &(_var) }
#define _SYSDEV_ULONG_ATTR(_name, _mode, _var)				\
	{ _SYSDEV_ATTR(_name, _mode, sysdev_show_ulong, sysdev_store_ulong), \
	  &(_var) }
#define PM_EVENT_FREEZE 	0x0001
#define PM_EVENT_PRETHAW PM_EVENT_QUIESCE
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
#define COMPLETION_INITIALIZER(work) \
	{ 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }
#define COMPLETION_INITIALIZER_ONSTACK(work) \
	({ init_completion(&work); work; })
#define DECLARE_COMPLETION(work) \
	struct completion work = COMPLETION_INITIALIZER(work)
# define DECLARE_COMPLETION_ONSTACK(work) \
	struct completion work = COMPLETION_INITIALIZER_ONSTACK(work)
#define INIT_COMPLETION(x)	((x).done = 0)

#define DECLARE_WAITQUEUE(name, tsk)					\
	wait_queue_t name = __WAITQUEUE_INITIALIZER(name, tsk)
#define DECLARE_WAIT_QUEUE_HEAD(name) \
	wait_queue_head_t name = __WAIT_QUEUE_HEAD_INITIALIZER(name)
# define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) \
	wait_queue_head_t name = __WAIT_QUEUE_HEAD_INIT_ONSTACK(name)
#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)
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
#define DEFINE_WAIT_FUNC(name, function)				\
	wait_queue_t name = {						\
		.private	= current,				\
		.func		= function,				\
		.task_list	= LIST_HEAD_INIT((name).task_list),	\
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
# define __WAIT_QUEUE_HEAD_INIT_ONSTACK(name) \
	({ init_waitqueue_head(&name); name; })
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
		if (condition) {					\
			finish_wait(&wq, &__wait);			\
			break;						\
		}							\
		if (!signal_pending(current)) {				\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		abort_exclusive_wait(&wq, &__wait, 			\
				TASK_INTERRUPTIBLE, NULL);		\
		break;							\
	}								\
} while (0)
#define __wait_event_interruptible_locked(wq, condition, exclusive, irq) \
({									\
	int __ret = 0;							\
	DEFINE_WAIT(__wait);						\
	if (exclusive)							\
		__wait.flags |= WQ_FLAG_EXCLUSIVE;			\
	do {								\
		if (likely(list_empty(&__wait.task_list)))		\
			__add_wait_queue_tail(&(wq), &__wait);		\
		set_current_state(TASK_INTERRUPTIBLE);			\
		if (signal_pending(current)) {				\
			__ret = -ERESTARTSYS;				\
			break;						\
		}							\
		if (irq)						\
			spin_unlock_irq(&(wq).lock);			\
		else							\
			spin_unlock(&(wq).lock);			\
		schedule();						\
		if (irq)						\
			spin_lock_irq(&(wq).lock);			\
		else							\
			spin_lock(&(wq).lock);				\
	} while (!(condition));						\
	__remove_wait_queue(&(wq), &__wait);				\
	__set_current_state(TASK_RUNNING);				\
	__ret;								\
})
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
#define __wait_event_killable(wq, condition, ret)			\
do {									\
	DEFINE_WAIT(__wait);						\
									\
	for (;;) {							\
		prepare_to_wait(&wq, &__wait, TASK_KILLABLE);		\
		if (condition)						\
			break;						\
		if (!fatal_signal_pending(current)) {			\
			schedule();					\
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
#define init_waitqueue_head(q)				\
	do {						\
		static struct lock_class_key __key;	\
							\
		__init_waitqueue_head((q), &__key);	\
	} while (0)
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
#define wait_event_interruptible_exclusive_locked(wq, condition)	\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, 0))
#define wait_event_interruptible_exclusive_locked_irq(wq, condition)	\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 1, 1))
#define wait_event_interruptible_locked(wq, condition)			\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, 0))
#define wait_event_interruptible_locked_irq(wq, condition)		\
	((condition)							\
	 ? 0 : __wait_event_interruptible_locked(wq, condition, 0, 1))
#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})
#define wait_event_killable(wq, condition)				\
({									\
	int __ret = 0;							\
	if (!(condition))						\
		__wait_event_killable(wq, condition, __ret);		\
	__ret;								\
})
#define wait_event_timeout(wq, condition, timeout)			\
({									\
	long __ret = timeout;						\
	if (!(condition)) 						\
		__wait_event_timeout(wq, condition, __ret);		\
	__ret;								\
})
#define wake_up(x)			__wake_up(x, TASK_NORMAL, 1, NULL)
#define wake_up_all(x)			__wake_up(x, TASK_NORMAL, 0, NULL)
#define wake_up_interruptible(x)	__wake_up(x, TASK_INTERRUPTIBLE, 1, NULL)
#define wake_up_interruptible_all(x)	__wake_up(x, TASK_INTERRUPTIBLE, 0, NULL)
#define wake_up_interruptible_nr(x, nr)	__wake_up(x, TASK_INTERRUPTIBLE, nr, NULL)
#define wake_up_interruptible_poll(x, m)			\
	__wake_up(x, TASK_INTERRUPTIBLE, 1, (void *) (m))
#define wake_up_interruptible_sync(x)	__wake_up_sync((x), TASK_INTERRUPTIBLE, 1)
#define wake_up_interruptible_sync_poll(x, m)				\
	__wake_up_sync_key((x), TASK_INTERRUPTIBLE, 1, (void *) (m))
#define wake_up_locked(x)		__wake_up_locked((x), TASK_NORMAL)
#define wake_up_locked_poll(x, m)				\
	__wake_up_locked_key((x), TASK_NORMAL, (void *) (m))
#define wake_up_nr(x, nr)		__wake_up(x, TASK_NORMAL, nr, NULL)
#define wake_up_poll(x, m)				\
	__wake_up(x, TASK_NORMAL, 1, (void *) (m))
#define EXPORT_SYMBOL(sym)					\
	__EXPORT_SYMBOL(sym, "")
#define EXPORT_SYMBOL_GPL(sym)					\
	__EXPORT_SYMBOL(sym, "_gpl")
#define EXPORT_SYMBOL_GPL_FUTURE(sym)				\
	__EXPORT_SYMBOL(sym, "_gpl_future")
#define EXPORT_UNUSED_SYMBOL(sym) __EXPORT_SYMBOL(sym, "_unused")
#define EXPORT_UNUSED_SYMBOL_GPL(sym) __EXPORT_SYMBOL(sym, "_unused_gpl")
#define MODULE_ALIAS(_alias) MODULE_INFO(alias, _alias)
#define MODULE_ARCH_INIT {}
#define MODULE_AUTHOR(_author) MODULE_INFO(author, _author)
#define MODULE_DESCRIPTION(_description) MODULE_INFO(description, _description)
#define MODULE_DEVICE_TABLE(type,name)		\
  MODULE_GENERIC_TABLE(type##_device,name)
#define MODULE_FIRMWARE(_firmware) MODULE_INFO(firmware, _firmware)
#define MODULE_GENERIC_TABLE(gtype,name)			\
extern const struct gtype##_id __mod_##gtype##_table		\
  __attribute__ ((unused, alias(__stringify(name))))
#define MODULE_INFO(tag, info) __MODULE_INFO(tag, tag, info)
#define MODULE_LICENSE(_license) MODULE_INFO(license, _license)
#define MODULE_NAME_LEN MAX_PARAM_PREFIX_LEN
#define MODULE_PARM_DESC(_parm, desc) \
	__MODULE_INFO(parm, _parm, #_parm ":" desc)

#define MODULE_SYMBOL_PREFIX CONFIG_SYMBOL_PREFIX
#define MODULE_VERSION(_version) MODULE_INFO(version, _version)
#define THIS_MODULE (&__this_module)

#define __CRC_SYMBOL(sym, sec)					\
	extern void *__crc_##sym __attribute__((weak));		\
	static const unsigned long __kcrctab_##sym		\
	__used							\
	__attribute__((section("__kcrctab" sec), unused))	\
	= (unsigned long) &__crc_##sym;
#define __EXPORT_SYMBOL(sym, sec)				\
	extern typeof(sym) sym;					\
	__CRC_SYMBOL(sym, sec)					\
	static const char __kstrtab_##sym[]			\
	__attribute__((section("__ksymtab_strings"), aligned(1))) \
	= MODULE_SYMBOL_PREFIX #sym;                    	\
	static const struct kernel_symbol __ksymtab_##sym	\
	__used							\
	__attribute__((section("__ksymtab" sec), unused))	\
	= { (unsigned long)&sym, __kstrtab_##sym }
#define __MODULE_STRING(x) __stringify(x)
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

#define show_module_flags(flags) __print_flags(flags, "",	\
	{ (1UL << TAINT_PROPRIETARY_MODULE),	"P" },		\
	{ (1UL << TAINT_FORCED_MODULE),		"F" },		\
	{ (1UL << TAINT_CRAP),			"C" })
#define DECLARE_TRACE_NOARGS(name)					\
		__DECLARE_TRACE(name, void, , void *__data, __data)
#define DEFINE_TRACE(name)						\
	DEFINE_TRACE_FN(name, NULL, NULL);
#define DEFINE_TRACE_FN(name, reg, unreg)				\
	static const char __tpstrtab_##name[]				\
	__attribute__((section("__tracepoints_strings"))) = #name;	\
	struct tracepoint __tracepoint_##name				\
	__attribute__((section("__tracepoints"), aligned(32))) =	\
		{ __tpstrtab_##name, 0, reg, unreg, NULL }
#define EXPORT_TRACEPOINT_SYMBOL(name)					\
	EXPORT_SYMBOL(__tracepoint_##name)
#define EXPORT_TRACEPOINT_SYMBOL_GPL(name)				\
	EXPORT_SYMBOL_GPL(__tracepoint_##name)
#define PARAMS(args...) args
#define TP_ARGS(args...)	args
#define TP_PROTO(args...)	args

#define __DECLARE_TRACE(name, proto, args, data_proto, data_args)	\
	extern struct tracepoint __tracepoint_##name;			\
	static inline void trace_##name(proto)				\
	{								\
		if (unlikely(__tracepoint_##name.state))		\
			__DO_TRACE(&__tracepoint_##name,		\
				TP_PROTO(data_proto),			\
				TP_ARGS(data_args));			\
	}								\
	static inline int						\
	register_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_register(#name, (void *)probe,	\
						 data);			\
	}								\
	static inline int						\
	unregister_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_unregister(#name, (void *)probe, \
						   data);		\
	}								\
	static inline void						\
	check_trace_callback_type_##name(void (*cb)(data_proto))	\
	{								\
	}
#define __DO_TRACE(tp, proto, args)					\
	do {								\
		struct tracepoint_func *it_func_ptr;			\
		void *it_func;						\
		void *__data;						\
									\
		rcu_read_lock_sched_notrace();				\
		it_func_ptr = rcu_dereference_sched((tp)->funcs);	\
		if (it_func_ptr) {					\
			do {						\
				it_func = (it_func_ptr)->func;		\
				__data = (it_func_ptr)->data;		\
				((void(*)(proto))(it_func))(args);	\
			} while ((++it_func_ptr)->func);		\
		}							\
		rcu_read_unlock_sched_notrace();			\
	} while (0)
#define INIT_RCU_HEAD(ptr) do { \
       (ptr)->next = NULL; (ptr)->func = NULL; \
} while (0)
#define RCU_HEAD(head) struct rcu_head head = RCU_HEAD_INIT

#define __do_rcu_dereference_check(c)					\
	do {								\
		static bool __warned;					\
		if (debug_lockdep_rcu_enabled() && !__warned && !(c)) {	\
			__warned = true;				\
			lockdep_rcu_dereference("__FILE__", "__LINE__");	\
		}							\
	} while (0)
#define rcu_access_pointer(p)	ACCESS_ONCE(p)
#define rcu_assign_pointer(p, v) \
	({ \
		if (!__builtin_constant_p(v) || \
		    ((v) != NULL)) \
			smp_wmb(); \
		(p) = (v); \
	})
#define rcu_dereference(p) \
	rcu_dereference_check(p, rcu_read_lock_held())
#define rcu_dereference_bh(p) \
		rcu_dereference_check(p, rcu_read_lock_bh_held())
#define rcu_dereference_check(p, c) \
	({ \
		__do_rcu_dereference_check(c); \
		rcu_dereference_raw(p); \
	})
#define rcu_dereference_protected(p, c) \
	({ \
		__do_rcu_dereference_check(c); \
		(p); \
	})
#define rcu_dereference_raw(p)	({ \
				typeof(p) _________p1 = ACCESS_ONCE(p); \
				smp_read_barrier_depends(); \
				(_________p1); \
				})
#define rcu_dereference_sched(p) \
		rcu_dereference_check(p, rcu_read_lock_sched_held())
# define rcu_read_acquire()		do { } while (0)
# define rcu_read_acquire_bh()		do { } while (0)
# define rcu_read_acquire_sched() \
		lock_acquire(&rcu_sched_lock_map, 0, 0, 2, 1, NULL, _THIS_IP_)
# define rcu_read_release()		do { } while (0)
# define rcu_read_release_bh()	lock_release(&rcu_bh_lock_map, 1, _THIS_IP_)
# define rcu_read_release_sched() \
		lock_release(&rcu_sched_lock_map, 1, _THIS_IP_)

#define __rcu_read_lock()	preempt_disable()
#define __rcu_read_lock_bh()	local_bh_disable()
#define __rcu_read_unlock()	preempt_enable()
#define __rcu_read_unlock_bh()	local_bh_enable()
#define rcu_init_sched()	do { } while (0)
#define INTERNODE_CACHE_SHIFT L1_CACHE_SHIFT
#define L1_CACHE_ALIGN(x) ALIGN(x, L1_CACHE_BYTES)
#define SMP_CACHE_BYTES L1_CACHE_BYTES

#define ____cacheline_aligned __attribute__((__aligned__(SMP_CACHE_BYTES)))
#define ____cacheline_aligned_in_smp ____cacheline_aligned
#define ____cacheline_internodealigned_in_smp \
	__attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))
#define __cacheline_aligned_in_smp __cacheline_aligned

#define cache_line_size()	L1_CACHE_BYTES

#define rcu_preempt_depth() (current->rcu_read_lock_nesting)
#define synchronize_rcu synchronize_sched
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
#define seqlock_init(x)					\
	do {						\
		(x)->sequence = 0;			\
		spin_lock_init(&(x)->lock);		\
	} while (0)
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
({	typeof(variable) pscr_ret__;					\
	__verify_pcpu_ptr(&(variable));					\
	switch(sizeof(variable)) {					\
	case 1: pscr_ret__ = stem##1(variable);break;			\
	case 2: pscr_ret__ = stem##2(variable);break;			\
	case 4: pscr_ret__ = stem##4(variable);break;			\
	case 8: pscr_ret__ = stem##8(variable);break;			\
	default:							\
		__bad_size_call_parameter();break;			\
	}								\
	pscr_ret__;							\
})
#define __percpu_generic_to_op(var, val, op)				\
do {									\
	typeof(var) *pgto_ptr__ = &(var);				\
	get_cpu_var(*pgto_ptr__) op val;				\
	put_cpu_var(*pgto_ptr__);					\
} while (0)
# define __this_cpu_add(pcp, val)	__pcpu_size_call(__this_cpu_add_, (pcp), (val))
#  define __this_cpu_add_1(pcp, val)	__this_cpu_generic_to_op((pcp), (val), +=)
#  define __this_cpu_add_2(pcp, val)	__this_cpu_generic_to_op((pcp), (val), +=)
#  define __this_cpu_add_4(pcp, val)	__this_cpu_generic_to_op((pcp), (val), +=)
#  define __this_cpu_add_8(pcp, val)	__this_cpu_generic_to_op((pcp), (val), +=)
# define __this_cpu_and(pcp, val)	__pcpu_size_call(__this_cpu_and_, (pcp), (val))
#  define __this_cpu_and_1(pcp, val)	__this_cpu_generic_to_op((pcp), (val), &=)
#  define __this_cpu_and_2(pcp, val)	__this_cpu_generic_to_op((pcp), (val), &=)
#  define __this_cpu_and_4(pcp, val)	__this_cpu_generic_to_op((pcp), (val), &=)
#  define __this_cpu_and_8(pcp, val)	__this_cpu_generic_to_op((pcp), (val), &=)
# define __this_cpu_dec(pcp)		__this_cpu_sub((pcp), 1)
#define __this_cpu_generic_to_op(pcp, val, op)				\
do {									\
	*__this_cpu_ptr(&(pcp)) op val;					\
} while (0)
# define __this_cpu_inc(pcp)		__this_cpu_add((pcp), 1)
# define __this_cpu_or(pcp, val)	__pcpu_size_call(__this_cpu_or_, (pcp), (val))
#  define __this_cpu_or_1(pcp, val)	__this_cpu_generic_to_op((pcp), (val), |=)
#  define __this_cpu_or_2(pcp, val)	__this_cpu_generic_to_op((pcp), (val), |=)
#  define __this_cpu_or_4(pcp, val)	__this_cpu_generic_to_op((pcp), (val), |=)
#  define __this_cpu_or_8(pcp, val)	__this_cpu_generic_to_op((pcp), (val), |=)
# define __this_cpu_read(pcp)	__pcpu_size_call_return(__this_cpu_read_, (pcp))
#  define __this_cpu_read_1(pcp)	(*__this_cpu_ptr(&(pcp)))
#  define __this_cpu_read_2(pcp)	(*__this_cpu_ptr(&(pcp)))
#  define __this_cpu_read_4(pcp)	(*__this_cpu_ptr(&(pcp)))
#  define __this_cpu_read_8(pcp)	(*__this_cpu_ptr(&(pcp)))
# define __this_cpu_sub(pcp, val)	__this_cpu_add((pcp), -(val))
# define __this_cpu_write(pcp, val)	__pcpu_size_call(__this_cpu_write_, (pcp), (val))
#  define __this_cpu_write_1(pcp, val)	__this_cpu_generic_to_op((pcp), (val), =)
#  define __this_cpu_write_2(pcp, val)	__this_cpu_generic_to_op((pcp), (val), =)
#  define __this_cpu_write_4(pcp, val)	__this_cpu_generic_to_op((pcp), (val), =)
#  define __this_cpu_write_8(pcp, val)	__this_cpu_generic_to_op((pcp), (val), =)
# define __this_cpu_xor(pcp, val)	__pcpu_size_call(__this_cpu_xor_, (pcp), (val))
#  define __this_cpu_xor_1(pcp, val)	__this_cpu_generic_to_op((pcp), (val), ^=)
#  define __this_cpu_xor_2(pcp, val)	__this_cpu_generic_to_op((pcp), (val), ^=)
#  define __this_cpu_xor_4(pcp, val)	__this_cpu_generic_to_op((pcp), (val), ^=)
#  define __this_cpu_xor_8(pcp, val)	__this_cpu_generic_to_op((pcp), (val), ^=)
#define _this_cpu_generic_read(pcp)					\
({	typeof(pcp) ret__;						\
	preempt_disable();						\
	ret__ = *this_cpu_ptr(&(pcp));					\
	preempt_enable();						\
	ret__;								\
})
#define _this_cpu_generic_to_op(pcp, val, op)				\
do {									\
	preempt_disable();						\
	*__this_cpu_ptr(&(pcp)) op val;					\
	preempt_enable();						\
} while (0)
#define alloc_percpu(type)	\
	(typeof(type) __percpu *)__alloc_percpu(sizeof(type), __alignof__(type))
#define get_cpu_var(var) (*({				\
	preempt_disable();				\
	&__get_cpu_var(var); }))
# define irqsafe_cpu_add(pcp, val) __pcpu_size_call(irqsafe_cpu_add_, (pcp), (val))
#  define irqsafe_cpu_add_1(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), +=)
#  define irqsafe_cpu_add_2(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), +=)
#  define irqsafe_cpu_add_4(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), +=)
#  define irqsafe_cpu_add_8(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), +=)
# define irqsafe_cpu_and(pcp, val) __pcpu_size_call(irqsafe_cpu_and_, (val))
#  define irqsafe_cpu_and_1(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), &=)
#  define irqsafe_cpu_and_2(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), &=)
#  define irqsafe_cpu_and_4(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), &=)
#  define irqsafe_cpu_and_8(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), &=)
# define irqsafe_cpu_dec(pcp)	irqsafe_cpu_sub((pcp), 1)
#define irqsafe_cpu_generic_to_op(pcp, val, op)				\
do {									\
	unsigned long flags;						\
	local_irq_save(flags);						\
	*__this_cpu_ptr(&(pcp)) op val;					\
	local_irq_restore(flags);					\
} while (0)
# define irqsafe_cpu_inc(pcp)	irqsafe_cpu_add((pcp), 1)
# define irqsafe_cpu_or(pcp, val) __pcpu_size_call(irqsafe_cpu_or_, (val))
#  define irqsafe_cpu_or_1(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), |=)
#  define irqsafe_cpu_or_2(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), |=)
#  define irqsafe_cpu_or_4(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), |=)
#  define irqsafe_cpu_or_8(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), |=)
# define irqsafe_cpu_sub(pcp, val)	irqsafe_cpu_add((pcp), -(val))
# define irqsafe_cpu_xor(pcp, val) __pcpu_size_call(irqsafe_cpu_xor_, (val))
#  define irqsafe_cpu_xor_1(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), ^=)
#  define irqsafe_cpu_xor_2(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), ^=)
#  define irqsafe_cpu_xor_4(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), ^=)
#  define irqsafe_cpu_xor_8(pcp, val) irqsafe_cpu_generic_to_op((pcp), (val), ^=)
#define per_cpu_ptr(ptr, cpu)	SHIFT_PERCPU_PTR((ptr), per_cpu_offset((cpu)))
# define percpu_add(var, val)		__percpu_generic_to_op(var, (val), +=)
# define percpu_and(var, val)		__percpu_generic_to_op(var, (val), &=)
# define percpu_or(var, val)		__percpu_generic_to_op(var, (val), |=)
# define percpu_read(var)						\
  ({									\
	typeof(var) *pr_ptr__ = &(var);					\
	typeof(var) pr_ret__;						\
	pr_ret__ = get_cpu_var(*pr_ptr__);				\
	put_cpu_var(*pr_ptr__);						\
	pr_ret__;							\
  })
# define percpu_sub(var, val)		__percpu_generic_to_op(var, (val), -=)
# define percpu_write(var, val)		__percpu_generic_to_op(var, (val), =)
# define percpu_xor(var, val)		__percpu_generic_to_op(var, (val), ^=)
#define put_cpu_var(var) do {				\
	(void)&(var);					\
	preempt_enable();				\
} while (0)
# define this_cpu_add(pcp, val)		__pcpu_size_call(this_cpu_add_, (pcp), (val))
#  define this_cpu_add_1(pcp, val)	_this_cpu_generic_to_op((pcp), (val), +=)
#  define this_cpu_add_2(pcp, val)	_this_cpu_generic_to_op((pcp), (val), +=)
#  define this_cpu_add_4(pcp, val)	_this_cpu_generic_to_op((pcp), (val), +=)
#  define this_cpu_add_8(pcp, val)	_this_cpu_generic_to_op((pcp), (val), +=)
# define this_cpu_and(pcp, val)		__pcpu_size_call(this_cpu_and_, (pcp), (val))
#  define this_cpu_and_1(pcp, val)	_this_cpu_generic_to_op((pcp), (val), &=)
#  define this_cpu_and_2(pcp, val)	_this_cpu_generic_to_op((pcp), (val), &=)
#  define this_cpu_and_4(pcp, val)	_this_cpu_generic_to_op((pcp), (val), &=)
#  define this_cpu_and_8(pcp, val)	_this_cpu_generic_to_op((pcp), (val), &=)
# define this_cpu_dec(pcp)		this_cpu_sub((pcp), 1)
# define this_cpu_inc(pcp)		this_cpu_add((pcp), 1)
# define this_cpu_or(pcp, val)		__pcpu_size_call(this_cpu_or_, (pcp), (val))
#  define this_cpu_or_1(pcp, val)	_this_cpu_generic_to_op((pcp), (val), |=)
#  define this_cpu_or_2(pcp, val)	_this_cpu_generic_to_op((pcp), (val), |=)
#  define this_cpu_or_4(pcp, val)	_this_cpu_generic_to_op((pcp), (val), |=)
#  define this_cpu_or_8(pcp, val)	_this_cpu_generic_to_op((pcp), (val), |=)
# define this_cpu_read(pcp)	__pcpu_size_call_return(this_cpu_read_, (pcp))
#  define this_cpu_read_1(pcp)	_this_cpu_generic_read(pcp)
#  define this_cpu_read_2(pcp)	_this_cpu_generic_read(pcp)
#  define this_cpu_read_4(pcp)	_this_cpu_generic_read(pcp)
#  define this_cpu_read_8(pcp)	_this_cpu_generic_read(pcp)
# define this_cpu_sub(pcp, val)		this_cpu_add((pcp), -(val))
# define this_cpu_write(pcp, val)	__pcpu_size_call(this_cpu_write_, (pcp), (val))
#  define this_cpu_write_1(pcp, val)	_this_cpu_generic_to_op((pcp), (val), =)
#  define this_cpu_write_2(pcp, val)	_this_cpu_generic_to_op((pcp), (val), =)
#  define this_cpu_write_4(pcp, val)	_this_cpu_generic_to_op((pcp), (val), =)
#  define this_cpu_write_8(pcp, val)	_this_cpu_generic_to_op((pcp), (val), =)
# define this_cpu_xor(pcp, val)		__pcpu_size_call(this_cpu_or_, (pcp), (val))
#  define this_cpu_xor_1(pcp, val)	_this_cpu_generic_to_op((pcp), (val), ^=)
#  define this_cpu_xor_2(pcp, val)	_this_cpu_generic_to_op((pcp), (val), ^=)
#  define this_cpu_xor_4(pcp, val)	_this_cpu_generic_to_op((pcp), (val), ^=)
#  define this_cpu_xor_8(pcp, val)	_this_cpu_generic_to_op((pcp), (val), ^=)
#define PFN_ALIGN(x)	(((unsigned long)(x) + (PAGE_SIZE - 1)) & PAGE_MASK)
#define PFN_DOWN(x)	((x) >> PAGE_SHIFT)
#define PFN_PHYS(x)	((phys_addr_t)(x) << PAGE_SHIFT)
#define PFN_UP(x)	(((x) + PAGE_SIZE-1) >> PAGE_SHIFT)

#define MSG_CALL_FUNCTION       0x0004  

#define get_cpu()		({ preempt_disable(); smp_processor_id(); })
#define num_booting_cpus()			1
#define on_each_cpu(func,info,wait)		\
	({					\
		local_irq_disable();		\
		func(info);			\
		local_irq_enable();		\
		0;				\
	})
#define put_cpu()		preempt_enable()
#define raw_smp_processor_id()			0
#define smp_call_function(func, info, wait) \
			(up_smp_call_function(func, info))
#define smp_call_function_many(mask, func, info, wait) \
			(up_smp_call_function(func, info))
#define smp_prepare_boot_cpu()			do {} while (0)
# define smp_processor_id() debug_smp_processor_id()
#define MAX_PARAM_PREFIX_LEN (64 - sizeof(unsigned long))
#define MODULE_PARAM_PREFIX 

#define __MODULE_INFO(tag, name, info)					  \
static const char __module_cat(name,"__LINE__")[]				  \
  __used								  \
  __attribute__((section(".modinfo"),unused)) = __stringify(tag) "=" info
#define __MODULE_PARM_TYPE(name, _type)					  \
  __MODULE_INFO(parmtype, name##type, #name ":" _type)
#define ___module_cat(a,b) __mod_ ## a ## b
#define __module_cat(a,b) ___module_cat(a,b)
#define __module_param_call(prefix, name, set, get, arg, isbool, perm)	\
				\
	static int __param_perm_check_##name __attribute__((unused)) =	\
	BUILD_BUG_ON_ZERO((perm) < 0 || (perm) > 0777 || ((perm) & 2))	\
	+ BUILD_BUG_ON_ZERO(sizeof(""prefix) > MAX_PARAM_PREFIX_LEN);	\
	static const char __param_str_##name[] = prefix #name;		\
	static struct kernel_param __moduleparam_const __param_##name	\
	__used								\
    __attribute__ ((unused,__section__ ("__param"),aligned(sizeof(void *)))) \
	= { __param_str_##name, perm, isbool ? KPARAM_ISBOOL : 0,	\
	    set, get, { arg } }
#define __moduleparam_const const
#define __param_check(name, p, type) \
	static inline type *__check_##name(void) { return(p); }
#define core_param(name, var, type, perm)				\
	param_check_##type(name, &(var));				\
	__module_param_call("", name, param_set_##type, param_get_##type, \
			    &var, __same_type(var, bool), perm)
#define module_param(name, type, perm)				\
	module_param_named(name, name, type, perm)
#define module_param_array(name, type, nump, perm)		\
	module_param_array_named(name, name, type, nump, perm)
#define module_param_array_named(name, array, type, nump, perm)		\
	static const struct kparam_array __param_arr_##name		\
	= { ARRAY_SIZE(array), nump, param_set_##type, param_get_##type,\
	    sizeof(array[0]), array };					\
	__module_param_call(MODULE_PARAM_PREFIX, name,			\
			    param_array_set, param_array_get,		\
			    .arr = &__param_arr_##name,			\
			    __same_type(array[0], bool), perm);		\
	__MODULE_PARM_TYPE(name, "array of " #type)
#define module_param_call(name, set, get, arg, perm)			      \
	__module_param_call(MODULE_PARAM_PREFIX,			      \
			    name, set, get, arg,			      \
			    __same_type(*(arg), bool), perm)
#define module_param_named(name, value, type, perm)			   \
	param_check_##type(name, &(value));				   \
	module_param_call(name, param_set_##type, param_get_##type, &value, perm); \
	__MODULE_PARM_TYPE(name, #type)
#define module_param_string(name, string, len, perm)			\
	static const struct kparam_string __param_string_##name		\
		= { len, string };					\
	__module_param_call(MODULE_PARAM_PREFIX, name,			\
			    param_set_copystring, param_get_string,	\
			    .str = &__param_string_##name, 0, perm);	\
	__MODULE_PARM_TYPE(name, "string")
#define param_check_bool(name, p)					\
	static inline void __check_##name(void)				\
	{								\
		BUILD_BUG_ON(!__same_type(*(p), bool) &&		\
			     !__same_type(*(p), unsigned int) &&	\
			     !__same_type(*(p), int));			\
	}
#define param_check_byte(name, p) __param_check(name, p, unsigned char)
#define param_check_charp(name, p) __param_check(name, p, char *)
#define param_check_int(name, p) __param_check(name, p, int)
#define param_check_invbool(name, p) __param_check(name, p, bool)
#define param_check_long(name, p) __param_check(name, p, long)
#define param_check_short(name, p) __param_check(name, p, short)
#define param_check_uint(name, p) __param_check(name, p, unsigned int)
#define param_check_ulong(name, p) __param_check(name, p, unsigned long)
#define param_check_ushort(name, p) __param_check(name, p, unsigned short)



#define __ATTR(_name,_mode,_show,_store) { \
	.attr = {.name = __stringify(_name), .mode = _mode },	\
	.show	= _show,					\
	.store	= _store,					\
}
#define __ATTR_NULL { .attr = { .name = NULL } }
#define __ATTR_RO(_name) { \
	.attr	= { .name = __stringify(_name), .mode = 0444 },	\
	.show	= _name##_show,					\
}
#define attr_name(_attr) (_attr).attr.name
#define sysfs_attr_init(attr)				\
do {							\
	static struct lock_class_key __key;		\
							\
	(attr)->key = &__key;				\
} while(0)
#define sysfs_bin_attr_init(bin_attr) sysfs_attr_init(&(bin_attr)->attr)
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

# define elf_read_implies_exec(ex, have_pt_gnu_stack)	0
#define EM_BLACKFIN     106     
#define EM_CYGNUS_MN10300 0xbeef

#define KMOD_PATH_LEN 256

#define request_module(mod...) __request_module(true, mod)
#define request_module_nowait(mod...) __request_module(false, mod)
#define try_then_request_module(x, mod...) \
	((x) ?: (__request_module(true, mod), (x)))
#define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_WAIT|__GFP_IO|__GFP_FS))
#define GFP_CONSTRAINT_MASK (__GFP_HARDWALL|__GFP_THISNODE)
#define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)
#define GFP_RECLAIM_MASK (__GFP_WAIT|__GFP_HIGH|__GFP_IO|__GFP_FS|\
			__GFP_NOWARN|__GFP_REPEAT|__GFP_NOFAIL|\
			__GFP_NORETRY|__GFP_NOMEMALLOC)
#define GFP_SLAB_BUG_MASK (__GFP_DMA32|__GFP_HIGHMEM|~__GFP_BITS_MASK)
#define GFP_ZONE_BAD ( \
	1 << (__GFP_DMA | __GFP_HIGHMEM)				\
	| 1 << (__GFP_DMA | __GFP_DMA32)				\
	| 1 << (__GFP_DMA32 | __GFP_HIGHMEM)				\
	| 1 << (__GFP_DMA | __GFP_DMA32 | __GFP_HIGHMEM)		\
	| 1 << (__GFP_MOVABLE | __GFP_HIGHMEM | __GFP_DMA)		\
	| 1 << (__GFP_MOVABLE | __GFP_DMA32 | __GFP_DMA)		\
	| 1 << (__GFP_MOVABLE | __GFP_DMA32 | __GFP_HIGHMEM)		\
	| 1 << (__GFP_MOVABLE | __GFP_DMA32 | __GFP_DMA | __GFP_HIGHMEM)\
)
#define GFP_ZONE_TABLE ( \
	(ZONE_NORMAL << 0 * ZONES_SHIFT)				\
	| (OPT_ZONE_DMA << __GFP_DMA * ZONES_SHIFT)			\
	| (OPT_ZONE_HIGHMEM << __GFP_HIGHMEM * ZONES_SHIFT)		\
	| (OPT_ZONE_DMA32 << __GFP_DMA32 * ZONES_SHIFT)			\
	| (ZONE_NORMAL << __GFP_MOVABLE * ZONES_SHIFT)			\
	| (OPT_ZONE_DMA << (__GFP_MOVABLE | __GFP_DMA) * ZONES_SHIFT)	\
	| (ZONE_MOVABLE << (__GFP_MOVABLE | __GFP_HIGHMEM) * ZONES_SHIFT)\
	| (OPT_ZONE_DMA32 << (__GFP_MOVABLE | __GFP_DMA32) * ZONES_SHIFT)\
)
#define OPT_ZONE_DMA ZONE_DMA
#define OPT_ZONE_DMA32 ZONE_DMA32
#define OPT_ZONE_HIGHMEM ZONE_HIGHMEM
#define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
#define __GFP_BITS_SHIFT 22	
#define __GFP_HARDWALL   ((__force gfp_t)0x20000u) 
#define __GFP_NOMEMALLOC ((__force gfp_t)0x10000u) 
#define __GFP_NOTRACK_FALSE_POSITIVE (__GFP_NOTRACK)
#define __GFP_RECLAIMABLE ((__force gfp_t)0x80000u) 

#define __free_page(page) __free_pages((page), 0)
#define __get_dma_pages(gfp_mask, order) \
		__get_free_pages((gfp_mask) | GFP_DMA, (order))
#define __get_free_page(gfp_mask) \
		__get_free_pages((gfp_mask), 0)
#define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)
#define alloc_page_vma(gfp_mask, vma, addr) alloc_pages(gfp_mask, 0)
#define alloc_pages(gfp_mask, order) \
		alloc_pages_node(numa_node_id(), gfp_mask, order)
#define free_page(addr) free_pages((addr), 0)
#define LINUX_MM_DEBUG_H 1
#define VIRTUAL_BUG_ON(cond) BUG_ON(cond)
#define VM_BUG_ON(cond) BUG_ON(cond)

#define RECLAIM_DISTANCE 20
#define SD_ALLNODES_INIT (struct sched_domain) {			\
	.min_interval		= 64,					\
	.max_interval		= 64*num_online_cpus(),			\
	.busy_factor		= 128,					\
	.imbalance_pct		= 133,					\
	.cache_nice_tries	= 1,					\
	.busy_idx		= 3,					\
	.idle_idx		= 3,					\
	.flags			= 1*SD_LOAD_BALANCE			\
				| 1*SD_BALANCE_NEWIDLE			\
				| 0*SD_BALANCE_EXEC			\
				| 0*SD_BALANCE_FORK			\
				| 0*SD_BALANCE_WAKE			\
				| 0*SD_WAKE_AFFINE			\
				| 0*SD_SHARE_CPUPOWER			\
				| 0*SD_POWERSAVINGS_BALANCE		\
				| 0*SD_SHARE_PKG_RESOURCES		\
				| 1*SD_SERIALIZE			\
				| 0*SD_PREFER_SIBLING			\
				,					\
	.last_balance		= jiffies,				\
	.balance_interval	= 64,					\
}
#define SD_CPU_INIT (struct sched_domain) {				\
	.min_interval		= 1,					\
	.max_interval		= 4,					\
	.busy_factor		= 64,					\
	.imbalance_pct		= 125,					\
	.cache_nice_tries	= 1,					\
	.busy_idx		= 2,					\
	.idle_idx		= 1,					\
	.newidle_idx		= 0,					\
	.wake_idx		= 0,					\
	.forkexec_idx		= 0,					\
									\
	.flags			= 1*SD_LOAD_BALANCE			\
				| 1*SD_BALANCE_NEWIDLE			\
				| 1*SD_BALANCE_EXEC			\
				| 1*SD_BALANCE_FORK			\
				| 0*SD_BALANCE_WAKE			\
				| 1*SD_WAKE_AFFINE			\
				| 0*SD_PREFER_LOCAL			\
				| 0*SD_SHARE_CPUPOWER			\
				| 0*SD_SHARE_PKG_RESOURCES		\
				| 0*SD_SERIALIZE			\
				| sd_balance_for_package_power()	\
				| sd_power_saving_flags()		\
				,					\
	.last_balance		= jiffies,				\
	.balance_interval	= 1,					\
}
#define SD_MC_INIT (struct sched_domain) {				\
	.min_interval		= 1,					\
	.max_interval		= 4,					\
	.busy_factor		= 64,					\
	.imbalance_pct		= 125,					\
	.cache_nice_tries	= 1,					\
	.busy_idx		= 2,					\
	.wake_idx		= 0,					\
	.forkexec_idx		= 0,					\
									\
	.flags			= 1*SD_LOAD_BALANCE			\
				| 1*SD_BALANCE_NEWIDLE			\
				| 1*SD_BALANCE_EXEC			\
				| 1*SD_BALANCE_FORK			\
				| 0*SD_BALANCE_WAKE			\
				| 1*SD_WAKE_AFFINE			\
				| 0*SD_PREFER_LOCAL			\
				| 0*SD_SHARE_CPUPOWER			\
				| 1*SD_SHARE_PKG_RESOURCES		\
				| 0*SD_SERIALIZE			\
				| sd_balance_for_mc_power()		\
				| sd_power_saving_flags()		\
				,					\
	.last_balance		= jiffies,				\
	.balance_interval	= 1,					\
}
#define SD_SIBLING_INIT (struct sched_domain) {				\
	.min_interval		= 1,					\
	.max_interval		= 2,					\
	.busy_factor		= 64,					\
	.imbalance_pct		= 110,					\
									\
	.flags			= 1*SD_LOAD_BALANCE			\
				| 1*SD_BALANCE_NEWIDLE			\
				| 1*SD_BALANCE_EXEC			\
				| 1*SD_BALANCE_FORK			\
				| 0*SD_BALANCE_WAKE			\
				| 1*SD_WAKE_AFFINE			\
				| 1*SD_SHARE_CPUPOWER			\
				| 0*SD_POWERSAVINGS_BALANCE		\
				| 1*SD_SHARE_PKG_RESOURCES		\
				| 0*SD_SERIALIZE			\
				| 0*SD_PREFER_SIBLING			\
				,					\
	.last_balance		= jiffies,				\
	.balance_interval	= 1,					\
	.smt_gain		= 1178,				\
}

#define for_each_node_with_cpus(node)			\
	for_each_online_node(node)			\
		if (nr_cpus_node(node))
#define node_distance(from,to)	((from) == (to) ? LOCAL_DISTANCE : REMOTE_DISTANCE)
#define node_has_online_mem(nid) (1)
#define nr_cpus_node(node) cpumask_weight(cpumask_of_node(node))
#define topology_core_cpumask(cpu)		cpumask_of(cpu)
#define topology_core_id(cpu)			((void)(cpu), 0)
#define topology_physical_package_id(cpu)	((void)(cpu), -1)
#define topology_thread_cpumask(cpu)		cpumask_of(cpu)
#define DEF_PRIORITY 12
#define LRU_ACTIVE 1
#define LRU_BASE 0
#define LRU_FILE 2
#define MAX_ORDER 11
#define MAX_ORDER_NR_PAGES (1 << (MAX_ORDER - 1))
#define MAX_ZONELISTS 2
#define MAX_ZONES_PER_ZONELIST (MAX_NUMNODES * MAX_NR_ZONES)
#define MIGRATE_ISOLATE       4 
#define MIGRATE_MOVABLE       2
#define MIGRATE_PCPTYPES      3 
#define MIGRATE_RECLAIMABLE   1
#define MIGRATE_RESERVE       3
#define MIGRATE_TYPES         5
#define MIGRATE_UNMOVABLE     0
#define NODE_DATA(nid)		(&contig_page_data)
#define NODE_MEM_MAP(nid)	mem_map
#define NUMA_ZONELIST_ORDER_LEN 16	
#define PAGES_PER_SECTION       (1UL << PFN_SECTION_SHIFT)
#define PAGE_ALLOC_COSTLY_ORDER 3
#define SECTIONS_PER_ROOT       (PAGE_SIZE / sizeof (struct mem_section))
#define SECTION_BLOCKFLAGS_BITS \
	((1UL << (PFN_SECTION_SHIFT - pageblock_order)) * NR_PAGEBLOCK_BITS)
#define SECTION_NR_TO_ROOT(sec)	((sec) / SECTIONS_PER_ROOT)
#define ZONES_SHIFT 0
#define ZONE_PADDING(name)	struct zone_padding name;

#define early_pfn_in_nid(pfn, nid)	(1)
#define early_pfn_valid(pfn)	pfn_valid(pfn)
#define for_each_evictable_lru(l) for (l = 0; l <= LRU_ACTIVE_FILE; l++)
#define for_each_lru(l) for (l = 0; l < NR_LRU_LISTS; l++)
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
	for (z = first_zones_zonelist(zlist, highidx, nodemask, &zone);	\
		zone;							\
		z = next_zones_zonelist(++z, highidx, nodemask, &zone))	\

#define high_wmark_pages(z) (z->watermark[WMARK_HIGH])
#define low_wmark_pages(z) (z->watermark[WMARK_LOW])
#define min_wmark_pages(z) (z->watermark[WMARK_MIN])
#define nid_page_nr(nid, pagenr) 	pgdat_page_nr(NODE_DATA(nid),(pagenr))
#define node_present_pages(nid)	(NODE_DATA(nid)->node_present_pages)
#define node_spanned_pages(nid)	(NODE_DATA(nid)->node_spanned_pages)
#define pfn_to_nid(pfn)							\
({									\
	unsigned long __pfn_to_nid_pfn = (pfn);				\
	page_to_nid(pfn_to_page(__pfn_to_nid_pfn));			\
})
#define pfn_to_section_nr(pfn) ((pfn) >> PFN_SECTION_SHIFT)
#define pfn_valid_within(pfn) pfn_valid(pfn)
#define pgdat_page_nr(pgdat, pagenr)	((pgdat)->node_mem_map + (pagenr))
#define section_nr_to_pfn(sec) ((sec) << PFN_SECTION_SHIFT)
#define sparse_index_init(_sec, _nid)  do {} while (0)
#define sparse_init()	do {} while (0)
#define zone_idx(zone)		((zone) - (zone)->zone_pgdat->node_zones)

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
#define NETDEV_BONDING_DESLAVE  0x0012
#define NETDEV_BONDING_FAILOVER 0x000C
#define NETDEV_REGISTER 0x0005
#define NETDEV_UNREGISTER_BATCH 0x0011
#define RAW_INIT_NOTIFIER_HEAD(name) do {	\
		(name)->head = NULL;		\
	} while (0)
#define RAW_NOTIFIER_HEAD(name)					\
	struct raw_notifier_head name =				\
		RAW_NOTIFIER_INIT(name)
#define RAW_NOTIFIER_INIT(name)	{				\
		.head = NULL }

#define srcu_cleanup_notifier_head(name)	\
		cleanup_srcu_struct(&(name)->srcu);

#define init_srcu_struct(sp) \
({ \
	static struct lock_class_key __srcu_key; \
	\
	__init_srcu_struct((sp), #sp, &__srcu_key); \
})
#define srcu_barrier() barrier()
#define srcu_dereference(p, sp) \
		rcu_dereference_check(p, srcu_read_lock_held(sp))
# define srcu_read_acquire(sp) \
		lock_acquire(&(sp)->dep_map, 0, 0, 2, 1, NULL, _THIS_IP_)
# define srcu_read_release(sp) \
		lock_release(&(sp)->dep_map, 1, _THIS_IP_)
#define DEFINE_MUTEX(mutexname) \
	struct mutex mutexname = __MUTEX_INITIALIZER(mutexname)
# define __DEBUG_MUTEX_INITIALIZER(lockname)
# define __DEP_MAP_MUTEX_INITIALIZER(lockname) \
		, .dep_map = { .name = #lockname }

#define __MUTEX_INITIALIZER(lockname) \
		{ .count = ATOMIC_INIT(1) \
		, .wait_lock = __SPIN_LOCK_UNLOCKED(lockname.wait_lock) \
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
#define mutex_lock(lock) mutex_lock_nested(lock, 0)
#define mutex_lock_interruptible(lock) mutex_lock_interruptible_nested(lock, 0)
# define mutex_lock_interruptible_nested(lock, subclass) mutex_lock_interruptible(lock)
#define mutex_lock_killable(lock) mutex_lock_killable_nested(lock, 0)
# define mutex_lock_killable_nested(lock, subclass) mutex_lock_killable(lock)
# define mutex_lock_nested(lock, subclass) mutex_lock(lock)

# define down_read_nested(sem, subclass)		down_read(sem)
# define down_read_non_owner(sem)		down_read(sem)
# define down_write_nested(sem, subclass)	down_write(sem)
# define up_read_non_owner(sem)			up_read(sem)
#define DECLARE_RWSEM(name) \
	struct rw_semaphore name = __RWSEM_INITIALIZER(name)

# define __RWSEM_DEP_MAP_INIT(lockname) , .dep_map = { .name = #lockname }
#define __RWSEM_INITIALIZER(name) \
{ 0, __SPIN_LOCK_UNLOCKED(name.wait_lock), LIST_HEAD_INIT((name).wait_list) \
  __RWSEM_DEP_MAP_INIT(name) }
#define init_rwsem(sem)						\
do {								\
	static struct lock_class_key __key;			\
								\
	__init_rwsem((sem), #sem, &__key);			\
} while (0)

#define get_pageblock_flags(page) \
			get_pageblock_flags_group(page, 0, NR_PAGEBLOCK_BITS-1)
#define set_pageblock_flags(page) \
			set_pageblock_flags_group(page, 0, NR_PAGEBLOCK_BITS-1)
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
#define next_online_node(nid)	next_node((nid), node_states[N_ONLINE])
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
#define nodelist_scnprintf(buf, len, src) \
			__nodelist_scnprintf((buf), (len), &(src), MAX_NUMNODES)
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
#define MAX_NUMNODES    (1 << NODES_SHIFT)
#define NODES_SHIFT     CONFIG_NODES_SHIFT

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

#  define CALLER_ADDR0 ((unsigned long)__builtin_return_address(0))
#  define CALLER_ADDR1 ((unsigned long)__builtin_return_address(1))
#  define CALLER_ADDR2 ((unsigned long)__builtin_return_address(2))
#  define CALLER_ADDR3 ((unsigned long)__builtin_return_address(3))
#  define CALLER_ADDR4 ((unsigned long)__builtin_return_address(4))
#  define CALLER_ADDR5 ((unsigned long)__builtin_return_address(5))
#  define CALLER_ADDR6 ((unsigned long)__builtin_return_address(6))
#define FTRACE_ADDR ((unsigned long)ftrace_caller)
#define FTRACE_RETFUNC_DEPTH 50
#define FTRACE_RETSTACK_ALLOC_SIZE 32





#define register_ftrace_function(ops) ({ 0; })
#define unregister_ftrace_function(ops) ({ 0; })
#define ACC_MODE(x) ("\004\002\006\006"[(x)&O_ACCMODE])
#define ACL_NOT_CACHED ((void *)(-1))
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
static const struct file_operations __fops = {				\
	.owner	 = THIS_MODULE,						\
	.open	 = __fops ## _open,					\
	.release = simple_attr_release,					\
	.read	 = simple_attr_read,					\
	.write	 = simple_attr_write,					\
};
#define DISCARD_BARRIER (DISCARD_NOBARRIER | (1 << BIO_RW_BARRIER))
#define DISCARD_NOBARRIER (WRITE | (1 << BIO_RW_DISCARD))
#define FASYNC_MAGIC 0x4601
#define FIGETBSZ   _IO(0x00,2)	
#define FILE_LOCK_DEFERRED 1
#define FLOCK_VERIFY_READ  1
#define FLOCK_VERIFY_WRITE 2
#define FS_BINARY_MOUNTDATA 2
#define FS_HAS_SUBTYPE 4
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
#define IS_I_VERSION(inode)   __IS_FLG(inode, MS_I_VERSION)
#define IS_MANDLOCK(inode)	__IS_FLG(inode, MS_MANDLOCK)
#define IS_NOATIME(inode)   __IS_FLG(inode, MS_RDONLY|MS_NOATIME)
#define IS_NOCMTIME(inode)	((inode)->i_flags & S_NOCMTIME)
#define IS_NOQUOTA(inode)	((inode)->i_flags & S_NOQUOTA)
#define IS_POSIXACL(inode)	__IS_FLG(inode, MS_POSIXACL)
#define IS_PRIVATE(inode)	((inode)->i_flags & S_PRIVATE)
#define IS_RDONLY(inode) ((inode)->i_sb->s_flags & MS_RDONLY)
#define IS_SWAPFILE(inode)	((inode)->i_flags & S_SWAPFILE)
#define IS_SYNC(inode)		(__IS_FLG(inode, MS_SYNCHRONOUS) || \
					((inode)->i_flags & S_SYNC))
#define I_DIRTY (I_DIRTY_SYNC | I_DIRTY_DATASYNC | I_DIRTY_PAGES)
#define MAX_LFS_FILESIZE 	0x7fffffffffffffffUL
#define MAY_ACCESS 16
#define MAY_APPEND 8
#define MAY_EXEC 1
#define MAY_OPEN 32
#define MAY_READ 4
#define MAY_WRITE 2
#define MS_MGC_MSK 0xffff0000
#define MS_MGC_VAL 0xC0ED0000
#define NR_FILE  8192	
#define OPEN_FMODE(flag) ((__force fmode_t)((flag + 1) & O_ACCMODE))
#define READ 0
#define READA 2		
#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - sizeof(struct simple_transaction_argresp))
#define SWRITE 3	
#define WRITE 1

#define __IS_FLG(inode,flg) ((inode)->i_sb->s_flags & (flg))

#define __getname()		__getname_gfp(GFP_KERNEL)
#define __getname_gfp(gfp)	kmem_cache_alloc(names_cachep, (gfp))
#define __putname(name)		kmem_cache_free(names_cachep, (void *)(name))
#define bd_claim_by_disk(bdev, holder, disk)	bd_claim(bdev, holder)
#define bd_release_from_disk(bdev, disk)	bd_release(bdev)
#define bio_data_dir(bio)	((bio)->bi_rw & 1)
#define bio_rw(bio)		((bio)->bi_rw & (RW_MASK | RWA_MASK))
#define buffer_migrate_page NULL
#define file_count(x)	atomic_long_read(&(x)->f_count)
#define file_list_lock() spin_lock(&files_lock);
#define file_list_unlock() spin_unlock(&files_lock);
#define fops_get(fops) \
	(((fops) && try_module_get((fops)->owner) ? (fops) : NULL))
#define fops_put(fops) \
	do { if (fops) module_put((fops)->owner); } while(0)
#define fput_atomic(x)	atomic_long_add_unless(&(x)->f_count, -1, 1)
#define get_file(x)	atomic_long_inc(&(x)->f_count)
#define get_fs_excl() atomic_inc(&current->fs_excl)
#define has_fs_excl() atomic_read(&current->fs_excl)
#define i_size_ordered_init(inode) seqcount_init(&inode->i_size_seqcount)
#define is_owner_or_cap(inode)	\
	((current_fsuid() == (inode)->i_uid) || capable(CAP_FOWNER))
#define kern_mount(type) kern_mount_data(type, NULL)
#define put_fs_excl() atomic_dec(&current->fs_excl)
#define putname(name)   __putname(name)
#define special_file(m) (S_ISCHR(m)||S_ISBLK(m)||S_ISFIFO(m)||S_ISSOCK(m))
#define vfs_check_frozen(sb, level) \
	wait_event((sb)->s_wait_unfrozen, ((sb)->s_frozen < (level)))
#define IS_ERR_VALUE(x) unlikely((x) >= (unsigned long)-MAX_ERRNO)

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


#define RPC_MAX_AUTH_SIZE (400)
#define RPC_MAX_HEADER_WITH_AUTH \
	(RPC_CALLHDRSIZE + 2*(2+RPC_MAX_AUTH_SIZE/4))
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
#define Q_GETQUOTA 0x800007	
#define Q_QUOTAOFF 0x800003	
#define Q_QUOTAON  0x800002	
#define Q_SETINFO  0x800006	
#define Q_SETQUOTA 0x800008	
#define Q_SYNC     0x800001	
#define SUBCMDMASK  0x00ff
#define SUBCMDSHIFT 8
#define USRQUOTA  0		

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
#define V1_DQF_RSQUASH 1
#define V1_INIT_ALLOC 1
#define V1_INIT_REWRITE 1

#define FS_DQ_BHARD 	(1<<3)
#define FS_DQ_RTBTIMER 	(1<<8)
#define XQM_CMD(x)	(('X'<<8)+(x))	
#define XQM_COMMAND(x)	(((x) & (0xff<<8)) == ('X'<<8))	


#define percpu_counter_init(fbc, value)					\
	({								\
		static struct lock_class_key __key;			\
									\
		__percpu_counter_init(fbc, value, &__key);		\
	})

#define DECLARE_MUTEX(name)	\
	struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)

#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.lock		= __SPIN_LOCK_UNLOCKED((name).lock),		\
	.count		= n,						\
	.wait_list	= LIST_HEAD_INIT((name).wait_list),		\
}
#define init_MUTEX(sem)		sema_init(sem, 1)
#define init_MUTEX_LOCKED(sem)	sema_init(sem, 0)
#define CAP_AUDIT_CONTROL    30
#define CAP_AUDIT_WRITE      29
#define CAP_BOP_ALL(c, a, b, OP)                                    \
do {                                                                \
	unsigned __capi;                                            \
	CAP_FOR_EACH_U32(__capi) {                                  \
		c.cap[__capi] = a.cap[__capi] OP b.cap[__capi];     \
	}                                                           \
} while (0)
#define CAP_CHOWN            0
#define CAP_DAC_OVERRIDE     1
#define CAP_DAC_READ_SEARCH  2
# define CAP_EMPTY_SET    ((kernel_cap_t){{ 0, 0 }})
#define CAP_FOR_EACH_U32(__capi)  \
	for (__capi = 0; __capi < _KERNEL_CAPABILITY_U32S; ++__capi)
#define CAP_FOWNER           3
#define CAP_FSETID           4
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
# define CAP_FULL_SET     ((kernel_cap_t){{ ~0, ~0 }})
# define CAP_INIT_EFF_SET ((kernel_cap_t){{ ~CAP_TO_MASK(CAP_SETPCAP), ~0 }})
#define CAP_INIT_INH_SET    CAP_EMPTY_SET
#define CAP_IPC_LOCK         14
#define CAP_IPC_OWNER        15
#define CAP_KILL             5
#define CAP_LAST_CAP         CAP_MAC_ADMIN
#define CAP_LEASE            28
#define CAP_LINUX_IMMUTABLE  9
#define CAP_MAC_ADMIN        33
#define CAP_MAC_OVERRIDE     32
#define CAP_MKNOD            27
#define CAP_NET_ADMIN        12
#define CAP_NET_BIND_SERVICE 10
#define CAP_NET_BROADCAST    11
#define CAP_NET_RAW          13
# define CAP_NFSD_SET     ((kernel_cap_t){{ CAP_FS_MASK_B0 \
				    | CAP_TO_MASK(CAP_SYS_RESOURCE), \
				    CAP_FS_MASK_B1 } })
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
#define CAP_TO_INDEX(x)     ((x) >> 5)        
#define CAP_TO_MASK(x)      (1 << ((x) & 31)) 
#define CAP_UOP_ALL(c, a, OP)                                       \
do {                                                                \
	unsigned __capi;                                            \
	CAP_FOR_EACH_U32(__capi) {                                  \
		c.cap[__capi] = OP a.cap[__capi];                   \
	}                                                           \
} while (0)
#define VFS_CAP_U32             VFS_CAP_U32_2
#define VFS_CAP_U32_1           1
#define VFS_CAP_U32_2           2
#define XATTR_CAPS_SUFFIX "capability"
#define XATTR_CAPS_SZ           XATTR_CAPS_SZ_2
#define XATTR_CAPS_SZ_1         (sizeof(__le32)*(1 + 2*VFS_CAP_U32_1))
#define XATTR_CAPS_SZ_2         (sizeof(__le32)*(1 + 2*VFS_CAP_U32_2))
#define XATTR_NAME_CAPS XATTR_SECURITY_PREFIX XATTR_CAPS_SUFFIX
#define _KERNEL_CAPABILITY_U32S    _LINUX_CAPABILITY_U32S_3
#define _KERNEL_CAPABILITY_VERSION _LINUX_CAPABILITY_VERSION_3
#define _KERNEL_CAP_T_SIZE     (sizeof(kernel_cap_t))

#define _LINUX_CAPABILITY_U32S     _LINUX_CAPABILITY_U32S_1
#define _LINUX_CAPABILITY_U32S_1     1
#define _LINUX_CAPABILITY_U32S_2     2
#define _LINUX_CAPABILITY_U32S_3     2
#define _LINUX_CAPABILITY_VERSION  _LINUX_CAPABILITY_VERSION_1
#define _LINUX_CAPABILITY_VERSION_1  0x19980330
#define _LINUX_CAPABILITY_VERSION_2  0x20071026  
#define _LINUX_CAPABILITY_VERSION_3  0x20080522
#define _USER_CAP_HEADER_SIZE  (sizeof(struct __user_cap_header_struct))
# define cap_clear(c)         do { (c) = __cap_empty_set; } while (0)
#define cap_lower(c, flag)  ((c).cap[CAP_TO_INDEX(flag)] &= ~CAP_TO_MASK(flag))
#define cap_raise(c, flag)  ((c).cap[CAP_TO_INDEX(flag)] |= CAP_TO_MASK(flag))
#define cap_raised(c, flag) ((c).cap[CAP_TO_INDEX(flag)] & CAP_TO_MASK(flag))
# define cap_set_full(c)      do { (c) = __cap_full_set; } while (0)
# define cap_set_init_eff(c)  do { (c) = __cap_init_eff_set; } while (0)
#define cap_valid(x) ((x) >= 0 && (x) <= CAP_LAST_CAP)
#define has_capability(t, cap) (security_real_capable((t), (cap)) == 0)
#define has_capability_noaudit(t, cap) \
	(security_real_capable_noaudit((t), (cap)) == 0)

#define do_each_pid_task(pid, type, task)				\
	do {								\
		struct hlist_node *pos___;				\
		if ((pid) != NULL)					\
			hlist_for_each_entry_rcu((task), pos___,	\
				&(pid)->tasks[type], pids[type].node) {
#define do_each_pid_thread(pid, type, task)				\
	do_each_pid_task(pid, type, task) {				\
		struct task_struct *tg___ = task;			\
		do {
#define while_each_pid_task(pid, type, task)				\
				if (type == PIDTYPE_PID)		\
					break;				\
			}						\
	} while (0)
#define while_each_pid_thread(pid, type, task)				\
		} while_each_thread(tg___, task);			\
		task = tg___;						\
	} while_each_pid_task(pid, type, task)
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
#define RADIX_TREE_RETRY ((void *)-1UL)


#define DCACHE_AUTOFS_PENDING 0x0001    
#define DCACHE_NFSFS_RENAMED  0x0002    
#define DNAME_INLINE_LEN_MIN 32 
#define IS_ROOT(x) ((x) == (x)->d_parent)

#define init_name_hash()		0

#define __hlist_for_each_rcu(pos, head)			\
	for (pos = rcu_dereference((head)->first);	\
	     pos && ({ prefetch(pos->next); 1; });	\
	     pos = rcu_dereference(pos->next))
#define __list_for_each_rcu(pos, head) \
	for (pos = rcu_dereference_raw((head)->next); \
		pos != (head); \
		pos = rcu_dereference_raw(pos->next))
#define hlist_for_each_entry_continue_rcu(tpos, pos, member)		\
	for (pos = rcu_dereference((pos)->next);			\
	     pos && ({ prefetch(pos->next); 1; }) &&			\
	     ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; });  \
	     pos = rcu_dereference(pos->next))
#define hlist_for_each_entry_continue_rcu_bh(tpos, pos, member)		\
	for (pos = rcu_dereference_bh((pos)->next);			\
	     pos && ({ prefetch(pos->next); 1; }) &&			\
	     ({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; });  \
	     pos = rcu_dereference_bh(pos->next))
#define hlist_for_each_entry_rcu(tpos, pos, head, member)		 \
	for (pos = rcu_dereference_raw((head)->first);			 \
		pos && ({ prefetch(pos->next); 1; }) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; }); \
		pos = rcu_dereference_raw(pos->next))
#define hlist_for_each_entry_rcu_bh(tpos, pos, head, member)		 \
	for (pos = rcu_dereference_bh((head)->first);			 \
		pos && ({ prefetch(pos->next); 1; }) &&			 \
		({ tpos = hlist_entry(pos, typeof(*tpos), member); 1; }); \
		pos = rcu_dereference_bh(pos->next))
#define list_entry_rcu(ptr, type, member) \
	container_of(rcu_dereference_raw(ptr), type, member)
#define list_first_entry_rcu(ptr, type, member) \
	list_entry_rcu((ptr)->next, type, member)
#define list_for_each_continue_rcu(pos, head) \
	for ((pos) = rcu_dereference_raw((pos)->next); \
		prefetch((pos)->next), (pos) != (head); \
		(pos) = rcu_dereference_raw((pos)->next))
#define list_for_each_entry_continue_rcu(pos, head, member) 		\
	for (pos = list_entry_rcu(pos->member.next, typeof(*pos), member); \
	     prefetch(pos->member.next), &pos->member != (head);	\
	     pos = list_entry_rcu(pos->member.next, typeof(*pos), member))
#define list_for_each_entry_rcu(pos, head, member) \
	for (pos = list_entry_rcu((head)->next, typeof(*pos), member); \
		prefetch(pos->member.next), &pos->member != (head); \
		pos = list_entry_rcu(pos->member.next, typeof(*pos), member))
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

#define CALC_LOAD(load,exp,n) \
	load *= exp; \
	load += n*(FIXED_1-exp); \
	load >>= FSHIFT;
#define INIT_USER (&root_user)
# define MAX_LOCK_DEPTH 48UL
#define MMF_DUMPABLE      0  
#define MMF_DUMPABLE_BITS 2
#define MMF_DUMPABLE_MASK ((1 << MMF_DUMPABLE_BITS) - 1)
#define MMF_DUMP_FILTER_DEFAULT \
	((1 << MMF_DUMP_ANON_PRIVATE) |	(1 << MMF_DUMP_ANON_SHARED) |\
	 (1 << MMF_DUMP_HUGETLB_PRIVATE) | MMF_DUMP_MASK_DEFAULT_ELF)
#define MMF_DUMP_FILTER_MASK \
	(((1 << MMF_DUMP_FILTER_BITS) - 1) << MMF_DUMP_FILTER_SHIFT)
#define MMF_DUMP_HUGETLB_PRIVATE 7
#define MMF_DUMP_HUGETLB_SHARED  8
#define MMF_DUMP_SECURELY 1  
#define PF_FREEZER_NOSIG 0x80000000	
#define PF_LESS_THROTTLE 0x00100000	
#define PF_MCE_EARLY    0x08000000      
#define PF_MCE_PROCESS  0x00000080      
#define RCU_READ_UNLOCK_BLOCKED (1 << 0) 
#define RCU_READ_UNLOCK_NEED_QS (1 << 1) 
#define SCHED_RESET_ON_FORK     0x40000000
#define SEND_SIG_NOINFO ((struct siginfo *) 0)
#define TASK_COMM_LEN 16
#define TASK_SIZE_OF(tsk)	TASK_SIZE
#define TASK_STATE_TO_CHAR_STR "RSDTtZXxKW"

# define __ARCH_WANT_UNLOCKED_CTXSW
#define __set_current_state(state_value)			\
	do { current->state = (state_value); } while (0)
#define __set_task_state(tsk, state_value)		\
	do { (tsk)->state = (state_value); } while (0)
#define clear_stopped_child_used_math(child) do { (child)->flags &= ~PF_USED_MATH; } while (0)
#define clear_used_math() clear_stopped_child_used_math(current)
#define cond_resched() ({			\
	__might_sleep("__FILE__", "__LINE__", 0);	\
	_cond_resched();			\
})
#define cond_resched_lock(lock) ({				\
	__might_sleep("__FILE__", "__LINE__", PREEMPT_LOCK_OFFSET);	\
	__cond_resched_lock(lock);				\
})
#define cond_resched_softirq() ({				\
	__might_sleep("__FILE__", "__LINE__", SOFTIRQ_OFFSET);	\
	__cond_resched_softirq();				\
})
#define conditional_stopped_child_used_math(condition, child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= (condition) ? PF_USED_MATH : 0; } while (0)
#define conditional_used_math(condition) \
	conditional_stopped_child_used_math(condition, current)
#define copy_to_stopped_child_used_math(child) \
	do { (child)->flags &= ~PF_USED_MATH, (child)->flags |= current->flags & PF_USED_MATH; } while (0)
#define delay_group_leader(p) \
		(thread_group_leader(p) && !thread_group_empty(p))
#define do_each_thread(g, t) \
	for (g = t = &init_task ; (g = t = next_task(g)) != &init_task ; ) do
#define for_each_process(p) \
	for (p = &init_task ; (p = next_task(p)) != &init_task ; )
#define get_task_struct(tsk) do { atomic_inc(&(tsk)->usage); } while(0)
#define next_task(p) \
	list_entry_rcu((p)->tasks.next, struct task_struct, tasks)
# define rt_mutex_adjust_pi(p)		do { } while (0)
#define sched_exec()   {}
#define set_current_state(state_value)		\
	set_mb(current->state, (state_value))
#define set_stopped_child_used_math(child) do { (child)->flags |= PF_USED_MATH; } while (0)
#define set_task_state(tsk, state_value)		\
	set_mb((tsk)->state, (state_value))
#define set_used_math() set_stopped_child_used_math(current)
#define task_contributes_to_load(task)	\
				((task->state & TASK_UNINTERRUPTIBLE) != 0 && \
				 (task->flags & PF_FREEZING) == 0)
#define task_is_stopped(task)	((task->state & __TASK_STOPPED) != 0)
#define task_is_stopped_or_traced(task)	\
			((task->state & (__TASK_STOPPED | __TASK_TRACED)) != 0)
#define task_is_traced(task)	((task->state & __TASK_TRACED) != 0)
#define task_stack_page(task)	((task)->stack)
#define task_thread_info(task)	((struct thread_info *)(task)->stack)
#define thread_group_leader(p)	(p == p->group_leader)
#define tsk_cpus_allowed(tsk) (&(tsk)->cpus_allowed)
#define tsk_used_math(p) ((p)->flags & PF_USED_MATH)
#define used_math() tsk_used_math(current)
#define while_each_thread(g, t) \
	while ((t = next_thread(t)) != g)

#define aio_ring_avail(info, ring)	(((ring)->head + (info)->nr - 1 - (ring)->tail) % (info)->nr)
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
	} while (0)
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

#define PADDED(x,y)	x, y

#define GROUP_AT(gi, i) \
	((gi)->blocks[(i) / NGROUPS_PER_BLOCK][(i) % NGROUPS_PER_BLOCK])

#define __task_cred(task) \
	((const struct cred *)(rcu_dereference_check((task)->real_cred, rcu_read_lock_held() || lockdep_tasklist_lock_is_held())))
#define current_cap()		(current_cred_xxx(cap_effective))
#define current_cred() \
	(current->cred)
#define current_cred_xxx(xxx)			\
({						\
	current->cred->xxx;			\
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
#define current_security()	(current_cred_xxx(security))
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
#define current_user_ns()	(current_cred_xxx(user)->user_ns)
#define get_current_cred()				\
	(get_cred(current_cred()))
#define get_current_groups()				\
({							\
	struct group_info *__groups;			\
	struct cred *__cred;				\
	__cred = (struct cred *) current_cred();	\
	__groups = get_group_info(__cred->group_info);	\
	__groups;					\
})
#define get_current_user()				\
({							\
	struct user_struct *__u;			\
	struct cred *__cred;				\
	__cred = (struct cred *) current_cred();	\
	__u = get_uid(__cred->user);			\
	__u;						\
})
#define get_task_cred(task)				\
({							\
	struct cred *__cred;				\
	rcu_read_lock();				\
	__cred = (struct cred *) __task_cred((task));	\
	get_cred(__cred);				\
	rcu_read_unlock();				\
	__cred;						\
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


#define is_key_possessed(k)		0
#define key_fsgid_changed(t)		do { } while(0)
#define key_fsuid_changed(t)		do { } while(0)
#define key_get(k) 			({ NULL; })
#define key_init()			do { } while(0)
#define key_put(k)			do { } while(0)
#define key_ref_put(k)			do { } while(0)
#define key_ref_to_ptr(k)		NULL
#define key_replace_session_keyring()	do { } while(0)
#define key_revoke(k)			do { } while(0)
#define key_serial(k)			0
#define key_validate(k)			0
#define make_key_ref(k, p)		NULL
#define CTL_MAXNAME 10		

#define RB_CLEAR_NODE(node)	(rb_set_parent(node, node))
#define RB_EMPTY_NODE(node)	(rb_parent(node) == node)
#define RB_EMPTY_ROOT(root)	((root)->rb_node == NULL)
#define rb_color(r)   ((r)->rb_parent_color & 1)
#define rb_is_black(r) rb_color(r)
#define rb_is_red(r)   (!rb_color(r))
#define rb_parent(r)   ((struct rb_node *)((r)->rb_parent_color & ~3))
#define rb_set_black(r)  do { (r)->rb_parent_color |= 1; } while (0)
#define rb_set_red(r)  do { (r)->rb_parent_color &= ~1; } while (0)

#define HRTIMER_MAX_CLOCK_BASES 2

# define ktime_divns(kt, div)		(u64)((kt).tv64 / (div))

#define DEFINE_RT_MUTEX(mutexname) \
	struct rt_mutex mutexname = __RT_MUTEX_INITIALIZER(mutexname)
# define INIT_RT_MUTEXES(tsk)						\
	.pi_waiters	= PLIST_HEAD_INIT(tsk.pi_waiters, tsk.pi_lock),	\
	INIT_RT_MUTEX_DEBUG(tsk)
# define __DEBUG_RT_MUTEX_INITIALIZER(mutexname) \
	, .name = #mutexname, .file = "__FILE__", .line = "__LINE__"

#define __RT_MUTEX_INITIALIZER(mutexname) \
	{ .wait_lock = __RAW_SPIN_LOCK_UNLOCKED(mutexname.wait_lock) \
	, .wait_list = PLIST_HEAD_INIT_RAW(mutexname.wait_list, mutexname.wait_lock) \
	, .owner = NULL \
	__DEBUG_RT_MUTEX_INITIALIZER(mutexname)}
# define rt_mutex_debug_check_no_locks_held(task)	do { } while (0)
# define rt_mutex_debug_task_free(t)			do { } while (0)
# define rt_mutex_init(mutex)			__rt_mutex_init(mutex, __func__)
#define PLIST_HEAD_INIT(head, _lock)			\
{							\
	_PLIST_HEAD_INIT(head),				\
	PLIST_HEAD_LOCK_INIT(&(_lock))			\
}
#define PLIST_HEAD_INIT_RAW(head, _lock)		\
{							\
	_PLIST_HEAD_INIT(head),				\
	PLIST_HEAD_LOCK_INIT_RAW(&(_lock))		\
}
# define PLIST_HEAD_LOCK_INIT(_lock)		.spinlock = _lock
# define PLIST_HEAD_LOCK_INIT_RAW(_lock)	.rawlock = _lock
#define PLIST_NODE_INIT(node, __prio)			\
{							\
	.prio  = (__prio),				\
	.plist = { _PLIST_HEAD_INIT((node).plist) },	\
}

#define _PLIST_HEAD_INIT(head)				\
	.prio_list = LIST_HEAD_INIT((head).prio_list),	\
	.node_list = LIST_HEAD_INIT((head).node_list)
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

#define secure_computing(x) do { } while (0)
#define INIT_PROP_LOCAL_SINGLE(name)			\
{	.lock = __SPIN_LOCK_UNLOCKED(name.lock),	\
}
#define PROP_MAX_SHIFT (3*BITS_PER_LONG/4)

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
#define rt_sigmask(sig)	(1ULL << ((sig)-1))
#define sig_fatal(t, signr) \
	(!siginmask(signr, SIG_KERNEL_IGNORE_MASK|SIG_KERNEL_STOP_MASK) && \
	 (t)->sighand->action[(signr)-1].sa.sa_handler == SIG_DFL)
#define sig_kernel_coredump(sig) \
	(((sig) < SIGRTMIN) && siginmask(sig, SIG_KERNEL_COREDUMP_MASK))
#define sig_kernel_ignore(sig) \
	(((sig) < SIGRTMIN) && siginmask(sig, SIG_KERNEL_IGNORE_MASK))
#define sig_kernel_only(sig) \
	(((sig) < SIGRTMIN) && siginmask(sig, SIG_KERNEL_ONLY_MASK))
#define sig_kernel_stop(sig) \
	(((sig) < SIGRTMIN) && siginmask(sig, SIG_KERNEL_STOP_MASK))
#define sig_user_defined(t, signr) \
	(((t)->sighand->action[(signr)-1].sa.sa_handler != SIG_DFL) &&	\
	 ((t)->sighand->action[(signr)-1].sa.sa_handler != SIG_IGN))
#define siginmask(sig, mask) (rt_sigmask(sig) & (mask))
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

#define DIPC            25
#define IPCCALL(version,op)	((version)<<16 | (op))
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

#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))
#define AT_VECTOR_SIZE_ARCH 0


#define mm_cpumask(mm) (&(mm)->cpu_vm_mask)
#define  LINUX_PAGE_DEBUG_FLAGS_H
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
#define AT_VECTOR_SIZE_BASE 19 

#define KSYM_NAME_LEN 128
#define KSYM_SYMBOL_LEN (sizeof("%s+%#lx/%#lx [%s]") + (KSYM_NAME_LEN - 1) + \
			 2*(BITS_PER_LONG*3/10) + (MODULE_NAME_LEN - 1) + 1)

#define __print_symbol(fmt, addr)

#define PIDMAP_ENTRIES         ((PID_MAX_LIMIT + 8*PAGE_SIZE - 1)/PAGE_SIZE/8)


#define DEFAULT_SEEKS 2 


#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define PFN_SECTION_SHIFT 0
#define VM_CAN_NONLINEAR 0x08000000	
#define VM_ClearReadHint(v)		(v)->vm_flags &= ~VM_READHINTMASK
#define VM_FAULT_HWPOISON 0x0010	
#define VM_IO           0x00004000	
#define VM_NormalReadHint(v)		(!((v)->vm_flags & VM_READHINTMASK))
#define VM_RandomReadHint(v)		((v)->vm_flags & VM_RAND_READ)
#define VM_SPECIAL (VM_IO | VM_DONTEXPAND | VM_RESERVED | VM_PFNMAP)
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
#define sysctl_legacy_va_layout 0
#define vma_prio_tree_foreach(vma, iter, root, begin, end)	\
	for (prio_tree_iter_init(iter, root, begin, end), vma = NULL;	\
		(vma = vma_prio_tree_next(vma, iter)); )
#define DMA32_ZONE(xx) xx##_DMA32,
#define DMA_ZONE(xx) xx##_DMA,
#define FOR_ALL_ZONES(xx) DMA_ZONE(xx) DMA32_ZONE(xx) xx##_NORMAL HIGHMEM_ZONE(xx) , xx##_MOVABLE
#define HIGHMEM_ZONE(xx) , xx##_HIGH

#define __count_zone_vm_events(item, zone, delta) \
		__count_vm_events(item##_NORMAL - ZONE_NORMAL + \
		zone_idx(zone), delta)
#define add_zone_page_state(__z, __i, __d) mod_zone_page_state(__z, __i, __d)
#define dec_zone_page_state __dec_zone_page_state
#define inc_zone_page_state __inc_zone_page_state
#define mod_zone_page_state __mod_zone_page_state
#define node_page_state(node, item) global_page_state(item)
#define sub_zone_page_state(__z, __i, __d) mod_zone_page_state(__z, __i, -(__d))
#define zone_statistics(_zl,_z) do { } while (0)
#define CLEARPAGEFLAG(uname, lname)					\
static inline void ClearPage##uname(struct page *page)			\
			{ clear_bit(PG_##lname, &page->flags); }
#define CLEARPAGEFLAG_NOOP(uname)					\
static inline void ClearPage##uname(struct page *page) {  }
#define PAGEFLAG(uname, lname) TESTPAGEFLAG(uname, lname)		\
	SETPAGEFLAG(uname, lname) CLEARPAGEFLAG(uname, lname)
#define PAGEFLAG_FALSE(uname) 						\
static inline int Page##uname(struct page *page) 			\
			{ return 0; }
#define PAGE_FLAGS_CHECK_AT_FREE \
	(1 << PG_lru	 | 1 << PG_locked    | \
	 1 << PG_private | 1 << PG_private_2 | \
	 1 << PG_buddy	 | 1 << PG_writeback | 1 << PG_reserved | \
	 1 << PG_slab	 | 1 << PG_swapcache | 1 << PG_active | \
	 1 << PG_unevictable | __PG_MLOCKED | __PG_HWPOISON)

#define PG_head_tail_mask ((1L << PG_compound) | (1L << PG_reclaim))
#define PageHighMem(__p) is_highmem(page_zone(__p))
#define SETPAGEFLAG(uname, lname)					\
static inline void SetPage##uname(struct page *page)			\
			{ set_bit(PG_##lname, &page->flags); }
#define SETPAGEFLAG_NOOP(uname)						\
static inline void SetPage##uname(struct page *page) {  }
#define TESTCLEARFLAG(uname, lname)					\
static inline int TestClearPage##uname(struct page *page)		\
		{ return test_and_clear_bit(PG_##lname, &page->flags); }
#define TESTCLEARFLAG_FALSE(uname)					\
static inline int TestClearPage##uname(struct page *page) { return 0; }
#define TESTPAGEFLAG(uname, lname)					\
static inline int Page##uname(struct page *page) 			\
			{ return test_bit(PG_##lname, &page->flags); }
#define TESTSCFLAG(uname, lname)					\
	TESTSETFLAG(uname, lname) TESTCLEARFLAG(uname, lname)
#define TESTSETFLAG(uname, lname)					\
static inline int TestSetPage##uname(struct page *page)			\
		{ return test_and_set_bit(PG_##lname, &page->flags); }
#define __CLEARPAGEFLAG(uname, lname)					\
static inline void __ClearPage##uname(struct page *page)		\
			{ __clear_bit(PG_##lname, &page->flags); }
#define __CLEARPAGEFLAG_NOOP(uname)					\
static inline void __ClearPage##uname(struct page *page) {  }
#define __PAGEFLAG(uname, lname) TESTPAGEFLAG(uname, lname)		\
	__SETPAGEFLAG(uname, lname)  __CLEARPAGEFLAG(uname, lname)
#define __PG_HWPOISON (1UL << PG_hwpoison)
#define __SETPAGEFLAG(uname, lname)					\
static inline void __SetPage##uname(struct page *page)			\
			{ __set_bit(PG_##lname, &page->flags); }
#define __TESTCLEARFLAG(uname, lname)					\
static inline int __TestClearPage##uname(struct page *page)		\
		{ return __test_and_clear_bit(PG_##lname, &page->flags); }
#define __TESTCLEARFLAG_FALSE(uname)					\
static inline int __TestClearPage##uname(struct page *page) { return 0; }
#define MAX_RESOURCE ((resource_size_t)~0)

# define IRQ_EXIT_OFFSET (HARDIRQ_OFFSET-1)

#define MAX_HARDIRQ_BITS 10
# define PREEMPT_CHECK_OFFSET 0
# define PREEMPT_INATOMIC_BASE kernel_locked()
#define __IRQ_MASK(x)	((1UL << (x))-1)
#define __irq_enter()					\
	do {						\
		account_system_vtime(current);		\
		add_preempt_count(HARDIRQ_OFFSET);	\
		trace_hardirq_enter();			\
	} while (0)
#define __irq_exit()					\
	do {						\
		trace_hardirq_exit();			\
		account_system_vtime(current);		\
		sub_preempt_count(HARDIRQ_OFFSET);	\
	} while (0)
#define hardirq_count()	(preempt_count() & HARDIRQ_MASK)
#define in_atomic()	((preempt_count() & ~PREEMPT_ACTIVE) != PREEMPT_INATOMIC_BASE)
#define in_atomic_preempt_off() \
		((preempt_count() & ~PREEMPT_ACTIVE) != PREEMPT_CHECK_OFFSET)
#define in_interrupt()		(irq_count())
#define in_irq()		(hardirq_count())
#define in_nmi()	(preempt_count() & NMI_MASK)
#define in_softirq()		(softirq_count())
#define irq_count()	(preempt_count() & (HARDIRQ_MASK | SOFTIRQ_MASK \
				 | NMI_MASK))
#define nmi_enter()						\
	do {							\
		ftrace_nmi_enter();				\
		BUG_ON(in_nmi());				\
		add_preempt_count(NMI_OFFSET + HARDIRQ_OFFSET);	\
		lockdep_off();					\
		rcu_nmi_enter();				\
		trace_hardirq_enter();				\
	} while (0)
#define nmi_exit()						\
	do {							\
		trace_hardirq_exit();				\
		rcu_nmi_exit();					\
		lockdep_on();					\
		BUG_ON(!in_nmi());				\
		sub_preempt_count(NMI_OFFSET + HARDIRQ_OFFSET);	\
		ftrace_nmi_exit();				\
	} while (0)
# define preemptible()	(preempt_count() == 0 && !irqs_disabled())
# define rcu_irq_enter() do { } while (0)
# define rcu_irq_exit() do { } while (0)
# define rcu_nmi_enter() do { } while (0)
# define rcu_nmi_exit() do { } while (0)
#define softirq_count()	(preempt_count() & SOFTIRQ_MASK)
# define synchronize_irq(irq)	barrier()


#define cycle_kernel_lock()			do { } while(0)
#define kernel_locked()				1
#define lock_kernel() do {					\
	_lock_kernel(__func__, "__FILE__", "__LINE__");		\
} while (0)
#define reacquire_kernel_lock(task)		0
#define release_kernel_lock(tsk) do { 		\
	if (unlikely((tsk)->lock_depth >= 0))	\
		__release_kernel_lock();	\
} while (0)
#define unlock_kernel()	do {					\
	_unlock_kernel(__func__, "__FILE__", "__LINE__");		\
} while (0)


#define ring_buffer_alloc(size, flags)			\
({							\
	static struct lock_class_key __key;		\
	__ring_buffer_alloc((size), (flags), &__key);	\
})
#define SEQ_SKIP 1
#define SEQ_START_TOKEN ((void *)1)


#define kmemcheck_annotate_bitfield(ptr, name)	\
	do {					\
	} while (0)
#define kmemcheck_annotate_variable(var)	\
	do {					\
	} while (0)


#define kmemcheck_enabled 0

#define KMALLOC_CACHES (2 * SLUB_PAGE_SHIFT)
#define KMALLOC_MIN_SIZE ARCH_KMALLOC_MINALIGN
#define KMALLOC_SHIFT_LOW ilog2(KMALLOC_MIN_SIZE)
#define SLUB_DMA __GFP_DMA
#define SLUB_MAX_SIZE (2 * PAGE_SIZE)
#define SLUB_PAGE_SHIFT (PAGE_SHIFT + 2)



#define DMA_TX_TYPE_END (DMA_SLAVE + 1)
#define async_dma_find_channel(type) dma_find_channel(DMA_ASYNC_TX)
#define async_dmaengine_get()	dmaengine_get()
#define async_dmaengine_put()	dmaengine_put()
#define dma_async_memcpy_complete(chan, cookie, last, used)\
	dma_async_is_tx_complete(chan, cookie, last, used)
#define dma_async_memcpy_issue_pending(chan) dma_async_issue_pending(chan)
#define dma_cap_clear(tx, mask) __dma_cap_clear((tx), &(mask))
#define dma_cap_set(tx, mask) __dma_cap_set((tx), &(mask))
#define dma_cap_zero(mask) __dma_cap_zero(&(mask))
#define dma_has_cap(tx, mask) __dma_has_cap((tx), &(mask))
#define dma_request_channel(mask, x, y) __dma_request_channel(&(mask), x, y)
#define dma_submit_error(cookie) ((cookie) < 0 ? 1 : 0)
#define first_dma_cap(mask) __first_dma_cap(&(mask))
#define for_each_dma_cap_mask(cap, mask) \
	for ((cap) = first_dma_cap(mask);	\
		(cap) < DMA_TX_TYPE_END;	\
		(cap) = next_dma_cap((cap), (mask)))
#define net_dmaengine_get()	dmaengine_get()
#define net_dmaengine_put()	dmaengine_put()
#define next_dma_cap(n, mask) __next_dma_cap((n), &(mask))
#define DEFINE_DMA_UNMAP_ADDR(ADDR_NAME)        dma_addr_t ADDR_NAME
#define DEFINE_DMA_UNMAP_LEN(LEN_NAME)          __u32 LEN_NAME
#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))

#define dma_map_sg_attrs(dev, sgl, nents, dir, attrs) \
	dma_map_sg(dev, sgl, nents, dir)
#define dma_map_single_attrs(dev, cpu_addr, size, dir, attrs) \
	dma_map_single(dev, cpu_addr, size, dir)
#define dma_unmap_addr(PTR, ADDR_NAME)           ((PTR)->ADDR_NAME)
#define dma_unmap_addr_set(PTR, ADDR_NAME, VAL)  (((PTR)->ADDR_NAME) = (VAL))
#define dma_unmap_len(PTR, LEN_NAME)             ((PTR)->LEN_NAME)
#define dma_unmap_len_set(PTR, LEN_NAME, VAL)    (((PTR)->LEN_NAME) = (VAL))
#define dma_unmap_sg_attrs(dev, sgl, nents, dir, attrs) \
	dma_unmap_sg(dev, sgl, nents, dir)
#define dma_unmap_single_attrs(dev, dma_addr, size, dir, attrs) \
	dma_unmap_single(dev, dma_addr, size, dir)

#define dma_alloc_noncoherent(d, s, h, f) dma_alloc_coherent(d, s, h, f)
#define dma_free_noncoherent(d, s, v, h) dma_free_coherent(d, s, v, h)
#define dma_sync_sg_for_device dma_sync_sg_for_cpu
#define dma_sync_single_for_device dma_sync_single_for_cpu
#define dma_sync_single_range_for_device dma_sync_single_range_for_cpu

#define for_each_sg(sglist, sg, nr, __i)	\
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))
#define sg_chain_ptr(sg)	\
	((struct scatterlist *) ((sg)->page_link & ~0x03))
#define sg_is_chain(sg)		((sg)->page_link & 0x01)
#define sg_is_last(sg)		((sg)->page_link & 0x02)
#define DEFINE_DMA_ATTRS(x) 					\
	struct dma_attrs x = {					\
		.flags = { [0 ... __DMA_ATTRS_LONGS-1] = 0 },	\
	}

#define __DMA_ATTRS_LONGS BITS_TO_LONGS(DMA_ATTR_MAX)

#define BUG() do {} while(0)
#define BUGFLAG_TAINT(taint)	(BUGFLAG_WARNING | ((taint) << 8))
#define BUG_GET_TAINT(bug)	((bug)->flags >> 8)
#define BUG_ON(condition) do { if (condition) ; } while(0)

#define WARN(condition, format...) ({					\
	int __ret_warn_on = !!(condition);				\
	unlikely(__ret_warn_on);					\
})
#define WARN_ON(condition) ({						\
	int __ret_warn_on = !!(condition);				\
	unlikely(__ret_warn_on);					\
})
#define WARN_ONCE(condition, format...)	({			\
	static bool __warned;					\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once))				\
		if (WARN(!__warned, format)) 			\
			__warned = true;			\
	unlikely(__ret_warn_once);				\
})
#define WARN_ON_ONCE(condition)	({				\
	static bool __warned;					\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once))				\
		if (WARN_ON(!__warned)) 			\
			__warned = true;			\
	unlikely(__ret_warn_once);				\
})
#define WARN_ON_RATELIMIT(condition, state)			\
		WARN_ON((condition) && __ratelimit(state))
# define WARN_ON_SMP(x)			WARN_ON(x)
#define WARN_TAINT(condition, taint, format...) ({			\
	int __ret_warn_on = !!(condition);				\
	if (unlikely(__ret_warn_on))					\
		__WARN_printf_taint(taint, format);			\
	unlikely(__ret_warn_on);					\
})
#define WARN_TAINT_ONCE(condition, taint, format...)	({	\
	static bool __warned;					\
	int __ret_warn_once = !!(condition);			\
								\
	if (unlikely(__ret_warn_once))				\
		if (WARN_TAINT(!__warned, taint, format))	\
			__warned = true;			\
	unlikely(__ret_warn_once);				\
})

#define __WARN()		warn_slowpath_null("__FILE__", "__LINE__")
#define __WARN_printf(arg...)	warn_slowpath_fmt("__FILE__", "__LINE__", arg)
#define __WARN_printf_taint(taint, arg...)				\
	warn_slowpath_fmt_taint("__FILE__", "__LINE__", taint, arg)
#define BUS_ATTR(_name, _mode, _show, _store)	\
struct bus_attribute bus_attr_##_name = __ATTR(_name, _mode, _show, _store)
#define CLASS_ATTR(_name, _mode, _show, _store)			\
struct class_attribute class_attr_##_name = __ATTR(_name, _mode, _show, _store)
#define CLASS_ATTR_STRING(_name, _mode, _str) \
	struct class_attribute_string class_attr_##_name = \
		_CLASS_ATTR_STRING(_name, _mode, _str)
#define DEVICE_ATTR(_name, _mode, _show, _store) \
struct device_attribute dev_attr_##_name = __ATTR(_name, _mode, _show, _store)
#define DRIVER_ATTR(_name, _mode, _show, _store)	\
struct driver_attribute driver_attr_##_name =		\
	__ATTR(_name, _mode, _show, _store)
#define MODULE_ALIAS_CHARDEV(major,minor) \
	MODULE_ALIAS("char-major-" __stringify(major) "-" __stringify(minor))
#define MODULE_ALIAS_CHARDEV_MAJOR(major) \
	MODULE_ALIAS("char-major-" __stringify(major) "-*")
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
	WARN(1, "Device: %s\n" format, dev_driver_string(dev), ## arg);
#define dev_alert(dev, format, arg...)		\
	dev_printk(KERN_ALERT , dev , format , ## arg)
#define dev_crit(dev, format, arg...)		\
	dev_printk(KERN_CRIT , dev , format , ## arg)
#define dev_dbg(dev, format, arg...)		\
	dev_printk(KERN_DEBUG , dev , format , ## arg)
#define dev_emerg(dev, format, arg...)		\
	dev_printk(KERN_EMERG , dev , format , ## arg)
#define dev_err(dev, format, arg...)		\
	dev_printk(KERN_ERR , dev , format , ## arg)
#define dev_info(dev, format, arg...)		\
	dev_printk(KERN_INFO , dev , format , ## arg)
#define dev_notice(dev, format, arg...)		\
	dev_printk(KERN_NOTICE , dev , format , ## arg)
#define dev_printk(level, dev, format, arg...)	\
	printk(level "%s %s: " format , dev_driver_string(dev) , \
	       dev_name(dev) , ## arg)
#define dev_vdbg(dev, format, arg...)		\
	({ if (0) dev_printk(KERN_DEBUG, dev, format, ##arg); 0; })
#define dev_warn(dev, format, arg...)		\
	dev_printk(KERN_WARNING , dev , format , ## arg)
#define device_schedule_callback(dev, func)			\
	device_schedule_callback_owner(dev, func, THIS_MODULE)
#define devres_alloc(release, size, gfp) \
	__devres_alloc(release, size, gfp, #release)

#define DEFINE_KLIST(_name, _get, _put)					\
	struct klist _name = KLIST_INIT(_name, _get, _put)
#define KLIST_INIT(_name, _get, _put)					\
	{ .k_lock	= __SPIN_LOCK_UNLOCKED(_name.k_lock),		\
	  .k_list	= LIST_HEAD_INIT(_name.k_list),			\
	  .get		= _get,						\
	  .put		= _put, }

#define IORESOURCE_IRQ_OPTIONAL 	(1<<5)

#define __request_mem_region(start,n,name, excl) __request_region(&iomem_resource, (start), (n), (name), excl)
#define check_mem_region(start,n)	__check_region(&iomem_resource, (start), (n))
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
#define TS_PRIV_ALIGN(len) (((len) + TS_PRIV_ALIGNTO-1) & ~(TS_PRIV_ALIGNTO-1))

#define DECLARE_SOCKADDR(type, dst, src)	\
	type dst = ({ __sockaddr_check_size(sizeof(*dst)); (type) src; })
#define MODULE_ALIAS_NETPROTO(proto) \
	MODULE_ALIAS("net-pf-" __stringify(proto))
#define MODULE_ALIAS_NET_PF_PROTO(pf, proto) \
	MODULE_ALIAS("net-pf-" __stringify(pf) "-proto-" __stringify(proto))
#define MODULE_ALIAS_NET_PF_PROTO_TYPE(pf, proto, type) \
	MODULE_ALIAS("net-pf-" __stringify(pf) "-proto-" __stringify(proto) \
		     "-type-" __stringify(type))
#define SOCK_MAX (SOCK_PACKET + 1)
#define SOCK_TYPE_MASK 0xf

#define net_random()		random32()
#define net_srandom(seed)	srandom32((__force u32)seed)
#define		     sockfd_put(sock) fput(sock->file)
#define DEFINE_RATELIMIT_STATE(name, interval_init, burst_init)		\
									\
	struct ratelimit_state name = {					\
		.lock		= __SPIN_LOCK_UNLOCKED(name.lock),	\
		.interval	= interval_init,			\
		.burst		= burst_init,				\
	}

#define __ratelimit(state) ___ratelimit(state, __func__)


# define for_each_irq_desc(irq, desc)		\
	for (irq = 0; irq < nr_irqs; irq++)
# define for_each_irq_desc_reverse(irq, desc)                          \
	for (irq = nr_irqs - 1; irq >= 0; irq--)
#define for_each_irq_nr(irq)                   \
       for (irq = 0; irq < nr_irqs; irq++)
#define irq_node(irq)	(irq_to_desc(irq)->node)
#define irq_to_desc(irq)	(&irq_desc[irq])
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
#define MSG_CMSG_CLOEXEC 0x40000000	
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
#define __sockaddr_check_size(size)	\
	BUILD_BUG_ON(((size) > sizeof(struct __kernel_sockaddr_storage)))
#define sockaddr_storage __kernel_sockaddr_storage
#define SIOCBONDCHANGEACTIVE   0x8995   
#define SIOCBONDINFOQUERY      0x8994	
#define SIOCBONDRELEASE 0x8991		
#define SIOCBONDSETHWADDR      0x8992	
#define SIOCBONDSLAVEINFOQUERY 0x8993   
#define SIOCBRADDBR     0x89a0		
#define SIOCBRDELBR     0x89a1		
#define SIOCPROTOPRIVATE 0x89E0 
#define SIOCSHWTSTAMP   0x89b0

#define ASSERT_RTNL() do { \
	if (unlikely(!rtnl_is_locked())) { \
		printk(KERN_ERR "RTNL: assertion failed at %s (%d)\n", \
		       "__FILE__",  "__LINE__"); \
		dump_stack(); \
	} \
} while(0)
#define RTAX_ADVMSS RTAX_ADVMSS
#define RTAX_CWND RTAX_CWND
#define RTAX_FEATURES RTAX_FEATURES
#define RTAX_HOPLIMIT RTAX_HOPLIMIT
#define RTAX_INITCWND RTAX_INITCWND
#define RTAX_INITRWND RTAX_INITRWND
#define RTAX_LOCK RTAX_LOCK
#define RTAX_MAX (__RTAX_MAX - 1)
#define RTAX_MTU RTAX_MTU
#define RTAX_REORDERING RTAX_REORDERING
#define RTAX_RTO_MIN RTAX_RTO_MIN
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
({	struct rtattr *__start = (struct rtattr *)skb_tail_pointer(skb); \
	RTA_PUT(skb, type, 0, NULL); \
	__start;  })
#define RTA_NEST_CANCEL(skb, start) \
({	if (start) \
		skb_trim(skb, (unsigned char *) (start) - (skb)->data); \
	-1; })
#define RTA_NEST_COMPAT(skb, type, attrlen, data) \
({	struct rtattr *__start = (struct rtattr *)skb_tail_pointer(skb); \
	RTA_PUT(skb, type, attrlen, data); \
	RTA_NEST(skb, type); \
	__start; })
#define RTA_NEST_COMPAT_END(skb, start) \
({	struct rtattr *__nest = (void *)(start) + NLMSG_ALIGN((start)->rta_len); \
	(start)->rta_len = skb_tail_pointer(skb) - (unsigned char *)(start); \
	RTA_NEST_END(skb, __nest); \
	(skb)->len; })
#define RTA_NEST_END(skb, start) \
({	(start)->rta_len = skb_tail_pointer(skb) - (unsigned char *)(start); \
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
	memset(skb_tail_pointer(skb) - (RTA_ALIGN(attrlen) - attrlen), 0, \
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
#define RTM_DELADDRLABEL RTM_DELADDRLABEL
#define RTM_FAM(cmd)	(((cmd) - RTM_BASE) >> 2)
#define RTM_GETACTION   RTM_GETACTION
#define RTM_GETADDRLABEL RTM_GETADDRLABEL
#define RTM_GETDCB RTM_GETDCB
#define RTM_GETMULTICAST RTM_GETMULTICAST
#define RTM_NEWACTION   RTM_NEWACTION
#define RTM_NEWADDRLABEL RTM_NEWADDRLABEL
#define RTM_NEWNDUSEROPT RTM_NEWNDUSEROPT
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
#define TCAA_MAX 1
#define TCA_ACT_TAB 1 	
#define TCA_MAX (__TCA_MAX - 1)
#define TCA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct tcmsg))
#define TCA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct tcmsg))))

#define __RTA_PUT(skb, attrtype, attrlen) \
({ 	if (unlikely(skb_tailroom(skb) < (int)RTA_SPACE(attrlen))) \
		goto rtattr_failure; \
   	__rta_reserve(skb, attrtype, attrlen); })
#define NDA_MAX (__NDA_MAX - 1)
#define NDTA_MAX (__NDTA_MAX - 1)
#define NDTPA_MAX (__NDTPA_MAX - 1)

#define IFA_MAX (__IFA_MAX - 1)
#define IFA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifaddrmsg))
#define IFA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifaddrmsg))))

#define IFLA_COST IFLA_COST
#define IFLA_LINKINFO IFLA_LINKINFO
#define IFLA_MACVLAN_MAX (__IFLA_MACVLAN_MAX - 1)
#define IFLA_MAP IFLA_MAP
#define IFLA_MASTER IFLA_MASTER
#define IFLA_MAX (__IFLA_MAX - 1)
#define IFLA_PAYLOAD(n) NLMSG_PAYLOAD(n,sizeof(struct ifinfomsg))
#define IFLA_PORT_MAX (__IFLA_PORT_MAX - 1)
#define IFLA_PRIORITY IFLA_PRIORITY
#define IFLA_PROTINFO IFLA_PROTINFO
#define IFLA_RTA(r)  ((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ifinfomsg))))
#define IFLA_TXQLEN IFLA_TXQLEN
#define IFLA_VF_INFO_MAX (__IFLA_VF_INFO_MAX - 1)
#define IFLA_VF_MAX (__IFLA_VF_MAX - 1)
#define IFLA_VF_PORT_MAX (__IFLA_VF_PORT_MAX - 1)
#define IFLA_WEIGHT IFLA_WEIGHT
#define IFLA_WIRELESS IFLA_WIRELESS

#define HARD_TX_LOCK(dev, txq, cpu) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_lock(txq, cpu);		\
	}						\
}
#define HARD_TX_UNLOCK(dev, txq) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_unlock(txq);			\
	}						\
}

#define HAVE_NETIF_MSG 1

#define HAVE_NETIF_RECEIVE_SKB 1
#define HAVE_NETIF_RX 1

#define HH_DATA_ALIGN(__len) \
	(((__len)+(HH_DATA_MOD-1))&~(HH_DATA_MOD - 1))
#define HH_DATA_OFF(__len) \
	(HH_DATA_MOD - (((__len - 1) & (HH_DATA_MOD - 1)) + 1))
#define LL_ALLOCATED_SPACE(dev) \
	((((dev)->hard_header_len+(dev)->needed_headroom+(dev)->needed_tailroom)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#  define LL_MAX_HEADER 128
#define LL_RESERVED_SPACE(dev) \
	((((dev)->hard_header_len+(dev)->needed_headroom)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) \
	((((dev)->hard_header_len+(dev)->needed_headroom+(extra))&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define MAX_HEADER LL_MAX_HEADER
#define NAPI_GRO_CB(skb) ((struct napi_gro_cb *)(skb)->cb)
#define NETDEV_BOOT_SETUP_MAX 8
#define NETDEV_FCOE_WWNN 0
#define NETDEV_FCOE_WWPN 1
#define RPS_DEV_FLOW_TABLE_SIZE(_num) (sizeof(struct rps_dev_flow_table) + \
    (_num * sizeof(struct rps_dev_flow)))
#define RPS_MAP_SIZE(_num) (sizeof(struct rps_map) + (_num * sizeof(u16)))
#define RPS_NO_CPU 0xffff
#define SET_ETHTOOL_OPS(netdev,ops) \
	( (netdev)->ethtool_ops = (ops) )
#define SET_NETDEV_DEV(net, pdev)	((net)->dev.parent = (pdev))
#define SET_NETDEV_DEVTYPE(net, devtype)	((net)->dev.type = (devtype))

#define alloc_netdev(sizeof_priv, name, setup) \
	alloc_netdev_mq(sizeof_priv, name, setup, 1)
#define for_each_dev_addr(dev, ha) \
		list_for_each_entry_rcu(ha, &dev->dev_addrs.list, list)
#define for_each_netdev(net, d)		\
		list_for_each_entry(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_continue(net, d)		\
		list_for_each_entry_continue(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_continue_rcu(net, d)		\
	list_for_each_entry_continue_rcu(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_rcu(net, d)		\
		list_for_each_entry_rcu(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_reverse(net, d)	\
		list_for_each_entry_reverse(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_safe(net, d, n)	\
		list_for_each_entry_safe(d, n, &(net)->dev_base_head, dev_list)
# define napi_synchronize(n)	barrier()
#define net_device_entry(lh)	list_entry(lh, struct net_device, dev_list)
#define net_xmit_errno(e)	((e) != NET_XMIT_CN ? -ENOBUFS : 0)
#define net_xmit_eval(e)	((e) == NET_XMIT_CN ? 0 : (e))
#define netdev_WARN(dev, format, args...)			\
	WARN(1, "netdevice: %s\n" format, netdev_name(dev), ##args);
#define netdev_alert(dev, format, args...)			\
	netdev_printk(KERN_ALERT, dev, format, ##args)
#define netdev_crit(dev, format, args...)			\
	netdev_printk(KERN_CRIT, dev, format, ##args)
#define netdev_dbg(__dev, format, args...)			\
	netdev_printk(KERN_DEBUG, __dev, format, ##args)
#define netdev_emerg(dev, format, args...)			\
	netdev_printk(KERN_EMERG, dev, format, ##args)
#define netdev_err(dev, format, args...)			\
	netdev_printk(KERN_ERR, dev, format, ##args)
#define netdev_for_each_mc_addr(ha, dev) \
	netdev_hw_addr_list_for_each(ha, &(dev)->mc)
#define netdev_for_each_uc_addr(ha, dev) \
	netdev_hw_addr_list_for_each(ha, &(dev)->uc)
#define netdev_hw_addr_list_count(l) ((l)->count)
#define netdev_hw_addr_list_empty(l) (netdev_hw_addr_list_count(l) == 0)
#define netdev_hw_addr_list_for_each(ha, l) \
	list_for_each_entry(ha, &(l)->list, list)
#define netdev_info(dev, format, args...)			\
	netdev_printk(KERN_INFO, dev, format, ##args)
#define netdev_mc_count(dev) netdev_hw_addr_list_count(&(dev)->mc)
#define netdev_mc_empty(dev) netdev_hw_addr_list_empty(&(dev)->mc)
#define netdev_notice(dev, format, args...)			\
	netdev_printk(KERN_NOTICE, dev, format, ##args)
#define netdev_printk(level, netdev, format, args...)		\
	dev_printk(level, (netdev)->dev.parent,			\
		   "%s: " format,				\
		   netdev_name(netdev), ##args)
#define netdev_uc_count(dev) netdev_hw_addr_list_count(&(dev)->uc)
#define netdev_uc_empty(dev) netdev_hw_addr_list_empty(&(dev)->uc)
#define netdev_vdbg(dev, format, args...)			\
({								\
	if (0)							\
		netdev_printk(KERN_DEBUG, dev, format, ##args);	\
	0;							\
})
#define netdev_warn(dev, format, args...)			\
	netdev_printk(KERN_WARNING, dev, format, ##args)
#define netif_alert(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_ALERT, dev, fmt, ##args)
#define netif_crit(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_CRIT, dev, fmt, ##args)
#define netif_dbg(priv, type, dev, format, args...)		\
	netif_printk(priv, type, KERN_DEBUG, dev, format, ##args)
#define netif_emerg(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_EMERG, dev, fmt, ##args)
#define netif_err(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_ERR, dev, fmt, ##args)
#define netif_info(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_INFO, (dev), fmt, ##args)
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
	netif_printk(priv, type, KERN_NOTICE, dev, fmt, ##args)
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
	netif_printk(priv, type, KERN_WARNING, dev, fmt, ##args)
#define to_net_dev(d) container_of(d, struct net_device, dev)
#define DECLARE_TASKLET(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(0), func, data }
#define DECLARE_TASKLET_DISABLED(name, func, data) \
struct tasklet_struct name = { NULL, 0, ATOMIC_INIT(1), func, data }

#define __raise_softirq_irqoff(nr) do { or_softirq_pending(1UL << (nr)); } while (0)
#  define disable_irq_lockdep(irq)		disable_irq(irq)
#  define disable_irq_nosync_lockdep(irq)	disable_irq_nosync(irq)
#  define disable_irq_nosync_lockdep_irqsave(irq, flags) \
						disable_irq_nosync(irq)
#  define enable_irq_lockdep(irq)		enable_irq(irq)
#  define enable_irq_lockdep_irqrestore(irq, flags) \
						enable_irq(irq)
#define hard_irq_disable()	do { } while(0)
# define local_irq_enable_in_hardirq()	do { } while (0)
#define or_softirq_pending(x)  (local_softirq_pending() |= (x))
#define set_softirq_pending(x) (local_softirq_pending() = (x))
#define tasklet_trylock(t) 1
#define tasklet_unlock(t) do { } while (0)
#define tasklet_unlock_wait(t) do { } while (0)
# define INIT_TRACE_IRQFLAGS

#define irqs_disabled()						\
({								\
	unsigned long _flags;					\
								\
	raw_local_save_flags(_flags);				\
	raw_irqs_disabled_flags(_flags);			\
})
#define irqs_disabled_flags(flags)		\
({						\
	typecheck(unsigned long, flags);	\
	raw_irqs_disabled_flags(flags);		\
})
#define local_irq_disable() \
	do { raw_local_irq_disable(); trace_hardirqs_off(); } while (0)
#define local_irq_enable() \
	do { trace_hardirqs_on(); raw_local_irq_enable(); } while (0)
#define local_irq_restore(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
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
		typecheck(unsigned long, flags);	\
		raw_local_irq_save(flags);		\
		trace_hardirqs_off();			\
	} while (0)
#define local_save_flags(flags)				\
	do {						\
		typecheck(unsigned long, flags);	\
		raw_local_save_flags(flags);		\
	} while (0)
# define lockdep_softirq_enter()	do { current->softirq_context++; } while (0)
# define lockdep_softirq_exit()	do { current->softirq_context--; } while (0)
# define raw_local_irq_disable()	local_irq_disable()
# define raw_local_irq_enable()		local_irq_enable()
# define raw_local_irq_restore(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		local_irq_restore(flags);		\
	} while (0)
# define raw_local_irq_save(flags)			\
	do {						\
		typecheck(unsigned long, flags);	\
		local_irq_save(flags);			\
	} while (0)
#define safe_halt()						\
	do {							\
		trace_hardirqs_on();				\
		raw_safe_halt();				\
	} while (0)
# define start_critical_timings() do { } while (0)
# define stop_critical_timings() do { } while (0)
# define trace_hardirq_context(p)	((p)->hardirq_context)
# define trace_hardirq_enter()	do { current->hardirq_context++; } while (0)
# define trace_hardirq_exit()	do { current->hardirq_context--; } while (0)
# define trace_hardirqs_enabled(p)	((p)->hardirqs_enabled)
# define trace_hardirqs_off()		do { } while (0)
# define trace_hardirqs_on()		do { } while (0)
# define trace_softirq_context(p)	((p)->softirq_context)
# define trace_softirqs_enabled(p)	((p)->softirqs_enabled)
# define trace_softirqs_off(ip)		do { } while (0)
# define trace_softirqs_on(ip)		do { } while (0)
#define IRQ_RETVAL(x)	((x) != IRQ_NONE)



#define NETDEV_HASHBITS    8
#define NETDEV_HASHENTRIES (1 << NETDEV_HASHBITS)




#define for_each_net(VAR)				\
	list_for_each_entry(VAR, &net_namespace_list, list)
#define for_each_net_rcu(VAR)				\
	list_for_each_entry_rcu(VAR, &net_namespace_list, list)
#define read_pnet(pnet)		(&init_net)
#define write_pnet(pnet, net)	do { (void)(net);} while (0)



#define XFRMA_MAX (__XFRMA_MAX - 1)
#define XFRMA_SAD_MAX (__XFRMA_SAD_MAX - 1)
#define XFRMA_SPD_MAX (__XFRMA_SPD_MAX - 1)
#define XFRM_AE_MAX (__XFRM_AE_MAX - 1)
#define XFRM_INF (~(__u64)0)
#define XFRM_MODE_BEET 4
#define XFRM_MODE_IN_TRIGGER 3
#define XFRM_MODE_MAX 5
#define XFRM_MODE_ROUTEOPTIMIZATION 2
#define XFRM_MODE_TRANSPORT 0
#define XFRM_MODE_TUNNEL 1
#define XFRM_MSG_ACQUIRE XFRM_MSG_ACQUIRE
#define XFRM_MSG_ALLOCSPI XFRM_MSG_ALLOCSPI
#define XFRM_MSG_DELPOLICY XFRM_MSG_DELPOLICY
#define XFRM_MSG_DELSA XFRM_MSG_DELSA
#define XFRM_MSG_EXPIRE XFRM_MSG_EXPIRE
#define XFRM_MSG_FLUSHPOLICY XFRM_MSG_FLUSHPOLICY
#define XFRM_MSG_FLUSHSA XFRM_MSG_FLUSHSA
#define XFRM_MSG_GETAE XFRM_MSG_GETAE
#define XFRM_MSG_GETPOLICY XFRM_MSG_GETPOLICY
#define XFRM_MSG_GETSA XFRM_MSG_GETSA
#define XFRM_MSG_GETSADINFO XFRM_MSG_GETSADINFO
#define XFRM_MSG_GETSPDINFO XFRM_MSG_GETSPDINFO
#define XFRM_MSG_MAPPING XFRM_MSG_MAPPING
#define XFRM_MSG_MAX (__XFRM_MSG_MAX - 1)
#define XFRM_MSG_MIGRATE XFRM_MSG_MIGRATE
#define XFRM_MSG_NEWAE XFRM_MSG_NEWAE
#define XFRM_MSG_NEWPOLICY XFRM_MSG_NEWPOLICY
#define XFRM_MSG_NEWSA XFRM_MSG_NEWSA
#define XFRM_MSG_NEWSADINFO XFRM_MSG_NEWSADINFO
#define XFRM_MSG_NEWSPDINFO XFRM_MSG_NEWSPDINFO
#define XFRM_MSG_POLEXPIRE XFRM_MSG_POLEXPIRE
#define XFRM_MSG_REPORT XFRM_MSG_REPORT
#define XFRM_MSG_UPDPOLICY XFRM_MSG_UPDPOLICY
#define XFRM_MSG_UPDSA XFRM_MSG_UPDSA
#define XFRM_NR_MSGTYPES (XFRM_MSG_MAX + 1 - XFRM_MSG_BASE)
#define XFRM_SC_ALG_RESERVED 0
#define XFRM_SC_ALG_SELINUX 1
#define XFRM_SC_DOI_LSM 1
#define XFRM_SC_DOI_RESERVED 0


#define INIT_HLIST_NULLS_HEAD(ptr, nulls) \
	((ptr)->first = (struct hlist_nulls_node *) (1UL | (((long)nulls) << 1)))

#define hlist_nulls_entry(ptr, type, member) container_of(ptr,type,member)
#define hlist_nulls_for_each_entry(tpos, pos, head, member)		       \
	for (pos = (head)->first;					       \
	     (!is_a_nulls(pos)) &&					       \
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)
#define hlist_nulls_for_each_entry_from(tpos, pos, member)	\
	for (; (!is_a_nulls(pos)) && 				\
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = pos->next)

#define NFC_ALTERED 0x8000
#define NFC_UNKNOWN 0x4000
#define NF_ACCEPT 1
#define NF_DROP 0
#define NF_HOOK(pf, hook, skb, indev, outdev, okfn) (okfn)(skb)
#define NF_HOOK_COND(pf, hook, skb, indev, outdev, okfn, cond) (okfn)(skb)
#define NF_MAX_HOOKS 8
#define NF_MAX_VERDICT NF_STOP
#define NF_QUEUE 3
#define NF_QUEUE_NR(x) ((((x) << NF_VERDICT_BITS) & NF_VERDICT_QMASK) | NF_QUEUE)
#define NF_REPEAT 4
#define NF_STOLEN 2
#define NF_STOP 5
#define NF_VERDICT_BITS 16
#define NF_VERDICT_MASK 0x0000ffff
#define NF_VERDICT_QBITS 16
#define NF_VERDICT_QMASK 0xffff0000

#define FIRST_PROCESS_ENTRY 256
#define PROC_NUMBUF 13

#define proc_net_fops_create(net, name, mode, fops)  ({ (void)(mode), NULL; })
#define remove_proc_entry(name, parent) do {} while (0)
#define AFS_SUPER_MAGIC                0x5346414F
#define DEBUGFS_MAGIC          0x64626720
#define HUGETLBFS_MAGIC 	0x958458f6	

#define FLOWI_FLAG_ANYSRC 0x01

#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
		{ { { 0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }
#define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }

#define GROUP_FILTER_SIZE(numsrc) \
	(sizeof(struct group_filter) - sizeof(struct __kernel_sockaddr_storage) \
	+ (numsrc) * sizeof(struct __kernel_sockaddr_storage))
#define INADDR_ALLHOSTS_GROUP 	0xe0000001U	
#define INADDR_ALLRTRS_GROUP    0xe0000002U	
#define INADDR_MAX_LOCAL_GROUP  0xe00000ffU	
#define INADDR_UNSPEC_GROUP   	0xe0000000U	
#define IP_DEFAULT_MULTICAST_LOOP       1
#define IP_DEFAULT_MULTICAST_TTL        1
#define IP_MINTTL       21
#define IP_MSFILTER_SIZE(numsrc) \
	(sizeof(struct ip_msfilter) - sizeof(__u32) \
	+ (numsrc) * sizeof(__u32))
#define IP_MULTICAST_LOOP 		34
#define IP_MULTICAST_TTL 		33
#define IP_ORIGDSTADDR       20
#define IP_RECVORIGDSTADDR   IP_ORIGDSTADDR

#define IFF_802_1Q_VLAN 0x1             
#define IFF_DONT_BRIDGE 0x800		
#define IFF_MASTER_ARPMON 0x100		
#define IFF_SLAVE_NEEDARP 0x40		
#define IFF_XMIT_DST_RELEASE 0x400	
#define IF_IFACE_SYNC_SERIAL 0x1005	
#define IF_IFACE_X21D   0x1006          
#define IF_PROTO_FR_ADD_ETH_PVC 0x2008	
#define IF_PROTO_FR_ADD_PVC 0x2004	
#define IF_PROTO_FR_DEL_ETH_PVC 0x2009	
#define IF_PROTO_FR_DEL_PVC 0x2005	
#define IF_PROTO_FR_ETH_PVC 0x200B
#define IF_PROTO_HDLC_ETH 0x2007	
#define IF_PROTO_RAW    0x200C          

#define CLOCK_DEFAULT   0	
#define GENERIC_HDLC_VERSION 4	








#define DECLARE_SNMP_STAT(type, name)	\
	extern __typeof__(type) __percpu *name[2]
#define DEFINE_SNMP_STAT(type, name)	\
	__typeof__(type) __percpu *name[2]
#define ICMP6MSG_MIB_MAX  __ICMP6MSG_MIB_MAX
#define SNMP_ADD_STATS(mib, field, addend)	\
			this_cpu_add(mib[!in_softirq()]->mibs[field], addend)
#define SNMP_ADD_STATS_BH(mib, field, addend)	\
			__this_cpu_add(mib[0]->mibs[field], addend)
#define SNMP_ADD_STATS_USER(mib, field, addend)	\
			this_cpu_add(mib[1]->mibs[field], addend)
#define SNMP_DEC_STATS(mib, field)	\
			this_cpu_dec(mib[!in_softirq()]->mibs[field])
#define SNMP_INC_STATS(mib, field)	\
			this_cpu_inc(mib[!in_softirq()]->mibs[field])
#define SNMP_INC_STATS_BH(mib, field)	\
			__this_cpu_inc(mib[0]->mibs[field])
#define SNMP_INC_STATS_USER(mib, field)	\
			this_cpu_inc(mib[1]->mibs[field])
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
#define SNMP_UPD_PO_STATS(mib, basefield, addend)	\
	do { \
		__typeof__(*mib[0]) *ptr; \
		preempt_disable(); \
		ptr = this_cpu_ptr((mib)[!in_softirq()]); \
		ptr->mibs[basefield##PKTS]++; \
		ptr->mibs[basefield##OCTETS] += addend;\
		preempt_enable(); \
	} while (0)
#define SNMP_UPD_PO_STATS_BH(mib, basefield, addend)	\
	do { \
		__typeof__(*mib[0]) *ptr = \
			__this_cpu_ptr((mib)[!in_softirq()]); \
		ptr->mibs[basefield##PKTS]++; \
		ptr->mibs[basefield##OCTETS] += addend;\
	} while (0)


#define __ICMP6MSG_MIB_MAX 512 
#define __ICMPMSG_MIB_MAX 512	

#define ETHTOOL_MAX_NTUPLE_LIST_ENTRY 1024
#define ETHTOOL_MAX_NTUPLE_STRING_PER_ENTRY 14
#define ETHTOOL_RXNTUPLE_ACTION_DROP -1


#define mdelay(n) (\
	(__builtin_constant_p(n) && (n)<=MAX_UDELAY_MS) ? udelay((n)*1000) : \
	({unsigned long __ms=(n); while (__ms--) udelay(1000);}))
#define ndelay(x) ndelay(x)
#define PM_QOS_CPU_DMA_LATENCY 1
#define PM_QOS_DEFAULT_VALUE -1
#define PM_QOS_NETWORK_LATENCY 2
#define PM_QOS_NETWORK_THROUGHPUT 3
#define PM_QOS_NUM_CLASSES 4
#define PM_QOS_RESERVED 0
#define MODULE_ALIAS_MISCDEV(minor)				\
	MODULE_ALIAS("char-major-" __stringify(MISC_MAJOR)	\
	"-" __stringify(minor))

#define COMPAQ_CISS_MAJOR2      106
#define COMPAQ_CISS_MAJOR3      107
#define COMPAQ_CISS_MAJOR4      108
#define COMPAQ_CISS_MAJOR5      109
#define COMPAQ_CISS_MAJOR6      110
#define COMPAQ_CISS_MAJOR7      111
#define SCSI_CHANGER_MAJOR      86

#define TPACKET_ALIGN(x)	(((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))

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
#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#define DEFAULT_POLLMASK (POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM)
#define FDS_BYTES(nr)	(FDS_LONGS(nr)*sizeof(long))
#define FDS_LONGS(nr)	(((nr)+FDS_BITPERLONG-1)/FDS_BITPERLONG)
#define MAX_INT64_SECONDS (((s64)(~((u64)0)>>1)/HZ)-1)
#define MAX_STACK_ALLOC 832


#define hlist_nulls_for_each_entry_rcu(tpos, pos, head, member) \
	for (pos = rcu_dereference_raw((head)->first);			 \
		(!is_a_nulls(pos)) &&			\
		({ tpos = hlist_nulls_entry(pos, typeof(*tpos), member); 1; }); \
		pos = rcu_dereference_raw(pos->next))
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
#define SKF_AD_MARK 	20
#define SKF_AD_OFF    (-0x1000)
#define SKF_AD_PKTTYPE 	4
#define SKF_AD_PROTOCOL 0
#define SKF_LL_OFF    (-0x200000)
#define SKF_NET_OFF   (-0x100000)

#define SECURITY_CAP_AUDIT 1
#define SECURITY_CAP_NOAUDIT 0

#define MSGMAP  MSGMNB            
#define MSGMAX  8192      
#define MSGMNB 16384      
#define MSGMNI    16        
#define MSGPOOL (MSGMNI * MSGMNB / 1024) 
#define MSGSEG (__MSGSEG <= 0xffff ? __MSGSEG : 0xffff)
#define MSGSSZ  16                
#define MSGTQL  MSGMNB            
#define MSG_EXCEPT      020000  
#define MSG_INFO 12
#define MSG_MEM_SCALE 32
#define MSG_NOERROR     010000  
#define MSG_STAT 11

#define __MSGSEG ((MSGPOOL * 1024) / MSGSSZ) 
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
#define BINPRM_MAX_RECURSION 4
#define CORENAME_MAX_SIZE 128
#define EXSTACK_DEFAULT   0	
#define EXSTACK_DISABLE_X 1	
#define EXSTACK_ENABLE_X  2	
#define MAX_ARG_STRINGS 0x7FFFFFFF
#define MAX_ARG_STRLEN (PAGE_SIZE * 32)

#define DEFSECDESCLEN 192 
#define EXEC_BIT        0x1
#define NUM_AUTHS 6 
#define NUM_SUBAUTHS 5 
#define NUM_WK_SIDS 7 
#define READ_BIT        0x4
#define SIDNAMELENGTH 20 
#define WRITE_BIT       0x2

#define CIFS_MOUNT_CIFS_ACL     0x200 
#define CIFS_MOUNT_DIRECT_IO    8 
#define CIFS_MOUNT_DYNPERM      0x1000 
#define CIFS_MOUNT_MAP_SPECIAL_CHR 0x20 
#define CIFS_MOUNT_NOPOSIXBRL   0x2000 
#define CIFS_MOUNT_NOSSYNC      0x4000 
#define CIFS_MOUNT_NO_BRL       0x100 
#define CIFS_MOUNT_NO_PERM      1 
#define CIFS_MOUNT_NO_XATTR     0x10  
#define CIFS_MOUNT_OVERR_GID    0x800 
#define CIFS_MOUNT_OVERR_UID    0x400 
#define CIFS_MOUNT_POSIX_PATHS  0x40  
#define CIFS_MOUNT_SERVER_INUM  4 
#define CIFS_MOUNT_SET_UID      2 
#define CIFS_MOUNT_UNX_EMUL     0x80  

#define BDI_CAP_NO_ACCT_AND_WRITEBACK \
	(BDI_CAP_NO_WRITEBACK | BDI_CAP_NO_ACCT_DIRTY | BDI_CAP_NO_ACCT_WB)
#define BDI_CAP_VMFLAGS \
	(BDI_CAP_READ_MAP | BDI_CAP_WRITE_MAP | BDI_CAP_EXEC_MAP)
#define BDI_STAT_BATCH (8*(1+ilog2(nr_cpu_ids)))







