#include<libintl.h>
#include<strings.h>

#include<locale.h>
#include<stddef.h>

#include<time.h>



#include<stdint.h>
#include<signal.h>
#include<stdio.h>
#include<stdarg.h>
#include<sys/time.h>
#include<netdb.h>

#include<limits.h>


#include<sys/stat.h>
#include<stdbool.h>
#include<fcntl.h>
#include<sys/types.h>

#include<assert.h>


#include<arpa/inet.h>
#include<pwd.h>


#include<ctype.h>
#include<errno.h>
#include<netinet/in.h>
#include<unistd.h>
#include<math.h>

#include<stdlib.h>
#include<setjmp.h>
#include<string.h>




#define CROSSTABVIEW_MAX_COLUMNS 1600




#define DEFAULT_PAGER "more"

#define DEFAULT_EDITOR_LINENUMBER_ARG "+"
#define DEFAULT_FIELD_SEP "|"
#define DEFAULT_PROMPT1 "%/%R%# "
#define DEFAULT_PROMPT2 "%/%R%# "
#define DEFAULT_PROMPT3 ">> "
#define DEFAULT_RECORD_SEP "\n"
#define EXIT_BADCONN 2
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
#define EXIT_USER 3


#define INSTR_TIME_ACCUM_DIFF(x,y,z) \
	do { \
		(x).tv_sec += (y).tv_sec - (z).tv_sec; \
		(x).tv_nsec += (y).tv_nsec - (z).tv_nsec; \
		 \
		while ((x).tv_nsec < 0) \
		{ \
			(x).tv_nsec += 1000000000; \
			(x).tv_sec--; \
		} \
		while ((x).tv_nsec >= 1000000000) \
		{ \
			(x).tv_nsec -= 1000000000; \
			(x).tv_sec++; \
		} \
	} while (0)
#define INSTR_TIME_ADD(x,y) \
	do { \
		(x).tv_sec += (y).tv_sec; \
		(x).tv_usec += (y).tv_usec; \
		 \
		while ((x).tv_usec >= 1000000) \
		{ \
			(x).tv_usec -= 1000000; \
			(x).tv_sec++; \
		} \
	} while (0)
#define INSTR_TIME_GET_DOUBLE(t) \
	(((double) (t).tv_sec) + ((double) (t).tv_nsec) / 1000000000.0)
#define INSTR_TIME_GET_MICROSEC(t) \
	(((uint64) (t).tv_sec * (uint64) 1000000) + (uint64) ((t).tv_nsec / 1000))
#define INSTR_TIME_GET_MILLISEC(t) \
	(((double) (t).tv_sec * 1000.0) + ((double) (t).tv_nsec) / 1000000.0)

#define INSTR_TIME_IS_ZERO(t)	((t).tv_usec == 0 && (t).tv_sec == 0)
#define INSTR_TIME_SET_CURRENT(t)	gettimeofday(&(t), NULL)
#define INSTR_TIME_SET_ZERO(t)	((t).tv_sec = 0, (t).tv_usec = 0)
#define INSTR_TIME_SUBTRACT(x,y) \
	do { \
		(x).tv_sec -= (y).tv_sec; \
		(x).tv_nsec -= (y).tv_nsec; \
		 \
		while ((x).tv_nsec < 0) \
		{ \
			(x).tv_nsec += 1000000000; \
			(x).tv_sec--; \
		} \
	} while (0)


#define FRONTEND 1


#define Abs(x)			((x) >= 0 ? (x) : -(x))
#define Assert(condition)	((void)true)
#define AssertArg(condition)	((void)true)
#define AssertMacro(condition)	((void)true)
#define AssertPointerAlignment(ptr, bndr)	((void)true)
#define AssertState(condition)	((void)true)
#define AssertVariableIsOfType(varname, typename) \
	StaticAssertStmt(__builtin_types_compatible_p(__typeof__(varname), typename), \
	CppAsString(varname) " does not have type " CppAsString(typename))
#define AssertVariableIsOfTypeMacro(varname, typename) \
	(StaticAssertExpr(__builtin_types_compatible_p(__typeof__(varname), typename), \
	 CppAsString(varname) " does not have type " CppAsString(typename)))
#define BUFFERALIGN(LEN)		TYPEALIGN(ALIGNOF_BUFFER, (LEN))
#define BUFFERALIGN_DOWN(LEN)	TYPEALIGN_DOWN(ALIGNOF_BUFFER, (LEN))
#define BoolIsValid(boolean)	((boolean) == false || (boolean) == true)
#define CACHELINEALIGN(LEN)		TYPEALIGN(PG_CACHE_LINE_SIZE, (LEN))

#define CppAsString(identifier) #identifier
#define CppAsString2(x)			CppAsString(x)
#define CppConcat(x, y)			x##y
#define DOUBLEALIGN(LEN)		TYPEALIGN(ALIGNOF_DOUBLE, (LEN))
#define DOUBLEALIGN_DOWN(LEN)	TYPEALIGN_DOWN(ALIGNOF_DOUBLE, (LEN))
#define HAVE_INT128 1

#define HAVE_PG_ATTRIBUTE_NORETURN 1
#define HAVE_STRTOLL 1
#define HAVE_STRTOULL 1
#define INT64CONST(x)  (x##L)
#define INT64_FORMAT "%" INT64_MODIFIER "d"
#define INTALIGN(LEN)			TYPEALIGN(ALIGNOF_INT, (LEN))
#define INTALIGN_DOWN(LEN)		TYPEALIGN_DOWN(ALIGNOF_INT, (LEN))
#define INVERT_COMPARE_RESULT(var) \
	((var) = ((var) < 0) ? 1 : -(var))
#define IS_HIGHBIT_SET(ch)		((unsigned char)(ch) & HIGHBIT)
#define LONGALIGN(LEN)			TYPEALIGN(ALIGNOF_LONG, (LEN))
#define LONGALIGN_DOWN(LEN)		TYPEALIGN_DOWN(ALIGNOF_LONG, (LEN))
#define LONG_ALIGN_MASK (sizeof(long) - 1)
#define MAXALIGN(LEN)			TYPEALIGN(MAXIMUM_ALIGNOF, (LEN))
#define MAXALIGN64(LEN)			TYPEALIGN64(MAXIMUM_ALIGNOF, (LEN))
#define MAXALIGN_DOWN(LEN)		TYPEALIGN_DOWN(MAXIMUM_ALIGNOF, (LEN))
#define MAXDIM 6
#define Max(x, y)		((x) > (y) ? (x) : (y))
#define MemSet(start, val, len) \
	do \
	{ \
		 \
		void   *_vstart = (void *) (start); \
		int		_val = (val); \
		Size	_len = (len); \
\
		if ((((uintptr_t) _vstart) & LONG_ALIGN_MASK) == 0 && \
			(_len & LONG_ALIGN_MASK) == 0 && \
			_val == 0 && \
			_len <= MEMSET_LOOP_LIMIT && \
			 \
			MEMSET_LOOP_LIMIT != 0) \
		{ \
			long *_start = (long *) _vstart; \
			long *_stop = (long *) ((char *) _start + _len); \
			while (_start < _stop) \
				*_start++ = 0; \
		} \
		else \
			memset(_vstart, _val, _len); \
	} while (0)
#define MemSetAligned(start, val, len) \
	do \
	{ \
		long   *_start = (long *) (start); \
		int		_val = (val); \
		Size	_len = (len); \
\
		if ((_len & LONG_ALIGN_MASK) == 0 && \
			_val == 0 && \
			_len <= MEMSET_LOOP_LIMIT && \
			MEMSET_LOOP_LIMIT != 0) \
		{ \
			long *_stop = (long *) ((char *) _start + _len); \
			while (_start < _stop) \
				*_start++ = 0; \
		} \
		else \
			memset(_start, _val, _len); \
	} while (0)
#define MemSetLoop(start, val, len) \
	do \
	{ \
		long * _start = (long *) (start); \
		long * _stop = (long *) ((char *) _start + (Size) (len)); \
	\
		while (_start < _stop) \
			*_start++ = 0; \
	} while (0)
#define MemSetTest(val, len) \
	( ((len) & LONG_ALIGN_MASK) == 0 && \
	(len) <= MEMSET_LOOP_LIMIT && \
	MEMSET_LOOP_LIMIT != 0 && \
	(val) == 0 )
#define Min(x, y)		((x) < (y) ? (x) : (y))
#define NON_EXEC_STATIC static
#define NameStr(name)	((name).data)
#define OffsetToPointer(base, offset) \
		((void *)((char *) base + offset))
#define OidIsValid(objectId)  ((bool) ((objectId) != InvalidOid))


#define PG_BINARY_A "ab"
#define PG_BINARY_R "rb"
#define PG_BINARY_W "wb"
#define PG_TEXTDOMAIN(domain) (domain CppAsString2(SO_MAJOR_VERSION) "-" PG_MAJORVERSION)
#define PG_USED_FOR_ASSERTS_ONLY pg_attribute_unused()
#define PointerIsAligned(pointer, type) \
		(((uintptr_t)(pointer) % (sizeof (type))) == 0)
#define PointerIsValid(pointer) ((const void*)(pointer) != NULL)
#define RegProcedureIsValid(p)	OidIsValid(p)
#define SHORTALIGN(LEN)			TYPEALIGN(ALIGNOF_SHORT, (LEN))
#define SHORTALIGN_DOWN(LEN)	TYPEALIGN_DOWN(ALIGNOF_SHORT, (LEN))
#define SIGNAL_ARGS  int postgres_signal_arg
#define SIZE_MAX PG_UINT64_MAX
#define SQL_STR_DOUBLE(ch, escape_backslash)	\
	((ch) == '\'' || ((ch) == '\\' && (escape_backslash)))
#define StaticAssertExpr(condition, errmessage) \
	((void) ({ StaticAssertStmt(condition, errmessage); true; }))
#define StaticAssertStmt(condition, errmessage) \
	do { _Static_assert(condition, errmessage); } while(0)
#define StrNCpy(dst,src,len) \
	do \
	{ \
		char * _dst = (dst); \
		Size _len = (len); \
\
		if (_len > 0) \
		{ \
			strncpy(_dst, (src), _len); \
			_dst[_len-1] = '\0'; \
		} \
	} while (0)
#define TYPEALIGN(ALIGNVAL,LEN)  \
	(((uintptr_t) (LEN) + ((ALIGNVAL) - 1)) & ~((uintptr_t) ((ALIGNVAL) - 1)))
#define TYPEALIGN64(ALIGNVAL,LEN)  \
	(((uint64) (LEN) + ((ALIGNVAL) - 1)) & ~((uint64) ((ALIGNVAL) - 1)))
#define TYPEALIGN_DOWN(ALIGNVAL,LEN)  \
	(((uintptr_t) (LEN)) & ~((uintptr_t) ((ALIGNVAL) - 1)))
#define Trap(condition, errorType)	((void)true)
#define TrapMacro(condition, errorType) (true)
#define UINT64CONST(x) (x##UL)
#define UINT64_FORMAT "%" INT64_MODIFIER "u"
#define USE_STDBOOL 1
#define _(x) gettext(x)
#define dgettext(d,x) (x)
#define dngettext(d,s,p,n) ((n) == 1 ? (s) : (p))
#define gettext(x) (x)
#define gettext_noop(x) (x)

#define lengthof(array) (sizeof (array) / sizeof ((array)[0]))
#define likely(x)	__builtin_expect((x) != 0, 1)
#define memmove(d, s, c)		bcopy(s, d, c)
#define ngettext(s,p,n) ((n) == 1 ? (s) : (p))
#define offsetof(type, field)	((long) &((type *)0)->field)
#define pg_attribute_aligned(a) __attribute__((aligned(a)))
#define pg_attribute_always_inline __attribute__((always_inline)) inline
#define pg_attribute_format_arg(a) __attribute__((format_arg(a)))
#define pg_attribute_no_sanitize_alignment() __attribute__((no_sanitize("alignment")))
#define pg_attribute_noreturn() __attribute__((noreturn))
#define pg_attribute_packed() __attribute__((packed))
#define pg_attribute_printf(f,a) __attribute__((format(PG_PRINTF_ATTRIBUTE, f, a)))
#define pg_attribute_unused() __attribute__((unused))
#define pg_noinline __attribute__((noinline))
#define pg_unreachable() __builtin_unreachable()
#define sigjmp_buf jmp_buf
#define siglongjmp longjmp
#define sigsetjmp(x,y) setjmp(x)
#define strtoll __strtoll
#define strtoull __strtoull

#define unconstify(underlying_type, expr) \
	(StaticAssertExpr(__builtin_types_compatible_p(__typeof(expr), const underlying_type), \
					  "wrong cast"), \
	 (underlying_type) (expr))
#define unlikely(x) __builtin_expect((x) != 0, 0)
#define unvolatize(underlying_type, expr) \
	(StaticAssertExpr(__builtin_types_compatible_p(__typeof(expr), volatile underlying_type), \
					  "wrong cast"), \
	 (underlying_type) (expr))
#define DEVNULL "nul"
#define EXE ".exe"
#define IS_DIR_SEP(ch)	((ch) == '/')
#define PGINVALID_SOCKET (-1)
#define PG_BACKEND_VERSIONSTR "postgres (PostgreSQL) " PG_VERSION "\n"

#define SSL_get_current_compression(x) 0
#define TIMEZONE_GLOBAL _timezone
#define TZNAME_GLOBAL _tzname
#define closesocket close
#define		fopen(a,b) pgwin32_fopen(a,b)
#define fprintf(...)	pg_fprintf(__VA_ARGS__)
#define fseeko(a, b, c) fseek(a, b, c)
#define ftello(a)		ftell(a)
#define is_absolute_path(filename) \
( \
	IS_DIR_SEP((filename)[0]) \
)
#define isinf __builtin_isinf
#define		open(a,b,c) pgwin32_open(a,b,c)
#define pclose(a) _pclose(a)
#define pgoff_t off_t
#define popen(a,b) pgwin32_popen(a,b)
#define pqsignal_no_restart(signo, func) pqsignal(signo, func)
#define printf(...)		pg_printf(__VA_ARGS__)
#define qsort(a,b,c,d) pg_qsort(a,b,c,d)
#define readlink(path, buf, size)	pgreadlink(path, buf, size)
#define rename(from, to)		pgrename(from, to)
#define snprintf(...)	pg_snprintf(__VA_ARGS__)
#define sprintf(...)	pg_sprintf(__VA_ARGS__)
#define symlink(oldpath, newpath)	pgsymlink(oldpath, newpath)
#define system(a) pgwin32_system(a)
#define unlink(path)			pgunlink(path)
#define vfprintf(...)	pg_vfprintf(__VA_ARGS__)
#define vsnprintf(...)	pg_vsnprintf(__VA_ARGS__)
#define DLSUFFIX ".dll"
#define EACCESS 2048
#define EADDRINUSE WSAEADDRINUSE
#define EADDRNOTAVAIL WSAEADDRNOTAVAIL
#define EAFNOSUPPORT WSAEAFNOSUPPORT
#define EAGAIN WSAEWOULDBLOCK
#define ECONNABORTED WSAECONNABORTED
#define ECONNREFUSED WSAECONNREFUSED
#define ECONNRESET WSAECONNRESET
#define EHOSTUNREACH WSAEHOSTUNREACH
#define EIDRM 4096
#define EINPROGRESS WSAEINPROGRESS
#define EINTR WSAEINTR
#define EISCONN WSAEISCONN
#define EMSGSIZE WSAEMSGSIZE
#define ENABLE_SSPI 1
#define ENOBUFS WSAENOBUFS
#define ENOTCONN WSAENOTCONN
#define ENOTSOCK WSAENOTSOCK
#define EOPNOTSUPP WSAEOPNOTSUPP
#define EPROTONOSUPPORT WSAEPROTONOSUPPORT
#define EWOULDBLOCK WSAEWOULDBLOCK

#define F_OK 0
#define GETNCNT 16384
#define GETPID 262144
#define GETVAL 65536

#define HAVE_UNION_SEMUN 1
#define IPC_CREAT 512
#define IPC_EXCL 1024
#define IPC_PRIVATE 234564
#define IPC_RMID 256
#define IPC_STAT 4096
#define ITIMER_REAL 0
#define O_DSYNC 0x0080
#define PG_SIGNAL_COUNT 32

#define R_OK 4
#define SETALL 8192
#define SETVAL 131072
#define SIG_DFL ((pqsigfunc)0)
#define SIG_ERR ((pqsigfunc)-1)
#define SIG_IGN ((pqsigfunc)1)
#define S_IRGRP 0
#define S_IROTH 0
#define S_IRUSR _S_IREAD
#define S_IRWXG 0
#define S_IRWXO 0
#define S_IRWXU (S_IRUSR | S_IWUSR | S_IXUSR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#define S_IWGRP 0
#define S_IWOTH 0
#define S_IWUSR _S_IWRITE
#define S_IXGRP 0
#define S_IXOTH 0
#define S_IXUSR _S_IEXEC
#define UNBLOCKED_SIGNAL_QUEUE()	(pg_signal_queue & ~pg_signal_mask)

#define WEXITSTATUS(w)	(w)
#define WIFEXITED(w)	(((w) & 0XFFFFFF00) == 0)
#define WIFSIGNALED(w)	(!WIFEXITED(w))
#define WTERMSIG(w)		(w)
#define W_OK 2


#define accept(s, addr, addrlen) pgwin32_accept(s, addr, addrlen)
#define bind(s, addr, addrlen) pgwin32_bind(s, addr, addrlen)
#define connect(s, name, namelen) pgwin32_connect(s, name, namelen)
#define fsync(fd) _commit(fd)
#define ftruncate(a,b)	chsize(a,b)
#define isalnum_l _isalnum_l
#define isalpha_l _isalpha_l
#define isdigit_l _isdigit_l
#define isgraph_l _isgraph_l
#define islower_l _islower_l
#define isnan(x) _isnan(x)
#define isprint_l _isprint_l
#define ispunct_l _ispunct_l
#define isspace_l _isspace_l
#define isupper_l _isupper_l
#define iswalnum_l _iswalnum_l
#define iswalpha_l _iswalpha_l
#define iswdigit_l _iswdigit_l
#define iswgraph_l _iswgraph_l
#define iswlower_l _iswlower_l
#define iswprint_l _iswprint_l
#define iswpunct_l _iswpunct_l
#define iswspace_l _iswspace_l
#define iswupper_l _iswupper_l
#define kill(pid,sig)	pgkill(pid,sig)
#define listen(s, backlog) pgwin32_listen(s, backlog)
#define locale_t _locale_t
#define lstat(path, sb) stat(path, sb)
#define mbstowcs_l _mbstowcs_l
#define mkdir(a,b)	mkdir(a)
#define putenv(x) pgwin32_putenv(x)
#define recv(s, buf, len, flags) pgwin32_recv(s, buf, len, flags)
#define select(n, r, w, e, timeout) pgwin32_select(n, r, w, e, timeout)
#define send(s, buf, len, flags) pgwin32_send(s, buf, len, flags)
#define setlocale(a,b) pgwin32_setlocale(a,b)
#define sigmask(sig) ( 1 << ((sig)-1) )
#define socket(af, type, protocol) pgwin32_socket(af, type, protocol)
#define stat(a,b) pgwin32_safestat(a,b)
#define strcoll_l _strcoll_l
#define strxfrm_l _strxfrm_l
#define tolower_l _tolower_l
#define toupper_l _toupper_l
#define towlower_l _towlower_l
#define towupper_l _towupper_l
#define unsetenv(x) pgwin32_unsetenv(x)
#define wcscoll_l _wcscoll_l
#define wcstombs_l _wcstombs_l
#define OID_MAX  UINT_MAX
#define PG_DIAG_CONSTRAINT_NAME 'n'
#define PG_DIAG_INTERNAL_POSITION 'p'
#define PG_DIAG_MESSAGE_PRIMARY 'M'
#define PG_DIAG_SEVERITY_NONLOCALIZED 'V'
#define PG_DIAG_SOURCE_FUNCTION 'R'
#define PG_DIAG_STATEMENT_POSITION 'P'

#define atooid(x) ((Oid) strtoul((x), NULL, 10))
