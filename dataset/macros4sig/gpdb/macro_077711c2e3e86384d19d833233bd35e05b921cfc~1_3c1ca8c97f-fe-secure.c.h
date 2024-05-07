#include<stdlib.h>




#include<unistd.h>
#include<fcntl.h>
#include<arpa/inet.h>

#include<netinet/tcp.h>
#include<stdarg.h>
#include<sys/un.h>


#include<signal.h>
#include<stddef.h>
#include<stdio.h>

#include<sys/socket.h>
#include<string.h>

#include<time.h>

#include<strings.h>
#include<netinet/in.h>

#include<pwd.h>

#include<libintl.h>


#include<sys/stat.h>
#include<locale.h>
#include<pthread.h>

#include<sys/time.h>

#include<sys/types.h>

#include<ctype.h>
#include<errno.h>


#include<stdint.h>
#include<netdb.h>

#define ECONNRESET WSAECONNRESET
#define EINPROGRESS WSAEINPROGRESS
#define EINTR WSAEINTR
#define EWOULDBLOCK WSAEWOULDBLOCK

#define _errno errno
#define _ftime(a) ftime(a)
#define _timeb timeb
#define close(a) _close(a)
#define popen(a,b) _popen(a,b)
#define read(a,b,c) _read(a,b,c)
#define write(a,b,c) _write(a,b,c)
#define CMDSTATUS_LEN 64		

#define PGTHREAD_ERROR(msg) \
	do { \
		fprintf(stderr, "%s\n", msg); \
		abort(); \
	} while (0)

#define SOCK_ERRNO (WSAGetLastError())
#define SOCK_ERRNO_SET(e) WSASetLastError(e)
#define SOCK_STRERROR winsock_strerror

#define libpq_gettext(x) (x)
#define pglock_thread()		pg_g_threadlock(true)
#define pgunlock_thread()	pg_g_threadlock(false)
#define pqIsnonblocking(conn)	((conn)->nonblocking)

#define PQExpBufferBroken(str)	\
	((str) == NULL || (str)->maxlen == 0)
#define PQExpBufferDataBroken(buf)	\
	((buf).maxlen == 0)
#define CANCEL_REQUEST_CODE PG_PROTOCOL(1234,5678)
#define HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN 1
#define MAX_STARTUP_PACKET_LENGTH 10000
#define NEGOTIATE_SSL_CODE PG_PROTOCOL(1234,5679)
#define PG_PROTOCOL(m,n)	(((m) << 16) | (n))
#define PG_PROTOCOL_MAJOR(v)	((v) >> 16)
#define PG_PROTOCOL_MINOR(v)	((v) & 0x0000ffff)

#define SM_DATABASE_USER (SM_DATABASE+SM_USER+1)		
#define UNIXSOCK_PATH(path, port, sockdir) \
		snprintf(path, sizeof(path), "%s/.s.PGSQL.%d", \
				((sockdir) && *(sockdir) != '\0') ? (sockdir) : \
				DEFAULT_PGSOCKET_DIR, \
				(port))
#define ss_family __ss_family
#define ss_len __ss_len

#define freeaddrinfo pg_freeaddrinfo
#define gai_strerror pg_gai_strerror
#define getaddrinfo pg_getaddrinfo
#define getnameinfo pg_getnameinfo


#define PQfreeNotify(ptr) PQfreemem(ptr)
#define PQsetdb(M_PGHOST,M_PGPORT,M_PGOPT,M_PGTTY,M_DBNAME)  \
	PQsetdbLogin(M_PGHOST, M_PGPORT, M_PGOPT, M_PGTTY, M_DBNAME, NULL, NULL)
#define OID_MAX  UINT_MAX
#define PG_DIAG_INTERNAL_POSITION 'p'
#define PG_DIAG_MESSAGE_PRIMARY 'M'
#define PG_DIAG_SOURCE_FUNCTION 'R'
#define PG_DIAG_STATEMENT_POSITION 'P'

#define FRONTEND 1

#define Abs(x)			((x) >= 0 ? (x) : -(x))
#define BUFFERALIGN(LEN)		TYPEALIGN(ALIGNOF_BUFFER, (LEN))
#define BoolIsValid(boolean)	((boolean) == false || (boolean) == true)

#define CppAsString(identifier) #identifier
#define CppAsString2(x) CppAsString(x)
#define CppConcat(x, y)			x##y
#define DOUBLEALIGN(LEN)		TYPEALIGN(ALIGNOF_DOUBLE, (LEN))
#define DOUBLEALIGN_DOWN(LEN)	TYPEALIGN_DOWN(ALIGNOF_DOUBLE, (LEN))

#define HAVE_STRTOLL 1
#define HAVE_STRTOULL 1
#define INT64CONST(x)  ((int64) x##LL)
#define INTALIGN(LEN)			TYPEALIGN(ALIGNOF_INT, (LEN))
#define INTALIGN_DOWN(LEN)		TYPEALIGN_DOWN(ALIGNOF_INT, (LEN))
#define IS_HIGHBIT_SET(ch)		((unsigned char)(ch) & HIGHBIT)
#define LONGALIGN(LEN)			TYPEALIGN(ALIGNOF_LONG, (LEN))
#define LONGALIGN_DOWN(LEN)		TYPEALIGN_DOWN(ALIGNOF_LONG, (LEN))
#define LONG_ALIGN_MASK (sizeof(long) - 1)
#define MAXALIGN(LEN)			TYPEALIGN(MAXIMUM_ALIGNOF, (LEN))
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
		if ((((intptr_t) _vstart) & LONG_ALIGN_MASK) == 0 && \
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
#define OidIsValid(objectId)  ((bool) ((objectId) != InvalidOid))


#define PG_BINARY_A "ab"
#define PG_BINARY_R "rb"
#define PG_BINARY_W "wb"
#define PG_TEXTDOMAIN(domain) (domain CppAsString2(SO_MAJOR_VERSION) "-" PG_MAJORVERSION)
#define PointerIsAligned(pointer, type) \
		(((intptr_t)(pointer) % (sizeof (type))) == 0)
#define PointerIsValid(pointer) ((void*)(pointer) != NULL)
#define RegProcedureIsValid(p)	OidIsValid(p)
#define SHORTALIGN(LEN)			TYPEALIGN(ALIGNOF_SHORT, (LEN))
#define SHORTALIGN_DOWN(LEN)	TYPEALIGN_DOWN(ALIGNOF_SHORT, (LEN))
#define SIGNAL_ARGS  int postgres_signal_arg
#define SQL_STR_DOUBLE(ch, escape_backslash)	\
	((ch) == '\'' || ((ch) == '\\' && (escape_backslash)))
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
	(((intptr_t) (LEN) + ((ALIGNVAL) - 1)) & ~((intptr_t) ((ALIGNVAL) - 1)))
#define TYPEALIGN_DOWN(ALIGNVAL,LEN)  \
	(((intptr_t) (LEN)) & ~((intptr_t) ((ALIGNVAL) - 1)))
#define UINT64CONST(x) ((uint64) x##ULL)

#define _(x) gettext(x)


#define dgettext(d,x) (x)
#define dngettext(d,s,p,n) ((n) == 1 ? (s) : (p))
#define endof(array)	(&(array)[lengthof(array)])
#define errcode __msvc_errcode
#define gettext(x) (x)
#define gettext_noop(x) (x)
#define lengthof(array) (sizeof (array) / sizeof ((array)[0]))
#define memmove(d, s, c)		bcopy(s, d, c)
#define ngettext(s,p,n) ((n) == 1 ? (s) : (p))
#define offsetof(type, field)	((long) &((type *)0)->field)
#define sigjmp_buf jmp_buf
#define siglongjmp longjmp
#define sigsetjmp(x,y) setjmp(x)
#define strtoll strtoq
#define strtoull strtouq
#define DEVNULL "nul"
#define DEVTTY "/dev/tty"
#define EXE ".exe"
#define IS_DIR_SEP(ch)	((ch) == '/')
#define PGINVALID_SOCKET (-1)

#define PG_SIGNAL_COUNT 32
#define SYSTEMQUOTE "\""
#define TIMEZONE_GLOBAL timezone
#define TZNAME_GLOBAL tzname
#define closesocket close
#define		fopen(a,b) pgwin32_fopen(a,b)
#define fprintf(...)	pg_fprintf(__VA_ARGS__)
#define fseeko(a, b, c) fseek(a, b, c)
#define ftello(a)		ftell(a)
#define is_absolute_path(filename) \
( \
	IS_DIR_SEP((filename)[0]) \
)
#define kill(pid,sig)	pgkill(pid,sig)
#define		open(a,b,c) pgwin32_open(a,b,c)
#define pclose(a) _pclose(a)
#define pgoff_t off_t
#define pgpipe(a)			pipe(a)
#define piperead(a,b,c)		read(a,b,c)
#define pipewrite(a,b,c)	write(a,b,c)
#define printf(...)		pg_printf(__VA_ARGS__)
#define qsort(a,b,c,d) pg_qsort(a,b,c,d)
#define readlink(path, buf, size)	pgreadlink(path, buf, size)
#define rename(from, to)		pgrename(from, to)
#define setlocale(a,b) pgwin32_setlocale(a,b)
#define snprintf(...)	pg_snprintf(__VA_ARGS__)
#define sprintf(...)	pg_sprintf(__VA_ARGS__)
#define stat(a,b) pgwin32_safestat(a,b)
#define symlink(oldpath, newpath)	pgsymlink(oldpath, newpath)
#define unlink(path)			pgunlink(path)
#define vfprintf(...)	pg_vfprintf(__VA_ARGS__)
#define vsnprintf(...)	pg_vsnprintf(__VA_ARGS__)


