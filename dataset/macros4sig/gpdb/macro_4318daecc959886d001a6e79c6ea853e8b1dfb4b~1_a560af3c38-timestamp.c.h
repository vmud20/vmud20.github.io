#include<fcntl.h>

#include<arpa/inet.h>

#include<stdio.h>
#include<sys/stat.h>
#include<pwd.h>
#include<limits.h>
#include<sys/types.h>
#include<stdlib.h>
#include<strings.h>
#include<float.h>
#include<ctype.h>
#include<assert.h>
#include<math.h>

#include<stddef.h>

#include<netinet/in.h>


#include<time.h>
#include<stdint.h>
#include<errno.h>
#include<netdb.h>
#include<locale.h>

#include<string.h>

#include<libintl.h>

#include<stdarg.h>




#define DTERR_INTERVAL_OVERFLOW (-4)
#define DTERR_MD_FIELD_OVERFLOW (-3)	
#define DTK_M(t)		(0x01 << (t))

#define FMODULO(t,q,u) \
do { \
	(q) = (((t) < 0) ? ceil((t) / (u)): floor((t) / (u))); \
	if ((q) != 0) (t) -= rint((q) * (u)); \
} while(0)
#define INTERVAL_FULL_RANGE (0x7FFF)
#define INTERVAL_MASK(b) (1 << (b))
#define ISODATE 22
#define ISOTIME 23
#define IS_VALID_JULIAN(y,m,d) ((((y) > JULIAN_MINYEAR) \
  || (((y) == JULIAN_MINYEAR) && (((m) > JULIAN_MINMONTH) \
  || (((m) == JULIAN_MINMONTH) && ((d) >= JULIAN_MINDAY))))) \
 && ((y) < JULIAN_MAXYEAR))
#define IS_VALID_UTIME(y,m,d) ((((y) > UTIME_MINYEAR) \
 || (((y) == UTIME_MINYEAR) && (((m) > UTIME_MINMONTH) \
  || (((m) == UTIME_MINMONTH) && ((d) >= UTIME_MINDAY))))) \
 && (((y) < UTIME_MAXYEAR) \
 || (((y) == UTIME_MAXYEAR) && (((m) < UTIME_MAXMONTH) \
  || (((m) == UTIME_MAXMONTH) && ((d) <= UTIME_MAXDAY))))))
#define JULIAN_MAXYEAR (5874898)
#define JULIAN_MINDAY (24)
#define JULIAN_MINMONTH (11)
#define JULIAN_MINYEAR (-4713)
#define MAX_INTERVAL_PRECISION 6
#define MICROSECOND 14
#define MILLISECOND 13
#define MONTHS_PER_YEAR 12
#define SECS_PER_MINUTE 60
#define TIMESTAMP_IS_NOBEGIN(j) ((j) == DT_NOBEGIN)
#define TIMESTAMP_IS_NOEND(j)	((j) == DT_NOEND)
#define TIMESTAMP_NOBEGIN(j)	do {(j) = DT_NOBEGIN;} while (0)
#define TIMESTAMP_NOEND(j)			do {(j) = DT_NOEND;} while (0)
#define TIMESTAMP_NOT_FINITE(j) (TIMESTAMP_IS_NOBEGIN(j) || TIMESTAMP_IS_NOEND(j))
#define TMODULO(t,q,u) \
do { \
	(q) = ((t) / (u)); \
	if ((q) != 0) (t) -= ((q) * (u)); \
} while(0)
#define TSROUND(j) (rint(((double) (j)) * TS_PREC_INV) / TS_PREC_INV)
#define TS_PREC_INV 1000000.0
#define USECS_PER_MINUTE INT64CONST(60000000)
#define UTIME_MAXDAY (18)
#define UTIME_MAXMONTH (01)
#define UTIME_MAXYEAR (2038)
#define UTIME_MINDAY (14)
#define UTIME_MINMONTH (12)
#define UTIME_MINYEAR (1901)
#define isleap(y) (((y) % 4) == 0 && (((y) % 100) != 0 || ((y) % 400) == 0))

#define bool char
#define FRONTEND 1



#define palloc0fast(sz) \
	( MemSetTest(0, sz) ? \
		MemoryContextAllocZeroAligned(CurrentMemoryContext, sz) : \
		MemoryContextAllocZero(CurrentMemoryContext, sz) )
#define Abs(x)			((x) >= 0 ? (x) : -(x))


#define AssertMacro(condition)	((void)true)

#define AssertVariableIsOfType(varname, typename) \
	StaticAssertStmt(__builtin_types_compatible_p(__typeof__(varname), typename), \
	CppAsString(varname) " does not have type " CppAsString(typename))
#define AssertVariableIsOfTypeMacro(varname, typename) \
	((void) StaticAssertExpr(__builtin_types_compatible_p(__typeof__(varname), typename), \
	 CppAsString(varname) " does not have type " CppAsString(typename)))
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
#define OidIsValid(objectId)  ((bool) ((objectId) != InvalidOid))


#define PG_BINARY_A "ab"
#define PG_BINARY_R "rb"
#define PG_BINARY_W "wb"
#define PG_TEXTDOMAIN(domain) (domain CppAsString2(SO_MAJOR_VERSION) "-" PG_MAJORVERSION)
#define PG_USED_FOR_ASSERTS_ONLY __attribute__((unused))
#define PointerIsAligned(pointer, type) \
		(((uintptr_t)(pointer) % (sizeof (type))) == 0)
#define PointerIsValid(pointer) ((const void*)(pointer) != NULL)
#define RegProcedureIsValid(p)	OidIsValid(p)
#define SHORTALIGN(LEN)			TYPEALIGN(ALIGNOF_SHORT, (LEN))
#define SHORTALIGN_DOWN(LEN)	TYPEALIGN_DOWN(ALIGNOF_SHORT, (LEN))
#define SIGNAL_ARGS  int postgres_signal_arg
#define SQL_STR_DOUBLE(ch, escape_backslash)	\
	((ch) == '\'' || ((ch) == '\\' && (escape_backslash)))
#define STATIC_IF_INLINE static inline
#define StaticAssertExpr(condition, errmessage) \
	({ StaticAssertStmt(condition, errmessage); true; })
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
#define Trap(condition, errorType)
#define TrapMacro(condition, errorType)	(true)
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
#define pg_unreachable() __builtin_unreachable()
#define sigjmp_buf jmp_buf
#define siglongjmp longjmp
#define sigsetjmp(x,y) setjmp(x)
#define strtoll strtoq
#define strtoull strtouq
#define DEVNULL "nul"
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
#define popen(a,b) _popen(a,b)
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
#define OID_MAX  UINT_MAX
#define PG_DIAG_CONSTRAINT_NAME 'n'
#define PG_DIAG_INTERNAL_POSITION 'p'
#define PG_DIAG_MESSAGE_PRIMARY 'M'
#define PG_DIAG_SOURCE_FUNCTION 'R'
#define PG_DIAG_STATEMENT_POSITION 'P'

