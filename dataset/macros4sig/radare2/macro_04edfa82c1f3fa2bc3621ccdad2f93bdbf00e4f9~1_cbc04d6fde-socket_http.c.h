



#include<string.h>

#include<limits.h>
#include<semaphore.h>
#include<sys/types.h>

#include<stdarg.h>


#include<sys/param.h>
#include<stdlib.h>


#include<unistd.h>
#include<pthread.h>




#include<time.h>
#include<stddef.h>




#include<stdbool.h>



#include<sys/time.h>
#include<sys/un.h>
#include<fcntl.h>


#include<sched.h>
#include<malloc.h>



#include<sys/socket.h>
#include<netdb.h>
#include<dirent.h>
#include<sys/wait.h>


#include<assert.h>



#include<poll.h>
#include<netinet/in.h>
#include<arpa/inet.h>


#include<ctype.h>
#include<wchar.h>
#include<sys/stat.h>

#include<signal.h>


#include<netinet/tcp.h>
#include<stdio.h>


#include<stdint.h>

#define RNumBig mpz_t




#define R_PJ_H 1
#define R_PRINT_JSON_DEPTH_LIMIT 128

#define R_STRBUF_SAFEGET(sb) (r_strbuf_get (sb) ? r_strbuf_get (sb) : "")
#define ASN1_CLASS    0xC0 
#define ASN1_FORM     0x20 
#define ASN1_JSON_EMPTY "{}"
#define ASN1_JSON_NULL  "null"
#define ASN1_LENLONG  0x80 
#define ASN1_LENSHORT 0x7F 
#define ASN1_OID_LEN  64
#define ASN1_TAG      0x1F 
#define CLASS_APPLICATION  0x40 
#define CLASS_CONTEXT      0x80 
#define CLASS_PRIVATE      0xC0 
#define CLASS_UNIVERSAL    0x00 
#define FORM_CONSTRUCTED   0x20 
#define FORM_PRIMITIVE     0x00 

#define TAG_BITSTRING       0x03 
#define TAG_BMPSTRING       0x1E 
#define TAG_BOOLEAN         0x01 
#define TAG_EMBEDDED_PDV    0x0B 
#define TAG_ENUMERATED      0x0A 
#define TAG_EOC             0x00 
#define TAG_EXTERNAL        0x08 
#define TAG_GENERALIZEDTIME 0x18 
#define TAG_GENERALSTRING   0x1B 
#define TAG_GRAPHICSTRING   0x19 
#define TAG_IA5STRING       0x16 
#define TAG_INTEGER         0x02 
#define TAG_NULL            0x05 
#define TAG_NUMERICSTRING   0x12 
#define TAG_OBJDESCRIPTOR   0x07 
#define TAG_OCTETSTRING     0x04 
#define TAG_OID             0x06 
#define TAG_PRINTABLESTRING 0x13 
#define TAG_REAL            0x09 
#define TAG_SEQUENCE        0x10 
#define TAG_SET             0x11 
#define TAG_T61STRING       0x14 
#define TAG_UNIVERSALSTRING 0x1C 
#define TAG_UTCTIME         0x17 
#define TAG_UTF8STRING      0x0C 
#define TAG_VIDEOTEXSTRING  0x15 
#define TAG_VISIBLESTRING   0x1A 

#define BITS2BYTES(x) (((x)/8)+(((x)%8)?1:0))
#define CTA(x,y,z) (x+CTO(y,z))
#define CTI(x,y,z) (*((size_t*)(CTA(x,y,z))))
#define CTO(y,z) ((size_t) &((y*)0)->z)
#define CTS(x,y,z,t,v) {t* _=(t*)CTA(x,y,z);*_=v;}
#define FS "\\"
  #define FUNC_ATTR_ALLOC_ALIGN(x) __attribute__((alloc_align(x)))
  #define FUNC_ATTR_ALLOC_SIZE(x) __attribute__((alloc_size(x)))
  #define FUNC_ATTR_ALLOC_SIZE_PROD(x,y) __attribute__((alloc_size(x,y)))
  #define FUNC_ATTR_ALWAYS_INLINE __attribute__((always_inline))
  #define FUNC_ATTR_CONST __attribute__((const))
  #define FUNC_ATTR_MALLOC __attribute__((malloc))
  #define FUNC_ATTR_PURE __attribute__ ((pure))
  #define FUNC_ATTR_USED __attribute__((used))
  #define FUNC_ATTR_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#define HAS_CLOCK_NANOSLEEP 1
#define HAVE_EPRINTF 1
#define HAVE_REGEXP 0
#define HHXFMT  "x"
#define LDBLFMT "f"
#define LIBC_HAVE_FORK 1
#define LIBC_HAVE_PLEDGE 1
#define LIBC_HAVE_PTRACE 0
#define LIBC_HAVE_SYSTEM 0
#define O_BINARY 0
#define PERROR_WITH_FILELINE 0
#define PFMT32d "d"
#define PFMT32o "o"
#define PFMT32u "u"
#define PFMT32x "x"
#define PFMT64d "I64d"
#define PFMT64o "I64o"
#define PFMT64u "I64u"
#define PFMT64x "I64x"
#define PFMTSZd "Id"
#define PFMTSZo "Io"
#define PFMTSZu "Iu"
#define PFMTSZx "Ix"

#define R_ABS(x) (((x)<0)?-(x):(x))
    #define R_API __attribute__((visibility("default")))
#define R_ARRAY_SIZE(x) (sizeof (x) / sizeof ((x)[0]))
#define R_BETWEEN(x,y,z) (((y)>=(x)) && ((y)<=(z)))
#define R_BIT_CHK(x,y) (*(x) & (1<<(y)))
#define R_BIT_SET(x,y) (((ut8*)x)[y>>4] |= (1<<(y&0xf)))
#define R_BIT_TOGGLE(x, y) ( R_BIT_CHK (x, y) ? \
		R_BIT_UNSET (x, y): R_BIT_SET (x, y))
#define R_BIT_UNSET(x,y) (((ut8*)x)[y>>4] &= ~(1<<(y&0xf)))
#define R_BORROW 
#define R_BTW(x,y,z) (((x)>=(y))&&((y)<=(z)))?y:x
#define R_DEPRECATE 
#define R_DIM(x,y,z) (((x)<(y))?(y):((x)>(z))?(z):(x))
#define R_FREE(x) { free((void *)x); x = NULL; }

#define R_IFNULL(x) 
#define R_IN 
#define R_INOUT 

#define R_JOIN_2_PATHS(p1, p2) p1 R_SYS_DIR p2
#define R_JOIN_3_PATHS(p1, p2, p3) p1 R_SYS_DIR p2 R_SYS_DIR p3
#define R_JOIN_4_PATHS(p1, p2, p3, p4) p1 R_SYS_DIR p2 R_SYS_DIR p3 R_SYS_DIR p4
#define R_JOIN_5_PATHS(p1, p2, p3, p4, p5) p1 R_SYS_DIR p2 R_SYS_DIR p3 R_SYS_DIR p4 R_SYS_DIR p5
#define R_LIB_VERSION(x) \
R_API const char *x##_version() { return "" R2_GITTAP; }
#define R_LIB_VERSION_HEADER(x) \
R_API const char *x##_version(void)
#define R_MAX(x,y) (((x)>(y))?(x):(y))

#define R_MEM_ALIGN(x) ((void *)(size_t)(((ut64)(size_t)x) & 0xfffffffffffff000LL))
#define R_MIN(x,y) (((x)>(y))?(y):(x))

#define R_MODE_ARRAY 0x010
#define R_MODE_CLASSDUMP 0x040
#define R_MODE_EQUAL 0x080
#define R_MODE_JSON 0x008
#define R_MODE_PRINT 0x000
#define R_MODE_RADARE 0x001
#define R_MODE_SET 0x002
#define R_MODE_SIMPLE 0x004
#define R_MODE_SIMPLEST 0x020
#define R_NEW(x) (x*)malloc(sizeof(x))
#define R_NEW0(x) (x*)calloc(1,sizeof(x))
#define R_NEWCOPY(x,y) (x*)r_new_copy(sizeof(x), y)
#define R_NEWS(x,y) (x*)malloc(sizeof(x)*(y))
#define R_NEWS0(x,y) (x*)calloc(y,sizeof(x))
#define R_NEW_COPY(x,y) x=(void*)malloc(sizeof(y));memcpy(x,y,sizeof(y))
#define R_NONNULL 
#define R_NULLABLE 
#define R_OUT 
#define R_OWN 
#define R_PTR_ALIGN(v,t) \
	((char *)(((size_t)(v) ) \
	& ~(t - 1)))
#define R_PTR_ALIGN_NEXT(v,t) \
	((char *)(((size_t)(v) + (t - 1)) \
	& ~(t - 1)))
#define R_PTR_MOVE(d,s) d=s;s=NULL;
#define R_REF_FUNCTIONS(s, n) \
static inline void n##_ref(s *x) { x->R_REF_NAME++; } \
static inline void n##_unref(s *x) { r_unref (x, n##_free); }
#define R_REF_NAME refcount
#define R_REF_TYPE RRef R_REF_NAME
#define R_ROUND(x,y) ((x)%(y))?(x)+((y)-((x)%(y))):(x)
# define R_SYS_ARCH "ppc"
# define R_SYS_BASE ((ut64)0x1000)
#  define R_SYS_BITS (R_SYS_BITS_32 | R_SYS_BITS_64)
#define R_SYS_DIR "\\"
#  define R_SYS_ENDIAN 0
#define R_SYS_ENDIAN_BI 3
#define R_SYS_ENDIAN_BIG 2
#define R_SYS_ENDIAN_LITTLE 1
#define R_SYS_ENDIAN_NONE 0
#define R_SYS_ENVSEP ";"
#define R_SYS_HOME "USERPROFILE"
#define R_SYS_OS "qnx"
#define R_SYS_TMP "TEMP"
#define R_UNUSED __attribute__((__unused__))
#define TARGET_OS_IPHONE 1
#define TODO(x) eprintf(__func__"  " x)
#  define UNUSED_FUNCTION(x) __attribute__((__unused__)) UNUSED_ ## x

#define ZERO_FILL(x) memset (&x, 0, sizeof (x))
#define _FILE_OFFSET_BITS 64

  #define __BSD__ 0
#define __KFBSD__ 1
#define __POWERPC__ 1
  #define __UNIX__ 1
  #define __WINDOWS__ 1

#define __func__ __FUNCTION__
#define __i386__ 1
#define __packed __attribute__((__packed__))
#define __x86_64__ 1
#define _perror(str,file,line,func) \
  { \
	  char buf[256]; \
	  snprintf(buf,sizeof(buf),"[%s:%d %s] %s",file,line,func,str); \
	  r_sys_perror_str(buf); \
  }
#  define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define eprintf(...) fprintf(stderr,__VA_ARGS__)
#define mips mips
#define perror(x) _perror(x,"__FILE__","__LINE__",__func__)
#define r_offsetof(type, member) offsetof(type, member)
#define r_ref(x) x->R_REF_NAME++;
#define r_ref_init(x) x->R_REF_NAME = 1
#define r_sys_perror(x) _perror(x,"__FILE__","__LINE__",__func__)
#define r_unref(x,f) { assert (x->R_REF_NAME> 0); if (!--(x->R_REF_NAME)) { f(x); } }

  #define strcasecmp stricmp
  #define strncasecmp strnicmp
#define typeof(arg) __typeof__(arg)

#define ut8p_b(x) ((x)[0])
#define ut8p_bd(x) ((x)[0]|((x)[1]<<8)|((x)[2]<<16)|((x)[3]<<24))
#define ut8p_bq(x) ((x)[0]|((x)[1]<<8)|((x)[2]<<16)|((x)[3]<<24)|((x)[4]<<32)|((x)[5]<<40)|((x)[6]<<48)|((x)[7]<<56))
#define ut8p_bw(x) ((x)[0]|((x)[1]<<8))
#define ut8p_ld(x) ((x)[3]|((x)[2]<<8)|((x)[1]<<16)|((x)[0]<<24))
#define ut8p_lq(x) ((x)[7]|((x)[6]<<8)|((x)[5]<<16)|((x)[4]<<24)|((x)[3]<<32)|((x)[2]<<40)|((x)[1]<<48)|((x)[0]<<56))
#define ut8p_lw(x) ((x)[1]|((x)[0]<<8))
#define B0000 0
#define B0001 1
#define B0010 2
#define B0011 3
#define B0100 4
#define B0101 5
#define B0110 6
#define B0111 7
#define B1000 8
#define B1001 9
#define B1010 10
#define B1011 11
#define B1100 12
#define B1101 13
#define B1110 14
#define B1111 15
#define B4(a,b,c,d) ((a<<12)|(b<<8)|(c<<4)|(d))
#define B_EVEN(x)        (((x)&1)==0)
#define B_IS_SET(x, n)   (((x) & (1ULL<<(n)))?1:0)
#define B_ODD(x)         (!B_EVEN((x)))
#define B_SET(x, n)      ((x) |= (1ULL<<(n)))
#define B_TOGGLE(x, n)   ((x) ^= (1ULL<<(n)))
#define B_UNSET(x, n)    ((x) &= ~(1ULL<<(n)))
#define DEBUGGER 0
#define HEAPTYPE(x) \
	static x* x##_new(x n) {\
		x *m = malloc(sizeof (x));\
		return m? *m = n, m: m; \
	}
#define INFINITY (1.0f/0.0f)
#define NAN (0.0f/0.0f)

# define R_ALIGNED(x) __declspec(align(x))
#define R_EMPTY { 0 }
#define R_EMPTY2 {{ 0 }}
#define R_PACKED( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop) )
#define ST16_MAX 0x7FFF
#define ST16_MIN (-ST16_MAX-1)
#define ST32_MAX 0x7FFFFFFF
#define ST32_MIN (-ST32_MAX-1)
#define ST64_MAX 0x7FFFFFFFFFFFFFFFULL
#define ST64_MIN (-ST64_MAX-1)
#define ST8_MAX  0x7F
#define ST8_MIN  (-ST8_MAX-1)
#define SZT_ADD_OVFCHK(x,y) ((SIZE_MAX - (x)) < (y))
#define UT16_ADD_OVFCHK(x,y) ((UT16_MAX - (x)) < (y))
#define UT16_ALIGN(x) (x + (x - (x % sizeof (ut16))))
#define UT16_GT0 0x8000U
#define UT16_MAX 0xFFFFU
#define UT32_ADD_OVFCHK(x,y) ((UT32_MAX - (x)) < (y))
#define UT32_ALIGN(x) (x + (x - (x % sizeof (ut32))))
#define UT32_GT0 0x80000000U
#define UT32_HI(x) ((ut32)(((ut64)(x))>>32)&UT32_MAX)
#define UT32_LO(x) ((ut32)((x)&UT32_MAX))
#define UT32_LT0 0x7FFFFFFFU
#define UT32_MAX 0xFFFFFFFFU
#define UT32_MIN 0U
#define UT64_16U 0xFFFFFFFFFFFF0000ULL
#define UT64_32U 0xFFFFFFFF00000000ULL
#define UT64_8U  0xFFFFFFFFFFFFFF00ULL
#define UT64_ADD_OVFCHK(x,y) ((UT64_MAX - (x)) < (y))
#define UT64_ALIGN(x) (x + (x - (x % sizeof (ut64))))
#define UT64_GT0 0x8000000000000000ULL
#define UT64_LT0 0x7FFFFFFFFFFFFFFFULL
#define UT64_MAX 0xFFFFFFFFFFFFFFFFULL
#define UT64_MIN 0ULL
#define UT8_ADD_OVFCHK(x,y) ((UT8_MAX - (x)) < (y))
#define UT8_GT0  0x80U
#define UT8_MAX  0xFFU
#define UT8_MIN  0x00U
#define boolt int
#define cut8 const unsigned char
#define st16 short
#define st32 int
#define st64 long long
#define st8 signed char
#define ut16 unsigned short
#define ut32 unsigned int
#define ut64 unsigned long long
#define ut8 unsigned char
#define IS_DIGIT(x) ((x) >= '0' && (x) <= '9')
#define IS_HEXCHAR(x) (((x) >= '0' && (x) <= '9') || ((x) >= 'a' && (x) <= 'f') || ((x) >= 'A' && (x) <= 'F'))
#define IS_LOWER(c) ((c) >= 'a' && (c) <= 'z')
#define IS_NULLSTR(x) (!(x) || !*(x))
#define IS_OCTAL(x) ((x) >= '0' && (x) <= '7')
#define IS_PRINTABLE(x) ((x) >=' ' && (x) <= '~')
#define IS_SEPARATOR(x) ((x) == ' ' || (x)=='\t' || (x) == '\n' || (x) == '\r' || (x) == ' '|| \
		(x) == ',' || (x) == ';' || (x) == ':' || (x) == '[' || (x) == ']' || \
		(x) == '(' || (x) == ')' || (x) == '{' || (x) == '}')
#define IS_UPPER(c) ((c) >= 'A' && (c) <= 'Z')
#define IS_WHITECHAR(x) ((x) == ' ' || (x)=='\t' || (x) == '\n' || (x) == '\r')
#define IS_WHITESPACE(x) ((x) == ' ' || (x) == '\t')







#define r_acp_to_utf8(str) r_acp_to_utf8_l ((char *)str, -1)
#define r_utf16_to_utf8(wc) r_utf16_to_utf8_l ((wchar_t *)wc, -1)
#define r_utf8_to_acp(cstring) r_utf8_to_acp_l ((char *)cstring, -1)
#define r_utf8_to_utf16(cstring) r_utf8_to_utf16_l ((char *)cstring, -1)



#define ROFList_Parent RList

#define r_list_empty(x) (!(x) || !(x)->length)
#define r_list_foreach(list, it, pos)\
	if (list)\
		for (it = list->head; it && (pos = it->data, 1); it = it->n)
#define r_list_foreach_iter(list, it)\
	if (list)\
		for (it = list->head; it; it = it->n)
#define r_list_foreach_prev(list, it, pos)\
	if (list)\
		for (it = list->tail; it && (pos = it->data, 1); it = it->p)
#define r_list_foreach_prev_safe(list, it, tmp, pos) \
	for (it = list->tail; it && (pos = it->data, tmp = it->p, 1); it = tmp)
#define r_list_foreach_safe(list, it, tmp, pos)\
	if (list)\
		for (it = list->head; it && (pos = it->data, tmp = it->n, 1); it = tmp)
#define r_list_head(x) ((x)? (x)->head: NULL)
#define r_list_iter_cur(x) x->p
#define r_list_iter_free(x) x
#define r_list_iter_get(x)\
	x->data;\
	x = x->n
#define r_list_iter_next(x) (x? 1: 0)
#define r_list_iterator(x) (x)? (x)->head: NULL
#define r_list_push(x, y) r_list_append (x, y)
#define r_list_tail(x) ((x)? (x)->tail: NULL)
#define r_oflist_append(x, y) r_oflist_deserialize (x), r_list_append (x, y)
#define r_oflist_array(x) x->array? x->array: (x->array = r_oflist_serialize (x)), x->array
#define r_oflist_delete(x, y) r_oflist_deserialize (x), r_list_delete (x, y)
#define r_oflist_deserialize(x)\
	free (x->array - 1), x->array = 0
#define r_oflist_destroy(x) r_oflist_deserialize (x)
#define r_oflist_free(x) r_oflist_deserialize (x), r_list_free (x)
#define r_oflist_length(x, y) r_list_length (x, y)
#define r_oflist_prepend(x, y) r_oflist_deserialize (x), r_list_prepend (x, y)
#define r_oflist_serialize(x)\
	x->array = r_flist_new (r_list_length (x)), { \
		int idx = 0;\
		void *ptr;\
		RListIter *iter;\
		r_list_foreach (x, iter, ptr) r_flist_set (x->array, idx++, ptr);\
	}\
	x->array;

#define SDB_KSZ 0xff
#define SDB_LIST_SORTED 1
#define SDB_LIST_UNSORTED 0
#define SDB_MAX_KEY 0xff
#define SDB_MAX_PATH 256
#define SDB_MAX_VALUE 0xffffff
#define SDB_MIN_KEY 1
#define SDB_MIN_VALUE 1
#define SDB_MODE _S_IWRITE | _S_IREAD
#define SDB_NUM_BASE 16
#define SDB_NUM_BUFSZ 64
#define SDB_OPTION_ALL 0xff
#define SDB_OPTION_FS      (1 << 2)
#define SDB_OPTION_JOURNAL (1 << 3)
#define SDB_OPTION_NONE 0
#define SDB_OPTION_NOSTAMP (1 << 1)
#define SDB_OPTION_SYNC    (1 << 0)
#define SDB_RS ','
#define SDB_SS ","
#define SDB_VSZ 0xffffff
#define sdb_aforeach(x,y) \
	{ char *next; \
	if (y) for (x=y;;) { \
		x = sdb_anext (x, &next);
#define sdb_aforeach_next(x) \
	if (!next) break; \
	*(next-1) = ','; \
	x = next; } }
#define sdb_json_format_free(x) free ((x)->buf)

#define RFList void**
#define r_flist_foreach(it, pos) \
	r_flist_rewind(it); \
	while (r_flist_next (it) && (pos = r_flist_get (it)))
#define r_flist_get(it) *(it++)
#define r_flist_iterator(x) x
#define r_flist_next(it) *it!=0
#define r_flist_rewind(it) while(it!=*it) it--; it++;
#define r_flist_t void**
#define r_flist_unref(x) x
#define R_SYS_DEVNULL "nul"

#define W32_TCALL(name) name"W"
#define W32_TCHAR_FSTR "%S"
#    define r_sys_breakpoint() __asm__ volatile ("bkpt $0");
#define r_sys_conv_utf8_to_win(buf) r_utf8_to_utf16 (buf)
#define r_sys_conv_utf8_to_win_l(buf, len) r_utf8_to_utf16_l (buf, len)
#define r_sys_conv_win_to_utf8(buf) r_utf16_to_utf8 (buf)
#define r_sys_conv_win_to_utf8_l(buf, len) r_utf16_to_utf8_l ((wchar_t *)buf, len)
#define r_sys_mkdir_failed() (GetLastError () != ERROR_ALREADY_EXISTS)
#  define r_sys_trap() __asm__ __volatile__ (".word 0");



#define R_STRPOOL_INC 1024

#define R_STR_DUP(x) ((x) ? strdup ((x)) : NULL)

#define R_STR_ISEMPTY(x) (!(x) || !*(x))
#define R_STR_ISNOTEMPTY(x) ((x) && *(x))
#define r_str_array(x,y) ((y>=0 && y<(sizeof(x)/sizeof(*x)))?x[y]:"")
#define r_str_cpy(x,y) memmove(x,y,strlen(y)+1);


#define R_SPACES_MAX 512
#define r_spaces_foreach(sp, it, s) \
	r_rbtree_foreach ((sp)->spaces, (it), (s), RSpace, rb)

#define HAVE_CAPSICUM 1






#define R_NUMCALC_STRSZ 1024


#define MACRO_LOG_FUNC __func__
#define MACRO_WEAK_SYM __attribute__ ((weak))
#define R_DEFAULT_LOGLVL R_LOGLVL_WARN
#define R_LOG(lvl, tag, fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", lvl, tag, fmtstr, ##__VA_ARGS__);
#define R_LOG_DEBUG(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_DEBUG, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_ERROR(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_ERROR, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_FATAL(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_FATAL, NULL, fmtstr, ##__VA_ARGS__);

#define R_LOG_INFO(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_INFO, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_SILLY(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_SILLY, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_VERBOSE(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_VERBOSE, NULL, fmtstr, ##__VA_ARGS__);
#define R_LOG_WARN(fmtstr, ...) r_log (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", R_LOGLVL_WARN, NULL, fmtstr, ##__VA_ARGS__);
#define R_VLOG(lvl, tag, fmtstr, args) r_vlog (MACRO_LOG_FUNC, "__FILE__", \
	"__LINE__", lvl, tag, fmtstr, args);







#define BITWORD_BITS_SHIFT 5
#define RBitword ut32

#define R_BUF_CUR 1
#define R_BUF_END 2

#define R_BUF_SET 0



#define r_interval_tree_foreach(tree, it, dat) \
	for ((it) = r_rbtree_first (&(tree)->root->node); r_rbtree_iter_has (&it) && (dat = r_interval_tree_iter_get (&it)->data); r_rbtree_iter_next (&(it)))
#define r_interval_tree_foreach_prev(tree, it, dat) \
	for ((it) = r_rbtree_last (&(tree)->root->node); r_rbtree_iter_has (&it) && (dat = r_rbtree_iter_get (&it, RIntervalNode, node)->data); r_rbtree_iter_prev (&(it)))

#define R_RBTREE_MAX_HEIGHT 62
#define r_rbtree_cont_foreach(tree, it, dat) \
	for ((it) = r_rbtree_first (&tree->root->node); r_rbtree_iter_has(&it) && (dat = r_rbtree_iter_get (&it, RContRBNode, node)->data); r_rbtree_iter_next (&(it)))
#define r_rbtree_cont_foreach_prev(tree, it, dat) \
	for ((it) = r_rbtree_last (&tree->root->node); r_rbtree_iter_has(&it) && (dat = r_rbtree_iter_get (&it, RContRBNode, node)->data); r_rbtree_iter_prev (&(it)))
#define r_rbtree_foreach(root, it, data, struc, rb) \
	for ((it) = r_rbtree_first (root); r_rbtree_iter_has(&it) && (data = r_rbtree_iter_get (&it, struc, rb)); r_rbtree_iter_next (&(it)))
#define r_rbtree_foreach_prev(root, it, data, struc, rb) \
	for ((it) = r_rbtree_last (root); r_rbtree_iter_has(&it) && (data = r_rbtree_iter_get (&it, struc, rb)); r_rbtree_iter_prev (&(it)))
#define r_rbtree_iter_get(it, struc, rb) (container_of ((it)->path[(it)->len-1], struc, rb))
#define r_rbtree_iter_has(it) ((it)->len)
#define r_rbtree_iter_while(it, data, struc, rb) \
	for (; r_rbtree_iter_has(&it) && (data = r_rbtree_iter_get (&it, struc, rb)); r_rbtree_iter_next (&(it)))
#define r_rbtree_iter_while_prev(it, data, struc, rb) \
	for (; r_rbtree_iter_has(&it) && (data = r_rbtree_iter_get (&it, struc, rb)); r_rbtree_iter_prev (&(it)))
#define R_MALLOC_GLOBAL 0
#define R_MALLOC_WRAPPER 0
#define _R_UTIL_ALLOC_H_ 1
#define _r_calloc r_calloc
#define _r_free r_free
#define _r_malloc r_malloc
#define _r_realloc r_realloc
#define r_calloc(x,y) calloc((x),(y))
#define r_free(x) free((x))
#define r_malloc(x) malloc((x))
#define r_realloc(x,y) realloc((x),(y))

#define H_LOG_(loglevel, fmt, ...)

#define R_CHECKS_LEVEL 2
#define R_FUNCTION ((const char*) (__PRETTY_FUNCTION__))
#define R_STATIC_ASSERT(x)\
	switch (0) {\
	case 0:\
	case (x):;\
	}
#define r_return_if_fail(expr) do { assert (expr); } while(0)
#define r_return_if_reached() \
	do { \
		H_LOG_ (R_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached\n", "__FILE__", "__LINE__", R_FUNCTION); \
		return; \
	} while (0)
#define r_return_val_if_fail(expr, val) do { assert (expr); } while(0)
#define r_return_val_if_reached(val) \
	do { \
		H_LOG_ (R_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached\n", "__FILE__", "__LINE__", R_FUNCTION); \
		return (val); \
	} while (0)
#define r_warn_if_fail(expr) \
	do { \
		if (!(expr)) { \
			r_assert_log (R_LOGLVL_WARN, "WARNING (%s:%d):%s%s runtime check failed: (%s)\n", \
				"__FILE__", "__LINE__", R_FUNCTION, R_FUNCTION[0] ? ":" : "", #expr); \
		} \
	} while (0)
#define r_warn_if_reached() \
	do { \
		r_assert_log (R_LOGLVL_WARN, "(%s:%d):%s%s code should not be reached\n", \
			"__FILE__", "__LINE__", R_FUNCTION, R_FUNCTION[0] ? ":" : ""); \
	} while (0)


#define r_pvector_foreach(vec, it) \
	for (it = (void **)(vec)->v.a; it != (void **)(vec)->v.a + (vec)->v.len; it++)
#define r_pvector_foreach_prev(vec, it) \
	for (it = ((vec)->v.len == 0 ? NULL : (void **)(vec)->v.a + (vec)->v.len - 1); it != NULL && it != (void **)(vec)->v.a - 1; it--)
#define r_pvector_lower_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->v.len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if ((cmp ((x), ((void **)(vec)->v.a)[m])) > 0) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0) \

#define r_vector_enumerate(vec, it, i) \
	if (!r_vector_empty (vec)) \
		for (it = (void *)(vec)->a, i = 0; i < (vec)->len; it = (void *)((char *)it + (vec)->elem_size), i++)
#define r_vector_foreach(vec, it) \
	if (!r_vector_empty (vec)) \
		for (it = (void *)(vec)->a; (char *)it != (char *)(vec)->a + ((vec)->len * (vec)->elem_size); it = (void *)((char *)it + (vec)->elem_size))
#define r_vector_lower_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if ((cmp (x, ((char *)(vec)->a + (vec)->elem_size * m))) > 0) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0) \

#define HT_TYPE 2

#define HAVE_PTHREAD 0
#define HAVE_PTHREAD_NP 0

#define R_TH_COND_T CONDITION_VARIABLE
#define R_TH_FUNCTION(x) RThreadFunctionRet (*x)(struct r_th_t *)
#define R_TH_LOCK_T CRITICAL_SECTION
#define R_TH_SEM_T HANDLE
#define R_TH_TID HANDLE



#define r_skiplist_foreach(list, it, pos)\
	if (list)\
		for (it = list->head->forward[0]; it != list->head && ((pos = it->data) || 1); it = it->forward[0])
#define r_skiplist_foreach_safe(list, it, tmp, pos)\
	if (list)\
		for (it = list->head->forward[0]; it != list->head && ((pos = it->data) || 1) && ((tmp = it->forward[0]) || 1); it = tmp)
#define r_skiplist_islast(list, el) (el->forward[0] == list->head)
#define r_skiplist_length(list) (list->size)
#define R_GETOPT_H 1

#define MSG_DONTWAIT 0

#define R_INVALID_SOCKET INVALID_SOCKET
#define R_RUN_PROFILE_NARGS 512
#define R_SOCKET_PROTO_TCP IPPROTO_TCP
#define R_SOCKET_PROTO_UDP IPPROTO_UDP
#define R_SOCKET_PROTO_UNIX 0x1337
#define SD_BOTH 2
#define SD_RECEIVE  0
#define SD_SEND 1
#define r_socket_connect_tcp(a, b, c, d) r_socket_connect (a, b, c, R_SOCKET_PROTO_TCP, d)
#define r_socket_connect_udp(a, b, c, d) r_socket_connect (a, b, c, R_SOCKET_PROTO_UDP, d)
#define r_socket_connect_unix(a, b) r_socket_connect (a, b, b, R_SOCKET_PROTO_UNIX, 0)

