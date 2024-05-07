#include<stddef.h>

#include<sched.h>
#include<sys/time.h>


#include<stdlib.h>
#include<errno.h>
#include<stdarg.h>

#include<semaphore.h>
#include<sys/types.h>
#include<time.h>
#include<limits.h>


#include<inttypes.h>
#include<stdio.h>
#include<sys/stat.h>
#include<sys/socket.h>
#include<stdbool.h>



#include<signal.h>
#include<stdint.h>
#include<dirent.h>
#include<sys/wait.h>
#include<pthread.h>
#include<unistd.h>

#include<fcntl.h>
#include<ctype.h>
#include<sys/ioctl.h>
#include<string.h>


#include<assert.h>
#include<sys/param.h>
#include<wchar.h>


#include<math.h>

#include<termios.h>

#define ARROW_LEFT 9
#define ARROW_RIGHT 8
#define CONS_BUFSZ 0x4f00
#define CONS_COLORS_SIZE 21
#define CONS_MAX_ATTR_SZ 16
#define CONS_PALETTE_SIZE 22
#define CORNER_BL 5
#define CORNER_BR 4
#define CORNER_TL 6
#define CORNER_TR 6
#define Color_BBGBLACK   Color_BGGRAY
#define Color_BBGBLUE    "\x1b[104m"
#define Color_BBGCYAN    "\x1b[106m"
#define Color_BBGGREEN   "\x1b[102m"
#define Color_BBGMAGENTA "\x1b[105m"
#define Color_BBGRED     "\x1b[101m"
#define Color_BBGWHITE   "\x1b[107m"
#define Color_BBGYELLOW  "\x1b[103m"
#define Color_BBLACK     Color_GRAY
#define Color_BBLUE      "\x1b[94m"
#define Color_BCYAN      "\x1b[96m"
#define Color_BGBLACK    "\x1b[40m"
#define Color_BGBLUE     "\x1b[44m"
#define Color_BGCYAN     "\x1b[46m"
#define Color_BGGRAY     "\x1b[100m"
#define Color_BGGREEN    "\x1b[42m"
#define Color_BGMAGENTA  "\x1b[45m"
#define Color_BGRED      "\x1b[41m"
#define Color_BGREEN     "\x1b[92m"
#define Color_BGWHITE    "\x1b[47m"
#define Color_BGYELLOW   "\x1b[43m"
#define Color_BLACK      "\x1b[30m"
#define Color_BLINK        "\x1b[5m"
#define Color_BLUE       "\x1b[34m"
#define Color_BMAGENTA   "\x1b[95m"
#define Color_BRED       "\x1b[91m"
#define Color_BWHITE     "\x1b[97m"
#define Color_BYELLOW    "\x1b[93m"
#define Color_CYAN       "\x1b[36m"
#define Color_GRAY       "\x1b[90m"
#define Color_GREEN      "\x1b[32m"
#define Color_INVERT       "\x1b[7m"
#define Color_INVERT_RESET "\x1b[27m"
#define Color_MAGENTA    "\x1b[35m"
#define Color_RED        "\x1b[31m"
#define Color_RESET      "\x1b[0m" 
#define Color_RESET_BG   "\x1b[49m" 
#define Color_RESET_NOBG "\x1b[27;22;24;25;28;39m"  
#define Color_RESET_TERMINAL  "\x1b" "c\x1b(K\x1b[0m\x1b[J\x1b[?25h"
#define Color_WHITE      "\x1b[37m"
#define Color_YELLOW     "\x1b[33m"
#define Colors_PLAIN { \
	Color_BLACK, Color_RED, Color_WHITE, \
	Color_GREEN, Color_MAGENTA, Color_YELLOW, \
	Color_CYAN, Color_BLUE, Color_GRAY}
#define DOT_STYLE_BACKEDGE 2
#define DOT_STYLE_CONDITIONAL 1
#define DOT_STYLE_NORMAL 0
# define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
# define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#define HUD_BUF_SIZE 512
#define LINE_CROSS 1
#define LINE_HORIZ 2
#define LINE_UP 3
#define LINE_VERT 0

#define RCOLOR(a, r, g, b, bgr, bgg, bgb, id16) {0, a, r, g, b, bgr, bgg, bgb, id16}
#define RColor_BBGBLACK   RCOLOR(ALPHA_BG, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00,  8)
#define RColor_BBGBLUE    RCOLOR(ALPHA_BG, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 12)
#define RColor_BBGCYAN    RCOLOR(ALPHA_BG, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 14)
#define RColor_BBGGREEN   RCOLOR(ALPHA_BG, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 10)
#define RColor_BBGMAGENTA RCOLOR(ALPHA_BG, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 13)
#define RColor_BBGRED     RCOLOR(ALPHA_BG, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,  9)
#define RColor_BBGWHITE   RCOLOR(ALPHA_BG, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 15)
#define RColor_BBGYELLOW  RCOLOR(ALPHA_BG, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 11)
#define RColor_BBLACK     RCOLOR(ALPHA_FG, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00,  8)
#define RColor_BBLUE      RCOLOR(ALPHA_FG, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 12)
#define RColor_BCYAN      RCOLOR(ALPHA_FG, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 14)
#define RColor_BGBLACK    RCOLOR(ALPHA_BG, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0)
#define RColor_BGBLUE     RCOLOR(ALPHA_BG, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,  4)
#define RColor_BGCYAN     RCOLOR(ALPHA_BG, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00,  6)
#define RColor_BGGRAY     RColor_BBGBLACK
#define RColor_BGGREEN    RCOLOR(ALPHA_BG, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,  2)
#define RColor_BGMAGENTA  RCOLOR(ALPHA_BG, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00,  5)
#define RColor_BGRED      RCOLOR(ALPHA_BG, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,  1)
#define RColor_BGREEN     RCOLOR(ALPHA_FG, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 10)
#define RColor_BGWHITE    RCOLOR(ALPHA_BG, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00,  7)
#define RColor_BGYELLOW   RCOLOR(ALPHA_BG, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00,  3)
#define RColor_BLACK      RCOLOR(ALPHA_FG, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0)
#define RColor_BLUE       RCOLOR(ALPHA_FG, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,  4)
#define RColor_BMAGENTA   RCOLOR(ALPHA_FG, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 13)
#define RColor_BRED       RCOLOR(ALPHA_FG, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,  9)
#define RColor_BWHITE     RCOLOR(ALPHA_FG, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 15)
#define RColor_BYELLOW    RCOLOR(ALPHA_FG, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 11)
#define RColor_CYAN       RCOLOR(ALPHA_FG, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00,  6)
#define RColor_GRAY       RColor_BBLACK
#define RColor_GREEN      RCOLOR(ALPHA_FG, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,  2)
#define RColor_MAGENTA    RCOLOR(ALPHA_FG, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00,  5)
#define RColor_NULL       RCOLOR(0x00,     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, -1)
#define RColor_RED        RCOLOR(ALPHA_FG, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,  1)
#define RColor_WHITE      RCOLOR(ALPHA_FG, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00,  7)
#define RColor_YELLOW     RCOLOR(ALPHA_FG, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00,  3)
#define RUNECODESTR_ARROW_LEFT "\xcd"
#define RUNECODESTR_ARROW_RIGHT "\xcc"
#define RUNECODESTR_CORNER_BL "\xcb"
#define RUNECODESTR_CORNER_BR "\xca"
#define RUNECODESTR_CORNER_TL "\xcf"
#define RUNECODESTR_CORNER_TR "\xd0"
#define RUNECODESTR_CURVE_CORNER_BL "\xd5"
#define RUNECODESTR_CURVE_CORNER_BR "\xd4"
#define RUNECODESTR_CURVE_CORNER_TL "\xd2"
#define RUNECODESTR_CURVE_CORNER_TR "\xd3"
#define RUNECODESTR_LINE_CROSS "\xc9"
#define RUNECODESTR_LINE_HORIZ "\xce"
#define RUNECODESTR_LINE_UP "\xd1"
#define RUNECODESTR_LINE_VERT "\xc8"
#define RUNECODESTR_MAX 0xd5
#define RUNECODESTR_MIN 0xc8 
#define RUNECODE_ARROW_LEFT 0xcd
#define RUNECODE_ARROW_RIGHT 0xcc
#define RUNECODE_CORNER_BL 0xcb
#define RUNECODE_CORNER_BR 0xca
#define RUNECODE_CORNER_TL 0xcf
#define RUNECODE_CORNER_TR 0xd0
#define RUNECODE_CURVE_CORNER_BL 0xd5
#define RUNECODE_CURVE_CORNER_BR 0xd4
#define RUNECODE_CURVE_CORNER_TL 0xd2
#define RUNECODE_CURVE_CORNER_TR 0xd3
#define RUNECODE_LINE_CROSS 0xc9
#define RUNECODE_LINE_HORIZ 0xce
#define RUNECODE_LINE_UP 0xd1
#define RUNECODE_LINE_VERT 0xc8
#define RUNECODE_MAX 0xd6
#define RUNECODE_MIN 0xc8 
#define RUNE_ARROW_LEFT "<"
#define RUNE_ARROW_RIGHT ">"
#define RUNE_CORNER_BL "└"
#define RUNE_CORNER_BR "┘"
#define RUNE_CORNER_TL "┌"
#define RUNE_CORNER_TR "┐"
#define RUNE_CURVE_CORNER_BL "╰"
#define RUNE_CURVE_CORNER_BR "╯"
#define RUNE_CURVE_CORNER_TL "╭"
#define RUNE_CURVE_CORNER_TR "╮"
#define RUNE_LINE_CROSS "┼" 
#define RUNE_LINE_HORIZ "─"
#define RUNE_LINE_UP "↑"
#define RUNE_LINE_VERT "│"
#define RUNE_LONG_LINE_HORIZ "―"
#define R_CONS_CLEAR_FROM_CURSOR_TO_END "\x1b[0J\r"
#define R_CONS_CLEAR_FROM_CURSOR_TO_EOL "\x1b[0K\r"
#define R_CONS_CLEAR_LINE "\x1b[2K\r"
#define R_CONS_CLEAR_SCREEN "\x1b[2J\r"
#define R_CONS_CMD_DEPTH 100
#define R_CONS_CURSOR_DOWN "\x1b[B"
#define R_CONS_CURSOR_LEFT "\x1b[D"
#define R_CONS_CURSOR_RESTORE "\x1b[u"
#define R_CONS_CURSOR_RIGHT "\x1b[C"
#define R_CONS_CURSOR_SAVE "\x1b[s"
#define R_CONS_CURSOR_UP "\x1b[A"
#define R_CONS_GET_CURSOR_POSITION "\x1b[6n"
#define R_CONS_GREP_COUNT 10
#define R_CONS_GREP_TOKENS 64
#define R_CONS_GREP_WORDS 10
#define R_CONS_GREP_WORD_SIZE 64
#define R_CONS_INVERT(x,y) (y? (x?Color_INVERT: Color_INVERT_RESET): (x?"[":"]"))
#define R_CONS_KEY_ESC 0x1b
#define R_CONS_KEY_F1 0xf1
#define R_CONS_KEY_F10 0xfa
#define R_CONS_KEY_F11 0xfb
#define R_CONS_KEY_F12 0xfc
#define R_CONS_KEY_F2 0xf2
#define R_CONS_KEY_F3 0xf3
#define R_CONS_KEY_F4 0xf4
#define R_CONS_KEY_F5 0xf5
#define R_CONS_KEY_F6 0xf6
#define R_CONS_KEY_F7 0xf7
#define R_CONS_KEY_F8 0xf8
#define R_CONS_KEY_F9 0xf9
#define R_EDGES_X_INC 4
#define R_LINE_BUFSIZE 4096
#define R_LINE_HISTSIZE 256
#define R_SELWIDGET_DIR_DOWN 1
#define R_SELWIDGET_DIR_UP 0
#define R_SELWIDGET_MAXH 15
#define R_SELWIDGET_MAXW 30
#define R_UTF8_BLOCK "\u2588"
#define R_UTF8_CIRCLE "\u25EF"
#define R_UTF8_DOOR "🚪"
#define R_UTF8_KEYBOARD "⌨"
#define R_UTF8_LEFT_POINTING_MAGNIFYING_GLASS "🔍"
#define R_UTF8_POLICE_CARS_REVOLVING_LIGHT "🚨"
#define R_UTF8_SEE_NO_EVIL_MONKEY "🙈"
#define R_UTF8_SKULL_AND_CROSSBONES "☠"
#define R_UTF8_VS16 "\xef\xb8\x8f"
#define R_UTF8_WHITE_HEAVY_CHECK_MARK "✅"
#define STR_IS_NULL(x) (!x || !x[0])
#define r_cons_print(x) r_cons_strcat (x)

#define r_pvector_foreach(vec, it) \
	if ((vec)->v.len > 0) \
	for (it = (void **)(vec)->v.a; it != (void **)(vec)->v.a + (vec)->v.len; it++)
#define r_pvector_foreach_prev(vec, it) \
	if ((vec)->v.len > 0) \
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
#define r_vector_foreach_prev(vec, it) \
	if (!r_vector_empty (vec)) \
		for (it = (void *)((char *)(vec)->a + (((vec)->len - 1)* (vec)->elem_size)); (char *)it != (char *)(vec)->a; it = (void *)((char *)it - (vec)->elem_size))
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

#define r_vector_upper_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->len, m; \
		for (i = 0; i < h; ) { \
			m = i + ((h - i) >> 1); \
			if ((cmp (x, ((char *)(vec)->a + (vec)->elem_size * m))) < 0) { \
				h = m; \
			} else { \
				i = m + 1; \
			} \
		} \
	} while (0) \

#define H_LOG_(loglevel, fmt, ...)

#define R_CHECKS_LEVEL 2
#define R_FUNCTION ((const char*) (__PRETTY_FUNCTION__))
#define R_STATIC_ASSERT(x) switch (0) { case 0: case (x):; }
#define r_return_if_fail(expr) do { assert (expr); } while(0)
#define r_return_if_reached() \
	do { \
		H_LOG_ (R_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached", "__FILE__", "__LINE__", R_FUNCTION); \
		return; \
	} while (0)
#define r_return_val_if_fail(expr, val) do { assert (expr); } while(0)
#define r_return_val_if_reached(val) \
	do { \
		H_LOG_ (R_LOGLVL_ERROR, "file %s: line %d (%s): should not be reached", "__FILE__", "__LINE__", R_FUNCTION); \
		return (val); \
	} while (0)
#define r_warn_if_fail(expr) \
	do { \
		if (!(expr)) { \
			r_assert_log (R_LOGLVL_WARN, R_LOG_ORIGIN, "WARNING (%s:%d):%s%s runtime check failed: (%s)", \
				"__FILE__", "__LINE__", R_FUNCTION, R_FUNCTION[0] ? ":" : "", #expr); \
		} \
	} while (0)
#define r_warn_if_reached() \
	do { \
		r_assert_log (R_LOGLVL_WARN, R_LOG_ORIGIN, "(%s:%d):%s%s code should not be reached", \
			"__FILE__", "__LINE__", R_FUNCTION, R_FUNCTION[0] ? ":" : ""); \
	} while (0)
#define BITS2BYTES(x) (((x)/8)+(((x)%8)?1:0))
#define CLOCK_MONOTONIC 0
#define CTA(x,y,z) (x+CTO(y,z))
#define CTI(x,y,z) (*((size_t*)(CTA(x,y,z))))
#define CTO(y,z) ((size_t) &((y*)0)->z)
#define CTS(x,y,z,t,v) {t* _=(t*)CTA(x,y,z);*_=v;}













#define EPRINT_VAR_WRAPPER(name, fmt, ...) {				\
	char *eprint_env = r_sys_getenv ("R2_NO_EPRINT_MACROS");	\
	if (!eprint_env || strcmp (eprint_env, "1")) {			\
		eprintf (#name ": " fmt "\n", __VA_ARGS__);		\
	}								\
	free (eprint_env);						\
}
#define FS '\\'
  #define FUNC_ATTR_ALLOC_ALIGN(x) __attribute__((alloc_align(x)))
  #define FUNC_ATTR_ALLOC_SIZE(x) __attribute__((alloc_size(x)))
  #define FUNC_ATTR_ALLOC_SIZE_PROD(x,y) __attribute__((alloc_size(x,y)))
  #define FUNC_ATTR_ALWAYS_INLINE __attribute__((always_inline))
  #define FUNC_ATTR_CONST __attribute__((const))
  #define FUNC_ATTR_MALLOC __attribute__((malloc))
  #define FUNC_ATTR_PURE __attribute__ ((pure))
  #define FUNC_ATTR_USED __attribute__((used))
  #define FUNC_ATTR_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
# define HAS_CLOCK_MONOTONIC 0
#  define HAS_CLOCK_NANOSLEEP 1
#define HAVE_PTY 0
#define HAVE_REGEXP 0
#define HAVE_SYSTEM 0
#define HHXFMT  "x"
#define LDBLFMT "f"
#define LIBC_HAVE_FORK 1
#define LIBC_HAVE_PLEDGE 1
#define LIBC_HAVE_PRIV_SET 1
#define LIBC_HAVE_PTRACE 0
#define LIBC_HAVE_SYSTEM 0
#define MONOTONIC_APPLE (__APPLE__ && CLOCK_MONOTONIC_RAW)
#define MONOTONIC_FREEBSD (__FreeBSD__ && __FreeBSD_version >= 1101000)
#define MONOTONIC_LINUX (__linux__ && _POSIX_C_SOURCE >= 199309L)
#define MONOTONIC_NETBSD (__NetBSD__ && __NetBSD_Version__ >= 700000000)
#define MONOTONIC_UNIX (MONOTONIC_APPLE || MONOTONIC_LINUX || MONOTONIC_FREEBSD || MONOTONIC_NETBSD)
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
#define PFMTDPTR "td"
#define PFMTSZd "Id"
#define PFMTSZo "Io"
#define PFMTSZu "Iu"
#define PFMTSZx "Ix"
#define R2_DEBUG_EPRINT 0

  #define R2__BSD__ 0
  #define R2__UNIX__ 1
  #define R2__WINDOWS__ 1
    #define R_API __declspec(dllexport)
#define R_ARRAY_SIZE(x) (sizeof (x) / sizeof ((x)[0]))
#define R_BIT_CHK(x,y) (*(x) & (1<<(y)))
#define R_BIT_SET(x,y) (((ut8*)x)[y>>4] |= (1<<(y&0xf)))
#define R_BIT_TOGGLE(x, y) ( R_BIT_CHK (x, y) ? \
		R_BIT_UNSET (x, y): R_BIT_SET (x, y))
#define R_BIT_UNSET(x,y) (((ut8*)x)[y>>4] &= ~(1<<(y&0xf)))
#define R_BORROW 
#  define R_DEPRECATE
#  define R_DEPRECATED __attribute__((deprecated))
#define R_FREE(x) { free((void *)x); x = NULL; }

#define R_HIDDEN __attribute__((visibility("hidden")))
#define R_IFNULL(x) 
#define R_IN 
#define R_INOUT 

#define R_JOIN_2_PATHS(p1, p2) p1 R_SYS_DIR p2
#define R_JOIN_3_PATHS(p1, p2, p3) p1 R_SYS_DIR p2 R_SYS_DIR p3
#define R_JOIN_4_PATHS(p1, p2, p3, p4) p1 R_SYS_DIR p2 R_SYS_DIR p3 R_SYS_DIR p4
#define R_JOIN_5_PATHS(p1, p2, p3, p4, p5) p1 R_SYS_DIR p2 R_SYS_DIR p3 R_SYS_DIR p4 R_SYS_DIR p5
#define R_LIB_VERSION(x) \
R_API const char *x##_version(void) { return "" R2_GITTAP; }
#define R_LIB_VERSION_HEADER(x) \
R_API const char *x##_version(void)
#define R_MEM_ALIGN(x) ((void *)(size_t)(((ut64)(size_t)x) & 0xfffffffffffff000LL))
#define R_MODE_ARRAY 0x010
#define R_MODE_CLASSDUMP 0x040
#define R_MODE_EQUAL 0x080
#define R_MODE_JSON 0x008
#define R_MODE_PRINT 0x000
#define R_MODE_RADARE 0x001
#define R_MODE_SET 0x002
#define R_MODE_SIMPLE 0x004
#define R_MODE_SIMPLEST 0x020
#define R_NEW(x) (x*)malloc(sizeof (x))
#define R_NEW0(x) (x*)calloc(1,sizeof (x))
#define R_NEWCOPY(x,y) (x*)r_new_copy(sizeof (x), y)
#define R_NEWS(x,y) (x*)malloc(sizeof (x)*(y))
#define R_NEWS0(x,y) (x*)calloc(y,sizeof (x))
#define R_NEW_COPY(x,y) x=(void*)malloc(sizeof (y));memcpy(x,y,sizeof (y))
#define R_NONNULL 
#define R_NULLABLE 
#define R_OUT 
#define R_OWN 
#define R_PRINTF_CHECK(fmt, dots) __attribute__ ((format (printf, fmt, dots)))
#define R_PTR_ALIGN(v,t) \
	((char *)(((size_t)(v) ) \
	& ~(t - 1)))
#define R_PTR_ALIGN_NEXT(v,t) \
	((char *)(((size_t)(v) + (t - 1)) \
	& ~(t - 1)))
#define R_PTR_MOVE(d,s) d=s;s=NULL;
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
#define R_UNUSED_RESULT(x) if ((x)) {}
#  define R_WIP __attribute__((deprecated))
#define TARGET_OS_IPHONE 1
#define TODO(x) eprintf(__func__"  " x)
#  define UNUSED_FUNCTION(x) __attribute__((__unused__)) UNUSED_ ## x

#define ZERO_FILL(x) memset (&x, 0, sizeof (x))
#define _FILE_OFFSET_BITS 64

#define __KFBSD__ 1
#define __POWERPC__ 1

#define __func__ __FUNCTION__
#define __i386__ 1
#define __packed __attribute__((__packed__))
#define __x86_64__ 1
#define _perror(str,file,line,func) \
  { \
	  char buf[256]; \
	  snprintf(buf,sizeof (buf),"[%s:%d %s] %s",file,line,func,str); \
	  r_sys_perror_str(buf); \
  }
#define container_of(ptr, type, member) (ptr? ((type *)((char *)(ptr) - r_offsetof(type, member))): NULL)
#define eprintf(...) fprintf (stderr, __VA_ARGS__)
#define mips mips
#define perror(x) _perror(x,"__FILE__","__LINE__",__func__)
#define r_offsetof(type, member) offsetof(type, member)
#define r_sys_perror(x) _perror(x,"__FILE__","__LINE__",__func__)

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

#define ASCII_MAX 127
#define ASCII_MIN 32
#define B0000 0
#define B0001 1
#define B0010 2
#define B0011 3
#define B0100 4
#define B0101 5
#define B0110 6
#define B0111 7
#define B1000 8
#define B10000 16
#define B10001 17
#define B1001 9
#define B10010 18
#define B10011 19
#define B1010 10
#define B10100 20
#define B10101 21
#define B1011 11
#define B10110 22
#define B10111 23
#define B1100 12
#define B11000 24
#define B11001 25
#define B1101 13
#define B11010 26
#define B11011 27
#define B1110 14
#define B11100 28
#define B11101 29
#define B1111 15
#define B11110 30
#define B11111 31
#define B4(a,b,c,d) ((a<<12)|(b<<8)|(c<<4)|(d))
#define B_EVEN(x)        (((x) & 1) == 0)
#define B_IS_SET(x, n)   (((x) & (1ULL << (n)))? 1: 0)
#define B_ODD(x)         (!B_EVEN((x)))
#define B_SET(x, n)      ((x) |= (1ULL << (n)))
#define B_TOGGLE(x, n)   ((x) ^= (1ULL << (n)))
#define B_UNSET(x, n)    ((x) &= ~(1ULL << (n)))
#define DEBUGGER 0
#define F128_NAN  (strtold("NAN", NULL))
#define F128_NINF (-strtold("INF", NULL))
#define F128_PINF (strtold("INF", NULL))
#define F32_NAN   (strtof("NAN", NULL))
#define F32_NINF  (-strtof("INF", NULL))
#define F32_PINF  (strtof("INF", NULL))
#define F64_NAN   (strtod("NAN", NULL))
#define F64_NINF  (-strtod("INF", NULL))
#define F64_PINF  (strtod("INF", NULL))
#define HEAPTYPE(x) \
	static x* x##_new(x n) {\
		x *m = malloc(sizeof (x));\
		return m? *m = n, m: m; \
	}
#define INFINITY (1.0f/0.0f)
#define NAN (0.0f/0.0f)

#define R_ABS(x) (((x)<0)?-(x):(x))
# define R_ALIGNED(x) __declspec(align(x))
#define R_BETWEEN(x,y,z) (((y)>=(x)) && ((y)<=(z)))
#define R_BTW(x,y,z) (((x)>=(y))&&((y)<=(z)))?y:x
#define R_DIM(x,y,z) (((x)<(y))?(y):((x)>(z))?(z):(x))
#define R_DIRTY(x) (x)->is_dirty = true
#define R_DIRTY_VAR bool is_dirty
#define R_IGNORE_RETURN(x) if ((x)) {;}
#define R_IS_DIRTY(x) (x)->is_dirty
#define R_LIKELY(x) __builtin_expect((size_t)(x),1)
#define R_MAX(x,y) (((x)>(y))?(x):(y))

#define R_MIN(x,y) (((x)>(y))?(y):(x))

#define R_MUSTUSE __attribute__((warn_unused_result))
#define R_PACKED( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop) )
#define R_ROUND(x,y) ((x)%(y))?(x)+((y)-((x)%(y))):(x)
#define R_UNLIKELY(x) __builtin_expect((size_t)(x),0)
#define R_UNUSED __attribute__((__unused__))
#define R_UNWRAP2(a,b) ((a)? a->b: NULL)
#define R_UNWRAP3(a,b,c) ((a)? a->b? a->b->c: NULL: NULL)
#define R_UNWRAP4(a,b,c,d) ((a)? a->b? a->b->c? a->b->c->d: NULL: NULL: NULL)
#define R_UNWRAP5(a,b,c,d,e) ((a)? a->b? a->b->c? a->b->c->d? a->b->c->d->e: NULL: NULL: NULL: NULL)
#define R_UNWRAP6(a,b,c,d,e,f) ((a)? a->b? a->b->c? a->b->c->d? a->b->c->d->e? a->b->c->d->e: NULL, NULL: NULL: NULL: NULL)
#define R_WEAK __attribute__ ((weak))
#define SSZT_MAX  ST32_MAX
#define SSZT_MIN  ST32_MIN
#define ST16_MAX 0x7FFF
#define ST16_MIN (-ST16_MAX-1)
#define ST32_MAX 0x7FFFFFFF
#define ST32_MIN (-ST32_MAX-1)
#define ST64_MAX ((st64)0x7FFFFFFFFFFFFFFFULL)
#define ST64_MIN ((st64)(-ST64_MAX-1))
#define ST8_MAX  0x7F
#define ST8_MIN  (-ST8_MAX - 1)
#define SZT_MAX  UT32_MAX
#define SZT_MIN  UT32_MIN
#define UT16_ALIGN(x) (x + (x - (x % sizeof (ut16))))
#define UT16_GT0 0x8000U
#define UT16_MAX 0xFFFFU
#define UT16_MIN 0U
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
#define UT64_ALIGN(x) (x + (x - (x % sizeof (ut64))))
#define UT64_GT0 ((ut64)0x8000000000000000ULL)
#define UT64_LT0 ((ut64)0x7FFFFFFFFFFFFFFFULL)
#define UT64_MAX ((ut64)0xFFFFFFFFFFFFFFFFULL)
#define UT64_MIN 0ULL
#define UT8_GT0  0x80U
#define UT8_MAX  0xFFU
#define UT8_MIN  0x00U
#define cut8 const uint8_t
#define st16 int16_t
#define st32 int32_t
#define st64 int64_t
#define st8 int8_t
#define ut16 uint16_t
#define ut32 uint32_t
#define ut64 uint64_t
#define ut8 uint8_t

#define SIGNED_DIV_OVERFLOW_CHECK(overflow_name, type_base, type_mid, type_max) \
static inline bool overflow_name(type_base a, type_base b) { \
	return (!b || (a == type_mid && b == type_max)); \
}
#define SIGNED_MUL_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
static inline bool overflow_name(type_base a, type_base b) { \
	if (a > 0) { \
		if (b > 0) { return a > type_max / b; } \
		return b < type_min / a; \
	} \
	if (b > 0) { return a < type_min / b; } \
	return a && b < type_max / a; \
}
#define SSZT_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > SSIZE_MAX - (x))) || (((x) < 0) && (a) < SSIZE_MIN - (x)))
#define SSZT_SUB_OVFCHK(a,b) SSZT_ADD_OVFCHK(a,-(b))
#define ST16_ADD_OVFCHK(a,b) ((((b) > 0) && ((a) > ST16_MAX - (b))) || (((b) < 0) && ((a) < ST16_MIN - (b))))
#define ST16_SUB_OVFCHK(a,b) ST16_ADD_OVFCHK(a,-(b))
#define ST32_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST32_MAX - (x))) || (((x) < 0) && (a) < ST32_MIN - (x)))
#define ST32_SUB_OVFCHK(a,b) ST32_ADD_OVFCHK(a,-(b))
#define ST64_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST64_MAX - (x))) || (((x) < 0) && (a) < ST64_MIN - (x)))
#define ST64_SUB_OVFCHK(a,b) ST64_ADD_OVFCHK(a,-(b))
#define ST8_ADD_OVFCHK(a,x) ((((x) > 0) && ((a) > ST8_MAX - (x))) || ((x) < 0 && (a) < ST8_MIN - (x)))
#define ST8_SUB_OVFCHK(a,b) ST8_ADD_OVFCHK(a,-(b))
#define SZT_ADD_OVFCHK(x,y) ((SIZE_MAX - (x)) < (y))
#define SZT_SUB_OVFCHK(a,b) SZT_ADD_OVFCHK(a,-(b))
#define UNSIGNED_DIV_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
static inline bool overflow_name(type_base a, type_base b) { \
	(void)(a); \
	return !b; \
}
#define UNSIGNED_MUL_OVERFLOW_CHECK(overflow_name, type_base, type_min, type_max) \
static inline bool overflow_name(type_base a, type_base b) { \
	return (a > 0 && b > 0 && a > type_max / b); \
}
#define UT16_ADD_OVFCHK(x,y) ((UT16_MAX - (x)) < (y))
#define UT16_SUB_OVFCHK(a,b) UT16_ADD_OVFCHK(a,-(b))
#define UT32_ADD_OVFCHK(x,y) ((UT32_MAX - (x)) < (y))
#define UT32_SUB_OVFCHK(a,b) UT32_ADD_OVFCHK(a,-(b))
#define UT64_ADD_OVFCHK(x,y) ((UT64_MAX - (x)) < (y))
#define UT64_SUB_OVFCHK(a,b) UT64_ADD_OVFCHK(a,-(b))
#define UT8_ADD_OVFCHK(x,y) ((UT8_MAX - (x)) < (y))
#define UT8_SUB_OVFCHK(a,b) UT8_ADD_OVFCHK(a,-(b))

#define SHELL_PATH "/bin/sh"
#define TERMUX_PREFIX "/data/data/com.termux/files/usr"

#define R_SYS_BITS_CHECK(x, y) (bool)( \
	(((x) & R_SYS_BITS_MASK) == (y)) || \
	((((x) >> R_SYS_BITS_SIZE) & R_SYS_BITS_MASK) == (y)) || \
	((((x) >> (R_SYS_BITS_SIZE*2)) & R_SYS_BITS_MASK) == (y)) || \
	((((x) >> (R_SYS_BITS_SIZE*3)) & R_SYS_BITS_MASK) == (y)) \
)
#define R_SYS_BITS_MASK 0xff
#define R_SYS_BITS_PACK(x) (RSysBits)(x)
#define R_SYS_BITS_PACK1(x) (RSysBits)(x)
#define R_SYS_BITS_PACK2(x,y) (RSysBits)((x) | ((y)<<R_SYS_BITS_SIZE))
#define R_SYS_BITS_PACK3(x,y,z) (RSysBits)((x) | ((y)<<R_SYS_BITS_SIZE) | ((z) << (R_SYS_BITS_SIZE*2)))
#define R_SYS_BITS_PACK4(x,y,z,q) (RSysBits)((x) | ((y)<<R_SYS_BITS_SIZE) | ((z) << (R_SYS_BITS_SIZE*2)) | ((q) << (R_SYS_BITS_SIZE*3)) )
#define R_SYS_BITS_SIZE 8
#define R_SYS_DEVNULL "/dev/null"

#define W32_TCALL(name) name"W"
#define W32_TCHAR_FSTR "%S"
#    define r_sys_breakpoint() __asm__ volatile ("bkpt $0");
#define r_sys_conv_utf8_to_win(buf) r_utf8_to_utf16 (buf)
#define r_sys_conv_utf8_to_win_l(buf, len) r_utf8_to_utf16_l (buf, len)
#define r_sys_conv_win_to_utf8(buf) r_utf16_to_utf8 (buf)
#define r_sys_conv_win_to_utf8_l(buf, len) r_utf16_to_utf8_l ((wchar_t *)buf, len)
#define r_sys_mkdir_failed() (GetLastError () != ERROR_ALREADY_EXISTS)
#  define r_sys_trap() __asm__ __volatile__ (".word 0");


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
#define r_list_iter_cur(x) (x)->p
#define r_list_iter_free(x) (x)
#define r_list_iter_get(x) (x)->data; (x)=(x)->n
#define r_list_iter_next(x) ((x)? 1: 0)
#define r_list_iterator(x) (x)? (x)->head: NULL
#define r_list_push(x, y) r_list_append ((x), (y))
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

#define R_STR_DUP(x) (((x) != NULL) ? strdup ((x)) : NULL)

#define R_STR_ISEMPTY(x) (!(x) || !*(x))
#define R_STR_ISNOTEMPTY(x) ((x) && *(x))
#define r_str_array(x,y) ((y >= 0 && y < (sizeof (x) / sizeof (*(x))))?(x)[(y)]: "")
#define r_str_cat(x,y) memmove ((x) + strlen (x), (y), strlen (y) + 1);
#define r_str_cpy(x,y) memmove ((x), (y), strlen (y) + 1);
#define r_str_startswith r_str_startswith_inline
#define r_strf(s,...) (snprintf (strbuf, sizeof (strbuf), s, __VA_ARGS__)?strbuf: strbuf)
#define r_strf_buffer(s) char strbuf[s]
#define r_strf_var(n,s, f, ...) char n[s]; snprintf (n, s, f, __VA_ARGS__);


#define HAVE_CAPSICUM 1
#define R_SANDBOX_GRAIN_ALL (8|4|2|1)
#define R_SANDBOX_GRAIN_DISK (2)
#define R_SANDBOX_GRAIN_EXEC (8)
#define R_SANDBOX_GRAIN_FILES (4)
#define R_SANDBOX_GRAIN_NONE (0)
#define R_SANDBOX_GRAIN_SOCKET (1)


#define R_NUMCALC_STRSZ 1024

#define R_LOG(f,...) do {} while(0)
#define R_LOGLVL_DEFAULT R_LOGLVL_WARN
#define R_LOG_DEBUG(f,...) do {} while(0)
#define R_LOG_DISABLE 0
#define R_LOG_ERROR(f,...) do {} while(0)
#define R_LOG_FATAL(f,...) do {} while(0)

#define R_LOG_INFO(f,...) do {} while(0)
#define R_LOG_ORIGIN __FUNCTION__
#define R_LOG_SOURCE "__FILE__"
#define R_LOG_TODO(f,...) do {} while(0)
#define R_LOG_WARN(f,...) do {} while(0)
#define etrace(m) eprintf ("--> %s:%d : %s\n", __FUNCTION__, "__LINE__", m)


#define R_PJ_H 1
#define R_PRINT_JSON_DEPTH_LIMIT 128

#define R_STRBUF_SAFEGET(sb) (r_strbuf_get (sb) ? r_strbuf_get (sb) : "")
#define HAVE_PTHREAD 0
#define HAVE_PTHREAD_NP 0
# define HAVE_STDATOMIC_H 0
# define HAVE_TH_LOCAL 0

# define R_ATOMIC_BOOL int
#define R_CRITICAL_ENTER(x) r_th_lock_enter((x)->lock)
#define R_CRITICAL_LEAVE(x) r_th_lock_leave((x)->lock)
#define R_THREAD_LOCK_INIT {0}
#define R_TH_COND_T int
# define R_TH_LOCAL __thread
#define R_TH_LOCK_T int
#define R_TH_SEM_T int
#define R_TH_TID int
#define WANT_THREADS 1


