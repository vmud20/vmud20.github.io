

#include<sys/cdefs.h>
#include<stdlib.h>

#include<stddef.h>

#include<sys/types.h>



#define alloca(n) __builtin_alloca(n)



#define clearerr(p)	(!__isthreaded ? __sclearerr(p) : (clearerr)(p))
#define feof(p)		(!__isthreaded ? __sfeof(p) : (feof)(p))
#define ferror(p)	(!__isthreaded ? __sferror(p) : (ferror)(p))
#define fileno(p)	(!__isthreaded ? __sfileno(p) : (fileno)(p))
#define getc(fp)	(!__isthreaded ? __sgetc(fp) : (getc)(fp))

#define putc(x, fp)	(!__isthreaded ? __sputc(x, fp) : (putc)(x, fp))
#define putc_unlocked(x, fp)	__sputc(x, fp)
#define putchar_unlocked(c)	putc_unlocked(c, stdout)
#define OBJALLOC_ALIGN offsetof (struct objalloc_align, d)


#define objalloc_alloc(o, l) _objalloc_alloc ((o), (l))
#define offsetof(TYPE, MEMBER) ((unsigned long) &((TYPE *)0)->MEMBER)
# define ARG_UNUSED(NAME) NAME ATTRIBUTE_UNUSED
#  define ATTRIBUTE_ALIGNED_ALIGNOF(m) __attribute__ ((__aligned__ (__alignof__ (m))))
#  define ATTRIBUTE_FPTR_PRINTF(m, n) ATTRIBUTE_PRINTF(m, n)
# define ATTRIBUTE_FPTR_PRINTF_1 ATTRIBUTE_FPTR_PRINTF(1, 2)
# define ATTRIBUTE_FPTR_PRINTF_2 ATTRIBUTE_FPTR_PRINTF(2, 3)
# define ATTRIBUTE_FPTR_PRINTF_3 ATTRIBUTE_FPTR_PRINTF(3, 4)
# define ATTRIBUTE_FPTR_PRINTF_4 ATTRIBUTE_FPTR_PRINTF(4, 5)
# define ATTRIBUTE_FPTR_PRINTF_5 ATTRIBUTE_FPTR_PRINTF(5, 6)
#  define ATTRIBUTE_MALLOC __attribute__ ((__malloc__))
#  define ATTRIBUTE_NONNULL(m) __attribute__ ((__nonnull__ (m)))
#define ATTRIBUTE_NORETURN __attribute__ ((__noreturn__))
#  define ATTRIBUTE_NULL_PRINTF(m, n) __attribute__ ((__format__ (__printf__, m, n)))
# define ATTRIBUTE_NULL_PRINTF_1 ATTRIBUTE_NULL_PRINTF(1, 2)
# define ATTRIBUTE_NULL_PRINTF_2 ATTRIBUTE_NULL_PRINTF(2, 3)
# define ATTRIBUTE_NULL_PRINTF_3 ATTRIBUTE_NULL_PRINTF(3, 4)
# define ATTRIBUTE_NULL_PRINTF_4 ATTRIBUTE_NULL_PRINTF(4, 5)
# define ATTRIBUTE_NULL_PRINTF_5 ATTRIBUTE_NULL_PRINTF(5, 6)
#define ATTRIBUTE_PRINTF(m, n) __attribute__ ((__format__ (__printf__, m, n))) ATTRIBUTE_NONNULL(m)
#define ATTRIBUTE_PRINTF_1 ATTRIBUTE_PRINTF(1, 2)
#define ATTRIBUTE_PRINTF_2 ATTRIBUTE_PRINTF(2, 3)
#define ATTRIBUTE_PRINTF_3 ATTRIBUTE_PRINTF(3, 4)
#define ATTRIBUTE_PRINTF_4 ATTRIBUTE_PRINTF(4, 5)
#define ATTRIBUTE_PRINTF_5 ATTRIBUTE_PRINTF(5, 6)
#  define ATTRIBUTE_PURE __attribute__ ((__pure__))
#  define ATTRIBUTE_SENTINEL __attribute__ ((__sentinel__))
#define ATTRIBUTE_UNUSED __attribute__ ((__unused__))
#  define ATTRIBUTE_UNUSED_LABEL ATTRIBUTE_UNUSED

#define DEFUN(name, arglist, args)	name(args)
#define DEFUN_VOID(name)		name(void)

#define EXFUN(name, proto)		name proto
#define GCC_VERSION ("__GNUC__" * 1000 + "__GNUC_MINOR__")

#define PARAMS(ARGS)		ARGS
#define PROTO(type, name, arglist)	type name arglist

#define VA_CLOSE(AP)		} va_end(AP); }
#define VA_FIXEDARG(AP, T, N)	struct Qdmy
#define VA_OPEN(AP, VAR)	{ va_list AP; va_start(AP, VAR); { struct Qdmy
#define VA_START(VA_LIST, VAR)	va_start(VA_LIST, VAR)

#define VPARAMS(ARGS)		ARGS
# define __attribute__(x)

#  define inline __inline__   


