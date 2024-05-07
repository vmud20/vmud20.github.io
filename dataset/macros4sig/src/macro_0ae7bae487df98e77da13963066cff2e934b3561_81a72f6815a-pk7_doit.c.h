

#include<sys/cdefs.h>


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
