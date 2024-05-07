#include<sys/mman.h>
#include<sys/types.h>
#include<unistd.h>
#include<fcntl.h>

#include<sys/param.h>

#include<sys/stat.h>
#include<sys/cdefs.h>

#include<sys/unistd.h>

#include<netinet/in.h>


#define F_LOCK          1	
#define F_TEST          3	
#define F_TLOCK         2	
#define F_ULOCK         0	





#  define ftrylockfile(fp)		(0)

#define putc(x, fp)	__sputc(x, fp)
#define putc_unlocked(x, fp)	__sputc(x, fp)
#define putchar_unlocked(c)	putc_unlocked(c, stdout)
