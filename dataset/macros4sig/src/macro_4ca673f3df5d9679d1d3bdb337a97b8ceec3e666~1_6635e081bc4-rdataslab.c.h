



#include<sys/types.h>









#include<sys/cdefs.h>




#define DNS_RDATASLAB_EXACT 0x2
#define DNS_RDATASLAB_FORCE 0x1
#define DNS_RDATASLAB_H 1
#define DNS_TYPES_H 1
#define DNS_RDATASET_H 1
#define DNS_RDATASET_VALID(set)	       ISC_MAGIC_VALID(set, DNS_RDATASET_MAGIC)
#define DNS_RDATA_H 1
#define DNS_RDATA_INIT { NULL, 0, 0, 0, 0, {(void*)(-1), (void *)(-1)}}
#define DNS_NAME_COUNTLABELS(n) \
	((n)->labels)
#define DNS_NAME_FORMATSIZE (DNS_NAME_MAXTEXT + 1)
#define DNS_NAME_H 1
#define DNS_NAME_INIT(n, o) \
do { \
	(n)->magic = DNS_NAME_MAGIC; \
	(n)->ndata = NULL; \
	(n)->length = 0; \
	(n)->labels = 0; \
	(n)->attributes = 0; \
	(n)->offsets = (o); \
	(n)->buffer = NULL; \
	ISC_LINK_INIT((n), link); \
	ISC_LIST_INIT((n)->list); \
} while (0)
#define DNS_NAME_ISABSOLUTE(n) \
	(((n)->attributes & DNS_NAMEATTR_ABSOLUTE) != 0 ? ISC_TRUE : ISC_FALSE)
#define DNS_NAME_MAXTEXT 1023
#define DNS_NAME_MAXWIRE 255
#define DNS_NAME_RESET(n) \
do { \
	(n)->ndata = NULL; \
	(n)->length = 0; \
	(n)->labels = 0; \
	(n)->attributes &= ~DNS_NAMEATTR_ABSOLUTE; \
	if ((n)->buffer != NULL) \
		isc_buffer_clear((n)->buffer); \
} while (0)
#define DNS_NAME_SETBUFFER(n, b) \
	(n)->buffer = (b)
#define DNS_NAME_SPLIT(n, l, p, s) \
do { \
	dns_name_t *_n = (n); \
	dns_name_t *_p = (p); \
	dns_name_t *_s = (s); \
	unsigned int _l = (l); \
	if (_p != NULL) \
		dns_name_getlabelsequence(_n, 0, _n->labels - _l, _p); \
	if (_s != NULL) \
		dns_name_getlabelsequence(_n, _n->labels - _l, _l, _s); \
} while (0)
#define DNS_NAME_TOREGION(n, r) \
do { \
	(r)->base = (n)->ndata; \
	(r)->length = (n)->length; \
} while (0)
#define dns_name_countlabels(n)		DNS_NAME_COUNTLABELS(n)
#define dns_name_init(n, o)		DNS_NAME_INIT(n, o)
#define dns_name_isabsolute(n)		DNS_NAME_ISABSOLUTE(n)
#define dns_name_reset(n)		DNS_NAME_RESET(n)
#define dns_name_setbuffer(n, b)	DNS_NAME_SETBUFFER(n, b)
#define dns_name_split(n, l, p, s)	DNS_NAME_SPLIT(n, l, p, s)
#define dns_name_toregion(n, r)		DNS_NAME_TOREGION(n, r)

#define clearerr(p)	(!__isthreaded ? __sclearerr(p) : (clearerr)(p))
#define feof(p)		(!__isthreaded ? __sfeof(p) : (feof)(p))
#define ferror(p)	(!__isthreaded ? __sferror(p) : (ferror)(p))
#define fileno(p)	(!__isthreaded ? __sfileno(p) : (fileno)(p))
#define getc(fp)	(!__isthreaded ? __sgetc(fp) : (getc)(fp))
#define getchar_unlocked()	getc_unlocked(stdin)
#define putc(x, fp)	(!__isthreaded ? __sputc(x, fp) : (putc)(x, fp))
#define putc_unlocked(x, fp)	__sputc(x, fp)
#define putchar_unlocked(c)	putc_unlocked(c, stdout)
#define DNS_RESULT_H 1
#define DNS_RESULT_ISRCODE(result) \
	(ISC_RESULTCLASS_INCLASS(ISC_RESULTCLASS_DNSRCODE, (result)))



