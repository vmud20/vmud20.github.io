






#include<string.h>












#include<errno.h>



#include<sys/cdefs.h>
#include<stdlib.h>







#define DEC32(a)	((a)=((a)-1)&0xffffffffL)
#define EXPLICIT_CHAR2_CURVE_TYPE  2
#define EXPLICIT_PRIME_CURVE_TYPE  1   
#define FP_ICC  (int (*)(const void *,const void *))

#define IMPLEMENT_dtls1_meth_func(func_name, s_accept, s_connect, s_get_meth) \
SSL_METHOD *func_name(void)  \
	{ \
	static SSL_METHOD func_name##_data= { \
		DTLS1_VERSION, \
		dtls1_new, \
		dtls1_clear, \
		dtls1_free, \
		s_accept, \
		s_connect, \
		ssl3_read, \
		ssl3_peek, \
		ssl3_write, \
		ssl3_shutdown, \
		ssl3_renegotiate, \
		ssl3_renegotiate_check, \
		dtls1_get_message, \
		dtls1_read_bytes, \
		dtls1_write_app_data_bytes, \
		dtls1_dispatch_alert, \
		dtls1_ctrl, \
		ssl3_ctx_ctrl, \
		ssl3_get_cipher_by_char, \
		ssl3_put_cipher_by_char, \
		ssl3_pending, \
		ssl3_num_ciphers, \
		dtls1_get_cipher, \
		s_get_meth, \
		dtls1_default_timeout, \
		&DTLSv1_enc_data, \
		ssl_undefined_void_function, \
		ssl3_callback_ctrl, \
		ssl3_ctx_callback_ctrl, \
	}; \
	return &func_name##_data; \
	}
#define IMPLEMENT_ssl23_meth_func(func_name, s_accept, s_connect, s_get_meth) \
SSL_METHOD *func_name(void)  \
	{ \
	static SSL_METHOD func_name##_data= { \
	TLS1_VERSION, \
	tls1_new, \
	tls1_clear, \
	tls1_free, \
	s_accept, \
	s_connect, \
	ssl23_read, \
	ssl23_peek, \
	ssl23_write, \
	ssl_undefined_function, \
	ssl_undefined_function, \
	ssl_ok, \
	ssl3_get_message, \
	ssl3_read_bytes, \
	ssl3_write_bytes, \
	ssl3_dispatch_alert, \
	ssl3_ctrl, \
	ssl3_ctx_ctrl, \
	ssl23_get_cipher_by_char, \
	ssl23_put_cipher_by_char, \
	ssl_undefined_const_function, \
	ssl23_num_ciphers, \
	ssl23_get_cipher, \
	s_get_meth, \
	ssl23_default_timeout, \
	&ssl3_undef_enc_method, \
	ssl_undefined_void_function, \
	ssl3_callback_ctrl, \
	ssl3_ctx_callback_ctrl, \
	}; \
	return &func_name##_data; \
	}
#define IMPLEMENT_ssl2_meth_func(func_name, s_accept, s_connect, s_get_meth) \
SSL_METHOD *func_name(void)  \
	{ \
	static SSL_METHOD func_name##_data= { \
		SSL2_VERSION, \
		ssl2_new,	 \
		ssl2_clear,	 \
		ssl2_free,	 \
		s_accept, \
		s_connect, \
		ssl2_read, \
		ssl2_peek, \
		ssl2_write, \
		ssl2_shutdown, \
		ssl_ok,	 \
		ssl_ok,	 \
		NULL,  \
		NULL,  \
		NULL,  \
		NULL,  \
		ssl2_ctrl,	 \
		ssl2_ctx_ctrl,	 \
		ssl2_get_cipher_by_char, \
		ssl2_put_cipher_by_char, \
		ssl2_pending, \
		ssl2_num_ciphers, \
		ssl2_get_cipher, \
		s_get_meth, \
		ssl2_default_timeout, \
		&ssl3_undef_enc_method, \
		ssl_undefined_void_function, \
		ssl2_callback_ctrl,	 \
		ssl2_ctx_callback_ctrl,	 \
	}; \
	return &func_name##_data; \
	}
#define IMPLEMENT_ssl3_meth_func(func_name, s_accept, s_connect, s_get_meth) \
SSL_METHOD *func_name(void)  \
	{ \
	static SSL_METHOD func_name##_data= { \
		SSL3_VERSION, \
		ssl3_new, \
		ssl3_clear, \
		ssl3_free, \
		s_accept, \
		s_connect, \
		ssl3_read, \
		ssl3_peek, \
		ssl3_write, \
		ssl3_shutdown, \
		ssl3_renegotiate, \
		ssl3_renegotiate_check, \
		ssl3_get_message, \
		ssl3_read_bytes, \
		ssl3_write_bytes, \
		ssl3_dispatch_alert, \
		ssl3_ctrl, \
		ssl3_ctx_ctrl, \
		ssl3_get_cipher_by_char, \
		ssl3_put_cipher_by_char, \
		ssl3_pending, \
		ssl3_num_ciphers, \
		ssl3_get_cipher, \
		s_get_meth, \
		ssl3_default_timeout, \
		&SSLv3_enc_data, \
		ssl_undefined_void_function, \
		ssl3_callback_ctrl, \
		ssl3_ctx_callback_ctrl, \
	}; \
	return &func_name##_data; \
	}
#define IMPLEMENT_tls1_meth_func(func_name, s_accept, s_connect, s_get_meth) \
SSL_METHOD *func_name(void)  \
	{ \
	static SSL_METHOD func_name##_data= { \
		TLS1_VERSION, \
		tls1_new, \
		tls1_clear, \
		tls1_free, \
		s_accept, \
		s_connect, \
		ssl3_read, \
		ssl3_peek, \
		ssl3_write, \
		ssl3_shutdown, \
		ssl3_renegotiate, \
		ssl3_renegotiate_check, \
		ssl3_get_message, \
		ssl3_read_bytes, \
		ssl3_write_bytes, \
		ssl3_dispatch_alert, \
		ssl3_ctrl, \
		ssl3_ctx_ctrl, \
		ssl3_get_cipher_by_char, \
		ssl3_put_cipher_by_char, \
		ssl3_pending, \
		ssl3_num_ciphers, \
		ssl3_get_cipher, \
		s_get_meth, \
		tls1_default_timeout, \
		&TLSv1_enc_data, \
		ssl_undefined_void_function, \
		ssl3_callback_ctrl, \
		ssl3_ctx_callback_ctrl, \
	}; \
	return &func_name##_data; \
	}
#define INC32(a)	((a)=((a)+1)&0xffffffffL)
#define NAMED_CURVE_TYPE           3
# define OPENSSL_EXTERN OPENSSL_EXPORT

#define SSL_C_EXPORT_KEYLENGTH(c)	SSL_EXPORT_KEYLENGTH((c)->algorithms, \
				(c)->algo_strength)
#define SSL_C_EXPORT_PKEYLENGTH(c)	SSL_EXPORT_PKEYLENGTH((c)->algo_strength)
#define SSL_C_IS_EXPORT(c)	SSL_IS_EXPORT((c)->algo_strength)
#define SSL_C_IS_EXPORT40(c)	SSL_IS_EXPORT40((c)->algo_strength)
#define SSL_C_IS_EXPORT56(c)	SSL_IS_EXPORT56((c)->algo_strength)
#define SSL_DSS 		SSL_aDSS
#define SSL_EXPORT_KEYLENGTH(a,s)	(SSL_IS_EXPORT40(s) ? 5 : \
				 ((a)&SSL_ENC_MASK) == SSL_DES ? 8 : 7)
#define SSL_EXPORT_PKEYLENGTH(a) (SSL_IS_EXPORT40(a) ? 512 : 1024)
#define SSL_IS_EXPORT(a)	((a)&SSL_EXPORT)
#define SSL_IS_EXPORT40(a)	((a)&SSL_EXP40)
#define SSL_IS_EXPORT56(a)	((a)&SSL_EXP56)
#define SSL_KRB5                (SSL_kKRB5|SSL_aKRB5)
#define SSL_PKEY_ECC            5
#define SSL_SEED          	0x10000000L
#define SSL_aDH 		0x00001000L 
#define SSL_aDSS 		0x00000200L 
#define SSL_aECDSA              0x00004000L 
#define SSL_aFZA 		0x00000400L
#define SSL_aKRB5               0x00002000L 
#define SSL_aNULL 		0x00000800L 
#define SSL_kECDH               0x00000040L 
#define SSL_kECDHE              0x00000080L 
#define c2l(c,l)	(l = ((unsigned long)(*((c)++)))     , \
			 l|=(((unsigned long)(*((c)++)))<< 8), \
			 l|=(((unsigned long)(*((c)++)))<<16), \
			 l|=(((unsigned long)(*((c)++)))<<24))
#define c2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 8: l2 =((unsigned long)(*(--(c))))<<24; \
			case 7: l2|=((unsigned long)(*(--(c))))<<16; \
			case 6: l2|=((unsigned long)(*(--(c))))<< 8; \
			case 5: l2|=((unsigned long)(*(--(c))));     \
			case 4: l1 =((unsigned long)(*(--(c))))<<24; \
			case 3: l1|=((unsigned long)(*(--(c))))<<16; \
			case 2: l1|=((unsigned long)(*(--(c))))<< 8; \
			case 1: l1|=((unsigned long)(*(--(c))));     \
				} \
			}
#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)    )&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24)&0xff))
#define l2cn(l1,l2,c,n)	{ \
			c+=n; \
			switch (n) { \
			case 8: *(--(c))=(unsigned char)(((l2)>>24)&0xff); \
			case 7: *(--(c))=(unsigned char)(((l2)>>16)&0xff); \
			case 6: *(--(c))=(unsigned char)(((l2)>> 8)&0xff); \
			case 5: *(--(c))=(unsigned char)(((l2)    )&0xff); \
			case 4: *(--(c))=(unsigned char)(((l1)>>24)&0xff); \
			case 3: *(--(c))=(unsigned char)(((l1)>>16)&0xff); \
			case 2: *(--(c))=(unsigned char)(((l1)>> 8)&0xff); \
			case 1: *(--(c))=(unsigned char)(((l1)    )&0xff); \
				} \
			}
#define l2n(l,c)	(*((c)++)=(unsigned char)(((l)>>24)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16)&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
			 *((c)++)=(unsigned char)(((l)    )&0xff))
#define l2n3(l,c)	((c[0]=(unsigned char)(((l)>>16)&0xff), \
			  c[1]=(unsigned char)(((l)>> 8)&0xff), \
			  c[2]=(unsigned char)(((l)    )&0xff)),c+=3)
#define l2n6(l,c)	(*((c)++)=(unsigned char)(((l)>>40)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>32)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16)&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
			 *((c)++)=(unsigned char)(((l)    )&0xff))
#define n2l(c,l)	(l =((unsigned long)(*((c)++)))<<24, \
			 l|=((unsigned long)(*((c)++)))<<16, \
			 l|=((unsigned long)(*((c)++)))<< 8, \
			 l|=((unsigned long)(*((c)++))))
#define n2l3(c,l)	((l =(((unsigned long)(c[0]))<<16)| \
			     (((unsigned long)(c[1]))<< 8)| \
			     (((unsigned long)(c[2]))    )),c+=3)
#define n2l6(c,l)	(l =((BN_ULLONG)(*((c)++)))<<40, \
			 l|=((BN_ULLONG)(*((c)++)))<<32, \
			 l|=((BN_ULLONG)(*((c)++)))<<24, \
			 l|=((BN_ULLONG)(*((c)++)))<<16, \
			 l|=((BN_ULLONG)(*((c)++)))<< 8, \
			 l|=((BN_ULLONG)(*((c)++))))
#define n2s(c,s)	((s=(((unsigned int)(c[0]))<< 8)| \
			    (((unsigned int)(c[1]))    )),c+=2)
#define s2n(s,c)	((c[0]=(unsigned char)(((s)>> 8)&0xff), \
			  c[1]=(unsigned char)(((s)    )&0xff)),c+=2)
#define ssl_get_cipher_by_char(ssl,ptr) \
		((ssl)->method->get_cipher_by_char(ptr))
#define ssl_put_cipher_by_char(ssl,ciph,ptr) \
		((ssl)->method->put_cipher_by_char((ciph),(ptr)))
#    define DEFAULT_HOME  ""
#    define DEVRANDOM "/dev/urandom\x24"
#define DEVRANDOM_EGD "/var/run/egd-pool","/dev/egd-pool","/etc/egd-pool","/etc/entropy"
#    define EXIT(n) _wsetexit(_WINEXITNOPERSIST)
#  define GETPID_IS_MEANINGLESS
#define Getenv getenv

#        define INVALID_SOCKET (int)(~0)
#    define LIST_SEPARATOR_CHAR ','
#    define MAC_OS_pre_X
#  define MSDOS
#  define MS_CALLBACK
#  define MS_FAR
#  define MS_STATIC
#  define NO_CHMOD
#  define NO_DIRENT
#    define NO_SYSLOG
#      define NO_SYS_PARAM_H
#    define NO_SYS_TYPES_H
#    define OPENSSL_CONF   "openssl.cnf"
#    define OPENSSL_EXIT(n) do { if (n == 0) EXIT(n); return(n); } while(0)
#  define OPENSSL_IMPLEMENTS_strncasecmp
#  define OPENSSL_NO_FP_API
#define REF_PRINT(a,b)	fprintf(stderr,"%08X:%4d:%s\n",(int)b,b->references,a)
#    define RFILE    ".rnd"
#      define SHUTDOWN(fd)		close(fd)
#      define SHUTDOWN2(fd)		close(fd)
#    define SSLEAY_CONF    OPENSSL_CONF
#      define SSLeay_Read(a,b,c)	(-1)
#      define SSLeay_Write(a,b,c)	(-1)
#  define SSLeay_getpid()	getpid()
#define TTY_STRUCT int
#    define VMS 1

#  define WIN16
#  define WIN32
#  define WINDOWS

#    define _O_BINARY O_BINARY
#    define _O_TEXT O_TEXT
#      define _WIN32_WINNT 0x0400
#    define _int64 __int64
#    define _kbhit kbhit
#    define _setmode setmode
#        define accept(s,f,l)	((int)accept(s,f,l))
#define clear_socket_error()	WSASetLastError(0)
#define clear_sys_error()	SetLastError(0)
#define closesocket(s)		close_s(s)
#define get_last_socket_error()	WSAGetLastError()
#define get_last_sys_error()	GetLastError()
#      define getpid GetThreadID
#define ioctlsocket(a,b,c)      ioctl(a,b,c)
# define memcmp OPENSSL_memcmp
# define memmove(s1,s2,n) bcopy((s2),(s1),(n))
#      define pid_t int 
#define readsocket(s,b,n)	recv((s),(b),(n),0)
#      define setvbuf(a, b, c, d) setbuffer((a), (b), (d))
#define sleep(a) taskDelay((a) * sysClkRateGet())
#        define socket(d,t,p)	((int)socket(d,t,p))
#      define ssize_t int 
#        define stderr (&__iob_func()[2])
#        define stdin  (&__iob_func()[0])
#        define stdout (&__iob_func()[1])
#    define strcasecmp stricmp
# define strerror(errnum) \
	(((errnum)<0 || (errnum)>=sys_nerr) ? NULL : sys_errlist[errnum])
#      define strlen(s) _strlen31(s)
#    define strncasecmp strnicmp
# define strtoul(s,e,b) ((unsigned long int)strtol((s),(e),(b)))
#define writesocket(s,b,n)	send((s),(b),(n),0)



#define alloca(sz) __builtin_alloca(sz)

# define OPENSSL_DECLARE_EXIT extern void exit(int);
# define OPENSSL_DECLARE_GLOBAL(type,name) type *_shadow_##name(void)
# define OPENSSL_EXPORT globalref
# define OPENSSL_GLOBAL globaldef
# define OPENSSL_GLOBAL_REF(name) (*(_shadow_##name()))
# define OPENSSL_IMPLEMENT_GLOBAL(type,name)			     \
	extern type _hide_##name;				     \
	type *_shadow_##name(void) { return &_hide_##name; }	     \
	static type _hide_##name
# define OPENSSL_IMPORT globalref
#   define OPENSSL_OPT_WINDLL
#  define OPENSSL_SYS_AIX
#  define OPENSSL_SYS_CRAY
#  define OPENSSL_SYS_LINUX
# define OPENSSL_SYS_MACINTOSH_CLASSIC
#  define OPENSSL_SYS_MACOSX
#  define OPENSSL_SYS_MACOSX_RHAPSODY
#  define OPENSSL_SYS_MPE
#  define OPENSSL_SYS_MSDOS
# define OPENSSL_SYS_NETWARE
#  define OPENSSL_SYS_NEWS4
# define OPENSSL_SYS_OS2
#  define OPENSSL_SYS_SNI
#  define OPENSSL_SYS_SUNOS
#  define OPENSSL_SYS_ULTRASPARC

# define OPENSSL_SYS_VMS
#  define OPENSSL_SYS_VMS_DECC
# define OPENSSL_SYS_VOS
# define OPENSSL_SYS_VXWORKS
# define OPENSSL_SYS_WIN32_UWIN
# define OPENSSL_SYS_WINDOWS
# define OPENSSL_UNISTD_IO <io.h>
