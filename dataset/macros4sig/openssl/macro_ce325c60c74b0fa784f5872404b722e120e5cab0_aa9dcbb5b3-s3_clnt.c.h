



#include<stdlib.h>





#include<stddef.h>
#include<stdio.h>

#include<errno.h>

#include<string.h>












#include<time.h>


#define DEC32(a)	((a)=((a)-1)&0xffffffffL)
#define EXPLICIT_CHAR2_CURVE_TYPE  2
#define EXPLICIT_PRIME_CURVE_TYPE  1   
#define FP_ICC  (int (*)(const void *,const void *))

#define IMPLEMENT_dtls1_meth_func(version, func_name, s_accept, s_connect, \
					s_get_meth, enc_data) \
const SSL_METHOD *func_name(void)  \
	{ \
	static const SSL_METHOD func_name##_data= { \
		version, \
		dtls1_new, \
		dtls1_clear, \
		dtls1_free, \
		s_accept, \
		s_connect, \
		ssl3_read, \
		ssl3_peek, \
		ssl3_write, \
		dtls1_shutdown, \
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
		&enc_data, \
		ssl_undefined_void_function, \
		ssl3_callback_ctrl, \
		ssl3_ctx_callback_ctrl, \
	}; \
	return &func_name##_data; \
	}
#define IMPLEMENT_ssl23_meth_func(func_name, s_accept, s_connect, s_get_meth) \
const SSL_METHOD *func_name(void)  \
	{ \
	static const SSL_METHOD func_name##_data= { \
	TLS1_2_VERSION, \
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
	&TLSv1_2_enc_data, \
	ssl_undefined_void_function, \
	ssl3_callback_ctrl, \
	ssl3_ctx_callback_ctrl, \
	}; \
	return &func_name##_data; \
	}
#define IMPLEMENT_ssl3_meth_func(func_name, s_accept, s_connect, s_get_meth) \
const SSL_METHOD *func_name(void)  \
	{ \
	static const SSL_METHOD func_name##_data= { \
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
#define IMPLEMENT_tls_meth_func(version, func_name, s_accept, s_connect, \
				s_get_meth, enc_data) \
const SSL_METHOD *func_name(void)  \
	{ \
	static const SSL_METHOD func_name##_data= { \
		version, \
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
		&enc_data, \
		ssl_undefined_void_function, \
		ssl3_callback_ctrl, \
		ssl3_ctx_callback_ctrl, \
	}; \
	return &func_name##_data; \
	}
#define INC32(a)	((a)=((a)+1)&0xffffffffL)
#define NAMED_CURVE_TYPE           3
# define OPENSSL_EXTERN OPENSSL_EXPORT
#define SSL_AES        		(SSL_AES128|SSL_AES256|SSL_AES128GCM|SSL_AES256GCM)
#define SSL_CERT_FLAGS_CHECK_TLS_STRICT \
	(SSL_CERT_FLAG_SUITEB_128_LOS|SSL_CERT_FLAG_TLS_STRICT)
#define SSL_CLIENT_USE_TLS1_2_CIPHERS(s)	\
		((SSL_IS_DTLS(s) && s->client_version <= DTLS1_2_VERSION) || \
		(!SSL_IS_DTLS(s) && s->client_version >= TLS1_2_VERSION))
#define SSL_C_EXPORT_KEYLENGTH(c)	SSL_EXPORT_KEYLENGTH((c)->algorithm_enc, \
				(c)->algo_strength)
#define SSL_C_EXPORT_PKEYLENGTH(c)	SSL_EXPORT_PKEYLENGTH((c)->algo_strength)
#define SSL_C_IS_EXPORT(c)	SSL_IS_EXPORT((c)->algo_strength)
#define SSL_C_IS_EXPORT40(c)	SSL_IS_EXPORT40((c)->algo_strength)
#define SSL_C_IS_EXPORT56(c)	SSL_IS_EXPORT56((c)->algo_strength)
#define SSL_EXPORT_KEYLENGTH(a,s)	(SSL_IS_EXPORT40(s) ? 5 : \
				 (a) == SSL_DES ? 8 : 7)
#define SSL_EXPORT_PKEYLENGTH(a) (SSL_IS_EXPORT40(a) ? 512 : 1024)
#define SSL_GOST89MAC   0x00000008L
#define SSL_GOST94      0x00000004L
#define SSL_HANDSHAKE_MAC_DEFAULT (SSL_HANDSHAKE_MAC_MD5 | SSL_HANDSHAKE_MAC_SHA)
#define SSL_HANDSHAKE_MAC_GOST94 0x40
#define SSL_HANDSHAKE_MAC_MD5 0x10
#define SSL_HANDSHAKE_MAC_SHA 0x20
#define SSL_HANDSHAKE_MAC_SHA256 0x80
#define SSL_HANDSHAKE_MAC_SHA384 0x100
#define SSL_HM_HEADER_LENGTH(s)	s->method->ssl3_enc->hhlen
#define SSL_IS_DTLS(s)	(s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_DTLS)
#define SSL_IS_EXPORT(a)	((a)&SSL_EXPORT)
#define SSL_IS_EXPORT40(a)	((a)&SSL_EXP40)
#define SSL_IS_EXPORT56(a)	((a)&SSL_EXP56)
#define SSL_MAX_DIGEST 6
#define SSL_PKEY_ECC            5
#define SSL_USE_ETM(s) (s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC)
#define SSL_USE_EXPLICIT_IV(s)	\
		(s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_EXPLICIT_IV)
#define SSL_USE_SIGALGS(s)	\
			(s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_SIGALGS)
#define SSL_USE_TLS1_2_CIPHERS(s)	\
		(s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_TLS1_2_CIPHERS)
#define SSL_aDH 		0x00000008L 
#define SSL_aDSS 		0x00000002L 
#define SSL_aECDH 		0x00000010L 
#define SSL_aECDSA              0x00000040L 
#define SSL_aGOST01 			0x00000200L 
#define SSL_aKRB5               0x00000020L 
#define SSL_aNULL 		0x00000004L 
#define SSL_aPSK                0x00000080L 
#define SSL_aSRP 		0x00000400L 
#define SSL_kGOST       0x00000200L 
#define SSL_kSRP        0x00000400L 
#define TLS1_PRF (TLS1_PRF_MD5 | TLS1_PRF_SHA1)
#define TLS1_PRF_DGST_SHIFT 10
#define TLS1_PRF_GOST94 (SSL_HANDSHAKE_MAC_GOST94 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_MD5 (SSL_HANDSHAKE_MAC_MD5 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA1 (SSL_HANDSHAKE_MAC_SHA << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA256 (SSL_HANDSHAKE_MAC_SHA256 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA384 (SSL_HANDSHAKE_MAC_SHA384 << TLS1_PRF_DGST_SHIFT)
#define TLS1_STREAM_MAC 0x04
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
#define dtls1_process_heartbeat SSL_test_functions()->p_dtls1_process_heartbeat
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
#define l2n8(l,c)	(*((c)++)=(unsigned char)(((l)>>56)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>48)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>40)&0xff), \
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
#define ssl3_setup_buffers SSL_test_functions()->p_ssl3_setup_buffers
#define ssl_do_write(s)  s->method->ssl3_enc->do_write(s)
#define ssl_handshake_start(s) \
	(((unsigned char *)s->init_buf->data) + s->method->ssl3_enc->hhlen)
#define ssl_init_wbio_buffer SSL_test_functions()->p_ssl_init_wbio_buffer
#define ssl_put_cipher_by_char(ssl,ciph,ptr) \
		((ssl)->method->put_cipher_by_char((ciph),(ptr)))
#define ssl_set_handshake_header(s, htype, len) \
	s->method->ssl3_enc->set_handshake_header(s, htype, len)
#define tls1_process_heartbeat SSL_test_functions()->p_tls1_process_heartbeat
#define tls1_suiteb(s)	(s->cert->cert_flags & SSL_CERT_FLAG_SUITEB_128_LOS)
#    define DEFAULT_HOME  ""
#    define DEVRANDOM "/dev/urandom\x24"
#define DEVRANDOM_EGD "/var/run/egd-pool","/dev/egd-pool","/etc/egd-pool","/etc/entropy"
#      define EACCES   13
#  define EXIT(n) exit(n)
#  define GETPID_IS_MEANINGLESS

#        define INVALID_SOCKET (int)(~0)
#  define LIST_SEPARATOR_CHAR ';'
#  define MSDOS
#  define NO_CHMOD
#  define NO_DIRENT
#    define NO_SYSLOG
#  define NO_SYS_PARAM_H

#  define OPENSSL_EXIT(n) return(n)
#  define OPENSSL_IMPLEMENTS_strncasecmp
#  define OPENSSL_NO_DGRAM
#  define OPENSSL_NO_FP_API
#    define OPENSSL_NO_POSIX_IO
#      define OPENSSL_USE_IPV6 1
#define REF_PRINT(a,b)	fprintf(stderr,"%08X:%4d:%s\n",(int)b,b->references,a)
#      define SHUTDOWN(fd)		close(fd)
#      define SHUTDOWN2(fd)		close(fd)
#      define SSLeay_Read(a,b,c)	(-1)
#      define SSLeay_Write(a,b,c)	(-1)
#define TTY_STRUCT int
#          define UNIX_PATH_MAX sizeof(((struct sockaddr_un *)NULL)->sun_path)
#  define WIN32
#  define WINDOWS

#    define _O_BINARY O_BINARY
#    define _O_TEXT O_TEXT
#      define _WIN32_WINNT 0x0400
#    define _int64 __int64
#    define _kbhit kbhit
#    define _setmode setmode
#        define accept(s,f,l)	((int)accept(s,f,l))
#  define check_winnt() (1)
#define clear_socket_error()	WSASetLastError(0)
#define clear_sys_error()	SetLastError(0)
#define get_last_socket_error()	WSAGetLastError()
#define get_last_sys_error()	GetLastError()
#define getpid taskIdSelf
#        define getservbyname _masked_declaration_getservbyname
#  define inline __inline__
# define memcmp OPENSSL_memcmp
# define memmove(s1,s2,n) bcopy((s2),(s1),(n))
#define readsocket(s,b,n)	recv((s),(b),(n),0)
#define sleep(a) taskDelay((a) * sysClkRateGet())
#        define socket(d,t,p)	((int)socket(d,t,p))
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








#include<sys/cdefs.h>


# define KSSL_LCL_H
# define DEC32(a)        ((a)=((a)-1)&0xffffffffL)
#  define EXPLICIT_CHAR2_CURVE_TYPE  2
#  define EXPLICIT_PRIME_CURVE_TYPE  1
# define FP_ICC  (int (*)(const void *,const void *))
# define HEADER_SSL_LOCL_H
# define IMPLEMENT_dtls1_meth_func(func_name, s_accept, s_connect, s_get_meth) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                DTLS1_VERSION, \
                dtls1_new, \
                dtls1_clear, \
                dtls1_free, \
                s_accept, \
                s_connect, \
                ssl3_read, \
                ssl3_peek, \
                ssl3_write, \
                dtls1_shutdown, \
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
# define IMPLEMENT_ssl23_meth_func(func_name, s_accept, s_connect, s_get_meth) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
        TLS1_2_VERSION, \
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
# define IMPLEMENT_ssl2_meth_func(func_name, s_accept, s_connect, s_get_meth) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                SSL2_VERSION, \
                ssl2_new,        \
                ssl2_clear,      \
                ssl2_free,       \
                s_accept, \
                s_connect, \
                ssl2_read, \
                ssl2_peek, \
                ssl2_write, \
                ssl2_shutdown, \
                ssl_ok,  \
                ssl_ok,  \
                NULL,  \
                NULL,  \
                NULL,  \
                NULL,  \
                ssl2_ctrl,       \
                ssl2_ctx_ctrl,   \
                ssl2_get_cipher_by_char, \
                ssl2_put_cipher_by_char, \
                ssl2_pending, \
                ssl2_num_ciphers, \
                ssl2_get_cipher, \
                s_get_meth, \
                ssl2_default_timeout, \
                &ssl3_undef_enc_method, \
                ssl_undefined_void_function, \
                ssl2_callback_ctrl,      \
                ssl2_ctx_callback_ctrl,  \
        }; \
        return &func_name##_data; \
        }
# define IMPLEMENT_ssl3_meth_func(func_name, s_accept, s_connect, s_get_meth) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
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
# define IMPLEMENT_tls_meth_func(version, func_name, s_accept, s_connect, \
                                s_get_meth) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
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
# define INC32(a)        ((a)=((a)+1)&0xffffffffL)
# define MAX_MAC_SIZE    20     
#  define NAMED_CURVE_TYPE           3
#  define OPENSSL_EXTERN OPENSSL_EXPORT
# define SEC_ESC_BIT     0x40
# define SSL_3DES                0x00000002L
# define SSL_AEAD                0x00000040L
# define SSL_AES                 (SSL_AES128|SSL_AES256|SSL_AES128GCM|SSL_AES256GCM)
# define SSL_AES128              0x00000040L
# define SSL_AES128GCM           0x00001000L
# define SSL_AES256              0x00000080L
# define SSL_AES256GCM           0x00002000L
# define SSL_CAMELLIA            (SSL_CAMELLIA128|SSL_CAMELLIA256)
# define SSL_CAMELLIA128         0x00000100L
# define SSL_CAMELLIA256         0x00000200L
# define SSL_C_EXPORT_KEYLENGTH(c)       SSL_EXPORT_KEYLENGTH((c)->algorithm_enc, \
                                (c)->algo_strength)
# define SSL_C_EXPORT_PKEYLENGTH(c)      SSL_EXPORT_PKEYLENGTH((c)->algo_strength)
# define SSL_C_IS_EXPORT(c)      SSL_IS_EXPORT((c)->algo_strength)
# define SSL_C_IS_EXPORT40(c)    SSL_IS_EXPORT40((c)->algo_strength)
# define SSL_C_IS_EXPORT56(c)    SSL_IS_EXPORT56((c)->algo_strength)
# define SSL_DECRYPT     0
# define SSL_DES                 0x00000001L
# define SSL_ENCRYPT     1
# define SSL_EXP40               0x00000008L
# define SSL_EXP56               0x00000010L
# define SSL_EXPORT              0x00000002L
# define SSL_EXPORT_KEYLENGTH(a,s)       (SSL_IS_EXPORT40(s) ? 5 : \
                                 (a) == SSL_DES ? 8 : 7)
# define SSL_EXPORT_PKEYLENGTH(a) (SSL_IS_EXPORT40(a) ? 512 : 1024)
# define SSL_EXP_MASK            0x00000003L
# define SSL_FIPS                0x00000100L
# define SSL_GOST89MAC   0x00000008L
# define SSL_GOST94      0x00000004L
# define SSL_HANDSHAKE_MAC_DEFAULT (SSL_HANDSHAKE_MAC_MD5 | SSL_HANDSHAKE_MAC_SHA)
# define SSL_HANDSHAKE_MAC_GOST94 0x40
# define SSL_HANDSHAKE_MAC_MD5 0x10
# define SSL_HANDSHAKE_MAC_SHA 0x20
# define SSL_HANDSHAKE_MAC_SHA256 0x80
# define SSL_HANDSHAKE_MAC_SHA384 0x100
# define SSL_HIGH                0x00000080L
# define SSL_IDEA                0x00000010L
# define SSL_IS_DTLS(s) (s->method->version == DTLS1_VERSION)
# define SSL_IS_EXPORT(a)        ((a)&SSL_EXPORT)
# define SSL_IS_EXPORT40(a)      ((a)&SSL_EXP40)
# define SSL_IS_EXPORT56(a)      ((a)&SSL_EXP56)
# define SSL_LOW                 0x00000020L
# define SSL_MAX_DIGEST 6
# define SSL_MD5                 0x00000001L
# define SSL_MEDIUM              0x00000040L
# define SSL_MICRO               (SSL_EXP40)
# define SSL_MINI                (SSL_EXP56)
# define SSL_NOT_EXP             0x00000001L
# define SSL_PKEY_DH_DSA         4
# define SSL_PKEY_DH_RSA         3
# define SSL_PKEY_DSA_SIGN       2
# define SSL_PKEY_ECC            5
# define SSL_PKEY_GOST01         7
# define SSL_PKEY_GOST94         6
# define SSL_PKEY_NUM            8
# define SSL_PKEY_RSA_ENC        0
# define SSL_PKEY_RSA_SIGN       1
# define SSL_RC2                 0x00000008L
# define SSL_RC4                 0x00000004L
# define SSL_SEED                0x00000800L
# define SSL_SHA1                0x00000002L
# define SSL_SHA256              0x00000010L
# define SSL_SHA384              0x00000020L
# define SSL_SSLV2               0x00000001UL
# define SSL_SSLV3               0x00000002UL
# define SSL_STRONG_MASK         0x000001fcL
# define SSL_STRONG_NONE         0x00000004L
# define SSL_TLSV1               SSL_SSLV3
# define SSL_TLSV1_2             0x00000004UL
# define SSL_aDH                 0x00000008L
# define SSL_aDSS                0x00000002L
# define SSL_aECDH               0x00000010L
# define SSL_aECDSA              0x00000040L
# define SSL_aGOST01                     0x00000200L
# define SSL_aGOST94                             0x00000100L
# define SSL_aKRB5               0x00000020L
# define SSL_aNULL               0x00000004L
# define SSL_aPSK                0x00000080L
# define SSL_aRSA                0x00000001L
# define SSL_aSRP                0x00000400L
# define SSL_eGOST2814789CNT     0x00000400L
# define SSL_eNULL               0x00000020L
# define SSL_kDHd                0x00000004L
# define SSL_kDHr                0x00000002L
# define SSL_kECDHe              0x00000040L
# define SSL_kECDHr              0x00000020L
# define SSL_kEDH                0x00000008L
# define SSL_kEECDH              0x00000080L
# define SSL_kGOST       0x00000200L
# define SSL_kKRB5               0x00000010L
# define SSL_kPSK                0x00000100L
# define SSL_kRSA                0x00000001L
# define SSL_kSRP        0x00000400L
# define THREE_BYTE_MASK 0x3fff
# define TLS1_PRF (TLS1_PRF_MD5 | TLS1_PRF_SHA1)
# define TLS1_PRF_DGST_MASK      (0xff << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_DGST_SHIFT 10
# define TLS1_PRF_GOST94 (SSL_HANDSHAKE_MAC_GOST94 << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_MD5 (SSL_HANDSHAKE_MAC_MD5 << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA1 (SSL_HANDSHAKE_MAC_SHA << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA256 (SSL_HANDSHAKE_MAC_SHA256 << TLS1_PRF_DGST_SHIFT)
# define TLS1_PRF_SHA384 (SSL_HANDSHAKE_MAC_SHA384 << TLS1_PRF_DGST_SHIFT)
# define TLS1_STREAM_MAC 0x04
# define TWO_BYTE_BIT    0x80
# define TWO_BYTE_MASK   0x7fff
# define c2l(c,l)        (l = ((unsigned long)(*((c)++)))     , \
                         l|=(((unsigned long)(*((c)++)))<< 8), \
                         l|=(((unsigned long)(*((c)++)))<<16), \
                         l|=(((unsigned long)(*((c)++)))<<24))
# define c2ln(c,l1,l2,n) { \
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
#  define dtls1_process_heartbeat SSL_test_functions()->p_dtls1_process_heartbeat
# define l2c(l,c)        (*((c)++)=(unsigned char)(((l)    )&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff))
# define l2cn(l1,l2,c,n) { \
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
# define l2n(l,c)        (*((c)++)=(unsigned char)(((l)>>24)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))
# define l2n3(l,c)       ((c[0]=(unsigned char)(((l)>>16)&0xff), \
                          c[1]=(unsigned char)(((l)>> 8)&0xff), \
                          c[2]=(unsigned char)(((l)    )&0xff)),c+=3)
# define l2n6(l,c)       (*((c)++)=(unsigned char)(((l)>>40)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>32)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))
# define l2n8(l,c)       (*((c)++)=(unsigned char)(((l)>>56)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>48)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>40)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>32)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))
# define n2l(c,l)        (l =((unsigned long)(*((c)++)))<<24, \
                         l|=((unsigned long)(*((c)++)))<<16, \
                         l|=((unsigned long)(*((c)++)))<< 8, \
                         l|=((unsigned long)(*((c)++))))
# define n2l3(c,l)       ((l =(((unsigned long)(c[0]))<<16)| \
                             (((unsigned long)(c[1]))<< 8)| \
                             (((unsigned long)(c[2]))    )),c+=3)
# define n2l6(c,l)       (l =((BN_ULLONG)(*((c)++)))<<40, \
                         l|=((BN_ULLONG)(*((c)++)))<<32, \
                         l|=((BN_ULLONG)(*((c)++)))<<24, \
                         l|=((BN_ULLONG)(*((c)++)))<<16, \
                         l|=((BN_ULLONG)(*((c)++)))<< 8, \
                         l|=((BN_ULLONG)(*((c)++))))
# define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
                            (((unsigned int)(c[1]))    )),c+=2)
# define s2n(s,c)        ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
                          c[1]=(unsigned char)(((s)    )&0xff)),c+=2)
#  define ssl3_setup_buffers SSL_test_functions()->p_ssl3_setup_buffers
# define ssl_get_cipher_by_char(ssl,ptr) \
                ((ssl)->method->get_cipher_by_char(ptr))
#  define ssl_init_wbio_buffer SSL_test_functions()->p_ssl_init_wbio_buffer
# define ssl_put_cipher_by_char(ssl,ciph,ptr) \
                ((ssl)->method->put_cipher_by_char((ciph),(ptr)))
#  define tls1_process_heartbeat SSL_test_functions()->p_tls1_process_heartbeat
#    define tlsext_tick_md  EVP_sha1
#    define tlsext_tick_md  EVP_sha256
#  define __LOCALE_T_DECLARED
#define getc_unlocked(fp)	__sgetc(fp)

#define putc(x, fp)	__sputc(x, fp)
#define putc_unlocked(x, fp)	__sputc(x, fp)
#define putchar_unlocked(x)	putc_unlocked(x, stdout)
#define fgets(str, len, fp) \
    __fgets_chk(str, len, __ssp_bos(str), fp)
#define gets(str) \
    __gets_chk(str, __ssp_bos(str))
#define snprintf(str, len, ...) \
    __builtin___snprintf_chk(str, len, 0, __ssp_bos(str), __VA_ARGS__)
#define sprintf(str, ...) \
    __builtin___sprintf_chk(str, 0, __ssp_bos(str), __VA_ARGS__)
#define vsnprintf(str, len, fmt, ap) \
    __builtin___vsnprintf_chk(str, len, 0, __ssp_bos(str), fmt, ap)
#define vsprintf(str, fmt, ap) \
    __builtin___vsprintf_chk(str, 0, __ssp_bos(str), fmt, ap)
#   define __SSP_FORTIFY_LEVEL 2
#   define __SSP_FORTIFY_LEVEL 1
#  define __SSP_FORTIFY_LEVEL 0
# define __SSP_FORTIFY_LEVEL 0
#define __ssp_bos(ptr) __builtin_object_size(ptr, __SSP_FORTIFY_LEVEL > 1)
#define __ssp_bos0(ptr) __builtin_object_size(ptr, 0)
#define __ssp_check(buf, len, bos) \
	if (bos(buf) != (size_t)-1 && len > bos(buf)) \
		__chk_fail()
#define __ssp_inline static __inline __attribute__((__always_inline__))
#define __ssp_overlap(a, b, l) \
    (((a) <= (b) && (b) < (a) + (l)) || ((b) <= (a) && (a) < (b) + (l)))
#define __ssp_real(fun)		__ssp_real_(fun)
#define __ssp_real_(fun)	fun
#define __ssp_real_(fun)	__ssp_real_ ## fun
#define __ssp_redirect(rtype, fun, args, call) \
    __ssp_redirect_raw(rtype, fun, fun, args, call, 1, __ssp_bos)
#define __ssp_redirect0(rtype, fun, args, call) \
    __ssp_redirect_raw(rtype, fun, fun, args, call, 1, __ssp_bos0)
#define __ssp_redirect_raw(rtype, fun, symbol, args, call, cond, bos) \
rtype __ssp_real_(fun) args __RENAME(symbol); \
__ssp_inline rtype fun args __RENAME(__ssp_protected_ ## fun); \
__ssp_inline rtype fun args { \
	if (cond) \
		__ssp_check(__buf, __len, bos); \
	return __ssp_real_(fun) call; \
}
