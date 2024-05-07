




#include<stdlib.h>






#include<stddef.h>
#include<stdio.h>

#include<errno.h>

#include<string.h>













#include<time.h>



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
