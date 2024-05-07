

#include<signal.h>
#include<fcntl.h>
#include<sys/prctl.h>
#include<sys/un.h>
#include<stdlib.h>
#include<sys/resource.h>
#include<string.h>

#include<stdarg.h>

#include<poll.h>
#include<getopt.h>







#include<locale.h>

#include<sys/socket.h>
#include<time.h>
#include<stdio.h>
#include<sys/types.h>
#include<unistd.h>

#include<errno.h>
#include<sys/stat.h>

#include<setjmp.h>

#include<limits.h>






#define AJAX_TIMEOUT 45

#define BINARY_MSG         "\001%d%p"
#define HTTP_DONE          0
#define HTTP_ERROR         1
#define HTTP_PARTIAL_REPLY 4
#define HTTP_READ_MORE     2
#define HTTP_SUSPEND       3

#define NOINTR(x) ({ int i__; while ((i__ = (x)) < 0 && errno == EINTR); i__;})
#define NO_MSG             "\001"
#define WS_CONNECTION_CLOSED 0x7F00
#define WS_CONNECTION_OPENED 0xFF00
#define WS_END_OF_FRAME      0x0200
#define WS_START_OF_FRAME    0x0100





#define MSG_DEBUG   4
#define MSG_DEFAULT MSG_ERROR
#define MSG_ERROR   1
#define MSG_INFO    3
#define MSG_MESSAGE 0
#define MSG_QUIET  -1
#define MSG_WARN    2
#define check(x)  do {                                                        \
                    if (!(x))                                                 \
                      fatal("Check failed at ""__FILE__"":%d in %s(): %s",      \
                             "__LINE__", __func__, #x);                         \
                  } while (0)
#define dcheck(x) do {                                                        \
                    if (!(x))                                                 \
                      (logIsDebug() ? fatal : error)(                         \
                            "Check failed at ""__FILE__"":%d in %s(): %s",      \
                             "__LINE__", __func__, #x);                         \
                  } while (0)


#define UNIX_PATH_MAX 108
#define BIO_ctrl                     x_BIO_ctrl
#define BIO_f_buffer                 x_BIO_f_buffer
#define BIO_free_all                 x_BIO_free_all
#define BIO_new                      x_BIO_new
#define BIO_new_socket               x_BIO_new_socket
#define BIO_pop                      x_BIO_pop
#define BIO_push                     x_BIO_push
#define BIO_set_buffer_read_data(b, buf, num)                                 \
                                 (x_BIO_ctrl(b, BIO_C_SET_BUFF_READ_DATA,     \
                                             num, buf))
#define EC_KEY_free                  x_EC_KEY_free
#define EC_KEY_new_by_curve_name     x_EC_KEY_new_by_curve_name
#define ERR_clear_error              x_ERR_clear_error
#define ERR_peek_error               x_ERR_peek_error
#define HAVE_OPENSSL 1
# define HAVE_OPENSSL_EC
#define SSL_COMP_get_compression_methods    x_SSL_COMP_get_compression_methods
#define SSL_CTX_callback_ctrl        x_SSL_CTX_callback_ctrl
#define SSL_CTX_check_private_key    x_SSL_CTX_check_private_key
#define SSL_CTX_ctrl                 x_SSL_CTX_ctrl
#define SSL_CTX_free                 x_SSL_CTX_free
#define SSL_CTX_new                  x_SSL_CTX_new
#define SSL_CTX_set_cipher_list      x_SSL_CTX_set_cipher_list
#define SSL_CTX_set_info_callback    x_SSL_CTX_set_info_callback
#define SSL_CTX_set_tlsext_servername_arg(ctx, arg)                           \
                                 (x_SSL_CTX_ctrl(ctx,                         \
                                          SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, \
                                          0, (void *)arg))
#define SSL_CTX_set_tlsext_servername_callback(ctx, cb)                       \
                                 (x_SSL_CTX_callback_ctrl(ctx,                \
                                           SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, \
                                           (void (*)(void))cb))
#define SSL_CTX_set_tmp_ecdh(ctx, ecdh)                                       \
                                 (x_SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TMP_ECDH,  \
                                                 0, (char *)ecdh))
#define SSL_CTX_use_PrivateKey_ASN1  x_SSL_CTX_use_PrivateKey_ASN1
#define SSL_CTX_use_PrivateKey_file  x_SSL_CTX_use_PrivateKey_file
#define SSL_CTX_use_certificate_ASN1 x_SSL_CTX_use_certificate_ASN1
#define SSL_CTX_use_certificate_file x_SSL_CTX_use_certificate_file
#define SSL_ERROR_WANT_READ  2
#define SSL_ERROR_WANT_WRITE 3

#define SSL_ctrl                     x_SSL_ctrl
#define SSL_free                     x_SSL_free
#define SSL_get_app_data(s)      (x_SSL_get_ex_data(s, 0))
#define SSL_get_error                x_SSL_get_error
#define SSL_get_ex_data              x_SSL_get_ex_data
#define SSL_get_rbio                 x_SSL_get_rbio
#define SSL_get_servername           x_SSL_get_servername
#define SSL_get_wbio                 x_SSL_get_wbio
#define SSL_library_init             x_SSL_library_init
#define SSL_new                      x_SSL_new
#define SSL_read                     x_SSL_read
#define SSL_set_SSL_CTX              x_SSL_set_SSL_CTX
#define SSL_set_accept_state         x_SSL_set_accept_state
#define SSL_set_app_data(s, arg) (x_SSL_set_ex_data(s, 0, (char *)arg))
#define SSL_set_bio                  x_SSL_set_bio
#define SSL_set_ex_data              x_SSL_set_ex_data
#define SSL_set_mode(ssl, op)    (x_SSL_ctrl((ssl), SSL_CTRL_MODE, (op), NULL))
#define SSL_shutdown                 x_SSL_shutdown
#define SSL_write                    x_SSL_write
#define SSLv23_server_method         x_SSLv23_server_method
#define X509_free                    x_X509_free
#define d2i_X509                     x_d2i_X509
#define sk_zero                      x_sk_zero

