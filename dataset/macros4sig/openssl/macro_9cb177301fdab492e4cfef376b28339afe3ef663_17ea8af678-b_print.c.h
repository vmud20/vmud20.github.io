#include<ctype.h>
#include<limits.h>
#include<string.h>
#include<stdio.h>
#include<assert.h>
# define BIO_BIND_NORMAL                 0
# define BIO_BIND_REUSEADDR              BIO_SOCK_REUSEADDR
# define BIO_BIND_REUSEADDR_IF_UNUSED    BIO_SOCK_REUSEADDR
# define BIO_CB_CTRL     0x06
# define BIO_CB_FREE     0x01
# define BIO_CB_GETS     0x05
# define BIO_CB_PUTS     0x04
# define BIO_CB_READ     0x02
# define BIO_CB_RETURN   0x80
# define BIO_CB_WRITE    0x03
# define BIO_CB_return(a) ((a)|BIO_CB_RETURN)
# define BIO_CLOSE               0x01
# define BIO_CTRL_DGRAM_CONNECT       31
# define BIO_CTRL_DGRAM_GET_FALLBACK_MTU   47
# define BIO_CTRL_DGRAM_GET_MTU            41
# define BIO_CTRL_DGRAM_GET_MTU_OVERHEAD   49
# define BIO_CTRL_DGRAM_GET_PEER           46
# define BIO_CTRL_DGRAM_GET_RECV_TIMEOUT 34
# define BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP 37
# define BIO_CTRL_DGRAM_GET_SEND_TIMEOUT 36
# define BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP 38
# define BIO_CTRL_DGRAM_MTU_DISCOVER       39
# define BIO_CTRL_DGRAM_MTU_EXCEEDED       43
# define BIO_CTRL_DGRAM_QUERY_MTU          40
#  define BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY                51
#  define BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD               53
#  define BIO_CTRL_DGRAM_SCTP_GET_PRINFO                  64
#  define BIO_CTRL_DGRAM_SCTP_GET_RCVINFO         62
#  define BIO_CTRL_DGRAM_SCTP_GET_SNDINFO         60
#  define BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY               52
#  define BIO_CTRL_DGRAM_SCTP_SAVE_SHUTDOWN               70
#  define BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE    50
#  define BIO_CTRL_DGRAM_SCTP_SET_PRINFO                  65
#  define BIO_CTRL_DGRAM_SCTP_SET_RCVINFO         63
#  define BIO_CTRL_DGRAM_SCTP_SET_SNDINFO         61
# define BIO_CTRL_DGRAM_SET_CONNECTED 32
# define BIO_CTRL_DGRAM_SET_DONT_FRAG      48
# define BIO_CTRL_DGRAM_SET_MTU            42
# define BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT   45
# define BIO_CTRL_DGRAM_SET_PEEK_MODE      50
# define BIO_CTRL_DGRAM_SET_PEER           44
# define BIO_CTRL_DGRAM_SET_RECV_TIMEOUT 33
# define BIO_CTRL_DGRAM_SET_SEND_TIMEOUT 35
# define BIO_CTRL_DUP            12
# define BIO_CTRL_EOF            2
# define BIO_CTRL_FLUSH          11
# define BIO_CTRL_GET            5
# define BIO_CTRL_GET_CALLBACK   15
# define BIO_CTRL_GET_CLOSE      8
# define BIO_CTRL_INFO           3
# define BIO_CTRL_PENDING        10
# define BIO_CTRL_POP            7
# define BIO_CTRL_PUSH           6
# define BIO_CTRL_RESET          1
# define BIO_CTRL_SET            4
# define BIO_CTRL_SET_CALLBACK   14
# define BIO_CTRL_SET_CLOSE      9
# define BIO_CTRL_SET_FILENAME   30
# define BIO_CTRL_WPENDING       13
# define BIO_C_DESTROY_BIO_PAIR                  139
# define BIO_C_DO_STATE_MACHINE                  101
# define BIO_C_FILE_SEEK                         128
# define BIO_C_FILE_TELL                         133
# define BIO_C_GET_ACCEPT                        124
# define BIO_C_GET_BIND_MODE                     132
# define BIO_C_GET_BUFF_NUM_LINES                116
# define BIO_C_GET_BUF_MEM_PTR                   115
# define BIO_C_GET_CIPHER_CTX                    129
# define BIO_C_GET_CIPHER_STATUS                 113
# define BIO_C_GET_CONNECT                       123
# define BIO_C_GET_EX_ARG                        154
# define BIO_C_GET_FD                            105
# define BIO_C_GET_FILE_PTR                      107
# define BIO_C_GET_MD                            112
# define BIO_C_GET_MD_CTX                        120
# define BIO_C_GET_PREFIX                        150
# define BIO_C_GET_READ_REQUEST                  141
# define BIO_C_GET_SOCKS                         134
# define BIO_C_GET_SSL                           110
# define BIO_C_GET_SSL_NUM_RENEGOTIATES          126
# define BIO_C_GET_SUFFIX                        152
# define BIO_C_GET_WRITE_BUF_SIZE                137
# define BIO_C_GET_WRITE_GUARANTEE               140
# define BIO_C_MAKE_BIO_PAIR                     138
# define BIO_C_NREAD                             144
# define BIO_C_NREAD0                            143
# define BIO_C_NWRITE                            146
# define BIO_C_NWRITE0                           145
# define BIO_C_RESET_READ_REQUEST                147
# define BIO_C_SET_ACCEPT                        118
# define BIO_C_SET_BIND_MODE                     131
# define BIO_C_SET_BUFF_READ_DATA                122
# define BIO_C_SET_BUFF_SIZE                     117
# define BIO_C_SET_BUF_MEM                       114
# define BIO_C_SET_BUF_MEM_EOF_RETURN            130
# define BIO_C_SET_CONNECT                       100
# define BIO_C_SET_CONNECT_MODE                  155
# define BIO_C_SET_EX_ARG                        153
# define BIO_C_SET_FD                            104
# define BIO_C_SET_FILENAME                      108
# define BIO_C_SET_FILE_PTR                      106
# define BIO_C_SET_MD                            111
# define BIO_C_SET_MD_CTX                        148
# define BIO_C_SET_NBIO                          102
# define BIO_C_SET_PREFIX                        149
# define BIO_C_SET_SOCKS                         135
# define BIO_C_SET_SSL                           109
# define BIO_C_SET_SSL_RENEGOTIATE_BYTES         125
# define BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT       127
# define BIO_C_SET_SUFFIX                        151
# define BIO_C_SET_WRITE_BUF_SIZE                136
# define BIO_C_SHUTDOWN_WR                       142
# define BIO_C_SSL_MODE                          119
# define BIO_FAMILY_IPANY                        256
# define BIO_FAMILY_IPV4                         4
# define BIO_FAMILY_IPV6                         6
# define BIO_FLAGS_BASE64_NO_NL  0x100
# define BIO_FLAGS_IO_SPECIAL    0x04
# define BIO_FLAGS_MEM_RDONLY    0x200
# define BIO_FLAGS_READ          0x01
# define BIO_FLAGS_RWS (BIO_FLAGS_READ|BIO_FLAGS_WRITE|BIO_FLAGS_IO_SPECIAL)
# define BIO_FLAGS_SHOULD_RETRY  0x08
#  define BIO_FLAGS_UPLINK        0
# define BIO_FLAGS_WRITE         0x02
# define BIO_FP_APPEND           0x08
# define BIO_FP_READ             0x02
# define BIO_FP_TEXT             0x10
# define BIO_FP_WRITE            0x04
# define BIO_F_ACPT_STATE                                 100
# define BIO_F_ADDR_STRINGS                               134
# define BIO_F_BIO_ACCEPT                                 101
# define BIO_F_BIO_ACCEPT_EX                              137
# define BIO_F_BIO_BER_GET_HEADER                         102
# define BIO_F_BIO_CALLBACK_CTRL                          131
# define BIO_F_BIO_CONNECT                                138
# define BIO_F_BIO_CTRL                                   103
# define BIO_F_BIO_GETHOSTBYNAME                          120
# define BIO_F_BIO_GETS                                   104
# define BIO_F_BIO_GET_ACCEPT_SOCKET                      105
# define BIO_F_BIO_GET_HOST_IP                            106
# define BIO_F_BIO_GET_PORT                               107
# define BIO_F_BIO_LISTEN                                 139
# define BIO_F_BIO_LOOKUP                                 135
# define BIO_F_BIO_MAKE_PAIR                              121
# define BIO_F_BIO_NEW                                    108
# define BIO_F_BIO_NEW_FILE                               109
# define BIO_F_BIO_NEW_MEM_BUF                            126
# define BIO_F_BIO_NREAD                                  123
# define BIO_F_BIO_NREAD0                                 124
# define BIO_F_BIO_NWRITE                                 125
# define BIO_F_BIO_NWRITE0                                122
# define BIO_F_BIO_PARSE_HOSTSERV                         136
# define BIO_F_BIO_PUTS                                   110
# define BIO_F_BIO_READ                                   111
# define BIO_F_BIO_SOCKET                                 140
# define BIO_F_BIO_SOCKET_NBIO                            142
# define BIO_F_BIO_SOCK_INFO                              141
# define BIO_F_BIO_SOCK_INIT                              112
# define BIO_F_BIO_WRITE                                  113
# define BIO_F_BUFFER_CTRL                                114
# define BIO_F_CONN_CTRL                                  127
# define BIO_F_CONN_STATE                                 115
# define BIO_F_DGRAM_SCTP_READ                            132
# define BIO_F_DGRAM_SCTP_WRITE                           133
# define BIO_F_FILE_CTRL                                  116
# define BIO_F_FILE_READ                                  130
# define BIO_F_LINEBUFFER_CTRL                            129
# define BIO_F_MEM_READ                                   128
# define BIO_F_MEM_WRITE                                  117
# define BIO_F_SSL_NEW                                    118
# define BIO_F_WSASTARTUP                                 119
# define BIO_NOCLOSE             0x00
# define BIO_RR_ACCEPT                   0x03
# define BIO_RR_CONNECT                  0x02
# define BIO_RR_SSL_X509_LOOKUP          0x01
# define BIO_R_ACCEPT_ERROR                               100
# define BIO_R_ADDRINFO_ADDR_IS_NOT_AF_INET               141
# define BIO_R_AMBIGUOUS_HOST_OR_SERVICE                  129
# define BIO_R_BAD_FOPEN_MODE                             101
# define BIO_R_BAD_HOSTNAME_LOOKUP                        102
# define BIO_R_BROKEN_PIPE                                124
# define BIO_R_CONNECT_ERROR                              103
# define BIO_R_EOF_ON_MEMORY_BIO                          127
# define BIO_R_ERROR_SETTING_NBIO                         104
# define BIO_R_ERROR_SETTING_NBIO_ON_ACCEPTED_SOCKET      105
# define BIO_R_ERROR_SETTING_NBIO_ON_ACCEPT_SOCKET        106
# define BIO_R_GETHOSTBYNAME_ADDR_IS_NOT_AF_INET          107
# define BIO_R_GETSOCKNAME_ERROR                          132
# define BIO_R_GETSOCKNAME_TRUNCATED_ADDRESS              133
# define BIO_R_GETTING_SOCKTYPE                           134
# define BIO_R_INVALID_ARGUMENT                           125
# define BIO_R_INVALID_IP_ADDRESS                         108
# define BIO_R_INVALID_SOCKET                             135
# define BIO_R_IN_USE                                     123
# define BIO_R_KEEPALIVE                                  109
# define BIO_R_LISTEN_V6_ONLY                             136
# define BIO_R_LOOKUP_RETURNED_NOTHING                    142
# define BIO_R_MALFORMED_HOST_OR_SERVICE                  130
# define BIO_R_NBIO_CONNECT_ERROR                         110
# define BIO_R_NO_ACCEPT_ADDR_OR_SERVICE_SPECIFIED        143
# define BIO_R_NO_ACCEPT_PORT_SPECIFIED                   111
# define BIO_R_NO_HOSTNAME_OR_SERVICE_SPECIFIED           144
# define BIO_R_NO_HOSTNAME_SPECIFIED                      112
# define BIO_R_NO_PORT_DEFINED                            113
# define BIO_R_NO_SERVICE_SPECIFIED                       114
# define BIO_R_NO_SUCH_FILE                               128
# define BIO_R_NULL_PARAMETER                             115
# define BIO_R_TAG_MISMATCH                               116
# define BIO_R_UNABLE_TO_BIND_SOCKET                      117
# define BIO_R_UNABLE_TO_CREATE_SOCKET                    118
# define BIO_R_UNABLE_TO_KEEPALIVE                        137
# define BIO_R_UNABLE_TO_LISTEN_SOCKET                    119
# define BIO_R_UNABLE_TO_NODELAY                          138
# define BIO_R_UNABLE_TO_REUSEADDR                        139
# define BIO_R_UNAVAILABLE_IP_FAMILY                      145
# define BIO_R_UNINITIALIZED                              120
# define BIO_R_UNKNOWN_INFO_TYPE                          140
# define BIO_R_UNSUPPORTED_IP_FAMILY                      146
# define BIO_R_UNSUPPORTED_METHOD                         121
# define BIO_R_UNSUPPORTED_PROTOCOL_FAMILY                131
# define BIO_R_WRITE_TO_READ_ONLY_BIO                     126
# define BIO_R_WSASTARTUP                                 122
# define BIO_SOCK_KEEPALIVE    0x04
# define BIO_SOCK_NODELAY      0x10
# define BIO_SOCK_NONBLOCK     0x08
# define BIO_SOCK_REUSEADDR    0x01
# define BIO_SOCK_V6_ONLY      0x02
# define BIO_TYPE_ACCEPT         (13|0x0400|0x0100)
# define BIO_TYPE_ASN1           (22|0x0200)
# define BIO_TYPE_BASE64         (11|0x0200)
# define BIO_TYPE_BER            (18|0x0200)
# define BIO_TYPE_BIO            (19|0x0400)
# define BIO_TYPE_BUFFER         (9|0x0200)
# define BIO_TYPE_CIPHER         (10|0x0200)
# define BIO_TYPE_COMP           (23|0x0200)
# define BIO_TYPE_CONNECT        (12|0x0400|0x0100)
# define BIO_TYPE_DESCRIPTOR     0x0100
# define BIO_TYPE_DGRAM          (21|0x0400|0x0100)
#  define BIO_TYPE_DGRAM_SCTP     (24|0x0400|0x0100)
# define BIO_TYPE_FD             (4|0x0400|0x0100)
# define BIO_TYPE_FILE           (2|0x0400)
# define BIO_TYPE_FILTER         0x0200
# define BIO_TYPE_LINEBUFFER     (20|0x0200)
# define BIO_TYPE_MD             (8|0x0200)
# define BIO_TYPE_MEM            (1|0x0400)
# define BIO_TYPE_NBIO_TEST      (16|0x0200)
# define BIO_TYPE_NONE           0
# define BIO_TYPE_NULL           (6|0x0400)
# define BIO_TYPE_NULL_FILTER    (17|0x0200)
# define BIO_TYPE_SOCKET         (5|0x0400|0x0100)
# define BIO_TYPE_SOURCE_SINK    0x0400
# define BIO_TYPE_SSL            (7|0x0200)
# define BIO_append_filename(b,name) BIO_ctrl(b,BIO_C_SET_FILENAME, \
                BIO_CLOSE|BIO_FP_APPEND,name)
# define BIO_buffer_get_num_lines(b) BIO_ctrl(b,BIO_CTRL_GET,0,NULL)
# define BIO_cb_post(a)  ((a)&BIO_CB_RETURN)
# define BIO_cb_pre(a)   (!((a)&BIO_CB_RETURN))
# define BIO_clear_retry_flags(b) \
                BIO_clear_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
# define BIO_ctrl_dgram_connect(b,peer)  \
                     (int)BIO_ctrl(b,BIO_CTRL_DGRAM_CONNECT,0, (char *)peer)
# define BIO_ctrl_set_connected(b,peer) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (char *)peer)
# define BIO_destroy_bio_pair(b)    (int)BIO_ctrl(b,BIO_C_DESTROY_BIO_PAIR,0,NULL)
# define BIO_dgram_get_mtu_overhead(b) \
         (unsigned int)BIO_ctrl((b), BIO_CTRL_DGRAM_GET_MTU_OVERHEAD, 0, NULL)
# define BIO_dgram_get_peer(b,peer) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_PEER, 0, (char *)peer)
# define BIO_dgram_recv_timedout(b) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)
# define BIO_dgram_send_timedout(b) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_GET_SEND_TIMER_EXP, 0, NULL)
# define BIO_dgram_set_peer(b,peer) \
         (int)BIO_ctrl(b, BIO_CTRL_DGRAM_SET_PEER, 0, (char *)peer)
# define BIO_do_accept(b)        BIO_do_handshake(b)
# define BIO_do_connect(b)       BIO_do_handshake(b)
# define BIO_do_handshake(b)     BIO_ctrl(b,BIO_C_DO_STATE_MACHINE,0,NULL)
# define BIO_dup_state(b,ret)    BIO_ctrl(b,BIO_CTRL_DUP,0,(char *)(ret))
# define BIO_eof(b)              (int)BIO_ctrl(b,BIO_CTRL_EOF,0,NULL)
# define BIO_flush(b)            (int)BIO_ctrl(b,BIO_CTRL_FLUSH,0,NULL)
# define BIO_get_accept_ip_family(b)   BIO_ctrl(b,BIO_C_GET_ACCEPT,4,NULL)
# define BIO_get_accept_name(b)        ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,0))
# define BIO_get_accept_port(b)        ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,1))
# define BIO_get_app_data(s)             BIO_get_ex_data(s,0)
# define BIO_get_bind_mode(b)    BIO_ctrl(b,BIO_C_GET_BIND_MODE,0,NULL)
# define BIO_get_buffer_num_lines(b)     BIO_ctrl(b,BIO_C_GET_BUFF_NUM_LINES,0,NULL)
# define BIO_get_close(b)        (int)BIO_ctrl(b,BIO_CTRL_GET_CLOSE,0,NULL)
# define BIO_get_conn_address(b)       ((const BIO_ADDR *)BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,2,NULL))
# define BIO_get_conn_hostname(b)      ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,0,NULL))
# define BIO_get_conn_ip_family(b)     BIO_ctrl(b,BIO_C_GET_CONNECT,3,NULL)
# define BIO_get_conn_port(b)          ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_CONNECT,1,NULL))
#define BIO_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_BIO, l, p, newf, dupf, freef)
# define BIO_get_fd(b,c)         BIO_ctrl(b,BIO_C_GET_FD,0,(char *)c)
# define BIO_get_flags(b) BIO_test_flags(b, ~(0x0))
# define BIO_get_fp(b,fpp)       BIO_ctrl(b,BIO_C_GET_FILE_PTR,0,(char *)fpp)
# define BIO_get_info_callback(b,cbp) (int)BIO_ctrl(b,BIO_CTRL_GET_CALLBACK,0, \
                                                   cbp)
# define BIO_get_mem_data(b,pp)  BIO_ctrl(b,BIO_CTRL_INFO,0,(char *)pp)
# define BIO_get_mem_ptr(b,pp)   BIO_ctrl(b,BIO_C_GET_BUF_MEM_PTR,0,(char *)pp)
# define BIO_get_num_renegotiates(b) \
        BIO_ctrl(b,BIO_C_GET_SSL_NUM_RENEGOTIATES,0,NULL);
# define BIO_get_peer_name(b)          ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,2))
# define BIO_get_peer_port(b)          ((const char *)BIO_ptr_ctrl(b,BIO_C_GET_ACCEPT,3))
# define BIO_get_read_request(b)    (int)BIO_ctrl(b,BIO_C_GET_READ_REQUEST,0,NULL)
# define BIO_get_retry_flags(b) \
                BIO_test_flags(b, (BIO_FLAGS_RWS|BIO_FLAGS_SHOULD_RETRY))
# define BIO_get_ssl(b,sslp)     BIO_ctrl(b,BIO_C_GET_SSL,0,(char *)sslp)
# define BIO_get_write_buf_size(b,size) (size_t)BIO_ctrl(b,BIO_C_GET_WRITE_BUF_SIZE,size,NULL)
# define BIO_get_write_guarantee(b) (int)BIO_ctrl(b,BIO_C_GET_WRITE_GUARANTEE,0,NULL)
# define BIO_make_bio_pair(b1,b2)   (int)BIO_ctrl(b1,BIO_C_MAKE_BIO_PAIR,0,b2)
# define BIO_pending(b)          (int)BIO_ctrl(b,BIO_CTRL_PENDING,0,NULL)
#  define BIO_read_filename(b,name) BIO_ctrl(b,BIO_C_SET_FILENAME, \
                BIO_CLOSE|BIO_FP_READ,(char *)name)
# define BIO_reset(b)            (int)BIO_ctrl(b,BIO_CTRL_RESET,0,NULL)
# define BIO_retry_type(a)               BIO_test_flags(a, BIO_FLAGS_RWS)
# define BIO_rw_filename(b,name) BIO_ctrl(b,BIO_C_SET_FILENAME, \
                BIO_CLOSE|BIO_FP_READ|BIO_FP_WRITE,name)
# define BIO_seek(b,ofs) (int)BIO_ctrl(b,BIO_C_FILE_SEEK,ofs,NULL)
# define BIO_set_accept_bios(b,bio)    BIO_ctrl(b,BIO_C_SET_ACCEPT,3,(char *)bio)
# define BIO_set_accept_ip_family(b,f) BIO_int_ctrl(b,BIO_C_SET_ACCEPT,4,f)
# define BIO_set_accept_name(b,name)   BIO_ctrl(b,BIO_C_SET_ACCEPT,0,(char *)name)
# define BIO_set_accept_port(b,port)   BIO_ctrl(b,BIO_C_SET_ACCEPT,1,(char *)port)
# define BIO_set_app_data(s,arg)         BIO_set_ex_data(s,0,arg)
# define BIO_set_bind_mode(b,mode) BIO_ctrl(b,BIO_C_SET_BIND_MODE,mode,NULL)
# define BIO_set_buffer_read_data(b,buf,num) BIO_ctrl(b,BIO_C_SET_BUFF_READ_DATA,num,buf)
# define BIO_set_buffer_size(b,size)     BIO_ctrl(b,BIO_C_SET_BUFF_SIZE,size,NULL)
# define BIO_set_close(b,c)      (int)BIO_ctrl(b,BIO_CTRL_SET_CLOSE,(c),NULL)
# define BIO_set_conn_address(b,addr)  BIO_ctrl(b,BIO_C_SET_CONNECT,2,(char *)addr)
# define BIO_set_conn_hostname(b,name) BIO_ctrl(b,BIO_C_SET_CONNECT,0,(char *)name)
# define BIO_set_conn_ip_family(b,f)   BIO_int_ctrl(b,BIO_C_SET_CONNECT,3,f)
# define BIO_set_conn_mode(b,n)        BIO_ctrl(b,BIO_C_SET_CONNECT_MODE,(n),NULL)
# define BIO_set_conn_port(b,port)     BIO_ctrl(b,BIO_C_SET_CONNECT,1,(char *)port)
# define BIO_set_fd(b,fd,c)      BIO_int_ctrl(b,BIO_C_SET_FD,c,fd)
# define BIO_set_fp(b,fp,c)      BIO_ctrl(b,BIO_C_SET_FILE_PTR,c,(char *)fp)
# define BIO_set_info_callback(b,cb) (int)BIO_callback_ctrl(b,BIO_CTRL_SET_CALLBACK,cb)
# define BIO_set_mem_buf(b,bm,c) BIO_ctrl(b,BIO_C_SET_BUF_MEM,c,(char *)bm)
# define BIO_set_mem_eof_return(b,v) \
                                BIO_ctrl(b,BIO_C_SET_BUF_MEM_EOF_RETURN,v,NULL)
# define BIO_set_nbio(b,n)             BIO_ctrl(b,BIO_C_SET_NBIO,(n),NULL)
# define BIO_set_nbio_accept(b,n)      BIO_ctrl(b,BIO_C_SET_ACCEPT,2,(n)?(void *)"a":NULL)
# define BIO_set_read_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,0)
# define BIO_set_retry_read(b) \
                BIO_set_flags(b, (BIO_FLAGS_READ|BIO_FLAGS_SHOULD_RETRY))
# define BIO_set_retry_special(b) \
                BIO_set_flags(b, (BIO_FLAGS_IO_SPECIAL|BIO_FLAGS_SHOULD_RETRY))
# define BIO_set_retry_write(b) \
                BIO_set_flags(b, (BIO_FLAGS_WRITE|BIO_FLAGS_SHOULD_RETRY))
# define BIO_set_ssl(b,ssl,c)    BIO_ctrl(b,BIO_C_SET_SSL,c,(char *)ssl)
# define BIO_set_ssl_mode(b,client)      BIO_ctrl(b,BIO_C_SSL_MODE,client,NULL)
# define BIO_set_ssl_renegotiate_bytes(b,num) \
        BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_BYTES,num,NULL);
# define BIO_set_ssl_renegotiate_timeout(b,seconds) \
        BIO_ctrl(b,BIO_C_SET_SSL_RENEGOTIATE_TIMEOUT,seconds,NULL);
# define BIO_set_write_buf_size(b,size) (int)BIO_ctrl(b,BIO_C_SET_WRITE_BUF_SIZE,size,NULL)
# define BIO_set_write_buffer_size(b,size) BIO_int_ctrl(b,BIO_C_SET_BUFF_SIZE,size,1)
# define BIO_should_io_special(a)        BIO_test_flags(a, BIO_FLAGS_IO_SPECIAL)
# define BIO_should_read(a)              BIO_test_flags(a, BIO_FLAGS_READ)
# define BIO_should_retry(a)             BIO_test_flags(a, BIO_FLAGS_SHOULD_RETRY)
# define BIO_should_write(a)             BIO_test_flags(a, BIO_FLAGS_WRITE)
# define BIO_shutdown_wr(b) (int)BIO_ctrl(b, BIO_C_SHUTDOWN_WR, 0, NULL)
# define BIO_tell(b)     (int)BIO_ctrl(b,BIO_C_FILE_TELL,0,NULL)
# define BIO_wpending(b)         (int)BIO_ctrl(b,BIO_CTRL_WPENDING,0,NULL)
# define BIO_write_filename(b,name) BIO_ctrl(b,BIO_C_SET_FILENAME, \
                BIO_CLOSE|BIO_FP_WRITE,name)
# define HEADER_BIO_H
#  define __bio_h__attr__ __attribute__
# define BN_BITS        (BN_BITS2 * 2)
# define BN_BITS2       (BN_BYTES * 8)
# define BN_BLINDING_NO_RECREATE 0x00000002
# define BN_BLINDING_NO_UPDATE   0x00000001
#  define BN_BYTES        8
# define BN_FLG_CONSTTIME        0x04
#  define BN_FLG_EXP_CONSTTIME BN_FLG_CONSTTIME
#  define BN_FLG_FREE            0x8000 
# define BN_FLG_MALLOCED         0x01
# define BN_FLG_SECURE           0x08
# define BN_FLG_STATIC_DATA      0x02
# define BN_F_BNRAND                                      127
# define BN_F_BN_BLINDING_CONVERT_EX                      100
# define BN_F_BN_BLINDING_CREATE_PARAM                    128
# define BN_F_BN_BLINDING_INVERT_EX                       101
# define BN_F_BN_BLINDING_NEW                             102
# define BN_F_BN_BLINDING_UPDATE                          103
# define BN_F_BN_BN2DEC                                   104
# define BN_F_BN_BN2HEX                                   105
# define BN_F_BN_COMPUTE_WNAF                             142
# define BN_F_BN_CTX_GET                                  116
# define BN_F_BN_CTX_NEW                                  106
# define BN_F_BN_CTX_START                                129
# define BN_F_BN_DIV                                      107
# define BN_F_BN_DIV_NO_BRANCH                            138
# define BN_F_BN_DIV_RECP                                 130
# define BN_F_BN_EXP                                      123
# define BN_F_BN_EXPAND2                                  108
# define BN_F_BN_EXPAND_INTERNAL                          120
# define BN_F_BN_GENCB_NEW                                143
# define BN_F_BN_GENERATE_DSA_NONCE                       140
# define BN_F_BN_GENERATE_PRIME_EX                        141
# define BN_F_BN_GF2M_MOD                                 131
# define BN_F_BN_GF2M_MOD_EXP                             132
# define BN_F_BN_GF2M_MOD_MUL                             133
# define BN_F_BN_GF2M_MOD_SOLVE_QUAD                      134
# define BN_F_BN_GF2M_MOD_SOLVE_QUAD_ARR                  135
# define BN_F_BN_GF2M_MOD_SQR                             136
# define BN_F_BN_GF2M_MOD_SQRT                            137
# define BN_F_BN_LSHIFT                                   145
# define BN_F_BN_MOD_EXP2_MONT                            118
# define BN_F_BN_MOD_EXP_MONT                             109
# define BN_F_BN_MOD_EXP_MONT_CONSTTIME                   124
# define BN_F_BN_MOD_EXP_MONT_WORD                        117
# define BN_F_BN_MOD_EXP_RECP                             125
# define BN_F_BN_MOD_EXP_SIMPLE                           126
# define BN_F_BN_MOD_INVERSE                              110
# define BN_F_BN_MOD_INVERSE_NO_BRANCH                    139
# define BN_F_BN_MOD_LSHIFT_QUICK                         119
# define BN_F_BN_MOD_MUL_RECIPROCAL                       111
# define BN_F_BN_MOD_SQRT                                 121
# define BN_F_BN_MPI2BN                                   112
# define BN_F_BN_NEW                                      113
# define BN_F_BN_RAND                                     114
# define BN_F_BN_RAND_RANGE                               122
# define BN_F_BN_RSHIFT                                   146
# define BN_F_BN_SET_WORDS                                144
# define BN_F_BN_USUB                                     115
#  define BN_GF2m_cmp(a, b) BN_ucmp((a), (b))
#  define BN_GF2m_sub(r, a, b) BN_GF2m_add(r, a, b)
# define BN_R_ARG2_LT_ARG3                                100
# define BN_R_BAD_RECIPROCAL                              101
# define BN_R_BIGNUM_TOO_LONG                             114
# define BN_R_BITS_TOO_SMALL                              118
# define BN_R_CALLED_WITH_EVEN_MODULUS                    102
# define BN_R_DIV_BY_ZERO                                 103
# define BN_R_ENCODING_ERROR                              104
# define BN_R_EXPAND_ON_STATIC_BIGNUM_DATA                105
# define BN_R_INPUT_NOT_REDUCED                           110
# define BN_R_INVALID_LENGTH                              106
# define BN_R_INVALID_RANGE                               115
# define BN_R_INVALID_SHIFT                               119
# define BN_R_NOT_A_SQUARE                                111
# define BN_R_NOT_INITIALIZED                             107
# define BN_R_NO_INVERSE                                  108
# define BN_R_NO_SOLUTION                                 116
# define BN_R_PRIVATE_KEY_TOO_LARGE                       117
# define BN_R_P_IS_NOT_PRIME                              112
# define BN_R_TOO_MANY_ITERATIONS                         113
# define BN_R_TOO_MANY_TEMPORARY_VARIABLES                109
# define BN_TBIT        ((BN_ULONG)1 << (BN_BITS2 - 1))
#  define BN_ULONG        unsigned long
# define BN_mod(rem,m,d,ctx) BN_div(NULL,(rem),(m),(d),(ctx))
# define BN_num_bytes(a) ((BN_num_bits(a)+7)/8)
# define BN_one(a)       (BN_set_word((a),1))
# define BN_prime_checks 0      
# define BN_prime_checks_for_size(b) ((b) >= 1300 ?  2 : \
                                (b) >=  850 ?  3 : \
                                (b) >=  650 ?  4 : \
                                (b) >=  550 ?  5 : \
                                (b) >=  450 ?  6 : \
                                (b) >=  400 ?  7 : \
                                (b) >=  350 ?  8 : \
                                (b) >=  300 ?  9 : \
                                (b) >=  250 ? 12 : \
                                (b) >=  200 ? 15 : \
                                (b) >=  150 ? 18 : \
                                 27)
#  define BN_zero(a)      BN_zero_ex(a)
# define HEADER_BN_H
# define DECIMAL_SIZE(type)      ((sizeof(type)*8+2)/3+1)
# define HEADER_CRYPTLIB_H
# define HEX_SIZE(type)          (sizeof(type)*2)
#  define X509_CERT_AREA          OPENSSLDIR
#  define X509_CERT_DIR           OPENSSLDIR "/certs"
# define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
#  define X509_CERT_FILE          "SSLCERTS:cert.pem"
# define X509_CERT_FILE_EVP       "SSL_CERT_FILE"
#  define X509_PRIVATE_DIR        "SSLPRIVATE:"
