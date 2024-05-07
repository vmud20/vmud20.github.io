






#include<strings.h>













#include<stddef.h>
















#include<memory.h>




#include<time.h>



#include<stdbool.h>














#include<ctype.h>
#include<unistd.h>
#include<signal.h>




















#include<stdint.h>










#include<limits.h>
#include<stdio.h>

#include<sys/types.h>
#include<string.h>


#define MUTT_ALIAS         (1 << 0)  
#define MUTT_CLEAR         (1 << 5)  
#define MUTT_CMD           (1 << 3)  
#define MUTT_COMMAND       (1 << 6)  
#define MUTT_COMP_NO_FLAGS       0   
#define MUTT_EFILE         (1 << 2)  
#define MUTT_FILE          (1 << 1)  
#define MUTT_LABEL         (1 << 8)  

#define MUTT_NM_QUERY      (1 << 9)  
#define MUTT_NM_TAG        (1 << 10) 
#define MUTT_NOSPAM 2
#define MUTT_PASS          (1 << 4)  
#define MUTT_PATTERN       (1 << 7)  
#define MUTT_SPAM   1
#define MUTT_TOKEN_BACKTICK_VARS (1 << 7)  
#define MUTT_TOKEN_COMMENT       (1 << 5)  
#define MUTT_TOKEN_CONDENSE      (1 << 1)  
#define MUTT_TOKEN_EQUAL         (1 << 0)  
#define MUTT_TOKEN_MINUS         (1 << 11)  
#define MUTT_TOKEN_NOSHELL       (1 << 8)  
#define MUTT_TOKEN_NO_FLAGS            0   
#define MUTT_TOKEN_PATTERN       (1 << 4)  
#define MUTT_TOKEN_PLUS          (1 << 10)  
#define MUTT_TOKEN_QUESTION      (1 << 9)  
#define MUTT_TOKEN_QUOTE         (1 << 3)  
#define MUTT_TOKEN_SEMICOLON     (1 << 6)  
#define MUTT_TOKEN_SPACE         (1 << 2)  
#define PATH_MAX 4096

#define fgetc fgetc_unlocked
#define fgets fgets_unlocked
#define MAX_SEQ 8

#define MUTT_UNBIND  1<<0
#define MUTT_UNMACRO 1<<1

#define MUTT_NAMED   (1 << 0)


#define mutt_set_flag(m, e, flag, bf) mutt_set_flag_update(m, e, flag, bf, true)
#define APPLICATION_PGP         (1 << 11) 
#define APPLICATION_SMIME       (1 << 12) 
#define KEYFLAG_ABILITIES (KEYFLAG_CANSIGN | KEYFLAG_CANENCRYPT | KEYFLAG_PREFER_ENCRYPTION | KEYFLAG_PREFER_SIGNING)
#define KEYFLAG_CANENCRYPT        (1 << 1)  
#define KEYFLAG_CANSIGN           (1 << 0)  
#define KEYFLAG_CANTUSE (KEYFLAG_DISABLED | KEYFLAG_REVOKED | KEYFLAG_EXPIRED)
#define KEYFLAG_CRITICAL          (1 << 12) 
#define KEYFLAG_DISABLED          (1 << 10) 
#define KEYFLAG_EXPIRED           (1 << 8)  
#define KEYFLAG_ISX509            (1 << 2)  
#define KEYFLAG_NO_FLAGS                0   
#define KEYFLAG_PREFER_ENCRYPTION (1 << 13) 
#define KEYFLAG_PREFER_SIGNING    (1 << 14) 
#define KEYFLAG_RESTRICTIONS (KEYFLAG_CANTUSE | KEYFLAG_CRITICAL)
#define KEYFLAG_REVOKED           (1 << 9)  
#define KEYFLAG_SECRET            (1 << 7)  
#define KEYFLAG_SUBKEY            (1 << 11) 

#define PGP_ENCRYPT  (APPLICATION_PGP | SEC_ENCRYPT)
#define PGP_GOODSIGN (APPLICATION_PGP | SEC_GOODSIGN)
#define PGP_INLINE   (APPLICATION_PGP | SEC_INLINE)
#define PGP_KEY      (APPLICATION_PGP | SEC_KEYBLOCK)
#define PGP_SIGN     (APPLICATION_PGP | SEC_SIGN)
#define PGP_TRADITIONAL_CHECKED (1 << 13) 
#define SEC_ALL_FLAGS          ((1 << 14) - 1)
#define SEC_AUTOCRYPT           (1 << 9)  
#define SEC_AUTOCRYPT_OVERRIDE  (1 << 10) 
#define SEC_BADSIGN             (1 << 3)  
#define SEC_ENCRYPT             (1 << 0)  
#define SEC_GOODSIGN            (1 << 2)  
#define SEC_INLINE              (1 << 7)  
#define SEC_KEYBLOCK            (1 << 6)  
#define SEC_NO_FLAGS                  0   
#define SEC_OPPENCRYPT          (1 << 8)  
#define SEC_PARTSIGN            (1 << 4)  
#define SEC_SIGN                (1 << 1)  
#define SEC_SIGNOPAQUE          (1 << 5)  
#define SMIME_BADSIGN  (APPLICATION_SMIME | SEC_BADSIGN)
#define SMIME_ENCRYPT  (APPLICATION_SMIME | SEC_ENCRYPT)
#define SMIME_GOODSIGN (APPLICATION_SMIME | SEC_GOODSIGN)
#define SMIME_OPAQUE   (APPLICATION_SMIME | SEC_SIGNOPAQUE)
#define SMIME_SIGN     (APPLICATION_SMIME | SEC_SIGN)
#define WithCrypto (APPLICATION_PGP | APPLICATION_SMIME)



#define SORT_CODE(x) ((OptAuxSort ? C_SortAux : C_Sort) & SORT_REVERSE) ? -(x) : x
#define INITVAL(x) = x

#define WHERE extern



#define MUTT_ADD_FROM     (1 << 0) 
#define MUTT_APPEND        (1 << 1) 
#define MUTT_APPENDNEW     (1 << 6) 
#define MUTT_MSG_NO_FLAGS       0  

#define MUTT_NEWFOLDER     (1 << 4) 
#define MUTT_NOSORT        (1 << 0) 
#define MUTT_OPEN_NO_FLAGS       0  
#define MUTT_PEEK          (1 << 5) 
#define MUTT_QUIET         (1 << 3) 
#define MUTT_READONLY      (1 << 2) 
#define MUTT_SET_DRAFT    (1 << 1) 


#define mutt_buffer_mktemp(buf)                         mutt_buffer_mktemp_pfx_sfx(buf, "neomutt", NULL)
#define mutt_buffer_mktemp_pfx_sfx(buf, prefix, suffix) mutt_buffer_mktemp_full(buf, prefix, suffix, "__FILE__", "__LINE__")
#define mutt_mktemp(buf, buflen)                         mutt_mktemp_pfx_sfx(buf, buflen, "neomutt", NULL)
#define mutt_mktemp_pfx_sfx(buf, buflen, prefix, suffix) mutt_mktemp_full(buf, buflen, prefix, suffix, "__FILE__", "__LINE__")

#define MUTT_FORMAT_ARROWCURSOR (1 << 4) 

#define MUTT_FORMAT_FORCESUBJ   (1 << 0) 
#define MUTT_FORMAT_INDEX       (1 << 5) 
#define MUTT_FORMAT_NOFILTER    (1 << 6) 
#define MUTT_FORMAT_NO_FLAGS          0  
#define MUTT_FORMAT_OPTIONAL    (1 << 2) 
#define MUTT_FORMAT_PLAIN       (1 << 7) 
#define MUTT_FORMAT_STAT_FILE   (1 << 3) 
#define MUTT_FORMAT_TREE        (1 << 1) 

#define MUTT_SOCK_LOG_CMD  2
#define MUTT_SOCK_LOG_FULL 5
#define MUTT_SOCK_LOG_HDR  3
#define mutt_socket_readln(buf, buflen, conn) mutt_socket_readln_d(buf, buflen, conn, MUTT_SOCK_LOG_CMD)
#define mutt_socket_send(conn, buf)           mutt_socket_send_d(conn, buf, MUTT_SOCK_LOG_CMD)
#define mutt_socket_send_d(conn, buf, dbg)    mutt_socket_write_d(conn, buf, mutt_str_strlen(buf), dbg)
#define mutt_socket_write_n(conn, buf, len)   mutt_socket_write_d(conn, buf, len, MUTT_SOCK_LOG_CMD)




#define MUTT_ACCOUNT_HOOK  (1 << 9)  
#define MUTT_APPEND_HOOK   (1 << 13) 
#define MUTT_CHARSET_HOOK  (1 << 5)  
#define MUTT_CLOSE_HOOK    (1 << 14) 
#define MUTT_CRYPT_HOOK    (1 << 8)  
#define MUTT_FCC_HOOK      (1 << 3)  
#define MUTT_FOLDER_HOOK   (1 << 0)  
#define MUTT_GLOBAL_HOOK   (1 << 19) 

#define MUTT_HOOK_NO_FLAGS       0   
#define MUTT_ICONV_HOOK    (1 << 6)  
#define MUTT_IDXFMTHOOK    (1 << 15) 
#define MUTT_MBOX_HOOK     (1 << 1)  
#define MUTT_MESSAGE_HOOK  (1 << 7)  
#define MUTT_OPEN_HOOK     (1 << 12) 
#define MUTT_REPLY_HOOK    (1 << 10) 
#define MUTT_SAVE_HOOK     (1 << 4)  
#define MUTT_SEND2_HOOK    (1 << 11) 
#define MUTT_SEND_HOOK     (1 << 2)  
#define MUTT_SHUTDOWN_HOOK (1 << 18) 
#define MUTT_STARTUP_HOOK  (1 << 17) 
#define MUTT_TIMEOUT_HOOK  (1 << 16) 


#define ANUM "%u"

#define NNTP_ACACHE_LEN 10
#define anum_t uint32_t



#define NNTP_PORT 119
#define NNTP_SSL_PORT 563
