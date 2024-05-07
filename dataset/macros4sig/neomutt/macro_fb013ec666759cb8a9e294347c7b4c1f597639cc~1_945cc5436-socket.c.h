
#include<stdbool.h>
#include<stddef.h>










#include<stdint.h>











#include<memory.h>

#include<limits.h>
#include<errno.h>


#include<stdio.h>



#include<string.h>


#include<time.h>


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
#define MAX_SEQ 8

#define MUTT_UNBIND  1<<0
#define MUTT_UNMACRO 1<<1

#define MUTT_NAMED   (1 << 0)

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

#define MUTT_ACCT_LOGIN     (1 << 2)  
#define MUTT_ACCT_NO_FLAGS        0   
#define MUTT_ACCT_PASS      (1 << 3)  
#define MUTT_ACCT_PORT      (1 << 0)  
#define MUTT_ACCT_SSL       (1 << 4)  
#define MUTT_ACCT_USER      (1 << 1)  




