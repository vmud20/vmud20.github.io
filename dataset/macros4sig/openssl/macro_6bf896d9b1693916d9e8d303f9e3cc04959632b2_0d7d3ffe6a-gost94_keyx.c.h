#include<string.h>










#include<stdlib.h>


#define EVP_MD_CTRL_KEY_LEN (EVP_MD_CTRL_ALG_CTRL+3)
#define EVP_MD_CTRL_SET_KEY (EVP_MD_CTRL_ALG_CTRL+4)
#define EVP_PKEY_CTRL_GOST_MAC_HEXKEY (EVP_PKEY_ALG_CTRL+3)
#define EVP_PKEY_CTRL_GOST_PARAMSET (EVP_PKEY_ALG_CTRL+1)
#define GOST_CTRL_CRYPT_PARAMS (ENGINE_CMD_BASE+GOST_PARAM_CRYPT_PARAMS)
#define GOST_PARAM_CRYPT_PARAMS 0
#define GOST_PARAM_MAX 0

#define hexkey_ctrl_string "hexkey"
#define key_ctrl_string "key"
#define param_ctrl_string "paramset"



#define GOSTerr(f,r) ERR_GOST_error((f),(r),"__FILE__","__LINE__")

