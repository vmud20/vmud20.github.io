



#include<sys/cdefs.h>






#define BLOCK_CIPHER_all_funcs(cname, cprefix, cbits, kstruct, ksched) \
	BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched) \
	BLOCK_CIPHER_func_cfb(cname, cprefix, cbits, kstruct, ksched) \
	BLOCK_CIPHER_func_ecb(cname, cprefix, kstruct, ksched) \
	BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched)
#define BLOCK_CIPHER_def1(cname, nmode, mode, MODE, kstruct, nid, block_size, \
			  key_len, iv_len, flags, init_key, cleanup, \
			  set_asn1, get_asn1, ctrl) \
static const EVP_CIPHER cname##_##mode = { \
	nid##_##nmode, block_size, key_len, iv_len, \
	flags | EVP_CIPH_##MODE##_MODE, \
	init_key, \
	cname##_##mode##_cipher, \
	cleanup, \
	sizeof(kstruct), \
	set_asn1, get_asn1,\
	ctrl, \
	NULL \
}; \
const EVP_CIPHER *EVP_##cname##_##mode(void) { return &cname##_##mode; }
#define BLOCK_CIPHER_def_cbc(cname, kstruct, nid, block_size, key_len, \
			     iv_len, flags, init_key, cleanup, set_asn1, \
			     get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, cbc, cbc, CBC, kstruct, nid, block_size, key_len, \
		  iv_len, flags, init_key, cleanup, set_asn1, get_asn1, ctrl)
#define BLOCK_CIPHER_def_cfb(cname, kstruct, nid, key_len, \
			     iv_len, cbits, flags, init_key, cleanup, \
			     set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, cfb##cbits, cfb##cbits, CFB, kstruct, nid, 1, \
		  key_len, iv_len, flags, init_key, cleanup, set_asn1, \
		  get_asn1, ctrl)
#define BLOCK_CIPHER_def_ecb(cname, kstruct, nid, block_size, key_len, \
			     flags, init_key, cleanup, set_asn1, \
			     get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, ecb, ecb, ECB, kstruct, nid, block_size, key_len, \
		  0, flags, init_key, cleanup, set_asn1, get_asn1, ctrl)
#define BLOCK_CIPHER_def_ofb(cname, kstruct, nid, key_len, \
			     iv_len, cbits, flags, init_key, cleanup, \
			     set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def1(cname, ofb##cbits, ofb, OFB, kstruct, nid, 1, \
		  key_len, iv_len, flags, init_key, cleanup, set_asn1, \
		  get_asn1, ctrl)
#define BLOCK_CIPHER_defs(cname, kstruct, \
			  nid, block_size, key_len, iv_len, cbits, flags, \
			  init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_cbc(cname, kstruct, nid, block_size, key_len, iv_len, flags, \
		     init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_cfb(cname, kstruct, nid, key_len, iv_len, cbits, \
		     flags, init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_ofb(cname, kstruct, nid, key_len, iv_len, cbits, \
		     flags, init_key, cleanup, set_asn1, get_asn1, ctrl) \
BLOCK_CIPHER_def_ecb(cname, kstruct, nid, block_size, key_len, flags, \
		     init_key, cleanup, set_asn1, get_asn1, ctrl)
#define BLOCK_CIPHER_ecb_loop() \
	size_t i, bl; \
	bl = ctx->cipher->block_size;\
	if(inl < bl) return 1;\
	inl -= bl; \
	for(i=0; i <= inl; i+=bl)
#define BLOCK_CIPHER_func_cbc(cname, cprefix, kstruct, ksched) \
static int cname##_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
	while(inl>=EVP_MAXCHUNK) \
	    {\
	    cprefix##_cbc_encrypt(in, out, (long)EVP_MAXCHUNK, &((kstruct *)ctx->cipher_data)->ksched, ctx->iv, ctx->encrypt);\
	    inl-=EVP_MAXCHUNK;\
	    in +=EVP_MAXCHUNK;\
	    out+=EVP_MAXCHUNK;\
	    }\
	if (inl)\
	    cprefix##_cbc_encrypt(in, out, (long)inl, &((kstruct *)ctx->cipher_data)->ksched, ctx->iv, ctx->encrypt);\
	return 1;\
}
#define BLOCK_CIPHER_func_cfb(cname, cprefix, cbits, kstruct, ksched) \
static int cname##_cfb##cbits##_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
	size_t chunk=EVP_MAXCHUNK;\
	if (cbits==1)  chunk>>=3;\
	if (inl<chunk) chunk=inl;\
	while(inl && inl>=chunk)\
	    {\
            cprefix##_cfb##cbits##_encrypt(in, out, (long)((cbits==1) && !(ctx->flags & EVP_CIPH_FLAG_LENGTH_BITS) ?inl*8:inl), &((kstruct *)ctx->cipher_data)->ksched, ctx->iv, &ctx->num, ctx->encrypt);\
	    inl-=chunk;\
	    in +=chunk;\
	    out+=chunk;\
	    if(inl<chunk) chunk=inl;\
	    }\
	return 1;\
}
#define BLOCK_CIPHER_func_ecb(cname, cprefix, kstruct, ksched) \
static int cname##_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
	BLOCK_CIPHER_ecb_loop() \
		cprefix##_ecb_encrypt(in + i, out + i, &((kstruct *)ctx->cipher_data)->ksched, ctx->encrypt);\
	return 1;\
}
#define BLOCK_CIPHER_func_ofb(cname, cprefix, cbits, kstruct, ksched) \
static int cname##_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl) \
{\
	while(inl>=EVP_MAXCHUNK)\
	    {\
	    cprefix##_ofb##cbits##_encrypt(in, out, (long)EVP_MAXCHUNK, &((kstruct *)ctx->cipher_data)->ksched, ctx->iv, &ctx->num);\
	    inl-=EVP_MAXCHUNK;\
	    in +=EVP_MAXCHUNK;\
	    out+=EVP_MAXCHUNK;\
	    }\
	if (inl)\
	    cprefix##_ofb##cbits##_encrypt(in, out, (long)inl, &((kstruct *)ctx->cipher_data)->ksched, ctx->iv, &ctx->num);\
	return 1;\
}
#define EVP_C_DATA(kstruct, ctx)	((kstruct *)(ctx)->cipher_data)
#define EVP_MAXCHUNK ((size_t)1<<(sizeof(long)*8-2))
#define IMPLEMENT_BLOCK_CIPHER(cname, ksched, cprefix, kstruct, nid, \
			       block_size, key_len, iv_len, cbits, \
			       flags, init_key, \
			       cleanup, set_asn1, get_asn1, ctrl) \
	BLOCK_CIPHER_all_funcs(cname, cprefix, cbits, kstruct, ksched) \
	BLOCK_CIPHER_defs(cname, kstruct, nid, block_size, key_len, iv_len, \
			  cbits, flags, init_key, cleanup, set_asn1, \
			  get_asn1, ctrl)
#define IMPLEMENT_CFBR(cipher,cprefix,kstruct,ksched,keysize,cbits,iv_len) \
	BLOCK_CIPHER_func_cfb(cipher##_##keysize,cprefix,cbits,kstruct,ksched) \
	BLOCK_CIPHER_def_cfb(cipher##_##keysize,kstruct, \
			     NID_##cipher##_##keysize, keysize/8, iv_len, cbits, \
			     0, cipher##_init_key, NULL, \
			     EVP_CIPHER_set_asn1_iv, \
			     EVP_CIPHER_get_asn1_iv, \
			     NULL)
#define CMS_CERTCHOICE_CERT             0
#define CMS_CERTCHOICE_EXCERT           1
#define CMS_CERTCHOICE_OTHER            4
#define CMS_CERTCHOICE_V1ACERT          2
#define CMS_CERTCHOICE_V2ACERT          3
#define CMS_OIK_ISSUER_SERIAL           0
#define CMS_OIK_KEYIDENTIFIER           1
#define CMS_OIK_PUBKEY                  2
#define CMS_RECIPINFO_ISSUER_SERIAL     0
#define CMS_RECIPINFO_KEYIDENTIFIER     1
#define CMS_REK_ISSUER_SERIAL           0
#define CMS_REK_KEYIDENTIFIER           1
#define CMS_REVCHOICE_CRL               0
#define CMS_REVCHOICE_OTHER             1
#define CMS_SIGNERINFO_ISSUER_SERIAL    0
#define CMS_SIGNERINFO_KEYIDENTIFIER    1


#define X509_CERT_DIR_EVP        "SSL_CERT_DIR"
#define X509_CERT_FILE_EVP       "SSL_CERT_FILE"

