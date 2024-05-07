








static int generate_key(DH *dh);
static int compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);
static int dh_bn_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);


static int dh_init(DH *dh);
static int dh_finish(DH *dh);

int DH_generate_key(DH *dh)
	{
	return dh->meth->generate_key(dh);
	}

int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
	{
	return dh->meth->compute_key(key, pub_key, dh);
	}

static DH_METHOD dh_ossl = {
"OpenSSL DH Method", generate_key, compute_key, dh_bn_mod_exp, dh_init, dh_finish, 0, NULL, NULL };









const DH_METHOD *DH_OpenSSL(void)
{
	return &dh_ossl;
}

static int generate_key(DH *dh)
	{
	int ok=0;
	int generate_new_key=0;
	unsigned l;
	BN_CTX *ctx;
	BN_MONT_CTX *mont=NULL;
	BIGNUM *pub_key=NULL,*priv_key=NULL;

	ctx = BN_CTX_new();
	if (ctx == NULL) goto err;

	if (dh->priv_key == NULL)
		{
		priv_key=BN_new();
		if (priv_key == NULL) goto err;
		generate_new_key=1;
		}
	else priv_key=dh->priv_key;

	if (dh->pub_key == NULL)
		{
		pub_key=BN_new();
		if (pub_key == NULL) goto err;
		}
	else pub_key=dh->pub_key;


	if (dh->flags & DH_FLAG_CACHE_MONT_P)
		{
		mont = BN_MONT_CTX_set_locked(&dh->method_mont_p, CRYPTO_LOCK_DH, dh->p, ctx);
		if (!mont)
			goto err;
		}

	if (generate_new_key)
		{
		l = dh->length ? dh->length : BN_num_bits(dh->p)-1; 
		if (!BN_rand(priv_key, l, 0, 0)) goto err;
		}

	{
		BIGNUM local_prk;
		BIGNUM *prk;

		if ((dh->flags & DH_FLAG_NO_EXP_CONSTTIME) == 0)
			{
			BN_init(&local_prk);
			prk = &local_prk;
			BN_with_flags(prk, priv_key, BN_FLG_EXP_CONSTTIME);
			}
		else prk = priv_key;

		if (!dh->meth->bn_mod_exp(dh, pub_key, dh->g, prk, dh->p, ctx, mont)) goto err;
	}
		
	dh->pub_key=pub_key;
	dh->priv_key=priv_key;
	ok=1;
err:
	if (ok != 1)
		DHerr(DH_F_GENERATE_KEY,ERR_R_BN_LIB);

	if ((pub_key != NULL)  && (dh->pub_key == NULL))  BN_free(pub_key);
	if ((priv_key != NULL) && (dh->priv_key == NULL)) BN_free(priv_key);
	BN_CTX_free(ctx);
	return(ok);
	}

static int compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
	{
	BN_CTX *ctx;
	BN_MONT_CTX *mont=NULL;
	BIGNUM *tmp;
	int ret= -1;
        int check_result;

	ctx = BN_CTX_new();
	if (ctx == NULL) goto err;
	BN_CTX_start(ctx);
	tmp = BN_CTX_get(ctx);
	
	if (dh->priv_key == NULL)
		{
		DHerr(DH_F_COMPUTE_KEY,DH_R_NO_PRIVATE_VALUE);
		goto err;
		}

	if (dh->flags & DH_FLAG_CACHE_MONT_P)
		{
		mont = BN_MONT_CTX_set_locked(&dh->method_mont_p, CRYPTO_LOCK_DH, dh->p, ctx);
		if ((dh->flags & DH_FLAG_NO_EXP_CONSTTIME) == 0)
			{
			
			BN_set_flags(dh->priv_key, BN_FLG_EXP_CONSTTIME);
			}
		if (!mont)
			goto err;
		}

        if (!DH_check_pub_key(dh, pub_key, &check_result) || check_result)
		{
		DHerr(DH_F_COMPUTE_KEY,DH_R_INVALID_PUBKEY);
		goto err;
		}

	if (!dh->meth->bn_mod_exp(dh, tmp, pub_key, dh->priv_key,dh->p,ctx,mont))
		{
		DHerr(DH_F_COMPUTE_KEY,ERR_R_BN_LIB);
		goto err;
		}

	ret=BN_bn2bin(tmp,key);
err:
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		}
	return(ret);
	}

static int dh_bn_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)


	{
	
	if (a->top == 1 && ((dh->flags & DH_FLAG_NO_EXP_CONSTTIME) != 0))
		{
		BN_ULONG A = a->d[0];
		return BN_mod_exp_mont_word(r,A,p,m,ctx,m_ctx);
		}
	else return BN_mod_exp_mont(r,a,p,m,ctx,m_ctx);
	}


static int dh_init(DH *dh)
	{
	dh->flags |= DH_FLAG_CACHE_MONT_P;
	return(1);
	}

static int dh_finish(DH *dh)
	{
	if(dh->method_mont_p)
		BN_MONT_CTX_free(dh->method_mont_p);
	return(1);
	}
