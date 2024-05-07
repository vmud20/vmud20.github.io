










int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_MONT_CTX *mont, BN_CTX *ctx)
	{
	BIGNUM *tmp;
	int ret=0;

	BN_CTX_start(ctx);
	tmp = BN_CTX_get(ctx);
	if (tmp == NULL) goto err;

	bn_check_top(tmp);
	if (a == b)
		{
		if (!BN_sqr(tmp,a,ctx)) goto err;
		}
	else {
		if (!BN_mul(tmp,a,b,ctx)) goto err;
		}
	
	if (!BN_from_montgomery(r,tmp,mont,ctx)) goto err;
	ret=1;
err:
	BN_CTX_end(ctx);
	return(ret);
	}

int BN_from_montgomery(BIGNUM *ret, const BIGNUM *a, BN_MONT_CTX *mont, BN_CTX *ctx)
	{
	int retn=0;


	BIGNUM *n,*r;
	BN_ULONG *ap,*np,*rp,n0,v,*nrp;
	int al,nl,max,i,x,ri;

	BN_CTX_start(ctx);
	if ((r = BN_CTX_get(ctx)) == NULL) goto err;

	if (!BN_copy(r,a)) goto err;
	n= &(mont->N);

	ap=a->d;
	
	al=ri=mont->ri/BN_BITS2;
	
	nl=n->top;
	if ((al == 0) || (nl == 0)) { r->top=0; return(1); }

	max=(nl+al+1); 
	if (bn_wexpand(r,max) == NULL) goto err;
	if (bn_wexpand(ret,max) == NULL) goto err;

	r->neg=a->neg^n->neg;
	np=n->d;
	rp=r->d;
	nrp= &(r->d[nl]);

	

	for (i=r->top; i<max; i++) 
		r->d[i]=0;

	memset(&(r->d[r->top]),0,(max-r->top)*sizeof(BN_ULONG)); 


	r->top=max;
	n0=mont->n0;


	fprintf(stderr,"word BN_from_montgomery %d * %d\n",nl,nl);

	for (i=0; i<nl; i++)
		{

                {
                   long long t1;
                   long long t2;
                   long long t3;
                   t1 = rp[0] * (n0 & 0177777);
                   t2 = 037777600000l;
                   t2 = n0 & t2;
                   t3 = rp[0] & 0177777;
                   t2 = (t3 * t2) & BN_MASK2;
                   t1 = t1 + t2;
                   v=bn_mul_add_words(rp,np,nl,(BN_ULONG) t1);
                }

		v=bn_mul_add_words(rp,np,nl,(rp[0]*n0)&BN_MASK2);

		nrp++;
		rp++;
		if (((nrp[-1]+=v)&BN_MASK2) >= v)
			continue;
		else {
			if (((++nrp[0])&BN_MASK2) != 0) continue;
			if (((++nrp[1])&BN_MASK2) != 0) continue;
			for (x=2; (((++nrp[x])&BN_MASK2) == 0); x++) ;
			}
		}
	bn_fix_top(r);
	
	

	BN_rshift(ret,r,mont->ri);

	ret->neg = r->neg;
	x=ri;
	rp=ret->d;
	ap= &(r->d[x]);
	if (r->top < x)
		al=0;
	else al=r->top-x;
	ret->top=al;
	al-=4;
	for (i=0; i<al; i+=4)
		{
		BN_ULONG t1,t2,t3,t4;
		
		t1=ap[i+0];
		t2=ap[i+1];
		t3=ap[i+2];
		t4=ap[i+3];
		rp[i+0]=t1;
		rp[i+1]=t2;
		rp[i+2]=t3;
		rp[i+3]=t4;
		}
	al+=4;
	for (; i<al; i++)
		rp[i]=ap[i];


	BIGNUM *t1,*t2;

	BN_CTX_start(ctx);
	t1 = BN_CTX_get(ctx);
	t2 = BN_CTX_get(ctx);
	if (t1 == NULL || t2 == NULL) goto err;
	
	if (!BN_copy(t1,a)) goto err;
	BN_mask_bits(t1,mont->ri);

	if (!BN_mul(t2,t1,&mont->Ni,ctx)) goto err;
	BN_mask_bits(t2,mont->ri);

	if (!BN_mul(t1,t2,&mont->N,ctx)) goto err;
	if (!BN_add(t2,a,t1)) goto err;
	if (!BN_rshift(ret,t2,mont->ri)) goto err;


	if (BN_ucmp(ret, &(mont->N)) >= 0)
		{
		if (!BN_usub(ret,ret,&(mont->N))) goto err;
		}
	retn=1;
 err:
	BN_CTX_end(ctx);
	return(retn);
	}

BN_MONT_CTX *BN_MONT_CTX_new(void)
	{
	BN_MONT_CTX *ret;

	if ((ret=(BN_MONT_CTX *)OPENSSL_malloc(sizeof(BN_MONT_CTX))) == NULL)
		return(NULL);

	BN_MONT_CTX_init(ret);
	ret->flags=BN_FLG_MALLOCED;
	return(ret);
	}

void BN_MONT_CTX_init(BN_MONT_CTX *ctx)
	{
	ctx->ri=0;
	BN_init(&(ctx->RR));
	BN_init(&(ctx->N));
	BN_init(&(ctx->Ni));
	ctx->flags=0;
	}

void BN_MONT_CTX_free(BN_MONT_CTX *mont)
	{
	if(mont == NULL)
	    return;

	BN_free(&(mont->RR));
	BN_free(&(mont->N));
	BN_free(&(mont->Ni));
	if (mont->flags & BN_FLG_MALLOCED)
		OPENSSL_free(mont);
	}

int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx)
	{
	BIGNUM Ri,*R;

	BN_init(&Ri);
	R= &(mont->RR);					
	if (!BN_copy(&(mont->N),mod)) goto err;		
	mont->N.neg = 0;


		{
		BIGNUM tmod;
		BN_ULONG buf[2];

		mont->ri=(BN_num_bits(mod)+(BN_BITS2-1))/BN_BITS2*BN_BITS2;
		if (!(BN_zero(R))) goto err;
		if (!(BN_set_bit(R,BN_BITS2))) goto err;	

		buf[0]=mod->d[0]; 
		buf[1]=0;
		tmod.d=buf;
		tmod.top=1;
		tmod.dmax=2;
		tmod.neg=0;
							
		if ((BN_mod_inverse(&Ri,R,&tmod,ctx)) == NULL)
			goto err;
		if (!BN_lshift(&Ri,&Ri,BN_BITS2)) goto err; 
		if (!BN_is_zero(&Ri))
			{
			if (!BN_sub_word(&Ri,1)) goto err;
			}
		else  {
			if (!BN_set_word(&Ri,BN_MASK2)) goto err;  
			}
		if (!BN_div(&Ri,NULL,&Ri,&tmod,ctx)) goto err;
		
		mont->n0 = (Ri.top > 0) ? Ri.d[0] : 0;
		BN_free(&Ri);
		}

		{ 
		mont->ri=BN_num_bits(&mont->N);
		if (!BN_zero(R)) goto err;
		if (!BN_set_bit(R,mont->ri)) goto err;  
		                                        
		if ((BN_mod_inverse(&Ri,R,&mont->N,ctx)) == NULL)
			goto err;
		if (!BN_lshift(&Ri,&Ri,mont->ri)) goto err; 
		if (!BN_sub_word(&Ri,1)) goto err;
							
		if (!BN_div(&(mont->Ni),NULL,&Ri,&mont->N,ctx)) goto err;
		BN_free(&Ri);
		}


	
	if (!BN_zero(&(mont->RR))) goto err;
	if (!BN_set_bit(&(mont->RR),mont->ri*2)) goto err;
	if (!BN_mod(&(mont->RR),&(mont->RR),&(mont->N),ctx)) goto err;

	return(1);
err:
	return(0);
	}

BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from)
	{
	if (to == from) return(to);

	if (!BN_copy(&(to->RR),&(from->RR))) return NULL;
	if (!BN_copy(&(to->N),&(from->N))) return NULL;
	if (!BN_copy(&(to->Ni),&(from->Ni))) return NULL;
	to->ri=from->ri;
	to->n0=from->n0;
	return(to);
	}

BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, int lock, const BIGNUM *mod, BN_CTX *ctx)
	{
	if (*pmont)
		return *pmont;
	CRYPTO_w_lock(lock);
	if (!*pmont)
		{
		*pmont = BN_MONT_CTX_new();
		if (*pmont && !BN_MONT_CTX_set(*pmont, mod, ctx))
			{
			BN_MONT_CTX_free(*pmont);
			*pmont = NULL;
			}
		}
	CRYPTO_w_unlock(lock);
	return *pmont;
	}
		

