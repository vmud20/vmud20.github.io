










int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
	{
	int i,nm,nd;
	int ret = 0;
	BIGNUM *D;

	bn_check_top(m);
	bn_check_top(d);
	if (BN_is_zero(d))
		{
		BNerr(BN_F_BN_DIV,BN_R_DIV_BY_ZERO);
		return(0);
		}

	if (BN_ucmp(m,d) < 0)
		{
		if (rem != NULL)
			{ if (BN_copy(rem,m) == NULL) return(0); }
		if (dv != NULL) BN_zero(dv);
		return(1);
		}

	BN_CTX_start(ctx);
	D = BN_CTX_get(ctx);
	if (dv == NULL) dv = BN_CTX_get(ctx);
	if (rem == NULL) rem = BN_CTX_get(ctx);
	if (D == NULL || dv == NULL || rem == NULL)
		goto end;

	nd=BN_num_bits(d);
	nm=BN_num_bits(m);
	if (BN_copy(D,d) == NULL) goto end;
	if (BN_copy(rem,m) == NULL) goto end;

	
	BN_zero(dv);
	bn_wexpand(dv,1);
	dv->top=1;

	if (!BN_lshift(D,D,nm-nd)) goto end;
	for (i=nm-nd; i>=0; i--)
		{
		if (!BN_lshift1(dv,dv)) goto end;
		if (BN_ucmp(rem,D) >= 0)
			{
			dv->d[0]|=1;
			if (!BN_usub(rem,rem,D)) goto end;
			}

		if (!BN_rshift1(D,D)) goto end;
		}
	rem->neg=BN_is_zero(rem)?0:m->neg;
	dv->neg=m->neg^d->neg;
	ret = 1;
 end:
	BN_CTX_end(ctx);
	return(ret);
	}






   









   














static int BN_div_no_branch(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor, BN_CTX *ctx);
int BN_div(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num, const BIGNUM *divisor, BN_CTX *ctx)
	{
	int norm_shift,i,loop;
	BIGNUM *tmp,wnum,*snum,*sdiv,*res;
	BN_ULONG *resp,*wnump;
	BN_ULONG d0,d1;
	int num_n,div_n;

	
	if (num->top > 0 && num->d[num->top - 1] == 0)
		{
		BNerr(BN_F_BN_DIV,BN_R_NOT_INITIALIZED);
		return 0;
		}

	bn_check_top(num);

	if ((BN_get_flags(num, BN_FLG_CONSTTIME) != 0) || (BN_get_flags(divisor, BN_FLG_CONSTTIME) != 0))
		{
		return BN_div_no_branch(dv, rm, num, divisor, ctx);
		}

	bn_check_top(dv);
	bn_check_top(rm);
	 
	bn_check_top(divisor);

	if (BN_is_zero(divisor))
		{
		BNerr(BN_F_BN_DIV,BN_R_DIV_BY_ZERO);
		return(0);
		}

	if (BN_ucmp(num,divisor) < 0)
		{
		if (rm != NULL)
			{ if (BN_copy(rm,num) == NULL) return(0); }
		if (dv != NULL) BN_zero(dv);
		return(1);
		}

	BN_CTX_start(ctx);
	tmp=BN_CTX_get(ctx);
	snum=BN_CTX_get(ctx);
	sdiv=BN_CTX_get(ctx);
	if (dv == NULL)
		res=BN_CTX_get(ctx);
	else	res=dv;
	if (sdiv == NULL || res == NULL || tmp == NULL || snum == NULL)
		goto err;

	
	norm_shift=BN_BITS2-((BN_num_bits(divisor))%BN_BITS2);
	if (!(BN_lshift(sdiv,divisor,norm_shift))) goto err;
	sdiv->neg=0;
	norm_shift+=BN_BITS2;
	if (!(BN_lshift(snum,num,norm_shift))) goto err;
	snum->neg=0;
	div_n=sdiv->top;
	num_n=snum->top;
	loop=num_n-div_n;
	
	wnum.neg   = 0;
	wnum.d     = &(snum->d[loop]);
	wnum.top   = div_n;
	
	wnum.dmax  = snum->dmax - loop; 

	
	
	d0=sdiv->d[div_n-1];
	d1=(div_n == 1)?0:sdiv->d[div_n-2];

	
	wnump= &(snum->d[num_n-1]);

	
	res->neg= (num->neg^divisor->neg);
	if (!bn_wexpand(res,(loop+1))) goto err;
	res->top=loop;
	resp= &(res->d[loop-1]);

	
	if (!bn_wexpand(tmp,(div_n+1))) goto err;

	if (BN_ucmp(&wnum,sdiv) >= 0)
		{
		
		bn_clear_top2max(&wnum);
		bn_sub_words(wnum.d, wnum.d, sdiv->d, div_n);
		*resp=1;
		}
	else res->top--;
	
	if (res->top == 0)
		res->neg = 0;
	else resp--;

	for (i=0; i<loop-1; i++, wnump--, resp--)
		{
		BN_ULONG q,l0;
		

		BN_ULONG bn_div_3_words(BN_ULONG*,BN_ULONG,BN_ULONG);
		q=bn_div_3_words(wnump,d1,d0);

		BN_ULONG n0,n1,rem=0;

		n0=wnump[0];
		n1=wnump[-1];
		if (n0 == d0)
			q=BN_MASK2;
		else 			 {

			BN_ULLONG t2;


			q=(BN_ULONG)(((((BN_ULLONG)n0)<<BN_BITS2)|n1)/d0);

			q=bn_div_words(n0,n1,d0);

			fprintf(stderr,"DEBUG: bn_div_words(0x%08X,0x%08X,0x%08 X) -> 0x%08X\n" n0, n1, d0, q);




			
			rem=(n1-q*d0)&BN_MASK2;

			t2=(BN_ULLONG)d1*q;

			for (;;)
				{
				if (t2 <= ((((BN_ULLONG)rem)<<BN_BITS2)|wnump[-2]))
					break;
				q--;
				rem += d0;
				if (rem < d0) break; 
				t2 -= d1;
				}

			BN_ULONG t2l,t2h;

			q=bn_div_words(n0,n1,d0);

			fprintf(stderr,"DEBUG: bn_div_words(0x%08X,0x%08X,0x%08 X) -> 0x%08X\n" n0, n1, d0, q);


			rem=(n1-q*d0)&BN_MASK2;



			BN_UMULT_LOHI(t2l,t2h,d1,q);

			t2l = d1 * q;
			t2h = BN_UMULT_HIGH(d1,q);

			{
			BN_ULONG ql, qh;
			t2l=LBITS(d1); t2h=HBITS(d1);
			ql =LBITS(q);  qh =HBITS(q);
			mul64(t2l,t2h,ql,qh); 
			}


			for (;;)
				{
				if ((t2h < rem) || ((t2h == rem) && (t2l <= wnump[-2])))
					break;
				q--;
				rem += d0;
				if (rem < d0) break; 
				if (t2l < d1) t2h--; t2l -= d1;
				}

			}


		l0=bn_mul_words(tmp->d,sdiv->d,div_n,q);
		tmp->d[div_n]=l0;
		wnum.d--;
		
		if (bn_sub_words(wnum.d, wnum.d, tmp->d, div_n+1))
			{
			
			q--;
			if (bn_add_words(wnum.d, wnum.d, sdiv->d, div_n))
				
				(*wnump)++;
			}
		
		*resp = q;
		}
	bn_correct_top(snum);
	if (rm != NULL)
		{
		
		int neg = num->neg;
		BN_rshift(rm,snum,norm_shift);
		if (!BN_is_zero(rm))
			rm->neg = neg;
		bn_check_top(rm);
		}
	BN_CTX_end(ctx);
	return(1);
err:
	bn_check_top(rm);
	BN_CTX_end(ctx);
	return(0);
	}



static int BN_div_no_branch(BIGNUM *dv, BIGNUM *rm, const BIGNUM *num,  const BIGNUM *divisor, BN_CTX *ctx)
	{
	int norm_shift,i,loop;
	BIGNUM *tmp,wnum,*snum,*sdiv,*res;
	BN_ULONG *resp,*wnump;
	BN_ULONG d0,d1;
	int num_n,div_n;

	bn_check_top(dv);
	bn_check_top(rm);
	 
	bn_check_top(divisor);

	if (BN_is_zero(divisor))
		{
		BNerr(BN_F_BN_DIV_NO_BRANCH,BN_R_DIV_BY_ZERO);
		return(0);
		}

	BN_CTX_start(ctx);
	tmp=BN_CTX_get(ctx);
	snum=BN_CTX_get(ctx);
	sdiv=BN_CTX_get(ctx);
	if (dv == NULL)
		res=BN_CTX_get(ctx);
	else	res=dv;
	if (sdiv == NULL || res == NULL) goto err;

	
	norm_shift=BN_BITS2-((BN_num_bits(divisor))%BN_BITS2);
	if (!(BN_lshift(sdiv,divisor,norm_shift))) goto err;
	sdiv->neg=0;
	norm_shift+=BN_BITS2;
	if (!(BN_lshift(snum,num,norm_shift))) goto err;
	snum->neg=0;

	
	if (snum->top <= sdiv->top+1) 
		{
		if (bn_wexpand(snum, sdiv->top + 2) == NULL) goto err;
		for (i = snum->top; i < sdiv->top + 2; i++) snum->d[i] = 0;
		snum->top = sdiv->top + 2;
		}
	else {
		if (bn_wexpand(snum, snum->top + 1) == NULL) goto err;
		snum->d[snum->top] = 0;
		snum->top ++;
		}

	div_n=sdiv->top;
	num_n=snum->top;
	loop=num_n-div_n;
	
	wnum.neg   = 0;
	wnum.d     = &(snum->d[loop]);
	wnum.top   = div_n;
	
	wnum.dmax  = snum->dmax - loop; 

	
	
	d0=sdiv->d[div_n-1];
	d1=(div_n == 1)?0:sdiv->d[div_n-2];

	
	wnump= &(snum->d[num_n-1]);

	
	res->neg= (num->neg^divisor->neg);
	if (!bn_wexpand(res,(loop+1))) goto err;
	res->top=loop-1;
	resp= &(res->d[loop-1]);

	
	if (!bn_wexpand(tmp,(div_n+1))) goto err;

	
	if (res->top == 0)
		res->neg = 0;
	else resp--;

	for (i=0; i<loop-1; i++, wnump--, resp--)
		{
		BN_ULONG q,l0;
		

		BN_ULONG bn_div_3_words(BN_ULONG*,BN_ULONG,BN_ULONG);
		q=bn_div_3_words(wnump,d1,d0);

		BN_ULONG n0,n1,rem=0;

		n0=wnump[0];
		n1=wnump[-1];
		if (n0 == d0)
			q=BN_MASK2;
		else 			 {

			BN_ULLONG t2;


			q=(BN_ULONG)(((((BN_ULLONG)n0)<<BN_BITS2)|n1)/d0);

			q=bn_div_words(n0,n1,d0);

			fprintf(stderr,"DEBUG: bn_div_words(0x%08X,0x%08X,0x%08 X) -> 0x%08X\n" n0, n1, d0, q);




			
			rem=(n1-q*d0)&BN_MASK2;

			t2=(BN_ULLONG)d1*q;

			for (;;)
				{
				if (t2 <= ((((BN_ULLONG)rem)<<BN_BITS2)|wnump[-2]))
					break;
				q--;
				rem += d0;
				if (rem < d0) break; 
				t2 -= d1;
				}

			BN_ULONG t2l,t2h;

			q=bn_div_words(n0,n1,d0);

			fprintf(stderr,"DEBUG: bn_div_words(0x%08X,0x%08X,0x%08 X) -> 0x%08X\n" n0, n1, d0, q);


			rem=(n1-q*d0)&BN_MASK2;



			BN_UMULT_LOHI(t2l,t2h,d1,q);

			t2l = d1 * q;
			t2h = BN_UMULT_HIGH(d1,q);

			{
			BN_ULONG ql, qh;
			t2l=LBITS(d1); t2h=HBITS(d1);
			ql =LBITS(q);  qh =HBITS(q);
			mul64(t2l,t2h,ql,qh); 
			}


			for (;;)
				{
				if ((t2h < rem) || ((t2h == rem) && (t2l <= wnump[-2])))
					break;
				q--;
				rem += d0;
				if (rem < d0) break; 
				if (t2l < d1) t2h--; t2l -= d1;
				}

			}


		l0=bn_mul_words(tmp->d,sdiv->d,div_n,q);
		tmp->d[div_n]=l0;
		wnum.d--;
		
		if (bn_sub_words(wnum.d, wnum.d, tmp->d, div_n+1))
			{
			
			q--;
			if (bn_add_words(wnum.d, wnum.d, sdiv->d, div_n))
				
				(*wnump)++;
			}
		
		*resp = q;
		}
	bn_correct_top(snum);
	if (rm != NULL)
		{
		
		int neg = num->neg;
		BN_rshift(rm,snum,norm_shift);
		if (!BN_is_zero(rm))
			rm->neg = neg;
		bn_check_top(rm);
		}
	bn_correct_top(res);
	BN_CTX_end(ctx);
	return(1);
err:
	bn_check_top(rm);
	BN_CTX_end(ctx);
	return(0);
	}


