







static int ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs, STACK_OF(X509) *certs, X509_STORE *st, unsigned long flags);
static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id);
static int ocsp_check_issuer(OCSP_BASICRESP *bs, STACK_OF(X509) *chain, unsigned long flags);
static int ocsp_check_ids(STACK_OF(OCSP_SINGLERESP) *sresp, OCSP_CERTID **ret);
static int ocsp_match_issuerid(X509 *cert, OCSP_CERTID *cid, STACK_OF(OCSP_SINGLERESP) *sresp);
static int ocsp_check_delegated(X509 *x, int flags);
static int ocsp_req_find_signer(X509 **psigner, OCSP_REQUEST *req, X509_NAME *nm, STACK_OF(X509) *certs, X509_STORE *st, unsigned long flags);



int OCSP_basic_verify(OCSP_BASICRESP *bs, STACK_OF(X509) *certs, X509_STORE *st, unsigned long flags)
	{
	X509 *signer, *x;
	STACK_OF(X509) *chain = NULL;
	X509_STORE_CTX ctx;
	int i, ret = 0;
	ret = ocsp_find_signer(&signer, bs, certs, st, flags);
	if (!ret)
		{
		OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND);
		goto end;
		}
	if ((ret == 2) && (flags & OCSP_TRUSTOTHER))
		flags |= OCSP_NOVERIFY;
	if (!(flags & OCSP_NOSIGS))
		{
		EVP_PKEY *skey;
		skey = X509_get_pubkey(signer);
		ret = OCSP_BASICRESP_verify(bs, skey, 0);
		EVP_PKEY_free(skey);
		if(ret <= 0)
			{
			OCSPerr(OCSP_F_OCSP_BASIC_VERIFY, OCSP_R_SIGNATURE_FAILURE);
			goto end;
			}
		}
	if (!(flags & OCSP_NOVERIFY))
		{
		int init_res;
		if(flags & OCSP_NOCHAIN)
			init_res = X509_STORE_CTX_init(&ctx, st, signer, NULL);
		else init_res = X509_STORE_CTX_init(&ctx, st, signer, bs->certs);
		if(!init_res)
			{
			ret = -1;
			OCSPerr(OCSP_F_OCSP_BASIC_VERIFY,ERR_R_X509_LIB);
			goto end;
			}

		X509_STORE_CTX_set_purpose(&ctx, X509_PURPOSE_OCSP_HELPER);
		ret = X509_verify_cert(&ctx);
		chain = X509_STORE_CTX_get1_chain(&ctx);
		X509_STORE_CTX_cleanup(&ctx);
                if (ret <= 0)
			{
			i = X509_STORE_CTX_get_error(&ctx);	
			OCSPerr(OCSP_F_OCSP_BASIC_VERIFY,OCSP_R_CERTIFICATE_VERIFY_ERROR);
			ERR_add_error_data(2, "Verify error:", X509_verify_cert_error_string(i));
                        goto end;
                	}
		if(flags & OCSP_NOCHECKS)
			{
			ret = 1;
			goto end;
			}
		
		ret = ocsp_check_issuer(bs, chain, flags);

		
		if (ret != 0) goto end;

		
		if(flags & OCSP_NOEXPLICIT) goto end;

		x = sk_X509_value(chain, sk_X509_num(chain) - 1);
		if(X509_check_trust(x, NID_OCSP_sign, 0) != X509_TRUST_TRUSTED)
			{
			OCSPerr(OCSP_F_OCSP_BASIC_VERIFY,OCSP_R_ROOT_CA_NOT_TRUSTED);
			goto end;
			}
		ret = 1;
		}



	end:
	if(chain) sk_X509_pop_free(chain, X509_free);
	return ret;
	}


static int ocsp_find_signer(X509 **psigner, OCSP_BASICRESP *bs, STACK_OF(X509) *certs, X509_STORE *st, unsigned long flags)
	{
	X509 *signer;
	OCSP_RESPID *rid = bs->tbsResponseData->responderId;
	if ((signer = ocsp_find_signer_sk(certs, rid)))
		{
		*psigner = signer;
		return 2;
		}
	if(!(flags & OCSP_NOINTERN) && (signer = ocsp_find_signer_sk(bs->certs, rid)))
		{
		*psigner = signer;
		return 1;
		}
	

	*psigner = NULL;
	return 0;
	}


static X509 *ocsp_find_signer_sk(STACK_OF(X509) *certs, OCSP_RESPID *id)
	{
	int i;
	unsigned char tmphash[SHA_DIGEST_LENGTH], *keyhash;
	X509 *x;

	
	if (id->type == V_OCSP_RESPID_NAME)
		return X509_find_by_subject(certs, id->value.byName);

	

	
	if (id->value.byKey->length != SHA_DIGEST_LENGTH) return NULL;
	keyhash = id->value.byKey->data;
	
	for (i = 0; i < sk_X509_num(certs); i++)
		{
		x = sk_X509_value(certs, i);
		X509_pubkey_digest(x, EVP_sha1(), tmphash, NULL);
		if(!memcmp(keyhash, tmphash, SHA_DIGEST_LENGTH))
			return x;
		}
	return NULL;
	}


static int ocsp_check_issuer(OCSP_BASICRESP *bs, STACK_OF(X509) *chain, unsigned long flags)
	{
	STACK_OF(OCSP_SINGLERESP) *sresp;
	X509 *signer, *sca;
	OCSP_CERTID *caid = NULL;
	int i;
	sresp = bs->tbsResponseData->responses;

	if (sk_X509_num(chain) <= 0)
		{
		OCSPerr(OCSP_F_OCSP_CHECK_ISSUER, OCSP_R_NO_CERTIFICATES_IN_CHAIN);
		return -1;
		}

	
	i = ocsp_check_ids(sresp, &caid);

	
	if (i <= 0) return i;

	signer = sk_X509_value(chain, 0);
	
	if (sk_X509_num(chain) > 1)
		{
		sca = sk_X509_value(chain, 1);
		i = ocsp_match_issuerid(sca, caid, sresp);
		if (i < 0) return i;
		if (i)
			{
			
			if (ocsp_check_delegated(signer, flags)) return 1;
			return 0;
			}
		}

	
	return ocsp_match_issuerid(signer, caid, sresp);
	}



	
static int ocsp_check_ids(STACK_OF(OCSP_SINGLERESP) *sresp, OCSP_CERTID **ret)
	{
	OCSP_CERTID *tmpid, *cid;
	int i, idcount;

	idcount = sk_OCSP_SINGLERESP_num(sresp);
	if (idcount <= 0)
		{
		OCSPerr(OCSP_F_OCSP_CHECK_IDS, OCSP_R_RESPONSE_CONTAINS_NO_REVOCATION_DATA);
		return -1;
		}

	cid = sk_OCSP_SINGLERESP_value(sresp, 0)->certId;

	*ret = NULL;

	for (i = 1; i < idcount; i++)
		{
		tmpid = sk_OCSP_SINGLERESP_value(sresp, i)->certId;
		
		if (OCSP_id_issuer_cmp(cid, tmpid))
			{
			
			if (OBJ_cmp(tmpid->hashAlgorithm->algorithm, cid->hashAlgorithm->algorithm))
					return 2;
			
			return 0;
			}
		}

	
	*ret = cid;
	return 1;
	}


static int ocsp_match_issuerid(X509 *cert, OCSP_CERTID *cid, STACK_OF(OCSP_SINGLERESP) *sresp)
	{
	
	if(cid)
		{
		const EVP_MD *dgst;
		X509_NAME *iname;
		int mdlen;
		unsigned char md[EVP_MAX_MD_SIZE];
		if (!(dgst = EVP_get_digestbyobj(cid->hashAlgorithm->algorithm)))
			{
			OCSPerr(OCSP_F_OCSP_MATCH_ISSUERID, OCSP_R_UNKNOWN_MESSAGE_DIGEST);
			return -1;
			}

		mdlen = EVP_MD_size(dgst);
		if (mdlen < 0)
		    return -1;
		if ((cid->issuerNameHash->length != mdlen) || (cid->issuerKeyHash->length != mdlen))
			return 0;
		iname = X509_get_subject_name(cert);
		if (!X509_NAME_digest(iname, dgst, md, NULL))
			return -1;
		if (memcmp(md, cid->issuerNameHash->data, mdlen))
			return 0;
		X509_pubkey_digest(cert, dgst, md, NULL);
		if (memcmp(md, cid->issuerKeyHash->data, mdlen))
			return 0;

		return 1;

		}
	else {
		
		int i, ret;
		OCSP_CERTID *tmpid;
		for (i = 0; i < sk_OCSP_SINGLERESP_num(sresp); i++)
			{
			tmpid = sk_OCSP_SINGLERESP_value(sresp, i)->certId;
			ret = ocsp_match_issuerid(cert, tmpid, NULL);
			if (ret <= 0) return ret;
			}
		return 1;
		}
			
	}

static int ocsp_check_delegated(X509 *x, int flags)
	{
	X509_check_purpose(x, -1, 0);
	if ((x->ex_flags & EXFLAG_XKUSAGE) && (x->ex_xkusage & XKU_OCSP_SIGN))
		return 1;
	OCSPerr(OCSP_F_OCSP_CHECK_DELEGATED, OCSP_R_MISSING_OCSPSIGNING_USAGE);
	return 0;
	}



int OCSP_request_verify(OCSP_REQUEST *req, STACK_OF(X509) *certs, X509_STORE *store, unsigned long flags)
        {
	X509 *signer;
	X509_NAME *nm;
	GENERAL_NAME *gen;
	int ret;
	X509_STORE_CTX ctx;
	if (!req->optionalSignature) 
		{
		OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, OCSP_R_REQUEST_NOT_SIGNED);
		return 0;
		}
	gen = req->tbsRequest->requestorName;
	if (!gen || gen->type != GEN_DIRNAME)
		{
		OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, OCSP_R_UNSUPPORTED_REQUESTORNAME_TYPE);
		return 0;
		}
	nm = gen->d.directoryName;
	ret = ocsp_req_find_signer(&signer, req, nm, certs, store, flags);
	if (ret <= 0)
		{
		OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, OCSP_R_SIGNER_CERTIFICATE_NOT_FOUND);
		return 0;
		}
	if ((ret == 2) && (flags & OCSP_TRUSTOTHER))
		flags |= OCSP_NOVERIFY;
	if (!(flags & OCSP_NOSIGS))
		{
		EVP_PKEY *skey;
		skey = X509_get_pubkey(signer);
		ret = OCSP_REQUEST_verify(req, skey);
		EVP_PKEY_free(skey);
		if(ret <= 0)
			{
			OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY, OCSP_R_SIGNATURE_FAILURE);
			return 0;
			}
		}
	if (!(flags & OCSP_NOVERIFY))
		{
		int init_res;
		if(flags & OCSP_NOCHAIN)
			init_res = X509_STORE_CTX_init(&ctx, store, signer, NULL);
		else init_res = X509_STORE_CTX_init(&ctx, store, signer, req->optionalSignature->certs);

		if(!init_res)
			{
			OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY,ERR_R_X509_LIB);
			return 0;
			}

		X509_STORE_CTX_set_purpose(&ctx, X509_PURPOSE_OCSP_HELPER);
		X509_STORE_CTX_set_trust(&ctx, X509_TRUST_OCSP_REQUEST);
		ret = X509_verify_cert(&ctx);
		X509_STORE_CTX_cleanup(&ctx);
                if (ret <= 0)
			{
			ret = X509_STORE_CTX_get_error(&ctx);	
			OCSPerr(OCSP_F_OCSP_REQUEST_VERIFY,OCSP_R_CERTIFICATE_VERIFY_ERROR);
			ERR_add_error_data(2, "Verify error:", X509_verify_cert_error_string(ret));
                        return 0;
                	}
		}
	return 1;
        }

static int ocsp_req_find_signer(X509 **psigner, OCSP_REQUEST *req, X509_NAME *nm, STACK_OF(X509) *certs, X509_STORE *st, unsigned long flags)
	{
	X509 *signer;
	if(!(flags & OCSP_NOINTERN))
		{
		signer = X509_find_by_subject(req->optionalSignature->certs, nm);
		*psigner = signer;
		return 1;
		}

	signer = X509_find_by_subject(certs, nm);
	if (signer)
		{
		*psigner = signer;
		return 2;
		}
	return 0;
	}
