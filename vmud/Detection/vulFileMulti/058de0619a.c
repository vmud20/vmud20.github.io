

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	        static void H_Init(HMAC_CTX *ctx)







{
	uint8_t allzero[SHA256_DIGEST_LENGTH];

	memset(allzero, 0, SHA256_DIGEST_LENGTH);
	HMAC_Init(ctx, allzero, SHA256_DIGEST_LENGTH, EVP_sha256());
}

static void H_Update(HMAC_CTX *ctx, uint8_t const *data, int len)
{
	HMAC_Update(ctx, data, len);
}

static void H_Final(HMAC_CTX *ctx, uint8_t *digest)
{
	unsigned int mdlen = SHA256_DIGEST_LENGTH;

	HMAC_Final(ctx, digest, &mdlen);
	HMAC_CTX_cleanup(ctx);
}


static void eap_pwd_kdf(uint8_t *key, int keylen, char const *label, int labellen, uint8_t *result, int resultbitlen)
{
	HMAC_CTX hctx;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	uint16_t i, ctr, L;
	int resultbytelen, len = 0;
	unsigned int mdlen = SHA256_DIGEST_LENGTH;
	uint8_t mask = 0xff;

	resultbytelen = (resultbitlen + 7)/8;
	ctr = 0;
	L = htons(resultbitlen);
	while (len < resultbytelen) {
		ctr++; i = htons(ctr);
		HMAC_Init(&hctx, key, keylen, EVP_sha256());
		if (ctr > 1) {
			HMAC_Update(&hctx, digest, mdlen);
		}
		HMAC_Update(&hctx, (uint8_t *) &i, sizeof(uint16_t));
		HMAC_Update(&hctx, (uint8_t const *)label, labellen);
		HMAC_Update(&hctx, (uint8_t *) &L, sizeof(uint16_t));
		HMAC_Final(&hctx, digest, &mdlen);
		if ((len + (int) mdlen) > resultbytelen) {
			memcpy(result + len, digest, resultbytelen - len);
		} else {
			memcpy(result + len, digest, mdlen);
		}
		len += mdlen;
		HMAC_CTX_cleanup(&hctx);
	}

	
	if (resultbitlen % 8) {
		mask <<= (8 - (resultbitlen % 8));
		result[resultbytelen - 1] &= mask;
	}
}

int compute_password_element (pwd_session_t *sess, uint16_t grp_num, char const *password, int password_len, char const *id_server, int id_server_len, char const *id_peer, int id_peer_len, uint32_t *token)



{
	BIGNUM *x_candidate = NULL, *rnd = NULL, *cofactor = NULL;
	HMAC_CTX ctx;
	uint8_t pwe_digest[SHA256_DIGEST_LENGTH], *prfbuf = NULL, ctr;
	int nid, is_odd, primebitlen, primebytelen, ret = 0;

	switch (grp_num) { 
	case 19:
		nid = NID_X9_62_prime256v1;
		break;

	case 20:
		nid = NID_secp384r1;
		break;

	case 21:
		nid = NID_secp521r1;
		break;

	case 25:
		nid = NID_X9_62_prime192v1;
		break;

	case 26:
		nid = NID_secp224r1;
		break;

	default:
		DEBUG("unknown group %d", grp_num);
		goto fail;
	}

	sess->pwe = NULL;
	sess->order = NULL;
	sess->prime = NULL;

	if ((sess->group = EC_GROUP_new_by_curve_name(nid)) == NULL) {
		DEBUG("unable to create EC_GROUP");
		goto fail;
	}

	if (((rnd = BN_new()) == NULL) || ((cofactor = BN_new()) == NULL) || ((sess->pwe = EC_POINT_new(sess->group)) == NULL) || ((sess->order = BN_new()) == NULL) || ((sess->prime = BN_new()) == NULL) || ((x_candidate = BN_new()) == NULL)) {




		DEBUG("unable to create bignums");
		goto fail;
	}

	if (!EC_GROUP_get_curve_GFp(sess->group, sess->prime, NULL, NULL, NULL)) {
		DEBUG("unable to get prime for GFp curve");
		goto fail;
	}

	if (!EC_GROUP_get_order(sess->group, sess->order, NULL)) {
		DEBUG("unable to get order for curve");
		goto fail;
	}

	if (!EC_GROUP_get_cofactor(sess->group, cofactor, NULL)) {
		DEBUG("unable to get cofactor for curve");
		goto fail;
	}

	primebitlen = BN_num_bits(sess->prime);
	primebytelen = BN_num_bytes(sess->prime);
	if ((prfbuf = talloc_zero_array(sess, uint8_t, primebytelen)) == NULL) {
		DEBUG("unable to alloc space for prf buffer");
		goto fail;
	}
	ctr = 0;
	while (1) {
		if (ctr > 10) {
			DEBUG("unable to find random point on curve for group %d, something's fishy", grp_num);
			goto fail;
		}
		ctr++;

		
		H_Init(&ctx);
		H_Update(&ctx, (uint8_t *)token, sizeof(*token));
		H_Update(&ctx, (uint8_t const *)id_peer, id_peer_len);
		H_Update(&ctx, (uint8_t const *)id_server, id_server_len);
		H_Update(&ctx, (uint8_t const *)password, password_len);
		H_Update(&ctx, (uint8_t *)&ctr, sizeof(ctr));
		H_Final(&ctx, pwe_digest);

		BN_bin2bn(pwe_digest, SHA256_DIGEST_LENGTH, rnd);
		eap_pwd_kdf(pwe_digest, SHA256_DIGEST_LENGTH, "EAP-pwd Hunting And Pecking", strlen("EAP-pwd Hunting And Pecking"), prfbuf, primebitlen);

		BN_bin2bn(prfbuf, primebytelen, x_candidate);
		
		if (primebitlen % 8) BN_rshift(x_candidate, x_candidate, (8 - (primebitlen % 8)));
		if (BN_ucmp(x_candidate, sess->prime) >= 0) continue;

		
		is_odd = BN_is_odd(rnd) ? 1 : 0;

		
		if (!EC_POINT_set_compressed_coordinates_GFp(sess->group, sess->pwe, x_candidate, is_odd, NULL)) {
			continue;
		}

		
		if (!EC_POINT_is_on_curve(sess->group, sess->pwe, NULL)) {
			DEBUG("EAP-pwd: point is not on curve");
			continue;
		}

		if (BN_cmp(cofactor, BN_value_one())) {
			
			if (!EC_POINT_mul(sess->group, sess->pwe, NULL, sess->pwe, cofactor, NULL)) {
				DEBUG("EAP-pwd: cannot multiply generator by order");
				continue;
			}

			if (EC_POINT_is_at_infinity(sess->group, sess->pwe)) {
				DEBUG("EAP-pwd: point is at infinity");
				continue;
			}
		}
		
		break;
	}

	sess->group_num = grp_num;
	if (0) {
		fail:		
		ret = -1;
	}

	
	BN_free(cofactor);
	BN_free(x_candidate);
	BN_free(rnd);
	talloc_free(prfbuf);

	return ret;
}

int compute_scalar_element (pwd_session_t *sess, BN_CTX *bnctx) {
	BIGNUM *mask = NULL;
	int ret = -1;

	if (((sess->private_value = BN_new()) == NULL) || ((sess->my_element = EC_POINT_new(sess->group)) == NULL) || ((sess->my_scalar = BN_new()) == NULL) || ((mask = BN_new()) == NULL)) {


		DEBUG2("server scalar allocation failed");
		goto fail;
	}

	BN_rand_range(sess->private_value, sess->order);
	BN_rand_range(mask, sess->order);
	BN_add(sess->my_scalar, sess->private_value, mask);
	BN_mod(sess->my_scalar, sess->my_scalar, sess->order, bnctx);

	if (!EC_POINT_mul(sess->group, sess->my_element, NULL, sess->pwe, mask, bnctx)) {
		DEBUG2("server element allocation failed");
		goto fail;
	}

	if (!EC_POINT_invert(sess->group, sess->my_element, bnctx)) {
		DEBUG2("server element inversion failed");
		goto fail;
	}

	ret = 0;

fail:
	BN_free(mask);

	return ret;
}

int process_peer_commit (pwd_session_t *sess, uint8_t *commit, BN_CTX *bnctx)
{
	uint8_t *ptr;
	BIGNUM *x = NULL, *y = NULL, *cofactor = NULL;
	EC_POINT *K = NULL, *point = NULL;
	int res = 1;

	if (((sess->peer_scalar = BN_new()) == NULL) || ((sess->k = BN_new()) == NULL) || ((cofactor = BN_new()) == NULL) || ((x = BN_new()) == NULL) || ((y = BN_new()) == NULL) || ((point = EC_POINT_new(sess->group)) == NULL) || ((K = EC_POINT_new(sess->group)) == NULL) || ((sess->peer_element = EC_POINT_new(sess->group)) == NULL)) {






		DEBUG2("pwd: failed to allocate room to process peer's commit");
		goto finish;
	}

	if (!EC_GROUP_get_cofactor(sess->group, cofactor, NULL)) {
		DEBUG2("pwd: unable to get group co-factor");
		goto finish;
	}

	
	ptr = (uint8_t *)commit;
	BN_bin2bn(ptr, BN_num_bytes(sess->prime), x);
	ptr += BN_num_bytes(sess->prime);
	BN_bin2bn(ptr, BN_num_bytes(sess->prime), y);
	ptr += BN_num_bytes(sess->prime);
	BN_bin2bn(ptr, BN_num_bytes(sess->order), sess->peer_scalar);

	if (!EC_POINT_set_affine_coordinates_GFp(sess->group, sess->peer_element, x, y, bnctx)) {
		DEBUG2("pwd: unable to get coordinates of peer's element");
		goto finish;
	}

	
	if (BN_cmp(cofactor, BN_value_one())) {
		if (!EC_POINT_mul(sess->group, point, NULL, sess->peer_element, cofactor, NULL)) {
			DEBUG2("pwd: unable to multiply element by co-factor");
			goto finish;
		}

		if (EC_POINT_is_at_infinity(sess->group, point)) {
			DEBUG2("pwd: peer's element is in small sub-group");
			goto finish;
		}
	}

	
	if ((!EC_POINT_mul(sess->group, K, NULL, sess->pwe, sess->peer_scalar, bnctx)) || (!EC_POINT_add(sess->group, K, K, sess->peer_element, bnctx)) || (!EC_POINT_mul(sess->group, K, NULL, K, sess->private_value, bnctx))) {

		DEBUG2("pwd: unable to compute shared key, k");
		goto finish;
	}

	
	if (BN_cmp(cofactor, BN_value_one())) {
		if (!EC_POINT_mul(sess->group, K, NULL, K, cofactor, NULL)) {
			DEBUG2("pwd: unable to multiply k by co-factor");
			goto finish;
		}
	}

	
	if (EC_POINT_is_at_infinity(sess->group, K)) {
		DEBUG2("pwd: k is point-at-infinity!");
		goto finish;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(sess->group, K, sess->k, NULL, bnctx)) {
		DEBUG2("pwd: unable to get shared secret from K");
		goto finish;
	}
	res = 0;

finish:
	EC_POINT_free(K);
	EC_POINT_free(point);
	BN_free(cofactor);
	BN_free(x);
	BN_free(y);

	return res;
}

int compute_server_confirm (pwd_session_t *sess, uint8_t *buf, BN_CTX *bnctx)
{
	BIGNUM *x = NULL, *y = NULL;
	HMAC_CTX ctx;
	uint8_t *cruft = NULL;
	int offset, req = -1;

	
	if (((cruft = talloc_zero_array(sess, uint8_t, BN_num_bytes(sess->prime))) == NULL) || ((x = BN_new()) == NULL) || ((y = BN_new()) == NULL)) {
		DEBUG2("pwd: unable to allocate space to compute confirm!");
		goto finish;
	}

	
	H_Init(&ctx);

	
	offset = BN_num_bytes(sess->prime) - BN_num_bytes(sess->k);
	BN_bn2bin(sess->k, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->prime));

	
	if (!EC_POINT_get_affine_coordinates_GFp(sess->group, sess->my_element, x, y, bnctx)) {
		DEBUG2("pwd: unable to get coordinates of server element");
		goto finish;
	}
	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->prime) - BN_num_bytes(x);
	BN_bn2bin(x, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->prime));

	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->prime) - BN_num_bytes(y);
	BN_bn2bin(y, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->prime));

	
	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->order) - BN_num_bytes(sess->my_scalar);
	BN_bn2bin(sess->my_scalar, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->order));

	
	if (!EC_POINT_get_affine_coordinates_GFp(sess->group, sess->peer_element, x, y, bnctx)) {
		DEBUG2("pwd: unable to get coordinates of peer's element");
		goto finish;
	}

	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->prime) - BN_num_bytes(x);
	BN_bn2bin(x, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->prime));

	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->prime) - BN_num_bytes(y);
	BN_bn2bin(y, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->prime));

	
	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->order) - BN_num_bytes(sess->peer_scalar);
	BN_bn2bin(sess->peer_scalar, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->order));

	
	H_Update(&ctx, (uint8_t *)&sess->ciphersuite, sizeof(sess->ciphersuite));

	H_Final(&ctx, buf);

	req = 0;
finish:
	talloc_free(cruft);
	BN_free(x);
	BN_free(y);

	return req;
}

int compute_peer_confirm (pwd_session_t *sess, uint8_t *buf, BN_CTX *bnctx)
{
	BIGNUM *x = NULL, *y = NULL;
	HMAC_CTX ctx;
	uint8_t *cruft = NULL;
	int offset, req = -1;

	
	if (((cruft = talloc_zero_array(sess, uint8_t, BN_num_bytes(sess->prime))) == NULL) || ((x = BN_new()) == NULL) || ((y = BN_new()) == NULL)) {
		DEBUG2("pwd: unable to allocate space to compute confirm!");
		goto finish;
	}

	
	H_Init(&ctx);

	
	offset = BN_num_bytes(sess->prime) - BN_num_bytes(sess->k);
	BN_bn2bin(sess->k, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->prime));

	
	if (!EC_POINT_get_affine_coordinates_GFp(sess->group, sess->peer_element, x, y, bnctx)) {
		DEBUG2("pwd: unable to get coordinates of peer's element");
		goto finish;
	}

	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->prime) - BN_num_bytes(x);
	BN_bn2bin(x, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->prime));

	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->prime) - BN_num_bytes(y);
	BN_bn2bin(y, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->prime));

	
	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->order) - BN_num_bytes(sess->peer_scalar);
	BN_bn2bin(sess->peer_scalar, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->order));

	
	if (!EC_POINT_get_affine_coordinates_GFp(sess->group, sess->my_element, x, y, bnctx)) {
		DEBUG2("pwd: unable to get coordinates of server element");
		goto finish;
	}
	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->prime) - BN_num_bytes(x);
	BN_bn2bin(x, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->prime));

	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->prime) - BN_num_bytes(y);
	BN_bn2bin(y, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->prime));

	
	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->order) - BN_num_bytes(sess->my_scalar);
	BN_bn2bin(sess->my_scalar, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->order));

	
	H_Update(&ctx, (uint8_t *)&sess->ciphersuite, sizeof(sess->ciphersuite));

	H_Final(&ctx, buf);

	req = 0;
finish:
	talloc_free(cruft);
	BN_free(x);
	BN_free(y);

	return req;
}

int compute_keys (pwd_session_t *sess, uint8_t *peer_confirm, uint8_t *msk, uint8_t *emsk)
{
	HMAC_CTX ctx;
	uint8_t mk[SHA256_DIGEST_LENGTH], *cruft;
	uint8_t session_id[SHA256_DIGEST_LENGTH + 1];
	uint8_t msk_emsk[128];		
	int offset;

	if ((cruft = talloc_array(sess, uint8_t, BN_num_bytes(sess->prime))) == NULL) {
		DEBUG2("pwd: unable to allocate space to compute keys");
		return -1;
	}

	
	session_id[0] = PW_EAP_PWD;
	H_Init(&ctx);
	H_Update(&ctx, (uint8_t *)&sess->ciphersuite, sizeof(sess->ciphersuite));
	offset = BN_num_bytes(sess->order) - BN_num_bytes(sess->peer_scalar);
	memset(cruft, 0, BN_num_bytes(sess->prime));
	BN_bn2bin(sess->peer_scalar, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->order));
	offset = BN_num_bytes(sess->order) - BN_num_bytes(sess->my_scalar);
	memset(cruft, 0, BN_num_bytes(sess->prime));
	BN_bn2bin(sess->my_scalar, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->order));
	H_Final(&ctx, (uint8_t *)&session_id[1]);

	
	H_Init(&ctx);

	memset(cruft, 0, BN_num_bytes(sess->prime));
	offset = BN_num_bytes(sess->prime) - BN_num_bytes(sess->k);
	BN_bn2bin(sess->k, cruft + offset);
	H_Update(&ctx, cruft, BN_num_bytes(sess->prime));

	H_Update(&ctx, peer_confirm, SHA256_DIGEST_LENGTH);

	H_Update(&ctx, sess->my_confirm, SHA256_DIGEST_LENGTH);

	H_Final(&ctx, mk);

	
	eap_pwd_kdf(mk, SHA256_DIGEST_LENGTH, (char const *)session_id, SHA256_DIGEST_LENGTH + 1, msk_emsk, 1024);

	memcpy(msk, msk_emsk, 64);
	memcpy(emsk, msk_emsk + 64, 64);

	talloc_free(cruft);
	return 0;
}




