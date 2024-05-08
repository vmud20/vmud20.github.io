
















static int rxrpc_vet_description_s(const char *);
static int rxrpc_preparse(struct key_preparsed_payload *);
static int rxrpc_preparse_s(struct key_preparsed_payload *);
static void rxrpc_free_preparse(struct key_preparsed_payload *);
static void rxrpc_free_preparse_s(struct key_preparsed_payload *);
static void rxrpc_destroy(struct key *);
static void rxrpc_destroy_s(struct key *);
static void rxrpc_describe(const struct key *, struct seq_file *);
static long rxrpc_read(const struct key *, char __user *, size_t);


struct key_type key_type_rxrpc = {
	.name		= "rxrpc", .preparse	= rxrpc_preparse, .free_preparse	= rxrpc_free_preparse, .instantiate	= generic_key_instantiate, .destroy	= rxrpc_destroy, .describe	= rxrpc_describe, .read		= rxrpc_read, };






EXPORT_SYMBOL(key_type_rxrpc);


struct key_type key_type_rxrpc_s = {
	.name		= "rxrpc_s", .vet_description = rxrpc_vet_description_s, .preparse	= rxrpc_preparse_s, .free_preparse	= rxrpc_free_preparse_s, .instantiate	= generic_key_instantiate, .destroy	= rxrpc_destroy_s, .describe	= rxrpc_describe, };








static int rxrpc_vet_description_s(const char *desc)
{
	unsigned long num;
	char *p;

	num = simple_strtoul(desc, &p, 10);
	if (*p != ':' || num > 65535)
		return -EINVAL;
	num = simple_strtoul(p + 1, &p, 10);
	if (*p || num < 1 || num > 255)
		return -EINVAL;
	return 0;
}


static int rxrpc_preparse_xdr_rxkad(struct key_preparsed_payload *prep, size_t datalen, const __be32 *xdr, unsigned int toklen)

{
	struct rxrpc_key_token *token, **pptoken;
	size_t plen;
	u32 tktlen;

	_enter(",{%x,%x,%x,%x},%u", ntohl(xdr[0]), ntohl(xdr[1]), ntohl(xdr[2]), ntohl(xdr[3]), toklen);


	if (toklen <= 8 * 4)
		return -EKEYREJECTED;
	tktlen = ntohl(xdr[7]);
	_debug("tktlen: %x", tktlen);
	if (tktlen > AFSTOKEN_RK_TIX_MAX)
		return -EKEYREJECTED;
	if (toklen < 8 * 4 + tktlen)
		return -EKEYREJECTED;

	plen = sizeof(*token) + sizeof(*token->kad) + tktlen;
	prep->quotalen = datalen + plen;

	plen -= sizeof(*token);
	token = kzalloc(sizeof(*token), GFP_KERNEL);
	if (!token)
		return -ENOMEM;

	token->kad = kzalloc(plen, GFP_KERNEL);
	if (!token->kad) {
		kfree(token);
		return -ENOMEM;
	}

	token->security_index	= RXRPC_SECURITY_RXKAD;
	token->kad->ticket_len	= tktlen;
	token->kad->vice_id	= ntohl(xdr[0]);
	token->kad->kvno	= ntohl(xdr[1]);
	token->kad->start	= ntohl(xdr[4]);
	token->kad->expiry	= ntohl(xdr[5]);
	token->kad->primary_flag = ntohl(xdr[6]);
	memcpy(&token->kad->session_key, &xdr[2], 8);
	memcpy(&token->kad->ticket, &xdr[8], tktlen);

	_debug("SCIX: %u", token->security_index);
	_debug("TLEN: %u", token->kad->ticket_len);
	_debug("EXPY: %x", token->kad->expiry);
	_debug("KVNO: %u", token->kad->kvno);
	_debug("PRIM: %u", token->kad->primary_flag);
	_debug("SKEY: %02x%02x%02x%02x%02x%02x%02x%02x", token->kad->session_key[0], token->kad->session_key[1], token->kad->session_key[2], token->kad->session_key[3], token->kad->session_key[4], token->kad->session_key[5], token->kad->session_key[6], token->kad->session_key[7]);



	if (token->kad->ticket_len >= 8)
		_debug("TCKT: %02x%02x%02x%02x%02x%02x%02x%02x", token->kad->ticket[0], token->kad->ticket[1], token->kad->ticket[2], token->kad->ticket[3], token->kad->ticket[4], token->kad->ticket[5], token->kad->ticket[6], token->kad->ticket[7]);




	
	prep->payload.data[1] = (void *)((unsigned long)prep->payload.data[1] + 1);

	
	for (pptoken = (struct rxrpc_key_token **)&prep->payload.data[0];
	     *pptoken;
	     pptoken = &(*pptoken)->next)
		continue;
	*pptoken = token;
	if (token->kad->expiry < prep->expiry)
		prep->expiry = token->kad->expiry;

	_leave(" = 0");
	return 0;
}

static void rxrpc_free_krb5_principal(struct krb5_principal *princ)
{
	int loop;

	if (princ->name_parts) {
		for (loop = princ->n_name_parts - 1; loop >= 0; loop--)
			kfree(princ->name_parts[loop]);
		kfree(princ->name_parts);
	}
	kfree(princ->realm);
}

static void rxrpc_free_krb5_tagged(struct krb5_tagged_data *td)
{
	kfree(td->data);
}


static void rxrpc_rxk5_free(struct rxk5_key *rxk5)
{
	int loop;

	rxrpc_free_krb5_principal(&rxk5->client);
	rxrpc_free_krb5_principal(&rxk5->server);
	rxrpc_free_krb5_tagged(&rxk5->session);

	if (rxk5->addresses) {
		for (loop = rxk5->n_addresses - 1; loop >= 0; loop--)
			rxrpc_free_krb5_tagged(&rxk5->addresses[loop]);
		kfree(rxk5->addresses);
	}
	if (rxk5->authdata) {
		for (loop = rxk5->n_authdata - 1; loop >= 0; loop--)
			rxrpc_free_krb5_tagged(&rxk5->authdata[loop]);
		kfree(rxk5->authdata);
	}

	kfree(rxk5->ticket);
	kfree(rxk5->ticket2);
	kfree(rxk5);
}


static int rxrpc_krb5_decode_principal(struct krb5_principal *princ, const __be32 **_xdr, unsigned int *_toklen)

{
	const __be32 *xdr = *_xdr;
	unsigned int toklen = *_toklen, n_parts, loop, tmp;

	
	if (toklen <= 12)
		return -EINVAL;

	_enter(",{%x,%x,%x},%u", ntohl(xdr[0]), ntohl(xdr[1]), ntohl(xdr[2]), toklen);

	n_parts = ntohl(*xdr++);
	toklen -= 4;
	if (n_parts <= 0 || n_parts > AFSTOKEN_K5_COMPONENTS_MAX)
		return -EINVAL;
	princ->n_name_parts = n_parts;

	if (toklen <= (n_parts + 1) * 4)
		return -EINVAL;

	princ->name_parts = kcalloc(n_parts, sizeof(char *), GFP_KERNEL);
	if (!princ->name_parts)
		return -ENOMEM;

	for (loop = 0; loop < n_parts; loop++) {
		if (toklen < 4)
			return -EINVAL;
		tmp = ntohl(*xdr++);
		toklen -= 4;
		if (tmp <= 0 || tmp > AFSTOKEN_STRING_MAX)
			return -EINVAL;
		if (tmp > toklen)
			return -EINVAL;
		princ->name_parts[loop] = kmalloc(tmp + 1, GFP_KERNEL);
		if (!princ->name_parts[loop])
			return -ENOMEM;
		memcpy(princ->name_parts[loop], xdr, tmp);
		princ->name_parts[loop][tmp] = 0;
		tmp = (tmp + 3) & ~3;
		toklen -= tmp;
		xdr += tmp >> 2;
	}

	if (toklen < 4)
		return -EINVAL;
	tmp = ntohl(*xdr++);
	toklen -= 4;
	if (tmp <= 0 || tmp > AFSTOKEN_K5_REALM_MAX)
		return -EINVAL;
	if (tmp > toklen)
		return -EINVAL;
	princ->realm = kmalloc(tmp + 1, GFP_KERNEL);
	if (!princ->realm)
		return -ENOMEM;
	memcpy(princ->realm, xdr, tmp);
	princ->realm[tmp] = 0;
	tmp = (tmp + 3) & ~3;
	toklen -= tmp;
	xdr += tmp >> 2;

	_debug("%s/...@%s", princ->name_parts[0], princ->realm);

	*_xdr = xdr;
	*_toklen = toklen;
	_leave(" = 0 [toklen=%u]", toklen);
	return 0;
}


static int rxrpc_krb5_decode_tagged_data(struct krb5_tagged_data *td, size_t max_data_size, const __be32 **_xdr, unsigned int *_toklen)


{
	const __be32 *xdr = *_xdr;
	unsigned int toklen = *_toklen, len;

	
	if (toklen <= 8)
		return -EINVAL;

	_enter(",%zu,{%x,%x},%u", max_data_size, ntohl(xdr[0]), ntohl(xdr[1]), toklen);

	td->tag = ntohl(*xdr++);
	len = ntohl(*xdr++);
	toklen -= 8;
	if (len > max_data_size)
		return -EINVAL;
	td->data_len = len;

	if (len > 0) {
		td->data = kmemdup(xdr, len, GFP_KERNEL);
		if (!td->data)
			return -ENOMEM;
		len = (len + 3) & ~3;
		toklen -= len;
		xdr += len >> 2;
	}

	_debug("tag %x len %x", td->tag, td->data_len);

	*_xdr = xdr;
	*_toklen = toklen;
	_leave(" = 0 [toklen=%u]", toklen);
	return 0;
}


static int rxrpc_krb5_decode_tagged_array(struct krb5_tagged_data **_td, u8 *_n_elem, u8 max_n_elem, size_t max_elem_size, const __be32 **_xdr, unsigned int *_toklen)




{
	struct krb5_tagged_data *td;
	const __be32 *xdr = *_xdr;
	unsigned int toklen = *_toklen, n_elem, loop;
	int ret;

	
	if (toklen < 4)
		return -EINVAL;

	_enter(",,%u,%zu,{%x},%u", max_n_elem, max_elem_size, ntohl(xdr[0]), toklen);

	n_elem = ntohl(*xdr++);
	toklen -= 4;
	if (n_elem > max_n_elem)
		return -EINVAL;
	*_n_elem = n_elem;
	if (n_elem > 0) {
		if (toklen <= (n_elem + 1) * 4)
			return -EINVAL;

		_debug("n_elem %d", n_elem);

		td = kcalloc(n_elem, sizeof(struct krb5_tagged_data), GFP_KERNEL);
		if (!td)
			return -ENOMEM;
		*_td = td;

		for (loop = 0; loop < n_elem; loop++) {
			ret = rxrpc_krb5_decode_tagged_data(&td[loop], max_elem_size, &xdr, &toklen);

			if (ret < 0)
				return ret;
		}
	}

	*_xdr = xdr;
	*_toklen = toklen;
	_leave(" = 0 [toklen=%u]", toklen);
	return 0;
}


static int rxrpc_krb5_decode_ticket(u8 **_ticket, u16 *_tktlen, const __be32 **_xdr, unsigned int *_toklen)
{
	const __be32 *xdr = *_xdr;
	unsigned int toklen = *_toklen, len;

	
	if (toklen <= 4)
		return -EINVAL;

	_enter(",{%x},%u", ntohl(xdr[0]), toklen);

	len = ntohl(*xdr++);
	toklen -= 4;
	if (len > AFSTOKEN_K5_TIX_MAX)
		return -EINVAL;
	*_tktlen = len;

	_debug("ticket len %u", len);

	if (len > 0) {
		*_ticket = kmemdup(xdr, len, GFP_KERNEL);
		if (!*_ticket)
			return -ENOMEM;
		len = (len + 3) & ~3;
		toklen -= len;
		xdr += len >> 2;
	}

	*_xdr = xdr;
	*_toklen = toklen;
	_leave(" = 0 [toklen=%u]", toklen);
	return 0;
}


static int rxrpc_preparse_xdr_rxk5(struct key_preparsed_payload *prep, size_t datalen, const __be32 *xdr, unsigned int toklen)

{
	struct rxrpc_key_token *token, **pptoken;
	struct rxk5_key *rxk5;
	const __be32 *end_xdr = xdr + (toklen >> 2);
	int ret;

	_enter(",{%x,%x,%x,%x},%u", ntohl(xdr[0]), ntohl(xdr[1]), ntohl(xdr[2]), ntohl(xdr[3]), toklen);


	
	prep->quotalen = datalen + toklen;

	token = kzalloc(sizeof(*token), GFP_KERNEL);
	if (!token)
		return -ENOMEM;

	rxk5 = kzalloc(sizeof(*rxk5), GFP_KERNEL);
	if (!rxk5) {
		kfree(token);
		return -ENOMEM;
	}

	token->security_index = RXRPC_SECURITY_RXK5;
	token->k5 = rxk5;

	
	ret = rxrpc_krb5_decode_principal(&rxk5->client, &xdr, &toklen);
	if (ret < 0)
		goto error;
	ret = rxrpc_krb5_decode_principal(&rxk5->server, &xdr, &toklen);
	if (ret < 0)
		goto error;

	
	ret = rxrpc_krb5_decode_tagged_data(&rxk5->session, AFSTOKEN_DATA_MAX, &xdr, &toklen);
	if (ret < 0)
		goto error;

	if (toklen < 4 * 8 + 2 * 4)
		goto inval;
	rxk5->authtime	= be64_to_cpup((const __be64 *) xdr);
	xdr += 2;
	rxk5->starttime	= be64_to_cpup((const __be64 *) xdr);
	xdr += 2;
	rxk5->endtime	= be64_to_cpup((const __be64 *) xdr);
	xdr += 2;
	rxk5->renew_till = be64_to_cpup((const __be64 *) xdr);
	xdr += 2;
	rxk5->is_skey = ntohl(*xdr++);
	rxk5->flags = ntohl(*xdr++);
	toklen -= 4 * 8 + 2 * 4;

	_debug("times: a=%llx s=%llx e=%llx rt=%llx", rxk5->authtime, rxk5->starttime, rxk5->endtime, rxk5->renew_till);

	_debug("is_skey=%x flags=%x", rxk5->is_skey, rxk5->flags);

	
	ret = rxrpc_krb5_decode_tagged_array(&rxk5->addresses, &rxk5->n_addresses, AFSTOKEN_K5_ADDRESSES_MAX, AFSTOKEN_DATA_MAX, &xdr, &toklen);



	if (ret < 0)
		goto error;

	ASSERTCMP((end_xdr - xdr) << 2, ==, toklen);

	
	ret = rxrpc_krb5_decode_ticket(&rxk5->ticket, &rxk5->ticket_len, &xdr, &toklen);
	if (ret < 0)
		goto error;
	ret = rxrpc_krb5_decode_ticket(&rxk5->ticket2, &rxk5->ticket2_len, &xdr, &toklen);
	if (ret < 0)
		goto error;

	ASSERTCMP((end_xdr - xdr) << 2, ==, toklen);

	
	ret = rxrpc_krb5_decode_tagged_array(&rxk5->authdata, &rxk5->n_authdata, AFSTOKEN_K5_AUTHDATA_MAX, AFSTOKEN_BDATALN_MAX, &xdr, &toklen);



	if (ret < 0)
		goto error;

	ASSERTCMP((end_xdr - xdr) << 2, ==, toklen);

	if (toklen != 0)
		goto inval;

	
	for (pptoken = (struct rxrpc_key_token **)&prep->payload.data[0];
	     *pptoken;
	     pptoken = &(*pptoken)->next)
		continue;
	*pptoken = token;
	if (token->kad->expiry < prep->expiry)
		prep->expiry = token->kad->expiry;

	_leave(" = 0");
	return 0;

inval:
	ret = -EINVAL;
error:
	rxrpc_rxk5_free(rxk5);
	kfree(token);
	_leave(" = %d", ret);
	return ret;
}


static int rxrpc_preparse_xdr(struct key_preparsed_payload *prep)
{
	const __be32 *xdr = prep->data, *token;
	const char *cp;
	unsigned int len, tmp, loop, ntoken, toklen, sec_ix;
	size_t datalen = prep->datalen;
	int ret;

	_enter(",{%x,%x,%x,%x},%zu", ntohl(xdr[0]), ntohl(xdr[1]), ntohl(xdr[2]), ntohl(xdr[3]), prep->datalen);


	if (datalen > AFSTOKEN_LENGTH_MAX)
		goto not_xdr;

	
	if (datalen & 3)
		goto not_xdr;

	
	if (ntohl(*xdr++) != 0)
		goto not_xdr;
	datalen -= 4;

	
	len = ntohl(*xdr++);
	if (len < 1 || len > AFSTOKEN_CELL_MAX)
		goto not_xdr;
	datalen -= 4;
	tmp = (len + 3) & ~3;
	if (tmp > datalen)
		goto not_xdr;

	cp = (const char *) xdr;
	for (loop = 0; loop < len; loop++)
		if (!isprint(cp[loop]))
			goto not_xdr;
	if (len < tmp)
		for (; loop < tmp; loop++)
			if (cp[loop])
				goto not_xdr;
	_debug("cellname: [%u/%u] '%*.*s'", len, tmp, len, len, (const char *) xdr);
	datalen -= tmp;
	xdr += tmp >> 2;

	
	if (datalen < 12)
		goto not_xdr;
	ntoken = ntohl(*xdr++);
	datalen -= 4;
	_debug("ntoken: %x", ntoken);
	if (ntoken < 1 || ntoken > AFSTOKEN_MAX)
		goto not_xdr;

	
	token = xdr;
	loop = ntoken;
	do {
		if (datalen < 8)
			goto not_xdr;
		toklen = ntohl(*xdr++);
		sec_ix = ntohl(*xdr);
		datalen -= 4;
		_debug("token: [%x/%zx] %x", toklen, datalen, sec_ix);
		if (toklen < 20 || toklen > datalen)
			goto not_xdr;
		datalen -= (toklen + 3) & ~3;
		xdr += (toklen + 3) >> 2;

	} while (--loop > 0);

	_debug("remainder: %zu", datalen);
	if (datalen != 0)
		goto not_xdr;

	
	do {
		xdr = token;
		toklen = ntohl(*xdr++);
		token = xdr + ((toklen + 3) >> 2);
		sec_ix = ntohl(*xdr++);
		toklen -= 4;

		_debug("TOKEN type=%u [%p-%p]", sec_ix, xdr, token);

		switch (sec_ix) {
		case RXRPC_SECURITY_RXKAD:
			ret = rxrpc_preparse_xdr_rxkad(prep, datalen, xdr, toklen);
			if (ret != 0)
				goto error;
			break;

		case RXRPC_SECURITY_RXK5:
			ret = rxrpc_preparse_xdr_rxk5(prep, datalen, xdr, toklen);
			if (ret != 0)
				goto error;
			break;

		default:
			ret = -EPROTONOSUPPORT;
			goto error;
		}

	} while (--ntoken > 0);

	_leave(" = 0");
	return 0;

not_xdr:
	_leave(" = -EPROTO");
	return -EPROTO;
error:
	_leave(" = %d", ret);
	return ret;
}


static int rxrpc_preparse(struct key_preparsed_payload *prep)
{
	const struct rxrpc_key_data_v1 *v1;
	struct rxrpc_key_token *token, **pp;
	size_t plen;
	u32 kver;
	int ret;

	_enter("%zu", prep->datalen);

	
	if (!prep->data && prep->datalen == 0)
		return 0;

	
	if (prep->datalen > 7 * 4) {
		ret = rxrpc_preparse_xdr(prep);
		if (ret != -EPROTO)
			return ret;
	}

	
	ret = -EINVAL;
	if (prep->datalen <= 4 || !prep->data)
		goto error;
	memcpy(&kver, prep->data, sizeof(kver));
	prep->data += sizeof(kver);
	prep->datalen -= sizeof(kver);

	_debug("KEY I/F VERSION: %u", kver);

	ret = -EKEYREJECTED;
	if (kver != 1)
		goto error;

	
	ret = -EINVAL;
	if (prep->datalen < sizeof(*v1))
		goto error;

	v1 = prep->data;
	if (prep->datalen != sizeof(*v1) + v1->ticket_length)
		goto error;

	_debug("SCIX: %u", v1->security_index);
	_debug("TLEN: %u", v1->ticket_length);
	_debug("EXPY: %x", v1->expiry);
	_debug("KVNO: %u", v1->kvno);
	_debug("SKEY: %02x%02x%02x%02x%02x%02x%02x%02x", v1->session_key[0], v1->session_key[1], v1->session_key[2], v1->session_key[3], v1->session_key[4], v1->session_key[5], v1->session_key[6], v1->session_key[7]);



	if (v1->ticket_length >= 8)
		_debug("TCKT: %02x%02x%02x%02x%02x%02x%02x%02x", v1->ticket[0], v1->ticket[1], v1->ticket[2], v1->ticket[3], v1->ticket[4], v1->ticket[5], v1->ticket[6], v1->ticket[7]);




	ret = -EPROTONOSUPPORT;
	if (v1->security_index != RXRPC_SECURITY_RXKAD)
		goto error;

	plen = sizeof(*token->kad) + v1->ticket_length;
	prep->quotalen = plen + sizeof(*token);

	ret = -ENOMEM;
	token = kzalloc(sizeof(*token), GFP_KERNEL);
	if (!token)
		goto error;
	token->kad = kzalloc(plen, GFP_KERNEL);
	if (!token->kad)
		goto error_free;

	token->security_index		= RXRPC_SECURITY_RXKAD;
	token->kad->ticket_len		= v1->ticket_length;
	token->kad->expiry		= v1->expiry;
	token->kad->kvno		= v1->kvno;
	memcpy(&token->kad->session_key, &v1->session_key, 8);
	memcpy(&token->kad->ticket, v1->ticket, v1->ticket_length);

	
	prep->payload.data[1] = (void *)((unsigned long)prep->payload.data[1] + 1);

	
	pp = (struct rxrpc_key_token **)&prep->payload.data[0];
	while (*pp)
		pp = &(*pp)->next;
	*pp = token;
	if (token->kad->expiry < prep->expiry)
		prep->expiry = token->kad->expiry;
	token = NULL;
	ret = 0;

error_free:
	kfree(token);
error:
	return ret;
}


static void rxrpc_free_token_list(struct rxrpc_key_token *token)
{
	struct rxrpc_key_token *next;

	for (; token; token = next) {
		next = token->next;
		switch (token->security_index) {
		case RXRPC_SECURITY_RXKAD:
			kfree(token->kad);
			break;
		case RXRPC_SECURITY_RXK5:
			if (token->k5)
				rxrpc_rxk5_free(token->k5);
			break;
		default:
			pr_err("Unknown token type %x on rxrpc key\n", token->security_index);
			BUG();
		}

		kfree(token);
	}
}


static void rxrpc_free_preparse(struct key_preparsed_payload *prep)
{
	rxrpc_free_token_list(prep->payload.data[0]);
}


static int rxrpc_preparse_s(struct key_preparsed_payload *prep)
{
	struct crypto_skcipher *ci;

	_enter("%zu", prep->datalen);

	if (prep->datalen != 8)
		return -EINVAL;

	memcpy(&prep->payload.data[2], prep->data, 8);

	ci = crypto_alloc_skcipher("pcbc(des)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(ci)) {
		_leave(" = %ld", PTR_ERR(ci));
		return PTR_ERR(ci);
	}

	if (crypto_skcipher_setkey(ci, prep->data, 8) < 0)
		BUG();

	prep->payload.data[0] = ci;
	_leave(" = 0");
	return 0;
}


static void rxrpc_free_preparse_s(struct key_preparsed_payload *prep)
{
	if (prep->payload.data[0])
		crypto_free_skcipher(prep->payload.data[0]);
}


static void rxrpc_destroy(struct key *key)
{
	rxrpc_free_token_list(key->payload.data[0]);
}


static void rxrpc_destroy_s(struct key *key)
{
	if (key->payload.data[0]) {
		crypto_free_skcipher(key->payload.data[0]);
		key->payload.data[0] = NULL;
	}
}


static void rxrpc_describe(const struct key *key, struct seq_file *m)
{
	seq_puts(m, key->description);
}


int rxrpc_request_key(struct rxrpc_sock *rx, char __user *optval, int optlen)
{
	struct key *key;
	char *description;

	_enter("");

	if (optlen <= 0 || optlen > PAGE_SIZE - 1)
		return -EINVAL;

	description = memdup_user_nul(optval, optlen);
	if (IS_ERR(description))
		return PTR_ERR(description);

	key = request_key(&key_type_rxrpc, description, NULL);
	if (IS_ERR(key)) {
		kfree(description);
		_leave(" = %ld", PTR_ERR(key));
		return PTR_ERR(key);
	}

	rx->key = key;
	kfree(description);
	_leave(" = 0 [key %x]", key->serial);
	return 0;
}


int rxrpc_server_keyring(struct rxrpc_sock *rx, char __user *optval, int optlen)
{
	struct key *key;
	char *description;

	_enter("");

	if (optlen <= 0 || optlen > PAGE_SIZE - 1)
		return -EINVAL;

	description = memdup_user_nul(optval, optlen);
	if (IS_ERR(description))
		return PTR_ERR(description);

	key = request_key(&key_type_keyring, description, NULL);
	if (IS_ERR(key)) {
		kfree(description);
		_leave(" = %ld", PTR_ERR(key));
		return PTR_ERR(key);
	}

	rx->securities = key;
	kfree(description);
	_leave(" = 0 [key %x]", key->serial);
	return 0;
}


int rxrpc_get_server_data_key(struct rxrpc_connection *conn, const void *session_key, time_t expiry, u32 kvno)


{
	const struct cred *cred = current_cred();
	struct key *key;
	int ret;

	struct {
		u32 kver;
		struct rxrpc_key_data_v1 v1;
	} data;

	_enter("");

	key = key_alloc(&key_type_rxrpc, "x", GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, cred, 0, KEY_ALLOC_NOT_IN_QUOTA, NULL);

	if (IS_ERR(key)) {
		_leave(" = -ENOMEM [alloc %ld]", PTR_ERR(key));
		return -ENOMEM;
	}

	_debug("key %d", key_serial(key));

	data.kver = 1;
	data.v1.security_index = RXRPC_SECURITY_RXKAD;
	data.v1.ticket_length = 0;
	data.v1.expiry = expiry;
	data.v1.kvno = 0;

	memcpy(&data.v1.session_key, session_key, sizeof(data.v1.session_key));

	ret = key_instantiate_and_link(key, &data, sizeof(data), NULL, NULL);
	if (ret < 0)
		goto error;

	conn->params.key = key;
	_leave(" = 0 [%d]", key_serial(key));
	return 0;

error:
	key_revoke(key);
	key_put(key);
	_leave(" = -ENOMEM [ins %d]", ret);
	return -ENOMEM;
}
EXPORT_SYMBOL(rxrpc_get_server_data_key);


struct key *rxrpc_get_null_key(const char *keyname)
{
	const struct cred *cred = current_cred();
	struct key *key;
	int ret;

	key = key_alloc(&key_type_rxrpc, keyname, GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, cred, KEY_POS_SEARCH, KEY_ALLOC_NOT_IN_QUOTA, NULL);

	if (IS_ERR(key))
		return key;

	ret = key_instantiate_and_link(key, NULL, 0, NULL, NULL);
	if (ret < 0) {
		key_revoke(key);
		key_put(key);
		return ERR_PTR(ret);
	}

	return key;
}
EXPORT_SYMBOL(rxrpc_get_null_key);


static long rxrpc_read(const struct key *key, char __user *buffer, size_t buflen)
{
	const struct rxrpc_key_token *token;
	const struct krb5_principal *princ;
	size_t size;
	__be32 __user *xdr, *oldxdr;
	u32 cnlen, toksize, ntoks, tok, zero;
	u16 toksizes[AFSTOKEN_MAX];
	int loop;

	_enter("");

	
	if (memcmp(key->description, "afs@", 4) != 0)
		return -EOPNOTSUPP;
	cnlen = strlen(key->description + 4);



	
	size = 2 * 4;	
	size += RND(cnlen);	
	size += 1 * 4;	

	ntoks = 0;
	for (token = key->payload.data[0]; token; token = token->next) {
		toksize = 4;	

		switch (token->security_index) {
		case RXRPC_SECURITY_RXKAD:
			toksize += 9 * 4;	
			toksize += RND(token->kad->ticket_len);
			break;

		case RXRPC_SECURITY_RXK5:
			princ = &token->k5->client;
			toksize += 4 + princ->n_name_parts * 4;
			for (loop = 0; loop < princ->n_name_parts; loop++)
				toksize += RND(strlen(princ->name_parts[loop]));
			toksize += 4 + RND(strlen(princ->realm));

			princ = &token->k5->server;
			toksize += 4 + princ->n_name_parts * 4;
			for (loop = 0; loop < princ->n_name_parts; loop++)
				toksize += RND(strlen(princ->name_parts[loop]));
			toksize += 4 + RND(strlen(princ->realm));

			toksize += 8 + RND(token->k5->session.data_len);

			toksize += 4 * 8 + 2 * 4;

			toksize += 4 + token->k5->n_addresses * 8;
			for (loop = 0; loop < token->k5->n_addresses; loop++)
				toksize += RND(token->k5->addresses[loop].data_len);

			toksize += 4 + RND(token->k5->ticket_len);
			toksize += 4 + RND(token->k5->ticket2_len);

			toksize += 4 + token->k5->n_authdata * 8;
			for (loop = 0; loop < token->k5->n_authdata; loop++)
				toksize += RND(token->k5->authdata[loop].data_len);
			break;

		default: 
			BUG();
			continue;
		}

		_debug("token[%u]: toksize=%u", ntoks, toksize);
		ASSERTCMP(toksize, <=, AFSTOKEN_LENGTH_MAX);

		toksizes[ntoks++] = toksize;
		size += toksize + 4; 
	}



	if (!buffer || buflen < size)
		return size;

	xdr = (__be32 __user *) buffer;
	zero = 0;


























	ENCODE(0);					
	ENCODE_DATA(cnlen, key->description + 4);	
	ENCODE(ntoks);

	tok = 0;
	for (token = key->payload.data[0]; token; token = token->next) {
		toksize = toksizes[tok++];
		ENCODE(toksize);
		oldxdr = xdr;
		ENCODE(token->security_index);

		switch (token->security_index) {
		case RXRPC_SECURITY_RXKAD:
			ENCODE(token->kad->vice_id);
			ENCODE(token->kad->kvno);
			ENCODE_DATA(8, token->kad->session_key);
			ENCODE(token->kad->start);
			ENCODE(token->kad->expiry);
			ENCODE(token->kad->primary_flag);
			ENCODE_DATA(token->kad->ticket_len, token->kad->ticket);
			break;

		case RXRPC_SECURITY_RXK5:
			princ = &token->k5->client;
			ENCODE(princ->n_name_parts);
			for (loop = 0; loop < princ->n_name_parts; loop++)
				ENCODE_STR(princ->name_parts[loop]);
			ENCODE_STR(princ->realm);

			princ = &token->k5->server;
			ENCODE(princ->n_name_parts);
			for (loop = 0; loop < princ->n_name_parts; loop++)
				ENCODE_STR(princ->name_parts[loop]);
			ENCODE_STR(princ->realm);

			ENCODE(token->k5->session.tag);
			ENCODE_DATA(token->k5->session.data_len, token->k5->session.data);

			ENCODE64(token->k5->authtime);
			ENCODE64(token->k5->starttime);
			ENCODE64(token->k5->endtime);
			ENCODE64(token->k5->renew_till);
			ENCODE(token->k5->is_skey);
			ENCODE(token->k5->flags);

			ENCODE(token->k5->n_addresses);
			for (loop = 0; loop < token->k5->n_addresses; loop++) {
				ENCODE(token->k5->addresses[loop].tag);
				ENCODE_DATA(token->k5->addresses[loop].data_len, token->k5->addresses[loop].data);
			}

			ENCODE_DATA(token->k5->ticket_len, token->k5->ticket);
			ENCODE_DATA(token->k5->ticket2_len, token->k5->ticket2);

			ENCODE(token->k5->n_authdata);
			for (loop = 0; loop < token->k5->n_authdata; loop++) {
				ENCODE(token->k5->authdata[loop].tag);
				ENCODE_DATA(token->k5->authdata[loop].data_len, token->k5->authdata[loop].data);
			}
			break;

		default:
			BUG();
			break;
		}

		ASSERTCMP((unsigned long)xdr - (unsigned long)oldxdr, ==, toksize);
	}






	ASSERTCMP(tok, ==, ntoks);
	ASSERTCMP((char __user *) xdr - buffer, ==, size);
	_leave(" = %zu", size);
	return size;

fault:
	_leave(" = -EFAULT");
	return -EFAULT;
}
