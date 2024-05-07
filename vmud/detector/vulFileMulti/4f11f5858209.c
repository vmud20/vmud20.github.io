
















extern kmem_cache_t *sctp_chunk_cachep;

SCTP_STATIC struct sctp_chunk *sctp_make_chunk(const struct sctp_association *asoc, __u8 type, __u8 flags, int paylen);

static sctp_cookie_param_t *sctp_pack_cookie(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const struct sctp_chunk *init_chunk, int *cookie_len, const __u8 *raw_addrs, int addrs_len);



static int sctp_process_param(struct sctp_association *asoc, union sctp_params param, const union sctp_addr *peer_addr, gfp_t gfp);




int sctp_chunk_iif(const struct sctp_chunk *chunk)
{
	struct sctp_af *af;
	int iif = 0;

	af = sctp_get_af_specific(ipver2af(chunk->skb->nh.iph->version));
	if (af)
		iif = af->skb_iif(chunk->skb);

	return iif;
}


static const struct sctp_paramhdr ecap_param = {
	SCTP_PARAM_ECN_CAPABLE, __constant_htons(sizeof(struct sctp_paramhdr)), };

static const struct sctp_paramhdr prsctp_param = {
	SCTP_PARAM_FWD_TSN_SUPPORT, __constant_htons(sizeof(struct sctp_paramhdr)), };



void  sctp_init_cause(struct sctp_chunk *chunk, __u16 cause_code, const void *payload, size_t paylen)
{
	sctp_errhdr_t err;
	int padlen;
	__u16 len;

        
	err.cause = cause_code;
	len = sizeof(sctp_errhdr_t) + paylen;
	padlen = len % 4;
	err.length  = htons(len);
	len += padlen;
	sctp_addto_chunk(chunk, sizeof(sctp_errhdr_t), &err);
	chunk->subh.err_hdr = sctp_addto_chunk(chunk, paylen, payload);
}


struct sctp_chunk *sctp_make_init(const struct sctp_association *asoc, const struct sctp_bind_addr *bp, gfp_t gfp, int vparam_len)

{
	sctp_inithdr_t init;
	union sctp_params addrs;
	size_t chunksize;
	struct sctp_chunk *retval = NULL;
	int num_types, addrs_len = 0;
	struct sctp_sock *sp;
	sctp_supported_addrs_param_t sat;
	__u16 types[2];
	sctp_adaption_ind_param_t aiparam;

	
	retval = NULL;

	
	addrs = sctp_bind_addrs_to_raw(bp, &addrs_len, gfp);

	init.init_tag		   = htonl(asoc->c.my_vtag);
	init.a_rwnd		   = htonl(asoc->rwnd);
	init.num_outbound_streams  = htons(asoc->c.sinit_num_ostreams);
	init.num_inbound_streams   = htons(asoc->c.sinit_max_instreams);
	init.initial_tsn	   = htonl(asoc->c.initial_tsn);

	
	sp = sctp_sk(asoc->base.sk);
	num_types = sp->pf->supported_addrs(sp, types);

	chunksize = sizeof(init) + addrs_len + SCTP_SAT_LEN(num_types);
	chunksize += sizeof(ecap_param);
	if (sctp_prsctp_enable)
		chunksize += sizeof(prsctp_param);
	chunksize += sizeof(aiparam);
	chunksize += vparam_len;

	

	retval = sctp_make_chunk(asoc, SCTP_CID_INIT, 0, chunksize);
	if (!retval)
		goto nodata;

	retval->subh.init_hdr = sctp_addto_chunk(retval, sizeof(init), &init);
	retval->param_hdr.v = sctp_addto_chunk(retval, addrs_len, addrs.v);

	
	sat.param_hdr.type = SCTP_PARAM_SUPPORTED_ADDRESS_TYPES;
	sat.param_hdr.length = htons(SCTP_SAT_LEN(num_types));
	sctp_addto_chunk(retval, sizeof(sat), &sat);
	sctp_addto_chunk(retval, num_types * sizeof(__u16), &types);

	sctp_addto_chunk(retval, sizeof(ecap_param), &ecap_param);
	if (sctp_prsctp_enable)
		sctp_addto_chunk(retval, sizeof(prsctp_param), &prsctp_param);
	aiparam.param_hdr.type = SCTP_PARAM_ADAPTION_LAYER_IND;
	aiparam.param_hdr.length = htons(sizeof(aiparam));
	aiparam.adaption_ind = htonl(sp->adaption_ind);
	sctp_addto_chunk(retval, sizeof(aiparam), &aiparam);
nodata:
	kfree(addrs.v);
	return retval;
}

struct sctp_chunk *sctp_make_init_ack(const struct sctp_association *asoc, const struct sctp_chunk *chunk, gfp_t gfp, int unkparam_len)

{
	sctp_inithdr_t initack;
	struct sctp_chunk *retval;
	union sctp_params addrs;
	int addrs_len;
	sctp_cookie_param_t *cookie;
	int cookie_len;
	size_t chunksize;
	sctp_adaption_ind_param_t aiparam;

	retval = NULL;

	
	addrs = sctp_bind_addrs_to_raw(&asoc->base.bind_addr, &addrs_len, gfp);

	initack.init_tag	        = htonl(asoc->c.my_vtag);
	initack.a_rwnd			= htonl(asoc->rwnd);
	initack.num_outbound_streams	= htons(asoc->c.sinit_num_ostreams);
	initack.num_inbound_streams	= htons(asoc->c.sinit_max_instreams);
	initack.initial_tsn		= htonl(asoc->c.initial_tsn);

	
	cookie = sctp_pack_cookie(asoc->ep, asoc, chunk, &cookie_len, addrs.v, addrs_len);
	if (!cookie)
		goto nomem_cookie;

	
	chunksize = sizeof(initack) + addrs_len + cookie_len + unkparam_len;

        
	if (asoc->peer.ecn_capable)
		chunksize += sizeof(ecap_param);

        
	if (asoc->peer.prsctp_capable)
		chunksize += sizeof(prsctp_param);

	chunksize += sizeof(aiparam);

	
	retval = sctp_make_chunk(asoc, SCTP_CID_INIT_ACK, 0, chunksize);
	if (!retval)
		goto nomem_chunk;

	
	retval->transport = chunk->transport;
	retval->subh.init_hdr = sctp_addto_chunk(retval, sizeof(initack), &initack);
	retval->param_hdr.v = sctp_addto_chunk(retval, addrs_len, addrs.v);
	sctp_addto_chunk(retval, cookie_len, cookie);
	if (asoc->peer.ecn_capable)
		sctp_addto_chunk(retval, sizeof(ecap_param), &ecap_param);
	if (asoc->peer.prsctp_capable)
		sctp_addto_chunk(retval, sizeof(prsctp_param), &prsctp_param);

	aiparam.param_hdr.type = SCTP_PARAM_ADAPTION_LAYER_IND;
	aiparam.param_hdr.length = htons(sizeof(aiparam));
	aiparam.adaption_ind = htonl(sctp_sk(asoc->base.sk)->adaption_ind);
	sctp_addto_chunk(retval, sizeof(aiparam), &aiparam);

	
	retval->asoc = (struct sctp_association *) asoc;

	
	if (chunk)
		retval->transport = chunk->transport;

nomem_chunk:
	kfree(cookie);
nomem_cookie:
	kfree(addrs.v);
	return retval;
}


struct sctp_chunk *sctp_make_cookie_echo(const struct sctp_association *asoc, const struct sctp_chunk *chunk)
{
	struct sctp_chunk *retval;
	void *cookie;
	int cookie_len;

	cookie = asoc->peer.cookie;
	cookie_len = asoc->peer.cookie_len;

	
	retval = sctp_make_chunk(asoc, SCTP_CID_COOKIE_ECHO, 0, cookie_len);
	if (!retval)
		goto nodata;
	retval->subh.cookie_hdr = sctp_addto_chunk(retval, cookie_len, cookie);

	
	if (chunk)
		retval->transport = chunk->transport;

nodata:
	return retval;
}


struct sctp_chunk *sctp_make_cookie_ack(const struct sctp_association *asoc, const struct sctp_chunk *chunk)
{
	struct sctp_chunk *retval;

	retval = sctp_make_chunk(asoc, SCTP_CID_COOKIE_ACK, 0, 0);

	
	if (retval && chunk)
		retval->transport = chunk->transport;

	return retval;
}


struct sctp_chunk *sctp_make_cwr(const struct sctp_association *asoc, const __u32 lowest_tsn, const struct sctp_chunk *chunk)

{
	struct sctp_chunk *retval;
	sctp_cwrhdr_t cwr;

	cwr.lowest_tsn = htonl(lowest_tsn);
	retval = sctp_make_chunk(asoc, SCTP_CID_ECN_CWR, 0, sizeof(sctp_cwrhdr_t));

	if (!retval)
		goto nodata;

	retval->subh.ecn_cwr_hdr = sctp_addto_chunk(retval, sizeof(cwr), &cwr);

	
	if (chunk)
		retval->transport = chunk->transport;

nodata:
	return retval;
}


struct sctp_chunk *sctp_make_ecne(const struct sctp_association *asoc, const __u32 lowest_tsn)
{
	struct sctp_chunk *retval;
	sctp_ecnehdr_t ecne;

	ecne.lowest_tsn = htonl(lowest_tsn);
	retval = sctp_make_chunk(asoc, SCTP_CID_ECN_ECNE, 0, sizeof(sctp_ecnehdr_t));
	if (!retval)
		goto nodata;
	retval->subh.ecne_hdr = sctp_addto_chunk(retval, sizeof(ecne), &ecne);

nodata:
	return retval;
}


struct sctp_chunk *sctp_make_datafrag_empty(struct sctp_association *asoc, const struct sctp_sndrcvinfo *sinfo, int data_len, __u8 flags, __u16 ssn)

{
	struct sctp_chunk *retval;
	struct sctp_datahdr dp;
	int chunk_len;

	
	dp.tsn = 0;
	dp.stream = htons(sinfo->sinfo_stream);
	dp.ppid   = sinfo->sinfo_ppid;

	
	if (sinfo->sinfo_flags & SCTP_UNORDERED) {
		flags |= SCTP_DATA_UNORDERED;
		dp.ssn = 0;
	} else dp.ssn = htons(ssn);

	chunk_len = sizeof(dp) + data_len;
	retval = sctp_make_chunk(asoc, SCTP_CID_DATA, flags, chunk_len);
	if (!retval)
		goto nodata;

	retval->subh.data_hdr = sctp_addto_chunk(retval, sizeof(dp), &dp);
	memcpy(&retval->sinfo, sinfo, sizeof(struct sctp_sndrcvinfo));

nodata:
	return retval;
}


struct sctp_chunk *sctp_make_sack(const struct sctp_association *asoc)
{
	struct sctp_chunk *retval;
	struct sctp_sackhdr sack;
	int len;
	__u32 ctsn;
	__u16 num_gabs, num_dup_tsns;
	struct sctp_tsnmap *map = (struct sctp_tsnmap *)&asoc->peer.tsn_map;

	ctsn = sctp_tsnmap_get_ctsn(map);
	SCTP_DEBUG_PRINTK("sackCTSNAck sent:  0x%x.\n", ctsn);

	
	num_gabs = sctp_tsnmap_num_gabs(map);
	num_dup_tsns = sctp_tsnmap_num_dups(map);

	
	sack.cum_tsn_ack	    = htonl(ctsn);
	sack.a_rwnd 		    = htonl(asoc->a_rwnd);
	sack.num_gap_ack_blocks     = htons(num_gabs);
	sack.num_dup_tsns           = htons(num_dup_tsns);

	len = sizeof(sack)
		+ sizeof(struct sctp_gap_ack_block) * num_gabs + sizeof(__u32) * num_dup_tsns;

	
	retval = sctp_make_chunk(asoc, SCTP_CID_SACK, 0, len);
	if (!retval)
		goto nodata;

	
	retval->transport = asoc->peer.last_data_from;

	retval->subh.sack_hdr = sctp_addto_chunk(retval, sizeof(sack), &sack);

	
	if (num_gabs)
		sctp_addto_chunk(retval, sizeof(__u32) * num_gabs, sctp_tsnmap_get_gabs(map));

	
	if (num_dup_tsns)
		sctp_addto_chunk(retval, sizeof(__u32) * num_dup_tsns, sctp_tsnmap_get_dups(map));

nodata:
	return retval;
}


struct sctp_chunk *sctp_make_shutdown(const struct sctp_association *asoc, const struct sctp_chunk *chunk)
{
	struct sctp_chunk *retval;
	sctp_shutdownhdr_t shut;
	__u32 ctsn;

	ctsn = sctp_tsnmap_get_ctsn(&asoc->peer.tsn_map);
	shut.cum_tsn_ack = htonl(ctsn);

	retval = sctp_make_chunk(asoc, SCTP_CID_SHUTDOWN, 0, sizeof(sctp_shutdownhdr_t));
	if (!retval)
		goto nodata;

	retval->subh.shutdown_hdr = sctp_addto_chunk(retval, sizeof(shut), &shut);

	if (chunk)
		retval->transport = chunk->transport;
nodata:
	return retval;
}

struct sctp_chunk *sctp_make_shutdown_ack(const struct sctp_association *asoc, const struct sctp_chunk *chunk)
{
	struct sctp_chunk *retval;

	retval = sctp_make_chunk(asoc, SCTP_CID_SHUTDOWN_ACK, 0, 0);

	
	if (retval && chunk)
		retval->transport = chunk->transport;

	return retval;
}

struct sctp_chunk *sctp_make_shutdown_complete( const struct sctp_association *asoc, const struct sctp_chunk *chunk)

{
	struct sctp_chunk *retval;
	__u8 flags = 0;

	
	flags |= asoc ? 0 : SCTP_CHUNK_FLAG_T;

	retval = sctp_make_chunk(asoc, SCTP_CID_SHUTDOWN_COMPLETE, flags, 0);

	
	if (retval && chunk)
		retval->transport = chunk->transport;

        return retval;
}


struct sctp_chunk *sctp_make_abort(const struct sctp_association *asoc, const struct sctp_chunk *chunk, const size_t hint)

{
	struct sctp_chunk *retval;
	__u8 flags = 0;

	
	if (!asoc) {
		if (chunk && chunk->chunk_hdr && chunk->chunk_hdr->type == SCTP_CID_INIT)
			flags = 0;
		else flags = SCTP_CHUNK_FLAG_T;
	}

	retval = sctp_make_chunk(asoc, SCTP_CID_ABORT, flags, hint);

	
	if (retval && chunk)
		retval->transport = chunk->transport;

	return retval;
}


struct sctp_chunk *sctp_make_abort_no_data( const struct sctp_association *asoc, const struct sctp_chunk *chunk, __u32 tsn)

{
	struct sctp_chunk *retval;
	__u32 payload;

	retval = sctp_make_abort(asoc, chunk, sizeof(sctp_errhdr_t)
				 + sizeof(tsn));

	if (!retval)
		goto no_mem;

	
	payload = htonl(tsn);
	sctp_init_cause(retval, SCTP_ERROR_NO_DATA, (const void *)&payload, sizeof(payload));

	
	if (chunk)
		retval->transport = chunk->transport;

no_mem:
	return retval;
}


struct sctp_chunk *sctp_make_abort_user(const struct sctp_association *asoc, const struct sctp_chunk *chunk, const struct msghdr *msg)

{
	struct sctp_chunk *retval;
	void *payload = NULL, *payoff;
	size_t paylen = 0;
	struct iovec *iov = NULL;
	int iovlen = 0;

	if (msg) {
		iov = msg->msg_iov;
		iovlen = msg->msg_iovlen;
		paylen = get_user_iov_size(iov, iovlen);
	}

	retval = sctp_make_abort(asoc, chunk, sizeof(sctp_errhdr_t) + paylen);
	if (!retval)
		goto err_chunk;

	if (paylen) {
		
		payload = kmalloc(paylen, GFP_ATOMIC);
		if (!payload)
			goto err_payload;
		payoff = payload;

		for (; iovlen > 0; --iovlen) {
			if (copy_from_user(payoff, iov->iov_base,iov->iov_len))
				goto err_copy;
			payoff += iov->iov_len;
			iov++;
		}
	}

	sctp_init_cause(retval, SCTP_ERROR_USER_ABORT, payload, paylen);

	if (paylen)
		kfree(payload);

	return retval;

err_copy:
	kfree(payload);
err_payload:
	sctp_chunk_free(retval);
	retval = NULL;
err_chunk:
	return retval;
}

 
struct sctp_chunk *sctp_make_abort_violation( const struct sctp_association *asoc, const struct sctp_chunk *chunk, const __u8   *payload, const size_t paylen)



{
	struct sctp_chunk  *retval;
	struct sctp_paramhdr phdr;

	retval = sctp_make_abort(asoc, chunk, sizeof(sctp_errhdr_t) + paylen + sizeof(sctp_chunkhdr_t));
	if (!retval)
		goto end;

	sctp_init_cause(retval, SCTP_ERROR_PROTO_VIOLATION, payload, paylen);

	phdr.type = htons(chunk->chunk_hdr->type);
	phdr.length = chunk->chunk_hdr->length;
	sctp_addto_chunk(retval, sizeof(sctp_paramhdr_t), &phdr);

end:
	return retval;
}


struct sctp_chunk *sctp_make_heartbeat(const struct sctp_association *asoc, const struct sctp_transport *transport, const void *payload, const size_t paylen)

{
	struct sctp_chunk *retval = sctp_make_chunk(asoc, SCTP_CID_HEARTBEAT, 0, paylen);

	if (!retval)
		goto nodata;

	
	retval->transport = (struct sctp_transport *) transport;
	retval->subh.hbs_hdr = sctp_addto_chunk(retval, paylen, payload);

nodata:
	return retval;
}

struct sctp_chunk *sctp_make_heartbeat_ack(const struct sctp_association *asoc, const struct sctp_chunk *chunk, const void *payload, const size_t paylen)

{
	struct sctp_chunk *retval;

	retval  = sctp_make_chunk(asoc, SCTP_CID_HEARTBEAT_ACK, 0, paylen);
	if (!retval)
		goto nodata;

	retval->subh.hbs_hdr = sctp_addto_chunk(retval, paylen, payload);

	
	if (chunk)
		retval->transport = chunk->transport;

nodata:
	return retval;
}


static struct sctp_chunk *sctp_make_op_error_space( const struct sctp_association *asoc, const struct sctp_chunk *chunk, size_t size)


{
	struct sctp_chunk *retval;

	retval = sctp_make_chunk(asoc, SCTP_CID_ERROR, 0, sizeof(sctp_errhdr_t) + size);
	if (!retval)
		goto nodata;

	
	if (chunk)
		retval->transport = chunk->transport;

nodata:
	return retval;
}


struct sctp_chunk *sctp_make_op_error(const struct sctp_association *asoc, const struct sctp_chunk *chunk, __u16 cause_code, const void *payload, size_t paylen)


{
	struct sctp_chunk *retval;

	retval = sctp_make_op_error_space(asoc, chunk, paylen);
	if (!retval)
		goto nodata;

	sctp_init_cause(retval, cause_code, payload, paylen);

nodata:
	return retval;
}




struct sctp_chunk *sctp_chunkify(struct sk_buff *skb, const struct sctp_association *asoc, struct sock *sk)

{
	struct sctp_chunk *retval;

	retval = kmem_cache_alloc(sctp_chunk_cachep, SLAB_ATOMIC);

	if (!retval)
		goto nodata;
	memset(retval, 0, sizeof(struct sctp_chunk));

	if (!sk) {
		SCTP_DEBUG_PRINTK("chunkifying skb %p w/o an sk\n", skb);
	}

	INIT_LIST_HEAD(&retval->list);
	retval->skb		= skb;
	retval->asoc		= (struct sctp_association *)asoc;
	retval->resent  	= 0;
	retval->has_tsn		= 0;
	retval->has_ssn         = 0;
	retval->rtt_in_progress	= 0;
	retval->sent_at		= 0;
	retval->singleton	= 1;
	retval->end_of_packet	= 0;
	retval->ecn_ce_done	= 0;
	retval->pdiscard	= 0;

	
	retval->tsn_missing_report = 0;
	retval->tsn_gap_acked = 0;
	retval->fast_retransmit = 0;

	
	retval->msg = NULL;

	
	INIT_LIST_HEAD(&retval->transmitted_list);
	INIT_LIST_HEAD(&retval->frag_list);
	SCTP_DBG_OBJCNT_INC(chunk);
	atomic_set(&retval->refcnt, 1);

nodata:
	return retval;
}


void sctp_init_addrs(struct sctp_chunk *chunk, union sctp_addr *src, union sctp_addr *dest)
{
	memcpy(&chunk->source, src, sizeof(union sctp_addr));
	memcpy(&chunk->dest, dest, sizeof(union sctp_addr));
}


const union sctp_addr *sctp_source(const struct sctp_chunk *chunk)
{
	
	if (chunk->transport) {
		return &chunk->transport->ipaddr;
	} else {
		
		return &chunk->source;
	}
}


SCTP_STATIC struct sctp_chunk *sctp_make_chunk(const struct sctp_association *asoc, __u8 type, __u8 flags, int paylen)

{
	struct sctp_chunk *retval;
	sctp_chunkhdr_t *chunk_hdr;
	struct sk_buff *skb;
	struct sock *sk;

	
	skb = alloc_skb(WORD_ROUND(sizeof(sctp_chunkhdr_t) + paylen), GFP_ATOMIC);
	if (!skb)
		goto nodata;

	
	chunk_hdr = (sctp_chunkhdr_t *)skb_put(skb, sizeof(sctp_chunkhdr_t));
	chunk_hdr->type	  = type;
	chunk_hdr->flags  = flags;
	chunk_hdr->length = htons(sizeof(sctp_chunkhdr_t));

	sk = asoc ? asoc->base.sk : NULL;
	retval = sctp_chunkify(skb, asoc, sk);
	if (!retval) {
		kfree_skb(skb);
		goto nodata;
	}

	retval->chunk_hdr = chunk_hdr;
	retval->chunk_end = ((__u8 *)chunk_hdr) + sizeof(struct sctp_chunkhdr);

	
	skb->sk = sk;

	return retval;
nodata:
	return NULL;
}



static void sctp_chunk_destroy(struct sctp_chunk *chunk)
{
	
	dev_kfree_skb(chunk->skb);

	SCTP_DBG_OBJCNT_DEC(chunk);
	kmem_cache_free(sctp_chunk_cachep, chunk);
}


void sctp_chunk_free(struct sctp_chunk *chunk)
{
	BUG_ON(!list_empty(&chunk->list));
	list_del_init(&chunk->transmitted_list);

	
	if (chunk->msg)
		sctp_datamsg_put(chunk->msg);

	sctp_chunk_put(chunk);
}


void sctp_chunk_hold(struct sctp_chunk *ch)
{
	atomic_inc(&ch->refcnt);
}


void sctp_chunk_put(struct sctp_chunk *ch)
{
	if (atomic_dec_and_test(&ch->refcnt))
		sctp_chunk_destroy(ch);
}


void *sctp_addto_chunk(struct sctp_chunk *chunk, int len, const void *data)
{
	void *target;
	void *padding;
	int chunklen = ntohs(chunk->chunk_hdr->length);
	int padlen = chunklen % 4;

	padding = skb_put(chunk->skb, padlen);
	target = skb_put(chunk->skb, len);

	memset(padding, 0, padlen);
	memcpy(target, data, len);

	
	chunk->chunk_hdr->length = htons(chunklen + padlen + len);
	chunk->chunk_end = chunk->skb->tail;

	return target;
}


int sctp_user_addto_chunk(struct sctp_chunk *chunk, int off, int len, struct iovec *data)
{
	__u8 *target;
	int err = 0;

	
	target = skb_put(chunk->skb, len);

	
	if ((err = memcpy_fromiovecend(target, data, off, len)))
		goto out;

	
	chunk->chunk_hdr->length = htons(ntohs(chunk->chunk_hdr->length) + len);
	chunk->chunk_end = chunk->skb->tail;

out:
	return err;
}


void sctp_chunk_assign_ssn(struct sctp_chunk *chunk)
{
	__u16 ssn;
	__u16 sid;

	if (chunk->has_ssn)
		return;

	
	if (chunk->chunk_hdr->flags & SCTP_DATA_UNORDERED) {
		ssn = 0;
	} else {
		sid = htons(chunk->subh.data_hdr->stream);
		if (chunk->chunk_hdr->flags & SCTP_DATA_LAST_FRAG)
			ssn = sctp_ssn_next(&chunk->asoc->ssnmap->out, sid);
		else ssn = sctp_ssn_peek(&chunk->asoc->ssnmap->out, sid);
		ssn = htons(ssn);
	}

	chunk->subh.data_hdr->ssn = ssn;
	chunk->has_ssn = 1;
}


void sctp_chunk_assign_tsn(struct sctp_chunk *chunk)
{
	if (!chunk->has_tsn) {
		
		chunk->subh.data_hdr->tsn = htonl(sctp_association_get_next_tsn(chunk->asoc));
		chunk->has_tsn = 1;
	}
}


struct sctp_association *sctp_make_temp_asoc(const struct sctp_endpoint *ep, struct sctp_chunk *chunk, gfp_t gfp)

{
	struct sctp_association *asoc;
	struct sk_buff *skb;
	sctp_scope_t scope;
	struct sctp_af *af;

	
	scope = sctp_scope(sctp_source(chunk));
	asoc = sctp_association_new(ep, ep->base.sk, scope, gfp);
	if (!asoc)
		goto nodata;
	asoc->temp = 1;
	skb = chunk->skb;
	
	af = sctp_get_af_specific(ipver2af(skb->nh.iph->version));
	if (unlikely(!af))
		goto fail;
	af->from_skb(&asoc->c.peer_addr, skb, 1);
nodata:
	return asoc;

fail:
	sctp_association_free(asoc);
	return NULL;
}


static sctp_cookie_param_t *sctp_pack_cookie(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const struct sctp_chunk *init_chunk, int *cookie_len, const __u8 *raw_addrs, int addrs_len)



{
	sctp_cookie_param_t *retval;
	struct sctp_signed_cookie *cookie;
	struct scatterlist sg;
	int headersize, bodysize;
	unsigned int keylen;
	char *key;

	
	headersize = sizeof(sctp_paramhdr_t) +  (sizeof(struct sctp_signed_cookie) - sizeof(struct sctp_cookie));

	bodysize = sizeof(struct sctp_cookie)
		+ ntohs(init_chunk->chunk_hdr->length) + addrs_len;

	
	if (bodysize % SCTP_COOKIE_MULTIPLE)
		bodysize += SCTP_COOKIE_MULTIPLE - (bodysize % SCTP_COOKIE_MULTIPLE);
	*cookie_len = headersize + bodysize;

	retval = kmalloc(*cookie_len, GFP_ATOMIC);

	if (!retval) {
		*cookie_len = 0;
		goto nodata;
	}

	
	memset(retval, 0x00, *cookie_len);
	cookie = (struct sctp_signed_cookie *) retval->body;

	
	retval->p.type = SCTP_PARAM_STATE_COOKIE;
	retval->p.length = htons(*cookie_len);

	
	cookie->c = asoc->c;
	
	cookie->c.raw_addr_list_len = addrs_len;

	
	cookie->c.prsctp_capable = asoc->peer.prsctp_capable;

	
	cookie->c.adaption_ind = asoc->peer.adaption_ind;

	
	do_gettimeofday(&cookie->c.expiration);
	TIMEVAL_ADD(asoc->cookie_life, cookie->c.expiration);

	
	memcpy(&cookie->c.peer_init[0], init_chunk->chunk_hdr, ntohs(init_chunk->chunk_hdr->length));

	
	memcpy((__u8 *)&cookie->c.peer_init[0] + ntohs(init_chunk->chunk_hdr->length), raw_addrs, addrs_len);

  	if (sctp_sk(ep->base.sk)->hmac) {
		
		sg.page = virt_to_page(&cookie->c);
		sg.offset = (unsigned long)(&cookie->c) % PAGE_SIZE;
		sg.length = bodysize;
		keylen = SCTP_SECRET_SIZE;
		key = (char *)ep->secret_key[ep->current_key];

		sctp_crypto_hmac(sctp_sk(ep->base.sk)->hmac, key, &keylen, &sg, 1, cookie->signature);
	}

nodata:
	return retval;
}


struct sctp_association *sctp_unpack_cookie( const struct sctp_endpoint *ep, const struct sctp_association *asoc, struct sctp_chunk *chunk, gfp_t gfp, int *error, struct sctp_chunk **errp)



{
	struct sctp_association *retval = NULL;
	struct sctp_signed_cookie *cookie;
	struct sctp_cookie *bear_cookie;
	int headersize, bodysize, fixed_size;
	__u8 *digest = ep->digest;
	struct scatterlist sg;
	unsigned int keylen, len;
	char *key;
	sctp_scope_t scope;
	struct sk_buff *skb = chunk->skb;
	struct timeval tv;

	
	headersize = sizeof(sctp_chunkhdr_t) + (sizeof(struct sctp_signed_cookie) - sizeof(struct sctp_cookie));

	bodysize = ntohs(chunk->chunk_hdr->length) - headersize;
	fixed_size = headersize + sizeof(struct sctp_cookie);

	
	len = ntohs(chunk->chunk_hdr->length);
	if (len < fixed_size + sizeof(struct sctp_chunkhdr))
		goto malformed;

	
	if (bodysize % SCTP_COOKIE_MULTIPLE)
		goto malformed;

	
	cookie = chunk->subh.cookie_hdr;
	bear_cookie = &cookie->c;

	if (!sctp_sk(ep->base.sk)->hmac)
		goto no_hmac;

	
	keylen = SCTP_SECRET_SIZE;
	sg.page = virt_to_page(bear_cookie);
	sg.offset = (unsigned long)(bear_cookie) % PAGE_SIZE;
	sg.length = bodysize;
	key = (char *)ep->secret_key[ep->current_key];

	memset(digest, 0x00, SCTP_SIGNATURE_SIZE);
	sctp_crypto_hmac(sctp_sk(ep->base.sk)->hmac, key, &keylen, &sg, 1, digest);

	if (memcmp(digest, cookie->signature, SCTP_SIGNATURE_SIZE)) {
		
		key = (char *)ep->secret_key[ep->last_key];
		memset(digest, 0x00, SCTP_SIGNATURE_SIZE);
		sctp_crypto_hmac(sctp_sk(ep->base.sk)->hmac, key, &keylen, &sg, 1, digest);

		if (memcmp(digest, cookie->signature, SCTP_SIGNATURE_SIZE)) {
			
			*error = -SCTP_IERROR_BAD_SIG;
			goto fail;
		}
	}

no_hmac:
	
	if (ntohl(chunk->sctp_hdr->vtag) != bear_cookie->my_vtag) {
		*error = -SCTP_IERROR_BAD_TAG;
		goto fail;
	}

	if (ntohs(chunk->sctp_hdr->source) != bear_cookie->peer_addr.v4.sin_port || ntohs(chunk->sctp_hdr->dest) != bear_cookie->my_port) {
		*error = -SCTP_IERROR_BAD_PORTS;
		goto fail;
	}

	
	skb_get_timestamp(skb, &tv);
	if (!asoc && tv_lt(bear_cookie->expiration, tv)) {
		__u16 len;
		
		len = ntohs(chunk->chunk_hdr->length);
		*errp = sctp_make_op_error_space(asoc, chunk, len);
		if (*errp) {
			suseconds_t usecs = (tv.tv_sec - bear_cookie->expiration.tv_sec) * 1000000L + tv.tv_usec - bear_cookie->expiration.tv_usec;


			usecs = htonl(usecs);
			sctp_init_cause(*errp, SCTP_ERROR_STALE_COOKIE, &usecs, sizeof(usecs));
			*error = -SCTP_IERROR_STALE_COOKIE;
		} else *error = -SCTP_IERROR_NOMEM;

		goto fail;
	}

	
	scope = sctp_scope(sctp_source(chunk));
	retval = sctp_association_new(ep, ep->base.sk, scope, gfp);
	if (!retval) {
		*error = -SCTP_IERROR_NOMEM;
		goto fail;
	}

	
	retval->peer.port = ntohs(chunk->sctp_hdr->source);

	
	memcpy(&retval->c, bear_cookie, sizeof(*bear_cookie));

	if (sctp_assoc_set_bind_addr_from_cookie(retval, bear_cookie, GFP_ATOMIC) < 0) {
		*error = -SCTP_IERROR_NOMEM;
		goto fail;
	}

	
	if (list_empty(&retval->base.bind_addr.address_list)) {
		sctp_add_bind_addr(&retval->base.bind_addr, &chunk->dest, 1, GFP_ATOMIC);
	}

	retval->next_tsn = retval->c.initial_tsn;
	retval->ctsn_ack_point = retval->next_tsn - 1;
	retval->addip_serial = retval->c.initial_tsn;
	retval->adv_peer_ack_point = retval->ctsn_ack_point;
	retval->peer.prsctp_capable = retval->c.prsctp_capable;
	retval->peer.adaption_ind = retval->c.adaption_ind;

	
	return retval;

fail:
	if (retval)
		sctp_association_free(retval);

	return NULL;

malformed:
	
	*error = -SCTP_IERROR_MALFORMED;
	goto fail;
}



struct __sctp_missing {
	__u32 num_missing;
	__u16 type;
}  __attribute__((packed));


static int sctp_process_missing_param(const struct sctp_association *asoc, sctp_param_t paramtype, struct sctp_chunk *chunk, struct sctp_chunk **errp)


{
	struct __sctp_missing report;
	__u16 len;

	len = WORD_ROUND(sizeof(report));

	
	if (!*errp)
		*errp = sctp_make_op_error_space(asoc, chunk, len);

	if (*errp) {
		report.num_missing = htonl(1);
		report.type = paramtype;
		sctp_init_cause(*errp, SCTP_ERROR_INV_PARAM, &report, sizeof(report));
	}

	
	return 0;
}


static int sctp_process_inv_mandatory(const struct sctp_association *asoc, struct sctp_chunk *chunk, struct sctp_chunk **errp)

{
	

	if (!*errp)
		*errp = sctp_make_op_error_space(asoc, chunk, 0);

	if (*errp)
		sctp_init_cause(*errp, SCTP_ERROR_INV_PARAM, NULL, 0);

	
	return 0;
}

static int sctp_process_inv_paramlength(const struct sctp_association *asoc, struct sctp_paramhdr *param, const struct sctp_chunk *chunk, struct sctp_chunk **errp)


{
	char		error[] = "The following parameter had invalid length:";
	size_t		payload_len = WORD_ROUND(sizeof(error)) +  sizeof(sctp_paramhdr_t);


	
	if (!*errp)
		*errp = sctp_make_op_error_space(asoc, chunk, payload_len);

	if (*errp) {
		sctp_init_cause(*errp, SCTP_ERROR_PROTO_VIOLATION, error, sizeof(error));
		sctp_addto_chunk(*errp, sizeof(sctp_paramhdr_t), param);
	}

	return 0;
}



static int sctp_process_hn_param(const struct sctp_association *asoc, union sctp_params param, struct sctp_chunk *chunk, struct sctp_chunk **errp)


{
	__u16 len = ntohs(param.p->length);

	
	if (!*errp)
		*errp = sctp_make_op_error_space(asoc, chunk, len);

	if (*errp)
		sctp_init_cause(*errp, SCTP_ERROR_DNS_FAILED, param.v, len);

	
	return 0;
}


static int sctp_process_unk_param(const struct sctp_association *asoc, union sctp_params param, struct sctp_chunk *chunk, struct sctp_chunk **errp)


{
	int retval = 1;

	switch (param.p->type & SCTP_PARAM_ACTION_MASK) {
	case SCTP_PARAM_ACTION_DISCARD:
		retval =  0;
		break;
	case SCTP_PARAM_ACTION_DISCARD_ERR:
		retval =  0;
		
		if (NULL == *errp)
			*errp = sctp_make_op_error_space(asoc, chunk, ntohs(chunk->chunk_hdr->length));

		if (*errp)
			sctp_init_cause(*errp, SCTP_ERROR_UNKNOWN_PARAM, param.v, WORD_ROUND(ntohs(param.p->length)));


		break;
	case SCTP_PARAM_ACTION_SKIP:
		break;
	case SCTP_PARAM_ACTION_SKIP_ERR:
		
		if (NULL == *errp)
			*errp = sctp_make_op_error_space(asoc, chunk, ntohs(chunk->chunk_hdr->length));

		if (*errp) {
			sctp_init_cause(*errp, SCTP_ERROR_UNKNOWN_PARAM, param.v, WORD_ROUND(ntohs(param.p->length)));

		} else {
			
			retval = 0;
		}

		break;
	default:
		break;
	}

	return retval;
}


static int sctp_verify_param(const struct sctp_association *asoc, union sctp_params param, sctp_cid_t cid, struct sctp_chunk *chunk, struct sctp_chunk **err_chunk)



{
	int retval = 1;

	

	switch (param.p->type) {
	case SCTP_PARAM_IPV4_ADDRESS:
	case SCTP_PARAM_IPV6_ADDRESS:
	case SCTP_PARAM_COOKIE_PRESERVATIVE:
	case SCTP_PARAM_SUPPORTED_ADDRESS_TYPES:
	case SCTP_PARAM_STATE_COOKIE:
	case SCTP_PARAM_HEARTBEAT_INFO:
	case SCTP_PARAM_UNRECOGNIZED_PARAMETERS:
	case SCTP_PARAM_ECN_CAPABLE:
	case SCTP_PARAM_ADAPTION_LAYER_IND:
		break;

	case SCTP_PARAM_HOST_NAME_ADDRESS:
		
		return sctp_process_hn_param(asoc, param, chunk, err_chunk);
	case SCTP_PARAM_FWD_TSN_SUPPORT:
		if (sctp_prsctp_enable)
			break;
		 
	default:
		SCTP_DEBUG_PRINTK("Unrecognized param: %d for chunk %d.\n", ntohs(param.p->type), cid);
		return sctp_process_unk_param(asoc, param, chunk, err_chunk);

		break;
	}
	return retval;
}


int sctp_verify_init(const struct sctp_association *asoc, sctp_cid_t cid, sctp_init_chunk_t *peer_init, struct sctp_chunk *chunk, struct sctp_chunk **errp)



{
	union sctp_params param;
	int has_cookie = 0;

	
	if ((0 == peer_init->init_hdr.num_outbound_streams) || (0 == peer_init->init_hdr.num_inbound_streams)) {

		sctp_process_inv_mandatory(asoc, chunk, errp);
		return 0;
	}

	
	sctp_walk_params(param, peer_init, init_hdr.params) {

		if (SCTP_PARAM_STATE_COOKIE == param.p->type)
			has_cookie = 1;

	} 

	
	if (param.v < (void*)chunk->chunk_end - sizeof(sctp_paramhdr_t)) {
		sctp_process_inv_paramlength(asoc, param.p, chunk, errp);
		return 0;
	}

	
	if ((SCTP_CID_INIT_ACK == cid) && !has_cookie) {
		sctp_process_missing_param(asoc, SCTP_PARAM_STATE_COOKIE, chunk, errp);
		return 0;
	}

	

	sctp_walk_params(param, peer_init, init_hdr.params) {

		if (!sctp_verify_param(asoc, param, cid, chunk, errp)) {
			if (SCTP_PARAM_HOST_NAME_ADDRESS == param.p->type)
				return 0;
			else return 1;
		}

	} 

	return 1;
}


int sctp_process_init(struct sctp_association *asoc, sctp_cid_t cid, const union sctp_addr *peer_addr, sctp_init_chunk_t *peer_init, gfp_t gfp)

{
	union sctp_params param;
	struct sctp_transport *transport;
	struct list_head *pos, *temp;
	char *cookie;

	

	
	if (peer_addr)
		if(!sctp_assoc_add_peer(asoc, peer_addr, gfp, SCTP_ACTIVE))
			goto nomem;

	

	sctp_walk_params(param, peer_init, init_hdr.params) {

		if (!sctp_process_param(asoc, param, peer_addr, gfp))
                        goto clean_up;
	}

	
	list_for_each_safe(pos, temp, &asoc->peer.transport_addr_list) {
		transport = list_entry(pos, struct sctp_transport, transports);
		if (transport->state == SCTP_UNKNOWN) {
			sctp_assoc_rm_peer(asoc, transport);
		}
	}

	
	asoc->peer.i.init_tag = ntohl(peer_init->init_hdr.init_tag);
	asoc->peer.i.a_rwnd = ntohl(peer_init->init_hdr.a_rwnd);
	asoc->peer.i.num_outbound_streams = ntohs(peer_init->init_hdr.num_outbound_streams);
	asoc->peer.i.num_inbound_streams = ntohs(peer_init->init_hdr.num_inbound_streams);
	asoc->peer.i.initial_tsn = ntohl(peer_init->init_hdr.initial_tsn);

	
	if (asoc->c.sinit_num_ostreams  > ntohs(peer_init->init_hdr.num_inbound_streams)) {
		asoc->c.sinit_num_ostreams = ntohs(peer_init->init_hdr.num_inbound_streams);
	}

	if (asoc->c.sinit_max_instreams > ntohs(peer_init->init_hdr.num_outbound_streams)) {
		asoc->c.sinit_max_instreams = ntohs(peer_init->init_hdr.num_outbound_streams);
	}

	
	asoc->c.peer_vtag = asoc->peer.i.init_tag;

	
	asoc->peer.rwnd = asoc->peer.i.a_rwnd;

	
	cookie = asoc->peer.cookie;
	if (cookie) {
		asoc->peer.cookie = kmalloc(asoc->peer.cookie_len, gfp);
		if (!asoc->peer.cookie)
			goto clean_up;
		memcpy(asoc->peer.cookie, cookie, asoc->peer.cookie_len);
	}

	
	list_for_each(pos, &asoc->peer.transport_addr_list) {
		transport = list_entry(pos, struct sctp_transport, transports);
		transport->ssthresh = asoc->peer.i.a_rwnd;
	}

	
	sctp_tsnmap_init(&asoc->peer.tsn_map, SCTP_TSN_MAP_SIZE, asoc->peer.i.initial_tsn);

	

	
	if (!asoc->temp) {
		int assoc_id;
		int error;

		asoc->ssnmap = sctp_ssnmap_new(asoc->c.sinit_max_instreams, asoc->c.sinit_num_ostreams, gfp);
		if (!asoc->ssnmap)
			goto clean_up;

	retry:
		if (unlikely(!idr_pre_get(&sctp_assocs_id, gfp)))
			goto clean_up;
		spin_lock_bh(&sctp_assocs_id_lock);
		error = idr_get_new_above(&sctp_assocs_id, (void *)asoc, 1, &assoc_id);
		spin_unlock_bh(&sctp_assocs_id_lock);
		if (error == -EAGAIN)
			goto retry;
		else if (error)
			goto clean_up;

		asoc->assoc_id = (sctp_assoc_t) assoc_id;
	}

	
	asoc->peer.addip_serial = asoc->peer.i.initial_tsn - 1;
	return 1;

clean_up:
	
	list_for_each_safe(pos, temp, &asoc->peer.transport_addr_list) {
		transport = list_entry(pos, struct sctp_transport, transports);
		list_del_init(pos);
		sctp_transport_free(transport);
	}

	asoc->peer.transport_count = 0;

nomem:
	return 0;
}



static int sctp_process_param(struct sctp_association *asoc, union sctp_params param, const union sctp_addr *peer_addr, gfp_t gfp)


{
	union sctp_addr addr;
	int i;
	__u16 sat;
	int retval = 1;
	sctp_scope_t scope;
	time_t stale;
	struct sctp_af *af;

	
	switch (param.p->type) {
	case SCTP_PARAM_IPV6_ADDRESS:
		if (PF_INET6 != asoc->base.sk->sk_family)
			break;
		
	case SCTP_PARAM_IPV4_ADDRESS:
		af = sctp_get_af_specific(param_type2af(param.p->type));
		af->from_addr_param(&addr, param.addr, asoc->peer.port, 0);
		scope = sctp_scope(peer_addr);
		if (sctp_in_scope(&addr, scope))
			if (!sctp_assoc_add_peer(asoc, &addr, gfp, SCTP_UNCONFIRMED))
				return 0;
		break;

	case SCTP_PARAM_COOKIE_PRESERVATIVE:
		if (!sctp_cookie_preserve_enable)
			break;

		stale = ntohl(param.life->lifespan_increment);

		
		asoc->cookie_life.tv_sec += stale / 1000;
		asoc->cookie_life.tv_usec += (stale % 1000) * 1000;
		break;

	case SCTP_PARAM_HOST_NAME_ADDRESS:
		SCTP_DEBUG_PRINTK("unimplemented SCTP_HOST_NAME_ADDRESS\n");
		break;

	case SCTP_PARAM_SUPPORTED_ADDRESS_TYPES:
		
		asoc->peer.ipv4_address = 0;
		asoc->peer.ipv6_address = 0;

		
		sat = ntohs(param.p->length) - sizeof(sctp_paramhdr_t);
		if (sat)
			sat /= sizeof(__u16);

		for (i = 0; i < sat; ++i) {
			switch (param.sat->types[i]) {
			case SCTP_PARAM_IPV4_ADDRESS:
				asoc->peer.ipv4_address = 1;
				break;

			case SCTP_PARAM_IPV6_ADDRESS:
				asoc->peer.ipv6_address = 1;
				break;

			case SCTP_PARAM_HOST_NAME_ADDRESS:
				asoc->peer.hostname_address = 1;
				break;

			default: 
				break;
			};
		}
		break;

	case SCTP_PARAM_STATE_COOKIE:
		asoc->peer.cookie_len = ntohs(param.p->length) - sizeof(sctp_paramhdr_t);
		asoc->peer.cookie = param.cookie->body;
		break;

	case SCTP_PARAM_HEARTBEAT_INFO:
		
		break;

	case SCTP_PARAM_UNRECOGNIZED_PARAMETERS:
		
		break;

	case SCTP_PARAM_ECN_CAPABLE:
		asoc->peer.ecn_capable = 1;
		break;

	case SCTP_PARAM_ADAPTION_LAYER_IND:
		asoc->peer.adaption_ind = param.aind->adaption_ind;
		break;

	case SCTP_PARAM_FWD_TSN_SUPPORT:
		if (sctp_prsctp_enable) {
			asoc->peer.prsctp_capable = 1;
			break;
		}
		 
	default:
		
		SCTP_DEBUG_PRINTK("Ignoring param: %d for association %p.\n", ntohs(param.p->type), asoc);
		break;
	};

	return retval;
}


__u32 sctp_generate_tag(const struct sctp_endpoint *ep)
{
	
	__u32 x;

	do {
		get_random_bytes(&x, sizeof(__u32));
	} while (x == 0);

	return x;
}


__u32 sctp_generate_tsn(const struct sctp_endpoint *ep)
{
	__u32 retval;

	get_random_bytes(&retval, sizeof(__u32));
	return retval;
}


static struct sctp_chunk *sctp_make_asconf(struct sctp_association *asoc, union sctp_addr *addr, int vparam_len)

{
	sctp_addiphdr_t asconf;
	struct sctp_chunk *retval;
	int length = sizeof(asconf) + vparam_len;
	union sctp_addr_param addrparam;
	int addrlen;
	struct sctp_af *af = sctp_get_af_specific(addr->v4.sin_family);

	addrlen = af->to_addr_param(addr, &addrparam);
	if (!addrlen)
		return NULL;
	length += addrlen;

	
	retval = sctp_make_chunk(asoc, SCTP_CID_ASCONF, 0, length);
	if (!retval)
		return NULL;

	asconf.serial = htonl(asoc->addip_serial++);

	retval->subh.addip_hdr = sctp_addto_chunk(retval, sizeof(asconf), &asconf);
	retval->param_hdr.v = sctp_addto_chunk(retval, addrlen, &addrparam);

	return retval;
}


struct sctp_chunk *sctp_make_asconf_update_ip(struct sctp_association *asoc, union sctp_addr	      *laddr, struct sockaddr	      *addrs, int		      addrcnt, __u16		      flags)



{
	sctp_addip_param_t	param;
	struct sctp_chunk	*retval;
	union sctp_addr_param	addr_param;
	union sctp_addr		*addr;
	void			*addr_buf;
	struct sctp_af		*af;
	int			paramlen = sizeof(param);
	int			addr_param_len = 0;
	int 			totallen = 0;
	int 			i;

	
	addr_buf = addrs;
	for (i = 0; i < addrcnt; i++) {
		addr = (union sctp_addr *)addr_buf;
		af = sctp_get_af_specific(addr->v4.sin_family);
		addr_param_len = af->to_addr_param(addr, &addr_param);

		totallen += paramlen;
		totallen += addr_param_len;

		addr_buf += af->sockaddr_len;
	}

	
	retval = sctp_make_asconf(asoc, laddr, totallen);
	if (!retval)
		return NULL;

	
	addr_buf = addrs;
	for (i = 0; i < addrcnt; i++) {
		addr = (union sctp_addr *)addr_buf;
		af = sctp_get_af_specific(addr->v4.sin_family);
		addr_param_len = af->to_addr_param(addr, &addr_param);
		param.param_hdr.type = flags;
		param.param_hdr.length = htons(paramlen + addr_param_len);
		param.crr_id = i;

		sctp_addto_chunk(retval, paramlen, &param);
		sctp_addto_chunk(retval, addr_param_len, &addr_param);

		addr_buf += af->sockaddr_len;
	}
	return retval;
}


struct sctp_chunk *sctp_make_asconf_set_prim(struct sctp_association *asoc, union sctp_addr *addr)
{
	sctp_addip_param_t	param;
	struct sctp_chunk 	*retval;
	int 			len = sizeof(param);
	union sctp_addr_param	addrparam;
	int			addrlen;
	struct sctp_af		*af = sctp_get_af_specific(addr->v4.sin_family);

	addrlen = af->to_addr_param(addr, &addrparam);
	if (!addrlen)
		return NULL;
	len += addrlen;

	
	retval = sctp_make_asconf(asoc, addr, len);
	if (!retval)
		return NULL;

	param.param_hdr.type = SCTP_PARAM_SET_PRIMARY;
	param.param_hdr.length = htons(len);
	param.crr_id = 0;

	sctp_addto_chunk(retval, sizeof(param), &param);
	sctp_addto_chunk(retval, addrlen, &addrparam);

	return retval;
}


static struct sctp_chunk *sctp_make_asconf_ack(const struct sctp_association *asoc, __u32 serial, int vparam_len)
{
	sctp_addiphdr_t		asconf;
	struct sctp_chunk	*retval;
	int			length = sizeof(asconf) + vparam_len;

	
	retval = sctp_make_chunk(asoc, SCTP_CID_ASCONF_ACK, 0, length);
	if (!retval)
		return NULL;

	asconf.serial = htonl(serial);

	retval->subh.addip_hdr = sctp_addto_chunk(retval, sizeof(asconf), &asconf);

	return retval;
}


static void sctp_add_asconf_response(struct sctp_chunk *chunk, __u32 crr_id, __u16 err_code, sctp_addip_param_t *asconf_param)
{
	sctp_addip_param_t 	ack_param;
	sctp_errhdr_t		err_param;
	int			asconf_param_len = 0;
	int			err_param_len = 0;
	__u16			response_type;

	if (SCTP_ERROR_NO_ERROR == err_code) {
		response_type = SCTP_PARAM_SUCCESS_REPORT;
	} else {
		response_type = SCTP_PARAM_ERR_CAUSE;
		err_param_len = sizeof(err_param);
		if (asconf_param)
			asconf_param_len = ntohs(asconf_param->param_hdr.length);
	}

	 
	ack_param.param_hdr.type = response_type;
	ack_param.param_hdr.length = htons(sizeof(ack_param) + err_param_len + asconf_param_len);

	ack_param.crr_id = crr_id;
	sctp_addto_chunk(chunk, sizeof(ack_param), &ack_param);

	if (SCTP_ERROR_NO_ERROR == err_code)
		return;

	
	err_param.cause = err_code;
	err_param.length = htons(err_param_len + asconf_param_len);
	sctp_addto_chunk(chunk, err_param_len, &err_param);

	
	if (asconf_param)
		sctp_addto_chunk(chunk, asconf_param_len, asconf_param);
}


static __u16 sctp_process_asconf_param(struct sctp_association *asoc, struct sctp_chunk *asconf, sctp_addip_param_t *asconf_param)

{
	struct sctp_transport *peer;
	struct sctp_af *af;
	union sctp_addr	addr;
	struct list_head *pos;
	union sctp_addr_param *addr_param;
				 
	addr_param = (union sctp_addr_param *)
			((void *)asconf_param + sizeof(sctp_addip_param_t));

	af = sctp_get_af_specific(param_type2af(addr_param->v4.param_hdr.type));
	if (unlikely(!af))
		return SCTP_ERROR_INV_PARAM;

	af->from_addr_param(&addr, addr_param, asoc->peer.port, 0);
	switch (asconf_param->param_hdr.type) {
	case SCTP_PARAM_ADD_IP:
		

		peer = sctp_assoc_add_peer(asoc, &addr, GFP_ATOMIC, SCTP_UNCONFIRMED);
		if (!peer)
			return SCTP_ERROR_RSRC_LOW;

		
		if (!mod_timer(&peer->hb_timer, sctp_transport_timeout(peer)))
			sctp_transport_hold(peer);
		break;
	case SCTP_PARAM_DEL_IP:
		
		pos = asoc->peer.transport_addr_list.next;
		if (pos->next == &asoc->peer.transport_addr_list)
			return SCTP_ERROR_DEL_LAST_IP;

		
		if (sctp_cmp_addr_exact(sctp_source(asconf), &addr))
			return SCTP_ERROR_DEL_SRC_IP;

		sctp_assoc_del_peer(asoc, &addr);
		break;
	case SCTP_PARAM_SET_PRIMARY:
		peer = sctp_assoc_lookup_paddr(asoc, &addr);
		if (!peer)
			return SCTP_ERROR_INV_PARAM;

		sctp_assoc_set_primary(asoc, peer);
		break;
	default:
		return SCTP_ERROR_INV_PARAM;
		break;
	}

	return SCTP_ERROR_NO_ERROR;
}


struct sctp_chunk *sctp_process_asconf(struct sctp_association *asoc, struct sctp_chunk *asconf)
{
	sctp_addiphdr_t		*hdr;
	union sctp_addr_param	*addr_param;
	sctp_addip_param_t	*asconf_param;
	struct sctp_chunk	*asconf_ack;

	__u16	err_code;
	int	length = 0;
	int	chunk_len = asconf->skb->len;
	__u32	serial;
	int	all_param_pass = 1;

	hdr = (sctp_addiphdr_t *)asconf->skb->data;
	serial = ntohl(hdr->serial);

	 
	length = sizeof(sctp_addiphdr_t);
	addr_param = (union sctp_addr_param *)(asconf->skb->data + length);
	chunk_len -= length;

	 
	length = ntohs(addr_param->v4.param_hdr.length);
	asconf_param = (sctp_addip_param_t *)((void *)addr_param + length);
	chunk_len -= length;

	
	asconf_ack = sctp_make_asconf_ack(asoc, serial, chunk_len * 2);
	if (!asconf_ack)
		goto done;

	
	while (chunk_len > 0) {
		err_code = sctp_process_asconf_param(asoc, asconf, asconf_param);
		
		if (SCTP_ERROR_NO_ERROR != err_code)
			all_param_pass = 0;

		if (!all_param_pass)
			sctp_add_asconf_response(asconf_ack, asconf_param->crr_id, err_code, asconf_param);


		
		if (SCTP_ERROR_RSRC_LOW == err_code)
			goto done;

		
		length = ntohs(asconf_param->param_hdr.length);
		asconf_param = (sctp_addip_param_t *)((void *)asconf_param + length);
		chunk_len -= length;
	}
	
done:
	asoc->peer.addip_serial++;

	
	if (asconf_ack) {
		if (asoc->addip_last_asconf_ack)
			sctp_chunk_free(asoc->addip_last_asconf_ack);

		sctp_chunk_hold(asconf_ack);
		asoc->addip_last_asconf_ack = asconf_ack;
	}

	return asconf_ack;
}


static int sctp_asconf_param_success(struct sctp_association *asoc, sctp_addip_param_t *asconf_param)
{
	struct sctp_af *af;
	union sctp_addr	addr;
	struct sctp_bind_addr *bp = &asoc->base.bind_addr;
	union sctp_addr_param *addr_param;
	struct list_head *pos;
	struct sctp_transport *transport;
	struct sctp_sockaddr_entry *saddr;
	int retval = 0;

	addr_param = (union sctp_addr_param *)
			((void *)asconf_param + sizeof(sctp_addip_param_t));

	
	af = sctp_get_af_specific(param_type2af(addr_param->v4.param_hdr.type));
	af->from_addr_param(&addr, addr_param, bp->port, 0);

	switch (asconf_param->param_hdr.type) {
	case SCTP_PARAM_ADD_IP:
		sctp_local_bh_disable();
		sctp_write_lock(&asoc->base.addr_lock);
		list_for_each(pos, &bp->address_list) {
			saddr = list_entry(pos, struct sctp_sockaddr_entry, list);
			if (sctp_cmp_addr_exact(&saddr->a, &addr))
				saddr->use_as_src = 1;
		}
		sctp_write_unlock(&asoc->base.addr_lock);
		sctp_local_bh_enable();
		break;
	case SCTP_PARAM_DEL_IP:
		sctp_local_bh_disable();
		sctp_write_lock(&asoc->base.addr_lock);
		retval = sctp_del_bind_addr(bp, &addr);
		sctp_write_unlock(&asoc->base.addr_lock);
		sctp_local_bh_enable();
		list_for_each(pos, &asoc->peer.transport_addr_list) {
			transport = list_entry(pos, struct sctp_transport, transports);
			dst_release(transport->dst);
			sctp_transport_route(transport, NULL, sctp_sk(asoc->base.sk));
		}
		break;
	default:
		break;
	}

	return retval;
}


static __u16 sctp_get_asconf_response(struct sctp_chunk *asconf_ack, sctp_addip_param_t *asconf_param, int no_err)

{
	sctp_addip_param_t	*asconf_ack_param;
	sctp_errhdr_t		*err_param;
	int			length;
	int			asconf_ack_len = asconf_ack->skb->len;
	__u16			err_code;

	if (no_err)
		err_code = SCTP_ERROR_NO_ERROR;
	else err_code = SCTP_ERROR_REQ_REFUSED;

	 
	length = sizeof(sctp_addiphdr_t);
	asconf_ack_param = (sctp_addip_param_t *)(asconf_ack->skb->data + length);
	asconf_ack_len -= length;

	while (asconf_ack_len > 0) {
		if (asconf_ack_param->crr_id == asconf_param->crr_id) {
			switch(asconf_ack_param->param_hdr.type) {
			case SCTP_PARAM_SUCCESS_REPORT:
				return SCTP_ERROR_NO_ERROR;
			case SCTP_PARAM_ERR_CAUSE:
				length = sizeof(sctp_addip_param_t);
				err_param = (sctp_errhdr_t *)
					   ((void *)asconf_ack_param + length);
				asconf_ack_len -= length;
				if (asconf_ack_len > 0)
					return err_param->cause;
				else return SCTP_ERROR_INV_PARAM;
				break;
			default:
				return SCTP_ERROR_INV_PARAM;
			}
		}

		length = ntohs(asconf_ack_param->param_hdr.length);
		asconf_ack_param = (sctp_addip_param_t *)
					((void *)asconf_ack_param + length);
		asconf_ack_len -= length;
	}

	return err_code;
}


int sctp_process_asconf_ack(struct sctp_association *asoc, struct sctp_chunk *asconf_ack)
{
	struct sctp_chunk	*asconf = asoc->addip_last_asconf;
	union sctp_addr_param	*addr_param;
	sctp_addip_param_t	*asconf_param;
	int	length = 0;
	int	asconf_len = asconf->skb->len;
	int	all_param_pass = 0;
	int	no_err = 1;
	int	retval = 0;
	__u16	err_code = SCTP_ERROR_NO_ERROR;

	 
	length = sizeof(sctp_addip_chunk_t);
	addr_param = (union sctp_addr_param *)(asconf->skb->data + length);
	asconf_len -= length;

	 
	length = ntohs(addr_param->v4.param_hdr.length);
	asconf_param = (sctp_addip_param_t *)((void *)addr_param + length);
	asconf_len -= length;

	
	if (asconf_ack->skb->len == sizeof(sctp_addiphdr_t))
		all_param_pass = 1;

	
	while (asconf_len > 0) {
		if (all_param_pass)
			err_code = SCTP_ERROR_NO_ERROR;
		else {
			err_code = sctp_get_asconf_response(asconf_ack, asconf_param, no_err);

			if (no_err && (SCTP_ERROR_NO_ERROR != err_code))
				no_err = 0;
		}

		switch (err_code) {
		case SCTP_ERROR_NO_ERROR:
			retval = sctp_asconf_param_success(asoc, asconf_param);
			break;

		case SCTP_ERROR_RSRC_LOW:
			retval = 1;
			break;

		case SCTP_ERROR_INV_PARAM:
				
			asoc->peer.addip_disabled_mask |= asconf_param->param_hdr.type;
			break;

		case SCTP_ERROR_REQ_REFUSED:
		case SCTP_ERROR_DEL_LAST_IP:
		case SCTP_ERROR_DEL_SRC_IP:
		default:
			 break;
		}

		 
		length = ntohs(asconf_param->param_hdr.length);
		asconf_param = (sctp_addip_param_t *)((void *)asconf_param + length);
		asconf_len -= length;
	}

	
	sctp_chunk_free(asconf);
	asoc->addip_last_asconf = NULL;

	
	if (!list_empty(&asoc->addip_chunk_list)) {
		struct list_head *entry = asoc->addip_chunk_list.next;
		asconf = list_entry(entry, struct sctp_chunk, list);

		list_del_init(entry);

		
		sctp_chunk_hold(asconf);
		if (sctp_primitive_ASCONF(asoc, asconf))
			sctp_chunk_free(asconf);
		else asoc->addip_last_asconf = asconf;
	}

	return retval;
}

 
struct sctp_chunk *sctp_make_fwdtsn(const struct sctp_association *asoc, __u32 new_cum_tsn, size_t nstreams, struct sctp_fwdtsn_skip *skiplist)

{
	struct sctp_chunk *retval = NULL;
	struct sctp_fwdtsn_chunk *ftsn_chunk;
	struct sctp_fwdtsn_hdr ftsn_hdr; 
	struct sctp_fwdtsn_skip skip;
	size_t hint;
	int i;

	hint = (nstreams + 1) * sizeof(__u32);

	retval = sctp_make_chunk(asoc, SCTP_CID_FWD_TSN, 0, hint);

	if (!retval)
		return NULL;

	ftsn_chunk = (struct sctp_fwdtsn_chunk *)retval->subh.fwdtsn_hdr;

	ftsn_hdr.new_cum_tsn = htonl(new_cum_tsn);
	retval->subh.fwdtsn_hdr = sctp_addto_chunk(retval, sizeof(ftsn_hdr), &ftsn_hdr);

	for (i = 0; i < nstreams; i++) {
		skip.stream = skiplist[i].stream;
		skip.ssn = skiplist[i].ssn;
		sctp_addto_chunk(retval, sizeof(skip), &skip);
	}

	return retval;
}
