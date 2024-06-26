














static struct sctp_packet *sctp_abort_pkt_new(const struct sctp_endpoint *ep, const struct sctp_association *asoc, struct sctp_chunk *chunk, const void *payload, size_t paylen);



static int sctp_eat_data(const struct sctp_association *asoc, struct sctp_chunk *chunk, sctp_cmd_seq_t *commands);

static struct sctp_packet *sctp_ootb_pkt_new(const struct sctp_association *asoc, const struct sctp_chunk *chunk);
static void sctp_send_stale_cookie_err(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const struct sctp_chunk *chunk, sctp_cmd_seq_t *commands, struct sctp_chunk *err_chunk);



static sctp_disposition_t sctp_sf_do_5_2_6_stale(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands);



static sctp_disposition_t sctp_sf_shut_8_4_5(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands);



static struct sctp_sackhdr *sctp_sm_pull_sack(struct sctp_chunk *chunk);

static sctp_disposition_t sctp_stop_t1_and_abort(sctp_cmd_seq_t *commands, __u16 error, int sk_err, const struct sctp_association *asoc, struct sctp_transport *transport);



static sctp_disposition_t sctp_sf_violation_chunklen( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands);






static inline int sctp_chunk_length_valid(struct sctp_chunk *chunk, __u16 required_length)

{
	__u16 chunk_length = ntohs(chunk->chunk_hdr->length);

	if (unlikely(chunk_length < required_length))
		return 0;

	return 1;
}




sctp_disposition_t sctp_sf_do_4_C(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	struct sctp_ulpevent *ev;

	
	if (!chunk->singleton)
		return SCTP_DISPOSITION_VIOLATION;

	if (!sctp_vtag_verify_either(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	ev = sctp_ulpevent_make_assoc_change(asoc, 0, SCTP_SHUTDOWN_COMP, 0, 0, 0, GFP_ATOMIC);
	if (!ev)
		goto nomem;

	sctp_add_cmd_sf(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T2_SHUTDOWN));

	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T5_SHUTDOWN_GUARD));

	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_CLOSED));

	SCTP_INC_STATS(SCTP_MIB_SHUTDOWNS);
	SCTP_DEC_STATS(SCTP_MIB_CURRESTAB);

	sctp_add_cmd_sf(commands, SCTP_CMD_DELETE_TCB, SCTP_NULL());

	return SCTP_DISPOSITION_DELETE_TCB;

nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_do_5_1B_init(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	struct sctp_chunk *repl;
	struct sctp_association *new_asoc;
	struct sctp_chunk *err_chunk;
	struct sctp_packet *packet;
	sctp_unrecognized_param_t *unk_param;
	struct sock *sk;
	int len;

	
	if (!chunk->singleton)
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (ep == sctp_sk((sctp_get_ctl_sock()))->ep)
		return sctp_sf_tabort_8_4_8(ep, asoc, type, arg, commands);

	sk = ep->base.sk;
	
	if (!sctp_sstate(sk, LISTENING) || (sctp_style(sk, TCP) && sk_acceptq_is_full(sk)))

		return sctp_sf_tabort_8_4_8(ep, asoc, type, arg, commands);

	
	if (chunk->sctp_hdr->vtag != 0)
		return sctp_sf_tabort_8_4_8(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_init_chunk_t)))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	err_chunk = NULL;
	if (!sctp_verify_init(asoc, chunk->chunk_hdr->type, (sctp_init_chunk_t *)chunk->chunk_hdr, chunk, &err_chunk)) {

		
		if (err_chunk) {
			packet = sctp_abort_pkt_new(ep, asoc, arg, (__u8 *)(err_chunk->chunk_hdr) + sizeof(sctp_chunkhdr_t), ntohs(err_chunk->chunk_hdr->length) - sizeof(sctp_chunkhdr_t));




			sctp_chunk_free(err_chunk);

			if (packet) {
				sctp_add_cmd_sf(commands, SCTP_CMD_SEND_PKT, SCTP_PACKET(packet));
				SCTP_INC_STATS(SCTP_MIB_OUTCTRLCHUNKS);
				return SCTP_DISPOSITION_CONSUME;
			} else {
				return SCTP_DISPOSITION_NOMEM;
			}
		} else {
			return sctp_sf_tabort_8_4_8(ep, asoc, type, arg, commands);
		}
	}

        
	chunk->subh.init_hdr = (sctp_inithdr_t *)chunk->skb->data;

	
	chunk->param_hdr.v = skb_pull(chunk->skb, sizeof(sctp_inithdr_t));

	new_asoc = sctp_make_temp_asoc(ep, chunk, GFP_ATOMIC);
	if (!new_asoc)
		goto nomem;

	
	if (!sctp_process_init(new_asoc, chunk->chunk_hdr->type, sctp_source(chunk), (sctp_init_chunk_t *)chunk->chunk_hdr, GFP_ATOMIC))


		goto nomem_init;

	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_ASOC, SCTP_ASOC(new_asoc));

	

	
	len = 0;
	if (err_chunk)
		len = ntohs(err_chunk->chunk_hdr->length) - sizeof(sctp_chunkhdr_t);

	if (sctp_assoc_set_bind_addr_from_ep(new_asoc, GFP_ATOMIC) < 0)
		goto nomem_ack;

	repl = sctp_make_init_ack(new_asoc, chunk, GFP_ATOMIC, len);
	if (!repl)
		goto nomem_ack;

	
	if (err_chunk) {
		
		unk_param = (sctp_unrecognized_param_t *)
			    ((__u8 *)(err_chunk->chunk_hdr) + sizeof(sctp_chunkhdr_t));
		
		sctp_addto_chunk(repl, len, unk_param);
		sctp_chunk_free(err_chunk);
	}

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(repl));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_DELETE_TCB, SCTP_NULL());

	return SCTP_DISPOSITION_DELETE_TCB;

nomem_ack:
	if (err_chunk)
		sctp_chunk_free(err_chunk);
nomem_init:
	sctp_association_free(new_asoc);
nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_do_5_1C_ack(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	sctp_init_chunk_t *initchunk;
	__u32 init_tag;
	struct sctp_chunk *err_chunk;
	struct sctp_packet *packet;
	__u16 error;

	if (!sctp_vtag_verify(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_initack_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);
	
	if (!chunk->singleton)
		return SCTP_DISPOSITION_VIOLATION;

	
	chunk->subh.init_hdr = (sctp_inithdr_t *) chunk->skb->data;

	init_tag = ntohl(chunk->subh.init_hdr->init_tag);

	
	if (!init_tag) {
		struct sctp_chunk *reply = sctp_make_abort(asoc, chunk, 0);
		if (!reply)
			goto nomem;

		sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(reply));
		return sctp_stop_t1_and_abort(commands, SCTP_ERROR_INV_PARAM, ECONNREFUSED, asoc, chunk->transport);

	}

	
	err_chunk = NULL;
	if (!sctp_verify_init(asoc, chunk->chunk_hdr->type, (sctp_init_chunk_t *)chunk->chunk_hdr, chunk, &err_chunk)) {


		SCTP_INC_STATS(SCTP_MIB_ABORTEDS);

		
		if (err_chunk) {
			packet = sctp_abort_pkt_new(ep, asoc, arg, (__u8 *)(err_chunk->chunk_hdr) + sizeof(sctp_chunkhdr_t), ntohs(err_chunk->chunk_hdr->length) - sizeof(sctp_chunkhdr_t));




			sctp_chunk_free(err_chunk);

			if (packet) {
				sctp_add_cmd_sf(commands, SCTP_CMD_SEND_PKT, SCTP_PACKET(packet));
				SCTP_INC_STATS(SCTP_MIB_OUTCTRLCHUNKS);
				error = SCTP_ERROR_INV_PARAM;
			} else {
				error = SCTP_ERROR_NO_RESOURCE;
			}
		} else {
			sctp_sf_tabort_8_4_8(ep, asoc, type, arg, commands);
			error = SCTP_ERROR_INV_PARAM;
		}
		return sctp_stop_t1_and_abort(commands, error, ECONNREFUSED, asoc, chunk->transport);
	}

	
	chunk->param_hdr.v = skb_pull(chunk->skb, sizeof(sctp_inithdr_t));

	initchunk = (sctp_init_chunk_t *) chunk->chunk_hdr;

	sctp_add_cmd_sf(commands, SCTP_CMD_PEER_INIT, SCTP_PEER_INIT(initchunk));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_INIT_COUNTER_RESET, SCTP_NULL());

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_INIT));
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_START, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_COOKIE));
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_COOKIE_ECHOED));

	
	
	sctp_add_cmd_sf(commands, SCTP_CMD_GEN_COOKIE_ECHO, SCTP_CHUNK(err_chunk));

	return SCTP_DISPOSITION_CONSUME;

nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_do_5_1D_ce(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)


{
	struct sctp_chunk *chunk = arg;
	struct sctp_association *new_asoc;
	sctp_init_chunk_t *peer_init;
	struct sctp_chunk *repl;
	struct sctp_ulpevent *ev;
	int error = 0;
	struct sctp_chunk *err_chk_p;

	
	if (ep == sctp_sk((sctp_get_ctl_sock()))->ep)
		return sctp_sf_ootb(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_chunkhdr_t)))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
        chunk->subh.cookie_hdr = (struct sctp_signed_cookie *)chunk->skb->data;
	if (!pskb_pull(chunk->skb, ntohs(chunk->chunk_hdr->length) - sizeof(sctp_chunkhdr_t)))
		goto nomem;

	
	new_asoc = sctp_unpack_cookie(ep, asoc, chunk, GFP_ATOMIC, &error, &err_chk_p);

	
	if (!new_asoc) {
		
		switch (error) {
		case -SCTP_IERROR_NOMEM:
			goto nomem;

		case -SCTP_IERROR_STALE_COOKIE:
			sctp_send_stale_cookie_err(ep, asoc, chunk, commands, err_chk_p);
			return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

		case -SCTP_IERROR_BAD_SIG:
		default:
			return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
		};
	}

	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_ASOC, SCTP_ASOC(new_asoc));
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_ESTABLISHED));
	SCTP_INC_STATS(SCTP_MIB_CURRESTAB);
	SCTP_INC_STATS(SCTP_MIB_PASSIVEESTABS);
	sctp_add_cmd_sf(commands, SCTP_CMD_HB_TIMERS_START, SCTP_NULL());

	if (new_asoc->autoclose)
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_START, SCTP_TO(SCTP_EVENT_TIMEOUT_AUTOCLOSE));

	sctp_add_cmd_sf(commands, SCTP_CMD_TRANSMIT, SCTP_NULL());

	
	
	peer_init = &chunk->subh.cookie_hdr->c.peer_init[0];

	if (!sctp_process_init(new_asoc, chunk->chunk_hdr->type, &chunk->subh.cookie_hdr->c.peer_addr, peer_init, GFP_ATOMIC))

		goto nomem_init;

	repl = sctp_make_cookie_ack(new_asoc, chunk);
	if (!repl)
		goto nomem_repl;

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(repl));

	
	ev = sctp_ulpevent_make_assoc_change(new_asoc, 0, SCTP_COMM_UP, 0, new_asoc->c.sinit_num_ostreams, new_asoc->c.sinit_max_instreams, GFP_ATOMIC);


	if (!ev)
		goto nomem_ev;

	sctp_add_cmd_sf(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev));

	
	if (new_asoc->peer.adaption_ind) {
		ev = sctp_ulpevent_make_adaption_indication(new_asoc, GFP_ATOMIC);
		if (!ev)
			goto nomem_ev;

		sctp_add_cmd_sf(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev));
	}

	return SCTP_DISPOSITION_CONSUME;

nomem_ev:
	sctp_chunk_free(repl);
nomem_repl:
nomem_init:
	sctp_association_free(new_asoc);
nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_do_5_1E_ca(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)


{
	struct sctp_chunk *chunk = arg;
	struct sctp_ulpevent *ev;

	if (!sctp_vtag_verify(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_chunkhdr_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	
	sctp_add_cmd_sf(commands, SCTP_CMD_INIT_COUNTER_RESET, SCTP_NULL());

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_COOKIE));
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_ESTABLISHED));
	SCTP_INC_STATS(SCTP_MIB_CURRESTAB);
	SCTP_INC_STATS(SCTP_MIB_ACTIVEESTABS);
	sctp_add_cmd_sf(commands, SCTP_CMD_HB_TIMERS_START, SCTP_NULL());
	if (asoc->autoclose)
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_START, SCTP_TO(SCTP_EVENT_TIMEOUT_AUTOCLOSE));
	sctp_add_cmd_sf(commands, SCTP_CMD_TRANSMIT, SCTP_NULL());

	
	ev = sctp_ulpevent_make_assoc_change(asoc, 0, SCTP_COMM_UP, 0, asoc->c.sinit_num_ostreams, asoc->c.sinit_max_instreams, GFP_ATOMIC);



	if (!ev)
		goto nomem;

	sctp_add_cmd_sf(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev));

	
	if (asoc->peer.adaption_ind) {
		ev = sctp_ulpevent_make_adaption_indication(asoc, GFP_ATOMIC);
		if (!ev)
			goto nomem;

		sctp_add_cmd_sf(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev));
	}

	return SCTP_DISPOSITION_CONSUME;
nomem:
	return SCTP_DISPOSITION_NOMEM;
}


static sctp_disposition_t sctp_sf_heartbeat(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_transport *transport = (struct sctp_transport *) arg;
	struct sctp_chunk *reply;
	sctp_sender_hb_info_t hbinfo;
	size_t paylen = 0;

	hbinfo.param_hdr.type = SCTP_PARAM_HEARTBEAT_INFO;
	hbinfo.param_hdr.length = htons(sizeof(sctp_sender_hb_info_t));
	hbinfo.daddr = transport->ipaddr;
	hbinfo.sent_at = jiffies;
	hbinfo.hb_nonce = transport->hb_nonce;

	
	paylen = sizeof(sctp_sender_hb_info_t);
	reply = sctp_make_heartbeat(asoc, transport, &hbinfo, paylen);
	if (!reply)
		return SCTP_DISPOSITION_NOMEM;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_RTO_PENDING, SCTP_TRANSPORT(transport));

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(reply));
	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_sendbeat_8_3(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_transport *transport = (struct sctp_transport *) arg;

	if (asoc->overall_error_count >= asoc->max_retrans) {
		sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ETIMEDOUT));
		
		sctp_add_cmd_sf(commands, SCTP_CMD_ASSOC_FAILED, SCTP_U32(SCTP_ERROR_NO_ERROR));
		SCTP_INC_STATS(SCTP_MIB_ABORTEDS);
		SCTP_DEC_STATS(SCTP_MIB_CURRESTAB);
		return SCTP_DISPOSITION_DELETE_TCB;
	}

	

	if (transport->param_flags & SPP_HB_ENABLE) {
		if (SCTP_DISPOSITION_NOMEM == sctp_sf_heartbeat(ep, asoc, type, arg, commands))

			return SCTP_DISPOSITION_NOMEM;
		
		sctp_add_cmd_sf(commands, SCTP_CMD_TRANSPORT_RESET, SCTP_TRANSPORT(transport));
	}
	sctp_add_cmd_sf(commands, SCTP_CMD_HB_TIMER_UPDATE, SCTP_TRANSPORT(transport));

        return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_beat_8_3(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	struct sctp_chunk *reply;
	size_t paylen = 0;

	if (!sctp_vtag_verify(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_heartbeat_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	
	chunk->subh.hb_hdr = (sctp_heartbeathdr_t *) chunk->skb->data;
	paylen = ntohs(chunk->chunk_hdr->length) - sizeof(sctp_chunkhdr_t);
	if (!pskb_pull(chunk->skb, paylen))
		goto nomem;

	reply = sctp_make_heartbeat_ack(asoc, chunk, chunk->subh.hb_hdr, paylen);
	if (!reply)
		goto nomem;

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(reply));
	return SCTP_DISPOSITION_CONSUME;

nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_backbeat_8_3(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	union sctp_addr from_addr;
	struct sctp_transport *link;
	sctp_sender_hb_info_t *hbinfo;
	unsigned long max_interval;

	if (!sctp_vtag_verify(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_heartbeat_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	hbinfo = (sctp_sender_hb_info_t *) chunk->skb->data;
	
	if (ntohs(hbinfo->param_hdr.length) != sizeof(sctp_sender_hb_info_t)) {
		return SCTP_DISPOSITION_DISCARD;
	}

	from_addr = hbinfo->daddr;
	link = sctp_assoc_lookup_paddr(asoc, &from_addr);

	
	if (unlikely(!link)) {
		if (from_addr.sa.sa_family == AF_INET6) {
			printk(KERN_WARNING "%s association %p could not find address " NIP6_FMT "\n", __FUNCTION__, asoc, NIP6(from_addr.v6.sin6_addr));




		} else {
			printk(KERN_WARNING "%s association %p could not find address " NIPQUAD_FMT "\n", __FUNCTION__, asoc, NIPQUAD(from_addr.v4.sin_addr.s_addr));




		}
		return SCTP_DISPOSITION_DISCARD;
	}

	
	if (hbinfo->hb_nonce != link->hb_nonce)
		return SCTP_DISPOSITION_DISCARD;

	max_interval = link->hbinterval + link->rto;

	
	if (time_after(hbinfo->sent_at, jiffies) || time_after(jiffies, hbinfo->sent_at + max_interval)) {
		SCTP_DEBUG_PRINTK("%s: HEARTBEAT ACK with invalid timestamp" "received for transport: %p\n", __FUNCTION__, link);

		return SCTP_DISPOSITION_DISCARD;
	}

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TRANSPORT_ON, SCTP_TRANSPORT(link));

	return SCTP_DISPOSITION_CONSUME;
}


static int sctp_sf_send_restart_abort(union sctp_addr *ssa, struct sctp_chunk *init, sctp_cmd_seq_t *commands)

{
	int len;
	struct sctp_packet *pkt;
	union sctp_addr_param *addrparm;
	struct sctp_errhdr *errhdr;
	struct sctp_endpoint *ep;
	char buffer[sizeof(struct sctp_errhdr)+sizeof(union sctp_addr_param)];
	struct sctp_af *af = sctp_get_af_specific(ssa->v4.sin_family);

	
	errhdr = (struct sctp_errhdr *)buffer;
	addrparm = (union sctp_addr_param *)errhdr->variable;

	
	len = af->to_addr_param(ssa, addrparm);
	len += sizeof(sctp_errhdr_t);

	errhdr->cause = SCTP_ERROR_RESTART;
	errhdr->length = htons(len);

	
	ep = sctp_sk((sctp_get_ctl_sock()))->ep;

	
	pkt = sctp_abort_pkt_new(ep, NULL, init, errhdr, len);

	if (!pkt)
		goto out;
	sctp_add_cmd_sf(commands, SCTP_CMD_SEND_PKT, SCTP_PACKET(pkt));

	SCTP_INC_STATS(SCTP_MIB_OUTCTRLCHUNKS);

	
	sctp_add_cmd_sf(commands, SCTP_CMD_DISCARD_PACKET, SCTP_NULL());

out:
	
	return 0;
}


static int sctp_sf_check_restart_addrs(const struct sctp_association *new_asoc, const struct sctp_association *asoc, struct sctp_chunk *init, sctp_cmd_seq_t *commands)


{
	struct sctp_transport *new_addr, *addr;
	struct list_head *pos, *pos2;
	int found;

	

	
	new_addr = NULL;
	found = 0;

	list_for_each(pos, &new_asoc->peer.transport_addr_list) {
		new_addr = list_entry(pos, struct sctp_transport, transports);
		found = 0;
		list_for_each(pos2, &asoc->peer.transport_addr_list) {
			addr = list_entry(pos2, struct sctp_transport, transports);
			if (sctp_cmp_addr_exact(&new_addr->ipaddr, &addr->ipaddr)) {
				found = 1;
				break;
			}
		}
		if (!found)
			break;
	}

	
	if (!found && new_addr) {
		sctp_sf_send_restart_abort(&new_addr->ipaddr, init, commands);
	}

	
	return found;
}


static void sctp_tietags_populate(struct sctp_association *new_asoc, const struct sctp_association *asoc)
{
	switch (asoc->state) {

	

	case SCTP_STATE_COOKIE_WAIT:
		new_asoc->c.my_vtag     = asoc->c.my_vtag;
		new_asoc->c.my_ttag     = asoc->c.my_vtag;
		new_asoc->c.peer_ttag   = 0;
		break;

	case SCTP_STATE_COOKIE_ECHOED:
		new_asoc->c.my_vtag     = asoc->c.my_vtag;
		new_asoc->c.my_ttag     = asoc->c.my_vtag;
		new_asoc->c.peer_ttag   = asoc->c.peer_vtag;
		break;

	
	default:
		new_asoc->c.my_ttag   = asoc->c.my_vtag;
		new_asoc->c.peer_ttag = asoc->c.peer_vtag;
		break;
	};

	
	new_asoc->rwnd                  = asoc->rwnd;
	new_asoc->c.sinit_num_ostreams  = asoc->c.sinit_num_ostreams;
	new_asoc->c.sinit_max_instreams = asoc->c.sinit_max_instreams;
	new_asoc->c.initial_tsn         = asoc->c.initial_tsn;
}


static char sctp_tietags_compare(struct sctp_association *new_asoc, const struct sctp_association *asoc)
{
	
	if ((asoc->c.my_vtag != new_asoc->c.my_vtag) && (asoc->c.peer_vtag != new_asoc->c.peer_vtag) && (asoc->c.my_vtag == new_asoc->c.my_ttag) && (asoc->c.peer_vtag == new_asoc->c.peer_ttag))


		return 'A';

	
	if ((asoc->c.my_vtag == new_asoc->c.my_vtag) && ((asoc->c.peer_vtag != new_asoc->c.peer_vtag) || (0 == asoc->c.peer_vtag))) {

		return 'B';
	}

	
	if ((asoc->c.my_vtag == new_asoc->c.my_vtag) && (asoc->c.peer_vtag == new_asoc->c.peer_vtag))
		return 'D';

	
	if ((asoc->c.my_vtag != new_asoc->c.my_vtag) && (asoc->c.peer_vtag == new_asoc->c.peer_vtag) && (0 == new_asoc->c.my_ttag) && (0 == new_asoc->c.peer_ttag))


		return 'C';

	
	return 'E';
}


static sctp_disposition_t sctp_sf_do_unexpected_init( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	sctp_disposition_t retval;
	struct sctp_chunk *chunk = arg;
	struct sctp_chunk *repl;
	struct sctp_association *new_asoc;
	struct sctp_chunk *err_chunk;
	struct sctp_packet *packet;
	sctp_unrecognized_param_t *unk_param;
	int len;

	
	if (!chunk->singleton)
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (chunk->sctp_hdr->vtag != 0)
		return sctp_sf_tabort_8_4_8(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_init_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);
	
	chunk->subh.init_hdr = (sctp_inithdr_t *) chunk->skb->data;

	
	chunk->param_hdr.v = skb_pull(chunk->skb, sizeof(sctp_inithdr_t));

	
	err_chunk = NULL;
	if (!sctp_verify_init(asoc, chunk->chunk_hdr->type, (sctp_init_chunk_t *)chunk->chunk_hdr, chunk, &err_chunk)) {

		
		if (err_chunk) {
			packet = sctp_abort_pkt_new(ep, asoc, arg, (__u8 *)(err_chunk->chunk_hdr) + sizeof(sctp_chunkhdr_t), ntohs(err_chunk->chunk_hdr->length) - sizeof(sctp_chunkhdr_t));




			if (packet) {
				sctp_add_cmd_sf(commands, SCTP_CMD_SEND_PKT, SCTP_PACKET(packet));
				SCTP_INC_STATS(SCTP_MIB_OUTCTRLCHUNKS);
				retval = SCTP_DISPOSITION_CONSUME;
			} else {
				retval = SCTP_DISPOSITION_NOMEM;
			}
			goto cleanup;
		} else {
			return sctp_sf_tabort_8_4_8(ep, asoc, type, arg, commands);
		}
	}

	
	new_asoc = sctp_make_temp_asoc(ep, chunk, GFP_ATOMIC);
	if (!new_asoc)
		goto nomem;

	
	if (!sctp_process_init(new_asoc, chunk->chunk_hdr->type, sctp_source(chunk), (sctp_init_chunk_t *)chunk->chunk_hdr, GFP_ATOMIC)) {


		retval = SCTP_DISPOSITION_NOMEM;
		goto nomem_init;
	}

	
	if (!sctp_state(asoc, COOKIE_WAIT)) {
		if (!sctp_sf_check_restart_addrs(new_asoc, asoc, chunk, commands)) {
			retval = SCTP_DISPOSITION_CONSUME;
			goto cleanup_asoc;
		}
	}

	sctp_tietags_populate(new_asoc, asoc);

	

	
	len = 0;
	if (err_chunk) {
		len = ntohs(err_chunk->chunk_hdr->length) - sizeof(sctp_chunkhdr_t);
	}

	if (sctp_assoc_set_bind_addr_from_ep(new_asoc, GFP_ATOMIC) < 0)
		goto nomem;

	repl = sctp_make_init_ack(new_asoc, chunk, GFP_ATOMIC, len);
	if (!repl)
		goto nomem;

	
	if (err_chunk) {
		
		unk_param = (sctp_unrecognized_param_t *)
			    ((__u8 *)(err_chunk->chunk_hdr) + sizeof(sctp_chunkhdr_t));
		
		sctp_addto_chunk(repl, len, unk_param);
	}

	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_ASOC, SCTP_ASOC(new_asoc));
	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(repl));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_DELETE_TCB, SCTP_NULL());
	retval = SCTP_DISPOSITION_CONSUME;

cleanup:
	if (err_chunk)
		sctp_chunk_free(err_chunk);
	return retval;
nomem:
	retval = SCTP_DISPOSITION_NOMEM;
	goto cleanup;
nomem_init:
cleanup_asoc:
	sctp_association_free(new_asoc);
	goto cleanup;
}


sctp_disposition_t sctp_sf_do_5_2_1_siminit(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	
	return sctp_sf_do_unexpected_init(ep, asoc, type, arg, commands);
}


sctp_disposition_t sctp_sf_do_5_2_2_dupinit(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	
	return sctp_sf_do_unexpected_init(ep, asoc, type, arg, commands);
}




static sctp_disposition_t sctp_sf_do_dupcook_a(const struct sctp_endpoint *ep, const struct sctp_association *asoc, struct sctp_chunk *chunk, sctp_cmd_seq_t *commands, struct sctp_association *new_asoc)



{
	sctp_init_chunk_t *peer_init;
	struct sctp_ulpevent *ev;
	struct sctp_chunk *repl;
	struct sctp_chunk *err;
	sctp_disposition_t disposition;

	
	peer_init = &chunk->subh.cookie_hdr->c.peer_init[0];

	if (!sctp_process_init(new_asoc, chunk->chunk_hdr->type, sctp_source(chunk), peer_init, GFP_ATOMIC))

		goto nomem;

	
	if (!sctp_sf_check_restart_addrs(new_asoc, asoc, chunk, commands)) {
		return SCTP_DISPOSITION_CONSUME;
	}

	
	if (sctp_state(asoc, SHUTDOWN_ACK_SENT)) {
		disposition = sctp_sf_do_9_2_reshutack(ep, asoc, SCTP_ST_CHUNK(chunk->chunk_hdr->type), chunk, commands);

		if (SCTP_DISPOSITION_NOMEM == disposition)
			goto nomem;

		err = sctp_make_op_error(asoc, chunk, SCTP_ERROR_COOKIE_IN_SHUTDOWN, NULL, 0);

		if (err)
			sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(err));

		return SCTP_DISPOSITION_CONSUME;
	}

	
	sctp_add_cmd_sf(commands, SCTP_CMD_PURGE_OUTQUEUE, SCTP_NULL());

	
	sctp_add_cmd_sf(commands, SCTP_CMD_UPDATE_ASSOC, SCTP_ASOC(new_asoc));

	repl = sctp_make_cookie_ack(new_asoc, chunk);
	if (!repl)
		goto nomem;

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(repl));

	
	ev = sctp_ulpevent_make_assoc_change(asoc, 0, SCTP_RESTART, 0, new_asoc->c.sinit_num_ostreams, new_asoc->c.sinit_max_instreams, GFP_ATOMIC);


	if (!ev)
		goto nomem_ev;

	sctp_add_cmd_sf(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev));
	return SCTP_DISPOSITION_CONSUME;

nomem_ev:
	sctp_chunk_free(repl);
nomem:
	return SCTP_DISPOSITION_NOMEM;
}



static sctp_disposition_t sctp_sf_do_dupcook_b(const struct sctp_endpoint *ep, const struct sctp_association *asoc, struct sctp_chunk *chunk, sctp_cmd_seq_t *commands, struct sctp_association *new_asoc)



{
	sctp_init_chunk_t *peer_init;
	struct sctp_ulpevent *ev;
	struct sctp_chunk *repl;

	
	peer_init = &chunk->subh.cookie_hdr->c.peer_init[0];
	if (!sctp_process_init(new_asoc, chunk->chunk_hdr->type, sctp_source(chunk), peer_init, GFP_ATOMIC))

		goto nomem;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_UPDATE_ASSOC, SCTP_ASOC(new_asoc));
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_ESTABLISHED));
	SCTP_INC_STATS(SCTP_MIB_CURRESTAB);
	sctp_add_cmd_sf(commands, SCTP_CMD_HB_TIMERS_START, SCTP_NULL());

	repl = sctp_make_cookie_ack(new_asoc, chunk);
	if (!repl)
		goto nomem;

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(repl));
	sctp_add_cmd_sf(commands, SCTP_CMD_TRANSMIT, SCTP_NULL());

	
	ev = sctp_ulpevent_make_assoc_change(asoc, 0, SCTP_COMM_UP, 0, new_asoc->c.sinit_num_ostreams, new_asoc->c.sinit_max_instreams, GFP_ATOMIC);


	if (!ev)
		goto nomem_ev;

	sctp_add_cmd_sf(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev));

	
	if (asoc->peer.adaption_ind) {
		ev = sctp_ulpevent_make_adaption_indication(asoc, GFP_ATOMIC);
		if (!ev)
			goto nomem_ev;

		sctp_add_cmd_sf(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev));
	}

	return SCTP_DISPOSITION_CONSUME;

nomem_ev:
	sctp_chunk_free(repl);
nomem:
	return SCTP_DISPOSITION_NOMEM;
}



static sctp_disposition_t sctp_sf_do_dupcook_c(const struct sctp_endpoint *ep, const struct sctp_association *asoc, struct sctp_chunk *chunk, sctp_cmd_seq_t *commands, struct sctp_association *new_asoc)



{
	
	return SCTP_DISPOSITION_DISCARD;
}



static sctp_disposition_t sctp_sf_do_dupcook_d(const struct sctp_endpoint *ep, const struct sctp_association *asoc, struct sctp_chunk *chunk, sctp_cmd_seq_t *commands, struct sctp_association *new_asoc)



{
	struct sctp_ulpevent *ev = NULL;
	struct sctp_chunk *repl;

	

	
	if (asoc->state < SCTP_STATE_ESTABLISHED) {
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_COOKIE));
		sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_ESTABLISHED));
		SCTP_INC_STATS(SCTP_MIB_CURRESTAB);
		sctp_add_cmd_sf(commands, SCTP_CMD_HB_TIMERS_START, SCTP_NULL());

		
		ev = sctp_ulpevent_make_assoc_change(new_asoc, 0, SCTP_COMM_UP, 0, new_asoc->c.sinit_num_ostreams, new_asoc->c.sinit_max_instreams, GFP_ATOMIC);



		if (!ev)
			goto nomem;
		sctp_add_cmd_sf(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev));

		
		if (new_asoc->peer.adaption_ind) {
			ev = sctp_ulpevent_make_adaption_indication(new_asoc, GFP_ATOMIC);
			if (!ev)
				goto nomem;

			sctp_add_cmd_sf(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev));
		}
	}
	sctp_add_cmd_sf(commands, SCTP_CMD_TRANSMIT, SCTP_NULL());

	repl = sctp_make_cookie_ack(new_asoc, chunk);
	if (!repl)
		goto nomem;

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(repl));
	sctp_add_cmd_sf(commands, SCTP_CMD_TRANSMIT, SCTP_NULL());

	return SCTP_DISPOSITION_CONSUME;

nomem:
	if (ev)
		sctp_ulpevent_free(ev);
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_do_5_2_4_dupcook(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	sctp_disposition_t retval;
	struct sctp_chunk *chunk = arg;
	struct sctp_association *new_asoc;
	int error = 0;
	char action;
	struct sctp_chunk *err_chk_p;

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_chunkhdr_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	
        chunk->subh.cookie_hdr = (struct sctp_signed_cookie *)chunk->skb->data;
	if (!pskb_pull(chunk->skb, ntohs(chunk->chunk_hdr->length) - sizeof(sctp_chunkhdr_t)))
		goto nomem;

	
	new_asoc = sctp_unpack_cookie(ep, asoc, chunk, GFP_ATOMIC, &error, &err_chk_p);

	
	if (!new_asoc) {
		
		switch (error) {
		case -SCTP_IERROR_NOMEM:
			goto nomem;

		case -SCTP_IERROR_STALE_COOKIE:
			sctp_send_stale_cookie_err(ep, asoc, chunk, commands, err_chk_p);
			return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
		case -SCTP_IERROR_BAD_SIG:
		default:
			return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
		};
	}

	
	action = sctp_tietags_compare(new_asoc, asoc);

	switch (action) {
	case 'A': 
		retval = sctp_sf_do_dupcook_a(ep, asoc, chunk, commands, new_asoc);
		break;

	case 'B': 
		retval = sctp_sf_do_dupcook_b(ep, asoc, chunk, commands, new_asoc);
		break;

	case 'C': 
		retval = sctp_sf_do_dupcook_c(ep, asoc, chunk, commands, new_asoc);
		break;

	case 'D': 
		retval = sctp_sf_do_dupcook_d(ep, asoc, chunk, commands, new_asoc);
		break;

	default: 
		retval = sctp_sf_pdiscard(ep, asoc, type, arg, commands);
		break;
        };

	
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_ASOC, SCTP_ASOC(new_asoc));
	sctp_add_cmd_sf(commands, SCTP_CMD_DELETE_TCB, SCTP_NULL());

	return retval;

nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_shutdown_pending_abort( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	struct sctp_chunk *chunk = arg;

	if (!sctp_vtag_verify_either(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_abort_chunk_t)))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T5_SHUTDOWN_GUARD));

	return sctp_sf_do_9_1_abort(ep, asoc, type, arg, commands);
}


sctp_disposition_t sctp_sf_shutdown_sent_abort(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;

	if (!sctp_vtag_verify_either(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_abort_chunk_t)))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T2_SHUTDOWN));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T5_SHUTDOWN_GUARD));

	return sctp_sf_do_9_1_abort(ep, asoc, type, arg, commands);
}


sctp_disposition_t sctp_sf_shutdown_ack_sent_abort( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	
	return sctp_sf_shutdown_sent_abort(ep, asoc, type, arg, commands);
}


sctp_disposition_t sctp_sf_cookie_echoed_err(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	sctp_errhdr_t *err;

	if (!sctp_vtag_verify(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_operr_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	
	
	sctp_walk_errors(err, chunk->chunk_hdr) {
		if (SCTP_ERROR_STALE_COOKIE == err->cause)
			return sctp_sf_do_5_2_6_stale(ep, asoc, type,  arg, commands);
	}

	
	return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
}


static sctp_disposition_t sctp_sf_do_5_2_6_stale(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	time_t stale;
	sctp_cookie_preserve_param_t bht;
	sctp_errhdr_t *err;
	struct sctp_chunk *reply;
	struct sctp_bind_addr *bp;
	int attempts = asoc->init_err_counter + 1;

	if (attempts > asoc->max_init_attempts) {
		sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ETIMEDOUT));
		sctp_add_cmd_sf(commands, SCTP_CMD_INIT_FAILED, SCTP_U32(SCTP_ERROR_STALE_COOKIE));
		return SCTP_DISPOSITION_DELETE_TCB;
	}

	err = (sctp_errhdr_t *)(chunk->skb->data);

	
	stale = ntohl(*(suseconds_t *)((u8 *)err + sizeof(sctp_errhdr_t)));
	stale = (stale * 2) / 1000;

	bht.param_hdr.type = SCTP_PARAM_COOKIE_PRESERVATIVE;
	bht.param_hdr.length = htons(sizeof(bht));
	bht.lifespan_increment = htonl(stale);

	
	bp = (struct sctp_bind_addr *) &asoc->base.bind_addr;
	reply = sctp_make_init(asoc, bp, GFP_ATOMIC, sizeof(bht));
	if (!reply)
		goto nomem;

	sctp_addto_chunk(reply, sizeof(bht), &bht);

	
	sctp_add_cmd_sf(commands, SCTP_CMD_CLEAR_INIT_TAG, SCTP_NULL());

	
	sctp_add_cmd_sf(commands, SCTP_CMD_T3_RTX_TIMERS_STOP, SCTP_NULL());
	sctp_add_cmd_sf(commands, SCTP_CMD_HB_TIMERS_STOP, SCTP_NULL());

	
	sctp_add_cmd_sf(commands, SCTP_CMD_DEL_NON_PRIMARY, SCTP_NULL());

	
	sctp_add_cmd_sf(commands, SCTP_CMD_RETRAN,  SCTP_TRANSPORT(asoc->peer.primary_path));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_INIT_COUNTER_INC, SCTP_NULL());

	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_COOKIE));
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_COOKIE_WAIT));
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_START, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_INIT));

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(reply));

	return SCTP_DISPOSITION_CONSUME;

nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_do_9_1_abort(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	unsigned len;
	__u16 error = SCTP_ERROR_NO_ERROR;

	if (!sctp_vtag_verify_either(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_abort_chunk_t)))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	len = ntohs(chunk->chunk_hdr->length);
	if (len >= sizeof(struct sctp_chunkhdr) + sizeof(struct sctp_errhdr))
		error = ((sctp_errhdr_t *)chunk->skb->data)->cause;

	sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ECONNRESET));
 	
	sctp_add_cmd_sf(commands, SCTP_CMD_ASSOC_FAILED, SCTP_U32(error));
	SCTP_INC_STATS(SCTP_MIB_ABORTEDS);
	SCTP_DEC_STATS(SCTP_MIB_CURRESTAB);

	return SCTP_DISPOSITION_ABORT;
}


sctp_disposition_t sctp_sf_cookie_wait_abort(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	unsigned len;
	__u16 error = SCTP_ERROR_NO_ERROR;

	if (!sctp_vtag_verify_either(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_abort_chunk_t)))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	len = ntohs(chunk->chunk_hdr->length);
	if (len >= sizeof(struct sctp_chunkhdr) + sizeof(struct sctp_errhdr))
		error = ((sctp_errhdr_t *)chunk->skb->data)->cause;

	return sctp_stop_t1_and_abort(commands, error, ECONNREFUSED, asoc, chunk->transport);
}


sctp_disposition_t sctp_sf_cookie_wait_icmp_abort(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	return sctp_stop_t1_and_abort(commands, SCTP_ERROR_NO_ERROR, ENOPROTOOPT, asoc, (struct sctp_transport *)arg);

}


sctp_disposition_t sctp_sf_cookie_echoed_abort(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	
	return sctp_sf_cookie_wait_abort(ep, asoc, type, arg, commands);
}


static sctp_disposition_t sctp_stop_t1_and_abort(sctp_cmd_seq_t *commands, __u16 error, int sk_err, const struct sctp_association *asoc, struct sctp_transport *transport)


{
	SCTP_DEBUG_PRINTK("ABORT received (INIT).\n");
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_CLOSED));
	SCTP_INC_STATS(SCTP_MIB_ABORTEDS);
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_INIT));
	sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(sk_err));
	
	sctp_add_cmd_sf(commands, SCTP_CMD_INIT_FAILED, SCTP_U32(error));
	return SCTP_DISPOSITION_ABORT;
}


sctp_disposition_t sctp_sf_do_9_2_shutdown(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	sctp_shutdownhdr_t *sdh;
	sctp_disposition_t disposition;
	struct sctp_ulpevent *ev;

	if (!sctp_vtag_verify(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(struct sctp_shutdown_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	
	sdh = (sctp_shutdownhdr_t *)chunk->skb->data;
	skb_pull(chunk->skb, sizeof(sctp_shutdownhdr_t));
	chunk->subh.shutdown_hdr = sdh;

	
	ev = sctp_ulpevent_make_shutdown_event(asoc, 0, GFP_ATOMIC);
	if (!ev) {
		disposition = SCTP_DISPOSITION_NOMEM;
		goto out;	
	}
	sctp_add_cmd_sf(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_SHUTDOWN_RECEIVED));
	disposition = SCTP_DISPOSITION_CONSUME;

	if (sctp_outq_is_empty(&asoc->outqueue)) {
		disposition = sctp_sf_do_9_2_shutdown_ack(ep, asoc, type, arg, commands);
	}

	if (SCTP_DISPOSITION_NOMEM == disposition)
		goto out;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_PROCESS_CTSN, SCTP_U32(chunk->subh.shutdown_hdr->cum_tsn_ack));

out:
	return disposition;
}


sctp_disposition_t sctp_sf_do_9_2_reshutack(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = (struct sctp_chunk *) arg;
	struct sctp_chunk *reply;

	
	reply = sctp_make_shutdown_ack(asoc, chunk);
	if (NULL == reply)
		goto nomem;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_SETUP_T2, SCTP_CHUNK(reply));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_RESTART, SCTP_TO(SCTP_EVENT_TIMEOUT_T2_SHUTDOWN));

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(reply));

	return SCTP_DISPOSITION_CONSUME;
nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_do_ecn_cwr(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	sctp_cwrhdr_t *cwr;
	struct sctp_chunk *chunk = arg;

	if (!sctp_vtag_verify(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_ecne_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);
		
	cwr = (sctp_cwrhdr_t *) chunk->skb->data;
	skb_pull(chunk->skb, sizeof(sctp_cwrhdr_t));

	cwr->lowest_tsn = ntohl(cwr->lowest_tsn);

	
	if (TSN_lte(asoc->last_ecne_tsn, cwr->lowest_tsn)) {
		
		sctp_add_cmd_sf(commands, SCTP_CMD_ECN_CWR, SCTP_U32(cwr->lowest_tsn));

	}
	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_do_ecne(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	sctp_ecnehdr_t *ecne;
	struct sctp_chunk *chunk = arg;

	if (!sctp_vtag_verify(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_ecne_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	ecne = (sctp_ecnehdr_t *) chunk->skb->data;
	skb_pull(chunk->skb, sizeof(sctp_ecnehdr_t));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_ECN_ECNE, SCTP_U32(ntohl(ecne->lowest_tsn)));

	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_eat_data_6_2(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	int error;

	if (!sctp_vtag_verify(chunk, asoc)) {
		sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_BAD_TAG, SCTP_NULL());
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
        }

	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_data_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	error = sctp_eat_data(asoc, chunk, commands );
	switch (error) {
	case SCTP_IERROR_NO_ERROR:
		break;
	case SCTP_IERROR_HIGH_TSN:
	case SCTP_IERROR_BAD_STREAM:
		goto discard_noforce;
	case SCTP_IERROR_DUP_TSN:
	case SCTP_IERROR_IGNORE_TSN:
		goto discard_force;
	case SCTP_IERROR_NO_DATA:
		goto consume;
	default:
		BUG();
	}

	if (asoc->autoclose) {
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_RESTART, SCTP_TO(SCTP_EVENT_TIMEOUT_AUTOCLOSE));
	}

	
	if (chunk->end_of_packet)
		sctp_add_cmd_sf(commands, SCTP_CMD_GEN_SACK, SCTP_NOFORCE());

	return SCTP_DISPOSITION_CONSUME;

discard_force:
	
	
	if (chunk->end_of_packet)
		sctp_add_cmd_sf(commands, SCTP_CMD_GEN_SACK, SCTP_FORCE());
	return SCTP_DISPOSITION_DISCARD;

discard_noforce:
	if (chunk->end_of_packet)
		sctp_add_cmd_sf(commands, SCTP_CMD_GEN_SACK, SCTP_NOFORCE());

	return SCTP_DISPOSITION_DISCARD;
consume:
	return SCTP_DISPOSITION_CONSUME;
	
}


sctp_disposition_t sctp_sf_eat_data_fast_4_4(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	int error;

	if (!sctp_vtag_verify(chunk, asoc)) {
		sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_BAD_TAG, SCTP_NULL());
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
	}

	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_data_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	error = sctp_eat_data(asoc, chunk, commands );
	switch (error) {
	case SCTP_IERROR_NO_ERROR:
	case SCTP_IERROR_HIGH_TSN:
	case SCTP_IERROR_DUP_TSN:
	case SCTP_IERROR_IGNORE_TSN:
	case SCTP_IERROR_BAD_STREAM:
		break;
	case SCTP_IERROR_NO_DATA:
		goto consume;
	default:
		BUG();
	}

	

	
	if (chunk->end_of_packet) {
		
		sctp_add_cmd_sf(commands, SCTP_CMD_GEN_SHUTDOWN, SCTP_NULL());
		sctp_add_cmd_sf(commands, SCTP_CMD_GEN_SACK, SCTP_FORCE());
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_RESTART, SCTP_TO(SCTP_EVENT_TIMEOUT_T2_SHUTDOWN));
	}

consume:
	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_eat_sack_6_2(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	sctp_sackhdr_t *sackh;
	__u32 ctsn;

	if (!sctp_vtag_verify(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_sack_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	
	sackh = sctp_sm_pull_sack(chunk);
	
	if (!sackh)
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
	chunk->subh.sack_hdr = sackh;
	ctsn = ntohl(sackh->cum_tsn_ack);

	
	if (TSN_lt(ctsn, asoc->ctsn_ack_point)) {
		SCTP_DEBUG_PRINTK("ctsn %x\n", ctsn);
		SCTP_DEBUG_PRINTK("ctsn_ack_point %x\n", asoc->ctsn_ack_point);
		return SCTP_DISPOSITION_DISCARD;
	}

	
	sctp_add_cmd_sf(commands, SCTP_CMD_PROCESS_SACK, SCTP_SACKH(sackh));

	
	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_tabort_8_4_8(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_packet *packet = NULL;
	struct sctp_chunk *chunk = arg;
	struct sctp_chunk *abort;

	packet = sctp_ootb_pkt_new(asoc, chunk);

	if (packet) {
		
        	abort = sctp_make_abort(asoc, chunk, 0);
		if (!abort) {
			sctp_ootb_pkt_free(packet);
			return SCTP_DISPOSITION_NOMEM;
		}

		
		if (sctp_test_T_bit(abort))
			packet->vtag = ntohl(chunk->sctp_hdr->vtag);

		
		abort->skb->sk = ep->base.sk;

		sctp_packet_append_chunk(packet, abort);

		sctp_add_cmd_sf(commands, SCTP_CMD_SEND_PKT, SCTP_PACKET(packet));

		SCTP_INC_STATS(SCTP_MIB_OUTCTRLCHUNKS);

		return SCTP_DISPOSITION_CONSUME;
	}

	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_operr_notify(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	struct sctp_ulpevent *ev;

	if (!sctp_vtag_verify(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_operr_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	while (chunk->chunk_end > chunk->skb->data) {
		ev = sctp_ulpevent_make_remote_error(asoc, chunk, 0, GFP_ATOMIC);
		if (!ev)
			goto nomem;

		if (!sctp_add_cmd(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev))) {
			sctp_ulpevent_free(ev);
			goto nomem;
		}

		sctp_add_cmd_sf(commands, SCTP_CMD_PROCESS_OPERR, SCTP_CHUNK(chunk));
	}
	return SCTP_DISPOSITION_CONSUME;

nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_do_9_2_final(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	struct sctp_chunk *reply;
	struct sctp_ulpevent *ev;

	if (!sctp_vtag_verify(chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_chunkhdr_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	
	ev = sctp_ulpevent_make_assoc_change(asoc, 0, SCTP_SHUTDOWN_COMP, 0, 0, 0, GFP_ATOMIC);
	if (!ev)
		goto nomem;

	sctp_add_cmd_sf(commands, SCTP_CMD_EVENT_ULP, SCTP_ULPEVENT(ev));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T2_SHUTDOWN));

	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T5_SHUTDOWN_GUARD));

	
	reply = sctp_make_shutdown_complete(asoc, chunk);
	if (!reply)
		goto nomem;

	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_CLOSED));
	SCTP_INC_STATS(SCTP_MIB_SHUTDOWNS);
	SCTP_DEC_STATS(SCTP_MIB_CURRESTAB);
	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(reply));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_DELETE_TCB, SCTP_NULL());
	return SCTP_DISPOSITION_DELETE_TCB;

nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_ootb(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	struct sk_buff *skb = chunk->skb;
	sctp_chunkhdr_t *ch;
	__u8 *ch_end;
	int ootb_shut_ack = 0;

	SCTP_INC_STATS(SCTP_MIB_OUTOFBLUES);

	ch = (sctp_chunkhdr_t *) chunk->chunk_hdr;
	do {
		
		if (ntohs(ch->length) < sizeof(sctp_chunkhdr_t))
			break;

		ch_end = ((__u8 *)ch) + WORD_ROUND(ntohs(ch->length));
		if (ch_end > skb->tail)
			break;

		if (SCTP_CID_SHUTDOWN_ACK == ch->type)
			ootb_shut_ack = 1;

		
		if (SCTP_CID_ABORT == ch->type)
			return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
			
		ch = (sctp_chunkhdr_t *) ch_end;
	} while (ch_end < skb->tail);

	if (ootb_shut_ack)
		sctp_sf_shut_8_4_5(ep, asoc, type, arg, commands);
	else sctp_sf_tabort_8_4_8(ep, asoc, type, arg, commands);

	return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
}


static sctp_disposition_t sctp_sf_shut_8_4_5(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_packet *packet = NULL;
	struct sctp_chunk *chunk = arg;
	struct sctp_chunk *shut;

	packet = sctp_ootb_pkt_new(asoc, chunk);

	if (packet) {
		
		shut = sctp_make_shutdown_complete(asoc, chunk);
		if (!shut) {
			sctp_ootb_pkt_free(packet);
			return SCTP_DISPOSITION_NOMEM;
		}

		
		if (sctp_test_T_bit(shut))
			packet->vtag = ntohl(chunk->sctp_hdr->vtag);

		
		shut->skb->sk = ep->base.sk;

		sctp_packet_append_chunk(packet, shut);

		sctp_add_cmd_sf(commands, SCTP_CMD_SEND_PKT, SCTP_PACKET(packet));

		SCTP_INC_STATS(SCTP_MIB_OUTCTRLCHUNKS);

		
		if (!sctp_chunk_length_valid(chunk, sizeof(sctp_chunkhdr_t)))
			return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

		return SCTP_DISPOSITION_CONSUME;
	}

	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_do_8_5_1_E_sa(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	
	return sctp_sf_shut_8_4_5(ep, NULL, type, arg, commands);
}


sctp_disposition_t sctp_sf_do_asconf(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)


{
	struct sctp_chunk	*chunk = arg;
	struct sctp_chunk	*asconf_ack = NULL;
	sctp_addiphdr_t		*hdr;
	__u32			serial;

	if (!sctp_vtag_verify(chunk, asoc)) {
		sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_BAD_TAG, SCTP_NULL());
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
	}

	
	if (!sctp_chunk_length_valid(chunk, sizeof(sctp_addip_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	hdr = (sctp_addiphdr_t *)chunk->skb->data;
	serial = ntohl(hdr->serial);

	
	if (serial == asoc->peer.addip_serial + 1) {
   		
		asconf_ack = sctp_process_asconf((struct sctp_association *)
						 asoc, chunk);
		if (!asconf_ack)
			return SCTP_DISPOSITION_NOMEM;
	} else if (serial == asoc->peer.addip_serial) {
		
		if (asoc->addip_last_asconf_ack)
			asconf_ack = asoc->addip_last_asconf_ack;
		else return SCTP_DISPOSITION_DISCARD;
	} else {
			
		return SCTP_DISPOSITION_DISCARD;
	}

	
	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(asconf_ack));
	
	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_do_asconf_ack(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)


{
	struct sctp_chunk	*asconf_ack = arg;
	struct sctp_chunk	*last_asconf = asoc->addip_last_asconf;
	struct sctp_chunk	*abort;
	sctp_addiphdr_t		*addip_hdr;
	__u32			sent_serial, rcvd_serial;

	if (!sctp_vtag_verify(asconf_ack, asoc)) {
		sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_BAD_TAG, SCTP_NULL());
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
	}

	
	if (!sctp_chunk_length_valid(asconf_ack, sizeof(sctp_addip_chunk_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	addip_hdr = (sctp_addiphdr_t *)asconf_ack->skb->data;
	rcvd_serial = ntohl(addip_hdr->serial);

	if (last_asconf) {
		addip_hdr = (sctp_addiphdr_t *)last_asconf->subh.addip_hdr;
		sent_serial = ntohl(addip_hdr->serial);
	} else {
		sent_serial = asoc->addip_serial - 1;
	}

	
	if (ADDIP_SERIAL_gte(rcvd_serial, sent_serial + 1) && !(asoc->addip_last_asconf)) {
		abort = sctp_make_abort(asoc, asconf_ack, sizeof(sctp_errhdr_t));
		if (abort) {
			sctp_init_cause(abort, SCTP_ERROR_ASCONF_ACK, NULL, 0);
			sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(abort));
		}
		
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T4_RTO));
		sctp_add_cmd_sf(commands, SCTP_CMD_DISCARD_PACKET,SCTP_NULL());
		sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ECONNABORTED));
		sctp_add_cmd_sf(commands, SCTP_CMD_ASSOC_FAILED, SCTP_U32(SCTP_ERROR_ASCONF_ACK));
		SCTP_INC_STATS(SCTP_MIB_ABORTEDS);
		SCTP_DEC_STATS(SCTP_MIB_CURRESTAB);
		return SCTP_DISPOSITION_ABORT;
	}

	if ((rcvd_serial == sent_serial) && asoc->addip_last_asconf) {
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T4_RTO));

		if (!sctp_process_asconf_ack((struct sctp_association *)asoc, asconf_ack))
			return SCTP_DISPOSITION_CONSUME;

		abort = sctp_make_abort(asoc, asconf_ack, sizeof(sctp_errhdr_t));
		if (abort) {
			sctp_init_cause(abort, SCTP_ERROR_RSRC_LOW, NULL, 0);
			sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(abort));
		}
		
		sctp_add_cmd_sf(commands, SCTP_CMD_DISCARD_PACKET,SCTP_NULL());
		sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ECONNABORTED));
		sctp_add_cmd_sf(commands, SCTP_CMD_ASSOC_FAILED, SCTP_U32(SCTP_ERROR_ASCONF_ACK));
		SCTP_INC_STATS(SCTP_MIB_ABORTEDS);
		SCTP_DEC_STATS(SCTP_MIB_CURRESTAB);
		return SCTP_DISPOSITION_ABORT;
	}

	return SCTP_DISPOSITION_DISCARD;
}


sctp_disposition_t sctp_sf_eat_fwd_tsn(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;
	struct sctp_fwdtsn_hdr *fwdtsn_hdr;
	__u16 len;
	__u32 tsn;

	if (!sctp_vtag_verify(chunk, asoc)) {
		sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_BAD_TAG, SCTP_NULL());
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
	}

	
	if (!sctp_chunk_length_valid(chunk, sizeof(struct sctp_fwdtsn_chunk)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	fwdtsn_hdr = (struct sctp_fwdtsn_hdr *)chunk->skb->data;
	chunk->subh.fwdtsn_hdr = fwdtsn_hdr;
	len = ntohs(chunk->chunk_hdr->length);
	len -= sizeof(struct sctp_chunkhdr);
	skb_pull(chunk->skb, len);

	tsn = ntohl(fwdtsn_hdr->new_cum_tsn);
	SCTP_DEBUG_PRINTK("%s: TSN 0x%x.\n", __FUNCTION__, tsn);

	
	if (sctp_tsnmap_check(&asoc->peer.tsn_map, tsn) < 0)
		goto discard_noforce;

	sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_FWDTSN, SCTP_U32(tsn));
	if (len > sizeof(struct sctp_fwdtsn_hdr))
		sctp_add_cmd_sf(commands, SCTP_CMD_PROCESS_FWDTSN,  SCTP_CHUNK(chunk));
	
	
	if (asoc->autoclose) {
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_RESTART, SCTP_TO(SCTP_EVENT_TIMEOUT_AUTOCLOSE));
	}
	
	
	sctp_add_cmd_sf(commands, SCTP_CMD_GEN_SACK, SCTP_NOFORCE());

	return SCTP_DISPOSITION_CONSUME;

discard_noforce:
	return SCTP_DISPOSITION_DISCARD;
}

sctp_disposition_t sctp_sf_eat_fwd_tsn_fast( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	struct sctp_chunk *chunk = arg;
	struct sctp_fwdtsn_hdr *fwdtsn_hdr;
	__u16 len;
	__u32 tsn;

	if (!sctp_vtag_verify(chunk, asoc)) {
		sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_BAD_TAG, SCTP_NULL());
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
	}

	
	if (!sctp_chunk_length_valid(chunk, sizeof(struct sctp_fwdtsn_chunk)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	fwdtsn_hdr = (struct sctp_fwdtsn_hdr *)chunk->skb->data;
	chunk->subh.fwdtsn_hdr = fwdtsn_hdr;
	len = ntohs(chunk->chunk_hdr->length);
	len -= sizeof(struct sctp_chunkhdr);
	skb_pull(chunk->skb, len);

	tsn = ntohl(fwdtsn_hdr->new_cum_tsn);
	SCTP_DEBUG_PRINTK("%s: TSN 0x%x.\n", __FUNCTION__, tsn);

	
	if (sctp_tsnmap_check(&asoc->peer.tsn_map, tsn) < 0)
		goto gen_shutdown;

	sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_FWDTSN, SCTP_U32(tsn));
	if (len > sizeof(struct sctp_fwdtsn_hdr))
		sctp_add_cmd_sf(commands, SCTP_CMD_PROCESS_FWDTSN,  SCTP_CHUNK(chunk));
	
	
gen_shutdown:
	
	sctp_add_cmd_sf(commands, SCTP_CMD_GEN_SHUTDOWN, SCTP_NULL());
	sctp_add_cmd_sf(commands, SCTP_CMD_GEN_SACK, SCTP_FORCE());
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_RESTART, SCTP_TO(SCTP_EVENT_TIMEOUT_T2_SHUTDOWN));

        return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_unk_chunk(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *unk_chunk = arg;
	struct sctp_chunk *err_chunk;
	sctp_chunkhdr_t *hdr;

	SCTP_DEBUG_PRINTK("Processing the unknown chunk id %d.\n", type.chunk);

	if (!sctp_vtag_verify(unk_chunk, asoc))
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

	
	if (!sctp_chunk_length_valid(unk_chunk, sizeof(sctp_chunkhdr_t)))
		return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);

	switch (type.chunk & SCTP_CID_ACTION_MASK) {
	case SCTP_CID_ACTION_DISCARD:
		
		return sctp_sf_pdiscard(ep, asoc, type, arg, commands);
		break;
	case SCTP_CID_ACTION_DISCARD_ERR:
		
		sctp_sf_pdiscard(ep, asoc, type, arg, commands);

		
		hdr = unk_chunk->chunk_hdr;
		err_chunk = sctp_make_op_error(asoc, unk_chunk, SCTP_ERROR_UNKNOWN_CHUNK, hdr, WORD_ROUND(ntohs(hdr->length)));

		if (err_chunk) {
			sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(err_chunk));
		}
		return SCTP_DISPOSITION_CONSUME;
		break;
	case SCTP_CID_ACTION_SKIP:
		
		return SCTP_DISPOSITION_DISCARD;
		break;
	case SCTP_CID_ACTION_SKIP_ERR:
		
		hdr = unk_chunk->chunk_hdr;
		err_chunk = sctp_make_op_error(asoc, unk_chunk, SCTP_ERROR_UNKNOWN_CHUNK, hdr, WORD_ROUND(ntohs(hdr->length)));

		if (err_chunk) {
			sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(err_chunk));
		}
		
		return SCTP_DISPOSITION_CONSUME;
		break;
	default:
		break;
	}

	return SCTP_DISPOSITION_DISCARD;
}


sctp_disposition_t sctp_sf_discard_chunk(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	SCTP_DEBUG_PRINTK("Chunk %d is discarded\n", type.chunk);
	return SCTP_DISPOSITION_DISCARD;
}


sctp_disposition_t sctp_sf_pdiscard(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	sctp_add_cmd_sf(commands, SCTP_CMD_DISCARD_PACKET, SCTP_NULL());

	return SCTP_DISPOSITION_CONSUME;
}



sctp_disposition_t sctp_sf_violation(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	return SCTP_DISPOSITION_VIOLATION;
}



static sctp_disposition_t sctp_sf_violation_chunklen( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	struct sctp_chunk *chunk =  arg;
	struct sctp_chunk *abort = NULL;
	char 		   err_str[]="The following chunk had invalid length:";

	
	abort = sctp_make_abort_violation(asoc, chunk, err_str, sizeof(err_str));
	if (!abort)
		goto nomem;

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(abort));
	SCTP_INC_STATS(SCTP_MIB_OUTCTRLCHUNKS);

	if (asoc->state <= SCTP_STATE_COOKIE_ECHOED) {
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_INIT));
		sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ECONNREFUSED));
		sctp_add_cmd_sf(commands, SCTP_CMD_INIT_FAILED, SCTP_U32(SCTP_ERROR_PROTO_VIOLATION));
	} else {
		sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ECONNABORTED));
		sctp_add_cmd_sf(commands, SCTP_CMD_ASSOC_FAILED, SCTP_U32(SCTP_ERROR_PROTO_VIOLATION));
		SCTP_DEC_STATS(SCTP_MIB_CURRESTAB);
	}

	sctp_add_cmd_sf(commands, SCTP_CMD_DISCARD_PACKET, SCTP_NULL());

	SCTP_INC_STATS(SCTP_MIB_ABORTEDS);
	
	return SCTP_DISPOSITION_ABORT;

nomem:
	return SCTP_DISPOSITION_NOMEM;
}



sctp_disposition_t sctp_sf_do_prm_asoc(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *repl;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_COOKIE_WAIT));

	

	repl = sctp_make_init(asoc, &asoc->base.bind_addr, GFP_ATOMIC, 0);
	if (!repl)
		goto nomem;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_ASOC, SCTP_ASOC((struct sctp_association *) asoc));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_INIT_CHOOSE_TRANSPORT, SCTP_CHUNK(repl));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_START, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_INIT));
	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(repl));
	return SCTP_DISPOSITION_CONSUME;

nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_do_prm_send(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(chunk));
	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_do_9_2_prm_shutdown( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	int disposition;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_SHUTDOWN_PENDING));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_START, SCTP_TO(SCTP_EVENT_TIMEOUT_T5_SHUTDOWN_GUARD));

	disposition = SCTP_DISPOSITION_CONSUME;
	if (sctp_outq_is_empty(&asoc->outqueue)) {
		disposition = sctp_sf_do_9_2_start_shutdown(ep, asoc, type, arg, commands);
	}
	return disposition;
}


sctp_disposition_t sctp_sf_do_9_1_prm_abort( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	
	struct msghdr *msg = arg;
	struct sctp_chunk *abort;
	sctp_disposition_t retval;

	retval = SCTP_DISPOSITION_CONSUME;

	
	abort = sctp_make_abort_user(asoc, NULL, msg);
	if (!abort)
		retval = SCTP_DISPOSITION_NOMEM;
	else sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(abort));

	

	sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ECONNABORTED));
	
	sctp_add_cmd_sf(commands, SCTP_CMD_ASSOC_FAILED, SCTP_U32(SCTP_ERROR_USER_ABORT));

	SCTP_INC_STATS(SCTP_MIB_ABORTEDS);
	SCTP_DEC_STATS(SCTP_MIB_CURRESTAB);

	return retval;
}


sctp_disposition_t sctp_sf_error_closed(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_ERROR, SCTP_ERROR(-EINVAL));
	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_error_shutdown(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_ERROR, SCTP_ERROR(-ESHUTDOWN));
	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_cookie_wait_prm_shutdown( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_INIT));

	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_CLOSED));

	SCTP_INC_STATS(SCTP_MIB_SHUTDOWNS);

	sctp_add_cmd_sf(commands, SCTP_CMD_DELETE_TCB, SCTP_NULL());

	return SCTP_DISPOSITION_DELETE_TCB;
}


sctp_disposition_t sctp_sf_cookie_echoed_prm_shutdown( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	
	return sctp_sf_cookie_wait_prm_shutdown(ep, asoc, type, arg, commands);
}


sctp_disposition_t sctp_sf_cookie_wait_prm_abort( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	struct msghdr *msg = arg;
	struct sctp_chunk *abort;
	sctp_disposition_t retval;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_INIT));
	retval = SCTP_DISPOSITION_CONSUME;

	
	abort = sctp_make_abort_user(asoc, NULL, msg);
	if (!abort)
		retval = SCTP_DISPOSITION_NOMEM;
	else sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(abort));

	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_CLOSED));

	SCTP_INC_STATS(SCTP_MIB_ABORTEDS);

	

	sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ECONNREFUSED));
	
	sctp_add_cmd_sf(commands, SCTP_CMD_INIT_FAILED, SCTP_U32(SCTP_ERROR_USER_ABORT));

	return retval;
}


sctp_disposition_t sctp_sf_cookie_echoed_prm_abort( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	
	return sctp_sf_cookie_wait_prm_abort(ep, asoc, type, arg, commands);
}


sctp_disposition_t sctp_sf_shutdown_pending_prm_abort( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T5_SHUTDOWN_GUARD));

	return sctp_sf_do_9_1_prm_abort(ep, asoc, type, arg, commands);
}


sctp_disposition_t sctp_sf_shutdown_sent_prm_abort( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T2_SHUTDOWN));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T5_SHUTDOWN_GUARD));

	return sctp_sf_do_9_1_prm_abort(ep, asoc, type, arg, commands);
}


sctp_disposition_t sctp_sf_shutdown_ack_sent_prm_abort( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	
	return sctp_sf_shutdown_sent_prm_abort(ep, asoc, type, arg, commands);
}


sctp_disposition_t sctp_sf_do_prm_requestheartbeat( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	return sctp_sf_heartbeat(ep, asoc, type, (struct sctp_transport *)arg, commands);
}


sctp_disposition_t sctp_sf_do_prm_asconf(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *chunk = arg;

	sctp_add_cmd_sf(commands, SCTP_CMD_SETUP_T4, SCTP_CHUNK(chunk));
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_START, SCTP_TO(SCTP_EVENT_TIMEOUT_T4_RTO));
	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(chunk));
	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_ignore_primitive( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	SCTP_DEBUG_PRINTK("Primitive type %d is ignored.\n", type.primitive);
	return SCTP_DISPOSITION_DISCARD;
}




sctp_disposition_t sctp_sf_do_9_2_start_shutdown( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	struct sctp_chunk *reply;

	
	reply = sctp_make_shutdown(asoc, NULL);
	if (!reply)
		goto nomem;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_SETUP_T2, SCTP_CHUNK(reply));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_START, SCTP_TO(SCTP_EVENT_TIMEOUT_T2_SHUTDOWN));

	if (asoc->autoclose)
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_AUTOCLOSE));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_SHUTDOWN_SENT));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_HB_TIMERS_STOP, SCTP_NULL());

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(reply));

	return SCTP_DISPOSITION_CONSUME;

nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_do_9_2_shutdown_ack( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	struct sctp_chunk *chunk = (struct sctp_chunk *) arg;
	struct sctp_chunk *reply;

	
	if (chunk) {
		if (!sctp_vtag_verify(chunk, asoc))
			return sctp_sf_pdiscard(ep, asoc, type, arg, commands);

		
		if (!sctp_chunk_length_valid(chunk, sizeof(struct sctp_shutdown_chunk_t)))
			return sctp_sf_violation_chunklen(ep, asoc, type, arg, commands);
	}

	
	reply = sctp_make_shutdown_ack(asoc, chunk);
	if (!reply)
		goto nomem;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_SETUP_T2, SCTP_CHUNK(reply));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_RESTART, SCTP_TO(SCTP_EVENT_TIMEOUT_T2_SHUTDOWN));

	if (asoc->autoclose)
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_AUTOCLOSE));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_SHUTDOWN_ACK_SENT));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_HB_TIMERS_STOP, SCTP_NULL());

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(reply));

	return SCTP_DISPOSITION_CONSUME;

nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_ignore_other(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	SCTP_DEBUG_PRINTK("The event other type %d is ignored\n", type.other);
	return SCTP_DISPOSITION_DISCARD;
}




sctp_disposition_t sctp_sf_do_6_3_3_rtx(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_transport *transport = arg;

	if (asoc->overall_error_count >= asoc->max_retrans) {
		sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ETIMEDOUT));
		
		sctp_add_cmd_sf(commands, SCTP_CMD_ASSOC_FAILED, SCTP_U32(SCTP_ERROR_NO_ERROR));
		SCTP_INC_STATS(SCTP_MIB_ABORTEDS);
		SCTP_DEC_STATS(SCTP_MIB_CURRESTAB);
		return SCTP_DISPOSITION_DELETE_TCB;
	}

	

	

	

	
	sctp_add_cmd_sf(commands, SCTP_CMD_RETRAN, SCTP_TRANSPORT(transport));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_STRIKE, SCTP_TRANSPORT(transport));

	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_do_6_2_sack(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	sctp_add_cmd_sf(commands, SCTP_CMD_GEN_SACK, SCTP_FORCE());
	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_t1_init_timer_expire(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *repl = NULL;
	struct sctp_bind_addr *bp;
	int attempts = asoc->init_err_counter + 1;

	SCTP_DEBUG_PRINTK("Timer T1 expired (INIT).\n");

	if (attempts <= asoc->max_init_attempts) {
		bp = (struct sctp_bind_addr *) &asoc->base.bind_addr;
		repl = sctp_make_init(asoc, bp, GFP_ATOMIC, 0);
		if (!repl)
			return SCTP_DISPOSITION_NOMEM;

		
		sctp_add_cmd_sf(commands, SCTP_CMD_INIT_CHOOSE_TRANSPORT, SCTP_CHUNK(repl));

		
		sctp_add_cmd_sf(commands, SCTP_CMD_INIT_RESTART, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_INIT));

		sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(repl));
	} else {
		SCTP_DEBUG_PRINTK("Giving up on INIT, attempts: %d" " max_init_attempts: %d\n", attempts, asoc->max_init_attempts);

		sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ETIMEDOUT));
		sctp_add_cmd_sf(commands, SCTP_CMD_INIT_FAILED, SCTP_U32(SCTP_ERROR_NO_ERROR));
		return SCTP_DISPOSITION_DELETE_TCB;
	}

	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_t1_cookie_timer_expire(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *repl = NULL;
	int attempts = asoc->init_err_counter + 1;

	SCTP_DEBUG_PRINTK("Timer T1 expired (COOKIE-ECHO).\n");

	if (attempts <= asoc->max_init_attempts) {
		repl = sctp_make_cookie_echo(asoc, NULL);
		if (!repl)
			return SCTP_DISPOSITION_NOMEM;

		
		sctp_add_cmd_sf(commands, SCTP_CMD_COOKIEECHO_RESTART, SCTP_TO(SCTP_EVENT_TIMEOUT_T1_COOKIE));

		sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(repl));
	} else {
		sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ETIMEDOUT));
		sctp_add_cmd_sf(commands, SCTP_CMD_INIT_FAILED, SCTP_U32(SCTP_ERROR_NO_ERROR));
		return SCTP_DISPOSITION_DELETE_TCB;
	}

	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_t2_timer_expire(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *reply = NULL;

	SCTP_DEBUG_PRINTK("Timer T2 expired.\n");
	if (asoc->overall_error_count >= asoc->max_retrans) {
		sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ETIMEDOUT));
		
		sctp_add_cmd_sf(commands, SCTP_CMD_ASSOC_FAILED, SCTP_U32(SCTP_ERROR_NO_ERROR));
		SCTP_INC_STATS(SCTP_MIB_ABORTEDS);
		SCTP_DEC_STATS(SCTP_MIB_CURRESTAB);
		return SCTP_DISPOSITION_DELETE_TCB;
	}

	switch (asoc->state) {
	case SCTP_STATE_SHUTDOWN_SENT:
		reply = sctp_make_shutdown(asoc, NULL);
		break;

	case SCTP_STATE_SHUTDOWN_ACK_SENT:
		reply = sctp_make_shutdown_ack(asoc, NULL);
		break;

	default:
		BUG();
		break;
	};

	if (!reply)
		goto nomem;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_STRIKE, SCTP_TRANSPORT(asoc->shutdown_last_sent_to));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_SETUP_T2, SCTP_CHUNK(reply));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_RESTART, SCTP_TO(SCTP_EVENT_TIMEOUT_T2_SHUTDOWN));
	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(reply));
	return SCTP_DISPOSITION_CONSUME;

nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_t4_timer_expire( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	struct sctp_chunk *chunk = asoc->addip_last_asconf;
	struct sctp_transport *transport = chunk->transport;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_STRIKE, SCTP_TRANSPORT(transport));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_SETUP_T4, SCTP_CHUNK(chunk));

	
	if (asoc->overall_error_count >= asoc->max_retrans) {
		sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_STOP, SCTP_TO(SCTP_EVENT_TIMEOUT_T4_RTO));
		sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ETIMEDOUT));
		sctp_add_cmd_sf(commands, SCTP_CMD_ASSOC_FAILED, SCTP_U32(SCTP_ERROR_NO_ERROR));
		SCTP_INC_STATS(SCTP_MIB_ABORTEDS);
		SCTP_INC_STATS(SCTP_MIB_CURRESTAB);
		return SCTP_DISPOSITION_ABORT;
	}

	

	
	sctp_chunk_hold(asoc->addip_last_asconf);
	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(asoc->addip_last_asconf));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_RESTART, SCTP_TO(SCTP_EVENT_TIMEOUT_T4_RTO));

	return SCTP_DISPOSITION_CONSUME;
}


sctp_disposition_t sctp_sf_t5_timer_expire(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	struct sctp_chunk *reply = NULL;

	SCTP_DEBUG_PRINTK("Timer T5 expired.\n");

	reply = sctp_make_abort(asoc, NULL, 0);
	if (!reply)
		goto nomem;

	sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(reply));
	sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ETIMEDOUT));
	sctp_add_cmd_sf(commands, SCTP_CMD_ASSOC_FAILED, SCTP_U32(SCTP_ERROR_NO_ERROR));

	return SCTP_DISPOSITION_DELETE_TCB;
nomem:
	return SCTP_DISPOSITION_NOMEM;
}


sctp_disposition_t sctp_sf_autoclose_timer_expire( const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)




{
	int disposition;

	
	sctp_add_cmd_sf(commands, SCTP_CMD_NEW_STATE, SCTP_STATE(SCTP_STATE_SHUTDOWN_PENDING));

	
	sctp_add_cmd_sf(commands, SCTP_CMD_TIMER_START, SCTP_TO(SCTP_EVENT_TIMEOUT_T5_SHUTDOWN_GUARD));
	disposition = SCTP_DISPOSITION_CONSUME;
	if (sctp_outq_is_empty(&asoc->outqueue)) {
		disposition = sctp_sf_do_9_2_start_shutdown(ep, asoc, type, arg, commands);
	}
	return disposition;
}




sctp_disposition_t sctp_sf_not_impl(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	return SCTP_DISPOSITION_NOT_IMPL;
}


sctp_disposition_t sctp_sf_bug(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	return SCTP_DISPOSITION_BUG;
}


sctp_disposition_t sctp_sf_timer_ignore(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const sctp_subtype_t type, void *arg, sctp_cmd_seq_t *commands)



{
	SCTP_DEBUG_PRINTK("Timer %d ignored.\n", type.chunk);
	return SCTP_DISPOSITION_CONSUME;
}




static struct sctp_sackhdr *sctp_sm_pull_sack(struct sctp_chunk *chunk)
{
	struct sctp_sackhdr *sack;
	unsigned int len;
	__u16 num_blocks;
	__u16 num_dup_tsns;

	
	sack = (struct sctp_sackhdr *) chunk->skb->data;

	num_blocks = ntohs(sack->num_gap_ack_blocks);
	num_dup_tsns = ntohs(sack->num_dup_tsns);
	len = sizeof(struct sctp_sackhdr);
	len += (num_blocks + num_dup_tsns) * sizeof(__u32);
	if (len > chunk->skb->len)
		return NULL;

	skb_pull(chunk->skb, len);

	return sack;
}


static struct sctp_packet *sctp_abort_pkt_new(const struct sctp_endpoint *ep, const struct sctp_association *asoc, struct sctp_chunk *chunk, const void *payload, size_t paylen)



{
	struct sctp_packet *packet;
	struct sctp_chunk *abort;

	packet = sctp_ootb_pkt_new(asoc, chunk);

	if (packet) {
		
		abort = sctp_make_abort(asoc, chunk, paylen);
		if (!abort) {
			sctp_ootb_pkt_free(packet);
			return NULL;
		}

		
		if (sctp_test_T_bit(abort))
			packet->vtag = ntohl(chunk->sctp_hdr->vtag);

		
		sctp_addto_chunk(abort, paylen, payload);

		
		abort->skb->sk = ep->base.sk;

		sctp_packet_append_chunk(packet, abort);

	}

	return packet;
}


static struct sctp_packet *sctp_ootb_pkt_new(const struct sctp_association *asoc, const struct sctp_chunk *chunk)
{
	struct sctp_packet *packet;
	struct sctp_transport *transport;
	__u16 sport;
	__u16 dport;
	__u32 vtag;

	
	sport = ntohs(chunk->sctp_hdr->dest);
	dport = ntohs(chunk->sctp_hdr->source);

	
	if (asoc) {
		vtag = asoc->peer.i.init_tag;
	} else {
		
		switch(chunk->chunk_hdr->type) {
		case SCTP_CID_INIT:
		{
			sctp_init_chunk_t *init;

			init = (sctp_init_chunk_t *)chunk->chunk_hdr;
			vtag = ntohl(init->init_hdr.init_tag);
			break;
		}
		default:	
			vtag = ntohl(chunk->sctp_hdr->vtag);
			break;
		}
	}

	
	transport = sctp_transport_new(sctp_source(chunk), GFP_ATOMIC);
	if (!transport)
		goto nomem;

	
	sctp_transport_route(transport, (union sctp_addr *)&chunk->dest, sctp_sk(sctp_get_ctl_sock()));

	packet = sctp_packet_init(&transport->packet, transport, sport, dport);
	packet = sctp_packet_config(packet, vtag, 0);

	return packet;

nomem:
	return NULL;
}


void sctp_ootb_pkt_free(struct sctp_packet *packet)
{
	sctp_transport_free(packet->transport);
}


static void sctp_send_stale_cookie_err(const struct sctp_endpoint *ep, const struct sctp_association *asoc, const struct sctp_chunk *chunk, sctp_cmd_seq_t *commands, struct sctp_chunk *err_chunk)



{
	struct sctp_packet *packet;

	if (err_chunk) {
		packet = sctp_ootb_pkt_new(asoc, chunk);
		if (packet) {
			struct sctp_signed_cookie *cookie;

			
			cookie = chunk->subh.cookie_hdr;
			packet->vtag = cookie->c.peer_vtag;
			
			
			err_chunk->skb->sk = ep->base.sk;
			sctp_packet_append_chunk(packet, err_chunk);
			sctp_add_cmd_sf(commands, SCTP_CMD_SEND_PKT, SCTP_PACKET(packet));
			SCTP_INC_STATS(SCTP_MIB_OUTCTRLCHUNKS);
		} else sctp_chunk_free (err_chunk);
	}
}



static int sctp_eat_data(const struct sctp_association *asoc, struct sctp_chunk *chunk, sctp_cmd_seq_t *commands)

{
	sctp_datahdr_t *data_hdr;
	struct sctp_chunk *err;
	size_t datalen;
	sctp_verb_t deliver;
	int tmp;
	__u32 tsn;
	int account_value;
	struct sctp_tsnmap *map = (struct sctp_tsnmap *)&asoc->peer.tsn_map;
	struct sock *sk = asoc->base.sk;
	int rcvbuf_over = 0;

	data_hdr = chunk->subh.data_hdr = (sctp_datahdr_t *)chunk->skb->data;
	skb_pull(chunk->skb, sizeof(sctp_datahdr_t));

	tsn = ntohl(data_hdr->tsn);
	SCTP_DEBUG_PRINTK("eat_data: TSN 0x%x.\n", tsn);

	

	
	if ((asoc->state == SCTP_STATE_ESTABLISHED) && (!chunk->data_accepted)) {
		
		if (asoc->ep->rcvbuf_policy)
			account_value = atomic_read(&asoc->rmem_alloc);
		else account_value = atomic_read(&sk->sk_rmem_alloc);
		if (account_value > sk->sk_rcvbuf) {
			
			if ((sctp_tsnmap_get_ctsn(map) + 1) != tsn)
				return SCTP_IERROR_IGNORE_TSN;

			
			rcvbuf_over = 1;
		}
	}

	

	if (!chunk->ecn_ce_done) {
		struct sctp_af *af;
		chunk->ecn_ce_done = 1;

		af = sctp_get_af_specific( ipver2af(chunk->skb->nh.iph->version));

		if (af && af->is_ce(chunk->skb) && asoc->peer.ecn_capable) {
			
			sctp_add_cmd_sf(commands, SCTP_CMD_ECN_CE, SCTP_U32(tsn));
		}
	}

	tmp = sctp_tsnmap_check(&asoc->peer.tsn_map, tsn);
	if (tmp < 0) {
		
		return SCTP_IERROR_HIGH_TSN;
	} else if (tmp > 0) {
		
		sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_DUP, SCTP_U32(tsn));
		return SCTP_IERROR_DUP_TSN;
	}

	

	
	datalen = ntohs(chunk->chunk_hdr->length);
	datalen -= sizeof(sctp_data_chunk_t);

	deliver = SCTP_CMD_CHUNK_ULP;

	
	if ((datalen >= asoc->rwnd) && (!asoc->ulpq.pd_mode)) {

		
		sctp_add_cmd_sf(commands, SCTP_CMD_PART_DELIVER, SCTP_NULL());
	}

        
	if (!asoc->rwnd || asoc->rwnd_over || (datalen > asoc->rwnd + asoc->frag_point) || (rcvbuf_over && (!skb_queue_len(&sk->sk_receive_queue)))) {


		
		if (sctp_tsnmap_has_gap(map) && (sctp_tsnmap_get_ctsn(map) + 1) == tsn) {
			SCTP_DEBUG_PRINTK("Reneging for tsn:%u\n", tsn);
			deliver = SCTP_CMD_RENEGE;
		} else {
			SCTP_DEBUG_PRINTK("Discard tsn: %u len: %Zd, " "rwnd: %d\n", tsn, datalen, asoc->rwnd);

			return SCTP_IERROR_IGNORE_TSN;
		}
	}

	
	if (unlikely(0 == datalen)) {
		err = sctp_make_abort_no_data(asoc, chunk, tsn);
		if (err) {
			sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(err));
		}
		
		sctp_add_cmd_sf(commands, SCTP_CMD_DISCARD_PACKET,SCTP_NULL());
		sctp_add_cmd_sf(commands, SCTP_CMD_SET_SK_ERR, SCTP_ERROR(ECONNABORTED));
		sctp_add_cmd_sf(commands, SCTP_CMD_ASSOC_FAILED, SCTP_U32(SCTP_ERROR_NO_DATA));
		SCTP_INC_STATS(SCTP_MIB_ABORTEDS);
		SCTP_DEC_STATS(SCTP_MIB_CURRESTAB);
		return SCTP_IERROR_NO_DATA;
	}

	
	if (SCTP_CMD_CHUNK_ULP == deliver)
		sctp_add_cmd_sf(commands, SCTP_CMD_REPORT_TSN, SCTP_U32(tsn));

	chunk->data_accepted = 1;

	
	if (chunk->chunk_hdr->flags & SCTP_DATA_UNORDERED)
		SCTP_INC_STATS(SCTP_MIB_INUNORDERCHUNKS);
	else SCTP_INC_STATS(SCTP_MIB_INORDERCHUNKS);

	
	if (ntohs(data_hdr->stream) >= asoc->c.sinit_max_instreams) {
		err = sctp_make_op_error(asoc, chunk, SCTP_ERROR_INV_STRM, &data_hdr->stream, sizeof(data_hdr->stream));

		if (err)
			sctp_add_cmd_sf(commands, SCTP_CMD_REPLY, SCTP_CHUNK(err));
		return SCTP_IERROR_BAD_STREAM;
	}

	
	sctp_add_cmd_sf(commands, deliver, SCTP_CHUNK(chunk));

	return SCTP_IERROR_NO_ERROR;
}
