























enum {
    RTCP_SDES_NULL  = 0, RTCP_SDES_CNAME = 1, RTCP_SDES_NAME  = 2, RTCP_SDES_EMAIL = 3, RTCP_SDES_PHONE = 4, RTCP_SDES_LOC   = 5, RTCP_SDES_TOOL  = 6, RTCP_SDES_NOTE  = 7 };






















PJ_DEF(pj_status_t) pjmedia_rtcp_get_ntp_time(const pjmedia_rtcp_session *sess, pjmedia_rtcp_ntp_rec *ntp)
{


    pj_timestamp ts;
    pj_status_t status;

    status = pj_get_timestamp(&ts);

    
    ntp->hi = (pj_uint32_t)((ts.u64 - sess->ts_base.u64) / sess->ts_freq.u64)
	      + sess->tv_base.sec + JAN_1970;

    
    ts.u64 = (ts.u64 - sess->ts_base.u64) % sess->ts_freq.u64;
    pj_assert(ts.u64 < sess->ts_freq.u64);
    ts.u64 = (ts.u64 << 32) / sess->ts_freq.u64;

    
    ntp->lo = ts.u32.lo;





    
    {
	

	
	enum { MIN_DIFF = 400 };

	pj_time_val ts_time, elapsed, diff;

	pj_gettimeofday(&elapsed);

	ts_time.sec = ntp->hi - sess->tv_base.sec - JAN_1970;
	ts_time.msec = (long)(ntp->lo * 1000.0 / 0xFFFFFFFF);

	PJ_TIME_VAL_SUB(elapsed, sess->tv_base);

	if (PJ_TIME_VAL_LT(ts_time, elapsed)) {
	    diff = elapsed;
	    PJ_TIME_VAL_SUB(diff, ts_time);
	} else {
	    diff = ts_time;
	    PJ_TIME_VAL_SUB(diff, elapsed);
	}

	if (PJ_TIME_VAL_MSEC(diff) >= MIN_DIFF) {

	    TRACE_((sess->name, "RTCP NTP timestamp corrected by %d ms", PJ_TIME_VAL_MSEC(diff)));


	    ntp->hi = elapsed.sec + sess->tv_base.sec + JAN_1970;
	    ntp->lo = (elapsed.msec * 65536 / 1000) << 16;
	}

    }


    return status;
}



PJ_DEF(void) pjmedia_rtcp_session_setting_default( pjmedia_rtcp_session_setting *settings)
{
    pj_bzero(settings, sizeof(*settings));
}



PJ_DEF(void) pjmedia_rtcp_init_stat(pjmedia_rtcp_stat *stat)
{
    pj_time_val now;

    pj_assert(stat);

    pj_bzero(stat, sizeof(pjmedia_rtcp_stat));

    pj_math_stat_init(&stat->rtt);
    pj_math_stat_init(&stat->rx.loss_period);
    pj_math_stat_init(&stat->rx.jitter);
    pj_math_stat_init(&stat->tx.loss_period);
    pj_math_stat_init(&stat->tx.jitter);


    pj_math_stat_init(&stat->rx_ipdv);



    pj_math_stat_init(&stat->rx_raw_jitter);


    pj_gettimeofday(&now);
    stat->start = now;
}



PJ_DEF(void) pjmedia_rtcp_init(pjmedia_rtcp_session *sess,  char *name, unsigned clock_rate, unsigned samples_per_frame, pj_uint32_t ssrc)



{
    pjmedia_rtcp_session_setting settings;

    pjmedia_rtcp_session_setting_default(&settings);
    settings.name = name;
    settings.clock_rate = clock_rate;
    settings.samples_per_frame = samples_per_frame;
    settings.ssrc = ssrc;

    pjmedia_rtcp_init2(sess, &settings);
}



PJ_DEF(void) pjmedia_rtcp_init2( pjmedia_rtcp_session *sess, const pjmedia_rtcp_session_setting *settings)
{
    pjmedia_rtcp_sr_pkt *sr_pkt = &sess->rtcp_sr_pkt;
    pj_time_val now;
    
    
    pj_bzero(sess, sizeof(pjmedia_rtcp_session));

    
    sess->rtp_last_ts = (unsigned)-1;

    
    sess->name = settings->name ? settings->name : (char*)THIS_FILE;

    
    sess->clock_rate = settings->clock_rate;
    sess->pkt_size = settings->samples_per_frame;

    
    sr_pkt->common.version = 2;
    sr_pkt->common.count = 1;
    sr_pkt->common.pt = RTCP_SR;
    sr_pkt->common.length = pj_htons(12);
    sr_pkt->common.ssrc = pj_htonl(settings->ssrc);
    
    
    pj_memcpy(&sess->rtcp_rr_pkt.common, &sr_pkt->common,  sizeof(pjmedia_rtcp_common));
    sess->rtcp_rr_pkt.common.pt = RTCP_RR;
    sess->rtcp_rr_pkt.common.length = pj_htons(7);

    
    pj_gettimeofday(&now);
    sess->tv_base = now;
    pj_get_timestamp(&sess->ts_base);
    pj_get_timestamp_freq(&sess->ts_freq);
    sess->rtp_ts_base = settings->rtp_ts_base;

    
    pjmedia_rtcp_init_stat(&sess->stat);

    
}


PJ_DEF(void) pjmedia_rtcp_fini(pjmedia_rtcp_session *sess)
{

    pjmedia_rtcp_xr_fini(&sess->xr_session);

    
    PJ_UNUSED_ARG(sess);

}

static void rtcp_init_seq(pjmedia_rtcp_session *sess)
{
    sess->received = 0;
    sess->exp_prior = 0;
    sess->rx_prior = 0;
    sess->transit = 0;
    sess->jitter = 0;
}

PJ_DEF(void) pjmedia_rtcp_rx_rtp( pjmedia_rtcp_session *sess,  unsigned seq, unsigned rtp_ts, unsigned payload)


{
    pjmedia_rtcp_rx_rtp2(sess, seq, rtp_ts, payload, PJ_FALSE);
}

PJ_DEF(void) pjmedia_rtcp_rx_rtp2(pjmedia_rtcp_session *sess,  unsigned seq, unsigned rtp_ts, unsigned payload, pj_bool_t discarded)



{   
    pj_timestamp ts;
    pj_uint32_t arrival;
    pj_int32_t transit;
    pjmedia_rtp_status seq_st;


    PJ_UNUSED_ARG(discarded);


    if (sess->stat.rx.pkt == 0) {
	
	pjmedia_rtp_seq_init(&sess->seq_ctrl, (pj_uint16_t)seq);
    } 

    sess->stat.rx.pkt++;
    sess->stat.rx.bytes += payload;

    
    pjmedia_rtp_seq_update(&sess->seq_ctrl, (pj_uint16_t)seq, &seq_st);

    if (seq_st.status.flag.restart) {
	rtcp_init_seq(sess);
    }
    
    if (seq_st.status.flag.dup) {
	sess->stat.rx.dup++;
	TRACE_((sess->name, "Duplicate packet detected"));
    }

    if (seq_st.status.flag.outorder && !seq_st.status.flag.probation) {
	sess->stat.rx.reorder++;
	TRACE_((sess->name, "Out-of-order packet detected"));
    }

    if (seq_st.status.flag.bad) {
	sess->stat.rx.discard++;


	pjmedia_rtcp_xr_rx_rtp(&sess->xr_session, seq,  -1, (seq_st.status.flag.dup? 1:0), (!seq_st.status.flag.dup? 1:-1), -1, -1, 0);






	TRACE_((sess->name, "Bad packet discarded"));
	return;
    }

    
    ++sess->received;

    
    if (seq_st.diff > 1) {
	unsigned count = seq_st.diff - 1;
	unsigned period;

	period = count * sess->pkt_size * 1000 / sess->clock_rate;
	period *= 1000;

	
	sess->stat.rx.loss += (seq_st.diff - 1);
	TRACE_((sess->name, "%d packet(s) lost", seq_st.diff - 1));

	
	pj_math_stat_update(&sess->stat.rx.loss_period, period);
    }


    
    if (seq_st.diff == 1 && rtp_ts != sess->rtp_last_ts) {
	
	pj_get_timestamp(&ts);
	ts.u64 = ts.u64 * sess->clock_rate / sess->ts_freq.u64;
	arrival = ts.u32.lo;

	transit = arrival - rtp_ts;
    
	
	if (sess->transit == 0 ||  sess->received < PJMEDIA_RTCP_IGNORE_FIRST_PACKETS)
	{
	    sess->transit = transit;
	    sess->stat.rx.jitter.min = (unsigned)-1;
	} else {
	    pj_int32_t d;
	    pj_uint32_t jitter;

	    d = transit - sess->transit;
	    if (d < 0) 
		d = -d;
	    
	    sess->jitter += d - ((sess->jitter + 8) >> 4);

	    
	    jitter = sess->jitter >> 4;
	    
	    
	    if (jitter < 4294)
		jitter = jitter * 1000000 / sess->clock_rate;
	    else {
		jitter = jitter * 1000 / sess->clock_rate;
		jitter *= 1000;
	    }
	    pj_math_stat_update(&sess->stat.rx.jitter, jitter);



	    {
		pj_uint32_t raw_jitter;

		
		if (d < 4294)
		    raw_jitter = d * 1000000 / sess->clock_rate;
		else {
		    raw_jitter = d * 1000 / sess->clock_rate;
		    raw_jitter *= 1000;
		}
		
		
		pj_math_stat_update(&sess->stat.rx_raw_jitter, raw_jitter);
	    }




	    {
		pj_int32_t ipdv;

		ipdv = transit - sess->transit;
		
		if (ipdv > -2147 && ipdv < 2147)
		    ipdv = ipdv * 1000000 / (int)sess->clock_rate;
		else {
		    ipdv = ipdv * 1000 / (int)sess->clock_rate;
		    ipdv *= 1000;
		}
		
		
		pj_math_stat_update(&sess->stat.rx_ipdv, ipdv);
	    }



	    pjmedia_rtcp_xr_rx_rtp(&sess->xr_session, seq,  0, 0, discarded, (sess->jitter >> 4), -1, 0);






	    
	    sess->transit = transit;
	}

    } else if (seq_st.diff > 1) {
	int i;

	
	for (i=seq_st.diff-1; i>0; --i) {
	    pjmedia_rtcp_xr_rx_rtp(&sess->xr_session, seq - i,  1, 0, 0, -1, -1, 0);




	}

	
	pjmedia_rtcp_xr_rx_rtp(&sess->xr_session, seq,  0, 0, discarded, -1, -1, 0);





    }

    
    sess->rtp_last_ts = rtp_ts;
}

PJ_DEF(void) pjmedia_rtcp_tx_rtp(pjmedia_rtcp_session *sess,  unsigned bytes_payload_size)
{
    
    sess->stat.tx.pkt++;
    sess->stat.tx.bytes += bytes_payload_size;
}


static void parse_rtcp_report( pjmedia_rtcp_session *sess, const void *pkt, pj_size_t size)

{
    pjmedia_rtcp_common *common = (pjmedia_rtcp_common*) pkt;
    const pjmedia_rtcp_rr *rr = NULL;
    const pjmedia_rtcp_sr *sr = NULL;
    pj_uint32_t last_loss, jitter_samp, jitter;

    
    if (common->pt == RTCP_SR) {
	sr = (pjmedia_rtcp_sr*) (((char*)pkt) + sizeof(pjmedia_rtcp_common));
	if (common->count > 0 && size >= (sizeof(pjmedia_rtcp_sr_pkt))) {
	    rr = (pjmedia_rtcp_rr*)(((char*)pkt) + (sizeof(pjmedia_rtcp_common)
				    + sizeof(pjmedia_rtcp_sr)));
	}
    } else if (common->pt == RTCP_RR && common->count > 0) {
	rr = (pjmedia_rtcp_rr*)(((char*)pkt) + sizeof(pjmedia_rtcp_common));

    } else if (common->pt == RTCP_XR) {
	if (sess->xr_enabled)
	    pjmedia_rtcp_xr_rx_rtcp_xr(&sess->xr_session, pkt, size);

	return;

    }


    if (sr) {
	
	sess->rx_lsr = ((pj_ntohl(sr->ntp_sec) & 0x0000FFFF) << 16) |  ((pj_ntohl(sr->ntp_frac) >> 16) & 0xFFFF);

	
	pj_get_timestamp(&sess->rx_lsr_time);

	TRACE_((sess->name, "Rx RTCP SR: ntp_ts=%p",  sess->rx_lsr, (pj_uint32_t)(sess->rx_lsr_time.u64*65536/sess->ts_freq.u64)));

    }


    
    if (rr == NULL)
	return;


    last_loss = sess->stat.tx.loss;

    
    sess->stat.tx.loss = (rr->total_lost_2 << 16) + (rr->total_lost_1 << 8) + rr->total_lost_0;


    TRACE_((sess->name, "Rx RTCP RR: total_lost_2=%x, 1=%x, 0=%x, lost=%d",  (int)rr->total_lost_2, (int)rr->total_lost_1, (int)rr->total_lost_0, sess->stat.tx.loss));



    
    
    if (sess->stat.tx.loss > last_loss) {
	unsigned period;

	
	period = (sess->stat.tx.loss - last_loss) * sess->pkt_size * 1000 / sess->clock_rate;

	
	period *= 1000;

	
	pj_math_stat_update(&sess->stat.tx.loss_period, period);
    }

    
    jitter_samp = pj_ntohl(rr->jitter);
    
    if (jitter_samp <= 4294)
	jitter = jitter_samp * 1000000 / sess->clock_rate;
    else {
	jitter = jitter_samp * 1000 / sess->clock_rate;
	jitter *= 1000;
    }

    
    pj_math_stat_update(&sess->stat.tx.jitter, jitter);

    
    if (rr->lsr && rr->dlsr) {
	pj_uint32_t lsr, now, dlsr;
	pj_uint64_t eedelay;
	pjmedia_rtcp_ntp_rec ntp;

	
	lsr = pj_ntohl(rr->lsr);

	
	dlsr = pj_ntohl(rr->dlsr);

	
	pjmedia_rtcp_get_ntp_time(sess, &ntp);
	now = ((ntp.hi & 0xFFFF) << 16) + (ntp.lo >> 16);

	
	eedelay = now - lsr - dlsr;

	
	if (eedelay < 4294) {
	    eedelay = (eedelay * 1000000) >> 16;
	} else {
	    eedelay = (eedelay * 1000) >> 16;
	    eedelay *= 1000;
	}

	TRACE_((sess->name, "Rx RTCP RR: lsr=%p, dlsr=%p (%d:%03dms), " "now=%p, rtt=%p", lsr, dlsr, dlsr/65536, (dlsr%65536)*1000/65536, now, (pj_uint32_t)eedelay));


	
	
	if (now-dlsr >= lsr) {
	    unsigned rtt = (pj_uint32_t)eedelay;
	    
	    
	    if (eedelay > 30 * 1000 * 1000UL) {

		TRACE_((sess->name, "RTT not making any sense, ignored.."));
		goto end_rtt_calc;
	    }


	    
	    if (rtt > ((unsigned)sess->stat.rtt.mean * PJMEDIA_RTCP_NORMALIZE_FACTOR) && sess->stat.rtt.n!=0)
	    {
		unsigned orig_rtt = rtt;
		rtt = sess->stat.rtt.mean * PJMEDIA_RTCP_NORMALIZE_FACTOR;
		PJ_LOG(5,(sess->name, "RTT value %d usec is normalized to %d usec", orig_rtt, rtt));

	    }

	    TRACE_((sess->name, "RTCP RTT is set to %d usec", rtt));

	    
	    pj_math_stat_update(&sess->stat.rtt, rtt);

	} else {
	    PJ_LOG(5, (sess->name, "Internal RTCP NTP clock skew detected: " "lsr=%p, now=%p, dlsr=%p (%d:%03dms), " "diff=%d", lsr, now, dlsr, dlsr/65536, (dlsr%65536)*1000/65536, dlsr-(now-lsr)));




	}
    }

end_rtt_calc:

    pj_gettimeofday(&sess->stat.tx.update);
    sess->stat.tx.update_cnt++;
}


static void parse_rtcp_sdes(pjmedia_rtcp_session *sess, const void *pkt, pj_size_t size)

{
    pjmedia_rtcp_sdes *sdes = &sess->stat.peer_sdes;
    char *p, *p_end;
    char *b, *b_end;

    p = (char*)pkt + 8;
    p_end = (char*)pkt + size;

    pj_bzero(sdes, sizeof(*sdes));
    b = sess->stat.peer_sdes_buf_;
    b_end = b + sizeof(sess->stat.peer_sdes_buf_);

    while (p < p_end) {
	pj_uint8_t sdes_type, sdes_len;
	pj_str_t sdes_value = {NULL, 0};

	sdes_type = *p++;

	
	if (sdes_type == RTCP_SDES_NULL || p == p_end)
	    break;

	sdes_len = *p++;

	
	if (p + sdes_len > p_end)
	    break;

	
	if (b + sdes_len < b_end) {
	    pj_memcpy(b, p, sdes_len);
	    sdes_value.ptr = b;
	    sdes_value.slen = sdes_len;
	    b += sdes_len;
	} else {
	    
	    PJ_LOG(5, (sess->name, "Unsufficient buffer to save RTCP SDES type %d:%.*s", sdes_type, sdes_len, p));

	    p += sdes_len;
	    continue;
	}

	switch (sdes_type) {
	case RTCP_SDES_CNAME:
	    sdes->cname = sdes_value;
	    break;
	case RTCP_SDES_NAME:
	    sdes->name = sdes_value;
	    break;
	case RTCP_SDES_EMAIL:
	    sdes->email = sdes_value;
	    break;
	case RTCP_SDES_PHONE:
	    sdes->phone = sdes_value;
	    break;
	case RTCP_SDES_LOC:
	    sdes->loc = sdes_value;
	    break;
	case RTCP_SDES_TOOL:
	    sdes->tool = sdes_value;
	    break;
	case RTCP_SDES_NOTE:
	    sdes->note = sdes_value;
	    break;
	default:
	    TRACE_((sess->name, "Received unknown RTCP SDES type %d:%.*s", sdes_type, sdes_value.slen, sdes_value.ptr));
	    break;
	}

	p += sdes_len;
    }
}


static void parse_rtcp_bye(pjmedia_rtcp_session *sess, const void *pkt, pj_size_t size)

{
    pj_str_t reason = {"-", 1};

    
    if (size > 8) {
    	
	reason.slen = PJ_MIN(sizeof(sess->stat.peer_sdes_buf_), *((pj_uint8_t*)pkt+8));
        reason.slen = PJ_MIN(reason.slen, size-9);

	pj_memcpy(sess->stat.peer_sdes_buf_, ((pj_uint8_t*)pkt+9), reason.slen);
	reason.ptr = sess->stat.peer_sdes_buf_;
    }

    
    PJ_LOG(5, (sess->name, "Received RTCP BYE, reason: %.*s", reason.slen, reason.ptr));
}


static void parse_rtcp_fb(pjmedia_rtcp_session *sess, const void *pkt, pj_size_t size)

{
    unsigned cnt = 1;
    pjmedia_rtcp_fb_nack nack[1];
    
    
    pjmedia_event ev;
    pj_timestamp ts_now;

    pj_get_timestamp(&ts_now);

    if (pjmedia_rtcp_fb_parse_nack(pkt, size, &cnt, nack)==PJ_SUCCESS)
    {
	pjmedia_event_init(&ev, PJMEDIA_EVENT_RX_RTCP_FB, &ts_now, sess);
	ev.data.rx_rtcp_fb.cap.type = PJMEDIA_RTCP_FB_NACK;
	ev.data.rx_rtcp_fb.msg.nack = nack[0];
	pjmedia_event_publish(NULL, sess, &ev, 0);

    } else if (pjmedia_rtcp_fb_parse_pli(pkt, size)==PJ_SUCCESS)
    {
	pjmedia_event_init(&ev, PJMEDIA_EVENT_RX_RTCP_FB, &ts_now, sess);
	ev.data.rx_rtcp_fb.cap.type = PJMEDIA_RTCP_FB_NACK;
	pj_strset2(&ev.data.rx_rtcp_fb.cap.param, (char*)"pli");
	pjmedia_event_publish(NULL, sess, &ev, 0);

	
    } else {
	
	TRACE_((sess->name, "Received unknown RTCP feedback"));
    }
}


PJ_DEF(void) pjmedia_rtcp_rx_rtcp( pjmedia_rtcp_session *sess, const void *pkt, pj_size_t size)

{
    pj_uint8_t *p, *p_end;

    p = (pj_uint8_t*)pkt;
    p_end = p + size;
    while (p < p_end) {
	pjmedia_rtcp_common *common = (pjmedia_rtcp_common*)p;
	unsigned len;

	len = (pj_ntohs((pj_uint16_t)common->length)+1) * 4;
	if (p + len > p_end)
	    break;

	switch(common->pt) {
	case RTCP_SR:
	case RTCP_RR:
	case RTCP_XR:
	    parse_rtcp_report(sess, p, len);
	    break;
	case RTCP_SDES:
	    parse_rtcp_sdes(sess, p, len);
	    break;
	case RTCP_BYE:
	    parse_rtcp_bye(sess, p, len);
	    break;
	case RTCP_RTPFB:
	case RTCP_PSFB:
	    parse_rtcp_fb(sess, p, len);
	    break;
	default:
	    
	    TRACE_((sess->name, "Received unknown RTCP packet type=%d", common->pt));
	    break;
	}

	p += len;
    }
}


PJ_DEF(void) pjmedia_rtcp_build_rtcp(pjmedia_rtcp_session *sess,  void **ret_p_pkt, int *len)
{
    pj_uint32_t expected, expected_interval, received_interval, lost_interval;
    pjmedia_rtcp_sr *sr;
    pjmedia_rtcp_rr *rr;
    pj_timestamp ts_now;
    pjmedia_rtcp_ntp_rec ntp;

    
    pj_get_timestamp(&ts_now);
    pjmedia_rtcp_get_ntp_time(sess, &ntp);


    
    if (sess->stat.tx.pkt != pj_ntohl(sess->rtcp_sr_pkt.sr.sender_pcount)) {
	pj_time_val ts_time;
	pj_uint32_t rtp_ts;

	
	*ret_p_pkt = (void*) &sess->rtcp_sr_pkt;
	*len = sizeof(pjmedia_rtcp_sr_pkt);
	rr = &sess->rtcp_sr_pkt.rr;
	sr = &sess->rtcp_sr_pkt.sr;

	
	sr->sender_pcount = pj_htonl(sess->stat.tx.pkt);

	
	sr->sender_bcount = pj_htonl(sess->stat.tx.bytes);

	
	sr->ntp_sec = pj_htonl(ntp.hi);
	sr->ntp_frac = pj_htonl(ntp.lo);

	
	ts_time.sec = ntp.hi - sess->tv_base.sec - JAN_1970;
	ts_time.msec = (long)(ntp.lo * 1000.0 / 0xFFFFFFFF);
	rtp_ts = sess->rtp_ts_base + (pj_uint32_t)(sess->clock_rate*ts_time.sec) + (pj_uint32_t)(sess->clock_rate*ts_time.msec/1000);

	sr->rtp_ts = pj_htonl(rtp_ts);

	TRACE_((sess->name, "TX RTCP SR: ntp_ts=%p",  ((ntp.hi & 0xFFFF) << 16) + ((ntp.lo & 0xFFFF0000)
				>> 16)));


    } else {
	
	*ret_p_pkt = (void*) &sess->rtcp_rr_pkt;
	*len = sizeof(pjmedia_rtcp_rr_pkt);
	rr = &sess->rtcp_rr_pkt.rr;
	sr = NULL;
    }
    
    
    rr->ssrc = pj_htonl(sess->peer_ssrc);
    rr->last_seq = (sess->seq_ctrl.cycles & 0xFFFF0000L);
    
    sess->rtcp_sr_pkt.rr.last_seq += sess->seq_ctrl.max_seq;
    sess->rtcp_rr_pkt.rr.last_seq += sess->seq_ctrl.max_seq;
    rr->last_seq = pj_htonl(rr->last_seq);


    
    rr->jitter = pj_htonl(sess->jitter >> 4);
    
    
    
    expected = pj_ntohl(rr->last_seq) - sess->seq_ctrl.base_seq;

    

    rr->total_lost_2 = (sess->stat.rx.loss >> 16) & 0xFF;
    rr->total_lost_1 = (sess->stat.rx.loss >> 8) & 0xFF;
    rr->total_lost_0 = (sess->stat.rx.loss & 0xFF);

    
    expected_interval = expected - sess->exp_prior;
    sess->exp_prior = expected;
    
    received_interval = sess->received - sess->rx_prior;
    sess->rx_prior = sess->received;
    
    if (expected_interval >= received_interval)
	lost_interval = expected_interval - received_interval;
    else lost_interval = 0;
    
    if (expected_interval==0 || lost_interval == 0) {
	rr->fract_lost = 0;
    } else {
	rr->fract_lost = (lost_interval << 8) / expected_interval;
    }
    
    if (sess->rx_lsr_time.u64 == 0 || sess->rx_lsr == 0) {
	rr->lsr = 0;
	rr->dlsr = 0;
    } else {
	pj_timestamp ts;
	pj_uint32_t lsr = sess->rx_lsr;
	pj_uint64_t lsr_time = sess->rx_lsr_time.u64;
	pj_uint32_t dlsr;
	
	
	lsr_time = (lsr_time << 16) / sess->ts_freq.u64;

	
	rr->lsr = pj_htonl(lsr);
	
	
	ts.u64 = ts_now.u64;

	
	ts.u64 = (ts.u64 << 16) / sess->ts_freq.u64;

	
	dlsr = (pj_uint32_t)(ts.u64 - lsr_time);
	rr->dlsr = pj_htonl(dlsr);

	TRACE_((sess->name,"Tx RTCP RR: lsr=%p, lsr_time=%p, now=%p, dlsr=%p" "(%ds:%03dms)", lsr, (pj_uint32_t)lsr_time, (pj_uint32_t)ts.u64, dlsr, dlsr/65536, (dlsr%65536)*1000/65536 ));






    }
    
    
    pj_gettimeofday(&sess->stat.rx.update);
    sess->stat.rx.update_cnt++;
}


PJ_DEF(pj_status_t) pjmedia_rtcp_build_rtcp_sdes( pjmedia_rtcp_session *session, void *buf, pj_size_t *length, const pjmedia_rtcp_sdes *sdes)



{
    pjmedia_rtcp_common *hdr;
    pj_uint8_t *p;
    pj_size_t len;

    PJ_ASSERT_RETURN(session && buf && length && sdes, PJ_EINVAL);

    
    if (sdes->cname.slen > 255 || sdes->name.slen  > 255 || sdes->email.slen > 255 || sdes->phone.slen > 255 || sdes->loc.slen   > 255 || sdes->tool.slen  > 255 || sdes->note.slen  > 255)


    {
	return PJ_EINVAL;
    }

    
    len = sizeof(*hdr);
    if (sdes->cname.slen) len += sdes->cname.slen + 2;
    if (sdes->name.slen)  len += sdes->name.slen  + 2;
    if (sdes->email.slen) len += sdes->email.slen + 2;
    if (sdes->phone.slen) len += sdes->phone.slen + 2;
    if (sdes->loc.slen)   len += sdes->loc.slen   + 2;
    if (sdes->tool.slen)  len += sdes->tool.slen  + 2;
    if (sdes->note.slen)  len += sdes->note.slen  + 2;
    len++; 
    len = ((len+3)/4) * 4;
    if (len > *length)
	return PJ_ETOOSMALL;

    
    hdr = (pjmedia_rtcp_common*)buf;
    pj_memcpy(hdr, &session->rtcp_sr_pkt.common,  sizeof(*hdr));
    hdr->pt = RTCP_SDES;
    hdr->length = pj_htons((pj_uint16_t)(len/4 - 1));

    
    p = (pj_uint8_t*)hdr + sizeof(*hdr);






    BUILD_SDES_ITEM(cname, RTCP_SDES_CNAME);
    BUILD_SDES_ITEM(name,  RTCP_SDES_NAME);
    BUILD_SDES_ITEM(email, RTCP_SDES_EMAIL);
    BUILD_SDES_ITEM(phone, RTCP_SDES_PHONE);
    BUILD_SDES_ITEM(loc,   RTCP_SDES_LOC);
    BUILD_SDES_ITEM(tool,  RTCP_SDES_TOOL);
    BUILD_SDES_ITEM(note,  RTCP_SDES_NOTE);


    
    *p++ = 0;

    
    while ((p-(pj_uint8_t*)buf) % 4)
	*p++ = 0;

    
    pj_assert((int)len == p-(pj_uint8_t*)buf);
    *length = len;

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjmedia_rtcp_build_rtcp_bye(pjmedia_rtcp_session *session, void *buf, pj_size_t *length, const pj_str_t *reason)


{
    pjmedia_rtcp_common *hdr;
    pj_uint8_t *p;
    pj_size_t len;

    PJ_ASSERT_RETURN(session && buf && length, PJ_EINVAL);

    
    if (reason && reason->slen > 255)
	return PJ_EINVAL;

    
    len = sizeof(*hdr);
    if (reason && reason->slen) len += reason->slen + 1;
    len = ((len+3)/4) * 4;
    if (len > *length)
	return PJ_ETOOSMALL;

    
    hdr = (pjmedia_rtcp_common*)buf;
    pj_memcpy(hdr, &session->rtcp_sr_pkt.common,  sizeof(*hdr));
    hdr->pt = RTCP_BYE;
    hdr->length = pj_htons((pj_uint16_t)(len/4 - 1));

    
    p = (pj_uint8_t*)hdr + sizeof(*hdr);
    if (reason && reason->slen) {
	*p++ = (pj_uint8_t)reason->slen;
	pj_memcpy(p, reason->ptr, reason->slen);
	p += reason->slen;
    }

    
    while ((p-(pj_uint8_t*)buf) % 4)
	*p++ = 0;

    pj_assert((int)len == p-(pj_uint8_t*)buf);
    *length = len;

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjmedia_rtcp_enable_xr( pjmedia_rtcp_session *sess,  pj_bool_t enable)
{


    
    if (!(enable ^ sess->xr_enabled))
	return PJ_SUCCESS;

    if (!enable) {
	sess->xr_enabled = PJ_FALSE;
	return PJ_SUCCESS;
    }

    pjmedia_rtcp_xr_init(&sess->xr_session, sess, 0, 1);
    sess->xr_enabled = PJ_TRUE;

    return PJ_SUCCESS;



    PJ_UNUSED_ARG(sess);
    PJ_UNUSED_ARG(enable);
    return PJ_ENOTSUP;


}
