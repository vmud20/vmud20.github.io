



















PJ_DEF(pj_status_t) pjmedia_rtcp_fb_build_nack( pjmedia_rtcp_session *session, void *buf, pj_size_t *length, unsigned nack_cnt, const pjmedia_rtcp_fb_nack nack[])




{
    pjmedia_rtcp_common *hdr;
    pj_uint8_t *p;
    unsigned len, i;

    PJ_ASSERT_RETURN(session && buf && length && nack_cnt && nack, PJ_EINVAL);

    len = (3 + nack_cnt) * 4;
    if (len > *length)
	return PJ_ETOOSMALL;

    
    hdr = (pjmedia_rtcp_common*)buf;
    pj_memcpy(hdr, &session->rtcp_rr_pkt.common,  sizeof(*hdr));
    hdr->pt = RTCP_RTPFB;
    hdr->count = 1; 
    hdr->length = pj_htons((pj_uint16_t)(len/4 - 1));

    
    p = (pj_uint8_t*)hdr + sizeof(*hdr);
    for (i = 0; i < nack_cnt; ++i) {
	pj_uint16_t val;
	val = pj_htons((pj_uint16_t)nack[i].pid);
	pj_memcpy(p, &val, 2);
	val = pj_htons(nack[i].blp);
	pj_memcpy(p+2, &val, 2);
	p += 4;
    }

    
    *length = len;

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_rtcp_fb_build_pli( pjmedia_rtcp_session *session, void *buf, pj_size_t *length)


{
    pjmedia_rtcp_common *hdr;
    unsigned len;

    PJ_ASSERT_RETURN(session && buf && length, PJ_EINVAL);

    len = 12;
    if (len > *length)
	return PJ_ETOOSMALL;

    
    hdr = (pjmedia_rtcp_common*)buf;
    pj_memcpy(hdr, &session->rtcp_rr_pkt.common,  sizeof(*hdr));
    hdr->pt = RTCP_PSFB;
    hdr->count = 1; 
    hdr->length = pj_htons((pj_uint16_t)(len/4 - 1));

    
    *length = len;

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_rtcp_fb_build_sli( pjmedia_rtcp_session *session, void *buf, pj_size_t *length, unsigned sli_cnt, const pjmedia_rtcp_fb_sli sli[])




{
    pjmedia_rtcp_common *hdr;
    pj_uint8_t *p;
    unsigned len, i;

    PJ_ASSERT_RETURN(session && buf && length && sli_cnt && sli, PJ_EINVAL);

    len = (3 + sli_cnt) * 4;
    if (len > *length)
	return PJ_ETOOSMALL;

    
    hdr = (pjmedia_rtcp_common*)buf;
    pj_memcpy(hdr, &session->rtcp_rr_pkt.common,  sizeof(*hdr));
    hdr->pt = RTCP_PSFB;
    hdr->count = 2; 
    hdr->length = pj_htons((pj_uint16_t)(len/4 - 1));

    
    p = (pj_uint8_t*)hdr + sizeof(*hdr);
    for (i = 0; i < sli_cnt; ++i) {
	
	*p++  = (pj_uint8_t)((sli[i].first >> 5) & 0xFF);   
	*p    = (pj_uint8_t)((sli[i].first & 31) << 3);	    
	
	*p++ |= (pj_uint8_t)((sli[i].number >> 10) & 7);    
	*p++  = (pj_uint8_t)((sli[i].number >> 2) & 0xFF);  
	*p    = (pj_uint8_t)((sli[i].number & 3) << 6);	    
	
	*p++ |= (sli[i].pict_id & 63);
    }

    
    *length = len;

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_rtcp_fb_build_rpsi( pjmedia_rtcp_session *session, void *buf, pj_size_t *length, const pjmedia_rtcp_fb_rpsi *rpsi)



{
    pjmedia_rtcp_common *hdr;
    pj_uint8_t *p;
    unsigned bitlen, padlen, len;

    PJ_ASSERT_RETURN(session && buf && length && rpsi, PJ_EINVAL);

    bitlen = rpsi->rpsi_bit_len + 16;
    padlen = (32 - (bitlen % 32)) % 32;
    len = (3 + (bitlen+padlen)/32) * 4;
    if (len > *length)
	return PJ_ETOOSMALL;

    
    hdr = (pjmedia_rtcp_common*)buf;
    pj_memcpy(hdr, &session->rtcp_rr_pkt.common,  sizeof(*hdr));
    hdr->pt = RTCP_PSFB;
    hdr->count = 3; 
    hdr->length = pj_htons((pj_uint16_t)(len/4 - 1));

    
    p = (pj_uint8_t*)hdr + sizeof(*hdr);
    
    *p++ = (pj_uint8_t)padlen;
    
    *p++ = rpsi->pt & 0x7F;
    
    pj_memcpy(p, rpsi->rpsi.ptr, rpsi->rpsi_bit_len/8);
    p += rpsi->rpsi_bit_len/8;
    if (rpsi->rpsi_bit_len % 8) {
	*p++ = *(rpsi->rpsi.ptr + rpsi->rpsi_bit_len/8);
    }
    
    if (padlen >= 8)
	pj_bzero(p, padlen/8);

    
    *length = len;

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_rtcp_fb_setting_default( pjmedia_rtcp_fb_setting *opt)
{
    pj_bzero(opt, sizeof(*opt));
    opt->dont_use_avpf = PJ_TRUE;

    return PJ_SUCCESS;
}


static void pjmedia_rtcp_fb_cap_dup(pj_pool_t *pool, pjmedia_rtcp_fb_cap *dst, const pjmedia_rtcp_fb_cap *src)

{
    pj_strdup(pool, &dst->codec_id, &src->codec_id);
    dst->type = src->type;
    pj_strdup(pool, &dst->type_name, &src->type_name);
    pj_strdup(pool, &dst->param, &src->param);
}



PJ_DEF(void) pjmedia_rtcp_fb_setting_dup( pj_pool_t *pool, pjmedia_rtcp_fb_setting *dst, const pjmedia_rtcp_fb_setting *src)

{
    unsigned i;

    pj_assert(pool && dst && src);

    pj_memcpy(dst, src, sizeof(pjmedia_rtcp_fb_setting));
    for (i = 0; i < src->cap_count; ++i) {
	pjmedia_rtcp_fb_cap_dup(pool, &dst->caps[i], &src->caps[i]);
    }
}



PJ_DEF(void) pjmedia_rtcp_fb_info_dup( pj_pool_t *pool, pjmedia_rtcp_fb_info *dst, const pjmedia_rtcp_fb_info *src)

{
    unsigned i;

    pj_assert(pool && dst && src);

    pj_memcpy(dst, src, sizeof(pjmedia_rtcp_fb_info));
    for (i = 0; i < src->cap_count; ++i) {
	pjmedia_rtcp_fb_cap_dup(pool, &dst->caps[i], &src->caps[i]);
    }
}



struct rtcp_fb_type_name_t {
    pjmedia_rtcp_fb_type     type;
    const char		    *name;
} rtcp_fb_type_name[] = {
    {PJMEDIA_RTCP_FB_ACK,	"ack", {PJMEDIA_RTCP_FB_NACK,	"nack", {PJMEDIA_RTCP_FB_TRR_INT,	"trr-int" };




static pj_status_t add_sdp_attr_rtcp_fb( pj_pool_t *pool, const char *pt, const pjmedia_rtcp_fb_cap *cap, pjmedia_sdp_media *m)


{
    pjmedia_sdp_attr *a;
    char tmp[128];
    pj_str_t val;
    pj_str_t type_name = {0};

    if (cap->type < PJMEDIA_RTCP_FB_OTHER)
	pj_cstr(&type_name, rtcp_fb_type_name[cap->type].name);
    else if (cap->type == PJMEDIA_RTCP_FB_OTHER)
	type_name = cap->type_name;

    if (type_name.slen == 0)
	return PJ_EINVAL;

    
    if (cap->param.slen) {
	pj_ansi_snprintf(tmp, sizeof(tmp), "%s %.*s %.*s", pt, (int)type_name.slen, type_name.ptr, (int)cap->param.slen, cap->param.ptr);

    } else {
	pj_ansi_snprintf(tmp, sizeof(tmp), "%s %.*s", pt, (int)type_name.slen, type_name.ptr);
    }
    pj_strset2(&val, tmp);

    
    a = pjmedia_sdp_attr_create(pool, "rtcp-fb", &val);
    m->attr[m->attr_count++] = a;

    return PJ_SUCCESS;
}


typedef struct sdp_codec_info_t {
    char	 id[32];
    unsigned	 pt;
} sdp_codec_info_t;



static pj_status_t get_codec_info_from_sdp(pjmedia_endpt *endpt, const pjmedia_sdp_media *m, unsigned *sci_cnt, sdp_codec_info_t sci[])


{
    pjmedia_codec_mgr *codec_mgr;
    unsigned j, cnt = 0;
    pjmedia_type type = PJMEDIA_TYPE_UNKNOWN;
    pj_status_t status;

    type = pjmedia_get_type(&m->desc.media);
    if (type != PJMEDIA_TYPE_AUDIO && type != PJMEDIA_TYPE_VIDEO)
	return PJMEDIA_EUNSUPMEDIATYPE;

    codec_mgr = pjmedia_endpt_get_codec_mgr(endpt);
    for (j = 0; j < m->desc.fmt_count && cnt < *sci_cnt; ++j) {
	unsigned pt = 0;
	pt = pj_strtoul(&m->desc.fmt[j]);
	if (pt < 96) {
	    if (type == PJMEDIA_TYPE_AUDIO) {
		const pjmedia_codec_info *ci;
		status = pjmedia_codec_mgr_get_codec_info(codec_mgr, pt, &ci);
		if (status != PJ_SUCCESS)
		    continue;

		pjmedia_codec_info_to_id(ci, sci[cnt].id, sizeof(sci[0].id));
	    } else {

		const pjmedia_vid_codec_info *ci;
		status = pjmedia_vid_codec_mgr_get_codec_info(NULL, pt, &ci);
		if (status != PJ_SUCCESS)
		    continue;

		pjmedia_vid_codec_info_to_id(ci, sci[cnt].id, sizeof(sci[0].id));

		continue;

	    }
	} else {
	    pjmedia_sdp_attr *a;
	    pjmedia_sdp_rtpmap r;
	    a = pjmedia_sdp_media_find_attr2(m, "rtpmap", &m->desc.fmt[j]);
	    if (a == NULL)
		continue;
	    status = pjmedia_sdp_attr_get_rtpmap(a, &r);
	    if (status != PJ_SUCCESS)
		continue;

	    if (type == PJMEDIA_TYPE_AUDIO) {
		
		if (r.param.slen) {
		    pj_ansi_snprintf(sci[cnt].id, sizeof(sci[0].id), "%.*s/%d/%.*s", (int)r.enc_name.slen, r.enc_name.ptr, r.clock_rate, (int)r.param.slen, r.param.ptr);



		} else {
		    pj_ansi_snprintf(sci[cnt].id, sizeof(sci[0].id), "%.*s/%d/1", (int)r.enc_name.slen, r.enc_name.ptr, r.clock_rate);


		}
	    } else {
		
		pj_ansi_snprintf(sci[cnt].id, sizeof(sci[0].id), "%.*s/%d", (int)r.enc_name.slen, r.enc_name.ptr, pt);

	    }
	}
	sci[cnt++].pt = pt;
    }
    *sci_cnt = cnt;
    
    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjmedia_rtcp_fb_encode_sdp( pj_pool_t *pool, pjmedia_endpt *endpt, const pjmedia_rtcp_fb_setting *opt, pjmedia_sdp_session *sdp_local, unsigned med_idx, const pjmedia_sdp_session *sdp_remote)





{
    pjmedia_sdp_media *m = sdp_local->media[med_idx];
    unsigned i;
    unsigned sci_cnt = 0;
    sdp_codec_info_t sci[PJMEDIA_MAX_SDP_FMT];
    pj_status_t status;

    PJ_UNUSED_ARG(sdp_remote);

    PJ_ASSERT_RETURN(pool && endpt && opt && sdp_local, PJ_EINVAL);
    PJ_ASSERT_RETURN(med_idx < sdp_local->media_count, PJ_EINVAL);

    
    if (!opt->dont_use_avpf) {
	unsigned proto = pjmedia_sdp_transport_get_proto(&m->desc.transport);
	if (!PJMEDIA_TP_PROTO_HAS_FLAG(proto, PJMEDIA_TP_PROFILE_RTCP_FB)) {
	    pj_str_t new_tp;
	    pj_strdup_with_null(pool, &new_tp, &m->desc.transport);
	    new_tp.ptr[new_tp.slen++] = 'F';
	    m->desc.transport = new_tp;
	}
    }

    
    for (i = 0; i < opt->cap_count; ++i) {
	unsigned j;

	
	if (pj_strcmp2(&opt->caps[i].codec_id, "*") == 0) {
	    status = add_sdp_attr_rtcp_fb(pool, "*", &opt->caps[i], m);
	    if (status != PJ_SUCCESS) {
		PJ_PERROR(3, (THIS_FILE, status, "Failed generating SDP a=rtcp-fb:*"));
	    }
	    continue;
	}

	
	if (sci_cnt == 0) {
	    sci_cnt = PJ_ARRAY_SIZE(sci);
	    status = get_codec_info_from_sdp(endpt, m, &sci_cnt, sci);
	    if (status != PJ_SUCCESS) {
		PJ_PERROR(3, (THIS_FILE, status, "Failed populating codec info from SDP"));
		return status;
	    }
	}

	for (j = 0; j < sci_cnt; ++j) {
	    if (pj_strnicmp2(&opt->caps[i].codec_id, sci[j].id, opt->caps[i].codec_id.slen) == 0)
	    {
		char tmp[4];
		snprintf(tmp, sizeof(tmp), "%d", sci[j].pt);
		status = add_sdp_attr_rtcp_fb(pool, tmp, &opt->caps[i], m);
		if (status != PJ_SUCCESS) {
		    PJ_PERROR(3, (THIS_FILE, status, "Failed generating SDP a=rtcp-fb:%d (%s)", sci[j].pt, opt->caps[i].codec_id.ptr));

		}
		break;
	    }
	}
	if (j == sci_cnt) {
	    
	    PJ_PERROR(6, (THIS_FILE, PJ_ENOTFOUND, "Failed generating SDP a=rtcp-fb for %s", opt->caps[i].codec_id.ptr));

	}
    }

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_rtcp_fb_decode_sdp( pj_pool_t *pool, pjmedia_endpt *endpt, const void *opt, const pjmedia_sdp_session *sdp, unsigned med_idx, pjmedia_rtcp_fb_info *info)





{
    return pjmedia_rtcp_fb_decode_sdp2(pool, endpt, opt, sdp, med_idx, -1, info);
}


PJ_DEF(pj_status_t) pjmedia_rtcp_fb_decode_sdp2( pj_pool_t *pool, pjmedia_endpt *endpt, const void *opt, const pjmedia_sdp_session *sdp, unsigned med_idx, int pt, pjmedia_rtcp_fb_info *info)






{
    unsigned sci_cnt = PJMEDIA_MAX_SDP_FMT;
    sdp_codec_info_t sci[PJMEDIA_MAX_SDP_FMT];
    const pjmedia_sdp_media *m;
    pj_status_t status;
    unsigned i;

    PJ_UNUSED_ARG(opt);

    PJ_ASSERT_RETURN(pool && endpt && opt==NULL && sdp, PJ_EINVAL);
    PJ_ASSERT_RETURN(med_idx < sdp->media_count, PJ_EINVAL);
    PJ_ASSERT_RETURN(pt <= 127, PJ_EINVAL);

    m = sdp->media[med_idx];
    status = get_codec_info_from_sdp(endpt, m, &sci_cnt, sci);
    if (status != PJ_SUCCESS)
	return status;

    pj_bzero(info, sizeof(*info));

    
    for (i = 0; i < m->attr_count; ++i) {
	const pjmedia_sdp_attr *a = m->attr[i];
	pj_str_t token;
	pj_ssize_t tok_idx;
	unsigned j;
	const char *codec_id = NULL;
	pj_str_t type_name = {0};
	pjmedia_rtcp_fb_type type = PJMEDIA_RTCP_FB_OTHER;

	
	if (pj_strcmp2(&a->name, "rtcp-fb") != 0)
	    continue;

	
	tok_idx = pj_strtok2(&a->value, " \t", &token, 0);
	if (tok_idx == a->value.slen)
	    continue;

	if (pj_strcmp2(&token, "*") == 0) {
	    
	    codec_id = "*";
	} else {
	    
	    unsigned pt_ = (unsigned) pj_strtoul2(&token, NULL, 10);
	    for (j = 0; j < sci_cnt; ++j) {
		
		if (pt_ == sci[j].pt && (pt < 0 || pt == (int)pt_)) {
		    codec_id = sci[j].id;
		    break;
		}
	    }
	}

	
	if (!codec_id)
	    continue;

	
	tok_idx = pj_strtok2(&a->value, " \t", &token, tok_idx + token.slen);
	if (tok_idx == a->value.slen)
	    continue;

	for (j = 0; j < PJ_ARRAY_SIZE(rtcp_fb_type_name); ++j) {
	    if (pj_strcmp2(&token, rtcp_fb_type_name[j].name) == 0) {
		type = rtcp_fb_type_name[j].type;
		break;
	    }
	}
	if (type == PJMEDIA_RTCP_FB_OTHER)
	    type_name = token;

	
	pj_strdup2(pool, &info->caps[info->cap_count].codec_id, codec_id);
	info->caps[info->cap_count].type = type;
	if (type == PJMEDIA_RTCP_FB_OTHER)
	    pj_strdup(pool, &info->caps[info->cap_count].type_name, &type_name);

	
	tok_idx = pj_strtok2(&a->value, " \t", &token, tok_idx + token.slen);
	if (tok_idx != a->value.slen)
	    pj_strdup(pool, &info->caps[info->cap_count].param, &token);

	
	if (++info->cap_count == PJMEDIA_RTCP_FB_MAX_CAP)
	    break;
    }

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_rtcp_fb_parse_nack( const void *buf, pj_size_t length, unsigned *nack_cnt, pjmedia_rtcp_fb_nack nack[])



{
    pjmedia_rtcp_common *hdr = (pjmedia_rtcp_common*) buf;
    pj_uint8_t *p;
    unsigned cnt, i;

    PJ_ASSERT_RETURN(buf && nack_cnt && nack, PJ_EINVAL);
    PJ_ASSERT_RETURN(length >= sizeof(pjmedia_rtcp_common), PJ_ETOOSMALL);

    
    if (hdr->pt != RTCP_RTPFB || hdr->count != 1)
	return PJ_ENOTFOUND;

    cnt = pj_ntohs((pj_uint16_t)hdr->length) - 2;
    if (length < (cnt+3)*4)
	return PJ_ETOOSMALL;

    *nack_cnt = PJ_MIN(*nack_cnt, cnt);

    p = (pj_uint8_t*)hdr + sizeof(*hdr);
    for (i = 0; i < *nack_cnt; ++i) {
	pj_uint16_t val;

	pj_memcpy(&val, p, 2);
	nack[i].pid = pj_ntohs(val);
	pj_memcpy(&val, p+2, 2);
	nack[i].blp = pj_ntohs(val);
	p += 4;
    }

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_rtcp_fb_parse_pli( const void *buf, pj_size_t length)

{
    pjmedia_rtcp_common *hdr = (pjmedia_rtcp_common*) buf;

    PJ_ASSERT_RETURN(buf, PJ_EINVAL);
    PJ_ASSERT_RETURN(length >= 12, PJ_ETOOSMALL);

    
    if (hdr->pt != RTCP_PSFB || hdr->count != 1)
	return PJ_ENOTFOUND;

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_rtcp_fb_parse_sli( const void *buf, pj_size_t length, unsigned *sli_cnt, pjmedia_rtcp_fb_sli sli[])



{
    pjmedia_rtcp_common *hdr = (pjmedia_rtcp_common*) buf;
    pj_uint8_t *p;
    unsigned cnt, i;

    PJ_ASSERT_RETURN(buf && sli_cnt && sli, PJ_EINVAL);
    PJ_ASSERT_RETURN(length >= sizeof(pjmedia_rtcp_common), PJ_ETOOSMALL);

    
    if (hdr->pt != RTCP_PSFB || hdr->count != 2)
	return PJ_ENOTFOUND;

    cnt = pj_ntohs((pj_uint16_t)hdr->length) - 2;
    if (length < (cnt+3)*4)
	return PJ_ETOOSMALL;

    *sli_cnt = PJ_MIN(*sli_cnt, cnt);

    p = (pj_uint8_t*)hdr + sizeof(*hdr);
    for (i = 0; i < *sli_cnt; ++i) {
	
	sli[i].first = (p[0] << 5) + ((p[1] & 0xF8) >> 3);
	
	sli[i].number = ((p[1] & 0x07) << 10) + (p[2] << 2) + ((p[3] & 0xC0) >> 6);

	
	sli[i].pict_id = (p[3] & 0x3F);
	p += 4;
    }

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_rtcp_fb_parse_rpsi( const void *buf, pj_size_t length, pjmedia_rtcp_fb_rpsi *rpsi)


{
    pjmedia_rtcp_common *hdr = (pjmedia_rtcp_common*) buf;
    pj_uint8_t *p;
    pj_uint8_t padlen;
    pj_size_t rpsi_len;

    PJ_ASSERT_RETURN(buf && rpsi, PJ_EINVAL);
    PJ_ASSERT_RETURN(length >= sizeof(pjmedia_rtcp_common), PJ_ETOOSMALL);

    
    if (hdr->pt != RTCP_PSFB || hdr->count != 3)
	return PJ_ENOTFOUND;

    rpsi_len = (pj_ntohs((pj_uint16_t)hdr->length)-2) * 4;
    if (length < rpsi_len + 12)
	return PJ_ETOOSMALL;

    p = (pj_uint8_t*)hdr + sizeof(*hdr);
    padlen = *p++;
    rpsi->pt = (*p++ & 0x7F);
    rpsi->rpsi_bit_len = rpsi_len*8 - 16 - padlen;
    pj_strset(&rpsi->rpsi, (char*)p, (rpsi->rpsi_bit_len + 7)/8);

    return PJ_SUCCESS;
}
