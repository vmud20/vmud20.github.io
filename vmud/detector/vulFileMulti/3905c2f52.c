














enum {
    SKIP_WS = 0, SYNTAX_ERROR = 1, };








typedef struct parse_context {
    pj_status_t last_error;
} parse_context;



static void parse_version(pj_scanner *scanner, volatile parse_context *ctx);
static void parse_origin(pj_scanner *scanner, pjmedia_sdp_session *ses, volatile parse_context *ctx);
static void parse_time(pj_scanner *scanner, pjmedia_sdp_session *ses, volatile parse_context *ctx);
static void parse_generic_line(pj_scanner *scanner, pj_str_t *str, volatile parse_context *ctx);
static void parse_connection_info(pj_scanner *scanner, pjmedia_sdp_conn *conn, volatile parse_context *ctx);
static void parse_bandwidth_info(pj_scanner *scanner, pjmedia_sdp_bandw *bandw, volatile parse_context *ctx);
static pjmedia_sdp_attr *parse_attr(pj_pool_t *pool, pj_scanner *scanner, volatile parse_context *ctx);
static void parse_media(pj_scanner *scanner, pjmedia_sdp_media *med, volatile parse_context *ctx);
static void on_scanner_error(pj_scanner *scanner);


static int is_initialized;
static pj_cis_buf_t cis_buf;
static pj_cis_t cs_digit, cs_token;

static void init_sdp_parser(void)
{
    if (is_initialized != 0)
	return;

    pj_enter_critical_section();

    if (is_initialized != 0) {
	pj_leave_critical_section();
	return;
    }
    
    pj_cis_buf_init(&cis_buf);

    pj_cis_init(&cis_buf, &cs_token);
    pj_cis_add_alpha(&cs_token);
    pj_cis_add_num(&cs_token);
    pj_cis_add_str(&cs_token, TOKEN);

    pj_cis_init(&cis_buf, &cs_digit);
    pj_cis_add_num(&cs_digit);

    is_initialized = 1;
    pj_leave_critical_section();
}

PJ_DEF(pjmedia_sdp_attr*) pjmedia_sdp_attr_create( pj_pool_t *pool, const char *name, const pj_str_t *value)

{
    pjmedia_sdp_attr *attr;

    PJ_ASSERT_RETURN(pool && name, NULL);

    attr = PJ_POOL_ALLOC_T(pool, pjmedia_sdp_attr);
    pj_strdup2(pool, &attr->name, name);

    if (value)
	pj_strdup_with_null(pool, &attr->value, value);
    else {
	attr->value.ptr = NULL;
	attr->value.slen = 0;
    }

    return attr;
}

PJ_DEF(pjmedia_sdp_attr*) pjmedia_sdp_attr_clone(pj_pool_t *pool,  const pjmedia_sdp_attr *rhs)
{
    pjmedia_sdp_attr *attr;
    
    PJ_ASSERT_RETURN(pool && rhs, NULL);

    attr = PJ_POOL_ALLOC_T(pool, pjmedia_sdp_attr);

    pj_strdup(pool, &attr->name, &rhs->name);
    pj_strdup_with_null(pool, &attr->value, &rhs->value);

    return attr;
}

PJ_DEF(pjmedia_sdp_attr*) pjmedia_sdp_attr_find (unsigned count,  pjmedia_sdp_attr *const attr_array[], const pj_str_t *name, const pj_str_t *c_fmt)


{
    unsigned i;
    unsigned c_pt = 0xFFFF;

    PJ_ASSERT_RETURN(count <= PJMEDIA_MAX_SDP_ATTR, NULL);

    if (c_fmt)
	c_pt = pj_strtoul(c_fmt);

    for (i=0; i<count; ++i) {
	if (pj_strcmp(&attr_array[i]->name, name) == 0) {
	    const pjmedia_sdp_attr *a = attr_array[i];
	    if (c_fmt) {
		unsigned pt = (unsigned) pj_strtoul2(&a->value, NULL, 10);
		if (pt == c_pt) {
		    return (pjmedia_sdp_attr*)a;
		}
	    } else  return (pjmedia_sdp_attr*)a;
	}
    }
    return NULL;
}

PJ_DEF(pjmedia_sdp_attr*) pjmedia_sdp_attr_find2(unsigned count,  pjmedia_sdp_attr *const attr_array[], const char *c_name, const pj_str_t *c_fmt)


{
    pj_str_t name;

    name.ptr = (char*)c_name;
    name.slen = pj_ansi_strlen(c_name);

    return pjmedia_sdp_attr_find(count, attr_array, &name, c_fmt);
}



PJ_DEF(pj_status_t) pjmedia_sdp_attr_add(unsigned *count, pjmedia_sdp_attr *attr_array[], pjmedia_sdp_attr *attr)

{
    PJ_ASSERT_RETURN(count && attr_array && attr, PJ_EINVAL);
    PJ_ASSERT_RETURN(*count < PJMEDIA_MAX_SDP_ATTR, PJ_ETOOMANY);

    attr_array[*count] = attr;
    (*count)++;

    return PJ_SUCCESS;
}


PJ_DEF(unsigned) pjmedia_sdp_attr_remove_all(unsigned *count, pjmedia_sdp_attr *attr_array[], const char *name)

{
    unsigned i, removed = 0;
    pj_str_t attr_name;

    PJ_ASSERT_RETURN(count && attr_array && name, PJ_EINVAL);
    PJ_ASSERT_RETURN(*count <= PJMEDIA_MAX_SDP_ATTR, PJ_ETOOMANY);

    attr_name.ptr = (char*)name;
    attr_name.slen = pj_ansi_strlen(name);

    for (i=0; i<*count; ) {
	if (pj_strcmp(&attr_array[i]->name, &attr_name)==0) {
	    pj_array_erase(attr_array, sizeof(pjmedia_sdp_attr*), *count, i);
	    --(*count);
	    ++removed;
	} else {
	    ++i;
	}   
    }

    return removed;
}


PJ_DEF(pj_status_t) pjmedia_sdp_attr_remove( unsigned *count, pjmedia_sdp_attr *attr_array[], pjmedia_sdp_attr *attr )

{
    unsigned i, removed=0;

    PJ_ASSERT_RETURN(count && attr_array && attr, PJ_EINVAL);
    PJ_ASSERT_RETURN(*count <= PJMEDIA_MAX_SDP_ATTR, PJ_ETOOMANY);

    for (i=0; i<*count; ) {
	if (attr_array[i] == attr) {
	    pj_array_erase(attr_array, sizeof(pjmedia_sdp_attr*), *count, i);
	    --(*count);
	    ++removed;
	} else {
	    ++i;
	}
    }

    return removed ? PJ_SUCCESS : PJ_ENOTFOUND;
}


PJ_DEF(pj_status_t) pjmedia_sdp_attr_get_rtpmap( const pjmedia_sdp_attr *attr, pjmedia_sdp_rtpmap *rtpmap)
{
    pj_scanner scanner;
    pj_str_t token;
    pj_status_t status = -1;
    char term = 0;
    PJ_USE_EXCEPTION;

    PJ_ASSERT_RETURN(pj_strcmp2(&attr->name, "rtpmap")==0, PJ_EINVALIDOP);

    if (attr->value.slen == 0)
        return PJMEDIA_SDP_EINATTR;

    init_sdp_parser();

    
    if (attr->value.ptr[attr->value.slen] != 0 && attr->value.ptr[attr->value.slen] != '\r' && attr->value.ptr[attr->value.slen] != '\n')

    {
	pj_assert(!"Shouldn't happen");
	term = attr->value.ptr[attr->value.slen];
	attr->value.ptr[attr->value.slen] = '\0';
    }

        
    pj_scan_init(&scanner, (char*)attr->value.ptr, attr->value.slen, PJ_SCAN_AUTOSKIP_WS, &on_scanner_error);

    

    
    rtpmap->pt.slen = rtpmap->param.slen = rtpmap->enc_name.slen = 0;
    rtpmap->clock_rate = 0;

    
    PJ_TRY {

	
	pj_scan_get(&scanner, &cs_token, &rtpmap->pt);


	
	pj_scan_get(&scanner, &cs_token, &rtpmap->enc_name);

	
	if (pj_scan_get_char(&scanner) != '/') {
	    status = PJMEDIA_SDP_EINRTPMAP;
	    goto on_return;
	}


	
	pj_scan_get(&scanner, &cs_digit, &token);
	rtpmap->clock_rate = pj_strtoul(&token);

	
	if (*scanner.curptr == '/') {
	    
	    pj_scan_get_char(&scanner);
	    pj_scan_get(&scanner, &cs_token, &rtpmap->param);
	} else {
	    rtpmap->param.slen = 0;
	}

	status = PJ_SUCCESS;
    }
    PJ_CATCH_ANY {
	status = PJMEDIA_SDP_EINRTPMAP;
    }
    PJ_END;


on_return:
    pj_scan_fini(&scanner);
    if (term) {
	attr->value.ptr[attr->value.slen] = term;
    }
    return status;
}

PJ_DEF(pj_status_t) pjmedia_sdp_attr_get_fmtp( const pjmedia_sdp_attr *attr, pjmedia_sdp_fmtp *fmtp)
{
    const char *p = attr->value.ptr;
    const char *end = attr->value.ptr + attr->value.slen;
    pj_str_t token;

    PJ_ASSERT_RETURN(pj_strcmp2(&attr->name, "fmtp")==0, PJ_EINVALIDOP);

    if (attr->value.slen == 0)
        return PJMEDIA_SDP_EINATTR;

    

    
    token.ptr = (char*)p;
    while (pj_isdigit(*p) && p!=end)
	++p;
    token.slen = p - token.ptr;
    if (token.slen == 0)
	return PJMEDIA_SDP_EINFMTP;

    fmtp->fmt = token;

    
    if (*p != ' ') return PJMEDIA_SDP_EINFMTP;

    
    ++p;

    
    fmtp->fmt_param.ptr = (char*)p;
    fmtp->fmt_param.slen = end - p;

    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjmedia_sdp_attr_get_rtcp(const pjmedia_sdp_attr *attr, pjmedia_sdp_rtcp_attr *rtcp)
{
    pj_scanner scanner;
    pj_str_t token;
    pj_status_t status = -1;
    PJ_USE_EXCEPTION;

    PJ_ASSERT_RETURN(pj_strcmp2(&attr->name, "rtcp")==0, PJ_EINVALIDOP);

    if (attr->value.slen == 0)
        return PJMEDIA_SDP_EINATTR;

    init_sdp_parser();

    

    
    pj_scan_init(&scanner, (char*)attr->value.ptr, attr->value.slen, PJ_SCAN_AUTOSKIP_WS, &on_scanner_error);

    
    rtcp->net_type.slen = rtcp->addr_type.slen = rtcp->addr.slen = 0;

    
    PJ_TRY {

	
	pj_scan_get(&scanner, &cs_token, &token);
	rtcp->port = pj_strtoul(&token);

	
	if (!pj_scan_is_eof(&scanner)) {

	    
	    pj_scan_get(&scanner, &cs_token, &rtcp->net_type);

	    
	    pj_scan_get(&scanner, &cs_token, &rtcp->addr_type);

	    
	    
	    pj_scan_get_until_chr(&scanner, "/ \t\r\n", &rtcp->addr);

	}

	status = PJ_SUCCESS;

    }
    PJ_CATCH_ANY {
	status = PJMEDIA_SDP_EINRTCP;
    }
    PJ_END;

    pj_scan_fini(&scanner);
    return status;
}


PJ_DEF(pjmedia_sdp_attr*) pjmedia_sdp_attr_create_rtcp(pj_pool_t *pool, const pj_sockaddr *a)
{
    enum {
	ATTR_LEN = PJ_INET6_ADDRSTRLEN+16 };
    char tmp_addr[PJ_INET6_ADDRSTRLEN];
    pjmedia_sdp_attr *attr;

    attr = PJ_POOL_ALLOC_T(pool, pjmedia_sdp_attr);
    attr->name = pj_str("rtcp");
    attr->value.ptr = (char*) pj_pool_alloc(pool, ATTR_LEN);
    if (a->addr.sa_family == pj_AF_INET()) {
	attr->value.slen =  pj_ansi_snprintf(attr->value.ptr, ATTR_LEN, "%u IN IP4 %s", pj_sockaddr_get_port(a), pj_sockaddr_print(a, tmp_addr, sizeof(tmp_addr), 0));




    } else if (a->addr.sa_family == pj_AF_INET6()) {
	attr->value.slen =  pj_ansi_snprintf(attr->value.ptr, ATTR_LEN, "%u IN IP6 %s", pj_sockaddr_get_port(a), pj_sockaddr_print(a, tmp_addr, sizeof(tmp_addr), 0));





    } else {
	pj_assert(!"Unsupported address family");
	return NULL;
    }

    return attr;
}


PJ_DEF(pj_status_t) pjmedia_sdp_attr_get_ssrc(const pjmedia_sdp_attr *attr, pjmedia_sdp_ssrc_attr *ssrc)
{
    pj_scanner scanner;
    pj_str_t token;
    pj_status_t status = -1;
    PJ_USE_EXCEPTION;

    PJ_ASSERT_RETURN(pj_strcmp2(&attr->name, "ssrc")==0, PJ_EINVALIDOP);

    if (attr->value.slen == 0)
        return PJMEDIA_SDP_EINATTR;

    init_sdp_parser();

    

    
    pj_scan_init(&scanner, (char*)attr->value.ptr, attr->value.slen, PJ_SCAN_AUTOSKIP_WS, &on_scanner_error);

    
    pj_bzero(ssrc, sizeof(*ssrc));

    
    PJ_TRY {
        pj_str_t scan_attr;

	
	pj_scan_get(&scanner, &cs_digit, &token);
	ssrc->ssrc = pj_strtoul(&token);

    	pj_scan_get_char(&scanner);
	pj_scan_get(&scanner, &cs_token, &scan_attr);
	
	
	if (!pj_scan_is_eof(&scanner) && pj_scan_get_char(&scanner) == ':' && pj_strcmp2(&scan_attr, "cname"))

	{
	    pj_scan_get(&scanner, &cs_token, &ssrc->cname);
	}

	status = PJ_SUCCESS;

    }
    PJ_CATCH_ANY {
	status = PJMEDIA_SDP_EINSSRC;
    }
    PJ_END;

    pj_scan_fini(&scanner);
    return status;
}


PJ_DEF(pjmedia_sdp_attr*) pjmedia_sdp_attr_create_ssrc( pj_pool_t *pool, pj_uint32_t ssrc, const pj_str_t *cname)

{
    pjmedia_sdp_attr *attr;

    if (cname->slen == 0)
        return NULL;

    attr = PJ_POOL_ALLOC_T(pool, pjmedia_sdp_attr);
    attr->name = pj_str("ssrc");
    attr->value.ptr = (char*) pj_pool_alloc(pool, cname->slen+7  + 10 + 1 );

    attr->value.slen = pj_ansi_snprintf(attr->value.ptr, cname->slen+18, "%u cname:%.*s", ssrc, (int)cname->slen, cname->ptr);


    return attr;
}


PJ_DEF(pj_status_t) pjmedia_sdp_attr_to_rtpmap(pj_pool_t *pool, const pjmedia_sdp_attr *attr, pjmedia_sdp_rtpmap **p_rtpmap)

{
    PJ_ASSERT_RETURN(pool && attr && p_rtpmap, PJ_EINVAL);

    *p_rtpmap = PJ_POOL_ALLOC_T(pool, pjmedia_sdp_rtpmap);
    PJ_ASSERT_RETURN(*p_rtpmap, PJ_ENOMEM);

    return pjmedia_sdp_attr_get_rtpmap(attr, *p_rtpmap);
}


PJ_DEF(pj_status_t) pjmedia_sdp_rtpmap_to_attr(pj_pool_t *pool, const pjmedia_sdp_rtpmap *rtpmap, pjmedia_sdp_attr **p_attr)

{
    pjmedia_sdp_attr *attr;
    char tempbuf[128];
    int len;

    
    PJ_ASSERT_RETURN(pool && rtpmap && p_attr, PJ_EINVAL);

    
    PJ_ASSERT_RETURN(rtpmap->enc_name.slen && rtpmap->clock_rate, PJMEDIA_SDP_EINRTPMAP);


    attr = PJ_POOL_ALLOC_T(pool, pjmedia_sdp_attr);
    PJ_ASSERT_RETURN(attr != NULL, PJ_ENOMEM);

    attr->name.ptr = "rtpmap";
    attr->name.slen = 6;

    
    len = pj_ansi_snprintf(tempbuf, sizeof(tempbuf),  "%.*s %.*s/%u%s%.*s", (int)rtpmap->pt.slen, rtpmap->pt.ptr, (int)rtpmap->enc_name.slen, rtpmap->enc_name.ptr, rtpmap->clock_rate, (rtpmap->param.slen ? "/" : ""), (int)rtpmap->param.slen, rtpmap->param.ptr);









    if (len < 1 || len >= (int)sizeof(tempbuf))
	return PJMEDIA_SDP_ERTPMAPTOOLONG;

    attr->value.slen = len;
    attr->value.ptr = (char*) pj_pool_alloc(pool, attr->value.slen+1);
    pj_memcpy(attr->value.ptr, tempbuf, attr->value.slen+1);

    *p_attr = attr;
    return PJ_SUCCESS;
}


static int print_connection_info( pjmedia_sdp_conn *c, char *buf, int len)
{
    int printed;

    printed = pj_ansi_snprintf(buf, len, "c=%.*s %.*s %.*s\r\n", (int)c->net_type.slen, c->net_type.ptr, (int)c->addr_type.slen, c->addr_type.ptr, (int)c->addr.slen, c->addr.ptr);





    if (printed < 1 || printed >= len)
	return -1;

    return printed;
}


PJ_DEF(pjmedia_sdp_conn*) pjmedia_sdp_conn_clone (pj_pool_t *pool,  const pjmedia_sdp_conn *rhs)
{
    pjmedia_sdp_conn *c = PJ_POOL_ALLOC_T(pool, pjmedia_sdp_conn);
    if (!c) return NULL;

    if (!pj_strdup (pool, &c->net_type, &rhs->net_type)) return NULL;
    if (!pj_strdup (pool, &c->addr_type, &rhs->addr_type)) return NULL;
    if (!pj_strdup (pool, &c->addr, &rhs->addr)) return NULL;

    return c;
}

PJ_DEF(pjmedia_sdp_bandw*)
pjmedia_sdp_bandw_clone (pj_pool_t *pool,  const pjmedia_sdp_bandw *rhs)
{
    pjmedia_sdp_bandw *b = PJ_POOL_ALLOC_T(pool, pjmedia_sdp_bandw);
    if (!b) return NULL;

    if (!pj_strdup (pool, &b->modifier, &rhs->modifier)) return NULL;
    b->value = rhs->value;

    return b;
}

static pj_ssize_t print_bandw(const pjmedia_sdp_bandw *bandw, char *buf, pj_size_t len)
{
    char *p = buf;

    if ((int)len < bandw->modifier.slen + 10 + 5)
	return -1;

    *p++ = 'b';
    *p++ = '=';
    pj_memcpy(p, bandw->modifier.ptr, bandw->modifier.slen);
    p += bandw->modifier.slen;
    *p++ = ':';
    p += pj_utoa(bandw->value, p);

    *p++ = '\r';
    *p++ = '\n';
    return p-buf;
}

static pj_ssize_t print_attr(const pjmedia_sdp_attr *attr,  char *buf, pj_size_t len)
{
    char *p = buf;

    if ((int)len < attr->name.slen + attr->value.slen + 10)
	return -1;

    *p++ = 'a';
    *p++ = '=';
    pj_memcpy(p, attr->name.ptr, attr->name.slen);
    p += attr->name.slen;
    

    if (attr->value.slen) {
	*p++ = ':';
	pj_memcpy(p, attr->value.ptr, attr->value.slen);
	p += attr->value.slen;
    }

    *p++ = '\r';
    *p++ = '\n';
    return p-buf;
}

static int print_media_desc(const pjmedia_sdp_media *m, char *buf, pj_size_t len)
{
    char *p = buf;
    char *end = buf+len;
    unsigned i;
    int printed;

    
    if (len < (pj_size_t)m->desc.media.slen+m->desc.transport.slen+12+24) {
	return -1;
    }
    *p++ = 'm';	    
    *p++ = '=';
    pj_memcpy(p, m->desc.media.ptr, m->desc.media.slen);
    p += m->desc.media.slen;
    *p++ = ' ';
    printed = pj_utoa(m->desc.port, p);
    p += printed;
    if (m->desc.port_count > 1) {
	*p++ = '/';
	printed = pj_utoa(m->desc.port_count, p);
	p += printed;
    }
    *p++ = ' ';
    pj_memcpy(p, m->desc.transport.ptr, m->desc.transport.slen);
    p += m->desc.transport.slen;
    for (i=0; i<m->desc.fmt_count; ++i) {
	if (end-p > m->desc.fmt[i].slen) {
	    *p++ = ' ';
	    pj_memcpy(p, m->desc.fmt[i].ptr, m->desc.fmt[i].slen);
	    p += m->desc.fmt[i].slen;
	} else {
	    return -1;
	}
    }

    if (end-p >= 2) {
	*p++ = '\r';
	*p++ = '\n';
    } else {
	return -1;
    }

    
    if (m->conn) {
	printed = print_connection_info(m->conn, p, (int)(end-p));
	if (printed < 0) {
	    return -1;
	}
	p += printed;
    }
    
    
    for (i=0; i<m->bandw_count; ++i) {
	printed = (int)print_bandw(m->bandw[i], p, end-p);
	if (printed < 0) {
	    return -1;
	}
	p += printed;
    }

    
    for (i=0; i<m->attr_count; ++i) {
	printed = (int)print_attr(m->attr[i], p, end-p);
	if (printed < 0) {
	    return -1;
	}
	p += printed;
    }

    return (int)(p-buf);
}

PJ_DEF(int) pjmedia_sdp_media_print(const pjmedia_sdp_media *media, char *buf, pj_size_t size)
{
	return print_media_desc(media, buf, size);
}

PJ_DEF(pjmedia_sdp_media*) pjmedia_sdp_media_clone( pj_pool_t *pool, const pjmedia_sdp_media *rhs)

{
    unsigned int i;
    pjmedia_sdp_media *m = PJ_POOL_ALLOC_T(pool, pjmedia_sdp_media);
    PJ_ASSERT_RETURN(m != NULL, NULL);

    pj_strdup (pool, &m->desc.media, &rhs->desc.media);
    m->desc.port = rhs->desc.port;
    m->desc.port_count = rhs->desc.port_count;
    pj_strdup (pool, &m->desc.transport, &rhs->desc.transport);
    m->desc.fmt_count = rhs->desc.fmt_count;
    for (i=0; i<rhs->desc.fmt_count; ++i)
	pj_strdup(pool, &m->desc.fmt[i], &rhs->desc.fmt[i]);

    if (rhs->conn) {
	m->conn = pjmedia_sdp_conn_clone (pool, rhs->conn);
	PJ_ASSERT_RETURN(m->conn != NULL, NULL);
    } else {
	m->conn = NULL;
    }

    m->bandw_count = rhs->bandw_count;
    for (i=0; i < rhs->bandw_count; ++i) {
	m->bandw[i] = pjmedia_sdp_bandw_clone (pool, rhs->bandw[i]);
	PJ_ASSERT_RETURN(m->bandw[i] != NULL, NULL);
    }

    m->attr_count = rhs->attr_count;
    for (i=0; i < rhs->attr_count; ++i) {
	m->attr[i] = pjmedia_sdp_attr_clone (pool, rhs->attr[i]);
	PJ_ASSERT_RETURN(m->attr[i] != NULL, NULL);
    }

    return m;
}

PJ_DEF(pjmedia_sdp_attr*) pjmedia_sdp_media_find_attr( const pjmedia_sdp_media *m, const pj_str_t *name, const pj_str_t *fmt)

{
    PJ_ASSERT_RETURN(m && name, NULL);
    return pjmedia_sdp_attr_find(m->attr_count, m->attr, name, fmt);
}



PJ_DEF(pjmedia_sdp_attr*) pjmedia_sdp_media_find_attr2( const pjmedia_sdp_media *m, const char *name, const pj_str_t *fmt)

{
    PJ_ASSERT_RETURN(m && name, NULL);
    return pjmedia_sdp_attr_find2(m->attr_count, m->attr, name, fmt);
}


PJ_DEF(pj_status_t) pjmedia_sdp_media_add_attr( pjmedia_sdp_media *m, pjmedia_sdp_attr *attr)
{
    return pjmedia_sdp_attr_add(&m->attr_count, m->attr, attr);
}

PJ_DEF(pj_status_t) pjmedia_sdp_session_add_attr(pjmedia_sdp_session *s, pjmedia_sdp_attr *attr)
{
    return pjmedia_sdp_attr_add(&s->attr_count, s->attr, attr);
}

PJ_DEF(unsigned) pjmedia_sdp_media_remove_all_attr(pjmedia_sdp_media *m, const char *name)
{
    return pjmedia_sdp_attr_remove_all(&m->attr_count, m->attr, name);
}

PJ_DEF(pj_status_t) pjmedia_sdp_media_remove_attr(pjmedia_sdp_media *m, pjmedia_sdp_attr *attr)
{
    return pjmedia_sdp_attr_remove(&m->attr_count, m->attr, attr);
}

static int print_session(const pjmedia_sdp_session *ses,  char *buf, pj_ssize_t len)
{
    char *p = buf;
    char *end = buf+len;
    unsigned i;
    int printed;

    
    if (len < 5+  2+ses->origin.user.slen+18+ ses->origin.net_type.slen+ses->origin.addr.slen + 2)

    {
	return -1;
    }

    
    pj_memcpy(p, "v=0\r\n", 5);
    p += 5;

    
    *p++ = 'o';
    *p++ = '=';
    pj_memcpy(p, ses->origin.user.ptr, ses->origin.user.slen);
    p += ses->origin.user.slen;
    *p++ = ' ';
    printed = pj_utoa(ses->origin.id, p);
    p += printed;
    *p++ = ' ';
    printed = pj_utoa(ses->origin.version, p);
    p += printed;
    *p++ = ' ';
    pj_memcpy(p, ses->origin.net_type.ptr, ses->origin.net_type.slen);
    p += ses->origin.net_type.slen;
    *p++ = ' ';
    pj_memcpy(p, ses->origin.addr_type.ptr, ses->origin.addr_type.slen);
    p += ses->origin.addr_type.slen;
    *p++ = ' ';
    pj_memcpy(p, ses->origin.addr.ptr, ses->origin.addr.slen);
    p += ses->origin.addr.slen;
    *p++ = '\r';
    *p++ = '\n';

    
    if ((end-p)  < 8+ses->name.slen) {
	return -1;
    }
    *p++ = 's';
    *p++ = '=';
    pj_memcpy(p, ses->name.ptr, ses->name.slen);
    p += ses->name.slen;
    *p++ = '\r';
    *p++ = '\n';

    
    if (ses->conn) {
	printed = print_connection_info(ses->conn, p, (int)(end-p));
	if (printed < 1) {
	    return -1;
	}
	p += printed;
    }

    
    for (i=0; i<ses->bandw_count; ++i) {
	printed = (int)print_bandw(ses->bandw[i], p, end-p);
	if (printed < 1) {
	    return -1;
	}
	p += printed;
    }

    
    if ((end-p) < 24) {
	return -1;
    }
    *p++ = 't';
    *p++ = '=';
    printed = pj_utoa(ses->time.start, p);
    p += printed;
    *p++ = ' ';
    printed = pj_utoa(ses->time.stop, p);
    p += printed;
    *p++ = '\r';
    *p++ = '\n';

    
    for (i=0; i<ses->attr_count; ++i) {
	printed = (int)print_attr(ses->attr[i], p, end-p);
	if (printed < 0) {
	    return -1;
	}
	p += printed;
    }

    
    for (i=0; i<ses->media_count; ++i) {
	printed = print_media_desc(ses->media[i], p, (int)(end-p));
	if (printed < 0) {
	    return -1;
	}
	p += printed;
    }

    return (int)(p-buf);
}



static void parse_version(pj_scanner *scanner,  volatile parse_context *ctx)
{
    ctx->last_error = PJMEDIA_SDP_EINVER;

    
    if (*(scanner->curptr+1) != '=') {
	on_scanner_error(scanner);
	return;
    }

    
    if (*(scanner->curptr+2) != '0') {
	on_scanner_error(scanner);
	return;
    }

    
    pj_scan_skip_line(scanner);
}

static void parse_origin(pj_scanner *scanner, pjmedia_sdp_session *ses, volatile parse_context *ctx)
{
    pj_str_t str;

    ctx->last_error = PJMEDIA_SDP_EINORIGIN;

    
    if (*(scanner->curptr+1) != '=') {
	on_scanner_error(scanner);
	return;
    }

    
    pj_scan_advance_n(scanner, 2, SKIP_WS);

    
    pj_scan_get_until_ch(scanner, ' ', &ses->origin.user);
    pj_scan_get_char(scanner);

    
    pj_scan_get_until_ch(scanner, ' ', &str);
    ses->origin.id = pj_strtoul(&str);
    pj_scan_get_char(scanner);

    
    pj_scan_get_until_ch(scanner, ' ', &str);
    ses->origin.version = pj_strtoul(&str);
    pj_scan_get_char(scanner);

    
    pj_scan_get_until_ch(scanner, ' ', &ses->origin.net_type);
    pj_scan_get_char(scanner);

    
    pj_scan_get_until_ch(scanner, ' ', &ses->origin.addr_type);
    pj_scan_get_char(scanner);

    
    pj_scan_get_until_chr(scanner, " \t\r\n", &ses->origin.addr);

    
    pj_scan_skip_line(scanner);

}

static void parse_time(pj_scanner *scanner, pjmedia_sdp_session *ses, volatile parse_context *ctx)
{
    pj_str_t str;

    ctx->last_error = PJMEDIA_SDP_EINTIME;

    
    if (*(scanner->curptr+1) != '=') {
	on_scanner_error(scanner);
	return;
    }

    
    pj_scan_advance_n(scanner, 2, SKIP_WS);

    
    pj_scan_get_until_ch(scanner, ' ', &str);
    ses->time.start = pj_strtoul(&str);

    pj_scan_get_char(scanner);

    
    pj_scan_get_until_chr(scanner, " \t\r\n", &str);
    ses->time.stop = pj_strtoul(&str);

    
    pj_scan_skip_line(scanner);
}

static void parse_generic_line(pj_scanner *scanner, pj_str_t *str, volatile parse_context *ctx)
{
    ctx->last_error = PJMEDIA_SDP_EINSDP;

    
    if (*(scanner->curptr+1) != '=') {
	on_scanner_error(scanner);
	return;
    }

    
    pj_scan_advance_n(scanner, 2, SKIP_WS);

    
    pj_scan_get_until_chr(scanner, "\r\n", str);

    
    pj_scan_get_newline(scanner);
}

static void parse_connection_info(pj_scanner *scanner, pjmedia_sdp_conn *conn, volatile parse_context *ctx)
{
    ctx->last_error = PJMEDIA_SDP_EINCONN;

    
    pj_scan_advance_n(scanner, 2, SKIP_WS);

    
    pj_scan_get_until_ch(scanner, ' ', &conn->net_type);
    pj_scan_get_char(scanner);

    
    pj_scan_get_until_ch(scanner, ' ', &conn->addr_type);
    pj_scan_get_char(scanner);

    
    pj_scan_get_until_chr(scanner, "/ \t\r\n", &conn->addr);
    PJ_TODO(PARSE_SDP_CONN_ADDRESS_SUBFIELDS);

    
    pj_scan_skip_line(scanner);
}

static void parse_bandwidth_info(pj_scanner *scanner, pjmedia_sdp_bandw *bandw, volatile parse_context *ctx)
{
    pj_str_t str;

    ctx->last_error = PJMEDIA_SDP_EINBANDW;

    
    pj_scan_advance_n(scanner, 2, SKIP_WS);

    
    pj_scan_get_until_ch(scanner, ':', &bandw->modifier);
    pj_scan_get_char(scanner);

    
    pj_scan_get_until_chr(scanner, " \t\r\n", &str);
    bandw->value = pj_strtoul(&str);

    
    pj_scan_skip_line(scanner);
}

static void parse_media(pj_scanner *scanner, pjmedia_sdp_media *med, volatile parse_context *ctx)
{
    pj_str_t str;

    ctx->last_error = PJMEDIA_SDP_EINMEDIA;

    
    if (*(scanner->curptr+1) != '=') {
	on_scanner_error(scanner);
	return;
    }

    
    pj_scan_advance_n(scanner, 2, SKIP_WS);

    
    pj_scan_get_until_ch(scanner, ' ', &med->desc.media);
    pj_scan_get_char(scanner);

    
    pj_scan_get(scanner, &cs_token, &str);
    med->desc.port = (unsigned short)pj_strtoul(&str);
    if (*scanner->curptr == '/') {
	
	pj_scan_get_char(scanner);
	pj_scan_get(scanner, &cs_token, &str);
	med->desc.port_count = pj_strtoul(&str);

    } else {
	med->desc.port_count = 0;
    }

    if (pj_scan_get_char(scanner) != ' ') {
	PJ_THROW(SYNTAX_ERROR);
    }

    
    pj_scan_get_until_chr(scanner, " \t\r\n", &med->desc.transport);

    
    med->desc.fmt_count = 0;
    while (*scanner->curptr == ' ') {
	pj_str_t fmt;

	pj_scan_get_char(scanner);

	
	if ((*scanner->curptr == '\r') || (*scanner->curptr == '\n'))
		break;

	pj_scan_get(scanner, &cs_token, &fmt);
	if (med->desc.fmt_count < PJMEDIA_MAX_SDP_FMT)
	    med->desc.fmt[med->desc.fmt_count++] = fmt;
	else PJ_PERROR(2,(THIS_FILE, PJ_ETOOMANY, "Error adding SDP media format %.*s, " "format is ignored", (int)fmt.slen, fmt.ptr));



    }

    
    pj_scan_skip_line(scanner);
}

static void on_scanner_error(pj_scanner *scanner)
{
    PJ_UNUSED_ARG(scanner);

    PJ_THROW(SYNTAX_ERROR);
}

static pjmedia_sdp_attr *parse_attr( pj_pool_t *pool, pj_scanner *scanner, volatile parse_context *ctx)
{
    pjmedia_sdp_attr *attr;

    ctx->last_error = PJMEDIA_SDP_EINATTR;

    attr = PJ_POOL_ALLOC_T(pool, pjmedia_sdp_attr);

    
    if (*(scanner->curptr+1) != '=') {
	on_scanner_error(scanner);
	return NULL;
    }

    
    pj_scan_advance_n(scanner, 2, SKIP_WS);
    
    
    pj_scan_get(scanner, &cs_token, &attr->name);

    if (*scanner->curptr && *scanner->curptr != '\r' &&  *scanner->curptr != '\n')
    {
	
	if (*scanner->curptr == ':')
	    pj_scan_get_char(scanner);

	
	if (*scanner->curptr != '\r' && *scanner->curptr != '\n') {
	    pj_scan_get_until_chr(scanner, "\r\n", &attr->value);
	} else {
	    attr->value.ptr = NULL;
	    attr->value.slen = 0;
	}

    } else {
	attr->value.ptr = NULL;
	attr->value.slen = 0;
    }

    
    pj_scan_skip_line(scanner);

    return attr;
}



static void apply_media_direction(pjmedia_sdp_session *sdp)
{
    pjmedia_sdp_attr *dir_attr = NULL;
    unsigned i;

    const pj_str_t inactive = { "inactive", 8 };
    const pj_str_t sendonly = { "sendonly", 8 };
    const pj_str_t recvonly = { "recvonly", 8 };
    const pj_str_t sendrecv = { "sendrecv", 8 };

    
    for (i = 0; i < sdp->attr_count && !dir_attr; ++i) {
	if (!pj_strcmp(&sdp->attr[i]->name, &sendonly) || !pj_strcmp(&sdp->attr[i]->name, &recvonly) || !pj_strcmp(&sdp->attr[i]->name, &inactive))

	{
	    dir_attr = sdp->attr[i];
	}
    }

    
    if (dir_attr) {
	
	pjmedia_sdp_attr_remove(&sdp->attr_count, sdp->attr, dir_attr);

	
	for (i = 0; i < sdp->media_count; ++i) {
	    pjmedia_sdp_media *m;
	    unsigned j;

	    
	    m = sdp->media[i];
	    for (j = 0; j < m->attr_count; ++j) {
		if (!pj_strcmp(&m->attr[j]->name, &sendrecv) || !pj_strcmp(&m->attr[j]->name, &sendonly) || !pj_strcmp(&m->attr[j]->name, &recvonly) || !pj_strcmp(&m->attr[j]->name, &inactive))


		{
		    break;
		}
	    }

	    
	    if (j == m->attr_count)
		pjmedia_sdp_media_add_attr(m, dir_attr);
	}
    }
}



PJ_DEF(pj_status_t) pjmedia_sdp_parse( pj_pool_t *pool, char *buf, pj_size_t len, pjmedia_sdp_session **p_sdp)

{
    pj_scanner scanner;
    pjmedia_sdp_session *session;
    pjmedia_sdp_media *media = NULL;
    pjmedia_sdp_attr *attr;
    pjmedia_sdp_conn *conn;
    pjmedia_sdp_bandw *bandw;
    pj_str_t dummy;
    int cur_name = 254;
    volatile parse_context ctx;
    PJ_USE_EXCEPTION;

    ctx.last_error = PJ_SUCCESS;

    init_sdp_parser();

    pj_scan_init(&scanner, buf, len, 0, &on_scanner_error);
    session = PJ_POOL_ZALLOC_T(pool, pjmedia_sdp_session);
    PJ_ASSERT_RETURN(session != NULL, PJ_ENOMEM);

    
    while (*scanner.curptr=='\r' || *scanner.curptr=='\n')
	pj_scan_get_char(&scanner);

    PJ_TRY {
	while (!pj_scan_is_eof(&scanner)) {
		cur_name = *scanner.curptr;
		switch (cur_name) {
		case 'a':
		    attr = parse_attr(pool, &scanner, &ctx);
		    if (attr) {
			if (media) {
			    if (media->attr_count < PJMEDIA_MAX_SDP_ATTR)
				pjmedia_sdp_media_add_attr(media, attr);
			    else PJ_PERROR(2, (THIS_FILE, PJ_ETOOMANY, "Error adding media attribute, " "attribute is ignored"));


			} else {
			    if (session->attr_count < PJMEDIA_MAX_SDP_ATTR)
				pjmedia_sdp_session_add_attr(session, attr);
			    else PJ_PERROR(2, (THIS_FILE, PJ_ETOOMANY, "Error adding session attribute" ", attribute is ignored"));


			}
		    }
		    break;
		case 'o':
		    parse_origin(&scanner, session, &ctx);
		    break;
		case 's':
		    parse_generic_line(&scanner, &session->name, &ctx);
		    break;
		case 'c':
		    conn = PJ_POOL_ZALLOC_T(pool, pjmedia_sdp_conn);
		    parse_connection_info(&scanner, conn, &ctx);
		    if (media) {
			media->conn = conn;
		    } else {
			session->conn = conn;
		    }
		    break;
		case 't':
		    parse_time(&scanner, session, &ctx);
		    break;
		case 'm':
		    media = PJ_POOL_ZALLOC_T(pool, pjmedia_sdp_media);
		    parse_media(&scanner, media, &ctx);
		    if (session->media_count < PJMEDIA_MAX_SDP_MEDIA)
			session->media[ session->media_count++ ] = media;
		    else PJ_PERROR(2,(THIS_FILE, PJ_ETOOMANY, "Error adding media, media is ignored"));

		    break;
		case 'v':
		    parse_version(&scanner, &ctx);
		    break;
		case 13:
		case 10:
		    pj_scan_get_char(&scanner);
		    
		    while (!pj_scan_is_eof(&scanner)) {
			if (*scanner.curptr != 13 && *scanner.curptr != 10) {
			    ctx.last_error = PJMEDIA_SDP_EINSDP;
			    on_scanner_error(&scanner);
			}
			pj_scan_get_char(&scanner);
		    }
		    break;
		case 'b':
		    bandw = PJ_POOL_ZALLOC_T(pool, pjmedia_sdp_bandw);
		    parse_bandwidth_info(&scanner, bandw, &ctx);
		    if (media) {
			if (media->bandw_count < PJMEDIA_MAX_SDP_BANDW)
			    media->bandw[media->bandw_count++] = bandw;
			else PJ_PERROR(2, (THIS_FILE, PJ_ETOOMANY, "Error adding media bandwidth " "info, info is ignored"));


		    } else {
			if (session->bandw_count < PJMEDIA_MAX_SDP_BANDW)
			    session->bandw[session->bandw_count++] = bandw;
			else PJ_PERROR(2, (THIS_FILE, PJ_ETOOMANY, "Error adding session bandwidth " "info, info is ignored"));


		    }
		    break;
		default:
		    if (cur_name >= 'a' && cur_name <= 'z')
			parse_generic_line(&scanner, &dummy, &ctx);
		    else  {
			ctx.last_error = PJMEDIA_SDP_EINSDP;
			on_scanner_error(&scanner);
		    }
		    break;
		}
	}

	ctx.last_error = PJ_SUCCESS;

    }
    PJ_CATCH_ANY {		
	PJ_PERROR(4, (THIS_FILE, ctx.last_error, "Error parsing SDP in line %d col %d", scanner.line, pj_scan_get_col(&scanner)));


	session = NULL;

	pj_assert(ctx.last_error != PJ_SUCCESS);
    }
    PJ_END;

    pj_scan_fini(&scanner);

    if (session)
	apply_media_direction(session);

    *p_sdp = session;
    return ctx.last_error;
}


PJ_DEF(int) pjmedia_sdp_print( const pjmedia_sdp_session *desc,  char *buf, pj_size_t size)
{
    return print_session(desc, buf, size);
}



PJ_DEF(pjmedia_sdp_session*) pjmedia_sdp_session_clone( pj_pool_t *pool, const pjmedia_sdp_session *rhs)
{
    pjmedia_sdp_session *sess;
    unsigned i;

    PJ_ASSERT_RETURN(pool && rhs, NULL);

    sess = PJ_POOL_ZALLOC_T(pool, pjmedia_sdp_session);
    PJ_ASSERT_RETURN(sess != NULL, NULL);

    
    pj_strdup(pool, &sess->origin.user, &rhs->origin.user);
    sess->origin.id = rhs->origin.id;
    sess->origin.version = rhs->origin.version;
    pj_strdup(pool, &sess->origin.net_type, &rhs->origin.net_type);
    pj_strdup(pool, &sess->origin.addr_type, &rhs->origin.addr_type);
    pj_strdup(pool, &sess->origin.addr, &rhs->origin.addr);

    
    pj_strdup(pool, &sess->name, &rhs->name);

    
    if (rhs->conn) {
	sess->conn = pjmedia_sdp_conn_clone(pool, rhs->conn);
	PJ_ASSERT_RETURN(sess->conn != NULL, NULL);
    }

    
    sess->bandw_count = rhs->bandw_count;
    for (i=0; i<rhs->bandw_count; ++i) {
	sess->bandw[i] = pjmedia_sdp_bandw_clone(pool, rhs->bandw[i]);
    }

    
    sess->time.start = rhs->time.start;
    sess->time.stop = rhs->time.stop;

    
    sess->attr_count = rhs->attr_count;
    for (i=0; i<rhs->attr_count; ++i) {
	sess->attr[i] = pjmedia_sdp_attr_clone(pool, rhs->attr[i]);
    }

    
    sess->media_count = rhs->media_count;
    for (i=0; i<rhs->media_count; ++i) {
	sess->media[i] = pjmedia_sdp_media_clone(pool, rhs->media[i]);
    }

    return sess;
}








static pj_status_t validate_sdp_conn(const pjmedia_sdp_conn *c)
{
    CHECK( c, PJ_EINVAL);
    CHECK( pj_strcmp2(&c->net_type, "IN")==0, PJMEDIA_SDP_EINCONN);
    CHECK( pj_strcmp2(&c->addr_type, "IP4")==0 || pj_strcmp2(&c->addr_type, "IP6")==0, PJMEDIA_SDP_EINCONN);

    CHECK( c->addr.slen != 0, PJMEDIA_SDP_EINCONN);

    return PJ_SUCCESS;
}



PJ_DEF(pj_status_t) pjmedia_sdp_validate(const pjmedia_sdp_session *sdp)
{
    return pjmedia_sdp_validate2(sdp, PJ_TRUE);
}



PJ_DEF(pj_status_t) pjmedia_sdp_validate2(const pjmedia_sdp_session *sdp, pj_bool_t strict)
{
    unsigned i;
    const pj_str_t STR_RTPMAP = { "rtpmap", 6 };

    CHECK( sdp != NULL, PJ_EINVAL);

    
    CHECK( sdp->origin.user.slen != 0, PJMEDIA_SDP_EINORIGIN);
    CHECK( pj_strcmp2(&sdp->origin.net_type, "IN")==0,  PJMEDIA_SDP_EINORIGIN);
    CHECK( pj_strcmp2(&sdp->origin.addr_type, "IP4")==0 || pj_strcmp2(&sdp->origin.addr_type, "IP6")==0, PJMEDIA_SDP_EINORIGIN);

    CHECK( sdp->origin.addr.slen != 0, PJMEDIA_SDP_EINORIGIN);

    
    CHECK( sdp->name.slen != 0, PJMEDIA_SDP_EINNAME);

    

    
    if (sdp->conn) {
	pj_status_t status = validate_sdp_conn(sdp->conn);
	if (status != PJ_SUCCESS)
	    return status;
    }

    
    for (i=0; i<sdp->media_count; ++i) {
	const pjmedia_sdp_media *m = sdp->media[i];
	unsigned j;

	
	CHECK( m->desc.media.slen != 0, PJMEDIA_SDP_EINMEDIA);
	CHECK( m->desc.transport.slen != 0, PJMEDIA_SDP_EINMEDIA);
	CHECK( m->desc.fmt_count != 0 || m->desc.port==0, PJMEDIA_SDP_ENOFMT);

	
	if (m->conn) {
	    pj_status_t status = validate_sdp_conn(m->conn);
	    if (status != PJ_SUCCESS)
		return status;
	}

	
	if (m->conn == NULL) {
	    if (sdp->conn == NULL)
		if (strict || m->desc.port != 0)
		    return PJMEDIA_SDP_EMISSINGCONN;
	}

	
	for (j=0; j<m->desc.fmt_count; ++j) {

	    
	    if (pj_isdigit(*m->desc.fmt[j].ptr)) {
		unsigned long pt;
		pj_status_t status = pj_strtoul3(&m->desc.fmt[j], &pt, 10);

		
		CHECK( status == PJ_SUCCESS && pt <= 127, PJMEDIA_SDP_EINPT);

		
		if (m->desc.port != 0 && pt >= 96) {
		    const pjmedia_sdp_attr *a;

		    a = pjmedia_sdp_media_find_attr(m, &STR_RTPMAP,  &m->desc.fmt[j]);
		    CHECK( a != NULL, PJMEDIA_SDP_EMISSINGRTPMAP);
		}
	    }
	}
    }

    
    return PJ_SUCCESS;
}


PJ_DEF(pj_status_t) pjmedia_sdp_transport_cmp( const pj_str_t *t1, const pj_str_t *t2)
{
    pj_uint32_t t1_proto, t2_proto;

    
    if (pj_stricmp(t1, t2) == 0)
	return PJ_SUCCESS;

    
    t1_proto = pjmedia_sdp_transport_get_proto(t1);
    t2_proto = pjmedia_sdp_transport_get_proto(t2);
    if (PJMEDIA_TP_PROTO_HAS_FLAG(t1_proto, PJMEDIA_TP_PROTO_RTP_AVP) &&  PJMEDIA_TP_PROTO_HAS_FLAG(t2_proto, PJMEDIA_TP_PROTO_RTP_AVP))
    {
	return PJ_SUCCESS;
    }

    
    
    
    
    
    
    
    

    return PJMEDIA_SDP_ETPORTNOTEQUAL;
}



PJ_DEF(pj_uint32_t) pjmedia_sdp_transport_get_proto(const pj_str_t *tp)
{
    pj_str_t token, rest = {0};
    pj_ssize_t idx;

    PJ_ASSERT_RETURN(tp, PJMEDIA_TP_PROTO_NONE);

    idx = pj_strtok2(tp, "/", &token, 0);
    if (idx != tp->slen)
	pj_strset(&rest, tp->ptr + token.slen + 1, tp->slen - token.slen - 1);

    if (pj_stricmp2(&token, "RTP") == 0) {
	

	
	if (pj_stricmp2(&rest, "AVP") == 0)
	    return PJMEDIA_TP_PROTO_RTP_AVP;

	
	if (pj_stricmp2(&rest, "SAVP") == 0)
	    return PJMEDIA_TP_PROTO_RTP_SAVP;

	
	if (pj_stricmp2(&rest, "AVPF") == 0)
	    return PJMEDIA_TP_PROTO_RTP_AVPF;

	
	if (pj_stricmp2(&rest, "SAVPF") == 0)
	    return PJMEDIA_TP_PROTO_RTP_SAVPF;

    } else if (pj_stricmp2(&token, "UDP") == 0) {
	

	
	if (rest.slen == 0)
	    return PJMEDIA_TP_PROTO_UDP;

	
	if (pj_stricmp2(&rest, "TLS/RTP/SAVP") == 0)
	    return PJMEDIA_TP_PROTO_DTLS_SRTP;

	
	if (pj_stricmp2(&rest, "TLS/RTP/SAVPF") == 0)
	    return PJMEDIA_TP_PROTO_DTLS_SRTPF;
    }

    
    return PJMEDIA_TP_PROTO_UNKNOWN;
}


PJ_DEF(pj_status_t) pjmedia_sdp_media_deactivate(pj_pool_t *pool, pjmedia_sdp_media *m)
{
    PJ_ASSERT_RETURN(m, PJ_EINVAL);
    PJ_UNUSED_ARG(pool);

    
    m->desc.port = 0;

    
    m->attr_count = 0;

    return PJ_SUCCESS;
}


PJ_DEF(pjmedia_sdp_media*) pjmedia_sdp_media_clone_deactivate( pj_pool_t *pool, const pjmedia_sdp_media *rhs)

{
    unsigned int i;
    pjmedia_sdp_media *m;

    PJ_ASSERT_RETURN(pool && rhs, NULL);

    m = PJ_POOL_ZALLOC_T(pool, pjmedia_sdp_media);
    pj_memcpy(m, rhs, sizeof(*m));

    
    pj_strdup (pool, &m->desc.media, &rhs->desc.media);
    pj_strdup (pool, &m->desc.transport, &rhs->desc.transport);
    for (i=0; i<rhs->desc.fmt_count; ++i)
	pj_strdup(pool, &m->desc.fmt[i], &rhs->desc.fmt[i]);

    if (rhs->conn) {
	m->conn = pjmedia_sdp_conn_clone (pool, rhs->conn);
	PJ_ASSERT_RETURN(m->conn != NULL, NULL);
    }

    m->bandw_count = rhs->bandw_count;
    for (i=0; i < rhs->bandw_count; ++i) {
	m->bandw[i] = pjmedia_sdp_bandw_clone (pool, rhs->bandw[i]);
	PJ_ASSERT_RETURN(m->bandw[i] != NULL, NULL);
    }

    
    pjmedia_sdp_media_deactivate(pool, m);

    return m;
}
