






module AP_MODULE_DECLARE_DATA proxy_http_module;

static apr_status_t ap_proxy_http_cleanup(const char *scheme, request_rec *r, proxy_conn_rec *backend);



static int proxy_http_canon(request_rec *r, char *url)
{
    char *host, *path, sport[7];
    char *search = NULL;
    const char *err;
    const char *scheme;
    apr_port_t port, def_port;

    
    if (strncasecmp(url, "http:", 5) == 0) {
        url += 5;
        scheme = "http";
    }
    else if (strncasecmp(url, "https:", 6) == 0) {
        url += 6;
        scheme = "https";
    }
    else {
        return DECLINED;
    }
    def_port = apr_uri_port_of_scheme(scheme);

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "HTTP: canonicalising URL %s", url);

    
    port = def_port;
    err = ap_proxy_canon_netloc(r->pool, &url, NULL, NULL, &host, &port);
    if (err) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01083)
                      "error parsing URL %s: %s", url, err);
        return HTTP_BAD_REQUEST;
    }

    
    switch (r->proxyreq) {
    default: 
    case PROXYREQ_REVERSE:
        if (apr_table_get(r->notes, "proxy-nocanon")) {
            path = url;   
        }
        else {
            path = ap_proxy_canonenc(r->pool, url, strlen(url), enc_path, 0, r->proxyreq);
            search = r->args;
        }
        break;
    case PROXYREQ_PROXY:
        path = url;
        break;
    }

    if (path == NULL)
        return HTTP_BAD_REQUEST;

    if (port != def_port)
        apr_snprintf(sport, sizeof(sport), ":%d", port);
    else sport[0] = '\0';

    if (ap_strchr_c(host, ':')) { 
        host = apr_pstrcat(r->pool, "[", host, "]", NULL);
    }
    r->filename = apr_pstrcat(r->pool, "proxy:", scheme, "://", host, sport, "/", path, (search) ? "?" : "", (search) ? search : "", NULL);
    return OK;
}


typedef struct header_dptr {
    apr_pool_t *pool;
    apr_table_t *table;
    apr_time_t time;
} header_dptr;
static ap_regex_t *warn_rx;
static int clean_warning_headers(void *data, const char *key, const char *val)
{
    apr_table_t *headers = ((header_dptr*)data)->table;
    apr_pool_t *pool = ((header_dptr*)data)->pool;
    char *warning;
    char *date;
    apr_time_t warn_time;
    const int nmatch = 3;
    ap_regmatch_t pmatch[3];

    if (headers == NULL) {
        ((header_dptr*)data)->table = headers = apr_table_make(pool, 2);
    }

    while (!ap_regexec(warn_rx, val, nmatch, pmatch, 0)) {
        warning = apr_pstrndup(pool, val+pmatch[0].rm_so, pmatch[0].rm_eo - pmatch[0].rm_so);
        warn_time = 0;
        if (pmatch[2].rm_eo > pmatch[2].rm_so) {
            
            date = apr_pstrndup(pool, val+pmatch[2].rm_so, pmatch[2].rm_eo - pmatch[2].rm_so);
            warn_time = apr_date_parse_http(date);
        }
        if (!warn_time || (warn_time == ((header_dptr*)data)->time)) {
            apr_table_addn(headers, key, warning);
        }
        val += pmatch[0].rm_eo;
    }
    return 1;
}
static apr_table_t *ap_proxy_clean_warnings(apr_pool_t *p, apr_table_t *headers)
{
   header_dptr x;
   x.pool = p;
   x.table = NULL;
   x.time = apr_date_parse_http(apr_table_get(headers, "Date"));
   apr_table_do(clean_warning_headers, &x, headers, "Warning", NULL);
   if (x.table != NULL) {
       apr_table_unset(headers, "Warning");
       return apr_table_overlay(p, headers, x.table);
   }
   else {
        return headers;
   }
}
static int clear_conn_headers(void *data, const char *key, const char *val)
{
    apr_table_t *headers = ((header_dptr*)data)->table;
    apr_pool_t *pool = ((header_dptr*)data)->pool;
    const char *name;
    char *next = apr_pstrdup(pool, val);
    while (*next) {
        name = next;
        while (*next && !apr_isspace(*next) && (*next != ',')) {
            ++next;
        }
        while (*next && (apr_isspace(*next) || (*next == ','))) {
            *next++ = '\0';
        }
        apr_table_unset(headers, name);
    }
    return 1;
}
static void ap_proxy_clear_connection(apr_pool_t *p, apr_table_t *headers)
{
    header_dptr x;
    x.pool = p;
    x.table = headers;
    apr_table_unset(headers, "Proxy-Connection");
    apr_table_do(clear_conn_headers, &x, headers, "Connection", NULL);
    apr_table_unset(headers, "Connection");
}
static void add_te_chunked(apr_pool_t *p, apr_bucket_alloc_t *bucket_alloc, apr_bucket_brigade *header_brigade)

{
    apr_bucket *e;
    char *buf;
    const char te_hdr[] = "Transfer-Encoding: chunked" CRLF;

    buf = apr_pmemdup(p, te_hdr, sizeof(te_hdr)-1);
    ap_xlate_proto_to_ascii(buf, sizeof(te_hdr)-1);

    e = apr_bucket_pool_create(buf, sizeof(te_hdr)-1, p, bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
}

static void add_cl(apr_pool_t *p, apr_bucket_alloc_t *bucket_alloc, apr_bucket_brigade *header_brigade, const char *cl_val)


{
    apr_bucket *e;
    char *buf;

    buf = apr_pstrcat(p, "Content-Length: ", cl_val, CRLF, NULL);


    ap_xlate_proto_to_ascii(buf, strlen(buf));
    e = apr_bucket_pool_create(buf, strlen(buf), p, bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
}




static void terminate_headers(apr_bucket_alloc_t *bucket_alloc, apr_bucket_brigade *header_brigade)
{
    apr_bucket *e;

    
    e = apr_bucket_immortal_create(ASCII_CRLF, 2, bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
}

static int pass_brigade(apr_bucket_alloc_t *bucket_alloc, request_rec *r, proxy_conn_rec *p_conn, conn_rec *origin, apr_bucket_brigade *bb, int flush)


{
    apr_status_t status;
    apr_off_t transferred;

    if (flush) {
        apr_bucket *e = apr_bucket_flush_create(bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }
    apr_brigade_length(bb, 0, &transferred);
    if (transferred != -1)
        p_conn->worker->s->transferred += transferred;
    status = ap_pass_brigade(origin->output_filters, bb);
    if (status != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01084)
                      "pass request body failed to %pI (%s)", p_conn->addr, p_conn->hostname);
        if (origin->aborted) {
            const char *ssl_note;

            if (((ssl_note = apr_table_get(origin->notes, "SSL_connect_rv"))
                != NULL) && (strcmp(ssl_note, "err") == 0)) {
                return ap_proxyerror(r, HTTP_INTERNAL_SERVER_ERROR, "Error during SSL Handshake with" " remote server");

            }
            return APR_STATUS_IS_TIMEUP(status) ? HTTP_GATEWAY_TIME_OUT : HTTP_BAD_GATEWAY;
        }
        else {
            return HTTP_BAD_REQUEST;
        }
    }
    apr_brigade_cleanup(bb);
    return OK;
}



static int stream_reqbody_chunked(apr_pool_t *p, request_rec *r, proxy_conn_rec *p_conn, conn_rec *origin, apr_bucket_brigade *header_brigade, apr_bucket_brigade *input_brigade)




{
    int seen_eos = 0, rv = OK;
    apr_size_t hdr_len;
    apr_off_t bytes;
    apr_status_t status;
    apr_bucket_alloc_t *bucket_alloc = r->connection->bucket_alloc;
    apr_bucket_brigade *bb;
    apr_bucket *e;

    add_te_chunked(p, bucket_alloc, header_brigade);
    terminate_headers(bucket_alloc, header_brigade);

    while (!APR_BUCKET_IS_EOS(APR_BRIGADE_FIRST(input_brigade)))
    {
        char chunk_hdr[20];  

        
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
            seen_eos = 1;

            
            e = APR_BRIGADE_LAST(input_brigade);
            apr_bucket_delete(e);
        }

        apr_brigade_length(input_brigade, 1, &bytes);

        hdr_len = apr_snprintf(chunk_hdr, sizeof(chunk_hdr), "%" APR_UINT64_T_HEX_FMT CRLF, (apr_uint64_t)bytes);


        ap_xlate_proto_to_ascii(chunk_hdr, hdr_len);
        e = apr_bucket_transient_create(chunk_hdr, hdr_len, bucket_alloc);
        APR_BRIGADE_INSERT_HEAD(input_brigade, e);

        
        e = apr_bucket_immortal_create(ASCII_CRLF, 2, bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(input_brigade, e);

        if (header_brigade) {
            
            bb = header_brigade;

            
            status = ap_save_brigade(NULL, &bb, &input_brigade, p);
            if (status != APR_SUCCESS) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            header_brigade = NULL;
        }
        else {
            bb = input_brigade;
        }

        
        rv = pass_brigade(bucket_alloc, r, p_conn, origin, bb, 0);
        if (rv != OK) {
            return rv;
        }

        if (seen_eos) {
            break;
        }

        status = ap_get_brigade(r->input_filters, input_brigade, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);


        if (status != APR_SUCCESS) {
            return HTTP_BAD_REQUEST;
        }
    }

    if (header_brigade) {
        
        bb = header_brigade;
    }
    else {
        if (!APR_BRIGADE_EMPTY(input_brigade)) {
            
            e = APR_BRIGADE_LAST(input_brigade);
            AP_DEBUG_ASSERT(APR_BUCKET_IS_EOS(e));
            apr_bucket_delete(e);
        }
        bb = input_brigade;
    }

    e = apr_bucket_immortal_create(ASCII_ZERO ASCII_CRLF  ASCII_CRLF, 5, bucket_alloc);


    APR_BRIGADE_INSERT_TAIL(bb, e);

    if (apr_table_get(r->subprocess_env, "proxy-sendextracrlf")) {
        e = apr_bucket_immortal_create(ASCII_CRLF, 2, bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }

    
    rv = pass_brigade(bucket_alloc, r, p_conn, origin, bb, 1);
    return rv;
}

static int stream_reqbody_cl(apr_pool_t *p, request_rec *r, proxy_conn_rec *p_conn, conn_rec *origin, apr_bucket_brigade *header_brigade, apr_bucket_brigade *input_brigade, const char *old_cl_val)





{
    int seen_eos = 0, rv = 0;
    apr_status_t status = APR_SUCCESS;
    apr_bucket_alloc_t *bucket_alloc = r->connection->bucket_alloc;
    apr_bucket_brigade *bb;
    apr_bucket *e;
    apr_off_t cl_val = 0;
    apr_off_t bytes;
    apr_off_t bytes_streamed = 0;

    if (old_cl_val) {
        char *endstr;

        add_cl(p, bucket_alloc, header_brigade, old_cl_val);
        status = apr_strtoff(&cl_val, old_cl_val, &endstr, 10);

        if (status || *endstr || endstr == old_cl_val || cl_val < 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01085)
                          "could not parse request Content-Length (%s)", old_cl_val);
            return HTTP_BAD_REQUEST;
        }
    }
    terminate_headers(bucket_alloc, header_brigade);

    while (!APR_BUCKET_IS_EOS(APR_BRIGADE_FIRST(input_brigade)))
    {
        apr_brigade_length(input_brigade, 1, &bytes);
        bytes_streamed += bytes;

        
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
            seen_eos = 1;

            
            e = APR_BRIGADE_LAST(input_brigade);
            apr_bucket_delete(e);

            if (apr_table_get(r->subprocess_env, "proxy-sendextracrlf")) {
                e = apr_bucket_immortal_create(ASCII_CRLF, 2, bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(input_brigade, e);
            }
        }

        
        if (bytes_streamed > cl_val) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01086)
                          "read more bytes of request body than expected " "(got %" APR_OFF_T_FMT ", expected %" APR_OFF_T_FMT ")", bytes_streamed, cl_val);

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        if (header_brigade) {
            
            bb = header_brigade;

            
            status = ap_save_brigade(NULL, &bb, &input_brigade, p);
            if (status != APR_SUCCESS) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            header_brigade = NULL;
        }
        else {
            bb = input_brigade;
        }

        
        rv = pass_brigade(bucket_alloc, r, p_conn, origin, bb, seen_eos);
        if (rv != OK) {
            return rv ;
        }

        if (seen_eos) {
            break;
        }

        status = ap_get_brigade(r->input_filters, input_brigade, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);


        if (status != APR_SUCCESS) {
            return HTTP_BAD_REQUEST;
        }
    }

    if (bytes_streamed != cl_val) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01087)
                      "client %s given Content-Length did not match" " number of body bytes read", r->connection->client_ip);
        return HTTP_BAD_REQUEST;
    }

    if (header_brigade) {
        
        bb = header_brigade;
        return(pass_brigade(bucket_alloc, r, p_conn, origin, bb, 1));
    }

    return OK;
}

static int spool_reqbody_cl(apr_pool_t *p, request_rec *r, proxy_conn_rec *p_conn, conn_rec *origin, apr_bucket_brigade *header_brigade, apr_bucket_brigade *input_brigade, int force_cl)





{
    int seen_eos = 0;
    apr_status_t status;
    apr_bucket_alloc_t *bucket_alloc = r->connection->bucket_alloc;
    apr_bucket_brigade *body_brigade;
    apr_bucket *e;
    apr_off_t bytes, bytes_spooled = 0, fsize = 0;
    apr_file_t *tmpfile = NULL;
    apr_off_t limit;

    body_brigade = apr_brigade_create(p, bucket_alloc);

    limit = ap_get_limit_req_body(r);

    while (!APR_BUCKET_IS_EOS(APR_BRIGADE_FIRST(input_brigade)))
    {
        
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
            seen_eos = 1;

            
            e = APR_BRIGADE_LAST(input_brigade);
            apr_bucket_delete(e);
        }

        apr_brigade_length(input_brigade, 1, &bytes);

        if (bytes_spooled + bytes > MAX_MEM_SPOOL) {
            
            if (bytes_spooled + bytes > limit) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01088)
                              "Request body is larger than the configured " "limit of %" APR_OFF_T_FMT, limit);
                return HTTP_REQUEST_ENTITY_TOO_LARGE;
            }
            
            if (tmpfile == NULL) {
                const char *temp_dir;
                char *template;

                status = apr_temp_dir_get(&temp_dir, p);
                if (status != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01089)
                                  "search for temporary directory failed");
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                apr_filepath_merge(&template, temp_dir, "modproxy.tmp.XXXXXX", APR_FILEPATH_NATIVE, p);

                status = apr_file_mktemp(&tmpfile, template, 0, p);
                if (status != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01090)
                                  "creation of temporary file in directory " "%s failed", temp_dir);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
            }
            for (e = APR_BRIGADE_FIRST(input_brigade);
                 e != APR_BRIGADE_SENTINEL(input_brigade);
                 e = APR_BUCKET_NEXT(e)) {
                const char *data;
                apr_size_t bytes_read, bytes_written;

                apr_bucket_read(e, &data, &bytes_read, APR_BLOCK_READ);
                status = apr_file_write_full(tmpfile, data, bytes_read, &bytes_written);
                if (status != APR_SUCCESS) {
                    const char *tmpfile_name;

                    if (apr_file_name_get(&tmpfile_name, tmpfile) != APR_SUCCESS) {
                        tmpfile_name = "(unknown)";
                    }
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01091)
                                  "write to temporary file %s failed", tmpfile_name);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }
                AP_DEBUG_ASSERT(bytes_read == bytes_written);
                fsize += bytes_written;
            }
            apr_brigade_cleanup(input_brigade);
        }
        else {

            
            status = ap_save_brigade(NULL, &body_brigade, &input_brigade, p);
            if (status != APR_SUCCESS) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }

        }

        bytes_spooled += bytes;

        if (seen_eos) {
            break;
        }

        status = ap_get_brigade(r->input_filters, input_brigade, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);


        if (status != APR_SUCCESS) {
            return HTTP_BAD_REQUEST;
        }
    }

    if (bytes_spooled || force_cl) {
        add_cl(p, bucket_alloc, header_brigade, apr_off_t_toa(p, bytes_spooled));
    }
    terminate_headers(bucket_alloc, header_brigade);
    APR_BRIGADE_CONCAT(header_brigade, body_brigade);
    if (tmpfile) {
        apr_brigade_insert_file(header_brigade, tmpfile, 0, fsize, p);
    }
    if (apr_table_get(r->subprocess_env, "proxy-sendextracrlf")) {
        e = apr_bucket_immortal_create(ASCII_CRLF, 2, bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(header_brigade, e);
    }
    
    return(pass_brigade(bucket_alloc, r, p_conn, origin, header_brigade, 1));
}


static apr_status_t proxy_buckets_lifetime_transform(request_rec *r, apr_bucket_brigade *from, apr_bucket_brigade *to)
{
    apr_bucket *e;
    apr_bucket *new;
    const char *data;
    apr_size_t bytes;
    apr_status_t rv = APR_SUCCESS;

    apr_brigade_cleanup(to);
    for (e = APR_BRIGADE_FIRST(from);
         e != APR_BRIGADE_SENTINEL(from);
         e = APR_BUCKET_NEXT(e)) {
        if (!APR_BUCKET_IS_METADATA(e)) {
            apr_bucket_read(e, &data, &bytes, APR_BLOCK_READ);
            new = apr_bucket_transient_create(data, bytes, r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(to, new);
        }
        else if (APR_BUCKET_IS_FLUSH(e)) {
            new = apr_bucket_flush_create(r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(to, new);
        }
        else if (APR_BUCKET_IS_EOS(e)) {
            new = apr_bucket_eos_create(r->connection->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(to, new);
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00964)
                          "Unhandled bucket type of type %s in" " proxy_buckets_lifetime_transform", e->type->name);
            apr_bucket_delete(e);
            rv = APR_EGENERAL;
        }
    }
    return rv;
}

static int ap_proxy_http_request(apr_pool_t *p, request_rec *r, proxy_conn_rec *p_conn, proxy_worker *worker, proxy_server_conf *conf, apr_uri_t *uri, char *url, char *server_portstr)




{
    conn_rec *c = r->connection;
    apr_bucket_alloc_t *bucket_alloc = c->bucket_alloc;
    apr_bucket_brigade *header_brigade;
    apr_bucket_brigade *input_brigade;
    apr_bucket_brigade *temp_brigade;
    apr_bucket *e;
    char *buf;
    const apr_array_header_t *headers_in_array;
    const apr_table_entry_t *headers_in;
    int counter;
    apr_status_t status;
    enum rb_methods {RB_INIT, RB_STREAM_CL, RB_STREAM_CHUNKED, RB_SPOOL_CL};
    enum rb_methods rb_method = RB_INIT;
    const char *old_cl_val = NULL;
    const char *old_te_val = NULL;
    apr_off_t bytes_read = 0;
    apr_off_t bytes;
    int force10, rv;
    apr_table_t *headers_in_copy;
    proxy_dir_conf *dconf;
    conn_rec *origin = p_conn->connection;
    int do_100_continue;

    dconf = ap_get_module_config(r->per_dir_config, &proxy_module);
    header_brigade = apr_brigade_create(p, origin->bucket_alloc);

    

    
    do_100_continue = (worker->s->ping_timeout_set && ap_request_has_body(r)
                       && (PROXYREQ_REVERSE == r->proxyreq)
                       && !(apr_table_get(r->subprocess_env, "force-proxy-request-1.0")));

    if (apr_table_get(r->subprocess_env, "force-proxy-request-1.0")) {
        
        if (r->expecting_100) {
            return HTTP_EXPECTATION_FAILED;
        }
        buf = apr_pstrcat(p, r->method, " ", url, " HTTP/1.0" CRLF, NULL);
        force10 = 1;
        p_conn->close++;
    } else {
        buf = apr_pstrcat(p, r->method, " ", url, " HTTP/1.1" CRLF, NULL);
        force10 = 0;
    }
    if (apr_table_get(r->subprocess_env, "proxy-nokeepalive")) {
        origin->keepalive = AP_CONN_CLOSE;
        p_conn->close++;
    }
    ap_xlate_proto_to_ascii(buf, strlen(buf));
    e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);
    if (dconf->preserve_host == 0) {
        if (ap_strchr_c(uri->hostname, ':')) { 
            if (uri->port_str && uri->port != DEFAULT_HTTP_PORT) {
                buf = apr_pstrcat(p, "Host: [", uri->hostname, "]:", uri->port_str, CRLF, NULL);
            } else {
                buf = apr_pstrcat(p, "Host: [", uri->hostname, "]", CRLF, NULL);
            }
        } else {
            if (uri->port_str && uri->port != DEFAULT_HTTP_PORT) {
                buf = apr_pstrcat(p, "Host: ", uri->hostname, ":", uri->port_str, CRLF, NULL);
            } else {
                buf = apr_pstrcat(p, "Host: ", uri->hostname, CRLF, NULL);
            }
        }
    }
    else {
        
        const char* hostname = apr_table_get(r->headers_in,"Host");
        if (!hostname) {
            hostname =  r->server->server_hostname;
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01092)
                          "no HTTP 0.9 request (with no host line) " "on incoming request and preserve host set " "forcing hostname to be %s for uri %s", hostname, r->uri);


        }
        buf = apr_pstrcat(p, "Host: ", hostname, CRLF, NULL);
    }
    ap_xlate_proto_to_ascii(buf, strlen(buf));
    e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(header_brigade, e);

    
    if (conf->viaopt == via_block) {
        
        apr_table_unset(r->headers_in, "Via");
    } else if (conf->viaopt != via_off) {
        const char *server_name = ap_get_server_name(r);
        
        if (server_name == r->hostname)
            server_name = r->server->server_hostname;
        
        
        apr_table_mergen(r->headers_in, "Via", (conf->viaopt == via_full)
                         ? apr_psprintf(p, "%d.%d %s%s (%s)", HTTP_VERSION_MAJOR(r->proto_num), HTTP_VERSION_MINOR(r->proto_num), server_name, server_portstr, AP_SERVER_BASEVERSION)



                         : apr_psprintf(p, "%d.%d %s%s", HTTP_VERSION_MAJOR(r->proto_num), HTTP_VERSION_MINOR(r->proto_num), server_name, server_portstr)


        );
    }

    
    if (do_100_continue) {
        apr_table_mergen(r->headers_in, "Expect", "100-Continue");
        r->expecting_100 = 1;
    }

    
    if (dconf->add_forwarded_headers) {
       if (PROXYREQ_REVERSE == r->proxyreq) {
           const char *buf;

           
           apr_table_mergen(r->headers_in, "X-Forwarded-For", r->useragent_ip);

           
           if ((buf = apr_table_get(r->headers_in, "Host"))) {
               apr_table_mergen(r->headers_in, "X-Forwarded-Host", buf);
           }

           
           apr_table_mergen(r->headers_in, "X-Forwarded-Server", r->server->server_hostname);
       }
    }

    proxy_run_fixups(r);
    
    headers_in_copy = apr_table_copy(r->pool, r->headers_in);
    ap_proxy_clear_connection(p, headers_in_copy);
    
    headers_in_array = apr_table_elts(headers_in_copy);
    headers_in = (const apr_table_entry_t *) headers_in_array->elts;
    for (counter = 0; counter < headers_in_array->nelts; counter++) {
        if (headers_in[counter].key == NULL || headers_in[counter].val == NULL   || !strcasecmp(headers_in[counter].key, "Host")




            
             || !strcasecmp(headers_in[counter].key, "Keep-Alive")
             || !strcasecmp(headers_in[counter].key, "TE")
             || !strcasecmp(headers_in[counter].key, "Trailer")
             || !strcasecmp(headers_in[counter].key, "Upgrade")

             ) {
            continue;
        }
        
        if (!strcasecmp(headers_in[counter].key,"Proxy-Authorization")) {
            if (r->user != NULL) { 
                if (!apr_table_get(r->subprocess_env, "Proxy-Chain-Auth")) {
                    continue;
                }
            }
        }


        
        if (!strcasecmp(headers_in[counter].key, "Transfer-Encoding")) {
            old_te_val = headers_in[counter].val;
            continue;
        }
        if (!strcasecmp(headers_in[counter].key, "Content-Length")) {
            old_cl_val = headers_in[counter].val;
            continue;
        }

        
        if (r->main) {
            if (    !strcasecmp(headers_in[counter].key, "If-Match")
                 || !strcasecmp(headers_in[counter].key, "If-Modified-Since")
                 || !strcasecmp(headers_in[counter].key, "If-Range")
                 || !strcasecmp(headers_in[counter].key, "If-Unmodified-Since")
                 || !strcasecmp(headers_in[counter].key, "If-None-Match")) {
                continue;
            }
        }

        buf = apr_pstrcat(p, headers_in[counter].key, ": ", headers_in[counter].val, CRLF, NULL);

        ap_xlate_proto_to_ascii(buf, strlen(buf));
        e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(header_brigade, e);
    }

    
    input_brigade = apr_brigade_create(p, bucket_alloc);

    
    if (!r->kept_body && r->main) {
        
        p_conn->close++;
        if (old_cl_val) {
            old_cl_val = NULL;
            apr_table_unset(r->headers_in, "Content-Length");
        }
        if (old_te_val) {
            old_te_val = NULL;
            apr_table_unset(r->headers_in, "Transfer-Encoding");
        }
        rb_method = RB_STREAM_CL;
        e = apr_bucket_eos_create(input_brigade->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(input_brigade, e);
        goto skip_body;
    }

    
    if (old_te_val && strcasecmp(old_te_val, "chunked") != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01093)
                      "%s Transfer-Encoding is not supported", old_te_val);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (old_cl_val && old_te_val) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01094)
                      "client %s (%s) requested Transfer-Encoding " "chunked body with Content-Length (C-L ignored)", c->client_ip, c->remote_host ? c->remote_host: "");

        apr_table_unset(r->headers_in, "Content-Length");
        old_cl_val = NULL;
        origin->keepalive = AP_CONN_CLOSE;
        p_conn->close++;
    }

    
    temp_brigade = apr_brigade_create(p, bucket_alloc);
    do {
        status = ap_get_brigade(r->input_filters, temp_brigade, AP_MODE_READBYTES, APR_BLOCK_READ, MAX_MEM_SPOOL - bytes_read);

        if (status != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01095)
                          "prefetch request body failed to %pI (%s)" " from %s (%s)", p_conn->addr, p_conn->hostname ? p_conn->hostname: "", c->client_ip, c->remote_host ? c->remote_host: "");


            return HTTP_BAD_REQUEST;
        }

        apr_brigade_length(temp_brigade, 1, &bytes);
        bytes_read += bytes;

        
        status = ap_save_brigade(NULL, &input_brigade, &temp_brigade, p);
        if (status != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, APLOGNO(01096)
                          "processing prefetched request body failed" " to %pI (%s) from %s (%s)", p_conn->addr, p_conn->hostname ? p_conn->hostname: "", c->client_ip, c->remote_host ? c->remote_host: "");


            return HTTP_INTERNAL_SERVER_ERROR;
        }

    
    } while ((bytes_read < MAX_MEM_SPOOL - 80)
              && !APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade)));

    
    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(input_brigade))) {
        
        if (old_cl_val || old_te_val || bytes_read) {
            old_cl_val = apr_off_t_toa(r->pool, bytes_read);
        }
        rb_method = RB_STREAM_CL;
    }
    else if (old_te_val) {
        if (force10 || (apr_table_get(r->subprocess_env, "proxy-sendcl")
                  && !apr_table_get(r->subprocess_env, "proxy-sendchunks")
                  && !apr_table_get(r->subprocess_env, "proxy-sendchunked"))) {
            rb_method = RB_SPOOL_CL;
        }
        else {
            rb_method = RB_STREAM_CHUNKED;
        }
    }
    else if (old_cl_val) {
        if (r->input_filters == r->proto_input_filters) {
            rb_method = RB_STREAM_CL;
        }
        else if (!force10 && (apr_table_get(r->subprocess_env, "proxy-sendchunks")
                      || apr_table_get(r->subprocess_env, "proxy-sendchunked"))
                  && !apr_table_get(r->subprocess_env, "proxy-sendcl")) {
            rb_method = RB_STREAM_CHUNKED;
        }
        else {
            rb_method = RB_SPOOL_CL;
        }
    }
    else {
        
        rb_method = RB_SPOOL_CL;
    }


skip_body:
    
    if (!force10) {
        if (p_conn->close) {
            buf = apr_pstrdup(p, "Connection: close" CRLF);
        }
        else {
            buf = apr_pstrdup(p, "Connection: Keep-Alive" CRLF);
        }
        ap_xlate_proto_to_ascii(buf, strlen(buf));
        e = apr_bucket_pool_create(buf, strlen(buf), p, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(header_brigade, e);
    }

    
    switch(rb_method) {
    case RB_STREAM_CHUNKED:
        rv = stream_reqbody_chunked(p, r, p_conn, origin, header_brigade, input_brigade);
        break;
    case RB_STREAM_CL:
        rv = stream_reqbody_cl(p, r, p_conn, origin, header_brigade, input_brigade, old_cl_val);
        break;
    case RB_SPOOL_CL:
        rv = spool_reqbody_cl(p, r, p_conn, origin, header_brigade, input_brigade, (old_cl_val != NULL)
                                              || (old_te_val != NULL)
                                              || (bytes_read > 0));
        break;
    default:
        
        rv = HTTP_INTERNAL_SERVER_ERROR ;
        break;
    }

    if (rv != OK) {
        
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01097)
                      "pass request body failed to %pI (%s) from %s (%s)", p_conn->addr, p_conn->hostname ? p_conn->hostname: "", c->client_ip, c->remote_host ? c->remote_host: "");

        return rv;
    }

    return OK;
}


static const char *date_canon(apr_pool_t *p, const char *date)
{
    apr_status_t rv;
    char* ndate;

    apr_time_t time = apr_date_parse_http(date);
    if (!time) {
        return date;
    }

    ndate = apr_palloc(p, APR_RFC822_DATE_LEN);
    rv = apr_rfc822_date(ndate, time);
    if (rv != APR_SUCCESS) {
        return date;
    }

    return ndate;
}

static request_rec *make_fake_req(conn_rec *c, request_rec *r)
{
    apr_pool_t *pool;
    request_rec *rp;

    apr_pool_create(&pool, c->pool);

    rp = apr_pcalloc(pool, sizeof(*r));

    rp->pool            = pool;
    rp->status          = HTTP_OK;

    rp->headers_in      = apr_table_make(pool, 50);
    rp->subprocess_env  = apr_table_make(pool, 50);
    rp->headers_out     = apr_table_make(pool, 12);
    rp->err_headers_out = apr_table_make(pool, 5);
    rp->notes           = apr_table_make(pool, 5);

    rp->server = r->server;
    rp->log = r->log;
    rp->proxyreq = r->proxyreq;
    rp->request_time = r->request_time;
    rp->connection      = c;
    rp->output_filters  = c->output_filters;
    rp->input_filters   = c->input_filters;
    rp->proto_output_filters  = c->output_filters;
    rp->proto_input_filters   = c->input_filters;
    rp->useragent_ip = c->client_ip;
    rp->useragent_addr = c->client_addr;

    rp->request_config  = ap_create_request_config(pool);
    proxy_run_create_req(r, rp);

    return rp;
}

static void process_proxy_header(request_rec *r, proxy_dir_conf *c, const char *key, const char *value)
{
    static const char *date_hdrs[] = { "Date", "Expires", "Last-Modified", NULL };
    static const struct {
        const char *name;
        ap_proxy_header_reverse_map_fn func;
    } transform_hdrs[] = {
        { "Location", ap_proxy_location_reverse_map }, { "Content-Location", ap_proxy_location_reverse_map }, { "URI", ap_proxy_location_reverse_map }, { "Destination", ap_proxy_location_reverse_map }, { "Set-Cookie", ap_proxy_cookie_reverse_map }, { NULL, NULL }




    };
    int i;
    for (i = 0; date_hdrs[i]; ++i) {
        if (!strcasecmp(date_hdrs[i], key)) {
            apr_table_add(r->headers_out, key, date_canon(r->pool, value));
            return;
        }
    }
    for (i = 0; transform_hdrs[i].name; ++i) {
        if (!strcasecmp(transform_hdrs[i].name, key)) {
            apr_table_add(r->headers_out, key, (*transform_hdrs[i].func)(r, c, value));
            return;
       }
    }
    apr_table_add(r->headers_out, key, value);
    return;
}


static void ap_proxy_read_headers(request_rec *r, request_rec *rr, char *buffer, int size, conn_rec *c, int *pread_len)

{
    int len;
    char *value, *end;
    char field[MAX_STRING_LEN];
    int saw_headers = 0;
    void *sconf = r->server->module_config;
    proxy_server_conf *psc;
    proxy_dir_conf *dconf;

    dconf = ap_get_module_config(r->per_dir_config, &proxy_module);
    psc = (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    r->headers_out = apr_table_make(r->pool, 20);
    *pread_len = 0;

    
    ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "Headers received from backend:");
    while ((len = ap_getline(buffer, size, rr, 1)) > 0) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "%s", buffer);

        if (!(value = strchr(buffer, ':'))) {     

            
             

            if (!apr_date_checkmask(buffer, "HTTP/#.# ###*")) {
                if (psc->badopt == bad_error) {
                    
                    r->headers_out = NULL;
                    return ;
                }
                else if (psc->badopt == bad_body) {
                    
                    if (saw_headers) {
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01098)
                                      "Starting body due to bogus non-header " "in headers returned by %s (%s)", r->uri, r->method);

                        *pread_len = len;
                        return ;
                    } else {
                         ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01099)
                                       "No HTTP headers returned by %s (%s)", r->uri, r->method);
                        return ;
                    }
                }
            }
            
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01100)
                          "Ignoring bogus HTTP header returned by %s (%s)", r->uri, r->method);
            continue;
        }

        *value = '\0';
        ++value;
        
        while (apr_isspace(*value))
            ++value;            

        
        for (end = &value[strlen(value)-1]; end > value && apr_isspace(*end); -- end)
            *end = '\0';

        
        process_proxy_header(r, dconf, buffer, value) ;
        saw_headers = 1;

        
        if (len >= size - 1) {
            while ((len = ap_getline(field, MAX_STRING_LEN, rr, 1))
                    >= MAX_STRING_LEN - 1) {
                
            }
            if (len == 0) 
                break;
        }
    }
}



static int addit_dammit(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

static apr_status_t ap_proxygetline(apr_bucket_brigade *bb, char *s, int n, request_rec *r, int fold, int *writen)

{
    char *tmp_s = s;
    apr_status_t rv;
    apr_size_t len;

    rv = ap_rgetline(&tmp_s, n, &len, r, fold, bb);
    apr_brigade_cleanup(bb);

    if (rv == APR_SUCCESS) {
        *writen = (int) len;
    } else if (APR_STATUS_IS_ENOSPC(rv)) {
        *writen = n;
    } else {
        *writen = -1;
    }

    return rv;
}






static apr_status_t ap_proxy_http_process_response(apr_pool_t * p, request_rec *r, proxy_conn_rec **backend_ptr, proxy_worker *worker, proxy_server_conf *conf, char *server_portstr) {




    conn_rec *c = r->connection;
    char buffer[HUGE_STRING_LEN];
    const char *buf;
    char keepchar;
    apr_bucket *e;
    apr_bucket_brigade *bb, *tmp_bb;
    apr_bucket_brigade *pass_bb;
    int len, backasswards;
    int interim_response = 0; 
    int pread_len = 0;
    apr_table_t *save_table;
    int backend_broke = 0;
    static const char *hop_by_hop_hdrs[] = {"Keep-Alive", "Proxy-Authenticate", "TE", "Trailer", "Upgrade", NULL};
    int i;
    const char *te = NULL;
    int original_status = r->status;
    int proxy_status = OK;
    const char *original_status_line = r->status_line;
    const char *proxy_status_line = NULL;
    proxy_conn_rec *backend = *backend_ptr;
    conn_rec *origin = backend->connection;
    apr_interval_time_t old_timeout = 0;
    proxy_dir_conf *dconf;
    int do_100_continue;

    dconf = ap_get_module_config(r->per_dir_config, &proxy_module);

    do_100_continue = (worker->s->ping_timeout_set && ap_request_has_body(r)
                       && (PROXYREQ_REVERSE == r->proxyreq)
                       && !(apr_table_get(r->subprocess_env, "force-proxy-request-1.0")));

    bb = apr_brigade_create(p, c->bucket_alloc);
    pass_bb = apr_brigade_create(p, c->bucket_alloc);

    
    if (do_100_continue) {
        apr_socket_timeout_get(backend->sock, &old_timeout);
        if (worker->s->ping_timeout != old_timeout) {
            apr_status_t rc;
            rc = apr_socket_timeout_set(backend->sock, worker->s->ping_timeout);
            if (rc != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, APLOGNO(01101)
                              "could not set 100-Continue timeout");
            }
        }
    }

    

    backend->r = make_fake_req(origin, r);
    
    backend->r->proxyreq = PROXYREQ_RESPONSE;
    apr_table_setn(r->notes, "proxy-source-port", apr_psprintf(r->pool, "%hu", origin->local_addr->port));
    tmp_bb = apr_brigade_create(p, c->bucket_alloc);
    do {
        apr_status_t rc;

        apr_brigade_cleanup(bb);

        rc = ap_proxygetline(tmp_bb, buffer, sizeof(buffer), backend->r, 0, &len);
        if (len == 0) {
            
            rc = ap_proxygetline(tmp_bb, buffer, sizeof(buffer), backend->r, 0, &len);
        }
        if (len <= 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, APLOGNO(01102)
                          "error reading status line from remote " "server %s:%d", backend->hostname, backend->port);
            if (APR_STATUS_IS_TIMEUP(rc)) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01103) "read timeout");
                if (do_100_continue) {
                    return ap_proxyerror(r, HTTP_SERVICE_UNAVAILABLE, "Timeout on 100-Continue");
                }
            }
            
            if (r->proxyreq == PROXYREQ_REVERSE && c->keepalives && !APR_STATUS_IS_TIMEUP(rc)) {
                apr_bucket *eos;

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01104)
                              "Closing connection to client because" " reading from backend server %s:%d failed." " Number of keepalives %i", backend->hostname, backend->port, c->keepalives);


                ap_proxy_backend_broke(r, bb);
                
                e = ap_bucket_eoc_create(c->bucket_alloc);
                eos = APR_BRIGADE_LAST(bb);
                while ((APR_BRIGADE_SENTINEL(bb) != eos)
                       && !APR_BUCKET_IS_EOS(eos)) {
                    eos = APR_BUCKET_PREV(eos);
                }
                if (eos == APR_BRIGADE_SENTINEL(bb)) {
                    APR_BRIGADE_INSERT_TAIL(bb, e);
                }
                else {
                    APR_BUCKET_INSERT_BEFORE(eos, e);
                }
                ap_pass_brigade(r->output_filters, bb);
                
                backend->close = 1;
                
                return OK;
            }
            else if (!c->keepalives) {
                     ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01105)
                                   "NOT Closing connection to client" " although reading from backend server %s:%d" " failed.", backend->hostname, backend->port);


            }
            return ap_proxyerror(r, HTTP_BAD_GATEWAY, "Error reading from remote server");
        }
        
        backend->worker->s->read += len;

        
        if (apr_date_checkmask(buffer, "HTTP/#.# ###*")) {
            int major, minor;

            major = buffer[5] - '0';
            minor = buffer[7] - '0';

            
            if ((major != 1) || (len >= sizeof(buffer)-1)) {
                return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_pstrcat(p, "Corrupt status line returned by remote " "server: ", buffer, NULL));

            }
            backasswards = 0;

            keepchar = buffer[12];
            buffer[12] = '\0';
            proxy_status = atoi(&buffer[9]);
            apr_table_setn(r->notes, "proxy-status", apr_pstrdup(r->pool, &buffer[9]));

            if (keepchar != '\0') {
                buffer[12] = keepchar;
            } else {
                
                buffer[12] = ' ';
                buffer[13] = '\0';
            }
            proxy_status_line = apr_pstrdup(p, &buffer[9]);

            
            r->status = proxy_status;
            r->status_line = proxy_status_line;

            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "Status from backend: %d", proxy_status);

            
            
            

            
            save_table = apr_table_make(r->pool, 2);
            apr_table_do(addit_dammit, save_table, r->headers_out, "Set-Cookie", NULL);

            
            ap_proxy_read_headers(r, backend->r, buffer, sizeof(buffer), origin, &pread_len);

            if (r->headers_out == NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01106)
                              "bad HTTP/%d.%d header returned by %s (%s)", major, minor, r->uri, r->method);
                backend->close += 1;
                
                r->headers_out = apr_table_make(r->pool,1);
                r->status = HTTP_BAD_GATEWAY;
                r->status_line = "bad gateway";
                return r->status;
            }

            
            apr_table_do(addit_dammit, save_table, r->headers_out, "Set-Cookie", NULL);

            
            if (!apr_is_empty_table(save_table)) {
                apr_table_unset(r->headers_out, "Set-Cookie");
                r->headers_out = apr_table_overlay(r->pool, r->headers_out, save_table);

            }

            
            if (apr_table_get(r->headers_out, "Transfer-Encoding")
                    && apr_table_get(r->headers_out, "Content-Length")) {
                
                apr_table_unset(r->headers_out, "Content-Length");
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01107)
                              "server %s:%d returned Transfer-Encoding" " and Content-Length", backend->hostname, backend->port);

                backend->close += 1;
            }

            
            te = apr_table_get(r->headers_out, "Transfer-Encoding");
            
            backend->close += ap_find_token(p, apr_table_get(r->headers_out, "Connection"), "close");
            ap_proxy_clear_connection(p, r->headers_out);
            if ((buf = apr_table_get(r->headers_out, "Content-Type"))) {
                ap_set_content_type(r, apr_pstrdup(p, buf));
            }
            if (!ap_is_HTTP_INFO(proxy_status)) {
                ap_proxy_pre_http_request(origin, backend->r);
            }

            
            for (i=0; hop_by_hop_hdrs[i]; ++i) {
                apr_table_unset(r->headers_out, hop_by_hop_hdrs[i]);
            }
            
            r->headers_out = ap_proxy_clean_warnings(p, r->headers_out);

            
            if (conf->viaopt != via_off && conf->viaopt != via_block) {
                const char *server_name = ap_get_server_name(r);
                
                if (server_name == r->hostname)
                    server_name = r->server->server_hostname;
                
                apr_table_addn(r->headers_out, "Via", (conf->viaopt == via_full)
                                     ? apr_psprintf(p, "%d.%d %s%s (%s)", HTTP_VERSION_MAJOR(r->proto_num), HTTP_VERSION_MINOR(r->proto_num), server_name, server_portstr, AP_SERVER_BASEVERSION)




                                     : apr_psprintf(p, "%d.%d %s%s", HTTP_VERSION_MAJOR(r->proto_num), HTTP_VERSION_MINOR(r->proto_num), server_name, server_portstr)



                );
            }

            
            if ((major < 1) || (minor < 1)) {
                backend->close += 1;
                origin->keepalive = AP_CONN_CLOSE;
            }
        } else {
            
            backasswards = 1;
            r->status = 200;
            r->status_line = "200 OK";
            backend->close += 1;
        }

        if (ap_is_HTTP_INFO(proxy_status)) {
            interim_response++;
            
            if (do_100_continue && (r->status == HTTP_CONTINUE)
                && (worker->s->ping_timeout != old_timeout)) {
                    apr_socket_timeout_set(backend->sock, old_timeout);
            }
        }
        else {
            interim_response = 0;
        }
        if (interim_response) {
            
            const char *policy = apr_table_get(r->subprocess_env, "proxy-interim-response");
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "HTTP: received interim %d response", r->status);
            if (!policy || !strcasecmp(policy, "RFC")) {
                ap_send_interim_response(r, 1);
            }
            
            else if (strcasecmp(policy, "Suppress")) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01108)
                              "undefined proxy interim response policy");
            }
        }
        

        if ((proxy_status == 401) && (dconf->error_override)) {
            const char *buf;
            const char *wa = "WWW-Authenticate";
            if ((buf = apr_table_get(r->headers_out, wa))) {
                apr_table_set(r->err_headers_out, wa, buf);
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01109)
                              "origin server sent 401 without " "WWW-Authenticate header");
            }
        }

        r->sent_bodyct = 1;
        
        if (backasswards || pread_len) {
            apr_ssize_t cntr = (apr_ssize_t)pread_len;
            if (backasswards) {
                
                ap_xlate_proto_to_ascii(buffer, len);
                cntr = (apr_ssize_t)len;
            }
            e = apr_bucket_heap_create(buffer, cntr, NULL, c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
        }
        
        if (ap_is_HTTP_ERROR(r->status) && dconf->error_override) {
            
            r->status = HTTP_OK;
            
            if (!r->header_only &&  (proxy_status != HTTP_NO_CONTENT) && (proxy_status != HTTP_NOT_MODIFIED)) {

                ap_discard_request_body(backend->r);
            }
            return proxy_status;
        }

        
        if ((!r->header_only) &&                    !interim_response && (proxy_status != HTTP_NO_CONTENT) && (proxy_status != HTTP_NOT_MODIFIED)) {



            
            backend->r->headers_in = apr_table_clone(backend->r->pool, r->headers_out);
            
            if (te && !apr_table_get(backend->r->headers_in, "Transfer-Encoding")) {
                apr_table_add(backend->r->headers_in, "Transfer-Encoding", te);
            }

            apr_table_unset(r->headers_out,"Transfer-Encoding");

            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "start body send");

            
            if (!dconf->error_override || !ap_is_HTTP_ERROR(proxy_status)) {
                
                apr_read_type_e mode = APR_NONBLOCK_READ;
                int finish = FALSE;

                
                if (dconf->error_override && !ap_is_HTTP_ERROR(proxy_status)
                        && ap_is_HTTP_ERROR(original_status)) {
                    r->status = original_status;
                    r->status_line = original_status_line;
                }

                do {
                    apr_off_t readbytes;
                    apr_status_t rv;

                    rv = ap_get_brigade(backend->r->input_filters, bb, AP_MODE_READBYTES, mode, conf->io_buffer_size);


                    
                    if (mode == APR_NONBLOCK_READ && (APR_STATUS_IS_EAGAIN(rv)
                            || (rv == APR_SUCCESS && APR_BRIGADE_EMPTY(bb)))) {
                        
                        e = apr_bucket_flush_create(c->bucket_alloc);
                        APR_BRIGADE_INSERT_TAIL(bb, e);
                        if (ap_pass_brigade(r->output_filters, bb)
                            || c->aborted) {
                            backend->close = 1;
                            break;
                        }
                        apr_brigade_cleanup(bb);
                        mode = APR_BLOCK_READ;
                        continue;
                    }
                    else if (rv == APR_EOF) {
                        break;
                    }
                    else if (rv != APR_SUCCESS) {
                        
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01110)
                                      "error reading response");
                        ap_proxy_backend_broke(r, bb);
                        ap_pass_brigade(r->output_filters, bb);
                        backend_broke = 1;
                        backend->close = 1;
                        break;
                    }
                    
                    mode = APR_NONBLOCK_READ;

                    apr_brigade_length(bb, 0, &readbytes);
                    backend->worker->s->read += readbytes;

                    {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01111)
                                  "readbytes: %#x", readbytes);
                    }

                    
                    if (APR_BRIGADE_EMPTY(bb)) {
                        apr_brigade_cleanup(bb);
                        break;
                    }

                    
                    proxy_buckets_lifetime_transform(r, bb, pass_bb);

                    
                    if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(pass_bb))) {

                        
                        finish = TRUE;

                        
                        for (e = APR_BRIGADE_FIRST(pass_bb); e != APR_BRIGADE_SENTINEL(pass_bb); e = APR_BUCKET_NEXT(e)) {

                            apr_bucket_setaside(e, r->pool);
                        }

                        
                        apr_brigade_cleanup(bb);

                        
                        ap_proxy_release_connection(backend->worker->s->scheme, backend, r->server);
                        
                        *backend_ptr = NULL;

                    }

                    
                    if (ap_pass_brigade(r->output_filters, pass_bb) != APR_SUCCESS || c->aborted) {
                        
                        
                        if (*backend_ptr) {
                            backend->close = 1;  
                        }
                        finish = TRUE;
                    }

                    
                    apr_brigade_cleanup(pass_bb);
                    apr_brigade_cleanup(bb);

                } while (!finish);
            }
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "end body send");
        }
        else if (!interim_response) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "header only");

            
            ap_proxy_release_connection(backend->worker->s->scheme, backend, r->server);
            *backend_ptr = NULL;

            
            e = apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(bb, e);
            ap_pass_brigade(r->output_filters, bb);

            apr_brigade_cleanup(bb);
        }
    } while (interim_response && (interim_response < AP_MAX_INTERIM_RESPONSES));

    
    if (interim_response >= AP_MAX_INTERIM_RESPONSES) {
        return ap_proxyerror(r, HTTP_BAD_GATEWAY, apr_psprintf(p, "Too many (%d) interim responses from origin server", interim_response));


    }

    
    if (c->aborted || backend_broke) {
        return DONE;
    }

    return OK;
}

static apr_status_t ap_proxy_http_cleanup(const char *scheme, request_rec *r, proxy_conn_rec *backend)

{
    ap_proxy_release_connection(scheme, backend, r->server);
    return OK;
}


static int proxy_http_handler(request_rec *r, proxy_worker *worker, proxy_server_conf *conf, char *url, const char *proxyname, apr_port_t proxyport)


{
    int status;
    char server_portstr[32];
    char *scheme;
    const char *proxy_function;
    const char *u;
    proxy_conn_rec *backend = NULL;
    int is_ssl = 0;
    conn_rec *c = r->connection;
    int retry = 0;
    
    apr_pool_t *p = r->pool;
    apr_uri_t *uri = apr_palloc(p, sizeof(*uri));

    
    u = strchr(url, ':');
    if (u == NULL || u[1] != '/' || u[2] != '/' || u[3] == '\0')
       return DECLINED;
    if ((u - url) > 14)
        return HTTP_BAD_REQUEST;
    scheme = apr_pstrndup(p, url, u - url);
    
    ap_str_tolower(scheme);
    
    if (strcmp(scheme, "https") == 0) {
        if (!ap_proxy_ssl_enable(NULL)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01112)
                          "HTTPS: declining URL %s (mod_ssl not configured?)", url);
            return DECLINED;
        }
        is_ssl = 1;
        proxy_function = "HTTPS";
    }
    else if (!(strcmp(scheme, "http") == 0 || (strcmp(scheme, "ftp") == 0 && proxyname))) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01113) "HTTP: declining URL %s", url);
        return DECLINED; 
    }
    else {
        if (*scheme == 'h')
            proxy_function = "HTTP";
        else proxy_function = "FTP";
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "HTTP: serving URL %s", url);


    
    if ((status = ap_proxy_acquire_connection(proxy_function, &backend, worker, r->server)) != OK)
        goto cleanup;


    backend->is_ssl = is_ssl;

    if (is_ssl) {
        ap_proxy_ssl_connection_cleanup(backend, r);
    }

    
    if ((r->proxyreq == PROXYREQ_REVERSE) && (!c->keepalives)
        && (apr_table_get(r->subprocess_env, "proxy-initial-not-pooled"))) {
        backend->close = 1;
    }

    while (retry < 2) {
        char *locurl = url;

        
        if ((status = ap_proxy_determine_connection(p, r, conf, worker, backend, uri, &locurl, proxyname, proxyport, server_portstr, sizeof(server_portstr))) != OK)


            break;

        
        if (ap_proxy_connect_backend(proxy_function, backend, worker, r->server)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01114)
                          "HTTP: failed to make connection to backend: %s", backend->hostname);
            status = HTTP_SERVICE_UNAVAILABLE;
            break;
        }

        
        if (!backend->connection) {
            if ((status = ap_proxy_connection_create(proxy_function, backend, c, r->server)) != OK)
                break;
            
            if (is_ssl) {
                proxy_dir_conf *dconf;
                const char *ssl_hostname;

                
                dconf = ap_get_module_config(r->per_dir_config, &proxy_module);
                if ((dconf->preserve_host != 0) && (r->hostname != NULL)) {
                    ssl_hostname = r->hostname;
                }
                else {
                    ssl_hostname = uri->hostname;
                }

                apr_table_set(backend->connection->notes, "proxy-request-hostname", ssl_hostname);
            }
        }

        
        if ((status = ap_proxy_http_request(p, r, backend, worker, conf, uri, locurl, server_portstr)) != OK) {
            if ((status == HTTP_SERVICE_UNAVAILABLE) && worker->s->ping_timeout_set) {
                backend->close = 1;
                ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r, APLOGNO(01115)
                              "HTTP: 100-Continue failed to %pI (%s)", worker->cp->addr, worker->s->hostname);
                retry++;
                continue;
            } else {
                break;
            }

        }

        
        status = ap_proxy_http_process_response(p, r, &backend, worker, conf, server_portstr);

        break;
    }

    
cleanup:
    if (backend) {
        if (status != OK)
            backend->close = 1;
        ap_proxy_http_cleanup(proxy_function, r, backend);
    }
    return status;
}
static void ap_proxy_http_register_hook(apr_pool_t *p)
{
    proxy_hook_scheme_handler(proxy_http_handler, NULL, NULL, APR_HOOK_FIRST);
    proxy_hook_canon_handler(proxy_http_canon, NULL, NULL, APR_HOOK_FIRST);
    warn_rx = ap_pregcomp(p, "[0-9]{3}[ \t]+[^ \t]+[ \t]+\"[^\"]*\"([ \t]+\"([^\"]+)\")?", 0);
}

AP_DECLARE_MODULE(proxy_http) = {
    STANDARD20_MODULE_STUFF, NULL, NULL, NULL, NULL, NULL, ap_proxy_http_register_hook };







