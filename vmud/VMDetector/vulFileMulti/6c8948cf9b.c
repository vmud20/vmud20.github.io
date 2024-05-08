









































APR_HOOK_STRUCT( APR_HOOK_LINK(pre_read_request)
    APR_HOOK_LINK(post_read_request)
    APR_HOOK_LINK(log_transaction)
    APR_HOOK_LINK(http_scheme)
    APR_HOOK_LINK(default_port)
    APR_HOOK_LINK(note_auth_failure)
)

AP_DECLARE_DATA ap_filter_rec_t *ap_old_write_func = NULL;



static const char *needcset[] = {
    "text/plain", "text/html", NULL };


static const apr_strmatch_pattern **needcset_patterns;
static const apr_strmatch_pattern *charset_pattern;

AP_DECLARE(void) ap_setup_make_content_type(apr_pool_t *pool)
{
    int i;
    for (i = 0; needcset[i]; i++) {
        continue;
    }
    needcset_patterns = (const apr_strmatch_pattern **)
        apr_palloc(pool, (i + 1) * sizeof(apr_strmatch_pattern *));
    for (i = 0; needcset[i]; i++) {
        needcset_patterns[i] = apr_strmatch_precompile(pool, needcset[i], 0);
    }
    needcset_patterns[i] = NULL;
    charset_pattern = apr_strmatch_precompile(pool, "charset=", 0);
}


AP_DECLARE(const char *)ap_make_content_type(request_rec *r, const char *type)
{
    const apr_strmatch_pattern **pcset;
    core_dir_config *conf = (core_dir_config *)ap_get_core_module_config(r->per_dir_config);
    core_request_config *request_conf;
    apr_size_t type_len;

    if (!type || *type == '\0') {
        return NULL;
    }

    if (conf->add_default_charset != ADD_DEFAULT_CHARSET_ON) {
        return type;
    }

    request_conf = ap_get_core_module_config(r->request_config);
    if (request_conf->suppress_charset) {
        return type;
    }

    type_len = strlen(type);

    if (apr_strmatch(charset_pattern, type, type_len) != NULL) {
        
        
        ;
    }
    else {
        
        for (pcset = needcset_patterns; *pcset ; pcset++) {
            if (apr_strmatch(*pcset, type, type_len) != NULL) {
                struct iovec concat[3];
                concat[0].iov_base = (void *)type;
                concat[0].iov_len = type_len;
                concat[1].iov_base = (void *)"; charset=";
                concat[1].iov_len = sizeof("; charset=") - 1;
                concat[2].iov_base = (void *)(conf->add_default_charset_name);
                concat[2].iov_len = strlen(conf->add_default_charset_name);
                type = apr_pstrcatv(r->pool, concat, 3, NULL);
                break;
            }
        }
    }

    return type;
}

AP_DECLARE(void) ap_set_content_length(request_rec *r, apr_off_t clength)
{
    r->clength = clength;
    apr_table_setn(r->headers_out, "Content-Length", apr_off_t_toa(r->pool, clength));
}


AP_DECLARE(apr_time_t) ap_rationalize_mtime(request_rec *r, apr_time_t mtime)
{
    apr_time_t now;

    
    now = (mtime < r->request_time) ? r->request_time : apr_time_now();
    return (mtime > now) ? now : mtime;
}


AP_DECLARE(apr_status_t) ap_rgetline_core(char **s, apr_size_t n, apr_size_t *read, request_rec *r, int fold, apr_bucket_brigade *bb)

{
    apr_status_t rv;
    apr_bucket *e;
    apr_size_t bytes_handled = 0, current_alloc = 0;
    char *pos, *last_char = *s;
    int do_alloc = (*s == NULL), saw_eos = 0;

    
    if (last_char)
        *last_char = '\0';

    for (;;) {
        apr_brigade_cleanup(bb);
        rv = ap_get_brigade(r->proto_input_filters, bb, AP_MODE_GETLINE, APR_BLOCK_READ, 0);
        if (rv != APR_SUCCESS) {
            return rv;
        }

        
        if (APR_BRIGADE_EMPTY(bb)) {
            return APR_EGENERAL;
        }

        for (e = APR_BRIGADE_FIRST(bb);
             e != APR_BRIGADE_SENTINEL(bb);
             e = APR_BUCKET_NEXT(e))
        {
            const char *str;
            apr_size_t len;

            
            if (APR_BUCKET_IS_EOS(e)) {
                saw_eos = 1;
                break;
            }

            rv = apr_bucket_read(e, &str, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                return rv;
            }

            if (len == 0) {
                
                continue;
            }

            
            if (n < bytes_handled + len) {
                *read = bytes_handled;
                if (*s) {
                    
                    if (bytes_handled > 0) {
                        (*s)[bytes_handled-1] = '\0';
                    }
                    else {
                        (*s)[0] = '\0';
                    }
                }
                return APR_ENOSPC;
            }

            
            if (do_alloc) {
                
                if (!*s) {
                    current_alloc = len;
                    *s = apr_palloc(r->pool, current_alloc);
                }
                else if (bytes_handled + len > current_alloc) {
                    
                    apr_size_t new_size = current_alloc * 2;
                    char *new_buffer;

                    if (bytes_handled + len > new_size) {
                        new_size = (bytes_handled + len) * 2;
                    }

                    new_buffer = apr_palloc(r->pool, new_size);

                    
                    memcpy(new_buffer, *s, bytes_handled);
                    current_alloc = new_size;
                    *s = new_buffer;
                }
            }

            
            pos = *s + bytes_handled;
            memcpy(pos, str, len);
            last_char = pos + len - 1;

            
            bytes_handled += len;
        }

        
        if (last_char && (*last_char == APR_ASCII_LF)) {
            break;
        }
    }

    
    if (last_char > *s && last_char[-1] == APR_ASCII_CR) {
        last_char--;
    }
    *last_char = '\0';
    bytes_handled = last_char - *s;

    
    if (fold && bytes_handled && !saw_eos) {
        for (;;) {
            const char *str;
            apr_size_t len;
            char c;

            
            apr_brigade_cleanup(bb);

            
            rv = ap_get_brigade(r->proto_input_filters, bb, AP_MODE_SPECULATIVE, APR_BLOCK_READ, 1);
            if (rv != APR_SUCCESS) {
                return rv;
            }

            if (APR_BRIGADE_EMPTY(bb)) {
                break;
            }

            e = APR_BRIGADE_FIRST(bb);

            
            if (APR_BUCKET_IS_EOS(e)) {
                break;
            }

            rv = apr_bucket_read(e, &str, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                apr_brigade_cleanup(bb);
                return rv;
            }

            
            
            c = *str;
            if (c == APR_ASCII_BLANK || c == APR_ASCII_TAB) {
                
                if (bytes_handled >= n) {
                    *read = n;
                    
                    (*s)[n-1] = '\0';
                    return APR_ENOSPC;
                }
                else {
                    apr_size_t next_size, next_len;
                    char *tmp;

                    
                    if (do_alloc) {
                        tmp = NULL;
                    } else {
                        
                        tmp = last_char;
                    }

                    next_size = n - bytes_handled;

                    rv = ap_rgetline_core(&tmp, next_size, &next_len, r, 0, bb);
                    if (rv != APR_SUCCESS) {
                        return rv;
                    }

                    if (do_alloc && next_len > 0) {
                        char *new_buffer;
                        apr_size_t new_size = bytes_handled + next_len + 1;

                        
                        new_buffer = apr_palloc(r->pool, new_size);

                        
                        memcpy(new_buffer, *s, bytes_handled);

                        
                        memcpy(new_buffer + bytes_handled, tmp, next_len + 1);
                        *s = new_buffer;
                    }

                    last_char += next_len;
                    bytes_handled += next_len;
                }
            }
            else { 
                break;
            }
        }
    }
    *read = bytes_handled;

    
    if (strlen(*s) < bytes_handled) {
        return APR_EINVAL;
    }

    return APR_SUCCESS;
}


AP_DECLARE(apr_status_t) ap_rgetline(char **s, apr_size_t n, apr_size_t *read, request_rec *r, int fold, apr_bucket_brigade *bb)

{
    
    apr_status_t rv;

    rv = ap_rgetline_core(s, n, read, r, fold, bb);
    if (rv == APR_SUCCESS) {
        ap_xlate_proto_from_ascii(*s, *read);
    }
    return rv;
}


AP_DECLARE(int) ap_getline(char *s, int n, request_rec *r, int fold)
{
    char *tmp_s = s;
    apr_status_t rv;
    apr_size_t len;
    apr_bucket_brigade *tmp_bb;

    tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    rv = ap_rgetline(&tmp_s, n, &len, r, fold, tmp_bb);
    apr_brigade_destroy(tmp_bb);

    
    if (rv == APR_ENOSPC) {
        return n;
    }

    
    if (rv != APR_SUCCESS) {
        return -1;
    }

    return (int)len;
}


AP_CORE_DECLARE(void) ap_parse_uri(request_rec *r, const char *uri)
{
    int status = HTTP_OK;

    r->unparsed_uri = apr_pstrdup(r->pool, uri);

    
    while ((uri[0] == '/') && (uri[1] == '/')) {
        ++uri ;
    }
    if (r->method_number == M_CONNECT) {
        status = apr_uri_parse_hostinfo(r->pool, uri, &r->parsed_uri);
    }
    else {
        status = apr_uri_parse(r->pool, uri, &r->parsed_uri);
    }

    if (status == APR_SUCCESS) {
        
        if (r->parsed_uri.scheme && !strcasecmp(r->parsed_uri.scheme, ap_http_scheme(r))) {
            r->hostname = r->parsed_uri.hostname;
        }
        else if (r->method_number == M_CONNECT) {
            r->hostname = r->parsed_uri.hostname;
        }

        r->args = r->parsed_uri.query;
        r->uri = r->parsed_uri.path ? r->parsed_uri.path : apr_pstrdup(r->pool, "/");


        
        {
            char *x;

            for (x = r->uri; (x = strchr(x, '\\')) != NULL; )
                *x = '/';
        }

    }
    else {
        r->args = NULL;
        r->hostname = NULL;
        r->status = HTTP_BAD_REQUEST;             
        r->uri = apr_pstrdup(r->pool, uri);
    }
}

static int read_request_line(request_rec *r, apr_bucket_brigade *bb)
{
    const char *ll;
    const char *uri;
    const char *pro;

    int major = 1, minor = 0;   
    char http[5];
    apr_size_t len;
    int num_blank_lines = 0;
    int max_blank_lines = r->server->limit_req_fields;
    core_server_config *conf = ap_get_core_module_config(r->server->module_config);
    int strict = conf->http_conformance & AP_HTTP_CONFORMANCE_STRICT;
    int enforce_strict = !(conf->http_conformance & AP_HTTP_CONFORMANCE_LOGONLY);

    if (max_blank_lines <= 0) {
        max_blank_lines = DEFAULT_LIMIT_REQUEST_FIELDS;
    }

    

    do {
        apr_status_t rv;

        
        r->the_request = NULL;
        rv = ap_rgetline(&(r->the_request), (apr_size_t)(r->server->limit_req_line + 2), &len, r, 0, bb);

        if (rv != APR_SUCCESS) {
            r->request_time = apr_time_now();

            
            if (APR_STATUS_IS_ENOSPC(rv)) {
                r->status    = HTTP_REQUEST_URI_TOO_LARGE;
                r->proto_num = HTTP_VERSION(1,0);
                r->protocol  = apr_pstrdup(r->pool, "HTTP/1.0");
            }
            else if (APR_STATUS_IS_TIMEUP(rv)) {
                r->status = HTTP_REQUEST_TIME_OUT;
            }
            else if (APR_STATUS_IS_EINVAL(rv)) {
                r->status = HTTP_BAD_REQUEST;
            }
            return 0;
        }
    } while ((len <= 0) && (++num_blank_lines < max_blank_lines));

    if (APLOGrtrace5(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE5, 0, r, "Request received from client: %s", ap_escape_logitem(r->pool, r->the_request));

    }

    r->request_time = apr_time_now();
    ll = r->the_request;
    r->method = ap_getword_white(r->pool, &ll);

    uri = ap_getword_white(r->pool, &ll);

    

    r->method_number = ap_method_number_of(r->method);
    if (r->method_number == M_GET && r->method[0] == 'H') {
        r->header_only = 1;
    }

    ap_parse_uri(r, uri);

    if (ll[0]) {
        r->assbackwards = 0;
        pro = ll;
        len = strlen(ll);
    } else {
        r->assbackwards = 1;
        pro = "HTTP/0.9";
        len = 8;
        if (conf->http09_enable == AP_HTTP09_DISABLE) {
                r->status = HTTP_VERSION_NOT_SUPPORTED;
                r->protocol = apr_pstrmemdup(r->pool, pro, len);
                
                r->assbackwards = 0;
                r->proto_num = HTTP_VERSION(0, 9);
                r->connection->keepalive = AP_CONN_CLOSE;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02401)
                              "HTTP/0.9 denied by server configuration");
                return 0;
        }
    }
    r->protocol = apr_pstrmemdup(r->pool, pro, len);

    
    if (len == 8 && pro[0] == 'H' && pro[1] == 'T' && pro[2] == 'T' && pro[3] == 'P' && pro[4] == '/' && apr_isdigit(pro[5]) && pro[6] == '.' && apr_isdigit(pro[7])) {


        r->proto_num = HTTP_VERSION(pro[5] - '0', pro[7] - '0');
    }
    else {
        if (strict) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02418)
                          "Invalid protocol '%s'", r->protocol);
            if (enforce_strict) {
                r->status = HTTP_BAD_REQUEST;
                return 0;
            }
        }
        if (3 == sscanf(r->protocol, "%4s/%u.%u", http, &major, &minor)
            && (strcasecmp("http", http) == 0)
            && (minor < HTTP_VERSION(1, 0)) ) { 
            r->proto_num = HTTP_VERSION(major, minor);
        }
        else {
            r->proto_num = HTTP_VERSION(1, 0);
        }
    }

    if (strict) {
        int err = 0;
        if (ap_has_cntrl(r->the_request)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02420)
                          "Request line must not contain control characters");
            err = HTTP_BAD_REQUEST;
        }
        if (r->parsed_uri.fragment) {
            
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02421)
                          "URI must not contain a fragment");
            err = HTTP_BAD_REQUEST;
        }
        else if (r->parsed_uri.user || r->parsed_uri.password) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02422)
                          "URI must not contain a username/password");
            err = HTTP_BAD_REQUEST;
        }
        else if (r->method_number == M_INVALID) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02423)
                          "Invalid HTTP method string: %s", r->method);
            err = HTTP_NOT_IMPLEMENTED;
        }
        else if (r->assbackwards == 0 && r->proto_num < HTTP_VERSION(1, 0)) {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02424)
                          "HTTP/0.x does not take a protocol");
            err = HTTP_BAD_REQUEST;
        }

        if (err && enforce_strict) {
            r->status = err;
            return 0;
        }
    }

    return 1;
}

static int table_do_fn_check_lengths(void *r_, const char *key, const char *value)
{
    request_rec *r = r_;
    if (value == NULL || r->server->limit_req_fieldsize >= strlen(value) )
        return 1;

    r->status = HTTP_BAD_REQUEST;
    apr_table_setn(r->notes, "error-notes", apr_pstrcat(r->pool, "Size of a request header field " "after merging exceeds server limit.<br />" "\n<pre>\n", ap_escape_html(r->pool, key), "</pre>\n", NULL));




    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00560) "Request header " "exceeds LimitRequestFieldSize after merging: %s", key);
    return 0;
}



static int field_name_len(const char *field)
{
    const char *end = ap_strchr_c(field, ':');
    if (end == NULL || end - field > LOG_NAME_MAX_LEN)
        return LOG_NAME_MAX_LEN;
    return end - field;
}

AP_DECLARE(void) ap_get_mime_headers_core(request_rec *r, apr_bucket_brigade *bb)
{
    char *last_field = NULL;
    apr_size_t last_len = 0;
    apr_size_t alloc_len = 0;
    char *field;
    char *value;
    apr_size_t len;
    int fields_read = 0;
    char *tmp_field;
    core_server_config *conf = ap_get_core_module_config(r->server->module_config);

    
    while(1) {
        apr_status_t rv;
        int folded = 0;

        field = NULL;
        rv = ap_rgetline(&field, r->server->limit_req_fieldsize + 2, &len, r, 0, bb);

        if (rv != APR_SUCCESS) {
            if (APR_STATUS_IS_TIMEUP(rv)) {
                r->status = HTTP_REQUEST_TIME_OUT;
            }
            else {
                r->status = HTTP_BAD_REQUEST;
            }

            
            if (rv == APR_ENOSPC) {
                const char *field_escaped;
                if (field) {
                    
                    field[len - 1] = '\0';
                    field_escaped = ap_escape_html(r->pool, field);
                }
                else {
                    field_escaped = field = "";
                }

                apr_table_setn(r->notes, "error-notes", apr_psprintf(r->pool, "Size of a request header field " "exceeds server limit.<br />\n" "<pre>\n%.*s\n</pre>\n", field_name_len(field_escaped), field_escaped));





                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00561)
                              "Request header exceeds LimitRequestFieldSize%s" "%.*s", *field ? ": " : "", field_name_len(field), field);


            }
            return;
        }

        if (last_field != NULL) {
            if ((len > 0) && ((*field == '\t') || *field == ' ')) {
                
                apr_size_t fold_len = last_len + len + 1; 

                if (fold_len >= (apr_size_t)(r->server->limit_req_fieldsize)) {
                    r->status = HTTP_BAD_REQUEST;
                    
                    apr_table_setn(r->notes, "error-notes", apr_psprintf(r->pool, "Size of a request header field " "after folding " "exceeds server limit.<br />\n" "<pre>\n%.*s\n</pre>\n", field_name_len(last_field), ap_escape_html(r->pool, last_field)));






                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00562)
                                  "Request header exceeds LimitRequestFieldSize " "after folding: %.*s", field_name_len(last_field), last_field);

                    return;
                }

                if (fold_len > alloc_len) {
                    char *fold_buf;
                    alloc_len += alloc_len;
                    if (fold_len > alloc_len) {
                        alloc_len = fold_len;
                    }
                    fold_buf = (char *)apr_palloc(r->pool, alloc_len);
                    memcpy(fold_buf, last_field, last_len);
                    last_field = fold_buf;
                }
                memcpy(last_field + last_len, field, len +1); 
                last_len += len;
                folded = 1;
            }
            else  {

                if (r->server->limit_req_fields && (++fields_read > r->server->limit_req_fields)) {
                    r->status = HTTP_BAD_REQUEST;
                    apr_table_setn(r->notes, "error-notes", "The number of request header fields " "exceeds this server's limit.");

                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00563)
                                  "Number of request headers exceeds " "LimitRequestFields");
                    return;
                }

                if (!(value = strchr(last_field, ':'))) { 
                    r->status = HTTP_BAD_REQUEST;      
                    apr_table_setn(r->notes, "error-notes", apr_psprintf(r->pool, "Request header field is " "missing ':' separator.<br />\n" "<pre>\n%.*s</pre>\n", (int)LOG_NAME_MAX_LEN, ap_escape_html(r->pool, last_field)));






                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00564)
                                  "Request header field is missing ':' " "separator: %.*s", (int)LOG_NAME_MAX_LEN, last_field);

                    return;
                }

                tmp_field = value - 1; 

                *value++ = '\0'; 

                while (*value == ' ' || *value == '\t') {
                    ++value;            
                }

                
                while (tmp_field > last_field && (*tmp_field == ' ' || *tmp_field == '\t')) {
                    *tmp_field-- = '\0';
                }

                
                tmp_field = last_field + last_len - 1;
                while (tmp_field > value && (*tmp_field == ' ' || *tmp_field == '\t')) {
                    *tmp_field-- = '\0';
                }

                if (conf->http_conformance & AP_HTTP_CONFORMANCE_STRICT) {
                    int err = 0;

                    if (*last_field == '\0') {
                        err = HTTP_BAD_REQUEST;
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02425)
                                      "Empty request header field name not allowed");
                    }
                    else if (ap_has_cntrl(last_field)) {
                        err = HTTP_BAD_REQUEST;
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02426)
                                      "[HTTP strict] Request header field name contains " "control character: %.*s", (int)LOG_NAME_MAX_LEN, last_field);

                    }
                    else if (ap_has_cntrl(value)) {
                        err = HTTP_BAD_REQUEST;
                        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02427)
                                      "Request header field '%.*s' contains " "control character", (int)LOG_NAME_MAX_LEN, last_field);

                    }
                    if (err && !(conf->http_conformance & AP_HTTP_CONFORMANCE_LOGONLY)) {
                        r->status = err;
                        return;
                    }
                }
                apr_table_addn(r->headers_in, last_field, value);

                
                alloc_len = 0;

            } 
        }

        
        if (len == 0) {
            break;
        }

        
        if (!folded) {
            last_field = field;
            last_len = len;
        }
    }

    
    apr_table_compress(r->headers_in, APR_OVERLAP_TABLES_MERGE);

    
    apr_table_do(table_do_fn_check_lengths, r, r->headers_in, NULL);
}

AP_DECLARE(void) ap_get_mime_headers(request_rec *r)
{
    apr_bucket_brigade *tmp_bb;
    tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    ap_get_mime_headers_core(r, tmp_bb);
    apr_brigade_destroy(tmp_bb);
}

request_rec *ap_read_request(conn_rec *conn)
{
    request_rec *r;
    apr_pool_t *p;
    const char *expect;
    int access_status;
    apr_bucket_brigade *tmp_bb;
    apr_socket_t *csd;
    apr_interval_time_t cur_timeout;


    apr_pool_create(&p, conn->pool);
    apr_pool_tag(p, "request");
    r = apr_pcalloc(p, sizeof(request_rec));
    AP_READ_REQUEST_ENTRY((intptr_t)r, (uintptr_t)conn);
    r->pool            = p;
    r->connection      = conn;
    r->server          = conn->base_server;

    r->user            = NULL;
    r->ap_auth_type    = NULL;

    r->allowed_methods = ap_make_method_list(p, 2);

    r->headers_in      = apr_table_make(r->pool, 25);
    r->subprocess_env  = apr_table_make(r->pool, 25);
    r->headers_out     = apr_table_make(r->pool, 12);
    r->err_headers_out = apr_table_make(r->pool, 5);
    r->notes           = apr_table_make(r->pool, 5);

    r->request_config  = ap_create_request_config(r->pool);
    

    r->proto_output_filters = conn->output_filters;
    r->output_filters  = r->proto_output_filters;
    r->proto_input_filters = conn->input_filters;
    r->input_filters   = r->proto_input_filters;
    ap_run_create_request(r);
    r->per_dir_config  = r->server->lookup_defaults;

    r->sent_bodyct     = 0;                      

    r->read_length     = 0;
    r->read_body       = REQUEST_NO_BODY;

    r->status          = HTTP_OK;  
    r->the_request     = NULL;

    
    r->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

    r->useragent_addr = conn->client_addr;
    r->useragent_ip = conn->client_ip;

    tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    ap_run_pre_read_request(r, conn);

    
    if (!read_request_line(r, tmp_bb)) {
        switch (r->status) {
        case HTTP_REQUEST_URI_TOO_LARGE:
        case HTTP_BAD_REQUEST:
        case HTTP_VERSION_NOT_SUPPORTED:
        case HTTP_NOT_IMPLEMENTED:
            if (r->status == HTTP_REQUEST_URI_TOO_LARGE) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00565)
                              "request failed: client's request-line exceeds LimitRequestLine (longer than %d)", r->server->limit_req_line);
            }
            else if (r->method == NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00566)
                              "request failed: invalid characters in URI");
            }
            ap_send_error_response(r, 0);
            ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
            ap_run_log_transaction(r);
            apr_brigade_destroy(tmp_bb);
            goto traceout;
        case HTTP_REQUEST_TIME_OUT:
            ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
            if (!r->connection->keepalives)
                ap_run_log_transaction(r);
            apr_brigade_destroy(tmp_bb);
            goto traceout;
        default:
            apr_brigade_destroy(tmp_bb);
            r = NULL;
            goto traceout;
        }
    }

    
    csd = ap_get_conn_socket(conn);
    apr_socket_timeout_get(csd, &cur_timeout);
    if (cur_timeout != conn->base_server->timeout) {
        apr_socket_timeout_set(csd, conn->base_server->timeout);
        cur_timeout = conn->base_server->timeout;
    }

    if (!r->assbackwards) {
        const char *tenc;

        ap_get_mime_headers_core(r, tmp_bb);
        if (r->status != HTTP_OK) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00567)
                          "request failed: error reading the headers");
            ap_send_error_response(r, 0);
            ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
            ap_run_log_transaction(r);
            apr_brigade_destroy(tmp_bb);
            goto traceout;
        }

        tenc = apr_table_get(r->headers_in, "Transfer-Encoding");
        if (tenc) {
            
            if (!(strcasecmp(tenc, "chunked") == 0  || ap_find_last_token(r->pool, tenc, "chunked"))) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02539)
                              "client sent unknown Transfer-Encoding " "(%s): %s", tenc, r->uri);
                r->status = HTTP_BAD_REQUEST;
                conn->keepalive = AP_CONN_CLOSE;
                ap_send_error_response(r, 0);
                ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
                ap_run_log_transaction(r);
                apr_brigade_destroy(tmp_bb);
                goto traceout;
            }

            
            apr_table_unset(r->headers_in, "Content-Length");
        }
    }
    else {
        if (r->header_only) {
            
            ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00568)
                          "client sent invalid HTTP/0.9 request: HEAD %s", r->uri);
            r->header_only = 0;
            r->status = HTTP_BAD_REQUEST;
            ap_send_error_response(r, 0);
            ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
            ap_run_log_transaction(r);
            apr_brigade_destroy(tmp_bb);
            goto traceout;
        }
    }

    apr_brigade_destroy(tmp_bb);

    
    ap_update_vhost_from_headers(r);
    access_status = r->status;

    
    if (cur_timeout != r->server->timeout) {
        apr_socket_timeout_set(csd, r->server->timeout);
        cur_timeout = r->server->timeout;
    }

    
    r->per_dir_config = r->server->lookup_defaults;

    if ((!r->hostname && (r->proto_num >= HTTP_VERSION(1, 1)))
        || ((r->proto_num == HTTP_VERSION(1, 1))
            && !apr_table_get(r->headers_in, "Host"))) {
        
        access_status = HTTP_BAD_REQUEST;
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00569)
                      "client sent HTTP/1.1 request without hostname " "(see RFC2616 section 14.23): %s", r->uri);
    }

    

    ap_add_input_filter_handle(ap_http_input_filter_handle, NULL, r, r->connection);

    if (access_status != HTTP_OK || (access_status = ap_run_post_read_request(r))) {
        ap_die(access_status, r);
        ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
        ap_run_log_transaction(r);
        r = NULL;
        goto traceout;
    }

    if (((expect = apr_table_get(r->headers_in, "Expect")) != NULL)
        && (expect[0] != '\0')) {
        
        if (strcasecmp(expect, "100-continue") == 0) {
            r->expecting_100 = 1;
        }
        else {
            core_server_config *conf;

            conf = ap_get_core_module_config(r->server->module_config);
            if (conf->http_expect_strict != AP_HTTP_EXPECT_STRICT_DISABLE) {
                r->status = HTTP_EXPECTATION_FAILED;
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00570)
                              "client sent an unrecognized expectation value " "of Expect: %s", expect);
                ap_send_error_response(r, 0);
                ap_update_child_status(conn->sbh, SERVER_BUSY_LOG, r);
                ap_run_log_transaction(r);
                goto traceout;
            } else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(02595)
                              "client sent an unrecognized expectation value " "of Expect (not fatal): %s", expect);
            }
        }
    }

    AP_READ_REQUEST_SUCCESS((uintptr_t)r, (char *)r->method, (char *)r->uri, (char *)r->server->defn_name, r->status);
    return r;
    traceout:
    AP_READ_REQUEST_FAILURE((uintptr_t)r);
    return r;
}



static void strip_headers_request_body(request_rec *rnew)
{
    apr_table_unset(rnew->headers_in, "Content-Encoding");
    apr_table_unset(rnew->headers_in, "Content-Language");
    apr_table_unset(rnew->headers_in, "Content-Length");
    apr_table_unset(rnew->headers_in, "Content-Location");
    apr_table_unset(rnew->headers_in, "Content-MD5");
    apr_table_unset(rnew->headers_in, "Content-Range");
    apr_table_unset(rnew->headers_in, "Content-Type");
    apr_table_unset(rnew->headers_in, "Expires");
    apr_table_unset(rnew->headers_in, "Last-Modified");
    apr_table_unset(rnew->headers_in, "Transfer-Encoding");
}



AP_DECLARE(void) ap_set_sub_req_protocol(request_rec *rnew, const request_rec *r)
{
    rnew->the_request     = r->the_request;  

    rnew->assbackwards    = 1;   
    rnew->no_local_copy   = 1;   
    rnew->method          = "GET";
    rnew->method_number   = M_GET;
    rnew->protocol        = "INCLUDED";

    rnew->status          = HTTP_OK;

    rnew->headers_in      = apr_table_copy(rnew->pool, r->headers_in);

    
    if (!r->kept_body && (apr_table_get(r->headers_in, "Content-Length")
        || apr_table_get(r->headers_in, "Transfer-Encoding"))) {
        strip_headers_request_body(rnew);
    }
    rnew->subprocess_env  = apr_table_copy(rnew->pool, r->subprocess_env);
    rnew->headers_out     = apr_table_make(rnew->pool, 5);
    rnew->err_headers_out = apr_table_make(rnew->pool, 5);
    rnew->notes           = apr_table_make(rnew->pool, 5);

    rnew->expecting_100   = r->expecting_100;
    rnew->read_length     = r->read_length;
    rnew->read_body       = REQUEST_NO_BODY;

    rnew->main = (request_rec *) r;
}

static void error_output_stream(request_rec *r, int status)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    b = ap_bucket_error_create(status, NULL, r->pool, r->connection->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);
}

static void end_output_stream(request_rec *r)
{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);
}

AP_DECLARE(void) ap_finalize_sub_req_protocol(request_rec *sub)
{
    
    if (!sub->eos_sent) {
        end_output_stream(sub);
    }
}


AP_DECLARE(void) ap_finalize_request_protocol(request_rec *r)
{
    int status = ap_discard_request_body(r);

    
    if (status) {
        error_output_stream(r, status);
    }
    if (!r->eos_sent) {
        end_output_stream(r);
    }
}


AP_DECLARE(void) ap_note_auth_failure(request_rec *r)
{
    const char *type = ap_auth_type(r);
    if (type) {
        ap_run_note_auth_failure(r, type);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00571) "need AuthType to note auth failure: %s", r->uri);
    }
}

AP_DECLARE(void) ap_note_basic_auth_failure(request_rec *r)
{
    ap_note_auth_failure(r);
}

AP_DECLARE(void) ap_note_digest_auth_failure(request_rec *r)
{
    ap_note_auth_failure(r);
}

AP_DECLARE(int) ap_get_basic_auth_pw(request_rec *r, const char **pw)
{
    const char *auth_line = apr_table_get(r->headers_in, (PROXYREQ_PROXY == r->proxyreq)
                                              ? "Proxy-Authorization" : "Authorization");
    const char *t;

    if (!(t = ap_auth_type(r)) || strcasecmp(t, "Basic"))
        return DECLINED;

    if (!ap_auth_name(r)) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00572) "need AuthName: %s", r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!auth_line) {
        ap_note_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
        
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00573)
                      "client used wrong authentication scheme: %s", r->uri);
        ap_note_auth_failure(r);
        return HTTP_UNAUTHORIZED;
    }

    while (*auth_line == ' ' || *auth_line == '\t') {
        auth_line++;
    }

    t = ap_pbase64decode(r->pool, auth_line);
    r->user = ap_getword_nulls (r->pool, &t, ':');
    r->ap_auth_type = "Basic";

    *pw = t;

    return OK;
}

struct content_length_ctx {
    int data_sent;  
    apr_bucket_brigade *tmpbb;
};


AP_CORE_DECLARE_NONSTD(apr_status_t) ap_content_length_filter( ap_filter_t *f, apr_bucket_brigade *b)

{
    request_rec *r = f->r;
    struct content_length_ctx *ctx;
    apr_bucket *e;
    int eos = 0;
    apr_read_type_e eblock = APR_NONBLOCK_READ;

    ctx = f->ctx;
    if (!ctx) {
        f->ctx = ctx = apr_palloc(r->pool, sizeof(*ctx));
        ctx->data_sent = 0;
        ctx->tmpbb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    }

    
    e = APR_BRIGADE_FIRST(b);
    while (e != APR_BRIGADE_SENTINEL(b)) {
        if (APR_BUCKET_IS_EOS(e)) {
            eos = 1;
            break;
        }
        if (e->length == (apr_size_t)-1) {
            apr_size_t len;
            const char *ignored;
            apr_status_t rv;

            
            rv = apr_bucket_read(e, &ignored, &len, eblock);
            if (rv == APR_SUCCESS) {
                
                eblock = APR_NONBLOCK_READ;
                r->bytes_sent += len;
            }
            else if (APR_STATUS_IS_EAGAIN(rv)) {
                
                if (e != APR_BRIGADE_FIRST(b)) {
                    apr_bucket *flush;
                    apr_brigade_split_ex(b, e, ctx->tmpbb);
                    flush = apr_bucket_flush_create(r->connection->bucket_alloc);

                    APR_BRIGADE_INSERT_TAIL(b, flush);
                    rv = ap_pass_brigade(f->next, b);
                    if (rv != APR_SUCCESS || f->c->aborted) {
                        return rv;
                    }
                    apr_brigade_cleanup(b);
                    APR_BRIGADE_CONCAT(b, ctx->tmpbb);
                    e = APR_BRIGADE_FIRST(b);

                    ctx->data_sent = 1;
                }
                eblock = APR_BLOCK_READ;
                continue;
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00574)
                              "ap_content_length_filter: " "apr_bucket_read() failed");
                return rv;
            }
        }
        else {
            r->bytes_sent += e->length;
        }
        e = APR_BUCKET_NEXT(e);
    }

    
    if (ctx->data_sent == 0 && eos &&  !(r->header_only && r->bytes_sent == 0 && apr_table_get(r->headers_out, "Content-Length"))) {


        ap_set_content_length(r, r->bytes_sent);
    }

    ctx->data_sent = 1;
    return ap_pass_brigade(f->next, b);
}


AP_DECLARE(apr_status_t) ap_send_fd(apr_file_t *fd, request_rec *r, apr_off_t offset, apr_size_t len, apr_size_t *nbytes)

{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb = NULL;
    apr_status_t rv;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);

    apr_brigade_insert_file(bb, fd, offset, len, r->pool);

    rv = ap_pass_brigade(r->output_filters, bb);
    if (rv != APR_SUCCESS) {
        *nbytes = 0; 
    }
    else {
        *nbytes = len;
    }

    return rv;
}



AP_DECLARE(apr_size_t) ap_send_mmap(apr_mmap_t *mm, request_rec *r, apr_size_t offset, apr_size_t length)


{
    conn_rec *c = r->connection;
    apr_bucket_brigade *bb = NULL;
    apr_bucket *b;

    bb = apr_brigade_create(r->pool, c->bucket_alloc);
    b = apr_bucket_mmap_create(mm, offset, length, c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);

    return mm->size; 
}


typedef struct {
    apr_bucket_brigade *bb;
    apr_bucket_brigade *tmpbb;
} old_write_filter_ctx;

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_old_write_filter( ap_filter_t *f, apr_bucket_brigade *bb)
{
    old_write_filter_ctx *ctx = f->ctx;

    AP_DEBUG_ASSERT(ctx);

    if (ctx->bb != NULL) {
        
        APR_BRIGADE_PREPEND(bb, ctx->bb);
    }

    return ap_pass_brigade(f->next, bb);
}

static ap_filter_t *insert_old_write_filter(request_rec *r)
{
    ap_filter_t *f;
    old_write_filter_ctx *ctx;

    

    
    for (f = r->output_filters; f != NULL; f = f->next) {
        if (ap_old_write_func == f->frec)
            break;
    }

    if (f == NULL) {
        
        ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        ctx->tmpbb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

        ap_add_output_filter("OLD_WRITE", ctx, r, r->connection);
        f = r->output_filters;
    }

    return f;
}

static apr_status_t buffer_output(request_rec *r, const char *str, apr_size_t len)
{
    conn_rec *c = r->connection;
    ap_filter_t *f;
    old_write_filter_ctx *ctx;

    if (len == 0)
        return APR_SUCCESS;

    f = insert_old_write_filter(r);
    ctx = f->ctx;

    
    if (f != r->output_filters) {
        apr_status_t rv;
        apr_bucket *b = apr_bucket_transient_create(str, len, c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->tmpbb, b);

        rv = ap_pass_brigade(r->output_filters, ctx->tmpbb);
        apr_brigade_cleanup(ctx->tmpbb);
        return rv;
    }

    if (ctx->bb == NULL) {
        ctx->bb = apr_brigade_create(r->pool, c->bucket_alloc);
    }

    return ap_fwrite(f->next, ctx->bb, str, len);
}

AP_DECLARE(int) ap_rputc(int c, request_rec *r)
{
    char c2 = (char)c;

    if (r->connection->aborted) {
        return -1;
    }

    if (buffer_output(r, &c2, 1) != APR_SUCCESS)
        return -1;

    return c;
}

AP_DECLARE(int) ap_rwrite(const void *buf, int nbyte, request_rec *r)
{
    if (r->connection->aborted)
        return -1;

    if (buffer_output(r, buf, nbyte) != APR_SUCCESS)
        return -1;

    return nbyte;
}

struct ap_vrprintf_data {
    apr_vformatter_buff_t vbuff;
    request_rec *r;
    char *buff;
};


static int r_flush(apr_vformatter_buff_t *buff)
{
    

    
    struct ap_vrprintf_data *vd = (struct ap_vrprintf_data*)buff;

    if (vd->r->connection->aborted)
        return -1;

    
    if (buffer_output(vd->r, vd->buff, AP_IOBUFSIZE)) {
        return -1;
    }

    
    vd->vbuff.curpos = vd->buff;
    vd->vbuff.endpos = vd->buff + AP_IOBUFSIZE;

    return 0;
}

AP_DECLARE(int) ap_vrprintf(request_rec *r, const char *fmt, va_list va)
{
    apr_size_t written;
    struct ap_vrprintf_data vd;
    char vrprintf_buf[AP_IOBUFSIZE];

    vd.vbuff.curpos = vrprintf_buf;
    vd.vbuff.endpos = vrprintf_buf + AP_IOBUFSIZE;
    vd.r = r;
    vd.buff = vrprintf_buf;

    if (r->connection->aborted)
        return -1;

    written = apr_vformatter(r_flush, &vd.vbuff, fmt, va);

    if (written != -1) {
        int n = vd.vbuff.curpos - vrprintf_buf;

        
        if (buffer_output(r, vrprintf_buf,n) != APR_SUCCESS)
            return -1;

        written += n;
    }

    return written;
}

AP_DECLARE_NONSTD(int) ap_rprintf(request_rec *r, const char *fmt, ...)
{
    va_list va;
    int n;

    if (r->connection->aborted)
        return -1;

    va_start(va, fmt);
    n = ap_vrprintf(r, fmt, va);
    va_end(va);

    return n;
}

AP_DECLARE_NONSTD(int) ap_rvputs(request_rec *r, ...)
{
    va_list va;
    const char *s;
    apr_size_t len;
    apr_size_t written = 0;

    if (r->connection->aborted)
        return -1;

    
    va_start(va, r);
    while (1) {
        s = va_arg(va, const char *);
        if (s == NULL)
            break;

        len = strlen(s);
        if (buffer_output(r, s, len) != APR_SUCCESS) {
            return -1;
        }

        written += len;
    }
    va_end(va);

    return written;
}

AP_DECLARE(int) ap_rflush(request_rec *r)
{
    conn_rec *c = r->connection;
    apr_bucket *b;
    ap_filter_t *f;
    old_write_filter_ctx *ctx;
    apr_status_t rv;

    f = insert_old_write_filter(r);
    ctx = f->ctx;

    b = apr_bucket_flush_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(ctx->tmpbb, b);

    rv = ap_pass_brigade(r->output_filters, ctx->tmpbb);
    apr_brigade_cleanup(ctx->tmpbb);
    if (rv != APR_SUCCESS)
        return -1;

    return 0;
}


AP_DECLARE(void) ap_set_last_modified(request_rec *r)
{
    if (!r->assbackwards) {
        apr_time_t mod_time = ap_rationalize_mtime(r, r->mtime);
        char *datestr = apr_palloc(r->pool, APR_RFC822_DATE_LEN);

        apr_rfc822_date(datestr, mod_time);
        apr_table_setn(r->headers_out, "Last-Modified", datestr);
    }
}

typedef struct hdr_ptr {
    ap_filter_t *f;
    apr_bucket_brigade *bb;
} hdr_ptr;
static int send_header(void *data, const char *key, const char *val)
{
    ap_fputstrs(((hdr_ptr*)data)->f, ((hdr_ptr*)data)->bb, key, ": ", val, CRLF, NULL);
    return 1;
}
AP_DECLARE(void) ap_send_interim_response(request_rec *r, int send_headers)
{
    hdr_ptr x;
    char *status_line = NULL;
    request_rec *rr;

    if (r->proto_num < HTTP_VERSION(1,1)) {
        
        return;
    }
    if (!ap_is_HTTP_INFO(r->status)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(00575)
                      "Status is %d - not sending interim response", r->status);
        return;
    }
    if ((r->status == HTTP_CONTINUE) && !r->expecting_100) {
        
        return;
    }

    
    for (rr = r; rr != NULL; rr = rr->main) {
        rr->expecting_100 = 0;
    }

    status_line = apr_pstrcat(r->pool, AP_SERVER_PROTOCOL, " ", r->status_line, CRLF, NULL);
    ap_xlate_proto_to_ascii(status_line, strlen(status_line));

    x.f = r->connection->output_filters;
    x.bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);

    ap_fputs(x.f, x.bb, status_line);
    if (send_headers) {
        apr_table_do(send_header, &x, r->headers_out, NULL);
        apr_table_clear(r->headers_out);
    }
    ap_fputs(x.f, x.bb, CRLF_ASCII);
    ap_fflush(x.f, x.bb);
    apr_brigade_destroy(x.bb);
}


AP_IMPLEMENT_HOOK_VOID(pre_read_request, (request_rec *r, conn_rec *c), (r, c))

AP_IMPLEMENT_HOOK_RUN_ALL(int,post_read_request, (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,log_transaction, (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(const char *,http_scheme, (const request_rec *r), (r), NULL)
AP_IMPLEMENT_HOOK_RUN_FIRST(unsigned short,default_port, (const request_rec *r), (r), 0)
AP_IMPLEMENT_HOOK_RUN_FIRST(int, note_auth_failure, (request_rec *r, const char *auth_type), (r, auth_type), DECLINED)

