










APR_DECLARE_OPTIONAL_FN(int, ssl_proxy_enable, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(int, ssl_engine_disable, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(char *, ssl_var_lookup, (apr_pool_t *, server_rec *, conn_rec *, request_rec *, char *));












static const char *set_worker_param(apr_pool_t *p, proxy_worker *worker, const char *key, const char *val)


{

    int ival;
    apr_interval_time_t timeout;

    if (!strcasecmp(key, "loadfactor")) {
        
        worker->s->lbfactor = atoi(val);
        if (worker->s->lbfactor < 1 || worker->s->lbfactor > 100)
            return "LoadFactor must be a number between 1..100";
    }
    else if (!strcasecmp(key, "retry")) {
        
        ival = atoi(val);
        if (ival < 0)
            return "Retry must be a positive value";
        worker->s->retry = apr_time_from_sec(ival);
        worker->s->retry_set = 1;
    }
    else if (!strcasecmp(key, "ttl")) {
        
        ival = atoi(val);
        if (ival < 1)
            return "TTL must be at least one second";
        worker->s->ttl = apr_time_from_sec(ival);
    }
    else if (!strcasecmp(key, "min")) {
        
        ival = atoi(val);
        if (ival < 0)
            return "Min must be a positive number";
        worker->s->min = ival;
    }
    else if (!strcasecmp(key, "max")) {
        
        ival = atoi(val);
        if (ival < 0)
            return "Max must be a positive number";
        worker->s->hmax = ival;
    }
    
    else if (!strcasecmp(key, "smax")) {
        
        ival = atoi(val);
        if (ival < 0)
            return "Smax must be a positive number";
        worker->s->smax = ival;
    }
    else if (!strcasecmp(key, "acquire")) {
        
        if (ap_timeout_parameter_parse(val, &timeout, "ms") != APR_SUCCESS)
            return "Acquire timeout has wrong format";
        if (timeout < 1000)
            return "Acquire must be at least one millisecond";
        worker->s->acquire = timeout;
        worker->s->acquire_set = 1;
    }
    else if (!strcasecmp(key, "timeout")) {
        
        ival = atoi(val);
        if (ival < 1)
            return "Timeout must be at least one second";
        worker->s->timeout = apr_time_from_sec(ival);
        worker->s->timeout_set = 1;
    }
    else if (!strcasecmp(key, "iobuffersize")) {
        long s = atol(val);
        if (s < 512 && s) {
            return "IOBufferSize must be >= 512 bytes, or 0 for system default.";
        }
        worker->s->io_buffer_size = (s ? s : AP_IOBUFSIZE);
        worker->s->io_buffer_size_set = 1;
    }
    else if (!strcasecmp(key, "receivebuffersize")) {
        ival = atoi(val);
        if (ival < 512 && ival != 0) {
            return "ReceiveBufferSize must be >= 512 bytes, or 0 for system default.";
        }
        worker->s->recv_buffer_size = ival;
        worker->s->recv_buffer_size_set = 1;
    }
    else if (!strcasecmp(key, "keepalive")) {
        if (!strcasecmp(val, "on"))
            worker->s->keepalive = 1;
        else if (!strcasecmp(val, "off"))
            worker->s->keepalive = 0;
        else return "KeepAlive must be On|Off";
        worker->s->keepalive_set = 1;
    }
    else if (!strcasecmp(key, "disablereuse")) {
        if (!strcasecmp(val, "on"))
            worker->s->disablereuse = 1;
        else if (!strcasecmp(val, "off"))
            worker->s->disablereuse = 0;
        else return "DisableReuse must be On|Off";
        worker->s->disablereuse_set = 1;
    }
    else if (!strcasecmp(key, "route")) {
        
        if (strlen(val) >= PROXY_WORKER_MAX_ROUTE_SIZE)
            return "Route length must be < 64 characters";
        PROXY_STRNCPY(worker->s->route, val);
    }
    else if (!strcasecmp(key, "redirect")) {
        
        if (strlen(val) >= PROXY_WORKER_MAX_ROUTE_SIZE)
            return "Redirect length must be < 64 characters";
        PROXY_STRNCPY(worker->s->redirect, val);
    }
    else if (!strcasecmp(key, "status")) {
        const char *v;
        int mode = 1;
        apr_status_t rv;
        
        for (v = val; *v; v++) {
            if (*v == '+') {
                mode = 1;
                v++;
            }
            else if (*v == '-') {
                mode = 0;
                v++;
            }
            rv = ap_proxy_set_wstatus(*v, mode, worker);
            if (rv != APR_SUCCESS)
                return "Unknown status parameter option";
        }
    }
    else if (!strcasecmp(key, "flushpackets")) {
        if (!strcasecmp(val, "on"))
            worker->s->flush_packets = flush_on;
        else if (!strcasecmp(val, "off"))
            worker->s->flush_packets = flush_off;
        else if (!strcasecmp(val, "auto"))
            worker->s->flush_packets = flush_auto;
        else return "flushpackets must be on|off|auto";
    }
    else if (!strcasecmp(key, "flushwait")) {
        ival = atoi(val);
        if (ival > 1000 || ival < 0) {
            return "flushwait must be <= 1000, or 0 for system default of 10 millseconds.";
        }
        if (ival == 0)
            worker->s->flush_wait = PROXY_FLUSH_WAIT;
        else worker->s->flush_wait = ival * 1000;
    }
    else if (!strcasecmp(key, "ping")) {
        
        if (ap_timeout_parameter_parse(val, &timeout, "s") != APR_SUCCESS)
            return "Ping/Pong timeout has wrong format";
        if (timeout < 1000)
            return "Ping/Pong timeout must be at least one millisecond";
        worker->s->ping_timeout = timeout;
        worker->s->ping_timeout_set = 1;
    }
    else if (!strcasecmp(key, "lbset")) {
        ival = atoi(val);
        if (ival < 0 || ival > 99)
            return "lbset must be between 0 and 99";
        worker->s->lbset = ival;
    }
    else if (!strcasecmp(key, "connectiontimeout")) {
        
        if (ap_timeout_parameter_parse(val, &timeout, "s") != APR_SUCCESS)
            return "Connectiontimeout has wrong format";
        if (timeout < 1000)
            return "Connectiontimeout must be at least one millisecond.";
        worker->s->conn_timeout = timeout;
        worker->s->conn_timeout_set = 1;
    }
    else if (!strcasecmp(key, "flusher")) {
        if (strlen(val) >= PROXY_WORKER_MAX_SCHEME_SIZE)
            return "flusher name length must be < 16 characters";
        PROXY_STRNCPY(worker->s->flusher, val);
    }
    else {
        return "unknown Worker parameter";
    }
    return NULL;
}

static const char *set_balancer_param(proxy_server_conf *conf, apr_pool_t *p, proxy_balancer *balancer, const char *key, const char *val)



{

    int ival;
    if (!strcasecmp(key, "stickysession")) {
        char *path;
        
        if (strlen(val) > (PROXY_BALANCER_MAX_STICKY_SIZE-1))
            return "stickysession length must be < 64 characters";
        PROXY_STRNCPY(balancer->s->sticky_path, val);
        PROXY_STRNCPY(balancer->s->sticky, val);

        if ((path = strchr((char *)balancer->s->sticky, '|'))) {
            *path++ = '\0';
            PROXY_STRNCPY(balancer->s->sticky_path, path);
        }
    }
    else if (!strcasecmp(key, "nofailover")) {
        
        if (!strcasecmp(val, "on"))
            balancer->s->sticky_force = 1;
        else if (!strcasecmp(val, "off"))
            balancer->s->sticky_force = 0;
        else return "failover must be On|Off";
    }
    else if (!strcasecmp(key, "timeout")) {
        
        ival = atoi(val);
        if (ival < 1)
            return "timeout must be at least one second";
        balancer->s->timeout = apr_time_from_sec(ival);
    }
    else if (!strcasecmp(key, "maxattempts")) {
        
        ival = atoi(val);
        if (ival < 0)
            return "maximum number of attempts must be a positive number";
        balancer->s->max_attempts = ival;
        balancer->s->max_attempts_set = 1;
    }
    else if (!strcasecmp(key, "lbmethod")) {
        proxy_balancer_method *provider;
        if (strlen(val) > (sizeof(balancer->s->lbpname)-1))
            return "unknown lbmethod";
        provider = ap_lookup_provider(PROXY_LBMETHOD, val, "0");
        if (provider) {
            balancer->lbmethod = provider;
            if (PROXY_STRNCPY(balancer->s->lbpname, val) == APR_SUCCESS) {
                return NULL;
            }
            else {
                return "lbmethod name too large";
            }
        }
        return "unknown lbmethod";
    }
    else if (!strcasecmp(key, "scolonpathdelim")) {
        
        if (!strcasecmp(val, "on"))
            balancer->s->scolonsep = 1;
        else if (!strcasecmp(val, "off"))
            balancer->s->scolonsep = 0;
        else return "scolonpathdelim must be On|Off";
    }
    else if (!strcasecmp(key, "failonstatus")) {
        char *val_split;
        char *status;
        char *tok_state;

        val_split = apr_pstrdup(p, val);

        balancer->errstatuses = apr_array_make(p, 1, sizeof(int));

        status = apr_strtok(val_split, ", ", &tok_state);
        while (status != NULL) {
            ival = atoi(status);
            if (ap_is_HTTP_VALID_RESPONSE(ival)) {
                *(int *)apr_array_push(balancer->errstatuses) = ival;
            }
            else {
                return "failonstatus must be one or more HTTP response codes";
            }
            status = apr_strtok(NULL, ", ", &tok_state);
        }

    }
    else if (!strcasecmp(key, "nonce")) {
        if (!strcasecmp(val, "None")) {
            *balancer->s->nonce = '\0';
        }
        else {
            if (PROXY_STRNCPY(balancer->s->nonce, val) != APR_SUCCESS) {
                return "Provided nonce is too large";
            }
        }
    }
    else if (!strcasecmp(key, "growth")) {
        ival = atoi(val);
        if (ival < 1 || ival > 100)   
            return "growth must be between 1 and 100";
        balancer->growth = ival;
    }
    else {
        return "unknown Balancer parameter";
    }
    return NULL;
}

static int alias_match(const char *uri, const char *alias_fakename)
{
    const char *end_fakename = alias_fakename + strlen(alias_fakename);
    const char *aliasp = alias_fakename, *urip = uri;
    const char *end_uri = uri + strlen(uri);

    while (aliasp < end_fakename && urip < end_uri) {
        if (*aliasp == '/') {
            
            if (*urip != '/')
                return 0;

            while (*aliasp == '/')
                ++aliasp;
            while (*urip == '/')
                ++urip;
        }
        else {
            
            if (*urip++ != *aliasp++)
                return 0;
        }
    }

    
    if (aliasp > end_fakename) {
        aliasp = end_fakename;
    }
    if (urip > end_uri) {
        urip = end_uri;
    }

   
   if (urip == end_uri && aliasp != end_fakename) {
       return 0;
   }

    
    if (aliasp[-1] != '/' && *urip != '\0' && *urip != '/')
        return 0;

    

    return urip - uri;
}


static int proxy_detect(request_rec *r)
{
    void *sconf = r->server->module_config;
    proxy_server_conf *conf = (proxy_server_conf *) ap_get_module_config(sconf, &proxy_module);

    

    if (conf->req && r->parsed_uri.scheme) {
        
        if (!(r->parsed_uri.hostname && !strcasecmp(r->parsed_uri.scheme, ap_http_scheme(r))
              && ap_matches_request_vhost(r, r->parsed_uri.hostname, (apr_port_t)(r->parsed_uri.port_str ? r->parsed_uri.port : ap_default_port(r))))) {

            r->proxyreq = PROXYREQ_PROXY;
            r->uri = r->unparsed_uri;
            r->filename = apr_pstrcat(r->pool, "proxy:", r->uri, NULL);
            r->handler = "proxy-server";
        }
    }
    
    else if (conf->req && r->method_number == M_CONNECT && r->parsed_uri.hostname && r->parsed_uri.port_str) {

        r->proxyreq = PROXYREQ_PROXY;
        r->uri = r->unparsed_uri;
        r->filename = apr_pstrcat(r->pool, "proxy:", r->uri, NULL);
        r->handler = "proxy-server";
    }
    return DECLINED;
}

static const char *proxy_interpolate(request_rec *r, const char *str)
{
    
    const char *start;
    const char *end;
    const char *var;
    const char *val;
    const char *firstpart;

    start = ap_strstr_c(str, "${");
    if (start == NULL) {
        return str;
    }
    end = ap_strchr_c(start+2, '}');
    if (end == NULL) {
        return str;
    }
    
    var = apr_pstrndup(r->pool, start+2, end-(start+2));
    val = apr_table_get(r->subprocess_env, var);
    firstpart = apr_pstrndup(r->pool, str, (start-str));

    if (val == NULL) {
        return apr_pstrcat(r->pool, firstpart, proxy_interpolate(r, end+1), NULL);
    }
    else {
        return apr_pstrcat(r->pool, firstpart, val, proxy_interpolate(r, end+1), NULL);
    }
}
static apr_array_header_t *proxy_vars(request_rec *r, apr_array_header_t *hdr)
{
    int i;
    apr_array_header_t *ret = apr_array_make(r->pool, hdr->nelts, sizeof (struct proxy_alias));
    struct proxy_alias *old = (struct proxy_alias *) hdr->elts;

    for (i = 0; i < hdr->nelts; ++i) {
        struct proxy_alias *newcopy = apr_array_push(ret);
        newcopy->fake = (old[i].flags & PROXYPASS_INTERPOLATE)
                        ? proxy_interpolate(r, old[i].fake) : old[i].fake;
        newcopy->real = (old[i].flags & PROXYPASS_INTERPOLATE)
                        ? proxy_interpolate(r, old[i].real) : old[i].real;
    }
    return ret;
}

PROXY_DECLARE(int) ap_proxy_trans_match(request_rec *r, struct proxy_alias *ent, proxy_dir_conf *dconf)
{
    int len;
    const char *fake;
    const char *real;
    ap_regmatch_t regm[AP_MAX_REG_MATCH];
    ap_regmatch_t reg1[AP_MAX_REG_MATCH];
    char *found = NULL;
    int mismatch = 0;
    unsigned int nocanon = ent->flags & PROXYPASS_NOCANON;
    const char *use_uri = nocanon ? r->unparsed_uri : r->uri;

    if (dconf && (dconf->interpolate_env == 1) && (ent->flags & PROXYPASS_INTERPOLATE)) {
        fake = proxy_interpolate(r, ent->fake);
        real = proxy_interpolate(r, ent->real);
    }
    else {
        fake = ent->fake;
        real = ent->real;
    }
    if (ent->regex) {
        if (!ap_regexec(ent->regex, r->uri, AP_MAX_REG_MATCH, regm, 0)) {
            if ((real[0] == '!') && (real[1] == '\0')) {
                return DECLINED;
            }
            
            if (nocanon && ap_regexec(ent->regex, r->unparsed_uri, AP_MAX_REG_MATCH, reg1, 0)) {
                mismatch = 1;
                use_uri = r->uri;
            }
            found = ap_pregsub(r->pool, real, use_uri, AP_MAX_REG_MATCH, (use_uri == r->uri) ? regm : reg1);
            if (!found) {
                ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, "Substitution in regular expression failed. " "Replacement too long?");

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            
            if (strcmp(found, real) != 0) {
                found = apr_pstrcat(r->pool, "proxy:", found, NULL);
            }
            else {
                found = apr_pstrcat(r->pool, "proxy:", real, use_uri, NULL);
            }
        }
    }
    else {
        len = alias_match(r->uri, fake);

        if (len != 0) {
            if ((real[0] == '!') && (real[1] == '\0')) {
                return DECLINED;
            }
            if (nocanon && len != alias_match(r->unparsed_uri, ent->fake)) {
                mismatch = 1;
                use_uri = r->uri;
            }
            found = apr_pstrcat(r->pool, "proxy:", real, use_uri + len, NULL);
        }
    }
    if (mismatch) {
        
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "Unescaped URL path matched ProxyPass; ignoring unsafe nocanon");
    }

    if (found) {
        r->filename = found;
        r->handler = "proxy-server";
        r->proxyreq = PROXYREQ_REVERSE;
        if (nocanon && !mismatch) {
            
            apr_table_setn(r->notes, "proxy-nocanon", "1");
        }
        return OK;
    }

    return DONE;
}

static int proxy_trans(request_rec *r)
{
    int i;
    struct proxy_alias *ent;
    proxy_dir_conf *dconf;
    proxy_server_conf *conf;

    if (r->proxyreq) {
        
        return OK;
    }

    

    dconf = ap_get_module_config(r->per_dir_config, &proxy_module);

    
    if (dconf->alias) {
        int rv = ap_proxy_trans_match(r, dconf->alias, dconf);
        if (DONE != rv) {
            return rv;
        }
    }

    conf = (proxy_server_conf *) ap_get_module_config(r->server->module_config, &proxy_module);

    
    if (conf->aliases->nelts) {
        ent = (struct proxy_alias *) conf->aliases->elts;
        for (i = 0; i < conf->aliases->nelts; i++) {
            int rv = ap_proxy_trans_match(r, &ent[i], dconf);
            if (DONE != rv) {
                return rv;
            }
        }
    }
    return DECLINED;
}

static int proxy_walk(request_rec *r)
{
    proxy_server_conf *sconf = ap_get_module_config(r->server->module_config, &proxy_module);
    ap_conf_vector_t *per_dir_defaults = r->server->lookup_defaults;
    ap_conf_vector_t **sec_proxy = (ap_conf_vector_t **) sconf->sec_proxy->elts;
    ap_conf_vector_t *entry_config;
    proxy_dir_conf *entry_proxy;
    int num_sec = sconf->sec_proxy->nelts;
    
    const char *proxyname = r->filename + 6;
    int j;

    for (j = 0; j < num_sec; ++j)
    {
        entry_config = sec_proxy[j];
        entry_proxy = ap_get_module_config(entry_config, &proxy_module);

        
        if (entry_proxy->r ? ap_regexec(entry_proxy->r, proxyname, 0, NULL, 0)
              : (entry_proxy->p_is_fnmatch ? apr_fnmatch(entry_proxy->p, proxyname, 0)
                   : strncmp(proxyname, entry_proxy->p, strlen(entry_proxy->p)))) {
            continue;
        }
        per_dir_defaults = ap_merge_per_dir_configs(r->pool, per_dir_defaults, entry_config);
    }

    r->per_dir_config = per_dir_defaults;

    return OK;
}

static int proxy_map_location(request_rec *r)
{
    int access_status;

    if (!r->proxyreq || !r->filename || strncmp(r->filename, "proxy:", 6) != 0)
        return DECLINED;

    
    if ((access_status = proxy_walk(r))) {
        ap_die(access_status, r);
        return access_status;
    }

    return OK;
}





static int proxy_fixup(request_rec *r)
{
    char *url, *p;
    int access_status;
    proxy_dir_conf *dconf = ap_get_module_config(r->per_dir_config, &proxy_module);

    if (!r->proxyreq || !r->filename || strncmp(r->filename, "proxy:", 6) != 0)
        return DECLINED;

    
    url = &r->filename[6];

    if ((dconf->interpolate_env == 1) && (r->proxyreq == PROXYREQ_REVERSE)) {
        
        proxy_req_conf *rconf = apr_palloc(r->pool, sizeof(proxy_req_conf));
        ap_set_module_config(r->request_config, &proxy_module, rconf);
        rconf->raliases = proxy_vars(r, dconf->raliases);
        rconf->cookie_paths = proxy_vars(r, dconf->cookie_paths);
        rconf->cookie_domains = proxy_vars(r, dconf->cookie_domains);
    }

    
    if ((access_status = proxy_run_canon_handler(r, url))) {
        return access_status;
    }

    p = strchr(url, ':');
    if (p == NULL || p == url)
        return HTTP_BAD_REQUEST;

    return OK;      
}






static int proxy_needsdomain(request_rec *r, const char *url, const char *domain)
{
    char *nuri;
    const char *ref;

    
    if (!r->proxyreq || r->method_number != M_GET || !r->parsed_uri.hostname)
        return DECLINED;

    
    if (strchr(r->parsed_uri.hostname, '.') != NULL  || strchr(r->parsed_uri.hostname, ':') != NULL || strcasecmp(r->parsed_uri.hostname, "localhost") == 0)

        return DECLINED;    

    ref = apr_table_get(r->headers_in, "Referer");

    
    
    r->parsed_uri.hostname = apr_pstrcat(r->pool, r->parsed_uri.hostname, domain, NULL);
    nuri = apr_uri_unparse(r->pool, &r->parsed_uri, APR_URI_UNP_REVEALPASSWORD);


    apr_table_setn(r->headers_out, "Location", nuri);
    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "Domain missing: %s sent to %s%s%s", r->uri, apr_uri_unparse(r->pool, &r->parsed_uri, APR_URI_UNP_OMITUSERINFO), ref ? " from " : "", ref ? ref : "");




    return HTTP_MOVED_PERMANENTLY;
}




static int proxy_handler(request_rec *r)
{
    char *uri, *scheme, *p;
    const char *p2;
    void *sconf = r->server->module_config;
    proxy_server_conf *conf = (proxy_server_conf *)
        ap_get_module_config(sconf, &proxy_module);
    apr_array_header_t *proxies = conf->proxies;
    struct proxy_remote *ents = (struct proxy_remote *) proxies->elts;
    int i, rc, access_status;
    int direct_connect = 0;
    const char *str;
    long maxfwd;
    proxy_balancer *balancer = NULL;
    proxy_worker *worker = NULL;
    int attempts = 0, max_attempts = 0;
    struct dirconn_entry *list = (struct dirconn_entry *)conf->dirconn->elts;

    
    if (!r->proxyreq || !r->filename || strncmp(r->filename, "proxy:", 6) != 0)
        return DECLINED;

    
    if ((str = apr_table_get(r->headers_in, "Max-Forwards"))) {
        maxfwd = strtol(str, NULL, 10);
        if (maxfwd < 1) {
            switch (r->method_number) {
            case M_TRACE: {
                int access_status;
                r->proxyreq = PROXYREQ_NONE;
                if ((access_status = ap_send_http_trace(r)))
                    ap_die(access_status, r);
                else ap_finalize_request_protocol(r);
                return OK;
            }
            case M_OPTIONS: {
                int access_status;
                r->proxyreq = PROXYREQ_NONE;
                if ((access_status = ap_send_http_options(r)))
                    ap_die(access_status, r);
                else ap_finalize_request_protocol(r);
                return OK;
            }
            default: {
                return ap_proxyerror(r, HTTP_BAD_GATEWAY, "Max-Forwards has reached zero - proxy loop?");
            }
            }
        }
        maxfwd = (maxfwd > 0) ? maxfwd - 1 : 0;
    }
    else {
        
        maxfwd = conf->maxfwd;
    }
    if (maxfwd >= 0) {
        apr_table_setn(r->headers_in, "Max-Forwards", apr_psprintf(r->pool, "%ld", maxfwd));
    }

    if (r->method_number == M_TRACE) {
        core_server_config *coreconf = (core_server_config *)
                                       ap_get_core_module_config(sconf);

        if (coreconf->trace_enable == AP_TRACE_DISABLE)
        {
            
            apr_table_setn(r->notes, "error-notes", "TRACE forbidden by server configuration");
            apr_table_setn(r->notes, "verbose-error-to", "*");
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "TRACE forbidden by server configuration");
            return HTTP_METHOD_NOT_ALLOWED;
        }

        
        if (coreconf->trace_enable != AP_TRACE_EXTENDED && (r->read_length || r->read_chunked || r->remaining))
        {
            
            apr_table_setn(r->notes, "error-notes", "TRACE with request body is not allowed");
            apr_table_setn(r->notes, "verbose-error-to", "*");
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "TRACE with request body is not allowed");
            return HTTP_REQUEST_ENTITY_TOO_LARGE;
        }
    }

    uri = r->filename + 6;
    p = strchr(uri, ':');
    if (p == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "proxy_handler no URL in %s", r->filename);
        return HTTP_BAD_REQUEST;
    }

    
    if (conf->domain != NULL) {
        rc = proxy_needsdomain(r, uri, conf->domain);
        if (ap_is_HTTP_REDIRECT(rc))
            return HTTP_MOVED_PERMANENTLY;
    }

    scheme = apr_pstrndup(r->pool, uri, p - uri);
    
    
    for (direct_connect = i = 0; i < conf->dirconn->nelts && !direct_connect; i++) {
        direct_connect = list[i].matcher(&list[i], r);
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, (direct_connect) ? "NoProxy for %s" : "UseProxy for %s", r->uri);



    do {
        char *url = uri;
        
        access_status = ap_proxy_pre_request(&worker, &balancer, r, conf, &url);
        if (access_status != OK) {
            
            if (access_status != HTTP_SERVICE_UNAVAILABLE)
                return access_status;
            
            if (!worker)
                balancer = NULL;
            goto cleanup;
        }

        
        if (balancer) {
            ap_proxy_initialize_worker(worker, r->server, conf->pool);
        }

        if (balancer && balancer->s->max_attempts_set && !max_attempts)
            max_attempts = balancer->s->max_attempts;
        
        if (!direct_connect) {
            for (i = 0; i < proxies->nelts; i++) {
                p2 = ap_strchr_c(ents[i].scheme, ':');  
                if (strcmp(ents[i].scheme, "*") == 0 || (ents[i].use_regex && ap_regexec(ents[i].regexp, url, 0, NULL, 0) == 0) || (p2 == NULL && strcasecmp(scheme, ents[i].scheme) == 0) || (p2 != NULL && strncasecmp(url, ents[i].scheme, strlen(ents[i].scheme)) == 0)) {






                    
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Trying to run scheme_handler against proxy");
                    access_status = proxy_run_scheme_handler(r, worker, conf, url, ents[i].hostname, ents[i].port);



                    
                    if (access_status != DECLINED) {
                        const char *cl_a;
                        char *end;
                        apr_off_t cl;

                        
                        if (access_status != HTTP_BAD_GATEWAY) {
                            goto cleanup;
                        }
                        cl_a = apr_table_get(r->headers_in, "Content-Length");
                        if (cl_a) {
                            apr_strtoff(&cl, cl_a, &end, 10);
                            
                            if (cl > 0) {
                                goto cleanup;
                            }
                        }
                        
                        if (apr_table_get(r->headers_in, "Transfer-Encoding")) {
                            goto cleanup;
                        }
                    }
                }
            }
        }

        
        

        
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Running scheme %s handler (attempt %d)", scheme, attempts);

        AP_PROXY_RUN(r, worker, conf, url, attempts);
        access_status = proxy_run_scheme_handler(r, worker, conf, url, NULL, 0);
        if (access_status == OK)
            break;
        else if (access_status == HTTP_INTERNAL_SERVER_ERROR) {
            
            if (balancer) {
                worker->s->status |= PROXY_WORKER_IN_ERROR;
                worker->s->error_time = apr_time_now();
            }
            break;
        }
        else if (access_status == HTTP_SERVICE_UNAVAILABLE) {
            
            if (balancer) {
                worker->s->status |= PROXY_WORKER_IN_ERROR;
                worker->s->error_time = apr_time_now();
            }
        }
        else {
            
            break;
        }
        
    } while (!PROXY_WORKER_IS_USABLE(worker) && max_attempts > attempts++);

    if (DECLINED == access_status) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "No protocol handler was valid for the URL %s. " "If you are using a DSO version of mod_proxy, make sure " "the proxy submodules are included in the configuration " "using LoadModule.", r->uri);



        access_status = HTTP_INTERNAL_SERVER_ERROR;
        goto cleanup;
    }
cleanup:
    ap_proxy_post_request(worker, balancer, r, conf);

    proxy_run_request_status(&access_status, r);
    AP_PROXY_RUN_FINISHED(r, attempts, access_status);

    return access_status;
}




static void * create_proxy_config(apr_pool_t *p, server_rec *s)
{
    unsigned int id;
    proxy_server_conf *ps = apr_pcalloc(p, sizeof(proxy_server_conf));

    ps->sec_proxy = apr_array_make(p, 10, sizeof(ap_conf_vector_t *));
    ps->proxies = apr_array_make(p, 10, sizeof(struct proxy_remote));
    ps->aliases = apr_array_make(p, 10, sizeof(struct proxy_alias));
    ps->noproxies = apr_array_make(p, 10, sizeof(struct noproxy_entry));
    ps->dirconn = apr_array_make(p, 10, sizeof(struct dirconn_entry));
    ps->workers = apr_array_make(p, 10, sizeof(proxy_worker));
    ps->balancers = apr_array_make(p, 10, sizeof(proxy_balancer));
    ps->forward = NULL;
    ps->reverse = NULL;
    ps->domain = NULL;

    id = ap_proxy_hashfunc(apr_psprintf(p, "%pp-%" APR_TIME_T_FMT, ps, apr_time_now()), PROXY_HASHFUNC_DEFAULT);

    id = ap_proxy_hashfunc(apr_psprintf(p, "%pp", ps), PROXY_HASHFUNC_DEFAULT);

    ps->id = apr_psprintf(p, "s%x", id);
    ps->viaopt = via_off; 
    ps->viaopt_set = 0; 
    ps->req = 0;
    ps->max_balancers = 0;
    ps->bgrowth = 5;
    ps->bgrowth_set = 0;
    ps->req_set = 0;
    ps->recv_buffer_size = 0; 
    ps->recv_buffer_size_set = 0;
    ps->io_buffer_size = AP_IOBUFSIZE;
    ps->io_buffer_size_set = 0;
    ps->maxfwd = DEFAULT_MAX_FORWARDS;
    ps->maxfwd_set = 0;
    ps->timeout = 0;
    ps->timeout_set = 0;
    ps->badopt = bad_error;
    ps->badopt_set = 0;
    ps->source_address = NULL;
    ps->source_address_set = 0;
    ps->pool = p;

    return ps;
}

static void * merge_proxy_config(apr_pool_t *p, void *basev, void *overridesv)
{
    proxy_server_conf *ps = apr_pcalloc(p, sizeof(proxy_server_conf));
    proxy_server_conf *base = (proxy_server_conf *) basev;
    proxy_server_conf *overrides = (proxy_server_conf *) overridesv;

    ps->proxies = apr_array_append(p, base->proxies, overrides->proxies);
    ps->sec_proxy = apr_array_append(p, base->sec_proxy, overrides->sec_proxy);
    ps->aliases = apr_array_append(p, base->aliases, overrides->aliases);
    ps->noproxies = apr_array_append(p, base->noproxies, overrides->noproxies);
    ps->dirconn = apr_array_append(p, base->dirconn, overrides->dirconn);
    ps->workers = apr_array_append(p, base->workers, overrides->workers);
    ps->balancers = apr_array_append(p, base->balancers, overrides->balancers);
    ps->forward = overrides->forward ? overrides->forward : base->forward;
    ps->reverse = overrides->reverse ? overrides->reverse : base->reverse;

    ps->domain = (overrides->domain == NULL) ? base->domain : overrides->domain;
    ps->id = (overrides->id == NULL) ? base->id : overrides->id;
    ps->viaopt = (overrides->viaopt_set == 0) ? base->viaopt : overrides->viaopt;
    ps->viaopt_set = overrides->viaopt_set || base->viaopt_set;
    ps->req = (overrides->req_set == 0) ? base->req : overrides->req;
    ps->req_set = overrides->req_set || base->req_set;
    ps->bgrowth = (overrides->bgrowth_set == 0) ? base->bgrowth : overrides->bgrowth;
    ps->bgrowth_set = overrides->bgrowth_set || base->bgrowth_set;
    ps->max_balancers = overrides->max_balancers || base->max_balancers;
    ps->recv_buffer_size = (overrides->recv_buffer_size_set == 0) ? base->recv_buffer_size : overrides->recv_buffer_size;
    ps->recv_buffer_size_set = overrides->recv_buffer_size_set || base->recv_buffer_size_set;
    ps->io_buffer_size = (overrides->io_buffer_size_set == 0) ? base->io_buffer_size : overrides->io_buffer_size;
    ps->io_buffer_size_set = overrides->io_buffer_size_set || base->io_buffer_size_set;
    ps->maxfwd = (overrides->maxfwd_set == 0) ? base->maxfwd : overrides->maxfwd;
    ps->maxfwd_set = overrides->maxfwd_set || base->maxfwd_set;
    ps->timeout = (overrides->timeout_set == 0) ? base->timeout : overrides->timeout;
    ps->timeout_set = overrides->timeout_set || base->timeout_set;
    ps->badopt = (overrides->badopt_set == 0) ? base->badopt : overrides->badopt;
    ps->badopt_set = overrides->badopt_set || base->badopt_set;
    ps->proxy_status = (overrides->proxy_status_set == 0) ? base->proxy_status : overrides->proxy_status;
    ps->proxy_status_set = overrides->proxy_status_set || base->proxy_status_set;
    ps->source_address = (overrides->source_address_set == 0) ? base->source_address : overrides->source_address;
    ps->source_address_set = overrides->source_address_set || base->source_address_set;
    ps->pool = p;
    return ps;
}
static const char *set_source_address(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf = ap_get_module_config(parms->server->module_config, &proxy_module);
    struct apr_sockaddr_t *addr;

    if (APR_SUCCESS == apr_sockaddr_info_get(&addr, arg, APR_UNSPEC, 0, 0, psf->pool)) {
        psf->source_address = addr;
        psf->source_address_set = 1;
    }
    else {
        return "ProxySourceAddress invalid value";
    }

    return NULL;
}

static void *create_proxy_dir_config(apr_pool_t *p, char *dummy)
{
    proxy_dir_conf *new = (proxy_dir_conf *) apr_pcalloc(p, sizeof(proxy_dir_conf));

    

    
    new->raliases = apr_array_make(p, 10, sizeof(struct proxy_alias));
    new->cookie_paths = apr_array_make(p, 10, sizeof(struct proxy_alias));
    new->cookie_domains = apr_array_make(p, 10, sizeof(struct proxy_alias));
    new->preserve_host_set = 0;
    new->preserve_host = 0;
    new->interpolate_env = -1; 
    new->error_override = 0;
    new->error_override_set = 0;
    new->add_forwarded_headers = 1;

    return (void *) new;
}

static void *merge_proxy_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    proxy_dir_conf *new = (proxy_dir_conf *) apr_pcalloc(p, sizeof(proxy_dir_conf));
    proxy_dir_conf *add = (proxy_dir_conf *) addv;
    proxy_dir_conf *base = (proxy_dir_conf *) basev;

    new->p = add->p;
    new->p_is_fnmatch = add->p_is_fnmatch;
    new->r = add->r;

    
    new->raliases = apr_array_append(p, base->raliases, add->raliases);
    new->cookie_paths = apr_array_append(p, base->cookie_paths, add->cookie_paths);
    new->cookie_domains = apr_array_append(p, base->cookie_domains, add->cookie_domains);
    new->interpolate_env = (add->interpolate_env == -1) ? base->interpolate_env : add->interpolate_env;
    new->preserve_host = (add->preserve_host_set == 0) ? base->preserve_host : add->preserve_host;
    new->preserve_host_set = add->preserve_host_set || base->preserve_host_set;
    new->error_override = (add->error_override_set == 0) ? base->error_override : add->error_override;
    new->error_override_set = add->error_override_set || base->error_override_set;
    new->alias = (add->alias_set == 0) ? base->alias : add->alias;
    new->alias_set = add->alias_set || base->alias_set;
    new->add_forwarded_headers = add->add_forwarded_headers;
    return new;
}


static const char * add_proxy(cmd_parms *cmd, void *dummy, const char *f1, const char *r1, int regex)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf = (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
    struct proxy_remote *new;
    char *p, *q;
    char *r, *f, *scheme;
    ap_regex_t *reg = NULL;
    int port;

    r = apr_pstrdup(cmd->pool, r1);
    scheme = apr_pstrdup(cmd->pool, r1);
    f = apr_pstrdup(cmd->pool, f1);
    p = strchr(r, ':');
    if (p == NULL || p[1] != '/' || p[2] != '/' || p[3] == '\0') {
        if (regex)
            return "ProxyRemoteMatch: Bad syntax for a remote proxy server";
        else return "ProxyRemote: Bad syntax for a remote proxy server";
    }
    else {
        scheme[p-r] = 0;
    }
    q = strchr(p + 3, ':');
    if (q != NULL) {
        if (sscanf(q + 1, "%u", &port) != 1 || port > 65535) {
            if (regex)
                return "ProxyRemoteMatch: Bad syntax for a remote proxy server (bad port number)";
            else return "ProxyRemote: Bad syntax for a remote proxy server (bad port number)";
        }
        *q = '\0';
    }
    else port = -1;
    *p = '\0';
    if (regex) {
        reg = ap_pregcomp(cmd->pool, f, AP_REG_EXTENDED);
        if (!reg)
            return "Regular expression for ProxyRemoteMatch could not be compiled.";
    }
    else if (strchr(f, ':') == NULL)
            ap_str_tolower(f);      
    ap_str_tolower(p + 3);      

    if (port == -1) {
        port = apr_uri_port_of_scheme(scheme);
    }

    new = apr_array_push(conf->proxies);
    new->scheme = f;
    new->protocol = r;
    new->hostname = p + 3;
    new->port = port;
    new->regexp = reg;
    new->use_regex = regex;
    return NULL;
}

static const char * add_proxy_noregex(cmd_parms *cmd, void *dummy, const char *f1, const char *r1)
{
    return add_proxy(cmd, dummy, f1, r1, 0);
}

static const char * add_proxy_regex(cmd_parms *cmd, void *dummy, const char *f1, const char *r1)
{
    return add_proxy(cmd, dummy, f1, r1, 1);
}

static const char * add_pass(cmd_parms *cmd, void *dummy, const char *arg, int is_regex)
{
    proxy_dir_conf *dconf = (proxy_dir_conf *)dummy;
    server_rec *s = cmd->server;
    proxy_server_conf *conf = (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
    struct proxy_alias *new;
    char *f = cmd->path;
    char *r = NULL;
    char *word;
    apr_table_t *params = apr_table_make(cmd->pool, 5);
    const apr_array_header_t *arr;
    const apr_table_entry_t *elts;
    int i;
    int use_regex = is_regex;
    unsigned int flags = 0;
    const char *err;

    err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES);
    if (err) {
        return err;
    }

    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        if (!f) {
            if (!strcmp(word, "~")) {
                if (is_regex) {
                    return "ProxyPassMatch invalid syntax ('~' usage).";
                }
                use_regex = 1;
                continue;
            }
            f = word;
        }
        else if (!r) {
            r = word;
        }
        else if (!strcasecmp(word,"nocanon")) {
            flags |= PROXYPASS_NOCANON;
        }
        else if (!strcasecmp(word,"interpolate")) {
            flags |= PROXYPASS_INTERPOLATE;
        }
        else {
            char *val = strchr(word, '=');
            if (!val) {
                if (cmd->path) {
                    if (*r == '/') {
                        return "ProxyPass|ProxyPassMatch can not have a path when defined in " "a location.";
                    }
                    else {
                        return "Invalid ProxyPass|ProxyPassMatch parameter. Parameter must " "be in the form 'key=value'.";
                    }
                }
                else {
                    return "Invalid ProxyPass|ProxyPassMatch parameter. Parameter must be " "in the form 'key=value'.";
                }
            }
            else *val++ = '\0';
            apr_table_setn(params, word, val);
        }
    };

    if (r == NULL) {
        return "ProxyPass|ProxyPassMatch needs a path when not defined in a location";
    }

    
    if (cmd->path) {
        dconf->alias = apr_pcalloc(cmd->pool, sizeof(struct proxy_alias));
        dconf->alias_set = 1;
        new = dconf->alias;
        if (apr_fnmatch_test(f)) {
            use_regex = 1;
        }
    }
    
    else {
        new = apr_array_push(conf->aliases);
    }

    new->fake = apr_pstrdup(cmd->pool, f);
    new->real = apr_pstrdup(cmd->pool, r);
    new->flags = flags;
    if (use_regex) {
        new->regex = ap_pregcomp(cmd->pool, f, AP_REG_EXTENDED);
        if (new->regex == NULL)
            return "Regular expression could not be compiled.";
    }
    else {
        new->regex = NULL;
    }

    if (r[0] == '!' && r[1] == '\0')
        return NULL;

    arr = apr_table_elts(params);
    elts = (const apr_table_entry_t *)arr->elts;
    
    if (ap_proxy_valid_balancer_name(r, 9)) {
        proxy_balancer *balancer = ap_proxy_get_balancer(cmd->pool, conf, r, 0);
        if (!balancer) {
            const char *err = ap_proxy_define_balancer(cmd->pool, &balancer, conf, r, f, 0);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass ", err, NULL);
        }
        else {
            ap_proxy_update_balancer(cmd->pool, balancer, f);
        }
        for (i = 0; i < arr->nelts; i++) {
            const char *err = set_balancer_param(conf, cmd->pool, balancer, elts[i].key, elts[i].val);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass ", err, NULL);
        }
        new->balancer = balancer;
    }
    else {
        proxy_worker *worker = ap_proxy_get_worker(cmd->temp_pool, NULL, conf, r);
        int reuse = 0;
        if (!worker) {
            const char *err = ap_proxy_define_worker(cmd->pool, &worker, NULL, conf, r, 0);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "ProxyPass ", err, NULL);

            PROXY_COPY_CONF_PARAMS(worker, conf);
        } else {
            reuse = 1;
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, cmd->server, "Sharing worker '%s' instead of creating new worker '%s'", worker->s->name, new->real);

        }

        for (i = 0; i < arr->nelts; i++) {
            if (reuse) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server, "Ignoring parameter '%s=%s' for worker '%s' because of worker sharing", elts[i].key, elts[i].val, worker->s->name);

            } else {
                const char *err = set_worker_param(cmd->pool, worker, elts[i].key, elts[i].val);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, "ProxyPass ", err, NULL);
            }
        }
    }
    return NULL;
}

static const char * add_pass_noregex(cmd_parms *cmd, void *dummy, const char *arg)
{
    return add_pass(cmd, dummy, arg, 0);
}

static const char * add_pass_regex(cmd_parms *cmd, void *dummy, const char *arg)
{
    return add_pass(cmd, dummy, arg, 1);
}


static const char * add_pass_reverse(cmd_parms *cmd, void *dconf, const char *f, const char *r, const char *i)
{
    proxy_dir_conf *conf = dconf;
    struct proxy_alias *new;
    const char *fake;
    const char *real;
    const char *interp;
    const char *err;

    err = ap_check_cmd_context(cmd, NOT_IN_DIRECTORY|NOT_IN_FILES);
    if (err) {
        return err;
    }

    if (cmd->path == NULL) {
        if (r == NULL || !strcasecmp(r, "interpolate")) {
            return "ProxyPassReverse needs a path when not defined in a location";
        }
        fake = f;
        real = r;
        interp = i;
    }
    else {
        if (r && strcasecmp(r, "interpolate")) {
            return "ProxyPassReverse can not have a path when defined in a location";
        }
        fake = cmd->path;
        real = f;
        interp = r;
    }

    new = apr_array_push(conf->raliases);
    new->fake = fake;
    new->real = real;
    new->flags = interp ? PROXYPASS_INTERPOLATE : 0;

    return NULL;
}
static const char* cookie_path(cmd_parms *cmd, void *dconf, const char *f, const char *r, const char *interp)
{
    proxy_dir_conf *conf = dconf;
    struct proxy_alias *new;

    new = apr_array_push(conf->cookie_paths);
    new->fake = f;
    new->real = r;
    new->flags = interp ? PROXYPASS_INTERPOLATE : 0;

    return NULL;
}
static const char* cookie_domain(cmd_parms *cmd, void *dconf, const char *f, const char *r, const char *interp)
{
    proxy_dir_conf *conf = dconf;
    struct proxy_alias *new;

    new = apr_array_push(conf->cookie_domains);
    new->fake = f;
    new->real = r;
    new->flags = interp ? PROXYPASS_INTERPOLATE : 0;
    return NULL;
}

static const char * set_proxy_exclude(cmd_parms *parms, void *dummy, const char *arg)
{
    server_rec *s = parms->server;
    proxy_server_conf *conf = ap_get_module_config(s->module_config, &proxy_module);
    struct noproxy_entry *new;
    struct noproxy_entry *list = (struct noproxy_entry *) conf->noproxies->elts;
    struct apr_sockaddr_t *addr;
    int found = 0;
    int i;

    
    for (i = 0; i < conf->noproxies->nelts; i++) {
        if (strcasecmp(arg, list[i].name) == 0) { 
            found = 1;
        }
    }

    if (!found) {
        new = apr_array_push(conf->noproxies);
        new->name = arg;
        if (APR_SUCCESS == apr_sockaddr_info_get(&addr, new->name, APR_UNSPEC, 0, 0, parms->pool)) {
            new->addr = addr;
        }
        else {
            new->addr = NULL;
        }
    }
    return NULL;
}



static const char * set_proxy_dirconn(cmd_parms *parms, void *dummy, const char *arg)
{
    server_rec *s = parms->server;
    proxy_server_conf *conf = ap_get_module_config(s->module_config, &proxy_module);
    struct dirconn_entry *New;
    struct dirconn_entry *list = (struct dirconn_entry *) conf->dirconn->elts;
    int found = 0;
    int i;

    
    for (i = 0; i < conf->dirconn->nelts; i++) {
        if (strcasecmp(arg, list[i].name) == 0)
            found = 1;
    }

    if (!found) {
        New = apr_array_push(conf->dirconn);
        New->name = apr_pstrdup(parms->pool, arg);
        New->hostaddr = NULL;

    if (ap_proxy_is_ipaddr(New, parms->pool)) {

        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, "Parsed addr %s", inet_ntoa(New->addr));
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, "Parsed mask %s", inet_ntoa(New->mask));

    }
    else if (ap_proxy_is_domainname(New, parms->pool)) {
        ap_str_tolower(New->name);

        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, "Parsed domain %s", New->name);

        }
        else if (ap_proxy_is_hostname(New, parms->pool)) {
            ap_str_tolower(New->name);

            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, "Parsed host %s", New->name);

        }
        else {
            ap_proxy_is_word(New, parms->pool);

            fprintf(stderr, "Parsed word %s\n", New->name);

        }
    }
    return NULL;
}

static const char * set_proxy_domain(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf = ap_get_module_config(parms->server->module_config, &proxy_module);

    if (arg[0] != '.')
        return "ProxyDomain: domain name must start with a dot.";

    psf->domain = arg;
    return NULL;
}

static const char * set_proxy_req(cmd_parms *parms, void *dummy, int flag)
{
    proxy_server_conf *psf = ap_get_module_config(parms->server->module_config, &proxy_module);

    psf->req = flag;
    psf->req_set = 1;
    return NULL;
}

static const char * set_proxy_error_override(cmd_parms *parms, void *dconf, int flag)
{
    proxy_dir_conf *conf = dconf;

    conf->error_override = flag;
    conf->error_override_set = 1;
    return NULL;
}
static const char * add_proxy_http_headers(cmd_parms *parms, void *dconf, int flag)
{
   proxy_dir_conf *conf = dconf;
   conf->add_forwarded_headers = flag;
   return NULL;
}
static const char * set_preserve_host(cmd_parms *parms, void *dconf, int flag)
{
    proxy_dir_conf *conf = dconf;

    conf->preserve_host = flag;
    conf->preserve_host_set = 1;
    return NULL;
}

static const char * set_recv_buffer_size(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf = ap_get_module_config(parms->server->module_config, &proxy_module);
    int s = atoi(arg);
    if (s < 512 && s != 0) {
        return "ProxyReceiveBufferSize must be >= 512 bytes, or 0 for system default.";
    }

    psf->recv_buffer_size = s;
    psf->recv_buffer_size_set = 1;
    return NULL;
}

static const char * set_io_buffer_size(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf = ap_get_module_config(parms->server->module_config, &proxy_module);
    long s = atol(arg);
    if (s < 512 && s) {
        return "ProxyIOBufferSize must be >= 512 bytes, or 0 for system default.";
    }
    psf->io_buffer_size = (s ? s : AP_IOBUFSIZE);
    psf->io_buffer_size_set = 1;
    return NULL;
}

static const char * set_max_forwards(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf = ap_get_module_config(parms->server->module_config, &proxy_module);
    long s = atol(arg);

    psf->maxfwd = s;
    psf->maxfwd_set = 1;
    return NULL;
}
static const char* set_proxy_timeout(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf = ap_get_module_config(parms->server->module_config, &proxy_module);
    int timeout;

    timeout = atoi(arg);
    if (timeout<1) {
        return "Proxy Timeout must be at least 1 second.";
    }
    psf->timeout_set = 1;
    psf->timeout = apr_time_from_sec(timeout);

    return NULL;
}

static const char* set_via_opt(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf = ap_get_module_config(parms->server->module_config, &proxy_module);

    if (strcasecmp(arg, "Off") == 0)
        psf->viaopt = via_off;
    else if (strcasecmp(arg, "On") == 0)
        psf->viaopt = via_on;
    else if (strcasecmp(arg, "Block") == 0)
        psf->viaopt = via_block;
    else if (strcasecmp(arg, "Full") == 0)
        psf->viaopt = via_full;
    else {
        return "ProxyVia must be one of: " "off | on | full | block";
    }

    psf->viaopt_set = 1;
    return NULL;
}

static const char* set_bad_opt(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf = ap_get_module_config(parms->server->module_config, &proxy_module);

    if (strcasecmp(arg, "IsError") == 0)
        psf->badopt = bad_error;
    else if (strcasecmp(arg, "Ignore") == 0)
        psf->badopt = bad_ignore;
    else if (strcasecmp(arg, "StartBody") == 0)
        psf->badopt = bad_body;
    else {
        return "ProxyBadHeader must be one of: " "IsError | Ignore | StartBody";
    }

    psf->badopt_set = 1;
    return NULL;
}

static const char* set_status_opt(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf = ap_get_module_config(parms->server->module_config, &proxy_module);

    if (strcasecmp(arg, "Off") == 0)
        psf->proxy_status = status_off;
    else if (strcasecmp(arg, "On") == 0)
        psf->proxy_status = status_on;
    else if (strcasecmp(arg, "Full") == 0)
        psf->proxy_status = status_full;
    else {
        return "ProxyStatus must be one of: " "off | on | full";
    }

    psf->proxy_status_set = 1;
    return NULL;
}

static const char *set_bgrowth(cmd_parms *parms, void *dummy, const char *arg)
{
    proxy_server_conf *psf = ap_get_module_config(parms->server->module_config, &proxy_module);

    int growth = atoi(arg);
    if (growth < 0 || growth > 1000) {
        return "BalancerGrowth must be between 0 and 1000";
    }
    psf->bgrowth = growth;
    psf->bgrowth_set = 1;

    return NULL;
}

static const char *add_member(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf = ap_get_module_config(s->module_config, &proxy_module);
    proxy_balancer *balancer;
    proxy_worker *worker;
    char *path = cmd->path;
    char *name = NULL;
    char *word;
    apr_table_t *params = apr_table_make(cmd->pool, 5);
    const apr_array_header_t *arr;
    const apr_table_entry_t *elts;
    int reuse = 0;
    int i;
    
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err)
        return err;

    if (cmd->path)
        path = apr_pstrdup(cmd->pool, cmd->path);

    while (*arg) {
        char *val;
        word = ap_getword_conf(cmd->pool, &arg);
        val = strchr(word, '=');

        if (!val) {
            if (!path)
                path = word;
            else if (!name)
                name = word;
            else {
                if (cmd->path)
                    return "BalancerMember can not have a balancer name when defined in a location";
                else return "Invalid BalancerMember parameter. Parameter must " "be in the form 'key=value'";

            }
        } else {
            *val++ = '\0';
            apr_table_setn(params, word, val);
        }
    }
    if (!path)
        return "BalancerMember must define balancer name when outside <Proxy > section";
    if (!name)
        return "BalancerMember must define remote proxy server";

    ap_str_tolower(path);   

    
    balancer = ap_proxy_get_balancer(cmd->temp_pool, conf, path, 0);
    if (!balancer) {
        err = ap_proxy_define_balancer(cmd->pool, &balancer, conf, path, "/", 0);
        if (err)
            return apr_pstrcat(cmd->temp_pool, "BalancerMember ", err, NULL);
    }

    
    worker = ap_proxy_get_worker(cmd->temp_pool, balancer, conf, name);
    if (!worker) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "Defining worker '%s' for balancer '%s'", name, balancer->s->name);

        if ((err = ap_proxy_define_worker(cmd->pool, &worker, balancer, conf, name, 0)) != NULL)
            return apr_pstrcat(cmd->temp_pool, "BalancerMember ", err, NULL);
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server, "Defined worker '%s' for balancer '%s'", worker->s->name, balancer->s->name);

        PROXY_COPY_CONF_PARAMS(worker, conf);
    } else {
        reuse = 1;
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, cmd->server, "Sharing worker '%s' instead of creating new worker '%s'", worker->s->name, name);

    }

    arr = apr_table_elts(params);
    elts = (const apr_table_entry_t *)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        if (reuse) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server, "Ignoring parameter '%s=%s' for worker '%s' because of worker sharing", elts[i].key, elts[i].val, worker->s->name);

        } else {
            err = set_worker_param(cmd->pool, worker, elts[i].key, elts[i].val);
            if (err)
                return apr_pstrcat(cmd->temp_pool, "BalancerMember ", err, NULL);
        }
    }

    return NULL;
}

static const char * set_proxy_param(cmd_parms *cmd, void *dummy, const char *arg)
{
    server_rec *s = cmd->server;
    proxy_server_conf *conf = (proxy_server_conf *) ap_get_module_config(s->module_config, &proxy_module);
    char *name = NULL;
    char *word, *val;
    proxy_balancer *balancer = NULL;
    proxy_worker *worker = NULL;
    int in_proxy_section = 0;
    
    const char *err = ap_check_cmd_context(cmd, NOT_IN_HTACCESS);
    if (err)
        return err;

    if (cmd->directive->parent && strncasecmp(cmd->directive->parent->directive, "<Proxy", 6) == 0) {

        const char *pargs = cmd->directive->parent->args;
        
        name = ap_getword_conf(cmd->temp_pool, &pargs);
        if ((word = ap_strchr(name, '>')))
            *word = '\0';
        in_proxy_section = 1;
    }
    else {
        
        name = ap_getword_conf(cmd->temp_pool, &arg);
    }

    if (ap_proxy_valid_balancer_name(name, 9)) {
        balancer = ap_proxy_get_balancer(cmd->pool, conf, name, 0);
        if (!balancer) {
            if (in_proxy_section) {
                err = ap_proxy_define_balancer(cmd->pool, &balancer, conf, name, "/", 0);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, "ProxySet ", err, NULL);
            }
            else return apr_pstrcat(cmd->temp_pool, "ProxySet can not find '", name, "' Balancer.", NULL);

        }
    }
    else {
        worker = ap_proxy_get_worker(cmd->temp_pool, NULL, conf, name);
        if (!worker) {
            if (in_proxy_section) {
                err = ap_proxy_define_worker(cmd->pool, &worker, NULL, conf, name, 0);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, "ProxySet ", err, NULL);
            }
            else return apr_pstrcat(cmd->temp_pool, "ProxySet can not find '", name, "' Worker.", NULL);

        }
    }

    while (*arg) {
        word = ap_getword_conf(cmd->pool, &arg);
        val = strchr(word, '=');
        if (!val) {
            return "Invalid ProxySet parameter. Parameter must be " "in the form 'key=value'";
        }
        else *val++ = '\0';
        if (worker)
            err = set_worker_param(cmd->pool, worker, word, val);
        else err = set_balancer_param(conf, cmd->pool, balancer, word, val);

        if (err)
            return apr_pstrcat(cmd->temp_pool, "ProxySet: ", err, " ", word, "=", val, "; ", name, NULL);
    }

    return NULL;
}

static void ap_add_per_proxy_conf(server_rec *s, ap_conf_vector_t *dir_config)
{
    proxy_server_conf *sconf = ap_get_module_config(s->module_config, &proxy_module);
    void **new_space = (void **)apr_array_push(sconf->sec_proxy);

    *new_space = dir_config;
}

static const char *proxysection(cmd_parms *cmd, void *mconfig, const char *arg)
{
    const char *errmsg;
    const char *endp = ap_strrchr_c(arg, '>');
    int old_overrides = cmd->override;
    char *old_path = cmd->path;
    proxy_dir_conf *conf;
    ap_conf_vector_t *new_dir_conf = ap_create_per_dir_config(cmd->pool);
    ap_regex_t *r = NULL;
    const command_rec *thiscmd = cmd->cmd;
    char *word, *val;
    proxy_balancer *balancer = NULL;
    proxy_worker *worker = NULL;

    const char *err = ap_check_cmd_context(cmd, NOT_IN_DIR_LOC_FILE);
    proxy_server_conf *sconf = (proxy_server_conf *) ap_get_module_config(cmd->server->module_config, &proxy_module);

    if (err != NULL) {
        return err;
    }

    if (endp == NULL) {
        return apr_pstrcat(cmd->pool, cmd->cmd->name, "> directive missing closing '>'", NULL);
    }

    arg = apr_pstrndup(cmd->pool, arg, endp-arg);

    if (!arg) {
        if (thiscmd->cmd_data)
            return "<ProxyMatch > block must specify a path";
        else return "<Proxy > block must specify a path";
    }

    cmd->path = ap_getword_conf(cmd->pool, &arg);
    cmd->override = OR_ALL|ACCESS_CONF;

    if (!strncasecmp(cmd->path, "proxy:", 6))
        cmd->path += 6;

    
    if (thiscmd->cmd_data) { 
        r = ap_pregcomp(cmd->pool, cmd->path, AP_REG_EXTENDED);
        if (!r) {
            return "Regex could not be compiled";
        }
    }
    else if (!strcmp(cmd->path, "~")) {
        cmd->path = ap_getword_conf(cmd->pool, &arg);
        if (!cmd->path)
            return "<Proxy ~ > block must specify a path";
        if (strncasecmp(cmd->path, "proxy:", 6))
            cmd->path += 6;
        r = ap_pregcomp(cmd->pool, cmd->path, AP_REG_EXTENDED);
        if (!r) {
            return "Regex could not be compiled";
        }
    }

    
    conf = ap_set_config_vectors(cmd->server, new_dir_conf, cmd->path, &proxy_module, cmd->pool);

    errmsg = ap_walk_config(cmd->directive->first_child, cmd, new_dir_conf);
    if (errmsg != NULL)
        return errmsg;

    conf->r = r;
    conf->p = cmd->path;
    conf->p_is_fnmatch = apr_fnmatch_test(conf->p);

    ap_add_per_proxy_conf(cmd->server, new_dir_conf);

    if (*arg != '\0') {
        if (thiscmd->cmd_data)
            return "Multiple <ProxyMatch> arguments not (yet) supported.";
        if (conf->p_is_fnmatch)
            return apr_pstrcat(cmd->pool, thiscmd->name, "> arguments are not supported for wildchar url.", NULL);

        if (!ap_strchr_c(conf->p, ':'))
            return apr_pstrcat(cmd->pool, thiscmd->name, "> arguments are not supported for non url.", NULL);

        if (ap_proxy_valid_balancer_name((char *)conf->p, 9)) {
            balancer = ap_proxy_get_balancer(cmd->pool, sconf, conf->p, 0);
            if (!balancer) {
                err = ap_proxy_define_balancer(cmd->pool, &balancer, sconf, conf->p, "/", 0);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, thiscmd->name, " ", err, NULL);
            }
        }
        else {
            worker = ap_proxy_get_worker(cmd->temp_pool, NULL, sconf, conf->p);
            if (!worker) {
                err = ap_proxy_define_worker(cmd->pool, &worker, NULL, sconf, conf->p, 0);
                if (err)
                    return apr_pstrcat(cmd->temp_pool, thiscmd->name, " ", err, NULL);
            }
        }
        if (worker == NULL && balancer == NULL) {
            return apr_pstrcat(cmd->pool, thiscmd->name, "> arguments are supported only for workers.", NULL);

        }
        while (*arg) {
            word = ap_getword_conf(cmd->pool, &arg);
            val = strchr(word, '=');
            if (!val) {
                return "Invalid Proxy parameter. Parameter must be " "in the form 'key=value'";
            }
            else *val++ = '\0';
            if (worker)
                err = set_worker_param(cmd->pool, worker, word, val);
            else err = set_balancer_param(sconf, cmd->pool, balancer, word, val);

            if (err)
                return apr_pstrcat(cmd->temp_pool, thiscmd->name, " ", err, " ", word, "=", val, "; ", conf->p, NULL);
        }
    }

    cmd->path = old_path;
    cmd->override = old_overrides;

    return NULL;
}

static const command_rec proxy_cmds[] = {
    AP_INIT_RAW_ARGS("<Proxy", proxysection, NULL, RSRC_CONF, "Container for directives affecting resources located in the proxied " "location"), AP_INIT_RAW_ARGS("<ProxyMatch", proxysection, (void*)1, RSRC_CONF, "Container for directives affecting resources located in the proxied " "location, in regular expression syntax"), AP_INIT_FLAG("ProxyRequests", set_proxy_req, NULL, RSRC_CONF, "on if the true proxy requests should be accepted"), AP_INIT_TAKE2("ProxyRemote", add_proxy_noregex, NULL, RSRC_CONF, "a scheme, partial URL or '*' and a proxy server"), AP_INIT_TAKE2("ProxyRemoteMatch", add_proxy_regex, NULL, RSRC_CONF, "a regex pattern and a proxy server"), AP_INIT_FLAG("ProxyPassInterpolateEnv", ap_set_flag_slot_char, (void*)APR_OFFSETOF(proxy_dir_conf, interpolate_env), RSRC_CONF|ACCESS_CONF, "Interpolate Env Vars in reverse Proxy") , AP_INIT_RAW_ARGS("ProxyPass", add_pass_noregex, NULL, RSRC_CONF|ACCESS_CONF, "a virtual path and a URL"), AP_INIT_RAW_ARGS("ProxyPassMatch", add_pass_regex, NULL, RSRC_CONF|ACCESS_CONF, "a virtual path and a URL"), AP_INIT_TAKE123("ProxyPassReverse", add_pass_reverse, NULL, RSRC_CONF|ACCESS_CONF, "a virtual path and a URL for reverse proxy behaviour"), AP_INIT_TAKE23("ProxyPassReverseCookiePath", cookie_path, NULL, RSRC_CONF|ACCESS_CONF, "Path rewrite rule for proxying cookies"), AP_INIT_TAKE23("ProxyPassReverseCookieDomain", cookie_domain, NULL, RSRC_CONF|ACCESS_CONF, "Domain rewrite rule for proxying cookies"), AP_INIT_ITERATE("ProxyBlock", set_proxy_exclude, NULL, RSRC_CONF, "A list of names, hosts or domains to which the proxy will not connect"), AP_INIT_TAKE1("ProxyReceiveBufferSize", set_recv_buffer_size, NULL, RSRC_CONF, "Receive buffer size for outgoing HTTP and FTP connections in bytes"), AP_INIT_TAKE1("ProxyIOBufferSize", set_io_buffer_size, NULL, RSRC_CONF, "IO buffer size for outgoing HTTP and FTP connections in bytes"), AP_INIT_TAKE1("ProxyMaxForwards", set_max_forwards, NULL, RSRC_CONF, "The maximum number of proxies a request may be forwarded through."), AP_INIT_ITERATE("NoProxy", set_proxy_dirconn, NULL, RSRC_CONF, "A list of domains, hosts, or subnets to which the proxy will connect directly"), AP_INIT_TAKE1("ProxyDomain", set_proxy_domain, NULL, RSRC_CONF, "The default intranet domain name (in absence of a domain in the URL)"), AP_INIT_TAKE1("ProxyVia", set_via_opt, NULL, RSRC_CONF, "Configure Via: proxy header header to one of: on | off | block | full"), AP_INIT_FLAG("ProxyErrorOverride", set_proxy_error_override, NULL, RSRC_CONF|ACCESS_CONF, "use our error handling pages instead of the servers' we are proxying"), AP_INIT_FLAG("ProxyPreserveHost", set_preserve_host, NULL, RSRC_CONF|ACCESS_CONF, "on if we should preserve host header while proxying"), AP_INIT_TAKE1("ProxyTimeout", set_proxy_timeout, NULL, RSRC_CONF, "Set the timeout (in seconds) for a proxied connection. " "This overrides the server timeout"), AP_INIT_TAKE1("ProxyBadHeader", set_bad_opt, NULL, RSRC_CONF, "How to handle bad header line in response: IsError | Ignore | StartBody"), AP_INIT_RAW_ARGS("BalancerMember", add_member, NULL, RSRC_CONF|ACCESS_CONF, "A balancer name and scheme with list of params"), AP_INIT_TAKE1("BalancerGrowth", set_bgrowth, NULL, RSRC_CONF, "Number of additional Balancers that can be added post-config"), AP_INIT_TAKE1("ProxyStatus", set_status_opt, NULL, RSRC_CONF, "Configure Status: proxy status to one of: on | off | full"), AP_INIT_RAW_ARGS("ProxySet", set_proxy_param, NULL, RSRC_CONF|ACCESS_CONF, "A balancer or worker name with list of params"), AP_INIT_TAKE1("ProxySourceAddress", set_source_address, NULL, RSRC_CONF, "Configure local source IP used for request forward"), AP_INIT_FLAG("ProxyAddHeaders", add_proxy_http_headers, NULL, RSRC_CONF|ACCESS_CONF, "on if X-Forwarded-* headers should be added or completed"), {NULL}



























































};

static APR_OPTIONAL_FN_TYPE(ssl_proxy_enable) *proxy_ssl_enable = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_engine_disable) *proxy_ssl_disable = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *proxy_is_https = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *proxy_ssl_val = NULL;

PROXY_DECLARE(int) ap_proxy_ssl_enable(conn_rec *c)
{
    
    if (proxy_ssl_enable) {
        return c ? proxy_ssl_enable(c) : 1;
    }

    return 0;
}

PROXY_DECLARE(int) ap_proxy_ssl_disable(conn_rec *c)
{
    if (proxy_ssl_disable) {
        return proxy_ssl_disable(c);
    }

    return 0;
}

PROXY_DECLARE(int) ap_proxy_conn_is_https(conn_rec *c)
{
    if (proxy_is_https) {
        return proxy_is_https(c);
    }
    else return 0;
}

PROXY_DECLARE(const char *) ap_proxy_ssl_val(apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, const char *var)

{
    if (proxy_ssl_val) {
        
        return (const char *)proxy_ssl_val(p, s, c, r, (char *)var);
    }
    else return NULL;
}

static int proxy_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{

    proxy_ssl_enable = APR_RETRIEVE_OPTIONAL_FN(ssl_proxy_enable);
    proxy_ssl_disable = APR_RETRIEVE_OPTIONAL_FN(ssl_engine_disable);
    proxy_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
    proxy_ssl_val = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
    ap_proxy_strmatch_path = apr_strmatch_precompile(pconf, "path=", 0);
    ap_proxy_strmatch_domain = apr_strmatch_precompile(pconf, "domain=", 0);

    return OK;
}


static int proxy_status_hook(request_rec *r, int flags)
{
    int i, n;
    void *sconf = r->server->module_config;
    proxy_server_conf *conf = (proxy_server_conf *)
        ap_get_module_config(sconf, &proxy_module);
    proxy_balancer *balancer = NULL;
    proxy_worker **worker = NULL;

    if (flags & AP_STATUS_SHORT || conf->balancers->nelts == 0 || conf->proxy_status == status_off)
        return OK;

    balancer = (proxy_balancer *)conf->balancers->elts;
    for (i = 0; i < conf->balancers->nelts; i++) {
        ap_rputs("<hr />\n<h1>Proxy LoadBalancer Status for ", r);
        ap_rvputs(r, balancer->s->name, "</h1>\n\n", NULL);
        ap_rputs("\n\n<table border=\"0\"><tr>" "<th>SSes</th><th>Timeout</th><th>Method</th>" "</tr>\n<tr>", r);

        if (*balancer->s->sticky) {
            if (strcmp(balancer->s->sticky, balancer->s->sticky_path)) {
                ap_rvputs(r, "<td>", balancer->s->sticky, " | ", balancer->s->sticky_path, NULL);
            }
            else {
                ap_rvputs(r, "<td>", balancer->s->sticky, NULL);
            }
        }
        else {
            ap_rputs("<td> - ", r);
        }
        ap_rprintf(r, "</td><td>%" APR_TIME_T_FMT "</td>", apr_time_sec(balancer->s->timeout));
        ap_rprintf(r, "<td>%s</td>\n", balancer->lbmethod->name);
        ap_rputs("</table>\n", r);
        ap_rputs("\n\n<table border=\"0\"><tr>" "<th>Sch</th><th>Host</th><th>Stat</th>" "<th>Route</th><th>Redir</th>" "<th>F</th><th>Set</th><th>Acc</th><th>Wr</th><th>Rd</th>" "</tr>\n", r);




        worker = (proxy_worker **)balancer->workers->elts;
        for (n = 0; n < balancer->workers->nelts; n++) {
            char fbuf[50];
            ap_rvputs(r, "<tr>\n<td>", (*worker)->s->scheme, "</td>", NULL);
            ap_rvputs(r, "<td>", (*worker)->s->hostname, "</td><td>", NULL);
            ap_rvputs(r, ap_proxy_parse_wstatus(r->pool, *worker), NULL);
            ap_rvputs(r, "</td><td>", (*worker)->s->route, NULL);
            ap_rvputs(r, "</td><td>", (*worker)->s->redirect, NULL);
            ap_rprintf(r, "</td><td>%d</td>", (*worker)->s->lbfactor);
            ap_rprintf(r, "<td>%d</td>", (*worker)->s->lbset);
            ap_rprintf(r, "<td>%" APR_SIZE_T_FMT "</td><td>", (*worker)->s->elected);
            ap_rputs(apr_strfsize((*worker)->s->transferred, fbuf), r);
            ap_rputs("</td><td>", r);
            ap_rputs(apr_strfsize((*worker)->s->read, fbuf), r);
            ap_rputs("</td>\n", r);

            
            ap_rputs("</tr>\n", r);

            ++worker;
        }
        ap_rputs("</table>\n", r);
        ++balancer;
    }
    ap_rputs("<hr /><table>\n" "<tr><th>SSes</th><td>Sticky session name</td></tr>\n" "<tr><th>Timeout</th><td>Balancer Timeout</td></tr>\n" "<tr><th>Sch</th><td>Connection scheme</td></tr>\n" "<tr><th>Host</th><td>Backend Hostname</td></tr>\n" "<tr><th>Stat</th><td>Worker status</td></tr>\n" "<tr><th>Route</th><td>Session Route</td></tr>\n" "<tr><th>Redir</th><td>Session Route Redirection</td></tr>\n" "<tr><th>F</th><td>Load Balancer Factor</td></tr>\n" "<tr><th>Acc</th><td>Number of uses</td></tr>\n" "<tr><th>Wr</th><td>Number of bytes transferred</td></tr>\n" "<tr><th>Rd</th><td>Number of bytes read</td></tr>\n" "</table>", r);












    return OK;
}

static void child_init(apr_pool_t *p, server_rec *s)
{
    proxy_worker *reverse = NULL;

    
    while (s) {
        void *sconf = s->module_config;
        proxy_server_conf *conf;
        proxy_worker *worker;
        int i;

        conf = (proxy_server_conf *)ap_get_module_config(sconf, &proxy_module);
        
        worker = (proxy_worker *)conf->workers->elts;
        for (i = 0; i < conf->workers->nelts; i++, worker++) {
            ap_proxy_initialize_worker(worker, s, conf->pool);
        }
        
        if (conf->req_set && conf->req) {
            proxy_worker *forward;
            ap_proxy_define_worker(p, &forward, NULL, NULL, "http://www.apache.org", 0);
            conf->forward = forward;
            PROXY_STRNCPY(conf->forward->s->name,     "proxy:forward");
            PROXY_STRNCPY(conf->forward->s->hostname, "*");
            PROXY_STRNCPY(conf->forward->s->scheme,   "*");
            conf->forward->hash.def = conf->forward->s->hash.def = ap_proxy_hashfunc(conf->forward->s->name, PROXY_HASHFUNC_DEFAULT);
             conf->forward->hash.fnv = conf->forward->s->hash.fnv = ap_proxy_hashfunc(conf->forward->s->name, PROXY_HASHFUNC_FNV);
            
            conf->forward->s->status |= PROXY_WORKER_IGNORE_ERRORS;
            
            conf->forward->s->is_address_reusable = 0;
            ap_proxy_initialize_worker(conf->forward, s, conf->pool);
        }
        if (!reverse) {
            ap_proxy_define_worker(p, &reverse, NULL, NULL, "http://www.apache.org", 0);
            PROXY_STRNCPY(reverse->s->name,     "proxy:reverse");
            PROXY_STRNCPY(reverse->s->hostname, "*");
            PROXY_STRNCPY(reverse->s->scheme,   "*");
            reverse->hash.def = reverse->s->hash.def = ap_proxy_hashfunc(reverse->s->name, PROXY_HASHFUNC_DEFAULT);
            reverse->hash.fnv = reverse->s->hash.fnv = ap_proxy_hashfunc(reverse->s->name, PROXY_HASHFUNC_FNV);
            
            reverse->s->status |= PROXY_WORKER_IGNORE_ERRORS;
            
            reverse->s->is_address_reusable = 0;
        }
        conf->reverse = reverse;
        ap_proxy_initialize_worker(conf->reverse, s, conf->pool);
        s = s->next;
    }
}


static int proxy_pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)
{
    APR_OPTIONAL_HOOK(ap, status_hook, proxy_status_hook, NULL, NULL, APR_HOOK_MIDDLE);
    
    proxy_lb_workers = 0;
    return OK;
}
static void register_hooks(apr_pool_t *p)
{
    
    static const char * const aszSucc[] = { "mod_rewrite.c", NULL};
    
    static const char *const aszPred[] = { "mpm_winnt.c", "mod_proxy_balancer.c", NULL};

    
    ap_hook_handler(proxy_handler, NULL, NULL, APR_HOOK_FIRST);
    
    ap_hook_translate_name(proxy_trans, aszSucc, NULL, APR_HOOK_FIRST);
    
    ap_hook_map_to_storage(proxy_map_location, NULL,NULL, APR_HOOK_FIRST);
    
    ap_hook_fixups(proxy_fixup, NULL, aszSucc, APR_HOOK_FIRST);
    
    ap_hook_post_read_request(proxy_detect, NULL, NULL, APR_HOOK_FIRST);
    
    ap_hook_pre_config(proxy_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    
    ap_hook_post_config(proxy_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    
    ap_hook_child_init(child_init, aszPred, NULL, APR_HOOK_MIDDLE);

}

AP_DECLARE_MODULE(proxy) = {
    STANDARD20_MODULE_STUFF, create_proxy_dir_config, merge_proxy_dir_config, create_proxy_config, merge_proxy_config, proxy_cmds, register_hooks };







APR_HOOK_STRUCT( APR_HOOK_LINK(scheme_handler)
    APR_HOOK_LINK(canon_handler)
    APR_HOOK_LINK(pre_request)
    APR_HOOK_LINK(post_request)
    APR_HOOK_LINK(request_status)
)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, scheme_handler, (request_rec *r, proxy_worker *worker, proxy_server_conf *conf, char *url, const char *proxyhost, apr_port_t proxyport),(r,worker,conf, url,proxyhost,proxyport),DECLINED)




APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, canon_handler, (request_rec *r, char *url),(r, url),DECLINED)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, pre_request, ( proxy_worker **worker, proxy_balancer **balancer, request_rec *r, proxy_server_conf *conf, char **url),(worker,balancer, r,conf,url),DECLINED)





APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(proxy, PROXY, int, post_request, (proxy_worker *worker, proxy_balancer *balancer, request_rec *r, proxy_server_conf *conf),(worker, balancer,r,conf),DECLINED)




APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(proxy, PROXY, int, fixups, (request_rec *r), (r), OK, DECLINED)

APR_IMPLEMENT_OPTIONAL_HOOK_RUN_ALL(proxy, PROXY, int, request_status, (int *status, request_rec *r), (status, r), OK, DECLINED)


