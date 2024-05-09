



APLOG_USE_MODULE(cache);

extern APR_OPTIONAL_FN_TYPE(ap_cache_generate_key) *cache_generate_key;

extern module AP_MODULE_DECLARE_DATA cache_module;




int cache_remove_url(cache_request_rec *cache, apr_pool_t *p)
{
    cache_provider_list *list;
    cache_handle_t *h;

    list = cache->providers;

    
    h = cache->stale_handle ? cache->stale_handle : cache->handle;
    if (!h) {
       return OK;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "cache: Removing url %s from the cache", h->cache_obj->key);

    
    while(list) {
        list->provider->remove_url(h, p);
        list = list->next;
    }
    return OK;
}



int cache_create_entity(request_rec *r, apr_off_t size)
{
    cache_provider_list *list;
    cache_handle_t *h = apr_pcalloc(r->pool, sizeof(cache_handle_t));
    char *key;
    apr_status_t rv;
    cache_request_rec *cache = (cache_request_rec *)
                         ap_get_module_config(r->request_config, &cache_module);

    rv = cache_generate_key(r, r->pool, &key);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    list = cache->providers;
    
    while (list) {
        switch (rv = list->provider->create_entity(h, r, key, size)) {
        case OK: {
            cache->handle = h;
            cache->provider = list->provider;
            cache->provider_name = list->provider_name;
            return OK;
        }
        case DECLINED: {
            list = list->next;
            continue;
        }
        default: {
            return rv;
        }
        }
    }
    return DECLINED;
}

static int set_cookie_doo_doo(void *v, const char *key, const char *val)
{
    apr_table_addn(v, key, val);
    return 1;
}

CACHE_DECLARE(void) ap_cache_accept_headers(cache_handle_t *h, request_rec *r, int preserve_orig)
{
    apr_table_t *cookie_table, *hdr_copy;
    const char *v;

    v = apr_table_get(h->resp_hdrs, "Content-Type");
    if (v) {
        ap_set_content_type(r, v);
        apr_table_unset(h->resp_hdrs, "Content-Type");
        
        apr_table_unset(r->headers_out, "Content-Type");
        apr_table_unset(r->err_headers_out, "Content-Type");
    }

    
    v = apr_table_get(h->resp_hdrs, "Last-Modified");
    if (v) {
        ap_update_mtime(r, apr_date_parse_http(v));
        ap_set_last_modified(r);
        apr_table_unset(h->resp_hdrs, "Last-Modified");
    }

    
    cookie_table = apr_table_make(r->pool, 2);
    apr_table_do(set_cookie_doo_doo, cookie_table, r->err_headers_out, "Set-Cookie", NULL);
    apr_table_do(set_cookie_doo_doo, cookie_table, h->resp_hdrs, "Set-Cookie", NULL);
    apr_table_unset(r->err_headers_out, "Set-Cookie");
    apr_table_unset(h->resp_hdrs, "Set-Cookie");

    if (preserve_orig) {
        hdr_copy = apr_table_copy(r->pool, h->resp_hdrs);
        apr_table_overlap(hdr_copy, r->headers_out, APR_OVERLAP_TABLES_SET);
        r->headers_out = hdr_copy;
    }
    else {
        apr_table_overlap(r->headers_out, h->resp_hdrs, APR_OVERLAP_TABLES_SET);
    }
    if (!apr_is_empty_table(cookie_table)) {
        r->err_headers_out = apr_table_overlay(r->pool, r->err_headers_out, cookie_table);
    }
}


int cache_select(request_rec *r)
{
    cache_provider_list *list;
    apr_status_t rv;
    cache_handle_t *h;
    char *key;
    cache_request_rec *cache = (cache_request_rec *)
                         ap_get_module_config(r->request_config, &cache_module);

    rv = cache_generate_key(r, r->pool, &key);
    if (rv != APR_SUCCESS) {
        return rv;
    }
    
    h = apr_palloc(r->pool, sizeof(cache_handle_t));

    list = cache->providers;

    while (list) {
        switch ((rv = list->provider->open_entity(h, r, key))) {
        case OK: {
            char *vary = NULL;
            int fresh;

            if (list->provider->recall_headers(h, r) != APR_SUCCESS) {
                
                return DECLINED;
            }

            
            vary = apr_pstrdup(r->pool, apr_table_get(h->resp_hdrs, "Vary"));
            while (vary && *vary) {
                char *name = vary;
                const char *h1, *h2;

                
                while (*vary && !apr_isspace(*vary) && (*vary != ','))
                    ++vary;
                while (*vary && (apr_isspace(*vary) || (*vary == ','))) {
                    *vary = '\0';
                    ++vary;
                }

                
                h1 = apr_table_get(r->headers_in, name);
                h2 = apr_table_get(h->req_hdrs, name);
                if (h1 == h2) {
                    
                }
                else if (h1 && h2 && !strcmp(h1, h2)) {
                    
                }
                else {
                    
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "cache_select_url(): Vary header mismatch.");

                    return DECLINED;
                }
            }

            cache->provider = list->provider;
            cache->provider_name = list->provider_name;

            
            fresh = ap_cache_check_freshness(h, r);
            if (!fresh) {
                const char *etag, *lastmod;

                ap_log_error(APLOG_MARK, APLOG_DEBUG, APR_SUCCESS, r->server, "Cached response for %s isn't fresh.  Adding/replacing " "conditional request headers.", r->uri);


                
                cache->stale_headers = apr_table_copy(r->pool, r->headers_in);

                
                apr_table_unset(r->headers_in, "If-Match");
                apr_table_unset(r->headers_in, "If-Modified-Since");
                apr_table_unset(r->headers_in, "If-None-Match");
                apr_table_unset(r->headers_in, "If-Range");
                apr_table_unset(r->headers_in, "If-Unmodified-Since");

                
                apr_table_unset(r->headers_in, "Range");

                etag = apr_table_get(h->resp_hdrs, "ETag");
                lastmod = apr_table_get(h->resp_hdrs, "Last-Modified");

                if (etag || lastmod) {
                    

                    if (etag) {
                        apr_table_set(r->headers_in, "If-None-Match", etag);
                    }

                    if (lastmod) {
                        apr_table_set(r->headers_in, "If-Modified-Since", lastmod);
                    }
                    cache->stale_handle = h;
                }
                else {
                    int irv;

                    
                    irv = cache->provider->remove_url(h, r->pool);
                    if (irv != OK) {
                        ap_log_error(APLOG_MARK, APLOG_DEBUG, irv, r->server, "cache: attempt to remove url from cache unsuccessful.");
                    }
                }

                return DECLINED;
            }

            
            ap_cache_accept_headers(h, r, 0);

            cache->handle = h;
            return OK;
        }
        case DECLINED: {
            
            list = list->next;
            continue;
        }
        default: {
            
            return rv;
        }
        }
    }
    return DECLINED;
}

apr_status_t cache_generate_key_default(request_rec *r, apr_pool_t* p, char**key)
{
    cache_server_conf *conf;
    cache_request_rec *cache;
    char *port_str, *hn, *lcs;
    const char *hostname, *scheme;
    int i;
    char *path, *querystring;

    cache = (cache_request_rec *) ap_get_module_config(r->request_config, &cache_module);
    if (!cache) {
        
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "cache: No cache request information available for key" " generation");

        *key = "";
        return APR_EGENERAL;
    }
    if (cache->key) {
        
        *key = apr_pstrdup(p, cache->key);
        return APR_SUCCESS;
    }

    
    conf = (cache_server_conf *) ap_get_module_config(r->server->module_config, &cache_module);

    
    if (!r->proxyreq || (r->proxyreq == PROXYREQ_REVERSE)) {
        
        hostname =  ap_get_server_name(r);
        if (!hostname) {
            hostname = "_default_";
        }
    }
    else if(r->parsed_uri.hostname) {
        
        hn = apr_pstrdup(p, r->parsed_uri.hostname);
        ap_str_tolower(hn);
        
        hostname = hn;
    }
    else {
        
        hostname = "_default_";
    }

    
    if (r->proxyreq && r->parsed_uri.scheme) {
        
        lcs = apr_pstrdup(p, r->parsed_uri.scheme);
        ap_str_tolower(lcs);
        
        scheme = lcs;
    }
    else {
        scheme = ap_http_scheme(r);
    }

    
    if(r->proxyreq && (r->proxyreq != PROXYREQ_REVERSE)) {
        if (r->parsed_uri.port_str) {
            port_str = apr_pcalloc(p, strlen(r->parsed_uri.port_str) + 2);
            port_str[0] = ':';
            for (i = 0; r->parsed_uri.port_str[i]; i++) {
                port_str[i + 1] = apr_tolower(r->parsed_uri.port_str[i]);
            }
        }
        else if (apr_uri_port_of_scheme(scheme)) {
            port_str = apr_psprintf(p, ":%u", apr_uri_port_of_scheme(scheme));
        }
        else {
            
            port_str = "";
        }
    }
    else {
        
        port_str = apr_psprintf(p, ":%u", ap_get_server_port(r));
    }

    
    path = r->parsed_uri.path;
    querystring = r->parsed_uri.query;
    if (conf->ignore_session_id->nelts) {
        int i;
        char **identifier;

        identifier = (char **)conf->ignore_session_id->elts;
        for (i = 0; i < conf->ignore_session_id->nelts; i++, identifier++) {
            int len;
            char *param;

            len = strlen(*identifier);
            
            if ((param = strrchr(path, ';'))
                && !strncmp(param + 1, *identifier, len)
                && (*(param + len + 1) == '=')
                && !strchr(param + len + 2, '/')) {
                path = apr_pstrndup(p, path, param - path);
                continue;
            }
            
            if (querystring) {
                
                if (!strncmp(querystring, *identifier, len)
                    && (*(querystring + len) == '=')) {
                    param = querystring;
                }
                else {
                    char *complete;

                    
                    complete = apr_pstrcat(p, "&", *identifier, "=", NULL);
                    param = strstr(querystring, complete);
                    
                    if (param) {
                        param++;
                    }
                }
                if (param) {
                    char *amp;

                    if (querystring != param) {
                        querystring = apr_pstrndup(p, querystring, param - querystring);
                    }
                    else {
                        querystring = "";
                    }

                    if ((amp = strchr(param + len + 1, '&'))) {
                        querystring = apr_pstrcat(p, querystring, amp + 1, NULL);
                    }
                    else {
                        
                        if (*querystring) {
                            querystring[strlen(querystring) - 1] = '\0';
                        }
                    }
                }
            }
        }
    }

    
    if (conf->ignorequerystring) {
        *key = apr_pstrcat(p, scheme, "://", hostname, port_str, path, "?", NULL);
    }
    else {
        *key = apr_pstrcat(p, scheme, "://", hostname, port_str, path, "?", querystring, NULL);
    }

    
    cache->key = apr_pstrdup(r->pool, *key);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "cache: Key for entity %s?%s is %s", r->parsed_uri.path, r->parsed_uri.query, *key);


    return APR_SUCCESS;
}
