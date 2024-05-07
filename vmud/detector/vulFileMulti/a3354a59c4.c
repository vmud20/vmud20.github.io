












APR_HOOK_STRUCT( APR_HOOK_LINK(session_load)
                APR_HOOK_LINK(session_save)
                APR_HOOK_LINK(session_encode)
                APR_HOOK_LINK(session_decode)
)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(ap, SESSION, int, session_load, (request_rec * r, session_rec ** z), (r, z), DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(ap, SESSION, int, session_save, (request_rec * r, session_rec * z), (r, z), DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_ALL(ap, SESSION, int, session_encode, (request_rec * r, session_rec * z), (r, z), OK, DECLINED)
APR_IMPLEMENT_EXTERNAL_HOOK_RUN_ALL(ap, SESSION, int, session_decode, (request_rec * r, session_rec * z), (r, z), OK, DECLINED)

static int session_identity_encode(request_rec * r, session_rec * z);
static int session_identity_decode(request_rec * r, session_rec * z);
static int session_fixups(request_rec * r);


static int session_included(request_rec * r, session_dir_conf * conf)
{

    const char **includes = (const char **) conf->includes->elts;
    const char **excludes = (const char **) conf->excludes->elts;
    int included = 1;                
    int i;

    if (conf->includes->nelts) {
        included = 0;
        for (i = 0; !included && i < conf->includes->nelts; i++) {
            const char *include = includes[i];
            if (strncmp(r->uri, include, strlen(include))) {
                included = 1;
            }
        }
    }

    if (conf->excludes->nelts) {
        for (i = 0; included && i < conf->includes->nelts; i++) {
            const char *exclude = excludes[i];
            if (strncmp(r->uri, exclude, strlen(exclude))) {
                included = 0;
            }
        }
    }

    return included;
}


static apr_status_t ap_session_load(request_rec * r, session_rec ** z)
{

    session_dir_conf *dconf = ap_get_module_config(r->per_dir_config, &session_module);
    apr_time_t now;
    session_rec *zz = NULL;
    int rv = 0;

    
    if (!dconf || !dconf->enabled) {
        return APR_SUCCESS;
    }

    
    if (!session_included(r, dconf)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01814)
                      "excluded by configuration for: %s", r->uri);
        return APR_SUCCESS;
    }

    
    rv = ap_run_session_load(r, &zz);
    if (DECLINED == rv) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01815)
                      "session is enabled but no session modules have been configured, " "session not loaded: %s", r->uri);
        return APR_EGENERAL;
    }
    else if (OK != rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01816)
                      "error while loading the session, " "session not loaded: %s", r->uri);
        return rv;
    }

    
    now = apr_time_now();
    if (!zz || (zz->expiry && zz->expiry < now)) {

        
        zz = (session_rec *) apr_pcalloc(r->pool, sizeof(session_rec));
        zz->pool = r->pool;
        zz->entries = apr_table_make(zz->pool, 10);
        zz->uuid = (apr_uuid_t *) apr_pcalloc(zz->pool, sizeof(apr_uuid_t));
        apr_uuid_get(zz->uuid);

    }
    else {
        rv = ap_run_session_decode(r, zz);
        if (OK != rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01817)
                          "error while decoding the session, " "session not loaded: %s", r->uri);
            return rv;
        }
    }

    
    if (!zz->expiry && dconf->maxage) {
        zz->expiry = now + dconf->maxage * APR_USEC_PER_SEC;
        zz->maxage = dconf->maxage;
    }

    *z = zz;

    return APR_SUCCESS;

}


static apr_status_t ap_session_save(request_rec * r, session_rec * z)
{
    if (z) {
        apr_time_t now = apr_time_now();
        int rv = 0;

        session_dir_conf *dconf = ap_get_module_config(r->per_dir_config, &session_module);

        
        if (z->written) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01818)
                          "attempt made to save the session twice, " "session not saved: %s", r->uri);
            return APR_EGENERAL;
        }
        if (z->expiry && z->expiry < now) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01819)
                          "attempt made to save a session when the session had already expired, " "session not saved: %s", r->uri);
            return APR_EGENERAL;
        }

        
        if (dconf->maxage) {
            z->expiry = now + dconf->maxage * APR_USEC_PER_SEC;
            z->maxage = dconf->maxage;
        }

        
        rv = ap_run_session_encode(r, z);
        if (OK != rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01820)
                          "error while encoding the session, " "session not saved: %s", r->uri);
            return rv;
        }

        
        rv = ap_run_session_save(r, z);
        if (DECLINED == rv) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01821)
                          "session is enabled but no session modules have been configured, " "session not saved: %s", r->uri);
            return APR_EGENERAL;
        }
        else if (OK != rv) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01822)
                          "error while saving the session, " "session not saved: %s", r->uri);
            return rv;
        }
        else {
            z->written = 1;
        }
    }

    return APR_SUCCESS;

}


static apr_status_t ap_session_get(request_rec * r, session_rec * z, const char *key, const char **value)
{
    if (!z) {
        apr_status_t rv;
        rv = ap_session_load(r, &z);
        if (APR_SUCCESS != rv) {
            return rv;
        }
    }
    if (z && z->entries) {
        *value = apr_table_get(z->entries, key);
    }

    return OK;
}


static apr_status_t ap_session_set(request_rec * r, session_rec * z, const char *key, const char *value)
{
    if (!z) {
        apr_status_t rv;
        rv = ap_session_load(r, &z);
        if (APR_SUCCESS != rv) {
            return rv;
        }
    }
    if (z) {
        if (value) {
            apr_table_set(z->entries, key, value);
        }
        else {
            apr_table_unset(z->entries, key);
        }
        z->dirty = 1;
    }
    return APR_SUCCESS;
}

static int identity_count(int *count, const char *key, const char *val)
{
    *count += strlen(key) * 3 + strlen(val) * 3 + 1;
    return 1;
}

static int identity_concat(char *buffer, const char *key, const char *val)
{
    char *slider = buffer;
    int length = strlen(slider);
    slider += length;
    if (length) {
        *slider = '&';
        slider++;
    }
    ap_escape_urlencoded_buffer(slider, key);
    slider += strlen(slider);
    *slider = '=';
    slider++;
    ap_escape_urlencoded_buffer(slider, val);
    return 1;
}


static apr_status_t session_identity_encode(request_rec * r, session_rec * z)
{

    char *buffer = NULL;
    int length = 0;
    if (z->expiry) {
        char *expiry = apr_psprintf(z->pool, "%" APR_INT64_T_FMT, z->expiry);
        apr_table_setn(z->entries, SESSION_EXPIRY, expiry);
    }
    apr_table_do((int (*) (void *, const char *, const char *))
                 identity_count, &length, z->entries, NULL);
    buffer = apr_pcalloc(r->pool, length + 1);
    apr_table_do((int (*) (void *, const char *, const char *))
                 identity_concat, buffer, z->entries, NULL);
    z->encoded = buffer;
    return OK;

}


static apr_status_t session_identity_decode(request_rec * r, session_rec * z)
{

    char *last = NULL;
    char *encoded, *pair;
    const char *sep = "&";

    
    if (!z->encoded) {
        return OK;
    }

    
    encoded = apr_pstrdup(r->pool, z->encoded);
    pair = apr_strtok(encoded, sep, &last);
    while (pair && pair[0]) {
        char *plast = NULL;
        const char *psep = "=";
        char *key = apr_strtok(pair, psep, &plast);
        char *val = apr_strtok(NULL, psep, &plast);
        if (key && *key) {
            if (!val || !*val) {
                apr_table_unset(z->entries, key);
            }
            else if (!ap_unescape_urlencoded(key) && !ap_unescape_urlencoded(val)) {
                if (!strcmp(SESSION_EXPIRY, key)) {
                    z->expiry = (apr_time_t) apr_atoi64(val);
                }
                else {
                    apr_table_set(z->entries, key, val);
                }
            }
        }
        pair = apr_strtok(NULL, sep, &last);
    }
    z->encoded = NULL;
    return OK;

}


static apr_status_t session_output_filter(ap_filter_t * f, apr_bucket_brigade * in)
{

    
    request_rec *r = f->r->main;
    if (!r) {
        r = f->r;
    }
    while (r) {
        session_rec *z = NULL;
        session_dir_conf *conf = ap_get_module_config(r->per_dir_config, &session_module);

        
        
        ap_session_load(r, &z);
        if (!z || z->written) {
            r = r->next;
            continue;
        }

        
        if (conf->header_set) {
            const char *override = apr_table_get(r->err_headers_out, conf->header);
            if (!override) {
                override = apr_table_get(r->headers_out, conf->header);
            }
            if (override) {
                z->encoded = override;
                session_identity_decode(r, z);
            }
        }

        
        
        ap_session_save(r, z);

        r = r->next;
    }

    
    ap_remove_output_filter(f);

    
    return ap_pass_brigade(f->next, in);

}


static void session_insert_output_filter(request_rec * r)
{
    ap_add_output_filter("MOD_SESSION_OUT", NULL, r, r->connection);
}


static int session_fixups(request_rec * r)
{
    session_dir_conf *conf = ap_get_module_config(r->per_dir_config, &session_module);

    session_rec *z = NULL;

    
    ap_session_load(r, &z);

    if (z && conf->env) {
        session_identity_encode(r, z);
        if (z->encoded) {
            apr_table_set(r->subprocess_env, HTTP_SESSION, z->encoded);
            z->encoded = NULL;
        }
    }

    return OK;

}


static void *create_session_dir_config(apr_pool_t * p, char *dummy)
{
    session_dir_conf *new = (session_dir_conf *) apr_pcalloc(p, sizeof(session_dir_conf));

    new->includes = apr_array_make(p, 10, sizeof(const char **));
    new->excludes = apr_array_make(p, 10, sizeof(const char **));

    return (void *) new;
}

static void *merge_session_dir_config(apr_pool_t * p, void *basev, void *addv)
{
    session_dir_conf *new = (session_dir_conf *) apr_pcalloc(p, sizeof(session_dir_conf));
    session_dir_conf *add = (session_dir_conf *) addv;
    session_dir_conf *base = (session_dir_conf *) basev;

    new->enabled = (add->enabled_set == 0) ? base->enabled : add->enabled;
    new->enabled_set = add->enabled_set || base->enabled_set;
    new->maxage = (add->maxage_set == 0) ? base->maxage : add->maxage;
    new->maxage_set = add->maxage_set || base->maxage_set;
    new->header = (add->header_set == 0) ? base->header : add->header;
    new->header_set = add->header_set || base->header_set;
    new->env = (add->env_set == 0) ? base->env : add->env;
    new->env_set = add->env_set || base->env_set;
    new->includes = apr_array_append(p, base->includes, add->includes);
    new->excludes = apr_array_append(p, base->excludes, add->excludes);

    return new;
}


static const char * set_session_enable(cmd_parms * parms, void *dconf, int flag)
{
    session_dir_conf *conf = dconf;

    conf->enabled = flag;
    conf->enabled_set = 1;

    return NULL;
}

static const char * set_session_maxage(cmd_parms * parms, void *dconf, const char *arg)
{
    session_dir_conf *conf = dconf;

    conf->maxage = atol(arg);
    conf->maxage_set = 1;

    return NULL;
}

static const char * set_session_header(cmd_parms * parms, void *dconf, const char *arg)
{
    session_dir_conf *conf = dconf;

    conf->header = arg;
    conf->header_set = 1;

    return NULL;
}

static const char * set_session_env(cmd_parms * parms, void *dconf, int flag)
{
    session_dir_conf *conf = dconf;

    conf->env = flag;
    conf->env_set = 1;

    return NULL;
}

static const char *add_session_include(cmd_parms * cmd, void *dconf, const char *f)
{
    session_dir_conf *conf = dconf;

    const char **new = apr_array_push(conf->includes);
    *new = f;

    return NULL;
}

static const char *add_session_exclude(cmd_parms * cmd, void *dconf, const char *f)
{
    session_dir_conf *conf = dconf;

    const char **new = apr_array_push(conf->excludes);
    *new = f;

    return NULL;
}


static const command_rec session_cmds[] = {
    AP_INIT_FLAG("Session", set_session_enable, NULL, RSRC_CONF|OR_AUTHCFG, "on if a session should be maintained for these URLs"), AP_INIT_TAKE1("SessionMaxAge", set_session_maxage, NULL, RSRC_CONF|OR_AUTHCFG, "length of time for which a session should be valid. Zero to disable"), AP_INIT_TAKE1("SessionHeader", set_session_header, NULL, RSRC_CONF|OR_AUTHCFG, "output header, if present, whose contents will be injected into the session."), AP_INIT_FLAG("SessionEnv", set_session_env, NULL, RSRC_CONF|OR_AUTHCFG, "on if a session should be written to the CGI environment. Defaults to off"), AP_INIT_TAKE1("SessionInclude", add_session_include, NULL, RSRC_CONF|OR_AUTHCFG, "URL prefixes to include in the session. Defaults to all URLs"), AP_INIT_TAKE1("SessionExclude", add_session_exclude, NULL, RSRC_CONF|OR_AUTHCFG, "URL prefixes to exclude from the session. Defaults to no URLs"), {NULL}











};

static void register_hooks(apr_pool_t * p)
{
    ap_register_output_filter("MOD_SESSION_OUT", session_output_filter, NULL, AP_FTYPE_CONTENT_SET);
    ap_hook_insert_filter(session_insert_output_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_insert_error_filter(session_insert_output_filter, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_fixups(session_fixups, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_session_encode(session_identity_encode, NULL, NULL, APR_HOOK_REALLY_FIRST);
    ap_hook_session_decode(session_identity_decode, NULL, NULL, APR_HOOK_REALLY_LAST);
    APR_REGISTER_OPTIONAL_FN(ap_session_get);
    APR_REGISTER_OPTIONAL_FN(ap_session_set);
    APR_REGISTER_OPTIONAL_FN(ap_session_load);
    APR_REGISTER_OPTIONAL_FN(ap_session_save);
}

AP_DECLARE_MODULE(session) = {
    STANDARD20_MODULE_STUFF, create_session_dir_config, merge_session_dir_config, NULL, NULL, session_cmds, register_hooks };






