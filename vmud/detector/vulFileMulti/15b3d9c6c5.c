









module AP_MODULE_DECLARE_DATA session_cookie_module;


typedef struct {
    const char *name;
    int name_set;
    const char *name_attrs;
    const char *name2;
    int name2_set;
    const char *name2_attrs;
    int remove;
    int remove_set;
} session_cookie_dir_conf;


static apr_status_t session_cookie_save(request_rec * r, session_rec * z)
{

    session_cookie_dir_conf *conf = ap_get_module_config(r->per_dir_config, &session_cookie_module);

    
    apr_table_addn(r->headers_out, "Cache-Control", "no-cache");

    
    if (conf->name_set) {
        if (z->encoded && z->encoded[0]) {
            ap_cookie_write(r, conf->name, z->encoded, conf->name_attrs, z->maxage, r->headers_out, r->err_headers_out, NULL);

        }
        else {
            ap_cookie_remove(r, conf->name, conf->name_attrs, r->headers_out, r->err_headers_out, NULL);
        }
    }

    
    if (conf->name2_set) {
        if (z->encoded && z->encoded[0]) {
            ap_cookie_write2(r, conf->name2, z->encoded, conf->name2_attrs, z->maxage, r->headers_out, r->err_headers_out, NULL);

        }
        else {
            ap_cookie_remove2(r, conf->name2, conf->name2_attrs, r->headers_out, r->err_headers_out, NULL);
        }
    }

    if (conf->name_set || conf->name2_set) {
        return OK;
    }
    return DECLINED;

}


static apr_status_t session_cookie_load(request_rec * r, session_rec ** z)
{

    session_cookie_dir_conf *conf = ap_get_module_config(r->per_dir_config, &session_cookie_module);

    session_rec *zz = NULL;
    const char *val = NULL;
    const char *note = NULL;
    const char *name = NULL;
    request_rec *m = r;

    
    while (m->prev) {
        m = m->prev;
    }
    
    while (m->main) {
        m = m->main;
    }

    
    if (conf->name2_set) {
        name = conf->name2;
    }
    else if (conf->name_set) {
        name = conf->name;
    }
    else {
        return DECLINED;
    }

    
    note = apr_pstrcat(m->pool, MOD_SESSION_COOKIE, name, NULL);
    zz = (session_rec *)apr_table_get(m->notes, note);
    if (zz) {
        *z = zz;
        return OK;
    }

    
    ap_cookie_read(r, name, &val, conf->remove);

    
    zz = (session_rec *) apr_pcalloc(m->pool, sizeof(session_rec));
    zz->pool = m->pool;
    zz->entries = apr_table_make(m->pool, 10);
    zz->encoded = val;
    zz->uuid = (apr_uuid_t *) apr_pcalloc(m->pool, sizeof(apr_uuid_t));
    *z = zz;

    
    apr_table_setn(m->notes, note, (char *)zz);

    return OK;

}



static void *create_session_cookie_dir_config(apr_pool_t * p, char *dummy)
{
    session_cookie_dir_conf *new = (session_cookie_dir_conf *) apr_pcalloc(p, sizeof(session_cookie_dir_conf));

    return (void *) new;
}

static void *merge_session_cookie_dir_config(apr_pool_t * p, void *basev, void *addv)
{
    session_cookie_dir_conf *new = (session_cookie_dir_conf *)
                                apr_pcalloc(p, sizeof(session_cookie_dir_conf));
    session_cookie_dir_conf *add = (session_cookie_dir_conf *) addv;
    session_cookie_dir_conf *base = (session_cookie_dir_conf *) basev;

    new->name = (add->name_set == 0) ? base->name : add->name;
    new->name_attrs = (add->name_set == 0) ? base->name_attrs : add->name_attrs;
    new->name_set = add->name_set || base->name_set;
    new->name2 = (add->name2_set == 0) ? base->name2 : add->name2;
    new->name2_attrs = (add->name2_set == 0) ? base->name2_attrs : add->name2_attrs;
    new->name2_set = add->name2_set || base->name2_set;
    new->remove = (add->remove_set == 0) ? base->remove : add->remove;
    new->remove_set = add->remove_set || base->remove_set;

    return new;
}


static const char *check_string(cmd_parms * cmd, const char *string)
{
    if (!string || !*string || ap_strchr_c(string, '=') || ap_strchr_c(string, '&')) {
        return apr_pstrcat(cmd->pool, cmd->directive->directive, " cannot be empty, or contain '=' or '&'.", NULL);

    }
    return NULL;
}

static const char *set_cookie_name(cmd_parms * cmd, void *config, const char *args)
{
    char *last;
    char *line = apr_pstrdup(cmd->pool, args);
    session_cookie_dir_conf *conf = (session_cookie_dir_conf *) config;
    char *cookie = apr_strtok(line, " \t", &last);
    conf->name = cookie;
    conf->name_set = 1;
    while (apr_isspace(*last)) {
        last++;
    }
    conf->name_attrs = last;
    return check_string(cmd, cookie);
}

static const char *set_cookie_name2(cmd_parms * cmd, void *config, const char *args)
{
    char *last;
    char *line = apr_pstrdup(cmd->pool, args);
    session_cookie_dir_conf *conf = (session_cookie_dir_conf *) config;
    char *cookie = apr_strtok(line, " \t", &last);
    conf->name2 = cookie;
    conf->name2_set = 1;
    while (apr_isspace(*last)) {
        last++;
    }
    conf->name2_attrs = last;
    return check_string(cmd, cookie);
}

static const char * set_remove(cmd_parms * parms, void *dconf, int flag)
{
    session_cookie_dir_conf *conf = dconf;

    conf->remove = flag;
    conf->remove_set = 1;

    return NULL;
}

static const command_rec session_cookie_cmds[] = {
    AP_INIT_RAW_ARGS("SessionCookieName", set_cookie_name, NULL, RSRC_CONF|OR_AUTHCFG, "The name of the RFC2109 cookie carrying the session"), AP_INIT_RAW_ARGS("SessionCookieName2", set_cookie_name2, NULL, RSRC_CONF|OR_AUTHCFG, "The name of the RFC2965 cookie carrying the session"), AP_INIT_FLAG("SessionCookieRemove", set_remove, NULL, RSRC_CONF|OR_AUTHCFG, "Set to 'On' to remove the session cookie from the headers " "and hide the cookie from a backend server or process"), {NULL}






};

static void register_hooks(apr_pool_t * p)
{
    ap_hook_session_load(session_cookie_load, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_session_save(session_cookie_save, NULL, NULL, APR_HOOK_MIDDLE);
}

AP_DECLARE_MODULE(session_cookie) = {
    STANDARD20_MODULE_STUFF, create_session_cookie_dir_config, merge_session_cookie_dir_config, NULL, NULL, session_cookie_cmds, register_hooks };






