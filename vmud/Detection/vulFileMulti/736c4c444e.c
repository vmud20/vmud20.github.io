




































APR_HOOK_STRUCT( APR_HOOK_LINK(translate_name)
    APR_HOOK_LINK(map_to_storage)
    APR_HOOK_LINK(check_user_id)
    APR_HOOK_LINK(fixups)
    APR_HOOK_LINK(type_checker)
    APR_HOOK_LINK(access_checker)
    APR_HOOK_LINK(access_checker_ex)
    APR_HOOK_LINK(auth_checker)
    APR_HOOK_LINK(insert_filter)
    APR_HOOK_LINK(create_request)
    APR_HOOK_LINK(post_perdir_config)
    APR_HOOK_LINK(dirwalk_stat)
)

AP_IMPLEMENT_HOOK_RUN_FIRST(int,translate_name, (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,map_to_storage, (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,check_user_id, (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,fixups, (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,type_checker, (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int,access_checker, (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,access_checker_ex, (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(int,auth_checker, (request_rec *r), (r), DECLINED)
AP_IMPLEMENT_HOOK_VOID(insert_filter, (request_rec *r), (r))
AP_IMPLEMENT_HOOK_RUN_ALL(int, create_request, (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_ALL(int, post_perdir_config, (request_rec *r), (r), OK, DECLINED)
AP_IMPLEMENT_HOOK_RUN_FIRST(apr_status_t,dirwalk_stat, (apr_finfo_t *finfo, request_rec *r, apr_int32_t wanted), (finfo, r, wanted), AP_DECLINED)


static int auth_internal_per_conf = 0;
static int auth_internal_per_conf_hooks = 0;
static int auth_internal_per_conf_providers = 0;


static int decl_die(int status, const char *phase, request_rec *r)
{
    if (status == DECLINED) {
        ap_log_rerror(APLOG_MARK, APLOG_CRIT, 0, r, APLOGNO(00025)
                      "configuration error:  couldn't %s: %s", phase, r->uri);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "auth phase '%s' gave status %d: %s", phase, status, r->uri);

        return status;
    }
}


AP_DECLARE(int) ap_process_request_internal(request_rec *r)
{
    int file_req = (r->main && r->filename);
    int access_status;
    core_dir_config *d;

    
    if (!r->proxyreq && r->parsed_uri.path) {
        d = ap_get_core_module_config(r->per_dir_config);
        if (d->allow_encoded_slashes) {
            access_status = ap_unescape_url_keep2f(r->parsed_uri.path, d->decode_encoded_slashes);
        }
        else {
            access_status = ap_unescape_url(r->parsed_uri.path);
        }
        if (access_status) {
            if (access_status == HTTP_NOT_FOUND) {
                if (! d->allow_encoded_slashes) {
                    ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00026)
                                  "found %%2f (encoded '/') in URI " "(decoded='%s'), returning 404", r->parsed_uri.path);

                }
            }
            return access_status;
        }
    }

    ap_getparents(r->uri);     

    
    if (!file_req) {
        if ((access_status = ap_location_walk(r))) {
            return access_status;
        }
        if ((access_status = ap_if_walk(r))) {
            return access_status;
        }

        
        if (!r->connection->log) {
            d = ap_get_core_module_config(r->per_dir_config);
            if (d->log)
                r->log = d->log;
        }

        if ((access_status = ap_run_translate_name(r))) {
            return decl_die(access_status, "translate", r);
        }
    }

    
    r->per_dir_config = r->server->lookup_defaults;

    if ((access_status = ap_run_map_to_storage(r))) {
        
        return access_status;
    }

    
    if ((access_status = ap_location_walk(r))) {
        return access_status;
    }
    if ((access_status = ap_if_walk(r))) {
        return access_status;
    }

    
    if (!r->connection->log) {
        d = ap_get_core_module_config(r->per_dir_config);
        if (d->log)
            r->log = d->log;
    }

    if ((access_status = ap_run_post_perdir_config(r))) {
        return access_status;
    }

    
    if (r->main == NULL) {
        if ((access_status = ap_run_header_parser(r))) {
            return access_status;
        }
    }

    
    if (r->prev && (r->prev->per_dir_config == r->per_dir_config)) {
        r->user = r->prev->user;
        r->ap_auth_type = r->prev->ap_auth_type;
    }
    else if (r->main && (r->main->per_dir_config == r->per_dir_config)) {
        r->user = r->main->user;
        r->ap_auth_type = r->main->ap_auth_type;
    }
    else {
        switch (ap_satisfies(r)) {
        case SATISFY_ALL:
        case SATISFY_NOSPEC:
            if ((access_status = ap_run_access_checker(r)) != OK) {
                return decl_die(access_status, "check access (with Satisfy All)", r);
            }

            access_status = ap_run_access_checker_ex(r);
            if (access_status == OK) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "request authorized without authentication by " "access_checker_ex hook: %s", r->uri);

            }
            else if (access_status != DECLINED) {
                return decl_die(access_status, "check access", r);
            }
            else {
                if ((access_status = ap_run_check_user_id(r)) != OK) {
                    return decl_die(access_status, "check user", r);
                }
                if (r->user == NULL) {
                    
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00027)
                                  "No authentication done but request not " "allowed without authentication for %s. " "Authentication not configured?", r->uri);


                    access_status = HTTP_INTERNAL_SERVER_ERROR;
                    return decl_die(access_status, "check user", r);
                }
                if ((access_status = ap_run_auth_checker(r)) != OK) {
                    return decl_die(access_status, "check authorization", r);
                }
            }
            break;
        case SATISFY_ANY:
            if ((access_status = ap_run_access_checker(r)) == OK) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "request authorized without authentication by " "access_checker hook and 'Satisfy any': %s", r->uri);


                break;
            }

            access_status = ap_run_access_checker_ex(r);
            if (access_status == OK) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "request authorized without authentication by " "access_checker_ex hook: %s", r->uri);

            }
            else if (access_status != DECLINED) {
                return decl_die(access_status, "check access", r);
            }
            else {
                if ((access_status = ap_run_check_user_id(r)) != OK) {
                    return decl_die(access_status, "check user", r);
                }
                if (r->user == NULL) {
                    
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00028)
                                  "No authentication done but request not " "allowed without authentication for %s. " "Authentication not configured?", r->uri);


                    access_status = HTTP_INTERNAL_SERVER_ERROR;
                    return decl_die(access_status, "check user", r);
                }
                if ((access_status = ap_run_auth_checker(r)) != OK) {
                    return decl_die(access_status, "check authorization", r);
                }
            }
            break;
        }
    }
    
    if ((access_status = ap_run_type_checker(r)) != OK) {
        return decl_die(access_status, "find types", r);
    }

    if ((access_status = ap_run_fixups(r)) != OK) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "fixups hook gave %d: %s", access_status, r->uri);
        return access_status;
    }

    return OK;
}




typedef struct walk_walked_t {
    ap_conf_vector_t *matched; 
    ap_conf_vector_t *merged;  
} walk_walked_t;

typedef struct walk_cache_t {
    const char         *cached;          
    ap_conf_vector_t  **dir_conf_tested; 
    ap_conf_vector_t   *dir_conf_merged; 
    ap_conf_vector_t   *per_dir_result;  
    apr_array_header_t *walked;          
    struct walk_cache_t *prev; 
    int count; 
} walk_cache_t;

static walk_cache_t *prep_walk_cache(apr_size_t t, request_rec *r)
{
    void **note, **inherit_note;
    walk_cache_t *cache, *prev_cache, *copy_cache;
    int count;

    
    note = ap_get_request_note(r, t);
    AP_DEBUG_ASSERT(note != NULL);

    copy_cache = prev_cache = *note;
    count = prev_cache ? (prev_cache->count + 1) : 0;

    if ((r->prev && (inherit_note = ap_get_request_note(r->prev, t))
         && *inherit_note)
        || (r->main && (inherit_note = ap_get_request_note(r->main, t))
            && *inherit_note)) {
        walk_cache_t *inherit_cache = *inherit_note;

        while (inherit_cache->count > count) {
            inherit_cache = inherit_cache->prev;
        }
        if (inherit_cache->count == count) {
            copy_cache = inherit_cache;
        }
    }

    if (copy_cache) {
        cache = apr_pmemdup(r->pool, copy_cache, sizeof(*cache));
        cache->walked = apr_array_copy(r->pool, cache->walked);
        cache->prev = prev_cache;
        cache->count = count;
    }
    else {
        cache = apr_pcalloc(r->pool, sizeof(*cache));
        cache->walked = apr_array_make(r->pool, 4, sizeof(walk_walked_t));
    }

    *note = cache;

    return cache;
}





static int resolve_symlink(char *d, apr_finfo_t *lfi, int opts, apr_pool_t *p)
{
    apr_finfo_t fi;
    const char *savename;

    if (!(opts & (OPT_SYM_OWNER | OPT_SYM_LINKS))) {
        return HTTP_FORBIDDEN;
    }

    
    savename = (lfi->valid & APR_FINFO_NAME) ? lfi->name : NULL;

    
    if (!(opts & OPT_SYM_OWNER)) {
        if (apr_stat(&fi, d, lfi->valid & ~(APR_FINFO_NAME | APR_FINFO_LINK), p)
            != APR_SUCCESS)
        {
            return HTTP_FORBIDDEN;
        }

        
        memcpy(lfi, &fi, sizeof(fi));
        if (savename) {
            lfi->name = savename;
            lfi->valid |= APR_FINFO_NAME;
        }

        return OK;
    }

    
    if (!(lfi->valid & APR_FINFO_OWNER)) {
        if (apr_stat(lfi, d, lfi->valid | APR_FINFO_LINK | APR_FINFO_OWNER, p)
            != APR_SUCCESS)
        {
            return HTTP_FORBIDDEN;
        }
    }

    if (apr_stat(&fi, d, lfi->valid & ~(APR_FINFO_NAME), p) != APR_SUCCESS) {
        return HTTP_FORBIDDEN;
    }

    if (apr_uid_compare(fi.user, lfi->user) != APR_SUCCESS) {
        return HTTP_FORBIDDEN;
    }

    
    memcpy(lfi, &fi, sizeof(fi));
    if (savename) {
        lfi->name = savename;
        lfi->valid |= APR_FINFO_NAME;
    }

    return OK;
}




typedef struct core_opts_t {
        allow_options_t opts;
        allow_options_t add;
        allow_options_t remove;
        overrides_t override;
        overrides_t override_opts;
        apr_table_t *override_list;
} core_opts_t;

static void core_opts_merge(const ap_conf_vector_t *sec, core_opts_t *opts)
{
    core_dir_config *this_dir = ap_get_core_module_config(sec);

    if (!this_dir) {
        return;
    }

    if (this_dir->opts & OPT_UNSET) {
        opts->add = (opts->add & ~this_dir->opts_remove)
                   | this_dir->opts_add;
        opts->remove = (opts->remove & ~this_dir->opts_add)
                      | this_dir->opts_remove;
        opts->opts = (opts->opts & ~opts->remove) | opts->add;
    }
    else {
        opts->opts = this_dir->opts;
        opts->add = this_dir->opts_add;
        opts->remove = this_dir->opts_remove;
    }

    if (!(this_dir->override & OR_UNSET)) {
        opts->override = this_dir->override;
        opts->override_opts = this_dir->override_opts;
    }

   if (this_dir->override_list != NULL) {
        opts->override_list = this_dir->override_list;
   }

}




AP_DECLARE(int) ap_directory_walk(request_rec *r)
{
    ap_conf_vector_t *now_merged = NULL;
    core_server_config *sconf = ap_get_core_module_config(r->server->module_config);
    ap_conf_vector_t **sec_ent = (ap_conf_vector_t **) sconf->sec_dir->elts;
    int num_sec = sconf->sec_dir->nelts;
    walk_cache_t *cache;
    char *entry_dir;
    apr_status_t rv;
    int cached;

    
    if (r->filename == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00029)
                      "Module bug?  Request filename is missing for URI %s", r->uri);
       return OK;
    }

    
    if ((rv = apr_filepath_merge(&entry_dir, NULL, r->filename, APR_FILEPATH_NOTRELATIVE, r->pool))
                  != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(00030)
                      "Module bug?  Request filename path %s is invalid or " "or not absolute for uri %s", r->filename, r->uri);

        return OK;
    }

    
    r->filename = entry_dir;

    cache = prep_walk_cache(AP_NOTE_DIRECTORY_WALK, r);
    cached = (cache->cached != NULL);

    
    if (r->finfo.filetype == APR_NOFILE || r->finfo.filetype == APR_LNK) {
        rv = ap_run_dirwalk_stat(&r->finfo, r, APR_FINFO_MIN);

        
        if ((rv != APR_SUCCESS) || (r->finfo.filetype != APR_NOFILE && (r->finfo.filetype != APR_DIR) && (r->filename[strlen(r->filename) - 1] == '/'))) {


             r->finfo.filetype = APR_NOFILE; 
        }
    }

    if (r->finfo.filetype == APR_REG) {
        entry_dir = ap_make_dirstr_parent(r->pool, entry_dir);
    }
    else if (r->filename[strlen(r->filename) - 1] != '/') {
        entry_dir = apr_pstrcat(r->pool, r->filename, "/", NULL);
    }

    
    if (cached && ((r->finfo.filetype == APR_REG)
            || ((r->finfo.filetype == APR_DIR)
                && (!r->path_info || !*r->path_info)))
        && (cache->dir_conf_tested == sec_ent)
        && (strcmp(entry_dir, cache->cached) == 0)) {
        int familiar = 0;

        
        if (r->per_dir_config == cache->per_dir_result) {
            familiar = 1;
        }

        if (r->per_dir_config == cache->dir_conf_merged) {
            r->per_dir_config = cache->per_dir_result;
            familiar = 1;
        }

        if (familiar) {
            apr_finfo_t thisinfo;
            int res;
            allow_options_t opts;
            core_dir_config *this_dir;

            this_dir = ap_get_core_module_config(r->per_dir_config);
            opts = this_dir->opts;
            
            if (!(opts & OPT_SYM_LINKS)) {
                rv = ap_run_dirwalk_stat(&thisinfo, r, APR_FINFO_MIN | APR_FINFO_NAME | APR_FINFO_LINK);
                
                if ((rv != APR_INCOMPLETE) && (rv != APR_SUCCESS)) {
                    
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00031)
                                  "access to %s failed; stat of '%s' failed.", r->uri, r->filename);
                    return r->status = HTTP_FORBIDDEN;
                }
                if (thisinfo.filetype == APR_LNK) {
                    
                    if ((res = resolve_symlink(r->filename, &thisinfo, opts, r->pool)) != OK) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00032)
                                      "Symbolic link not allowed " "or link target not accessible: %s", r->filename);

                        return r->status = res;
                    }
                }
            }
            return OK;
        }

        if (cache->walked->nelts) {
            now_merged = ((walk_walked_t*)cache->walked->elts)
                [cache->walked->nelts - 1].merged;
        }
    }
    else {
        
        int sec_idx;
        int matches = cache->walked->nelts;
        int cached_matches = matches;
        walk_walked_t *last_walk = (walk_walked_t*)cache->walked->elts;
        core_dir_config *this_dir;
        core_opts_t opts;
        apr_finfo_t thisinfo;
        char *save_path_info;
        apr_size_t buflen;
        char *buf;
        unsigned int seg, startseg;
        apr_pool_t *rxpool = NULL;

        
        apr_size_t filename_len;

        apr_size_t canonical_len;


        cached &= auth_internal_per_conf;

        
        this_dir = ap_get_core_module_config(r->per_dir_config);
        opts.opts = this_dir->opts;
        opts.add = this_dir->opts_add;
        opts.remove = this_dir->opts_remove;
        opts.override = this_dir->override;
        opts.override_opts = this_dir->override_opts;
        opts.override_list = this_dir->override_list;

        
        if ((r->finfo.filetype == APR_DIR) && r->path_info && *r->path_info)
        {
            if ((rv = apr_filepath_merge(&r->path_info, r->filename, r->path_info, APR_FILEPATH_NOTABOVEROOT, r->pool))

                != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00033)
                              "dir_walk error, path_info %s is not relative " "to the filename path %s for uri %s", r->path_info, r->filename, r->uri);

                return HTTP_INTERNAL_SERVER_ERROR;
            }

            save_path_info = NULL;
        }
        else {
            save_path_info = r->path_info;
            r->path_info = r->filename;
        }



        canonical_len = 0;
        while (r->canonical_filename && r->canonical_filename[canonical_len] && (r->canonical_filename[canonical_len] == r->path_info[canonical_len])) {

             ++canonical_len;
        }

        while (canonical_len && ((r->canonical_filename[canonical_len - 1] != '/' && r->canonical_filename[canonical_len - 1])

                   || (r->path_info[canonical_len - 1] != '/' && r->path_info[canonical_len - 1]))) {
            --canonical_len;
        }

        
        rv = apr_filepath_root((const char **)&r->filename, (const char **)&r->path_info, canonical_len ? 0 : APR_FILEPATH_TRUENAME, r->pool);


        filename_len = strlen(r->filename);

        
        if ((rv == APR_SUCCESS) && canonical_len && (filename_len > canonical_len)) {
            rv = apr_filepath_root((const char **)&r->filename, (const char **)&r->path_info, APR_FILEPATH_TRUENAME, r->pool);

            filename_len = strlen(r->filename);
            canonical_len = 0;
        }



        rv = apr_filepath_root((const char **)&r->filename, (const char **)&r->path_info, 0, r->pool);

        filename_len = strlen(r->filename);



        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00034)
                          "dir_walk error, could not determine the root " "path of filename %s%s for uri %s", r->filename, r->path_info, r->uri);

            return HTTP_INTERNAL_SERVER_ERROR;
        }

        
        buflen = filename_len + strlen(r->path_info) + 2;
        buf = apr_palloc(r->pool, buflen);
        memcpy(buf, r->filename, filename_len + 1);
        r->filename = buf;
        thisinfo.valid = APR_FINFO_TYPE;
        thisinfo.filetype = APR_DIR; 

        
        startseg = seg = ap_count_dirs(r->filename);
        sec_idx = 0;

        
        do {
            int res;
            char *seg_name;
            char *delim;
            int temp_slash=0;

            
            if ((seg > startseg) && r->filename[filename_len-1] != '/') {
                r->filename[filename_len++] = '/';
                r->filename[filename_len] = 0;
                temp_slash=1;
            }

            
            for (; sec_idx < num_sec; ++sec_idx) {

                ap_conf_vector_t *entry_config = sec_ent[sec_idx];
                core_dir_config *entry_core;
                entry_core = ap_get_core_module_config(entry_config);

                
                if (entry_core->r || entry_core->d_components > seg) {
                    break;
                }

                
                if (entry_core->d_components && ((entry_core->d_components < seg)
                     || (entry_core->d_is_fnmatch ? (apr_fnmatch(entry_core->d, r->filename, APR_FNM_PATHNAME) != APR_SUCCESS)

                         : (strcmp(r->filename, entry_core->d) != 0)))) {
                    continue;
                }

                
                core_opts_merge(sec_ent[sec_idx], &opts);

                
                if (matches) {
                    if (last_walk->matched == sec_ent[sec_idx]) {
                        now_merged = last_walk->merged;
                        ++last_walk;
                        --matches;
                        continue;
                    }

                    
                    cache->walked->nelts -= matches;
                    matches = 0;
                    cached = 0;
                }

                if (now_merged) {
                    now_merged = ap_merge_per_dir_configs(r->pool, now_merged, sec_ent[sec_idx]);

                }
                else {
                    now_merged = sec_ent[sec_idx];
                }

                last_walk = (walk_walked_t*)apr_array_push(cache->walked);
                last_walk->matched = sec_ent[sec_idx];
                last_walk->merged = now_merged;
            }

            
            do {  

                ap_conf_vector_t *htaccess_conf = NULL;

                
                if (seg < startseg || (!opts.override && opts.override_list == NULL)) {
                    break;
                }


                res = ap_parse_htaccess(&htaccess_conf, r, opts.override, opts.override_opts, opts.override_list, apr_pstrdup(r->pool, r->filename), sconf->access_name);


                if (res) {
                    return res;
                }

                if (!htaccess_conf) {
                    break;
                }

                
                core_opts_merge(htaccess_conf, &opts);

                
                if (matches) {
                    if (last_walk->matched == htaccess_conf) {
                        now_merged = last_walk->merged;
                        ++last_walk;
                        --matches;
                        break;
                    }

                    
                    cache->walked->nelts -= matches;
                    matches = 0;
                    cached = 0;
                }

                if (now_merged) {
                    now_merged = ap_merge_per_dir_configs(r->pool, now_merged, htaccess_conf);

                }
                else {
                    now_merged = htaccess_conf;
                }

                last_walk = (walk_walked_t*)apr_array_push(cache->walked);
                last_walk->matched = htaccess_conf;
                last_walk->merged = now_merged;

            } while (0); 

            
            if (temp_slash) {
                r->filename[--filename_len] = '\0';
            }

            
            if (!r->path_info || !*r->path_info) {
                break;
            }

            

            seg_name = r->filename + filename_len;
            delim = strchr(r->path_info + (*r->path_info == '/' ? 1 : 0), '/');
            if (delim) {
                apr_size_t path_info_len = delim - r->path_info;
                *delim = '\0';
                memcpy(seg_name, r->path_info, path_info_len + 1);
                filename_len += path_info_len;
                r->path_info = delim;
                *delim = '/';
            }
            else {
                apr_size_t path_info_len = strlen(r->path_info);
                memcpy(seg_name, r->path_info, path_info_len + 1);
                filename_len += path_info_len;
                r->path_info += path_info_len;
            }
            if (*seg_name == '/')
                ++seg_name;

            
            if (!*seg_name) {
                break;
            }

            
            if (r->finfo.filetype != APR_NOFILE  && (filename_len <= canonical_len)


                && ((opts.opts & (OPT_SYM_OWNER | OPT_SYM_LINKS)) == OPT_SYM_LINKS))
            {

                thisinfo.filetype = APR_DIR;
                ++seg;
                continue;
            }

            
            rv = ap_run_dirwalk_stat(&thisinfo, r, APR_FINFO_MIN | APR_FINFO_NAME | APR_FINFO_LINK);

            if (APR_STATUS_IS_ENOENT(rv)) {
                
                thisinfo.filetype = APR_NOFILE;
                break;
            }
            else if (APR_STATUS_IS_EACCES(rv)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00035)
                              "access to %s denied (filesystem path '%s') " "because search permissions are missing on a " "component of the path", r->uri, r->filename);

                return r->status = HTTP_FORBIDDEN;
            }
            else if ((rv != APR_SUCCESS && rv != APR_INCOMPLETE)
                     || !(thisinfo.valid & APR_FINFO_TYPE)) {
                
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(00036)
                              "access to %s failed (filesystem path '%s')",  r->uri, r->filename);
                return r->status = HTTP_FORBIDDEN;
            }

            
            if ((thisinfo.valid & APR_FINFO_NAME)
                && strcmp(seg_name, thisinfo.name)) {
                
                strcpy(seg_name, thisinfo.name);
                filename_len = strlen(r->filename);
            }

            if (thisinfo.filetype == APR_LNK) {
                
                if ((res = resolve_symlink(r->filename, &thisinfo, opts.opts, r->pool)) != OK) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00037)
                                  "Symbolic link not allowed " "or link target not accessible: %s", r->filename);

                    return r->status = res;
                }
            }

            
            if (thisinfo.filetype == APR_REG || thisinfo.filetype == APR_NOFILE) {
                
                break;
            }
            else if (thisinfo.filetype != APR_DIR) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00038)
                              "Forbidden: %s doesn't point to " "a file or directory", r->filename);

                return r->status = HTTP_FORBIDDEN;
            }

            ++seg;
        } while (thisinfo.filetype == APR_DIR);

        
        if (r->finfo.filetype == APR_NOFILE || r->finfo.filetype == APR_LNK) {
            r->finfo = thisinfo;
        }

        
        if (save_path_info) {
            if (r->path_info && *r->path_info) {
                r->path_info = ap_make_full_path(r->pool, r->path_info, save_path_info);
            }
            else {
                r->path_info = save_path_info;
            }
        }

        
        for (; sec_idx < num_sec; ++sec_idx) {

            int nmatch = 0;
            int i;
            ap_regmatch_t *pmatch = NULL;

            core_dir_config *entry_core;
            entry_core = ap_get_core_module_config(sec_ent[sec_idx]);

            if (!entry_core->r) {
                continue;
            }

            if (entry_core->refs && entry_core->refs->nelts) {
                if (!rxpool) {
                    apr_pool_create(&rxpool, r->pool);
                }
                nmatch = entry_core->refs->nelts;
                pmatch = apr_palloc(rxpool, nmatch*sizeof(ap_regmatch_t));
            }

            if (ap_regexec(entry_core->r, r->filename, nmatch, pmatch, 0)) {
                continue;
            }

            for (i = 0; i < nmatch; i++) {
                if (pmatch[i].rm_so >= 0 && pmatch[i].rm_eo >= 0 && ((const char **)entry_core->refs->elts)[i]) {
                    apr_table_setn(r->subprocess_env,  ((const char **)entry_core->refs->elts)[i], apr_pstrndup(r->pool, r->filename + pmatch[i].rm_so, pmatch[i].rm_eo - pmatch[i].rm_so));



                }
            }

            
            core_opts_merge(sec_ent[sec_idx], &opts);

            
            if (matches) {
                if (last_walk->matched == sec_ent[sec_idx]) {
                    now_merged = last_walk->merged;
                    ++last_walk;
                    --matches;
                    continue;
                }

                
                cache->walked->nelts -= matches;
                matches = 0;
                cached = 0;
            }

            if (now_merged) {
                now_merged = ap_merge_per_dir_configs(r->pool, now_merged, sec_ent[sec_idx]);

            }
            else {
                now_merged = sec_ent[sec_idx];
            }

            last_walk = (walk_walked_t*)apr_array_push(cache->walked);
            last_walk->matched = sec_ent[sec_idx];
            last_walk->merged = now_merged;
        }

        if (rxpool) {
            apr_pool_destroy(rxpool);
        }

        
        if (matches) {
            cache->walked->nelts -= matches;
            cached = 0;
        }
        else if (cache->walked->nelts > cached_matches) {
            cached = 0;
        }
    }



    
    r->canonical_filename = r->filename;

    if (r->finfo.filetype == APR_DIR) {
        cache->cached = r->filename;
    }
    else {
        cache->cached = ap_make_dirstr_parent(r->pool, r->filename);
    }

    if (cached && r->per_dir_config == cache->dir_conf_merged) {
        r->per_dir_config = cache->per_dir_result;
        return OK;
    }

    cache->dir_conf_tested = sec_ent;
    cache->dir_conf_merged = r->per_dir_config;

    
    if (now_merged) {
        r->per_dir_config = ap_merge_per_dir_configs(r->pool, r->per_dir_config, now_merged);

    }
    cache->per_dir_result = r->per_dir_config;

    return OK;
}


AP_DECLARE(int) ap_location_walk(request_rec *r)
{
    ap_conf_vector_t *now_merged = NULL;
    core_server_config *sconf = ap_get_core_module_config(r->server->module_config);
    ap_conf_vector_t **sec_ent = (ap_conf_vector_t **)sconf->sec_url->elts;
    int num_sec = sconf->sec_url->nelts;
    walk_cache_t *cache;
    const char *entry_uri;
    int cached;

    
    if (!num_sec) {
        return OK;
    }

    cache = prep_walk_cache(AP_NOTE_LOCATION_WALK, r);
    cached = (cache->cached != NULL);

    
    if (r->uri[0] != '/') {
        entry_uri = r->uri;
    }
    else {
        char *uri = apr_pstrdup(r->pool, r->uri);
        ap_no2slash(uri);
        entry_uri = uri;
    }

    
    if (cached && (cache->dir_conf_tested == sec_ent)
        && (strcmp(entry_uri, cache->cached) == 0)) {
        
        if (r->per_dir_config == cache->per_dir_result) {
            return OK;
        }

        if (cache->walked->nelts) {
            now_merged = ((walk_walked_t*)cache->walked->elts)
                                            [cache->walked->nelts - 1].merged;
        }
    }
    else {
        
        int len, sec_idx;
        int matches = cache->walked->nelts;
        int cached_matches = matches;
        walk_walked_t *last_walk = (walk_walked_t*)cache->walked->elts;
        apr_pool_t *rxpool = NULL;

        cached &= auth_internal_per_conf;
        cache->cached = entry_uri;

        
        for (sec_idx = 0; sec_idx < num_sec; ++sec_idx) {

            core_dir_config *entry_core;
            entry_core = ap_get_core_module_config(sec_ent[sec_idx]);

            
            len = strlen(entry_core->d);

            
            if (entry_core->r) {

                int nmatch = 0;
                int i;
                ap_regmatch_t *pmatch = NULL;

                if (entry_core->refs && entry_core->refs->nelts) {
                    if (!rxpool) {
                        apr_pool_create(&rxpool, r->pool);
                    }
                    nmatch = entry_core->refs->nelts;
                    pmatch = apr_palloc(rxpool, nmatch*sizeof(ap_regmatch_t));
                }

                if (ap_regexec(entry_core->r, r->uri, nmatch, pmatch, 0)) {
                    continue;
                }

                for (i = 0; i < nmatch; i++) {
                    if (pmatch[i].rm_so >= 0 && pmatch[i].rm_eo >= 0 &&  ((const char **)entry_core->refs->elts)[i]) {
                        apr_table_setn(r->subprocess_env, ((const char **)entry_core->refs->elts)[i], apr_pstrndup(r->pool, r->uri + pmatch[i].rm_so, pmatch[i].rm_eo - pmatch[i].rm_so));



                    }
                }

            }
            else {

                if ((entry_core->d_is_fnmatch ? apr_fnmatch(entry_core->d, cache->cached, APR_FNM_PATHNAME)
                   : (strncmp(entry_core->d, cache->cached, len)
                      || (len > 0 && entry_core->d[len - 1] != '/' && cache->cached[len] != '/' && cache->cached[len] != '\0')))) {


                    continue;
                }

            }

            
            if (matches) {
                if (last_walk->matched == sec_ent[sec_idx]) {
                    now_merged = last_walk->merged;
                    ++last_walk;
                    --matches;
                    continue;
                }

                
                cache->walked->nelts -= matches;
                matches = 0;
                cached = 0;
            }

            if (now_merged) {
                now_merged = ap_merge_per_dir_configs(r->pool, now_merged, sec_ent[sec_idx]);

            }
            else {
                now_merged = sec_ent[sec_idx];
            }

            last_walk = (walk_walked_t*)apr_array_push(cache->walked);
            last_walk->matched = sec_ent[sec_idx];
            last_walk->merged = now_merged;
        }

        if (rxpool) {
            apr_pool_destroy(rxpool);
        }

        
        if (matches) {
            cache->walked->nelts -= matches;
            cached = 0;
        }
        else if (cache->walked->nelts > cached_matches) {
            cached = 0;
        }
    }

    if (cached && r->per_dir_config == cache->dir_conf_merged) {
        r->per_dir_config = cache->per_dir_result;
        return OK;
    }

    cache->dir_conf_tested = sec_ent;
    cache->dir_conf_merged = r->per_dir_config;

    
    if (now_merged) {
        r->per_dir_config = ap_merge_per_dir_configs(r->pool, r->per_dir_config, now_merged);

    }
    cache->per_dir_result = r->per_dir_config;

    return OK;
}

AP_DECLARE(int) ap_file_walk(request_rec *r)
{
    ap_conf_vector_t *now_merged = NULL;
    core_dir_config *dconf = ap_get_core_module_config(r->per_dir_config);
    ap_conf_vector_t **sec_ent = NULL;
    int num_sec = 0;
    walk_cache_t *cache;
    const char *test_file;
    int cached;

    if (dconf->sec_file) {
        sec_ent = (ap_conf_vector_t **)dconf->sec_file->elts;
        num_sec = dconf->sec_file->nelts;
    }

    
    if (r->filename == NULL) {
        return OK;
    }

    cache = prep_walk_cache(AP_NOTE_FILE_WALK, r);
    cached = (cache->cached != NULL);

    
    if (!num_sec) {
        return OK;
    }

    
    test_file = strrchr(r->filename, '/');
    if (test_file == NULL) {
        test_file = apr_pstrdup(r->pool, r->filename);
    }
    else {
        test_file = apr_pstrdup(r->pool, ++test_file);
    }

    
    if (cached && (cache->dir_conf_tested == sec_ent)
        && (strcmp(test_file, cache->cached) == 0)) {
        
        if (r->per_dir_config == cache->per_dir_result) {
            return OK;
        }

        if (cache->walked->nelts) {
            now_merged = ((walk_walked_t*)cache->walked->elts)
                [cache->walked->nelts - 1].merged;
        }
    }
    else {
        
        int sec_idx;
        int matches = cache->walked->nelts;
        int cached_matches = matches;
        walk_walked_t *last_walk = (walk_walked_t*)cache->walked->elts;
        apr_pool_t *rxpool = NULL;

        cached &= auth_internal_per_conf;
        cache->cached = test_file;

        
        for (sec_idx = 0; sec_idx < num_sec; ++sec_idx) {
            core_dir_config *entry_core;
            entry_core = ap_get_core_module_config(sec_ent[sec_idx]);

            if (entry_core->r) {

                int nmatch = 0;
                int i;
                ap_regmatch_t *pmatch = NULL;

                if (entry_core->refs && entry_core->refs->nelts) {
                    if (!rxpool) {
                        apr_pool_create(&rxpool, r->pool);
                    }
                    nmatch = entry_core->refs->nelts;
                    pmatch = apr_palloc(rxpool, nmatch*sizeof(ap_regmatch_t));
                }

                if (ap_regexec(entry_core->r, cache->cached, nmatch, pmatch, 0)) {
                    continue;
                }

                for (i = 0; i < nmatch; i++) {
                    if (pmatch[i].rm_so >= 0 && pmatch[i].rm_eo >= 0 &&  ((const char **)entry_core->refs->elts)[i]) {
                        apr_table_setn(r->subprocess_env, ((const char **)entry_core->refs->elts)[i], apr_pstrndup(r->pool, cache->cached + pmatch[i].rm_so, pmatch[i].rm_eo - pmatch[i].rm_so));



                    }
                }

            }
            else {
                if ((entry_core->d_is_fnmatch ? apr_fnmatch(entry_core->d, cache->cached, APR_FNM_PATHNAME)
                       : strcmp(entry_core->d, cache->cached))) {
                    continue;
                }
            }

            
            if (matches) {
                if (last_walk->matched == sec_ent[sec_idx]) {
                    now_merged = last_walk->merged;
                    ++last_walk;
                    --matches;
                    continue;
                }

                
                cache->walked->nelts -= matches;
                matches = 0;
                cached = 0;
            }

            if (now_merged) {
                now_merged = ap_merge_per_dir_configs(r->pool, now_merged, sec_ent[sec_idx]);

            }
            else {
                now_merged = sec_ent[sec_idx];
            }

            last_walk = (walk_walked_t*)apr_array_push(cache->walked);
            last_walk->matched = sec_ent[sec_idx];
            last_walk->merged = now_merged;
        }

        if (rxpool) {
            apr_pool_destroy(rxpool);
        }

        
        if (matches) {
            cache->walked->nelts -= matches;
            cached = 0;
        }
        else if (cache->walked->nelts > cached_matches) {
            cached = 0;
        }
    }

    if (cached && r->per_dir_config == cache->dir_conf_merged) {
        r->per_dir_config = cache->per_dir_result;
        return OK;
    }

    cache->dir_conf_tested = sec_ent;
    cache->dir_conf_merged = r->per_dir_config;

    
    if (now_merged) {
        r->per_dir_config = ap_merge_per_dir_configs(r->pool, r->per_dir_config, now_merged);

    }
    cache->per_dir_result = r->per_dir_config;

    return OK;
}

AP_DECLARE(int) ap_if_walk(request_rec *r)
{
    ap_conf_vector_t *now_merged = NULL;
    core_dir_config *dconf = ap_get_core_module_config(r->per_dir_config);
    ap_conf_vector_t **sec_ent = NULL;
    int num_sec = 0;
    walk_cache_t *cache;
    int cached;
    int sec_idx;
    int matches;
    int cached_matches;
    int prev_result = -1;
    walk_walked_t *last_walk;

    if (dconf->sec_if) {
        sec_ent = (ap_conf_vector_t **)dconf->sec_if->elts;
        num_sec = dconf->sec_if->nelts;
    }

    
    if (!num_sec) {
        return OK;
    }

    cache = prep_walk_cache(AP_NOTE_IF_WALK, r);
    cached = (cache->cached != NULL);
    cache->cached = (void *)1;
    matches = cache->walked->nelts;
    cached_matches = matches;
    last_walk = (walk_walked_t*)cache->walked->elts;

    cached &= auth_internal_per_conf;

    
    for (sec_idx = 0; sec_idx < num_sec; ++sec_idx) {
        const char *err = NULL;
        core_dir_config *entry_core;
        int rc;
        entry_core = ap_get_core_module_config(sec_ent[sec_idx]);

        AP_DEBUG_ASSERT(entry_core->condition_ifelse != 0);
        if (entry_core->condition_ifelse & AP_CONDITION_ELSE) {
            AP_DEBUG_ASSERT(prev_result != -1);
            if (prev_result == 1)
                continue;
        }

        if (entry_core->condition_ifelse & AP_CONDITION_IF) {
            rc = ap_expr_exec(r, entry_core->condition, &err);
            if (rc <= 0) {
                if (rc < 0)
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(00039)
                                  "Failed to evaluate <If > condition: %s", err);
                prev_result = 0;
                continue;
            }
            prev_result = 1;
        }
        else {
            prev_result = -1;
        }

        
        if (matches) {
            if (last_walk->matched == sec_ent[sec_idx]) {
                now_merged = last_walk->merged;
                ++last_walk;
                --matches;
                continue;
            }

            
            cache->walked->nelts -= matches;
            matches = 0;
            cached = 0;
        }

        if (now_merged) {
            now_merged = ap_merge_per_dir_configs(r->pool, now_merged, sec_ent[sec_idx]);

        }
        else {
            now_merged = sec_ent[sec_idx];
        }

        last_walk = (walk_walked_t*)apr_array_push(cache->walked);
        last_walk->matched = sec_ent[sec_idx];
        last_walk->merged = now_merged;
    }

    
    if (matches) {
        cache->walked->nelts -= matches;
        cached = 0;
    }
    else if (cache->walked->nelts > cached_matches) {
        cached = 0;
    }

    if (cached && r->per_dir_config == cache->dir_conf_merged) {
        r->per_dir_config = cache->per_dir_result;
        return OK;
    }

    cache->dir_conf_tested = sec_ent;
    cache->dir_conf_merged = r->per_dir_config;

    
    if (now_merged) {
        r->per_dir_config = ap_merge_per_dir_configs(r->pool, r->per_dir_config, now_merged);

    }
    cache->per_dir_result = r->per_dir_config;

    return OK;
}



static request_rec *make_sub_request(const request_rec *r, ap_filter_t *next_filter)
{
    apr_pool_t *rrp;
    request_rec *rnew;

    apr_pool_create(&rrp, r->pool);
    apr_pool_tag(rrp, "subrequest");
    rnew = apr_pcalloc(rrp, sizeof(request_rec));
    rnew->pool = rrp;

    rnew->hostname       = r->hostname;
    rnew->request_time   = r->request_time;
    rnew->connection     = r->connection;
    rnew->server         = r->server;
    rnew->log            = r->log;

    rnew->request_config = ap_create_request_config(rnew->pool);

    
    rnew->per_dir_config = r->server->lookup_defaults;

    rnew->htaccess = r->htaccess;
    rnew->allowed_methods = ap_make_method_list(rnew->pool, 2);

    
    ap_copy_method_list(rnew->allowed_methods, r->allowed_methods);

    
    if (next_filter) {
        
        rnew->input_filters = r->input_filters;
        rnew->proto_input_filters = r->proto_input_filters;
        rnew->output_filters = next_filter;
        rnew->proto_output_filters = r->proto_output_filters;
        ap_add_output_filter_handle(ap_subreq_core_filter_handle, NULL, rnew, rnew->connection);
    }
    else {
        
        rnew->proto_input_filters = r->proto_input_filters;
        rnew->proto_output_filters = r->proto_output_filters;

        rnew->input_filters = r->proto_input_filters;
        rnew->output_filters = r->proto_output_filters;
    }

    rnew->useragent_addr = r->useragent_addr;
    rnew->useragent_ip = r->useragent_ip;

    

    ap_set_sub_req_protocol(rnew, r);

    
    ap_run_create_request(rnew);

    
    rnew->used_path_info = AP_REQ_DEFAULT_PATH_INFO;

    
    rnew->kept_body = r->kept_body;

    return rnew;
}

AP_CORE_DECLARE_NONSTD(apr_status_t) ap_sub_req_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *e = APR_BRIGADE_LAST(bb);

    if (APR_BUCKET_IS_EOS(e)) {
        apr_bucket_delete(e);
    }

    if (!APR_BRIGADE_EMPTY(bb)) {
        return ap_pass_brigade(f->next, bb);
    }

    return APR_SUCCESS;
}

extern APR_OPTIONAL_FN_TYPE(authz_some_auth_required) *ap__authz_ap_some_auth_required;

AP_DECLARE(int) ap_some_auth_required(request_rec *r)
{
    
    if (ap__authz_ap_some_auth_required) {
        return ap__authz_ap_some_auth_required(r);
    }
    else return 0;
}

AP_DECLARE(void) ap_clear_auth_internal(void)
{
    auth_internal_per_conf_hooks = 0;
    auth_internal_per_conf_providers = 0;
}

AP_DECLARE(void) ap_setup_auth_internal(apr_pool_t *ptemp)
{
    int total_auth_hooks = 0;
    int total_auth_providers = 0;

    auth_internal_per_conf = 0;

    if (_hooks.link_access_checker) {
        total_auth_hooks += _hooks.link_access_checker->nelts;
    }
    if (_hooks.link_access_checker_ex) {
        total_auth_hooks += _hooks.link_access_checker_ex->nelts;
    }
    if (_hooks.link_check_user_id) {
        total_auth_hooks += _hooks.link_check_user_id->nelts;
    }
    if (_hooks.link_auth_checker) {
        total_auth_hooks += _hooks.link_auth_checker->nelts;
    }

    if (total_auth_hooks > auth_internal_per_conf_hooks) {
        return;
    }

    total_auth_providers += ap_list_provider_names(ptemp, AUTHN_PROVIDER_GROUP, AUTHN_PROVIDER_VERSION)->nelts;

    total_auth_providers += ap_list_provider_names(ptemp, AUTHZ_PROVIDER_GROUP, AUTHZ_PROVIDER_VERSION)->nelts;


    if (total_auth_providers > auth_internal_per_conf_providers) {
        return;
    }

    auth_internal_per_conf = 1;
}

AP_DECLARE(apr_status_t) ap_register_auth_provider(apr_pool_t *pool, const char *provider_group, const char *provider_name, const char *provider_version, const void *provider, int type)




{
    if ((type & AP_AUTH_INTERNAL_MASK) == AP_AUTH_INTERNAL_PER_CONF) {
        ++auth_internal_per_conf_providers;
    }

    return ap_register_provider(pool, provider_group, provider_name, provider_version, provider);
}

AP_DECLARE(void) ap_hook_check_access(ap_HOOK_access_checker_t *pf, const char * const *aszPre, const char * const *aszSucc, int nOrder, int type)


{
    if ((type & AP_AUTH_INTERNAL_MASK) == AP_AUTH_INTERNAL_PER_CONF) {
        ++auth_internal_per_conf_hooks;
    }

    ap_hook_access_checker(pf, aszPre, aszSucc, nOrder);
}

AP_DECLARE(void) ap_hook_check_access_ex(ap_HOOK_access_checker_ex_t *pf, const char * const *aszPre, const char * const *aszSucc, int nOrder, int type)


{
    if ((type & AP_AUTH_INTERNAL_MASK) == AP_AUTH_INTERNAL_PER_CONF) {
        ++auth_internal_per_conf_hooks;
    }

    ap_hook_access_checker_ex(pf, aszPre, aszSucc, nOrder);
}

AP_DECLARE(void) ap_hook_check_authn(ap_HOOK_check_user_id_t *pf, const char * const *aszPre, const char * const *aszSucc, int nOrder, int type)


{
    if ((type & AP_AUTH_INTERNAL_MASK) == AP_AUTH_INTERNAL_PER_CONF) {
        ++auth_internal_per_conf_hooks;
    }

    ap_hook_check_user_id(pf, aszPre, aszSucc, nOrder);
}

AP_DECLARE(void) ap_hook_check_authz(ap_HOOK_auth_checker_t *pf, const char * const *aszPre, const char * const *aszSucc, int nOrder, int type)


{
    if ((type & AP_AUTH_INTERNAL_MASK) == AP_AUTH_INTERNAL_PER_CONF) {
        ++auth_internal_per_conf_hooks;
    }

    ap_hook_auth_checker(pf, aszPre, aszSucc, nOrder);
}

AP_DECLARE(request_rec *) ap_sub_req_method_uri(const char *method, const char *new_uri, const request_rec *r, ap_filter_t *next_filter)


{
    request_rec *rnew;
    
    int res = HTTP_INTERNAL_SERVER_ERROR;
    char *udir;

    rnew = make_sub_request(r, next_filter);

    
    rnew->method = method;
    rnew->method_number = ap_method_number_of(method);

    if (new_uri[0] == '/') {
        ap_parse_uri(rnew, new_uri);
    }
    else {
        udir = ap_make_dirstr_parent(rnew->pool, r->uri);
        udir = ap_escape_uri(rnew->pool, udir);    
        ap_parse_uri(rnew, ap_make_full_path(rnew->pool, udir, new_uri));
    }

    
    if (ap_is_recursion_limit_exceeded(r)) {
        rnew->status = HTTP_INTERNAL_SERVER_ERROR;
        return rnew;
    }

    
    if (next_filter) {
        res = ap_run_quick_handler(rnew, 1);
    }

    if (next_filter == NULL || res != OK) {
        if ((res = ap_process_request_internal(rnew))) {
            rnew->status = res;
        }
    }

    return rnew;
}

AP_DECLARE(request_rec *) ap_sub_req_lookup_uri(const char *new_uri, const request_rec *r, ap_filter_t *next_filter)

{
    return ap_sub_req_method_uri("GET", new_uri, r, next_filter);
}

AP_DECLARE(request_rec *) ap_sub_req_lookup_dirent(const apr_finfo_t *dirent, const request_rec *r, int subtype, ap_filter_t *next_filter)


{
    request_rec *rnew;
    int res;
    char *fdir;
    char *udir;

    rnew = make_sub_request(r, next_filter);

    
    if (r->path_info && *r->path_info) {
        
        udir = apr_pstrdup(rnew->pool, r->uri);
        udir[ap_find_path_info(udir, r->path_info)] = '\0';
        udir = ap_make_dirstr_parent(rnew->pool, udir);

        rnew->uri = ap_make_full_path(rnew->pool, udir, dirent->name);
        if (subtype == AP_SUBREQ_MERGE_ARGS) {
            rnew->uri = ap_make_full_path(rnew->pool, rnew->uri, r->path_info + 1);
            rnew->path_info = apr_pstrdup(rnew->pool, r->path_info);
        }
        rnew->uri = ap_escape_uri(rnew->pool, rnew->uri);
    }
    else {
        udir = ap_make_dirstr_parent(rnew->pool, r->uri);
        rnew->uri = ap_escape_uri(rnew->pool, ap_make_full_path(rnew->pool, udir, dirent->name));

    }

    fdir = ap_make_dirstr_parent(rnew->pool, r->filename);
    rnew->filename = ap_make_full_path(rnew->pool, fdir, dirent->name);
    if (r->canonical_filename == r->filename) {
        rnew->canonical_filename = rnew->filename;
    }

    
    rnew->per_dir_config = r->server->lookup_defaults;

    if ((dirent->valid & APR_FINFO_MIN) != APR_FINFO_MIN) {
        
        apr_status_t rv;
        if (ap_allow_options(rnew) & OPT_SYM_LINKS) {
            if (((rv = apr_stat(&rnew->finfo, rnew->filename, APR_FINFO_MIN, rnew->pool)) != APR_SUCCESS)
                && (rv != APR_INCOMPLETE)) {
                rnew->finfo.filetype = APR_NOFILE;
            }
        }
        else {
            if (((rv = apr_stat(&rnew->finfo, rnew->filename, APR_FINFO_LINK | APR_FINFO_MIN, rnew->pool)) != APR_SUCCESS)

                && (rv != APR_INCOMPLETE)) {
                rnew->finfo.filetype = APR_NOFILE;
            }
        }
    }
    else {
        memcpy(&rnew->finfo, dirent, sizeof(apr_finfo_t));
    }

    if (rnew->finfo.filetype == APR_LNK) {
        
        if ((res = resolve_symlink(rnew->filename, &rnew->finfo, ap_allow_options(rnew), rnew->pool))
            != OK) {
            rnew->status = res;
            return rnew;
        }
    }

    if (rnew->finfo.filetype == APR_DIR) {
        
        strcat(rnew->filename, "/");
        if (!rnew->path_info || !*rnew->path_info) {
            strcat(rnew->uri, "/");
        }
    }

    
    if (r->args && *r->args && (subtype == AP_SUBREQ_MERGE_ARGS)) {
        ap_parse_uri(rnew, apr_pstrcat(r->pool, rnew->uri, "?", r->args, NULL));
    }
    else {
        ap_parse_uri(rnew, rnew->uri);
    }

    
    if (ap_is_recursion_limit_exceeded(r)) {
        rnew->status = HTTP_INTERNAL_SERVER_ERROR;
        return rnew;
    }

    if ((res = ap_process_request_internal(rnew))) {
        rnew->status = res;
    }

    return rnew;
}

AP_DECLARE(request_rec *) ap_sub_req_lookup_file(const char *new_file, const request_rec *r, ap_filter_t *next_filter)

{
    request_rec *rnew;
    int res;
    char *fdir;
    apr_size_t fdirlen;

    rnew = make_sub_request(r, next_filter);

    fdir = ap_make_dirstr_parent(rnew->pool, r->filename);
    fdirlen = strlen(fdir);

    
    if (r->canonical_filename == r->filename) {
        rnew->canonical_filename = (char*)(1);
    }

    if (apr_filepath_merge(&rnew->filename, fdir, new_file, APR_FILEPATH_TRUENAME, rnew->pool) != APR_SUCCESS) {
        rnew->status = HTTP_FORBIDDEN;
        return rnew;
    }

    if (rnew->canonical_filename) {
        rnew->canonical_filename = rnew->filename;
    }

    

    if (strncmp(rnew->filename, fdir, fdirlen) == 0 && rnew->filename[fdirlen] && ap_strchr_c(rnew->filename + fdirlen, '/') == NULL) {

        apr_status_t rv;
        if (ap_allow_options(rnew) & OPT_SYM_LINKS) {
            if (((rv = apr_stat(&rnew->finfo, rnew->filename, APR_FINFO_MIN, rnew->pool)) != APR_SUCCESS)
                && (rv != APR_INCOMPLETE)) {
                rnew->finfo.filetype = APR_NOFILE;
            }
        }
        else {
            if (((rv = apr_stat(&rnew->finfo, rnew->filename, APR_FINFO_LINK | APR_FINFO_MIN, rnew->pool)) != APR_SUCCESS)

                && (rv != APR_INCOMPLETE)) {
                rnew->finfo.filetype = APR_NOFILE;
            }
        }

        if (r->uri && *r->uri) {
            char *udir = ap_make_dirstr_parent(rnew->pool, r->uri);
            rnew->uri = ap_make_full_path(rnew->pool, udir, rnew->filename + fdirlen);
            ap_parse_uri(rnew, rnew->uri);    
        }
        else {
            ap_parse_uri(rnew, new_file);        
            rnew->uri = apr_pstrdup(rnew->pool, "");
        }
    }
    else {
        
        ap_parse_uri(rnew, new_file);        
        
        rnew->uri = apr_pstrdup(rnew->pool, "");
    }

    
    if (ap_is_recursion_limit_exceeded(r)) {
        rnew->status = HTTP_INTERNAL_SERVER_ERROR;
        return rnew;
    }

    if ((res = ap_process_request_internal(rnew))) {
        rnew->status = res;
    }

    return rnew;
}

AP_DECLARE(int) ap_run_sub_req(request_rec *r)
{
    int retval = DECLINED;
    
    if (!(r->filename && r->finfo.filetype != APR_NOFILE)) {
        retval = ap_run_quick_handler(r, 0);
    }
    if (retval != OK) {
        retval = ap_invoke_handler(r);
        if (retval == DONE) {
            retval = OK;
        }
    }
    ap_finalize_sub_req_protocol(r);
    return retval;
}

AP_DECLARE(void) ap_destroy_sub_req(request_rec *r)
{
    
    apr_pool_destroy(r->pool);
}


AP_DECLARE(void) ap_update_mtime(request_rec *r, apr_time_t dependency_mtime)
{
    if (r->mtime < dependency_mtime) {
        r->mtime = dependency_mtime;
    }
}


AP_DECLARE(int) ap_is_initial_req(request_rec *r)
{
    return (r->main == NULL)       
           && (r->prev == NULL);   
}

