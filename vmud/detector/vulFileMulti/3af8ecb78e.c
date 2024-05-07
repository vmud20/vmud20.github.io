

















DAV_DECLARE(dav_error*) dav_new_error(apr_pool_t *p, int status, int error_id, apr_status_t aprerr, const char *desc)
{
    dav_error *err = apr_pcalloc(p, sizeof(*err));

    

    err->status = status;
    err->error_id = error_id;
    err->desc = desc;
    err->aprerr = aprerr;

    return err;
}

DAV_DECLARE(dav_error*) dav_new_error_tag(apr_pool_t *p, int status, int error_id, apr_status_t aprerr, const char *desc, const char *namespace, const char *tagname)



{
    dav_error *err = dav_new_error(p, status, error_id, aprerr, desc);

    err->tagname = tagname;
    err->namespace = namespace;

    return err;
}


DAV_DECLARE(dav_error*) dav_push_error(apr_pool_t *p, int status, int error_id, const char *desc, dav_error *prev)

{
    dav_error *err = apr_pcalloc(p, sizeof(*err));

    err->status = status;
    err->error_id = error_id;
    err->desc = desc;
    err->prev = prev;

    return err;
}

DAV_DECLARE(void) dav_check_bufsize(apr_pool_t * p, dav_buffer *pbuf, apr_size_t extra_needed)
{
    
    if (pbuf->cur_len + extra_needed > pbuf->alloc_len) {
        char *newbuf;

        pbuf->alloc_len += extra_needed + DAV_BUFFER_PAD;
        newbuf = apr_palloc(p, pbuf->alloc_len);
        memcpy(newbuf, pbuf->buf, pbuf->cur_len);
        pbuf->buf = newbuf;
    }
}

DAV_DECLARE(void) dav_set_bufsize(apr_pool_t * p, dav_buffer *pbuf, apr_size_t size)
{
    

    

    
    if (size + DAV_BUFFER_PAD > pbuf->alloc_len) {
        
        pbuf->alloc_len = size + DAV_BUFFER_PAD;
        if (pbuf->alloc_len < DAV_BUFFER_MINSIZE)
            pbuf->alloc_len = DAV_BUFFER_MINSIZE;

        pbuf->buf = apr_palloc(p, pbuf->alloc_len);
    }
    pbuf->cur_len = size;
}



DAV_DECLARE(void) dav_buffer_init(apr_pool_t *p, dav_buffer *pbuf, const char *str)
{
    dav_set_bufsize(p, pbuf, strlen(str));
    memcpy(pbuf->buf, str, pbuf->cur_len + 1);
}


DAV_DECLARE(void) dav_buffer_append(apr_pool_t *p, dav_buffer *pbuf, const char *str)
{
    apr_size_t len = strlen(str);

    dav_check_bufsize(p, pbuf, len + 1);
    memcpy(pbuf->buf + pbuf->cur_len, str, len + 1);
    pbuf->cur_len += len;
}


DAV_DECLARE(void) dav_buffer_place(apr_pool_t *p, dav_buffer *pbuf, const char *str)
{
    apr_size_t len = strlen(str);

    dav_check_bufsize(p, pbuf, len + 1);
    memcpy(pbuf->buf + pbuf->cur_len, str, len + 1);
}


DAV_DECLARE(void) dav_buffer_place_mem(apr_pool_t *p, dav_buffer *pbuf, const void *mem, apr_size_t amt, apr_size_t pad)

{
    dav_check_bufsize(p, pbuf, amt + pad);
    memcpy(pbuf->buf + pbuf->cur_len, mem, amt);
}


DAV_DECLARE(dav_lookup_result) dav_lookup_uri(const char *uri, request_rec * r, int must_be_absolute)

{
    dav_lookup_result result = { 0 };
    const char *scheme;
    apr_port_t port;
    apr_uri_t comp;
    char *new_file;
    const char *domain;

    
    if (apr_uri_parse(r->pool, uri, &comp) != APR_SUCCESS) {
        result.err.status = HTTP_BAD_REQUEST;
        result.err.desc = "Invalid syntax in Destination URI.";
        return result;
    }

    
    if (comp.scheme == NULL && must_be_absolute) {
        result.err.status = HTTP_BAD_REQUEST;
        result.err.desc = "Destination URI must be an absolute URI.";
        return result;
    }

    
    if (comp.query != NULL || comp.fragment != NULL) {
        result.err.status = HTTP_BAD_REQUEST;
        result.err.desc = "Destination URI contains invalid components " "(a query or a fragment).";

        return result;
    }

    
    if (comp.scheme != NULL || comp.port != 0 || must_be_absolute)
    {
        
        scheme = r->parsed_uri.scheme;
        if (scheme == NULL)
            scheme = ap_http_scheme(r);

        
        if (comp.port == 0)
            comp.port = apr_uri_port_of_scheme(comp.scheme);

        
        port = r->connection->local_addr->port;
        if (strcasecmp(comp.scheme, scheme) != 0  || comp.port != port  ) {



            result.err.status = HTTP_BAD_GATEWAY;
            result.err.desc = apr_psprintf(r->pool, "Destination URI refers to " "different scheme or port " "(%s://hostname:%d)" APR_EOL_STR "(want: %s://hostname:%d)", comp.scheme ? comp.scheme : scheme, comp.port ? comp.port : port, scheme, port);






            return result;
        }
    }

    

    
    if (comp.hostname != NULL && strrchr(comp.hostname, '.') == NULL && (domain = strchr(r->server->server_hostname, '.')) != NULL) {

        comp.hostname = apr_pstrcat(r->pool, comp.hostname, domain, NULL);
    }

    

    if (comp.hostname != NULL && !ap_matches_request_vhost(r, comp.hostname, port)) {
        result.err.status = HTTP_BAD_GATEWAY;
        result.err.desc = "Destination URI refers to a different server.";
        return result;
    }


    

    
    new_file = apr_uri_unparse(r->pool, &comp, APR_URI_UNP_OMITSITEPART);

    
    result.rnew = ap_sub_req_method_uri(r->method, new_file, r, NULL);

    return result;
}




DAV_DECLARE(int) dav_validate_root(const apr_xml_doc *doc, const char *tagname)
{
    return doc->root && doc->root->ns == APR_XML_NS_DAV_ID && strcmp(doc->root->name, tagname) == 0;

}


DAV_DECLARE(apr_xml_elem *) dav_find_child(const apr_xml_elem *elem, const char *tagname)
{
    apr_xml_elem *child = elem->first_child;

    for (; child; child = child->next)
        if (child->ns == APR_XML_NS_DAV_ID && !strcmp(child->name, tagname))
            return child;
    return NULL;
}


DAV_DECLARE(const char *) dav_xml_get_cdata(const apr_xml_elem *elem, apr_pool_t *pool, int strip_white)
{
    apr_size_t len = 0;
    apr_text *scan;
    const apr_xml_elem *child;
    char *cdata;
    char *s;
    apr_size_t tlen;
    const char *found_text = NULL; 
    int found_count = 0;

    for (scan = elem->first_cdata.first; scan != NULL; scan = scan->next) {
        found_text = scan->text;
        ++found_count;
        len += strlen(found_text);
    }

    for (child = elem->first_child; child != NULL; child = child->next) {
        for (scan = child->following_cdata.first;
             scan != NULL;
             scan = scan->next) {
            found_text = scan->text;
            ++found_count;
            len += strlen(found_text);
        }
    }

    
    if (len == 0)
        return "";
    if (found_count == 1) {
        if (!strip_white || (!apr_isspace(*found_text)
                && !apr_isspace(found_text[len - 1])))
            return found_text;
    }

    cdata = s = apr_palloc(pool, len + 1);

    for (scan = elem->first_cdata.first; scan != NULL; scan = scan->next) {
        tlen = strlen(scan->text);
        memcpy(s, scan->text, tlen);
        s += tlen;
    }

    for (child = elem->first_child; child != NULL; child = child->next) {
        for (scan = child->following_cdata.first;
             scan != NULL;
             scan = scan->next) {
            tlen = strlen(scan->text);
            memcpy(s, scan->text, tlen);
            s += tlen;
        }
    }

    *s = '\0';

    if (strip_white) {
        
        while (apr_isspace(*cdata))     
            ++cdata;

        
        while (len-- > 0 && apr_isspace(cdata[len]))
            continue;
        cdata[len + 1] = '\0';
    }

    return cdata;
}

DAV_DECLARE(dav_xmlns_info *) dav_xmlns_create(apr_pool_t *pool)
{
    dav_xmlns_info *xi = apr_pcalloc(pool, sizeof(*xi));

    xi->pool = pool;
    xi->uri_prefix = apr_hash_make(pool);
    xi->prefix_uri = apr_hash_make(pool);

    return xi;
}

DAV_DECLARE(void) dav_xmlns_add(dav_xmlns_info *xi, const char *prefix, const char *uri)
{
    
    apr_hash_set(xi->prefix_uri, prefix, APR_HASH_KEY_STRING, uri);

    
    apr_hash_set(xi->uri_prefix, uri, APR_HASH_KEY_STRING, prefix);
}

DAV_DECLARE(const char *) dav_xmlns_add_uri(dav_xmlns_info *xi, const char *uri)
{
    const char *prefix;

    if ((prefix = apr_hash_get(xi->uri_prefix, uri, APR_HASH_KEY_STRING)) != NULL)
        return prefix;

    prefix = apr_psprintf(xi->pool, "g%d", xi->count++);
    dav_xmlns_add(xi, prefix, uri);
    return prefix;
}

DAV_DECLARE(const char *) dav_xmlns_get_uri(dav_xmlns_info *xi, const char *prefix)
{
    return apr_hash_get(xi->prefix_uri, prefix, APR_HASH_KEY_STRING);
}

DAV_DECLARE(const char *) dav_xmlns_get_prefix(dav_xmlns_info *xi, const char *uri)
{
    return apr_hash_get(xi->uri_prefix, uri, APR_HASH_KEY_STRING);
}

DAV_DECLARE(void) dav_xmlns_generate(dav_xmlns_info *xi, apr_text_header *phdr)
{
    apr_hash_index_t *hi = apr_hash_first(xi->pool, xi->prefix_uri);

    for (; hi != NULL; hi = apr_hash_next(hi)) {
        const void *prefix;
        void *uri;
        const char *s;

        apr_hash_this(hi, &prefix, NULL, &uri);

        s = apr_psprintf(xi->pool, " xmlns:%s=\"%s\"", (const char *)prefix, (const char *)uri);
        apr_text_append(xi->pool, phdr, s);
    }
}




DAV_DECLARE(time_t) dav_get_timeout(request_rec *r)
{
    time_t now, expires = DAV_TIMEOUT_INFINITE;

    const char *timeout_const = apr_table_get(r->headers_in, "Timeout");
    const char *timeout = apr_pstrdup(r->pool, timeout_const), *val;

    if (timeout == NULL)
        return DAV_TIMEOUT_INFINITE;

    

    while ((val = ap_getword_white(r->pool, &timeout)) && strlen(val)) {
        if (!strncmp(val, "Infinite", 8)) {
            return DAV_TIMEOUT_INFINITE;
        }

        if (!strncmp(val, "Second-", 7)) {
            val += 7;
            
            expires = atol(val);
            now     = time(NULL);
            return now + expires;
        }
    }

    return DAV_TIMEOUT_INFINITE;
}




static dav_if_header *dav_add_if_resource(apr_pool_t *p, dav_if_header *next_ih, const char *uri, apr_size_t uri_len)
{
    dav_if_header *ih;

    if ((ih = apr_pcalloc(p, sizeof(*ih))) == NULL)
        return NULL;

    ih->uri = uri;
    ih->uri_len = uri_len;
    ih->next = next_ih;

    return ih;
}


static dav_error * dav_add_if_state(apr_pool_t *p, dav_if_header *ih, const char *state_token, dav_if_state_type t, int condition, const dav_hooks_locks *locks_hooks)


{
    dav_if_state_list *new_sl;

    new_sl = apr_pcalloc(p, sizeof(*new_sl));

    new_sl->condition = condition;
    new_sl->type      = t;

    if (t == dav_if_opaquelock) {
        dav_error *err;

        if ((err = (*locks_hooks->parse_locktoken)(p, state_token, &new_sl->locktoken)) != NULL) {
            
            if (err->error_id == DAV_ERR_LOCK_UNK_STATE_TOKEN) {
                new_sl->type = dav_if_unknown;
            }
            else {
                
                return err;
            }
        }
    }
    else new_sl->etag = state_token;

    new_sl->next = ih->state;
    ih->state = new_sl;

    return NULL;
}


static char *dav_fetch_next_token(char **str, char term)
{
    char *sp;
    char *token;

    token = *str + 1;

    while (*token && (*token == ' ' || *token == '\t'))
        token++;

    if ((sp = strchr(token, term)) == NULL)
        return NULL;

    *sp = '\0';
    *str = sp;
    return token;
}


static dav_error * dav_process_if_header(request_rec *r, dav_if_header **p_ih)
{
    dav_error *err;
    char *str;
    char *list;
    const char *state_token;
    const char *uri = NULL;        
    apr_size_t uri_len = 0;
    apr_status_t rv;
    dav_if_header *ih = NULL;
    apr_uri_t parsed_uri;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    enum {no_tagged, tagged, unknown} list_type = unknown;
    int condition;

    *p_ih = NULL;

    if ((str = apr_pstrdup(r->pool, apr_table_get(r->headers_in, "If"))) == NULL)
        return NULL;

    while (*str) {
        switch(*str) {
        case '<':
            
            if (list_type == no_tagged || ((uri = dav_fetch_next_token(&str, '>')) == NULL)) {
                return dav_new_error(r->pool, HTTP_BAD_REQUEST, DAV_ERR_IF_TAGGED, 0, "Invalid If-header: unclosed \"<\" or " "unexpected tagged-list production.");


            }

            
            if ((rv = apr_uri_parse(r->pool, uri, &parsed_uri)) != APR_SUCCESS) {
                return dav_new_error(r->pool, HTTP_BAD_REQUEST, DAV_ERR_IF_TAGGED, rv, "Invalid URI in tagged If-header.");

            }
            

            
            ap_getparents(parsed_uri.path);
            uri_len = strlen(parsed_uri.path);
            if (uri_len > 1 && parsed_uri.path[uri_len - 1] == '/')
                parsed_uri.path[--uri_len] = '\0';

            uri = parsed_uri.path;
            list_type = tagged;
            break;

        case '(':
            

            
            if (list_type == unknown)
                list_type = no_tagged;

            if ((list = dav_fetch_next_token(&str, ')')) == NULL) {
                return dav_new_error(r->pool, HTTP_BAD_REQUEST, DAV_ERR_IF_UNCLOSED_PAREN, 0, "Invalid If-header: unclosed \"(\".");

            }

            if ((ih = dav_add_if_resource(r->pool, ih, uri, uri_len)) == NULL) {
                
                return dav_new_error(r->pool, HTTP_BAD_REQUEST, DAV_ERR_IF_PARSE, 0, "Internal server error parsing \"If:\" " "header.");


            }

            condition = DAV_IF_COND_NORMAL;

            while (*list) {
                

                switch (*list) {
                case '<':
                    if ((state_token = dav_fetch_next_token(&list, '>')) == NULL) {
                        
                        return dav_new_error(r->pool, HTTP_BAD_REQUEST, DAV_ERR_IF_PARSE, 0, NULL);
                    }

                    if ((err = dav_add_if_state(r->pool, ih, state_token, dav_if_opaquelock, condition, locks_hooks)) != NULL) {
                        
                        return err;
                    }
                    condition = DAV_IF_COND_NORMAL;
                    break;

                case '[':
                    if ((state_token = dav_fetch_next_token(&list, ']')) == NULL) {
                        
                        return dav_new_error(r->pool, HTTP_BAD_REQUEST, DAV_ERR_IF_PARSE, 0, NULL);
                    }

                    if ((err = dav_add_if_state(r->pool, ih, state_token, dav_if_etag, condition, locks_hooks)) != NULL) {
                        
                        return err;
                    }
                    condition = DAV_IF_COND_NORMAL;
                    break;

                case 'N':
                    if (list[1] == 'o' && list[2] == 't') {
                        if (condition != DAV_IF_COND_NORMAL) {
                            return dav_new_error(r->pool, HTTP_BAD_REQUEST, DAV_ERR_IF_MULTIPLE_NOT, 0, "Invalid \"If:\" header: " "Multiple \"not\" entries " "for the same state.");



                        }
                        condition = DAV_IF_COND_NOT;
                    }
                    list += 2;
                    break;

                case ' ':
                case '\t':
                    break;

                default:
                    return dav_new_error(r->pool, HTTP_BAD_REQUEST, DAV_ERR_IF_UNK_CHAR, 0, apr_psprintf(r->pool, "Invalid \"If:\" " "header: Unexpected " "character encountered " "(0x%02x, '%c').", *list, *list));






                }

                list++;
            }
            break;

        case ' ':
        case '\t':
            break;

        default:
            return dav_new_error(r->pool, HTTP_BAD_REQUEST, DAV_ERR_IF_UNK_CHAR, 0, apr_psprintf(r->pool, "Invalid \"If:\" header: " "Unexpected character " "encountered (0x%02x, '%c').", *str, *str));





        }

        str++;
    }

    *p_ih = ih;
    return NULL;
}

static int dav_find_submitted_locktoken(const dav_if_header *if_header, const dav_lock *lock_list, const dav_hooks_locks *locks_hooks)

{
    for (; if_header != NULL; if_header = if_header->next) {
        const dav_if_state_list *state_list;

        for (state_list = if_header->state;
             state_list != NULL;
             state_list = state_list->next) {

            if (state_list->type == dav_if_opaquelock) {
                const dav_lock *lock;

                

                
                for (lock = lock_list; lock != NULL; lock = lock->next) {

                    if (!(*locks_hooks->compare_locktoken)(state_list->locktoken, lock->locktoken)) {
                        return 1;
                    }
                }
            }
        }
    }

    return 0;
}


static dav_error * dav_validate_resource_state(apr_pool_t *p, const dav_resource *resource, dav_lockdb *lockdb, const dav_if_header *if_header, int flags, dav_buffer *pbuf, request_rec *r)





{
    dav_error *err;
    const char *uri;
    const char *etag;
    const dav_hooks_locks *locks_hooks = (lockdb ? lockdb->hooks : NULL);
    const dav_if_header *ifhdr_scan;
    dav_if_state_list *state_list;
    dav_lock *lock_list;
    dav_lock *lock;
    int num_matched;
    int num_that_apply;
    int seen_locktoken;
    apr_size_t uri_len;
    const char *reason = NULL;

    

    

    

    if (lockdb == NULL) {
        
        lock_list = NULL;
    }
    else {
        
        if ((err = dav_lock_query(lockdb, resource, &lock_list)) != NULL) {
            return dav_push_error(p, HTTP_INTERNAL_SERVER_ERROR, 0, "The locks could not be queried for " "verification against a possible \"If:\" " "header.", err);




        }

        
    }

    
    if (flags & DAV_LOCKSCOPE_EXCLUSIVE) {
        if (lock_list != NULL) {
            return dav_new_error(p, HTTP_LOCKED, 0, 0, "Existing lock(s) on the requested resource " "prevent an exclusive lock.");

        }

        
        seen_locktoken = 1;
    }
    else if (flags & DAV_LOCKSCOPE_SHARED) {
        
        for (lock = lock_list; lock != NULL; lock = lock->next) {
            if (lock->scope == DAV_LOCKSCOPE_EXCLUSIVE) {
                return dav_new_error(p, HTTP_LOCKED, 0, 0, "The requested resource is already " "locked exclusively.");

            }
        }

        
        seen_locktoken = 1;
    }
    else {
        
        seen_locktoken = (lock_list == NULL);
    }

    
    if (if_header == NULL) {
        if (seen_locktoken)
            return NULL;

        return dav_new_error(p, HTTP_LOCKED, 0, 0, "This resource is locked and an \"If:\" header " "was not supplied to allow access to the " "resource.");


    }
    

    
    if (lock_list == NULL && if_header->dummy_header) {
        if (flags & DAV_VALIDATE_IS_PARENT)
            return NULL;
        return dav_new_error(p, HTTP_BAD_REQUEST, 0, 0, "The locktoken specified in the \"Lock-Token:\" " "header is invalid because this resource has no " "outstanding locks.");


    }

    
    uri = resource->uri;
    uri_len = strlen(uri);
    if (uri[uri_len - 1] == '/') {
        dav_set_bufsize(p, pbuf, uri_len);
        memcpy(pbuf->buf, uri, uri_len);
        pbuf->buf[--uri_len] = '\0';
        uri = pbuf->buf;
    }

    
    etag = (*resource->hooks->getetag)(resource);

    
    num_that_apply = 0;

    
    for (ifhdr_scan = if_header;
         ifhdr_scan != NULL;
         ifhdr_scan = ifhdr_scan->next) {

        

        if (ifhdr_scan->uri != NULL && (uri_len != ifhdr_scan->uri_len || memcmp(uri, ifhdr_scan->uri, uri_len) != 0)) {

            
            continue;
        }

        

        
        ++num_that_apply;

        
        for (state_list = ifhdr_scan->state;
             state_list != NULL;
             state_list = state_list->next) {

            switch(state_list->type) {
            case dav_if_etag:
            {
                const char *given_etag, *current_etag;
                int mismatch;

                
                if (state_list->etag[0] == 'W' && state_list->etag[1] == '/') {
                    given_etag = state_list->etag + 2;
                }
                else {
                    given_etag = state_list->etag;
                }
                if (etag[0] == 'W' && etag[1] == '/') {
                    current_etag = etag + 2;
                }
                else {
                    current_etag = etag;
                }

                mismatch = strcmp(given_etag, current_etag);

                if (state_list->condition == DAV_IF_COND_NORMAL && mismatch) {
                    
                    reason = "an entity-tag was specified, but the resource's " "actual ETag does not match.";

                    goto state_list_failed;
                }
                else if (state_list->condition == DAV_IF_COND_NOT && !mismatch) {
                    
                    reason = "an entity-tag was specified using the \"Not\" form, " "but the resource's actual ETag matches the provided " "entity-tag.";


                    goto state_list_failed;
                }
                break;
            }

            case dav_if_opaquelock:
                if (lockdb == NULL) {
                    if (state_list->condition == DAV_IF_COND_NOT) {
                        
                        continue;
                    }

                    

                    
                    reason = "a State-token was supplied, but a lock database " "is not available for to provide the required lock.";

                    goto state_list_failed;
                }

                
                num_matched = 0;
                for (lock = lock_list; lock != NULL; lock = lock->next) {

                    

                    
                    if ((*locks_hooks->compare_locktoken)(state_list->locktoken, lock->locktoken)) {
                        continue;
                    }

                    
                    seen_locktoken = 1;

                    if (state_list->condition == DAV_IF_COND_NOT) {
                        
                        reason = "a State-token was supplied, which used a " "\"Not\" condition. The State-token was found " "in the locks on this resource";


                        goto state_list_failed;
                    }

                    

                    
                    if (lock->auth_user && (!r->user || strcmp(lock->auth_user, r->user))) {

                        const char *errmsg;

                        errmsg = apr_pstrcat(p, "User \"", r->user, "\" submitted a locktoken created " "by user \"", lock->auth_user, "\".", NULL);



                        return dav_new_error(p, HTTP_FORBIDDEN, 0, 0, errmsg);
                    }

                    
                    num_matched = 1;
                    break;
                }

                if (num_matched == 0 && state_list->condition == DAV_IF_COND_NORMAL) {
                    
                    reason = "a State-token was supplied, but it was not found " "in the locks on this resource.";

                    goto state_list_failed;
                }

                break;

            case dav_if_unknown:
                

                if (state_list->condition == DAV_IF_COND_NORMAL) {
                    reason = "an unknown state token was supplied";
                    goto state_list_failed;
                }
                break;

            } 
        } 

        
        if (seen_locktoken) {
            
            return NULL;
        }

        
        break;

        
      state_list_failed:
        ;

    } 

    

    if (ifhdr_scan == NULL) {
        

        
        if (num_that_apply == 0) {
            if (seen_locktoken)
                return NULL;

            
            if (dav_find_submitted_locktoken(if_header, lock_list, locks_hooks)) {
                
                return NULL;
            }

            return dav_new_error(p, HTTP_LOCKED, 0 , 0, "This resource is locked and the \"If:\" " "header did not specify one of the " "locktokens for this resource's lock(s).");


        }
        

        
        if (if_header->dummy_header) {
            return dav_new_error(p, HTTP_BAD_REQUEST, 0, 0, "The locktoken specified in the " "\"Lock-Token:\" header did not specify one " "of this resource's locktoken(s).");


        }

        if (reason == NULL) {
            return dav_new_error(p, HTTP_PRECONDITION_FAILED, 0, 0, "The preconditions specified by the \"If:\" " "header did not match this resource.");

        }

        return dav_new_error(p, HTTP_PRECONDITION_FAILED, 0, 0, apr_psprintf(p, "The precondition(s) specified by " "the \"If:\" header did not match " "this resource. At least one " "failure is because: %s", reason));




    }

    

    
    if (dav_find_submitted_locktoken(if_header, lock_list, locks_hooks)) {
        
        return NULL;
    }

    
    if (if_header->dummy_header) {
        return dav_new_error(p, HTTP_BAD_REQUEST, 0, 0, "The locktoken specified in the " "\"Lock-Token:\" header did not specify one " "of this resource's locktoken(s).");


    }

    return dav_new_error(p, HTTP_LOCKED, 1 , 0, "This resource is locked and the \"If:\" header " "did not specify one of the " "locktokens for this resource's lock(s).");


}


static dav_error * dav_validate_walker(dav_walk_resource *wres, int calltype)
{
    dav_walker_ctx *ctx = wres->walk_ctx;
    dav_error *err;

    if ((err = dav_validate_resource_state(ctx->w.pool, wres->resource, ctx->w.lockdb, ctx->if_header, ctx->flags, &ctx->work_buf, ctx->r)) == NULL) {


        
        return NULL;
    }

    
    if (ap_is_HTTP_SERVER_ERROR(err->status)
        || (*wres->resource->hooks->is_same_resource)(wres->resource, ctx->w.root)) {
        
        return err;
    }

    
    dav_add_response(wres, err->status, NULL);

    return NULL;
}


static int dav_meets_conditions(request_rec *r, int resource_state)
{
    const char *if_match, *if_none_match;
    int retVal;

    
    if ((if_match = apr_table_get(r->headers_in, "If-Match")) != NULL) {
        if (if_match[0] == '*' && resource_state != DAV_RESOURCE_EXISTS)
            return HTTP_PRECONDITION_FAILED;
    }

    retVal = ap_meets_conditions(r);

    
    if (retVal == HTTP_PRECONDITION_FAILED) {
        
        if ((if_none_match = apr_table_get(r->headers_in, "If-None-Match")) != NULL) {
            if (if_none_match[0] == '*' && resource_state != DAV_RESOURCE_EXISTS) {
                return OK;
            }
        }
    }

    return retVal;
}


DAV_DECLARE(dav_error *) dav_validate_request(request_rec *r, dav_resource *resource, int depth, dav_locktoken *locktoken, dav_response **response, int flags, dav_lockdb *lockdb)





{
    dav_error *err;
    int result;
    dav_if_header *if_header;
    int lock_db_opened_locally = 0;
    const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);
    const dav_hooks_repository *repos_hooks = resource->hooks;
    dav_buffer work_buf = { 0 };
    dav_response *new_response;
    int resource_state;
    const char *etag;
    int set_etag = 0;


    if (depth && response == NULL) {
        
        return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, 0, "DESIGN ERROR: dav_validate_request called " "with depth>0, but no response ptr.");

    }


    if (response != NULL)
        *response = NULL;

    
    etag = apr_table_get(r->headers_out, "ETag");
    if (!etag) {
        etag = (*resource->hooks->getetag)(resource);
        if (etag && *etag) {
            apr_table_set(r->headers_out, "ETag", etag);
            set_etag = 1;
        }
    }
    
    resource_state = dav_get_resource_state(r, resource);
    result = dav_meets_conditions(r, resource_state);
    if (set_etag) {
        
        apr_table_unset(r->headers_out, "ETag");
    }
    if (result != OK) {
        return dav_new_error(r->pool, result, 0, 0, NULL);
    }

    
    if ((err = dav_process_if_header(r, &if_header)) != NULL) {
        
        return err;
    }

    
    if (locktoken != NULL) {
        dav_if_header *ifhdr_new;

        ifhdr_new = apr_pcalloc(r->pool, sizeof(*ifhdr_new));
        ifhdr_new->uri = resource->uri;
        ifhdr_new->uri_len = strlen(resource->uri);
        ifhdr_new->dummy_header = 1;

        ifhdr_new->state = apr_pcalloc(r->pool, sizeof(*ifhdr_new->state));
        ifhdr_new->state->type = dav_if_opaquelock;
        ifhdr_new->state->condition = DAV_IF_COND_NORMAL;
        ifhdr_new->state->locktoken = locktoken;

        ifhdr_new->next = if_header;
        if_header = ifhdr_new;
    }

    
    if (lockdb == NULL) {
        if (locks_hooks != NULL) {
            if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, &lockdb)) != NULL) {
                
                return err;
            }
            lock_db_opened_locally = 1;
        }
    }

    
    if (resource->exists && depth > 0) {
        dav_walker_ctx ctx = { { 0 } };
        dav_response *multi_status;

        ctx.w.walk_type = DAV_WALKTYPE_NORMAL;
        ctx.w.func = dav_validate_walker;
        ctx.w.walk_ctx = &ctx;
        ctx.w.pool = r->pool;
        ctx.w.root = resource;

        ctx.if_header = if_header;
        ctx.r = r;
        ctx.flags = flags;

        if (lockdb != NULL) {
            ctx.w.lockdb = lockdb;
            ctx.w.walk_type |= DAV_WALKTYPE_LOCKNULL;
        }

        err = (*repos_hooks->walk)(&ctx.w, DAV_INFINITY, &multi_status);
        if (err == NULL) {
            *response = multi_status;;
        }
        
    }
    else {
        err = dav_validate_resource_state(r->pool, resource, lockdb, if_header, flags, &work_buf, r);
    }

    
    if (err == NULL && (flags & DAV_VALIDATE_PARENT)) {
        dav_resource *parent_resource;

        err = (*repos_hooks->get_parent_resource)(resource, &parent_resource);

        if (err == NULL && parent_resource == NULL) {
            err = dav_new_error(r->pool, HTTP_FORBIDDEN, 0, 0, "Cannot access parent of repository root.");
        }
        else if (err == NULL) {
            err = dav_validate_resource_state(r->pool, parent_resource, lockdb, if_header, flags | DAV_VALIDATE_IS_PARENT, &work_buf, r);



            
            if (err != NULL) {
                new_response = apr_pcalloc(r->pool, sizeof(*new_response));

                new_response->href = parent_resource->uri;
                new_response->status = err->status;
                new_response->desc = "A validation error has occurred on the parent resource, " "preventing the operation on the resource specified by " "the Request-URI.";


                if (err->desc != NULL) {
                    new_response->desc = apr_pstrcat(r->pool, new_response->desc, " The error was: ", err->desc, NULL);


                }

                
                new_response->next = *response;
                *response = new_response;

                err = NULL;
            }
        }
    }

    if (lock_db_opened_locally)
        (*locks_hooks->close_lockdb)(lockdb);

    
    if (err == NULL && response != NULL && *response != NULL) {
        apr_text *propstat = NULL;

        if ((flags & DAV_VALIDATE_USE_424) != 0) {
            
            return dav_new_error(r->pool, HTTP_FAILED_DEPENDENCY, 0, 0, "An error occurred on another resource, " "preventing the requested operation on " "this resource.");


        }

        
        if ((flags & DAV_VALIDATE_ADD_LD) != 0) {
            propstat = apr_pcalloc(r->pool, sizeof(*propstat));
            propstat->text = "<D:propstat>" DEBUG_CR "<D:prop><D:lockdiscovery/></D:prop>" DEBUG_CR "<D:status>HTTP/1.1 424 Failed Dependency</D:status>" DEBUG_CR "</D:propstat>" DEBUG_CR;



        }

        
        new_response = apr_pcalloc(r->pool, sizeof(*new_response));
        new_response->href = resource->uri;
        new_response->status = HTTP_FAILED_DEPENDENCY;
        new_response->propresult.propstats = propstat;
        new_response->desc = "An error occurred on another resource, preventing the " "requested operation on this resource.";


        new_response->next = *response;
        *response = new_response;

        
        return dav_new_error(r->pool, HTTP_MULTI_STATUS, 0, 0, "Error(s) occurred on resources during the " "validation process.");

    }

    return err;
}


DAV_DECLARE(dav_error *) dav_get_locktoken_list(request_rec *r, dav_locktoken_list **ltl)
{
    dav_error *err;
    dav_if_header *if_header;
    dav_if_state_list *if_state;
    dav_locktoken_list *lock_token = NULL;

    *ltl = NULL;

    if ((err = dav_process_if_header(r, &if_header)) != NULL) {
        
        return err;
    }

    while (if_header != NULL) {
        if_state = if_header->state;        
        while (if_state != NULL)        {
            if (if_state->condition == DAV_IF_COND_NORMAL && if_state->type == dav_if_opaquelock) {
                lock_token = apr_pcalloc(r->pool, sizeof(dav_locktoken_list));
                lock_token->locktoken = if_state->locktoken;
                lock_token->next = *ltl;
                *ltl = lock_token;
            }
            if_state = if_state->next;
        }
        if_header = if_header->next;
    }
    if (*ltl == NULL) {
        
        return dav_new_error(r->pool, HTTP_BAD_REQUEST, DAV_ERR_IF_ABSENT, 0, "No locktokens were specified in the \"If:\" " "header, so the refresh could not be performed.");

    }

    return NULL;
}



static const char *strip_white(const char *s, apr_pool_t *pool)
{
    apr_size_t idx;

    
    while (apr_isspace(*s))     
        ++s;

    
    idx = strlen(s) - 1;
    if (apr_isspace(s[idx])) {
        char *s2 = apr_pstrdup(pool, s);

        while (apr_isspace(s2[idx]) && idx > 0)
            --idx;
        s2[idx + 1] = '\0';
        return s2;
    }

    return s;
}





DAV_DECLARE(void) dav_add_vary_header(request_rec *in_req, request_rec *out_req, const dav_resource *resource)

{
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(in_req);

    

    
    if (vsn_hooks != NULL) {
        const char *target = apr_table_get(in_req->headers_in, DAV_LABEL_HDR);
        const char *vary = apr_table_get(out_req->headers_out, "Vary");

        
        if (target != NULL) {
            if (vary == NULL)
                vary = DAV_LABEL_HDR;
            else vary = apr_pstrcat(out_req->pool, vary, "," DAV_LABEL_HDR, NULL);


            apr_table_setn(out_req->headers_out, "Vary", vary);
        }
    }
}


static dav_error * dav_can_auto_checkout( request_rec *r, dav_resource *resource, dav_auto_version auto_version, dav_lockdb **lockdb, int *auto_checkout)




{
    dav_error *err;
    dav_lock *lock_list;

    *auto_checkout = 0;

    if (auto_version == DAV_AUTO_VERSION_ALWAYS) {
        *auto_checkout = 1;
    }
    else if (auto_version == DAV_AUTO_VERSION_LOCKED) {
        if (*lockdb == NULL) {
            const dav_hooks_locks *locks_hooks = DAV_GET_HOOKS_LOCKS(r);

            if (locks_hooks == NULL) {
                return dav_new_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, 0, "Auto-checkout is only enabled for locked resources, " "but there is no lock provider.");

            }

            if ((err = (*locks_hooks->open_lockdb)(r, 0, 0, lockdb)) != NULL) {
                return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, "Cannot open lock database to determine " "auto-versioning behavior.", err);


            }
        }

        if ((err = dav_lock_query(*lockdb, resource, &lock_list)) != NULL) {
            return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, "The locks could not be queried for " "determining auto-versioning behavior.", err);



        }

        if (lock_list != NULL)
            *auto_checkout = 1;
    }

    return NULL;
}


DAV_DECLARE(dav_error *) dav_auto_checkout( request_rec *r, dav_resource *resource, int parent_only, dav_auto_version_info *av_info)



{
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_lockdb *lockdb = NULL;
    dav_error *err = NULL;

    
    memset(av_info, 0, sizeof(*av_info));

    
    if (vsn_hooks == NULL)
        return NULL;

    
    if (!resource->exists || parent_only) {
        dav_resource *parent;

        if ((err = (*resource->hooks->get_parent_resource)(resource, &parent)) != NULL)
            goto done;

        if (parent == NULL || !parent->exists) {
            err = dav_new_error(r->pool, HTTP_CONFLICT, 0, 0, apr_psprintf(r->pool, "Missing one or more intermediate " "collections. Cannot create resource %s.", ap_escape_html(r->pool, resource->uri)));



            goto done;
        }

        av_info->parent_resource = parent;

        
        if (parent->versioned && !parent->working) {
            int checkout_parent;

            if ((err = dav_can_auto_checkout(r, parent, (*vsn_hooks->auto_versionable)(parent), &lockdb, &checkout_parent))

                != NULL) {
                goto done;
            }

            if (!checkout_parent) {
                err = dav_new_error(r->pool, HTTP_CONFLICT, 0, 0, "<DAV:cannot-modify-checked-in-parent>");
                goto done;
            }

            
            if ((err = (*vsn_hooks->checkout)(parent, 1 , 0, 0, 0, NULL, NULL))
                != NULL)
            {
                err = dav_push_error(r->pool, HTTP_CONFLICT, 0, apr_psprintf(r->pool, "Unable to auto-checkout parent collection. " "Cannot create resource %s.", ap_escape_html(r->pool, resource->uri)), err);




                goto done;
            }

            
            av_info->parent_checkedout = 1;
        }
    }

    
    if (parent_only)
        goto done;

    
    if (!resource->exists && (*vsn_hooks->auto_versionable)(resource) == DAV_AUTO_VERSION_ALWAYS) {

        if ((err = (*vsn_hooks->vsn_control)(resource, NULL)) != NULL) {
            err = dav_push_error(r->pool, HTTP_CONFLICT, 0, apr_psprintf(r->pool, "Unable to create versioned resource %s.", ap_escape_html(r->pool, resource->uri)), err);



            goto done;
        }

        
        av_info->resource_versioned = 1;
    }

    
    if (resource->versioned && !resource->working) {
        int checkout_resource;

        if ((err = dav_can_auto_checkout(r, resource, (*vsn_hooks->auto_versionable)(resource), &lockdb, &checkout_resource)) != NULL) {

            goto done;
        }

        if (!checkout_resource) {
            err = dav_new_error(r->pool, HTTP_CONFLICT, 0, 0, "<DAV:cannot-modify-version-controlled-content>");
            goto done;
        }

        
        if ((err = (*vsn_hooks->checkout)(resource, 1 , 0, 0, 0, NULL, NULL))
            != NULL)
        {
            err = dav_push_error(r->pool, HTTP_CONFLICT, 0, apr_psprintf(r->pool, "Unable to checkout resource %s.", ap_escape_html(r->pool, resource->uri)), err);



            goto done;
        }

        
        av_info->resource_checkedout = 1;
    }

done:

    
    if (lockdb != NULL)
        (*lockdb->hooks->close_lockdb)(lockdb);

    
    if (err != NULL) {
        dav_auto_checkin(r, resource, 1 , 0 , av_info);
        return err;
    }

    return NULL;
}


DAV_DECLARE(dav_error *) dav_auto_checkin( request_rec *r, dav_resource *resource, int undo, int unlock, dav_auto_version_info *av_info)




{
    const dav_hooks_vsn *vsn_hooks = DAV_GET_HOOKS_VSN(r);
    dav_error *err = NULL;
    dav_auto_version auto_version;

    
    if (vsn_hooks == NULL)
        return NULL;

    
    if (undo) {
        if (resource != NULL) {
            if (av_info->resource_checkedout) {
                if ((err = (*vsn_hooks->uncheckout)(resource)) != NULL) {
                    return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, apr_psprintf(r->pool, "Unable to undo auto-checkout " "of resource %s.", ap_escape_html(r->pool, resource->uri)), err);




                }
            }

            if (av_info->resource_versioned) {
                dav_response *response;

                
                if ((err = (*resource->hooks->remove_resource)(resource, &response)) != NULL) {
                    return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, apr_psprintf(r->pool, "Unable to undo auto-version-control " "of resource %s.", ap_escape_html(r->pool, resource->uri)), err);




                }
            }
        }

        if (av_info->parent_resource != NULL && av_info->parent_checkedout) {
            if ((err = (*vsn_hooks->uncheckout)(av_info->parent_resource)) != NULL) {
                return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, apr_psprintf(r->pool, "Unable to undo auto-checkout " "of parent collection %s.", ap_escape_html(r->pool, av_info->parent_resource->uri)), err);




            }
        }

        return NULL;
    }

    
    if (resource != NULL && resource->working && (unlock || av_info->resource_checkedout)) {

        auto_version = (*vsn_hooks->auto_versionable)(resource);

        if (auto_version == DAV_AUTO_VERSION_ALWAYS || (unlock && (auto_version == DAV_AUTO_VERSION_LOCKED))) {

            if ((err = (*vsn_hooks->checkin)(resource, 0 , NULL))
                != NULL) {
                return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, apr_psprintf(r->pool, "Unable to auto-checkin resource %s.", ap_escape_html(r->pool, resource->uri)), err);



            }
        }
    }

    
    if (!unlock && av_info->parent_checkedout && av_info->parent_resource != NULL && av_info->parent_resource->working) {



        auto_version = (*vsn_hooks->auto_versionable)(av_info->parent_resource);

        if (auto_version == DAV_AUTO_VERSION_ALWAYS) {
            if ((err = (*vsn_hooks->checkin)(av_info->parent_resource, 0 , NULL))
                != NULL) {
                return dav_push_error(r->pool, HTTP_INTERNAL_SERVER_ERROR, 0, apr_psprintf(r->pool, "Unable to auto-checkin parent collection %s.", ap_escape_html(r->pool, av_info->parent_resource->uri)), err);



            }
        }
    }

    return NULL;
}
