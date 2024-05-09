




















module AP_MODULE_DECLARE_DATA proxy_ftp_module;

typedef struct {
    int ftp_list_on_wildcard;
    int ftp_list_on_wildcard_set;
    int ftp_escape_wildcards;
    int ftp_escape_wildcards_set;
    const char *ftp_directory_charset;
} proxy_ftp_dir_conf;

static void *create_proxy_ftp_dir_config(apr_pool_t *p, char *dummy)
{
    proxy_ftp_dir_conf *new = (proxy_ftp_dir_conf *) apr_pcalloc(p, sizeof(proxy_ftp_dir_conf));

    
    new->ftp_list_on_wildcard = 1;
    new->ftp_escape_wildcards = 1;

    return (void *) new;
}

static void *merge_proxy_ftp_dir_config(apr_pool_t *p, void *basev, void *addv)
{
    proxy_ftp_dir_conf *new = (proxy_ftp_dir_conf *) apr_pcalloc(p, sizeof(proxy_ftp_dir_conf));
    proxy_ftp_dir_conf *add = (proxy_ftp_dir_conf *) addv;
    proxy_ftp_dir_conf *base = (proxy_ftp_dir_conf *) basev;

    
    new->ftp_list_on_wildcard = add->ftp_list_on_wildcard_set ? add->ftp_list_on_wildcard :
                                base->ftp_list_on_wildcard;
    new->ftp_list_on_wildcard_set = add->ftp_list_on_wildcard_set ? 1 :
                                base->ftp_list_on_wildcard_set;
    new->ftp_escape_wildcards = add->ftp_escape_wildcards_set ? add->ftp_escape_wildcards :
                                base->ftp_escape_wildcards;
    new->ftp_escape_wildcards_set = add->ftp_escape_wildcards_set ? 1 :
                                base->ftp_escape_wildcards_set;
    new->ftp_directory_charset = add->ftp_directory_charset ? add->ftp_directory_charset :
                                 base->ftp_directory_charset;
    return new;
}

static const char *set_ftp_list_on_wildcard(cmd_parms *cmd, void *dconf, int flag)
{
    proxy_ftp_dir_conf *conf = dconf;

    conf->ftp_list_on_wildcard = flag;
    conf->ftp_list_on_wildcard_set = 1;
    return NULL;
}

static const char *set_ftp_escape_wildcards(cmd_parms *cmd, void *dconf, int flag)
{
    proxy_ftp_dir_conf *conf = dconf;

    conf->ftp_escape_wildcards = flag;
    conf->ftp_escape_wildcards_set = 1;
    return NULL;
}

static const char *set_ftp_directory_charset(cmd_parms *cmd, void *dconf, const char *arg)
{
    proxy_ftp_dir_conf *conf = dconf;

    conf->ftp_directory_charset = arg;
    return NULL;
}


static int decodeenc(char *x)
{
    int i, j, ch;

    if (x[0] == '\0')
        return 0;               
    for (i = 0, j = 0; x[i] != '\0'; i++, j++) {
        
        ch = x[i];
        if (ch == '%' && apr_isxdigit(x[i + 1]) && apr_isxdigit(x[i + 2])) {
            ch = ap_proxy_hex2c(&x[i + 1]);
            i += 2;
        }
        x[j] = ch;
    }
    x[j] = '\0';
    return j;
}



static const char *ftp_escape_globbingchars(apr_pool_t *p, const char *path, proxy_ftp_dir_conf *dconf)
{
    char *ret;
    char *d;

    if (!dconf->ftp_escape_wildcards) {
        return path;
    }

    ret = apr_palloc(p, 2*strlen(path)+sizeof(""));
    for (d = ret; *path; ++path) {
        if (strchr(FTP_GLOBBING_CHARS, *path) != NULL)
            *d++ = '\\';
        *d++ = *path;
    }
    *d = '\0';
    return ret;
}


static int ftp_check_globbingchars(const char *path)
{
    for ( ; *path; ++path) {
        if (*path == '\\')
            ++path;
        if (*path != '\0' && strchr(FTP_GLOBBING_CHARS, *path) != NULL)
            return TRUE;
    }
    return FALSE;
}


static int ftp_check_string(const char *x)
{
    int i, ch = 0;

    char buf[1];


    for (i = 0; x[i] != '\0'; i++) {
        ch = x[i];
        if (ch == '%' && apr_isxdigit(x[i + 1]) && apr_isxdigit(x[i + 2])) {
            ch = ap_proxy_hex2c(&x[i + 1]);
            i += 2;
        }

        if (ch == '\015' || ch == '\012' || (ch & 0x80))

        if (ch == '\r' || ch == '\n')
            return 0;
        buf[0] = ch;
        ap_xlate_proto_to_ascii(buf, 1);
        if (buf[0] & 0x80)

            return 0;
    }
    return 1;
}


static apr_status_t ftp_string_read(conn_rec *c, apr_bucket_brigade *bb, char *buff, apr_size_t bufflen, int *eos)
{
    apr_bucket *e;
    apr_status_t rv;
    char *pos = buff;
    char *response;
    int found = 0;
    apr_size_t len;

    
    buff[0] = 0;
    *eos = 0;

    
    while (!found) {
        
        if (APR_SUCCESS != (rv = ap_get_brigade(c->input_filters, bb, AP_MODE_GETLINE, APR_BLOCK_READ, 0))) {


            return rv;
        }
        
        while (!found) {
            if (*eos || APR_BRIGADE_EMPTY(bb)) {
                
                return APR_ECONNABORTED;
            }
            e = APR_BRIGADE_FIRST(bb);
            if (APR_BUCKET_IS_EOS(e)) {
                *eos = 1;
            }
            else {
                if (APR_SUCCESS != (rv = apr_bucket_read(e, (const char **)&response, &len, APR_BLOCK_READ))) {


                    return rv;
                }
                
                if (memchr(response, APR_ASCII_LF, len)) {
                    found = 1;
                }
                
                if (len > ((bufflen-1)-(pos-buff))) {
                    len = (bufflen-1)-(pos-buff);
                }
                if (len > 0) {
                    memcpy(pos, response, len);
                    pos += len;
                }
            }
            apr_bucket_delete(e);
        }
        *pos = '\0';
    }

    return APR_SUCCESS;
}


static int proxy_ftp_canon(request_rec *r, char *url)
{
    char *user, *password, *host, *path, *parms, *strp, sport[7];
    apr_pool_t *p = r->pool;
    const char *err;
    apr_port_t port, def_port;

    
    if (ap_cstr_casecmpn(url, "ftp:", 4) == 0) {
        url += 4;
    }
    else {
        return DECLINED;
    }
    def_port = apr_uri_port_of_scheme("ftp");

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "canonicalising URL %s", url);

    port = def_port;
    err = ap_proxy_canon_netloc(p, &url, &user, &password, &host, &port);
    if (err)
        return HTTP_BAD_REQUEST;
    if (user != NULL && !ftp_check_string(user))
        return HTTP_BAD_REQUEST;
    if (password != NULL && !ftp_check_string(password))
        return HTTP_BAD_REQUEST;

    
    
    strp = strchr(url, ';');
    if (strp != NULL) {
        *(strp++) = '\0';
        parms = ap_proxy_canonenc(p, strp, strlen(strp), enc_parm, 0, r->proxyreq);
        if (parms == NULL)
            return HTTP_BAD_REQUEST;
    }
    else parms = "";

    path = ap_proxy_canonenc(p, url, strlen(url), enc_path, 0, r->proxyreq);
    if (path == NULL)
        return HTTP_BAD_REQUEST;
    if (!ftp_check_string(path))
        return HTTP_BAD_REQUEST;

    if (r->proxyreq && r->args != NULL) {
        if (strp != NULL) {
            strp = ap_proxy_canonenc(p, r->args, strlen(r->args), enc_parm, 1, r->proxyreq);
            if (strp == NULL)
                return HTTP_BAD_REQUEST;
            parms = apr_pstrcat(p, parms, "?", strp, NULL);
        }
        else {
            strp = ap_proxy_canonenc(p, r->args, strlen(r->args), enc_fpath, 1, r->proxyreq);
            if (strp == NULL)
                return HTTP_BAD_REQUEST;
            path = apr_pstrcat(p, path, "?", strp, NULL);
        }
        r->args = NULL;
    }



    if (port != def_port)
        apr_snprintf(sport, sizeof(sport), ":%d", port);
    else sport[0] = '\0';

    if (ap_strchr_c(host, ':')) { 
        host = apr_pstrcat(p, "[", host, "]", NULL);
    }
    r->filename = apr_pstrcat(p, "proxy:ftp://", (user != NULL) ? user : "", (password != NULL) ? ":" : "", (password != NULL) ? password : "", (user != NULL) ? "@" : "", host, sport, "/", path, (parms[0] != '\0') ? ";" : "", parms, NULL);




    return OK;
}





static int ftp_getrc_msg(conn_rec *ftp_ctrl, apr_bucket_brigade *bb, char *msgbuf, int msglen)
{
    int status;
    char response[MAX_LINE_LEN];
    char buff[5];
    char *mb = msgbuf, *me = &msgbuf[msglen];
    apr_status_t rv;
    int eos;

    if (APR_SUCCESS != (rv = ftp_string_read(ftp_ctrl, bb, response, sizeof(response), &eos))) {
        return -1;
    }

    if (!apr_isdigit(response[0]) || !apr_isdigit(response[1]) || !apr_isdigit(response[2]) || (response[3] != ' ' && response[3] != '-'))
        status = 0;
    else status = 100 * response[0] + 10 * response[1] + response[2] - 111 * '0';

    mb = apr_cpystrn(mb, response + 4, me - mb);

    if (response[3] == '-') {
        memcpy(buff, response, 3);
        buff[3] = ' ';
        do {
            if (APR_SUCCESS != (rv = ftp_string_read(ftp_ctrl, bb, response, sizeof(response), &eos))) {
                return -1;
            }
            mb = apr_cpystrn(mb, response + (' ' == response[0] ? 1 : 4), me - mb);
        } while (memcmp(response, buff, 4) != 0);
    }

    return status;
}





typedef struct {
    apr_bucket_brigade *in;
    char buffer[MAX_STRING_LEN];
    enum {
        HEADER, BODY, FOOTER }    state;
}      proxy_dir_ctx_t;




static ap_regex_t *ls_regex;

static apr_status_t proxy_send_dir_filter(ap_filter_t *f, apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_pool_t *p = r->pool;
    apr_bucket_brigade *out = apr_brigade_create(p, c->bucket_alloc);
    apr_status_t rv;

    int n;
    char *dir, *path, *reldir, *site, *str, *type;

    const char *pwd = apr_table_get(r->notes, "Directory-PWD");
    const char *readme = apr_table_get(r->notes, "Directory-README");

    proxy_dir_ctx_t *ctx = f->ctx;

    if (!ctx) {
        f->ctx = ctx = apr_pcalloc(p, sizeof(*ctx));
        ctx->in = apr_brigade_create(p, c->bucket_alloc);
        ctx->buffer[0] = 0;
        ctx->state = HEADER;
    }

    
    APR_BRIGADE_CONCAT(ctx->in, in);

    if (HEADER == ctx->state) {

        
        const char *basedir = "";  
        char *wildcard = NULL;
        const char *escpath;

        
        if (r->proxyreq == PROXYREQ_REVERSE) {
            site = ap_construct_url(p, "", r);
        }
        else {
            
            site = apr_uri_unparse(p, &f->r->parsed_uri, APR_URI_UNP_OMITPASSWORD | APR_URI_UNP_OMITPATHINFO);

        }

        
        path = apr_uri_unparse(p, &f->r->parsed_uri, APR_URI_UNP_OMITSITEPART | APR_URI_UNP_OMITQUERY);

        
        if (ap_cstr_casecmpn(path, "/%2f", 4) == 0) {
            basedir = "/%2f";
        }

        
        if ((type = strstr(path, ";type=")) != NULL)
            *type++ = '\0';

        (void)decodeenc(path);

        while (path[1] == '/') 
            ++path;

        reldir = strrchr(path, '/');
        if (reldir != NULL && ftp_check_globbingchars(reldir)) {
            wildcard = &reldir[1];
            reldir[0] = '\0'; 
        }

        
        
        path = dir = apr_pstrcat(p, path, "/", NULL);
        for (n = strlen(path); n > 1 && path[n - 1] == '/' && path[n - 2] == '/'; --n)
            path[n - 1] = '\0';

        
        str = (basedir[0] != '\0') ? "<a href=\"/%2f/\">%2f</a>/" : "";

        
        escpath = ap_escape_html(p, path);
        str = apr_psprintf(p, DOCTYPE_HTML_3_2 "<html>\n <head>\n  <title>%s%s%s</title>\n" "<base href=\"%s%s%s\">\n" " </head>\n" " <body>\n  <h2>Directory of " "<a href=\"/\">%s</a>/%s", ap_escape_html(p, site), basedir, escpath, ap_escape_uri(p, site), basedir, escpath, ap_escape_uri(p, site), str);








        APR_BRIGADE_INSERT_TAIL(out, apr_bucket_pool_create(str, strlen(str), p, c->bucket_alloc));

        for (dir = path+1; (dir = strchr(dir, '/')) != NULL; )
        {
            *dir = '\0';
            if ((reldir = strrchr(path+1, '/'))==NULL) {
                reldir = path+1;
            }
            else ++reldir;
            
            str = apr_psprintf(p, "<a href=\"%s%s/\">%s</a>/", basedir, ap_escape_uri(p, path), ap_escape_html(p, reldir));

            *dir = '/';
            while (*dir == '/')
              ++dir;
            APR_BRIGADE_INSERT_TAIL(out, apr_bucket_pool_create(str, strlen(str), p, c->bucket_alloc));

        }
        if (wildcard != NULL) {
            wildcard = ap_escape_html(p, wildcard);
            APR_BRIGADE_INSERT_TAIL(out, apr_bucket_pool_create(wildcard, strlen(wildcard), p, c->bucket_alloc));

        }

        
        
        if (pwd == NULL || strncmp(pwd, path, strlen(pwd)) == 0) {
            str = apr_psprintf(p, "</h2>\n\n  <hr />\n\n<pre>");
        }
        else {
            str = apr_psprintf(p, "</h2>\n\n(%s)\n\n  <hr />\n\n<pre>", ap_escape_html(p, pwd));
        }
        APR_BRIGADE_INSERT_TAIL(out, apr_bucket_pool_create(str, strlen(str), p, c->bucket_alloc));

        
        if (readme) {
            str = apr_psprintf(p, "%s\n</pre>\n\n<hr />\n\n<pre>\n", ap_escape_html(p, readme));

            APR_BRIGADE_INSERT_TAIL(out, apr_bucket_pool_create(str, strlen(str), p, c->bucket_alloc));

        }

        
        APR_BRIGADE_INSERT_TAIL(out, apr_bucket_flush_create(c->bucket_alloc));
        if (APR_SUCCESS != (rv = ap_pass_brigade(f->next, out))) {
            return rv;
        }
        apr_brigade_cleanup(out);

        ctx->state = BODY;
    }

    
    while (BODY == ctx->state) {
        char *filename;
        int found = 0;
        int eos = 0;
        ap_regmatch_t re_result[LS_REG_MATCH];

        
        
        while (!found && !APR_BRIGADE_EMPTY(ctx->in)) {
            char *pos, *response;
            apr_size_t len, max;
            apr_bucket *e;

            e = APR_BRIGADE_FIRST(ctx->in);
            if (APR_BUCKET_IS_EOS(e)) {
                eos = 1;
                break;
            }
            if (APR_SUCCESS != (rv = apr_bucket_read(e, (const char **)&response, &len, APR_BLOCK_READ))) {
                return rv;
            }
            pos = memchr(response, APR_ASCII_LF, len);
            if (pos != NULL) {
                if ((response + len) != (pos + 1)) {
                    len = pos - response + 1;
                    apr_bucket_split(e, pos - response + 1);
                }
                found = 1;
            }
            max = sizeof(ctx->buffer) - strlen(ctx->buffer) - 1;
            if (len > max) {
                len = max;
            }

            
            apr_cpystrn(ctx->buffer+strlen(ctx->buffer), response, len+1);

            apr_bucket_delete(e);
        }

        
        if (eos) {
            ctx->state = FOOTER;
            break;
        }

        
        if (!found) {
            return APR_SUCCESS;
        }

        {
            apr_size_t n = strlen(ctx->buffer);
            if (ctx->buffer[n-1] == CRLF[1])  
                ctx->buffer[--n] = '\0';
            if (ctx->buffer[n-1] == CRLF[0])  
                ctx->buffer[--n] = '\0';
        }

        
        if (ctx->buffer[0] == 'l' && (filename = strstr(ctx->buffer, " -> ")) != NULL) {
            char *link_ptr = filename;

            do {
                filename--;
            } while (filename[0] != ' ' && filename > ctx->buffer);
            if (filename > ctx->buffer)
                *(filename++) = '\0';
            *(link_ptr++) = '\0';
            str = apr_psprintf(p, "%s <a href=\"%s\">%s %s</a>\n", ap_escape_html(p, ctx->buffer), ap_escape_uri(p, filename), ap_escape_html(p, filename), ap_escape_html(p, link_ptr));



        }

        
        else if (ctx->buffer[0] == 'd' || ctx->buffer[0] == '-' || ctx->buffer[0] == 'l' || apr_isdigit(ctx->buffer[0])) {
            int searchidx = 0;
            char *searchptr = NULL;
            int firstfile = 1;
            if (apr_isdigit(ctx->buffer[0])) {  
                searchptr = strchr(ctx->buffer, '<');
                if (searchptr != NULL)
                    *searchptr = '[';
                searchptr = strchr(ctx->buffer, '>');
                if (searchptr != NULL)
                    *searchptr = ']';
            }

            filename = strrchr(ctx->buffer, ' ');
            if (filename == NULL) {
                
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01034)
                              "proxy_ftp: could not parse line %s", ctx->buffer);
                
                ctx->buffer[0] = 0;
                continue;  
            }
            *(filename++) = '\0';

            
            if (!strcmp(filename, ".") || !strcmp(filename, "..") || firstfile) {
                firstfile = 0;
                searchidx = filename - ctx->buffer;
            }
            else if (searchidx != 0 && ctx->buffer[searchidx] != 0) {
                *(--filename) = ' ';
                ctx->buffer[searchidx - 1] = '\0';
                filename = &ctx->buffer[searchidx];
            }

            
            if (!strcmp(filename, ".") || !strcmp(filename, "..") || ctx->buffer[0] == 'd') {
                str = apr_psprintf(p, "%s <a href=\"%s/\">%s</a>\n", ap_escape_html(p, ctx->buffer), ap_escape_uri(p, filename), ap_escape_html(p, filename));


            }
            else {
                str = apr_psprintf(p, "%s <a href=\"%s\">%s</a>\n", ap_escape_html(p, ctx->buffer), ap_escape_uri(p, filename), ap_escape_html(p, filename));


            }
        }
        
        else if (0 == ap_regexec(ls_regex, ctx->buffer, LS_REG_MATCH, re_result, 0)) {
            
            filename = apr_pstrndup(p, &ctx->buffer[re_result[2].rm_so], re_result[2].rm_eo - re_result[2].rm_so);

            str = apr_pstrcat(p, ap_escape_html(p, apr_pstrndup(p, ctx->buffer, re_result[2].rm_so)), "<a href=\"", ap_escape_uri(p, filename), "\">", ap_escape_html(p, filename), "</a>\n", NULL);

        }
        else {
            strcat(ctx->buffer, "\n"); 
            str = ap_escape_html(p, ctx->buffer);
        }

        
        ctx->buffer[0] = 0;

        APR_BRIGADE_INSERT_TAIL(out, apr_bucket_pool_create(str, strlen(str), p, c->bucket_alloc));
        APR_BRIGADE_INSERT_TAIL(out, apr_bucket_flush_create(c->bucket_alloc));
        if (APR_SUCCESS != (rv = ap_pass_brigade(f->next, out))) {
            return rv;
        }
        apr_brigade_cleanup(out);

    }

    if (FOOTER == ctx->state) {
        str = apr_psprintf(p, "</pre>\n\n  <hr />\n\n  %s\n\n </body>\n</html>\n", ap_psignature("", r));
        APR_BRIGADE_INSERT_TAIL(out, apr_bucket_pool_create(str, strlen(str), p, c->bucket_alloc));
        APR_BRIGADE_INSERT_TAIL(out, apr_bucket_flush_create(c->bucket_alloc));
        APR_BRIGADE_INSERT_TAIL(out, apr_bucket_eos_create(c->bucket_alloc));
        if (APR_SUCCESS != (rv = ap_pass_brigade(f->next, out))) {
            return rv;
        }
        apr_brigade_destroy(out);
    }

    return APR_SUCCESS;
}


static apr_port_t parse_epsv_reply(const char *reply)
{
    const char *p;
    char *ep;
    long port;

    
    p = ap_strchr_c(reply, '(');
    if (p == NULL || !p[1] || p[1] != p[2] || p[1] != p[3] || p[4] == p[1]) {
        return 0;
    }

    errno = 0;
    port = strtol(p + 4, &ep, 10);
    if (errno || port < 1 || port > 65535 || ep[0] != p[1] || ep[1] != ')') {
        return 0;
    }

    return (apr_port_t)port;
}


static int proxy_ftp_command(const char *cmd, request_rec *r, conn_rec *ftp_ctrl, apr_bucket_brigade *bb, char **pmessage)

{
    char *crlf;
    int rc;
    char message[HUGE_STRING_LEN];

    
    if (cmd != NULL) {
        conn_rec *c = r->connection;
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_pool_create(cmd, strlen(cmd), r->pool, c->bucket_alloc));
        APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_flush_create(c->bucket_alloc));
        ap_pass_brigade(ftp_ctrl->output_filters, bb);

        if (APLOGrtrace2(r)) {
            
            apr_cpystrn(message, cmd, sizeof(message));
            if ((crlf = strchr(message, '\r')) != NULL || (crlf = strchr(message, '\n')) != NULL)
                *crlf = '\0';
            if (strncmp(message,"PASS ", 5) == 0)
                strcpy(&message[5], "****");
            ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, ">%s", message);
        }
    }

    rc = ftp_getrc_msg(ftp_ctrl, bb, message, sizeof(message));
    if (rc == -1 || rc == 421)
        strcpy(message,"<unable to read result>");
    if ((crlf = strchr(message, '\r')) != NULL || (crlf = strchr(message, '\n')) != NULL)
        *crlf = '\0';
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r, "<%3.3u %s", rc, message);

    if (pmessage != NULL)
        *pmessage = apr_pstrdup(r->pool, message);

    return rc;
}


static int ftp_set_TYPE(char xfer_type, request_rec *r, conn_rec *ftp_ctrl, apr_bucket_brigade *bb, char **pmessage)
{
    char old_type[2] = { 'A', '\0' }; 
    int ret = HTTP_OK;
    int rc;

    
    old_type[0] = xfer_type;

    rc = proxy_ftp_command(apr_pstrcat(r->pool, "TYPE ", old_type, CRLF, NULL), r, ftp_ctrl, bb, pmessage);

    
    
    
    
    
    
    if (rc == -1) {
        ret = ap_proxyerror(r, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
    }
    else if (rc == 421) {
        ret = ap_proxyerror(r, HTTP_BAD_GATEWAY, "Error reading from remote server");
    }
    else if (rc != 200 && rc != 504) {
        ret = ap_proxyerror(r, HTTP_BAD_GATEWAY, "Unable to set transfer type");
    }

    else if (rc == 504) {
        
    }

    return ret;
}



static char *ftp_get_PWD(request_rec *r, conn_rec *ftp_ctrl, apr_bucket_brigade *bb)
{
    char *cwd = NULL;
    char *ftpmessage = NULL;

    
    
    
    
    
    
    
    switch (proxy_ftp_command("PWD" CRLF, r, ftp_ctrl, bb, &ftpmessage)) {
        case -1:
            ap_proxyerror(r, HTTP_GATEWAY_TIME_OUT, "Failed to read PWD on ftp server");
            break;

        case 421:
        case 550:
            ap_proxyerror(r, HTTP_BAD_GATEWAY, "Failed to read PWD on ftp server");
            break;

        case 257: {
            const char *dirp = ftpmessage;
            cwd = ap_getword_conf(r->pool, &dirp);
        }
    }
    return cwd;
}



static int ftp_unauthorized(request_rec *r, int log_it)
{
    r->proxyreq = PROXYREQ_NONE;
    
    if (log_it)
        ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(01035)
                      "missing or failed auth to %s", apr_uri_unparse(r->pool, &r->parsed_uri, APR_URI_UNP_OMITPATHINFO));


    apr_table_setn(r->err_headers_out, "WWW-Authenticate", apr_pstrcat(r->pool, "Basic realm=\"", apr_uri_unparse(r->pool, &r->parsed_uri, APR_URI_UNP_OMITPASSWORD | APR_URI_UNP_OMITPATHINFO), "\"", NULL));




    return HTTP_UNAUTHORIZED;
}

static apr_status_t proxy_ftp_cleanup(request_rec *r, proxy_conn_rec *backend)
{

    backend->close = 1;
    ap_set_module_config(r->connection->conn_config, &proxy_ftp_module, NULL);
    ap_proxy_release_connection("FTP", backend, r->server);

    return OK;
}

static int ftp_proxyerror(request_rec *r, proxy_conn_rec *conn, int statuscode, const char *message)
{
    proxy_ftp_cleanup(r, conn);
    return ap_proxyerror(r, statuscode, message);
}

static int proxy_ftp_handler(request_rec *r, proxy_worker *worker, proxy_server_conf *conf, char *url, const char *proxyhost, apr_port_t proxyport)

{
    apr_pool_t *p = r->pool;
    conn_rec *c = r->connection;
    proxy_conn_rec *backend;
    apr_socket_t *sock, *local_sock, *data_sock = NULL;
    apr_sockaddr_t *connect_addr = NULL;
    apr_status_t rv;
    conn_rec *origin, *data = NULL;
    apr_status_t err = APR_SUCCESS;

    apr_status_t uerr = APR_SUCCESS;

    apr_bucket_brigade *bb;
    char *buf, *connectname;
    apr_port_t connectport;
    char *ftpmessage = NULL;
    char *path, *strp, *type_suffix, *cwd = NULL;
    apr_uri_t uri;
    char *user = NULL;

    const char *password = NULL;
    int len, rc;
    int one = 1;
    char *size = NULL;
    char xfer_type = 'A'; 
    int  dirlisting = 0;

    apr_time_t mtime = 0L;

    proxy_ftp_dir_conf *fdconf = ap_get_module_config(r->per_dir_config, &proxy_ftp_module);

    
    int connect = 0, use_port = 0;
    char dates[APR_RFC822_DATE_LEN];
    int status;
    apr_pool_t *address_pool;

    
    if (proxyhost) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "declining URL %s - proxyhost %s specified:", url, proxyhost);

        return DECLINED;        
    }
    if (ap_cstr_casecmpn(url, "ftp:", 4)) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "declining URL %s - not ftp:", url);
        return DECLINED;        
    }
    ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "serving URL %s", url);


    

    
    if (r->method_number != M_GET)
        return HTTP_NOT_IMPLEMENTED;

    
    if (r->parsed_uri.hostname == NULL) {
        if (APR_SUCCESS != apr_uri_parse(p, url, &uri)) {
            return ap_proxyerror(r, HTTP_BAD_REQUEST, apr_psprintf(p, "URI cannot be parsed: %s", url));
        }
        connectname = uri.hostname;
        connectport = uri.port;
        path = apr_pstrdup(p, uri.path);
    }
    else {
        connectname = r->parsed_uri.hostname;
        connectport = r->parsed_uri.port;
        path = apr_pstrdup(p, r->parsed_uri.path);
    }
    if (connectport == 0) {
        connectport = apr_uri_port_of_scheme("ftp");
    }
    path = (path != NULL && path[0] != '\0') ? &path[1] : "";

    type_suffix = strchr(path, ';');
    if (type_suffix != NULL)
        *(type_suffix++) = '\0';

    if (type_suffix != NULL && strncmp(type_suffix, "type=", 5) == 0 && apr_isalpha(type_suffix[5])) {
        
        if ( ! (dirlisting = (apr_tolower(type_suffix[5]) == 'd')))
            xfer_type = apr_toupper(type_suffix[5]);

        
        if (strchr("AEI", xfer_type) == NULL)
            return ap_proxyerror(r, HTTP_BAD_REQUEST, apr_pstrcat(r->pool, "ftp proxy supports only types 'a', 'i', or 'e': \"", type_suffix, "\" is invalid.", NULL));

    }
    else {
        
        xfer_type = 'I';
    }


    
    if ((password = apr_table_get(r->headers_in, "Authorization")) != NULL && ap_cstr_casecmp(ap_getword(r->pool, &password, ' '), "Basic") == 0 && (password = ap_pbase64decode(r->pool, password))[0] != ':') {

        
        if (!ftp_check_string(password)) {
            return ap_proxyerror(r, HTTP_BAD_REQUEST, "user credentials contained invalid character");
        }
        
        user = ap_getword_nulls(r->connection->pool, &password, ':');
        r->ap_auth_type = "Basic";
        r->user = r->parsed_uri.user = user;
    }
    else if ((user = r->parsed_uri.user) != NULL) {
        user = apr_pstrdup(p, user);
        decodeenc(user);
        if ((password = r->parsed_uri.password) != NULL) {
            char *tmp = apr_pstrdup(p, password);
            decodeenc(tmp);
            password = tmp;
        }
    }
    else {
        user = "anonymous";
        password = "apache-proxy@";
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01036)
                  "connecting %s to %s:%d", url, connectname, connectport);

    if (worker->s->is_address_reusable) {
        if (!worker->cp->addr) {

            if ((err = PROXY_THREAD_LOCK(worker->balancer)) != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, err, r, APLOGNO(01037) "lock");
                return HTTP_INTERNAL_SERVER_ERROR;
            }

        }
        connect_addr = worker->cp->addr;
        address_pool = worker->cp->pool;
    }
    else address_pool = r->pool;

    
    if (!connect_addr)
        err = apr_sockaddr_info_get(&(connect_addr), connectname, APR_UNSPEC, connectport, 0, address_pool);


    if (worker->s->is_address_reusable && !worker->cp->addr) {
        worker->cp->addr = connect_addr;

        if ((uerr = PROXY_THREAD_UNLOCK(worker->balancer)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, uerr, r, APLOGNO(01038) "unlock");
        }

    }
    
    if (APR_SUCCESS != err) {
        return ap_proxyerror(r, HTTP_GATEWAY_TIME_OUT, apr_pstrcat(p, "DNS lookup failure for: ", connectname, NULL));

    }

    
    if (OK != ap_proxy_checkproxyblock(r, conf, connectname, connect_addr)) {
        return ap_proxyerror(r, HTTP_FORBIDDEN, "Connect to remote machine blocked");
    }

    
    backend = (proxy_conn_rec *) ap_get_module_config(c->conn_config, &proxy_ftp_module);
    if (!backend) {
        status = ap_proxy_acquire_connection("FTP", &backend, worker, r->server);
        if (status != OK) {
            if (backend) {
                backend->close = 1;
                ap_proxy_release_connection("FTP", backend, r->server);
            }
            return status;
        }
        
        backend->addr = connect_addr;
        ap_set_module_config(c->conn_config, &proxy_ftp_module, backend);
    }


    


    if (ap_proxy_connect_backend("FTP", backend, worker, r->server)) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01039)
                      "an error occurred creating a new connection to %pI (%s)", connect_addr, connectname);
        proxy_ftp_cleanup(r, backend);
        return HTTP_SERVICE_UNAVAILABLE;
    }

    status = ap_proxy_connection_create_ex("FTP", backend, r);
    if (status != OK) {
        proxy_ftp_cleanup(r, backend);
        return status;
    }

    
    origin = backend->connection;
    sock = backend->sock;

    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "control connection complete");


    

    bb = apr_brigade_create(p, c->bucket_alloc);

    
    
    
    
    rc = proxy_ftp_command(NULL, r, origin, bb, &ftpmessage);
    if (rc == -1) {
        return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
    }
    else if (rc == 421) {
        return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
    }
    else if (rc == 120) {
        
        char *secs_str = ftpmessage;
        time_t secs;

        
        while (*secs_str)
            if ((secs_str==ftpmessage || apr_isspace(secs_str[-1])) && apr_isdigit(secs_str[0]))
                break;
        if (*secs_str != '\0') {
            secs = atol(secs_str);
            apr_table_addn(r->headers_out, "Retry-After", apr_psprintf(p, "%lu", (unsigned long)(60 * secs)));
        }
        return ftp_proxyerror(r, backend, HTTP_SERVICE_UNAVAILABLE, ftpmessage);
    }
    else if (rc != 220) {
        return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, ftpmessage);
    }

    rc = proxy_ftp_command(apr_pstrcat(p, "USER ", user, CRLF, NULL), r, origin, bb, &ftpmessage);
    
    
    
    
    
    
    
    
    
    
    if (rc == -1) {
        return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
    }
    else if (rc == 421) {
        return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
    }
    else if (rc == 530) {
        proxy_ftp_cleanup(r, backend);
        return ftp_unauthorized(r, 1);  
    }
    else if (rc != 230 && rc != 331) {
        return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, ftpmessage);
    }

    if (rc == 331) {            
        if (password == NULL) {
            proxy_ftp_cleanup(r, backend);
            return ftp_unauthorized(r, 0);
        }

        rc = proxy_ftp_command(apr_pstrcat(p, "PASS ", password, CRLF, NULL), r, origin, bb, &ftpmessage);
        
        
        
        
        
        
        
        
        if (rc == -1) {
            return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
        }
        else if (rc == 421) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
        }
        else if (rc == 332) {
            return ftp_proxyerror(r, backend, HTTP_UNAUTHORIZED, apr_pstrcat(p, "Need account for login: ", ftpmessage, NULL));
        }
        
        else if (rc == 530) {
            proxy_ftp_cleanup(r, backend);
            return ftp_unauthorized(r, 1);      
        }
        else if (rc != 230 && rc != 202) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, ftpmessage);
        }
    }
    apr_table_set(r->notes, "Directory-README", ftpmessage);


    
    if (ap_cstr_casecmpn(path, "%2f", 3) == 0) {
        path += 3;
        while (*path == '/') 
            ++path;

        rc = proxy_ftp_command("CWD /" CRLF, r, origin, bb, &ftpmessage);
        if (rc == -1) {
            return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
        }
        else if (rc == 421) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
        }
    }

    
    for (;;) {
        strp = strchr(path, '/');
        if (strp == NULL)
            break;
        *strp = '\0';

        decodeenc(path); 

        if (strchr(path, '/')) { 
            return ftp_proxyerror(r, backend, HTTP_BAD_REQUEST, "Use of /%2f is only allowed at the base directory");
        }

        
        rc = proxy_ftp_command(apr_pstrcat(p, "CWD ", ftp_escape_globbingchars(p, path, fdconf), CRLF, NULL), r, origin, bb, &ftpmessage);

        *strp = '/';
        
        
        
        
        
        
        
        
        if (rc == -1) {
            return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
        }
        else if (rc == 421) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
        }
        else if (rc == 550) {
            return ftp_proxyerror(r, backend, HTTP_NOT_FOUND, ftpmessage);
        }
        else if (rc != 250) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, ftpmessage);
        }

        path = strp + 1;
    }

    



    
    {
        apr_port_t data_port;

        
        rc = proxy_ftp_command("EPSV" CRLF, r, origin, bb, &ftpmessage);
        
        
        
        
        
        
        
        if (rc == -1) {
            return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
        }
        else if (rc == 421) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
        }
        else if (rc != 229 && rc != 500 && rc != 501 && rc != 502) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, ftpmessage);
        }
        else if (rc == 229) {
            
            data_port = parse_epsv_reply(ftpmessage);

            if (data_port) {
                apr_sockaddr_t *remote_addr, epsv_addr;

                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "EPSV contacting remote host on port %d", data_port);

                
                rv = apr_socket_addr_get(&remote_addr, APR_REMOTE, sock);
                if (rv == APR_SUCCESS) {
                    
                    epsv_addr = *remote_addr;
                    epsv_addr.port = data_port;

                    if (epsv_addr.family == APR_INET6) {
                        epsv_addr.sa.sin6.sin6_port = htons(data_port);
                    }
                    else  {

                        epsv_addr.sa.sin.sin_port = htons(data_port);
                    }
                    rv = apr_socket_create(&data_sock, epsv_addr.family, SOCK_STREAM, 0, r->pool);
                }

                if (rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01040) 
                                  "could not establish socket for client data connection");
                    proxy_ftp_cleanup(r, backend);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                if (conf->recv_buffer_size > 0 && (rv = apr_socket_opt_set(data_sock, APR_SO_RCVBUF, conf->recv_buffer_size))) {

                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01041)
                                  "apr_socket_opt_set(SO_RCVBUF): Failed to " "set ProxyReceiveBufferSize, using default");
                }

                rv = apr_socket_opt_set(data_sock, APR_TCP_NODELAY, 1);
                if (rv != APR_SUCCESS && rv != APR_ENOTIMPL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01042)
                                  "apr_socket_opt_set(APR_TCP_NODELAY): " "Failed to set");
                }

                rv = apr_socket_connect(data_sock, &epsv_addr);
                if (rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01043)
                                  "EPSV attempt to connect to %pI failed - " "Firewall/NAT?", &epsv_addr);
                    return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, apr_psprintf(r->pool, "EPSV attempt to connect to %pI failed - firewall/NAT?", &epsv_addr));


                }
                else {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "connected data socket to %pI", &epsv_addr);
                    connect = 1;
                }
            }
        }
    }

    
    if (!connect) {
        rc = proxy_ftp_command("PASV" CRLF, r, origin, bb, &ftpmessage);
        
        
        
        
        
        
        
        if (rc == -1) {
            return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
        }
        else if (rc == 421) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
        }
        else if (rc != 227 && rc != 502) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, ftpmessage);
        }
        else if (rc == 227) {
            unsigned int h0, h1, h2, h3, p0, p1;
            char *pstr;
            char *tok_cntx;



            pstr = ftpmessage;
            pstr = apr_strtok(pstr, " ", &tok_cntx);    
            if (pstr != NULL) {
                if (*(pstr + strlen(pstr) + 1) == '=') {
                    pstr += strlen(pstr) + 2;
                }
                else {
                    pstr = apr_strtok(NULL, "(", &tok_cntx);    
                    if (pstr != NULL)
                        pstr = apr_strtok(NULL, ")", &tok_cntx);
                }
            }



            if (pstr != NULL && (sscanf(pstr, "%d,%d,%d,%d,%d,%d", &h3, &h2, &h1, &h0, &p1, &p0) == 6)) {

                apr_sockaddr_t *pasv_addr;
                apr_port_t pasvport = (p1 << 8) + p0;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01044)
                              "PASV contacting host %d.%d.%d.%d:%d", h3, h2, h1, h0, pasvport);

                if ((rv = apr_socket_create(&data_sock, connect_addr->family, SOCK_STREAM, 0, r->pool)) != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01045)
                                  "error creating PASV socket");
                    proxy_ftp_cleanup(r, backend);
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                if (conf->recv_buffer_size > 0 && (rv = apr_socket_opt_set(data_sock, APR_SO_RCVBUF, conf->recv_buffer_size))) {

                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01046)
                                  "apr_socket_opt_set(SO_RCVBUF): Failed to set ProxyReceiveBufferSize, using default");
                }

                rv = apr_socket_opt_set(data_sock, APR_TCP_NODELAY, 1);
                if (rv != APR_SUCCESS && rv != APR_ENOTIMPL) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01047)
                                  "apr_socket_opt_set(APR_TCP_NODELAY): " "Failed to set");
                }

                
                apr_sockaddr_info_get(&pasv_addr, apr_psprintf(p, "%d.%d.%d.%d", h3, h2, h1, h0), connect_addr->family, pasvport, 0, p);
                rv = apr_socket_connect(data_sock, pasv_addr);
                if (rv != APR_SUCCESS) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01048)
                                  "PASV attempt to connect to %pI failed - Firewall/NAT?", pasv_addr);
                    return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, apr_psprintf(r->pool, "PASV attempt to connect to %pI failed - firewall/NAT?", pasv_addr));


                }
                else {
                    connect = 1;
                }
            }
        }
    }


    
    if (!connect) {
        apr_sockaddr_t *local_addr;
        char *local_ip;
        apr_port_t local_port;
        unsigned int h0, h1, h2, h3, p0, p1;

        if ((rv = apr_socket_create(&local_sock, connect_addr->family, SOCK_STREAM, 0, r->pool)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01049)
                          "error creating local socket");
            proxy_ftp_cleanup(r, backend);
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        apr_socket_addr_get(&local_addr, APR_LOCAL, sock);
        local_port = local_addr->port;
        apr_sockaddr_ip_get(&local_ip, local_addr);

        if ((rv = apr_socket_opt_set(local_sock, APR_SO_REUSEADDR, one))
                != APR_SUCCESS) {

            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01050)
                          "error setting reuseaddr option");
            proxy_ftp_cleanup(r, backend);
            return HTTP_INTERNAL_SERVER_ERROR;

        }

        apr_sockaddr_info_get(&local_addr, local_ip, APR_UNSPEC, local_port, 0, r->pool);

        if ((rv = apr_socket_bind(local_sock, local_addr)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01051)
                          "error binding to ftp data socket %pI", local_addr);
            proxy_ftp_cleanup(r, backend);
            return HTTP_INTERNAL_SERVER_ERROR;
        }

        
        if ((rv = apr_socket_listen(local_sock, 2)) != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01052)
                          "error listening to ftp data socket %pI", local_addr);
            proxy_ftp_cleanup(r, backend);
            return HTTP_INTERNAL_SERVER_ERROR;
        }



        if (local_ip && (sscanf(local_ip, "%d.%d.%d.%d", &h3, &h2, &h1, &h0) == 4)) {
            p1 = (local_port >> 8);
            p0 = (local_port & 0xFF);

            rc = proxy_ftp_command(apr_psprintf(p, "PORT %d,%d,%d,%d,%d,%d" CRLF, h3, h2, h1, h0, p1, p0), r, origin, bb, &ftpmessage);
            
            
            
            
            
            
            
            if (rc == -1) {
                return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
            }
            else if (rc == 421) {
                return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
            }
            else if (rc != 200) {
                return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, ftpmessage);
            }

            
            use_port = 1;
        }
        else {

            return ftp_proxyerror(r, backend, HTTP_NOT_IMPLEMENTED, "Connect to IPV6 ftp server using EPRT not supported. Enable EPSV.");
        }
    }


    

    
    len = decodeenc(path);

    if (strchr(path, '/')) { 
       return ftp_proxyerror(r, backend, HTTP_BAD_REQUEST, "Use of /%2f is only allowed at the base directory");
    }

    
    if (len == 0 || (ftp_check_globbingchars(path) && fdconf->ftp_list_on_wildcard)) {
        dirlisting = 1;
    }
    else {
        
        
        
        ftp_set_TYPE(xfer_type, r, origin, bb, &ftpmessage);
        rc = proxy_ftp_command(apr_pstrcat(p, "SIZE ", ftp_escape_globbingchars(p, path, fdconf), CRLF, NULL), r, origin, bb, &ftpmessage);

        if (rc == -1) {
            return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
        }
        else if (rc == 421) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
        }
        else if (rc == 213) {
            int j;
            for (j = 0; apr_isdigit(ftpmessage[j]); j++)
                ;
            ftpmessage[j] = '\0';
            if (ftpmessage[0] != '\0')
                 size = ftpmessage; 
        }
        else if (rc == 550) {    
            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "SIZE shows this is a directory");
            dirlisting = 1;
            rc = proxy_ftp_command(apr_pstrcat(p, "CWD ", ftp_escape_globbingchars(p, path, fdconf), CRLF, NULL), r, origin, bb, &ftpmessage);

            
            
            
            
            
            
            
            
            if (rc == -1) {
                return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
            }
            else if (rc == 421) {
                return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
            }
            else if (rc == 550) {
                return ftp_proxyerror(r, backend, HTTP_NOT_FOUND, ftpmessage);
            }
            else if (rc != 250) {
                return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, ftpmessage);
            }
            path = "";
            len = 0;
        }
    }

    cwd = ftp_get_PWD(r, origin, bb);
    if (cwd != NULL) {
        apr_table_set(r->notes, "Directory-PWD", cwd);
    }

    if (dirlisting) {
        ftp_set_TYPE('A', r, origin, bb, NULL);
        
        
        if (len != 0)
            buf = apr_pstrcat(p, "LIST ", path, CRLF, NULL);
        else if (cwd == NULL || strchr(cwd, '/') != NULL)
            buf = "LIST -lag" CRLF;
        else buf = "LIST" CRLF;
    }
    else {
        
        ftp_set_TYPE(xfer_type, r, origin, bb, &ftpmessage);

        
        rc = proxy_ftp_command(apr_pstrcat(p, "MDTM ", ftp_escape_globbingchars(p, path, fdconf), CRLF, NULL), r, origin, bb, &ftpmessage);
        
        if (rc == 213) {
            struct {
                char YYYY[4+1];
                char MM[2+1];
                char DD[2+1];
                char hh[2+1];
                char mm[2+1];
                char ss[2+1];
            } time_val;
            if (6 == sscanf(ftpmessage, "%4[0-9]%2[0-9]%2[0-9]%2[0-9]%2[0-9]%2[0-9]", time_val.YYYY, time_val.MM, time_val.DD, time_val.hh, time_val.mm, time_val.ss)) {
                struct tm tms;
                memset (&tms, '\0', sizeof tms);
                tms.tm_year = atoi(time_val.YYYY) - 1900;
                tms.tm_mon  = atoi(time_val.MM)   - 1;
                tms.tm_mday = atoi(time_val.DD);
                tms.tm_hour = atoi(time_val.hh);
                tms.tm_min  = atoi(time_val.mm);
                tms.tm_sec  = atoi(time_val.ss);

                mtime = timegm(&tms);
                mtime *= APR_USEC_PER_SEC;

                
                mtime = mktime(&tms);
                mtime += tms.tm_gmtoff;
                mtime *= APR_USEC_PER_SEC;

                mtime = 0L;

            }
        }


        buf = apr_pstrcat(p, "RETR ", ftp_escape_globbingchars(p, path, fdconf), CRLF, NULL);
    }
    rc = proxy_ftp_command(buf, r, origin, bb, &ftpmessage);
    

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    if (rc == -1) {
        return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
    }
    else if (rc == 421) {
        return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
    }
    else if (rc == 550) {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "RETR failed, trying LIST instead");

        
        dirlisting = 1;
        ftp_set_TYPE('A', r, origin, bb, NULL);

        rc = proxy_ftp_command(apr_pstrcat(p, "CWD ", ftp_escape_globbingchars(p, path, fdconf), CRLF, NULL), r, origin, bb, &ftpmessage);

        
        
        
        
        
        
        
        
        if (rc == -1) {
            return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
        }
        else if (rc == 421) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
        }
        else if (rc == 550) {
            return ftp_proxyerror(r, backend, HTTP_NOT_FOUND, ftpmessage);
        }
        else if (rc != 250) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, ftpmessage);
        }

        
        cwd = ftp_get_PWD(r, origin, bb);
        if (cwd != NULL) {
            apr_table_set(r->notes, "Directory-PWD", cwd);
        }

        
        rc = proxy_ftp_command((cwd == NULL || strchr(cwd, '/') != NULL)
                               ? "LIST -lag" CRLF : "LIST" CRLF, r, origin, bb, &ftpmessage);

        
        if (rc == -1) {
            return ftp_proxyerror(r, backend, HTTP_GATEWAY_TIME_OUT, "Error reading from remote server");
        }
        else if (rc == 421) {
            return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, "Error reading from remote server");
        }
    }
    if (rc != 125 && rc != 150 && rc != 226 && rc != 250) {
        return ftp_proxyerror(r, backend, HTTP_BAD_GATEWAY, ftpmessage);
    }

    r->status = HTTP_OK;
    r->status_line = "200 OK";

    apr_rfc822_date(dates, r->request_time);
    apr_table_setn(r->headers_out, "Date", dates);
    apr_table_setn(r->headers_out, "Server", ap_get_server_banner());

    
    if (dirlisting) {
        ap_set_content_type(r, apr_pstrcat(p, "text/html;charset=", fdconf->ftp_directory_charset ? fdconf->ftp_directory_charset :

                                           "ISO-8859-1",  NULL));
    }
    else {
        if (xfer_type != 'A' && size != NULL) {
            
            apr_table_setn(r->headers_out, "Content-Length", size);
            ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "Content-Length set to %s", size);
        }
    }
    if (r->content_type) {
        apr_table_setn(r->headers_out, "Content-Type", r->content_type);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "Content-Type set to %s", r->content_type);
    }


    if (mtime != 0L) {
        char datestr[APR_RFC822_DATE_LEN];
        apr_rfc822_date(datestr, mtime);
        apr_table_set(r->headers_out, "Last-Modified", datestr);
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "Last-Modified set to %s", datestr);
    }


    
    if (dirlisting && r->content_encoding != NULL)
        r->content_encoding = NULL;

    
    if (r->content_encoding != NULL && r->content_encoding[0] != '\0') {
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "Content-Encoding set to %s", r->content_encoding);
        apr_table_setn(r->headers_out, "Content-Encoding", r->content_encoding);
    }

    
    if (use_port) {
        for (;;) {
            rv = apr_socket_accept(&data_sock, local_sock, r->pool);
            if (APR_STATUS_IS_EINTR(rv)) {
                continue;
            }
            else if (rv == APR_SUCCESS) {
                break;
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01053)
                              "failed to accept data connection");
                proxy_ftp_cleanup(r, backend);
                return HTTP_GATEWAY_TIME_OUT;
            }
        }
    }

    
    data = ap_run_create_connection(p, r->server, data_sock, r->connection->id, r->connection->sbh, c->bucket_alloc);
    if (!data) {
        
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01054)
                      "an error occurred creating the transfer connection");
        proxy_ftp_cleanup(r, backend);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    
    ap_proxy_ssl_engine(data, r->per_dir_config, 0);
    
    rc = ap_run_pre_connection(data, data_sock);
    if (rc != OK && rc != DONE) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01055)
                      "pre_connection setup failed (%d)", rc);
        data->aborted = 1;
        proxy_ftp_cleanup(r, backend);
        return rc;
    }

    

    
    r->sent_bodyct = 1;

    if (dirlisting) {
        
        ap_add_output_filter("PROXY_SEND_DIR", NULL, r, r->connection);
    }

    
    if (!r->header_only) {
        apr_bucket *e;
        int finish = FALSE;

        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "start body send");

        
        while (ap_get_brigade(data->input_filters, bb, AP_MODE_READBYTES, APR_BLOCK_READ, conf->io_buffer_size) == APR_SUCCESS) {




            {
                apr_off_t readbytes;
                apr_brigade_length(bb, 0, &readbytes);
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, APLOGNO(01056)
                             "proxy: readbytes: %#x", readbytes);
            }

            
            if (APR_BRIGADE_EMPTY(bb)) {
                break;
            }

            
            if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
                
                ap_flush_conn(data);
                if (data_sock) {
                    apr_socket_close(data_sock);
                }
                data_sock = NULL;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01057)
                              "data connection closed");
                
                finish = TRUE;
            }

            
            if (FALSE == finish) {
                e = apr_bucket_flush_create(c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(bb, e);
            }

            
            if (ap_pass_brigade(r->output_filters, bb) != APR_SUCCESS || c->aborted) {
                
                finish = TRUE;
            }

            
            apr_brigade_cleanup(bb);

            
            if (TRUE == finish) {
                break;
            }
        }
        ap_log_rerror(APLOG_MARK, APLOG_TRACE3, 0, r, "end body send");

    }
    if (data_sock) {
        ap_flush_conn(data);
        apr_socket_close(data_sock);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01058) "data connection closed");
    }

    
    proxy_ftp_command(NULL, r, origin, bb, &ftpmessage);
    apr_brigade_cleanup(bb);

    

    
    proxy_ftp_command("QUIT" CRLF, r, origin, bb, &ftpmessage);
    
    
    
    ap_flush_conn(origin);
    proxy_ftp_cleanup(r, backend);

    apr_brigade_destroy(bb);
    return OK;
}

static void ap_proxy_ftp_register_hook(apr_pool_t *p)
{
    
    proxy_hook_scheme_handler(proxy_ftp_handler, NULL, NULL, APR_HOOK_MIDDLE);
    proxy_hook_canon_handler(proxy_ftp_canon, NULL, NULL, APR_HOOK_MIDDLE);
    
    ap_register_output_filter("PROXY_SEND_DIR", proxy_send_dir_filter, NULL, AP_FTYPE_RESOURCE);
    
    ls_regex = ap_pregcomp(p, LS_REG_PATTERN, AP_REG_EXTENDED);
    ap_assert(ls_regex != NULL);
}

static const command_rec proxy_ftp_cmds[] = {
    AP_INIT_FLAG("ProxyFtpListOnWildcard", set_ftp_list_on_wildcard, NULL, RSRC_CONF|ACCESS_CONF, "Whether wildcard characters in a path cause mod_proxy_ftp to list the files instead of trying to get them. Defaults to on."), AP_INIT_FLAG("ProxyFtpEscapeWildcards", set_ftp_escape_wildcards, NULL, RSRC_CONF|ACCESS_CONF, "Whether the proxy should escape wildcards in paths before sending them to the FTP server.  Defaults to on, but most FTP servers will need it turned off if you need to manage paths that contain wildcard characters."), AP_INIT_TAKE1("ProxyFtpDirCharset", set_ftp_directory_charset, NULL, RSRC_CONF|ACCESS_CONF, "Define the character set for proxied FTP listings"), {NULL}





};


AP_DECLARE_MODULE(proxy_ftp) = {
    STANDARD20_MODULE_STUFF, create_proxy_ftp_dir_config, merge_proxy_ftp_dir_config, NULL, NULL, proxy_ftp_cmds, ap_proxy_ftp_register_hook };






