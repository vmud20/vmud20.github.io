


























































static ap_dbd_t *(*dbd_acquire)(request_rec*) = NULL;
static void (*dbd_prepare)(server_rec*, const char*, const char*) = NULL;
static const char* really_last_key = "rewrite_really_last";













































































































typedef struct {
    const char *datafile;          
    const char *dbmtype;           
    const char *checkfile;         
    const char *cachename;         
    int   type;                    
    apr_file_t *fpin;              
    apr_file_t *fpout;             
    apr_file_t *fperr;             
    char *(*func)(request_rec *,    char *);
    char **argv;                   
    const char *dbdq;              
    const char *checkfile2;        
} rewritemap_entry;


typedef enum {
    CONDPAT_REGEX = 0, CONDPAT_FILE_EXISTS, CONDPAT_FILE_SIZE, CONDPAT_FILE_LINK, CONDPAT_FILE_DIR, CONDPAT_FILE_XBIT, CONDPAT_LU_URL, CONDPAT_LU_FILE, CONDPAT_STR_LT, CONDPAT_STR_LE, CONDPAT_STR_EQ, CONDPAT_STR_GT, CONDPAT_STR_GE, CONDPAT_INT_LT, CONDPAT_INT_LE, CONDPAT_INT_EQ, CONDPAT_INT_GT, CONDPAT_INT_GE, CONDPAT_AP_EXPR } pattern_type;



















typedef struct {
    char           *input;   
    char           *pattern; 
    ap_regex_t     *regexp;  
    ap_expr_info_t *expr;    
    int             flags;   
    pattern_type    ptype;   
    int             pskip;   
} rewritecond_entry;


typedef struct data_item {
    struct data_item *next;
    char *data;
} data_item;

typedef struct {
    apr_array_header_t *rewriteconds;
    char      *pattern;              
    ap_regex_t *regexp;              
    char      *output;               
    int        flags;                
    char      *forced_mimetype;      
    char      *forced_handler;       
    int        forced_responsecode;  
    data_item *env;                  
    data_item *cookie;               
    int        skip;                 
} rewriterule_entry;

typedef struct {
    int           state;              
    int           options;            
    apr_hash_t         *rewritemaps;  
    apr_array_header_t *rewriteconds; 
    apr_array_header_t *rewriterules; 
    server_rec   *server;             
    unsigned int state_set:1;
    unsigned int options_set:1;
} rewrite_server_conf;

typedef struct {
    int           state;              
    int           options;            
    apr_array_header_t *rewriteconds; 
    apr_array_header_t *rewriterules; 
    char         *directory;          
    const char   *baseurl;            
    unsigned int state_set:1;
    unsigned int options_set:1;
    unsigned int baseurl_set:1;
} rewrite_perdir_conf;


typedef struct cache {
    apr_pool_t         *pool;
    apr_hash_t         *maps;

    apr_thread_mutex_t *lock;

} cache;


typedef struct {
    apr_time_t mtime;
    apr_pool_t *pool;
    apr_hash_t *entries;
} cachedmap;


typedef struct backrefinfo {
    const char *source;
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
} backrefinfo;


typedef struct result_list {
    struct result_list *next;
    apr_size_t len;
    const char *string;
} result_list;


typedef struct {
    request_rec *r;
    const char  *uri;
    const char  *vary_this;
    const char  *vary;
    char        *perdir;
    backrefinfo briRR;
    backrefinfo briRC;
} rewrite_ctx;




module AP_MODULE_DECLARE_DATA rewrite_module;


static apr_hash_t *mapfunc_hash;


static cache *cachep;


static int proxy_available;


static apr_global_mutex_t *rewrite_mapr_lock_acquire = NULL;
const char *rewritemap_mutex_type = "rewrite-map";


static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *rewrite_ssl_lookup = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *rewrite_is_https = NULL;
static char *escape_uri(apr_pool_t *p, const char *path);




static void do_rewritelog(request_rec *r, int level, char *perdir, const char *fmt, ...)
        __attribute__((format(printf,4,5)));

static void do_rewritelog(request_rec *r, int level, char *perdir, const char *fmt, ...)
{
    char *logline, *text;
    const char *rhost, *rname;
    int redir;
    request_rec *req;
    va_list ap;

    if (!APLOG_R_IS_LEVEL(r, APLOG_DEBUG + level))
        return;

    rhost = ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_NOLOOKUP, NULL);
    rname = ap_get_remote_logname(r);

    for (redir=0, req=r; req->prev; req = req->prev) {
        ++redir;
    }

    va_start(ap, fmt);
    text = apr_pvsprintf(r->pool, fmt, ap);
    va_end(ap);

    logline = apr_psprintf(r->pool, "%s %s %s [%s/sid#%pp][rid#%pp/%s%s%s] " "%s%s%s%s", rhost ? rhost : "UNKNOWN-HOST", rname ? rname : "-", r->user ? (*r->user ? r->user : "\"\"") : "-", ap_get_server_name(r), (void *)(r->server), (void *)r, r->main ? "subreq" : "initial", redir ? "/redir#" : "", redir ? apr_itoa(r->pool, redir) : "", perdir ? "[perdir " : "", perdir ? perdir : "", perdir ? "] ": "", text);














    AP_REWRITE_LOG((uintptr_t)r, level, r->main ? 0 : 1, (char *)ap_get_server_name(r), logline);

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG + level, 0, r, "%s", logline);

    return;
}






static unsigned is_absolute_uri(char *uri, int *supportsqs)
{
    int dummy, *sqs;

    sqs = (supportsqs ? supportsqs : &dummy);
    *sqs = 0;
    
    if (*uri == '/' || strlen(uri) <= 5) {
        return 0;
    }

    switch (*uri++) {
    case 'a':
    case 'A':
        if (!strncasecmp(uri, "jp://", 5)) {        
          *sqs = 1;
          return 6;
        }
        break;

    case 'b':
    case 'B':
        if (!strncasecmp(uri, "alancer://", 10)) {   
          *sqs = 1;
          return 11;
        }
        break;

    case 'f':
    case 'F':
        if (!strncasecmp(uri, "tp://", 5)) {        
            return 6;
        }
        if (!strncasecmp(uri, "cgi://", 6)) {       
            *sqs = 1;
            return 7;
        }
        break;

    case 'g':
    case 'G':
        if (!strncasecmp(uri, "opher://", 8)) {     
            return 9;
        }
        break;

    case 'h':
    case 'H':
        if (!strncasecmp(uri, "ttp://", 6)) {       
            *sqs = 1;
            return 7;
        }
        else if (!strncasecmp(uri, "ttps://", 7)) { 
            
            return 8;
        }
        break;

    case 'l':
    case 'L':
        if (!strncasecmp(uri, "dap://", 6)) {       
            return 7;
        }
        break;

    case 'm':
    case 'M':
        if (!strncasecmp(uri, "ailto:", 6)) {       
            *sqs = 1;
            return 7;
        }
        break;

    case 'n':
    case 'N':
        if (!strncasecmp(uri, "ews:", 4)) {         
            return 5;
        }
        else if (!strncasecmp(uri, "ntp://", 6)) {  
            return 7;
        }
        break;

    case 's':
    case 'S':
        if (!strncasecmp(uri, "cgi://", 6)) {       
            *sqs = 1;
            return 7;
        }
        break;
    }

    return 0;
}

static const char c2x_table[] = "0123456789abcdef";

static APR_INLINE unsigned char *c2x(unsigned what, unsigned char prefix, unsigned char *where)
{

    what = apr_xlate_conv_byte(ap_hdrs_to_ascii, (unsigned char)what);

    *where++ = prefix;
    *where++ = c2x_table[what >> 4];
    *where++ = c2x_table[what & 0xf];
    return where;
}


static char *escape_uri(apr_pool_t *p, const char *path) {
    char *copy = apr_palloc(p, 3 * strlen(path) + 3);
    const unsigned char *s = (const unsigned char *)path;
    unsigned char *d = (unsigned char *)copy;
    unsigned c;

    while ((c = *s)) {
        if (apr_isalnum(c) || c == '_') {
            *d++ = c;
        }
        else if (c == ' ') {
            *d++ = '+';
        }
        else {
            d = c2x(c, '%', d);
        }
        ++s;
    }
    *d = '\0';
    return copy;
}


static char *escape_absolute_uri(apr_pool_t *p, char *uri, unsigned scheme)
{
    char *cp;

    
    if (!scheme || strlen(uri) < scheme) {
        return NULL;
    }

    cp = uri + scheme;

    
    if (cp[-1] == '/') {
        
        while (*cp && *cp != '/') {
            ++cp;
        }

        
        if (!*cp || !*++cp) {
            return apr_pstrdup(p, uri);
        }

        
        scheme = cp - uri;

        
        if (!strncasecmp(uri, "ldap", 4)) {
            char *token[5];
            int c = 0;

            token[0] = cp = apr_pstrdup(p, cp);
            while (*cp && c < 4) {
                if (*cp == '?') {
                    token[++c] = cp + 1;
                    *cp = '\0';
                }
                ++cp;
            }

            return apr_pstrcat(p, apr_pstrndup(p, uri, scheme), ap_escape_uri(p, token[0]), (c >= 1) ? "?" : NULL, (c >= 1) ? ap_escape_uri(p, token[1]) : NULL, (c >= 2) ? "?" : NULL, (c >= 2) ? ap_escape_uri(p, token[2]) : NULL, (c >= 3) ? "?" : NULL, (c >= 3) ? ap_escape_uri(p, token[3]) : NULL, (c >= 4) ? "?" : NULL, (c >= 4) ? ap_escape_uri(p, token[4]) : NULL, NULL);









        }
    }

    
    return apr_pstrcat(p, apr_pstrndup(p, uri, scheme), ap_escape_uri(p, cp), NULL);
}


static void splitout_queryargs(request_rec *r, int qsappend, int qsdiscard)
{
    char *q;
    int split;

    
    if (is_absolute_uri(r->filename, &split)
        && !split) {
        r->args = NULL; 
        return;
    }

    if ( qsdiscard ) {
        r->args = NULL; 
        rewritelog((r, 2, NULL, "discarding query string"));
    }

    q = ap_strchr(r->filename, '?');
    if (q != NULL) {
        char *olduri;
        apr_size_t len;

        olduri = apr_pstrdup(r->pool, r->filename);
        *q++ = '\0';
        if (qsappend) {
            r->args = apr_pstrcat(r->pool, q, "&", r->args, NULL);
        }
        else {
            r->args = apr_pstrdup(r->pool, q);
        }

        len = strlen(r->args);
        if (!len) {
            r->args = NULL;
        }
        else if (r->args[len-1] == '&') {
            r->args[len-1] = '\0';
        }

        rewritelog((r, 3, NULL, "split uri=%s -> uri=%s, args=%s", olduri, r->filename, r->args ? r->args : "<none>"));
    }

    return;
}


static void reduce_uri(request_rec *r)
{
    char *cp;
    apr_size_t l;

    cp = (char *)ap_http_scheme(r);
    l  = strlen(cp);
    if (   strlen(r->filename) > l+3 && strncasecmp(r->filename, cp, l) == 0 && r->filename[l]   == ':' && r->filename[l+1] == '/' && r->filename[l+2] == '/' ) {




        unsigned short port;
        char *portp, *host, *url, *scratch;

        scratch = apr_pstrdup(r->pool, r->filename); 

        
        cp = host = scratch + l + 3;    
        while (*cp && *cp != '/' && *cp != ':') {
            ++cp;
        }

        if (*cp == ':') {      
            *cp++ = '\0';
            portp = cp;
            while (*cp && *cp != '/') {
                ++cp;
            }
            *cp = '\0';

            port = atoi(portp);
            url = r->filename + (cp - scratch);
            if (!*url) {
                url = "/";
            }
        }
        else if (*cp == '/') { 
            *cp = '\0';

            port = ap_default_port(r);
            url = r->filename + (cp - scratch);
        }
        else {
            port = ap_default_port(r);
            url = "/";
        }

        
        if (ap_matches_request_vhost(r, host, port)) {
            rewritelog((r, 3, NULL, "reduce %s -> %s", r->filename, url));
            r->filename = apr_pstrdup(r->pool, url);
        }
    }

    return;
}


static void fully_qualify_uri(request_rec *r)
{
    if (r->method_number == M_CONNECT) {
        return;
    }
    else if (!is_absolute_uri(r->filename, NULL)) {
        const char *thisserver;
        char *thisport;
        int port;

        thisserver = ap_get_server_name_for_url(r);
        port = ap_get_server_port(r);
        thisport = ap_is_default_port(port, r)
                   ? "" : apr_psprintf(r->pool, ":%u", port);

        r->filename = apr_psprintf(r->pool, "%s://%s%s%s%s", ap_http_scheme(r), thisserver, thisport, (*r->filename == '/') ? "" : "/", r->filename);


    }

    return;
}


static int prefix_stat(const char *path, apr_pool_t *pool)
{
    const char *curpath = path;
    const char *root;
    const char *slash;
    char *statpath;
    apr_status_t rv;

    rv = apr_filepath_root(&root, &curpath, APR_FILEPATH_TRUENAME, pool);

    if (rv != APR_SUCCESS) {
        return 0;
    }

    
    if ((slash = ap_strchr_c(curpath, '/')) != NULL) {
        rv = apr_filepath_merge(&statpath, root, apr_pstrndup(pool, curpath, (apr_size_t)(slash - curpath)), APR_FILEPATH_NOTABOVEROOT | APR_FILEPATH_NOTRELATIVE, pool);



    }
    else {
        rv = apr_filepath_merge(&statpath, root, curpath, APR_FILEPATH_NOTABOVEROOT | APR_FILEPATH_NOTRELATIVE, pool);

    }

    if (rv == APR_SUCCESS) {
        apr_finfo_t sb;

        if (apr_stat(&sb, statpath, APR_FINFO_MIN, pool) == APR_SUCCESS) {
            return 1;
        }
    }

    return 0;
}


static char *subst_prefix_path(request_rec *r, char *input, char *match, const char *subst)
{
    apr_size_t len = strlen(match);

    if (len && match[len - 1] == '/') {
        --len;
    }

    if (!strncmp(input, match, len) && input[len++] == '/') {
        apr_size_t slen, outlen;
        char *output;

        rewritelog((r, 5, NULL, "strip matching prefix: %s -> %s", input, input+len));

        slen = strlen(subst);
        if (slen && subst[slen - 1] != '/') {
            ++slen;
        }

        outlen = strlen(input) + slen - len;
        output = apr_palloc(r->pool, outlen + 1); 

        memcpy(output, subst, slen);
        if (slen && !output[slen-1]) {
            output[slen-1] = '/';
        }
        memcpy(output+slen, input+len, outlen - slen);
        output[outlen] = '\0';

        rewritelog((r, 4, NULL, "add subst prefix: %s -> %s", input+len, output));

        return output;
    }

    
    return input;
}




static void set_cache_value(const char *name, apr_time_t t, char *key, char *val)
{
    cachedmap *map;

    if (cachep) {

        apr_thread_mutex_lock(cachep->lock);

        map = apr_hash_get(cachep->maps, name, APR_HASH_KEY_STRING);

        if (!map) {
            apr_pool_t *p;

            if (apr_pool_create(&p, cachep->pool) != APR_SUCCESS) {

                apr_thread_mutex_unlock(cachep->lock);

                return;
            }

            map = apr_palloc(cachep->pool, sizeof(cachedmap));
            map->pool = p;
            map->entries = apr_hash_make(map->pool);
            map->mtime = t;

            apr_hash_set(cachep->maps, name, APR_HASH_KEY_STRING, map);
        }
        else if (map->mtime != t) {
            apr_pool_clear(map->pool);
            map->entries = apr_hash_make(map->pool);
            map->mtime = t;
        }

        
        apr_hash_set(map->entries, apr_pstrdup(map->pool, key), APR_HASH_KEY_STRING, apr_pstrdup(map->pool, val));



        apr_thread_mutex_unlock(cachep->lock);

    }

    return;
}

static char *get_cache_value(const char *name, apr_time_t t, char *key, apr_pool_t *p)
{
    cachedmap *map;
    char *val = NULL;

    if (cachep) {

        apr_thread_mutex_lock(cachep->lock);

        map = apr_hash_get(cachep->maps, name, APR_HASH_KEY_STRING);

        if (map) {
            
            if (map->mtime != t) {
                apr_pool_clear(map->pool);
                map->entries = apr_hash_make(map->pool);
                map->mtime = t;
            }
            else {
                val = apr_hash_get(map->entries, key, APR_HASH_KEY_STRING);
                if (val) {
                    
                    val = apr_pstrdup(p, val);
                }
            }
        }


        apr_thread_mutex_unlock(cachep->lock);

    }

    return val;
}

static int init_cache(apr_pool_t *p)
{
    cachep = apr_palloc(p, sizeof(cache));
    if (apr_pool_create(&cachep->pool, p) != APR_SUCCESS) {
        cachep = NULL; 
        return 0;
    }

    cachep->maps = apr_hash_make(cachep->pool);

    (void)apr_thread_mutex_create(&(cachep->lock), APR_THREAD_MUTEX_DEFAULT, p);


    return 1;
}






static char *rewrite_mapfunc_toupper(request_rec *r, char *key)
{
    ap_str_toupper(key);

    return key;
}

static char *rewrite_mapfunc_tolower(request_rec *r, char *key)
{
    ap_str_tolower(key);

    return key;
}

static char *rewrite_mapfunc_escape(request_rec *r, char *key)
{
    return ap_escape_uri(r->pool, key);
}

static char *rewrite_mapfunc_unescape(request_rec *r, char *key)
{
    ap_unescape_url(key);

    return key;
}

static char *select_random_value_part(request_rec *r, char *value)
{
    char *p = value;
    unsigned n = 1;

    
    while ((p = ap_strchr(p, '|')) != NULL) {
        ++n;
        ++p;
    }

    if (n > 1) {
        n = ap_random_pick(1, n);

        
        while (--n && (value = ap_strchr(value, '|')) != NULL) {
            ++value;
        }

        if (value) { 
            p = ap_strchr(value, '|');
            if (p) {
                *p = '\0';
            }
        }
    }

    return value;
}


static void rewrite_child_errfn(apr_pool_t *p, apr_status_t err, const char *desc)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, err, NULL, "%s", desc);
}

static apr_status_t rewritemap_program_child(apr_pool_t *p, const char *progname, char **argv, apr_file_t **fpout, apr_file_t **fpin)


{
    apr_status_t rc;
    apr_procattr_t *procattr;
    apr_proc_t *procnew;

    if (   APR_SUCCESS == (rc=apr_procattr_create(&procattr, p))
        && APR_SUCCESS == (rc=apr_procattr_io_set(procattr, APR_FULL_BLOCK, APR_FULL_BLOCK, APR_NO_PIPE))
        && APR_SUCCESS == (rc=apr_procattr_dir_set(procattr, ap_make_dirstr_parent(p, argv[0])))
        && APR_SUCCESS == (rc=apr_procattr_cmdtype_set(procattr, APR_PROGRAM))
        && APR_SUCCESS == (rc=apr_procattr_child_errfn_set(procattr, rewrite_child_errfn))
        && APR_SUCCESS == (rc=apr_procattr_error_check_set(procattr, 1))) {

        procnew = apr_pcalloc(p, sizeof(*procnew));
        rc = apr_proc_create(procnew, argv[0], (const char **)argv, NULL, procattr, p);

        if (rc == APR_SUCCESS) {
            apr_pool_note_subprocess(p, procnew, APR_KILL_AFTER_TIMEOUT);

            if (fpin) {
                (*fpin) = procnew->in;
            }

            if (fpout) {
                (*fpout) = procnew->out;
            }
        }
    }

    return (rc);
}

static apr_status_t run_rewritemap_programs(server_rec *s, apr_pool_t *p)
{
    rewrite_server_conf *conf;
    apr_hash_index_t *hi;
    apr_status_t rc;

    conf = ap_get_module_config(s->module_config, &rewrite_module);

    
    if (conf->state == ENGINE_DISABLED) {
        return APR_SUCCESS;
    }

    for (hi = apr_hash_first(p, conf->rewritemaps); hi; hi = apr_hash_next(hi)){
        apr_file_t *fpin = NULL;
        apr_file_t *fpout = NULL;
        rewritemap_entry *map;
        void *val;

        apr_hash_this(hi, NULL, NULL, &val);
        map = val;

        if (map->type != MAPTYPE_PRG) {
            continue;
        }
        if (!(map->argv[0]) || !*(map->argv[0]) || map->fpin || map->fpout) {
            continue;
        }

        rc = rewritemap_program_child(p, map->argv[0], map->argv, &fpout, &fpin);
        if (rc != APR_SUCCESS || fpin == NULL || fpout == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, rc, s, "mod_rewrite: could not start RewriteMap " "program %s", map->checkfile);

            return rc;
        }
        map->fpin  = fpin;
        map->fpout = fpout;
    }

    return APR_SUCCESS;
}




static char *lookup_map_txtfile(request_rec *r, const char *file, char *key)
{
    apr_file_t *fp = NULL;
    char line[REWRITE_MAX_TXT_MAP_LINE + 1]; 
    char *value, *keylast;
    apr_status_t rv;

    if ((rv = apr_file_open(&fp, file, APR_READ|APR_BUFFERED, APR_OS_DEFAULT, r->pool)) != APR_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "mod_rewrite: can't open text RewriteMap file %s", file);
        return NULL;
    }

    keylast = key + strlen(key);
    value = NULL;
    while (apr_file_gets(line, sizeof(line), fp) == APR_SUCCESS) {
        char *p, *c;

        
        if (*line == '#' || apr_isspace(*line)) {
            continue;
        }

        p = line;
        c = key;
        while (c < keylast && *p == *c && !apr_isspace(*p)) {
            ++p;
            ++c;
        }

        
        if (c != keylast || !apr_isspace(*p)) {
            continue;
        }

        
        while (*p && apr_isspace(*p)) {
            ++p;
        }

        
        if (!*p) {
            continue;
        }

        
        c = p;
        while (*p && !apr_isspace(*p)) {
            ++p;
        }
        value = apr_pstrmemdup(r->pool, c, p - c);
        break;
    }
    apr_file_close(fp);

    return value;
}

static char *lookup_map_dbmfile(request_rec *r, const char *file, const char *dbmtype, char *key)
{
    apr_dbm_t *dbmfp = NULL;
    apr_datum_t dbmkey;
    apr_datum_t dbmval;
    char *value;
    apr_status_t rv;

    if ((rv = apr_dbm_open_ex(&dbmfp, dbmtype, file, APR_DBM_READONLY, APR_OS_DEFAULT, r->pool)) != APR_SUCCESS)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "mod_rewrite: can't open DBM RewriteMap %s", file);
        return NULL;
    }

    dbmkey.dptr  = key;
    dbmkey.dsize = strlen(key);

    if (apr_dbm_fetch(dbmfp, dbmkey, &dbmval) == APR_SUCCESS && dbmval.dptr) {
        value = apr_pstrmemdup(r->pool, dbmval.dptr, dbmval.dsize);
    }
    else {
        value = NULL;
    }

    apr_dbm_close(dbmfp);

    return value;
}
static char *lookup_map_dbd(request_rec *r, char *key, const char *label)
{
    apr_status_t rv;
    apr_dbd_prepared_t *stmt;
    const char *errmsg;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t *row = NULL;
    const char *ret = NULL;
    int n = 0;
    ap_dbd_t *db = dbd_acquire(r);

    stmt = apr_hash_get(db->prepared, label, APR_HASH_KEY_STRING);

    rv = apr_dbd_pvselect(db->driver, r->pool, db->handle, &res, stmt, 0, key, NULL);
    if (rv != 0) {
        errmsg = apr_dbd_error(db->driver, db->handle, rv);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "rewritemap: error %s querying for %s", errmsg, key);
        return NULL;
    }
    while ((rv = apr_dbd_get_row(db->driver, r->pool, res, &row, -1)) == 0) {
        ++n;
        if (ret == NULL) {
            ret = apr_dbd_get_entry(db->driver, row, 0);
        }
        else {
            
            if ((double)rand() < (double)RAND_MAX/(double)n) {
                ret = apr_dbd_get_entry(db->driver, row, 0);
            }
        }
    }
    if (rv != -1) {
        errmsg = apr_dbd_error(db->driver, db->handle, rv);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "rewritemap: error %s looking up %s", errmsg, key);
    }
    switch (n) {
    case 0:
        return NULL;
    case 1:
        return apr_pstrdup(r->pool, ret);
    default:
        
        rewritelog((r, 3, NULL, "Multiple values found for %s", key));
        return apr_pstrdup(r->pool, ret);
    }
}

static char *lookup_map_program(request_rec *r, apr_file_t *fpin, apr_file_t *fpout, char *key)
{
    char *buf;
    char c;
    apr_size_t i, nbytes, combined_len = 0;
    apr_status_t rv;
    const char *eol = APR_EOL_STR;
    apr_size_t eolc = 0;
    int found_nl = 0;
    result_list *buflist = NULL, *curbuf = NULL;


    struct iovec iova[2];
    apr_size_t niov;


    
    if (fpin == NULL || fpout == NULL || ap_strchr(key, '\n')) {
        return NULL;
    }

    
    if (rewrite_mapr_lock_acquire) {
        rv = apr_global_mutex_lock(rewrite_mapr_lock_acquire);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "apr_global_mutex_lock(rewrite_mapr_lock_acquire) " "failed");

            return NULL; 
        }
    }

    

    nbytes = strlen(key);
    apr_file_write(fpin, key, &nbytes);
    nbytes = 1;
    apr_file_write(fpin, "\n", &nbytes);

    iova[0].iov_base = key;
    iova[0].iov_len = strlen(key);
    iova[1].iov_base = "\n";
    iova[1].iov_len = 1;

    niov = 2;
    apr_file_writev(fpin, iova, niov, &nbytes);


    buf = apr_palloc(r->pool, REWRITE_PRG_MAP_BUF + 1);

    
    nbytes = 1;
    apr_file_read(fpout, &c, &nbytes);
    do {
        i = 0;
        while (nbytes == 1 && (i < REWRITE_PRG_MAP_BUF)) {
            if (c == eol[eolc]) {
                if (!eol[++eolc]) {
                    
                    --eolc;
                    if (i < eolc) {
                        curbuf->len -= eolc-i;
                        i = 0;
                    }
                    else {
                        i -= eolc;
                    }
                    ++found_nl;
                    break;
                }
            }

            
            else if (eolc) {
                eolc = 0;
            }

            
            else if (c == '\n') {
                ++found_nl;
                break;
            }

            buf[i++] = c;
            apr_file_read(fpout, &c, &nbytes);
        }

        
        if (buflist || (nbytes == 1 && !found_nl)) {
            if (!buflist) {
                curbuf = buflist = apr_palloc(r->pool, sizeof(*buflist));
            }
            else if (i) {
                curbuf->next = apr_palloc(r->pool, sizeof(*buflist));
                curbuf = curbuf->next;

            }
            curbuf->next = NULL;

            if (i) {
                curbuf->string = buf;
                curbuf->len = i;
                combined_len += i;
                buf = apr_palloc(r->pool, REWRITE_PRG_MAP_BUF);
            }

            if (nbytes == 1 && !found_nl) {
                continue;
            }
        }

        break;
    } while (1);

    
    if (buflist) {
        char *p;

        p = buf = apr_palloc(r->pool, combined_len + 1); 
        while (buflist) {
            if (buflist->len) {
                memcpy(p, buflist->string, buflist->len);
                p += buflist->len;
            }
            buflist = buflist->next;
        }
        *p = '\0';
        i = combined_len;
    }
    else {
        buf[i] = '\0';
    }

    
    if (rewrite_mapr_lock_acquire) {
        rv = apr_global_mutex_unlock(rewrite_mapr_lock_acquire);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "apr_global_mutex_unlock(rewrite_mapr_lock_acquire) " "failed");

            return NULL; 
        }
    }

    
    if (i == 4 && !strcasecmp(buf, "NULL")) {
        return NULL;
    }

    return buf;
}


static char *lookup_map(request_rec *r, char *name, char *key)
{
    rewrite_server_conf *conf;
    rewritemap_entry *s;
    char *value;
    apr_finfo_t st;
    apr_status_t rv;

    
    conf = ap_get_module_config(r->server->module_config, &rewrite_module);
    s = apr_hash_get(conf->rewritemaps, name, APR_HASH_KEY_STRING);

    
    if (!s) {
        return NULL;
    }

    switch (s->type) {
    
    case MAPTYPE_RND:
    case MAPTYPE_TXT:
        rv = apr_stat(&st, s->checkfile, APR_FINFO_MIN, r->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "mod_rewrite: can't access text RewriteMap file %s", s->checkfile);

            return NULL;
        }

        value = get_cache_value(s->cachename, st.mtime, key, r->pool);
        if (!value) {
            rewritelog((r, 6, NULL, "cache lookup FAILED, forcing new map lookup"));

            value = lookup_map_txtfile(r, s->datafile, key);
            if (!value) {
                rewritelog((r, 5, NULL, "map lookup FAILED: map=%s[txt] key=%s", name, key));
                set_cache_value(s->cachename, st.mtime, key, "");
                return NULL;
            }

            rewritelog((r, 5, NULL,"map lookup OK: map=%s[txt] key=%s -> val=%s", name, key, value));
            set_cache_value(s->cachename, st.mtime, key, value);
        }
        else {
            rewritelog((r,5,NULL,"cache lookup OK: map=%s[txt] key=%s -> val=%s", name, key, value));
        }

        if (s->type == MAPTYPE_RND && *value) {
            value = select_random_value_part(r, value);
            rewritelog((r, 5, NULL, "randomly chosen the subvalue `%s'",value));
        }

        return *value ? value : NULL;

    
    case MAPTYPE_DBM:
        rv = apr_stat(&st, s->checkfile, APR_FINFO_MIN, r->pool);
        if (rv != APR_SUCCESS) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "mod_rewrite: can't access DBM RewriteMap file %s", s->checkfile);

        }
        else if(s->checkfile2 != NULL) {
            apr_finfo_t st2;

            rv = apr_stat(&st2, s->checkfile2, APR_FINFO_MIN, r->pool);
            if (rv != APR_SUCCESS) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "mod_rewrite: can't access DBM RewriteMap " "file %s", s->checkfile2);

            }
            else if(st2.mtime > st.mtime) {
                st.mtime = st2.mtime;
            }
        }
        if(rv != APR_SUCCESS) {
            return NULL;
        }

        value = get_cache_value(s->cachename, st.mtime, key, r->pool);
        if (!value) {
            rewritelog((r, 6, NULL, "cache lookup FAILED, forcing new map lookup"));

            value = lookup_map_dbmfile(r, s->datafile, s->dbmtype, key);
            if (!value) {
                rewritelog((r, 5, NULL, "map lookup FAILED: map=%s[dbm] key=%s", name, key));
                set_cache_value(s->cachename, st.mtime, key, "");
                return NULL;
            }

            rewritelog((r, 5, NULL, "map lookup OK: map=%s[dbm] key=%s -> " "val=%s", name, key, value));

            set_cache_value(s->cachename, st.mtime, key, value);
            return value;
        }

        rewritelog((r, 5, NULL, "cache lookup OK: map=%s[dbm] key=%s -> val=%s", name, key, value));
        return *value ? value : NULL;

    
    case MAPTYPE_DBD:
        value = lookup_map_dbd(r, key, s->dbdq);
        if (!value) {
            rewritelog((r, 5, NULL, "SQL map lookup FAILED: map %s key=%s", name, key));
            return NULL;
        }

        rewritelog((r, 5, NULL, "SQL map lookup OK: map %s key=%s, val=%s", name, key, value));

        return value;

    
    case MAPTYPE_DBD_CACHE:
        value = get_cache_value(s->cachename, 0, key, r->pool);
        if (!value) {
            rewritelog((r, 6, NULL, "cache lookup FAILED, forcing new map lookup"));

            value = lookup_map_dbd(r, key, s->dbdq);
            if (!value) {
                rewritelog((r, 5, NULL, "SQL map lookup FAILED: map %s key=%s", name, key));
                set_cache_value(s->cachename, 0, key, "");
                return NULL;
            }

            rewritelog((r, 5, NULL, "SQL map lookup OK: map %s key=%s, val=%s", name, key, value));

            set_cache_value(s->cachename, 0, key, value);
            return value;
        }

        rewritelog((r, 5, NULL, "cache lookup OK: map=%s[SQL] key=%s, val=%s", name, key, value));
        return *value ? value : NULL;

    
    case MAPTYPE_PRG:
        value = lookup_map_program(r, s->fpin, s->fpout, key);
        if (!value) {
            rewritelog((r, 5,NULL,"map lookup FAILED: map=%s key=%s", name, key));
            return NULL;
        }

        rewritelog((r, 5, NULL, "map lookup OK: map=%s key=%s -> val=%s", name, key, value));
        return value;

    
    case MAPTYPE_INT:
        value = s->func(r, key);
        if (!value) {
            rewritelog((r, 5,NULL,"map lookup FAILED: map=%s key=%s", name, key));
            return NULL;
        }

        rewritelog((r, 5, NULL, "map lookup OK: map=%s key=%s -> val=%s", name, key, value));
        return value;
    }

    return NULL;
}


static const char *lookup_header(const char *name, rewrite_ctx *ctx)
{
    const char *val = apr_table_get(ctx->r->headers_in, name);

    if (val) {
        ctx->vary_this = ctx->vary_this ? apr_pstrcat(ctx->r->pool, ctx->vary_this, ", ", name, NULL)

                         : apr_pstrdup(ctx->r->pool, name);
    }

    return val;
}


static APR_INLINE const char *la_u(rewrite_ctx *ctx)
{
    rewrite_perdir_conf *conf;

    if (*ctx->uri == '/') {
        return ctx->uri;
    }

    conf = ap_get_module_config(ctx->r->per_dir_config, &rewrite_module);

    return apr_pstrcat(ctx->r->pool, conf->baseurl ? conf->baseurl : conf->directory, ctx->uri, NULL);

}


static char *lookup_variable(char *var, rewrite_ctx *ctx)
{
    const char *result;
    request_rec *r = ctx->r;
    apr_size_t varlen = strlen(var);

    
    if (varlen < 4) {
        return "";
    }

    result = NULL;

    
    if (var[3] == ':') {
        if (var[4] && !strncasecmp(var, "ENV", 3)) {
            var += 4;
            result = apr_table_get(r->notes, var);

            if (!result) {
                result = apr_table_get(r->subprocess_env, var);
            }
            if (!result) {
                result = getenv(var);
            }
        }
        else if (var[4] && !strncasecmp(var, "SSL", 3) && rewrite_ssl_lookup) {
            result = rewrite_ssl_lookup(r->pool, r->server, r->connection, r, var + 4);
        }
    }
    else if (var[4] == ':') {
        if (var[5]) {
            request_rec *rr;
            const char *path;

            if (!strncasecmp(var, "HTTP", 4)) {
                result = lookup_header(var+5, ctx);
            }
            else if (!strncasecmp(var, "LA-U", 4)) {
                if (ctx->uri && subreq_ok(r)) {
                    path = ctx->perdir ? la_u(ctx) : ctx->uri;
                    rr = ap_sub_req_lookup_uri(path, r, NULL);
                    ctx->r = rr;
                    result = apr_pstrdup(r->pool, lookup_variable(var+5, ctx));
                    ctx->r = r;
                    ap_destroy_sub_req(rr);

                    rewritelog((r, 5, ctx->perdir, "lookahead: path=%s var=%s " "-> val=%s", path, var+5, result));

                    return (char *)result;
                }
            }
            else if (!strncasecmp(var, "LA-F", 4)) {
                if (ctx->uri && subreq_ok(r)) {
                    path = ctx->uri;
                    if (ctx->perdir && *path == '/') {
                        
                        rr = ap_sub_req_lookup_uri(path, r, NULL);
                    }
                    else {
                        if (ctx->perdir) {
                            rewrite_perdir_conf *conf;

                            conf = ap_get_module_config(r->per_dir_config, &rewrite_module);

                            path = apr_pstrcat(r->pool, conf->directory, path, NULL);
                        }

                        rr = ap_sub_req_lookup_file(path, r, NULL);
                    }

                    ctx->r = rr;
                    result = apr_pstrdup(r->pool, lookup_variable(var+5, ctx));
                    ctx->r = r;
                    ap_destroy_sub_req(rr);

                    rewritelog((r, 5, ctx->perdir, "lookahead: path=%s var=%s " "-> val=%s", path, var+5, result));

                    return (char *)result;
                }
            }
        }
    }

    
    else {
        apr_time_exp_t tm;

        
        ap_str_toupper(var);

        switch (varlen) {
        case  4:
            if (!strcmp(var, "TIME")) {
                apr_time_exp_lt(&tm, apr_time_now());
                result = apr_psprintf(r->pool, "%04d%02d%02d%02d%02d%02d", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

                rewritelog((r, 1, ctx->perdir, "RESULT='%s'", result));
                return (char *)result;
            }
            else if (!strcmp(var, "IPV6")) {
                int flag = FALSE;

                apr_sockaddr_t *addr = r->client_addr;
                flag = (addr->family == AF_INET6 && !IN6_IS_ADDR_V4MAPPED((struct in6_addr *)addr->ipaddr_ptr));
                rewritelog((r, 1, ctx->perdir, "IPV6='%s'", flag ? "on" : "off"));

                rewritelog((r, 1, ctx->perdir, "IPV6='off' (IPv6 is not enabled)"));

                result = (flag ? "on" : "off");
            }
            break;

        case  5:
            if (!strcmp(var, "HTTPS")) {
                int flag = rewrite_is_https && rewrite_is_https(r->connection);
                return apr_pstrdup(r->pool, flag ? "on" : "off");
            }
            break;

        case  8:
            switch (var[6]) {
            case 'A':
                if (!strcmp(var, "TIME_DAY")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_mday);
                }
                break;

            case 'E':
                if (!strcmp(var, "TIME_SEC")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_sec);
                }
                break;

            case 'I':
                if (!strcmp(var, "TIME_MIN")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_min);
                }
                break;

            case 'O':
                if (!strcmp(var, "TIME_MON")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_mon+1);
                }
                break;
            }
            break;

        case  9:
            switch (var[7]) {
            case 'A':
                if (var[8] == 'Y' && !strcmp(var, "TIME_WDAY")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%d", tm.tm_wday);
                }
                else if (!strcmp(var, "TIME_YEAR")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%04d", tm.tm_year+1900);
                }
                break;

            case 'E':
                if (!strcmp(var, "IS_SUBREQ")) {
                    result = (r->main ? "true" : "false");
                }
                break;

            case 'F':
                if (!strcmp(var, "PATH_INFO")) {
                    result = r->path_info;
                }
                break;

            case 'P':
                if (!strcmp(var, "AUTH_TYPE")) {
                    result = r->ap_auth_type;
                }
                break;

            case 'S':
                if (!strcmp(var, "HTTP_HOST")) {
                    result = lookup_header("Host", ctx);
                }
                break;

            case 'U':
                if (!strcmp(var, "TIME_HOUR")) {
                    apr_time_exp_lt(&tm, apr_time_now());
                    return apr_psprintf(r->pool, "%02d", tm.tm_hour);
                }
                break;
            }
            break;

        case 11:
            switch (var[8]) {
            case 'A':
                if (!strcmp(var, "SERVER_NAME")) {
                    result = ap_get_server_name_for_url(r);
                }
                break;

            case 'D':
                if (*var == 'R' && !strcmp(var, "REMOTE_ADDR")) {
                    result = r->client_ip;
                }
                else if (!strcmp(var, "SERVER_ADDR")) {
                    result = r->connection->local_ip;
                }
                break;

            case 'E':
                if (*var == 'H' && !strcmp(var, "HTTP_ACCEPT")) {
                    result = lookup_header("Accept", ctx);
                }
                else if (!strcmp(var, "THE_REQUEST")) {
                    result = r->the_request;
                }
                break;

            case 'I':
                if (!strcmp(var, "API_VERSION")) {
                    return apr_psprintf(r->pool, "%d:%d", MODULE_MAGIC_NUMBER_MAJOR, MODULE_MAGIC_NUMBER_MINOR);

                }
                break;

            case 'K':
                if (!strcmp(var, "HTTP_COOKIE")) {
                    result = lookup_header("Cookie", ctx);
                }
                break;

            case 'O':
                if (*var == 'S' && !strcmp(var, "SERVER_PORT")) {
                    return apr_psprintf(r->pool, "%u", ap_get_server_port(r));
                }
                else if (var[7] == 'H' && !strcmp(var, "REMOTE_HOST")) {
                    result = ap_get_remote_host(r->connection,r->per_dir_config, REMOTE_NAME, NULL);
                }
                else if (!strcmp(var, "REMOTE_PORT")) {
                    return apr_itoa(r->pool, r->client_addr->port);
                }
                break;

            case 'S':
                if (*var == 'R' && !strcmp(var, "REMOTE_USER")) {
                    result = r->user;
                }
                else if (!strcmp(var, "SCRIPT_USER")) {
                    result = "<unknown>";
                    if (r->finfo.valid & APR_FINFO_USER) {
                        apr_uid_name_get((char **)&result, r->finfo.user, r->pool);
                    }
                }
                break;

            case 'U':
                if (!strcmp(var, "REQUEST_URI")) {
                    result = r->uri;
                }
                break;
            }
            break;

        case 12:
            switch (var[3]) {
            case 'I':
                if (!strcmp(var, "SCRIPT_GROUP")) {
                    result = "<unknown>";
                    if (r->finfo.valid & APR_FINFO_GROUP) {
                        apr_gid_name_get((char **)&result, r->finfo.group, r->pool);
                    }
                }
                break;

            case 'O':
                if (!strcmp(var, "REMOTE_IDENT")) {
                    result = ap_get_remote_logname(r);
                }
                break;

            case 'P':
                if (!strcmp(var, "HTTP_REFERER")) {
                    result = lookup_header("Referer", ctx);
                }
                break;

            case 'R':
                if (!strcmp(var, "QUERY_STRING")) {
                    result = r->args;
                }
                break;

            case 'V':
                if (!strcmp(var, "SERVER_ADMIN")) {
                    result = r->server->server_admin;
                }
                break;
            }
            break;

        case 13:
            if (!strcmp(var, "DOCUMENT_ROOT")) {
                result = ap_document_root(r);
            }
            break;

        case 14:
            if (*var == 'H' && !strcmp(var, "HTTP_FORWARDED")) {
                result = lookup_header("Forwarded", ctx);
            }
            else if (*var == 'C' && !strcmp(var, "CONTEXT_PREFIX")) {
                result = ap_context_prefix(r);
            }
            else if (var[8] == 'M' && !strcmp(var, "REQUEST_METHOD")) {
                result = r->method;
            }
            else if (!strcmp(var, "REQUEST_SCHEME")) {
                result = ap_http_scheme(r);
            }
            break;

        case 15:
            switch (var[7]) {
            case 'E':
                if (!strcmp(var, "HTTP_USER_AGENT")) {
                    result = lookup_header("User-Agent", ctx);
                }
                break;

            case 'F':
                if (!strcmp(var, "SCRIPT_FILENAME")) {
                    result = r->filename; 
                }
                break;

            case 'P':
                if (!strcmp(var, "SERVER_PROTOCOL")) {
                    result = r->protocol;
                }
                break;

            case 'S':
                if (!strcmp(var, "SERVER_SOFTWARE")) {
                    result = ap_get_server_banner();
                }
                break;
            }
            break;

        case 16:
            if (!strcmp(var, "REQUEST_FILENAME")) {
                result = r->filename; 
            }
            break;

        case 21:
            if (!strcmp(var, "HTTP_PROXY_CONNECTION")) {
                result = lookup_header("Proxy-Connection", ctx);
            }
            else if (!strcmp(var, "CONTEXT_DOCUMENT_ROOT")) {
                result = ap_context_document_root(r);
            }
            break;
        }
    }

    return apr_pstrdup(r->pool, result ? result : "");
}





static APR_INLINE char *find_closing_curly(char *s)
{
    unsigned depth;

    for (depth = 1; *s; ++s) {
        if (*s == RIGHT_CURLY && --depth == 0) {
            return s;
        }
        else if (*s == LEFT_CURLY) {
            ++depth;
        }
    }

    return NULL;
}

static APR_INLINE char *find_char_in_curlies(char *s, int c)
{
    unsigned depth;

    for (depth = 1; *s; ++s) {
        if (*s == c && depth == 1) {
            return s;
        }
        else if (*s == RIGHT_CURLY && --depth == 0) {
            return NULL;
        }
        else if (*s == LEFT_CURLY) {
            ++depth;
        }
    }

    return NULL;
}


static char *do_expand(char *input, rewrite_ctx *ctx, rewriterule_entry *entry)
{
    result_list *result, *current;
    result_list sresult[SMALL_EXPANSION];
    unsigned spc = 0;
    apr_size_t span, inputlen, outlen;
    char *p, *c;
    apr_pool_t *pool = ctx->r->pool;

    span = strcspn(input, "\\$%");
    inputlen = strlen(input);

    
    if (inputlen == span) {
        return apr_pstrmemdup(pool, input, inputlen);
    }

    
    result = current = &(sresult[spc++]);

    p = input + span;
    current->next = NULL;
    current->string = input;
    current->len = span;
    outlen = span;

    
    do {
        
        if (current->len) {
            current->next = (spc < SMALL_EXPANSION)
                            ? &(sresult[spc++])
                            : (result_list *)apr_palloc(pool, sizeof(result_list));
            current = current->next;
            current->next = NULL;
            current->len = 0;
        }

        
        if (*p == '\\') {
            current->len = 1;
            ++outlen;
            if (!p[1]) {
                current->string = p;
                break;
            }
            else {
                current->string = ++p;
                ++p;
            }
        }

        
        else if (p[1] == '{') {
            char *endp;

            endp = find_closing_curly(p+2);
            if (!endp) {
                current->len = 2;
                current->string = p;
                outlen += 2;
                p += 2;
            }

            
            else if (*p == '%') {
                p = lookup_variable(apr_pstrmemdup(pool, p+2, endp-p-2), ctx);

                span = strlen(p);
                current->len = span;
                current->string = p;
                outlen += span;
                p = endp + 1;
            }

            
            else {     
                char *key;

                

                key = find_char_in_curlies(p+2, ':');
                if (!key) {
                    current->len = 2;
                    current->string = p;
                    outlen += 2;
                    p += 2;
                }
                else {
                    char *map, *dflt;

                    map = apr_pstrmemdup(pool, p+2, endp-p-2);
                    key = map + (key-p-2);
                    *key++ = '\0';
                    dflt = find_char_in_curlies(key, '|');
                    if (dflt) {
                        *dflt++ = '\0';
                    }

                    
                    key = lookup_map(ctx->r, map, do_expand(key, ctx, entry));

                    if (!key && dflt && *dflt) {
                        key = do_expand(dflt, ctx, entry);
                    }

                    if (key) {
                        span = strlen(key);
                        current->len = span;
                        current->string = key;
                        outlen += span;
                    }

                    p = endp + 1;
                }
            }
        }

        
        else if (apr_isdigit(p[1])) {
            int n = p[1] - '0';
            backrefinfo *bri = (*p == '$') ? &ctx->briRR : &ctx->briRC;

            
            if (bri->source && n < AP_MAX_REG_MATCH && bri->regmatch[n].rm_eo > bri->regmatch[n].rm_so) {
                span = bri->regmatch[n].rm_eo - bri->regmatch[n].rm_so;
                if (entry && (entry->flags & RULEFLAG_ESCAPEBACKREF)) {
                    
                    char *tmp2, *tmp;
                    tmp = apr_pstrmemdup(pool, bri->source + bri->regmatch[n].rm_so, span);
                    tmp2 = escape_uri(pool, tmp);
                    rewritelog((ctx->r, 5, ctx->perdir, "escaping backreference '%s' to '%s'", tmp, tmp2));

                    current->len = span = strlen(tmp2);
                    current->string = tmp2;
                } else {
                    current->len = span;
                    current->string = bri->source + bri->regmatch[n].rm_so;
                }

                outlen += span;
            }

            p += 2;
        }

        
        else {
            current->len = 1;
            current->string = p++;
            ++outlen;
        }

        
        if (*p && (span = strcspn(p, "\\$%")) > 0) {
            if (current->len) {
                current->next = (spc < SMALL_EXPANSION)
                                ? &(sresult[spc++])
                                : (result_list *)apr_palloc(pool, sizeof(result_list));
                current = current->next;
                current->next = NULL;
            }

            current->len = span;
            current->string = p;
            p += span;
            outlen += span;
        }

    } while (p < input+inputlen);

    
    c = p = apr_palloc(pool, outlen + 1); 
    do {
        if (result->len) {
            ap_assert(c+result->len <= p+outlen); 
            memcpy(c, result->string, result->len);
            c += result->len;
        }
        result = result->next;
    } while (result);

    p[outlen] = '\0';

    return p;
}


static void do_expand_env(data_item *env, rewrite_ctx *ctx)
{
    char *name, *val;

    while (env) {
        name = do_expand(env->data, ctx, NULL);
        if (*name == '!') {
            name++;
            apr_table_unset(ctx->r->subprocess_env, name);
            rewritelog((ctx->r, 5, NULL, "unsetting env variable '%s'", name));
        }
        else {
            if ((val = ap_strchr(name, ':')) != NULL) {
                *val++ = '\0';
            } else {
                val = "";
            }

            apr_table_set(ctx->r->subprocess_env, name, val);
            rewritelog((ctx->r, 5, NULL, "setting env variable '%s' to '%s'", name, val));
        }

        env = env->next;
    }

    return;
}


static void add_cookie(request_rec *r, char *s)
{
    char *var;
    char *val;
    char *domain;
    char *expires;
    char *path;
    char *secure;
    char *httponly;

    char *tok_cntx;
    char *cookie;

    var = apr_strtok(s, ":", &tok_cntx);
    val = apr_strtok(NULL, ":", &tok_cntx);
    domain = apr_strtok(NULL, ":", &tok_cntx);

    if (var && val && domain) {
        request_rec *rmain = r;
        char *notename;
        void *data;

        while (rmain->main) {
            rmain = rmain->main;
        }

        notename = apr_pstrcat(rmain->pool, var, "_rewrite", NULL);
        apr_pool_userdata_get(&data, notename, rmain->pool);
        if (!data) {
            char *exp_time = NULL;

            expires = apr_strtok(NULL, ":", &tok_cntx);
            path = expires ? apr_strtok(NULL, ":", &tok_cntx) : NULL;
            secure = path ? apr_strtok(NULL, ":", &tok_cntx) : NULL;
            httponly = secure ? apr_strtok(NULL, ":", &tok_cntx) : NULL;

            if (expires) {
                apr_time_exp_t tms;
                long exp_min;

                exp_min = atol(expires);
                if (exp_min) {
                    apr_time_exp_gmt(&tms, r->request_time + apr_time_from_sec((60 * exp_min)));
                    exp_time = apr_psprintf(r->pool, "%s, %.2d-%s-%.4d " "%.2d:%.2d:%.2d GMT", apr_day_snames[tms.tm_wday], tms.tm_mday, apr_month_snames[tms.tm_mon], tms.tm_year+1900, tms.tm_hour, tms.tm_min, tms.tm_sec);





                }
            }

            cookie = apr_pstrcat(rmain->pool, var, "=", val, "; path=", path ? path : "/", "; domain=", domain, expires ? (exp_time ? "; expires=" : "")



                                 : NULL, expires ? (exp_time ? exp_time : "")
                                 : NULL, (secure && (!strcasecmp(secure, "true")
                                             || !strcmp(secure, "1")
                                             || !strcasecmp(secure, "secure"))) ? "; secure" : NULL, (httponly && (!strcasecmp(httponly, "true")


                                               || !strcmp(httponly, "1")
                                               || !strcasecmp(httponly, "HttpOnly"))) ? "; HttpOnly" : NULL, NULL);



            apr_table_addn(rmain->err_headers_out, "Set-Cookie", cookie);
            apr_pool_userdata_set("set", notename, NULL, rmain->pool);
            rewritelog((rmain, 5, NULL, "setting cookie '%s'", cookie));
        }
        else {
            rewritelog((rmain, 5, NULL, "skipping already set cookie '%s'", var));
        }
    }

    return;
}

static void do_expand_cookie(data_item *cookie, rewrite_ctx *ctx)
{
    while (cookie) {
        add_cookie(ctx->r, do_expand(cookie->data, ctx, NULL));
        cookie = cookie->next;
    }

    return;
}



static char *expand_tildepaths(request_rec *r, char *uri)
{
    if (uri && *uri == '/' && uri[1] == '~') {
        char *p, *user;

        p = user = uri + 2;
        while (*p && *p != '/') {
            ++p;
        }

        if (p > user) {
            char *homedir;

            user = apr_pstrmemdup(r->pool, user, p-user);
            if (apr_uid_homepath_get(&homedir, user, r->pool) == APR_SUCCESS) {
                if (*p) {
                    
                    user = homedir + strlen(homedir) - 1;
                    if (user >= homedir && *user == '/') {
                        *user = '\0';
                    }

                    return apr_pstrcat(r->pool, homedir, p, NULL);
                }
                else {
                    return homedir;
                }
            }
        }
    }

    return uri;
}





static apr_status_t rewritelock_create(server_rec *s, apr_pool_t *p)
{
    apr_status_t rc;

    
    
    rc = ap_global_mutex_create(&rewrite_mapr_lock_acquire, NULL, rewritemap_mutex_type, NULL, s, p, 0);
    if (rc != APR_SUCCESS) {
        return rc;
    }

    return APR_SUCCESS;
}

static apr_status_t rewritelock_remove(void *data)
{
    
    if (rewrite_mapr_lock_acquire) {
        apr_global_mutex_destroy(rewrite_mapr_lock_acquire);
        rewrite_mapr_lock_acquire = NULL;
    }
    return(0);
}





static int parseargline(char *str, char **a1, char **a2, char **a3)
{
    char quote;

    while (apr_isspace(*str)) {
        ++str;
    }

    
    quote = (*str == '"' || *str == '\'') ? *str++ : '\0';
    *a1 = str;

    for (; *str; ++str) {
        if ((apr_isspace(*str) && !quote) || (*str == quote)) {
            break;
        }
        if (*str == '\\' && apr_isspace(str[1])) {
            ++str;
            continue;
        }
    }

    if (!*str) {
        return 1;
    }
    *str++ = '\0';

    while (apr_isspace(*str)) {
        ++str;
    }

    
    quote = (*str == '"' || *str == '\'') ? *str++ : '\0';
    *a2 = str;

    for (; *str; ++str) {
        if ((apr_isspace(*str) && !quote) || (*str == quote)) {
            break;
        }
        if (*str == '\\' && apr_isspace(str[1])) {
            ++str;
            continue;
        }
    }

    if (!*str) {
        *a3 = NULL; 
        return 0;
    }
    *str++ = '\0';

    while (apr_isspace(*str)) {
        ++str;
    }

    if (!*str) {
        *a3 = NULL; 
        return 0;
    }

    
    quote = (*str == '"' || *str == '\'') ? *str++ : '\0';
    *a3 = str;
    for (; *str; ++str) {
        if ((apr_isspace(*str) && !quote) || (*str == quote)) {
            break;
        }
        if (*str == '\\' && apr_isspace(str[1])) {
            ++str;
            continue;
        }
    }
    *str = '\0';

    return 0;
}

static void *config_server_create(apr_pool_t *p, server_rec *s)
{
    rewrite_server_conf *a;

    a = (rewrite_server_conf *)apr_pcalloc(p, sizeof(rewrite_server_conf));

    a->state           = ENGINE_DISABLED;
    a->options         = OPTION_NONE;
    a->rewritemaps     = apr_hash_make(p);
    a->rewriteconds    = apr_array_make(p, 2, sizeof(rewritecond_entry));
    a->rewriterules    = apr_array_make(p, 2, sizeof(rewriterule_entry));
    a->server          = s;

    return (void *)a;
}

static void *config_server_merge(apr_pool_t *p, void *basev, void *overridesv)
{
    rewrite_server_conf *a, *base, *overrides;

    a         = (rewrite_server_conf *)apr_pcalloc(p, sizeof(rewrite_server_conf));
    base      = (rewrite_server_conf *)basev;
    overrides = (rewrite_server_conf *)overridesv;

    a->state = (overrides->state_set == 0) ? base->state : overrides->state;
    a->state_set = overrides->state_set || base->state_set;
    a->options = (overrides->options_set == 0) ? base->options : overrides->options;
    a->options_set = overrides->options_set || base->options_set;

    a->server  = overrides->server;

    if (a->options & OPTION_INHERIT) {
        
        a->rewritemaps     = apr_hash_overlay(p, overrides->rewritemaps, base->rewritemaps);
        a->rewriteconds    = apr_array_append(p, overrides->rewriteconds, base->rewriteconds);
        a->rewriterules    = apr_array_append(p, overrides->rewriterules, base->rewriterules);
    }
    else if (a->options & OPTION_INHERIT_BEFORE) {
        
        a->rewritemaps     = apr_hash_overlay(p, base->rewritemaps, overrides->rewritemaps);
        a->rewriteconds    = apr_array_append(p, base->rewriteconds, overrides->rewriteconds);
        a->rewriterules    = apr_array_append(p, base->rewriterules, overrides->rewriterules);
    }
    else {
        
        a->rewritemaps     = overrides->rewritemaps;
        a->rewriteconds    = overrides->rewriteconds;
        a->rewriterules    = overrides->rewriterules;
    }

    return (void *)a;
}

static void *config_perdir_create(apr_pool_t *p, char *path)
{
    rewrite_perdir_conf *a;

    a = (rewrite_perdir_conf *)apr_pcalloc(p, sizeof(rewrite_perdir_conf));

    a->state           = ENGINE_DISABLED;
    a->options         = OPTION_NONE;
    a->baseurl         = NULL;
    a->rewriteconds    = apr_array_make(p, 2, sizeof(rewritecond_entry));
    a->rewriterules    = apr_array_make(p, 2, sizeof(rewriterule_entry));

    if (path == NULL) {
        a->directory = NULL;
    }
    else {
        
        if (path[strlen(path)-1] == '/') {
            a->directory = apr_pstrdup(p, path);
        }
        else {
            a->directory = apr_pstrcat(p, path, "/", NULL);
        }
    }

    return (void *)a;
}

static void *config_perdir_merge(apr_pool_t *p, void *basev, void *overridesv)
{
    rewrite_perdir_conf *a, *base, *overrides;

    a         = (rewrite_perdir_conf *)apr_pcalloc(p, sizeof(rewrite_perdir_conf));
    base      = (rewrite_perdir_conf *)basev;
    overrides = (rewrite_perdir_conf *)overridesv;

    a->state = (overrides->state_set == 0) ? base->state : overrides->state;
    a->state_set = overrides->state_set || base->state_set;
    a->options = (overrides->options_set == 0) ? base->options : overrides->options;
    a->options_set = overrides->options_set || base->options_set;
    a->baseurl = (overrides->baseurl_set == 0) ? base->baseurl : overrides->baseurl;
    a->baseurl_set = overrides->baseurl_set || base->baseurl_set;

    a->directory  = overrides->directory;

    if (a->options & OPTION_INHERIT) {
        a->rewriteconds = apr_array_append(p, overrides->rewriteconds, base->rewriteconds);
        a->rewriterules = apr_array_append(p, overrides->rewriterules, base->rewriterules);
    }
    else if (a->options & OPTION_INHERIT_BEFORE) {
        a->rewriteconds    = apr_array_append(p, base->rewriteconds, overrides->rewriteconds);
        a->rewriterules    = apr_array_append(p, base->rewriterules, overrides->rewriterules);
    }
    else {
        a->rewriteconds = overrides->rewriteconds;
        a->rewriterules = overrides->rewriterules;
    }

    return (void *)a;
}

static const char *cmd_rewriteengine(cmd_parms *cmd, void *in_dconf, int flag)
{
    rewrite_perdir_conf *dconf = in_dconf;
    rewrite_server_conf *sconf;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    
    if (cmd->path == NULL) {
        sconf->state = (flag ? ENGINE_ENABLED : ENGINE_DISABLED);
        sconf->state_set = 1;
        dconf->state = sconf->state;
        dconf->state_set = 1;
    }
    
    else {
        dconf->state = (flag ? ENGINE_ENABLED : ENGINE_DISABLED);
        dconf->state_set = 1;
    }

    return NULL;
}

static const char *cmd_rewriteoptions(cmd_parms *cmd, void *in_dconf, const char *option)
{
    int options = 0;

    while (*option) {
        char *w = ap_getword_conf(cmd->temp_pool, &option);

        if (!strcasecmp(w, "inherit")) {
            options |= OPTION_INHERIT;
        }
        else if (!strcasecmp(w, "inheritbefore")) {
            options |= OPTION_INHERIT_BEFORE;
        }
        else if (!strcasecmp(w, "allownoslash")) {
            options |= OPTION_NOSLASH;
        }
        else if (!strncasecmp(w, "MaxRedirects=", 13)) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server, "RewriteOptions: MaxRedirects option has been " "removed in favor of the global " "LimitInternalRecursion directive and will be " "ignored.");



        }
        else {
            return apr_pstrcat(cmd->pool, "RewriteOptions: unknown option '", w, "'", NULL);
        }
    }

    
    if (cmd->path == NULL) { 
        rewrite_perdir_conf *dconf = in_dconf;
        rewrite_server_conf *sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);


        sconf->options |= options;
        sconf->options_set = 1;
        dconf->options |= options;
        dconf->options_set = 1;
    }
    
    else {                  
        rewrite_perdir_conf *dconf = in_dconf;

        dconf->options |= options;
        dconf->options_set = 1;
    }

    return NULL;
}

static const char *cmd_rewritemap(cmd_parms *cmd, void *dconf, const char *a1, const char *a2)
{
    rewrite_server_conf *sconf;
    rewritemap_entry *newmap;
    apr_finfo_t st;
    const char *fname;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    newmap = apr_palloc(cmd->pool, sizeof(rewritemap_entry));
    newmap->func = NULL;

    if (strncasecmp(a2, "txt:", 4) == 0) {
        if ((fname = ap_server_root_relative(cmd->pool, a2+4)) == NULL) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad path to txt map: ", a2+4, NULL);
        }

        newmap->type      = MAPTYPE_TXT;
        newmap->datafile  = fname;
        newmap->checkfile = fname;
        newmap->checkfile2= NULL;
        newmap->cachename = apr_psprintf(cmd->pool, "%pp:%s", (void *)cmd->server, a1);
    }
    else if (strncasecmp(a2, "rnd:", 4) == 0) {
        if ((fname = ap_server_root_relative(cmd->pool, a2+4)) == NULL) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad path to rnd map: ", a2+4, NULL);
        }

        newmap->type      = MAPTYPE_RND;
        newmap->datafile  = fname;
        newmap->checkfile = fname;
        newmap->checkfile2= NULL;
        newmap->cachename = apr_psprintf(cmd->pool, "%pp:%s", (void *)cmd->server, a1);
    }
    else if (strncasecmp(a2, "dbm", 3) == 0) {
        apr_status_t rv;

        newmap->type = MAPTYPE_DBM;
        fname = NULL;
        newmap->cachename = apr_psprintf(cmd->pool, "%pp:%s", (void *)cmd->server, a1);

        if (a2[3] == ':') {
            newmap->dbmtype = "default";
            fname = a2+4;
        }
        else if (a2[3] == '=') {
            const char *colon = ap_strchr_c(a2 + 4, ':');

            if (colon) {
                newmap->dbmtype = apr_pstrndup(cmd->pool, a2 + 4, colon - (a2 + 3) - 1);
                fname = colon + 1;
            }
        }

        if (!fname) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad map:", a2, NULL);
        }

        if ((newmap->datafile = ap_server_root_relative(cmd->pool, fname)) == NULL) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad path to dbm map: ", fname, NULL);
        }

        rv = apr_dbm_get_usednames_ex(cmd->pool, newmap->dbmtype, newmap->datafile, &newmap->checkfile, &newmap->checkfile2);

        if (rv != APR_SUCCESS) {
            return apr_pstrcat(cmd->pool, "RewriteMap: dbm type ", newmap->dbmtype, " is invalid", NULL);
        }
    }
    else if ((strncasecmp(a2, "dbd:", 4) == 0)
             || (strncasecmp(a2, "fastdbd:", 8) == 0)) {
        if (dbd_prepare == NULL) {
            return "RewriteMap types dbd and fastdbd require mod_dbd!";
        }
        if ((a2[0] == 'd') || (a2[0] == 'D')) {
            newmap->type = MAPTYPE_DBD;
            fname = a2+4;
        }
        else {
            newmap->type = MAPTYPE_DBD_CACHE;
            fname = a2+8;
            newmap->cachename = apr_psprintf(cmd->pool, "%pp:%s", (void *)cmd->server, a1);
        }
        newmap->dbdq = a1;
        dbd_prepare(cmd->server, fname, newmap->dbdq);
    }
    else if (strncasecmp(a2, "prg:", 4) == 0) {
        apr_tokenize_to_argv(a2 + 4, &newmap->argv, cmd->pool);

        fname = newmap->argv[0];
        if ((newmap->argv[0] = ap_server_root_relative(cmd->pool, fname)) == NULL) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad path to prg map: ", fname, NULL);
        }

        newmap->type      = MAPTYPE_PRG;
        newmap->datafile  = NULL;
        newmap->checkfile = newmap->argv[0];
        newmap->checkfile2= NULL;
        newmap->cachename = NULL;
    }
    else if (strncasecmp(a2, "int:", 4) == 0) {
        newmap->type      = MAPTYPE_INT;
        newmap->datafile  = NULL;
        newmap->checkfile = NULL;
        newmap->checkfile2= NULL;
        newmap->cachename = NULL;
        newmap->func      = (char *(*)(request_rec *,char *))
                            apr_hash_get(mapfunc_hash, a2+4, strlen(a2+4));
        if (newmap->func == NULL) {
            return apr_pstrcat(cmd->pool, "RewriteMap: internal map not found:", a2+4, NULL);
        }
    }
    else {
        if ((fname = ap_server_root_relative(cmd->pool, a2)) == NULL) {
            return apr_pstrcat(cmd->pool, "RewriteMap: bad path to txt map: ", a2, NULL);
        }

        newmap->type      = MAPTYPE_TXT;
        newmap->datafile  = fname;
        newmap->checkfile = fname;
        newmap->checkfile2= NULL;
        newmap->cachename = apr_psprintf(cmd->pool, "%pp:%s", (void *)cmd->server, a1);
    }
    newmap->fpin  = NULL;
    newmap->fpout = NULL;

    if (newmap->checkfile && (apr_stat(&st, newmap->checkfile, APR_FINFO_MIN, cmd->pool) != APR_SUCCESS)) {

        return apr_pstrcat(cmd->pool, "RewriteMap: file for map ", a1, " not found:", newmap->checkfile, NULL);

    }

    apr_hash_set(sconf->rewritemaps, a1, APR_HASH_KEY_STRING, newmap);

    return NULL;
}

static const char *cmd_rewritebase(cmd_parms *cmd, void *in_dconf, const char *a1)
{
    rewrite_perdir_conf *dconf = in_dconf;

    if (cmd->path == NULL || dconf == NULL) {
        return "RewriteBase: only valid in per-directory config files";
    }
    if (a1[0] == '\0') {
        return "RewriteBase: empty URL not allowed";
    }
    if (a1[0] != '/') {
        return "RewriteBase: argument is not a valid URL";
    }

    dconf->baseurl = a1;
    dconf->baseurl_set = 1;

    return NULL;
}


static const char *cmd_parseflagfield(apr_pool_t *p, void *cfg, char *key, const char *(*parse)(apr_pool_t *, void *, char *, char *))


{
    char *val, *nextp, *endp;
    const char *err;

    endp = key + strlen(key) - 1;
    if (*key != '[' || *endp != ']') {
        return "bad flag delimiters";
    }

    *endp = ','; 
    ++key;

    while (*key) {
        
        while (apr_isspace(*key)) {
            ++key;
        }

        if (!*key || (nextp = ap_strchr(key, ',')) == NULL) { 
            break;
        }

        
        endp = nextp - 1;
        while (apr_isspace(*endp)) {
            --endp;
        }
        *++endp = '\0';

        
        val = ap_strchr(key, '=');
        if (val) {
            *val++ = '\0';
        }
        else {
            val = endp;
        }

        err = parse(p, cfg, key, val);
        if (err) {
            return err;
        }

        key = nextp + 1;
    }

    return NULL;
}

static const char *cmd_rewritecond_setflag(apr_pool_t *p, void *_cfg, char *key, char *val)
{
    rewritecond_entry *cfg = _cfg;

    if (   strcasecmp(key, "nocase") == 0 || strcasecmp(key, "NC") == 0    ) {
        cfg->flags |= CONDFLAG_NOCASE;
    }
    else if (   strcasecmp(key, "ornext") == 0 || strcasecmp(key, "OR") == 0    ) {
        cfg->flags |= CONDFLAG_ORNEXT;
    }
    else if (   strcasecmp(key, "novary") == 0 || strcasecmp(key, "NV") == 0    ) {
        cfg->flags |= CONDFLAG_NOVARY;
    }
    else {
        return apr_pstrcat(p, "unknown flag '", key, "'", NULL);
    }
    return NULL;
}

static const char *cmd_rewritecond(cmd_parms *cmd, void *in_dconf, const char *in_str)
{
    rewrite_perdir_conf *dconf = in_dconf;
    char *str = apr_pstrdup(cmd->pool, in_str);
    rewrite_server_conf *sconf;
    rewritecond_entry *newcond;
    ap_regex_t *regexp;
    char *a1;
    char *a2;
    char *a3;
    const char *err;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    
    if (cmd->path == NULL) {   
        newcond = apr_array_push(sconf->rewriteconds);
    }
    else {                     
        newcond = apr_array_push(dconf->rewriteconds);
    }

    
    if (parseargline(str, &a1, &a2, &a3)) {
        return apr_pstrcat(cmd->pool, "RewriteCond: bad argument line '", str, "'", NULL);
    }

    
    newcond->input = a1;

    
    newcond->flags = CONDFLAG_NONE;
    if (a3 != NULL) {
        if ((err = cmd_parseflagfield(cmd->pool, newcond, a3, cmd_rewritecond_setflag)) != NULL) {
            return apr_pstrcat(cmd->pool, "RewriteCond: ", err, NULL);
        }
    }

    
    newcond->pattern = a2;
    if (*a2 == '!') {
        newcond->flags |= CONDFLAG_NOTMATCH;
        ++a2;
    }

    
    newcond->ptype = CONDPAT_REGEX;
    if (strcasecmp(a1, "expr") == 0) {
        newcond->ptype = CONDPAT_AP_EXPR;
    }
    else if (*a2 && a2[1]) {
        if (!a2[2] && *a2 == '-') {
            switch (a2[1]) {
            case 'f': newcond->ptype = CONDPAT_FILE_EXISTS; break;
            case 's': newcond->ptype = CONDPAT_FILE_SIZE;   break;
            case 'd': newcond->ptype = CONDPAT_FILE_DIR;    break;
            case 'x': newcond->ptype = CONDPAT_FILE_XBIT;   break;
            case 'h': newcond->ptype = CONDPAT_FILE_LINK;   break;
            case 'L': newcond->ptype = CONDPAT_FILE_LINK;   break;
            case 'U': newcond->ptype = CONDPAT_LU_URL;      break;
            case 'F': newcond->ptype = CONDPAT_LU_FILE;     break;
            case 'l': if (a2[2] == 't')
                          a2 += 3, newcond->ptype = CONDPAT_INT_LT;
                      else if (a2[2] == 'e')
                          a2 += 3, newcond->ptype = CONDPAT_INT_LE;
                      else  newcond->ptype = CONDPAT_FILE_LINK;
                      break;
            case 'g': if (a2[2] == 't')
                          a2 += 3, newcond->ptype = CONDPAT_INT_GT;
                      else if (a2[2] == 'e')
                          a2 += 3, newcond->ptype = CONDPAT_INT_GE;
                      break;
            case 'e': if (a2[2] == 'q')
                          a2 += 3, newcond->ptype = CONDPAT_INT_EQ;
                      break;
            case 'n': if (a2[2] == 'e') {
                          
                          a2 += 3, newcond->ptype = CONDPAT_INT_EQ;
                          newcond->flags ^= CONDFLAG_NOTMATCH;
                      }
                      break;
            }
        }
        else {
            switch (*a2) {
            case '>': if (*++a2 == '=')
                          ++a2, newcond->ptype = CONDPAT_STR_GE;
                      else newcond->ptype = CONDPAT_STR_GT;
                      break;

            case '<': if (*++a2 == '=')
                          ++a2, newcond->ptype = CONDPAT_STR_LE;
                      else newcond->ptype = CONDPAT_STR_LT;
                      break;

            case '=': newcond->ptype = CONDPAT_STR_EQ;
                      
                      if (*++a2 == '"' && a2[1] == '"' && !a2[2])
                          a2 += 2;
                      break;
            }
        }
    }

    if ((newcond->ptype != CONDPAT_REGEX) && (newcond->ptype < CONDPAT_STR_LT || newcond->ptype > CONDPAT_STR_GE) && (newcond->flags & CONDFLAG_NOCASE)) {

        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server, "RewriteCond: NoCase option for non-regex pattern '%s' " "is not supported and will be ignored. (%s:%d)", a2, cmd->directive->filename, cmd->directive->line_num);


        newcond->flags &= ~CONDFLAG_NOCASE;
    }

    newcond->pskip = a2 - newcond->pattern;
    newcond->pattern += newcond->pskip;

    if (newcond->ptype == CONDPAT_REGEX) {
        regexp = ap_pregcomp(cmd->pool, a2, AP_REG_EXTENDED | ((newcond->flags & CONDFLAG_NOCASE)
                                             ? AP_REG_ICASE : 0));
        if (!regexp) {
            return apr_pstrcat(cmd->pool, "RewriteCond: cannot compile regular " "expression '", a2, "'", NULL);
        }

        newcond->regexp  = regexp;
    }
    else if (newcond->ptype == CONDPAT_AP_EXPR) {
        unsigned int flags = newcond->flags & CONDFLAG_NOVARY ? AP_EXPR_FLAG_DONT_VARY : 0;
        newcond->expr = ap_expr_parse_cmd(cmd, a2, flags, &err, NULL);
        if (err)
            return apr_psprintf(cmd->pool, "RewriteCond: cannot compile " "expression \"%s\": %s", a2, err);
    }

    return NULL;
}

static const char *cmd_rewriterule_setflag(apr_pool_t *p, void *_cfg, char *key, char *val)
{
    rewriterule_entry *cfg = _cfg;
    int error = 0;

    switch (*key++) {
    case 'b':
    case 'B':
        if (!*key || !strcasecmp(key, "ackrefescaping")) {
            cfg->flags |= RULEFLAG_ESCAPEBACKREF;
        }
        else {
            ++error;
        }
        break;
    case 'c':
    case 'C':
        if (!*key || !strcasecmp(key, "hain")) {           
            cfg->flags |= RULEFLAG_CHAIN;
        }
        else if (((*key == 'O' || *key == 'o') && !key[1])
                 || !strcasecmp(key, "ookie")) {           
            data_item *cp = cfg->cookie;

            if (!cp) {
                cp = cfg->cookie = apr_palloc(p, sizeof(*cp));
            }
            else {
                while (cp->next) {
                    cp = cp->next;
                }
                cp->next = apr_palloc(p, sizeof(*cp));
                cp = cp->next;
            }

            cp->next = NULL;
            cp->data = val;
        }
        else {
            ++error;
        }
        break;
    case 'd':
    case 'D':
        if (!*key || !strcasecmp(key, "PI") || !strcasecmp(key,"iscardpath")) {
            cfg->flags |= (RULEFLAG_DISCARDPATHINFO);
        }
        break;
    case 'e':
    case 'E':
        if (!*key || !strcasecmp(key, "nv")) {             
            data_item *cp = cfg->env;

            if (!cp) {
                cp = cfg->env = apr_palloc(p, sizeof(*cp));
            }
            else {
                while (cp->next) {
                    cp = cp->next;
                }
                cp->next = apr_palloc(p, sizeof(*cp));
                cp = cp->next;
            }

            cp->next = NULL;
            cp->data = val;
        }
        else if (!strcasecmp(key, "nd")) {                
            cfg->flags |= RULEFLAG_END;
        }
        else {
            ++error;
        }
        break;

    case 'f':
    case 'F':
        if (!*key || !strcasecmp(key, "orbidden")) {       
            cfg->flags |= (RULEFLAG_STATUS | RULEFLAG_NOSUB);
            cfg->forced_responsecode = HTTP_FORBIDDEN;
        }
        else {
            ++error;
        }
        break;

    case 'g':
    case 'G':
        if (!*key || !strcasecmp(key, "one")) {            
            cfg->flags |= (RULEFLAG_STATUS | RULEFLAG_NOSUB);
            cfg->forced_responsecode = HTTP_GONE;
        }
        else {
            ++error;
        }
        break;

    case 'h':
    case 'H':
        if (!*key || !strcasecmp(key, "andler")) {         
            cfg->forced_handler = val;
        }
        else {
            ++error;
        }
        break;
    case 'l':
    case 'L':
        if (!*key || !strcasecmp(key, "ast")) {            
            cfg->flags |= RULEFLAG_LASTRULE;
        }
        else {
            ++error;
        }
        break;

    case 'n':
    case 'N':
        if (((*key == 'E' || *key == 'e') && !key[1])
            || !strcasecmp(key, "oescape")) {              
            cfg->flags |= RULEFLAG_NOESCAPE;
        }
        else if (!*key || !strcasecmp(key, "ext")) {       
            cfg->flags |= RULEFLAG_NEWROUND;
        }
        else if (((*key == 'S' || *key == 's') && !key[1])
            || !strcasecmp(key, "osubreq")) {              
            cfg->flags |= RULEFLAG_IGNOREONSUBREQ;
        }
        else if (((*key == 'C' || *key == 'c') && !key[1])
            || !strcasecmp(key, "ocase")) {                
            cfg->flags |= RULEFLAG_NOCASE;
        }
        else {
            ++error;
        }
        break;

    case 'p':
    case 'P':
        if (!*key || !strcasecmp(key, "roxy")) {           
            cfg->flags |= RULEFLAG_PROXY;
        }
        else if (((*key == 'T' || *key == 't') && !key[1])
            || !strcasecmp(key, "assthrough")) {           
            cfg->flags |= RULEFLAG_PASSTHROUGH;
        }
        else {
            ++error;
        }
        break;

    case 'q':
    case 'Q':
        if (   !strcasecmp(key, "SA")
            || !strcasecmp(key, "sappend")) {              
            cfg->flags |= RULEFLAG_QSAPPEND;
        } else if ( !strcasecmp(key, "SD")
                || !strcasecmp(key, "sdiscard") ) {       
            cfg->flags |= RULEFLAG_QSDISCARD;
        }
        else {
            ++error;
        }
        break;

    case 'r':
    case 'R':
        if (!*key || !strcasecmp(key, "edirect")) {        
            int status = 0;

            cfg->flags |= RULEFLAG_FORCEREDIRECT;
            if (*val) {
                if (strcasecmp(val, "permanent") == 0) {
                    status = HTTP_MOVED_PERMANENTLY;
                }
                else if (strcasecmp(val, "temp") == 0) {
                    status = HTTP_MOVED_TEMPORARILY;
                }
                else if (strcasecmp(val, "seeother") == 0) {
                    status = HTTP_SEE_OTHER;
                }
                else if (apr_isdigit(*val)) {
                    status = atoi(val);
                    if (status != HTTP_INTERNAL_SERVER_ERROR) {
                        int idx = ap_index_of_response(HTTP_INTERNAL_SERVER_ERROR);

                        if (ap_index_of_response(status) == idx) {
                            return apr_psprintf(p, "invalid HTTP " "response code '%s' for " "flag 'R'", val);


                        }
                    }
                    if (!ap_is_HTTP_REDIRECT(status)) {
                        cfg->flags |= (RULEFLAG_STATUS | RULEFLAG_NOSUB);
                    }
                }
                cfg->forced_responsecode = status;
            }
        }
        else {
            ++error;
        }
        break;

    case 's':
    case 'S':
        if (!*key || !strcasecmp(key, "kip")) {            
            cfg->skip = atoi(val);
        }
        else {
            ++error;
        }
        break;

    case 't':
    case 'T':
        if (!*key || !strcasecmp(key, "ype")) {            
            cfg->forced_mimetype = val;
        }
        else {
            ++error;
        }
        break;
    default:
        ++error;
        break;
    }

    if (error) {
        return apr_pstrcat(p, "unknown flag '", --key, "'", NULL);
    }

    return NULL;
}

static const char *cmd_rewriterule(cmd_parms *cmd, void *in_dconf, const char *in_str)
{
    rewrite_perdir_conf *dconf = in_dconf;
    char *str = apr_pstrdup(cmd->pool, in_str);
    rewrite_server_conf *sconf;
    rewriterule_entry *newrule;
    ap_regex_t *regexp;
    char *a1;
    char *a2;
    char *a3;
    const char *err;

    sconf = ap_get_module_config(cmd->server->module_config, &rewrite_module);

    
    if (cmd->path == NULL) {   
        newrule = apr_array_push(sconf->rewriterules);
    }
    else {                     
        newrule = apr_array_push(dconf->rewriterules);
    }

    
    if (parseargline(str, &a1, &a2, &a3)) {
        return apr_pstrcat(cmd->pool, "RewriteRule: bad argument line '", str, "'", NULL);
    }

    
    newrule->forced_mimetype     = NULL;
    newrule->forced_handler      = NULL;
    newrule->forced_responsecode = HTTP_MOVED_TEMPORARILY;
    newrule->flags  = RULEFLAG_NONE;
    newrule->env = NULL;
    newrule->cookie = NULL;
    newrule->skip   = 0;
    if (a3 != NULL) {
        if ((err = cmd_parseflagfield(cmd->pool, newrule, a3, cmd_rewriterule_setflag)) != NULL) {
            return apr_pstrcat(cmd->pool, "RewriteRule: ", err, NULL);
        }
    }

    
    if (*a1 == '!') {
        newrule->flags |= RULEFLAG_NOTMATCH;
        ++a1;
    }

    regexp = ap_pregcomp(cmd->pool, a1, AP_REG_EXTENDED | ((newrule->flags & RULEFLAG_NOCASE)
                                         ? AP_REG_ICASE : 0));
    if (!regexp) {
        return apr_pstrcat(cmd->pool, "RewriteRule: cannot compile regular expression '", a1, "'", NULL);

    }

    newrule->pattern = a1;
    newrule->regexp  = regexp;

    
    newrule->output = a2;
    if (*a2 == '-' && !a2[1]) {
        newrule->flags |= RULEFLAG_NOSUB;
    }

    
    if (cmd->path == NULL) {  
        newrule->rewriteconds   = sconf->rewriteconds;
        sconf->rewriteconds = apr_array_make(cmd->pool, 2, sizeof(rewritecond_entry));
    }
    else {                    
        newrule->rewriteconds   = dconf->rewriteconds;
        dconf->rewriteconds = apr_array_make(cmd->pool, 2, sizeof(rewritecond_entry));
    }

    return NULL;
}





static APR_INLINE int compare_lexicography(char *a, char *b)
{
    apr_size_t i, lena, lenb;

    lena = strlen(a);
    lenb = strlen(b);

    if (lena == lenb) {
        for (i = 0; i < lena; ++i) {
            if (a[i] != b[i]) {
                return ((unsigned char)a[i] > (unsigned char)b[i]) ? 1 : -1;
            }
        }

        return 0;
    }

    return ((lena > lenb) ? 1 : -1);
}


static int apply_rewrite_cond(rewritecond_entry *p, rewrite_ctx *ctx)
{
    char *input = NULL;
    apr_finfo_t sb;
    request_rec *rsub, *r = ctx->r;
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
    int rc = 0;
    int basis;

    if (p->ptype != CONDPAT_AP_EXPR)
        input = do_expand(p->input, ctx, NULL);

    switch (p->ptype) {
    case CONDPAT_FILE_EXISTS:
        if (   apr_stat(&sb, input, APR_FINFO_MIN, r->pool) == APR_SUCCESS && sb.filetype == APR_REG) {
            rc = 1;
        }
        break;

    case CONDPAT_FILE_SIZE:
        if (   apr_stat(&sb, input, APR_FINFO_MIN, r->pool) == APR_SUCCESS && sb.filetype == APR_REG && sb.size > 0) {
            rc = 1;
        }
        break;

    case CONDPAT_FILE_LINK:

        if (   apr_stat(&sb, input, APR_FINFO_MIN | APR_FINFO_LINK, r->pool) == APR_SUCCESS && sb.filetype == APR_LNK) {

            rc = 1;
        }

        break;

    case CONDPAT_FILE_DIR:
        if (   apr_stat(&sb, input, APR_FINFO_MIN, r->pool) == APR_SUCCESS && sb.filetype == APR_DIR) {
            rc = 1;
        }
        break;

    case CONDPAT_FILE_XBIT:
        if (   apr_stat(&sb, input, APR_FINFO_PROT, r->pool) == APR_SUCCESS && (sb.protection & (APR_UEXECUTE | APR_GEXECUTE | APR_WEXECUTE))) {
            rc = 1;
        }
        break;

    case CONDPAT_LU_URL:
        if (*input && subreq_ok(r)) {
            rsub = ap_sub_req_lookup_uri(input, r, NULL);
            if (rsub->status < 400) {
                rc = 1;
            }
            rewritelog((r, 5, NULL, "RewriteCond URI (-U) check: " "path=%s -> status=%d", input, rsub->status));
            ap_destroy_sub_req(rsub);
        }
        break;

    case CONDPAT_LU_FILE:
        if (*input && subreq_ok(r)) {
            rsub = ap_sub_req_lookup_file(input, r, NULL);
            if (rsub->status < 300 &&  apr_stat(&sb, rsub->filename, APR_FINFO_MIN, r->pool) == APR_SUCCESS) {


                rc = 1;
            }
            rewritelog((r, 5, NULL, "RewriteCond file (-F) check: path=%s " "-> file=%s status=%d", input, rsub->filename, rsub->status));

            ap_destroy_sub_req(rsub);
        }
        break;

    case CONDPAT_STR_GE:
        basis = 0;
        goto test_str_g;
    case CONDPAT_STR_GT:
        basis = 1;
test_str_g:
        if (p->flags & CONDFLAG_NOCASE) {
            rc = (strcasecmp(input, p->pattern) >= basis) ? 1 : 0;
        }
        else {
            rc = (compare_lexicography(input, p->pattern) >= basis) ? 1 : 0;
        }
        break;

    case CONDPAT_STR_LE:
        basis = 0;
        goto test_str_l;
    case CONDPAT_STR_LT:
        basis = -1;
test_str_l:
        if (p->flags & CONDFLAG_NOCASE) {
            rc = (strcasecmp(input, p->pattern) <= basis) ? 1 : 0;
        }
        else {
            rc = (compare_lexicography(input, p->pattern) <= basis) ? 1 : 0;
        }
        break;

    case CONDPAT_STR_EQ:
        
        if (p->flags & CONDFLAG_NOCASE) {
            rc = !strcasecmp(input, p->pattern);
        }
        else {
            rc = !strcmp(input, p->pattern);
        }
        break;

    case CONDPAT_INT_GE: rc = (atoi(input) >= atoi(p->pattern)); break;
    case CONDPAT_INT_GT: rc = (atoi(input) > atoi(p->pattern));  break;

    case CONDPAT_INT_LE: rc = (atoi(input) <= atoi(p->pattern)); break;
    case CONDPAT_INT_LT: rc = (atoi(input) < atoi(p->pattern));  break;

    case CONDPAT_INT_EQ: rc = (atoi(input) == atoi(p->pattern)); break;

    case CONDPAT_AP_EXPR:
        {
            const char *err, *source;
            rc = ap_expr_exec_re(r, p->expr, AP_MAX_REG_MATCH, regmatch, &source, &err);
            if (rc < 0 || err) {
                rewritelog((r, 1, ctx->perdir, "RewriteCond: expr='%s' evaluation failed: %s", p->pattern - p->pskip, err));

                rc = 0;
            }
            
            if (rc && !(p->flags & CONDFLAG_NOTMATCH)) {
                ctx->briRC.source = source;
                memcpy(ctx->briRC.regmatch, regmatch, sizeof(regmatch));
            }
        }
        break;
    default:
        
        rc = !ap_regexec(p->regexp, input, AP_MAX_REG_MATCH, regmatch, 0);

        
        if (rc && !(p->flags & CONDFLAG_NOTMATCH)) {
            ctx->briRC.source = input;
            memcpy(ctx->briRC.regmatch, regmatch, sizeof(regmatch));
        }
        break;
    }

    if (p->flags & CONDFLAG_NOTMATCH) {
        rc = !rc;
    }

    rewritelog((r, 4, ctx->perdir, "RewriteCond: input='%s' pattern='%s'%s " "=> %s", input, p->pattern - p->pskip, (p->flags & CONDFLAG_NOCASE) ? " [NC]" : "", rc ? "matched" : "not-matched"));



    return rc;
}


static APR_INLINE void force_type_handler(rewriterule_entry *p, rewrite_ctx *ctx)
{
    char *expanded;

    if (p->forced_mimetype) {
        expanded = do_expand(p->forced_mimetype, ctx, p);

        if (*expanded) {
            ap_str_tolower(expanded);

            rewritelog((ctx->r, 2, ctx->perdir, "remember %s to have MIME-type " "'%s'", ctx->r->filename, expanded));

            apr_table_setn(ctx->r->notes, REWRITE_FORCED_MIMETYPE_NOTEVAR, expanded);
        }
    }

    if (p->forced_handler) {
        expanded = do_expand(p->forced_handler, ctx, p);

        if (*expanded) {
            ap_str_tolower(expanded);

            rewritelog((ctx->r, 2, ctx->perdir, "remember %s to have " "Content-handler '%s'", ctx->r->filename, expanded));

            apr_table_setn(ctx->r->notes, REWRITE_FORCED_HANDLER_NOTEVAR, expanded);
        }
    }
}


static int apply_rewrite_rule(rewriterule_entry *p, rewrite_ctx *ctx)
{
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
    apr_array_header_t *rewriteconds;
    rewritecond_entry *conds;
    int i, rc;
    char *newuri = NULL;
    request_rec *r = ctx->r;
    int is_proxyreq = 0;

    ctx->uri = r->filename;

    if (ctx->perdir) {
        apr_size_t dirlen = strlen(ctx->perdir);

        
        is_proxyreq = (   r->proxyreq && r->filename && !strncmp(r->filename, "proxy:", 6));

        
        if (r->path_info && *r->path_info) {
            rewritelog((r, 3, ctx->perdir, "add path info postfix: %s -> %s%s", ctx->uri, ctx->uri, r->path_info));
            ctx->uri = apr_pstrcat(r->pool, ctx->uri, r->path_info, NULL);
        }

        
        if (!is_proxyreq && strlen(ctx->uri) >= dirlen && !strncmp(ctx->uri, ctx->perdir, dirlen)) {

            rewritelog((r, 3, ctx->perdir, "strip per-dir prefix: %s -> %s", ctx->uri, ctx->uri + dirlen));
            ctx->uri = ctx->uri + dirlen;
        }
    }

    
    rewritelog((r, 3, ctx->perdir, "applying pattern '%s' to uri '%s'", p->pattern, ctx->uri));

    rc = !ap_regexec(p->regexp, ctx->uri, AP_MAX_REG_MATCH, regmatch, 0);
    if (! (( rc && !(p->flags & RULEFLAG_NOTMATCH)) || (!rc &&  (p->flags & RULEFLAG_NOTMATCH))   ) ) {
        return 0;
    }

    
    ctx->vary_this = NULL;
    ctx->briRC.source = NULL;

    if (p->flags & RULEFLAG_NOTMATCH) {
        ctx->briRR.source = NULL;
    }
    else {
        ctx->briRR.source = apr_pstrdup(r->pool, ctx->uri);
        memcpy(ctx->briRR.regmatch, regmatch, sizeof(regmatch));
    }

    
    rewriteconds = p->rewriteconds;
    conds = (rewritecond_entry *)rewriteconds->elts;

    for (i = 0; i < rewriteconds->nelts; ++i) {
        rewritecond_entry *c = &conds[i];

        rc = apply_rewrite_cond(c, ctx);
        
        if (c->flags & CONDFLAG_NOVARY) {
            ctx->vary_this = NULL;
        }
        if (c->flags & CONDFLAG_ORNEXT) {
            if (!rc) {
                
                ctx->vary_this = NULL;
                continue;
            }
            else {
                
                while (   i < rewriteconds->nelts && c->flags & CONDFLAG_ORNEXT) {
                    c = &conds[++i];
                }
            }
        }
        else if (!rc) {
            return 0;
        }

        
        if (ctx->vary_this) {
            ctx->vary = ctx->vary ? apr_pstrcat(r->pool, ctx->vary, ", ", ctx->vary_this, NULL)

                        : ctx->vary_this;
            ctx->vary_this = NULL;
        }
    }

    
    if (!(p->flags & RULEFLAG_NOSUB)) {
        newuri = do_expand(p->output, ctx, p);
        rewritelog((r, 2, ctx->perdir, "rewrite '%s' -> '%s'", ctx->uri, newuri));
    }

    
    do_expand_env(p->env, ctx);
    do_expand_cookie(p->cookie, ctx);

    
    if (p->flags & RULEFLAG_NOSUB) {
        force_type_handler(p, ctx);

        if (p->flags & RULEFLAG_STATUS) {
            rewritelog((r, 2, ctx->perdir, "forcing responsecode %d for %s", p->forced_responsecode, r->filename));

            r->status = p->forced_responsecode;
        }

        return 2;
    }

    
    r->filename = newuri;

    if (ctx->perdir && (p->flags & RULEFLAG_DISCARDPATHINFO)) {
        r->path_info = NULL;
    }

    splitout_queryargs(r, p->flags & RULEFLAG_QSAPPEND, p->flags & RULEFLAG_QSDISCARD);

    
    if (   ctx->perdir && !is_proxyreq && *r->filename != '/' && !is_absolute_uri(r->filename, NULL)) {
        rewritelog((r, 3, ctx->perdir, "add per-dir prefix: %s -> %s%s", r->filename, ctx->perdir, r->filename));

        r->filename = apr_pstrcat(r->pool, ctx->perdir, r->filename, NULL);
    }

    
    if (p->flags & RULEFLAG_PROXY) {
        
        if (ctx->perdir && (p->flags & RULEFLAG_NOESCAPE) == 0) {
            char *old_filename = r->filename;

            r->filename = ap_escape_uri(r->pool, r->filename);
            rewritelog((r, 2, ctx->perdir, "escaped URI in per-dir context " "for proxy, %s -> %s", old_filename, r->filename));
        }

        fully_qualify_uri(r);

        rewritelog((r, 2, ctx->perdir, "forcing proxy-throughput with %s", r->filename));

        r->filename = apr_pstrcat(r->pool, "proxy:", r->filename, NULL);
        return 1;
    }

    
    if (p->flags & RULEFLAG_FORCEREDIRECT) {
        fully_qualify_uri(r);

        rewritelog((r, 2, ctx->perdir, "explicitly forcing redirect with %s", r->filename));

        r->status = p->forced_responsecode;
        return 1;
    }

    
    reduce_uri(r);

    
    if (is_absolute_uri(r->filename, NULL)) {
        rewritelog((r, 2, ctx->perdir, "implicitly forcing redirect (rc=%d) " "with %s", p->forced_responsecode, r->filename));

        r->status = p->forced_responsecode;
        return 1;
    }

    
    force_type_handler(p, ctx);

    
    return 1;
}


static int apply_rewrite_list(request_rec *r, apr_array_header_t *rewriterules, char *perdir)
{
    rewriterule_entry *entries;
    rewriterule_entry *p;
    int i;
    int changed;
    int rc;
    int s;
    rewrite_ctx *ctx;

    ctx = apr_palloc(r->pool, sizeof(*ctx));
    ctx->perdir = perdir;
    ctx->r = r;

    
    entries = (rewriterule_entry *)rewriterules->elts;
    changed = 0;
    loop:
    for (i = 0; i < rewriterules->nelts; i++) {
        p = &entries[i];

        
        if (r->main != NULL && (p->flags & RULEFLAG_IGNOREONSUBREQ || p->flags & RULEFLAG_FORCEREDIRECT    )) {

            continue;
        }

        
        ctx->vary = NULL;
        rc = apply_rewrite_rule(p, ctx);

        if (rc) {
            
            if (ctx->vary) {
                apr_table_merge(r->headers_out, "Vary", ctx->vary);
            }

            
            if (p->flags & RULEFLAG_STATUS) {
                return ACTION_STATUS;
            }

            
            if (rc != 2) {
                changed = ((p->flags & RULEFLAG_NOESCAPE)
                           ? ACTION_NOESCAPE : ACTION_NORMAL);
            }

            
            if (p->flags & RULEFLAG_PASSTHROUGH) {
                rewritelog((r, 2, perdir, "forcing '%s' to get passed through " "to next API URI-to-filename handler", r->filename));
                r->filename = apr_pstrcat(r->pool, "passthrough:", r->filename, NULL);
                changed = ACTION_NORMAL;
                break;
            }

            if (p->flags & RULEFLAG_END) {
                rewritelog((r, 8, perdir, "Rule has END flag, no further rewriting for this request"));
                apr_pool_userdata_set("1", really_last_key, apr_pool_cleanup_null, r->pool);
                break;
            }
            
            if (p->flags & (RULEFLAG_PROXY | RULEFLAG_LASTRULE)) {
                break;
            }

            
            if (p->flags & RULEFLAG_NEWROUND) {
                goto loop;
            }

            
            if (p->skip > 0) {
                s = p->skip;
                while (   i < rewriterules->nelts && s > 0) {
                    i++;
                    s--;
                }
            }
        }
        else {
            
            while (   i < rewriterules->nelts && p->flags & RULEFLAG_CHAIN) {
                i++;
                p = &entries[i];
            }
        }
    }
    return changed;
}




static int pre_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp)

{
    APR_OPTIONAL_FN_TYPE(ap_register_rewrite_mapfunc) *map_pfn_register;

    ap_mutex_register(pconf, rewritemap_mutex_type, NULL, APR_LOCK_DEFAULT, 0);

    
    map_pfn_register = APR_RETRIEVE_OPTIONAL_FN(ap_register_rewrite_mapfunc);
    if (map_pfn_register) {
        map_pfn_register("tolower", rewrite_mapfunc_tolower);
        map_pfn_register("toupper", rewrite_mapfunc_toupper);
        map_pfn_register("escape", rewrite_mapfunc_escape);
        map_pfn_register("unescape", rewrite_mapfunc_unescape);
    }
    dbd_acquire = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
    dbd_prepare = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_prepare);
    return OK;
}

static int post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)


{
    apr_status_t rv;

    
    proxy_available = (ap_find_linked_module("mod_proxy.c") != NULL);

    rv = rewritelock_create(s, p);
    if (rv != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_pool_cleanup_register(p, (void *)s, rewritelock_remove, apr_pool_cleanup_null);

    
    if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_CONFIG) {
        for (; s; s = s->next) {
            if (run_rewritemap_programs(s, p) != APR_SUCCESS) {
                return HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }

    rewrite_ssl_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
    rewrite_is_https = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

    return OK;
}

static void init_child(apr_pool_t *p, server_rec *s)
{
    apr_status_t rv = 0; 

    if (rewrite_mapr_lock_acquire) {
        rv = apr_global_mutex_child_init(&rewrite_mapr_lock_acquire, apr_global_mutex_lockfile(rewrite_mapr_lock_acquire), p);
        if (rv != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "mod_rewrite: could not init rewrite_mapr_lock_acquire" " in child");

        }
    }

    
    if (!init_cache(p)) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, s, "mod_rewrite: could not init map cache in child");
    }
}





static int hook_uri2file(request_rec *r)
{
    rewrite_perdir_conf *dconf;
    rewrite_server_conf *conf;
    const char *saved_rulestatus;
    const char *var;
    const char *thisserver;
    char *thisport;
    const char *thisurl;
    unsigned int port;
    int rulestatus;
    void *skipdata;

    
    conf = ap_get_module_config(r->server->module_config, &rewrite_module);

    dconf = (rewrite_perdir_conf *)ap_get_module_config(r->per_dir_config, &rewrite_module);

    
    if (!dconf || dconf->state == ENGINE_DISABLED) {
        return DECLINED;
    }

    
    if (conf->server != r->server) {
        return DECLINED;
    }

    
    apr_pool_userdata_get(&skipdata, really_last_key, r->pool);
    if (skipdata != NULL) {
        rewritelog((r, 8, NULL, "Declining, no further rewriting due to END flag"));
        return DECLINED;
    }

    

    if (r->main == NULL) {
         var = apr_table_get(r->subprocess_env, REDIRECT_ENVVAR_SCRIPT_URL);
         if (var == NULL) {
             apr_table_setn(r->subprocess_env, ENVVAR_SCRIPT_URL, r->uri);
         }
         else {
             apr_table_setn(r->subprocess_env, ENVVAR_SCRIPT_URL, var);
         }
    }
    else {
         var = apr_table_get(r->main->subprocess_env, ENVVAR_SCRIPT_URL);
         apr_table_setn(r->subprocess_env, ENVVAR_SCRIPT_URL, var);
    }

    

    
    thisserver = ap_get_server_name_for_url(r);
    port = ap_get_server_port(r);
    if (ap_is_default_port(port, r)) {
        thisport = "";
    }
    else {
        thisport = apr_psprintf(r->pool, ":%u", port);
    }
    thisurl = apr_table_get(r->subprocess_env, ENVVAR_SCRIPT_URL);

    
    var = apr_pstrcat(r->pool, ap_http_scheme(r), "://", thisserver, thisport, thisurl, NULL);
    apr_table_setn(r->subprocess_env, ENVVAR_SCRIPT_URI, var);

    if (!(saved_rulestatus = apr_table_get(r->notes,"mod_rewrite_rewritten"))) {
        
        if (r->filename == NULL) {
            r->filename = apr_pstrdup(r->pool, r->uri);
            rewritelog((r, 2, NULL, "init rewrite engine with requested uri %s", r->filename));
        }
        else {
            rewritelog((r, 2, NULL, "init rewrite engine with passed filename " "%s. Original uri = %s", r->filename, r->uri));
        }

        
        rulestatus = apply_rewrite_list(r, conf->rewriterules, NULL);
        apr_table_setn(r->notes, "mod_rewrite_rewritten", apr_psprintf(r->pool,"%d",rulestatus));
    }
    else {
        rewritelog((r, 2, NULL, "uri already rewritten. Status %s, Uri %s, " "r->filename %s", saved_rulestatus, r->uri, r->filename));

        rulestatus = atoi(saved_rulestatus);
    }

    if (rulestatus) {
        unsigned skip;
        apr_size_t flen;

        if (ACTION_STATUS == rulestatus) {
            int n = r->status;

            r->status = HTTP_OK;
            return n;
        }

        flen = r->filename ? strlen(r->filename) : 0;
        if (flen > 6 && strncmp(r->filename, "proxy:", 6) == 0) {
            

            
            if (!proxy_available) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "attempt to make remote request from mod_rewrite " "without proxy enabled: %s", r->filename);

                return HTTP_FORBIDDEN;
            }

            if (rulestatus == ACTION_NOESCAPE) {
                apr_table_setn(r->notes, "proxy-nocanon", "1");
            }

            
            if (r->path_info != NULL) {
                r->filename = apr_pstrcat(r->pool, r->filename, r->path_info, NULL);
            }
            if ((r->args != NULL)
                && ((r->proxyreq == PROXYREQ_PROXY)
                    || (rulestatus == ACTION_NOESCAPE))) {
                
                r->filename = apr_pstrcat(r->pool, r->filename, "?", r->args, NULL);
            }

            
            if (PROXYREQ_NONE == r->proxyreq) {
                r->proxyreq = PROXYREQ_REVERSE;
            }
            r->handler  = "proxy-server";

            rewritelog((r, 1, NULL, "go-ahead with proxy request %s [OK]", r->filename));
            return OK;
        }
        else if ((skip = is_absolute_uri(r->filename, NULL)) > 0) {
            int n;

            

            if (rulestatus != ACTION_NOESCAPE) {
                rewritelog((r, 1, NULL, "escaping %s for redirect", r->filename));
                r->filename = escape_absolute_uri(r->pool, r->filename, skip);
            }

            
            if (r->args) {
                r->filename = apr_pstrcat(r->pool, r->filename, "?", (rulestatus == ACTION_NOESCAPE)
                                            ? r->args : ap_escape_uri(r->pool, r->args), NULL);

            }

            
            if (ap_is_HTTP_REDIRECT(r->status)) {
                n = r->status;
                r->status = HTTP_OK; 
            }
            else {
                n = HTTP_MOVED_TEMPORARILY;
            }

            
            apr_table_setn(r->headers_out, "Location", r->filename);
            rewritelog((r, 1, NULL, "redirect to %s [REDIRECT/%d]", r->filename, n));

            return n;
        }
        else if (flen > 12 && strncmp(r->filename, "passthrough:", 12) == 0) {
            
            r->uri = apr_pstrdup(r->pool, r->filename+12);
            return DECLINED;
        }
        else {
            

            

            r->filename = expand_tildepaths(r, r->filename);

            rewritelog((r, 2, NULL, "local path result: %s", r->filename));

            
            if (   *r->filename != '/' && !ap_os_is_path_absolute(r->pool, r->filename)) {
                return HTTP_BAD_REQUEST;
            }

            
            if (!prefix_stat(r->filename, r->pool)) {
                int res;
                char *tmp = r->uri;

                r->uri = r->filename;
                res = ap_core_translate(r);
                r->uri = tmp;

                if (res != OK) {
                    rewritelog((r, 1, NULL, "prefixing with document_root of %s" " FAILED", r->filename));

                    return res;
                }

                rewritelog((r, 2, NULL, "prefixed with document_root to %s", r->filename));
            }

            rewritelog((r, 1, NULL, "go-ahead with %s [OK]", r->filename));
            return OK;
        }
    }
    else {
        rewritelog((r, 1, NULL, "pass through %s", r->filename));
        return DECLINED;
    }
}


static int hook_fixup(request_rec *r)
{
    rewrite_perdir_conf *dconf;
    char *cp;
    char *cp2;
    const char *ccp;
    apr_size_t l;
    int rulestatus;
    int n;
    char *ofilename, *oargs;
    int is_proxyreq;
    void *skipdata;

    dconf = (rewrite_perdir_conf *)ap_get_module_config(r->per_dir_config, &rewrite_module);

    
    if (dconf == NULL) {
        return DECLINED;
    }

    
    if (dconf->state == ENGINE_DISABLED) {
        return DECLINED;
    }

    
    if (dconf->directory == NULL) {
        return DECLINED;
    }

    
    is_proxyreq = (   r->proxyreq && r->filename && !strncmp(r->filename, "proxy:", 6));

    
    if (!is_proxyreq && !(dconf->options & OPTION_NOSLASH)) {
        l = strlen(dconf->directory) - 1;
        if (r->filename && strlen(r->filename) == l && (dconf->directory)[l] == '/' && !strncmp(r->filename, dconf->directory, l)) {

            return DECLINED;
        }
    }

    
    apr_pool_userdata_get(&skipdata, really_last_key, r->pool);
    if (skipdata != NULL) {
        rewritelog((r, 8, dconf->directory, "Declining, no further rewriting due to END flag"));
        return DECLINED;
    }

    
    if (!(ap_allow_options(r) & (OPT_SYM_LINKS | OPT_SYM_OWNER))) {
        
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Options FollowSymLinks and SymLinksIfOwnerMatch are both off, " "so the RewriteRule directive is also forbidden " "due to its similar ability to circumvent directory restrictions : " "%s", r->filename);



        return HTTP_FORBIDDEN;
    }

    
    ofilename = r->filename;
    oargs = r->args;

    if (r->filename == NULL) {
        r->filename = apr_pstrdup(r->pool, r->uri);
        rewritelog((r, 2, dconf->directory, "init rewrite engine with" " requested uri %s", r->filename));
    }

    
    rulestatus = apply_rewrite_list(r, dconf->rewriterules, dconf->directory);
    if (rulestatus) {
        unsigned skip;

        if (ACTION_STATUS == rulestatus) {
            int n = r->status;

            r->status = HTTP_OK;
            return n;
        }

        l = strlen(r->filename);
        if (l > 6 && strncmp(r->filename, "proxy:", 6) == 0) {
            

            
            if (r->args != NULL) {
                
                r->filename = apr_pstrcat(r->pool, r->filename, "?", r->args, NULL);
            }

            
            if (PROXYREQ_NONE == r->proxyreq) {
                r->proxyreq = PROXYREQ_REVERSE;
            }
            r->handler  = "proxy-server";

            rewritelog((r, 1, dconf->directory, "go-ahead with proxy request " "%s [OK]", r->filename));
            return OK;
        }
        else if ((skip = is_absolute_uri(r->filename, NULL)) > 0) {
            

            
            if (dconf->baseurl != NULL) {
                
                cp = r->filename + skip;

                if ((cp = ap_strchr(cp, '/')) != NULL && *(++cp)) {
                    rewritelog((r, 2, dconf->directory, "trying to replace prefix %s with %s", dconf->directory, dconf->baseurl));


                    
                    cp2 = subst_prefix_path(r, cp, (*dconf->directory == '/')
                                                   ? dconf->directory + 1 : dconf->directory, dconf->baseurl + 1);

                    if (strcmp(cp2, cp) != 0) {
                        *cp = '\0';
                        r->filename = apr_pstrcat(r->pool, r->filename, cp2, NULL);
                    }
                }
            }

            
            if (rulestatus != ACTION_NOESCAPE) {
                rewritelog((r, 1, dconf->directory, "escaping %s for redirect", r->filename));
                r->filename = escape_absolute_uri(r->pool, r->filename, skip);
            }

            
            if (r->args) {
                char *escaped_args = NULL;
                int noescape = (rulestatus == ACTION_NOESCAPE || (oargs && !strcmp(r->args, oargs)));

                r->filename = apr_pstrcat(r->pool, r->filename, "?", noescape ? r->args : (escaped_args = ap_escape_uri(r->pool, r->args)), NULL);




                rewritelog((r, 1, dconf->directory, "%s %s to query string for redirect %s", noescape ? "copying" : "escaping", r->args , noescape ? "" : escaped_args));


            }

            
            if (ap_is_HTTP_REDIRECT(r->status)) {
                n = r->status;
                r->status = HTTP_OK; 
            }
            else {
                n = HTTP_MOVED_TEMPORARILY;
            }

            
            apr_table_setn(r->headers_out, "Location", r->filename);
            rewritelog((r, 1, dconf->directory, "redirect to %s [REDIRECT/%d]", r->filename, n));
            return n;
        }
        else {
            

            
            if (l > 12 && strncmp(r->filename, "passthrough:", 12) == 0) {
                r->filename = apr_pstrdup(r->pool, r->filename+12);
            }

            
            if (   *r->filename != '/' && !ap_os_is_path_absolute(r->pool, r->filename)) {
                return HTTP_BAD_REQUEST;
            }

            
            if (ofilename != NULL && strcmp(r->filename, ofilename) == 0) {
                rewritelog((r, 1, dconf->directory, "initial URL equal rewritten" " URL: %s [IGNORING REWRITE]", r->filename));
                return OK;
            }

            
            if (dconf->baseurl != NULL) {
                rewritelog((r, 2, dconf->directory, "trying to replace prefix " "%s with %s", dconf->directory, dconf->baseurl));

                r->filename = subst_prefix_path(r, r->filename, dconf->directory, dconf->baseurl);

            }
            else {
                
                if ((ccp = ap_document_root(r)) != NULL) {
                    
                    l = strlen(ccp);
                    if (ccp[l-1] == '/') {
                        --l;
                    }
                    if (!strncmp(r->filename, ccp, l) && r->filename[l] == '/') {
                        rewritelog((r, 2,dconf->directory, "strip document_root" " prefix: %s -> %s", r->filename, r->filename+l));


                        r->filename = apr_pstrdup(r->pool, r->filename+l);
                    }
                }
            }

            
            rewritelog((r, 1, dconf->directory, "internal redirect with %s " "[INTERNAL REDIRECT]", r->filename));
            r->filename = apr_pstrcat(r->pool, "redirect:", r->filename, NULL);
            r->handler = "redirect-handler";
            return OK;
        }
    }
    else {
        rewritelog((r, 1, dconf->directory, "pass through %s", r->filename));
        r->filename = ofilename;
        return DECLINED;
    }
}


static int hook_mimetype(request_rec *r)
{
    const char *t;

    
    t = apr_table_get(r->notes, REWRITE_FORCED_MIMETYPE_NOTEVAR);
    if (t && *t) {
        rewritelog((r, 1, NULL, "force filename %s to have MIME-type '%s'", r->filename, t));

        ap_set_content_type(r, t);
    }

    
    t = apr_table_get(r->notes, REWRITE_FORCED_HANDLER_NOTEVAR);
    if (t && *t) {
        rewritelog((r, 1, NULL, "force filename %s to have the " "Content-handler '%s'", r->filename, t));

        r->handler = t;
    }

    return OK;
}



static int handler_redirect(request_rec *r)
{
    if (strcmp(r->handler, "redirect-handler")) {
        return DECLINED;
    }

    
    if (strncmp(r->filename, "redirect:", 9) != 0) {
        return DECLINED;
    }

    
    ap_internal_redirect(apr_pstrcat(r->pool, r->filename+9, r->args ? "?" : NULL, r->args, NULL), r);

    
    return OK;
}




static const command_rec command_table[] = {
    AP_INIT_FLAG(    "RewriteEngine",   cmd_rewriteengine,  NULL, OR_FILEINFO, "On or Off to enable or disable (default) the whole " "rewriting engine"), AP_INIT_ITERATE( "RewriteOptions",  cmd_rewriteoptions,  NULL, OR_FILEINFO, "List of option strings to set"), AP_INIT_TAKE1(   "RewriteBase",     cmd_rewritebase,     NULL, OR_FILEINFO, "the base URL of the per-directory context"), AP_INIT_RAW_ARGS("RewriteCond",     cmd_rewritecond,     NULL, OR_FILEINFO, "an input string and a to be applied regexp-pattern"), AP_INIT_RAW_ARGS("RewriteRule",     cmd_rewriterule,     NULL, OR_FILEINFO, "an URL-applied regexp-pattern and a substitution URL"), AP_INIT_TAKE2(   "RewriteMap",      cmd_rewritemap,      NULL, RSRC_CONF, "a mapname and a filename"), { NULL }












};

static void ap_register_rewrite_mapfunc(char *name, rewrite_mapfunc_t *func)
{
    apr_hash_set(mapfunc_hash, name, strlen(name), (const void *)func);
}

static void register_hooks(apr_pool_t *p)
{
    
    static const char * const aszPre[]={ "mod_proxy.c", NULL };

    
    mapfunc_hash = apr_hash_make(p);
    APR_REGISTER_OPTIONAL_FN(ap_register_rewrite_mapfunc);

    ap_hook_handler(handler_redirect, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(init_child, NULL, NULL, APR_HOOK_MIDDLE);

    ap_hook_fixups(hook_fixup, aszPre, NULL, APR_HOOK_FIRST);
    ap_hook_fixups(hook_mimetype, NULL, NULL, APR_HOOK_LAST);
    ap_hook_translate_name(hook_uri2file, NULL, NULL, APR_HOOK_FIRST);
}

    
AP_DECLARE_MODULE(rewrite) = {
   STANDARD20_MODULE_STUFF, config_perdir_create, config_perdir_merge, config_server_create, config_server_merge, command_table, register_hooks };








