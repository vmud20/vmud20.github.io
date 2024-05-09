




































































AP_DECLARE(char *) ap_field_noparam(apr_pool_t *p, const char *intype)
{
    const char *semi;

    if (intype == NULL) return NULL;

    semi = ap_strchr_c(intype, ';');
    if (semi == NULL) {
        return apr_pstrdup(p, intype);
    }
    else {
        while ((semi > intype) && apr_isspace(semi[-1])) {
            semi--;
        }
        return apr_pstrmemdup(p, intype, semi - intype);
    }
}

AP_DECLARE(char *) ap_ht_time(apr_pool_t *p, apr_time_t t, const char *fmt, int gmt)
{
    apr_size_t retcode;
    char ts[MAX_STRING_LEN];
    char tf[MAX_STRING_LEN];
    apr_time_exp_t xt;

    if (gmt) {
        const char *f;
        char *strp;

        apr_time_exp_gmt(&xt, t);
        
        for(strp = tf, f = fmt; strp < tf + sizeof(tf) - 6 && (*strp = *f)
            ; f++, strp++) {
            if (*f != '%') continue;
            switch (f[1]) {
            case '%':
                *++strp = *++f;
                break;
            case 'Z':
                *strp++ = 'G';
                *strp++ = 'M';
                *strp = 'T';
                f++;
                break;
            case 'z': 
                *strp++ = '+';
                *strp++ = '0';
                *strp++ = '0';
                *strp++ = '0';
                *strp = '0';
                f++;
                break;
            }
        }
        *strp = '\0';
        fmt = tf;
    }
    else {
        apr_time_exp_lt(&xt, t);
    }

    
    apr_strftime(ts, &retcode, MAX_STRING_LEN, fmt, &xt);
    ts[MAX_STRING_LEN - 1] = '\0';
    return apr_pstrdup(p, ts);
}







AP_DECLARE(int) ap_strcmp_match(const char *str, const char *expected)
{
    int x, y;

    for (x = 0, y = 0; expected[y]; ++y, ++x) {
        if ((!str[x]) && (expected[y] != '*'))
            return -1;
        if (expected[y] == '*') {
            while (expected[++y] == '*');
            if (!expected[y])
                return 0;
            while (str[x]) {
                int ret;
                if ((ret = ap_strcmp_match(&str[x++], &expected[y])) != 1)
                    return ret;
            }
            return -1;
        }
        else if ((expected[y] != '?') && (str[x] != expected[y]))
            return 1;
    }
    return (str[x] != '\0');
}

AP_DECLARE(int) ap_strcasecmp_match(const char *str, const char *expected)
{
    int x, y;

    for (x = 0, y = 0; expected[y]; ++y, ++x) {
        if (!str[x] && expected[y] != '*')
            return -1;
        if (expected[y] == '*') {
            while (expected[++y] == '*');
            if (!expected[y])
                return 0;
            while (str[x]) {
                int ret;
                if ((ret = ap_strcasecmp_match(&str[x++], &expected[y])) != 1)
                    return ret;
            }
            return -1;
        }
        else if (expected[y] != '?' && apr_tolower(str[x]) != apr_tolower(expected[y]))
            return 1;
    }
    return (str[x] != '\0');
}


AP_DECLARE(int) ap_os_is_path_absolute(apr_pool_t *p, const char *dir)
{
    const char *newpath;
    const char *ourdir = dir;
    if (apr_filepath_root(&newpath, &dir, 0, p) != APR_SUCCESS || strncmp(newpath, ourdir, strlen(newpath)) != 0) {
        return 0;
    }
    return 1;
}

AP_DECLARE(int) ap_is_matchexp(const char *str)
{
    int x;

    for (x = 0; str[x]; x++)
        if ((str[x] == '*') || (str[x] == '?'))
            return 1;
    return 0;
}



static apr_status_t regex_cleanup(void *preg)
{
    ap_regfree((ap_regex_t *) preg);
    return APR_SUCCESS;
}

AP_DECLARE(ap_regex_t *) ap_pregcomp(apr_pool_t *p, const char *pattern, int cflags)
{
    ap_regex_t *preg = apr_palloc(p, sizeof *preg);
    int err = ap_regcomp(preg, pattern, cflags);
    if (err) {
        if (err == AP_REG_ESPACE)
            ap_abort_on_oom();
        return NULL;
    }

    apr_pool_cleanup_register(p, (void *) preg, regex_cleanup, apr_pool_cleanup_null);

    return preg;
}

AP_DECLARE(void) ap_pregfree(apr_pool_t *p, ap_regex_t *reg)
{
    ap_regfree(reg);
    apr_pool_cleanup_kill(p, (void *) reg, regex_cleanup);
}


AP_DECLARE(char *) ap_strcasestr(const char *s1, const char *s2)
{
    char *p1, *p2;
    if (*s2 == '\0') {
        
        return((char *)s1);
    }
    while(1) {
        for ( ; (*s1 != '\0') && (apr_tolower(*s1) != apr_tolower(*s2)); s1++);
        if (*s1 == '\0') {
            return(NULL);
        }
        
        p1 = (char *)s1;
        p2 = (char *)s2;
        for (++p1, ++p2; apr_tolower(*p1) == apr_tolower(*p2); ++p1, ++p2) {
            if (*p1 == '\0') {
                
                return((char *)s1);
            }
        }
        if (*p2 == '\0') {
            
            break;
        }
        
        s1++;
    }
    return((char *)s1);
}


AP_DECLARE(const char *) ap_stripprefix(const char *bigstring, const char *prefix)
{
    const char *p1;

    if (*prefix == '\0')
        return bigstring;

    p1 = bigstring;
    while (*p1 && *prefix) {
        if (*p1++ != *prefix++)
            return bigstring;
    }
    if (*prefix == '\0')
        return p1;

    
    return bigstring;
}



static apr_status_t regsub_core(apr_pool_t *p, char **result, struct ap_varbuf *vb, const char *input, const char *source, apr_size_t nmatch, ap_regmatch_t pmatch[], apr_size_t maxlen)


{
    const char *src = input;
    char *dst;
    char c;
    apr_size_t no;
    apr_size_t len = 0;

    AP_DEBUG_ASSERT((result && p && !vb) || (vb && !p && !result));
    if (!source || nmatch>AP_MAX_REG_MATCH)
        return APR_EINVAL;
    if (!nmatch) {
        len = strlen(src);
        if (maxlen > 0 && len >= maxlen)
            return APR_ENOMEM;
        if (!vb) {
            *result = apr_pstrmemdup(p, src, len);
            return APR_SUCCESS;
        }
        else {
            ap_varbuf_strmemcat(vb, src, len);
            return APR_SUCCESS;
        }
    }

    
    while ((c = *src++) != '\0') {
        if (c == '$' && apr_isdigit(*src))
            no = *src++ - '0';
        else no = AP_MAX_REG_MATCH;

        if (no >= AP_MAX_REG_MATCH) {  
            if (c == '\\' && *src)
                src++;
            len++;
        }
        else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
            if (APR_SIZE_MAX - len <= pmatch[no].rm_eo - pmatch[no].rm_so)
                return APR_ENOMEM;
            len += pmatch[no].rm_eo - pmatch[no].rm_so;
        }

    }

    if (len >= maxlen && maxlen > 0)
        return APR_ENOMEM;

    if (!vb) {
        *result = dst = apr_palloc(p, len + 1);
    }
    else {
        if (vb->strlen == AP_VARBUF_UNKNOWN)
            vb->strlen = strlen(vb->buf);
        ap_varbuf_grow(vb, vb->strlen + len);
        dst = vb->buf + vb->strlen;
        vb->strlen += len;
    }

    

    src = input;

    while ((c = *src++) != '\0') {
        if (c == '$' && apr_isdigit(*src))
            no = *src++ - '0';
        else no = AP_MAX_REG_MATCH;

        if (no >= AP_MAX_REG_MATCH) {  
            if (c == '\\' && *src)
                c = *src++;
            *dst++ = c;
        }
        else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
            len = pmatch[no].rm_eo - pmatch[no].rm_so;
            memcpy(dst, source + pmatch[no].rm_so, len);
            dst += len;
        }

    }
    *dst = '\0';

    return APR_SUCCESS;
}




AP_DECLARE(char *) ap_pregsub(apr_pool_t *p, const char *input, const char *source, apr_size_t nmatch, ap_regmatch_t pmatch[])

{
    char *result;
    apr_status_t rc = regsub_core(p, &result, NULL, input, source, nmatch, pmatch, AP_PREGSUB_MAXLEN);
    if (rc != APR_SUCCESS)
        result = NULL;
    return result;
}

AP_DECLARE(apr_status_t) ap_pregsub_ex(apr_pool_t *p, char **result, const char *input, const char *source, apr_size_t nmatch, ap_regmatch_t pmatch[], apr_size_t maxlen)


{
    apr_status_t rc = regsub_core(p, result, NULL, input, source, nmatch, pmatch, maxlen);
    if (rc != APR_SUCCESS)
        *result = NULL;
    return rc;
}


AP_DECLARE(void) ap_getparents(char *name)
{
    char *next;
    int l, w, first_dot;

    
    
    for (next = name; *next && (*next != '.'); next++) {
    }

    l = w = first_dot = next - name;
    while (name[l] != '\0') {
        if (name[l] == '.' && IS_SLASH(name[l + 1])
            && (l == 0 || IS_SLASH(name[l - 1])))
            l += 2;
        else name[w++] = name[l++];
    }

    
    if (w == 1 && name[0] == '.')
        w--;
    else if (w > 1 && name[w - 1] == '.' && IS_SLASH(name[w - 2]))
        w--;
    name[w] = '\0';

    
    l = first_dot;

    while (name[l] != '\0') {
        if (name[l] == '.' && name[l + 1] == '.' && IS_SLASH(name[l + 2])
            && (l == 0 || IS_SLASH(name[l - 1]))) {
            int m = l + 3, n;

            l = l - 2;
            if (l >= 0) {
                while (l >= 0 && !IS_SLASH(name[l]))
                    l--;
                l++;
            }
            else l = 0;
            n = l;
            while ((name[n] = name[m]))
                (++n, ++m);
        }
        else ++l;
    }

    
    if (l == 2 && name[0] == '.' && name[1] == '.')
        name[0] = '\0';
    else if (l > 2 && name[l - 1] == '.' && name[l - 2] == '.' && IS_SLASH(name[l - 3])) {
        l = l - 4;
        if (l >= 0) {
            while (l >= 0 && !IS_SLASH(name[l]))
                l--;
            l++;
        }
        else l = 0;
        name[l] = '\0';
    }
}

AP_DECLARE(void) ap_no2slash(char *name)
{
    char *d, *s;

    s = d = name;


    
    if (s[0] == '/' && s[1] == '/')
        *d++ = *s++;


    while (*s) {
        if ((*d++ = *s) == '/') {
            do {
                ++s;
            } while (*s == '/');
        }
        else {
            ++s;
        }
    }
    *d = '\0';
}



AP_DECLARE(char *) ap_make_dirstr_prefix(char *d, const char *s, int n)
{
    if (n < 1) {
        *d = '/';
        *++d = '\0';
        return (d);
    }

    for (;;) {
        if (*s == '\0' || (*s == '/' && (--n) == 0)) {
            *d = '/';
            break;
        }
        *d++ = *s++;
    }
    *++d = 0;
    return (d);
}



AP_DECLARE(char *) ap_make_dirstr_parent(apr_pool_t *p, const char *s)
{
    const char *last_slash = ap_strrchr_c(s, '/');
    char *d;
    int l;

    if (last_slash == NULL) {
        return apr_pstrdup(p, "");
    }
    l = (last_slash - s) + 1;
    d = apr_pstrmemdup(p, s, l);

    return (d);
}


AP_DECLARE(int) ap_count_dirs(const char *path)
{
    int x, n;

    for (x = 0, n = 0; path[x]; x++)
        if (path[x] == '/')
            n++;
    return n;
}

AP_DECLARE(char *) ap_getword_nc(apr_pool_t *atrans, char **line, char stop)
{
    return ap_getword(atrans, (const char **) line, stop);
}

AP_DECLARE(char *) ap_getword(apr_pool_t *atrans, const char **line, char stop)
{
    const char *pos = *line;
    int len;
    char *res;

    while ((*pos != stop) && *pos) {
        ++pos;
    }

    len = pos - *line;
    res = apr_pstrmemdup(atrans, *line, len);

    if (stop) {
        while (*pos == stop) {
            ++pos;
        }
    }
    *line = pos;

    return res;
}

AP_DECLARE(char *) ap_getword_white_nc(apr_pool_t *atrans, char **line)
{
    return ap_getword_white(atrans, (const char **) line);
}

AP_DECLARE(char *) ap_getword_white(apr_pool_t *atrans, const char **line)
{
    const char *pos = *line;
    int len;
    char *res;

    while (!apr_isspace(*pos) && *pos) {
        ++pos;
    }

    len = pos - *line;
    res = apr_pstrmemdup(atrans, *line, len);

    while (apr_isspace(*pos)) {
        ++pos;
    }

    *line = pos;

    return res;
}

AP_DECLARE(char *) ap_getword_nulls_nc(apr_pool_t *atrans, char **line, char stop)
{
    return ap_getword_nulls(atrans, (const char **) line, stop);
}

AP_DECLARE(char *) ap_getword_nulls(apr_pool_t *atrans, const char **line, char stop)
{
    const char *pos = ap_strchr_c(*line, stop);
    char *res;

    if (!pos) {
        apr_size_t len = strlen(*line);
        res = apr_pstrmemdup(atrans, *line, len);
        *line += len;
        return res;
    }

    res = apr_pstrmemdup(atrans, *line, pos - *line);

    ++pos;

    *line = pos;

    return res;
}



static char *substring_conf(apr_pool_t *p, const char *start, int len, char quote)
{
    char *result = apr_palloc(p, len + 1);
    char *resp = result;
    int i;

    for (i = 0; i < len; ++i) {
        if (start[i] == '\\' && (start[i + 1] == '\\' || (quote && start[i + 1] == quote)))
            *resp++ = start[++i];
        else *resp++ = start[i];
    }

    *resp++ = '\0';

    return (char *)ap_resolve_env(p,result);

    return result;

}

AP_DECLARE(char *) ap_getword_conf_nc(apr_pool_t *p, char **line)
{
    return ap_getword_conf(p, (const char **) line);
}

AP_DECLARE(char *) ap_getword_conf(apr_pool_t *p, const char **line)
{
    const char *str = *line, *strend;
    char *res;
    char quote;

    while (apr_isspace(*str))
        ++str;

    if (!*str) {
        *line = str;
        return "";
    }

    if ((quote = *str) == '"' || quote == '\'') {
        strend = str + 1;
        while (*strend && *strend != quote) {
            if (*strend == '\\' && strend[1] && (strend[1] == quote || strend[1] == '\\')) {
                strend += 2;
            }
            else {
                ++strend;
            }
        }
        res = substring_conf(p, str + 1, strend - str - 1, quote);

        if (*strend == quote)
            ++strend;
    }
    else {
        strend = str;
        while (*strend && !apr_isspace(*strend))
            ++strend;

        res = substring_conf(p, str, strend - str, 0);
    }

    while (apr_isspace(*strend))
        ++strend;
    *line = strend;
    return res;
}

AP_DECLARE(int) ap_cfg_closefile(ap_configfile_t *cfp)
{

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, APLOGNO(00551)
        "Done with config file %s", cfp->name);

    return (cfp->close == NULL) ? 0 : cfp->close(cfp->param);
}


static apr_status_t cfg_close(void *param)
{
    return apr_file_close(param);
}

static apr_status_t cfg_getch(char *ch, void *param)
{
    return apr_file_getc(ch, param);
}

static apr_status_t cfg_getstr(void *buf, apr_size_t bufsiz, void *param)
{
    return apr_file_gets(buf, bufsiz, param);
}


AP_DECLARE(apr_status_t) ap_pcfg_openfile(ap_configfile_t **ret_cfg, apr_pool_t *p, const char *name)
{
    ap_configfile_t *new_cfg;
    apr_file_t *file = NULL;
    apr_finfo_t finfo;
    apr_status_t status;

    char buf[120];


    if (name == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(00552)
               "Internal error: pcfg_openfile() called with NULL filename");
        return APR_EBADF;
    }

    status = apr_file_open(&file, name, APR_READ | APR_BUFFERED, APR_OS_DEFAULT, p);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, APLOGNO(00553)
                "Opening config file %s (%s)", name, (status != APR_SUCCESS) ? apr_strerror(status, buf, sizeof(buf)) : "successful");


    if (status != APR_SUCCESS)
        return status;

    status = apr_file_info_get(&finfo, APR_FINFO_TYPE, file);
    if (status != APR_SUCCESS)
        return status;

    if (finfo.filetype != APR_REG &&  strcasecmp(apr_filepath_name_get(name), "nul") != 0) {


        strcmp(name, "/dev/null") != 0) {

        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, APLOGNO(00554)
                     "Access to file %s denied by server: not a regular file", name);
        apr_file_close(file);
        return APR_EBADF;
    }


    
    {
        unsigned char buf[4];
        apr_size_t len = 3;
        status = apr_file_read(file, buf, &len);
        if ((status != APR_SUCCESS) || (len < 3)
              || memcmp(buf, "\xEF\xBB\xBF", 3) != 0) {
            apr_off_t zero = 0;
            apr_file_seek(file, APR_SET, &zero);
        }
    }


    new_cfg = apr_palloc(p, sizeof(*new_cfg));
    new_cfg->param = file;
    new_cfg->name = apr_pstrdup(p, name);
    new_cfg->getch = cfg_getch;
    new_cfg->getstr = cfg_getstr;
    new_cfg->close = cfg_close;
    new_cfg->line_number = 0;
    *ret_cfg = new_cfg;
    return APR_SUCCESS;
}



AP_DECLARE(ap_configfile_t *) ap_pcfg_open_custom( apr_pool_t *p, const char *descr, void *param, apr_status_t (*getc_func) (char *ch, void *param), apr_status_t (*gets_func) (void *buf, apr_size_t bufsize, void *param), apr_status_t (*close_func) (void *param))



{
    ap_configfile_t *new_cfg = apr_palloc(p, sizeof(*new_cfg));
    new_cfg->param = param;
    new_cfg->name = descr;
    new_cfg->getch = getc_func;
    new_cfg->getstr = gets_func;
    new_cfg->close = close_func;
    new_cfg->line_number = 0;
    return new_cfg;
}


AP_DECLARE(apr_status_t) ap_cfg_getc(char *ch, ap_configfile_t *cfp)
{
    apr_status_t rc = cfp->getch(ch, cfp->param);
    if (rc == APR_SUCCESS && *ch == LF)
        ++cfp->line_number;
    return rc;
}

AP_DECLARE(const char *) ap_pcfg_strerror(apr_pool_t *p, ap_configfile_t *cfp, apr_status_t rc)
{
    if (rc == APR_SUCCESS)
        return NULL;

    if (rc == APR_ENOSPC)
        return apr_psprintf(p, "Error reading %s at line %d: Line too long", cfp->name, cfp->line_number);

    return apr_psprintf(p, "Error reading %s at line %d: %pm", cfp->name, cfp->line_number, &rc);
}



static apr_status_t ap_cfg_getline_core(char *buf, apr_size_t bufsize, ap_configfile_t *cfp)
{
    apr_status_t rc;
    
    if (cfp->getstr != NULL) {
        char *cp;
        char *cbuf = buf;
        apr_size_t cbufsize = bufsize;

        while (1) {
            ++cfp->line_number;
            rc = cfp->getstr(cbuf, cbufsize, cfp->param);
            if (rc == APR_EOF) {
                if (cbuf != buf) {
                    *cbuf = '\0';
                    break;
                }
                else {
                    return APR_EOF;
                }
            }
            if (rc != APR_SUCCESS) {
                return rc;
            }

            
            cp = cbuf;
            cp += strlen(cp);
            if (cp > cbuf && cp[-1] == LF) {
                cp--;
                if (cp > cbuf && cp[-1] == CR)
                    cp--;
                if (cp > cbuf && cp[-1] == '\\') {
                    cp--;
                    
                    cbufsize -= (cp-cbuf);
                    cbuf = cp;
                    continue;
                }
            }
            else if (cp - buf >= bufsize - 1) {
                return APR_ENOSPC;
            }
            break;
        }
    } else {
        
        apr_size_t i = 0;

        if (bufsize < 2) {
            
            return APR_EINVAL;
        }
        buf[0] = '\0';

        while (1) {
            char c;
            rc = cfp->getch(&c, cfp->param);
            if (rc == APR_EOF) {
                if (i > 0)
                    break;
                else return APR_EOF;
            }
            if (rc != APR_SUCCESS)
                return rc;
            if (c == LF) {
                ++cfp->line_number;
                
                if (i > 0 && buf[i-1] == '\\') {
                    i--;
                    continue;
                }
                else {
                    break;
                }
            }
            else if (i >= bufsize - 2) {
                return APR_ENOSPC;
            }
            buf[i] = c;
            ++i;
        }
        buf[i] = '\0';
    }
    return APR_SUCCESS;
}

static int cfg_trim_line(char *buf)
{
    char *start, *end;
    
    start = buf;
    while (apr_isspace(*start))
        ++start;
    
    end = &start[strlen(start)];
    while (--end >= start && apr_isspace(*end))
        *end = '\0';
    
    if (start != buf)
        memmove(buf, start, end - start + 2);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, APLOGNO(00555) "Read config: '%s'", buf);

    return end - start + 1;
}



AP_DECLARE(apr_status_t) ap_cfg_getline(char *buf, apr_size_t bufsize, ap_configfile_t *cfp)
{
    apr_status_t rc = ap_cfg_getline_core(buf, bufsize, cfp);
    if (rc == APR_SUCCESS)
        cfg_trim_line(buf);
    return rc;
}

AP_DECLARE(apr_status_t) ap_varbuf_cfg_getline(struct ap_varbuf *vb, ap_configfile_t *cfp, apr_size_t max_len)

{
    apr_status_t rc;
    apr_size_t new_len;
    vb->strlen = 0;
    *vb->buf = '\0';

    if (vb->strlen == AP_VARBUF_UNKNOWN)
        vb->strlen = strlen(vb->buf);
    if (vb->avail - vb->strlen < 3) {
        new_len = vb->avail * 2;
        if (new_len > max_len)
            new_len = max_len;
        else if (new_len < 3)
            new_len = 3;
        ap_varbuf_grow(vb, new_len);
    }

    for (;;) {
        rc = ap_cfg_getline_core(vb->buf + vb->strlen, vb->avail - vb->strlen, cfp);
        if (rc == APR_ENOSPC || rc == APR_SUCCESS)
            vb->strlen += strlen(vb->buf + vb->strlen);
        if (rc != APR_ENOSPC)
            break;
        if (vb->avail >= max_len)
            return APR_ENOSPC;
        new_len = vb->avail * 2;
        if (new_len > max_len)
            new_len = max_len;
        ap_varbuf_grow(vb, new_len);
        --cfp->line_number;
    }
    if (vb->strlen > max_len)
        return APR_ENOSPC;
    if (rc == APR_SUCCESS)
        vb->strlen = cfg_trim_line(vb->buf);
    return rc;
}


AP_DECLARE(const char *) ap_size_list_item(const char **field, int *len)
{
    const unsigned char *ptr = (const unsigned char *)*field;
    const unsigned char *token;
    int in_qpair, in_qstr, in_com;

    

    while (*ptr == ',' || apr_isspace(*ptr))
        ++ptr;

    token = ptr;

    

    for (in_qpair = in_qstr = in_com = 0;
         *ptr && (in_qpair || in_qstr || in_com || *ptr != ',');
         ++ptr) {

        if (in_qpair) {
            in_qpair = 0;
        }
        else {
            switch (*ptr) {
                case '\\': in_qpair = 1;      
                           break;
                case '"' : if (!in_com)       
                               in_qstr = !in_qstr;
                           break;
                case '(' : if (!in_qstr)      
                               ++in_com;
                           break;
                case ')' : if (in_com)        
                               --in_com;
                           break;
                default  : break;
            }
        }
    }

    if ((*len = (ptr - token)) == 0) {
        *field = (const char *)ptr;
        return NULL;
    }

    

    while (*ptr == ',' || apr_isspace(*ptr))
        ++ptr;

    *field = (const char *)ptr;
    return (const char *)token;
}


AP_DECLARE(char *) ap_get_list_item(apr_pool_t *p, const char **field)
{
    const char *tok_start;
    const unsigned char *ptr;
    unsigned char *pos;
    char *token;
    int addspace = 0, in_qpair = 0, in_qstr = 0, in_com = 0, tok_len = 0;

    
    if ((tok_start = ap_size_list_item(field, &tok_len)) == NULL) {
        return NULL;
    }
    token = apr_palloc(p, tok_len + 1);

    
    for (ptr = (const unsigned char *)tok_start, pos = (unsigned char *)token;
         *ptr && (in_qpair || in_qstr || in_com || *ptr != ',');
         ++ptr) {

        if (in_qpair) {
            in_qpair = 0;
            *pos++ = *ptr;
        }
        else {
            switch (*ptr) {
                case '\\': in_qpair = 1;
                           if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case '"' : if (!in_com)
                               in_qstr = !in_qstr;
                           if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case '(' : if (!in_qstr)
                               ++in_com;
                           if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case ')' : if (in_com)
                               --in_com;
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case ' ' :
                case '\t': if (addspace)
                               break;
                           if (in_com || in_qstr)
                               *pos++ = *ptr;
                           else addspace = 1;
                           break;
                case '=' :
                case '/' :
                case ';' : if (!(in_com || in_qstr))
                               addspace = -1;
                           *pos++ = *ptr;
                           break;
                default  : if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = (in_com || in_qstr) ? *ptr : apr_tolower(*ptr);
                           addspace = 0;
                           break;
            }
        }
    }
    *pos = '\0';

    return token;
}

typedef enum ap_etag_e {
    AP_ETAG_NONE, AP_ETAG_WEAK, AP_ETAG_STRONG } ap_etag_e;




static int find_list_item(apr_pool_t *p, const char *line, const char *tok, ap_etag_e type)
{
    const unsigned char *pos;
    const unsigned char *ptr = (const unsigned char *)line;
    int good = 0, addspace = 0, in_qpair = 0, in_qstr = 0, in_com = 0;

    if (!line || !tok) {
        return 0;
    }
    if (type == AP_ETAG_STRONG && *tok != '\"') {
        return 0;
    }
    if (type == AP_ETAG_WEAK) {
        if (*tok == 'W' && (*(tok+1)) == '/' && (*(tok+2)) == '\"') {
            tok += 2;
        }
        else if (*tok != '\"') {
            return 0;
        }
    }

    do {  

        
        while (*ptr == ',' || apr_isspace(*ptr)) {
            ++ptr;
        }

        
        if (type == AP_ETAG_STRONG && *ptr != '\"') {
            break;
        }
        if (type == AP_ETAG_WEAK) {
            if (*ptr == 'W' && (*(ptr+1)) == '/' && (*(ptr+2)) == '\"') {
                ptr += 2;
            }
            else if (*ptr != '\"') {
                break;
            }
        }

        if (*ptr)
            good = 1;  
        else break;

        
        for (pos = (const unsigned char *)tok;
             *ptr && (in_qpair || in_qstr || in_com || *ptr != ',');
             ++ptr) {

            if (in_qpair) {
                in_qpair = 0;
                if (good)
                    good = (*pos++ == *ptr);
            }
            else {
                switch (*ptr) {
                    case '\\': in_qpair = 1;
                               if (addspace == 1)
                                   good = good && (*pos++ == ' ');
                               good = good && (*pos++ == *ptr);
                               addspace = 0;
                               break;
                    case '"' : if (!in_com)
                                   in_qstr = !in_qstr;
                               if (addspace == 1)
                                   good = good && (*pos++ == ' ');
                               good = good && (*pos++ == *ptr);
                               addspace = 0;
                               break;
                    case '(' : if (!in_qstr)
                                   ++in_com;
                               if (addspace == 1)
                                   good = good && (*pos++ == ' ');
                               good = good && (*pos++ == *ptr);
                               addspace = 0;
                               break;
                    case ')' : if (in_com)
                                   --in_com;
                               good = good && (*pos++ == *ptr);
                               addspace = 0;
                               break;
                    case ' ' :
                    case '\t': if (addspace || !good)
                                   break;
                               if (in_com || in_qstr)
                                   good = (*pos++ == *ptr);
                               else addspace = 1;
                               break;
                    case '=' :
                    case '/' :
                    case ';' : if (!(in_com || in_qstr))
                                   addspace = -1;
                               good = good && (*pos++ == *ptr);
                               break;
                    default  : if (!good)
                                   break;
                               if (addspace == 1)
                                   good = (*pos++ == ' ');
                               if (in_com || in_qstr)
                                   good = good && (*pos++ == *ptr);
                               else good = good && (apr_tolower(*pos++) == apr_tolower(*ptr));

                               addspace = 0;
                               break;
                }
            }
        }
        if (good && *pos)
            good = 0;          

    } while (*ptr && !good);

    return good;
}


AP_DECLARE(int) ap_find_list_item(apr_pool_t *p, const char *line, const char *tok)
{
    return find_list_item(p, line, tok, AP_ETAG_NONE);
}


AP_DECLARE(int) ap_find_etag_strong(apr_pool_t *p, const char *line, const char *tok)
{
    return find_list_item(p, line, tok, AP_ETAG_STRONG);
}


AP_DECLARE(int) ap_find_etag_weak(apr_pool_t *p, const char *line, const char *tok)
{
    return find_list_item(p, line, tok, AP_ETAG_WEAK);
}



AP_DECLARE(char *) ap_get_token(apr_pool_t *p, const char **accept_line, int accept_white)
{
    const char *ptr = *accept_line;
    const char *tok_start;
    char *token;

    

    while (apr_isspace(*ptr))
        ++ptr;

    tok_start = ptr;

    

    while (*ptr && (accept_white || !apr_isspace(*ptr))
           && *ptr != ';' && *ptr != ',') {
        if (*ptr++ == '"')
            while (*ptr)
                if (*ptr++ == '"')
                    break;
    }

    token = apr_pstrmemdup(p, tok_start, ptr - tok_start);

    

    while (apr_isspace(*ptr))
        ++ptr;

    *accept_line = ptr;
    return token;
}



AP_DECLARE(int) ap_find_token(apr_pool_t *p, const char *line, const char *tok)
{
    const unsigned char *start_token;
    const unsigned char *s;

    if (!line)
        return 0;

    s = (const unsigned char *)line;
    for (;;) {
        
        while (TEST_CHAR(*s, T_HTTP_TOKEN_STOP)) {
            ++s;
        }
        if (!*s) {
            return 0;
        }
        start_token = s;
        
        while (*s && !TEST_CHAR(*s, T_HTTP_TOKEN_STOP)) {
            ++s;
        }
        if (!strncasecmp((const char *)start_token, (const char *)tok, s - start_token)) {
            return 1;
        }
        if (!*s) {
            return 0;
        }
    }
}


AP_DECLARE(int) ap_find_last_token(apr_pool_t *p, const char *line, const char *tok)
{
    int llen, tlen, lidx;

    if (!line)
        return 0;

    llen = strlen(line);
    tlen = strlen(tok);
    lidx = llen - tlen;

    if (lidx < 0 || (lidx > 0 && !(apr_isspace(line[lidx - 1]) || line[lidx - 1] == ',')))
        return 0;

    return (strncasecmp(&line[lidx], tok, tlen) == 0);
}

AP_DECLARE(char *) ap_escape_shell_cmd(apr_pool_t *p, const char *str)
{
    char *cmd;
    unsigned char *d;
    const unsigned char *s;

    cmd = apr_palloc(p, 2 * strlen(str) + 1);        
    d = (unsigned char *)cmd;
    s = (const unsigned char *)str;
    for (; *s; ++s) {


        
        if (*s == '\r' || *s == '\n') {
             *d++ = ' ';
             continue;
         }


        if (TEST_CHAR(*s, T_ESCAPE_SHELL_CMD)) {
            *d++ = '\\';
        }
        *d++ = *s;
    }
    *d = '\0';

    return cmd;
}

static char x2c(const char *what)
{
    char digit;


    digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));

    char xstr[5];
    xstr[0]='0';
    xstr[1]='x';
    xstr[2]=what[0];
    xstr[3]=what[1];
    xstr[4]='\0';
    digit = apr_xlate_conv_byte(ap_hdrs_from_ascii, 0xFF & strtol(xstr, NULL, 16));

    return (digit);
}



static int unescape_url(char *url, const char *forbid, const char *reserved)
{
    int badesc, badpath;
    char *x, *y;

    badesc = 0;
    badpath = 0;
    
    y = strchr(url, '%');
    if (y == NULL) {
        return OK;
    }
    for (x = y; *y; ++x, ++y) {
        if (*y != '%') {
            *x = *y;
        }
        else {
            if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
                badesc = 1;
                *x = '%';
            }
            else {
                char decoded;
                decoded = x2c(y + 1);
                if ((decoded == '\0')
                    || (forbid && ap_strchr_c(forbid, decoded))) {
                    badpath = 1;
                    *x = decoded;
                    y += 2;
                }
                else if (reserved && ap_strchr_c(reserved, decoded)) {
                    *x++ = *y++;
                    *x++ = *y++;
                    *x = *y;
                }
                else {
                    *x = decoded;
                    y += 2;
                }
            }
        }
    }
    *x = '\0';
    if (badesc) {
        return HTTP_BAD_REQUEST;
    }
    else if (badpath) {
        return HTTP_NOT_FOUND;
    }
    else {
        return OK;
    }
}
AP_DECLARE(int) ap_unescape_url(char *url)
{
    
    return unescape_url(url, SLASHES, NULL);
}
AP_DECLARE(int) ap_unescape_url_keep2f(char *url, int decode_slashes)
{
    
    if (decode_slashes) {
        
        return unescape_url(url, NULL, NULL);
    } else {
        
        return unescape_url(url, NULL, SLASHES);
    }
}


AP_DECLARE(int) ap_unescape_url_proxy(char *url)
{
    
    return unescape_url(url, NULL, "/;?");
}
AP_DECLARE(int) ap_unescape_url_reserved(char *url, const char *reserved)
{
    return unescape_url(url, NULL, reserved);
}


AP_DECLARE(int) ap_unescape_urlencoded(char *query)
{
    char *slider;

    
    if (query) {
        for (slider = query; *slider; slider++) {
            if (*slider == '+') {
                *slider = ' ';
            }
        }
    }

    
    return unescape_url(query, NULL, NULL);
}

AP_DECLARE(char *) ap_construct_server(apr_pool_t *p, const char *hostname, apr_port_t port, const request_rec *r)
{
    if (ap_is_default_port(port, r)) {
        return apr_pstrdup(p, hostname);
    }
    else {
        return apr_psprintf(p, "%s:%u", hostname, port);
    }
}

AP_DECLARE(int) ap_unescape_all(char *url)
{
    return unescape_url(url, NULL, NULL);
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



AP_DECLARE(char *) ap_escape_path_segment_buffer(char *copy, const char *segment)
{
    const unsigned char *s = (const unsigned char *)segment;
    unsigned char *d = (unsigned char *)copy;
    unsigned c;

    while ((c = *s)) {
        if (TEST_CHAR(c, T_ESCAPE_PATH_SEGMENT)) {
            d = c2x(c, '%', d);
        }
        else {
            *d++ = c;
        }
        ++s;
    }
    *d = '\0';
    return copy;
}

AP_DECLARE(char *) ap_escape_path_segment(apr_pool_t *p, const char *segment)
{
    return ap_escape_path_segment_buffer(apr_palloc(p, 3 * strlen(segment) + 1), segment);
}

AP_DECLARE(char *) ap_os_escape_path(apr_pool_t *p, const char *path, int partial)
{
    
    char *copy = apr_palloc(p, 3 * strlen(path) + 3 + 1);
    const unsigned char *s = (const unsigned char *)path;
    unsigned char *d = (unsigned char *)copy;
    unsigned c;

    if (!partial) {
        const char *colon = ap_strchr_c(path, ':');
        const char *slash = ap_strchr_c(path, '/');

        if (colon && (!slash || colon < slash)) {
            *d++ = '.';
            *d++ = '/';
        }
    }
    while ((c = *s)) {
        if (TEST_CHAR(c, T_OS_ESCAPE_PATH)) {
            d = c2x(c, '%', d);
        }
        else {
            *d++ = c;
        }
        ++s;
    }
    *d = '\0';
    return copy;
}

AP_DECLARE(char *) ap_escape_urlencoded_buffer(char *copy, const char *buffer)
{
    const unsigned char *s = (const unsigned char *)buffer;
    unsigned char *d = (unsigned char *)copy;
    unsigned c;

    while ((c = *s)) {
        if (TEST_CHAR(c, T_ESCAPE_URLENCODED)) {
            d = c2x(c, '%', d);
        }
        else if (c == ' ') {
            *d++ = '+';
        }
        else {
            *d++ = c;
        }
        ++s;
    }
    *d = '\0';
    return copy;
}

AP_DECLARE(char *) ap_escape_urlencoded(apr_pool_t *p, const char *buffer)
{
    return ap_escape_urlencoded_buffer(apr_palloc(p, 3 * strlen(buffer) + 1), buffer);
}



AP_DECLARE(char *) ap_escape_html2(apr_pool_t *p, const char *s, int toasc)
{
    int i, j;
    char *x;

    
    for (i = 0, j = 0; s[i] != '\0'; i++)
        if (s[i] == '<' || s[i] == '>')
            j += 3;
        else if (s[i] == '&')
            j += 4;
        else if (s[i] == '"')
            j += 5;
        else if (toasc && !apr_isascii(s[i]))
            j += 5;

    if (j == 0)
        return apr_pstrmemdup(p, s, i);

    x = apr_palloc(p, i + j + 1);
    for (i = 0, j = 0; s[i] != '\0'; i++, j++)
        if (s[i] == '<') {
            memcpy(&x[j], "&lt;", 4);
            j += 3;
        }
        else if (s[i] == '>') {
            memcpy(&x[j], "&gt;", 4);
            j += 3;
        }
        else if (s[i] == '&') {
            memcpy(&x[j], "&amp;", 5);
            j += 4;
        }
        else if (s[i] == '"') {
            memcpy(&x[j], "&quot;", 6);
            j += 5;
        }
        else if (toasc && !apr_isascii(s[i])) {
            char *esc = apr_psprintf(p, "&#%3.3d;", (unsigned char)s[i]);
            memcpy(&x[j], esc, 6);
            j += 5;
        }
        else x[j] = s[i];

    x[j] = '\0';
    return x;
}
AP_DECLARE(char *) ap_escape_logitem(apr_pool_t *p, const char *str)
{
    char *ret;
    unsigned char *d;
    const unsigned char *s;
    apr_size_t length, escapes = 0;

    if (!str) {
        return NULL;
    }

    
    s = (const unsigned char *)str;
    for (; *s; ++s) {
        if (TEST_CHAR(*s, T_ESCAPE_LOGITEM)) {
            escapes++;
        }
    }
    
    
    length = s - (const unsigned char *)str + 1;
    
    
    if (escapes == 0) {
        return apr_pmemdup(p, str, length);
    }
    
    
    ret = apr_palloc(p, length + 3 * escapes);
    d = (unsigned char *)ret;
    s = (const unsigned char *)str;
    for (; *s; ++s) {
        if (TEST_CHAR(*s, T_ESCAPE_LOGITEM)) {
            *d++ = '\\';
            switch(*s) {
            case '\b':
                *d++ = 'b';
                break;
            case '\n':
                *d++ = 'n';
                break;
            case '\r':
                *d++ = 'r';
                break;
            case '\t':
                *d++ = 't';
                break;
            case '\v':
                *d++ = 'v';
                break;
            case '\\':
            case '"':
                *d++ = *s;
                break;
            default:
                c2x(*s, 'x', d);
                d += 3;
            }
        }
        else {
            *d++ = *s;
        }
    }
    *d = '\0';

    return ret;
}

AP_DECLARE(apr_size_t) ap_escape_errorlog_item(char *dest, const char *source, apr_size_t buflen)
{
    unsigned char *d, *ep;
    const unsigned char *s;

    if (!source || !buflen) { 
        return 0;
    }

    d = (unsigned char *)dest;
    s = (const unsigned char *)source;
    ep = d + buflen - 1;

    for (; d < ep && *s; ++s) {

        if (TEST_CHAR(*s, T_ESCAPE_LOGITEM)) {
            *d++ = '\\';
            if (d >= ep) {
                --d;
                break;
            }

            switch(*s) {
            case '\b':
                *d++ = 'b';
                break;
            case '\n':
                *d++ = 'n';
                break;
            case '\r':
                *d++ = 'r';
                break;
            case '\t':
                *d++ = 't';
                break;
            case '\v':
                *d++ = 'v';
                break;
            case '\\':
                *d++ = *s;
                break;
            case '"': 
                d[-1] = *s;
                break;
            default:
                if (d >= ep - 2) {
                    ep = --d; 
                    break;
                }
                c2x(*s, 'x', d);
                d += 3;
            }
        }
        else {
            *d++ = *s;
        }
    }
    *d = '\0';

    return (d - (unsigned char *)dest);
}

AP_DECLARE(void) ap_bin2hex(const void *src, apr_size_t srclen, char *dest)
{
    const unsigned char *in = src;
    apr_size_t i;

    for (i = 0; i < srclen; i++) {
        *dest++ = c2x_table[in[i] >> 4];
        *dest++ = c2x_table[in[i] & 0xf];
    }
    *dest = '\0';
}

AP_DECLARE(int) ap_has_cntrl(const char *str)
{
    while (*str) {
        if (apr_iscntrl(*str))
            return 1;
        str++;
    }
    return 0;
}

AP_DECLARE(int) ap_is_directory(apr_pool_t *p, const char *path)
{
    apr_finfo_t finfo;

    if (apr_stat(&finfo, path, APR_FINFO_TYPE, p) != APR_SUCCESS)
        return 0;                

    return (finfo.filetype == APR_DIR);
}

AP_DECLARE(int) ap_is_rdirectory(apr_pool_t *p, const char *path)
{
    apr_finfo_t finfo;

    if (apr_stat(&finfo, path, APR_FINFO_LINK | APR_FINFO_TYPE, p) != APR_SUCCESS)
        return 0;                

    return (finfo.filetype == APR_DIR);
}

AP_DECLARE(char *) ap_make_full_path(apr_pool_t *a, const char *src1, const char *src2)
{
    apr_size_t len1, len2;
    char *path;

    len1 = strlen(src1);
    len2 = strlen(src2);
     
    path = (char *)apr_palloc(a, len1 + len2 + 3);
    if (len1 == 0) {
        *path = '/';
        memcpy(path + 1, src2, len2 + 1);
    }
    else {
        char *next;
        memcpy(path, src1, len1);
        next = path + len1;
        if (next[-1] != '/') {
            *next++ = '/';
        }
        memcpy(next, src2, len2 + 1);
    }
    return path;
}


AP_DECLARE(int) ap_is_url(const char *u)
{
    int x;

    for (x = 0; u[x] != ':'; x++) {
        if ((!u[x]) || ((!apr_isalnum(u[x])) && (u[x] != '+') && (u[x] != '-') && (u[x] != '.'))) {

            return 0;
        }
    }

    return (x ? 1 : 0);                
}

AP_DECLARE(int) ap_ind(const char *s, char c)
{
    const char *p = ap_strchr_c(s, c);

    if (p == NULL)
        return -1;
    return p - s;
}

AP_DECLARE(int) ap_rind(const char *s, char c)
{
    const char *p = ap_strrchr_c(s, c);

    if (p == NULL)
        return -1;
    return p - s;
}

AP_DECLARE(void) ap_str_tolower(char *str)
{
    while (*str) {
        *str = apr_tolower(*str);
        ++str;
    }
}

AP_DECLARE(void) ap_str_toupper(char *str)
{
    while (*str) {
        *str = apr_toupper(*str);
        ++str;
    }
}


char *ap_get_local_host(apr_pool_t *a)
{



    char str[MAXHOSTNAMELEN + 1];
    char *server_hostname = NULL;
    apr_sockaddr_t *sockaddr;
    char *hostname;

    if (apr_gethostname(str, sizeof(str) - 1, a) != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP | APLOG_WARNING, 0, a, APLOGNO(00556)
                     "%s: apr_gethostname() failed to determine ServerName", ap_server_argv0);
    } else {
        str[sizeof(str) - 1] = '\0';
        if (apr_sockaddr_info_get(&sockaddr, str, APR_UNSPEC, 0, 0, a) == APR_SUCCESS) {
            if ( (apr_getnameinfo(&hostname, sockaddr, 0) == APR_SUCCESS) && (ap_strchr_c(hostname, '.')) ) {
                server_hostname = apr_pstrdup(a, hostname);
                return server_hostname;
            } else if (ap_strchr_c(str, '.')) {
                server_hostname = apr_pstrdup(a, str);
            } else {
                apr_sockaddr_ip_get(&hostname, sockaddr);
                server_hostname = apr_pstrdup(a, hostname);
            }
        } else {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP | APLOG_WARNING, 0, a, APLOGNO(00557)
                         "%s: apr_sockaddr_info_get() failed for %s", ap_server_argv0, str);
        }
    }

    if (!server_hostname)
        server_hostname = apr_pstrdup(a, "127.0.0.1");

    ap_log_perror(APLOG_MARK, APLOG_ALERT|APLOG_STARTUP, 0, a, APLOGNO(00558)
                 "%s: Could not reliably determine the server's fully qualified " "domain name, using %s. Set the 'ServerName' directive globally " "to suppress this message", ap_server_argv0, server_hostname);



    return server_hostname;
}


AP_DECLARE(char *) ap_pbase64decode(apr_pool_t *p, const char *bufcoded)
{
    char *decoded;
    int l;

    decoded = (char *) apr_palloc(p, 1 + apr_base64_decode_len(bufcoded));
    l = apr_base64_decode(decoded, bufcoded);
    decoded[l] = '\0'; 

    return decoded;
}

AP_DECLARE(char *) ap_pbase64encode(apr_pool_t *p, char *string)
{
    char *encoded;
    int l = strlen(string);

    encoded = (char *) apr_palloc(p, 1 + apr_base64_encode_len(l));
    l = apr_base64_encode(encoded, string, l);
    encoded[l] = '\0'; 

    return encoded;
}


AP_DECLARE(void) ap_content_type_tolower(char *str)
{
    char *semi;

    semi = strchr(str, ';');
    if (semi) {
        *semi = '\0';
    }

    ap_str_tolower(str);

    if (semi) {
        *semi = ';';
    }
}


AP_DECLARE(char *) ap_escape_quotes(apr_pool_t *p, const char *instring)
{
    int newlen = 0;
    const char *inchr = instring;
    char *outchr, *outstring;

    
    while (*inchr != '\0') {
        newlen++;
        if (*inchr == '"') {
            newlen++;
        }
        
        if ((*inchr == '\\') && (inchr[1] != '\0')) {
            inchr++;
            newlen++;
        }
        inchr++;
    }
    outstring = apr_palloc(p, newlen + 1);
    inchr = instring;
    outchr = outstring;
    
    while (*inchr != '\0') {
        if ((*inchr == '\\') && (inchr[1] != '\0')) {
            *outchr++ = *inchr++;
            *outchr++ = *inchr++;
        }
        if (*inchr == '"') {
            *outchr++ = '\\';
        }
        if (*inchr != '\0') {
            *outchr++ = *inchr++;
        }
    }
    *outchr = '\0';
    return outstring;
}


AP_DECLARE(char *) ap_append_pid(apr_pool_t *p, const char *string, const char *delim)
{
    return apr_psprintf(p, "%s%s%" APR_PID_T_FMT, string, delim, getpid());

}


AP_DECLARE(apr_status_t) ap_timeout_parameter_parse( const char *timeout_parameter, apr_interval_time_t *timeout, const char *default_time_unit)


{
    char *endp;
    const char *time_str;
    apr_int64_t tout;

    tout = apr_strtoi64(timeout_parameter, &endp, 10);
    if (errno) {
        return errno;
    }
    if (!endp || !*endp) {
        time_str = default_time_unit;
    }
    else {
        time_str = endp;
    }

    switch (*time_str) {
        
    case 's':
        *timeout = (apr_interval_time_t) apr_time_from_sec(tout);
        break;
    case 'h':
        
        *timeout = (apr_interval_time_t) apr_time_from_sec(tout * 3600);
        break;
    case 'm':
        switch (*(++time_str)) {
        
        case 's':
            *timeout = (apr_interval_time_t) tout * 1000;
            break;
        
        case 'i':
            *timeout = (apr_interval_time_t) apr_time_from_sec(tout * 60);
            break;
        default:
            return APR_EGENERAL;
        }
        break;
    default:
        return APR_EGENERAL;
    }
    return APR_SUCCESS;
}


AP_DECLARE(int) ap_request_has_body(request_rec *r)
{
    apr_off_t cl;
    char *estr;
    const char *cls;
    int has_body;

    has_body = (!r->header_only && (r->kept_body || apr_table_get(r->headers_in, "Transfer-Encoding")

                    || ( (cls = apr_table_get(r->headers_in, "Content-Length"))
                        && (apr_strtoff(&cl, cls, &estr, 10) == APR_SUCCESS)
                        && (!*estr)
                        && (cl > 0) )
                    )
                );
    return has_body;
}

AP_DECLARE_NONSTD(apr_status_t) ap_pool_cleanup_set_null(void *data_)
{
    void **ptr = (void **)data_;
    *ptr = NULL;
    return APR_SUCCESS;
}

AP_DECLARE(apr_status_t) ap_str2_alnum(const char *src, char *dest) {

    for ( ; *src; src++, dest++)
    {
        if (!apr_isprint(*src))
            *dest = 'x';
        else if (!apr_isalnum(*src))
            *dest = '_';
        else *dest = (char)*src;
    }
    *dest = '\0';
    return APR_SUCCESS;

}

AP_DECLARE(apr_status_t) ap_pstr2_alnum(apr_pool_t *p, const char *src, const char **dest)
{
    char *new = apr_palloc(p, strlen(src)+1);
    if (!new)
        return APR_ENOMEM;
    *dest = new;
    return ap_str2_alnum(src, new);
}




typedef enum {
    FORM_NORMAL, FORM_AMP, FORM_NAME, FORM_VALUE, FORM_PERCENTA, FORM_PERCENTB, FORM_ABORT } ap_form_type_t;







AP_DECLARE(int) ap_parse_form_data(request_rec *r, ap_filter_t *f, apr_array_header_t **ptr, apr_size_t num, apr_size_t usize)

{
    apr_bucket_brigade *bb = NULL;
    int seen_eos = 0;
    char buffer[HUGE_STRING_LEN + 1];
    const char *ct;
    apr_size_t offset = 0;
    apr_ssize_t size;
    ap_form_type_t state = FORM_NAME, percent = FORM_NORMAL;
    ap_form_pair_t *pair = NULL;
    apr_array_header_t *pairs = apr_array_make(r->pool, 4, sizeof(ap_form_pair_t));

    char hi = 0;
    char low = 0;

    *ptr = pairs;

    
    ct = apr_table_get(r->headers_in, "Content-Type");
    if (!ct || strncasecmp("application/x-www-form-urlencoded", ct, 33)) {
        return ap_discard_request_body(r);
    }

    if (usize > APR_SIZE_MAX >> 1)
        size = APR_SIZE_MAX >> 1;
    else size = usize;

    if (!f) {
        f = r->input_filters;
    }

    bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
    do {
        apr_bucket *bucket = NULL, *last = NULL;

        int rv = ap_get_brigade(f, bb, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
        if (rv != APR_SUCCESS) {
            apr_brigade_destroy(bb);
            return ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
        }

        for (bucket = APR_BRIGADE_FIRST(bb);
             bucket != APR_BRIGADE_SENTINEL(bb);
             last = bucket, bucket = APR_BUCKET_NEXT(bucket)) {
            const char *data;
            apr_size_t len, slide;

            if (last) {
                apr_bucket_delete(last);
            }
            if (APR_BUCKET_IS_EOS(bucket)) {
                seen_eos = 1;
                break;
            }
            if (bucket->length == 0) {
                continue;
            }

            rv = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                apr_brigade_destroy(bb);
                return HTTP_BAD_REQUEST;
            }

            slide = len;
            while (state != FORM_ABORT && slide-- > 0 && size >= 0 && num != 0) {
                char c = *data++;
                if ('+' == c) {
                    c = ' ';
                }
                else if ('&' == c) {
                    state = FORM_AMP;
                }
                if ('%' == c) {
                    percent = FORM_PERCENTA;
                    continue;
                }
                if (FORM_PERCENTA == percent) {
                    if (c >= 'a') {
                        hi = c - 'a' + 10;
                    }
                    else if (c >= 'A') {
                        hi = c - 'A' + 10;
                    }
                    else if (c >= '0') {
                        hi = c - '0';
                    }
                    hi = hi << 4;
                    percent = FORM_PERCENTB;
                    continue;
                }
                if (FORM_PERCENTB == percent) {
                    if (c >= 'a') {
                        low = c - 'a' + 10;
                    }
                    else if (c >= 'A') {
                        low = c - 'A' + 10;
                    }
                    else if (c >= '0') {
                        low = c - '0';
                    }
                    c = low | hi;
                    percent = FORM_NORMAL;
                }
                switch (state) {
                    case FORM_AMP:
                        if (pair) {
                            const char *tmp = apr_pmemdup(r->pool, buffer, offset);
                            apr_bucket *b = apr_bucket_pool_create(tmp, offset, r->pool, r->connection->bucket_alloc);
                            APR_BRIGADE_INSERT_TAIL(pair->value, b);
                        }
                        state = FORM_NAME;
                        pair = NULL;
                        offset = 0;
                        num--;
                        break;
                    case FORM_NAME:
                        if (offset < HUGE_STRING_LEN) {
                            if ('=' == c) {
                                buffer[offset] = 0;
                                offset = 0;
                                pair = (ap_form_pair_t *) apr_array_push(pairs);
                                pair->name = apr_pstrdup(r->pool, buffer);
                                pair->value = apr_brigade_create(r->pool, r->connection->bucket_alloc);
                                state = FORM_VALUE;
                            }
                            else {
                                buffer[offset++] = c;
                                size--;
                            }
                        }
                        else {
                            state = FORM_ABORT;
                        }
                        break;
                    case FORM_VALUE:
                        if (offset >= HUGE_STRING_LEN) {
                            const char *tmp = apr_pmemdup(r->pool, buffer, offset);
                            apr_bucket *b = apr_bucket_pool_create(tmp, offset, r->pool, r->connection->bucket_alloc);
                            APR_BRIGADE_INSERT_TAIL(pair->value, b);
                            offset = 0;
                        }
                        buffer[offset++] = c;
                        size--;
                        break;
                    default:
                        break;
                }
            }

        }

        apr_brigade_cleanup(bb);
    } while (!seen_eos);

    if (FORM_ABORT == state || size < 0 || num == 0) {
        return HTTP_REQUEST_ENTITY_TOO_LARGE;
    }
    else if (FORM_VALUE == state && pair && offset > 0) {
        const char *tmp = apr_pmemdup(r->pool, buffer, offset);
        apr_bucket *b = apr_bucket_pool_create(tmp, offset, r->pool, r->connection->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pair->value, b);
    }

    return OK;

}




struct ap_varbuf_info {
    struct apr_memnode_t *node;
    apr_allocator_t *allocator;
};

static apr_status_t varbuf_cleanup(void *info_)
{
    struct ap_varbuf_info *info = info_;
    info->node->next = NULL;
    apr_allocator_free(info->allocator, info->node);
    return APR_SUCCESS;
}

const char nul = '\0';
static char * const varbuf_empty = (char *)&nul;

AP_DECLARE(void) ap_varbuf_init(apr_pool_t *p, struct ap_varbuf *vb, apr_size_t init_size)
{
    vb->buf = varbuf_empty;
    vb->avail = 0;
    vb->strlen = AP_VARBUF_UNKNOWN;
    vb->pool = p;
    vb->info = NULL;

    ap_varbuf_grow(vb, init_size);
}

AP_DECLARE(void) ap_varbuf_grow(struct ap_varbuf *vb, apr_size_t new_len)
{
    apr_memnode_t *new_node = NULL;
    apr_allocator_t *allocator;
    struct ap_varbuf_info *new_info;
    char *new;

    AP_DEBUG_ASSERT(vb->strlen == AP_VARBUF_UNKNOWN || vb->avail >= vb->strlen);

    if (new_len <= vb->avail)
        return;

    if (new_len < 2 * vb->avail && vb->avail < VARBUF_MAX_SIZE/2) {
        
        new_len = 2 * vb->avail;
    }
    else if (new_len > VARBUF_MAX_SIZE) {
        apr_abortfunc_t abort_fn = apr_pool_abort_get(vb->pool);
        ap_assert(abort_fn != NULL);
        abort_fn(APR_ENOMEM);
        return;
    }

    new_len++;  
    if (new_len <= VARBUF_SMALL_SIZE) {
        new_len = APR_ALIGN_DEFAULT(new_len);
        new = apr_palloc(vb->pool, new_len);
        if (vb->avail && vb->strlen != 0) {
            AP_DEBUG_ASSERT(vb->buf != NULL);
            AP_DEBUG_ASSERT(vb->buf != varbuf_empty);
            if (new == vb->buf + vb->avail + 1) {
                
                vb->avail += new_len;
                return;
            }
            else {
                
                memcpy(new, vb->buf, vb->strlen == AP_VARBUF_UNKNOWN ? vb->avail + 1 : vb->strlen + 1);
            }
        }
        else {
            *new = '\0';
        }
        vb->avail = new_len - 1;
        vb->buf = new;
        return;
    }

    
    allocator = apr_pool_allocator_get(vb->pool);
    if (new_len <= VARBUF_MAX_SIZE)
        new_node = apr_allocator_alloc(allocator, new_len + APR_ALIGN_DEFAULT(sizeof(*new_info)));
    if (!new_node) {
        apr_abortfunc_t abort_fn = apr_pool_abort_get(vb->pool);
        ap_assert(abort_fn != NULL);
        abort_fn(APR_ENOMEM);
        return;
    }
    new_info = (struct ap_varbuf_info *)new_node->first_avail;
    new_node->first_avail += APR_ALIGN_DEFAULT(sizeof(*new_info));
    new_info->node = new_node;
    new_info->allocator = allocator;
    new = new_node->first_avail;
    AP_DEBUG_ASSERT(new_node->endp - new_node->first_avail >= new_len);
    new_len = new_node->endp - new_node->first_avail;

    if (vb->avail && vb->strlen != 0)
        memcpy(new, vb->buf, vb->strlen == AP_VARBUF_UNKNOWN ? vb->avail + 1 : vb->strlen + 1);
    else *new = '\0';
    if (vb->info)
        apr_pool_cleanup_run(vb->pool, vb->info, varbuf_cleanup);
    apr_pool_cleanup_register(vb->pool, new_info, varbuf_cleanup, apr_pool_cleanup_null);
    vb->info = new_info;
    vb->buf = new;
    vb->avail = new_len - 1;
}

AP_DECLARE(void) ap_varbuf_strmemcat(struct ap_varbuf *vb, const char *str, int len)
{
    if (len == 0)
        return;
    if (!vb->avail) {
        ap_varbuf_grow(vb, len);
        memcpy(vb->buf, str, len);
        vb->buf[len] = '\0';
        vb->strlen = len;
        return;
    }
    if (vb->strlen == AP_VARBUF_UNKNOWN)
        vb->strlen = strlen(vb->buf);
    ap_varbuf_grow(vb, vb->strlen + len);
    memcpy(vb->buf + vb->strlen, str, len);
    vb->strlen += len;
    vb->buf[vb->strlen] = '\0';
}

AP_DECLARE(void) ap_varbuf_free(struct ap_varbuf *vb)
{
    if (vb->info) {
        apr_pool_cleanup_run(vb->pool, vb->info, varbuf_cleanup);
        vb->info = NULL;
    }
    vb->buf = NULL;
}

AP_DECLARE(char *) ap_varbuf_pdup(apr_pool_t *p, struct ap_varbuf *buf, const char *prepend, apr_size_t prepend_len, const char *append, apr_size_t append_len, apr_size_t *new_len)


{
    apr_size_t i = 0;
    struct iovec vec[3];

    if (prepend) {
        vec[i].iov_base = (void *)prepend;
        vec[i].iov_len = prepend_len;
        i++;
    }
    if (buf->avail && buf->strlen) {
        if (buf->strlen == AP_VARBUF_UNKNOWN)
            buf->strlen = strlen(buf->buf);
        vec[i].iov_base = (void *)buf->buf;
        vec[i].iov_len = buf->strlen;
        i++;
    }
    if (append) {
        vec[i].iov_base = (void *)append;
        vec[i].iov_len = append_len;
        i++;
    }
    if (i)
        return apr_pstrcatv(p, vec, i, new_len);

    if (new_len)
        *new_len = 0;
    return "";
}

AP_DECLARE(apr_status_t) ap_varbuf_regsub(struct ap_varbuf *vb, const char *input, const char *source, apr_size_t nmatch, ap_regmatch_t pmatch[], apr_size_t maxlen)




{
    return regsub_core(NULL, NULL, vb, input, source, nmatch, pmatch, maxlen);
}

static const char * const oom_message = "[crit] Memory allocation failed, " "aborting process." APR_EOL_STR;

AP_DECLARE(void) ap_abort_on_oom()
{
    int written, count = strlen(oom_message);
    const char *buf = oom_message;
    do {
        written = write(STDERR_FILENO, buf, count);
        if (written == count)
            break;
        if (written > 0) {
            buf += written;
            count -= written;
        }
    } while (written >= 0 || errno == EINTR);
    abort();
}

AP_DECLARE(void *) ap_malloc(size_t size)
{
    void *p = malloc(size);
    if (p == NULL && size != 0)
        ap_abort_on_oom();
    return p;
}

AP_DECLARE(void *) ap_calloc(size_t nelem, size_t size)
{
    void *p = calloc(nelem, size);
    if (p == NULL && nelem != 0 && size != 0)
        ap_abort_on_oom();
    return p;
}

AP_DECLARE(void *) ap_realloc(void *ptr, size_t size)
{
    void *p = realloc(ptr, size);
    if (p == NULL && size != 0)
        ap_abort_on_oom();
    return p;
}

AP_DECLARE(void) ap_get_sload(ap_sload_t *ld)
{
    int i, j, server_limit, thread_limit;
    int ready = 0;
    int busy = 0;
    int total;
    ap_generation_t mpm_generation;

    
    ld->idle = -1;
    ld->busy = -1;
    ld->bytes_served = 0;
    ld->access_count = 0;

    ap_mpm_query(AP_MPMQ_GENERATION, &mpm_generation);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);

    for (i = 0; i < server_limit; i++) {
        process_score *ps;
        ps = ap_get_scoreboard_process(i);

        for (j = 0; j < thread_limit; j++) {
            int res;
            worker_score *ws = NULL;
            ws = &ap_scoreboard_image->servers[i][j];
            res = ws->status;

            if (!ps->quiescing && ps->pid) {
                if (res == SERVER_READY && ps->generation == mpm_generation) {
                    ready++;
                }
                else if (res != SERVER_DEAD && res != SERVER_STARTING && res != SERVER_IDLE_KILL && ps->generation == mpm_generation) {

                    busy++;
                }   
            }

            if (ap_extended_status && !ps->quiescing && ps->pid) {
                if (ws->access_count != 0  || (res != SERVER_READY && res != SERVER_DEAD)) {
                    ld->access_count += ws->access_count;
                    ld->bytes_served += ws->bytes_served;
                }
            }
        }
    }
    total = busy + ready;
    if (total) {
        ld->idle = ready * 100 / total;
        ld->busy = busy * 100 / total;
    }
}

AP_DECLARE(void) ap_get_loadavg(ap_loadavg_t *ld)
{
    
    ld->loadavg = -1.0;
    ld->loadavg5 = -1.0;
    ld->loadavg15 = -1.0;


    {
        double la[3];
        int num;

        num = getloadavg(la, 3);
        if (num > 0) {
            ld->loadavg = (float)la[0];
        }
        if (num > 1) {
            ld->loadavg5 = (float)la[1];
        }
        if (num > 2) {
            ld->loadavg15 = (float)la[2];
        }
    }

}

static const char * const pw_cache_note_name = "conn_cache_note";
struct pw_cache {
    
    struct ap_varbuf vb;
    apr_size_t pwlen;
    apr_status_t result;
};

AP_DECLARE(apr_status_t) ap_password_validate(request_rec *r, const char *username, const char *passwd, const char *hash)


{
    struct pw_cache *cache;
    apr_size_t hashlen;

    cache = (struct pw_cache *)apr_table_get(r->connection->notes, pw_cache_note_name);
    if (cache != NULL) {
        if (strncmp(passwd, cache->vb.buf, cache->pwlen) == 0 && strcmp(hash, cache->vb.buf + cache->pwlen) == 0) {
            return cache->result;
        }
        
        cache->vb.strlen = 0;
    }
    else {
        cache = apr_palloc(r->connection->pool, sizeof(struct pw_cache));
        ap_varbuf_init(r->connection->pool, &cache->vb, 0);
        apr_table_setn(r->connection->notes, pw_cache_note_name, (void *)cache);
    }
    cache->pwlen = strlen(passwd);
    hashlen = strlen(hash);
    ap_varbuf_grow(&cache->vb, cache->pwlen + hashlen + 1);
    memcpy(cache->vb.buf, passwd, cache->pwlen);
    memcpy(cache->vb.buf + cache->pwlen, hash, hashlen + 1);
    cache->result = apr_password_validate(passwd, hash);
    return cache->result;
}

AP_DECLARE(char *) ap_get_exec_line(apr_pool_t *p, const char *cmd, const char * const * argv)

{
    char buf[MAX_STRING_LEN];
    apr_procattr_t *procattr;
    apr_proc_t *proc;
    apr_file_t *fp;
    apr_size_t nbytes = 1;
    char c;
    int k;

    if (apr_procattr_create(&procattr, p) != APR_SUCCESS)
        return NULL;
    if (apr_procattr_io_set(procattr, APR_FULL_BLOCK, APR_FULL_BLOCK, APR_FULL_BLOCK) != APR_SUCCESS)
        return NULL;
    if (apr_procattr_dir_set(procattr, ap_make_dirstr_parent(p, cmd)) != APR_SUCCESS)
        return NULL;
    if (apr_procattr_cmdtype_set(procattr, APR_PROGRAM) != APR_SUCCESS)
        return NULL;
    proc = apr_pcalloc(p, sizeof(apr_proc_t));
    if (apr_proc_create(proc, cmd, argv, NULL, procattr, p) != APR_SUCCESS)
        return NULL;
    fp = proc->out;

    if (fp == NULL)
        return NULL;
    
    for (k = 0; apr_file_read(fp, &c, &nbytes) == APR_SUCCESS && nbytes == 1 && (k < MAX_STRING_LEN-1)     ; ) {
        if (c == '\n' || c == '\r')
            break;
        buf[k++] = c;
    }
    buf[k] = '\0'; 
    apr_file_close(fp);

    return apr_pstrndup(p, buf, k);
}
