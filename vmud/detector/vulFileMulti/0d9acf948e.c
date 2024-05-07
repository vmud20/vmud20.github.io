





















































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
        return apr_pstrndup(p, intype, semi - intype);
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
    register int x;

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

    if (ap_regcomp(preg, pattern, cflags)) {
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



AP_DECLARE(char *) ap_pregsub(apr_pool_t *p, const char *input, const char *source, size_t nmatch, ap_regmatch_t pmatch[])

{
    const char *src = input;
    char *dest, *dst;
    char c;
    size_t no;
    int len;

    if (!source)
        return NULL;
    if (!nmatch)
        return apr_pstrdup(p, src);

    

    len = 0;

    while ((c = *src++) != '\0') {
        if (c == '&')
            no = 0;
        else if (c == '$' && apr_isdigit(*src))
            no = *src++ - '0';
        else no = 10;

        if (no > 9) {                
            if (c == '\\' && (*src == '$' || *src == '&'))
                c = *src++;
            len++;
        }
        else if (no < nmatch && pmatch[no].rm_so < pmatch[no].rm_eo) {
            len += pmatch[no].rm_eo - pmatch[no].rm_so;
        }

    }

    dest = dst = apr_pcalloc(p, len + 1);

    

    src = input;

    while ((c = *src++) != '\0') {
        if (c == '&')
            no = 0;
        else if (c == '$' && apr_isdigit(*src))
            no = *src++ - '0';
        else no = 10;

        if (no > 9) {                
            if (c == '\\' && (*src == '$' || *src == '&'))
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

    return dest;
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
            register int m = l + 3, n;

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
    d = apr_palloc(p, l + 1);
    memcpy(d, s, l);
    d[l] = 0;
    return (d);
}


AP_DECLARE(int) ap_count_dirs(const char *path)
{
    register int x, n;

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
    res = (char *)apr_palloc(atrans, len + 1);
    memcpy(res, *line, len);
    res[len] = 0;

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
    res = (char *)apr_palloc(atrans, len + 1);
    memcpy(res, *line, len);
    res[len] = 0;

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
        res = apr_pstrdup(atrans, *line);
        *line += strlen(*line);
        return res;
    }

    res = apr_pstrndup(atrans, *line, pos - *line);

    ++pos;

    *line = pos;

    return res;
}



static char *substring_conf(apr_pool_t *p, const char *start, int len, char quote)
{
    char *result = apr_palloc(p, len + 2);
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

    while (*str && apr_isspace(*str))
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

    while (*strend && apr_isspace(*strend))
        ++strend;
    *line = strend;
    return res;
}


AP_DECLARE(const char *) ap_resolve_env(apr_pool_t *p, const char * word)
{

    struct sll {
        struct sll *next;
        const char *string;
        apr_size_t len;
    } *result, *current, sresult[SMALL_EXPANSION];
    char *res_buf, *cp;
    const char *s, *e, *ep;
    unsigned spc;
    apr_size_t outlen;

    s = ap_strchr_c(word, '$');
    if (!s) {
        return word;
    }

    
    ep = word + strlen(word);
    spc = 0;
    result = current = &(sresult[spc++]);
    current->next = NULL;
    current->string = word;
    current->len = s - word;
    outlen = current->len;

    do {
        
        if (current->len) {
            current->next = (spc < SMALL_EXPANSION)
                            ? &(sresult[spc++])
                            : (struct sll *)apr_palloc(p, sizeof(*current->next));
            current = current->next;
            current->next = NULL;
            current->len = 0;
        }

        if (*s == '$') {
            if (s[1] == '{' && (e = ap_strchr_c(s, '}'))) {
                word = getenv(apr_pstrndup(p, s+2, e-s-2));
                if (word) {
                    current->string = word;
                    current->len = strlen(word);
                    outlen += current->len;
                }
                else {
                    current->string = s;
                    current->len = e - s + 1;
                    outlen += current->len;
                }
                s = e + 1;
            }
            else {
                current->string = s++;
                current->len = 1;
                ++outlen;
            }
        }
        else {
            word = s;
            s = ap_strchr_c(s, '$');
            current->string = word;
            current->len = s ? s - word : ep - word;
            outlen += current->len;
        }
    } while (s && *s);

    
    res_buf = cp = apr_palloc(p, outlen + 1);
    do {
        if (result->len) {
            memcpy(cp, result->string, result->len);
            cp += result->len;
        }
        result = result->next;
    } while (result);
    res_buf[outlen] = '\0';

    return res_buf;
}

AP_DECLARE(int) ap_cfg_closefile(ap_configfile_t *cfp)
{

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "Done with config file %s", cfp->name);

    return (cfp->close == NULL) ? 0 : cfp->close(cfp->param);
}

static apr_status_t cfg_close(void *param)
{
    apr_file_t *cfp = (apr_file_t *) param;
    return (apr_file_close(cfp));
}

static int cfg_getch(void *param)
{
    char ch;
    apr_file_t *cfp = (apr_file_t *) param;
    if (apr_file_getc(&ch, cfp) == APR_SUCCESS)
        return ch;
    return (int)EOF;
}

static void *cfg_getstr(void *buf, size_t bufsiz, void *param)
{
    apr_file_t *cfp = (apr_file_t *) param;
    apr_status_t rv;
    rv = apr_file_gets(buf, bufsiz, cfp);
    if (rv == APR_SUCCESS) {
        return buf;
    }
    return NULL;
}


AP_DECLARE(apr_status_t) ap_pcfg_openfile(ap_configfile_t **ret_cfg, apr_pool_t *p, const char *name)
{
    ap_configfile_t *new_cfg;
    apr_file_t *file = NULL;
    apr_finfo_t finfo;
    apr_status_t status;

    char buf[120];


    if (name == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Internal error: pcfg_openfile() called with NULL filename");
        return APR_EBADF;
    }

    status = apr_file_open(&file, name, APR_READ | APR_BUFFERED, APR_OS_DEFAULT, p);

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "Opening config file %s (%s)", name, (status != APR_SUCCESS) ? apr_strerror(status, buf, sizeof(buf)) : "successful");



    if (status != APR_SUCCESS)
        return status;

    status = apr_file_info_get(&finfo, APR_FINFO_TYPE, file);
    if (status != APR_SUCCESS)
        return status;

    if (finfo.filetype != APR_REG &&  strcasecmp(apr_filepath_name_get(name), "nul") != 0) {


        strcmp(name, "/dev/null") != 0) {

        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Access to file %s denied by server: not a regular file", name);

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
    new_cfg->getch = (int (*)(void *)) cfg_getch;
    new_cfg->getstr = (void *(*)(void *, size_t, void *)) cfg_getstr;
    new_cfg->close = (int (*)(void *)) cfg_close;
    new_cfg->line_number = 0;
    *ret_cfg = new_cfg;
    return APR_SUCCESS;
}



AP_DECLARE(ap_configfile_t *) ap_pcfg_open_custom(apr_pool_t *p, const char *descr, void *param, int(*getch)(void *param), void *(*getstr) (void *buf, size_t bufsiz, void *param), int(*close_func)(void *param))




{
    ap_configfile_t *new_cfg = apr_palloc(p, sizeof(*new_cfg));

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "Opening config handler %s", descr);

    new_cfg->param = param;
    new_cfg->name = descr;
    new_cfg->getch = getch;
    new_cfg->getstr = getstr;
    new_cfg->close = close_func;
    new_cfg->line_number = 0;
    return new_cfg;
}


AP_DECLARE(int) ap_cfg_getc(ap_configfile_t *cfp)
{
    register int ch = cfp->getch(cfp->param);
    if (ch == LF)
        ++cfp->line_number;
    return ch;
}



AP_DECLARE(int) ap_cfg_getline(char *buf, size_t bufsize, ap_configfile_t *cfp)
{
    
    if (cfp->getstr != NULL) {
        char *src, *dst;
        char *cp;
        char *cbuf = buf;
        size_t cbufsize = bufsize;

        while (1) {
            ++cfp->line_number;
            if (cfp->getstr(cbuf, cbufsize, cfp->param) == NULL)
                return 1;

            
            cp = cbuf;
            while (cp < cbuf+cbufsize && *cp != '\0')
                cp++;
            if (cp > cbuf && cp[-1] == LF) {
                cp--;
                if (cp > cbuf && cp[-1] == CR)
                    cp--;
                if (cp > cbuf && cp[-1] == '\\') {
                    cp--;
                    if (!(cp > cbuf && cp[-1] == '\\')) {
                        
                        cbufsize -= (cp-cbuf);
                        cbuf = cp;
                        continue;
                    }
                    else {
                        
                        for ( ; cp < cbuf+cbufsize && *cp != '\0'; cp++)
                            cp[0] = cp[1];
                    }
                }
            }
            break;
        }

        
        src = buf;
        while (apr_isspace(*src))
            ++src;
        
        dst = &src[strlen(src)];
        while (--dst >= src && apr_isspace(*dst))
            *dst = '\0';
        
        if (src != buf)
            for (dst = buf; (*dst++ = *src++) != '\0'; )
                ;


        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "Read config: %s", buf);

        return 0;
    } else {
        
        register int c;
        register size_t i = 0;

        buf[0] = '\0';
        
        do {
            c = cfp->getch(cfp->param);
        } while (c == '\t' || c == ' ');

        if (c == EOF)
            return 1;

        if(bufsize < 2) {
            
            return 1;
        }

        while (1) {
            if ((c == '\t') || (c == ' ')) {
                buf[i++] = ' ';
                while ((c == '\t') || (c == ' '))
                    c = cfp->getch(cfp->param);
            }
            if (c == CR) {
                
                c = cfp->getch(cfp->param);
            }
            if (c == LF) {
                
                ++cfp->line_number;
            }
            if (c == EOF || c == 0x4 || c == LF || i >= (bufsize - 2)) {
                
                if (i > 0 && buf[i-1] == '\\') {
                    i--;
                    if (!(i > 0 && buf[i-1] == '\\')) {
                        
                        c = cfp->getch(cfp->param);
                        continue;
                    }
                    
                }
                
                while (i > 0 && apr_isspace(buf[i - 1]))
                    --i;
                buf[i] = '\0';

                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, NULL, "Read config: %s", buf);

                return 0;
            }
            buf[i] = c;
            ++i;
            c = cfp->getch(cfp->param);
        }
    }
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


AP_DECLARE(int) ap_find_list_item(apr_pool_t *p, const char *line, const char *tok)
{
    const unsigned char *pos;
    const unsigned char *ptr = (const unsigned char *)line;
    int good = 0, addspace = 0, in_qpair = 0, in_qstr = 0, in_com = 0;

    if (!line || !tok)
        return 0;

    do {  

        

        while (*ptr == ',' || apr_isspace(*ptr))
            ++ptr;

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
                               else good = good && (*pos++ == apr_tolower(*ptr));
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




AP_DECLARE(char *) ap_get_token(apr_pool_t *p, const char **accept_line, int accept_white)
{
    const char *ptr = *accept_line;
    const char *tok_start;
    char *token;
    int tok_len;

    

    while (*ptr && apr_isspace(*ptr))
        ++ptr;

    tok_start = ptr;

    

    while (*ptr && (accept_white || !apr_isspace(*ptr))
           && *ptr != ';' && *ptr != ',') {
        if (*ptr++ == '"')
            while (*ptr)
                if (*ptr++ == '"')
                    break;
    }

    tok_len = ptr - tok_start;
    token = apr_pstrndup(p, tok_start, tok_len);

    

    while (*ptr && apr_isspace(*ptr))
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
    register char digit;


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


AP_DECLARE(int) ap_unescape_url(char *url)
{
    register int badesc, badpath;
    char *x, *y;

    badesc = 0;
    badpath = 0;
    
    y = strchr(url, '%');
    if (y == NULL) {
        return OK;
    }
    for (x = y; *y; ++x, ++y) {
        if (*y != '%')
            *x = *y;
        else {
            if (!apr_isxdigit(*(y + 1)) || !apr_isxdigit(*(y + 2))) {
                badesc = 1;
                *x = '%';
            }
            else {
                *x = x2c(y + 1);
                y += 2;
                if (IS_SLASH(*x) || *x == '\0')
                    badpath = 1;
            }
        }
    }
    *x = '\0';
    if (badesc)
        return HTTP_BAD_REQUEST;
    else if (badpath)
        return HTTP_NOT_FOUND;
    else return OK;
}

AP_DECLARE(int) ap_unescape_url_keep2f(char *url)
{
    register int badesc, badpath;
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
                if (decoded == '\0') {
                    badpath = 1;
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

AP_DECLARE(char *) ap_construct_server(apr_pool_t *p, const char *hostname, apr_port_t port, const request_rec *r)
{
    if (ap_is_default_port(port, r)) {
        return apr_pstrdup(p, hostname);
    }
    else {
        return apr_psprintf(p, "%s:%u", hostname, port);
    }
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



AP_DECLARE(char *) ap_escape_path_segment(apr_pool_t *p, const char *segment)
{
    char *copy = apr_palloc(p, 3 * strlen(segment) + 1);
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

AP_DECLARE(char *) ap_os_escape_path(apr_pool_t *p, const char *path, int partial)
{
    char *copy = apr_palloc(p, 3 * strlen(path) + 3);
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



AP_DECLARE(char *) ap_escape_html(apr_pool_t *p, const char *s)
{
    int i, j;
    char *x;

    
    for (i = 0, j = 0; s[i] != '\0'; i++)
        if (s[i] == '<' || s[i] == '>')
            j += 3;
        else if (s[i] == '&')
            j += 4;

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
        else x[j] = s[i];

    x[j] = '\0';
    return x;
}

AP_DECLARE(char *) ap_escape_logitem(apr_pool_t *p, const char *str)
{
    char *ret;
    unsigned char *d;
    const unsigned char *s;

    if (!str) {
        return NULL;
    }

    ret = apr_palloc(p, 4 * strlen(str) + 1); 
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
    register int x;

    for (x = 0; u[x] != ':'; x++) {
        if ((!u[x]) || ((!apr_isalpha(u[x])) && (!apr_isdigit(u[x])) && (u[x] != '+') && (u[x] != '-') && (u[x] != '.'))) {

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


char *ap_get_local_host(apr_pool_t *a)
{



    char str[MAXHOSTNAMELEN + 1];
    char *server_hostname = NULL;
    apr_sockaddr_t *sockaddr;
    char *hostname;

    if (apr_gethostname(str, sizeof(str) - 1, a) != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP | APLOG_WARNING, 0, a, "%s: apr_gethostname() failed to determine ServerName", ap_server_argv0);

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
            ap_log_perror(APLOG_MARK, APLOG_STARTUP | APLOG_WARNING, 0, a, "%s: apr_sockaddr_info_get() failed for %s", ap_server_argv0, str);

        }
    }

    if (!server_hostname)
        server_hostname = apr_pstrdup(a, "127.0.0.1");

    ap_log_perror(APLOG_MARK, APLOG_ALERT|APLOG_STARTUP, 0, a, "%s: Could not reliably determine the server's fully qualified " "domain name, using %s for ServerName", ap_server_argv0, server_hostname);



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
    while (*str) {
        *str = apr_tolower(*str);
        ++str;
    }
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
