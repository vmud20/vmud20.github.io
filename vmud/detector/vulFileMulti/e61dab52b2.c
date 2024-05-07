































static const char deflateFilterName[] = "DEFLATE";
module AP_MODULE_DECLARE_DATA deflate_module;





typedef struct deflate_filter_config_t {
    int windowSize;
    int memlevel;
    int compressionlevel;
    apr_size_t bufferSize;
    char *note_ratio_name;
    char *note_input_name;
    char *note_output_name;
    int etag_opt;
} deflate_filter_config;


static const char gzip_header[10] = { '\037', '\213', Z_DEFLATED, 0, 0, 0, 0, 0, 0, 0x03 };





static const char deflate_magic[2] = { '\037', '\213' };







static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *mod_deflate_ssl_var = NULL;


static int check_gzip(request_rec *r, apr_table_t *hdrs1, apr_table_t *hdrs2)
{
    int found = 0;
    apr_table_t *hdrs = hdrs1;
    const char *encoding = apr_table_get(hdrs, "Content-Encoding");

    if (!encoding && (hdrs2 != NULL)) {
        
        encoding = apr_table_get(hdrs2, "Content-Encoding");
        hdrs = hdrs2;
        if (!encoding) {
            encoding = r->content_encoding;
            hdrs = NULL;
        }
    }
    if (encoding && *encoding) {

        
        if (!strcasecmp(encoding, "gzip")
            || !strcasecmp(encoding, "x-gzip")) {
            found = 1;
            if (hdrs) {
                apr_table_unset(hdrs, "Content-Encoding");
            }
            else {
                r->content_encoding = NULL;
            }
        }
        else if (ap_strchr_c(encoding, ',') != NULL) {
            
            char *new_encoding = apr_pstrdup(r->pool, encoding);
            char *ptr;
            for(;;) {
                char *token = ap_strrchr(new_encoding, ',');
                if (!token) {        
                    if (!strcasecmp(new_encoding, "gzip")
                        || !strcasecmp(new_encoding, "x-gzip")) {
                        found = 1;
                        if (hdrs) {
                            apr_table_unset(hdrs, "Content-Encoding");
                        }
                        else {
                            r->content_encoding = NULL;
                        }
                    }
                    break; 
                }
                for (ptr=token+1; apr_isspace(*ptr); ++ptr);
                if (!strcasecmp(ptr, "gzip")
                    || !strcasecmp(ptr, "x-gzip")) {
                    *token = '\0';
                    if (hdrs) {
                        apr_table_setn(hdrs, "Content-Encoding", new_encoding);
                    }
                    else {
                        r->content_encoding = new_encoding;
                    }
                    found = 1;
                }
                else if (!ptr[0] || !strcasecmp(ptr, "identity")) {
                    *token = '\0';
                    continue; 
                }
                break; 
            }
        }
    }
    
    if (hdrs && r->content_encoding) {
        r->content_encoding = apr_table_get(hdrs, "Content-Encoding");
    }
    return found;
}


static void putLong(unsigned char *string, unsigned long x)
{
    string[0] = (unsigned char)(x & 0xff);
    string[1] = (unsigned char)((x & 0xff00) >> 8);
    string[2] = (unsigned char)((x & 0xff0000) >> 16);
    string[3] = (unsigned char)((x & 0xff000000) >> 24);
}


static unsigned long getLong(unsigned char *string)
{
    return ((unsigned long)string[0])
          | (((unsigned long)string[1]) << 8)
          | (((unsigned long)string[2]) << 16)
          | (((unsigned long)string[3]) << 24);
}

static void *create_deflate_server_config(apr_pool_t *p, server_rec *s)
{
    deflate_filter_config *c = apr_pcalloc(p, sizeof *c);

    c->memlevel   = DEFAULT_MEMLEVEL;
    c->windowSize = DEFAULT_WINDOWSIZE;
    c->bufferSize = DEFAULT_BUFFERSIZE;
    c->compressionlevel = DEFAULT_COMPRESSION;
    c->etag_opt = AP_DEFLATE_ETAG_ADDSUFFIX;

    return c;
}

static const char *deflate_set_window_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    deflate_filter_config *c = ap_get_module_config(cmd->server->module_config, &deflate_module);
    int i;

    i = atoi(arg);

    if (i < 1 || i > 15)
        return "DeflateWindowSize must be between 1 and 15";

    c->windowSize = i * -1;

    return NULL;
}

static const char *deflate_set_buffer_size(cmd_parms *cmd, void *dummy, const char *arg)
{
    deflate_filter_config *c = ap_get_module_config(cmd->server->module_config, &deflate_module);
    int n = atoi(arg);

    if (n <= 0) {
        return "DeflateBufferSize should be positive";
    }

    c->bufferSize = (apr_size_t)n;

    return NULL;
}
static const char *deflate_set_note(cmd_parms *cmd, void *dummy, const char *arg1, const char *arg2)
{
    deflate_filter_config *c = ap_get_module_config(cmd->server->module_config, &deflate_module);

    if (arg2 == NULL) {
        c->note_ratio_name = apr_pstrdup(cmd->pool, arg1);
    }
    else if (!strcasecmp(arg1, "ratio")) {
        c->note_ratio_name = apr_pstrdup(cmd->pool, arg2);
    }
    else if (!strcasecmp(arg1, "input")) {
        c->note_input_name = apr_pstrdup(cmd->pool, arg2);
    }
    else if (!strcasecmp(arg1, "output")) {
        c->note_output_name = apr_pstrdup(cmd->pool, arg2);
    }
    else {
        return apr_psprintf(cmd->pool, "Unknown note type %s", arg1);
    }

    return NULL;
}

static const char *deflate_set_memlevel(cmd_parms *cmd, void *dummy, const char *arg)
{
    deflate_filter_config *c = ap_get_module_config(cmd->server->module_config, &deflate_module);
    int i;

    i = atoi(arg);

    if (i < 1 || i > 9)
        return "DeflateMemLevel must be between 1 and 9";

    c->memlevel = i;

    return NULL;
}

static const char *deflate_set_etag(cmd_parms *cmd, void *dummy, const char *arg)
{
    deflate_filter_config *c = ap_get_module_config(cmd->server->module_config, &deflate_module);

    if (!strcasecmp(arg, "NoChange")) { 
      c->etag_opt = AP_DEFLATE_ETAG_NOCHANGE;
    }
    else if (!strcasecmp(arg, "AddSuffix")) { 
      c->etag_opt = AP_DEFLATE_ETAG_ADDSUFFIX;
    }
    else if (!strcasecmp(arg, "Remove")) { 
      c->etag_opt = AP_DEFLATE_ETAG_REMOVE;
    }
    else { 
        return "DeflateAlterETAG accepts only 'NoChange', 'AddSuffix', and 'Remove'";
    }

    return NULL;
}


static const char *deflate_set_compressionlevel(cmd_parms *cmd, void *dummy, const char *arg)
{
    deflate_filter_config *c = ap_get_module_config(cmd->server->module_config, &deflate_module);
    int i;

    i = atoi(arg);

    if (i < 1 || i > 9)
        return "Compression Level must be between 1 and 9";

    c->compressionlevel = i;

    return NULL;
}

typedef struct deflate_ctx_t {
    z_stream stream;
    unsigned char *buffer;
    unsigned long crc;
    apr_bucket_brigade *bb, *proc_bb;
    int (*libz_end_func)(z_streamp);
    unsigned char *validation_buffer;
    apr_size_t validation_buffer_length;
    char header[10]; 
    apr_size_t header_len;
    int zlib_flags;
    unsigned int consume_pos, consume_len;
    unsigned int filter_init:1;
    unsigned int done:1;
} deflate_ctx;








static int flush_libz_buffer(deflate_ctx *ctx, deflate_filter_config *c, struct apr_bucket_alloc_t *bucket_alloc, int (*libz_func)(z_streamp, int), int flush, int crc)


{
    int zRC = Z_OK;
    int done = 0;
    unsigned int deflate_len;
    apr_bucket *b;

    for (;;) {
         deflate_len = c->bufferSize - ctx->stream.avail_out;

         if (deflate_len != 0) {
             
             if (crc) {
                 ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, deflate_len);
             }
             b = apr_bucket_heap_create((char *)ctx->buffer, deflate_len, NULL, bucket_alloc);

             APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
             ctx->stream.next_out = ctx->buffer;
             ctx->stream.avail_out = c->bufferSize;
         }

         if (done)
             break;

         zRC = libz_func(&ctx->stream, flush);

         
         if (zRC == Z_BUF_ERROR) {
             zRC = Z_OK;
             break;
         }

         done = (ctx->stream.avail_out != 0 || zRC == Z_STREAM_END);

         if (zRC != Z_OK && zRC != Z_STREAM_END)
             break;
    }
    return zRC;
}

static apr_status_t deflate_ctx_cleanup(void *data)
{
    deflate_ctx *ctx = (deflate_ctx *)data;

    if (ctx)
        ctx->libz_end_func(&ctx->stream);
    return APR_SUCCESS;
}


static void deflate_check_etag(request_rec *r, const char *transform, int etag_opt)
{
    const char *etag = apr_table_get(r->headers_out, "ETag");
    apr_size_t etaglen;

    if (etag_opt == AP_DEFLATE_ETAG_REMOVE) { 
        apr_table_unset(r->headers_out, "ETag");
        return;
    }

    if ((etag && ((etaglen = strlen(etag)) > 2))) {
        if (etag[etaglen - 1] == '"') {
            apr_size_t transformlen = strlen(transform);
            char *newtag = apr_palloc(r->pool, etaglen + transformlen + 2);
            char *d = newtag;
            char *e = d + etaglen - 1;
            const char *s = etag;

            for (; d < e; ++d, ++s) {
                *d = *s;          
            }
            *d++ = '-';           
            s = transform;
            e = d + transformlen;
            for (; d < e; ++d, ++s) {
                *d = *s;          
            }
            *d++ = '"';           
            *d   = '\0';          

            apr_table_setn(r->headers_out, "ETag", newtag);
        }
    }
}

static int have_ssl_compression(request_rec *r)
{
    const char *comp;
    if (mod_deflate_ssl_var == NULL)
        return 0;
    comp = mod_deflate_ssl_var(r->pool, r->server, r->connection, r, "SSL_COMPRESS_METHOD");
    if (comp == NULL || *comp == '\0' || strcmp(comp, "NULL") == 0)
        return 0;
    return 1;
}

static apr_status_t deflate_out_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *e;
    request_rec *r = f->r;
    deflate_ctx *ctx = f->ctx;
    int zRC;
    apr_size_t len = 0, blen;
    const char *data;
    deflate_filter_config *c;

    
    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    c = ap_get_module_config(r->server->module_config, &deflate_module);

    
    if (!ctx) {
        char *token;
        const char *encoding;

        if (have_ssl_compression(r)) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Compression enabled at SSL level; not compressing " "at HTTP level.");

            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        
        e = APR_BRIGADE_LAST(bb);
        if (APR_BUCKET_IS_EOS(e)) {
            
            e = APR_BRIGADE_FIRST(bb);
            while (1) {
                apr_status_t rc;
                if (APR_BUCKET_IS_EOS(e)) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Not compressing very small response of %" APR_SIZE_T_FMT " bytes", len);

                    ap_remove_output_filter(f);
                    return ap_pass_brigade(f->next, bb);
                }
                if (APR_BUCKET_IS_METADATA(e)) {
                    e = APR_BUCKET_NEXT(e);
                    continue;
                }

                rc = apr_bucket_read(e, &data, &blen, APR_BLOCK_READ);
                if (rc != APR_SUCCESS)
                    return rc;
                len += blen;
                
                if (len > sizeof(gzip_header) + VALIDATION_SIZE + 50)
                    break;

                e = APR_BUCKET_NEXT(e);
            }
        }

        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));

        
        if ((r->main != NULL) || (r->status == HTTP_NO_CONTENT) || apr_table_get(r->subprocess_env, "no-gzip") || apr_table_get(r->headers_out, "Content-Range")

           ) {
            if (APLOG_R_IS_LEVEL(r, APLOG_TRACE1)) {
                const char *reason = (r->main != NULL)                           ? "subrequest" :
                    (r->status == HTTP_NO_CONTENT)              ? "no content" :
                    apr_table_get(r->subprocess_env, "no-gzip") ? "no-gzip" :
                    "content-range";
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Not compressing (%s)", reason);
            }
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        
        if (r->content_type == NULL || strncmp(r->content_type, "text/html", 9)) {
            const char *env_value = apr_table_get(r->subprocess_env, "gzip-only-text/html");
            if ( env_value && (strcmp(env_value,"1") == 0) ) {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Not compressing, (gzip-only-text/html)");
                ap_remove_output_filter(f);
                return ap_pass_brigade(f->next, bb);
            }
        }

        
        encoding = apr_table_get(r->headers_out, "Content-Encoding");
        if (encoding) {
            const char *err_enc;

            err_enc = apr_table_get(r->err_headers_out, "Content-Encoding");
            if (err_enc) {
                encoding = apr_pstrcat(r->pool, encoding, ",", err_enc, NULL);
            }
        }
        else {
            encoding = apr_table_get(r->err_headers_out, "Content-Encoding");
        }

        if (r->content_encoding) {
            encoding = encoding ? apr_pstrcat(r->pool, encoding, ",", r->content_encoding, NULL)
                                : r->content_encoding;
        }

        if (encoding) {
            const char *tmp = encoding;

            token = ap_get_token(r->pool, &tmp, 0);
            while (token && *token) {
                
                if (strcmp(token, "identity") && strcmp(token, "7bit") && strcmp(token, "8bit") && strcmp(token, "binary")) {
                    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Not compressing (content-encoding already " " set: %s)", token);

                    ap_remove_output_filter(f);
                    return ap_pass_brigade(f->next, bb);
                }

                
                if (*tmp) {
                    ++tmp;
                }
                token = (*tmp) ? ap_get_token(r->pool, &tmp, 0) : NULL;
            }
        }

        
        apr_table_mergen(r->headers_out, "Vary", "Accept-Encoding");

        
        if (!apr_table_get(r->subprocess_env, "force-gzip")) {
            const char *accepts;
            
            accepts = apr_table_get(r->headers_in, "Accept-Encoding");
            if (accepts == NULL) {
                ap_remove_output_filter(f);
                return ap_pass_brigade(f->next, bb);
            }

            token = ap_get_token(r->pool, &accepts, 0);
            while (token && token[0] && strcasecmp(token, "gzip")) {
                
                while (*accepts == ';') {
                    ++accepts;
                    ap_get_token(r->pool, &accepts, 1);
                }

                
                if (*accepts == ',') {
                    ++accepts;
                }
                token = (*accepts) ? ap_get_token(r->pool, &accepts, 0) : NULL;
            }

            
            if (token == NULL || token[0] == '\0') {
                ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Not compressing (no Accept-Encoding: gzip)");
                ap_remove_output_filter(f);
                return ap_pass_brigade(f->next, bb);
            }
        }
        else {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "Forcing compression (force-gzip set)");
        }

        

        if (r->status != HTTP_NOT_MODIFIED) {
            ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);
            ctx->buffer = apr_palloc(r->pool, c->bufferSize);
            ctx->libz_end_func = deflateEnd;

            zRC = deflateInit2(&ctx->stream, c->compressionlevel, Z_DEFLATED, c->windowSize, c->memlevel, Z_DEFAULT_STRATEGY);


            if (zRC != Z_OK) {
                deflateEnd(&ctx->stream);
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01383)
                              "unable to init Zlib: " "deflateInit2 returned %d: URL %s", zRC, r->uri);

                
                ap_remove_output_filter(f);
                return ap_pass_brigade(f->next, bb);
            }
            
            apr_pool_cleanup_register(r->pool, ctx, deflate_ctx_cleanup, apr_pool_cleanup_null);

            
            ctx->filter_init = 1;
        }

        

        
        if (!encoding || !strcasecmp(encoding, "identity")) {
            apr_table_setn(r->headers_out, "Content-Encoding", "gzip");
        }
        else {
            apr_table_mergen(r->headers_out, "Content-Encoding", "gzip");
        }
        
        if (r->content_encoding) {
            r->content_encoding = apr_table_get(r->headers_out, "Content-Encoding");
        }
        apr_table_unset(r->headers_out, "Content-Length");
        apr_table_unset(r->headers_out, "Content-MD5");
        if (c->etag_opt != AP_DEFLATE_ETAG_NOCHANGE) {  
            deflate_check_etag(r, "gzip", c->etag_opt);
        }

        
        if (r->status == HTTP_NOT_MODIFIED) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        
        e = apr_bucket_immortal_create(gzip_header, sizeof gzip_header, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

        
        ctx->stream.next_out = ctx->buffer;
        ctx->stream.avail_out = c->bufferSize;
    } else if (!ctx->filter_init) {
        
        return ap_pass_brigade(f->next, bb);
    }

    while (!APR_BRIGADE_EMPTY(bb))
    {
        apr_bucket *b;

        
        if (r->header_only && r->bytes_sent) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        e = APR_BRIGADE_FIRST(bb);

        if (APR_BUCKET_IS_EOS(e)) {
            char *buf;

            ctx->stream.avail_in = 0; 
            
            flush_libz_buffer(ctx, c, f->c->bucket_alloc, deflate, Z_FINISH, NO_UPDATE_CRC);

            buf = apr_palloc(r->pool, VALIDATION_SIZE);
            putLong((unsigned char *)&buf[0], ctx->crc);
            putLong((unsigned char *)&buf[4], ctx->stream.total_in);

            b = apr_bucket_pool_create(buf, VALIDATION_SIZE, r->pool, f->c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01384)
                          "Zlib: Compressed %ld to %ld : URL %s", ctx->stream.total_in, ctx->stream.total_out, r->uri);

            
            if (c->note_input_name) {
                apr_table_setn(r->notes, c->note_input_name, (ctx->stream.total_in > 0)
                                ? apr_off_t_toa(r->pool, ctx->stream.total_in)
                                : "-");
            }

            if (c->note_output_name) {
                apr_table_setn(r->notes, c->note_output_name, (ctx->stream.total_in > 0)
                                ? apr_off_t_toa(r->pool, ctx->stream.total_out)
                                : "-");
            }

            if (c->note_ratio_name) {
                apr_table_setn(r->notes, c->note_ratio_name, (ctx->stream.total_in > 0)
                                ? apr_itoa(r->pool, (int)(ctx->stream.total_out * 100 / ctx->stream.total_in))


                                : "-");
            }

            deflateEnd(&ctx->stream);
            
            apr_pool_cleanup_kill(r->pool, ctx, deflate_ctx_cleanup);

            
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            
            return ap_pass_brigade(f->next, ctx->bb);
        }

        if (APR_BUCKET_IS_FLUSH(e)) {
            apr_status_t rv;

            
            zRC = flush_libz_buffer(ctx, c, f->c->bucket_alloc, deflate, Z_SYNC_FLUSH, NO_UPDATE_CRC);
            if (zRC != Z_OK) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01385)
                              "Zlib error %d flushing zlib output buffer (%s)", zRC, ctx->stream.msg);
                return APR_EGENERAL;
            }

            
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
            rv = ap_pass_brigade(f->next, ctx->bb);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            continue;
        }

        if (APR_BUCKET_IS_METADATA(e)) {
            
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
            continue;
        }

        
        apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
        if (!len) {
            apr_bucket_delete(e);
            continue;
        }
        if (len > INT_MAX) {
            apr_bucket_split(e, INT_MAX);
            apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
        }

        
        ctx->crc = crc32(ctx->crc, (const Bytef *)data, len);

        
        ctx->stream.next_in = (unsigned char *)data; 
        ctx->stream.avail_in = len;

        while (ctx->stream.avail_in != 0) {
            if (ctx->stream.avail_out == 0) {
                apr_status_t rv;

                ctx->stream.next_out = ctx->buffer;
                len = c->bufferSize - ctx->stream.avail_out;

                b = apr_bucket_heap_create((char *)ctx->buffer, len, NULL, f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
                ctx->stream.avail_out = c->bufferSize;
                
                rv = ap_pass_brigade(f->next, ctx->bb);
                if (rv != APR_SUCCESS) {
                    return rv;
                }
            }

            zRC = deflate(&(ctx->stream), Z_NO_FLUSH);

            if (zRC != Z_OK) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01386)
                              "Zlib error %d deflating data (%s)", zRC, ctx->stream.msg);
                return APR_EGENERAL;
            }
        }

        apr_bucket_delete(e);
    }

    return APR_SUCCESS;
}

static apr_status_t consume_zlib_flags(deflate_ctx *ctx, const char **data, apr_size_t *len)
{
    if ((ctx->zlib_flags & EXTRA_FIELD)) {
        
        if (ctx->consume_pos == 0) {
            if (!*len) {
                return APR_INCOMPLETE;
            }
            ctx->consume_len = (unsigned int)**data;
            ctx->consume_pos++;
            ++*data;
            --*len;
        }
        if (ctx->consume_pos == 1) {
            if (!*len) {
                return APR_INCOMPLETE;
            }
            ctx->consume_len += ((unsigned int)**data) << 8;
            ctx->consume_pos++;
            ++*data;
            --*len;
        }
        if (*len < ctx->consume_len) {
            ctx->consume_len -= *len;
            *len = 0;
            return APR_INCOMPLETE;
        }
        *data += ctx->consume_len;
        *len -= ctx->consume_len;

        ctx->consume_len = ctx->consume_pos = 0;
        ctx->zlib_flags &= ~EXTRA_FIELD;
    }

    if ((ctx->zlib_flags & ORIG_NAME)) {
        
        while (*len && **data) {
            ++*data;
            --*len;
        }
        if (!*len) {
            return APR_INCOMPLETE;
        }
        
        ++*data;
        --*len;

        ctx->zlib_flags &= ~ORIG_NAME;
    }

    if ((ctx->zlib_flags & COMMENT)) {
        
        while (*len && **data) {
            ++*data;
            --*len;
        }
        if (!*len) {
            return APR_INCOMPLETE;
        }
        
        ++*data;
        --*len;

        ctx->zlib_flags &= ~COMMENT;
    }

    if ((ctx->zlib_flags & HEAD_CRC)) {
        
        if (ctx->consume_pos == 0) {
            if (!*len) {
                return APR_INCOMPLETE;
            }
            ctx->consume_pos++;
            ++*data;
            --*len;
        }
        if (!*len) {
            return APR_INCOMPLETE;
        }
        ++*data;
        --*len;
        
        ctx->consume_pos = 0;
        ctx->zlib_flags &= ~HEAD_CRC;
    }

    return APR_SUCCESS;
}


static apr_status_t deflate_in_filter(ap_filter_t *f, apr_bucket_brigade *bb, ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)



{
    apr_bucket *bkt;
    request_rec *r = f->r;
    deflate_ctx *ctx = f->ctx;
    int zRC;
    apr_status_t rv;
    deflate_filter_config *c;

    
    if (mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    c = ap_get_module_config(r->server->module_config, &deflate_module);

    if (!ctx || ctx->header_len < sizeof(ctx->header)) {
        apr_size_t len;

        if (!ctx) {
            
            if (!ap_is_initial_req(r)) {
                ap_remove_input_filter(f);
                return ap_get_brigade(f->next, bb, mode, block, readbytes);
            }

            
            if (apr_table_get(r->headers_in, "Content-Range") != NULL) {
                ap_remove_input_filter(f);
                return ap_get_brigade(f->next, bb, mode, block, readbytes);
            }

            
            if (check_gzip(r, r->headers_in, NULL) == 0) {
                ap_remove_input_filter(f);
                return ap_get_brigade(f->next, bb, mode, block, readbytes);
            }

            f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
            ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);
            ctx->proc_bb = apr_brigade_create(r->pool, f->c->bucket_alloc);
            ctx->buffer = apr_palloc(r->pool, c->bufferSize);
        }

        do {
            apr_brigade_cleanup(ctx->bb);

            len = sizeof(ctx->header) - ctx->header_len;
            rv = ap_get_brigade(f->next, ctx->bb, AP_MODE_READBYTES, block, len);

            
            if (rv != APR_SUCCESS || APR_BRIGADE_EMPTY(ctx->bb)) {
                return rv;
            }

            
            bkt = APR_BRIGADE_FIRST(ctx->bb);
            if (APR_BUCKET_IS_EOS(bkt)) {
                if (ctx->header_len) {
                    
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02619)
                                  "Encountered premature end-of-stream while " "reading inflate header");
                    return APR_EGENERAL;
                }
                APR_BUCKET_REMOVE(bkt);
                APR_BRIGADE_INSERT_TAIL(bb, bkt);
                ap_remove_input_filter(f);
                return APR_SUCCESS;
            }

            rv = apr_brigade_flatten(ctx->bb, ctx->header + ctx->header_len, &len);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            if (len && !ctx->header_len) {
                apr_table_unset(r->headers_in, "Content-Length");
                apr_table_unset(r->headers_in, "Content-MD5");
            }
            ctx->header_len += len;

        } while (ctx->header_len < sizeof(ctx->header));

        
        if (ctx->header[0] != deflate_magic[0] || ctx->header[1] != deflate_magic[1]) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01387)
                          "Zlib: Invalid header");
            return APR_EGENERAL;
        }

        ctx->zlib_flags = ctx->header[3];
        if ((ctx->zlib_flags & RESERVED)) {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01388)
                          "Zlib: Invalid flags %02x", ctx->zlib_flags);
            return APR_EGENERAL;
        }

        zRC = inflateInit2(&ctx->stream, c->windowSize);

        if (zRC != Z_OK) {
            f->ctx = NULL;
            inflateEnd(&ctx->stream);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01389)
                          "unable to init Zlib: " "inflateInit2 returned %d: URL %s", zRC, r->uri);

            ap_remove_input_filter(f);
            return ap_get_brigade(f->next, bb, mode, block, readbytes);
        }

        
        ctx->stream.next_out = ctx->buffer;
        ctx->stream.avail_out = c->bufferSize;

        apr_brigade_cleanup(ctx->bb);
    }

    if (APR_BRIGADE_EMPTY(ctx->proc_bb)) {
        rv = ap_get_brigade(f->next, ctx->bb, mode, block, readbytes);

        
        if (block == APR_NONBLOCK_READ && (APR_STATUS_IS_EAGAIN(rv)
                    || (rv == APR_SUCCESS && APR_BRIGADE_EMPTY(ctx->bb)))) {
            return rv;
        }
        if (rv != APR_SUCCESS) {
            inflateEnd(&ctx->stream);
            return rv;
        }

        for (bkt = APR_BRIGADE_FIRST(ctx->bb);
             bkt != APR_BRIGADE_SENTINEL(ctx->bb);
             bkt = APR_BUCKET_NEXT(bkt))
        {
            const char *data;
            apr_size_t len;

            if (APR_BUCKET_IS_EOS(bkt)) {
                if (!ctx->done) {
                    inflateEnd(&ctx->stream);
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02481)
                                  "Encountered premature end-of-stream while inflating");
                    return APR_EGENERAL;
                }

                
                APR_BUCKET_REMOVE(bkt);
                APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, bkt);
                break;
            }

            if (APR_BUCKET_IS_FLUSH(bkt)) {
                apr_bucket *tmp_b;
                zRC = inflate(&(ctx->stream), Z_SYNC_FLUSH);
                if (zRC != Z_OK) {
                    inflateEnd(&ctx->stream);
                    ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01391)
                                  "Zlib error %d inflating data (%s)", zRC, ctx->stream.msg);
                    return APR_EGENERAL;
                }

                ctx->stream.next_out = ctx->buffer;
                len = c->bufferSize - ctx->stream.avail_out;

                ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
                tmp_b = apr_bucket_heap_create((char *)ctx->buffer, len, NULL, f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, tmp_b);
                ctx->stream.avail_out = c->bufferSize;

                
                tmp_b = APR_BUCKET_PREV(bkt);
                APR_BUCKET_REMOVE(bkt);
                APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, bkt);
                bkt = tmp_b;
                continue;
            }

            
            if (ctx->done) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02482)
                              "Encountered extra data after compressed data");
                return APR_EGENERAL;
            }

            
            apr_bucket_read(bkt, &data, &len, APR_BLOCK_READ);
            if (!len) {
                continue;
            }
            if (len > INT_MAX) {
                apr_bucket_split(bkt, INT_MAX);
                apr_bucket_read(bkt, &data, &len, APR_BLOCK_READ);
            }

            if (ctx->zlib_flags) {
                rv = consume_zlib_flags(ctx, &data, &len);
                if (rv == APR_SUCCESS) {
                    ctx->zlib_flags = 0;
                }
                if (!len) {
                    continue;
                }
            }

            
            ctx->stream.next_in = (unsigned char *)data;
            ctx->stream.avail_in = (int)len;

            zRC = Z_OK;

            if (!ctx->validation_buffer) {
                while (ctx->stream.avail_in != 0) {
                    if (ctx->stream.avail_out == 0) {
                        apr_bucket *tmp_heap;
                        ctx->stream.next_out = ctx->buffer;
                        len = c->bufferSize - ctx->stream.avail_out;

                        ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
                        tmp_heap = apr_bucket_heap_create((char *)ctx->buffer, len, NULL, f->c->bucket_alloc);
                        APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, tmp_heap);
                        ctx->stream.avail_out = c->bufferSize;
                    }

                    zRC = inflate(&ctx->stream, Z_NO_FLUSH);

                    if (zRC == Z_STREAM_END) {
                        ctx->validation_buffer = apr_pcalloc(r->pool, VALIDATION_SIZE);
                        ctx->validation_buffer_length = 0;
                        break;
                    }

                    if (zRC != Z_OK) {
                        inflateEnd(&ctx->stream);
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01392)
                                      "Zlib error %d inflating data (%s)", zRC, ctx->stream.msg);
                        return APR_EGENERAL;
                    }
                }
            }

            if (ctx->validation_buffer) {
                apr_bucket *tmp_heap;
                apr_size_t avail, valid;
                unsigned char *buf = ctx->validation_buffer;

                avail = ctx->stream.avail_in;
                valid = (apr_size_t)VALIDATION_SIZE - ctx->validation_buffer_length;

                
                if (avail < valid) {
                    memcpy(buf + ctx->validation_buffer_length, ctx->stream.next_in, avail);
                    ctx->validation_buffer_length += avail;
                    continue;
                }
                memcpy(buf + ctx->validation_buffer_length, ctx->stream.next_in, valid);
                ctx->validation_buffer_length += valid;

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01393)
                              "Zlib: Inflated %ld to %ld : URL %s", ctx->stream.total_in, ctx->stream.total_out, r->uri);


                len = c->bufferSize - ctx->stream.avail_out;

                ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
                tmp_heap = apr_bucket_heap_create((char *)ctx->buffer, len, NULL, f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, tmp_heap);
                ctx->stream.avail_out = c->bufferSize;

                {
                    unsigned long compCRC, compLen;
                    compCRC = getLong(buf);
                    if (ctx->crc != compCRC) {
                        inflateEnd(&ctx->stream);
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01394)
                                      "Zlib: CRC error inflating data");
                        return APR_EGENERAL;
                    }
                    compLen = getLong(buf + VALIDATION_SIZE / 2);
                    
                    if ((ctx->stream.total_out & 0xFFFFFFFF) != compLen) {
                        inflateEnd(&ctx->stream);
                        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01395)
                                      "Zlib: Length %ld of inflated data does " "not match expected value %ld", ctx->stream.total_out, compLen);

                        return APR_EGENERAL;
                    }
                }

                inflateEnd(&ctx->stream);

                ctx->done = 1;

                
                if (avail > valid) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02485)
                                  "Encountered extra data after compressed data");
                    return APR_EGENERAL;
                }
            }

        }
        apr_brigade_cleanup(ctx->bb);
    }

    
    if (block == APR_BLOCK_READ && APR_BRIGADE_EMPTY(ctx->proc_bb) && ctx->stream.avail_out < c->bufferSize) {

        apr_bucket *tmp_heap;
        apr_size_t len;
        ctx->stream.next_out = ctx->buffer;
        len = c->bufferSize - ctx->stream.avail_out;

        ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
        tmp_heap = apr_bucket_heap_create((char *)ctx->buffer, len, NULL, f->c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(ctx->proc_bb, tmp_heap);
        ctx->stream.avail_out = c->bufferSize;
    }

    if (!APR_BRIGADE_EMPTY(ctx->proc_bb)) {
        if (apr_brigade_partition(ctx->proc_bb, readbytes, &bkt) == APR_INCOMPLETE) {
            APR_BRIGADE_CONCAT(bb, ctx->proc_bb);
        }
        else {
            APR_BRIGADE_CONCAT(bb, ctx->proc_bb);
            apr_brigade_split_ex(bb, bkt, ctx->proc_bb);
        }
        if (APR_BUCKET_IS_EOS(APR_BRIGADE_LAST(bb))) {
            ap_remove_input_filter(f);
        }
    }

    return APR_SUCCESS;
}



static apr_status_t inflate_out_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *e;
    request_rec *r = f->r;
    deflate_ctx *ctx = f->ctx;
    int zRC;
    apr_status_t rv;
    deflate_filter_config *c;

    
    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    c = ap_get_module_config(r->server->module_config, &deflate_module);

    if (!ctx) {

        
        if (!ap_is_initial_req(r) || (r->status == HTTP_NO_CONTENT) || (apr_table_get(r->headers_out, "Content-Range") != NULL) || (check_gzip(r, r->headers_out, r->err_headers_out) == 0)

           ) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        
        apr_table_unset(r->headers_out, "Content-Length");
        apr_table_unset(r->headers_out, "Content-MD5");
        if (c->etag_opt != AP_DEFLATE_ETAG_NOCHANGE) {
            deflate_check_etag(r, "gunzip", c->etag_opt);
        }

        
        if (r->status == HTTP_NOT_MODIFIED) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);
        ctx->buffer = apr_palloc(r->pool, c->bufferSize);
        ctx->libz_end_func = inflateEnd;
        ctx->validation_buffer = NULL;
        ctx->validation_buffer_length = 0;

        zRC = inflateInit2(&ctx->stream, c->windowSize);

        if (zRC != Z_OK) {
            f->ctx = NULL;
            inflateEnd(&ctx->stream);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01397)
                          "unable to init Zlib: " "inflateInit2 returned %d: URL %s", zRC, r->uri);

            
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        
        apr_pool_cleanup_register(r->pool, ctx, deflate_ctx_cleanup, apr_pool_cleanup_null);

        
        ctx->stream.next_out = ctx->buffer;
        ctx->stream.avail_out = c->bufferSize;
    }

    while (!APR_BRIGADE_EMPTY(bb))
    {
        const char *data;
        apr_bucket *b;
        apr_size_t len;

        e = APR_BRIGADE_FIRST(bb);

        if (APR_BUCKET_IS_EOS(e)) {
            
            ap_remove_output_filter(f);
            
            ctx->stream.avail_in = 0;
            
            flush_libz_buffer(ctx, c, f->c->bucket_alloc, inflate, Z_SYNC_FLUSH, UPDATE_CRC);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01398)
                          "Zlib: Inflated %ld to %ld : URL %s", ctx->stream.total_in, ctx->stream.total_out, r->uri);

            if (ctx->validation_buffer_length == VALIDATION_SIZE) {
                unsigned long compCRC, compLen;
                compCRC = getLong(ctx->validation_buffer);
                if (ctx->crc != compCRC) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01399)
                                  "Zlib: Checksum of inflated stream invalid");
                    return APR_EGENERAL;
                }
                ctx->validation_buffer += VALIDATION_SIZE / 2;
                compLen = getLong(ctx->validation_buffer);
                
                if ((ctx->stream.total_out & 0xFFFFFFFF) != compLen) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01400)
                                  "Zlib: Length of inflated stream invalid");
                    return APR_EGENERAL;
                }
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01401)
                              "Zlib: Validation bytes not present");
                return APR_EGENERAL;
            }

            inflateEnd(&ctx->stream);
            
            apr_pool_cleanup_kill(r->pool, ctx, deflate_ctx_cleanup);

            
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            
            return ap_pass_brigade(f->next, ctx->bb);
        }

        if (APR_BUCKET_IS_FLUSH(e)) {
            apr_status_t rv;

            
            zRC = flush_libz_buffer(ctx, c, f->c->bucket_alloc, inflate, Z_SYNC_FLUSH, UPDATE_CRC);
            if (zRC == Z_STREAM_END) {
                if (ctx->validation_buffer == NULL) {
                    ctx->validation_buffer = apr_pcalloc(f->r->pool, VALIDATION_SIZE);
                }
            }
            else if (zRC != Z_OK) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01402)
                              "Zlib error %d flushing inflate buffer (%s)", zRC, ctx->stream.msg);
                return APR_EGENERAL;
            }

            
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
            rv = ap_pass_brigade(f->next, ctx->bb);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            continue;
        }

        if (APR_BUCKET_IS_METADATA(e)) {
            
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
            continue;
        }

        
        apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
        if (!len) {
            apr_bucket_delete(e);
            continue;
        }
        if (len > INT_MAX) {
            apr_bucket_split(e, INT_MAX);
            apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
        }

        
        if (ctx->header_len < sizeof(ctx->header)) {
            apr_size_t rem;

            rem = sizeof(ctx->header) - ctx->header_len;
            if (len < rem) {
                memcpy(ctx->header + ctx->header_len, data, len);
                ctx->header_len += len;
                apr_bucket_delete(e);
                continue;
            }
            memcpy(ctx->header + ctx->header_len, data, rem);
            ctx->header_len += rem;
            {
                int zlib_method;
                zlib_method = ctx->header[2];
                if (zlib_method != Z_DEFLATED) {
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01404)
                                  "inflate: data not deflated!");
                    ap_remove_output_filter(f);
                    return ap_pass_brigade(f->next, bb);
                }
                if (ctx->header[0] != deflate_magic[0] || ctx->header[1] != deflate_magic[1]) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01405)
                                      "inflate: bad header");
                    return APR_EGENERAL ;
                }
                ctx->zlib_flags = ctx->header[3];
                if ((ctx->zlib_flags & RESERVED)) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(02620)
                                  "inflate: bad flags %02x", ctx->zlib_flags);
                    return APR_EGENERAL;
                }
            }
            if (len == rem) {
                apr_bucket_delete(e);
                continue;
            }
            data += rem;
            len -= rem;
        }

        if (ctx->zlib_flags) {
            rv = consume_zlib_flags(ctx, &data, &len);
            if (rv == APR_SUCCESS) {
                ctx->zlib_flags = 0;
            }
            if (!len) {
                apr_bucket_delete(e);
                continue;
            }
        }

        
        ctx->stream.next_in = (unsigned char *)data;
        ctx->stream.avail_in = len;

        if (ctx->validation_buffer) {
            if (ctx->validation_buffer_length < VALIDATION_SIZE) {
                apr_size_t copy_size;

                copy_size = VALIDATION_SIZE - ctx->validation_buffer_length;
                if (copy_size > ctx->stream.avail_in)
                    copy_size = ctx->stream.avail_in;
                memcpy(ctx->validation_buffer + ctx->validation_buffer_length, ctx->stream.next_in, copy_size);
                
                ctx->stream.avail_in -= copy_size;
                ctx->validation_buffer_length += copy_size;
            }
            if (ctx->stream.avail_in) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01407)
                              "Zlib: %d bytes of garbage at the end of " "compressed stream.", ctx->stream.avail_in);
                
                ctx->stream.avail_in = 0;
            }
        }

        while (ctx->stream.avail_in != 0) {
            if (ctx->stream.avail_out == 0) {

                ctx->stream.next_out = ctx->buffer;
                len = c->bufferSize - ctx->stream.avail_out;

                ctx->crc = crc32(ctx->crc, (const Bytef *)ctx->buffer, len);
                b = apr_bucket_heap_create((char *)ctx->buffer, len, NULL, f->c->bucket_alloc);
                APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
                ctx->stream.avail_out = c->bufferSize;
                
                rv = ap_pass_brigade(f->next, ctx->bb);
                if (rv != APR_SUCCESS) {
                    return rv;
                }
            }

            zRC = inflate(&ctx->stream, Z_NO_FLUSH);

            if (zRC == Z_STREAM_END) {
                
                ctx->validation_buffer = apr_pcalloc(f->r->pool, VALIDATION_SIZE);
                if (ctx->stream.avail_in > VALIDATION_SIZE) {
                    ctx->validation_buffer_length = VALIDATION_SIZE;
                    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, APLOGNO(01408)
                                  "Zlib: %d bytes of garbage at the end of " "compressed stream.", ctx->stream.avail_in - VALIDATION_SIZE);

                } else if (ctx->stream.avail_in > 0) {
                           ctx->validation_buffer_length = ctx->stream.avail_in;
                }
                if (ctx->validation_buffer_length)
                    memcpy(ctx->validation_buffer, ctx->stream.next_in, ctx->validation_buffer_length);
                break;
            }

            if (zRC != Z_OK) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, APLOGNO(01409)
                              "Zlib error %d inflating data (%s)", zRC, ctx->stream.msg);
                return APR_EGENERAL;
            }
        }

        apr_bucket_delete(e);
    }

    return APR_SUCCESS;
}

static int mod_deflate_post_config(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    mod_deflate_ssl_var = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
    return OK;
}



static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter(deflateFilterName, deflate_out_filter, NULL, AP_FTYPE_CONTENT_SET);
    ap_register_output_filter("INFLATE", inflate_out_filter, NULL, AP_FTYPE_RESOURCE-1);
    ap_register_input_filter(deflateFilterName, deflate_in_filter, NULL, AP_FTYPE_CONTENT_SET);
    ap_hook_post_config(mod_deflate_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec deflate_filter_cmds[] = {
    AP_INIT_TAKE12("DeflateFilterNote", deflate_set_note, NULL, RSRC_CONF, "Set a note to report on compression ratio"), AP_INIT_TAKE1("DeflateWindowSize", deflate_set_window_size, NULL, RSRC_CONF, "Set the Deflate window size (1-15)"), AP_INIT_TAKE1("DeflateBufferSize", deflate_set_buffer_size, NULL, RSRC_CONF, "Set the Deflate Buffer Size"), AP_INIT_TAKE1("DeflateMemLevel", deflate_set_memlevel, NULL, RSRC_CONF, "Set the Deflate Memory Level (1-9)"), AP_INIT_TAKE1("DeflateCompressionLevel", deflate_set_compressionlevel, NULL, RSRC_CONF, "Set the Deflate Compression Level (1-9)"), AP_INIT_TAKE1("DeflateAlterEtag", deflate_set_etag, NULL, RSRC_CONF, "Set how mod_deflate should modify ETAG response headers: 'AddSuffix' (default), 'NoChange' (2.2.x behavior), 'Remove'"),  {NULL}












};





AP_DECLARE_MODULE(deflate) = {
    STANDARD20_MODULE_STUFF, NULL, NULL, create_deflate_server_config, NULL, deflate_filter_cmds, register_hooks };






