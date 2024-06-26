































static int state_transition[][7] = {
    
  1, 0, 0, 0, 0, 0, 0 }, 1, 1, 0, 0, 0, 0, 0 }, 0, 0, 1, 0, 0, 0, 0 }, 0, 0, 0, 1, 0, 0, 0 }, 1, 1, 0, 0, 1, 0, 0 }, 1, 1, 0, 0, 0, 1, 0 }, 1, 1, 0, 0, 1, 1, 1 }, };







static void H2_STREAM_OUT_LOG(int lvl, h2_stream *s, const char *tag)
{
    if (APLOG_C_IS_LEVEL(s->session->c, lvl)) {
        conn_rec *c = s->session->c;
        char buffer[4 * 1024];
        const char *line = "(null)";
        apr_size_t len, bmax = sizeof(buffer)/sizeof(buffer[0]);
        
        len = h2_util_bb_print(buffer, bmax, tag, "", s->out_buffer);
        ap_log_cerror(APLOG_MARK, lvl, 0, c, "bb_dump(%s): %s",  c->log_id, len? buffer : line);
    }
}

static int set_state(h2_stream *stream, h2_stream_state_t state)
{
    int allowed = state_transition[state][stream->state];
    if (allowed) {
        stream->state = state;
        return 1;
    }
    
    ap_log_cerror(APLOG_MARK, APLOG_WARNING, 0, stream->session->c, APLOGNO(03081)
                  "h2_stream(%ld-%d): invalid state transition from %d to %d",  stream->session->id, stream->id, stream->state, state);
    return 0;
}

static int close_input(h2_stream *stream) 
{
    switch (stream->state) {
        case H2_STREAM_ST_CLOSED_INPUT:
        case H2_STREAM_ST_CLOSED:
            return 0; 
        case H2_STREAM_ST_CLOSED_OUTPUT:
            
            set_state(stream, H2_STREAM_ST_CLOSED);
            break;
        default:
            
            set_state(stream, H2_STREAM_ST_CLOSED_INPUT);
            break;
    }
    return 1;
}

static int input_closed(h2_stream *stream) 
{
    switch (stream->state) {
        case H2_STREAM_ST_OPEN:
        case H2_STREAM_ST_CLOSED_OUTPUT:
            return 0;
        default:
            return 1;
    }
}

static int close_output(h2_stream *stream) 
{
    switch (stream->state) {
        case H2_STREAM_ST_CLOSED_OUTPUT:
        case H2_STREAM_ST_CLOSED:
            return 0; 
        case H2_STREAM_ST_CLOSED_INPUT:
            
            set_state(stream, H2_STREAM_ST_CLOSED);
            break;
        default:
            
            set_state(stream, H2_STREAM_ST_CLOSED_OUTPUT);
            break;
    }
    return 1;
}

static int input_open(const h2_stream *stream) 
{
    switch (stream->state) {
        case H2_STREAM_ST_OPEN:
        case H2_STREAM_ST_CLOSED_OUTPUT:
            return 1;
        default:
            return 0;
    }
}

static int output_open(h2_stream *stream) 
{
    switch (stream->state) {
        case H2_STREAM_ST_OPEN:
        case H2_STREAM_ST_CLOSED_INPUT:
            return 1;
        default:
            return 0;
    }
}

static void prep_output(h2_stream *stream) {
    conn_rec *c = stream->session->c;
    if (!stream->out_buffer) {
        stream->out_buffer = apr_brigade_create(stream->pool, c->bucket_alloc);
    }
}

static void prepend_response(h2_stream *stream, h2_headers *response)
{
    conn_rec *c = stream->session->c;
    apr_bucket *b;
    
    prep_output(stream);
    b = h2_bucket_headers_create(c->bucket_alloc, response);
    APR_BRIGADE_INSERT_HEAD(stream->out_buffer, b);
}

static apr_status_t stream_pool_cleanup(void *ctx)
{
    h2_stream *stream = ctx;
    apr_status_t status;
    
    ap_assert(stream->can_be_cleaned);
    if (stream->files) {
        apr_file_t *file;
        int i;
        for (i = 0; i < stream->files->nelts; ++i) {
            file = APR_ARRAY_IDX(stream->files, i, apr_file_t*);
            status = apr_file_close(file);
            ap_log_cerror(APLOG_MARK, APLOG_TRACE3, status, stream->session->c,  "h2_stream(%ld-%d): destroy, closed file %d", stream->session->id, stream->id, i);

        }
        stream->files = NULL;
    }
    return APR_SUCCESS;
}

h2_stream *h2_stream_open(int id, apr_pool_t *pool, h2_session *session, int initiated_on)
{
    h2_stream *stream = apr_pcalloc(pool, sizeof(h2_stream));
    
    stream->id           = id;
    stream->initiated_on = initiated_on;
    stream->created      = apr_time_now();
    stream->state        = H2_STREAM_ST_IDLE;
    stream->pool         = pool;
    stream->session      = session;
    stream->can_be_cleaned = 1;

    h2_beam_create(&stream->input, pool, id, "input", H2_BEAM_OWNER_SEND, 0);
    h2_beam_create(&stream->output, pool, id, "output", H2_BEAM_OWNER_RECV, 0);
    
    set_state(stream, H2_STREAM_ST_OPEN);
    apr_pool_cleanup_register(pool, stream, stream_pool_cleanup,  apr_pool_cleanup_null);
    ap_log_cerror(APLOG_MARK, APLOG_DEBUG, 0, session->c, APLOGNO(03082)
                  "h2_stream(%ld-%d): opened", session->id, stream->id);
    return stream;
}

void h2_stream_cleanup(h2_stream *stream)
{
    apr_status_t status;
    
    ap_assert(stream);
    if (stream->out_buffer) {
        
        apr_brigade_cleanup(stream->out_buffer);
    }
    h2_beam_abort(stream->input);
    status = h2_beam_wait_empty(stream->input, APR_NONBLOCK_READ);
    if (status == APR_EAGAIN) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, stream->session->c,  "h2_stream(%ld-%d): wait on input drain", stream->session->id, stream->id);

        status = h2_beam_wait_empty(stream->input, APR_BLOCK_READ);
        ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, stream->session->c,  "h2_stream(%ld-%d): input drain returned", stream->session->id, stream->id);

    }
}

void h2_stream_destroy(h2_stream *stream)
{
    ap_assert(stream);
    ap_assert(!h2_mplx_stream_get(stream->session->mplx, stream->id));
    ap_log_cerror(APLOG_MARK, APLOG_TRACE3, 0, stream->session->c,  "h2_stream(%ld-%d): destroy", stream->session->id, stream->id);

    stream->can_be_cleaned = 1;
    if (stream->pool) {
        apr_pool_destroy(stream->pool);
    }
}

void h2_stream_eos_destroy(h2_stream *stream)
{
    h2_session_stream_done(stream->session, stream);
    
}

apr_pool_t *h2_stream_detach_pool(h2_stream *stream)
{
    apr_pool_t *pool = stream->pool;
    stream->pool = NULL;
    return pool;
}

void h2_stream_rst(h2_stream *stream, int error_code)
{
    stream->rst_error = error_code;
    close_input(stream);
    close_output(stream);
    if (stream->out_buffer) {
        apr_brigade_cleanup(stream->out_buffer);
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c, "h2_stream(%ld-%d): reset, error=%d", stream->session->id, stream->id, error_code);

}

apr_status_t h2_stream_set_request_rec(h2_stream *stream, request_rec *r)
{
    h2_request *req;
    apr_status_t status;

    ap_assert(stream->request == NULL);
    ap_assert(stream->rtmp == NULL);
    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    status = h2_request_rcreate(&req, stream->pool, r);
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, status, r, APLOGNO(03058)
                  "h2_request(%d): set_request_rec %s host=%s://%s%s", stream->id, req->method, req->scheme, req->authority, req->path);

    stream->rtmp = req;
    return status;
}

apr_status_t h2_stream_set_request(h2_stream *stream, const h2_request *r)
{
    ap_assert(stream->request == NULL);
    ap_assert(stream->rtmp == NULL);
    stream->rtmp = h2_request_clone(stream->pool, r);
    return APR_SUCCESS;
}

static apr_status_t add_trailer(h2_stream *stream, const char *name, size_t nlen, const char *value, size_t vlen)

{
    conn_rec *c = stream->session->c;
    char *hname, *hvalue;

    if (nlen == 0 || name[0] == ':') {
        ap_log_cerror(APLOG_MARK, APLOG_DEBUG, APR_EINVAL, c, APLOGNO(03060)
                      "h2_request(%ld-%d): pseudo header in trailer", c->id, stream->id);
        return APR_EINVAL;
    }
    if (h2_req_ignore_trailer(name, nlen)) {
        return APR_SUCCESS;
    }
    if (!stream->trailers) {
        stream->trailers = apr_table_make(stream->pool, 5);
    }
    hname = apr_pstrndup(stream->pool, name, nlen);
    hvalue = apr_pstrndup(stream->pool, value, vlen);
    h2_util_camel_case_header(hname, nlen);
    apr_table_mergen(stream->trailers, hname, hvalue);
    
    return APR_SUCCESS;
}

apr_status_t h2_stream_add_header(h2_stream *stream, const char *name, size_t nlen, const char *value, size_t vlen)

{
    ap_assert(stream);
    
    if (!stream->has_response) {
        if (name[0] == ':') {
            if ((vlen) > stream->session->s->limit_req_line) {
                
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c, "h2_stream(%ld-%d): pseudo header %s too long", stream->session->id, stream->id, name);

                return h2_stream_set_error(stream,  HTTP_REQUEST_URI_TOO_LARGE);
            }
        }
        else if ((nlen + 2 + vlen) > stream->session->s->limit_req_fieldsize) {
            
            ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c, "h2_stream(%ld-%d): header %s too long", stream->session->id, stream->id, name);

            return h2_stream_set_error(stream,  HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
        }
        
        if (name[0] != ':') {
            ++stream->request_headers_added;
            if (stream->request_headers_added  > stream->session->s->limit_req_fields) {
                
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c, "h2_stream(%ld-%d): too many header lines", stream->session->id, stream->id);

                return h2_stream_set_error(stream,  HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE);
            }
        }
    }
    
    if (h2_stream_is_scheduled(stream)) {
        return add_trailer(stream, name, nlen, value, vlen);
    }
    else {
        if (!stream->rtmp) {
            stream->rtmp = h2_req_create(stream->id, stream->pool,  NULL, NULL, NULL, NULL, NULL, 0);
        }
        if (stream->state != H2_STREAM_ST_OPEN) {
            return APR_ECONNRESET;
        }
        return h2_request_add_header(stream->rtmp, stream->pool, name, nlen, value, vlen);
    }
}

apr_status_t h2_stream_schedule(h2_stream *stream, int eos, int push_enabled,  h2_stream_pri_cmp *cmp, void *ctx)
{
    apr_status_t status = APR_EINVAL;
    ap_assert(stream);
    ap_assert(stream->session);
    ap_assert(stream->session->mplx);
    
    if (!stream->scheduled) {
        if (eos) {
            close_input(stream);
        }

        if (h2_stream_is_ready(stream)) {
            
            return h2_mplx_process(stream->session->mplx, stream, cmp, ctx);
        }
        else if (!stream->request && stream->rtmp) {
            
            status = h2_request_end_headers(stream->rtmp, stream->pool, eos);
            if (status == APR_SUCCESS) {
                stream->rtmp->serialize = h2_config_geti(stream->session->config, H2_CONF_SER_HEADERS);

                stream->request = stream->rtmp;
                stream->rtmp = NULL;
                stream->scheduled = 1;

                stream->push_policy = h2_push_policy_determine(stream->request->headers,  stream->pool, push_enabled);
            
                
                status = h2_mplx_process(stream->session->mplx, stream, cmp, ctx);
                ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c, "h2_stream(%ld-%d): scheduled %s %s://%s%s " "chunked=%d", stream->session->id, stream->id, stream->request->method, stream->request->scheme, stream->request->authority, stream->request->path, stream->request->chunked);





                return status;
            }
        }
        else {
            status = APR_ECONNRESET;
        }
    }
    
    h2_stream_rst(stream, H2_ERR_INTERNAL_ERROR);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, stream->session->c, "h2_stream(%ld-%d): RST=2 (internal err) %s %s://%s%s", stream->session->id, stream->id, stream->request->method, stream->request->scheme, stream->request->authority, stream->request->path);



    return status;
}

int h2_stream_is_scheduled(const h2_stream *stream)
{
    return stream->scheduled;
}

apr_status_t h2_stream_close_input(h2_stream *stream)
{
    conn_rec *c = stream->session->c;
    apr_status_t status;
    apr_bucket_brigade *tmp;
    apr_bucket *b;

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c, "h2_stream(%ld-%d): closing input", stream->session->id, stream->id);

    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    
    tmp = apr_brigade_create(stream->pool, c->bucket_alloc);
    if (stream->trailers && !apr_is_empty_table(stream->trailers)) {
        h2_headers *r = h2_headers_create(HTTP_OK, stream->trailers,  NULL, stream->pool);
        b = h2_bucket_headers_create(c->bucket_alloc, r);
        APR_BRIGADE_INSERT_TAIL(tmp, b);
        stream->trailers = NULL;
    }
    
    b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(tmp, b);
    status = h2_beam_send(stream->input, tmp, APR_BLOCK_READ);
    apr_brigade_destroy(tmp);
    return status;
}

apr_status_t h2_stream_write_data(h2_stream *stream, const char *data, size_t len, int eos)
{
    conn_rec *c = stream->session->c;
    apr_status_t status = APR_SUCCESS;
    apr_bucket_brigade *tmp;
    
    ap_assert(stream);
    if (!stream->input) {
        return APR_EOF;
    }
    if (input_closed(stream) || !stream->request) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "h2_stream(%ld-%d): writing denied, closed=%d, eoh=%d", stream->session->id, stream->id, input_closed(stream), stream->request != NULL);


        return APR_EINVAL;
    }

    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, c, "h2_stream(%ld-%d): add %ld input bytes", stream->session->id, stream->id, (long)len);

    
    tmp = apr_brigade_create(stream->pool, c->bucket_alloc);
    apr_brigade_write(tmp, NULL, NULL, data, len);
    status = h2_beam_send(stream->input, tmp, APR_BLOCK_READ);
    apr_brigade_destroy(tmp);
    
    stream->in_data_frames++;
    stream->in_data_octets += len;
    
    if (eos) {
        return h2_stream_close_input(stream);
    }
    
    return status;
}

static apr_status_t fill_buffer(h2_stream *stream, apr_size_t amount)
{
    conn_rec *c = stream->session->c;
    apr_bucket *b;
    apr_status_t status;
    
    if (!stream->output) {
        return APR_EOF;
    }
    status = h2_beam_receive(stream->output, stream->out_buffer,  APR_NONBLOCK_READ, amount);
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, stream->session->c, "h2_stream(%ld-%d): beam_received", stream->session->id, stream->id);

    
    for (b = APR_BRIGADE_FIRST(stream->out_buffer);
         b != APR_BRIGADE_SENTINEL(stream->out_buffer);
         b = APR_BUCKET_NEXT(b)) {
        if (APR_BUCKET_IS_FILE(b)) {
            apr_bucket_file *f = (apr_bucket_file *)b->data;
            apr_pool_t *fpool = apr_file_pool_get(f->fd);
            if (fpool != c->pool) {
                apr_bucket_setaside(b, c->pool);
                if (!stream->files) {
                    stream->files = apr_array_make(stream->pool,  5, sizeof(apr_file_t*));
                }
                APR_ARRAY_PUSH(stream->files, apr_file_t*) = f->fd;
            }
        }
    }
    return status;
}

apr_status_t h2_stream_set_error(h2_stream *stream, int http_status)
{
    h2_headers *response;
    
    if (h2_stream_is_ready(stream)) {
        return APR_EINVAL;
    }
    if (stream->rtmp) {
        stream->request = stream->rtmp;
        stream->rtmp = NULL;
    }
    response = h2_headers_die(http_status, stream->request, stream->pool);
    prepend_response(stream, response);
    h2_beam_close(stream->output);
    return APR_SUCCESS;
}

static apr_bucket *get_first_headers_bucket(apr_bucket_brigade *bb)
{
    if (bb) {
        apr_bucket *b = APR_BRIGADE_FIRST(bb);
        while (b != APR_BRIGADE_SENTINEL(bb)) {
            if (H2_BUCKET_IS_HEADERS(b)) {
                return b;
            }
            b = APR_BUCKET_NEXT(b);
        }
    }
    return NULL;
}

apr_status_t h2_stream_out_prepare(h2_stream *stream, apr_off_t *plen,  int *peos, h2_headers **presponse)
{
    conn_rec *c = stream->session->c;
    apr_status_t status = APR_SUCCESS;
    apr_off_t requested;
    apr_bucket *b, *e;

    if (presponse) {
        *presponse = NULL;
    }
    
    if (stream->rst_error) {
        *plen = 0;
        *peos = 1;
        return APR_ECONNRESET;
    }
    
    if (!output_open(stream)) {
        return APR_ECONNRESET;
    }
    prep_output(stream);

    if (*plen > 0) {
        requested = H2MIN(*plen, H2_DATA_CHUNK_SIZE);
    }
    else {
        requested = H2_DATA_CHUNK_SIZE;
    }
    *plen = requested;
    
    H2_STREAM_OUT_LOG(APLOG_TRACE2, stream, "h2_stream_out_prepare_pre");
    h2_util_bb_avail(stream->out_buffer, plen, peos);
    if (!*peos && *plen < requested) {
        
        status = fill_buffer(stream, (requested - *plen) + H2_DATA_CHUNK_SIZE);
        if (APR_STATUS_IS_EOF(status)) {
            apr_bucket *eos = apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(stream->out_buffer, eos);
            status = APR_SUCCESS;
        }
        else if (status == APR_EAGAIN) {
            
            status = APR_SUCCESS;
        }
        *plen = requested;
        h2_util_bb_avail(stream->out_buffer, plen, peos);
    }
    H2_STREAM_OUT_LOG(APLOG_TRACE2, stream, "h2_stream_out_prepare_post");
    
    b = APR_BRIGADE_FIRST(stream->out_buffer);
    while (b != APR_BRIGADE_SENTINEL(stream->out_buffer)) {
        e = APR_BUCKET_NEXT(b);
        if (APR_BUCKET_IS_FLUSH(b)
            || (!APR_BUCKET_IS_METADATA(b) && b->length == 0)) {
            APR_BUCKET_REMOVE(b);
            apr_bucket_destroy(b);
        }
        else {
            break;
        }
        b = e;
    }
    
    b = get_first_headers_bucket(stream->out_buffer);
    if (b) {
        
        *peos = 0;
        *plen = 0;
        if (b == APR_BRIGADE_FIRST(stream->out_buffer)) {
            if (presponse) {
                *presponse = h2_bucket_headers_get(b);
                APR_BUCKET_REMOVE(b);
                apr_bucket_destroy(b);
                status = APR_SUCCESS;
            }
            else {
                
                h2_mplx_keep_active(stream->session->mplx, stream->id);
                status = APR_EAGAIN;
            }
        }
        else {
            apr_bucket *e = APR_BRIGADE_FIRST(stream->out_buffer);
            while (e != APR_BRIGADE_SENTINEL(stream->out_buffer)) {
                if (e == b) {
                    break;
                }
                else if (e->length != (apr_size_t)-1) {
                    *plen += e->length;
                }
                e = APR_BUCKET_NEXT(e);
            }
        }
    }
    
    if (!*peos && !*plen && status == APR_SUCCESS  && (!presponse || !*presponse)) {
        status = APR_EAGAIN;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE1, status, c, "h2_stream(%ld-%d): prepare, len=%ld eos=%d", c->id, stream->id, (long)*plen, *peos);

    return status;
}

static int is_not_headers(apr_bucket *b)
{
    return !H2_BUCKET_IS_HEADERS(b);
}

apr_status_t h2_stream_read_to(h2_stream *stream, apr_bucket_brigade *bb,  apr_off_t *plen, int *peos)
{
    conn_rec *c = stream->session->c;
    apr_status_t status = APR_SUCCESS;

    if (stream->rst_error) {
        return APR_ECONNRESET;
    }
    status = h2_append_brigade(bb, stream->out_buffer, plen, peos, is_not_headers);
    if (status == APR_SUCCESS && !*peos && !*plen) {
        status = APR_EAGAIN;
    }
    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, status, c, "h2_stream(%ld-%d): read_to, len=%ld eos=%d", c->id, stream->id, (long)*plen, *peos);

    return status;
}


int h2_stream_input_is_open(const h2_stream *stream) 
{
    return input_open(stream);
}

apr_status_t h2_stream_submit_pushes(h2_stream *stream, h2_headers *response)
{
    apr_status_t status = APR_SUCCESS;
    apr_array_header_t *pushes;
    int i;
    
    pushes = h2_push_collect_update(stream, stream->request, response);
    if (pushes && !apr_is_empty_array(pushes)) {
        ap_log_cerror(APLOG_MARK, APLOG_TRACE1, 0, stream->session->c, "h2_stream(%ld-%d): found %d push candidates", stream->session->id, stream->id, pushes->nelts);

        for (i = 0; i < pushes->nelts; ++i) {
            h2_push *push = APR_ARRAY_IDX(pushes, i, h2_push*);
            h2_stream *s = h2_session_push(stream->session, stream, push);
            if (!s) {
                status = APR_ECONNRESET;
                break;
            }
        }
    }
    return status;
}

apr_table_t *h2_stream_get_trailers(h2_stream *stream)
{
    return NULL;
}

const h2_priority *h2_stream_get_priority(h2_stream *stream,  h2_headers *response)
{
    if (response && stream->initiated_on) {
        const char *ctype = apr_table_get(response->headers, "content-type");
        if (ctype) {
            
            return h2_config_get_priority(stream->session->config, ctype);
        }
    }
    return NULL;
}

const char *h2_stream_state_str(h2_stream *stream)
{
    switch (stream->state) {
        case H2_STREAM_ST_IDLE:
            return "IDLE";
        case H2_STREAM_ST_OPEN:
            return "OPEN";
        case H2_STREAM_ST_RESV_LOCAL:
            return "RESERVED_LOCAL";
        case H2_STREAM_ST_RESV_REMOTE:
            return "RESERVED_REMOTE";
        case H2_STREAM_ST_CLOSED_INPUT:
            return "HALF_CLOSED_REMOTE";
        case H2_STREAM_ST_CLOSED_OUTPUT:
            return "HALF_CLOSED_LOCAL";
        case H2_STREAM_ST_CLOSED:
            return "CLOSED";
        default:
            return "UNKNOWN";
            
    }
}

int h2_stream_is_ready(h2_stream *stream)
{
    if (stream->has_response) {
        return 1;
    }
    else if (stream->out_buffer && get_first_headers_bucket(stream->out_buffer)) {
        return 1;
    }
    return 0;
}


