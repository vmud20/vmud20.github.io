

















module AP_MODULE_DECLARE_DATA mem_cache_module;

typedef enum {
    CACHE_TYPE_FILE = 1, CACHE_TYPE_HEAP, CACHE_TYPE_MMAP } cache_type_e;



typedef struct mem_cache_object {
    apr_pool_t *pool;
    cache_type_e type;
    apr_table_t *header_out;
    apr_table_t *req_hdrs; 
    apr_size_t m_len;
    void *m;
    apr_os_file_t fd;
    apr_int32_t flags;  
    long priority;      
    long total_refs;          

    apr_uint32_t pos;   

} mem_cache_object_t;

typedef struct {
    apr_thread_mutex_t *lock;
    cache_cache_t *cache_cache;

    
    apr_size_t min_cache_object_size;   
    apr_size_t max_cache_object_size;   
    apr_size_t max_cache_size;          
    apr_size_t max_object_cnt;
    cache_pqueue_set_priority cache_remove_algorithm;

    
    apr_off_t max_streaming_buffer_size;
} mem_cache_conf;
static mem_cache_conf *sconf;









static int remove_entity(cache_handle_t *h);
static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *i);
static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b);
static apr_status_t recall_headers(cache_handle_t *h, request_rec *r);
static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb);

static void cleanup_cache_object(cache_object_t *obj);

static long memcache_get_priority(void*a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;

    return  mobj->priority;
}

static void memcache_inc_frequency(void*a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;

    mobj->total_refs++;
    mobj->priority = 0;
}

static void memcache_set_pos(void *a, apr_ssize_t pos)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;

    apr_atomic_set32(&mobj->pos, pos);
}
static apr_ssize_t memcache_get_pos(void *a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;

    return apr_atomic_read32(&mobj->pos);
}

static apr_size_t memcache_cache_get_size(void*a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;
    return mobj->m_len;
}

static const char* memcache_cache_get_key(void*a)
{
    cache_object_t *obj = (cache_object_t *)a;
    return obj->key;
}

static void memcache_cache_free(void*a)
{
    cache_object_t *obj = (cache_object_t *)a;

    
    if (!apr_atomic_dec32(&obj->refcount)) {
        cleanup_cache_object(obj);
    }
}

static long memcache_lru_algorithm(long queue_clock, void *a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;
    if (mobj->priority == 0)
        mobj->priority = queue_clock - mobj->total_refs;

    
    return mobj->priority;
}

static long memcache_gdsf_algorithm(long queue_clock, void *a)
{
    cache_object_t *obj = (cache_object_t *)a;
    mem_cache_object_t *mobj = obj->vobj;

    if (mobj->priority == 0)
        mobj->priority = queue_clock - (long)(mobj->total_refs*1000 / mobj->m_len);

    return mobj->priority;
}

static void cleanup_cache_object(cache_object_t *obj)
{
    mem_cache_object_t *mobj = obj->vobj;

    
    if (mobj) {
        if (mobj->m) {
            free(mobj->m);
        }
        if (mobj->type == CACHE_TYPE_FILE && mobj->fd) {

            CloseHandle(mobj->fd);

            close(mobj->fd);

        }
    }

    apr_pool_destroy(mobj->pool);
}
static apr_status_t decrement_refcount(void *arg)
{
    cache_object_t *obj = (cache_object_t *) arg;

    
    if (!obj->complete) {
        cache_object_t *tobj = NULL;
        if (sconf->lock) {
            apr_thread_mutex_lock(sconf->lock);
        }
        tobj = cache_find(sconf->cache_cache, obj->key);
        if (tobj == obj) {
            cache_remove(sconf->cache_cache, obj);
            apr_atomic_dec32(&obj->refcount);
        }
        if (sconf->lock) {
            apr_thread_mutex_unlock(sconf->lock);
        }
    }

    
    if (!apr_atomic_dec32(&obj->refcount)) {
        cleanup_cache_object(obj);
    }
    return APR_SUCCESS;
}
static apr_status_t cleanup_cache_mem(void *sconfv)
{
    cache_object_t *obj;
    mem_cache_conf *co = (mem_cache_conf*) sconfv;

    if (!co) {
        return APR_SUCCESS;
    }
    if (!co->cache_cache) {
        return APR_SUCCESS;
    }

    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    obj = cache_pop(co->cache_cache);
    while (obj) {
        
        if (!apr_atomic_dec32(&obj->refcount)) {
            cleanup_cache_object(obj);
        }
        obj = cache_pop(co->cache_cache);
    }

    
    cache_free(co->cache_cache);

    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }
    return APR_SUCCESS;
}

static void *create_cache_config(apr_pool_t *p, server_rec *s)
{
    sconf = apr_pcalloc(p, sizeof(mem_cache_conf));

    sconf->min_cache_object_size = DEFAULT_MIN_CACHE_OBJECT_SIZE;
    sconf->max_cache_object_size = DEFAULT_MAX_CACHE_OBJECT_SIZE;
    
    sconf->max_object_cnt = DEFAULT_MAX_OBJECT_CNT;
    
    sconf->max_cache_size = DEFAULT_MAX_CACHE_SIZE;
    sconf->cache_cache = NULL;
    sconf->cache_remove_algorithm = memcache_gdsf_algorithm;
    sconf->max_streaming_buffer_size = DEFAULT_MAX_STREAMING_BUFFER_SIZE;

    return sconf;
}

static int create_entity(cache_handle_t *h, cache_type_e type_e, request_rec *r, const char *key, apr_off_t len)
{
    apr_status_t rv;
    apr_pool_t *pool;
    cache_object_t *obj, *tmp_obj;
    mem_cache_object_t *mobj;

    if (len == -1) {
        
        len = sconf->max_streaming_buffer_size;
    }

    
    if (len < sconf->min_cache_object_size || len > sconf->max_cache_object_size) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "mem_cache: URL %s failed the size check and will not be cached.", key);

        return DECLINED;
    }

    if (type_e == CACHE_TYPE_FILE) {
        
        if (!r->filename) {
            return DECLINED;
        }
    }

    rv = apr_pool_create(&pool, NULL);

    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, rv, r->server, "mem_cache: Failed to create memory pool.");
        return DECLINED;
    }

    
    obj = apr_pcalloc(pool, sizeof(*obj));
    obj->key = apr_pstrdup(pool, key);

    
    mobj = apr_pcalloc(pool, sizeof(*mobj));
    mobj->pool = pool;

    
    apr_atomic_set32(&obj->refcount, 1);
    mobj->total_refs = 1;
    obj->complete = 0;
    obj->vobj = mobj;
    
    mobj->m_len = (apr_size_t)len;
    mobj->type = type_e;

    
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    tmp_obj = (cache_object_t *) cache_find(sconf->cache_cache, key);

    if (!tmp_obj) {
        cache_insert(sconf->cache_cache, obj);
        
        apr_atomic_inc32(&obj->refcount);
    }
    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    if (tmp_obj) {
        
        cleanup_cache_object(obj);
        return DECLINED;
    }

    apr_pool_cleanup_register(r->pool, obj, decrement_refcount, apr_pool_cleanup_null);

    
    h->cache_obj = obj;

    return OK;
}

static int create_mem_entity(cache_handle_t *h, request_rec *r, const char *key, apr_off_t len)
{
    return create_entity(h, CACHE_TYPE_HEAP, r, key, len);
}

static int create_fd_entity(cache_handle_t *h, request_rec *r, const char *key, apr_off_t len)
{
    return create_entity(h, CACHE_TYPE_FILE, r, key, len);
}

static int open_entity(cache_handle_t *h, request_rec *r, const char *key)
{
    cache_object_t *obj;

    
    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }
    obj = (cache_object_t *) cache_find(sconf->cache_cache, key);
    if (obj) {
        if (obj->complete) {
            request_rec *rmain=r, *rtmp;
            apr_atomic_inc32(&obj->refcount);
            
            cache_update(sconf->cache_cache, obj);

            
            rtmp = r;
            while (rtmp) {
                rmain = rtmp;
                rtmp = rmain->main;
            }
            apr_pool_cleanup_register(rmain->pool, obj, decrement_refcount, apr_pool_cleanup_null);
        }
        else {
            obj = NULL;
        }
    }

    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    if (!obj) {
        return DECLINED;
    }

    
    h->cache_obj = obj;
    h->req_hdrs = NULL;  
    return OK;
}


static int remove_entity(cache_handle_t *h)
{
    cache_object_t *obj = h->cache_obj;
    cache_object_t *tobj = NULL;

    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }

    
    tobj = cache_find(sconf->cache_cache, obj->key);
    if (tobj == obj) {
        cache_remove(sconf->cache_cache, obj);
        apr_atomic_dec32(&obj->refcount);
    }

    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    return OK;
}



static int remove_url(cache_handle_t *h, apr_pool_t *p)
{
    cache_object_t *obj;
    int cleanup = 0;

    if (sconf->lock) {
        apr_thread_mutex_lock(sconf->lock);
    }

    obj = h->cache_obj;
    if (obj) {
        cache_remove(sconf->cache_cache, obj);
        
        cleanup = !apr_atomic_dec32(&obj->refcount);
    }
    if (sconf->lock) {
        apr_thread_mutex_unlock(sconf->lock);
    }

    if (cleanup) {
        cleanup_cache_object(obj);
    }

    return OK;
}

static apr_status_t recall_headers(cache_handle_t *h, request_rec *r)
{
    mem_cache_object_t *mobj = (mem_cache_object_t*) h->cache_obj->vobj;

    h->req_hdrs = apr_table_copy(r->pool, mobj->req_hdrs);
    h->resp_hdrs = apr_table_copy(r->pool, mobj->header_out);

    return OK;
}

static apr_status_t recall_body(cache_handle_t *h, apr_pool_t *p, apr_bucket_brigade *bb)
{
    apr_bucket *b;
    mem_cache_object_t *mobj = (mem_cache_object_t*) h->cache_obj->vobj;

    if (mobj->type == CACHE_TYPE_FILE) {
        
        apr_file_t *file;
        apr_os_file_put(&file, &mobj->fd, mobj->flags, p);

        apr_brigade_insert_file(bb, file, 0, mobj->m_len, p);
    }
    else {
        
        b = apr_bucket_immortal_create(mobj->m, mobj->m_len, bb->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(bb, b);
    }
    b = apr_bucket_eos_create(bb->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);

    return APR_SUCCESS;
}


static apr_status_t store_headers(cache_handle_t *h, request_rec *r, cache_info *info)
{
    cache_object_t *obj = h->cache_obj;
    mem_cache_object_t *mobj = (mem_cache_object_t*) obj->vobj;
    apr_table_t *headers_out;

    
    mobj->req_hdrs = apr_table_copy(mobj->pool, r->headers_in);

    
    headers_out = ap_cache_cacheable_hdrs_out(r->pool, r->headers_out, r->server);

    
    if (!apr_table_get(headers_out, "Content-Type")
        && r->content_type) {
        apr_table_setn(headers_out, "Content-Type", ap_make_content_type(r, r->content_type));
    }

    headers_out = apr_table_overlay(r->pool, headers_out, r->err_headers_out);
    mobj->header_out = apr_table_copy(mobj->pool, headers_out);

    
    obj->info.status = info->status;
    if (info->date) {
        obj->info.date = info->date;
    }
    if (info->response_time) {
        obj->info.response_time = info->response_time;
    }
    if (info->request_time) {
        obj->info.request_time = info->request_time;
    }
    if (info->expire) {
        obj->info.expire = info->expire;
    }

    return APR_SUCCESS;
}

static apr_status_t store_body(cache_handle_t *h, request_rec *r, apr_bucket_brigade *b)
{
    apr_status_t rv;
    cache_object_t *obj = h->cache_obj;
    cache_object_t *tobj = NULL;
    mem_cache_object_t *mobj = (mem_cache_object_t*) obj->vobj;
    apr_read_type_e eblock = APR_BLOCK_READ;
    apr_bucket *e;
    char *cur;
    int eos = 0;

    if (mobj->type == CACHE_TYPE_FILE) {
        apr_file_t *file = NULL;
        int fd = 0;
        int other = 0;

        
        for (e = APR_BRIGADE_FIRST(b);
             e != APR_BRIGADE_SENTINEL(b);
             e = APR_BUCKET_NEXT(e))
        {
            if (APR_BUCKET_IS_EOS(e)) {
                eos = 1;
            }
            else if (APR_BUCKET_IS_FILE(e)) {
                apr_bucket_file *a = e->data;
                fd++;
                file = a->fd;
            }
            else {
                other++;
            }
        }
        if (fd == 1 && !other && eos) {
            apr_file_t *tmpfile;
            const char *name;
            
            apr_file_name_get(&name, file);
            mobj->flags = ((APR_SENDFILE_ENABLED & apr_file_flags_get(file))
                           | APR_READ | APR_BINARY | APR_XTHREAD | APR_FILE_NOCLEANUP);
            rv = apr_file_open(&tmpfile, name, mobj->flags, APR_OS_DEFAULT, r->pool);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            apr_file_inherit_unset(tmpfile);
            apr_os_file_get(&(mobj->fd), tmpfile);

            
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "mem_cache: Cached file: %s with key: %s", name, obj->key);
            obj->complete = 1;
            return APR_SUCCESS;
        }

        
        mobj->type = CACHE_TYPE_HEAP;
    }

    
    if (mobj->m == NULL) {
        mobj->m = malloc(mobj->m_len);
        if (mobj->m == NULL) {
            return APR_ENOMEM;
        }
        obj->count = 0;
    }
    cur = (char*) mobj->m + obj->count;

    
    for (e = APR_BRIGADE_FIRST(b);
         e != APR_BRIGADE_SENTINEL(b);
         e = APR_BUCKET_NEXT(e))
    {
        const char *s;
        apr_size_t len;

        if (APR_BUCKET_IS_EOS(e)) {
            if (mobj->m_len > obj->count) {
                
                mobj->m = realloc(mobj->m, obj->count);
                if (!mobj->m) {
                    return APR_ENOMEM;
                }

                
                if (sconf->lock) {
                    apr_thread_mutex_lock(sconf->lock);
                }
                
                tobj = (cache_object_t *) cache_find(sconf->cache_cache, obj->key);
                if (tobj == obj) {
                    
                    cache_remove(sconf->cache_cache, obj);
                    
                    mobj->m_len = obj->count;

                    cache_insert(sconf->cache_cache, obj);
                    
                }
                else if (tobj) {
                    

                } else {
                    
                    mobj->m_len = obj->count;
                    cache_insert(sconf->cache_cache, obj);
                    apr_atomic_inc32(&obj->refcount);
                }

                if (sconf->lock) {
                    apr_thread_mutex_unlock(sconf->lock);
                }
            }
            
            ap_log_error(APLOG_MARK, APLOG_INFO, 0, r->server, "mem_cache: Cached url: %s", obj->key);
            obj->complete = 1;
            break;
        }
        rv = apr_bucket_read(e, &s, &len, eblock);
        if (rv != APR_SUCCESS) {
            return rv;
        }
        if (len) {
            
           if ((obj->count + len) > mobj->m_len) {
               return APR_ENOMEM;
           }
           else {
               memcpy(cur, s, len);
               cur+=len;
               obj->count+=len;
           }
        }
        
        AP_DEBUG_ASSERT(obj->count <= mobj->m_len);
    }
    return APR_SUCCESS;
}

static int mem_cache_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    int threaded_mpm;

    
    if (sconf->min_cache_object_size >= sconf->max_cache_object_size) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "MCacheMaxObjectSize must be greater than MCacheMinObjectSize");
        return DONE;
    }
    if (sconf->max_cache_object_size >= sconf->max_cache_size) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, s, "MCacheSize must be greater than MCacheMaxObjectSize");
        return DONE;
    }
    if (sconf->max_streaming_buffer_size > sconf->max_cache_object_size) {
        
        if (sconf->max_streaming_buffer_size != DEFAULT_MAX_STREAMING_BUFFER_SIZE && sconf->max_cache_object_size != DEFAULT_MAX_CACHE_OBJECT_SIZE) {
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "MCacheMaxStreamingBuffer must be less than or equal to MCacheMaxObjectSize. " "Resetting MCacheMaxStreamingBuffer to MCacheMaxObjectSize.");

        }
        sconf->max_streaming_buffer_size = sconf->max_cache_object_size;
    }
    if (sconf->max_streaming_buffer_size < sconf->min_cache_object_size) {
        ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "MCacheMaxStreamingBuffer must be greater than or equal to MCacheMinObjectSize. " "Resetting MCacheMaxStreamingBuffer to MCacheMinObjectSize.");

        sconf->max_streaming_buffer_size = sconf->min_cache_object_size;
    }
    ap_mpm_query(AP_MPMQ_IS_THREADED, &threaded_mpm);
    if (threaded_mpm) {
        apr_thread_mutex_create(&sconf->lock, APR_THREAD_MUTEX_DEFAULT, p);
    }

    sconf->cache_cache = cache_init(sconf->max_object_cnt, sconf->max_cache_size, memcache_get_priority, sconf->cache_remove_algorithm, memcache_get_pos, memcache_set_pos, memcache_inc_frequency, memcache_cache_get_size, memcache_cache_get_key, memcache_cache_free);








    apr_pool_cleanup_register(p, sconf, cleanup_cache_mem, apr_pool_cleanup_null);

    if (sconf->cache_cache)
        return OK;

    return -1;

}

static const char *set_max_cache_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    apr_size_t val;

    if (sscanf(arg, "%" APR_SIZE_T_FMT, &val) != 1) {
        return "MCacheSize argument must be an integer representing the max cache size in KBytes.";
    }
    sconf->max_cache_size = val*1024;
    return NULL;
}
static const char *set_min_cache_object_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    apr_size_t val;

    if (sscanf(arg, "%" APR_SIZE_T_FMT, &val) != 1) {
        return "MCacheMinObjectSize value must be an positive integer (bytes)";
    }
    if (val > 0)
       sconf->min_cache_object_size = val;
    else return  "MCacheMinObjectSize value must be an positive integer (bytes)";
    return NULL;
}
static const char *set_max_cache_object_size(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    apr_size_t val;

    if (sscanf(arg, "%" APR_SIZE_T_FMT, &val) != 1) {
        return "MCacheMaxObjectSize value must be an integer (bytes)";
    }
    sconf->max_cache_object_size = val;
    return NULL;
}
static const char *set_max_object_count(cmd_parms *parms, void *in_struct_ptr, const char *arg)
{
    apr_size_t val;

    if (sscanf(arg, "%" APR_SIZE_T_FMT, &val) != 1) {
        return "MCacheMaxObjectCount value must be an integer";
    }
    sconf->max_object_cnt = val;
    return NULL;
}

static const char *set_cache_removal_algorithm(cmd_parms *parms, void *name, const char *arg)
{
    if (strcasecmp("LRU", arg)) {
        sconf->cache_remove_algorithm = memcache_lru_algorithm;
    }
    else {
        if (strcasecmp("GDSF", arg)) {
            sconf->cache_remove_algorithm = memcache_gdsf_algorithm;
        }
        else {
            return "currently implemented algorithms are LRU and GDSF";
        }
    }
    return NULL;
}

static const char *set_max_streaming_buffer(cmd_parms *parms, void *dummy, const char *arg)
{
    char *err;
    if (apr_strtoff(&sconf->max_streaming_buffer_size, arg, &err, 10) || *err) {
        return "MCacheMaxStreamingBuffer value must be a number";
    }

    return NULL;
}

static const command_rec cache_cmds[] = {
    AP_INIT_TAKE1("MCacheSize", set_max_cache_size, NULL, RSRC_CONF, "The maximum amount of memory used by the cache in KBytes"), AP_INIT_TAKE1("MCacheMaxObjectCount", set_max_object_count, NULL, RSRC_CONF, "The maximum number of objects allowed to be placed in the cache"), AP_INIT_TAKE1("MCacheMinObjectSize", set_min_cache_object_size, NULL, RSRC_CONF, "The minimum size (in bytes) of an object to be placed in the cache"), AP_INIT_TAKE1("MCacheMaxObjectSize", set_max_cache_object_size, NULL, RSRC_CONF, "The maximum size (in bytes) of an object to be placed in the cache"), AP_INIT_TAKE1("MCacheRemovalAlgorithm", set_cache_removal_algorithm, NULL, RSRC_CONF, "The algorithm used to remove entries from the cache (default: GDSF)"), AP_INIT_TAKE1("MCacheMaxStreamingBuffer", set_max_streaming_buffer, NULL, RSRC_CONF, "Maximum number of bytes of content to buffer for a streamed response"), {NULL}











};

static const cache_provider cache_mem_provider = {
    &remove_entity, &store_headers, &store_body, &recall_headers, &recall_body, &create_mem_entity, &open_entity, &remove_url, };








static const cache_provider cache_fd_provider = {
    &remove_entity, &store_headers, &store_body, &recall_headers, &recall_body, &create_fd_entity, &open_entity, &remove_url, };








static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(mem_cache_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    
    
    
    ap_register_provider(p, CACHE_PROVIDER_GROUP, "mem", "0", &cache_mem_provider);
    ap_register_provider(p, CACHE_PROVIDER_GROUP, "fd", "0", &cache_fd_provider);
}

module AP_MODULE_DECLARE_DATA mem_cache_module = {
    STANDARD20_MODULE_STUFF, NULL, NULL, create_cache_config, NULL, cache_cmds, register_hooks };






