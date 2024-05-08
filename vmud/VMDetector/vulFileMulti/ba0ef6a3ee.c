



























AP_DECLARE_DATA scoreboard *ap_scoreboard_image = NULL;
AP_DECLARE_DATA const char *ap_scoreboard_fname = NULL;
static ap_scoreboard_e scoreboard_type;

const char * ap_set_scoreboard(cmd_parms *cmd, void *dummy, const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_scoreboard_fname = arg;
    return NULL;
}


AP_DECLARE_DATA int ap_extended_status = 0;

const char *ap_set_extended_status(cmd_parms *cmd, void *dummy, int arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    ap_extended_status = arg;
    return NULL;
}

AP_DECLARE_DATA int ap_mod_status_reqtail = 0;

const char *ap_set_reqtail(cmd_parms *cmd, void *dummy, int arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }
    ap_mod_status_reqtail = arg;
    return NULL;
}






static   apr_shm_t *ap_scoreboard_shm = NULL;




APR_HOOK_STRUCT( APR_HOOK_LINK(pre_mpm)
)

AP_IMPLEMENT_HOOK_RUN_ALL(int,pre_mpm, (apr_pool_t *p, ap_scoreboard_e sb_type), (p, sb_type),OK,DECLINED)


static APR_OPTIONAL_FN_TYPE(ap_logio_get_last_bytes)
                                *pfn_ap_logio_get_last_bytes;

struct ap_sb_handle_t {
    int child_num;
    int thread_num;
};

static int server_limit, thread_limit;
static apr_size_t scoreboard_size;


static apr_status_t ap_cleanup_shared_mem(void *d)
{

    free(ap_scoreboard_image);
    ap_scoreboard_image = NULL;
    apr_shm_destroy(ap_scoreboard_shm);

    return APR_SUCCESS;
}

AP_DECLARE(int) ap_calc_scoreboard_size(void)
{
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);

    scoreboard_size = sizeof(global_score);
    scoreboard_size += sizeof(process_score) * server_limit;
    scoreboard_size += sizeof(worker_score) * server_limit * thread_limit;

    pfn_ap_logio_get_last_bytes = APR_RETRIEVE_OPTIONAL_FN(ap_logio_get_last_bytes);

    return scoreboard_size;
}

AP_DECLARE(void) ap_init_scoreboard(void *shared_score)
{
    char *more_storage;
    int i;

    ap_calc_scoreboard_size();
    ap_scoreboard_image = ap_calloc(1, sizeof(scoreboard) + server_limit * sizeof(worker_score *));
    more_storage = shared_score;
    ap_scoreboard_image->global = (global_score *)more_storage;
    more_storage += sizeof(global_score);
    ap_scoreboard_image->parent = (process_score *)more_storage;
    more_storage += sizeof(process_score) * server_limit;
    ap_scoreboard_image->servers = (worker_score **)((char*)ap_scoreboard_image + sizeof(scoreboard));
    for (i = 0; i < server_limit; i++) {
        ap_scoreboard_image->servers[i] = (worker_score *)more_storage;
        more_storage += thread_limit * sizeof(worker_score);
    }
    ap_assert(more_storage == (char*)shared_score + scoreboard_size);
    ap_scoreboard_image->global->server_limit = server_limit;
    ap_scoreboard_image->global->thread_limit = thread_limit;
}


static apr_status_t create_namebased_scoreboard(apr_pool_t *pool, const char *fname)
{

    apr_status_t rv;

    
    apr_shm_remove(fname, pool); 

    rv = apr_shm_create(&ap_scoreboard_shm, scoreboard_size, fname, pool);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(00001)
                     "unable to create or access scoreboard \"%s\" " "(name-based shared memory failure)", fname);
        return rv;
    }

    return APR_SUCCESS;
}


static apr_status_t open_scoreboard(apr_pool_t *pconf)
{

    apr_status_t rv;
    char *fname = NULL;
    apr_pool_t *global_pool;

    
    rv = apr_pool_create(&global_pool, NULL);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(00002)
                     "Fatal error: unable to create global pool " "for use by the scoreboard");
        return rv;
    }

    
    if (ap_scoreboard_fname) {
        
        fname = ap_runtime_dir_relative(pconf, ap_scoreboard_fname);
        if (!fname) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, APR_EBADPATH, ap_server_conf, APLOGNO(00003)
                         "Fatal error: Invalid Scoreboard path %s", ap_scoreboard_fname);
            return APR_EBADPATH;
        }
        return create_namebased_scoreboard(global_pool, fname);
    }
    else { 
        rv = apr_shm_create(&ap_scoreboard_shm, scoreboard_size, NULL, global_pool);
        if ((rv != APR_SUCCESS) && (rv != APR_ENOTIMPL)) {
            ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(00004)
                         "Unable to create or access scoreboard " "(anonymous shared memory failure)");
            return rv;
        }
        
        else if (rv == APR_ENOTIMPL) {
            
            ap_scoreboard_fname = DEFAULT_SCOREBOARD;
            fname = ap_runtime_dir_relative(pconf, ap_scoreboard_fname);

            return create_namebased_scoreboard(global_pool, fname);
        }
    }

    return APR_SUCCESS;
}


AP_DECLARE(apr_status_t) ap_reopen_scoreboard(apr_pool_t *p, apr_shm_t **shm, int detached)
{

    if (!detached) {
        return APR_SUCCESS;
    }
    if (apr_shm_size_get(ap_scoreboard_shm) < scoreboard_size) {
        ap_log_error(APLOG_MARK, APLOG_CRIT, 0, ap_server_conf, APLOGNO(00005)
                     "Fatal error: shared scoreboard too small for child!");
        apr_shm_detach(ap_scoreboard_shm);
        ap_scoreboard_shm = NULL;
        return APR_EINVAL;
    }
    
    if (*shm) {
        *shm = ap_scoreboard_shm;
    }

    return APR_SUCCESS;
}

apr_status_t ap_cleanup_scoreboard(void *d)
{
    if (ap_scoreboard_image == NULL) {
        return APR_SUCCESS;
    }
    if (scoreboard_type == SB_SHARED) {
        ap_cleanup_shared_mem(NULL);
    }
    else {
        free(ap_scoreboard_image->global);
        free(ap_scoreboard_image);
        ap_scoreboard_image = NULL;
    }
    return APR_SUCCESS;
}


int ap_create_scoreboard(apr_pool_t *p, ap_scoreboard_e sb_type)
{
    int i;

    apr_status_t rv;


    pfn_ap_logio_get_last_bytes = APR_RETRIEVE_OPTIONAL_FN(ap_logio_get_last_bytes);

    if (ap_scoreboard_image) {
        ap_scoreboard_image->global->restart_time = apr_time_now();
        memset(ap_scoreboard_image->parent, 0, sizeof(process_score) * server_limit);
        for (i = 0; i < server_limit; i++) {
            memset(ap_scoreboard_image->servers[i], 0, sizeof(worker_score) * thread_limit);
        }
        return OK;
    }

    ap_calc_scoreboard_size();

    if (sb_type == SB_SHARED) {
        void *sb_shared;
        rv = open_scoreboard(p);
        if (rv || !(sb_shared = apr_shm_baseaddr_get(ap_scoreboard_shm))) {
            return HTTP_INTERNAL_SERVER_ERROR;
        }
        memset(sb_shared, 0, scoreboard_size);
        ap_init_scoreboard(sb_shared);
    }
    else  {

        
        void *sb_mem = ap_calloc(1, scoreboard_size);
        ap_init_scoreboard(sb_mem);
    }

    scoreboard_type = sb_type;
    ap_scoreboard_image->global->running_generation = 0;
    ap_scoreboard_image->global->restart_time = apr_time_now();

    apr_pool_cleanup_register(p, NULL, ap_cleanup_scoreboard, apr_pool_cleanup_null);

    return OK;
}



AP_DECLARE(int) ap_exists_scoreboard_image(void)
{
    return (ap_scoreboard_image ? 1 : 0);
}

AP_DECLARE(void) ap_increment_counts(ap_sb_handle_t *sb, request_rec *r)
{
    worker_score *ws;
    apr_off_t bytes;

    if (!sb)
        return;

    ws = &ap_scoreboard_image->servers[sb->child_num][sb->thread_num];
    if (pfn_ap_logio_get_last_bytes != NULL) {
        bytes = pfn_ap_logio_get_last_bytes(r->connection);
    }
    else if (r->method_number == M_GET && r->method[0] == 'H') {
        bytes = 0;
    }
    else {
        bytes = r->bytes_sent;
    }


    times(&ws->times);

    ws->access_count++;
    ws->my_access_count++;
    ws->conn_count++;
    ws->bytes_served += bytes;
    ws->my_bytes_served += bytes;
    ws->conn_bytes += bytes;
}

AP_DECLARE(int) ap_find_child_by_pid(apr_proc_t *pid)
{
    int i;
    int max_daemons_limit = 0;

    ap_mpm_query(AP_MPMQ_MAX_DAEMONS, &max_daemons_limit);

    for (i = 0; i < max_daemons_limit; ++i) {
        if (ap_scoreboard_image->parent[i].pid == pid->pid) {
            return i;
        }
    }

    return -1;
}

AP_DECLARE(void) ap_create_sb_handle(ap_sb_handle_t **new_sbh, apr_pool_t *p, int child_num, int thread_num)
{
    *new_sbh = (ap_sb_handle_t *)apr_palloc(p, sizeof(ap_sb_handle_t));
    (*new_sbh)->child_num = child_num;
    (*new_sbh)->thread_num = thread_num;
}

static void copy_request(char *rbuf, apr_size_t rbuflen, request_rec *r)
{
    char *p;

    if (r->the_request == NULL) {
        apr_cpystrn(rbuf, "NULL", rbuflen);
        return; 
    }

    if (r->parsed_uri.password == NULL) {
        p = r->the_request;
    }
    else {
        
        p = apr_pstrcat(r->pool, r->method, " ", apr_uri_unparse(r->pool, &r->parsed_uri, APR_URI_UNP_OMITPASSWORD), r->assbackwards ? NULL : " ", r->protocol, NULL);


    }

    
    if (!ap_mod_status_reqtail) {
        apr_cpystrn(rbuf, p, rbuflen);
    }
    else {
        apr_size_t slen = strlen(p);
        if (slen < rbuflen) {
            
            apr_cpystrn(rbuf, p, rbuflen);
        }
        else {
            apr_cpystrn(rbuf, p+(slen-rbuflen+1), rbuflen);
        }
    }
}

static int update_child_status_internal(int child_num, int thread_num, int status, conn_rec *c, request_rec *r)



{
    int old_status;
    worker_score *ws;
    process_score *ps;
    int mpm_generation;

    ws = &ap_scoreboard_image->servers[child_num][thread_num];
    old_status = ws->status;
    ws->status = status;

    ps = &ap_scoreboard_image->parent[child_num];

    if (status == SERVER_READY && old_status == SERVER_STARTING) {
        ws->thread_num = child_num * thread_limit + thread_num;
        ap_mpm_query(AP_MPMQ_GENERATION, &mpm_generation);
        ps->generation = mpm_generation;
    }

    if (ap_extended_status) {
        if (status == SERVER_READY || status == SERVER_DEAD) {
            
            if (status == SERVER_DEAD) {
                ws->my_access_count = 0L;
                ws->my_bytes_served = 0L;
            }
            ws->conn_count = 0;
            ws->conn_bytes = 0;
            ws->last_used = apr_time_now();
        }
        if (r) {
            apr_cpystrn(ws->client, ap_get_remote_host(c, r->per_dir_config, REMOTE_NOLOOKUP, NULL), sizeof(ws->client));
            copy_request(ws->request, sizeof(ws->request), r);
            if (r->server) {
                apr_snprintf(ws->vhost, sizeof(ws->vhost), "%s:%d", r->server->server_hostname, r->connection->local_addr->port);

            }
        }
        else if (c) {
            apr_cpystrn(ws->client, ap_get_remote_host(c, NULL, REMOTE_NOLOOKUP, NULL), sizeof(ws->client));
            ws->request[0]='\0';
            ws->vhost[0]='\0';
        }
    }

    return old_status;
}

AP_DECLARE(int) ap_update_child_status_from_indexes(int child_num, int thread_num, int status, request_rec *r)


{
    if (child_num < 0) {
        return -1;
    }

    return update_child_status_internal(child_num, thread_num, status, r ? r->connection : NULL, r);

}

AP_DECLARE(int) ap_update_child_status(ap_sb_handle_t *sbh, int status, request_rec *r)
{
    if (!sbh)
        return -1;

    return update_child_status_internal(sbh->child_num, sbh->thread_num, status, r ? r->connection : NULL, r);


}

AP_DECLARE(int) ap_update_child_status_from_conn(ap_sb_handle_t *sbh, int status, conn_rec *c)
{
    if (!sbh)
        return -1;

    return update_child_status_internal(sbh->child_num, sbh->thread_num, status, c, NULL);
}

AP_DECLARE(void) ap_time_process_request(ap_sb_handle_t *sbh, int status)
{
    worker_score *ws;

    if (!sbh)
        return;

    if (sbh->child_num < 0) {
        return;
    }

    ws = &ap_scoreboard_image->servers[sbh->child_num][sbh->thread_num];

    if (status == START_PREQUEST) {
        ws->start_time = ws->last_used = apr_time_now();
    }
    else if (status == STOP_PREQUEST) {
        ws->stop_time = ws->last_used = apr_time_now();
    }
}

AP_DECLARE(worker_score *) ap_get_scoreboard_worker_from_indexes(int x, int y)
{
    if (((x < 0) || (x >= server_limit)) || ((y < 0) || (y >= thread_limit))) {
        return(NULL); 
    }
    return &ap_scoreboard_image->servers[x][y];
}

AP_DECLARE(worker_score *) ap_get_scoreboard_worker(ap_sb_handle_t *sbh)
{
    if (!sbh)
        return NULL;

    return ap_get_scoreboard_worker_from_indexes(sbh->child_num, sbh->thread_num);
}

AP_DECLARE(process_score *) ap_get_scoreboard_process(int x)
{
    if ((x < 0) || (x >= server_limit)) {
        return(NULL); 
    }
    return &ap_scoreboard_image->parent[x];
}

AP_DECLARE(global_score *) ap_get_scoreboard_global()
{
    return ap_scoreboard_image->global;
}
