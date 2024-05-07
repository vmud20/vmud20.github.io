























static int stopped = 0;

typedef struct ossl_init_stop_st OPENSSL_INIT_STOP;
struct ossl_init_stop_st {
    void (*handler)(void);
    OPENSSL_INIT_STOP *next;
};

static OPENSSL_INIT_STOP *stop_handlers = NULL;
static CRYPTO_RWLOCK *init_lock = NULL;

static CRYPTO_ONCE base = CRYPTO_ONCE_STATIC_INIT;
static int base_inited = 0;
DEFINE_RUN_ONCE_STATIC(ossl_init_base)
{
    

    OSSL_TRACE(INIT, "ossl_init_base: setting up stop handlers\n");

    ossl_malloc_setup_failures();


    if ((init_lock = CRYPTO_THREAD_lock_new()) == NULL)
        goto err;
    OPENSSL_cpuid_setup();

    if (!ossl_init_thread())
        return 0;

    base_inited = 1;
    return 1;

err:
    OSSL_TRACE(INIT, "ossl_init_base failed!\n");
    CRYPTO_THREAD_lock_free(init_lock);
    init_lock = NULL;

    return 0;
}

static CRYPTO_ONCE register_atexit = CRYPTO_ONCE_STATIC_INIT;

static int win32atexit(void)
{
    OPENSSL_cleanup();
    return 0;
}


DEFINE_RUN_ONCE_STATIC(ossl_init_register_atexit)
{

    fprintf(stderr, "OPENSSL_INIT: ossl_init_register_atexit()\n");



    
    if (_onexit(win32atexit) == NULL)
        return 0;

    if (atexit(OPENSSL_cleanup) != 0)
        return 0;



    return 1;
}

DEFINE_RUN_ONCE_STATIC_ALT(ossl_init_no_register_atexit, ossl_init_register_atexit)
{

    fprintf(stderr, "OPENSSL_INIT: ossl_init_no_register_atexit ok!\n");

    
    return 1;
}

static CRYPTO_ONCE load_crypto_nodelete = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(ossl_init_load_crypto_nodelete)
{
    OSSL_TRACE(INIT, "ossl_init_load_crypto_nodelete()\n");



    {
        HMODULE handle = NULL;
        BOOL ret;

        
        ret = GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, (void *)&base_inited, &handle);


        OSSL_TRACE1(INIT, "ossl_init_load_crypto_nodelete: " "obtained DSO reference? %s\n", (ret == TRUE ? "No!" : "Yes."));


        return (ret == TRUE) ? 1 : 0;
    }

    
    {
        DSO *dso;
        void *err;

        if (!err_shelve_state(&err))
            return 0;

        dso = DSO_dsobyaddr(&base_inited, DSO_FLAG_NO_UNLOAD_ON_FREE);
        
        OSSL_TRACE1(INIT, "obtained DSO reference? %s\n", (dso == NULL ? "No!" : "Yes."));
        DSO_free(dso);
        err_unshelve_state(err);
    }



    return 1;
}

static CRYPTO_ONCE load_crypto_strings = CRYPTO_ONCE_STATIC_INIT;
static int load_crypto_strings_inited = 0;
DEFINE_RUN_ONCE_STATIC(ossl_init_load_crypto_strings)
{
    int ret = 1;
    

    OSSL_TRACE(INIT, "err_load_crypto_strings_int()\n");
    ret = err_load_crypto_strings_int();
    load_crypto_strings_inited = 1;

    return ret;
}

DEFINE_RUN_ONCE_STATIC_ALT(ossl_init_no_load_crypto_strings, ossl_init_load_crypto_strings)
{
    
    return 1;
}

static CRYPTO_ONCE add_all_ciphers = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(ossl_init_add_all_ciphers)
{
    

    OSSL_TRACE(INIT, "openssl_add_all_ciphers_int()\n");
    openssl_add_all_ciphers_int();

    return 1;
}

DEFINE_RUN_ONCE_STATIC_ALT(ossl_init_no_add_all_ciphers, ossl_init_add_all_ciphers)
{
    
    return 1;
}

static CRYPTO_ONCE add_all_digests = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(ossl_init_add_all_digests)
{
    

    OSSL_TRACE(INIT, "openssl_add_all_digests()\n");
    openssl_add_all_digests_int();

    return 1;
}

DEFINE_RUN_ONCE_STATIC_ALT(ossl_init_no_add_all_digests, ossl_init_add_all_digests)
{
    
    return 1;
}

static CRYPTO_ONCE config = CRYPTO_ONCE_STATIC_INIT;
static int config_inited = 0;
static const OPENSSL_INIT_SETTINGS *conf_settings = NULL;
DEFINE_RUN_ONCE_STATIC(ossl_init_config)
{
    int ret = openssl_config_int(conf_settings);
    config_inited = 1;
    return ret;
}
DEFINE_RUN_ONCE_STATIC_ALT(ossl_init_no_config, ossl_init_config)
{
    OSSL_TRACE(INIT, "openssl_no_config_int()\n");
    openssl_no_config_int();
    config_inited = 1;
    return 1;
}

static CRYPTO_ONCE async = CRYPTO_ONCE_STATIC_INIT;
static int async_inited = 0;
DEFINE_RUN_ONCE_STATIC(ossl_init_async)
{
    OSSL_TRACE(INIT, "async_init()\n");
    if (!async_init())
        return 0;
    async_inited = 1;
    return 1;
}


static CRYPTO_ONCE engine_openssl = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(ossl_init_engine_openssl)
{
    OSSL_TRACE(INIT, "engine_load_openssl_int()\n");
    engine_load_openssl_int();
    return 1;
}

static CRYPTO_ONCE engine_rdrand = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(ossl_init_engine_rdrand)
{
    OSSL_TRACE(INIT, "engine_load_rdrand_int()\n");
    engine_load_rdrand_int();
    return 1;
}

static CRYPTO_ONCE engine_dynamic = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(ossl_init_engine_dynamic)
{
    OSSL_TRACE(INIT, "engine_load_dynamic_int()\n");
    engine_load_dynamic_int();
    return 1;
}


static CRYPTO_ONCE engine_devcrypto = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(ossl_init_engine_devcrypto)
{
    OSSL_TRACE(INIT, "engine_load_devcrypto_int()\n");
    engine_load_devcrypto_int();
    return 1;
}


static CRYPTO_ONCE engine_padlock = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(ossl_init_engine_padlock)
{
    OSSL_TRACE(INIT, "engine_load_padlock_int()\n");
    engine_load_padlock_int();
    return 1;
}


static CRYPTO_ONCE engine_capi = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(ossl_init_engine_capi)
{
    OSSL_TRACE(INIT, "engine_load_capi_int()\n");
    engine_load_capi_int();
    return 1;
}


static CRYPTO_ONCE engine_afalg = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(ossl_init_engine_afalg)
{
    OSSL_TRACE(INIT, "engine_load_afalg_int()\n");
    engine_load_afalg_int();
    return 1;
}





static CRYPTO_ONCE zlib = CRYPTO_ONCE_STATIC_INIT;

static int zlib_inited = 0;
DEFINE_RUN_ONCE_STATIC(ossl_init_zlib)
{
    
    zlib_inited = 1;
    return 1;
}


void OPENSSL_cleanup(void)
{
    OPENSSL_INIT_STOP *currhandler, *lasthandler;

    

    
    if (!base_inited)
        return;

    
    if (stopped)
        return;
    stopped = 1;

    
    OPENSSL_thread_stop();

    currhandler = stop_handlers;
    while (currhandler != NULL) {
        currhandler->handler();
        lasthandler = currhandler;
        currhandler = currhandler->next;
        OPENSSL_free(lasthandler);
    }
    stop_handlers = NULL;

    CRYPTO_THREAD_lock_free(init_lock);
    init_lock = NULL;

    


    if (zlib_inited) {
        OSSL_TRACE(INIT, "OPENSSL_cleanup: comp_zlib_cleanup_int()\n");
        comp_zlib_cleanup_int();
    }


    if (async_inited) {
        OSSL_TRACE(INIT, "OPENSSL_cleanup: async_deinit()\n");
        async_deinit();
    }

    if (load_crypto_strings_inited) {
        OSSL_TRACE(INIT, "OPENSSL_cleanup: err_free_strings_int()\n");
        err_free_strings_int();
    }

    
    OSSL_TRACE(INIT, "OPENSSL_cleanup: rand_cleanup_int()\n");
    rand_cleanup_int();

    OSSL_TRACE(INIT, "OPENSSL_cleanup: conf_modules_free_int()\n");
    conf_modules_free_int();


    OSSL_TRACE(INIT, "OPENSSL_cleanup: engine_cleanup_int()\n");
    engine_cleanup_int();

    OSSL_TRACE(INIT, "OPENSSL_cleanup: ossl_store_cleanup_int()\n");
    ossl_store_cleanup_int();

    OSSL_TRACE(INIT, "OPENSSL_cleanup: openssl_ctx_default_deinit()\n");
    openssl_ctx_default_deinit();

    ossl_cleanup_thread();

    OSSL_TRACE(INIT, "OPENSSL_cleanup: bio_cleanup()\n");
    bio_cleanup();

    OSSL_TRACE(INIT, "OPENSSL_cleanup: evp_cleanup_int()\n");
    evp_cleanup_int();

    OSSL_TRACE(INIT, "OPENSSL_cleanup: obj_cleanup_int()\n");
    obj_cleanup_int();

    OSSL_TRACE(INIT, "OPENSSL_cleanup: err_int()\n");
    err_cleanup();

    OSSL_TRACE(INIT, "OPENSSL_cleanup: CRYPTO_secure_malloc_done()\n");
    CRYPTO_secure_malloc_done();

    OSSL_TRACE(INIT, "OPENSSL_cleanup: ossl_trace_cleanup()\n");
    ossl_trace_cleanup();

    base_inited = 0;
}


int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings)
{
    

    if (stopped) {
        if (!(opts & OPENSSL_INIT_BASE_ONLY))
            CRYPTOerr(CRYPTO_F_OPENSSL_INIT_CRYPTO, ERR_R_INIT_FAIL);
        return 0;
    }

    
    if (!RUN_ONCE(&base, ossl_init_base))
        return 0;

    if (opts & OPENSSL_INIT_BASE_ONLY)
        return 1;

    
    if ((opts & OPENSSL_INIT_NO_ATEXIT) != 0) {
        if (!RUN_ONCE_ALT(&register_atexit, ossl_init_no_register_atexit, ossl_init_register_atexit))
            return 0;
    } else if (!RUN_ONCE(&register_atexit, ossl_init_register_atexit)) {
        return 0;
    }

    if (!RUN_ONCE(&load_crypto_nodelete, ossl_init_load_crypto_nodelete))
        return 0;

    if ((opts & OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS)
            && !RUN_ONCE_ALT(&load_crypto_strings, ossl_init_no_load_crypto_strings, ossl_init_load_crypto_strings))

        return 0;

    if ((opts & OPENSSL_INIT_LOAD_CRYPTO_STRINGS)
            && !RUN_ONCE(&load_crypto_strings, ossl_init_load_crypto_strings))
        return 0;

    if ((opts & OPENSSL_INIT_NO_ADD_ALL_CIPHERS)
            && !RUN_ONCE_ALT(&add_all_ciphers, ossl_init_no_add_all_ciphers, ossl_init_add_all_ciphers))
        return 0;

    if ((opts & OPENSSL_INIT_ADD_ALL_CIPHERS)
            && !RUN_ONCE(&add_all_ciphers, ossl_init_add_all_ciphers))
        return 0;

    if ((opts & OPENSSL_INIT_NO_ADD_ALL_DIGESTS)
            && !RUN_ONCE_ALT(&add_all_digests, ossl_init_no_add_all_digests, ossl_init_add_all_digests))
        return 0;

    if ((opts & OPENSSL_INIT_ADD_ALL_DIGESTS)
            && !RUN_ONCE(&add_all_digests, ossl_init_add_all_digests))
        return 0;

    if ((opts & OPENSSL_INIT_ATFORK)
            && !openssl_init_fork_handlers())
        return 0;

    if ((opts & OPENSSL_INIT_NO_LOAD_CONFIG)
            && !RUN_ONCE_ALT(&config, ossl_init_no_config, ossl_init_config))
        return 0;

    if (opts & OPENSSL_INIT_LOAD_CONFIG) {
        int ret;
        CRYPTO_THREAD_write_lock(init_lock);
        conf_settings = settings;
        ret = RUN_ONCE(&config, ossl_init_config);
        conf_settings = NULL;
        CRYPTO_THREAD_unlock(init_lock);
        if (ret <= 0)
            return 0;
    }

    if ((opts & OPENSSL_INIT_ASYNC)
            && !RUN_ONCE(&async, ossl_init_async))
        return 0;


    if ((opts & OPENSSL_INIT_ENGINE_OPENSSL)
            && !RUN_ONCE(&engine_openssl, ossl_init_engine_openssl))
        return 0;

    if ((opts & OPENSSL_INIT_ENGINE_RDRAND)
            && !RUN_ONCE(&engine_rdrand, ossl_init_engine_rdrand))
        return 0;

    if ((opts & OPENSSL_INIT_ENGINE_DYNAMIC)
            && !RUN_ONCE(&engine_dynamic, ossl_init_engine_dynamic))
        return 0;


    if ((opts & OPENSSL_INIT_ENGINE_CRYPTODEV)
            && !RUN_ONCE(&engine_devcrypto, ossl_init_engine_devcrypto))
        return 0;


    if ((opts & OPENSSL_INIT_ENGINE_PADLOCK)
            && !RUN_ONCE(&engine_padlock, ossl_init_engine_padlock))
        return 0;


    if ((opts & OPENSSL_INIT_ENGINE_CAPI)
            && !RUN_ONCE(&engine_capi, ossl_init_engine_capi))
        return 0;


    if ((opts & OPENSSL_INIT_ENGINE_AFALG)
            && !RUN_ONCE(&engine_afalg, ossl_init_engine_afalg))
        return 0;


    if (opts & (OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_ENGINE_OPENSSL | OPENSSL_INIT_ENGINE_AFALG)) {

        ENGINE_register_all_complete();
    }



    if ((opts & OPENSSL_INIT_ZLIB)
            && !RUN_ONCE(&zlib, ossl_init_zlib))
        return 0;


    return 1;
}

int OPENSSL_atexit(void (*handler)(void))
{
    OPENSSL_INIT_STOP *newhand;


    {
        union {
            void *sym;
            void (*func)(void);
        } handlersym;

        handlersym.func = handler;

        {
            HMODULE handle = NULL;
            BOOL ret;

            
            ret = GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, handlersym.sym, &handle);


            if (!ret)
                return 0;
        }

        
        {
            DSO *dso = NULL;

            ERR_set_mark();
            dso = DSO_dsobyaddr(handlersym.sym, DSO_FLAG_NO_UNLOAD_ON_FREE);
            
            OSSL_TRACE1(INIT, "atexit: obtained DSO reference? %s\n", (dso == NULL ? "No!" : "Yes."));

            DSO_free(dso);
            ERR_pop_to_mark();
        }

    }


    if ((newhand = OPENSSL_malloc(sizeof(*newhand))) == NULL) {
        CRYPTOerr(CRYPTO_F_OPENSSL_ATEXIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    newhand->handler = handler;
    newhand->next = stop_handlers;
    stop_handlers = newhand;

    return 1;
}




void OPENSSL_fork_prepare(void)
{
}

void OPENSSL_fork_parent(void)
{
}

void OPENSSL_fork_child(void)
{
    rand_fork();
    
}

