














static ENGINE *funct_ref;
static CRYPTO_RWLOCK *rand_engine_lock;

static CRYPTO_RWLOCK *rand_meth_lock;
static const RAND_METHOD *default_RAND_meth;
static CRYPTO_ONCE rand_init = CRYPTO_ONCE_STATIC_INIT;

static int rand_inited = 0;


int rand_fork_count;






size_t rand_acquire_entropy_from_tsc(RAND_POOL *pool)
{
    unsigned char c;
    int i;

    if ((OPENSSL_ia32cap_P[0] & (1 << 4)) != 0) {
        for (i = 0; i < TSC_READ_COUNT; i++) {
            c = (unsigned char)(OPENSSL_rdtsc() & 0xFF);
            rand_pool_add(pool, &c, 1, 4);
        }
    }
    return rand_pool_entropy_available(pool);
}



size_t OPENSSL_ia32_rdseed_bytes(unsigned char *buf, size_t len);
size_t OPENSSL_ia32_rdrand_bytes(unsigned char *buf, size_t len);


size_t rand_acquire_entropy_from_cpu(RAND_POOL *pool)
{
    size_t bytes_needed;
    unsigned char *buffer;

    bytes_needed = rand_pool_bytes_needed(pool, 1 );
    if (bytes_needed > 0) {
        buffer = rand_pool_add_begin(pool, bytes_needed);

        if (buffer != NULL) {
            
            if ((OPENSSL_ia32cap_P[2] & (1 << 18)) != 0) {
                if (OPENSSL_ia32_rdseed_bytes(buffer, bytes_needed)
                    == bytes_needed) {
                    rand_pool_add_end(pool, bytes_needed, 8 * bytes_needed);
                }
            } else if ((OPENSSL_ia32cap_P[1] & (1 << (62 - 32))) != 0) {
                if (OPENSSL_ia32_rdrand_bytes(buffer, bytes_needed)
                    == bytes_needed) {
                    rand_pool_add_end(pool, bytes_needed, 8 * bytes_needed);
                }
            } else {
                rand_pool_add_end(pool, 0, 0);
            }
        }
    }

    return rand_pool_entropy_available(pool);
}




size_t rand_drbg_get_entropy(RAND_DRBG *drbg, unsigned char **pout, int entropy, size_t min_len, size_t max_len, int prediction_resistance)


{
    size_t ret = 0;
    size_t entropy_available = 0;
    RAND_POOL *pool;

    if (drbg->parent != NULL && drbg->strength > drbg->parent->strength) {
        
        RANDerr(RAND_F_RAND_DRBG_GET_ENTROPY, RAND_R_PARENT_STRENGTH_TOO_WEAK);
        return 0;
    }

    if (drbg->seed_pool != NULL) {
        pool = drbg->seed_pool;
        pool->entropy_requested = entropy;
    } else {
        pool = rand_pool_new(entropy, drbg->secure, min_len, max_len);
        if (pool == NULL)
            return 0;
    }

    if (drbg->parent != NULL) {
        size_t bytes_needed = rand_pool_bytes_needed(pool, 1 );
        unsigned char *buffer = rand_pool_add_begin(pool, bytes_needed);

        if (buffer != NULL) {
            size_t bytes = 0;

            
            rand_drbg_lock(drbg->parent);
            if (RAND_DRBG_generate(drbg->parent, buffer, bytes_needed, prediction_resistance, NULL, 0) != 0)


                bytes = bytes_needed;
            drbg->reseed_next_counter = tsan_load(&drbg->parent->reseed_prop_counter);
            rand_drbg_unlock(drbg->parent);

            rand_pool_add_end(pool, bytes, 8 * bytes);
            entropy_available = rand_pool_entropy_available(pool);
        }

    } else {
        
        entropy_available = rand_pool_acquire_entropy(pool);
    }

    if (entropy_available > 0) {
        ret   = rand_pool_length(pool);
        *pout = rand_pool_detach(pool);
    }

    if (drbg->seed_pool == NULL)
        rand_pool_free(pool);
    return ret;
}


void rand_drbg_cleanup_entropy(RAND_DRBG *drbg, unsigned char *out, size_t outlen)
{
    if (drbg->seed_pool == NULL) {
        if (drbg->secure)
            OPENSSL_secure_clear_free(out, outlen);
        else OPENSSL_clear_free(out, outlen);
    }
}


size_t rand_drbg_get_additional_data(RAND_POOL *pool, unsigned char **pout)
{
    size_t ret = 0;

    if (rand_pool_add_additional_data(pool) == 0)
        goto err;

    ret = rand_pool_length(pool);
    *pout = rand_pool_detach(pool);

 err:
    return ret;
}

void rand_drbg_cleanup_additional_data(RAND_POOL *pool, unsigned char *out)
{
    rand_pool_reattach(pool, out);
}

void rand_fork(void)
{
    rand_fork_count++;
}


DEFINE_RUN_ONCE_STATIC(do_rand_init)
{

    rand_engine_lock = CRYPTO_THREAD_lock_new();
    if (rand_engine_lock == NULL)
        return 0;


    rand_meth_lock = CRYPTO_THREAD_lock_new();
    if (rand_meth_lock == NULL)
        goto err;

    if (!rand_pool_init())
        goto err;

    rand_inited = 1;
    return 1;

 err:
    CRYPTO_THREAD_lock_free(rand_meth_lock);
    rand_meth_lock = NULL;

    CRYPTO_THREAD_lock_free(rand_engine_lock);
    rand_engine_lock = NULL;

    return 0;
}

void rand_cleanup_int(void)
{
    const RAND_METHOD *meth = default_RAND_meth;

    if (!rand_inited)
        return;

    if (meth != NULL && meth->cleanup != NULL)
        meth->cleanup();
    RAND_set_rand_method(NULL);
    rand_pool_cleanup();

    CRYPTO_THREAD_lock_free(rand_engine_lock);
    rand_engine_lock = NULL;

    CRYPTO_THREAD_lock_free(rand_meth_lock);
    rand_meth_lock = NULL;
    rand_inited = 0;
}



void RAND_keep_random_devices_open(int keep)
{
    if (RUN_ONCE(&rand_init, do_rand_init))
        rand_pool_keep_random_devices_open(keep);
}


int RAND_poll(void)
{
    int ret = 0;

    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth == RAND_OpenSSL()) {
        
        RAND_DRBG *drbg = RAND_DRBG_get0_master();

        if (drbg == NULL)
            return 0;

        rand_drbg_lock(drbg);
        ret = rand_drbg_restart(drbg, NULL, 0, 0);
        rand_drbg_unlock(drbg);

        return ret;

    } else {
        RAND_POOL *pool = NULL;

        
        pool = rand_pool_new(RAND_DRBG_STRENGTH, 1, (RAND_DRBG_STRENGTH + 7) / 8, RAND_POOL_MAX_LENGTH);

        if (pool == NULL)
            return 0;

        if (rand_pool_acquire_entropy(pool) == 0)
            goto err;

        if (meth->add == NULL || meth->add(rand_pool_buffer(pool), rand_pool_length(pool), (rand_pool_entropy(pool) / 8.0)) == 0)


            goto err;

        ret = 1;

     err:
        rand_pool_free(pool);
    }

    return ret;
}




RAND_POOL *rand_pool_new(int entropy_requested, int secure, size_t min_len, size_t max_len)
{
    RAND_POOL *pool = OPENSSL_zalloc(sizeof(*pool));
    size_t min_alloc_size = RAND_POOL_MIN_ALLOCATION(secure);

    if (pool == NULL) {
        RANDerr(RAND_F_RAND_POOL_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    pool->min_len = min_len;
    pool->max_len = (max_len > RAND_POOL_MAX_LENGTH) ? RAND_POOL_MAX_LENGTH : max_len;
    pool->alloc_len = min_len < min_alloc_size ? min_alloc_size : min_len;
    if (pool->alloc_len > pool->max_len)
        pool->alloc_len = pool->max_len;

    if (secure)
        pool->buffer = OPENSSL_secure_zalloc(pool->alloc_len);
    else pool->buffer = OPENSSL_zalloc(pool->alloc_len);

    if (pool->buffer == NULL) {
        RANDerr(RAND_F_RAND_POOL_NEW, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    pool->entropy_requested = entropy_requested;
    pool->secure = secure;

    return pool;

err:
    OPENSSL_free(pool);
    return NULL;
}


RAND_POOL *rand_pool_attach(const unsigned char *buffer, size_t len, size_t entropy)
{
    RAND_POOL *pool = OPENSSL_zalloc(sizeof(*pool));

    if (pool == NULL) {
        RANDerr(RAND_F_RAND_POOL_ATTACH, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    
    pool->buffer = (unsigned char *) buffer;
    pool->len = len;

    pool->attached = 1;

    pool->min_len = pool->max_len = pool->alloc_len = pool->len;
    pool->entropy = entropy;

    return pool;
}


void rand_pool_free(RAND_POOL *pool)
{
    if (pool == NULL)
        return;

    
    if (!pool->attached) {
        if (pool->secure)
            OPENSSL_secure_clear_free(pool->buffer, pool->alloc_len);
        else OPENSSL_clear_free(pool->buffer, pool->alloc_len);
    }

    OPENSSL_free(pool);
}


const unsigned char *rand_pool_buffer(RAND_POOL *pool)
{
    return pool->buffer;
}


size_t rand_pool_entropy(RAND_POOL *pool)
{
    return pool->entropy;
}


size_t rand_pool_length(RAND_POOL *pool)
{
    return pool->len;
}


unsigned char *rand_pool_detach(RAND_POOL *pool)
{
    unsigned char *ret = pool->buffer;
    pool->buffer = NULL;
    pool->entropy = 0;
    return ret;
}


void rand_pool_reattach(RAND_POOL *pool, unsigned char *buffer)
{
    pool->buffer = buffer;
    OPENSSL_cleanse(pool->buffer, pool->len);
    pool->len = 0;
}






size_t rand_pool_entropy_available(RAND_POOL *pool)
{
    if (pool->entropy < pool->entropy_requested)
        return 0;

    if (pool->len < pool->min_len)
        return 0;

    return pool->entropy;
}



size_t rand_pool_entropy_needed(RAND_POOL *pool)
{
    if (pool->entropy < pool->entropy_requested)
        return pool->entropy_requested - pool->entropy;

    return 0;
}


static int rand_pool_grow(RAND_POOL *pool, size_t len)
{
    if (len > pool->alloc_len - pool->len) {
        unsigned char *p;
        const size_t limit = pool->max_len / 2;
        size_t newlen = pool->alloc_len;

        if (pool->attached || len > pool->max_len - pool->len) {
            RANDerr(RAND_F_RAND_POOL_GROW, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        do newlen = newlen < limit ? newlen * 2 : pool->max_len;
        while (len > newlen - pool->len);

        if (pool->secure)
            p = OPENSSL_secure_zalloc(newlen);
        else p = OPENSSL_zalloc(newlen);
        if (p == NULL) {
            RANDerr(RAND_F_RAND_POOL_GROW, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        memcpy(p, pool->buffer, pool->len);
        if (pool->secure)
            OPENSSL_secure_clear_free(pool->buffer, pool->alloc_len);
        else OPENSSL_clear_free(pool->buffer, pool->alloc_len);
        pool->buffer = p;
        pool->alloc_len = newlen;
    }
    return 1;
}



size_t rand_pool_bytes_needed(RAND_POOL *pool, unsigned int entropy_factor)
{
    size_t bytes_needed;
    size_t entropy_needed = rand_pool_entropy_needed(pool);

    if (entropy_factor < 1) {
        RANDerr(RAND_F_RAND_POOL_BYTES_NEEDED, RAND_R_ARGUMENT_OUT_OF_RANGE);
        return 0;
    }

    bytes_needed = ENTROPY_TO_BYTES(entropy_needed, entropy_factor);

    if (bytes_needed > pool->max_len - pool->len) {
        
        RANDerr(RAND_F_RAND_POOL_BYTES_NEEDED, RAND_R_RANDOM_POOL_OVERFLOW);
        return 0;
    }

    if (pool->len < pool->min_len && bytes_needed < pool->min_len - pool->len)
        
        bytes_needed = pool->min_len - pool->len;

    
    if (!rand_pool_grow(pool, bytes_needed)) {
        
        pool->max_len = pool->len = 0;
        return 0;
    }

    return bytes_needed;
}


size_t rand_pool_bytes_remaining(RAND_POOL *pool)
{
    return pool->max_len - pool->len;
}


int rand_pool_add(RAND_POOL *pool, const unsigned char *buffer, size_t len, size_t entropy)
{
    if (len > pool->max_len - pool->len) {
        RANDerr(RAND_F_RAND_POOL_ADD, RAND_R_ENTROPY_INPUT_TOO_LONG);
        return 0;
    }

    if (pool->buffer == NULL) {
        RANDerr(RAND_F_RAND_POOL_ADD, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (len > 0) {
        
        if (pool->alloc_len > pool->len && pool->buffer + pool->len == buffer) {
            RANDerr(RAND_F_RAND_POOL_ADD, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        
        if (!rand_pool_grow(pool, len))
            return 0;
        memcpy(pool->buffer + pool->len, buffer, len);
        pool->len += len;
        pool->entropy += entropy;
    }

    return 1;
}


unsigned char *rand_pool_add_begin(RAND_POOL *pool, size_t len)
{
    if (len == 0)
        return NULL;

    if (len > pool->max_len - pool->len) {
        RANDerr(RAND_F_RAND_POOL_ADD_BEGIN, RAND_R_RANDOM_POOL_OVERFLOW);
        return NULL;
    }

    if (pool->buffer == NULL) {
        RANDerr(RAND_F_RAND_POOL_ADD_BEGIN, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    
    if (!rand_pool_grow(pool, len))
        return NULL;

    return pool->buffer + pool->len;
}


int rand_pool_add_end(RAND_POOL *pool, size_t len, size_t entropy)
{
    if (len > pool->alloc_len - pool->len) {
        RANDerr(RAND_F_RAND_POOL_ADD_END, RAND_R_RANDOM_POOL_OVERFLOW);
        return 0;
    }

    if (len > 0) {
        pool->len += len;
        pool->entropy += entropy;
    }

    return 1;
}


int RAND_set_rand_method(const RAND_METHOD *meth)
{
    if (!RUN_ONCE(&rand_init, do_rand_init))
        return 0;

    CRYPTO_THREAD_write_lock(rand_meth_lock);

    ENGINE_finish(funct_ref);
    funct_ref = NULL;

    default_RAND_meth = meth;
    CRYPTO_THREAD_unlock(rand_meth_lock);
    return 1;
}


const RAND_METHOD *RAND_get_rand_method(void)
{

    return NULL;

    const RAND_METHOD *tmp_meth = NULL;

    if (!RUN_ONCE(&rand_init, do_rand_init))
        return NULL;

    CRYPTO_THREAD_write_lock(rand_meth_lock);
    if (default_RAND_meth == NULL) {

        ENGINE *e;

        
        if ((e = ENGINE_get_default_RAND()) != NULL && (tmp_meth = ENGINE_get_RAND(e)) != NULL) {
            funct_ref = e;
            default_RAND_meth = tmp_meth;
        } else {
            ENGINE_finish(e);
            default_RAND_meth = &rand_meth;
        }

        default_RAND_meth = &rand_meth;

    }
    tmp_meth = default_RAND_meth;
    CRYPTO_THREAD_unlock(rand_meth_lock);
    return tmp_meth;

}


int RAND_set_rand_engine(ENGINE *engine)
{
    const RAND_METHOD *tmp_meth = NULL;

    if (!RUN_ONCE(&rand_init, do_rand_init))
        return 0;

    if (engine != NULL) {
        if (!ENGINE_init(engine))
            return 0;
        tmp_meth = ENGINE_get_RAND(engine);
        if (tmp_meth == NULL) {
            ENGINE_finish(engine);
            return 0;
        }
    }
    CRYPTO_THREAD_write_lock(rand_engine_lock);
    
    RAND_set_rand_method(tmp_meth);
    funct_ref = engine;
    CRYPTO_THREAD_unlock(rand_engine_lock);
    return 1;
}


void RAND_seed(const void *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->seed != NULL)
        meth->seed(buf, num);
}

void RAND_add(const void *buf, int num, double randomness)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->add != NULL)
        meth->add(buf, num, randomness);
}


int rand_priv_bytes_ex(OPENSSL_CTX *ctx, unsigned char *buf, int num)
{
    RAND_DRBG *drbg;
    int ret;
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth != RAND_OpenSSL())
        return meth->bytes(buf, num);

    drbg = OPENSSL_CTX_get0_private_drbg(ctx);
    if (drbg == NULL)
        return 0;

    ret = RAND_DRBG_bytes(drbg, buf, num);
    return ret;
}

int RAND_priv_bytes(unsigned char *buf, int num)
{
    return rand_priv_bytes_ex(NULL, buf, num);
}

int rand_bytes_ex(OPENSSL_CTX *ctx, unsigned char *buf, int num)
{
    RAND_DRBG *drbg;
    int ret;
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth != RAND_OpenSSL()) {
        if (meth->bytes != NULL)
            return meth->bytes(buf, num);
        RANDerr(RAND_F_RAND_BYTES_EX, RAND_R_FUNC_NOT_IMPLEMENTED);
        return -1;
    }

    drbg = OPENSSL_CTX_get0_public_drbg(ctx);
    if (drbg == NULL)
        return 0;

    ret = RAND_DRBG_bytes(drbg, buf, num);
    return ret;
}

int RAND_bytes(unsigned char *buf, int num)
{
    return rand_bytes_ex(NULL, buf, num);
}


int RAND_pseudo_bytes(unsigned char *buf, int num)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->pseudorand != NULL)
        return meth->pseudorand(buf, num);
    return -1;
}


int RAND_status(void)
{
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth->status != NULL)
        return meth->status();
    return 0;
}
