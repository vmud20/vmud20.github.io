













typedef struct drbg_global_st {
    

    
    RAND_DRBG *master_drbg;
    
    CRYPTO_THREAD_LOCAL public_drbg;
    
    CRYPTO_THREAD_LOCAL private_drbg;
} DRBG_GLOBAL;

typedef struct drbg_nonce_global_st {
    CRYPTO_RWLOCK *rand_nonce_lock;
    int rand_nonce_count;
} DRBG_NONCE_GLOBAL;


static const char ossl_pers_string[] = DRBG_DEFAULT_PERS_STRING;








static int rand_drbg_type[3] = {
    RAND_DRBG_TYPE,  RAND_DRBG_TYPE, RAND_DRBG_TYPE };


static unsigned int rand_drbg_flags[3] = {
    RAND_DRBG_FLAGS | RAND_DRBG_FLAG_MASTER,  RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC, RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PRIVATE };



static unsigned int master_reseed_interval = MASTER_RESEED_INTERVAL;
static unsigned int slave_reseed_interval  = SLAVE_RESEED_INTERVAL;

static time_t master_reseed_time_interval = MASTER_RESEED_TIME_INTERVAL;
static time_t slave_reseed_time_interval  = SLAVE_RESEED_TIME_INTERVAL;


static const unsigned int rand_drbg_used_flags = RAND_DRBG_FLAG_CTR_NO_DF | RAND_DRBG_FLAG_HMAC | RAND_DRBG_TYPE_FLAGS;


static RAND_DRBG *drbg_setup(OPENSSL_CTX *ctx, RAND_DRBG *parent, int drbg_type);

static RAND_DRBG *rand_drbg_new(OPENSSL_CTX *ctx, int secure, int type, unsigned int flags, RAND_DRBG *parent);




static int is_ctr(int type)
{
    switch (type) {
    case NID_aes_128_ctr:
    case NID_aes_192_ctr:
    case NID_aes_256_ctr:
        return 1;
    default:
        return 0;
    }
}

static int is_digest(int type)
{
    switch (type) {
    case NID_sha1:
    case NID_sha224:
    case NID_sha256:
    case NID_sha384:
    case NID_sha512:
    case NID_sha512_224:
    case NID_sha512_256:
    case NID_sha3_224:
    case NID_sha3_256:
    case NID_sha3_384:
    case NID_sha3_512:
        return 1;
    default:
        return 0;
    }
}


static void *drbg_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    DRBG_GLOBAL *dgbl = OPENSSL_zalloc(sizeof(*dgbl));

    if (dgbl == NULL)
        return NULL;


    
     OPENSSL_init_crypto(0, NULL);


    if (!CRYPTO_THREAD_init_local(&dgbl->private_drbg, NULL))
        goto err1;

    if (!CRYPTO_THREAD_init_local(&dgbl->public_drbg, NULL))
        goto err2;

    dgbl->master_drbg = drbg_setup(libctx, NULL, RAND_DRBG_TYPE_MASTER);
    if (dgbl->master_drbg == NULL)
        goto err3;

    return dgbl;

 err3:
    CRYPTO_THREAD_cleanup_local(&dgbl->public_drbg);
 err2:
    CRYPTO_THREAD_cleanup_local(&dgbl->private_drbg);
 err1:
    OPENSSL_free(dgbl);
    return NULL;
}

static void drbg_ossl_ctx_free(void *vdgbl)
{
    DRBG_GLOBAL *dgbl = vdgbl;

    if (dgbl == NULL)
        return;

    RAND_DRBG_free(dgbl->master_drbg);
    CRYPTO_THREAD_cleanup_local(&dgbl->private_drbg);
    CRYPTO_THREAD_cleanup_local(&dgbl->public_drbg);

    OPENSSL_free(dgbl);
}

static const OPENSSL_CTX_METHOD drbg_ossl_ctx_method = {
    drbg_ossl_ctx_new, drbg_ossl_ctx_free, };



static void *drbg_nonce_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    DRBG_NONCE_GLOBAL *dngbl = OPENSSL_zalloc(sizeof(*dngbl));

    if (dngbl == NULL)
        return NULL;

    dngbl->rand_nonce_lock = CRYPTO_THREAD_lock_new();
    if (dngbl->rand_nonce_lock == NULL) {
        OPENSSL_free(dngbl);
        return NULL;
    }

    return dngbl;
}

static void drbg_nonce_ossl_ctx_free(void *vdngbl)
{
    DRBG_NONCE_GLOBAL *dngbl = vdngbl;

    if (dngbl == NULL)
        return;

    CRYPTO_THREAD_lock_free(dngbl->rand_nonce_lock);

    OPENSSL_free(dngbl);
}

static const OPENSSL_CTX_METHOD drbg_nonce_ossl_ctx_method = {
    drbg_nonce_ossl_ctx_new, drbg_nonce_ossl_ctx_free, };


static DRBG_GLOBAL *drbg_get_global(OPENSSL_CTX *libctx)
{
    return openssl_ctx_get_data(libctx, OPENSSL_CTX_DRBG_INDEX, &drbg_ossl_ctx_method);
}


size_t rand_drbg_get_nonce(RAND_DRBG *drbg, unsigned char **pout, int entropy, size_t min_len, size_t max_len)

{
    size_t ret = 0;
    RAND_POOL *pool;
    DRBG_NONCE_GLOBAL *dngbl = openssl_ctx_get_data(drbg->libctx, OPENSSL_CTX_DRBG_NONCE_INDEX, &drbg_nonce_ossl_ctx_method);

    struct {
        void *instance;
        int count;
    } data;

    if (dngbl == NULL)
        return 0;

    memset(&data, 0, sizeof(data));
    pool = rand_pool_new(0, 0, min_len, max_len);
    if (pool == NULL)
        return 0;

    if (rand_pool_add_nonce_data(pool) == 0)
        goto err;

    data.instance = drbg;
    CRYPTO_atomic_add(&dngbl->rand_nonce_count, 1, &data.count, dngbl->rand_nonce_lock);

    if (rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0) == 0)
        goto err;

    ret   = rand_pool_length(pool);
    *pout = rand_pool_detach(pool);

 err:
    rand_pool_free(pool);

    return ret;
}


void rand_drbg_cleanup_nonce(RAND_DRBG *drbg, unsigned char *out, size_t outlen)
{
    OPENSSL_clear_free(out, outlen);
}


int RAND_DRBG_set(RAND_DRBG *drbg, int type, unsigned int flags)
{
    int ret = 1;

    if (type == 0 && flags == 0) {
        type = rand_drbg_type[RAND_DRBG_TYPE_MASTER];
        flags = rand_drbg_flags[RAND_DRBG_TYPE_MASTER];
    }

    
    if (drbg->type != 0 && (type != drbg->type || flags != drbg->flags)) {
        drbg->meth->uninstantiate(drbg);
        rand_pool_free(drbg->adin_pool);
        drbg->adin_pool = NULL;
    }

    drbg->state = DRBG_UNINITIALISED;
    drbg->flags = flags;
    drbg->type = type;

    if (type == 0) {
        
        drbg->meth = NULL;
        return 1;
    } else if (is_ctr(type)) {
        ret = drbg_ctr_init(drbg);
    } else if (is_digest(type)) {
        if (flags & RAND_DRBG_FLAG_HMAC)
            ret = drbg_hmac_init(drbg);
        else ret = drbg_hash_init(drbg);
    } else {
        drbg->type = 0;
        drbg->flags = 0;
        drbg->meth = NULL;
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_UNSUPPORTED_DRBG_TYPE);
        return 0;
    }

    if (ret == 0) {
        drbg->state = DRBG_ERROR;
        RANDerr(RAND_F_RAND_DRBG_SET, RAND_R_ERROR_INITIALISING_DRBG);
    }
    return ret;
}


int RAND_DRBG_set_defaults(int type, unsigned int flags)
{
    int all;
    if (!(is_digest(type) || is_ctr(type))) {
        RANDerr(RAND_F_RAND_DRBG_SET_DEFAULTS, RAND_R_UNSUPPORTED_DRBG_TYPE);
        return 0;
    }

    if ((flags & ~rand_drbg_used_flags) != 0) {
        RANDerr(RAND_F_RAND_DRBG_SET_DEFAULTS, RAND_R_UNSUPPORTED_DRBG_FLAGS);
        return 0;
    }

    all = ((flags & RAND_DRBG_TYPE_FLAGS) == 0);
    if (all || (flags & RAND_DRBG_FLAG_MASTER) != 0) {
        rand_drbg_type[RAND_DRBG_TYPE_MASTER] = type;
        rand_drbg_flags[RAND_DRBG_TYPE_MASTER] = flags | RAND_DRBG_FLAG_MASTER;
    }
    if (all || (flags & RAND_DRBG_FLAG_PUBLIC) != 0) {
        rand_drbg_type[RAND_DRBG_TYPE_PUBLIC]  = type;
        rand_drbg_flags[RAND_DRBG_TYPE_PUBLIC] = flags | RAND_DRBG_FLAG_PUBLIC;
    }
    if (all || (flags & RAND_DRBG_FLAG_PRIVATE) != 0) {
        rand_drbg_type[RAND_DRBG_TYPE_PRIVATE] = type;
        rand_drbg_flags[RAND_DRBG_TYPE_PRIVATE] = flags | RAND_DRBG_FLAG_PRIVATE;
    }
    return 1;
}



static RAND_DRBG *rand_drbg_new(OPENSSL_CTX *ctx, int secure, int type, unsigned int flags, RAND_DRBG *parent)



{
    RAND_DRBG *drbg = secure ? OPENSSL_secure_zalloc(sizeof(*drbg))
                             : OPENSSL_zalloc(sizeof(*drbg));

    if (drbg == NULL) {
        RANDerr(RAND_F_RAND_DRBG_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    drbg->libctx = ctx;
    drbg->secure = secure && CRYPTO_secure_allocated(drbg);
    drbg->fork_count = rand_fork_count;
    drbg->parent = parent;

    if (parent == NULL) {

        drbg->get_entropy = rand_crngt_get_entropy;
        drbg->cleanup_entropy = rand_crngt_cleanup_entropy;

        drbg->get_entropy = rand_drbg_get_entropy;
        drbg->cleanup_entropy = rand_drbg_cleanup_entropy;


        drbg->get_nonce = rand_drbg_get_nonce;
        drbg->cleanup_nonce = rand_drbg_cleanup_nonce;


        drbg->reseed_interval = master_reseed_interval;
        drbg->reseed_time_interval = master_reseed_time_interval;
    } else {
        drbg->get_entropy = rand_drbg_get_entropy;
        drbg->cleanup_entropy = rand_drbg_cleanup_entropy;
        

        drbg->reseed_interval = slave_reseed_interval;
        drbg->reseed_time_interval = slave_reseed_time_interval;
    }

    if (RAND_DRBG_set(drbg, type, flags) == 0)
        goto err;

    if (parent != NULL) {
        rand_drbg_lock(parent);
        if (drbg->strength > parent->strength) {
            
            rand_drbg_unlock(parent);
            RANDerr(RAND_F_RAND_DRBG_NEW, RAND_R_PARENT_STRENGTH_TOO_WEAK);
            goto err;
        }
        rand_drbg_unlock(parent);
    }

    return drbg;

 err:
    RAND_DRBG_free(drbg);

    return NULL;
}

RAND_DRBG *RAND_DRBG_new_ex(OPENSSL_CTX *ctx, int type, unsigned int flags, RAND_DRBG *parent)
{
    return rand_drbg_new(ctx, 0, type, flags, parent);
}

RAND_DRBG *RAND_DRBG_new(int type, unsigned int flags, RAND_DRBG *parent)
{
    return RAND_DRBG_new_ex(NULL, type, flags, parent);
}

RAND_DRBG *RAND_DRBG_secure_new_ex(OPENSSL_CTX *ctx, int type, unsigned int flags, RAND_DRBG *parent)
{
    return rand_drbg_new(ctx, 1, type, flags, parent);
}

RAND_DRBG *RAND_DRBG_secure_new(int type, unsigned int flags, RAND_DRBG *parent)
{
    return RAND_DRBG_secure_new_ex(NULL, type, flags, parent);
}

void RAND_DRBG_free(RAND_DRBG *drbg)
{
    if (drbg == NULL)
        return;

    if (drbg->meth != NULL)
        drbg->meth->uninstantiate(drbg);
    rand_pool_free(drbg->adin_pool);
    CRYPTO_THREAD_lock_free(drbg->lock);
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DRBG, drbg, &drbg->ex_data);

    if (drbg->secure)
        OPENSSL_secure_clear_free(drbg, sizeof(*drbg));
    else OPENSSL_clear_free(drbg, sizeof(*drbg));
}


int RAND_DRBG_instantiate(RAND_DRBG *drbg, const unsigned char *pers, size_t perslen)
{
    unsigned char *nonce = NULL, *entropy = NULL;
    size_t noncelen = 0, entropylen = 0;
    size_t min_entropy = drbg->strength;
    size_t min_entropylen = drbg->min_entropylen;
    size_t max_entropylen = drbg->max_entropylen;

    if (perslen > drbg->max_perslen) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_PERSONALISATION_STRING_TOO_LONG);
        goto end;
    }

    if (drbg->meth == NULL) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED);
        goto end;
    }

    if (drbg->state != DRBG_UNINITIALISED) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, drbg->state == DRBG_ERROR ? RAND_R_IN_ERROR_STATE : RAND_R_ALREADY_INSTANTIATED);

        goto end;
    }

    drbg->state = DRBG_ERROR;

    
    if (drbg->min_noncelen > 0 && drbg->get_nonce == NULL) {
        min_entropy += drbg->strength / 2;
        min_entropylen += drbg->min_noncelen;
        max_entropylen += drbg->max_noncelen;
    }

    drbg->reseed_next_counter = tsan_load(&drbg->reseed_prop_counter);
    if (drbg->reseed_next_counter) {
        drbg->reseed_next_counter++;
        if(!drbg->reseed_next_counter)
            drbg->reseed_next_counter = 1;
    }

    if (drbg->get_entropy != NULL)
        entropylen = drbg->get_entropy(drbg, &entropy, min_entropy, min_entropylen, max_entropylen, 0);
    if (entropylen < min_entropylen || entropylen > max_entropylen) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (drbg->min_noncelen > 0 && drbg->get_nonce != NULL) {
        noncelen = drbg->get_nonce(drbg, &nonce, drbg->strength / 2, drbg->min_noncelen, drbg->max_noncelen);
        if (noncelen < drbg->min_noncelen || noncelen > drbg->max_noncelen) {
            RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_ERROR_RETRIEVING_NONCE);
            goto end;
        }
    }

    if (!drbg->meth->instantiate(drbg, entropy, entropylen, nonce, noncelen, pers, perslen)) {
        RANDerr(RAND_F_RAND_DRBG_INSTANTIATE, RAND_R_ERROR_INSTANTIATING_DRBG);
        goto end;
    }

    drbg->state = DRBG_READY;
    drbg->reseed_gen_counter = 1;
    drbg->reseed_time = time(NULL);
    tsan_store(&drbg->reseed_prop_counter, drbg->reseed_next_counter);

 end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, entropy, entropylen);
    if (nonce != NULL && drbg->cleanup_nonce != NULL)
        drbg->cleanup_nonce(drbg, nonce, noncelen);
    if (drbg->state == DRBG_READY)
        return 1;
    return 0;
}


int RAND_DRBG_uninstantiate(RAND_DRBG *drbg)
{
    int index = -1, type, flags;
    if (drbg->meth == NULL) {
        drbg->state = DRBG_ERROR;
        RANDerr(RAND_F_RAND_DRBG_UNINSTANTIATE, RAND_R_NO_DRBG_IMPLEMENTATION_SELECTED);
        return 0;
    }

    
    drbg->meth->uninstantiate(drbg);

    
    if (drbg->flags & RAND_DRBG_FLAG_MASTER)
        index = RAND_DRBG_TYPE_MASTER;
    else if (drbg->flags & RAND_DRBG_FLAG_PRIVATE)
        index = RAND_DRBG_TYPE_PRIVATE;
    else if (drbg->flags & RAND_DRBG_FLAG_PUBLIC)
        index = RAND_DRBG_TYPE_PUBLIC;

    if (index != -1) {
        flags = rand_drbg_flags[index];
        type = rand_drbg_type[index];
    } else {
        flags = drbg->flags;
        type = drbg->type;
    }
    return RAND_DRBG_set(drbg, type, flags);
}


int RAND_DRBG_reseed(RAND_DRBG *drbg, const unsigned char *adin, size_t adinlen, int prediction_resistance)

{
    unsigned char *entropy = NULL;
    size_t entropylen = 0;

    if (drbg->state == DRBG_ERROR) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_IN_ERROR_STATE);
        return 0;
    }
    if (drbg->state == DRBG_UNINITIALISED) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_NOT_INSTANTIATED);
        return 0;
    }

    if (adin == NULL) {
        adinlen = 0;
    } else if (adinlen > drbg->max_adinlen) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    drbg->state = DRBG_ERROR;

    drbg->reseed_next_counter = tsan_load(&drbg->reseed_prop_counter);
    if (drbg->reseed_next_counter) {
        drbg->reseed_next_counter++;
        if(!drbg->reseed_next_counter)
            drbg->reseed_next_counter = 1;
    }

    if (drbg->get_entropy != NULL)
        entropylen = drbg->get_entropy(drbg, &entropy, drbg->strength, drbg->min_entropylen, drbg->max_entropylen, prediction_resistance);


    if (entropylen < drbg->min_entropylen || entropylen > drbg->max_entropylen) {
        RANDerr(RAND_F_RAND_DRBG_RESEED, RAND_R_ERROR_RETRIEVING_ENTROPY);
        goto end;
    }

    if (!drbg->meth->reseed(drbg, entropy, entropylen, adin, adinlen))
        goto end;

    drbg->state = DRBG_READY;
    drbg->reseed_gen_counter = 1;
    drbg->reseed_time = time(NULL);
    tsan_store(&drbg->reseed_prop_counter, drbg->reseed_next_counter);

 end:
    if (entropy != NULL && drbg->cleanup_entropy != NULL)
        drbg->cleanup_entropy(drbg, entropy, entropylen);
    if (drbg->state == DRBG_READY)
        return 1;
    return 0;
}


int rand_drbg_restart(RAND_DRBG *drbg, const unsigned char *buffer, size_t len, size_t entropy)
{
    int reseeded = 0;
    const unsigned char *adin = NULL;
    size_t adinlen = 0;

    if (drbg->seed_pool != NULL) {
        RANDerr(RAND_F_RAND_DRBG_RESTART, ERR_R_INTERNAL_ERROR);
        drbg->state = DRBG_ERROR;
        rand_pool_free(drbg->seed_pool);
        drbg->seed_pool = NULL;
        return 0;
    }

    if (buffer != NULL) {
        if (entropy > 0) {
            if (drbg->max_entropylen < len) {
                RANDerr(RAND_F_RAND_DRBG_RESTART, RAND_R_ENTROPY_INPUT_TOO_LONG);
                drbg->state = DRBG_ERROR;
                return 0;
            }

            if (entropy > 8 * len) {
                RANDerr(RAND_F_RAND_DRBG_RESTART, RAND_R_ENTROPY_OUT_OF_RANGE);
                drbg->state = DRBG_ERROR;
                return 0;
            }

            
            drbg->seed_pool = rand_pool_attach(buffer, len, entropy);
            if (drbg->seed_pool == NULL)
                return 0;
        } else {
            if (drbg->max_adinlen < len) {
                RANDerr(RAND_F_RAND_DRBG_RESTART, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
                drbg->state = DRBG_ERROR;
                return 0;
            }
            adin = buffer;
            adinlen = len;
        }
    }

    
    if (drbg->state == DRBG_ERROR)
        RAND_DRBG_uninstantiate(drbg);

    
    if (drbg->state == DRBG_UNINITIALISED) {
        
        RAND_DRBG_instantiate(drbg, (const unsigned char *) ossl_pers_string, sizeof(ossl_pers_string) - 1);

        
        reseeded = (drbg->state == DRBG_READY);
    }

    
    if (drbg->state == DRBG_READY) {
        if (adin != NULL) {
            
            drbg->meth->reseed(drbg, adin, adinlen, NULL, 0);
        } else if (reseeded == 0) {
            
            RAND_DRBG_reseed(drbg, NULL, 0, 0);
        }
    }

    rand_pool_free(drbg->seed_pool);
    drbg->seed_pool = NULL;

    return drbg->state == DRBG_READY;
}


int RAND_DRBG_generate(RAND_DRBG *drbg, unsigned char *out, size_t outlen, int prediction_resistance, const unsigned char *adin, size_t adinlen)

{
    int reseed_required = 0;

    if (drbg->state != DRBG_READY) {
        
        rand_drbg_restart(drbg, NULL, 0, 0);

        if (drbg->state == DRBG_ERROR) {
            RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_IN_ERROR_STATE);
            return 0;
        }
        if (drbg->state == DRBG_UNINITIALISED) {
            RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_NOT_INSTANTIATED);
            return 0;
        }
    }

    if (outlen > drbg->max_request) {
        RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_REQUEST_TOO_LARGE_FOR_DRBG);
        return 0;
    }
    if (adinlen > drbg->max_adinlen) {
        RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_ADDITIONAL_INPUT_TOO_LONG);
        return 0;
    }

    if (drbg->fork_count != rand_fork_count) {
        drbg->fork_count = rand_fork_count;
        reseed_required = 1;
    }

    if (drbg->reseed_interval > 0) {
        if (drbg->reseed_gen_counter > drbg->reseed_interval)
            reseed_required = 1;
    }
    if (drbg->reseed_time_interval > 0) {
        time_t now = time(NULL);
        if (now < drbg->reseed_time || now - drbg->reseed_time >= drbg->reseed_time_interval)
            reseed_required = 1;
    }
    if (drbg->parent != NULL) {
        unsigned int reseed_counter = tsan_load(&drbg->reseed_prop_counter);
        if (reseed_counter > 0 && tsan_load(&drbg->parent->reseed_prop_counter)
                   != reseed_counter)
            reseed_required = 1;
    }

    if (reseed_required || prediction_resistance) {
        if (!RAND_DRBG_reseed(drbg, adin, adinlen, prediction_resistance)) {
            RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_RESEED_ERROR);
            return 0;
        }
        adin = NULL;
        adinlen = 0;
    }

    if (!drbg->meth->generate(drbg, out, outlen, adin, adinlen)) {
        drbg->state = DRBG_ERROR;
        RANDerr(RAND_F_RAND_DRBG_GENERATE, RAND_R_GENERATE_ERROR);
        return 0;
    }

    drbg->reseed_gen_counter++;

    return 1;
}


int RAND_DRBG_bytes(RAND_DRBG *drbg, unsigned char *out, size_t outlen)
{
    unsigned char *additional = NULL;
    size_t additional_len;
    size_t chunk;
    size_t ret = 0;

    if (drbg->adin_pool == NULL) {
        if (drbg->type == 0)
            goto err;
        drbg->adin_pool = rand_pool_new(0, 0, 0, drbg->max_adinlen);
        if (drbg->adin_pool == NULL)
            goto err;
    }

    additional_len = rand_drbg_get_additional_data(drbg->adin_pool, &additional);

    for ( ; outlen > 0; outlen -= chunk, out += chunk) {
        chunk = outlen;
        if (chunk > drbg->max_request)
            chunk = drbg->max_request;
        ret = RAND_DRBG_generate(drbg, out, chunk, 0, additional, additional_len);
        if (!ret)
            goto err;
    }
    ret = 1;

 err:
    if (additional != NULL)
        rand_drbg_cleanup_additional_data(drbg->adin_pool, additional);

    return ret;
}


int RAND_DRBG_set_callbacks(RAND_DRBG *drbg, RAND_DRBG_get_entropy_fn get_entropy, RAND_DRBG_cleanup_entropy_fn cleanup_entropy, RAND_DRBG_get_nonce_fn get_nonce, RAND_DRBG_cleanup_nonce_fn cleanup_nonce)



{
    if (drbg->state != DRBG_UNINITIALISED || drbg->parent != NULL)
        return 0;
    drbg->get_entropy = get_entropy;
    drbg->cleanup_entropy = cleanup_entropy;
    drbg->get_nonce = get_nonce;
    drbg->cleanup_nonce = cleanup_nonce;
    return 1;
}


int RAND_DRBG_set_reseed_interval(RAND_DRBG *drbg, unsigned int interval)
{
    if (interval > MAX_RESEED_INTERVAL)
        return 0;
    drbg->reseed_interval = interval;
    return 1;
}


int RAND_DRBG_set_reseed_time_interval(RAND_DRBG *drbg, time_t interval)
{
    if (interval > MAX_RESEED_TIME_INTERVAL)
        return 0;
    drbg->reseed_time_interval = interval;
    return 1;
}



int RAND_DRBG_set_reseed_defaults( unsigned int _master_reseed_interval, unsigned int _slave_reseed_interval, time_t _master_reseed_time_interval, time_t _slave_reseed_time_interval )




{
    if (_master_reseed_interval > MAX_RESEED_INTERVAL || _slave_reseed_interval > MAX_RESEED_INTERVAL)
        return 0;

    if (_master_reseed_time_interval > MAX_RESEED_TIME_INTERVAL || _slave_reseed_time_interval > MAX_RESEED_TIME_INTERVAL)
        return 0;

    master_reseed_interval = _master_reseed_interval;
    slave_reseed_interval = _slave_reseed_interval;

    master_reseed_time_interval = _master_reseed_time_interval;
    slave_reseed_time_interval = _slave_reseed_time_interval;

    return 1;
}


int rand_drbg_lock(RAND_DRBG *drbg)
{
    if (drbg->lock != NULL)
        return CRYPTO_THREAD_write_lock(drbg->lock);

    return 1;
}


int rand_drbg_unlock(RAND_DRBG *drbg)
{
    if (drbg->lock != NULL)
        return CRYPTO_THREAD_unlock(drbg->lock);

    return 1;
}


int rand_drbg_enable_locking(RAND_DRBG *drbg)
{
    if (drbg->state != DRBG_UNINITIALISED) {
        RANDerr(RAND_F_RAND_DRBG_ENABLE_LOCKING, RAND_R_DRBG_ALREADY_INITIALIZED);
        return 0;
    }

    if (drbg->lock == NULL) {
        if (drbg->parent != NULL && drbg->parent->lock == NULL) {
            RANDerr(RAND_F_RAND_DRBG_ENABLE_LOCKING, RAND_R_PARENT_LOCKING_NOT_ENABLED);
            return 0;
        }

        drbg->lock = CRYPTO_THREAD_lock_new();
        if (drbg->lock == NULL) {
            RANDerr(RAND_F_RAND_DRBG_ENABLE_LOCKING, RAND_R_FAILED_TO_CREATE_LOCK);
            return 0;
        }
    }

    return 1;
}


int RAND_DRBG_set_ex_data(RAND_DRBG *drbg, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&drbg->ex_data, idx, arg);
}

void *RAND_DRBG_get_ex_data(const RAND_DRBG *drbg, int idx)
{
    return CRYPTO_get_ex_data(&drbg->ex_data, idx);
}





static RAND_DRBG *drbg_setup(OPENSSL_CTX *ctx, RAND_DRBG *parent, int drbg_type)
{
    RAND_DRBG *drbg;

    drbg = RAND_DRBG_secure_new_ex(ctx, rand_drbg_type[drbg_type], rand_drbg_flags[drbg_type], parent);
    if (drbg == NULL)
        return NULL;

    
    if (parent == NULL && rand_drbg_enable_locking(drbg) == 0)
        goto err;

    
    tsan_store(&drbg->reseed_prop_counter, 1);

    
    (void)RAND_DRBG_instantiate(drbg, (const unsigned char *) ossl_pers_string, sizeof(ossl_pers_string) - 1);

    return drbg;

err:
    RAND_DRBG_free(drbg);
    return NULL;
}

static void drbg_delete_thread_state(void *arg)
{
    OPENSSL_CTX *ctx = arg;
    DRBG_GLOBAL *dgbl = drbg_get_global(ctx);
    RAND_DRBG *drbg;

    if (dgbl == NULL)
        return;
    drbg = CRYPTO_THREAD_get_local(&dgbl->public_drbg);
    CRYPTO_THREAD_set_local(&dgbl->public_drbg, NULL);
    RAND_DRBG_free(drbg);

    drbg = CRYPTO_THREAD_get_local(&dgbl->private_drbg);
    CRYPTO_THREAD_set_local(&dgbl->private_drbg, NULL);
    RAND_DRBG_free(drbg);
}


static int drbg_bytes(unsigned char *out, int count)
{
    int ret;
    RAND_DRBG *drbg = RAND_DRBG_get0_public();

    if (drbg == NULL)
        return 0;

    ret = RAND_DRBG_bytes(drbg, out, count);

    return ret;
}


size_t rand_drbg_seedlen(RAND_DRBG *drbg)
{
    
    size_t min_entropy = drbg->strength;
    size_t min_entropylen = drbg->min_entropylen;

    
    if (drbg->min_noncelen > 0 && drbg->get_nonce == NULL) {
        min_entropy += drbg->strength / 2;
        min_entropylen += drbg->min_noncelen;
    }

    
    min_entropy >>= 3;

    
    return min_entropy > min_entropylen ? min_entropy : min_entropylen;
}


static int drbg_add(const void *buf, int num, double randomness)
{
    int ret = 0;
    RAND_DRBG *drbg = RAND_DRBG_get0_master();
    size_t buflen;
    size_t seedlen;

    if (drbg == NULL)
        return 0;

    if (num < 0 || randomness < 0.0)
        return 0;

    rand_drbg_lock(drbg);
    seedlen = rand_drbg_seedlen(drbg);

    buflen = (size_t)num;


    
    randomness = 0.0;

    if (buflen < seedlen || randomness < (double) seedlen) {

        
        unsigned char dummy[1];

        ret = RAND_DRBG_generate(drbg, dummy, sizeof(dummy), 0, buf, buflen);
        rand_drbg_unlock(drbg);
        return ret;

        
        randomness = 0.0;

    }

    if (randomness > (double)seedlen) {
        
        randomness = (double)seedlen;
    }

    ret = rand_drbg_restart(drbg, buf, buflen, (size_t)(8 * randomness));
    rand_drbg_unlock(drbg);

    return ret;
}


static int drbg_seed(const void *buf, int num)
{
    return drbg_add(buf, num, num);
}


static int drbg_status(void)
{
    int ret;
    RAND_DRBG *drbg = RAND_DRBG_get0_master();

    if (drbg == NULL)
        return 0;

    rand_drbg_lock(drbg);
    ret = drbg->state == DRBG_READY ? 1 : 0;
    rand_drbg_unlock(drbg);
    return ret;
}


RAND_DRBG *OPENSSL_CTX_get0_master_drbg(OPENSSL_CTX *ctx)
{
    DRBG_GLOBAL *dgbl = drbg_get_global(ctx);

    if (dgbl == NULL)
        return NULL;

    return dgbl->master_drbg;
}

RAND_DRBG *RAND_DRBG_get0_master(void)
{
    return OPENSSL_CTX_get0_master_drbg(NULL);
}


RAND_DRBG *OPENSSL_CTX_get0_public_drbg(OPENSSL_CTX *ctx)
{
    DRBG_GLOBAL *dgbl = drbg_get_global(ctx);
    RAND_DRBG *drbg;

    if (dgbl == NULL)
        return NULL;

    drbg = CRYPTO_THREAD_get_local(&dgbl->public_drbg);
    if (drbg == NULL) {
        ctx = openssl_ctx_get_concrete(ctx);
        if (!ossl_init_thread_start(NULL, ctx, drbg_delete_thread_state))
            return NULL;
        drbg = drbg_setup(ctx, dgbl->master_drbg, RAND_DRBG_TYPE_PUBLIC);
        CRYPTO_THREAD_set_local(&dgbl->public_drbg, drbg);
    }
    return drbg;
}

RAND_DRBG *RAND_DRBG_get0_public(void)
{
    return OPENSSL_CTX_get0_public_drbg(NULL);
}


RAND_DRBG *OPENSSL_CTX_get0_private_drbg(OPENSSL_CTX *ctx)
{
    DRBG_GLOBAL *dgbl = drbg_get_global(ctx);
    RAND_DRBG *drbg;

    if (dgbl == NULL)
        return NULL;

    drbg = CRYPTO_THREAD_get_local(&dgbl->private_drbg);
    if (drbg == NULL) {
        ctx = openssl_ctx_get_concrete(ctx);
        if (!ossl_init_thread_start(NULL, ctx, drbg_delete_thread_state))
            return NULL;
        drbg = drbg_setup(ctx, dgbl->master_drbg, RAND_DRBG_TYPE_PRIVATE);
        CRYPTO_THREAD_set_local(&dgbl->private_drbg, drbg);
    }
    return drbg;
}

RAND_DRBG *RAND_DRBG_get0_private(void)
{
    return OPENSSL_CTX_get0_private_drbg(NULL);
}

RAND_METHOD rand_meth = {
    drbg_seed, drbg_bytes, NULL, drbg_add, drbg_bytes, drbg_status };






RAND_METHOD *RAND_OpenSSL(void)
{

    return &rand_meth;

    return NULL;

}
