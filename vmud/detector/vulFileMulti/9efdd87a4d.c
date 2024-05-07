



















typedef struct drbg_selftest_data_st {
    int post;
    int nid;
    unsigned int flags;

    
    const unsigned char *entropy;
    size_t entropylen;
    const unsigned char *nonce;
    size_t noncelen;
    const unsigned char *pers;
    size_t perslen;
    const unsigned char *adin;
    size_t adinlen;
    const unsigned char *entropyreseed;
    size_t entropyreseedlen;
    const unsigned char *adinreseed;
    size_t adinreseedlen;
    const unsigned char *adin2;
    size_t adin2len;
    const unsigned char *expected;
    size_t exlen;
    const unsigned char *kat2;
    size_t kat2len;

    
    const unsigned char *entropy_pr;
    size_t entropylen_pr;
    const unsigned char *nonce_pr;
    size_t noncelen_pr;
    const unsigned char *pers_pr;
    size_t perslen_pr;
    const unsigned char *adin_pr;
    size_t adinlen_pr;
    const unsigned char *entropypr_pr;
    size_t entropyprlen_pr;
    const unsigned char *ading_pr;
    size_t adinglen_pr;
    const unsigned char *entropyg_pr;
    size_t entropyglen_pr;
    const unsigned char *kat_pr;
    size_t katlen_pr;
    const unsigned char *kat2_pr;
    size_t kat2len_pr;
} DRBG_SELFTEST_DATA;





























static DRBG_SELFTEST_DATA drbg_test[] = {

    
    make_drbg_test_data_no_df (NID_aes_128_ctr, aes_128_no_df,  0), make_drbg_test_data_no_df (NID_aes_192_ctr, aes_192_no_df,  0), make_drbg_test_data_no_df (NID_aes_256_ctr, aes_256_no_df,  1),  make_drbg_test_data_use_df(NID_aes_128_ctr, aes_128_use_df, 0), make_drbg_test_data_use_df(NID_aes_192_ctr, aes_192_use_df, 0), make_drbg_test_data_use_df(NID_aes_256_ctr, aes_256_use_df, 1), make_drbg_test_data_hash(NID_sha1, sha1, 0), make_drbg_test_data_hash(NID_sha224, sha224, 0), make_drbg_test_data_hash(NID_sha256, sha256, 1), make_drbg_test_data_hash(NID_sha384, sha384, 0), make_drbg_test_data_hash(NID_sha512, sha512, 0), };












static int app_data_index;


typedef struct test_ctx_st {
    const unsigned char *entropy;
    size_t entropylen;
    int entropycnt;
    const unsigned char *nonce;
    size_t noncelen;
    int noncecnt;
} TEST_CTX;

static size_t kat_entropy(RAND_DRBG *drbg, unsigned char **pout, int entropy, size_t min_len, size_t max_len, int prediction_resistance)

{
    TEST_CTX *t = (TEST_CTX *)RAND_DRBG_get_ex_data(drbg, app_data_index);

    t->entropycnt++;
    *pout = (unsigned char *)t->entropy;
    return t->entropylen;
}

static size_t kat_nonce(RAND_DRBG *drbg, unsigned char **pout, int entropy, size_t min_len, size_t max_len)
{
    TEST_CTX *t = (TEST_CTX *)RAND_DRBG_get_ex_data(drbg, app_data_index);

    t->noncecnt++;
    *pout = (unsigned char *)t->nonce;
    return t->noncelen;
}

 
static int disable_crngt(RAND_DRBG *drbg)
{
    static const char pers[] = DRBG_DEFAULT_PERS_STRING;
    const int instantiate = drbg->state != DRBG_UNINITIALISED;

    if (drbg->get_entropy != rand_crngt_get_entropy)
        return 1;

     if ((instantiate && !RAND_DRBG_uninstantiate(drbg))
        || !TEST_true(RAND_DRBG_set_callbacks(drbg, &rand_drbg_get_entropy, &rand_drbg_cleanup_entropy, &rand_drbg_get_nonce, &rand_drbg_cleanup_nonce))


        || (instantiate && !RAND_DRBG_instantiate(drbg, (const unsigned char *)pers, sizeof(pers) - 1)))

        return 0;
    return 1;
}

static int uninstantiate(RAND_DRBG *drbg)
{
    int ret = drbg == NULL ? 1 : RAND_DRBG_uninstantiate(drbg);

    ERR_clear_error();
    return ret;
}


static int single_kat(DRBG_SELFTEST_DATA *td)
{
    RAND_DRBG *drbg = NULL;
    TEST_CTX t;
    int failures = 0;
    unsigned char buff[1024];

    
    if (!TEST_ptr(drbg = RAND_DRBG_new(td->nid, td->flags, NULL)))
        return 0;
    if (!TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL, kat_nonce, NULL))
        || !TEST_true(disable_crngt(drbg))) {
        failures++;
        goto err;
    }
    memset(&t, 0, sizeof(t));
    t.entropy = td->entropy;
    t.entropylen = td->entropylen;
    t.nonce = td->nonce;
    t.noncelen = td->noncelen;
    RAND_DRBG_set_ex_data(drbg, app_data_index, &t);

    if (!TEST_true(RAND_DRBG_instantiate(drbg, td->pers, td->perslen))
            || !TEST_true(RAND_DRBG_generate(drbg, buff, td->exlen, 0, td->adin, td->adinlen))
            || !TEST_mem_eq(td->expected, td->exlen, buff, td->exlen))
        failures++;

    
    t.entropy = td->entropyreseed;
    t.entropylen = td->entropyreseedlen;
    if (!TEST_true(RAND_DRBG_reseed(drbg, td->adinreseed, td->adinreseedlen, 0)
            || !TEST_true(RAND_DRBG_generate(drbg, buff, td->kat2len, 0, td->adin2, td->adin2len))
            || !TEST_mem_eq(td->kat2, td->kat2len, buff, td->kat2len)))
        failures++;
    uninstantiate(drbg);

    
    if (!TEST_true(RAND_DRBG_set(drbg, td->nid, td->flags))
            || !TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL, kat_nonce, NULL)))
        failures++;
    RAND_DRBG_set_ex_data(drbg, app_data_index, &t);
    t.entropy = td->entropy_pr;
    t.entropylen = td->entropylen_pr;
    t.nonce = td->nonce_pr;
    t.noncelen = td->noncelen_pr;
    t.entropycnt = 0;
    t.noncecnt = 0;
    if (!TEST_true(RAND_DRBG_instantiate(drbg, td->pers_pr, td->perslen_pr)))
        failures++;

    
    t.entropy = td->entropypr_pr;
    t.entropylen = td->entropyprlen_pr;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->katlen_pr, 1, td->adin_pr, td->adinlen_pr))
            || !TEST_mem_eq(td->kat_pr, td->katlen_pr, buff, td->katlen_pr))
        failures++;

    
    t.entropy = td->entropyg_pr;
    t.entropylen = td->entropyglen_pr;

    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->kat2len_pr, 1, td->ading_pr, td->adinglen_pr))
                || !TEST_mem_eq(td->kat2_pr, td->kat2len_pr, buff, td->kat2len_pr))
        failures++;

err:
    uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    return failures == 0;
}


static int init(RAND_DRBG *drbg, DRBG_SELFTEST_DATA *td, TEST_CTX *t)
{
    if (!TEST_true(RAND_DRBG_set(drbg, td->nid, td->flags))
            || !TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL, kat_nonce, NULL)))
        return 0;
    RAND_DRBG_set_ex_data(drbg, app_data_index, t);
    t->entropy = td->entropy;
    t->entropylen = td->entropylen;
    t->nonce = td->nonce;
    t->noncelen = td->noncelen;
    t->entropycnt = 0;
    t->noncecnt = 0;
    return 1;
}


static int instantiate(RAND_DRBG *drbg, DRBG_SELFTEST_DATA *td, TEST_CTX *t)
{
    if (!TEST_true(init(drbg, td, t))
            || !TEST_true(RAND_DRBG_instantiate(drbg, td->pers, td->perslen)))
        return 0;
    return 1;
}


static int error_check(DRBG_SELFTEST_DATA *td)
{
    static char zero[sizeof(RAND_DRBG)];
    RAND_DRBG *drbg = NULL;
    TEST_CTX t;
    unsigned char buff[1024];
    unsigned int reseed_counter_tmp;
    int ret = 0;

    if (!TEST_ptr(drbg = RAND_DRBG_new(td->nid, td->flags, NULL))
        || !TEST_true(disable_crngt(drbg)))
        goto err;

    

    
    if (!init(drbg, td, &t)
            || RAND_DRBG_instantiate(drbg, td->pers, drbg->max_perslen + 1) > 0)
        goto err;

    

    
    t.entropylen = 0;
    if (TEST_int_le(RAND_DRBG_instantiate(drbg, td->pers, td->perslen), 0))
        goto err;

    
    if (!TEST_false(RAND_DRBG_generate(drbg, buff, td->exlen, 0, td->adin, td->adinlen))
            || !uninstantiate(drbg))
        goto err;

    
    t.entropylen = drbg->min_entropylen - 1;
    if (!init(drbg, td, &t)
            || RAND_DRBG_instantiate(drbg, td->pers, td->perslen) > 0 || !uninstantiate(drbg))
        goto err;

    
    t.entropylen = drbg->max_entropylen + 1;
    if (!init(drbg, td, &t)
            || RAND_DRBG_instantiate(drbg, td->pers, td->perslen) > 0 || !uninstantiate(drbg))
        goto err;

    

    
    if (drbg->min_noncelen) {
        t.noncelen = drbg->min_noncelen - 1;
        if (!init(drbg, td, &t)
                || RAND_DRBG_instantiate(drbg, td->pers, td->perslen) > 0 || !uninstantiate(drbg))
            goto err;
    }

    
    if (drbg->max_noncelen) {
        t.noncelen = drbg->max_noncelen + 1;
        if (!init(drbg, td, &t)
                || RAND_DRBG_instantiate(drbg, td->pers, td->perslen) > 0 || !uninstantiate(drbg))
            goto err;
    }

    
    if (!instantiate(drbg, td, &t)
            || !TEST_true(RAND_DRBG_generate(drbg, buff, td->exlen, 0, td->adin, td->adinlen)))
        goto err;

    
    if (!TEST_false(RAND_DRBG_generate(drbg, buff, drbg->max_request + 1, 0, td->adin, td->adinlen)))
        goto err;

    
    if (!TEST_false(RAND_DRBG_generate(drbg, buff, td->exlen, 0, td->adin, drbg->max_adinlen + 1)))
        goto err;

    
    t.entropylen = 0;
    if (TEST_false(RAND_DRBG_generate(drbg, buff, td->exlen, 1, td->adin, td->adinlen))
            || !uninstantiate(drbg))
        goto err;

    
    if (!instantiate(drbg, td, &t))
        goto err;
    reseed_counter_tmp = drbg->reseed_gen_counter;
    drbg->reseed_gen_counter = drbg->reseed_interval;

    
    t.entropycnt = 0;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->exlen, 0, td->adin, td->adinlen))
            || !TEST_int_eq(t.entropycnt, 1)
            || !TEST_int_eq(drbg->reseed_gen_counter, reseed_counter_tmp + 1)
            || !uninstantiate(drbg))
        goto err;

    
    t.entropylen = 0;
    if (!TEST_false(RAND_DRBG_generate(drbg, buff, td->exlen, 1, td->adin, td->adinlen))
            || !uninstantiate(drbg))
        goto err;

    
    if (!instantiate(drbg, td, &t))
        goto err;
    reseed_counter_tmp = drbg->reseed_gen_counter;
    drbg->reseed_gen_counter = drbg->reseed_interval;

    
    t.entropycnt = 0;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->exlen, 0, td->adin, td->adinlen))
            || !TEST_int_eq(t.entropycnt, 1)
            || !TEST_int_eq(drbg->reseed_gen_counter, reseed_counter_tmp + 1)
            || !uninstantiate(drbg))
        goto err;

    

    
    if (!instantiate(drbg, td, &t)
            || RAND_DRBG_reseed(drbg, td->adin, drbg->max_adinlen + 1, 0) > 0)
        goto err;

    
    t.entropylen = 0;
    if (!TEST_int_le(RAND_DRBG_reseed(drbg, td->adin, td->adinlen, 0), 0)
            || !uninstantiate(drbg))
        goto err;

    
    if (!instantiate(drbg, td, &t))
        goto err;
    t.entropylen = drbg->max_entropylen + 1;
    if (!TEST_int_le(RAND_DRBG_reseed(drbg, td->adin, td->adinlen, 0), 0)
            || !uninstantiate(drbg))
        goto err;

    
    if (!instantiate(drbg, td, &t))
        goto err;
    t.entropylen = drbg->min_entropylen - 1;
    if (!TEST_int_le(RAND_DRBG_reseed(drbg, td->adin, td->adinlen, 0), 0)
            || !uninstantiate(drbg))
        goto err;

    
    if (!TEST_mem_eq(zero, sizeof(drbg->data), &drbg->data, sizeof(drbg->data)))
        goto err;

    ret = 1;

err:
    uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    return ret;
}

static int test_kats(int i)
{
    DRBG_SELFTEST_DATA *td = &drbg_test[i];
    int rv = 0;

    if (!single_kat(td))
        goto err;
    rv = 1;

err:
    return rv;
}

static int test_error_checks(int i)
{
    DRBG_SELFTEST_DATA *td = &drbg_test[i];
    int rv = 0;

    if (error_check(td))
        goto err;
    rv = 1;

err:
    return rv;
}


typedef struct hook_ctx_st {
    RAND_DRBG *drbg;
    
    RAND_DRBG_get_entropy_fn get_entropy;
    
    int fail;
    
    int reseed_count;
} HOOK_CTX;

static HOOK_CTX master_ctx, public_ctx, private_ctx;

static HOOK_CTX *get_hook_ctx(RAND_DRBG *drbg)
{
    return (HOOK_CTX *)RAND_DRBG_get_ex_data(drbg, app_data_index);
}


static size_t get_entropy_hook(RAND_DRBG *drbg, unsigned char **pout, int entropy, size_t min_len, size_t max_len, int prediction_resistance)

{
    size_t ret;
    HOOK_CTX *ctx = get_hook_ctx(drbg);

    if (ctx->fail != 0)
        return 0;

    ret = ctx->get_entropy(drbg, pout, entropy, min_len, max_len, prediction_resistance);

    if (ret != 0)
        ctx->reseed_count++;
    return ret;
}


static void hook_drbg(RAND_DRBG *drbg, HOOK_CTX *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->drbg = drbg;
    ctx->get_entropy = drbg->get_entropy;
    drbg->get_entropy = get_entropy_hook;
    RAND_DRBG_set_ex_data(drbg, app_data_index, ctx);
}


static void unhook_drbg(RAND_DRBG *drbg)
{
    HOOK_CTX *ctx = get_hook_ctx(drbg);

    drbg->get_entropy = ctx->get_entropy;
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DRBG, drbg, &drbg->ex_data);
}


static void reset_hook_ctx(HOOK_CTX *ctx)
{
    ctx->fail = 0;
    ctx->reseed_count = 0;
}


static void reset_drbg_hook_ctx(void)
{
    reset_hook_ctx(&master_ctx);
    reset_hook_ctx(&public_ctx);
    reset_hook_ctx(&private_ctx);
}


static int test_drbg_reseed(int expect_success, RAND_DRBG *master, RAND_DRBG *public, RAND_DRBG *private, int expect_master_reseed, int expect_public_reseed, int expect_private_reseed, time_t reseed_time )







{
    unsigned char buf[32];
    time_t before_reseed, after_reseed;
    int expected_state = (expect_success ? DRBG_READY : DRBG_ERROR);

    

    
    if (!TEST_int_ne(master->reseed_prop_counter, 0)
        || !TEST_int_ne(public->reseed_prop_counter, 0)
        || !TEST_int_ne(private->reseed_prop_counter, 0))
        return 0;

    
    if (!TEST_int_le(public->reseed_prop_counter, master->reseed_prop_counter)
        || !TEST_int_le(private->reseed_prop_counter, master->reseed_prop_counter))
        return 0;

    

    if (reseed_time == 0)
        reseed_time = time(NULL);

    
    before_reseed = expect_master_reseed == 1 ? reseed_time : 0;
    if (!TEST_int_eq(RAND_bytes(buf, sizeof(buf)), expect_success)
        || !TEST_int_eq(RAND_priv_bytes(buf, sizeof(buf)), expect_success))
        return 0;
    after_reseed = time(NULL);


    

    
    if (!TEST_int_eq(master->state, expected_state)
        || !TEST_int_eq(public->state, expected_state)
        || !TEST_int_eq(private->state, expected_state))
        return 0;

    if (expect_master_reseed >= 0) {
        
        if (!TEST_int_eq(master_ctx.reseed_count, expect_master_reseed))
            return 0;
    }

    if (expect_public_reseed >= 0) {
        
        if (!TEST_int_eq(public_ctx.reseed_count, expect_public_reseed))
            return 0;
    }

    if (expect_private_reseed >= 0) {
        
        if (!TEST_int_eq(private_ctx.reseed_count, expect_private_reseed))
            return 0;
    }

    if (expect_success == 1) {
        
        if (!TEST_int_eq(public->reseed_prop_counter, master->reseed_prop_counter)
            || !TEST_int_eq(private->reseed_prop_counter, master->reseed_prop_counter))
            return 0;

        
        if (!TEST_time_t_le(before_reseed, master->reseed_time)
            || !TEST_time_t_le(master->reseed_time, after_reseed))
            return 0;

        
        if (!TEST_time_t_ge(public->reseed_time, master->reseed_time)
            || !TEST_time_t_ge(private->reseed_time, master->reseed_time))
            return 0;
    } else {
        ERR_clear_error();
    }

    return 1;
}


static int test_rand_drbg_reseed(void)
{
    RAND_DRBG *master, *public, *private;
    unsigned char rand_add_buf[256];
    int rv=0;
    time_t before_reseed;

    
    if (!TEST_ptr_eq(RAND_get_rand_method(), RAND_OpenSSL()))
        return 0;

    
    if (!TEST_ptr(master = RAND_DRBG_get0_master())
        || !TEST_ptr(public = RAND_DRBG_get0_public())
        || !TEST_ptr(private = RAND_DRBG_get0_private()))
        return 0;

    
    if (!TEST_ptr_ne(public, private)
        || !TEST_ptr_ne(public, master)
        || !TEST_ptr_ne(private, master)
        || !TEST_ptr_eq(public->parent, master)
        || !TEST_ptr_eq(private->parent, master))
        return 0;

    
    if (!TEST_true(disable_crngt(master)))
        return 0;

    
    RAND_DRBG_uninstantiate(private);
    RAND_DRBG_uninstantiate(public);
    RAND_DRBG_uninstantiate(master);


    
    hook_drbg(master,  &master_ctx);
    hook_drbg(public,  &public_ctx);
    hook_drbg(private, &private_ctx);


    
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 1, 1, 1, 0)))
        goto error;
    reset_drbg_hook_ctx();


    
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 0, 0, 0, 0)))
        goto error;
    reset_drbg_hook_ctx();

    
    master->reseed_prop_counter++;
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 0, 1, 1, 0)))
        goto error;
    reset_drbg_hook_ctx();

    
    master->reseed_prop_counter++;
    private->reseed_prop_counter++;
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 0, 1, 0, 0)))
        goto error;
    reset_drbg_hook_ctx();

    
    master->reseed_prop_counter++;
    public->reseed_prop_counter++;
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 0, 0, 1, 0)))
        goto error;
    reset_drbg_hook_ctx();


    
    memset(rand_add_buf, 'r', sizeof(rand_add_buf));


    
    before_reseed = time(NULL);
    RAND_add(rand_add_buf, sizeof(rand_add_buf), sizeof(rand_add_buf));
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 1, 1, 1, before_reseed)))
        goto error;
    reset_drbg_hook_ctx();


    
    master_ctx.fail = 1;
    master->reseed_prop_counter++;
    RAND_add(rand_add_buf, sizeof(rand_add_buf), sizeof(rand_add_buf));
    if (!TEST_true(test_drbg_reseed(0, master, public, private, 0, 0, 0, 0)))
        goto error;
    reset_drbg_hook_ctx();

    
    before_reseed = time(NULL);
    RAND_add(rand_add_buf, sizeof(rand_add_buf), sizeof(rand_add_buf));
    if (!TEST_true(test_drbg_reseed(1, master, public, private, 0, 0, 0, before_reseed)))
        goto error;
    reset_drbg_hook_ctx();


    rv = 1;

error:
    
    unhook_drbg(master);
    unhook_drbg(public);
    unhook_drbg(private);

    return rv;
}


static int multi_thread_rand_bytes_succeeded = 1;
static int multi_thread_rand_priv_bytes_succeeded = 1;

static void run_multi_thread_test(void)
{
    unsigned char buf[256];
    time_t start = time(NULL);
    RAND_DRBG *public = NULL, *private = NULL;

    if (!TEST_ptr(public = RAND_DRBG_get0_public())
            || !TEST_ptr(private = RAND_DRBG_get0_private())) {
        multi_thread_rand_bytes_succeeded = 0;
        return;
    }
    RAND_DRBG_set_reseed_time_interval(private, 1);
    RAND_DRBG_set_reseed_time_interval(public, 1);

    do {
        if (RAND_bytes(buf, sizeof(buf)) <= 0)
            multi_thread_rand_bytes_succeeded = 0;
        if (RAND_priv_bytes(buf, sizeof(buf)) <= 0)
            multi_thread_rand_priv_bytes_succeeded = 0;
    }
    while(time(NULL) - start < 5);
}



typedef HANDLE thread_t;

static DWORD WINAPI thread_run(LPVOID arg)
{
    run_multi_thread_test();
    
    OPENSSL_thread_stop();
    return 0;
}

static int run_thread(thread_t *t)
{
    *t = CreateThread(NULL, 0, thread_run, NULL, 0, NULL);
    return *t != NULL;
}

static int wait_for_thread(thread_t thread)
{
    return WaitForSingleObject(thread, INFINITE) == 0;
}



typedef pthread_t thread_t;

static void *thread_run(void *arg)
{
    run_multi_thread_test();
    
    OPENSSL_thread_stop();
    return NULL;
}

static int run_thread(thread_t *t)
{
    return pthread_create(t, NULL, thread_run, NULL) == 0;
}

static int wait_for_thread(thread_t thread)
{
    return pthread_join(thread, NULL) == 0;
}






static int test_multi_thread(void)
{
    thread_t t[THREADS];
    int i;

    for (i = 0; i < THREADS; i++)
        run_thread(&t[i]);
    run_multi_thread_test();
    for (i = 0; i < THREADS; i++)
        wait_for_thread(t[i]);

    if (!TEST_true(multi_thread_rand_bytes_succeeded))
        return 0;
    if (!TEST_true(multi_thread_rand_priv_bytes_succeeded))
        return 0;

    return 1;
}



static int test_rand_seed(void)
{
    RAND_DRBG *master = NULL;
    unsigned char rand_buf[256];
    size_t rand_buflen;
    size_t required_seed_buflen = 0;

    if (!TEST_ptr(master = RAND_DRBG_get0_master())
        || !TEST_true(disable_crngt(master)))
        return 0;


    required_seed_buflen = rand_drbg_seedlen(master);


    memset(rand_buf, 0xCD, sizeof(rand_buf));

    for ( rand_buflen = 256 ; rand_buflen > 0 ; --rand_buflen ) {
        RAND_DRBG_uninstantiate(master);
        RAND_seed(rand_buf, rand_buflen);

        if (!TEST_int_eq(RAND_status(), (rand_buflen >= required_seed_buflen)))
            return 0;
    }

    return 1;
}


static int test_rand_add(void)
{
    unsigned char rand_buf[256];
    size_t rand_buflen;

    memset(rand_buf, 0xCD, sizeof(rand_buf));

    
    RAND_seed(rand_buf, sizeof(rand_buf));
    if (!TEST_true(RAND_status()))
        return 0;

    for ( rand_buflen = 256 ; rand_buflen > 0 ; --rand_buflen ) {
        RAND_add(rand_buf, rand_buflen, 0.0);
        if (!TEST_true(RAND_status()))
            return 0;
    }

    return 1;
}

static int test_rand_drbg_prediction_resistance(void)
{
    RAND_DRBG *m = NULL, *i = NULL, *s = NULL;
    unsigned char buf1[51], buf2[sizeof(buf1)];
    int ret = 0, mreseed, ireseed, sreseed;

    
    if (!TEST_ptr(m = RAND_DRBG_new(0, 0, NULL))
        || !TEST_true(disable_crngt(m))
        || !TEST_true(RAND_DRBG_instantiate(m, NULL, 0))
        || !TEST_ptr(i = RAND_DRBG_new(0, 0, m))
        || !TEST_true(RAND_DRBG_instantiate(i, NULL, 0))
        || !TEST_ptr(s = RAND_DRBG_new(0, 0, i))
        || !TEST_true(RAND_DRBG_instantiate(s, NULL, 0)))
        goto err;

    
    mreseed = ++m->reseed_prop_counter;
    ireseed = ++i->reseed_prop_counter;
    sreseed = s->reseed_prop_counter;
    if (!TEST_true(RAND_DRBG_reseed(s, NULL, 0, 0))
        || !TEST_int_eq(m->reseed_prop_counter, mreseed)
        || !TEST_int_eq(i->reseed_prop_counter, ireseed)
        || !TEST_int_gt(s->reseed_prop_counter, sreseed))
        goto err;

    
    sreseed = s->reseed_prop_counter;
    if (!TEST_true(RAND_DRBG_reseed(s, NULL, 0, 1))
        || !TEST_int_gt(m->reseed_prop_counter, mreseed)
        || !TEST_int_gt(i->reseed_prop_counter, ireseed)
        || !TEST_int_gt(s->reseed_prop_counter, sreseed))
        goto err;

    
    mreseed = ++m->reseed_prop_counter;
    ireseed = ++i->reseed_prop_counter;
    sreseed = s->reseed_prop_counter;
    if (!TEST_true(RAND_DRBG_generate(s, buf1, sizeof(buf1), 0, NULL, 0))
        || !TEST_int_eq(m->reseed_prop_counter, mreseed)
        || !TEST_int_eq(i->reseed_prop_counter, ireseed)
        || !TEST_int_gt(s->reseed_prop_counter, sreseed))
        goto err;

    
    sreseed = s->reseed_prop_counter;
    if (!TEST_true(RAND_DRBG_generate(s, buf2, sizeof(buf2), 1, NULL, 0))
        || !TEST_int_gt(m->reseed_prop_counter, mreseed)
        || !TEST_int_gt(i->reseed_prop_counter, ireseed)
        || !TEST_int_gt(s->reseed_prop_counter, sreseed)
        || !TEST_mem_ne(buf1, sizeof(buf1), buf2, sizeof(buf2)))
        goto err;

    
    mreseed = ++m->reseed_prop_counter;
    ireseed = ++i->reseed_prop_counter;
    sreseed = s->reseed_prop_counter;
    if (!TEST_true(RAND_DRBG_reseed(s, NULL, 0, 0))
        || !TEST_int_eq(m->reseed_prop_counter, mreseed)
        || !TEST_int_eq(i->reseed_prop_counter, ireseed)
        || !TEST_int_gt(s->reseed_prop_counter, sreseed))
        goto err;

    ret = 1;
err:
    RAND_DRBG_free(s);
    RAND_DRBG_free(i);
    RAND_DRBG_free(m);
    return ret;
}

static int test_multi_set(void)
{
    int rv = 0;
    RAND_DRBG *drbg = NULL;

    
    if (!TEST_ptr(drbg = RAND_DRBG_new(0, 0, NULL))
        || !TEST_true(disable_crngt(drbg)))
        goto err;
    
    if (!TEST_true(RAND_DRBG_set(drbg, NID_sha1, RAND_DRBG_FLAG_HMAC)))
        goto err;
    
    if (!TEST_true(RAND_DRBG_set(drbg, NID_sha1, RAND_DRBG_FLAG_HMAC)))
        goto err;
    
    if (!TEST_true(RAND_DRBG_set(drbg, NID_sha256, 0)))
        goto err;
    
    if (!TEST_true(RAND_DRBG_set(drbg, NID_sha256, 0)))
        goto err;
    
    if (!TEST_true(RAND_DRBG_set(drbg, NID_aes_192_ctr, 0)))
        goto err;
    
    if (!TEST_true(RAND_DRBG_set(drbg, NID_aes_192_ctr, 0)))
        goto err;
    if (!TEST_int_gt(RAND_DRBG_instantiate(drbg, NULL, 0), 0))
        goto err;

    rv = 1;
err:
    uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    return rv;
}

static int test_set_defaults(void)
{
    RAND_DRBG *master = NULL, *public = NULL, *private = NULL;

           
    return TEST_ptr(master = RAND_DRBG_get0_master())
           && TEST_ptr(public = RAND_DRBG_get0_public())
           && TEST_ptr(private = RAND_DRBG_get0_private())
           && TEST_int_eq(master->type, RAND_DRBG_TYPE)
           && TEST_int_eq(master->flags, RAND_DRBG_FLAGS | RAND_DRBG_FLAG_MASTER)
           && TEST_int_eq(public->type, RAND_DRBG_TYPE)
           && TEST_int_eq(public->flags, RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC)
           && TEST_int_eq(private->type, RAND_DRBG_TYPE)
           && TEST_int_eq(private->flags, RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PRIVATE)

           
           && TEST_true(RAND_DRBG_set_defaults(NID_sha256, RAND_DRBG_FLAG_MASTER))
           && TEST_true(RAND_DRBG_uninstantiate(master))
           && TEST_int_eq(master->type, NID_sha256)
           && TEST_int_eq(master->flags, RAND_DRBG_FLAG_MASTER)
           && TEST_int_eq(public->type, RAND_DRBG_TYPE)
           && TEST_int_eq(public->flags, RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC)
           && TEST_int_eq(private->type, RAND_DRBG_TYPE)
           && TEST_int_eq(private->flags, RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PRIVATE)
           
           && TEST_true(RAND_DRBG_set_defaults(NID_sha256, RAND_DRBG_FLAG_PRIVATE|RAND_DRBG_FLAG_HMAC))
           && TEST_true(RAND_DRBG_uninstantiate(private))
           && TEST_int_eq(master->type, NID_sha256)
           && TEST_int_eq(master->flags, RAND_DRBG_FLAG_MASTER)
           && TEST_int_eq(public->type, RAND_DRBG_TYPE)
           && TEST_int_eq(public->flags, RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC)
           && TEST_int_eq(private->type, NID_sha256)
           && TEST_int_eq(private->flags, RAND_DRBG_FLAG_PRIVATE | RAND_DRBG_FLAG_HMAC)
           
           && TEST_true(RAND_DRBG_set_defaults(NID_sha1, RAND_DRBG_FLAG_PUBLIC | RAND_DRBG_FLAG_HMAC))

           && TEST_true(RAND_DRBG_uninstantiate(public))
           && TEST_int_eq(master->type, NID_sha256)
           && TEST_int_eq(master->flags, RAND_DRBG_FLAG_MASTER)
           && TEST_int_eq(public->type, NID_sha1)
           && TEST_int_eq(public->flags, RAND_DRBG_FLAG_PUBLIC | RAND_DRBG_FLAG_HMAC)
           && TEST_int_eq(private->type, NID_sha256)
           && TEST_int_eq(private->flags, RAND_DRBG_FLAG_PRIVATE | RAND_DRBG_FLAG_HMAC)
           
           && TEST_true(RAND_DRBG_set_defaults(NID_sha256, 0))
           && TEST_true(RAND_DRBG_uninstantiate(public))
           && TEST_int_eq(public->type, NID_sha256)
           && TEST_int_eq(public->flags, RAND_DRBG_FLAG_PUBLIC)

          

          
           && TEST_true(RAND_DRBG_set_defaults(NID_aes_256_ctr, RAND_DRBG_FLAG_CTR_NO_DF))
           && TEST_true(RAND_DRBG_uninstantiate(master))
           && TEST_int_eq(master->type, NID_aes_256_ctr)
           && TEST_int_eq(master->flags, RAND_DRBG_FLAG_MASTER|RAND_DRBG_FLAG_CTR_NO_DF)

           
           && TEST_true(RAND_DRBG_set_defaults(RAND_DRBG_TYPE, RAND_DRBG_FLAGS | RAND_DRBG_FLAG_MASTER | RAND_DRBG_FLAG_PUBLIC | RAND_DRBG_FLAG_PRIVATE))



           && TEST_true(RAND_DRBG_uninstantiate(master))
           && TEST_true(RAND_DRBG_uninstantiate(public))
           && TEST_true(RAND_DRBG_uninstantiate(private));
}


static const struct s_drgb_types {
    int nid;
    int flags;
} drgb_types[] = {
    { NID_aes_128_ctr,  0                   }, { NID_aes_192_ctr,  0                   }, { NID_aes_256_ctr,  0                   }, { NID_sha1,         0                   }, { NID_sha224,       0                   }, { NID_sha256,       0                   }, { NID_sha384,       0                   }, { NID_sha512,       0                   }, { NID_sha512_224,   0                   }, { NID_sha512_256,   0                   }, { NID_sha3_224,     0                   }, { NID_sha3_256,     0                   }, { NID_sha3_384,     0                   }, { NID_sha3_512,     0                   }, { NID_sha1,         RAND_DRBG_FLAG_HMAC }, { NID_sha224,       RAND_DRBG_FLAG_HMAC }, { NID_sha256,       RAND_DRBG_FLAG_HMAC }, { NID_sha384,       RAND_DRBG_FLAG_HMAC }, { NID_sha512,       RAND_DRBG_FLAG_HMAC }, { NID_sha512_224,   RAND_DRBG_FLAG_HMAC }, { NID_sha512_256,   RAND_DRBG_FLAG_HMAC }, { NID_sha3_224,     RAND_DRBG_FLAG_HMAC }, { NID_sha3_256,     RAND_DRBG_FLAG_HMAC }, { NID_sha3_384,     RAND_DRBG_FLAG_HMAC }, { NID_sha3_512,     RAND_DRBG_FLAG_HMAC }, };


























static const size_t crngt_num_cases = 6;

static size_t crngt_case, crngt_idx;

static int crngt_entropy_cb(OPENSSL_CTX *ctx, RAND_POOL *pool, unsigned char *buf, unsigned char *md, unsigned int *md_size)

{
    size_t i, z;

    if (!TEST_int_lt(crngt_idx, crngt_num_cases))
        return 0;
    
    z = crngt_idx++;
    if (z > 0 && crngt_case == z)
        z--;
    for (i = 0; i < CRNGT_BUFSIZ; i++)
        buf[i] = (unsigned char)(i + 'A' + z);
    return EVP_Digest(buf, CRNGT_BUFSIZ, md, md_size, EVP_sha256(), NULL);
}

static int test_crngt(int n)
{
    const struct s_drgb_types *dt = drgb_types + n / crngt_num_cases;
    RAND_DRBG *drbg = NULL;
    unsigned char buff[100];
    size_t ent;
    int res = 0;
    int expect;
    OPENSSL_CTX *ctx = OPENSSL_CTX_new();

    if (!TEST_ptr(ctx))
        return 0;
    if (!TEST_ptr(drbg = RAND_DRBG_new_ex(ctx, dt->nid, dt->flags, NULL)))
        goto err;
    ent = (drbg->min_entropylen + CRNGT_BUFSIZ - 1) / CRNGT_BUFSIZ;
    crngt_case = n % crngt_num_cases;
    crngt_idx = 0;
    crngt_get_entropy = &crngt_entropy_cb;

    if (!TEST_true(RAND_DRBG_set_callbacks(drbg, &rand_crngt_get_entropy, &rand_crngt_cleanup_entropy, &rand_drbg_get_nonce, &rand_drbg_cleanup_nonce)))


        goto err;

    expect = crngt_case == 0 || crngt_case > ent;
    if (!TEST_int_eq(RAND_DRBG_instantiate(drbg, NULL, 0), expect))
        goto err;
    if (!expect)
        goto fin;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, sizeof(buff), 0, NULL, 0)))
        goto err;

    expect = crngt_case == 0 || crngt_case > 2 * ent;
    if (!TEST_int_eq(RAND_DRBG_reseed(drbg, NULL, 0, 0), expect))
        goto err;
    if (!expect)
        goto fin;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, sizeof(buff), 0, NULL, 0)))
        goto err;

fin:
    res = 1;
err:
    if (!res)
        TEST_note("DRBG %zd case %zd block %zd", n / crngt_num_cases, crngt_case, crngt_idx);
    uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    crngt_get_entropy = &rand_crngt_get_entropy_cb;
    OPENSSL_CTX_free(ctx);
    return res;
}

int setup_tests(void)
{
    app_data_index = RAND_DRBG_get_ex_new_index(0L, NULL, NULL, NULL, NULL);

    ADD_ALL_TESTS(test_kats, OSSL_NELEM(drbg_test));
    ADD_ALL_TESTS(test_error_checks, OSSL_NELEM(drbg_test));
    ADD_TEST(test_rand_drbg_reseed);
    ADD_TEST(test_rand_seed);
    ADD_TEST(test_rand_add);
    ADD_TEST(test_rand_drbg_prediction_resistance);
    ADD_TEST(test_multi_set);
    ADD_TEST(test_set_defaults);

    ADD_TEST(test_multi_thread);

    ADD_ALL_TESTS(test_crngt, crngt_num_cases * OSSL_NELEM(drgb_types));
    return 1;
}
