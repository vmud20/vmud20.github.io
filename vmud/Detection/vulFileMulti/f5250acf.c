




















static void openvpn_encrypt_aead(struct buffer *buf, struct buffer work, struct crypto_options *opt)

{

    struct gc_arena gc;
    int outlen = 0;
    const struct key_ctx *ctx = &opt->key_ctx_bi.encrypt;
    uint8_t *mac_out = NULL;
    const cipher_kt_t *cipher_kt = cipher_ctx_get_cipher_kt(ctx->cipher);
    const int mac_len = cipher_kt_tag_size(cipher_kt);

    
    ASSERT(ctx->cipher);
    ASSERT(cipher_kt_mode_aead(cipher_kt));
    ASSERT(packet_id_initialized(&opt->packet_id));

    gc_init(&gc);

    
    {
        struct buffer iv_buffer;
        uint8_t iv[OPENVPN_MAX_IV_LENGTH] = {0};
        const int iv_len = cipher_ctx_iv_length(ctx->cipher);

        ASSERT(iv_len >= OPENVPN_AEAD_MIN_IV_LEN && iv_len <= OPENVPN_MAX_IV_LENGTH);

        buf_set_write(&iv_buffer, iv, iv_len);

        
        ASSERT(packet_id_write(&opt->packet_id.send, &iv_buffer, false, false));

        
        ASSERT(buf_write(&iv_buffer, ctx->implicit_iv, ctx->implicit_iv_len));
        ASSERT(iv_buffer.len == iv_len);

        
        ASSERT(buf_write(&work, iv, iv_len - ctx->implicit_iv_len));
        dmsg(D_PACKET_CONTENT, "ENCRYPT IV: %s", format_hex(iv, iv_len, 0, &gc));

        
        ASSERT(cipher_ctx_reset(ctx->cipher, iv));
    }

    
    mac_out = buf_write_alloc(&work, mac_len);
    ASSERT(mac_out);

    dmsg(D_PACKET_CONTENT, "ENCRYPT FROM: %s", format_hex(BPTR(buf), BLEN(buf), 80, &gc));

    
    if (!buf_safe(&work, buf->len + cipher_ctx_block_size(ctx->cipher)))
    {
        msg(D_CRYPT_ERRORS, "ENCRYPT: buffer size error, bc=%d bo=%d bl=%d wc=%d wo=%d wl=%d", buf->capacity, buf->offset, buf->len, work.capacity, work.offset, work.len);


        goto err;
    }

    
    ASSERT(cipher_ctx_update_ad(ctx->cipher, BPTR(&work), BLEN(&work) - mac_len));
    dmsg(D_PACKET_CONTENT, "ENCRYPT AD: %s", format_hex(BPTR(&work), BLEN(&work) - mac_len, 0, &gc));

    
    ASSERT(cipher_ctx_update(ctx->cipher, BEND(&work), &outlen, BPTR(buf), BLEN(buf)));
    ASSERT(buf_inc_len(&work, outlen));

    
    ASSERT(cipher_ctx_final(ctx->cipher, BEND(&work), &outlen));
    ASSERT(buf_inc_len(&work, outlen));

    
    ASSERT(cipher_ctx_get_tag(ctx->cipher, mac_out, mac_len));

    *buf = work;

    dmsg(D_PACKET_CONTENT, "ENCRYPT TO: %s", format_hex(BPTR(buf), BLEN(buf), 80, &gc));

    gc_free(&gc);
    return;

err:
    crypto_clear_error();
    buf->len = 0;
    gc_free(&gc);
    return;

    ASSERT(0);

}

static void openvpn_encrypt_v1(struct buffer *buf, struct buffer work, struct crypto_options *opt)

{
    struct gc_arena gc;
    gc_init(&gc);

    if (buf->len > 0 && opt)
    {
        const struct key_ctx *ctx = &opt->key_ctx_bi.encrypt;
        uint8_t *mac_out = NULL;
        const uint8_t *hmac_start = NULL;

        
        if (ctx->cipher)
        {
            uint8_t iv_buf[OPENVPN_MAX_IV_LENGTH] = {0};
            const int iv_size = cipher_ctx_iv_length(ctx->cipher);
            const cipher_kt_t *cipher_kt = cipher_ctx_get_cipher_kt(ctx->cipher);
            int outlen;

            
            if (ctx->hmac)
            {
                mac_out = buf_write_alloc(&work, hmac_ctx_size(ctx->hmac));
                ASSERT(mac_out);
                hmac_start = BEND(&work);
            }

            if (cipher_kt_mode_cbc(cipher_kt))
            {
                
                prng_bytes(iv_buf, iv_size);

                
                if (packet_id_initialized(&opt->packet_id))
                {
                    ASSERT(packet_id_write(&opt->packet_id.send, buf, opt->flags & CO_PACKET_ID_LONG_FORM, true));

                }
            }
            else if (cipher_kt_mode_ofb_cfb(cipher_kt))
            {
                struct buffer b;

                
                ASSERT(packet_id_initialized(&opt->packet_id));

                buf_set_write(&b, iv_buf, iv_size);
                ASSERT(packet_id_write(&opt->packet_id.send, &b, true, false));
            }
            else  {
                ASSERT(0);
            }

            
            ASSERT(buf_write(&work, iv_buf, iv_size));
            dmsg(D_PACKET_CONTENT, "ENCRYPT IV: %s", format_hex(iv_buf, iv_size, 0, &gc));

            dmsg(D_PACKET_CONTENT, "ENCRYPT FROM: %s", format_hex(BPTR(buf), BLEN(buf), 80, &gc));

            
            ASSERT(cipher_ctx_reset(ctx->cipher, iv_buf));

            
            if (!buf_safe(&work, buf->len + cipher_ctx_block_size(ctx->cipher)))
            {
                msg(D_CRYPT_ERRORS, "ENCRYPT: buffer size error, bc=%d bo=%d bl=%d wc=%d wo=%d wl=%d cbs=%d", buf->capacity, buf->offset, buf->len, work.capacity, work.offset, work.len, cipher_ctx_block_size(ctx->cipher));






                goto err;
            }

            
            ASSERT(cipher_ctx_update(ctx->cipher, BEND(&work), &outlen, BPTR(buf), BLEN(buf)));
            ASSERT(buf_inc_len(&work, outlen));

            
            ASSERT(cipher_ctx_final(ctx->cipher, BEND(&work), &outlen));
            ASSERT(buf_inc_len(&work, outlen));

            
            ASSERT(cipher_kt_mode(cipher_kt) != OPENVPN_MODE_CBC || outlen == iv_size);
        }
        else                             {
            if (packet_id_initialized(&opt->packet_id))
            {
                ASSERT(packet_id_write(&opt->packet_id.send, buf, BOOL_CAST(opt->flags & CO_PACKET_ID_LONG_FORM), true));

            }
            if (ctx->hmac)
            {
                hmac_start = BPTR(buf);
                ASSERT(mac_out = buf_prepend(buf, hmac_ctx_size(ctx->hmac)));
            }
            if (BLEN(&work))
            {
                buf_write_prepend(buf, BPTR(&work), BLEN(&work));
            }
            work = *buf;
        }

        
        if (ctx->hmac)
        {
            hmac_ctx_reset(ctx->hmac);
            hmac_ctx_update(ctx->hmac, hmac_start, BEND(&work) - hmac_start);
            hmac_ctx_final(ctx->hmac, mac_out);
            dmsg(D_PACKET_CONTENT, "ENCRYPT HMAC: %s", format_hex(mac_out, hmac_ctx_size(ctx->hmac), 80, &gc));
        }

        *buf = work;

        dmsg(D_PACKET_CONTENT, "ENCRYPT TO: %s", format_hex(BPTR(&work), BLEN(&work), 80, &gc));
    }

    gc_free(&gc);
    return;

err:
    crypto_clear_error();
    buf->len = 0;
    gc_free(&gc);
    return;
}

void openvpn_encrypt(struct buffer *buf, struct buffer work, struct crypto_options *opt)

{
    if (buf->len > 0 && opt)
    {
        const cipher_kt_t *cipher_kt = cipher_ctx_get_cipher_kt(opt->key_ctx_bi.encrypt.cipher);

        if (cipher_kt_mode_aead(cipher_kt))
        {
            openvpn_encrypt_aead(buf, work, opt);
        }
        else {
            openvpn_encrypt_v1(buf, work, opt);
        }
    }
}

bool crypto_check_replay(struct crypto_options *opt, const struct packet_id_net *pin, const char *error_prefix, struct gc_arena *gc)


{
    bool ret = false;
    packet_id_reap_test(&opt->packet_id.rec);
    if (packet_id_test(&opt->packet_id.rec, pin))
    {
        packet_id_add(&opt->packet_id.rec, pin);
        if (opt->pid_persist && (opt->flags & CO_PACKET_ID_LONG_FORM))
        {
            packet_id_persist_save_obj(opt->pid_persist, &opt->packet_id);
        }
        ret = true;
    }
    else {
        if (!(opt->flags & CO_MUTE_REPLAY_WARNINGS))
        {
            msg(D_REPLAY_ERRORS, "%s: bad packet ID (may be a replay): %s -- " "see the man page entry for --no-replay and --replay-window for " "more info or silence this warning with --mute-replay-warnings", error_prefix, packet_id_net_print(pin, true, gc));


        }
    }
    return ret;
}


static bool openvpn_decrypt_aead(struct buffer *buf, struct buffer work, struct crypto_options *opt, const struct frame *frame, const uint8_t *ad_start)


{

    static const char error_prefix[] = "AEAD Decrypt error";
    struct packet_id_net pin = { 0 };
    const struct key_ctx *ctx = &opt->key_ctx_bi.decrypt;
    const cipher_kt_t *cipher_kt = cipher_ctx_get_cipher_kt(ctx->cipher);
    uint8_t *tag_ptr = NULL;
    int tag_size = 0;
    int outlen;
    struct gc_arena gc;

    gc_init(&gc);

    ASSERT(opt);
    ASSERT(frame);
    ASSERT(buf->len > 0);
    ASSERT(ctx->cipher);
    ASSERT(cipher_kt_mode_aead(cipher_kt));

    dmsg(D_PACKET_CONTENT, "DECRYPT FROM: %s", format_hex(BPTR(buf), BLEN(buf), 80, &gc));

    ASSERT(ad_start >= buf->data && ad_start <= BPTR(buf));

    ASSERT(buf_init(&work, FRAME_HEADROOM_ADJ(frame, FRAME_HEADROOM_MARKER_DECRYPT)));

    
    ASSERT(packet_id_initialized(&opt->packet_id));

    
    {
        uint8_t iv[OPENVPN_MAX_IV_LENGTH] = { 0 };
        const int iv_len = cipher_ctx_iv_length(ctx->cipher);
        const size_t packet_iv_len = iv_len - ctx->implicit_iv_len;

        ASSERT(ctx->implicit_iv_len <= iv_len);
        if (buf->len + ctx->implicit_iv_len < iv_len)
        {
            CRYPT_ERROR("missing IV info");
        }

        memcpy(iv, BPTR(buf), packet_iv_len);
        memcpy(iv + packet_iv_len, ctx->implicit_iv, ctx->implicit_iv_len);

        dmsg(D_PACKET_CONTENT, "DECRYPT IV: %s", format_hex(iv, iv_len, 0, &gc));

        
        if (!cipher_ctx_reset(ctx->cipher, iv))
        {
            CRYPT_ERROR("cipher init failed");
        }
    }

    
    if (!packet_id_read(&pin, buf, false))
    {
        CRYPT_ERROR("error reading packet-id");
    }

    
    tag_size = cipher_kt_tag_size(cipher_kt);
    if (buf->len < tag_size)
    {
        CRYPT_ERROR("missing tag");
    }
    tag_ptr = BPTR(buf);
    ASSERT(buf_advance(buf, tag_size));
    dmsg(D_PACKET_CONTENT, "DECRYPT MAC: %s", format_hex(tag_ptr, tag_size, 0, &gc));

    
    if (!EVP_CIPHER_CTX_ctrl(ctx->cipher, EVP_CTRL_GCM_SET_TAG, tag_size, tag_ptr))
    {
        CRYPT_ERROR("setting tag failed");
    }


    if (buf->len < 1)
    {
        CRYPT_ERROR("missing payload");
    }

    dmsg(D_PACKET_CONTENT, "DECRYPT FROM: %s", format_hex(BPTR(buf), BLEN(buf), 0, &gc));

    
    if (!buf_safe(&work, buf->len + cipher_ctx_block_size(ctx->cipher)))
    {
        CRYPT_ERROR("potential buffer overflow");
    }

    {
        
        const int ad_size = BPTR(buf) - ad_start - tag_size;
        ASSERT(cipher_ctx_update_ad(ctx->cipher, ad_start, ad_size));
        dmsg(D_PACKET_CONTENT, "DECRYPT AD: %s", format_hex(BPTR(buf) - ad_size - tag_size, ad_size, 0, &gc));
    }

    
    if (!cipher_ctx_update(ctx->cipher, BPTR(&work), &outlen, BPTR(buf), BLEN(buf)))
    {
        CRYPT_ERROR("cipher update failed");
    }
    ASSERT(buf_inc_len(&work, outlen));
    if (!cipher_ctx_final_check_tag(ctx->cipher, BPTR(&work) + outlen, &outlen, tag_ptr, tag_size))
    {
        CRYPT_ERROR("cipher final failed");
    }
    ASSERT(buf_inc_len(&work, outlen));

    dmsg(D_PACKET_CONTENT, "DECRYPT TO: %s", format_hex(BPTR(&work), BLEN(&work), 80, &gc));

    if (!crypto_check_replay(opt, &pin, error_prefix, &gc))
    {
        goto error_exit;
    }

    *buf = work;

    gc_free(&gc);
    return true;

error_exit:
    crypto_clear_error();
    buf->len = 0;
    gc_free(&gc);
    return false;

    ASSERT(0);
    return false;

}


static bool openvpn_decrypt_v1(struct buffer *buf, struct buffer work, struct crypto_options *opt, const struct frame *frame)

{
    static const char error_prefix[] = "Authenticate/Decrypt packet error";
    struct gc_arena gc;
    gc_init(&gc);

    if (buf->len > 0 && opt)
    {
        const struct key_ctx *ctx = &opt->key_ctx_bi.decrypt;
        struct packet_id_net pin;
        bool have_pin = false;

        dmsg(D_PACKET_CONTENT, "DECRYPT FROM: %s", format_hex(BPTR(buf), BLEN(buf), 80, &gc));

        
        if (ctx->hmac)
        {
            int hmac_len;
            uint8_t local_hmac[MAX_HMAC_KEY_LENGTH]; 

            hmac_ctx_reset(ctx->hmac);

            
            hmac_len = hmac_ctx_size(ctx->hmac);

            
            if (buf->len < hmac_len)
            {
                CRYPT_ERROR("missing authentication info");
            }

            hmac_ctx_update(ctx->hmac, BPTR(buf) + hmac_len, BLEN(buf) - hmac_len);
            hmac_ctx_final(ctx->hmac, local_hmac);

            
            if (memcmp_constant_time(local_hmac, BPTR(buf), hmac_len))
            {
                CRYPT_ERROR("packet HMAC authentication failed");
            }

            ASSERT(buf_advance(buf, hmac_len));
        }

        

        if (ctx->cipher)
        {
            const int iv_size = cipher_ctx_iv_length(ctx->cipher);
            const cipher_kt_t *cipher_kt = cipher_ctx_get_cipher_kt(ctx->cipher);
            uint8_t iv_buf[OPENVPN_MAX_IV_LENGTH] = { 0 };
            int outlen;

            
            ASSERT(buf_init(&work, FRAME_HEADROOM_ADJ(frame, FRAME_HEADROOM_MARKER_DECRYPT)));

            
            if (buf->len < iv_size)
            {
                CRYPT_ERROR("missing IV info");
            }
            memcpy(iv_buf, BPTR(buf), iv_size);
            ASSERT(buf_advance(buf, iv_size));
            dmsg(D_PACKET_CONTENT, "DECRYPT IV: %s", format_hex(iv_buf, iv_size, 0, &gc));

            if (buf->len < 1)
            {
                CRYPT_ERROR("missing payload");
            }

            
            if (!cipher_ctx_reset(ctx->cipher, iv_buf))
            {
                CRYPT_ERROR("cipher init failed");
            }

            
            if (!buf_safe(&work, buf->len + cipher_ctx_block_size(ctx->cipher)))
            {
                CRYPT_ERROR("potential buffer overflow");
            }

            
            if (!cipher_ctx_update(ctx->cipher, BPTR(&work), &outlen, BPTR(buf), BLEN(buf)))
            {
                CRYPT_ERROR("cipher update failed");
            }
            ASSERT(buf_inc_len(&work, outlen));

            
            if (!cipher_ctx_final(ctx->cipher, BPTR(&work) + outlen, &outlen))
            {
                CRYPT_ERROR("cipher final failed");
            }
            ASSERT(buf_inc_len(&work, outlen));

            dmsg(D_PACKET_CONTENT, "DECRYPT TO: %s", format_hex(BPTR(&work), BLEN(&work), 80, &gc));

            
            {
                if (cipher_kt_mode_cbc(cipher_kt))
                {
                    if (packet_id_initialized(&opt->packet_id))
                    {
                        if (!packet_id_read(&pin, &work, BOOL_CAST(opt->flags & CO_PACKET_ID_LONG_FORM)))
                        {
                            CRYPT_ERROR("error reading CBC packet-id");
                        }
                        have_pin = true;
                    }
                }
                else if (cipher_kt_mode_ofb_cfb(cipher_kt))
                {
                    struct buffer b;

                    
                    ASSERT(packet_id_initialized(&opt->packet_id));

                    buf_set_read(&b, iv_buf, iv_size);
                    if (!packet_id_read(&pin, &b, true))
                    {
                        CRYPT_ERROR("error reading CFB/OFB packet-id");
                    }
                    have_pin = true;
                }
                else  {
                    ASSERT(0);
                }
            }
        }
        else {
            work = *buf;
            if (packet_id_initialized(&opt->packet_id))
            {
                if (!packet_id_read(&pin, &work, BOOL_CAST(opt->flags & CO_PACKET_ID_LONG_FORM)))
                {
                    CRYPT_ERROR("error reading packet-id");
                }
                have_pin = !BOOL_CAST(opt->flags & CO_IGNORE_PACKET_ID);
            }
        }

        if (have_pin && !crypto_check_replay(opt, &pin, error_prefix, &gc))
        {
            goto error_exit;
        }
        *buf = work;
    }

    gc_free(&gc);
    return true;

error_exit:
    crypto_clear_error();
    buf->len = 0;
    gc_free(&gc);
    return false;
}


bool openvpn_decrypt(struct buffer *buf, struct buffer work, struct crypto_options *opt, const struct frame *frame, const uint8_t *ad_start)


{
    bool ret = false;

    if (buf->len > 0 && opt)
    {
        const struct key_ctx *ctx = &opt->key_ctx_bi.decrypt;
        if (cipher_kt_mode_aead(cipher_ctx_get_cipher_kt(ctx->cipher)))
        {
            ret = openvpn_decrypt_aead(buf, work, opt, frame, ad_start);
        }
        else {
            ret = openvpn_decrypt_v1(buf, work, opt, frame);
        }
    }
    else {
        ret = true;
    }
    return ret;
}

void crypto_adjust_frame_parameters(struct frame *frame, const struct key_type *kt, bool packet_id, bool packet_id_long_form)



{
    size_t crypto_overhead = 0;

    if (packet_id)
    {
        crypto_overhead += packet_id_size(packet_id_long_form);
    }

    if (kt->cipher)
    {
        crypto_overhead += cipher_kt_iv_size(kt->cipher);

        if (cipher_kt_mode_aead(kt->cipher))
        {
            crypto_overhead += cipher_kt_tag_size(kt->cipher);
        }

        
        crypto_overhead += cipher_kt_block_size(kt->cipher);
    }

    crypto_overhead += kt->hmac_length;

    frame_add_to_extra_frame(frame, crypto_overhead);

    msg(D_MTU_DEBUG, "%s: Adjusting frame parameters for crypto by %u bytes", __func__, (unsigned int) crypto_overhead);
}

size_t crypto_max_overhead(void)
{
    return packet_id_size(true) + OPENVPN_MAX_IV_LENGTH +OPENVPN_MAX_CIPHER_BLOCK_SIZE +max_int(OPENVPN_MAX_HMAC_SIZE, OPENVPN_AEAD_TAG_LENGTH);

}


void init_key_type(struct key_type *kt, const char *ciphername, const char *authname, int keysize, bool tls_mode, bool warn)

{
    bool aead_cipher = false;

    ASSERT(ciphername);
    ASSERT(authname);

    CLEAR(*kt);
    if (strcmp(ciphername, "none") != 0)
    {
        kt->cipher = cipher_kt_get(translate_cipher_name_from_openvpn(ciphername));
        if (!kt->cipher)
        {
            msg(M_FATAL, "Cipher %s not supported", ciphername);
        }

        kt->cipher_length = cipher_kt_key_size(kt->cipher);
        if (keysize > 0 && keysize <= MAX_CIPHER_KEY_LENGTH)
        {
            kt->cipher_length = keysize;
        }

        
        aead_cipher = cipher_kt_mode_aead(kt->cipher);
        if (!(cipher_kt_mode_cbc(kt->cipher)
              || (tls_mode && aead_cipher)

              || (tls_mode && cipher_kt_mode_ofb_cfb(kt->cipher))

              ))
        {
            msg(M_FATAL, "Cipher '%s' mode not supported", ciphername);
        }

        if (OPENVPN_MAX_CIPHER_BLOCK_SIZE < cipher_kt_block_size(kt->cipher))
        {
            msg(M_FATAL, "Cipher '%s' not allowed: block size too big.", ciphername);
        }
    }
    else {
        if (warn)
        {
            msg(M_WARN, "******* WARNING *******: '--cipher none' was specified. " "This means NO encryption will be performed and tunnelled " "data WILL be transmitted in clear text over the network! " "PLEASE DO RECONSIDER THIS SETTING!");


        }
    }
    if (strcmp(authname, "none") != 0)
    {
        if (!aead_cipher) 
        {
            kt->digest = md_kt_get(authname);
            kt->hmac_length = md_kt_size(kt->digest);

            if (OPENVPN_MAX_HMAC_SIZE < kt->hmac_length)
            {
                msg(M_FATAL, "HMAC '%s' not allowed: digest size too big.", authname);
            }
        }
    }
    else if (!aead_cipher)
    {
        if (warn)
        {
            msg(M_WARN, "******* WARNING *******: '--auth none' was specified. " "This means no authentication will be performed on received " "packets, meaning you CANNOT trust that the data received by " "the remote side have NOT been manipulated. " "PLEASE DO RECONSIDER THIS SETTING!");



        }
    }
}


void init_key_ctx(struct key_ctx *ctx, struct key *key, const struct key_type *kt, int enc, const char *prefix)


{
    struct gc_arena gc = gc_new();
    CLEAR(*ctx);
    if (kt->cipher && kt->cipher_length > 0)
    {

        ALLOC_OBJ(ctx->cipher, cipher_ctx_t);
        cipher_ctx_init(ctx->cipher, key->cipher, kt->cipher_length, kt->cipher, enc);

        msg(D_HANDSHAKE, "%s: Cipher '%s' initialized with %d bit key", prefix, translate_cipher_name_to_openvpn(cipher_kt_name(kt->cipher)), kt->cipher_length *8);



        dmsg(D_SHOW_KEYS, "%s: CIPHER KEY: %s", prefix, format_hex(key->cipher, kt->cipher_length, 0, &gc));
        dmsg(D_CRYPTO_DEBUG, "%s: CIPHER block_size=%d iv_size=%d", prefix, cipher_kt_block_size(kt->cipher), cipher_kt_iv_size(kt->cipher));

        if (cipher_kt_block_size(kt->cipher) < 128/8)
        {
            msg(M_WARN, "WARNING: INSECURE cipher with block size less than 128" " bit (%d bit).  This allows attacks like SWEET32.  Mitigate by " "using a --cipher with a larger block size (e.g. AES-256-CBC).", cipher_kt_block_size(kt->cipher)*8);


        }
    }
    if (kt->digest && kt->hmac_length > 0)
    {
        ALLOC_OBJ(ctx->hmac, hmac_ctx_t);
        hmac_ctx_init(ctx->hmac, key->hmac, kt->hmac_length, kt->digest);

        msg(D_HANDSHAKE, "%s: Using %d bit message hash '%s' for HMAC authentication", prefix, md_kt_size(kt->digest) * 8, md_kt_name(kt->digest));


        dmsg(D_SHOW_KEYS, "%s: HMAC KEY: %s", prefix, format_hex(key->hmac, kt->hmac_length, 0, &gc));

        dmsg(D_CRYPTO_DEBUG, "%s: HMAC size=%d block_size=%d", prefix, md_kt_size(kt->digest), hmac_ctx_size(ctx->hmac));



    }
    gc_free(&gc);
}

void free_key_ctx(struct key_ctx *ctx)
{
    if (ctx->cipher)
    {
        cipher_ctx_cleanup(ctx->cipher);
        free(ctx->cipher);
        ctx->cipher = NULL;
    }
    if (ctx->hmac)
    {
        hmac_ctx_cleanup(ctx->hmac);
        free(ctx->hmac);
        ctx->hmac = NULL;
    }
    ctx->implicit_iv_len = 0;
}

void free_key_ctx_bi(struct key_ctx_bi *ctx)
{
    free_key_ctx(&ctx->encrypt);
    free_key_ctx(&ctx->decrypt);
}

static bool key_is_zero(struct key *key, const struct key_type *kt)
{
    int i;
    for (i = 0; i < kt->cipher_length; ++i)
        if (key->cipher[i])
        {
            return false;
        }
    msg(D_CRYPT_ERRORS, "CRYPTO INFO: WARNING: zero key detected");
    return true;
}


bool check_key(struct key *key, const struct key_type *kt)
{
    if (kt->cipher)
    {
        
        if (key_is_zero(key, kt))
        {
            return false;
        }

        
        {
            const int ndc = key_des_num_cblocks(kt->cipher);
            if (ndc)
            {
                return key_des_check(key->cipher, kt->cipher_length, ndc);
            }
            else {
                return true;
            }
        }
    }
    return true;
}


void fixup_key(struct key *key, const struct key_type *kt)
{
    struct gc_arena gc = gc_new();
    if (kt->cipher)
    {

        const struct key orig = *key;

        const int ndc = key_des_num_cblocks(kt->cipher);

        if (ndc)
        {
            key_des_fixup(key->cipher, kt->cipher_length, ndc);
        }


        if (check_debug_level(D_CRYPTO_DEBUG))
        {
            if (memcmp(orig.cipher, key->cipher, kt->cipher_length))
            {
                dmsg(D_CRYPTO_DEBUG, "CRYPTO INFO: fixup_key: before=%s after=%s", format_hex(orig.cipher, kt->cipher_length, 0, &gc), format_hex(key->cipher, kt->cipher_length, 0, &gc));

            }
        }

    }
    gc_free(&gc);
}

void check_replay_consistency(const struct key_type *kt, bool packet_id)
{
    ASSERT(kt);

    if (!packet_id && (cipher_kt_mode_ofb_cfb(kt->cipher)
                       || cipher_kt_mode_aead(kt->cipher)))
    {
        msg(M_FATAL, "--no-replay cannot be used with a CFB, OFB or AEAD mode cipher");
    }
}


void generate_key_random(struct key *key, const struct key_type *kt)
{
    int cipher_len = MAX_CIPHER_KEY_LENGTH;
    int hmac_len = MAX_HMAC_KEY_LENGTH;

    struct gc_arena gc = gc_new();

    do {
        CLEAR(*key);
        if (kt)
        {
            if (kt->cipher && kt->cipher_length > 0 && kt->cipher_length <= cipher_len)
            {
                cipher_len = kt->cipher_length;
            }

            if (kt->digest && kt->hmac_length > 0 && kt->hmac_length <= hmac_len)
            {
                hmac_len = kt->hmac_length;
            }
        }
        if (!rand_bytes(key->cipher, cipher_len)
            || !rand_bytes(key->hmac, hmac_len))
        {
            msg(M_FATAL, "ERROR: Random number generator cannot obtain entropy for key generation");
        }

        dmsg(D_SHOW_KEY_SOURCE, "Cipher source entropy: %s", format_hex(key->cipher, cipher_len, 0, &gc));
        dmsg(D_SHOW_KEY_SOURCE, "HMAC source entropy: %s", format_hex(key->hmac, hmac_len, 0, &gc));

        if (kt)
        {
            fixup_key(key, kt);
        }
    } while (kt && !check_key(key, kt));

    gc_free(&gc);
}


void key2_print(const struct key2 *k, const struct key_type *kt, const char *prefix0, const char *prefix1)



{
    struct gc_arena gc = gc_new();
    ASSERT(k->n == 2);
    dmsg(D_SHOW_KEY_SOURCE, "%s (cipher): %s", prefix0, format_hex(k->keys[0].cipher, kt->cipher_length, 0, &gc));

    dmsg(D_SHOW_KEY_SOURCE, "%s (hmac): %s", prefix0, format_hex(k->keys[0].hmac, kt->hmac_length, 0, &gc));

    dmsg(D_SHOW_KEY_SOURCE, "%s (cipher): %s", prefix1, format_hex(k->keys[1].cipher, kt->cipher_length, 0, &gc));

    dmsg(D_SHOW_KEY_SOURCE, "%s (hmac): %s", prefix1, format_hex(k->keys[1].hmac, kt->hmac_length, 0, &gc));

    gc_free(&gc);
}

void test_crypto(struct crypto_options *co, struct frame *frame)
{
    int i, j;
    struct gc_arena gc = gc_new();
    struct buffer src = alloc_buf_gc(TUN_MTU_SIZE(frame), &gc);
    struct buffer work = alloc_buf_gc(BUF_SIZE(frame), &gc);
    struct buffer encrypt_workspace = alloc_buf_gc(BUF_SIZE(frame), &gc);
    struct buffer decrypt_workspace = alloc_buf_gc(BUF_SIZE(frame), &gc);
    struct buffer buf = clear_buf();
    void *buf_p;

    
    ASSERT(buf_init(&work, FRAME_HEADROOM(frame)));


    
    {
        const cipher_kt_t *cipher = cipher_ctx_get_cipher_kt(co->key_ctx_bi.encrypt.cipher);

        if (cipher_kt_mode_aead(cipher))
        {
            size_t impl_iv_len = cipher_kt_iv_size(cipher) - sizeof(packet_id_type);
            ASSERT(cipher_kt_iv_size(cipher) <= OPENVPN_MAX_IV_LENGTH);
            ASSERT(cipher_kt_iv_size(cipher) >= OPENVPN_AEAD_MIN_IV_LEN);

            
            ASSERT(rand_bytes(co->key_ctx_bi.encrypt.implicit_iv, OPENVPN_MAX_IV_LENGTH));
            co->key_ctx_bi.encrypt.implicit_iv_len = impl_iv_len;

            memcpy(co->key_ctx_bi.decrypt.implicit_iv, co->key_ctx_bi.encrypt.implicit_iv, OPENVPN_MAX_IV_LENGTH);
            co->key_ctx_bi.decrypt.implicit_iv_len = impl_iv_len;
        }
    }


    msg(M_INFO, "Entering " PACKAGE_NAME " crypto self-test mode.");
    for (i = 1; i <= TUN_MTU_SIZE(frame); ++i)
    {
        update_time();

        msg(M_INFO, "TESTING ENCRYPT/DECRYPT of packet length=%d", i);

        
        ASSERT(buf_init(&src, 0));
        ASSERT(i <= src.capacity);
        src.len = i;
        ASSERT(rand_bytes(BPTR(&src), BLEN(&src)));

        
        buf = work;
        buf_p = buf_write_alloc(&buf, BLEN(&src));
        ASSERT(buf_p);
        memcpy(buf_p, BPTR(&src), BLEN(&src));

        
        ASSERT(buf_init(&encrypt_workspace, FRAME_HEADROOM(frame)));

        
        openvpn_encrypt(&buf, encrypt_workspace, co);

        
        openvpn_decrypt(&buf, decrypt_workspace, co, frame, BPTR(&buf));

        
        if (buf.len != src.len)
        {
            msg(M_FATAL, "SELF TEST FAILED, src.len=%d buf.len=%d", src.len, buf.len);
        }
        for (j = 0; j < i; ++j)
        {
            const uint8_t in = *(BPTR(&src) + j);
            const uint8_t out = *(BPTR(&buf) + j);
            if (in != out)
            {
                msg(M_FATAL, "SELF TEST FAILED, pos=%d in=%d out=%d", j, in, out);
            }
        }
    }
    msg(M_INFO, PACKAGE_NAME " crypto self-test mode SUCCEEDED.");
    gc_free(&gc);
}

void crypto_read_openvpn_key(const struct key_type *key_type, struct key_ctx_bi *ctx, const char *key_file, const char *key_inline, const int key_direction, const char *key_name, const char *opt_name)


{
    struct key2 key2;
    struct key_direction_state kds;
    char log_prefix[128] = { 0 };

    if (key_inline)
    {
        read_key_file(&key2, key_inline, RKF_MUST_SUCCEED|RKF_INLINE);
    }
    else {
        read_key_file(&key2, key_file, RKF_MUST_SUCCEED);
    }

    if (key2.n != 2)
    {
        msg(M_ERR, "File '%s' does not have OpenVPN Static Key format.  Using " "free-form passphrase file is not supported anymore.", key_file);
    }

    
    verify_fix_key2(&key2, key_type, key_file);

    
    key_direction_state_init(&kds, key_direction);
    must_have_n_keys(key_file, opt_name, &key2, kds.need_keys);

    
    openvpn_snprintf(log_prefix, sizeof(log_prefix), "Outgoing %s", key_name);
    init_key_ctx(&ctx->encrypt, &key2.keys[kds.out_key], key_type, OPENVPN_OP_ENCRYPT, log_prefix);
    openvpn_snprintf(log_prefix, sizeof(log_prefix), "Incoming %s", key_name);
    init_key_ctx(&ctx->decrypt, &key2.keys[kds.in_key], key_type, OPENVPN_OP_DECRYPT, log_prefix);

    secure_memzero(&key2, sizeof(key2));
}


static const char static_key_head[] = "-----BEGIN OpenVPN Static key V1-----";
static const char static_key_foot[] = "-----END OpenVPN Static key V1-----";

static const char printable_char_fmt[] = "Non-Hex character ('%c') found at line %d in key file '%s' (%d/%d/%d bytes found/min/max)";

static const char unprintable_char_fmt[] = "Non-Hex, unprintable character (0x%02x) found at line %d in key file '%s' (%d/%d/%d bytes found/min/max)";



void read_key_file(struct key2 *key2, const char *file, const unsigned int flags)
{
    struct gc_arena gc = gc_new();
    struct buffer in;
    int fd, size;
    uint8_t hex_byte[3] = {0, 0, 0};
    const char *error_filename = file;

    
    const unsigned char *cp;
    int hb_index = 0;
    int line_num = 1;
    int line_index = 0;
    int match = 0;

    
    uint8_t *out = (uint8_t *) &key2->keys;
    const int keylen = sizeof(key2->keys);
    int count = 0;

    






    int state = PARSE_INITIAL;

    
    const int hlen = strlen(static_key_head);
    const int flen = strlen(static_key_foot);
    const int onekeylen = sizeof(key2->keys[0]);

    CLEAR(*key2);

    
    if (flags & RKF_INLINE) 
    {
        size = strlen(file) + 1;
        buf_set_read(&in, (const uint8_t *)file, size);
        error_filename = INLINE_FILE_TAG;
    }
    else  {
        in = alloc_buf_gc(2048, &gc);
        fd = platform_open(file, O_RDONLY, 0);
        if (fd == -1)
        {
            msg(M_ERR, "Cannot open file key file '%s'", file);
        }
        size = read(fd, in.data, in.capacity);
        if (size < 0)
        {
            msg(M_FATAL, "Read error on key file ('%s')", file);
        }
        if (size == in.capacity)
        {
            msg(M_FATAL, "Key file ('%s') can be a maximum of %d bytes", file, (int)in.capacity);
        }
        close(fd);
    }

    cp = (unsigned char *)in.data;
    while (size > 0)
    {
        const unsigned char c = *cp;


        msg(M_INFO, "char='%c'[%d] s=%d ln=%d li=%d m=%d c=%d", c, (int)c, state, line_num, line_index, match, count);


        if (c == '\n')
        {
            line_index = match = 0;
            ++line_num;
        }
        else {
            
            if (!line_index)
            {
                
                if (state == PARSE_HEAD)
                {
                    state = PARSE_DATA;
                }

                
                if ((state == PARSE_DATA || state == PARSE_DATA_COMPLETE) && c == '-')
                {
                    state = PARSE_FOOT;
                }
            }

            
            if (state == PARSE_INITIAL)
            {
                if (line_index < hlen && c == static_key_head[line_index])
                {
                    if (++match == hlen)
                    {
                        state = PARSE_HEAD;
                    }
                }
            }

            
            if (state == PARSE_FOOT)
            {
                if (line_index < flen && c == static_key_foot[line_index])
                {
                    if (++match == flen)
                    {
                        state = PARSE_FINISHED;
                    }
                }
            }

            
            if (state == PARSE_DATA)
            {
                if (isxdigit(c))
                {
                    ASSERT(hb_index >= 0 && hb_index < 2);
                    hex_byte[hb_index++] = c;
                    if (hb_index == 2)
                    {
                        unsigned int u;
                        ASSERT(sscanf((const char *)hex_byte, "%x", &u) == 1);
                        *out++ = u;
                        hb_index = 0;
                        if (++count == keylen)
                        {
                            state = PARSE_DATA_COMPLETE;
                        }
                    }
                }
                else if (isspace(c))
                {
                }
                else {
                    msg(M_FATAL, (isprint(c) ? printable_char_fmt : unprintable_char_fmt), c, line_num, error_filename, count, onekeylen, keylen);

                }
            }
            ++line_index;
        }
        ++cp;
        --size;
    }

    
    key2->n = count / onekeylen;

    ASSERT(key2->n >= 0 && key2->n <= (int) SIZE(key2->keys));

    if (flags & RKF_MUST_SUCCEED)
    {
        if (!key2->n)
        {
            msg(M_FATAL, "Insufficient key material or header text not found in file '%s' (%d/%d/%d bytes found/min/max)", error_filename, count, onekeylen, keylen);
        }

        if (state != PARSE_FINISHED)
        {
            msg(M_FATAL, "Footer text not found in file '%s' (%d/%d/%d bytes found/min/max)", error_filename, count, onekeylen, keylen);
        }
    }

    
    if (!(flags & RKF_INLINE))
    {
        buf_clear(&in);
    }


    
    {
        int i;
        printf("KEY READ, n=%d\n", key2->n);
        for (i = 0; i < (int) SIZE(key2->keys); ++i)
        {
            
            const char *fmt = format_hex_ex((const uint8_t *)&key2->keys[i], sizeof(key2->keys[i]), 0, 16, "\n", &gc);




            printf("[%d]\n%s\n\n", i, fmt);
        }
    }


    
    gc_free(&gc);
}


int write_key_file(const int nkeys, const char *filename)
{
    struct gc_arena gc = gc_new();

    int fd, i;
    int nbits = 0;

    
    struct buffer out = alloc_buf_gc(2048, &gc);
    struct buffer nbits_head_text = alloc_buf_gc(128, &gc);

    
    const int bytes_per_line = 16;

    
    fd = platform_open(filename, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);

    if (fd == -1)
    {
        msg(M_ERR, "Cannot open shared secret file '%s' for write", filename);
    }

    buf_printf(&out, "%s\n", static_key_head);

    for (i = 0; i < nkeys; ++i)
    {
        struct key key;
        char *fmt;

        
        generate_key_random(&key, NULL);

        
        fmt = format_hex_ex((const uint8_t *)&key, sizeof(key), 0, bytes_per_line, "\n", &gc);





        
        nbits += sizeof(key) * 8;

        
        buf_printf(&out, "%s\n", fmt);

        
        secure_memzero(fmt, strlen(fmt));
        secure_memzero(&key, sizeof(key));
    }

    buf_printf(&out, "%s\n", static_key_foot);

    
    buf_printf(&nbits_head_text, "#\n# %d bit OpenVPN static key\n#\n", nbits);
    buf_write_string_file(&nbits_head_text, filename, fd);

    
    buf_write_string_file(&out, filename, fd);

    if (close(fd))
    {
        msg(M_ERR, "Close error on shared secret file %s", filename);
    }

    
    buf_clear(&out);

    
    gc_free(&gc);

    return nbits;
}

void must_have_n_keys(const char *filename, const char *option, const struct key2 *key2, int n)
{
    if (key2->n < n)
    {

        msg(M_FATAL, "Key file '%s' used in --%s contains insufficient key material [keys found=%d required=%d]", filename, option, key2->n, n);

        msg(M_FATAL, "Key file '%s' used in --%s contains insufficient key material [keys found=%d required=%d] -- try generating a new key file with '" PACKAGE " --genkey --secret [file]', or use the existing key file in bidirectional mode by specifying --%s without a key direction parameter", filename, option, key2->n, n, option);

    }
}

int ascii2keydirection(int msglevel, const char *str)
{
    if (!str)
    {
        return KEY_DIRECTION_BIDIRECTIONAL;
    }
    else if (!strcmp(str, "0"))
    {
        return KEY_DIRECTION_NORMAL;
    }
    else if (!strcmp(str, "1"))
    {
        return KEY_DIRECTION_INVERSE;
    }
    else {
        msg(msglevel, "Unknown key direction '%s' -- must be '0' or '1'", str);
        return -1;
    }
    return KEY_DIRECTION_BIDIRECTIONAL; 
}

const char * keydirection2ascii(int kd, bool remote)
{
    if (kd == KEY_DIRECTION_BIDIRECTIONAL)
    {
        return NULL;
    }
    else if (kd == KEY_DIRECTION_NORMAL)
    {
        return remote ? "1" : "0";
    }
    else if (kd == KEY_DIRECTION_INVERSE)
    {
        return remote ? "0" : "1";
    }
    else {
        ASSERT(0);
    }
    return NULL; 
}

void key_direction_state_init(struct key_direction_state *kds, int key_direction)
{
    CLEAR(*kds);
    switch (key_direction)
    {
        case KEY_DIRECTION_NORMAL:
            kds->out_key = 0;
            kds->in_key = 1;
            kds->need_keys = 2;
            break;

        case KEY_DIRECTION_INVERSE:
            kds->out_key = 1;
            kds->in_key = 0;
            kds->need_keys = 2;
            break;

        case KEY_DIRECTION_BIDIRECTIONAL:
            kds->out_key = 0;
            kds->in_key = 0;
            kds->need_keys = 1;
            break;

        default:
            ASSERT(0);
    }
}

void verify_fix_key2(struct key2 *key2, const struct key_type *kt, const char *shared_secret_file)
{
    int i;

    for (i = 0; i < key2->n; ++i)
    {
        
        fixup_key(&key2->keys[i], kt);

        
        if (!check_key(&key2->keys[i], kt))
        {
            msg(M_FATAL, "Key #%d in '%s' is bad.  Try making a new key with --genkey.", i+1, shared_secret_file);
        }
    }
}


bool write_key(const struct key *key, const struct key_type *kt, struct buffer *buf)

{
    ASSERT(kt->cipher_length <= MAX_CIPHER_KEY_LENGTH && kt->hmac_length <= MAX_HMAC_KEY_LENGTH);

    if (!buf_write(buf, &kt->cipher_length, 1))
    {
        return false;
    }
    if (!buf_write(buf, &kt->hmac_length, 1))
    {
        return false;
    }
    if (!buf_write(buf, key->cipher, kt->cipher_length))
    {
        return false;
    }
    if (!buf_write(buf, key->hmac, kt->hmac_length))
    {
        return false;
    }

    return true;
}


int read_key(struct key *key, const struct key_type *kt, struct buffer *buf)
{
    uint8_t cipher_length;
    uint8_t hmac_length;

    CLEAR(*key);
    if (!buf_read(buf, &cipher_length, 1))
    {
        goto read_err;
    }
    if (!buf_read(buf, &hmac_length, 1))
    {
        goto read_err;
    }

    if (!buf_read(buf, key->cipher, cipher_length))
    {
        goto read_err;
    }
    if (!buf_read(buf, key->hmac, hmac_length))
    {
        goto read_err;
    }

    if (cipher_length != kt->cipher_length || hmac_length != kt->hmac_length)
    {
        goto key_len_err;
    }

    return 1;

read_err:
    msg(D_TLS_ERRORS, "TLS Error: error reading key from remote");
    return -1;

key_len_err:
    msg(D_TLS_ERRORS, "TLS Error: key length mismatch, local cipher/hmac %d/%d, remote cipher/hmac %d/%d", kt->cipher_length, kt->hmac_length, cipher_length, hmac_length);

    return 0;
}



static uint8_t *nonce_data = NULL; 
static const md_kt_t *nonce_md = NULL; 
static int nonce_secret_len = 0; 


static void prng_reset_nonce()
{
    const int size = md_kt_size(nonce_md) + nonce_secret_len;

    if (!rand_bytes(nonce_data, size))
    {
        msg(M_FATAL, "ERROR: Random number generator cannot obtain entropy for PRNG");
    }

    
    {
        int i;
        for (i = 0; i < size; ++i)
            nonce_data[i] = (uint8_t) i;
    }

}

void prng_init(const char *md_name, const int nonce_secret_len_parm)
{
    prng_uninit();
    nonce_md = md_name ? md_kt_get(md_name) : NULL;
    if (nonce_md)
    {
        ASSERT(nonce_secret_len_parm >= NONCE_SECRET_LEN_MIN && nonce_secret_len_parm <= NONCE_SECRET_LEN_MAX);
        nonce_secret_len = nonce_secret_len_parm;
        {
            const int size = md_kt_size(nonce_md) + nonce_secret_len;
            dmsg(D_CRYPTO_DEBUG, "PRNG init md=%s size=%d", md_kt_name(nonce_md), size);
            nonce_data = (uint8_t *) malloc(size);
            check_malloc_return(nonce_data);
            prng_reset_nonce();
        }
    }
}

void prng_uninit(void)
{
    free(nonce_data);
    nonce_data = NULL;
    nonce_md = NULL;
    nonce_secret_len = 0;
}

void prng_bytes(uint8_t *output, int len)
{
    static size_t processed = 0;

    if (nonce_md)
    {
        const int md_size = md_kt_size(nonce_md);
        while (len > 0)
        {
            const int blen = min_int(len, md_size);
            md_full(nonce_md, nonce_data, md_size + nonce_secret_len, nonce_data);
            memcpy(output, nonce_data, blen);
            output += blen;
            len -= blen;

            
            processed += blen;
            if (processed > PRNG_NONCE_RESET_BYTES)
            {
                prng_reset_nonce();
                processed = 0;
            }
        }
    }
    else {
        ASSERT(rand_bytes(output, len));
    }
}


long int get_random()
{
    long int l;
    prng_bytes((unsigned char *)&l, sizeof(l));
    if (l < 0)
    {
        l = -l;
    }
    return l;
}

static const cipher_name_pair * get_cipher_name_pair(const char *cipher_name)
{
    const cipher_name_pair *pair;
    size_t i = 0;

    
    for (; i < cipher_name_translation_table_count; i++)
    {
        pair = &cipher_name_translation_table[i];
        if (0 == strcmp(cipher_name, pair->openvpn_name)
            || 0 == strcmp(cipher_name, pair->lib_name))
        {
            return pair;
        }
    }

    
    return NULL;
}

const char * translate_cipher_name_from_openvpn(const char *cipher_name)
{
    const cipher_name_pair *pair = get_cipher_name_pair(cipher_name);

    if (NULL == pair)
    {
        return cipher_name;
    }

    return pair->lib_name;
}

const char * translate_cipher_name_to_openvpn(const char *cipher_name)
{
    const cipher_name_pair *pair = get_cipher_name_pair(cipher_name);

    if (NULL == pair)
    {
        return cipher_name;
    }

    return pair->openvpn_name;
}


