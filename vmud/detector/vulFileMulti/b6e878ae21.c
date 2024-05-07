















const char tls1_version_str[] = "TLSv1" OPENSSL_VERSION_PTEXT;


static int tls_decrypt_ticket(SSL *s, const unsigned char *tick, int ticklen, const unsigned char *sess_id, int sesslen, SSL_SESSION **psess);

static int ssl_check_clienthello_tlsext_early(SSL *s);
int ssl_check_serverhello_tlsext(SSL *s);


SSL3_ENC_METHOD const TLSv1_enc_data = {
    tls1_enc, tls1_mac, tls1_setup_key_block, tls1_generate_master_secret, tls1_change_cipher_state, tls1_final_finish_mac, TLS1_FINISH_MAC_LENGTH, tls1_cert_verify_mac, TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE, TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE, tls1_alert_code, tls1_export_keying_material, 0, SSL3_HM_HEADER_LENGTH, ssl3_set_handshake_header, ssl3_handshake_write };
















SSL3_ENC_METHOD const TLSv1_1_enc_data = {
    tls1_enc, tls1_mac, tls1_setup_key_block, tls1_generate_master_secret, tls1_change_cipher_state, tls1_final_finish_mac, TLS1_FINISH_MAC_LENGTH, tls1_cert_verify_mac, TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE, TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE, tls1_alert_code, tls1_export_keying_material, SSL_ENC_FLAG_EXPLICIT_IV, SSL3_HM_HEADER_LENGTH, ssl3_set_handshake_header, ssl3_handshake_write };
















SSL3_ENC_METHOD const TLSv1_2_enc_data = {
    tls1_enc, tls1_mac, tls1_setup_key_block, tls1_generate_master_secret, tls1_change_cipher_state, tls1_final_finish_mac, TLS1_FINISH_MAC_LENGTH, tls1_cert_verify_mac, TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE, TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE, tls1_alert_code, tls1_export_keying_material, SSL_ENC_FLAG_EXPLICIT_IV | SSL_ENC_FLAG_SIGALGS | SSL_ENC_FLAG_SHA256_PRF | SSL_ENC_FLAG_TLS1_2_CIPHERS, SSL3_HM_HEADER_LENGTH, ssl3_set_handshake_header, ssl3_handshake_write };

















long tls1_default_timeout(void)
{
    
    return (60 * 60 * 2);
}

int tls1_new(SSL *s)
{
    if (!ssl3_new(s))
        return (0);
    s->method->ssl_clear(s);
    return (1);
}

void tls1_free(SSL *s)
{

    if (s->tlsext_session_ticket) {
        OPENSSL_free(s->tlsext_session_ticket);
    }

    ssl3_free(s);
}

void tls1_clear(SSL *s)
{
    ssl3_clear(s);
    s->version = s->method->version;
}



typedef struct {
    int nid;                    
    int secbits;                
    unsigned int flags;         
} tls_curve_info;




static const tls_curve_info nid_list[] = {
    {NID_sect163k1, 80, TLS_CURVE_CHAR2},  {NID_sect163r1, 80, TLS_CURVE_CHAR2}, {NID_sect163r2, 80, TLS_CURVE_CHAR2}, {NID_sect193r1, 80, TLS_CURVE_CHAR2}, {NID_sect193r2, 80, TLS_CURVE_CHAR2}, {NID_sect233k1, 112, TLS_CURVE_CHAR2}, {NID_sect233r1, 112, TLS_CURVE_CHAR2}, {NID_sect239k1, 112, TLS_CURVE_CHAR2}, {NID_sect283k1, 128, TLS_CURVE_CHAR2}, {NID_sect283r1, 128, TLS_CURVE_CHAR2}, {NID_sect409k1, 192, TLS_CURVE_CHAR2}, {NID_sect409r1, 192, TLS_CURVE_CHAR2}, {NID_sect571k1, 256, TLS_CURVE_CHAR2}, {NID_sect571r1, 256, TLS_CURVE_CHAR2}, {NID_secp160k1, 80, TLS_CURVE_PRIME}, {NID_secp160r1, 80, TLS_CURVE_PRIME}, {NID_secp160r2, 80, TLS_CURVE_PRIME}, {NID_secp192k1, 80, TLS_CURVE_PRIME}, {NID_X9_62_prime192v1, 80, TLS_CURVE_PRIME}, {NID_secp224k1, 112, TLS_CURVE_PRIME}, {NID_secp224r1, 112, TLS_CURVE_PRIME}, {NID_secp256k1, 128, TLS_CURVE_PRIME}, {NID_X9_62_prime256v1, 128, TLS_CURVE_PRIME}, {NID_secp384r1, 192, TLS_CURVE_PRIME}, {NID_secp521r1, 256, TLS_CURVE_PRIME}, {NID_brainpoolP256r1, 128, TLS_CURVE_PRIME}, {NID_brainpoolP384r1, 192, TLS_CURVE_PRIME}, {NID_brainpoolP512r1, 256, TLS_CURVE_PRIME}, };




























static const unsigned char ecformats_default[] = {
    TLSEXT_ECPOINTFORMAT_uncompressed, TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime, TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2 };



static const unsigned char eccurves_default[] = {
    0, 14,                       0, 13, 0, 25, 0, 28, 0, 11, 0, 12, 0, 27, 0, 24, 0, 9, 0, 10, 0, 26, 0, 22, 0, 23, 0, 8, 0, 6, 0, 7, 0, 20, 0, 21, 0, 4, 0, 5, 0, 18, 0, 19, 0, 1, 0, 2, 0, 3, 0, 15, 0, 16, 0, 17, };




























static const unsigned char suiteb_curves[] = {
    0, TLSEXT_curve_P_256, 0, TLSEXT_curve_P_384 };


int tls1_ec_curve_id2nid(int curve_id)
{
    
    if ((curve_id < 1) || ((unsigned int)curve_id > sizeof(nid_list) / sizeof(nid_list[0])))
        return 0;
    return nid_list[curve_id - 1].nid;
}

int tls1_ec_nid2curve_id(int nid)
{
    
    switch (nid) {
    case NID_sect163k1:        
        return 1;
    case NID_sect163r1:        
        return 2;
    case NID_sect163r2:        
        return 3;
    case NID_sect193r1:        
        return 4;
    case NID_sect193r2:        
        return 5;
    case NID_sect233k1:        
        return 6;
    case NID_sect233r1:        
        return 7;
    case NID_sect239k1:        
        return 8;
    case NID_sect283k1:        
        return 9;
    case NID_sect283r1:        
        return 10;
    case NID_sect409k1:        
        return 11;
    case NID_sect409r1:        
        return 12;
    case NID_sect571k1:        
        return 13;
    case NID_sect571r1:        
        return 14;
    case NID_secp160k1:        
        return 15;
    case NID_secp160r1:        
        return 16;
    case NID_secp160r2:        
        return 17;
    case NID_secp192k1:        
        return 18;
    case NID_X9_62_prime192v1: 
        return 19;
    case NID_secp224k1:        
        return 20;
    case NID_secp224r1:        
        return 21;
    case NID_secp256k1:        
        return 22;
    case NID_X9_62_prime256v1: 
        return 23;
    case NID_secp384r1:        
        return 24;
    case NID_secp521r1:        
        return 25;
    case NID_brainpoolP256r1:  
        return 26;
    case NID_brainpoolP384r1:  
        return 27;
    case NID_brainpoolP512r1:  
        return 28;
    default:
        return 0;
    }
}


static int tls1_get_curvelist(SSL *s, int sess, const unsigned char **pcurves, size_t *num_curves)

{
    size_t pcurveslen = 0;
    if (sess) {
        *pcurves = s->session->tlsext_ellipticcurvelist;
        pcurveslen = s->session->tlsext_ellipticcurvelist_length;
    } else {
        
        switch (tls1_suiteb(s)) {
        case SSL_CERT_FLAG_SUITEB_128_LOS:
            *pcurves = suiteb_curves;
            pcurveslen = sizeof(suiteb_curves);
            break;

        case SSL_CERT_FLAG_SUITEB_128_LOS_ONLY:
            *pcurves = suiteb_curves;
            pcurveslen = 2;
            break;

        case SSL_CERT_FLAG_SUITEB_192_LOS:
            *pcurves = suiteb_curves + 2;
            pcurveslen = 2;
            break;
        default:
            *pcurves = s->tlsext_ellipticcurvelist;
            pcurveslen = s->tlsext_ellipticcurvelist_length;
        }
        if (!*pcurves) {
            *pcurves = eccurves_default;
            pcurveslen = sizeof(eccurves_default);
        }
    }

    
    if (pcurveslen & 1) {
        SSLerr(SSL_F_TLS1_GET_CURVELIST, ERR_R_INTERNAL_ERROR);
        *num_curves = 0;
        return 0;
    } else {
        *num_curves = pcurveslen / 2;
        return 1;
    }
}


static int tls_curve_allowed(SSL *s, const unsigned char *curve, int op)
{
    const tls_curve_info *cinfo;
    if (curve[0])
        return 1;
    if ((curve[1] < 1) || ((size_t)curve[1] > sizeof(nid_list) / sizeof(nid_list[0])))
        return 0;
    cinfo = &nid_list[curve[1] - 1];

    if (cinfo->flags & TLS_CURVE_CHAR2)
        return 0;

    return ssl_security(s, op, cinfo->secbits, cinfo->nid, (void *)curve);
}


int tls1_check_curve(SSL *s, const unsigned char *p, size_t len)
{
    const unsigned char *curves;
    size_t num_curves, i;
    unsigned int suiteb_flags = tls1_suiteb(s);
    if (len != 3 || p[0] != NAMED_CURVE_TYPE)
        return 0;
    
    if (suiteb_flags) {
        unsigned long cid = s->s3->tmp.new_cipher->id;
        if (p[1])
            return 0;
        if (cid == TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256) {
            if (p[2] != TLSEXT_curve_P_256)
                return 0;
        } else if (cid == TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384) {
            if (p[2] != TLSEXT_curve_P_384)
                return 0;
        } else                   return 0;
    }
    if (!tls1_get_curvelist(s, 0, &curves, &num_curves))
        return 0;
    for (i = 0; i < num_curves; i++, curves += 2) {
        if (p[1] == curves[0] && p[2] == curves[1])
            return tls_curve_allowed(s, p + 1, SSL_SECOP_CURVE_CHECK);
    }
    return 0;
}


int tls1_shared_curve(SSL *s, int nmatch)
{
    const unsigned char *pref, *supp;
    size_t num_pref, num_supp, i, j;
    int k;
    
    if (s->server == 0)
        return -1;
    if (nmatch == -2) {
        if (tls1_suiteb(s)) {
            
            unsigned long cid = s->s3->tmp.new_cipher->id;
            if (cid == TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
                return NID_X9_62_prime256v1; 
            if (cid == TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
                return NID_secp384r1; 
            
            return NID_undef;
        }
        
        nmatch = 0;
    }
    
    if (!tls1_get_curvelist (s, (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE) != 0, &supp, &num_supp))

        
        return nmatch == -1 ? 0 : NID_undef;
    if (!tls1_get_curvelist (s, !(s->options & SSL_OP_CIPHER_SERVER_PREFERENCE), &pref, &num_pref))

        return nmatch == -1 ? 0 : NID_undef;
    k = 0;
    for (i = 0; i < num_pref; i++, pref += 2) {
        const unsigned char *tsupp = supp;
        for (j = 0; j < num_supp; j++, tsupp += 2) {
            if (pref[0] == tsupp[0] && pref[1] == tsupp[1]) {
                if (!tls_curve_allowed(s, pref, SSL_SECOP_CURVE_SHARED))
                    continue;
                if (nmatch == k) {
                    int id = (pref[0] << 8) | pref[1];
                    return tls1_ec_curve_id2nid(id);
                }
                k++;
            }
        }
    }
    if (nmatch == -1)
        return k;
    
    return NID_undef;
}

int tls1_set_curves(unsigned char **pext, size_t *pextlen, int *curves, size_t ncurves)
{
    unsigned char *clist, *p;
    size_t i;
    
    unsigned long dup_list = 0;
    clist = OPENSSL_malloc(ncurves * 2);
    if (!clist)
        return 0;
    for (i = 0, p = clist; i < ncurves; i++) {
        unsigned long idmask;
        int id;
        id = tls1_ec_nid2curve_id(curves[i]);
        idmask = 1L << id;
        if (!id || (dup_list & idmask)) {
            OPENSSL_free(clist);
            return 0;
        }
        dup_list |= idmask;
        s2n(id, p);
    }
    if (*pext)
        OPENSSL_free(*pext);
    *pext = clist;
    *pextlen = ncurves * 2;
    return 1;
}



typedef struct {
    size_t nidcnt;
    int nid_arr[MAX_CURVELIST];
} nid_cb_st;

static int nid_cb(const char *elem, int len, void *arg)
{
    nid_cb_st *narg = arg;
    size_t i;
    int nid;
    char etmp[20];
    if (elem == NULL)
        return 0;
    if (narg->nidcnt == MAX_CURVELIST)
        return 0;
    if (len > (int)(sizeof(etmp) - 1))
        return 0;
    memcpy(etmp, elem, len);
    etmp[len] = 0;
    nid = EC_curve_nist2nid(etmp);
    if (nid == NID_undef)
        nid = OBJ_sn2nid(etmp);
    if (nid == NID_undef)
        nid = OBJ_ln2nid(etmp);
    if (nid == NID_undef)
        return 0;
    for (i = 0; i < narg->nidcnt; i++)
        if (narg->nid_arr[i] == nid)
            return 0;
    narg->nid_arr[narg->nidcnt++] = nid;
    return 1;
}


int tls1_set_curves_list(unsigned char **pext, size_t *pextlen, const char *str)
{
    nid_cb_st ncb;
    ncb.nidcnt = 0;
    if (!CONF_parse_list(str, ':', 1, nid_cb, &ncb))
        return 0;
    if (pext == NULL)
        return 1;
    return tls1_set_curves(pext, pextlen, ncb.nid_arr, ncb.nidcnt);
}


static int tls1_set_ec_id(unsigned char *curve_id, unsigned char *comp_id, EC_KEY *ec)
{
    int is_prime, id;
    const EC_GROUP *grp;
    const EC_METHOD *meth;
    if (!ec)
        return 0;
    
    grp = EC_KEY_get0_group(ec);
    if (!grp)
        return 0;
    meth = EC_GROUP_method_of(grp);
    if (!meth)
        return 0;
    if (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field)
        is_prime = 1;
    else is_prime = 0;
    
    id = EC_GROUP_get_curve_name(grp);
    id = tls1_ec_nid2curve_id(id);
    
    if (id) {
        curve_id[0] = 0;
        curve_id[1] = (unsigned char)id;
    } else {
        curve_id[0] = 0xff;
        if (is_prime)
            curve_id[1] = 0x01;
        else curve_id[1] = 0x02;
    }
    if (comp_id) {
        if (EC_KEY_get0_public_key(ec) == NULL)
            return 0;
        if (EC_KEY_get_conv_form(ec) == POINT_CONVERSION_COMPRESSED) {
            if (is_prime)
                *comp_id = TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime;
            else *comp_id = TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2;
        } else *comp_id = TLSEXT_ECPOINTFORMAT_uncompressed;
    }
    return 1;
}


static int tls1_check_ec_key(SSL *s, unsigned char *curve_id, unsigned char *comp_id)
{
    const unsigned char *pformats, *pcurves;
    size_t num_formats, num_curves, i;
    int j;
    
    if (comp_id && s->session->tlsext_ecpointformatlist) {
        pformats = s->session->tlsext_ecpointformatlist;
        num_formats = s->session->tlsext_ecpointformatlist_length;
        for (i = 0; i < num_formats; i++, pformats++) {
            if (*comp_id == *pformats)
                break;
        }
        if (i == num_formats)
            return 0;
    }
    if (!curve_id)
        return 1;
    
    for (j = 0; j <= 1; j++) {
        if (!tls1_get_curvelist(s, j, &pcurves, &num_curves))
            return 0;
        for (i = 0; i < num_curves; i++, pcurves += 2) {
            if (pcurves[0] == curve_id[0] && pcurves[1] == curve_id[1])
                break;
        }
        if (i == num_curves)
            return 0;
        
        if (!s->server)
            break;
    }
    return 1;
}

static void tls1_get_formatlist(SSL *s, const unsigned char **pformats, size_t *num_formats)
{
    
    if (s->tlsext_ecpointformatlist) {
        *pformats = s->tlsext_ecpointformatlist;
        *num_formats = s->tlsext_ecpointformatlist_length;
    } else {
        *pformats = ecformats_default;
        
        if (tls1_suiteb(s))
            *num_formats = sizeof(ecformats_default) - 1;
        else *num_formats = sizeof(ecformats_default);
    }
}


static int tls1_check_cert_param(SSL *s, X509 *x, int set_ee_md)
{
    unsigned char comp_id, curve_id[2];
    EVP_PKEY *pkey;
    int rv;
    pkey = X509_get_pubkey(x);
    if (!pkey)
        return 0;
    
    if (pkey->type != EVP_PKEY_EC) {
        EVP_PKEY_free(pkey);
        return 1;
    }
    rv = tls1_set_ec_id(curve_id, &comp_id, pkey->pkey.ec);
    EVP_PKEY_free(pkey);
    if (!rv)
        return 0;
    
    rv = tls1_check_ec_key(s, s->server ? curve_id : NULL, &comp_id);
    if (!rv)
        return 0;
    
    if (set_ee_md && tls1_suiteb(s)) {
        int check_md;
        size_t i;
        CERT *c = s->cert;
        if (curve_id[0])
            return 0;
        
        if (curve_id[1] == TLSEXT_curve_P_256)
            check_md = NID_ecdsa_with_SHA256;
        else if (curve_id[1] == TLSEXT_curve_P_384)
            check_md = NID_ecdsa_with_SHA384;
        else return 0;
        for (i = 0; i < c->shared_sigalgslen; i++)
            if (check_md == c->shared_sigalgs[i].signandhash_nid)
                break;
        if (i == c->shared_sigalgslen)
            return 0;
        if (set_ee_md == 2) {
            if (check_md == NID_ecdsa_with_SHA256)
                c->pkeys[SSL_PKEY_ECC].digest = EVP_sha256();
            else c->pkeys[SSL_PKEY_ECC].digest = EVP_sha384();
        }
    }
    return rv;
}



int tls1_check_ec_tmp_key(SSL *s, unsigned long cid)
{
    unsigned char curve_id[2];
    EC_KEY *ec = s->cert->ecdh_tmp;

    
    if (s->cert->cert_flags & SSL_CERT_FLAG_BROKEN_PROTOCOL)
        return 1;

    
    if (tls1_suiteb(s)) {
        
        if (cid == TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
            curve_id[1] = TLSEXT_curve_P_256;
        else if (cid == TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
            curve_id[1] = TLSEXT_curve_P_384;
        else return 0;
        curve_id[0] = 0;
        
        if (!tls1_check_ec_key(s, curve_id, NULL))
            return 0;
        
        if (s->cert->ecdh_tmp_auto || s->cert->ecdh_tmp_cb)
            return 1;
        
        else {
            unsigned char curve_tmp[2];
            if (!ec)
                return 0;
            if (!tls1_set_ec_id(curve_tmp, NULL, ec))
                return 0;
            if (!curve_tmp[0] || curve_tmp[1] == curve_id[1])
                return 1;
            return 0;
        }

    }
    if (s->cert->ecdh_tmp_auto) {
        
        if (tls1_shared_curve(s, 0))
            return 1;
        else return 0;
    }
    if (!ec) {
        if (s->cert->ecdh_tmp_cb)
            return 1;
        else return 0;
    }
    if (!tls1_set_ec_id(curve_id, NULL, ec))
        return 0;


    return 1;

    return tls1_check_ec_key(s, curve_id, NULL);

}




static int tls1_check_cert_param(SSL *s, X509 *x, int set_ee_md)
{
    return 1;
}





























static const unsigned char tls12_sigalgs[] = {
    tlsext_sigalg(TLSEXT_hash_sha512)
        tlsext_sigalg(TLSEXT_hash_sha384)
        tlsext_sigalg(TLSEXT_hash_sha256)
        tlsext_sigalg(TLSEXT_hash_sha224)
        tlsext_sigalg(TLSEXT_hash_sha1)
};


static const unsigned char suiteb_sigalgs[] = {
    tlsext_sigalg_ecdsa(TLSEXT_hash_sha256)
        tlsext_sigalg_ecdsa(TLSEXT_hash_sha384)
};

size_t tls12_get_psigalgs(SSL *s, const unsigned char **psigs)
{
    

    switch (tls1_suiteb(s)) {
    case SSL_CERT_FLAG_SUITEB_128_LOS:
        *psigs = suiteb_sigalgs;
        return sizeof(suiteb_sigalgs);

    case SSL_CERT_FLAG_SUITEB_128_LOS_ONLY:
        *psigs = suiteb_sigalgs;
        return 2;

    case SSL_CERT_FLAG_SUITEB_192_LOS:
        *psigs = suiteb_sigalgs + 2;
        return 2;
    }

    
    if (s->server && s->cert->client_sigalgs) {
        *psigs = s->cert->client_sigalgs;
        return s->cert->client_sigalgslen;
    } else if (s->cert->conf_sigalgs) {
        *psigs = s->cert->conf_sigalgs;
        return s->cert->conf_sigalgslen;
    } else {
        *psigs = tls12_sigalgs;
        return sizeof(tls12_sigalgs);
    }
}


int tls12_check_peer_sigalg(const EVP_MD **pmd, SSL *s, const unsigned char *sig, EVP_PKEY *pkey)
{
    const unsigned char *sent_sigs;
    size_t sent_sigslen, i;
    int sigalg = tls12_get_sigid(pkey);
    
    if (sigalg == -1)
        return -1;
    
    if (sigalg != (int)sig[1]) {
        SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_WRONG_SIGNATURE_TYPE);
        return 0;
    }

    if (pkey->type == EVP_PKEY_EC) {
        unsigned char curve_id[2], comp_id;
        
        if (!tls1_set_ec_id(curve_id, &comp_id, pkey->pkey.ec))
            return 0;
        if (!s->server && !tls1_check_ec_key(s, curve_id, &comp_id)) {
            SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_WRONG_CURVE);
            return 0;
        }
        
        if (tls1_suiteb(s)) {
            if (curve_id[0])
                return 0;
            if (curve_id[1] == TLSEXT_curve_P_256) {
                if (sig[0] != TLSEXT_hash_sha256) {
                    SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_ILLEGAL_SUITEB_DIGEST);
                    return 0;
                }
            } else if (curve_id[1] == TLSEXT_curve_P_384) {
                if (sig[0] != TLSEXT_hash_sha384) {
                    SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_ILLEGAL_SUITEB_DIGEST);
                    return 0;
                }
            } else return 0;
        }
    } else if (tls1_suiteb(s))
        return 0;


    
    sent_sigslen = tls12_get_psigalgs(s, &sent_sigs);
    for (i = 0; i < sent_sigslen; i += 2, sent_sigs += 2) {
        if (sig[0] == sent_sigs[0] && sig[1] == sent_sigs[1])
            break;
    }
    
    if (i == sent_sigslen && (sig[0] != TLSEXT_hash_sha1 || s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT)) {

        SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_WRONG_SIGNATURE_TYPE);
        return 0;
    }
    *pmd = tls12_get_hash(sig[0]);
    if (*pmd == NULL) {
        SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_UNKNOWN_DIGEST);
        return 0;
    }
    
    if (!ssl_security(s, SSL_SECOP_SIGALG_CHECK, EVP_MD_size(*pmd) * 4, EVP_MD_type(*pmd), (void *)sig)) {

        SSLerr(SSL_F_TLS12_CHECK_PEER_SIGALG, SSL_R_WRONG_SIGNATURE_TYPE);
        return 0;
    }
    
    if (s->session && s->session->sess_cert)
        s->session->sess_cert->peer_key->digest = *pmd;
    return 1;
}


void ssl_set_client_disabled(SSL *s)
{
    CERT *c = s->cert;
    c->mask_a = 0;
    c->mask_k = 0;
    
    if (!SSL_CLIENT_USE_TLS1_2_CIPHERS(s))
        c->mask_ssl = SSL_TLSV1_2;
    else c->mask_ssl = 0;
    ssl_set_sig_mask(&c->mask_a, s, SSL_SECOP_SIGALG_MASK);
    
    if (c->mask_a & SSL_aRSA)
        c->mask_k |= SSL_kDHr | SSL_kECDHr;
    if (c->mask_a & SSL_aDSS)
        c->mask_k |= SSL_kDHd;
    if (c->mask_a & SSL_aECDSA)
        c->mask_k |= SSL_kECDHe;

    if (!kssl_tgt_is_available(s->kssl_ctx)) {
        c->mask_a |= SSL_aKRB5;
        c->mask_k |= SSL_kKRB5;
    }


    
    if (!s->psk_client_callback) {
        c->mask_a |= SSL_aPSK;
        c->mask_k |= SSL_kPSK;
    }


    if (!(s->srp_ctx.srp_Mask & SSL_kSRP)) {
        c->mask_a |= SSL_aSRP;
        c->mask_k |= SSL_kSRP;
    }

    c->valid = 1;
}

int ssl_cipher_disabled(SSL *s, const SSL_CIPHER *c, int op)
{
    CERT *ct = s->cert;
    if (c->algorithm_ssl & ct->mask_ssl || c->algorithm_mkey & ct->mask_k || c->algorithm_auth & ct->mask_a)
        return 1;
    return !ssl_security(s, op, c->strength_bits, 0, (void *)c);
}

static int tls_use_ticket(SSL *s)
{
    if (s->options & SSL_OP_NO_TICKET)
        return 0;
    return ssl_security(s, SSL_SECOP_TICKET, 0, 0, NULL);
}

unsigned char *ssl_add_clienthello_tlsext(SSL *s, unsigned char *buf, unsigned char *limit, int *al)
{
    int extdatalen = 0;
    unsigned char *orig = buf;
    unsigned char *ret = buf;

    
    int using_ecc = 0;
    if (s->version >= TLS1_VERSION || SSL_IS_DTLS(s)) {
        int i;
        unsigned long alg_k, alg_a;
        STACK_OF(SSL_CIPHER) *cipher_stack = SSL_get_ciphers(s);

        for (i = 0; i < sk_SSL_CIPHER_num(cipher_stack); i++) {
            SSL_CIPHER *c = sk_SSL_CIPHER_value(cipher_stack, i);

            alg_k = c->algorithm_mkey;
            alg_a = c->algorithm_auth;
            if ((alg_k & (SSL_kECDHE | SSL_kECDHr | SSL_kECDHe)
                 || (alg_a & SSL_aECDSA))) {
                using_ecc = 1;
                break;
            }
        }
    }


    ret += 2;

    if (ret >= limit)
        return NULL;            

    
    if (s->renegotiate) {
        int el;

        if (!ssl_add_clienthello_renegotiate_ext(s, 0, &el, 0)) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        if ((limit - ret - 4 - el) < 0)
            return NULL;

        s2n(TLSEXT_TYPE_renegotiate, ret);
        s2n(el, ret);

        if (!ssl_add_clienthello_renegotiate_ext(s, ret, &el, el)) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        ret += el;
    }
    
    if (s->client_version == SSL3_VERSION)
        goto done;

    if (s->tlsext_hostname != NULL) {
        
        unsigned long size_str;
        long lenmax;

        

        if ((lenmax = limit - ret - 9) < 0 || (size_str = strlen(s->tlsext_hostname)) > (unsigned long)lenmax)

            return NULL;

        
        s2n(TLSEXT_TYPE_server_name, ret);
        s2n(size_str + 5, ret);

        
        s2n(size_str + 3, ret);

        
        *(ret++) = (unsigned char)TLSEXT_NAMETYPE_host_name;
        s2n(size_str, ret);
        memcpy(ret, s->tlsext_hostname, size_str);
        ret += size_str;
    }

    
    if (s->srp_ctx.login != NULL) { 

        int login_len = strlen(s->srp_ctx.login);
        if (login_len > 255 || login_len == 0) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        
        if ((limit - ret - 5 - login_len) < 0)
            return NULL;

        
        s2n(TLSEXT_TYPE_srp, ret);
        s2n(login_len + 1, ret);
        (*ret++) = (unsigned char)login_len;
        memcpy(ret, s->srp_ctx.login, login_len);
        ret += login_len;
    }



    if (using_ecc) {
        
        long lenmax;
        const unsigned char *pcurves, *pformats;
        size_t num_curves, num_formats, curves_list_len;
        size_t i;
        unsigned char *etmp;

        tls1_get_formatlist(s, &pformats, &num_formats);

        if ((lenmax = limit - ret - 5) < 0)
            return NULL;
        if (num_formats > (size_t)lenmax)
            return NULL;
        if (num_formats > 255) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        s2n(TLSEXT_TYPE_ec_point_formats, ret);
        
        s2n(num_formats + 1, ret);
        *(ret++) = (unsigned char)num_formats;
        memcpy(ret, pformats, num_formats);
        ret += num_formats;

        
        pcurves = s->tlsext_ellipticcurvelist;
        if (!tls1_get_curvelist(s, 0, &pcurves, &num_curves))
            return NULL;

        if ((lenmax = limit - ret - 6) < 0)
            return NULL;
        if (num_curves > (size_t)lenmax / 2)
            return NULL;
        if (num_curves > 65532 / 2) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        s2n(TLSEXT_TYPE_elliptic_curves, ret);
        etmp = ret + 4;
        
        for (i = 0; i < num_curves; i++, pcurves += 2) {
            if (tls_curve_allowed(s, pcurves, SSL_SECOP_CURVE_SUPPORTED)) {
                *etmp++ = pcurves[0];
                *etmp++ = pcurves[1];
            }
        }

        curves_list_len = etmp - ret - 4;

        s2n(curves_list_len + 2, ret);
        s2n(curves_list_len, ret);
        ret += curves_list_len;
    }


    if (tls_use_ticket(s)) {
        int ticklen;
        if (!s->new_session && s->session && s->session->tlsext_tick)
            ticklen = s->session->tlsext_ticklen;
        else if (s->session && s->tlsext_session_ticket && s->tlsext_session_ticket->data) {
            ticklen = s->tlsext_session_ticket->length;
            s->session->tlsext_tick = OPENSSL_malloc(ticklen);
            if (!s->session->tlsext_tick)
                return NULL;
            memcpy(s->session->tlsext_tick, s->tlsext_session_ticket->data, ticklen);
            s->session->tlsext_ticklen = ticklen;
        } else ticklen = 0;
        if (ticklen == 0 && s->tlsext_session_ticket && s->tlsext_session_ticket->data == NULL)
            goto skip_ext;
        
        if ((long)(limit - ret - 4 - ticklen) < 0)
            return NULL;
        s2n(TLSEXT_TYPE_session_ticket, ret);
        s2n(ticklen, ret);
        if (ticklen) {
            memcpy(ret, s->session->tlsext_tick, ticklen);
            ret += ticklen;
        }
    }
 skip_ext:

    if (SSL_USE_SIGALGS(s)) {
        size_t salglen;
        const unsigned char *salg;
        unsigned char *etmp;
        salglen = tls12_get_psigalgs(s, &salg);
        if ((size_t)(limit - ret) < salglen + 6)
            return NULL;
        s2n(TLSEXT_TYPE_signature_algorithms, ret);
        etmp = ret;
        
        ret += 4;
        salglen = tls12_copy_sigalgs(s, ret, salg, salglen);
        
        s2n(salglen + 2, etmp);
        s2n(salglen, etmp);
        ret += salglen;
    }

    if (s->tlsext_status_type == TLSEXT_STATUSTYPE_ocsp) {
        int i;
        long extlen, idlen, itmp;
        OCSP_RESPID *id;

        idlen = 0;
        for (i = 0; i < sk_OCSP_RESPID_num(s->tlsext_ocsp_ids); i++) {
            id = sk_OCSP_RESPID_value(s->tlsext_ocsp_ids, i);
            itmp = i2d_OCSP_RESPID(id, NULL);
            if (itmp <= 0)
                return NULL;
            idlen += itmp + 2;
        }

        if (s->tlsext_ocsp_exts) {
            extlen = i2d_X509_EXTENSIONS(s->tlsext_ocsp_exts, NULL);
            if (extlen < 0)
                return NULL;
        } else extlen = 0;

        if ((long)(limit - ret - 7 - extlen - idlen) < 0)
            return NULL;
        s2n(TLSEXT_TYPE_status_request, ret);
        if (extlen + idlen > 0xFFF0)
            return NULL;
        s2n(extlen + idlen + 5, ret);
        *(ret++) = TLSEXT_STATUSTYPE_ocsp;
        s2n(idlen, ret);
        for (i = 0; i < sk_OCSP_RESPID_num(s->tlsext_ocsp_ids); i++) {
            
            unsigned char *q = ret;
            id = sk_OCSP_RESPID_value(s->tlsext_ocsp_ids, i);
            
            ret += 2;
            itmp = i2d_OCSP_RESPID(id, &ret);
            
            s2n(itmp, q);
        }
        s2n(extlen, ret);
        if (extlen > 0)
            i2d_X509_EXTENSIONS(s->tlsext_ocsp_exts, &ret);
    }

    
    if ((limit - ret - 4 - 1) < 0)
        return NULL;
    s2n(TLSEXT_TYPE_heartbeat, ret);
    s2n(1, ret);
    
    if (s->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_RECV_REQUESTS)
        *(ret++) = SSL_TLSEXT_HB_DONT_SEND_REQUESTS;
    else *(ret++) = SSL_TLSEXT_HB_ENABLED;



    if (s->ctx->next_proto_select_cb && !s->s3->tmp.finish_md_len) {
        
        if (limit - ret - 4 < 0)
            return NULL;
        s2n(TLSEXT_TYPE_next_proto_neg, ret);
        s2n(0, ret);
    }


    if (s->alpn_client_proto_list && !s->s3->tmp.finish_md_len) {
        if ((size_t)(limit - ret) < 6 + s->alpn_client_proto_list_len)
            return NULL;
        s2n(TLSEXT_TYPE_application_layer_protocol_negotiation, ret);
        s2n(2 + s->alpn_client_proto_list_len, ret);
        s2n(s->alpn_client_proto_list_len, ret);
        memcpy(ret, s->alpn_client_proto_list, s->alpn_client_proto_list_len);
        ret += s->alpn_client_proto_list_len;
    }

    if (SSL_IS_DTLS(s) && SSL_get_srtp_profiles(s)) {
        int el;

        ssl_add_clienthello_use_srtp_ext(s, 0, &el, 0);

        if ((limit - ret - 4 - el) < 0)
            return NULL;

        s2n(TLSEXT_TYPE_use_srtp, ret);
        s2n(el, ret);

        if (ssl_add_clienthello_use_srtp_ext(s, ret, &el, el)) {
            SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }
        ret += el;
    }

    custom_ext_init(&s->cert->cli_ext);
    
    if (!custom_ext_add(s, 0, &ret, limit, al))
        return NULL;

    s2n(TLSEXT_TYPE_encrypt_then_mac, ret);
    s2n(0, ret);

    s2n(TLSEXT_TYPE_extended_master_secret, ret);
    s2n(0, ret);

    
    if (s->options & SSL_OP_TLSEXT_PADDING) {
        int hlen = ret - (unsigned char *)s->init_buf->data;
        
        if (s->state == SSL23_ST_CW_CLNT_HELLO_A)
            hlen -= 5;
        if (hlen > 0xff && hlen < 0x200) {
            hlen = 0x200 - hlen;
            if (hlen >= 4)
                hlen -= 4;
            else hlen = 0;

            s2n(TLSEXT_TYPE_padding, ret);
            s2n(hlen, ret);
            memset(ret, 0, hlen);
            ret += hlen;
        }
    }

 done:

    if ((extdatalen = ret - orig - 2) == 0)
        return orig;

    s2n(extdatalen, orig);
    return ret;
}

unsigned char *ssl_add_serverhello_tlsext(SSL *s, unsigned char *buf, unsigned char *limit, int *al)
{
    int extdatalen = 0;
    unsigned char *orig = buf;
    unsigned char *ret = buf;

    int next_proto_neg_seen;


    unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    unsigned long alg_a = s->s3->tmp.new_cipher->algorithm_auth;
    int using_ecc = (alg_k & (SSL_kECDHE | SSL_kECDHr | SSL_kECDHe))
        || (alg_a & SSL_aECDSA);
    using_ecc = using_ecc && (s->session->tlsext_ecpointformatlist != NULL);


    ret += 2;
    if (ret >= limit)
        return NULL;            

    if (s->s3->send_connection_binding) {
        int el;

        if (!ssl_add_serverhello_renegotiate_ext(s, 0, &el, 0)) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        if ((limit - ret - 4 - el) < 0)
            return NULL;

        s2n(TLSEXT_TYPE_renegotiate, ret);
        s2n(el, ret);

        if (!ssl_add_serverhello_renegotiate_ext(s, ret, &el, el)) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        ret += el;
    }

    
    if (s->version == SSL3_VERSION)
        goto done;

    if (!s->hit && s->servername_done == 1 && s->session->tlsext_hostname != NULL) {
        if ((long)(limit - ret - 4) < 0)
            return NULL;

        s2n(TLSEXT_TYPE_server_name, ret);
        s2n(0, ret);
    }

    if (using_ecc) {
        const unsigned char *plist;
        size_t plistlen;
        
        long lenmax;

        tls1_get_formatlist(s, &plist, &plistlen);

        if ((lenmax = limit - ret - 5) < 0)
            return NULL;
        if (plistlen > (size_t)lenmax)
            return NULL;
        if (plistlen > 255) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }

        s2n(TLSEXT_TYPE_ec_point_formats, ret);
        s2n(plistlen + 1, ret);
        *(ret++) = (unsigned char)plistlen;
        memcpy(ret, plist, plistlen);
        ret += plistlen;

    }
    


    if (s->tlsext_ticket_expected && tls_use_ticket(s)) {
        if ((long)(limit - ret - 4) < 0)
            return NULL;
        s2n(TLSEXT_TYPE_session_ticket, ret);
        s2n(0, ret);
    }

    if (s->tlsext_status_expected) {
        if ((long)(limit - ret - 4) < 0)
            return NULL;
        s2n(TLSEXT_TYPE_status_request, ret);
        s2n(0, ret);
    }


    if (SSL_IS_DTLS(s) && s->srtp_profile) {
        int el;

        ssl_add_serverhello_use_srtp_ext(s, 0, &el, 0);

        if ((limit - ret - 4 - el) < 0)
            return NULL;

        s2n(TLSEXT_TYPE_use_srtp, ret);
        s2n(el, ret);

        if (ssl_add_serverhello_use_srtp_ext(s, ret, &el, el)) {
            SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT, ERR_R_INTERNAL_ERROR);
            return NULL;
        }
        ret += el;
    }


    if (((s->s3->tmp.new_cipher->id & 0xFFFF) == 0x80 || (s->s3->tmp.new_cipher->id & 0xFFFF) == 0x81)
        && (SSL_get_options(s) & SSL_OP_CRYPTOPRO_TLSEXT_BUG)) {
        const unsigned char cryptopro_ext[36] = {
            0xfd, 0xe8,          0x00, 0x20, 0x30, 0x1e, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x09, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x16, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x17 };





        if (limit - ret < 36)
            return NULL;
        memcpy(ret, cryptopro_ext, 36);
        ret += 36;

    }

    
    if (s->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED) {
        if ((limit - ret - 4 - 1) < 0)
            return NULL;
        s2n(TLSEXT_TYPE_heartbeat, ret);
        s2n(1, ret);
        
        if (s->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_RECV_REQUESTS)
            *(ret++) = SSL_TLSEXT_HB_DONT_SEND_REQUESTS;
        else *(ret++) = SSL_TLSEXT_HB_ENABLED;

    }



    next_proto_neg_seen = s->s3->next_proto_neg_seen;
    s->s3->next_proto_neg_seen = 0;
    if (next_proto_neg_seen && s->ctx->next_protos_advertised_cb) {
        const unsigned char *npa;
        unsigned int npalen;
        int r;

        r = s->ctx->next_protos_advertised_cb(s, &npa, &npalen, s-> ctx->next_protos_advertised_cb_arg);

        if (r == SSL_TLSEXT_ERR_OK) {
            if ((long)(limit - ret - 4 - npalen) < 0)
                return NULL;
            s2n(TLSEXT_TYPE_next_proto_neg, ret);
            s2n(npalen, ret);
            memcpy(ret, npa, npalen);
            ret += npalen;
            s->s3->next_proto_neg_seen = 1;
        }
    }

    if (!custom_ext_add(s, 1, &ret, limit, al))
        return NULL;

    if (s->s3->flags & TLS1_FLAGS_ENCRYPT_THEN_MAC) {
        
        if (s->s3->tmp.new_cipher->algorithm_mac == SSL_AEAD || s->s3->tmp.new_cipher->algorithm_enc == SSL_RC4)
            s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;
        else {
            s2n(TLSEXT_TYPE_encrypt_then_mac, ret);
            s2n(0, ret);
        }
    }

    if (!s->hit && s->session->flags & SSL_SESS_FLAG_EXTMS) {
        s2n(TLSEXT_TYPE_extended_master_secret, ret);
        s2n(0, ret);
    }

    if (s->s3->alpn_selected) {
        const unsigned char *selected = s->s3->alpn_selected;
        unsigned len = s->s3->alpn_selected_len;

        if ((long)(limit - ret - 4 - 2 - 1 - len) < 0)
            return NULL;
        s2n(TLSEXT_TYPE_application_layer_protocol_negotiation, ret);
        s2n(3 + len, ret);
        s2n(1 + len, ret);
        *ret++ = len;
        memcpy(ret, selected, len);
        ret += len;
    }

 done:

    if ((extdatalen = ret - orig - 2) == 0)
        return orig;

    s2n(extdatalen, orig);
    return ret;
}


static int tls1_alpn_handle_client_hello(SSL *s, const unsigned char *data, unsigned data_len, int *al)
{
    unsigned i;
    unsigned proto_len;
    const unsigned char *selected;
    unsigned char selected_len;
    int r;

    if (s->ctx->alpn_select_cb == NULL)
        return 0;

    if (data_len < 2)
        goto parse_error;

    
    i = ((unsigned)data[0]) << 8 | ((unsigned)data[1]);
    data_len -= 2;
    data += 2;
    if (data_len != i)
        goto parse_error;

    if (data_len < 2)
        goto parse_error;

    for (i = 0; i < data_len;) {
        proto_len = data[i];
        i++;

        if (proto_len == 0)
            goto parse_error;

        if (i + proto_len < i || i + proto_len > data_len)
            goto parse_error;

        i += proto_len;
    }

    r = s->ctx->alpn_select_cb(s, &selected, &selected_len, data, data_len, s->ctx->alpn_select_cb_arg);
    if (r == SSL_TLSEXT_ERR_OK) {
        if (s->s3->alpn_selected)
            OPENSSL_free(s->s3->alpn_selected);
        s->s3->alpn_selected = OPENSSL_malloc(selected_len);
        if (!s->s3->alpn_selected) {
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }
        memcpy(s->s3->alpn_selected, selected, selected_len);
        s->s3->alpn_selected_len = selected_len;
    }
    return 0;

 parse_error:
    *al = SSL_AD_DECODE_ERROR;
    return -1;
}



static void ssl_check_for_safari(SSL *s, const unsigned char *data, const unsigned char *d, int n)
{
    unsigned short type, size;
    static const unsigned char kSafariExtensionsBlock[] = {
        0x00, 0x0a,              0x00, 0x08, 0x00, 0x06, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,  0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, };











    
    static const unsigned char kSafariTLS12ExtensionsBlock[] = {
        0x00, 0x0d,              0x00, 0x0c, 0x00, 0x0a, 0x05, 0x01, 0x04, 0x01, 0x02, 0x01, 0x04, 0x03, 0x02, 0x03, };








    if (data >= (d + n - 2))
        return;
    data += 2;

    if (data > (d + n - 4))
        return;
    n2s(data, type);
    n2s(data, size);

    if (type != TLSEXT_TYPE_server_name)
        return;

    if (data + size > d + n)
        return;
    data += size;

    if (TLS1_get_client_version(s) >= TLS1_2_VERSION) {
        const size_t len1 = sizeof(kSafariExtensionsBlock);
        const size_t len2 = sizeof(kSafariTLS12ExtensionsBlock);

        if (data + len1 + len2 != d + n)
            return;
        if (memcmp(data, kSafariExtensionsBlock, len1) != 0)
            return;
        if (memcmp(data + len1, kSafariTLS12ExtensionsBlock, len2) != 0)
            return;
    } else {
        const size_t len = sizeof(kSafariExtensionsBlock);

        if (data + len != d + n)
            return;
        if (memcmp(data, kSafariExtensionsBlock, len) != 0)
            return;
    }

    s->s3->is_probably_safari = 1;
}


static int ssl_scan_clienthello_tlsext(SSL *s, unsigned char **p, unsigned char *d, int n, int *al)
{
    unsigned short type;
    unsigned short size;
    unsigned short len;
    unsigned char *data = *p;
    int renegotiate_seen = 0;

    s->servername_done = 0;
    s->tlsext_status_type = -1;

    s->s3->next_proto_neg_seen = 0;


    if (s->s3->alpn_selected) {
        OPENSSL_free(s->s3->alpn_selected);
        s->s3->alpn_selected = NULL;
    }

    s->tlsext_heartbeat &= ~(SSL_TLSEXT_HB_ENABLED | SSL_TLSEXT_HB_DONT_SEND_REQUESTS);



    if (s->options & SSL_OP_SAFARI_ECDHE_ECDSA_BUG)
        ssl_check_for_safari(s, data, d, n);


    
    if (s->cert->peer_sigalgs) {
        OPENSSL_free(s->cert->peer_sigalgs);
        s->cert->peer_sigalgs = NULL;
    }

    s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;



    if (s->srp_ctx.login != NULL) {
        OPENSSL_free(s->srp_ctx.login);
        s->srp_ctx.login = NULL;
    }


    s->srtp_profile = NULL;

    if (data >= (d + n - 2))
        goto ri_check;
    n2s(data, len);

    if (data > (d + n - len))
        goto ri_check;

    while (data <= (d + n - 4)) {
        n2s(data, type);
        n2s(data, size);

        if (data + size > (d + n))
            goto ri_check;
        if (s->tlsext_debug_cb)
            s->tlsext_debug_cb(s, 0, type, data, size, s->tlsext_debug_arg);
        if (type == TLSEXT_TYPE_renegotiate) {
            if (!ssl_parse_clienthello_renegotiate_ext(s, data, size, al))
                return 0;
            renegotiate_seen = 1;
        } else if (s->version == SSL3_VERSION) {
        }


        else if (type == TLSEXT_TYPE_server_name) {
            unsigned char *sdata;
            int servname_type;
            int dsize;

            if (size < 2) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }
            n2s(data, dsize);
            size -= 2;
            if (dsize > size) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }

            sdata = data;
            while (dsize > 3) {
                servname_type = *(sdata++);
                n2s(sdata, len);
                dsize -= 3;

                if (len > dsize) {
                    *al = SSL_AD_DECODE_ERROR;
                    return 0;
                }
                if (s->servername_done == 0)
                    switch (servname_type) {
                    case TLSEXT_NAMETYPE_host_name:
                        if (!s->hit) {
                            if (s->session->tlsext_hostname) {
                                *al = SSL_AD_DECODE_ERROR;
                                return 0;
                            }
                            if (len > TLSEXT_MAXLEN_host_name) {
                                *al = TLS1_AD_UNRECOGNIZED_NAME;
                                return 0;
                            }
                            if ((s->session->tlsext_hostname = OPENSSL_malloc(len + 1)) == NULL) {
                                *al = TLS1_AD_INTERNAL_ERROR;
                                return 0;
                            }
                            memcpy(s->session->tlsext_hostname, sdata, len);
                            s->session->tlsext_hostname[len] = '\0';
                            if (strlen(s->session->tlsext_hostname) != len) {
                                OPENSSL_free(s->session->tlsext_hostname);
                                s->session->tlsext_hostname = NULL;
                                *al = TLS1_AD_UNRECOGNIZED_NAME;
                                return 0;
                            }
                            s->servername_done = 1;

                        } else s->servername_done = s->session->tlsext_hostname && strlen(s->session->tlsext_hostname) == len && strncmp(s->session->tlsext_hostname, (char *)sdata, len) == 0;




                        break;

                    default:
                        break;
                    }

                dsize -= len;
            }
            if (dsize != 0) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }

        }

        else if (type == TLSEXT_TYPE_srp) {
            if (size <= 0 || ((len = data[0])) != (size - 1)) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }
            if (s->srp_ctx.login != NULL) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }
            if ((s->srp_ctx.login = OPENSSL_malloc(len + 1)) == NULL)
                return -1;
            memcpy(s->srp_ctx.login, &data[1], len);
            s->srp_ctx.login[len] = '\0';

            if (strlen(s->srp_ctx.login) != len) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }
        }



        else if (type == TLSEXT_TYPE_ec_point_formats) {
            unsigned char *sdata = data;
            int ecpointformatlist_length = *(sdata++);

            if (ecpointformatlist_length != size - 1 || ecpointformatlist_length < 1) {
                *al = TLS1_AD_DECODE_ERROR;
                return 0;
            }
            if (!s->hit) {
                if (s->session->tlsext_ecpointformatlist) {
                    OPENSSL_free(s->session->tlsext_ecpointformatlist);
                    s->session->tlsext_ecpointformatlist = NULL;
                }
                s->session->tlsext_ecpointformatlist_length = 0;
                if ((s->session->tlsext_ecpointformatlist = OPENSSL_malloc(ecpointformatlist_length)) == NULL) {
                    *al = TLS1_AD_INTERNAL_ERROR;
                    return 0;
                }
                s->session->tlsext_ecpointformatlist_length = ecpointformatlist_length;
                memcpy(s->session->tlsext_ecpointformatlist, sdata, ecpointformatlist_length);
            }
        } else if (type == TLSEXT_TYPE_elliptic_curves) {
            unsigned char *sdata = data;
            int ellipticcurvelist_length = (*(sdata++) << 8);
            ellipticcurvelist_length += (*(sdata++));

            if (ellipticcurvelist_length != size - 2 || ellipticcurvelist_length < 1 ||  ellipticcurvelist_length & 1) {


                *al = TLS1_AD_DECODE_ERROR;
                return 0;
            }
            if (!s->hit) {
                if (s->session->tlsext_ellipticcurvelist) {
                    *al = TLS1_AD_DECODE_ERROR;
                    return 0;
                }
                s->session->tlsext_ellipticcurvelist_length = 0;
                if ((s->session->tlsext_ellipticcurvelist = OPENSSL_malloc(ellipticcurvelist_length)) == NULL) {
                    *al = TLS1_AD_INTERNAL_ERROR;
                    return 0;
                }
                s->session->tlsext_ellipticcurvelist_length = ellipticcurvelist_length;
                memcpy(s->session->tlsext_ellipticcurvelist, sdata, ellipticcurvelist_length);
            }
        }

        else if (type == TLSEXT_TYPE_session_ticket) {
            if (s->tls_session_ticket_ext_cb && !s->tls_session_ticket_ext_cb(s, data, size, s->tls_session_ticket_ext_cb_arg))

            {
                *al = TLS1_AD_INTERNAL_ERROR;
                return 0;
            }
        } else if (type == TLSEXT_TYPE_signature_algorithms) {
            int dsize;
            if (s->cert->peer_sigalgs || size < 2) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }
            n2s(data, dsize);
            size -= 2;
            if (dsize != size || dsize & 1 || !dsize) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }
            if (!tls1_save_sigalgs(s, data, dsize)) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }
        } else if (type == TLSEXT_TYPE_status_request) {

            if (size < 5) {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }

            s->tlsext_status_type = *data++;
            size--;
            if (s->tlsext_status_type == TLSEXT_STATUSTYPE_ocsp) {
                const unsigned char *sdata;
                int dsize;
                
                n2s(data, dsize);
                size -= 2;
                if (dsize > size) {
                    *al = SSL_AD_DECODE_ERROR;
                    return 0;
                }
                while (dsize > 0) {
                    OCSP_RESPID *id;
                    int idsize;
                    if (dsize < 4) {
                        *al = SSL_AD_DECODE_ERROR;
                        return 0;
                    }
                    n2s(data, idsize);
                    dsize -= 2 + idsize;
                    size -= 2 + idsize;
                    if (dsize < 0) {
                        *al = SSL_AD_DECODE_ERROR;
                        return 0;
                    }
                    sdata = data;
                    data += idsize;
                    id = d2i_OCSP_RESPID(NULL, &sdata, idsize);
                    if (!id) {
                        *al = SSL_AD_DECODE_ERROR;
                        return 0;
                    }
                    if (data != sdata) {
                        OCSP_RESPID_free(id);
                        *al = SSL_AD_DECODE_ERROR;
                        return 0;
                    }
                    if (!s->tlsext_ocsp_ids && !(s->tlsext_ocsp_ids = sk_OCSP_RESPID_new_null())) {

                        OCSP_RESPID_free(id);
                        *al = SSL_AD_INTERNAL_ERROR;
                        return 0;
                    }
                    if (!sk_OCSP_RESPID_push(s->tlsext_ocsp_ids, id)) {
                        OCSP_RESPID_free(id);
                        *al = SSL_AD_INTERNAL_ERROR;
                        return 0;
                    }
                }

                
                if (size < 2) {
                    *al = SSL_AD_DECODE_ERROR;
                    return 0;
                }
                n2s(data, dsize);
                size -= 2;
                if (dsize != size) {
                    *al = SSL_AD_DECODE_ERROR;
                    return 0;
                }
                sdata = data;
                if (dsize > 0) {
                    if (s->tlsext_ocsp_exts) {
                        sk_X509_EXTENSION_pop_free(s->tlsext_ocsp_exts, X509_EXTENSION_free);
                    }

                    s->tlsext_ocsp_exts = d2i_X509_EXTENSIONS(NULL, &sdata, dsize);
                    if (!s->tlsext_ocsp_exts || (data + dsize != sdata)) {
                        *al = SSL_AD_DECODE_ERROR;
                        return 0;
                    }
                }
            }
            
            else s->tlsext_status_type = -1;
        }

        else if (type == TLSEXT_TYPE_heartbeat) {
            switch (data[0]) {
            case 0x01:         
                s->tlsext_heartbeat |= SSL_TLSEXT_HB_ENABLED;
                break;
            case 0x02:         
                s->tlsext_heartbeat |= SSL_TLSEXT_HB_ENABLED;
                s->tlsext_heartbeat |= SSL_TLSEXT_HB_DONT_SEND_REQUESTS;
                break;
            default:
                *al = SSL_AD_ILLEGAL_PARAMETER;
                return 0;
            }
        }


        else if (type == TLSEXT_TYPE_next_proto_neg && s->s3->tmp.finish_md_len == 0 && s->s3->alpn_selected == NULL) {

            
            s->s3->next_proto_neg_seen = 1;
        }


        else if (type == TLSEXT_TYPE_application_layer_protocol_negotiation && s->ctx->alpn_select_cb && s->s3->tmp.finish_md_len == 0) {
            if (tls1_alpn_handle_client_hello(s, data, size, al) != 0)
                return 0;

            
            s->s3->next_proto_neg_seen = 0;

        }

        

        else if (SSL_IS_DTLS(s) && SSL_get_srtp_profiles(s)
                 && type == TLSEXT_TYPE_use_srtp) {
            if (ssl_parse_clienthello_use_srtp_ext(s, data, size, al))
                return 0;
        }


        else if (type == TLSEXT_TYPE_encrypt_then_mac)
            s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC;

        else if (type == TLSEXT_TYPE_extended_master_secret) {
            if (!s->hit)
                s->session->flags |= SSL_SESS_FLAG_EXTMS;
        }
        
        else if (!s->hit) {
            if (custom_ext_parse(s, 1, type, data, size, al) <= 0)
                return 0;
        }

        data += size;
    }

    *p = data;

 ri_check:

    

    if (!renegotiate_seen && s->renegotiate && !(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_SSL_SCAN_CLIENTHELLO_TLSEXT, SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
        return 0;
    }

    return 1;
}

int ssl_parse_clienthello_tlsext(SSL *s, unsigned char **p, unsigned char *d, int n)
{
    int al = -1;
    custom_ext_init(&s->cert->srv_ext);
    if (ssl_scan_clienthello_tlsext(s, p, d, n, &al) <= 0) {
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        return 0;
    }

    if (ssl_check_clienthello_tlsext_early(s) <= 0) {
        SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT, SSL_R_CLIENTHELLO_TLSEXT);
        return 0;
    }
    return 1;
}



static char ssl_next_proto_validate(unsigned char *d, unsigned len)
{
    unsigned int off = 0;

    while (off < len) {
        if (d[off] == 0)
            return 0;
        off += d[off];
        off++;
    }

    return off == len;
}


static int ssl_scan_serverhello_tlsext(SSL *s, unsigned char **p, unsigned char *d, int n, int *al)
{
    unsigned short length;
    unsigned short type;
    unsigned short size;
    unsigned char *data = *p;
    int tlsext_servername = 0;
    int renegotiate_seen = 0;


    s->s3->next_proto_neg_seen = 0;

    s->tlsext_ticket_expected = 0;

    if (s->s3->alpn_selected) {
        OPENSSL_free(s->s3->alpn_selected);
        s->s3->alpn_selected = NULL;
    }

    s->tlsext_heartbeat &= ~(SSL_TLSEXT_HB_ENABLED | SSL_TLSEXT_HB_DONT_SEND_REQUESTS);



    s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;


    if (data >= (d + n - 2))
        goto ri_check;

    n2s(data, length);
    if (data + length != d + n) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    while (data <= (d + n - 4)) {
        n2s(data, type);
        n2s(data, size);

        if (data + size > (d + n))
            goto ri_check;

        if (s->tlsext_debug_cb)
            s->tlsext_debug_cb(s, 1, type, data, size, s->tlsext_debug_arg);

        if (type == TLSEXT_TYPE_renegotiate) {
            if (!ssl_parse_serverhello_renegotiate_ext(s, data, size, al))
                return 0;
            renegotiate_seen = 1;
        } else if (s->version == SSL3_VERSION) {
        } else if (type == TLSEXT_TYPE_server_name) {
            if (s->tlsext_hostname == NULL || size > 0) {
                *al = TLS1_AD_UNRECOGNIZED_NAME;
                return 0;
            }
            tlsext_servername = 1;
        }

        else if (type == TLSEXT_TYPE_ec_point_formats) {
            unsigned char *sdata = data;
            int ecpointformatlist_length = *(sdata++);

            if (ecpointformatlist_length != size - 1) {
                *al = TLS1_AD_DECODE_ERROR;
                return 0;
            }
            if (!s->hit) {
                s->session->tlsext_ecpointformatlist_length = 0;
                if (s->session->tlsext_ecpointformatlist != NULL)
                    OPENSSL_free(s->session->tlsext_ecpointformatlist);
                if ((s->session->tlsext_ecpointformatlist = OPENSSL_malloc(ecpointformatlist_length)) == NULL) {
                    *al = TLS1_AD_INTERNAL_ERROR;
                    return 0;
                }
                s->session->tlsext_ecpointformatlist_length = ecpointformatlist_length;
                memcpy(s->session->tlsext_ecpointformatlist, sdata, ecpointformatlist_length);
            }
        }


        else if (type == TLSEXT_TYPE_session_ticket) {
            if (s->tls_session_ticket_ext_cb && !s->tls_session_ticket_ext_cb(s, data, size, s->tls_session_ticket_ext_cb_arg))

            {
                *al = TLS1_AD_INTERNAL_ERROR;
                return 0;
            }
            if (!tls_use_ticket(s) || (size > 0)) {
                *al = TLS1_AD_UNSUPPORTED_EXTENSION;
                return 0;
            }
            s->tlsext_ticket_expected = 1;
        }
        else if (type == TLSEXT_TYPE_status_request) {
            
            if ((s->tlsext_status_type == -1) || (size > 0)) {
                *al = TLS1_AD_UNSUPPORTED_EXTENSION;
                return 0;
            }
            
            s->tlsext_status_expected = 1;
        }

        else if (type == TLSEXT_TYPE_next_proto_neg && s->s3->tmp.finish_md_len == 0) {
            unsigned char *selected;
            unsigned char selected_len;

            
            if (s->ctx->next_proto_select_cb == NULL) {
                *al = TLS1_AD_UNSUPPORTED_EXTENSION;
                return 0;
            }
            
            if (!ssl_next_proto_validate(data, size)) {
                *al = TLS1_AD_DECODE_ERROR;
                return 0;
            }
            if (s-> ctx->next_proto_select_cb(s, &selected, &selected_len, data, size, s->ctx->next_proto_select_cb_arg) != SSL_TLSEXT_ERR_OK) {



                *al = TLS1_AD_INTERNAL_ERROR;
                return 0;
            }
            s->next_proto_negotiated = OPENSSL_malloc(selected_len);
            if (!s->next_proto_negotiated) {
                *al = TLS1_AD_INTERNAL_ERROR;
                return 0;
            }
            memcpy(s->next_proto_negotiated, selected, selected_len);
            s->next_proto_negotiated_len = selected_len;
            s->s3->next_proto_neg_seen = 1;
        }


        else if (type == TLSEXT_TYPE_application_layer_protocol_negotiation) {
            unsigned len;

            
            if (s->alpn_client_proto_list == NULL) {
                *al = TLS1_AD_UNSUPPORTED_EXTENSION;
                return 0;
            }
            if (size < 4) {
                *al = TLS1_AD_DECODE_ERROR;
                return 0;
            }
            
            len = data[0];
            len <<= 8;
            len |= data[1];
            if (len != (unsigned)size - 2) {
                *al = TLS1_AD_DECODE_ERROR;
                return 0;
            }
            len = data[2];
            if (len != (unsigned)size - 3) {
                *al = TLS1_AD_DECODE_ERROR;
                return 0;
            }
            if (s->s3->alpn_selected)
                OPENSSL_free(s->s3->alpn_selected);
            s->s3->alpn_selected = OPENSSL_malloc(len);
            if (!s->s3->alpn_selected) {
                *al = TLS1_AD_INTERNAL_ERROR;
                return 0;
            }
            memcpy(s->s3->alpn_selected, data + 3, len);
            s->s3->alpn_selected_len = len;
        }

        else if (type == TLSEXT_TYPE_heartbeat) {
            switch (data[0]) {
            case 0x01:         
                s->tlsext_heartbeat |= SSL_TLSEXT_HB_ENABLED;
                break;
            case 0x02:         
                s->tlsext_heartbeat |= SSL_TLSEXT_HB_ENABLED;
                s->tlsext_heartbeat |= SSL_TLSEXT_HB_DONT_SEND_REQUESTS;
                break;
            default:
                *al = SSL_AD_ILLEGAL_PARAMETER;
                return 0;
            }
        }


        else if (SSL_IS_DTLS(s) && type == TLSEXT_TYPE_use_srtp) {
            if (ssl_parse_serverhello_use_srtp_ext(s, data, size, al))
                return 0;
        }


        else if (type == TLSEXT_TYPE_encrypt_then_mac) {
            
            if (s->s3->tmp.new_cipher->algorithm_mac != SSL_AEAD && s->s3->tmp.new_cipher->algorithm_enc != SSL_RC4)
                s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC;
        }

        else if (type == TLSEXT_TYPE_extended_master_secret) {
            if (!s->hit)
                s->session->flags |= SSL_SESS_FLAG_EXTMS;
        }
        
        else if (custom_ext_parse(s, 0, type, data, size, al) <= 0)
            return 0;

        data += size;
    }

    if (data != d + n) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    if (!s->hit && tlsext_servername == 1) {
        if (s->tlsext_hostname) {
            if (s->session->tlsext_hostname == NULL) {
                s->session->tlsext_hostname = BUF_strdup(s->tlsext_hostname);
                if (!s->session->tlsext_hostname) {
                    *al = SSL_AD_UNRECOGNIZED_NAME;
                    return 0;
                }
            } else {
                *al = SSL_AD_DECODE_ERROR;
                return 0;
            }
        }
    }

    *p = data;

 ri_check:

    
    if (!renegotiate_seen && !(s->options & SSL_OP_LEGACY_SERVER_CONNECT)
        && !(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_SSL_SCAN_SERVERHELLO_TLSEXT, SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
        return 0;
    }

    return 1;
}

int ssl_prepare_clienthello_tlsext(SSL *s)
{

    return 1;
}

int ssl_prepare_serverhello_tlsext(SSL *s)
{
    return 1;
}

static int ssl_check_clienthello_tlsext_early(SSL *s)
{
    int ret = SSL_TLSEXT_ERR_NOACK;
    int al = SSL_AD_UNRECOGNIZED_NAME;


    
    


    if (s->ctx != NULL && s->ctx->tlsext_servername_callback != 0)
        ret = s->ctx->tlsext_servername_callback(s, &al, s->ctx->tlsext_servername_arg);

    else if (s->initial_ctx != NULL && s->initial_ctx->tlsext_servername_callback != 0)
        ret = s->initial_ctx->tlsext_servername_callback(s, &al, s-> initial_ctx->tlsext_servername_arg);



    switch (ret) {
    case SSL_TLSEXT_ERR_ALERT_FATAL:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        return -1;

    case SSL_TLSEXT_ERR_ALERT_WARNING:
        ssl3_send_alert(s, SSL3_AL_WARNING, al);
        return 1;

    case SSL_TLSEXT_ERR_NOACK:
        s->servername_done = 0;
    default:
        return 1;
    }
}

int tls1_set_server_sigalgs(SSL *s)
{
    int al;
    size_t i;
    
    if (s->cert->shared_sigalgs) {
        OPENSSL_free(s->cert->shared_sigalgs);
        s->cert->shared_sigalgs = NULL;
    }
    
    for (i = 0; i < SSL_PKEY_NUM; i++) {
        s->cert->pkeys[i].digest = NULL;
        s->cert->pkeys[i].valid_flags = 0;
    }

    
    if (s->cert->peer_sigalgs) {
        if (!tls1_process_sigalgs(s)) {
            SSLerr(SSL_F_TLS1_SET_SERVER_SIGALGS, ERR_R_MALLOC_FAILURE);
            al = SSL_AD_INTERNAL_ERROR;
            goto err;
        }
        
        if (!s->cert->shared_sigalgs) {
            SSLerr(SSL_F_TLS1_SET_SERVER_SIGALGS, SSL_R_NO_SHARED_SIGATURE_ALGORITHMS);
            al = SSL_AD_ILLEGAL_PARAMETER;
            goto err;
        }
    } else ssl_cert_set_default_md(s->cert);
    return 1;
 err:
    ssl3_send_alert(s, SSL3_AL_FATAL, al);
    return 0;
}

int ssl_check_clienthello_tlsext_late(SSL *s)
{
    int ret = SSL_TLSEXT_ERR_OK;
    int al;

    
    if ((s->tlsext_status_type != -1) && s->ctx && s->ctx->tlsext_status_cb) {
        int r;
        CERT_PKEY *certpkey;
        certpkey = ssl_get_server_send_pkey(s);
        
        if (certpkey == NULL) {
            s->tlsext_status_expected = 0;
            return 1;
        }
        
        s->cert->key = certpkey;
        r = s->ctx->tlsext_status_cb(s, s->ctx->tlsext_status_arg);
        switch (r) {
            
        case SSL_TLSEXT_ERR_NOACK:
            s->tlsext_status_expected = 0;
            break;
            
        case SSL_TLSEXT_ERR_OK:
            if (s->tlsext_ocsp_resp)
                s->tlsext_status_expected = 1;
            else s->tlsext_status_expected = 0;
            break;
            
        case SSL_TLSEXT_ERR_ALERT_FATAL:
            ret = SSL_TLSEXT_ERR_ALERT_FATAL;
            al = SSL_AD_INTERNAL_ERROR;
            goto err;
        }
    } else s->tlsext_status_expected = 0;

 err:
    switch (ret) {
    case SSL_TLSEXT_ERR_ALERT_FATAL:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        return -1;

    case SSL_TLSEXT_ERR_ALERT_WARNING:
        ssl3_send_alert(s, SSL3_AL_WARNING, al);
        return 1;

    default:
        return 1;
    }
}

int ssl_check_serverhello_tlsext(SSL *s)
{
    int ret = SSL_TLSEXT_ERR_NOACK;
    int al = SSL_AD_UNRECOGNIZED_NAME;


    
    unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    unsigned long alg_a = s->s3->tmp.new_cipher->algorithm_auth;
    if ((s->tlsext_ecpointformatlist != NULL)
        && (s->tlsext_ecpointformatlist_length > 0)
        && (s->session->tlsext_ecpointformatlist != NULL)
        && (s->session->tlsext_ecpointformatlist_length > 0)
        && ((alg_k & (SSL_kECDHE | SSL_kECDHr | SSL_kECDHe))
            || (alg_a & SSL_aECDSA))) {
        
        size_t i;
        unsigned char *list;
        int found_uncompressed = 0;
        list = s->session->tlsext_ecpointformatlist;
        for (i = 0; i < s->session->tlsext_ecpointformatlist_length; i++) {
            if (*(list++) == TLSEXT_ECPOINTFORMAT_uncompressed) {
                found_uncompressed = 1;
                break;
            }
        }
        if (!found_uncompressed) {
            SSLerr(SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT, SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST);
            return -1;
        }
    }
    ret = SSL_TLSEXT_ERR_OK;


    if (s->ctx != NULL && s->ctx->tlsext_servername_callback != 0)
        ret = s->ctx->tlsext_servername_callback(s, &al, s->ctx->tlsext_servername_arg);

    else if (s->initial_ctx != NULL && s->initial_ctx->tlsext_servername_callback != 0)
        ret = s->initial_ctx->tlsext_servername_callback(s, &al, s-> initial_ctx->tlsext_servername_arg);



    
    if ((s->tlsext_status_type != -1) && !(s->tlsext_status_expected)
        && s->ctx && s->ctx->tlsext_status_cb) {
        int r;
        
        if (s->tlsext_ocsp_resp) {
            OPENSSL_free(s->tlsext_ocsp_resp);
            s->tlsext_ocsp_resp = NULL;
        }
        s->tlsext_ocsp_resplen = -1;
        r = s->ctx->tlsext_status_cb(s, s->ctx->tlsext_status_arg);
        if (r == 0) {
            al = SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
            ret = SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        if (r < 0) {
            al = SSL_AD_INTERNAL_ERROR;
            ret = SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }

    switch (ret) {
    case SSL_TLSEXT_ERR_ALERT_FATAL:
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        return -1;

    case SSL_TLSEXT_ERR_ALERT_WARNING:
        ssl3_send_alert(s, SSL3_AL_WARNING, al);
        return 1;

    case SSL_TLSEXT_ERR_NOACK:
        s->servername_done = 0;
    default:
        return 1;
    }
}

int ssl_parse_serverhello_tlsext(SSL *s, unsigned char **p, unsigned char *d, int n)
{
    int al = -1;
    if (s->version < SSL3_VERSION)
        return 1;
    if (ssl_scan_serverhello_tlsext(s, p, d, n, &al) <= 0) {
        ssl3_send_alert(s, SSL3_AL_FATAL, al);
        return 0;
    }

    if (ssl_check_serverhello_tlsext(s) <= 0) {
        SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT, SSL_R_SERVERHELLO_TLSEXT);
        return 0;
    }
    return 1;
}


int tls1_process_ticket(SSL *s, unsigned char *session_id, int len, const unsigned char *limit, SSL_SESSION **ret)
{
    
    const unsigned char *p = session_id + len;
    unsigned short i;

    *ret = NULL;
    s->tlsext_ticket_expected = 0;

    
    if (!tls_use_ticket(s))
        return 0;
    if ((s->version <= SSL3_VERSION) || !limit)
        return 0;
    if (p >= limit)
        return -1;
    
    if (SSL_IS_DTLS(s)) {
        i = *(p++);
        p += i;
        if (p >= limit)
            return -1;
    }
    
    n2s(p, i);
    p += i;
    if (p >= limit)
        return -1;
    
    i = *(p++);
    p += i;
    if (p > limit)
        return -1;
    
    if ((p + 2) >= limit)
        return 0;
    n2s(p, i);
    while ((p + 4) <= limit) {
        unsigned short type, size;
        n2s(p, type);
        n2s(p, size);
        if (p + size > limit)
            return 0;
        if (type == TLSEXT_TYPE_session_ticket) {
            int r;
            if (size == 0) {
                
                s->tlsext_ticket_expected = 1;
                return 1;
            }
            if (s->tls_session_secret_cb) {
                
                return 2;
            }
            r = tls_decrypt_ticket(s, p, size, session_id, len, ret);
            switch (r) {
            case 2:            
                s->tlsext_ticket_expected = 1;
                return 2;
            case 3:            
                return r;
            case 4:            
                s->tlsext_ticket_expected = 1;
                return 3;
            default:           
                return -1;
            }
        }
        p += size;
    }
    return 0;
}


static int tls_decrypt_ticket(SSL *s, const unsigned char *etick, int eticklen, const unsigned char *sess_id, int sesslen, SSL_SESSION **psess)

{
    SSL_SESSION *sess;
    unsigned char *sdec;
    const unsigned char *p;
    int slen, mlen, renew_ticket = 0;
    unsigned char tick_hmac[EVP_MAX_MD_SIZE];
    HMAC_CTX hctx;
    EVP_CIPHER_CTX ctx;
    SSL_CTX *tctx = s->initial_ctx;
    
    if (eticklen < 48)
        return 2;
    
    HMAC_CTX_init(&hctx);
    EVP_CIPHER_CTX_init(&ctx);
    if (tctx->tlsext_ticket_key_cb) {
        unsigned char *nctick = (unsigned char *)etick;
        int rv = tctx->tlsext_ticket_key_cb(s, nctick, nctick + 16, &ctx, &hctx, 0);
        if (rv < 0)
            return -1;
        if (rv == 0)
            return 2;
        if (rv == 2)
            renew_ticket = 1;
    } else {
        
        if (memcmp(etick, tctx->tlsext_tick_key_name, 16))
            return 2;
        HMAC_Init_ex(&hctx, tctx->tlsext_tick_hmac_key, 16, EVP_sha256(), NULL);
        EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, tctx->tlsext_tick_aes_key, etick + 16);
    }
    
    mlen = HMAC_size(&hctx);
    if (mlen < 0) {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -1;
    }
    eticklen -= mlen;
    
    HMAC_Update(&hctx, etick, eticklen);
    HMAC_Final(&hctx, tick_hmac, NULL);
    HMAC_CTX_cleanup(&hctx);
    if (CRYPTO_memcmp(tick_hmac, etick + eticklen, mlen)) {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 2;
    }
    
    
    p = etick + 16 + EVP_CIPHER_CTX_iv_length(&ctx);
    eticklen -= 16 + EVP_CIPHER_CTX_iv_length(&ctx);
    sdec = OPENSSL_malloc(eticklen);
    if (!sdec) {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return -1;
    }
    EVP_DecryptUpdate(&ctx, sdec, &slen, p, eticklen);
    if (EVP_DecryptFinal(&ctx, sdec + slen, &mlen) <= 0) {
        EVP_CIPHER_CTX_cleanup(&ctx);
        OPENSSL_free(sdec);
        return 2;
    }
    slen += mlen;
    EVP_CIPHER_CTX_cleanup(&ctx);
    p = sdec;

    sess = d2i_SSL_SESSION(NULL, &p, slen);
    OPENSSL_free(sdec);
    if (sess) {
        
        if (sesslen)
            memcpy(sess->session_id, sess_id, sesslen);
        sess->session_id_length = sesslen;
        *psess = sess;
        if (renew_ticket)
            return 4;
        else return 3;
    }
    ERR_clear_error();
    
    return 2;
}



typedef struct {
    int nid;
    int id;
} tls12_lookup;

static const tls12_lookup tls12_md[] = {
    {NID_md5, TLSEXT_hash_md5}, {NID_sha1, TLSEXT_hash_sha1}, {NID_sha224, TLSEXT_hash_sha224}, {NID_sha256, TLSEXT_hash_sha256}, {NID_sha384, TLSEXT_hash_sha384}, {NID_sha512, TLSEXT_hash_sha512}




};

static const tls12_lookup tls12_sig[] = {
    {EVP_PKEY_RSA, TLSEXT_signature_rsa}, {EVP_PKEY_DSA, TLSEXT_signature_dsa}, {EVP_PKEY_EC, TLSEXT_signature_ecdsa}

};

static int tls12_find_id(int nid, const tls12_lookup *table, size_t tlen)
{
    size_t i;
    for (i = 0; i < tlen; i++) {
        if (table[i].nid == nid)
            return table[i].id;
    }
    return -1;
}

static int tls12_find_nid(int id, const tls12_lookup *table, size_t tlen)
{
    size_t i;
    for (i = 0; i < tlen; i++) {
        if ((table[i].id) == id)
            return table[i].nid;
    }
    return NID_undef;
}

int tls12_get_sigandhash(unsigned char *p, const EVP_PKEY *pk, const EVP_MD *md)
{
    int sig_id, md_id;
    if (!md)
        return 0;
    md_id = tls12_find_id(EVP_MD_type(md), tls12_md, sizeof(tls12_md) / sizeof(tls12_lookup));
    if (md_id == -1)
        return 0;
    sig_id = tls12_get_sigid(pk);
    if (sig_id == -1)
        return 0;
    p[0] = (unsigned char)md_id;
    p[1] = (unsigned char)sig_id;
    return 1;
}

int tls12_get_sigid(const EVP_PKEY *pk)
{
    return tls12_find_id(pk->type, tls12_sig, sizeof(tls12_sig) / sizeof(tls12_lookup));
}

typedef struct {
    int nid;
    int secbits;
    const EVP_MD *(*mfunc) (void);
} tls12_hash_info;

static const tls12_hash_info tls12_md_info[] = {

    {NID_md5, 64, 0},  {NID_md5, 64, EVP_md5},  {NID_sha1, 80, EVP_sha1}, {NID_sha224, 112, EVP_sha224}, {NID_sha256, 128, EVP_sha256}, {NID_sha384, 192, EVP_sha384}, {NID_sha512, 256, EVP_sha512}







};

static const tls12_hash_info *tls12_get_hash_info(unsigned char hash_alg)
{
    if (hash_alg == 0)
        return NULL;
    if (hash_alg > sizeof(tls12_md_info) / sizeof(tls12_md_info[0]))
        return NULL;
    return tls12_md_info + hash_alg - 1;
}

const EVP_MD *tls12_get_hash(unsigned char hash_alg)
{
    const tls12_hash_info *inf;
    if (hash_alg == TLSEXT_hash_md5 && FIPS_mode())
        return NULL;
    inf = tls12_get_hash_info(hash_alg);
    if (!inf || !inf->mfunc)
        return NULL;
    return inf->mfunc();
}

static int tls12_get_pkey_idx(unsigned char sig_alg)
{
    switch (sig_alg) {

    case TLSEXT_signature_rsa:
        return SSL_PKEY_RSA_SIGN;


    case TLSEXT_signature_dsa:
        return SSL_PKEY_DSA_SIGN;


    case TLSEXT_signature_ecdsa:
        return SSL_PKEY_ECC;

    }
    return -1;
}


static void tls1_lookup_sigalg(int *phash_nid, int *psign_nid, int *psignhash_nid, const unsigned char *data)
{
    int sign_nid = 0, hash_nid = 0;
    if (!phash_nid && !psign_nid && !psignhash_nid)
        return;
    if (phash_nid || psignhash_nid) {
        hash_nid = tls12_find_nid(data[0], tls12_md, sizeof(tls12_md) / sizeof(tls12_lookup));
        if (phash_nid)
            *phash_nid = hash_nid;
    }
    if (psign_nid || psignhash_nid) {
        sign_nid = tls12_find_nid(data[1], tls12_sig, sizeof(tls12_sig) / sizeof(tls12_lookup));
        if (psign_nid)
            *psign_nid = sign_nid;
    }
    if (psignhash_nid) {
        if (sign_nid && hash_nid)
            OBJ_find_sigid_by_algs(psignhash_nid, hash_nid, sign_nid);
        else *psignhash_nid = NID_undef;
    }
}


static int tls12_sigalg_allowed(SSL *s, int op, const unsigned char *ptmp)
{
    
    const tls12_hash_info *hinf = tls12_get_hash_info(ptmp[0]);
    if (!hinf || !hinf->mfunc)
        return 0;
    
    if (tls12_get_pkey_idx(ptmp[1]) == -1)
        return 0;
    
    return ssl_security(s, op, hinf->secbits, hinf->nid, (void *)ptmp);
}



void ssl_set_sig_mask(unsigned long *pmask_a, SSL *s, int op)
{
    const unsigned char *sigalgs;
    size_t i, sigalgslen;
    int have_rsa = 0, have_dsa = 0, have_ecdsa = 0;
    
    sigalgslen = tls12_get_psigalgs(s, &sigalgs);
    for (i = 0; i < sigalgslen; i += 2, sigalgs += 2) {
        switch (sigalgs[1]) {

        case TLSEXT_signature_rsa:
            if (!have_rsa && tls12_sigalg_allowed(s, op, sigalgs))
                have_rsa = 1;
            break;


        case TLSEXT_signature_dsa:
            if (!have_dsa && tls12_sigalg_allowed(s, op, sigalgs))
                have_dsa = 1;
            break;


        case TLSEXT_signature_ecdsa:
            if (!have_ecdsa && tls12_sigalg_allowed(s, op, sigalgs))
                have_ecdsa = 1;
            break;

        }
    }
    if (!have_rsa)
        *pmask_a |= SSL_aRSA;
    if (!have_dsa)
        *pmask_a |= SSL_aDSS;
    if (!have_ecdsa)
        *pmask_a |= SSL_aECDSA;
}

size_t tls12_copy_sigalgs(SSL *s, unsigned char *out, const unsigned char *psig, size_t psiglen)
{
    unsigned char *tmpout = out;
    size_t i;
    for (i = 0; i < psiglen; i += 2, psig += 2) {
        if (tls12_sigalg_allowed(s, SSL_SECOP_SIGALG_SUPPORTED, psig)) {
            *tmpout++ = psig[0];
            *tmpout++ = psig[1];
        }
    }
    return tmpout - out;
}


static int tls12_shared_sigalgs(SSL *s, TLS_SIGALGS *shsig, const unsigned char *pref, size_t preflen, const unsigned char *allow, size_t allowlen)

{
    const unsigned char *ptmp, *atmp;
    size_t i, j, nmatch = 0;
    for (i = 0, ptmp = pref; i < preflen; i += 2, ptmp += 2) {
        
        if (!tls12_sigalg_allowed(s, SSL_SECOP_SIGALG_SHARED, ptmp))
            continue;
        for (j = 0, atmp = allow; j < allowlen; j += 2, atmp += 2) {
            if (ptmp[0] == atmp[0] && ptmp[1] == atmp[1]) {
                nmatch++;
                if (shsig) {
                    shsig->rhash = ptmp[0];
                    shsig->rsign = ptmp[1];
                    tls1_lookup_sigalg(&shsig->hash_nid, &shsig->sign_nid, &shsig->signandhash_nid, ptmp);

                    shsig++;
                }
                break;
            }
        }
    }
    return nmatch;
}


static int tls1_set_shared_sigalgs(SSL *s)
{
    const unsigned char *pref, *allow, *conf;
    size_t preflen, allowlen, conflen;
    size_t nmatch;
    TLS_SIGALGS *salgs = NULL;
    CERT *c = s->cert;
    unsigned int is_suiteb = tls1_suiteb(s);
    if (c->shared_sigalgs) {
        OPENSSL_free(c->shared_sigalgs);
        c->shared_sigalgs = NULL;
    }
    
    if (!s->server && c->client_sigalgs && !is_suiteb) {
        conf = c->client_sigalgs;
        conflen = c->client_sigalgslen;
    } else if (c->conf_sigalgs && !is_suiteb) {
        conf = c->conf_sigalgs;
        conflen = c->conf_sigalgslen;
    } else conflen = tls12_get_psigalgs(s, &conf);
    if (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE || is_suiteb) {
        pref = conf;
        preflen = conflen;
        allow = c->peer_sigalgs;
        allowlen = c->peer_sigalgslen;
    } else {
        allow = conf;
        allowlen = conflen;
        pref = c->peer_sigalgs;
        preflen = c->peer_sigalgslen;
    }
    nmatch = tls12_shared_sigalgs(s, NULL, pref, preflen, allow, allowlen);
    if (!nmatch)
        return 1;
    salgs = OPENSSL_malloc(nmatch * sizeof(TLS_SIGALGS));
    if (!salgs)
        return 0;
    nmatch = tls12_shared_sigalgs(s, salgs, pref, preflen, allow, allowlen);
    c->shared_sigalgs = salgs;
    c->shared_sigalgslen = nmatch;
    return 1;
}



int tls1_save_sigalgs(SSL *s, const unsigned char *data, int dsize)
{
    CERT *c = s->cert;
    
    if (!SSL_USE_SIGALGS(s))
        return 1;
    
    if (!c)
        return 0;

    if (c->peer_sigalgs)
        OPENSSL_free(c->peer_sigalgs);
    c->peer_sigalgs = OPENSSL_malloc(dsize);
    if (!c->peer_sigalgs)
        return 0;
    c->peer_sigalgslen = dsize;
    memcpy(c->peer_sigalgs, data, dsize);
    return 1;
}

int tls1_process_sigalgs(SSL *s)
{
    int idx;
    size_t i;
    const EVP_MD *md;
    CERT *c = s->cert;
    TLS_SIGALGS *sigptr;
    if (!tls1_set_shared_sigalgs(s))
        return 0;


    if (s->cert->cert_flags & SSL_CERT_FLAG_BROKEN_PROTOCOL) {
        
        const unsigned char *sigs = NULL;
        if (s->server)
            sigs = c->conf_sigalgs;
        else sigs = c->client_sigalgs;
        if (sigs) {
            idx = tls12_get_pkey_idx(sigs[1]);
            md = tls12_get_hash(sigs[0]);
            c->pkeys[idx].digest = md;
            c->pkeys[idx].valid_flags = CERT_PKEY_EXPLICIT_SIGN;
            if (idx == SSL_PKEY_RSA_SIGN) {
                c->pkeys[SSL_PKEY_RSA_ENC].valid_flags = CERT_PKEY_EXPLICIT_SIGN;
                c->pkeys[SSL_PKEY_RSA_ENC].digest = md;
            }
        }
    }


    for (i = 0, sigptr = c->shared_sigalgs;
         i < c->shared_sigalgslen; i++, sigptr++) {
        idx = tls12_get_pkey_idx(sigptr->rsign);
        if (idx > 0 && c->pkeys[idx].digest == NULL) {
            md = tls12_get_hash(sigptr->rhash);
            c->pkeys[idx].digest = md;
            c->pkeys[idx].valid_flags = CERT_PKEY_EXPLICIT_SIGN;
            if (idx == SSL_PKEY_RSA_SIGN) {
                c->pkeys[SSL_PKEY_RSA_ENC].valid_flags = CERT_PKEY_EXPLICIT_SIGN;
                c->pkeys[SSL_PKEY_RSA_ENC].digest = md;
            }
        }

    }
    
    if (!(s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT)) {
        

        if (!c->pkeys[SSL_PKEY_DSA_SIGN].digest)
            c->pkeys[SSL_PKEY_DSA_SIGN].digest = EVP_sha1();


        if (!c->pkeys[SSL_PKEY_RSA_SIGN].digest) {
            c->pkeys[SSL_PKEY_RSA_SIGN].digest = EVP_sha1();
            c->pkeys[SSL_PKEY_RSA_ENC].digest = EVP_sha1();
        }


        if (!c->pkeys[SSL_PKEY_ECC].digest)
            c->pkeys[SSL_PKEY_ECC].digest = EVP_sha1();

    }
    return 1;
}

int SSL_get_sigalgs(SSL *s, int idx, int *psign, int *phash, int *psignhash, unsigned char *rsig, unsigned char *rhash)

{
    const unsigned char *psig = s->cert->peer_sigalgs;
    if (psig == NULL)
        return 0;
    if (idx >= 0) {
        idx <<= 1;
        if (idx >= (int)s->cert->peer_sigalgslen)
            return 0;
        psig += idx;
        if (rhash)
            *rhash = psig[0];
        if (rsig)
            *rsig = psig[1];
        tls1_lookup_sigalg(phash, psign, psignhash, psig);
    }
    return s->cert->peer_sigalgslen / 2;
}

int SSL_get_shared_sigalgs(SSL *s, int idx, int *psign, int *phash, int *psignhash, unsigned char *rsig, unsigned char *rhash)

{
    TLS_SIGALGS *shsigalgs = s->cert->shared_sigalgs;
    if (!shsigalgs || idx >= (int)s->cert->shared_sigalgslen)
        return 0;
    shsigalgs += idx;
    if (phash)
        *phash = shsigalgs->hash_nid;
    if (psign)
        *psign = shsigalgs->sign_nid;
    if (psignhash)
        *psignhash = shsigalgs->signandhash_nid;
    if (rsig)
        *rsig = shsigalgs->rsign;
    if (rhash)
        *rhash = shsigalgs->rhash;
    return s->cert->shared_sigalgslen;
}


int tls1_process_heartbeat(SSL *s)
{
    unsigned char *p = &s->s3->rrec.data[0], *pl;
    unsigned short hbtype;
    unsigned int payload;
    unsigned int padding = 16;  

    if (s->msg_callback)
        s->msg_callback(0, s->version, TLS1_RT_HEARTBEAT, &s->s3->rrec.data[0], s->s3->rrec.length, s, s->msg_callback_arg);


    
    if (1 + 2 + 16 > s->s3->rrec.length)
        return 0;               
    hbtype = *p++;
    n2s(p, payload);
    if (1 + 2 + payload + 16 > s->s3->rrec.length)
        return 0;               
    pl = p;

    if (hbtype == TLS1_HB_REQUEST) {
        unsigned char *buffer, *bp;
        int r;

        
        buffer = OPENSSL_malloc(1 + 2 + payload + padding);
        if (buffer == NULL) {
            SSLerr(SSL_F_TLS1_PROCESS_HEARTBEAT, ERR_R_MALLOC_FAILURE);
            return -1;
        }
        bp = buffer;

        
        *bp++ = TLS1_HB_RESPONSE;
        s2n(payload, bp);
        memcpy(bp, pl, payload);
        bp += payload;
        
        RAND_pseudo_bytes(bp, padding);

        r = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding);

        if (r >= 0 && s->msg_callback)
            s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT, buffer, 3 + payload + padding, s, s->msg_callback_arg);


        OPENSSL_free(buffer);

        if (r < 0)
            return r;
    } else if (hbtype == TLS1_HB_RESPONSE) {
        unsigned int seq;

        
        n2s(pl, seq);

        if (payload == 18 && seq == s->tlsext_hb_seq) {
            s->tlsext_hb_seq++;
            s->tlsext_hb_pending = 0;
        }
    }

    return 0;
}

int tls1_heartbeat(SSL *s)
{
    unsigned char *buf, *p;
    int ret;
    unsigned int payload = 18;  
    unsigned int padding = 16;  

    
    if (!(s->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED) || s->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_SEND_REQUESTS) {
        SSLerr(SSL_F_TLS1_HEARTBEAT, SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT);
        return -1;
    }

    
    if (s->tlsext_hb_pending) {
        SSLerr(SSL_F_TLS1_HEARTBEAT, SSL_R_TLS_HEARTBEAT_PENDING);
        return -1;
    }

    
    if (SSL_in_init(s) || s->in_handshake) {
        SSLerr(SSL_F_TLS1_HEARTBEAT, SSL_R_UNEXPECTED_MESSAGE);
        return -1;
    }

    
    OPENSSL_assert(payload + padding <= 16381);

    
    buf = OPENSSL_malloc(1 + 2 + payload + padding);
    if (buf == NULL) {
        SSLerr(SSL_F_TLS1_HEARTBEAT, ERR_R_MALLOC_FAILURE);
        return -1;
    }
    p = buf;
    
    *p++ = TLS1_HB_REQUEST;
    
    s2n(payload, p);
    
    s2n(s->tlsext_hb_seq, p);
    
    RAND_pseudo_bytes(p, 16);
    p += 16;
    
    RAND_pseudo_bytes(p, padding);

    ret = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buf, 3 + payload + padding);
    if (ret >= 0) {
        if (s->msg_callback)
            s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT, buf, 3 + payload + padding, s, s->msg_callback_arg);


        s->tlsext_hb_pending = 1;
    }

    OPENSSL_free(buf);

    return ret;
}




typedef struct {
    size_t sigalgcnt;
    int sigalgs[MAX_SIGALGLEN];
} sig_cb_st;

static int sig_cb(const char *elem, int len, void *arg)
{
    sig_cb_st *sarg = arg;
    size_t i;
    char etmp[20], *p;
    int sig_alg, hash_alg;
    if (elem == NULL)
        return 0;
    if (sarg->sigalgcnt == MAX_SIGALGLEN)
        return 0;
    if (len > (int)(sizeof(etmp) - 1))
        return 0;
    memcpy(etmp, elem, len);
    etmp[len] = 0;
    p = strchr(etmp, '+');
    if (!p)
        return 0;
    *p = 0;
    p++;
    if (!*p)
        return 0;

    if (!strcmp(etmp, "RSA"))
        sig_alg = EVP_PKEY_RSA;
    else if (!strcmp(etmp, "DSA"))
        sig_alg = EVP_PKEY_DSA;
    else if (!strcmp(etmp, "ECDSA"))
        sig_alg = EVP_PKEY_EC;
    else return 0;

    hash_alg = OBJ_sn2nid(p);
    if (hash_alg == NID_undef)
        hash_alg = OBJ_ln2nid(p);
    if (hash_alg == NID_undef)
        return 0;

    for (i = 0; i < sarg->sigalgcnt; i += 2) {
        if (sarg->sigalgs[i] == sig_alg && sarg->sigalgs[i + 1] == hash_alg)
            return 0;
    }
    sarg->sigalgs[sarg->sigalgcnt++] = hash_alg;
    sarg->sigalgs[sarg->sigalgcnt++] = sig_alg;
    return 1;
}


int tls1_set_sigalgs_list(CERT *c, const char *str, int client)
{
    sig_cb_st sig;
    sig.sigalgcnt = 0;
    if (!CONF_parse_list(str, ':', 1, sig_cb, &sig))
        return 0;
    if (c == NULL)
        return 1;
    return tls1_set_sigalgs(c, sig.sigalgs, sig.sigalgcnt, client);
}

int tls1_set_sigalgs(CERT *c, const int *psig_nids, size_t salglen, int client)
{
    unsigned char *sigalgs, *sptr;
    int rhash, rsign;
    size_t i;
    if (salglen & 1)
        return 0;
    sigalgs = OPENSSL_malloc(salglen);
    if (sigalgs == NULL)
        return 0;
    for (i = 0, sptr = sigalgs; i < salglen; i += 2) {
        rhash = tls12_find_id(*psig_nids++, tls12_md, sizeof(tls12_md) / sizeof(tls12_lookup));
        rsign = tls12_find_id(*psig_nids++, tls12_sig, sizeof(tls12_sig) / sizeof(tls12_lookup));

        if (rhash == -1 || rsign == -1)
            goto err;
        *sptr++ = rhash;
        *sptr++ = rsign;
    }

    if (client) {
        if (c->client_sigalgs)
            OPENSSL_free(c->client_sigalgs);
        c->client_sigalgs = sigalgs;
        c->client_sigalgslen = salglen;
    } else {
        if (c->conf_sigalgs)
            OPENSSL_free(c->conf_sigalgs);
        c->conf_sigalgs = sigalgs;
        c->conf_sigalgslen = salglen;
    }

    return 1;

 err:
    OPENSSL_free(sigalgs);
    return 0;
}

static int tls1_check_sig_alg(CERT *c, X509 *x, int default_nid)
{
    int sig_nid;
    size_t i;
    if (default_nid == -1)
        return 1;
    sig_nid = X509_get_signature_nid(x);
    if (default_nid)
        return sig_nid == default_nid ? 1 : 0;
    for (i = 0; i < c->shared_sigalgslen; i++)
        if (sig_nid == c->shared_sigalgs[i].signandhash_nid)
            return 1;
    return 0;
}


static int ssl_check_ca_name(STACK_OF(X509_NAME) *names, X509 *x)
{
    X509_NAME *nm;
    int i;
    nm = X509_get_issuer_name(x);
    for (i = 0; i < sk_X509_NAME_num(names); i++) {
        if (!X509_NAME_cmp(nm, sk_X509_NAME_value(names, i)))
            return 1;
    }
    return 0;
}










int tls1_check_chain(SSL *s, X509 *x, EVP_PKEY *pk, STACK_OF(X509) *chain, int idx)
{
    int i;
    int rv = 0;
    int check_flags = 0, strict_mode;
    CERT_PKEY *cpk = NULL;
    CERT *c = s->cert;
    unsigned int suiteb_flags = tls1_suiteb(s);
    
    if (idx != -1) {
        
        if (idx == -2) {
            cpk = c->key;
            idx = cpk - c->pkeys;
        } else cpk = c->pkeys + idx;
        x = cpk->x509;
        pk = cpk->privatekey;
        chain = cpk->chain;
        strict_mode = c->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT;
        
        if (!x || !pk)
            goto end;

        
        if (s->cert->cert_flags & SSL_CERT_FLAG_BROKEN_PROTOCOL) {
            rv = CERT_PKEY_STRICT_FLAGS | CERT_PKEY_EXPLICIT_SIGN | CERT_PKEY_VALID | CERT_PKEY_SIGN;
            cpk->valid_flags = rv;
            return rv;
        }

    } else {
        if (!x || !pk)
            return 0;
        idx = ssl_cert_type(x, pk);
        if (idx == -1)
            return 0;
        cpk = c->pkeys + idx;
        if (c->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT)
            check_flags = CERT_PKEY_STRICT_FLAGS;
        else check_flags = CERT_PKEY_VALID_FLAGS;
        strict_mode = 1;
    }

    if (suiteb_flags) {
        int ok;
        if (check_flags)
            check_flags |= CERT_PKEY_SUITEB;
        ok = X509_chain_check_suiteb(NULL, x, chain, suiteb_flags);
        if (ok == X509_V_OK)
            rv |= CERT_PKEY_SUITEB;
        else if (!check_flags)
            goto end;
    }

    
    if (TLS1_get_version(s) >= TLS1_2_VERSION && strict_mode) {
        int default_nid;
        unsigned char rsign = 0;
        if (c->peer_sigalgs)
            default_nid = 0;
        
        else {
            switch (idx) {
            case SSL_PKEY_RSA_ENC:
            case SSL_PKEY_RSA_SIGN:
            case SSL_PKEY_DH_RSA:
                rsign = TLSEXT_signature_rsa;
                default_nid = NID_sha1WithRSAEncryption;
                break;

            case SSL_PKEY_DSA_SIGN:
            case SSL_PKEY_DH_DSA:
                rsign = TLSEXT_signature_dsa;
                default_nid = NID_dsaWithSHA1;
                break;

            case SSL_PKEY_ECC:
                rsign = TLSEXT_signature_ecdsa;
                default_nid = NID_ecdsa_with_SHA1;
                break;

            default:
                default_nid = -1;
                break;
            }
        }
        
        if (default_nid > 0 && c->conf_sigalgs) {
            size_t j;
            const unsigned char *p = c->conf_sigalgs;
            for (j = 0; j < c->conf_sigalgslen; j += 2, p += 2) {
                if (p[0] == TLSEXT_hash_sha1 && p[1] == rsign)
                    break;
            }
            if (j == c->conf_sigalgslen) {
                if (check_flags)
                    goto skip_sigs;
                else goto end;
            }
        }
        
        if (!tls1_check_sig_alg(c, x, default_nid)) {
            if (!check_flags)
                goto end;
        } else rv |= CERT_PKEY_EE_SIGNATURE;
        rv |= CERT_PKEY_CA_SIGNATURE;
        for (i = 0; i < sk_X509_num(chain); i++) {
            if (!tls1_check_sig_alg(c, sk_X509_value(chain, i), default_nid)) {
                if (check_flags) {
                    rv &= ~CERT_PKEY_CA_SIGNATURE;
                    break;
                } else goto end;
            }
        }
    }
    
    else if (check_flags)
        rv |= CERT_PKEY_EE_SIGNATURE | CERT_PKEY_CA_SIGNATURE;
 skip_sigs:
    
    if (tls1_check_cert_param(s, x, check_flags ? 1 : 2))
        rv |= CERT_PKEY_EE_PARAM;
    else if (!check_flags)
        goto end;
    if (!s->server)
        rv |= CERT_PKEY_CA_PARAM;
    
    else if (strict_mode) {
        rv |= CERT_PKEY_CA_PARAM;
        for (i = 0; i < sk_X509_num(chain); i++) {
            X509 *ca = sk_X509_value(chain, i);
            if (!tls1_check_cert_param(s, ca, 0)) {
                if (check_flags) {
                    rv &= ~CERT_PKEY_CA_PARAM;
                    break;
                } else goto end;
            }
        }
    }
    if (!s->server && strict_mode) {
        STACK_OF(X509_NAME) *ca_dn;
        int check_type = 0;
        switch (pk->type) {
        case EVP_PKEY_RSA:
            check_type = TLS_CT_RSA_SIGN;
            break;
        case EVP_PKEY_DSA:
            check_type = TLS_CT_DSS_SIGN;
            break;
        case EVP_PKEY_EC:
            check_type = TLS_CT_ECDSA_SIGN;
            break;
        case EVP_PKEY_DH:
        case EVP_PKEY_DHX:
            {
                int cert_type = X509_certificate_type(x, pk);
                if (cert_type & EVP_PKS_RSA)
                    check_type = TLS_CT_RSA_FIXED_DH;
                if (cert_type & EVP_PKS_DSA)
                    check_type = TLS_CT_DSS_FIXED_DH;
            }
        }
        if (check_type) {
            const unsigned char *ctypes;
            int ctypelen;
            if (c->ctypes) {
                ctypes = c->ctypes;
                ctypelen = (int)c->ctype_num;
            } else {
                ctypes = (unsigned char *)s->s3->tmp.ctype;
                ctypelen = s->s3->tmp.ctype_num;
            }
            for (i = 0; i < ctypelen; i++) {
                if (ctypes[i] == check_type) {
                    rv |= CERT_PKEY_CERT_TYPE;
                    break;
                }
            }
            if (!(rv & CERT_PKEY_CERT_TYPE) && !check_flags)
                goto end;
        } else rv |= CERT_PKEY_CERT_TYPE;

        ca_dn = s->s3->tmp.ca_names;

        if (!sk_X509_NAME_num(ca_dn))
            rv |= CERT_PKEY_ISSUER_NAME;

        if (!(rv & CERT_PKEY_ISSUER_NAME)) {
            if (ssl_check_ca_name(ca_dn, x))
                rv |= CERT_PKEY_ISSUER_NAME;
        }
        if (!(rv & CERT_PKEY_ISSUER_NAME)) {
            for (i = 0; i < sk_X509_num(chain); i++) {
                X509 *xtmp = sk_X509_value(chain, i);
                if (ssl_check_ca_name(ca_dn, xtmp)) {
                    rv |= CERT_PKEY_ISSUER_NAME;
                    break;
                }
            }
        }
        if (!check_flags && !(rv & CERT_PKEY_ISSUER_NAME))
            goto end;
    } else rv |= CERT_PKEY_ISSUER_NAME | CERT_PKEY_CERT_TYPE;

    if (!check_flags || (rv & check_flags) == check_flags)
        rv |= CERT_PKEY_VALID;

 end:

    if (TLS1_get_version(s) >= TLS1_2_VERSION) {
        if (cpk->valid_flags & CERT_PKEY_EXPLICIT_SIGN)
            rv |= CERT_PKEY_EXPLICIT_SIGN | CERT_PKEY_SIGN;
        else if (cpk->digest)
            rv |= CERT_PKEY_SIGN;
    } else rv |= CERT_PKEY_SIGN | CERT_PKEY_EXPLICIT_SIGN;

    
    if (!check_flags) {
        if (rv & CERT_PKEY_VALID)
            cpk->valid_flags = rv;
        else {
            
            cpk->valid_flags &= CERT_PKEY_EXPLICIT_SIGN;
            return 0;
        }
    }
    return rv;
}


void tls1_set_cert_validity(SSL *s)
{
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_RSA_ENC);
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_RSA_SIGN);
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_DSA_SIGN);
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_DH_RSA);
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_DH_DSA);
    tls1_check_chain(s, NULL, NULL, NULL, SSL_PKEY_ECC);
}


int SSL_check_chain(SSL *s, X509 *x, EVP_PKEY *pk, STACK_OF(X509) *chain)
{
    return tls1_check_chain(s, x, pk, chain, -1);
}




DH *ssl_get_auto_dh(SSL *s)
{
    int dh_secbits = 80;
    if (s->cert->dh_tmp_auto == 2)
        return DH_get_1024_160();
    if (s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) {
        if (s->s3->tmp.new_cipher->strength_bits == 256)
            dh_secbits = 128;
        else dh_secbits = 80;
    } else {
        CERT_PKEY *cpk = ssl_get_server_send_pkey(s);
        dh_secbits = EVP_PKEY_security_bits(cpk->privatekey);
    }

    if (dh_secbits >= 128) {
        DH *dhp = DH_new();
        if (!dhp)
            return NULL;
        dhp->g = BN_new();
        if (dhp->g)
            BN_set_word(dhp->g, 2);
        if (dh_secbits >= 192)
            dhp->p = get_rfc3526_prime_8192(NULL);
        else dhp->p = get_rfc3526_prime_3072(NULL);
        if (!dhp->p || !dhp->g) {
            DH_free(dhp);
            return NULL;
        }
        return dhp;
    }
    if (dh_secbits >= 112)
        return DH_get_2048_224();
    return DH_get_1024_160();
}


static int ssl_security_cert_key(SSL *s, SSL_CTX *ctx, X509 *x, int op)
{
    int secbits;
    EVP_PKEY *pkey = X509_get_pubkey(x);
    if (pkey) {
        secbits = EVP_PKEY_security_bits(pkey);
        EVP_PKEY_free(pkey);
    } else secbits = -1;
    if (s)
        return ssl_security(s, op, secbits, 0, x);
    else return ssl_ctx_security(ctx, op, secbits, 0, x);
}

static int ssl_security_cert_sig(SSL *s, SSL_CTX *ctx, X509 *x, int op)
{
    
    int secbits = -1, md_nid = NID_undef, sig_nid;
    sig_nid = X509_get_signature_nid(x);
    if (sig_nid && OBJ_find_sigid_algs(sig_nid, &md_nid, NULL)) {
        const EVP_MD *md;
        if (md_nid && (md = EVP_get_digestbynid(md_nid)))
            secbits = EVP_MD_size(md) * 4;
    }
    if (s)
        return ssl_security(s, op, secbits, md_nid, x);
    else return ssl_ctx_security(ctx, op, secbits, md_nid, x);
}

int ssl_security_cert(SSL *s, SSL_CTX *ctx, X509 *x, int vfy, int is_ee)
{
    if (vfy)
        vfy = SSL_SECOP_PEER;
    if (is_ee) {
        if (!ssl_security_cert_key(s, ctx, x, SSL_SECOP_EE_KEY | vfy))
            return SSL_R_EE_KEY_TOO_SMALL;
    } else {
        if (!ssl_security_cert_key(s, ctx, x, SSL_SECOP_CA_KEY | vfy))
            return SSL_R_CA_KEY_TOO_SMALL;
    }
    if (!ssl_security_cert_sig(s, ctx, x, SSL_SECOP_CA_MD | vfy))
        return SSL_R_CA_MD_TOO_WEAK;
    return 1;
}



int ssl_security_cert_chain(SSL *s, STACK_OF(X509) *sk, X509 *x, int vfy)
{
    int rv, start_idx, i;
    if (x == NULL) {
        x = sk_X509_value(sk, 0);
        start_idx = 1;
    } else start_idx = 0;

    rv = ssl_security_cert(s, NULL, x, vfy, 1);
    if (rv != 1)
        return rv;

    for (i = start_idx; i < sk_X509_num(sk); i++) {
        x = sk_X509_value(sk, i);
        rv = ssl_security_cert(s, NULL, x, vfy, 0);
        if (rv != 1)
            return rv;
    }
    return 1;
}
