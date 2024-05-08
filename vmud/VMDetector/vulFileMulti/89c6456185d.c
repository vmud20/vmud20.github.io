












static const char S_strtab_error[] = "Cannot modify shared string table in hv_%s";

STATIC void S_more_he(pTHX)
{
    dVAR;
    
    const size_t arena_size = Perl_malloc_good_size(PERL_ARENA_SIZE);
    HE* he = (HE*) Perl_get_arena(aTHX_ arena_size, HE_SVSLOT);
    HE * const heend = &he[arena_size / sizeof(HE) - 1];

    PL_body_roots[HE_SVSLOT] = he;
    while (he < heend) {
	HeNEXT(he) = (HE*)(he + 1);
	he++;
    }
    HeNEXT(he) = 0;
}








STATIC HE* S_new_he(pTHX)
{
    dVAR;
    HE* he;
    void ** const root = &PL_body_roots[HE_SVSLOT];

    if (!*root)
	S_more_he(aTHX);
    he = (HE*) *root;
    assert(he);
    *root = HeNEXT(he);
    return he;
}











STATIC HEK * S_save_hek_flags(const char *str, I32 len, U32 hash, int flags)
{
    const int flags_masked = flags & HVhek_MASK;
    char *k;
    register HEK *hek;

    PERL_ARGS_ASSERT_SAVE_HEK_FLAGS;

    Newx(k, HEK_BASESIZE + len + 2, char);
    hek = (HEK*)k;
    Copy(str, HEK_KEY(hek), len, char);
    HEK_KEY(hek)[len] = 0;
    HEK_LEN(hek) = len;
    HEK_HASH(hek) = hash;
    HEK_FLAGS(hek) = (unsigned char)flags_masked | HVhek_UNSHARED;

    if (flags & HVhek_FREEKEY)
	Safefree(str);
    return hek;
}



void Perl_free_tied_hv_pool(pTHX)
{
    dVAR;
    HE *he = PL_hv_fetch_ent_mh;
    while (he) {
	HE * const ohe = he;
	Safefree(HeKEY_hek(he));
	he = HeNEXT(he);
	del_HE(ohe);
    }
    PL_hv_fetch_ent_mh = NULL;
}


HEK * Perl_hek_dup(pTHX_ HEK *source, CLONE_PARAMS* param)
{
    HEK *shared;

    PERL_ARGS_ASSERT_HEK_DUP;
    PERL_UNUSED_ARG(param);

    if (!source)
	return NULL;

    shared = (HEK*)ptr_table_fetch(PL_ptr_table, source);
    if (shared) {
	
	(void)share_hek_hek(shared);
    }
    else {
	shared = share_hek_flags(HEK_KEY(source), HEK_LEN(source), HEK_HASH(source), HEK_FLAGS(source));

	ptr_table_store(PL_ptr_table, source, shared);
    }
    return shared;
}

HE * Perl_he_dup(pTHX_ const HE *e, bool shared, CLONE_PARAMS* param)
{
    HE *ret;

    PERL_ARGS_ASSERT_HE_DUP;

    if (!e)
	return NULL;
    
    ret = (HE*)ptr_table_fetch(PL_ptr_table, e);
    if (ret)
	return ret;

    
    ret = new_HE();
    ptr_table_store(PL_ptr_table, e, ret);

    HeNEXT(ret) = he_dup(HeNEXT(e),shared, param);
    if (HeKLEN(e) == HEf_SVKEY) {
	char *k;
	Newx(k, HEK_BASESIZE + sizeof(const SV *), char);
	HeKEY_hek(ret) = (HEK*)k;
	HeKEY_sv(ret) = SvREFCNT_inc(sv_dup(HeKEY_sv(e), param));
    }
    else if (shared) {
	
	HEK * const source = HeKEY_hek(e);
	HEK *shared = (HEK*)ptr_table_fetch(PL_ptr_table, source);

	if (shared) {
	    
	    (void)share_hek_hek(shared);
	}
	else {
	    shared = share_hek_flags(HEK_KEY(source), HEK_LEN(source), HEK_HASH(source), HEK_FLAGS(source));

	    ptr_table_store(PL_ptr_table, source, shared);
	}
	HeKEY_hek(ret) = shared;
    }
    else HeKEY_hek(ret) = save_hek_flags(HeKEY(e), HeKLEN(e), HeHASH(e), HeKFLAGS(e));

    HeVAL(ret) = SvREFCNT_inc(sv_dup(HeVAL(e), param));
    return ret;
}


static void S_hv_notallowed(pTHX_ int flags, const char *key, I32 klen, const char *msg)

{
    SV * const sv = sv_newmortal();

    PERL_ARGS_ASSERT_HV_NOTALLOWED;

    if (!(flags & HVhek_FREEKEY)) {
	sv_setpvn(sv, key, klen);
    }
    else {
	
	
	sv_usepvn(sv, (char *) key, klen);
    }
    if (flags & HVhek_UTF8) {
	SvUTF8_on(sv);
    }
    Perl_croak(aTHX_ msg, SVfARG(sv));
}










void * Perl_hv_common_key_len(pTHX_ HV *hv, const char *key, I32 klen_i32, const int action, SV *val, const U32 hash)

{
    STRLEN klen;
    int flags;

    PERL_ARGS_ASSERT_HV_COMMON_KEY_LEN;

    if (klen_i32 < 0) {
	klen = -klen_i32;
	flags = HVhek_UTF8;
    } else {
	klen = klen_i32;
	flags = 0;
    }
    return hv_common(hv, NULL, key, klen, flags, action, val, hash);
}

void * Perl_hv_common(pTHX_ HV *hv, SV *keysv, const char *key, STRLEN klen, int flags, int action, SV *val, register U32 hash)

{
    dVAR;
    XPVHV* xhv;
    HE *entry;
    HE **oentry;
    SV *sv;
    bool is_utf8;
    int masked_flags;
    const int return_svp = action & HV_FETCH_JUST_SV;

    if (!hv)
	return NULL;
    if (SvTYPE(hv) == SVTYPEMASK)
	return NULL;

    assert(SvTYPE(hv) == SVt_PVHV);

    if (SvSMAGICAL(hv) && SvGMAGICAL(hv) && !(action & HV_DISABLE_UVAR_XKEY)) {
	MAGIC* mg;
	if ((mg = mg_find((const SV *)hv, PERL_MAGIC_uvar))) {
	    struct ufuncs * const uf = (struct ufuncs *)mg->mg_ptr;
	    if (uf->uf_set == NULL) {
		SV* obj = mg->mg_obj;

		if (!keysv) {
		    keysv = newSVpvn_flags(key, klen, SVs_TEMP | ((flags & HVhek_UTF8)
					    ? SVf_UTF8 : 0));
		}
		
		mg->mg_obj = keysv;         
		uf->uf_index = action;      
		magic_getuvar(MUTABLE_SV(hv), mg);
		keysv = mg->mg_obj;         
		mg->mg_obj = obj;

		
		hash = 0;
	    }
	}
    }
    if (keysv) {
	if (flags & HVhek_FREEKEY)
	    Safefree(key);
	key = SvPV_const(keysv, klen);
	is_utf8 = (SvUTF8(keysv) != 0);
	if (SvIsCOW_shared_hash(keysv)) {
	    flags = HVhek_KEYCANONICAL | (is_utf8 ? HVhek_UTF8 : 0);
	} else {
	    flags = 0;
	}
    } else {
	is_utf8 = ((flags & HVhek_UTF8) ? TRUE : FALSE);
    }

    if (action & HV_DELETE) {
	return (void *) hv_delete_common(hv, keysv, key, klen, flags | (is_utf8 ? HVhek_UTF8 : 0), action, hash);

    }

    xhv = (XPVHV*)SvANY(hv);
    if (SvMAGICAL(hv)) {
	if (SvRMAGICAL(hv) && !(action & (HV_FETCH_ISSTORE|HV_FETCH_ISEXISTS))) {
	    if (mg_find((const SV *)hv, PERL_MAGIC_tied)
		|| SvGMAGICAL((const SV *)hv))
	    {
		
		if (!keysv) {
		    keysv = newSVpvn_utf8(key, klen, is_utf8);
  		} else {
		    keysv = newSVsv(keysv);
		}
                sv = sv_newmortal();
                mg_copy(MUTABLE_SV(hv), sv, (char *)keysv, HEf_SVKEY);

		
		entry = PL_hv_fetch_ent_mh;
		if (entry)
		    PL_hv_fetch_ent_mh = HeNEXT(entry);
		else {
		    char *k;
		    entry = new_HE();
		    Newx(k, HEK_BASESIZE + sizeof(const SV *), char);
		    HeKEY_hek(entry) = (HEK*)k;
		}
		HeNEXT(entry) = NULL;
		HeSVKEY_set(entry, keysv);
		HeVAL(entry) = sv;
		sv_upgrade(sv, SVt_PVLV);
		LvTYPE(sv) = 'T';
		 
		LvTARG(sv) = MUTABLE_SV(entry);

		
		if (flags & HVhek_FREEKEY)
		    Safefree(key);

		if (return_svp) {
		    return entry ? (void *) &HeVAL(entry) : NULL;
		}
		return (void *) entry;
	    }

	    else if (mg_find((const SV *)hv, PERL_MAGIC_env)) {
		U32 i;
		for (i = 0; i < klen; ++i)
		    if (isLOWER(key[i])) {
			
			const char * const nkey = strupr(savepvn(key,klen));
			
			void *result = hv_common(hv, NULL, nkey, klen, HVhek_FREEKEY, 0 | HV_DISABLE_UVAR_XKEY | return_svp, NULL , 0 );





			if (!result && (action & HV_FETCH_LVALUE)) {
			    
			    result = hv_common(hv, keysv, key, klen, flags, HV_FETCH_ISSTORE | HV_DISABLE_UVAR_XKEY | return_svp, newSV(0), hash);



			} else {
			    if (flags & HVhek_FREEKEY)
				Safefree(key);
			}
			return result;
		    }
	    }

	} 
	else if (SvRMAGICAL(hv) && (action & HV_FETCH_ISEXISTS)) {
	    if (mg_find((const SV *)hv, PERL_MAGIC_tied)
		|| SvGMAGICAL((const SV *)hv)) {
		
		SV * const svret = sv_newmortal();
		sv = sv_newmortal();

		if (keysv || is_utf8) {
		    if (!keysv) {
			keysv = newSVpvn_utf8(key, klen, TRUE);
		    } else {
			keysv = newSVsv(keysv);
		    }
		    mg_copy(MUTABLE_SV(hv), sv, (char *)sv_2mortal(keysv), HEf_SVKEY);
		} else {
		    mg_copy(MUTABLE_SV(hv), sv, key, klen);
		}
		if (flags & HVhek_FREEKEY)
		    Safefree(key);
		magic_existspack(svret, mg_find(sv, PERL_MAGIC_tiedelem));
		
		return SvTRUE(svret) ? (void *)hv : NULL;
		}

	    else if (mg_find((const SV *)hv, PERL_MAGIC_env)) {
		
		char * const keysave = (char * const)key;
		
		key = savepvn(key,klen);
		key = (const char*)strupr((char*)key);
		is_utf8 = FALSE;
		hash = 0;
		keysv = 0;

		if (flags & HVhek_FREEKEY) {
		    Safefree(keysave);
		}
		flags |= HVhek_FREEKEY;
	    }

	} 
	else if (action & HV_FETCH_ISSTORE) {
	    bool needs_copy;
	    bool needs_store;
	    hv_magic_check (hv, &needs_copy, &needs_store);
	    if (needs_copy) {
		const bool save_taint = PL_tainted;
		if (keysv || is_utf8) {
		    if (!keysv) {
			keysv = newSVpvn_utf8(key, klen, TRUE);
		    }
		    if (PL_tainting)
			PL_tainted = SvTAINTED(keysv);
		    keysv = sv_2mortal(newSVsv(keysv));
		    mg_copy(MUTABLE_SV(hv), val, (char*)keysv, HEf_SVKEY);
		} else {
		    mg_copy(MUTABLE_SV(hv), val, key, klen);
		}

		TAINT_IF(save_taint);
		if (!needs_store) {
		    if (flags & HVhek_FREEKEY)
			Safefree(key);
		    return NULL;
		}

		else if (mg_find((const SV *)hv, PERL_MAGIC_env)) {
		    
		    const char *keysave = key;
		    
		    key = savepvn(key,klen);
		    key = (const char*)strupr((char*)key);
		    is_utf8 = FALSE;
		    hash = 0;
		    keysv = 0;

		    if (flags & HVhek_FREEKEY) {
			Safefree(keysave);
		    }
		    flags |= HVhek_FREEKEY;
		}

	    }
	} 
    } 

    if (!HvARRAY(hv)) {
	if ((action & (HV_FETCH_LVALUE | HV_FETCH_ISSTORE))

		 || (SvRMAGICAL((const SV *)hv)
		     && mg_find((const SV *)hv, PERL_MAGIC_env))

								  ) {
	    char *array;
	    Newxz(array, PERL_HV_ARRAY_ALLOC_BYTES(xhv->xhv_max+1 ), char);

	    HvARRAY(hv) = (HE**)array;
	}

	else if (action & HV_FETCH_ISEXISTS) {
	    
	}

	else {
	    
            if (flags & HVhek_FREEKEY)
                Safefree(key);

	    return NULL;
	}
    }

    if (is_utf8 & !(flags & HVhek_KEYCANONICAL)) {
	char * const keysave = (char *)key;
	key = (char*)bytes_from_utf8((U8*)key, &klen, &is_utf8);
        if (is_utf8)
	    flags |= HVhek_UTF8;
	else flags &= ~HVhek_UTF8;
        if (key != keysave) {
	    if (flags & HVhek_FREEKEY)
		Safefree(keysave);
            flags |= HVhek_WASUTF8 | HVhek_FREEKEY;
	    
	    hash = 0;
	}
    }

    if (HvREHASH(hv)) {
	PERL_HASH_INTERNAL(hash, key, klen);
	
	
	flags |= HVhek_REHASH;
    } else if (!hash) {
        if (keysv && (SvIsCOW_shared_hash(keysv))) {
            hash = SvSHARED_HASH(keysv);
        } else {
            PERL_HASH(hash, key, klen);
        }
    }

    masked_flags = (flags & HVhek_MASK);


    if (!HvARRAY(hv)) entry = NULL;
    else  {

	entry = (HvARRAY(hv))[hash & (I32) HvMAX(hv)];
    }
    for (; entry; entry = HeNEXT(entry)) {
	if (HeHASH(entry) != hash)		
	    continue;
	if (HeKLEN(entry) != (I32)klen)
	    continue;
	if (HeKEY(entry) != key && memNE(HeKEY(entry),key,klen))	
	    continue;
	if ((HeKFLAGS(entry) ^ masked_flags) & HVhek_UTF8)
	    continue;

        if (action & (HV_FETCH_LVALUE|HV_FETCH_ISSTORE)) {
	    if (HeKFLAGS(entry) != masked_flags) {
		
		if (HvSHAREKEYS(hv)) {
		    
		    HEK * const new_hek = share_hek_flags(key, klen, hash, masked_flags);
		    unshare_hek (HeKEY_hek(entry));
		    HeKEY_hek(entry) = new_hek;
		}
		else if (hv == PL_strtab) {
		    
		    if (flags & HVhek_FREEKEY)
			Safefree(key);
		    Perl_croak(aTHX_ S_strtab_error, action & HV_FETCH_LVALUE ? "fetch" : "store");
		}
		else HeKFLAGS(entry) = masked_flags;
		if (masked_flags & HVhek_ENABLEHVKFLAGS)
		    HvHASKFLAGS_on(hv);
	    }
	    if (HeVAL(entry) == &PL_sv_placeholder) {
		
		if (action & HV_FETCH_LVALUE) {
		    if (SvMAGICAL(hv)) {
			
			break;
		    }
		    
		    val = newSV(0);
		    HvPLACEHOLDERS(hv)--;
		} else {
		    
		    if (val != &PL_sv_placeholder)
			HvPLACEHOLDERS(hv)--;
		}
		HeVAL(entry) = val;
	    } else if (action & HV_FETCH_ISSTORE) {
		SvREFCNT_dec(HeVAL(entry));
		HeVAL(entry) = val;
	    }
	} else if (HeVAL(entry) == &PL_sv_placeholder) {
	    
	    break;
	}
	if (flags & HVhek_FREEKEY)
	    Safefree(key);
	if (return_svp) {
	    return entry ? (void *) &HeVAL(entry) : NULL;
	}
	return entry;
    }

    if (!(action & HV_FETCH_ISSTORE) 
	&& SvRMAGICAL((const SV *)hv)
	&& mg_find((const SV *)hv, PERL_MAGIC_env)) {
	unsigned long len;
	const char * const env = PerlEnv_ENVgetenv_len(key,&len);
	if (env) {
	    sv = newSVpvn(env,len);
	    SvTAINTED_on(sv);
	    return hv_common(hv, keysv, key, klen, flags, HV_FETCH_ISSTORE|HV_DISABLE_UVAR_XKEY|return_svp, sv, hash);

	}
    }


    if (!entry && SvREADONLY(hv) && !(action & HV_FETCH_ISEXISTS)) {
	hv_notallowed(flags, key, klen, "Attempt to access disallowed key '%"SVf"' in" " a restricted hash");

    }
    if (!(action & (HV_FETCH_LVALUE|HV_FETCH_ISSTORE))) {
	
	if (flags & HVhek_FREEKEY)
	    Safefree(key);
	return NULL;
    }
    if (action & HV_FETCH_LVALUE) {
	val = newSV(0);
	if (SvMAGICAL(hv)) {
	    
	    
	    
	    return hv_common(hv, keysv, key, klen, flags, HV_FETCH_ISSTORE|HV_DISABLE_UVAR_XKEY|return_svp, val, hash);

	    
	}
    }

    

    if (!HvARRAY(hv)) {
	
	char *array;
	Newxz(array, PERL_HV_ARRAY_ALLOC_BYTES(xhv->xhv_max+1 ), char);

	HvARRAY(hv) = (HE**)array;
    }

    oentry = &(HvARRAY(hv))[hash & (I32) xhv->xhv_max];

    entry = new_HE();
    
    if (HvSHAREKEYS(hv))
	HeKEY_hek(entry) = share_hek_flags(key, klen, hash, flags);
    else if (hv == PL_strtab) {
	
	if (flags & HVhek_FREEKEY)
	    Safefree(key);
	Perl_croak(aTHX_ S_strtab_error, action & HV_FETCH_LVALUE ? "fetch" : "store");
    }
    else                                        HeKEY_hek(entry) = save_hek_flags(key, klen, hash, flags);
    HeVAL(entry) = val;
    HeNEXT(entry) = *oentry;
    *oentry = entry;

    if (val == &PL_sv_placeholder)
	HvPLACEHOLDERS(hv)++;
    if (masked_flags & HVhek_ENABLEHVKFLAGS)
	HvHASKFLAGS_on(hv);

    {
	const HE *counter = HeNEXT(entry);

	xhv->xhv_keys++; 
	if (!counter) {				
	    xhv->xhv_fill++; 
	} else if (xhv->xhv_keys > (IV)xhv->xhv_max) {
	    hsplit(hv);
	} else if(!HvREHASH(hv)) {
	    U32 n_links = 1;

	    while ((counter = HeNEXT(counter)))
		n_links++;

	    if (n_links > HV_MAX_LENGTH_BEFORE_SPLIT) {
		
		hsplit(hv);
	    }
	}
    }

    if (return_svp) {
	return entry ? (void *) &HeVAL(entry) : NULL;
    }
    return (void *) entry;
}

STATIC void S_hv_magic_check(HV *hv, bool *needs_copy, bool *needs_store)
{
    const MAGIC *mg = SvMAGIC(hv);

    PERL_ARGS_ASSERT_HV_MAGIC_CHECK;

    *needs_copy = FALSE;
    *needs_store = TRUE;
    while (mg) {
	if (isUPPER(mg->mg_type)) {
	    *needs_copy = TRUE;
	    if (mg->mg_type == PERL_MAGIC_tied) {
		*needs_store = FALSE;
		return; 
	    }
	}
	mg = mg->mg_moremagic;
    }
}



SV * Perl_hv_scalar(pTHX_ HV *hv)
{
    SV *sv;

    PERL_ARGS_ASSERT_HV_SCALAR;

    if (SvRMAGICAL(hv)) {
	MAGIC * const mg = mg_find((const SV *)hv, PERL_MAGIC_tied);
	if (mg)
	    return magic_scalarpack(hv, mg);
    }

    sv = sv_newmortal();
    if (HvFILL((const HV *)hv)) 
        Perl_sv_setpvf(aTHX_ sv, "%ld/%ld", (long)HvFILL(hv), (long)HvMAX(hv) + 1);
    else sv_setiv(sv, 0);
    
    return sv;
}



STATIC SV * S_hv_delete_common(pTHX_ HV *hv, SV *keysv, const char *key, STRLEN klen, int k_flags, I32 d_flags, U32 hash)

{
    dVAR;
    register XPVHV* xhv;
    register HE *entry;
    register HE **oentry;
    HE *const *first_entry;
    bool is_utf8 = (k_flags & HVhek_UTF8) ? TRUE : FALSE;
    int masked_flags;

    if (SvRMAGICAL(hv)) {
	bool needs_copy;
	bool needs_store;
	hv_magic_check (hv, &needs_copy, &needs_store);

	if (needs_copy) {
	    SV *sv;
	    entry = (HE *) hv_common(hv, keysv, key, klen, k_flags & ~HVhek_FREEKEY, HV_FETCH_LVALUE|HV_DISABLE_UVAR_XKEY, NULL, hash);


	    sv = entry ? HeVAL(entry) : NULL;
	    if (sv) {
		if (SvMAGICAL(sv)) {
		    mg_clear(sv);
		}
		if (!needs_store) {
		    if (mg_find(sv, PERL_MAGIC_tiedelem)) {
			
			sv_unmagic(sv, PERL_MAGIC_tiedelem);
			return sv;
		    }		
		    return NULL;		
		}

		else if (mg_find((const SV *)hv, PERL_MAGIC_env)) {
		    
		    keysv = newSVpvn_flags(key, klen, SVs_TEMP);
		    if (k_flags & HVhek_FREEKEY) {
			Safefree(key);
		    }
		    key = strupr(SvPVX(keysv));
		    is_utf8 = 0;
		    k_flags = 0;
		    hash = 0;
		}

	    }
	}
    }
    xhv = (XPVHV*)SvANY(hv);
    if (!HvARRAY(hv))
	return NULL;

    if (is_utf8) {
	const char * const keysave = key;
	key = (char*)bytes_from_utf8((U8*)key, &klen, &is_utf8);

        if (is_utf8)
            k_flags |= HVhek_UTF8;
	else k_flags &= ~HVhek_UTF8;
        if (key != keysave) {
	    if (k_flags & HVhek_FREEKEY) {
		
		Safefree(keysave);
	    }
	    k_flags |= HVhek_WASUTF8 | HVhek_FREEKEY;
	}
        HvHASKFLAGS_on(MUTABLE_SV(hv));
    }

    if (HvREHASH(hv)) {
	PERL_HASH_INTERNAL(hash, key, klen);
    } else if (!hash) {
        if (keysv && (SvIsCOW_shared_hash(keysv))) {
            hash = SvSHARED_HASH(keysv);
        } else {
            PERL_HASH(hash, key, klen);
        }
    }

    masked_flags = (k_flags & HVhek_MASK);

    first_entry = oentry = &(HvARRAY(hv))[hash & (I32) HvMAX(hv)];
    entry = *oentry;
    for (; entry; oentry = &HeNEXT(entry), entry = *oentry) {
	SV *sv;
	if (HeHASH(entry) != hash)		
	    continue;
	if (HeKLEN(entry) != (I32)klen)
	    continue;
	if (HeKEY(entry) != key && memNE(HeKEY(entry),key,klen))	
	    continue;
	if ((HeKFLAGS(entry) ^ masked_flags) & HVhek_UTF8)
	    continue;

	if (hv == PL_strtab) {
	    if (k_flags & HVhek_FREEKEY)
		Safefree(key);
	    Perl_croak(aTHX_ S_strtab_error, "delete");
	}

	
	if (HeVAL(entry) == &PL_sv_placeholder) {
	    if (k_flags & HVhek_FREEKEY)
		Safefree(key);
	    return NULL;
	}
	if (SvREADONLY(hv) && HeVAL(entry) && SvREADONLY(HeVAL(entry))) {
	    hv_notallowed(k_flags, key, klen, "Attempt to delete readonly key '%"SVf"' from" " a restricted hash");

	}
        if (k_flags & HVhek_FREEKEY)
            Safefree(key);

	if (d_flags & G_DISCARD)
	    sv = NULL;
	else {
	    sv = sv_2mortal(HeVAL(entry));
	    HeVAL(entry) = &PL_sv_placeholder;
	}

	
	if (SvREADONLY(hv)) {
	    SvREFCNT_dec(HeVAL(entry));
	    HeVAL(entry) = &PL_sv_placeholder;
	    
	    HvPLACEHOLDERS(hv)++;
	} else {
	    *oentry = HeNEXT(entry);
	    if(!*first_entry) {
		xhv->xhv_fill--; 
	    }
	    if (SvOOK(hv) && entry == HvAUX(hv)->xhv_eiter )
		HvLAZYDEL_on(hv);
	    else hv_free_ent(hv, entry);
	    xhv->xhv_keys--; 
	    if (xhv->xhv_keys == 0)
	        HvHASKFLAGS_off(hv);
	}
	return sv;
    }
    if (SvREADONLY(hv)) {
	hv_notallowed(k_flags, key, klen, "Attempt to delete disallowed key '%"SVf"' from" " a restricted hash");

    }

    if (k_flags & HVhek_FREEKEY)
	Safefree(key);
    return NULL;
}

STATIC void S_hsplit(pTHX_ HV *hv)
{
    dVAR;
    register XPVHV* const xhv = (XPVHV*)SvANY(hv);
    const I32 oldsize = (I32) xhv->xhv_max+1; 
    register I32 newsize = oldsize * 2;
    register I32 i;
    char *a = (char*) HvARRAY(hv);
    register HE **aep;
    register HE **oentry;
    int longest_chain = 0;
    int was_shared;

    PERL_ARGS_ASSERT_HSPLIT;

    

    if (HvPLACEHOLDERS_get(hv) && !SvREADONLY(hv)) {
      
      hv_clear_placeholders(hv);
    }
	       
    PL_nomemok = TRUE;

    Renew(a, PERL_HV_ARRAY_ALLOC_BYTES(newsize)
	  + (SvOOK(hv) ? sizeof(struct xpvhv_aux) : 0), char);
    if (!a) {
      PL_nomemok = FALSE;
      return;
    }
    if (SvOOK(hv)) {
	Move(&a[oldsize * sizeof(HE*)], &a[newsize * sizeof(HE*)], 1, struct xpvhv_aux);
    }

    Newx(a, PERL_HV_ARRAY_ALLOC_BYTES(newsize)
	+ (SvOOK(hv) ? sizeof(struct xpvhv_aux) : 0), char);
    if (!a) {
      PL_nomemok = FALSE;
      return;
    }
    Copy(HvARRAY(hv), a, oldsize * sizeof(HE*), char);
    if (SvOOK(hv)) {
	Copy(HvAUX(hv), &a[newsize * sizeof(HE*)], 1, struct xpvhv_aux);
    }
    if (oldsize >= 64) {
	offer_nice_chunk(HvARRAY(hv), PERL_HV_ARRAY_ALLOC_BYTES(oldsize)
			 + (SvOOK(hv) ? sizeof(struct xpvhv_aux) : 0));
    }
    else Safefree(HvARRAY(hv));


    PL_nomemok = FALSE;
    Zero(&a[oldsize * sizeof(HE*)], (newsize-oldsize) * sizeof(HE*), char);	
    xhv->xhv_max = --newsize;	
    HvARRAY(hv) = (HE**) a;
    aep = (HE**)a;

    for (i=0; i<oldsize; i++,aep++) {
	int left_length = 0;
	int right_length = 0;
	register HE *entry;
	register HE **bep;

	if (!*aep)				
	    continue;
	bep = aep+oldsize;
	for (oentry = aep, entry = *aep; entry; entry = *oentry) {
	    if ((HeHASH(entry) & newsize) != (U32)i) {
		*oentry = HeNEXT(entry);
		HeNEXT(entry) = *bep;
		if (!*bep)
		    xhv->xhv_fill++; 
		*bep = entry;
		right_length++;
		continue;
	    }
	    else {
		oentry = &HeNEXT(entry);
		left_length++;
	    }
	}
	if (!*aep)				
	    xhv->xhv_fill--; 
	
	if (left_length > longest_chain)
	    longest_chain = left_length;
	if (right_length > longest_chain)
	    longest_chain = right_length;
    }


    
    if (longest_chain <= HV_MAX_LENGTH_BEFORE_SPLIT  || HvREHASH(hv)) {
	return;
    }

    if (hv == PL_strtab) {
	
	return;
    }

    
    

    ++newsize;
    Newxz(a, PERL_HV_ARRAY_ALLOC_BYTES(newsize)
	 + (SvOOK(hv) ? sizeof(struct xpvhv_aux) : 0), char);
    if (SvOOK(hv)) {
	Copy(HvAUX(hv), &a[newsize * sizeof(HE*)], 1, struct xpvhv_aux);
    }

    was_shared = HvSHAREKEYS(hv);

    xhv->xhv_fill = 0;
    HvSHAREKEYS_off(hv);
    HvREHASH_on(hv);

    aep = HvARRAY(hv);

    for (i=0; i<newsize; i++,aep++) {
	register HE *entry = *aep;
	while (entry) {
	    
	    HE * const next = HeNEXT(entry);
	    UV hash;
	    HE **bep;

	    
	    PERL_HASH_INTERNAL(hash, HeKEY(entry), HeKLEN(entry));

	    if (was_shared) {
		
		HEK * const new_hek = save_hek_flags(HeKEY(entry), HeKLEN(entry), hash, HeKFLAGS(entry));

		unshare_hek (HeKEY_hek(entry));
		HeKEY_hek(entry) = new_hek;
	    } else {
		
		HeHASH(entry) = hash;
	    }
	    
	    HEK_REHASH_on(HeKEY_hek(entry));
	    

	    
	    bep = ((HE**)a) + (hash & (I32) xhv->xhv_max);
	    if (!*bep)
		    xhv->xhv_fill++; 
	    HeNEXT(entry) = *bep;
	    *bep = entry;

	    entry = next;
	}
    }
    Safefree (HvARRAY(hv));
    HvARRAY(hv) = (HE **)a;
}

void Perl_hv_ksplit(pTHX_ HV *hv, IV newmax)
{
    dVAR;
    register XPVHV* xhv = (XPVHV*)SvANY(hv);
    const I32 oldsize = (I32) xhv->xhv_max+1; 
    register I32 newsize;
    register I32 i;
    register char *a;
    register HE **aep;
    register HE *entry;
    register HE **oentry;

    PERL_ARGS_ASSERT_HV_KSPLIT;

    newsize = (I32) newmax;			
    if (newsize != newmax || newmax <= oldsize)
	return;
    while ((newsize & (1 + ~newsize)) != newsize) {
	newsize &= ~(newsize & (1 + ~newsize));	
    }
    if (newsize < newmax)
	newsize *= 2;
    if (newsize < newmax)
	return;					

    a = (char *) HvARRAY(hv);
    if (a) {
	PL_nomemok = TRUE;

	Renew(a, PERL_HV_ARRAY_ALLOC_BYTES(newsize)
	      + (SvOOK(hv) ? sizeof(struct xpvhv_aux) : 0), char);
	if (!a) {
	  PL_nomemok = FALSE;
	  return;
	}
	if (SvOOK(hv)) {
	    Copy(&a[oldsize * sizeof(HE*)], &a[newsize * sizeof(HE*)], 1, struct xpvhv_aux);
	}

	Newx(a, PERL_HV_ARRAY_ALLOC_BYTES(newsize)
	    + (SvOOK(hv) ? sizeof(struct xpvhv_aux) : 0), char);
	if (!a) {
	  PL_nomemok = FALSE;
	  return;
	}
	Copy(HvARRAY(hv), a, oldsize * sizeof(HE*), char);
	if (SvOOK(hv)) {
	    Copy(HvAUX(hv), &a[newsize * sizeof(HE*)], 1, struct xpvhv_aux);
	}
	if (oldsize >= 64) {
	    offer_nice_chunk(HvARRAY(hv), PERL_HV_ARRAY_ALLOC_BYTES(oldsize)
			     + (SvOOK(hv) ? sizeof(struct xpvhv_aux) : 0));
	}
	else Safefree(HvARRAY(hv));

	PL_nomemok = FALSE;
	Zero(&a[oldsize * sizeof(HE*)], (newsize-oldsize) * sizeof(HE*), char); 
    }
    else {
	Newxz(a, PERL_HV_ARRAY_ALLOC_BYTES(newsize), char);
    }
    xhv->xhv_max = --newsize; 	
    HvARRAY(hv) = (HE **) a;
    if (!xhv->xhv_fill )	
	return;

    aep = (HE**)a;
    for (i=0; i<oldsize; i++,aep++) {
	if (!*aep)				
	    continue;
	for (oentry = aep, entry = *aep; entry; entry = *oentry) {
	    register I32 j = (HeHASH(entry) & newsize);

	    if (j != i) {
		j -= i;
		*oentry = HeNEXT(entry);
		if (!(HeNEXT(entry) = aep[j]))
		    xhv->xhv_fill++; 
		aep[j] = entry;
		continue;
	    }
	    else oentry = &HeNEXT(entry);
	}
	if (!*aep)				
	    xhv->xhv_fill--; 
    }
}

HV * Perl_newHVhv(pTHX_ HV *ohv)
{
    dVAR;
    HV * const hv = newHV();
    STRLEN hv_max, hv_fill;

    if (!ohv || (hv_fill = HvFILL(ohv)) == 0)
	return hv;
    hv_max = HvMAX(ohv);

    if (!SvMAGICAL((const SV *)ohv)) {
	
	STRLEN i;
	const bool shared = !!HvSHAREKEYS(ohv);
	HE **ents, ** const oents = (HE **)HvARRAY(ohv);
	char *a;
	Newx(a, PERL_HV_ARRAY_ALLOC_BYTES(hv_max+1), char);
	ents = (HE**)a;

	
	for (i = 0; i <= hv_max; i++) {
	    HE *prev = NULL;
	    HE *oent = oents[i];

	    if (!oent) {
		ents[i] = NULL;
		continue;
	    }

	    
	    for (; oent; oent = HeNEXT(oent)) {
		const U32 hash   = HeHASH(oent);
		const char * const key = HeKEY(oent);
		const STRLEN len = HeKLEN(oent);
		const int flags  = HeKFLAGS(oent);
		HE * const ent   = new_HE();
		SV *const val    = HeVAL(oent);

		HeVAL(ent) = SvIMMORTAL(val) ? val : newSVsv(val);
		HeKEY_hek(ent)
                    = shared ? share_hek_flags(key, len, hash, flags)
                             :  save_hek_flags(key, len, hash, flags);
		if (prev)
		    HeNEXT(prev) = ent;
		else ents[i] = ent;
		prev = ent;
		HeNEXT(ent) = NULL;
	    }
	}

	HvMAX(hv)   = hv_max;
	HvFILL(hv)  = hv_fill;
	HvTOTALKEYS(hv)  = HvTOTALKEYS(ohv);
	HvARRAY(hv) = ents;
    } 
    else {
	
	HE *entry;
	const I32 riter = HvRITER_get(ohv);
	HE * const eiter = HvEITER_get(ohv);

	
	while (hv_max && hv_max + 1 >= hv_fill * 2)
	    hv_max = hv_max / 2;
	HvMAX(hv) = hv_max;

	hv_iterinit(ohv);
	while ((entry = hv_iternext_flags(ohv, 0))) {
	    SV *const val = HeVAL(entry);
	    (void)hv_store_flags(hv, HeKEY(entry), HeKLEN(entry), SvIMMORTAL(val) ? val : newSVsv(val), HeHASH(entry), HeKFLAGS(entry));

	}
	HvRITER_set(ohv, riter);
	HvEITER_set(ohv, eiter);
    }

    return hv;
}


HV * Perl_hv_copy_hints_hv(pTHX_ HV *const ohv)
{
    HV * const hv = newHV();
    STRLEN hv_fill;

    if (ohv && (hv_fill = HvFILL(ohv))) {
	STRLEN hv_max = HvMAX(ohv);
	HE *entry;
	const I32 riter = HvRITER_get(ohv);
	HE * const eiter = HvEITER_get(ohv);

	while (hv_max && hv_max + 1 >= hv_fill * 2)
	    hv_max = hv_max / 2;
	HvMAX(hv) = hv_max;

	hv_iterinit(ohv);
	while ((entry = hv_iternext_flags(ohv, 0))) {
	    SV *const sv = newSVsv(HeVAL(entry));
	    SV *heksv = newSVhek(HeKEY_hek(entry));
	    sv_magic(sv, NULL, PERL_MAGIC_hintselem, (char *)heksv, HEf_SVKEY);
	    SvREFCNT_dec(heksv);
	    (void)hv_store_flags(hv, HeKEY(entry), HeKLEN(entry), sv, HeHASH(entry), HeKFLAGS(entry));
	}
	HvRITER_set(ohv, riter);
	HvEITER_set(ohv, eiter);
    }
    hv_magic(hv, NULL, PERL_MAGIC_hints);
    return hv;
}

void Perl_hv_free_ent(pTHX_ HV *hv, register HE *entry)
{
    dVAR;
    SV *val;

    PERL_ARGS_ASSERT_HV_FREE_ENT;

    if (!entry)
	return;
    val = HeVAL(entry);
    if (HvNAME(hv) && anonymise_cv(HvNAME_HEK(hv), val) && GvCVu(val))
	mro_method_changed_in(hv);
    SvREFCNT_dec(val);
    if (HeKLEN(entry) == HEf_SVKEY) {
	SvREFCNT_dec(HeKEY_sv(entry));
	Safefree(HeKEY_hek(entry));
    }
    else if (HvSHAREKEYS(hv))
	unshare_hek(HeKEY_hek(entry));
    else Safefree(HeKEY_hek(entry));
    del_HE(entry);
}

static I32 S_anonymise_cv(pTHX_ HEK *stash, SV *val)
{
    CV *cv;

    PERL_ARGS_ASSERT_ANONYMISE_CV;

    if (val && isGV(val) && isGV_with_GP(val) && (cv = GvCV(val))) {
	if ((SV *)CvGV(cv) == val) {
	    GV *anongv;

	    if (stash) {
		SV *gvname = newSVhek(stash);
		sv_catpvs(gvname, "::__ANON__");
		anongv = gv_fetchsv(gvname, GV_ADDMULTI, SVt_PVCV);
		SvREFCNT_dec(gvname);
	    } else {
		anongv = gv_fetchpvs("__ANON__::__ANON__", GV_ADDMULTI, SVt_PVCV);
	    }
	    CvGV(cv) = anongv;
	    CvANON_on(cv);
	    return 1;
	}
    }
    return 0;
}

void Perl_hv_delayfree_ent(pTHX_ HV *hv, register HE *entry)
{
    dVAR;

    PERL_ARGS_ASSERT_HV_DELAYFREE_ENT;

    if (!entry)
	return;
    
    sv_2mortal(SvREFCNT_inc(HeVAL(entry)));	
    if (HeKLEN(entry) == HEf_SVKEY) {
	sv_2mortal(SvREFCNT_inc(HeKEY_sv(entry)));
    }
    hv_free_ent(hv, entry);
}



void Perl_hv_clear(pTHX_ HV *hv)
{
    dVAR;
    register XPVHV* xhv;
    if (!hv)
	return;

    DEBUG_A(Perl_hv_assert(aTHX_ hv));

    xhv = (XPVHV*)SvANY(hv);

    if (SvREADONLY(hv) && HvARRAY(hv) != NULL) {
	
	STRLEN i;
	for (i = 0; i <= xhv->xhv_max; i++) {
	    HE *entry = (HvARRAY(hv))[i];
	    for (; entry; entry = HeNEXT(entry)) {
		
		if (HeVAL(entry) != &PL_sv_placeholder) {
		    if (HeVAL(entry) && SvREADONLY(HeVAL(entry))) {
			SV* const keysv = hv_iterkeysv(entry);
			Perl_croak(aTHX_ "Attempt to delete readonly key '%"SVf"' from a restricted hash", (void*)keysv);

		    }
		    SvREFCNT_dec(HeVAL(entry));
		    HeVAL(entry) = &PL_sv_placeholder;
		    HvPLACEHOLDERS(hv)++;
		}
	    }
	}
	goto reset;
    }

    hfreeentries(hv);
    HvPLACEHOLDERS_set(hv, 0);
    if (HvARRAY(hv))
	Zero(HvARRAY(hv), xhv->xhv_max+1 , HE*);

    if (SvRMAGICAL(hv))
	mg_clear(MUTABLE_SV(hv));

    HvHASKFLAGS_off(hv);
    HvREHASH_off(hv);
    reset:
    if (SvOOK(hv)) {
        if(HvNAME_get(hv))
            mro_isa_changed_in(hv);
	HvEITER_set(hv, NULL);
    }
}



void Perl_hv_clear_placeholders(pTHX_ HV *hv)
{
    dVAR;
    const U32 items = (U32)HvPLACEHOLDERS_get(hv);

    PERL_ARGS_ASSERT_HV_CLEAR_PLACEHOLDERS;

    if (items)
	clear_placeholders(hv, items);
}

static void S_clear_placeholders(pTHX_ HV *hv, U32 items)
{
    dVAR;
    I32 i;

    PERL_ARGS_ASSERT_CLEAR_PLACEHOLDERS;

    if (items == 0)
	return;

    i = HvMAX(hv);
    do {
	
	bool first = TRUE;
	HE **oentry = &(HvARRAY(hv))[i];
	HE *entry;

	while ((entry = *oentry)) {
	    if (HeVAL(entry) == &PL_sv_placeholder) {
		*oentry = HeNEXT(entry);
		if (first && !*oentry)
		    HvFILL(hv)--; 
		if (entry == HvEITER_get(hv))
		    HvLAZYDEL_on(hv);
		else hv_free_ent(hv, entry);

		if (--items == 0) {
		    
		    HvTOTALKEYS(hv) -= (IV)HvPLACEHOLDERS_get(hv);
		    if (HvKEYS(hv) == 0)
			HvHASKFLAGS_off(hv);
		    HvPLACEHOLDERS_set(hv, 0);
		    return;
		}
	    } else {
		oentry = &HeNEXT(entry);
		first = FALSE;
	    }
	}
    } while (--i >= 0);
    
    assert (items == 0);
    assert (0);
}

STATIC void S_hfreeentries(pTHX_ HV *hv)
{
    
    HE **const orig_array = HvARRAY(hv);
    HEK *name;
    int attempts = 100;

    PERL_ARGS_ASSERT_HFREEENTRIES;

    if (!orig_array)
	return;

    if (HvNAME(hv) && orig_array != NULL) {
	
	STRLEN i;
	XPVHV *xhv = (XPVHV*)SvANY(hv);

	for (i = 0; i <= xhv->xhv_max; i++) {
	    HE *entry = (HvARRAY(hv))[i];
	    for (; entry; entry = HeNEXT(entry)) {
		SV *val = HeVAL(entry);
		
		anonymise_cv(NULL, val);
	    }
	}
    }

    if (SvOOK(hv)) {
	
	struct xpvhv_aux *iter = HvAUX(hv);

	name = iter->xhv_name;
	iter->xhv_name = NULL;
    } else {
	name = NULL;
    }

    

    while (1) {
	
	HE ** const array = HvARRAY(hv);
	I32 i = HvMAX(hv);

	

	if (SvOOK(hv)) {
	    HE *entry;
            struct mro_meta *meta;
	    struct xpvhv_aux *iter = HvAUX(hv);
	    

	    if (iter->xhv_backreferences) {
		
		SvREFCNT_dec(iter->xhv_backreferences);
		if (AvFILLp(iter->xhv_backreferences) == -1) {
		    
		    SvREFCNT_dec(iter->xhv_backreferences);

		} else {
		    sv_magic(MUTABLE_SV(hv), MUTABLE_SV(iter->xhv_backreferences), PERL_MAGIC_backref, NULL, 0);

		}
		iter->xhv_backreferences = NULL;
	    }

	    entry = iter->xhv_eiter; 
	    if (entry && HvLAZYDEL(hv)) {	
		HvLAZYDEL_off(hv);
		hv_free_ent(hv, entry);
	    }
	    iter->xhv_riter = -1; 	
	    iter->xhv_eiter = NULL;	

            if((meta = iter->xhv_mro_meta)) {
		if (meta->mro_linear_all) {
		    SvREFCNT_dec(MUTABLE_SV(meta->mro_linear_all));
		    meta->mro_linear_all = NULL;
		    
		    meta->mro_linear_current = NULL;
		} else if (meta->mro_linear_current) {
		    
		    SvREFCNT_dec(meta->mro_linear_current);
		    meta->mro_linear_current = NULL;
		}
                if(meta->mro_nextmethod) SvREFCNT_dec(meta->mro_nextmethod);
                SvREFCNT_dec(meta->isa);
                Safefree(meta);
                iter->xhv_mro_meta = NULL;
            }

	    

	    SvFLAGS(hv) &= ~SVf_OOK; 
	    
	}

	
	HvARRAY(hv) = NULL;
	HvFILL(hv) = 0;
	((XPVHV*) SvANY(hv))->xhv_keys = 0;


	do {
	    
	    HE *entry = array[i];

	    while (entry) {
		register HE * const oentry = entry;
		entry = HeNEXT(entry);
		hv_free_ent(hv, oentry);
	    }
	} while (--i >= 0);

	
	if (array != orig_array) {
	    Safefree(array);
	}

	if (!HvARRAY(hv)) {
	    
	    break;
	}

	if (SvOOK(hv)) {
	    
	    assert(HvARRAY(hv));

	    if (HvAUX(hv)->xhv_name) {
		unshare_hek_or_pvn(HvAUX(hv)->xhv_name, 0, 0, 0);
	    }
	}

	if (--attempts == 0) {
	    Perl_die(aTHX_ "panic: hfreeentries failed to free hash - something is repeatedly re-creating entries");
	}
    }
	
    HvARRAY(hv) = orig_array;

    
    if (name) {
	
	SvFLAGS(hv) |= SVf_OOK;
	HvAUX(hv)->xhv_name = name;
    }
}



void Perl_hv_undef(pTHX_ HV *hv)
{
    dVAR;
    register XPVHV* xhv;
    const char *name;

    if (!hv)
	return;
    DEBUG_A(Perl_hv_assert(aTHX_ hv));
    xhv = (XPVHV*)SvANY(hv);

    if ((name = HvNAME_get(hv)) && !PL_dirty)
        mro_isa_changed_in(hv);

    hfreeentries(hv);
    if (name) {
        if (PL_stashcache)
	    (void)hv_delete(PL_stashcache, name, HvNAMELEN_get(hv), G_DISCARD);
	hv_name_set(hv, NULL, 0, 0);
    }
    SvFLAGS(hv) &= ~SVf_OOK;
    Safefree(HvARRAY(hv));
    xhv->xhv_max   = 7;	
    HvARRAY(hv) = 0;
    HvPLACEHOLDERS_set(hv, 0);

    if (SvRMAGICAL(hv))
	mg_clear(MUTABLE_SV(hv));
}

static struct xpvhv_aux* S_hv_auxinit(HV *hv) {
    struct xpvhv_aux *iter;
    char *array;

    PERL_ARGS_ASSERT_HV_AUXINIT;

    if (!HvARRAY(hv)) {
	Newxz(array, PERL_HV_ARRAY_ALLOC_BYTES(HvMAX(hv) + 1)
	    + sizeof(struct xpvhv_aux), char);
    } else {
	array = (char *) HvARRAY(hv);
	Renew(array, PERL_HV_ARRAY_ALLOC_BYTES(HvMAX(hv) + 1)
	      + sizeof(struct xpvhv_aux), char);
    }
    HvARRAY(hv) = (HE**) array;
    
    SvFLAGS(hv) |= SVf_OOK;
    iter = HvAUX(hv);

    iter->xhv_riter = -1; 	
    iter->xhv_eiter = NULL;	
    iter->xhv_name = 0;
    iter->xhv_backreferences = 0;
    iter->xhv_mro_meta = NULL;
    return iter;
}



I32 Perl_hv_iterinit(pTHX_ HV *hv)
{
    PERL_ARGS_ASSERT_HV_ITERINIT;

    

    if (!hv)
	Perl_croak(aTHX_ "Bad hash");

    if (SvOOK(hv)) {
	struct xpvhv_aux * const iter = HvAUX(hv);
	HE * const entry = iter->xhv_eiter; 
	if (entry && HvLAZYDEL(hv)) {	
	    HvLAZYDEL_off(hv);
	    hv_free_ent(hv, entry);
	}
	iter->xhv_riter = -1; 	
	iter->xhv_eiter = NULL; 
    } else {
	hv_auxinit(hv);
    }

    
    return HvTOTALKEYS(hv);
}

I32 * Perl_hv_riter_p(pTHX_ HV *hv) {
    struct xpvhv_aux *iter;

    PERL_ARGS_ASSERT_HV_RITER_P;

    if (!hv)
	Perl_croak(aTHX_ "Bad hash");

    iter = SvOOK(hv) ? HvAUX(hv) : hv_auxinit(hv);
    return &(iter->xhv_riter);
}

HE ** Perl_hv_eiter_p(pTHX_ HV *hv) {
    struct xpvhv_aux *iter;

    PERL_ARGS_ASSERT_HV_EITER_P;

    if (!hv)
	Perl_croak(aTHX_ "Bad hash");

    iter = SvOOK(hv) ? HvAUX(hv) : hv_auxinit(hv);
    return &(iter->xhv_eiter);
}

void Perl_hv_riter_set(pTHX_ HV *hv, I32 riter) {
    struct xpvhv_aux *iter;

    PERL_ARGS_ASSERT_HV_RITER_SET;

    if (!hv)
	Perl_croak(aTHX_ "Bad hash");

    if (SvOOK(hv)) {
	iter = HvAUX(hv);
    } else {
	if (riter == -1)
	    return;

	iter = hv_auxinit(hv);
    }
    iter->xhv_riter = riter;
}

void Perl_hv_eiter_set(pTHX_ HV *hv, HE *eiter) {
    struct xpvhv_aux *iter;

    PERL_ARGS_ASSERT_HV_EITER_SET;

    if (!hv)
	Perl_croak(aTHX_ "Bad hash");

    if (SvOOK(hv)) {
	iter = HvAUX(hv);
    } else {
	
	if (!eiter)
	    return;

	iter = hv_auxinit(hv);
    }
    iter->xhv_eiter = eiter;
}

void Perl_hv_name_set(pTHX_ HV *hv, const char *name, U32 len, U32 flags)
{
    dVAR;
    struct xpvhv_aux *iter;
    U32 hash;

    PERL_ARGS_ASSERT_HV_NAME_SET;
    PERL_UNUSED_ARG(flags);

    if (len > I32_MAX)
	Perl_croak(aTHX_ "panic: hv name too long (%"UVuf")", (UV) len);

    if (SvOOK(hv)) {
	iter = HvAUX(hv);
	if (iter->xhv_name) {
	    unshare_hek_or_pvn(iter->xhv_name, 0, 0, 0);
	}
    } else {
	if (name == 0)
	    return;

	iter = hv_auxinit(hv);
    }
    PERL_HASH(hash, name, len);
    iter->xhv_name = name ? share_hek(name, len, hash) : NULL;
}

AV ** Perl_hv_backreferences_p(pTHX_ HV *hv) {
    struct xpvhv_aux * const iter = SvOOK(hv) ? HvAUX(hv) : hv_auxinit(hv);

    PERL_ARGS_ASSERT_HV_BACKREFERENCES_P;
    PERL_UNUSED_CONTEXT;

    return &(iter->xhv_backreferences);
}

void Perl_hv_kill_backrefs(pTHX_ HV *hv) {
    AV *av;

    PERL_ARGS_ASSERT_HV_KILL_BACKREFS;

    if (!SvOOK(hv))
	return;

    av = HvAUX(hv)->xhv_backreferences;

    if (av) {
	HvAUX(hv)->xhv_backreferences = 0;
	Perl_sv_kill_backrefs(aTHX_ MUTABLE_SV(hv), av);
	SvREFCNT_dec(av);
    }
}



HE * Perl_hv_iternext_flags(pTHX_ HV *hv, I32 flags)
{
    dVAR;
    register XPVHV* xhv;
    register HE *entry;
    HE *oldentry;
    MAGIC* mg;
    struct xpvhv_aux *iter;

    PERL_ARGS_ASSERT_HV_ITERNEXT_FLAGS;

    if (!hv)
	Perl_croak(aTHX_ "Bad hash");

    xhv = (XPVHV*)SvANY(hv);

    if (!SvOOK(hv)) {
	
	hv_iterinit(hv);
    }
    iter = HvAUX(hv);

    oldentry = entry = iter->xhv_eiter; 
    if (SvMAGICAL(hv) && SvRMAGICAL(hv)) {
	if ( ( mg = mg_find((const SV *)hv, PERL_MAGIC_tied) ) ) {
            SV * const key = sv_newmortal();
            if (entry) {
                sv_setsv(key, HeSVKEY_force(entry));
                SvREFCNT_dec(HeSVKEY(entry));       
            }
            else {
                char *k;
                HEK *hek;

                
                iter->xhv_eiter = entry = new_HE(); 
                Zero(entry, 1, HE);
                Newxz(k, HEK_BASESIZE + sizeof(const SV *), char);
                hek = (HEK*)k;
                HeKEY_hek(entry) = hek;
                HeKLEN(entry) = HEf_SVKEY;
            }
            magic_nextpack(MUTABLE_SV(hv),mg,key);
            if (SvOK(key)) {
                
                HeSVKEY_set(entry, SvREFCNT_inc_simple_NN(key));
                return entry;               
            }
            SvREFCNT_dec(HeVAL(entry));
            Safefree(HeKEY_hek(entry));
            del_HE(entry);
            iter->xhv_eiter = NULL; 
            return NULL;
        }
    }

    if (!entry && SvRMAGICAL((const SV *)hv)
	&& mg_find((const SV *)hv, PERL_MAGIC_env)) {
	prime_env_iter();

	
	hv_iterinit(hv);
	iter = HvAUX(hv);
	oldentry = entry = iter->xhv_eiter; 

    }


    
    assert (HvARRAY(hv));

    
    if (entry)
    {
	entry = HeNEXT(entry);
        if (!(flags & HV_ITERNEXT_WANTPLACEHOLDERS)) {
            
            while (entry && HeVAL(entry) == &PL_sv_placeholder) {
                entry = HeNEXT(entry);
            }
	}
    }

    
    if ((flags & HV_ITERNEXT_WANTPLACEHOLDERS)
	? HvTOTALKEYS(hv) : HvUSEDKEYS(hv)) {
	while (!entry) {
	    

	    iter->xhv_riter++; 
	    if (iter->xhv_riter > (I32)xhv->xhv_max ) {
		
		iter->xhv_riter = -1; 
		break;
	    }
	    entry = (HvARRAY(hv))[iter->xhv_riter];

	    if (!(flags & HV_ITERNEXT_WANTPLACEHOLDERS)) {
		
		while (entry && HeVAL(entry) == &PL_sv_placeholder)
		    entry = HeNEXT(entry);
	    }
	    
	}
    }

    if (oldentry && HvLAZYDEL(hv)) {		
	HvLAZYDEL_off(hv);
	hv_free_ent(hv, oldentry);
    }

    

    iter->xhv_eiter = entry; 
    return entry;
}



char * Perl_hv_iterkey(pTHX_ register HE *entry, I32 *retlen)
{
    PERL_ARGS_ASSERT_HV_ITERKEY;

    if (HeKLEN(entry) == HEf_SVKEY) {
	STRLEN len;
	char * const p = SvPV(HeKEY_sv(entry), len);
	*retlen = len;
	return p;
    }
    else {
	*retlen = HeKLEN(entry);
	return HeKEY(entry);
    }
}




SV * Perl_hv_iterkeysv(pTHX_ register HE *entry)
{
    PERL_ARGS_ASSERT_HV_ITERKEYSV;

    return sv_2mortal(newSVhek(HeKEY_hek(entry)));
}



SV * Perl_hv_iterval(pTHX_ HV *hv, register HE *entry)
{
    PERL_ARGS_ASSERT_HV_ITERVAL;

    if (SvRMAGICAL(hv)) {
	if (mg_find((const SV *)hv, PERL_MAGIC_tied)) {
	    SV* const sv = sv_newmortal();
	    if (HeKLEN(entry) == HEf_SVKEY)
		mg_copy(MUTABLE_SV(hv), sv, (char*)HeKEY_sv(entry), HEf_SVKEY);
	    else mg_copy(MUTABLE_SV(hv), sv, HeKEY(entry), HeKLEN(entry));
	    return sv;
	}
    }
    return HeVAL(entry);
}



SV * Perl_hv_iternextsv(pTHX_ HV *hv, char **key, I32 *retlen)
{
    HE * const he = hv_iternext_flags(hv, 0);

    PERL_ARGS_ASSERT_HV_ITERNEXTSV;

    if (!he)
	return NULL;
    *key = hv_iterkey(he, retlen);
    return hv_iterval(hv, he);
}




void Perl_unsharepvn(pTHX_ const char *str, I32 len, U32 hash)
{
    unshare_hek_or_pvn (NULL, str, len, hash);
}


void Perl_unshare_hek(pTHX_ HEK *hek)
{
    assert(hek);
    unshare_hek_or_pvn(hek, NULL, 0, 0);
}


STATIC void S_unshare_hek_or_pvn(pTHX_ const HEK *hek, const char *str, I32 len, U32 hash)
{
    dVAR;
    register XPVHV* xhv;
    HE *entry;
    register HE **oentry;
    HE **first;
    bool is_utf8 = FALSE;
    int k_flags = 0;
    const char * const save = str;
    struct shared_he *he = NULL;

    if (hek) {
	
	he = (struct shared_he *)(((char *)hek)
				  - STRUCT_OFFSET(struct shared_he, shared_he_hek));

	
	assert (he->shared_he_he.hent_hek == hek);

	if (he->shared_he_he.he_valu.hent_refcount - 1) {
	    --he->shared_he_he.he_valu.hent_refcount;
	    return;
	}

        hash = HEK_HASH(hek);
    } else if (len < 0) {
        STRLEN tmplen = -len;
        is_utf8 = TRUE;
        
        str = (char*)bytes_from_utf8((U8*)str, &tmplen, &is_utf8);
        len = tmplen;
        if (is_utf8)
            k_flags = HVhek_UTF8;
        if (str != save)
            k_flags |= HVhek_WASUTF8 | HVhek_FREEKEY;
    }

    
    xhv = (XPVHV*)SvANY(PL_strtab);
    
    first = oentry = &(HvARRAY(PL_strtab))[hash & (I32) HvMAX(PL_strtab)];
    if (he) {
	const HE *const he_he = &(he->shared_he_he);
        for (entry = *oentry; entry; oentry = &HeNEXT(entry), entry = *oentry) {
            if (entry == he_he)
                break;
        }
    } else {
        const int flags_masked = k_flags & HVhek_MASK;
        for (entry = *oentry; entry; oentry = &HeNEXT(entry), entry = *oentry) {
            if (HeHASH(entry) != hash)		
                continue;
            if (HeKLEN(entry) != len)
                continue;
            if (HeKEY(entry) != str && memNE(HeKEY(entry),str,len))	
                continue;
            if (HeKFLAGS(entry) != flags_masked)
                continue;
            break;
        }
    }

    if (entry) {
        if (--entry->he_valu.hent_refcount == 0) {
            *oentry = HeNEXT(entry);
            if (!*first) {
		
                xhv->xhv_fill--; 
	    }
            Safefree(entry);
            xhv->xhv_keys--; 
        }
    }

    if (!entry)
	Perl_ck_warner_d(aTHX_ packWARN(WARN_INTERNAL), "Attempt to free non-existent shared string '%s'%s" pTHX__FORMAT, hek ? HEK_KEY(hek) : str, ((k_flags & HVhek_UTF8) ? " (utf8)" : "") pTHX__VALUE);



    if (k_flags & HVhek_FREEKEY)
	Safefree(str);
}


HEK * Perl_share_hek(pTHX_ const char *str, I32 len, register U32 hash)
{
    bool is_utf8 = FALSE;
    int flags = 0;
    const char * const save = str;

    PERL_ARGS_ASSERT_SHARE_HEK;

    if (len < 0) {
      STRLEN tmplen = -len;
      is_utf8 = TRUE;
      
      str = (char*)bytes_from_utf8((U8*)str, &tmplen, &is_utf8);
      len = tmplen;
      
      if (is_utf8)
          flags = HVhek_UTF8;
      
      if (str != save)
          flags |= HVhek_WASUTF8 | HVhek_FREEKEY;
    }

    return share_hek_flags (str, len, hash, flags);
}

STATIC HEK * S_share_hek_flags(pTHX_ const char *str, I32 len, register U32 hash, int flags)
{
    dVAR;
    register HE *entry;
    const int flags_masked = flags & HVhek_MASK;
    const U32 hindex = hash & (I32) HvMAX(PL_strtab);
    register XPVHV * const xhv = (XPVHV*)SvANY(PL_strtab);

    PERL_ARGS_ASSERT_SHARE_HEK_FLAGS;

    

    
    entry = (HvARRAY(PL_strtab))[hindex];
    for (;entry; entry = HeNEXT(entry)) {
	if (HeHASH(entry) != hash)		
	    continue;
	if (HeKLEN(entry) != len)
	    continue;
	if (HeKEY(entry) != str && memNE(HeKEY(entry),str,len))	
	    continue;
	if (HeKFLAGS(entry) != flags_masked)
	    continue;
	break;
    }

    if (!entry) {
	
	struct shared_he *new_entry;
	HEK *hek;
	char *k;
	HE **const head = &HvARRAY(PL_strtab)[hindex];
	HE *const next = *head;

	

	Newx(k, STRUCT_OFFSET(struct shared_he, shared_he_hek.hek_key[0]) + len + 2, char);
	new_entry = (struct shared_he *)k;
	entry = &(new_entry->shared_he_he);
	hek = &(new_entry->shared_he_hek);

	Copy(str, HEK_KEY(hek), len, char);
	HEK_KEY(hek)[len] = 0;
	HEK_LEN(hek) = len;
	HEK_HASH(hek) = hash;
	HEK_FLAGS(hek) = (unsigned char)flags_masked;

	
	HeKEY_hek(entry) = hek;
	entry->he_valu.hent_refcount = 0;
	HeNEXT(entry) = next;
	*head = entry;

	xhv->xhv_keys++; 
	if (!next) {			
	    xhv->xhv_fill++; 
	} else if (xhv->xhv_keys > (IV)xhv->xhv_max ) {
		hsplit(PL_strtab);
	}
    }

    ++entry->he_valu.hent_refcount;

    if (flags & HVhek_FREEKEY)
	Safefree(str);

    return HeKEY_hek(entry);
}

I32 * Perl_hv_placeholders_p(pTHX_ HV *hv)
{
    dVAR;
    MAGIC *mg = mg_find((const SV *)hv, PERL_MAGIC_rhash);

    PERL_ARGS_ASSERT_HV_PLACEHOLDERS_P;

    if (!mg) {
	mg = sv_magicext(MUTABLE_SV(hv), 0, PERL_MAGIC_rhash, 0, 0, 0);

	if (!mg) {
	    Perl_die(aTHX_ "panic: hv_placeholders_p");
	}
    }
    return &(mg->mg_len);
}


I32 Perl_hv_placeholders_get(pTHX_ const HV *hv)
{
    dVAR;
    MAGIC * const mg = mg_find((const SV *)hv, PERL_MAGIC_rhash);

    PERL_ARGS_ASSERT_HV_PLACEHOLDERS_GET;

    return mg ? mg->mg_len : 0;
}

void Perl_hv_placeholders_set(pTHX_ HV *hv, I32 ph)
{
    dVAR;
    MAGIC * const mg = mg_find((const SV *)hv, PERL_MAGIC_rhash);

    PERL_ARGS_ASSERT_HV_PLACEHOLDERS_SET;

    if (mg) {
	mg->mg_len = ph;
    } else if (ph) {
	if (!sv_magicext(MUTABLE_SV(hv), 0, PERL_MAGIC_rhash, 0, 0, ph))
	    Perl_die(aTHX_ "panic: hv_placeholders_set");
    }
    
}

STATIC SV * S_refcounted_he_value(pTHX_ const struct refcounted_he *he)
{
    dVAR;
    SV *value;

    PERL_ARGS_ASSERT_REFCOUNTED_HE_VALUE;

    switch(he->refcounted_he_data[0] & HVrhek_typemask) {
    case HVrhek_undef:
	value = newSV(0);
	break;
    case HVrhek_delete:
	value = &PL_sv_placeholder;
	break;
    case HVrhek_IV:
	value = newSViv(he->refcounted_he_val.refcounted_he_u_iv);
	break;
    case HVrhek_UV:
	value = newSVuv(he->refcounted_he_val.refcounted_he_u_uv);
	break;
    case HVrhek_PV:
    case HVrhek_PV_UTF8:
	
	value = newSV_type(SVt_PV);
	SvPV_set(value, (char *) he->refcounted_he_data + 1);
	SvCUR_set(value, he->refcounted_he_val.refcounted_he_u_len);
	
	SvLEN_set(value, 0);
	SvPOK_on(value);
	SvREADONLY_on(value);
	if ((he->refcounted_he_data[0] & HVrhek_typemask) == HVrhek_PV_UTF8)
	    SvUTF8_on(value);
	break;
    default:
	Perl_croak(aTHX_ "panic: refcounted_he_value bad flags %x", he->refcounted_he_data[0]);
    }
    return value;
}


HV * Perl_refcounted_he_chain_2hv(pTHX_ const struct refcounted_he *chain)
{
    dVAR;
    HV *hv = newHV();
    U32 placeholders = 0;
    
    const U32 max = HvMAX(hv);

    if (!HvARRAY(hv)) {
	char *array;
	Newxz(array, PERL_HV_ARRAY_ALLOC_BYTES(max + 1), char);
	HvARRAY(hv) = (HE**)array;
    }

    while (chain) {

	U32 hash = chain->refcounted_he_hash;

	U32 hash = HEK_HASH(chain->refcounted_he_hek);

	HE **oentry = &((HvARRAY(hv))[hash & max]);
	HE *entry = *oentry;
	SV *value;

	for (; entry; entry = HeNEXT(entry)) {
	    if (HeHASH(entry) == hash) {
		

		const STRLEN klen = HeKLEN(entry);
		const char *const key = HeKEY(entry);
		if (klen == chain->refcounted_he_keylen && (!!HeKUTF8(entry)
			== !!(chain->refcounted_he_data[0] & HVhek_UTF8))
		    && memEQ(key, REF_HE_KEY(chain), klen))
		    goto next_please;

		if (HeKEY_hek(entry) == chain->refcounted_he_hek)
		    goto next_please;
		if (HeKLEN(entry) == HEK_LEN(chain->refcounted_he_hek)
		    && HeKUTF8(entry) == HEK_UTF8(chain->refcounted_he_hek)
		    && memEQ(HeKEY(entry), HEK_KEY(chain->refcounted_he_hek), HeKLEN(entry)))
		    goto next_please;

	    }
	}
	assert (!entry);
	entry = new_HE();


	HeKEY_hek(entry)
	    = share_hek_flags(REF_HE_KEY(chain), chain->refcounted_he_keylen, chain->refcounted_he_hash, (chain->refcounted_he_data[0] & (HVhek_UTF8|HVhek_WASUTF8)));




	HeKEY_hek(entry) = share_hek_hek(chain->refcounted_he_hek);

	value = refcounted_he_value(chain);
	if (value == &PL_sv_placeholder)
	    placeholders++;
	HeVAL(entry) = value;

	
	HeNEXT(entry) = *oentry;
	if (!HeNEXT(entry)) {
	    
	    HvFILL(hv)++;
	}
	*oentry = entry;

	HvTOTALKEYS(hv)++;

    next_please:
	chain = chain->refcounted_he_next;
    }

    if (placeholders) {
	clear_placeholders(hv, placeholders);
	HvTOTALKEYS(hv) -= placeholders;
    }

    
    HvHASKFLAGS_on(hv);
    DEBUG_A(Perl_hv_assert(aTHX_ hv));

    return hv;
}

SV * Perl_refcounted_he_fetch(pTHX_ const struct refcounted_he *chain, SV *keysv, const char *key, STRLEN klen, int flags, U32 hash)

{
    dVAR;
    
    SV *value = &PL_sv_placeholder;

    if (chain) {
	
	bool is_utf8;

	if (keysv) {
	    if (flags & HVhek_FREEKEY)
		Safefree(key);
	    key = SvPV_const(keysv, klen);
	    flags = 0;
	    is_utf8 = (SvUTF8(keysv) != 0);
	} else {
	    is_utf8 = ((flags & HVhek_UTF8) ? TRUE : FALSE);
	}

	if (!hash) {
	    if (keysv && (SvIsCOW_shared_hash(keysv))) {
		hash = SvSHARED_HASH(keysv);
	    } else {
		PERL_HASH(hash, key, klen);
	    }
	}

	for (; chain; chain = chain->refcounted_he_next) {

	    if (hash != chain->refcounted_he_hash)
		continue;
	    if (klen != chain->refcounted_he_keylen)
		continue;
	    if (memNE(REF_HE_KEY(chain),key,klen))
		continue;
	    if (!!is_utf8 != !!(chain->refcounted_he_data[0] & HVhek_UTF8))
		continue;

	    if (hash != HEK_HASH(chain->refcounted_he_hek))
		continue;
	    if (klen != (STRLEN)HEK_LEN(chain->refcounted_he_hek))
		continue;
	    if (memNE(HEK_KEY(chain->refcounted_he_hek),key,klen))
		continue;
	    if (!!is_utf8 != !!HEK_UTF8(chain->refcounted_he_hek))
		continue;


	    value = sv_2mortal(refcounted_he_value(chain));
	    break;
	}
    }

    if (flags & HVhek_FREEKEY)
	Safefree(key);

    return value;
}



struct refcounted_he * Perl_refcounted_he_new(pTHX_ struct refcounted_he *const parent, SV *const key, SV *const value) {

    dVAR;
    STRLEN key_len;
    const char *key_p = SvPV_const(key, key_len);
    STRLEN value_len = 0;
    const char *value_p = NULL;
    char value_type;
    char flags;
    bool is_utf8 = SvUTF8(key) ? TRUE : FALSE;

    if (SvPOK(value)) {
	value_type = HVrhek_PV;
    } else if (SvIOK(value)) {
	value_type = SvUOK((const SV *)value) ? HVrhek_UV : HVrhek_IV;
    } else if (value == &PL_sv_placeholder) {
	value_type = HVrhek_delete;
    } else if (!SvOK(value)) {
	value_type = HVrhek_undef;
    } else {
	value_type = HVrhek_PV;
    }

    if (value_type == HVrhek_PV) {
	
	value_p = SvPV_const(value, value_len);
	if (SvUTF8(value))
	    value_type = HVrhek_PV_UTF8;
    }
    flags = value_type;

    if (is_utf8) {
	
	key_p = (char*)bytes_from_utf8((const U8*)key_p, &key_len, &is_utf8);
	flags |= is_utf8 ? HVhek_UTF8 : HVhek_WASUTF8;
    }

    return refcounted_he_new_common(parent, key_p, key_len, flags, value_type, ((value_type == HVrhek_PV || value_type == HVrhek_PV_UTF8) ? (void *)value_p : (void *)value), value_len);



}

static struct refcounted_he * S_refcounted_he_new_common(pTHX_ struct refcounted_he *const parent, const char *const key_p, const STRLEN key_len, const char flags, char value_type, const void *value, const STRLEN value_len) {



    dVAR;
    struct refcounted_he *he;
    U32 hash;
    const bool is_pv = value_type == HVrhek_PV || value_type == HVrhek_PV_UTF8;
    STRLEN key_offset = is_pv ? value_len + 2 : 1;

    PERL_ARGS_ASSERT_REFCOUNTED_HE_NEW_COMMON;


    he = (struct refcounted_he*)
	PerlMemShared_malloc(sizeof(struct refcounted_he) - 1 + key_len + key_offset);


    he = (struct refcounted_he*)
	PerlMemShared_malloc(sizeof(struct refcounted_he) - 1 + key_offset);


    he->refcounted_he_next = parent;

    if (is_pv) {
	Copy((char *)value, he->refcounted_he_data + 1, value_len + 1, char);
	he->refcounted_he_val.refcounted_he_u_len = value_len;
    } else if (value_type == HVrhek_IV) {
	he->refcounted_he_val.refcounted_he_u_iv = SvIVX((const SV *)value);
    } else if (value_type == HVrhek_UV) {
	he->refcounted_he_val.refcounted_he_u_uv = SvUVX((const SV *)value);
    }

    PERL_HASH(hash, key_p, key_len);


    he->refcounted_he_hash = hash;
    he->refcounted_he_keylen = key_len;
    Copy(key_p, he->refcounted_he_data + key_offset, key_len, char);

    he->refcounted_he_hek = share_hek_flags(key_p, key_len, hash, flags);


    if (flags & HVhek_WASUTF8) {
	
	Safefree(key_p);
    }

    he->refcounted_he_data[0] = flags;
    he->refcounted_he_refcnt = 1;

    return he;
}



void Perl_refcounted_he_free(pTHX_ struct refcounted_he *he) {
    dVAR;
    PERL_UNUSED_CONTEXT;

    while (he) {
	struct refcounted_he *copy;
	U32 new_count;

	HINTS_REFCNT_LOCK;
	new_count = --he->refcounted_he_refcnt;
	HINTS_REFCNT_UNLOCK;
	
	if (new_count) {
	    return;
	}


	unshare_hek_or_pvn (he->refcounted_he_hek, 0, 0, 0);

	copy = he;
	he = he->refcounted_he_next;
	PerlMemShared_free(copy);
    }
}


const char * Perl_fetch_cop_label(pTHX_ struct refcounted_he *const chain, STRLEN *len, U32 *flags) {

    if (!chain)
	return NULL;

    if (chain->refcounted_he_keylen != 1)
	return NULL;
    if (*REF_HE_KEY(chain) != ':')
	return NULL;

    if ((STRLEN)HEK_LEN(chain->refcounted_he_hek) != 1)
	return NULL;
    if (*HEK_KEY(chain->refcounted_he_hek) != ':')
	return NULL;

    
    if ((chain->refcounted_he_data[0] & HVrhek_typemask) != HVrhek_PV && (chain->refcounted_he_data[0] & HVrhek_typemask) != HVrhek_PV_UTF8)
	return NULL;

    if (len)
	*len = chain->refcounted_he_val.refcounted_he_u_len;
    if (flags) {
	*flags = ((chain->refcounted_he_data[0] & HVrhek_typemask)
		  == HVrhek_PV_UTF8) ? SVf_UTF8 : 0;
    }
    return chain->refcounted_he_data + 1;
}


struct refcounted_he * Perl_store_cop_label(pTHX_ struct refcounted_he *const chain, const char *label)
{
    PERL_ARGS_ASSERT_STORE_COP_LABEL;

    return refcounted_he_new_common(chain, ":", 1, HVrhek_PV, HVrhek_PV, label, strlen(label));
}





void Perl_hv_assert(pTHX_ HV *hv)
{
    dVAR;
    HE* entry;
    int withflags = 0;
    int placeholders = 0;
    int real = 0;
    int bad = 0;
    const I32 riter = HvRITER_get(hv);
    HE *eiter = HvEITER_get(hv);

    PERL_ARGS_ASSERT_HV_ASSERT;

    (void)hv_iterinit(hv);

    while ((entry = hv_iternext_flags(hv, HV_ITERNEXT_WANTPLACEHOLDERS))) {
	
	if (HeVAL(entry) == &PL_sv_placeholder)
	    placeholders++;
	else real++;
	
	if (HeSVKEY(entry)) {
	    NOOP;   
	} else if (HeKUTF8(entry)) {
	    withflags++;
	    if (HeKWASUTF8(entry)) {
		PerlIO_printf(Perl_debug_log, "hash key has both WASUTF8 and UTF8: '%.*s'\n", (int) HeKLEN(entry),  HeKEY(entry));

		bad = 1;
	    }
	} else if (HeKWASUTF8(entry))
	    withflags++;
    }
    if (!SvTIED_mg((const SV *)hv, PERL_MAGIC_tied)) {
	static const char bad_count[] = "Count %d %s(s), but hash reports %d\n";
	const int nhashkeys = HvUSEDKEYS(hv);
	const int nhashplaceholders = HvPLACEHOLDERS_get(hv);

	if (nhashkeys != real) {
	    PerlIO_printf(Perl_debug_log, bad_count, real, "keys", nhashkeys );
	    bad = 1;
	}
	if (nhashplaceholders != placeholders) {
	    PerlIO_printf(Perl_debug_log, bad_count, placeholders, "placeholder", nhashplaceholders );
	    bad = 1;
	}
    }
    if (withflags && ! HvHASKFLAGS(hv)) {
	PerlIO_printf(Perl_debug_log, "Hash has HASKFLAGS off but I count %d key(s) with flags\n", withflags);

	bad = 1;
    }
    if (bad) {
	sv_dump(MUTABLE_SV(hv));
    }
    HvRITER_set(hv, riter);		
    HvEITER_set(hv, eiter);
}




