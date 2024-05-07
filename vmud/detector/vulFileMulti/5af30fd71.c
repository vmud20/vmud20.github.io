
















garray_T def_functions = {0, 0, sizeof(dfunc_T), 50, NULL};

static void delete_def_function_contents(dfunc_T *dfunc, int mark_deleted);


    int lookup_local(char_u *name, size_t len, lvar_T *lvar, cctx_T *cctx)
{
    int	    idx;
    lvar_T  *lvp;

    if (len == 0)
	return FAIL;

    
    for (idx = 0; idx < cctx->ctx_locals.ga_len; ++idx)
    {
	lvp = ((lvar_T *)cctx->ctx_locals.ga_data) + idx;
	if (STRNCMP(name, lvp->lv_name, len) == 0 && STRLEN(lvp->lv_name) == len)
	{
	    if (lvar != NULL)
	    {
		*lvar = *lvp;
		lvar->lv_from_outer = 0;
	    }
	    return OK;
	}
    }

    
    if (cctx->ctx_outer != NULL)
    {
	if (lookup_local(name, len, lvar, cctx->ctx_outer) == OK)
	{
	    if (lvar != NULL)
	    {
		cctx->ctx_outer_used = TRUE;
		++lvar->lv_from_outer;
	    }
	    return OK;
	}
    }

    return FAIL;
}


    int arg_exists( char_u	*name, size_t	len, int	*idxp, type_T	**type, int	*gen_load_outer, cctx_T	*cctx)






{
    int	    idx;
    char_u  *va_name;

    if (len == 0)
	return FAIL;
    for (idx = 0; idx < cctx->ctx_ufunc->uf_args_visible; ++idx)
    {
	char_u *arg = FUNCARG(cctx->ctx_ufunc, idx);

	if (STRNCMP(name, arg, len) == 0 && arg[len] == NUL)
	{
	    if (idxp != NULL)
	    {
		
		
		*idxp = idx - (cctx->ctx_ufunc->uf_args.ga_len + STACK_FRAME_SIZE)
			      + (cctx->ctx_ufunc->uf_va_name != NULL ? -1 : 0);

		if (cctx->ctx_ufunc->uf_arg_types != NULL)
		    *type = cctx->ctx_ufunc->uf_arg_types[idx];
		else *type = &t_any;
	    }
	    return OK;
	}
    }

    va_name = cctx->ctx_ufunc->uf_va_name;
    if (va_name != NULL && STRNCMP(name, va_name, len) == 0 && va_name[len] == NUL)
    {
	if (idxp != NULL)
	{
	    
	    *idxp = -STACK_FRAME_SIZE - 1;
	    *type = cctx->ctx_ufunc->uf_va_type;
	}
	return OK;
    }

    if (cctx->ctx_outer != NULL)
    {
	
	if (arg_exists(name, len, idxp, type, gen_load_outer, cctx->ctx_outer)
									 == OK)
	{
	    if (gen_load_outer != NULL)
		++*gen_load_outer;
	    return OK;
	}
    }

    return FAIL;
}


    static sallvar_T * find_script_var(char_u *name, size_t len, cctx_T *cctx)
{
    scriptitem_T    *si = SCRIPT_ITEM(current_sctx.sc_sid);
    hashitem_T	    *hi;
    int		    cc;
    sallvar_T	    *sav;
    ufunc_T	    *ufunc;

    
    if (len > 0)
    {
	cc = name[len];
	name[len] = NUL;
    }
    hi = hash_find(&si->sn_all_vars.dv_hashtab, name);
    if (len > 0)
	name[len] = cc;
    if (HASHITEM_EMPTY(hi))
	return NULL;

    sav = HI2SAV(hi);
    if (sav->sav_block_id == 0)
	
	return sav;

    if (cctx == NULL)
    {
	
	
	while (sav != NULL)
	{
	    if (sav->sav_block_id <= si->sn_current_block_id)
		break;
	    sav = sav->sav_next;
	}
	return sav;
    }

    
    
    ufunc = cctx->ctx_ufunc;
    while (sav != NULL)
    {
	int idx;

	
	
	for (idx = 0; idx < ufunc->uf_block_depth; ++idx)
	    if (ufunc->uf_block_ids[idx] == sav->sav_block_id)
		return sav;
	sav = sav->sav_next;
    }

    
    return NULL;
}


    int script_is_vim9()
{
    return SCRIPT_ITEM(current_sctx.sc_sid)->sn_version == SCRIPT_VERSION_VIM9;
}


    int script_var_exists(char_u *name, size_t len, cctx_T *cctx)
{
    if (current_sctx.sc_sid <= 0)
	return FAIL;
    if (script_is_vim9())
    {
	
	
	if (find_script_var(name, len, cctx) != NULL)
	    return OK;
    }
    else {
	hashtab_T	*ht = &SCRIPT_VARS(current_sctx.sc_sid);
	dictitem_T	*di;
	int		cc;

	
	cc = name[len];
	name[len] = NUL;
	di = find_var_in_ht(ht, 0, name, TRUE);
	name[len] = cc;
	if (di != NULL)
	    return OK;
    }

    return FAIL;
}


    static int variable_exists(char_u *name, size_t len, cctx_T *cctx)
{
    return (cctx != NULL && (lookup_local(name, len, NULL, cctx) == OK || arg_exists(name, len, NULL, NULL, NULL, cctx) == OK))

	    || script_var_exists(name, len, cctx) == OK || find_imported(name, len, cctx) != NULL;
}


    static int item_exists(char_u *name, size_t len, int cmd UNUSED, cctx_T *cctx)
{
    int	    is_global;
    char_u  *p;

    if (variable_exists(name, len, cctx))
	return TRUE;

    
    
    
    
    p = skipwhite(name + len);

    if (name[len] == '(' || (p[0] == '-' && p[1] == '>'))
    {
	
	
	
	is_global = (name[0] == 'g' && name[1] == ':');
	return find_func(is_global ? name + 2 : name, is_global, cctx) != NULL;
    }
    return FALSE;
}


    int check_defined(char_u *p, size_t len, cctx_T *cctx, int is_arg)
{
    int		c = p[len];
    ufunc_T	*ufunc = NULL;

    
    if (len == 1 && *p == '_')
	return OK;

    if (script_var_exists(p, len, cctx) == OK)
    {
	if (is_arg)
	    semsg(_(e_argument_already_declared_in_script_str), p);
	else semsg(_(e_variable_already_declared_in_script_str), p);
	return FAIL;
    }

    p[len] = NUL;
    if ((cctx != NULL && (lookup_local(p, len, NULL, cctx) == OK || arg_exists(p, len, NULL, NULL, NULL, cctx) == OK))

	    || find_imported(p, len, cctx) != NULL || (ufunc = find_func_even_dead(p, FALSE, cctx)) != NULL)
    {
	
	if (ufunc == NULL || ((ufunc->uf_flags & FC_DEAD) == 0 && (!func_is_global(ufunc)
					     || (p[0] == 'g' && p[1] == ':'))))
	{
	    if (is_arg)
		semsg(_(e_argument_name_shadows_existing_variable_str), p);
	    else semsg(_(e_name_already_defined_str), p);
	    p[len] = c;
	    return FAIL;
	}
    }
    p[len] = c;
    return OK;
}



    static int use_typecheck(type_T *actual, type_T *expected)
{
    if (actual->tt_type == VAR_ANY || actual->tt_type == VAR_UNKNOWN || (actual->tt_type == VAR_FUNC && (expected->tt_type == VAR_FUNC || expected->tt_type == VAR_PARTIAL)



		&& (actual->tt_member == &t_any || actual->tt_member == &t_unknown || actual->tt_argcount < 0)

		&& (actual->tt_member == &t_unknown || (actual->tt_member == &t_void)
					 == (expected->tt_member == &t_void))))
	return TRUE;
    if ((actual->tt_type == VAR_LIST || actual->tt_type == VAR_DICT)
				       && actual->tt_type == expected->tt_type)
	
	return use_typecheck(actual->tt_member, expected->tt_member);
    return FALSE;
}


    static int need_type_where( type_T	*actual, type_T	*expected, int	offset, where_T	where, cctx_T	*cctx, int	silent, int	actual_is_const)







{
    int ret;

    if (expected == &t_bool && actual != &t_bool && (actual->tt_flags & TTFLAG_BOOL_OK))
    {
	
	
	generate_2BOOL(cctx, FALSE, offset);
	return OK;
    }

    ret = check_type_maybe(expected, actual, FALSE, where);
    if (ret == OK)
	return OK;

    
    
    if (!actual_is_const && ret == MAYBE && use_typecheck(actual, expected))
    {
	generate_TYPECHECK(cctx, expected, offset, where.wt_index);
	return OK;
    }

    if (!silent)
	type_mismatch_where(expected, actual, where);
    return FAIL;
}

    int need_type( type_T	*actual, type_T	*expected, int	offset, int	arg_idx, cctx_T	*cctx, int	silent, int	actual_is_const)







{
    where_T where = WHERE_INIT;

    where.wt_index = arg_idx;
    return need_type_where(actual, expected, offset, where, cctx, silent, actual_is_const);
}


    lvar_T * reserve_local( cctx_T	*cctx, char_u	*name, size_t	len, int	isConst, type_T	*type)





{
    lvar_T  *lvar;
    dfunc_T *dfunc;

    if (arg_exists(name, len, NULL, NULL, NULL, cctx) == OK)
    {
	emsg_namelen(_(e_str_is_used_as_argument), name, (int)len);
	return NULL;
    }

    if (GA_GROW_FAILS(&cctx->ctx_locals, 1))
	return NULL;
    lvar = ((lvar_T *)cctx->ctx_locals.ga_data) + cctx->ctx_locals.ga_len++;
    CLEAR_POINTER(lvar);

    
    
    
    
    dfunc = ((dfunc_T *)def_functions.ga_data) + cctx->ctx_ufunc->uf_dfunc_idx;
    lvar->lv_idx = dfunc->df_var_names.ga_len;

    lvar->lv_name = vim_strnsave(name, len == 0 ? STRLEN(name) : len);
    lvar->lv_const = isConst;
    lvar->lv_type = type;

    
    if (GA_GROW_FAILS(&dfunc->df_var_names, 1))
	return NULL;
    ((char_u **)dfunc->df_var_names.ga_data)[lvar->lv_idx] = vim_strsave(lvar->lv_name);
    ++dfunc->df_var_names.ga_len;

    return lvar;
}


    static int check_item_writable(svar_T *sv, int check_writable, char_u *name)
{
    if ((check_writable == ASSIGN_CONST && sv->sv_const != 0)
	    || (check_writable == ASSIGN_FINAL && sv->sv_const == ASSIGN_CONST))
    {
	semsg(_(e_cannot_change_readonly_variable_str), name);
	return FAIL;
    }
    return OK;
}


    int get_script_item_idx(int sid, char_u *name, int check_writable, cctx_T *cctx)
{
    hashtab_T	    *ht;
    dictitem_T	    *di;
    scriptitem_T    *si = SCRIPT_ITEM(sid);
    svar_T	    *sv;
    int		    idx;

    if (!SCRIPT_ID_VALID(sid))
	return -1;
    if (sid == current_sctx.sc_sid)
    {
	sallvar_T *sav = find_script_var(name, 0, cctx);

	if (sav == NULL)
	    return -2;
	idx = sav->sav_var_vals_idx;
	sv = ((svar_T *)si->sn_var_vals.ga_data) + idx;
	if (check_item_writable(sv, check_writable, name) == FAIL)
	    return -2;
	return idx;
    }

    
    ht = &SCRIPT_VARS(sid);
    di = find_var_in_ht(ht, 0, name, TRUE);
    if (di == NULL)
	return -2;

    
    for (idx = 0; idx < si->sn_var_vals.ga_len; ++idx)
    {
	sv = ((svar_T *)si->sn_var_vals.ga_data) + idx;
	if (sv->sv_tv == &di->di_tv)
	{
	    if (check_item_writable(sv, check_writable, name) == FAIL)
		return -2;
	    return idx;
	}
    }
    return -1;
}


    imported_T * find_imported(char_u *name, size_t len, cctx_T *cctx)
{
    int		    idx;

    if (!SCRIPT_ID_VALID(current_sctx.sc_sid))
	return NULL;
    if (cctx != NULL)
	for (idx = 0; idx < cctx->ctx_imports.ga_len; ++idx)
	{
	    imported_T *import = ((imported_T *)cctx->ctx_imports.ga_data)
									 + idx;

	    if (len == 0 ? STRCMP(name, import->imp_name) == 0 : STRLEN(import->imp_name) == len && STRNCMP(name, import->imp_name, len) == 0)

		return import;
	}

    return find_imported_in_script(name, len, current_sctx.sc_sid);
}

    imported_T * find_imported_in_script(char_u *name, size_t len, int sid)
{
    scriptitem_T    *si;
    int		    idx;

    if (!SCRIPT_ID_VALID(sid))
	return NULL;
    si = SCRIPT_ITEM(sid);
    for (idx = 0; idx < si->sn_imports.ga_len; ++idx)
    {
	imported_T *import = ((imported_T *)si->sn_imports.ga_data) + idx;

	if (len == 0 ? STRCMP(name, import->imp_name) == 0 : STRLEN(import->imp_name) == len && STRNCMP(name, import->imp_name, len) == 0)

	    return import;
    }
    return NULL;
}


    static void free_imported(cctx_T *cctx)
{
    int idx;

    for (idx = 0; idx < cctx->ctx_imports.ga_len; ++idx)
    {
	imported_T *import = ((imported_T *)cctx->ctx_imports.ga_data) + idx;

	vim_free(import->imp_name);
    }
    ga_clear(&cctx->ctx_imports);
}


    char_u * may_peek_next_line(cctx_T *cctx, char_u *arg, char_u **nextp)
{
    char_u *p = skipwhite(arg);

    *nextp = NULL;
    if (*p == NUL || (VIM_ISWHITE(*arg) && vim9_comment_start(p)))
    {
	*nextp = peek_next_line_from_context(cctx);
	if (*nextp != NULL)
	    return *nextp;
    }
    return p;
}


    char_u * peek_next_line_from_context(cctx_T *cctx)
{
    int lnum = cctx->ctx_lnum;

    while (++lnum < cctx->ctx_ufunc->uf_lines.ga_len)
    {
	char_u *line = ((char_u **)cctx->ctx_ufunc->uf_lines.ga_data)[lnum];
	char_u *p;

	
	if (line != NULL)
	{
	    p = skipwhite(line);
	    if (vim9_bad_comment(p))
		return NULL;
	    if (*p != NUL && !vim9_comment_start(p))
		return p;
	}
    }
    return NULL;
}


    char_u * next_line_from_context(cctx_T *cctx, int skip_comment)
{
    char_u	*line;

    do {
	++cctx->ctx_lnum;
	if (cctx->ctx_lnum >= cctx->ctx_ufunc->uf_lines.ga_len)
	{
	    line = NULL;
	    break;
	}
	line = ((char_u **)cctx->ctx_ufunc->uf_lines.ga_data)[cctx->ctx_lnum];
	cctx->ctx_line_start = line;
	SOURCING_LNUM = cctx->ctx_lnum + 1;
    } while (line == NULL || *skipwhite(line) == NUL || (skip_comment && vim9_comment_start(skipwhite(line))));
    return line;
}


    int may_get_next_line(char_u *whitep, char_u **arg, cctx_T *cctx)
{
    *arg = skipwhite(whitep);
    if (vim9_bad_comment(*arg))
	return FAIL;
    if (**arg == NUL || (VIM_ISWHITE(*whitep) && vim9_comment_start(*arg)))
    {
	char_u *next = next_line_from_context(cctx, TRUE);

	if (next == NULL)
	    return FAIL;
	*arg = skipwhite(next);
    }
    return OK;
}


    int may_get_next_line_error(char_u *whitep, char_u **arg, cctx_T *cctx)
{
    if (may_get_next_line(whitep, arg, cctx) == FAIL)
    {
	SOURCING_LNUM = cctx->ctx_lnum + 1;
	emsg(_(e_line_incomplete));
	return FAIL;
    }
    return OK;
}


    static char_u * exarg_getline( int c UNUSED, void *cookie, int indent UNUSED, getline_opt_T options UNUSED)




{
    cctx_T  *cctx = (cctx_T *)cookie;
    char_u  *p;

    for (;;)
    {
	if (cctx->ctx_lnum >= cctx->ctx_ufunc->uf_lines.ga_len - 1)
	    return NULL;
	++cctx->ctx_lnum;
	p = ((char_u **)cctx->ctx_ufunc->uf_lines.ga_data)[cctx->ctx_lnum];
	
	if (p != NULL)
	    return vim_strsave(p);
    }
}

    void fill_exarg_from_cctx(exarg_T *eap, cctx_T *cctx)
{
    eap->getline = exarg_getline;
    eap->cookie = cctx;
}


    int func_needs_compiling(ufunc_T *ufunc, compiletype_T compile_type)
{
    switch (ufunc->uf_def_status)
    {
	case UF_TO_BE_COMPILED:
	    return TRUE;

	case UF_COMPILED:
	{
	    dfunc_T *dfunc = ((dfunc_T *)def_functions.ga_data)
							 + ufunc->uf_dfunc_idx;

	    switch (compile_type)
	    {
		case CT_PROFILE:

		    return dfunc->df_instr_prof == NULL;

		case CT_NONE:
		    return dfunc->df_instr == NULL;
		case CT_DEBUG:
		    return dfunc->df_instr_debug == NULL;
	    }
	}

	case UF_NOT_COMPILED:
	case UF_COMPILE_ERROR:
	case UF_COMPILING:
	    break;
    }
    return FALSE;
}


    static char_u * compile_nested_function(exarg_T *eap, cctx_T *cctx, char_u **line_to_free)
{
    int		is_global = *eap->arg == 'g' && eap->arg[1] == ':';
    char_u	*name_start = eap->arg;
    char_u	*name_end = to_name_end(eap->arg, TRUE);
    int		off;
    char_u	*func_name;
    char_u	*lambda_name;
    ufunc_T	*ufunc;
    int		r = FAIL;
    compiletype_T   compile_type;

    if (eap->forceit)
    {
	emsg(_(e_cannot_use_bang_with_nested_def));
	return NULL;
    }

    if (*name_start == '/')
    {
	name_end = skip_regexp(name_start + 1, '/', TRUE);
	if (*name_end == '/')
	    ++name_end;
	set_nextcmd(eap, name_end);
    }
    if (name_end == name_start || *skipwhite(name_end) != '(')
    {
	if (!ends_excmd2(name_start, name_end))
	{
	    semsg(_(e_invalid_command_str), eap->cmd);
	    return NULL;
	}

	
	if (generate_DEF(cctx, name_start, name_end - name_start) == FAIL)
	    return NULL;
	return eap->nextcmd == NULL ? (char_u *)"" : eap->nextcmd;
    }

    
    if (name_start[1] == ':' && !is_global)
    {
	semsg(_(e_namespace_not_supported_str), name_start);
	return NULL;
    }
    if (check_defined(name_start, name_end - name_start, cctx, FALSE) == FAIL)
	return NULL;

    eap->arg = name_end;
    fill_exarg_from_cctx(eap, cctx);

    eap->forceit = FALSE;
    
    lambda_name = vim_strsave(get_lambda_name());
    if (lambda_name == NULL)
	return NULL;

    
    off = is_global ? 2 : 0;
    func_name = vim_strnsave(name_start + off, name_end - name_start - off);
    if (func_name == NULL)
    {
	r = FAIL;
	goto theend;
    }

    ufunc = define_function(eap, lambda_name, line_to_free);
    if (ufunc == NULL)
    {
	r = eap->skip ? OK : FAIL;
	goto theend;
    }
    if (eap->nextcmd != NULL)
    {
	semsg(_(e_text_found_after_str_str), eap->cmdidx == CMD_def ? "enddef" : "endfunction", eap->nextcmd);
	r = FAIL;
	func_ptr_unref(ufunc);
	goto theend;
    }

    
    if (!is_global && cctx->ctx_ufunc->uf_block_depth > 0)
    {
	int block_depth = cctx->ctx_ufunc->uf_block_depth;

	ufunc->uf_block_ids = ALLOC_MULT(int, block_depth);
	if (ufunc->uf_block_ids != NULL)
	{
	    mch_memmove(ufunc->uf_block_ids, cctx->ctx_ufunc->uf_block_ids, sizeof(int) * block_depth);
	    ufunc->uf_block_depth = block_depth;
	}
    }

    compile_type = COMPILE_TYPE(ufunc);

    
    
    if (cctx->ctx_compile_type == CT_PROFILE)
	compile_type = CT_PROFILE;

    if (func_needs_compiling(ufunc, compile_type)
	    && compile_def_function(ufunc, TRUE, compile_type, cctx) == FAIL)
    {
	func_ptr_unref(ufunc);
	goto theend;
    }


    
    
    if (compile_type == CT_PROFILE && func_needs_compiling(ufunc, CT_NONE))
	compile_def_function(ufunc, FALSE, CT_NONE, cctx);


    if (is_global)
    {
	r = generate_NEWFUNC(cctx, lambda_name, func_name);
	func_name = NULL;
	lambda_name = NULL;
    }
    else {
	
	lvar_T	*lvar = reserve_local(cctx, func_name, name_end - name_start, TRUE, ufunc->uf_func_type);

	if (lvar == NULL)
	    goto theend;
	if (generate_FUNCREF(cctx, ufunc) == FAIL)
	    goto theend;
	r = generate_STORE(cctx, ISN_STORE, lvar->lv_idx, NULL);
    }

theend:
    vim_free(lambda_name);
    vim_free(func_name);
    return r == FAIL ? NULL : (char_u *)"";
}


    int assignment_len(char_u *p, int *heredoc)
{
    if (*p == '=')
    {
	if (p[1] == '<' && p[2] == '<')
	{
	    *heredoc = TRUE;
	    return 3;
	}
	return 1;
    }
    if (vim_strchr((char_u *)"+-*/%", *p) != NULL && p[1] == '=')
	return 2;
    if (STRNCMP(p, "..=", 3) == 0)
	return 3;
    return 0;
}


    static void generate_loadvar( cctx_T		*cctx, assign_dest_T	dest, char_u		*name, lvar_T		*lvar, type_T		*type)





{
    switch (dest)
    {
	case dest_option:
	case dest_func_option:
	    generate_LOAD(cctx, ISN_LOADOPT, 0, name, type);
	    break;
	case dest_global:
	    if (vim_strchr(name, AUTOLOAD_CHAR) == NULL)
		generate_LOAD(cctx, ISN_LOADG, 0, name + 2, type);
	    else generate_LOAD(cctx, ISN_LOADAUTO, 0, name, type);
	    break;
	case dest_buffer:
	    generate_LOAD(cctx, ISN_LOADB, 0, name + 2, type);
	    break;
	case dest_window:
	    generate_LOAD(cctx, ISN_LOADW, 0, name + 2, type);
	    break;
	case dest_tab:
	    generate_LOAD(cctx, ISN_LOADT, 0, name + 2, type);
	    break;
	case dest_script:
	    compile_load_scriptvar(cctx, name + (name[1] == ':' ? 2 : 0), NULL, NULL, TRUE);
	    break;
	case dest_env:
	    
	    generate_LOAD(cctx, ISN_LOADENV, 0, name, type);
	    break;
	case dest_reg:
	    generate_LOAD(cctx, ISN_LOADREG, name[1], NULL, &t_string);
	    break;
	case dest_vimvar:
	    generate_LOADV(cctx, name + 2, TRUE);
	    break;
	case dest_local:
	    if (lvar->lv_from_outer > 0)
		generate_LOADOUTER(cctx, lvar->lv_idx, lvar->lv_from_outer, type);
	    else generate_LOAD(cctx, ISN_LOAD, lvar->lv_idx, NULL, type);
	    break;
	case dest_expr:
	    
	    break;
    }
}


    static char_u * skip_index(char_u *start)
{
    char_u *p = start;

    if (*p == '[')
    {
	p = skipwhite(p + 1);
	(void)skip_expr(&p, NULL);
	p = skipwhite(p);
	if (*p == ']')
	    return p + 1;
	return p;
    }
    
    return to_name_end(p + 1, TRUE);
}

    void vim9_declare_error(char_u *name)
{
    char *scope = "";

    switch (*name)
    {
	case 'g': scope = _("global"); break;
	case 'b': scope = _("buffer"); break;
	case 'w': scope = _("window"); break;
	case 't': scope = _("tab"); break;
	case 'v': scope = "v:"; break;
	case '$': semsg(_(e_cannot_declare_an_environment_variable), name);
		  return;
	case '&': semsg(_(e_cannot_declare_an_option), name);
		  return;
	case '@': semsg(_(e_cannot_declare_a_register_str), name);
		  return;
	default: return;
    }
    semsg(_(e_cannot_declare_a_scope_variable), scope, name);
}


    int get_var_dest( char_u		*name, assign_dest_T	*dest, int		cmdidx, int		*option_scope, int		*vimvaridx, type_T		**type, cctx_T		*cctx)







{
    char_u *p;

    if (*name == '&')
    {
	int		cc;
	long		numval;
	getoption_T	opt_type;
	int		opt_p_flags;

	*dest = dest_option;
	if (cmdidx == CMD_final || cmdidx == CMD_const)
	{
	    emsg(_(e_cannot_lock_option));
	    return FAIL;
	}
	p = name;
	p = find_option_end(&p, option_scope);
	if (p == NULL)
	{
	    
	    emsg(_(e_unexpected_characters_in_assignment));
	    return FAIL;
	}
	cc = *p;
	*p = NUL;
	opt_type = get_option_value(skip_option_env_lead(name), &numval, NULL, &opt_p_flags, *option_scope);
	*p = cc;
	switch (opt_type)
	{
	    case gov_unknown:
		    semsg(_(e_unknown_option_str), name);
		    return FAIL;
	    case gov_string:
	    case gov_hidden_string:
		    if (opt_p_flags & P_FUNC)
		    {
			
			*type = &t_any;
			*dest = dest_func_option;
		    }
		    else {
			*type = &t_string;
		    }
		    break;
	    case gov_bool:
	    case gov_hidden_bool:
		    *type = &t_bool;
		    break;
	    case gov_number:
	    case gov_hidden_number:
		    *type = &t_number;
		    break;
	}
    }
    else if (*name == '$')
    {
	*dest = dest_env;
	*type = &t_string;
    }
    else if (*name == '@')
    {
	if (name[1] != '@' && (!valid_yank_reg(name[1], FALSE) || name[1] == '.'))
	{
	    emsg_invreg(name[1]);
	    return FAIL;
	}
	*dest = dest_reg;
	*type = name[1] == '#' ? &t_number_or_string : &t_string;
    }
    else if (STRNCMP(name, "g:", 2) == 0)
    {
	*dest = dest_global;
    }
    else if (STRNCMP(name, "b:", 2) == 0)
    {
	*dest = dest_buffer;
    }
    else if (STRNCMP(name, "w:", 2) == 0)
    {
	*dest = dest_window;
    }
    else if (STRNCMP(name, "t:", 2) == 0)
    {
	*dest = dest_tab;
    }
    else if (STRNCMP(name, "v:", 2) == 0)
    {
	typval_T	*vtv;
	int		di_flags;

	*vimvaridx = find_vim_var(name + 2, &di_flags);
	if (*vimvaridx < 0)
	{
	    semsg(_(e_variable_not_found_str), name);
	    return FAIL;
	}
	
	if (var_check_ro(di_flags, name, FALSE))
	    return FAIL;
	*dest = dest_vimvar;
	vtv = get_vim_var_tv(*vimvaridx);
	*type = typval2type_vimvar(vtv, cctx->ctx_type_list);
    }
    return OK;
}

    static int is_decl_command(int cmdidx)
{
    return cmdidx == CMD_let || cmdidx == CMD_var || cmdidx == CMD_final || cmdidx == CMD_const;
}


    int compile_lhs( char_u	*var_start, lhs_T	*lhs, int	cmdidx, int	heredoc, int	oplen, cctx_T	*cctx)






{
    char_u	*var_end;
    int		is_decl = is_decl_command(cmdidx);

    CLEAR_POINTER(lhs);
    lhs->lhs_dest = dest_local;
    lhs->lhs_vimvaridx = -1;
    lhs->lhs_scriptvar_idx = -1;

    
    
    
    lhs->lhs_dest_end = skip_var_one(var_start, FALSE);
    if (*var_start == '@')
	var_end = var_start + 2;
    else {
	
	var_end = skip_option_env_lead(var_start);
	var_end = to_name_end(var_end, TRUE);
    }

    
    if (is_decl && lhs->lhs_dest_end == var_start + 2 && lhs->lhs_dest_end[-1] == ':')
	--lhs->lhs_dest_end;
    if (is_decl && var_end == var_start + 2 && var_end[-1] == ':')
	--var_end;
    lhs->lhs_end = lhs->lhs_dest_end;

    
    lhs->lhs_varlen = var_end - var_start;
    lhs->lhs_varlen_total = lhs->lhs_varlen;
    lhs->lhs_name = vim_strnsave(var_start, lhs->lhs_varlen);
    if (lhs->lhs_name == NULL)
	return FAIL;

    if (lhs->lhs_dest_end > var_start + lhs->lhs_varlen)
	
	lhs->lhs_has_index = TRUE;

    if (heredoc)
	lhs->lhs_type = &t_list_string;
    else lhs->lhs_type = &t_any;

    if (cctx->ctx_skip != SKIP_YES)
    {
	int	    declare_error = FALSE;

	if (get_var_dest(lhs->lhs_name, &lhs->lhs_dest, cmdidx, &lhs->lhs_opt_flags, &lhs->lhs_vimvaridx, &lhs->lhs_type, cctx) == FAIL)

	    return FAIL;
	if (lhs->lhs_dest != dest_local && cmdidx != CMD_const && cmdidx != CMD_final)
	{
	    
	    declare_error = is_decl;
	}
	else {
	    
	    if (check_reserved_name(lhs->lhs_name) == FAIL)
		return FAIL;

	    if (lookup_local(var_start, lhs->lhs_varlen, &lhs->lhs_local_lvar, cctx) == OK)
		lhs->lhs_lvar = &lhs->lhs_local_lvar;
	    else {
		CLEAR_FIELD(lhs->lhs_arg_lvar);
		if (arg_exists(var_start, lhs->lhs_varlen, &lhs->lhs_arg_lvar.lv_idx, &lhs->lhs_arg_lvar.lv_type, &lhs->lhs_arg_lvar.lv_from_outer, cctx) == OK)

		{
		    if (is_decl)
		    {
			semsg(_(e_str_is_used_as_argument), lhs->lhs_name);
			return FAIL;
		    }
		    lhs->lhs_lvar = &lhs->lhs_arg_lvar;
		}
	    }
	    if (lhs->lhs_lvar != NULL)
	    {
		if (is_decl)
		{
		    semsg(_(e_variable_already_declared), lhs->lhs_name);
		    return FAIL;
		}
	    }
	    else {
		int script_namespace = lhs->lhs_varlen > 1 && STRNCMP(var_start, "s:", 2) == 0;
		int script_var = (script_namespace ? script_var_exists(var_start + 2, lhs->lhs_varlen - 2, cctx)

			  : script_var_exists(var_start, lhs->lhs_varlen, cctx)) == OK;
		imported_T  *import = find_imported(var_start, lhs->lhs_varlen, cctx);

		if (script_namespace || script_var || import != NULL)
		{
		    char_u	*rawname = lhs->lhs_name + (lhs->lhs_name[1] == ':' ? 2 : 0);

		    if (is_decl)
		    {
			if (script_namespace)
			    semsg(_(e_cannot_declare_script_variable_in_function), lhs->lhs_name);
			else semsg(_(e_variable_already_declared_in_script_str), lhs->lhs_name);

			return FAIL;
		    }
		    else if (cctx->ctx_ufunc->uf_script_ctx_version == SCRIPT_VERSION_VIM9 && script_namespace && !script_var && import == NULL)


		    {
			semsg(_(e_unknown_variable_str), lhs->lhs_name);
			return FAIL;
		    }

		    lhs->lhs_dest = dest_script;

		    
		    lhs->lhs_scriptvar_sid = current_sctx.sc_sid;
		    if (import != NULL)
		    {
			char_u	*dot = vim_strchr(var_start, '.');
			char_u	*p;

			
			if (dot == NULL)
			{
			    semsg(_(e_no_dot_after_imported_name_str), var_start);
			    return FAIL;
			}
			p = skipwhite(dot + 1);
			var_end = to_name_end(p, TRUE);
			if (var_end == p)
			{
			    semsg(_(e_missing_name_after_imported_name_str), var_start);
			    return FAIL;
			}
			vim_free(lhs->lhs_name);
			lhs->lhs_varlen = var_end - p;
			lhs->lhs_name = vim_strnsave(p, lhs->lhs_varlen);
			if (lhs->lhs_name == NULL)
			    return FAIL;
			rawname = lhs->lhs_name;
			lhs->lhs_scriptvar_sid = import->imp_sid;
			

			
			
			lhs->lhs_has_index = lhs->lhs_dest_end > skipwhite(var_end);
		    }
		    if (SCRIPT_ID_VALID(lhs->lhs_scriptvar_sid))
		    {
			
			lhs->lhs_scriptvar_idx = get_script_item_idx( lhs->lhs_scriptvar_sid, rawname, lhs->lhs_has_index ? ASSIGN_FINAL : ASSIGN_CONST, cctx);


			if (lhs->lhs_scriptvar_idx >= 0)
			{
			    scriptitem_T *si = SCRIPT_ITEM( lhs->lhs_scriptvar_sid);
			    svar_T	 *sv = ((svar_T *)si->sn_var_vals.ga_data)
						      + lhs->lhs_scriptvar_idx;
			    lhs->lhs_type = sv->sv_type;
			}
		    }
		}
		else if (check_defined(var_start, lhs->lhs_varlen, cctx, FALSE)
								       == FAIL)
		    return FAIL;
	    }
	}

	if (declare_error)
	{
	    vim9_declare_error(lhs->lhs_name);
	    return FAIL;
	}
    }

    
    if (lhs->lhs_varlen > 1 || var_start[lhs->lhs_varlen] != ':')
	var_end = lhs->lhs_dest_end;

    if (lhs->lhs_dest != dest_option && lhs->lhs_dest != dest_func_option)
    {
	if (is_decl && *var_end == ':')
	{
	    char_u *p;

	    
	    if (!VIM_ISWHITE(var_end[1]))
	    {
		semsg(_(e_white_space_required_after_str_str), ":", var_end);
		return FAIL;
	    }
	    p = skipwhite(var_end + 1);
	    lhs->lhs_type = parse_type(&p, cctx->ctx_type_list, TRUE);
	    if (lhs->lhs_type == NULL)
		return FAIL;
	    lhs->lhs_has_type = TRUE;
	    lhs->lhs_end = p;
	}
	else if (lhs->lhs_lvar != NULL)
	    lhs->lhs_type = lhs->lhs_lvar->lv_type;
    }

    if (oplen == 3 && !heredoc && lhs->lhs_dest != dest_global && !lhs->lhs_has_index && lhs->lhs_type->tt_type != VAR_STRING && lhs->lhs_type->tt_type != VAR_ANY)



    {
	emsg(_(e_can_only_concatenate_to_string));
	return FAIL;
    }

    if (lhs->lhs_lvar == NULL && lhs->lhs_dest == dest_local && cctx->ctx_skip != SKIP_YES)
    {
	if (oplen > 1 && !heredoc)
	{
	    
	    semsg(_(e_cannot_use_operator_on_new_variable), lhs->lhs_name);
	    return FAIL;
	}
	if (!is_decl)
	{
	    semsg(_(e_unknown_variable_str), lhs->lhs_name);
	    return FAIL;
	}

	
	if ((lhs->lhs_type->tt_type == VAR_FUNC || lhs->lhs_type->tt_type == VAR_PARTIAL)
		&& var_wrong_func_name(lhs->lhs_name, TRUE))
	    return FAIL;

	
	lhs->lhs_lvar = reserve_local(cctx, var_start, lhs->lhs_varlen, cmdidx == CMD_final || cmdidx == CMD_const, lhs->lhs_type);
	if (lhs->lhs_lvar == NULL)
	    return FAIL;
	lhs->lhs_new_local = TRUE;
    }

    lhs->lhs_member_type = lhs->lhs_type;
    if (lhs->lhs_has_index)
    {
	char_u	*after = var_start + lhs->lhs_varlen;
	char_u	*p;

	
	if (is_decl)
	{
	    emsg(_(e_cannot_use_index_when_declaring_variable));
	    return FAIL;
	}

	
	
	
	
	for (;;)
	{
	    p = skip_index(after);
	    if (*p != '[' && *p != '.')
	    {
		lhs->lhs_varlen_total = p - var_start;
		break;
	    }
	    after = p;
	}
	if (after > var_start + lhs->lhs_varlen)
	{
	    lhs->lhs_varlen = after - var_start;
	    lhs->lhs_dest = dest_expr;
	    
	    
	    lhs->lhs_type = &t_any;
	}

	if (lhs->lhs_type->tt_member == NULL)
	    lhs->lhs_member_type = &t_any;
	else lhs->lhs_member_type = lhs->lhs_type->tt_member;
    }
    return OK;
}


    int compile_assign_lhs( char_u	*var_start, lhs_T	*lhs, int	cmdidx, int	is_decl, int	heredoc, int	oplen, cctx_T	*cctx)







{
    if (compile_lhs(var_start, lhs, cmdidx, heredoc, oplen, cctx) == FAIL)
	return FAIL;

    if (!lhs->lhs_has_index && lhs->lhs_lvar == &lhs->lhs_arg_lvar)
    {
	semsg(_(e_cannot_assign_to_argument), lhs->lhs_name);
	return FAIL;
    }
    if (!is_decl && lhs->lhs_lvar != NULL && lhs->lhs_lvar->lv_const && !lhs->lhs_has_index)
    {
	semsg(_(e_cannot_assign_to_constant), lhs->lhs_name);
	return FAIL;
    }
    return OK;
}


    static int has_list_index(char_u *idx_start, cctx_T *cctx)
{
    char_u  *p = idx_start;
    int	    save_skip;

    if (*p != '[')
	return FALSE;

    p = skipwhite(p + 1);
    if (*p == ':')
	return TRUE;

    save_skip = cctx->ctx_skip;
    cctx->ctx_skip = SKIP_YES;
    (void)compile_expr0(&p, cctx);
    cctx->ctx_skip = save_skip;
    return *skipwhite(p) == ':';
}


    static int compile_assign_index( char_u	*var_start, lhs_T	*lhs, int	*range, cctx_T	*cctx)




{
    size_t	varlen = lhs->lhs_varlen;
    char_u	*p;
    int		r = OK;
    int		need_white_before = TRUE;
    int		empty_second;

    p = var_start + varlen;
    if (*p == '[')
    {
	p = skipwhite(p + 1);
	if (*p == ':')
	{
	    
	    r = generate_PUSHNR(cctx, 0);
	    need_white_before = FALSE;
	}
	else r = compile_expr0(&p, cctx);

	if (r == OK && *skipwhite(p) == ':')
	{
	    
	    
	    *range = TRUE;
	    p = skipwhite(p);
	    empty_second = *skipwhite(p + 1) == ']';
	    if ((need_white_before && !IS_WHITE_OR_NUL(p[-1]))
		    || (!empty_second && !IS_WHITE_OR_NUL(p[1])))
	    {
		semsg(_(e_white_space_required_before_and_after_str_at_str), ":", p);
		return FAIL;
	    }
	    p = skipwhite(p + 1);
	    if (*p == ']')
		
		r = generate_PUSHSPEC(cctx, VVAL_NONE);
	    else r = compile_expr0(&p, cctx);
	}

	if (r == OK && *skipwhite(p) != ']')
	{
	    
	    emsg(_(e_missing_closing_square_brace));
	    r = FAIL;
	}
    }
    else  {
	char_u *key_end = to_name_end(p + 1, TRUE);
	char_u *key = vim_strnsave(p + 1, key_end - p - 1);

	r = generate_PUSHS(cctx, &key);
    }
    return r;
}


    static int compile_load_lhs( lhs_T	*lhs, char_u	*var_start, type_T	*rhs_type, cctx_T	*cctx)




{
    if (lhs->lhs_dest == dest_expr)
    {
	size_t	    varlen = lhs->lhs_varlen;
	int	    c = var_start[varlen];
	int	    lines_len = cctx->ctx_ufunc->uf_lines.ga_len;
	char_u	    *p = var_start;
	int	    res;

	
	
	var_start[varlen] = NUL;
	cctx->ctx_ufunc->uf_lines.ga_len = cctx->ctx_lnum + 1;
	res = compile_expr0(&p, cctx);
	var_start[varlen] = c;
	cctx->ctx_ufunc->uf_lines.ga_len = lines_len;
	if (res == FAIL || p != var_start + varlen)
	{
	    
	    if (res != FAIL)
		emsg(_(e_missing_closing_square_brace));
	    return FAIL;
	}

	lhs->lhs_type = cctx->ctx_type_stack.ga_len == 0 ? &t_void : get_type_on_stack(cctx, 0);
	
	if (rhs_type != NULL && lhs->lhs_type->tt_member != NULL && rhs_type != &t_void && need_type(rhs_type, lhs->lhs_type->tt_member, -2, 0, cctx, FALSE, FALSE) == FAIL)


	    return FAIL;
    }
    else generate_loadvar(cctx, lhs->lhs_dest, lhs->lhs_name, lhs->lhs_lvar, lhs->lhs_type);

    return OK;
}


    int compile_load_lhs_with_index(lhs_T *lhs, char_u *var_start, cctx_T *cctx)
{
    compile_load_lhs(lhs, var_start, NULL, cctx);

    if (lhs->lhs_has_index)
    {
	int range = FALSE;

	
	
	if (compile_assign_index(var_start, lhs, &range, cctx) == FAIL)
	    return FAIL;
	if (range)
	{
	    semsg(_(e_cannot_use_range_with_assignment_operator_str), var_start);
	    return FAIL;
	}

	
	if (compile_member(FALSE, NULL, cctx) == FAIL)
	    return FAIL;
    }
    return OK;
}


    int compile_assign_unlet( char_u	*var_start, lhs_T	*lhs, int	is_assign, type_T	*rhs_type, cctx_T	*cctx)





{
    vartype_T	dest_type;
    int		range = FALSE;

    if (compile_assign_index(var_start, lhs, &range, cctx) == FAIL)
	return FAIL;
    if (is_assign && range && lhs->lhs_type->tt_type != VAR_LIST && lhs->lhs_type != &t_blob && lhs->lhs_type != &t_any)


    {
	semsg(_(e_cannot_use_range_with_assignment_str), var_start);
	return FAIL;
    }

    if (lhs->lhs_type == &t_any)
    {
	
	dest_type = VAR_ANY;
    }
    else {
	dest_type = lhs->lhs_type->tt_type;
	if (dest_type == VAR_DICT && range)
	{
	    emsg(e_cannot_use_range_with_dictionary);
	    return FAIL;
	}
	if (dest_type == VAR_DICT && may_generate_2STRING(-1, FALSE, cctx) == FAIL)
	    return FAIL;
	if (dest_type == VAR_LIST || dest_type == VAR_BLOB)
	{
	    type_T *type;

	    if (range)
	    {
		type = get_type_on_stack(cctx, 1);
		if (need_type(type, &t_number, -1, 0, cctx, FALSE, FALSE) == FAIL)
		return FAIL;
	    }
	    type = get_type_on_stack(cctx, 0);
	    if ((dest_type != VAR_BLOB && type != &t_special)
		    && need_type(type, &t_number, -1, 0, cctx, FALSE, FALSE) == FAIL)
		return FAIL;
	}
    }

    
    
    
    
    
    if (compile_load_lhs(lhs, var_start, rhs_type, cctx) == FAIL)
	return FAIL;

    if (dest_type == VAR_LIST || dest_type == VAR_DICT || dest_type == VAR_BLOB || dest_type == VAR_ANY)
    {
	if (is_assign)
	{
	    if (range)
	    {
		if (generate_instr_drop(cctx, ISN_STORERANGE, 4) == NULL)
		    return FAIL;
	    }
	    else {
		isn_T	*isn = generate_instr_drop(cctx, ISN_STOREINDEX, 3);

		if (isn == NULL)
		    return FAIL;
		isn->isn_arg.vartype = dest_type;
	    }
	}
	else if (range)
	{
	    if (generate_instr_drop(cctx, ISN_UNLETRANGE, 3) == NULL)
		return FAIL;
	}
	else {
	    if (generate_instr_drop(cctx, ISN_UNLETINDEX, 2) == NULL)
		return FAIL;
	}
    }
    else {
	emsg(_(e_indexable_type_required));
	return FAIL;
    }

    return OK;
}


    static char_u * compile_assignment(char_u *arg, exarg_T *eap, cmdidx_T cmdidx, cctx_T *cctx)
{
    char_u	*var_start;
    char_u	*p;
    char_u	*end = arg;
    char_u	*ret = NULL;
    int		var_count = 0;
    int		var_idx;
    int		semicolon = 0;
    int		did_generate_slice = FALSE;
    garray_T	*instr = &cctx->ctx_instr;
    char_u	*op;
    int		oplen = 0;
    int		heredoc = FALSE;
    int		incdec = FALSE;
    type_T	*rhs_type = &t_any;
    char_u	*sp;
    int		is_decl = is_decl_command(cmdidx);
    lhs_T	lhs;
    long	start_lnum = SOURCING_LNUM;

    
    p = skip_var_list(arg, TRUE, &var_count, &semicolon, TRUE);
    if (p == NULL)
	return *arg == '[' ? arg : NULL;

    lhs.lhs_name = NULL;

    sp = p;
    p = skipwhite(p);
    op = p;
    oplen = assignment_len(p, &heredoc);

    if (var_count > 0 && oplen == 0)
	
	return arg;

    if (oplen > 0 && (!VIM_ISWHITE(*sp) || !IS_WHITE_OR_NUL(op[oplen])))
    {
	error_white_both(op, oplen);
	return NULL;
    }
    if (eap->cmdidx == CMD_increment || eap->cmdidx == CMD_decrement)
    {
	if (VIM_ISWHITE(eap->cmd[2]))
	{
	    semsg(_(e_no_white_space_allowed_after_str_str), eap->cmdidx == CMD_increment ? "++" : "--", eap->cmd);
	    return NULL;
	}
	op = (char_u *)(eap->cmdidx == CMD_increment ? "+=" : "-=");
	oplen = 2;
	incdec = TRUE;
    }

    if (heredoc)
    {
	list_T	   *l;
	listitem_T *li;

	
	eap->getline = exarg_getline;
	eap->cookie = cctx;
	l = heredoc_get(eap, op + 3, FALSE);
	if (l == NULL)
	    return NULL;

	if (cctx->ctx_skip != SKIP_YES)
	{
	    
	    FOR_ALL_LIST_ITEMS(l, li)
	    {
		generate_PUSHS(cctx, &li->li_tv.vval.v_string);
		li->li_tv.vval.v_string = NULL;
	    }
	    generate_NEWLIST(cctx, l->lv_len);
	}
	list_free(l);
	p += STRLEN(p);
	end = p;
    }
    else if (var_count > 0)
    {
	char_u *wp;

	
	
	

	wp = op + oplen;
	if (may_get_next_line_error(wp, &p, cctx) == FAIL)
	    return FAIL;
	if (compile_expr0(&p, cctx) == FAIL)
	    return NULL;
	end = p;

	if (cctx->ctx_skip != SKIP_YES)
	{
	    type_T	*stacktype;
	    int		needed_list_len;
	    int		did_check = FALSE;

	    stacktype = cctx->ctx_type_stack.ga_len == 0 ? &t_void : get_type_on_stack(cctx, 0);
	    if (stacktype->tt_type == VAR_VOID)
	    {
		emsg(_(e_cannot_use_void_value));
		goto theend;
	    }
	    if (need_type(stacktype, &t_list_any, -1, 0, cctx, FALSE, FALSE) == FAIL)
		goto theend;
	    
	    needed_list_len = semicolon ? var_count - 1 : var_count;
	    if (instr->ga_len > 0)
	    {
		isn_T	*isn = ((isn_T *)instr->ga_data) + instr->ga_len - 1;

		if (isn->isn_type == ISN_NEWLIST)
		{
		    did_check = TRUE;
		    if (semicolon ? isn->isn_arg.number < needed_list_len : isn->isn_arg.number != needed_list_len)
		    {
			semsg(_(e_expected_nr_items_but_got_nr), needed_list_len, isn->isn_arg.number);
			goto theend;
		    }
		}
	    }
	    if (!did_check)
		generate_CHECKLEN(cctx, needed_list_len, semicolon);
	    if (stacktype->tt_member != NULL)
		rhs_type = stacktype->tt_member;
	}
    }

    
    if (var_count > 0)
	var_start = skipwhite(arg + 1);  
    else var_start = arg;
    for (var_idx = 0; var_idx == 0 || var_idx < var_count; var_idx++)
    {
	int	instr_count = -1;
	int	save_lnum;
	int	skip_store = FALSE;

	if (var_start[0] == '_' && !eval_isnamec(var_start[1]))
	{
	    
	    if (var_count > 0)
	    {
		var_start = skipwhite(var_start + 2);
		continue;
	    }
	    emsg(_(e_cannot_use_underscore_here));
	    goto theend;
	}
	vim_free(lhs.lhs_name);

	
	if (compile_assign_lhs(var_start, &lhs, cmdidx, is_decl, heredoc, oplen, cctx) == FAIL)
	    goto theend;
	if (heredoc)
	{
	    SOURCING_LNUM = start_lnum;
	    if (lhs.lhs_has_type && need_type(&t_list_string, lhs.lhs_type, -1, 0, cctx, FALSE, FALSE) == FAIL)

		goto theend;
	}
	else {
	    if (cctx->ctx_skip == SKIP_YES)
	    {
		if (oplen > 0 && var_count == 0)
		{
		    
		    p = skipwhite(op + oplen);
		    (void)compile_expr0(&p, cctx);
		}
	    }
	    else if (oplen > 0)
	    {
		int	is_const = FALSE;
		char_u	*wp;

		
		if (*op != '=' && compile_load_lhs_with_index(&lhs, var_start, cctx) == FAIL)

		    goto theend;

		
		if (var_count == 0)
		{
		    int	r;

		    
		    instr_count = instr->ga_len;
		    if (incdec)
		    {
			r = generate_PUSHNR(cctx, 1);
		    }
		    else {
			
			
			if (lhs.lhs_new_local)
			    --cctx->ctx_locals.ga_len;
			wp = op + oplen;
			if (may_get_next_line_error(wp, &p, cctx) == FAIL)
			{
			    if (lhs.lhs_new_local)
				++cctx->ctx_locals.ga_len;
			    goto theend;
			}
			r = compile_expr0_ext(&p, cctx, &is_const);
			if (lhs.lhs_new_local)
			    ++cctx->ctx_locals.ga_len;
			if (r == FAIL)
			    goto theend;
		    }
		}
		else if (semicolon && var_idx == var_count - 1)
		{
		    
		    did_generate_slice = TRUE;
		    if (generate_SLICE(cctx, var_count - 1) == FAIL)
			goto theend;
		}
		else {
		    
		    
		    if (generate_GETITEM(cctx, var_idx, *op != '=') == FAIL)
			goto theend;
		}

		rhs_type = cctx->ctx_type_stack.ga_len == 0 ? &t_void : get_type_on_stack(cctx, 0);
		if (lhs.lhs_lvar != NULL && (is_decl || !lhs.lhs_has_type))
		{
		    if ((rhs_type->tt_type == VAR_FUNC || rhs_type->tt_type == VAR_PARTIAL)
			    && !lhs.lhs_has_index && var_wrong_func_name(lhs.lhs_name, TRUE))
			goto theend;

		    if (lhs.lhs_new_local && !lhs.lhs_has_type)
		    {
			if (rhs_type->tt_type == VAR_VOID)
			{
			    emsg(_(e_cannot_use_void_value));
			    goto theend;
			}
			else {
			    
			    
			    if (rhs_type == &t_list_empty)
				lhs.lhs_lvar->lv_type = &t_list_any;
			    else if (rhs_type == &t_dict_empty)
				lhs.lhs_lvar->lv_type = &t_dict_any;
			    else if (rhs_type == &t_unknown)
				lhs.lhs_lvar->lv_type = &t_any;
			    else lhs.lhs_lvar->lv_type = rhs_type;
			}
		    }
		    else if (*op == '=')
		    {
			type_T *use_type = lhs.lhs_lvar->lv_type;
			where_T where = WHERE_INIT;

			
			
			SOURCING_LNUM = start_lnum;
			where.wt_index = var_count > 0 ? var_idx + 1 : 0;
			where.wt_variable = var_count > 0;
			
			
			if (lhs.lhs_has_index && !has_list_index(var_start + lhs.lhs_varlen, cctx))

			    use_type = lhs.lhs_member_type;
			if (need_type_where(rhs_type, use_type, -1, where, cctx, FALSE, is_const) == FAIL)
			    goto theend;
		    }
		}
		else {
		    type_T *lhs_type = lhs.lhs_member_type;

		    
		    
		    
		    if ((lhs_type == &t_number_or_string || lhs_type == &t_float)
			    && rhs_type->tt_type == VAR_NUMBER)
			lhs_type = &t_number;
		    if (*p != '=' && need_type(rhs_type, lhs_type, -1, 0, cctx, FALSE, FALSE) == FAIL)
		    goto theend;
		}
	    }
	    else if (cmdidx == CMD_final)
	    {
		emsg(_(e_final_requires_a_value));
		goto theend;
	    }
	    else if (cmdidx == CMD_const)
	    {
		emsg(_(e_const_requires_a_value));
		goto theend;
	    }
	    else if (!lhs.lhs_has_type || lhs.lhs_dest == dest_option || lhs.lhs_dest == dest_func_option)
	    {
		emsg(_(e_type_or_initialization_required));
		goto theend;
	    }
	    else {
		
		if (GA_GROW_FAILS(instr, 1))
		    goto theend;
		switch (lhs.lhs_member_type->tt_type)
		{
		    case VAR_BOOL:
			generate_PUSHBOOL(cctx, VVAL_FALSE);
			break;
		    case VAR_FLOAT:

			generate_PUSHF(cctx, 0.0);

			break;
		    case VAR_STRING:
			generate_PUSHS(cctx, NULL);
			break;
		    case VAR_BLOB:
			generate_PUSHBLOB(cctx, blob_alloc());
			break;
		    case VAR_FUNC:
			generate_PUSHFUNC(cctx, NULL, &t_func_void);
			break;
		    case VAR_LIST:
			generate_NEWLIST(cctx, 0);
			break;
		    case VAR_DICT:
			generate_NEWDICT(cctx, 0);
			break;
		    case VAR_JOB:
			generate_PUSHJOB(cctx, NULL);
			break;
		    case VAR_CHANNEL:
			generate_PUSHCHANNEL(cctx, NULL);
			break;
		    case VAR_NUMBER:
		    case VAR_UNKNOWN:
		    case VAR_ANY:
		    case VAR_PARTIAL:
		    case VAR_VOID:
		    case VAR_INSTR:
		    case VAR_SPECIAL:  
			
			
			if (lhs.lhs_dest == dest_local)
			    skip_store = TRUE;
			else generate_PUSHNR(cctx, 0);
			break;
		}
	    }
	    if (var_count == 0)
		end = p;
	}

	
	if (cctx->ctx_skip == SKIP_YES)
	    break;

	if (oplen > 0 && *op != '=')
	{
	    type_T	    *expected;
	    type_T	    *stacktype = NULL;

	    if (*op == '.')
	    {
		if (may_generate_2STRING(-1, FALSE, cctx) == FAIL)
		    goto theend;
	    }
	    else {
		expected = lhs.lhs_member_type;
		stacktype = get_type_on_stack(cctx, 0);
		if (   !(expected == &t_float && (stacktype == &t_number || stacktype == &t_number_bool)) &&  need_type(stacktype, expected, -1, 0, cctx, FALSE, FALSE) == FAIL)






		    goto theend;
	    }

	    if (*op == '.')
	    {
		if (generate_instr_drop(cctx, ISN_CONCAT, 1) == NULL)
		    goto theend;
	    }
	    else if (*op == '+')
	    {
		if (generate_add_instr(cctx, operator_type(lhs.lhs_member_type, stacktype), lhs.lhs_member_type, stacktype, EXPR_APPEND) == FAIL)


		    goto theend;
	    }
	    else if (generate_two_op(cctx, op) == FAIL)
		goto theend;
	}

	
	save_lnum = cctx->ctx_lnum;
	cctx->ctx_lnum = start_lnum - 1;

	if (lhs.lhs_has_index)
	{
	    
	    
	    if (compile_assign_unlet(var_start, &lhs, TRUE, rhs_type, cctx)
								       == FAIL)
	    {
		cctx->ctx_lnum = save_lnum;
		goto theend;
	    }
	}
	else {
	    if (is_decl && cmdidx == CMD_const && (lhs.lhs_dest == dest_script || lhs.lhs_dest == dest_global || lhs.lhs_dest == dest_local))

		
		generate_LOCKCONST(cctx);

	    if ((lhs.lhs_type->tt_type == VAR_DICT || lhs.lhs_type->tt_type == VAR_LIST)
		    && lhs.lhs_type->tt_member != NULL && lhs.lhs_type->tt_member != &t_unknown)
		
		
		generate_SETTYPE(cctx, lhs.lhs_type);

	    if (!skip_store && generate_store_lhs(cctx, &lhs, instr_count, is_decl) == FAIL)
	    {
		cctx->ctx_lnum = save_lnum;
		goto theend;
	    }
	}
	cctx->ctx_lnum = save_lnum;

	if (var_idx + 1 < var_count)
	    var_start = skipwhite(lhs.lhs_end + 1);
    }

    
    
    if (var_count > 0 && (!semicolon || !did_generate_slice))
    {
	if (generate_instr_drop(cctx, ISN_DROP, 1) == NULL)
	    goto theend;
    }

    ret = skipwhite(end);

theend:
    vim_free(lhs.lhs_name);
    return ret;
}


    static int may_compile_assignment(exarg_T *eap, char_u **line, cctx_T *cctx)
{
    char_u  *pskip;
    char_u  *p;

    
    
    
    
    pskip = (*eap->cmd == '&' || *eap->cmd == '$' || *eap->cmd == '@')
						 ? eap->cmd + 1 : eap->cmd;
    p = to_name_end(pskip, TRUE);
    if (p > eap->cmd && *p != NUL)
    {
	char_u *var_end;
	int	oplen;
	int	heredoc;

	if (eap->cmd[0] == '@')
	    var_end = eap->cmd + 2;
	else var_end = find_name_end(pskip, NULL, NULL, FNE_CHECK_START | FNE_INCL_BR);

	oplen = assignment_len(skipwhite(var_end), &heredoc);
	if (oplen > 0)
	{
	    size_t len = p - eap->cmd;

	    
	    
	    
	    
	    
	    
	    
	    
	    
	    if (*eap->cmd == '&' || *eap->cmd == '$' || *eap->cmd == '@' || ((len) > 2 && eap->cmd[1] == ':')


		    || variable_exists(eap->cmd, len, cctx))
	    {
		*line = compile_assignment(eap->cmd, eap, CMD_SIZE, cctx);
		if (*line == NULL || *line == eap->cmd)
		    return FAIL;
		return OK;
	    }
	}
    }

    if (*eap->cmd == '[')
    {
	
	*line = compile_assignment(eap->cmd, eap, CMD_SIZE, cctx);
	if (*line == NULL)
	    return FAIL;
	if (*line != eap->cmd)
	    return OK;
    }
    return NOTDONE;
}


    static int check_args_shadowing(ufunc_T *ufunc, cctx_T *cctx)
{
    int	    i;
    char_u  *arg;
    int	    r = OK;

    
    ufunc->uf_args_visible = 0;

    
    for (i = 0; i < ufunc->uf_args.ga_len; ++i)
    {
	arg = ((char_u **)(ufunc->uf_args.ga_data))[i];
	if (check_defined(arg, STRLEN(arg), cctx, TRUE) == FAIL)
	{
	    r = FAIL;
	    break;
	}
    }
    ufunc->uf_args_visible = ufunc->uf_args.ga_len;
    return r;
}



    static int add_def_function(ufunc_T *ufunc)
{
    dfunc_T *dfunc;

    if (def_functions.ga_len == 0)
    {
	
	
	if (GA_GROW_FAILS(&def_functions, 1))
	    return FAIL;
	++def_functions.ga_len;
    }

    
    if (GA_GROW_FAILS(&def_functions, 1))
	return FAIL;
    dfunc = ((dfunc_T *)def_functions.ga_data) + def_functions.ga_len;
    CLEAR_POINTER(dfunc);
    dfunc->df_idx = def_functions.ga_len;
    ufunc->uf_dfunc_idx = dfunc->df_idx;
    dfunc->df_ufunc = ufunc;
    dfunc->df_name = vim_strsave(ufunc->uf_name);
    ga_init2(&dfunc->df_var_names, sizeof(char_u *), 10);
    ++dfunc->df_refcount;
    ++def_functions.ga_len;
    return OK;
}


    int compile_def_function( ufunc_T		*ufunc, int		check_return_type, compiletype_T   compile_type, cctx_T		*outer_cctx)




{
    char_u	*line = NULL;
    char_u	*line_to_free = NULL;
    char_u	*p;
    char	*errormsg = NULL;	
    cctx_T	cctx;
    garray_T	*instr;
    int		did_emsg_before = did_emsg;
    int		did_emsg_silent_before = did_emsg_silent;
    int		ret = FAIL;
    sctx_T	save_current_sctx = current_sctx;
    int		save_estack_compiling = estack_compiling;
    int		save_cmod_flags = cmdmod.cmod_flags;
    int		do_estack_push;
    int		new_def_function = FALSE;

    int		prof_lnum = -1;

    int		debug_lnum = -1;

    
    
    if (ufunc->uf_dfunc_idx > 0)
    {
	dfunc_T *dfunc = ((dfunc_T *)def_functions.ga_data)
							 + ufunc->uf_dfunc_idx;
	isn_T	*instr_dest = NULL;

	switch (compile_type)
	{
	    case CT_PROFILE:

			    instr_dest = dfunc->df_instr_prof; break;

	    case CT_NONE:   instr_dest = dfunc->df_instr; break;
	    case CT_DEBUG:  instr_dest = dfunc->df_instr_debug; break;
	}
	if (instr_dest != NULL)
	    
	    delete_def_function_contents(dfunc, FALSE);
	ga_clear_strings(&dfunc->df_var_names);
    }
    else {
	if (add_def_function(ufunc) == FAIL)
	    return FAIL;
	new_def_function = TRUE;
    }

    ufunc->uf_def_status = UF_COMPILING;

    CLEAR_FIELD(cctx);

    cctx.ctx_compile_type = compile_type;
    cctx.ctx_ufunc = ufunc;
    cctx.ctx_lnum = -1;
    cctx.ctx_outer = outer_cctx;
    ga_init2(&cctx.ctx_locals, sizeof(lvar_T), 10);
    
    ga_init2(&cctx.ctx_type_stack, sizeof(type2_T), 50);
    ga_init2(&cctx.ctx_imports, sizeof(imported_T), 10);
    cctx.ctx_type_list = &ufunc->uf_type_list;
    ga_init2(&cctx.ctx_instr, sizeof(isn_T), 50);
    instr = &cctx.ctx_instr;

    
    
    
    current_sctx = ufunc->uf_script_ctx;
    current_sctx.sc_version = SCRIPT_VERSION_VIM9;

    
    cmdmod.cmod_flags &= ~CMOD_LEGACY;

    
    do_estack_push = !estack_top_is_ufunc(ufunc, 1);
    if (do_estack_push)
	estack_push_ufunc(ufunc, 1);
    estack_compiling = TRUE;

    if (check_args_shadowing(ufunc, &cctx) == FAIL)
	goto erret;

    if (ufunc->uf_def_args.ga_len > 0)
    {
	int	count = ufunc->uf_def_args.ga_len;
	int	first_def_arg = ufunc->uf_args.ga_len - count;
	int	i;
	char_u	*arg;
	int	off = STACK_FRAME_SIZE + (ufunc->uf_va_name != NULL ? 1 : 0);
	int	did_set_arg_type = FALSE;

	
	SOURCING_LNUM = 0;  
	for (i = 0; i < count; ++i)
	{
	    type_T	*val_type;
	    int		arg_idx = first_def_arg + i;
	    where_T	where = WHERE_INIT;
	    int		r;
	    int		jump_instr_idx = instr->ga_len;
	    isn_T	*isn;

	    
	    if (generate_JUMP_IF_ARG_SET(&cctx, i - count - off) == FAIL)
		goto erret;

	    
	    ufunc->uf_args_visible = arg_idx;

	    arg = ((char_u **)(ufunc->uf_def_args.ga_data))[i];
	    r = compile_expr0(&arg, &cctx);

	    if (r == FAIL)
		goto erret;

	    
	    
	    
	    val_type = get_type_on_stack(&cctx, 0);
	    where.wt_index = arg_idx + 1;
	    if (ufunc->uf_arg_types[arg_idx] == &t_unknown)
	    {
		did_set_arg_type = TRUE;
		ufunc->uf_arg_types[arg_idx] = val_type;
	    }
	    else if (need_type_where(val_type, ufunc->uf_arg_types[arg_idx], -1, where, &cctx, FALSE, FALSE) == FAIL)
		goto erret;

	    if (generate_STORE(&cctx, ISN_STORE, i - count - off, NULL) == FAIL)
		goto erret;

	    
	    isn = ((isn_T *)instr->ga_data) + jump_instr_idx;
	    isn->isn_arg.jumparg.jump_where = instr->ga_len;
	}

	if (did_set_arg_type)
	    set_function_type(ufunc);
    }
    ufunc->uf_args_visible = ufunc->uf_args.ga_len;

    
    for (;;)
    {
	exarg_T	    ea;
	int	    starts_with_colon = FALSE;
	char_u	    *cmd;
	cmdmod_T    local_cmdmod;

	
	
	if (did_emsg_before != did_emsg)
	    goto erret;

	if (line != NULL && *line == '|')
	    
	    ++line;
	else if (line != NULL && *skipwhite(line) != NUL && !(*line == '#' && (line == cctx.ctx_line_start || VIM_ISWHITE(line[-1]))))

	{
	    semsg(_(e_trailing_characters_str), line);
	    goto erret;
	}
	else if (line != NULL && vim9_bad_comment(skipwhite(line)))
	    goto erret;
	else {
	    line = next_line_from_context(&cctx, FALSE);
	    if (cctx.ctx_lnum >= ufunc->uf_lines.ga_len)
	    {
		

		if (cctx.ctx_skip != SKIP_YES)
		    may_generate_prof_end(&cctx, prof_lnum);

		break;
	    }
	    
	    
	    if (line != NULL)
	    {
		line = vim_strsave(line);
		vim_free(line_to_free);
		line_to_free = line;
	    }
	}

	CLEAR_FIELD(ea);
	ea.cmdlinep = &line;
	ea.cmd = skipwhite(line);

	if (*ea.cmd == '#')
	{
	    
	    line = (char_u *)"";
	    continue;
	}


	if (cctx.ctx_compile_type == CT_PROFILE && cctx.ctx_lnum != prof_lnum && cctx.ctx_skip != SKIP_YES)
	{
	    may_generate_prof_end(&cctx, prof_lnum);

	    prof_lnum = cctx.ctx_lnum;
	    generate_instr(&cctx, ISN_PROF_START);
	}

	if (cctx.ctx_compile_type == CT_DEBUG && cctx.ctx_lnum != debug_lnum && cctx.ctx_skip != SKIP_YES)
	{
	    debug_lnum = cctx.ctx_lnum;
	    generate_instr_debug(&cctx);
	}
	cctx.ctx_prev_lnum = cctx.ctx_lnum + 1;

	
	switch (*ea.cmd)
	{
	    case '}':
		{
		    
		    scopetype_T stype = cctx.ctx_scope == NULL ? NO_SCOPE : cctx.ctx_scope->se_type;

		    if (stype == BLOCK_SCOPE)
		    {
			compile_endblock(&cctx);
			line = ea.cmd;
		    }
		    else {
			emsg(_(e_using_rcurly_outside_if_block_scope));
			goto erret;
		    }
		    if (line != NULL)
			line = skipwhite(ea.cmd + 1);
		    continue;
		}

	    case '{':
		
		
		if (ends_excmd(*skipwhite(ea.cmd + 1)))
		{
		    line = compile_block(ea.cmd, &cctx);
		    continue;
		}
		break;
	}

	
	cctx.ctx_has_cmdmod = FALSE;
	if (parse_command_modifiers(&ea, &errormsg, &local_cmdmod, FALSE)
								       == FAIL)
	{
	    if (errormsg != NULL)
		goto erret;
	    
	    line = (char_u *)"";
	    continue;
	}
	generate_cmdmods(&cctx, &local_cmdmod);
	undo_cmdmod(&local_cmdmod);

	
	
	for (p = ea.cmd; p >= line; --p)
	{
	    if (*p == ':')
		starts_with_colon = TRUE;
	    if (p < ea.cmd && !VIM_ISWHITE(*p))
		break;
	}

	
	p = ea.cmd;
	if (!(local_cmdmod.cmod_flags & CMOD_LEGACY))
	{
	    if (checkforcmd(&ea.cmd, "call", 3))
	    {
		if (*ea.cmd == '(')
		    
		    ea.cmd = p;
		else ea.cmd = skipwhite(ea.cmd);
	    }

	    if (!starts_with_colon)
	    {
		int	    assign;

		
		assign = may_compile_assignment(&ea, &line, &cctx);
		if (assign == OK)
		    goto nextline;
		if (assign == FAIL)
		    goto erret;
	    }
	}

	
	cmd = ea.cmd;
	if ((*cmd != '$' || starts_with_colon)
		&& (starts_with_colon || !(*cmd == '\'' || (cmd[0] != NUL && cmd[0] == cmd[1] && (*cmd == '+' || *cmd == '-')))))

	{
	    ea.cmd = skip_range(ea.cmd, TRUE, NULL);
	    if (ea.cmd > cmd)
	    {
		if (!starts_with_colon && !(local_cmdmod.cmod_flags & CMOD_LEGACY))
		{
		    semsg(_(e_colon_required_before_range_str), cmd);
		    goto erret;
		}
		ea.addr_count = 1;
		if (ends_excmd2(line, ea.cmd))
		{
		    
		    generate_EXEC(&cctx, ISN_EXECRANGE, vim_strnsave(cmd, ea.cmd - cmd));
		    line = ea.cmd;
		    goto nextline;
		}
	    }
	}
	p = find_ex_command(&ea, NULL, starts_with_colon || (local_cmdmod.cmod_flags & CMOD_LEGACY)
						  ? NULL : item_exists, &cctx);

	if (p == NULL)
	{
	    if (cctx.ctx_skip != SKIP_YES)
		emsg(_(e_ambiguous_use_of_user_defined_command));
	    goto erret;
	}

	
	if (local_cmdmod.cmod_flags & CMOD_LEGACY)
	{
	    char_u *start = ea.cmd;

	    switch (ea.cmdidx)
	    {
		case CMD_if:
		case CMD_elseif:
		case CMD_else:
		case CMD_endif:
		case CMD_for:
		case CMD_endfor:
		case CMD_continue:
		case CMD_break:
		case CMD_while:
		case CMD_endwhile:
		case CMD_try:
		case CMD_catch:
		case CMD_finally:
		case CMD_endtry:
			semsg(_(e_cannot_use_legacy_with_command_str), ea.cmd);
			goto erret;
		default: break;
	    }

	    
	    if (checkforcmd(&start, "return", 4))
		ea.cmdidx = CMD_return;
	    else ea.cmdidx = CMD_legacy;
	}

	if (p == ea.cmd && ea.cmdidx != CMD_SIZE)
	{
	    if (cctx.ctx_skip == SKIP_YES && ea.cmdidx != CMD_eval)
	    {
		line += STRLEN(line);
		goto nextline;
	    }
	    else if (ea.cmdidx != CMD_eval)
	    {
		
		
		semsg(_(e_command_not_recognized_str), ea.cmd);
		goto erret;
	    }
	}

	if (cctx.ctx_had_return && ea.cmdidx != CMD_elseif && ea.cmdidx != CMD_else && ea.cmdidx != CMD_endif && ea.cmdidx != CMD_endfor && ea.cmdidx != CMD_endwhile && ea.cmdidx != CMD_catch && ea.cmdidx != CMD_finally && ea.cmdidx != CMD_endtry)







	{
	    emsg(_(e_unreachable_code_after_return));
	    goto erret;
	}

	p = skipwhite(p);
	if (ea.cmdidx != CMD_SIZE && ea.cmdidx != CMD_write && ea.cmdidx != CMD_read)
	{
	    if (ea.cmdidx >= 0)
		ea.argt = excmd_get_argt(ea.cmdidx);
	    if ((ea.argt & EX_BANG) && *p == '!')
	    {
		ea.forceit = TRUE;
		p = skipwhite(p + 1);
	    }
	}

	switch (ea.cmdidx)
	{
	    case CMD_def:
	    case CMD_function:
		    ea.arg = p;
		    line = compile_nested_function(&ea, &cctx, &line_to_free);
		    break;

	    case CMD_return:
		    line = compile_return(p, check_return_type, local_cmdmod.cmod_flags & CMOD_LEGACY, &cctx);
		    cctx.ctx_had_return = TRUE;
		    break;

	    case CMD_let:
		    emsg(_(e_cannot_use_let_in_vim9_script));
		    break;
	    case CMD_var:
	    case CMD_final:
	    case CMD_const:
	    case CMD_increment:
	    case CMD_decrement:
		    line = compile_assignment(p, &ea, ea.cmdidx, &cctx);
		    if (line == p)
			line = NULL;
		    break;

	    case CMD_unlet:
	    case CMD_unlockvar:
	    case CMD_lockvar:
		    line = compile_unletlock(p, &ea, &cctx);
		    break;

	    case CMD_import:
		    emsg(_(e_import_can_only_be_used_in_script));
		    line = NULL;
		    break;

	    case CMD_if:
		    line = compile_if(p, &cctx);
		    break;
	    case CMD_elseif:
		    line = compile_elseif(p, &cctx);
		    cctx.ctx_had_return = FALSE;
		    break;
	    case CMD_else:
		    line = compile_else(p, &cctx);
		    cctx.ctx_had_return = FALSE;
		    break;
	    case CMD_endif:
		    line = compile_endif(p, &cctx);
		    break;

	    case CMD_while:
		    line = compile_while(p, &cctx);
		    break;
	    case CMD_endwhile:
		    line = compile_endwhile(p, &cctx);
		    cctx.ctx_had_return = FALSE;
		    break;

	    case CMD_for:
		    line = compile_for(p, &cctx);
		    break;
	    case CMD_endfor:
		    line = compile_endfor(p, &cctx);
		    cctx.ctx_had_return = FALSE;
		    break;
	    case CMD_continue:
		    line = compile_continue(p, &cctx);
		    break;
	    case CMD_break:
		    line = compile_break(p, &cctx);
		    break;

	    case CMD_try:
		    line = compile_try(p, &cctx);
		    break;
	    case CMD_catch:
		    line = compile_catch(p, &cctx);
		    cctx.ctx_had_return = FALSE;
		    break;
	    case CMD_finally:
		    line = compile_finally(p, &cctx);
		    cctx.ctx_had_return = FALSE;
		    break;
	    case CMD_endtry:
		    line = compile_endtry(p, &cctx);
		    cctx.ctx_had_return = FALSE;
		    break;
	    case CMD_throw:
		    line = compile_throw(p, &cctx);
		    break;

	    case CMD_eval:
		    line = compile_eval(p, &cctx);
		    break;

	    case CMD_echo:
	    case CMD_echon:
	    case CMD_execute:
	    case CMD_echomsg:
	    case CMD_echoerr:
	    case CMD_echoconsole:
		    line = compile_mult_expr(p, ea.cmdidx, &cctx);
		    break;

	    case CMD_put:
		    ea.cmd = cmd;
		    line = compile_put(p, &ea, &cctx);
		    break;

	    case CMD_substitute:
		    if (check_global_and_subst(ea.cmd, p) == FAIL)
			goto erret;
		    if (cctx.ctx_skip == SKIP_YES)
			line = (char_u *)"";
		    else {
			ea.arg = p;
			line = compile_substitute(line, &ea, &cctx);
		    }
		    break;

	    case CMD_redir:
		    ea.arg = p;
		    line = compile_redir(line, &ea, &cctx);
		    break;

	    case CMD_cexpr:
	    case CMD_lexpr:
	    case CMD_caddexpr:
	    case CMD_laddexpr:
	    case CMD_cgetexpr:
	    case CMD_lgetexpr:

		    ea.arg = p;
		    line = compile_cexpr(line, &ea, &cctx);

		    ex_ni(&ea);
		    line = NULL;

		    break;

	    case CMD_append:
	    case CMD_change:
	    case CMD_insert:
	    case CMD_k:
	    case CMD_t:
	    case CMD_xit:
		    not_in_vim9(&ea);
		    goto erret;

	    case CMD_SIZE:
		    if (cctx.ctx_skip != SKIP_YES)
		    {
			semsg(_(e_invalid_command_str), ea.cmd);
			goto erret;
		    }
		    
		    line = (char_u *)"";
		    break;

	    case CMD_lua:
	    case CMD_mzscheme:
	    case CMD_perl:
	    case CMD_py3:
	    case CMD_python3:
	    case CMD_python:
	    case CMD_pythonx:
	    case CMD_ruby:
	    case CMD_tcl:
		    ea.arg = p;
		    if (vim_strchr(line, '\n') == NULL)
			line = compile_exec(line, &ea, &cctx);
		    else   line = compile_script(line, &cctx);


		    break;

	    case CMD_global:
		    if (check_global_and_subst(ea.cmd, p) == FAIL)
			goto erret;
		    
	    default:
		    
		    ea.arg = p;
		    line = compile_exec(line, &ea, &cctx);
		    break;
	}
nextline:
	if (line == NULL)
	    goto erret;
	line = skipwhite(line);

	
	generate_undo_cmdmods(&cctx);

	if (cctx.ctx_type_stack.ga_len < 0)
	{
	    iemsg("Type stack underflow");
	    goto erret;
	}
    }

    if (cctx.ctx_scope != NULL)
    {
	if (cctx.ctx_scope->se_type == IF_SCOPE)
	    emsg(_(e_missing_endif));
	else if (cctx.ctx_scope->se_type == WHILE_SCOPE)
	    emsg(_(e_missing_endwhile));
	else if (cctx.ctx_scope->se_type == FOR_SCOPE)
	    emsg(_(e_missing_endfor));
	else emsg(_(e_missing_rcurly));
	goto erret;
    }

    if (!cctx.ctx_had_return)
    {
	if (ufunc->uf_ret_type->tt_type == VAR_UNKNOWN)
	    ufunc->uf_ret_type = &t_void;
	else if (ufunc->uf_ret_type->tt_type != VAR_VOID)
	{
	    emsg(_(e_missing_return_statement));
	    goto erret;
	}

	
	generate_instr(&cctx, ISN_RETURN_VOID);
    }

    
    
    if (emsg_silent == 0 || did_emsg_silent == did_emsg_silent_before)
    {
	dfunc_T	*dfunc = ((dfunc_T *)def_functions.ga_data)
							 + ufunc->uf_dfunc_idx;
	dfunc->df_deleted = FALSE;
	dfunc->df_script_seq = current_sctx.sc_seq;

	if (cctx.ctx_compile_type == CT_PROFILE)
	{
	    dfunc->df_instr_prof = instr->ga_data;
	    dfunc->df_instr_prof_count = instr->ga_len;
	}
	else  if (cctx.ctx_compile_type == CT_DEBUG)

	{
	    dfunc->df_instr_debug = instr->ga_data;
	    dfunc->df_instr_debug_count = instr->ga_len;
	}
	else {
	    dfunc->df_instr = instr->ga_data;
	    dfunc->df_instr_count = instr->ga_len;
	}
	dfunc->df_varcount = dfunc->df_var_names.ga_len;
	dfunc->df_has_closure = cctx.ctx_has_closure;
	if (cctx.ctx_outer_used)
	    ufunc->uf_flags |= FC_CLOSURE;
	ufunc->uf_def_status = UF_COMPILED;
    }

    ret = OK;

erret:
    if (ufunc->uf_def_status == UF_COMPILING)
    {
	dfunc_T	*dfunc = ((dfunc_T *)def_functions.ga_data)
							 + ufunc->uf_dfunc_idx;

	
	clear_instr_ga(instr);
	VIM_CLEAR(dfunc->df_name);
	ga_clear_strings(&dfunc->df_var_names);

	
	
	if (!dfunc->df_deleted && new_def_function && ufunc->uf_dfunc_idx == def_functions.ga_len - 1)
	{
	    --def_functions.ga_len;
	    ufunc->uf_dfunc_idx = 0;
	}
	ufunc->uf_def_status = UF_COMPILE_ERROR;

	while (cctx.ctx_scope != NULL)
	    drop_scope(&cctx);

	if (errormsg != NULL)
	    emsg(errormsg);
	else if (did_emsg == did_emsg_before)
	    emsg(_(e_compiling_def_function_failed));
    }

    if (cctx.ctx_redir_lhs.lhs_name != NULL)
    {
	if (ret == OK)
	{
	    emsg(_(e_missing_redir_end));
	    ret = FAIL;
	}
	vim_free(cctx.ctx_redir_lhs.lhs_name);
	vim_free(cctx.ctx_redir_lhs.lhs_whole);
    }

    current_sctx = save_current_sctx;
    estack_compiling = save_estack_compiling;
    cmdmod.cmod_flags =	save_cmod_flags;
    if (do_estack_push)
	estack_pop();

    vim_free(line_to_free);
    free_imported(&cctx);
    free_locals(&cctx);
    ga_clear(&cctx.ctx_type_stack);
    return ret;
}

    void set_function_type(ufunc_T *ufunc)
{
    int varargs = ufunc->uf_va_name != NULL;
    int argcount = ufunc->uf_args.ga_len;

    
    
    
    
    if (argcount > 0 || varargs)
    {
	if (ufunc->uf_type_list.ga_itemsize == 0)
	    ga_init2(&ufunc->uf_type_list, sizeof(type_T *), 10);
	ufunc->uf_func_type = alloc_func_type(ufunc->uf_ret_type, argcount, &ufunc->uf_type_list);
	
	if (func_type_add_arg_types(ufunc->uf_func_type, argcount + varargs, &ufunc->uf_type_list) == FAIL)

	    return;
	ufunc->uf_func_type->tt_argcount = argcount + varargs;
	ufunc->uf_func_type->tt_min_argcount = argcount - ufunc->uf_def_args.ga_len;
	if (ufunc->uf_arg_types == NULL)
	{
	    int i;

	    
	    for (i = 0; i < argcount; ++i)
		ufunc->uf_func_type->tt_args[i] = &t_any;
	}
	else mch_memmove(ufunc->uf_func_type->tt_args, ufunc->uf_arg_types, sizeof(type_T *) * argcount);

	if (varargs)
	{
	    ufunc->uf_func_type->tt_args[argcount] = ufunc->uf_va_type == NULL ? &t_list_any : ufunc->uf_va_type;
	    ufunc->uf_func_type->tt_flags = TTFLAG_VARARGS;
	}
    }
    else  ufunc->uf_func_type = get_func_type(ufunc->uf_ret_type, argcount, &ufunc->uf_type_list);


}


    static void delete_def_function_contents(dfunc_T *dfunc, int mark_deleted)
{
    int idx;

    ga_clear(&dfunc->df_def_args_isn);
    ga_clear_strings(&dfunc->df_var_names);

    if (dfunc->df_instr != NULL)
    {
	for (idx = 0; idx < dfunc->df_instr_count; ++idx)
	    delete_instr(dfunc->df_instr + idx);
	VIM_CLEAR(dfunc->df_instr);
	dfunc->df_instr = NULL;
    }
    if (dfunc->df_instr_debug != NULL)
    {
	for (idx = 0; idx < dfunc->df_instr_debug_count; ++idx)
	    delete_instr(dfunc->df_instr_debug + idx);
	VIM_CLEAR(dfunc->df_instr_debug);
	dfunc->df_instr_debug = NULL;
    }

    if (dfunc->df_instr_prof != NULL)
    {
	for (idx = 0; idx < dfunc->df_instr_prof_count; ++idx)
	    delete_instr(dfunc->df_instr_prof + idx);
	VIM_CLEAR(dfunc->df_instr_prof);
	dfunc->df_instr_prof = NULL;
    }


    if (mark_deleted)
	dfunc->df_deleted = TRUE;
    if (dfunc->df_ufunc != NULL)
	dfunc->df_ufunc->uf_def_status = UF_NOT_COMPILED;
}


    void unlink_def_function(ufunc_T *ufunc)
{
    if (ufunc->uf_dfunc_idx > 0)
    {
	dfunc_T *dfunc = ((dfunc_T *)def_functions.ga_data)
							 + ufunc->uf_dfunc_idx;

	if (--dfunc->df_refcount <= 0)
	    delete_def_function_contents(dfunc, TRUE);
	ufunc->uf_def_status = UF_NOT_COMPILED;
	ufunc->uf_dfunc_idx = 0;
	if (dfunc->df_ufunc == ufunc)
	    dfunc->df_ufunc = NULL;
    }
}


    void link_def_function(ufunc_T *ufunc)
{
    if (ufunc->uf_dfunc_idx > 0)
    {
	dfunc_T *dfunc = ((dfunc_T *)def_functions.ga_data)
							 + ufunc->uf_dfunc_idx;

	++dfunc->df_refcount;
    }
}



    void free_def_functions(void)
{
    int idx;

    for (idx = 0; idx < def_functions.ga_len; ++idx)
    {
	dfunc_T *dfunc = ((dfunc_T *)def_functions.ga_data) + idx;

	delete_def_function_contents(dfunc, TRUE);
	vim_free(dfunc->df_name);
    }

    ga_clear(&def_functions);
}




