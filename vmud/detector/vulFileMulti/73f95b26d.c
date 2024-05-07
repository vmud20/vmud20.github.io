














    static int current_instr_idx(cctx_T *cctx)
{
    garray_T	*instr = &cctx->ctx_instr;
    int		idx = instr->ga_len;

    while (idx > 0)
    {
	if (cctx->ctx_has_cmdmod && ((isn_T *)instr->ga_data)[idx - 1] .isn_type == ISN_CMDMOD)
	{
	    --idx;
	    continue;
	}

	if (((isn_T *)instr->ga_data)[idx - 1].isn_type == ISN_PROF_START)
	{
	    --idx;
	    continue;
	}

	if (((isn_T *)instr->ga_data)[idx - 1].isn_type == ISN_DEBUG)
	{
	    --idx;
	    continue;
	}
	break;
    }
    return idx;
}

    static void unwind_locals(cctx_T *cctx, int new_top, int keep)
{
    if (cctx->ctx_locals.ga_len > new_top)
	for (int idx = new_top; idx < cctx->ctx_locals.ga_len; ++idx)
	{
	    lvar_T *lvar = ((lvar_T *)cctx->ctx_locals.ga_data) + idx;
	    VIM_CLEAR(lvar->lv_name);
	}
    if (!keep)
	cctx->ctx_locals.ga_len = new_top;
}


    void free_locals(cctx_T *cctx)
{
    unwind_locals(cctx, 0, FALSE);
    ga_clear(&cctx->ctx_locals);
}



    int check_vim9_unlet(char_u *name)
{
    if (*name == NUL)
    {
	semsg(_(e_argument_required_for_str), "unlet");
	return FAIL;
    }

    if (name[1] != ':' || vim_strchr((char_u *)"gwtb", *name) == NULL)
    {
	
	if (*name == 's' && !script_is_vim9())
	    return OK;
	semsg(_(e_cannot_unlet_str), name);
	return FAIL;
    }
    return OK;
}


    static int compile_unlet( lval_T  *lvp, char_u  *name_end, exarg_T *eap, int	    deep UNUSED, void    *coookie)





{
    cctx_T	*cctx = coookie;
    char_u	*p = lvp->ll_name;
    int		cc = *name_end;
    int		ret = OK;

    if (cctx->ctx_skip == SKIP_YES)
	return OK;

    *name_end = NUL;
    if (*p == '$')
    {
	
	ret = generate_UNLET(cctx, ISN_UNLETENV, p + 1, eap->forceit);
    }
    else if (vim_strchr(p, '.') != NULL || vim_strchr(p, '[') != NULL)
    {
	lhs_T	    lhs;

	
	
	
	
	
	
	
	ret = compile_lhs(p, &lhs, CMD_unlet, FALSE, FALSE, 0, cctx);

	
	
	if (ret == OK)
	{
	    if (!lhs.lhs_has_index)
	    {
		semsg(_(e_cannot_unlet_imported_item_str), p);
		ret = FAIL;
	    }
	    else ret = compile_assign_unlet(p, &lhs, FALSE, &t_void, cctx);
	}

	vim_free(lhs.lhs_name);
    }
    else if (check_vim9_unlet(p) == FAIL)
    {
	ret = FAIL;
    }
    else {
	
	ret = generate_UNLET(cctx, ISN_UNLET, p, eap->forceit);
    }

    *name_end = cc;
    return ret;
}


    static int compile_lock_unlock( lval_T  *lvp, char_u  *name_end, exarg_T *eap, int	    deep, void    *coookie)





{
    cctx_T	*cctx = coookie;
    int		cc = *name_end;
    char_u	*p = lvp->ll_name;
    int		ret = OK;
    size_t	len;
    char_u	*buf;
    isntype_T	isn = ISN_EXEC;
    char	*cmd = eap->cmdidx == CMD_lockvar ? "lockvar" : "unlockvar";

    if (cctx->ctx_skip == SKIP_YES)
	return OK;

    if (*p == NUL)
    {
	semsg(_(e_argument_required_for_str), cmd);
	return FAIL;
    }

    
    if (p[1] != ':')
    {
	char_u *end = find_name_end(p, NULL, NULL, FNE_CHECK_START);

	if (lookup_local(p, end - p, NULL, cctx) == OK)
	{
	    char_u *s = p;

	    if (*end != '.' && *end != '[')
	    {
		emsg(_(e_cannot_lock_unlock_local_variable));
		return FAIL;
	    }

	    
	    
	    if (compile_load(&s, end, cctx, FALSE, FALSE) == FAIL)
		return FAIL;
	    isn = ISN_LOCKUNLOCK;
	}
    }

    
    *name_end = NUL;
    len = name_end - p + 20;
    buf = alloc(len);
    if (buf == NULL)
	ret = FAIL;
    else {
	if (deep < 0)
	    vim_snprintf((char *)buf, len, "%s! %s", cmd, p);
	else vim_snprintf((char *)buf, len, "%s %d %s", cmd, deep, p);
	ret = generate_EXEC_copy(cctx, isn, buf);

	vim_free(buf);
	*name_end = cc;
    }
    return ret;
}


    char_u * compile_unletlock(char_u *arg, exarg_T *eap, cctx_T *cctx)
{
    int	    deep = 0;
    char_u  *p = arg;

    if (eap->cmdidx != CMD_unlet)
    {
	if (eap->forceit)
	    deep = -1;
	else if (vim_isdigit(*p))
	{
	    deep = getdigits(&p);
	    p = skipwhite(p);
	}
	else deep = 2;
    }

    ex_unletlock(eap, p, deep, GLV_NO_AUTOLOAD | GLV_COMPILING, eap->cmdidx == CMD_unlet ? compile_unlet : compile_lock_unlock, cctx);

    return eap->nextcmd == NULL ? (char_u *)"" : eap->nextcmd;
}


    static int compile_jump_to_end( endlabel_T  **el, jumpwhen_T  when, int	    funcref_idx, cctx_T	    *cctx)




{
    garray_T	*instr = &cctx->ctx_instr;
    endlabel_T  *endlabel = ALLOC_CLEAR_ONE(endlabel_T);

    if (endlabel == NULL)
	return FAIL;
    endlabel->el_next = *el;
    *el = endlabel;
    endlabel->el_end_label = instr->ga_len;

    if (when == JUMP_WHILE_FALSE)
	generate_WHILE(cctx, funcref_idx);
    else generate_JUMP(cctx, when, 0);
    return OK;
}

    static void compile_fill_jump_to_end(endlabel_T **el, int jump_where, cctx_T *cctx)
{
    garray_T	*instr = &cctx->ctx_instr;

    while (*el != NULL)
    {
	endlabel_T  *cur = (*el);
	isn_T	    *isn;

	isn = ((isn_T *)instr->ga_data) + cur->el_end_label;
	isn->isn_arg.jump.jump_where = jump_where;
	*el = cur->el_next;
	vim_free(cur);
    }
}

    static void compile_free_jump_to_end(endlabel_T **el)
{
    while (*el != NULL)
    {
	endlabel_T  *cur = (*el);

	*el = cur->el_next;
	vim_free(cur);
    }
}


    static scope_T * new_scope(cctx_T *cctx, scopetype_T type)
{
    scope_T *scope = ALLOC_CLEAR_ONE(scope_T);

    if (scope == NULL)
	return NULL;
    scope->se_outer = cctx->ctx_scope;
    cctx->ctx_scope = scope;
    scope->se_type = type;
    scope->se_local_count = cctx->ctx_locals.ga_len;
    if (scope->se_outer != NULL)
	scope->se_loop_depth = scope->se_outer->se_loop_depth;
    return scope;
}


    void drop_scope(cctx_T *cctx)
{
    scope_T *scope = cctx->ctx_scope;

    if (scope == NULL)
    {
	iemsg("calling drop_scope() without a scope");
	return;
    }
    cctx->ctx_scope = scope->se_outer;
    switch (scope->se_type)
    {
	case IF_SCOPE:
	    compile_free_jump_to_end(&scope->se_u.se_if.is_end_label); break;
	case FOR_SCOPE:
	    compile_free_jump_to_end(&scope->se_u.se_for.fs_end_label); break;
	case WHILE_SCOPE:
	    compile_free_jump_to_end(&scope->se_u.se_while.ws_end_label); break;
	case TRY_SCOPE:
	    compile_free_jump_to_end(&scope->se_u.se_try.ts_end_label); break;
	case NO_SCOPE:
	case BLOCK_SCOPE:
	    break;
    }
    vim_free(scope);
}

    static int misplaced_cmdmod(cctx_T *cctx)
{
    garray_T	*instr = &cctx->ctx_instr;

    if (cctx->ctx_has_cmdmod && ((isn_T *)instr->ga_data)[instr->ga_len - 1].isn_type == ISN_CMDMOD)

    {
	emsg(_(e_misplaced_command_modifier));
	return TRUE;
    }
    return FALSE;
}


    char_u * compile_if(char_u *arg, cctx_T *cctx)
{
    char_u	*p = arg;
    garray_T	*instr = &cctx->ctx_instr;
    int		instr_count = instr->ga_len;
    scope_T	*scope;
    skip_T	skip_save = cctx->ctx_skip;
    ppconst_T	ppconst;

    CLEAR_FIELD(ppconst);
    if (compile_expr1(&p, cctx, &ppconst) == FAIL)
    {
	clear_ppconst(&ppconst);
	return NULL;
    }
    if (!ends_excmd2(arg, skipwhite(p)))
    {
	semsg(_(e_trailing_characters_str), p);
	return NULL;
    }
    if (cctx->ctx_skip == SKIP_YES)
	clear_ppconst(&ppconst);
    else if (instr->ga_len == instr_count && ppconst.pp_used == 1)
    {
	int error = FALSE;
	int v;

	
	v = tv_get_bool_chk(&ppconst.pp_tv[0], &error);
	clear_ppconst(&ppconst);
	if (error)
	    return NULL;
	cctx->ctx_skip = v ? SKIP_NOT : SKIP_YES;
    }
    else {
	
	cctx->ctx_skip = SKIP_UNKNOWN;
	if (generate_ppconst(cctx, &ppconst) == FAIL)
	    return NULL;
	if (bool_on_stack(cctx) == FAIL)
	    return NULL;
    }

    
    generate_undo_cmdmods(cctx);

    scope = new_scope(cctx, IF_SCOPE);
    if (scope == NULL)
	return NULL;
    scope->se_skip_save = skip_save;
    
    scope->se_u.se_if.is_had_return = TRUE;

    if (cctx->ctx_skip == SKIP_UNKNOWN)
    {
	
	scope->se_u.se_if.is_if_label = instr->ga_len;
	generate_JUMP(cctx, JUMP_IF_FALSE, 0);
    }
    else scope->se_u.se_if.is_if_label = -1;


    if (cctx->ctx_compile_type == CT_PROFILE && cctx->ctx_skip == SKIP_YES && skip_save != SKIP_YES)
    {
	
	
	cctx->ctx_skip = SKIP_NOT;
	generate_instr(cctx, ISN_PROF_END);
	cctx->ctx_skip = SKIP_YES;
    }


    return p;
}

    char_u * compile_elseif(char_u *arg, cctx_T *cctx)
{
    char_u	*p = arg;
    garray_T	*instr = &cctx->ctx_instr;
    int		instr_count;
    isn_T	*isn;
    scope_T	*scope = cctx->ctx_scope;
    ppconst_T	ppconst;
    skip_T	save_skip = cctx->ctx_skip;

    if (scope == NULL || scope->se_type != IF_SCOPE)
    {
	emsg(_(e_elseif_without_if));
	return NULL;
    }
    unwind_locals(cctx, scope->se_local_count, TRUE);
    if (!cctx->ctx_had_return)
	scope->se_u.se_if.is_had_return = FALSE;

    if (cctx->ctx_skip == SKIP_NOT)
    {
	
	cctx->ctx_skip = SKIP_YES;
	scope->se_u.se_if.is_seen_skip_not = TRUE;
    }
    if (scope->se_u.se_if.is_seen_skip_not)
    {
	
	
	instr->ga_len = current_instr_idx(cctx);

	skip_expr_cctx(&p, cctx);
	return p;
    }

    if (cctx->ctx_skip == SKIP_UNKNOWN)
    {
	int	    moved_cmdmod = FALSE;
	int	    saved_debug = FALSE;
	isn_T	    debug_isn;

	
	if (((isn_T *)instr->ga_data)[instr->ga_len - 1].isn_type == ISN_CMDMOD)
	{
	    if (GA_GROW_FAILS(instr, 1))
		return NULL;
	    ((isn_T *)instr->ga_data)[instr->ga_len] = ((isn_T *)instr->ga_data)[instr->ga_len - 1];
	    --instr->ga_len;
	    moved_cmdmod = TRUE;
	}

	
	
	if (cctx->ctx_compile_type == CT_DEBUG && instr->ga_len > 0 && ((isn_T *)instr->ga_data)[instr->ga_len - 1] .isn_type == ISN_DEBUG)

	{
	    --instr->ga_len;
	    debug_isn = ((isn_T *)instr->ga_data)[instr->ga_len];
	    saved_debug = TRUE;
	}

	if (compile_jump_to_end(&scope->se_u.se_if.is_end_label, JUMP_ALWAYS, 0, cctx) == FAIL)
	    return NULL;
	
	isn = ((isn_T *)instr->ga_data) + scope->se_u.se_if.is_if_label;
	isn->isn_arg.jump.jump_where = instr->ga_len;

	if (moved_cmdmod)
	    ++instr->ga_len;

	if (saved_debug)
	{
	    
	    if (GA_GROW_FAILS(instr, 1))
		return NULL;
	    ((isn_T *)instr->ga_data)[instr->ga_len] = debug_isn;
	    ++instr->ga_len;
	}
    }

    
    CLEAR_FIELD(ppconst);
    if (cctx->ctx_skip == SKIP_YES)
    {
	cctx->ctx_skip = SKIP_UNKNOWN;

	if (cctx->ctx_compile_type == CT_PROFILE)
	    
	    generate_instr(cctx, ISN_PROF_START);

	if (cctx->ctx_compile_type == CT_DEBUG)
	    
	    generate_instr_debug(cctx);
    }

    instr_count = instr->ga_len;
    if (compile_expr1(&p, cctx, &ppconst) == FAIL)
    {
	clear_ppconst(&ppconst);
	return NULL;
    }
    cctx->ctx_skip = save_skip;
    if (!ends_excmd2(arg, skipwhite(p)))
    {
	clear_ppconst(&ppconst);
	semsg(_(e_trailing_characters_str), p);
	return NULL;
    }
    if (scope->se_skip_save == SKIP_YES)
	clear_ppconst(&ppconst);
    else if (instr->ga_len == instr_count && ppconst.pp_used == 1)
    {
	int error = FALSE;
	int v;

	
	v = tv_get_bool_chk(&ppconst.pp_tv[0], &error);
	if (error)
	{
	    clear_ppconst(&ppconst);
	    return NULL;
	}
	cctx->ctx_skip = v ? SKIP_NOT : SKIP_YES;
	clear_ppconst(&ppconst);
	scope->se_u.se_if.is_if_label = -1;
    }
    else {
	
	cctx->ctx_skip = SKIP_UNKNOWN;
	if (generate_ppconst(cctx, &ppconst) == FAIL)
	    return NULL;
	if (bool_on_stack(cctx) == FAIL)
	    return NULL;

	
	generate_undo_cmdmods(cctx);

	
	scope->se_u.se_if.is_if_label = instr->ga_len;
	generate_JUMP(cctx, JUMP_IF_FALSE, 0);
    }

    return p;
}

    char_u * compile_else(char_u *arg, cctx_T *cctx)
{
    char_u	*p = arg;
    garray_T	*instr = &cctx->ctx_instr;
    isn_T	*isn;
    scope_T	*scope = cctx->ctx_scope;

    if (scope == NULL || scope->se_type != IF_SCOPE)
    {
	emsg(_(e_else_without_if));
	return NULL;
    }
    unwind_locals(cctx, scope->se_local_count, TRUE);
    if (!cctx->ctx_had_return)
	scope->se_u.se_if.is_had_return = FALSE;
    scope->se_u.se_if.is_seen_else = TRUE;


    if (cctx->ctx_compile_type == CT_PROFILE)
    {
	if (cctx->ctx_skip == SKIP_NOT && ((isn_T *)instr->ga_data)[instr->ga_len - 1] .isn_type == ISN_PROF_START)

	    
	    
	    --instr->ga_len;
	if (cctx->ctx_skip == SKIP_YES && !scope->se_u.se_if.is_seen_skip_not)
	{
	    
	    
	    cctx->ctx_skip = SKIP_NOT;
	    generate_instr(cctx, ISN_PROF_END);
	    generate_instr(cctx, ISN_PROF_START);
	    cctx->ctx_skip = SKIP_YES;
	}
    }


    if (!scope->se_u.se_if.is_seen_skip_not && scope->se_skip_save != SKIP_YES)
    {
	
	if (cctx->ctx_skip == SKIP_UNKNOWN)
	{
	    if (!cctx->ctx_had_return && compile_jump_to_end(&scope->se_u.se_if.is_end_label, JUMP_ALWAYS, 0, cctx) == FAIL)

		return NULL;
	}

	if (cctx->ctx_skip == SKIP_UNKNOWN)
	{
	    if (scope->se_u.se_if.is_if_label >= 0)
	    {
		
		isn = ((isn_T *)instr->ga_data) + scope->se_u.se_if.is_if_label;
		isn->isn_arg.jump.jump_where = instr->ga_len;
		scope->se_u.se_if.is_if_label = -1;
	    }
	}

	if (cctx->ctx_skip != SKIP_UNKNOWN)
	    cctx->ctx_skip = cctx->ctx_skip == SKIP_YES ? SKIP_NOT : SKIP_YES;
    }

    return p;
}

    char_u * compile_endif(char_u *arg, cctx_T *cctx)
{
    scope_T	*scope = cctx->ctx_scope;
    ifscope_T	*ifscope;
    garray_T	*instr = &cctx->ctx_instr;
    isn_T	*isn;

    if (misplaced_cmdmod(cctx))
	return NULL;

    if (scope == NULL || scope->se_type != IF_SCOPE)
    {
	emsg(_(e_endif_without_if));
	return NULL;
    }
    ifscope = &scope->se_u.se_if;
    unwind_locals(cctx, scope->se_local_count, TRUE);
    if (!cctx->ctx_had_return)
	ifscope->is_had_return = FALSE;

    if (scope->se_u.se_if.is_if_label >= 0)
    {
	
	isn = ((isn_T *)instr->ga_data) + scope->se_u.se_if.is_if_label;
	isn->isn_arg.jump.jump_where = instr->ga_len;
    }
    
    compile_fill_jump_to_end(&ifscope->is_end_label, instr->ga_len, cctx);


    
    
    if (cctx->ctx_compile_type == CT_PROFILE && cctx->ctx_skip == SKIP_YES && scope->se_skip_save != SKIP_YES)
    {
	cctx->ctx_skip = SKIP_NOT;
	generate_instr(cctx, ISN_PROF_START);
    }

    cctx->ctx_skip = scope->se_skip_save;

    
    
    cctx->ctx_had_return = ifscope->is_had_return && ifscope->is_seen_else;

    drop_scope(cctx);
    return arg;
}


    static void compile_fill_loop_info(loop_info_T *loop_info, int funcref_idx, cctx_T *cctx)
{
    loop_info->li_funcref_idx = funcref_idx;
    loop_info->li_local_count = cctx->ctx_locals.ga_len;
    loop_info->li_closure_count = cctx->ctx_closure_count;
}


    char_u * compile_for(char_u *arg_start, cctx_T *cctx)
{
    char_u	*arg;
    char_u	*arg_end;
    char_u	*name = NULL;
    char_u	*p;
    char_u	*wp;
    int		var_count = 0;
    int		var_list = FALSE;
    int		semicolon = FALSE;
    size_t	varlen;
    garray_T	*instr = &cctx->ctx_instr;
    scope_T	*scope;
    forscope_T	*forscope;
    lvar_T	*loop_lvar;	
    int		loop_lvar_idx;
    lvar_T	*funcref_lvar;
    int		funcref_lvar_idx;
    lvar_T	*var_lvar;	
    type_T	*vartype;
    type_T	*item_type = &t_any;
    int		idx;
    int		prev_lnum = cctx->ctx_prev_lnum;

    p = skip_var_list(arg_start, TRUE, &var_count, &semicolon, FALSE);
    if (p == NULL)
	return NULL;
    if (var_count == 0)
	var_count = 1;
    else var_list = TRUE;

    
    wp = p;
    if (may_get_next_line_error(wp, &p, cctx) == FAIL)
	return NULL;
    if (STRNCMP(p, "in", 2) != 0 || !IS_WHITE_OR_NUL(p[2]))
    {
	if (*p == ':' && wp != p)
	    semsg(_(e_no_white_space_allowed_before_colon_str), p);
	else emsg(_(e_missing_in_after_for));
	return NULL;
    }
    wp = p + 2;
    if (may_get_next_line_error(wp, &p, cctx) == FAIL)
	return NULL;

    
    
    if (cctx->ctx_compile_type == CT_DEBUG && instr->ga_len > 0 && ((isn_T *)instr->ga_data)[instr->ga_len - 1] .isn_type == ISN_DEBUG)

    {
	prev_lnum = ((isn_T *)instr->ga_data)[instr->ga_len - 1] .isn_arg.debug.dbg_break_lnum;
    }

    scope = new_scope(cctx, FOR_SCOPE);
    if (scope == NULL)
	return NULL;
    if (scope->se_loop_depth == MAX_LOOP_DEPTH)
    {
	emsg(_(e_loop_nesting_too_deep));
	return NULL;
    }
    ++scope->se_loop_depth;
    forscope = &scope->se_u.se_for;

    
    
    loop_lvar = reserve_local(cctx, (char_u *)"", 0, ASSIGN_VAR, &t_number);
    if (loop_lvar == NULL)
    {
	drop_scope(cctx);
	return NULL;  
    }
    
    loop_lvar_idx = loop_lvar->lv_idx;
    generate_STORENR(cctx, loop_lvar_idx, -1);

    
    
    
    funcref_lvar = reserve_local(cctx, (char_u *)"", 0, ASSIGN_VAR, &t_number);
    if (funcref_lvar == NULL)
    {
	drop_scope(cctx);
	return NULL;  
    }
    
    funcref_lvar_idx = funcref_lvar->lv_idx;

    
    arg = p;
    if (compile_expr0(&arg, cctx) == FAIL)
    {
	drop_scope(cctx);
	return NULL;
    }
    arg_end = arg;

    if (cctx->ctx_skip != SKIP_YES)
    {
	
	
	vartype = get_type_on_stack(cctx, 0);
	if (vartype->tt_type != VAR_LIST && vartype->tt_type != VAR_STRING && vartype->tt_type != VAR_BLOB && vartype->tt_type != VAR_ANY && vartype->tt_type != VAR_UNKNOWN)



	{
	    semsg(_(e_for_loop_on_str_not_supported), vartype_name(vartype->tt_type));
	    drop_scope(cctx);
	    return NULL;
	}

	if (vartype->tt_type == VAR_STRING)
	    item_type = &t_string;
	else if (vartype->tt_type == VAR_BLOB)
	    item_type = &t_number;
	else if (vartype->tt_type == VAR_LIST && vartype->tt_member->tt_type != VAR_ANY)
	{
	    if (!var_list)
		item_type = vartype->tt_member;
	    else if (vartype->tt_member->tt_type == VAR_LIST && vartype->tt_member->tt_member->tt_type != VAR_ANY)
		item_type = vartype->tt_member->tt_member;
	}

	
	generate_undo_cmdmods(cctx);

	
	forscope->fs_top_label = current_instr_idx(cctx);

	if (cctx->ctx_compile_type == CT_DEBUG)
	{
	    int		save_prev_lnum = cctx->ctx_prev_lnum;
	    isn_T	*isn;

	    
	    
	    
	    
	    
	    cctx->ctx_prev_lnum = prev_lnum;
	    isn = generate_instr_debug(cctx);
	    ++isn->isn_arg.debug.dbg_var_names_len;
	    cctx->ctx_prev_lnum = save_prev_lnum;
	}

	generate_FOR(cctx, loop_lvar_idx);

	arg = arg_start;
	if (var_list)
	{
	    generate_UNPACK(cctx, var_count, semicolon);
	    arg = skipwhite(arg + 1);	

	    
	    --cctx->ctx_type_stack.ga_len;

	    
	    for (idx = 0; idx < var_count; ++idx)
	    {
		type_T *type = (semicolon && idx == 0) ? vartype : item_type;

		if (push_type_stack(cctx, type) == FAIL)
		{
		    drop_scope(cctx);
		    return NULL;
		}
	    }
	}

	for (idx = 0; idx < var_count; ++idx)
	{
	    assign_dest_T	dest = dest_local;
	    int			opt_flags = 0;
	    int			vimvaridx = -1;
	    type_T		*type = &t_any;
	    type_T		*lhs_type = &t_any;
	    where_T		where = WHERE_INIT;

	    p = skip_var_one(arg, FALSE);
	    varlen = p - arg;
	    name = vim_strnsave(arg, varlen);
	    if (name == NULL)
		goto failed;
	    if (*p == ':')
	    {
		p = skipwhite(p + 1);
		lhs_type = parse_type(&p, cctx->ctx_type_list, TRUE);
	    }

	    if (get_var_dest(name, &dest, CMD_for, &opt_flags, &vimvaridx, &type, cctx) == FAIL)
		goto failed;
	    if (dest != dest_local)
	    {
		if (generate_store_var(cctx, dest, opt_flags, vimvaridx, 0, 0, type, name) == FAIL)
		    goto failed;
	    }
	    else if (varlen == 1 && *arg == '_')
	    {
		
		if (generate_instr_drop(cctx, ISN_DROP, 1) == NULL)
		    goto failed;
	    }
	    else {
		
		if (STRNCMP(name, "s:", 2) == 0)
		{
		    emsg(_(e_cannot_use_script_variable_in_for_loop));
		    goto failed;
		}

		if (!valid_varname(arg, (int)varlen, FALSE))
		    goto failed;
		if (lookup_local(arg, varlen, NULL, cctx) == OK)
		{
		    semsg(_(e_variable_already_declared), arg);
		    goto failed;
		}

		
		where.wt_index = var_list ? idx + 1 : 0;
		where.wt_variable = TRUE;
		if (lhs_type == &t_any)
		    lhs_type = item_type;
		else if (item_type != &t_unknown && need_type_where(item_type, lhs_type, -1, where, cctx, FALSE, FALSE) == FAIL)

		    goto failed;
		var_lvar = reserve_local(cctx, arg, varlen, ASSIGN_FINAL, lhs_type);
		if (var_lvar == NULL)
		    
		    goto failed;

		if (semicolon && idx == var_count - 1)
		    var_lvar->lv_type = vartype;
		generate_STORE(cctx, ISN_STORE, var_lvar->lv_idx, NULL);
	    }

	    if (*p == ',' || *p == ';')
		++p;
	    arg = skipwhite(p);
	    vim_free(name);
	}

	
	compile_fill_loop_info(&forscope->fs_loop_info, funcref_lvar_idx, cctx);
	forscope->fs_loop_info.li_depth = scope->se_loop_depth - 1;
    }

    return arg_end;

failed:
    vim_free(name);
    drop_scope(cctx);
    return NULL;
}


    static int compile_loop_end(loop_info_T *loop_info, cctx_T *cctx)
{
    if (cctx->ctx_locals.ga_len > loop_info->li_local_count && cctx->ctx_closure_count > loop_info->li_closure_count)
	return generate_ENDLOOP(cctx, loop_info);
    return OK;
}


    char_u * compile_endfor(char_u *arg, cctx_T *cctx)
{
    garray_T	*instr = &cctx->ctx_instr;
    scope_T	*scope = cctx->ctx_scope;
    forscope_T	*forscope;
    isn_T	*isn;

    if (misplaced_cmdmod(cctx))
	return NULL;

    if (scope == NULL || scope->se_type != FOR_SCOPE)
    {
	emsg(_(e_endfor_without_for));
	return NULL;
    }
    forscope = &scope->se_u.se_for;
    cctx->ctx_scope = scope->se_outer;
    if (cctx->ctx_skip != SKIP_YES)
    {
	
	
	if (compile_loop_end(&forscope->fs_loop_info, cctx) == FAIL)
	    return NULL;

	unwind_locals(cctx, scope->se_local_count, FALSE);

	
	generate_JUMP(cctx, JUMP_ALWAYS, forscope->fs_top_label);

	
	
	isn = ((isn_T *)instr->ga_data) + forscope->fs_top_label + (cctx->ctx_compile_type == CT_DEBUG ? 1 : 0);
	isn->isn_arg.forloop.for_end = instr->ga_len;

	
	compile_fill_jump_to_end(&forscope->fs_end_label, instr->ga_len, cctx);

	
	if (generate_instr_drop(cctx, ISN_DROP, 1) == NULL)
	    return NULL;
    }

    vim_free(scope);

    return arg;
}


    char_u * compile_while(char_u *arg, cctx_T *cctx)
{
    char_u	    *p = arg;
    scope_T	    *scope;
    whilescope_T    *whilescope;
    lvar_T	    *funcref_lvar;
    int		    funcref_lvar_idx;

    scope = new_scope(cctx, WHILE_SCOPE);
    if (scope == NULL)
	return NULL;
    if (scope->se_loop_depth == MAX_LOOP_DEPTH)
    {
	emsg(_(e_loop_nesting_too_deep));
	return NULL;
    }
    ++scope->se_loop_depth;
    whilescope = &scope->se_u.se_while;

    
    whilescope->ws_top_label = current_instr_idx(cctx);

    
    
    funcref_lvar = reserve_local(cctx, (char_u *)"", 0, ASSIGN_VAR, &t_number);
    if (funcref_lvar == NULL)
    {
	drop_scope(cctx);
	return NULL;  
    }
    
    funcref_lvar_idx = funcref_lvar->lv_idx;

    
    compile_fill_loop_info(&whilescope->ws_loop_info, funcref_lvar_idx, cctx);
    whilescope->ws_loop_info.li_depth = scope->se_loop_depth - 1;

    
    if (compile_expr0(&p, cctx) == FAIL)
	return NULL;

    if (!ends_excmd2(arg, skipwhite(p)))
    {
	semsg(_(e_trailing_characters_str), p);
	return NULL;
    }

    if (cctx->ctx_skip != SKIP_YES)
    {
	if (bool_on_stack(cctx) == FAIL)
	    return FAIL;

	
	generate_undo_cmdmods(cctx);

	
	if (compile_jump_to_end(&whilescope->ws_end_label, JUMP_WHILE_FALSE, funcref_lvar_idx, cctx) == FAIL)
	    return FAIL;
    }

    return p;
}


    char_u * compile_endwhile(char_u *arg, cctx_T *cctx)
{
    scope_T	*scope = cctx->ctx_scope;
    garray_T	*instr = &cctx->ctx_instr;

    if (misplaced_cmdmod(cctx))
	return NULL;
    if (scope == NULL || scope->se_type != WHILE_SCOPE)
    {
	emsg(_(e_endwhile_without_while));
	return NULL;
    }
    cctx->ctx_scope = scope->se_outer;
    if (cctx->ctx_skip != SKIP_YES)
    {
	whilescope_T	*whilescope = &scope->se_u.se_while;

	
	
	if (compile_loop_end(&whilescope->ws_loop_info, cctx) == FAIL)
	    return NULL;

	unwind_locals(cctx, scope->se_local_count, FALSE);


	
	may_generate_prof_end(cctx, cctx->ctx_lnum);


	
	generate_JUMP(cctx, JUMP_ALWAYS, scope->se_u.se_while.ws_top_label);

	
	
	compile_fill_jump_to_end(&scope->se_u.se_while.ws_end_label, instr->ga_len, cctx);
    }

    vim_free(scope);

    return arg;
}


    int get_loop_var_info(cctx_T *cctx, loopvarinfo_T *lvi)
{
    scope_T	*scope = cctx->ctx_scope;
    int		prev_local_count = 0;

    CLEAR_POINTER(lvi);
    for (;;)
    {
	loop_info_T	*loopinfo;
	int		cur_local_last;
	int		start_local_count;

	while (scope != NULL && scope->se_type != WHILE_SCOPE && scope->se_type != FOR_SCOPE)
	    scope = scope->se_outer;
	if (scope == NULL)
	    break;

	if (scope->se_type == WHILE_SCOPE)
	{
	    loopinfo = &scope->se_u.se_while.ws_loop_info;
	    
	    cur_local_last = loopinfo->li_local_count - 1;
	}
	else {
	    loopinfo = &scope->se_u.se_for.fs_loop_info;
	    
	    
	    cur_local_last = loopinfo->li_local_count - 3;
	}

	start_local_count = loopinfo->li_local_count;
	if (cctx->ctx_locals.ga_len > start_local_count)
	{
	    lvi->lvi_loop[loopinfo->li_depth].var_idx = (short)start_local_count;
	    lvi->lvi_loop[loopinfo->li_depth].var_count = (short)(cctx->ctx_locals.ga_len - start_local_count - prev_local_count);

	    if (lvi->lvi_depth == 0)
		lvi->lvi_depth = loopinfo->li_depth + 1;
	}

	scope = scope->se_outer;
	prev_local_count = cctx->ctx_locals.ga_len - cur_local_last;
    }
    return lvi->lvi_depth > 0;
}


    void get_loop_var_idx(cctx_T *cctx, int idx, lvar_T *lvar)
{
    loopvarinfo_T lvi;

    lvar->lv_loop_depth = -1;
    lvar->lv_loop_idx = -1;
    if (get_loop_var_info(cctx, &lvi))
    {
	int depth;

	for (depth = lvi.lvi_depth - 1; depth >= 0; --depth)
	    if (idx >= lvi.lvi_loop[depth].var_idx && idx < lvi.lvi_loop[depth].var_idx + lvi.lvi_loop[depth].var_count)

	    {
		lvar->lv_loop_depth = depth;
		lvar->lv_loop_idx = lvi.lvi_loop[depth].var_idx;
		return;
	    }
    }
}


    static int compile_find_scope( int	    *loop_label, endlabel_T  ***el, int	    *try_scopes, char	    *error, cctx_T	    *cctx)





{
    scope_T	*scope = cctx->ctx_scope;

    for (;;)
    {
	if (scope == NULL)
	{
	    if (error != NULL)
		emsg(_(error));
	    return FAIL;
	}
	if (scope->se_type == FOR_SCOPE)
	{
	    if (compile_loop_end(&scope->se_u.se_for.fs_loop_info, cctx)
								       == FAIL)
		return FAIL;
	    if (loop_label != NULL)
		*loop_label = scope->se_u.se_for.fs_top_label;
	    if (el != NULL)
		*el = &scope->se_u.se_for.fs_end_label;
	    break;
	}
	if (scope->se_type == WHILE_SCOPE)
	{
	    if (compile_loop_end(&scope->se_u.se_while.ws_loop_info, cctx)
								       == FAIL)
		return FAIL;
	    if (loop_label != NULL)
		*loop_label = scope->se_u.se_while.ws_top_label;
	    if (el != NULL)
		*el = &scope->se_u.se_while.ws_end_label;
	    break;
	}
	if (try_scopes != NULL && scope->se_type == TRY_SCOPE)
	    ++*try_scopes;
	scope = scope->se_outer;
    }
    return OK;
}


    char_u * compile_continue(char_u *arg, cctx_T *cctx)
{
    int		try_scopes = 0;
    int		loop_label;

    if (compile_find_scope(&loop_label, NULL, &try_scopes, e_continue_without_while_or_for, cctx) == FAIL)
	return NULL;
    if (try_scopes > 0)
	
	
	generate_TRYCONT(cctx, try_scopes, loop_label);
    else  generate_JUMP(cctx, JUMP_ALWAYS, loop_label);


    return arg;
}


    char_u * compile_break(char_u *arg, cctx_T *cctx)
{
    int		try_scopes = 0;
    endlabel_T	**el;

    if (compile_find_scope(NULL, &el, &try_scopes, e_break_without_while_or_for, cctx) == FAIL)
	return NULL;

    if (try_scopes > 0)
	
	
	
	generate_TRYCONT(cctx, try_scopes, cctx->ctx_instr.ga_len + 1);

    
    
    if (compile_jump_to_end(el, JUMP_ALWAYS, 0, cctx) == FAIL)
	return FAIL;

    return arg;
}


    char_u * compile_block(char_u *arg, cctx_T *cctx)
{
    if (new_scope(cctx, BLOCK_SCOPE) == NULL)
	return NULL;
    return skipwhite(arg + 1);
}


    void compile_endblock(cctx_T *cctx)
{
    scope_T	*scope = cctx->ctx_scope;

    cctx->ctx_scope = scope->se_outer;
    unwind_locals(cctx, scope->se_local_count, TRUE);
    vim_free(scope);
}


    char_u * compile_try(char_u *arg, cctx_T *cctx)
{
    garray_T	*instr = &cctx->ctx_instr;
    scope_T	*try_scope;
    scope_T	*scope;

    if (misplaced_cmdmod(cctx))
	return NULL;

    
    try_scope = new_scope(cctx, TRY_SCOPE);
    if (try_scope == NULL)
	return NULL;

    if (cctx->ctx_skip != SKIP_YES)
    {
	isn_T	*isn;

	
	
	
	
	try_scope->se_u.se_try.ts_try_label = instr->ga_len;
	if ((isn = generate_instr(cctx, ISN_TRY)) == NULL)
	    return NULL;
	isn->isn_arg.tryref.try_ref = ALLOC_CLEAR_ONE(tryref_T);
	if (isn->isn_arg.tryref.try_ref == NULL)
	    return NULL;
    }

    
    scope = new_scope(cctx, BLOCK_SCOPE);
    if (scope == NULL)
	return NULL;

    return arg;
}


    char_u * compile_catch(char_u *arg, cctx_T *cctx UNUSED)
{
    scope_T	*scope = cctx->ctx_scope;
    garray_T	*instr = &cctx->ctx_instr;
    char_u	*p;
    isn_T	*isn;

    if (misplaced_cmdmod(cctx))
	return NULL;

    
    if (scope != NULL && scope->se_type == BLOCK_SCOPE)
	compile_endblock(cctx);
    scope = cctx->ctx_scope;

    
    if (scope == NULL || scope->se_type != TRY_SCOPE)
    {
	emsg(_(e_catch_without_try));
	return NULL;
    }

    if (scope->se_u.se_try.ts_caught_all)
    {
	emsg(_(e_catch_unreachable_after_catch_all));
	return NULL;
    }
    if (!cctx->ctx_had_return)
	scope->se_u.se_try.ts_no_return = TRUE;

    if (cctx->ctx_skip != SKIP_YES)
    {

	
	if (cctx->ctx_compile_type == CT_PROFILE && instr->ga_len > 0 && ((isn_T *)instr->ga_data)[instr->ga_len - 1] .isn_type == ISN_PROF_START)


	    --instr->ga_len;

	
	if (compile_jump_to_end(&scope->se_u.se_try.ts_end_label, JUMP_ALWAYS, 0, cctx) == FAIL)
	    return NULL;

	
	isn = ((isn_T *)instr->ga_data) + scope->se_u.se_try.ts_try_label;
	if (isn->isn_arg.tryref.try_ref->try_catch == 0)
	    isn->isn_arg.tryref.try_ref->try_catch = instr->ga_len;
	if (scope->se_u.se_try.ts_catch_label != 0)
	{
	    
	    isn = ((isn_T *)instr->ga_data) + scope->se_u.se_try.ts_catch_label;
	    isn->isn_arg.jump.jump_where = instr->ga_len;
	}

	if (cctx->ctx_compile_type == CT_PROFILE)
	{
	    
	    generate_instr(cctx, ISN_PROF_END);
	    
	    generate_instr(cctx, ISN_PROF_START);
	}

	if (cctx->ctx_compile_type == CT_DEBUG)
	    generate_instr_debug(cctx);
    }

    p = skipwhite(arg);
    if (ends_excmd2(arg, p))
    {
	scope->se_u.se_try.ts_caught_all = TRUE;
	scope->se_u.se_try.ts_catch_label = 0;
    }
    else {
	char_u *end;
	char_u *pat;
	char_u *tofree = NULL;
	int	dropped = 0;
	int	len;

	
	generate_instr_type(cctx, ISN_PUSHEXC, &t_string);

	end = skip_regexp_ex(p + 1, *p, TRUE, &tofree, &dropped, NULL);
	if (*end != *p)
	{
	    semsg(_(e_separator_mismatch_str), p);
	    vim_free(tofree);
	    return NULL;
	}
	if (tofree == NULL)
	    len = (int)(end - (p + 1));
	else len = (int)(end - tofree);
	pat = vim_strnsave(tofree == NULL ? p + 1 : tofree, len);
	vim_free(tofree);
	p += len + 2 + dropped;
	if (pat == NULL)
	    return NULL;
	if (generate_PUSHS(cctx, &pat) == FAIL)
	    return NULL;

	if (generate_COMPARE(cctx, EXPR_MATCH, FALSE) == FAIL)
	    return NULL;

	scope->se_u.se_try.ts_catch_label = instr->ga_len;
	if (generate_JUMP(cctx, JUMP_IF_FALSE, 0) == FAIL)
	    return NULL;
    }

    if (cctx->ctx_skip != SKIP_YES && generate_instr(cctx, ISN_CATCH) == NULL)
	return NULL;

    if (new_scope(cctx, BLOCK_SCOPE) == NULL)
	return NULL;
    return p;
}

    char_u * compile_finally(char_u *arg, cctx_T *cctx)
{
    scope_T	*scope = cctx->ctx_scope;
    garray_T	*instr = &cctx->ctx_instr;
    isn_T	*isn;
    int		this_instr;

    if (misplaced_cmdmod(cctx))
	return NULL;

    
    if (scope != NULL && scope->se_type == BLOCK_SCOPE)
	compile_endblock(cctx);
    scope = cctx->ctx_scope;

    
    if (scope == NULL || scope->se_type != TRY_SCOPE)
    {
	emsg(_(e_finally_without_try));
	return NULL;
    }

    if (cctx->ctx_skip != SKIP_YES)
    {
	
	isn = ((isn_T *)instr->ga_data) + scope->se_u.se_try.ts_try_label;
	if (isn->isn_arg.tryref.try_ref->try_finally != 0)
	{
	    emsg(_(e_multiple_finally));
	    return NULL;
	}

	this_instr = instr->ga_len;

	if (cctx->ctx_compile_type == CT_PROFILE && ((isn_T *)instr->ga_data)[this_instr - 1] .isn_type == ISN_PROF_START)

	{
	    
	    --this_instr;

	    
	    if (this_instr > 0 && ((isn_T *)instr->ga_data)[this_instr - 1] .isn_type == ISN_PROF_END)
		--this_instr;
	}


	
	compile_fill_jump_to_end(&scope->se_u.se_try.ts_end_label, this_instr, cctx);

	
	if (isn->isn_arg.tryref.try_ref->try_catch == 0)
	    isn->isn_arg.tryref.try_ref->try_catch = this_instr;
	isn->isn_arg.tryref.try_ref->try_finally = this_instr;
	if (scope->se_u.se_try.ts_catch_label != 0)
	{
	    
	    isn = ((isn_T *)instr->ga_data) + scope->se_u.se_try.ts_catch_label;
	    isn->isn_arg.jump.jump_where = this_instr;
	    scope->se_u.se_try.ts_catch_label = 0;
	}
	scope->se_u.se_try.ts_has_finally = TRUE;
	if (generate_instr(cctx, ISN_FINALLY) == NULL)
	    return NULL;
    }

    return arg;
}

    char_u * compile_endtry(char_u *arg, cctx_T *cctx)
{
    scope_T	*scope = cctx->ctx_scope;
    garray_T	*instr = &cctx->ctx_instr;
    isn_T	*try_isn;

    if (misplaced_cmdmod(cctx))
	return NULL;

    
    if (scope != NULL && scope->se_type == BLOCK_SCOPE)
	compile_endblock(cctx);
    scope = cctx->ctx_scope;

    
    if (scope == NULL || scope->se_type != TRY_SCOPE)
    {
	if (scope == NULL)
	    emsg(_(e_endtry_without_try));
	else if (scope->se_type == WHILE_SCOPE)
	    emsg(_(e_missing_endwhile));
	else if (scope->se_type == FOR_SCOPE)
	    emsg(_(e_missing_endfor));
	else emsg(_(e_missing_endif));
	return NULL;
    }

    try_isn = ((isn_T *)instr->ga_data) + scope->se_u.se_try.ts_try_label;
    if (cctx->ctx_skip != SKIP_YES)
    {
	if (try_isn->isn_arg.tryref.try_ref->try_catch == 0 && try_isn->isn_arg.tryref.try_ref->try_finally == 0)
	{
	    emsg(_(e_missing_catch_or_finally));
	    return NULL;
	}


	if (cctx->ctx_compile_type == CT_PROFILE && ((isn_T *)instr->ga_data)[instr->ga_len - 1] .isn_type == ISN_PROF_START)

	    
	    
	    --instr->ga_len;


	
	
	compile_fill_jump_to_end(&scope->se_u.se_try.ts_end_label, instr->ga_len, cctx);

	if (scope->se_u.se_try.ts_catch_label != 0)
	{
	    
	    isn_T *isn = ((isn_T *)instr->ga_data)
					   + scope->se_u.se_try.ts_catch_label;
	    isn->isn_arg.jump.jump_where = instr->ga_len;
	}
    }

    
    
    
    if (!(scope->se_u.se_try.ts_has_finally && cctx->ctx_had_return)
	    && (scope->se_u.se_try.ts_no_return || !scope->se_u.se_try.ts_caught_all))
	cctx->ctx_had_return = FALSE;

    compile_endblock(cctx);

    if (cctx->ctx_skip != SKIP_YES)
    {
	
	
	try_isn->isn_arg.tryref.try_ref->try_endtry = instr->ga_len;
	if (generate_instr(cctx, ISN_ENDTRY) == NULL)
	    return NULL;

	if (cctx->ctx_compile_type == CT_PROFILE)
	    generate_instr(cctx, ISN_PROF_START);

    }
    return arg;
}


    char_u * compile_throw(char_u *arg, cctx_T *cctx UNUSED)
{
    char_u *p = skipwhite(arg);

    if (compile_expr0(&p, cctx) == FAIL)
	return NULL;
    if (cctx->ctx_skip == SKIP_YES)
	return p;
    if (may_generate_2STRING(-1, FALSE, cctx) == FAIL)
	return NULL;
    if (generate_instr_drop(cctx, ISN_THROW, 1) == NULL)
	return NULL;

    return p;
}


    char_u * compile_eval(char_u *arg, cctx_T *cctx)
{
    char_u	*p = arg;
    int		name_only;
    long	lnum = SOURCING_LNUM;

    
    
    
    name_only = cmd_is_name_only(arg);

    if (compile_expr0(&p, cctx) == FAIL)
	return NULL;

    if (name_only && lnum == SOURCING_LNUM)
    {
	semsg(_(e_expression_without_effect_str), arg);
	return NULL;
    }

    
    generate_instr_drop(cctx, ISN_DROP, 1);

    return skipwhite(p);
}


    int get_defer_var_idx(cctx_T *cctx)
{
    dfunc_T	*dfunc = ((dfunc_T *)def_functions.ga_data)
					       + cctx->ctx_ufunc->uf_dfunc_idx;
    if (dfunc->df_defer_var_idx == 0)
    {
	lvar_T *lvar = reserve_local(cctx, (char_u *)"@defer@", 7, TRUE, &t_list_any);
	if (lvar == NULL)
	    return 0;
	dfunc->df_defer_var_idx = lvar->lv_idx + 1;
    }
    return dfunc->df_defer_var_idx;
}


    char_u * compile_defer(char_u *arg_start, cctx_T *cctx)
{
    char_u	*paren;
    char_u	*arg = arg_start;
    int		argcount = 0;
    int		defer_var_idx;
    type_T	*type;
    int		func_idx;

    
    
    paren = vim_strchr(arg, '(');
    if (paren == NULL)
    {
	semsg(_(e_missing_parenthesis_str), arg);
	return NULL;
    }
    *paren = NUL;
    func_idx = find_internal_func(arg);
    if (func_idx >= 0)
	
	generate_PUSHFUNC(cctx, (char_u *)internal_func_name(func_idx), &t_func_any, FALSE);
    else if (compile_expr0(&arg, cctx) == FAIL)
	return NULL;
    *paren = '(';

    
    type = get_type_on_stack(cctx, 0);
    if (type->tt_type != VAR_FUNC)
    {
	emsg(_(e_function_name_required));
	return NULL;
    }

    
    arg = skipwhite(paren + 1);
    if (compile_arguments(&arg, cctx, &argcount, CA_NOT_SPECIAL) == FAIL)
	return NULL;

    if (func_idx >= 0)
    {
	type2_T	*argtypes = NULL;
	type2_T	shuffled_argtypes[MAX_FUNC_ARGS];

	if (check_internal_func_args(cctx, func_idx, argcount, FALSE, &argtypes, shuffled_argtypes) == FAIL)
	    return NULL;
    }
    else if (check_func_args_from_type(cctx, type, argcount, TRUE, arg_start) == FAIL)
	return NULL;

    defer_var_idx = get_defer_var_idx(cctx);
    if (defer_var_idx == 0)
	return NULL;
    if (generate_DEFER(cctx, defer_var_idx - 1, argcount) == FAIL)
	return NULL;

    return skipwhite(arg);
}


    char_u * compile_mult_expr(char_u *arg, int cmdidx, long cmd_count, cctx_T *cctx)
{
    char_u	*p = arg;
    char_u	*prev = arg;
    char_u	*expr_start;
    int		count = 0;
    int		start_ctx_lnum = cctx->ctx_lnum;
    type_T	*type;
    int		r = OK;

    for (;;)
    {
	if (ends_excmd2(prev, p))
	    break;
	expr_start = p;
	if (compile_expr0(&p, cctx) == FAIL)
	    return NULL;

	if (cctx->ctx_skip != SKIP_YES)
	{
	    
	    type = get_type_on_stack(cctx, 0);
	    if (type->tt_type == VAR_VOID)
	    {
		semsg(_(e_expression_does_not_result_in_value_str), expr_start);
		return NULL;
	    }
	}

	++count;
	prev = p;
	p = skipwhite(p);
    }

    if (count > 0)
    {
	long save_lnum = cctx->ctx_lnum;

	
	cctx->ctx_lnum = start_ctx_lnum;

	if (cmdidx == CMD_echo || cmdidx == CMD_echon)
	    r = generate_ECHO(cctx, cmdidx == CMD_echo, count);
	else if (cmdidx == CMD_execute)
	    r = generate_MULT_EXPR(cctx, ISN_EXECUTE, count);
	else if (cmdidx == CMD_echomsg)
	    r = generate_MULT_EXPR(cctx, ISN_ECHOMSG, count);

	else if (cmdidx == CMD_echowindow)
	    r = generate_ECHOWINDOW(cctx, count, cmd_count);

	else if (cmdidx == CMD_echoconsole)
	    r = generate_MULT_EXPR(cctx, ISN_ECHOCONSOLE, count);
	else r = generate_MULT_EXPR(cctx, ISN_ECHOERR, count);

	cctx->ctx_lnum = save_lnum;
    }
    return r == OK ? p : NULL;
}


    static int compile_variable_range(exarg_T *eap, cctx_T *cctx)
{
    char_u *range_end = skip_range(eap->cmd, TRUE, NULL);
    char_u *p = skipdigits(eap->cmd);

    if (p == range_end)
	return FAIL;
    return generate_RANGE(cctx, vim_strnsave(eap->cmd, range_end - eap->cmd));
}


    char_u * compile_put(char_u *arg, exarg_T *eap, cctx_T *cctx)
{
    char_u	*line = arg;
    linenr_T	lnum;
    char	*errormsg;
    int		above = eap->forceit;

    eap->regname = *line;

    if (eap->regname == '=')
    {
	char_u *p = skipwhite(line + 1);

	if (compile_expr0(&p, cctx) == FAIL)
	    return NULL;
	line = p;
    }
    else if (eap->regname != NUL)
	++line;

    if (compile_variable_range(eap, cctx) == OK)
    {
	lnum = above ? LNUM_VARIABLE_RANGE_ABOVE : LNUM_VARIABLE_RANGE;
    }
    else {
	
	
	if (parse_cmd_address(eap, &errormsg, FALSE) == FAIL)
	    
	    return NULL;
	if (eap->addr_count == 0)
	    lnum = -1;
	else lnum = eap->line2;
	if (above)
	    --lnum;
    }

    generate_PUT(cctx, eap->regname, lnum);
    return line;
}


    char_u * compile_exec(char_u *line_arg, exarg_T *eap, cctx_T *cctx)
{
    char_u	*line = line_arg;
    char_u	*p;
    int		has_expr = FALSE;
    char_u	*nextcmd = (char_u *)"";
    char_u	*tofree = NULL;
    char_u	*cmd_arg = NULL;

    if (cctx->ctx_skip == SKIP_YES)
	goto theend;

    
    
    if (cctx->ctx_has_cmdmod)
    {
	garray_T	*instr = &cctx->ctx_instr;
	isn_T		*isn = ((isn_T *)instr->ga_data) + instr->ga_len - 1;

	if (isn->isn_type == ISN_CMDMOD)
	{
	    vim_regfree(isn->isn_arg.cmdmod.cf_cmdmod ->cmod_filter_regmatch.regprog);
	    vim_free(isn->isn_arg.cmdmod.cf_cmdmod);
	    --instr->ga_len;
	    cctx->ctx_has_cmdmod = FALSE;
	}
    }

    if (eap->cmdidx >= 0 && eap->cmdidx < CMD_SIZE)
    {
	long	argt = eap->argt;
	int	usefilter = FALSE;

	has_expr = argt & (EX_XFILE | EX_EXPAND);

	
	
	
	if ((eap->cmdidx == CMD_write || eap->cmdidx == CMD_read)
							   && *eap->arg == '!')
	    
	    usefilter = TRUE;
	if ((argt & EX_TRLBAR) && !usefilter)
	{
	    eap->argt = argt;
	    separate_nextcmd(eap, TRUE);
	    if (eap->nextcmd != NULL)
		nextcmd = eap->nextcmd;
	}
	else if (eap->cmdidx == CMD_wincmd)
	{
	    p = eap->arg;
	    if (*p != NUL)
		++p;
	    if (*p == 'g' || *p == Ctrl_G)
		++p;
	    p = skipwhite(p);
	    if (*p == '|')
	    {
		*p = NUL;
		nextcmd = p + 1;
	    }
	}
	else if (eap->cmdidx == CMD_command || eap->cmdidx == CMD_autocmd)
	{
	    
	    p = eap->arg + STRLEN(eap->arg) - 1;
	    while (p > eap->arg && VIM_ISWHITE(*p))
		--p;
	    if (*p == '{')
	    {
		exarg_T ea;
		int	flags = 0;  
		int	start_lnum = SOURCING_LNUM;

		CLEAR_FIELD(ea);
		ea.arg = eap->arg;
		fill_exarg_from_cctx(&ea, cctx);
		(void)may_get_cmd_block(&ea, p, &tofree, &flags);
		if (tofree != NULL)
		{
		    *p = NUL;
		    line = concat_str(line, tofree);
		    if (line == NULL)
			goto theend;
		    vim_free(tofree);
		    tofree = line;
		    SOURCING_LNUM = start_lnum;
		}
	    }
	}
    }

    if (eap->cmdidx == CMD_syntax && STRNCMP(eap->arg, "include ", 8) == 0)
    {
	
	has_expr = TRUE;
	eap->arg = skipwhite(eap->arg + 7);
	if (*eap->arg == '@')
	    eap->arg = skiptowhite(eap->arg);
    }

    if ((eap->cmdidx == CMD_global || eap->cmdidx == CMD_vglobal)
						       && STRLEN(eap->arg) > 4)
    {
	int delim = *eap->arg;

	p = skip_regexp_ex(eap->arg + 1, delim, TRUE, NULL, NULL, NULL);
	if (*p == delim)
	    cmd_arg = p + 1;
    }

    if (eap->cmdidx == CMD_folddoopen || eap->cmdidx == CMD_folddoclosed)
	cmd_arg = eap->arg;

    if (cmd_arg != NULL)
    {
	exarg_T nea;

	CLEAR_FIELD(nea);
	nea.cmd = cmd_arg;
	p = find_ex_command(&nea, NULL, lookup_scriptitem, NULL);
	if (nea.cmdidx < CMD_SIZE)
	{
	    has_expr = excmd_get_argt(nea.cmdidx) & (EX_XFILE | EX_EXPAND);
	    if (has_expr)
		eap->arg = skiptowhite(eap->arg);
	}
    }

    if (has_expr && (p = (char_u *)strstr((char *)eap->arg, "`=")) != NULL)
    {
	int	count = 0;
	char_u	*start = skipwhite(line);

	
	
	
	
	
	
	
	for (;;)
	{
	    if (p > start)
	    {
		char_u *val = vim_strnsave(start, p - start);

		generate_PUSHS(cctx, &val);
		++count;
	    }
	    p += 2;
	    if (compile_expr0(&p, cctx) == FAIL)
		return NULL;
	    may_generate_2STRING(-1, TRUE, cctx);
	    ++count;
	    p = skipwhite(p);
	    if (*p != '`')
	    {
		emsg(_(e_missing_backtick));
		return NULL;
	    }
	    start = p + 1;

	    p = (char_u *)strstr((char *)start, "`=");
	    if (p == NULL)
	    {
		if (*skipwhite(start) != NUL)
		{
		    char_u *val = vim_strsave(start);

		    generate_PUSHS(cctx, &val);
		    ++count;
		}
		break;
	    }
	}
	generate_EXECCONCAT(cctx, count);
    }
    else generate_EXEC_copy(cctx, ISN_EXEC, line);

theend:
    if (*nextcmd != NUL)
    {
	
	--nextcmd;
	*nextcmd = '|';
    }
    vim_free(tofree);

    return nextcmd;
}


    char_u * compile_script(char_u *line, cctx_T *cctx)
{
    if (cctx->ctx_skip != SKIP_YES)
    {
	isn_T	*isn;

	if ((isn = generate_instr(cctx, ISN_EXEC_SPLIT)) == NULL)
	    return NULL;
	isn->isn_arg.string = vim_strsave(line);
    }
    return (char_u *)"";
}



    char_u * compile_substitute(char_u *arg, exarg_T *eap, cctx_T *cctx)
{
    char_u  *cmd = eap->arg;
    char_u  *expr = (char_u *)strstr((char *)cmd, "\\=");

    if (expr != NULL)
    {
	int delimiter = *cmd++;

	
	cmd = skip_regexp_ex(cmd, delimiter, magic_isset(), NULL, NULL, NULL);
	if (cmd[0] == delimiter && cmd[1] == '\\' && cmd[2] == '=')
	{
	    garray_T	save_ga = cctx->ctx_instr;
	    char_u	*end;
	    int		expr_res;
	    int		trailing_error;
	    int		instr_count;
	    isn_T	*instr;
	    isn_T	*isn;

	    cmd += 3;
	    end = skip_substitute(cmd, delimiter);

	    
	    
	    cctx->ctx_instr.ga_len = 0;
	    cctx->ctx_instr.ga_maxlen = 0;
	    cctx->ctx_instr.ga_data = NULL;
	    expr_res = compile_expr0(&cmd, cctx);
	    if (end[-1] == NUL)
		end[-1] = delimiter;
	    cmd = skipwhite(cmd);
	    trailing_error = *cmd != delimiter && *cmd != NUL;

	    if (expr_res == FAIL || trailing_error || GA_GROW_FAILS(&cctx->ctx_instr, 1))
	    {
		if (trailing_error)
		    semsg(_(e_trailing_characters_str), cmd);
		clear_instr_ga(&cctx->ctx_instr);
		cctx->ctx_instr = save_ga;
		return NULL;
	    }

	    
	    
	    
	    instr_count = cctx->ctx_instr.ga_len;
	    instr = cctx->ctx_instr.ga_data;
	    instr[instr_count].isn_type = ISN_FINISH;

	    cctx->ctx_instr = save_ga;
	    if ((isn = generate_instr(cctx, ISN_SUBSTITUTE)) == NULL)
	    {
		int idx;

		for (idx = 0; idx < instr_count; ++idx)
		    delete_instr(instr + idx);
		vim_free(instr);
		return NULL;
	    }
	    isn->isn_arg.subs.subs_cmd = vim_strsave(arg);
	    isn->isn_arg.subs.subs_instr = instr;

	    
	    if (*end == '&')
		++end;
	    while (ASCII_ISALPHA(*end) || *end == '#')
		++end;
	    return end;
	}
    }

    return compile_exec(arg, eap, cctx);
}

    char_u * compile_redir(char_u *line, exarg_T *eap, cctx_T *cctx)
{
    char_u  *arg = eap->arg;
    lhs_T   *lhs = &cctx->ctx_redir_lhs;

    if (lhs->lhs_name != NULL)
    {
	if (STRNCMP(arg, "END", 3) == 0)
	{
	    if (lhs->lhs_append)
	    {
		
		if (compile_load_lhs_with_index(lhs, lhs->lhs_whole, cctx) == FAIL)
		    return NULL;
	    }

	    
	    
	    generate_instr_type(cctx, ISN_REDIREND, &t_string);

	    if (lhs->lhs_append)
		generate_CONCAT(cctx, 2);

	    if (lhs->lhs_has_index)
	    {
		
		
		if (compile_assign_unlet(lhs->lhs_whole, lhs, TRUE, &t_string, cctx) == FAIL)
		    return NULL;
	    }
	    else if (generate_store_lhs(cctx, lhs, -1, FALSE) == FAIL)
		return NULL;

	    VIM_CLEAR(lhs->lhs_name);
	    VIM_CLEAR(lhs->lhs_whole);
	    return arg + 3;
	}
	emsg(_(e_cannot_nest_redir));
	return NULL;
    }

    if (arg[0] == '=' && arg[1] == '>')
    {
	int	    append = FALSE;

	
	arg += 2;
	if (*arg == '>')
	{
	    ++arg;
	    append = TRUE;
	}
	arg = skipwhite(arg);

	if (compile_assign_lhs(arg, lhs, CMD_redir, FALSE, FALSE, FALSE, 1, cctx) == FAIL)
	    return NULL;
	if (need_type(&t_string, lhs->lhs_member_type, -1, 0, cctx, FALSE, FALSE) == FAIL)
	    return NULL;
	generate_instr(cctx, ISN_REDIRSTART);
	lhs->lhs_append = append;
	if (lhs->lhs_has_index)
	{
	    lhs->lhs_whole = vim_strnsave(arg, lhs->lhs_varlen_total);
	    if (lhs->lhs_whole == NULL)
		return NULL;
	}

	return arg + lhs->lhs_varlen_total;
    }

    
    return compile_exec(line, eap, cctx);
}


    char_u * compile_cexpr(char_u *line, exarg_T *eap, cctx_T *cctx)
{
    isn_T	*isn;
    char_u	*p;

    isn = generate_instr(cctx, ISN_CEXPR_AUCMD);
    if (isn == NULL)
	return NULL;
    isn->isn_arg.number = eap->cmdidx;

    p = eap->arg;
    if (compile_expr0(&p, cctx) == FAIL)
	return NULL;

    isn = generate_instr(cctx, ISN_CEXPR_CORE);
    if (isn == NULL)
	return NULL;
    isn->isn_arg.cexpr.cexpr_ref = ALLOC_ONE(cexprref_T);
    if (isn->isn_arg.cexpr.cexpr_ref == NULL)
	return NULL;
    isn->isn_arg.cexpr.cexpr_ref->cer_cmdidx = eap->cmdidx;
    isn->isn_arg.cexpr.cexpr_ref->cer_forceit = eap->forceit;
    isn->isn_arg.cexpr.cexpr_ref->cer_cmdline = vim_strsave(skipwhite(line));

    return p;
}



    char_u * compile_return(char_u *arg, int check_return_type, int legacy, cctx_T *cctx)
{
    char_u	*p = arg;
    type_T	*stack_type;

    if (*p != NUL && *p != '|' && *p != '\n')
    {
	
	
	if (cctx->ctx_ufunc->uf_ret_type->tt_type == VAR_VOID && (cctx->ctx_ufunc->uf_flags & FC_LAMBDA) == 0)
	{
	    emsg(_(e_returning_value_in_function_without_return_type));
	    return NULL;
	}
	if (legacy)
	{
	    int save_flags = cmdmod.cmod_flags;

	    generate_LEGACY_EVAL(cctx, p);
	    if (need_type(&t_any, cctx->ctx_ufunc->uf_ret_type, -1, 0, cctx, FALSE, FALSE) == FAIL)
		return NULL;
	    cmdmod.cmod_flags |= CMOD_LEGACY;
	    (void)skip_expr(&p, NULL);
	    cmdmod.cmod_flags = save_flags;
	}
	else {
	    
	    if (compile_expr0(&p, cctx) == FAIL)
		return NULL;
	}

	if (cctx->ctx_skip != SKIP_YES)
	{
	    
	    
	    
	    stack_type = get_type_on_stack(cctx, 0);
	    if ((check_return_type && (cctx->ctx_ufunc->uf_ret_type == NULL || cctx->ctx_ufunc->uf_ret_type == &t_unknown))
		    || (!check_return_type && cctx->ctx_ufunc->uf_ret_type == &t_unknown))
	    {
		cctx->ctx_ufunc->uf_ret_type = stack_type;
	    }
	    else {
		if (need_type(stack_type, cctx->ctx_ufunc->uf_ret_type, -1, 0, cctx, FALSE, FALSE) == FAIL)
		    return NULL;
	    }
	}
    }
    else {
	
	
	if (cctx->ctx_ufunc->uf_ret_type->tt_type != VAR_VOID && cctx->ctx_ufunc->uf_ret_type->tt_type != VAR_UNKNOWN)
	{
	    emsg(_(e_missing_return_value));
	    return NULL;
	}

	
	generate_PUSHNR(cctx, 0);
    }

    
    if (compile_find_scope(NULL, NULL, NULL, NULL, cctx) == FAIL)

    
    generate_undo_cmdmods(cctx);

    if (cctx->ctx_skip != SKIP_YES && generate_instr(cctx, ISN_RETURN) == NULL)
	return NULL;

    
    return skipwhite(p);
}


    int check_global_and_subst(char_u *cmd, char_u *arg)
{
    if (arg == cmd + 1 && vim_strchr((char_u *)":-.", *arg) != NULL)
    {
	semsg(_(e_separator_not_supported_str), arg);
	return FAIL;
    }
    if (VIM_ISWHITE(cmd[1]))
    {
	semsg(_(e_no_white_space_allowed_before_separator_str), cmd);
	return FAIL;
    }
    return OK;
}



