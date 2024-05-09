


















static cmdline_info_T ccline;


static int	new_cmdpos;	


static int	extra_char = NUL;  
				   
static int	extra_char_shift;


static int	cmd_hkmap = 0;	


static char_u	*getcmdline_int(int firstc, long count, int indent, int clear_ccline);
static int	cmdline_charsize(int idx);
static void	set_cmdspos(void);
static void	set_cmdspos_cursor(void);
static void	correct_cmdspos(int idx, int cells);
static void	alloc_cmdbuff(int len);
static void	draw_cmdline(int start, int len);
static void	save_cmdline(cmdline_info_T *ccp);
static void	restore_cmdline(cmdline_info_T *ccp);
static int	cmdline_paste(int regname, int literally, int remcr);
static void	redrawcmdprompt(void);
static int	ccheck_abbr(int);

static int	empty_pattern_magic(char_u *pat, size_t len, magic_T magic_val);



static int	open_cmdwin(void);

static int	cedit_key INIT(= -1);	



    static void trigger_cmd_autocmd(int typechar, int evt)
{
    char_u	typestr[2];

    typestr[0] = typechar;
    typestr[1] = NUL;
    apply_autocmds(evt, typestr, typestr, FALSE, curbuf);
}


    static void abandon_cmdline(void)
{
    VIM_CLEAR(ccline.cmdbuff);
    if (msg_scrolled == 0)
	compute_cmdrow();
    msg("");
    redraw_cmdline = TRUE;
}



    static int empty_pattern(char_u *p, int delim)
{
    size_t	n = STRLEN(p);
    magic_T	magic_val = MAGIC_ON;

    if (n > 0)
	(void) skip_regexp_ex(p, delim, magic_isset(), NULL, NULL, &magic_val);
    else return TRUE;

    return empty_pattern_magic(p, n, magic_val);
}

    static int empty_pattern_magic(char_u *p, size_t len, magic_T magic_val)
{
    
    while (len >= 2 && p[len - 2] == '\\' && vim_strchr((char_u *)"mMvVcCZ", p[len - 1]) != NULL)
       len -= 2;

    
    
    return len == 0 || (len > 1 && ((p[len - 2] == '\\' && p[len - 1] == '|' && magic_val == MAGIC_ON)

		|| (p[len - 2] != '\\' && p[len - 1] == '|' && magic_val == MAGIC_ALL)));
}


typedef struct {
    colnr_T	vs_curswant;
    colnr_T	vs_leftcol;
    linenr_T	vs_topline;

    int		vs_topfill;

    linenr_T	vs_botline;
    linenr_T	vs_empty_rows;
} viewstate_T;

    static void save_viewstate(viewstate_T *vs)
{
    vs->vs_curswant = curwin->w_curswant;
    vs->vs_leftcol = curwin->w_leftcol;
    vs->vs_topline = curwin->w_topline;

    vs->vs_topfill = curwin->w_topfill;

    vs->vs_botline = curwin->w_botline;
    vs->vs_empty_rows = curwin->w_empty_rows;
}

    static void restore_viewstate(viewstate_T *vs)
{
    curwin->w_curswant = vs->vs_curswant;
    curwin->w_leftcol = vs->vs_leftcol;
    curwin->w_topline = vs->vs_topline;

    curwin->w_topfill = vs->vs_topfill;

    curwin->w_botline = vs->vs_botline;
    curwin->w_empty_rows = vs->vs_empty_rows;
}


typedef struct {
    pos_T	search_start;	
    pos_T	save_cursor;
    int		winid;		
    viewstate_T	init_viewstate;
    viewstate_T	old_viewstate;
    pos_T	match_start;
    pos_T	match_end;
    int		did_incsearch;
    int		incsearch_postponed;
    optmagic_T	magic_overruled_save;
} incsearch_state_T;

    static void init_incsearch_state(incsearch_state_T *is_state)
{
    is_state->winid = curwin->w_id;
    is_state->match_start = curwin->w_cursor;
    is_state->did_incsearch = FALSE;
    is_state->incsearch_postponed = FALSE;
    is_state->magic_overruled_save = magic_overruled;
    CLEAR_POS(&is_state->match_end);
    is_state->save_cursor = curwin->w_cursor;  
    is_state->search_start = curwin->w_cursor;
    save_viewstate(&is_state->init_viewstate);
    save_viewstate(&is_state->old_viewstate);
}


    static void set_search_match(pos_T *t)
{
    t->lnum += search_match_lines;
    t->col = search_match_endcol;
    if (t->lnum > curbuf->b_ml.ml_line_count)
    {
	t->lnum = curbuf->b_ml.ml_line_count;
	coladvance((colnr_T)MAXCOL);
    }
}


    static int do_incsearch_highlighting( int		    firstc, int		    *search_delim, incsearch_state_T   *is_state, int		    *skiplen, int		    *patlen)





{
    char_u	*cmd;
    cmdmod_T	dummy_cmdmod;
    char_u	*p;
    int		delim_optional = FALSE;
    int		delim;
    char_u	*end;
    char	*dummy;
    exarg_T	ea;
    pos_T	save_cursor;
    int		use_last_pat;
    int		retval = FALSE;
    magic_T     magic = 0;

    *skiplen = 0;
    *patlen = ccline.cmdlen;

    if (!p_is || cmd_silent)
	return FALSE;

    
    search_first_line = 0;
    search_last_line = MAXLNUM;

    if (firstc == '/' || firstc == '?')
    {
	*search_delim = firstc;
	return TRUE;
    }
    if (firstc != ':')
	return FALSE;

    ++emsg_off;
    CLEAR_FIELD(ea);
    ea.line1 = 1;
    ea.line2 = 1;
    ea.cmd = ccline.cmdbuff;
    ea.addr_type = ADDR_LINES;

    CLEAR_FIELD(dummy_cmdmod);
    parse_command_modifiers(&ea, &dummy, &dummy_cmdmod, TRUE);

    cmd = skip_range(ea.cmd, TRUE, NULL);
    if (vim_strchr((char_u *)"sgvl", *cmd) == NULL)
	goto theend;

    
    for (p = cmd; ASCII_ISALPHA(*p); ++p)
	;
    if (*skipwhite(p) == NUL)
	goto theend;

    if (STRNCMP(cmd, "substitute", p - cmd) == 0 || STRNCMP(cmd, "smagic", p - cmd) == 0 || STRNCMP(cmd, "snomagic", MAX(p - cmd, 3)) == 0 || STRNCMP(cmd, "vglobal", p - cmd) == 0)


    {
	if (*cmd == 's' && cmd[1] == 'm')
	    magic_overruled = OPTION_MAGIC_ON;
	else if (*cmd == 's' && cmd[1] == 'n')
	    magic_overruled = OPTION_MAGIC_OFF;
    }
    else if (STRNCMP(cmd, "sort", MAX(p - cmd, 3)) == 0)
    {
	
	if (*p == '!')
	    p = skipwhite(p + 1);
	while (ASCII_ISALPHA(*(p = skipwhite(p))))
	    ++p;
	if (*p == NUL)
	    goto theend;
    }
    else if (STRNCMP(cmd, "vimgrep", MAX(p - cmd, 3)) == 0 || STRNCMP(cmd, "vimgrepadd", MAX(p - cmd, 8)) == 0 || STRNCMP(cmd, "lvimgrep", MAX(p - cmd, 2)) == 0 || STRNCMP(cmd, "lvimgrepadd", MAX(p - cmd, 9)) == 0 || STRNCMP(cmd, "global", p - cmd) == 0)



    {
	
	if (*p == '!')
	{
	    p++;
	    if (*skipwhite(p) == NUL)
		goto theend;
	}
	if (*cmd != 'g')
	    delim_optional = TRUE;
    }
    else goto theend;

    p = skipwhite(p);
    delim = (delim_optional && vim_isIDc(*p)) ? ' ' : *p++;
    *search_delim = delim;
    end = skip_regexp_ex(p, delim, magic_isset(), NULL, NULL, &magic);

    use_last_pat = end == p && *end == delim;

    if (end == p && !use_last_pat)
	goto theend;

    
    if (!use_last_pat)
    {
	char c = *end;
	int  empty;

	*end = NUL;
	empty = empty_pattern_magic(p, STRLEN(p), magic);
	*end = c;
	if (empty)
	    goto theend;
    }

    
    *skiplen = (int)(p - ccline.cmdbuff);
    *patlen = (int)(end - p);

    
    save_cursor = curwin->w_cursor;
    curwin->w_cursor = is_state->search_start;
    parse_cmd_address(&ea, &dummy, TRUE);
    if (ea.addr_count > 0)
    {
	
	if (ea.line2 < ea.line1)
	{
	    search_first_line = ea.line2;
	    search_last_line = ea.line1;
	}
	else {
	    search_first_line = ea.line1;
	    search_last_line = ea.line2;
	}
    }
    else if (cmd[0] == 's' && cmd[1] != 'o')
    {
	
	search_first_line = curwin->w_cursor.lnum;
	search_last_line = curwin->w_cursor.lnum;
    }

    curwin->w_cursor = save_cursor;
    retval = TRUE;
theend:
    --emsg_off;
    return retval;
}

    static void finish_incsearch_highlighting( int gotesc, incsearch_state_T *is_state, int call_update_screen)



{
    if (is_state->did_incsearch)
    {
	is_state->did_incsearch = FALSE;
	if (gotesc)
	    curwin->w_cursor = is_state->save_cursor;
	else {
	    if (!EQUAL_POS(is_state->save_cursor, is_state->search_start))
	    {
		
		curwin->w_cursor = is_state->save_cursor;
		setpcmark();
	    }
	    curwin->w_cursor = is_state->search_start;
	}
	restore_viewstate(&is_state->old_viewstate);
	highlight_match = FALSE;

	
	search_first_line = 0;
	search_last_line = MAXLNUM;

	magic_overruled = is_state->magic_overruled_save;

	validate_cursor();	
	redraw_all_later(SOME_VALID);
	if (call_update_screen)
	    update_screen(SOME_VALID);
    }
}


    static void may_do_incsearch_highlighting( int		    firstc, long		    count, incsearch_state_T   *is_state)



{
    int		skiplen, patlen;
    int		found;  
    pos_T	end_pos;

    proftime_T	tm;
    searchit_arg_T sia;

    int		next_char;
    int		use_last_pat;
    int		did_do_incsearch = is_state->did_incsearch;
    int		search_delim;

    
    
    save_last_search_pattern();

    if (!do_incsearch_highlighting(firstc, &search_delim, is_state, &skiplen, &patlen))
    {
	restore_last_search_pattern();
	finish_incsearch_highlighting(FALSE, is_state, TRUE);
	if (did_do_incsearch && vpeekc() == NUL)
	    
	    redrawcmd();
	return;
    }

    
    if (char_avail())
    {
	restore_last_search_pattern();
	is_state->incsearch_postponed = TRUE;
	return;
    }
    is_state->incsearch_postponed = FALSE;

    if (search_first_line == 0)
	
	curwin->w_cursor = is_state->search_start;
    else if (search_first_line > curbuf->b_ml.ml_line_count)
    {
	
	curwin->w_cursor.lnum = curbuf->b_ml.ml_line_count;
	curwin->w_cursor.col = MAXCOL;
    }
    else {
	
	curwin->w_cursor.lnum = search_first_line;
	curwin->w_cursor.col = 0;
    }

    
    next_char = ccline.cmdbuff[skiplen + patlen];
    use_last_pat = patlen == 0 && skiplen > 0 && ccline.cmdbuff[skiplen - 1] == next_char;

    
    if (patlen == 0 && !use_last_pat)
    {
	found = 0;
	set_no_hlsearch(TRUE); 
	redraw_all_later(SOME_VALID);
    }
    else {
	int search_flags = SEARCH_OPT + SEARCH_NOOF + SEARCH_PEEK;

	cursor_off();	
	out_flush();
	++emsg_off;	

	
	profile_setlimit(500L, &tm);

	if (!p_hls)
	    search_flags += SEARCH_KEEP;
	if (search_first_line != 0)
	    search_flags += SEARCH_START;
	ccline.cmdbuff[skiplen + patlen] = NUL;

	CLEAR_FIELD(sia);
	sia.sa_tm = &tm;

	found = do_search(NULL, firstc == ':' ? '/' : firstc, search_delim, ccline.cmdbuff + skiplen, count, search_flags,  &sia  NULL  );






	ccline.cmdbuff[skiplen + patlen] = next_char;
	--emsg_off;

	if (curwin->w_cursor.lnum < search_first_line || curwin->w_cursor.lnum > search_last_line)
	{
	    
	    found = 0;
	    curwin->w_cursor = is_state->search_start;
	}

	
	if (got_int)
	{
	    (void)vpeekc();	
	    got_int = FALSE;	
	    found = 0;
	}
	else if (char_avail())
	    
	    is_state->incsearch_postponed = TRUE;
    }
    if (found != 0)
	highlight_match = TRUE;		
    else highlight_match = FALSE;

    
    
    restore_viewstate(&is_state->old_viewstate);
    changed_cline_bef_curs();
    update_topline();

    if (found != 0)
    {
	pos_T	    save_pos = curwin->w_cursor;

	is_state->match_start = curwin->w_cursor;
	set_search_match(&curwin->w_cursor);
	validate_cursor();
	end_pos = curwin->w_cursor;
	is_state->match_end = end_pos;
	curwin->w_cursor = save_pos;
    }
    else end_pos = curwin->w_cursor;

    
    
    if (!use_last_pat)
    {
	next_char = ccline.cmdbuff[skiplen + patlen];
	ccline.cmdbuff[skiplen + patlen] = NUL;
	if (empty_pattern(ccline.cmdbuff + skiplen, search_delim)
							       && !no_hlsearch)
	{
	    redraw_all_later(SOME_VALID);
	    set_no_hlsearch(TRUE);
	}
	ccline.cmdbuff[skiplen + patlen] = next_char;
    }

    validate_cursor();
    
    if (p_ru && curwin->w_status_height > 0)
	curwin->w_redr_status = TRUE;

    update_screen(SOME_VALID);
    highlight_match = FALSE;
    restore_last_search_pattern();

    
    
    if (ccline.cmdbuff[skiplen + patlen] != NUL)
	curwin->w_cursor = is_state->search_start;
    else if (found != 0)
	curwin->w_cursor = end_pos;

    msg_starthere();
    redrawcmdline();
    is_state->did_incsearch = TRUE;
}


    static int may_adjust_incsearch_highlighting( int			firstc, long			count, incsearch_state_T	*is_state, int			c)




{
    int	    skiplen, patlen;
    pos_T   t;
    char_u  *pat;
    int	    search_flags = SEARCH_NOOF;
    int	    i;
    int	    save;
    int	    search_delim;

    
    
    save_last_search_pattern();

    if (!do_incsearch_highlighting(firstc, &search_delim, is_state, &skiplen, &patlen))
    {
	restore_last_search_pattern();
	return OK;
    }
    if (patlen == 0 && ccline.cmdbuff[skiplen] == NUL)
    {
	restore_last_search_pattern();
	return FAIL;
    }

    if (search_delim == ccline.cmdbuff[skiplen])
    {
	pat = last_search_pattern();
	if (pat == NULL)
	{
	    restore_last_search_pattern();
	    return FAIL;
	}
	skiplen = 0;
	patlen = (int)STRLEN(pat);
    }
    else pat = ccline.cmdbuff + skiplen;

    cursor_off();
    out_flush();
    if (c == Ctrl_G)
    {
	t = is_state->match_end;
	if (LT_POS(is_state->match_start, is_state->match_end))
	    
	    
	    (void)decl(&t);
	search_flags += SEARCH_COL;
    }
    else t = is_state->match_start;
    if (!p_hls)
	search_flags += SEARCH_KEEP;
    ++emsg_off;
    save = pat[patlen];
    pat[patlen] = NUL;
    i = searchit(curwin, curbuf, &t, NULL, c == Ctrl_G ? FORWARD : BACKWARD, pat, count, search_flags, RE_SEARCH, NULL);

    --emsg_off;
    pat[patlen] = save;
    if (i)
    {
	is_state->search_start = is_state->match_start;
	is_state->match_end = t;
	is_state->match_start = t;
	if (c == Ctrl_T && firstc != '?')
	{
	    
	    
	    is_state->search_start = t;
	    (void)decl(&is_state->search_start);
	}
	else if (c == Ctrl_G && firstc == '?')
	{
	    
	    
	    is_state->search_start = t;
	    (void)incl(&is_state->search_start);
	}
	if (LT_POS(t, is_state->search_start) && c == Ctrl_G)
	{
	    
	    is_state->search_start = t;
	    if (firstc == '?')
		(void)incl(&is_state->search_start);
	    else (void)decl(&is_state->search_start);
	}

	set_search_match(&is_state->match_end);
	curwin->w_cursor = is_state->match_start;
	changed_cline_bef_curs();
	update_topline();
	validate_cursor();
	highlight_match = TRUE;
	save_viewstate(&is_state->old_viewstate);
	update_screen(NOT_VALID);
	highlight_match = FALSE;
	redrawcmdline();
	curwin->w_cursor = is_state->match_end;
    }
    else vim_beep(BO_ERROR);
    restore_last_search_pattern();
    return FAIL;
}


    static int may_add_char_to_search(int firstc, int *c, incsearch_state_T *is_state)
{
    int		skiplen, patlen, search_delim;

    
    
    save_last_search_pattern();

    if (!do_incsearch_highlighting(firstc, &search_delim, is_state, &skiplen, &patlen))
    {
	restore_last_search_pattern();
	return FAIL;
    }
    restore_last_search_pattern();

    
    if (is_state->did_incsearch)
    {
	curwin->w_cursor = is_state->match_end;
	*c = gchar_cursor();
	if (*c != NUL)
	{
	    
	    
	    
	    if (p_ic && p_scs && !pat_has_uppercase(ccline.cmdbuff + skiplen))
		*c = MB_TOLOWER(*c);
	    if (*c == search_delim || vim_strchr((char_u *)( magic_isset() ? "\\~^$.*[" : "\\^$"), *c) != NULL)
	    {
		
		stuffcharReadbuff(*c);
		*c = '\\';
	    }
	    
	    if (mb_char2len(*c) != mb_ptr2len(ml_get_cursor()))
	    {
		int save_c = *c;

		while (mb_char2len(*c) != mb_ptr2len(ml_get_cursor()))
		{
		    curwin->w_cursor.col += mb_char2len(*c);
		    *c = gchar_cursor();
		    stuffcharReadbuff(*c);
		}
		*c = save_c;
	    }
	    return FAIL;
	}
    }
    return OK;
}




    static int cmdline_has_arabic(int start, int len)
{
    int	    j;
    int	    mb_l;
    int	    u8c;
    char_u  *p;
    int	    u8cc[MAX_MCO];

    if (!enc_utf8)
	return FALSE;

    for (j = start; j < start + len; j += mb_l)
    {
	p = ccline.cmdbuff + j;
	u8c = utfc_ptr2char_len(p, u8cc, start + len - j);
	mb_l = utfc_ptr2len_len(p, start + len - j);
	if (ARABIC_CHAR(u8c))
	    return TRUE;
    }
    return FALSE;
}


    void cmdline_init(void)
{
    CLEAR_FIELD(ccline);
}


    static int cmdline_handle_backslash_key(int c, int *gotesc)
{
    ++no_mapping;
    ++allow_keys;
    c = plain_vgetc();
    --no_mapping;
    --allow_keys;

    
    
    if (c != Ctrl_N && c != Ctrl_G && (c != 'e' || (ccline.cmdfirstc == '=' && KeyTyped)

		|| cmdline_star > 0  ))

    {
	vungetc(c);
	return PROCESS_NEXT_KEY;
    }


    if (c == 'e')
    {
	char_u	*p = NULL;
	int	len;

	
	if (ccline.cmdpos == ccline.cmdlen)
	    new_cmdpos = 99999;	
	else new_cmdpos = ccline.cmdpos;

	c = get_expr_register();
	if (c == '=')
	{
	    
	    
	    
	    ++textlock;
	    p = get_expr_line();
	    --textlock;

	    if (p != NULL)
	    {
		len = (int)STRLEN(p);
		if (realloc_cmdbuff(len + 1) == OK)
		{
		    ccline.cmdlen = len;
		    STRCPY(ccline.cmdbuff, p);
		    vim_free(p);

		    
		    
		    if (new_cmdpos > ccline.cmdlen)
			ccline.cmdpos = ccline.cmdlen;
		    else ccline.cmdpos = new_cmdpos;

		    KeyTyped = FALSE;	
		    redrawcmd();
		    return CMDLINE_CHANGED;
		}
		vim_free(p);
	    }
	}
	beep_flush();
	got_int = FALSE;	
	did_emsg = FALSE;
	emsg_on_display = FALSE;
	redrawcmd();
	return CMDLINE_NOT_CHANGED;
    }


    if (c == Ctrl_G && p_im && restart_edit == 0)
	restart_edit = 'a';
    *gotesc = TRUE;	
			
    return GOTO_NORMAL_MODE;
}


    static int cmdline_wildchar_complete( int		c, int		escape, int		*did_wild_list, int		*wim_index_p, expand_T	*xp, int		*gotesc)






{
    int		wim_index = *wim_index_p;
    int		res;
    int		j;
    int		options = WILD_NO_BEEP;

    if (wim_flags[wim_index] & WIM_BUFLASTUSED)
	options |= WILD_BUFLASTUSED;
    if (xp->xp_numfiles > 0)   
    {
	
	if (xp->xp_numfiles > 1 && !*did_wild_list && ((wim_flags[wim_index] & WIM_LIST)


		    || (p_wmnu && (wim_flags[wim_index] & WIM_FULL) != 0)

		    ))
	{

	    (void)showmatches(xp, p_wmnu && ((wim_flags[wim_index] & WIM_LIST) == 0));

	    (void)showmatches(xp, FALSE);

	    redrawcmd();
	    *did_wild_list = TRUE;
	}
	if (wim_flags[wim_index] & WIM_LONGEST)
	    res = nextwild(xp, WILD_LONGEST, options, escape);
	else if (wim_flags[wim_index] & WIM_FULL)
	    res = nextwild(xp, WILD_NEXT, options, escape);
	else res = OK;
    }
    else		     {
	wim_index = 0;
	j = ccline.cmdpos;
	
	
	if (wim_flags[0] & WIM_LONGEST)
	    res = nextwild(xp, WILD_LONGEST, options, escape);
	else res = nextwild(xp, WILD_EXPAND_KEEP, options, escape);

	
	if (got_int)
	{
	    (void)vpeekc();	
	    got_int = FALSE;	
	    (void)ExpandOne(xp, NULL, NULL, 0, WILD_FREE);

	    xp->xp_context = EXPAND_NOTHING;

	    *wim_index_p = wim_index;
	    return CMDLINE_CHANGED;
	}

	
	
	
	if (res == OK && xp->xp_numfiles > 1)
	{
	    
	    
	    if (wim_flags[0] == WIM_LONGEST && ccline.cmdpos == j)
		wim_index = 1;
	    if ((wim_flags[wim_index] & WIM_LIST)

		    || (p_wmnu && (wim_flags[wim_index] & WIM_FULL) != 0)

	       )
	    {
		if (!(wim_flags[0] & WIM_LONGEST))
		{

		    int p_wmnu_save = p_wmnu;
		    p_wmnu = 0;

		    
		    nextwild(xp, WILD_PREV, 0, escape);

		    p_wmnu = p_wmnu_save;

		}

		(void)showmatches(xp, p_wmnu && ((wim_flags[wim_index] & WIM_LIST) == 0));

		(void)showmatches(xp, FALSE);

		redrawcmd();
		*did_wild_list = TRUE;
		if (wim_flags[wim_index] & WIM_LONGEST)
		    nextwild(xp, WILD_LONGEST, options, escape);
		else if (wim_flags[wim_index] & WIM_FULL)
		    nextwild(xp, WILD_NEXT, options, escape);
	    }
	    else vim_beep(BO_WILD);
	}

	else if (xp->xp_numfiles == -1)
	    xp->xp_context = EXPAND_NOTHING;

    }
    if (wim_index < 3)
	++wim_index;
    if (c == ESC)
	*gotesc = TRUE;

    *wim_index_p = wim_index;
    return (res == OK) ? CMDLINE_CHANGED : CMDLINE_NOT_CHANGED;
}


    static int cmdline_erase_chars( int c, int indent  , incsearch_state_T *isp  )






{
    int		i;
    int		j;

    if (c == K_KDEL)
	c = K_DEL;

    
    if (c == K_DEL && ccline.cmdpos != ccline.cmdlen)
	++ccline.cmdpos;
    if (has_mbyte && c == K_DEL)
	ccline.cmdpos += mb_off_next(ccline.cmdbuff, ccline.cmdbuff + ccline.cmdpos);
    if (ccline.cmdpos > 0)
    {
	char_u *p;

	j = ccline.cmdpos;
	p = ccline.cmdbuff + j;
	if (has_mbyte)
	{
	    p = mb_prevptr(ccline.cmdbuff, p);
	    if (c == Ctrl_W)
	    {
		while (p > ccline.cmdbuff && vim_isspace(*p))
		    p = mb_prevptr(ccline.cmdbuff, p);
		i = mb_get_class(p);
		while (p > ccline.cmdbuff && mb_get_class(p) == i)
		    p = mb_prevptr(ccline.cmdbuff, p);
		if (mb_get_class(p) != i)
		    p += (*mb_ptr2len)(p);
	    }
	}
	else if (c == Ctrl_W)
	{
	    while (p > ccline.cmdbuff && vim_isspace(p[-1]))
		--p;
	    if (p > ccline.cmdbuff)
	    {
		i = vim_iswordc(p[-1]);
		while (p > ccline.cmdbuff && !vim_isspace(p[-1])
			&& vim_iswordc(p[-1]) == i)
		    --p;
	    }
	}
	else --p;
	ccline.cmdpos = (int)(p - ccline.cmdbuff);
	ccline.cmdlen -= j - ccline.cmdpos;
	i = ccline.cmdpos;
	while (i < ccline.cmdlen)
	    ccline.cmdbuff[i++] = ccline.cmdbuff[j++];

	
	ccline.cmdbuff[ccline.cmdlen] = NUL;

	if (ccline.cmdlen == 0)
	{
	    isp->search_start = isp->save_cursor;
	    
	    
	    isp->old_viewstate = isp->init_viewstate;
	}

	redrawcmd();
    }
    else if (ccline.cmdlen == 0 && c != Ctrl_W && ccline.cmdprompt == NULL && indent == 0)
    {
	
	if (exmode_active  || ccline.cmdfirstc == '>'  )



	    return CMDLINE_NOT_CHANGED;

	VIM_CLEAR(ccline.cmdbuff);	
	if (!cmd_silent)
	{

	    if (cmdmsg_rl)
		msg_col = Columns;
	    else  msg_col = 0;

	    msg_putchar(' ');		
	}

	if (ccline.cmdlen == 0)
	    isp->search_start = isp->save_cursor;

	redraw_cmdline = TRUE;
	return GOTO_NORMAL_MODE;
    }
    return CMDLINE_CHANGED;
}


    static void cmdline_toggle_langmap(long *b_im_ptr)
{
    if (map_to_exists_mode((char_u *)"", MODE_LANGMAP, FALSE))
    {
	
	State ^= MODE_LANGMAP;

	im_set_active(FALSE);	

	if (b_im_ptr != NULL)
	{
	    if (State & MODE_LANGMAP)
		*b_im_ptr = B_IMODE_LMAP;
	    else *b_im_ptr = B_IMODE_NONE;
	}
    }

    else {
	
	
	
	if ((p_imdisable && b_im_ptr != NULL)
		? *b_im_ptr == B_IMODE_IM : im_get_status())
	{
	    im_set_active(FALSE);	
	    if (b_im_ptr != NULL)
		*b_im_ptr = B_IMODE_NONE;
	}
	else {
	    im_set_active(TRUE);	
	    if (b_im_ptr != NULL)
		*b_im_ptr = B_IMODE_IM;
	}
    }

    if (b_im_ptr != NULL)
    {
	if (b_im_ptr == &curbuf->b_p_iminsert)
	    set_iminsert_global();
	else set_imsearch_global();
    }

    ui_cursor_shape();	


    
    status_redraw_curbuf();

}


    static int cmdline_insert_reg(int *gotesc UNUSED)
{
    int		i;
    int		c;


    dont_scroll = TRUE;	

    putcmdline('"', TRUE);
    ++no_mapping;
    ++allow_keys;
    i = c = plain_vgetc();	
    if (i == Ctrl_O)
	i = Ctrl_R;		
    if (i == Ctrl_R)
	c = plain_vgetc();	
    extra_char = NUL;
    --no_mapping;
    --allow_keys;

    
    new_cmdpos = -1;
    if (c == '=')
    {
	if (ccline.cmdfirstc == '='   || cmdline_star > 0)
	{
	    beep_flush();
	    c = ESC;
	}
	else c = get_expr_register();
    }

    if (c != ESC)	    
    {
	cmdline_paste(c, i == Ctrl_R, FALSE);


	
	
	if (aborting())
	{
	    *gotesc = TRUE;  
	    
	    return GOTO_NORMAL_MODE;
	}

	KeyTyped = FALSE;	

	if (new_cmdpos >= 0)
	{
	    
	    if (new_cmdpos > ccline.cmdlen)
		ccline.cmdpos = ccline.cmdlen;
	    else ccline.cmdpos = new_cmdpos;
	}

    }
    
    redrawcmd();

    
    return CMDLINE_NOT_CHANGED;
}


    static void cmdline_left_right_mouse(int c, int *ignore_drag_release)
{
    if (c == K_LEFTRELEASE || c == K_RIGHTRELEASE)
	*ignore_drag_release = TRUE;
    else *ignore_drag_release = FALSE;

    
    if (!gui.in_use)

	if (!mouse_has(MOUSE_COMMAND))
	    return;

    if (mouse_row < cmdline_row && clip_star.available)
    {
	int	    button, is_click, is_drag;

	
	button = get_mouse_button(KEY2TERMCAP1(c), &is_click, &is_drag);
	if (mouse_model_popup() && button == MOUSE_LEFT && (mod_mask & MOD_MASK_SHIFT))
	{
	    
	    button = MOUSE_RIGHT;
	    mod_mask &= ~MOD_MASK_SHIFT;
	}
	clip_modeless(button, is_click, is_drag);
	return;
    }


    set_cmdspos();
    for (ccline.cmdpos = 0; ccline.cmdpos < ccline.cmdlen;
	    ++ccline.cmdpos)
    {
	int	i;

	i = cmdline_charsize(ccline.cmdpos);
	if (mouse_row <= cmdline_row + ccline.cmdspos / Columns && mouse_col < ccline.cmdspos % Columns + i)
	    break;
	if (has_mbyte)
	{
	    
	    correct_cmdspos(ccline.cmdpos, i);
	    ccline.cmdpos += (*mb_ptr2len)(ccline.cmdbuff + ccline.cmdpos) - 1;
	}
	ccline.cmdspos += i;
    }
}


    static int cmdline_browse_history( int	c, int	firstc, char_u	**curcmdstr, int	histype, int	*hiscnt_p, expand_T *xp)






{
    int		i;
    int		j;
    char_u	*lookfor = *curcmdstr;
    int		hiscnt = *hiscnt_p;
    int		res;

    if (get_hislen() == 0 || firstc == NUL)	
	return CMDLINE_NOT_CHANGED;

    i = hiscnt;

    
    if (lookfor == NULL)
    {
	if ((lookfor = vim_strsave(ccline.cmdbuff)) == NULL)
	    return CMDLINE_NOT_CHANGED;
	lookfor[ccline.cmdpos] = NUL;
    }

    j = (int)STRLEN(lookfor);
    for (;;)
    {
	
	if (c == K_UP|| c == K_S_UP || c == Ctrl_P || c == K_PAGEUP || c == K_KPAGEUP)
	{
	    if (hiscnt == get_hislen())	
		hiscnt = *get_hisidx(histype);
	    else if (hiscnt == 0 && *get_hisidx(histype)
		    != get_hislen() - 1)
		hiscnt = get_hislen() - 1;
	    else if (hiscnt != *get_hisidx(histype) + 1)
		--hiscnt;
	    else			 {
		hiscnt = i;
		break;
	    }
	}
	else     {
	    
	    if (hiscnt == *get_hisidx(histype))
	    {
		hiscnt = get_hislen();
		break;
	    }

	    
	    if (hiscnt == get_hislen())
		break;
	    if (hiscnt == get_hislen() - 1)   
		hiscnt = 0;
	    else ++hiscnt;
	}
	if (hiscnt < 0 || get_histentry(histype)[hiscnt].hisstr == NULL)
	{
	    hiscnt = i;
	    break;
	}
	if ((c != K_UP && c != K_DOWN)
		|| hiscnt == i || STRNCMP(get_histentry(histype)[hiscnt].hisstr, lookfor, (size_t)j) == 0)

	    break;
    }

    if (hiscnt != i)	
    {
	char_u	*p;
	int		len;
	int		old_firstc;

	VIM_CLEAR(ccline.cmdbuff);
	xp->xp_context = EXPAND_NOTHING;
	if (hiscnt == get_hislen())
	    p = lookfor;	
	else p = get_histentry(histype)[hiscnt].hisstr;

	if (histype == HIST_SEARCH && p != lookfor && (old_firstc = p[STRLEN(p) + 1]) != firstc)

	{
	    
	    
	    
	    
	    for (i = 0; i <= 1; ++i)
	    {
		len = 0;
		for (j = 0; p[j] != NUL; ++j)
		{
		    
		    
		    if (p[j] == old_firstc && (j == 0 || p[j - 1] != '\\'))
		    {
			if (i > 0)
			    ccline.cmdbuff[len] = firstc;
		    }
		    else {
			
			
			if (p[j] == firstc && (j == 0 || p[j - 1] != '\\'))
			{
			    if (i > 0)
				ccline.cmdbuff[len] = '\\';
			    ++len;
			}
			if (i > 0)
			    ccline.cmdbuff[len] = p[j];
		    }
		    ++len;
		}
		if (i == 0)
		{
		    alloc_cmdbuff(len);
		    if (ccline.cmdbuff == NULL)
		    {
			res = GOTO_NORMAL_MODE;
			goto done;
		    }
		}
	    }
	    ccline.cmdbuff[len] = NUL;
	}
	else {
	    alloc_cmdbuff((int)STRLEN(p));
	    if (ccline.cmdbuff == NULL)
	    {
		res = GOTO_NORMAL_MODE;
		goto done;
	    }
	    STRCPY(ccline.cmdbuff, p);
	}

	ccline.cmdpos = ccline.cmdlen = (int)STRLEN(ccline.cmdbuff);
	redrawcmd();
	res = CMDLINE_CHANGED;
	goto done;
    }
    beep_flush();
    res = CMDLINE_NOT_CHANGED;

done:
    *curcmdstr = lookfor;
    *hiscnt_p = hiscnt;
    return res;
}


    static int init_ccline(int firstc, int indent)
{
    ccline.overstrike = FALSE;		    

    
    ccline.cmdfirstc = (firstc == '@' ? 0 : firstc);
    ccline.cmdindent = (firstc > 0 ? indent : 0);

    
    alloc_cmdbuff(indent + 50);
    if (ccline.cmdbuff == NULL)
	return FAIL;
    ccline.cmdlen = ccline.cmdpos = 0;
    ccline.cmdbuff[0] = NUL;
    sb_text_start_cmdline();

    
    if (firstc <= 0)
    {
	vim_memset(ccline.cmdbuff, ' ', indent);
	ccline.cmdbuff[indent] = NUL;
	ccline.cmdpos = indent;
	ccline.cmdspos = indent;
	ccline.cmdlen = indent;
    }

    return OK;
}


    char_u * getcmdline( int		  firstc, long	  count, int		  indent, getline_opt_T do_concat UNUSED)




{
    return getcmdline_int(firstc, count, indent, TRUE);
}

    static char_u * getcmdline_int( int		firstc, long	count UNUSED, int		indent, int		clear_ccline)




{
    static int	depth = 0;	    
    int		c;
    int		i;
    int		j;
    int		gotesc = FALSE;		
    int		do_abbr;		
    char_u	*lookfor = NULL;	
    int		hiscnt;			
    int		histype;		

    incsearch_state_T	is_state;

    int		did_wild_list = FALSE;	
    int		wim_index = 0;		
    int		res;
    int		save_msg_scroll = msg_scroll;
    int		save_State = State;	
    int		some_key_typed = FALSE;	
    
    
    int		ignore_drag_release = TRUE;

    int		break_ctrl_c = FALSE;

    expand_T	xpc;
    long	*b_im_ptr = NULL;
    cmdline_info_T save_ccline;
    int		did_save_ccline = FALSE;
    int		cmdline_type;
    int		wild_type;

    
    ++depth;

    if (ccline.cmdbuff != NULL)
    {
	
	
	save_cmdline(&save_ccline);
	did_save_ccline = TRUE;
    }
    if (clear_ccline)
	CLEAR_FIELD(ccline);


    if (firstc == -1)
    {
	firstc = NUL;
	break_ctrl_c = TRUE;
    }


    
    if (firstc == ':' || firstc == '=' || firstc == '>')
	cmd_hkmap = 0;



    init_incsearch_state(&is_state);


    if (init_ccline(firstc, indent) != OK)
	goto theend;	

    if (depth == 50)
    {
	
	emsg(_(e_command_too_recursive));
	goto theend;
    }

    ExpandInit(&xpc);
    ccline.xpc = &xpc;


    if (curwin->w_p_rl && *curwin->w_p_rlc == 's' && (firstc == '/' || firstc == '?'))
	cmdmsg_rl = TRUE;
    else cmdmsg_rl = FALSE;


    redir_off = TRUE;		
    if (!cmd_silent)
    {
	i = msg_scrolled;
	msg_scrolled = 0;		
	gotocmdline(TRUE);
	msg_scrolled += i;
	redrawcmdprompt();		
	set_cmdspos();
    }
    xpc.xp_context = EXPAND_NOTHING;
    xpc.xp_backslash = XP_BS_NONE;

    xpc.xp_shell = FALSE;



    if (ccline.input_fn)
    {
	xpc.xp_context = ccline.xp_context;
	xpc.xp_pattern = ccline.cmdbuff;
	xpc.xp_arg = ccline.xp_arg;
    }


    
    msg_scroll = FALSE;

    State = MODE_CMDLINE;

    if (firstc == '/' || firstc == '?' || firstc == '@')
    {
	
	if (curbuf->b_p_imsearch == B_IMODE_USE_INSERT)
	    b_im_ptr = &curbuf->b_p_iminsert;
	else b_im_ptr = &curbuf->b_p_imsearch;
	if (*b_im_ptr == B_IMODE_LMAP)
	    State |= MODE_LANGMAP;

	im_set_active(*b_im_ptr == B_IMODE_IM);

    }

    else if (p_imcmdline)
	im_set_active(TRUE);


    setmouse();

    ui_cursor_shape();		


    
    
    settmode(TMODE_RAW);

    
    cmdline_type = firstc == NUL ? '-' : firstc;
    trigger_cmd_autocmd(cmdline_type, EVENT_CMDLINEENTER);

    if (!debug_mode)
	may_trigger_modechanged();


    init_history();
    hiscnt = get_hislen();	
    histype = hist_char2type(firstc);


    do_digraph(-1);		


    
    
    if (did_emsg)
	redrawcmd();


    
    
    if (!cmd_silent && msg_scrolled == 0)
    {
	int	found_one = FALSE;
	win_T	*wp;

	FOR_ALL_WINDOWS(wp)
	    if (*p_stl != NUL || *wp->w_p_stl != NUL)
	    {
		wp->w_redr_status = TRUE;
		found_one = TRUE;
	    }
	if (found_one)
	    redraw_statuslines();
    }


    did_emsg = FALSE;
    got_int = FALSE;

    
    for (;;)
    {
	int trigger_cmdlinechanged = TRUE;
	int end_wildmenu;

	redir_off = TRUE;	
				
				

	dont_scroll = FALSE;	

	quit_more = FALSE;	

	did_emsg = FALSE;	
				
				

	
	may_trigger_safestate(xpc.xp_numfiles <= 0);

	
	
	do {
	    cursorcmd();		
	    c = safe_vgetc();
	} while (c == K_IGNORE || c == K_NOP);

	if (c == K_COMMAND || c == K_SCRIPT_COMMAND)
	{
	    int	    clen = ccline.cmdlen;

	    if (do_cmdkey_command(c, DOCMD_NOWAIT) == OK)
	    {
		if (clen == ccline.cmdlen)
		    trigger_cmdlinechanged = FALSE;
		goto cmdline_changed;
	    }
	}

	if (KeyTyped)
	{
	    some_key_typed = TRUE;

	    if (cmd_hkmap)
		c = hkmap(c);
	    if (cmdmsg_rl && !KeyStuffed)
	    {
		
		
		
		switch (c)
		{
		    case K_RIGHT:   c = K_LEFT; break;
		    case K_S_RIGHT: c = K_S_LEFT; break;
		    case K_C_RIGHT: c = K_C_LEFT; break;
		    case K_LEFT:    c = K_RIGHT; break;
		    case K_S_LEFT:  c = K_S_RIGHT; break;
		    case K_C_LEFT:  c = K_C_RIGHT; break;
		}
	    }

	}

	
	if ((c == Ctrl_C  || c == intr_char  )




		&& firstc != '@'   && !break_ctrl_c  && !global_busy)




	    got_int = FALSE;

	
	
	if (lookfor != NULL && c != K_S_DOWN && c != K_S_UP && c != K_DOWN && c != K_UP && c != K_PAGEDOWN && c != K_PAGEUP && c != K_KPAGEDOWN && c != K_KPAGEUP && c != K_LEFT && c != K_RIGHT && (xpc.xp_numfiles > 0 || (c != Ctrl_P && c != Ctrl_N)))





	    VIM_CLEAR(lookfor);

	
	if (c != p_wc && c == K_S_TAB && xpc.xp_numfiles > 0)
	    c = Ctrl_P;


	if (p_wmnu)
	    c = wildmenu_translate_key(&ccline, c, &xpc, did_wild_list);

	if (cmdline_pum_active())
	{
	    
	    
	    
	    if (c == Ctrl_E || c == Ctrl_Y)
	    {
		wild_type = (c == Ctrl_E) ? WILD_CANCEL : WILD_APPLY;
		if (nextwild(&xpc, wild_type, WILD_NO_BEEP, firstc != '@') == FAIL)
		    break;
		c = Ctrl_E;
	    }
	}


	
	
	
	
	
	end_wildmenu = (!(c == p_wc && KeyTyped) && c != p_wcm && c != Ctrl_N && c != Ctrl_P && c != Ctrl_A && c != Ctrl_L);

	end_wildmenu = end_wildmenu && (!cmdline_pum_active() || (c != K_PAGEDOWN && c != K_PAGEUP && c != K_KPAGEDOWN && c != K_KPAGEUP));



	
	if (end_wildmenu)
	{

	    if (cmdline_pum_active())
		cmdline_pum_remove();

	    if (xpc.xp_numfiles != -1)
		(void)ExpandOne(&xpc, NULL, NULL, 0, WILD_FREE);
	    did_wild_list = FALSE;

	    if (!p_wmnu || (c != K_UP && c != K_DOWN))

		xpc.xp_context = EXPAND_NOTHING;
	    wim_index = 0;

	    wildmenu_cleanup(&ccline);

	}


	if (p_wmnu)
	    c = wildmenu_process_key(&ccline, c, &xpc);


	
	
	if (c == Ctrl_BSL)
	{
	    res = cmdline_handle_backslash_key(c, &gotesc);
	    if (res == CMDLINE_CHANGED)
		goto cmdline_changed;
	    else if (res == CMDLINE_NOT_CHANGED)
		goto cmdline_not_changed;
	    else if (res == GOTO_NORMAL_MODE)
		goto returncmd;		
	    c = Ctrl_BSL;		
					
	}


	if (c == cedit_key || c == K_CMDWIN)
	{
	    
	    if ((c == K_CMDWIN || ex_normal_busy == 0) && got_int == FALSE)
	    {
		
		c = open_cmdwin();
		some_key_typed = TRUE;
	    }
	}

	else    c = do_digraph(c);





	if (c == '\n' || c == '\r' || c == K_KENTER || (c == ESC && (!KeyTyped || vim_strchr(p_cpo, CPO_ESC) != NULL)))
	{
	    
	    if (exmode_active && c != ESC && ccline.cmdpos == ccline.cmdlen && ccline.cmdpos > 0 && ccline.cmdbuff[ccline.cmdpos - 1] == '\\')



	    {
		if (c == K_KENTER)
		    c = '\n';
	    }
	    else {
		gotesc = FALSE;	
				
		if (ccheck_abbr(c + ABBR_OFF))
		    goto cmdline_changed;
		if (!cmd_silent)
		{
		    windgoto(msg_row, 0);
		    out_flush();
		}
		break;
	    }
	}

	
	if ((c == p_wc && !gotesc && KeyTyped) || c == p_wcm)
	{
	    res = cmdline_wildchar_complete(c, firstc != '@', &did_wild_list, &wim_index, &xpc, &gotesc);
	    if (res == CMDLINE_CHANGED)
		goto cmdline_changed;
	}

	gotesc = FALSE;

	
	if (c == K_S_TAB && KeyTyped)
	{
	    if (nextwild(&xpc, WILD_EXPAND_KEEP, 0, firstc != '@') == OK)
	    {
		if (xpc.xp_numfiles > 1)
		{

		    
		    showmatches(&xpc, p_wmnu && ((wim_flags[wim_index] & WIM_LIST) == 0));

		    (void)showmatches(&xpc, FALSE);

		}
		if (nextwild(&xpc, WILD_PREV, 0, firstc != '@') == OK && nextwild(&xpc, WILD_PREV, 0, firstc != '@') == OK)
		    goto cmdline_changed;
	    }
	}

	if (c == NUL || c == K_ZERO)	    
	    c = NL;

	do_abbr = TRUE;		

	
	switch (c)
	{
	case K_BS:
	case Ctrl_H:
	case K_DEL:
	case K_KDEL:
	case Ctrl_W:
	    res = cmdline_erase_chars(c, indent  , &is_state  );



	    if (res == CMDLINE_NOT_CHANGED)
		goto cmdline_not_changed;
	    else if (res == GOTO_NORMAL_MODE)
		goto returncmd;		
	    goto cmdline_changed;

	case K_INS:
	case K_KINS:
		ccline.overstrike = !ccline.overstrike;

		ui_cursor_shape();	

		goto cmdline_not_changed;

	case Ctrl_HAT:
		cmdline_toggle_langmap(b_im_ptr);
		goto cmdline_not_changed;


	case Ctrl_U:
		
		j = ccline.cmdpos;
		ccline.cmdlen -= j;
		i = ccline.cmdpos = 0;
		while (i < ccline.cmdlen)
		    ccline.cmdbuff[i++] = ccline.cmdbuff[j++];
		
		ccline.cmdbuff[ccline.cmdlen] = NUL;

		if (ccline.cmdlen == 0)
		    is_state.search_start = is_state.save_cursor;

		redrawcmd();
		goto cmdline_changed;


	case Ctrl_Y:
		
		if (clip_star.state != SELECT_CLEARED)
		{
		    if (clip_star.state == SELECT_DONE)
			clip_copy_modeless_selection(TRUE);
		    goto cmdline_not_changed;
		}
		break;


	case ESC:	
	case Ctrl_C:
		
		
		if (exmode_active && (ex_normal_busy == 0 || typebuf.tb_len > 0))
		    goto cmdline_not_changed;

		gotesc = TRUE;		
					
		goto returncmd;		

	case Ctrl_R:			
		res = cmdline_insert_reg(&gotesc);
		if (res == CMDLINE_NOT_CHANGED)
		    goto cmdline_not_changed;
		else if (res == GOTO_NORMAL_MODE)
		    goto returncmd;
		goto cmdline_changed;

	case Ctrl_D:
		if (showmatches(&xpc, FALSE) == EXPAND_NOTHING)
		    break;	

		redrawcmd();
		continue;	

	case K_RIGHT:
	case K_S_RIGHT:
	case K_C_RIGHT:
		do {
		    if (ccline.cmdpos >= ccline.cmdlen)
			break;
		    i = cmdline_charsize(ccline.cmdpos);
		    if (KeyTyped && ccline.cmdspos + i >= Columns * Rows)
			break;
		    ccline.cmdspos += i;
		    if (has_mbyte)
			ccline.cmdpos += (*mb_ptr2len)(ccline.cmdbuff + ccline.cmdpos);
		    else ++ccline.cmdpos;
		}
		while ((c == K_S_RIGHT || c == K_C_RIGHT || (mod_mask & (MOD_MASK_SHIFT|MOD_MASK_CTRL)))
			&& ccline.cmdbuff[ccline.cmdpos] != ' ');
		if (has_mbyte)
		    set_cmdspos_cursor();
		goto cmdline_not_changed;

	case K_LEFT:
	case K_S_LEFT:
	case K_C_LEFT:
		if (ccline.cmdpos == 0)
		    goto cmdline_not_changed;
		do {
		    --ccline.cmdpos;
		    if (has_mbyte)	
			ccline.cmdpos -= (*mb_head_off)(ccline.cmdbuff, ccline.cmdbuff + ccline.cmdpos);
		    ccline.cmdspos -= cmdline_charsize(ccline.cmdpos);
		}
		while (ccline.cmdpos > 0 && (c == K_S_LEFT || c == K_C_LEFT || (mod_mask & (MOD_MASK_SHIFT|MOD_MASK_CTRL)))

			&& ccline.cmdbuff[ccline.cmdpos - 1] != ' ');
		if (has_mbyte)
		    set_cmdspos_cursor();
		goto cmdline_not_changed;

	case K_IGNORE:
		
		goto cmdline_not_changed;


	    
	    
	case K_F4:
	    if (mod_mask == MOD_MASK_ALT)
	    {
		redrawcmd();	    
		goto cmdline_not_changed;
	    }
	    break;


	case K_MIDDLEDRAG:
	case K_MIDDLERELEASE:
		goto cmdline_not_changed;	

	case K_MIDDLEMOUSE:

		
		if (!gui.in_use)

		    if (!mouse_has(MOUSE_COMMAND))
			goto cmdline_not_changed;   

		if (clip_star.available)
		    cmdline_paste('*', TRUE, TRUE);
		else  cmdline_paste(0, TRUE, TRUE);

		redrawcmd();
		goto cmdline_changed;


	case K_DROP:
		cmdline_paste('~', TRUE, FALSE);
		redrawcmd();
		goto cmdline_changed;


	case K_LEFTDRAG:
	case K_LEFTRELEASE:
	case K_RIGHTDRAG:
	case K_RIGHTRELEASE:
		
		
		if (ignore_drag_release)
		    goto cmdline_not_changed;
		
	case K_LEFTMOUSE:
	case K_RIGHTMOUSE:
		cmdline_left_right_mouse(c, &ignore_drag_release);
		goto cmdline_not_changed;

	
	case K_MOUSEDOWN:
	case K_MOUSEUP:
	case K_MOUSELEFT:
	case K_MOUSERIGHT:
	
	case K_X1MOUSE:
	case K_X1DRAG:
	case K_X1RELEASE:
	case K_X2MOUSE:
	case K_X2DRAG:
	case K_X2RELEASE:
	case K_MOUSEMOVE:
		goto cmdline_not_changed;


	case K_LEFTMOUSE_NM:	
	case K_LEFTRELEASE_NM:
		goto cmdline_not_changed;

	case K_VER_SCROLLBAR:
		if (msg_scrolled == 0)
		{
		    gui_do_scroll();
		    redrawcmd();
		}
		goto cmdline_not_changed;

	case K_HOR_SCROLLBAR:
		if (msg_scrolled == 0)
		{
		    gui_do_horiz_scroll(scrollbar_value, FALSE);
		    redrawcmd();
		}
		goto cmdline_not_changed;


	case K_TABLINE:
	case K_TABMENU:
		
		
		if (gui_use_tabline())
		    gui_mch_set_curtab(tabpage_index(curtab));
		goto cmdline_not_changed;


	case K_SELECT:	    
		goto cmdline_not_changed;

	case Ctrl_B:	    
	case K_HOME:
	case K_KHOME:
	case K_S_HOME:
	case K_C_HOME:
		ccline.cmdpos = 0;
		set_cmdspos();
		goto cmdline_not_changed;

	case Ctrl_E:	    
	case K_END:
	case K_KEND:
	case K_S_END:
	case K_C_END:
		ccline.cmdpos = ccline.cmdlen;
		set_cmdspos_cursor();
		goto cmdline_not_changed;

	case Ctrl_A:	    

		if (cmdline_pum_active())
		    
		    
		    cmdline_pum_cleanup(&ccline);

		if (nextwild(&xpc, WILD_ALL, 0, firstc != '@') == FAIL)
		    break;
		xpc.xp_context = EXPAND_NOTHING;
		did_wild_list = FALSE;
		goto cmdline_changed;

	case Ctrl_L:

		if (may_add_char_to_search(firstc, &c, &is_state) == OK)
		    goto cmdline_not_changed;


		
		if (nextwild(&xpc, WILD_LONGEST, 0, firstc != '@') == FAIL)
		    break;
		goto cmdline_changed;

	case Ctrl_N:	    
	case Ctrl_P:	    
		if (xpc.xp_numfiles > 0)
		{
		    wild_type = (c == Ctrl_P) ? WILD_PREV : WILD_NEXT;
		    if (nextwild(&xpc, wild_type, 0, firstc != '@') == FAIL)
			break;
		    goto cmdline_not_changed;
		}
		
	case K_UP:
	case K_DOWN:
	case K_S_UP:
	case K_S_DOWN:
	case K_PAGEUP:
	case K_KPAGEUP:
	case K_PAGEDOWN:
	case K_KPAGEDOWN:

		if (cmdline_pum_active()
			&& (c == K_PAGEUP || c == K_PAGEDOWN || c == K_KPAGEUP || c == K_KPAGEDOWN))
		{
		    
		    
		    wild_type = WILD_PAGEUP;
		    if (c == K_PAGEDOWN || c == K_KPAGEDOWN)
			wild_type = WILD_PAGEDOWN;
		    if (nextwild(&xpc, wild_type, 0, firstc != '@') == FAIL)
			break;
		    goto cmdline_not_changed;
		}
		else  {

		    res = cmdline_browse_history(c, firstc, &lookfor, histype, &hiscnt, &xpc);
		    if (res == CMDLINE_CHANGED)
			goto cmdline_changed;
		    else if (res == GOTO_NORMAL_MODE)
			goto returncmd;
		}
		goto cmdline_not_changed;


	case Ctrl_G:	    
	case Ctrl_T:	    
		if (may_adjust_incsearch_highlighting( firstc, count, &is_state, c) == FAIL)
		    goto cmdline_not_changed;
		break;


	case Ctrl_V:
	case Ctrl_Q:
		{
		    ignore_drag_release = TRUE;
		    putcmdline('^', TRUE);

		    
		    
		    
		    c = get_literal(mod_mask & MOD_MASK_SHIFT);

		    do_abbr = FALSE;	    
		    extra_char = NUL;
		    
		    if (enc_utf8 && utf_iscomposing(c) && !cmd_silent)
		    {
			draw_cmdline(ccline.cmdpos, ccline.cmdlen - ccline.cmdpos);
			msg_putchar(' ');
			cursorcmd();
		    }
		}

		break;


	case Ctrl_K:
		ignore_drag_release = TRUE;
		putcmdline('?', TRUE);

		dont_scroll = TRUE;	    

		c = get_digraph(TRUE);
		extra_char = NUL;
		if (c != NUL)
		    break;

		redrawcmd();
		goto cmdline_not_changed;



	case Ctrl__:	    
		if (!p_ari)
		    break;
		cmd_hkmap = !cmd_hkmap;
		goto cmdline_not_changed;


	case K_PS:
		bracketed_paste(PASTE_CMDLINE, FALSE, NULL);
		goto cmdline_changed;

	default:

		if (c == intr_char)
		{
		    gotesc = TRUE;	
					
		    goto returncmd;	
		}

		
		if (!IS_SPECIAL(c))
		    mod_mask = 0x0;
		break;
	}
	

	if (do_abbr && (IS_SPECIAL(c) || !vim_iswordc(c))
		&& (ccheck_abbr(   (has_mbyte && c >= 0x100) ? (c + ABBR_OFF) : c)


		    || c == Ctrl_RSB))
	    goto cmdline_changed;

	
	if (IS_SPECIAL(c) || mod_mask != 0)
	    put_on_cmdline(get_special_key_name(c, mod_mask), -1, TRUE);
	else {
	    if (has_mbyte)
	    {
		j = (*mb_char2bytes)(c, IObuff);
		IObuff[j] = NUL;	
		put_on_cmdline(IObuff, j, TRUE);
	    }
	    else {
		IObuff[0] = c;
		put_on_cmdline(IObuff, 1, TRUE);
	    }
	}
	goto cmdline_changed;


cmdline_not_changed:

	if (!is_state.incsearch_postponed)
	    continue;


cmdline_changed:

	
	if (is_state.winid != curwin->w_id)
	    init_incsearch_state(&is_state);

	if (trigger_cmdlinechanged)
	    
	    trigger_cmd_autocmd(cmdline_type, EVENT_CMDLINECHANGED);


	if (xpc.xp_context == EXPAND_NOTHING && (KeyTyped || vpeekc() == NUL))
	    may_do_incsearch_highlighting(firstc, count, &is_state);



	if (cmdmsg_rl  || (p_arshape && !p_tbidi && cmdline_has_arabic(0, ccline.cmdlen))



		)
	    
	    
	    
	    
	    if (vpeekc() == NUL)
		redrawcmd();

    }

returncmd:


    cmdmsg_rl = FALSE;


    ExpandCleanup(&xpc);
    ccline.xpc = NULL;


    finish_incsearch_highlighting(gotesc, &is_state, FALSE);


    if (ccline.cmdbuff != NULL)
    {
	
	if (ccline.cmdlen && firstc != NUL && (some_key_typed || histype == HIST_SEARCH))
	{
	    add_to_history(histype, ccline.cmdbuff, TRUE, histype == HIST_SEARCH ? firstc : NUL);
	    if (firstc == ':')
	    {
		vim_free(new_last_cmdline);
		new_last_cmdline = vim_strsave(ccline.cmdbuff);
	    }
	}

	if (gotesc)
	    abandon_cmdline();
    }

    
    msg_check();
    msg_scroll = save_msg_scroll;
    redir_off = FALSE;

    
    if (some_key_typed)
	need_wait_return = FALSE;

    
    trigger_cmd_autocmd(cmdline_type, EVENT_CMDLINELEAVE);

    State = save_State;


    if (!debug_mode)
	may_trigger_modechanged();



    if (b_im_ptr != NULL && *b_im_ptr != B_IMODE_LMAP)
	im_save_status(b_im_ptr);
    im_set_active(FALSE);

    setmouse();

    ui_cursor_shape();		

    sb_text_end_cmdline();

theend:
    {
	char_u *p = ccline.cmdbuff;

	--depth;
	if (did_save_ccline)
	    restore_cmdline(&save_ccline);
	else ccline.cmdbuff = NULL;
	return p;
    }
}



    char_u * getcmdline_prompt( int		firstc, char_u	*prompt, int		attr, int		xp_context, char_u	*xp_arg)





{
    char_u		*s;
    cmdline_info_T	save_ccline;
    int			did_save_ccline = FALSE;
    int			msg_col_save = msg_col;
    int			msg_silent_save = msg_silent;

    if (ccline.cmdbuff != NULL)
    {
	
	save_cmdline(&save_ccline);
	did_save_ccline = TRUE;
    }

    CLEAR_FIELD(ccline);
    ccline.cmdprompt = prompt;
    ccline.cmdattr = attr;

    ccline.xp_context = xp_context;
    ccline.xp_arg = xp_arg;
    ccline.input_fn = (firstc == '@');

    msg_silent = 0;
    s = getcmdline_int(firstc, 1L, 0, FALSE);

    if (did_save_ccline)
	restore_cmdline(&save_ccline);

    msg_silent = msg_silent_save;
    
    
    
    
    if (ccline.cmdbuff != NULL)
	msg_col = msg_col_save;

    return s;
}



    int check_opt_wim(void)
{
    char_u	new_wim_flags[4];
    char_u	*p;
    int		i;
    int		idx = 0;

    for (i = 0; i < 4; ++i)
	new_wim_flags[i] = 0;

    for (p = p_wim; *p; ++p)
    {
	for (i = 0; ASCII_ISALPHA(p[i]); ++i)
	    ;
	if (p[i] != NUL && p[i] != ',' && p[i] != ':')
	    return FAIL;
	if (i == 7 && STRNCMP(p, "longest", 7) == 0)
	    new_wim_flags[idx] |= WIM_LONGEST;
	else if (i == 4 && STRNCMP(p, "full", 4) == 0)
	    new_wim_flags[idx] |= WIM_FULL;
	else if (i == 4 && STRNCMP(p, "list", 4) == 0)
	    new_wim_flags[idx] |= WIM_LIST;
	else if (i == 8 && STRNCMP(p, "lastused", 8) == 0)
	    new_wim_flags[idx] |= WIM_BUFLASTUSED;
	else return FAIL;
	p += i;
	if (*p == NUL)
	    break;
	if (*p == ',')
	{
	    if (idx == 3)
		return FAIL;
	    ++idx;
	}
    }

    
    while (idx < 3)
    {
	new_wim_flags[idx + 1] = new_wim_flags[idx];
	++idx;
    }

    
    for (i = 0; i < 4; ++i)
	wim_flags[i] = new_wim_flags[i];
    return OK;
}


    int text_locked(void)
{

    if (cmdwin_type != 0)
	return TRUE;

    return textlock != 0;
}


    void text_locked_msg(void)
{
    emsg(_(get_text_locked_msg()));
}

    char * get_text_locked_msg(void)
{

    if (cmdwin_type != 0)
	return e_invalid_in_cmdline_window;

    return e_not_allowed_to_change_text_or_change_window;
}


    int curbuf_locked(void)
{
    if (curbuf_lock > 0)
    {
	emsg(_(e_not_allowed_to_edit_another_buffer_now));
	return TRUE;
    }
    return allbuf_locked();
}


    int allbuf_locked(void)
{
    if (allbuf_lock > 0)
    {
	emsg(_(e_not_allowed_to_change_buffer_information_now));
	return TRUE;
    }
    return FALSE;
}

    static int cmdline_charsize(int idx)
{

    if (cmdline_star > 0)	    
	return 1;

    return ptr2cells(ccline.cmdbuff + idx);
}


    static void set_cmdspos(void)
{
    if (ccline.cmdfirstc != NUL)
	ccline.cmdspos = 1 + ccline.cmdindent;
    else ccline.cmdspos = 0 + ccline.cmdindent;
}


    static void set_cmdspos_cursor(void)
{
    int		i, m, c;

    set_cmdspos();
    if (KeyTyped)
    {
	m = Columns * Rows;
	if (m < 0)	
	    m = MAXCOL;
    }
    else m = MAXCOL;
    for (i = 0; i < ccline.cmdlen && i < ccline.cmdpos; ++i)
    {
	c = cmdline_charsize(i);
	
	if (has_mbyte)
	    correct_cmdspos(i, c);
	
	
	if ((ccline.cmdspos += c) >= m)
	{
	    ccline.cmdspos -= c;
	    break;
	}
	if (has_mbyte)
	    i += (*mb_ptr2len)(ccline.cmdbuff + i) - 1;
    }
}


    static void correct_cmdspos(int idx, int cells)
{
    if ((*mb_ptr2len)(ccline.cmdbuff + idx) > 1 && (*mb_ptr2cells)(ccline.cmdbuff + idx) > 1 && ccline.cmdspos % Columns + cells > Columns)

	ccline.cmdspos++;
}


    char_u * getexline( int		c, void	*cookie UNUSED, int		indent, getline_opt_T options)




{
    
    if (exec_from_reg && vpeekc() == ':')
	(void)vgetc();
    return getcmdline(c, 1L, indent, options);
}


    char_u * getexmodeline( int		promptc,  void	*cookie UNUSED, int		indent, getline_opt_T options UNUSED)





{
    garray_T	line_ga;
    char_u	*pend;
    int		startcol = 0;
    int		c1 = 0;
    int		escaped = FALSE;	
    int		vcol = 0;
    char_u	*p;
    int		prev_char;
    int		len;

    
    
    cursor_on();

    
    compute_cmdrow();
    if ((msg_col || msg_didout) && promptc != '?')
	msg_putchar('\n');
    if (promptc == ':')
    {
	
	if (p_prompt)
	    msg_putchar(':');
	while (indent-- > 0)
	    msg_putchar(' ');
	startcol = msg_col;
    }

    ga_init2(&line_ga, 1, 30);

    
    if (promptc <= 0)
    {
	vcol = indent;
	while (indent >= 8)
	{
	    ga_append(&line_ga, TAB);
	    msg_puts("        ");
	    indent -= 8;
	}
	while (indent-- > 0)
	{
	    ga_append(&line_ga, ' ');
	    msg_putchar(' ');
	}
    }
    ++no_mapping;
    ++allow_keys;

    
    got_int = FALSE;
    while (!got_int)
    {
	long    sw;
	char_u *s;

	if (ga_grow(&line_ga, 40) == FAIL)
	    break;

	
	prev_char = c1;

	
	if (ex_normal_busy > 0 && typebuf.tb_len == 0)
	    c1 = '\n';
	else c1 = vgetc();

	
	if (got_int)
	{
	    msg_putchar('\n');
	    break;
	}

	if (c1 == K_PS)
	{
	    bracketed_paste(PASTE_EX, FALSE, &line_ga);
	    goto redraw;
	}

	if (!escaped)
	{
	    
	    if (c1 == '\r')
		c1 = '\n';

	    if (c1 == BS || c1 == K_BS || c1 == DEL || c1 == K_DEL || c1 == K_KDEL)
	    {
		if (line_ga.ga_len > 0)
		{
		    if (has_mbyte)
		    {
			p = (char_u *)line_ga.ga_data;
			p[line_ga.ga_len] = NUL;
			len = (*mb_head_off)(p, p + line_ga.ga_len - 1) + 1;
			line_ga.ga_len -= len;
		    }
		    else --line_ga.ga_len;
		    goto redraw;
		}
		continue;
	    }

	    if (c1 == Ctrl_U)
	    {
		msg_col = startcol;
		msg_clr_eos();
		line_ga.ga_len = 0;
		goto redraw;
	    }

	    if (c1 == Ctrl_T)
	    {
		sw = get_sw_value(curbuf);
		p = (char_u *)line_ga.ga_data;
		p[line_ga.ga_len] = NUL;
		indent = get_indent_str(p, 8, FALSE);
		indent += sw - indent % sw;
add_indent:
		while (get_indent_str(p, 8, FALSE) < indent)
		{
		    (void)ga_grow(&line_ga, 2);  
		    p = (char_u *)line_ga.ga_data;
		    s = skipwhite(p);
		    mch_memmove(s + 1, s, line_ga.ga_len - (s - p) + 1);
		    *s = ' ';
		    ++line_ga.ga_len;
		}
redraw:
		
		msg_col = startcol;
		vcol = 0;
		p = (char_u *)line_ga.ga_data;
		p[line_ga.ga_len] = NUL;
		while (p < (char_u *)line_ga.ga_data + line_ga.ga_len)
		{
		    if (*p == TAB)
		    {
			do msg_putchar(' ');
			while (++vcol % 8);
			++p;
		    }
		    else {
			len = mb_ptr2len(p);
			msg_outtrans_len(p, len);
			vcol += ptr2cells(p);
			p += len;
		    }
		}
		msg_clr_eos();
		windgoto(msg_row, msg_col);
		continue;
	    }

	    if (c1 == Ctrl_D)
	    {
		
		p = (char_u *)line_ga.ga_data;
		if (prev_char == '0' || prev_char == '^')
		{
		    if (prev_char == '^')
			ex_keep_indent = TRUE;
		    indent = 0;
		    p[--line_ga.ga_len] = NUL;
		}
		else {
		    p[line_ga.ga_len] = NUL;
		    indent = get_indent_str(p, 8, FALSE);
		    if (indent > 0)
		    {
			--indent;
			indent -= indent % get_sw_value(curbuf);
		    }
		}
		while (get_indent_str(p, 8, FALSE) > indent)
		{
		    s = skipwhite(p);
		    mch_memmove(s - 1, s, line_ga.ga_len - (s - p) + 1);
		    --line_ga.ga_len;
		}
		goto add_indent;
	    }

	    if (c1 == Ctrl_V || c1 == Ctrl_Q)
	    {
		escaped = TRUE;
		continue;
	    }

	    
	    if (IS_SPECIAL(c1))
		continue;
	}

	if (IS_SPECIAL(c1))
	    c1 = '?';
	if (has_mbyte)
	    len = (*mb_char2bytes)(c1, (char_u *)line_ga.ga_data + line_ga.ga_len);
	else {
	    len = 1;
	    ((char_u *)line_ga.ga_data)[line_ga.ga_len] = c1;
	}
	if (c1 == '\n')
	    msg_putchar('\n');
	else if (c1 == TAB)
	{
	    
	    do msg_putchar(' ');
	    while (++vcol % 8);
	}
	else {
	    msg_outtrans_len( ((char_u *)line_ga.ga_data) + line_ga.ga_len, len);
	    vcol += char2cells(c1);
	}
	line_ga.ga_len += len;
	escaped = FALSE;

	windgoto(msg_row, msg_col);
	pend = (char_u *)(line_ga.ga_data) + line_ga.ga_len;

	
	
	if (line_ga.ga_len > 0 && pend[-1] == '\n')
	{
	    int bcount = 0;

	    while (line_ga.ga_len - 2 >= bcount && pend[-2 - bcount] == '\\')
		++bcount;

	    if (bcount > 0)
	    {
		
		
		line_ga.ga_len -= (bcount + 1) / 2;
		pend -= (bcount + 1) / 2;
		pend[-1] = '\n';
	    }

	    if ((bcount & 1) == 0)
	    {
		--line_ga.ga_len;
		--pend;
		*pend = NUL;
		break;
	    }
	}
    }

    --no_mapping;
    --allow_keys;

    
    msg_didout = FALSE;
    msg_col = 0;
    if (msg_row < Rows - 1)
	++msg_row;
    emsg_on_display = FALSE;		

    if (got_int)
	ga_clear(&line_ga);

    return (char_u *)line_ga.ga_data;
}



    int cmdline_overstrike(void)
{
    return ccline.overstrike;
}


    int cmdline_at_end(void)
{
    return (ccline.cmdpos >= ccline.cmdlen);
}




    colnr_T cmdline_getvcol_cursor(void)
{
    if (ccline.cmdbuff == NULL || ccline.cmdpos > ccline.cmdlen)
	return MAXCOL;

    if (has_mbyte)
    {
	colnr_T	col;
	int	i = 0;

	for (col = 0; i < ccline.cmdpos; ++col)
	    i += (*mb_ptr2len)(ccline.cmdbuff + i);

	return col;
    }
    else return ccline.cmdpos;
}




    static void redrawcmd_preedit(void)
{
    if ((State & MODE_CMDLINE)
	    && xic != NULL  && !p_imdisable && im_is_preediting())


    {
	int	cmdpos = 0;
	int	cmdspos;
	int	old_row;
	int	old_col;
	colnr_T	col;

	old_row = msg_row;
	old_col = msg_col;
	cmdspos = ((ccline.cmdfirstc != NUL) ? 1 : 0) + ccline.cmdindent;

	if (has_mbyte)
	{
	    for (col = 0; col < preedit_start_col && cmdpos < ccline.cmdlen; ++col)
	    {
		cmdspos += (*mb_ptr2cells)(ccline.cmdbuff + cmdpos);
		cmdpos  += (*mb_ptr2len)(ccline.cmdbuff + cmdpos);
	    }
	}
	else {
	    cmdspos += preedit_start_col;
	    cmdpos  += preedit_start_col;
	}

	msg_row = cmdline_row + (cmdspos / (int)Columns);
	msg_col = cmdspos % (int)Columns;
	if (msg_row >= Rows)
	    msg_row = Rows - 1;

	for (col = 0; cmdpos < ccline.cmdlen; ++col)
	{
	    int char_len;
	    int char_attr;

	    char_attr = im_get_feedback_attr(col);
	    if (char_attr < 0)
		break; 

	    if (has_mbyte)
		char_len = (*mb_ptr2len)(ccline.cmdbuff + cmdpos);
	    else char_len = 1;

	    msg_outtrans_len_attr(ccline.cmdbuff + cmdpos, char_len, char_attr);
	    cmdpos += char_len;
	}

	msg_row = old_row;
	msg_col = old_col;
    }
}



    static void alloc_cmdbuff(int len)
{
    
    if (len < 80)
	len = 100;
    else len += 20;

    ccline.cmdbuff = alloc(len);    
    ccline.cmdbufflen = len;
}


    int realloc_cmdbuff(int len)
{
    char_u	*p;

    if (len < ccline.cmdbufflen)
	return OK;			

    p = ccline.cmdbuff;
    alloc_cmdbuff(len);			
    if (ccline.cmdbuff == NULL)		
    {
	ccline.cmdbuff = p;		
	return FAIL;
    }
    
    
    mch_memmove(ccline.cmdbuff, p, (size_t)ccline.cmdlen);
    ccline.cmdbuff[ccline.cmdlen] = NUL;
    vim_free(p);

    if (ccline.xpc != NULL && ccline.xpc->xp_pattern != NULL && ccline.xpc->xp_context != EXPAND_NOTHING && ccline.xpc->xp_context != EXPAND_UNSUCCESSFUL)


    {
	int i = (int)(ccline.xpc->xp_pattern - p);

	
	
	if (i >= 0 && i <= ccline.cmdlen)
	    ccline.xpc->xp_pattern = ccline.cmdbuff + i;
    }

    return OK;
}


static char_u	*arshape_buf = NULL;


    void free_arshape_buf(void)
{
    vim_free(arshape_buf);
}




    static void draw_cmdline(int start, int len)
{

    int		i;

    if (cmdline_star > 0)
	for (i = 0; i < len; ++i)
	{
	    msg_putchar('*');
	    if (has_mbyte)
		i += (*mb_ptr2len)(ccline.cmdbuff + start + i) - 1;
	}
    else   if (p_arshape && !p_tbidi && cmdline_has_arabic(start, len))


    {
	static int	buflen = 0;
	char_u		*p;
	int		j;
	int		newlen = 0;
	int		mb_l;
	int		pc, pc1 = 0;
	int		prev_c = 0;
	int		prev_c1 = 0;
	int		u8c;
	int		u8cc[MAX_MCO];
	int		nc = 0;

	
	if (len * 2 + 2 > buflen)
	{
	    
	    
	    vim_free(arshape_buf);
	    buflen = len * 2 + 2;
	    arshape_buf = alloc(buflen);
	    if (arshape_buf == NULL)
		return;	
	}

	if (utf_iscomposing(utf_ptr2char(ccline.cmdbuff + start)))
	{
	    
	    arshape_buf[0] = ' ';
	    newlen = 1;
	}

	for (j = start; j < start + len; j += mb_l)
	{
	    p = ccline.cmdbuff + j;
	    u8c = utfc_ptr2char_len(p, u8cc, start + len - j);
	    mb_l = utfc_ptr2len_len(p, start + len - j);
	    if (ARABIC_CHAR(u8c))
	    {
		
		if (cmdmsg_rl)
		{
		    
		    pc = prev_c;
		    pc1 = prev_c1;
		    prev_c1 = u8cc[0];
		    if (j + mb_l >= start + len)
			nc = NUL;
		    else nc = utf_ptr2char(p + mb_l);
		}
		else {
		    
		    if (j + mb_l >= start + len)
			pc = NUL;
		    else {
			int	pcc[MAX_MCO];

			pc = utfc_ptr2char_len(p + mb_l, pcc, start + len - j - mb_l);
			pc1 = pcc[0];
		    }
		    nc = prev_c;
		}
		prev_c = u8c;

		u8c = arabic_shape(u8c, NULL, &u8cc[0], pc, pc1, nc);

		newlen += (*mb_char2bytes)(u8c, arshape_buf + newlen);
		if (u8cc[0] != 0)
		{
		    newlen += (*mb_char2bytes)(u8cc[0], arshape_buf + newlen);
		    if (u8cc[1] != 0)
			newlen += (*mb_char2bytes)(u8cc[1], arshape_buf + newlen);
		}
	    }
	    else {
		prev_c = u8c;
		mch_memmove(arshape_buf + newlen, p, mb_l);
		newlen += mb_l;
	    }
	}

	msg_outtrans_len(arshape_buf, newlen);
    }
    else  msg_outtrans_len(ccline.cmdbuff + start, len);

}


    void putcmdline(int c, int shift)
{
    if (cmd_silent)
	return;
    msg_no_more = TRUE;
    msg_putchar(c);
    if (shift)
	draw_cmdline(ccline.cmdpos, ccline.cmdlen - ccline.cmdpos);
    msg_no_more = FALSE;
    cursorcmd();
    extra_char = c;
    extra_char_shift = shift;
}


    void unputcmdline(void)
{
    if (cmd_silent)
	return;
    msg_no_more = TRUE;
    if (ccline.cmdlen == ccline.cmdpos)
	msg_putchar(' ');
    else if (has_mbyte)
	draw_cmdline(ccline.cmdpos, (*mb_ptr2len)(ccline.cmdbuff + ccline.cmdpos));
    else draw_cmdline(ccline.cmdpos, 1);
    msg_no_more = FALSE;
    cursorcmd();
    extra_char = NUL;
}


    int put_on_cmdline(char_u *str, int len, int redraw)
{
    int		retval;
    int		i;
    int		m;
    int		c;

    if (len < 0)
	len = (int)STRLEN(str);

    
    if (ccline.cmdlen + len + 1 >= ccline.cmdbufflen)
	retval = realloc_cmdbuff(ccline.cmdlen + len + 1);
    else retval = OK;
    if (retval == OK)
    {
	if (!ccline.overstrike)
	{
	    mch_memmove(ccline.cmdbuff + ccline.cmdpos + len, ccline.cmdbuff + ccline.cmdpos, (size_t)(ccline.cmdlen - ccline.cmdpos));

	    ccline.cmdlen += len;
	}
	else {
	    if (has_mbyte)
	    {
		
		m = 0;
		for (i = 0; i < len; i += (*mb_ptr2len)(str + i))
		    ++m;
		
		
		for (i = ccline.cmdpos; i < ccline.cmdlen && m > 0;
				 i += (*mb_ptr2len)(ccline.cmdbuff + i))
		    --m;
		if (i < ccline.cmdlen)
		{
		    mch_memmove(ccline.cmdbuff + ccline.cmdpos + len, ccline.cmdbuff + i, (size_t)(ccline.cmdlen - i));
		    ccline.cmdlen += ccline.cmdpos + len - i;
		}
		else ccline.cmdlen = ccline.cmdpos + len;
	    }
	    else if (ccline.cmdpos + len > ccline.cmdlen)
		ccline.cmdlen = ccline.cmdpos + len;
	}
	mch_memmove(ccline.cmdbuff + ccline.cmdpos, str, (size_t)len);
	ccline.cmdbuff[ccline.cmdlen] = NUL;

	if (enc_utf8)
	{
	    
	    
	    i = 0;
	    c = utf_ptr2char(ccline.cmdbuff + ccline.cmdpos);
	    while (ccline.cmdpos > 0 && utf_iscomposing(c))
	    {
		i = (*mb_head_off)(ccline.cmdbuff, ccline.cmdbuff + ccline.cmdpos - 1) + 1;
		ccline.cmdpos -= i;
		len += i;
		c = utf_ptr2char(ccline.cmdbuff + ccline.cmdpos);
	    }

	    if (i == 0 && ccline.cmdpos > 0 && arabic_maycombine(c))
	    {
		
		i = (*mb_head_off)(ccline.cmdbuff, ccline.cmdbuff + ccline.cmdpos - 1) + 1;
		if (arabic_combine(utf_ptr2char(ccline.cmdbuff + ccline.cmdpos - i), c))
		{
		    ccline.cmdpos -= i;
		    len += i;
		}
		else i = 0;
	    }

	    if (i != 0)
	    {
		
		i = ptr2cells(ccline.cmdbuff + ccline.cmdpos);
		ccline.cmdspos -= i;
		msg_col -= i;
		if (msg_col < 0)
		{
		    msg_col += Columns;
		    --msg_row;
		}
	    }
	}

	if (redraw && !cmd_silent)
	{
	    msg_no_more = TRUE;
	    i = cmdline_row;
	    cursorcmd();
	    draw_cmdline(ccline.cmdpos, ccline.cmdlen - ccline.cmdpos);
	    
	    if (cmdline_row != i || ccline.overstrike)
		msg_clr_eos();
	    msg_no_more = FALSE;
	}
	if (KeyTyped)
	{
	    m = Columns * Rows;
	    if (m < 0)	
		m = MAXCOL;
	}
	else m = MAXCOL;
	for (i = 0; i < len; ++i)
	{
	    c = cmdline_charsize(ccline.cmdpos);
	    
	    if (has_mbyte)
		correct_cmdspos(ccline.cmdpos, c);
	    
	    
	    
	    if (ccline.cmdspos + c < m)
		ccline.cmdspos += c;

	    if (has_mbyte)
	    {
		c = (*mb_ptr2len)(ccline.cmdbuff + ccline.cmdpos) - 1;
		if (c > len - i - 1)
		    c = len - i - 1;
		ccline.cmdpos += c;
		i += c;
	    }
	    ++ccline.cmdpos;
	}
    }
    if (redraw)
	msg_check();
    return retval;
}

static cmdline_info_T	prev_ccline;
static int		prev_ccline_used = FALSE;


    static void save_cmdline(cmdline_info_T *ccp)
{
    if (!prev_ccline_used)
    {
	CLEAR_FIELD(prev_ccline);
	prev_ccline_used = TRUE;
    }
    *ccp = prev_ccline;
    prev_ccline = ccline;
    ccline.cmdbuff = NULL;  
}


    static void restore_cmdline(cmdline_info_T *ccp)
{
    ccline = prev_ccline;
    prev_ccline = *ccp;
}


    static int cmdline_paste( int regname, int literally, int remcr)



{
    long		i;
    char_u		*arg;
    char_u		*p;
    int			allocated;

    
    
    if (regname != Ctrl_F && regname != Ctrl_P && regname != Ctrl_W && regname != Ctrl_A && regname != Ctrl_L && !valid_yank_reg(regname, FALSE))

	return FAIL;

    
    
    line_breakcheck();
    if (got_int)
	return FAIL;


    regname = may_get_selection(regname);


    
    
    ++textlock;
    i = get_spec_reg(regname, &arg, &allocated, TRUE);
    --textlock;

    if (i)
    {
	
	if (arg == NULL)
	    return FAIL;

	
	
	p = arg;
	if (p_is && regname == Ctrl_W)
	{
	    char_u  *w;
	    int	    len;

	    
	    for (w = ccline.cmdbuff + ccline.cmdpos; w > ccline.cmdbuff; )
	    {
		if (has_mbyte)
		{
		    len = (*mb_head_off)(ccline.cmdbuff, w - 1) + 1;
		    if (!vim_iswordc(mb_ptr2char(w - len)))
			break;
		    w -= len;
		}
		else {
		    if (!vim_iswordc(w[-1]))
			break;
		    --w;
		}
	    }
	    len = (int)((ccline.cmdbuff + ccline.cmdpos) - w);
	    if (p_ic ? STRNICMP(w, arg, len) == 0 : STRNCMP(w, arg, len) == 0)
		p += len;
	}

	cmdline_paste_str(p, literally);
	if (allocated)
	    vim_free(arg);
	return OK;
    }

    return cmdline_paste_reg(regname, literally, remcr);
}


    void cmdline_paste_str(char_u *s, int literally)
{
    int		c, cv;

    if (literally)
	put_on_cmdline(s, -1, TRUE);
    else while (*s != NUL)
	{
	    cv = *s;
	    if (cv == Ctrl_V && s[1])
		++s;
	    if (has_mbyte)
		c = mb_cptr2char_adv(&s);
	    else c = *s++;
	    if (cv == Ctrl_V || c == ESC || c == Ctrl_C || c == CAR || c == NL || c == Ctrl_L  || c == intr_char  || (c == Ctrl_BSL && *s == Ctrl_N))




		stuffcharReadbuff(Ctrl_V);
	    stuffcharReadbuff(c);
	}
}


    void redrawcmdline(void)
{
    redrawcmdline_ex(TRUE);
}


    void redrawcmdline_ex(int do_compute_cmdrow)
{
    if (cmd_silent)
	return;
    need_wait_return = FALSE;
    if (do_compute_cmdrow)
	compute_cmdrow();
    redrawcmd();
    cursorcmd();
}

    static void redrawcmdprompt(void)
{
    int		i;

    if (cmd_silent)
	return;
    if (ccline.cmdfirstc != NUL)
	msg_putchar(ccline.cmdfirstc);
    if (ccline.cmdprompt != NULL)
    {
	msg_puts_attr((char *)ccline.cmdprompt, ccline.cmdattr);
	ccline.cmdindent = msg_col + (msg_row - cmdline_row) * Columns;
	
	if (ccline.cmdfirstc != NUL)
	    --ccline.cmdindent;
    }
    else for (i = ccline.cmdindent; i > 0; --i)
	    msg_putchar(' ');
}


    void redrawcmd(void)
{
    if (cmd_silent)
	return;

    
    if (ccline.cmdbuff == NULL)
    {
	windgoto(cmdline_row, 0);
	msg_clr_eos();
	return;
    }

    msg_start();
    redrawcmdprompt();

    
    msg_no_more = TRUE;
    draw_cmdline(0, ccline.cmdlen);
    msg_clr_eos();
    msg_no_more = FALSE;

    set_cmdspos_cursor();
    if (extra_char != NUL)
	putcmdline(extra_char, extra_char_shift);

    
    msg_scroll = FALSE;		

    
    
    skip_redraw = FALSE;
}

    void compute_cmdrow(void)
{
    if (exmode_active || msg_scrolled != 0)
	cmdline_row = Rows - 1;
    else cmdline_row = W_WINROW(lastwin) + lastwin->w_height + lastwin->w_status_height;

}

    void cursorcmd(void)
{
    if (cmd_silent)
	return;


    if (cmdmsg_rl)
    {
	msg_row = cmdline_row  + (ccline.cmdspos / (int)(Columns - 1));
	msg_col = (int)Columns - (ccline.cmdspos % (int)(Columns - 1)) - 1;
	if (msg_row <= 0)
	    msg_row = Rows - 1;
    }
    else  {

	msg_row = cmdline_row + (ccline.cmdspos / (int)Columns);
	msg_col = ccline.cmdspos % (int)Columns;
	if (msg_row >= Rows)
	    msg_row = Rows - 1;
    }

    windgoto(msg_row, msg_col);

    if (p_imst == IM_ON_THE_SPOT)
	redrawcmd_preedit();


    mch_update_cursor();

}

    void gotocmdline(int clr)
{
    msg_start();

    if (cmdmsg_rl)
	msg_col = Columns - 1;
    else  msg_col = 0;

    if (clr)		    
	msg_clr_eos();	    
    windgoto(cmdline_row, 0);
}


    static int ccheck_abbr(int c)
{
    int spos = 0;

    if (p_paste || no_abbr)	    
	return FALSE;

    
    
    while (VIM_ISWHITE(ccline.cmdbuff[spos]) && spos < ccline.cmdlen)
	spos++;
    if (ccline.cmdlen - spos > 5 && ccline.cmdbuff[spos] == '\'' && ccline.cmdbuff[spos + 2] == ',' && ccline.cmdbuff[spos + 3] == '\'')


	spos += 5;
    else  spos = 0;


    return check_abbr(c, ccline.cmdbuff, ccline.cmdpos, spos);
}


    char_u * vim_strsave_fnameescape(char_u *fname, int what)
{
    char_u	*p;

    char_u	buf[20];
    int		j = 0;

    
    
    for (p = what == VSE_BUFFER ? BUFFER_ESC_CHARS : PATH_ESC_CHARS;
								*p != NUL; ++p)
	if ((*p != '[' && *p != '{' && *p != '!') || !vim_isfilec(*p))
	    buf[j++] = *p;
    buf[j] = NUL;
    p = vim_strsave_escaped(fname, buf);

    p = vim_strsave_escaped(fname, what == VSE_SHELL ? SHELL_ESC_CHARS : what == VSE_BUFFER ? BUFFER_ESC_CHARS : PATH_ESC_CHARS);
    if (what == VSE_SHELL && csh_like_shell() && p != NULL)
    {
	char_u	    *s;

	
	
	s = vim_strsave_escaped(p, (char_u *)"!");
	vim_free(p);
	p = s;
    }


    
    
    if (p != NULL && (*p == '>' || *p == '+' || (*p == '-' && p[1] == NUL)))
	escape_fname(&p);

    return p;
}


    void escape_fname(char_u **pp)
{
    char_u	*p;

    p = alloc(STRLEN(*pp) + 2);
    if (p != NULL)
    {
	p[0] = '\\';
	STRCPY(p + 1, *pp);
	vim_free(*pp);
	*pp = p;
    }
}


    void tilde_replace( char_u  *orig_pat, int	    num_files, char_u  **files)



{
    int	    i;
    char_u  *p;

    if (orig_pat[0] == '~' && vim_ispathsep(orig_pat[1]))
    {
	for (i = 0; i < num_files; ++i)
	{
	    p = home_replace_save(NULL, files[i]);
	    if (p != NULL)
	    {
		vim_free(files[i]);
		files[i] = p;
	    }
	}
    }
}


    cmdline_info_T * get_cmdline_info(void)
{
    return &ccline;
}



    static cmdline_info_T * get_ccline_ptr(void)
{
    if ((State & MODE_CMDLINE) == 0)
	return NULL;
    if (ccline.cmdbuff != NULL)
	return &ccline;
    if (prev_ccline_used && prev_ccline.cmdbuff != NULL)
	return &prev_ccline;
    return NULL;
}




    static char_u * get_cmdline_str(void)
{
    cmdline_info_T *p;

    if (cmdline_star > 0)
	return NULL;
    p = get_ccline_ptr();
    if (p == NULL)
	return NULL;
    return vim_strnsave(p->cmdbuff, p->cmdlen);
}


    static char_u * get_cmdline_completion(void)
{
    cmdline_info_T *p;

    if (cmdline_star > 0)
	return NULL;

    p = get_ccline_ptr();
    if (p != NULL && p->xpc != NULL)
    {
	char_u *cmd_compl;

	set_expand_context(p->xpc);

	cmd_compl = cmdcomplete_type_to_str(p->xpc->xp_context);
	if (cmd_compl != NULL)
	    return vim_strsave(cmd_compl);
    }

    return NULL;
}


    void f_getcmdcompltype(typval_T *argvars UNUSED, typval_T *rettv)
{
    rettv->v_type = VAR_STRING;
    rettv->vval.v_string = get_cmdline_completion();
}


    void f_getcmdline(typval_T *argvars UNUSED, typval_T *rettv)
{
    rettv->v_type = VAR_STRING;
    rettv->vval.v_string = get_cmdline_str();
}


    void f_getcmdpos(typval_T *argvars UNUSED, typval_T *rettv)
{
    cmdline_info_T *p = get_ccline_ptr();

    rettv->vval.v_number = 0;
    if (p != NULL)
    rettv->vval.v_number = p->cmdpos + 1;
}


    static int get_cmdline_screen_pos(void)
{
    cmdline_info_T *p = get_ccline_ptr();

    if (p == NULL)
	return -1;
    return p->cmdspos;
}


    void f_getcmdscreenpos(typval_T *argvars UNUSED, typval_T *rettv)
{
    rettv->vval.v_number = get_cmdline_screen_pos() + 1;
}


    static int set_cmdline_pos( int		pos)

{
    cmdline_info_T *p = get_ccline_ptr();

    if (p == NULL)
	return 1;

    
    
    if (pos < 0)
	new_cmdpos = 0;
    else new_cmdpos = pos;
    return 0;
}


    void f_setcmdpos(typval_T *argvars, typval_T *rettv)
{
    int		pos;

    if (in_vim9script() && check_for_number_arg(argvars, 0) == FAIL)
	return;

    pos = (int)tv_get_number(&argvars[0]) - 1;
    if (pos >= 0)
	rettv->vval.v_number = set_cmdline_pos(pos);
}




    static int get_cmdline_type(void)
{
    cmdline_info_T *p = get_ccline_ptr();

    if (p == NULL)
	return NUL;
    if (p->cmdfirstc == NUL)
	return  (p->input_fn) ? '@' :


	    '-';
    return p->cmdfirstc;
}




    void f_getcmdtype(typval_T *argvars UNUSED, typval_T *rettv)
{
    rettv->v_type = VAR_STRING;
    rettv->vval.v_string = alloc(2);
    if (rettv->vval.v_string != NULL)
    {
	rettv->vval.v_string[0] = get_cmdline_type();
	rettv->vval.v_string[1] = NUL;
    }
}




    int get_cmdline_firstc(void)
{
    return ccline.cmdfirstc;
}


    int get_list_range(char_u **str, int *num1, int *num2)
{
    int		len;
    int		first = FALSE;
    varnumber_T	num;

    *str = skipwhite(*str);
    if (**str == '-' || vim_isdigit(**str))  
    {
	vim_str2nr(*str, NULL, &len, 0, &num, NULL, 0, FALSE);
	*str += len;
	*num1 = (int)num;
	first = TRUE;
    }
    *str = skipwhite(*str);
    if (**str == ',')			
    {
	*str = skipwhite(*str + 1);
	vim_str2nr(*str, NULL, &len, 0, &num, NULL, 0, FALSE);
	if (len > 0)
	{
	    *num2 = (int)num;
	    *str = skipwhite(*str + len);
	}
	else if (!first)		
	    return FAIL;
    }
    else if (first)			
	*num2 = *num1;
    return OK;
}



    char * check_cedit(void)
{
    int n;

    if (*p_cedit == NUL)
	cedit_key = -1;
    else {
	n = string_to_key(p_cedit, FALSE);
	if (vim_isprintc(n))
	    return e_invalid_argument;
	cedit_key = n;
    }
    return NULL;
}


    static int open_cmdwin(void)
{
    bufref_T		old_curbuf;
    win_T		*old_curwin = curwin;
    bufref_T		bufref;
    win_T		*wp;
    int			i;
    linenr_T		lnum;
    int			histtype;
    garray_T		winsizes;
    int			save_restart_edit = restart_edit;
    int			save_State = State;
    int			save_exmode = exmode_active;

    int			save_cmdmsg_rl = cmdmsg_rl;


    int			save_KeyTyped;


    
    if (cmdwin_type != 0  || cmdline_star > 0  )



    {
	beep_flush();
	return K_IGNORE;
    }
    set_bufref(&old_curbuf, curbuf);

    
    win_size_save(&winsizes);

    
    
    pum_undisplay();

    
    cmdmod.cmod_tab = 0;
    cmdmod.cmod_flags |= CMOD_NOSWAPFILE;

    
    if (win_split((int)p_cwh, WSP_BOT) == FAIL)
    {
	beep_flush();
	ga_clear(&winsizes);
	return K_IGNORE;
    }
    
    got_int = FALSE;

    
    cmdwin_type = get_cmdline_type();

    
    if (do_ecmd(0, NULL, NULL, NULL, ECMD_ONE, ECMD_HIDE, NULL) == FAIL)
    {
	
	win_close(curwin, TRUE);
	ga_clear(&winsizes);
	cmdwin_type = 0;
	return Ctrl_C;
    }

    apply_autocmds(EVENT_BUFFILEPRE, NULL, NULL, FALSE, curbuf);
    (void)setfname(curbuf, (char_u *)_("[Command Line]"), NULL, TRUE);
    apply_autocmds(EVENT_BUFFILEPOST, NULL, NULL, FALSE, curbuf);
    set_option_value_give_err((char_u *)"bt", 0L, (char_u *)"nofile", OPT_LOCAL);
    curbuf->b_p_ma = TRUE;

    curwin->w_p_fen = FALSE;


    curwin->w_p_rl = cmdmsg_rl;
    cmdmsg_rl = FALSE;

    RESET_BINDING(curwin);

    
    ++curbuf_lock;

    
    need_wait_return = FALSE;

    histtype = hist_char2type(cmdwin_type);
    if (histtype == HIST_CMD || histtype == HIST_DEBUG)
    {
	if (p_wc == TAB)
	{
	    add_map((char_u *)"<buffer> <Tab> <C-X><C-V>", MODE_INSERT);
	    add_map((char_u *)"<buffer> <Tab> a<C-X><C-V>", MODE_NORMAL);
	}
	set_option_value_give_err((char_u *)"ft", 0L, (char_u *)"vim", OPT_LOCAL);
    }
    --curbuf_lock;

    
    
    curbuf->b_p_tw = 0;

    
    init_history();
    if (get_hislen() > 0)
    {
	i = *get_hisidx(histtype);
	if (i >= 0)
	{
	    lnum = 0;
	    do {
		if (++i == get_hislen())
		    i = 0;
		if (get_histentry(histtype)[i].hisstr != NULL)
		    ml_append(lnum++, get_histentry(histtype)[i].hisstr, (colnr_T)0, FALSE);
	    }
	    while (i != *get_hisidx(histtype));
	}
    }

    
    
    ml_replace(curbuf->b_ml.ml_line_count, ccline.cmdbuff, TRUE);
    curwin->w_cursor.lnum = curbuf->b_ml.ml_line_count;
    curwin->w_cursor.col = ccline.cmdpos;
    changed_line_abv_curs();
    invalidate_botline();
    redraw_later(SOME_VALID);

    
    exmode_active = 0;

    State = MODE_NORMAL;
    setmouse();

    
    cmdwin_result = 0;

    
    trigger_cmd_autocmd(cmdwin_type, EVENT_CMDWINENTER);
    if (restart_edit != 0)	
	stuffcharReadbuff(K_NOP);

    i = RedrawingDisabled;
    RedrawingDisabled = 0;

    
    main_loop(TRUE, FALSE);

    RedrawingDisabled = i;


    save_KeyTyped = KeyTyped;


    
    trigger_cmd_autocmd(cmdwin_type, EVENT_CMDWINLEAVE);


    
    KeyTyped = save_KeyTyped;


    cmdwin_type = 0;
    exmode_active = save_exmode;

    
    
    if (!win_valid(old_curwin) || !bufref_valid(&old_curbuf))
    {
	cmdwin_result = Ctrl_C;
	emsg(_(e_active_window_or_buffer_deleted));
    }
    else {

	
	if (aborting() && cmdwin_result != K_IGNORE)
	    cmdwin_result = Ctrl_C;

	
	vim_free(ccline.cmdbuff);
	if (cmdwin_result == K_XF1 || cmdwin_result == K_XF2) 
	{
	    char *p = (cmdwin_result == K_XF2) ? "qa" : "qa!";

	    if (histtype == HIST_CMD)
	    {
		
		ccline.cmdbuff = vim_strsave((char_u *)p);
		cmdwin_result = CAR;
	    }
	    else {
		
		ccline.cmdbuff = NULL;
		stuffcharReadbuff(':');
		stuffReadbuff((char_u *)p);
		stuffcharReadbuff(CAR);
	    }
	}
	else if (cmdwin_result == K_XF2)	
	{
	    ccline.cmdbuff = vim_strsave((char_u *)"qa");
	    cmdwin_result = CAR;
	}
	else if (cmdwin_result == Ctrl_C)
	{
	    
	    
	    ccline.cmdbuff = NULL;
	}
	else ccline.cmdbuff = vim_strsave(ml_get_curline());
	if (ccline.cmdbuff == NULL)
	{
	    ccline.cmdbuff = vim_strsave((char_u *)"");
	    ccline.cmdlen = 0;
	    ccline.cmdbufflen = 1;
	    ccline.cmdpos = 0;
	    cmdwin_result = Ctrl_C;
	}
	else {
	    ccline.cmdlen = (int)STRLEN(ccline.cmdbuff);
	    ccline.cmdbufflen = ccline.cmdlen + 1;
	    ccline.cmdpos = curwin->w_cursor.col;
	    if (ccline.cmdpos > ccline.cmdlen)
		ccline.cmdpos = ccline.cmdlen;
	    if (cmdwin_result == K_IGNORE)
	    {
		set_cmdspos_cursor();
		redrawcmd();
	    }
	}


	
	curwin->w_p_cole = 0;

	
	wp = curwin;
	set_bufref(&bufref, curbuf);
	win_goto(old_curwin);

	
	
	if (win_valid(wp) && wp != curwin)
	    win_close(wp, TRUE);

	
	
	if (bufref_valid(&bufref) && bufref.br_buf != curbuf)
	    close_buffer(NULL, bufref.br_buf, DOBUF_WIPE, FALSE, FALSE);

	
	win_size_restore(&winsizes);
    }

    ga_clear(&winsizes);
    restart_edit = save_restart_edit;

    cmdmsg_rl = save_cmdmsg_rl;


    State = save_State;
    setmouse();

    return cmdwin_result;
}


    int is_in_cmdwin(void)
{
    return cmdwin_type != 0 && get_cmdline_type() == NUL;
}



    char_u * script_get(exarg_T *eap UNUSED, char_u *cmd UNUSED)
{

    list_T	*l;
    listitem_T	*li;
    char_u	*s;
    garray_T	ga;

    if (cmd[0] != '<' || cmd[1] != '<' || eap->getline == NULL)
	return NULL;
    cmd += 2;

    l = heredoc_get(eap, cmd, TRUE, FALSE);
    if (l == NULL)
	return NULL;

    ga_init2(&ga, 1, 0x400);

    FOR_ALL_LIST_ITEMS(l, li)
    {
	s = tv_get_string(&li->li_tv);
	ga_concat(&ga, s);
	ga_append(&ga, '\n');
    }
    ga_append(&ga, NUL);

    list_free(l);
    return (char_u *)ga.ga_data;

    return NULL;

}



    void get_user_input( typval_T	*argvars, typval_T	*rettv, int		inputdialog, int		secret)




{
    char_u	*prompt;
    char_u	*p = NULL;
    int		c;
    char_u	buf[NUMBUFLEN];
    int		cmd_silent_save = cmd_silent;
    char_u	*defstr = (char_u *)"";
    int		xp_type = EXPAND_NOTHING;
    char_u	*xp_arg = NULL;

    rettv->v_type = VAR_STRING;
    rettv->vval.v_string = NULL;
    if (input_busy)
	return;  

    if (in_vim9script()
	    && (check_for_string_arg(argvars, 0) == FAIL || check_for_opt_string_arg(argvars, 1) == FAIL || (argvars[1].v_type != VAR_UNKNOWN && check_for_opt_string_arg(argvars, 2) == FAIL)))


	return;

    prompt = tv_get_string_chk(&argvars[0]);


    
    
    if (no_console_input() && !is_not_a_term())
	return;


    cmd_silent = FALSE;		
    if (prompt != NULL)
    {
	
	
	p = vim_strrchr(prompt, '\n');
	if (p == NULL)
	    p = prompt;
	else {
	    ++p;
	    c = *p;
	    *p = NUL;
	    msg_start();
	    msg_clr_eos();
	    msg_puts_attr((char *)prompt, get_echo_attr());
	    msg_didout = FALSE;
	    msg_starthere();
	    *p = c;
	}
	cmdline_row = msg_row;

	if (argvars[1].v_type != VAR_UNKNOWN)
	{
	    defstr = tv_get_string_buf_chk(&argvars[1], buf);
	    if (defstr != NULL)
		stuffReadbuffSpec(defstr);

	    if (!inputdialog && argvars[2].v_type != VAR_UNKNOWN)
	    {
		char_u	*xp_name;
		int	xp_namelen;
		long	argt = 0;

		
		rettv->vval.v_string = NULL;

		xp_name = tv_get_string_buf_chk(&argvars[2], buf);
		if (xp_name == NULL)
		    return;

		xp_namelen = (int)STRLEN(xp_name);

		if (parse_compl_arg(xp_name, xp_namelen, &xp_type, &argt, &xp_arg) == FAIL)
		    return;
	    }
	}

	if (defstr != NULL)
	{
	    int save_ex_normal_busy = ex_normal_busy;
	    int save_vgetc_busy = vgetc_busy;
	    int save_input_busy = input_busy;

	    input_busy |= vgetc_busy;
	    ex_normal_busy = 0;
	    vgetc_busy = 0;
	    rettv->vval.v_string = getcmdline_prompt(secret ? NUL : '@', p, get_echo_attr(), xp_type, xp_arg);

	    ex_normal_busy = save_ex_normal_busy;
	    vgetc_busy = save_vgetc_busy;
	    input_busy = save_input_busy;
	}
	if (inputdialog && rettv->vval.v_string == NULL && argvars[1].v_type != VAR_UNKNOWN && argvars[2].v_type != VAR_UNKNOWN)

	    rettv->vval.v_string = vim_strsave(tv_get_string_buf( &argvars[2], buf));

	vim_free(xp_arg);

	
	need_wait_return = FALSE;
	msg_didout = FALSE;
    }
    cmd_silent = cmd_silent_save;
}

