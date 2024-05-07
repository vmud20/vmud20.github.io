








    int tabstop_set(char_u *var, int **array)
{
    int	    valcount = 1;
    int	    t;
    char_u  *cp;

    if (var[0] == NUL || (var[0] == '0' && var[1] == NUL))
    {
	*array = NULL;
	return OK;
    }

    for (cp = var; *cp != NUL; ++cp)
    {
	if (cp == var || cp[-1] == ',')
	{
	    char_u *end;

	    if (strtol((char *)cp, (char **)&end, 10) <= 0)
	    {
		if (cp != end)
		    emsg(_(e_argument_must_be_positive));
		else semsg(_(e_invalid_argument_str), cp);
		return FAIL;
	    }
	}

	if (VIM_ISDIGIT(*cp))
	    continue;
	if (cp[0] == ',' && cp > var && cp[-1] != ',' && cp[1] != NUL)
	{
	    ++valcount;
	    continue;
	}
	semsg(_(e_invalid_argument_str), var);
	return FAIL;
    }

    *array = ALLOC_MULT(int, valcount + 1);
    if (*array == NULL)
	return FAIL;
    (*array)[0] = valcount;

    t = 1;
    for (cp = var; *cp != NUL;)
    {
	int n = atoi((char *)cp);

	
	if (n < 0 || n > 9999)
	{
	    semsg(_(e_invalid_argument_str), cp);
	    vim_free(*array);
	    *array = NULL;
	    return FAIL;
	}
	(*array)[t++] = n;
	while (*cp != NUL && *cp != ',')
	    ++cp;
	if (*cp != NUL)
	    ++cp;
    }

    return OK;
}


    int tabstop_padding(colnr_T col, int ts_arg, int *vts)
{
    int		ts = ts_arg == 0 ? 8 : ts_arg;
    int		tabcount;
    colnr_T	tabcol = 0;
    int		t;
    int		padding = 0;

    if (vts == NULL || vts[0] == 0)
	return ts - (col % ts);

    tabcount = vts[0];

    for (t = 1; t <= tabcount; ++t)
    {
	tabcol += vts[t];
	if (tabcol > col)
	{
	    padding = (int)(tabcol - col);
	    break;
	}
    }
    if (t > tabcount)
	padding = vts[tabcount] - (int)((col - tabcol) % vts[tabcount]);

    return padding;
}


    int tabstop_at(colnr_T col, int ts, int *vts)
{
    int		tabcount;
    colnr_T	tabcol = 0;
    int		t;
    int		tab_size = 0;

    if (vts == 0 || vts[0] == 0)
	return ts;

    tabcount = vts[0];
    for (t = 1; t <= tabcount; ++t)
    {
	tabcol += vts[t];
	if (tabcol > col)
	{
	    tab_size = vts[t];
	    break;
	}
    }
    if (t > tabcount)
	tab_size = vts[tabcount];

    return tab_size;
}


    colnr_T tabstop_start(colnr_T col, int ts, int *vts)
{
    int		tabcount;
    colnr_T	tabcol = 0;
    int		t;
    int         excess;

    if (vts == NULL || vts[0] == 0)
	return (col / ts) * ts;

    tabcount = vts[0];
    for (t = 1; t <= tabcount; ++t)
    {
	tabcol += vts[t];
	if (tabcol > col)
	    return tabcol - vts[t];
    }

    excess = tabcol % vts[tabcount];
    return excess + ((col - excess) / vts[tabcount]) * vts[tabcount];
}


    void tabstop_fromto( colnr_T start_col, colnr_T end_col, int	ts_arg, int	*vts, int	*ntabs, int	*nspcs)






{
    int		spaces = end_col - start_col;
    colnr_T	tabcol = 0;
    int		padding = 0;
    int		tabcount;
    int		t;
    int		ts = ts_arg == 0 ? curbuf->b_p_ts : ts_arg;

    if (vts == NULL || vts[0] == 0)
    {
	int tabs = 0;
	int initspc = 0;

	initspc = ts - (start_col % ts);
	if (spaces >= initspc)
	{
	    spaces -= initspc;
	    tabs++;
	}
	tabs += spaces / ts;
	spaces -= (spaces / ts) * ts;

	*ntabs = tabs;
	*nspcs = spaces;
	return;
    }

    
    tabcount = vts[0];
    for (t = 1; t <= tabcount; ++t)
    {
	tabcol += vts[t];
	if (tabcol > start_col)
	{
	    padding = (int)(tabcol - start_col);
	    break;
	}
    }
    if (t > tabcount)
	padding = vts[tabcount] - (int)((start_col - tabcol) % vts[tabcount]);

    
    if (spaces < padding)
    {
	*ntabs = 0;
	*nspcs = spaces;
	return;
    }

    *ntabs = 1;
    spaces -= padding;

    
    while (spaces != 0 && ++t <= tabcount)
    {
	padding = vts[t];
	if (spaces < padding)
	{
	    *nspcs = spaces;
	    return;
	}
	++*ntabs;
	spaces -= padding;
    }

    *ntabs += spaces / vts[tabcount];
    *nspcs =  spaces % vts[tabcount];
}


    static int tabstop_eq(int *ts1, int *ts2)
{
    int		t;

    if ((ts1 == 0 && ts2) || (ts1 && ts2 == 0))
	return FALSE;
    if (ts1 == ts2)
	return TRUE;
    if (ts1[0] != ts2[0])
	return FALSE;

    for (t = 1; t <= ts1[0]; ++t)
	if (ts1[t] != ts2[t])
	    return FALSE;

    return TRUE;
}



    int * tabstop_copy(int *oldts)
{
    int		*newts;
    int		t;

    if (oldts == NULL)
	return NULL;
    newts = ALLOC_MULT(int, oldts[0] + 1);
    if (newts != NULL)
	for (t = 0; t <= oldts[0]; ++t)
	    newts[t] = oldts[t];
    return newts;
}



    int tabstop_count(int *ts)
{
    return ts != NULL ? ts[0] : 0;
}


    int tabstop_first(int *ts)
{
    return ts != NULL ? ts[1] : 8;
}




    long get_sw_value(buf_T *buf)
{
    return get_sw_value_col(buf, 0);
}


    static long get_sw_value_pos(buf_T *buf, pos_T *pos)
{
    pos_T save_cursor = curwin->w_cursor;
    long sw_value;

    curwin->w_cursor = *pos;
    sw_value = get_sw_value_col(buf, get_nolist_virtcol());
    curwin->w_cursor = save_cursor;
    return sw_value;
}


    long get_sw_value_indent(buf_T *buf)
{
    pos_T pos = curwin->w_cursor;

    pos.col = getwhitecols_curline();
    return get_sw_value_pos(buf, &pos);
}


    long get_sw_value_col(buf_T *buf, colnr_T col UNUSED)
{
    return buf->b_p_sw ? buf->b_p_sw :

	tabstop_at(col, buf->b_p_ts, buf->b_p_vts_array);

	buf->b_p_ts;

}


    long get_sts_value(void)
{
    return curbuf->b_p_sts < 0 ? get_sw_value(curbuf) : curbuf->b_p_sts;
}


    int get_indent(void)
{

    return get_indent_str_vtab(ml_get_curline(), (int)curbuf->b_p_ts, curbuf->b_p_vts_array, FALSE);

    return get_indent_str(ml_get_curline(), (int)curbuf->b_p_ts, FALSE);

}


    int get_indent_lnum(linenr_T lnum)
{

    return get_indent_str_vtab(ml_get(lnum), (int)curbuf->b_p_ts, curbuf->b_p_vts_array, FALSE);

    return get_indent_str(ml_get(lnum), (int)curbuf->b_p_ts, FALSE);

}



    int get_indent_buf(buf_T *buf, linenr_T lnum)
{

    return get_indent_str_vtab(ml_get_buf(buf, lnum, FALSE), (int)curbuf->b_p_ts, buf->b_p_vts_array, FALSE);

    return get_indent_str(ml_get_buf(buf, lnum, FALSE), (int)buf->b_p_ts, FALSE);

}



    int get_indent_str( char_u	*ptr, int		ts, int		list)



{
    int		count = 0;

    for ( ; *ptr; ++ptr)
    {
	if (*ptr == TAB)
	{
	    if (!list || curwin->w_lcs_chars.tab1)
		
		count += ts - (count % ts);
	    else   count += ptr2cells(ptr);


	}
	else if (*ptr == ' ')
	    ++count;		
	else break;
    }
    return count;
}



    int get_indent_str_vtab(char_u *ptr, int ts, int *vts, int list)
{
    int		count = 0;

    for ( ; *ptr; ++ptr)
    {
	if (*ptr == TAB)    
	{
	    if (!list || curwin->w_lcs_chars.tab1)
		count += tabstop_padding(count, ts, vts);
	    else   count += ptr2cells(ptr);


	}
	else if (*ptr == ' ')
	    ++count;		
	else break;
    }
    return count;
}



    int set_indent( int		size, int		flags)


{
    char_u	*p;
    char_u	*newline;
    char_u	*oldline;
    char_u	*s;
    int		todo;
    int		ind_len;	    
    int		line_len;
    int		doit = FALSE;
    int		ind_done = 0;	    

    int		ind_col = 0;

    int		tab_pad;
    int		retval = FALSE;
    int		orig_char_len = -1; 
				    

    
    
    todo = size;
    ind_len = 0;
    p = oldline = ml_get_curline();

    
    

    
    
    
    if (!curbuf->b_p_et || (!(flags & SIN_INSERT) && curbuf->b_p_pi))
    {
	
	
	if (!(flags & SIN_INSERT) && curbuf->b_p_pi)
	{
	    ind_done = 0;

	    
	    while (todo > 0 && VIM_ISWHITE(*p))
	    {
		if (*p == TAB)
		{

		    tab_pad = tabstop_padding(ind_done, curbuf->b_p_ts, curbuf->b_p_vts_array);

		    tab_pad = (int)curbuf->b_p_ts - (ind_done % (int)curbuf->b_p_ts);

		    
		    if (todo < tab_pad)
			break;
		    todo -= tab_pad;
		    ++ind_len;
		    ind_done += tab_pad;
		}
		else {
		    --todo;
		    ++ind_len;
		    ++ind_done;
		}
		++p;
	    }


	    
	    ind_col = ind_done;

	    
	    
	    if (curbuf->b_p_et)
		orig_char_len = ind_len;

	    

	    tab_pad = tabstop_padding(ind_done, curbuf->b_p_ts, curbuf->b_p_vts_array);

	    tab_pad = (int)curbuf->b_p_ts - (ind_done % (int)curbuf->b_p_ts);

	    if (todo >= tab_pad && orig_char_len == -1)
	    {
		doit = TRUE;
		todo -= tab_pad;
		++ind_len;
		

		ind_col += tab_pad;

	    }
	}

	

	for (;;)
	{
	    tab_pad = tabstop_padding(ind_col, curbuf->b_p_ts, curbuf->b_p_vts_array);
	    if (todo < tab_pad)
		break;
	    if (*p != TAB)
		doit = TRUE;
	    else ++p;
	    todo -= tab_pad;
	    ++ind_len;
	    ind_col += tab_pad;
	}

	while (todo >= (int)curbuf->b_p_ts)
	{
	    if (*p != TAB)
		doit = TRUE;
	    else ++p;
	    todo -= (int)curbuf->b_p_ts;
	    ++ind_len;
	    
	}

    }
    
    while (todo > 0)
    {
	if (*p != ' ')
	    doit = TRUE;
	else ++p;
	--todo;
	++ind_len;
	
    }

    
    if (!doit && !VIM_ISWHITE(*p) && !(flags & SIN_INSERT))
	return FALSE;

    
    if (flags & SIN_INSERT)
	p = oldline;
    else p = skipwhite(p);
    line_len = (int)STRLEN(p) + 1;

    
    
    
    if (orig_char_len != -1)
    {
	newline = alloc(orig_char_len + size - ind_done + line_len);
	if (newline == NULL)
	    return FALSE;
	todo = size - ind_done;
	ind_len = orig_char_len + todo;    
					   
					   
	p = oldline;
	s = newline;
	while (orig_char_len > 0)
	{
	    *s++ = *p++;
	    orig_char_len--;
	}

	
	
	while (VIM_ISWHITE(*p))
	    ++p;

    }
    else {
	todo = size;
	newline = alloc(ind_len + line_len);
	if (newline == NULL)
	    return FALSE;
	s = newline;
    }

    
    
    if (!curbuf->b_p_et)
    {
	
	
	if (!(flags & SIN_INSERT) && curbuf->b_p_pi)
	{
	    p = oldline;
	    ind_done = 0;

	    while (todo > 0 && VIM_ISWHITE(*p))
	    {
		if (*p == TAB)
		{

		    tab_pad = tabstop_padding(ind_done, curbuf->b_p_ts, curbuf->b_p_vts_array);

		    tab_pad = (int)curbuf->b_p_ts - (ind_done % (int)curbuf->b_p_ts);

		    
		    if (todo < tab_pad)
			break;
		    todo -= tab_pad;
		    ind_done += tab_pad;
		}
		else {
		    --todo;
		    ++ind_done;
		}
		*s++ = *p++;
	    }

	    

	    tab_pad = tabstop_padding(ind_done, curbuf->b_p_ts, curbuf->b_p_vts_array);

	    tab_pad = (int)curbuf->b_p_ts - (ind_done % (int)curbuf->b_p_ts);

	    if (todo >= tab_pad)
	    {
		*s++ = TAB;
		todo -= tab_pad;

		ind_done += tab_pad;

	    }

	    p = skipwhite(p);
	}


	for (;;)
	{
	    tab_pad = tabstop_padding(ind_done, curbuf->b_p_ts, curbuf->b_p_vts_array);
	    if (todo < tab_pad)
		break;
	    *s++ = TAB;
	    todo -= tab_pad;
	    ind_done += tab_pad;
	}

	while (todo >= (int)curbuf->b_p_ts)
	{
	    *s++ = TAB;
	    todo -= (int)curbuf->b_p_ts;
	}

    }
    while (todo > 0)
    {
	*s++ = ' ';
	--todo;
    }
    mch_memmove(s, p, (size_t)line_len);

    
    if (!(flags & SIN_UNDO) || u_savesub(curwin->w_cursor.lnum) == OK)
    {
	colnr_T old_offset = (colnr_T)(p - oldline);
	colnr_T new_offset = (colnr_T)(s - newline);

	
	ml_replace(curwin->w_cursor.lnum, newline, FALSE);
	if (flags & SIN_CHANGED)
	    changed_bytes(curwin->w_cursor.lnum, 0);

	
	if (saved_cursor.lnum == curwin->w_cursor.lnum)
	{
	    if (saved_cursor.col >= old_offset)
		
		
		saved_cursor.col += ind_len - old_offset;
	    else if (saved_cursor.col >= new_offset)
		
		
		saved_cursor.col = new_offset;
	}

	{
	    int added = ind_len - old_offset;

	    
	    
	    
	    adjust_prop_columns(curwin->w_cursor.lnum, added > 0 ? old_offset : (colnr_T)ind_len, added, 0);
	}

	retval = TRUE;
    }
    else vim_free(newline);

    curwin->w_cursor.col = ind_len;
    return retval;
}


    int get_number_indent(linenr_T lnum)
{
    colnr_T	col;
    pos_T	pos;

    regmatch_T	regmatch;
    int		lead_len = 0;	

    if (lnum > curbuf->b_ml.ml_line_count)
	return -1;
    pos.lnum = 0;

    
    if ((State & INSERT) || has_format_option(FO_Q_COMS))
	lead_len = get_leader_len(ml_get(lnum), NULL, FALSE, TRUE);

    regmatch.regprog = vim_regcomp(curbuf->b_p_flp, RE_MAGIC);
    if (regmatch.regprog != NULL)
    {
	regmatch.rm_ic = FALSE;

	
	
	if (vim_regexec(&regmatch, ml_get(lnum) + lead_len, (colnr_T)0))
	{
	    pos.lnum = lnum;
	    pos.col = (colnr_T)(*regmatch.endp - ml_get(lnum));
	    pos.coladd = 0;
	}
	vim_regfree(regmatch.regprog);
    }

    if (pos.lnum == 0 || *ml_get_pos(&pos) == NUL)
	return -1;
    getvcol(curwin, &pos, &col, NULL, NULL);
    return (int)col;
}



    int briopt_check(win_T *wp)
{
    char_u	*p;
    int		bri_shift = 0;
    long	bri_min = 20;
    int		bri_sbr = FALSE;
    int		bri_list = 0;

    p = wp->w_p_briopt;
    while (*p != NUL)
    {
	if (STRNCMP(p, "shift:", 6) == 0 && ((p[6] == '-' && VIM_ISDIGIT(p[7])) || VIM_ISDIGIT(p[6])))
	{
	    p += 6;
	    bri_shift = getdigits(&p);
	}
	else if (STRNCMP(p, "min:", 4) == 0 && VIM_ISDIGIT(p[4]))
	{
	    p += 4;
	    bri_min = getdigits(&p);
	}
	else if (STRNCMP(p, "sbr", 3) == 0)
	{
	    p += 3;
	    bri_sbr = TRUE;
	}
	else if (STRNCMP(p, "list:", 5) == 0)
	{
	    p += 5;
	    bri_list = getdigits(&p);
	}
	if (*p != ',' && *p != NUL)
	    return FAIL;
	if (*p == ',')
	    ++p;
    }

    wp->w_briopt_shift = bri_shift;
    wp->w_briopt_min   = bri_min;
    wp->w_briopt_sbr   = bri_sbr;
    wp->w_briopt_list  = bri_list;

    return OK;
}


    int get_breakindent_win( win_T	*wp, char_u	*line)


{
    static int	    prev_indent = 0;	
    static long	    prev_ts     = 0L;	
    static char_u   *prev_line = NULL;	
    static varnumber_T prev_tick = 0;   

    static int      *prev_vts = NULL;   

    static int      prev_list = 0;	
    static int      prev_listopt = 0;	
    
    static char_u   *prev_flp = NULL;
    int		    bri = 0;
    
    const int	    eff_wwidth = wp->w_width - ((wp->w_p_nu || wp->w_p_rnu)
				&& (vim_strchr(p_cpo, CPO_NUMCOL) == NULL)
						? number_width(wp) + 1 : 0);

    
    
    
    
    
    if (prev_line != line || prev_ts != wp->w_buffer->b_p_ts || prev_tick != CHANGEDTICK(wp->w_buffer)
	    || prev_listopt != wp->w_briopt_list || (prev_flp == NULL || (STRCMP(prev_flp, get_flp_value(wp->w_buffer)) != 0))


	    || prev_vts != wp->w_buffer->b_p_vts_array  )

    {
	prev_line = line;
	prev_ts = wp->w_buffer->b_p_ts;
	prev_tick = CHANGEDTICK(wp->w_buffer);

	prev_vts = wp->w_buffer->b_p_vts_array;
	prev_indent = get_indent_str_vtab(line, (int)wp->w_buffer->b_p_ts, wp->w_buffer->b_p_vts_array, wp->w_p_list);


	prev_indent = get_indent_str(line, (int)wp->w_buffer->b_p_ts, wp->w_p_list);

	prev_listopt = wp->w_briopt_list;
	prev_list = 0;
	vim_free(prev_flp);
	prev_flp = vim_strsave(get_flp_value(wp->w_buffer));
	
	if (wp->w_briopt_list != 0)
	{
	    regmatch_T	    regmatch;

	    regmatch.regprog = vim_regcomp(prev_flp, RE_MAGIC + RE_STRING + RE_AUTO + RE_STRICT);

	    if (regmatch.regprog != NULL)
	    {
		regmatch.rm_ic = FALSE;
		if (vim_regexec(&regmatch, line, 0))
		{
		    if (wp->w_briopt_list > 0)
			prev_list = wp->w_briopt_list;
		    else prev_list = (*regmatch.endp - *regmatch.startp);
		}
		vim_regfree(regmatch.regprog);
	    }
	}
    }
    bri = prev_indent + wp->w_briopt_shift;

    
    bri += win_col_off2(wp);

    
    if (wp->w_briopt_list != 0)
    {
	if (wp->w_briopt_list > 0)
	    bri += prev_list;
	else bri = prev_list;
    }

    
    if (wp->w_briopt_sbr)
	bri -= vim_strsize(get_showbreak_value(wp));


    
    if (bri < 0)
	bri = 0;

    
    
    else if (bri > eff_wwidth - wp->w_briopt_min)
	bri = (eff_wwidth - wp->w_briopt_min < 0)
					   ? 0 : eff_wwidth - wp->w_briopt_min;

    return bri;
}



    int inindent(int extra)
{
    char_u	*ptr;
    colnr_T	col;

    for (col = 0, ptr = ml_get_curline(); VIM_ISWHITE(*ptr); ++col)
	++ptr;
    if (col >= curwin->w_cursor.col + extra)
	return TRUE;
    else return FALSE;
}



    void op_reindent(oparg_T *oap, int (*how)(void))
{
    long	i;
    char_u	*l;
    int		amount;
    linenr_T	first_changed = 0;
    linenr_T	last_changed = 0;
    linenr_T	start_lnum = curwin->w_cursor.lnum;

    
    if (!curbuf->b_p_ma)
    {
	emsg(_(e_cannot_make_changes_modifiable_is_off));
	return;
    }

    for (i = oap->line_count; --i >= 0 && !got_int; )
    {
	
	

	if (i > 1 && (i % 50 == 0 || i == oap->line_count - 1)
		&& oap->line_count > p_report)
	    smsg(_("%ld lines to indent... "), i);

	
	

	if (i != oap->line_count - 1 || oap->line_count == 1 || how != get_lisp_indent)

	{
	    l = skipwhite(ml_get_curline());
	    if (*l == NUL)		    
		amount = 0;
	    else amount = how();

	    if (amount >= 0 && set_indent(amount, SIN_UNDO))
	    {
		
		if (first_changed == 0)
		    first_changed = curwin->w_cursor.lnum;
		last_changed = curwin->w_cursor.lnum;
	    }
	}
	++curwin->w_cursor.lnum;
	curwin->w_cursor.col = 0;  
    }

    
    curwin->w_cursor.lnum = start_lnum;
    beginline(BL_SOL | BL_FIX);

    
    
    
    if (last_changed != 0)
	changed_lines(first_changed, 0, oap->is_VIsual ? start_lnum + oap->line_count :
		last_changed + 1, 0L);
    else if (oap->is_VIsual)
	redraw_curbuf_later(INVERTED);

    if (oap->line_count > p_report)
    {
	i = oap->line_count - (i + 1);
	smsg(NGETTEXT("%ld line indented ", "%ld lines indented ", i), i);
    }
    if ((cmdmod.cmod_flags & CMOD_LOCKMARKS) == 0)
    {
	
	curbuf->b_op_start = oap->start;
	curbuf->b_op_end = oap->end;
    }
}




    int preprocs_left(void)
{
    return   (curbuf->b_p_si && !curbuf->b_p_cin) ||  curbuf->b_p_si    (curbuf->b_p_cin && in_cinkeys('#', ' ', TRUE)








					   && curbuf->b_ind_hash_comment == 0)

	;
}




    void ins_try_si(int c)
{
    pos_T	*pos, old_pos;
    char_u	*ptr;
    int		i;
    int		temp;

    
    if (((did_si || can_si_back) && c == '{') || (can_si && c == '}'))
    {
	
	if (c == '}' && (pos = findmatch(NULL, '{')) != NULL)
	{
	    old_pos = curwin->w_cursor;
	    
	    
	    
	    
	    
	    ptr = ml_get(pos->lnum);
	    i = pos->col;
	    if (i > 0)		
		while (--i > 0 && VIM_ISWHITE(ptr[i]))
		    ;
	    curwin->w_cursor.lnum = pos->lnum;
	    curwin->w_cursor.col = i;
	    if (ptr[i] == ')' && (pos = findmatch(NULL, '(')) != NULL)
		curwin->w_cursor = *pos;
	    i = get_indent();
	    curwin->w_cursor = old_pos;
	    if (State & VREPLACE_FLAG)
		change_indent(INDENT_SET, i, FALSE, NUL, TRUE);
	    else (void)set_indent(i, SIN_CHANGED);
	}
	else if (curwin->w_cursor.col > 0)
	{
	    
	    
	    temp = TRUE;
	    if (c == '{' && can_si_back && curwin->w_cursor.lnum > 1)
	    {
		old_pos = curwin->w_cursor;
		i = get_indent();
		while (curwin->w_cursor.lnum > 1)
		{
		    ptr = skipwhite(ml_get(--(curwin->w_cursor.lnum)));

		    
		    if (*ptr != '#' && *ptr != NUL)
			break;
		}
		if (get_indent() >= i)
		    temp = FALSE;
		curwin->w_cursor = old_pos;
	    }
	    if (temp)
		shift_line(TRUE, FALSE, 1, TRUE);
	}
    }

    
    if (curwin->w_cursor.col > 0 && can_si && c == '#')
    {
	
	old_indent = get_indent();
	(void)set_indent(0, SIN_CHANGED);
    }

    
    if (ai_col > curwin->w_cursor.col)
	ai_col = curwin->w_cursor.col;
}



    void change_indent( int		type, int		amount, int		round, int		replaced, int		call_changed_bytes)





{
    int		vcol;
    int		last_vcol;
    int		insstart_less;		
    int		new_cursor_col;
    int		i;
    char_u	*ptr;
    int		save_p_list;
    int		start_col;
    colnr_T	vc;
    colnr_T	orig_col = 0;		
    char_u	*new_line, *orig_line = NULL;	

    
    if (State & VREPLACE_FLAG)
    {
	orig_line = vim_strsave(ml_get_curline());  
	orig_col = curwin->w_cursor.col;
    }

    
    save_p_list = curwin->w_p_list;
    curwin->w_p_list = FALSE;
    vc = getvcol_nolist(&curwin->w_cursor);
    vcol = vc;

    
    
    
    start_col = curwin->w_cursor.col;

    
    new_cursor_col = curwin->w_cursor.col;
    beginline(BL_WHITE);
    new_cursor_col -= curwin->w_cursor.col;

    insstart_less = curwin->w_cursor.col;

    
    
    if (new_cursor_col < 0)
	vcol = get_indent() - vcol;

    if (new_cursor_col > 0)	    
	start_col = -1;

    
    if (type == INDENT_SET)
	(void)set_indent(amount, call_changed_bytes ? SIN_CHANGED : 0);
    else {
	int	save_State = State;

	
	if (State & VREPLACE_FLAG)
	    State = INSERT;
	shift_line(type == INDENT_DEC, round, 1, call_changed_bytes);
	State = save_State;
    }
    insstart_less -= curwin->w_cursor.col;

    
    
    
    
    
    
    
    if (new_cursor_col >= 0)
    {
	
	
	if (new_cursor_col == 0)
	    insstart_less = MAXCOL;
	new_cursor_col += curwin->w_cursor.col;
    }
    else if (!(State & INSERT))
	new_cursor_col = curwin->w_cursor.col;
    else {
	
	vcol = get_indent() - vcol;
	curwin->w_virtcol = (colnr_T)((vcol < 0) ? 0 : vcol);

	
	vcol = last_vcol = 0;
	new_cursor_col = -1;
	ptr = ml_get_curline();
	while (vcol <= (int)curwin->w_virtcol)
	{
	    last_vcol = vcol;
	    if (has_mbyte && new_cursor_col >= 0)
		new_cursor_col += (*mb_ptr2len)(ptr + new_cursor_col);
	    else ++new_cursor_col;
	    vcol += lbr_chartabsize(ptr, ptr + new_cursor_col, (colnr_T)vcol);
	}
	vcol = last_vcol;

	
	
	if (vcol != (int)curwin->w_virtcol)
	{
	    curwin->w_cursor.col = (colnr_T)new_cursor_col;
	    i = (int)curwin->w_virtcol - vcol;
	    ptr = alloc(i + 1);
	    if (ptr != NULL)
	    {
		new_cursor_col += i;
		ptr[i] = NUL;
		while (--i >= 0)
		    ptr[i] = ' ';
		ins_str(ptr);
		vim_free(ptr);
	    }
	}

	
	
	insstart_less = MAXCOL;
    }

    curwin->w_p_list = save_p_list;

    if (new_cursor_col <= 0)
	curwin->w_cursor.col = 0;
    else curwin->w_cursor.col = (colnr_T)new_cursor_col;
    curwin->w_set_curswant = TRUE;
    changed_cline_bef_curs();

    
    if (State & INSERT)
    {
	if (curwin->w_cursor.lnum == Insstart.lnum && Insstart.col != 0)
	{
	    if ((int)Insstart.col <= insstart_less)
		Insstart.col = 0;
	    else Insstart.col -= insstart_less;
	}
	if ((int)ai_col <= insstart_less)
	    ai_col = 0;
	else ai_col -= insstart_less;
    }

    
    
    
    
    
    if (REPLACE_NORMAL(State) && start_col >= 0)
    {
	while (start_col > (int)curwin->w_cursor.col)
	{
	    replace_join(0);	    
	    --start_col;
	}
	while (start_col < (int)curwin->w_cursor.col || replaced)
	{
	    replace_push(NUL);
	    if (replaced)
	    {
		replace_push(replaced);
		replaced = NUL;
	    }
	    ++start_col;
	}
    }

    
    
    
    if (State & VREPLACE_FLAG)
    {
	
	
	if (orig_line == NULL)
	    return;

	
	new_line = vim_strsave(ml_get_curline());
	if (new_line == NULL)
	    return;

	
	new_line[curwin->w_cursor.col] = NUL;

	
	ml_replace(curwin->w_cursor.lnum, orig_line, FALSE);
	curwin->w_cursor.col = orig_col;

	
	backspace_until_column(0);

	
	ins_bytes(new_line);

	vim_free(new_line);
    }
}


    int copy_indent(int size, char_u *src)
{
    char_u	*p = NULL;
    char_u	*line = NULL;
    char_u	*s;
    int		todo;
    int		ind_len;
    int		line_len = 0;
    int		tab_pad;
    int		ind_done;
    int		round;

    int		ind_col;


    
    
    for (round = 1; round <= 2; ++round)
    {
	todo = size;
	ind_len = 0;
	ind_done = 0;

	ind_col = 0;

	s = src;

	
	while (todo > 0 && VIM_ISWHITE(*s))
	{
	    if (*s == TAB)
	    {

		tab_pad = tabstop_padding(ind_done, curbuf->b_p_ts, curbuf->b_p_vts_array);

		tab_pad = (int)curbuf->b_p_ts - (ind_done % (int)curbuf->b_p_ts);

		
		if (todo < tab_pad)
		    break;
		todo -= tab_pad;
		ind_done += tab_pad;

		ind_col += tab_pad;

	    }
	    else {
		--todo;
		++ind_done;

		++ind_col;

	    }
	    ++ind_len;
	    if (p != NULL)
		*p++ = *s;
	    ++s;
	}

	

	tab_pad = tabstop_padding(ind_done, curbuf->b_p_ts, curbuf->b_p_vts_array);

	tab_pad = (int)curbuf->b_p_ts - (ind_done % (int)curbuf->b_p_ts);

	if (todo >= tab_pad && !curbuf->b_p_et)
	{
	    todo -= tab_pad;
	    ++ind_len;

	    ind_col += tab_pad;

	    if (p != NULL)
		*p++ = TAB;
	}

	
	if (!curbuf->b_p_et)
	{

	    for (;;)
	    {
		tab_pad = tabstop_padding(ind_col, curbuf->b_p_ts, curbuf->b_p_vts_array);
		if (todo < tab_pad)
		    break;
		todo -= tab_pad;
		++ind_len;
		ind_col += tab_pad;
		if (p != NULL)
		    *p++ = TAB;
	    }

	    while (todo >= (int)curbuf->b_p_ts)
	    {
		todo -= (int)curbuf->b_p_ts;
		++ind_len;
		if (p != NULL)
		    *p++ = TAB;
	    }

	}

	
	while (todo > 0)
	{
	    --todo;
	    ++ind_len;
	    if (p != NULL)
		*p++ = ' ';
	}

	if (p == NULL)
	{
	    
	    
	    line_len = (int)STRLEN(ml_get_curline()) + 1;
	    line = alloc(ind_len + line_len);
	    if (line == NULL)
		return FALSE;
	    p = line;
	}
    }

    
    mch_memmove(p, ml_get_curline(), (size_t)line_len);

    
    ml_replace(curwin->w_cursor.lnum, line, FALSE);

    
    curwin->w_cursor.col = ind_len;
    return TRUE;
}


    void ex_retab(exarg_T *eap)
{
    linenr_T	lnum;
    int		got_tab = FALSE;
    long	num_spaces = 0;
    long	num_tabs;
    long	len;
    long	col;
    long	vcol;
    long	start_col = 0;		
    long	start_vcol = 0;		
    long	old_len;
    char_u	*ptr;
    char_u	*new_line = (char_u *)1; 
    int		did_undo;		

    int		*new_vts_array = NULL;
    char_u	*new_ts_str;		

    int		temp;
    int		new_ts;

    int		save_list;
    linenr_T	first_line = 0;		
    linenr_T	last_line = 0;		

    save_list = curwin->w_p_list;
    curwin->w_p_list = 0;	    


    new_ts_str = eap->arg;
    if (tabstop_set(eap->arg, &new_vts_array) == FAIL)
	return;
    while (vim_isdigit(*(eap->arg)) || *(eap->arg) == ',')
	++(eap->arg);

    
    
    
    if (new_vts_array == NULL)
    {
	new_vts_array = curbuf->b_p_vts_array;
	new_ts_str = NULL;
    }
    else new_ts_str = vim_strnsave(new_ts_str, eap->arg - new_ts_str);

    ptr = eap->arg;
    new_ts = getdigits(&ptr);
    if (new_ts < 0 && *eap->arg == '-')
    {
	emsg(_(e_argument_must_be_positive));
	return;
    }
    if (new_ts < 0 || new_ts > 9999)
    {
	semsg(_(e_invalid_argument_str), eap->arg);
	return;
    }
    if (new_ts == 0)
	new_ts = curbuf->b_p_ts;

    for (lnum = eap->line1; !got_int && lnum <= eap->line2; ++lnum)
    {
	ptr = ml_get(lnum);
	col = 0;
	vcol = 0;
	did_undo = FALSE;
	for (;;)
	{
	    if (VIM_ISWHITE(ptr[col]))
	    {
		if (!got_tab && num_spaces == 0)
		{
		    
		    start_vcol = vcol;
		    start_col = col;
		}
		if (ptr[col] == ' ')
		    num_spaces++;
		else got_tab = TRUE;
	    }
	    else {
		if (got_tab || (eap->forceit && num_spaces > 1))
		{
		    

		    
		    len = num_spaces = vcol - start_vcol;
		    num_tabs = 0;
		    if (!curbuf->b_p_et)
		    {

			int t, s;

			tabstop_fromto(start_vcol, vcol, curbuf->b_p_ts, new_vts_array, &t, &s);
			num_tabs = t;
			num_spaces = s;

			temp = new_ts - (start_vcol % new_ts);
			if (num_spaces >= temp)
			{
			    num_spaces -= temp;
			    num_tabs++;
			}
			num_tabs += num_spaces / new_ts;
			num_spaces -= (num_spaces / new_ts) * new_ts;

		    }
		    if (curbuf->b_p_et || got_tab || (num_spaces + num_tabs < len))
		    {
			if (did_undo == FALSE)
			{
			    did_undo = TRUE;
			    if (u_save((linenr_T)(lnum - 1), (linenr_T)(lnum + 1)) == FAIL)
			    {
				new_line = NULL;	
				break;
			    }
			}

			
			len = num_spaces + num_tabs;
			old_len = (long)STRLEN(ptr);
			new_line = alloc(old_len - col + start_col + len + 1);
			if (new_line == NULL)
			    break;
			if (start_col > 0)
			    mch_memmove(new_line, ptr, (size_t)start_col);
			mch_memmove(new_line + start_col + len, ptr + col, (size_t)(old_len - col + 1));
			ptr = new_line + start_col;
			for (col = 0; col < len; col++)
			    ptr[col] = (col < num_tabs) ? '\t' : ' ';
			if (ml_replace(lnum, new_line, FALSE) == OK)
			    
			    new_line = curbuf->b_ml.ml_line_ptr;
			if (first_line == 0)
			    first_line = lnum;
			last_line = lnum;
			ptr = new_line;
			col = start_col + len;
		    }
		}
		got_tab = FALSE;
		num_spaces = 0;
	    }
	    if (ptr[col] == NUL)
		break;
	    vcol += chartabsize(ptr + col, (colnr_T)vcol);
	    if (has_mbyte)
		col += (*mb_ptr2len)(ptr + col);
	    else ++col;
	}
	if (new_line == NULL)		    
	    break;
	line_breakcheck();
    }
    if (got_int)
	emsg(_(e_interrupted));


    
    
    if (tabstop_count(curbuf->b_p_vts_array) == 0 && tabstop_count(new_vts_array) == 1 && curbuf->b_p_ts == tabstop_first(new_vts_array))

	; 
    else if (tabstop_count(curbuf->b_p_vts_array) > 0 && tabstop_eq(curbuf->b_p_vts_array, new_vts_array))
	; 
    else redraw_curbuf_later(NOT_VALID);

    if (curbuf->b_p_ts != new_ts)
	redraw_curbuf_later(NOT_VALID);

    if (first_line != 0)
	changed_lines(first_line, 0, last_line + 1, 0L);

    curwin->w_p_list = save_list;	


    if (new_ts_str != NULL)		
    {
	
	
	int *old_vts_ary = curbuf->b_p_vts_array;

	if (tabstop_count(old_vts_ary) > 0 || tabstop_count(new_vts_array) > 1)
	{
	    set_string_option_direct((char_u *)"vts", -1, new_ts_str, OPT_FREE|OPT_LOCAL, 0);
	    curbuf->b_p_vts_array = new_vts_array;
	    vim_free(old_vts_ary);
	}
	else {
	    
	    
	    curbuf->b_p_ts = tabstop_first(new_vts_array);
	    vim_free(new_vts_array);
	}
	vim_free(new_ts_str);
    }

    curbuf->b_p_ts = new_ts;

    coladvance(curwin->w_curswant);

    u_clearline();
}



    int get_expr_indent(void)
{
    int		indent = -1;
    char_u	*inde_copy;
    pos_T	save_pos;
    colnr_T	save_curswant;
    int		save_set_curswant;
    int		save_State;
    int		use_sandbox = was_set_insecurely((char_u *)"indentexpr", OPT_LOCAL);
    sctx_T	save_sctx = current_sctx;

    
    
    save_pos = curwin->w_cursor;
    save_curswant = curwin->w_curswant;
    save_set_curswant = curwin->w_set_curswant;
    set_vim_var_nr(VV_LNUM, curwin->w_cursor.lnum);
    if (use_sandbox)
	++sandbox;
    ++textwinlock;
    current_sctx = curbuf->b_p_script_ctx[BV_INDE];

    
    
    inde_copy = vim_strsave(curbuf->b_p_inde);
    if (inde_copy != NULL)
    {
	indent = (int)eval_to_number(inde_copy);
	vim_free(inde_copy);
    }

    if (use_sandbox)
	--sandbox;
    --textwinlock;
    current_sctx = save_sctx;

    
    
    
    save_State = State;
    State = INSERT;
    curwin->w_cursor = save_pos;
    curwin->w_curswant = save_curswant;
    curwin->w_set_curswant = save_set_curswant;
    check_cursor();
    State = save_State;

    
    if (did_throw && (vim_strchr(p_debug, 't') == NULL || trylevel == 0))
    {
	handle_did_throw();
	did_throw = FALSE;
    }

    
    if (indent < 0)
	indent = get_indent();

    return indent;
}




    static int lisp_match(char_u *p)
{
    char_u	buf[LSIZE];
    int		len;
    char_u	*word = *curbuf->b_p_lw != NUL ? curbuf->b_p_lw : p_lispwords;

    while (*word != NUL)
    {
	(void)copy_option_part(&word, buf, LSIZE, ",");
	len = (int)STRLEN(buf);
	if (STRNCMP(buf, p, len) == 0 && p[len] == ' ')
	    return TRUE;
    }
    return FALSE;
}


    int get_lisp_indent(void)
{
    pos_T	*pos, realpos, paren;
    int		amount;
    char_u	*that;
    colnr_T	col;
    colnr_T	firsttry;
    int		parencount, quotecount;
    int		vi_lisp;

    
    vi_lisp = (vim_strchr(p_cpo, CPO_LISP) != NULL);

    realpos = curwin->w_cursor;
    curwin->w_cursor.col = 0;

    if ((pos = findmatch(NULL, '(')) == NULL)
	pos = findmatch(NULL, '[');
    else {
	paren = *pos;
	pos = findmatch(NULL, '[');
	if (pos == NULL || LT_POSP(pos, &paren))
	    pos = &paren;
    }
    if (pos != NULL)
    {
	
	
	amount = -1;
	parencount = 0;

	while (--curwin->w_cursor.lnum >= pos->lnum)
	{
	    if (linewhite(curwin->w_cursor.lnum))
		continue;
	    for (that = ml_get_curline(); *that != NUL; ++that)
	    {
		if (*that == ';')
		{
		    while (*(that + 1) != NUL)
			++that;
		    continue;
		}
		if (*that == '\\')
		{
		    if (*(that + 1) != NUL)
			++that;
		    continue;
		}
		if (*that == '"' && *(that + 1) != NUL)
		{
		    while (*++that && *that != '"')
		    {
			
			if (*that == '\\')
			{
			    if (*++that == NUL)
				break;
			    if (that[1] == NUL)
			    {
				++that;
				break;
			    }
			}
		    }
		}
		if (*that == '(' || *that == '[')
		    ++parencount;
		else if (*that == ')' || *that == ']')
		    --parencount;
	    }
	    if (parencount == 0)
	    {
		amount = get_indent();
		break;
	    }
	}

	if (amount == -1)
	{
	    curwin->w_cursor.lnum = pos->lnum;
	    curwin->w_cursor.col = pos->col;
	    col = pos->col;

	    that = ml_get_curline();

	    if (vi_lisp && get_indent() == 0)
		amount = 2;
	    else {
		char_u *line = that;

		amount = 0;
		while (*that && col)
		{
		    amount += lbr_chartabsize_adv(line, &that, (colnr_T)amount);
		    col--;
		}

		
		
		
		
		

		if (!vi_lisp && (*that == '(' || *that == '[')
						      && lisp_match(that + 1))
		    amount += 2;
		else {
		    that++;
		    amount++;
		    firsttry = amount;

		    while (VIM_ISWHITE(*that))
		    {
			amount += lbr_chartabsize(line, that, (colnr_T)amount);
			++that;
		    }

		    if (*that && *that != ';') 
		    {
			
			
			if (!vi_lisp && *that != '(' && *that != '[')
			    firsttry++;

			parencount = 0;
			quotecount = 0;

			if (vi_lisp || (*that != '"' && *that != '\'' && *that != '#' && (*that < '0' || *that > '9')))



			{
			    while (*that && (!VIM_ISWHITE(*that)
					|| quotecount || parencount)
				    && (!((*that == '(' || *that == '[')
					    && !quotecount && !parencount && vi_lisp)))

			    {
				if (*that == '"')
				    quotecount = !quotecount;
				if ((*that == '(' || *that == '[')
							       && !quotecount)
				    ++parencount;
				if ((*that == ')' || *that == ']')
							       && !quotecount)
				    --parencount;
				if (*that == '\\' && *(that+1) != NUL)
				    amount += lbr_chartabsize_adv( line, &that, (colnr_T)amount);
				amount += lbr_chartabsize_adv( line, &that, (colnr_T)amount);
			    }
			}
			while (VIM_ISWHITE(*that))
			{
			    amount += lbr_chartabsize( line, that, (colnr_T)amount);
			    that++;
			}
			if (!*that || *that == ';')
			    amount = firsttry;
		    }
		}
	    }
	}
    }
    else amount = 0;

    curwin->w_cursor = realpos;

    return amount;
}





    void fixthisline(int (*get_the_indent)(void))
{
    int amount = get_the_indent();

    if (amount >= 0)
    {
	change_indent(INDENT_SET, amount, FALSE, 0, TRUE);
	if (linewhite(curwin->w_cursor.lnum))
	    did_ai = TRUE;	
    }
}


    void fix_indent(void)
{
    if (p_paste)
	return;

    if (curbuf->b_p_lisp && curbuf->b_p_ai)
	fixthisline(get_lisp_indent);


    else   if (cindent_on())


	    do_c_expr_indent();

}




    void f_indent(typval_T *argvars, typval_T *rettv)
{
    linenr_T	lnum;

    if (in_vim9script() && check_for_lnum_arg(argvars, 0) == FAIL)
	return;

    lnum = tv_get_lnum(argvars);
    if (lnum >= 1 && lnum <= curbuf->b_ml.ml_line_count)
	rettv->vval.v_number = get_indent_lnum(lnum);
    else {
	if (in_vim9script())
	    semsg(_(e_invalid_line_number_nr), lnum);
	rettv->vval.v_number = -1;
    }
}


    void f_lispindent(typval_T *argvars UNUSED, typval_T *rettv)
{

    pos_T	pos;
    linenr_T	lnum;

    if (in_vim9script() && check_for_lnum_arg(argvars, 0) == FAIL)
	return;

    pos = curwin->w_cursor;
    lnum = tv_get_lnum(argvars);
    if (lnum >= 1 && lnum <= curbuf->b_ml.ml_line_count)
    {
	curwin->w_cursor.lnum = lnum;
	rettv->vval.v_number = get_lisp_indent();
	curwin->w_cursor = pos;
    }
    else if (in_vim9script())
	semsg(_(e_invalid_line_number_nr), lnum);
    else  rettv->vval.v_number = -1;

}

