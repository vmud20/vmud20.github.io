












static int	compl_busy = FALSE;


static void ins_ctrl_v(void);
static void insert_special(int, int, int);
static void redo_literal(int c);
static void start_arrow_common(pos_T *end_insert_pos, int change);

static void check_spell_redraw(void);

static void stop_insert(pos_T *end_insert_pos, int esc, int nomove);
static int  echeck_abbr(int);
static void mb_replace_pop_ins(int cc);
static void replace_flush(void);
static void replace_do_bs(int limit_col);
static int del_char_after_col(int limit_col);
static void ins_reg(void);
static void ins_ctrl_g(void);
static void ins_ctrl_hat(void);
static int  ins_esc(long *count, int cmdchar, int nomove);

static void ins_ctrl_(void);

static int ins_start_select(int c);
static void ins_insert(int replaceState);
static void ins_ctrl_o(void);
static void ins_shift(int c, int lastc);
static void ins_del(void);
static int  ins_bs(int c, int mode, int *inserted_space_p);

static void ins_tabline(int c);

static void ins_left(void);
static void ins_home(int c);
static void ins_end(int c);
static void ins_s_left(void);
static void ins_right(void);
static void ins_s_right(void);
static void ins_up(int startcol);
static void ins_pageup(void);
static void ins_down(int startcol);
static void ins_pagedown(void);

static void ins_drop(void);

static int  ins_tab(void);

static int  ins_digraph(void);

static int  ins_ctrl_ey(int tc);

static char_u *do_insert_char_pre(int c);


static colnr_T	Insstart_textlen;	
static colnr_T	Insstart_blank_vcol;	
static int	update_Insstart_orig = TRUE; 

static char_u	*last_insert = NULL;	
					
static int	last_insert_skip; 
static int	new_insert_skip;  
static int	did_restart_edit;	


static int	can_cindent;		



static int	revins_on;		
static int	revins_chars;		
static int	revins_legal;		
static int	revins_scol;		


static int	ins_need_undo;		
					
					

static int	dont_sync_undo = FALSE;	
					


    int edit( int		cmdchar, int		startln, long	count)



{
    int		c = 0;
    char_u	*ptr;
    int		lastc = 0;
    int		mincol;
    static linenr_T o_lnum = 0;
    int		i;
    int		did_backspace = TRUE;	    

    int		line_is_white = FALSE;	    

    linenr_T	old_topline = 0;	    

    int		old_topfill = -1;

    int		inserted_space = FALSE;     
    int		replaceState = MODE_REPLACE;
    int		nomove = FALSE;		    

    int		cmdchar_todo = cmdchar;


    int		cursor_line_was_concealed;


    
    did_restart_edit = restart_edit;

    
    
    check_for_delay(TRUE);

    
    update_Insstart_orig = TRUE;


    
    if (sandbox != 0)
    {
	emsg(_(e_not_allowed_in_sandbox));
	return FALSE;
    }

    
    
    
    if (textwinlock != 0 || textlock != 0 || ins_compl_active() || compl_busy || pum_visible())
    {
	emsg(_(e_not_allowed_to_change_text_or_change_window));
	return FALSE;
    }
    ins_compl_clear();	    

    
    if (cmdchar != 'r' && cmdchar != 'v')
    {
	pos_T   save_cursor = curwin->w_cursor;


	if (cmdchar == 'R')
	    ptr = (char_u *)"r";
	else if (cmdchar == 'V')
	    ptr = (char_u *)"v";
	else ptr = (char_u *)"i";
	set_vim_var_string(VV_INSERTMODE, ptr, 1);
	set_vim_var_string(VV_CHAR, NULL, -1);  

	ins_apply_autocmds(EVENT_INSERTENTER);

	
	if (need_highlight_changed)
	    highlight_changed();

	
	
	
	
	
	
	if (!EQUAL_POS(curwin->w_cursor, save_cursor)

		&& *get_vim_var_str(VV_CHAR) == NUL  && save_cursor.lnum <= curbuf->b_ml.ml_line_count)

	{
	    int save_state = State;

	    curwin->w_cursor = save_cursor;
	    State = MODE_INSERT;
	    check_cursor_col();
	    State = save_state;
	}
    }


    
    cursor_line_was_concealed = curwin->w_p_cole > 0 && conceal_cursor_line(curwin);


    
    if (where_paste_started.lnum != 0)
	Insstart = where_paste_started;
    else {
	Insstart = curwin->w_cursor;
	if (startln)
	    Insstart.col = 0;
    }
    Insstart_textlen = (colnr_T)linetabsize(ml_get_curline());
    Insstart_blank_vcol = MAXCOL;
    if (!did_ai)
	ai_col = 0;

    if (cmdchar != NUL && restart_edit == 0)
    {
	ResetRedobuff();
	AppendNumberToRedobuff(count);
	if (cmdchar == 'V' || cmdchar == 'v')
	{
	    
	    AppendCharToRedobuff('g');
	    AppendCharToRedobuff((cmdchar == 'v') ? 'r' : 'R');
	}
	else {
	    if (cmdchar == K_PS)
		AppendCharToRedobuff('a');
	    else AppendCharToRedobuff(cmdchar);
	    if (cmdchar == 'g')		    
		AppendCharToRedobuff('I');
	    else if (cmdchar == 'r')	    
		count = 1;		    
	}
    }

    if (cmdchar == 'R')
    {
	State = MODE_REPLACE;
    }
    else if (cmdchar == 'V' || cmdchar == 'v')
    {
	State = MODE_VREPLACE;
	replaceState = MODE_VREPLACE;
	orig_line_count = curbuf->b_ml.ml_line_count;
	vr_lines_changed = 1;
    }
    else State = MODE_INSERT;

    may_trigger_modechanged();
    stop_insert_mode = FALSE;


    
    
    conceal_check_cursor_line(cursor_line_was_concealed);


    
    if (gchar_cursor() == TAB)
	curwin->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_VIRTCOL);

    
    if (curbuf->b_p_iminsert == B_IMODE_LMAP)
	State |= MODE_LANGMAP;

    im_set_active(curbuf->b_p_iminsert == B_IMODE_IM);


    setmouse();

    clear_showcmd();


    
    revins_on = (State == MODE_INSERT && p_ri);
    if (revins_on)
	undisplay_dollar();
    revins_chars = 0;
    revins_legal = 0;
    revins_scol = -1;

    if (!p_ek)
    {

	ch_log_output = TRUE;

	
	
	out_str(T_BD);

	
	
	out_str(T_CTE);
    }

    
    if (restart_edit != 0 && stuff_empty())
    {
	
	if (where_paste_started.lnum)
	    arrow_used = FALSE;
	else arrow_used = TRUE;
	restart_edit = 0;

	
	validate_virtcol();
	update_curswant();
	if (((ins_at_eol && curwin->w_cursor.lnum == o_lnum)
		    || curwin->w_curswant > curwin->w_virtcol)
		&& *(ptr = ml_get_curline() + curwin->w_cursor.col) != NUL)
	{
	    if (ptr[1] == NUL)
		++curwin->w_cursor.col;
	    else if (has_mbyte)
	    {
		i = (*mb_ptr2len)(ptr);
		if (ptr[i] == NUL)
		    curwin->w_cursor.col += i;
	    }
	}
	ins_at_eol = FALSE;
    }
    else arrow_used = FALSE;

    
    need_start_insertmode = FALSE;

    
    ins_need_undo = TRUE;

    where_paste_started.lnum = 0;

    can_cindent = TRUE;


    
    
    if (!p_im && did_restart_edit == 0)
	foldOpenCursor();


    
    i = 0;
    if (p_smd && msg_silent == 0)
	i = showmode();

    if (!p_im && did_restart_edit == 0)
	change_warning(i == 0 ? 0 : i + 1);


    ui_cursor_shape();		


    do_digraph(-1);		


    
    ptr = get_inserted();
    if (ptr == NULL)
	new_insert_skip = 0;
    else {
	new_insert_skip = (int)STRLEN(ptr);
	vim_free(ptr);
    }

    old_indent = 0;

    
    for (;;)
    {

	if (!revins_legal)
	    revins_scol = -1;	    
	else revins_legal = 0;

	if (arrow_used)	    
	    count = 0;

	if (update_Insstart_orig)
	    Insstart_orig = Insstart;

	if (stop_insert_mode && !ins_compl_active())
	{
	    
	    count = 0;
	    goto doESCkey;
	}

	
	if (!arrow_used)
	    curwin->w_set_curswant = TRUE;

	
	
	if (stuff_empty())
	{
	    did_check_timestamps = FALSE;
	    if (need_check_timestamps)
		check_timestamps(FALSE);
	}

	
	msg_scroll = FALSE;


	
	
	
	if (need_mouse_correct)
	    gui_mouse_correct();



	
	if (fdo_flags & FDO_INSERT)
	    foldOpenCursor();
	
	if (!char_avail())
	    foldCheckClose();



	if (bt_prompt(curbuf))
	{
	    init_prompt(cmdchar_todo);
	    cmdchar_todo = NUL;
	}


	
	if (curbuf->b_mod_set && curwin->w_p_wrap && !did_backspace && curwin->w_topline == old_topline  && curwin->w_topfill == old_topfill  )






	{
	    mincol = curwin->w_wcol;
	    validate_cursor_col();

	    if (  curwin->w_wcol < mincol - tabstop_at( get_nolist_virtcol(), curbuf->b_p_ts, curbuf->b_p_vts_array)




		(int)curwin->w_wcol < mincol - curbuf->b_p_ts  && curwin->w_wrow == W_WINROW(curwin)

				 + curwin->w_height - 1 - get_scrolloff_value()
		    && (curwin->w_cursor.lnum != curwin->w_topline  || curwin->w_topfill > 0  ))



	    {

		if (curwin->w_topfill > 0)
		    --curwin->w_topfill;
		else   if (hasFolding(curwin->w_topline, NULL, &old_topline))


		    set_topline(curwin, old_topline + 1);
		else  set_topline(curwin, curwin->w_topline + 1);

	    }
	}

	
	update_topline();

	did_backspace = FALSE;

	validate_cursor();		

	
	ins_redraw(TRUE);

	if (curwin->w_p_scb)
	    do_check_scrollbind(TRUE);

	if (curwin->w_p_crb)
	    do_check_cursorbind();
	update_curswant();
	old_topline = curwin->w_topline;

	old_topfill = curwin->w_topfill;



	dont_scroll = FALSE;		


	
	if (c != K_CURSORHOLD)
	    lastc = c;		

	
	if (dont_sync_undo == MAYBE)
	    dont_sync_undo = TRUE;
	else dont_sync_undo = FALSE;
	if (cmdchar == K_PS)
	    
	    c = K_PS;
	else do {

		c = safe_vgetc();

		if (stop_insert_mode  || (c == K_IGNORE && term_use_loop())


		   )
		{
		    
		    
		    if (c != K_IGNORE && c != K_NOP)
			vungetc(c);
		    count = 0;
		    nomove = TRUE;
		    ins_compl_prep(ESC);
		    goto doESCkey;
		}
	    } while (c == K_IGNORE || c == K_NOP);

	
	did_cursorhold = TRUE;


	if (p_hkmap && KeyTyped)
	    c = hkmap(c);		


	
	
	if (KeyTyped && !KeyStuffed)
	    win_ensure_size();

	
	if (ins_compl_active()
		&& pum_wanted()
		&& curwin->w_cursor.col >= ins_compl_col()
		&& ins_compl_has_shown_match())
	{
	    
	    if ((c == K_BS || c == Ctrl_H)
			&& curwin->w_cursor.col > ins_compl_col()
			&& (c = ins_compl_bs()) == NUL)
		continue;

	    
	    if (!ins_compl_used_match())
	    {
		
		
		
		if (c == Ctrl_L && (!ctrl_x_mode_line_or_eval()
			    || ins_compl_long_shown_match()))
		{
		    ins_compl_addfrommatch();
		    continue;
		}

		
		
		if (ins_compl_accept_char(c))
		{

		    
		    char_u *str = do_insert_char_pre(c);
		    char_u *p;

		    if (str != NULL)
		    {
			for (p = str; *p != NUL; MB_PTR_ADV(p))
			    ins_compl_addleader(PTR2CHAR(p));
			vim_free(str);
		    }
		    else  ins_compl_addleader(c);

		    continue;
		}

		
		
		
		if ((c == Ctrl_Y || (ins_compl_enter_selects()
				    && (c == CAR || c == K_KENTER || c == NL)))
			&& stop_arrow() == OK)
		{
		    ins_compl_delete();
		    ins_compl_insert(FALSE);
		}
	    }
	}

	
	
	ins_compl_init_get_longest();
	if (ins_compl_prep(c))
	    continue;

	
	
	
	if (c == Ctrl_BSL)
	{
	    
	    ins_redraw(FALSE);
	    ++no_mapping;
	    ++allow_keys;
	    c = plain_vgetc();
	    --no_mapping;
	    --allow_keys;
	    if (c != Ctrl_N && c != Ctrl_G && c != Ctrl_O)
	    {
		
		vungetc(c);
		c = Ctrl_BSL;
	    }
	    else if (c == Ctrl_G && p_im)
		continue;
	    else {
		if (c == Ctrl_O)
		{
		    ins_ctrl_o();
		    ins_at_eol = FALSE;	
		    nomove = TRUE;
		}
		count = 0;
		goto doESCkey;
	    }
	}


	c = do_digraph(c);


	if ((c == Ctrl_V || c == Ctrl_Q) && ctrl_x_mode_cmdline())
	    goto docomplete;
	if (c == Ctrl_V || c == Ctrl_Q)
	{
	    ins_ctrl_v();
	    c = Ctrl_V;	
	    continue;
	}


	if (cindent_on() && ctrl_x_mode_none())
	{
	    
	    
	    
	    
	    line_is_white = inindent(0);
	    if (in_cinkeys(c, '!', line_is_white))
		goto force_cindent;
	    if (can_cindent && in_cinkeys(c, '*', line_is_white)
							&& stop_arrow() == OK)
		do_c_expr_indent();
	}



	if (curwin->w_p_rl)
	    switch (c)
	    {
		case K_LEFT:	c = K_RIGHT; break;
		case K_S_LEFT:	c = K_S_RIGHT; break;
		case K_C_LEFT:	c = K_C_RIGHT; break;
		case K_RIGHT:	c = K_LEFT; break;
		case K_S_RIGHT: c = K_S_LEFT; break;
		case K_C_RIGHT: c = K_C_LEFT; break;
	    }


	
	if (ins_start_select(c))
	    continue;

	
	switch (c)
	{
	case ESC:	
	    if (echeck_abbr(ESC + ABBR_OFF))
		break;
	    

	case Ctrl_C:	

	    if (c == Ctrl_C && cmdwin_type != 0)
	    {
		
		cmdwin_result = K_IGNORE;
		got_int = FALSE; 
		nomove = TRUE;
		goto doESCkey;
	    }


	    if (c == Ctrl_C && bt_prompt(curbuf))
	    {
		if (invoke_prompt_interrupt())
		{
		    if (!bt_prompt(curbuf))
			
			
			goto doESCkey;
		    break;
		}
	    }



do_intr:

	    
	    
	    if (goto_im())
	    {
		if (got_int)
		{
		    (void)vgetc();		
		    got_int = FALSE;
		}
		else vim_beep(BO_IM);
		break;
	    }
doESCkey:
	    
	    
	    
	    if (ins_at_eol && gchar_cursor() == NUL)
		o_lnum = curwin->w_cursor.lnum;

	    if (ins_esc(&count, cmdchar, nomove))
	    {
		
		
		
		if (cmdchar != 'r' && cmdchar != 'v' && c != Ctrl_C)
		    ins_apply_autocmds(EVENT_INSERTLEAVE);
		did_cursorhold = FALSE;
		return (c == Ctrl_O);
	    }
	    continue;

	case Ctrl_Z:	
	    if (!p_im)
		goto normalchar;	
	    do_cmdline_cmd((char_u *)"stop");

	    ui_cursor_shape();		

	    continue;

	case Ctrl_O:	

	    if (ctrl_x_mode_omni())
		goto docomplete;

	    if (echeck_abbr(Ctrl_O + ABBR_OFF))
		break;
	    ins_ctrl_o();

	    
	    if (get_ve_flags() & VE_ONEMORE)
	    {
		ins_at_eol = FALSE;
		nomove = TRUE;
	    }
	    count = 0;
	    goto doESCkey;

	case K_INS:	
	case K_KINS:
	    ins_insert(replaceState);
	    break;

	case K_SELECT:	
	    break;

	case K_HELP:	
	case K_F1:
	case K_XF1:
	    stuffcharReadbuff(K_HELP);
	    if (p_im)
		need_start_insertmode = TRUE;
	    goto doESCkey;


	case K_F21:	
	    ++no_mapping;		
	    i = plain_vgetc();
	    --no_mapping;
	    netbeans_keycommand(i);
	    break;


	case K_ZERO:	
	case NUL:
	case Ctrl_A:
	    
	    
	    if (stuff_inserted(NUL, 1L, (c == Ctrl_A)) == FAIL && c != Ctrl_A && !p_im)
		goto doESCkey;		
	    inserted_space = FALSE;
	    break;

	case Ctrl_R:	
	    ins_reg();
	    auto_format(FALSE, TRUE);
	    inserted_space = FALSE;
	    break;

	case Ctrl_G:	
	    ins_ctrl_g();
	    break;

	case Ctrl_HAT:	
	    ins_ctrl_hat();
	    break;


	case Ctrl__:	
	    if (!p_ari)
		goto normalchar;
	    ins_ctrl_();
	    break;


	case Ctrl_D:	

	    if (ctrl_x_mode_path_defines())
		goto docomplete;

	    

	case Ctrl_T:	
	    if (c == Ctrl_T && ctrl_x_mode_thesaurus())
	    {
		if (has_compl_option(FALSE))
		    goto docomplete;
		break;
	    }

	    ins_shift(c, lastc);
	    auto_format(FALSE, TRUE);
	    inserted_space = FALSE;
	    break;

	case K_DEL:	
	case K_KDEL:
	    ins_del();
	    auto_format(FALSE, TRUE);
	    break;

	case K_BS:	
	case K_S_BS:
	case Ctrl_H:
	    did_backspace = ins_bs(c, BACKSPACE_CHAR, &inserted_space);
	    auto_format(FALSE, TRUE);
	    break;

	case Ctrl_W:	

	    if (bt_prompt(curbuf) && (mod_mask & MOD_MASK_SHIFT) == 0)
	    {
		
		
		stuffcharReadbuff(Ctrl_W);
		restart_edit = 'A';
		nomove = TRUE;
		count = 0;
		goto doESCkey;
	    }

	    did_backspace = ins_bs(c, BACKSPACE_WORD, &inserted_space);
	    auto_format(FALSE, TRUE);
	    break;

	case Ctrl_U:	

	    
	    if (ctrl_x_mode_function())
		goto docomplete;

	    did_backspace = ins_bs(c, BACKSPACE_LINE, &inserted_space);
	    auto_format(FALSE, TRUE);
	    inserted_space = FALSE;
	    break;

	case K_LEFTMOUSE:   
	case K_LEFTMOUSE_NM:
	case K_LEFTDRAG:
	case K_LEFTRELEASE:
	case K_LEFTRELEASE_NM:
	case K_MOUSEMOVE:
	case K_MIDDLEMOUSE:
	case K_MIDDLEDRAG:
	case K_MIDDLERELEASE:
	case K_RIGHTMOUSE:
	case K_RIGHTDRAG:
	case K_RIGHTRELEASE:
	case K_X1MOUSE:
	case K_X1DRAG:
	case K_X1RELEASE:
	case K_X2MOUSE:
	case K_X2DRAG:
	case K_X2RELEASE:
	    ins_mouse(c);
	    break;

	case K_MOUSEDOWN: 
	    ins_mousescroll(MSCR_DOWN);
	    break;

	case K_MOUSEUP:	
	    ins_mousescroll(MSCR_UP);
	    break;

	case K_MOUSELEFT: 
	    ins_mousescroll(MSCR_LEFT);
	    break;

	case K_MOUSERIGHT: 
	    ins_mousescroll(MSCR_RIGHT);
	    break;

	case K_PS:
	    bracketed_paste(PASTE_INSERT, FALSE, NULL);
	    if (cmdchar == K_PS)
		
		goto doESCkey;
	    break;
	case K_PE:
	    
	    break;


	case K_TABLINE:
	case K_TABMENU:
	    ins_tabline(c);
	    break;


	case K_IGNORE:	
	    break;

	case K_COMMAND:		    
	case K_SCRIPT_COMMAND:	    
	    do_cmdkey_command(c, 0);

	    if (term_use_loop())
		
		goto doESCkey;

	    break;

	case K_CURSORHOLD:	
	    ins_apply_autocmds(EVENT_CURSORHOLDI);
	    did_cursorhold = TRUE;
	    
	    if (dont_sync_undo == TRUE)
		dont_sync_undo = MAYBE;
	    break;


	    
	    
	case K_F4:
	    if (mod_mask != MOD_MASK_ALT)
		goto normalchar;
	    break;



	case K_VER_SCROLLBAR:
	    ins_scroll();
	    break;

	case K_HOR_SCROLLBAR:
	    ins_horscroll();
	    break;


	case K_HOME:	
	case K_KHOME:
	case K_S_HOME:
	case K_C_HOME:
	    ins_home(c);
	    break;

	case K_END:	
	case K_KEND:
	case K_S_END:
	case K_C_END:
	    ins_end(c);
	    break;

	case K_LEFT:	
	    if (mod_mask & (MOD_MASK_SHIFT|MOD_MASK_CTRL))
		ins_s_left();
	    else ins_left();
	    break;

	case K_S_LEFT:	
	case K_C_LEFT:
	    ins_s_left();
	    break;

	case K_RIGHT:	
	    if (mod_mask & (MOD_MASK_SHIFT|MOD_MASK_CTRL))
		ins_s_right();
	    else ins_right();
	    break;

	case K_S_RIGHT:	
	case K_C_RIGHT:
	    ins_s_right();
	    break;

	case K_UP:	
	    if (pum_visible())
		goto docomplete;
	    if (mod_mask & MOD_MASK_SHIFT)
		ins_pageup();
	    else ins_up(FALSE);
	    break;

	case K_S_UP:	
	case K_PAGEUP:
	case K_KPAGEUP:
	    if (pum_visible())
		goto docomplete;
	    ins_pageup();
	    break;

	case K_DOWN:	
	    if (pum_visible())
		goto docomplete;
	    if (mod_mask & MOD_MASK_SHIFT)
		ins_pagedown();
	    else ins_down(FALSE);
	    break;

	case K_S_DOWN:	
	case K_PAGEDOWN:
	case K_KPAGEDOWN:
	    if (pum_visible())
		goto docomplete;
	    ins_pagedown();
	    break;


	case K_DROP:	
	    ins_drop();
	    break;


	case K_S_TAB:	
	    c = TAB;
	    

	case TAB:	

	    if (ctrl_x_mode_path_patterns())
		goto docomplete;

	    inserted_space = FALSE;
	    if (ins_tab())
		goto normalchar;	
	    auto_format(FALSE, TRUE);
	    break;

	case K_KENTER:	
	    c = CAR;
	    
	case CAR:
	case NL:

	    
	    
	    if (bt_quickfix(curbuf) && c == CAR)
	    {
		if (curwin->w_llist_ref == NULL)    
		    do_cmdline_cmd((char_u *)".cc");
		else				     do_cmdline_cmd((char_u *)".ll");
		break;
	    }


	    if (cmdwin_type != 0)
	    {
		
		cmdwin_result = CAR;
		goto doESCkey;
	    }


	    if (bt_prompt(curbuf))
	    {
		invoke_prompt_callback();
		if (!bt_prompt(curbuf))
		    
		    
		    goto doESCkey;
		break;
	    }

	    if (ins_eol(c) == FAIL && !p_im)
		goto doESCkey;	    
	    auto_format(FALSE, FALSE);
	    inserted_space = FALSE;
	    break;

	case Ctrl_K:	    
	    if (ctrl_x_mode_dictionary())
	    {
		if (has_compl_option(TRUE))
		    goto docomplete;
		break;
	    }

	    c = ins_digraph();
	    if (c == NUL)
		break;

	    goto normalchar;

	case Ctrl_X:	
	    ins_ctrl_x();
	    break;

	case Ctrl_RSB:	
	    if (!ctrl_x_mode_tags())
		goto normalchar;
	    goto docomplete;

	case Ctrl_F:	
	    if (!ctrl_x_mode_files())
		goto normalchar;
	    goto docomplete;

	case 's':	
	case Ctrl_S:
	    if (!ctrl_x_mode_spell())
		goto normalchar;
	    goto docomplete;

	case Ctrl_L:	
	    if (!ctrl_x_mode_whole_line())
	    {
		
		if (p_im)
		{
		    if (echeck_abbr(Ctrl_L + ABBR_OFF))
			break;
		    goto doESCkey;
		}
		goto normalchar;
	    }
	    

	case Ctrl_P:	
	case Ctrl_N:
	    
	    
	    if (*curbuf->b_p_cpt == NUL && (ctrl_x_mode_normal() || ctrl_x_mode_whole_line())
		    && !compl_status_local())
		goto normalchar;

docomplete:
	    compl_busy = TRUE;

	    disable_fold_update++;  

	    if (ins_complete(c, TRUE) == FAIL)
		compl_status_clear();

	    disable_fold_update--;

	    compl_busy = FALSE;

	    can_si = may_do_si(); 

	    break;

	case Ctrl_Y:	
	case Ctrl_E:	
	    c = ins_ctrl_ey(c);
	    break;

	  default:

	    if (c == intr_char)		
		goto do_intr;


normalchar:
	    

	    if (!p_paste)
	    {
		
		char_u *str = do_insert_char_pre(c);
		char_u *p;

		if (str != NULL)
		{
		    if (*str != NUL && stop_arrow() != FAIL)
		    {
			
			for (p = str; *p != NUL; MB_PTR_ADV(p))
			{
			    c = PTR2CHAR(p);
			    if (c == CAR || c == K_KENTER || c == NL)
				ins_eol(c);
			    else ins_char(c);
			}
			AppendToRedobuffLit(str, -1);
		    }
		    vim_free(str);
		    c = NUL;
		}

		
		
		if (c == NUL)
		    break;
	    }


	    
	    ins_try_si(c);


	    if (c == ' ')
	    {
		inserted_space = TRUE;

		if (inindent(0))
		    can_cindent = FALSE;

		if (Insstart_blank_vcol == MAXCOL && curwin->w_cursor.lnum == Insstart.lnum)
		    Insstart_blank_vcol = get_nolist_virtcol();
	    }

	    
	    
	    
	    if (vim_iswordc(c) || (!echeck_abbr(   (has_mbyte && c >= 0x100) ? (c + ABBR_OFF) : c)


			&& c != Ctrl_RSB))
	    {
		insert_special(c, FALSE, FALSE);

		revins_legal++;
		revins_chars++;

	    }

	    auto_format(FALSE, TRUE);


	    
	    
	    foldOpenCursor();

	    break;
	}   

	
	if (c != K_CURSORHOLD   && ctrl_x_mode_normal()



	       )
	    did_cursorhold = FALSE;

	
	if (arrow_used)
	    inserted_space = FALSE;


	if (can_cindent && cindent_on() && ctrl_x_mode_normal())
	{
force_cindent:
	    
	    if (in_cinkeys(c, ' ', line_is_white))
	    {
		if (stop_arrow() == OK)
		    
		    do_c_expr_indent();
	    }
	}


    }	
    
}

    int ins_need_undo_get(void)
{
    return ins_need_undo;
}


    void ins_redraw(int ready)
{

    linenr_T	conceal_old_cursor_line = 0;
    linenr_T	conceal_new_cursor_line = 0;
    int		conceal_update_lines = FALSE;


    if (char_avail())
	return;

    
    
    if (ready && (has_cursormovedI()

		|| popup_visible   || curwin->w_p_cole > 0  )




	    && !EQUAL_POS(last_cursormoved, curwin->w_cursor)
	    && !pum_visible())
    {

	
	
	
	
	if (syntax_present(curwin) && must_redraw)
	    update_screen(0);

	if (has_cursormovedI())
	{
	    
	    
	    update_curswant();
	    ins_apply_autocmds(EVENT_CURSORMOVEDI);
	}

	if (popup_visible)
	    popup_check_cursor_pos();


	if (curwin->w_p_cole > 0)
	{
	    conceal_old_cursor_line = last_cursormoved.lnum;
	    conceal_new_cursor_line = curwin->w_cursor.lnum;
	    conceal_update_lines = TRUE;
	}

	last_cursormoved = curwin->w_cursor;
    }

    
    if (ready && has_textchangedI()
	    && curbuf->b_last_changedtick_i != CHANGEDTICK(curbuf)
	    && !pum_visible())
    {
	aco_save_T	aco;
	varnumber_T	tick = CHANGEDTICK(curbuf);

	
	aucmd_prepbuf(&aco, curbuf);
	apply_autocmds(EVENT_TEXTCHANGEDI, NULL, NULL, FALSE, curbuf);
	aucmd_restbuf(&aco);
	curbuf->b_last_changedtick_i = CHANGEDTICK(curbuf);
	if (tick != CHANGEDTICK(curbuf))  
	    u_save(curwin->w_cursor.lnum, (linenr_T)(curwin->w_cursor.lnum + 1));
    }

    
    
    
    if (ready && has_textchangedP()
	    && curbuf->b_last_changedtick_pum != CHANGEDTICK(curbuf)
	    && pum_visible())
    {
	aco_save_T	aco;
	varnumber_T	tick = CHANGEDTICK(curbuf);

	
	aucmd_prepbuf(&aco, curbuf);
	apply_autocmds(EVENT_TEXTCHANGEDP, NULL, NULL, FALSE, curbuf);
	aucmd_restbuf(&aco);
	curbuf->b_last_changedtick_pum = CHANGEDTICK(curbuf);
	if (tick != CHANGEDTICK(curbuf))  
	    u_save(curwin->w_cursor.lnum, (linenr_T)(curwin->w_cursor.lnum + 1));
    }

    if (ready)
	may_trigger_winscrolled();

    
    may_trigger_safestate(ready && !ins_compl_active()
	    && !pum_visible());


    if ((conceal_update_lines && (conceal_old_cursor_line != conceal_new_cursor_line || conceal_cursor_line(curwin)))

	    || need_cursor_line_redraw)
    {
	if (conceal_old_cursor_line != conceal_new_cursor_line)
	    redrawWinline(curwin, conceal_old_cursor_line);
	redrawWinline(curwin, conceal_new_cursor_line == 0 ? curwin->w_cursor.lnum : conceal_new_cursor_line);
	curwin->w_valid &= ~VALID_CROW;
	need_cursor_line_redraw = FALSE;
    }

    if (must_redraw)
	update_screen(0);
    else if (clear_cmdline || redraw_cmdline)
	showmode();		
    showruler(FALSE);
    setcursor();
    emsg_on_display = FALSE;	
}


    static void ins_ctrl_v(void)
{
    int		c;
    int		did_putchar = FALSE;

    
    ins_redraw(FALSE);

    if (redrawing() && !char_avail())
    {
	edit_putchar('^', TRUE);
	did_putchar = TRUE;
    }
    AppendToRedobuff((char_u *)CTRL_V_STR);	


    add_to_showcmd_c(Ctrl_V);


    
    
    c = get_literal(mod_mask & MOD_MASK_SHIFT);
    if (did_putchar)
	
	
	edit_unputchar();

    clear_showcmd();


    insert_special(c, FALSE, TRUE);

    revins_chars++;
    revins_legal++;

}


    static int decodeModifyOtherKeys(int c)
{
    char_u  *p = typebuf.tb_buf + typebuf.tb_off;
    int	    idx;
    int	    form = 0;
    int	    argidx = 0;
    int	    arg[2] = {0, 0};

    
    
    
    if (typebuf.tb_len >= 4 && (c == CSI || (c == ESC && *p == '[')))
    {
	idx = (*p == '[');
	if (p[idx] == '2' && p[idx + 1] == '7' && p[idx + 2] == ';')
	{
	    form = 1;
	    idx += 3;
	}
	while (idx < typebuf.tb_len && argidx < 2)
	{
	    if (p[idx] == ';')
		++argidx;
	    else if (VIM_ISDIGIT(p[idx]))
		arg[argidx] = arg[argidx] * 10 + (p[idx] - '0');
	    else break;
	    ++idx;
	}
	if (idx < typebuf.tb_len && p[idx] == (form == 1 ? '~' : 'u')
		&& argidx == 1)
	{
	    
	    typebuf.tb_off += idx + 1;
	    typebuf.tb_len -= idx + 1;

	    if (typebuf.tb_len == 0)
		typebuf_was_filled = FALSE;


	    mod_mask = decode_modifiers(arg[!form]);
	    c = merge_modifyOtherKeys(arg[form], &mod_mask);
	}
    }

    return c;
}


static int  pc_status;




static char_u pc_bytes[MB_MAXBYTES + 1]; 
static int  pc_attr;
static int  pc_row;
static int  pc_col;

    void edit_putchar(int c, int highlight)
{
    int	    attr;

    if (ScreenLines != NULL)
    {
	update_topline();	
	validate_cursor();
	if (highlight)
	    attr = HL_ATTR(HLF_8);
	else attr = 0;
	pc_row = W_WINROW(curwin) + curwin->w_wrow;
	pc_col = curwin->w_wincol;
	pc_status = PC_STATUS_UNSET;

	if (curwin->w_p_rl)
	{
	    pc_col += curwin->w_width - 1 - curwin->w_wcol;
	    if (has_mbyte)
	    {
		int fix_col = mb_fix_col(pc_col, pc_row);

		if (fix_col != pc_col)
		{
		    screen_putchar(' ', pc_row, fix_col, attr);
		    --curwin->w_wcol;
		    pc_status = PC_STATUS_RIGHT;
		}
	    }
	}
	else  {

	    pc_col += curwin->w_wcol;
	    if (mb_lefthalve(pc_row, pc_col))
		pc_status = PC_STATUS_LEFT;
	}

	
	if (pc_status == PC_STATUS_UNSET)
	{
	    screen_getbytes(pc_row, pc_col, pc_bytes, &pc_attr);
	    pc_status = PC_STATUS_SET;
	}
	screen_putchar(c, pc_row, pc_col, attr);
    }
}



    void set_insstart(linenr_T lnum, int col)
{
    Insstart.lnum = lnum;
    Insstart.col = col;
    Insstart_orig = Insstart;
    Insstart_textlen = Insstart.col;
    Insstart_blank_vcol = MAXCOL;
    arrow_used = FALSE;
}



    void edit_unputchar(void)
{
    if (pc_status != PC_STATUS_UNSET && pc_row >= msg_scrolled)
    {
	if (pc_status == PC_STATUS_RIGHT)
	    ++curwin->w_wcol;
	if (pc_status == PC_STATUS_RIGHT || pc_status == PC_STATUS_LEFT)
	    redrawWinline(curwin, curwin->w_cursor.lnum);
	else screen_puts(pc_bytes, pc_row - msg_scrolled, pc_col, pc_attr);
    }
}


    void display_dollar(colnr_T col)
{
    colnr_T save_col;

    if (!redrawing())
	return;

    cursor_off();
    save_col = curwin->w_cursor.col;
    curwin->w_cursor.col = col;
    if (has_mbyte)
    {
	char_u *p;

	
	p = ml_get_curline();
	curwin->w_cursor.col -= (*mb_head_off)(p, p + col);
    }
    curs_columns(FALSE);	    
    if (curwin->w_wcol < curwin->w_width)
    {
	edit_putchar('$', FALSE);
	dollar_vcol = curwin->w_virtcol;
    }
    curwin->w_cursor.col = save_col;
}


    void undisplay_dollar(void)
{
    if (dollar_vcol >= 0)
    {
	dollar_vcol = -1;
	redrawWinline(curwin, curwin->w_cursor.lnum);
    }
}


    void truncate_spaces(char_u *line)
{
    int	    i;

    
    for (i = (int)STRLEN(line) - 1; i >= 0 && VIM_ISWHITE(line[i]); i--)
    {
	if (State & REPLACE_FLAG)
	    replace_join(0);	    
    }
    line[i + 1] = NUL;
}


    void backspace_until_column(int col)
{
    while ((int)curwin->w_cursor.col > col)
    {
	curwin->w_cursor.col--;
	if (State & REPLACE_FLAG)
	    replace_do_bs(col);
	else if (!del_char_after_col(col))
	    break;
    }
}


   static int del_char_after_col(int limit_col UNUSED)
{
    if (enc_utf8 && limit_col >= 0)
    {
	colnr_T ecol = curwin->w_cursor.col + 1;

	
	
	
	mb_adjust_cursor();
	while (curwin->w_cursor.col < (colnr_T)limit_col)
	{
	    int l = utf_ptr2len(ml_get_cursor());

	    if (l == 0)  
		break;
	    curwin->w_cursor.col += l;
	}
	if (*ml_get_cursor() == NUL || curwin->w_cursor.col == ecol)
	    return FALSE;
	del_bytes((long)((int)ecol - curwin->w_cursor.col), FALSE, TRUE);
    }
    else (void)del_char(FALSE);
    return TRUE;
}


    int get_literal(int noReduceKeys)
{
    int		cc;
    int		nc;
    int		i;
    int		hex = FALSE;
    int		octal = FALSE;
    int		unicode = 0;

    if (got_int)
	return Ctrl_C;


    
    if (gui.in_use)
    {
	++allow_keys;
	if (noReduceKeys)
	    ++no_reduce_keys;
    }


    dont_scroll = TRUE;		

    ++no_mapping;		
    cc = 0;
    i = 0;
    for (;;)
    {
	nc = plain_vgetc();
	if ((nc == ESC || nc == CSI) && !noReduceKeys)
	    nc = decodeModifyOtherKeys(nc);

	if ((mod_mask & ~MOD_MASK_SHIFT) != 0)
	    
	    
	    break;


	if ((State & MODE_CMDLINE) == 0 && MB_BYTE2LEN_CHECK(nc) == 1)
	    add_to_showcmd(nc);

	if (nc == 'x' || nc == 'X')
	    hex = TRUE;
	else if (nc == 'o' || nc == 'O')
	    octal = TRUE;
	else if (nc == 'u' || nc == 'U')
	    unicode = nc;
	else {
	    if (hex || unicode != 0)
	    {
		if (!vim_isxdigit(nc))
		    break;
		cc = cc * 16 + hex2nr(nc);
	    }
	    else if (octal)
	    {
		if (nc < '0' || nc > '7')
		    break;
		cc = cc * 8 + nc - '0';
	    }
	    else {
		if (!VIM_ISDIGIT(nc))
		    break;
		cc = cc * 10 + nc - '0';
	    }

	    ++i;
	}

	if (cc > 255 && unicode == 0)
	    cc = 255;		
	nc = 0;

	if (hex)		
	{
	    if (i >= 2)
		break;
	}
	else if (unicode)	
	{
	    if ((unicode == 'u' && i >= 4) || (unicode == 'U' && i >= 8))
		break;
	}
	else if (i >= 3)	
	    break;
    }
    if (i == 0)	    
    {
	if (nc == K_ZERO)   
	{
	    cc = '\n';
	    nc = 0;
	}
	else {
	    cc = nc;
	    nc = 0;
	}
    }

    if (cc == 0)	
	cc = '\n';
    if (enc_dbcs && (cc & 0xff) == 0)
	cc = '?';	
			

    --no_mapping;

    if (gui.in_use)
    {
	--allow_keys;
	if (noReduceKeys)
	    --no_reduce_keys;
    }

    if (nc)
    {
	vungetc(nc);
	
	mod_mask = 0;
    }
    got_int = FALSE;	    
    return cc;
}


    static void insert_special( int	    c, int	    allow_modmask, int	    ctrlv)



{
    char_u  *p;
    int	    len;

    

    
    if (mod_mask & MOD_MASK_CMD)
	allow_modmask = TRUE;

    if (IS_SPECIAL(c) || (mod_mask && allow_modmask))
    {
	p = get_special_key_name(c, mod_mask);
	len = (int)STRLEN(p);
	c = p[len - 1];
	if (len > 2)
	{
	    if (stop_arrow() == FAIL)
		return;
	    p[len - 1] = NUL;
	    ins_str(p);
	    AppendToRedobuffLit(p, -1);
	    ctrlv = FALSE;
	}
    }
    if (stop_arrow() == OK)
	insertchar(c, ctrlv ? INSCHAR_CTRLV : 0, -1);
}





    void insertchar( int		c, int		flags, int		second_indent)



{
    int		textwidth;
    char_u	*p;
    int		fo_ins_blank;
    int		force_format = flags & INSCHAR_FORMAT;

    textwidth = comp_textwidth(force_format);
    fo_ins_blank = has_format_option(FO_INS_BLANK);

    
    if (textwidth > 0 && (force_format || (!VIM_ISWHITE(c)

		    && !((State & REPLACE_FLAG)
			&& !(State & VREPLACE_FLAG)
			&& *ml_get_cursor() != NUL)
		    && (curwin->w_cursor.lnum != Insstart.lnum || ((!has_format_option(FO_INS_LONG)
				|| Insstart_textlen <= (colnr_T)textwidth)
			    && (!fo_ins_blank || Insstart_blank_vcol <= (colnr_T)textwidth ))))))

    {
	
	

	int     do_internal = TRUE;
	colnr_T virtcol = get_nolist_virtcol()
				  + char2cells(c != NUL ? c : gchar_cursor());

	if (*curbuf->b_p_fex != NUL && (flags & INSCHAR_NO_FEX) == 0 && (force_format || virtcol > (colnr_T)textwidth))
	{
	    do_internal = (fex_format(curwin->w_cursor.lnum, 1L, c) != 0);
	    
	    
	    ins_need_undo = TRUE;
	}
	if (do_internal)

	    internal_format(textwidth, second_indent, flags, c == NUL, c);
    }

    if (c == NUL)	    
	return;

    
    if (did_ai && c == end_comment_pending)
    {
	char_u  *line;
	char_u	lead_end[COM_MAX_LEN];	    
	int	middle_len, end_len;
	int	i;

	
	i = get_leader_len(line = ml_get_curline(), &p, FALSE, TRUE);
	if (i > 0 && vim_strchr(p, COM_MIDDLE) != NULL)	
	{
	    
	    while (*p && p[-1] != ':')	
		++p;
	    middle_len = copy_option_part(&p, lead_end, COM_MAX_LEN, ",");
	    
	    while (middle_len > 0 && VIM_ISWHITE(lead_end[middle_len - 1]))
		--middle_len;

	    
	    while (*p && p[-1] != ':')	
		++p;
	    end_len = copy_option_part(&p, lead_end, COM_MAX_LEN, ",");

	    
	    i = curwin->w_cursor.col;
	    while (--i >= 0 && VIM_ISWHITE(line[i]))
		;
	    i++;

	    
	    i -= middle_len;

	    
	    if (i >= 0 && lead_end[end_len - 1] == end_comment_pending)
	    {
		
		backspace_until_column(i);

		
		
		ins_bytes_len(lead_end, end_len - 1);
	    }
	}
    }
    end_comment_pending = NUL;

    did_ai = FALSE;

    did_si = FALSE;
    can_si = FALSE;
    can_si_back = FALSE;


    

    dont_scroll = FALSE;		


    if (       !ISSPECIAL(c)
	    && (!has_mbyte || (*mb_char2len)(c) == 1)
	    && !has_insertcharpre()
	    && vpeekc() != NUL && !(State & REPLACE_FLAG)

	    && !cindent_on()


	    && !p_ri  )

    {

	char_u		buf[INPUT_BUFLEN + 1];
	int		i;
	colnr_T		virtcol = 0;

	buf[0] = c;
	i = 1;
	if (textwidth > 0)
	    virtcol = get_nolist_virtcol();
	
	while (	   (c = vpeekc()) != NUL && !ISSPECIAL(c)
		&& (!has_mbyte || MB_BYTE2LEN_CHECK(c) == 1)
		&& i < INPUT_BUFLEN && (textwidth == 0 || (virtcol += byte2cells(buf[i - 1])) < (colnr_T)textwidth)

		&& !(!no_abbr && !vim_iswordc(c) && vim_iswordc(buf[i - 1])))
	{

	    c = vgetc();
	    if (p_hkmap && KeyTyped)
		c = hkmap(c);		    
	    buf[i++] = c;

	    buf[i++] = vgetc();

	}


	do_digraph(-1);			
	do_digraph(buf[i-1]);		

	buf[i] = NUL;
	ins_str(buf);
	if (flags & INSCHAR_CTRLV)
	{
	    redo_literal(*buf);
	    i = 1;
	}
	else i = 0;
	if (buf[i] != NUL)
	    AppendToRedobuffLit(buf + i, -1);
    }
    else {
	int		cc;

	if (has_mbyte && (cc = (*mb_char2len)(c)) > 1)
	{
	    char_u	buf[MB_MAXBYTES + 1];

	    (*mb_char2bytes)(c, buf);
	    buf[cc] = NUL;
	    ins_char_bytes(buf, cc);
	    AppendCharToRedobuff(c);
	}
	else {
	    ins_char(c);
	    if (flags & INSCHAR_CTRLV)
		redo_literal(c);
	    else AppendCharToRedobuff(c);
	}
    }
}


    static void redo_literal(int c)
{
    char_u	buf[10];

    
    
    if (VIM_ISDIGIT(c))
    {
	vim_snprintf((char *)buf, sizeof(buf), "%03d", c);
	AppendToRedobuff(buf);
    }
    else AppendCharToRedobuff(c);
}


    void start_arrow( pos_T    *end_insert_pos)

{
    start_arrow_common(end_insert_pos, TRUE);
}


    static void start_arrow_with_change( pos_T    *end_insert_pos, int	      end_change)


{
    start_arrow_common(end_insert_pos, end_change);
    if (!end_change)
    {
	AppendCharToRedobuff(Ctrl_G);
	AppendCharToRedobuff('U');
    }
}

    static void start_arrow_common( pos_T    *end_insert_pos, int	      end_change)


{
    if (!arrow_used && end_change)	
    {
	AppendToRedobuff(ESC_STR);
	stop_insert(end_insert_pos, FALSE, FALSE);
	arrow_used = TRUE;	
    }

    check_spell_redraw();

}



    static void check_spell_redraw(void)
{
    if (spell_redraw_lnum != 0)
    {
	linenr_T	lnum = spell_redraw_lnum;

	spell_redraw_lnum = 0;
	redrawWinline(curwin, lnum);
    }
}




    int stop_arrow(void)
{
    if (arrow_used)
    {
	Insstart = curwin->w_cursor;	
	if (Insstart.col > Insstart_orig.col && !ins_need_undo)
	    
	    
	    update_Insstart_orig = FALSE;
	Insstart_textlen = (colnr_T)linetabsize(ml_get_curline());

	if (u_save_cursor() == OK)
	{
	    arrow_used = FALSE;
	    ins_need_undo = FALSE;
	}

	ai_col = 0;
	if (State & VREPLACE_FLAG)
	{
	    orig_line_count = curbuf->b_ml.ml_line_count;
	    vr_lines_changed = 1;
	}
	ResetRedobuff();
	AppendToRedobuff((char_u *)"1i");   
	new_insert_skip = 2;
    }
    else if (ins_need_undo)
    {
	if (u_save_cursor() == OK)
	    ins_need_undo = FALSE;
    }


    
    foldOpenCursor();


    return (arrow_used || ins_need_undo ? FAIL : OK);
}


    static void stop_insert( pos_T	*end_insert_pos, int		esc, int		nomove)



{
    int		cc;
    char_u	*ptr;

    stop_redo_ins();
    replace_flush();		

    
    ptr = get_inserted();
    if (did_restart_edit == 0 || (ptr != NULL && (int)STRLEN(ptr) > new_insert_skip))
    {
	vim_free(last_insert);
	last_insert = ptr;
	last_insert_skip = new_insert_skip;
    }
    else vim_free(ptr);

    if (!arrow_used && end_insert_pos != NULL)
    {
	
	
	
	
	if (!ins_need_undo && has_format_option(FO_AUTO))
	{
	    pos_T   tpos = curwin->w_cursor;

	    
	    
	    
	    cc = 'x';
	    if (curwin->w_cursor.col > 0 && gchar_cursor() == NUL)
	    {
		dec_cursor();
		cc = gchar_cursor();
		if (!VIM_ISWHITE(cc))
		    curwin->w_cursor = tpos;
	    }

	    auto_format(TRUE, FALSE);

	    if (VIM_ISWHITE(cc))
	    {
		if (gchar_cursor() != NUL)
		    inc_cursor();
		
		
		if (gchar_cursor() == NUL && curwin->w_cursor.lnum == tpos.lnum && curwin->w_cursor.col == tpos.col)

		    curwin->w_cursor.coladd = tpos.coladd;
	    }
	}

	
	check_auto_format(TRUE);

	
	
	
	
	
	if (!nomove && did_ai && (esc || (vim_strchr(p_cpo, CPO_INDENT) == NULL && curwin->w_cursor.lnum != end_insert_pos->lnum))
		&& end_insert_pos->lnum <= curbuf->b_ml.ml_line_count)
	{
	    pos_T	tpos = curwin->w_cursor;

	    curwin->w_cursor = *end_insert_pos;
	    check_cursor_col();  
	    for (;;)
	    {
		if (gchar_cursor() == NUL && curwin->w_cursor.col > 0)
		    --curwin->w_cursor.col;
		cc = gchar_cursor();
		if (!VIM_ISWHITE(cc))
		    break;
		if (del_char(TRUE) == FAIL)
		    break;  
	    }
	    if (curwin->w_cursor.lnum != tpos.lnum)
		curwin->w_cursor = tpos;
	    else {
		
		tpos = curwin->w_cursor;
		tpos.col++;
		if (cc != NUL && gchar_pos(&tpos) == NUL)
		    ++curwin->w_cursor.col;	
	    }

	    
	    
	    if (VIsual_active && VIsual.lnum == curwin->w_cursor.lnum)
	    {
		int len = (int)STRLEN(ml_get_curline());

		if (VIsual.col > len)
		{
		    VIsual.col = len;
		    VIsual.coladd = 0;
		}
	    }
	}
    }
    did_ai = FALSE;

    did_si = FALSE;
    can_si = FALSE;
    can_si_back = FALSE;


    
    
    if (end_insert_pos != NULL)
    {
	curbuf->b_op_start = Insstart;
	curbuf->b_op_start_orig = Insstart_orig;
	curbuf->b_op_end = *end_insert_pos;
    }
}


    void set_last_insert(int c)
{
    char_u	*s;

    vim_free(last_insert);
    last_insert = alloc(MB_MAXBYTES * 3 + 5);
    if (last_insert != NULL)
    {
	s = last_insert;
	
	if (c < ' ' || c == DEL)
	    *s++ = Ctrl_V;
	s = add_char2buf(c, s);
	*s++ = ESC;
	*s++ = NUL;
	last_insert_skip = 0;
    }
}


    void free_last_insert(void)
{
    VIM_CLEAR(last_insert);
}



    char_u * add_char2buf(int c, char_u *s)
{
    char_u	temp[MB_MAXBYTES + 1];
    int		i;
    int		len;

    len = (*mb_char2bytes)(c, temp);
    for (i = 0; i < len; ++i)
    {
	c = temp[i];
	
	if (c == K_SPECIAL)
	{
	    *s++ = K_SPECIAL;
	    *s++ = KS_SPECIAL;
	    *s++ = KE_FILLER;
	}

	else if (c == CSI)
	{
	    *s++ = CSI;
	    *s++ = KS_EXTRA;
	    *s++ = (int)KE_CSI;
	}

	else *s++ = c;
    }
    return s;
}


    void beginline(int flags)
{
    if ((flags & BL_SOL) && !p_sol)
	coladvance(curwin->w_curswant);
    else {
	curwin->w_cursor.col = 0;
	curwin->w_cursor.coladd = 0;

	if (flags & (BL_WHITE | BL_SOL))
	{
	    char_u  *ptr;

	    for (ptr = ml_get_curline(); VIM_ISWHITE(*ptr)
			       && !((flags & BL_FIX) && ptr[1] == NUL); ++ptr)
		++curwin->w_cursor.col;
	}
	curwin->w_set_curswant = TRUE;
    }
}



    int oneright(void)
{
    char_u	*ptr;
    int		l;

    if (virtual_active())
    {
	pos_T	prevpos = curwin->w_cursor;

	
	ptr = ml_get_cursor();
	coladvance(getviscol() + ((*ptr != TAB && vim_isprintc((*mb_ptr2char)(ptr)))
		    ? ptr2cells(ptr) : 1));
	curwin->w_set_curswant = TRUE;
	
	return (prevpos.col != curwin->w_cursor.col || prevpos.coladd != curwin->w_cursor.coladd) ? OK : FAIL;
    }

    ptr = ml_get_cursor();
    if (*ptr == NUL)
	return FAIL;	    

    if (has_mbyte)
	l = (*mb_ptr2len)(ptr);
    else l = 1;

    
    
    if (ptr[l] == NUL && (get_ve_flags() & VE_ONEMORE) == 0)
	return FAIL;
    curwin->w_cursor.col += l;

    curwin->w_set_curswant = TRUE;
    return OK;
}

    int oneleft(void)
{
    if (virtual_active())
    {

	int width;

	int v = getviscol();

	if (v == 0)
	    return FAIL;


	
	width = 1;
	for (;;)
	{
	    coladvance(v - width);
	    
	    
	    
	    if ((*get_showbreak_value(curwin) == NUL && !curwin->w_p_bri && !has_mbyte) || getviscol() < v)
		break;
	    ++width;
	}

	coladvance(v - 1);


	if (curwin->w_cursor.coladd == 1)
	{
	    char_u *ptr;

	    
	    ptr = ml_get_cursor();
	    if (*ptr != TAB && vim_isprintc((*mb_ptr2char)(ptr))
							 && ptr2cells(ptr) > 1)
		curwin->w_cursor.coladd = 0;
	}

	curwin->w_set_curswant = TRUE;
	return OK;
    }

    if (curwin->w_cursor.col == 0)
	return FAIL;

    curwin->w_set_curswant = TRUE;
    --curwin->w_cursor.col;

    
    
    if (has_mbyte)
	mb_adjust_cursor();
    return OK;
}

    int cursor_up( long	n, int		upd_topline)


{
    linenr_T	lnum;

    if (n > 0)
    {
	lnum = curwin->w_cursor.lnum;
	
	
	if (lnum <= 1 || (n >= lnum && vim_strchr(p_cpo, CPO_MINUS) != NULL))
	    return FAIL;
	if (n >= lnum)
	    lnum = 1;
	else  if (hasAnyFolding(curwin))

	{
	    
	    
	    (void)hasFolding(lnum, &lnum, NULL);

	    while (n--)
	    {
		
		--lnum;
		if (lnum <= 1)
		    break;
		
		
		
		if (n > 0 || !((State & MODE_INSERT) || (fdo_flags & FDO_ALL)))
		    (void)hasFolding(lnum, &lnum, NULL);
	    }
	    if (lnum < 1)
		lnum = 1;
	}
	else  lnum -= n;

	curwin->w_cursor.lnum = lnum;
    }

    
    coladvance(curwin->w_curswant);

    if (upd_topline)
	update_topline();	

    return OK;
}


    int cursor_down( long	n, int		upd_topline)


{
    linenr_T	lnum;

    if (n > 0)
    {
	lnum = curwin->w_cursor.lnum;

	
	(void)hasFolding(lnum, NULL, &lnum);

	
	
	if (lnum >= curbuf->b_ml.ml_line_count || (lnum + n > curbuf->b_ml.ml_line_count && vim_strchr(p_cpo, CPO_MINUS) != NULL))

	    return FAIL;
	if (lnum + n >= curbuf->b_ml.ml_line_count)
	    lnum = curbuf->b_ml.ml_line_count;
	else  if (hasAnyFolding(curwin))

	{
	    linenr_T	last;

	    
	    while (n--)
	    {
		if (hasFolding(lnum, NULL, &last))
		    lnum = last + 1;
		else ++lnum;
		if (lnum >= curbuf->b_ml.ml_line_count)
		    break;
	    }
	    if (lnum > curbuf->b_ml.ml_line_count)
		lnum = curbuf->b_ml.ml_line_count;
	}
	else  lnum += n;

	curwin->w_cursor.lnum = lnum;
    }

    
    coladvance(curwin->w_curswant);

    if (upd_topline)
	update_topline();	

    return OK;
}


    int stuff_inserted( int	    c, long    count, int	    no_esc)



{
    char_u	*esc_ptr;
    char_u	*ptr;
    char_u	*last_ptr;
    char_u	last = NUL;

    ptr = get_last_insert();
    if (ptr == NULL)
    {
	emsg(_(e_no_inserted_text_yet));
	return FAIL;
    }

    
    if (c != NUL)
	stuffcharReadbuff(c);
    if ((esc_ptr = vim_strrchr(ptr, ESC)) != NULL)
	*esc_ptr = NUL;	    

    
    
    
    last_ptr = (esc_ptr ? esc_ptr : ptr + STRLEN(ptr)) - 1;
    if (last_ptr >= ptr && (*last_ptr == '0' || *last_ptr == '^')
	    && (no_esc || (*ptr == Ctrl_D && count > 1)))
    {
	last = *last_ptr;
	*last_ptr = NUL;
    }

    do {
	stuffReadbuff(ptr);
	
	if (last)
	    stuffReadbuff( (char_u *)(last == '0' ? "\026\060\064\070" : "\026^"));
    }
    while (--count > 0);

    if (last)
	*last_ptr = last;

    if (esc_ptr != NULL)
	*esc_ptr = ESC;	    

    
    if (!no_esc)
	stuffcharReadbuff(ESC);

    return OK;
}

    char_u * get_last_insert(void)
{
    if (last_insert == NULL)
	return NULL;
    return last_insert + last_insert_skip;
}


    char_u * get_last_insert_save(void)
{
    char_u	*s;
    int		len;

    if (last_insert == NULL)
	return NULL;
    s = vim_strsave(last_insert + last_insert_skip);
    if (s != NULL)
    {
	len = (int)STRLEN(s);
	if (len > 0 && s[len - 1] == ESC)	
	    s[len - 1] = NUL;
    }
    return s;
}


    static int echeck_abbr(int c)
{
    
    
    if (p_paste || no_abbr || arrow_used)
	return FALSE;

    return check_abbr(c, ml_get_curline(), curwin->w_cursor.col, curwin->w_cursor.lnum == Insstart.lnum ? Insstart.col : 0);
}



static char_u	*replace_stack = NULL;
static long	replace_stack_nr = 0;	    
static long	replace_stack_len = 0;	    

    void replace_push( int	    c)

{
    char_u  *p;

    if (replace_stack_nr < replace_offset)	
	return;
    if (replace_stack_len <= replace_stack_nr)
    {
	replace_stack_len += 50;
	p = ALLOC_MULT(char_u, replace_stack_len);
	if (p == NULL)	    
	{
	    replace_stack_len -= 50;
	    return;
	}
	if (replace_stack != NULL)
	{
	    mch_memmove(p, replace_stack, (size_t)(replace_stack_nr * sizeof(char_u)));
	    vim_free(replace_stack);
	}
	replace_stack = p;
    }
    p = replace_stack + replace_stack_nr - replace_offset;
    if (replace_offset)
	mch_memmove(p + 1, p, (size_t)(replace_offset * sizeof(char_u)));
    *p = c;
    ++replace_stack_nr;
}


    int replace_push_mb(char_u *p)
{
    int l = (*mb_ptr2len)(p);
    int j;

    for (j = l - 1; j >= 0; --j)
	replace_push(p[j]);
    return l;
}


    static int replace_pop(void)
{
    if (replace_stack_nr == 0)
	return -1;
    return (int)replace_stack[--replace_stack_nr];
}


    void replace_join( int	    off)

{
    int	    i;

    for (i = replace_stack_nr; --i >= 0; )
	if (replace_stack[i] == NUL && off-- <= 0)
	{
	    --replace_stack_nr;
	    mch_memmove(replace_stack + i, replace_stack + i + 1, (size_t)(replace_stack_nr - i));
	    return;
	}
}


    static void replace_pop_ins(void)
{
    int	    cc;
    int	    oldState = State;

    State = MODE_NORMAL;			
    while ((cc = replace_pop()) > 0)
    {
	mb_replace_pop_ins(cc);
	dec_cursor();
    }
    State = oldState;
}


    static void mb_replace_pop_ins(int cc)
{
    int		n;
    char_u	buf[MB_MAXBYTES + 1];
    int		i;
    int		c;

    if (has_mbyte && (n = MB_BYTE2LEN(cc)) > 1)
    {
	buf[0] = cc;
	for (i = 1; i < n; ++i)
	    buf[i] = replace_pop();
	ins_bytes_len(buf, n);
    }
    else ins_char(cc);

    if (enc_utf8)
	
	for (;;)
	{
	    c = replace_pop();
	    if (c == -1)	    
		break;
	    if ((n = MB_BYTE2LEN(c)) == 1)
	    {
		
		replace_push(c);
		break;
	    }

	    buf[0] = c;
	    for (i = 1; i < n; ++i)
		buf[i] = replace_pop();
	    if (utf_iscomposing(utf_ptr2char(buf)))
		ins_bytes_len(buf, n);
	    else {
		
		for (i = n - 1; i >= 0; --i)
		    replace_push(buf[i]);
		break;
	    }

	}
}


    static void replace_flush(void)
{
    VIM_CLEAR(replace_stack);
    replace_stack_len = 0;
    replace_stack_nr = 0;
}


    static void replace_do_bs(int limit_col)
{
    int		cc;
    int		orig_len = 0;
    int		ins_len;
    int		orig_vcols = 0;
    colnr_T	start_vcol;
    char_u	*p;
    int		i;
    int		vcol;

    cc = replace_pop();
    if (cc > 0)
    {

	size_t	len_before = 0;  

	if (curbuf->b_has_textprop)
	{
	    
	    
	    len_before = STRLEN(ml_get_curline());
	    ++text_prop_frozen;
	}

	if (State & VREPLACE_FLAG)
	{
	    
	    
	    getvcol(curwin, &curwin->w_cursor, NULL, &start_vcol, NULL);
	    orig_vcols = chartabsize(ml_get_cursor(), start_vcol);
	}
	if (has_mbyte)
	{
	    (void)del_char_after_col(limit_col);
	    if (State & VREPLACE_FLAG)
		orig_len = (int)STRLEN(ml_get_cursor());
	    replace_push(cc);
	}
	else {
	    pchar_cursor(cc);
	    if (State & VREPLACE_FLAG)
		orig_len = (int)STRLEN(ml_get_cursor()) - 1;
	}
	replace_pop_ins();

	if (State & VREPLACE_FLAG)
	{
	    
	    p = ml_get_cursor();
	    ins_len = (int)STRLEN(p) - orig_len;
	    vcol = start_vcol;
	    for (i = 0; i < ins_len; ++i)
	    {
		vcol += chartabsize(p + i, vcol);
		i += (*mb_ptr2len)(p) - 1;
	    }
	    vcol -= start_vcol;

	    
	    
	    curwin->w_cursor.col += ins_len;
	    while (vcol > orig_vcols && gchar_cursor() == ' ')
	    {
		del_char(FALSE);
		++orig_vcols;
	    }
	    curwin->w_cursor.col -= ins_len;
	}

	
	changed_bytes(curwin->w_cursor.lnum, curwin->w_cursor.col);


	if (curbuf->b_has_textprop)
	{
	    size_t len_now = STRLEN(ml_get_curline());

	    --text_prop_frozen;
	    adjust_prop_columns(curwin->w_cursor.lnum, curwin->w_cursor.col, (int)(len_now - len_before), 0);
	}

    }
    else if (cc == 0)
	(void)del_char_after_col(limit_col);
}



    int hkmap(int c)
{
    if (p_hkmapp)   
    {
	enum {hALEF=0, BET, GIMEL, DALET, HEI, VAV, ZAIN, HET, TET, IUD, KAFsofit, hKAF, LAMED, MEMsofit, MEM, NUNsofit, NUN, SAMEH, AIN, PEIsofit, PEI, ZADIsofit, ZADI, KOF, RESH, hSHIN, TAV};

	static char_u map[26] = {(char_u)hALEF, (char_u)BET  , (char_u)hKAF    , (char_u)DALET, (char_u)-1   , (char_u)PEIsofit, (char_u)GIMEL, (char_u)HEI  , (char_u)IUD     , (char_u)HET  , (char_u)KOF  , (char_u)LAMED   , (char_u)MEM  , (char_u)NUN  , (char_u)SAMEH   , (char_u)PEI  , (char_u)-1   , (char_u)RESH    , (char_u)ZAIN , (char_u)TAV  , (char_u)TET     , (char_u)VAV  , (char_u)hSHIN, (char_u)-1      , (char_u)AIN  , (char_u)ZADI ;









	if (c == 'N' || c == 'M' || c == 'P' || c == 'C' || c == 'Z')
	    return (int)(map[CharOrd(c)] - 1 + p_aleph);
							    
	else if (c == 'x')
	    return 'X';
	else if (c == 'q')
	    return '\''; 
	else if (c == 246)
	    return ' ';  
	else if (c == 228)
	    return ' ';  
	else if (c == 252)
	    return ' ';  
	
	
	
	
	else if (c >= 'a' && c <= 'z')
	    return (int)(map[CharOrdLow(c)] + p_aleph);
	else return c;
    }
    else {
	switch (c)
	{
	    case '`':	return ';';
	    case '/':	return '.';
	    case '\'':	return ',';
	    case 'q':	return '/';
	    case 'w':	return '\'';

			
	    case ',':	c = '{'; break;
	    case '.':	c = 'v'; break;
	    case ';':	c = 't'; break;
	    default: {
			 static char str[] = "zqbcxlsjphmkwonu ydafe rig";

			 if (c < 'a' || c > 'z')
			     return c;
			 c = str[CharOrdLow(c)];
			 break;
		     }
	}

	return (int)(CharOrdLow(c) + p_aleph);
    }
}


    static void ins_reg(void)
{
    int		need_redraw = FALSE;
    int		regname;
    int		literally = 0;
    int		vis_active = VIsual_active;

    
    pc_status = PC_STATUS_UNSET;
    if (redrawing() && !char_avail())
    {
	
	ins_redraw(FALSE);

	edit_putchar('"', TRUE);

	add_to_showcmd_c(Ctrl_R);

    }


    dont_scroll = TRUE;		


    
    ++no_mapping;
    ++allow_keys;
    regname = plain_vgetc();
    LANGMAP_ADJUST(regname, TRUE);
    if (regname == Ctrl_R || regname == Ctrl_O || regname == Ctrl_P)
    {
	
	literally = regname;

	add_to_showcmd_c(literally);

	regname = plain_vgetc();
	LANGMAP_ADJUST(regname, TRUE);
    }
    --no_mapping;
    --allow_keys;


    
    
    ++no_u_sync;
    if (regname == '=')
    {
	pos_T	curpos = curwin->w_cursor;

	int	im_on = im_get_status();

	
	
	u_sync_once = 2;

	regname = get_expr_register();

	
	curwin->w_cursor = curpos;
	check_cursor();

	
	if (im_on)
	    im_set_active(TRUE);

    }
    if (regname == NUL || !valid_yank_reg(regname, FALSE))
    {
	vim_beep(BO_REG);
	need_redraw = TRUE;	
    }
    else {

	if (literally == Ctrl_O || literally == Ctrl_P)
	{
	    
	    AppendCharToRedobuff(Ctrl_R);
	    AppendCharToRedobuff(literally);
	    AppendCharToRedobuff(regname);

	    do_put(regname, NULL, BACKWARD, 1L, (literally == Ctrl_P ? PUT_FIXINDENT : 0) | PUT_CURSEND);
	}
	else if (insert_reg(regname, literally) == FAIL)
	{
	    vim_beep(BO_REG);
	    need_redraw = TRUE;	
	}
	else if (stop_insert_mode)
	    
	    
	    
	    need_redraw = TRUE;


    }
    --no_u_sync;
    if (u_sync_once == 1)
	ins_need_undo = TRUE;
    u_sync_once = 0;


    clear_showcmd();


    
    if (need_redraw || stuff_empty())
	edit_unputchar();

    
    if (!vis_active && VIsual_active)
	end_visual_mode();
}


    static void ins_ctrl_g(void)
{
    int		c;

    
    setcursor();

    
    ++no_mapping;
    ++allow_keys;
    c = plain_vgetc();
    --no_mapping;
    --allow_keys;
    switch (c)
    {
	
	case K_UP:
	case Ctrl_K:
	case 'k': ins_up(TRUE);
		  break;

	
	case K_DOWN:
	case Ctrl_J:
	case 'j': ins_down(TRUE);
		  break;

	
	case 'u': u_sync(TRUE);
		  ins_need_undo = TRUE;

		  
		  
		  update_Insstart_orig = FALSE;
		  Insstart = curwin->w_cursor;
		  break;

	
	case 'U':
		  
		  
		  dont_sync_undo = MAYBE;
		  break;

	
	default:  vim_beep(BO_CTRLG);
    }
}


    static void ins_ctrl_hat(void)
{
    if (map_to_exists_mode((char_u *)"", MODE_LANGMAP, FALSE))
    {
	
	if (State & MODE_LANGMAP)
	{
	    curbuf->b_p_iminsert = B_IMODE_NONE;
	    State &= ~MODE_LANGMAP;
	}
	else {
	    curbuf->b_p_iminsert = B_IMODE_LMAP;
	    State |= MODE_LANGMAP;

	    im_set_active(FALSE);

	}
    }

    else {
	
	if (im_get_status())
	{
	    curbuf->b_p_iminsert = B_IMODE_NONE;
	    im_set_active(FALSE);
	}
	else {
	    curbuf->b_p_iminsert = B_IMODE_IM;
	    State &= ~MODE_LANGMAP;
	    im_set_active(TRUE);
	}
    }

    set_iminsert_global();
    showmode();

    
    if (gui.in_use)
	gui_update_cursor(TRUE, FALSE);


    
    status_redraw_curbuf();

}


    static int ins_esc( long	*count, int		cmdchar, int		nomove)



{
    int		temp;
    static int	disabled_redraw = FALSE;

    
    int		cursor_line_was_concealed = curwin->w_p_cole > 0 && conceal_cursor_line(curwin);



    check_spell_redraw();


    temp = curwin->w_cursor.col;
    if (disabled_redraw)
    {
	--RedrawingDisabled;
	disabled_redraw = FALSE;
    }
    if (!arrow_used)
    {
	
	if (cmdchar != 'r' && cmdchar != 'v')
	    AppendToRedobuff(p_im ? (char_u *)"\014" : ESC_STR);

	
	if (*count > 0)
	{
	    line_breakcheck();
	    if (got_int)
		*count = 0;
	}

	if (--*count > 0)	
	{
	    
	    if (vim_strchr(p_cpo, CPO_REPLCNT) != NULL)
		State &= ~REPLACE_FLAG;

	    (void)start_redo_ins();
	    if (cmdchar == 'r' || cmdchar == 'v')
		stuffRedoReadbuff(ESC_STR);	
	    ++RedrawingDisabled;
	    disabled_redraw = TRUE;
	    return FALSE;	
	}
	stop_insert(&curwin->w_cursor, TRUE, nomove);
	undisplay_dollar();
    }

    if (cmdchar != 'r' && cmdchar != 'v')
	ins_apply_autocmds(EVENT_INSERTLEAVEPRE);

    
    
    if (restart_edit == NUL && (colnr_T)temp == curwin->w_cursor.col)
	curwin->w_set_curswant = TRUE;

    
    if ((cmdmod.cmod_flags & CMOD_KEEPJUMPS) == 0)
	curbuf->b_last_insert = curwin->w_cursor;

    
    if (!nomove && (curwin->w_cursor.col != 0 || curwin->w_cursor.coladd > 0)

	    && (restart_edit == NUL || (gchar_cursor() == NUL && !VIsual_active))

	    && !revins_on  )

    {
	if (curwin->w_cursor.coladd > 0 || get_ve_flags() == VE_ALL)
	{
	    oneleft();
	    if (restart_edit != NUL)
		++curwin->w_cursor.coladd;
	}
	else {
	    --curwin->w_cursor.col;
	    
	    if (has_mbyte)
		mb_adjust_cursor();
	}
    }


    
    
    
    if (!(State & MODE_LANGMAP))
	im_save_status(&curbuf->b_p_iminsert);
    im_set_active(FALSE);


    State = MODE_NORMAL;
    may_trigger_modechanged();
    
    if (gchar_cursor() == TAB)
	curwin->w_valid &= ~(VALID_WROW|VALID_WCOL|VALID_VIRTCOL);

    setmouse();

    ui_cursor_shape();		

    if (!p_ek)
    {

	ch_log_output = TRUE;

	
	out_str(T_BE);

	
	out_str(T_CTI);
    }

    
    
    conceal_check_cursor_line(cursor_line_was_concealed);


    
    
    if (reg_recording != 0 || restart_edit != NUL)
	showmode();
    else if (p_smd && (got_int || !skip_showmode()))
	msg("");

    return TRUE;	    
}



    static void ins_ctrl_(void)
{
    if (revins_on && revins_chars && revins_scol >= 0)
    {
	while (gchar_cursor() != NUL && revins_chars--)
	    ++curwin->w_cursor.col;
    }
    p_ri = !p_ri;
    revins_on = (State == MODE_INSERT && p_ri);
    if (revins_on)
    {
	revins_scol = curwin->w_cursor.col;
	revins_legal++;
	revins_chars = 0;
	undisplay_dollar();
    }
    else revins_scol = -1;
    p_hkmap = curwin->w_p_rl ^ p_ri;    
    showmode();
}



    static int ins_start_select(int c)
{
    if (km_startsel)
	switch (c)
	{
	    case K_KHOME:
	    case K_KEND:
	    case K_PAGEUP:
	    case K_KPAGEUP:
	    case K_PAGEDOWN:
	    case K_KPAGEDOWN:

	    case K_LEFT:
	    case K_RIGHT:
	    case K_UP:
	    case K_DOWN:
	    case K_END:
	    case K_HOME:

		if (!(mod_mask & MOD_MASK_SHIFT))
		    break;
		
	    case K_S_LEFT:
	    case K_S_RIGHT:
	    case K_S_UP:
	    case K_S_DOWN:
	    case K_S_END:
	    case K_S_HOME:
		
		
		start_selection();

		
		stuffcharReadbuff(Ctrl_O);
		if (mod_mask)
		{
		    char_u	    buf[4];

		    buf[0] = K_SPECIAL;
		    buf[1] = KS_MODIFIER;
		    buf[2] = mod_mask;
		    buf[3] = NUL;
		    stuffReadbuff(buf);
		}
		stuffcharReadbuff(c);
		return TRUE;
	}
    return FALSE;
}


    static void ins_insert(int replaceState)
{

    set_vim_var_string(VV_INSERTMODE, (char_u *)((State & REPLACE_FLAG) ? "i" : replaceState == MODE_VREPLACE ? "v" : "r"), 1);


    ins_apply_autocmds(EVENT_INSERTCHANGE);
    if (State & REPLACE_FLAG)
	State = MODE_INSERT | (State & MODE_LANGMAP);
    else State = replaceState | (State & MODE_LANGMAP);
    may_trigger_modechanged();
    AppendCharToRedobuff(K_INS);
    showmode();

    ui_cursor_shape();		

}


    static void ins_ctrl_o(void)
{
    if (State & VREPLACE_FLAG)
	restart_edit = 'V';
    else if (State & REPLACE_FLAG)
	restart_edit = 'R';
    else restart_edit = 'I';
    if (virtual_active())
	ins_at_eol = FALSE;	
    else ins_at_eol = (gchar_cursor() == NUL);
}


    static void ins_shift(int c, int lastc)
{
    if (stop_arrow() == FAIL)
	return;
    AppendCharToRedobuff(c);

    
    if (c == Ctrl_D && (lastc == '0' || lastc == '^')
						  && curwin->w_cursor.col > 0)
    {
	--curwin->w_cursor.col;
	(void)del_char(FALSE);		
	
	if (State & REPLACE_FLAG)
	    replace_pop_ins();
	if (lastc == '^')
	    old_indent = get_indent();	
	change_indent(INDENT_SET, 0, TRUE, 0, TRUE);
    }
    else change_indent(c == Ctrl_D ? INDENT_DEC : INDENT_INC, 0, TRUE, 0, TRUE);

    if (did_ai && *skipwhite(ml_get_curline()) != NUL)
	did_ai = FALSE;

    did_si = FALSE;
    can_si = FALSE;
    can_si_back = FALSE;


    can_cindent = FALSE;	

}

    static void ins_del(void)
{
    int	    temp;

    if (stop_arrow() == FAIL)
	return;
    if (gchar_cursor() == NUL)		
    {
	temp = curwin->w_cursor.col;
	if (!can_bs(BS_EOL)		
		|| do_join(2, FALSE, TRUE, FALSE, FALSE) == FAIL)
	    vim_beep(BO_BS);
	else {
	    curwin->w_cursor.col = temp;
	    
	    
	    
	    if (State & VREPLACE_FLAG && orig_line_count > curbuf->b_ml.ml_line_count)
		orig_line_count = curbuf->b_ml.ml_line_count;
	}
    }
    else if (del_char(FALSE) == FAIL)  
	vim_beep(BO_BS);
    did_ai = FALSE;

    did_si = FALSE;
    can_si = FALSE;
    can_si_back = FALSE;

    AppendCharToRedobuff(K_DEL);
}


    static void ins_bs_one(colnr_T *vcolp)
{
    dec_cursor();
    getvcol(curwin, &curwin->w_cursor, vcolp, NULL, NULL);
    if (State & REPLACE_FLAG)
    {
	
	
	if (curwin->w_cursor.lnum != Insstart.lnum || curwin->w_cursor.col >= Insstart.col)
	    replace_do_bs(-1);
    }
    else (void)del_char(FALSE);
}


    static int ins_bs( int		c, int		mode, int		*inserted_space_p)



{
    linenr_T	lnum;
    int		cc;
    int		temp = 0;	    
    colnr_T	save_col;
    colnr_T	mincol;
    int		did_backspace = FALSE;
    int		in_indent;
    int		oldState;
    int		cpc[MAX_MCO];	    

    int		call_fix_indent = FALSE;


    
    if (       BUFEMPTY()
	    || (  !revins_on &&  ((curwin->w_cursor.lnum == 1 && curwin->w_cursor.col == 0)



		    || (!can_bs(BS_START)
			&& ((arrow_used  && !bt_prompt(curbuf)


			) || (curwin->w_cursor.lnum == Insstart_orig.lnum && curwin->w_cursor.col <= Insstart_orig.col)))
		    || (!can_bs(BS_INDENT) && !arrow_used && ai_col > 0 && curwin->w_cursor.col <= ai_col)
		    || (!can_bs(BS_EOL) && curwin->w_cursor.col == 0))))
    {
	vim_beep(BO_BS);
	return FALSE;
    }

    if (stop_arrow() == FAIL)
	return FALSE;
    in_indent = inindent(0);

    if (in_indent)
	can_cindent = FALSE;

    end_comment_pending = NUL;	

    if (revins_on)	    
	inc_cursor();


    
    
    
    
    if (curwin->w_cursor.coladd > 0)
    {
	if (mode == BACKSPACE_CHAR)
	{
	    --curwin->w_cursor.coladd;
	    return TRUE;
	}
	if (mode == BACKSPACE_WORD)
	{
	    curwin->w_cursor.coladd = 0;
	    return TRUE;
	}
	curwin->w_cursor.coladd = 0;
    }

    
    if (curwin->w_cursor.col == 0)
    {
	lnum = Insstart.lnum;
	if (curwin->w_cursor.lnum == lnum  || revins_on  )



	{
	    if (u_save((linenr_T)(curwin->w_cursor.lnum - 2), (linenr_T)(curwin->w_cursor.lnum + 1)) == FAIL)
		return FALSE;
	    --Insstart.lnum;
	    Insstart.col = (colnr_T)STRLEN(ml_get(Insstart.lnum));
	}
	
	cc = -1;
	if (State & REPLACE_FLAG)
	    cc = replace_pop();	    
	
	if ((State & REPLACE_FLAG) && curwin->w_cursor.lnum <= lnum)
	{
	    dec_cursor();
	}
	else {
	    if (!(State & VREPLACE_FLAG)
				   || curwin->w_cursor.lnum > orig_line_count)
	    {
		temp = gchar_cursor();	
		--curwin->w_cursor.lnum;

		
		
		
		if (has_format_option(FO_AUTO)
					   && has_format_option(FO_WHITE_PAR))
		{
		    char_u  *ptr = ml_get_buf(curbuf, curwin->w_cursor.lnum, TRUE);
		    int	    len;

		    len = (int)STRLEN(ptr);
		    if (len > 0 && ptr[len - 1] == ' ')
			ptr[len - 1] = NUL;
		}

		(void)do_join(2, FALSE, FALSE, FALSE, FALSE);
		if (temp == NUL && gchar_cursor() != NUL)
		    inc_cursor();
	    }
	    else dec_cursor();

	    
	    if (State & REPLACE_FLAG)
	    {
		
		oldState = State;
		State = MODE_NORMAL;
		
		while (cc > 0)
		{
		    save_col = curwin->w_cursor.col;
		    mb_replace_pop_ins(cc);
		    curwin->w_cursor.col = save_col;
		    cc = replace_pop();
		}
		
		replace_pop_ins();
		State = oldState;
	    }
	}
	did_ai = FALSE;
    }
    else {
	

	if (revins_on)		
	    dec_cursor();

	mincol = 0;
						
	if (mode == BACKSPACE_LINE && (curbuf->b_p_ai  || cindent_on()



		   )

		&& !revins_on  )

	{
	    save_col = curwin->w_cursor.col;
	    beginline(BL_WHITE);
	    if (curwin->w_cursor.col < save_col)
	    {
		mincol = curwin->w_cursor.col;

		
		call_fix_indent = TRUE;

	    }
	    curwin->w_cursor.col = save_col;
	}

	
	if (	   mode == BACKSPACE_CHAR && ((p_sta && in_indent)
		    || ((get_sts_value() != 0  || tabstop_count(curbuf->b_p_vsts_array)


			)
			&& curwin->w_cursor.col > 0 && (*(ml_get_cursor() - 1) == TAB || (*(ml_get_cursor() - 1) == ' ' && (!*inserted_space_p || arrow_used))))))



	{
	    int		ts;
	    colnr_T	vcol;
	    colnr_T	want_vcol;
	    colnr_T	start_vcol;

	    *inserted_space_p = FALSE;
	    
	    
	    
	    getvcol(curwin, &curwin->w_cursor, &vcol, NULL, NULL);
	    start_vcol = vcol;
	    dec_cursor();
	    getvcol(curwin, &curwin->w_cursor, NULL, NULL, &want_vcol);
	    inc_cursor();

	    if (p_sta && in_indent)
	    {
		ts = (int)get_sw_value(curbuf);
		want_vcol = (want_vcol / ts) * ts;
	    }
	    else want_vcol = tabstop_start(want_vcol, get_sts_value(), curbuf->b_p_vsts_array);


	    if (p_sta && in_indent)
		ts = (int)get_sw_value(curbuf);
	    else ts = (int)get_sts_value();
	    want_vcol = (want_vcol / ts) * ts;


	    
	    while (vcol > want_vcol && (cc = *(ml_get_cursor() - 1), VIM_ISWHITE(cc)))
		ins_bs_one(&vcol);

	    
	    while (vcol < want_vcol)
	    {
		
		if (curwin->w_cursor.lnum == Insstart_orig.lnum && curwin->w_cursor.col < Insstart_orig.col)
		    Insstart_orig.col = curwin->w_cursor.col;

		if (State & VREPLACE_FLAG)
		    ins_char(' ');
		else {
		    ins_str((char_u *)" ");
		    if ((State & REPLACE_FLAG))
			replace_push(NUL);
		}
		getvcol(curwin, &curwin->w_cursor, &vcol, NULL, NULL);
	    }

	    
	    
	    if (vcol >= start_vcol)
		ins_bs_one(&vcol);
	}

	
	else {
	    int cclass = 0, prev_cclass = 0;

	    if (has_mbyte)
		cclass = mb_get_class(ml_get_cursor());
	    do {

		if (!revins_on) 

		    dec_cursor();

		cc = gchar_cursor();
		
		if (has_mbyte)
		{
		    prev_cclass = cclass;
		    cclass = mb_get_class(ml_get_cursor());
		}

		
		if (mode == BACKSPACE_WORD && !vim_isspace(cc))
		{
		    mode = BACKSPACE_WORD_NOT_SPACE;
		    temp = vim_iswordc(cc);
		}
		
		else if (mode == BACKSPACE_WORD_NOT_SPACE && ((vim_isspace(cc) || vim_iswordc(cc) != temp)
			|| prev_cclass != cclass))
		{

		    if (!revins_on)

			inc_cursor();

		    else if (State & REPLACE_FLAG)
			dec_cursor();

		    break;
		}
		if (State & REPLACE_FLAG)
		    replace_do_bs(-1);
		else {
		    if (enc_utf8 && p_deco)
			(void)utfc_ptr2char(ml_get_cursor(), cpc);
		    (void)del_char(FALSE);
		    
		    if (enc_utf8 && p_deco && cpc[0] != NUL)
			inc_cursor();

		    if (revins_chars)
		    {
			revins_chars--;
			revins_legal++;
		    }
		    if (revins_on && gchar_cursor() == NUL)
			break;

		}
		
		if (mode == BACKSPACE_CHAR)
		    break;
	    } while (  revins_on ||  (curwin->w_cursor.col > mincol &&  (can_bs(BS_NOSTOP)




			|| (curwin->w_cursor.lnum != Insstart_orig.lnum || curwin->w_cursor.col != Insstart_orig.col)
		    )));
	}
	did_backspace = TRUE;
    }

    did_si = FALSE;
    can_si = FALSE;
    can_si_back = FALSE;

    if (curwin->w_cursor.col <= 1)
	did_ai = FALSE;


    if (call_fix_indent)
	fix_indent();


    
    AppendCharToRedobuff(c);

    
    if (curwin->w_cursor.lnum == Insstart_orig.lnum && curwin->w_cursor.col < Insstart_orig.col)
	Insstart_orig.col = curwin->w_cursor.col;

    
    
    
    
    
    
    
    if (vim_strchr(p_cpo, CPO_BACKSPACE) != NULL && dollar_vcol == -1)
	dollar_vcol = curwin->w_virtcol;


    
    
    
    if (did_backspace)
	foldOpenCursor();


    return did_backspace;
}


    int bracketed_paste(paste_mode_T mode, int drop, garray_T *gap)
{
    int		c;
    char_u	buf[NUMBUFLEN + MB_MAXBYTES];
    int		idx = 0;
    char_u	*end = find_termcode((char_u *)"PE");
    int		ret_char = -1;
    int		save_allow_keys = allow_keys;
    int		save_paste = p_paste;

    
    if (end != NULL && STRLEN(end) >= NUMBUFLEN)
	end = NULL;
    ++no_mapping;
    allow_keys = 0;
    if (!p_paste)
	
	
	set_option_value_give_err((char_u *)"paste", TRUE, NULL, 0);

    for (;;)
    {
	
	if (end == NULL && vpeekc() == NUL)
	    break;
	do c = vgetc();
	while (c == K_IGNORE || c == K_VER_SCROLLBAR || c == K_HOR_SCROLLBAR);
	if (c == NUL || got_int || (ex_normal_busy > 0 && c == Ctrl_C))
	    
	    
	    break;

	if (has_mbyte)
	    idx += (*mb_char2bytes)(c, buf + idx);
	else buf[idx++] = c;
	buf[idx] = NUL;
	if (end != NULL && STRNCMP(buf, end, idx) == 0)
	{
	    if (end[idx] == NUL)
		break; 
	    continue;
	}
	if (!drop)
	{
	    switch (mode)
	    {
		case PASTE_CMDLINE:
		    put_on_cmdline(buf, idx, TRUE);
		    break;

		case PASTE_EX:
		    
		    if (gap != NULL && ga_grow(gap, idx + 1) == OK)
		    {
			mch_memmove((char *)gap->ga_data + gap->ga_len, buf, (size_t)idx);
			gap->ga_len += idx;
		    }
		    break;

		case PASTE_INSERT:
		    if (stop_arrow() == OK)
		    {
			c = buf[0];
			if (idx == 1 && (c == CAR || c == K_KENTER || c == NL))
			    ins_eol(c);
			else {
			    ins_char_bytes(buf, idx);
			    AppendToRedobuffLit(buf, idx);
			}
		    }
		    break;

		case PASTE_ONE_CHAR:
		    if (ret_char == -1)
		    {
			if (has_mbyte)
			    ret_char = (*mb_ptr2char)(buf);
			else ret_char = buf[0];
		    }
		    break;
	    }
	}
	idx = 0;
    }

    --no_mapping;
    allow_keys = save_allow_keys;
    if (!save_paste)
	set_option_value_give_err((char_u *)"paste", FALSE, NULL, 0);

    return ret_char;
}


    static void ins_tabline(int c)
{
    
    if (c != K_TABMENU || current_tabmenu != TABLINE_MENU_CLOSE || (current_tab != 0 && current_tab != tabpage_index(curtab)))
    {
	undisplay_dollar();
	start_arrow(&curwin->w_cursor);

	can_cindent = TRUE;

    }

    if (c == K_TABLINE)
	goto_tabpage(current_tab);
    else {
	handle_tabmenu();
	redraw_statuslines();	
    }
}



    void ins_scroll(void)
{
    pos_T	tpos;

    undisplay_dollar();
    tpos = curwin->w_cursor;
    if (gui_do_scroll())
    {
	start_arrow(&tpos);

	can_cindent = TRUE;

    }
}

    void ins_horscroll(void)
{
    pos_T	tpos;

    undisplay_dollar();
    tpos = curwin->w_cursor;
    if (gui_do_horiz_scroll(scrollbar_value, FALSE))
    {
	start_arrow(&tpos);

	can_cindent = TRUE;

    }
}


    static void ins_left(void)
{
    pos_T	tpos;
    int		end_change = dont_sync_undo == FALSE; 


    if ((fdo_flags & FDO_HOR) && KeyTyped)
	foldOpenCursor();

    undisplay_dollar();
    tpos = curwin->w_cursor;
    if (oneleft() == OK)
    {

	
	
	if (p_imst == IM_OVER_THE_SPOT || !im_is_preediting())

	{
	    start_arrow_with_change(&tpos, end_change);
	    if (!end_change)
		AppendCharToRedobuff(K_LEFT);
	}

	
	if (revins_scol != -1 && (int)curwin->w_cursor.col >= revins_scol)
	    revins_legal++;
	revins_chars++;

    }

    
    else if (vim_strchr(p_ww, '[') != NULL && curwin->w_cursor.lnum > 1)
    {
	
	start_arrow(&tpos);
	--(curwin->w_cursor.lnum);
	coladvance((colnr_T)MAXCOL);
	curwin->w_set_curswant = TRUE;	
    }
    else vim_beep(BO_CRSR);
    dont_sync_undo = FALSE;
}

    static void ins_home(int c)
{
    pos_T	tpos;


    if ((fdo_flags & FDO_HOR) && KeyTyped)
	foldOpenCursor();

    undisplay_dollar();
    tpos = curwin->w_cursor;
    if (c == K_C_HOME)
	curwin->w_cursor.lnum = 1;
    curwin->w_cursor.col = 0;
    curwin->w_cursor.coladd = 0;
    curwin->w_curswant = 0;
    start_arrow(&tpos);
}

    static void ins_end(int c)
{
    pos_T	tpos;


    if ((fdo_flags & FDO_HOR) && KeyTyped)
	foldOpenCursor();

    undisplay_dollar();
    tpos = curwin->w_cursor;
    if (c == K_C_END)
	curwin->w_cursor.lnum = curbuf->b_ml.ml_line_count;
    coladvance((colnr_T)MAXCOL);
    curwin->w_curswant = MAXCOL;

    start_arrow(&tpos);
}

    static void ins_s_left()
{
    int end_change = dont_sync_undo == FALSE; 

    if ((fdo_flags & FDO_HOR) && KeyTyped)
	foldOpenCursor();

    undisplay_dollar();
    if (curwin->w_cursor.lnum > 1 || curwin->w_cursor.col > 0)
    {
	start_arrow_with_change(&curwin->w_cursor, end_change);
	if (!end_change)
	    AppendCharToRedobuff(K_S_LEFT);
	(void)bck_word(1L, FALSE, FALSE);
	curwin->w_set_curswant = TRUE;
    }
    else vim_beep(BO_CRSR);
    dont_sync_undo = FALSE;
}

    static void ins_right(void)
{
    int end_change = dont_sync_undo == FALSE; 


    if ((fdo_flags & FDO_HOR) && KeyTyped)
	foldOpenCursor();

    undisplay_dollar();
    if (gchar_cursor() != NUL || virtual_active())
    {
	start_arrow_with_change(&curwin->w_cursor, end_change);
	if (!end_change)
	    AppendCharToRedobuff(K_RIGHT);
	curwin->w_set_curswant = TRUE;
	if (virtual_active())
	    oneright();
	else {
	    if (has_mbyte)
		curwin->w_cursor.col += (*mb_ptr2len)(ml_get_cursor());
	    else ++curwin->w_cursor.col;
	}


	revins_legal++;
	if (revins_chars)
	    revins_chars--;

    }
    
    
    else if (vim_strchr(p_ww, ']') != NULL && curwin->w_cursor.lnum < curbuf->b_ml.ml_line_count)
    {
	start_arrow(&curwin->w_cursor);
	curwin->w_set_curswant = TRUE;
	++curwin->w_cursor.lnum;
	curwin->w_cursor.col = 0;
    }
    else vim_beep(BO_CRSR);
    dont_sync_undo = FALSE;
}

    static void ins_s_right()
{
    int end_change = dont_sync_undo == FALSE; 

    if ((fdo_flags & FDO_HOR) && KeyTyped)
	foldOpenCursor();

    undisplay_dollar();
    if (curwin->w_cursor.lnum < curbuf->b_ml.ml_line_count || gchar_cursor() != NUL)
    {
	start_arrow_with_change(&curwin->w_cursor, end_change);
	if (!end_change)
	    AppendCharToRedobuff(K_S_RIGHT);
	(void)fwd_word(1L, FALSE, 0);
	curwin->w_set_curswant = TRUE;
    }
    else vim_beep(BO_CRSR);
    dont_sync_undo = FALSE;
}

    static void ins_up( int		startcol)

{
    pos_T	tpos;
    linenr_T	old_topline = curwin->w_topline;

    int		old_topfill = curwin->w_topfill;


    undisplay_dollar();
    tpos = curwin->w_cursor;
    if (cursor_up(1L, TRUE) == OK)
    {
	if (startcol)
	    coladvance(getvcol_nolist(&Insstart));
	if (old_topline != curwin->w_topline  || old_topfill != curwin->w_topfill  )



	    redraw_later(VALID);
	start_arrow(&tpos);

	can_cindent = TRUE;

    }
    else vim_beep(BO_CRSR);
}

    static void ins_pageup(void)
{
    pos_T	tpos;

    undisplay_dollar();

    if (mod_mask & MOD_MASK_CTRL)
    {
	
	if (first_tabpage->tp_next != NULL)
	{
	    start_arrow(&curwin->w_cursor);
	    goto_tabpage(-1);
	}
	return;
    }

    tpos = curwin->w_cursor;
    if (onepage(BACKWARD, 1L) == OK)
    {
	start_arrow(&tpos);

	can_cindent = TRUE;

    }
    else vim_beep(BO_CRSR);
}

    static void ins_down( int		startcol)

{
    pos_T	tpos;
    linenr_T	old_topline = curwin->w_topline;

    int		old_topfill = curwin->w_topfill;


    undisplay_dollar();
    tpos = curwin->w_cursor;
    if (cursor_down(1L, TRUE) == OK)
    {
	if (startcol)
	    coladvance(getvcol_nolist(&Insstart));
	if (old_topline != curwin->w_topline  || old_topfill != curwin->w_topfill  )



	    redraw_later(VALID);
	start_arrow(&tpos);

	can_cindent = TRUE;

    }
    else vim_beep(BO_CRSR);
}

    static void ins_pagedown(void)
{
    pos_T	tpos;

    undisplay_dollar();

    if (mod_mask & MOD_MASK_CTRL)
    {
	
	if (first_tabpage->tp_next != NULL)
	{
	    start_arrow(&curwin->w_cursor);
	    goto_tabpage(0);
	}
	return;
    }

    tpos = curwin->w_cursor;
    if (onepage(FORWARD, 1L) == OK)
    {
	start_arrow(&tpos);

	can_cindent = TRUE;

    }
    else vim_beep(BO_CRSR);
}


    static void ins_drop(void)
{
    do_put('~', NULL, BACKWARD, 1L, PUT_CURSEND);
}



    static int ins_tab(void)
{
    int		ind;
    int		i;
    int		temp;

    if (Insstart_blank_vcol == MAXCOL && curwin->w_cursor.lnum == Insstart.lnum)
	Insstart_blank_vcol = get_nolist_virtcol();
    if (echeck_abbr(TAB + ABBR_OFF))
	return FALSE;

    ind = inindent(0);

    if (ind)
	can_cindent = FALSE;


    
    if (!curbuf->b_p_et  && !(p_sta && ind  && ((tabstop_count(curbuf->b_p_vts_array) > 1)



		    || (tabstop_count(curbuf->b_p_vts_array) == 1 && tabstop_first(curbuf->b_p_vts_array)
						       != get_sw_value(curbuf))
		    || (tabstop_count(curbuf->b_p_vts_array) == 0 && curbuf->b_p_ts != get_sw_value(curbuf))))
	    && tabstop_count(curbuf->b_p_vsts_array) == 0  && !(p_sta && ind && curbuf->b_p_ts != get_sw_value(curbuf))


	    && get_sts_value() == 0)
	return TRUE;

    if (stop_arrow() == FAIL)
	return TRUE;

    did_ai = FALSE;

    did_si = FALSE;
    can_si = FALSE;
    can_si_back = FALSE;

    AppendToRedobuff((char_u *)"\t");


    if (p_sta && ind)		
    {
	temp = (int)get_sw_value(curbuf);
	temp -= get_nolist_virtcol() % temp;
    }
    else if (tabstop_count(curbuf->b_p_vsts_array) > 0 || curbuf->b_p_sts != 0)
				
	temp = tabstop_padding(get_nolist_virtcol(), get_sts_value(), curbuf->b_p_vsts_array);
    else			 temp = tabstop_padding(get_nolist_virtcol(), curbuf->b_p_ts, curbuf->b_p_vts_array);


    if (p_sta && ind)		
	temp = (int)get_sw_value(curbuf);
    else if (curbuf->b_p_sts != 0) 
	temp = (int)get_sts_value();
    else			 temp = (int)curbuf->b_p_ts;
    temp -= get_nolist_virtcol() % temp;


    
    ins_char(' ');
    while (--temp > 0)
    {
	if (State & VREPLACE_FLAG)
	    ins_char(' ');
	else {
	    ins_str((char_u *)" ");
	    if (State & REPLACE_FLAG)	    
		replace_push(NUL);
	}
    }

    

    if (!curbuf->b_p_et && (tabstop_count(curbuf->b_p_vsts_array) > 0 || get_sts_value() > 0 || (p_sta && ind)))


    if (!curbuf->b_p_et && (get_sts_value() || (p_sta && ind)))

    {
	char_u		*ptr;
	char_u		*saved_line = NULL;	
	pos_T		pos;
	pos_T		fpos;
	pos_T		*cursor;
	colnr_T		want_vcol, vcol;
	int		change_col = -1;
	int		save_list = curwin->w_p_list;

	
	if (State & VREPLACE_FLAG)
	{
	    pos = curwin->w_cursor;
	    cursor = &pos;
	    saved_line = vim_strsave(ml_get_curline());
	    if (saved_line == NULL)
		return FALSE;
	    ptr = saved_line + pos.col;
	}
	else {
	    ptr = ml_get_cursor();
	    cursor = &curwin->w_cursor;
	}

	
	if (vim_strchr(p_cpo, CPO_LISTWM) == NULL)
	    curwin->w_p_list = FALSE;

	
	fpos = curwin->w_cursor;
	while (fpos.col > 0 && VIM_ISWHITE(ptr[-1]))
	{
	    --fpos.col;
	    --ptr;
	}

	
	if ((State & REPLACE_FLAG)
		&& fpos.lnum == Insstart.lnum && fpos.col < Insstart.col)
	{
	    ptr += Insstart.col - fpos.col;
	    fpos.col = Insstart.col;
	}

	
	getvcol(curwin, &fpos, &vcol, NULL, NULL);
	getvcol(curwin, cursor, &want_vcol, NULL, NULL);

	
	
	while (VIM_ISWHITE(*ptr))
	{
	    i = lbr_chartabsize(NULL, (char_u *)"\t", vcol);
	    if (vcol + i > want_vcol)
		break;
	    if (*ptr != TAB)
	    {
		*ptr = TAB;
		if (change_col < 0)
		{
		    change_col = fpos.col;  
		    
		    if (fpos.lnum == Insstart.lnum && fpos.col < Insstart.col)
			Insstart.col = fpos.col;
		}
	    }
	    ++fpos.col;
	    ++ptr;
	    vcol += i;
	}

	if (change_col >= 0)
	{
	    int repl_off = 0;
	    char_u *line = ptr;

	    
	    while (vcol < want_vcol && *ptr == ' ')
	    {
		vcol += lbr_chartabsize(line, ptr, vcol);
		++ptr;
		++repl_off;
	    }
	    if (vcol > want_vcol)
	    {
		
		--ptr;
		--repl_off;
	    }
	    fpos.col += repl_off;

	    
	    i = cursor->col - fpos.col;
	    if (i > 0)
	    {

		if (!(State & VREPLACE_FLAG))
		{
		    char_u  *newp;
		    int	    col;

		    newp = alloc(curbuf->b_ml.ml_line_len - i);
		    if (newp == NULL)
			return FALSE;

		    col = ptr - curbuf->b_ml.ml_line_ptr;
		    if (col > 0)
			mch_memmove(newp, ptr - col, col);
		    mch_memmove(newp + col, ptr + i, curbuf->b_ml.ml_line_len - col - i);

		    if (curbuf->b_ml.ml_flags & ML_LINE_DIRTY)
			vim_free(curbuf->b_ml.ml_line_ptr);
		    curbuf->b_ml.ml_line_ptr = newp;
		    curbuf->b_ml.ml_line_len -= i;
		    curbuf->b_ml.ml_flags = (curbuf->b_ml.ml_flags | ML_LINE_DIRTY) & ~ML_EMPTY;
		}
		else  STRMOVE(ptr, ptr + i);

		
		if ((State & REPLACE_FLAG) && !(State & VREPLACE_FLAG))
		    for (temp = i; --temp >= 0; )
			replace_join(repl_off);
	    }

	    if (netbeans_active())
	    {
		netbeans_removed(curbuf, fpos.lnum, cursor->col, (long)(i + 1));
		netbeans_inserted(curbuf, fpos.lnum, cursor->col, (char_u *)"\t", 1);
	    }

	    cursor->col -= i;

	    
	    if (State & VREPLACE_FLAG)
	    {
		
		backspace_until_column(change_col);

		
		
		ins_bytes_len(saved_line + change_col, cursor->col - change_col);
	    }
	}

	if (State & VREPLACE_FLAG)
	    vim_free(saved_line);
	curwin->w_p_list = save_list;
    }

    return FALSE;
}


    int ins_eol(int c)
{
    int	    i;

    if (echeck_abbr(c + ABBR_OFF))
	return OK;
    if (stop_arrow() == FAIL)
	return FAIL;
    undisplay_dollar();

    
    if ((State & REPLACE_FLAG) && !(State & VREPLACE_FLAG))
	replace_push(NUL);

    

    
    
    if (virtual_active() && curwin->w_cursor.coladd > 0)
	coladvance(getviscol());


    
    
    if (revins_on)
	curwin->w_cursor.col += (colnr_T)STRLEN(ml_get_cursor());


    AppendToRedobuff(NL_STR);
    i = open_line(FORWARD, has_format_option(FO_RET_COMS) ? OPENLINE_DO_COM : 0, old_indent, NULL);

    old_indent = 0;

    can_cindent = TRUE;


    
    foldOpenCursor();


    return i;
}



    static int ins_digraph(void)
{
    int	    c;
    int	    cc;
    int	    did_putchar = FALSE;

    pc_status = PC_STATUS_UNSET;
    if (redrawing() && !char_avail())
    {
	
	ins_redraw(FALSE);

	edit_putchar('?', TRUE);
	did_putchar = TRUE;

	add_to_showcmd_c(Ctrl_K);

    }


    dont_scroll = TRUE;		


    
    
    ++no_mapping;
    ++allow_keys;
    c = plain_vgetc();
    --no_mapping;
    --allow_keys;
    if (did_putchar)
	
	
	edit_unputchar();

    if (IS_SPECIAL(c) || mod_mask)	    
    {

	clear_showcmd();

	insert_special(c, TRUE, FALSE);
	return NUL;
    }
    if (c != ESC)
    {
	did_putchar = FALSE;
	if (redrawing() && !char_avail())
	{
	    
	    ins_redraw(FALSE);

	    if (char2cells(c) == 1)
	    {
		ins_redraw(FALSE);
		edit_putchar(c, TRUE);
		did_putchar = TRUE;
	    }

	    add_to_showcmd_c(c);

	}
	++no_mapping;
	++allow_keys;
	cc = plain_vgetc();
	--no_mapping;
	--allow_keys;
	if (did_putchar)
	    
	    
	    edit_unputchar();
	if (cc != ESC)
	{
	    AppendToRedobuff((char_u *)CTRL_V_STR);
	    c = digraph_get(c, cc, TRUE);

	    clear_showcmd();

	    return c;
	}
    }

    clear_showcmd();

    return NUL;
}



    int ins_copychar(linenr_T lnum)
{
    int	    c;
    int	    temp;
    char_u  *ptr, *prev_ptr;
    char_u  *line;

    if (lnum < 1 || lnum > curbuf->b_ml.ml_line_count)
    {
	vim_beep(BO_COPY);
	return NUL;
    }

    
    temp = 0;
    line = ptr = ml_get(lnum);
    prev_ptr = ptr;
    validate_virtcol();
    while ((colnr_T)temp < curwin->w_virtcol && *ptr != NUL)
    {
	prev_ptr = ptr;
	temp += lbr_chartabsize_adv(line, &ptr, (colnr_T)temp);
    }
    if ((colnr_T)temp > curwin->w_virtcol)
	ptr = prev_ptr;

    c = (*mb_ptr2char)(ptr);
    if (c == NUL)
	vim_beep(BO_COPY);
    return c;
}


    static int ins_ctrl_ey(int tc)
{
    int	    c = tc;

    if (ctrl_x_mode_scroll())
    {
	if (c == Ctrl_Y)
	    scrolldown_clamp();
	else scrollup_clamp();
	redraw_later(VALID);
    }
    else {
	c = ins_copychar(curwin->w_cursor.lnum + (c == Ctrl_Y ? -1 : 1));
	if (c != NUL)
	{
	    long	tw_save;

	    
	    
	    
	    
	    if (c < 256 && !isalnum(c))
		AppendToRedobuff((char_u *)CTRL_V_STR);	
	    tw_save = curbuf->b_p_tw;
	    curbuf->b_p_tw = -1;
	    insert_special(c, TRUE, FALSE);
	    curbuf->b_p_tw = tw_save;

	    revins_chars++;
	    revins_legal++;

	    c = Ctrl_V;	
	    auto_format(FALSE, TRUE);
	}
    }
    return c;
}


    colnr_T get_nolist_virtcol(void)
{
    
    if (curwin->w_buffer == NULL || curwin->w_buffer->b_ml.ml_mfp == NULL || curwin->w_cursor.lnum > curwin->w_buffer->b_ml.ml_line_count)

	return 0;
    if (curwin->w_p_list && vim_strchr(p_cpo, CPO_LISTWM) == NULL)
	return getvcol_nolist(&curwin->w_cursor);
    validate_virtcol();
    return curwin->w_virtcol;
}



    static char_u * do_insert_char_pre(int c)
{
    char_u	*res;
    char_u	buf[MB_MAXBYTES + 1];
    int		save_State = State;

    
    if (!has_insertcharpre())
	return NULL;

    if (has_mbyte)
	buf[(*mb_char2bytes)(c, buf)] = NUL;
    else {
	buf[0] = c;
	buf[1] = NUL;
    }

    
    ++textwinlock;
    set_vim_var_string(VV_CHAR, buf, -1);  

    res = NULL;
    if (ins_apply_autocmds(EVENT_INSERTCHARPRE))
    {
	
	
	
	if (STRCMP(buf, get_vim_var_str(VV_CHAR)) != 0)
	    res = vim_strsave(get_vim_var_str(VV_CHAR));
    }

    set_vim_var_string(VV_CHAR, NULL, -1);  
    --textwinlock;

    
    State = save_State;

    return res;
}



    int get_can_cindent(void)
{
    return can_cindent;
}

    void set_can_cindent(int val)
{
    can_cindent = val;
}



    int ins_apply_autocmds(event_T event)
{
    varnumber_T	tick = CHANGEDTICK(curbuf);
    int r;

    r = apply_autocmds(event, NULL, NULL, FALSE, curbuf);

    
    
    
    if (event != EVENT_INSERTLEAVE && tick != CHANGEDTICK(curbuf))
	u_save(curwin->w_cursor.lnum, (linenr_T)(curwin->w_cursor.lnum + 1));

    return r;
}
