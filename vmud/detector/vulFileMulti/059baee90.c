




static int	VIsual_mode_orig = NUL;		


static void	set_vcount_ca(cmdarg_T *cap, int *set_prevcount);

static int	nv_compare(const void *s1, const void *s2);
static void	unshift_special(cmdarg_T *cap);

static void	del_from_showcmd(int);



static void	nv_ignore(cmdarg_T *cap);
static void	nv_nop(cmdarg_T *cap);
static void	nv_error(cmdarg_T *cap);
static void	nv_help(cmdarg_T *cap);
static void	nv_addsub(cmdarg_T *cap);
static void	nv_page(cmdarg_T *cap);
static void	nv_zet(cmdarg_T *cap);

static void	nv_ver_scrollbar(cmdarg_T *cap);
static void	nv_hor_scrollbar(cmdarg_T *cap);


static void	nv_tabline(cmdarg_T *cap);
static void	nv_tabmenu(cmdarg_T *cap);

static void	nv_exmode(cmdarg_T *cap);
static void	nv_colon(cmdarg_T *cap);
static void	nv_ctrlg(cmdarg_T *cap);
static void	nv_ctrlh(cmdarg_T *cap);
static void	nv_clear(cmdarg_T *cap);
static void	nv_ctrlo(cmdarg_T *cap);
static void	nv_hat(cmdarg_T *cap);
static void	nv_Zet(cmdarg_T *cap);
static void	nv_ident(cmdarg_T *cap);
static void	nv_tagpop(cmdarg_T *cap);
static void	nv_scroll(cmdarg_T *cap);
static void	nv_right(cmdarg_T *cap);
static void	nv_left(cmdarg_T *cap);
static void	nv_up(cmdarg_T *cap);
static void	nv_down(cmdarg_T *cap);
static void	nv_end(cmdarg_T *cap);
static void	nv_dollar(cmdarg_T *cap);
static void	nv_search(cmdarg_T *cap);
static void	nv_next(cmdarg_T *cap);
static int	normal_search(cmdarg_T *cap, int dir, char_u *pat, int opt, int *wrapped);
static void	nv_csearch(cmdarg_T *cap);
static void	nv_brackets(cmdarg_T *cap);
static void	nv_percent(cmdarg_T *cap);
static void	nv_brace(cmdarg_T *cap);
static void	nv_mark(cmdarg_T *cap);
static void	nv_findpar(cmdarg_T *cap);
static void	nv_undo(cmdarg_T *cap);
static void	nv_kundo(cmdarg_T *cap);
static void	nv_Replace(cmdarg_T *cap);
static void	nv_replace(cmdarg_T *cap);
static void	nv_cursormark(cmdarg_T *cap, int flag, pos_T *pos);
static void	v_visop(cmdarg_T *cap);
static void	nv_subst(cmdarg_T *cap);
static void	nv_abbrev(cmdarg_T *cap);
static void	nv_optrans(cmdarg_T *cap);
static void	nv_gomark(cmdarg_T *cap);
static void	nv_pcmark(cmdarg_T *cap);
static void	nv_regname(cmdarg_T *cap);
static void	nv_visual(cmdarg_T *cap);
static void	n_start_visual_mode(int c);
static void	nv_window(cmdarg_T *cap);
static void	nv_suspend(cmdarg_T *cap);
static void	nv_g_cmd(cmdarg_T *cap);
static void	nv_dot(cmdarg_T *cap);
static void	nv_redo(cmdarg_T *cap);
static void	nv_Undo(cmdarg_T *cap);
static void	nv_tilde(cmdarg_T *cap);
static void	nv_operator(cmdarg_T *cap);

static void	set_op_var(int optype);

static void	nv_lineop(cmdarg_T *cap);
static void	nv_home(cmdarg_T *cap);
static void	nv_pipe(cmdarg_T *cap);
static void	nv_bck_word(cmdarg_T *cap);
static void	nv_wordcmd(cmdarg_T *cap);
static void	nv_beginline(cmdarg_T *cap);
static void	adjust_cursor(oparg_T *oap);
static void	adjust_for_sel(cmdarg_T *cap);
static void	nv_select(cmdarg_T *cap);
static void	nv_goto(cmdarg_T *cap);
static void	nv_normal(cmdarg_T *cap);
static void	nv_esc(cmdarg_T *oap);
static void	nv_edit(cmdarg_T *cap);
static void	invoke_edit(cmdarg_T *cap, int repl, int cmd, int startln);

static void	nv_object(cmdarg_T *cap);

static void	nv_record(cmdarg_T *cap);
static void	nv_at(cmdarg_T *cap);
static void	nv_halfpage(cmdarg_T *cap);
static void	nv_join(cmdarg_T *cap);
static void	nv_put(cmdarg_T *cap);
static void	nv_put_opt(cmdarg_T *cap, int fix_indent);
static void	nv_open(cmdarg_T *cap);

static void	nv_nbcmd(cmdarg_T *cap);


static void	nv_drop(cmdarg_T *cap);

static void	nv_cursorhold(cmdarg_T *cap);

static char *e_noident = N_("E349: No identifier under cursor");


typedef void (*nv_func_T)(cmdarg_T *cap);

















static const struct nv_cmd {
    int		cmd_char;	
    nv_func_T   cmd_func;	
    short_u	cmd_flags;	
    short	cmd_arg;	
} nv_cmds[] = {
    {NUL,	nv_error,	0,			0}, {Ctrl_A,	nv_addsub,	0,			0}, {Ctrl_B,	nv_page,	NV_STS,			BACKWARD}, {Ctrl_C,	nv_esc,		0,			TRUE}, {Ctrl_D,	nv_halfpage,	0,			0}, {Ctrl_E,	nv_scroll_line,	0,			TRUE}, {Ctrl_F,	nv_page,	NV_STS,			FORWARD}, {Ctrl_G,	nv_ctrlg,	0,			0}, {Ctrl_H,	nv_ctrlh,	0,			0}, {Ctrl_I,	nv_pcmark,	0,			0}, {NL,	nv_down,	0,			FALSE}, {Ctrl_K,	nv_error,	0,			0}, {Ctrl_L,	nv_clear,	0,			0}, {CAR,	nv_down,	0,			TRUE}, {Ctrl_N,	nv_down,	NV_STS,			FALSE}, {Ctrl_O,	nv_ctrlo,	0,			0}, {Ctrl_P,	nv_up,		NV_STS,			FALSE}, {Ctrl_Q,	nv_visual,	0,			FALSE}, {Ctrl_R,	nv_redo,	0,			0}, {Ctrl_S,	nv_ignore,	0,			0}, {Ctrl_T,	nv_tagpop,	NV_NCW,			0}, {Ctrl_U,	nv_halfpage,	0,			0}, {Ctrl_V,	nv_visual,	0,			FALSE}, {'V',	nv_visual,	0,			FALSE}, {'v',	nv_visual,	0,			FALSE}, {Ctrl_W,	nv_window,	0,			0}, {Ctrl_X,	nv_addsub,	0,			0}, {Ctrl_Y,	nv_scroll_line,	0,			FALSE}, {Ctrl_Z,	nv_suspend,	0,			0}, {ESC,	nv_esc,		0,			FALSE}, {Ctrl_BSL,	nv_normal,	NV_NCH_ALW,		0}, {Ctrl_RSB,	nv_ident,	NV_NCW,			0}, {Ctrl_HAT,	nv_hat,		NV_NCW,			0}, {Ctrl__,	nv_error,	0,			0}, {' ',	nv_right,	0,			0}, {'!',	nv_operator,	0,			0}, {'"',	nv_regname,	NV_NCH_NOP|NV_KEEPREG,	0}, {'#',	nv_ident,	0,			0}, {'$',	nv_dollar,	0,			0}, {'%',	nv_percent,	0,			0}, {'&',	nv_optrans,	0,			0}, {'\'',	nv_gomark,	NV_NCH_ALW,		TRUE}, {'(',	nv_brace,	0,			BACKWARD}, {')',	nv_brace,	0,			FORWARD}, {'*',	nv_ident,	0,			0}, {'+',	nv_down,	0,			TRUE}, {',',	nv_csearch,	0,			TRUE}, {'-',	nv_up,		0,			TRUE}, {'.',	nv_dot,		NV_KEEPREG,		0}, {'/',	nv_search,	0,			FALSE}, {'0',	nv_beginline,	0,			0}, {'1',	nv_ignore,	0,			0}, {'2',	nv_ignore,	0,			0}, {'3',	nv_ignore,	0,			0}, {'4',	nv_ignore,	0,			0}, {'5',	nv_ignore,	0,			0}, {'6',	nv_ignore,	0,			0}, {'7',	nv_ignore,	0,			0}, {'8',	nv_ignore,	0,			0}, {'9',	nv_ignore,	0,			0}, {':',	nv_colon,	0,			0}, {';',	nv_csearch,	0,			FALSE}, {'<',	nv_operator,	NV_RL,			0}, {'=',	nv_operator,	0,			0}, {'>',	nv_operator,	NV_RL,			0}, {'?',	nv_search,	0,			FALSE}, {'@',	nv_at,		NV_NCH_NOP,		FALSE}, {'A',	nv_edit,	0,			0}, {'B',	nv_bck_word,	0,			1}, {'C',	nv_abbrev,	NV_KEEPREG,		0}, {'D',	nv_abbrev,	NV_KEEPREG,		0}, {'E',	nv_wordcmd,	0,			TRUE}, {'F',	nv_csearch,	NV_NCH_ALW|NV_LANG,	BACKWARD}, {'G',	nv_goto,	0,			TRUE}, {'H',	nv_scroll,	0,			0}, {'I',	nv_edit,	0,			0}, {'J',	nv_join,	0,			0}, {'K',	nv_ident,	0,			0}, {'L',	nv_scroll,	0,			0}, {'M',	nv_scroll,	0,			0}, {'N',	nv_next,	0,			SEARCH_REV}, {'O',	nv_open,	0,			0}, {'P',	nv_put,		0,			0}, {'Q',	nv_exmode,	NV_NCW,			0}, {'R',	nv_Replace,	0,			FALSE}, {'S',	nv_subst,	NV_KEEPREG,		0}, {'T',	nv_csearch,	NV_NCH_ALW|NV_LANG,	BACKWARD}, {'U',	nv_Undo,	0,			0}, {'W',	nv_wordcmd,	0,			TRUE}, {'X',	nv_abbrev,	NV_KEEPREG,		0}, {'Y',	nv_abbrev,	NV_KEEPREG,		0}, {'Z',	nv_Zet,		NV_NCH_NOP|NV_NCW,	0}, {'[',	nv_brackets,	NV_NCH_ALW,		BACKWARD}, {'\\',	nv_error,	0,			0}, {']',	nv_brackets,	NV_NCH_ALW,		FORWARD}, {'^',	nv_beginline,	0,			BL_WHITE | BL_FIX}, {'_',	nv_lineop,	0,			0}, {'`',	nv_gomark,	NV_NCH_ALW,		FALSE}, {'a',	nv_edit,	NV_NCH,			0}, {'b',	nv_bck_word,	0,			0}, {'c',	nv_operator,	0,			0}, {'d',	nv_operator,	0,			0}, {'e',	nv_wordcmd,	0,			FALSE}, {'f',	nv_csearch,	NV_NCH_ALW|NV_LANG,	FORWARD}, {'g',	nv_g_cmd,	NV_NCH_ALW,		FALSE}, {'h',	nv_left,	NV_RL,			0}, {'i',	nv_edit,	NV_NCH,			0}, {'j',	nv_down,	0,			FALSE}, {'k',	nv_up,		0,			FALSE}, {'l',	nv_right,	NV_RL,			0}, {'m',	nv_mark,	NV_NCH_NOP,		0}, {'n',	nv_next,	0,			0}, {'o',	nv_open,	0,			0}, {'p',	nv_put,		0,			0}, {'q',	nv_record,	NV_NCH,			0}, {'r',	nv_replace,	NV_NCH_NOP|NV_LANG,	0}, {'s',	nv_subst,	NV_KEEPREG,		0}, {'t',	nv_csearch,	NV_NCH_ALW|NV_LANG,	FORWARD}, {'u',	nv_undo,	0,			0}, {'w',	nv_wordcmd,	0,			FALSE}, {'x',	nv_abbrev,	NV_KEEPREG,		0}, {'y',	nv_operator,	0,			0}, {'z',	nv_zet,		NV_NCH_ALW,		0}, {'{',	nv_findpar,	0,			BACKWARD}, {'|',	nv_pipe,	0,			0}, {'}',	nv_findpar,	0,			FORWARD}, {'~',	nv_tilde,	0,			0},   {POUND,	nv_ident,	0,			0}, {K_MOUSEUP, nv_mousescroll,	0,			MSCR_UP}, {K_MOUSEDOWN, nv_mousescroll, 0,			MSCR_DOWN}, {K_MOUSELEFT, nv_mousescroll, 0,			MSCR_LEFT}, {K_MOUSERIGHT, nv_mousescroll, 0,			MSCR_RIGHT}, {K_LEFTMOUSE, nv_mouse,	0,			0}, {K_LEFTMOUSE_NM, nv_mouse,	0,			0}, {K_LEFTDRAG, nv_mouse,	0,			0}, {K_LEFTRELEASE, nv_mouse,	0,			0}, {K_LEFTRELEASE_NM, nv_mouse, 0,			0}, {K_MOUSEMOVE, nv_mouse,	0,			0}, {K_MIDDLEMOUSE, nv_mouse,	0,			0}, {K_MIDDLEDRAG, nv_mouse,	0,			0}, {K_MIDDLERELEASE, nv_mouse,	0,			0}, {K_RIGHTMOUSE, nv_mouse,	0,			0}, {K_RIGHTDRAG, nv_mouse,	0,			0}, {K_RIGHTRELEASE, nv_mouse,	0,			0}, {K_X1MOUSE, nv_mouse,	0,			0}, {K_X1DRAG, nv_mouse,	0,			0}, {K_X1RELEASE, nv_mouse,	0,			0}, {K_X2MOUSE, nv_mouse,	0,			0}, {K_X2DRAG, nv_mouse,	0,			0}, {K_X2RELEASE, nv_mouse,	0,			0}, {K_IGNORE,	nv_ignore,	NV_KEEPREG,		0}, {K_NOP,	nv_nop,		0,			0}, {K_INS,	nv_edit,	0,			0}, {K_KINS,	nv_edit,	0,			0}, {K_BS,	nv_ctrlh,	0,			0}, {K_UP,	nv_up,		NV_SSS|NV_STS,		FALSE}, {K_S_UP,	nv_page,	NV_SS,			BACKWARD}, {K_DOWN,	nv_down,	NV_SSS|NV_STS,		FALSE}, {K_S_DOWN,	nv_page,	NV_SS,			FORWARD}, {K_LEFT,	nv_left,	NV_SSS|NV_STS|NV_RL,	0}, {K_S_LEFT,	nv_bck_word,	NV_SS|NV_RL,		0}, {K_C_LEFT,	nv_bck_word,	NV_SSS|NV_RL|NV_STS,	1}, {K_RIGHT,	nv_right,	NV_SSS|NV_STS|NV_RL,	0}, {K_S_RIGHT,	nv_wordcmd,	NV_SS|NV_RL,		FALSE}, {K_C_RIGHT,	nv_wordcmd,	NV_SSS|NV_RL|NV_STS,	TRUE}, {K_PAGEUP,	nv_page,	NV_SSS|NV_STS,		BACKWARD}, {K_KPAGEUP,	nv_page,	NV_SSS|NV_STS,		BACKWARD}, {K_PAGEDOWN, nv_page,	NV_SSS|NV_STS,		FORWARD}, {K_KPAGEDOWN, nv_page,	NV_SSS|NV_STS,		FORWARD}, {K_END,	nv_end,		NV_SSS|NV_STS,		FALSE}, {K_KEND,	nv_end,		NV_SSS|NV_STS,		FALSE}, {K_S_END,	nv_end,		NV_SS,			FALSE}, {K_C_END,	nv_end,		NV_SSS|NV_STS,		TRUE}, {K_HOME,	nv_home,	NV_SSS|NV_STS,		0}, {K_KHOME,	nv_home,	NV_SSS|NV_STS,		0}, {K_S_HOME,	nv_home,	NV_SS,			0}, {K_C_HOME,	nv_goto,	NV_SSS|NV_STS,		FALSE}, {K_DEL,	nv_abbrev,	0,			0}, {K_KDEL,	nv_abbrev,	0,			0}, {K_UNDO,	nv_kundo,	0,			0}, {K_HELP,	nv_help,	NV_NCW,			0}, {K_F1,	nv_help,	NV_NCW,			0}, {K_XF1,	nv_help,	NV_NCW,			0}, {K_SELECT,	nv_select,	0,			0},  {K_VER_SCROLLBAR, nv_ver_scrollbar, 0,		0}, {K_HOR_SCROLLBAR, nv_hor_scrollbar, 0,		0},   {K_TABLINE, nv_tabline,	0,			0}, {K_TABMENU, nv_tabmenu,	0,			0},   {K_F21,	nv_nbcmd,	NV_NCH_ALW,		0},   {K_DROP,	nv_drop,	NV_STS,			0},  {K_CURSORHOLD, nv_cursorhold, NV_KEEPREG,		0}, {K_PS,	nv_edit,	0,			0}, {K_COMMAND,	nv_colon,	0,			0}, };















































































































































































































static short nv_cmd_idx[NV_CMDS_SIZE];



static int nv_max_linear;


    static int nv_compare(const void *s1, const void *s2)
{
    int		c1, c2;

    
    c1 = nv_cmds[*(const short *)s1].cmd_char;
    c2 = nv_cmds[*(const short *)s2].cmd_char;
    if (c1 < 0)
	c1 = -c1;
    if (c2 < 0)
	c2 = -c2;
    return c1 - c2;
}


    void init_normal_cmds(void)
{
    int		i;

    
    for (i = 0; i < (int)NV_CMDS_SIZE; ++i)
	nv_cmd_idx[i] = i;

    
    qsort((void *)&nv_cmd_idx, (size_t)NV_CMDS_SIZE, sizeof(short), nv_compare);

    
    for (i = 0; i < (int)NV_CMDS_SIZE; ++i)
	if (i != nv_cmds[nv_cmd_idx[i]].cmd_char)
	    break;
    nv_max_linear = i - 1;
}


    static int find_command(int cmdchar)
{
    int		i;
    int		idx;
    int		top, bot;
    int		c;

    
    if (cmdchar >= 0x100)
	return -1;

    
    
    if (cmdchar < 0)
	cmdchar = -cmdchar;

    
    
    if (cmdchar <= nv_max_linear)
	return nv_cmd_idx[cmdchar];

    
    bot = nv_max_linear + 1;
    top = NV_CMDS_SIZE - 1;
    idx = -1;
    while (bot <= top)
    {
	i = (top + bot) / 2;
	c = nv_cmds[nv_cmd_idx[i]].cmd_char;
	if (c < 0)
	    c = -c;
	if (cmdchar == c)
	{
	    idx = nv_cmd_idx[i];
	    break;
	}
	if (cmdchar > c)
	    bot = i + 1;
	else top = i - 1;
    }
    return idx;
}


    void normal_cmd( oparg_T	*oap, int		toplevel UNUSED)


{
    cmdarg_T	ca;			
    int		c;
    int		ctrl_w = FALSE;		
    int		old_col = curwin->w_curswant;

    int		need_flushbuf;		

    pos_T	old_pos;		
    int		mapped_len;
    static int	old_mapped_len = 0;
    int		idx;

    int		set_prevcount = FALSE;

    int		save_did_cursorhold = did_cursorhold;

    CLEAR_FIELD(ca);	
    ca.oap = oap;

    
    
    
    ca.opcount = opcount;

    

    c = finish_op;

    finish_op = (oap->op_type != OP_NOP);

    if (finish_op != c)
    {
	ui_cursor_shape();		

	update_mouseshape(-1);

    }

    trigger_modechanged();

    
    
    if (!finish_op && !oap->regname)
    {
	ca.opcount = 0;

	set_prevcount = TRUE;

    }

    
    
    
    if (oap->prev_opcount > 0 || oap->prev_count0 > 0)
    {
	ca.opcount = oap->prev_opcount;
	ca.count0 = oap->prev_count0;
	oap->prev_opcount = 0;
	oap->prev_count0 = 0;
    }

    mapped_len = typebuf_maplen();

    State = NORMAL_BUSY;

    dont_scroll = FALSE;	



    
    
    
    if (toplevel && readbuf1_empty())
	set_vcount_ca(&ca, &set_prevcount);


    
    c = safe_vgetc();
    LANGMAP_ADJUST(c, get_real_state() != SELECTMODE);

    
    if (restart_edit == 0)
	old_mapped_len = 0;
    else if (old_mapped_len || (VIsual_active && mapped_len == 0 && typebuf_maplen() > 0))
	old_mapped_len = typebuf_maplen();

    if (c == NUL)
	c = K_ZERO;

    
    if (VIsual_active && VIsual_select && (vim_isprintc(c) || c == NL || c == CAR || c == K_KENTER))

    {
	
	
	
	
	
	ins_char_typebuf(vgetc_char, vgetc_mod_mask);
	if (restart_edit != 0)
	    c = 'd';
	else c = 'c';
	msg_nowait = TRUE;	
	old_mapped_len = 0;	
    }


    need_flushbuf = add_to_showcmd(c);


getcount:
    if (!(VIsual_active && VIsual_select))
    {
	
	while (    (c >= '1' && c <= '9')
		|| (ca.count0 != 0 && (c == K_DEL || c == K_KDEL || c == '0')))
	{
	    if (c == K_DEL || c == K_KDEL)
	    {
		ca.count0 /= 10;

		del_from_showcmd(4);	

	    }
	    else ca.count0 = ca.count0 * 10 + (c - '0');
	    if (ca.count0 < 0)	    
		ca.count0 = 999999999L;

	    
	    
	    
	    if (toplevel && readbuf1_empty())
		set_vcount_ca(&ca, &set_prevcount);

	    if (ctrl_w)
	    {
		++no_mapping;
		++allow_keys;		
	    }
	    ++no_zero_mapping;		
	    c = plain_vgetc();
	    LANGMAP_ADJUST(c, TRUE);
	    --no_zero_mapping;
	    if (ctrl_w)
	    {
		--no_mapping;
		--allow_keys;
	    }

	    need_flushbuf |= add_to_showcmd(c);

	}

	
	if (c == Ctrl_W && !ctrl_w && oap->op_type == OP_NOP)
	{
	    ctrl_w = TRUE;
	    ca.opcount = ca.count0;	
	    ca.count0 = 0;
	    ++no_mapping;
	    ++allow_keys;		
	    c = plain_vgetc();		
	    LANGMAP_ADJUST(c, TRUE);
	    --no_mapping;
	    --allow_keys;

	    need_flushbuf |= add_to_showcmd(c);

	    goto getcount;		
	}
    }

    if (c == K_CURSORHOLD)
    {
	
	
	oap->prev_opcount = ca.opcount;
	oap->prev_count0 = ca.count0;
    }
    else if (ca.opcount != 0)
    {
	
	if (ca.count0)
	    ca.count0 *= ca.opcount;
	else ca.count0 = ca.opcount;
	if (ca.count0 < 0)	    
	    ca.count0 = 999999999L;
    }

    
    ca.opcount = ca.count0;
    ca.count1 = (ca.count0 == 0 ? 1 : ca.count0);


    
    if (toplevel && readbuf1_empty())
	set_vcount(ca.count0, ca.count1, set_prevcount);


    
    if (ctrl_w)
    {
	ca.nchar = c;
	ca.cmdchar = Ctrl_W;
    }
    else ca.cmdchar = c;
    idx = find_command(ca.cmdchar);
    if (idx < 0)
    {
	
	clearopbeep(oap);
	goto normal_end;
    }

    if (text_locked() && (nv_cmds[idx].cmd_flags & NV_NCW))
    {
	
	clearopbeep(oap);
	text_locked_msg();
	goto normal_end;
    }
    if ((nv_cmds[idx].cmd_flags & NV_NCW) && curbuf_locked())
	goto normal_end;

    
    if (VIsual_active)
    {
	
	if (km_stopsel && (nv_cmds[idx].cmd_flags & NV_STS)
		&& !(mod_mask & MOD_MASK_SHIFT))
	{
	    end_visual_mode();
	    redraw_curbuf_later(INVERTED);
	}

	
	if (km_startsel)
	{
	    if (nv_cmds[idx].cmd_flags & NV_SS)
	    {
		unshift_special(&ca);
		idx = find_command(ca.cmdchar);
		if (idx < 0)
		{
		    
		    clearopbeep(oap);
		    goto normal_end;
		}
	    }
	    else if ((nv_cmds[idx].cmd_flags & NV_SSS)
					       && (mod_mask & MOD_MASK_SHIFT))
		mod_mask &= ~MOD_MASK_SHIFT;
	}
    }


    if (curwin->w_p_rl && KeyTyped && !KeyStuffed && (nv_cmds[idx].cmd_flags & NV_RL))
    {
	
	
	
	switch (ca.cmdchar)
	{
	    case 'l':	    ca.cmdchar = 'h'; break;
	    case K_RIGHT:   ca.cmdchar = K_LEFT; break;
	    case K_S_RIGHT: ca.cmdchar = K_S_LEFT; break;
	    case K_C_RIGHT: ca.cmdchar = K_C_LEFT; break;
	    case 'h':	    ca.cmdchar = 'l'; break;
	    case K_LEFT:    ca.cmdchar = K_RIGHT; break;
	    case K_S_LEFT:  ca.cmdchar = K_S_RIGHT; break;
	    case K_C_LEFT:  ca.cmdchar = K_C_RIGHT; break;
	    case '>':	    ca.cmdchar = '<'; break;
	    case '<':	    ca.cmdchar = '>'; break;
	}
	idx = find_command(ca.cmdchar);
    }


    
    if ((nv_cmds[idx].cmd_flags & NV_NCH)
	    && (((nv_cmds[idx].cmd_flags & NV_NCH_NOP) == NV_NCH_NOP && oap->op_type == OP_NOP)
		|| (nv_cmds[idx].cmd_flags & NV_NCH_ALW) == NV_NCH_ALW || (ca.cmdchar == 'q' && oap->op_type == OP_NOP && reg_recording == 0 && reg_executing == 0)



		|| ((ca.cmdchar == 'a' || ca.cmdchar == 'i')
		    && (oap->op_type != OP_NOP || VIsual_active))))
    {
	int	*cp;
	int	repl = FALSE;	
	int	lit = FALSE;	
	int	langmap_active = FALSE;    
	int	lang;		

	int	save_smd;	


	++no_mapping;
	++allow_keys;		
	
	
	did_cursorhold = TRUE;
	if (ca.cmdchar == 'g')
	{
	    
	    ca.nchar = plain_vgetc();
	    LANGMAP_ADJUST(ca.nchar, TRUE);

	    need_flushbuf |= add_to_showcmd(ca.nchar);

	    if (ca.nchar == 'r' || ca.nchar == '\'' || ca.nchar == '`' || ca.nchar == Ctrl_BSL)
	    {
		cp = &ca.extra_char;	
		if (ca.nchar != 'r')
		    lit = TRUE;			
		else repl = TRUE;
	    }
	    else cp = NULL;
	}
	else {
	    if (ca.cmdchar == 'r')		
		repl = TRUE;
	    cp = &ca.nchar;
	}
	lang = (repl || (nv_cmds[idx].cmd_flags & NV_LANG));

	
	if (cp != NULL)
	{
	    if (repl)
	    {
		State = REPLACE;	

		ui_cursor_shape();	

	    }
	    if (lang && curbuf->b_p_iminsert == B_IMODE_LMAP)
	    {
		
		--no_mapping;
		--allow_keys;
		if (repl)
		    State = LREPLACE;
		else State = LANGMAP;
		langmap_active = TRUE;
	    }

	    save_smd = p_smd;
	    p_smd = FALSE;	
	    if (lang && curbuf->b_p_iminsert == B_IMODE_IM)
		im_set_active(TRUE);

	    if ((State & INSERT) && !p_ek)
	    {

		ch_log_output = TRUE;

		
		
		out_str(T_BD);
		out_str(T_CTE);
	    }

	    *cp = plain_vgetc();

	    if ((State & INSERT) && !p_ek)
	    {

		ch_log_output = TRUE;

		
		out_str(T_BE);
		out_str(T_CTI);
	    }

	    if (langmap_active)
	    {
		
		++no_mapping;
		++allow_keys;
		State = NORMAL_BUSY;
	    }

	    if (lang)
	    {
		if (curbuf->b_p_iminsert != B_IMODE_LMAP)
		    im_save_status(&curbuf->b_p_iminsert);
		im_set_active(FALSE);
	    }
	    p_smd = save_smd;

	    State = NORMAL_BUSY;

	    need_flushbuf |= add_to_showcmd(*cp);


	    if (!lit)
	    {

		
		if (*cp == Ctrl_K && ((nv_cmds[idx].cmd_flags & NV_LANG)
			    || cp == &ca.extra_char)
			&& vim_strchr(p_cpo, CPO_DIGRAPH) == NULL)
		{
		    c = get_digraph(FALSE);
		    if (c > 0)
		    {
			*cp = c;

			
			del_from_showcmd(3);
			need_flushbuf |= add_to_showcmd(*cp);

		    }
		}


		
		LANGMAP_ADJUST(*cp, !lang);

		
		if (p_hkmap && lang && KeyTyped)
		    *cp = hkmap(*cp);

	    }

	    
	    if (cp == &ca.extra_char && ca.nchar == Ctrl_BSL && (ca.extra_char == Ctrl_N || ca.extra_char == Ctrl_G))

	    {
		ca.cmdchar = Ctrl_BSL;
		ca.nchar = ca.extra_char;
		idx = find_command(ca.cmdchar);
	    }
	    else if ((ca.nchar == 'n' || ca.nchar == 'N') && ca.cmdchar == 'g')
		ca.oap->op_type = get_op_type(*cp, NUL);
	    else if (*cp == Ctrl_BSL)
	    {
		long towait = (p_ttm >= 0 ? p_ttm : p_tm);

		
		
		while ((c = vpeekc()) <= 0 && towait > 0L)
		{
		    do_sleep(towait > 50L ? 50L : towait, FALSE);
		    towait -= 50L;
		}
		if (c > 0)
		{
		    c = plain_vgetc();
		    if (c != Ctrl_N && c != Ctrl_G)
			vungetc(c);
		    else {
			ca.cmdchar = Ctrl_BSL;
			ca.nchar = c;
			idx = find_command(ca.cmdchar);
		    }
		}
	    }

	    
	    
	    
	    
	    
	    --no_mapping;
	    while (enc_utf8 && lang && (c = vpeekc()) > 0 && (c >= 0x100 || MB_BYTE2LEN(vpeekc()) > 1))
	    {
		c = plain_vgetc();
		if (!utf_iscomposing(c))
		{
		    vungetc(c);		
		    break;
		}
		else if (ca.ncharC1 == 0)
		    ca.ncharC1 = c;
		else ca.ncharC2 = c;
	    }
	    ++no_mapping;
	}
	--no_mapping;
	--allow_keys;
    }


    
    if (need_flushbuf)
	out_flush();

    if (ca.cmdchar != K_IGNORE)
    {
	if (ex_normal_busy)
	    did_cursorhold = save_did_cursorhold;
	else did_cursorhold = FALSE;
    }

    State = NORMAL;

    if (ca.nchar == ESC)
    {
	clearop(oap);
	if (restart_edit == 0 && goto_im())
	    restart_edit = 'a';
	goto normal_end;
    }

    if (ca.cmdchar != K_IGNORE)
    {
	msg_didout = FALSE;    
	msg_col = 0;
    }

    old_pos = curwin->w_cursor;		

    
    
    if (!VIsual_active && km_startsel)
    {
	if (nv_cmds[idx].cmd_flags & NV_SS)
	{
	    start_selection();
	    unshift_special(&ca);
	    idx = find_command(ca.cmdchar);
	}
	else if ((nv_cmds[idx].cmd_flags & NV_SSS)
					   && (mod_mask & MOD_MASK_SHIFT))
	{
	    start_selection();
	    mod_mask &= ~MOD_MASK_SHIFT;
	}
    }

    
    ca.arg = nv_cmds[idx].cmd_arg;
    (nv_cmds[idx].cmd_func)(&ca);

    
    if (!finish_op && !oap->op_type && (idx < 0 || !(nv_cmds[idx].cmd_flags & NV_KEEPREG)))

    {
	clearop(oap);

	reset_reg_var();

    }

    
    
    if (old_mapped_len > 0)
	old_mapped_len = typebuf_maplen();

    
    if (ca.cmdchar != K_IGNORE && ca.cmdchar != K_MOUSEMOVE)
	do_pending_operator(&ca, old_col, FALSE);

    
    if (       ((p_smd && msg_silent == 0 && (restart_edit != 0 || (VIsual_active && old_pos.lnum == curwin->w_cursor.lnum && old_pos.col == curwin->w_cursor.col)




		       )
		    && (clear_cmdline || redraw_cmdline)
		    && (msg_didout || (msg_didany && msg_scroll))
		    && !msg_nowait && KeyTyped)
		|| (restart_edit != 0 && !VIsual_active && (msg_scroll || emsg_on_display)))


	    && oap->regname == 0 && !(ca.retval & CA_COMMAND_BUSY)
	    && stuff_empty()
	    && typebuf_typed()
	    && emsg_silent == 0 && !in_assert_fails && !did_wait_return && oap->op_type == OP_NOP)


    {
	int	save_State = State;

	
	if (restart_edit != 0)
	    State = INSERT;

	
	
	if (must_redraw && keep_msg != NULL && !emsg_on_display)
	{
	    char_u	*kmsg;

	    kmsg = keep_msg;
	    keep_msg = NULL;
	    
	    
	    setcursor();
	    update_screen(0);
	    
	    keep_msg = kmsg;

	    kmsg = vim_strsave(keep_msg);
	    if (kmsg != NULL)
	    {
		msg_attr((char *)kmsg, keep_msg_attr);
		vim_free(kmsg);
	    }
	}
	setcursor();

	ui_cursor_shape();		

	cursor_on();
	out_flush();
	if (msg_scroll || emsg_on_display)
	    ui_delay(1003L, TRUE);	
	ui_delay(3003L, FALSE);		
	State = save_State;

	msg_scroll = FALSE;
	emsg_on_display = FALSE;
    }

    
normal_end:

    msg_nowait = FALSE;


    if (finish_op)
	reset_reg_var();


    

    c = finish_op;

    finish_op = FALSE;
    trigger_modechanged();

    
    
    if (c || ca.cmdchar == 'r')
    {
	ui_cursor_shape();		

	update_mouseshape(-1);

    }



    if (oap->op_type == OP_NOP && oap->regname == 0 && ca.cmdchar != K_CURSORHOLD)
	clear_showcmd();


    checkpcmark();		
    vim_free(ca.searchbuf);

    if (has_mbyte)
	mb_adjust_cursor();

    if (curwin->w_p_scb && toplevel)
    {
	validate_cursor();	
	do_check_scrollbind(TRUE);
    }

    if (curwin->w_p_crb && toplevel)
    {
	validate_cursor();	
	do_check_cursorbind();
    }


    
    if (term_job_running(curbuf->b_term))
	restart_edit = 0;


    
    if (       oap->op_type == OP_NOP && ((restart_edit != 0 && !VIsual_active && old_mapped_len == 0)
		|| restart_VIsual_select == 1)
	    && !(ca.retval & CA_COMMAND_BUSY)
	    && stuff_empty()
	    && oap->regname == 0)
    {
	if (restart_VIsual_select == 1)
	{
	    VIsual_select = TRUE;
	    trigger_modechanged();
	    showmode();
	    restart_VIsual_select = 0;
	}
	if (restart_edit != 0 && !VIsual_active && old_mapped_len == 0)
	    (void)edit(restart_edit, FALSE, 1L);
    }

    if (restart_VIsual_select == 2)
	restart_VIsual_select = 1;

    
    opcount = ca.opcount;
}



    static void set_vcount_ca(cmdarg_T *cap, int *set_prevcount)
{
    long count = cap->count0;

    
    if (cap->opcount != 0)
	count = cap->opcount * (count == 0 ? 1 : count);
    set_vcount(count, count == 0 ? 1 : count, *set_prevcount);
    *set_prevcount = FALSE;  
}



    void check_visual_highlight(void)
{
    static int	    did_check = FALSE;

    if (full_screen)
    {
	if (!did_check && HL_ATTR(HLF_V) == 0)
	    msg(_("Warning: terminal cannot highlight"));
	did_check = TRUE;
    }
}



    static void call_yank_do_autocmd(int regname)
{
    oparg_T	oa;
    yankreg_T	*reg;

    clear_oparg(&oa);
    oa.regname = regname;
    oa.op_type = OP_YANK;
    oa.is_VIsual = TRUE;
    reg = get_register(regname, TRUE);
    yank_do_autocmd(&oa, reg);
    free_register(reg);
}



    void end_visual_mode()
{
    end_visual_mode_keep_button();
    reset_held_button();
}

    void end_visual_mode_keep_button()
{

    
    if (clip_star.available && clip_star.owned)
	clip_auto_select();


    
    
    if (has_textyankpost())
    {
	if (clip_isautosel_star())
	    call_yank_do_autocmd('*');
	if (clip_isautosel_plus())
	    call_yank_do_autocmd('+');
    }



    VIsual_active = FALSE;
    setmouse();
    mouse_dragging = 0;

    
    curbuf->b_visual.vi_mode = VIsual_mode;
    curbuf->b_visual.vi_start = VIsual;
    curbuf->b_visual.vi_end = curwin->w_cursor;
    curbuf->b_visual.vi_curswant = curwin->w_curswant;

    curbuf->b_visual_mode_eval = VIsual_mode;

    if (!virtual_active())
	curwin->w_cursor.coladd = 0;
    may_clear_cmdline();

    adjust_cursor_eol();
    trigger_modechanged();
}


    void reset_VIsual_and_resel(void)
{
    if (VIsual_active)
    {
	end_visual_mode();
	redraw_curbuf_later(INVERTED);	
    }
    VIsual_reselect = FALSE;
}


    void reset_VIsual(void)
{
    if (VIsual_active)
    {
	end_visual_mode();
	redraw_curbuf_later(INVERTED);	
	VIsual_reselect = FALSE;
    }
}

    void restore_visual_mode(void)
{
    if (VIsual_mode_orig != NUL)
    {
	curbuf->b_visual.vi_mode = VIsual_mode_orig;
	VIsual_mode_orig = NUL;
    }
}


    static int find_is_eval_item( char_u	*ptr, int		*colp, int		*bnp, int		dir)




{
    
    if ((*ptr == ']' && dir == BACKWARD) || (*ptr == '[' && dir == FORWARD))
	++*bnp;
    if (*bnp > 0)
    {
	if ((*ptr == '[' && dir == BACKWARD) || (*ptr == ']' && dir == FORWARD))
	    --*bnp;
	return TRUE;
    }

    
    if (*ptr == '.')
	return TRUE;

    
    if (ptr[dir == BACKWARD ? 0 : 1] == '>' && ptr[dir == BACKWARD ? -1 : 0] == '-')
    {
	*colp += dir;
	return TRUE;
    }
    return FALSE;
}


    int find_ident_under_cursor(char_u **text, int find_type)
{
    return find_ident_at_pos(curwin, curwin->w_cursor.lnum, curwin->w_cursor.col, text, NULL, find_type);
}


    int find_ident_at_pos( win_T	*wp, linenr_T	lnum, colnr_T	startcol, char_u	**text, int		*textcol, int		find_type)






{
    char_u	*ptr;
    int		col = 0;	
    int		i;
    int		this_class = 0;
    int		prev_class;
    int		prevcol;
    int		bn = 0;		

    
    ptr = ml_get_buf(wp->w_buffer, lnum, FALSE);
    for (i = (find_type & FIND_IDENT) ? 0 : 1;	i < 2; ++i)
    {
	
	col = startcol;
	if (has_mbyte)
	{
	    while (ptr[col] != NUL)
	    {
		
		if ((find_type & FIND_EVAL) && ptr[col] == ']')
		    break;
		this_class = mb_get_class(ptr + col);
		if (this_class != 0 && (i == 1 || this_class != 1))
		    break;
		col += (*mb_ptr2len)(ptr + col);
	    }
	}
	else while (ptr[col] != NUL && (i == 0 ? !vim_iswordc(ptr[col]) : VIM_ISWHITE(ptr[col]))

		    && (!(find_type & FIND_EVAL) || ptr[col] != ']')
		    )
		++col;

	
	bn = ptr[col] == ']';

	
	if (has_mbyte)
	{
	    
	    if ((find_type & FIND_EVAL) && ptr[col] == ']')
		this_class = mb_get_class((char_u *)"a");
	    else this_class = mb_get_class(ptr + col);
	    while (col > 0 && this_class != 0)
	    {
		prevcol = col - 1 - (*mb_head_off)(ptr, ptr + col - 1);
		prev_class = mb_get_class(ptr + prevcol);
		if (this_class != prev_class && (i == 0 || prev_class == 0 || (find_type & FIND_IDENT))


			&& (!(find_type & FIND_EVAL)
			    || prevcol == 0 || !find_is_eval_item(ptr + prevcol, &prevcol, &bn, BACKWARD))

			)
		    break;
		col = prevcol;
	    }

	    
	    
	    if (this_class > 2)
		this_class = 2;
	    if (!(find_type & FIND_STRING) || this_class == 2)
		break;
	}
	else {
	    while (col > 0 && ((i == 0 ? vim_iswordc(ptr[col - 1])

			    : (!VIM_ISWHITE(ptr[col - 1])
				&& (!(find_type & FIND_IDENT)
				    || !vim_iswordc(ptr[col - 1]))))
			|| ((find_type & FIND_EVAL)
			    && col > 1 && find_is_eval_item(ptr + col - 1, &col, &bn, BACKWARD))

			))
		--col;

	    
	    
	    if (!(find_type & FIND_STRING) || vim_iswordc(ptr[col]))
		break;
	}
    }

    if (ptr[col] == NUL || (i == 0 && (has_mbyte ? this_class != 2 : !vim_iswordc(ptr[col]))))
    {
	
	if ((find_type & FIND_NOERROR) == 0)
	{
	    if (find_type & FIND_STRING)
		emsg(_("E348: No string under cursor"));
	    else emsg(_(e_noident));
	}
	return 0;
    }
    ptr += col;
    *text = ptr;
    if (textcol != NULL)
	*textcol = col;

    
    bn = 0;
    startcol -= col;
    col = 0;
    if (has_mbyte)
    {
	
	this_class = mb_get_class(ptr);
	while (ptr[col] != NUL && ((i == 0 ? mb_get_class(ptr + col) == this_class : mb_get_class(ptr + col) != 0)

		    || ((find_type & FIND_EVAL)
			&& col <= (int)startcol && find_is_eval_item(ptr + col, &col, &bn, FORWARD))
		))
	    col += (*mb_ptr2len)(ptr + col);
    }
    else while ((i == 0 ? vim_iswordc(ptr[col])
		       : (ptr[col] != NUL && !VIM_ISWHITE(ptr[col])))
		    || ((find_type & FIND_EVAL)
			&& col <= (int)startcol && find_is_eval_item(ptr + col, &col, &bn, FORWARD))
		)
	    ++col;

    return col;
}


    static void prep_redo_cmd(cmdarg_T *cap)
{
    prep_redo(cap->oap->regname, cap->count0, NUL, cap->cmdchar, NUL, NUL, cap->nchar);
}


    void prep_redo( int	    regname, long    num, int	    cmd1, int	    cmd2, int	    cmd3, int	    cmd4, int	    cmd5)







{
    ResetRedobuff();
    if (regname != 0)	
    {
	AppendCharToRedobuff('"');
	AppendCharToRedobuff(regname);
    }
    if (num)
	AppendNumberToRedobuff(num);

    if (cmd1 != NUL)
	AppendCharToRedobuff(cmd1);
    if (cmd2 != NUL)
	AppendCharToRedobuff(cmd2);
    if (cmd3 != NUL)
	AppendCharToRedobuff(cmd3);
    if (cmd4 != NUL)
	AppendCharToRedobuff(cmd4);
    if (cmd5 != NUL)
	AppendCharToRedobuff(cmd5);
}


    static int checkclearop(oparg_T *oap)
{
    if (oap->op_type == OP_NOP)
	return FALSE;
    clearopbeep(oap);
    return TRUE;
}


    static int checkclearopq(oparg_T *oap)
{
    if (oap->op_type == OP_NOP && !VIsual_active)
	return FALSE;
    clearopbeep(oap);
    return TRUE;
}

    void clearop(oparg_T *oap)
{
    oap->op_type = OP_NOP;
    oap->regname = 0;
    oap->motion_force = NUL;
    oap->use_reg_one = FALSE;
    motion_force = NUL;
}

    void clearopbeep(oparg_T *oap)
{
    clearop(oap);
    beep_flush();
}


    static void unshift_special(cmdarg_T *cap)
{
    switch (cap->cmdchar)
    {
	case K_S_RIGHT:	cap->cmdchar = K_RIGHT; break;
	case K_S_LEFT:	cap->cmdchar = K_LEFT; break;
	case K_S_UP:	cap->cmdchar = K_UP; break;
	case K_S_DOWN:	cap->cmdchar = K_DOWN; break;
	case K_S_HOME:	cap->cmdchar = K_HOME; break;
	case K_S_END:	cap->cmdchar = K_END; break;
    }
    cap->cmdchar = simplify_key(cap->cmdchar, &mod_mask);
}


    void may_clear_cmdline(void)
{
    if (mode_displayed)
	clear_cmdline = TRUE;   

    else clear_showcmd();

}





static char_u	showcmd_buf[SHOWCMD_BUFLEN];
static char_u	old_showcmd_buf[SHOWCMD_BUFLEN];  
static int	showcmd_is_clear = TRUE;
static int	showcmd_visual = FALSE;

static void display_showcmd(void);

    void clear_showcmd(void)
{
    if (!p_sc)
	return;

    if (VIsual_active && !char_avail())
    {
	int		cursor_bot = LT_POS(VIsual, curwin->w_cursor);
	long		lines;
	colnr_T		leftcol, rightcol;
	linenr_T	top, bot;

	
	if (cursor_bot)
	{
	    top = VIsual.lnum;
	    bot = curwin->w_cursor.lnum;
	}
	else {
	    top = curwin->w_cursor.lnum;
	    bot = VIsual.lnum;
	}

	
	(void)hasFolding(top, &top, NULL);
	(void)hasFolding(bot, NULL, &bot);

	lines = bot - top + 1;

	if (VIsual_mode == Ctrl_V)
	{

	    char_u *saved_sbr = p_sbr;
	    char_u *saved_w_sbr = curwin->w_p_sbr;

	    
	    p_sbr = empty_option;
	    curwin->w_p_sbr = empty_option;

	    getvcols(curwin, &curwin->w_cursor, &VIsual, &leftcol, &rightcol);

	    p_sbr = saved_sbr;
	    curwin->w_p_sbr = saved_w_sbr;

	    sprintf((char *)showcmd_buf, "%ldx%ld", lines, (long)(rightcol - leftcol + 1));
	}
	else if (VIsual_mode == 'V' || VIsual.lnum != curwin->w_cursor.lnum)
	    sprintf((char *)showcmd_buf, "%ld", lines);
	else {
	    char_u  *s, *e;
	    int	    l;
	    int	    bytes = 0;
	    int	    chars = 0;

	    if (cursor_bot)
	    {
		s = ml_get_pos(&VIsual);
		e = ml_get_cursor();
	    }
	    else {
		s = ml_get_cursor();
		e = ml_get_pos(&VIsual);
	    }
	    while ((*p_sel != 'e') ? s <= e : s < e)
	    {
		l = (*mb_ptr2len)(s);
		if (l == 0)
		{
		    ++bytes;
		    ++chars;
		    break;  
		}
		bytes += l;
		++chars;
		s += l;
	    }
	    if (bytes == chars)
		sprintf((char *)showcmd_buf, "%d", chars);
	    else sprintf((char *)showcmd_buf, "%d-%d", chars, bytes);
	}
	showcmd_buf[SHOWCMD_COLS] = NUL;	
	showcmd_visual = TRUE;
    }
    else {
	showcmd_buf[0] = NUL;
	showcmd_visual = FALSE;

	
	if (showcmd_is_clear)
	    return;
    }

    display_showcmd();
}


    int add_to_showcmd(int c)
{
    char_u	*p;
    int		old_len;
    int		extra_len;
    int		overflow;
    int		i;
    static int	ignore[] = {

	K_VER_SCROLLBAR, K_HOR_SCROLLBAR, K_LEFTMOUSE_NM, K_LEFTRELEASE_NM,  K_IGNORE, K_PS, K_LEFTMOUSE, K_LEFTDRAG, K_LEFTRELEASE, K_MOUSEMOVE, K_MIDDLEMOUSE, K_MIDDLEDRAG, K_MIDDLERELEASE, K_RIGHTMOUSE, K_RIGHTDRAG, K_RIGHTRELEASE, K_MOUSEDOWN, K_MOUSEUP, K_MOUSELEFT, K_MOUSERIGHT, K_X1MOUSE, K_X1DRAG, K_X1RELEASE, K_X2MOUSE, K_X2DRAG, K_X2RELEASE, K_CURSORHOLD, 0 };











    if (!p_sc || msg_silent != 0)
	return FALSE;

    if (showcmd_visual)
    {
	showcmd_buf[0] = NUL;
	showcmd_visual = FALSE;
    }

    
    if (IS_SPECIAL(c))
	for (i = 0; ignore[i] != 0; ++i)
	    if (ignore[i] == c)
		return FALSE;

    p = transchar(c);
    if (*p == ' ')
	STRCPY(p, "<20>");
    old_len = (int)STRLEN(showcmd_buf);
    extra_len = (int)STRLEN(p);
    overflow = old_len + extra_len - SHOWCMD_COLS;
    if (overflow > 0)
	mch_memmove(showcmd_buf, showcmd_buf + overflow, old_len - overflow + 1);
    STRCAT(showcmd_buf, p);

    if (char_avail())
	return FALSE;

    display_showcmd();

    return TRUE;
}

    void add_to_showcmd_c(int c)
{
    if (!add_to_showcmd(c))
	setcursor();
}


    static void del_from_showcmd(int len)
{
    int	    old_len;

    if (!p_sc)
	return;

    old_len = (int)STRLEN(showcmd_buf);
    if (len > old_len)
	len = old_len;
    showcmd_buf[old_len - len] = NUL;

    if (!char_avail())
	display_showcmd();
}


    void push_showcmd(void)
{
    if (p_sc)
	STRCPY(old_showcmd_buf, showcmd_buf);
}

    void pop_showcmd(void)
{
    if (!p_sc)
	return;

    STRCPY(showcmd_buf, old_showcmd_buf);

    display_showcmd();
}

    static void display_showcmd(void)
{
    int	    len;

    cursor_off();

    len = (int)STRLEN(showcmd_buf);
    if (len == 0)
	showcmd_is_clear = TRUE;
    else {
	screen_puts(showcmd_buf, (int)Rows - 1, sc_col, 0);
	showcmd_is_clear = FALSE;
    }

    
    screen_puts((char_u *)"          " + len, (int)Rows - 1, sc_col + len, 0);

    setcursor();	    
}



    void do_check_scrollbind(int check)
{
    static win_T	*old_curwin = NULL;
    static linenr_T	old_topline = 0;

    static int		old_topfill = 0;

    static buf_T	*old_buf = NULL;
    static colnr_T	old_leftcol = 0;

    if (check && curwin->w_p_scb)
    {
	
	
	if (did_syncbind)
	    did_syncbind = FALSE;
	else if (curwin == old_curwin)
	{
	    
	    if ((curwin->w_buffer == old_buf  || curwin->w_p_diff  )



		&& (curwin->w_topline != old_topline  || curwin->w_topfill != old_topfill  || curwin->w_leftcol != old_leftcol))



	    {
		check_scrollbind(curwin->w_topline - old_topline, (long)(curwin->w_leftcol - old_leftcol));
	    }
	}
	else if (vim_strchr(p_sbo, 'j')) 
	{
	    
	    check_scrollbind(curwin->w_topline - curwin->w_scbind_pos, 0L);
	}
	curwin->w_scbind_pos = curwin->w_topline;
    }

    old_curwin = curwin;
    old_topline = curwin->w_topline;

    old_topfill = curwin->w_topfill;

    old_buf = curwin->w_buffer;
    old_leftcol = curwin->w_leftcol;
}


    void check_scrollbind(linenr_T topline_diff, long leftcol_diff)
{
    int		want_ver;
    int		want_hor;
    win_T	*old_curwin = curwin;
    buf_T	*old_curbuf = curbuf;
    int		old_VIsual_select = VIsual_select;
    int		old_VIsual_active = VIsual_active;
    colnr_T	tgt_leftcol = curwin->w_leftcol;
    long	topline;
    long	y;

    
    want_ver = (vim_strchr(p_sbo, 'v') && topline_diff != 0);

    want_ver |= old_curwin->w_p_diff;

    want_hor = (vim_strchr(p_sbo, 'h') && (leftcol_diff || topline_diff != 0));

    
    VIsual_select = VIsual_active = 0;
    FOR_ALL_WINDOWS(curwin)
    {
	curbuf = curwin->w_buffer;
	
	if (curwin != old_curwin && curwin->w_p_scb)
	{
	    
	    if (want_ver)
	    {

		if (old_curwin->w_p_diff && curwin->w_p_diff)
		{
		    diff_set_topline(old_curwin, curwin);
		}
		else  {

		    curwin->w_scbind_pos += topline_diff;
		    topline = curwin->w_scbind_pos;
		    if (topline > curbuf->b_ml.ml_line_count)
			topline = curbuf->b_ml.ml_line_count;
		    if (topline < 1)
			topline = 1;

		    y = topline - curwin->w_topline;
		    if (y > 0)
			scrollup(y, FALSE);
		    else scrolldown(-y, FALSE);
		}

		redraw_later(VALID);
		cursor_correct();
		curwin->w_redr_status = TRUE;
	    }

	    
	    if (want_hor && curwin->w_leftcol != tgt_leftcol)
	    {
		curwin->w_leftcol = tgt_leftcol;
		leftcol_changed();
	    }
	}
    }

    
    VIsual_select = old_VIsual_select;
    VIsual_active = old_VIsual_active;
    curwin = old_curwin;
    curbuf = old_curbuf;
}


    static void nv_ignore(cmdarg_T *cap)
{
    cap->retval |= CA_COMMAND_BUSY;	
}


    static void nv_nop(cmdarg_T *cap UNUSED)
{
}


    static void nv_error(cmdarg_T *cap)
{
    clearopbeep(cap->oap);
}


    static void nv_help(cmdarg_T *cap)
{
    if (!checkclearopq(cap->oap))
	ex_help(NULL);
}


    static void nv_addsub(cmdarg_T *cap)
{

    if (bt_prompt(curbuf) && !prompt_curpos_editable())
	clearopbeep(cap->oap);
    else  if (!VIsual_active && cap->oap->op_type == OP_NOP)

    {
	prep_redo_cmd(cap);
	cap->oap->op_type = cap->cmdchar == Ctrl_A ?  OP_NR_ADD : OP_NR_SUB;
	op_addsub(cap->oap, cap->count1, cap->arg);
	cap->oap->op_type = OP_NOP;
    }
    else if (VIsual_active)
	nv_operator(cap);
    else clearop(cap->oap);
}


    static void nv_page(cmdarg_T *cap)
{
    if (!checkclearop(cap->oap))
    {
	if (mod_mask & MOD_MASK_CTRL)
	{
	    
	    if (cap->arg == BACKWARD)
		goto_tabpage(-(int)cap->count1);
	    else goto_tabpage((int)cap->count0);
	}
	else (void)onepage(cap->arg, cap->count1);
    }
}


    static void nv_gd( oparg_T	*oap, int		nchar, int		thisblock)



{
    int		len;
    char_u	*ptr;

    if ((len = find_ident_under_cursor(&ptr, FIND_IDENT)) == 0 || find_decl(ptr, len, nchar == 'd', thisblock, SEARCH_START)
								       == FAIL)
    {
	clearopbeep(oap);
    }
    else {

	if ((fdo_flags & FDO_SEARCH) && KeyTyped && oap->op_type == OP_NOP)
	    foldOpenCursor();

	
	if (messaging() && !msg_silent && !shortmess(SHM_SEARCHCOUNT))
	    clear_cmdline = TRUE;
    }
}


    static int is_ident(char_u *line, int offset)
{
    int	i;
    int	incomment = FALSE;
    int	instring = 0;
    int	prev = 0;

    for (i = 0; i < offset && line[i] != NUL; i++)
    {
	if (instring != 0)
	{
	    if (prev != '\\' && line[i] == instring)
		instring = 0;
	}
	else if ((line[i] == '"' || line[i] == '\'') && !incomment)
	{
	    instring = line[i];
	}
	else {
	    if (incomment)
	    {
		if (prev == '*' && line[i] == '/')
		    incomment = FALSE;
	    }
	    else if (prev == '/' && line[i] == '*')
	    {
		incomment = TRUE;
	    }
	    else if (prev == '/' && line[i] == '/')
	    {
		return FALSE;
	    }
	}

	prev = line[i];
    }

    return incomment == FALSE && instring == 0;
}


    int find_decl( char_u	*ptr, int		len, int		locally, int		thisblock, int		flags_arg)





{
    char_u	*pat;
    pos_T	old_pos;
    pos_T	par_pos;
    pos_T	found_pos;
    int		t;
    int		save_p_ws;
    int		save_p_scs;
    int		retval = OK;
    int		incll;
    int		searchflags = flags_arg;
    int		valid;

    if ((pat = alloc(len + 7)) == NULL)
	return FAIL;

    
    
    sprintf((char *)pat, vim_iswordp(ptr) ? "\\V\\<%.*s\\>" : "\\V%.*s", len, ptr);
    old_pos = curwin->w_cursor;
    save_p_ws = p_ws;
    save_p_scs = p_scs;
    p_ws = FALSE;	
    p_scs = FALSE;	

    
    if (!locally || !findpar(&incll, BACKWARD, 1L, '{', FALSE))
    {
	setpcmark();			
	curwin->w_cursor.lnum = 1;
	par_pos = curwin->w_cursor;
    }
    else {
	par_pos = curwin->w_cursor;
	while (curwin->w_cursor.lnum > 1 && *skipwhite(ml_get_curline()) != NUL)
	    --curwin->w_cursor.lnum;
    }
    curwin->w_cursor.col = 0;

    
    CLEAR_POS(&found_pos);
    for (;;)
    {
	t = searchit(curwin, curbuf, &curwin->w_cursor, NULL, FORWARD, pat, 1L, searchflags, RE_LAST, NULL);
	if (curwin->w_cursor.lnum >= old_pos.lnum)
	    t = FAIL;	

	if (thisblock && t != FAIL)
	{
	    pos_T	*pos;

	    
	    
	    if ((pos = findmatchlimit(NULL, '}', FM_FORWARD, (int)(old_pos.lnum - curwin->w_cursor.lnum + 1))) != NULL && pos->lnum < old_pos.lnum)

	    {
		
		
		curwin->w_cursor = *pos;
		continue;
	    }
	}

	if (t == FAIL)
	{
	    
	    if (found_pos.lnum != 0)
	    {
		curwin->w_cursor = found_pos;
		t = OK;
	    }
	    break;
	}
	if (get_leader_len(ml_get_curline(), NULL, FALSE, TRUE) > 0)
	{
	    
	    ++curwin->w_cursor.lnum;
	    curwin->w_cursor.col = 0;
	    continue;
	}
	valid = is_ident(ml_get_curline(), curwin->w_cursor.col);

	
	
	if (!valid && found_pos.lnum != 0)
	{
	    curwin->w_cursor = found_pos;
	    break;
	}

	
	if (valid && !locally)
	    break;
	if (valid && curwin->w_cursor.lnum >= par_pos.lnum)
	{
	    
	    if (found_pos.lnum != 0)
		curwin->w_cursor = found_pos;
	    break;
	}

	
	
	
	if (!valid)
	    CLEAR_POS(&found_pos);
	else found_pos = curwin->w_cursor;
	
	
	searchflags &= ~SEARCH_START;
    }

    if (t == FAIL)
    {
	retval = FAIL;
	curwin->w_cursor = old_pos;
    }
    else {
	curwin->w_set_curswant = TRUE;
	
	reset_search_dir();
    }

    vim_free(pat);
    p_ws = save_p_ws;
    p_scs = save_p_scs;

    return retval;
}


    static int nv_screengo(oparg_T *oap, int dir, long dist)
{
    int		linelen = linetabsize(ml_get_curline());
    int		retval = OK;
    int		atend = FALSE;
    int		n;
    int		col_off1;	
    int		col_off2;	
    int		width1;		
    int		width2;		

    oap->motion_type = MCHAR;
    oap->inclusive = (curwin->w_curswant == MAXCOL);

    col_off1 = curwin_col_off();
    col_off2 = col_off1 - curwin_col_off2();
    width1 = curwin->w_width - col_off1;
    width2 = curwin->w_width - col_off2;
    if (width2 == 0)
	width2 = 1; 

    if (curwin->w_width != 0)
    {
      
      if (curwin->w_curswant == MAXCOL)
      {
	atend = TRUE;
	validate_virtcol();
	if (width1 <= 0)
	    curwin->w_curswant = 0;
	else {
	    curwin->w_curswant = width1 - 1;
	    if (curwin->w_virtcol > curwin->w_curswant)
		curwin->w_curswant += ((curwin->w_virtcol - curwin->w_curswant - 1) / width2 + 1) * width2;
	}
      }
      else {
	if (linelen > width1)
	    n = ((linelen - width1 - 1) / width2 + 1) * width2 + width1;
	else n = width1;
	if (curwin->w_curswant >= (colnr_T)n)
	    curwin->w_curswant = n - 1;
      }

      while (dist--)
      {
	if (dir == BACKWARD)
	{
	    if ((long)curwin->w_curswant >= width1  && !hasFolding(curwin->w_cursor.lnum, NULL, NULL)


	       )
		
		
		
		curwin->w_curswant -= width2;
	    else {
		

		
		
		if (!(fdo_flags & FDO_ALL))
		    (void)hasFolding(curwin->w_cursor.lnum, &curwin->w_cursor.lnum, NULL);

		if (curwin->w_cursor.lnum == 1)
		{
		    retval = FAIL;
		    break;
		}
		--curwin->w_cursor.lnum;

		linelen = linetabsize(ml_get_curline());
		if (linelen > width1)
		    curwin->w_curswant += (((linelen - width1 - 1) / width2)
								+ 1) * width2;
	    }
	}
	else  {
	    if (linelen > width1)
		n = ((linelen - width1 - 1) / width2 + 1) * width2 + width1;
	    else n = width1;
	    if (curwin->w_curswant + width2 < (colnr_T)n  && !hasFolding(curwin->w_cursor.lnum, NULL, NULL)


		    )
		
		curwin->w_curswant += width2;
	    else {
		

		
		(void)hasFolding(curwin->w_cursor.lnum, NULL, &curwin->w_cursor.lnum);

		if (curwin->w_cursor.lnum == curbuf->b_ml.ml_line_count)
		{
		    retval = FAIL;
		    break;
		}
		curwin->w_cursor.lnum++;
		curwin->w_curswant %= width2;
		
		
		
		
		if (curwin->w_curswant >= width1)
		    curwin->w_curswant -= width2;
		linelen = linetabsize(ml_get_curline());
	    }
	}
      }
    }

    if (virtual_active() && atend)
	coladvance(MAXCOL);
    else coladvance(curwin->w_curswant);

    if (curwin->w_cursor.col > 0 && curwin->w_p_wrap)
    {
	colnr_T virtcol;
	int	c;

	
	validate_virtcol();
	virtcol = curwin->w_virtcol;

	if (virtcol > (colnr_T)width1 && *get_showbreak_value(curwin) != NUL)
	    virtcol -= vim_strsize(get_showbreak_value(curwin));


	c = (*mb_ptr2char)(ml_get_cursor());
	if (dir == FORWARD && virtcol < curwin->w_curswant && (curwin->w_curswant <= (colnr_T)width1)
		&& !vim_isprintc(c) && c > 255)
	    oneright();

	if (virtcol > curwin->w_curswant && (curwin->w_curswant < (colnr_T)width1 ? (curwin->w_curswant > (colnr_T)width1 / 2)

		    : ((curwin->w_curswant - width1) % width2 > (colnr_T)width2 / 2)))
	    --curwin->w_cursor.col;
    }

    if (atend)
	curwin->w_curswant = MAXCOL;	    

    return retval;
}


    void nv_scroll_line(cmdarg_T *cap)
{
    if (!checkclearop(cap->oap))
	scroll_redraw(cap->arg, cap->count1);
}


    void scroll_redraw(int up, long count)
{
    linenr_T	prev_topline = curwin->w_topline;

    int		prev_topfill = curwin->w_topfill;

    linenr_T	prev_lnum = curwin->w_cursor.lnum;

    if (up)
	scrollup(count, TRUE);
    else scrolldown(count, TRUE);
    if (get_scrolloff_value())
    {
	
	
	cursor_correct();
	check_cursor_moved(curwin);
	curwin->w_valid |= VALID_TOPLINE;

	
	
	
	while (curwin->w_topline == prev_topline  && curwin->w_topfill == prev_topfill  )



	{
	    if (up)
	    {
		if (curwin->w_cursor.lnum > prev_lnum || cursor_down(1L, FALSE) == FAIL)
		    break;
	    }
	    else {
		if (curwin->w_cursor.lnum < prev_lnum || prev_topline == 1L || cursor_up(1L, FALSE) == FAIL)

		    break;
	    }
	    
	    
	    check_cursor_moved(curwin);
	    curwin->w_valid |= VALID_TOPLINE;
	}
    }
    if (curwin->w_cursor.lnum != prev_lnum)
	coladvance(curwin->w_curswant);
    redraw_later(VALID);
}


    static void nv_zet(cmdarg_T *cap)
{
    long	n;
    colnr_T	col;
    int		nchar = cap->nchar;

    long	old_fdl = curwin->w_p_fdl;
    int		old_fen = curwin->w_p_fen;


    int		undo = FALSE;

    long        siso = get_sidescrolloff_value();

    if (VIM_ISDIGIT(nchar))
    {
	
	if (checkclearop(cap->oap))
	    return;
	n = nchar - '0';
	for (;;)
	{

	    dont_scroll = TRUE;		

	    ++no_mapping;
	    ++allow_keys;   
	    nchar = plain_vgetc();
	    LANGMAP_ADJUST(nchar, TRUE);
	    --no_mapping;
	    --allow_keys;

	    (void)add_to_showcmd(nchar);

	    if (nchar == K_DEL || nchar == K_KDEL)
		n /= 10;
	    else if (VIM_ISDIGIT(nchar))
		n = n * 10 + (nchar - '0');
	    else if (nchar == CAR)
	    {

		need_mouse_correct = TRUE;

		win_setheight((int)n);
		break;
	    }
	    else if (nchar == 'l' || nchar == 'h' || nchar == K_LEFT || nchar == K_RIGHT)


	    {
		cap->count1 = n ? n * cap->count1 : cap->count1;
		goto dozet;
	    }
	    else {
		clearopbeep(cap->oap);
		break;
	    }
	}
	cap->oap->op_type = OP_NOP;
	return;
    }

dozet:
    if (     cap->nchar != 'f' && cap->nchar != 'F' && !(VIsual_active && vim_strchr((char_u *)"dcCoO", cap->nchar))





	    && cap->nchar != 'j' && cap->nchar != 'k' &&  checkclearop(cap->oap))


	return;

    
    if ((vim_strchr((char_u *)"+\r\nt.z^-b", nchar) != NULL)
	    && cap->count0 && cap->count0 != curwin->w_cursor.lnum)
    {
	setpcmark();
	if (cap->count0 > curbuf->b_ml.ml_line_count)
	    curwin->w_cursor.lnum = curbuf->b_ml.ml_line_count;
	else curwin->w_cursor.lnum = cap->count0;
	check_cursor_col();
    }

    switch (nchar)
    {
		
    case '+':
		if (cap->count0 == 0)
		{
		    
		    validate_botline();	
		    if (curwin->w_botline > curbuf->b_ml.ml_line_count)
			curwin->w_cursor.lnum = curbuf->b_ml.ml_line_count;
		    else curwin->w_cursor.lnum = curwin->w_botline;
		}
		
    case NL:
    case CAR:
    case K_KENTER:
		beginline(BL_WHITE | BL_FIX);
		

    case 't':	scroll_cursor_top(0, TRUE);
		redraw_later(VALID);
		set_fraction(curwin);
		break;

		
    case '.':	beginline(BL_WHITE | BL_FIX);
		

    case 'z':	scroll_cursor_halfway(TRUE);
		redraw_later(VALID);
		set_fraction(curwin);
		break;

		
    case '^':	
		
		
		if (cap->count0 != 0)
		{
		    scroll_cursor_bot(0, TRUE);
		    curwin->w_cursor.lnum = curwin->w_topline;
		}
		else if (curwin->w_topline == 1)
		    curwin->w_cursor.lnum = 1;
		else curwin->w_cursor.lnum = curwin->w_topline - 1;
		
    case '-':
		beginline(BL_WHITE | BL_FIX);
		

    case 'b':	scroll_cursor_bot(0, TRUE);
		redraw_later(VALID);
		set_fraction(curwin);
		break;

		
    case 'H':
		cap->count1 *= curwin->w_width / 2;
		

		
    case 'h':
    case K_LEFT:
		if (!curwin->w_p_wrap)
		{
		    if ((colnr_T)cap->count1 > curwin->w_leftcol)
			curwin->w_leftcol = 0;
		    else curwin->w_leftcol -= (colnr_T)cap->count1;
		    leftcol_changed();
		}
		break;

		
    case 'L':	cap->count1 *= curwin->w_width / 2;
		

		
    case 'l':
    case K_RIGHT:
		if (!curwin->w_p_wrap)
		{
		    
		    curwin->w_leftcol += (colnr_T)cap->count1;
		    leftcol_changed();
		}
		break;

		
    case 's':	if (!curwin->w_p_wrap)
		{

		    if (hasFolding(curwin->w_cursor.lnum, NULL, NULL))
			col = 0;	
		    else  getvcol(curwin, &curwin->w_cursor, &col, NULL, NULL);

		    if ((long)col > siso)
			col -= siso;
		    else col = 0;
		    if (curwin->w_leftcol != col)
		    {
			curwin->w_leftcol = col;
			redraw_later(NOT_VALID);
		    }
		}
		break;

		
    case 'e':	if (!curwin->w_p_wrap)
		{

		    if (hasFolding(curwin->w_cursor.lnum, NULL, NULL))
			col = 0;	
		    else  getvcol(curwin, &curwin->w_cursor, NULL, NULL, &col);

		    n = curwin->w_width - curwin_col_off();
		    if ((long)col + siso < n)
			col = 0;
		    else col = col + siso - n + 1;
		    if (curwin->w_leftcol != col)
		    {
			curwin->w_leftcol = col;
			redraw_later(NOT_VALID);
		    }
		}
		break;

		
    case 'P':
    case 'p':  nv_put(cap);
	       break;
		
    case 'y':  nv_operator(cap);
	       break;

		
		
    case 'F':
    case 'f':   if (foldManualAllowed(TRUE))
		{
		    cap->nchar = 'f';
		    nv_operator(cap);
		    curwin->w_p_fen = TRUE;

		    
		    if (nchar == 'F' && cap->oap->op_type == OP_FOLD)
		    {
			nv_operator(cap);
			finish_op = TRUE;
		    }
		}
		else clearopbeep(cap->oap);
		break;

		
		
    case 'd':
    case 'D':	if (foldManualAllowed(FALSE))
		{
		    if (VIsual_active)
			nv_operator(cap);
		    else deleteFold(curwin->w_cursor.lnum, curwin->w_cursor.lnum, nchar == 'D', FALSE);

		}
		break;

		
    case 'E':	if (foldmethodIsManual(curwin))
		{
		    clearFolding(curwin);
		    changed_window_setting();
		}
		else if (foldmethodIsMarker(curwin))
		    deleteFold((linenr_T)1, curbuf->b_ml.ml_line_count, TRUE, FALSE);
		else emsg(_("E352: Cannot erase folds with current 'foldmethod'"));
		break;

		
    case 'n':	curwin->w_p_fen = FALSE;
		break;

		
    case 'N':	curwin->w_p_fen = TRUE;
		break;

		
    case 'i':	curwin->w_p_fen = !curwin->w_p_fen;
		break;

		
    case 'a':	if (hasFolding(curwin->w_cursor.lnum, NULL, NULL))
		    openFold(curwin->w_cursor.lnum, cap->count1);
		else {
		    closeFold(curwin->w_cursor.lnum, cap->count1);
		    curwin->w_p_fen = TRUE;
		}
		break;

		
    case 'A':	if (hasFolding(curwin->w_cursor.lnum, NULL, NULL))
		    openFoldRecurse(curwin->w_cursor.lnum);
		else {
		    closeFoldRecurse(curwin->w_cursor.lnum);
		    curwin->w_p_fen = TRUE;
		}
		break;

		
    case 'o':	if (VIsual_active)
		    nv_operator(cap);
		else openFold(curwin->w_cursor.lnum, cap->count1);
		break;

		
    case 'O':	if (VIsual_active)
		    nv_operator(cap);
		else openFoldRecurse(curwin->w_cursor.lnum);
		break;

		
    case 'c':	if (VIsual_active)
		    nv_operator(cap);
		else closeFold(curwin->w_cursor.lnum, cap->count1);
		curwin->w_p_fen = TRUE;
		break;

		
    case 'C':	if (VIsual_active)
		    nv_operator(cap);
		else closeFoldRecurse(curwin->w_cursor.lnum);
		curwin->w_p_fen = TRUE;
		break;

		
    case 'v':	foldOpenCursor();
		break;

		
    case 'x':	curwin->w_p_fen = TRUE;
		curwin->w_foldinvalid = TRUE;	
		newFoldLevel();			
		foldOpenCursor();
		break;

		
    case 'X':	curwin->w_p_fen = TRUE;
		curwin->w_foldinvalid = TRUE;	
		old_fdl = -1;			
		break;

		
    case 'm':	if (curwin->w_p_fdl > 0)
		{
		    curwin->w_p_fdl -= cap->count1;
		    if (curwin->w_p_fdl < 0)
			curwin->w_p_fdl = 0;
		}
		old_fdl = -1;		
		curwin->w_p_fen = TRUE;
		break;

		
    case 'M':	curwin->w_p_fdl = 0;
		old_fdl = -1;		
		curwin->w_p_fen = TRUE;
		break;

		
    case 'r':	curwin->w_p_fdl += cap->count1;
		{
		    int d = getDeepestNesting();

		    if (curwin->w_p_fdl >= d)
			curwin->w_p_fdl = d;
		}
		break;

		
    case 'R':	curwin->w_p_fdl = getDeepestNesting();
		old_fdl = -1;		
		break;

    case 'j':	
    case 'k':	
		if (foldMoveTo(TRUE, nchar == 'j' ? FORWARD : BACKWARD, cap->count1) == FAIL)
		    clearopbeep(cap->oap);
		break;




    case 'u':	
		++no_mapping;
		++allow_keys;   
		nchar = plain_vgetc();
		LANGMAP_ADJUST(nchar, TRUE);
		--no_mapping;
		--allow_keys;

		(void)add_to_showcmd(nchar);

		if (vim_strchr((char_u *)"gGwW", nchar) == NULL)
		{
		    clearopbeep(cap->oap);
		    break;
		}
		undo = TRUE;
		

    case 'g':	
    case 'w':	
    case 'G':	
    case 'W':	
		{
		    char_u  *ptr = NULL;
		    int	    len;

		    if (checkclearop(cap->oap))
			break;
		    if (VIsual_active && get_visual_text(cap, &ptr, &len)
								      == FAIL)
			return;
		    if (ptr == NULL)
		    {
			pos_T	pos = curwin->w_cursor;

			
			
			
			emsg_off++;
			len = spell_move_to(curwin, FORWARD, TRUE, TRUE, NULL);
			emsg_off--;
			if (len != 0 && curwin->w_cursor.col <= pos.col)
			    ptr = ml_get_pos(&curwin->w_cursor);
			curwin->w_cursor = pos;
		    }

		    if (ptr == NULL && (len = find_ident_under_cursor(&ptr, FIND_IDENT)) == 0)
			return;
		    spell_add_word(ptr, len, nchar == 'w' || nchar == 'W' ? SPELL_ADD_BAD : SPELL_ADD_GOOD, (nchar == 'G' || nchar == 'W')

						       ? 0 : (int)cap->count1, undo);
		}
		break;

    case '=':	
		if (!checkclearop(cap->oap))
		    spell_suggest((int)cap->count0);
		break;


    default:	clearopbeep(cap->oap);
    }


    
    if (old_fen != curwin->w_p_fen)
    {

	win_T	    *wp;

	if (foldmethodIsDiff(curwin) && curwin->w_p_scb)
	{
	    
	    FOR_ALL_WINDOWS(wp)
	    {
		if (wp != curwin && foldmethodIsDiff(wp) && wp->w_p_scb)
		{
		    wp->w_p_fen = curwin->w_p_fen;
		    changed_window_setting_win(wp);
		}
	    }
	}

	changed_window_setting();
    }

    
    if (old_fdl != curwin->w_p_fdl)
	newFoldLevel();

}



    static void nv_ver_scrollbar(cmdarg_T *cap)
{
    if (cap->oap->op_type != OP_NOP)
	clearopbeep(cap->oap);

    
    gui_do_scroll();
}


    static void nv_hor_scrollbar(cmdarg_T *cap)
{
    if (cap->oap->op_type != OP_NOP)
	clearopbeep(cap->oap);

    
    gui_do_horiz_scroll(scrollbar_value, FALSE);
}




    static void nv_tabline(cmdarg_T *cap)
{
    if (cap->oap->op_type != OP_NOP)
	clearopbeep(cap->oap);

    
    goto_tabpage(current_tab);
}


    static void nv_tabmenu(cmdarg_T *cap)
{
    if (cap->oap->op_type != OP_NOP)
	clearopbeep(cap->oap);

    
    handle_tabmenu();
}


    void handle_tabmenu(void)
{
    switch (current_tabmenu)
    {
	case TABLINE_MENU_CLOSE:
	    if (current_tab == 0)
		do_cmdline_cmd((char_u *)"tabclose");
	    else {
		vim_snprintf((char *)IObuff, IOSIZE, "tabclose %d", current_tab);
		do_cmdline_cmd(IObuff);
	    }
	    break;

	case TABLINE_MENU_NEW:
	    if (current_tab == 0)
		do_cmdline_cmd((char_u *)"$tabnew");
	    else {
		vim_snprintf((char *)IObuff, IOSIZE, "%dtabnew", current_tab - 1);
		do_cmdline_cmd(IObuff);
	    }
	    break;

	case TABLINE_MENU_OPEN:
	    if (current_tab == 0)
		do_cmdline_cmd((char_u *)"browse $tabnew");
	    else {
		vim_snprintf((char *)IObuff, IOSIZE, "browse %dtabnew", current_tab - 1);
		do_cmdline_cmd(IObuff);
	    }
	    break;
    }
}



    static void nv_exmode(cmdarg_T *cap)
{
    
    if (VIsual_active)
	vim_beep(BO_EX);
    else if (!checkclearop(cap->oap))
	do_exmode(FALSE);
}


    static void nv_colon(cmdarg_T *cap)
{
    int	old_p_im;
    int	cmd_result;
    int	is_cmdkey = cap->cmdchar == K_COMMAND;

    if (VIsual_active && !is_cmdkey)
	nv_operator(cap);
    else {
	if (cap->oap->op_type != OP_NOP)
	{
	    
	    cap->oap->motion_type = MCHAR;
	    cap->oap->inclusive = FALSE;
	}
	else if (cap->count0 && !is_cmdkey)
	{
	    
	    stuffcharReadbuff('.');
	    if (cap->count0 > 1)
	    {
		stuffReadbuff((char_u *)",.+");
		stuffnumReadbuff((long)cap->count0 - 1L);
	    }
	}

	
	if (KeyTyped)
	    compute_cmdrow();

	old_p_im = p_im;

	
	cmd_result = do_cmdline(NULL, is_cmdkey ? getcmdkeycmd : getexline, NULL, cap->oap->op_type != OP_NOP ? DOCMD_KEEPLINE : 0);

	
	if (p_im != old_p_im)
	{
	    if (p_im)
		restart_edit = 'i';
	    else restart_edit = 0;
	}

	if (cmd_result == FAIL)
	    
	    clearop(cap->oap);
	else if (cap->oap->op_type != OP_NOP && (cap->oap->start.lnum > curbuf->b_ml.ml_line_count || cap->oap->start.col > (colnr_T)STRLEN(ml_get(cap->oap->start.lnum))


		    || did_emsg ))
	    
	    clearopbeep(cap->oap);
    }
}


    static void nv_ctrlg(cmdarg_T *cap)
{
    if (VIsual_active)	
    {
	VIsual_select = !VIsual_select;
	trigger_modechanged();
	showmode();
    }
    else if (!checkclearop(cap->oap))
	
	fileinfo((int)cap->count0, FALSE, TRUE);
}


    static void nv_ctrlh(cmdarg_T *cap)
{
    if (VIsual_active && VIsual_select)
    {
	cap->cmdchar = 'x';	
	v_visop(cap);
    }
    else nv_left(cap);
}


    static void nv_clear(cmdarg_T *cap)
{
    if (!checkclearop(cap->oap))
    {

	
	syn_stack_free_all(curwin->w_s);

	{
	    win_T *wp;

	    FOR_ALL_WINDOWS(wp)
		wp->w_s->b_syn_slow = FALSE;
	}


	redraw_later(CLEAR);


	if (!gui.in_use)

	    resize_console_buf();

    }
}


    static void nv_ctrlo(cmdarg_T *cap)
{
    if (VIsual_active && VIsual_select)
    {
	VIsual_select = FALSE;
	trigger_modechanged();
	showmode();
	restart_VIsual_select = 2;	
    }
    else {
	cap->count1 = -cap->count1;
	nv_pcmark(cap);
    }
}


    static void nv_hat(cmdarg_T *cap)
{
    if (!checkclearopq(cap->oap))
	(void)buflist_getfile((int)cap->count0, (linenr_T)0, GETF_SETMARK|GETF_ALT, FALSE);
}


    static void nv_Zet(cmdarg_T *cap)
{
    if (!checkclearopq(cap->oap))
    {
	switch (cap->nchar)
	{
			
	    case 'Z':	do_cmdline_cmd((char_u *)"x");
			break;

			
	    case 'Q':	do_cmdline_cmd((char_u *)"q!");
			break;

	    default:	clearopbeep(cap->oap);
	}
    }
}


    void do_nv_ident(int c1, int c2)
{
    oparg_T	oa;
    cmdarg_T	ca;

    clear_oparg(&oa);
    CLEAR_FIELD(ca);
    ca.oap = &oa;
    ca.cmdchar = c1;
    ca.nchar = c2;
    nv_ident(&ca);
}


    static void nv_ident(cmdarg_T *cap)
{
    char_u	*ptr = NULL;
    char_u	*buf;
    unsigned	buflen;
    char_u	*newbuf;
    char_u	*p;
    char_u	*kp;		
    int		kp_help;	
    int		kp_ex;		
    int		n = 0;		
    int		cmdchar;
    int		g_cmd;		
    int		tag_cmd = FALSE;
    char_u	*aux_ptr;
    int		isman;
    int		isman_s;

    if (cap->cmdchar == 'g')	
    {
	cmdchar = cap->nchar;
	g_cmd = TRUE;
    }
    else {
	cmdchar = cap->cmdchar;
	g_cmd = FALSE;
    }

    if (cmdchar == POUND)	
	cmdchar = '#';

    
    if (cmdchar == ']' || cmdchar == Ctrl_RSB || cmdchar == 'K')
    {
	if (VIsual_active && get_visual_text(cap, &ptr, &n) == FAIL)
	    return;
	if (checkclearopq(cap->oap))
	    return;
    }

    if (ptr == NULL && (n = find_ident_under_cursor(&ptr, (cmdchar == '*' || cmdchar == '#')
				 ? FIND_IDENT|FIND_STRING : FIND_IDENT)) == 0)
    {
	clearop(cap->oap);
	return;
    }

    
    
    
    kp = (*curbuf->b_p_kp == NUL ? p_kp : curbuf->b_p_kp);
    kp_help = (*kp == NUL || STRCMP(kp, ":he") == 0 || STRCMP(kp, ":help") == 0);
    if (kp_help && *skipwhite(ptr) == NUL)
    {
	emsg(_(e_noident));	 
	return;
    }
    kp_ex = (*kp == ':');
    buflen = (unsigned)(n * 2 + 30 + STRLEN(kp));
    buf = alloc(buflen);
    if (buf == NULL)
	return;
    buf[0] = NUL;

    switch (cmdchar)
    {
	case '*':
	case '#':
	    
	    setpcmark();
	    curwin->w_cursor.col = (colnr_T) (ptr - ml_get_curline());

	    if (!g_cmd && vim_iswordp(ptr))
		STRCPY(buf, "\\<");
	    no_smartcase = TRUE;	
	    break;

	case 'K':
	    if (kp_help)
		STRCPY(buf, "he! ");
	    else if (kp_ex)
	    {
		if (cap->count0 != 0)
		    vim_snprintf((char *)buf, buflen, "%s %ld", kp, cap->count0);
		else STRCPY(buf, kp);
		STRCAT(buf, " ");
	    }
	    else {
		
		
		while (*ptr == '-' && n > 0)
		{
		    ++ptr;
		    --n;
		}
		if (n == 0)
		{
		    emsg(_(e_noident));	 
		    vim_free(buf);
		    return;
		}

		
		
		isman = (STRCMP(kp, "man") == 0);
		isman_s = (STRCMP(kp, "man -s") == 0);
		if (cap->count0 != 0 && !(isman || isman_s))
		    sprintf((char *)buf, ".,.+%ld", cap->count0 - 1);

		STRCAT(buf, "! ");
		if (cap->count0 == 0 && isman_s)
		    STRCAT(buf, "man");
		else STRCAT(buf, kp);
		STRCAT(buf, " ");
		if (cap->count0 != 0 && (isman || isman_s))
		{
		    sprintf((char *)buf + STRLEN(buf), "%ld", cap->count0);
		    STRCAT(buf, " ");
		}
	    }
	    break;

	case ']':
	    tag_cmd = TRUE;

	    if (p_cst)
		STRCPY(buf, "cstag ");
	    else  STRCPY(buf, "ts ");

	    break;

	default:
	    tag_cmd = TRUE;
	    if (curbuf->b_help)
		STRCPY(buf, "he! ");
	    else {
		if (g_cmd)
		    STRCPY(buf, "tj ");
		else if (cap->count0 == 0)
		    STRCPY(buf, "ta ");
		else sprintf((char *)buf, ":%ldta ", cap->count0);
	    }
    }

    
    if (cmdchar == 'K' && !kp_help)
    {
	ptr = vim_strnsave(ptr, n);
	if (kp_ex)
	    
	    p = vim_strsave_fnameescape(ptr, VSE_NONE);
	else  p = vim_strsave_shellescape(ptr, TRUE, TRUE);

	vim_free(ptr);
	if (p == NULL)
	{
	    vim_free(buf);
	    return;
	}
	newbuf = vim_realloc(buf, STRLEN(buf) + STRLEN(p) + 1);
	if (newbuf == NULL)
	{
	    vim_free(buf);
	    vim_free(p);
	    return;
	}
	buf = newbuf;
	STRCAT(buf, p);
	vim_free(p);
    }
    else {
	if (cmdchar == '*')
	    aux_ptr = (char_u *)(magic_isset() ? "/.*~[^$\\" : "/^$\\");
	else if (cmdchar == '#')
	    aux_ptr = (char_u *)(magic_isset() ? "/?.*~[^$\\" : "/?^$\\");
	else if (tag_cmd)
	{
	    if (curbuf->b_help)
		
		aux_ptr = (char_u *)"";
	    else aux_ptr = (char_u *)"\\|\"\n[";
	}
	else aux_ptr = (char_u *)"\\|\"\n*?[";

	p = buf + STRLEN(buf);
	while (n-- > 0)
	{
	    
	    if (vim_strchr(aux_ptr, *ptr) != NULL)
		*p++ = '\\';
	    
	    
	    if (has_mbyte)
	    {
		int i;
		int len = (*mb_ptr2len)(ptr) - 1;

		for (i = 0; i < len && n >= 1; ++i, --n)
		    *p++ = *ptr++;
	    }
	    *p++ = *ptr++;
	}
	*p = NUL;
    }

    
    if (cmdchar == '*' || cmdchar == '#')
    {
	if (!g_cmd && (has_mbyte ? vim_iswordp(mb_prevptr(ml_get_curline(), ptr))
		    : vim_iswordc(ptr[-1])))
	    STRCAT(buf, "\\>");

	
	init_history();
	add_to_history(HIST_SEARCH, buf, TRUE, NUL);

	(void)normal_search(cap, cmdchar == '*' ? '/' : '?', buf, 0, NULL);
    }
    else {
	g_tag_at_cursor = TRUE;
	do_cmdline_cmd(buf);
	g_tag_at_cursor = FALSE;
    }

    vim_free(buf);
}


    int get_visual_text( cmdarg_T	*cap, char_u	**pp, int		*lenp)



{
    if (VIsual_mode != 'V')
	unadjust_for_sel();
    if (VIsual.lnum != curwin->w_cursor.lnum)
    {
	if (cap != NULL)
	    clearopbeep(cap->oap);
	return FAIL;
    }
    if (VIsual_mode == 'V')
    {
	*pp = ml_get_curline();
	*lenp = (int)STRLEN(*pp);
    }
    else {
	if (LT_POS(curwin->w_cursor, VIsual))
	{
	    *pp = ml_get_pos(&curwin->w_cursor);
	    *lenp = VIsual.col - curwin->w_cursor.col + 1;
	}
	else {
	    *pp = ml_get_pos(&VIsual);
	    *lenp = curwin->w_cursor.col - VIsual.col + 1;
	}
	if (has_mbyte)
	    
	    *lenp += (*mb_ptr2len)(*pp + (*lenp - 1)) - 1;
    }
    reset_VIsual_and_resel();
    return OK;
}


    static void nv_tagpop(cmdarg_T *cap)
{
    if (!checkclearopq(cap->oap))
	do_tag((char_u *)"", DT_POP, (int)cap->count1, FALSE, TRUE);
}


    static void nv_scroll(cmdarg_T *cap)
{
    int		used = 0;
    long	n;

    linenr_T	lnum;

    int		half;

    cap->oap->motion_type = MLINE;
    setpcmark();

    if (cap->cmdchar == 'L')
    {
	validate_botline();	    
	curwin->w_cursor.lnum = curwin->w_botline - 1;
	if (cap->count1 - 1 >= curwin->w_cursor.lnum)
	    curwin->w_cursor.lnum = 1;
	else {

	    if (hasAnyFolding(curwin))
	    {
		
		for (n = cap->count1 - 1; n > 0 && curwin->w_cursor.lnum > curwin->w_topline; --n)
		{
		    (void)hasFolding(curwin->w_cursor.lnum, &curwin->w_cursor.lnum, NULL);
		    --curwin->w_cursor.lnum;
		}
	    }
	    else  curwin->w_cursor.lnum -= cap->count1 - 1;

	}
    }
    else {
	if (cap->cmdchar == 'M')
	{

	    
	    used -= diff_check_fill(curwin, curwin->w_topline)
							  - curwin->w_topfill;

	    validate_botline();	    
	    half = (curwin->w_height - curwin->w_empty_rows + 1) / 2;
	    for (n = 0; curwin->w_topline + n < curbuf->b_ml.ml_line_count; ++n)
	    {

		
		
		if (n > 0 && used + diff_check_fill(curwin, curwin->w_topline + n) / 2 >= half)
		{
		    --n;
		    break;
		}

		used += plines(curwin->w_topline + n);
		if (used >= half)
		    break;

		if (hasFolding(curwin->w_topline + n, NULL, &lnum))
		    n = lnum - curwin->w_topline;

	    }
	    if (n > 0 && used > curwin->w_height)
		--n;
	}
	else  {
	    n = cap->count1 - 1;

	    if (hasAnyFolding(curwin))
	    {
		
		lnum = curwin->w_topline;
		while (n-- > 0 && lnum < curwin->w_botline - 1)
		{
		    (void)hasFolding(lnum, NULL, &lnum);
		    ++lnum;
		}
		n = lnum - curwin->w_topline;
	    }

	}
	curwin->w_cursor.lnum = curwin->w_topline + n;
	if (curwin->w_cursor.lnum > curbuf->b_ml.ml_line_count)
	    curwin->w_cursor.lnum = curbuf->b_ml.ml_line_count;
    }

    
    if (cap->oap->op_type == OP_NOP)
	cursor_correct();
    beginline(BL_SOL | BL_FIX);
}


    static void nv_right(cmdarg_T *cap)
{
    long	n;
    int		past_line;

    if (mod_mask & (MOD_MASK_SHIFT | MOD_MASK_CTRL))
    {
	
	if (mod_mask & MOD_MASK_CTRL)
	    cap->arg = TRUE;
	nv_wordcmd(cap);
	return;
    }

    cap->oap->motion_type = MCHAR;
    cap->oap->inclusive = FALSE;
    past_line = (VIsual_active && *p_sel != 'o');

    
    if (virtual_active())
	past_line = 0;

    for (n = cap->count1; n > 0; --n)
    {
	if ((!past_line && oneright() == FAIL)
		|| (past_line && *ml_get_cursor() == NUL)
		)
	{
	    
	    if (       ((cap->cmdchar == ' ' && vim_strchr(p_ww, 's') != NULL)
			|| (cap->cmdchar == 'l' && vim_strchr(p_ww, 'l') != NULL)
			|| (cap->cmdchar == K_RIGHT && vim_strchr(p_ww, '>') != NULL))
		    && curwin->w_cursor.lnum < curbuf->b_ml.ml_line_count)
	    {
		
		
		
		if (	   cap->oap->op_type != OP_NOP && !cap->oap->inclusive && !LINEEMPTY(curwin->w_cursor.lnum))

		    cap->oap->inclusive = TRUE;
		else {
		    ++curwin->w_cursor.lnum;
		    curwin->w_cursor.col = 0;
		    curwin->w_cursor.coladd = 0;
		    curwin->w_set_curswant = TRUE;
		    cap->oap->inclusive = FALSE;
		}
		continue;
	    }
	    if (cap->oap->op_type == OP_NOP)
	    {
		
		if (n == cap->count1)
		    beep_flush();
	    }
	    else {
		if (!LINEEMPTY(curwin->w_cursor.lnum))
		    cap->oap->inclusive = TRUE;
	    }
	    break;
	}
	else if (past_line)
	{
	    curwin->w_set_curswant = TRUE;
	    if (virtual_active())
		oneright();
	    else {
		if (has_mbyte)
		    curwin->w_cursor.col += (*mb_ptr2len)(ml_get_cursor());
		else ++curwin->w_cursor.col;
	    }
	}
    }

    if (n != cap->count1 && (fdo_flags & FDO_HOR) && KeyTyped && cap->oap->op_type == OP_NOP)
	foldOpenCursor();

}


    static void nv_left(cmdarg_T *cap)
{
    long	n;

    if (mod_mask & (MOD_MASK_SHIFT | MOD_MASK_CTRL))
    {
	
	if (mod_mask & MOD_MASK_CTRL)
	    cap->arg = 1;
	nv_bck_word(cap);
	return;
    }

    cap->oap->motion_type = MCHAR;
    cap->oap->inclusive = FALSE;
    for (n = cap->count1; n > 0; --n)
    {
	if (oneleft() == FAIL)
	{
	    
	    
	    
	    if (       (((cap->cmdchar == K_BS || cap->cmdchar == Ctrl_H)
			    && vim_strchr(p_ww, 'b') != NULL)
			|| (cap->cmdchar == 'h' && vim_strchr(p_ww, 'h') != NULL)
			|| (cap->cmdchar == K_LEFT && vim_strchr(p_ww, '<') != NULL))
		    && curwin->w_cursor.lnum > 1)
	    {
		--(curwin->w_cursor.lnum);
		coladvance((colnr_T)MAXCOL);
		curwin->w_set_curswant = TRUE;

		
		
		
		
		if (	   (cap->oap->op_type == OP_DELETE || cap->oap->op_type == OP_CHANGE)
			&& !LINEEMPTY(curwin->w_cursor.lnum))
		{
		    char_u *cp = ml_get_cursor();

		    if (*cp != NUL)
		    {
			if (has_mbyte)
			    curwin->w_cursor.col += (*mb_ptr2len)(cp);
			else ++curwin->w_cursor.col;
		    }
		    cap->retval |= CA_NO_ADJ_OP_END;
		}
		continue;
	    }
	    
	    else if (cap->oap->op_type == OP_NOP && n == cap->count1)
		beep_flush();
	    break;
	}
    }

    if (n != cap->count1 && (fdo_flags & FDO_HOR) && KeyTyped && cap->oap->op_type == OP_NOP)
	foldOpenCursor();

}


    static void nv_up(cmdarg_T *cap)
{
    if (mod_mask & MOD_MASK_SHIFT)
    {
	
	cap->arg = BACKWARD;
	nv_page(cap);
    }
    else {
	cap->oap->motion_type = MLINE;
	if (cursor_up(cap->count1, cap->oap->op_type == OP_NOP) == FAIL)
	    clearopbeep(cap->oap);
	else if (cap->arg)
	    beginline(BL_WHITE | BL_FIX);
    }
}


    static void nv_down(cmdarg_T *cap)
{
    if (mod_mask & MOD_MASK_SHIFT)
    {
	
	cap->arg = FORWARD;
	nv_page(cap);
    }

    
    else if (bt_quickfix(curbuf) && cap->cmdchar == CAR)
	qf_view_result(FALSE);

    else {

	
	if (cmdwin_type != 0 && cap->cmdchar == CAR)
	    cmdwin_result = CAR;
	else    if (bt_prompt(curbuf) && cap->cmdchar == CAR && curwin->w_cursor.lnum == curbuf->b_ml.ml_line_count)




	{
	    invoke_prompt_callback();
	    if (restart_edit == 0)
		restart_edit = 'a';
	}
	else  {

	    cap->oap->motion_type = MLINE;
	    if (cursor_down(cap->count1, cap->oap->op_type == OP_NOP) == FAIL)
		clearopbeep(cap->oap);
	    else if (cap->arg)
		beginline(BL_WHITE | BL_FIX);
	}
    }
}



    static void nv_gotofile(cmdarg_T *cap)
{
    char_u	*ptr;
    linenr_T	lnum = -1;

    if (text_locked())
    {
	clearopbeep(cap->oap);
	text_locked_msg();
	return;
    }
    if (curbuf_locked())
    {
	clearop(cap->oap);
	return;
    }

    if (ERROR_IF_TERM_POPUP_WINDOW)
	return;


    ptr = grab_file_name(cap->count1, &lnum);

    if (ptr != NULL)
    {
	
	if (curbufIsChanged() && curbuf->b_nwindows <= 1 && !buf_hide(curbuf))
	    (void)autowrite(curbuf, FALSE);
	setpcmark();
	if (do_ecmd(0, ptr, NULL, NULL, ECMD_LAST, buf_hide(curbuf) ? ECMD_HIDE : 0, curwin) == OK && cap->nchar == 'F' && lnum >= 0)

	{
	    curwin->w_cursor.lnum = lnum;
	    check_cursor_lnum();
	    beginline(BL_SOL | BL_FIX);
	}
	vim_free(ptr);
    }
    else clearop(cap->oap);
}



    static void nv_end(cmdarg_T *cap)
{
    if (cap->arg || (mod_mask & MOD_MASK_CTRL))	
    {
	cap->arg = TRUE;
	nv_goto(cap);
	cap->count1 = 1;		
    }
    nv_dollar(cap);
}


    static void nv_dollar(cmdarg_T *cap)
{
    cap->oap->motion_type = MCHAR;
    cap->oap->inclusive = TRUE;
    
    
    
    if (!virtual_active() || gchar_cursor() != NUL || cap->oap->op_type == OP_NOP)
	curwin->w_curswant = MAXCOL;	
    if (cursor_down((long)(cap->count1 - 1), cap->oap->op_type == OP_NOP) == FAIL)
	clearopbeep(cap->oap);

    else if ((fdo_flags & FDO_HOR) && KeyTyped && cap->oap->op_type == OP_NOP)
	foldOpenCursor();

}


    static void nv_search(cmdarg_T *cap)
{
    oparg_T	*oap = cap->oap;
    pos_T	save_cursor = curwin->w_cursor;

    if (cap->cmdchar == '?' && cap->oap->op_type == OP_ROT13)
    {
	
	cap->cmdchar = 'g';
	cap->nchar = '?';
	nv_operator(cap);
	return;
    }

    
    
    cap->searchbuf = getcmdline(cap->cmdchar, cap->count1, 0, TRUE);

    if (cap->searchbuf == NULL)
    {
	clearop(oap);
	return;
    }

    (void)normal_search(cap, cap->cmdchar, cap->searchbuf, (cap->arg || !EQUAL_POS(save_cursor, curwin->w_cursor))
						      ? 0 : SEARCH_MARK, NULL);
}


    static void nv_next(cmdarg_T *cap)
{
    pos_T   old = curwin->w_cursor;
    int	    wrapped = FALSE;
    int	    i = normal_search(cap, 0, NULL, SEARCH_MARK | cap->arg, &wrapped);

    if (i == 1 && !wrapped && EQUAL_POS(old, curwin->w_cursor))
    {
	
	
	
	cap->count1 += 1;
	(void)normal_search(cap, 0, NULL, SEARCH_MARK | cap->arg, NULL);
	cap->count1 -= 1;
    }
}


    static int normal_search( cmdarg_T	*cap, int		dir, char_u	*pat, int		opt, int		*wrapped)





{
    int		i;
    searchit_arg_T sia;

    cap->oap->motion_type = MCHAR;
    cap->oap->inclusive = FALSE;
    cap->oap->use_reg_one = TRUE;
    curwin->w_set_curswant = TRUE;

    CLEAR_FIELD(sia);
    i = do_search(cap->oap, dir, dir, pat, cap->count1, opt | SEARCH_OPT | SEARCH_ECHO | SEARCH_MSG, &sia);
    if (wrapped != NULL)
	*wrapped = sia.sa_wrapped;
    if (i == 0)
	clearop(cap->oap);
    else {
	if (i == 2)
	    cap->oap->motion_type = MLINE;
	curwin->w_cursor.coladd = 0;

	if (cap->oap->op_type == OP_NOP && (fdo_flags & FDO_SEARCH) && KeyTyped)
	    foldOpenCursor();

    }

    
    
    check_cursor();
    return i;
}


    static void nv_csearch(cmdarg_T *cap)
{
    int		t_cmd;

    if (cap->cmdchar == 't' || cap->cmdchar == 'T')
	t_cmd = TRUE;
    else t_cmd = FALSE;

    cap->oap->motion_type = MCHAR;
    if (IS_SPECIAL(cap->nchar) || searchc(cap, t_cmd) == FAIL)
	clearopbeep(cap->oap);
    else {
	curwin->w_set_curswant = TRUE;
	
	if (gchar_cursor() == TAB && virtual_active() && cap->arg == FORWARD && (t_cmd || cap->oap->op_type != OP_NOP))
	{
	    colnr_T	scol, ecol;

	    getvcol(curwin, &curwin->w_cursor, &scol, NULL, &ecol);
	    curwin->w_cursor.coladd = ecol - scol;
	}
	else curwin->w_cursor.coladd = 0;
	adjust_for_sel(cap);

	if ((fdo_flags & FDO_HOR) && KeyTyped && cap->oap->op_type == OP_NOP)
	    foldOpenCursor();

    }
}


    static void nv_brackets(cmdarg_T *cap)
{
    pos_T	new_pos = {0, 0, 0};
    pos_T	prev_pos;
    pos_T	*pos = NULL;	    
    pos_T	old_pos;	    
    int		flag;
    long	n;
    int		findc;
    int		c;

    cap->oap->motion_type = MCHAR;
    cap->oap->inclusive = FALSE;
    old_pos = curwin->w_cursor;
    curwin->w_cursor.coladd = 0;    


    
    if (cap->nchar == 'f')
	nv_gotofile(cap);
    else     if (vim_strchr((char_u *)





		"iI\005dD\067",  "iI\011dD\004",  cap->nchar) != NULL)



    {
	char_u	*ptr;
	int	len;

	if ((len = find_ident_under_cursor(&ptr, FIND_IDENT)) == 0)
	    clearop(cap->oap);
	else {
	    find_pattern_in_path(ptr, 0, len, TRUE, cap->count0 == 0 ? !isupper(cap->nchar) : FALSE, ((cap->nchar & 0xf) == ('d' & 0xf)) ?  FIND_DEFINE : FIND_ANY, cap->count1, isupper(cap->nchar) ? ACTION_SHOW_ALL :



			    islower(cap->nchar) ? ACTION_SHOW : ACTION_GOTO, cap->cmdchar == ']' ? curwin->w_cursor.lnum + 1 : (linenr_T)1, (linenr_T)MAXLNUM);

	    curwin->w_set_curswant = TRUE;
	}
    }
    else    if (  (cap->cmdchar == '[' && vim_strchr((char_u *)"{(*/#mM", cap->nchar) != NULL)




	    || (cap->cmdchar == ']' && vim_strchr((char_u *)"})*/#mM", cap->nchar) != NULL))
    {
	if (cap->nchar == '*')
	    cap->nchar = '/';
	prev_pos.lnum = 0;
	if (cap->nchar == 'm' || cap->nchar == 'M')
	{
	    if (cap->cmdchar == '[')
		findc = '{';
	    else findc = '}';
	    n = 9999;
	}
	else {
	    findc = cap->nchar;
	    n = cap->count1;
	}
	for ( ; n > 0; --n)
	{
	    if ((pos = findmatchlimit(cap->oap, findc, (cap->cmdchar == '[') ? FM_BACKWARD : FM_FORWARD, 0)) == NULL)
	    {
		if (new_pos.lnum == 0)	
		{
		    if (cap->nchar != 'm' && cap->nchar != 'M')
			clearopbeep(cap->oap);
		}
		else pos = &new_pos;
		break;
	    }
	    prev_pos = new_pos;
	    curwin->w_cursor = *pos;
	    new_pos = *pos;
	}
	curwin->w_cursor = old_pos;

	
	if (cap->nchar == 'm' || cap->nchar == 'M')
	{
	    
	    int	    norm = ((findc == '{') == (cap->nchar == 'm'));

	    n = cap->count1;
	    
	    if (prev_pos.lnum != 0)
	    {
		pos = &prev_pos;
		curwin->w_cursor = prev_pos;
		if (norm)
		    --n;
	    }
	    else pos = NULL;
	    while (n > 0)
	    {
		for (;;)
		{
		    if ((findc == '{' ? dec_cursor() : inc_cursor()) < 0)
		    {
			
			if (pos == NULL)
			    clearopbeep(cap->oap);
			n = 0;
			break;
		    }
		    c = gchar_cursor();
		    if (c == '{' || c == '}')
		    {
			
			
			if ((c == findc && norm) || (n == 1 && !norm))
			{
			    new_pos = curwin->w_cursor;
			    pos = &new_pos;
			    n = 0;
			}
			
			
			else if (new_pos.lnum == 0)
			{
			    new_pos = curwin->w_cursor;
			    pos = &new_pos;
			}
			
			else if ((pos = findmatchlimit(cap->oap, findc, (cap->cmdchar == '[') ? FM_BACKWARD : FM_FORWARD, 0)) == NULL)

			    n = 0;
			else curwin->w_cursor = *pos;
			break;
		    }
		}
		--n;
	    }
	    curwin->w_cursor = old_pos;
	    if (pos == NULL && new_pos.lnum != 0)
		clearopbeep(cap->oap);
	}
	if (pos != NULL)
	{
	    setpcmark();
	    curwin->w_cursor = *pos;
	    curwin->w_set_curswant = TRUE;

	    if ((fdo_flags & FDO_BLOCK) && KeyTyped && cap->oap->op_type == OP_NOP)
		foldOpenCursor();

	}
    }

    
    else if (cap->nchar == '[' || cap->nchar == ']')
    {
	if (cap->nchar == cap->cmdchar)		    
	    flag = '{';
	else flag = '}';

	curwin->w_set_curswant = TRUE;
	
	if (!findpar(&cap->oap->inclusive, cap->arg, cap->count1, flag, (cap->oap->op_type != OP_NOP && cap->arg == FORWARD && flag == '{')))

	    clearopbeep(cap->oap);
	else {
	    if (cap->oap->op_type == OP_NOP)
		beginline(BL_WHITE | BL_FIX);

	    if ((fdo_flags & FDO_BLOCK) && KeyTyped && cap->oap->op_type == OP_NOP)
		foldOpenCursor();

	}
    }

    
    else if (cap->nchar == 'p' || cap->nchar == 'P')
    {
	nv_put_opt(cap, TRUE);
    }

    
    else if (cap->nchar == '\'' || cap->nchar == '`')
    {
	pos = &curwin->w_cursor;
	for (n = cap->count1; n > 0; --n)
	{
	    prev_pos = *pos;
	    pos = getnextmark(pos, cap->cmdchar == '[' ? BACKWARD : FORWARD, cap->nchar == '\'');
	    if (pos == NULL)
		break;
	}
	if (pos == NULL)
	    pos = &prev_pos;
	nv_cursormark(cap, cap->nchar == '\'', pos);
    }

    
    else if (cap->nchar >= K_RIGHTRELEASE && cap->nchar <= K_LEFTMOUSE)
    {
	(void)do_mouse(cap->oap, cap->nchar, (cap->cmdchar == ']') ? FORWARD : BACKWARD, cap->count1, PUT_FIXINDENT);

    }


    
    else if (cap->nchar == 'z')
    {
	if (foldMoveTo(FALSE, cap->cmdchar == ']' ? FORWARD : BACKWARD, cap->count1) == FAIL)
	    clearopbeep(cap->oap);
    }



    
    else if (cap->nchar == 'c')
    {
	if (diff_move_to(cap->cmdchar == ']' ? FORWARD : BACKWARD, cap->count1) == FAIL)
	    clearopbeep(cap->oap);
    }



    
    else if (cap->nchar == 's' || cap->nchar == 'S')
    {
	setpcmark();
	for (n = 0; n < cap->count1; ++n)
	    if (spell_move_to(curwin, cap->cmdchar == ']' ? FORWARD : BACKWARD, cap->nchar == 's' ? TRUE : FALSE, FALSE, NULL) == 0)
	    {
		clearopbeep(cap->oap);
		break;
	    }
	    else curwin->w_set_curswant = TRUE;

	if (cap->oap->op_type == OP_NOP && (fdo_flags & FDO_SEARCH) && KeyTyped)
	    foldOpenCursor();

    }


    
    else clearopbeep(cap->oap);
}


    static void nv_percent(cmdarg_T *cap)
{
    pos_T	*pos;

    linenr_T	lnum = curwin->w_cursor.lnum;


    cap->oap->inclusive = TRUE;
    if (cap->count0)	    
    {
	if (cap->count0 > 100)
	    clearopbeep(cap->oap);
	else {
	    cap->oap->motion_type = MLINE;
	    setpcmark();
	    
	    
	    
	    
	    if (curbuf->b_ml.ml_line_count >= 21474836)
		curwin->w_cursor.lnum = (curbuf->b_ml.ml_line_count + 99L)
							 / 100L * cap->count0;
	    else curwin->w_cursor.lnum = (curbuf->b_ml.ml_line_count * cap->count0 + 99L) / 100L;

	    if (curwin->w_cursor.lnum < 1)
		curwin->w_cursor.lnum = 1;
	    if (curwin->w_cursor.lnum > curbuf->b_ml.ml_line_count)
		curwin->w_cursor.lnum = curbuf->b_ml.ml_line_count;
	    beginline(BL_SOL | BL_FIX);
	}
    }
    else		     {
	cap->oap->motion_type = MCHAR;
	cap->oap->use_reg_one = TRUE;
	if ((pos = findmatch(cap->oap, NUL)) == NULL)
	    clearopbeep(cap->oap);
	else {
	    setpcmark();
	    curwin->w_cursor = *pos;
	    curwin->w_set_curswant = TRUE;
	    curwin->w_cursor.coladd = 0;
	    adjust_for_sel(cap);
	}
    }

    if (cap->oap->op_type == OP_NOP && lnum != curwin->w_cursor.lnum && (fdo_flags & FDO_PERCENT)

	    && KeyTyped)
	foldOpenCursor();

}


    static void nv_brace(cmdarg_T *cap)
{
    cap->oap->motion_type = MCHAR;
    cap->oap->use_reg_one = TRUE;
    
    cap->oap->inclusive = FALSE;
    curwin->w_set_curswant = TRUE;

    if (findsent(cap->arg, cap->count1) == FAIL)
	clearopbeep(cap->oap);
    else {
	
	adjust_cursor(cap->oap);
	curwin->w_cursor.coladd = 0;

	if ((fdo_flags & FDO_BLOCK) && KeyTyped && cap->oap->op_type == OP_NOP)
	    foldOpenCursor();

    }
}


    static void nv_mark(cmdarg_T *cap)
{
    if (!checkclearop(cap->oap))
    {
	if (setmark(cap->nchar) == FAIL)
	    clearopbeep(cap->oap);
    }
}


    static void nv_findpar(cmdarg_T *cap)
{
    cap->oap->motion_type = MCHAR;
    cap->oap->inclusive = FALSE;
    cap->oap->use_reg_one = TRUE;
    curwin->w_set_curswant = TRUE;
    if (!findpar(&cap->oap->inclusive, cap->arg, cap->count1, NUL, FALSE))
	clearopbeep(cap->oap);
    else {
	curwin->w_cursor.coladd = 0;

	if ((fdo_flags & FDO_BLOCK) && KeyTyped && cap->oap->op_type == OP_NOP)
	    foldOpenCursor();

    }
}


    static void nv_undo(cmdarg_T *cap)
{
    if (cap->oap->op_type == OP_LOWER || VIsual_active)
    {
	
	cap->cmdchar = 'g';
	cap->nchar = 'u';
	nv_operator(cap);
    }
    else nv_kundo(cap);
}


    static void nv_kundo(cmdarg_T *cap)
{
    if (!checkclearopq(cap->oap))
    {

	if (bt_prompt(curbuf))
	{
	    clearopbeep(cap->oap);
	    return;
	}

	u_undo((int)cap->count1);
	curwin->w_set_curswant = TRUE;
    }
}


    static void nv_replace(cmdarg_T *cap)
{
    char_u	*ptr;
    int		had_ctrl_v;
    long	n;

    if (checkclearop(cap->oap))
	return;

    if (bt_prompt(curbuf) && !prompt_curpos_editable())
    {
	clearopbeep(cap->oap);
	return;
    }


    
    if (cap->nchar == Ctrl_V)
    {
	had_ctrl_v = Ctrl_V;
	cap->nchar = get_literal(FALSE);
	
	if (cap->nchar > DEL)
	    had_ctrl_v = NUL;
    }
    else had_ctrl_v = NUL;

    
    if (IS_SPECIAL(cap->nchar))
    {
	clearopbeep(cap->oap);
	return;
    }

    
    if (VIsual_active)
    {
	if (got_int)
	    reset_VIsual();
	if (had_ctrl_v)
	{
	    
	    
	    if (cap->nchar == CAR)
		cap->nchar = REPLACE_CR_NCHAR;
	    else if (cap->nchar == NL)
		cap->nchar = REPLACE_NL_NCHAR;
	}
	nv_operator(cap);
	return;
    }

    
    if (virtual_active())
    {
	if (u_save_cursor() == FAIL)
	    return;
	if (gchar_cursor() == NUL)
	{
	    
	    coladvance_force((colnr_T)(getviscol() + cap->count1));
	    curwin->w_cursor.col -= cap->count1;
	}
	else if (gchar_cursor() == TAB)
	    coladvance_force(getviscol());
    }

    
    ptr = ml_get_cursor();
    if (STRLEN(ptr) < (unsigned)cap->count1 || (has_mbyte && mb_charlen(ptr) < cap->count1))
    {
	clearopbeep(cap->oap);
	return;
    }

    
    if (had_ctrl_v != Ctrl_V && cap->nchar == '\t' && (curbuf->b_p_et || p_sta))
    {
	stuffnumReadbuff(cap->count1);
	stuffcharReadbuff('R');
	stuffcharReadbuff('\t');
	stuffcharReadbuff(ESC);
	return;
    }

    
    if (u_save_cursor() == FAIL)
	return;

    if (had_ctrl_v != Ctrl_V && (cap->nchar == '\r' || cap->nchar == '\n'))
    {
	
	(void)del_chars(cap->count1, FALSE);	
	stuffcharReadbuff('\r');
	stuffcharReadbuff(ESC);

	
	invoke_edit(cap, TRUE, 'r', FALSE);
    }
    else {
	prep_redo(cap->oap->regname, cap->count1, NUL, 'r', NUL, had_ctrl_v, cap->nchar);

	curbuf->b_op_start = curwin->w_cursor;
	if (has_mbyte)
	{
	    int		old_State = State;

	    if (cap->ncharC1 != 0)
		AppendCharToRedobuff(cap->ncharC1);
	    if (cap->ncharC2 != 0)
		AppendCharToRedobuff(cap->ncharC2);

	    
	    
	    
	    for (n = cap->count1; n > 0; --n)
	    {
		State = REPLACE;
		if (cap->nchar == Ctrl_E || cap->nchar == Ctrl_Y)
		{
		    int c = ins_copychar(curwin->w_cursor.lnum + (cap->nchar == Ctrl_Y ? -1 : 1));
		    if (c != NUL)
			ins_char(c);
		    else  ++curwin->w_cursor.col;

		}
		else ins_char(cap->nchar);
		State = old_State;
		if (cap->ncharC1 != 0)
		    ins_char(cap->ncharC1);
		if (cap->ncharC2 != 0)
		    ins_char(cap->ncharC2);
	    }
	}
	else {
	    
	    for (n = cap->count1; n > 0; --n)
	    {
		
		if (cap->nchar == Ctrl_E || cap->nchar == Ctrl_Y)
		{
		  int c = ins_copychar(curwin->w_cursor.lnum + (cap->nchar == Ctrl_Y ? -1 : 1));

		  ptr = ml_get_buf(curbuf, curwin->w_cursor.lnum, TRUE);
		  if (c != NUL)
		    ptr[curwin->w_cursor.col] = c;
		}
		else {
		    ptr = ml_get_buf(curbuf, curwin->w_cursor.lnum, TRUE);
		    ptr[curwin->w_cursor.col] = cap->nchar;
		}
		if (p_sm && msg_silent == 0)
		    showmatch(cap->nchar);
		++curwin->w_cursor.col;
	    }

	    if (netbeans_active())
	    {
		colnr_T  start = (colnr_T)(curwin->w_cursor.col - cap->count1);

		netbeans_removed(curbuf, curwin->w_cursor.lnum, start, (long)cap->count1);
		netbeans_inserted(curbuf, curwin->w_cursor.lnum, start, &ptr[start], (int)cap->count1);
	    }


	    
	    changed_bytes(curwin->w_cursor.lnum, (colnr_T)(curwin->w_cursor.col - cap->count1));
	}
	--curwin->w_cursor.col;	    
	
	
	if (has_mbyte)
	    mb_adjust_cursor();
	curbuf->b_op_end = curwin->w_cursor;
	curwin->w_set_curswant = TRUE;
	set_last_insert(cap->nchar);
    }
}


    static void v_swap_corners(int cmdchar)
{
    pos_T	old_cursor;
    colnr_T	left, right;

    if (cmdchar == 'O' && VIsual_mode == Ctrl_V)
    {
	old_cursor = curwin->w_cursor;
	getvcols(curwin, &old_cursor, &VIsual, &left, &right);
	curwin->w_cursor.lnum = VIsual.lnum;
	coladvance(left);
	VIsual = curwin->w_cursor;

	curwin->w_cursor.lnum = old_cursor.lnum;
	curwin->w_curswant = right;
	
	
	if (old_cursor.lnum >= VIsual.lnum && *p_sel == 'e')
	    ++curwin->w_curswant;
	coladvance(curwin->w_curswant);
	if (curwin->w_cursor.col == old_cursor.col && (!virtual_active()
		    || curwin->w_cursor.coladd == old_cursor.coladd))
	{
	    curwin->w_cursor.lnum = VIsual.lnum;
	    if (old_cursor.lnum <= VIsual.lnum && *p_sel == 'e')
		++right;
	    coladvance(right);
	    VIsual = curwin->w_cursor;

	    curwin->w_cursor.lnum = old_cursor.lnum;
	    coladvance(left);
	    curwin->w_curswant = left;
	}
    }
    else {
	old_cursor = curwin->w_cursor;
	curwin->w_cursor = VIsual;
	VIsual = old_cursor;
	curwin->w_set_curswant = TRUE;
    }
}


    static void nv_Replace(cmdarg_T *cap)
{
    if (VIsual_active)		
    {
	cap->cmdchar = 'c';
	cap->nchar = NUL;
	VIsual_mode_orig = VIsual_mode; 
	VIsual_mode = 'V';
	nv_operator(cap);
    }
    else if (!checkclearopq(cap->oap))
    {
	if (!curbuf->b_p_ma)
	    emsg(_(e_cannot_make_changes_modifiable_is_off));
	else {
	    if (virtual_active())
		coladvance(getviscol());
	    invoke_edit(cap, FALSE, cap->arg ? 'V' : 'R', FALSE);
	}
    }
}


    static void nv_vreplace(cmdarg_T *cap)
{
    if (VIsual_active)
    {
	cap->cmdchar = 'r';
	cap->nchar = cap->extra_char;
	nv_replace(cap);	
    }
    else if (!checkclearopq(cap->oap))
    {
	if (!curbuf->b_p_ma)
	    emsg(_(e_cannot_make_changes_modifiable_is_off));
	else {
	    if (cap->extra_char == Ctrl_V)	
		cap->extra_char = get_literal(FALSE);
	    stuffcharReadbuff(cap->extra_char);
	    stuffcharReadbuff(ESC);
	    if (virtual_active())
		coladvance(getviscol());
	    invoke_edit(cap, TRUE, 'v', FALSE);
	}
    }
}


    static void n_swapchar(cmdarg_T *cap)
{
    long	n;
    pos_T	startpos;
    int		did_change = 0;

    pos_T	pos;
    char_u	*ptr;
    int		count;


    if (checkclearopq(cap->oap))
	return;

    if (LINEEMPTY(curwin->w_cursor.lnum) && vim_strchr(p_ww, '~') == NULL)
    {
	clearopbeep(cap->oap);
	return;
    }

    prep_redo_cmd(cap);

    if (u_save_cursor() == FAIL)
	return;

    startpos = curwin->w_cursor;

    pos = startpos;

    for (n = cap->count1; n > 0; --n)
    {
	did_change |= swapchar(cap->oap->op_type, &curwin->w_cursor);
	inc_cursor();
	if (gchar_cursor() == NUL)
	{
	    if (vim_strchr(p_ww, '~') != NULL && curwin->w_cursor.lnum < curbuf->b_ml.ml_line_count)
	    {

		if (netbeans_active())
		{
		    if (did_change)
		    {
			ptr = ml_get(pos.lnum);
			count = (int)STRLEN(ptr) - pos.col;
			netbeans_removed(curbuf, pos.lnum, pos.col, (long)count);
			netbeans_inserted(curbuf, pos.lnum, pos.col, &ptr[pos.col], count);
		    }
		    pos.col = 0;
		    pos.lnum++;
		}

		++curwin->w_cursor.lnum;
		curwin->w_cursor.col = 0;
		if (n > 1)
		{
		    if (u_savesub(curwin->w_cursor.lnum) == FAIL)
			break;
		    u_clearline();
		}
	    }
	    else break;
	}
    }

    if (did_change && netbeans_active())
    {
	ptr = ml_get(pos.lnum);
	count = curwin->w_cursor.col - pos.col;
	netbeans_removed(curbuf, pos.lnum, pos.col, (long)count);
	netbeans_inserted(curbuf, pos.lnum, pos.col, &ptr[pos.col], count);
    }



    check_cursor();
    curwin->w_set_curswant = TRUE;
    if (did_change)
    {
	changed_lines(startpos.lnum, startpos.col, curwin->w_cursor.lnum + 1, 0L);
	curbuf->b_op_start = startpos;
	curbuf->b_op_end = curwin->w_cursor;
	if (curbuf->b_op_end.col > 0)
	    --curbuf->b_op_end.col;
    }
}


    static void nv_cursormark(cmdarg_T *cap, int flag, pos_T *pos)
{
    if (check_mark(pos) == FAIL)
	clearop(cap->oap);
    else {
	if (cap->cmdchar == '\'' || cap->cmdchar == '`' || cap->cmdchar == '[' || cap->cmdchar == ']')


	    setpcmark();
	curwin->w_cursor = *pos;
	if (flag)
	    beginline(BL_WHITE | BL_FIX);
	else check_cursor();
    }
    cap->oap->motion_type = flag ? MLINE : MCHAR;
    if (cap->cmdchar == '`')
	cap->oap->use_reg_one = TRUE;
    cap->oap->inclusive = FALSE;		
    curwin->w_set_curswant = TRUE;
}


    static void v_visop(cmdarg_T *cap)
{
    static char_u trans[] = "YyDdCcxdXdAAIIrr";

    
    
    if (isupper(cap->cmdchar))
    {
	if (VIsual_mode != Ctrl_V)
	{
	    VIsual_mode_orig = VIsual_mode;
	    VIsual_mode = 'V';
	}
	else if (cap->cmdchar == 'C' || cap->cmdchar == 'D')
	    curwin->w_curswant = MAXCOL;
    }
    cap->cmdchar = *(vim_strchr(trans, cap->cmdchar) + 1);
    nv_operator(cap);
}


    static void nv_subst(cmdarg_T *cap)
{

    
    if (term_swap_diff() == OK)
	return;


    if (bt_prompt(curbuf) && !prompt_curpos_editable())
    {
	clearopbeep(cap->oap);
	return;
    }

    if (VIsual_active)	
    {
	if (cap->cmdchar == 'S')
	{
	    VIsual_mode_orig = VIsual_mode;
	    VIsual_mode = 'V';
	}
	cap->cmdchar = 'c';
	nv_operator(cap);
    }
    else nv_optrans(cap);
}


    static void nv_abbrev(cmdarg_T *cap)
{
    if (cap->cmdchar == K_DEL || cap->cmdchar == K_KDEL)
	cap->cmdchar = 'x';		

    
    if (VIsual_active)
	v_visop(cap);
    else nv_optrans(cap);
}


    static void nv_optrans(cmdarg_T *cap)
{
    static char_u *(ar[8]) = {(char_u *)"dl", (char_u *)"dh", (char_u *)"d$", (char_u *)"c$", (char_u *)"cl", (char_u *)"cc", (char_u *)"yy", (char_u *)":s\r";


    static char_u *str = (char_u *)"xXDCsSY&";

    if (!checkclearopq(cap->oap))
    {
	
	
	if (cap->cmdchar == 'D' && vim_strchr(p_cpo, CPO_HASH) != NULL)
	{
	    cap->oap->start = curwin->w_cursor;
	    cap->oap->op_type = OP_DELETE;

	    set_op_var(OP_DELETE);

	    cap->count1 = 1;
	    nv_dollar(cap);
	    finish_op = TRUE;
	    ResetRedobuff();
	    AppendCharToRedobuff('D');
	}
	else {
	    if (cap->count0)
		stuffnumReadbuff(cap->count0);
	    stuffReadbuff(ar[(int)(vim_strchr(str, cap->cmdchar) - str)]);
	}
    }
    cap->opcount = 0;
}


    static void nv_gomark(cmdarg_T *cap)
{
    pos_T	*pos;
    int		c;

    pos_T	old_cursor = curwin->w_cursor;
    int		old_KeyTyped = KeyTyped;    


    if (cap->cmdchar == 'g')
	c = cap->extra_char;
    else c = cap->nchar;
    pos = getmark(c, (cap->oap->op_type == OP_NOP));
    if (pos == (pos_T *)-1)	    
    {
	if (cap->arg)
	{
	    check_cursor_lnum();
	    beginline(BL_WHITE | BL_FIX);
	}
	else check_cursor();
    }
    else nv_cursormark(cap, cap->arg, pos);

    
    if (!virtual_active())
	curwin->w_cursor.coladd = 0;
    check_cursor_col();

    if (cap->oap->op_type == OP_NOP && pos != NULL && (pos == (pos_T *)-1 || !EQUAL_POS(old_cursor, *pos))

	    && (fdo_flags & FDO_MARK)
	    && old_KeyTyped)
	foldOpenCursor();

}


    static void nv_pcmark(cmdarg_T *cap)
{

    pos_T	*pos;

    linenr_T	lnum = curwin->w_cursor.lnum;
    int		old_KeyTyped = KeyTyped;    


    if (!checkclearopq(cap->oap))
    {
	if (cap->cmdchar == TAB && mod_mask == MOD_MASK_CTRL)
	{
	    if (goto_tabpage_lastused() == FAIL)
		clearopbeep(cap->oap);
	    return;
	}
	if (cap->cmdchar == 'g')
	    pos = movechangelist((int)cap->count1);
	else pos = movemark((int)cap->count1);
	if (pos == (pos_T *)-1)		
	{
	    curwin->w_set_curswant = TRUE;
	    check_cursor();
	}
	else if (pos != NULL)		    
	    nv_cursormark(cap, FALSE, pos);
	else if (cap->cmdchar == 'g')
	{
	    if (curbuf->b_changelistlen == 0)
		emsg(_("E664: changelist is empty"));
	    else if (cap->count1 < 0)
		emsg(_("E662: At start of changelist"));
	    else emsg(_("E663: At end of changelist"));
	}
	else clearopbeep(cap->oap);

	if (cap->oap->op_type == OP_NOP && (pos == (pos_T *)-1 || lnum != curwin->w_cursor.lnum)
		&& (fdo_flags & FDO_MARK)
		&& old_KeyTyped)
	    foldOpenCursor();

    }

    clearopbeep(cap->oap);

}


    static void nv_regname(cmdarg_T *cap)
{
    if (checkclearop(cap->oap))
	return;

    if (cap->nchar == '=')
	cap->nchar = get_expr_register();

    if (cap->nchar != NUL && valid_yank_reg(cap->nchar, FALSE))
    {
	cap->oap->regname = cap->nchar;
	cap->opcount = cap->count0;	

	set_reg_var(cap->oap->regname);

    }
    else clearopbeep(cap->oap);
}


    static void nv_visual(cmdarg_T *cap)
{
    if (cap->cmdchar == Ctrl_Q)
	cap->cmdchar = Ctrl_V;

    
    
    if (cap->oap->op_type != OP_NOP)
    {
	motion_force = cap->oap->motion_force = cap->cmdchar;
	finish_op = FALSE;	
	return;
    }

    VIsual_select = cap->arg;
    if (VIsual_active)	    
    {
	if (VIsual_mode == cap->cmdchar)    
	    end_visual_mode();
	else				     {
	    VIsual_mode = cap->cmdchar;
	    showmode();
	    trigger_modechanged();
	}
	redraw_curbuf_later(INVERTED);	    
    }
    else		     {
	check_visual_highlight();
	if (cap->count0 > 0 && resel_VIsual_mode != NUL)
	{
	    
	    VIsual = curwin->w_cursor;

	    VIsual_active = TRUE;
	    VIsual_reselect = TRUE;
	    if (!cap->arg)
		
		may_start_select('c');
	    setmouse();
	    if (p_smd && msg_silent == 0)
		redraw_cmdline = TRUE;	    
	    
	    if (resel_VIsual_mode != 'v' || resel_VIsual_line_count > 1)
	    {
		curwin->w_cursor.lnum += resel_VIsual_line_count * cap->count0 - 1;
		check_cursor();
	    }
	    VIsual_mode = resel_VIsual_mode;
	    if (VIsual_mode == 'v')
	    {
		if (resel_VIsual_line_count <= 1)
		{
		    validate_virtcol();
		    curwin->w_curswant = curwin->w_virtcol + resel_VIsual_vcol * cap->count0 - 1;
		}
		else curwin->w_curswant = resel_VIsual_vcol;
		coladvance(curwin->w_curswant);
	    }
	    if (resel_VIsual_vcol == MAXCOL)
	    {
		curwin->w_curswant = MAXCOL;
		coladvance((colnr_T)MAXCOL);
	    }
	    else if (VIsual_mode == Ctrl_V)
	    {
		validate_virtcol();
		curwin->w_curswant = curwin->w_virtcol + resel_VIsual_vcol * cap->count0 - 1;
		coladvance(curwin->w_curswant);
	    }
	    else curwin->w_set_curswant = TRUE;
	    redraw_curbuf_later(INVERTED);	
	}
	else {
	    if (!cap->arg)
		
		may_start_select('c');
	    n_start_visual_mode(cap->cmdchar);
	    if (VIsual_mode != 'V' && *p_sel == 'e')
		++cap->count1;  
	    if (cap->count0 > 0 && --cap->count1 > 0)
	    {
		
		if (VIsual_mode == 'v' || VIsual_mode == Ctrl_V)
		    nv_right(cap);
		else if (VIsual_mode == 'V')
		    nv_down(cap);
	    }
	}
    }
}


    void start_selection(void)
{
    
    may_start_select('k');
    n_start_visual_mode('v');
}


    void may_start_select(int c)
{
    VIsual_select = (stuff_empty() && typebuf_typed()
		    && (vim_strchr(p_slm, c) != NULL));
}


    static void n_start_visual_mode(int c)
{

    int cursor_line_was_concealed = curwin->w_p_cole > 0 && conceal_cursor_line(curwin);


    VIsual_mode = c;
    VIsual_active = TRUE;
    VIsual_reselect = TRUE;

    
    
    if (c == Ctrl_V && (get_ve_flags() & VE_BLOCK) && gchar_cursor() == TAB)
    {
	validate_virtcol();
	coladvance(curwin->w_virtcol);
    }
    VIsual = curwin->w_cursor;


    foldAdjustVisual();


    trigger_modechanged();
    setmouse();

    
    conceal_check_cursor_line(cursor_line_was_concealed);


    if (p_smd && msg_silent == 0)
	redraw_cmdline = TRUE;	

    
    
    clip_star.vmode = NUL;


    
    
    if (curwin->w_redr_type < INVERTED)
    {
	curwin->w_old_cursor_lnum = curwin->w_cursor.lnum;
	curwin->w_old_visual_lnum = curwin->w_cursor.lnum;
    }
}



    static void nv_window(cmdarg_T *cap)
{
    if (cap->nchar == ':')
    {
	
	cap->cmdchar = ':';
	cap->nchar = NUL;
	nv_colon(cap);
    }
    else if (!checkclearop(cap->oap))
	do_window(cap->nchar, cap->count0, NUL); 
}


    static void nv_suspend(cmdarg_T *cap)
{
    clearop(cap->oap);
    if (VIsual_active)
	end_visual_mode();		
    do_cmdline_cmd((char_u *)"stop");
}


    static void nv_g_cmd(cmdarg_T *cap)
{
    oparg_T	*oap = cap->oap;
    pos_T	tpos;
    int		i;
    int		flag = FALSE;

    switch (cap->nchar)
    {
    case Ctrl_A:
    case Ctrl_X:

    
	if (!VIsual_active && cap->nchar == Ctrl_A)
	    vim_mem_profile_dump();
	else   if (VIsual_active)


	{
	    cap->arg = TRUE;
	    cap->cmdchar = cap->nchar;
	    cap->nchar = NUL;
	    nv_addsub(cap);
	}
	else clearopbeep(oap);
	break;

    
    case 'R':
	cap->arg = TRUE;
	nv_Replace(cap);
	break;

    case 'r':
	nv_vreplace(cap);
	break;

    case '&':
	do_cmdline_cmd((char_u *)"%s//~/&");
	break;

    
    case 'v':
	if (checkclearop(oap))
	    break;

	if (	   curbuf->b_visual.vi_start.lnum == 0 || curbuf->b_visual.vi_start.lnum > curbuf->b_ml.ml_line_count || curbuf->b_visual.vi_end.lnum == 0)

	    beep_flush();
	else {
	    
	    if (VIsual_active)
	    {
		i = VIsual_mode;
		VIsual_mode = curbuf->b_visual.vi_mode;
		curbuf->b_visual.vi_mode = i;

		curbuf->b_visual_mode_eval = i;

		i = curwin->w_curswant;
		curwin->w_curswant = curbuf->b_visual.vi_curswant;
		curbuf->b_visual.vi_curswant = i;

		tpos = curbuf->b_visual.vi_end;
		curbuf->b_visual.vi_end = curwin->w_cursor;
		curwin->w_cursor = curbuf->b_visual.vi_start;
		curbuf->b_visual.vi_start = VIsual;
	    }
	    else {
		VIsual_mode = curbuf->b_visual.vi_mode;
		curwin->w_curswant = curbuf->b_visual.vi_curswant;
		tpos = curbuf->b_visual.vi_end;
		curwin->w_cursor = curbuf->b_visual.vi_start;
	    }

	    VIsual_active = TRUE;
	    VIsual_reselect = TRUE;

	    
	    
	    check_cursor();
	    VIsual = curwin->w_cursor;
	    curwin->w_cursor = tpos;
	    check_cursor();
	    update_topline();
	    
	    if (cap->arg)
		VIsual_select = TRUE;
	    else may_start_select('c');
	    setmouse();

	    
	    
	    clip_star.vmode = NUL;

	    redraw_curbuf_later(INVERTED);
	    showmode();
	}
	break;
    
    case 'V':
	VIsual_reselect = FALSE;
	break;

    
    case K_BS:
	cap->nchar = Ctrl_H;
	
    case 'h':
    case 'H':
    case Ctrl_H:

	
	if (cap->nchar == Ctrl_H)
	    cap->cmdchar = Ctrl_V;
	else  cap->cmdchar = cap->nchar + ('v' - 'h');

	cap->arg = TRUE;
	nv_visual(cap);
	break;

    
    
    
    case 'N':
    case 'n':
	if (!current_search(cap->count1, cap->nchar == 'n'))
	    clearopbeep(oap);
	break;

    
    case 'j':
    case K_DOWN:
	
	if (!curwin->w_p_wrap)
	{
	    oap->motion_type = MLINE;
	    i = cursor_down(cap->count1, oap->op_type == OP_NOP);
	}
	else i = nv_screengo(oap, FORWARD, cap->count1);
	if (i == FAIL)
	    clearopbeep(oap);
	break;

    case 'k':
    case K_UP:
	
	if (!curwin->w_p_wrap)
	{
	    oap->motion_type = MLINE;
	    i = cursor_up(cap->count1, oap->op_type == OP_NOP);
	}
	else i = nv_screengo(oap, BACKWARD, cap->count1);
	if (i == FAIL)
	    clearopbeep(oap);
	break;

    
    case 'J':
	nv_join(cap);
	break;

    
    case '^':
	flag = TRUE;
	

    case '0':
    case 'm':
    case K_HOME:
    case K_KHOME:
	oap->motion_type = MCHAR;
	oap->inclusive = FALSE;
	if (curwin->w_p_wrap && curwin->w_width != 0)
	{
	    int		width1 = curwin->w_width - curwin_col_off();
	    int		width2 = width1 + curwin_col_off2();

	    validate_virtcol();
	    i = 0;
	    if (curwin->w_virtcol >= (colnr_T)width1 && width2 > 0)
		i = (curwin->w_virtcol - width1) / width2 * width2 + width1;
	}
	else i = curwin->w_leftcol;
	
	
	
	if (cap->nchar == 'm')
	    i += (curwin->w_width - curwin_col_off()
		    + ((curwin->w_p_wrap && i > 0)
			? curwin_col_off2() : 0)) / 2;
	coladvance((colnr_T)i);
	if (flag)
	{
	    do i = gchar_cursor();
	    while (VIM_ISWHITE(i) && oneright() == OK);
	    curwin->w_valid &= ~VALID_WCOL;
	}
	curwin->w_set_curswant = TRUE;
	break;

    case 'M':
	{
	    char_u  *ptr = ml_get_curline();

	    oap->motion_type = MCHAR;
	    oap->inclusive = FALSE;
	    if (has_mbyte)
		i = mb_string2cells(ptr, (int)STRLEN(ptr));
	    else i = (int)STRLEN(ptr);
	    if (cap->count0 > 0 && cap->count0 <= 100)
		coladvance((colnr_T)(i * cap->count0 / 100));
	    else coladvance((colnr_T)(i / 2));
	    curwin->w_set_curswant = TRUE;
	}
	break;

    case '_':
	
	
	cap->oap->motion_type = MCHAR;
	cap->oap->inclusive = TRUE;
	curwin->w_curswant = MAXCOL;
	if (cursor_down((long)(cap->count1 - 1), cap->oap->op_type == OP_NOP) == FAIL)
	    clearopbeep(cap->oap);
	else {
	    char_u  *ptr = ml_get_curline();

	    
	    if (curwin->w_cursor.col > 0 && ptr[curwin->w_cursor.col] == NUL)
		--curwin->w_cursor.col;

	    
	    while (curwin->w_cursor.col > 0 && VIM_ISWHITE(ptr[curwin->w_cursor.col]))
		--curwin->w_cursor.col;
	    curwin->w_set_curswant = TRUE;
	    adjust_for_sel(cap);
	}
	break;

    case '$':
    case K_END:
    case K_KEND:
	{
	    int col_off = curwin_col_off();

	    oap->motion_type = MCHAR;
	    oap->inclusive = TRUE;
	    if (curwin->w_p_wrap && curwin->w_width != 0)
	    {
		curwin->w_curswant = MAXCOL;    
		if (cap->count1 == 1)
		{
		    int		width1 = curwin->w_width - col_off;
		    int		width2 = width1 + curwin_col_off2();

		    validate_virtcol();
		    i = width1 - 1;
		    if (curwin->w_virtcol >= (colnr_T)width1)
			i += ((curwin->w_virtcol - width1) / width2 + 1)
								     * width2;
		    coladvance((colnr_T)i);

		    
		    validate_virtcol();
		    curwin->w_curswant = curwin->w_virtcol;
		    curwin->w_set_curswant = FALSE;
		    if (curwin->w_cursor.col > 0 && curwin->w_p_wrap)
		    {
			
			if (curwin->w_virtcol > (colnr_T)i)
			    --curwin->w_cursor.col;
		    }
		}
		else if (nv_screengo(oap, FORWARD, cap->count1 - 1) == FAIL)
		    clearopbeep(oap);
	    }
	    else {
		if (cap->count1 > 1)
		    
		    (void)cursor_down(cap->count1 - 1, FALSE);

		i = curwin->w_leftcol + curwin->w_width - col_off - 1;
		coladvance((colnr_T)i);

		
		if (curwin->w_cursor.col > 0 && (*mb_ptr2cells)(ml_get_cursor()) > 1)
		{
		    colnr_T vcol;

		    getvvcol(curwin, &curwin->w_cursor, NULL, NULL, &vcol);
		    if (vcol >= curwin->w_leftcol + curwin->w_width - col_off)
			--curwin->w_cursor.col;
		}

		
		validate_virtcol();
		curwin->w_curswant = curwin->w_virtcol;
		curwin->w_set_curswant = FALSE;
	    }
	}
	break;

    
    case '*':
    case '#':

    case POUND:		

    case Ctrl_RSB:		
    case ']':			
	nv_ident(cap);
	break;

    
    case 'e':
    case 'E':
	oap->motion_type = MCHAR;
	curwin->w_set_curswant = TRUE;
	oap->inclusive = TRUE;
	if (bckend_word(cap->count1, cap->nchar == 'E', FALSE) == FAIL)
	    clearopbeep(oap);
	break;

    
    case Ctrl_G:
	cursor_pos_info(NULL);
	break;

    
    case 'i':
	if (curbuf->b_last_insert.lnum != 0)
	{
	    curwin->w_cursor = curbuf->b_last_insert;
	    check_cursor_lnum();
	    i = (int)STRLEN(ml_get_curline());
	    if (curwin->w_cursor.col > (colnr_T)i)
	    {
		if (virtual_active())
		    curwin->w_cursor.coladd += curwin->w_cursor.col - i;
		curwin->w_cursor.col = i;
	    }
	}
	cap->cmdchar = 'i';
	nv_edit(cap);
	break;

    
    case 'I':
	beginline(0);
	if (!checkclearopq(oap))
	    invoke_edit(cap, FALSE, 'g', FALSE);
	break;


    
    case 'f':
    case 'F':
	nv_gotofile(cap);
	break;


	
    case '\'':
	cap->arg = TRUE;
	
    case '`':
	nv_gomark(cap);
	break;

    
    case 's':
	do_sleep(cap->count1 * 1000L, FALSE);
	break;

    
    case 'a':
	do_ascii(NULL);
	break;

    
    case '8':
	if (cap->count0 == 8)
	    utf_find_illegal();
	else show_utf8();
	break;

    
    case '<':
	show_sb_text();
	break;

    
    case 'g':
	cap->arg = FALSE;
	nv_goto(cap);
	break;

    
    case 'q':
    case 'w':
	oap->cursor_start = curwin->w_cursor;
	
    case '~':
    case 'u':
    case 'U':
    case '?':
    case '@':
	nv_operator(cap);
	break;

    
    case 'd':
    case 'D':
	nv_gd(oap, cap->nchar, (int)cap->count0);
	break;

    
    case K_MIDDLEMOUSE:
    case K_MIDDLEDRAG:
    case K_MIDDLERELEASE:
    case K_LEFTMOUSE:
    case K_LEFTDRAG:
    case K_LEFTRELEASE:
    case K_MOUSEMOVE:
    case K_RIGHTMOUSE:
    case K_RIGHTDRAG:
    case K_RIGHTRELEASE:
    case K_X1MOUSE:
    case K_X1DRAG:
    case K_X1RELEASE:
    case K_X2MOUSE:
    case K_X2DRAG:
    case K_X2RELEASE:
	mod_mask = MOD_MASK_CTRL;
	(void)do_mouse(oap, cap->nchar, BACKWARD, cap->count1, 0);
	break;

    case K_IGNORE:
	break;

    
    case 'p':
    case 'P':
	nv_put(cap);
	break;


    
    case 'o':
	goto_byte(cap->count0);
	break;


    
    case 'Q':
	if (text_locked())
	{
	    clearopbeep(cap->oap);
	    text_locked_msg();
	    break;
	}

	if (!checkclearopq(oap))
	    do_exmode(TRUE);
	break;


    case ',':
	nv_pcmark(cap);
	break;

    case ';':
	cap->count1 = -cap->count1;
	nv_pcmark(cap);
	break;


    case 't':
	if (!checkclearop(oap))
	    goto_tabpage((int)cap->count0);
	break;
    case 'T':
	if (!checkclearop(oap))
	    goto_tabpage(-(int)cap->count1);
	break;

    case TAB:
	if (!checkclearop(oap) && goto_tabpage_lastused() == FAIL)
	    clearopbeep(oap);
	break;

    case '+':
    case '-': 
	if (!checkclearopq(oap))
	    undo_time(cap->nchar == '-' ? -cap->count1 : cap->count1, FALSE, FALSE, FALSE);
	break;

    default:
	clearopbeep(oap);
	break;
    }
}


    static void n_opencmd(cmdarg_T *cap)
{

    linenr_T	oldline = curwin->w_cursor.lnum;


    if (!checkclearopq(cap->oap))
    {

	if (cap->cmdchar == 'O')
	    
	    (void)hasFolding(curwin->w_cursor.lnum, &curwin->w_cursor.lnum, NULL);
	else  (void)hasFolding(curwin->w_cursor.lnum, NULL, &curwin->w_cursor.lnum);



	if (u_save((linenr_T)(curwin->w_cursor.lnum - (cap->cmdchar == 'O' ? 1 : 0)), (linenr_T)(curwin->w_cursor.lnum + (cap->cmdchar == 'o' ? 1 : 0))


		       ) == OK && open_line(cap->cmdchar == 'O' ? BACKWARD : FORWARD, has_format_option(FO_OPEN_COMS) ? OPENLINE_DO_COM : 0, 0) == OK)


	{

	    if (curwin->w_p_cole > 0 && oldline != curwin->w_cursor.lnum)
		redrawWinline(curwin, oldline);


	    if (curwin->w_p_cul)
		
		curwin->w_valid &= ~VALID_CROW;

	    
	    if (vim_strchr(p_cpo, CPO_HASH) != NULL)
		cap->count1 = 1;
	    invoke_edit(cap, FALSE, cap->cmdchar, TRUE);
	}
    }
}


    static void nv_dot(cmdarg_T *cap)
{
    if (!checkclearopq(cap->oap))
    {
	
	if (start_redo(cap->count0, restart_edit != 0 && !arrow_used) == FAIL)
	    clearopbeep(cap->oap);
    }
}


    static void nv_redo(cmdarg_T *cap)
{
    if (!checkclearopq(cap->oap))
    {
	u_redo((int)cap->count1);
	curwin->w_set_curswant = TRUE;
    }
}


    static void nv_Undo(cmdarg_T *cap)
{
    
    if (cap->oap->op_type == OP_UPPER || VIsual_active)
    {
	
	cap->cmdchar = 'g';
	cap->nchar = 'U';
	nv_operator(cap);
    }
    else if (!checkclearopq(cap->oap))
    {
	u_undoline();
	curwin->w_set_curswant = TRUE;
    }
}


    static void nv_tilde(cmdarg_T *cap)
{
    if (!p_to && !VIsual_active && cap->oap->op_type != OP_TILDE)
    {

	if (bt_prompt(curbuf) && !prompt_curpos_editable())
	{
	    clearopbeep(cap->oap);
	    return;
	}

	n_swapchar(cap);
    }
    else nv_operator(cap);
}


    static void nv_operator(cmdarg_T *cap)
{
    int	    op_type;

    op_type = get_op_type(cap->cmdchar, cap->nchar);

    if (bt_prompt(curbuf) && op_is_change(op_type) && !prompt_curpos_editable())
    {
	clearopbeep(cap->oap);
	return;
    }


    if (op_type == cap->oap->op_type)	    
	nv_lineop(cap);
    else if (!checkclearop(cap->oap))
    {
	cap->oap->start = curwin->w_cursor;
	cap->oap->op_type = op_type;

	set_op_var(op_type);

    }
}



    static void set_op_var(int optype)
{
    char_u	opchars[3];

    if (optype == OP_NOP)
	set_vim_var_string(VV_OP, NULL, 0);
    else {
	opchars[0] = get_op_char(optype);
	opchars[1] = get_extra_op_char(optype);
	opchars[2] = NUL;
	set_vim_var_string(VV_OP, opchars, -1);
    }
}



    static void nv_lineop(cmdarg_T *cap)
{
    cap->oap->motion_type = MLINE;
    if (cursor_down(cap->count1 - 1L, cap->oap->op_type == OP_NOP) == FAIL)
	clearopbeep(cap->oap);
    else if (  (cap->oap->op_type == OP_DELETE  && cap->oap->motion_force != 'v' && cap->oap->motion_force != Ctrl_V)

	    || cap->oap->op_type == OP_LSHIFT || cap->oap->op_type == OP_RSHIFT)
	beginline(BL_SOL | BL_FIX);
    else if (cap->oap->op_type != OP_YANK)	
	beginline(BL_WHITE | BL_FIX);
}


    static void nv_home(cmdarg_T *cap)
{
    
    if (mod_mask & MOD_MASK_CTRL)
	nv_goto(cap);
    else {
	cap->count0 = 1;
	nv_pipe(cap);
    }
    ins_at_eol = FALSE;	    
			    
}


    static void nv_pipe(cmdarg_T *cap)
{
    cap->oap->motion_type = MCHAR;
    cap->oap->inclusive = FALSE;
    beginline(0);
    if (cap->count0 > 0)
    {
	coladvance((colnr_T)(cap->count0 - 1));
	curwin->w_curswant = (colnr_T)(cap->count0 - 1);
    }
    else curwin->w_curswant = 0;
    
    
    curwin->w_set_curswant = FALSE;
}


    static void nv_bck_word(cmdarg_T *cap)
{
    cap->oap->motion_type = MCHAR;
    cap->oap->inclusive = FALSE;
    curwin->w_set_curswant = TRUE;
    if (bck_word(cap->count1, cap->arg, FALSE) == FAIL)
	clearopbeep(cap->oap);

    else if ((fdo_flags & FDO_HOR) && KeyTyped && cap->oap->op_type == OP_NOP)
	foldOpenCursor();

}


    static void nv_wordcmd(cmdarg_T *cap)
{
    int		n;
    int		word_end;
    int		flag = FALSE;
    pos_T	startpos = curwin->w_cursor;

    
    if (cap->cmdchar == 'e' || cap->cmdchar == 'E')
	word_end = TRUE;
    else word_end = FALSE;
    cap->oap->inclusive = word_end;

    
    if (!word_end && cap->oap->op_type == OP_CHANGE)
    {
	n = gchar_cursor();
	if (n != NUL)			
	{
	    if (VIM_ISWHITE(n))
	    {
		
		if (cap->count1 == 1 && vim_strchr(p_cpo, CPO_CW) != NULL)
		{
		    cap->oap->inclusive = TRUE;
		    cap->oap->motion_type = MCHAR;
		    return;
		}
	    }
	    else {
		
		cap->oap->inclusive = TRUE;
		word_end = TRUE;
		flag = TRUE;
	    }
	}
    }

    cap->oap->motion_type = MCHAR;
    curwin->w_set_curswant = TRUE;
    if (word_end)
	n = end_word(cap->count1, cap->arg, flag, FALSE);
    else n = fwd_word(cap->count1, cap->arg, cap->oap->op_type != OP_NOP);

    
    
    if (LT_POS(startpos, curwin->w_cursor))
	adjust_cursor(cap->oap);

    if (n == FAIL && cap->oap->op_type == OP_NOP)
	clearopbeep(cap->oap);
    else {
	adjust_for_sel(cap);

	if ((fdo_flags & FDO_HOR) && KeyTyped && cap->oap->op_type == OP_NOP)
	    foldOpenCursor();

    }
}


    static void adjust_cursor(oparg_T *oap)
{
    
    
    
    
    if (curwin->w_cursor.col > 0 && gchar_cursor() == NUL && (!VIsual_active || *p_sel == 'o')
		&& !virtual_active() && (get_ve_flags() & VE_ONEMORE) == 0)
    {
	--curwin->w_cursor.col;
	
	if (has_mbyte)
	    mb_adjust_cursor();
	oap->inclusive = TRUE;
    }
}


    static void nv_beginline(cmdarg_T *cap)
{
    cap->oap->motion_type = MCHAR;
    cap->oap->inclusive = FALSE;
    beginline(cap->arg);

    if ((fdo_flags & FDO_HOR) && KeyTyped && cap->oap->op_type == OP_NOP)
	foldOpenCursor();

    ins_at_eol = FALSE;	    
			    
}


    static void adjust_for_sel(cmdarg_T *cap)
{
    if (VIsual_active && cap->oap->inclusive && *p_sel == 'e' && gchar_cursor() != NUL && LT_POS(VIsual, curwin->w_cursor))
    {
	if (has_mbyte)
	    inc_cursor();
	else ++curwin->w_cursor.col;
	cap->oap->inclusive = FALSE;
    }
}


    int unadjust_for_sel(void)
{
    pos_T	*pp;

    if (*p_sel == 'e' && !EQUAL_POS(VIsual, curwin->w_cursor))
    {
	if (LT_POS(VIsual, curwin->w_cursor))
	    pp = &curwin->w_cursor;
	else pp = &VIsual;
	if (pp->coladd > 0)
	    --pp->coladd;
	else if (pp->col > 0)
	{
	    --pp->col;
	    mb_adjustpos(curbuf, pp);
	}
	else if (pp->lnum > 1)
	{
	    --pp->lnum;
	    pp->col = (colnr_T)STRLEN(ml_get(pp->lnum));
	    return TRUE;
	}
    }
    return FALSE;
}


    static void nv_select(cmdarg_T *cap)
{
    if (VIsual_active)
	VIsual_select = TRUE;
    else if (VIsual_reselect)
    {
	cap->nchar = 'v';	    
	cap->arg = TRUE;
	nv_g_cmd(cap);
    }
}



    static void nv_goto(cmdarg_T *cap)
{
    linenr_T	lnum;

    if (cap->arg)
	lnum = curbuf->b_ml.ml_line_count;
    else lnum = 1L;
    cap->oap->motion_type = MLINE;
    setpcmark();

    
    if (cap->count0 != 0)
	lnum = cap->count0;
    if (lnum < 1L)
	lnum = 1L;
    else if (lnum > curbuf->b_ml.ml_line_count)
	lnum = curbuf->b_ml.ml_line_count;
    curwin->w_cursor.lnum = lnum;
    beginline(BL_SOL | BL_FIX);

    if ((fdo_flags & FDO_JUMP) && KeyTyped && cap->oap->op_type == OP_NOP)
	foldOpenCursor();

}


    static void nv_normal(cmdarg_T *cap)
{
    if (cap->nchar == Ctrl_N || cap->nchar == Ctrl_G)
    {
	clearop(cap->oap);
	if (restart_edit != 0 && mode_displayed)
	    clear_cmdline = TRUE;		
	restart_edit = 0;

	if (cmdwin_type != 0)
	    cmdwin_result = Ctrl_C;

	if (VIsual_active)
	{
	    end_visual_mode();		
	    redraw_curbuf_later(INVERTED);
	}
	
	if (cap->nchar == Ctrl_G && p_im)
	    restart_edit = 'a';
    }
    else clearopbeep(cap->oap);
}


    static void nv_esc(cmdarg_T *cap)
{
    int		no_reason;

    no_reason = (cap->oap->op_type == OP_NOP && cap->opcount == 0 && cap->count0 == 0 && cap->oap->regname == 0 && !p_im);




    if (cap->arg)		
    {
	if (restart_edit == 0  && cmdwin_type == 0  && !VIsual_active && no_reason)




	{
	    if (anyBufIsChanged())
		msg(_("Type  :qa!  and press <Enter> to abandon all changes and exit Vim"));
	    else msg(_("Type  :qa  and press <Enter> to exit Vim"));
	}

	
	
	if (!p_im)
	    restart_edit = 0;

	if (cmdwin_type != 0)
	{
	    cmdwin_result = K_IGNORE;
	    got_int = FALSE;	
	    return;
	}

    }

    else if (cmdwin_type != 0 && ex_normal_busy)
    {
	
	
	
	cmdwin_result = K_IGNORE;
	return;
    }


    if (VIsual_active)
    {
	end_visual_mode();	
	check_cursor_col();	
	curwin->w_set_curswant = TRUE;
	redraw_curbuf_later(INVERTED);
    }
    else if (no_reason)
	vim_beep(BO_ESC);
    clearop(cap->oap);

    
    
    if (restart_edit == 0 && goto_im() && ex_normal_busy == 0)
	restart_edit = 'a';
}


    void set_cursor_for_append_to_line(void)
{
    curwin->w_set_curswant = TRUE;
    if (get_ve_flags() == VE_ALL)
    {
	int save_State = State;

	
	
	State = INSERT;
	coladvance((colnr_T)MAXCOL);
	State = save_State;
    }
    else curwin->w_cursor.col += (colnr_T)STRLEN(ml_get_cursor());
}


    static void nv_edit(cmdarg_T *cap)
{
    
    if (cap->cmdchar == K_INS || cap->cmdchar == K_KINS)
	cap->cmdchar = 'i';

    
    if (VIsual_active && (cap->cmdchar == 'A' || cap->cmdchar == 'I'))
    {

	if (term_in_normal_mode())
	{
	    end_visual_mode();
	    clearop(cap->oap);
	    term_enter_job_mode();
	    return;
	}

	v_visop(cap);
    }

    
    else if ((cap->cmdchar == 'a' || cap->cmdchar == 'i')
	    && (cap->oap->op_type != OP_NOP || VIsual_active))
    {

	nv_object(cap);

	clearopbeep(cap->oap);

    }

    else if (term_in_normal_mode())
    {
	clearop(cap->oap);
	term_enter_job_mode();
	return;
    }

    else if (!curbuf->b_p_ma && !p_im)
    {
	
	emsg(_(e_cannot_make_changes_modifiable_is_off));
	clearop(cap->oap);
	if (cap->cmdchar == K_PS)
	    
	    bracketed_paste(PASTE_INSERT, TRUE, NULL);
    }
    else if (cap->cmdchar == K_PS && VIsual_active)
    {
	pos_T old_pos = curwin->w_cursor;
	pos_T old_visual = VIsual;

	
	if (VIsual_mode == 'V' || curwin->w_cursor.lnum != VIsual.lnum)
	{
	    shift_delete_registers();
	    cap->oap->regname = '1';
	}
	else cap->oap->regname = '-';
	cap->cmdchar = 'd';
	cap->nchar = NUL;
	nv_operator(cap);
	do_pending_operator(cap, 0, FALSE);
	cap->cmdchar = K_PS;

	
	
	if (*ml_get_cursor() != NUL && LT_POS(curwin->w_cursor, old_pos)
				       && LT_POS(curwin->w_cursor, old_visual))
	    inc_cursor();

	
	invoke_edit(cap, FALSE, cap->cmdchar, FALSE);
    }
    else if (!checkclearopq(cap->oap))
    {
	switch (cap->cmdchar)
	{
	    case 'A':	
		set_cursor_for_append_to_line();
		break;

	    case 'I':	
		if (vim_strchr(p_cpo, CPO_INSEND) == NULL)
		    beginline(BL_WHITE);
		else beginline(BL_WHITE|BL_FIX);
		break;

	    case K_PS:
		
		
		if (curwin->w_cursor.col == 0)
		    break;
		

	    case 'a':	
		
		
		if (virtual_active()
			&& (curwin->w_cursor.coladd > 0 || *ml_get_cursor() == NUL || *ml_get_cursor() == TAB))

		    curwin->w_cursor.coladd++;
		else if (*ml_get_cursor() != NUL)
		    inc_cursor();
		break;
	}

	if (curwin->w_cursor.coladd && cap->cmdchar != 'A')
	{
	    int save_State = State;

	    
	    
	    State = INSERT;
	    coladvance(getviscol());
	    State = save_State;
	}

	invoke_edit(cap, FALSE, cap->cmdchar, FALSE);
    }
    else if (cap->cmdchar == K_PS)
	
	bracketed_paste(PASTE_INSERT, TRUE, NULL);
}


    static void invoke_edit( cmdarg_T	*cap, int		repl, int		cmd, int		startln)




{
    int		restart_edit_save = 0;

    
    
    
    if (repl || !stuff_empty())
	restart_edit_save = restart_edit;
    else restart_edit_save = 0;

    
    restart_edit = 0;

    if (edit(cmd, startln, cap->count1))
	cap->retval |= CA_COMMAND_BUSY;

    if (restart_edit == 0)
	restart_edit = restart_edit_save;
}



    static void nv_object( cmdarg_T	*cap)

{
    int		flag;
    int		include;
    char_u	*mps_save;

    if (cap->cmdchar == 'i')
	include = FALSE;    
    else include = TRUE;

    
    mps_save = curbuf->b_p_mps;
    curbuf->b_p_mps = (char_u *)"(:),{:},[:],<:>";

    switch (cap->nchar)
    {
	case 'w': 
		flag = current_word(cap->oap, cap->count1, include, FALSE);
		break;
	case 'W': 
		flag = current_word(cap->oap, cap->count1, include, TRUE);
		break;
	case 'b': 
	case '(':
	case ')':
		flag = current_block(cap->oap, cap->count1, include, '(', ')');
		break;
	case 'B': 
	case '{':
	case '}':
		flag = current_block(cap->oap, cap->count1, include, '{', '}');
		break;
	case '[': 
	case ']':
		flag = current_block(cap->oap, cap->count1, include, '[', ']');
		break;
	case '<': 
	case '>':
		flag = current_block(cap->oap, cap->count1, include, '<', '>');
		break;
	case 't': 
		
		
		
		
		
		
		cap->retval |= CA_NO_ADJ_OP_END;
		flag = current_tagblock(cap->oap, cap->count1, include);
		break;
	case 'p': 
		flag = current_par(cap->oap, cap->count1, include, 'p');
		break;
	case 's': 
		flag = current_sent(cap->oap, cap->count1, include);
		break;
	case '"': 
	case '\'': 
	case '`': 
		flag = current_quote(cap->oap, cap->count1, include, cap->nchar);
		break;

	case 'S': 
	case 'f': 
	case 'u': 

	default:
		flag = FAIL;
		break;
    }

    curbuf->b_p_mps = mps_save;
    if (flag == FAIL)
	clearopbeep(cap->oap);
    adjust_cursor_col();
    curwin->w_set_curswant = TRUE;
}



    static void nv_record(cmdarg_T *cap)
{
    if (cap->oap->op_type == OP_FORMAT)
    {
	
	cap->cmdchar = 'g';
	cap->nchar = 'q';
	nv_operator(cap);
    }
    else if (!checkclearop(cap->oap))
    {

	if (cap->nchar == ':' || cap->nchar == '/' || cap->nchar == '?')
	{
	    stuffcharReadbuff(cap->nchar);
	    stuffcharReadbuff(K_CMDWIN);
	}
	else    if (reg_executing == 0 && do_record(cap->nchar) == FAIL)



		clearopbeep(cap->oap);
    }
}


    static void nv_at(cmdarg_T *cap)
{
    if (checkclearop(cap->oap))
	return;

    if (cap->nchar == '=')
    {
	if (get_expr_register() == NUL)
	    return;
    }

    while (cap->count1-- && !got_int)
    {
	if (do_execreg(cap->nchar, FALSE, FALSE, FALSE) == FAIL)
	{
	    clearopbeep(cap->oap);
	    break;
	}
	line_breakcheck();
    }
}


    static void nv_halfpage(cmdarg_T *cap)
{
    if ((cap->cmdchar == Ctrl_U && curwin->w_cursor.lnum == 1)
	    || (cap->cmdchar == Ctrl_D && curwin->w_cursor.lnum == curbuf->b_ml.ml_line_count))
	clearopbeep(cap->oap);
    else if (!checkclearop(cap->oap))
	halfpage(cap->cmdchar == Ctrl_D, cap->count0);
}


    static void nv_join(cmdarg_T *cap)
{
    if (VIsual_active)	
	nv_operator(cap);
    else if (!checkclearop(cap->oap))
    {
	if (cap->count0 <= 1)
	    cap->count0 = 2;	    
	if (curwin->w_cursor.lnum + cap->count0 - 1 > curbuf->b_ml.ml_line_count)
	{
	    
	    if (cap->count0 <= 2)
	    {
		clearopbeep(cap->oap);
		return;
	    }
	    cap->count0 = curbuf->b_ml.ml_line_count - curwin->w_cursor.lnum + 1;
	}

	prep_redo(cap->oap->regname, cap->count0, NUL, cap->cmdchar, NUL, NUL, cap->nchar);
	(void)do_join(cap->count0, cap->nchar == NUL, TRUE, TRUE, TRUE);
    }
}


    static void nv_put(cmdarg_T *cap)
{
    nv_put_opt(cap, FALSE);
}


    static void nv_put_opt(cmdarg_T *cap, int fix_indent)
{
    int		regname = 0;
    void	*reg1 = NULL, *reg2 = NULL;
    int		empty = FALSE;
    int		was_visual = FALSE;
    int		dir;
    int		flags = 0;

    if (cap->oap->op_type != OP_NOP)
    {

	
	if (cap->oap->op_type == OP_DELETE && cap->cmdchar == 'p')
	{
	    clearop(cap->oap);
	    nv_diffgetput(TRUE, cap->opcount);
	}
	else  clearopbeep(cap->oap);

    }

    else if (bt_prompt(curbuf) && !prompt_curpos_editable())
    {
	clearopbeep(cap->oap);
    }

    else {
	if (fix_indent)
	{
	    dir = (cap->cmdchar == ']' && cap->nchar == 'p')
							 ? FORWARD : BACKWARD;
	    flags |= PUT_FIXINDENT;
	}
	else dir = (cap->cmdchar == 'P' || ((cap->cmdchar == 'g' || cap->cmdchar == 'z')

			&& cap->nchar == 'P')) ? BACKWARD : FORWARD;
	prep_redo_cmd(cap);
	if (cap->cmdchar == 'g')
	    flags |= PUT_CURSEND;
	else if (cap->cmdchar == 'z')
	    flags |= PUT_BLOCK_INNER;

	if (VIsual_active)
	{
	    
	    
	    
	    
	    was_visual = TRUE;
	    regname = cap->oap->regname;

	    adjust_clip_reg(&regname);

	   if (regname == 0 || regname == '"' || VIM_ISDIGIT(regname) || regname == '-'  || (clip_unnamed && (regname == '*' || regname == '+'))




		    )
	    {
		
		
		reg1 = get_register(regname, TRUE);
	    }

	    
	    cap->cmdchar = 'd';
	    cap->nchar = NUL;
	    cap->oap->regname = NUL;
	    ++msg_silent;
	    nv_operator(cap);
	    do_pending_operator(cap, 0, FALSE);
	    empty = (curbuf->b_ml.ml_flags & ML_EMPTY);
	    --msg_silent;

	    
	    cap->oap->regname = regname;

	    if (reg1 != NULL)
	    {
		
		
		reg2 = get_register(regname, FALSE);
		put_register(regname, reg1);
	    }

	    
	    
	    
	    if (VIsual_mode == 'V')
		flags |= PUT_LINE;
	    else if (VIsual_mode == 'v')
		flags |= PUT_LINE_SPLIT;
	    if (VIsual_mode == Ctrl_V && dir == FORWARD)
		flags |= PUT_LINE_FORWARD;
	    dir = BACKWARD;
	    if ((VIsual_mode != 'V' && curwin->w_cursor.col < curbuf->b_op_start.col)
		    || (VIsual_mode == 'V' && curwin->w_cursor.lnum < curbuf->b_op_start.lnum))
		
		
		dir = FORWARD;
	    
	    VIsual_active = TRUE;
	}
	do_put(cap->oap->regname, NULL, dir, cap->count1, flags);

	
	if (reg2 != NULL)
	    put_register(regname, reg2);

	
	
	if (was_visual)
	{
	    curbuf->b_visual.vi_start = curbuf->b_op_start;
	    curbuf->b_visual.vi_end = curbuf->b_op_end;
	    
	    if (*p_sel == 'e')
		inc(&curbuf->b_visual.vi_end);
	}

	
	
	if (empty && *ml_get(curbuf->b_ml.ml_line_count) == NUL)
	{
	    ml_delete_flags(curbuf->b_ml.ml_line_count, ML_DEL_MESSAGE);
	    deleted_lines(curbuf->b_ml.ml_line_count + 1, 1);

	    
	    
	    if (curwin->w_cursor.lnum > curbuf->b_ml.ml_line_count)
	    {
		curwin->w_cursor.lnum = curbuf->b_ml.ml_line_count;
		coladvance((colnr_T)MAXCOL);
	    }
	}
	auto_format(FALSE, TRUE);
    }
}


    static void nv_open(cmdarg_T *cap)
{

    
    if (cap->oap->op_type == OP_DELETE && cap->cmdchar == 'o')
    {
	clearop(cap->oap);
	nv_diffgetput(FALSE, cap->opcount);
    }
    else  if (VIsual_active)

	v_swap_corners(cap->cmdchar);

    else if (bt_prompt(curbuf))
	clearopbeep(cap->oap);

    else n_opencmd(cap);
}


    static void nv_nbcmd(cmdarg_T *cap)
{
    netbeans_keycommand(cap->nchar);
}



    static void nv_drop(cmdarg_T *cap UNUSED)
{
    do_put('~', NULL, BACKWARD, 1L, PUT_CURSEND);
}



    static void nv_cursorhold(cmdarg_T *cap)
{
    apply_autocmds(EVENT_CURSORHOLD, NULL, NULL, FALSE, curbuf);
    did_cursorhold = TRUE;
    cap->retval |= CA_COMMAND_BUSY;	
}
