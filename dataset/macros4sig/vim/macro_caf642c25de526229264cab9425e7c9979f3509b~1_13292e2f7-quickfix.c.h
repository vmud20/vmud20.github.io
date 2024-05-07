
#include<stddef.h>

#include<assert.h>

#include<stdarg.h>
#include<float.h>



#include<limits.h>


#define ALLOC_CLEAR_MULT(type, count)  (type *)alloc_clear(sizeof(type) * (count))
#define ALLOC_CLEAR_ONE(type)  (type *)alloc_clear(sizeof(type))
#define ALLOC_CLEAR_ONE_ID(type, id)  (type *)alloc_clear_id(sizeof(type), id)
#define ALLOC_MULT(type, count)  (type *)alloc(sizeof(type) * (count))
#define ALLOC_ONE(type)  (type *)alloc(sizeof(type))
#define ALLOC_ONE_ID(type, id)  (type *)alloc_id(sizeof(type), id)
# define APPENDBIN  "ab"
#define ASSIGN_FOR_LOOP 0x40 
#define ASSIGN_NO_MEMBER_TYPE 0x20 
#define ASSIGN_UPDATE_BLOCK_ID 0x100  
# define ATTRIBUTE_COLD
# define ATTRIBUTE_FORMAT_PRINTF(fmt_idx, arg_idx) \
    __attribute__((format(printf, fmt_idx, arg_idx)))
#define AUTOLOAD_CHAR '#'
#define BARTYPE_HISTORY 2
#define BARTYPE_MARK 4
#define BARTYPE_REGISTER 3
#define BARTYPE_VERSION 1
#define BFA_IGNORE_ABORT 8	
# define BROWSE_DIR 2	    
#  define BROWSE_FILTER_ALL_FILES (char_u *)N_("All Files (*.*)\t*.*\n")
#  define BROWSE_FILTER_DEFAULT \
	(char_u *)N_("All Files (*.*)\t*.*\nC source (*.c, *.h)\t*.c;*.h\nC++ source (*.cpp, *.hpp)\t*.cpp;*.hpp\nVB code (*.bas, *.frm)\t*.bas;*.frm\nVim files (*.vim, _vimrc, _gvimrc)\t*.vim;_vimrc;_gvimrc\n")
#  define BROWSE_FILTER_MACROS \
	(char_u *)N_("Vim macro files (*.vim)\t*.vim\nAll Files (*.*)\t*.*\n")
# define BROWSE_SAVE 1	    
#  define BUFFER_ESC_CHARS ((char_u *)" \t\n*?[`$\\%#'\"|!<")
# define CHECK_DOUBLE_CLICK 1	
#define CLEAR_FIELD(field)  vim_memset(&(field), 0, sizeof(field))
#define CLEAR_POINTER(ptr)  vim_memset((ptr), 0, sizeof(*(ptr)))
#define CLIP_ZINDEX 32000
#define COPYID_INC 2
#define COPYID_MASK (~0x1)
#define DIALOG_MSG_SIZE 1000	
#define DICT_MAXNEST 100	
#define DIP_AFTER   0x80	
#define DIP_NOAFTER 0x40	
#define DIP_NORTP   0x20	
#define DIP_START   0x08	
#define DOBUF_WIPE_REUSE 5	
#define DOCMD_KEEPLINE  0x20	
#  define DO_INIT
#define DO_NOT_FREE_CNT 99999	
#  define EILSEQ 123
# define ELAPSED_FUNC(v) elapsed(&(v))
# define ELAPSED_INIT(v) gettimeofday(&(v), NULL)
# define ELAPSED_TICKCOUNT
# define ELAPSED_TIMEVAL
#define ETYPE_ARG_UNKNOWN 1
# define EXTERN extern
#  define FEAT_CLIPBOARD
#  define FEAT_GETTEXT
#  define FEAT_GUI
#  define FEAT_MBYTE_IME
#  define FEAT_RENDER_OPTIONS
#  define FEAT_SOUND
#  define FEAT_SOUND_MACOSX
# define FEAT_X11
#define FILEINFO_ENC_FAIL    1	
#define FILEINFO_INFO_FAIL   3	
#define FILEINFO_READ_FAIL   2	
#define FLEN_FIXED 40
#define FOLD_TEXT_LEN  51	
#define GETFILE_NOT_WRITTEN 2	
#define GETFILE_OPEN_OTHER (-1)	
#define GETFILE_SAME_FILE   0	
#define GETFILE_SUCCESS(x)  ((x) <= 0)
#define GLV_ASSIGN_WITH_OP TFN_ASSIGN_WITH_OP 
#  define GUI_FUNCTION(f)	    (gui.in_use ? gui_##f : termgui_##f)
#  define GUI_FUNCTION2(f, pixel)   (gui.in_use \
				    ?  ((pixel) != INVALCOLOR \
					? gui_##f((pixel)) \
					: INVALCOLOR) \
				    : termgui_##f((pixel)))
# define GUI_MCH_GET_RGB2(pixel)    GUI_FUNCTION2(mch_get_rgb, (pixel))
#   define HAVE_BIND_TEXTDOMAIN_CODESET 1
# define HAVE_INPUT_METHOD
# define HAVE_PATHDEF
#  define HAVE_SELECT
#define HL_ATTR(n)	highlight_attr[(int)(n)]
#define HL_FLAGS {'8', '~', '@', 'd', 'e', 'h', 'i', 'l', 'y', 'm', 'M', \
		  'n', 'a', 'b', 'N', 'G', 'O', 'r', 's', 'S', 'c', 't', 'v', 'V', \
		  'w', 'W', 'f', 'F', 'A', 'C', 'D', 'T', '-', '>', \
		  'B', 'P', 'R', 'L', \
		  '+', '=', '[', ']', '{', '}', 'x', 'X', \
		  '*', '#', '_', '!', '.', 'o', 'q', \
		  'z', 'Z'
#  define ICONV_E2BIG  7
#  define ICONV_EILSEQ 42
#  define ICONV_EINVAL 22
#  define ICONV_ERRNO (*iconv_errno())
# define IME_WITHOUT_XIM
#  define INIT(x) x
#  define INIT2(a, b) = {a, b}
#  define INIT3(a, b, c) = {a, b, c}
#  define INIT4(a, b, c, d) = {a, b, c, d}
#  define INIT5(a, b, c, d, e) = {a, b, c, d, e}
#  define INIT6(a, b, c, d, e, f) = {a, b, c, d, e, f}
#define INSCHAR_COM_LIST 16	
#define KEYLEN_PART_KEY (-1)	
#define KEYLEN_PART_MAP (-2)	
#define KEYLEN_REMOVED  9999	
#define LALLOC_CLEAR_MULT(type, count)  (type *)lalloc_clear(sizeof(type) * (count), FALSE)
#define LALLOC_CLEAR_ONE(type)  (type *)lalloc_clear(sizeof(type), FALSE)
#define LALLOC_MULT(type, count)  (type *)lalloc(sizeof(type) * (count), FALSE)
#define LOG_ALWAYS 9	    
# define LONG_LONG_OFF_T
#define LOWEST_WIN_ID 1000
# define MACOS_CONVERT
# define MACOS_X
# define MAXCOL (0x3fffffffL)		
# define MAXLNUM (0x3fffffffL)		
#define MAXMAPLEN   50
#  define MAXPATHL  MAXPATHLEN
#define MAX_FUNC_NAME_LEN   200
#define MAX_LSHIFT_BITS (varnumber_T)((sizeof(uvarnumber_T) * 8) - 1)
# define MAX_NAMED_PIPE_SIZE 65535
# define MAX_OPEN_CHANNELS 10
#define MAX_SWAP_PAGE_SIZE 50000
#define MAX_TYPENR 65535
# define MAY_WANT_TO_LOG_THIS if (ch_log_output == FALSE) ch_log_output = TRUE;
#define MB_BYTE2LEN(b)		mb_bytelen_tab[b]
#define MB_BYTE2LEN_CHECK(b)	(((b) < 0 || (b) > 255) ? 1 : mb_bytelen_tab[b])
#define MB_FILLER_CHAR '<'  
# define MB_STRICMP(d, s)	mb_strnicmp((char_u *)(d), (char_u *)(s), (int)MAXCOL)
# define MB_STRNICMP(d, s, n)	mb_strnicmp((char_u *)(d), (char_u *)(s), (int)(n))
#define MIN_SWAP_PAGE_SIZE 1048
#define MODE_NORMAL_BUSY (0x1000 | MODE_NORMAL)
#define MOUSE_COLOFF 10000
#define MOUSE_DRAG_XTERM   0x40
#define MOUSE_MOVE 0x700    
#define MSG_BUF_CLEN  (MSG_BUF_LEN / 6)    
#define MSG_BUF_LEN 480	
# define MSWIN
# define MULTISIGN_BYTE 2   
#  define NGETTEXT(x, xs, n) (*dyn_libintl_ngettext)((char *)(x), (char *)(xs), (n))
#define NUMBUFLEN 65
#define NUM_MOUSE_CLICKS(code) \
    (((unsigned)((code) & 0xC0) >> 6) + 1)
#   define N_(x) gettext_noop(x)
# define OLDXAW
#define OPENLINE_COM_LIST   0x10    
#define OPENLINE_DELSPACES  0x01    
#define OPENLINE_KEEPTRAIL  0x04    
#define OPENLINE_MARKFIX    0x08    
# define OPEN_CHR_FILES
#define OUT_STR(s)		    out_str((char_u *)(s))
#define OUT_STR_NF(s)		    out_str_nf((char_u *)(s))
# define O_EXTRA    O_BINARY
# define O_NOFOLLOW 0
#  define PATH_ESC_CHARS ((char_u *)" \t\n*?{`\\%#'\"|!")
# define PERROR(msg)		    (void)semsg("%s: %s", (char *)(msg), strerror(errno))
#define POPF_HIDDEN_FORCE 0x04	
#define PRINTF_DECIMAL_LONG_U SCANF_DECIMAL_LONG_U
# define PRINTF_HEX_LONG_U      "0x%llx"
#   define PROF_GET_TIME(tm) clock_gettime(CLOCK_MONOTONIC, tm)
#   define PROF_NSEC 1
#   define PROF_TIME_BLANK "              "
#   define PROF_TIME_FORMAT "%3ld.%09ld"
#   define PROF_TOTALS_HEADER "count     total (s)      self (s)"
#define PUT_BLOCK_INNER 64      
#define PUT_LINE_FORWARD 32	
# define READBIN    "rb"
#define READ_NOWINENTER 0x80	
#define REPLACE_CR_NCHAR    (-1)
#define REPLACE_NL_NCHAR    (-2)
# define ROOT_UID 0
# define R_OK 4		
#  define SA_ONSTACK_COMPATIBILITY
# define SCANF_DECIMAL_LONG_U   "%llu"
# define SCANF_HEX_LONG_U       "%llx"
#define SEARCH_COL  0x1000  
#define SEARCH_ECHO   0x02  
#define SEARCH_END    0x40  
#define SEARCH_HIS    0x20  
#define SEARCH_KEEP  0x400  
#define SEARCH_MARK  0x200  
#define SEARCH_MSG    0x0c  
#define SEARCH_NFMSG  0x08  
#define SEARCH_NOOF   0x80  
#define SEARCH_OPT    0x10  
#define SEARCH_PEEK  0x800  
#define SEARCH_REV    0x01  
#define SEARCH_START 0x100  
#define SET_NUM_MOUSE_CLICKS(code, num) \
    ((code) = ((code) & 0x3f) | ((((num) - 1) & 3) << 6))
#  define SHELL_ESC_CHARS ((char_u *)" \t\n*?{`\\%#'|!()&")
#define SHOWCMD_COLS 10			
#define SIGNAL_UNBLOCK  (-2)
#define SIGN_BYTE 1	    
# define SST_MAX_ENTRIES 1000	
# define SST_MIN_ENTRIES 150	
#define STR2NR_ALL (STR2NR_BIN + STR2NR_OCT + STR2NR_HEX + STR2NR_OOCT)
#define STR2NR_BIN  0x01
#define STR2NR_FORCE 0x80   
#define STR2NR_HEX  0x04
#define STR2NR_NO_OCT (STR2NR_BIN + STR2NR_HEX + STR2NR_OOCT)
#define STR2NR_OCT  0x02
#define STR2NR_OOCT 0x08    
#define STR2NR_QUOTE 0x10   
#define STRCAT(d, s)	    strcat((char *)(d), (char *)(s))
#define STRCMP(d, s)	    strcmp((char *)(d), (char *)(s))
# define STRCOLL(d, s)     strcoll((char *)(d), (char *)(s))
#define STRCPY(d, s)	    strcpy((char *)(d), (char *)(s))
#  define STRICMP(d, s)	    stricmp((char *)(d), (char *)(s))
#define STRLEN(s)	    strlen((char *)(s))
#define STRMOVE(d, s)	    mch_memmove((d), (s), STRLEN(s) + 1)
#define STRNCAT(d, s, n)    strncat((char *)(d), (char *)(s), (size_t)(n))
#define STRNCMP(d, s, n)    strncmp((char *)(d), (char *)(s), (size_t)(n))
#define STRNCPY(d, s, n)    strncpy((char *)(d), (char *)(s), (size_t)(n))
#  define STRNICMP(d, s, n) strnicmp((char *)(d), (char *)(s), (size_t)(n))
# define SUN_SYSTEM
#  define S_ISBLK(m)	(((m) & S_IFMT) == S_IFBLK)
#  define S_ISCHR(m)	(((m) & S_IFMT) == S_IFCHR)
#  define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#  define S_ISFIFO(m)	(((m) & S_IFMT) == S_IFIFO)
#  define S_ISLNK(m)	(((m) & S_IFMT) == S_IFLNK)
#  define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#  define S_ISSOCK(m)	(((m) & S_IFMT) == S_IFSOCK)
#define TABSTOP_MAX 9999
#define TBUFSZ 2048		
#define TERM_STR(n)	term_strings[(int)(n)]
#define TFN_ASSIGN_WITH_OP 0x100  
#   define TV_FSEC_SEC 1000000000L
#  define UINT32_TYPEDEF uint32_t
#define UNDO_HASH_SIZE 32
# define UNIX
#    define UNUSED __attribute__((unused))
#  define USE_FILE_CHOOSER
# define USE_INPUT_BUF
# define USE_MCH_ERRMSG
#define VALID_BOTLINE_AP 0x40	
#define VAR_TYPE_CHANNEL    9
#define VIF_GET_OLDFILES    16	
# define VIMENC_ATOM_NAME "_VIMENC_TEXT"
#define VIMINFO_VERSION 4
#define VIMINFO_VERSION_WITH_HISTORY 2
#define VIMINFO_VERSION_WITH_MARKS 4
#define VIMINFO_VERSION_WITH_REGISTERS 3
# define VIM_ATOM_NAME "_VIM_TEXT"
#define VIM_DISCARDALL  6
#  define VIM_SIZEOF_INT __SIZEOF_INT__
# define VIM__H
# define VISIBLE_HEIGHT(wp)	((wp)->w_height + (wp)->w_winbar_height)
#define VV_COLLATE      99
#define VV_COLORNAMES   101
#define VV_COMPLETED_ITEM 60
#define VV_MOUSE_LNUM   52
#define VV_OPTION_COMMAND 65
#define VV_OPTION_NEW   61
#define VV_OPTION_OLD   62
#define VV_OPTION_OLDGLOBAL 64
#define VV_OPTION_OLDLOCAL 63
#define VV_OPTION_TYPE  66
#define VV_SEARCHFORWARD 55
#define VV_SIZEOFPOINTER 104
#define VV_TERMBLINKRESP 94
#define VV_TERMSTYLERESP 93
#define VV_VIM_DID_ENTER 75
#define WILD_IGNORE_COMPLETESLASH   0x400
# define WINBAR_HEIGHT(wp)	(wp)->w_winbar_height
#   define WM_OLE (WM_APP+0)
# define WRITEBIN   "wb"	
#define W_ENDCOL(wp)	((wp)->w_wincol + (wp)->w_width)
# define W_OK 2		
# define W_WINROW(wp)	((wp)->w_winrow + (wp)->w_winbar_height)
#  define _(x) gettext((char *)(x))
#    define _BSD_SOURCE 1
#    define _DEFAULT_SOURCE 1
#    define _SVID_SOURCE 1
#  define _TANDEM_SOURCE
#   define _XOPEN_SOURCE    700
# define __ARGS(x)  x
#  define bind_textdomain_codeset(domain, codeset) (*dyn_libintl_bind_textdomain_codeset)((domain), (codeset))
#  define bindtextdomain(domain, dir) (*dyn_libintl_bindtextdomain)((domain), (dir))
# define display_errors()	fflush(stderr)
# define do_dialog gui_mch_dialog
#define fnamecmp(x, y) vim_fnamecmp((char_u *)(x), (char_u *)(y))
#define fnamencmp(x, y, n) vim_fnamencmp((char_u *)(x), (char_u *)(y), (size_t)(n))
#  define gtk_adjustment_set_lower(adj, low) \
    do { (adj)->lower = low; } while (0)
#  define gtk_adjustment_set_page_increment(adj, inc) \
    do { (adj)->page_increment = inc; } while (0)
#  define gtk_adjustment_set_page_size(adj, size) \
    do { (adj)->page_size = size; } while (0)
#  define gtk_adjustment_set_step_increment(adj, inc) \
    do { (adj)->step_increment = inc; } while (0)
#  define gtk_adjustment_set_upper(adj, up) \
    do { (adj)->upper = up; } while (0)
#  define gtk_plug_get_socket_window(wid)	((wid)->socket_window)
#  define gtk_selection_data_get_data(sel)	((sel)->data)
#  define gtk_selection_data_get_data_type(sel)	((sel)->type)
#  define gtk_selection_data_get_format(sel)	((sel)->format)
#  define gtk_selection_data_get_length(sel)	((sel)->length)
#  define gtk_selection_data_get_selection(sel)	((sel)->selection)
#  define gtk_widget_get_allocation(wid, alloc) \
    do { *(alloc) = (wid)->allocation; } while (0)
#  define gtk_widget_get_has_window(wid)	!GTK_WIDGET_NO_WINDOW(wid)
#  define gtk_widget_get_mapped(wid)	GTK_WIDGET_MAPPED(wid)
#  define gtk_widget_get_realized(wid)	GTK_WIDGET_REALIZED(wid)
#  define gtk_widget_get_sensitive(wid)	GTK_WIDGET_SENSITIVE(wid)
#  define gtk_widget_get_visible(wid)	GTK_WIDGET_VISIBLE(wid)
#  define gtk_widget_get_window(wid)	((wid)->window)
#  define gtk_widget_has_focus(wid)	GTK_WIDGET_HAS_FOCUS(wid)
#  define gtk_widget_set_allocation(wid, alloc) \
    do { (wid)->allocation = *(alloc); } while (0)
#  define gtk_widget_set_can_default(wid, can) \
    do { if (can) \
	    { GTK_WIDGET_SET_FLAGS(wid, GTK_CAN_DEFAULT); } \
	else \
	    { GTK_WIDGET_UNSET_FLAGS(wid, GTK_CAN_DEFAULT); } } while (0)
#  define gtk_widget_set_can_focus(wid, can) \
    do { if (can) \
	    { GTK_WIDGET_SET_FLAGS(wid, GTK_CAN_FOCUS); } \
	else \
	    { GTK_WIDGET_UNSET_FLAGS(wid, GTK_CAN_FOCUS); } } while (0)
#  define gtk_widget_set_mapped(wid, map) \
    do { if (map) \
	    { GTK_WIDGET_SET_FLAGS(wid, GTK_MAPPED); } \
	else \
	    { GTK_WIDGET_UNSET_FLAGS(wid, GTK_MAPPED); } } while (0)
#  define gtk_widget_set_realized(wid, rea) \
    do { if (rea) \
	    { GTK_WIDGET_SET_FLAGS(wid, GTK_REALIZED); } \
	else \
	    { GTK_WIDGET_UNSET_FLAGS(wid, GTK_REALIZED); } } while (0)
#  define gtk_widget_set_visible(wid, vis) \
    do { if (vis) \
	    { gtk_widget_show(wid); } \
	else \
	    { gtk_widget_hide(wid); } } while (0)
#  define gtk_widget_set_window(wid, win) \
    do { (wid)->window = (win); } while (0)
#  define libintl_wputenv(envstring) (*dyn_libintl_wputenv)(envstring)
# define likely(x)	__builtin_expect((x), 1)
# define mch_errmsg(str)	fprintf(stderr, "%s", (str))
# define mch_fopen(n, p)	fopen((n), (p))
# define mch_memmove(to, from, len) memmove((char*)(to), (char*)(from), (size_t)(len))
# define mch_msg(str)		printf("%s", (str))
# define mch_open(n, m, p)	open((n), (m), (p))
# define nbdebug(a)
# define number_width(x) 7
# define read_eintr(fd, buf, count) vim_read((fd), (buf), (count))
#  define textdomain(domain) (*dyn_libintl_textdomain)(domain)
#   define tv_fsec tv_nsec
# define unlikely(x)	__builtin_expect((x), 0)
#  define vim_fseek fseeko64
#  define vim_ftell ftello64
# define vim_handle_signal(x) 0
#  define vim_lseek lseek64
# define vim_memset(ptr, c, size)   memset((ptr), (c), (size))
# define vim_read(fd, buf, count)   read((fd), (char *)(buf), (unsigned int)(count))
# define vim_realloc(ptr, size)  mem_realloc((ptr), (size))
# define vim_strpbrk(s, cs) (char_u *)strpbrk((char *)(s), (char *)(cs))
# define vim_write(fd, buf, count)  write((fd), (char *)(buf), (unsigned int)(count))
# define write_eintr(fd, buf, count) vim_write((fd), (buf), (count))
# define ARABIC_CHAR(ch)	    (((ch) & 0xFF00) == 0x0600)
#define ARRAY_LENGTH(a) (sizeof(a) / sizeof((a)[0]))
#define ASCII_ISALNUM(c) (ASCII_ISALPHA(c) || VIM_ISDIGIT(c))
#define ASCII_ISALPHA(c) (ASCII_ISUPPER(c) || ASCII_ISLOWER(c))
#define ASCII_ISLOWER(c) ((unsigned)(c) - 'a' < 26)
#define ASCII_ISUPPER(c) ((unsigned)(c) - 'A' < 26)
#define BUFEMPTY() (curbuf->b_ml.ml_line_count == 1 && *ml_get((linenr_T)1) == NUL)
# define CHECK_CURBUF \
    do { \
	if (curwin != NULL && curwin->w_buffer != curbuf) \
	    iemsg("curbuf != curwin->w_buffer"); \
    } while (0)
#define CHECK_LIST_MATERIALIZE(l) \
    do { \
	if ((l)->lv_first == &range_list_item) \
	    range_list_materialize(l); \
    } while (0)
#define CLEAR_POS(a) do {(a)->lnum = 0; (a)->col = 0; (a)->coladd = 0;} while (0)
# define CURSOR_BAR_RIGHT (curwin->w_p_rl && (!(State & MODE_CMDLINE) || cmdmsg_rl))
#   define DBL_EPSILON 2.2204460492503131e-16
#define DI2HIKEY(di) ((di)->di_key)
# define DO_AUTOCHDIR do { if (p_acd) do_autochdir(); } while (0)
#define EMPTY_IF_NULL(x) ((x) ? (x) : (char_u *)"")
#define EMPTY_POS(a) ((a).lnum == 0 && (a).col == 0 && (a).coladd == 0)
#define EQUAL_POS(a, b) (((a).lnum == (b).lnum) && ((a).col == (b).col) && ((a).coladd == (b).coladd))
# define ERROR_IF_ANY_POPUP_WINDOW error_if_popup_window(TRUE)
# define ERROR_IF_POPUP_WINDOW error_if_popup_window(FALSE)
# define ERROR_IF_TERM_POPUP_WINDOW error_if_term_popup_window()
# define ESTACK_CHECK_DECLARATION int estack_len_before
# define ESTACK_CHECK_NOW \
    do { \
	if (estack_len_before != exestack.ga_len) \
	    siemsg("Exestack length expected: %d, actual: %d", estack_len_before, exestack.ga_len); \
    } while (0)
# define ESTACK_CHECK_SETUP do { estack_len_before = exestack.ga_len; } while (0)
#define FOR_ALL_BUFFERS(buf) \
    for ((buf) = firstbuf; (buf) != NULL; (buf) = (buf)->b_next)
#define FOR_ALL_BUF_WININFO(buf, wip) \
    for ((wip) = (buf)->b_wininfo; (wip) != NULL; (wip) = (wip)->wi_next)
#define FOR_ALL_CHILD_MENUS(p, c) \
    for ((c) = (p)->children; (c) != NULL; (c) = (c)->next)
#define FOR_ALL_FRAMES(frp, first_frame) \
    for ((frp) = first_frame; (frp) != NULL; (frp) = (frp)->fr_next)
#define FOR_ALL_HASHTAB_ITEMS(ht, hi, todo) \
    for ((hi) = (ht)->ht_array; (todo) > 0; ++(hi))
#define FOR_ALL_LIST_ITEMS(l, li) \
    for ((li) = (l) == NULL ? NULL : (l)->lv_first; (li) != NULL; (li) = (li)->li_next)
#define FOR_ALL_MENUS(m) \
    for ((m) = root_menu; (m) != NULL; (m) = (m)->next)
#define FOR_ALL_POPUPWINS(wp) \
    for ((wp) = first_popupwin; (wp) != NULL; (wp) = (wp)->w_next)
#define FOR_ALL_POPUPWINS_IN_TAB(tp, wp) \
    for ((wp) = (tp)->tp_first_popupwin; (wp) != NULL; (wp) = (wp)->w_next)
#define FOR_ALL_SIGNS_IN_BUF(buf, sign) \
    for ((sign) = (buf)->b_signlist; (sign) != NULL; (sign) = (sign)->se_next)
#define FOR_ALL_SPELL_LANGS(slang) \
    for ((slang) = first_lang; (slang) != NULL; (slang) = (slang)->sl_next)
#define FOR_ALL_TABPAGES(tp) \
    for ((tp) = first_tabpage; (tp) != NULL; (tp) = (tp)->tp_next)
#define FOR_ALL_TAB_WINDOWS(tp, wp) \
    for ((tp) = first_tabpage; (tp) != NULL; (tp) = (tp)->tp_next) \
	for ((wp) = ((tp) == curtab) \
		? firstwin : (tp)->tp_firstwin; (wp); (wp) = (wp)->w_next)
#define FOR_ALL_WINDOWS(wp) \
    for ((wp) = firstwin; (wp) != NULL; (wp) = (wp)->w_next)
#define FOR_ALL_WINDOWS_IN_TAB(tp, wp) \
    for ((wp) = ((tp) == NULL || (tp) == curtab) \
	    ? firstwin : (tp)->tp_firstwin; (wp); (wp) = (wp)->w_next)
# define FUNCARG(fp, j)	((char_u **)(fp->uf_args.ga_data))[j]
#define GA_GROW_FAILS(gap, n) unlikely((((gap)->ga_maxlen - (gap)->ga_len < (n)) ? ga_grow_inner((gap), (n)) : OK) == FAIL)
#define GA_GROW_OK(gap, n) likely((((gap)->ga_maxlen - (gap)->ga_len < (n)) ? ga_grow_inner((gap), (n)) : OK) == OK)
#define HI2DI(hi)     HIKEY2DI((hi)->hi_key)
#define HIKEY2DI(p)  ((dictitem_T *)((p) - offsetof(dictitem_T, di_key)))
#     define INFINITY DBL_MAX
#define IS_USER_CMDIDX(idx) ((int)(idx) < 0)
#define IS_WHITE_OR_NUL(x)	((x) == ' ' || (x) == '\t' || (x) == NUL)
# define LANGMAP_ADJUST(c, condition) \
    do { \
	if (*p_langmap \
		&& (condition) \
		&& (p_lrm || (!p_lrm && KeyTyped)) \
		&& !KeyStuffed \
		&& (c) >= 0) \
	{ \
	    if ((c) < 256) \
		c = langmap_mapchar[c]; \
	    else \
		c = langmap_adjust_mb(c); \
	} \
    } while (0)
#define LINEEMPTY(p) (*ml_get(p) == NUL)
#define LTOREQ_POS(a, b) (LT_POS(a, b) || EQUAL_POS(a, b))
#define LT_POS(a, b) (((a).lnum != (b).lnum) \
		   ? (a).lnum < (b).lnum \
		   : (a).col != (b).col \
		       ? (a).col < (b).col \
		       : (a).coladd < (b).coladd)
#define LT_POSP(a, b) (((a)->lnum != (b)->lnum) \
		   ? (a)->lnum < (b)->lnum \
		   : (a)->col != (b)->col \
		       ? (a)->col < (b)->col \
		       : (a)->coladd < (b)->coladd)
# define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MB_CASEFOLD(c)	(enc_utf8 ? utf_fold(c) : MB_TOLOWER(c))
#define MB_CHAR2BYTES(c, b) do { if (has_mbyte) (b) += (*mb_char2bytes)((c), (b)); else *(b)++ = (c); } while(0)
#define MB_CHAR2LEN(c)	    (has_mbyte ? mb_char2len(c) : 1)
#define MB_CHARLEN(p)	    (has_mbyte ? mb_charlen(p) : (int)STRLEN(p))
#define MB_COPY_CHAR(f, t) do { if (has_mbyte) mb_copy_char(&(f), &(t)); else *(t)++ = *(f)++; } while (0)
#define MB_CPTR2LEN(p)	    (enc_utf8 ? utf_ptr2len(p) : (*mb_ptr2len)(p))
#define MB_CPTR_ADV(p)	    p += enc_utf8 ? utf_ptr2len(p) : (*mb_ptr2len)(p)
#define MB_ISLOWER(c)	vim_islower(c)
#define MB_ISUPPER(c)	vim_isupper(c)
#define MB_PTR_ADV(p)	    p += (*mb_ptr2len)(p)
#define MB_PTR_BACK(s, p)  p -= has_mbyte ? ((*mb_head_off)(s, (p) - 1) + 1) : 1
#define MB_TOLOWER(c)	vim_tolower(c)
#define MB_TOUPPER(c)	vim_toupper(c)
# define MESSAGE_QUEUE
# define MIN(a, b) ((a) < (b) ? (a) : (b))
#   define NAN (INFINITY-INFINITY)
#define PBYTE(lp, c) (*(ml_get_buf(curbuf, (lp).lnum, TRUE) + (lp).col) = (c))
# define PLINES_NOFILL(x) plines_nofill(x)
# define PLINES_WIN_NOFILL(w, l, h) plines_win_nofill((w), (l), (h))
#define PTR2CHAR(p)	    (has_mbyte ? mb_ptr2char(p) : (int)*(p))
#define REPLACE_NORMAL(s) (((s) & REPLACE_FLAG) && !((s) & VREPLACE_FLAG))
#define RESET_BINDING(wp)  do { (wp)->w_p_scb = FALSE; (wp)->w_p_crb = FALSE; \
			    } while (0)
# define TIME_MSG(s) do { if (time_fd != NULL) time_msg(s, NULL); } while (0)
#define TOLOWER_ASC(c)	(((c) < 'A' || (c) > 'Z') ? (c) : (c) + ('a' - 'A'))
#  define TOLOWER_LOC(c)	tolower_tab[(c) & 255]
#define TOUPPER_ASC(c)	(((c) < 'a' || (c) > 'z') ? (c) : (c) - ('a' - 'A'))
#  define TOUPPER_LOC(c)	toupper_tab[(c) & 255]
# define UTF_COMPOSINGLIKE(p1, p2)  utf_composinglike((p1), (p2))
#define VIM_CLEAR(p) \
    do { \
	if ((p) != NULL) \
	{ \
	    vim_free(p); \
	    (p) = NULL; \
	} \
    } while (0)
#define VIM_ISBREAK(c) ((c) < 256 && breakat_flags[(char_u)(c)])
#define VIM_ISDIGIT(c) ((unsigned)(c) - '0' < 10)
#define VIM_ISWHITE(x)		((x) == ' ' || (x) == '\t')
# define WIN_IS_POPUP(wp) ((wp)->w_popup_flags != 0)
#    define isnan(x) _isnan(x)
#   define mch_access(n, p)	access((n), (p))
# define mch_disable_flush()	gui_disable_flush()
# define mch_enable_flush()	gui_enable_flush()
#  define mch_fstat(n, p)	_fstat64((n), (p))
# define mch_lstat(n, p)	lstat((n), (p))
#  define mch_open_rw(n, f)	mch_open((n), (f), S_IREAD | S_IWRITE)
#   define mch_stat(n, p)	vim_stat((n), (p))
#define IS_SPECIAL(c)		((c) < 0)
#define KEY2TERMCAP0(x)		((-(x)) & 0xff)
#define KEY2TERMCAP1(x)		(((unsigned)(-(x)) >> 8) & 0xff)
#define K_HOR_SCROLLBAR   TERMCAP2KEY(KS_HOR_SCROLLBAR, KE_FILLER)
#define K_LEFTRELEASE_NM TERMCAP2KEY(KS_EXTRA, KE_LEFTRELEASE_NM)
#define K_SCRIPT_COMMAND TERMCAP2KEY(KS_EXTRA, KE_SCRIPT_COMMAND)
#define K_SECOND(c)	((c) == K_SPECIAL ? KS_SPECIAL : (c) == NUL ? KS_ZERO : KEY2TERMCAP0(c))
#define K_SGR_MOUSERELEASE TERMCAP2KEY(KS_SGR_MOUSE_RELEASE, KE_FILLER)
#define K_THIRD(c)	(((c) == K_SPECIAL || (c) == NUL) ? KE_FILLER : KEY2TERMCAP1(c))
#define K_X1RELEASE     TERMCAP2KEY(KS_EXTRA, KE_X1RELEASE)
#define K_X2RELEASE     TERMCAP2KEY(KS_EXTRA, KE_X2RELEASE)
#define MAX_KEY_CODE_LEN    6
#define MAX_KEY_NAME_LEN    32
#define TERMCAP2KEY(a, b)	(-((a) + ((int)(b) << 8)))
#define TO_SPECIAL(a, b)    ((a) == KS_SPECIAL ? K_SPECIAL : (a) == KS_ZERO ? K_ZERO : TERMCAP2KEY(a, b))
#define CharOrd(x)	((x) < 'a' ? (x) - 'A' : (x) - 'a')
#define CharOrdLow(x)	((x) - 'a')
#define CharOrdUp(x)	((x) - 'A')
#define Ctrl_chr(x)	(TOUPPER_ASC(x) ^ 0x40) 
#define Meta(x)		((x) | 0x80)
#define ROT13(c, a)	(((((c) - (a)) + 13) % 26) + (a))
# define ALWAYS_USE_GUI
# define CURSOR_SHAPE
# define DOS_MOUSE
# define FEAT_ARABIC
# define FEAT_ARP
# define FEAT_AUTOCHDIR
#  define FEAT_AUTOSERVERNAME
# define FEAT_AUTOSHELLDIR
# define FEAT_BEVAL
# define FEAT_BEVAL_GUI
# define FEAT_BEVAL_TERM
#  define FEAT_BROWSE
# define FEAT_BROWSE_CMD
# define FEAT_BYTEOFF
# define FEAT_CLIENTSERVER
# define FEAT_COMPL_FUNC
# define FEAT_CONCEAL
#  define FEAT_CON_DIALOG
# define FEAT_CRYPT
# define FEAT_CSCOPE
# define FEAT_DIFF
# define FEAT_DIGRAPHS
# define FEAT_DND
# define FEAT_EMACS_TAGS
# define FEAT_EVAL
# define FEAT_FILTERPIPE
# define FEAT_FIND_ID
# define FEAT_FOLDING
# define FEAT_GUI_DARKTHEME
#  define FEAT_GUI_DIALOG
# define FEAT_GUI_TABLINE
# define FEAT_GUI_TEXTDIALOG
# define FEAT_GUI_X11
#  define FEAT_HUGE
# define FEAT_KEYMAP
# define FEAT_LANGMAP
# define FEAT_LIBCALL
# define FEAT_LINEBREAK
#  define FEAT_MENU
#  define FEAT_MOUSESHAPE
#  define FEAT_MOUSE_DEC
# define FEAT_MOUSE_GPM
#  define FEAT_MOUSE_NET
# define FEAT_MOUSE_PTERM
#  define FEAT_MOUSE_URXVT
# define FEAT_MOUSE_XTERM
# define FEAT_MULTI_LANG
#  define FEAT_NORMAL
# define FEAT_PERSISTENT_UNDO
# define FEAT_POSTSCRIPT
# define FEAT_PRINTER
# define FEAT_PROFILE
# define FEAT_PROP_POPUP
# define FEAT_QUICKFIX
# define FEAT_RELTIME
#   define FEAT_RIGHTLEFT
# define FEAT_SEARCH_EXTRA
# define FEAT_SESSION
# define FEAT_SIGNS
#  define FEAT_SIGN_ICONS
# define FEAT_SODIUM
# define FEAT_SOUND_CANBERRA
# define FEAT_SPELL
# define FEAT_STL_OPT
# define FEAT_SYN_HL
# define FEAT_SYSMOUSE
#  define FEAT_TEAROFF
# define FEAT_TERMGUICOLORS
# define FEAT_TERMRESPONSE
# define FEAT_TERM_POPUP_MENU
# define FEAT_TIMERS
#  define FEAT_TINY
# define FEAT_TOOLBAR
# define FEAT_VARTABS
# define FEAT_VIMINFO
# define FEAT_VTP
# define FEAT_WRITEBACKUP
# define FEAT_XCLIPBOARD
#  define FEAT_XFONTSET
# define FIND_REPLACE_DIALOG 1
# define HAS_MESSAGE_WINDOW
# define HAVE_SANDBOX
# define HAVE_XPM 1
#define MAX_MSG_HIST_LEN 200
#  define MCH_CURSOR_SHAPE
# define MSWIN_FR_BUFSIZE 256
# define MZSCHEME_GUI_THREADS
# define RUNTIME_DIRNAME "runtime"
# define STARTUPTIME 1
# define SYN_TIME_LIMIT 1
# define USE_DLOPEN
# define USE_ICONV
# define USE_XIM 1		
# define USE_XSMP
# define USING_LOAD_LIBRARY
# define WANT_X11
