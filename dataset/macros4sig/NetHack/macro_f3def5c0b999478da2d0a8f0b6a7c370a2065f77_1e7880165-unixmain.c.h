

#include<string.h>

#include<stddef.h>


#include<unistd.h>

#include<linux/unistd.h>

#include<stdarg.h>

#include<sys/stat.h>


#include<ctype.h>
#include<sys/wait.h>

#include<varargs.h>

#include<sys/file.h>


#include<pwd.h>

#include<time.h>
#include<memory.h>

#include<stdlib.h>

#include<strings.h>
#include<fcntl.h>





#include<signal.h>
#include<sys/syscall.h>


#include<sys/time.h>


#include<stdio.h>

#include<sys/types.h>
#define DLBBASENAME "nhdat"
#define DLBFILE "nhdat" 
#define DLBLIB 
#define DLBRSRC 

#define DLB_P struct dlb_handle *
#define FILENAME_CMP strcmp 
#define MAX_DLB_FILENAME 256
#define RDBMODE "rb"
#define RDTMODE "r"
#define SEEK_CUR 1
#define SEEK_END 2
#define SEEK_SET 0
#define WRBMODE "w+b"
#define WRTMODE "w+b"
#define dlb FILE

#define dlb_fclose fclose
#define dlb_fgetc fgetc
#define dlb_fgets fgets
#define dlb_fopen fopen
#define dlb_fread fread
#define dlb_fseek fseek
#define dlb_ftell ftell

#define AC_VALUE(AC) ((AC) >= 0 ? (AC) : -rnd(-(AC)))
#define ALL_FINISHED 0x01 
#define ALL_TYPES    0x010
#define ALL_TYPES_SELECTED -2
#define ARM_BONUS(obj)                      \
    (objects[(obj)->otyp].a_ac + (obj)->spe \
     - min((int) greatest_erosion(obj), objects[(obj)->otyp].a_ac))
#define AUTOSELECT_SINGLE 0x02 
#define BALL_IN_MON (u.uswallow && uball && uball->where == OBJ_FREE)
#define BASICENLIGHTENMENT 1 
#define BILLED_TYPES 0x020
#define BOLT_LIM 8        
#define BUCX_TYPES (BUC_ALLBKNOWN | BUC_UNKNOWN)
#define BUC_ALLBKNOWN (BUC_BLESSED | BUC_CURSED | BUC_UNCURSED)
#define BUC_BLESSED  0x080
#define BUC_CURSED   0x100
#define BUC_UNCURSED 0x200
#define BUC_UNKNOWN  0x400
#define BY_COOKIE 1
#define BY_NEXTHERE     0x01   
#define BY_ORACLE 0
#define BY_OTHER 9
#define BY_PAPER 2
#define CFDECLSPEC __cdecl
#define CHAIN_IN_MON (u.uswallow && uchain && uchain->where == OBJ_FREE)
#define CHOOSE_ALL   0x040
#define CORPSTAT_BURIED 0x02 
#define CORPSTAT_INIT 0x01   
#define CORPSTAT_NONE 0x00
#define CXN_ARTICLE 8   
#define CXN_NOCORPSE 16 
#define CXN_NORMAL 0    
#define CXN_NO_PFX 2    
#define CXN_PFX_THE 4   
#define CXN_SINGULAR 1  
#define DEFUNCT_MONSTER (-100)
#define DEVTEAM_EMAIL "devteam@nethack.org"
#define DEVTEAM_URL "https://www.nethack.org/"
#define DF_ALL      0x04
#define DF_NONE     0x00
#define DF_RANDOM   0x01
#define DISP_IN_GAME 3 
#define DO_MOVE 0   
#define DUMMY { 0 }       
#define ENL_GAMEINPROGRESS 0
#define ENL_GAMEOVERALIVE  1 
#define ENL_GAMEOVERDEAD   2
#define FAILEDUNTRAP 0x40  
#define FEATURE_NOTICE_VER(major, minor, patch)                    \
    (((unsigned long) major << 24) | ((unsigned long) minor << 16) \
     | ((unsigned long) patch << 8) | ((unsigned long) 0))
#define FEATURE_NOTICE_VER_MAJ (flags.suppress_alert >> 24)
#define FEATURE_NOTICE_VER_MIN \
    (((unsigned long) (0x0000000000FF0000L & flags.suppress_alert)) >> 16)
#define FEATURE_NOTICE_VER_PATCH \
    (((unsigned long) (0x000000000000FF00L & flags.suppress_alert)) >> 8)
#define FEEL_COCKATRICE 0x40   
#define FLING 0x02         
#define FM_EVERYWHERE (FM_FMON | FM_MIGRATE | FM_MYDOGS)
#define FM_FMON 0x01    
#define FM_MIGRATE 0x02 
#define FM_MYDOGS 0x04  
#define FORCEBUNGLE 0x04   
#define FORCETRAP 0x01     
#define GOLD_TYPES   0x004
#define GP_ALLOW_XY 0x08000 

#define HEALTHY_TIN (-3)
#define HOMEMADE_TIN 1
#define INCLUDE_HERO    0x80   
#define INVORDER_SORT   0x08   
#define IRON_BALL_W_INCR 160
#define LAUNCH_KNOWN 0x80  
#define LAUNCH_UNSEEN 0x40 
#define MAGICENLIGHTENMENT 2 
#define MATCH_WARN_OF_MON(mon)                                               \
    (Warn_of_mon && ((context.warntype.obj                                   \
                      && (context.warntype.obj & (mon)->data->mflags2))      \
                     || (context.warntype.polyd                              \
                         && (context.warntype.polyd & (mon)->data->mflags2)) \
                     || (context.warntype.species                            \
                         && (context.warntype.species == (mon)->data))))
#define MAX_CARR_CAP 1000 
#define MAY_DESTROY 0x08  
#define MAY_FRACTURE 0x10 
#define MAY_HIT (MAY_HITMON | MAY_HITYOU)
#define MAY_HITMON 0x02  
#define MAY_HITYOU 0x04  
#define MENUTYPELEN sizeof("traditional ")
#define MENU_COMBINATION 1
#define MENU_FULL 2
#define MENU_PARTIAL 3
#define MENU_SELECTED TRUE
#define MENU_TRADITIONAL 0
#define MENU_UNSELECTED FALSE
#define MG_BW_LAVA 0x80  
#define MG_CORPSE  0x01
#define MG_DETECT  0x04
#define MG_FLAG_NOOVERRIDE 0x01
#define MG_FLAG_NORMAL     0x00
#define MG_INVIS   0x02
#define MG_OBJPILE 0x40  
#define MG_PET     0x08
#define MG_RIDDEN  0x10
#define MG_STATUE  0x20
#define MM_ADJACENTOK   0x00010 
#define MM_ANGRY    0x00020 
#define MM_ASLEEP   0x02000 
#define MM_EDOG     0x01000 
#define MM_EGD      0x00100 
#define MM_EMIN     0x00800 
#define MM_EPRI     0x00200 
#define MM_ESHK     0x00400 
#define MM_IGNOREWATER  0x00008 
#define MM_NOCOUNTBIRTH 0x00004 
#define MM_NOGRP    0x04000 
#define MM_NONAME   0x00040 
#define MM_NOWAIT   0x00002 
#define Maybe_Half_Phys(dmg) \
    ((Half_physical_damage) ? (((dmg) + 1) / 2) : (dmg))
#define NDECL(f) f()
#define NODIAG(monnum) ((monnum) == PM_GRID_BUG)
#define NOTELL 0
#define NOWEBMSG 0x02      
#define NO_MINVENT  0x00001 
#define NO_MM_FLAGS 0x00000 
#define OFF 0
#define ON 1
#define OVERRIDE_MSGTYPE 2
#define PICK_RANDOM 0
#define PICK_RIGID 1
#define PLINE_NOREPEAT   1
#define POTION_OCCUPANT_CHANCE(n) (13 + 2 * (n))
#define RANDOM_TIN (-2)
#define RECURSIVETRAP 0x08 
#define ROLL 0x01          
#define ROTTEN_TIN 0
#define SELL_DELIBERATE (1)
#define SELL_DONTSELL (2)
#define SELL_NORMAL (0)
#define SET_IN_FILE 1  
#define SET_IN_GAME 4  
#define SET_IN_SYS 0   
#define SET_IN_WIZGAME 5  
#define SET_VIA_PROG 2 
#define SET__IS_VALUE_VALID(s) ((s < SET_IN_SYS) || (s > SET_IN_WIZGAME))
#define SHIFT_MSG 0x02     
#define SHIFT_SEENMSG 0x01 
#define SHOP_BARS_COST 300L 
#define SHOP_DOOR_COST 400L 
#define SHOP_HOLE_COST 200L 
#define SHOP_WALL_COST 200L 
#define SHOP_WALL_DMG  (10L * ACURRSTR) 
#define SIGNAL_ESCAPE   0x20   
#define SIGNAL_NOMENU   0x10   
#define SORTLOOT_INVLET 0x02
#define SORTLOOT_LOOT   0x04
#define SORTLOOT_PACK   0x01
#define SORTLOOT_PETRIFY 0x20 
#define SPINACH_TIN (-1)
#define STATIC_DCL extern
#define STATIC_OVL static
#define STATIC_PTR static
#define STATIC_VAR static
#define SUPPRESS_HISTORY 4
#define SYM_MAX (SYM_OFF_X + MAXOTHER)
#define SYM_OFF_M (SYM_OFF_O + MAXOCLASSES)
#define SYM_OFF_O (SYM_OFF_P + MAXPCHARS)
#define SYM_OFF_P (0)
#define SYM_OFF_W (SYM_OFF_M + MAXMCLASSES)
#define SYM_OFF_X (SYM_OFF_W + WARNCOUNT)
#define TELL 1
#define TEST_MOVE 1 
#define TEST_TRAP 3 
#define TEST_TRAV 2 
#define TOOKPLUNGE 0x10    
#define UNPAID_TYPES 0x002
#define URGENT_MESSAGE   8
#define USE_INVLET      0x04   

#define VAULT_GUARD_TIME 30
#define VIASITTING 0x20    
#define VIS_EFFECTS 0x01 
#define WAND_BACKFIRE_CHANCE 100
#define WORN_TYPES   0x008
#define XKILL_GIVEMSG   0
#define XKILL_NOCONDUCT 4
#define XKILL_NOCORPSE  2
#define XKILL_NOMSG     1
#define distu(xx, yy) dist2((int)(xx), (int)(yy), (int) u.ux, (int) u.uy)
#define getlogin() ((char *) 0)
#define getuid() 1
#define makeknown(x) discover_object((x), TRUE, TRUE)
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(x, y) ((x) < (y) ? (x) : (y))
#define nyNaq(query) yn_function(query, ynNaqchars, 'n')
#define nyaq(query) yn_function(query, ynaqchars, 'n')
#define onlineu(xx, yy) online2((int)(xx), (int)(yy), (int) u.ux, (int) u.uy)
#define plur(x) (((x) == 1) ? "" : "s")
#define rn1(x, y) (rn2(x) + (y))
#define yn(query) yn_function(query, ynchars, 'n')
#define ynNaq(query) yn_function(query, ynNaqchars, 'y')
#define ynaq(query) yn_function(query, ynaqchars, 'y')
#define ynq(query) yn_function(query, ynqchars, 'q')
#define E extern

#define lift_covet_and_placebc(x) \
            Lift_covet_and_placebc(x, __FUNCTION__, "__LINE__") 
#define placebc() Placebc(__FUNCTION__, "__LINE__")
#define unplacebc() Unplacebc(__FUNCTION__, "__LINE__")
#define unplacebc_and_covet_placebc() \
            Unplacebc_and_covet_placebc(__FUNCTION__, "__LINE__")
#define Armor_off() Armor_off_()
#define Armor_on() Armor_on_()
#define Boots_off() Boots_off_()
#define Boots_on() Boots_on_()
#define Gloves_off() Gloves_off_()
#define Gloves_on() Gloves_on_()
#define Hear_again() Hear_again_()
#define Helmet_off() Helmet_off_()
#define Helmet_on() Helmet_on_()

#define bhitm(x, y) bhitm_(x, y)
#define bhito(x, y) bhito_(x, y)
#define ck_bag(x) ck_bag_(x)
#define ckunpaid(x) ckunpaid_(x)
#define ddocall() ddocall_()
#define ddoinv() ddoinv_()
#define dig() dig_()
#define do_comp(x, y) comp_(x, y)
#define do_mname() do_mname_()
#define doapply() doapply_()
#define docast() docast_()
#define doclose() doclose_()
#define doddoremarm() doddoremarm_()
#define doddrop() doddrop_()
#define dodip() dodip_()
#define dodiscovered() dodiscovered_()
#define dodown() dodown_()
#define dodrink() dodrink_()
#define dodrop() dodrop_()
#define doeat() doeat_()
#define doengrave() doengrave_()
#define doextcmd() doextcmd_()
#define doextlist() doextlist_()
#define doextversion() doextversion_()
#define doforce() doforce_()
#define dohelp() dohelp_()
#define dohistory() dohistory_()
#define doidtrap() doidtrap_()
#define doinvoke() doinvoke_()
#define dojump() dojump_()
#define dokick() dokick_()
#define dolook() dolook_()
#define doloot() doloot_()
#define domonability() domonability_()
#define doname(x) doname_(x)
#define done1(sig) done1_(sig)
#define done2() done2_()
#define done_hangup(sig) done_hangup_(sig)
#define done_intr(sig) done_intr_(sig)
#define donull() donull_()
#define doopen() doopen_()
#define doorganize() doorganize_()
#define dopay() dopay_()
#define dopickup() dopickup_()
#define dopramulet() dopramulet_()
#define doprarm() doprarm_()
#define dopray() dopray_()
#define doprev_message() doprev_message_()
#define doprgold() doprgold_()
#define doprring() doprring_()
#define doprtool() doprtool_()
#define doprwep() doprwep_()
#define doputon() doputon_()
#define doquickwhatis() doquickwhatis_()
#define doread() doread_()
#define doredraw() doredraw_()
#define doremring() doremring_()
#define dorub() dorub_()
#define dosacrifice() dosacrifice_()
#define dosave() dosave_()
#define dosearch() dosearch_()
#define doset() doset_()
#define dosh() dosh_()
#define dosit() dosit_()
#define dosuspend() dosuspend_()
#define dotakeoff() dotakeoff_()
#define dotalk() dotalk_()
#define dotele() dotele_()
#define dothrow() dothrow_()
#define dotogglepickup() dotogglepickup_()
#define doturn() doturn_()
#define dotypeinv() dotypeinv_()
#define dountrap() dountrap_()
#define doup() doup_()
#define doversion() doversion_()
#define dovspell() dovspell_()
#define dowear() dowear_()
#define dowhatdoes() dowhatdoes_()
#define dowhatis() dowhatis_()
#define dowield() dowield_()
#define dowipe() dowipe_()
#define dozap() dozap_()
#define drop(x) drop_(x)
#define eatfood() eatfood_()
#define eatmdone() eatmdone_()
#define enter_explore_mode() enter_explore_mode_()
#define findone(zx, zy, num) findone_(zx, zy, num)
#define float_down() float_down_()
#define forcelock() forcelock_()
#define genl_outrip(tmpwin, how) genl_outrip_(tmpwin, how)
#define gush(x, y, poolcnt) gush_(x, y, poolcnt)
#define hangup(sig) hangup_(sig)
#define identify(x) identify_(x)
#define in_container(x) in_container_(x)
#define intruph() intruph_()
#define learn() learn_()
#define mbhitm(x, y) mbhitm_(x, y)
#define openone(zx, zy, num) openone_(zx, zy, num)
#define opentin() opentin_()
#define out_container(x) out_container_(x)
#define picklock() picklock_()
#define prayer_done() prayer_done_()
#define select_off(x) select_off_(x)
#define set_lit(x, y, val) set_lit_(x, y, val)
#define stealarm() stealarm_()
#define take_off() take_off_()
#define timed_occupation() timed_occupation_()
#define tty_add_menu(a, b, c, d, e, f, g, h) \
    tty_add_menu_(a, b, c, d, e, f, g, h)
#define tty_askname() tty_askname_()
#define tty_clear_nhwindow(x) tty_clear_nhwindow_(x)
#define tty_cliparound(x, y) tty_cliparound_(x, y)
#define tty_create_nhwindow(x) tty_create_nhwindow_(x)
#define tty_curs(x, y, z) tty_curs_(x, y, z)
#define tty_delay_output() tty_delay_output_()
#define tty_destroy_nhwindow(x) tty_destroy_nhwindow_(x)
#define tty_display_file(x, y) tty_display_file_(x, y)
#define tty_display_nhwindow(x, y) tty_display_nhwindow_(x, y)
#define tty_doprev_message() tty_doprev_message_()
#define tty_end_menu(a, b) tty_end_menu_(a, b)
#define tty_end_screen() tty_end_screen_()
#define tty_exit_nhwindows(x) tty_exit_nhwindows_(x)
#define tty_get_ext_cmd() tty_get_ext_cmd_()
#define tty_get_nh_event() tty_get_nh_event_()
#define tty_getlin(x, y) tty_getlin_(x, y)
#define tty_init_nhwindows(x, y) tty_init_nhwindows_(x, y)
#define tty_mark_synch() tty_mark_synch_()
#define tty_nh_poskey(x, y, z) tty_nh_poskey_(x, y, z)
#define tty_nhbell() tty_nhbell_()
#define tty_nhgetch() tty_nhgetch_()
#define tty_number_pad(x) tty_number_pad_(x)
#define tty_player_selection() tty_player_selection_()
#define tty_print_glyph(a, b, c, d, e) tty_print_glyph_(a, b, c, d, e)
#define tty_putstr(x, y, z) tty_putstr_(x, y, z)
#define tty_raw_print(x) tty_raw_print_(x)
#define tty_raw_print_bold(x) tty_raw_print_bold_(x)
#define tty_resume_nhwindows() tty_resume_nhwindows_()
#define tty_select_menu(a, b, c) tty_select_menu_(a, b, c)
#define tty_start_menu(x) tty_start_menu_(x)
#define tty_start_screen() tty_start_screen_()
#define tty_suspend_nhwindows(x) tty_suspend_nhwindows_(x)
#define tty_update_inventory() tty_update_inventory_()
#define tty_update_positionbar(x) tty_update_positionbar_(x)
#define tty_wait_synch() tty_wait_synch_()
#define tty_yn_function(x, y, z) tty_yn_function_(x, y, z)
#define unfaint() unfaint_()
#define wantdoor(x, y, dummy) wantdoor_(x, y, dummy)
#define wipeoff() wipeoff_()
#define wiz_attributes() wiz_attributes_()
#define wiz_detect() wiz_detect_()
#define wiz_genesis() wiz_genesis_()
#define wiz_identify() wiz_identify_()
#define wiz_level_tele() wiz_level_tele_()
#define wiz_map() wiz_map_()
#define wiz_where() wiz_where_()
#define wiz_wish() wiz_wish_()
#define xname(x) xname_(x)
#define MAXWIN 20 
#define NHW_BASE 6


#define WIN_CANCELLED 1
#define WIN_LOCKHISTORY 2 
#define WIN_STOP 1        
#define fflush term_flush
#define putc(x) xputc(x)
#define putchar term_putc
#define puts term_puts
#define SYSOPT_SEDUCE sysopt.seduce

#define ALIGN_BOTTOM 4
#define ALIGN_LEFT   1
#define ALIGN_RIGHT  2
#define ALIGN_TOP    3
#define CARGS void *
#define MAP_MODE_ASCII10x18 9
#define MAP_MODE_ASCII12x16 8
#define MAP_MODE_ASCII16x12 7
#define MAP_MODE_ASCII16x8  4
#define MAP_MODE_ASCII4x6   1
#define MAP_MODE_ASCII6x8   2
#define MAP_MODE_ASCII7x12  5
#define MAP_MODE_ASCII8x12  6
#define MAP_MODE_ASCII8x8   3
#define MAP_MODE_ASCII_FIT_TO_SCREEN 10
#define MAP_MODE_TILES      0
#define MAP_MODE_TILES_FIT_TO_SCREEN 11
#define RS_ALGNMNT 4
#define RS_GENDER  3
#define RS_NAME    0
#define RS_RACE    2
#define RS_ROLE    1
#define RS_filter  5
#define RS_menu_arg(x) (ROLE_RANDOM - ((x) + 1)) 
#define VIA_DIALOG  0
#define VIA_PROMPTS 1
#define WC2_DARKGRAY      0x0020L 
#define WC2_FLUSH_STATUS  0x0080L 
#define WC2_FULLSCREEN    0x0001L 
#define WC2_GUICOLOR      0x2000L 
#define WC2_HILITE_STATUS 0x0008L 
#define WC2_HITPOINTBAR   0x0040L 
#define WC2_PETATTR       0x1000L 
#define WC2_RESET_STATUS  0x0100L 
#define WC2_SELECTSAVED   0x0010L 
#define WC2_SOFTKEYBOARD  0x0002L 
#define WC2_STATUSLINES   0x0400L 
#define WC2_SUPPRESS_HIST 0x8000L 
#define WC2_TERM_SIZE     0x0200L 
#define WC2_URGENT_MESG   0x4000L 
#define WC2_WINDOWBORDERS 0x0800L 
#define WC2_WRAPTEXT      0x0004L 
#define WC_ALIGN_MESSAGE 0x00000200L 
#define WC_ALIGN_STATUS  0x00000400L 
#define WC_ASCII_MAP     0x00000004L 
#define WC_COLOR         0x00000001L 
#define WC_EIGHT_BIT_IN  0x04000000L 
#define WC_FONTSIZ_MAP   0x00020000L 
#define WC_FONTSIZ_MENU  0x00100000L 
#define WC_FONTSIZ_MESSAGE 0x040000L 
#define WC_FONTSIZ_STATUS 0x0080000L 
#define WC_FONTSIZ_TEXT  0x00200000L 
#define WC_FONT_MAP      0x00001000L 
#define WC_FONT_MENU     0x00008000L 
#define WC_FONT_MESSAGE  0x00002000L 
#define WC_FONT_STATUS   0x00004000L 
#define WC_FONT_TEXT     0x00010000L 
#define WC_HILITE_PET    0x00000002L 
#define WC_INVERSE       0x00000100L 
#define WC_MAP_MODE      0x10000000L 
#define WC_MOUSE_SUPPORT 0x80000000UL 
#define WC_PERM_INVENT   0x08000000L 
#define WC_PLAYER_SELECTION 0x40000000L 
#define WC_POPUP_DIALOG  0x01000000L 
#define WC_PRELOAD_TILES 0x00000010L 
#define WC_SCROLL_AMOUNT 0x02000000L 
#define WC_SCROLL_MARGIN 0x00400000L 
#define WC_SPLASH_SCREEN 0x00800000L 
#define WC_TILED_MAP     0x00000008L 
#define WC_TILE_FILE     0x00000080L 
#define WC_TILE_HEIGHT   0x00000040L 
#define WC_TILE_WIDTH    0x00000020L 
#define WC_VARY_MSGCOUNT 0x00000800L 
#define WC_WINDOWCOLORS  0x20000000L 
#define WINCHAIN_ALLOC 0
#define WINCHAIN_INIT  1
#define WINDOWPORT(wn) \
    (windowprocs.name && !strncmpi((wn), windowprocs.name, strlen((wn))))
#define WININIT      0
#define WININIT_UNDO 1

#define add_menu (*windowprocs.win_add_menu)
#define askname (*windowprocs.win_askname)
#define change_background (*windowprocs.win_change_background)
#define change_color (*windowprocs.win_change_color)
#define clear_nhwindow (*windowprocs.win_clear_nhwindow)
#define cliparound (*windowprocs.win_cliparound)
#define create_nhwindow (*windowprocs.win_create_nhwindow)
#define curs (*windowprocs.win_curs)
#define delay_output (*windowprocs.win_delay_output)
#define destroy_nhwindow (*windowprocs.win_destroy_nhwindow)
#define display_file (*windowprocs.win_display_file)
#define display_nhwindow (*windowprocs.win_display_nhwindow)
#define end_menu (*windowprocs.win_end_menu)
#define end_screen (*windowprocs.win_end_screen)
#define exit_nhwindows (*windowprocs.win_exit_nhwindows)
#define get_color_string (*windowprocs.win_get_color_string)
#define get_ext_cmd (*windowprocs.win_get_ext_cmd)
#define get_nh_event (*windowprocs.win_get_nh_event)
#define getlin (*windowprocs.win_getlin)
#define getmsghistory (*windowprocs.win_getmsghistory)
#define init_nhwindows (*windowprocs.win_init_nhwindows)
#define mark_synch (*windowprocs.win_mark_synch)
#define message_menu (*windowprocs.win_message_menu)
#define nh_doprev_message (*windowprocs.win_doprev_message)
#define nh_poskey (*windowprocs.win_nh_poskey)
#define nhbell (*windowprocs.win_nhbell)
#define nhgetch (*windowprocs.win_nhgetch)
#define number_pad (*windowprocs.win_number_pad)
#define outrip (*windowprocs.win_outrip)
#define player_selection (*windowprocs.win_player_selection)
#define preference_update (*windowprocs.win_preference_update)
#define print_glyph (*windowprocs.win_print_glyph)
#define putmixed (*windowprocs.win_putmixed)
#define putmsghistory (*windowprocs.win_putmsghistory)
#define putstr (*windowprocs.win_putstr)
#define raw_print (*windowprocs.win_raw_print)
#define raw_print_bold (*windowprocs.win_raw_print_bold)
#define resume_nhwindows (*windowprocs.win_resume_nhwindows)
#define select_menu (*windowprocs.win_select_menu)
#define set_font_name (*windowprocs.win_set_font_name)
#define start_menu (*windowprocs.win_start_menu)
#define start_screen (*windowprocs.win_start_screen)
#define status_enablefield (*windowprocs.win_status_enablefield)
#define status_update (*windowprocs.win_status_update)
#define suspend_nhwindows (*windowprocs.win_suspend_nhwindows)
#define update_positionbar (*windowprocs.win_update_positionbar)
#define wait_synch (*windowprocs.win_wait_synch)
#define BEFORE  0
#define BL_ATTCLR_MAX     CLR_MAX + 5
#define BL_HILITE_BOLD -3    
#define BL_HILITE_INVERSE -2 
#define BL_HILITE_NONE -1    
#define BL_MASK_BITS            13 
#define BL_MASK_BLIND           0x00000020L
#define BL_MASK_CONF            0x00000100L
#define BL_MASK_DEAF            0x00000040L
#define BL_MASK_FLY             0x00000800L
#define BL_MASK_FOODPOIS        0x00000008L
#define BL_MASK_HALLU           0x00000200L
#define BL_MASK_LEV             0x00000400L
#define BL_MASK_RIDE            0x00001000L
#define BL_MASK_SLIME           0x00000002L
#define BL_MASK_STONE           0x00000001L
#define BL_MASK_STRNGL          0x00000004L
#define BL_MASK_STUN            0x00000080L
#define BL_MASK_TERMILL         0x00000010L
#define BL_TH_ALWAYS_HILITE 105  
#define BL_TH_CONDITION 103      
#define BL_TH_NONE 0
#define BL_TH_TEXTMATCH 104      
#define BL_TH_UPDOWN 102         
#define BL_TH_VAL_ABSOLUTE 101   
#define BL_TH_VAL_PERCENTAGE 100 

#define HL_ATTCLR_BLINK   CLR_MAX + 1
#define HL_ATTCLR_BOLD    CLR_MAX + 4
#define HL_ATTCLR_DIM     CLR_MAX + 0
#define HL_ATTCLR_INVERSE CLR_MAX + 3
#define HL_ATTCLR_ULINE   CLR_MAX + 2
#define MAXCO 200
#define NOW     1
#define REASSESS_ONLY TRUE
#define VIA_WINDOWPORT() \
    ((windowprocs.wincap2 & (WC2_HILITE_STATUS | WC2_FLUSH_STATUS)) != 0)
#define MONST_INC 5

#define REG_HERO_INSIDE 0x01
#define REG_NOT_HEROS 0x02
#define clear_hero_inside(r) ((r)->player_flags &= ~REG_HERO_INSIDE)
#define clear_heros_fault(r) ((r)->player_flags |= REG_NOT_HEROS)
#define hero_inside(r) ((r)->player_flags & REG_HERO_INSIDE)
#define heros_fault(r) (!((r)->player_flags & REG_NOT_HEROS))
#define set_hero_inside(r) ((r)->player_flags |= REG_HERO_INSIDE)
#define set_heros_fault(r) ((r)->player_flags &= ~REG_NOT_HEROS)

#define BURN 3
#define DUST 1
#define ENGRAVE 2

#define ENGR_BLOOD 5
#define HEADSTONE 6
#define MARK 4
#define N_ENGRAVE 6
#define dealloc_engr(engr) free((genericptr_t)(engr))
#define newengr(lth) \
    (struct engr *) alloc((unsigned)(lth) + sizeof(struct engr))
#define BACKTRACK (-1)    

#define DISP_ALL     (-2) 
#define DISP_ALWAYS  (-5) 
#define DISP_BEAM    (-1) 
#define DISP_CHANGE  (-6) 
#define DISP_END     (-7) 
#define DISP_FLASH   (-4) 
#define DISP_FREEMEM (-8) 
#define DISP_TETHER  (-3) 
#define GLYPH_BODY_OFF    (NUMMONS + GLYPH_DETECT_OFF)
#define GLYPH_CMAP_OFF    (NUM_OBJECTS + GLYPH_OBJ_OFF)
#define GLYPH_DETECT_OFF  (1 + GLYPH_INVIS_OFF)
#define GLYPH_EXPLODE_OFF ((MAXPCHARS - MAXEXPCHARS) + GLYPH_CMAP_OFF)
#define GLYPH_INVISIBLE   GLYPH_INVIS_OFF
#define GLYPH_INVIS_OFF   (NUMMONS + GLYPH_PET_OFF)
#define GLYPH_MON_OFF     0
#define GLYPH_OBJ_OFF     (NUMMONS + GLYPH_RIDDEN_OFF)
#define GLYPH_PET_OFF     (NUMMONS + GLYPH_MON_OFF)
#define GLYPH_RIDDEN_OFF  (NUMMONS + GLYPH_BODY_OFF)
#define GLYPH_STATUE_OFF  (WARNCOUNT + GLYPH_WARNING_OFF)
#define GLYPH_SWALLOW_OFF ((NUM_ZAP << 2) + GLYPH_ZAP_OFF)
#define GLYPH_WARNING_OFF ((NUMMONS << 3) + GLYPH_SWALLOW_OFF)
#define GLYPH_ZAP_OFF     ((MAXEXPCHARS * EXPL_MAX) + GLYPH_EXPLODE_OFF)
#define MAX_GLYPH         (NUMMONS + GLYPH_STATUE_OFF)
#define NO_GLYPH          MAX_GLYPH
#define NUM_ZAP 8 
#define SHIELD_COUNT 21
#define canseemon(mon)                                                    \
    ((mon->wormno ? worm_known(mon)                                       \
                  : (cansee(mon->mx, mon->my) || see_with_infrared(mon))) \
     && mon_visible(mon))
#define canseeself() (Blind || u.uswallow || (!Invisible && !u.uundetected))
#define canspotmon(mon) (canseemon(mon) || sensemon(mon))
#define canspotself() (canseeself() || senseself())
#define cmap_to_glyph(cmap_idx) ((int) (cmap_idx) + GLYPH_CMAP_OFF)
#define covers_objects(xx, yy) \
    ((is_pool(xx, yy) && !Underwater) || (levl[xx][yy].typ == LAVAPOOL))
#define covers_traps(xx, yy) covers_objects(xx, yy)
#define detected_mon_to_glyph(mon, rng)                             \
    ((int) what_mon(monsndx((mon)->data), rng) + GLYPH_DETECT_OFF)
#define detected_monnum_to_glyph(mnum) ((int) (mnum) + GLYPH_DETECT_OFF)
#define display_self() \
    show_glyph(u.ux, u.uy,                                                  \
           maybe_display_usteed((U_AP_TYPE == M_AP_NOTHING)                 \
                                ? hero_glyph                                \
                                : (U_AP_TYPE == M_AP_FURNITURE)             \
                                  ? cmap_to_glyph(youmonst.mappearance)     \
                                  : (U_AP_TYPE == M_AP_OBJECT)              \
                                    ? objnum_to_glyph(youmonst.mappearance) \
                                        \
                                    : monnum_to_glyph(youmonst.mappearance)))
#define explosion_to_glyph(expltype, idx) \
    ((((expltype) * MAXEXPCHARS) + ((idx) - S_explode1)) + GLYPH_EXPLODE_OFF)
#define glyph_is_body(glyph) \
    ((glyph) >= GLYPH_BODY_OFF && (glyph) < (GLYPH_BODY_OFF + NUMMONS))
#define glyph_is_cmap(glyph) \
    ((glyph) >= GLYPH_CMAP_OFF && (glyph) < (GLYPH_CMAP_OFF + MAXPCHARS))
#define glyph_is_detected_monster(glyph) \
    ((glyph) >= GLYPH_DETECT_OFF && (glyph) < (GLYPH_DETECT_OFF + NUMMONS))
#define glyph_is_invisible(glyph) ((glyph) == GLYPH_INVISIBLE)
#define glyph_is_monster(glyph)                            \
    (glyph_is_normal_monster(glyph) || glyph_is_pet(glyph) \
     || glyph_is_ridden_monster(glyph) || glyph_is_detected_monster(glyph))
#define glyph_is_normal_monster(glyph) \
    ((glyph) >= GLYPH_MON_OFF && (glyph) < (GLYPH_MON_OFF + NUMMONS))
#define glyph_is_normal_object(glyph) \
    ((glyph) >= GLYPH_OBJ_OFF && (glyph) < (GLYPH_OBJ_OFF + NUM_OBJECTS))
#define glyph_is_object(glyph)                               \
    (glyph_is_normal_object(glyph) || glyph_is_statue(glyph) \
     || glyph_is_body(glyph))
#define glyph_is_pet(glyph) \
    ((glyph) >= GLYPH_PET_OFF && (glyph) < (GLYPH_PET_OFF + NUMMONS))
#define glyph_is_ridden_monster(glyph) \
    ((glyph) >= GLYPH_RIDDEN_OFF && (glyph) < (GLYPH_RIDDEN_OFF + NUMMONS))
#define glyph_is_statue(glyph) \
    ((glyph) >= GLYPH_STATUE_OFF && (glyph) < (GLYPH_STATUE_OFF + NUMMONS))
#define glyph_is_swallow(glyph)   \
    ((glyph) >= GLYPH_SWALLOW_OFF \
     && (glyph) < (GLYPH_SWALLOW_OFF + (NUMMONS << 3)))
#define glyph_is_trap(glyph)                         \
    ((glyph) >= (GLYPH_CMAP_OFF + trap_to_defsym(1)) \
     && (glyph) < (GLYPH_CMAP_OFF + trap_to_defsym(1) + TRAPNUM))
#define glyph_is_warning(glyph)   \
    ((glyph) >= GLYPH_WARNING_OFF \
     && (glyph) < (GLYPH_WARNING_OFF + WARNCOUNT))
#define glyph_to_cmap(glyph) \
    (glyph_is_cmap(glyph) ? ((glyph) - GLYPH_CMAP_OFF) : NO_GLYPH)
#define glyph_to_mon(glyph) \
    (glyph_is_normal_monster(glyph)                             \
         ? ((glyph) - GLYPH_MON_OFF)                            \
         : glyph_is_pet(glyph)                                  \
               ? ((glyph) - GLYPH_PET_OFF)                      \
               : glyph_is_detected_monster(glyph)               \
                     ? ((glyph) - GLYPH_DETECT_OFF)             \
                     : glyph_is_ridden_monster(glyph)           \
                           ? ((glyph) - GLYPH_RIDDEN_OFF)       \
                           : glyph_is_statue(glyph)             \
                                 ? ((glyph) - GLYPH_STATUE_OFF) \
                                 : NO_GLYPH)
#define glyph_to_obj(glyph) \
    (glyph_is_body(glyph)                        \
         ? CORPSE                                \
         : glyph_is_statue(glyph)                \
               ? STATUE                          \
               : glyph_is_normal_object(glyph)   \
                     ? ((glyph) - GLYPH_OBJ_OFF) \
                     : NO_GLYPH)
#define glyph_to_swallow(glyph) \
    (glyph_is_swallow(glyph) ? (((glyph) - GLYPH_SWALLOW_OFF) & 0x7) : 0)
#define glyph_to_trap(glyph) \
    (glyph_is_trap(glyph) ? ((int) defsym_to_trap((glyph) - GLYPH_CMAP_OFF)) \
                          : NO_GLYPH)
#define glyph_to_warning(glyph) \
    (glyph_is_warning(glyph) ? ((glyph) - GLYPH_WARNING_OFF) : NO_GLYPH);
#define hero_glyph                                                    \
    monnum_to_glyph((Upolyd || !flags.showrace)                       \
                        ? u.umonnum                                   \
                        : (flags.female && urace.femalenum != NON_PM) \
                              ? urace.femalenum                       \
                              : urace.malenum)
#define is_safepet(mon)                                                   \
    (mon && mon->mtame && canspotmon(mon) && flags.safe_dog && !Confusion \
     && !Hallucination && !Stunned)
#define knowninvisible(mon)                                               \
    (mtmp->minvis                                                         \
     && ((cansee(mon->mx, mon->my) && (See_invisible || Detect_monsters)) \
         || (!Blind && (HTelepat & ~INTRINSIC)                            \
             && distu(mon->mx, mon->my) <= (BOLT_LIM * BOLT_LIM))))
#define maybe_display_usteed(otherwise_self)                            \
    ((u.usteed && mon_visible(u.usteed))                                \
     ? ridden_mon_to_glyph(u.usteed, rn2_on_display_rng)                \
     : (otherwise_self))
#define mon_to_glyph(mon, rng)                                      \
    ((int) what_mon(monsndx((mon)->data), rng) + GLYPH_MON_OFF)
#define mon_visible(mon) \
    ( \
     (!mon->minvis || See_invisible)   \
     && !mon->mundetected)            
#define mon_warning(mon)                                                 \
    (Warning && !(mon)->mpeaceful && (distu((mon)->mx, (mon)->my) < 100) \
     && (((int) ((mon)->m_lev / 4)) >= context.warnlevel))
#define monnum_to_glyph(mnum) ((int) (mnum) + GLYPH_MON_OFF)
#define newsym_rn2 rn2_on_display_rng
#define obj_to_glyph(obj, rng)                                          \
    (((obj)->otyp == STATUE)                                            \
         ? statue_to_glyph(obj, rng)                                    \
         : Hallucination                                                \
               ? random_obj_to_glyph(rng)                               \
               : ((obj)->otyp == CORPSE)                                \
                     ? (int) (obj)->corpsenm + GLYPH_BODY_OFF           \
                     : (int) (obj)->otyp + GLYPH_OBJ_OFF)
#define objnum_to_glyph(onum) ((int) (onum) + GLYPH_OBJ_OFF)
#define pet_to_glyph(mon, rng)                                      \
    ((int) what_mon(monsndx((mon)->data), rng) + GLYPH_PET_OFF)
#define petnum_to_glyph(mnum) ((int) (mnum) + GLYPH_PET_OFF)
#define random_monster(rng) rng(NUMMONS)
#define random_obj_to_glyph(rng)                \
    ((otg_temp = random_object(rng)) == CORPSE  \
         ? random_monster(rng) + GLYPH_BODY_OFF \
         : otg_temp + GLYPH_OBJ_OFF)
#define random_object(rng) (rng(NUM_OBJECTS - 1) + 1)
#define random_trap(rng) (rng(TRAPNUM - 1) + 1)
#define ridden_mon_to_glyph(mon, rng)                               \
    ((int) what_mon(monsndx((mon)->data), rng) + GLYPH_RIDDEN_OFF)
#define ridden_monnum_to_glyph(mnum) ((int) (mnum) + GLYPH_RIDDEN_OFF)
#define see_with_infrared(mon)                        \
    (!Blind && Infravision && mon && infravisible(mon->data) \
     && couldsee(mon->mx, mon->my))
#define sensemon(mon) \
    (tp_sensemon(mon) || Detect_monsters || MATCH_WARN_OF_MON(mon))
#define senseself() (Unblind_telepat || Detect_monsters)
#define statue_to_glyph(obj, rng)                              \
    (Hallucination ? random_monster(rng) + GLYPH_MON_OFF       \
                   : (int) (obj)->corpsenm + GLYPH_STATUE_OFF)
#define tp_sensemon(mon) \
    (  \
       \
     (!mindless(mon->data))                                \
       \
      && ((Blind && Blind_telepat)                         \
            \
            \
          || (Unblind_telepat                              \
              && (distu(mon->mx, mon->my) <= (BOLT_LIM * BOLT_LIM)))))
#define trap_to_glyph(trap, rng)                                \
    cmap_to_glyph(trap_to_defsym(what_trap((trap)->ttyp, rng)))
#define vobj_at(x, y) (level.objects[x][y])
#define warning_to_glyph(mwarnlev) ((mwarnlev) + GLYPH_WARNING_OFF)
#define what_mon(mon, rng) (Hallucination ? random_monster(rng) : mon)
#define what_obj(obj, rng) (Hallucination ? random_object(rng) : obj)
#define what_trap(trp, rng) (Hallucination ? random_trap(rng) : trp)

#define acidic(ptr) (((ptr)->mflags1 & M1_ACID) != 0L)
#define always_hostile(ptr) (((ptr)->mflags2 & M2_HOSTILE) != 0L)
#define always_peaceful(ptr) (((ptr)->mflags2 & M2_PEACEFUL) != 0L)
#define amorphous(ptr) (((ptr)->mflags1 & M1_AMORPHOUS) != 0L)
#define amphibious(ptr) \
    (((ptr)->mflags1 & (M1_AMPHIBIOUS | M1_BREATHLESS)) != 0L)
#define befriend_with_obj(ptr, obj) \
    (((ptr) == &mons[PM_MONKEY] || (ptr) == &mons[PM_APE])               \
     ? (obj)->otyp == BANANA                                             \
     : (is_domestic(ptr) && (obj)->oclass == FOOD_CLASS                  \
        && ((ptr)->mlet != S_UNICORN                                     \
            || objects[(obj)->otyp].oc_material == VEGGY                 \
            || ((obj)->otyp == CORPSE && (obj)->corpsenm == PM_LICHEN))))
#define bigmonst(ptr) ((ptr)->msize >= MZ_LARGE)
#define breathless(ptr) (((ptr)->mflags1 & M1_BREATHLESS) != 0L)
#define can_breathe(ptr) attacktype(ptr, AT_BREA)
#define can_teleport(ptr) (((ptr)->mflags1 & M1_TPORT) != 0L)
#define cantweararm(ptr) (breakarm(ptr) || sliparm(ptr))
#define cantwield(ptr) (nohands(ptr) || verysmall(ptr))
#define carnivorous(ptr) (((ptr)->mflags1 & M1_CARNIVORE) != 0L)
#define ceiling_hider(ptr) \
    (is_hider(ptr) && ((is_clinger(ptr) && (ptr)->mlet != S_MIMIC) \
                       || is_flyer(ptr))) 
#define completelyburns(ptr) \
    ((ptr) == &mons[PM_PAPER_GOLEM] || (ptr) == &mons[PM_STRAW_GOLEM])
#define control_teleport(ptr) (((ptr)->mflags1 & M1_TPORT_CNTRL) != 0L)
#define could_twoweap(ptr) ((ptr)->mattk[1].aatyp == AT_WEAP)
#define eggs_in_water(ptr) \
    (lays_eggs(ptr) && (ptr)->mlet == S_EEL && is_swimmer(ptr))
#define emits_light(ptr)                                          \
    (((ptr)->mlet == S_LIGHT || (ptr) == &mons[PM_FLAMING_SPHERE] \
      || (ptr) == &mons[PM_SHOCKING_SPHERE]                       \
      || (ptr) == &mons[PM_FIRE_VORTEX])                          \
         ? 1                                                      \
         : ((ptr) == &mons[PM_FIRE_ELEMENTAL]) ? 1 : 0)
#define extra_nasty(ptr) (((ptr)->mflags2 & M2_NASTY) != 0L)
#define eyecount(ptr) \
    (!haseyes(ptr) ? 0                                                     \
     : ((ptr) == &mons[PM_CYCLOPS] || (ptr) == &mons[PM_FLOATING_EYE]) ? 1 \
       : 2)
#define flaming(ptr)                                                     \
    ((ptr) == &mons[PM_FIRE_VORTEX] || (ptr) == &mons[PM_FLAMING_SPHERE] \
     || (ptr) == &mons[PM_FIRE_ELEMENTAL] || (ptr) == &mons[PM_SALAMANDER])
#define has_head(ptr) (((ptr)->mflags1 & M1_NOHEAD) == 0L)
#define has_horns(ptr) (num_horns(ptr) > 0)
#define haseyes(ptr) (((ptr)->mflags1 & M1_NOEYES) == 0L)
#define hates_light(ptr) ((ptr) == &mons[PM_GREMLIN])
#define herbivorous(ptr) (((ptr)->mflags1 & M1_HERBIVORE) != 0L)
#define hides_under(ptr) (((ptr)->mflags1 & M1_CONCEAL) != 0L)
#define hug_throttles(ptr) ((ptr) == &mons[PM_ROPE_GOLEM])
#define humanoid(ptr) (((ptr)->mflags1 & M1_HUMANOID) != 0L)
#define infravisible(ptr) (((ptr)->mflags3 & M3_INFRAVISIBLE))
#define infravision(ptr) (((ptr)->mflags3 & M3_INFRAVISION))
#define is_animal(ptr) (((ptr)->mflags1 & M1_ANIMAL) != 0L)
#define is_armed(ptr) attacktype(ptr, AT_WEAP)
#define is_bat(ptr)                                         \
    ((ptr) == &mons[PM_BAT] || (ptr) == &mons[PM_GIANT_BAT] \
     || (ptr) == &mons[PM_VAMPIRE_BAT])
#define is_bird(ptr) ((ptr)->mlet == S_BAT && !is_bat(ptr))
#define is_clinger(ptr) (((ptr)->mflags1 & M1_CLING) != 0L)
#define is_covetous(ptr) (((ptr)->mflags3 & M3_COVETOUS))
#define is_demon(ptr) (((ptr)->mflags2 & M2_DEMON) != 0L)
#define is_displacer(ptr) (((ptr)->mflags3 & M3_DISPLACES) != 0L)
#define is_dlord(ptr) (is_demon(ptr) && is_lord(ptr))
#define is_domestic(ptr) (((ptr)->mflags2 & M2_DOMESTIC) != 0L)
#define is_dprince(ptr) (is_demon(ptr) && is_prince(ptr))
#define is_dwarf(ptr) (((ptr)->mflags2 & M2_DWARF) != 0L)
#define is_elf(ptr) (((ptr)->mflags2 & M2_ELF) != 0L)
#define is_female(ptr) (((ptr)->mflags2 & M2_FEMALE) != 0L)
#define is_floater(ptr) ((ptr)->mlet == S_EYE || (ptr)->mlet == S_LIGHT)
#define is_flyer(ptr) (((ptr)->mflags1 & M1_FLY) != 0L)
#define is_giant(ptr) (((ptr)->mflags2 & M2_GIANT) != 0L)
#define is_gnome(ptr) (((ptr)->mflags2 & M2_GNOME) != 0L)
#define is_golem(ptr) ((ptr)->mlet == S_GOLEM)
#define is_hider(ptr) (((ptr)->mflags1 & M1_HIDE) != 0L)
#define is_human(ptr) (((ptr)->mflags2 & M2_HUMAN) != 0L)
#define is_lminion(mon) \
    (is_minion((mon)->data) && mon_aligntyp(mon) == A_LAWFUL)
#define is_longworm(ptr)                                                   \
    (((ptr) == &mons[PM_BABY_LONG_WORM]) || ((ptr) == &mons[PM_LONG_WORM]) \
     || ((ptr) == &mons[PM_LONG_WORM_TAIL]))
#define is_lord(ptr) (((ptr)->mflags2 & M2_LORD) != 0L)
#define is_male(ptr) (((ptr)->mflags2 & M2_MALE) != 0L)
#define is_mercenary(ptr) (((ptr)->mflags2 & M2_MERC) != 0L)
#define is_mind_flayer(ptr) \
    ((ptr) == &mons[PM_MIND_FLAYER] || (ptr) == &mons[PM_MASTER_MIND_FLAYER])
#define is_minion(ptr) (((ptr)->mflags2 & M2_MINION) != 0L)
#define is_mplayer(ptr) \
    (((ptr) >= &mons[PM_ARCHEOLOGIST]) && ((ptr) <= &mons[PM_WIZARD]))
#define is_ndemon(ptr) \
    (is_demon(ptr) && (((ptr)->mflags2 & (M2_LORD | M2_PRINCE)) == 0L))
#define is_neuter(ptr) (((ptr)->mflags2 & M2_NEUTER) != 0L)
#define is_orc(ptr) (((ptr)->mflags2 & M2_ORC) != 0L)
#define is_placeholder(ptr)                             \
    ((ptr) == &mons[PM_ORC] || (ptr) == &mons[PM_GIANT] \
     || (ptr) == &mons[PM_ELF] || (ptr) == &mons[PM_HUMAN])
#define is_prince(ptr) (((ptr)->mflags2 & M2_PRINCE) != 0L)
#define is_reviver(ptr) (is_rider(ptr) || (ptr)->mlet == S_TROLL)
#define is_rider(ptr)                                      \
    ((ptr) == &mons[PM_DEATH] || (ptr) == &mons[PM_FAMINE] \
     || (ptr) == &mons[PM_PESTILENCE])
#define is_shapeshifter(ptr) (((ptr)->mflags2 & M2_SHAPESHIFTER) != 0L)
#define is_silent(ptr) ((ptr)->msound == MS_SILENT)
#define is_swimmer(ptr) (((ptr)->mflags1 & M1_SWIM) != 0L)
#define is_undead(ptr) (((ptr)->mflags2 & M2_UNDEAD) != 0L)
#define is_unicorn(ptr) ((ptr)->mlet == S_UNICORN && likes_gems(ptr))
#define is_vampire(ptr) ((ptr)->mlet == S_VAMPIRE)
#define is_wanderer(ptr) (((ptr)->mflags2 & M2_WANDER) != 0L)
#define is_watch(ptr) \
    ((ptr) == &mons[PM_WATCHMAN] || (ptr) == &mons[PM_WATCH_CAPTAIN])
#define is_were(ptr) (((ptr)->mflags2 & M2_WERE) != 0L)
#define is_whirly(ptr) \
    ((ptr)->mlet == S_VORTEX || (ptr) == &mons[PM_AIR_ELEMENTAL])
#define is_wooden(ptr) ((ptr) == &mons[PM_WOOD_GOLEM])
#define lays_eggs(ptr) (((ptr)->mflags1 & M1_OVIPAROUS) != 0L)
#define likes_fire(ptr)                                                  \
    ((ptr) == &mons[PM_FIRE_VORTEX] || (ptr) == &mons[PM_FLAMING_SPHERE] \
     || likes_lava(ptr))
#define likes_gems(ptr) (((ptr)->mflags2 & M2_JEWELS) != 0L)
#define likes_gold(ptr) (((ptr)->mflags2 & M2_GREEDY) != 0L)
#define likes_lava(ptr) \
    (ptr == &mons[PM_FIRE_ELEMENTAL] || ptr == &mons[PM_SALAMANDER])
#define likes_magic(ptr) (((ptr)->mflags2 & M2_MAGIC) != 0L)
#define likes_objs(ptr) (((ptr)->mflags2 & M2_COLLECT) != 0L || is_armed(ptr))
#define metallivorous(ptr) (((ptr)->mflags1 & M1_METALLIVORE) != 0L)
#define mindless(ptr) (((ptr)->mflags1 & M1_MINDLESS) != 0L)
#define needspick(ptr) (((ptr)->mflags1 & M1_NEEDPICK) != 0L)
#define nohands(ptr) (((ptr)->mflags1 & M1_NOHANDS) != 0L)
#define nolimbs(ptr) (((ptr)->mflags1 & M1_NOLIMBS) == M1_NOLIMBS)
#define noncorporeal(ptr) ((ptr)->mlet == S_GHOST)
#define nonliving(ptr) \
    (is_undead(ptr) || (ptr) == &mons[PM_MANES] || weirdnonliving(ptr))
#define notake(ptr) (((ptr)->mflags1 & M1_NOTAKE) != 0L)
#define passes_walls(ptr) (((ptr)->mflags1 & M1_WALLWALK) != 0L)
#define perceives(ptr) (((ptr)->mflags1 & M1_SEE_INVIS) != 0L)
#define pm_invisible(ptr) \
    ((ptr) == &mons[PM_STALKER] || (ptr) == &mons[PM_BLACK_LIGHT])
#define pm_resistance(ptr, typ) (((ptr)->mresists & (typ)) != 0)
#define poisonous(ptr) (((ptr)->mflags1 & M1_POIS) != 0L)
#define polyok(ptr) (((ptr)->mflags2 & M2_NOPOLY) == 0L)
#define race_hostile(ptr) (((ptr)->mflags2 & urace.hatemask) != 0L)
#define race_peaceful(ptr) (((ptr)->mflags2 & urace.lovemask) != 0L)
#define regenerates(ptr) (((ptr)->mflags1 & M1_REGEN) != 0L)
#define resists_acid(mon) \
    ((((mon)->data->mresists | (mon)->mextrinsics) & MR_ACID) != 0)
#define resists_cold(mon) \
    ((((mon)->data->mresists | (mon)->mextrinsics) & MR_COLD) != 0)
#define resists_disint(mon) \
    ((((mon)->data->mresists | (mon)->mextrinsics) & MR_DISINT) != 0)
#define resists_elec(mon) \
    ((((mon)->data->mresists | (mon)->mextrinsics) & MR_ELEC) != 0)
#define resists_fire(mon) \
    ((((mon)->data->mresists | (mon)->mextrinsics) & MR_FIRE) != 0)
#define resists_poison(mon) \
    ((((mon)->data->mresists | (mon)->mextrinsics) & MR_POISON) != 0)
#define resists_sleep(mon) \
    ((((mon)->data->mresists | (mon)->mextrinsics) & MR_SLEEP) != 0)
#define resists_ston(mon) \
    ((((mon)->data->mresists | (mon)->mextrinsics) & MR_STONE) != 0)
#define slimeproof(ptr) \
    ((ptr) == &mons[PM_GREEN_SLIME] || flaming(ptr) || noncorporeal(ptr))
#define slithy(ptr) (((ptr)->mflags1 & M1_SLITHY) != 0L)
#define strongmonst(ptr) (((ptr)->mflags2 & M2_STRONG) != 0L)
#define telepathic(ptr)                                                \
    ((ptr) == &mons[PM_FLOATING_EYE] || (ptr) == &mons[PM_MIND_FLAYER] \
     || (ptr) == &mons[PM_MASTER_MIND_FLAYER])
#define thick_skinned(ptr) (((ptr)->mflags1 & M1_THICK_HIDE) != 0L)
#define throws_rocks(ptr) (((ptr)->mflags2 & M2_ROCKTHROW) != 0L)
#define touch_petrifies(ptr) \
    ((ptr) == &mons[PM_COCKATRICE] || (ptr) == &mons[PM_CHICKATRICE])
#define tunnels(ptr) (((ptr)->mflags1 & M1_TUNNEL) != 0L)
#define type_is_pname(ptr) (((ptr)->mflags2 & M2_PNAME) != 0L)
#define unique_corpstat(ptr) (((ptr)->geno & G_UNIQ) != 0)
#define unsolid(ptr) (((ptr)->mflags1 & M1_UNSOLID) != 0L)
#define vegan(ptr)                                                 \
    ((ptr)->mlet == S_BLOB || (ptr)->mlet == S_JELLY               \
     || (ptr)->mlet == S_FUNGUS || (ptr)->mlet == S_VORTEX         \
     || (ptr)->mlet == S_LIGHT                                     \
     || ((ptr)->mlet == S_ELEMENTAL && (ptr) != &mons[PM_STALKER]) \
     || ((ptr)->mlet == S_GOLEM && (ptr) != &mons[PM_FLESH_GOLEM]  \
         && (ptr) != &mons[PM_LEATHER_GOLEM]) || noncorporeal(ptr))
#define vegetarian(ptr) \
    (vegan(ptr)         \
     || ((ptr)->mlet == S_PUDDING && (ptr) != &mons[PM_BLACK_PUDDING]))
#define verysmall(ptr) ((ptr)->msize < MZ_SMALL)
#define webmaker(ptr) \
    ((ptr) == &mons[PM_CAVE_SPIDER] || (ptr) == &mons[PM_GIANT_SPIDER])
#define weirdnonliving(ptr) (is_golem(ptr) || (ptr)->mlet == S_VORTEX)
#define your_race(ptr) (((ptr)->mflags2 & urace.selfmask) != 0L)
#define COULD_SEE 0x1 
#define IN_SIGHT 0x2  
#define LS_MONSTER 1
#define LS_OBJECT 0
#define MAX_RADIUS 15 
#define MONSEEN_DETECT   0x0020 
#define MONSEEN_INFRAVIS 0x0004 
#define MONSEEN_NORMAL   0x0001 
#define MONSEEN_SEEINVIS 0x0002 
#define MONSEEN_TELEPAT  0x0008 
#define MONSEEN_WARNMON  0x0040 
#define MONSEEN_XRAYVIS  0x0010 
#define TEMP_LIT 0x4  

#define cansee(x, y) (viz_array[y][x] & IN_SIGHT)
#define circle_ptr(z) (&circle_data[(int) circle_start[z]])
#define couldsee(x, y) (viz_array[y][x] & COULD_SEE)
#define m_cansee(mtmp, x2, y2) clear_path((mtmp)->mx, (mtmp)->my, (x2), (y2))
#define m_canseeu(m) \
    ((!Invis || perceives((m)->data))                      \
     && !Underwater                                        \
     && couldsee((m)->mx, (m)->my))
#define templit(x, y) (viz_array[y][x] & TEMP_LIT)
#define ACCESSIBLE(typ) ((typ) >= DOOR) 
#define AM_SHRINE 8
#define CLEAR_FOUNTAIN_LOOTED(x, y) levl[x][y].looted &= ~F_LOOTED;
#define CLEAR_FOUNTAIN_WARNED(x, y) levl[x][y].looted &= ~F_WARNED;
#define DARKROOMSYM (Is_rogue_level(&u.uz) ? S_stone : S_darkroom)
#define DB_DIR 3 
#define DB_EAST 2
#define DB_FLOOR 16
#define DB_ICE 8
#define DB_LAVA 4
#define DB_MOAT 0
#define DB_NORTH 0
#define DB_SOUTH 1
#define DB_UNDER 28 
#define DB_WEST 3
#define DEFAULT_GRAPHICS 0 
#define D_BROKEN 1
#define D_CLOSED 4
#define D_ISOPEN 2
#define D_LOCKED 8
#define D_NODOOR 0
#define D_SECRET 32 
#define D_TRAPPED 16
#define D_WARNED 16
#define FOUNTAIN_IS_LOOTED(x, y) (levl[x][y].looted & F_LOOTED)
#define FOUNTAIN_IS_WARNED(x, y) (levl[x][y].looted & F_WARNED)
#define F_LOOTED 1
#define F_WARNED 2
#define H_CURS    3
#define H_DEC     2
#define H_IBM     1
#define H_MAC     4 
#define H_UNK     0
#define ICED_MOAT 16
#define ICED_POOL 8
#define IS_AIR(typ) ((typ) == AIR || (typ) == CLOUD)
#define IS_ALTAR(typ) ((typ) == ALTAR)
#define IS_DOOR(typ) ((typ) == DOOR)
#define IS_DOORJOIN(typ) (IS_ROCK(typ) || (typ) == IRONBARS)
#define IS_DRAWBRIDGE(typ) \
    ((typ) == DRAWBRIDGE_UP || (typ) == DRAWBRIDGE_DOWN)
#define IS_FOUNTAIN(typ) ((typ) == FOUNTAIN)
#define IS_FURNITURE(typ) ((typ) >= STAIRS && (typ) <= ALTAR)
#define IS_GRAVE(typ) ((typ) == GRAVE)
#define IS_POOL(typ) ((typ) >= POOL && (typ) <= DRAWBRIDGE_UP)
#define IS_ROCK(typ) ((typ) < POOL)      
#define IS_ROOM(typ) ((typ) >= ROOM)    
#define IS_SINK(typ) ((typ) == SINK)
#define IS_SOFT(typ) ((typ) == AIR || (typ) == CLOUD || IS_POOL(typ))
#define IS_STWALL(typ) ((typ) <= DBWALL) 
#define IS_THRONE(typ) ((typ) == THRONE)
#define IS_TREE(typ)                                            \
    ((typ) == TREE || (level.flags.arboreal && (typ) == STONE))
#define IS_WALL(typ) ((typ) && (typ) <= DBWALL)
#define LA_DOWN 2
#define LA_UP 1
#define MAXDCHARS (S_water - S_stone + 1) 
#define MAXECHARS (S_explode9 - S_vbeam + 1) 
#define MAXEXPCHARS 9 
#define MAXOTHER 4
#define MAXTCHARS (S_vibrating_square - S_arrow_trap + 1) 
#define MON_AT(x, y) (level.monsters[x][y] != (struct monst *) 0)
#define NUM_GRAPHICS 2
#define OBJ_AT(x, y) (level.objects[x][y] != (struct obj *) 0)
#define PRIMARY 0          

#define ROGUESET 1         
#define SET_FOUNTAIN_LOOTED(x, y) levl[x][y].looted |= F_LOOTED;
#define SET_FOUNTAIN_WARNED(x, y) levl[x][y].looted |= F_WARNED;
#define SET_TYPLIT(x, y, ttyp, llit)                              \
    {                                                             \
        if ((x) >= 0 && (y) >= 0 && (x) < COLNO && (y) < ROWNO) { \
            if ((ttyp) < MAX_TYPE)                                \
                levl[(x)][(y)].typ = (ttyp);                      \
            if ((ttyp) == LAVAPOOL)                               \
                levl[(x)][(y)].lit = 1;                           \
            else if ((schar)(llit) != -2) {                       \
                if ((schar)(llit) == -1)                          \
                    levl[(x)][(y)].lit = rn2(2);                  \
                else                                              \
                    levl[(x)][(y)].lit = (llit);                  \
            }                                                     \
        }                                                         \
    }
#define SPACE_POS(typ) ((typ) > DOOR)
#define SV0   0x01
#define SV1   0x02
#define SV2   0x04
#define SV3   0x08
#define SV4   0x10
#define SV5   0x20
#define SV6   0x40
#define SV7   0x80
#define SVALL 0xFF
#define SYMHANDLING(ht) (symset[currentgraphics].handling == (ht))
#define SYM_BOULDER 0
#define SYM_CONTROL 1 
#define SYM_HERO_OVERRIDE 3
#define SYM_INVISIBLE 1
#define SYM_MON 4     
#define SYM_OC 3      
#define SYM_OTH 5     
#define SYM_PCHAR 2   
#define SYM_PET_OVERRIDE 2
#define S_LDWASHER 2
#define S_LPUDDING 1
#define S_LRING 4
#define Sokoban level.flags.sokoban_rules
#define TREE_LOOTED 1
#define TREE_SWARM 2
#define T_LOOTED 1
#define WM_C_INNER 2
#define WM_C_OUTER 1 
#define WM_MASK 0x07 
#define WM_T_BL 2
#define WM_T_BR 3
#define WM_T_LONG 1 
#define WM_W_BOTTOM WM_W_RIGHT
#define WM_W_LEFT 1 
#define WM_W_RIGHT 2
#define WM_W_TOP WM_W_LEFT
#define WM_X_BL 3
#define WM_X_BLTR 6
#define WM_X_BR 4
#define WM_X_TL 1 
#define WM_X_TLBR 5
#define WM_X_TR 2
#define W_NONDIGGABLE 0x08
#define W_NONPASSWALL 0x10
#define ZAP_POS(typ) ((typ) >= POOL)
#define altarmask flags
#define blessedftn horizontal 
#define defsym_to_trap(d) ((d) -S_arrow_trap + 1)
#define disturbed horizontal  
#define doormask flags
#define drawbridgemask flags
#define fmon level.monlist
#define fobj level.objlist
#define icedpool flags
#define is_cmap_corr(i) ((i) >= S_corr && (i) <= S_litcorr)
#define is_cmap_door(i) ((i) >= S_vodoor && (i) <= S_hcdoor)
#define is_cmap_drawbridge(i) ((i) >= S_vodbridge && (i) <= S_hcdbridge)
#define is_cmap_furniture(i) ((i) >= S_upstair && (i) <= S_fountain)
#define is_cmap_lava(i) ((i) == S_lava)
#define is_cmap_room(i) ((i) >= S_room && (i) <= S_darkroom)
#define is_cmap_trap(i) ((i) >= S_arrow_trap && (i) <= S_polymorph_trap)
#define is_cmap_wall(i) ((i) >= S_stone && (i) <= S_trwall)
#define is_cmap_water(i) ((i) == S_pool || (i) == S_water)
#define ladder flags
#define levl level.locations
#define looted flags
#define m_at(x, y) (MON_AT(x, y) ? level.monsters[x][y] : (struct monst *) 0)
#define m_buried_at(x, y) \
    (MON_BURIED_AT(x, y) ? level.monsters[x][y] : (struct monst *) 0)
#define place_worm_seg(m, x, y) \
    do {                                                        \
        if (level.monsters[x][y] && level.monsters[x][y] != m)  \
            impossible("place_worm_seg over mon");              \
        level.monsters[x][y] = m;                               \
    } while(0)
#define remove_monster(x, y) \
    do {                                                \
        if (!level.monsters[x][y])                      \
            impossible("no monster to remove");         \
        level.monsters[x][y] = (struct monst *) 0;      \
    } while(0)
#define trap_to_defsym(t) (S_arrow_trap + (t) -1)
#define wall_info flags
#define DISCLOSE_NO_WITHOUT_PROMPT '-'
#define DISCLOSE_PROMPT_DEFAULT_NO 'n'
#define DISCLOSE_PROMPT_DEFAULT_SPECIAL '?' 
#define DISCLOSE_PROMPT_DEFAULT_YES 'y'
#define DISCLOSE_SPECIAL_WITHOUT_PROMPT '#' 
#define DISCLOSE_YES_WITHOUT_PROMPT '+'

#define FULL_MOON 4
#define GPCOORDS_COMFULL 'f'
#define GPCOORDS_COMPASS 'c'
#define GPCOORDS_MAP     'm'
#define GPCOORDS_NONE    'n'
#define GPCOORDS_SCREEN  's'
#define MAX_ALTKEYHANDLER 25
#define NEW_MOON 0
#define NUM_DISCLOSURE_OPTIONS 6 
#define PARANOID_BONES      0x0008
#define PARANOID_BREAKWAND  0x0080
#define PARANOID_CONFIRM    0x0001
#define PARANOID_DIE        0x0004
#define PARANOID_EATING     0x0200
#define PARANOID_HIT        0x0010
#define PARANOID_PRAY       0x0020
#define PARANOID_QUIT       0x0002
#define PARANOID_REMOVE     0x0040
#define PARANOID_WERECHANGE 0x0100
#define ParanoidBones ((flags.paranoia_bits & PARANOID_BONES) != 0)
#define ParanoidBreakwand ((flags.paranoia_bits & PARANOID_BREAKWAND) != 0)
#define ParanoidConfirm ((flags.paranoia_bits & PARANOID_CONFIRM) != 0)
#define ParanoidDie ((flags.paranoia_bits & PARANOID_DIE) != 0)
#define ParanoidEating ((flags.paranoia_bits & PARANOID_EATING) != 0)
#define ParanoidHit ((flags.paranoia_bits & PARANOID_HIT) != 0)
#define ParanoidPray ((flags.paranoia_bits & PARANOID_PRAY) != 0)
#define ParanoidQuit ((flags.paranoia_bits & PARANOID_QUIT) != 0)
#define ParanoidRemove ((flags.paranoia_bits & PARANOID_REMOVE) != 0)
#define ParanoidWerechange ((flags.paranoia_bits & PARANOID_WERECHANGE) != 0)

#define TER_DETECT 0x10    
#define TER_MAP    0x01
#define TER_MON    0x08
#define TER_OBJ    0x04
#define TER_TRP    0x02
#define discover flags.explore
#define eight_bit_tty wc_eight_bit_input
#define hilite_pet wc_hilite_pet
#define large_font obsolete
#define popup_dialog wc_popup_dialog
#define preload_tiles wc_preload_tiles
#define use_color wc_color
#define use_inverse wc_inverse
#define wizard flags.debug
#define ANIMATE_NORMAL 0
#define ANIMATE_SHATTER 1
#define ANIMATE_SPELL 2
#define AS_MON_IS_UNIQUE 2 
#define AS_NO_MON 1        
#define AS_OK 0            

#define conjoined vl.v_conjoined
#define dealloc_trap(trap) free((genericptr_t)(trap))
#define is_hole(ttyp)  ((ttyp) == HOLE || (ttyp) == TRAPDOOR)
#define is_pit(ttyp) ((ttyp) == PIT || (ttyp) == SPIKED_PIT)
#define launch2 vl.v_launch2
#define launch_otyp vl.v_launch_otyp
#define newtrap() (struct trap *) alloc(sizeof(struct trap))
#define tnote vl.v_tnote
#define RANGE_GLOBAL 1 
#define RANGE_LEVEL 0  

#define AE tc_gbl_data.tc_AE
#define ARTICLE_A 2
#define ARTICLE_NONE 0
#define ARTICLE_THE 1
#define ARTICLE_YOUR 3
#define AS tc_gbl_data.tc_AS
#define BONESPREFIX 3
#define CO tc_gbl_data.tc_CO
#define CONFIGPREFIX 8
#define DATAPREFIX 4 

#define DOMOVE_RUSH         0x00000002
#define DOMOVE_WALK         0x00000001
#define EXACT_NAME 0x0F
#define FQN_MAX_FILENAME 512
#define HACKPREFIX 0
#define KILLED_BY 1
#define KILLED_BY_AN 0
#define LEVELPREFIX 1
#define LI tc_gbl_data.tc_LI
#define LOCKPREFIX 6
#define MAXLINFO (MAXDUNGEON * MAXLEVEL)
#define MSGTYP_MASK_REP_SHOW ((1 << MSGTYP_NOREP) | (1 << MSGTYP_NOSHOW))
#define MSGTYP_NOREP    1
#define MSGTYP_NORMAL   0
#define MSGTYP_NOSHOW   2
#define MSGTYP_STOP     3
#define NH_AMBER c_color_names.c_amber
#define NH_BLACK c_color_names.c_black
#define NH_BLUE c_color_names.c_blue
#define NH_GOLDEN c_color_names.c_golden
#define NH_GREEN c_color_names.c_green
#define NH_LIGHT_BLUE c_color_names.c_light_blue
#define NH_ORANGE c_color_names.c_orange
#define NH_PURPLE c_color_names.c_purple
#define NH_RED c_color_names.c_red
#define NH_SILVER c_color_names.c_silver
#define NH_WHITE c_color_names.c_white
#define NO_KILLER_PREFIX 2
#define Never_mind c_common_strings.c_Never_mind

#define PREFIX_COUNT 10
#define SAVEPREFIX 2
#define SCOREPREFIX 5
#define SUPPRESS_HALLUCINATION 0x04
#define SUPPRESS_INVISIBLE 0x02
#define SUPPRESS_IT 0x01
#define SUPPRESS_NAME 0x10
#define SUPPRESS_SADDLE 0x08
#define SYSCONFPREFIX 7
#define Something c_common_strings.c_Something
#define Sprintf1(buf, cstr) Sprintf(buf, "%s", cstr)
#define TROUBLEPREFIX 9
#define WARNCOUNT 6 
#define WINTYPELEN 16
#define You1(cstr) You("%s", cstr)
#define You_can_move_again c_common_strings.c_You_can_move_again
#define You_hear1(cstr) You_hear("%s", cstr)
#define Your1(cstr) Your("%s", cstr)
#define air_level               (dungeon_topology.d_air_level)
#define asmodeus_level          (dungeon_topology.d_asmodeus_level)
#define astral_level            (dungeon_topology.d_astral_level)
#define baalzebub_level         (dungeon_topology.d_baalzebub_level)
#define bigroom_level           (dungeon_topology.d_bigroom_level)
#define dunlev_reached(x) (dungeons[(x)->dnum].dunlev_ureached)
#define earth_level             (dungeon_topology.d_earth_level)
#define fakename c_common_strings.c_fakename
#define fire_level              (dungeon_topology.d_fire_level)
#define juiblex_level           (dungeon_topology.d_juiblex_level)
#define knox_level              (dungeon_topology.d_knox_level)
#define medusa_level            (dungeon_topology.d_medusa_level)
#define mineend_level           (dungeon_topology.d_mineend_level)
#define mines_dnum              (dungeon_topology.d_mines_dnum)
#define nemesis_level           (dungeon_topology.d_nemesis_level)
#define nothing_happens c_common_strings.c_nothing_happens
#define oracle_level            (dungeon_topology.d_oracle_level)
#define orcus_level             (dungeon_topology.d_orcus_level)
#define panic1(cstr) panic("%s", cstr)
#define pline1(cstr) pline("%s", cstr)
#define portal_level            (dungeon_topology.d_portal_level)
#define qlocate_level           (dungeon_topology.d_qlocate_level)
#define qstart_level            (dungeon_topology.d_qstart_level)
#define quest_dnum              (dungeon_topology.d_quest_dnum)
#define rogue_level             (dungeon_topology.d_rogue_level)
#define sanctum_level           (dungeon_topology.d_sanctum_level)
#define shudder_for_moment c_common_strings.c_shudder_for_moment
#define silly_thing_to c_common_strings.c_silly_thing_to
#define sokoban_dnum            (dungeon_topology.d_sokoban_dnum)
#define sokoend_level           (dungeon_topology.d_sokoend_level)
#define something c_common_strings.c_something
#define stronghold_level        (dungeon_topology.d_stronghold_level)
#define thats_enough_tries c_common_strings.c_thats_enough_tries
#define the_your c_common_strings.c_the_your
#define tower_dnum              (dungeon_topology.d_tower_dnum)
#define valley_level            (dungeon_topology.d_valley_level)
#define verbalize1(cstr) verbalize("%s", cstr)
#define vision_clears c_common_strings.c_vision_clears
#define water_level             (dungeon_topology.d_water_level)
#define wiz1_level              (dungeon_topology.d_wiz1_level)
#define wiz2_level              (dungeon_topology.d_wiz2_level)
#define wiz3_level              (dungeon_topology.d_wiz3_level)
#define xdnladder (dnladder.sx)
#define xdnstair (dnstair.sx)
#define xupladder (upladder.sx)
#define xupstair (upstair.sx)
#define ydnladder (dnladder.sy)
#define ydnstair (dnstair.sy)
#define yupladder (upladder.sy)
#define yupstair (upstair.sy)
#define A_CURRENT  0
#define A_ORIGINAL 1
#define BC_BALL 0x01  
#define BC_CHAIN 0x02 
#define CONVERT    2
#define LUCKADD    3  
#define LUCKMAX   10  
#define LUCKMIN (-10) 
#define Luck (u.uluck + u.moreluck)
#define ROLE_ALIGNMASK AM_MASK    
#define ROLE_ALIGNS 3     
#define ROLE_CHAOTIC   AM_CHAOTIC
#define ROLE_FEMALE    0x2000
#define ROLE_GENDERS 2    
#define ROLE_GENDMASK  0xf000     
#define ROLE_LAWFUL    AM_LAWFUL
#define ROLE_MALE      0x1000
#define ROLE_NEUTER    0x4000
#define ROLE_NEUTRAL   AM_NEUTRAL
#define ROLE_NONE (-1)
#define ROLE_RACEMASK  0x0ff8     
#define ROLE_RANDOM (-2)
#define Race_if(X) (urace.malenum == (X))
#define Race_switch (urace.malenum)
#define Role_if(X) (urole.malenum == (X))
#define Role_switch (urole.malenum)
#define SICK_ALL 0x03
#define SICK_NONVOMITABLE 0x02
#define SICK_VOMITABLE 0x01
#define Upolyd (u.umonnum != u.umonster)

#define mhe(mtmp)  (genders[pronoun_gender(mtmp, FALSE)].he)
#define mhim(mtmp) (genders[pronoun_gender(mtmp, FALSE)].him)
#define mhis(mtmp) (genders[pronoun_gender(mtmp, FALSE)].his)
#define noit_mhe(mtmp)  (genders[pronoun_gender(mtmp, TRUE)].he)
#define noit_mhim(mtmp) (genders[pronoun_gender(mtmp, TRUE)].him)
#define noit_mhis(mtmp) (genders[pronoun_gender(mtmp, TRUE)].his)
#define uhe()      (genders[flags.female ? 1 : 0].he)
#define uhim()     (genders[flags.female ? 1 : 0].him)
#define uhis()     (genders[flags.female ? 1 : 0].his)
#define P_ADVANCE(type) (u.weapon_skills[type].advance)
#define P_FIRST_H_TO_H P_BARE_HANDED_COMBAT
#define P_FIRST_SPELL P_ATTACK_SPELL
#define P_FIRST_WEAPON P_DAGGER
#define P_LAST_H_TO_H P_RIDING
#define P_LAST_SPELL P_MATTER_SPELL
#define P_LAST_WEAPON P_UNICORN_HORN
#define P_MARTIAL_ARTS P_BARE_HANDED_COMBAT 
#define P_MAX_SKILL(type) (u.weapon_skills[type].max_skill)
#define P_RESTRICTED(type) (u.weapon_skills[type].skill == P_ISRESTRICTED)
#define P_SKILL(type) (u.weapon_skills[type].skill)
#define P_SKILL_LIMIT 60 

#define martial_bonus() (Role_if(PM_SAMURAI) || Role_if(PM_MONK))
#define practice_needed_to_advance(level) ((level) * (level) *20)
#define BOTH_SIDES (LEFT_SIDE | RIGHT_SIDE)
#define FROMEXPER 0x01000000L   
#define FROMFORM 0x10000000L  
#define FROMOUTSIDE 0x04000000L 
#define FROMRACE 0x02000000L    
#define INTRINSIC (FROMOUTSIDE | FROMRACE | FROMEXPER)
#define I_SPECIAL 0x20000000L 
#define LAST_PROP (LIFESAVED)
#define LEFT_RING W_RINGL
#define LEFT_SIDE LEFT_RING

#define RIGHT_RING W_RINGR
#define RIGHT_SIDE RIGHT_RING
#define TIMEOUT 0x00ffffffL     
#define WORN_AMUL W_AMUL
#define WORN_ARMOR W_ARM
#define WORN_BLINDF W_TOOL
#define WORN_BOOTS W_ARMF
#define WORN_CLOAK W_ARMC
#define WORN_GLOVES W_ARMG
#define WORN_HELMET W_ARMH
#define WORN_SHIELD W_ARMS
#define WORN_SHIRT W_ARMU
#define W_ACCESSORY (W_RING | W_AMUL | W_TOOL)
#define W_AMUL 0x00010000L    
#define W_ARM 0x00000001L  
#define W_ARMC 0x00000002L 
#define W_ARMF 0x00000020L 
#define W_ARMG 0x00000010L 
#define W_ARMH 0x00000004L 
#define W_ARMOR (W_ARM | W_ARMC | W_ARMH | W_ARMS | W_ARMG | W_ARMF | W_ARMU)
#define W_ARMS 0x00000008L 
#define W_ARMU 0x00000040L 
#define W_ART 0x00001000L     
#define W_ARTI 0x00002000L    
#define W_BALL 0x00200000L   
#define W_CHAIN 0x00400000L  
#define W_QUIVER 0x00000200L  
#define W_RING (W_RINGL | W_RINGR)
#define W_RINGL 0x00020000L   
#define W_RINGR 0x00040000L   
#define W_SADDLE 0x00100000L 
#define W_SWAPWEP 0x00000400L 
#define W_TOOL 0x00080000L   
#define W_WEAPONS (W_WEP | W_SWAPWEP | W_QUIVER)
#define W_WEP 0x00000100L     
#define DEADMONSTER(mon) ((mon)->mhp < 1)
#define MAX_NUM_WORMS 32    
#define MFAST 2 
#define MINV_ALL      0x08
#define MINV_NOLET    0x04
#define MINV_PICKMASK 0x03 

#define MON_BUBBLEMOVE   0x10
#define MON_DETACH       0x02
#define MON_ENDGAME_FREE 0x20
#define MON_ENDGAME_MIGR 0x40
#define MON_FLOOR        0x00
#define MON_LIMBO        0x08
#define MON_MIGRATING    0x04
#define MON_NOWEP(mon) ((mon)->mw = (struct obj *) 0)
#define MON_OBLITERATE   0x80
#define MON_OFFMAP       0x01
#define MON_WEP(mon) ((mon)->mw)
#define MSLOW 1 
#define MSTATE_MASK      0xFF
#define MTSZ 4
#define M_AP_FLAG(m) ((m)->m_ap_type & ~M_AP_TYPMASK)
#define M_AP_F_DKNOWN 0x8
#define M_AP_TYPE(m) ((m)->m_ap_type & M_AP_TYPMASK)
#define M_AP_TYPMASK  0x7
#define STRAT_APPEARMSG 0x80000000UL
#define STRAT_ARRIVE    0x40000000L 
#define STRAT_CLOSE     0x10000000L
#define STRAT_GOAL      0x000000ffL
#define STRAT_GOALX(s) ((xchar) ((s & STRAT_XMASK) >> 16))
#define STRAT_GOALY(s) ((xchar) ((s & STRAT_YMASK) >> 8))
#define STRAT_GROUND    0x04000000L
#define STRAT_HEAL      0x08000000L
#define STRAT_MONSTR    0x02000000L
#define STRAT_NONE      0x00000000L
#define STRAT_PLAYER    0x01000000L
#define STRAT_STRATMASK 0x0f000000L
#define STRAT_WAITFORU  0x20000000L
#define STRAT_WAITMASK  (STRAT_CLOSE | STRAT_WAITFORU)
#define STRAT_XMASK     0x00ff0000L
#define STRAT_YMASK     0x0000ff00L
#define U_AP_FLAG (youmonst.m_ap_type & ~M_AP_TYPMASK)
#define U_AP_TYPE (youmonst.m_ap_type & M_AP_TYPMASK)
#define is_door_mappear(mon) (M_AP_TYPE(mon) == M_AP_FURNITURE   \
                              && ((mon)->mappearance == S_hcdoor \
                                  || (mon)->mappearance == S_vcdoor))
#define is_lightblocker_mappear(mon)                       \
    (is_obj_mappear(mon, BOULDER)                          \
     || (M_AP_TYPE(mon) == M_AP_FURNITURE                    \
         && ((mon)->mappearance == S_hcdoor                \
             || (mon)->mappearance == S_vcdoor             \
             || (mon)->mappearance < S_ndoor  \
             || (mon)->mappearance == S_tree)))
#define is_obj_mappear(mon,otyp) (M_AP_TYPE(mon) == M_AP_OBJECT \
                                  && (mon)->mappearance == (otyp))
#define is_starting_pet(mon) ((mon)->m_id == context.startingpet_mid)
#define is_vampshifter(mon)                                      \
    ((mon)->cham == PM_VAMPIRE || (mon)->cham == PM_VAMPIRE_LORD \
     || (mon)->cham == PM_VLAD_THE_IMPALER)
#define mstate mspare1      
#define mtemplit mburied      
#define newmonst() (struct monst *) alloc(sizeof (struct monst))
#define BILLSZ 200
#define EDOG(mon) ((mon)->mextra->edog)
#define EGD(mon) ((mon)->mextra->egd)
#define EMIN(mon) ((mon)->mextra->emin)
#define EPRI(mon) ((mon)->mextra->epri)
#define ESHK(mon) ((mon)->mextra->eshk)
#define FCSIZ (ROWNO + COLNO)
#define GD_DESTROYGOLD 0x02
#define GD_EATGOLD 0x01
#define MCORPSENM(mon) ((mon)->mextra->mcorpsenm)

#define MNAME(mon) ((mon)->mextra->mname)
#define REPAIR_DELAY 5 
#define has_edog(mon)  ((mon)->mextra && EDOG(mon))
#define has_egd(mon)   ((mon)->mextra && EGD(mon))
#define has_emin(mon)  ((mon)->mextra && EMIN(mon))
#define has_epri(mon)  ((mon)->mextra && EPRI(mon))
#define has_eshk(mon)  ((mon)->mextra && ESHK(mon))
#define has_mcorpsenm(mon) ((mon)->mextra && MCORPSENM(mon) != NON_PM)
#define has_mname(mon) ((mon)->mextra && MNAME(mon))
#define ALIGNLIM (10L + (moves / 200L))

#define AM_CHAOTIC 1
#define AM_LAWFUL 4
#define AM_MASK 7
#define AM_NEUTRAL 2
#define AM_NONE 0
#define AM_SPLEV_CO 3
#define AM_SPLEV_NONCO 7
#define A_CHAOTIC (-1)
#define A_COALIGNED 1
#define A_LAWFUL 1
#define A_NEUTRAL 0
#define A_NONE (-128) 
#define A_OPALIGNED (-1)
#define Align2amask(x) \
    (((x) == A_NONE) ? AM_NONE : ((x) == A_LAWFUL) ? AM_LAWFUL : (x) + 2)
#define Amask2align(x)                                          \
    ((aligntyp)((!(x)) ? A_NONE : ((x) == AM_LAWFUL) ? A_LAWFUL \
                                                     : ((int) x) - 2))
#define ABASE(x) (u.acurr.a[x])
#define ABON(x) (u.abon.a[x])
#define ACURR(x) (acurr(x))
#define ACURRSTR (acurrstr())
#define AEXE(x) (u.aexe.a[x])
#define AMAX(x) (u.amax.a[x])
#define ATEMP(x) (u.atemp.a[x])
#define ATIME(x) (u.atime.a[x])

#define ATTRMAX(x)                                        \
    ((x == A_STR && Upolyd && strongmonst(youmonst.data)) \
         ? STR18(100)                                     \
         : urace.attrmax[x])
#define ATTRMIN(x) (urace.attrmin[x])
#define MCURR(x) (u.macurr.a[x])
#define MMAX(x) (u.mamax.a[x])
#define STR18(x) (18 + (x))  
#define STR19(x) (100 + (x)) 
#define BURIED_TOO 0x2
#define CONTAINED_TOO 0x1
#define Dragon_mail_to_pm(obj) \
    &mons[PM_GRAY_DRAGON + (obj)->otyp - GRAY_DRAGON_SCALE_MAIL]
#define Dragon_scales_to_pm(obj) \
    &mons[PM_GRAY_DRAGON + (obj)->otyp - GRAY_DRAGON_SCALES]
#define Dragon_to_scales(pm) (GRAY_DRAGON_SCALES + (pm - mons))
#define EF_DESTROY 0x2 
#define EF_GREASE 0x1  
#define EF_NONE 0
#define EF_PAY 0x8     
#define EF_VERBOSE 0x4 
#define ERODE_BURN 0
#define ERODE_CORRODE 3
#define ERODE_ROT 2
#define ERODE_RUST 1
#define ER_DAMAGED 2   
#define ER_DESTROYED 3 
#define ER_GREASED 1   
#define ER_NOTHING 0   
#define Has_contents(o)                                \
    ( \
     (o)->cobj != (struct obj *) 0)
#define Is_box(otmp) (otmp->otyp == LARGE_BOX || otmp->otyp == CHEST)
#define Is_candle(otmp) \
    (otmp->otyp == TALLOW_CANDLE || otmp->otyp == WAX_CANDLE)
#define Is_container(o) ((o)->otyp >= LARGE_BOX && (o)->otyp <= BAG_OF_TRICKS)
#define Is_dragon_armor(obj) (Is_dragon_scales(obj) || Is_dragon_mail(obj))
#define Is_dragon_mail(obj)                \
    ((obj)->otyp >= GRAY_DRAGON_SCALE_MAIL \
     && (obj)->otyp <= YELLOW_DRAGON_SCALE_MAIL)
#define Is_dragon_scales(obj) \
    ((obj)->otyp >= GRAY_DRAGON_SCALES && (obj)->otyp <= YELLOW_DRAGON_SCALES)
#define Is_mbag(otmp) \
    (otmp->otyp == BAG_OF_HOLDING || otmp->otyp == BAG_OF_TRICKS)
#define Is_pudding(o)                                                 \
    (o->otyp == GLOB_OF_GRAY_OOZE || o->otyp == GLOB_OF_BROWN_PUDDING \
     || o->otyp == GLOB_OF_GREEN_SLIME || o->otyp == GLOB_OF_BLACK_PUDDING)
#define MAX_EGG_HATCH_TIME 200 
#define MAX_ERODE 3
#define MAX_OIL_IN_FLASK 400 
#define MINES_PRIZE 1
#define NOBJ_STATES 8
#define OBJ_BURIED 6    
#define OBJ_CONTAINED 2 
#define OBJ_FLOOR 1     
#define OBJ_FREE 0      

#define OBJ_INVENT 3    
#define OBJ_MIGRATING 5 
#define OBJ_MINVENT 4   
#define OBJ_ONBILL 7    
#define OLONG(o) ((o)->oextra->olong)
#define OMAILCMD(o) ((o)->oextra->omailcmd)
#define OMID(o) ((o)->oextra->omid)
#define OMONST(o) ((o)->oextra->omonst)
#define ONAME(o) ((o)->oextra->oname)
#define POTHIT_HERO_BASH   0 
#define POTHIT_HERO_THROW  1 
#define POTHIT_MONST_THROW 2 
#define POTHIT_OTHER_THROW 3 
#define SOKO_PRIZE1 2
#define SOKO_PRIZE2 3
#define STATUE_FEMALE 0x04
#define STATUE_HISTORIC 0x01
#define STATUE_MALE 0x02
#define SchroedingersBox(o) ((o)->otyp == LARGE_BOX && (o)->spe == 1)
#define age_is_relative(otmp)                                       \
    ((otmp)->otyp == BRASS_LANTERN || (otmp)->otyp == OIL_LAMP      \
     || (otmp)->otyp == CANDELABRUM_OF_INVOCATION                   \
     || (otmp)->otyp == TALLOW_CANDLE || (otmp)->otyp == WAX_CANDLE \
     || (otmp)->otyp == POT_OIL)
#define ammo_and_launcher(a, l) (is_ammo(a) && matching_launcher(a, l))
#define any_quest_artifact(o) ((o)->oartifact >= ART_ORB_OF_DETECTION)
#define bimanual(otmp)                                            \
    ((otmp->oclass == WEAPON_CLASS || otmp->oclass == TOOL_CLASS) \
     && objects[otmp->otyp].oc_bimanual)
#define carried(o) ((o)->where == OBJ_INVENT)
#define degraded_horn obroken 
#define fromsink corpsenm 
#define greatest_erosion(otmp)                                 \
    (int)((otmp)->oeroded > (otmp)->oeroded2 ? (otmp)->oeroded \
                                             : (otmp)->oeroded2)
#define has_olong(o) ((o)->oextra && OLONG(o))
#define has_omailcmd(o) ((o)->oextra && OMAILCMD(o))
#define has_omid(o) ((o)->oextra && OMID(o))
#define has_omonst(o) ((o)->oextra && OMONST(o))
#define has_oname(o) ((o)->oextra && ONAME(o))
#define ignitable(otmp)                                             \
    ((otmp)->otyp == BRASS_LANTERN || (otmp)->otyp == OIL_LAMP      \
     || (otmp)->otyp == CANDELABRUM_OF_INVOCATION                   \
     || (otmp)->otyp == TALLOW_CANDLE || (otmp)->otyp == WAX_CANDLE \
     || (otmp)->otyp == POT_OIL)
#define is_ammo(otmp)                                            \
    ((otmp->oclass == WEAPON_CLASS || otmp->oclass == GEM_CLASS) \
     && objects[otmp->otyp].oc_skill >= -P_CROSSBOW              \
     && objects[otmp->otyp].oc_skill <= -P_BOW)
#define is_axe(otmp)                                              \
    ((otmp->oclass == WEAPON_CLASS || otmp->oclass == TOOL_CLASS) \
     && objects[otmp->otyp].oc_skill == P_AXE)
#define is_blade(otmp)                           \
    (otmp->oclass == WEAPON_CLASS                \
     && objects[otmp->otyp].oc_skill >= P_DAGGER \
     && objects[otmp->otyp].oc_skill <= P_SABER)
#define is_boots(otmp)           \
    (otmp->oclass == ARMOR_CLASS \
     && objects[otmp->otyp].oc_armcat == ARM_BOOTS)
#define is_cloak(otmp)           \
    (otmp->oclass == ARMOR_CLASS \
     && objects[otmp->otyp].oc_armcat == ARM_CLOAK)
#define is_dwarvish_armor(otmp)               \
    ((otmp)->otyp == DWARVISH_IRON_HELM       \
     || (otmp)->otyp == DWARVISH_MITHRIL_COAT \
     || (otmp)->otyp == DWARVISH_CLOAK        \
     || (otmp)->otyp == DWARVISH_ROUNDSHIELD)
#define is_dwarvish_obj(otmp)                                  \
    (is_dwarvish_armor(otmp) || (otmp)->otyp == DWARVISH_SPEAR \
     || (otmp)->otyp == DWARVISH_SHORT_SWORD                   \
     || (otmp)->otyp == DWARVISH_MATTOCK)
#define is_elven_armor(otmp)                                              \
    ((otmp)->otyp == ELVEN_LEATHER_HELM                                   \
     || (otmp)->otyp == ELVEN_MITHRIL_COAT || (otmp)->otyp == ELVEN_CLOAK \
     || (otmp)->otyp == ELVEN_SHIELD || (otmp)->otyp == ELVEN_BOOTS)
#define is_elven_obj(otmp) (is_elven_armor(otmp) || is_elven_weapon(otmp))
#define is_elven_weapon(otmp)                                             \
    ((otmp)->otyp == ELVEN_ARROW || (otmp)->otyp == ELVEN_SPEAR           \
     || (otmp)->otyp == ELVEN_DAGGER || (otmp)->otyp == ELVEN_SHORT_SWORD \
     || (otmp)->otyp == ELVEN_BROADSWORD || (otmp)->otyp == ELVEN_BOW)
#define is_flimsy(otmp)                           \
    (objects[(otmp)->otyp].oc_material <= LEATHER \
     || (otmp)->otyp == RUBBER_HOSE)
#define is_gloves(otmp)          \
    (otmp->oclass == ARMOR_CLASS \
     && objects[otmp->otyp].oc_armcat == ARM_GLOVES)
#define is_gnomish_armor(otmp) (FALSE)
#define is_gnomish_obj(otmp) (is_gnomish_armor(otmp))
#define is_graystone(obj)                                 \
    ((obj)->otyp == LUCKSTONE || (obj)->otyp == LOADSTONE \
     || (obj)->otyp == FLINT || (obj)->otyp == TOUCHSTONE)
#define is_helmet(otmp) \
    (otmp->oclass == ARMOR_CLASS && objects[otmp->otyp].oc_armcat == ARM_HELM)
#define is_launcher(otmp)                                                  \
    (otmp->oclass == WEAPON_CLASS && objects[otmp->otyp].oc_skill >= P_BOW \
     && objects[otmp->otyp].oc_skill <= P_CROSSBOW)
#define is_mines_prize(o) \
    ((o)->otyp == iflags.mines_prize_type                \
     && (o)->record_achieve_special == MINES_PRIZE)
#define is_missile(otmp)                                          \
    ((otmp->oclass == WEAPON_CLASS || otmp->oclass == TOOL_CLASS) \
     && objects[otmp->otyp].oc_skill >= -P_BOOMERANG              \
     && objects[otmp->otyp].oc_skill <= -P_DART)
#define is_multigen(otmp)                           \
    (otmp->oclass == WEAPON_CLASS                   \
     && objects[otmp->otyp].oc_skill >= -P_SHURIKEN \
     && objects[otmp->otyp].oc_skill <= -P_BOW)
#define is_orcish_armor(otmp)                                            \
    ((otmp)->otyp == ORCISH_HELM || (otmp)->otyp == ORCISH_CHAIN_MAIL    \
     || (otmp)->otyp == ORCISH_RING_MAIL || (otmp)->otyp == ORCISH_CLOAK \
     || (otmp)->otyp == URUK_HAI_SHIELD || (otmp)->otyp == ORCISH_SHIELD)
#define is_orcish_obj(otmp)                                           \
    (is_orcish_armor(otmp) || (otmp)->otyp == ORCISH_ARROW            \
     || (otmp)->otyp == ORCISH_SPEAR || (otmp)->otyp == ORCISH_DAGGER \
     || (otmp)->otyp == ORCISH_SHORT_SWORD || (otmp)->otyp == ORCISH_BOW)
#define is_pick(otmp)                                             \
    ((otmp->oclass == WEAPON_CLASS || otmp->oclass == TOOL_CLASS) \
     && objects[otmp->otyp].oc_skill == P_PICK_AXE)
#define is_plural(o) \
    ((o)->quan != 1L                                                    \
         \
     || ((o)->oartifact == ART_EYES_OF_THE_OVERWORLD                    \
         && !undiscovered_artifact(ART_EYES_OF_THE_OVERWORLD)))
#define is_poisonable(otmp)                         \
    (otmp->oclass == WEAPON_CLASS                   \
     && objects[otmp->otyp].oc_skill >= -P_SHURIKEN \
     && objects[otmp->otyp].oc_skill <= -P_BOW)
#define is_pole(otmp)                                             \
    ((otmp->oclass == WEAPON_CLASS || otmp->oclass == TOOL_CLASS) \
     && (objects[otmp->otyp].oc_skill == P_POLEARMS               \
         || objects[otmp->otyp].oc_skill == P_LANCE))
#define is_readable(otmp)                                                    \
    ((otmp)->otyp == FORTUNE_COOKIE || (otmp)->otyp == T_SHIRT               \
     || (otmp)->otyp == ALCHEMY_SMOCK || (otmp)->otyp == CREDIT_CARD         \
     || (otmp)->otyp == CAN_OF_GREASE || (otmp)->otyp == MAGIC_MARKER        \
     || (otmp)->oclass == COIN_CLASS || (otmp)->oartifact == ART_ORB_OF_FATE \
     || (otmp)->otyp == CANDY_BAR)
#define is_shield(otmp)          \
    (otmp->oclass == ARMOR_CLASS \
     && objects[otmp->otyp].oc_armcat == ARM_SHIELD)
#define is_shirt(otmp)           \
    (otmp->oclass == ARMOR_CLASS \
     && objects[otmp->otyp].oc_armcat == ARM_SHIRT)
#define is_soko_prize(o) \
    (((o)->otyp == iflags.soko_prize_type1               \
      && (o)->record_achieve_special == SOKO_PRIZE1)     \
     || ((o)->otyp == iflags.soko_prize_type2            \
         && (o)->record_achieve_special == SOKO_PRIZE2))
#define is_spear(otmp) \
    (otmp->oclass == WEAPON_CLASS && objects[otmp->otyp].oc_skill == P_SPEAR)
#define is_suit(otmp) \
    (otmp->oclass == ARMOR_CLASS && objects[otmp->otyp].oc_armcat == ARM_SUIT)
#define is_sword(otmp)                                \
    (otmp->oclass == WEAPON_CLASS                     \
     && objects[otmp->otyp].oc_skill >= P_SHORT_SWORD \
     && objects[otmp->otyp].oc_skill <= P_SABER)
#define is_weptool(o) \
    ((o)->oclass == TOOL_CLASS && objects[(o)->otyp].oc_skill != P_NONE)
#define is_wet_towel(o) ((o)->otyp == TOWEL && (o)->spe > 0)
#define leashmon corpsenm 
#define matching_launcher(a, l) \
    ((l) && objects[(a)->otyp].oc_skill == -objects[(l)->otyp].oc_skill)
#define mcarried(o) ((o)->where == OBJ_MINVENT)
#define mhealup(obj) (ofood(obj) && (obj)->corpsenm == PM_NURSE)
#define mlevelgain(obj) (ofood(obj) && (obj)->corpsenm == PM_WRAITH)
#define newobj() (struct obj *) alloc(sizeof(struct obj))
#define nexthere v.v_nexthere
#define norevive oeroded2
#define novelidx corpsenm 
#define ocarry v.v_ocarry
#define ocontainer v.v_ocontainer
#define odiluted oeroded 
#define ofood(o) ((o)->otyp == CORPSE || (o)->otyp == EGG || (o)->otyp == TIN)
#define on_ice recharged    
#define opoisoned otrapped 
#define orotten oeroded  
#define pair_of(o) ((o)->otyp == LENSES || is_gloves(o) || is_boots(o))
#define polyfodder(obj) (ofood(obj) && pm_to_cham((obj)->corpsenm) != NON_PM)
#define record_achieve_special corpsenm
#define spestudied usecount 
#define stale_egg(egg) \
    ((monstermoves - (egg)->age) > (2 * MAX_EGG_HATCH_TIME))
#define uslinging() (uwep && objects[uwep->otyp].oc_skill == P_SLING)
#define BRIGHT 8
#define CLR_BLACK 0
#define CLR_BLUE 4
#define CLR_BRIGHT_BLUE 12
#define CLR_BRIGHT_CYAN 14
#define CLR_BRIGHT_GREEN 10
#define CLR_BRIGHT_MAGENTA 13
#define CLR_BROWN 3 
#define CLR_CYAN 6
#define CLR_GRAY 7 
#define CLR_GREEN 2
#define CLR_MAGENTA 5
#define CLR_MAX 16
#define CLR_ORANGE 9
#define CLR_RED 1
#define CLR_WHITE 15
#define CLR_YELLOW 11

#define DRAGON_SILVER CLR_BRIGHT_CYAN
#define HI_CLOTH CLR_BROWN
#define HI_COPPER CLR_YELLOW
#define HI_GLASS CLR_BRIGHT_CYAN
#define HI_GOLD CLR_YELLOW
#define HI_LEATHER CLR_BROWN
#define HI_METAL CLR_CYAN
#define HI_MINERAL CLR_GRAY
#define HI_OBJ CLR_MAGENTA
#define HI_ORGANIC CLR_BROWN
#define HI_PAPER CLR_WHITE
#define HI_SILVER CLR_GRAY
#define HI_WOOD CLR_BROWN
#define HI_ZAP CLR_BRIGHT_BLUE
#define NO_COLOR 8
#define ALL_MAP 0x1
#define ALL_SPELLS 0x2
#define MAX_SPELL_STUDY 3
#define NO_SPELL 0

#define decrnknow(spell) spl_book[spell].sp_know--
#define spellid(spell) spl_book[spell].sp_id
#define spellknow(spell) spl_book[spell].sp_know
#define MAX_QUEST_TRIES 7  
#define MIN_QUEST_ALIGN 20 
#define MIN_QUEST_LEVEL 14 

#define CONTEXTVERBSZ 30

#define ANY_P union any 
#define ATR_BLINK      5
#define ATR_BOLD       1
#define ATR_DIM        2
#define ATR_INVERSE    7
#define ATR_NOHISTORY 32
#define ATR_NONE       0
#define ATR_ULINE      4
#define ATR_URGENT    16
#define CLICK_1 1
#define CLICK_2 2
#define MENU_FIRST_PAGE         '^'
#define MENU_INVERT_ALL         '@'
#define MENU_INVERT_PAGE        '~'
#define MENU_ITEM_P struct mi
#define MENU_LAST_PAGE          '|'
#define MENU_NEXT_PAGE          '>'
#define MENU_PREVIOUS_PAGE      '<'
#define MENU_SEARCH             ':'
#define MENU_SELECT_ALL         '.'
#define MENU_SELECT_PAGE        ','
#define MENU_UNSELECT_ALL       '-'
#define MENU_UNSELECT_PAGE      '\\'
#define NHW_MAP 3
#define NHW_MENU 4
#define NHW_MESSAGE 1
#define NHW_STATUS 2
#define NHW_TEXT 5
#define PICK_ANY 2  
#define PICK_NONE 0 
#define PICK_ONE 1  

#define WIN_ERR ((winid) -1)
#define Acid_resistance (HAcid_resistance || EAcid_resistance)
#define Adornment u.uprops[ADORNED].extrinsic
#define Aggravate_monster (HAggravate_monster || EAggravate_monster)
#define Amphibious \
    (HMagical_breathing || EMagical_breathing || amphibious(youmonst.data))
#define Antimagic (HAntimagic || EAntimagic)
#define BClairvoyant u.uprops[CLAIRVOYANT].blocked
#define BFlying u.uprops[FLYING].blocked
#define BInvis u.uprops[INVIS].blocked
#define BLevitation u.uprops[LEVITATION].blocked
#define BStealth u.uprops[STEALTH].blocked
#define Blind                                     \
    ((u.uroleplay.blind || Blinded || Blindfolded \
      || !haseyes(youmonst.data))                 \
     && !(ublindf && ublindf->oartifact == ART_EYES_OF_THE_OVERWORLD))
#define Blind_telepat (HTelepat || ETelepat)
#define Blinded u.uprops[BLINDED].intrinsic
#define Blindfolded (ublindf && ublindf->otyp != LENSES)
#define Blindfolded_only                                            \
    (Blindfolded && ublindf->oartifact != ART_EYES_OF_THE_OVERWORLD \
     && !u.uroleplay.blind && !Blinded && haseyes(youmonst.data))
#define Breathless \
    (HMagical_breathing || EMagical_breathing || breathless(youmonst.data))
#define Clairvoyant ((HClairvoyant || EClairvoyant) && !BClairvoyant)
#define Cold_resistance (HCold_resistance || ECold_resistance)
#define Conflict (HConflict || EConflict)
#define Confusion HConfusion
#define Deaf (HDeaf || EDeaf)
#define Detect_monsters (HDetect_monsters || EDetect_monsters)
#define Disint_resistance (HDisint_resistance || EDisint_resistance)
#define Displaced EDisplaced
#define Drain_resistance (HDrain_resistance || EDrain_resistance)
#define EAcid_resistance u.uprops[ACID_RES].extrinsic
#define EAggravate_monster u.uprops[AGGRAVATE_MONSTER].extrinsic
#define EAntimagic u.uprops[ANTIMAGIC].extrinsic
#define EClairvoyant u.uprops[CLAIRVOYANT].extrinsic
#define ECold_resistance u.uprops[COLD_RES].extrinsic
#define EConflict u.uprops[CONFLICT].extrinsic
#define EDeaf u.uprops[DEAF].extrinsic
#define EDetect_monsters u.uprops[DETECT_MONSTERS].extrinsic
#define EDisint_resistance u.uprops[DISINT_RES].extrinsic
#define EDisplaced u.uprops[DISPLACED].extrinsic
#define EDrain_resistance u.uprops[DRAIN_RES].extrinsic
#define EEnergy_regeneration u.uprops[ENERGY_REGENERATION].extrinsic
#define EFast u.uprops[FAST].extrinsic
#define EFire_resistance u.uprops[FIRE_RES].extrinsic
#define EFlying u.uprops[FLYING].extrinsic
#define EFumbling u.uprops[FUMBLING].extrinsic
#define EHalf_physical_damage u.uprops[HALF_PHDAM].extrinsic
#define EHalf_spell_damage u.uprops[HALF_SPDAM].extrinsic
#define EHalluc_resistance u.uprops[HALLUC_RES].extrinsic
#define EHunger u.uprops[HUNGER].extrinsic
#define EInfravision u.uprops[INFRAVISION].extrinsic
#define EInvis u.uprops[INVIS].extrinsic
#define EJumping u.uprops[JUMPING].extrinsic
#define ELevitation u.uprops[LEVITATION].extrinsic
#define EMagical_breathing u.uprops[MAGICAL_BREATHING].extrinsic
#define EPasses_walls u.uprops[PASSES_WALLS].extrinsic
#define EPoison_resistance u.uprops[POISON_RES].extrinsic
#define EPolymorph u.uprops[POLYMORPH].extrinsic
#define EPolymorph_control u.uprops[POLYMORPH_CONTROL].extrinsic
#define EProtection u.uprops[PROTECTION].extrinsic
#define EProtection_from_shape_changers \
    u.uprops[PROT_FROM_SHAPE_CHANGERS].extrinsic
#define EReflecting u.uprops[REFLECTING].extrinsic
#define ERegeneration u.uprops[REGENERATION].extrinsic
#define ESearching u.uprops[SEARCHING].extrinsic
#define ESee_invisible u.uprops[SEE_INVIS].extrinsic
#define EShock_resistance u.uprops[SHOCK_RES].extrinsic
#define ESleep_resistance u.uprops[SLEEP_RES].extrinsic
#define ESleepy u.uprops[SLEEPY].extrinsic
#define ESlow_digestion u.uprops[SLOW_DIGESTION].extrinsic
#define EStealth u.uprops[STEALTH].extrinsic
#define EStone_resistance u.uprops[STONE_RES].extrinsic
#define ESwimming u.uprops[SWIMMING].extrinsic 
#define ETelepat u.uprops[TELEPAT].extrinsic
#define ETeleport_control u.uprops[TELEPORT_CONTROL].extrinsic
#define ETeleportation u.uprops[TELEPORT].extrinsic
#define EUnchanging u.uprops[UNCHANGING].extrinsic
#define EWarn_of_mon u.uprops[WARN_OF_MON].extrinsic
#define EWarning u.uprops[WARNING].extrinsic
#define EWounded_legs u.uprops[WOUNDED_LEGS].extrinsic
#define EWwalking u.uprops[WWALKING].extrinsic
#define Energy_regeneration (HEnergy_regeneration || EEnergy_regeneration)
#define Fast (HFast || EFast)
#define Fire_resistance (HFire_resistance || EFire_resistance)
#define Fixed_abil u.uprops[FIXED_ABIL].extrinsic 
#define Flying                                                      \
    ((HFlying || EFlying || (u.usteed && is_flyer(u.usteed->data))) \
     && !BFlying)
#define Free_action u.uprops[FREE_ACTION].extrinsic 
#define Fumbling (HFumbling || EFumbling)
#define Glib u.uprops[GLIB].intrinsic
#define HAcid_resistance u.uprops[ACID_RES].intrinsic
#define HAggravate_monster u.uprops[AGGRAVATE_MONSTER].intrinsic
#define HAntimagic u.uprops[ANTIMAGIC].intrinsic
#define HClairvoyant u.uprops[CLAIRVOYANT].intrinsic
#define HCold_resistance u.uprops[COLD_RES].intrinsic
#define HConflict u.uprops[CONFLICT].intrinsic
#define HConfusion u.uprops[CONFUSION].intrinsic
#define HDeaf u.uprops[DEAF].intrinsic
#define HDetect_monsters u.uprops[DETECT_MONSTERS].intrinsic
#define HDisint_resistance u.uprops[DISINT_RES].intrinsic
#define HDrain_resistance u.uprops[DRAIN_RES].intrinsic
#define HEnergy_regeneration u.uprops[ENERGY_REGENERATION].intrinsic
#define HFast u.uprops[FAST].intrinsic
#define HFire_resistance u.uprops[FIRE_RES].intrinsic
#define HFlying u.uprops[FLYING].intrinsic
#define HFumbling u.uprops[FUMBLING].intrinsic
#define HHalf_physical_damage u.uprops[HALF_PHDAM].intrinsic
#define HHalf_spell_damage u.uprops[HALF_SPDAM].intrinsic
#define HHalluc_resistance u.uprops[HALLUC_RES].intrinsic
#define HHallucination u.uprops[HALLUC].intrinsic
#define HHunger u.uprops[HUNGER].intrinsic
#define HInfravision u.uprops[INFRAVISION].intrinsic
#define HInvis u.uprops[INVIS].intrinsic
#define HJumping u.uprops[JUMPING].intrinsic
#define HLevitation u.uprops[LEVITATION].intrinsic
#define HMagical_breathing u.uprops[MAGICAL_BREATHING].intrinsic
#define HPasses_walls u.uprops[PASSES_WALLS].intrinsic
#define HPoison_resistance u.uprops[POISON_RES].intrinsic
#define HPolymorph u.uprops[POLYMORPH].intrinsic
#define HPolymorph_control u.uprops[POLYMORPH_CONTROL].intrinsic
#define HProtection u.uprops[PROTECTION].intrinsic
#define HProtection_from_shape_changers \
    u.uprops[PROT_FROM_SHAPE_CHANGERS].intrinsic
#define HReflecting u.uprops[REFLECTING].intrinsic
#define HRegeneration u.uprops[REGENERATION].intrinsic
#define HSearching u.uprops[SEARCHING].intrinsic
#define HSee_invisible u.uprops[SEE_INVIS].intrinsic
#define HShock_resistance u.uprops[SHOCK_RES].intrinsic
#define HSick_resistance u.uprops[SICK_RES].intrinsic
#define HSleep_resistance u.uprops[SLEEP_RES].intrinsic
#define HSleepy u.uprops[SLEEPY].intrinsic
#define HSlow_digestion u.uprops[SLOW_DIGESTION].intrinsic
#define HStealth u.uprops[STEALTH].intrinsic
#define HStone_resistance u.uprops[STONE_RES].intrinsic
#define HStun u.uprops[STUNNED].intrinsic 
#define HSwimming u.uprops[SWIMMING].intrinsic
#define HTelepat u.uprops[TELEPAT].intrinsic
#define HTeleport_control u.uprops[TELEPORT_CONTROL].intrinsic
#define HTeleportation u.uprops[TELEPORT].intrinsic
#define HUnchanging u.uprops[UNCHANGING].intrinsic
#define HUndead_warning u.uprops[WARN_UNDEAD].intrinsic
#define HWarn_of_mon u.uprops[WARN_OF_MON].intrinsic
#define HWarning u.uprops[WARNING].intrinsic
#define HWounded_legs u.uprops[WOUNDED_LEGS].intrinsic
#define Half_physical_damage (HHalf_physical_damage || EHalf_physical_damage)
#define Half_spell_damage (HHalf_spell_damage || EHalf_spell_damage)
#define Halluc_resistance (HHalluc_resistance || EHalluc_resistance)
#define Hallucination (HHallucination && !Halluc_resistance)
#define Hate_silver (u.ulycn >= LOW_PM || hates_silver(youmonst.data))
#define Hunger (HHunger || EHunger)
#define Infravision (HInfravision || EInfravision)
#define Invis ((HInvis || EInvis) && !BInvis)
#define Invisible (Invis && !See_invisible)
#define Invulnerable u.uprops[INVULNERABLE].intrinsic 
#define Jumping (HJumping || EJumping)
#define Lev_at_will                                                    \
    (((HLevitation & I_SPECIAL) != 0L || (ELevitation & W_ARTI) != 0L) \
     && (HLevitation & ~(I_SPECIAL | TIMEOUT)) == 0L                   \
     && (ELevitation & ~W_ARTI) == 0L)
#define Levitation ((HLevitation || ELevitation) && !BLevitation)
#define Lifesaved u.uprops[LIFESAVED].extrinsic
#define Passes_walls (HPasses_walls || EPasses_walls)
#define Poison_resistance (HPoison_resistance || EPoison_resistance)
#define Polymorph (HPolymorph || EPolymorph)
#define Polymorph_control (HPolymorph_control || EPolymorph_control)
#define Protection (HProtection || EProtection)
#define Protection_from_shape_changers \
    (HProtection_from_shape_changers || EProtection_from_shape_changers)
#define Punished (uball != 0)
#define Reflecting (HReflecting || EReflecting)
#define Regeneration (HRegeneration || ERegeneration)
#define Searching (HSearching || ESearching)
#define See_invisible (HSee_invisible || ESee_invisible)
#define Shock_resistance (HShock_resistance || EShock_resistance)
#define Sick u.uprops[SICK].intrinsic
#define Sick_resistance (HSick_resistance || defends(AD_DISE, uwep))
#define Sleep_resistance (HSleep_resistance || ESleep_resistance)
#define Sleepy (HSleepy || ESleepy)
#define Slimed u.uprops[SLIMED].intrinsic 
#define Slow_digestion (HSlow_digestion || ESlow_digestion) 
#define Stealth ((HStealth || EStealth) && !BStealth)
#define Stone_resistance (HStone_resistance || EStone_resistance)
#define Stoned u.uprops[STONED].intrinsic
#define Strangled u.uprops[STRANGLED].intrinsic
#define Stunned HStun
#define Swimming \
    (HSwimming || ESwimming || (u.usteed && is_swimmer(u.usteed->data)))
#define Teleport_control (HTeleport_control || ETeleport_control)
#define Teleportation (HTeleportation || ETeleportation)
#define Unaware (multi < 0 && (unconscious() || is_fainted()))
#define Unblind_telepat (ETelepat)
#define Unchanging (HUnchanging || EUnchanging) 
#define Undead_warning (HUndead_warning)
#define Underwater (u.uinwater)
#define Very_fast ((HFast & ~INTRINSIC) || EFast)
#define Vomiting u.uprops[VOMITING].intrinsic
#define Warn_of_mon (HWarn_of_mon || EWarn_of_mon)
#define Warning (HWarning || EWarning)
#define Wounded_legs (HWounded_legs || EWounded_legs)
#define Wwalking (EWwalking && !Is_waterlevel(&u.uz))

#define maybe_polyd(if_so, if_not) (Upolyd ? (if_so) : (if_not))
#define FAST_SPEED 15
#define LOW_PM (NON_PM + 1)          
#define NATTK 6
#define NON_PM (-1)                  
#define NORMAL_SPEED 12 

#define SLOW_SPEED 9
#define SPECIAL_PM PM_LONG_WORM_TAIL 
#define VERY_FAST 24
#define VERY_SLOW 3
#define WT_HUMAN 1450
#define G_EXTINCT                       \
    0x0001 
#define G_FREQ 0x0007     
#define G_GENO 0x0020     
#define G_GENOD 0x0002 
#define G_GONE (G_GENOD | G_EXTINCT)
#define G_HELL 0x0400     
#define G_KNOWN 0x0004 
#define G_LGROUP 0x0040   
#define G_NOCORPSE 0x0010 
#define G_NOGEN 0x0200    
#define G_NOHELL 0x0800   
#define G_SGROUP 0x0080   
#define G_UNIQ 0x1000     
#define M1_ACID 0x08000000L        
#define M1_AMORPHOUS 0x00000004L   
#define M1_AMPHIBIOUS 0x00000200L  
#define M1_ANIMAL 0x00040000L      
#define M1_BREATHLESS 0x00000400L  
#define M1_CARNIVORE 0x20000000L   
#define M1_CLING 0x00000010L       
#define M1_CONCEAL 0x00000080L     
#define M1_FLY 0x00000001L         
#define M1_HERBIVORE 0x40000000L   
#define M1_HIDE 0x00000100L        
#define M1_HUMANOID 0x00020000L    
#define M1_METALLIVORE 0x80000000UL 
#define M1_MINDLESS 0x00010000L    
#define M1_NEEDPICK 0x00000040L    
#define M1_NOEYES 0x00001000L      
#define M1_NOHANDS 0x00002000L     
#define M1_NOHEAD 0x00008000L      
#define M1_NOLIMBS 0x00006000L     
#define M1_NOTAKE 0x00000800L      
#define M1_OMNIVORE 0x60000000L    
#define M1_OVIPAROUS 0x00400000L   
#define M1_POIS 0x10000000L        
#define M1_REGEN 0x00800000L       
#define M1_SEE_INVIS 0x01000000L   
#define M1_SLITHY 0x00080000L      
#define M1_SWIM 0x00000002L        
#define M1_THICK_HIDE 0x00200000L  
#define M1_TPORT 0x02000000L       
#define M1_TPORT_CNTRL 0x04000000L 
#define M1_TUNNEL 0x00000020L      
#define M1_UNSOLID 0x00100000L     
#define M1_WALLWALK 0x00000008L    
#define M2_COLLECT 0x40000000L      
#define M2_DEMON 0x00000100L        
#define M2_DOMESTIC 0x00400000L     
#define M2_DWARF 0x00000020L        
#define M2_ELF 0x00000010L          
#define M2_FEMALE 0x00020000L       
#define M2_GIANT 0x00002000L        
#define M2_GNOME 0x00000040L        
#define M2_GREEDY 0x10000000L       
#define M2_HOSTILE 0x00100000L      
#define M2_HUMAN 0x00000008L        
#define M2_JEWELS 0x20000000L       
#define M2_LORD 0x00000400L         
#define M2_MAGIC 0x80000000UL 
#define M2_MALE 0x00010000L         
#define M2_MERC 0x00000200L         
#define M2_MINION 0x00001000L       
#define M2_NASTY 0x02000000L        
#define M2_NEUTER 0x00040000L       
#define M2_NOPOLY 0x00000001L       
#define M2_ORC 0x00000080L          
#define M2_PEACEFUL 0x00200000L     
#define M2_PNAME 0x00080000L        
#define M2_PRINCE 0x00000800L       
#define M2_ROCKTHROW 0x08000000L    
#define M2_SHAPESHIFTER 0x00004000L 
#define M2_STALK 0x01000000L        
#define M2_STRONG 0x04000000L       
#define M2_UNDEAD 0x00000002L       
#define M2_WANDER 0x00800000L       
#define M2_WERE 0x00000004L         
#define M3_CLOSE 0x0080     
#define M3_COVETOUS 0x001f 
#define M3_DISPLACES 0x0400 
#define M3_INFRAVISIBLE 0x0200 
#define M3_INFRAVISION 0x0100  
#define M3_WAITFORU 0x0040  
#define M3_WAITMASK 0x00c0 
#define M3_WANTSALL 0x001f  
#define M3_WANTSAMUL 0x0001 
#define M3_WANTSARTI 0x0010 
#define M3_WANTSBELL 0x0002 
#define M3_WANTSBOOK 0x0004 
#define M3_WANTSCAND 0x0008 
#define MH_DWARF M2_DWARF
#define MH_ELF M2_ELF
#define MH_GNOME M2_GNOME
#define MH_HUMAN M2_HUMAN
#define MH_ORC M2_ORC

#define MR2_DISPLACED 0x1000 
#define MR2_FUMBLING 0x4000  
#define MR2_LEVITATE 0x0200  
#define MR2_MAGBREATH 0x0800 
#define MR2_SEE_INVIS 0x0100 
#define MR2_STRENGTH 0x2000  
#define MR2_WATERWALK 0x0400 
#define MR_ACID 0x40   
#define MR_COLD 0x02   
#define MR_DISINT 0x08 
#define MR_ELEC 0x10   
#define MR_FIRE 0x01   
#define MR_POISON 0x20 
#define MR_SLEEP 0x04  
#define MR_STONE 0x80  
#define MS_ANIMAL 13    
#define MS_ARREST 21    
#define MS_BARK 1       
#define MS_BOAST 39     
#define MS_BONES 16     
#define MS_BRIBE 28     
#define MS_BURBLE 13    
#define MS_BUZZ 8       
#define MS_CUSS 29      
#define MS_DJINNI 24    
#define MS_GROWL 4      
#define MS_GRUNT 9      
#define MS_GUARD 23     
#define MS_GUARDIAN 33  
#define MS_GURGLE 12    
#define MS_HISS 7       
#define MS_HUMANOID 20  
#define MS_IMITATE 19   
#define MS_LAUGH 17     
#define MS_LEADER 31    
#define MS_MEW 2        
#define MS_MUMBLE 18    
#define MS_NEIGH 10     
#define MS_NEMESIS 32   
#define MS_NURSE 25     
#define MS_ORACLE 35    
#define MS_ORC MS_GRUNT 
#define MS_PRIEST 36    
#define MS_RIDER 30     
#define MS_ROAR 3       
#define MS_SEDUCE 26    
#define MS_SELL 34      
#define MS_SHRIEK 15    
#define MS_SILENT 0     
#define MS_SOLDIER 22   
#define MS_SPELL 37     
#define MS_SQAWK 6      
#define MS_SQEEK 5      
#define MS_VAMPIRE 27   
#define MS_WAIL 11      
#define MS_WERE 38      
#define MV_KNOWS_EGG                        \
    0x0008 
#define MZ_GIGANTIC 7      
#define MZ_HUGE 4          
#define MZ_HUMAN MZ_MEDIUM 
#define MZ_LARGE 3         
#define MZ_MEDIUM 2        
#define MZ_SMALL 1         
#define MZ_TINY 0          
#define AD_ACID 8   
#define AD_ANY (-1) 
#define AD_BLND 11  
#define AD_CLRC 240 
#define AD_COLD 3   
#define AD_CONF 25  
#define AD_CORR 42  
#define AD_CURS 253 
#define AD_DCAY 34  
#define AD_DETH 37  
#define AD_DGST 26  
#define AD_DISE 33  
#define AD_DISN 5   
#define AD_DRCO 31  
#define AD_DRDX 30  
#define AD_DREN 16  
#define AD_DRIN 32  
#define AD_DRLI 15  
#define AD_DRST 7   
#define AD_ELEC 6   
#define AD_ENCH 41  
#define AD_FAMN 39  
#define AD_FIRE 2   
#define AD_HALU 36  
#define AD_HEAL 27  
#define AD_LEGS 17  
#define AD_MAGM 1   
#define AD_PEST 38  
#define AD_PHYS 0   
#define AD_PLYS 14  
#define AD_RBRE 242 
#define AD_RUST 24  
#define AD_SAMU 252 
#define AD_SEDU 22  
#define AD_SGLD 20  
#define AD_SITM 21  
#define AD_SLEE 4   
#define AD_SLIM 40  
#define AD_SLOW 13  
#define AD_SPC1 9   
#define AD_SPC2 10  
#define AD_SPEL 241 
#define AD_SSEX 35  
#define AD_STCK 19  
#define AD_STON 18  
#define AD_STUN 12  
#define AD_TLPT 23  
#define AD_WERE 29  
#define AD_WRAP 28  
#define AT_ANY (-1) 
#define AT_BITE 2   
#define AT_BOOM 14  
#define AT_BREA 12  
#define AT_BUTT 4   
#define AT_CLAW 1   
#define AT_ENGL 11  
#define AT_EXPL 13  
#define AT_GAZE 15  
#define AT_HUGS 7   
#define AT_KICK 3   
#define AT_MAGC 255 
#define AT_NONE 0   
#define AT_SPIT 10  
#define AT_STNG 6   
#define AT_TENT 16  
#define AT_TUCH 5   
#define AT_WEAP 254 
#define MM_AGR_DIED 0x4 
#define MM_DEF_DIED 0x2 
#define MM_HIT 0x1      
#define MM_MISS 0x0     

#define ALLOW_COUNT (MAXOCLASSES + 1) 
#define ALLOW_NONE  (MAXOCLASSES + 3)
#define ALL_CLASSES (MAXOCLASSES + 2) 
#define AMULET_SYM '"'
#define ARMOR_SYM '['
#define BALL_SYM '0'
#define BURNING_OIL (MAXOCLASSES + 1) 
#define CHAIN_SYM '_'
#define FOOD_SYM '%'
#define GEM_SYM '*'
#define GOLD_SYM '$'
#define ILLOBJ_SYM ']' 
#define IMMEDIATE 2 
#define MON_EXPLODE (MAXOCLASSES + 2) 
#define NODIR 1     

#define OBJ_DESCR(obj) (obj_descr[(obj).oc_descr_idx].oc_descr)
#define OBJ_NAME(obj) (obj_descr[(obj).oc_name_idx].oc_name)
#define PIERCE 1 
#define POTION_SYM '!'
#define RAY 3       
#define RING_SYM '='
#define ROCK_SYM '`'
#define SCROLL_SYM '?'
#define SLASH 2  
#define SPBOOK_SYM '+'
#define TOOL_SYM '('
#define VENOM_SYM '.'
#define WAND_SYM '/'
#define WEAPON_SYM ')'
#define WHACK 0
#define a_ac oc_oc1     
#define a_can oc_oc2    
#define dealloc_fruit(rind) free((genericptr_t)(rind))
#define is_corrodeable(otmp)                   \
    (objects[otmp->otyp].oc_material == COPPER \
     || objects[otmp->otyp].oc_material == IRON)
#define is_damageable(otmp)                                        \
    (is_rustprone(otmp) || is_flammable(otmp) || is_rottable(otmp) \
     || is_corrodeable(otmp))
#define is_metallic(otmp)                    \
    (objects[otmp->otyp].oc_material >= IRON \
     && objects[otmp->otyp].oc_material <= MITHRIL)
#define is_organic(otmp) (objects[otmp->otyp].oc_material <= WOOD)
#define is_rustprone(otmp) (objects[otmp->otyp].oc_material == IRON)
#define newfruit() (struct fruit *) alloc(sizeof(struct fruit))
#define oc_armcat oc_subtyp 
#define oc_bimanual oc_big 
#define oc_bulky oc_big    
#define oc_hitbon oc_oc1 
#define oc_level oc_oc2 
#define oc_skill oc_subtyp  
#define ANY_SHOP (-2)
#define ANY_TYPE (-1)
#define D_SCATTER 0   
#define D_SHOP 1      
#define D_TEMPLE 2    
#define IS_LAST_ROOM_PTR(x) (ROOM_INDEX(x) == nroom)
#define IS_LAST_SUBROOM_PTR(x) (!nsubroom || SUBROOM_INDEX(x) == nsubroom)
#define IS_ROOM_INDEX(x)    ((x) >= 0 && (x) < MAXNROFROOMS)
#define IS_ROOM_PTR(x)      ((x) >= rooms && (x) < rooms + MAXNROFROOMS)
#define IS_SUBROOM_INDEX(x) ((x) > MAXNROFROOMS && (x) < (MAXNROFROOMS * 2))
#define IS_SUBROOM_PTR(x)   ((x) >= subrooms && (x) < subrooms + MAXNROFROOMS)
#define MAXRTYPE (CANDLESHOP) 

#define NO_ROOM     0 
#define ROOMOFFSET  3 
#define ROOM_INDEX(x)       ((x) -rooms)
#define SHARED      1 
#define SHARED_PLUS 2 
#define SUBROOM_INDEX(x)    ((x) -subrooms)
#define UNIQUESHOP (CANDLESHOP) 
#define DEF_ANGEL       'A'
#define DEF_ANT         'a'
#define DEF_BAT         'B'
#define DEF_BLOB        'b'
#define DEF_CENTAUR     'C'
#define DEF_COCKATRICE  'c'
#define DEF_DEMON       '&'
#define DEF_DOG         'd'
#define DEF_DRAGON      'D'
#define DEF_EEL         ';'
#define DEF_ELEMENTAL   'E'
#define DEF_EYE         'e'
#define DEF_FELINE      'f'
#define DEF_FUNGUS      'F'
#define DEF_GHOST       ' '
#define DEF_GIANT       'H'
#define DEF_GNOME       'G'
#define DEF_GOLEM       '\''
#define DEF_GREMLIN     'g'
#define DEF_HUMAN       '@'
#define DEF_HUMANOID    'h'
#define DEF_IMP         'i'
#define DEF_INVISIBLE   'I'
#define DEF_JABBERWOCK  'J'
#define DEF_JELLY       'j'
#define DEF_KOBOLD      'k'
#define DEF_KOP         'K'
#define DEF_LEPRECHAUN  'l'
#define DEF_LICH        'L'
#define DEF_LIGHT       'y'
#define DEF_LIZARD      ':'
#define DEF_MIMIC       'm'
#define DEF_MIMIC_DEF   ']'
#define DEF_MUMMY       'M'
#define DEF_NAGA        'N'
#define DEF_NYMPH       'n'
#define DEF_OGRE        'O'
#define DEF_ORC         'o'
#define DEF_PIERCER     'p'
#define DEF_PUDDING     'P'
#define DEF_QUADRUPED   'q'
#define DEF_QUANTMECH   'Q'
#define DEF_RODENT      'r'
#define DEF_RUSTMONST   'R'
#define DEF_SNAKE       'S'
#define DEF_SPIDER      's'
#define DEF_TRAPPER     't'
#define DEF_TROLL       'T'
#define DEF_UMBER       'U'
#define DEF_UNICORN     'u'
#define DEF_VAMPIRE     'V'
#define DEF_VORTEX      'v'
#define DEF_WORM        'w'
#define DEF_WORM_TAIL   '~'
#define DEF_WRAITH      'W'
#define DEF_XAN         'x'
#define DEF_XORN        'X'
#define DEF_YETI        'Y'
#define DEF_ZOMBIE      'Z'
#define DEF_ZRUTY       'z'

#define ACTIVE 1
#define Amask2msa(x) ((x) == 4 ? 3 : (x) &AM_MASK)
#define BR_NO_END1 1 
#define BR_NO_END2 2 
#define BR_PORTAL 3  
#define BR_STAIR 0   

#define FORGOTTEN 0x02    
#define FROMPERM 1 
#define In_endgame(x) ((x)->dnum == astral_level.dnum)
#define In_sokoban(x) ((x)->dnum == sokoban_dnum)
#define Inhell In_hell(&u.uz) 
#define Is_airlevel(x)      (Lcheck(x, &air_level))
#define Is_asmo_level(x)    (Lcheck(x, &asmodeus_level))
#define Is_astralevel(x)    (Lcheck(x, &astral_level))
#define Is_baal_level(x)    (Lcheck(x, &baalzebub_level))
#define Is_bigroom(x)       (Lcheck(x, &bigroom_level))
#define Is_earthlevel(x)    (Lcheck(x, &earth_level))
#define Is_firelevel(x)     (Lcheck(x, &fire_level))
#define Is_juiblex_level(x) (Lcheck(x, &juiblex_level))
#define Is_knox(x)          (Lcheck(x, &knox_level))
#define Is_medusa_level(x)  (Lcheck(x, &medusa_level))
#define Is_mineend_level(x) (Lcheck(x, &mineend_level))
#define Is_nemesis(x)       (Lcheck(x, &nemesis_level))
#define Is_oracle_level(x)  (Lcheck(x, &oracle_level))
#define Is_portal_level(x)  (Lcheck(x, &portal_level))
#define Is_qlocate(x)       (Lcheck(x, &qlocate_level))
#define Is_qstart(x)        (Lcheck(x, &qstart_level))
#define Is_rogue_level(x)   (Lcheck(x, &rogue_level))
#define Is_sanctum(x)       (Lcheck(x, &sanctum_level))
#define Is_sokoend_level(x) (Lcheck(x, &sokoend_level))
#define Is_stronghold(x)    (Lcheck(x, &stronghold_level))
#define Is_valley(x)        (Lcheck(x, &valley_level))
#define Is_waterlevel(x)    (Lcheck(x, &water_level))
#define Is_wiz1_level(x)    (Lcheck(x, &wiz1_level))
#define Is_wiz2_level(x)    (Lcheck(x, &wiz2_level))
#define Is_wiz3_level(x)    (Lcheck(x, &wiz3_level))
#define LFILE_EXISTS 0x04 
#define Lassigned(y) ((y)->dlevel || (y)->dnum)
#define Lcheck(x,z) (Lassigned(z) && on_level(x, z))
#define MIGR_APPROX_XY 1 
#define MIGR_EXACT_XY 2  
#define MIGR_LADDER_DOWN 6
#define MIGR_LADDER_UP 5
#define MIGR_LEFTOVERS 8192  
#define MIGR_NOBREAK 1024   
#define MIGR_NOSCATTER 2048 
#define MIGR_NOWHERE (-1) 
#define MIGR_PORTAL 8       
#define MIGR_RANDOM 0
#define MIGR_SSTAIRS 7      
#define MIGR_STAIRS_DOWN 4
#define MIGR_STAIRS_UP 3
#define MIGR_TO_SPECIES 4096  
#define MIGR_WITH_HERO 9    
#define MSA_CHAOTIC 3
#define MSA_LAWFUL 1
#define MSA_NEUTRAL 2
#define MSA_NONE 0 
#define Msa2amask(x) ((x) == 3 ? 4 : (x))
#define SWAPPED 2
#define TOPERM 2   
#define VISITED 0x01      
#define within_bounded_area(X, Y, LX, LY, HX, HY) \
    ((X) >= (LX) && (X) <= (HX) && (Y) >= (LY) && (Y) <= (HY))


#define crtdebug(stmt)                  \
    do {                                \
        if (showdebug("__FILE__")) {      \
            stmt;                       \
        }                               \
        _RPT0(_CRT_WARN, "\n");         \
    } while (0)
#define debugpline0(str) crtdebug(_RPT0(_CRT_WARN, str))
#define debugpline1(fmt, arg) crtdebug(_RPT1(_CRT_WARN, fmt, arg))
#define debugpline2(fmt, a1, a2) crtdebug(_RPT2(_CRT_WARN, fmt, a1, a2))
#define debugpline3(fmt, a1, a2, a3) \
    crtdebug(_RPT3(_CRT_WARN, fmt, a1, a2, a3))
#define debugpline4(fmt, a1, a2, a3, a4) \
    crtdebug(_RPT4(_CRT_WARN, fmt, a1, a2, a3, a4))
#define explicitdebug(file) debugcore(file, FALSE)
#define ifdebug(stmt)                   \
    do {                                \
        if (showdebug("__FILE__")) {      \
            stmt;                       \
        }                               \
    } while (0)
#define nhStr(str) ((char *) str)
#define nhUse(arg) 
#define showdebug(file) debugcore(file, TRUE)
#define AMII_GRAPHICS             
#define BEOS_GRAPHICS             
#define BITFIELDS 
#define CHDIR 
#define CLIPPING 
#define COMPRESS "/usr/bin/compress" 
#define COMPRESS_EXTENSION ".Z"      
# define CONFIG_ERROR_SECURE TRUE

#define DEFAULT_WC_TILED_MAP 
#define DEFAULT_WINDOW_SYS "Gnome"
#define DOAGAIN '\001' 
#define DUMPLOG_FILE        "/tmp/nethack.%n.%d.log"
#define DUMPLOG_MSG_COUNT   50
#define ENTRYMAX 100 
#define FREE_ALL_MEMORY             
#define GDBPATH "/usr/bin/gdb"
#define GEM_GRAPHICS             
#define GRAPHIC_TOMBSTONE 
#define GREPPATH "/bin/grep"
#define HACKDIR "\\nethack"
#define INSURANCE 
#define LOGFILE  "logfile"  
#define MACRO_CPATH 
#define NEWS     "news"     
#define PANICLOG "paniclog" 
#define PERSMAX 3 
#define PERS_IS_UID 1 
#define POINTSMIN 1 
#define STATUS_HILITES         
#define SYSCF                
#define SYSCF_FILE "sysconf" 
#define TTY_GRAPHICS 
#define UNIX 
#define USER_SOUNDS 
#define USE_ISAAC64 
#  define USE_TILES
#define USE_XPM           
#define WIZARD_NAME "wizard" 
#define XLOGFILE "xlogfile" 
#define schar char
#define ALIGNWEIGHT 4 
#define BOGUSMONFILE "bogusmon" 
#define BUFSZ 256  
#define Bitfield(x, n) unsigned x : n
#define CMDHELPFILE "cmdhelp"   
#define COLNO 80
#define DATAFILE "data"         

#define DEBUGHELP "wizhelp"     
#define DOORMAX 120     
#define ENGRAVEFILE "engrave"   
#define EPITAPHFILE "epitaph"   
#define EXIT_FAILURE 1
#define EXIT_SUCCESS 0
#define FALSE ((boolean) 0)


#define HELP "help"             
#define HISTORY "history"       
#define KEYHELP "keyhelp"       
#define LARGEST_INT 32767
#define LEV_EXT ".lev"          
#define LICENSE "license"       
#define MAXDUNGEON 16 
#define MAXLEVEL 32   
#define MAXMONNO 120 
#define MAXNROFROOMS 40 
#define MAXSTAIRS 1   
#define MAXULEV 30 
#define MAX_SUBROOMS 24 
#define MHPMAX 500   
#define NH_DEVEL_STATUS NH_STATUS_RELEASED
#define NH_STATUS_BETA        2         
#define NH_STATUS_POSTRELEASE 3         
#define NH_STATUS_RELEASED    0         
#define NH_STATUS_WIP         1         
#define OPTIONFILE "opthelp"    
#define OPTIONS_USED "options"  
#define ORACLEFILE "oracles"    



#define PL_CSIZ 32 
#define PL_FSIZ 32 
#define PL_NSIZ 32 
#define PL_PSIZ 63 
#define PORT_ID "Amiga"
#define PORT_SUB_ID "djgpp"
#define QBUFSZ 128 
#define RECORD "record"         
#define RLECOMP  
#define ROWNO 21
#define RUMORFILE "rumors"      
#define SFI1_EXTERNALCOMP (1UL)
#define SFI1_RLECOMP (1UL << 1)
#define SFI1_ZEROCOMP (1UL << 2)
#define SHELP "hh"              
#define SHORT_FILENAMES 
#define SIZE(x) (int)(sizeof(x) / sizeof(x[0]))

#define SYMBOLS "symbols"       
#define Sprintf (void) sprintf
#define Strcat (void) strcat
#define Strcpy (void) strcpy
#define TBUFSZ 300 
#define TRIBUTEFILE "tribute"   
#define TRUE ((boolean) 1)
#define Vfprintf (void) vfprintf
#define Vprintf (void) vprintf
#define Vsprintf (void) vsprintf
#define ZEROCOMP 


#define alloc(a) nhalloc(a, "__FILE__", (int) "__LINE__")
#define dupstr(s) nhdupstr(s, "__FILE__", (int) "__LINE__")
#define free(a) nhfree(a, "__FILE__", (int) "__LINE__")
#define nethack_enter(argc, argv) ((void) 0)
#define strcmpi(a, b) strncmpi((a), (b), -1)
#define ABORT C('a')
#define ALLOCA_HACK 

#define C(c) (0x1f & (c))
#define CONFIG_FILE ".nethackrc"
#define CONFIG_TEMPLATE ".nethackrc.template"
#define DUMPLOG      
#define EXEPATH              
#define FCMASK (_S_IREAD | _S_IWRITE) 
#define FILENAME BUFSZ 
#define GUIDEBOOK_FILE "Guidebook.txt"
#define HAS_STDINT_H    
#define HLOCK "NHPERM"
#define HOLD_LOCKFILE_OPEN 
#define INTERJECTION_TYPES (INTERJECT_PANIC + 1)
#define INTERJECT_PANIC 0
#define LAN_FEATURES 
#define LEFTBUTTON FROM_LEFT_1ST_BUTTON_PRESSED
#define M(c) ((char) (0x80 | (c)))
#define MAX_LAN_USERNAME 20
#define MIDBUTTON FROM_LEFT_2ND_BUTTON_PRESSED
#define MOUSEMASK (LEFTBUTTON | RIGHTBUTTON | MIDBUTTON)
#define NOCWD_ASSUMPTIONS 



#define OPTIONS_FILE OPTIONS_USED
#define PATHLEN BUFSZ  
#define PC_LOCKING 
#define PORT_DEBUG 
#define PORT_HELP "porthelp"

#define RIGHTBUTTON RIGHTMOST_BUTTON_PRESSED

#define RUNTIME_PORT_ID 
#define Rand() random()
#define SAFERHANGUP 
#define SELECTSAVED 
#define SELF_RECOVER 
#define SYMBOLS_TEMPLATE "symbols.template"
#define SYSCF_TEMPLATE "sysconf.template"
#define TEXTCOLOR 
#define TRADITIONAL_GLYPHMAP 

#define VERSION_IN_DLB_FILENAME     



#define index strchr
#define kbhit (*nt_kbhit)
#define nhassert(expression) ((void)0)
#define regularize nt_regularize
#define rindex strrchr
#define snprintf _snprintf
#define strncmpi(a, b, c) strnicmp(a, b, c)
#define BUFSIZ 255
#define DeleteFile(a) unlink(a)
#define NHSTR_BUFSIZE 255
#define NH_A2W(a, w, cb) \
    (MultiByteToWideChar(CP_ACP, 0, (a), -1, (w), (cb)), (w))
#define NH_W2A(w, a, cb) \
    (WideCharToMultiByte(CP_ACP, 0, (w), -1, (a), (cb), NULL, NULL), (a))
#define NOTSTDC 
#define PORT_CE_CPU "ALPHA"
#define PORT_CE_PLATFORM "Pocket PC"
#define S_IREAD GENERIC_READ
#define S_IWRITE GENERIC_WRITE

#define WIN32_LEAN_AND_MEAN 




#define ZeroMemory(p, s) memset((p), 0, (s))
#define _TIME_T_DEFINED 

#define abort() (void) TerminateProcess(GetCurrentProcess(), 0)
#define freopen(a, b, c) fopen(a, b)
#define getenv(a) ((char *) NULL)

#define interject_assistance(_1, _2, _3, _4)

#define rewind(stream) (void) fseek(stream, 0L, SEEK_SET)
#define strdup _strdup
#define stricmp(a, b) _stricmp(a, b)


#define SIG_RET_TYPE __signal_func_ptr
#define tgetch getchar
#define BONE_TYPE 'BONE'

#define DATA_TYPE 'DATA'
#define LEVL_TYPE 'LEVL'
#define MAC68K 

#define MAC_CREATOR 'nh31'  

#define PREF_TYPE 'PREF'
#define SAVE_TYPE 'SAVE'
#define TARGET_API_MAC_CARBON 0
#define TEXT_CREATOR 'ttxt' 
#define TEXT_TYPE 'TEXT'
#define YY_NEVER_INTERACTIVE 1


#define close macclose
#define creat maccreat
#define getpid() 1
#define lseek macseek
#define open macopen
#define read macread
#define unlink _unlink
#define write macwrite

#define AMIFLUSH 
#define AMIGA_INTUITION 
#define AMII_LOUDER_VOLUME 80
#define AMII_MAXCOLORS (1L << DEPTH)
#define AMII_MUFFLED_VOLUME 40
#define AMII_OKAY_VOLUME 60
#define AMII_SOFT_VOLUME 50

#define AZTEC_C_WORKAROUND 
#define DCC30_BUG 
#define DEFAULT_ICON "NetHack:default.icon" 
#define DEPTH 6 
#define DLBFILE2 "NetHack:nhsdat" 
#define FromWBench 0 
#define HACKFONT  
#define INTUI_NEW_LOOK 1
#define MAIL      
#define MFLOPPY 
#define MICRO 
#define O_BINARY 0
#define SHELL     

#define msmsg printf
#define remove(x) unlink(x)
#define MOVERLAY 


#define PCMUSIC 


#define SCREEN_BIOS 

#define SCREEN_VGA 


#define STKSIZ 5 * 1024 
#define TIMED_DELAY 


#define VROOMM 

#define lock djlock
#define msleep(k) (void) usleep((k) *1000)
#define vfprintf fprintf
#define vprintf printf
#define vsprintf sprintf



#define chdir _chdir
#define getcwd _getcwd
#define off_t long
#define seteuid(x) setreuid(-1, (x));
#define setmode _setmode
#define time_t long

#define GCC_BUG 
#define MINT 

#define SUSPEND 

#define TERMLIB   


#define OS2_32BITAPI 
#define OS2_GCC 
#define OS2_USESYSHEADERS 
#define sethanguphandler(foo) (void) signal(SIGHUP, (SIG_RET_TYPE) foo)
#define ALTMETA 
#define AMS_MAILBOX "/Mailbox"


#define DEF_MAILREADER "/usr/bin/mail"
#  define DEV_RANDOM "/dev/random"

#define LINUX    
#define MAILCKFREQ 50
#define NETWORK        
#define POSIX_JOB_CONTROL 
#define SERVER_ADMIN_MSG_CKFREQ 25
#define SVR4           
#define SYSV         
#define TERMINFO       





#define __HC__ hc
#define memcmp(s1, s2, n) bcmp(s2, s1, n)
#define memcpy(d, s, n) bcopy(s, d, n)
#define msleep(k) usleep((k) *1000)
#define An vms_an
#define C$$TRANSLATE(n) c__translate(n) 

#define DLB 

#define Local_HACKDIR "DISK$USERS:[GAMES.NETHACK.3_5_X.PLAY]\0\0\0\0\0\0\0\0"
#define Local_WIZARD "NHWIZARD\0\0\0\0"
#define O_CREAT 0x200
#define O_RDONLY 0
#define O_RDWR 2
#define O_TRUNC 0x400
#define O_WRONLY 1
#define STRICT_REF_DEF 
#define Shk_Your vms_shk_your
#define The vms_the
#define USE_QIO_INPUT 





#define alloca __builtin_alloca
#define bcopy(s, d, n) memcpy((d), (s), (n)) 
#define exit(sts) vms_exit(sts)         
#define fopen(f, m) vms_fopen(f, m)     
#  define initstate nh_initstate
#define link(f1, f2) vms_link(f1, f2)   
#define ospeed vms_ospeed
#  define random nh_random
#  define setstate nh_setstate
#  define srandom nh_srandom

#define ALIGNTYP_P aligntyp
#define BOOLEAN_P boolean
#define CHAR_P char
#define FDECL(f, p) f p

#define MONST_P void *

#define NORETURN __attribute__((noreturn))

#define OBJ_P void *
#define PRINTF_F(f, v) __attribute__((format(printf, f, v)))
#define SCHAR_P schar
#define SHORT_P short

#define UCHAR_P unsigned int
#define UNUSED __attribute__((unused))



#define VA_ARGS the_args
#define VA_DECL(typ1, var1) \
    (va_alist) va_dcl       \
    {                       \
        va_list the_args;   \
        typ1 var1;
#define VA_DECL2(typ1, var1, typ2, var2) \
    (va_alist) va_dcl                    \
    {                                    \
        va_list the_args;                \
        typ1 var1;                       \
        typ2 var2;
#define VA_END()      \
    va_end(the_args); \
    }
#define VA_INIT(var1, typ1) var1 = va_arg(the_args, typ1)
#define VA_NEXT(var1, typ1) (var1 = va_arg(the_args, typ1))
#define VA_PASS1(a1) a1
#define VA_SHIFT()                                                    \
    (arg1 = arg2, arg2 = arg3, arg3 = arg4, arg4 = arg5, arg5 = arg6, \
     arg6 = arg7, arg7 = arg8, arg8 = arg9, arg9 = 0)
#define VA_START(x) va_start(the_args, x)

#define VDECL(f, p) f p
#define VOID_ARGS void

#define XCHAR_P xchar
#define _VA_LIST_ 

#define __LANGUAGE_C LANGUAGE_C
#define __mips mips
#define __warn_unused_result__ 

#define genericptr void *
#define genericptr_t genericptr

#define void int

#define warn_unused_result 
#define AMIGA    
#define AZTEC_50 


#define KR1ED       



#define NEARDATA __near 

#define NOTSTDC    





#define USE_OLDARGS 


#define _DECC_V4_SOURCE 

#define __MSC 


