#include<sys/signal.h>
#include<errno.h>
#include<sys/time.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/utsname.h>
#include<sys/unistd.h>




#include<sys/ioctl.h>
#include<syslog.h>

#include<sys/wait.h>
#include<sys/file.h>
#include<sys/cdefs.h>
#include<fcntl.h>
#include<netinet/in.h>

#include<sgtty.h>

#include<sys/param.h>
#include<strings.h>
#include<string.h>
#include<sys/stat.h>

#define	DIR_DECRYPT		1
#define	DIR_ENCRYPT		2
#define	SK_DES		1	
#define Schedule DES_key_schedule
# define __ENCRYPTION__
#define	AUTH_OTHER	2	
#define	AUTH_REJECT	0	
#define	AUTH_UNKNOWN	1	
#define	AUTH_USER	3	
#define	AUTH_VALID	4	
#     define DEFAULT_IM  "\r\n\r\nFreeBSD (%h) (%t)\r\n\r\r\n\r"
#define	EXTERN	extern
#define FD_ZERO(p)	((p)->fds_bits[0] = 0)
#define	HIS_STATE_WILL			MY_STATE_DO
#define	HIS_WANT_STATE_WILL		MY_WANT_STATE_DO
#define	LOG_DAEMON	0
#define	LOG_ODELAY	0
#define	MY_STATE_DO		0x04
#define	MY_STATE_WILL		0x01
#define	MY_WANT_STATE_DO	0x08
#define	MY_WANT_STATE_WILL	0x02
#define	NETSLOP	64
#define	NO_AUTOKLUDGE	0x02
#define	TD_OPTIONS	0x10	
#define	TD_REPORT	0x01	


#  define _POSIX_VDISABLE VDISABLE
#define	his_state_is_do			my_state_is_will
#define	his_state_is_dont		my_state_is_wont
#define	his_state_is_will		my_state_is_do
#define	his_state_is_wont		my_state_is_dont
#define my_do_dont_is_changing(opt) \
			((options[opt]+MY_STATE_DO) & MY_WANT_STATE_DO)
#define my_want_state_is_do(opt)	(options[opt]&MY_WANT_STATE_DO)
#define my_want_state_is_dont(opt)	(!my_want_state_is_do(opt))
#define my_want_state_is_will(opt)	(options[opt]&MY_WANT_STATE_WILL)
#define my_want_state_is_wont(opt)	(!my_want_state_is_will(opt))
#define my_will_wont_is_changing(opt) \
			((options[opt]+MY_STATE_WILL) & MY_WANT_STATE_WILL)
#define	set_his_state_do		set_my_state_will
#define	set_his_state_dont		set_my_state_wont
#define	set_his_state_will		set_my_state_do
#define	set_his_state_wont		set_my_state_dont
#define	set_his_want_state_do		set_my_want_state_will
#define	set_his_want_state_dont		set_my_want_state_wont
#define	set_his_want_state_will		set_my_want_state_do
#define	set_his_want_state_wont		set_my_want_state_dont







#define XLOCALE_ISCTYPE(__fname, __cat) \
		_XLOCALE_INLINE int is##__fname##_l(int, locale_t); \
		_XLOCALE_INLINE int is##__fname##_l(int __c, locale_t __l)\
		{ return __sbistype_l(__c, __cat, __l); }

#define _XLOCALE_INLINE extern __inline
#define _XLOCALE_RUN_FUNCTIONS_DEFINED 1

#define _CurrentRuneLocale (__getCurrentRuneLocale())
#define AI_MASK \
    (AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_NUMERICSERV | \
    AI_ADDRCONFIG | AI_ALL | AI_V4MAPPED)

#define alloca(sz) __builtin_alloca(sz)
#define MB_CUR_MAX_L(x) ((size_t)___mb_cur_max_l(x))


#define	ABORT	238		
#define	AO	245		
#define	AUTHTYPE_CNT		7
#define	AUTHTYPE_KERBEROS_V4	1
#define	AUTHTYPE_KERBEROS_V5	2
#define	AUTHTYPE_MINK		4
#define	AUTHTYPE_NULL		0
#define	AUTHTYPE_SPX		3
#define	AUTHTYPE_SRA		6
#define	AUTHTYPE_TEST		99
#define	AUTH_HOW_MASK		2
#define	AUTH_HOW_MUTUAL		2
#define	AUTH_HOW_ONE_WAY	0
#define	AUTH_WHO_CLIENT		0	
#define	AUTH_WHO_MASK		1
#define	AUTH_WHO_SERVER		1	
#define	AYT	246		
#define	BREAK	243		
#define	COMPORT_SET_BAUDRATE	1	
#define	DM	242		
#define	DO	253		
#define	DONT	254		
#define	EC	247		
#define	EL	248		
#define	ENCRYPT_CNT		9
#define	ENCRYPT_DEC_KEYID	8
#define	ENCRYPT_ENC_KEYID	7
#define	ENCRYPT_END		4	
#define	ENCRYPT_IS		0	
#define	ENCRYPT_REPLY		2	
#define	ENCRYPT_REQEND		6	
#define	ENCRYPT_REQSTART	5	
#define	ENCRYPT_START		3	
#define	ENCRYPT_SUPPORT		1	
#define	ENCTYPE_ANY		0
#define	ENCTYPE_CNT		3
#define	ENCTYPE_DES_CFB64	1
#define	ENCTYPE_DES_OFB64	2
#define	ENV_ESC		2
#define EOR     239             
#define	GA	249		
#define	IAC	255		
#define	IP	244		
#define	LFLOW_OFF		0	
#define	LFLOW_ON		1	
#define	LFLOW_RESTART_ANY	2	
#define	LFLOW_RESTART_XON	3	
#define	LM_FORWARDMASK	2
#define	LM_MODE		1
#define	LM_SLC		3
#define	MODE_ACK	0x04
#define	MODE_EDIT	0x01
#define	MODE_MASK	0x1f
#define	MODE_TRAPSIG	0x02
#define	NEW_ENV_VALUE	1
#define	NEW_ENV_VAR	0
#define	NOP	241		
#define	NSLC		30
#define	NTELOPTS	(1+TELOPT_KERMIT)
#define	OLD_ENV_VALUE	0
#define	OLD_ENV_VAR	1
#define	SB	250		
#define	SE	240		
#define	SLC_ABORT	7
#define	SLC_ACK		0x80
#define	SLC_AO		4
#define	SLC_AYT		5
#define	SLC_BRK		2
#define	SLC_CANTCHANGE	1
#define	SLC_DEFAULT	3
#define SLC_EBOL        29
#define	SLC_EC		10
#define SLC_ECR         27
#define SLC_EEOL        30
#define	SLC_EL		11
#define	SLC_EOF		8
#define	SLC_EOR		6
#define	SLC_EW		12
#define SLC_EWR         28
#define	SLC_FLAGS	1
#define	SLC_FLUSHIN	0x40
#define	SLC_FLUSHOUT	0x20
#define	SLC_FORW1	17
#define	SLC_FORW2	18
#define	SLC_FUNC	0
#define SLC_INSRT       25
#define	SLC_IP		3
#define	SLC_LEVELBITS	0x03
#define	SLC_LNEXT	14
#define SLC_MCBOL       23
#define SLC_MCEOL       24
#define SLC_MCL         19
#define SLC_MCR         20
#define SLC_MCWL        21
#define SLC_MCWR        22
#define SLC_NAME(x)	slc_names[x]
#define	SLC_NAMELIST	"0", "SYNCH", "BRK", "IP", "AO", "AYT", "EOR",	\
			"ABORT", "EOF", "SUSP", "EC", "EL", "EW", "RP",	\
			"LNEXT", "XON", "XOFF", "FORW1", "FORW2",	\
			"MCL", "MCR", "MCWL", "MCWR", "MCBOL",		\
			"MCEOL", "INSRT", "OVER", "ECR", "EWR",		\
			"EBOL", "EEOL",					\
			0
#define	SLC_NOSUPPORT	0
#define SLC_OVER        26
#define	SLC_RP		13
#define	SLC_SUSP	9
#define	SLC_SYNCH	1
#define	SLC_VALUE	2
#define	SLC_VARIABLE	2
#define	SLC_XOFF	16
#define	SLC_XON		15
#define	SUSP	237		
#define	TELCMD_FIRST	xEOF
#define	TELCMD_LAST	IAC
#define	TELOPT_BM	19	
#define	TELOPT_CHARSET	42	
#define	TELOPT_COMPORT	44	
#define	TELOPT_DET	20	
#define	TELOPT_ENCRYPT	38	
#define	TELOPT_EOR	25	
#define	TELOPT_EXOPL	255	
#define	TELOPT_FIRST	TELOPT_BINARY
#define	TELOPT_KERMIT	47	
#define	TELOPT_LAST	TELOPT_KERMIT
#define	TELOPT_LFLOW	33	
#define	TELOPT_LOGOUT	18	
#define	TELOPT_NAMS	4	
#define TELOPT_NAOL 	8	
#define TELOPT_NAOP 	9	
#define	TELOPT_NAWS	31	
#define TELOPT_NEW_ENVIRON 39	
#define TELOPT_OLD_ENVIRON 36	
#define	TELOPT_OUTMRK	27	
#define	TELOPT_RCP	2	
#define	TELOPT_RCTE	7	
#define	TELOPT_SGA	3	
#define	TELOPT_SNDLOC	23	
#define	TELOPT_STATUS	5	
#define	TELOPT_SUPDUP	21	
#define	TELOPT_TM	6	
#define	TELOPT_TN3270E	40	
#define	TELOPT_TSPEED	32	
#define	TELOPT_TTYLOC	28	
#define	TELOPT_TTYPE	24	
#define	TELOPT_TUID	26	
#define	TELOPT_X3PAD	30	
#define	TELQUAL_INFO	2	
#define	TELQUAL_IS	0	
#define	TELQUAL_NAME	3	
#define	TELQUAL_REPLY	2	
#define	TELQUAL_SEND	1	
#define	WILL	251		
#define	WONT	252		
#define	xEOF	236		

#define LC_ALL_MASK      (LC_COLLATE_MASK | LC_CTYPE_MASK | LC_MESSAGES_MASK | \
			  LC_MONETARY_MASK | LC_NUMERIC_MASK | LC_TIME_MASK)
#define LC_COLLATE_MASK  (1<<0)
#define LC_CTYPE_MASK    (1<<1)
#define LC_GLOBAL_LOCALE ((locale_t)-1)
#define LC_MESSAGES_MASK (1<<5)
#define LC_MONETARY_MASK (1<<2)
#define LC_NUMERIC_MASK  (1<<3)
#define LC_TIME_MASK     (1<<4)
#define LC_VERSION_MASK  (1<<6)


