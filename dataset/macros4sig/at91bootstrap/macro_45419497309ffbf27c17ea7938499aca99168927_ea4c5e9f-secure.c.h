


#define BOOTSTRAP_DEBUG_LEVEL 0
#define DEBUG_INFO        1
#define DEBUG_LOUD        2
#define DEBUG_VERY_LOUD   4

#define console_printf(fmt_str, args...) \
	dbg_printf(fmt_str , ## args)
#define dbg_info(fmt_str, arg...)		\
	dbg_log(DEBUG_INFO, fmt_str , ## arg)
#define dbg_log(level, fmt_str, args...) \
	({ \
		(level) <= BOOTSTRAP_DEBUG_LEVEL ? dbg_printf((fmt_str), ##args) : 0; \
	})
#define dbg_loud(fmt_str, arg...)		\
	dbg_log(DEBUG_LOUD, fmt_str , ## arg)
#define dbg_very_loud(fmt_str, arg...)		\
	dbg_log(DEBUG_VERY_LOUD, fmt_str , ## arg)
#define BAUDRATE(mck, baud) \
	(((((mck) * 10) / ((baud) * 16)) % 10) >= 5) ? \
	(mck / (baud * 16) + 1) : ((mck) / (baud * 16))



#define ALIGN(size, align)	(((size) + (align) - 1) & (~((align) - 1)))
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define OF_ALIGN(size)		ALIGN(size, 4)

#define max(a, b)	(((a) > (b)) ? (a) : (b))
#define min(a, b)	(((a) < (b)) ? (a) : (b))
