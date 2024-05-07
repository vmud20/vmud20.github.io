#include<poll.h>

#include<sys/mman.h>
#include<stdio.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<errno.h>
#include<getopt.h>
#include<ctype.h>




#include<time.h>
#include<unistd.h>
#include<stdbool.h>
#include<wordexp.h>



#include<assert.h>




#include<stdlib.h>
#include<string.h>
#include<stdarg.h>
#include<stdint.h>







#define _ATTRIB_PRINTF(start, end) __attribute__((format(printf, start, end)))

#define swaylock_log(verb, fmt, ...) \
	_swaylock_log(verb, "[%s:%d] " fmt, _swaylock_strip_path("__FILE__"), \
			"__LINE__", ##__VA_ARGS__)
#define swaylock_log_errno(verb, fmt, ...) \
	swaylock_log(verb, fmt ": %s", ##__VA_ARGS__, strerror(errno))

