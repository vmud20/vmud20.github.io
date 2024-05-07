#include<stdint.h>
#include<sys/socket.h>
#include<unistd.h>
#include<sys/select.h>
#include<limits.h>
#include<time.h>
#include<assert.h>
#include<stdarg.h>
#include<netinet/tcp.h>
#include<ctype.h>

#include<sys/ioctl.h>
#include<signal.h>

#include<string.h>
#include<strings.h>
#include<sys/time.h>
#include<sys/types.h>
#include<math.h>
#include<netdb.h>
#include<float.h>
#include<stdio.h>
#include<netinet/in.h>



#include<stdlib.h>
#define BUF_CHUNK 65536 * 50
#define BUF_START 65536 * 100
#define ESL_DECLARE(type)			type __stdcall

#define ESL_DECLARE_NONSTD(type)		type __cdecl
#define ESL_LOG_ALERT ESL_PRE, ESL_LOG_LEVEL_ALERT
#define ESL_LOG_CRIT ESL_PRE, ESL_LOG_LEVEL_CRIT
#define ESL_LOG_DEBUG ESL_PRE, ESL_LOG_LEVEL_DEBUG
#define ESL_LOG_EMERG ESL_PRE, ESL_LOG_LEVEL_EMERG
#define ESL_LOG_ERROR ESL_PRE, ESL_LOG_LEVEL_ERROR
#define ESL_LOG_INFO ESL_PRE, ESL_LOG_LEVEL_INFO
#define ESL_LOG_LEVEL_ALERT 1
#define ESL_LOG_LEVEL_CRIT 2
#define ESL_LOG_LEVEL_DEBUG 7
#define ESL_LOG_LEVEL_EMERG 0
#define ESL_LOG_LEVEL_ERROR 3
#define ESL_LOG_LEVEL_INFO 6
#define ESL_LOG_LEVEL_NOTICE 5
#define ESL_LOG_LEVEL_WARNING 4
#define ESL_LOG_NOTICE ESL_PRE, ESL_LOG_LEVEL_NOTICE
#define ESL_LOG_WARNING ESL_PRE, ESL_LOG_LEVEL_WARNING
#define ESL_PRE "__FILE__", __FUNCTION__, "__LINE__"
#define ESL_SEQ_AND_COLOR ";"	
#define ESL_SEQ_BBLACK ESL_SEQ_ESC ESL_SEQ_B_BLACK ESL_SEQ_END_COLOR
#define ESL_SEQ_BBLUE ESL_SEQ_ESC ESL_SEQ_B_BLUE ESL_SEQ_END_COLOR
#define ESL_SEQ_BCYAN ESL_SEQ_ESC ESL_SEQ_B_CYAN ESL_SEQ_END_COLOR
#define ESL_SEQ_BGREEN ESL_SEQ_ESC ESL_SEQ_B_GREEN ESL_SEQ_END_COLOR
#define ESL_SEQ_BMAGEN ESL_SEQ_ESC ESL_SEQ_B_MAGEN ESL_SEQ_END_COLOR
#define ESL_SEQ_BRED ESL_SEQ_ESC ESL_SEQ_B_RED ESL_SEQ_END_COLOR
#define ESL_SEQ_BWHITE ESL_SEQ_ESC ESL_SEQ_B_WHITE ESL_SEQ_END_COLOR
#define ESL_SEQ_BYELLOW ESL_SEQ_ESC ESL_SEQ_B_YELLOW ESL_SEQ_END_COLOR
#define ESL_SEQ_B_BLACK "40"
#define ESL_SEQ_B_BLUE "44"
#define ESL_SEQ_B_CYAN "46"
#define ESL_SEQ_B_GREEN "42"
#define ESL_SEQ_B_MAGEN "45"
#define ESL_SEQ_B_RED "41"
#define ESL_SEQ_B_WHITE "47"
#define ESL_SEQ_B_YELLOW "43"
#define ESL_SEQ_CLEARLINE ESL_SEQ_ESC ESL_SEQ_CLEARLINE_CHAR_STR
#define ESL_SEQ_CLEARLINEEND ESL_SEQ_ESC ESL_SEQ_CLEARLINEEND_CHAR
#define ESL_SEQ_CLEARLINEEND_CHAR "K"
#define ESL_SEQ_CLEARLINE_CHAR '1'
#define ESL_SEQ_CLEARLINE_CHAR_STR "1"
#define ESL_SEQ_CLEARSCR ESL_SEQ_ESC ESL_SEQ_CLEARSCR_CHAR ESL_SEQ_HOME
#define ESL_SEQ_CLEARSCR_CHAR "2J"
#define ESL_SEQ_CLEARSCR_CHAR0 '2'
#define ESL_SEQ_CLEARSCR_CHAR1 'J'
#define ESL_SEQ_DEFAULT_COLOR ESL_SEQ_FWHITE
#define ESL_SEQ_END_COLOR "m"	
#define ESL_SEQ_ESC "\033["
#define ESL_SEQ_FBLACK ESL_SEQ_ESC ESL_SEQ_F_BLACK ESL_SEQ_END_COLOR
#define ESL_SEQ_FBLUE ESL_SEQ_ESC ESL_SEQ_F_BLUE ESL_SEQ_END_COLOR
#define ESL_SEQ_FCYAN ESL_SEQ_ESC ESL_SEQ_F_CYAN ESL_SEQ_END_COLOR
#define ESL_SEQ_FGREEN ESL_SEQ_ESC ESL_SEQ_F_GREEN ESL_SEQ_END_COLOR
#define ESL_SEQ_FMAGEN ESL_SEQ_ESC ESL_SEQ_F_MAGEN ESL_SEQ_END_COLOR
#define ESL_SEQ_FRED ESL_SEQ_ESC ESL_SEQ_F_RED ESL_SEQ_END_COLOR
#define ESL_SEQ_FWHITE ESL_SEQ_ESC ESL_SEQ_F_WHITE ESL_SEQ_END_COLOR
#define ESL_SEQ_FYELLOW ESL_SEQ_ESC ESL_SEQ_F_YELLOW ESL_SEQ_END_COLOR
#define ESL_SEQ_F_BLACK "30"
#define ESL_SEQ_F_BLUE "34"
#define ESL_SEQ_F_CYAN "36"
#define ESL_SEQ_F_GREEN "32"
#define ESL_SEQ_F_MAGEN "35"
#define ESL_SEQ_F_RED "31"
#define ESL_SEQ_F_WHITE "37"
#define ESL_SEQ_F_YELLOW "33"
#define ESL_SEQ_HOME ESL_SEQ_ESC ESL_SEQ_HOME_CHAR_STR
#define ESL_SEQ_HOME_CHAR 'H'
#define ESL_SEQ_HOME_CHAR_STR "H"
#define ESL_SOCK_INVALID INVALID_SOCKET
#define ESL_VA_NONE "%s", ""
#define HAVE_STRINGS_H 1
#define HAVE_SYS_SOCKET_H 1
#define S_IRUSR _S_IREAD
#define S_IWUSR _S_IWRITE



#define _XOPEN_SOURCE 600
#define __FUNCTION__ (const char *)__func__

#define __inline__ __inline
#define end_of(_s) *(*_s == '\0' ? _s : _s + strlen(_s) - 1)
#define esl_assert(expr) assert(expr);__analysis_assume( expr )
#define esl_clear_flag(obj, flag) (obj)->flags &= ~(flag)
#define esl_connect(_handle, _host, _port, _user, _password) esl_connect_timeout(_handle, _host, _port, _user, _password, 0)
#define esl_copy_string(_x, _y, _z) strncpy(_x, _y, _z - 1)
#define esl_recv(_h) esl_recv_event(_h, 0, NULL)
#define esl_recv_timed(_h, _ms) esl_recv_event_timed(_h, _ms, 0, NULL)
#define esl_safe_free(_x) if (_x) free(_x); _x = NULL
#define esl_send_recv(_handle, _cmd) esl_send_recv_timed(_handle, _cmd, 0)
#define esl_set_flag(obj, flag) (obj)->flags |= (flag)
#define esl_set_string(_x, _y) esl_copy_string(_x, _y, sizeof(_x))
#define esl_strlen_zero(s) (!s || *(s) == '\0')
#define esl_strlen_zero_buf(s) (*(s) == '\0')
#define esl_test_flag(obj, flag) ((obj)->flags & flag)
#define snprintf _snprintf
#define strcasecmp(s1, s2) _stricmp(s1, s2)
#define strerror_r(num, buf, size) strerror_s(buf, size, num)
#define strncasecmp(s1, s2, n) _strnicmp(s1, s2, n)
#define ESL_CONFIG_DIR "c:\\openesl"

#define ESL_PATH_SEPARATOR "\\"
#define ESL_URL_SEPARATOR "://"
#define esl_is_file_path(file) (*(file +1) == ':' || *file == '/' || strstr(file, SWITCH_URL_SEPARATOR))


#define ESL_EVENT_SUBCLASS_ANY NULL
#define esl_event_create(event, id) esl_event_create_subclass(event, id, ESL_EVENT_SUBCLASS_ANY)
#define esl_event_del_header(_e, _h) esl_event_del_header_val(_e, _h, NULL)
#define esl_event_get_header(_e, _h) esl_event_get_header_idx(_e, _h, -1)
#define esl_event_safe_destroy(_event) if (_event) esl_event_destroy(_event)

#define cJSON_AddFalseToObject(object,name)		cJSON_AddItemToObject(object, name, cJSON_CreateFalse())
#define cJSON_AddNullToObject(object,name)	cJSON_AddItemToObject(object, name, cJSON_CreateNull())
#define cJSON_AddNumberToObject(object,name,n)	cJSON_AddItemToObject(object, name, cJSON_CreateNumber(n))
#define cJSON_AddStringToObject(object,name,s)	cJSON_AddItemToObject(object, name, cJSON_CreateString(s))
#define cJSON_AddTrueToObject(object,name)	cJSON_AddItemToObject(object, name, cJSON_CreateTrue())
#define cJSON_Array 5
#define cJSON_False 0
#define cJSON_IsReference 256
#define cJSON_NULL 2
#define cJSON_Number 3
#define cJSON_Object 6
#define cJSON_String 4
#define cJSON_True 1

