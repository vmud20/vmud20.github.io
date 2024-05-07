#include<resolv.h>
#include<netdb.h>
#include<sys/types.h>
#include<sys/time.h>
#include<stdio.h>
#include<fcntl.h>
#include<stdarg.h>
#include<arpa/nameser.h>
#include<arpa/inet.h>
#include<stdlib.h>
#include<stddef.h>

#include<errno.h>
#include<regex.h>
#include<netinet/in.h>

#include<ctype.h>
#include<sys/socket.h>
#include<time.h>
#include<unistd.h>
#include<string.h>


#define IRC_REDIRECT_TIMEOUT_DEFAULT 60

#define IRC_RAW_BUFFER_NAME "irc_raw"
#define IRC_RAW_FLAG_BINARY   (1 << 4)
#define IRC_RAW_FLAG_MODIFIED (1 << 2)
#define IRC_RAW_FLAG_RECV     (1 << 0)
#define IRC_RAW_FLAG_REDIRECT (1 << 3)
#define IRC_RAW_FLAG_SEND     (1 << 1)
#define IRC_RAW_PREFIX_RECV          "-->"
#define IRC_RAW_PREFIX_RECV_MODIFIED "==>"
#define IRC_RAW_PREFIX_RECV_REDIRECT "R>>"
#define IRC_RAW_PREFIX_SEND          "<--"
#define IRC_RAW_PREFIX_SEND_MODIFIED "<=="

#define IRC_PROTOCOL_CALLBACK(__command)                                \
    int                                                                 \
    irc_protocol_cb_##__command (struct t_irc_server *server,           \
                                 time_t date,                           \
                                 const char *nick,                      \
                                 const char *address,                   \
                                 const char *host,                      \
                                 const char *command,                   \
                                 int ignored,                           \
                                 int argc,                              \
                                 char **argv,                           \
                                 char **argv_eol)
#define IRC_PROTOCOL_CHECK_HOST                                         \
    if (argv[0][0] != ':')                                              \
    {                                                                   \
        weechat_printf (server->buffer,                                 \
                        _("%s%s: \"%s\" command received without "      \
                          "host"),                                      \
                        weechat_prefix ("error"), IRC_PLUGIN_NAME,      \
                        command);                                       \
        return WEECHAT_RC_ERROR;                                        \
    }
#define IRC_PROTOCOL_MIN_ARGS(__min_args)                               \
    (void) date;                                                        \
    (void) nick;                                                        \
    (void) address;                                                     \
    (void) host;                                                        \
    (void) command;                                                     \
    (void) ignored;                                                     \
    (void) argv;                                                        \
    (void) argv_eol;                                                    \
    if (argc < __min_args)                                              \
    {                                                                   \
        weechat_printf (server->buffer,                                 \
                        _("%s%s: too few arguments received from IRC "  \
                          "server for command \"%s\" (received: %d "    \
                          "arguments, expected: at least %d)"),         \
                        weechat_prefix ("error"), IRC_PLUGIN_NAME,      \
                        command, argc, __min_args);                     \
        return WEECHAT_RC_ERROR;                                        \
    }


#define IRC_NICK_GROUP_OTHER_NAME   "..."
#define IRC_NICK_GROUP_OTHER_NUMBER 999
#define IRC_NICK_VALID_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHI"      \
    "JKLMNOPQRSTUVWXYZ0123456789-[]\\`_^{|}"



#define IRC_CONFIG_NAME "irc"

#define IRC_COMMAND_CALLBACK(__command)                                 \
    int                                                                 \
    irc_command_##__command (const void *pointer, void *data,           \
                             struct t_gui_buffer *buffer,               \
                             int argc, char **argv, char **argv_eol)
#define IRC_COMMAND_CAP_SUPPORTED_COMPLETION \
    "account-notify|away-notify|cap-notify|chghost|extended-join|"      \
    "invite-notify|multi-prefix|server-time|userhost-in-names|%*"
#define IRC_COMMAND_CHECK_SERVER(__command, __check_connection)         \
    if (!ptr_server)                                                    \
    {                                                                   \
        weechat_printf (NULL,                                           \
                        _("%s%s: command \"%s\" must be executed on "   \
                          "irc buffer (server, channel or private)"),   \
                        weechat_prefix ("error"), IRC_PLUGIN_NAME,      \
                        __command);                                     \
        return WEECHAT_RC_OK;                                           \
    }                                                                   \
    if (__check_connection && !ptr_server->is_connected)                \
    {                                                                   \
        weechat_printf (NULL,                                           \
                        _("%s%s: command \"%s\" must be executed on "   \
                          "connected irc server"),                      \
                        weechat_prefix ("error"), IRC_PLUGIN_NAME,      \
                        __command);                                     \
        return WEECHAT_RC_OK;                                           \
    }
#define IRC_COMMAND_CTCP_SUPPORTED_COMPLETION \
    "action|clientinfo|finger|ping|source|time|userinfo|version"

#define IRC_COLOR_BAR_BG weechat_color("bar_bg")
#define IRC_COLOR_BAR_DELIM weechat_color("bar_delim")
#define IRC_COLOR_BAR_FG weechat_color("bar_fg")
#define IRC_COLOR_BOLD_CHAR      '\x02'  
#define IRC_COLOR_BOLD_STR       "\x02"  
#define IRC_COLOR_CHAT_CHANNEL weechat_color("chat_channel")
#define IRC_COLOR_CHAT_DELIMITERS weechat_color("chat_delimiters")
#define IRC_COLOR_CHAT_HOST weechat_color("chat_host")
#define IRC_COLOR_CHAT_NICK weechat_color("chat_nick")
#define IRC_COLOR_CHAT_NICK_OTHER weechat_color("chat_nick_other")
#define IRC_COLOR_CHAT_NICK_SELF weechat_color("chat_nick_self")
#define IRC_COLOR_CHAT_SERVER weechat_color("chat_server")
#define IRC_COLOR_CHAT_VALUE weechat_color("chat_value")
#define IRC_COLOR_COLOR_CHAR     '\x03'  
#define IRC_COLOR_COLOR_STR      "\x03"  
#define IRC_COLOR_FIXED_CHAR     '\x11'  
#define IRC_COLOR_FIXED_STR      "\x11"  
#define IRC_COLOR_INPUT_NICK weechat_color(weechat_config_string(irc_config_color_input_nick))
#define IRC_COLOR_ITALIC_CHAR    '\x1D'  
#define IRC_COLOR_ITALIC_STR     "\x1D"  
#define IRC_COLOR_ITEM_AWAY weechat_color(weechat_config_string(irc_config_color_item_away))
#define IRC_COLOR_ITEM_CHANNEL_MODES weechat_color(weechat_config_string(irc_config_color_item_channel_modes))
#define IRC_COLOR_ITEM_LAG_COUNTING weechat_color(weechat_config_string(irc_config_color_item_lag_counting))
#define IRC_COLOR_ITEM_LAG_FINISHED weechat_color(weechat_config_string(irc_config_color_item_lag_finished))
#define IRC_COLOR_ITEM_NICK_MODES weechat_color(weechat_config_string(irc_config_color_item_nick_modes))
#define IRC_COLOR_MESSAGE_CHGHOST weechat_color(weechat_config_string(irc_config_color_message_chghost))
#define IRC_COLOR_MESSAGE_JOIN weechat_color(weechat_config_string(irc_config_color_message_join))
#define IRC_COLOR_MESSAGE_KICK weechat_color(weechat_config_string(irc_config_color_message_kick))
#define IRC_COLOR_MESSAGE_QUIT weechat_color(weechat_config_string(irc_config_color_message_quit))
#define IRC_COLOR_NICK_PREFIX_HALFOP weechat_color(weechat_config_string(irc_config_color_nick_prefix_halfop))
#define IRC_COLOR_NICK_PREFIX_OP weechat_color(weechat_config_string(irc_config_color_nick_prefix_op))
#define IRC_COLOR_NICK_PREFIX_USER weechat_color(weechat_config_string(irc_config_color_nick_prefix_user))
#define IRC_COLOR_NICK_PREFIX_VOICE weechat_color(weechat_config_string(irc_config_color_nick_prefix_voice))
#define IRC_COLOR_NOTICE weechat_color(weechat_config_string(irc_config_color_notice))
#define IRC_COLOR_REASON_KICK weechat_color(weechat_config_string(irc_config_color_reason_kick))
#define IRC_COLOR_REASON_QUIT weechat_color(weechat_config_string(irc_config_color_reason_quit))
#define IRC_COLOR_RESET weechat_color("reset")
#define IRC_COLOR_RESET_CHAR     '\x0F'  
#define IRC_COLOR_RESET_STR      "\x0F"  
#define IRC_COLOR_REVERSE_CHAR   '\x16'  
#define IRC_COLOR_REVERSE_STR    "\x16"  
#define IRC_COLOR_STATUS_NAME weechat_color("status_name")
#define IRC_COLOR_STATUS_NAME_SSL weechat_color("status_name_ssl")
#define IRC_COLOR_STATUS_NUMBER weechat_color("status_number")
#define IRC_COLOR_TERM2IRC_NUM_COLORS 16
#define IRC_COLOR_TOPIC_CURRENT weechat_color(weechat_config_string(irc_config_color_topic_current))
#define IRC_COLOR_TOPIC_NEW weechat_color(weechat_config_string(irc_config_color_topic_new))
#define IRC_COLOR_TOPIC_OLD weechat_color(weechat_config_string(irc_config_color_topic_old))
#define IRC_COLOR_UNDERLINE_CHAR '\x1F'  
#define IRC_COLOR_UNDERLINE_STR  "\x1F"  
#define IRC_NUM_COLORS        100
#define WEECHAT_COLOR_BLACK   COLOR_BLACK
#define WEECHAT_COLOR_BLUE    COLOR_RED
#define WEECHAT_COLOR_CYAN    COLOR_YELLOW
#define WEECHAT_COLOR_GREEN   COLOR_GREEN
#define WEECHAT_COLOR_MAGENTA COLOR_MAGENTA
#define WEECHAT_COLOR_RED     COLOR_BLUE
#define WEECHAT_COLOR_WHITE   COLOR_WHITE
#define WEECHAT_COLOR_YELLOW  COLOR_CYAN

#define IRC_CHANNEL_DEFAULT_CHANTYPES "#&+!"
#define IRC_CHANNEL_NICKS_SPEAKING_LIMIT 128
#define IRC_CHANNEL_TYPE_CHANNEL  0
#define IRC_CHANNEL_TYPE_PRIVATE  1
#define IRC_CHANNEL_TYPE_UNKNOWN  -1

#define IRC_BUFFER_GET_SERVER(__buffer)                                 \
    struct t_weechat_plugin *buffer_plugin = NULL;                      \
    struct t_irc_server *ptr_server = NULL;                             \
    buffer_plugin = weechat_buffer_get_pointer (__buffer, "plugin");    \
    if (buffer_plugin == weechat_irc_plugin)                            \
        irc_buffer_get_server_and_channel (__buffer, &ptr_server, NULL);
#define IRC_BUFFER_GET_SERVER_CHANNEL(__buffer)                         \
    struct t_weechat_plugin *buffer_plugin = NULL;                      \
    struct t_irc_server *ptr_server = NULL;                             \
    struct t_irc_channel *ptr_channel = NULL;                           \
    buffer_plugin = weechat_buffer_get_pointer (__buffer, "plugin");    \
    if (buffer_plugin == weechat_irc_plugin)                            \
    {                                                                   \
        irc_buffer_get_server_and_channel (__buffer, &ptr_server,       \
                                           &ptr_channel);               \
    }


#define IRC_SERVER_DEFAULT_NICKS    "weechat1,weechat2,weechat3,weechat4,weechat5"
#define IRC_SERVER_DEFAULT_PORT     6667
#define IRC_SERVER_DEFAULT_PORT_SSL 6697
#define IRC_SERVER_NUM_OUTQUEUES_PRIO 2
#define IRC_SERVER_OPTION_BOOLEAN(__server, __index)                          \
    ((!weechat_config_option_is_null(__server->options[__index])) ?           \
     weechat_config_boolean(__server->options[__index]) :                     \
     ((!weechat_config_option_is_null(irc_config_server_default[__index])) ?  \
      weechat_config_boolean(irc_config_server_default[__index])              \
      : weechat_config_boolean_default(irc_config_server_default[__index])))
#define IRC_SERVER_OPTION_INTEGER(__server, __index)                          \
    ((!weechat_config_option_is_null(__server->options[__index])) ?           \
     weechat_config_integer(__server->options[__index]) :                     \
     ((!weechat_config_option_is_null(irc_config_server_default[__index])) ?  \
      weechat_config_integer(irc_config_server_default[__index])              \
      : weechat_config_integer_default(irc_config_server_default[__index])))
#define IRC_SERVER_OPTION_STRING(__server, __index)                           \
    ((!weechat_config_option_is_null(__server->options[__index])) ?           \
     weechat_config_string(__server->options[__index]) :                      \
     ((!weechat_config_option_is_null(irc_config_server_default[__index])) ?  \
      weechat_config_string(irc_config_server_default[__index])               \
      : weechat_config_string_default(irc_config_server_default[__index])))
#define IRC_SERVER_SEND_OUTQ_PRIO_HIGH   (1 << 0)
#define IRC_SERVER_SEND_OUTQ_PRIO_LOW    (1 << 1)
#define IRC_SERVER_SEND_RETURN_HASHTABLE (1 << 2)
#define IRC_SERVER_VERSION_CAP "302"
#define NI_MAXHOST 256

#define IRC_PLUGIN_NAME "irc"

#define weechat_plugin weechat_irc_plugin
#define NG_(single,plural,number)                                       \
    (weechat_plugin->ngettext)(single, plural, number)
#define N_(string) (string)
    #define PATH_MAX 4096
#define WEECHAT_COMMAND_ERROR                                           \
    {                                                                   \
        weechat_printf_date_tags (                                      \
            NULL, 0, "no_filter",                                       \
            _("%sError with command \"%s\" "                            \
              "(help on command: /help %s)"),                           \
            weechat_prefix ("error"),                                   \
            argv_eol[0],                                                \
            argv[0] + 1);                                               \
        return WEECHAT_RC_ERROR;                                        \
    }
#define WEECHAT_COMMAND_MIN_ARGS(__min_args, __option)                  \
    if (argc < __min_args)                                              \
    {                                                                   \
        weechat_printf_date_tags (                                      \
            NULL, 0, "no_filter",                                       \
            _("%sToo few arguments for command \"%s%s%s\" "             \
              "(help on command: /help %s)"),                           \
            weechat_prefix ("error"),                                   \
            argv[0],                                                    \
            (__option && __option[0]) ? " " : "",                       \
            (__option && __option[0]) ? __option : "",                  \
            argv[0] + 1);                                               \
        return WEECHAT_RC_ERROR;                                        \
    }
#define WEECHAT_CONFIG_OPTION_NULL                 "null"
#define WEECHAT_CONFIG_OPTION_SET_ERROR             0
#define WEECHAT_CONFIG_OPTION_SET_OK_CHANGED        2
#define WEECHAT_CONFIG_OPTION_SET_OK_SAME_VALUE     1
#define WEECHAT_CONFIG_OPTION_SET_OPTION_NOT_FOUND -1
#define WEECHAT_CONFIG_OPTION_UNSET_ERROR          -1
#define WEECHAT_CONFIG_OPTION_UNSET_OK_NO_RESET     0
#define WEECHAT_CONFIG_OPTION_UNSET_OK_REMOVED      2
#define WEECHAT_CONFIG_OPTION_UNSET_OK_RESET        1
#define WEECHAT_CONFIG_READ_FILE_NOT_FOUND         -2
#define WEECHAT_CONFIG_READ_MEMORY_ERROR           -1
#define WEECHAT_CONFIG_READ_OK                      0
#define WEECHAT_CONFIG_WRITE_ERROR                 -1
#define WEECHAT_CONFIG_WRITE_MEMORY_ERROR          -2
#define WEECHAT_CONFIG_WRITE_OK                     0
#define WEECHAT_HASHTABLE_BUFFER                    "buffer"
#define WEECHAT_HASHTABLE_INTEGER                   "integer"
#define WEECHAT_HASHTABLE_POINTER                   "pointer"
#define WEECHAT_HASHTABLE_STRING                    "string"
#define WEECHAT_HASHTABLE_TIME                      "time"
#define WEECHAT_HDATA_CHAR                          1
#define WEECHAT_HDATA_HASHTABLE                     7
#define WEECHAT_HDATA_INTEGER                       2
#define WEECHAT_HDATA_LIST(__name, __flags)                             \
    weechat_hdata_new_list (hdata, #__name, &(__name), __flags);
#define WEECHAT_HDATA_LIST_CHECK_POINTERS           1
#define WEECHAT_HDATA_LONG                          3
#define WEECHAT_HDATA_OTHER                         0
#define WEECHAT_HDATA_POINTER                       5
#define WEECHAT_HDATA_SHARED_STRING                 8
#define WEECHAT_HDATA_STRING                        4
#define WEECHAT_HDATA_TIME                          6
#define WEECHAT_HDATA_VAR(__struct, __name, __type, __update_allowed,   \
                          __array_size, __hdata_name)                   \
    weechat_hdata_new_var (hdata, #__name, offsetof (__struct, __name), \
                           WEECHAT_HDATA_##__type, __update_allowed,    \
                           __array_size, __hdata_name)
#define WEECHAT_HOOK_CONNECT_ADDRESS_NOT_FOUND      1
#define WEECHAT_HOOK_CONNECT_CONNECTION_REFUSED     3
#define WEECHAT_HOOK_CONNECT_GNUTLS_CB_SET_CERT     1
#define WEECHAT_HOOK_CONNECT_GNUTLS_CB_VERIFY_CERT  0
#define WEECHAT_HOOK_CONNECT_GNUTLS_HANDSHAKE_ERROR 7
#define WEECHAT_HOOK_CONNECT_GNUTLS_INIT_ERROR      6
#define WEECHAT_HOOK_CONNECT_IP_ADDRESS_NOT_FOUND   2
#define WEECHAT_HOOK_CONNECT_LOCAL_HOSTNAME_ERROR   5
#define WEECHAT_HOOK_CONNECT_MEMORY_ERROR           8
#define WEECHAT_HOOK_CONNECT_OK                     0
#define WEECHAT_HOOK_CONNECT_PROXY_ERROR            4
#define WEECHAT_HOOK_CONNECT_SOCKET_ERROR           10
#define WEECHAT_HOOK_CONNECT_TIMEOUT                9
#define WEECHAT_HOOK_PROCESS_CHILD                  -3
#define WEECHAT_HOOK_PROCESS_ERROR                  -2
#define WEECHAT_HOOK_PROCESS_RUNNING                -1
#define WEECHAT_HOOK_SIGNAL_INT                     "int"
#define WEECHAT_HOOK_SIGNAL_POINTER                 "pointer"
#define WEECHAT_HOOK_SIGNAL_STRING                  "string"
#define WEECHAT_HOTLIST_HIGHLIGHT                   "3"
#define WEECHAT_HOTLIST_LOW                         "0"
#define WEECHAT_HOTLIST_MESSAGE                     "1"
#define WEECHAT_HOTLIST_PRIVATE                     "2"
#define WEECHAT_LIST_POS_BEGINNING                  "beginning"
#define WEECHAT_LIST_POS_END                        "end"
#define WEECHAT_LIST_POS_SORT                       "sort"
#define WEECHAT_PLUGIN_API_VERSION "20190810-01"
#define WEECHAT_PLUGIN_AUTHOR(__author)         \
    char weechat_plugin_author[] = __author;
#define WEECHAT_PLUGIN_DESCRIPTION(__desc)      \
    char weechat_plugin_description[] = __desc;
#define WEECHAT_PLUGIN_LICENSE(__license)       \
    char weechat_plugin_license[] = __license;
#define WEECHAT_PLUGIN_NAME(__name)                                     \
    char weechat_plugin_name[] = __name;                                \
    char weechat_plugin_api_version[] = WEECHAT_PLUGIN_API_VERSION;
#define WEECHAT_PLUGIN_PRIORITY(__priority)     \
    int weechat_plugin_priority = __priority;
#define WEECHAT_PLUGIN_VERSION(__version)       \
    char weechat_plugin_version[] = __version;
#define WEECHAT_RC_ERROR                           -1
#define WEECHAT_RC_OK                               0
#define WEECHAT_RC_OK_EAT                           1
#define WEECHAT_STRING_SPLIT_COLLAPSE_SEPS         (1 << 2)
#define WEECHAT_STRING_SPLIT_KEEP_EOL              (1 << 3)
#define WEECHAT_STRING_SPLIT_STRIP_LEFT            (1 << 0)
#define WEECHAT_STRING_SPLIT_STRIP_RIGHT           (1 << 1)

#define _(string) (weechat_plugin->gettext)(string)
#define weechat_arraylist_add(__arraylist, __pointer)                   \
    (weechat_plugin->arraylist_add)(__arraylist, __pointer)
#define weechat_arraylist_clear(__arraylist)                            \
    (weechat_plugin->arraylist_clear)(__arraylist)
#define weechat_arraylist_free(__arraylist)                             \
    (weechat_plugin->arraylist_free)(__arraylist)
#define weechat_arraylist_get(__arraylist, __index)                     \
    (weechat_plugin->arraylist_get)(__arraylist, __index)
#define weechat_arraylist_insert(__arraylist, __index, __pointer)       \
    (weechat_plugin->arraylist_insert)(__arraylist, __index, __pointer)
#define weechat_arraylist_new(__initial_size, __sorted,                 \
                              __allow_duplicates, __callback_cmp,       \
                              __callback_cmp_data, __callback_free,     \
                              __callback_free_data)                     \
    (weechat_plugin->arraylist_new)(__initial_size, __sorted,           \
                              __allow_duplicates, __callback_cmp,       \
                              __callback_cmp_data, __callback_free,     \
                              __callback_free_data)
#define weechat_arraylist_remove(__arraylist, __index)                  \
    (weechat_plugin->arraylist_remove)(__arraylist, __index)
#define weechat_arraylist_search(__arraylist, __pointer, __index,       \
                                 __index_insert)                        \
    (weechat_plugin->arraylist_search)(__arraylist, __pointer, __index, \
                                       __index_insert)
#define weechat_arraylist_size(__arraylist)                             \
    (weechat_plugin->arraylist_size)(__arraylist)
#define weechat_bar_item_new(__name, __build_callback,                  \
                             __build_callback_pointer,                  \
                             __build_callback_data)                     \
    (weechat_plugin->bar_item_new)(weechat_plugin, __name,              \
                                   __build_callback,                    \
                                   __build_callback_pointer,            \
                                   __build_callback_data)
#define weechat_bar_item_remove(__item)                                 \
    (weechat_plugin->bar_item_remove)(__item)
#define weechat_bar_item_search(__name)                                 \
    (weechat_plugin->bar_item_search)(__name)
#define weechat_bar_item_update(__name)                                 \
    (weechat_plugin->bar_item_update)(__name)
#define weechat_bar_new(__name, __hidden, __priority, __type,           \
                        __condition, __position, __filling_top_bottom,  \
                        __filling_left_right, __size, __size_max,       \
                        __color_fg, __color_delim, __color_bg,          \
                        __separator, __items)                           \
    (weechat_plugin->bar_new)(__name, __hidden, __priority, __type,     \
                              __condition, __position,                  \
                              __filling_top_bottom,                     \
                              __filling_left_right,                     \
                              __size, __size_max, __color_fg,           \
                              __color_delim, __color_bg, __separator,   \
                              __items)
#define weechat_bar_remove(__bar)                                       \
    (weechat_plugin->bar_remove)(__bar)
#define weechat_bar_search(__name)                                      \
    (weechat_plugin->bar_search)(__name)
#define weechat_bar_set(__bar, __property, __value)                     \
    (weechat_plugin->bar_set)(__bar, __property, __value)
#define weechat_bar_update(__name)                                      \
    (weechat_plugin->bar_update)(__name)
#define weechat_buffer_clear(__buffer)                                  \
    (weechat_plugin->buffer_clear)(__buffer)
#define weechat_buffer_close(__buffer)                                  \
    (weechat_plugin->buffer_close)(__buffer)
#define weechat_buffer_get_integer(__buffer, __property)                \
    (weechat_plugin->buffer_get_integer)(__buffer, __property)
#define weechat_buffer_get_pointer(__buffer, __property)                \
    (weechat_plugin->buffer_get_pointer)(__buffer, __property)
#define weechat_buffer_get_string(__buffer, __property)                 \
    (weechat_plugin->buffer_get_string)(__buffer, __property)
#define weechat_buffer_match_list(__buffer, __string)                   \
    (weechat_plugin->buffer_match_list)(__buffer, __string)
#define weechat_buffer_merge(__buffer, __target_buffer)                 \
    (weechat_plugin->buffer_merge)(__buffer, __target_buffer)
#define weechat_buffer_new(__name, __input_callback,                    \
                           __input_callback_pointer,                    \
                           __input_callback_data,                       \
                           __close_callback,                            \
                           __close_callback_pointer,                    \
                           __close_callback_data)                       \
    (weechat_plugin->buffer_new)(weechat_plugin, __name,                \
                                 __input_callback,                      \
                                 __input_callback_pointer,              \
                                 __input_callback_data,                 \
                                 __close_callback,                      \
                                 __close_callback_pointer,              \
                                 __close_callback_data)
#define weechat_buffer_search(__plugin, __name)                         \
    (weechat_plugin->buffer_search)(__plugin, __name)
#define weechat_buffer_search_main()                                    \
    (weechat_plugin->buffer_search_main)()
#define weechat_buffer_set(__buffer, __property, __value)               \
    (weechat_plugin->buffer_set)(__buffer, __property, __value)
#define weechat_buffer_set_pointer(__buffer, __property, __pointer)     \
    (weechat_plugin->buffer_set_pointer)(__buffer, __property,          \
                                         __pointer)
#define weechat_buffer_string_replace_local_var(__buffer, __string)     \
    (weechat_plugin->buffer_string_replace_local_var)(__buffer,         \
                                                      __string)
#define weechat_buffer_unmerge(__buffer, __number)                      \
    (weechat_plugin->buffer_unmerge)(__buffer, __number)
#define weechat_charset_set(__charset)                                  \
    (weechat_plugin->charset_set)(weechat_plugin, __charset)
#define weechat_color(__color_name)                                     \
    (weechat_plugin->color)(__color_name)
#define weechat_command(__buffer, __command)                            \
    (weechat_plugin->command)(weechat_plugin, __buffer, __command)
#define weechat_command_options(__buffer, __command, __options)         \
    (weechat_plugin->command_options)(weechat_plugin, __buffer,         \
                                      __command, __options)
#define weechat_config_boolean(__option)                                \
    (weechat_plugin->config_boolean)(__option)
#define weechat_config_boolean_default(__option)                        \
    (weechat_plugin->config_boolean_default)(__option)
#define weechat_config_color(__option)                                  \
    (weechat_plugin->config_color)(__option)
#define weechat_config_color_default(__option)                          \
    (weechat_plugin->config_color_default)(__option)
#define weechat_config_free(__config)                                   \
    (weechat_plugin->config_free)(__config)
#define weechat_config_get(__option)                                    \
    (weechat_plugin->config_get)(__option)
#define weechat_config_get_plugin(__option)                             \
    (weechat_plugin->config_get_plugin)(weechat_plugin, __option)
#define weechat_config_integer(__option)                                \
    (weechat_plugin->config_integer)(__option)
#define weechat_config_integer_default(__option)                        \
    (weechat_plugin->config_integer_default)(__option)
#define weechat_config_is_set_plugin(__option)                          \
    (weechat_plugin->config_is_set_plugin)(weechat_plugin, __option)
#define weechat_config_new(__name, __callback_reload,                   \
                           __callback_reload_pointer,                   \
                           __callback_reload_data)                      \
    (weechat_plugin->config_new)(weechat_plugin, __name,                \
                                 __callback_reload,                     \
                                 __callback_reload_pointer,             \
                                 __callback_reload_data)
#define weechat_config_new_option(__config, __section, __name, __type,  \
                                  __desc, __string_values, __min,       \
                                  __max, __default, __value,            \
                                  __null_value_allowed,                 \
                                  __callback_check,                     \
                                  __callback_check_pointer,             \
                                  __callback_check_data,                \
                                  __callback_change,                    \
                                  __callback_change_pointer,            \
                                  __callback_change_data,               \
                                  __callback_delete,                    \
                                  __callback_delete_pointer,            \
                                  __callback_delete_data)               \
    (weechat_plugin->config_new_option)(__config, __section, __name,    \
                                        __type, __desc,                 \
                                        __string_values,                \
                                        __min, __max, __default,        \
                                        __value,                        \
                                        __null_value_allowed,           \
                                        __callback_check,               \
                                        __callback_check_pointer,       \
                                        __callback_check_data,          \
                                        __callback_change,              \
                                        __callback_change_pointer,      \
                                        __callback_change_data,         \
                                        __callback_delete,              \
                                        __callback_delete_pointer,      \
                                        __callback_delete_data)
#define weechat_config_new_section(__config, __name,                    \
                                   __user_can_add_options,              \
                                   __user_can_delete_options,           \
                                   __cb_read,                           \
                                   __cb_read_pointer,                   \
                                   __cb_read_data,                      \
                                   __cb_write_std,                      \
                                   __cb_write_std_pointer,              \
                                   __cb_write_std_data,                 \
                                   __cb_write_def,                      \
                                   __cb_write_def_pointer,              \
                                   __cb_write_def_data,                 \
                                   __cb_create_option,                  \
                                   __cb_create_option_pointer,          \
                                   __cb_create_option_data,             \
                                   __cb_delete_option,                  \
                                   __cb_delete_option_pointer,          \
                                   __cb_delete_option_data)             \
    (weechat_plugin->config_new_section)(__config, __name,              \
                                         __user_can_add_options,        \
                                         __user_can_delete_options,     \
                                         __cb_read,                     \
                                         __cb_read_pointer,             \
                                         __cb_read_data,                \
                                         __cb_write_std,                \
                                         __cb_write_std_pointer,        \
                                         __cb_write_std_data,           \
                                         __cb_write_def,                \
                                         __cb_write_def_pointer,        \
                                         __cb_write_def_data,           \
                                         __cb_create_option,            \
                                         __cb_create_option_pointer,    \
                                         __cb_create_option_data,       \
                                         __cb_delete_option,            \
                                         __cb_delete_option_pointer,    \
                                         __cb_delete_option_data)
#define weechat_config_option_default_is_null(__option)                 \
    (weechat_plugin->config_option_default_is_null)(__option)
#define weechat_config_option_free(__option)                            \
    (weechat_plugin->config_option_free)(__option)
#define weechat_config_option_get_pointer(__option, __property)         \
    (weechat_plugin->config_option_get_pointer)(__option, __property)
#define weechat_config_option_get_string(__option, __property)         \
    (weechat_plugin->config_option_get_string)(__option, __property)
#define weechat_config_option_is_null(__option)                         \
    (weechat_plugin->config_option_is_null)(__option)
#define weechat_config_option_rename(__option, __new_name)              \
    (weechat_plugin->config_option_rename)(__option, __new_name)
#define weechat_config_option_reset(__option, __run_callback)           \
    (weechat_plugin->config_option_reset)(__option, __run_callback)
#define weechat_config_option_set(__option, __value, __run_callback)    \
    (weechat_plugin->config_option_set)(__option, __value,              \
                                        __run_callback)
#define weechat_config_option_set_null(__option, __run_callback)        \
    (weechat_plugin->config_option_set_null)(__option, __run_callback)
#define weechat_config_option_unset(__option)                           \
    (weechat_plugin->config_option_unset)(__option)
#define weechat_config_read(__config)                                   \
    (weechat_plugin->config_read)(__config)
#define weechat_config_reload(__config)                                 \
    (weechat_plugin->config_reload)(__config)
#define weechat_config_search_option(__config, __section, __name)       \
    (weechat_plugin->config_search_option)(__config, __section, __name)
#define weechat_config_search_section(__config, __name)                 \
    (weechat_plugin->config_search_section)(__config, __name)
#define weechat_config_search_section_option(__config, __section,       \
                                             __name, __section_found,   \
                                             __option_found)            \
    (weechat_plugin->config_search_section_option)(__config, __section, \
                                                   __name,              \
                                                   __section_found,     \
                                                   __option_found);
#define weechat_config_search_with_string(__name, __config, __section,  \
                                          __option, __pos_option)       \
    (weechat_plugin->config_search_with_string)(__name, __config,       \
                                                __section, __option,    \
                                                __pos_option);
#define weechat_config_section_free(__section)                          \
    (weechat_plugin->config_section_free)(__section)
#define weechat_config_section_free_options(__section)                  \
    (weechat_plugin->config_section_free_options)(__section)
#define weechat_config_set_desc_plugin(__option, __description)         \
    (weechat_plugin->config_set_desc_plugin)(weechat_plugin, __option,  \
                                             __description)
#define weechat_config_set_plugin(__option, __value)                    \
    (weechat_plugin->config_set_plugin)(weechat_plugin, __option,       \
                                        __value)
#define weechat_config_string(__option)                                 \
    (weechat_plugin->config_string)(__option)
#define weechat_config_string_default(__option)                         \
    (weechat_plugin->config_string_default)(__option)
#define weechat_config_string_to_boolean(__string)                      \
    (weechat_plugin->config_string_to_boolean)(__string)
#define weechat_config_unset_plugin(__option)                           \
    (weechat_plugin->config_unset_plugin)(weechat_plugin, __option)
#define weechat_config_write(__config)                                  \
    (weechat_plugin->config_write)(__config)
#define weechat_config_write_line(__config, __option, __value...)       \
    (weechat_plugin->config_write_line)(__config, __option, ##__value)
#define weechat_config_write_option(__config, __option)                 \
    (weechat_plugin->config_write_option)(__config, __option)
#define weechat_current_buffer()                                        \
    (weechat_plugin->buffer_search)(NULL, NULL)
#define weechat_current_window()                                        \
    (weechat_plugin->window_get_pointer)(NULL, "current")
#define weechat_exec_on_files(__directory, __recurse_subdirs,           \
                              __hidden_files, __callback,               \
                              __callback_data)                          \
    (weechat_plugin->exec_on_files)(__directory, __recurse_subdirs,     \
                                    __hidden_files,                     \
                                    __callback, __callback_data)
#define weechat_file_get_content(__filename)                            \
    (weechat_plugin->file_get_content)(__filename)
#define weechat_gettext(string) (weechat_plugin->gettext)(string)
#define weechat_hashtable_add_from_infolist(__hashtable, __infolist,    \
                                            __prefix)                   \
    (weechat_plugin->hashtable_add_from_infolist)(__hashtable,          \
                                                  __infolist,           \
                                                  __prefix)
#define weechat_hashtable_add_to_infolist(__hashtable, __infolist_item, \
                                          __prefix)                     \
    (weechat_plugin->hashtable_add_to_infolist)(__hashtable,            \
                                                __infolist_item,        \
                                                __prefix)
#define weechat_hashtable_dup(__hashtable)                              \
    (weechat_plugin->hashtable_dup)(__hashtable)
#define weechat_hashtable_free(__hashtable)                             \
    (weechat_plugin->hashtable_free)(__hashtable)
#define weechat_hashtable_get(__hashtable, __key)                       \
    (weechat_plugin->hashtable_get)(__hashtable, __key)
#define weechat_hashtable_get_integer(__hashtable, __property)          \
    (weechat_plugin->hashtable_get_integer)(__hashtable, __property)
#define weechat_hashtable_get_string(__hashtable, __property)           \
    (weechat_plugin->hashtable_get_string)(__hashtable, __property)
#define weechat_hashtable_has_key(__hashtable, __key)                   \
    (weechat_plugin->hashtable_has_key)(__hashtable, __key)
#define weechat_hashtable_map(__hashtable, __cb_map, __cb_map_data)     \
    (weechat_plugin->hashtable_map)(__hashtable, __cb_map,              \
                                    __cb_map_data)
#define weechat_hashtable_map_string(__hashtable, __cb_map,             \
                                     __cb_map_data)                     \
    (weechat_plugin->hashtable_map_string)(__hashtable, __cb_map,       \
                                           __cb_map_data)
#define weechat_hashtable_new(__size, __type_keys, __type_values,       \
                              __callback_hash_key, __callback_keycmp)   \
    (weechat_plugin->hashtable_new)(__size, __type_keys, __type_values, \
                                    __callback_hash_key,                \
                                    __callback_keycmp)
#define weechat_hashtable_remove(__hashtable, __key)                    \
    (weechat_plugin->hashtable_remove)(__hashtable, __key)
#define weechat_hashtable_remove_all(__hashtable)                       \
    (weechat_plugin->hashtable_remove_all)(__hashtable)
#define weechat_hashtable_set(__hashtable, __key, __value)              \
    (weechat_plugin->hashtable_set)(__hashtable, __key, __value)
#define weechat_hashtable_set_pointer(__hashtable, __property,          \
                                      __pointer)                        \
    (weechat_plugin->hashtable_set_pointer)(__hashtable, __property,    \
                                            __pointer)
#define weechat_hashtable_set_with_size(__hashtable, __key, __key_size, \
                                        __value, __value_size)          \
    (weechat_plugin->hashtable_set_with_size)(__hashtable, __key,       \
                                              __key_size, __value,      \
                                              __value_size)
#define weechat_hdata_char(__hdata, __pointer, __name)                  \
    (weechat_plugin->hdata_char)(__hdata, __pointer, __name)
#define weechat_hdata_check_pointer(__hdata, __list, __pointer)         \
    (weechat_plugin->hdata_check_pointer)(__hdata, __list, __pointer)
#define weechat_hdata_compare(__hdata, __pointer1, __pointer2, __name,  \
                              __case_sensitive)                         \
    (weechat_plugin->hdata_compare)(__hdata, __pointer1, __pointer2,    \
                                    __name, __case_sensitive)
#define weechat_hdata_get(__hdata_name)                                 \
    (weechat_plugin->hdata_get)(weechat_plugin, __hdata_name)
#define weechat_hdata_get_list(__hdata, __name)                         \
    (weechat_plugin->hdata_get_list)(__hdata, __name)
#define weechat_hdata_get_string(__hdata, __property)                   \
    (weechat_plugin->hdata_get_string)(__hdata, __property)
#define weechat_hdata_get_var(__hdata, __pointer, __name)               \
    (weechat_plugin->hdata_get_var)(__hdata, __pointer, __name)
#define weechat_hdata_get_var_array_size(__hdata, __pointer, __name)    \
    (weechat_plugin->hdata_get_var_array_size)(__hdata, __pointer,      \
                                               __name)
#define weechat_hdata_get_var_array_size_string(__hdata, __pointer,     \
                                                __name)                 \
    (weechat_plugin->hdata_get_var_array_size_string)(__hdata,          \
                                                      __pointer,        \
                                                      __name)
#define weechat_hdata_get_var_at_offset(__hdata, __pointer, __offset)   \
    (weechat_plugin->hdata_get_var_at_offset)(__hdata, __pointer,       \
                                              __offset)
#define weechat_hdata_get_var_hdata(__hdata, __name)                    \
    (weechat_plugin->hdata_get_var_hdata)(__hdata, __name)
#define weechat_hdata_get_var_offset(__hdata, __name)                   \
    (weechat_plugin->hdata_get_var_offset)(__hdata, __name)
#define weechat_hdata_get_var_type(__hdata, __name)                     \
    (weechat_plugin->hdata_get_var_type)(__hdata, __name)
#define weechat_hdata_get_var_type_string(__hdata, __name)              \
    (weechat_plugin->hdata_get_var_type_string)(__hdata, __name)
#define weechat_hdata_hashtable(__hdata, __pointer, __name)             \
    (weechat_plugin->hdata_hashtable)(__hdata, __pointer, __name)
#define weechat_hdata_integer(__hdata, __pointer, __name)               \
    (weechat_plugin->hdata_integer)(__hdata, __pointer, __name)
#define weechat_hdata_long(__hdata, __pointer, __name)                  \
    (weechat_plugin->hdata_long)(__hdata, __pointer, __name)
#define weechat_hdata_move(__hdata, __pointer, __count)                 \
    (weechat_plugin->hdata_move)(__hdata, __pointer, __count)
#define weechat_hdata_new(__hdata_name, __var_prev, __var_next,         \
                          __create_allowed, __delete_allowed,           \
                          __callback_update, __callback_update_data)    \
    (weechat_plugin->hdata_new)(weechat_plugin, __hdata_name,           \
                                __var_prev, __var_next,                 \
                                __create_allowed, __delete_allowed,     \
                                __callback_update,                      \
                                __callback_update_data)
#define weechat_hdata_new_list(__hdata, __name, __pointer, __flags)     \
    (weechat_plugin->hdata_new_list)(__hdata, __name, __pointer,        \
                                     __flags)
#define weechat_hdata_new_var(__hdata, __name, __offset, __type,        \
                              __update_allowed, __array_size,           \
                              __hdata_name)                             \
    (weechat_plugin->hdata_new_var)(__hdata, __name, __offset, __type,  \
                                    __update_allowed, __array_size,     \
                                    __hdata_name)
#define weechat_hdata_pointer(__hdata, __pointer, __name)               \
    (weechat_plugin->hdata_pointer)(__hdata, __pointer, __name)
#define weechat_hdata_search(__hdata, __pointer, __search, __move)      \
    (weechat_plugin->hdata_search)(__hdata, __pointer, __search,        \
                                   __move)
#define weechat_hdata_set(__hdata, __pointer, __name, __value)          \
    (weechat_plugin->hdata_set)(__hdata, __pointer, __name, __value)
#define weechat_hdata_string(__hdata, __pointer, __name)                \
    (weechat_plugin->hdata_string)(__hdata, __pointer, __name)
#define weechat_hdata_time(__hdata, __pointer, __name)                  \
    (weechat_plugin->hdata_time)(__hdata, __pointer, __name)
#define weechat_hdata_update(__hdata, __pointer, __hashtable)           \
    (weechat_plugin->hdata_update)(__hdata, __pointer, __hashtable)
#define weechat_hook_command(__command, __description, __args,          \
                             __args_desc, __completion, __callback,     \
                             __pointer, __data)                         \
    (weechat_plugin->hook_command)(weechat_plugin, __command,           \
                                   __description, __args, __args_desc,  \
                                   __completion, __callback, __pointer, \
                                   __data)
#define weechat_hook_command_run(__command, __callback, __pointer,      \
                                 __data)                                \
    (weechat_plugin->hook_command_run)(weechat_plugin, __command,       \
                                       __callback, __pointer, __data)
#define weechat_hook_completion(__completion, __description,            \
                                __callback, __pointer, __data)          \
    (weechat_plugin->hook_completion)(weechat_plugin, __completion,     \
                                      __description, __callback,        \
                                      __pointer, __data)
#define weechat_hook_completion_get_string(__completion, __property)    \
    (weechat_plugin->hook_completion_get_string)(__completion,          \
                                                 __property)
#define weechat_hook_completion_list_add(__completion, __word,          \
                                         __nick_completion, __where)    \
    (weechat_plugin->hook_completion_list_add)(__completion, __word,    \
                                               __nick_completion,       \
                                               __where)
#define weechat_hook_config(__option, __callback, __pointer, __data)    \
    (weechat_plugin->hook_config)(weechat_plugin, __option, __callback, \
                                  __pointer, __data)
#define weechat_hook_connect(__proxy, __address, __port, __ipv6,        \
                             __retry, __gnutls_sess, __gnutls_cb,       \
                             __gnutls_dhkey_size, __gnutls_priorities,  \
                             __local_hostname, __callback, __pointer,   \
                             __data)                                    \
    (weechat_plugin->hook_connect)(weechat_plugin, __proxy, __address,  \
                                   __port, __ipv6, __retry,             \
                                   __gnutls_sess, __gnutls_cb,          \
                                   __gnutls_dhkey_size,                 \
                                   __gnutls_priorities,                 \
                                   __local_hostname,                    \
                                   __callback, __pointer, __data)
#define weechat_hook_fd(__fd, __flag_read, __flag_write,                \
                        __flag_exception, __callback, __pointer,        \
                        __data)                                         \
    (weechat_plugin->hook_fd)(weechat_plugin, __fd, __flag_read,        \
                              __flag_write, __flag_exception,           \
                              __callback, __pointer, __data)
#define weechat_hook_focus(__area, __callback, __pointer, __data)       \
    (weechat_plugin->hook_focus)(weechat_plugin, __area, __callback,    \
                                 __pointer, __data)
#define weechat_hook_hdata(__hdata_name, __description, __callback,     \
                           __pointer, __data)                           \
    (weechat_plugin->hook_hdata)(weechat_plugin, __hdata_name,          \
                                 __description, __callback, __pointer,  \
                                 __data)
#define weechat_hook_hsignal(__signal, __callback, __pointer, __data)   \
    (weechat_plugin->hook_hsignal)(weechat_plugin, __signal,            \
                                   __callback, __pointer, __data)
#define weechat_hook_hsignal_send(__signal, __hashtable)                \
    (weechat_plugin->hook_hsignal_send)(__signal, __hashtable)
#define weechat_hook_info(__info_name, __description,                   \
                          __args_description, __callback, __pointer,    \
                          __data)                                       \
    (weechat_plugin->hook_info)(weechat_plugin, __info_name,            \
                                __description, __args_description,      \
                                __callback, __pointer, __data)
#define weechat_hook_info_hashtable(__info_name, __description,         \
                                    __args_description,                 \
                                    __output_description,               \
                                    __callback,                         \
                                    __pointer,                          \
                                    __data)                             \
    (weechat_plugin->hook_info_hashtable)(weechat_plugin, __info_name,  \
                                          __description,                \
                                          __args_description,           \
                                          __output_description,         \
                                          __callback, __pointer,        \
                                          __data)
#define weechat_hook_infolist(__infolist_name, __description,           \
                              __pointer_description,                    \
                              __args_description, __callback,           \
                              __pointer, __data)                        \
    (weechat_plugin->hook_infolist)(weechat_plugin, __infolist_name,    \
                                    __description,                      \
                                    __pointer_description,              \
                                    __args_description, __callback,     \
                                    __pointer, __data)
#define weechat_hook_line(_buffer_type, __buffer_name, __tags,          \
                          __callback, __pointer, __data)                \
    (weechat_plugin->hook_line)(weechat_plugin, _buffer_type,           \
                                __buffer_name, __tags, __callback,      \
                                __pointer, __data)
#define weechat_hook_modifier(__modifier, __callback, __pointer,        \
                              __data)                                   \
    (weechat_plugin->hook_modifier)(weechat_plugin, __modifier,         \
                                    __callback, __pointer, __data)
#define weechat_hook_modifier_exec(__modifier, __modifier_data,         \
                                   __string)                            \
    (weechat_plugin->hook_modifier_exec)(weechat_plugin, __modifier,    \
                                         __modifier_data, __string)
#define weechat_hook_print(__buffer, __tags, __msg, __strip__colors,    \
                           __callback, __pointer, __data)               \
    (weechat_plugin->hook_print)(weechat_plugin, __buffer, __tags,      \
                                 __msg, __strip__colors, __callback,    \
                                 __pointer, __data)
#define weechat_hook_process(__command, __timeout, __callback,          \
                             __callback_pointer, __callback_data)       \
    (weechat_plugin->hook_process)(weechat_plugin, __command,           \
                                   __timeout, __callback,               \
                                   __callback_pointer, __callback_data)
#define weechat_hook_process_hashtable(__command, __options, __timeout, \
                                       __callback, __callback_pointer,  \
                                       __callback_data)                 \
    (weechat_plugin->hook_process_hashtable)(weechat_plugin, __command, \
                                             __options, __timeout,      \
                                             __callback,                \
                                             __callback_pointer,        \
                                             __callback_data)
#define weechat_hook_set(__hook, __property, __value)                   \
    (weechat_plugin->hook_set)(__hook, __property, __value)
#define weechat_hook_signal(__signal, __callback, __pointer, __data)    \
    (weechat_plugin->hook_signal)(weechat_plugin, __signal, __callback, \
                                  __pointer, __data)
#define weechat_hook_signal_send(__signal, __type_data, __signal_data)  \
    (weechat_plugin->hook_signal_send)(__signal, __type_data,           \
                                       __signal_data)
#define weechat_hook_timer(__interval, __align_second, __max_calls,     \
                           __callback, __pointer, __data)               \
    (weechat_plugin->hook_timer)(weechat_plugin, __interval,            \
                                 __align_second, __max_calls,           \
                                 __callback, __pointer, __data)
#define weechat_iconv_from_internal(__charset, __string)                \
    (weechat_plugin->iconv_from_internal)(__charset, __string)
#define weechat_iconv_to_internal(__charset, __string)                  \
    (weechat_plugin->iconv_to_internal)(__charset, __string)
#define weechat_info_get(__info_name, __arguments)                      \
    (weechat_plugin->info_get)(weechat_plugin, __info_name,             \
                               __arguments)
#define weechat_info_get_hashtable(__info_name, __hashtable)            \
    (weechat_plugin->info_get_hashtable)(weechat_plugin, __info_name,   \
                                         __hashtable)
#define weechat_infolist_buffer(__item, __var, __size)                  \
    (weechat_plugin->infolist_buffer)(__item, __var, __size)
#define weechat_infolist_fields(__list)                                 \
    (weechat_plugin->infolist_fields)(__list)
#define weechat_infolist_free(__list)                                   \
    (weechat_plugin->infolist_free)(__list)
#define weechat_infolist_get(__infolist_name, __pointer, __arguments)   \
    (weechat_plugin->infolist_get)(weechat_plugin, __infolist_name,     \
                                   __pointer, __arguments)
#define weechat_infolist_integer(__item, __var)                         \
    (weechat_plugin->infolist_integer)(__item, __var)
#define weechat_infolist_new()                                          \
    (weechat_plugin->infolist_new)(weechat_plugin)
#define weechat_infolist_new_item(__list)                               \
    (weechat_plugin->infolist_new_item)(__list)
#define weechat_infolist_new_var_buffer(__item, __name, __buffer,       \
                                        __size)                         \
    (weechat_plugin->infolist_new_var_buffer)(__item, __name, __buffer, \
                                              __size)
#define weechat_infolist_new_var_integer(__item, __name, __value)       \
    (weechat_plugin->infolist_new_var_integer)(__item, __name, __value)
#define weechat_infolist_new_var_pointer(__item, __name, __pointer)     \
    (weechat_plugin->infolist_new_var_pointer)(__item, __name,          \
                                               __pointer)
#define weechat_infolist_new_var_string(__item, __name, __value)        \
    (weechat_plugin->infolist_new_var_string)(__item, __name, __value)
#define weechat_infolist_new_var_time(__item, __name, __time)           \
    (weechat_plugin->infolist_new_var_time)(__item, __name, __time)
#define weechat_infolist_next(__list)                                   \
    (weechat_plugin->infolist_next)(__list)
#define weechat_infolist_pointer(__item, __var)                         \
    (weechat_plugin->infolist_pointer)(__item, __var)
#define weechat_infolist_prev(__list)                                   \
    (weechat_plugin->infolist_prev)(__list)
#define weechat_infolist_reset_item_cursor(__list)                      \
    (weechat_plugin->infolist_reset_item_cursor)(__list)
#define weechat_infolist_search_var(__list, __name)                     \
    (weechat_plugin->infolist_search_var)(__list, __name)
#define weechat_infolist_string(__item, __var)                          \
    (weechat_plugin->infolist_string)(__item, __var)
#define weechat_infolist_time(__item, __var)                            \
    (weechat_plugin->infolist_time)(__item, __var)
#define weechat_key_bind(__context, __keys)                             \
    (weechat_plugin->key_bind)(__context, __keys)
#define weechat_key_unbind(__context, __key)                            \
    (weechat_plugin->key_unbind)(__context, __key)
#define weechat_list_add(__list, __string, __where, __user_data)        \
    (weechat_plugin->list_add)(__list, __string, __where, __user_data)
#define weechat_list_casesearch(__list, __string)                       \
    (weechat_plugin->list_casesearch)(__list, __string)
#define weechat_list_casesearch_pos(__list, __string)                   \
    (weechat_plugin->list_casesearch_pos)(__list, __string)
#define weechat_list_free(__list)                                       \
    (weechat_plugin->list_free)(__list)
#define weechat_list_get(__list, __index)                               \
    (weechat_plugin->list_get)(__list, __index)
#define weechat_list_new()                                              \
    (weechat_plugin->list_new)()
#define weechat_list_next(__item)                                       \
    (weechat_plugin->list_next)(__item)
#define weechat_list_prev(__item)                                       \
    (weechat_plugin->list_prev)(__item)
#define weechat_list_remove(__list, __item)                             \
    (weechat_plugin->list_remove)(__list, __item)
#define weechat_list_remove_all(__list)                                 \
    (weechat_plugin->list_remove_all)(__list)
#define weechat_list_search(__list, __string)                           \
    (weechat_plugin->list_search)(__list, __string)
#define weechat_list_search_pos(__list, __string)                       \
    (weechat_plugin->list_search_pos)(__list, __string)
#define weechat_list_set(__item, __value)                               \
    (weechat_plugin->list_set)(__item, __value)
#define weechat_list_size(__list)                                       \
    (weechat_plugin->list_size)(__list)
#define weechat_list_string(__item)                                     \
    (weechat_plugin->list_string)(__item)
#define weechat_list_user_data(__item)                                  \
    (weechat_plugin->list_user_data)(__item)
#define weechat_log_printf(__message, __argz...)                        \
    (weechat_plugin->log_printf)(__message, ##__argz)
#define weechat_mkdir(__directory, __mode)                              \
    (weechat_plugin->mkdir)(__directory, __mode)
#define weechat_mkdir_home(__directory, __mode)                         \
    (weechat_plugin->mkdir_home)(__directory, __mode)
#define weechat_mkdir_parents(__directory, __mode)                      \
    (weechat_plugin->mkdir_parents)(__directory, __mode)
#define weechat_network_connect_to(__proxy, __address,                  \
                                   __address_length)                    \
    (weechat_plugin->network_connect_to)(__proxy, __address,            \
                                         __address_length)
#define weechat_network_pass_proxy(__proxy, __sock, __address, __port)  \
    (weechat_plugin->network_pass_proxy)(__proxy, __sock, __address,    \
                                         __port)
#define weechat_ngettext(single,plural,number)                          \
    (weechat_plugin->ngettext)(single, plural, number)
#define weechat_nicklist_add_group(__buffer, __parent_group, __name,    \
                                   __color, __visible)                  \
    (weechat_plugin->nicklist_add_group)(__buffer, __parent_group,      \
                                         __name, __color, __visible)
#define weechat_nicklist_add_nick(__buffer, __group, __name, __color,   \
                                  __prefix, __prefix_color, __visible)  \
    (weechat_plugin->nicklist_add_nick)(__buffer, __group, __name,      \
                                        __color, __prefix,              \
                                        __prefix_color, __visible)
#define weechat_nicklist_get_next_item(__buffer, __group, __nick)       \
    (weechat_plugin->nicklist_get_next_item)(__buffer, __group, __nick)
#define weechat_nicklist_group_get_integer(__buffer, __group,           \
                                           __property)                  \
    (weechat_plugin->nicklist_group_get_integer)(__buffer, __group,     \
                                                 __property)
#define weechat_nicklist_group_get_pointer(__buffer, __group,           \
                                           __property)                  \
    (weechat_plugin->nicklist_group_get_pointer)(__buffer, __group,     \
                                                 __property)
#define weechat_nicklist_group_get_string(__buffer, __group,            \
                                          __property)                   \
    (weechat_plugin->nicklist_group_get_string)(__buffer, __group,      \
                                                __property)
#define weechat_nicklist_group_set(__buffer, __group, __property,       \
                                   __value)                             \
    (weechat_plugin->nicklist_group_set)(__buffer, __group, __property, \
                                         __value)
#define weechat_nicklist_nick_get_integer(__buffer, __nick, __property) \
    (weechat_plugin->nicklist_nick_get_integer)(__buffer, __nick,       \
                                                __property)
#define weechat_nicklist_nick_get_pointer(__buffer, __nick, __property) \
    (weechat_plugin->nicklist_nick_get_pointer)(__buffer, __nick,       \
                                                __property)
#define weechat_nicklist_nick_get_string(__buffer, __nick, __property)  \
    (weechat_plugin->nicklist_nick_get_string)(__buffer, __nick,        \
                                               __property)
#define weechat_nicklist_nick_set(__buffer, __nick, __property,         \
                                  __value)                              \
    (weechat_plugin->nicklist_nick_set)(__buffer, __nick, __property,   \
                                        __value)
#define weechat_nicklist_remove_all(__buffer)                           \
    (weechat_plugin->nicklist_remove_all)(__buffer)
#define weechat_nicklist_remove_group(__buffer, __group)                \
    (weechat_plugin->nicklist_remove_group)(__buffer, __group)
#define weechat_nicklist_remove_nick(__buffer, __nick)                  \
    (weechat_plugin->nicklist_remove_nick)(__buffer, __nick)
#define weechat_nicklist_search_group(__buffer, __from_group, __name)   \
    (weechat_plugin->nicklist_search_group)(__buffer, __from_group,     \
                                            __name)
#define weechat_nicklist_search_nick(__buffer, __from_group, __name)    \
    (weechat_plugin->nicklist_search_nick)(__buffer, __from_group,      \
                                           __name)
#define weechat_plugin_get_name(__plugin)                               \
    (weechat_plugin->plugin_get_name)(__plugin)
#define weechat_prefix(__prefix)                                        \
    (weechat_plugin->prefix)(__prefix)
#define weechat_printf(__buffer, __message, __argz...)                  \
    (weechat_plugin->printf_date_tags)(__buffer, 0, NULL, __message,    \
                                       ##__argz)
#define weechat_printf_date_tags(__buffer, __date, __tags, __message,   \
                                 __argz...)                             \
    (weechat_plugin->printf_date_tags)(__buffer, __date, __tags,        \
                                       __message, ##__argz)
#define weechat_printf_y(__buffer, __y, __message, __argz...)           \
    (weechat_plugin->printf_y)(__buffer, __y, __message, ##__argz)
#define weechat_strcasecmp(__string1, __string2)                        \
    (weechat_plugin->strcasecmp)(__string1, __string2)
#define weechat_strcasecmp_range(__string1, __string2, __range)         \
    (weechat_plugin->strcasecmp_range)(__string1, __string2, __range)
#define weechat_strcasestr(__string, __search)                          \
    (weechat_plugin->strcasestr)(__string, __search)
#define weechat_strcmp_ignore_chars(__string1, __string2,               \
                                    __chars_ignored, __case_sensitive)  \
    (weechat_plugin->strcmp_ignore_chars)(__string1, __string2,         \
                                          __chars_ignored,              \
                                          __case_sensitive)
#define weechat_string_base_decode(__base, __from, __to)                \
    (weechat_plugin->string_base_decode)(__base, __from, __to)
#define weechat_string_base_encode(__base, __from, __length, __to)      \
    (weechat_plugin->string_base_encode)(__base, __from, __length,      \
                                         __to)
#define weechat_string_build_with_split_string(__split_string,          \
                                               __separator)             \
    (weechat_plugin->string_build_with_split_string)(__split_string,    \
                                                     __separator)
#define weechat_string_convert_escaped_chars(__string)                  \
    (weechat_plugin->string_convert_escaped_chars)(__string)
#define weechat_string_dyn_alloc(__size_alloc)                          \
    (weechat_plugin->string_dyn_alloc)(__size_alloc)
#define weechat_string_dyn_concat(__string, __add)                      \
    (weechat_plugin->string_dyn_concat)(__string, __add)
#define weechat_string_dyn_copy(__string, __new_string)                 \
    (weechat_plugin->string_dyn_copy)(__string, __new_string)
#define weechat_string_dyn_free(__string, __free_string)                \
    (weechat_plugin->string_dyn_free)(__string, __free_string)
#define weechat_string_eval_expression(__expr, __pointers,              \
                                       __extra_vars, __options)         \
    (weechat_plugin->string_eval_expression)(__expr, __pointers,        \
                                             __extra_vars, __options)
#define weechat_string_eval_path_home(__path, __pointers,               \
                                      __extra_vars, __options)          \
    (weechat_plugin->string_eval_path_home)(__path, __pointers,         \
                                            __extra_vars, __options)
#define weechat_string_expand_home(__path)                              \
    (weechat_plugin->string_expand_home)(__path)
#define weechat_string_format_size(__size)                              \
    (weechat_plugin->string_format_size)(__size)
#define weechat_string_free_split(__split_string)                       \
    (weechat_plugin->string_free_split)(__split_string)
#define weechat_string_free_split_command(__split_command)              \
    (weechat_plugin->string_free_split_command)(__split_command)
#define weechat_string_has_highlight(__string, __highlight_words)       \
    (weechat_plugin->string_has_highlight)(__string, __highlight_words)
#define weechat_string_has_highlight_regex(__string, __regex)           \
    (weechat_plugin->string_has_highlight_regex)(__string, __regex)
#define weechat_string_hex_dump(__data, __data_size, __bytes_per_line,  \
                                __prefix, __suffix)                     \
    (weechat_plugin->string_hex_dump)(__data, __data_size,              \
                                      __bytes_per_line, __prefix,       \
                                      __suffix)
#define weechat_string_input_for_buffer(__string)                       \
    (weechat_plugin->string_input_for_buffer)(__string)
#define weechat_string_is_command_char(__string)                        \
    (weechat_plugin->string_is_command_char)(__string)
#define weechat_string_mask_to_regex(__mask)                            \
    (weechat_plugin->string_mask_to_regex)(__mask)
#define weechat_string_match(__string, __mask, __case_sensitive)        \
    (weechat_plugin->string_match)(__string, __mask, __case_sensitive)
#define weechat_string_match_list(__string, __masks, __case_sensitive)  \
    (weechat_plugin->string_match_list)(__string, __masks,              \
                                        __case_sensitive)
#define weechat_string_regcomp(__preg, __regex, __default_flags)        \
    (weechat_plugin->string_regcomp)(__preg, __regex, __default_flags)
#define weechat_string_regex_flags(__regex, __default_flags, __flags)   \
    (weechat_plugin->string_regex_flags)(__regex, __default_flags,      \
                                         __flags)
#define weechat_string_remove_color(__string, __replacement)            \
    (weechat_plugin->string_remove_color)(__string, __replacement)
#define weechat_string_remove_quotes(__string, __quotes)                \
    (weechat_plugin->string_remove_quotes)(__string, __quotes)
#define weechat_string_replace(__string, __search, __replace)           \
    (weechat_plugin->string_replace)(__string, __search, __replace)
#define weechat_string_replace_regex(__string, __regex, __replace,      \
                                     __reference_char, __callback,      \
                                     __callback_data)                   \
    (weechat_plugin->string_replace_regex)(__string, __regex,           \
                                           __replace,                   \
                                           __reference_char,            \
                                           __callback,                  \
                                           __callback_data)
#define weechat_string_split(__string, __separators, __strip_items,     \
                             __flags, __max, __num_items)               \
    (weechat_plugin->string_split)(__string, __separators,              \
                                   __strip_items, __flags,              \
                                   __max, __num_items)
#define weechat_string_split_command(__command, __separator)            \
    (weechat_plugin->string_split_command)(__command, __separator)
#define weechat_string_split_shell(__string, __num_items)               \
    (weechat_plugin->string_split_shell)(__string, __num_items)
#define weechat_string_strip(__string, __left, __right, __chars)        \
    (weechat_plugin->string_strip)(__string, __left, __right, __chars)
#define weechat_string_tolower(__string)                                \
    (weechat_plugin->string_tolower)(__string)
#define weechat_string_toupper(__string)                                \
    (weechat_plugin->string_toupper)(__string)
#define weechat_strlen_screen(__string)                                 \
    (weechat_plugin->strlen_screen)(__string)
#define weechat_strncasecmp(__string1, __string2, __max)                \
    (weechat_plugin->strncasecmp)(__string1, __string2, __max)
#define weechat_strncasecmp_range(__string1, __string2, __max, __range) \
    (weechat_plugin->strncasecmp_range)(__string1, __string2, __max,    \
                                        __range)
#define weechat_strndup(__string, __length)                             \
    (weechat_plugin->strndup)(__string, __length)
#define weechat_unhook(__hook)                                          \
    (weechat_plugin->unhook)( __hook)
#define weechat_unhook_all(__subplugin)                                 \
    (weechat_plugin->unhook_all)(weechat_plugin, __subplugin)
#define weechat_upgrade_close(__upgrade_file)                           \
    (weechat_plugin->upgrade_close)(__upgrade_file)
#define weechat_upgrade_new(__filename, __callback_read,                \
                            __callback_read_pointer,                    \
                            __callback_read_data)                       \
    (weechat_plugin->upgrade_new)(__filename, __callback_read,          \
                                  __callback_read_pointer,              \
                                  __callback_read_data)
#define weechat_upgrade_read(__upgrade_file)                            \
    (weechat_plugin->upgrade_read)(__upgrade_file)
#define weechat_upgrade_write_object(__upgrade_file, __object_id,       \
                                     __infolist)                        \
    (weechat_plugin->upgrade_write_object)(__upgrade_file, __object_id, \
                                           __infolist)
#define weechat_utf8_add_offset(__string, __offset)                     \
    (weechat_plugin->utf8_add_offset)(__string, __offset)
#define weechat_utf8_char_int(__string)                                 \
    (weechat_plugin->utf8_char_int)(__string)
#define weechat_utf8_char_size(__string)                                \
    (weechat_plugin->utf8_char_size)(__string)
#define weechat_utf8_char_size_screen(__string)                         \
    (weechat_plugin->utf8_char_size_screen)(__string)
#define weechat_utf8_charcasecmp(__string1, __string2)                  \
    (weechat_plugin->utf8_charcasecmp)(__string1, __string2)
#define weechat_utf8_charcmp(__string1, __string2)                      \
    (weechat_plugin->utf8_charcmp)(__string1, __string2)
#define weechat_utf8_has_8bits(__string)                                \
    (weechat_plugin->utf8_has_8bits)(__string)
#define weechat_utf8_is_valid(__string, __length, __error)              \
    (weechat_plugin->utf8_is_valid)(__string, __length, __error)
#define weechat_utf8_next_char(__string)                                \
    (weechat_plugin->utf8_next_char)(__string)
#define weechat_utf8_normalize(__string, __char)                        \
    (weechat_plugin->utf8_normalize)(__string, __char)
#define weechat_utf8_pos(__string, __real_pos)                          \
    (weechat_plugin->utf8_pos)(__string, __real_pos)
#define weechat_utf8_prev_char(__start, __string)                       \
    (weechat_plugin->utf8_prev_char)(__start, __string)
#define weechat_utf8_real_pos(__string, __pos)                          \
    (weechat_plugin->utf8_real_pos)(__string, __pos)
#define weechat_utf8_strlen(__string)                                   \
    (weechat_plugin->utf8_strlen)(__string)
#define weechat_utf8_strlen_screen(__string)                            \
    (weechat_plugin->utf8_strlen_screen)(__string)
#define weechat_utf8_strndup(__string, __length)                        \
    (weechat_plugin->utf8_strndup)(__string, __length)
#define weechat_utf8_strnlen(__string, __bytes)                         \
    (weechat_plugin->utf8_strnlen)(__string, __bytes)
#define weechat_util_get_time_string(__date)                            \
    (weechat_plugin->util_get_time_string)(__date)
#define weechat_util_timeval_add(__time, __interval)                    \
    (weechat_plugin->util_timeval_add)(__time, __interval)
#define weechat_util_timeval_cmp(__time1, __time2)                      \
    (weechat_plugin->util_timeval_cmp)(__time1, __time2)
#define weechat_util_timeval_diff(__time1, __time2)                     \
    (weechat_plugin->util_timeval_diff)(__time1, __time2)
#define weechat_util_version_number(__version)                          \
    (weechat_plugin->util_version_number)(__version)
#define weechat_va_format(__format)                                     \
    va_list argptr;                                                     \
    int vaa_size, vaa_num;                                              \
    char *vbuffer, *vaa_buffer2;                                        \
    vaa_size = 1024;                                                    \
    vbuffer = malloc (vaa_size);                                        \
    if (vbuffer)                                                        \
    {                                                                   \
        while (1)                                                       \
        {                                                               \
            va_start (argptr, __format);                                \
            vaa_num = vsnprintf (vbuffer, vaa_size, __format, argptr);  \
            va_end (argptr);                                            \
            if ((vaa_num >= 0) && (vaa_num < vaa_size))                 \
                break;                                                  \
            vaa_size = (vaa_num >= 0) ? vaa_num + 1 : vaa_size * 2;     \
            vaa_buffer2 = realloc (vbuffer, vaa_size);                  \
            if (!vaa_buffer2)                                           \
            {                                                           \
                free (vbuffer);                                         \
                vbuffer = NULL;                                         \
                break;                                                  \
            }                                                           \
            vbuffer = vaa_buffer2;                                      \
        }                                                               \
    }
#define weechat_window_get_integer(__window, __property)                \
    (weechat_plugin->window_get_integer)(__window, __property)
#define weechat_window_get_pointer(__window, __property)                \
    (weechat_plugin->window_get_pointer)(__window, __property)
#define weechat_window_get_string(__window, __property)                 \
    (weechat_plugin->window_get_string)(__window, __property)
#define weechat_window_search_with_buffer(__buffer)                     \
    (weechat_plugin->window_search_with_buffer)(__buffer)
#define weechat_window_set_title(__title)                               \
    (weechat_plugin->window_set_title)(__title)
