



#include<time.h>







#include<string.h>



#include<math.h>




#define node_foreach_child(node, func) node_foreach_child_full(node,func,0,NULL)
#define node_foreach_child_data(node, func, user_data) node_foreach_child_full(node,func,1,user_data)




#define item_unload(a) g_object_unref(a)
#define ITEM_VIEW_TYPE (itemview_get_type ())



#define UPDATE_REQUEST_TYPE (update_request_get_type ())

#define FEED_LIST_VIEW_TYPE (feed_list_view_get_type ())

#define IS_FEED(node) (node->type == feed_get_node_type ())

#define SUBSCRIPTION_TYPE(subscription)	(subscription->type)


#define NODE_TYPE(node)	(node->type)

#define AUTH_DIALOG_TYPE (auth_dialog_get_type ())




#define FEED_LIST_TYPE (feedlist_get_type ())

#define feedlist_foreach(func) node_foreach_child(feedlist_get_root(), func)
#define feedlist_foreach_data(func, user_data) node_foreach_child_data(feedlist_get_root(), func, user_data)
#define PRETTY_FUNCTION ""

#define debug0(level, fmt) if ((debug_level) & level) debug_printf (G_STRLOC, PRETTY_FUNCTION, level,fmt)
#define debug1(level, fmt, A) if ((debug_level) & level) debug_printf (G_STRLOC, PRETTY_FUNCTION, level,fmt, A)
#define debug2(level, fmt, A, B) if ((debug_level) & level) debug_printf (G_STRLOC, PRETTY_FUNCTION, level,fmt, A, B)
#define debug3(level, fmt, A, B, C) if ((debug_level) & level) debug_printf (G_STRLOC, PRETTY_FUNCTION, level,fmt, A, B, C)
#define debug4(level, fmt, A, B, C, D) if ((debug_level) & level) debug_printf (G_STRLOC, PRETTY_FUNCTION, level,fmt, A, B, C, D)
#define debug5(level, fmt, A, B, C, D, E) if ((debug_level) & level) debug_printf (G_STRLOC, PRETTY_FUNCTION, level,fmt, A, B, C, D, E)
#define debug6(level, fmt, A, B, C, D, E, F) if ((debug_level) & level) debug_printf (G_STRLOC, PRETTY_FUNCTION, level,fmt, A, B, C, D, E, F)
#define debug_end_measurement(level, name) if ((debug_level) & level) debug_end_measurement_func (PRETTY_FUNCTION, level, name)
#define debug_start_measurement(level) if ((debug_level) & level) debug_start_measurement_func (PRETTY_FUNCTION)

#define CONFIRM_MARK_ALL_READ 		"confirm-mark-all-read"
#define DEFER_DELETE_MODE               "defer-delete-mode"
#define DOWNLOAD_CUSTOM_COMMAND 	"download-custom-command"

#define conf_get_bool_value(key, value) conf_get_bool_value_from_schema (NULL, key, value)
#define conf_get_int_value(key, value) conf_get_int_value_from_schema (NULL, key, value)
#define conf_get_str_value(key, value) conf_get_str_value_from_schema (NULL, key, value)
#define conf_get_strv_value(key, value) conf_get_strv_value_from_schema (NULL, key, value)
#    define N_(String) gettext_noop (String)
#  define Q_(String) g_strip_context ((String), gettext (String))
#  define _(String) dgettext (PACKAGE, String)


#  define bindtextdomain(Domain,Directory) (Domain)
#  define dcgettext(Domain,Message,Type) (Message)
#  define dgettext(Domain,Message) (Message)
#  define gettext(String) (String)
#define strsep(a,b) common_strsep(a,b)
#  define textdomain(String) (String)

