#include<stdio.h>

#include<unistd.h>






#include<time.h>


#include<sys/wait.h>



#include<string.h>






#define node_foreach_child(node, func) node_foreach_child_full(node,func,0,NULL)
#define node_foreach_child_data(node, func, user_data) node_foreach_child_full(node,func,1,user_data)




#define item_unload(a) g_object_unref(a)


#define IS_FEED(node) (node->type == feed_get_node_type ())

#define SUBSCRIPTION_TYPE(subscription)	(subscription->type)


#define UPDATE_REQUEST_TYPE (update_request_get_type ())

#define NODE_TYPE(node)	(node->type)

#define LIFEREA_IS_PLUGINS_ENGINE(obj)           (G_TYPE_CHECK_INSTANCE_TYPE((obj), LIFEREA_TYPE_PLUGINS_ENGINE))
#define LIFEREA_IS_PLUGINS_ENGINE_CLASS(klass)   (G_TYPE_CHECK_CLASS_TYPE ((klass), LIFEREA_TYPE_PLUGINS_ENGINE))
#define LIFEREA_PLUGINS_ENGINE(obj)              (G_TYPE_CHECK_INSTANCE_CAST((obj), LIFEREA_TYPE_PLUGINS_ENGINE, LifereaPluginsEngine))
#define LIFEREA_PLUGINS_ENGINE_CLASS(klass)      (G_TYPE_CHECK_CLASS_CAST((klass), LIFEREA_TYPE_PLUGINS_ENGINE, LifereaPluginsEngineClass))
#define LIFEREA_PLUGINS_ENGINE_GET_CLASS(obj)    (G_TYPE_INSTANCE_GET_CLASS((obj), LIFEREA_TYPE_PLUGINS_ENGINE, LifereaPluginsEngineClass))
#define LIFEREA_TYPE_PLUGINS_ENGINE              (liferea_plugins_engine_get_type ())


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
#    define N_(String) gettext_noop (String)
#  define Q_(String) g_strip_context ((String), gettext (String))
#  define _(String) dgettext (PACKAGE, String)


#  define bindtextdomain(Domain,Directory) (Domain)
#  define dcgettext(Domain,Message,Type) (Message)
#  define dgettext(Domain,Message) (Message)
#  define gettext(String) (String)
#define strsep(a,b) common_strsep(a,b)
#  define textdomain(String) (String)
#define LIFEREA_AUTH_ACTIVATABLE(obj)		(G_TYPE_CHECK_INSTANCE_CAST ((obj), LIFEREA_AUTH_ACTIVATABLE_TYPE, LifereaAuthActivatable))
#define LIFEREA_AUTH_ACTIVATABLE_GET_IFACE(obj)	(G_TYPE_INSTANCE_GET_INTERFACE ((obj), LIFEREA_AUTH_ACTIVATABLE_TYPE, LifereaAuthActivatableInterface))
#define LIFEREA_AUTH_ACTIVATABLE_IFACE(obj)	(G_TYPE_CHECK_CLASS_CAST ((obj), LIFEREA_AUTH_ACTIVATABLE_TYPE, LifereaAuthActivatableInterface))
#define LIFEREA_IS_AUTH_ACTIVATABLE(obj)	(G_TYPE_CHECK_INSTANCE_TYPE ((obj), LIFEREA_AUTH_ACTIVATABLE_TYPE))

