#include<inttypes.h>




#include<iostream>
#include<memory>





#include<list>

#include<stdatomic.h>

#include<time.h>
#include<stdlib.h>




#include<stdexcept>

#include<type_traits>


#include<map>

#include<sys/types.h>

#include<atomic>
#include<stdarg.h>


#include<assert.h>



#include<stddef.h>

#include<algorithm>
#include<math.h>





#include<stdio.h>







#include<string>
#include<set>
#include<cassert>




#include<limits>

#include<string.h>

#include<vector>

#include<typeinfo>

#  define ETIMEDOUT 10060 
# define LIBVLC_NEED_CONDVAR
# define LIBVLC_NEED_RWLOCK
# define LIBVLC_NEED_SEMAPHORE
# define LIBVLC_NEED_SLEEP
# define LIBVLC_USE_PTHREAD           1
# define LIBVLC_USE_PTHREAD_CLEANUP   1
#define VLC_HARD_MIN_SLEEP  VLC_TICK_FROM_MS(10)   
#define VLC_SOFT_MIN_SLEEP  VLC_TICK_FROM_SEC(9)   
# define VLC_STATIC_COND { 0 }
#define VLC_STATIC_MUTEX { false, { { false, 0 } } }
#define VLC_STATIC_ONCE { 0, VLC_STATIC_MUTEX }
# define VLC_STATIC_RWLOCK { VLC_STATIC_MUTEX, VLC_STATIC_COND, 0 }

# define VLC_THREAD_CANCELED NULL
# define VLC_THREAD_PRIORITY_AUDIO    MAKESHORT(PRTYD_MAXIMUM, PRTYC_REGULAR)
# define VLC_THREAD_PRIORITY_HIGHEST  MAKESHORT(0, PRTYC_TIMECRITICAL)
# define VLC_THREAD_PRIORITY_INPUT \
                                    MAKESHORT(PRTYD_MAXIMUM / 2, PRTYC_REGULAR)
# define VLC_THREAD_PRIORITY_LOW      0
# define VLC_THREAD_PRIORITY_OUTPUT \
                                    MAKESHORT(PRTYD_MAXIMUM / 2, PRTYC_REGULAR)
# define VLC_THREAD_PRIORITY_VIDEO    0
#define VLC_TIMER_DISARM    (0)
#define VLC_TIMER_FIRE_ONCE (0)
# define _APPLE_C_SOURCE    1 
# define check_deadline( d ) \
    (__builtin_constant_p(d) ? impossible_deadline(d) : d)
# define check_delay( d ) \
    ((__builtin_constant_p(d < VLC_HARD_MIN_SLEEP) \
   && (d < VLC_HARD_MIN_SLEEP)) \
       ? impossible_delay(d) \
       : ((__builtin_constant_p(d < VLC_SOFT_MIN_SLEEP) \
       && (d < VLC_SOFT_MIN_SLEEP)) \
           ? harmful_delay(d) \
           : d))
#define mutex_cleanup_push( lock ) vlc_cleanup_push (vlc_cleanup_lock, lock)
# define poll(u,n,t) vlc_poll(u, n, t)
# define pthread_sigmask  sigprocmask
#  define vlc_cleanup_pop( ) \
        vlc_control_cancel (VLC_CLEANUP_POP); \
    } while (0)
#  define vlc_cleanup_push(routine, arg) do { (routine, arg)
#define vlc_global_lock( n ) vlc_global_mutex(n, true)
#define vlc_global_unlock( n ) vlc_global_mutex(n, false)
#define vlc_mutex_assert(m) assert(vlc_mutex_marked(m))
#define vlc_tick_sleep(d) vlc_tick_sleep(check_delay(d))
#define vlc_tick_wait(d) vlc_tick_wait(check_deadline(d))
#define KEY_BACKSPACE              0x08
#define KEY_BRIGHTNESS_DOWN  0x00630000
#define KEY_BRIGHTNESS_UP    0x00620000
#define KEY_BROWSER_BACK     0x003F0000
#define KEY_BROWSER_FAVORITES 0x00440000
#define KEY_BROWSER_FORWARD  0x00400000
#define KEY_BROWSER_HOME     0x00450000
#define KEY_BROWSER_REFRESH  0x00410000
#define KEY_BROWSER_SEARCH   0x00430000
#define KEY_BROWSER_STOP     0x00420000
#define KEY_DELETE           0x00360000
#define KEY_DOWN             0x00240000
#define KEY_END              0x00340000
#define KEY_ENTER                  0x0D
#define KEY_ESC                    0x1B
#define KEY_F1               0x00270000
#define KEY_F10              0x00300000
#define KEY_F11              0x00310000
#define KEY_F12              0x00320000
#define KEY_F2               0x00280000
#define KEY_F3               0x00290000
#define KEY_F4               0x002A0000
#define KEY_F5               0x002B0000
#define KEY_F6               0x002C0000
#define KEY_F7               0x002D0000
#define KEY_F8               0x002E0000
#define KEY_F9               0x002F0000
#define KEY_HOME             0x00330000
#define KEY_INSERT           0x00350000
#define KEY_LEFT             0x00210000
#define KEY_MEDIA_ANGLE      0x00540000
#define KEY_MEDIA_AUDIO      0x00530000
#define KEY_MEDIA_FORWARD    0x004F0000
#define KEY_MEDIA_FRAME_NEXT 0x00570000
#define KEY_MEDIA_FRAME_PREV 0x00560000
#define KEY_MEDIA_MENU       0x005A0000
#define KEY_MEDIA_NEXT_TRACK 0x00490000
#define KEY_MEDIA_PLAY_PAUSE 0x004C0000
#define KEY_MEDIA_PREV_TRACK 0x004A0000
#define KEY_MEDIA_RECORD     0x004D0000
#define KEY_MEDIA_REPEAT     0x00500000
#define KEY_MEDIA_REWIND     0x004E0000
#define KEY_MEDIA_SELECT     0x00580000
#define KEY_MEDIA_SHUFFLE    0x00510000
#define KEY_MEDIA_STOP       0x004B0000
#define KEY_MEDIA_SUBTITLE   0x00520000
#define KEY_MEDIA_TIME       0x00550000
#define KEY_MEDIA_VIEW       0x00590000
#define KEY_MENU             0x00370000
#define KEY_MODIFIER         0xFF000000
#define KEY_MODIFIER_ALT     0x01000000
#define KEY_MODIFIER_COMMAND 0x10000000
#define KEY_MODIFIER_CTRL    0x04000000
#define KEY_MODIFIER_META    0x08000000
#define KEY_MODIFIER_SHIFT   0x02000000
#define KEY_MOUSEWHEELDOWN   0x00F10000
#define KEY_MOUSEWHEELLEFT   0x00F20000
#define KEY_MOUSEWHEELRIGHT  0x00F30000
#define KEY_MOUSEWHEELUP     0x00F00000
#define KEY_MOUSEWHEEL_FROM_BUTTON(button) \
    (KEY_MOUSEWHEELUP | ((button - MOUSE_BUTTON_WHEEL_UP) << 16))
#define KEY_PAGEDOWN         0x003A0000
#define KEY_PAGEUP           0x00390000
#define KEY_PAUSE            0x003D0000
#define KEY_PRINT            0x003B0000
#define KEY_RIGHT            0x00220000
#define KEY_TAB                    0x09
#define KEY_UNSET            0x00000000
#define KEY_UP               0x00230000
#define KEY_VOLUME_DOWN      0x00470000
#define KEY_VOLUME_MUTE      0x00460000
#define KEY_VOLUME_UP        0x00480000
#define KEY_ZOOM_IN          0x00600000
#define KEY_ZOOM_OUT         0x00610000
#define VLC_ACTIONS_H 1
#define vlc_actions_get_key_names(x) vlc_actions_get_key_names(VLC_OBJECT(x))
#define vlc_actions_get_keycodes(a, b, c, d) vlc_actions_get_keycodes(VLC_OBJECT(a), b, c, d)

#define ATTRIBUTE_PACKED __attribute__ ((packed))
#define COMMAND_DATA_SIZE 8
#define PRAGMA_PACK 0

#define _VLC_MOUSE_H 1
#   define DIR_SEP "\\"
#   define DIR_SEP_CHAR '\\'
#define EMPTY_STR(str) (!str || !*str)
#define FREENULL(a) do { free( a ); a = NULL; } while(0)
#define GetDWBE(p) U32_AT(p)
#define GetQWBE(p) U64_AT(p)
#define GetWBE(p)  U16_AT(p)
#   define INCL_BASE
#   define INCL_PM
#define LICENSE_MSG \
  _("This program comes with NO WARRANTY, to the extent permitted by " \
    "law.\nYou may redistribute it under the terms of the GNU General " \
    "Public License;\nsee the file named COPYING for details.\n" \
    "Written by the VideoLAN team; see the AUTHORS file.\n")
#   define OS2EMX_PLAIN_CHAR
#       define O_NONBLOCK 0
#       define PATH_MAX MAX_PATH
#   define PATH_SEP ";"
#   define PATH_SEP_CHAR ';'
 #define PRId64 "lld"
 #define PRIi64 "lli"
 #define PRIo64 "llo"
 #define PRIu64 "llu"
 #define PRIx64 "llx"
#define VLC_API VLC_EXTERN VLC_EXPORT
#define VLC_CLIP(v, min, max)    __MIN(__MAX((v), (min)), (max))
# define VLC_COMMON_H 1
# define VLC_DEPRECATED __attribute__((deprecated))
#  define VLC_DEPRECATED_ENUM __attribute__((deprecated))
#define VLC_EBADVAR        (-7)
#define VLC_EGENERIC       (-1)
#define VLC_ENOITEM        (-8)
#define VLC_ENOMEM         (-2)
#define VLC_ENOMOD         (-4)
#define VLC_ENOOBJ         (-5)
#define VLC_ENOVAR         (-6)
#define VLC_ETIMEOUT       (-3)
# define VLC_EXPORT __declspec(dllexport)
# define VLC_EXTERN extern "C"
#  define VLC_FORMAT(x,y) __attribute__ ((format(gnu_printf,x,y)))
# define VLC_FORMAT_ARG(x) __attribute__ ((format_arg(x)))
#   define VLC_FOURCC( a, b, c, d ) \
        ( ((uint32_t)d) | ( ((uint32_t)c) << 8 ) \
           | ( ((uint32_t)b) << 16 ) | ( ((uint32_t)a) << 24 ) )
# define VLC_GCC_VERSION(maj,min) \
    (("__GNUC__" > (maj)) || ("__GNUC__" == (maj) && "__GNUC_MINOR__" >= (min)))
#define VLC_INT_FUNC(basename) \
        VLC_INT_FUNC_TYPE(basename, unsigned, ) \
        VLC_INT_FUNC_TYPE(basename, unsigned long, l) \
        VLC_INT_FUNC_TYPE(basename, unsigned long long, ll)
# define VLC_INT_FUNC_TYPE(basename,type,suffix) \
VLC_USED static inline int vlc_##basename##suffix(type x) \
{ \
    return __builtin_##basename##suffix(x); \
}
# define VLC_INT_GENERIC(func,x) \
    _Generic((x), \
        unsigned char:      func(x), \
          signed char:      func(x), \
        unsigned short:     func(x), \
          signed short:     func(x), \
        unsigned int:       func(x), \
          signed int:       func(x), \
        unsigned long:      func##l(x), \
          signed long:      func##l(x), \
        unsigned long long: func##ll(x), \
          signed long long: func##ll(x))
# define VLC_MALLOC __attribute__ ((malloc))
#define VLC_SUCCESS        (-0)
#   define VLC_TWOCC( a, b ) \
        ( (uint16_t)(b) | ( (uint16_t)(a) << 8 ) )
#define VLC_UNUSED(x) (void)(x)
# define VLC_USED __attribute__ ((warn_unused_result))
# define VLC_WEAK __attribute__((weak))
#           define _OFF_T_
#   define __MAX(a, b)   ( ((a) > (b)) ? (a) : (b) )
#   define __MIN(a, b)   ( ((a) < (b)) ? (a) : (b) )
# define add_overflow(a,b,r) \
    _Generic(*(r), \
        unsigned: uadd_overflow(a, b, (unsigned *)(r)), \
        unsigned long: uaddl_overflow(a, b, (unsigned long *)(r)), \
        unsigned long long: uaddll_overflow(a, b, (unsigned long long *)(r)))
# define clz(x) \
    _Generic((x), \
        unsigned char: (vlc_clz(x) - (sizeof (unsigned) - 1) * 8), \
        unsigned short: (vlc_clz(x) \
        - (sizeof (unsigned) - sizeof (unsigned short)) * 8), \
        unsigned: vlc_clz(x), \
        unsigned long: vlc_clzl(x), \
        unsigned long long: vlc_clzll(x))
#define container_of(ptr, type, member) \
    ((type *)(((char *)(ptr)) - offsetof(type, member)))
# define ctz(x) VLC_INT_GENERIC(vlc_ctz, x)
# define hton16(i) ((uint16_t)(i))
# define hton32(i) ((uint32_t)(i))
# define hton64(i) ((uint64_t)(i))
# define likely(p)     __builtin_expect(!!(p), 1)
#define mul_overflow(a,b,r) \
    _Generic(*(r), \
        unsigned: umul_overflow(a, b, (unsigned *)(r)), \
        unsigned long: umull_overflow(a, b, (unsigned long *)(r)), \
        unsigned long long: umulll_overflow(a, b, (unsigned long long *)(r)))
#define ntoh16(i) hton16(i)
#define ntoh32(i) hton32(i)
#define ntoh64(i) hton64(i)
#           define off_t long long
# define parity(x) VLC_INT_GENERIC(vlc_parity, x)
 #define snprintf __mingw_snprintf
#  define swab(a,b,c)  swab((char*) (a), (char*) (b), (c))
 #define swprintf _snwprintf
# define unlikely(p)   __builtin_expect(!!(p), 0)
# define unreachable() __builtin_unreachable()
# define vlc_assert(pred) assert(pred)
#define vlc_assert_unreachable() (vlc_assert(!"unreachable"), unreachable())
#define vlc_pgettext( ctx, id ) \
        vlc_pgettext_aux( ctx "\004" id, id )
# define vlc_popcount(x) \
    _Generic((x), \
        signed char:  vlc_popcount((unsigned char)(x)), \
        signed short: vlc_popcount((unsigned short)(x)), \
        default: VLC_INT_GENERIC(vlc_popcount ,x))
 #define vsnprintf __mingw_vsnprintf
#define VLC_CONFIGURATION_H 1
#define config_ChainParse( a, b, c, d ) config_ChainParse( VLC_OBJECT(a), b, c, d )
#define config_SaveConfigFile(a) config_SaveConfigFile(VLC_OBJECT(a))
#define VLC_VARIABLES_H 1
#define VLC_VAR_ADDCHOICE           0x0020
#define VLC_VAR_ADDRESS   0x0070
#define VLC_VAR_BOOL      0x0020
#define VLC_VAR_CHOICESCOUNT        0x0026
#define VLC_VAR_CLASS     0x00f0
#define VLC_VAR_CLEARCHOICES        0x0022
#define VLC_VAR_COORDS    0x00A0
#define VLC_VAR_DELCHOICE           0x0021
#define VLC_VAR_DOINHERIT 0x8000
#define VLC_VAR_FLAGS     0xff00
#define VLC_VAR_FLOAT     0x0050
#define VLC_VAR_GETCHOICES          0x0024
#define VLC_VAR_GETMAX              0x0017
#define VLC_VAR_GETMIN              0x0016
#define VLC_VAR_GETSTEP             0x0018
#define VLC_VAR_GETTEXT             0x0015
#define VLC_VAR_HASCHOICE 0x0100
#define VLC_VAR_INTEGER   0x0030
#define VLC_VAR_ISCOMMAND 0x2000
#define VLC_VAR_SETMINMAX           0x0027
#define VLC_VAR_SETSTEP             0x0012
#define VLC_VAR_SETTEXT             0x0014
#define VLC_VAR_SETVALUE            0x0013
#define VLC_VAR_STRING    0x0040
#define VLC_VAR_TYPE      0x00ff
#define VLC_VAR_VOID      0x0010
#define var_AddCallback(a,b,c,d) var_AddCallback(VLC_OBJECT(a), b, c, d)
#define var_AddListCallback(a,b,c,d) \
        var_AddListCallback(VLC_OBJECT(a), b, c, d)
#define var_Change(a,b,...) var_Change(VLC_OBJECT(a), b, __VA_ARGS__)
#define var_CountChoices(a,b) var_CountChoices(VLC_OBJECT(a),b)
#define var_Create(a,b,c) var_Create(VLC_OBJECT(a), b, c)
#define var_CreateGetAddress(a,b) var_CreateGetAddress( VLC_OBJECT(a), b)
#define var_CreateGetBool(a,b) var_CreateGetBool(VLC_OBJECT(a), b)
#define var_CreateGetBoolCommand(a,b)   var_CreateGetBoolCommand( VLC_OBJECT(a),b)
#define var_CreateGetFloat(a,b) var_CreateGetFloat(VLC_OBJECT(a), b)
#define var_CreateGetFloatCommand(a,b)   var_CreateGetFloatCommand( VLC_OBJECT(a),b)
#define var_CreateGetInteger(a,b) var_CreateGetInteger(VLC_OBJECT(a), b)
#define var_CreateGetIntegerCommand(a,b)   var_CreateGetIntegerCommand( VLC_OBJECT(a),b)
#define var_CreateGetNonEmptyString(a,b) \
        var_CreateGetNonEmptyString(VLC_OBJECT(a), b)
#define var_CreateGetNonEmptyStringCommand(a,b)   var_CreateGetNonEmptyStringCommand( VLC_OBJECT(a),b)
#define var_CreateGetString(a,b) var_CreateGetString(VLC_OBJECT(a), b)
#define var_CreateGetStringCommand(a,b)   var_CreateGetStringCommand( VLC_OBJECT(a),b)
#define var_DecInteger(a,b) var_DecInteger(VLC_OBJECT(a), b)
#define var_DelCallback(a,b,c,d) var_DelCallback(VLC_OBJECT(a), b, c, d)
#define var_DelListCallback(a,b,c,d) \
        var_DelListCallback(VLC_OBJECT(a), b, c, d)
#define var_Destroy(a,b) var_Destroy(VLC_OBJECT(a), b)
#define var_Get(a,b,c) var_Get(VLC_OBJECT(a), b, c)
#define var_GetAddress(a,b) var_GetAddress(VLC_OBJECT(a),b)
#define var_GetBool(a,b) var_GetBool(VLC_OBJECT(a),b)
#define var_GetChecked(o,n,t,v) var_GetChecked(VLC_OBJECT(o), n, t, v)
#define var_GetCoords(o,n,x,y) var_GetCoords(VLC_OBJECT(o), n, x, y)
#define var_GetFloat(a,b) var_GetFloat(VLC_OBJECT(a),b)
#define var_GetInteger(a,b) var_GetInteger(VLC_OBJECT(a),b)
#define var_GetNonEmptyString(a,b) var_GetNonEmptyString( VLC_OBJECT(a),b)
#define var_GetString(a,b) var_GetString(VLC_OBJECT(a),b)
#define var_IncInteger(a,b) var_IncInteger(VLC_OBJECT(a), b)
#define var_InheritAddress(o, n) var_InheritAddress(VLC_OBJECT(o), n)
#define var_InheritBool(o, n) var_InheritBool(VLC_OBJECT(o), n)
#define var_InheritFloat(o, n) var_InheritFloat(VLC_OBJECT(o), n)
#define var_InheritInteger(o, n) var_InheritInteger(VLC_OBJECT(o), n)
#define var_InheritString(o, n) var_InheritString(VLC_OBJECT(o), n)
#define var_InheritURational(a,b,c,d) var_InheritURational(VLC_OBJECT(a), b, c, d)
#define var_LocationParse(o, m, p) var_LocationParse(VLC_OBJECT(o), m, p)
#define var_NAndInteger(a,b,c) var_NAndInteger(VLC_OBJECT(a), b, c)
#define var_OrInteger(a,b,c) var_OrInteger(VLC_OBJECT(a), b, c)
#define var_Set(a,b,c) var_Set(VLC_OBJECT(a), b, c)
#define var_SetAddress(o, n, p) var_SetAddress(VLC_OBJECT(o), n, p)
#define var_SetBool(a,b,c) var_SetBool(VLC_OBJECT(a), b, c)
#define var_SetChecked(o,n,t,v) var_SetChecked(VLC_OBJECT(o), n, t, v)
#define var_SetCoords(o,n,x,y) var_SetCoords(VLC_OBJECT(o), n, x, y)
#define var_SetFloat(a,b,c) var_SetFloat(VLC_OBJECT(a), b, c)
#define var_SetInteger(a,b,c) var_SetInteger(VLC_OBJECT(a), b, c)
#define var_SetString(a,b,c) var_SetString(VLC_OBJECT(a), b, c)
#define var_ToggleBool(a,b) var_ToggleBool(VLC_OBJECT(a),b )
#define var_TriggerCallback(a,b) var_TriggerCallback(VLC_OBJECT(a), b)
#define var_Type(a,b) var_Type(VLC_OBJECT(a), b)
# define VLC_OBJECT(x) \
    _Generic((x)->obj, \
        struct vlc_object_marker *: (x), \
        default: (&((x)->obj)) \
    )
# define vlc_object_cast(t)
#define vlc_object_create(a,b) vlc_object_create( VLC_OBJECT(a), b )
#define vlc_object_delete(obj) vlc_object_delete(VLC_OBJECT(obj))
#define vlc_object_find_name(a,b) \
    vlc_object_find_name( VLC_OBJECT(a),b)
#define vlc_object_get_name(obj) var_GetString(obj, "module-name")
#define vlc_object_instance(o) vlc_object_instance(VLC_OBJECT(o))
#define vlc_object_logger(o) vlc_object_logger(VLC_OBJECT(o))
#define vlc_object_parent(o) vlc_object_parent(VLC_OBJECT(o))

#define msg_Dbg(p_this, ...) \
    msg_Generic(p_this, VLC_MSG_DBG, __VA_ARGS__)
#define msg_Err(p_this, ...) \
    msg_Generic(p_this, VLC_MSG_ERR, __VA_ARGS__)
#define msg_Generic(o, p, ...) \
    vlc_object_Log(VLC_OBJECT(o), p, vlc_module_name, "__FILE__", "__LINE__", \
                   __func__, __VA_ARGS__)
#define msg_GenericVa(o, p, fmt, ap) \
    vlc_object_vaLog(VLC_OBJECT(o), p, vlc_module_name, "__FILE__", "__LINE__", \
                     __func__, fmt, ap)
#define msg_Info(p_this, ...) \
    msg_Generic(p_this, VLC_MSG_INFO, __VA_ARGS__)
#define msg_Warn(p_this, ...) \
    msg_Generic(p_this, VLC_MSG_WARN, __VA_ARGS__)
#define vlc_debug(logger, ...)   vlc_log_gen(logger, VLC_MSG_DBG,  __VA_ARGS__)
#define vlc_error(logger, ...)   vlc_log_gen(logger, VLC_MSG_ERR,  __VA_ARGS__)
#define vlc_info(logger, ...)    vlc_log_gen(logger, VLC_MSG_INFO, __VA_ARGS__)
#define vlc_log_gen(logger, prio, ...) \
        vlc_Log(&(logger), prio, "generic", vlc_module_name, \
                "__FILE__", "__LINE__", __func__, __VA_ARGS__)
#define vlc_warning(logger, ...) vlc_log_gen(logger, VLC_MSG_WARN, __VA_ARGS__)
#define ARRAY_APPEND(array, elem)                                           \
  do {                                                                      \
    _ARRAY_GROW1(array);                                                    \
    (array).p_elems[(array).i_size] = elem;                                 \
    (array).i_size++;                                                       \
  } while(0)
#define ARRAY_BSEARCH(array, elem, zetype, key, answer) \
    BSEARCH( (array).p_elems, (array).i_size, elem, zetype, key, answer)
#define ARRAY_FIND(array, p, idx)                                           \
  TAB_FIND((array).i_size, (array).p_elems, p, idx)
#define ARRAY_FOREACH(item, array) \
    for (int array_index_##item = 0; \
         array_index_##item < (array).i_size && \
            ((item) = (array).p_elems[array_index_##item], 1); \
         ++array_index_##item)
#define ARRAY_INIT(array)                                                   \
  do {                                                                      \
    (array).i_alloc = 0;                                                    \
    (array).i_size = 0;                                                     \
    (array).p_elems = NULL;                                                 \
  } while(0)
#define ARRAY_INSERT(array,elem,pos)                                        \
  do {                                                                      \
    _ARRAY_GROW1(array);                                                    \
    if( (array).i_size - (pos) ) {                                          \
        memmove( (array).p_elems + (pos) + 1, (array).p_elems + (pos),      \
                 ((array).i_size-(pos)) * sizeof(*(array).p_elems) );       \
    }                                                                       \
    (array).p_elems[pos] = elem;                                            \
    (array).i_size++;                                                       \
  } while(0)
#define ARRAY_REMOVE(array,pos)                                             \
  do {                                                                      \
    if( (array).i_size - (pos) - 1 )                                        \
    {                                                                       \
        memmove( (array).p_elems + (pos), (array).p_elems + (pos) + 1,      \
                 ( (array).i_size - (pos) - 1 ) *sizeof(*(array).p_elems) );\
    }                                                                       \
    (array).i_size--;                                                       \
    _ARRAY_SHRINK(array);                                                   \
  } while(0)
#define ARRAY_RESET(array)                                                  \
  do {                                                                      \
    (array).i_alloc = 0;                                                    \
    (array).i_size = 0;                                                     \
    free( (array).p_elems ); (array).p_elems = NULL;                        \
  } while(0)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ARRAY_VAL(array, pos) array.p_elems[pos]
#define BSEARCH( entries, count, elem, zetype, key, answer ) \
   do {  \
    int low = 0, high = count - 1;   \
    answer = -1; \
    while( low <= high ) {\
        int mid = ((unsigned int)low + (unsigned int)high) >> 1;\
        zetype mid_val = entries[mid] elem;\
        if( mid_val < key ) \
            low = mid + 1; \
        else if ( mid_val > key ) \
            high = mid -1;  \
        else    \
        {   \
            answer = mid;  break;   \
        }\
    } \
 } while(0)
#define DECL_ARRAY(type) struct {                                           \
    int i_alloc;                                                            \
    int i_size;                                                             \
    type *p_elems;                                                          \
}
#define TAB_APPEND( count, tab, p )             \
    TAB_APPEND_CAST( , count, tab, p )
#define TAB_APPEND_CAST( cast, count, tab, p )             \
  do {                                          \
    if( (count) > 0 )                           \
        (tab) = cast realloc( tab, sizeof( *(tab) ) * ( (count) + 1 ) ); \
    else                                        \
        (tab) = cast malloc( sizeof( *(tab) ) );    \
    if( !(tab) ) abort();                       \
    (tab)[count] = (p);                         \
    (count)++;                                  \
  } while(0)
#define TAB_CLEAN( count, tab )                 \
  do {                                          \
    free( tab );                                \
    (count)= 0;                                 \
    (tab)= NULL;                                \
  } while(0)
#define TAB_ERASE( count, tab, index )      \
  do {                                      \
        if( (count) > 1 )                   \
            memmove( (tab) + (index),       \
                     (tab) + (index) + 1,   \
                     ((count) - (index) - 1 ) * sizeof( *(tab) ) );\
        (count)--;                          \
        if( (count) == 0 )                  \
        {                                   \
            free( tab );                    \
            (tab) = NULL;                   \
        }                                   \
  } while(0)
#define TAB_FIND( count, tab, p, idx )          \
  do {                                          \
    for( (idx) = 0; (idx) < (count); (idx)++ )  \
        if( (tab)[(idx)] == (p) )               \
            break;                              \
    if( (idx) >= (count) )                      \
        (idx) = -1;                             \
  } while(0)
#define TAB_INIT( count, tab )                  \
  do {                                          \
    (count) = 0;                                \
    (tab) = NULL;                               \
  } while(0)
#define TAB_INSERT( count, tab, p, index )      \
    TAB_INSERT_CAST( , count, tab, p, index )
#define TAB_INSERT_CAST( cast, count, tab, p, index ) do { \
    if( (count) > 0 )                           \
        (tab) = cast realloc( tab, sizeof( *(tab) ) * ( (count) + 1 ) ); \
    else                                        \
        (tab) = cast malloc( sizeof( *(tab) ) );       \
    if( !(tab) ) abort();                       \
    if( (count) - (index) > 0 )                 \
        memmove( (tab) + (index) + 1,           \
                 (tab) + (index),               \
                 ((count) - (index)) * sizeof( *(tab) ) );\
    (tab)[(index)] = (p);                       \
    (count)++;                                  \
} while(0)
#define TAB_REMOVE( count, tab, p )             \
  do {                                          \
        int i_index;                            \
        TAB_FIND( count, tab, p, i_index );     \
        if( i_index >= 0 )                      \
            TAB_ERASE( count, tab, i_index );   \
  } while(0)
#define TYPEDEF_ARRAY(type, name) typedef DECL_ARRAY(type) name;

#define _ARRAY_ALLOC(array, newsize) {                                      \
    (array).i_alloc = newsize;                                              \
    (array).p_elems = realloc( (array).p_elems, (array).i_alloc *           \
                               sizeof(*(array).p_elems) );                  \
    if( !(array).p_elems ) abort();                                         \
}
#define _ARRAY_GROW1(array) {                                               \
    if( (array).i_alloc < 10 )                                              \
        _ARRAY_ALLOC(array, 10 )                                            \
    else if( (array).i_alloc == (array).i_size )                            \
        _ARRAY_ALLOC(array, (int)((array).i_alloc * 1.5) )                    \
}
#define _ARRAY_SHRINK(array) {                                              \
    if( (array).i_size > 10 && (array).i_size < (int)((array).i_alloc / 1.5) ) {  \
        _ARRAY_ALLOC(array, (array).i_size + 5);                            \
    }                                                                       \
}
# define vlc_array_item_at_index(ar, idx) \
    _Generic((ar), \
        const vlc_array_t *: ((ar)->pp_elems[idx]), \
        vlc_array_t *: ((ar)->pp_elems[idx]))
#define MSFTIME_FROM_MS(sec)        (INT64_C(10000) * (sec))     
#define MSFTIME_FROM_SEC(sec)       (INT64_C(10000000) * (sec))  
#define MSFTIME_FROM_VLC_TICK(vtk)  ((vtk)  / (CLOCK_FREQ / INT64_C(10000000))
#define MSTRTIME_MAX_SIZE 22
#define MS_FROM_VLC_TICK(vtk) ((vtk) / (CLOCK_FREQ / INT64_C(1000)))
#define NS_FROM_VLC_TICK(vtk)   ((vtk) / (CLOCK_FREQ / (INT64_C(1000000000))))
#define SEC_FROM_VLC_TICK(vtk)   ((vtk) / CLOCK_FREQ)
#define US_FROM_VLC_TICK(vtk)   ((vtk) / (CLOCK_FREQ / INT64_C(1000000)))
#define VLC_TICK_FROM_MS(ms)  ((CLOCK_FREQ / INT64_C(1000)) * (ms))
#define VLC_TICK_FROM_MSFTIME(msft) ((msft) * (CLOCK_FREQ / INT64_C(10000000))
#define VLC_TICK_FROM_NS(ns)    ((ns)  * (CLOCK_FREQ / (INT64_C(1000000000))))
#define VLC_TICK_FROM_SEC(sec)   (CLOCK_FREQ * (sec))
#define VLC_TICK_FROM_US(us)    ((CLOCK_FREQ / INT64_C(1000000)) * (us))
# define __VLC_MTIME_H 1
#define vlc_tick_from_sec(sec) _Generic((sec), \
        double:  vlc_tick_from_secf(sec), \
        float:   vlc_tick_from_secf(sec), \
        default: vlc_tick_from_seci(sec) )
#define vlc_tick_from_timespec(tv) \
    (vlc_tick_from_sec( (tv)->tv_sec ) + VLC_TICK_FROM_NS( (tv)->tv_nsec ))
#define vlc_tick_from_timeval(tv) \
    (vlc_tick_from_sec( (tv)->tv_sec ) + VLC_TICK_FROM_US( (tv)->tv_usec ))
#define CLOCK_FREQ INT64_C(1000000)
#define DEFAULT_PTS_DELAY               VLC_TICK_FROM_MS(300)
#define INPUT_IDLE_SLEEP                VLC_TICK_FROM_MS(100)
#define INTF_IDLE_SLEEP                 VLC_TICK_FROM_MS(50)
#define VLC_TICK_0 INT64_C(1)
#define VLC_TICK_INVALID INT64_C(0)
#define VOUT_ASPECT_FACTOR              432000
#define VOUT_MAX_PLANES                 5
#define VOUT_MAX_WIDTH                  4096
#define VOUT_OUTMEM_SLEEP               VLC_TICK_FROM_MS(20)
#define VOUT_TITLE                      "VLC"



#define MATROSKA_COMPRESSION_BLIB   1
#define MATROSKA_COMPRESSION_HEADER 3
#define MATROSKA_COMPRESSION_LZOX   2
#define MATROSKA_COMPRESSION_NONE  -1
#define MATROSKA_COMPRESSION_ZLIB   0
#define MKVD_TIMECODESCALE 1000000
#define MKV_CHECKED_PTR_DECL( name, type, src ) type * name = MKV_IS_ID(src, type) ? static_cast<type*>(src) : NULL
#define MKV_IS_ID( el, C ) ( el != NULL && typeid( *el ) == typeid( C ) )


#define DEMUX_INIT_COMMON() do {            \
    p_demux->pf_control = Control;          \
    p_demux->pf_demux = Demux;              \
    p_demux->p_sys = calloc( 1, sizeof( demux_sys_t ) ); \
    if( !p_demux->p_sys ) return VLC_ENOMEM;\
    } while(0)
#define INPUT_UPDATE_META       0x0040
#define INPUT_UPDATE_SEEKPOINT  0x0020
#define INPUT_UPDATE_TITLE      0x0010
#define INPUT_UPDATE_TITLE_LIST 0x0100
#define VLC_DEMUXER_EGENERIC -1
#define VLC_DEMUXER_EOF       0
#define VLC_DEMUXER_SUCCESS   1
#define VLC_DEMUX_H 1
# define demux_UpdateTitleFromStream(demux) \
     demux_UpdateTitleFromStream(demux, \
         &((demux_sys_t *)((demux)->p_sys))->current_title, \
         &((demux_sys_t *)((demux)->p_sys))->current_seekpoint, \
         &((demux_sys_t *)((demux)->p_sys))->updates)
#define VLC_ES_OUT_H 1
#define VLC_STREAM_H 1
#define vlc_stream_MemoryNew(a, b, c, d) \
        vlc_stream_MemoryNew(VLC_OBJECT(a), b, c, d)
#define vlc_stream_NewURL(a, b) vlc_stream_NewURL(VLC_OBJECT(a), b)
#define BLOCK_FLAG_AU_END        0x0800
#define BLOCK_FLAG_BOTTOM_FIELD_FIRST 0x2000
#define BLOCK_FLAG_CLOCK         0x0080
#define BLOCK_FLAG_CORE_PRIVATE_MASK  0x00ff0000
#define BLOCK_FLAG_CORE_PRIVATE_SHIFT 16
#define BLOCK_FLAG_CORRUPTED     0x0400
#define BLOCK_FLAG_DISCONTINUITY 0x0001
#define BLOCK_FLAG_END_OF_SEQUENCE 0x0040
#define BLOCK_FLAG_HEADER        0x0020
#define BLOCK_FLAG_INTERLACED_MASK \
    (BLOCK_FLAG_TOP_FIELD_FIRST|BLOCK_FLAG_BOTTOM_FIELD_FIRST|BLOCK_FLAG_SINGLE_FIELD)
#define BLOCK_FLAG_PREROLL       0x0200
#define BLOCK_FLAG_PRIVATE_MASK  0xff000000
#define BLOCK_FLAG_PRIVATE_SHIFT 24
#define BLOCK_FLAG_SCRAMBLED     0x0100
#define BLOCK_FLAG_SINGLE_FIELD  0x4000
#define BLOCK_FLAG_TOP_FIELD_FIRST 0x1000
#define BLOCK_FLAG_TYPE_B        0x0008
#define BLOCK_FLAG_TYPE_I        0x0002
#define BLOCK_FLAG_TYPE_MASK \
    (BLOCK_FLAG_TYPE_I|BLOCK_FLAG_TYPE_P|BLOCK_FLAG_TYPE_B|BLOCK_FLAG_TYPE_PB)
#define BLOCK_FLAG_TYPE_P        0x0004
#define BLOCK_FLAG_TYPE_PB       0x0010
#define VLC_BLOCK_H 1
#define block_cleanup_push( block ) vlc_cleanup_push (block_Cleanup, block)
#define vlc_fifo_CleanupPush(fifo) vlc_cleanup_push(vlc_fifo_Cleanup, fifo)
#define AOUT_CHANMODE_DOLBYSTEREO 0x2
#define AOUT_CHANMODE_DUALMONO    0x1
#define AOUT_CHANS_2_0    (AOUT_CHANS_FRONT)
#define AOUT_CHANS_2_1    (AOUT_CHANS_FRONT | AOUT_CHAN_LFE)
#define AOUT_CHANS_3_0    (AOUT_CHANS_FRONT | AOUT_CHAN_CENTER)
#define AOUT_CHANS_3_1    (AOUT_CHANS_3_0   | AOUT_CHAN_LFE)
#define AOUT_CHANS_4_0    (AOUT_CHANS_FRONT | AOUT_CHANS_REAR)
#define AOUT_CHANS_4_0_MIDDLE (AOUT_CHANS_FRONT | AOUT_CHANS_MIDDLE)
#define AOUT_CHANS_4_1    (AOUT_CHANS_4_0   | AOUT_CHAN_LFE)
#define AOUT_CHANS_4_CENTER_REAR (AOUT_CHANS_FRONT | AOUT_CHANS_CENTER)
#define AOUT_CHANS_5_0    (AOUT_CHANS_4_0   | AOUT_CHAN_CENTER)
#define AOUT_CHANS_5_0_MIDDLE (AOUT_CHANS_4_0_MIDDLE | AOUT_CHAN_CENTER)
#define AOUT_CHANS_5_1    (AOUT_CHANS_5_0   | AOUT_CHAN_LFE)
#define AOUT_CHANS_6_0    (AOUT_CHANS_4_0   | AOUT_CHANS_MIDDLE)
#define AOUT_CHANS_6_1_MIDDLE (AOUT_CHANS_5_0_MIDDLE | AOUT_CHAN_REARCENTER | AOUT_CHAN_LFE)
#define AOUT_CHANS_7_0    (AOUT_CHANS_6_0   | AOUT_CHAN_CENTER)
#define AOUT_CHANS_7_1    (AOUT_CHANS_5_1   | AOUT_CHANS_MIDDLE)
#define AOUT_CHANS_8_1    (AOUT_CHANS_7_1   | AOUT_CHAN_REARCENTER)
#define AOUT_CHANS_CENTER (AOUT_CHAN_CENTER     | AOUT_CHAN_REARCENTER)
#define AOUT_CHANS_FRONT  (AOUT_CHAN_LEFT       | AOUT_CHAN_RIGHT)
#define AOUT_CHANS_MIDDLE (AOUT_CHAN_MIDDLELEFT | AOUT_CHAN_MIDDLERIGHT)
#define AOUT_CHANS_REAR   (AOUT_CHAN_REARLEFT   | AOUT_CHAN_REARRIGHT)
#define AOUT_CHANS_STEREO AOUT_CHANS_2_0
#define AOUT_CHAN_CENTER            0x1
#define AOUT_CHAN_LEFT              0x2
#define AOUT_CHAN_LFE               0x1000
#define AOUT_CHAN_MAX               9
#define AOUT_CHAN_MIDDLELEFT        0x100
#define AOUT_CHAN_MIDDLERIGHT       0x200
#define AOUT_CHAN_REARCENTER        0x10
#define AOUT_CHAN_REARLEFT          0x20
#define AOUT_CHAN_REARRIGHT         0x40
#define AOUT_CHAN_RIGHT             0x4
#define AUDIO_REPLAY_GAIN_ALBUM (1)
#define AUDIO_REPLAY_GAIN_MAX (2)
#define AUDIO_REPLAY_GAIN_TRACK (0)
#define CHROMA_LOCATION_MAX CHROMA_LOCATION_BOTTOM_CENTER
#define COLOR_PRIMARIES_BT470_BG        COLOR_PRIMARIES_BT601_625
#define COLOR_PRIMARIES_BT470_M         COLOR_PRIMARIES_FCC1953
#define COLOR_PRIMARIES_EBU_3213        COLOR_PRIMARIES_BT601_625
#define COLOR_PRIMARIES_MAX             COLOR_PRIMARIES_FCC1953
#define COLOR_PRIMARIES_SMTPE_170       COLOR_PRIMARIES_BT601_525
#define COLOR_PRIMARIES_SMTPE_240       COLOR_PRIMARIES_BT601_525 
#define COLOR_PRIMARIES_SMTPE_RP145     COLOR_PRIMARIES_BT601_525
#define COLOR_PRIMARIES_SRGB            COLOR_PRIMARIES_BT709
#define COLOR_RANGE_MAX    COLOR_RANGE_LIMITED
#define COLOR_RANGE_STUDIO COLOR_RANGE_LIMITED
#define COLOR_SPACE_MAX       COLOR_SPACE_BT2020
#define COLOR_SPACE_SMPTE_170 COLOR_SPACE_BT601
#define COLOR_SPACE_SMPTE_240 COLOR_SPACE_SMPTE_170
#define COLOR_SPACE_SRGB      COLOR_SPACE_BT709
#define ES_CATEGORY_COUNT (DATA_ES + 1)
#define ES_PRIORITY_MIN ES_PRIORITY_NOT_SELECTABLE
#define ES_PRIORITY_NOT_DEFAULTABLE -1
#define ES_PRIORITY_NOT_SELECTABLE  -2
#define ES_PRIORITY_SELECTABLE_MIN   0
#define INPUT_CHAN_MAX              64
#define MULTIVIEW_STEREO_MAX  MULTIVIEW_STEREO_CHECKERBOARD
#define ORIENT_FROM_EXIF(exif) ((0x57642310U >> (4 * ((exif) - 1))) & 7)
#define ORIENT_HFLIP(orient) ((orient) ^ 1)
#define ORIENT_IS_MIRROR(orient) parity(orient)
#define ORIENT_IS_SWAP(orient) (((orient) & 4) != 0)
#define ORIENT_ROTATE_180(orient) ((orient) ^ 3)
#define ORIENT_TO_EXIF(orient) ((0x76853421U >> (4 * (orient))) & 15)
#define ORIENT_VFLIP(orient) ((orient) ^ 2)
#define SPU_PALETTE_DEFINED  0xbeefbeef
#define TRANSFER_FUNC_ARIB_B67          TRANSFER_FUNC_HLG
#define TRANSFER_FUNC_BT2020            TRANSFER_FUNC_BT709
#define TRANSFER_FUNC_MAX               TRANSFER_FUNC_HLG
#define TRANSFER_FUNC_SMPTE_170         TRANSFER_FUNC_BT709
#define TRANSFER_FUNC_SMPTE_274         TRANSFER_FUNC_BT709
#define TRANSFER_FUNC_SMPTE_293         TRANSFER_FUNC_BT709
#define TRANSFER_FUNC_SMPTE_296         TRANSFER_FUNC_BT709
#define VIDEO_PALETTE_COLORS_MAX 256
#define VLC_ES_H 1
#define FIELD_OF_VIEW_DEGREES_DEFAULT  80.f
#define FIELD_OF_VIEW_DEGREES_MAX 150.f
#define FIELD_OF_VIEW_DEGREES_MIN 20.f
#define VLC_VIEWPOINT_H_ 1
#define VLC_CODEC_302M                       VLC_FOURCC('3','0','2','m')
#define VLC_CODEC_4XM             VLC_FOURCC('4','X','M','V')
#define VLC_CODEC_8BPS            VLC_FOURCC('8','B','P','S')
#define VLC_CODEC_A52                        VLC_FOURCC('a','5','2',' ')
#define VLC_CODEC_AASC            VLC_FOURCC('A','A','S','C')
#define VLC_CODEC_ADPCM_4XM                  VLC_FOURCC('4','x','m','a')
#define VLC_CODEC_ADPCM_ADX                  VLC_FOURCC('a','d','x',' ')
#define VLC_CODEC_ADPCM_CREATIVE             VLC_FOURCC('m','s',0x00,0xC0)
#define VLC_CODEC_ADPCM_DK3                  VLC_FOURCC('m','s',0x00,0x62)
#define VLC_CODEC_ADPCM_DK4                  VLC_FOURCC('m','s',0x00,0x61)
#define VLC_CODEC_ADPCM_EA                   VLC_FOURCC('A','D','E','A')
#define VLC_CODEC_ADPCM_EA_R1                VLC_FOURCC('E','A','R','1')
#define VLC_CODEC_ADPCM_G722                 VLC_FOURCC('g','7','2','2')
#define VLC_CODEC_ADPCM_G726                 VLC_FOURCC('g','7','2','6')
#define VLC_CODEC_ADPCM_IMA_AMV              VLC_FOURCC('i','m','a','v')
#define VLC_CODEC_ADPCM_IMA_APC              VLC_FOURCC('A','I','P','C')
#define VLC_CODEC_ADPCM_IMA_EA_SEAD          VLC_FOURCC('S','E','A','D')
#define VLC_CODEC_ADPCM_IMA_QT               VLC_FOURCC('i','m','a','4')
#define VLC_CODEC_ADPCM_IMA_WAV              VLC_FOURCC('m','s',0x00,0x11)
#define VLC_CODEC_ADPCM_IMA_WS               VLC_FOURCC('A','I','W','S')
#define VLC_CODEC_ADPCM_MS                   VLC_FOURCC('m','s',0x00,0x02)
#define VLC_CODEC_ADPCM_SBPRO_2              VLC_FOURCC('m','s',0x00,0xC2)
#define VLC_CODEC_ADPCM_SBPRO_3              VLC_FOURCC('m','s',0x00,0xC3)
#define VLC_CODEC_ADPCM_SBPRO_4              VLC_FOURCC('m','s',0x00,0xC4)
#define VLC_CODEC_ADPCM_SWF                  VLC_FOURCC('S','W','F','a')
#define VLC_CODEC_ADPCM_THP                  VLC_FOURCC('T','H','P','A')
#define VLC_CODEC_ADPCM_XA                   VLC_FOURCC('x','a',' ',' ')
#define VLC_CODEC_ADPCM_XA_EA                VLC_FOURCC('X','A','J', 0)
#define VLC_CODEC_ADPCM_YAMAHA               VLC_FOURCC('m','s',0x00,0x20)
#define VLC_CODEC_AGM             VLC_FOURCC('A','G','M','0')
#define VLC_CODEC_ALAC                       VLC_FOURCC('a','l','a','c')
#define VLC_CODEC_ALAW                       VLC_FOURCC('a','l','a','w')
#define VLC_CODEC_ALS                        VLC_FOURCC('a','l','s',' ')
#define VLC_CODEC_AMR_NB                     VLC_FOURCC('s','a','m','r')
#define VLC_CODEC_AMR_WB                     VLC_FOURCC('s','a','w','b')
#define VLC_CODEC_AMV             VLC_FOURCC('A','M','V',' ')
#define VLC_CODEC_ANDROID_OPAQUE  VLC_FOURCC('A','N','O','P')
#define VLC_CODEC_ANM             VLC_FOURCC('A','N','I','M')
#define VLC_CODEC_APE                        VLC_FOURCC('A','P','E',' ')
#define VLC_CODEC_ARGB            VLC_FOURCC('A','R','G','B')
#define VLC_CODEC_ARIB_A    VLC_FOURCC('a','r','b','a')
#define VLC_CODEC_ARIB_C    VLC_FOURCC('a','r','b','c')
#define VLC_CODEC_ASV1            VLC_FOURCC('A','S','V','1')
#define VLC_CODEC_ASV2            VLC_FOURCC('A','S','V','2')
#define VLC_CODEC_ATRAC1                     VLC_FOURCC('a','t','r','1')
#define VLC_CODEC_ATRAC3                     VLC_FOURCC('a','t','r','c')
#define VLC_CODEC_ATRAC3P                    VLC_FOURCC('a','t','r','p')
#define VLC_CODEC_AURA            VLC_FOURCC('A','U','R','A')
#define VLC_CODEC_AV1             VLC_FOURCC('a','v','0','1')
#define VLC_CODEC_AVS             VLC_FOURCC('A','V','S','V')
#define VLC_CODEC_BD_LPCM                    VLC_FOURCC('b','p','c','m')
#define VLC_CODEC_BD_PG     VLC_FOURCC('b','d','p','g')
#define VLC_CODEC_BD_TEXT   VLC_FOURCC('b','d','t','x')
#define VLC_CODEC_BETHSOFTVID     VLC_FOURCC('B','V','I','D')
#define VLC_CODEC_BFI             VLC_FOURCC('B','F','&','I')
#define VLC_CODEC_BGRA            VLC_FOURCC('B','G','R','A')
#define VLC_CODEC_BINKAUDIO_DCT   VLC_FOURCC('B','A','U','1')
#define VLC_CODEC_BINKAUDIO_RDFT  VLC_FOURCC('B','A','U','2')
#define VLC_CODEC_BINKVIDEO       VLC_FOURCC('B','I','K','f')
#define VLC_CODEC_BMP             VLC_FOURCC('b','m','p',' ')
#define VLC_CODEC_BMVAUDIO                   VLC_FOURCC('B','M','V','A')
#define VLC_CODEC_BMVVIDEO        VLC_FOURCC('B','M','V','V')
#define VLC_CODEC_BPG             VLC_FOURCC('B','P','G',0xFB)
#define VLC_CODEC_C93             VLC_FOURCC('I','C','9','3')
#define VLC_CODEC_CAVS            VLC_FOURCC('C','A','V','S')
#define VLC_CODEC_CDG             VLC_FOURCC('C','D','G',' ')
#define VLC_CODEC_CDXL            VLC_FOURCC('C','D','X','L')
#define VLC_CODEC_CEA608    VLC_FOURCC('c','6','0','8')
#define VLC_CODEC_CEA708    VLC_FOURCC('c','7','0','8')
#define VLC_CODEC_CINEFORM        VLC_FOURCC('C','F','H','D')
#define VLC_CODEC_CINEPAK         VLC_FOURCC('C','V','I','D')
#define VLC_CODEC_CLJR            VLC_FOURCC('C','L','J','R')
#define VLC_CODEC_CLLC            VLC_FOURCC('C','L','L','C')
#define VLC_CODEC_CMML      VLC_FOURCC('c','m','m','l')
#define VLC_CODEC_CMV             VLC_FOURCC('E','C','M','V')
#define VLC_CODEC_COOK                       VLC_FOURCC('c','o','o','k')
#define VLC_CODEC_CSCD            VLC_FOURCC('C','S','C','D')
#define VLC_CODEC_CVD       VLC_FOURCC('c','v','d',' ')
#define VLC_CODEC_CVPX_BGRA       VLC_FOURCC('C','V','P','B')
#define VLC_CODEC_CVPX_I420       VLC_FOURCC('C','V','P','I')
#define VLC_CODEC_CVPX_NV12       VLC_FOURCC('C','V','P','N')
#define VLC_CODEC_CVPX_P010       VLC_FOURCC('C','V','P','P')
#define VLC_CODEC_CVPX_UYVY       VLC_FOURCC('C','V','P','Y')
#define VLC_CODEC_CYUV            VLC_FOURCC('c','y','u','v')
#define VLC_CODEC_D3D11_OPAQUE          VLC_FOURCC('D','X','1','1') 
#define VLC_CODEC_D3D11_OPAQUE_10B      VLC_FOURCC('D','X','1','0') 
#define VLC_CODEC_D3D11_OPAQUE_BGRA     VLC_FOURCC('D','A','G','R')
#define VLC_CODEC_D3D11_OPAQUE_RGBA     VLC_FOURCC('D','X','R','G')
#define VLC_CODEC_D3D9_OPAQUE     VLC_FOURCC('D','X','A','9') 
#define VLC_CODEC_D3D9_OPAQUE_10B VLC_FOURCC('D','X','A','0') 
#define VLC_CODEC_DAALA           VLC_FOURCC('d','a','a','l')
#define VLC_CODEC_DAT12                      VLC_FOURCC('L','P','1','2')
#define VLC_CODEC_DFA             VLC_FOURCC('D','F','I','A')
#define VLC_CODEC_DIRAC           VLC_FOURCC('d','r','a','c')
#define VLC_CODEC_DIV1            VLC_FOURCC('D','I','V','1')
#define VLC_CODEC_DIV2            VLC_FOURCC('D','I','V','2')
#define VLC_CODEC_DIV3            VLC_FOURCC('D','I','V','3')
#define VLC_CODEC_DNXHD           VLC_FOURCC('A','V','d','n')
#define VLC_CODEC_DSD_LSBF                   VLC_FOURCC('D','S','D','l')
#define VLC_CODEC_DSD_LSBF_PLANAR            VLC_FOURCC('D','S','F','l')
#define VLC_CODEC_DSD_MSBF                   VLC_FOURCC('D','S','D',' ')
#define VLC_CODEC_DSD_MSBF_PLANAR            VLC_FOURCC('D','S','F','m')
#define VLC_CODEC_DSICINAUDIO                VLC_FOURCC('D','C','I','A')
#define VLC_CODEC_DSICINVIDEO     VLC_FOURCC('D','C','I','V')
#define VLC_CODEC_DTS                        VLC_FOURCC('d','t','s',' ')
#define VLC_CODEC_DV              VLC_FOURCC('d','v',' ',' ')
#define VLC_CODEC_DVAUDIO                    VLC_FOURCC('d','v','a','u')
#define VLC_CODEC_DVBS      VLC_FOURCC('d','v','b','s')
#define VLC_CODEC_DVDA_LPCM                  VLC_FOURCC('a','p','c','m')
#define VLC_CODEC_DVD_LPCM                   VLC_FOURCC('l','p','c','m')
#define VLC_CODEC_DXA             VLC_FOURCC('D','E','X','A')
#define VLC_CODEC_DXTORY          VLC_FOURCC('x','t','o','r')
#define VLC_CODEC_DXV             VLC_FOURCC('D','X','D','3')
#define VLC_CODEC_EAC3                       VLC_FOURCC('e','a','c','3')
#define VLC_CODEC_EBU_STL   VLC_FOURCC('S','T','L',' ')
#define VLC_CODEC_ESCAPE124       VLC_FOURCC('E','1','2','4')
#define VLC_CODEC_F32B                       VLC_FOURCC('f','3','2','b')
#define VLC_CODEC_F32L                       VLC_FOURCC('f','3','2','l')
#define VLC_CODEC_F64B                       VLC_FOURCC('f','6','4','b')
#define VLC_CODEC_F64L                       VLC_FOURCC('f','6','4','l')
#define VLC_CODEC_FFV1            VLC_FOURCC('F','F','V','1')
#define VLC_CODEC_FFVHUFF         VLC_FOURCC('F','F','V','H')
#define VLC_CODEC_FIC             VLC_FOURCC('F','I','C','V')
#   define VLC_CODEC_FL32 VLC_CODEC_F32B
#   define VLC_CODEC_FL64 VLC_CODEC_F64B
#define VLC_CODEC_FLAC                       VLC_FOURCC('f','l','a','c')
#define VLC_CODEC_FLASHSV         VLC_FOURCC('F','S','V','1')
#define VLC_CODEC_FLASHSV2        VLC_FOURCC('F','S','V','2')
#define VLC_CODEC_FLIC            VLC_FOURCC('F','L','I','C')
#define VLC_CODEC_FLV1            VLC_FOURCC('F','L','V','1')
#define VLC_CODEC_FMVC            VLC_FOURCC('F','M','V','C')
#define VLC_CODEC_FRAPS           VLC_FOURCC('F','P','S','1')
#define VLC_CODEC_FRWU            VLC_FOURCC('F','R','W','U')
#define VLC_CODEC_G2M2            VLC_FOURCC('G','2','M','2')
#define VLC_CODEC_G2M3            VLC_FOURCC('G','2','M','3')
#define VLC_CODEC_G2M4            VLC_FOURCC('G','2','M','4')
#define VLC_CODEC_G723_1                     VLC_FOURCC('g','7','2', 0x31)
#define VLC_CODEC_G729                       VLC_FOURCC('g','7','2','9')
#define VLC_CODEC_GBRA_PLANAR_10B VLC_FOURCC('G','B','0','B')
#define VLC_CODEC_GBRA_PLANAR_10L VLC_FOURCC('G','B','0','L')
#define VLC_CODEC_GBRA_PLANAR_12B VLC_FOURCC('G','B','C','B')
#define VLC_CODEC_GBRA_PLANAR_12L VLC_FOURCC('G','B','C','L')
#define VLC_CODEC_GBRA_PLANAR_16B VLC_FOURCC('G','B','E','B')
#define VLC_CODEC_GBRA_PLANAR_16L VLC_FOURCC('G','B','E','L')
#define VLC_CODEC_GBR_PLANAR      VLC_FOURCC('G','B','R','8')
#define VLC_CODEC_GBR_PLANAR_10B  VLC_FOURCC('G','B','A','B')
#define VLC_CODEC_GBR_PLANAR_10L  VLC_FOURCC('G','B','A','L')
#define VLC_CODEC_GBR_PLANAR_12B  VLC_FOURCC('G','B','B','B')
#define VLC_CODEC_GBR_PLANAR_12L  VLC_FOURCC('G','B','B','L')
#define VLC_CODEC_GBR_PLANAR_14B  VLC_FOURCC('G','B','D','B')
#define VLC_CODEC_GBR_PLANAR_14L  VLC_FOURCC('G','B','D','L')
#define VLC_CODEC_GBR_PLANAR_16B  VLC_FOURCC('G','B','F','B')
#define VLC_CODEC_GBR_PLANAR_16L  VLC_FOURCC('G','B','F','L')
#define VLC_CODEC_GBR_PLANAR_9B   VLC_FOURCC('G','B','9','B')
#define VLC_CODEC_GBR_PLANAR_9L   VLC_FOURCC('G','B','9','L')
#define VLC_CODEC_GIF             VLC_FOURCC('g','i','f',' ')
#define VLC_CODEC_GREY            VLC_FOURCC('G','R','E','Y')
#define VLC_CODEC_GREY_10B        VLC_FOURCC('G','0','F','B')
#define VLC_CODEC_GREY_10L        VLC_FOURCC('G','0','F','L')
#define VLC_CODEC_GREY_12B        VLC_FOURCC('G','2','F','B')
#define VLC_CODEC_GREY_12L        VLC_FOURCC('G','2','F','L')
#define VLC_CODEC_GREY_16B        VLC_FOURCC('G','R','F','B')
#define VLC_CODEC_GREY_16L        VLC_FOURCC('G','R','F','L')
#define VLC_CODEC_GSM                        VLC_FOURCC('g','s','m',' ')
#define VLC_CODEC_GSM_MS                     VLC_FOURCC('a','g','s','m')
#define VLC_CODEC_H261            VLC_FOURCC('h','2','6','1')
#define VLC_CODEC_H263            VLC_FOURCC('h','2','6','3')
#define VLC_CODEC_H263I           VLC_FOURCC('I','2','6','3')
#define VLC_CODEC_H263P           VLC_FOURCC('I','L','V','R')
#define VLC_CODEC_H264            VLC_FOURCC('h','2','6','4')
#define VLC_CODEC_HAP             VLC_FOURCC('H','A','P','1')
#define VLC_CODEC_HEVC            VLC_FOURCC('h','e','v','c')
#define VLC_CODEC_HNM4_VIDEO      VLC_FOURCC('H','N','M','4')
#define VLC_CODEC_HQX             VLC_FOURCC('C','H','Q','X')
#define VLC_CODEC_HQ_HQA          VLC_FOURCC('C','U','V','C')
#define VLC_CODEC_HUFFYUV         VLC_FOURCC('H','F','Y','U')
#define VLC_CODEC_I410            VLC_FOURCC('I','4','1','0')
#define VLC_CODEC_I411            VLC_FOURCC('I','4','1','1')
#define VLC_CODEC_I420            VLC_FOURCC('I','4','2','0')
#define VLC_CODEC_I420_10B        VLC_FOURCC('I','0','A','B')
#define VLC_CODEC_I420_10L        VLC_FOURCC('I','0','A','L')
#define VLC_CODEC_I420_12B        VLC_FOURCC('I','0','C','B')
#define VLC_CODEC_I420_12L        VLC_FOURCC('I','0','C','L')
#define VLC_CODEC_I420_16B        VLC_FOURCC('I','0','F','B')
#define VLC_CODEC_I420_16L        VLC_FOURCC('I','0','F','L')
#define VLC_CODEC_I420_9B         VLC_FOURCC('I','0','9','B')
#define VLC_CODEC_I420_9L         VLC_FOURCC('I','0','9','L')
#define VLC_CODEC_I422            VLC_FOURCC('I','4','2','2')
#define VLC_CODEC_I422_10B        VLC_FOURCC('I','2','A','B')
#define VLC_CODEC_I422_10L        VLC_FOURCC('I','2','A','L')
#define VLC_CODEC_I422_12B        VLC_FOURCC('I','2','C','B')
#define VLC_CODEC_I422_12L        VLC_FOURCC('I','2','C','L')
#define VLC_CODEC_I422_16B        VLC_FOURCC('I','2','F','B')
#define VLC_CODEC_I422_16L        VLC_FOURCC('I','2','F','L')
#define VLC_CODEC_I422_9B         VLC_FOURCC('I','2','9','B')
#define VLC_CODEC_I422_9L         VLC_FOURCC('I','2','9','L')
#define VLC_CODEC_I440            VLC_FOURCC('I','4','4','0')
#define VLC_CODEC_I444            VLC_FOURCC('I','4','4','4')
#define VLC_CODEC_I444_10B        VLC_FOURCC('I','4','A','B')
#define VLC_CODEC_I444_10L        VLC_FOURCC('I','4','A','L')
#define VLC_CODEC_I444_12B        VLC_FOURCC('I','4','C','B')
#define VLC_CODEC_I444_12L        VLC_FOURCC('I','4','C','L')
#define VLC_CODEC_I444_16B        VLC_FOURCC('I','4','F','B')
#define VLC_CODEC_I444_16L        VLC_FOURCC('I','4','F','L')
#define VLC_CODEC_I444_9B         VLC_FOURCC('I','4','9','B')
#define VLC_CODEC_I444_9L         VLC_FOURCC('I','4','9','L')
#define VLC_CODEC_ICOD            VLC_FOURCC('i','c','o','d')
#define VLC_CODEC_IDCIN           VLC_FOURCC('I','D','C','I')
#define VLC_CODEC_IMC                        VLC_FOURCC(0x1,0x4,0x0,0x0)
#define VLC_CODEC_IMM4            VLC_FOURCC('I','M','M','4')
#define VLC_CODEC_INDEO2          VLC_FOURCC('I','V','2','0')
#define VLC_CODEC_INDEO3          VLC_FOURCC('I','V','3','1')
#define VLC_CODEC_INDEO4          VLC_FOURCC('I','V','4','1')
#define VLC_CODEC_INDEO5          VLC_FOURCC('I','V','5','0')
#define VLC_CODEC_INDEO_AUDIO                VLC_FOURCC('m','s',0x04,0x02)
#define VLC_CODEC_INTERPLAY       VLC_FOURCC('i','m','v','e')
#define VLC_CODEC_INTERPLAY_DPCM             VLC_FOURCC('i','d','p','c')
#define VLC_CODEC_ITU_T140  VLC_FOURCC('t','1','4','0')
#define VLC_CODEC_J420            VLC_FOURCC('J','4','2','0')
#define VLC_CODEC_J422            VLC_FOURCC('J','4','2','2')
#define VLC_CODEC_J440            VLC_FOURCC('J','4','4','0')
#define VLC_CODEC_J444            VLC_FOURCC('J','4','4','4')
#define VLC_CODEC_JPEG            VLC_FOURCC('j','p','e','g')
#define VLC_CODEC_JPEG2000        VLC_FOURCC('J','P','2','K')
#define VLC_CODEC_JPEGLS          VLC_FOURCC('M','J','L','S')
#define VLC_CODEC_JV              VLC_FOURCC('J','V','0','0')
#define VLC_CODEC_KATE      VLC_FOURCC('k','a','t','e')
#define VLC_CODEC_KGV1            VLC_FOURCC('K','G','V','1')
#define VLC_CODEC_KMVC            VLC_FOURCC('K','M','V','C')
#define VLC_CODEC_LAGARITH        VLC_FOURCC('L','A','G','S')
#define VLC_CODEC_LCL_MSZH        VLC_FOURCC('M','S','Z','H')
#define VLC_CODEC_LCL_ZLIB        VLC_FOURCC('Z','L','I','B')
#define VLC_CODEC_LJPG            VLC_FOURCC('L','J','P','G')
#define VLC_CODEC_LOCO            VLC_FOURCC('L','O','C','O')
#define VLC_CODEC_MACE3                      VLC_FOURCC('M','A','C','3')
#define VLC_CODEC_MACE6                      VLC_FOURCC('M','A','C','6')
#define VLC_CODEC_MAD             VLC_FOURCC('M','A','D','V')
#define VLC_CODEC_MAGICYUV        VLC_FOURCC('M','8','Y','0')
#define VLC_CODEC_MDEC            VLC_FOURCC('M','D','E','C')
#define VLC_CODEC_METASOUND                  VLC_FOURCC('m','s',0x00,0x75)
#define VLC_CODEC_MIDI                       VLC_FOURCC('M','I','D','I')
#define VLC_CODEC_MIMIC           VLC_FOURCC('M','L','2','O')
#define VLC_CODEC_MJPG            VLC_FOURCC('M','J','P','G')
#define VLC_CODEC_MJPGB           VLC_FOURCC('m','j','p','b')
#define VLC_CODEC_MLP                        VLC_FOURCC('m','l','p',' ')
#define VLC_CODEC_MMAL_OPAQUE     VLC_FOURCC('M','M','A','L')
#define VLC_CODEC_MMVIDEO         VLC_FOURCC('M','M','V','I')
#define VLC_CODEC_MOTIONPIXELS    VLC_FOURCC('M','P','I','X')
#define VLC_CODEC_MP1V      VLC_FOURCC('m','p','1','v')
#define VLC_CODEC_MP2       VLC_FOURCC('m','p','2',' ')
#define VLC_CODEC_MP2V      VLC_FOURCC('m','p','2','v')
#define VLC_CODEC_MP3       VLC_FOURCC('m','p','3',' ')
#define VLC_CODEC_MP4A                       VLC_FOURCC('m','p','4','a')
#define VLC_CODEC_MP4V            VLC_FOURCC('m','p','4','v')
#define VLC_CODEC_MPGA                       VLC_FOURCC('m','p','g','a')
#define VLC_CODEC_MPGV            VLC_FOURCC('m','p','g','v')
#define VLC_CODEC_MSA1            VLC_FOURCC('M','S','A','1')
#define VLC_CODEC_MSRLE           VLC_FOURCC('m','r','l','e')
#define VLC_CODEC_MSS1            VLC_FOURCC('M','S','S','1')
#define VLC_CODEC_MSS2            VLC_FOURCC('M','S','S','2')
#define VLC_CODEC_MSVIDEO1        VLC_FOURCC('M','S','V','C')
#define VLC_CODEC_MTS2            VLC_FOURCC('M','T','S','2')
#define VLC_CODEC_MULAW                      VLC_FOURCC('m','l','a','w')
#define VLC_CODEC_MUSEPACK7                  VLC_FOURCC('M','P','C',' ')
#define VLC_CODEC_MUSEPACK8                  VLC_FOURCC('M','P','C','K')
#define VLC_CODEC_MXPEG           VLC_FOURCC('M','X','P','G')
#define VLC_CODEC_NELLYMOSER                 VLC_FOURCC('N','E','L','L')
#define VLC_CODEC_NUV             VLC_FOURCC('N','J','P','G')
#define VLC_CODEC_NV12            VLC_FOURCC('N','V','1','2')
#define VLC_CODEC_NV16            VLC_FOURCC('N','V','1','6')
#define VLC_CODEC_NV21            VLC_FOURCC('N','V','2','1')
#define VLC_CODEC_NV24            VLC_FOURCC('N','V','2','4')
#define VLC_CODEC_NV42            VLC_FOURCC('N','V','4','2')
#define VLC_CODEC_NV61            VLC_FOURCC('N','V','6','1')
#define VLC_CODEC_OGGSPOTS        VLC_FOURCC('S','P','O','T')
#define VLC_CODEC_OGT       VLC_FOURCC('o','g','t',' ')
#define VLC_CODEC_ON2AVC                     VLC_FOURCC('m','s',0x05,0x00)
#define VLC_CODEC_OPUS                       VLC_FOURCC('O','p','u','s')
#define VLC_CODEC_P010            VLC_FOURCC('P','0','1','0')
#define VLC_CODEC_PAM             VLC_FOURCC('p','a','m',' ')
#define VLC_CODEC_PCX             VLC_FOURCC('p','c','x',' ')
#define VLC_CODEC_PGM             VLC_FOURCC('p','g','m',' ')
#define VLC_CODEC_PGMYUV          VLC_FOURCC('p','g','m','y')
#define VLC_CODEC_PIXLET          VLC_FOURCC('p','x','l','t')
#define VLC_CODEC_PNG             VLC_FOURCC('p','n','g',' ')
#define VLC_CODEC_PNM             VLC_FOURCC('p','n','m',' ')
#define VLC_CODEC_PPM             VLC_FOURCC('p','p','m',' ')
#define VLC_CODEC_PRORES          VLC_FOURCC('a','p','c','n')
#define VLC_CODEC_QCELP                      VLC_FOURCC('Q','c','l','p')
#define VLC_CODEC_QDM2                       VLC_FOURCC('Q','D','M','2')
#define VLC_CODEC_QDMC                       VLC_FOURCC('Q','D','M','C')
#define VLC_CODEC_QDRAW           VLC_FOURCC('q','d','r','w')
#define VLC_CODEC_QPEG            VLC_FOURCC('Q','P','E','G')
#define VLC_CODEC_QTRLE           VLC_FOURCC('r','l','e',' ')
#define VLC_CODEC_QTXT      VLC_FOURCC('q','t','x','t')
#define VLC_CODEC_R420            VLC_FOURCC('r','4','2','0')
#define VLC_CODEC_RALF                       VLC_FOURCC('R','A','L','F')
#define VLC_CODEC_RA_144                     VLC_FOURCC('1','4','_','4')
#define VLC_CODEC_RA_288                     VLC_FOURCC('2','8','_','8')
#define VLC_CODEC_RGB12           VLC_FOURCC('R','V','1','2')
#define VLC_CODEC_RGB15           VLC_FOURCC('R','V','1','5')
#define VLC_CODEC_RGB16           VLC_FOURCC('R','V','1','6')
#define VLC_CODEC_RGB24           VLC_FOURCC('R','V','2','4')
#define VLC_CODEC_RGB32           VLC_FOURCC('R','V','3','2')
#define VLC_CODEC_RGB8            VLC_FOURCC('R','G','B','8')
#define VLC_CODEC_RGBA            VLC_FOURCC('R','G','B','A')
#define VLC_CODEC_RGBA10          VLC_FOURCC('R','G','A','0')
#define VLC_CODEC_RGBA64          VLC_FOURCC('R','G','A','4')
#define VLC_CODEC_RGBP            VLC_FOURCC('R','G','B','P')
#define VLC_CODEC_RL2             VLC_FOURCC('R','L','V','2')
#define VLC_CODEC_ROQ             VLC_FOURCC('R','o','Q','v')
#define VLC_CODEC_ROQ_DPCM                   VLC_FOURCC('R','o','Q','a')
#define VLC_CODEC_RPZA            VLC_FOURCC('r','p','z','a')
#define VLC_CODEC_RV10            VLC_FOURCC('R','V','1','0')
#define VLC_CODEC_RV13            VLC_FOURCC('R','V','1','3')
#define VLC_CODEC_RV20            VLC_FOURCC('R','V','2','0')
#define VLC_CODEC_RV30            VLC_FOURCC('R','V','3','0')
#define VLC_CODEC_RV40            VLC_FOURCC('R','V','4','0')
#define VLC_CODEC_S16B                       VLC_FOURCC('s','1','6','b')
#   define VLC_CODEC_S16I VLC_CODEC_S16L
#define VLC_CODEC_S16L                       VLC_FOURCC('s','1','6','l')
#define VLC_CODEC_S16L_PLANAR                VLC_FOURCC('s','1','l','p')
#   define VLC_CODEC_S16N VLC_CODEC_S16B
#define VLC_CODEC_S20B                       VLC_FOURCC('s','2','0','b')
#define VLC_CODEC_S24B                       VLC_FOURCC('s','2','4','b')
#define VLC_CODEC_S24B32                     VLC_FOURCC('S','2','4','4')
#define VLC_CODEC_S24DAUD                    VLC_FOURCC('d','a','u','d')
#   define VLC_CODEC_S24I VLC_CODEC_S24L
#define VLC_CODEC_S24L                       VLC_FOURCC('s','2','4','l')
#define VLC_CODEC_S24L32                     VLC_FOURCC('s','2','4','4')
#   define VLC_CODEC_S24N VLC_CODEC_S24B
#define VLC_CODEC_S32B                       VLC_FOURCC('s','3','2','b')
#   define VLC_CODEC_S32I VLC_CODEC_S32L
#define VLC_CODEC_S32L                       VLC_FOURCC('s','3','2','l')
#   define VLC_CODEC_S32N VLC_CODEC_S32B
#define VLC_CODEC_S8                         VLC_FOURCC('s','8',' ',' ')
#define VLC_CODEC_SCTE_18   VLC_FOURCC('S','C','1','8')
#define VLC_CODEC_SCTE_27   VLC_FOURCC('S','C','2','7')
#define VLC_CODEC_SDDS                       VLC_FOURCC('s','d','d','s')
#define VLC_CODEC_SGI             VLC_FOURCC('s','g','i',' ')
#define VLC_CODEC_SHORTEN                    VLC_FOURCC('s','h','n',' ')
#define VLC_CODEC_SIPR                       VLC_FOURCC('s','i','p','r')
#define VLC_CODEC_SMACKAUDIO                 VLC_FOURCC('S','M','K','A')
#define VLC_CODEC_SMACKVIDEO      VLC_FOURCC('S','M','K','2')
#define VLC_CODEC_SMC             VLC_FOURCC('s','m','c',' ')
#define VLC_CODEC_SP5X            VLC_FOURCC('S','P','5','X')
#define VLC_CODEC_SPEEDHQ         VLC_FOURCC('S','H','Q','2')
#define VLC_CODEC_SPEEX                      VLC_FOURCC('s','p','x',' ')
#define VLC_CODEC_SPU       VLC_FOURCC('s','p','u',' ')
#define VLC_CODEC_SSA       VLC_FOURCC('s','s','a',' ')
#define VLC_CODEC_SUBT      VLC_FOURCC('s','u','b','t')
#define VLC_CODEC_SVG             VLC_FOURCC('s','v','g',' ')
#define VLC_CODEC_SVQ1            VLC_FOURCC('S','V','Q','1')
#define VLC_CODEC_SVQ3            VLC_FOURCC('S','V','Q','3')
#define VLC_CODEC_TAK                        VLC_FOURCC('t','a','k',' ')
#define VLC_CODEC_TARGA           VLC_FOURCC('t','g','a',' ')
#define VLC_CODEC_TARKIN          VLC_FOURCC('t','a','r','k')
#define VLC_CODEC_TDSC            VLC_FOURCC('T','D','S','C')
#define VLC_CODEC_TELETEXT  VLC_FOURCC('t','e','l','x')
#define VLC_CODEC_TEXT      VLC_FOURCC('T','E','X','T')
#define VLC_CODEC_TGQ             VLC_FOURCC('T','G','Q','V')
#define VLC_CODEC_TGV             VLC_FOURCC('T','G','V','V')
#define VLC_CODEC_THEORA          VLC_FOURCC('t','h','e','o')
#define VLC_CODEC_THP             VLC_FOURCC('T','H','P','0')
#define VLC_CODEC_TIERTEXSEQVIDEO VLC_FOURCC('T','S','E','Q')
#define VLC_CODEC_TIFF            VLC_FOURCC('t','i','f','f')
#define VLC_CODEC_TMV             VLC_FOURCC('T','M','A','V')
#define VLC_CODEC_TQI             VLC_FOURCC('T','Q','I','V')
#define VLC_CODEC_TRUEHD                     VLC_FOURCC('t','r','h','d')
#define VLC_CODEC_TRUEMOTION1     VLC_FOURCC('D','U','C','K')
#define VLC_CODEC_TRUEMOTION2     VLC_FOURCC('T','M','2','0')
#define VLC_CODEC_TRUESPEECH                 VLC_FOURCC(0x22,0x0,0x0,0x0)
#define VLC_CODEC_TSC2            VLC_FOURCC('T','S','C','2')
#define VLC_CODEC_TSCC            VLC_FOURCC('T','S','C','C')
#define VLC_CODEC_TTA                        VLC_FOURCC('T','T','A','1')
#define VLC_CODEC_TTML      VLC_FOURCC('s','t','p','p')
#define VLC_CODEC_TTML_TS   VLC_FOURCC('s','t','p','P') 
#define VLC_CODEC_TWINVQ                     VLC_FOURCC('T','W','I','N')
#define VLC_CODEC_TX3G      VLC_FOURCC('t','x','3','g')
#define VLC_CODEC_TXD             VLC_FOURCC('T','X','D',' ')
#define VLC_CODEC_U16B                       VLC_FOURCC('u','1','6','b')
#   define VLC_CODEC_U16I VLC_CODEC_U16L
#define VLC_CODEC_U16L                       VLC_FOURCC('u','1','6','l')
#   define VLC_CODEC_U16N VLC_CODEC_U16B
#define VLC_CODEC_U24B                       VLC_FOURCC('u','2','4','b')
#   define VLC_CODEC_U24I VLC_CODEC_U24L
#define VLC_CODEC_U24L                       VLC_FOURCC('u','2','4','l')
#   define VLC_CODEC_U24N VLC_CODEC_U24B
#define VLC_CODEC_U32B                       VLC_FOURCC('u','3','2','b')
#   define VLC_CODEC_U32I VLC_CODEC_U32L
#define VLC_CODEC_U32L                       VLC_FOURCC('u','3','2','l')
#   define VLC_CODEC_U32N VLC_CODEC_U32B
#define VLC_CODEC_U8                         VLC_FOURCC('u','8',' ',' ')
#define VLC_CODEC_ULEAD_DV_AUDIO_NTSC        VLC_FOURCC('m','s',0x02,0x15)
#define VLC_CODEC_ULEAD_DV_AUDIO_PAL         VLC_FOURCC('m','s',0x02,0x16)
#define VLC_CODEC_ULTI            VLC_FOURCC('U','L','T','I')
#define VLC_CODEC_UNKNOWN         VLC_FOURCC('u','n','d','f')
#define VLC_CODEC_USF       VLC_FOURCC('u','s','f',' ')
#define VLC_CODEC_UTVIDEO         VLC_FOURCC('U','L','R','A')
#define VLC_CODEC_UYVY            VLC_FOURCC('U','Y','V','Y')
#define VLC_CODEC_V210            VLC_FOURCC('v','2','1','0')
#define VLC_CODEC_VAAPI_420 VLC_FOURCC('V','A','O','P') 
#define VLC_CODEC_VAAPI_420_10BPP VLC_FOURCC('V','A','O','0') 
#define VLC_CODEC_VB              VLC_FOURCC('V','B','V','1')
#define VLC_CODEC_VBLE            VLC_FOURCC('V','B','L','E')
#define VLC_CODEC_VC1             VLC_FOURCC('V','C','-','1')
#define VLC_CODEC_VCR1            VLC_FOURCC('V','C','R','1')
#define VLC_CODEC_VDPAU_OUTPUT    VLC_FOURCC('V','D','O','R')
#define VLC_CODEC_VDPAU_VIDEO_420 VLC_FOURCC('V','D','V','0')
#define VLC_CODEC_VDPAU_VIDEO_422 VLC_FOURCC('V','D','V','2')
#define VLC_CODEC_VDPAU_VIDEO_444 VLC_FOURCC('V','D','V','4')
#define VLC_CODEC_VIXL            VLC_FOURCC('V','I','X','L')
#define VLC_CODEC_VMDAUDIO                   VLC_FOURCC('v','m','d','a')
#define VLC_CODEC_VMDVIDEO        VLC_FOURCC('V','M','D','V')
#define VLC_CODEC_VMNC            VLC_FOURCC('V','M','n','c')
#define VLC_CODEC_VORBIS                     VLC_FOURCC('v','o','r','b')
#define VLC_CODEC_VP10            VLC_FOURCC('V','P',':','0')
#define VLC_CODEC_VP3             VLC_FOURCC('V','P','3',' ')
#define VLC_CODEC_VP4             VLC_FOURCC('V','P','4','0')
#define VLC_CODEC_VP5             VLC_FOURCC('V','P','5',' ')
#define VLC_CODEC_VP6             VLC_FOURCC('V','P','6','2')
#define VLC_CODEC_VP6A            VLC_FOURCC('V','P','6','A')
#define VLC_CODEC_VP6F            VLC_FOURCC('V','P','6','F')
#define VLC_CODEC_VP7             VLC_FOURCC('V','P','7','0')
#define VLC_CODEC_VP8             VLC_FOURCC('V','P','8','0')
#define VLC_CODEC_VP9             VLC_FOURCC('V','P','9','0')
#define VLC_CODEC_VUYA            VLC_FOURCC('V','U','Y','A')
#define VLC_CODEC_VYUY            VLC_FOURCC('V','Y','U','Y')
#define VLC_CODEC_WAVPACK                    VLC_FOURCC('W','V','P','K')
#define VLC_CODEC_WEBP            VLC_FOURCC('W','E','B','P')
#define VLC_CODEC_WEBVTT    VLC_FOURCC('w','v','t','t')
#define VLC_CODEC_WIDI_LPCM                  VLC_FOURCC('w','p','c','m')
#define VLC_CODEC_WMA1                       VLC_FOURCC('W','M','A','1')
#define VLC_CODEC_WMA2                       VLC_FOURCC('W','M','A','2')
#define VLC_CODEC_WMAL                       VLC_FOURCC('W','M','A','L')
#define VLC_CODEC_WMAP                       VLC_FOURCC('W','M','A','P')
#define VLC_CODEC_WMAS                       VLC_FOURCC('W','M','A','S')
#define VLC_CODEC_WMV1            VLC_FOURCC('W','M','V','1')
#define VLC_CODEC_WMV2            VLC_FOURCC('W','M','V','2')
#define VLC_CODEC_WMV3            VLC_FOURCC('W','M','V','3')
#define VLC_CODEC_WMVA            VLC_FOURCC('W','M','V','A')
#define VLC_CODEC_WMVP            VLC_FOURCC('W','M','V','P')
#define VLC_CODEC_WMVP2           VLC_FOURCC('W','V','P','2')
#define VLC_CODEC_WNV1            VLC_FOURCC('W','N','V','1')
#define VLC_CODEC_WS_VQA          VLC_FOURCC('W','V','Q','A')
#define VLC_CODEC_XAN_WC3         VLC_FOURCC('X','A','N','3')
#define VLC_CODEC_XAN_WC4         VLC_FOURCC('X','x','a','n')
#define VLC_CODEC_XSUB      VLC_FOURCC('X','S','U','B')
#define VLC_CODEC_XWD             VLC_FOURCC('X','W','D',' ')
#define VLC_CODEC_XYZ12     VLC_FOURCC('X','Y','1','2')
#define VLC_CODEC_Y211            VLC_FOURCC('Y','2','1','1')
#define VLC_CODEC_YOP             VLC_FOURCC('Y','O','P','V')
#define VLC_CODEC_YUV420A         VLC_FOURCC('I','4','0','A')
#define VLC_CODEC_YUV422A         VLC_FOURCC('I','4','2','A')
#define VLC_CODEC_YUVA            VLC_FOURCC('Y','U','V','A')
#define VLC_CODEC_YUVA_444_10B    VLC_FOURCC('Y','A','0','B')
#define VLC_CODEC_YUVA_444_10L    VLC_FOURCC('Y','A','0','L')
#define VLC_CODEC_YUVP            VLC_FOURCC('Y','U','V','P')
#define VLC_CODEC_YUYV            VLC_FOURCC('Y','U','Y','2')
#define VLC_CODEC_YV12            VLC_FOURCC('Y','V','1','2')
#define VLC_CODEC_YV9             VLC_FOURCC('Y','V','U','9')
#define VLC_CODEC_YVYU            VLC_FOURCC('Y','V','Y','U')
#define VLC_CODEC_ZMBV            VLC_FOURCC('Z','M','B','V')
#define VLC_FOURCC_H 1
#define A52_FRAME_NB 1536
#define AOUT_CHAN_REMAP_INIT { \
    AOUT_CHANIDX_LEFT,  \
    AOUT_CHANIDX_RIGHT, \
    AOUT_CHANIDX_MIDDLELEFT, \
    AOUT_CHANIDX_MIDDLERIGHT, \
    AOUT_CHANIDX_REARLEFT, \
    AOUT_CHANIDX_REARRIGHT, \
    AOUT_CHANIDX_REARCENTER, \
    AOUT_CHANIDX_CENTER, \
    AOUT_CHANIDX_LFE, \
}
#define AOUT_FILTERS_CFG_INIT (aout_filters_cfg_t) \
    { .remap = AOUT_CHAN_REMAP_INIT, \
      .headphones = false, \
    };
#define AOUT_FMTS_IDENTICAL( p_first, p_second ) (                          \
    ((p_first)->i_format == (p_second)->i_format)                           \
      && AOUT_FMTS_SIMILAR(p_first, p_second) )
#define AOUT_FMTS_SIMILAR( p_first, p_second ) (                            \
    ((p_first)->i_rate == (p_second)->i_rate)                               \
      && ((p_first)->channel_type == (p_second)->channel_type)            \
      && ((p_first)->i_physical_channels == (p_second)->i_physical_channels)\
      && ((p_first)->i_chan_mode == (p_second)->i_chan_mode) )
#define AOUT_FMT_HDMI( p_format )                   \
    ( (p_format)->i_format == VLC_CODEC_EAC3        \
    ||(p_format)->i_format == VLC_CODEC_TRUEHD      \
    ||(p_format)->i_format == VLC_CODEC_MLP         \
    )
#define AOUT_FMT_LINEAR( p_format ) \
    (aout_BitsPerSample((p_format)->i_format) != 0)
#define AOUT_FMT_SPDIF( p_format ) \
    ( ((p_format)->i_format == VLC_CODEC_SPDIFL)       \
       || ((p_format)->i_format == VLC_CODEC_SPDIFB)   \
       || ((p_format)->i_format == VLC_CODEC_A52)      \
       || ((p_format)->i_format == VLC_CODEC_DTS) )
#define AOUT_MAX_ADVANCE_TIME           (AOUT_MAX_PREPARE_TIME + VLC_TICK_FROM_SEC(1))
#define AOUT_MAX_PREPARE_TIME           VLC_TICK_FROM_SEC(2)
#define AOUT_MAX_PTS_ADVANCE            VLC_TICK_FROM_MS(40)
#define AOUT_MAX_PTS_DELAY              VLC_TICK_FROM_MS(60)
#define AOUT_MAX_RESAMPLING             10
#define AOUT_MIN_PREPARE_TIME           AOUT_MAX_PTS_ADVANCE
#define AOUT_RESTART_FILTERS        0x1
#define AOUT_RESTART_OUTPUT         (AOUT_RESTART_FILTERS|0x2)
#define AOUT_RESTART_STEREOMODE     (AOUT_RESTART_OUTPUT|0x4)
#define AOUT_SPDIF_SIZE 6144
#define AOUT_VAR_CHAN_DOLBYS        5
#define AOUT_VAR_CHAN_HEADPHONES    6
#define AOUT_VAR_CHAN_LEFT          3
#define AOUT_VAR_CHAN_MONO          7
#define AOUT_VAR_CHAN_RIGHT         4
#define AOUT_VAR_CHAN_RSTEREO       2
#define AOUT_VAR_CHAN_STEREO        1
#define AOUT_VAR_CHAN_UNSET         0 
#define AOUT_VOLUME_DEFAULT             256
#define AOUT_VOLUME_MAX                 512
#define VLC_AOUT_H 1
#define VLC_CODEC_SPDIFB VLC_FOURCC('s','p','d','b')
#define VLC_CODEC_SPDIFL VLC_FOURCC('s','p','d','i')
#define aout_FiltersDelete(o,f) \
        aout_FiltersDelete(VLC_OBJECT(o),f)
#define aout_FiltersNew(o,inf,outf,remap) \
        aout_FiltersNew(VLC_OBJECT(o),inf,outf,remap)
#define aout_FormatPrint(o, t, f) aout_FormatPrint(VLC_OBJECT(o), t, f)
#define INPUT_RATE_MAX 31.25f
#define INPUT_RATE_MIN 0.03125f
#define INPUT_TITLE_INTERACTIVE  0x02   
#define INPUT_TITLE_MENU         0x01   
#define VLC_INPUT_H 1
#define VLC_VOUT_OSD_H 1
#define VLC_VOUT_H_ 1
#define VOUT_ALIGN_BOTTOM       0x0008
#define VOUT_ALIGN_HMASK        0x0003
#define VOUT_ALIGN_LEFT         0x0001
#define VOUT_ALIGN_RIGHT        0x0002
#define VOUT_ALIGN_TOP          0x0004
#define VOUT_ALIGN_VMASK        0x000C
#define VOUT_SPU_CHANNEL_INVALID      (-1) 
#define VOUT_SPU_CHANNEL_OSD            0 
#define VOUT_SPU_CHANNEL_OSD_COUNT      3
#define VOUT_SPU_CHANNEL_OSD_HSLIDER    1
#define VOUT_SPU_CHANNEL_OSD_VSLIDER    2
#define vout_FlushAll( vout )  vout_Flush( vout, VLC_TICK_INVALID )
#define SUBPICTURE_ALIGN_BOTTOM     0x8
#define SUBPICTURE_ALIGN_LEFT       0x1
#define SUBPICTURE_ALIGN_MASK ( SUBPICTURE_ALIGN_LEFT|SUBPICTURE_ALIGN_RIGHT| \
                                SUBPICTURE_ALIGN_TOP |SUBPICTURE_ALIGN_BOTTOM )
#define SUBPICTURE_ALIGN_RIGHT      0x2
#define SUBPICTURE_ALIGN_TOP        0x4
#define VLC_SUBPICTURE_H 1
#define STYLE_ALPHA_OPAQUE      0xFF
#define STYLE_ALPHA_TRANSPARENT 0x00
#define STYLE_BACKGROUND        (1 << 4)
#define STYLE_BLINK_BACKGROUND  (1 << 11)
#define STYLE_BLINK_FOREGROUND  (1 << 10)
#define STYLE_BOLD              (1 << 0)
#define STYLE_DEFAULT_FONT_SIZE 20
#define STYLE_DEFAULT_REL_FONT_SIZE 6.25
#define STYLE_DOUBLEWIDTH       (1 << 9)
#define STYLE_FULLY_SET                 0xFFFF
#define STYLE_HALFWIDTH         (1 << 7)
#define STYLE_HAS_BACKGROUND_ALPHA      (1 << 8)
#define STYLE_HAS_BACKGROUND_COLOR      (1 << 7)
#define STYLE_HAS_FLAGS                 (1 << 2)
#define STYLE_HAS_FONT_ALPHA            (1 << 1)
#define STYLE_HAS_FONT_COLOR            (1 << 0)
#define STYLE_HAS_OUTLINE_ALPHA         (1 << 4)
#define STYLE_HAS_OUTLINE_COLOR         (1 << 3)
#define STYLE_HAS_SHADOW_ALPHA          (1 << 6)
#define STYLE_HAS_SHADOW_COLOR          (1 << 5)
#define STYLE_HAS_WRAP_INFO             (1 << 9)
#define STYLE_ITALIC            (1 << 1)
#define STYLE_MONOSPACED        (1 << 8)
#define STYLE_NO_DEFAULTS               0x0
#define STYLE_OUTLINE           (1 << 2)
#define STYLE_SHADOW            (1 << 3)
#define STYLE_STRIKEOUT         (1 << 6)
#define STYLE_UNDERLINE         (1 << 5)
#define VLC_TEXT_STYLE_H 1
#define A_PITCH      p[A_PLANE].i_pitch
#define A_PIXELS     p[A_PLANE].p_pixels
#define PICTURE_PLANE_MAX (VOUT_MAX_PLANES)
#define U_PITCH      p[U_PLANE].i_pitch
#define U_PIXELS     p[U_PLANE].p_pixels
#define VLC_PICTURE_H 1
#define V_PITCH      p[V_PLANE].i_pitch
#define V_PIXELS     p[V_PLANE].p_pixels
#define Y_PITCH      p[Y_PLANE].i_pitch
#define Y_PIXELS     p[Y_PLANE].p_pixels
#define INPUT_DURATION_INDEFINITE (-1) 
#define INPUT_DURATION_UNSET      VLC_TICK_INVALID
#define INPUT_ITEM_URI_NOP "vlc://nop" 
#define INPUT_META( name ) \
static inline \
void input_item_Set ## name (input_item_t *p_input, const char *val) \
{ \
    input_item_SetMeta (p_input, vlc_meta_ ## name, val); \
} \
static inline \
char *input_item_Get ## name (input_item_t *p_input) \
{ \
    return input_item_GetMeta (p_input, vlc_meta_ ## name); \
}
#define INPUT_RECORD_PREFIX "vlc-record-%Y-%m-%d-%Hh%Mm%Ss-$ N-$ p"
#define MASTER_EXTENSIONS \
    "asf", "avi", "divx", \
    "f4v", "flv", "m1v", \
    "m2v", "m4v", "mkv", \
    "mov", "mp2", "mp2v", \
    "mp4", "mp4v", "mpe", \
    "mpeg", "mpeg1", "mpeg2", \
    "mpeg4", "mpg", "mpv2", \
    "mxf", "ogv", "ogx", \
    "ps", "vro","webm", \
    "wmv", "wtv"
#define SLAVE_AUDIO_EXTENSIONS \
    "aac", "ac3", "dts", \
    "dtshd", "eac3", "flac", \
    "m4a", "mp3", "pcm" \

#define SLAVE_SPU_EXTENSIONS \
    "aqt", "ass",  "cdg", \
    "dks", "idx", "jss", \
    "mpl2", "mpsub", "pjs", \
    "psb", "rt", "sami", "sbv", \
    "scc", "smi", "srt", \
    "ssa",  "stl", "sub", \
    "tt", "ttml", "usf", \
    "vtt", "webvtt"
#define VLC_INPUT_ITEM_H 1
#define info_foreach(info, cat) vlc_list_foreach(info, cat, node)
#define input_item_GetArtURL   input_item_GetArtworkURL
#define input_item_GetTrackNum input_item_GetTrackNumber
#define input_item_New( psz_uri, psz_name ) \
    input_item_NewExt( psz_uri, psz_name, INPUT_DURATION_UNSET, ITEM_TYPE_UNKNOWN, ITEM_NET_UNKNOWN )
#define input_item_NewCard( psz_uri, psz_name ) \
    input_item_NewExt( psz_uri, psz_name, INPUT_DURATION_INDEFINITE, ITEM_TYPE_CARD, ITEM_LOCAL )
#define input_item_NewDirectory( psz_uri, psz_name, i_net ) \
    input_item_NewExt( psz_uri, psz_name, INPUT_DURATION_UNSET, ITEM_TYPE_DIRECTORY, i_net )
#define input_item_NewDisc( psz_uri, psz_name, i_duration ) \
    input_item_NewExt( psz_uri, psz_name, i_duration, ITEM_TYPE_DISC, ITEM_LOCAL )
#define input_item_NewFile( psz_uri, psz_name, i_duration, i_net ) \
    input_item_NewExt( psz_uri, psz_name, i_duration, ITEM_TYPE_FILE, i_net )
#define input_item_NewStream( psz_uri, psz_name, i_duration ) \
    input_item_NewExt( psz_uri, psz_name, i_duration, ITEM_TYPE_STREAM, ITEM_NET )
#define input_item_SetArtURL   input_item_SetArtworkURL
#define input_item_SetTrackNum input_item_SetTrackNumber
#define input_item_slave_Delete(p_slave) free(p_slave)
#define vlc_readdir_helper_init(p_rdh, p_obj, p_node) \
    vlc_readdir_helper_init(p_rdh, VLC_OBJECT(p_obj), p_node)
# define VLC_LIST_H 1
#define VLC_LIST_INITIALIZER(h) { h, h }
#define vlc_list_entry(ptr, type, member) container_of(ptr, type, member)
#define vlc_list_entry_aligned_size(p) \
    ((sizeof (*(p)) + sizeof (max_align_t) - 1) / sizeof (max_align_t))
#define vlc_list_entry_dummy(p) \
    (0 ? (p) : ((void *)(&(max_align_t[vlc_list_entry_aligned_size(p)]){})))
#define vlc_list_entry_p(node, p, member) \
    (0 ? (p) : (void *)(((char *)(node)) - vlc_list_offset_p(p, member)))
#define vlc_list_first_entry_or_null(head, type, member) \
        ((type *)vlc_list_first_or_null(head, offsetof (type, member)))
#define vlc_list_foreach(pos, head, member) \
    for (struct vlc_list_it vlc_list_it_##pos = vlc_list_it_start(head); \
         vlc_list_it_continue(&(vlc_list_it_##pos)) \
          && ((pos) = vlc_list_entry_p((vlc_list_it_##pos).current, \
                                       pos, member), true); \
         vlc_list_it_next(&(vlc_list_it_##pos)))
#define vlc_list_last_entry_or_null(head, type, member) \
        ((type *)vlc_list_last_or_null(head, offsetof (type, member)))
#define vlc_list_next_entry_or_null(head, entry, type, member) \
        ((type *)vlc_list_next_or_null(head, &(entry)->member, \
                                       offsetof (type, member)))
#define vlc_list_offset_p(p, member) \
    ((p) = vlc_list_entry_dummy(p), (char *)(&(p)->member) - (char *)(p))
#define vlc_list_prev_entry_or_null(head, entry, type, member) \
        ((type *)vlc_list_prev_or_null(head, &(entry)->member, \
                                       offsetof (type, member)))
# define VLC_EVENTS_H
#define ITEM_ART_FETCHED     2
#define ITEM_ART_NOTFOUND    4
#define ITEM_PREPARSED       1
#define VLC_META_ACTORS             vlc_meta_TypeToLocalizedString( vlc_meta_Actors )
#define VLC_META_ALBUM              vlc_meta_TypeToLocalizedString( vlc_meta_Album )
#define VLC_META_ALBUMARTIST        vlc_meta_TypeToLocalizedString( vlc_meta_AlbumArtist )
#define VLC_META_ARTIST             vlc_meta_TypeToLocalizedString( vlc_meta_Artist )
#define VLC_META_ART_URL            vlc_meta_TypeToLocalizedString( vlc_meta_ArtworkURL )
#define VLC_META_COPYRIGHT          vlc_meta_TypeToLocalizedString( vlc_meta_Copyright )
#define VLC_META_DATE               vlc_meta_TypeToLocalizedString( vlc_meta_Date )
#define VLC_META_DESCRIPTION        vlc_meta_TypeToLocalizedString( vlc_meta_Description )
#define VLC_META_DIRECTOR           vlc_meta_TypeToLocalizedString( vlc_meta_Director )
#define VLC_META_DISCNUMBER         vlc_meta_TypeToLocalizedString( vlc_meta_DiscNumber )
#define VLC_META_ENCODED_BY         vlc_meta_TypeToLocalizedString( vlc_meta_EncodedBy )
#define VLC_META_EPISODE            vlc_meta_TypeToLocalizedString( vlc_meta_Episode )
#define VLC_META_EXTRA_MB_ALBUMID   "MB_ALBUMID"
#define VLC_META_GENRE              vlc_meta_TypeToLocalizedString( vlc_meta_Genre )
#define VLC_META_H 1
#define VLC_META_LANGUAGE           vlc_meta_TypeToLocalizedString( vlc_meta_Language )
#define VLC_META_NOW_PLAYING        vlc_meta_TypeToLocalizedString( vlc_meta_NowPlaying )
#define VLC_META_PUBLISHER          vlc_meta_TypeToLocalizedString( vlc_meta_Publisher )
#define VLC_META_RATING             vlc_meta_TypeToLocalizedString( vlc_meta_Rating )
#define VLC_META_SEASON             vlc_meta_TypeToLocalizedString( vlc_meta_Season )
#define VLC_META_SETTING            vlc_meta_TypeToLocalizedString( vlc_meta_Setting )
#define VLC_META_SHOW_NAME          vlc_meta_TypeToLocalizedString( vlc_meta_ShowName )
#define VLC_META_TITLE              vlc_meta_TypeToLocalizedString( vlc_meta_Title )
#define VLC_META_TRACKID            vlc_meta_TypeToLocalizedString( vlc_meta_TrackID )
#define VLC_META_TRACK_NUMBER       vlc_meta_TypeToLocalizedString( vlc_meta_TrackNumber )
#define VLC_META_TYPE_COUNT 27
#define VLC_META_URL                vlc_meta_TypeToLocalizedString( vlc_meta_URL )
#define vlc_meta_SetActors( meta, b )      vlc_meta_Set( meta, vlc_meta_Actors, b )
#define vlc_meta_SetAlbum( meta, b )       vlc_meta_Set( meta, vlc_meta_Album, b )
#define vlc_meta_SetAlbumArtist( meta, b ) vlc_meta_Set( meta, vlc_meta_AlbumArtist, b )
#define vlc_meta_SetArtURL( meta, b )      vlc_meta_Set( meta, vlc_meta_ArtworkURL, b )
#define vlc_meta_SetArtist( meta, b )      vlc_meta_Set( meta, vlc_meta_Artist, b )
#define vlc_meta_SetCopyright( meta, b )   vlc_meta_Set( meta, vlc_meta_Copyright, b )
#define vlc_meta_SetDate( meta, b )        vlc_meta_Set( meta, vlc_meta_Date, b )
#define vlc_meta_SetDescription( meta, b ) vlc_meta_Set( meta, vlc_meta_Description, b )
#define vlc_meta_SetDirector( meta, b )    vlc_meta_Set( meta, vlc_meta_Director, b )
#define vlc_meta_SetDiscNumber( meta, b )  vlc_meta_Set( meta, vlc_meta_DiscNumber, b )
#define vlc_meta_SetEncodedBy( meta, b )   vlc_meta_Set( meta, vlc_meta_EncodedBy, b )
#define vlc_meta_SetEpisode( meta, b )     vlc_meta_Set( meta, vlc_meta_Episode, b )
#define vlc_meta_SetGenre( meta, b )       vlc_meta_Set( meta, vlc_meta_Genre, b )
#define vlc_meta_SetLanguage( meta, b )    vlc_meta_Set( meta, vlc_meta_Language, b )
#define vlc_meta_SetNowPlaying( meta, b )  vlc_meta_Set( meta, vlc_meta_NowPlaying, b )
#define vlc_meta_SetPublisher( meta, b )   vlc_meta_Set( meta, vlc_meta_Publisher, b )
#define vlc_meta_SetRating( meta, b )      vlc_meta_Set( meta, vlc_meta_Rating, b )
#define vlc_meta_SetSeason( meta, b )      vlc_meta_Set( meta, vlc_meta_Season, b )
#define vlc_meta_SetSetting( meta, b )     vlc_meta_Set( meta, vlc_meta_Setting, b )
#define vlc_meta_SetShowName( meta, b )    vlc_meta_Set( meta, vlc_meta_ShowName, b )
#define vlc_meta_SetTitle( meta, b )       vlc_meta_Set( meta, vlc_meta_Title, b )
#define vlc_meta_SetTrackID( meta, b )     vlc_meta_Set( meta, vlc_meta_TrackID, b )
#define vlc_meta_SetTrackNum( meta, b )    vlc_meta_Set( meta, vlc_meta_TrackNumber, b )
#define vlc_meta_SetTrackTotal( meta, b )  vlc_meta_Set( meta, vlc_meta_TrackTotal, b )
#define vlc_meta_SetURL( meta, b )         vlc_meta_Set( meta, vlc_meta_URL, b )
#define VLC_EPG_H 1
# define FromLocale    FromANSI
# define FromLocaleDup FromANSI
# define LocaleFree(s) free((char *)(s))
# define ToLocale      ToANSI
# define ToLocaleDup   ToANSI
#define VLC_CHARSET_H 1
#define VLC_ICONV_ERR ((size_t) -1)
#define CAT_ADVANCED 6
#define CAT_AUDIO 2
#define CAT_INPUT 4
#define CAT_INTERFACE 1
#define CAT_PLAYLIST 7
#define CAT_SOUT 5
#define CAT_VIDEO 3
#   define CDECL_SYMBOL            __cdecl
#define CONCATENATE( y, z ) CRUDE_HACK( y, z )
#define CONFIG_CATEGORY                     0x06 
#define CONFIG_HINT_CATEGORY                0x02  
#define CONFIG_HINT_USAGE                   0x05  
#define CONFIG_ITEM(x) (((x) & ~0xF) != 0)
#define CONFIG_ITEM_BOOL                    0x60  
#define CONFIG_ITEM_DIRECTORY               0x8E  
#define CONFIG_ITEM_FLOAT                   0x20  
#define CONFIG_ITEM_FONT                    0x8F  
#define CONFIG_ITEM_INTEGER                 0x40  
#define CONFIG_ITEM_KEY                     0x82  
#define CONFIG_ITEM_LOADFILE                0x8C  
#define CONFIG_ITEM_MODULE                  0x84  
#define CONFIG_ITEM_MODULE_CAT              0x85  
#define CONFIG_ITEM_MODULE_LIST             0x86  
#define CONFIG_ITEM_MODULE_LIST_CAT         0x87  
#define CONFIG_ITEM_PASSWORD                0x81  
#define CONFIG_ITEM_RGB                     0x41  
#define CONFIG_ITEM_SAVEFILE                0x8D  
#define CONFIG_ITEM_STRING                  0x80  
#define CONFIG_SECTION                      0x08 
#define CONFIG_SUBCATEGORY                  0x07 
#define CRUDE_HACK( y, z )  y##__##z
#   define DLL_SYMBOL              __declspec(dllexport)
#   define EXTERN_SYMBOL           extern "C"
# define LIBVLC_MODULES_MACROS_H 1
#define SUBCAT_ADVANCED_MISC 602
#define SUBCAT_ADVANCED_NETWORK 603
#define SUBCAT_AUDIO_AFILTER 203
#define SUBCAT_AUDIO_AOUT 202
#define SUBCAT_AUDIO_GENERAL 201
#define SUBCAT_AUDIO_MISC 205
#define SUBCAT_AUDIO_RESAMPLER 206
#define SUBCAT_AUDIO_VISUAL 204
#define SUBCAT_INPUT_ACCESS 402
#define SUBCAT_INPUT_ACODEC 405
#define SUBCAT_INPUT_DEMUX 403
#define SUBCAT_INPUT_GENERAL 401
#define SUBCAT_INPUT_SCODEC 406
#define SUBCAT_INPUT_STREAM_FILTER 407
#define SUBCAT_INPUT_VCODEC 404
#define SUBCAT_INTERFACE_CONTROL 103
#define SUBCAT_INTERFACE_GENERAL 101
#define SUBCAT_INTERFACE_HOTKEYS 104
#define SUBCAT_INTERFACE_MAIN 102
#define SUBCAT_PLAYLIST_EXPORT 703
#define SUBCAT_PLAYLIST_GENERAL 701
#define SUBCAT_PLAYLIST_SD 702
#define SUBCAT_SOUT_ACO 504
#define SUBCAT_SOUT_GENERAL 501
#define SUBCAT_SOUT_MUX 503
#define SUBCAT_SOUT_PACKETIZER 505
#define SUBCAT_SOUT_RENDERER 508
#define SUBCAT_SOUT_STREAM 502
#define SUBCAT_SOUT_VOD 507
#define SUBCAT_VIDEO_GENERAL 301
#define SUBCAT_VIDEO_SPLITTER 306
#define SUBCAT_VIDEO_SUBPIC 305
#define SUBCAT_VIDEO_VFILTER 303
#define SUBCAT_VIDEO_VOUT 302
#define VLC_API_VERSION_EXPORT \
    VLC_META_EXPORT(api_version, VLC_API_VERSION_STRING)
#define VLC_API_VERSION_STRING "4.0.4"
#define VLC_CONFIG_INTEGER_ENUM(cb) \
EXTERN_SYMBOL DLL_SYMBOL \
int CDECL_SYMBOL VLC_SYMBOL(vlc_entry_cfg_int_enum)(const char *name, \
    int64_t **values, char ***descs) \
{ \
    return (cb)(name, values, descs); \
}
#define VLC_CONFIG_STRING_ENUM(cb) \
EXTERN_SYMBOL DLL_SYMBOL \
int CDECL_SYMBOL VLC_SYMBOL(vlc_entry_cfg_str_enum)(const char *name, \
    char ***values, char ***descs) \
{ \
    return (cb)(name, values, descs); \
}
# define VLC_COPYRIGHT_EXPORT VLC_META_EXPORT(copyright, VLC_MODULE_COPYRIGHT)
#define VLC_COPYRIGHT_VIDEOLAN \
    "\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x20\x28\x43\x29\x20\x74\x68" \
    "\x65\x20\x56\x69\x64\x65\x6f\x4c\x41\x4e\x20\x56\x4c\x43\x20\x6d" \
    "\x65\x64\x69\x61\x20\x70\x6c\x61\x79\x65\x72\x20\x64\x65\x76\x65" \
    "\x6c\x6f\x70\x65\x72\x73"
# define VLC_LICENSE_EXPORT VLC_META_EXPORT(license, VLC_MODULE_LICENSE)
#define VLC_LICENSE_GPL_2_PLUS \
    "\x4c\x69\x63\x65\x6e\x73\x65\x64\x20\x75\x6e\x64\x65\x72\x20\x74" \
    "\x68\x65\x20\x74\x65\x72\x6d\x73\x20\x6f\x66\x20\x74\x68\x65\x20" \
    "\x47\x4e\x55\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x50\x75\x62\x6c" \
    "\x69\x63\x20\x4c\x69\x63\x65\x6e\x73\x65\x2c\x20\x76\x65\x72\x73" \
    "\x69\x6f\x6e\x20\x32\x20\x6f\x72\x20\x6c\x61\x74\x65\x72\x2e"
#define VLC_LICENSE_LGPL_2_1_PLUS \
    "\x4c\x69\x63\x65\x6e\x73\x65\x64\x20\x75\x6e\x64\x65\x72\x20\x74" \
    "\x68\x65\x20\x74\x65\x72\x6d\x73\x20\x6f\x66\x20\x74\x68\x65\x20" \
    "\x47\x4e\x55\x20\x4c\x65\x73\x73\x65\x72\x20\x47\x65\x6e\x65\x72" \
    "\x61\x6c\x20\x50\x75\x62\x6c\x69\x63\x20\x4c\x69\x63\x65\x6e\x73" \
    "\x65\x2c\x20\x76\x65\x72\x73\x69\x6f\x6e\x20\x32\x2e\x31\x20\x6f" \
    "\x72\x20\x6c\x61\x74\x65\x72\x2e"
#define VLC_METADATA_EXPORTS \
    VLC_API_VERSION_EXPORT \
    VLC_COPYRIGHT_EXPORT \
    VLC_LICENSE_EXPORT
#define VLC_META_EXPORT( name, value ) \
    EXTERN_SYMBOL DLL_SYMBOL const char * CDECL_SYMBOL \
    VLC_SYMBOL(vlc_entry_ ## name)(void); \
    EXTERN_SYMBOL DLL_SYMBOL const char * CDECL_SYMBOL \
    VLC_SYMBOL(vlc_entry_ ## name)(void) \
    { \
         return value; \
    }
# define VLC_MODULE_COPYRIGHT VLC_COPYRIGHT_VIDEOLAN
#  define VLC_MODULE_LICENSE VLC_LICENSE_LGPL_2_1_PLUS
# define VLC_MODULE_NAME_HIDDEN_SYMBOL \
    const char vlc_module_name[] = MODULE_STRING;
# define VLC_SYMBOL(symbol) symbol
#define add_bool( name, v, text, longtext, advc ) \
    add_typename_inner(CONFIG_ITEM_BOOL, name, text, longtext) \
    if (v) vlc_config_set (VLC_CONFIG_VALUE, (int64_t)true);
#define add_category_hint(text, longtext) \
    add_typedesc_inner( CONFIG_HINT_CATEGORY, text, longtext )
#define add_directory(name, value, text, longtext) \
    add_string_inner(CONFIG_ITEM_DIRECTORY, name, text, longtext, value)
#define add_float( name, v, text, longtext, advc ) \
    add_typename_inner(CONFIG_ITEM_FLOAT, name, text, longtext) \
    vlc_config_set (VLC_CONFIG_VALUE, (double)(v));
#define add_float_with_range( name, value, f_min, f_max, text, longtext, advc ) \
    add_float( name, value, text, longtext, advc ) \
    change_float_range( f_min, f_max )
#define add_font(name, value, text, longtext) \
    add_string_inner(CONFIG_ITEM_FONT, name, text, longtext, value)
#define add_int_inner(type, name, text, longtext, v) \
    add_typename_inner(type, name, text, longtext) \
    vlc_config_set (VLC_CONFIG_VALUE, (int64_t)(v));
#define add_integer( name, value, text, longtext, advc ) \
    add_int_inner(CONFIG_ITEM_INTEGER, name, text, longtext, value)
#define add_integer_with_range( name, value, i_min, i_max, text, longtext, advc ) \
    add_integer( name, value, text, longtext, advc ) \
    change_integer_range( i_min, i_max )
#define add_key(name, value, text, longtext) \
    add_string_inner(CONFIG_ITEM_KEY, "global-" name, text, longtext, \
                     KEY_UNSET) \
    add_string_inner(CONFIG_ITEM_KEY, name, text, longtext, value)
#define add_loadfile(name, value, text, longtext) \
    add_string_inner(CONFIG_ITEM_LOADFILE, name, text, longtext, value)
#define add_module(name, psz_caps, value, text, longtext) \
    add_string_inner(CONFIG_ITEM_MODULE, name, text, longtext, value) \
    vlc_config_set (VLC_CONFIG_CAPABILITY, (const char *)(psz_caps));
#define add_module_cat(name, i_subcategory, value, text, longtext) \
    add_string_inner(CONFIG_ITEM_MODULE_CAT, name, text, longtext, value) \
    change_integer_range (i_subcategory , 0);
#define add_module_list(name, psz_caps, value, text, longtext) \
    add_string_inner(CONFIG_ITEM_MODULE_LIST, name, text, longtext, value) \
    vlc_config_set (VLC_CONFIG_CAPABILITY, (const char *)(psz_caps));
#define add_module_list_cat(name, i_subcategory, value, text, longtext) \
    add_string_inner(CONFIG_ITEM_MODULE_LIST_CAT, name, text, longtext, \
                     value) \
    change_integer_range (i_subcategory , 0);
#define add_obsolete_bool( name ) \
        add_obsolete_inner( name, CONFIG_ITEM_BOOL )
#define add_obsolete_float( name ) \
        add_obsolete_inner( name, CONFIG_ITEM_FLOAT )
#define add_obsolete_inner( name, type ) \
    add_type_inner( type ) \
    vlc_config_set (VLC_CONFIG_NAME, (const char *)(name)); \
    vlc_config_set (VLC_CONFIG_REMOVED);
#define add_obsolete_integer( name ) \
        add_obsolete_inner( name, CONFIG_ITEM_INTEGER )
#define add_obsolete_string( name ) \
        add_obsolete_inner( name, CONFIG_ITEM_STRING )
#define add_password(name, value, text, longtext) \
    add_string_inner(CONFIG_ITEM_PASSWORD, name, text, longtext, value)
#define add_rgb(name, value, text, longtext) \
    add_int_inner(CONFIG_ITEM_RGB, name, text, longtext, value) \
    change_integer_range( 0, 0xFFFFFF )
#define add_savefile(name, value, text, longtext) \
    add_string_inner(CONFIG_ITEM_SAVEFILE, name, text, longtext, value)
#define add_shortcut( ... ) \
{ \
    const char *shortcuts[] = { __VA_ARGS__ }; \
    if (vlc_module_set (VLC_MODULE_SHORTCUT, \
                        sizeof(shortcuts)/sizeof(shortcuts[0]), shortcuts)) \
        goto error; \
}
#define add_string( name, value, text, longtext, advc ) \
    add_string_inner(CONFIG_ITEM_STRING, name, text, longtext, value)
#define add_string_inner(type, name, text, longtext, v) \
    add_typename_inner(type, name, text, longtext) \
    vlc_config_set (VLC_CONFIG_VALUE, (const char *)(v));
#define add_submodule( ) \
    if (vlc_plugin_set (VLC_MODULE_CREATE, &module)) \
        goto error;
#define add_type_inner( type ) \
    vlc_plugin_set (VLC_CONFIG_CREATE, (type), &config);
#define add_typedesc_inner( type, text, longtext ) \
    add_type_inner( type ) \
    vlc_config_set (VLC_CONFIG_DESC, \
                    (const char *)(text), (const char *)(longtext));
#define add_typename_inner(type, name, text, longtext) \
    add_typedesc_inner(type, text, longtext) \
    vlc_config_set (VLC_CONFIG_NAME, (const char *)(name));
#define add_usage_hint( text ) \
    add_typedesc_inner( CONFIG_HINT_USAGE, text, NULL )
#define cannot_unload_broken_library( ) \
    if (vlc_module_set (VLC_MODULE_NO_UNLOAD)) \
        goto error;
#define change_float_range( minv, maxv ) \
    vlc_config_set (VLC_CONFIG_RANGE, (double)(minv), (double)(maxv));
#define change_integer_list( list, list_text ) \
    vlc_config_set (VLC_CONFIG_LIST, \
                    (size_t)(sizeof (list) / sizeof (int)), \
                    (const int *)(list), \
                    (const char *const *)(list_text));
#define change_integer_range( minv, maxv ) \
    vlc_config_set (VLC_CONFIG_RANGE, (int64_t)(minv), (int64_t)(maxv));
#define change_private() \
    vlc_config_set (VLC_CONFIG_PRIVATE);
#define change_safe() \
    vlc_config_set (VLC_CONFIG_SAFE);
#define change_short( ch ) \
    vlc_config_set (VLC_CONFIG_SHORTCUT, (int)(ch));
#define change_string_list( list, list_text ) \
    vlc_config_set (VLC_CONFIG_LIST, \
                    (size_t)(sizeof (list) / sizeof (char *)), \
                    (const char *const *)(list), \
                    (const char *const *)(list_text));
#define change_volatile() \
    change_private() \
    vlc_config_set (VLC_CONFIG_VOLATILE);
#define set_callback(activate) \
    if (vlc_module_set(VLC_MODULE_CB_OPEN, #activate, (void *)(activate))) \
        goto error;
#define set_callbacks( activate, deactivate ) \
    set_callback(activate) \
    if (vlc_module_set(VLC_MODULE_CB_CLOSE, #deactivate, \
                       (void (*)(vlc_object_t *)){ deactivate })) \
        goto error;
#define set_capability( cap, score ) \
    if (vlc_module_set (VLC_MODULE_CAPABILITY, (const char *)(cap)) \
     || vlc_module_set (VLC_MODULE_SCORE, (int)(score))) \
        goto error;
#define set_category( i_id ) \
    add_type_inner( CONFIG_CATEGORY ) \
    vlc_config_set (VLC_CONFIG_VALUE, (int64_t)(i_id));
#define set_description( desc ) \
    if (vlc_module_set (VLC_MODULE_DESCRIPTION, (const char *)(desc))) \
        goto error;
#define set_help( help ) \
    if (vlc_module_set (VLC_MODULE_HELP, (const char *)(help))) \
        goto error;
#define set_section( text, longtext ) \
    add_typedesc_inner( CONFIG_SECTION, text, longtext )
#define set_shortname( shortname ) \
    if (vlc_module_set (VLC_MODULE_SHORTNAME, (const char *)(shortname))) \
        goto error;
#define set_subcategory( i_id ) \
    add_type_inner( CONFIG_SUBCATEGORY ) \
    vlc_config_set (VLC_CONFIG_VALUE, (int64_t)(i_id));
#define set_text_domain( dom ) \
    if (vlc_plugin_set (VLC_MODULE_TEXTDOMAIN, (dom))) \
        goto error;
#define vlc_config_set(...) vlc_set (opaque, config, __VA_ARGS__)
#define vlc_module_begin() \
EXTERN_SYMBOL DLL_SYMBOL \
int CDECL_SYMBOL VLC_SYMBOL(vlc_entry)(vlc_set_cb vlc_set, void *opaque) \
{ \
    module_t *module; \
    module_config_t *config = NULL; \
    if (vlc_plugin_set (VLC_MODULE_CREATE, &module)) \
        goto error; \
    if (vlc_module_set (VLC_MODULE_NAME, (MODULE_STRING))) \
        goto error;
#define vlc_module_end() \
    (void) config; \
    return 0; \
error: \
    return -1; \
} \
VLC_MODULE_NAME_HIDDEN_SYMBOL \
VLC_METADATA_EXPORTS
#define vlc_module_set(...) vlc_set (opaque, module, __VA_ARGS__)
#define vlc_plugin_set(...) vlc_set (opaque,   NULL, __VA_ARGS__)




