#include<xmmintrin.h>



#include<stdlib.h>


#include<math.h>

#include<fcntl.h>
#include<stddef.h>


#include<sys/stat.h>
#include<sys/time.h>
#include<limits.h>
#include<string.h>

#include<unistd.h>
#include<stdarg.h>
#include<alloca.h>
#include<sys/param.h>
#include<time.h>

#include<sys/types.h>
#include<stdint.h>
#include<errno.h>
#include<stdio.h>

#include<float.h>



#define NJS_EVENT_DELETE       2
#define NJS_EVENT_RELEASE      1

#define njs_posted_events(vm) (!njs_queue_is_empty(&(vm)->posted_events))
#define njs_promise_events(vm) (!njs_queue_is_empty(&(vm)->promise_events))
#define njs_waiting_events(vm) (!njs_lvlhsh_is_empty(&(vm)->events_hash))











#define NJS_FRAME_SIZE                                                        \
    njs_align_size(sizeof(njs_frame_t), sizeof(njs_value_t))
#define NJS_FRAME_SPARE_SIZE       (4 * 1024)
#define NJS_NATIVE_FRAME_SIZE                                                 \
    njs_align_size(sizeof(njs_native_frame_t), sizeof(njs_value_t))



#define njs_array_buffer_size(buffer)                                        \
    ((buffer)->size)
#define NJS_ARRAY_FAST_OBJECT_LENGTH   (1024)
#define NJS_ARRAY_FLAT_MAX_LENGTH      (1048576)
#define NJS_ARRAY_INVALID_INDEX        NJS_ARRAY_MAX_INDEX
#define NJS_ARRAY_LARGE_OBJECT_LENGTH  (32768)
#define NJS_ARRAY_MAX_INDEX            0xffffffff
#define NJS_ARRAY_SPARE                8

#define njs_fast_object(_sz)           ((_sz) <= NJS_ARRAY_FAST_OBJECT_LENGTH)
#define NJS_262_HASH                                                          \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        '$'), '2'), '6'), '2')
#define NJS_AGGREGATE_ERROR_HASH                                              \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'A'), 'g'), 'g'), 'r'), 'e'), 'g'), 'a'), 't'), 'e'),                 \
        'E'), 'r'), 'r'), 'o'), 'r')
#define NJS_ARGV_HASH                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'a'), 'r'), 'g'), 'v')
#define NJS_ARRAY_BUFFER_HASH                                                 \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'A'), 'r'), 'r'), 'a'), 'y'), 'B'), 'u'), 'f'), 'f'), 'e'), 'r')
#define NJS_ARRAY_HASH                                                        \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'A'), 'r'), 'r'), 'a'), 'y')
#define NJS_BOOLEAN_HASH                                                      \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'B'), 'o'), 'o'), 'l'), 'e'), 'a'), 'n')
#define NJS_BUFFER_HASH                                                       \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'B'), 'u'), 'f'), 'f'), 'e'), 'r')
#define NJS_CONFIGURABLE_HASH                                                 \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'c'), 'o'), 'n'), 'f'), 'i'), 'g'), 'u'), 'r'), 'a'), 'b'), 'l'), 'e')
#define NJS_CONSTRUCTOR_HASH                                                  \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'c'), 'o'), 'n'), 's'), 't'), 'r'), 'u'), 'c'), 't'), 'o'), 'r')
#define NJS_DATA_VIEW_HASH                                                    \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'D'), 'a'), 't'), 'a'), 'V'), 'i'), 'e'), 'w')
#define NJS_DATE_HASH                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'D'), 'a'), 't'), 'e')
#define NJS_ENCODING_HASH                                                     \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'e'), 'n'), 'c'), 'o'), 'd'), 'i'), 'n'), 'g')
#define NJS_ENUMERABLE_HASH                                                   \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'e'), 'n'), 'u'), 'm'), 'e'), 'r'), 'a'), 'b'), 'l'), 'e')
#define NJS_ENV_HASH                                                          \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'e'), 'n'), 'v')
#define NJS_ERRNO_HASH                                                        \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'e'), 'r'), 'r'), 'n'), 'o')
#define NJS_ERRORS_HASH                                                       \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'e'), 'r'), 'r'), 'o'), 'r'), 's')
#define NJS_ERROR_HASH                                                        \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'E'), 'r'), 'r'), 'o'), 'r')
#define NJS_EVAL_ERROR_HASH                                                   \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'E'), 'v'), 'a'), 'l'), 'E'), 'r'), 'r'), 'o'), 'r')
#define NJS_FLAG_HASH                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'f'), 'l'), 'a'), 'g')
#define NJS_FLOAT32ARRAY_HASH                                                 \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'F'), 'l'), 'o'), 'a'), 't'), '3'), '2'), 'A'), 'r'), 'r'), 'a'), 'y')
#define NJS_FLOAT64ARRAY_HASH                                                 \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'F'), 'l'), 'o'), 'a'), 't'), '6'), '4'), 'A'), 'r'), 'r'), 'a'), 'y')
#define NJS_FUNCTION_HASH                                                     \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'F'), 'u'), 'n'), 'c'), 't'), 'i'), 'o'), 'n')
#define NJS_GET_HASH                                                          \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'g'), 'e'), 't')
#define NJS_GLOBAL_HASH                                                       \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'g'), 'l'), 'o'), 'b'), 'a'), 'l')
#define NJS_GLOBAL_THIS_HASH                                                  \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'g'), 'l'), 'o'), 'b'), 'a'), 'l'), 'T'), 'h'), 'i'), 's')
#define NJS_GROUPS_HASH                                                       \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'g'), 'r'), 'o'), 'u'), 'p'), 's')
#define NJS_INDEX_HASH                                                        \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'i'), 'n'), 'd'), 'e'), 'x')
#define NJS_INPUT_HASH                                                        \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'i'), 'n'), 'p'), 'u'), 't')
#define NJS_INT16ARRAY_HASH                                                   \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'I'), 'n'), 't'), '1'), '6'), 'A'), 'r'), 'r'), 'a'), 'y')
#define NJS_INT32ARRAY_HASH                                                   \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'I'), 'n'), 't'), '3'), '2'), 'A'), 'r'), 'r'), 'a'), 'y')
#define NJS_INT8ARRAY_HASH                                                    \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'I'), 'n'), 't'), '8'), 'A'), 'r'), 'r'), 'a'), 'y')
#define NJS_INTERNAL_ERROR_HASH                                               \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'I'), 'n'), 't'), 'e'), 'r'), 'n'), 'a'), 'l'),                       \
        'E'), 'r'), 'r'), 'o'), 'r')
#define NJS_JOIN_HASH                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'j'), 'o'), 'i'), 'n')
#define NJS_JSON_HASH                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'J'), 'S'), 'O'), 'N')
#define NJS_LENGTH_HASH                                                       \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'l'), 'e'), 'n'), 'g'), 't'), 'h')
#define NJS_MATH_HASH                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'M'), 'a'), 't'), 'h')
#define NJS_MEMORY_ERROR_HASH                                                 \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'M'), 'e'), 'm'), 'o'), 'r'), 'y'),                                   \
        'E'), 'r'), 'r'), 'o'), 'r')
#define NJS_MESSAGE_HASH                                                      \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'm'), 'e'), 's'), 's'), 'a'), 'g'), 'e')
#define NJS_MODE_HASH                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'm'), 'o'), 'd'), 'e')
#define NJS_NAME_HASH                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'n'), 'a'), 'm'), 'e')
#define NJS_NJS_HASH                                                          \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'n'), 'j'), 's')
#define NJS_NUMBER_HASH                                                       \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'N'), 'u'), 'm'), 'b'), 'e'), 'r')
#define NJS_OBJECT_HASH                                                       \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'O'), 'b'), 'j'), 'e'), 'c'), 't')
#define NJS_PATH_HASH                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'p'), 'a'), 't'), 'h')
#define NJS_PROCESS_HASH                                                      \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'p'), 'r'), 'o'), 'c'), 'e'), 's'), 's')
#define NJS_PROMISE_HASH                                                      \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'P'), 'r'), 'o'), 'm'), 'i'), 's'), 'e')
#define NJS_PROTOTYPE_HASH                                                    \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'p'), 'r'), 'o'), 't'), 'o'), 't'), 'y'), 'p'), 'e')
#define NJS_RANGE_ERROR_HASH                                                  \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'R'), 'a'), 'n'), 'g'), 'e'), 'E'), 'r'), 'r'), 'o'), 'r')
#define NJS_REF_ERROR_HASH                                                    \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'R'), 'e'), 'f'), 'e'), 'r'), 'e'), 'n'), 'c'), 'e'),                 \
        'E'), 'r'), 'r'), 'o'), 'r')
#define NJS_REGEXP_HASH                                                       \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'R'), 'e'), 'g'), 'E'), 'x'), 'p')
#define NJS_SET_HASH                                                          \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        's'), 'e'), 't')
#define NJS_STACK_HASH                                                        \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        's'), 't'), 'a'), 'c'), 'k')
#define NJS_STRING_HASH                                                       \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'S'), 't'), 'r'), 'i'), 'n'), 'g')
#define NJS_SYMBOL_HASH                                                       \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'S'), 'y'), 'm'), 'b'), 'o'), 'l')
#define NJS_SYNTAX_ERROR_HASH                                                 \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'S'), 'y'), 'n'), 't'), 'a'), 'x'),                                   \
        'E'), 'r'), 'r'), 'o'), 'r')
#define NJS_SYSCALL_HASH                                                      \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        's'), 'y'), 's'), 'c'), 'a'), 'l'), 'l')
#define NJS_TEXT_DECODER_HASH                                                 \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'T'), 'e'), 'x'), 't'), 'D'), 'e'), 'c'), 'o'), 'd'), 'e'), 'r')
#define NJS_TEXT_ENCODER_HASH                                                 \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'T'), 'e'), 'x'), 't'), 'E'), 'n'), 'c'), 'o'), 'd'), 'e'), 'r')
#define NJS_TO_ISO_STRING_HASH                                                \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        't'), 'o'), 'I'), 'S'), 'O'), 'S'), 't'), 'r'), 'i'), 'n'), 'g')
#define NJS_TO_JSON_HASH                                                      \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        't'), 'o'), 'J'), 'S'), 'O'), 'N')
#define NJS_TO_STRING_HASH                                                    \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        't'), 'o'), 'S'), 't'), 'r'), 'i'), 'n'), 'g')
#define NJS_TYPE_ERROR_HASH                                                   \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'T'), 'y'), 'p'), 'e'), 'E'), 'r'), 'r'), 'o'), 'r')
#define NJS_UINT16ARRAY_HASH                                                  \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'U'), 'i'), 'n'), 't'), '1'), '6'), 'A'), 'r'), 'r'), 'a'), 'y')
#define NJS_UINT32ARRAY_HASH                                                  \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'U'), 'i'), 'n'), 't'), '3'), '2'), 'A'), 'r'), 'r'), 'a'), 'y')
#define NJS_UINT8ARRAY_HASH                                                   \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'U'), 'i'), 'n'), 't'), '8'), 'A'), 'r'), 'r'), 'a'), 'y')
#define NJS_UINT8CLAMPEDARRAY_HASH                                            \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'U'), 'i'), 'n'), 't'), '8'), 'C'), 'l'), 'a'), 'm'), 'p'), 'e'),     \
        'd'), 'A'), 'r'), 'r'), 'a'), 'y')
#define NJS_URI_ERROR_HASH                                                    \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'U'), 'R'), 'I'), 'E'), 'r'), 'r'), 'o'), 'r')
#define NJS_VALUE_HASH                                                        \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'v'), 'a'), 'l'), 'u'), 'e')
#define NJS_VALUE_OF_HASH                                                     \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'v'), 'a'), 'l'), 'u'), 'e'), 'O'), 'f')
#define NJS_WRITABABLE_HASH                                                   \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        'w'), 'r'), 'i'), 't'), 'a'), 'b'), 'l'), 'e')
#define NJS___PROTO___HASH                                                    \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(                                                         \
    njs_djb_hash_add(NJS_DJB_HASH_INIT,                                       \
        '_'), '_'), 'p'), 'r'), 'o'), 't'), 'o'), '_'), '_')

#define NJS_TRAVERSE_MAX_DEPTH 32

#define njs_object_proto_lookup(proto, vtype, ctype)                         \
    (ctype *) _njs_object_proto_lookup(proto, vtype)
#define NJS_STRING_MAP_STRIDE  32
#define NJS_STRING_MAX_LENGTH  0x7fffffff

#define njs_string_map_offset(size)  njs_align_size((size), sizeof(uint32_t))
#define njs_string_map_size(length)                                           \
    (((length - 1) / NJS_STRING_MAP_STRIDE) * sizeof(uint32_t))
#define njs_string_map_start(p)                                               \
    ((uint32_t *) njs_align_ptr((p), sizeof(uint32_t)))


#define NJS_INDEX_ERROR         ((njs_index_t) -1)
#define NJS_INDEX_NONE          ((njs_index_t) 0)
#define NJS_SCOPE_TYPE_MASK     ((NJS_SCOPE_VALUE_MAX) << NJS_SCOPE_VAR_SIZE)
#define NJS_SCOPE_TYPE_OFFSET   (NJS_SCOPE_VAR_SIZE + 4)
#define NJS_SCOPE_VALUE_MAX     ((1 << (32 - NJS_SCOPE_VALUE_OFFSET)) - 1)
#define NJS_SCOPE_VALUE_OFFSET  (NJS_SCOPE_TYPE_OFFSET + 1)
#define NJS_SCOPE_VAR_SIZE      4



#define njs_parser_after(_p, _l, _n, _opt, _state)                          \
    _njs_parser_after(_p, _l, _n, _opt, _state)
#define njs_parser_is_lvalue(node)                                            \
    ((node)->token_type == NJS_TOKEN_NAME                                     \
     || (node)->token_type == NJS_TOKEN_PROPERTY)
#define njs_parser_next(parser, _state)                                     \
    do {                                                                    \
        const char *name = njs_stringify(_state);                           \
        if (memcmp(name, "entry->state", njs_min(njs_strlen(name), 12))) {  \
            njs_printf("next(%s)\n", name + njs_length("njs_parser_"));     \
        }                                                                   \
                                                                            \
        parser->state = _state;                                             \
    } while(0)
#define njs_parser_ref_error(parser, fmt, ...)                                \
    njs_parser_lexer_error(parser, NJS_OBJ_TYPE_REF_ERROR, fmt,               \
                           ##__VA_ARGS__)
#define njs_parser_restricted_identifier(token)                               \
    (token == NJS_TOKEN_ARGUMENTS || token == NJS_TOKEN_EVAL)
#define njs_parser_syntax_error(parser, fmt, ...)                             \
    njs_parser_lexer_error(parser, NJS_OBJ_TYPE_SYNTAX_ERROR, fmt,            \
                           ##__VA_ARGS__)
#define NJS_TOKEN_FIRST_CONST     NJS_TOKEN_NULL
#define NJS_TOKEN_LAST_ASSIGNMENT   NJS_TOKEN_POST_DECREMENT
#define NJS_TOKEN_LAST_CONST      NJS_TOKEN_STRING


#define NJS_PREEMPT                     (-11)
#define NJS_VMCODE_2OPERANDS            1
#define NJS_VMCODE_3OPERANDS            0


#define NJS_INT64_DBL_MAX   (9.223372036854776e+18) 
#define NJS_INT64_DBL_MIN   (-9.223372036854776e+18) 
#define NJS_MAX_LENGTH      (0x1fffffffffffffLL)


#define njs_error(vm, fmt, ...)                                               \
    njs_error_fmt_new(vm, &vm->retval, NJS_OBJ_TYPE_ERROR, fmt, ##__VA_ARGS__)
#define njs_eval_error(vm, fmt, ...)                                          \
    njs_error_fmt_new(vm, &vm->retval, NJS_OBJ_TYPE_EVAL_ERROR, fmt,          \
                      ##__VA_ARGS__)
#define njs_internal_error(vm, fmt, ...)                                      \
    njs_error_fmt_new(vm, &vm->retval, NJS_OBJ_TYPE_INTERNAL_ERROR, fmt,      \
                      ##__VA_ARGS__)
#define njs_range_error(vm, fmt, ...)                                         \
    njs_error_fmt_new(vm, &vm->retval, NJS_OBJ_TYPE_RANGE_ERROR, fmt,         \
                      ##__VA_ARGS__)
#define njs_reference_error(vm, fmt, ...)                                     \
    njs_error_fmt_new(vm, &vm->retval, NJS_OBJ_TYPE_REF_ERROR, fmt,           \
                      ##__VA_ARGS__)
#define njs_syntax_error(vm, fmt, ...)                                        \
    njs_error_fmt_new(vm, &vm->retval, NJS_OBJ_TYPE_SYNTAX_ERROR, fmt,        \
                      ##__VA_ARGS__)
#define njs_type_error(vm, fmt, ...)                                          \
    njs_error_fmt_new(vm, &vm->retval, NJS_OBJ_TYPE_TYPE_ERROR, fmt,          \
                      ##__VA_ARGS__)
#define njs_uri_error(vm, fmt, ...)                                           \
    njs_error_fmt_new(vm, &vm->retval, NJS_OBJ_TYPE_URI_ERROR, fmt,           \
                      ##__VA_ARGS__)
#define NJS_MAX_STACK_SIZE       (256 * 1024)
#define NJS_OBJ_TYPE_HIDDEN_MAX    (NJS_OBJ_TYPE_TYPED_ARRAY + 1)
#define NJS_OBJ_TYPE_HIDDEN_MIN    (NJS_OBJ_TYPE_ITERATOR)
#define NJS_OBJ_TYPE_NORMAL_MAX    (NJS_OBJ_TYPE_HIDDEN_MAX)
#define NJS_OBJ_TYPE_TYPED_ARRAY_MAX    (NJS_OBJ_TYPE_FLOAT64_ARRAY + 1)
#define NJS_OBJ_TYPE_TYPED_ARRAY_MIN    (NJS_OBJ_TYPE_UINT8_ARRAY)
#define NJS_OBJ_TYPE_TYPED_ARRAY_SIZE   (NJS_OBJ_TYPE_TYPED_ARRAY_MAX         \
                                         - NJS_OBJ_TYPE_TYPED_ARRAY_MIN)
#define NJS_PROPERTY_QUERY_DELETE  2
#define NJS_PROPERTY_QUERY_GET     0
#define NJS_PROPERTY_QUERY_SET     1

#define njs_primitive_prototype_index(type)                                   \
    (NJS_OBJ_TYPE_BOOLEAN + ((type) - NJS_BOOLEAN))
#define njs_prototype_type(index)                                             \
    (index + NJS_OBJECT)
#define njs_typed_array_index(type)     (type - NJS_OBJ_TYPE_TYPED_ARRAY_MIN)
#define NJS_OBJECT_SPECIAL_MAX  (NJS_TYPED_ARRAY + 1)
#define NJS_OBJECT_SPECIAL_MIN  (NJS_FUNCTION)
#define NJS_STRING_LONG               15
#define NJS_STRING_SHORT              14

#define _njs_function(_function, _args_count, _ctor, _magic) {                \
    .native = 1,                                                              \
    .magic8 = _magic,                                                         \
    .args_count = _args_count,                                                \
    .ctor = _ctor,                                                            \
    .args_offset = 1,                                                         \
    .u.native = _function,                                                    \
    .object = { .type = NJS_FUNCTION,                                         \
                .shared = 1,                                                  \
                .extensible = 1 },                                            \
}
#define _njs_native_function(_func, _args, _ctor, _magic) {                   \
    .data = {                                                                 \
        .type = NJS_FUNCTION,                                                 \
        .truth = 1,                                                           \
        .u.function = & (njs_function_t) _njs_function(_func, _args,          \
                                                       _ctor, _magic)         \
    }                                                                         \
}
#define njs_array(value)                                                      \
    ((value)->data.u.array)
#define njs_array_buffer(value)                                               \
    ((value)->data.u.array_buffer)
#define njs_array_len(value)                                                  \
    ((value)->data.u.array->length)
#define njs_array_start(value)                                                \
    ((value)->data.u.array->start)
#define njs_bool(value)                                                       \
    ((value)->data.truth)
#define njs_data(value)                                                       \
    ((value)->data.u.data)
#define njs_data_view(value)                                                  \
    ((value)->data.u.data_view)
#define njs_date(value)                                                       \
    ((value)->data.u.date)
#define njs_function(value)                                                   \
    ((value)->data.u.function)
#define njs_function_lambda(value)                                            \
    ((value)->data.u.function->u.lambda)
#define njs_has_prototype(vm, value, proto)                                   \
    (((njs_object_prototype_t *)                                              \
        njs_object(value)->__proto__ - (vm)->prototypes) == proto)
#define njs_is_array(value)                                                   \
    ((value)->type == NJS_ARRAY)
#define njs_is_array_buffer(value)                                            \
    ((value)->type == NJS_ARRAY_BUFFER)
#define njs_is_boolean(value)                                                 \
    ((value)->type == NJS_BOOLEAN)
#define njs_is_constructor(value)                                             \
    (njs_is_function(value) && njs_function(value)->ctor)
#define njs_is_data(value, tag)                                               \
    ((value)->type == NJS_DATA                                                \
     && ((tag) == njs_make_tag(NJS_PROTO_ID_ANY)                              \
         || value->data.magic32 == (tag)))
#define njs_is_data_view(value)                                               \
    ((value)->type == NJS_DATA_VIEW)
#define njs_is_date(value)                                                    \
    ((value)->type == NJS_DATE)
#define njs_is_defined(value)                                                 \
    ((value)->type != NJS_UNDEFINED)
#define njs_is_detached_buffer(buffer)                                        \
    ((buffer)->u.data == NULL)
#define njs_is_error(value)                                                   \
    ((value)->type == NJS_OBJECT && njs_object(value)->error_data)
#define njs_is_fast_array(value)                                              \
    (njs_is_array(value) && njs_array(value)->object.fast_array)
#define njs_is_function(value)                                                \
    ((value)->type == NJS_FUNCTION)
#define njs_is_function_or_undefined(value)                                   \
    ((value)->type == NJS_FUNCTION || (value)->type == NJS_UNDEFINED)
#define njs_is_key(value)                                                     \
    (njs_is_string(value) || njs_is_symbol(value))
#define njs_is_null(value)                                                    \
    ((value)->type == NJS_NULL)
#define njs_is_null_or_undefined(value)                                       \
    ((value)->type <= NJS_UNDEFINED)
#define njs_is_null_or_undefined_or_boolean(value)                            \
    ((value)->type <= NJS_BOOLEAN)
#define njs_is_number(value)                                                  \
    ((value)->type == NJS_NUMBER)
#define njs_is_number_true(num)                                               \
    (!isnan(num) && num != 0)
#define njs_is_numeric(value)                                                 \
    ((value)->type <= NJS_NUMBER)
#define njs_is_object(value)                                                  \
    ((value)->type >= NJS_OBJECT)
#define njs_is_object_boolean(_value)                                         \
    (((_value)->type == NJS_OBJECT_VALUE)                                     \
     && njs_is_boolean(njs_object_value(_value)))
#define njs_is_object_data(_value, tag)                                       \
    (((_value)->type == NJS_OBJECT_VALUE)                                     \
     && njs_is_data(njs_object_value(_value), tag))
#define njs_is_object_number(_value)                                          \
    (((_value)->type == NJS_OBJECT_VALUE)                                     \
     && njs_is_number(njs_object_value(_value)))
#define njs_is_object_primitive(_value)                                       \
    (((_value)->type == NJS_OBJECT_VALUE)                                     \
     && njs_is_primitive(njs_object_value(_value)))
#define njs_is_object_string(_value)                                          \
    (((_value)->type == NJS_OBJECT_VALUE)                                     \
     && njs_is_string(njs_object_value(_value)))
#define njs_is_object_symbol(_value)                                          \
    (((_value)->type == NJS_OBJECT_VALUE)                                     \
     && njs_is_symbol(njs_object_value(_value)))
#define njs_is_object_value(value)                                            \
    ((value)->type == NJS_OBJECT_VALUE)
#define njs_is_primitive(value)                                               \
    ((value)->type <= NJS_STRING)
#define njs_is_promise(value)                                                 \
    ((value)->type == NJS_PROMISE)
#define njs_is_regexp(value)                                                  \
    ((value)->type == NJS_REGEXP)
#define njs_is_string(value)                                                  \
    ((value)->type == NJS_STRING)
#define njs_is_symbol(value)                                                  \
    ((value)->type == NJS_SYMBOL)
#define njs_is_true(value)                                                    \
    ((value)->data.truth != 0)
#define njs_is_typed_array(value)                                             \
    ((value)->type == NJS_TYPED_ARRAY)
#define njs_is_typed_array_uint8(value)                                       \
    (njs_is_typed_array(value)                                                \
     && njs_typed_array(value)->type == NJS_OBJ_TYPE_UINT8_ARRAY)
#define njs_is_undefined(value)                                               \
    ((value)->type == NJS_UNDEFINED)
#define njs_is_valid(value)                                                   \
    ((value)->type != NJS_INVALID)
#define njs_long_string(s) {                                                  \
    .long_string = {                                                          \
        .type = NJS_STRING,                                                   \
        .truth = (NJS_STRING_LONG << 4) | NJS_STRING_LONG,                    \
        .size = njs_length(s),                                                \
        .data = & (njs_string_t) {                                            \
            .start = (u_char *) s,                                            \
            .length = njs_length(s),                                          \
        }                                                                     \
    }                                                                         \
}
#define njs_make_tag(proto_id)                                                \
    (((njs_uint_t) proto_id << 8) | NJS_DATA_TAG_EXTERNAL)
#define njs_native_ctor(_function, _args_count, _magic)                       \
    _njs_function(_function, _args_count, 1, _magic)
#define njs_native_function(_function, _args_count)                           \
    _njs_native_function(_function, _args_count, 0, 0)
#define njs_native_function2(_function, _args_count, _magic)                  \
    _njs_native_function(_function, _args_count, 0, _magic)
#define njs_number(value)                                                     \
    ((value)->data.u.number)
#define njs_object(value)                                                     \
    ((value)->data.u.object)
#define njs_object_data(_value)                                               \
    njs_data(njs_object_value(_value))
#define njs_object_hash(value)                                                \
    (&(value)->data.u.object->hash)
#define njs_object_slots(value)                                               \
    ((value)->data.u.object->slots)
#define njs_object_value(_value)                                              \
    (&(_value)->data.u.object_value->value)
#define njs_promise(value)                                                    \
    ((value)->data.u.promise)
#define njs_prop_handler(_handler) {                                          \
    .data = {                                                                 \
        .type = NJS_INVALID,                                                  \
        .truth = 1,                                                           \
        .u = { .prop_handler = _handler }                                     \
    }                                                                         \
}
#define njs_prop_handler2(_handler, _magic16, _magic32) {                     \
    .data = {                                                                 \
        .type = NJS_INVALID,                                                  \
        .truth = 1,                                                           \
        .magic16 = _magic16,                                                  \
        .magic32 = _magic32,                                                  \
        .u = { .prop_handler = _handler }                                     \
    }                                                                         \
}
#define njs_property_query_init(pq, _query, _own)                             \
    do {                                                                      \
        (pq)->lhq.key.length = 0;                                             \
        (pq)->lhq.key.start = NULL;                                           \
        (pq)->lhq.value = NULL;                                               \
        (pq)->own_whiteout = NULL;                                            \
        (pq)->query = _query;                                                 \
        (pq)->shared = 0;                                                     \
        (pq)->own = _own;                                                     \
    } while (0)
#define njs_regexp(value)                                                     \
    ((value)->data.u.regexp)
#define njs_regexp_pattern(value)                                             \
    ((value)->data.u.regexp->pattern)
#define njs_release(vm, value)

#define njs_set_false(value)                                                  \
    *(value) = njs_value_false
#define njs_set_invalid(value)                                                \
    (value)->type = NJS_INVALID
#define njs_set_null(value)                                                   \
    *(value) = njs_value_null
#define njs_set_true(value)                                                   \
    *(value) = njs_value_true
#define njs_set_undefined(value)                                              \
    *(value) = njs_value_undefined
#define njs_string(s) {                                                       \
    .short_string = {                                                         \
        .type = NJS_STRING,                                                   \
        .size = njs_length(s),                                                \
        .length = njs_length(s),                                              \
        .start = s,                                                           \
    }                                                                         \
}
#define njs_string_get(value, str)                                            \
    do {                                                                      \
        if ((value)->short_string.size != NJS_STRING_LONG) {                  \
            (str)->length = (value)->short_string.size;                       \
            (str)->start = (u_char *) (value)->short_string.start;            \
                                                                              \
        } else {                                                              \
            (str)->length = (value)->long_string.size;                        \
            (str)->start = (u_char *) (value)->long_string.data->start;       \
        }                                                                     \
    } while (0)
#define njs_string_length_set(value, _length)                                 \
    do {                                                                      \
        if ((value)->short_string.size != NJS_STRING_LONG) {                  \
            (value)->short_string.length = length;                            \
                                                                              \
        } else {                                                              \
            (value)->long_string.data->length = length;                       \
        }                                                                     \
    } while (0)
#define njs_string_short_set(value, _size, _length)                           \
    do {                                                                      \
        (value)->type = NJS_STRING;                                           \
        njs_string_truth(value, _size);                                       \
        (value)->short_string.size = _size;                                   \
        (value)->short_string.length = _length;                               \
    } while (0)
#define njs_string_short_start(value)                                         \
    (value)->short_string.start
#define njs_string_truth(value, size)
#define njs_symbol_eq(value1, value2)                                         \
    (njs_symbol_key(value1) == njs_symbol_key(value2))
#define njs_symbol_key(value)                                                 \
    ((value)->data.magic32)
#define njs_typed_array(value)                                                \
    ((value)->data.u.typed_array)
#define njs_typed_array_buffer(value)                                         \
    ((value)->buffer)
#define njs_value(_type, _truth, _number) {                                   \
    .data = {                                                                 \
        .type = _type,                                                        \
        .truth = _truth,                                                      \
        .u.number = _number,                                                  \
    }                                                                         \
}
#define njs_wellknown_symbol(key) {                                           \
    .data = {                                                                 \
        .type = NJS_SYMBOL,                                                   \
        .truth = 1,                                                           \
        .magic32 = key,                                                       \
        .u = { .value = NULL }                                                \
    }                                                                         \
}
#define NJS_PROTO_ID_ANY    (-1)
#define NJS_VERSION                 "0.7.2"
#define NJS_VM_OPT_UNHANDLED_REJECTION_IGNORE   0
#define NJS_VM_OPT_UNHANDLED_REJECTION_THROW    1

#define njs_arg(args, nargs, n)                                               \
    ((n < nargs) ? njs_argument(args, n)                                      \
                 : (njs_value_t *) &njs_value_undefined)
#define njs_argument(args, n)                                                 \
    (njs_value_t *) ((u_char *) args + (n) * 16)
#define njs_lvalue_arg(lvalue, args, nargs, n)                                \
    ((n < nargs) ? njs_argument(args, n)                                      \
                 : (njs_value_assign(lvalue, &njs_value_undefined), lvalue))
#define njs_value_arg(val) ((njs_value_t *) val)
#define njs_value_assign(dst, src)                                            \
    memcpy(dst, src, sizeof(njs_opaque_value_t))
#define njs_vm_error(vm, fmt, ...)                                            \
    njs_vm_value_error_set(vm, njs_vm_retval(vm), fmt, ##__VA_ARGS__)
#define njs_vm_pending(vm)  (njs_vm_waiting(vm) || njs_vm_posted(vm))
#define njs_vm_unhandled_rejection(vm)                                         \
    ((vm)->options.unhandled_rejection == NJS_VM_OPT_UNHANDLED_REJECTION_THROW \
    && (vm)->promise_reason != NULL && (vm)->promise_reason->length != 0)

#define njs_print(buf, size)                                                 \
    njs_dprint(STDOUT_FILENO, (u_char *) buf, size)
#define njs_printf(fmt, ...)                                                 \
    njs_dprintf(STDOUT_FILENO, fmt, ##__VA_ARGS__)
#define njs_stderror(fmt, ...)                                               \
    njs_dprintf(STDERR_FILENO, fmt, ##__VA_ARGS__)
#define NJS_LVLHSH_BUCKET_END(bucket_size)                                    \
    (((bucket_size) - sizeof(void *))                                         \
        / (NJS_LVLHSH_ENTRY_SIZE * sizeof(uint32_t))                          \
     * NJS_LVLHSH_ENTRY_SIZE)
#define NJS_LVLHSH_BUCKET_SIZE(bucket_size)                                   \
    NJS_LVLHSH_BUCKET_END(bucket_size), bucket_size, (bucket_size - 1)
#define NJS_LVLHSH_DEFAULT                                                    \
    NJS_LVLHSH_BUCKET_SIZE(NJS_LVLHSH_DEFAULT_BUCKET_SIZE),                   \
    { 4, 4, 4, 4, 4, 4, 4, 0 }
#define NJS_LVLHSH_DEFAULT_BUCKET_SIZE  128
#define NJS_LVLHSH_ENTRY_SIZE           3
#define NJS_LVLHSH_LARGE_MEMALIGN                                             \
    NJS_LVLHSH_BUCKET_SIZE(NJS_LVLHSH_DEFAULT_BUCKET_SIZE),                   \
    { NJS_LVLHSH_MAX_MEMALIGN_SHIFT, 4, 4, 4, 4, 0, 0, 0 }
#define NJS_LVLHSH_LARGE_SLAB                                                 \
    NJS_LVLHSH_BUCKET_SIZE(NJS_LVLHSH_DEFAULT_BUCKET_SIZE),                   \
    { 10, 4, 4, 4, 4, 4, 4, 0 }
#define NJS_LVLHSH_MAX_MEMALIGN_SHIFT   NJS_LVLHSH_MEMALIGN_SHIFT
#define NJS_LVLHSH_MEMALIGN_SHIFT       (NJS_MAX_MEMALIGN_SHIFT - 3)

#define njs_lvlhsh_each_init(lhe, _proto)                                     \
    do {                                                                      \
        njs_memzero(lhe, sizeof(njs_lvlhsh_each_t));                          \
        (lhe)->proto = _proto;                                                \
    } while (0)
#define njs_lvlhsh_eq(lhl, lhr)                                               \
    ((lhl)->slot == (lhr)->slot)
#define njs_lvlhsh_init(lh)                                                   \
    (lh)->slot = NULL
#define njs_lvlhsh_is_empty(lh)                                               \
    ((lh)->slot == NULL)

#define njs_chb_append(chain, msg, len)                                      \
    njs_chb_append0(chain, (const char *) (msg), len)
#define njs_chb_append_literal(chain, literal)                               \
    njs_chb_append0(chain, literal, njs_length(literal))
#define njs_chb_node_room(n) (size_t) ((n)->end - (n)->pos)
#define njs_chb_node_size(n) (size_t) ((n)->pos - (n)->start)

#define njs_debug_alloc(...)                                                  \
    njs_stderror(__VA_ARGS__)


#define njs_surrogate_any(cp)                                                 \
    (((unsigned) (cp) - 0xd800) <= 0xdfff - 0xd800)
#define njs_surrogate_leading(cp)                                             \
    (((unsigned) (cp) - 0xd800) <= 0xdbff - 0xd800)
#define njs_surrogate_pair(high, low)                                         \
    (0x10000 + (((high) - 0xd800) << 10) + ((low) - 0xdc00))
#define njs_surrogate_trailing(cp)                                            \
    (((unsigned) (cp) - 0xdc00) <= 0xdfff - 0xdc00)

njs_cpymem(dst, src, n)                                                       \
    (((u_char *) memcpy(dst, src, n)) + (n))
njs_explicit_memzero(buf, length)                                             \
    explicit_bzero(buf, length)
#define njs_length(s)        (sizeof(s) - 1)
njs_memset(buf, c, length)                                                    \
    (void) memset(buf, c, length)
njs_memzero(buf, length)                                                      \
    (void) memset(buf, 0, length)
#define njs_null_str         { 0, NULL }
#define njs_str(s)           { njs_length(s), (u_char *) s }
#define njs_str_value(s)     (njs_str_t) njs_str(s)
njs_strchr(s1, c)                                                             \
    (u_char *) strchr((const char *) s1, (int) c)
njs_strlen(s)                                                                 \
    strlen((char *) s)
njs_strncmp(s1, s2, n)                                                        \
    strncmp((char *) s1, (char *) s2, n)
njs_strstr_case_eq(s1, s2)                                                    \
    (((s1)->length == (s2)->length)                                           \
     && (njs_strncasecmp((s1)->start, (s2)->start, (s1)->length) == 0))
njs_strstr_eq(s1, s2)                                                         \
    (((s1)->length == (s2)->length)                                           \
     && (memcmp((s1)->start, (s2)->start, (s1)->length) == 0))
#define NJS_EXPORT         __attribute__((visibility("default")))
#define NJS_MALLOC_LIKE    __attribute__((__malloc__))
#define NJS_MAX_ALIGNMENT  _MAX_ALIGNMENT
#define NJS_MM_DENORMALS_MASK 0x8040
#define NJS_PACKED    __attribute__((packed))

#define njs_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) (a) - 1))                     \
                 & ~((uintptr_t) (a) - 1))
#define njs_align_size(size, a)                                               \
    (((size) + ((size_t) (a) - 1)) & ~((size_t) (a) - 1))
#define njs_aligned(x)     __attribute__((aligned(x)))

#define njs_container_of(p, type, field)                                      \
    (type *) ((u_char *) (p) - offsetof(type, field))
#define njs_expect(c, x)   __builtin_expect((long) (x), (c))
#define njs_fast_path(x)   njs_expect(1, x)
#define njs_inline         static inline __attribute__((always_inline))
#define njs_leading_zeros(x)  (((x) == 0) ? 32 : __builtin_clz(x))
#define njs_leading_zeros64(x)  (((x) == 0) ? 64 : __builtin_clzll(x))
#define njs_max(val1, val2)                                                   \
    ((val1 < val2) ? (val2) : (val1))
#define njs_min(val1, val2)                                                   \
    ((val1 < val2) ? (val1) : (val2))
#define njs_mm_denormals(on)                                                  \
    _mm_setcsr((_mm_getcsr() & ~NJS_MM_DENORMALS_MASK) | (!(on) ? 0x8040: 0x0))
#define njs_msan_unpoison(ptr, size)  __msan_unpoison(ptr, size)
#define njs_nitems(x)                                                         \
    (sizeof(x) / sizeof((x)[0]))
#define njs_noinline       __attribute__((noinline))
#define njs_pragma_loop_disable_vectorization  __asm__("")
#define njs_prefetch(a)    __builtin_prefetch(a)
#define njs_slow_path(x)   njs_expect(0, x)
#define njs_stringify(v)    #v
#define njs_trunc_ptr(p, a)                                                   \
    (u_char *) ((uintptr_t) (p) & ~((uintptr_t) (a) - 1))
#define njs_unreachable()  __builtin_unreachable()
#define NJS_64BIT       1
#define NJS_AGAIN          (-2)
#define NJS_DECLINED       (-3)
#define NJS_DONE           (-4)
#define NJS_DOUBLE_LEN       (1 + DBL_MAX_10_EXP)
#define NJS_ERROR          (-1)
#define NJS_INT32_T_LEN      njs_length("-2147483648")
#define NJS_INT64_T_LEN      njs_length("-9223372036854775808")
#define NJS_INT_T_HEXLEN     NJS_INT64_T_HEXLEN
#define NJS_INT_T_LEN        NJS_INT64_T_LEN
#define NJS_INT_T_MAX        NJS_INT64_T_MAX
#define NJS_INT_T_SIZE  4
#define NJS_MAX_ERROR_STR    2048
#define NJS_OK             0
#define NJS_PTR_SIZE    8
#define _FILE_OFFSET_BITS  64




#define NJS_REGEX_UNSET      (size_t) (-1)

#define njs_regex_compile_ctx_t  void
#define njs_regex_generic_ctx_t  void
#define njs_regex_match_data_t   void

#define njs_assert(condition)                                                 \
    do {                                                                      \
        if (!(condition)) {                                                   \
            njs_stderror("Assertion \"%s\" failed at %s:%d\n", #condition,    \
                         "__FILE__", "__LINE__");                                 \
            abort();                                                          \
        }                                                                     \
    } while (0)


#define njs_arr_is_empty(arr)                                               \
    ((arr)->items == 0)
#define njs_arr_item(arr, i)                                                \
    ((void *) ((char *) (arr)->start + (arr)->item_size * (i)))
#define njs_arr_last(arr)                                                   \
    ((void *)                                                               \
        ((char *) (arr)->start                                              \
                      + (arr)->item_size * ((arr)->items - 1)))
#define njs_arr_reset(arr)                                                  \
    (arr)->items = 0;
#define NJS_RBTREE_NODE(node)                                                 \
    njs_rbtree_part_t         node;                                           \
    uint8_t                   node##_color
#define NJS_RBTREE_NODE_INIT  { NULL, NULL, NULL }, 0

#define njs_rbtree_is_empty(tree)                                             \
    (njs_rbtree_root(tree) == njs_rbtree_sentinel(tree))
#define njs_rbtree_is_there_successor(tree, node)                             \
    ((node) != njs_rbtree_sentinel(tree))
#define njs_rbtree_min(tree)                                                  \
    njs_rbtree_branch_min(tree, &(tree)->sentinel)
#define njs_rbtree_root(tree)                                                 \
    ((tree)->sentinel.left)
#define njs_rbtree_sentinel(tree)                                             \
    (&(tree)->sentinel)

#define njs_free(p)        free(p)
#define njs_malloc(size)   malloc(size)


#define njs_timezone(tm)                                                      \
    ((tm)->tm_gmtoff)


#define njs_queue_add(queue, tail)                                            \
    do {                                                                      \
        (queue)->head.prev->next = (tail)->head.next;                         \
        (tail)->head.next->prev = (queue)->head.prev;                         \
        (queue)->head.prev = (tail)->head.prev;                               \
        (queue)->head.prev->next = &(queue)->head;                            \
    } while (0)
#define njs_queue_first(queue)                                                \
    (queue)->head.next
#define njs_queue_head(queue)                                                 \
    (&(queue)->head)
#define njs_queue_init(queue)                                                 \
    do {                                                                      \
        (queue)->head.prev = &(queue)->head;                                  \
        (queue)->head.next = &(queue)->head;                                  \
    } while (0)
#define njs_queue_insert_after(target, link)                                  \
    do {                                                                      \
        (link)->next = (target)->next;                                        \
        (link)->next->prev = (link);                                          \
        (link)->prev = (target);                                              \
        (target)->next = (link);                                              \
    } while (0)
#define njs_queue_insert_before(target, link)                                 \
    do {                                                                      \
        (link)->next = (target);                                              \
        (link)->prev = (target)->prev;                                        \
        (target)->prev = (link);                                              \
        (link)->prev->next = (link);                                          \
    } while (0)
#define njs_queue_insert_head(queue, link)                                    \
    do {                                                                      \
        (link)->next = (queue)->head.next;                                    \
        (link)->next->prev = (link);                                          \
        (link)->prev = &(queue)->head;                                        \
        (queue)->head.next = (link);                                          \
    } while (0)
#define njs_queue_insert_tail(queue, link)                                    \
    do {                                                                      \
        (link)->prev = (queue)->head.prev;                                    \
        (link)->prev->next = (link);                                          \
        (link)->next = &(queue)->head;                                        \
        (queue)->head.prev = (link);                                          \
    } while (0)
#define njs_queue_is_empty(queue)                                             \
    (&(queue)->head == (queue)->head.prev)
#define njs_queue_last(queue)                                                 \
    (queue)->head.prev
#define njs_queue_link_data(lnk, type, link)                                  \
    njs_container_of(lnk, type, link)
#define njs_queue_next(link)                                                  \
    (link)->next
#define njs_queue_prev(link)                                                  \
    (link)->prev
#define njs_queue_remove(link)                                                \
    do {                                                                      \
        (link)->next->prev = (link)->prev;                                    \
        (link)->prev->next = (link)->next;                                    \
        (link)->prev = NULL;                                                  \
        (link)->next = NULL;                                                  \
    } while (0)
#define njs_queue_self(link)                                                  \
    njs_queue_sentinel(link)
#define njs_queue_sentinel(link)                                              \
    do {                                                                      \
        (link)->prev = (link);                                                \
        (link)->next = (link);                                                \
    } while (0)
#define njs_queue_split(queue, link, tail)                                    \
    do {                                                                      \
        (tail)->head.prev = (queue)->head.prev;                               \
        (tail)->head.prev->next = &(tail)->head;                              \
        (tail)->head.next = (link);                                           \
        (queue)->head.prev = (link)->prev;                                    \
        (queue)->head.prev->next = &(queue)->head;                            \
        (link)->prev = &(tail)->head;                                         \
    } while (0)
#define njs_queue_tail(queue)                                                 \
    (&(queue)->head)
#define njs_queue_truncate(queue, link)                                       \
    do {                                                                      \
        (queue)->head.prev = (link)->prev;                                    \
        (queue)->head.prev->next = &(queue)->head;                            \
    } while (0)

#define njs_alert(_trace, _level, ...)                                        \
    do {                                                                      \
        njs_trace_t  *_trace_ = _trace;                                       \
        uint32_t     _level_ = _level;                                        \
                                                                              \
        if (njs_slow_path(_trace_->level >= _level_)) {                       \
            njs_trace_handler(_trace_, _level_, __VA_ARGS__);                 \
        }                                                                     \
    } while (0)




#define njs_trace(_trace, ...)                                                \
    do {                                                                      \
        njs_trace_t  *_trace_ = _trace;                                       \
                                                                              \
        if (njs_slow_path(_trace_->level == NJS_LEVEL_TRACE)) {               \
            njs_trace_handler(_trace_, NJS_LEVEL_TRACE, __VA_ARGS__);         \
        }                                                                     \
    } while (0)

#define NJS_DJB_HASH_INIT  5381

#define njs_djb_hash_add(hash, val)                                           \
    ((uint32_t) ((((hash) << 5) + (hash)) ^ (uint32_t) (val)))



#define NJS_DBL_EXPONENT_BIAS       (NJS_DBL_EXPONENT_OFFSET                  \
                                     + NJS_DBL_SIGNIFICAND_SIZE)
#define NJS_DBL_EXPONENT_DENORMAL   (-NJS_DBL_EXPONENT_BIAS + 1)
#define NJS_DBL_EXPONENT_MASK       njs_uint64(0x7FF00000, 0x00000000)
#define NJS_DBL_EXPONENT_MAX        (0x7ff - NJS_DBL_EXPONENT_BIAS)
#define NJS_DBL_EXPONENT_MIN        (-NJS_DBL_EXPONENT_BIAS)
#define NJS_DBL_EXPONENT_OFFSET     ((int64_t) 0x3ff)
#define NJS_DBL_HIDDEN_BIT          njs_uint64(0x00100000, 0x00000000)
#define NJS_DBL_SIGNIFICAND_MASK    njs_uint64(0x000FFFFF, 0xFFFFFFFF)
#define NJS_DBL_SIGNIFICAND_SIZE    52
#define NJS_DBL_SIGN_MASK           njs_uint64(0x80000000, 0x00000000)
#define NJS_DECIMAL_EXPONENT_DIST   8
#define NJS_DECIMAL_EXPONENT_MAX    340
#define NJS_DECIMAL_EXPONENT_MIN    (-348)
#define NJS_DECIMAL_EXPONENT_OFF    348
#define NJS_DIYFP_SIGNIFICAND_SIZE  64
#define NJS_SIGNIFICAND_SHIFT       (NJS_DIYFP_SIGNIFICAND_SIZE               \
                                     - NJS_DBL_SIGNIFICAND_SIZE)
#define NJS_SIGNIFICAND_SIZE        53

#define njs_diyfp(_s, _e)           (njs_diyfp_t) \
                                    { .significand = (_s), .exp = (_e) }
#define njs_uint64(h, l)            (((uint64_t) (h) << 32) + (l))

#define NJS_MAX_PATH             PATH_MAX

#define njs_pagesize()      getpagesize()
