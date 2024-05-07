#include<sys/wait.h>


#include<unistd.h>
#include<sys/mman.h>

#include<signal.h>
#include<stdlib.h>
#include<errno.h>





#include<setjmp.h>
#include<fcntl.h>

#include<sys/types.h>

#include<assert.h>
#include<inttypes.h>
#include<stdarg.h>





#include<netinet/in.h>
#include<semaphore.h>
#include<scsi/sg.h>

#include<netdb.h>
#include<stdbool.h>



#include<pwd.h>


#include<limits.h>


#include<sys/uio.h>


#include<pthread.h>
#include<ctype.h>


#include<sys/stat.h>
#include<stdint.h>
#include<string.h>
#include<sanitizer/tsan_interface.h>








#include<sys/socket.h>
#include<getopt.h>
#include<sys/time.h>


#include<stdio.h>

#include<time.h>



#include<strings.h>

#include<netinet/tcp.h>





#include<sys/shm.h>
#include<stddef.h>
#include<arpa/inet.h>

#include<sys/sysmacros.h>



#include<sys/un.h>
#define DECLARE_CLASS_CHECKERS(ClassType, OBJ_NAME, TYPENAME) \
    static inline G_GNUC_UNUSED ClassType * \
    OBJ_NAME##_GET_CLASS(const void *obj) \
    { return OBJECT_GET_CLASS(ClassType, obj, TYPENAME); } \
    \
    static inline G_GNUC_UNUSED ClassType * \
    OBJ_NAME##_CLASS(const void *klass) \
    { return OBJECT_CLASS_CHECK(ClassType, klass, TYPENAME); }
#define DECLARE_INSTANCE_CHECKER(InstanceType, OBJ_NAME, TYPENAME) \
    static inline G_GNUC_UNUSED InstanceType * \
    OBJ_NAME(const void *obj) \
    { return OBJECT_CHECK(InstanceType, obj, TYPENAME); }
#define DECLARE_OBJ_CHECKERS(InstanceType, ClassType, OBJ_NAME, TYPENAME) \
    DECLARE_INSTANCE_CHECKER(InstanceType, OBJ_NAME, TYPENAME) \
    \
    DECLARE_CLASS_CHECKERS(ClassType, OBJ_NAME, TYPENAME)
#define DEFINE_TYPES(type_array)                                            \
static void do_qemu_init_ ## type_array(void)                               \
{                                                                           \
    type_register_static_array(type_array, ARRAY_SIZE(type_array));         \
}                                                                           \
type_init(do_qemu_init_ ## type_array)
#define INTERFACE_CHECK(interface, obj, name) \
    ((interface *)object_dynamic_cast_assert(OBJECT((obj)), (name), \
                                             "__FILE__", "__LINE__", __func__))
#define INTERFACE_CLASS(klass) \
    OBJECT_CLASS_CHECK(InterfaceClass, klass, TYPE_INTERFACE)
#define OBJECT(obj) \
    ((Object *)(obj))
#define OBJECT_CHECK(type, obj, name) \
    ((type *)object_dynamic_cast_assert(OBJECT(obj), (name), \
                                        "__FILE__", "__LINE__", __func__))
#define OBJECT_CLASS(class) \
    ((ObjectClass *)(class))
#define OBJECT_CLASS_CAST_CACHE 4
#define OBJECT_CLASS_CHECK(class_type, class, name) \
    ((class_type *)object_class_dynamic_cast_assert(OBJECT_CLASS(class), (name), \
                                               "__FILE__", "__LINE__", __func__))
#define OBJECT_DECLARE_SIMPLE_TYPE(InstanceType, MODULE_OBJ_NAME) \
    typedef struct InstanceType InstanceType; \
    \
    G_DEFINE_AUTOPTR_CLEANUP_FUNC(InstanceType, object_unref) \
    \
    DECLARE_INSTANCE_CHECKER(InstanceType, MODULE_OBJ_NAME, TYPE_##MODULE_OBJ_NAME)
#define OBJECT_DECLARE_TYPE(InstanceType, ClassType, MODULE_OBJ_NAME) \
    typedef struct InstanceType InstanceType; \
    typedef struct ClassType ClassType; \
    \
    G_DEFINE_AUTOPTR_CLEANUP_FUNC(InstanceType, object_unref) \
    \
    DECLARE_OBJ_CHECKERS(InstanceType, ClassType, \
                         MODULE_OBJ_NAME, TYPE_##MODULE_OBJ_NAME)
#define OBJECT_DEFINE_ABSTRACT_TYPE(ModuleObjName, module_obj_name, \
                                    MODULE_OBJ_NAME, PARENT_MODULE_OBJ_NAME) \
    OBJECT_DEFINE_TYPE_EXTENDED(ModuleObjName, module_obj_name, \
                                MODULE_OBJ_NAME, PARENT_MODULE_OBJ_NAME, \
                                true, { NULL })
#define OBJECT_DEFINE_TYPE(ModuleObjName, module_obj_name, MODULE_OBJ_NAME, \
                           PARENT_MODULE_OBJ_NAME) \
    OBJECT_DEFINE_TYPE_EXTENDED(ModuleObjName, module_obj_name, \
                                MODULE_OBJ_NAME, PARENT_MODULE_OBJ_NAME, \
                                false, { NULL })
#define OBJECT_DEFINE_TYPE_EXTENDED(ModuleObjName, module_obj_name, \
                                    MODULE_OBJ_NAME, PARENT_MODULE_OBJ_NAME, \
                                    ABSTRACT, ...) \
    static void \
    module_obj_name##_finalize(Object *obj); \
    static void \
    module_obj_name##_class_init(ObjectClass *oc, void *data); \
    static void \
    module_obj_name##_init(Object *obj); \
    \
    static const TypeInfo module_obj_name##_info = { \
        .parent = TYPE_##PARENT_MODULE_OBJ_NAME, \
        .name = TYPE_##MODULE_OBJ_NAME, \
        .instance_size = sizeof(ModuleObjName), \
        .instance_align = __alignof__(ModuleObjName), \
        .instance_init = module_obj_name##_init, \
        .instance_finalize = module_obj_name##_finalize, \
        .class_size = sizeof(ModuleObjName##Class), \
        .class_init = module_obj_name##_class_init, \
        .abstract = ABSTRACT, \
        .interfaces = (InterfaceInfo[]) { __VA_ARGS__ } , \
    }; \
    \
    static void \
    module_obj_name##_register_types(void) \
    { \
        type_register_static(&module_obj_name##_info); \
    } \
    type_init(module_obj_name##_register_types);
#define OBJECT_DEFINE_TYPE_WITH_INTERFACES(ModuleObjName, module_obj_name, \
                                           MODULE_OBJ_NAME, \
                                           PARENT_MODULE_OBJ_NAME, ...) \
    OBJECT_DEFINE_TYPE_EXTENDED(ModuleObjName, module_obj_name, \
                                MODULE_OBJ_NAME, PARENT_MODULE_OBJ_NAME, \
                                false, __VA_ARGS__)
#define OBJECT_GET_CLASS(class, obj, name) \
    OBJECT_CLASS_CHECK(class, object_get_class(OBJECT(obj)), name)

#define TYPE_INTERFACE "interface"
#define TYPE_OBJECT "object"
#define object_initialize_child(parent, propname, child, type)          \
    object_initialize_child_internal((parent), (propname),              \
                                     (child), sizeof(*(child)), (type))
#define DSO_STAMP_FUN         glue(qemu_stamp, CONFIG_STAMP)
#define DSO_STAMP_FUN_STR     stringify(DSO_STAMP_FUN)

#define audio_module_load_one(lib) module_load_one("audio-", lib, false)
#define block_init(function) module_init(function, MODULE_INIT_BLOCK)
#define block_module_load_one(lib) module_load_one("block-", lib, false)
#define fuzz_target_init(function) module_init(function, \
                                               MODULE_INIT_FUZZ_TARGET)
#define libqos_init(function) module_init(function, MODULE_INIT_LIBQOS)
#define migration_init(function) module_init(function, MODULE_INIT_MIGRATION)
# define modinfo(kind, value) \
    MODINFO_START kind value MODINFO_END
#define module_arch(name) modinfo(arch, name)
#define module_dep(name) modinfo(dep, name)
#define module_init(function, type)                                         \
static void __attribute__((constructor)) do_qemu_init_ ## function(void)    \
{                                                                           \
    register_dso_module_init(function, type);                               \
}
#define module_obj(name) modinfo(obj, name)
#define module_opts(name) modinfo(opts, name)
#define opts_init(function) module_init(function, MODULE_INIT_OPTS)
#define trace_init(function) module_init(function, MODULE_INIT_TRACE)
#define type_init(function) module_init(function, MODULE_INIT_QOM)
#define ui_module_load_one(lib) module_load_one("ui-", lib, false)
#define xen_backend_init(function) module_init(function, \
                                               MODULE_INIT_XEN_BACKEND)

#define STR_OR_NULL(str) ((str) ? (str) : "null")
#define MAX_OPTION_ROMS 16
#define MAX_PARALLEL_PORTS 3
#define MAX_PROM_ENVS 128


#define UUID_FMT "%02hhx%02hhx%02hhx%02hhx-" \
                 "%02hhx%02hhx-%02hhx%02hhx-" \
                 "%02hhx%02hhx-" \
                 "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
#define UUID_FMT_LEN 36
#define UUID_LE(time_low, time_mid, time_hi_and_version,                    \
  clock_seq_hi_and_reserved, clock_seq_low, node0, node1, node2,            \
  node3, node4, node5)                                                      \
  { (time_low) & 0xff, ((time_low) >> 8) & 0xff, ((time_low) >> 16) & 0xff, \
    ((time_low) >> 24) & 0xff, (time_mid) & 0xff, ((time_mid) >> 8) & 0xff, \
    (time_hi_and_version) & 0xff, ((time_hi_and_version) >> 8) & 0xff,      \
    (clock_seq_hi_and_reserved), (clock_seq_low), (node0), (node1), (node2),\
    (node3), (node4), (node5) }
#define UUID_NONE "00000000-0000-0000-0000-000000000000"
#define NOTIFIER_LIST_INITIALIZER(head) \
    { QLIST_HEAD_INITIALIZER((head).notifiers) }
#define NOTIFIER_WITH_RETURN_LIST_INITIALIZER(head) \
    { QLIST_HEAD_INITIALIZER((head).notifiers) }


#define QLIST_EMPTY(head)                ((head)->lh_first == NULL)
#define QLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *le_next;                         \
        struct type **le_prev;    \
}
#define QLIST_FIRST(head)                ((head)->lh_first)
#define QLIST_FOREACH(var, head, field)                                 \
        for ((var) = ((head)->lh_first);                                \
                (var);                                                  \
                (var) = ((var)->field.le_next))
#define QLIST_FOREACH_SAFE(var, head, field, next_var)                  \
        for ((var) = ((head)->lh_first);                                \
                (var) && ((next_var) = ((var)->field.le_next), 1);      \
                (var) = (next_var))
#define QLIST_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *lh_first;                       \
}
#define QLIST_HEAD_INITIALIZER(head)                                    \
        { NULL }
#define QLIST_INIT(head) do {                                           \
        (head)->lh_first = NULL;                                        \
} while (0)
#define QLIST_INSERT_AFTER(listelm, elm, field) do {                    \
        if (((elm)->field.le_next = (listelm)->field.le_next) != NULL)  \
                (listelm)->field.le_next->field.le_prev =               \
                    &(elm)->field.le_next;                              \
        (listelm)->field.le_next = (elm);                               \
        (elm)->field.le_prev = &(listelm)->field.le_next;               \
} while (0)
#define QLIST_INSERT_BEFORE(listelm, elm, field) do {                   \
        (elm)->field.le_prev = (listelm)->field.le_prev;                \
        (elm)->field.le_next = (listelm);                               \
        *(listelm)->field.le_prev = (elm);                              \
        (listelm)->field.le_prev = &(elm)->field.le_next;               \
} while (0)
#define QLIST_INSERT_HEAD(head, elm, field) do {                        \
        if (((elm)->field.le_next = (head)->lh_first) != NULL)          \
                (head)->lh_first->field.le_prev = &(elm)->field.le_next;\
        (head)->lh_first = (elm);                                       \
        (elm)->field.le_prev = &(head)->lh_first;                       \
} while (0)
#define QLIST_IS_INSERTED(elm, field) ((elm)->field.le_prev != NULL)
#define QLIST_NEXT(elm, field)           ((elm)->field.le_next)
#define QLIST_RAW_FIRST(head)                                                  \
        field_at_offset(head, 0, void *)
#define QLIST_RAW_FOREACH(elm, head, entry)                                    \
        for ((elm) = *QLIST_RAW_FIRST(head);                                   \
             (elm);                                                            \
             (elm) = *QLIST_RAW_NEXT(elm, entry))
#define QLIST_RAW_INSERT_AFTER(head, prev, elem, entry) do {                   \
        *QLIST_RAW_NEXT(prev, entry) = elem;                                   \
        *QLIST_RAW_PREVIOUS(elem, entry) = QLIST_RAW_NEXT(prev, entry);        \
        *QLIST_RAW_NEXT(elem, entry) = NULL;                                   \
} while (0)
#define QLIST_RAW_INSERT_HEAD(head, elm, entry) do {                           \
        void *first = *QLIST_RAW_FIRST(head);                                  \
        *QLIST_RAW_FIRST(head) = elm;                                          \
        *QLIST_RAW_PREVIOUS(elm, entry) = QLIST_RAW_FIRST(head);               \
        if (first) {                                                           \
            *QLIST_RAW_NEXT(elm, entry) = first;                               \
            *QLIST_RAW_PREVIOUS(first, entry) = QLIST_RAW_NEXT(elm, entry);    \
        } else {                                                               \
            *QLIST_RAW_NEXT(elm, entry) = NULL;                                \
        }                                                                      \
} while (0)
#define QLIST_RAW_NEXT(elm, entry)                                             \
        field_at_offset(elm, entry, void *)
#define QLIST_RAW_PREVIOUS(elm, entry)                                         \
        field_at_offset(elm, entry + sizeof(void *), void *)
#define QLIST_REMOVE(elm, field) do {                                   \
        if ((elm)->field.le_next != NULL)                               \
                (elm)->field.le_next->field.le_prev =                   \
                    (elm)->field.le_prev;                               \
        *(elm)->field.le_prev = (elm)->field.le_next;                   \
        (elm)->field.le_next = NULL;                                    \
        (elm)->field.le_prev = NULL;                                    \
} while (0)
#define QLIST_SAFE_REMOVE(elm, field) do {                              \
        if ((elm)->field.le_prev != NULL) {                             \
                if ((elm)->field.le_next != NULL)                       \
                        (elm)->field.le_next->field.le_prev =           \
                            (elm)->field.le_prev;                       \
                *(elm)->field.le_prev = (elm)->field.le_next;           \
                (elm)->field.le_next = NULL;                            \
                (elm)->field.le_prev = NULL;                            \
        }                                                               \
} while (0)
#define QLIST_SWAP(dstlist, srclist, field) do {                        \
        void *tmplist;                                                  \
        tmplist = (srclist)->lh_first;                                  \
        (srclist)->lh_first = (dstlist)->lh_first;                      \
        if ((srclist)->lh_first != NULL) {                              \
            (srclist)->lh_first->field.le_prev = &(srclist)->lh_first;  \
        }                                                               \
        (dstlist)->lh_first = tmplist;                                  \
        if ((dstlist)->lh_first != NULL) {                              \
            (dstlist)->lh_first->field.le_prev = &(dstlist)->lh_first;  \
        }                                                               \
} while (0)
#define QSIMPLEQ_CONCAT(head1, head2) do {                              \
    if (!QSIMPLEQ_EMPTY((head2))) {                                     \
        *(head1)->sqh_last = (head2)->sqh_first;                        \
        (head1)->sqh_last = (head2)->sqh_last;                          \
        QSIMPLEQ_INIT((head2));                                         \
    }                                                                   \
} while (0)
#define QSIMPLEQ_EMPTY(head)        ((head)->sqh_first == NULL)
#define QSIMPLEQ_EMPTY_ATOMIC(head) \
    (qatomic_read(&((head)->sqh_first)) == NULL)
#define QSIMPLEQ_ENTRY(type)                                            \
struct {                                                                \
    struct type *sqe_next;                            \
}
#define QSIMPLEQ_FIRST(head)        ((head)->sqh_first)
#define QSIMPLEQ_FOREACH(var, head, field)                              \
    for ((var) = ((head)->sqh_first);                                   \
        (var);                                                          \
        (var) = ((var)->field.sqe_next))
#define QSIMPLEQ_FOREACH_SAFE(var, head, field, next)                   \
    for ((var) = ((head)->sqh_first);                                   \
        (var) && ((next = ((var)->field.sqe_next)), 1);                 \
        (var) = (next))
#define QSIMPLEQ_HEAD(name, type)                                       \
struct name {                                                           \
    struct type *sqh_first;                          \
    struct type **sqh_last;              \
}
#define QSIMPLEQ_HEAD_INITIALIZER(head)                                 \
    { NULL, &(head).sqh_first }
#define QSIMPLEQ_INIT(head) do {                                        \
    (head)->sqh_first = NULL;                                           \
    (head)->sqh_last = &(head)->sqh_first;                              \
} while (0)
#define QSIMPLEQ_INSERT_AFTER(head, listelm, elm, field) do {           \
    if (((elm)->field.sqe_next = (listelm)->field.sqe_next) == NULL)    \
        (head)->sqh_last = &(elm)->field.sqe_next;                      \
    (listelm)->field.sqe_next = (elm);                                  \
} while (0)
#define QSIMPLEQ_INSERT_HEAD(head, elm, field) do {                     \
    if (((elm)->field.sqe_next = (head)->sqh_first) == NULL)            \
        (head)->sqh_last = &(elm)->field.sqe_next;                      \
    (head)->sqh_first = (elm);                                          \
} while (0)
#define QSIMPLEQ_INSERT_TAIL(head, elm, field) do {                     \
    (elm)->field.sqe_next = NULL;                                       \
    *(head)->sqh_last = (elm);                                          \
    (head)->sqh_last = &(elm)->field.sqe_next;                          \
} while (0)
#define QSIMPLEQ_LAST(head, type, field)                                \
    (QSIMPLEQ_EMPTY((head)) ?                                           \
        NULL :                                                          \
            ((struct type *)(void *)                                    \
        ((char *)((head)->sqh_last) - offsetof(struct type, field))))
#define QSIMPLEQ_NEXT(elm, field)   ((elm)->field.sqe_next)
#define QSIMPLEQ_PREPEND(head1, head2) do {                             \
    if (!QSIMPLEQ_EMPTY((head2))) {                                     \
        *(head2)->sqh_last = (head1)->sqh_first;                        \
        (head1)->sqh_first = (head2)->sqh_first;                          \
        QSIMPLEQ_INIT((head2));                                         \
    }                                                                   \
} while (0)
#define QSIMPLEQ_REMOVE(head, elm, type, field) do {                    \
    if ((head)->sqh_first == (elm)) {                                   \
        QSIMPLEQ_REMOVE_HEAD((head), field);                            \
    } else {                                                            \
        struct type *curelm = (head)->sqh_first;                        \
        while (curelm->field.sqe_next != (elm))                         \
            curelm = curelm->field.sqe_next;                            \
        if ((curelm->field.sqe_next =                                   \
            curelm->field.sqe_next->field.sqe_next) == NULL)            \
                (head)->sqh_last = &(curelm)->field.sqe_next;           \
        (elm)->field.sqe_next = NULL;                                   \
    }                                                                   \
} while (0)
#define QSIMPLEQ_REMOVE_HEAD(head, field) do {                          \
    typeof((head)->sqh_first) elm = (head)->sqh_first;                  \
    if (((head)->sqh_first = elm->field.sqe_next) == NULL)              \
        (head)->sqh_last = &(head)->sqh_first;                          \
    elm->field.sqe_next = NULL;                                         \
} while (0)
#define QSIMPLEQ_SPLIT_AFTER(head, elm, field, removed) do {            \
    QSIMPLEQ_INIT(removed);                                             \
    if (((removed)->sqh_first = (head)->sqh_first) != NULL) {           \
        if (((head)->sqh_first = (elm)->field.sqe_next) == NULL) {      \
            (head)->sqh_last = &(head)->sqh_first;                      \
        }                                                               \
        (removed)->sqh_last = &(elm)->field.sqe_next;                   \
        (elm)->field.sqe_next = NULL;                                   \
    }                                                                   \
} while (0)
#define QSLIST_EMPTY(head)       ((head)->slh_first == NULL)
#define QSLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *sle_next;                        \
}
#define QSLIST_FIRST(head)       ((head)->slh_first)
#define QSLIST_FOREACH(var, head, field)                                 \
        for((var) = (head)->slh_first; (var); (var) = (var)->field.sle_next)
#define QSLIST_FOREACH_SAFE(var, head, field, tvar)                      \
        for ((var) = QSLIST_FIRST((head));                               \
            (var) && ((tvar) = QSLIST_NEXT((var), field), 1);            \
            (var) = (tvar))
#define QSLIST_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *slh_first;                      \
}
#define QSLIST_HEAD_INITIALIZER(head)                                    \
        { NULL }
#define QSLIST_INIT(head) do {                                           \
        (head)->slh_first = NULL;                                       \
} while (0)
#define QSLIST_INSERT_AFTER(slistelm, elm, field) do {                   \
        (elm)->field.sle_next = (slistelm)->field.sle_next;             \
        (slistelm)->field.sle_next = (elm);                             \
} while (0)
#define QSLIST_INSERT_HEAD(head, elm, field) do {                        \
        (elm)->field.sle_next = (head)->slh_first;                       \
        (head)->slh_first = (elm);                                       \
} while (0)
#define QSLIST_INSERT_HEAD_ATOMIC(head, elm, field) do {                     \
        typeof(elm) save_sle_next;                                           \
        do {                                                                 \
            save_sle_next = (elm)->field.sle_next = (head)->slh_first;       \
        } while (qatomic_cmpxchg(&(head)->slh_first, save_sle_next, (elm)) !=\
                 save_sle_next);                                             \
} while (0)
#define QSLIST_MOVE_ATOMIC(dest, src) do {                               \
        (dest)->slh_first = qatomic_xchg(&(src)->slh_first, NULL);       \
} while (0)
#define QSLIST_NEXT(elm, field)  ((elm)->field.sle_next)
#define QSLIST_REMOVE(head, elm, type, field) do {                      \
    if ((head)->slh_first == (elm)) {                                   \
        QSLIST_REMOVE_HEAD((head), field);                              \
    } else {                                                            \
        struct type *curelm = (head)->slh_first;                        \
        while (curelm->field.sle_next != (elm))                         \
            curelm = curelm->field.sle_next;                            \
        curelm->field.sle_next = curelm->field.sle_next->field.sle_next; \
        (elm)->field.sle_next = NULL;                                   \
    }                                                                   \
} while (0)
#define QSLIST_REMOVE_AFTER(slistelm, field) do {                       \
        typeof(slistelm) next = (slistelm)->field.sle_next;             \
        (slistelm)->field.sle_next = next->field.sle_next;              \
        next->field.sle_next = NULL;                                    \
} while (0)
#define QSLIST_REMOVE_HEAD(head, field) do {                             \
        typeof((head)->slh_first) elm = (head)->slh_first;               \
        (head)->slh_first = elm->field.sle_next;                         \
        elm->field.sle_next = NULL;                                      \
} while (0)
#define QTAILQ_EMPTY(head)               ((head)->tqh_first == NULL)
#define QTAILQ_ENTRY(type)                                              \
union {                                                                 \
        struct type *tqe_next;                        \
        QTailQLink tqe_circ;           \
}
#define QTAILQ_FIRST(head)               ((head)->tqh_first)
#define QTAILQ_FOREACH(var, head, field)                                \
        for ((var) = ((head)->tqh_first);                               \
                (var);                                                  \
                (var) = ((var)->field.tqe_next))
#define QTAILQ_FOREACH_REVERSE(var, head, field)                        \
        for ((var) = QTAILQ_LAST(head);                                 \
                (var);                                                  \
                (var) = QTAILQ_PREV(var, field))
#define QTAILQ_FOREACH_REVERSE_SAFE(var, head, field, prev_var)         \
        for ((var) = QTAILQ_LAST(head);                                 \
             (var) && ((prev_var) = QTAILQ_PREV(var, field), 1);        \
             (var) = (prev_var))
#define QTAILQ_FOREACH_SAFE(var, head, field, next_var)                 \
        for ((var) = ((head)->tqh_first);                               \
                (var) && ((next_var) = ((var)->field.tqe_next), 1);     \
                (var) = (next_var))
#define QTAILQ_HEAD(name, type)                                         \
union name {                                                            \
        struct type *tqh_first;                      \
        QTailQLink tqh_circ;           \
}
#define QTAILQ_HEAD_INITIALIZER(head)                                   \
        { .tqh_circ = { NULL, &(head).tqh_circ } }
#define QTAILQ_INIT(head) do {                                          \
        (head)->tqh_first = NULL;                                       \
        (head)->tqh_circ.tql_prev = &(head)->tqh_circ;                  \
} while (0)
#define QTAILQ_INSERT_AFTER(head, listelm, elm, field) do {             \
        if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL)\
            (elm)->field.tqe_next->field.tqe_circ.tql_prev =            \
                &(elm)->field.tqe_circ;                                 \
        else                                                            \
            (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;         \
        (listelm)->field.tqe_next = (elm);                              \
        (elm)->field.tqe_circ.tql_prev = &(listelm)->field.tqe_circ;    \
} while (0)
#define QTAILQ_INSERT_BEFORE(listelm, elm, field) do {                       \
        (elm)->field.tqe_circ.tql_prev = (listelm)->field.tqe_circ.tql_prev; \
        (elm)->field.tqe_next = (listelm);                                   \
        (listelm)->field.tqe_circ.tql_prev->tql_next = (elm);                \
        (listelm)->field.tqe_circ.tql_prev = &(elm)->field.tqe_circ;         \
} while (0)
#define QTAILQ_INSERT_HEAD(head, elm, field) do {                       \
        if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)        \
            (head)->tqh_first->field.tqe_circ.tql_prev =                \
                &(elm)->field.tqe_circ;                                 \
        else                                                            \
            (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;         \
        (head)->tqh_first = (elm);                                      \
        (elm)->field.tqe_circ.tql_prev = &(head)->tqh_circ;             \
} while (0)
#define QTAILQ_INSERT_TAIL(head, elm, field) do {                       \
        (elm)->field.tqe_next = NULL;                                   \
        (elm)->field.tqe_circ.tql_prev = (head)->tqh_circ.tql_prev;     \
        (head)->tqh_circ.tql_prev->tql_next = (elm);                    \
        (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;             \
} while (0)
#define QTAILQ_IN_USE(elm, field)        ((elm)->field.tqe_circ.tql_prev != NULL)
#define QTAILQ_LAST(head)                                               \
        ((typeof((head)->tqh_first)) QTAILQ_LINK_PREV((head)->tqh_circ))
#define QTAILQ_LINK_PREV(link)                                          \
        ((link).tql_prev->tql_prev->tql_next)
#define QTAILQ_NEXT(elm, field)          ((elm)->field.tqe_next)
#define QTAILQ_PREV(elm, field)                                         \
        ((typeof((elm)->field.tqe_next)) QTAILQ_LINK_PREV((elm)->field.tqe_circ))
#define QTAILQ_RAW_FIRST(head)                                                 \
        field_at_offset(head, 0, void *)
#define QTAILQ_RAW_FOREACH(elm, head, entry)                                   \
        for ((elm) = *QTAILQ_RAW_FIRST(head);                                  \
             (elm);                                                            \
             (elm) = *QTAILQ_RAW_NEXT(elm, entry))
#define QTAILQ_RAW_INSERT_TAIL(head, elm, entry) do {                           \
        *QTAILQ_RAW_NEXT(elm, entry) = NULL;                                    \
        QTAILQ_RAW_TQE_CIRC(elm, entry)->tql_prev = QTAILQ_RAW_TQH_CIRC(head)->tql_prev; \
        QTAILQ_RAW_TQH_CIRC(head)->tql_prev->tql_next = (elm);                  \
        QTAILQ_RAW_TQH_CIRC(head)->tql_prev = QTAILQ_RAW_TQE_CIRC(elm, entry);  \
} while (0)
#define QTAILQ_RAW_NEXT(elm, entry)                                            \
        field_at_offset(elm, entry, void *)
#define QTAILQ_RAW_TQE_CIRC(elm, entry)                                        \
        field_at_offset(elm, entry, QTailQLink)
#define QTAILQ_RAW_TQH_CIRC(head)                                              \
        field_at_offset(head, 0, QTailQLink)
#define QTAILQ_REMOVE(head, elm, field) do {                            \
        if (((elm)->field.tqe_next) != NULL)                            \
            (elm)->field.tqe_next->field.tqe_circ.tql_prev =            \
                (elm)->field.tqe_circ.tql_prev;                         \
        else                                                            \
            (head)->tqh_circ.tql_prev = (elm)->field.tqe_circ.tql_prev; \
        (elm)->field.tqe_circ.tql_prev->tql_next = (elm)->field.tqe_next; \
        (elm)->field.tqe_circ.tql_prev = NULL;                          \
        (elm)->field.tqe_circ.tql_next = NULL;                          \
        (elm)->field.tqe_next = NULL;                                   \
} while (0)
#define QTAILQ_REMOVE_SEVERAL(head, left, right, field) do {            \
        if (((right)->field.tqe_next) != NULL)                          \
            (right)->field.tqe_next->field.tqe_circ.tql_prev =          \
                (left)->field.tqe_circ.tql_prev;                        \
        else                                                            \
            (head)->tqh_circ.tql_prev = (left)->field.tqe_circ.tql_prev; \
        (left)->field.tqe_circ.tql_prev->tql_next = (right)->field.tqe_next; \
    } while (0)
#define field_at_offset(base, offset, type)                                    \
        ((type *) (((char *) (base)) + (offset)))
#define MIPS_RDHWR(rd, value) {                         \
        __asm__ __volatile__ (".set   push\n\t"         \
                              ".set mips32r2\n\t"       \
                              "rdhwr  %0, "rd"\n\t"     \
                              ".set   pop"              \
                              : "=r" (value));          \
    }
#define NANOSECONDS_PER_SECOND 1000000000LL
#define QEMU_TIMER_ATTR_ALL      0xffffffff
#define QEMU_TIMER_ATTR_EXTERNAL ((int)BIT(0))

#define SCALE_MS 1000000
#define SCALE_NS 1
#define SCALE_US 1000

# define clol   clo32
# define clzl   clz32
# define ctol   cto32
# define ctpopl ctpop32
# define ctzl   ctz32
# define revbitl revbit32



#define CPU_CONVERT(endian, size, type)\
static inline type endian ## size ## _to_cpu(type v)\
{\
    return glue(endian, _bswap)(v, size);\
}\
\
static inline type cpu_to_ ## endian ## size(type v)\
{\
    return glue(endian, _bswap)(v, size);\
}\
\
static inline void endian ## size ## _to_cpus(type *p)\
{\
    glue(endian, _bswaps)(p, size);\
}\
\
static inline void cpu_to_ ## endian ## size ## s(type *p)\
{\
    glue(endian, _bswaps)(p, size);\
}
#define DO_STN_LDN_P(END) \
    static inline void stn_## END ## _p(void *ptr, int sz, uint64_t v)  \
    {                                                                   \
        switch (sz) {                                                   \
        case 1:                                                         \
            stb_p(ptr, v);                                              \
            break;                                                      \
        case 2:                                                         \
            stw_ ## END ## _p(ptr, v);                                  \
            break;                                                      \
        case 4:                                                         \
            stl_ ## END ## _p(ptr, v);                                  \
            break;                                                      \
        case 8:                                                         \
            stq_ ## END ## _p(ptr, v);                                  \
            break;                                                      \
        default:                                                        \
            g_assert_not_reached();                                     \
        }                                                               \
    }                                                                   \
    static inline uint64_t ldn_## END ## _p(const void *ptr, int sz)    \
    {                                                                   \
        switch (sz) {                                                   \
        case 1:                                                         \
            return ldub_p(ptr);                                         \
        case 2:                                                         \
            return lduw_ ## END ## _p(ptr);                             \
        case 4:                                                         \
            return (uint32_t)ldl_ ## END ## _p(ptr);                    \
        case 8:                                                         \
            return ldq_ ## END ## _p(ptr);                              \
        default:                                                        \
            g_assert_not_reached();                                     \
        }                                                               \
    }
#define be_bswap(v, size) (v)
#define be_bswaps(v, size)
# define const_le16(_x)                          \
    ((((_x) & 0x00ff) << 8) |                    \
     (((_x) & 0xff00) >> 8))
# define const_le32(_x)                          \
    ((((_x) & 0x000000ffU) << 24) |              \
     (((_x) & 0x0000ff00U) <<  8) |              \
     (((_x) & 0x00ff0000U) >>  8) |              \
     (((_x) & 0xff000000U) >> 24))
#define le_bswap(v, size) glue(bswap, size)(v)
#define le_bswaps(p, size) do { *p = glue(bswap, size)(*p); } while(0)

#define const_float16(x) (x)
#define const_float32(x) (x)
#define const_float64(x) (x)
#define float16_val(x) (x)
#define float32_val(x) (x)
#define float64_val(x) (x)
#define float_tininess_after_rounding  false
#define float_tininess_before_rounding true
#define make_float128(high_, low_) ((float128) { .high = high_, .low = low_ })
#define make_float128_init(high_, low_) { .high = high_, .low = low_ }
#define make_float16(x) (x)
#define make_float32(x) (x)
#define make_float64(x) (x)
#define make_floatx80(exp, mant) ((floatx80) { mant, exp })
#define make_floatx80_init(exp, mant) { .low = mant, .high = exp }

#define DO_UPCAST(type, field, dev) ( __extension__ ( { \
    char __attribute__((unused)) offset_must_be_zero[ \
        -offsetof(type, field)]; \
    container_of(dev, type, field);}))
# define GCC_FMT_ATTR(n, m) __attribute__((format(printf, n, m)))

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))
#define QEMU_ALWAYS_INLINE  __attribute__((always_inline))
#define QEMU_BUILD_BUG_MSG(x, msg) _Static_assert(!(x), msg)
#define QEMU_BUILD_BUG_ON(x) QEMU_BUILD_BUG_MSG(x, "not expecting: " #x)
#define QEMU_BUILD_BUG_ON_STRUCT(x) \
    struct { \
        int:(x) ? -1 : 1; \
    }
#define QEMU_BUILD_BUG_ON_ZERO(x) (sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)) - \
                                   sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)))
#define QEMU_DISABLE_CFI __attribute__((no_sanitize("cfi-icall")))
# define QEMU_ERROR(X) __attribute__((error(X)))
#define QEMU_EXTERN_C extern "C"
# define QEMU_FALLTHROUGH __attribute__((fallthrough))
# define QEMU_FLATTEN __attribute__((flatten))
# define QEMU_NONSTRING __attribute__((nonstring))
#define QEMU_NORETURN __attribute__ ((__noreturn__))
# define QEMU_PACKED __attribute__((gcc_struct, packed))
#define QEMU_SENTINEL __attribute__((sentinel))
#define QEMU_STATIC_ANALYSIS 1
#define QEMU_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#define __has_attribute(x) 0 
#define __has_builtin(x) 0 
#define __has_feature(x) 0 
#define __has_warning(x) 0 
#  define __printf__ __gnu_printf__
#define container_of(ptr, type, member) ({                      \
        const typeof(((type *) 0)->member) *__mptr = (ptr);     \
        (type *) ((char *) __mptr - offsetof(type, member));})
#define endof(container, field) \
    (offsetof(container, field) + sizeof_field(container, field))
#define glue(x, y) xglue(x, y)
#define likely(x)   __builtin_expect(!!(x), 1)
#define qemu_build_not_reached()  qemu_build_not_reached_always()
#define sizeof_field(type, field) sizeof(((type *)0)->field)
#define stringify(s)	tostring(s)
#define tostring(s)	#s
#define type_check(t1,t2) ((t1*)0 - (t2*)0)
#define typeof_field(type, field) typeof(((type *)0)->field)
#define unlikely(x)   __builtin_expect(!!(x), 0)
#define xglue(x, y) x ## y
#define BIT(nr)                 (1UL << (nr))

#define BITS_PER_BYTE           CHAR_BIT
#define BITS_PER_LONG           (sizeof (unsigned long) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))
#define BIT_MASK(nr)            (1UL << ((nr) % BITS_PER_LONG))
#define BIT_ULL(nr)             (1ULL << (nr))
#define BIT_WORD(nr)            ((nr) / BITS_PER_LONG)
#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))
#define DEFINE_LDST_DMA(_lname, _sname, _bits, _end) \
    static inline uint##_bits##_t ld##_lname##_##_end##_dma(AddressSpace *as, \
                                                            dma_addr_t addr) \
    {                                                                   \
        uint##_bits##_t val;                                            \
        dma_memory_read(as, addr, &val, (_bits) / 8);                   \
        return _end##_bits##_to_cpu(val);                               \
    }                                                                   \
    static inline void st##_sname##_##_end##_dma(AddressSpace *as,      \
                                                 dma_addr_t addr,       \
                                                 uint##_bits##_t val)   \
    {                                                                   \
        val = cpu_to_##_end##_bits(val);                                \
        dma_memory_write(as, addr, &val, (_bits) / 8);                  \
    }
#define DMA_ADDR_BITS 64
#define DMA_ADDR_FMT "%" PRIx64


#define QEMU_THREAD_DETACHED 1

#define QEMU_THREAD_JOINABLE 0
#define qemu_cond_timedwait(c, m, ms) ({                                       \
            QemuCondTimedWaitFunc _f = qatomic_read(&qemu_cond_timedwait_func);\
            _f(c, m, ms, "__FILE__", "__LINE__");                                  \
        })
#define qemu_cond_wait(c, m)                                            \
            qemu_cond_wait_impl(c, m, "__FILE__", "__LINE__")
#define qemu_mutex_lock(m)                                              \
            qemu_mutex_lock_impl(m, "__FILE__", "__LINE__")
#define qemu_mutex_lock__raw(m)                         \
        qemu_mutex_lock_impl(m, "__FILE__", "__LINE__")
#define qemu_mutex_trylock(m)                                           \
            qemu_mutex_trylock_impl(m, "__FILE__", "__LINE__")
#define qemu_mutex_trylock__raw(m)                      \
        qemu_mutex_trylock_impl(m, "__FILE__", "__LINE__")
#define qemu_mutex_unlock(mutex) \
        qemu_mutex_unlock_impl(mutex, "__FILE__", "__LINE__")
#define qemu_rec_mutex_lock(m)                                          \
            qemu_rec_mutex_lock_impl(m, "__FILE__", "__LINE__")
#define qemu_rec_mutex_trylock(m)                                       \
            qemu_rec_mutex_trylock_impl(m, "__FILE__", "__LINE__")
#define qemu_rec_mutex_unlock(mutex) \
        qemu_rec_mutex_unlock_impl(mutex, "__FILE__", "__LINE__")



# define ATOMIC_REG_SIZE  8

#define barrier()   ({ asm volatile("" ::: "memory"); (void)0; })
#define qatomic_add(ptr, n) \
    ((void) __atomic_fetch_add(ptr, n, __ATOMIC_SEQ_CST))
#define qatomic_add_fetch(ptr, n) __atomic_add_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define qatomic_and(ptr, n) \
    ((void) __atomic_fetch_and(ptr, n, __ATOMIC_SEQ_CST))
#define qatomic_and_fetch(ptr, n) __atomic_and_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define qatomic_cmpxchg(ptr, old, new)    ({                            \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE);                  \
    qatomic_cmpxchg__nocheck(ptr, old, new);                            \
})
#define qatomic_cmpxchg__nocheck(ptr, old, new)    ({                   \
    typeof_strip_qual(*ptr) _old = (old);                               \
    (void)__atomic_compare_exchange_n(ptr, &_old, new, false,           \
                              __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);      \
    _old;                                                               \
})
#define qatomic_dec(ptr) \
    ((void) __atomic_fetch_sub(ptr, 1, __ATOMIC_SEQ_CST))
#define qatomic_dec_fetch(ptr)    __atomic_sub_fetch(ptr, 1, __ATOMIC_SEQ_CST)
#define qatomic_fetch_add(ptr, n) __atomic_fetch_add(ptr, n, __ATOMIC_SEQ_CST)
#define qatomic_fetch_and(ptr, n) __atomic_fetch_and(ptr, n, __ATOMIC_SEQ_CST)
#define qatomic_fetch_dec(ptr)  __atomic_fetch_sub(ptr, 1, __ATOMIC_SEQ_CST)
#define qatomic_fetch_inc(ptr)  __atomic_fetch_add(ptr, 1, __ATOMIC_SEQ_CST)
#define qatomic_fetch_inc_nonzero(ptr) ({                               \
    typeof_strip_qual(*ptr) _oldn = qatomic_read(ptr);                  \
    while (_oldn && qatomic_cmpxchg(ptr, _oldn, _oldn + 1) != _oldn) {  \
        _oldn = qatomic_read(ptr);                                      \
    }                                                                   \
    _oldn;                                                              \
})
#define qatomic_fetch_or(ptr, n)  __atomic_fetch_or(ptr, n, __ATOMIC_SEQ_CST)
#define qatomic_fetch_sub(ptr, n) __atomic_fetch_sub(ptr, n, __ATOMIC_SEQ_CST)
#define qatomic_fetch_xor(ptr, n) __atomic_fetch_xor(ptr, n, __ATOMIC_SEQ_CST)
#define qatomic_inc(ptr) \
    ((void) __atomic_fetch_add(ptr, 1, __ATOMIC_SEQ_CST))
#define qatomic_inc_fetch(ptr)    __atomic_add_fetch(ptr, 1, __ATOMIC_SEQ_CST)
#define qatomic_load_acquire(ptr)                       \
    ({                                                  \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE);  \
    typeof_strip_qual(*ptr) _val;                       \
    __atomic_load(ptr, &_val, __ATOMIC_ACQUIRE);        \
    _val;                                               \
    })
#define qatomic_mb_read(ptr)                             \
    qatomic_load_acquire(ptr)
# define qatomic_mb_set(ptr, i)  ((void)qatomic_xchg(ptr, i))
#define qatomic_or(ptr, n) \
    ((void) __atomic_fetch_or(ptr, n, __ATOMIC_SEQ_CST))
#define qatomic_or_fetch(ptr, n)  __atomic_or_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define qatomic_rcu_read(ptr)                          \
    ({                                                 \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    typeof_strip_qual(*ptr) _val;                      \
    qatomic_rcu_read__nocheck(ptr, &_val);             \
    _val;                                              \
    })
#define qatomic_rcu_read__nocheck(ptr, valptr)           \
    __atomic_load(ptr, valptr, __ATOMIC_CONSUME);
#define qatomic_rcu_set(ptr, i) do {                   \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    __atomic_store_n(ptr, i, __ATOMIC_RELEASE);        \
} while(0)
#define qatomic_read(ptr)                              \
    ({                                                 \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    qatomic_read__nocheck(ptr);                        \
    })
#define qatomic_read__nocheck(ptr) \
    __atomic_load_n(ptr, __ATOMIC_RELAXED)
#define qatomic_read_i64(P) \
    _Generic(*(P), int64_t: qatomic_read__nocheck(P))
#define qatomic_read_u64(P) \
    _Generic(*(P), uint64_t: qatomic_read__nocheck(P))
#define qatomic_set(ptr, i)  do {                      \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE); \
    qatomic_set__nocheck(ptr, i);                      \
} while(0)
#define qatomic_set__nocheck(ptr, i) \
    __atomic_store_n(ptr, i, __ATOMIC_RELAXED)
#define qatomic_set_i64(P, V) \
    _Generic(*(P), int64_t: qatomic_set__nocheck(P, V))
#define qatomic_set_u64(P, V) \
    _Generic(*(P), uint64_t: qatomic_set__nocheck(P, V))
#define qatomic_store_release(ptr, i)  do {             \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE);  \
    __atomic_store_n(ptr, i, __ATOMIC_RELEASE);         \
} while(0)
#define qatomic_sub(ptr, n) \
    ((void) __atomic_fetch_sub(ptr, n, __ATOMIC_SEQ_CST))
#define qatomic_sub_fetch(ptr, n) __atomic_sub_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define qatomic_xchg(ptr, i)    ({                          \
    QEMU_BUILD_BUG_ON(sizeof(*ptr) > ATOMIC_REG_SIZE);      \
    qatomic_xchg__nocheck(ptr, i);                          \
})
#define qatomic_xchg__nocheck(ptr, i)    ({                 \
    __atomic_exchange_n(ptr, (i), __ATOMIC_SEQ_CST);        \
})
#define qatomic_xor(ptr, n) \
    ((void) __atomic_fetch_xor(ptr, n, __ATOMIC_SEQ_CST))
#define qatomic_xor_fetch(ptr, n) __atomic_xor_fetch(ptr, n, __ATOMIC_SEQ_CST)
#define signal_barrier()    __atomic_signal_fence(__ATOMIC_SEQ_CST)
#define smp_mb()                     ({ barrier(); __atomic_thread_fence(__ATOMIC_SEQ_CST); })
#define smp_mb_acquire()             ({ barrier(); __atomic_thread_fence(__ATOMIC_ACQUIRE); })
#define smp_mb_release()             ({ barrier(); __atomic_thread_fence(__ATOMIC_RELEASE); })
#define smp_read_barrier_depends()   ({ barrier(); __atomic_thread_fence(__ATOMIC_CONSUME); })
#define smp_rmb()   smp_mb_acquire()
#define smp_wmb()   smp_mb_release()
#define typeof_strip_qual(expr)                                                    \
  typeof(                                                                          \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), bool) ||                          \
        __builtin_types_compatible_p(typeof(expr), const bool) ||                  \
        __builtin_types_compatible_p(typeof(expr), volatile bool) ||               \
        __builtin_types_compatible_p(typeof(expr), const volatile bool),           \
        (bool)1,                                                                   \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), signed char) ||                   \
        __builtin_types_compatible_p(typeof(expr), const signed char) ||           \
        __builtin_types_compatible_p(typeof(expr), volatile signed char) ||        \
        __builtin_types_compatible_p(typeof(expr), const volatile signed char),    \
        (signed char)1,                                                            \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), unsigned char) ||                 \
        __builtin_types_compatible_p(typeof(expr), const unsigned char) ||         \
        __builtin_types_compatible_p(typeof(expr), volatile unsigned char) ||      \
        __builtin_types_compatible_p(typeof(expr), const volatile unsigned char),  \
        (unsigned char)1,                                                          \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), signed short) ||                  \
        __builtin_types_compatible_p(typeof(expr), const signed short) ||          \
        __builtin_types_compatible_p(typeof(expr), volatile signed short) ||       \
        __builtin_types_compatible_p(typeof(expr), const volatile signed short),   \
        (signed short)1,                                                           \
    __builtin_choose_expr(                                                         \
      __builtin_types_compatible_p(typeof(expr), unsigned short) ||                \
        __builtin_types_compatible_p(typeof(expr), const unsigned short) ||        \
        __builtin_types_compatible_p(typeof(expr), volatile unsigned short) ||     \
        __builtin_types_compatible_p(typeof(expr), const volatile unsigned short), \
        (unsigned short)1,                                                         \
      (expr)+0))))))

# define cpu_relax() asm volatile("rep; nop" ::: "memory")

#define BDRV_BLOCK_ALLOCATED    0x10
#define BDRV_BLOCK_DATA         0x01
#define BDRV_BLOCK_EOF          0x20
#define BDRV_BLOCK_OFFSET_VALID 0x04
#define BDRV_BLOCK_RAW          0x08
#define BDRV_BLOCK_RECURSE      0x40
#define BDRV_BLOCK_ZERO         0x02
#define BDRV_MAX_ALIGNMENT (1L << 30)
#define BDRV_MAX_LENGTH (QEMU_ALIGN_DOWN(INT64_MAX, BDRV_MAX_ALIGNMENT))
#define BDRV_OPT_AUTO_READ_ONLY "auto-read-only"
#define BDRV_OPT_CACHE_DIRECT   "cache.direct"
#define BDRV_OPT_CACHE_NO_FLUSH "cache.no-flush"
#define BDRV_OPT_CACHE_WB       "cache.writeback"
#define BDRV_OPT_DISCARD        "discard"
#define BDRV_OPT_FORCE_SHARE    "force-share"
#define BDRV_OPT_READ_ONLY      "read-only"
#define BDRV_O_ALLOW_RDWR  0x2000  
#define BDRV_O_AUTO_RDONLY 0x20000 
#define BDRV_O_CACHE_MASK  (BDRV_O_NOCACHE | BDRV_O_NO_FLUSH)
#define BDRV_O_CHECK       0x1000  
#define BDRV_O_COPY_ON_READ 0x0400 
#define BDRV_O_INACTIVE    0x0800  
#define BDRV_O_IO_URING    0x40000 
#define BDRV_O_NATIVE_AIO  0x0080 
#define BDRV_O_NOCACHE     0x0020 
#define BDRV_O_NO_BACKING  0x0100 
#define BDRV_O_NO_FLUSH    0x0200 
#define BDRV_O_NO_IO       0x10000 
#define BDRV_O_NO_SHARE    0x0001 
#define BDRV_O_PROTOCOL    0x8000  
#define BDRV_O_RDWR        0x0002
#define BDRV_O_RESIZE      0x0004 
#define BDRV_O_SNAPSHOT    0x0008 
#define BDRV_O_TEMPORARY   0x0010 
#define BDRV_O_UNMAP       0x4000  
#define BDRV_POLL_WHILE(bs, cond) ({                       \
    BlockDriverState *bs_ = (bs);                          \
    AIO_WAIT_WHILE(bdrv_get_aio_context(bs_),              \
                   cond); })
#define BDRV_REQUEST_MAX_BYTES (BDRV_REQUEST_MAX_SECTORS << BDRV_SECTOR_BITS)
#define BDRV_REQUEST_MAX_SECTORS MIN_CONST(SIZE_MAX >> BDRV_SECTOR_BITS, \
                                           INT_MAX >> BDRV_SECTOR_BITS)
#define BDRV_SECTOR_BITS   9
#define BDRV_SECTOR_SIZE   (1ULL << BDRV_SECTOR_BITS)
#define BLKDBG_EVENT(child, evt) \
    do { \
        if (child) { \
            bdrv_debug_event(child->bs, evt); \
        } \
    } while (0)



#define BITS_PER_LEVEL         (BITS_PER_LONG == 32 ? 5 : 6)

#define HBITMAP_LEVELS         ((HBITMAP_LOG_MAX_SIZE / BITS_PER_LEVEL) + 1)
#define HBITMAP_LOG_MAX_SIZE   (BITS_PER_LONG == 32 ? 34 : 41)

#define BLOCK_JOB_SLICE_TIME 100000000ULL 


#define QEMU_LOCK_GUARD(x)                                       \
    g_autoptr(QemuLockable)                                      \
    glue(qemu_lockable_auto, __COUNTER__) G_GNUC_UNUSED =        \
            qemu_lockable_auto_lock(QEMU_MAKE_LOCKABLE((x)))
#define QEMU_MAKE_LOCKABLE(x)                                           \
    _Generic((x), QemuLockable *: (x),                                  \
             void *: qemu_null_lockable(x),                             \
             QemuMutex *: qemu_make_lockable(x, QML_OBJ_(x, mutex)),    \
             QemuRecMutex *: qemu_make_lockable(x, QML_OBJ_(x, rec_mutex)), \
             CoMutex *: qemu_make_lockable(x, QML_OBJ_(x, co_mutex)),   \
             QemuSpin *: qemu_make_lockable(x, QML_OBJ_(x, spin)))
#define QEMU_MAKE_LOCKABLE_NONNULL(x)                           \
    _Generic((x), QemuLockable *: (x),                          \
                  QemuMutex *: QML_OBJ_(x, mutex),              \
                  QemuRecMutex *: QML_OBJ_(x, rec_mutex),       \
                  CoMutex *: QML_OBJ_(x, co_mutex),             \
                  QemuSpin *: QML_OBJ_(x, spin))
#define QML_OBJ_(x, name) (&(QemuLockable) {                            \
        .object = (x),                                                  \
        .lock = (QemuLockUnlockFunc *) qemu_ ## name ## _lock,          \
        .unlock = (QemuLockUnlockFunc *) qemu_ ## name ## _unlock       \
    })
#define WITH_QEMU_LOCK_GUARD(x) \
    WITH_QEMU_LOCK_GUARD_((x), glue(qemu_lockable_auto, __COUNTER__))
#define WITH_QEMU_LOCK_GUARD_(x, var) \
    for (g_autoptr(QemuLockable) var = \
                qemu_lockable_auto_lock(QEMU_MAKE_LOCKABLE_NONNULL((x))); \
         var; \
         qemu_lockable_auto_unlock(var), var = NULL)


#define qemu_co_enter_next(queue, lock) \
    qemu_co_enter_next_impl(queue, QEMU_MAKE_LOCKABLE(lock))
#define qemu_co_queue_wait(queue, lock) \
    qemu_co_queue_wait_impl(queue, QEMU_MAKE_LOCKABLE(lock))


#define aio_bh_new(ctx, cb, opaque) \
    aio_bh_new_full((ctx), (cb), (opaque), (stringify(cb)))
#define aio_bh_schedule_oneshot(ctx, cb, opaque) \
    aio_bh_schedule_oneshot_full((ctx), (cb), (opaque), (stringify(cb)))


#define BDRV_BITMAP_ALLOW_RO (BDRV_BITMAP_BUSY | BDRV_BITMAP_INCONSISTENT)
#define BDRV_BITMAP_DEFAULT (BDRV_BITMAP_BUSY | BDRV_BITMAP_RO |        \
                             BDRV_BITMAP_INCONSISTENT)
#define BDRV_BITMAP_MAX_NAME_SIZE 1023

#define FOR_EACH_DIRTY_BITMAP(bs, bitmap) \
for (bitmap = bdrv_dirty_bitmap_first(bs); bitmap; \
     bitmap = bdrv_dirty_bitmap_next(bitmap))

#define QEMU_IOVEC_INIT_BUF(self, buf, len)              \
{                                                        \
    .iov = &(self).local_iov,                            \
    .niov = 1,                                           \
    .nalloc = -1,                                        \
    .local_iov = {                                       \
        .iov_base = (void *)(buf),  \
        .iov_len = (len),                                \
    },                                                   \
}
#define iov_recv(sockfd, iov, iov_cnt, offset, bytes) \
  iov_send_recv(sockfd, iov, iov_cnt, offset, bytes, false)
#define iov_send(sockfd, iov, iov_cnt, offset, bytes) \
  iov_send_recv(sockfd, iov, iov_cnt, offset, bytes, true)
#define AIO_WAIT_WHILE(ctx, cond) ({                               \
    bool waited_ = false;                                          \
    AioWait *wait_ = &global_aio_wait;                             \
    AioContext *ctx_ = (ctx);                                      \
         \
    qatomic_inc(&wait_->num_waiters);                              \
    if (ctx_ && in_aio_context_home_thread(ctx_)) {                \
        while ((cond)) {                                           \
            aio_poll(ctx_, true);                                  \
            waited_ = true;                                        \
        }                                                          \
    } else {                                                       \
        assert(qemu_get_current_aio_context() ==                   \
               qemu_get_aio_context());                            \
        while ((cond)) {                                           \
            if (ctx_) {                                            \
                aio_context_release(ctx_);                         \
            }                                                      \
            aio_poll(qemu_get_aio_context(), true);                \
            if (ctx_) {                                            \
                aio_context_acquire(ctx_);                         \
            }                                                      \
            waited_ = true;                                        \
        }                                                          \
    }                                                              \
    qatomic_dec(&wait_->num_waiters);                              \
    waited_; })


#define SIG_IPI SIGUSR1
#define qemu_bh_new(cb, opaque) \
    qemu_bh_new_full((cb), (opaque), (stringify(cb)))
#define qemu_mutex_lock_iothread()                      \
    qemu_mutex_lock_iothread_impl("__FILE__", "__LINE__")

#define ARG1         as
#define ARG1_DECL    AddressSpace *as
#define ENDIANNESS   _le
#define GLOBAL_DIRTY_DIRTY_RATE (1U << 1)
#define GLOBAL_DIRTY_MASK  (0x3)
#define GLOBAL_DIRTY_MIGRATION  (1U << 0)
#define IOMMU_ACCESS_FLAG(r, w) (((r) ? IOMMU_RO : 0) | ((w) ? IOMMU_WO : 0))
#define IOMMU_NOTIFIER_ALL (IOMMU_NOTIFIER_IOTLB_EVENTS | \
                            IOMMU_NOTIFIER_DEVIOTLB_EVENTS)
#define IOMMU_NOTIFIER_DEVIOTLB_EVENTS IOMMU_NOTIFIER_DEVIOTLB_UNMAP
#define IOMMU_NOTIFIER_FOREACH(n, mr) \
    QLIST_FOREACH((n), &(mr)->iommu_notify, node)
#define IOMMU_NOTIFIER_IOTLB_EVENTS (IOMMU_NOTIFIER_MAP | IOMMU_NOTIFIER_UNMAP)
#define MAX_PHYS_ADDR            (((hwaddr)1 << MAX_PHYS_ADDR_SPACE_BITS) - 1)
#define MAX_PHYS_ADDR_SPACE_BITS 62

#define MEMORY_REGION_CACHE_INVALID ((MemoryRegionCache) { .mrs.mr = NULL })
#define RAM_ADDR_INVALID (~(ram_addr_t)0)
#define RAM_MIGRATABLE (1 << 4)
#define RAM_NORESERVE (1 << 7)
#define RAM_PMEM (1 << 5)
#define RAM_PREALLOC   (1 << 0)
#define RAM_PROTECTED (1 << 8)
#define RAM_RESIZEABLE (1 << 2)
#define RAM_SHARED     (1 << 1)
#define RAM_UF_WRITEPROTECT (1 << 6)
#define RAM_UF_ZEROPAGE (1 << 3)
#define SUFFIX       _cached_slow
#define TYPE_IOMMU_MEMORY_REGION "iommu-memory-region"
#define TYPE_MEMORY_REGION "memory-region"
#define TYPE_RAM_DISCARD_MANAGER "qemu:ram-discard-manager"
#define memory_region_is_iommu(mr) (memory_region_get_iommu(mr) != NULL)

#define RCU_READ_LOCK_GUARD() \
    g_autoptr(RCUReadAuto) _rcu_read_auto __attribute__((unused)) = rcu_read_auto_lock()
#define WITH_RCU_READ_LOCK_GUARD() \
    WITH_RCU_READ_LOCK_GUARD_(glue(_rcu_read_auto, __COUNTER__))
#define WITH_RCU_READ_LOCK_GUARD_(var) \
    for (g_autoptr(RCUReadAuto) var = rcu_read_auto_lock(); \
        (var); rcu_read_auto_unlock(var), (var) = NULL)
#define call_rcu(head, func, field)                                      \
    call_rcu1(({                                                         \
         char __attribute__((unused))                                    \
            offset_must_be_zero[-offsetof(typeof(*(head)), field)],      \
            func_type_invalid = (func) - (void (*)(typeof(head)))(func); \
         &(head)->field;                                                 \
      }),                                                                \
      (RCUCBFunc *)(func))
#define g_free_rcu(obj, field) \
    call_rcu1(({                                                         \
        char __attribute__((unused))                                     \
            offset_must_be_zero[-offsetof(typeof(*(obj)), field)];       \
        &(obj)->field;                                                   \
      }),                                                                \
      (RCUCBFunc *)g_free);
#define rcu_assert(args...)    assert(args)

#define smp_mb_global()            smp_mb()
#define smp_mb_placeholder()       barrier()

#define DIRTY_MEMORY_BLOCK_SIZE ((ram_addr_t)256 * 1024 * 8)
#define DIRTY_MEMORY_CODE      1
#define DIRTY_MEMORY_MIGRATION 2
#define DIRTY_MEMORY_NUM       3        
#define DIRTY_MEMORY_VGA       0
#define  INTERNAL_RAMBLOCK_FOREACH(block)  \
    QLIST_FOREACH_RCU(block, &ram_list.blocks, next)
#define RAMBLOCK_FOREACH(block) INTERNAL_RAMBLOCK_FOREACH(block)


#define QLIST_EMPTY_RCU(head) (qatomic_read(&(head)->lh_first) == NULL)
#define QLIST_FIRST_RCU(head) (qatomic_rcu_read(&(head)->lh_first))
#define QLIST_FOREACH_RCU(var, head, field)                 \
        for ((var) = qatomic_rcu_read(&(head)->lh_first);   \
                (var);                                      \
                (var) = qatomic_rcu_read(&(var)->field.le_next))
#define QLIST_FOREACH_SAFE_RCU(var, head, field, next_var)           \
    for ((var) = (qatomic_rcu_read(&(head)->lh_first));              \
      (var) &&                                                       \
          ((next_var) = qatomic_rcu_read(&(var)->field.le_next), 1); \
           (var) = (next_var))
#define QLIST_INSERT_AFTER_RCU(listelm, elm, field) do {    \
    (elm)->field.le_next = (listelm)->field.le_next;        \
    (elm)->field.le_prev = &(listelm)->field.le_next;       \
    qatomic_rcu_set(&(listelm)->field.le_next, (elm));      \
    if ((elm)->field.le_next != NULL) {                     \
       (elm)->field.le_next->field.le_prev =                \
        &(elm)->field.le_next;                              \
    }                                                       \
} while (0)
#define QLIST_INSERT_BEFORE_RCU(listelm, elm, field) do {   \
    (elm)->field.le_prev = (listelm)->field.le_prev;        \
    (elm)->field.le_next = (listelm);                       \
    qatomic_rcu_set((listelm)->field.le_prev, (elm));       \
    (listelm)->field.le_prev = &(elm)->field.le_next;       \
} while (0)
#define QLIST_INSERT_HEAD_RCU(head, elm, field) do {    \
    (elm)->field.le_prev = &(head)->lh_first;           \
    (elm)->field.le_next = (head)->lh_first;            \
    qatomic_rcu_set((&(head)->lh_first), (elm));        \
    if ((elm)->field.le_next != NULL) {                 \
       (elm)->field.le_next->field.le_prev =            \
        &(elm)->field.le_next;                          \
    }                                                   \
} while (0)
#define QLIST_NEXT_RCU(elm, field) (qatomic_rcu_read(&(elm)->field.le_next))
#define QLIST_REMOVE_RCU(elm, field) do {           \
    if ((elm)->field.le_next != NULL) {             \
       (elm)->field.le_next->field.le_prev =        \
        (elm)->field.le_prev;                       \
    }                                               \
    qatomic_set((elm)->field.le_prev, (elm)->field.le_next); \
} while (0)
#define QSIMPLEQ_EMPTY_RCU(head) \
    (qatomic_read(&(head)->sqh_first) == NULL)
#define QSIMPLEQ_FIRST_RCU(head)       qatomic_rcu_read(&(head)->sqh_first)
#define QSIMPLEQ_FOREACH_RCU(var, head, field)                          \
    for ((var) = qatomic_rcu_read(&(head)->sqh_first);                  \
         (var);                                                         \
         (var) = qatomic_rcu_read(&(var)->field.sqe_next))
#define QSIMPLEQ_FOREACH_SAFE_RCU(var, head, field, next)                \
    for ((var) = qatomic_rcu_read(&(head)->sqh_first);                   \
         (var) && ((next) = qatomic_rcu_read(&(var)->field.sqe_next), 1);\
         (var) = (next))
#define QSIMPLEQ_INSERT_AFTER_RCU(head, listelm, elm, field) do {       \
    (elm)->field.sqe_next = (listelm)->field.sqe_next;                  \
    if ((elm)->field.sqe_next == NULL) {                                \
        (head)->sqh_last = &(elm)->field.sqe_next;                      \
    }                                                                   \
    qatomic_rcu_set(&(listelm)->field.sqe_next, (elm));                 \
} while (0)
#define QSIMPLEQ_INSERT_HEAD_RCU(head, elm, field) do {         \
    (elm)->field.sqe_next = (head)->sqh_first;                  \
    if ((elm)->field.sqe_next == NULL) {                        \
        (head)->sqh_last = &(elm)->field.sqe_next;              \
    }                                                           \
    qatomic_rcu_set(&(head)->sqh_first, (elm));                 \
} while (0)
#define QSIMPLEQ_INSERT_TAIL_RCU(head, elm, field) do {    \
    (elm)->field.sqe_next = NULL;                          \
    qatomic_rcu_set((head)->sqh_last, (elm));              \
    (head)->sqh_last = &(elm)->field.sqe_next;             \
} while (0)
#define QSIMPLEQ_NEXT_RCU(elm, field)  qatomic_rcu_read(&(elm)->field.sqe_next)
#define QSIMPLEQ_REMOVE_HEAD_RCU(head, field) do {                     \
    qatomic_set(&(head)->sqh_first, (head)->sqh_first->field.sqe_next);\
    if ((head)->sqh_first == NULL) {                                   \
        (head)->sqh_last = &(head)->sqh_first;                         \
    }                                                                  \
} while (0)
#define QSIMPLEQ_REMOVE_RCU(head, elm, type, field) do {            \
    if ((head)->sqh_first == (elm)) {                               \
        QSIMPLEQ_REMOVE_HEAD_RCU((head), field);                    \
    } else {                                                        \
        struct type *curr = (head)->sqh_first;                      \
        while (curr->field.sqe_next != (elm)) {                     \
            curr = curr->field.sqe_next;                            \
        }                                                           \
        qatomic_set(&curr->field.sqe_next,                          \
                   curr->field.sqe_next->field.sqe_next);           \
        if (curr->field.sqe_next == NULL) {                         \
            (head)->sqh_last = &(curr)->field.sqe_next;             \
        }                                                           \
    }                                                               \
} while (0)
#define QSLIST_EMPTY_RCU(head)      (qatomic_read(&(head)->slh_first) == NULL)
#define QSLIST_FIRST_RCU(head)       qatomic_rcu_read(&(head)->slh_first)
#define QSLIST_FOREACH_RCU(var, head, field)                          \
    for ((var) = qatomic_rcu_read(&(head)->slh_first);                \
         (var);                                                       \
         (var) = qatomic_rcu_read(&(var)->field.sle_next))
#define QSLIST_FOREACH_SAFE_RCU(var, head, field, next)                   \
    for ((var) = qatomic_rcu_read(&(head)->slh_first);                    \
         (var) && ((next) = qatomic_rcu_read(&(var)->field.sle_next), 1); \
         (var) = (next))
#define QSLIST_INSERT_AFTER_RCU(head, listelm, elm, field) do {         \
    (elm)->field.sle_next = (listelm)->field.sle_next;                  \
    qatomic_rcu_set(&(listelm)->field.sle_next, (elm));                 \
} while (0)
#define QSLIST_INSERT_HEAD_RCU(head, elm, field) do {           \
    (elm)->field.sle_next = (head)->slh_first;                  \
    qatomic_rcu_set(&(head)->slh_first, (elm));                 \
} while (0)
#define QSLIST_NEXT_RCU(elm, field)  qatomic_rcu_read(&(elm)->field.sle_next)
#define QSLIST_REMOVE_HEAD_RCU(head, field) do {                       \
    qatomic_set(&(head)->slh_first, (head)->slh_first->field.sle_next);\
} while (0)
#define QSLIST_REMOVE_RCU(head, elm, type, field) do {              \
    if ((head)->slh_first == (elm)) {                               \
        QSLIST_REMOVE_HEAD_RCU((head), field);                      \
    } else {                                                        \
        struct type *curr = (head)->slh_first;                      \
        while (curr->field.sle_next != (elm)) {                     \
            curr = curr->field.sle_next;                            \
        }                                                           \
        qatomic_set(&curr->field.sle_next,                          \
                   curr->field.sle_next->field.sle_next);           \
    }                                                               \
} while (0)
#define QTAILQ_EMPTY_RCU(head)      (qatomic_read(&(head)->tqh_first) == NULL)
#define QTAILQ_FIRST_RCU(head)       qatomic_rcu_read(&(head)->tqh_first)
#define QTAILQ_FOREACH_RCU(var, head, field)                            \
    for ((var) = qatomic_rcu_read(&(head)->tqh_first);                  \
         (var);                                                         \
         (var) = qatomic_rcu_read(&(var)->field.tqe_next))
#define QTAILQ_FOREACH_SAFE_RCU(var, head, field, next)                  \
    for ((var) = qatomic_rcu_read(&(head)->tqh_first);                   \
         (var) && ((next) = qatomic_rcu_read(&(var)->field.tqe_next), 1);\
         (var) = (next))
#define QTAILQ_INSERT_AFTER_RCU(head, listelm, elm, field) do {         \
    (elm)->field.tqe_next = (listelm)->field.tqe_next;                  \
    if ((elm)->field.tqe_next != NULL) {                                \
        (elm)->field.tqe_next->field.tqe_circ.tql_prev =                \
            &(elm)->field.tqe_circ;                                     \
    } else {                                                            \
        (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;             \
    }                                                                   \
    qatomic_rcu_set(&(listelm)->field.tqe_next, (elm));                 \
    (elm)->field.tqe_circ.tql_prev = &(listelm)->field.tqe_circ;        \
} while (0)
#define QTAILQ_INSERT_BEFORE_RCU(listelm, elm, field) do {                \
    (elm)->field.tqe_circ.tql_prev = (listelm)->field.tqe_circ.tql_prev;  \
    (elm)->field.tqe_next = (listelm);                                    \
    qatomic_rcu_set(&(listelm)->field.tqe_circ.tql_prev->tql_next, (elm));\
    (listelm)->field.tqe_circ.tql_prev = &(elm)->field.tqe_circ;          \
} while (0)
#define QTAILQ_INSERT_HEAD_RCU(head, elm, field) do {                   \
    (elm)->field.tqe_next = (head)->tqh_first;                          \
    if ((elm)->field.tqe_next != NULL) {                                \
        (head)->tqh_first->field.tqe_circ.tql_prev =                    \
            &(elm)->field.tqe_circ;                                     \
    } else {                                                            \
        (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;             \
    }                                                                   \
    qatomic_rcu_set(&(head)->tqh_first, (elm));                         \
    (elm)->field.tqe_circ.tql_prev = &(head)->tqh_circ;                 \
} while (0)
#define QTAILQ_INSERT_TAIL_RCU(head, elm, field) do {                   \
    (elm)->field.tqe_next = NULL;                                       \
    (elm)->field.tqe_circ.tql_prev = (head)->tqh_circ.tql_prev;         \
    qatomic_rcu_set(&(head)->tqh_circ.tql_prev->tql_next, (elm));       \
    (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;                 \
} while (0)
#define QTAILQ_NEXT_RCU(elm, field)  qatomic_rcu_read(&(elm)->field.tqe_next)
#define QTAILQ_REMOVE_RCU(head, elm, field) do {                        \
    if (((elm)->field.tqe_next) != NULL) {                              \
        (elm)->field.tqe_next->field.tqe_circ.tql_prev =                \
            (elm)->field.tqe_circ.tql_prev;                             \
    } else {                                                            \
        (head)->tqh_circ.tql_prev = (elm)->field.tqe_circ.tql_prev;     \
    }                                                                   \
    qatomic_set(&(elm)->field.tqe_circ.tql_prev->tql_next,              \
                (elm)->field.tqe_next);                                 \
    (elm)->field.tqe_circ.tql_prev = NULL;                              \
} while (0)


#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs) { .unspecified = 1 })
#define MEMTX_DECODE_ERROR      (1U << 1) 
#define MEMTX_ERROR             (1U << 0) 
#define MEMTX_OK 0
#define HWADDR_BITS 64

#define HWADDR_MAX UINT64_MAX
#define HWADDR_PRIX PRIX64
#define HWADDR_PRId PRId64
#define HWADDR_PRIi PRIi64
#define HWADDR_PRIo PRIo64
#define HWADDR_PRIu PRIu64
#define HWADDR_PRIx PRIx64
#define TARGET_FMT_plx "%016" PRIx64

#define DEVICE_HOST_ENDIAN DEVICE_BIG_ENDIAN
#  define RAM_ADDR_FMT "%" PRIx64
#  define RAM_ADDR_MAX UINT64_MAX
#define DEFINE_PROP_AUDIODEV(_n, _s, _f) \
    DEFINE_PROP(_n, _s, _f, qdev_prop_audiodev, QEMUSoundCard)
#define DEFINE_PROP_BIOS_CHS_TRANS(_n, _s, _f, _d) \
    DEFINE_PROP_SIGNED(_n, _s, _f, _d, qdev_prop_bios_chs_trans, int)
#define DEFINE_PROP_BLOCKDEV_ON_ERROR(_n, _s, _f, _d) \
    DEFINE_PROP_SIGNED(_n, _s, _f, _d, qdev_prop_blockdev_on_error, \
                        BlockdevOnError)
#define DEFINE_PROP_BLOCKSIZE(_n, _s, _f) \
    DEFINE_PROP_UNSIGNED(_n, _s, _f, 0, qdev_prop_blocksize, uint32_t)
#define DEFINE_PROP_CHR(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_chr, CharBackend)
#define DEFINE_PROP_DRIVE(_n, _s, _f) \
    DEFINE_PROP(_n, _s, _f, qdev_prop_drive, BlockBackend *)
#define DEFINE_PROP_DRIVE_IOTHREAD(_n, _s, _f) \
    DEFINE_PROP(_n, _s, _f, qdev_prop_drive_iothread, BlockBackend *)
#define DEFINE_PROP_LOSTTICKPOLICY(_n, _s, _f, _d) \
    DEFINE_PROP_SIGNED(_n, _s, _f, _d, qdev_prop_losttickpolicy, \
                        LostTickPolicy)
#define DEFINE_PROP_MACADDR(_n, _s, _f)         \
    DEFINE_PROP(_n, _s, _f, qdev_prop_macaddr, MACAddr)
#define DEFINE_PROP_MULTIFD_COMPRESSION(_n, _s, _f, _d) \
    DEFINE_PROP_SIGNED(_n, _s, _f, _d, qdev_prop_multifd_compression, \
                       MultiFDCompression)
#define DEFINE_PROP_NETDEV(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_netdev, NICPeers)
#define DEFINE_PROP_OFF_AUTO_PCIBAR(_n, _s, _f, _d) \
    DEFINE_PROP_SIGNED(_n, _s, _f, _d, qdev_prop_off_auto_pcibar, \
                        OffAutoPCIBAR)
#define DEFINE_PROP_PCIE_LINK_SPEED(_n, _s, _f, _d) \
    DEFINE_PROP_SIGNED(_n, _s, _f, _d, qdev_prop_pcie_link_speed, \
                        PCIExpLinkSpeed)
#define DEFINE_PROP_PCIE_LINK_WIDTH(_n, _s, _f, _d) \
    DEFINE_PROP_SIGNED(_n, _s, _f, _d, qdev_prop_pcie_link_width, \
                        PCIExpLinkWidth)
#define DEFINE_PROP_PCI_DEVFN(_n, _s, _f, _d)                   \
    DEFINE_PROP_SIGNED(_n, _s, _f, _d, qdev_prop_pci_devfn, int32_t)
#define DEFINE_PROP_PCI_HOST_DEVADDR(_n, _s, _f) \
    DEFINE_PROP(_n, _s, _f, qdev_prop_pci_host_devaddr, PCIHostDeviceAddress)
#define DEFINE_PROP_RESERVED_REGION(_n, _s, _f)         \
    DEFINE_PROP(_n, _s, _f, qdev_prop_reserved_region, ReservedRegion)
#define DEFINE_PROP_UUID(_name, _state, _field) \
    DEFINE_PROP(_name, _state, _field, qdev_prop_uuid, QemuUUID, \
                .set_default = true)
#define DEFINE_PROP_UUID_NODEFAULT(_name, _state, _field) \
    DEFINE_PROP(_name, _state, _field, qdev_prop_uuid, QemuUUID)

#define DEFINE_PROP(_name, _state, _field, _prop, _type, ...) {  \
        .name      = (_name),                                    \
        .info      = &(_prop),                                   \
        .offset    = offsetof(_state, _field)                    \
            + type_check(_type, typeof_field(_state, _field)),   \
        __VA_ARGS__                                              \
        }
#define DEFINE_PROP_ARRAY(_name, _state, _field,               \
                          _arrayfield, _arrayprop, _arraytype) \
    DEFINE_PROP((PROP_ARRAY_LEN_PREFIX _name),                 \
                _state, _field, qdev_prop_arraylen, uint32_t,  \
                .set_default = true,                           \
                .defval.u = 0,                                 \
                .arrayinfo = &(_arrayprop),                    \
                .arrayfieldsize = sizeof(_arraytype),          \
                .arrayoffset = offsetof(_state, _arrayfield))
#define DEFINE_PROP_BIT(_name, _state, _field, _bit, _defval)   \
    DEFINE_PROP(_name, _state, _field, qdev_prop_bit, uint32_t, \
                .bitnr       = (_bit),                          \
                .set_default = true,                            \
                .defval.u    = (bool)_defval)
#define DEFINE_PROP_BIT64(_name, _state, _field, _bit, _defval)   \
    DEFINE_PROP(_name, _state, _field, qdev_prop_bit64, uint64_t, \
                .bitnr    = (_bit),                               \
                .set_default = true,                              \
                .defval.u  = (bool)_defval)
#define DEFINE_PROP_BOOL(_name, _state, _field, _defval)     \
    DEFINE_PROP(_name, _state, _field, qdev_prop_bool, bool, \
                .set_default = true,                         \
                .defval.u    = (bool)_defval)
#define DEFINE_PROP_END_OF_LIST()               \
    {}
#define DEFINE_PROP_INT32(_n, _s, _f, _d)                      \
    DEFINE_PROP_SIGNED(_n, _s, _f, _d, qdev_prop_int32, int32_t)
#define DEFINE_PROP_INT64(_n, _s, _f, _d)                      \
    DEFINE_PROP_SIGNED(_n, _s, _f, _d, qdev_prop_int64, int64_t)
#define DEFINE_PROP_LINK(_name, _state, _field, _type, _ptr_type)     \
    DEFINE_PROP(_name, _state, _field, qdev_prop_link, _ptr_type,     \
                .link_type  = _type)
#define DEFINE_PROP_ON_OFF_AUTO(_n, _s, _f, _d) \
    DEFINE_PROP_SIGNED(_n, _s, _f, _d, qdev_prop_on_off_auto, OnOffAuto)
#define DEFINE_PROP_SIGNED(_name, _state, _field, _defval, _prop, _type) \
    DEFINE_PROP(_name, _state, _field, _prop, _type,                     \
                .set_default = true,                                     \
                .defval.i    = (_type)_defval)
#define DEFINE_PROP_SIGNED_NODEFAULT(_name, _state, _field, _prop, _type) \
    DEFINE_PROP(_name, _state, _field, _prop, _type)
#define DEFINE_PROP_SIZE(_n, _s, _f, _d)                       \
    DEFINE_PROP_UNSIGNED(_n, _s, _f, _d, qdev_prop_size, uint64_t)
#define DEFINE_PROP_SIZE32(_n, _s, _f, _d)                       \
    DEFINE_PROP_UNSIGNED(_n, _s, _f, _d, qdev_prop_size32, uint32_t)
#define DEFINE_PROP_STRING(_n, _s, _f)             \
    DEFINE_PROP(_n, _s, _f, qdev_prop_string, char*)
#define DEFINE_PROP_UINT16(_n, _s, _f, _d)                      \
    DEFINE_PROP_UNSIGNED(_n, _s, _f, _d, qdev_prop_uint16, uint16_t)
#define DEFINE_PROP_UINT32(_n, _s, _f, _d)                      \
    DEFINE_PROP_UNSIGNED(_n, _s, _f, _d, qdev_prop_uint32, uint32_t)
#define DEFINE_PROP_UINT64(_n, _s, _f, _d)                      \
    DEFINE_PROP_UNSIGNED(_n, _s, _f, _d, qdev_prop_uint64, uint64_t)
#define DEFINE_PROP_UINT8(_n, _s, _f, _d)                       \
    DEFINE_PROP_UNSIGNED(_n, _s, _f, _d, qdev_prop_uint8, uint8_t)
#define DEFINE_PROP_UNSIGNED(_name, _state, _field, _defval, _prop, _type) \
    DEFINE_PROP(_name, _state, _field, _prop, _type,                       \
                .set_default = true,                                       \
                .defval.u  = (_type)_defval)
#define DEFINE_PROP_UNSIGNED_NODEFAULT(_name, _state, _field, _prop, _type) \
    DEFINE_PROP(_name, _state, _field, _prop, _type)
#define PROP_ARRAY_LEN_PREFIX "len-"


#define QDEV_HOTPLUG_HANDLER_PROPERTY "hotplug-handler"
#define TYPE_BUS "bus"
#define TYPE_DEVICE "device"

#define TYPE_RESETTABLE_INTERFACE "resettable"

#define HOTPLUG_HANDLER(obj) \
     INTERFACE_CHECK(HotplugHandler, (obj), TYPE_HOTPLUG_HANDLER)
#define TYPE_HOTPLUG_HANDLER "hotplug-handler"
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))

#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))
#define DECLARE_BITMAP(name,bits)                  \
        unsigned long name[BITS_TO_LONGS(bits)]
#define small_nbits(nbits)                      \
        ((nbits) <= BITS_PER_LONG)
#define DEFINE_BLOCK_CHS_PROPERTIES(_state, _conf)                      \
    DEFINE_PROP_UINT32("cyls", _state, _conf.cyls, 0),                  \
    DEFINE_PROP_UINT32("heads", _state, _conf.heads, 0),                \
    DEFINE_PROP_UINT32("secs", _state, _conf.secs, 0),                  \
    DEFINE_PROP_UINT32("lcyls", _state, _conf.lcyls, 0),                \
    DEFINE_PROP_UINT32("lheads", _state, _conf.lheads, 0),              \
    DEFINE_PROP_UINT32("lsecs", _state, _conf.lsecs, 0)
#define DEFINE_BLOCK_ERROR_PROPERTIES(_state, _conf)                    \
    DEFINE_PROP_BLOCKDEV_ON_ERROR("rerror", _state, _conf.rerror,       \
                                  BLOCKDEV_ON_ERROR_AUTO),              \
    DEFINE_PROP_BLOCKDEV_ON_ERROR("werror", _state, _conf.werror,       \
                                  BLOCKDEV_ON_ERROR_AUTO)
#define DEFINE_BLOCK_PROPERTIES(_state, _conf)                          \
    DEFINE_PROP_DRIVE("drive", _state, _conf.blk),                      \
    DEFINE_BLOCK_PROPERTIES_BASE(_state, _conf)
#define DEFINE_BLOCK_PROPERTIES_BASE(_state, _conf)                     \
    DEFINE_PROP_ON_OFF_AUTO("backend_defaults", _state,                 \
                            _conf.backend_defaults, ON_OFF_AUTO_AUTO),  \
    DEFINE_PROP_BLOCKSIZE("logical_block_size", _state,                 \
                          _conf.logical_block_size),                    \
    DEFINE_PROP_BLOCKSIZE("physical_block_size", _state,                \
                          _conf.physical_block_size),                   \
    DEFINE_PROP_SIZE32("min_io_size", _state, _conf.min_io_size, 0),    \
    DEFINE_PROP_SIZE32("opt_io_size", _state, _conf.opt_io_size, 0),    \
    DEFINE_PROP_SIZE32("discard_granularity", _state,                   \
                       _conf.discard_granularity, -1),                  \
    DEFINE_PROP_ON_OFF_AUTO("write-cache", _state, _conf.wce,           \
                            ON_OFF_AUTO_AUTO),                          \
    DEFINE_PROP_BOOL("share-rw", _state, _conf.share_rw, false)




#define TYPE_THROTTLE_GROUP "throttle-group"
#define BLOCK_FLAG_LAZY_REFCOUNTS   8

#define BLOCK_OPT_ADAPTER_TYPE      "adapter_type"
#define BLOCK_OPT_BACKING_FILE      "backing_file"
#define BLOCK_OPT_BACKING_FMT       "backing_fmt"
#define BLOCK_OPT_CLUSTER_SIZE      "cluster_size"
#define BLOCK_OPT_COMPAT6           "compat6"
#define BLOCK_OPT_COMPAT_LEVEL      "compat"
#define BLOCK_OPT_COMPRESSION_TYPE  "compression_type"
#define BLOCK_OPT_DATA_FILE         "data_file"
#define BLOCK_OPT_DATA_FILE_RAW     "data_file_raw"
#define BLOCK_OPT_ENCRYPT           "encryption"
#define BLOCK_OPT_ENCRYPT_FORMAT    "encrypt.format"
#define BLOCK_OPT_EXTENT_SIZE_HINT  "extent_size_hint"
#define BLOCK_OPT_EXTL2             "extended_l2"
#define BLOCK_OPT_HWVERSION         "hwversion"
#define BLOCK_OPT_LAZY_REFCOUNTS    "lazy_refcounts"
#define BLOCK_OPT_NOCOW             "nocow"
#define BLOCK_OPT_OBJECT_SIZE       "object_size"
#define BLOCK_OPT_PREALLOC          "preallocation"
#define BLOCK_OPT_REDUNDANCY        "redundancy"
#define BLOCK_OPT_REFCOUNT_BITS     "refcount_bits"
#define BLOCK_OPT_SIZE              "size"
#define BLOCK_OPT_SUBFMT            "subformat"
#define BLOCK_OPT_TABLE_SIZE        "table_size"
#define BLOCK_PROBE_BUF_SIZE        512

#define THROTTLE_VALUE_MAX 1000000000000000LL

#define SNAPSHOT_OPT_BASE       "snapshot."
#define SNAPSHOT_OPT_ID         "snapshot.id"
#define SNAPSHOT_OPT_NAME       "snapshot.name"

#define ABORTED_COMMAND     0x0b
#define ACA_ACTIVE           0x30
#define ACCESS_CONTROL_IN     0x86
#define ACCESS_CONTROL_OUT    0x87
#define ALLOW_MEDIUM_REMOVAL  0x1e
#define ALLOW_OVERWRITE       0x82
#define ATA_PASSTHROUGH_12    0xa1
#define ATA_PASSTHROUGH_16    0x85
#define BLANK_CHECK         0x08
#define BUSY                 0x08
#define CD_FRAMES                     75 
#define CD_FRAMESIZE                2048 
#define CD_MAX_BYTES       (CD_MINS * CD_SECS * CD_FRAMES * CD_FRAMESIZE)
#define CD_MAX_SECTORS     (CD_MAX_BYTES / 512)
#define CD_MINS                       80 
#define CD_SECS                       60 
#define CHANGE_DEFINITION     0x40
#define CHECK_CONDITION      0x02
#define COMMAND_TERMINATED   0x22
#define COMPARE               0x39
#define COMPARE_AND_WRITE     0x89
#define CONDITION_GOOD       0x04
#define COPY                  0x18
#define COPY_ABORTED        0x0a
#define COPY_VERIFY           0x3a
#define DATA_PROTECT        0x07
#define ERASE                 0x19
#define ERASE_12              0xac
#define ERASE_16              0x93
#define EXCHANGE_MEDIUM       0xa6
#define EXTENDED_COPY         0x83
#define EXTENDED_FORM        0x08
#define FORMAT_UNIT           0x04
#define GESN_DEVICE_BUSY              6
#define GESN_EXTERNAL_REQUEST         3
#define GESN_MEDIA                    4
#define GESN_MULTIPLE_HOSTS           5
#define GESN_NO_EVENTS                0
#define GESN_OPERATIONAL_CHANGE       1
#define GESN_POWER_MANAGEMENT         2
#define GET_CONFIGURATION     0x46
#define GET_DATA_BUFFER_STATUS 0x34
#define GET_EVENT_STATUS_NOTIFICATION 0x4a
#define GET_WINDOW            0x25
#define GOOD                 0x00
#define HARDWARE_ERROR      0x04
#define IDENT_DESCR_TGT_DESCR_SIZE 32
#define ILLEGAL_REQUEST     0x05
#define INITIALIZE_ELEMENT_STATUS 0x07
#define INITIALIZE_ELEMENT_STATUS_WITH_RANGE 0x37
#define INQUIRY               0x12
#define INTERMEDIATE_C_GOOD  0x14
#define INTERMEDIATE_GOOD    0x10
#define LOAD_UNLOAD           0x1b
#define LOCATE_10             0x2b
#define LOCATE_16             0x92
#define LOCK_UNLOCK_CACHE     0x36
#define LOG_SELECT            0x4c
#define LOG_SENSE             0x4d
#define LONG_FORM            0x06
#define MAINTENANCE_IN        0xa3
#define MAINTENANCE_OUT       0xa4
#define MECHANISM_STATUS      0xbd
#define MEC_BG_FORMAT_COMPLETED       5 
#define MEC_BG_FORMAT_RESTARTED       6 
#define MEC_EJECT_REQUESTED           1
#define MEC_MEDIA_CHANGED             4 
#define MEC_MEDIA_REMOVAL             3 
#define MEC_NEW_MEDIA                 2
#define MEC_NO_CHANGE                 0
#define MEDIUM_ERROR        0x03
#define MEDIUM_SCAN           0x38
#define MISCOMPARE          0x0e
#define MMC_PROFILE_BD_RE               0x0043
#define MMC_PROFILE_BD_ROM              0x0040
#define MMC_PROFILE_BD_R_RRM            0x0042
#define MMC_PROFILE_BD_R_SRM            0x0041
#define MMC_PROFILE_CD_R                0x0009
#define MMC_PROFILE_CD_ROM              0x0008
#define MMC_PROFILE_CD_RW               0x000A
#define MMC_PROFILE_DVD_DDR             0x0018
#define MMC_PROFILE_DVD_PLUS_R          0x001B
#define MMC_PROFILE_DVD_PLUS_RW         0x001A
#define MMC_PROFILE_DVD_PLUS_RW_DL      0x002A
#define MMC_PROFILE_DVD_PLUS_R_DL       0x002B
#define MMC_PROFILE_DVD_RAM             0x0012
#define MMC_PROFILE_DVD_ROM             0x0010
#define MMC_PROFILE_DVD_RW_DL           0x0017
#define MMC_PROFILE_DVD_RW_RO           0x0013
#define MMC_PROFILE_DVD_RW_SR           0x0014
#define MMC_PROFILE_DVD_R_DL_JR         0x0016
#define MMC_PROFILE_DVD_R_DL_SR         0x0015
#define MMC_PROFILE_DVD_R_SR            0x0011
#define MMC_PROFILE_HDDVD_R             0x0051
#define MMC_PROFILE_HDDVD_RAM           0x0052
#define MMC_PROFILE_HDDVD_ROM           0x0050
#define MMC_PROFILE_HDDVD_RW            0x0053
#define MMC_PROFILE_HDDVD_RW_DL         0x005A
#define MMC_PROFILE_HDDVD_R_DL          0x0058
#define MMC_PROFILE_INVALID             0xFFFF
#define MMC_PROFILE_NONE                0x0000
#define MODE_PAGE_ALLS                        0x3f
#define MODE_PAGE_AUDIO_CTL                   0x0e
#define MODE_PAGE_CACHING                     0x08
#define MODE_PAGE_CAPABILITIES                0x2a
#define MODE_PAGE_CDROM                       0x0d
#define MODE_PAGE_FAULT_FAIL                  0x1c
#define MODE_PAGE_FLEXIBLE_DISK_GEOMETRY      0x05
#define MODE_PAGE_HD_GEOMETRY                 0x04
#define MODE_PAGE_POWER                       0x1a
#define MODE_PAGE_R_W_ERROR                   0x01
#define MODE_PAGE_TO_PROTECT                  0x1d
#define MODE_SELECT           0x15
#define MODE_SELECT_10        0x55
#define MODE_SENSE            0x1a
#define MODE_SENSE_10         0x5a
#define MOVE_MEDIUM           0xa5
#define MS_MEDIA_PRESENT              2
#define MS_TRAY_OPEN                  1
#define NOT_READY           0x02
#define NO_SENSE            0x00
#define OBJECT_POSITION       0x31
#define PERSISTENT_RESERVE_IN 0x5e
#define PERSISTENT_RESERVE_OUT 0x5f
#define POSITION_TO_ELEMENT   0x2b
#define PRE_FETCH             0x34
#define PRE_FETCH_16          0x90
#define READ_10               0x28
#define READ_12               0xa8
#define READ_16               0x88
#define READ_6                0x08
#define READ_BLOCK_LIMITS     0x05
#define READ_BUFFER           0x3c
#define READ_CAPACITY_10      0x25
#define READ_CD               0xbe
#define READ_DEFECT_DATA      0x37
#define READ_DEFECT_DATA_12   0xb7
#define READ_DISC_INFORMATION 0x51
#define READ_DVD_STRUCTURE    0xad
#define READ_ELEMENT_STATUS   0xb8
#define READ_LONG_10          0x3e
#define READ_POSITION         0x34
#define READ_REVERSE          0x0f
#define READ_REVERSE_16       0x81
#define READ_TOC              0x43
#define REASSIGN_BLOCKS       0x07
#define RECEIVE_DIAGNOSTIC    0x1c
#define RECOVERED_ERROR     0x01
#define RECOVER_BUFFERED_DATA 0x14
#define RELEASE               0x17
#define RELEASE_10            0x57
#define REPORT_DENSITY_SUPPORT 0x44
#define REPORT_LUNS           0xa0
#define REQUEST_SENSE         0x03
#define RESERVATION_CONFLICT 0x18
#define RESERVE               0x16
#define RESERVE_10            0x56
#define RESERVE_TRACK         0x53
#define REWIND                0x01
#define SAI_READ_CAPACITY_16  0x10
#define SANITIZE              0x48
#define SCAN                  0x1b

#define SEARCH_EQUAL          0x31
#define SEARCH_EQUAL_12       0xb1
#define SEARCH_HIGH           0x30
#define SEARCH_HIGH_12        0xb0
#define SEARCH_LOW            0x32
#define SEARCH_LOW_12         0xb2
#define SEEK_10               0x2b
#define SEND                  0x2a
#define SEND_CUE_SHEET        0x5d
#define SEND_DIAGNOSTIC       0x1d
#define SEND_DVD_STRUCTURE    0xbf
#define SEND_VOLUME_TAG       0xb6
#define SERVICE_ACTION_IN_12  0xab
#define SERVICE_ACTION_IN_16  0x9e
#define SET_CAPACITY          0x0b
#define SET_CD_SPEED          0xbb
#define SET_LIMITS            0x33
#define SET_READ_AHEAD        0xa7
#define SET_WINDOW            0x24
#define SHORT_FORM_BLOCK_ID  0x00
#define SHORT_FORM_VENDOR_SPECIFIC 0x01
#define SPACE                 0x11
#define SPACE_16              0x91
#define START_STOP            0x1b
#define STATUS_MASK          0x3e
#define SYNCHRONIZE_CACHE     0x35
#define SYNCHRONIZE_CACHE_16  0x91
#define TASK_ABORTED         0x40
#define TASK_SET_FULL        0x28
#define TEST_UNIT_READY       0x00
#define TYPE_DISK           0x00
#define TYPE_ENCLOSURE      0x0d    
#define TYPE_INACTIVE       0x20
#define TYPE_MEDIUM_CHANGER 0x08
#define TYPE_MOD            0x07    
#define TYPE_NOT_PRESENT    0x1f
#define TYPE_NO_LUN         0x7f
#define TYPE_OSD            0x11    
#define TYPE_PRINTER        0x02
#define TYPE_PROCESSOR      0x03    
#define TYPE_RBC            0x0e    
#define TYPE_ROM            0x05
#define TYPE_SCANNER        0x06
#define TYPE_STORAGE_ARRAY  0x0c    
#define TYPE_TAPE           0x01
#define TYPE_WLUN           0x1e    
#define TYPE_WORM           0x04    
#define TYPE_ZBC            0x14    
#define UNIT_ATTENTION      0x06
#define UNMAP                 0x42
#define UPDATE_BLOCK          0x3d
#define VARLENGTH_CDB         0x7f
#define VERIFY_10             0x2f
#define VERIFY_12             0xaf
#define VERIFY_16             0x8f
#define VOLUME_OVERFLOW     0x0d
#define WRITE_10              0x2a
#define WRITE_12              0xaa
#define WRITE_16              0x8a
#define WRITE_6               0x0a
#define WRITE_BUFFER          0x3b
#define WRITE_FILEMARKS       0x10
#define WRITE_FILEMARKS_16    0x80
#define WRITE_LONG_10         0x3f
#define WRITE_LONG_16         0x9f
#define WRITE_SAME_10         0x41
#define WRITE_SAME_16         0x93
#define WRITE_VERIFY_10       0x2e
#define WRITE_VERIFY_12       0xae
#define WRITE_VERIFY_16       0x8e
#define XCOPY_BLK2BLK_SEG_DESC_SIZE 28
#define XCOPY_DESC_OFFSET 16


#define VMSTATE_2DARRAY(_field, _state, _n1, _n2, _version, _info, _type) { \
    .name       = (stringify(_field)),                                      \
    .version_id = (_version),                                               \
    .num        = (_n1) * (_n2),                                            \
    .info       = &(_info),                                                 \
    .size       = sizeof(_type),                                            \
    .flags      = VMS_ARRAY,                                                \
    .offset     = vmstate_offset_2darray(_state, _field, _type, _n1, _n2),  \
}
#define VMSTATE_ARRAY(_field, _state, _num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num        = (_num),                                            \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_ARRAY,                                         \
    .offset     = vmstate_offset_array(_state, _field, _type, _num), \
}
#define VMSTATE_ARRAY_INT32_UNSAFE(_field, _state, _field_num, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_INT32,                                  \
    .offset     = vmstate_offset_varray(_state, _field, _type),      \
}
#define VMSTATE_ARRAY_OF_POINTER(_field, _state, _num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num        = (_num),                                            \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_ARRAY|VMS_ARRAY_OF_POINTER,                    \
    .offset     = vmstate_offset_array(_state, _field, _type, _num), \
}
#define VMSTATE_ARRAY_OF_POINTER_TO_STRUCT(_f, _s, _n, _v, _vmsd, _type) { \
    .name       = (stringify(_f)),                                   \
    .version_id = (_v),                                              \
    .num        = (_n),                                              \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type *),                                    \
    .flags      = VMS_ARRAY|VMS_STRUCT|VMS_ARRAY_OF_POINTER,         \
    .offset     = vmstate_offset_array(_s, _f, _type*, _n),          \
}
#define VMSTATE_ARRAY_TEST(_field, _state, _num, _test, _info, _type) {\
    .name         = (stringify(_field)),                              \
    .field_exists = (_test),                                          \
    .num          = (_num),                                           \
    .info         = &(_info),                                         \
    .size         = sizeof(_type),                                    \
    .flags        = VMS_ARRAY,                                        \
    .offset       = vmstate_offset_array(_state, _field, _type, _num),\
}
#define VMSTATE_BITMAP(_field, _state, _version, _field_size) {      \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .size_offset  = vmstate_offset_value(_state, _field_size, int32_t),\
    .info         = &vmstate_info_bitmap,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER,                         \
    .offset       = offsetof(_state, _field),                        \
}
#define VMSTATE_BOOL(_f, _s)                                          \
    VMSTATE_BOOL_V(_f, _s, 0)
#define VMSTATE_BOOL_ARRAY(_f, _s, _n)                               \
    VMSTATE_BOOL_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_BOOL_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_bool, bool)
#define VMSTATE_BOOL_SUB_ARRAY(_f, _s, _start, _num)                \
    VMSTATE_SUB_ARRAY(_f, _s, _start, _num, 0, vmstate_info_bool, bool)
#define VMSTATE_BOOL_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_bool, bool)
#define VMSTATE_BOOL_V(_f, _s, _v)                                    \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_bool, bool)
#define VMSTATE_BUFFER(_f, _s)                                        \
    VMSTATE_BUFFER_V(_f, _s, 0)
#define VMSTATE_BUFFER_POINTER_UNSAFE(_field, _state, _version, _size) { \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .size       = (_size),                                           \
    .info       = &vmstate_info_buffer,                              \
    .flags      = VMS_BUFFER|VMS_POINTER,                            \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_BUFFER_START_MIDDLE(_f, _s, _start) \
    VMSTATE_BUFFER_START_MIDDLE_V(_f, _s, _start, 0)
#define VMSTATE_BUFFER_START_MIDDLE_V(_f, _s, _start, _v) \
    VMSTATE_STATIC_BUFFER(_f, _s, _v, NULL, _start, sizeof(typeof_field(_s, _f)))
#define VMSTATE_BUFFER_TEST(_f, _s, _test)                            \
    VMSTATE_STATIC_BUFFER(_f, _s, 0, _test, 0, sizeof(typeof_field(_s, _f)))
#define VMSTATE_BUFFER_UNSAFE(_field, _state, _version, _size)        \
    VMSTATE_BUFFER_UNSAFE_INFO(_field, _state, _version, vmstate_info_buffer, _size)
#define VMSTATE_BUFFER_UNSAFE_INFO(_field, _state, _version, _info, _size) \
    VMSTATE_BUFFER_UNSAFE_INFO_TEST(_field, _state, NULL, _version, _info, \
            _size)
#define VMSTATE_BUFFER_UNSAFE_INFO_TEST(_field, _state, _test, _version, _info, _size) { \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .field_exists = (_test),                                         \
    .size       = (_size),                                           \
    .info       = &(_info),                                          \
    .flags      = VMS_BUFFER,                                        \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_BUFFER_V(_f, _s, _v)                                  \
    VMSTATE_STATIC_BUFFER(_f, _s, _v, NULL, 0, sizeof(typeof_field(_s, _f)))
#define VMSTATE_CPUDOUBLE_ARRAY(_f, _s, _n)                           \
    VMSTATE_CPUDOUBLE_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_CPUDOUBLE_ARRAY_V(_f, _s, _n, _v)                     \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_cpudouble, CPU_DoubleU)
#define VMSTATE_END_OF_LIST()                                         \
    {}
#define VMSTATE_GTREE_DIRECT_KEY_V(_field, _state, _version, _vmsd, _val_type) \
{                                                                              \
    .name         = (stringify(_field)),                                       \
    .version_id   = (_version),                                                \
    .vmsd         = (_vmsd),                                                   \
    .info         = &vmstate_info_gtree,                                       \
    .start        = 0,                                                         \
    .size         = sizeof(_val_type),                                         \
    .offset       = offsetof(_state, _field),                                  \
}
#define VMSTATE_GTREE_V(_field, _state, _version, _vmsd,                       \
                        _key_type, _val_type)                                  \
{                                                                              \
    .name         = (stringify(_field)),                                       \
    .version_id   = (_version),                                                \
    .vmsd         = (_vmsd),                                                   \
    .info         = &vmstate_info_gtree,                                       \
    .start        = sizeof(_key_type),                                         \
    .size         = sizeof(_val_type),                                         \
    .offset       = offsetof(_state, _field),                                  \
}
#define  VMSTATE_INSTANCE_ID_ANY  -1
#define VMSTATE_INT16(_f, _s)                                         \
    VMSTATE_INT16_V(_f, _s, 0)
#define VMSTATE_INT16_ARRAY(_f, _s, _n)                               \
    VMSTATE_INT16_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_INT16_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_int16, int16_t)
#define VMSTATE_INT16_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_int16, int16_t)
#define VMSTATE_INT16_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int16, int16_t)
#define VMSTATE_INT32(_f, _s)                                         \
    VMSTATE_INT32_V(_f, _s, 0)
#define VMSTATE_INT32_ARRAY(_f, _s, _n)                               \
    VMSTATE_INT32_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_INT32_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_int32, int32_t)
#define VMSTATE_INT32_EQUAL(_f, _s, _err_hint)                        \
    VMSTATE_SINGLE_FULL(_f, _s, 0, 0,                                 \
                        vmstate_info_int32_equal, int32_t, _err_hint)
#define VMSTATE_INT32_POSITIVE_LE(_f, _s)                             \
    VMSTATE_SINGLE(_f, _s, 0, vmstate_info_int32_le, int32_t)
#define VMSTATE_INT32_TEST(_f, _s, _t)                                  \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_int32, int32_t)
#define VMSTATE_INT32_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int32, int32_t)
#define VMSTATE_INT64(_f, _s)                                         \
    VMSTATE_INT64_V(_f, _s, 0)
#define VMSTATE_INT64_ARRAY(_f, _s, _n)                               \
    VMSTATE_INT64_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_INT64_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_int64, int64_t)
#define VMSTATE_INT64_TEST(_f, _s, _t)                                  \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_int64, int64_t)
#define VMSTATE_INT64_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int64, int64_t)
#define VMSTATE_INT8(_f, _s)                                          \
    VMSTATE_INT8_V(_f, _s, 0)
#define VMSTATE_INT8_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_int8, int8_t)
#define VMSTATE_INT8_V(_f, _s, _v)                                    \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_int8, int8_t)
#define VMSTATE_PARTIAL_BUFFER(_f, _s, _size)                         \
    VMSTATE_STATIC_BUFFER(_f, _s, 0, NULL, 0, _size)
#define VMSTATE_PARTIAL_VBUFFER(_f, _s, _size)                        \
    VMSTATE_VBUFFER(_f, _s, 0, NULL, _size)
#define VMSTATE_PARTIAL_VBUFFER_UINT32(_f, _s, _size)                        \
    VMSTATE_VBUFFER_UINT32(_f, _s, 0, NULL, _size)
#define VMSTATE_POINTER(_field, _state, _version, _info, _type) {    \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_SINGLE|VMS_POINTER,                            \
    .offset     = vmstate_offset_value(_state, _field, _type),       \
}
#define VMSTATE_POINTER_TEST(_field, _state, _test, _info, _type) {  \
    .name       = (stringify(_field)),                               \
    .info       = &(_info),                                          \
    .field_exists = (_test),                                         \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_SINGLE|VMS_POINTER,                            \
    .offset     = vmstate_offset_value(_state, _field, _type),       \
}
#define VMSTATE_QLIST_V(_field, _state, _version, _vmsd, _type, _next)  \
{                                                                        \
    .name         = (stringify(_field)),                                 \
    .version_id   = (_version),                                          \
    .vmsd         = &(_vmsd),                                            \
    .size         = sizeof(_type),                                       \
    .info         = &vmstate_info_qlist,                                 \
    .offset       = offsetof(_state, _field),                            \
    .start        = offsetof(_type, _next),                              \
}
#define VMSTATE_QTAILQ_V(_field, _state, _version, _vmsd, _type, _next)  \
{                                                                        \
    .name         = (stringify(_field)),                                 \
    .version_id   = (_version),                                          \
    .vmsd         = &(_vmsd),                                            \
    .size         = sizeof(_type),                                       \
    .info         = &vmstate_info_qtailq,                                \
    .offset       = offsetof(_state, _field),                            \
    .start        = offsetof(_type, _next),                              \
}
#define VMSTATE_SINGLE(_field, _state, _version, _info, _type)        \
    VMSTATE_SINGLE_TEST(_field, _state, NULL, _version, _info, _type)
#define VMSTATE_SINGLE_FULL(_field, _state, _test, _version, _info,  \
                            _type, _err_hint) {                      \
    .name         = (stringify(_field)),                             \
    .err_hint     = (_err_hint),                                     \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size         = sizeof(_type),                                   \
    .info         = &(_info),                                        \
    .flags        = VMS_SINGLE,                                      \
    .offset       = vmstate_offset_value(_state, _field, _type),     \
}
#define VMSTATE_SINGLE_TEST(_field, _state, _test, _version, _info, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size         = sizeof(_type),                                   \
    .info         = &(_info),                                        \
    .flags        = VMS_SINGLE,                                      \
    .offset       = vmstate_offset_value(_state, _field, _type),     \
}
#define VMSTATE_STATIC_BUFFER(_field, _state, _version, _test, _start, _size) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size         = (_size - _start),                                \
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_BUFFER,                                      \
    .offset       = vmstate_offset_buffer(_state, _field) + _start,  \
}
#define VMSTATE_STRUCT(_field, _state, _version, _vmsd, _type)        \
    VMSTATE_STRUCT_TEST(_field, _state, NULL, _version, _vmsd, _type)
#define VMSTATE_STRUCT_2DARRAY(_field, _state, _n1, _n2, _version,    \
            _vmsd, _type)                                             \
    VMSTATE_STRUCT_2DARRAY_TEST(_field, _state, _n1, _n2, NULL,       \
            _version, _vmsd, _type)
#define VMSTATE_STRUCT_2DARRAY_TEST(_field, _state, _n1, _n2, _test, \
                                    _version, _vmsd, _type) {        \
    .name         = (stringify(_field)),                             \
    .num          = (_n1) * (_n2),                                   \
    .field_exists = (_test),                                         \
    .version_id   = (_version),                                      \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type),                                   \
    .flags        = VMS_STRUCT | VMS_ARRAY,                          \
    .offset       = vmstate_offset_2darray(_state, _field, _type,    \
                                           _n1, _n2),                \
}
#define VMSTATE_STRUCT_ARRAY(_field, _state, _num, _version, _vmsd, _type) \
    VMSTATE_STRUCT_ARRAY_TEST(_field, _state, _num, NULL, _version,   \
            _vmsd, _type)
#define VMSTATE_STRUCT_ARRAY_TEST(_field, _state, _num, _test, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .num          = (_num),                                          \
    .field_exists = (_test),                                         \
    .version_id   = (_version),                                      \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type),                                   \
    .flags        = VMS_STRUCT|VMS_ARRAY,                            \
    .offset       = vmstate_offset_array(_state, _field, _type, _num),\
}
#define VMSTATE_STRUCT_POINTER(_field, _state, _vmsd, _type)          \
    VMSTATE_STRUCT_POINTER_V(_field, _state, 0, _vmsd, _type)
#define VMSTATE_STRUCT_POINTER_TEST(_field, _state, _test, _vmsd, _type)     \
    VMSTATE_STRUCT_POINTER_TEST_V(_field, _state, _test, 0, _vmsd, _type)
#define VMSTATE_STRUCT_POINTER_TEST_V(_field, _state, _test, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                        \
    .field_exists = (_test),                                         \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type *),                                 \
    .flags        = VMS_STRUCT|VMS_POINTER,                          \
    .offset       = vmstate_offset_pointer(_state, _field, _type),   \
}
#define VMSTATE_STRUCT_POINTER_V(_field, _state, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                        \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type *),                                 \
    .flags        = VMS_STRUCT|VMS_POINTER,                          \
    .offset       = vmstate_offset_pointer(_state, _field, _type),   \
}
#define VMSTATE_STRUCT_SUB_ARRAY(_field, _state, _start, _num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                                     \
    .version_id = (_version),                                              \
    .num        = (_num),                                                  \
    .vmsd       = &(_vmsd),                                                \
    .size       = sizeof(_type),                                           \
    .flags      = VMS_STRUCT|VMS_ARRAY,                                    \
    .offset     = vmstate_offset_sub_array(_state, _field, _type, _start), \
}
#define VMSTATE_STRUCT_TEST(_field, _state, _test, _version, _vmsd, _type) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type),                                   \
    .flags        = VMS_STRUCT,                                      \
    .offset       = vmstate_offset_value(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_ALLOC(_field, _state, _field_num, _version, _vmsd, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_VARRAY_INT32|VMS_ALLOC|VMS_POINTER, \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_INT32(_field, _state, _field_num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_VARRAY_INT32,                       \
    .offset     = vmstate_offset_varray(_state, _field, _type),      \
}
#define VMSTATE_STRUCT_VARRAY_POINTER_INT32(_field, _state, _field_num, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .version_id = 0,                                                 \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .size       = sizeof(_type),                                     \
    .vmsd       = &(_vmsd),                                          \
    .flags      = VMS_POINTER | VMS_VARRAY_INT32 | VMS_STRUCT,       \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_POINTER_KNOWN(_field, _state, _num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .num          = (_num),                                          \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_ARRAY|VMS_POINTER,                  \
    .offset     = offsetof(_state, _field),                          \
}
#define VMSTATE_STRUCT_VARRAY_POINTER_UINT16(_field, _state, _field_num, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .version_id = 0,                                                 \
    .num_offset = vmstate_offset_value(_state, _field_num, uint16_t),\
    .size       = sizeof(_type),                                     \
    .vmsd       = &(_vmsd),                                          \
    .flags      = VMS_POINTER | VMS_VARRAY_UINT16 | VMS_STRUCT,      \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_POINTER_UINT32(_field, _state, _field_num, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .version_id = 0,                                                 \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t),\
    .size       = sizeof(_type),                                     \
    .vmsd       = &(_vmsd),                                          \
    .flags      = VMS_POINTER | VMS_VARRAY_INT32 | VMS_STRUCT,       \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_STRUCT_VARRAY_UINT32(_field, _state, _field_num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t), \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_VARRAY_UINT32,                      \
    .offset     = vmstate_offset_varray(_state, _field, _type),      \
}
#define VMSTATE_STRUCT_VARRAY_UINT8(_field, _state, _field_num, _version, _vmsd, _type) { \
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, uint8_t), \
    .version_id = (_version),                                        \
    .vmsd       = &(_vmsd),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_STRUCT|VMS_VARRAY_UINT8,                       \
    .offset     = vmstate_offset_varray(_state, _field, _type),      \
}
#define VMSTATE_SUB_ARRAY(_field, _state, _start, _num, _version, _info, _type) { \
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num        = (_num),                                            \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_ARRAY,                                         \
    .offset     = vmstate_offset_sub_array(_state, _field, _type, _start), \
}
#define VMSTATE_TIMER(_f, _s)                                         \
    VMSTATE_TIMER_V(_f, _s, 0)
#define VMSTATE_TIMER_ARRAY(_f, _s, _n)                              \
    VMSTATE_ARRAY(_f, _s, _n, 0, vmstate_info_timer, QEMUTimer)
#define VMSTATE_TIMER_PTR(_f, _s)                                         \
    VMSTATE_TIMER_PTR_V(_f, _s, 0)
#define VMSTATE_TIMER_PTR_ARRAY(_f, _s, _n)                              \
    VMSTATE_ARRAY_OF_POINTER(_f, _s, _n, 0, vmstate_info_timer, QEMUTimer *)
#define VMSTATE_TIMER_PTR_TEST(_f, _s, _test)                             \
    VMSTATE_POINTER_TEST(_f, _s, _test, vmstate_info_timer, QEMUTimer *)
#define VMSTATE_TIMER_PTR_V(_f, _s, _v)                                   \
    VMSTATE_POINTER(_f, _s, _v, vmstate_info_timer, QEMUTimer *)
#define VMSTATE_TIMER_TEST(_f, _s, _test)                             \
    VMSTATE_SINGLE_TEST(_f, _s, _test, 0, vmstate_info_timer, QEMUTimer)
#define VMSTATE_TIMER_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_timer, QEMUTimer)
#define VMSTATE_U16(_f, _s)                                        \
    VMSTATE_U16_V(_f, _s, 0)
#define VMSTATE_U16_V(_f, _s, _v)                                  \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint16, __u16)
#define VMSTATE_U32(_f, _s)                                        \
    VMSTATE_U32_V(_f, _s, 0)
#define VMSTATE_U32_V(_f, _s, _v)                                  \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint32, __u32)
#define VMSTATE_U64(_f, _s)                                        \
    VMSTATE_U64_V(_f, _s, 0)
#define VMSTATE_U64_V(_f, _s, _v)                                  \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint64, __u64)
#define VMSTATE_U8(_f, _s)                                         \
    VMSTATE_U8_V(_f, _s, 0)
#define VMSTATE_U8_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint8, __u8)
#define VMSTATE_UINT16(_f, _s)                                        \
    VMSTATE_UINT16_V(_f, _s, 0)
#define VMSTATE_UINT16_2DARRAY(_f, _s, _n1, _n2)                      \
    VMSTATE_UINT16_2DARRAY_V(_f, _s, _n1, _n2, 0)
#define VMSTATE_UINT16_2DARRAY_V(_f, _s, _n1, _n2, _v)                \
    VMSTATE_2DARRAY(_f, _s, _n1, _n2, _v, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT16_ARRAY(_f, _s, _n)                               \
    VMSTATE_UINT16_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINT16_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT16_EQUAL(_f, _s, _err_hint)                       \
    VMSTATE_SINGLE_FULL(_f, _s, 0, 0,                                 \
                        vmstate_info_uint16_equal, uint16_t, _err_hint)
#define VMSTATE_UINT16_EQUAL_V(_f, _s, _v, _err_hint)                 \
    VMSTATE_SINGLE_FULL(_f, _s, 0,  _v,                               \
                        vmstate_info_uint16_equal, uint16_t, _err_hint)
#define VMSTATE_UINT16_SUB_ARRAY(_f, _s, _start, _num)                \
    VMSTATE_SUB_ARRAY(_f, _s, _start, _num, 0, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT16_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT16_V(_f, _s, _v)                                  \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint16, uint16_t)
#define VMSTATE_UINT32(_f, _s)                                        \
    VMSTATE_UINT32_V(_f, _s, 0)
#define VMSTATE_UINT32_2DARRAY(_f, _s, _n1, _n2)                      \
    VMSTATE_UINT32_2DARRAY_V(_f, _s, _n1, _n2, 0)
#define VMSTATE_UINT32_2DARRAY_V(_f, _s, _n1, _n2, _v)                \
    VMSTATE_2DARRAY(_f, _s, _n1, _n2, _v, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_ARRAY(_f, _s, _n)                              \
    VMSTATE_UINT32_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINT32_ARRAY_V(_f, _s, _n, _v)                        \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_EQUAL(_f, _s, _err_hint)                       \
    VMSTATE_UINT32_EQUAL_V(_f, _s, 0, _err_hint)
#define VMSTATE_UINT32_EQUAL_V(_f, _s, _v, _err_hint)                 \
    VMSTATE_SINGLE_FULL(_f, _s, 0,  _v,                               \
                        vmstate_info_uint32_equal, uint32_t, _err_hint)
#define VMSTATE_UINT32_SUB_ARRAY(_f, _s, _start, _num)                \
    VMSTATE_SUB_ARRAY(_f, _s, _start, _num, 0, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_TEST(_f, _s, _t)                                  \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT32_V(_f, _s, _v)                                  \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint32, uint32_t)
#define VMSTATE_UINT64(_f, _s)                                        \
    VMSTATE_UINT64_V(_f, _s, 0)
#define VMSTATE_UINT64_2DARRAY(_f, _s, _n1, _n2)                      \
    VMSTATE_UINT64_2DARRAY_V(_f, _s, _n1, _n2, 0)
#define VMSTATE_UINT64_2DARRAY_V(_f, _s, _n1, _n2, _v)                 \
    VMSTATE_2DARRAY(_f, _s, _n1, _n2, _v, vmstate_info_uint64, uint64_t)
#define VMSTATE_UINT64_ARRAY(_f, _s, _n)                              \
    VMSTATE_UINT64_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINT64_ARRAY_V(_f, _s, _n, _v)                        \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_uint64, uint64_t)
#define VMSTATE_UINT64_EQUAL(_f, _s, _err_hint)                       \
    VMSTATE_UINT64_EQUAL_V(_f, _s, 0, _err_hint)
#define VMSTATE_UINT64_EQUAL_V(_f, _s, _v, _err_hint)                 \
    VMSTATE_SINGLE_FULL(_f, _s, 0,  _v,                               \
                        vmstate_info_uint64_equal, uint64_t, _err_hint)
#define VMSTATE_UINT64_SUB_ARRAY(_f, _s, _start, _num)                \
    VMSTATE_SUB_ARRAY(_f, _s, _start, _num, 0, vmstate_info_uint64, uint64_t)
#define VMSTATE_UINT64_TEST(_f, _s, _t)                                  \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_uint64, uint64_t)
#define VMSTATE_UINT64_V(_f, _s, _v)                                  \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint64, uint64_t)
#define VMSTATE_UINT8(_f, _s)                                         \
    VMSTATE_UINT8_V(_f, _s, 0)
#define VMSTATE_UINT8_2DARRAY(_f, _s, _n1, _n2)                       \
    VMSTATE_UINT8_2DARRAY_V(_f, _s, _n1, _n2, 0)
#define VMSTATE_UINT8_2DARRAY_V(_f, _s, _n1, _n2, _v)                 \
    VMSTATE_2DARRAY(_f, _s, _n1, _n2, _v, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8_ARRAY(_f, _s, _n)                               \
    VMSTATE_UINT8_ARRAY_V(_f, _s, _n, 0)
#define VMSTATE_UINT8_ARRAY_V(_f, _s, _n, _v)                         \
    VMSTATE_ARRAY(_f, _s, _n, _v, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8_EQUAL(_f, _s, _err_hint)                        \
    VMSTATE_SINGLE_FULL(_f, _s, 0, 0,                                 \
                        vmstate_info_uint8_equal, uint8_t, _err_hint)
#define VMSTATE_UINT8_SUB_ARRAY(_f, _s, _start, _num)                \
    VMSTATE_SUB_ARRAY(_f, _s, _start, _num, 0, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8_TEST(_f, _s, _t)                               \
    VMSTATE_SINGLE_TEST(_f, _s, _t, 0, vmstate_info_uint8, uint8_t)
#define VMSTATE_UINT8_V(_f, _s, _v)                                   \
    VMSTATE_SINGLE(_f, _s, _v, vmstate_info_uint8, uint8_t)
#define VMSTATE_UNUSED(_size)                                         \
    VMSTATE_UNUSED_V(0, _size)
#define VMSTATE_UNUSED_BUFFER(_test, _version, _size) {              \
    .name         = "unused",                                        \
    .field_exists = (_test),                                         \
    .version_id   = (_version),                                      \
    .size         = (_size),                                         \
    .info         = &vmstate_info_unused_buffer,                     \
    .flags        = VMS_BUFFER,                                      \
}
#define VMSTATE_UNUSED_TEST(_test, _size)                             \
    VMSTATE_UNUSED_BUFFER(_test, 0, _size)
#define VMSTATE_UNUSED_V(_v, _size)                                   \
    VMSTATE_UNUSED_BUFFER(NULL, _v, _size)
#define VMSTATE_UNUSED_VARRAY_UINT32(_state, _test, _version, _field_num, _size) {\
    .name         = "unused",                                        \
    .field_exists = (_test),                                         \
    .num_offset   = vmstate_offset_value(_state, _field_num, uint32_t),\
    .version_id   = (_version),                                      \
    .size         = (_size),                                         \
    .info         = &vmstate_info_unused_buffer,                     \
    .flags        = VMS_VARRAY_UINT32 | VMS_BUFFER,                  \
}
#define VMSTATE_VALIDATE(_name, _test) { \
    .name         = (_name),                                         \
    .field_exists = (_test),                                         \
    .flags        = VMS_ARRAY | VMS_MUST_EXIST,                      \
    .num          = 0,      \
}
#define VMSTATE_VARRAY_INT32(_field, _state, _field_num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num_offset = vmstate_offset_value(_state, _field_num, int32_t), \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_INT32|VMS_POINTER,                      \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_VARRAY_MULTIPLY(_field, _state, _field_num, _multiply, _info, _type) { \
    .name       = (stringify(_field)),                               \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t),\
    .num        = (_multiply),                                       \
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_UINT32|VMS_MULTIPLY_ELEMENTS,           \
    .offset     = vmstate_offset_varray(_state, _field, _type),      \
}
#define VMSTATE_VARRAY_UINT16_ALLOC(_field, _state, _field_num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num_offset = vmstate_offset_value(_state, _field_num, uint16_t),\
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_UINT16 | VMS_POINTER | VMS_ALLOC,       \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_VARRAY_UINT16_UNSAFE(_field, _state, _field_num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num_offset = vmstate_offset_value(_state, _field_num, uint16_t),\
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_UINT16,                                 \
    .offset     = vmstate_offset_varray(_state, _field, _type),      \
}
#define VMSTATE_VARRAY_UINT32(_field, _state, _field_num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t),\
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_UINT32|VMS_POINTER,                     \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_VARRAY_UINT32_ALLOC(_field, _state, _field_num, _version, _info, _type) {\
    .name       = (stringify(_field)),                               \
    .version_id = (_version),                                        \
    .num_offset = vmstate_offset_value(_state, _field_num, uint32_t),\
    .info       = &(_info),                                          \
    .size       = sizeof(_type),                                     \
    .flags      = VMS_VARRAY_UINT32|VMS_POINTER|VMS_ALLOC,           \
    .offset     = vmstate_offset_pointer(_state, _field, _type),     \
}
#define VMSTATE_VBUFFER(_field, _state, _version, _test, _field_size) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size_offset  = vmstate_offset_value(_state, _field_size, int32_t),\
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER,                         \
    .offset       = offsetof(_state, _field),                        \
}
#define VMSTATE_VBUFFER_ALLOC_UINT32(_field, _state, _version,       \
                                     _test, _field_size) {           \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size_offset  = vmstate_offset_value(_state, _field_size, uint32_t),\
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER|VMS_ALLOC,               \
    .offset       = offsetof(_state, _field),                        \
}
#define VMSTATE_VBUFFER_MULTIPLY(_field, _state, _version, _test,    \
                                 _field_size, _multiply) {           \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size_offset  = vmstate_offset_value(_state, _field_size, uint32_t),\
    .size         = (_multiply),                                      \
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER|VMS_MULTIPLY,            \
    .offset       = offsetof(_state, _field),                        \
}
#define VMSTATE_VBUFFER_UINT32(_field, _state, _version, _test, _field_size) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .field_exists = (_test),                                         \
    .size_offset  = vmstate_offset_value(_state, _field_size, uint32_t),\
    .info         = &vmstate_info_buffer,                            \
    .flags        = VMS_VBUFFER|VMS_POINTER,                         \
    .offset       = offsetof(_state, _field),                        \
}
#define VMSTATE_VSTRUCT(_field, _state, _vmsd, _type, _struct_version)\
    VMSTATE_VSTRUCT_TEST(_field, _state, NULL, 0, _vmsd, _type, _struct_version)
#define VMSTATE_VSTRUCT_TEST(_field, _state, _test, _version, _vmsd, _type, _struct_version) { \
    .name         = (stringify(_field)),                             \
    .version_id   = (_version),                                      \
    .struct_version_id = (_struct_version),                          \
    .field_exists = (_test),                                         \
    .vmsd         = &(_vmsd),                                        \
    .size         = sizeof(_type),                                   \
    .flags        = VMS_VSTRUCT,                                     \
    .offset       = vmstate_offset_value(_state, _field, _type),     \
}
#define VMSTATE_VSTRUCT_V(_field, _state, _version, _vmsd, _type, _struct_version) \
    VMSTATE_VSTRUCT_TEST(_field, _state, NULL, _version, _vmsd, _type, \
                         _struct_version)
#define VMSTATE_WITH_TMP(_state, _tmp_type, _vmsd) {                 \
    .name         = "tmp",                                           \
    .size         = sizeof(_tmp_type) +                              \
                    QEMU_BUILD_BUG_ON_ZERO(offsetof(_tmp_type, parent) != 0) + \
                    type_check_pointer(_state,                       \
                        typeof_field(_tmp_type, parent)),            \
    .vmsd         = &(_vmsd),                                        \
    .info         = &vmstate_info_tmp,                               \
}
#define VMS_NULLPTR_MARKER (0x30U) 
#define type_check_2darray(t1,t2,n,m) ((t1(*)[n][m])0 - (t2*)0)
#define type_check_array(t1,t2,n) ((t1(*)[n])0 - (t2*)0)
#define type_check_pointer(t1,t2) ((t1**)0 - (t2*)0)
#define type_check_varray(t1, t2, f)                                 \
    (type_check(t1, typeof_elt_of_field(t2, f))                      \
     + QEMU_BUILD_BUG_ON_ZERO(!QEMU_IS_ARRAY(((t2 *)0)->f)))
#define typeof_elt_of_field(type, field) typeof(((type *)0)->field[0])
#define vmstate_offset_2darray(_state, _field, _type, _n1, _n2)      \
    (offsetof(_state, _field) +                                      \
     type_check_2darray(_type, typeof_field(_state, _field), _n1, _n2))
#define vmstate_offset_array(_state, _field, _type, _num)            \
    (offsetof(_state, _field) +                                      \
     type_check_array(_type, typeof_field(_state, _field), _num))
#define vmstate_offset_buffer(_state, _field)                        \
    vmstate_offset_array(_state, _field, uint8_t,                    \
                         sizeof(typeof_field(_state, _field)))
#define vmstate_offset_pointer(_state, _field, _type)                \
    (offsetof(_state, _field) +                                      \
     type_check_pointer(_type, typeof_field(_state, _field)))
#define vmstate_offset_sub_array(_state, _field, _type, _start)      \
    vmstate_offset_value(_state, _field[_start], _type)
#define vmstate_offset_value(_state, _field, _type)                  \
    (offsetof(_state, _field) +                                      \
     type_check(_type, typeof_field(_state, _field)))
#define vmstate_offset_varray(_state, _field, _type)                 \
    (offsetof(_state, _field) +                                      \
     type_check_varray(_type, _state, _field))
#define TYPE_VMSTATE_IF "vmstate-if"
#define VMSTATE_IF(obj)                             \
    INTERFACE_CHECK(VMStateIf, (obj), TYPE_VMSTATE_IF)


#define qemu_get_sbyte qemu_get_byte
#define qemu_put_sbyte qemu_put_byte
#define DEFAULT_IO_TIMEOUT 30

#define SCSI_SENSE_BUF_SIZE 252
#define SCSI_SENSE_BUF_SIZE_OLD 96
#define TYPE_SCSI_BUS "SCSI"
#define TYPE_SCSI_DEVICE "scsi-device"
#define VMSTATE_SCSI_DEVICE(_field, _state) {                        \
    .name       = (stringify(_field)),                               \
    .size       = sizeof(SCSIDevice),                                \
    .vmsd       = &vmstate_scsi_device,                              \
    .flags      = VMS_STRUCT,                                        \
    .offset     = vmstate_offset_value(_state, _field, SCSIDevice),  \
}
#define SCSI_CMD_BUF_SIZE      16
#define SCSI_INQUIRY_LEN       36
#define SCSI_SENSE_LEN         18
#define SCSI_SENSE_LEN_SCANNER 32

#define SENSE_CODE(x) sense_code_ ## x
#define SG_ERR_DRIVER_SENSE    0x08
#define SG_ERR_DRIVER_TIMEOUT  0x06

#define error_report_once(fmt, ...)                     \
    ({                                                  \
        static bool print_once_;                        \
        error_report_once_cond(&print_once_,            \
                               fmt, ##__VA_ARGS__);     \
    })
#define warn_report_once(fmt, ...)                      \
    ({                                                  \
        static bool print_once_;                        \
        warn_report_once_cond(&print_once_,             \
                              fmt, ##__VA_ARGS__);      \
    })

#define ERRP_GUARD()                                            \
    g_auto(ErrorPropagator) _auto_errp_prop = {.errp = errp};   \
    do {                                                        \
        if (!errp || errp == &error_fatal) {                    \
            errp = &_auto_errp_prop.local_err;                  \
        }                                                       \
    } while (0)
#define error_set(errp, err_class, fmt, ...)                    \
    error_set_internal((errp), "__FILE__", "__LINE__", __func__,    \
                       (err_class), (fmt), ## __VA_ARGS__)
#define error_setg(errp, fmt, ...)                              \
    error_setg_internal((errp), "__FILE__", "__LINE__", __func__,   \
                        (fmt), ## __VA_ARGS__)
#define error_setg_errno(errp, os_error, fmt, ...)                      \
    error_setg_errno_internal((errp), "__FILE__", "__LINE__", __func__,     \
                              (os_error), (fmt), ## __VA_ARGS__)
#define error_setg_file_open(errp, os_errno, filename)                  \
    error_setg_file_open_internal((errp), "__FILE__", "__LINE__", __func__, \
                                  (os_errno), (filename))
#define error_setg_win32(errp, win32_err, fmt, ...)                     \
    error_setg_win32_internal((errp), "__FILE__", "__LINE__", __func__,     \
                              (win32_err), (fmt), ## __VA_ARGS__)
#define EiB     (INT64_C(1) << 60)
#define GiB     (INT64_C(1) << 30)
#define KiB     (INT64_C(1) << 10)
#define MiB     (INT64_C(1) << 20)
#define PiB     (INT64_C(1) << 50)

#define TiB     (INT64_C(1) << 40)
#define ARRAY_SIZE(x) ((sizeof(x) / sizeof((x)[0])) + \
                       QEMU_BUILD_BUG_ON_ZERO(!QEMU_IS_ARRAY(x)))
#define BUS_MCEERR_AO 5
#define BUS_MCEERR_AR 4
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define ECANCELED 4097
#define EMEDIUMTYPE 4098
#define ENOMEDIUM ENODEV
#define ENOTSUP 4096
#define ESHUTDOWN 4099
#define FMT_pid "%ld"
#define HAVE_CHARDEV_PARPORT 1
#define HAVE_CHARDEV_SERIAL 1
# define HOST_LONG_BITS 32
#define IOV_MAX 1024
#define MAP_ANONYMOUS MAP_ANON
#define MAP_FIXED_NOREPLACE 0
#define MAP_NORESERVE 0
#define MAX(a, b)                                       \
    ({                                                  \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b);       \
        _a > _b ? _a : _b;                              \
    })
# define MAX_CONST(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b)                                       \
    ({                                                  \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b);       \
        _a < _b ? _a : _b;                              \
    })
# define MIN_CONST(a, b) ((a) < (b) ? (a) : (b))
#define MIN_NON_ZERO(a, b)                              \
    ({                                                  \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b);       \
        _a == 0 ? _b : (_b == 0 || _b > _a) ? _a : _b;  \
    })
#define O_BINARY 0
#define O_LARGEFILE 0
#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))
#define QEMU_ALIGN_PTR_DOWN(p, n) \
    ((typeof(p))QEMU_ALIGN_DOWN((uintptr_t)(p), (n)))
#define QEMU_ALIGN_PTR_UP(p, n) \
    ((typeof(p))QEMU_ALIGN_UP((uintptr_t)(p), (n)))
#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))
#define QEMU_AUTO_VFREE __attribute__((cleanup(qemu_cleanup_generic_vfree)))
#define QEMU_HW_VERSION "2.5+"
#define QEMU_IS_ALIGNED(n, m) (((n) % (m)) == 0)
#define QEMU_IS_ARRAY(x) (!__builtin_types_compatible_p(typeof(x), \
                                                        typeof(&(x)[0])))
#define QEMU_MADV_DODUMP MADV_DODUMP
#define QEMU_MADV_DONTDUMP MADV_DONTDUMP
#define QEMU_MADV_DONTFORK  MADV_DONTFORK
#define QEMU_MADV_DONTNEED  MADV_DONTNEED
#define QEMU_MADV_HUGEPAGE MADV_HUGEPAGE
#define QEMU_MADV_INVALID -1
#define QEMU_MADV_MERGEABLE MADV_MERGEABLE
#define QEMU_MADV_NOHUGEPAGE MADV_NOHUGEPAGE
#define QEMU_MADV_REMOVE MADV_REMOVE
#define QEMU_MADV_UNMERGEABLE MADV_UNMERGEABLE
#define QEMU_MADV_WILLNEED  MADV_WILLNEED
#define QEMU_MAP_NORESERVE  (1 << 3)
#define QEMU_MAP_READONLY   (1 << 0)
#define QEMU_MAP_SHARED     (1 << 1)
#define QEMU_MAP_SYNC       (1 << 2)

#define QEMU_PTR_IS_ALIGNED(p, n) QEMU_IS_ALIGNED((uintptr_t)(p), (n))
#  define QEMU_VMALLOC_ALIGN (512 * 4096)
#define ROUND_DOWN(n, d) ((n) & -(0 ? (n) : (d)))
#define ROUND_UP(n, d) ROUND_DOWN((n) + (d) - 1, (d))
#define SIGIO SIGPOLL
#define SIZE_MAX ((size_t)-1)
#define TIME_MAX TYPE_MAXIMUM(time_t)
#define TYPE_MAXIMUM(t)                                                \
  ((t) (!TYPE_SIGNED(t)                                                \
        ? (t)-1                                                        \
        : ((((t)1 << (TYPE_WIDTH(t) - 2)) - 1) * 2 + 1)))
#define TYPE_SIGNED(t) (!((t)0 < (t)-1))
#define TYPE_WIDTH(t) (sizeof(t) * CHAR_BIT)
#define WCOREDUMP(status) 0
#define WEXITSTATUS(x) (x)
#define WIFEXITED(x)   1

#define _WIN32_WINNT 0x0600 



#define __USE_MINGW_ANSI_STDIO 1
#define assert(x)  g_assert(x)
#define daemon qemu_fake_daemon_function
#define qemu_timersub timersub
#define system platform_does_not_support_system


#define closesocket(s) close(s)
#define ioctlsocket(s, r, v) ioctl(s, r, v)
#define qemu_gettimeofday(tp) gettimeofday(tp, NULL)
# define EPROTONOSUPPORT EINVAL

#define accept qemu_accept_wrap
#define bind qemu_bind_wrap
#define connect qemu_connect_wrap
#define fsync _commit
# define ftruncate qemu_ftruncate64
#define getpeername qemu_getpeername_wrap
#define getsockname qemu_getsockname_wrap
#define getsockopt qemu_getsockopt_wrap
#define listen qemu_listen_wrap
# define lseek _lseeki64
#define recv qemu_recv_wrap
#define recvfrom qemu_recvfrom_wrap
#define send qemu_send_wrap
#define sendto qemu_sendto_wrap
# define setjmp(env) _setjmp(env, NULL)
#define setsockopt qemu_setsockopt_wrap
#define shutdown qemu_shutdown_wrap
#define sigjmp_buf jmp_buf
#define siglongjmp(env, val) longjmp(env, val)
#define sigsetjmp(env, savemask) setjmp(env)
#define socket qemu_socket_wrap
#define GLIB_VERSION_MAX_ALLOWED GLIB_VERSION_2_56
#define GLIB_VERSION_MIN_REQUIRED GLIB_VERSION_2_56

#define g_test_quick() (!qemu_g_test_slow())
#define g_test_slow() qemu_g_test_slow()
#define g_test_thorough() qemu_g_test_slow()

