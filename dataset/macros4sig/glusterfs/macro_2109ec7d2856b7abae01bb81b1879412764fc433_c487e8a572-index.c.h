

#include<syscall.h>

#include<libgen.h>
#include<ftw.h>



#include<signal.h>





#define INDEX_STACK_UNWIND(fop, frame, params...)                              \
    do {                                                                       \
        index_local_t *__local = NULL;                                         \
        if (frame) {                                                           \
            __local = frame->local;                                            \
            frame->local = NULL;                                               \
        }                                                                      \
        STACK_UNWIND_STRICT(fop, frame, params);                               \
        if (__local) {                                                         \
            inode_unref(__local->inode);                                       \
            if (__local->xdata)                                                \
                dict_unref(__local->xdata);                                    \
            mem_put(__local);                                                  \
        }                                                                      \
    } while (0)
#define INDEX_THREAD_STACK_SIZE ((size_t)(1024 * 1024))


