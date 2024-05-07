
#include<string.h>
#include<stdbool.h>


#include<stdio.h>
#include<stdarg.h>

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

#define COMPILER_ATTR(...) __attribute__((__VA_ARGS__))
#define MAYBE_UNUSED COMPILER_ATTR(unused)
#define SAFE_FREE(S) if((S) != NULL) {free((void*) (S)); (S)=NULL;}
#define SIZE_OF_ARY(ary) (sizeof(ary) / sizeof(ary[0]))
#define TPM2_ERROR_FORMAT "%s%s (0x%08x)"
#define TPM2_ERROR_TEXT(r) "Error", "Code", r
#define UNUSED(x) (void)(x)
#define base_rc(r) (r & ~TSS2_RC_LAYER_MASK)
#define goto_error(r,v,msg,label, ...)              \
    { r = v;  \
      LOG_ERROR(TPM2_ERROR_FORMAT " " msg, TPM2_ERROR_TEXT(r), ## __VA_ARGS__); \
      goto label; \
    }
#define goto_if_error(r,msg,label) \
    if (r != TSS2_RC_SUCCESS) { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        goto label;  \
    }
#define goto_if_null(p,msg,ec,label) \
    if ((p) == NULL) { \
        LOG_ERROR("%s ", (msg)); \
        r = (ec); \
        goto label;  \
    }
#define goto_state_if_error(r,s,msg,label) \
    if (r != TSS2_RC_SUCCESS) { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        esysContext->state = s; \
        goto label;  \
    }
#define number_rc(r) (r & ~TPM2_RC_N_MASK)
#define rc_layer(r) (r & TSS2_RC_LAYER_MASK)
#define return_error(r,msg) \
    { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        return r;  \
    }
#define return_if_error(r,msg) \
    if (r != TSS2_RC_SUCCESS) { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        return r;  \
    }
#define return_if_notnull(p,msg,ec) \
    if (p != NULL) { \
        LOG_ERROR("%s ", msg); \
        return ec; \
    }
#define return_if_null(p,msg,ec) \
    if (p == NULL) { \
        LOG_ERROR("%s ", msg); \
        return ec; \
    }
#define return_state_if_error(r,s,msg)      \
    if (r != TSS2_RC_SUCCESS) { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        esysContext->state = s; \
        return r;  \
    }
#define set_return_code(r_max, r, msg) \
    if (r != TSS2_RC_SUCCESS) { \
        LOG_ERROR("%s " TPM2_ERROR_FORMAT, msg, TPM2_ERROR_TEXT(r)); \
        r_max = r; \
    }
