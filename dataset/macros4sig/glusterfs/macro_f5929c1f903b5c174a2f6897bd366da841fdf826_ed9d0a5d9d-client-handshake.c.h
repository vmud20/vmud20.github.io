





#include<pthread.h>











#include<stdint.h>



#define CLIENT4_COMPOUND_FOP_CLEANUP(curr_req, fop)                            \
    do {                                                                       \
        gfx_##fop##_req *_req = &CPD4_REQ_FIELD(curr_req, fop);                \
                                                                               \
        GF_FREE(_req->xdata.pairs.pairs_val);                                  \
    } while (0)
#define CLIENT4_POST_FOP(fop, this_rsp_u, this_args_cbk, params...)            \
    do {                                                                       \
        gfx_common_rsp *_this_rsp = &CPD4_RSP_FIELD(this_rsp_u, fop);          \
        int _op_ret = 0;                                                       \
        int _op_errno = 0;                                                     \
                                                                               \
        _op_ret = _this_rsp->op_ret;                                           \
        _op_errno = gf_error_to_errno(_this_rsp->op_errno);                    \
        args_##fop##_cbk_store(this_args_cbk, _op_ret, _op_errno, params);     \
    } while (0)
#define CLIENT4_POST_FOP_TYPE(fop, rsp_type, this_rsp_u, this_args_cbk,        \
                              params...)                                       \
    do {                                                                       \
        gfx_##rsp_type##_rsp *_this_rsp = &CPD4_RSP_FIELD(this_rsp_u, fop);    \
        int _op_ret = 0;                                                       \
        int _op_errno = 0;                                                     \
                                                                               \
        _op_ret = _this_rsp->op_ret;                                           \
        _op_errno = gf_error_to_errno(_this_rsp->op_errno);                    \
        args_##fop##_cbk_store(this_args_cbk, _op_ret, _op_errno, params);     \
    } while (0)
#define CLIENT4_PRE_FOP(fop, xl, compound_req, op_errno, label, params...)     \
    do {                                                                       \
        gfx_##fop##_req *_req = (gfx_##fop##_req *)compound_req;               \
        int _ret = 0;                                                          \
                                                                               \
        _ret = client_pre_##fop##_v2(xl, _req, params);                        \
        if (_ret < 0) {                                                        \
            op_errno = -ret;                                                   \
            goto label;                                                        \
        }                                                                      \
    } while (0)
#define CLIENT_COMMON_RSP_CLEANUP(rsp, fop, i)                                 \
    do {                                                                       \
        compound_rsp *this_rsp = NULL;                                         \
        this_rsp = &rsp->compound_rsp_array.compound_rsp_array_val[i];         \
        gf_common_rsp *_this_rsp = &CPD_RSP_FIELD(this_rsp, fop);              \
                                                                               \
        free(_this_rsp->xdata.xdata_val);                                      \
    } while (0)
#define CLIENT_COMPOUND_FOP_CLEANUP(curr_req, fop)                             \
    do {                                                                       \
        gfs3_##fop##_req *_req = &CPD_REQ_FIELD(curr_req, fop);                \
                                                                               \
        GF_FREE(_req->xdata.xdata_val);                                        \
    } while (0)
#define CLIENT_DUMP_LOCKS "trusted.glusterfs.clientlk-dump"
#define CLIENT_FOP_RSP_CLEANUP(rsp, fop, i)                                    \
    do {                                                                       \
        compound_rsp *this_rsp = NULL;                                         \
        this_rsp = &rsp->compound_rsp_array.compound_rsp_array_val[i];         \
        gfs3_##fop##_rsp *_this_rsp = &CPD_RSP_FIELD(this_rsp, fop);           \
                                                                               \
        free(_this_rsp->xdata.xdata_val);                                      \
    } while (0)
#define CLIENT_GET_REMOTE_FD(xl, fd, flags, remote_fd, op_errno, label)        \
    do {                                                                       \
        int _ret = 0;                                                          \
        _ret = client_get_remote_fd(xl, fd, flags, &remote_fd);                \
        if (_ret < 0) {                                                        \
            op_errno = errno;                                                  \
            goto label;                                                        \
        }                                                                      \
        if (remote_fd == -1) {                                                 \
            gf_msg(xl->name, GF_LOG_WARNING, EBADFD, PC_MSG_BAD_FD,            \
                   " (%s) "                                                    \
                   "remote_fd is -1. EBADFD",                                  \
                   uuid_utoa(fd->inode->gfid));                                \
            op_errno = EBADFD;                                                 \
            goto label;                                                        \
        }                                                                      \
    } while (0)
#define CLIENT_POST_FOP(fop, this_rsp_u, this_args_cbk, params...)             \
    do {                                                                       \
        gf_common_rsp *_this_rsp = &CPD_RSP_FIELD(this_rsp_u, fop);            \
        int _op_ret = 0;                                                       \
        int _op_errno = 0;                                                     \
                                                                               \
        _op_ret = _this_rsp->op_ret;                                           \
        _op_errno = gf_error_to_errno(_this_rsp->op_errno);                    \
        args_##fop##_cbk_store(this_args_cbk, _op_ret, _op_errno, params);     \
    } while (0)
#define CLIENT_POST_FOP_TYPE(fop, this_rsp_u, this_args_cbk, params...)        \
    do {                                                                       \
        gfs3_##fop##_rsp *_this_rsp = &CPD_RSP_FIELD(this_rsp_u, fop);         \
        int _op_ret = 0;                                                       \
        int _op_errno = 0;                                                     \
                                                                               \
        _op_ret = _this_rsp->op_ret;                                           \
        _op_errno = gf_error_to_errno(_this_rsp->op_errno);                    \
        args_##fop##_cbk_store(this_args_cbk, _op_ret, _op_errno, params);     \
    } while (0)
#define CLIENT_PRE_FOP(fop, xl, compound_req, op_errno, label, params...)      \
    do {                                                                       \
        gfs3_##fop##_req *_req = (gfs3_##fop##_req *)compound_req;             \
        int _ret = 0;                                                          \
                                                                               \
        _ret = client_pre_##fop(xl, _req, params);                             \
        if (_ret < 0) {                                                        \
            op_errno = -ret;                                                   \
            goto label;                                                        \
        }                                                                      \
    } while (0)
#define CLIENT_STACK_UNWIND(op, frame, params...)                              \
    do {                                                                       \
        if (!frame)                                                            \
            break;                                                             \
        clnt_local_t *__local = frame->local;                                  \
        frame->local = NULL;                                                   \
        STACK_UNWIND_STRICT(op, frame, params);                                \
        client_local_wipe(__local);                                            \
    } while (0)
#define CPD4_REQ_FIELD(v, f) ((v)->compound_req_v2_u.compound_##f##_req)
#define CPD4_RSP_FIELD(v, f) ((v)->compound_rsp_v2_u.compound_##f##_rsp)
#define CPD_REQ_FIELD(v, f) (v)->compound_req_u.compound_##f##_req
#define CPD_RSP_FIELD(v, f) (v)->compound_rsp_u.compound_##f##_rsp
#define GF_MAX_SOCKET_WINDOW_SIZE (1 * GF_UNIT_MB)
#define GF_MIN_SOCKET_WINDOW_SIZE (0)


