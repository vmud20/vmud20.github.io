








#include<sys/time.h>

#include<pthread.h>

#include<fnmatch.h>





#include<sys/resource.h>




#include<stdio.h>






#define CALL_STATE(frame) ((server_state_t *)frame->root->state)
#define INODE_LRU_LIMIT(this)                                                  \
    (((server_conf_t *)(this->private))->config.inode_lru_limit)
#define IS_NOT_ROOT(pathlen) ((pathlen > 2) ? 1 : 0)
#define IS_ROOT_INODE(inode) (inode == inode->table->root)
#define SERVER_CONF(frame)                                                     \
    ((server_conf_t *)XPRT_FROM_FRAME(frame)->this->private)
#define XPRT_FROM_FRAME(frame) ((rpc_transport_t *)CALL_STATE(frame)->xprt)
#define XPRT_FROM_XLATOR(this) ((((server_conf_t *)this->private))->listen)

#define CPD4_REQ_FIELD(v, f) ((v)->compound_req_v2_u.compound_##f##_req)
#define CPD4_RSP_FIELD(v, f) ((v)->compound_rsp_v2_u.compound_##f##_rsp)
#define CPD_REQ_FIELD(v, f) ((v)->compound_req_u.compound_##f##_req)
#define CPD_RSP_FIELD(v, f) ((v)->compound_rsp_u.compound_##f##_rsp)
#define DEFAULT_BLOCK_SIZE 4194304 
#define DEFAULT_VOLUME_FILE_PATH CONFDIR "/glusterfs.vol"
#define GF_MAX_SOCKET_WINDOW_SIZE (1 * GF_UNIT_MB)
#define GF_MIN_SOCKET_WINDOW_SIZE (0)
#define SERVER4_COMMON_RSP_CLEANUP(rsp, fop, i)                                \
    do {                                                                       \
        compound_rsp_v2 *this_rsp = NULL;                                      \
        this_rsp = &rsp->compound_rsp_array.compound_rsp_array_val[i];         \
        gfx_common_rsp *_this_rsp = &CPD4_RSP_FIELD(this_rsp, fop);            \
                                                                               \
        GF_FREE(_this_rsp->xdata.pairs.pairs_val);                             \
    } while (0)
#define SERVER4_FOP_RSP_CLEANUP(rsp, fop, i, rsp_type)                         \
    do {                                                                       \
        compound_rsp_v2 *this_rsp = NULL;                                      \
        this_rsp = &rsp->compound_rsp_array.compound_rsp_array_val[i];         \
        gfx_##rsp_type##_rsp *_this_rsp = &CPD4_RSP_FIELD(this_rsp, fop);      \
                                                                               \
        GF_FREE(_this_rsp->xdata.pairs.pairs_val);                             \
    } while (0)
#define SERVER_COMMON_RSP_CLEANUP(rsp, fop, i)                                 \
    do {                                                                       \
        compound_rsp *this_rsp = NULL;                                         \
        this_rsp = &rsp->compound_rsp_array.compound_rsp_array_val[i];         \
        gf_common_rsp *_this_rsp = &CPD_RSP_FIELD(this_rsp, fop);              \
                                                                               \
        GF_FREE(_this_rsp->xdata.xdata_val);                                   \
    } while (0)
#define SERVER_COMPOUND_FOP_CLEANUP(curr_req, fop)                             \
    do {                                                                       \
        gfs3_##fop##_req *_req = &CPD_REQ_FIELD(curr_req, fop);                \
                                                                               \
        free(_req->xdata.xdata_val);                                           \
    } while (0)
#define SERVER_FOP_RSP_CLEANUP(rsp, fop, i)                                    \
    do {                                                                       \
        compound_rsp *this_rsp = NULL;                                         \
        this_rsp = &rsp->compound_rsp_array.compound_rsp_array_val[i];         \
        gfs3_##fop##_rsp *_this_rsp = &CPD_RSP_FIELD(this_rsp, fop);           \
                                                                               \
        GF_FREE(_this_rsp->xdata.xdata_val);                                   \
    } while (0)


