#include<sys/poll.h>
#include<sys/unistd.h>

#include<sys/cdefs.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<sys/param.h>
#include<sys/stat.h>


#include<sys/socket.h>
#include<rpc/pmap_prot.h>
#include<errno.h>
#include<sys/un.h>


#include<rpc/xdr.h>
#include<syslog.h>
#include<rpc/types.h>

#define alloca(sz) __builtin_alloca(sz)
#define MB_CUR_MAX_L(x) (___mb_cur_max_l(x))







#define __rpcb_get_dg_xidp(x)	(&((struct svc_dg_data *)(x)->xp_p2)->su_xid)




#define RPC_SVC_CONNMAXREC_GET  1
#define RPC_SVC_CONNMAXREC_SET  0	
#define SVCAUTH_UNWRAP(auth, xdrs, xfunc, xwhere)	\
	((auth)->svc_ah_ops->svc_ah_unwrap(auth, xdrs, xfunc, xwhere))
#define SVCAUTH_WRAP(auth, xdrs, xfunc, xwhere)		\
	((auth)->svc_ah_ops->svc_ah_wrap(auth, xdrs, xfunc, xwhere))
#define SVC_AUTH(xprt)					\
	(SVC_EXT(xprt)->xp_auth)
#define SVC_CONTROL(xprt, rq, in)			\
	(*(xprt)->xp_ops2->xp_control)((xprt), (rq), (in))
#define SVC_DESTROY(xprt)				\
	(*(xprt)->xp_ops->xp_destroy)(xprt)
#define SVC_EXT(xprt)					\
	((SVCXPRT_EXT *) xprt->xp_p3)
#define SVC_FREEARGS(xprt, xargs, argsp)		\
	(*(xprt)->xp_ops->xp_freeargs)((xprt), (xargs), (argsp))
#define SVC_GETARGS(xprt, xargs, argsp)			\
	(*(xprt)->xp_ops->xp_getargs)((xprt), (xargs), (argsp))
#define SVC_RECV(xprt, msg)				\
	(*(xprt)->xp_ops->xp_recv)((xprt), (msg))
#define SVC_REPLY(xprt, msg)				\
	(*(xprt)->xp_ops->xp_reply) ((xprt), (msg))
#define SVC_STAT(xprt)					\
	(*(xprt)->xp_ops->xp_stat)(xprt)

#define svc_destroy(xprt)				\
	(*(xprt)->xp_ops->xp_destroy)(xprt)
#define svc_fds svc_fdset.fds_bits[0]	
#define svc_freeargs(xprt, xargs, argsp)		\
	(*(xprt)->xp_ops->xp_freeargs)((xprt), (xargs), (argsp))
#define svc_getargs(xprt, xargs, argsp)			\
	(*(xprt)->xp_ops->xp_getargs)((xprt), (xargs), (argsp))
#define svc_getrpccaller(x) (&(x)->xp_rtaddr)
#define svc_recv(xprt, msg)				\
	(*(xprt)->xp_ops->xp_recv)((xprt), (msg))
#define svc_reply(xprt, msg)				\
	(*(xprt)->xp_ops->xp_reply) ((xprt), (msg))
#define svc_stat(xprt)					\
	(*(xprt)->xp_ops->xp_stat)(xprt)

#define svc_getcaller(x) (&(x)->xp_raddr)

#define MAX_MACHINE_NAME 255
#define NGRPS 16

#define authsys_parms authunix_parms

#define CLGET_RETRY_TIMEOUT 5   
#define CLGET_XID 		10	
#define CLSET_RETRY_TIMEOUT 4   
#define IS_UNRECOVERABLE_RPC(s) (((s) == RPC_AUTHERROR) || \
	((s) == RPC_CANTENCODEARGS) || \
	((s) == RPC_CANTDECODERES) || \
	((s) == RPC_VERSMISMATCH) || \
	((s) == RPC_PROCUNAVAIL) || \
	((s) == RPC_PROGUNAVAIL) || \
	((s) == RPC_PROGVERSMISMATCH) || \
	((s) == RPC_CANTDECODEARGS))
#define NULLPROC ((rpcproc_t)0)
#define RPCB_MULTICAST_ADDR "ff02::202"
#define RPCSMALLMSGSIZE 400	

#define UDPMSGSIZE      8800      

#define AUTH_DESTROY(auth)		\
		((*((auth)->ah_ops->ah_destroy))(auth))
#define AUTH_MARSHALL(auth, xdrs)	\
		((*((auth)->ah_ops->ah_marshal))(auth, xdrs))
#define AUTH_NEXTVERF(auth)		\
		((*((auth)->ah_ops->ah_nextverf))(auth))
#define AUTH_REFRESH(auth, msg)		\
		((*((auth)->ah_ops->ah_refresh))(auth, msg))
#define AUTH_VALIDATE(auth, verfp)	\
		((*((auth)->ah_ops->ah_validate))((auth), verfp))

#define auth_destroy(auth)		\
		((*((auth)->ah_ops->ah_destroy))(auth))
#define auth_marshall(auth, xdrs)	\
		((*((auth)->ah_ops->ah_marshal))(auth, xdrs))
#define auth_nextverf(auth)		\
		((*((auth)->ah_ops->ah_nextverf))(auth))
#define auth_refresh(auth, msg)		\
		((*((auth)->ah_ops->ah_refresh))(auth, msg))
#define auth_validate(auth, verfp)	\
		((*((auth)->ah_ops->ah_validate))((auth), verfp))
#define authsys_create(c,i1,i2,i3,ip) authunix_create((c),(i1),(i2),(i3),(ip))
#define authsys_create_default() authunix_create_default()
#define IXDR_GET_BOOL(buf)		((bool_t)IXDR_GET_LONG(buf))
#define IXDR_GET_ENUM(buf, t)		((t)IXDR_GET_LONG(buf))
#define IXDR_GET_INT32(buf)		((int32_t)__ntohl((u_int32_t)*(buf)++))
#define IXDR_GET_LONG(buf)		((long)__ntohl((u_int32_t)*(buf)++))
#define IXDR_GET_SHORT(buf)		((short)IXDR_GET_LONG(buf))
#define IXDR_GET_U_INT32(buf)		((u_int32_t)IXDR_GET_INT32(buf))
#define IXDR_GET_U_LONG(buf)		((u_long)IXDR_GET_LONG(buf))
#define IXDR_GET_U_SHORT(buf)		((u_short)IXDR_GET_LONG(buf))
#define IXDR_PUT_BOOL(buf, v)		IXDR_PUT_LONG((buf), (v))
#define IXDR_PUT_ENUM(buf, v)		IXDR_PUT_LONG((buf), (v))
#define IXDR_PUT_INT32(buf, v)		(*(buf)++ =(int32_t)__htonl((u_int32_t)v))
#define IXDR_PUT_LONG(buf, v)		(*(buf)++ =(int32_t)__htonl((u_int32_t)v))
#define IXDR_PUT_SHORT(buf, v)		IXDR_PUT_LONG((buf), (v))
#define IXDR_PUT_U_INT32(buf, v)	IXDR_PUT_INT32((buf), ((int32_t)(v)))
#define IXDR_PUT_U_LONG(buf, v)		IXDR_PUT_LONG((buf), (v))
#define IXDR_PUT_U_SHORT(buf, v)	IXDR_PUT_LONG((buf), (v))
#define MAX_NETOBJ_SZ 1024
#define NULL_xdrproc_t ((xdrproc_t)0)
#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
		    * BYTES_PER_XDR_UNIT)
#define XDR_CONTROL(xdrs, req, op)			\
	if ((xdrs)->x_ops->x_control)			\
		(*(xdrs)->x_ops->x_control)(xdrs, req, op)
#define XDR_GETBYTES(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)
#define XDR_GETINT32(xdrs, int32p)	xdr_getint32(xdrs, int32p)
#define XDR_GETLONG(xdrs, longp)			\
	(*(xdrs)->x_ops->x_getlong)(xdrs, longp)
#define XDR_GETPOS(xdrs)				\
	(*(xdrs)->x_ops->x_getpostn)(xdrs)
#define XDR_PUTBYTES(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)
#define XDR_PUTINT32(xdrs, int32p)	xdr_putint32(xdrs, int32p)
#define XDR_PUTLONG(xdrs, longp)			\
	(*(xdrs)->x_ops->x_putlong)(xdrs, longp)
#define XDR_SETPOS(xdrs, pos)				\
	(*(xdrs)->x_ops->x_setpostn)(xdrs, pos)

#define xdr_control(xdrs, req, op) XDR_CONTROL(xdrs, req, op)
#define xdr_getbytes(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)
#define xdr_getlong(xdrs, longp)			\
	(*(xdrs)->x_ops->x_getlong)(xdrs, longp)
#define xdr_getpos(xdrs)				\
	(*(xdrs)->x_ops->x_getpostn)(xdrs)
#define xdr_putbytes(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)
#define xdr_putlong(xdrs, longp)			\
	(*(xdrs)->x_ops->x_putlong)(xdrs, longp)
#define xdr_rpcport(xdrs, portp) xdr_u_int32(xdrs, portp)
#define xdr_rpcproc(xdrs, procp) xdr_u_int32(xdrs, procp)
#define xdr_rpcprog(xdrs, progp) xdr_u_int32(xdrs, progp)
#define xdr_rpcprot(xdrs, protp) xdr_u_int32(xdrs, protp)
#define xdr_rpcvers(xdrs, versp) xdr_u_int32(xdrs, versp)
#define xdr_setpos(xdrs, pos)				\
	(*(xdrs)->x_ops->x_setpostn)(xdrs, pos)
