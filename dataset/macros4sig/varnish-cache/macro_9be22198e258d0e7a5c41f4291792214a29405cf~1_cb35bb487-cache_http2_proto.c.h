#include<string.h>
#include<stdio.h>
#include<limits.h>
#include<sys/socket.h>


#include<unistd.h>
#include<stdlib.h>



#include<stdint.h>

#define VTIM_FORMAT_SIZE 30
#define VTCP_Assert(a) assert(VTCP_Check(a))

#define HSH_RUSH_POLICY -1
#define hoh_head _u.n.u_n_hoh_head
#define hoh_list _u.n.u_n_hoh_list
#define ASSERT_RXTHR(h2) do {assert(h2->rxthr == pthread_self());} while(0)

#define H2EC1(U,v,d) extern const struct h2_error_s H2CE_##U[1];
#define H2EC2(U,v,d) extern const struct h2_error_s H2SE_##U[1];
#define H2EC3(U,v,d) H2EC1(U,v,d) H2EC2(U,v,d)
#define H2_ERROR(NAME, val, sc, desc) H2EC##sc(NAME, val, desc)
#define H2_FRAME(l,U,...) extern const struct h2_frame_s H2_F_##U[1];
#define H2_FRAME_FLAGS(l,u,v)   extern const uint8_t H2FF_##u;
#define H2_SETTING(U,...) extern const struct h2_setting_s H2_SET_##U[1];
#define H2_STREAM(U,s,d) H2_S_##U,
#define VHD_RET(NAME, VAL, DESC)		\
	VHD_##NAME = VAL,
#define VHT_ENTRY_SIZE 32U
#define DSL(debug_bit, id, ...)					\
	do {							\
		if (DO_DEBUG(debug_bit))			\
			VSL(SLT_Debug, (id), __VA_ARGS__);	\
	} while (0)
#define EXP_COPY(to,fm)							\
	do {								\
		(to)->t_origin = (fm)->t_origin;			\
		(to)->ttl = (fm)->ttl;					\
		(to)->grace = (fm)->grace;				\
		(to)->keep = (fm)->keep;				\
	} while (0)
#define EXP_Dttl(req, oc) (oc->ttl - (req->t_req - oc->t_origin))
#define EXP_WHEN(to)							\
	((to)->t_origin + (to)->ttl + (to)->grace + (to)->keep)
#define EXP_ZERO(xx)							\
	do {								\
		(xx)->t_origin = 0.0;					\
		(xx)->ttl = 0.0;					\
		(xx)->grace = 0.0;					\
		(xx)->keep = 0.0;					\
	} while (0)
#define HTC_STATUS(e, n, s, l) HTC_S_ ## e = n,
#define OEV_MASK (OEV_INSERT|OEV_BANCHG|OEV_TTLCHG|OEV_EXPIRE)
#define SESS_ATTR(UP, low, typ, len)					\
	int SES_Set_##low(const struct sess *sp, const typ *src);	\
	int SES_Reserve_##low(struct sess *sp, typ **dst);
#define VCL_MET_MAC(l,u,t,b) \
    void VCL_##l##_method(struct vcl *, struct worker *, struct req *, \
	struct busyobj *bo, void *specific);

#define DEBUG_BIT(U, l, d) DBG_##U,
#define FEATURE_BIT(U, l, d, ld) FEATURE_##U,
#define PARAM(nm, ty, mi, ma, de, un, fl, st, lt, fn) ptyp_##ty nm;
  #define XYZZY DELAYED_EFFECT
#define VRE_ERROR_NOMATCH         (-1)


#define		 VSB_new_auto()				\
	VSB_new(NULL, NULL, 0, VSB_AUTOEXTEND)
