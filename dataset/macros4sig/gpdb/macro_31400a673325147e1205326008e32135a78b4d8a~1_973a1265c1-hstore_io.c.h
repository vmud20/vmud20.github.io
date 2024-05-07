




#include<ctype.h>







#define ARRPTR(x)		( (HEntry*) ( (HStore*)(x) + 1 ) )
#define CALCDATASIZE(x, lenstr) ( (x) * 2 * sizeof(HEntry) + HSHRDSIZE + (lenstr) )
#define DatumGetHStoreP(d) hstoreUpgrade(d)
#define HENTRY_ISFIRST 0x80000000
#define HENTRY_ISNULL  0x40000000
#define HENTRY_POSMASK 0x3FFFFFFF
#define HSE_ENDPOS(he_) ((he_).entry & HENTRY_POSMASK)
#define HSE_ISFIRST(he_) (((he_).entry & HENTRY_ISFIRST) != 0)
#define HSE_ISNULL(he_) (((he_).entry & HENTRY_ISNULL) != 0)
#define HSE_LEN(he_) (HSE_ISFIRST(he_)	\
					  ? HSE_ENDPOS(he_) \
					  : HSE_ENDPOS(he_) - HSE_ENDPOS((&(he_))[-1]))
#define HSE_OFF(he_) (HSE_ISFIRST(he_) ? 0 : HSE_ENDPOS((&(he_))[-1]))
#define HSTORE_MAX_KEY_LEN 0x3FFFFFFF
#define HSTORE_MAX_VALUE_LEN 0x3FFFFFFF
#define HSTORE_POLLUTE(newname_,oldname_) \
	PG_FUNCTION_INFO_V1(oldname_);		  \
	Datum oldname_(PG_FUNCTION_ARGS);	  \
	Datum newname_(PG_FUNCTION_ARGS);	  \
	Datum oldname_(PG_FUNCTION_ARGS) { return newname_(fcinfo); } \
	extern int no_such_variable
#define HSTORE_POLLUTE_NAMESPACE 1
#define HS_ADDITEM(dent_,dbuf_,dptr_,pair_)								\
	do {																\
		memcpy((dptr_), (pair_).key, (pair_).keylen);					\
		(dptr_) += (pair_).keylen;										\
		(dent_)++->entry = ((dptr_) - (dbuf_)) & HENTRY_POSMASK;		\
		if ((pair_).isnull)												\
			(dent_)++->entry = ((((dptr_) - (dbuf_)) & HENTRY_POSMASK)	\
								 | HENTRY_ISNULL);						\
		else															\
		{																\
			memcpy((dptr_), (pair_).val, (pair_).vallen);				\
			(dptr_) += (pair_).vallen;									\
			(dent_)++->entry = ((dptr_) - (dbuf_)) & HENTRY_POSMASK;	\
		}																\
	} while (0)
#define HS_COPYITEM(dent_,dbuf_,dptr_,sptr_,klen_,vlen_,vnull_)			\
	do {																\
		memcpy((dptr_), (sptr_), (klen_)+(vlen_));						\
		(dptr_) += (klen_)+(vlen_);										\
		(dent_)++->entry = ((dptr_) - (dbuf_) - (vlen_)) & HENTRY_POSMASK; \
		(dent_)++->entry = ((((dptr_) - (dbuf_)) & HENTRY_POSMASK)		\
							 | ((vnull_) ? HENTRY_ISNULL : 0));			\
	} while(0)
#define HS_COUNT(hsp_) ((hsp_)->size_ & 0x0FFFFFFF)
#define HS_FINALIZE(hsp_,count_,buf_,ptr_)							\
	do {															\
		int buflen = (ptr_) - (buf_);								\
		if ((count_))												\
			ARRPTR(hsp_)[0].entry |= HENTRY_ISFIRST;				\
		if ((count_) != HS_COUNT((hsp_)))							\
		{															\
			HS_SETCOUNT((hsp_),(count_));							\
			memmove(STRPTR(hsp_), (buf_), buflen);					\
		}															\
		SET_VARSIZE((hsp_), CALCDATASIZE((count_), buflen));		\
	} while (0)
#define HS_FIXSIZE(hsp_,count_)											\
	do {																\
		int bl = (count_) ? HSE_ENDPOS(ARRPTR(hsp_)[2*(count_)-1]) : 0; \
		SET_VARSIZE((hsp_), CALCDATASIZE((count_),bl));					\
	} while (0)
#define HS_FLAG_NEWVERSION 0x80000000
#define HS_KEY(arr_,str_,i_) ((str_) + HSE_OFF((arr_)[2*(i_)]))
#define HS_KEYLEN(arr_,i_) (HSE_LEN((arr_)[2*(i_)]))
#define HS_SETCOUNT(hsp_,c_) ((hsp_)->size_ = (c_) | HS_FLAG_NEWVERSION)
#define HS_VAL(arr_,str_,i_) ((str_) + HSE_OFF((arr_)[2*(i_)+1]))
#define HS_VALISNULL(arr_,i_) (HSE_ISNULL((arr_)[2*(i_)+1]))
#define HS_VALLEN(arr_,i_) (HSE_LEN((arr_)[2*(i_)+1]))
#define HStoreOldContainsStrategyNumber 13		
#define PG_GETARG_HS(x) DatumGetHStoreP(PG_GETARG_DATUM(x))
#define STRPTR(x)		( (char*)(ARRPTR(x) + HS_COUNT((HStore*)(x)) * 2) )

