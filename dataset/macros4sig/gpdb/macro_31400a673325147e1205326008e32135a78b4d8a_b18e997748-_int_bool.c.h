




#define ARRISEMPTY(x)  (ARRNELEMS(x) == 0)
#define ARRNELEMS(x)  ArrayGetNItems(ARR_NDIM(x), ARR_DIMS(x))
#define ARRPTR(x)  ( (int32 *) ARR_DATA_PTR(x) )
#define CALCGTSIZE(flag) ( GTHDRSIZE+(((flag) & ALLISTRUE) ? 0 : SIGLEN) )
#define CHECKARRVALID(x) \
	do { \
		if (ARR_HASNULL(x) && array_contains_nulls(x)) \
			ereport(ERROR, \
					(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), \
					 errmsg("array must not contain nulls"))); \
	} while(0)
#define CLRBIT(x,i)   GETBYTE(x,i) &= ~( 0x01 << ( (i) % BITS_PER_BYTE ) )
#define COMPUTESIZE(size)	( HDRSIZEQT + (size) * sizeof(ITEM) )
#define DatumGetQueryTypeP(X)		  ((QUERYTYPE *) PG_DETOAST_DATUM(X))
#define DatumGetQueryTypePCopy(X)	  ((QUERYTYPE *) PG_DETOAST_DATUM_COPY(X))
#define GETBIT(x,i) ( (GETBYTE(x,i) >> ( (i) % BITS_PER_BYTE )) & 0x01 )
#define GETBITBYTE(x,i) ( (*((char*)(x)) >> (i)) & 0x01 )
#define GETBYTE(x,i) ( *( (BITVECP)(x) + (int)( (i) / BITS_PER_BYTE ) ) )
#define GETQUERY(x)  ( (x)->items )
#define GETSIGN(x)		( (BITVECP)( (char*)x+GTHDRSIZE ) )
#define HASH(sign, val) SETBIT((sign), HASHVAL(val))
#define HASHVAL(val) (((unsigned int)(val)) % SIGLENBIT)
#define ISALLTRUE(x)	( ((GISTTYPE*)x)->flag & ALLISTRUE )
#define LOOPBYTE \
			for(i=0;i<SIGLEN;i++)
#define MAXNUMRANGE 100
#define PG_GETARG_QUERYTYPE_P(n)	  DatumGetQueryTypeP(PG_GETARG_DATUM(n))
#define PG_GETARG_QUERYTYPE_P_COPY(n) DatumGetQueryTypePCopy(PG_GETARG_DATUM(n))
#define PREPAREARR(x) \
	do { \
		int		_nelems_ = ARRNELEMS(x); \
		if (_nelems_ > 1) \
			if (isort(ARRPTR(x), _nelems_)) \
				(x) = _int_unique(x); \
	} while(0)
#define QSORT(a, direction) \
	do { \
		int		_nelems_ = ARRNELEMS(a); \
		if (_nelems_ > 1) \
			qsort((void*) ARRPTR(a), _nelems_, sizeof(int32), \
				  (direction) ? compASC : compDESC ); \
	} while(0)
#define SETBIT(x,i)   GETBYTE(x,i) |=  ( 0x01 << ( (i) % BITS_PER_BYTE ) )
#define SIGLENBIT (SIGLEN*BITS_PER_BYTE)
#define SIGLENINT  63			
#define SORT(x) \
	do { \
		int		_nelems_ = ARRNELEMS(x); \
		if (_nelems_ > 1) \
			isort(ARRPTR(x), _nelems_); \
	} while(0)
#define WISH_F(a,b,c) (double)( -(double)(((a)-(b))*((a)-(b))*((a)-(b)))*(c) )

