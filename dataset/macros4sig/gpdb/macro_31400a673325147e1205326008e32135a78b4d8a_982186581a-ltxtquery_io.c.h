

#include<ctype.h>



#define AHASH(sign, val) SETBIT((sign), AHASHVAL(val))
#define AHASHVAL(val) (((unsigned int)(val)) % ASIGLENBIT)
#define ALOOPBYTE \
			for(i=0;i<ASIGLEN;i++)
#define ASIGLENBIT (ASIGLEN*BITBYTE)
#define BITBYTE 8
#define CLRBIT(x,i)   GETBYTE(x,i) &= ~( 0x01 << ( (i) % BITBYTE ) )
#define COMPUTESIZE(size,lenofoperand)	( HDRSIZEQT + (size) * sizeof(ITEM) + (lenofoperand) )
#define FLG_CANLOOKSIGN(x) ( ( (x) & ( LQL_NOT | LVAR_ANYEND | LVAR_SUBLEXEME ) ) == 0 )
#define GETBIT(x,i) ( (GETBYTE(x,i) >> ( (i) % BITBYTE )) & 0x01 )
#define GETBITBYTE(x,i) ( ((unsigned char)(x)) >> i & 0x01 )
#define GETBYTE(x,i) ( *( (BITVECP)(x) + (int)( (i) / BITBYTE ) ) )
#define GETOPERAND(x)	( (char*)GETQUERY(x) + ((ltxtquery*)x)->size * sizeof(ITEM) )
#define GETQUERY(x)  (ITEM*)( (char*)(x)+HDRSIZEQT )
#define HASH(sign, val) SETBIT((sign), HASHVAL(val))
#define HASHVAL(val) (((unsigned int)(val)) % SIGLENBIT)
#define ISALNUM(x)	( t_isalpha(x) || t_isdigit(x)	|| ( pg_mblen(x) == 1 && t_iseq((x), '_') ) )
#define ISOPERATOR(x) ( (x)=='!' || (x)=='&' || (x)=='|' || (x)=='(' || (x)==')' )
#define LEVEL_NEXT(x)	( (ltree_level*)( ((char*)(x)) + MAXALIGN(((ltree_level*)(x))->len + LEVEL_HDRSIZE) ) )
#define LOOPBYTE \
			for(i=0;i<SIGLEN;i++)
#define LQL_CANLOOKSIGN(x) FLG_CANLOOKSIGN( ((lquery_level*)(x))->flag )
#define LQL_FIRST(x)	( (lquery_variant*)( ((char*)(x))+LQL_HDRSIZE ) )
#define LQL_HDRSIZE MAXALIGN( offsetof(lquery_level,variants) )
#define LQL_NEXT(x) ( (lquery_level*)( ((char*)(x)) + MAXALIGN(((lquery_level*)(x))->totallen) ) )
#define LQUERY_FIRST(x)   ( (lquery_level*)( ((char*)(x))+LQUERY_HDRSIZE ) )
#define LTG_ALLTRUE 0x02
#define LTG_GETLNODE(x) ( LTG_ISONENODE(x) ? LTG_NODE(x) : LTG_LNODE(x) )
#define LTG_GETRNODE(x) ( LTG_ISONENODE(x) ? LTG_NODE(x) : LTG_RNODE(x) )
#define LTG_HDRSIZE MAXALIGN(VARHDRSZ + sizeof(uint32))
#define LTG_ISALLTRUE(x) ( ((ltree_gist*)(x))->flag & LTG_ALLTRUE )
#define LTG_ISNORIGHT(x) ( ((ltree_gist*)(x))->flag & LTG_NORIGHT )
#define LTG_ISONENODE(x) ( ((ltree_gist*)(x))->flag & LTG_ONENODE )
#define LTG_LNODE(x)	( (ltree*)( ( ((char*)(x))+LTG_HDRSIZE ) + ( LTG_ISALLTRUE(x) ? 0 : SIGLEN ) ) )
#define LTG_NODE(x) ( (ltree*)( ((char*)(x))+LTG_HDRSIZE ) )
#define LTG_NORIGHT 0x04
#define LTG_ONENODE 0x01
#define LTG_RENODE(x)	( (ltree*)( ((char*)LTG_LNODE(x)) + VARSIZE(LTG_LNODE(x))) )
#define LTG_RNODE(x)	( LTG_ISNORIGHT(x) ? LTG_LNODE(x) : LTG_RENODE(x) )
#define LTG_SIGN(x) ( (BITVECP)( ((char*)(x))+LTG_HDRSIZE ) )
#define LTREE_FIRST(x)	( (ltree_level*)( ((char*)(x))+LTREE_HDRSIZE ) )
#define LTXTQUERY_TOO_BIG(size,lenofoperand) \
	((size) > (MaxAllocSize - HDRSIZEQT - (lenofoperand)) / sizeof(ITEM))
#define LVAR_ANYEND 0x01
#define LVAR_HDRSIZE   MAXALIGN(offsetof(lquery_variant, name))
#define LVAR_INCASE 0x02
#define LVAR_NEXT(x)	( (lquery_variant*)( ((char*)(x)) + MAXALIGN(((lquery_variant*)(x))->len) + LVAR_HDRSIZE ) )
#define PG_GETARG_LQUERY(x) ((lquery*)DatumGetPointer(PG_DETOAST_DATUM(PG_GETARG_DATUM(x))))
#define PG_GETARG_LQUERY_COPY(x) ((lquery*)DatumGetPointer(PG_DETOAST_DATUM_COPY(PG_GETARG_DATUM(x))))
#define PG_GETARG_LTREE(x)	((ltree*)DatumGetPointer(PG_DETOAST_DATUM(PG_GETARG_DATUM(x))))
#define PG_GETARG_LTREE_COPY(x) ((ltree*)DatumGetPointer(PG_DETOAST_DATUM_COPY(PG_GETARG_DATUM(x))))
#define PG_GETARG_LTXTQUERY(x) ((ltxtquery*)DatumGetPointer(PG_DETOAST_DATUM(PG_GETARG_DATUM(x))))
#define PG_GETARG_LTXTQUERY_COPY(x) ((ltxtquery*)DatumGetPointer(PG_DETOAST_DATUM_COPY(PG_GETARG_DATUM(x))))
#define SETBIT(x,i)   GETBYTE(x,i) |=  ( 0x01 << ( (i) % BITBYTE ) )
#define SIGLENBIT (SIGLEN*BITBYTE)
#define SIGLENINT  2


#define crc32(buf) ltree_crc32_sz((buf),strlen(buf))
