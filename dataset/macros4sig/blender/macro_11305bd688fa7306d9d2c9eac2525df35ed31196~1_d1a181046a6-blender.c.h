
#include<string.h>





#include<stdlib.h>

#include<stdio.h>

#include<stddef.h>








#include<fcntl.h>
#include<unistd.h>






#define BCLR(a,b)	( (a) & ~(1<<(b)) )

#define BMEMSET(mem, val, size) {unsigned int _i; char *_c = (char*) mem; for (_i=0; _i<size; _i++) *_c++ = val;}
#define BNTST(a,b)	( ( (a) & 1<<(b) )==0 )
#define BROW(min, max)	(((max)>=31? 0xFFFFFFFF: (1<<(max+1))-1) - ((min)? ((1<<(min))-1):0) )
#define BSET(a,b)	( (a) | 1<<(b) )
#define BTST(a,b)	( ( (a) & 1<<(b) )!=0 )   
#define BTST2(a,b,c)	( BTST( (a), (b) ) || BTST( (a), (c) ) )
#define DATA MAKE_ID('D','A','T','A')
#define DNA1 MAKE_ID('D','N','A','1')
#define ENDB MAKE_ID('E','N','D','B')
#define GLOB MAKE_ID('G','L','O','B')
#define ID_NEW(a)		if( (a) && (a)->id.newid ) (a)= (void *)(a)->id.newid
#define MAKE_ID(a,b,c,d) ( (int)(a)<<24 | (int)(b)<<16 | (c)<<8 | (d) )
#define O_BINARY 0
#define REND MAKE_ID('R','E','N','D')
#define TEST MAKE_ID('T','E','S','T') 
#define USER MAKE_ID('U','S','E','R')

#define BUILD_SEQAR_COUNT_CHILDREN 2
#define BUILD_SEQAR_COUNT_CURRENT  1
#define BUILD_SEQAR_COUNT_NOTHING  0
#define MAXSEQ          32
#define SEQP_BEGIN(ed, _seq) \
{ \
	SeqIterator iter;\
		for(seq_begin(ed, &iter, 1); iter.valid; seq_next(&iter)) { \
			_seq= iter.seq;
#define SEQ_BEGIN(ed, _seq) \
	{ \
		SeqIterator iter;\
		for(seq_begin(ed, &iter, 0); iter.valid; seq_next(&iter)) { \
			_seq= iter.seq;
#define SEQ_END \
		} \
		seq_end(&iter); \
	}


#define SETLOOPER(_sce_basis, _sce_iter, _base) _sce_iter= _sce_basis, _base= _setlooper_base_step(&_sce_iter, NULL); _base; _base= _setlooper_base_step(&_sce_iter, _base)


#define CMP_NODE_BILATERALBLUR  255
#define CMP_NODE_BRIGHTCONTRAST 249
#define CMP_NODE_COLORBALANCE 260
#define CMP_NODE_COLOR_MATTE 259
#define CMP_NODE_HUECORRECT 261
#define CMP_NODE_NORMALIZE      252
#define CMP_NODE_PREMULKEY  256
#define CMP_NODE_VIEW_LEVELS    258
#define CMP_SCALE_RENDERPERCENT 3
#define NODE_CLASS_PATTERN 12
#define NODE_CLASS_TEXTURE 13
#define SH_NODE_MAT_DIFF   1
#define SH_NODE_MAT_NEG    4
#define SH_NODE_MAT_SPEC   2
#define TEX_NODE_AT         423
#define TEX_NODE_BRICKS     404
#define TEX_NODE_CHECKER    402
#define TEX_NODE_COMPOSE    419
#define TEX_NODE_COORD      417
#define TEX_NODE_CURVE_RGB  410
#define TEX_NODE_CURVE_TIME 413
#define TEX_NODE_DECOMPOSE  420
#define TEX_NODE_DISTANCE   418
#define TEX_NODE_HUE_SAT    412
#define TEX_NODE_IMAGE      409
#define TEX_NODE_INVERT     411
#define TEX_NODE_MATH       405
#define TEX_NODE_MIX_RGB    406
#define TEX_NODE_OUTPUT     401
#define TEX_NODE_PROC      500
#define TEX_NODE_PROC_MAX  600
#define TEX_NODE_RGBTOBW    407
#define TEX_NODE_ROTATE     414
#define TEX_NODE_SCALE      422
#define TEX_NODE_TEXTURE    403
#define TEX_NODE_TRANSLATE  416
#define TEX_NODE_VALTONOR   421
#define TEX_NODE_VALTORGB   408
#define TEX_NODE_VIEWER     415


#define ID_FALLBACK_NAME "Untitled"
#define IS_TAGGED(_id) ((_id) && (((ID *)_id)->flag & LIB_DOIT))

#define IDP_Array(prop) ((prop)->data.pointer)
#define IDP_Double(prop) (*(double*)&(prop)->data.val)
#define IDP_Float(prop) (*(float*)&(prop)->data.val)
#define IDP_IDPArray(prop) ((IDProperty*)(prop)->data.pointer)
#define IDP_Int(prop) ((prop)->data.val)
#define IDP_String(prop) ((char*)(prop)->data.pointer)


#define G_AUTOPACK               (1 << 0)
#define G_FILE_AUTOPLAY          (1 << 2)
#define G_FILE_COMPRESS          (1 << 1)
#define G_FILE_ENABLE_ALL_FRAMES (1 << 3)				
#define G_FILE_GLSL_NO_EXTRA_TEX (1 << 21)				
#define G_FILE_LOCK              (1 << 7)
#define G_FILE_SHOW_DEBUG_PROPS  (1 << 4)				
#define G_FILE_SHOW_FRAMERATE    (1 << 5)				
#define G_FILE_SIGN              (1 << 8)
#define G_GREASEPENCIL 	(1 << 17)
#define G_SCRIPT_AUTOEXEC (1 << 13)
#define G_SCRIPT_OVERRIDE_PREF (1 << 14) 

#define DL_INDEX3               4
#define DL_INDEX4               5
#define DL_POLY                 0
#define DL_SEGM                 1
#define DL_SURF                 2
#define DL_VERTCOL              6

#define CD_ASSIGN    0  
#define CD_CALLOC    1  
#define CD_DEFAULT   2  
#define CD_DUPLICATE 4  
#define CD_REFERENCE 3  
#define ORIGINDEX_NONE -1
#define DAG_RL_ALL_BUT_DATA 61


#define CTX_DATA_BEGIN(C, Type, instance, member) \
	{ \
		ListBase ctx_data_list; \
		CollectionPointerLink *ctx_link; \
		CTX_data_##member(C, &ctx_data_list); \
		for(ctx_link=ctx_data_list.first; ctx_link; ctx_link=ctx_link->next) { \
			Type instance= ctx_link->ptr.data;
#define CTX_DATA_COUNT(C, member) \
	ctx_data_list_count(C, CTX_data_##member)
#define CTX_DATA_END \
		} \
		BLI_freelistN(&ctx_data_list); \
	}

