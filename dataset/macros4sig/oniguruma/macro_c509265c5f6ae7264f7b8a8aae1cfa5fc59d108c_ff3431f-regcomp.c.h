#include<alloca.h>
#include<ctype.h>
#include<stdint.h>
#include<malloc.h>

#include<inttypes.h>
#include<sys/types.h>
#include<limits.h>
#include<stddef.h>
#include<stdlib.h>
#include<string.h>
#define ANCHOR_(node)      (&((node)->u.anchor))
#define ANCR_ANYCHAR_INF_MASK  (ANCR_ANYCHAR_INF | ANCR_ANYCHAR_INF_ML)
#define ANCR_END_BUF_MASK      (ANCR_END_BUF | ANCR_SEMI_END_BUF)
#define BACKREFS_P(br) \
  (IS_NOT_NULL((br)->back_dynamic) ? (br)->back_dynamic : (br)->back_static)
#define BACKREF_(node)     (&((node)->u.backref))
#define BAG_(node)         (&((node)->u.bag))
#define CALL_(node)        (&((node)->u.call))
#define CCLASS_(node)      (&((node)->u.cclass))
#define CONS_(node)        (&((node)->u.cons))
#define CTYPE_(node)       (&((node)->u.ctype))
#define CTYPE_ANYCHAR      -1
#define CTYPE_OPTION(node, reg) \
  (NODE_IS_FIXED_OPTION(node) ? CTYPE_(node)->options : reg->options)
#define GIMMICK_(node)     (&((node)->u.gimmick))
#define IS_SYNTAX_BV(syn, bvm)    (((syn)->behavior & (bvm)) != 0)
#define IS_SYNTAX_OP(syn, opm)    (((syn)->op  & (opm)) != 0)
#define IS_SYNTAX_OP2(syn, opm)   (((syn)->op2 & (opm)) != 0)
#define NODE_ANCHOR_BODY(node)    ((node)->body)
#define NODE_BACKREFS_SIZE          6
#define NODE_BAG_BODY(node)       ((node)->body)
#define NODE_BIT_ALT        NODE_TYPE2BIT(NODE_ALT)
#define NODE_BIT_ANCHOR     NODE_TYPE2BIT(NODE_ANCHOR)
#define NODE_BIT_BACKREF    NODE_TYPE2BIT(NODE_BACKREF)
#define NODE_BIT_BAG        NODE_TYPE2BIT(NODE_BAG)
#define NODE_BIT_CALL       NODE_TYPE2BIT(NODE_CALL)
#define NODE_BIT_CCLASS     NODE_TYPE2BIT(NODE_CCLASS)
#define NODE_BIT_CTYPE      NODE_TYPE2BIT(NODE_CTYPE)
#define NODE_BIT_GIMMICK    NODE_TYPE2BIT(NODE_GIMMICK)
#define NODE_BIT_LIST       NODE_TYPE2BIT(NODE_LIST)
#define NODE_BIT_QUANT      NODE_TYPE2BIT(NODE_QUANT)
#define NODE_BIT_STRING     NODE_TYPE2BIT(NODE_STRING)
#define NODE_BODY(node)           ((node)->u.base.body)
#define NODE_CALL_BODY(node)      ((node)->body)
#define NODE_CAR(node)         (CONS_(node)->car)
#define NODE_CDR(node)         (CONS_(node)->cdr)
#define NODE_IS_ADDR_FIXED(node)      ((NODE_STATUS(node) & NODE_ST_ADDR_FIXED)   != 0)
#define NODE_IS_ANYCHAR(node) \
  (NODE_TYPE(node) == NODE_CTYPE && CTYPE_(node)->ctype == CTYPE_ANYCHAR)
#define NODE_IS_BACKREF(node)         ((NODE_STATUS(node) & NODE_ST_BACKREF)      != 0)
#define NODE_IS_BY_NAME(node)         ((NODE_STATUS(node) & NODE_ST_BY_NAME)      != 0)
#define NODE_IS_BY_NUMBER(node)       ((NODE_STATUS(node) & NODE_ST_BY_NUMBER)      != 0)
#define NODE_IS_CALLED(node)          ((NODE_STATUS(node) & NODE_ST_CALLED)         != 0)
#define NODE_IS_CHECKER(node)         ((NODE_STATUS(node) & NODE_ST_CHECKER)      != 0)
#define NODE_IS_CLEN_FIXED(node)      ((NODE_STATUS(node) & NODE_ST_CLEN_FIXED)   != 0)
#define NODE_IS_FIXED_OPTION(node)    ((NODE_STATUS(node) & NODE_ST_FIXED_OPTION) != 0)
#define NODE_IS_IN_MULTI_ENTRY(node)  ((NODE_STATUS(node) & NODE_ST_IN_MULTI_ENTRY) != 0)
#define NODE_IS_IN_REAL_REPEAT(node)  ((NODE_STATUS(node) & NODE_ST_IN_REAL_REPEAT) != 0)
#define NODE_IS_IN_ZERO_REPEAT(node)  ((NODE_STATUS(node) & NODE_ST_IN_ZERO_REPEAT) != 0)
#define NODE_IS_MARK1(node)           ((NODE_STATUS(node) & NODE_ST_MARK1)        != 0)
#define NODE_IS_MARK2(node)           ((NODE_STATUS(node) & NODE_ST_MARK2)        != 0)
#define NODE_IS_MAX_FIXED(node)       ((NODE_STATUS(node) & NODE_ST_MAX_FIXED)    != 0)
#define NODE_IS_MIN_FIXED(node)       ((NODE_STATUS(node) & NODE_ST_MIN_FIXED)    != 0)
#define NODE_IS_NAMED_GROUP(node)     ((NODE_STATUS(node) & NODE_ST_NAMED_GROUP)  != 0)
#define NODE_IS_NEST_LEVEL(node)      ((NODE_STATUS(node) & NODE_ST_NEST_LEVEL)   != 0)
#define NODE_IS_PROHIBIT_RECURSION(node) \
    ((NODE_STATUS(node) & NODE_ST_PROHIBIT_RECURSION) != 0)
#define NODE_IS_RECURSION(node)       ((NODE_STATUS(node) & NODE_ST_RECURSION)      != 0)
#define NODE_IS_SIMPLE_TYPE(node) \
  ((NODE_TYPE2BIT(NODE_TYPE(node)) & \
    (NODE_BIT_STRING | NODE_BIT_CCLASS | NODE_BIT_CTYPE | NODE_BIT_BACKREF)) != 0)
#define NODE_IS_STOP_BT_SIMPLE_REPEAT(node) \
    ((NODE_STATUS(node) & NODE_ST_STOP_BT_SIMPLE_REPEAT) != 0)
#define NODE_IS_SUPER(node)           ((NODE_STATUS(node) & NODE_ST_SUPER)        != 0)
#define NODE_QUANT_BODY(node)     ((node)->body)
#define NODE_SET_TYPE(node, ntype)   (node)->u.base.node_type = (ntype)
#define NODE_STATUS(node)           (((Node* )node)->u.base.status)
#define NODE_STATUS_ADD(node,f)     (NODE_STATUS(node) |= (NODE_ST_ ## f))
#define NODE_STATUS_REMOVE(node,f)  (NODE_STATUS(node) &= ~(NODE_ST_ ## f))
#define NODE_STRING_AMBIG              (1<<1)
#define NODE_STRING_BUF_SIZE       24  
#define NODE_STRING_CLEAR_RAW(node)      (node)->u.str.flag &= ~NODE_STRING_RAW
#define NODE_STRING_DONT_GET_OPT_INFO  (1<<3)
#define NODE_STRING_GOOD_AMBIG         (1<<2)
#define NODE_STRING_IS_AMBIG(node) \
  (((node)->u.str.flag & NODE_STRING_AMBIG) != 0)
#define NODE_STRING_IS_DONT_GET_OPT_INFO(node) \
  (((node)->u.str.flag & NODE_STRING_DONT_GET_OPT_INFO) != 0)
#define NODE_STRING_IS_GOOD_AMBIG(node) \
  (((node)->u.str.flag & NODE_STRING_GOOD_AMBIG) != 0)
#define NODE_STRING_IS_RAW(node) \
  (((node)->u.str.flag & NODE_STRING_RAW) != 0)
#define NODE_STRING_LEN(node)            (int )((node)->u.str.end - (node)->u.str.s)
#define NODE_STRING_MARGIN         16
#define NODE_STRING_RAW                (1<<0) 
#define NODE_STRING_SET_AMBIG(node)      (node)->u.str.flag |= NODE_STRING_AMBIG
#define NODE_STRING_SET_DONT_GET_OPT_INFO(node) \
  (node)->u.str.flag |= NODE_STRING_DONT_GET_OPT_INFO
#define NODE_STRING_SET_GOOD_AMBIG(node) (node)->u.str.flag |= NODE_STRING_GOOD_AMBIG
#define NODE_STRING_SET_RAW(node)        (node)->u.str.flag |= NODE_STRING_RAW
#define NODE_ST_ADDR_FIXED            (1<<8)
#define NODE_ST_BACKREF               (1<<16)
#define NODE_ST_BY_NAME               (1<<15) 
#define NODE_ST_BY_NUMBER             (1<<14) 
#define NODE_ST_CALLED                (1<<7)
#define NODE_ST_CHECKER               (1<<17)
#define NODE_ST_CLEN_FIXED            (1<<2)
#define NODE_ST_FIXED_OPTION          (1<<18)
#define NODE_ST_IN_MULTI_ENTRY        (1<<12)
#define NODE_ST_IN_REAL_REPEAT        (1<<10) 
#define NODE_ST_IN_ZERO_REPEAT        (1<<11) 
#define NODE_ST_MARK1                 (1<<3)
#define NODE_ST_MARK2                 (1<<4)
#define NODE_ST_MAX_FIXED             (1<<1)
#define NODE_ST_MIN_FIXED             (1<<0)
#define NODE_ST_NAMED_GROUP           (1<<9)
#define NODE_ST_NEST_LEVEL            (1<<13)
#define NODE_ST_PROHIBIT_RECURSION    (1<<19)
#define NODE_ST_RECURSION             (1<<6)
#define NODE_ST_STOP_BT_SIMPLE_REPEAT (1<<5)
#define NODE_ST_SUPER                 (1<<20)
#define NODE_TYPE(node)             ((node)->u.base.node_type)
#define NODE_TYPE2BIT(type)      (1<<(type))
#define NULL_NODE  ((Node* )0)
#define QUANT_(node)       (&((node)->u.quant))

#define SCANENV_MEMENV(senv) \
 (IS_NOT_NULL((senv)->mem_env_dynamic) ? \
    (senv)->mem_env_dynamic : (senv)->mem_env_static)
#define SCANENV_MEMENV_SIZE               8
#define STR_(node)         (&((node)->u.str))
#define ALIGNMENT_RIGHT(addr) do {\
  (addr) += (WORD_ALIGNMENT_SIZE - 1);\
  (addr) -= ((uintptr_t )(addr) % WORD_ALIGNMENT_SIZE);\
} while (0)
#define ANCHOR_HAS_BODY(a)      ((a)->type < ANCR_BEGIN_BUF)
#define ANCR_ANYCHAR_INF      (1<<14)
#define ANCR_ANYCHAR_INF_ML   (1<<15)
#define ANCR_BEGIN_BUF        (1<<4)
#define ANCR_BEGIN_LINE       (1<<5)
#define ANCR_BEGIN_POSITION   (1<<6)
#define ANCR_END_BUF          (1<<7)
#define ANCR_END_LINE         (1<<9)
#define ANCR_LOOK_BEHIND      (1<<2)
#define ANCR_LOOK_BEHIND_NOT  (1<<3)
#define ANCR_NO_TEXT_SEGMENT_BOUNDARY (1<<17)
#define ANCR_NO_WORD_BOUNDARY (1<<11)
#define ANCR_PREC_READ        (1<<0)
#define ANCR_PREC_READ_NOT    (1<<1)
#define ANCR_SEMI_END_BUF     (1<<8)
#define ANCR_TEXT_SEGMENT_BOUNDARY    (1<<16)
#define ANCR_WORD_BEGIN       (1<<12)
#define ANCR_WORD_BOUNDARY    (1<<10)
#define ANCR_WORD_END         (1<<13)
#define BB_ADD(buf,bytes,n)       BB_WRITE((buf),(buf)->used,(bytes),(n))
#define BB_ADD1(buf,byte)         BB_WRITE1((buf),(buf)->used,(byte))
#define BB_ENSURE_SIZE(buf,size) do{\
  unsigned int new_alloc = (buf)->alloc;\
  while (new_alloc < (unsigned int )(size)) { new_alloc *= 2; }\
  if ((buf)->alloc != new_alloc) {\
    (buf)->p = (UChar* )xrealloc((buf)->p, new_alloc);\
    if (IS_NULL((buf)->p)) return(ONIGERR_MEMORY);\
    (buf)->alloc = new_alloc;\
  }\
} while (0)
#define BB_EXPAND(buf,low) do{\
  do { (buf)->alloc *= 2; } while ((buf)->alloc < (unsigned int )low);\
  (buf)->p = (UChar* )xrealloc((buf)->p, (buf)->alloc);\
  if (IS_NULL((buf)->p)) return(ONIGERR_MEMORY);\
} while (0)
#define BB_GET_ADD_ADDRESS(buf)   ((buf)->p + (buf)->used)
#define BB_GET_BYTE(buf, pos) (buf)->p[(pos)]
#define BB_GET_OFFSET_POS(buf)    ((buf)->used)
#define BB_INIT(buf,size)    bbuf_init((BBuf* )(buf), (size))
#define BB_INSERT(buf,pos,bytes,n) do {\
  if (pos >= (buf)->used) {\
    BB_WRITE(buf,pos,bytes,n);\
  }\
  else {\
    BB_MOVE_RIGHT((buf),(pos),(pos) + (n),((buf)->used - (pos)));\
    xmemcpy((buf)->p + (pos), (bytes), (n));\
  }\
} while (0)
#define BB_MOVE_LEFT(buf,from,to,n) do {\
  xmemmove((buf)->p + (to), (buf)->p + (from), (n));\
} while (0)
#define BB_MOVE_LEFT_REDUCE(buf,from,to) do {\
  xmemmove((buf)->p + (to), (buf)->p + (from), (buf)->used - (from));\
  (buf)->used -= (from - to);\
} while (0)
#define BB_MOVE_RIGHT(buf,from,to,n) do {\
  if ((unsigned int )((to)+(n)) > (buf)->alloc) BB_EXPAND((buf),(to) + (n));\
  xmemmove((buf)->p + (to), (buf)->p + (from), (n));\
  if ((unsigned int )((to)+(n)) > (buf)->used) (buf)->used = (to) + (n);\
} while (0)
#define BB_SIZE_INC(buf,inc) do{\
  (buf)->alloc += (inc);\
  (buf)->p = (UChar* )xrealloc((buf)->p, (buf)->alloc);\
  if (IS_NULL((buf)->p)) return(ONIGERR_MEMORY);\
} while (0)
#define BB_WRITE(buf,pos,bytes,n) do{\
  int used = (pos) + (n);\
  if ((buf)->alloc < (unsigned int )used) BB_EXPAND((buf),used);\
  xmemcpy((buf)->p + (pos), (bytes), (n));\
  if ((buf)->used < (unsigned int )used) (buf)->used = used;\
} while (0)
#define BB_WRITE1(buf,pos,byte) do{\
  int used = (pos) + 1;\
  if ((buf)->alloc < (unsigned int )used) BB_EXPAND((buf),used);\
  (buf)->p[(pos)] = (byte);\
  if ((buf)->used < (unsigned int )used) (buf)->used = used;\
} while (0)
#define BC0_B(name, func)  do {\
  int len = onigenc_str_bytelen_null(enc, (UChar* )name);\
  id = onig_set_callout_of_name(enc, ONIG_CALLOUT_TYPE_SINGLE,\
                              (UChar* )(name), (UChar* )((name) + len),\
                              ONIG_CALLOUT_IN_BOTH,\
                              onig_builtin_ ## func, 0, 0, 0, 0, 0);\
  if (id < 0) return id;\
} while(0)
#define BC0_P(name, func)  do {\
  int len = onigenc_str_bytelen_null(enc, (UChar* )name);\
  id = onig_set_callout_of_name(enc, ONIG_CALLOUT_TYPE_SINGLE,\
                              (UChar* )(name), (UChar* )((name) + len),\
                              ONIG_CALLOUT_IN_PROGRESS,\
                              onig_builtin_ ## func, 0, 0, 0, 0, 0);\
  if (id < 0) return id;\
} while(0)
#define BC0_R(name, func)  do {\
  int len = onigenc_str_bytelen_null(enc, (UChar* )name);\
  id = onig_set_callout_of_name(enc, ONIG_CALLOUT_TYPE_SINGLE,\
                              (UChar* )(name), (UChar* )((name) + len),\
                              ONIG_CALLOUT_IN_RETRACTION,\
                              onig_builtin_ ## func, 0, 0, 0, 0, 0);\
  if (id < 0) return id;\
} while(0)
#define BC_B(name, func, na, ts)  do {\
  int len = onigenc_str_bytelen_null(enc, (UChar* )name);\
  id = onig_set_callout_of_name(enc, ONIG_CALLOUT_TYPE_SINGLE,\
                              (UChar* )(name), (UChar* )((name) + len),\
                              ONIG_CALLOUT_IN_BOTH,\
                              onig_builtin_ ## func, 0, (na), (ts), 0, 0);\
  if (id < 0) return id;\
} while(0)
#define BC_B_O(name, func, nts, ts, nopts, opts)  do {\
  int len = onigenc_str_bytelen_null(enc, (UChar* )name);\
  id = onig_set_callout_of_name(enc, ONIG_CALLOUT_TYPE_SINGLE,\
                           (UChar* )(name), (UChar* )((name) + len),\
                           ONIG_CALLOUT_IN_BOTH,\
                           onig_builtin_ ## func, 0, (nts), (ts), (nopts), (opts));\
  if (id < 0) return id;\
} while(0)
#define BC_P(name, func, na, ts)  do {\
  int len = onigenc_str_bytelen_null(enc, (UChar* )name);\
  id = onig_set_callout_of_name(enc, ONIG_CALLOUT_TYPE_SINGLE,\
                              (UChar* )(name), (UChar* )((name) + len),\
                              ONIG_CALLOUT_IN_PROGRESS,\
                                onig_builtin_ ## func, 0, (na), (ts), 0, 0); \
  if (id < 0) return id;\
} while(0)
#define BC_P_O(name, func, nts, ts, nopts, opts)  do {\
  int len = onigenc_str_bytelen_null(enc, (UChar* )name);\
  id = onig_set_callout_of_name(enc, ONIG_CALLOUT_TYPE_SINGLE,\
                           (UChar* )(name), (UChar* )((name) + len),\
                           ONIG_CALLOUT_IN_PROGRESS,\
                           onig_builtin_ ## func, 0, (nts), (ts), (nopts), (opts));\
  if (id < 0) return id;\
} while(0)
#define BITSET_AT(bs, pos)         (BS_ROOM(bs,pos) & BS_BIT(pos))
#define BITSET_CLEAR(bs) do {\
  int i;\
  for (i = 0; i < (int )BITSET_SIZE; i++) { (bs)[i] = 0; } \
} while (0)
#define BITSET_CLEAR_BIT(bs, pos)   BS_ROOM(bs,pos) &= ~(BS_BIT(pos))
#define BITSET_INVERT_BIT(bs, pos)  BS_ROOM(bs,pos) ^= BS_BIT(pos)
#define BITSET_SET_BIT(bs, pos)     BS_ROOM(bs,pos) |= BS_BIT(pos)
#define BITSET_SIZE        (SINGLE_BYTE_SIZE / BITS_IN_ROOM)
#define BITS_IN_ROOM       (sizeof(Bits) * BITS_PER_BYTE)
#define BITS_PER_BYTE      8
#define BS_BIT(pos)                (1 << (pos % BITS_IN_ROOM))
#define BS_ROOM(bs,pos)            (bs)[pos / BITS_IN_ROOM]
#define CHAR_MAP_SIZE       256
#define CHECK_NULL_RETURN(p)          if (IS_NULL(p)) return NULL
#define CHECK_NULL_RETURN_MEMERR(p)   if (IS_NULL(p)) return ONIGERR_MEMORY
#define COP(reg)            ((reg)->ops_curr)
#define COP_CURR_OFFSET(reg)  ((reg)->ops_used - 1)
#define COP_CURR_OFFSET_BYTES(reg, p)  \
  ((int )((char* )(&((reg)->ops_curr->p)) - (char* )((reg)->ops)))
#define DEFAULT_MATCH_STACK_LIMIT_SIZE              0 
#define DEFAULT_PARSE_DEPTH_LIMIT                4096
#define DEFAULT_RETRY_LIMIT_IN_MATCH         10000000
#define DIGITVAL(code)    ((code) - '0')
#define DISABLE_CASE_FOLD_MULTI_CHAR(case_fold_flag) \
  ((case_fold_flag) & ~INTERNAL_ONIGENC_CASE_FOLD_MULTI_CHAR)
#define FLAG_NCCLASS_NOT           (1<<0)
#define FLAG_NCCLASS_SHARE         (1<<1)
#define GET_ABSADDR_INC(addr,p)    PLATFORM_GET_INC(addr,   p, AbsAddrType)
#define GET_ALIGNMENT_PAD_SIZE(addr,pad_size) do {\
  (pad_size) = WORD_ALIGNMENT_SIZE - ((uintptr_t )(addr) % WORD_ALIGNMENT_SIZE);\
  if ((pad_size) == WORD_ALIGNMENT_SIZE) (pad_size) = 0;\
} while (0)
#define GET_BYTE_INC(byte,p) do{\
  byte = *(p);\
  (p)++;\
} while(0)
#define GET_CODE_POINT(code,p)   code = *((OnigCodePoint* )(p))
#define GET_LENGTH_INC(len,p)      PLATFORM_GET_INC(len,    p, LengthType)
#define GET_MEMNUM_INC(num,p)      PLATFORM_GET_INC(num,    p, MemNumType)
#define GET_MODE_INC(mode,p)            PLATFORM_GET_INC(mode, p, ModeType)
#define GET_OPTION_INC(option,p)   PLATFORM_GET_INC(option, p, OnigOptionType)
#define GET_POINTER_INC(ptr,p)     PLATFORM_GET_INC(ptr,    p, PointerType)
#define GET_RELADDR_INC(addr,p)    PLATFORM_GET_INC(addr,   p, RelAddrType)
#define GET_REPEATNUM_INC(num,p)   PLATFORM_GET_INC(num,    p, RepeatNumType)
#define GET_SAVE_TYPE_INC(type,p)       PLATFORM_GET_INC(type, p, SaveType)
#define GET_UPDATE_VAR_TYPE_INC(type,p) PLATFORM_GET_INC(type, p, UpdateVarType)
#define INFINITE_LEN        ONIG_INFINITE_DISTANCE
#define INIT_MATCH_STACK_SIZE                     160
#define INT_MAX_LIMIT           ((1UL << (SIZEOF_INT * 8 - 1)) - 1)
#define IS_ASCII_MODE_CTYPE_OPTION(ctype, options) \
  ((ctype) >= 0 && \
  (((ctype) < ONIGENC_CTYPE_ASCII  && IS_POSIX_ASCII(options)) ||\
   ((ctype) == ONIGENC_CTYPE_WORD  && IS_WORD_ASCII(options))  ||\
   ((ctype) == ONIGENC_CTYPE_DIGIT && IS_DIGIT_ASCII(options)) ||\
   ((ctype) == ONIGENC_CTYPE_SPACE && IS_SPACE_ASCII(options))))
#define IS_CODE_DIGIT_ASCII(enc, code) \
  (ONIGENC_IS_CODE_ASCII(code) && ONIGENC_IS_CODE_DIGIT(enc,code))
#define IS_CODE_WORD_ASCII(enc,code) \
  (ONIGENC_IS_CODE_ASCII(code) && ONIGENC_IS_CODE_WORD(enc,code))
#define IS_CODE_XDIGIT_ASCII(enc, code) \
  (ONIGENC_IS_CODE_ASCII(code) && ONIGENC_IS_CODE_XDIGIT(enc,code))
#define IS_DIGIT_ASCII(option) \
  ((option) & (ONIG_OPTION_DIGIT_IS_ASCII | ONIG_OPTION_POSIX_IS_ASCII))
#define IS_EXTEND(option)         ((option) & ONIG_OPTION_EXTEND)
#define IS_FIND_CONDITION(option) ((option) & \
          (ONIG_OPTION_FIND_LONGEST | ONIG_OPTION_FIND_NOT_EMPTY))
#define IS_FIND_LONGEST(option)   ((option) & ONIG_OPTION_FIND_LONGEST)
#define IS_FIND_NOT_EMPTY(option) ((option) & ONIG_OPTION_FIND_NOT_EMPTY)
#define IS_IGNORECASE(option)     ((option) & ONIG_OPTION_IGNORECASE)
#define IS_MC_ESC_CODE(code, syn) \
  ((code) == MC_ESC(syn) && \
   !IS_SYNTAX_OP2((syn), ONIG_SYN_OP2_INEFFECTIVE_ESCAPE))
#define IS_MULTILINE(option)      ((option) & ONIG_OPTION_MULTILINE)
#define IS_NCCLASS_FLAG_ON(cc,flag) ((NCCLASS_FLAGS(cc) & (flag)) != 0)
#define IS_NCCLASS_NOT(nd)      IS_NCCLASS_FLAG_ON(nd, FLAG_NCCLASS_NOT)
#define IS_NOTBOL(option)         ((option) & ONIG_OPTION_NOTBOL)
#define IS_NOTEOL(option)         ((option) & ONIG_OPTION_NOTEOL)
#define IS_NOT_NULL(p)                (((void*)(p)) != (void*)0)
#define IS_NULL(p)                    (((void*)(p)) == (void*)0)
#define IS_POSIX_ASCII(option)    ((option) & ONIG_OPTION_POSIX_IS_ASCII)
#define IS_POSIX_REGION(option)   ((option) & ONIG_OPTION_POSIX_REGION)
#define IS_REPEAT_INFINITE(n)   ((n) == REPEAT_INFINITE)
#define IS_SINGLELINE(option)     ((option) & ONIG_OPTION_SINGLELINE)
#define IS_SPACE_ASCII(option) \
  ((option) & (ONIG_OPTION_SPACE_IS_ASCII | ONIG_OPTION_POSIX_IS_ASCII))
#define IS_WORD_ANCHOR_TYPE(type) \
  ((type) == ANCR_WORD_BOUNDARY || (type) == ANCR_NO_WORD_BOUNDARY || \
   (type) == ANCR_WORD_BEGIN || (type) == ANCR_WORD_END)
#define IS_WORD_ASCII(option) \
  ((option) & (ONIG_OPTION_WORD_IS_ASCII | ONIG_OPTION_POSIX_IS_ASCII))
#define MAX(a,b) (((a)<(b))?(b):(a))
#define MC_ANYCHAR(syn)           (syn)->meta_char_table.anychar
#define MC_ANYCHAR_ANYTIME(syn)   (syn)->meta_char_table.anychar_anytime
#define MC_ANYTIME(syn)           (syn)->meta_char_table.anytime
#define MC_ESC(syn)               (syn)->meta_char_table.esc
#define MC_ONE_OR_MORE_TIME(syn)  (syn)->meta_char_table.one_or_more_time
#define MC_ZERO_OR_ONE_TIME(syn)  (syn)->meta_char_table.zero_or_one_time
#define MEM_STATUS_AT(stats,n) \
  ((n) < (int )MEM_STATUS_BITS_NUM  ?  ((stats) & ((MemStatusType )1 << n)) : ((stats) & 1))
#define MEM_STATUS_AT0(stats,n) \
  ((n) > 0 && (n) < (int )MEM_STATUS_BITS_NUM  ?  ((stats) & ((MemStatusType )1 << n)) : ((stats) & 1))
#define MEM_STATUS_BITS_NUM          (sizeof(MemStatusType) * 8)
#define MEM_STATUS_CLEAR(stats)      (stats) = 0
#define MEM_STATUS_ON(stats,n) do {\
  if ((n) < (int )MEM_STATUS_BITS_NUM) {\
    if ((n) != 0)\
      (stats) |= ((MemStatusType )1 << (n));\
  }\
  else\
    (stats) |= 1;\
} while (0)
#define MEM_STATUS_ON_ALL(stats)     (stats) = ~((MemStatusType )0)
#define MEM_STATUS_ON_SIMPLE(stats,n) do {\
    if ((n) < (int )MEM_STATUS_BITS_NUM)\
    (stats) |= ((MemStatusType )1 << (n));\
} while (0)
#define MIN(a,b) (((a)>(b))?(b):(a))
#define NCCLASS_CLEAR_NOT(nd)   NCCLASS_FLAG_CLEAR(nd, FLAG_NCCLASS_NOT)
#define NCCLASS_FLAGS(cc)           ((cc)->flags)
#define NCCLASS_FLAG_CLEAR(cc,flag)  (NCCLASS_FLAGS(cc) &= ~(flag))
#define NCCLASS_FLAG_SET(cc,flag)    (NCCLASS_FLAGS(cc) |= (flag))
#define NCCLASS_SET_NOT(nd)     NCCLASS_FLAG_SET(nd, FLAG_NCCLASS_NOT)
#define NULL_UCHARP                   ((UChar* )0)
#define ODIGITVAL(code)   DIGITVAL(code)

#define PLATFORM_GET_INC(val,p,type) do{\
  val  = *(type* )p;\
  (p) += sizeof(type);\
} while(0)


#define REPEAT_INFINITE         -1
#define SINGLE_BYTE_SIZE   (1 << BITS_PER_BYTE)
#define SIZE_ABSADDR          sizeof(AbsAddrType)
#define SIZE_BITSET        sizeof(BitSet)
#define SIZE_CODE_POINT       sizeof(OnigCodePoint)
#define SIZE_INC_OP                     1
#define SIZE_LENGTH           sizeof(LengthType)
#define SIZE_MEMNUM           sizeof(MemNumType)
#define SIZE_MODE             sizeof(ModeType)
#define SIZE_OPCODE           1
#define SIZE_OPTION           sizeof(OnigOptionType)
#define SIZE_OP_ANYCHAR_STAR            1
#define SIZE_OP_ANYCHAR_STAR_PEEK_NEXT  1
#define SIZE_OP_ATOMIC_END              1
#define SIZE_OP_ATOMIC_START            1
#define SIZE_OP_BACKREF                 1
#define SIZE_OP_CALL                    1
#define SIZE_OP_CALLOUT_CONTENTS        1
#define SIZE_OP_CALLOUT_NAME            1
#define SIZE_OP_EMPTY_CHECK_END         1
#define SIZE_OP_EMPTY_CHECK_START       1
#define SIZE_OP_FAIL                    1
#define SIZE_OP_JUMP                    1
#define SIZE_OP_LOOK_BEHIND             1
#define SIZE_OP_LOOK_BEHIND_NOT_END     1
#define SIZE_OP_LOOK_BEHIND_NOT_START   1
#define SIZE_OP_MEMORY_END              1
#define SIZE_OP_MEMORY_END_PUSH         1
#define SIZE_OP_MEMORY_END_PUSH_REC     1
#define SIZE_OP_MEMORY_END_REC          1
#define SIZE_OP_MEMORY_START            1
#define SIZE_OP_MEMORY_START_PUSH       1
#define SIZE_OP_POP_OUT                 1
#define SIZE_OP_PREC_READ_END           1
#define SIZE_OP_PREC_READ_NOT_END       1
#define SIZE_OP_PREC_READ_NOT_START     1
#define SIZE_OP_PREC_READ_START         1
#define SIZE_OP_PUSH                    1
#define SIZE_OP_PUSH_IF_PEEK_NEXT       1
#define SIZE_OP_PUSH_OR_JUMP_EXACT1     1
#define SIZE_OP_PUSH_SAVE_VAL           1
#define SIZE_OP_PUSH_SUPER              1
#define SIZE_OP_REPEAT                  1
#define SIZE_OP_REPEAT_INC              1
#define SIZE_OP_REPEAT_INC_NG           1
#define SIZE_OP_RETURN                  1
#define SIZE_OP_UPDATE_VAR              1
#define SIZE_OP_WORD_BOUNDARY           1
#define SIZE_POINTER          sizeof(PointerType)
#define SIZE_RELADDR          sizeof(RelAddrType)
#define SIZE_REPEATNUM        sizeof(RepeatNumType)
#define SIZE_SAVE_TYPE        sizeof(SaveType)
#define SIZE_UPDATE_VAR_TYPE  sizeof(UpdateVarType)
#define SYN_GNU_REGEX_BV \
  ( ONIG_SYN_CONTEXT_INDEP_ANCHORS | ONIG_SYN_CONTEXT_INDEP_REPEAT_OPS | \
    ONIG_SYN_CONTEXT_INVALID_REPEAT_OPS | ONIG_SYN_ALLOW_INVALID_INTERVAL | \
    ONIG_SYN_BACKSLASH_ESCAPE_IN_CC | ONIG_SYN_ALLOW_DOUBLE_RANGE_OP_IN_CC )
#define SYN_GNU_REGEX_OP \
  ( ONIG_SYN_OP_DOT_ANYCHAR | ONIG_SYN_OP_BRACKET_CC | \
    ONIG_SYN_OP_POSIX_BRACKET | ONIG_SYN_OP_DECIMAL_BACKREF | \
    ONIG_SYN_OP_BRACE_INTERVAL | ONIG_SYN_OP_LPAREN_SUBEXP | \
    ONIG_SYN_OP_VBAR_ALT | \
    ONIG_SYN_OP_ASTERISK_ZERO_INF | ONIG_SYN_OP_PLUS_ONE_INF | \
    ONIG_SYN_OP_QMARK_ZERO_ONE | \
    ONIG_SYN_OP_ESC_AZ_BUF_ANCHOR | ONIG_SYN_OP_ESC_CAPITAL_G_BEGIN_ANCHOR | \
    ONIG_SYN_OP_ESC_W_WORD | \
    ONIG_SYN_OP_ESC_B_WORD_BOUND | ONIG_SYN_OP_ESC_LTGT_WORD_BEGIN_END | \
    ONIG_SYN_OP_ESC_S_WHITE_SPACE | ONIG_SYN_OP_ESC_D_DIGIT | \
    ONIG_SYN_OP_LINE_ANCHOR )
#define SYN_POSIX_COMMON_OP \
 ( ONIG_SYN_OP_DOT_ANYCHAR | ONIG_SYN_OP_POSIX_BRACKET | \
   ONIG_SYN_OP_DECIMAL_BACKREF | \
   ONIG_SYN_OP_BRACKET_CC | ONIG_SYN_OP_ASTERISK_ZERO_INF | \
   ONIG_SYN_OP_LINE_ANCHOR | \
   ONIG_SYN_OP_ESC_CONTROL_CHARS )
#define USE_BACKREF_WITH_LEVEL        






#define USE_INSISTENT_CHECK_CAPTURES_IN_EMPTY_REPEAT    
#define USE_NEWLINE_AT_END_OF_STRING_HAS_EMPTY_LINE     








#define USE_WORD_BEGIN_END        
# define WORD_ALIGNMENT_SIZE     SIZEOF_SIZE_T
#define XDIGITVAL(enc,code) \
  (IS_CODE_DIGIT_ASCII(enc,code) ? DIGITVAL(code) \
   : (ONIGENC_IS_CODE_UPPER(enc,code) ? (code) - 'A' + 10 : (code) - 'a' + 10))
#define onig_st_is_member              st_is_member
#define st_add_direct                  onig_st_add_direct
#define st_cleanup_safe                onig_st_cleanup_safe
#define st_copy                        onig_st_copy
#define st_delete                      onig_st_delete
#define st_delete_safe                 onig_st_delete_safe
#define st_foreach                     onig_st_foreach
#define st_free_table                  onig_st_free_table
#define st_init_numtable               onig_st_init_numtable
#define st_init_numtable_with_size     onig_st_init_numtable_with_size
#define st_init_strtable               onig_st_init_strtable
#define st_init_strtable_with_size     onig_st_init_strtable_with_size
#define st_init_table                  onig_st_init_table
#define st_init_table_with_size        onig_st_init_table_with_size
#define st_insert                      onig_st_insert
#define st_lookup                      onig_st_lookup
#define st_nothing_key_clone           onig_st_nothing_key_clone
#define st_nothing_key_free            onig_st_nothing_key_free
#define xalloca     _alloca
#define xcalloc     calloc
#define xfree       free
#define xmalloc     malloc
#define xmemcpy     memcpy
#define xmemmove    memmove
#define xmemset     memset
#define xrealloc    realloc
#define xsnprintf   sprintf_s
#define xstrcat(dest,src,size)   strcat_s(dest,size,src)
#define xvsnprintf  vsnprintf
#  define ARG_UNUSED  __attribute__ ((unused))
#define BIT_CTYPE_ALNUM    (1<< ONIGENC_CTYPE_ALNUM)
#define BIT_CTYPE_ALPHA    (1<< ONIGENC_CTYPE_ALPHA)
#define BIT_CTYPE_ASCII    (1<< ONIGENC_CTYPE_ASCII)
#define BIT_CTYPE_BLANK    (1<< ONIGENC_CTYPE_BLANK)
#define BIT_CTYPE_CNTRL    (1<< ONIGENC_CTYPE_CNTRL)
#define BIT_CTYPE_DIGIT    (1<< ONIGENC_CTYPE_DIGIT)
#define BIT_CTYPE_GRAPH    (1<< ONIGENC_CTYPE_GRAPH)
#define BIT_CTYPE_LOWER    (1<< ONIGENC_CTYPE_LOWER)
#define BIT_CTYPE_NEWLINE  (1<< ONIGENC_CTYPE_NEWLINE)
#define BIT_CTYPE_PRINT    (1<< ONIGENC_CTYPE_PRINT)
#define BIT_CTYPE_PUNCT    (1<< ONIGENC_CTYPE_PUNCT)
#define BIT_CTYPE_SPACE    (1<< ONIGENC_CTYPE_SPACE)
#define BIT_CTYPE_UPPER    (1<< ONIGENC_CTYPE_UPPER)
#define BIT_CTYPE_WORD     (1<< ONIGENC_CTYPE_WORD)
#define BIT_CTYPE_XDIGIT   (1<< ONIGENC_CTYPE_XDIGIT)
#define CTYPE_IS_WORD_GRAPH_PRINT(ctype) \
  ((ctype) == ONIGENC_CTYPE_WORD || (ctype) == ONIGENC_CTYPE_GRAPH ||\
   (ctype) == ONIGENC_CTYPE_PRINT)
#define CTYPE_TO_BIT(ctype)  (1<<(ctype))
#define ENC_FLAG_ASCII_COMPATIBLE      (1<<0)
#define ENC_FLAG_SKIP_OFFSET_0             0
#define ENC_FLAG_SKIP_OFFSET_1         (1<<2)
#define ENC_FLAG_SKIP_OFFSET_1_OR_0    (ENC_SKIP_OFFSET_1_OR_0<<2)
#define ENC_FLAG_SKIP_OFFSET_2         (2<<2)
#define ENC_FLAG_SKIP_OFFSET_3         (3<<2)
#define ENC_FLAG_SKIP_OFFSET_4         (4<<2)
#define ENC_FLAG_SKIP_OFFSET_MASK      (7<<2)
#define ENC_FLAG_UNICODE               (1<<1)
#define ENC_GET_SKIP_OFFSET(enc) \
  (((enc)->flag & ENC_FLAG_SKIP_OFFSET_MASK)>>2)
#define ENC_SKIP_OFFSET_1_OR_0             7
#define FALSE   0
#define FOLDS1_FOLD(i)         (OnigUnicodeFolds1 + (i))
#define FOLDS1_NEXT_INDEX(i)   ((i) + 2 + OnigUnicodeFolds1[(i)+1])
#define FOLDS1_UNFOLDS(i)      (OnigUnicodeFolds1 + (i) + 2)
#define FOLDS1_UNFOLDS_NUM(i)  (OnigUnicodeFolds1[(i)+1])
#define FOLDS2_FOLD(i)         (OnigUnicodeFolds2 + (i))
#define FOLDS2_NEXT_INDEX(i)   ((i) + 3 + OnigUnicodeFolds2[(i)+2])
#define FOLDS2_UNFOLDS(i)      (OnigUnicodeFolds2 + (i) + 3)
#define FOLDS2_UNFOLDS_NUM(i)  (OnigUnicodeFolds2[(i)+2])
#define FOLDS3_FOLD(i)         (OnigUnicodeFolds3 + (i))
#define FOLDS3_NEXT_INDEX(i)   ((i) + 4 + OnigUnicodeFolds3[(i)+3])
#define FOLDS3_UNFOLDS(i)      (OnigUnicodeFolds3 + (i) + 4)
#define FOLDS3_UNFOLDS_NUM(i)  (OnigUnicodeFolds3[(i)+3])
#define FOLDS_FOLD_ADDR_BUK(buk, addr) do {\
  if ((buk)->fold_len == 1)\
    addr = OnigUnicodeFolds1 + (buk)->index;\
  else if ((buk)->fold_len == 2)\
    addr = OnigUnicodeFolds2 + (buk)->index;\
  else if ((buk)->fold_len == 3)\
    addr = OnigUnicodeFolds3 + (buk)->index;\
  else\
    return ONIGERR_INVALID_CODE_POINT_VALUE;\
} while (0)
#define MAX_CODE_POINT         (~((OnigCodePoint )0))
#define NULL   ((void* )0)
#define ONIGENC_ASCII_CODE_TO_LOWER_CASE(c) OnigEncAsciiToLowerCaseTable[c]
#define ONIGENC_ASCII_CODE_TO_UPPER_CASE(c) OnigEncAsciiToUpperCaseTable[c]
#define ONIGENC_ISO_8859_1_TO_LOWER_CASE(c) \
  OnigEncISO_8859_1_ToLowerCaseTable[c]
#define ONIGENC_ISO_8859_1_TO_UPPER_CASE(c) \
  OnigEncISO_8859_1_ToUpperCaseTable[c]
#define ONIGENC_IS_ASCII_CODE(code)  ((code) < 0x80)
#define ONIGENC_IS_ASCII_CODE_CASE_AMBIG(code) \
 (ONIGENC_IS_ASCII_CODE_CTYPE(code, ONIGENC_CTYPE_UPPER) ||\
  ONIGENC_IS_ASCII_CODE_CTYPE(code, ONIGENC_CTYPE_LOWER))
#define ONIGENC_IS_ASCII_CODE_CTYPE(code,ctype) \
  ((OnigEncAsciiCtypeTable[code] & CTYPE_TO_BIT(ctype)) != 0)
#define ONIGENC_IS_ASCII_CODE_WORD(code) \
  ((OnigEncAsciiCtypeTable[code] & CTYPE_TO_BIT(ONIGENC_CTYPE_WORD)) != 0)
#define ONIGENC_IS_ASCII_COMPATIBLE_ENCODING(enc)  \
  (((enc)->flag & ENC_FLAG_ASCII_COMPATIBLE) != 0)
#define ONIGENC_IS_UNICODE_ENCODING(enc) \
  (((enc)->flag & ENC_FLAG_UNICODE) != 0)

#define ONIG_CHECK_NULL_RETURN(p)          if (ONIG_IS_NULL(p)) return NULL
#define ONIG_CHECK_NULL_RETURN_VAL(p,val)  if (ONIG_IS_NULL(p)) return (val)
#define ONIG_ENCODING_INIT_DEFAULT           ONIG_ENCODING_ASCII
#define ONIG_IS_NOT_NULL(p)                (((void*)(p)) != (void*)0)
#define ONIG_IS_NULL(p)                    (((void*)(p)) == (void*)0)

#define TRUE    1



#define UTF16_IS_SURROGATE_FIRST(c)    (((c) & 0xfc) == 0xd8)
#define UTF16_IS_SURROGATE_SECOND(c)   (((c) & 0xfc) == 0xdc)
#define enclen(enc,p)          ONIGENC_MBC_ENC_LEN(enc,p)
#define INTERNAL_ONIGENC_CASE_FOLD_MULTI_CHAR   (1<<30)
#define ONIGENC_APPLY_ALL_CASE_FOLD(enc,case_fold_flag,f,arg) \
        (enc)->apply_all_case_fold(case_fold_flag,f,arg)
#define ONIGENC_CASE_FOLD_DEFAULT  OnigDefaultCaseFoldFlag
#define ONIGENC_CASE_FOLD_MIN      INTERNAL_ONIGENC_CASE_FOLD_MULTI_CHAR
#define ONIGENC_CASE_FOLD_TURKISH_AZERI         (1<<20)
#define ONIGENC_CODE_RANGE_FROM(range,i)  range[((i)*2) + 1]
#define ONIGENC_CODE_RANGE_NUM(range)     ((int )range[0])
#define ONIGENC_CODE_RANGE_TO(range,i)    range[((i)*2) + 2]
#define ONIGENC_CODE_TO_MBC(enc,code,buf)      (enc)->code_to_mbc(code,buf)
#define ONIGENC_CODE_TO_MBCLEN(enc,code)       (enc)->code_to_mbclen(code)
#define ONIGENC_CODE_TO_MBC_MAXLEN       7
#define ONIGENC_GET_CASE_FOLD_CODES_BY_STR(enc,case_fold_flag,p,end,acs) \
       (enc)->get_case_fold_codes_by_str(case_fold_flag,p,end,acs)
#define ONIGENC_GET_CASE_FOLD_CODES_MAX_NUM      13
#define ONIGENC_GET_CTYPE_CODE_RANGE(enc,ctype,sbout,ranges) \
        (enc)->get_ctype_code_range(ctype,sbout,ranges)
#define ONIGENC_IS_ALLOWED_REVERSE_MATCH(enc,s,end) \
        (enc)->is_allowed_reverse_match(s,end)
#define ONIGENC_IS_CODE_ALNUM(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_ALNUM)
#define ONIGENC_IS_CODE_ALPHA(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_ALPHA)
#define ONIGENC_IS_CODE_ASCII(code)       ((code) < 128)
#define ONIGENC_IS_CODE_BLANK(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_BLANK)
#define ONIGENC_IS_CODE_CNTRL(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_CNTRL)
#define ONIGENC_IS_CODE_CTYPE(enc,code,ctype)  (enc)->is_code_ctype(code,ctype)
#define ONIGENC_IS_CODE_DIGIT(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_DIGIT)
#define ONIGENC_IS_CODE_GRAPH(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_GRAPH)
#define ONIGENC_IS_CODE_LOWER(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_LOWER)
#define ONIGENC_IS_CODE_NEWLINE(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_NEWLINE)
#define ONIGENC_IS_CODE_PRINT(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_PRINT)
#define ONIGENC_IS_CODE_PUNCT(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_PUNCT)
#define ONIGENC_IS_CODE_SPACE(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_SPACE)
#define ONIGENC_IS_CODE_UPPER(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_UPPER)
#define ONIGENC_IS_CODE_WORD(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_WORD)
#define ONIGENC_IS_CODE_XDIGIT(enc,code) \
        ONIGENC_IS_CODE_CTYPE(enc,code,ONIGENC_CTYPE_XDIGIT)
#define ONIGENC_IS_MBC_ASCII(p)           (*(p)   < 128)
#define ONIGENC_IS_MBC_HEAD(enc,p)     (ONIGENC_MBC_ENC_LEN(enc,p) != 1)
#define ONIGENC_IS_MBC_NEWLINE(enc,p,end)      (enc)->is_mbc_newline((p),(end))
#define ONIGENC_IS_MBC_WORD(enc,s,end) \
   ONIGENC_IS_CODE_WORD(enc,ONIGENC_MBC_TO_CODE(enc,s,end))
#define ONIGENC_IS_MBC_WORD_ASCII(enc,s,end) onigenc_is_mbc_word_ascii(enc,s,end)
#define ONIGENC_IS_SINGLEBYTE(enc)     (ONIGENC_MBC_MAXLEN(enc) == 1)
#define ONIGENC_IS_UNDEF(enc)          ((enc) == ONIG_ENCODING_UNDEF)
#define ONIGENC_IS_VALID_MBC_STRING(enc,s,end) \
        (enc)->is_valid_mbc_string(s,end)
#define ONIGENC_LEFT_ADJUST_CHAR_HEAD(enc,start,s) \
        (enc)->left_adjust_char_head(start, s)
#define ONIGENC_MAX_COMP_CASE_FOLD_CODE_LEN       3
#define ONIGENC_MAX_STD_CTYPE  ONIGENC_CTYPE_ASCII
#define ONIGENC_MBC_CASE_FOLD(enc,flag,pp,end,buf) \
  (enc)->mbc_case_fold(flag,(const OnigUChar** )pp,end,buf)
#define ONIGENC_MBC_CASE_FOLD_MAXLEN    18
#define ONIGENC_MBC_ENC_LEN(enc,p)             (enc)->mbc_enc_len(p)
#define ONIGENC_MBC_MAXLEN(enc)               ((enc)->max_enc_len)
#define ONIGENC_MBC_MAXLEN_DIST(enc)           ONIGENC_MBC_MAXLEN(enc)
#define ONIGENC_MBC_MINLEN(enc)               ((enc)->min_enc_len)
#define ONIGENC_MBC_TO_CODE(enc,p,end)         (enc)->mbc_to_code((p),(end))
#define ONIGENC_NAME(enc)                      ((enc)->name)
#define ONIGENC_PROPERTY_NAME_TO_CTYPE(enc,p,end) \
  (enc)->property_name_to_ctype(enc,p,end)
#define ONIGENC_STEP_BACK(enc,start,s,n) \
        onigenc_step_back((enc),(start),(s),(n))
#define ONIGERR_CHAR_CLASS_VALUE_AT_END_OF_RANGE             -110
#define ONIGERR_CHAR_CLASS_VALUE_AT_START_OF_RANGE           -111
#define ONIGERR_CONTROL_CODE_SYNTAX                          -109
#define ONIGERR_DEFAULT_ENCODING_IS_NOT_SETTED                -21
#define ONIGERR_EMPTY_CHAR_CLASS                             -102
#define ONIGERR_EMPTY_GROUP_NAME                             -214
#define ONIGERR_EMPTY_RANGE_IN_CHAR_CLASS                    -203
#define ONIGERR_END_PATTERN_AT_CONTROL                       -106
#define ONIGERR_END_PATTERN_AT_ESCAPE                        -104
#define ONIGERR_END_PATTERN_AT_LEFT_BRACE                    -100
#define ONIGERR_END_PATTERN_AT_LEFT_BRACKET                  -101
#define ONIGERR_END_PATTERN_AT_META                          -105
#define ONIGERR_END_PATTERN_IN_GROUP                         -118
#define ONIGERR_END_PATTERN_WITH_UNMATCHED_PARENTHESIS       -117
#define ONIGERR_FAIL_TO_INITIALIZE                            -23
#define ONIGERR_GROUP_NUMBER_OVER_FOR_CAPTURE_HISTORY        -222
#define ONIGERR_INVALID_ABSENT_GROUP_GENERATOR_PATTERN       -226
#define ONIGERR_INVALID_ABSENT_GROUP_PATTERN                 -225
#define ONIGERR_INVALID_ARGUMENT                              -30
#define ONIGERR_INVALID_BACKREF                              -208
#define ONIGERR_INVALID_CALLOUT_ARG                          -232
#define ONIGERR_INVALID_CALLOUT_BODY                         -230
#define ONIGERR_INVALID_CALLOUT_NAME                         -228
#define ONIGERR_INVALID_CALLOUT_PATTERN                      -227
#define ONIGERR_INVALID_CALLOUT_TAG_NAME                     -231
#define ONIGERR_INVALID_CHAR_IN_GROUP_NAME                   -216
#define ONIGERR_INVALID_CHAR_PROPERTY_NAME                   -223
#define ONIGERR_INVALID_CODE_POINT_VALUE                     -400
#define ONIGERR_INVALID_COMBINATION_OF_OPTIONS               -403
#define ONIGERR_INVALID_GROUP_NAME                           -215
#define ONIGERR_INVALID_IF_ELSE_SYNTAX                       -224
#define ONIGERR_INVALID_LOOK_BEHIND_PATTERN                  -122
#define ONIGERR_INVALID_POSIX_BRACKET_TYPE                   -121
#define ONIGERR_INVALID_REPEAT_RANGE_PATTERN                 -123
#define ONIGERR_INVALID_WIDE_CHAR_VALUE                      -400
#define ONIGERR_LIBRARY_IS_NOT_INITIALIZED                   -500
#define ONIGERR_MATCH_STACK_LIMIT_OVER                        -15
#define ONIGERR_MEMORY                                         -5
#define ONIGERR_META_CODE_SYNTAX                             -108
#define ONIGERR_MISMATCH_CODE_LENGTH_IN_CLASS_RANGE          -204
#define ONIGERR_MULTIPLEX_DEFINED_NAME                       -219
#define ONIGERR_MULTIPLEX_DEFINITION_NAME_CALL               -220
#define ONIGERR_NESTED_REPEAT_OPERATOR                       -115
#define ONIGERR_NEVER_ENDING_RECURSION                       -221
#define ONIGERR_NOT_SUPPORTED_ENCODING_COMBINATION           -402
#define ONIGERR_NUMBERED_BACKREF_OR_CALL_NOT_ALLOWED         -209
#define ONIGERR_PARSER_BUG                                    -11
#define ONIGERR_PARSE_DEPTH_LIMIT_OVER                        -16
#define ONIGERR_PREMATURE_END_OF_CHAR_CLASS                  -103
#define ONIGERR_RETRY_LIMIT_IN_MATCH_OVER                     -17
#define ONIGERR_SPECIFIED_ENCODING_CANT_CONVERT_TO_WIDE_CHAR  -22
#define ONIGERR_STACK_BUG                                     -12
#define ONIGERR_TARGET_OF_REPEAT_OPERATOR_INVALID            -114
#define ONIGERR_TARGET_OF_REPEAT_OPERATOR_NOT_SPECIFIED      -113
#define ONIGERR_TOO_BIG_BACKREF_NUMBER                       -207
#define ONIGERR_TOO_BIG_NUMBER                               -200
#define ONIGERR_TOO_BIG_NUMBER_FOR_REPEAT_RANGE              -201
#define ONIGERR_TOO_BIG_WIDE_CHAR_VALUE                      -401
#define ONIGERR_TOO_LONG_PROPERTY_NAME                       -405
#define ONIGERR_TOO_LONG_WIDE_CHAR_VALUE                     -212
#define ONIGERR_TOO_MANY_CAPTURES                            -210
#define ONIGERR_TOO_MANY_MULTI_BYTE_RANGES                   -205
#define ONIGERR_TOO_MANY_USER_DEFINED_OBJECTS                -404
#define ONIGERR_TOO_SHORT_MULTI_BYTE_STRING                  -206
#define ONIGERR_TYPE_BUG                                       -6
#define ONIGERR_UNDEFINED_BYTECODE                            -13
#define ONIGERR_UNDEFINED_CALLOUT_NAME                       -229
#define ONIGERR_UNDEFINED_GROUP_OPTION                       -119
#define ONIGERR_UNDEFINED_GROUP_REFERENCE                    -218
#define ONIGERR_UNDEFINED_NAME_REFERENCE                     -217
#define ONIGERR_UNEXPECTED_BYTECODE                           -14
#define ONIGERR_UNMATCHED_CLOSE_PARENTHESIS                  -116
#define ONIGERR_UNMATCHED_RANGE_SPECIFIER_IN_CHAR_CLASS      -112
#define ONIGERR_UPPER_SMALLER_THAN_LOWER_IN_REPEAT_RANGE     -202


#define ONIGURUMA_VERSION_INT     60902
#define ONIGURUMA_VERSION_MAJOR   6
#define ONIGURUMA_VERSION_MINOR   9
#define ONIGURUMA_VERSION_TEENY   2
#define ONIG_ABORT                                            -3
#define ONIG_CALLOUT_DATA_SLOT_NUM    5
#define ONIG_CALLOUT_IN_BOTH  (ONIG_CALLOUT_IN_PROGRESS | ONIG_CALLOUT_IN_RETRACTION)
#define ONIG_CALLOUT_MAX_ARGS_NUM     4
#define ONIG_CHAR_TABLE_SIZE   256
#define ONIG_ENCODING_ASCII        (&OnigEncodingASCII)
#define ONIG_ENCODING_BIG5         (&OnigEncodingBIG5)
#define ONIG_ENCODING_CP1251       (&OnigEncodingCP1251)
#define ONIG_ENCODING_EUC_CN       (&OnigEncodingEUC_CN)
#define ONIG_ENCODING_EUC_JP       (&OnigEncodingEUC_JP)
#define ONIG_ENCODING_EUC_KR       (&OnigEncodingEUC_KR)
#define ONIG_ENCODING_EUC_TW       (&OnigEncodingEUC_TW)
#define ONIG_ENCODING_GB18030      (&OnigEncodingGB18030)
#define ONIG_ENCODING_ISO_8859_1   (&OnigEncodingISO_8859_1)
#define ONIG_ENCODING_ISO_8859_10  (&OnigEncodingISO_8859_10)
#define ONIG_ENCODING_ISO_8859_11  (&OnigEncodingISO_8859_11)
#define ONIG_ENCODING_ISO_8859_13  (&OnigEncodingISO_8859_13)
#define ONIG_ENCODING_ISO_8859_14  (&OnigEncodingISO_8859_14)
#define ONIG_ENCODING_ISO_8859_15  (&OnigEncodingISO_8859_15)
#define ONIG_ENCODING_ISO_8859_16  (&OnigEncodingISO_8859_16)
#define ONIG_ENCODING_ISO_8859_2   (&OnigEncodingISO_8859_2)
#define ONIG_ENCODING_ISO_8859_3   (&OnigEncodingISO_8859_3)
#define ONIG_ENCODING_ISO_8859_4   (&OnigEncodingISO_8859_4)
#define ONIG_ENCODING_ISO_8859_5   (&OnigEncodingISO_8859_5)
#define ONIG_ENCODING_ISO_8859_6   (&OnigEncodingISO_8859_6)
#define ONIG_ENCODING_ISO_8859_7   (&OnigEncodingISO_8859_7)
#define ONIG_ENCODING_ISO_8859_8   (&OnigEncodingISO_8859_8)
#define ONIG_ENCODING_ISO_8859_9   (&OnigEncodingISO_8859_9)
#define ONIG_ENCODING_KOI8         (&OnigEncodingKOI8)
#define ONIG_ENCODING_KOI8_R       (&OnigEncodingKOI8_R)
#define ONIG_ENCODING_SJIS         (&OnigEncodingSJIS)
#define ONIG_ENCODING_UNDEF    ((OnigEncoding )0)
#define ONIG_ENCODING_UTF16_BE     (&OnigEncodingUTF16_BE)
#define ONIG_ENCODING_UTF16_LE     (&OnigEncodingUTF16_LE)
#define ONIG_ENCODING_UTF32_BE     (&OnigEncodingUTF32_BE)
#define ONIG_ENCODING_UTF32_LE     (&OnigEncodingUTF32_LE)
#define ONIG_ENCODING_UTF8         (&OnigEncodingUTF8)
#define ONIG_EXTERN   extern __declspec(dllexport)
#define ONIG_INEFFECTIVE_META_CHAR          0
#define ONIG_INFINITE_DISTANCE  ~((OnigLen )0)
#define ONIG_IS_CAPTURE_HISTORY_GROUP(r, i) \
  ((i) <= ONIG_MAX_CAPTURE_HISTORY_GROUP && (r)->list && (r)->list[i])
#define ONIG_IS_OPTION_ON(options,option)   ((options) & (option))
#define ONIG_IS_PATTERN_ERROR(ecode)   ((ecode) <= -100 && (ecode) > -1000)
#define ONIG_MAX_BACKREF_NUM                1000
#define ONIG_MAX_CAPTURE_HISTORY_GROUP   31
#define ONIG_MAX_CAPTURE_NUM          2147483647  
#define ONIG_MAX_ERROR_MESSAGE_LEN            90
#define ONIG_MAX_MULTI_BYTE_RANGES_NUM     10000
#define ONIG_MAX_REPEAT_NUM               100000
#define ONIG_META_CHAR_ANYCHAR              1
#define ONIG_META_CHAR_ANYCHAR_ANYTIME      5
#define ONIG_META_CHAR_ANYTIME              2
#define ONIG_META_CHAR_ESCAPE               0
#define ONIG_META_CHAR_ONE_OR_MORE_TIME     4
#define ONIG_META_CHAR_ZERO_OR_ONE_TIME     3
#define ONIG_MISMATCH                                         -1
#define ONIG_NON_CALLOUT_NUM     0
#define ONIG_NON_NAME_ID        -1
#define ONIG_NORMAL                                            0
#define ONIG_NO_SUPPORT_CONFIG                                -2
#define ONIG_NREGION                          10
#define ONIG_NULL_WARN       onig_null_warn
#define ONIG_OPTION_CAPTURE_GROUP        (ONIG_OPTION_DONT_CAPTURE_GROUP << 1)
#define ONIG_OPTION_CHECK_VALIDITY_OF_STRING  (ONIG_OPTION_POSIX_REGION << 1)
#define ONIG_OPTION_DEFAULT            ONIG_OPTION_NONE
#define ONIG_OPTION_DIGIT_IS_ASCII       (ONIG_OPTION_WORD_IS_ASCII << 1)
#define ONIG_OPTION_DONT_CAPTURE_GROUP   (ONIG_OPTION_NEGATE_SINGLELINE  << 1)
#define ONIG_OPTION_EXTEND               (ONIG_OPTION_IGNORECASE         << 1)
#define ONIG_OPTION_FIND_LONGEST         (ONIG_OPTION_SINGLELINE         << 1)
#define ONIG_OPTION_FIND_NOT_EMPTY       (ONIG_OPTION_FIND_LONGEST       << 1)
#define ONIG_OPTION_IGNORECASE           1U
#define ONIG_OPTION_MAXBIT               ONIG_OPTION_TEXT_SEGMENT_WORD  
#define ONIG_OPTION_MULTILINE            (ONIG_OPTION_EXTEND             << 1)
#define ONIG_OPTION_NEGATE_SINGLELINE    (ONIG_OPTION_FIND_NOT_EMPTY     << 1)
#define ONIG_OPTION_NONE                 0U
#define ONIG_OPTION_NOTBOL                    (ONIG_OPTION_CAPTURE_GROUP << 1)
#define ONIG_OPTION_NOTEOL                    (ONIG_OPTION_NOTBOL << 1)
#define ONIG_OPTION_OFF(options,regopt)     ((options) &= ~(regopt))
#define ONIG_OPTION_ON(options,regopt)      ((options) |= (regopt))
#define ONIG_OPTION_POSIX_IS_ASCII       (ONIG_OPTION_SPACE_IS_ASCII << 1)
#define ONIG_OPTION_POSIX_REGION              (ONIG_OPTION_NOTEOL << 1)
#define ONIG_OPTION_SINGLELINE           (ONIG_OPTION_MULTILINE          << 1)
#define ONIG_OPTION_SPACE_IS_ASCII       (ONIG_OPTION_DIGIT_IS_ASCII << 1)
#define ONIG_OPTION_TEXT_SEGMENT_EXTENDED_GRAPHEME_CLUSTER  (ONIG_OPTION_POSIX_IS_ASCII << 1)
#define ONIG_OPTION_TEXT_SEGMENT_WORD    (ONIG_OPTION_TEXT_SEGMENT_EXTENDED_GRAPHEME_CLUSTER << 1)
#define ONIG_OPTION_WORD_IS_ASCII        (ONIG_OPTION_CHECK_VALIDITY_OF_STRING << 4)
#define ONIG_REGION_NOTPOS            -1
#define ONIG_SYNTAX_ASIS               (&OnigSyntaxASIS)
#define ONIG_SYNTAX_DEFAULT   OnigDefaultSyntax
#define ONIG_SYNTAX_EMACS              (&OnigSyntaxEmacs)
#define ONIG_SYNTAX_GNU_REGEX          (&OnigSyntaxGnuRegex)
#define ONIG_SYNTAX_GREP               (&OnigSyntaxGrep)
#define ONIG_SYNTAX_JAVA               (&OnigSyntaxJava)
#define ONIG_SYNTAX_ONIGURUMA          (&OnigSyntaxOniguruma)
#define ONIG_SYNTAX_PERL               (&OnigSyntaxPerl)
#define ONIG_SYNTAX_PERL_NG            (&OnigSyntaxPerl_NG)
#define ONIG_SYNTAX_POSIX_BASIC        (&OnigSyntaxPosixBasic)
#define ONIG_SYNTAX_POSIX_EXTENDED     (&OnigSyntaxPosixExtended)
#define ONIG_SYNTAX_RUBY               (&OnigSyntaxRuby)
#define ONIG_SYN_ALLOW_DOUBLE_RANGE_OP_IN_CC     (1U<<23) 
#define ONIG_SYN_ALLOW_EMPTY_RANGE_IN_CC         (1U<<22)
#define ONIG_SYN_ALLOW_INTERVAL_LOW_ABBREV       (1U<<4)  
#define ONIG_SYN_ALLOW_INVALID_INTERVAL          (1U<<3)  
#define ONIG_SYN_ALLOW_MULTIPLEX_DEFINITION_NAME (1U<<8)  
#define ONIG_SYN_ALLOW_UNMATCHED_CLOSE_SUBEXP    (1U<<2)  
#define ONIG_SYN_BACKSLASH_ESCAPE_IN_CC          (1U<<21) 
#define ONIG_SYN_CAPTURE_ONLY_NAMED_GROUP        (1U<<7)  
#define ONIG_SYN_CONTEXT_INDEP_ANCHORS           (1U<<31) 
#define ONIG_SYN_CONTEXT_INDEP_REPEAT_OPS        (1U<<0)  
#define ONIG_SYN_CONTEXT_INVALID_REPEAT_OPS      (1U<<1)  
#define ONIG_SYN_DIFFERENT_LEN_ALT_LOOK_BEHIND   (1U<<6)  
#define ONIG_SYN_FIXED_INTERVAL_IS_GREEDY_ONLY   (1U<<9)  
#define ONIG_SYN_NOT_NEWLINE_IN_NEGATIVE_CC      (1U<<20) 
#define ONIG_SYN_OP2_ASTERISK_CALLOUT_NAME      (1U<<29) 
#define ONIG_SYN_OP2_ATMARK_CAPTURE_HISTORY     (1U<<10) 
#define ONIG_SYN_OP2_CCLASS_SET_OP              (1U<<6)  
#define ONIG_SYN_OP2_ESC_CAPITAL_C_BAR_CONTROL  (1U<<11) 
#define ONIG_SYN_OP2_ESC_CAPITAL_K_KEEP         (1U<<22) 
#define ONIG_SYN_OP2_ESC_CAPITAL_M_BAR_META     (1U<<12) 
#define ONIG_SYN_OP2_ESC_CAPITAL_N_O_SUPER_DOT  (1U<<24) 
#define ONIG_SYN_OP2_ESC_CAPITAL_Q_QUOTE        (1U<<0)  
#define ONIG_SYN_OP2_ESC_CAPITAL_R_GENERAL_NEWLINE (1U<<23) 
#define ONIG_SYN_OP2_ESC_GNU_BUF_ANCHOR         (1U<<15) 
#define ONIG_SYN_OP2_ESC_G_SUBEXP_CALL          (1U<<9)  
#define ONIG_SYN_OP2_ESC_H_XDIGIT               (1U<<19) 
#define ONIG_SYN_OP2_ESC_K_NAMED_BACKREF        (1U<<8)  
#define ONIG_SYN_OP2_ESC_P_BRACE_CHAR_PROPERTY  (1U<<16) 
#define ONIG_SYN_OP2_ESC_P_BRACE_CIRCUMFLEX_NOT (1U<<17) 
#define ONIG_SYN_OP2_ESC_U_HEX4                 (1U<<14) 
#define ONIG_SYN_OP2_ESC_V_VTAB                 (1U<<13) 
#define ONIG_SYN_OP2_ESC_X_Y_GRAPHEME_CLUSTER   (1U<<26) 
#define ONIG_SYN_OP2_ESC_X_Y_TEXT_SEGMENT       (1U<<26) 
#define ONIG_SYN_OP2_INEFFECTIVE_ESCAPE         (1U<<20) 
#define ONIG_SYN_OP2_OPTION_ONIGURUMA           (1U<<30) 
#define ONIG_SYN_OP2_OPTION_PERL                (1U<<2)  
#define ONIG_SYN_OP2_OPTION_RUBY                (1U<<3)  
#define ONIG_SYN_OP2_PLUS_POSSESSIVE_INTERVAL   (1U<<5)  
#define ONIG_SYN_OP2_PLUS_POSSESSIVE_REPEAT     (1U<<4)  
#define ONIG_SYN_OP2_QMARK_BRACE_CALLOUT_CONTENTS (1U<<28) 
#define ONIG_SYN_OP2_QMARK_GROUP_EFFECT         (1U<<1)  
#define ONIG_SYN_OP2_QMARK_LPAREN_IF_ELSE       (1U<<21) 
#define ONIG_SYN_OP2_QMARK_LT_NAMED_GROUP       (1U<<7)  
#define ONIG_SYN_OP2_QMARK_PERL_SUBEXP_CALL     (1U<<27) 
#define ONIG_SYN_OP2_QMARK_TILDE_ABSENT_GROUP   (1U<<25) 
#define ONIG_SYN_OP_ASTERISK_ZERO_INF           (1U<<2)   
#define ONIG_SYN_OP_BRACE_INTERVAL              (1U<<8)   
#define ONIG_SYN_OP_BRACKET_CC                  (1U<<17)  
#define ONIG_SYN_OP_DECIMAL_BACKREF             (1U<<16)  
#define ONIG_SYN_OP_DOT_ANYCHAR                 (1U<<1)   
#define ONIG_SYN_OP_ESC_ASTERISK_ZERO_INF       (1U<<3)
#define ONIG_SYN_OP_ESC_AZ_BUF_ANCHOR           (1U<<14)  
#define ONIG_SYN_OP_ESC_BRACE_INTERVAL          (1U<<9)   
#define ONIG_SYN_OP_ESC_B_WORD_BOUND            (1U<<20)  
#define ONIG_SYN_OP_ESC_CAPITAL_G_BEGIN_ANCHOR  (1U<<15)  
#define ONIG_SYN_OP_ESC_CONTROL_CHARS           (1U<<26)  
#define ONIG_SYN_OP_ESC_C_CONTROL               (1U<<27)  
#define ONIG_SYN_OP_ESC_D_DIGIT                 (1U<<22)  
#define ONIG_SYN_OP_ESC_LPAREN_SUBEXP           (1U<<13)  
#define ONIG_SYN_OP_ESC_LTGT_WORD_BEGIN_END     (1U<<19)  
#define ONIG_SYN_OP_ESC_OCTAL3                  (1U<<28)  
#define ONIG_SYN_OP_ESC_O_BRACE_OCTAL           (1U<<31)  
#define ONIG_SYN_OP_ESC_PLUS_ONE_INF            (1U<<5)
#define ONIG_SYN_OP_ESC_QMARK_ZERO_ONE          (1U<<7)
#define ONIG_SYN_OP_ESC_S_WHITE_SPACE           (1U<<21)  
#define ONIG_SYN_OP_ESC_VBAR_ALT                (1U<<11)  
#define ONIG_SYN_OP_ESC_W_WORD                  (1U<<18)  
#define ONIG_SYN_OP_ESC_X_BRACE_HEX8            (1U<<30)  
#define ONIG_SYN_OP_ESC_X_HEX2                  (1U<<29)  
#define ONIG_SYN_OP_LINE_ANCHOR                 (1U<<23)  
#define ONIG_SYN_OP_LPAREN_SUBEXP               (1U<<12)  
#define ONIG_SYN_OP_PLUS_ONE_INF                (1U<<4)   
#define ONIG_SYN_OP_POSIX_BRACKET               (1U<<24)  
#define ONIG_SYN_OP_QMARK_NON_GREEDY            (1U<<25)  
#define ONIG_SYN_OP_QMARK_ZERO_ONE              (1U<<6)   
#define ONIG_SYN_OP_VARIABLE_META_CHARACTERS    (1U<<0)
#define ONIG_SYN_OP_VBAR_ALT                    (1U<<10)   
#define ONIG_SYN_STRICT_CHECK_BACKREF            (1U<<5)  
#define ONIG_SYN_WARN_CC_OP_NOT_ESCAPED          (1U<<24) 
#define ONIG_SYN_WARN_REDUNDANT_NESTED_REPEAT    (1U<<25) 
#define ONIG_TRAVERSE_CALLBACK_AT_BOTH \
  ( ONIG_TRAVERSE_CALLBACK_AT_FIRST | ONIG_TRAVERSE_CALLBACK_AT_LAST )
#define ONIG_TRAVERSE_CALLBACK_AT_FIRST   1
#define ONIG_TRAVERSE_CALLBACK_AT_LAST    2
# define PV_(args) args
# define P_(args) args
#define UChar OnigUChar
#define onig_enc_len(enc,p,end)        ONIGENC_MBC_ENC_LEN(enc,p)
