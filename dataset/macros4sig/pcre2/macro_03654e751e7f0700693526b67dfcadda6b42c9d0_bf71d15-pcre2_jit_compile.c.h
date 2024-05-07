


#include<string.h>

#include<stddef.h>


#include<stdio.h>



#include<stdlib.h>


#include<limits.h>
#include<ctype.h>

#define C(X) case X: return VEXTQ(zero, a, VECTOR_FACTOR - X);









# define FF_UTF
#define JIT_HAS_FAST_FORWARD_CHAR_PAIR_SIMD 1
#define JIT_HAS_FAST_FORWARD_CHAR_SIMD 1
#define JIT_HAS_FAST_REQUESTED_CHAR_SIMD 1
#define SSE2_COMPARE_TYPE_INDEX 0
# define VANDQ vandq_u8
# define VCEQQ vceqq_u8
# define VDUPQ vdupq_n_u8
#define VECTOR_ELEMENT_SIZE 0
# define VECTOR_FACTOR 16
# define VEXTQ vextq_u8
# define VLD1Q(X) vld1q_u8((sljit_u8 *)(X))
# define VORRQ vorrq_u8
# define VST1Q vst1q_u8
# define vect_t uint8x16_t
#   define FF_FUN ffcs_utf
#define ADDRESSING_DEPENDS_ON(exp, reg) \
	(((exp) & SLJIT_MEM) && (((exp) & REG_MASK) == reg || OFFS_REG(exp) == reg))
#define ADJUST_LOCAL_OFFSET(p, i) \
	if ((p) == (SLJIT_MEM1(SLJIT_SP))) \
		(i) += SLJIT_LOCALS_OFFSET;
#define CHECK(x) \
	do { \
		if (SLJIT_UNLIKELY(x)) { \
			compiler->error = SLJIT_ERR_BAD_ARGUMENT; \
			return SLJIT_ERR_BAD_ARGUMENT; \
		} \
	} while (0)
#define CHECK_ARGUMENT(x) \
	do { \
		if (SLJIT_UNLIKELY(!(x))) \
			return 1; \
	} while (0)
#define CHECK_ERROR() \
	do { \
		if (SLJIT_UNLIKELY(compiler->error)) \
			return compiler->error; \
	} while (0)
#define CHECK_ERROR_PTR() \
	do { \
		if (SLJIT_UNLIKELY(compiler->error)) \
			return NULL; \
	} while (0)
#define CHECK_IF_VIRTUAL_REGISTER(p) ((p) <= SLJIT_S3 && (p) >= SLJIT_S8)
#define CHECK_PTR(x) \
	do { \
		if (SLJIT_UNLIKELY(x)) { \
			compiler->error = SLJIT_ERR_BAD_ARGUMENT; \
			return NULL; \
		} \
	} while (0)
#define CHECK_REG_INDEX(x) \
	do { \
		if (SLJIT_UNLIKELY(x)) { \
			return -2; \
		} \
	} while (0)
#define CHECK_RETURN_OK return 0
#define CHECK_RETURN_TYPE sljit_s32
#define FAIL_IF(expr) \
	do { \
		if (SLJIT_UNLIKELY(expr)) \
			return compiler->error; \
	} while (0)
#define FAIL_IF_NULL(ptr) \
	do { \
		if (SLJIT_UNLIKELY(!(ptr))) { \
			compiler->error = SLJIT_ERR_ALLOC_FAILED; \
			return SLJIT_ERR_ALLOC_FAILED; \
		} \
	} while (0)
#define FAST_IS_REG(reg)	((reg) <= REG_MASK)
#define FUNCTION_CHECK_DST(p, i) \
	CHECK_ARGUMENT(function_check_dst(compiler, p, i));
#define FUNCTION_CHECK_IS_FREG(fr) \
	(((fr) >= SLJIT_FR0 && (fr) < (SLJIT_FR0 + compiler->fscratches)) \
	|| ((fr) > (SLJIT_FS0 - compiler->fsaveds) && (fr) <= SLJIT_FS0))
#define FUNCTION_CHECK_IS_REG(r) \
	(((r) >= SLJIT_R0 && (r) < (SLJIT_R0 + compiler->scratches)) \
	|| ((r) > (SLJIT_S0 - compiler->saveds) && (r) <= SLJIT_S0))
#define FUNCTION_CHECK_SRC(p, i) \
	CHECK_ARGUMENT(function_check_src(compiler, p, i));
#define FUNCTION_CHECK_SRC_MEM(p, i) \
	CHECK_ARGUMENT(function_check_src_mem(compiler, p, i));
#define FUNCTION_FCHECK(p, i) \
	CHECK_ARGUMENT(function_fcheck(compiler, p, i));
#define GET_ALL_FLAGS(op) \
	((op) & (SLJIT_32 | SLJIT_SET_Z | VARIABLE_FLAG_MASK))
#define GET_FLAG_TYPE(op) ((op) >> VARIABLE_FLAG_SHIFT)
#define GET_OPCODE(op) \
	((op) & ~(SLJIT_32 | SLJIT_SET_Z | VARIABLE_FLAG_MASK))
#define GET_SAVED_FLOAT_REGISTERS_SIZE(fscratches, fsaveds, size) \
	(((fscratches < SLJIT_NUMBER_OF_SCRATCH_FLOAT_REGISTERS ? 0 : (fscratches - SLJIT_NUMBER_OF_SCRATCH_FLOAT_REGISTERS)) + \
		(fsaveds)) * (sljit_s32)(size))
#define GET_SAVED_REGISTERS_SIZE(scratches, saveds, extra) \
	(((scratches < SLJIT_NUMBER_OF_SCRATCH_REGISTERS ? 0 : (scratches - SLJIT_NUMBER_OF_SCRATCH_REGISTERS)) + \
		(saveds) + (sljit_s32)(extra)) * (sljit_s32)sizeof(sljit_sw))
#define HAS_FLAGS(op) \
	((op) & (SLJIT_SET_Z | VARIABLE_FLAG_MASK))
#define JUMP_POSTFIX(type) \
	((type & 0xff) <= SLJIT_NOT_OVERFLOW ? ((type & SLJIT_32) ? "32" : "") \
	: ((type & 0xff) <= SLJIT_ORDERED_F64 ? ((type & SLJIT_32) ? ".f32" : ".f64") : ""))
#define OFFS_REG(reg)		(((reg) >> 8) & REG_MASK)
#define PTR_FAIL_IF(expr) \
	do { \
		if (SLJIT_UNLIKELY(expr)) \
			return NULL; \
	} while (0)
#define PTR_FAIL_IF_NULL(ptr) \
	do { \
		if (SLJIT_UNLIKELY(!(ptr))) { \
			compiler->error = SLJIT_ERR_ALLOC_FAILED; \
			return NULL; \
		} \
	} while (0)
#define PTR_FAIL_WITH_EXEC_IF(ptr) \
	do { \
		if (SLJIT_UNLIKELY(!(ptr))) { \
			compiler->error = SLJIT_ERR_EX_ALLOC_FAILED; \
			return NULL; \
		} \
	} while (0)
#define SELECT_FOP1_OPERATION_WITH_CHECKS(compiler, op, dst, dstw, src, srcw) \
	SLJIT_COMPILE_ASSERT(!(SLJIT_CONV_SW_FROM_F64 & 0x1) && !(SLJIT_CONV_F64_FROM_SW & 0x1), \
		invalid_float_opcodes); \
	if (GET_OPCODE(op) >= SLJIT_CONV_SW_FROM_F64 && GET_OPCODE(op) <= SLJIT_CMP_F64) { \
		if (GET_OPCODE(op) == SLJIT_CMP_F64) { \
			CHECK(check_sljit_emit_fop1_cmp(compiler, op, dst, dstw, src, srcw)); \
			ADJUST_LOCAL_OFFSET(dst, dstw); \
			ADJUST_LOCAL_OFFSET(src, srcw); \
			return sljit_emit_fop1_cmp(compiler, op, dst, dstw, src, srcw); \
		} \
		if ((GET_OPCODE(op) | 0x1) == SLJIT_CONV_S32_FROM_F64) { \
			CHECK(check_sljit_emit_fop1_conv_sw_from_f64(compiler, op, dst, dstw, src, srcw)); \
			ADJUST_LOCAL_OFFSET(dst, dstw); \
			ADJUST_LOCAL_OFFSET(src, srcw); \
			return sljit_emit_fop1_conv_sw_from_f64(compiler, op, dst, dstw, src, srcw); \
		} \
		CHECK(check_sljit_emit_fop1_conv_f64_from_sw(compiler, op, dst, dstw, src, srcw)); \
		ADJUST_LOCAL_OFFSET(dst, dstw); \
		ADJUST_LOCAL_OFFSET(src, srcw); \
		return sljit_emit_fop1_conv_f64_from_sw(compiler, op, dst, dstw, src, srcw); \
	} \
	CHECK(check_sljit_emit_fop1(compiler, op, dst, dstw, src, srcw)); \
	ADJUST_LOCAL_OFFSET(dst, dstw); \
	ADJUST_LOCAL_OFFSET(src, srcw);
#define SLJIT_ADD_EXEC_OFFSET(ptr, exec_offset) ((sljit_u8 *)(ptr) + (exec_offset))
#define SLJIT_ARGUMENT_CHECKS 1
#define SLJIT_ARG_MASK ((1 << SLJIT_ARG_SHIFT) - 1)
#define SLJIT_CPUINFO SLJIT_CPUINFO_PART1 SLJIT_CPUINFO_PART2 SLJIT_CPUINFO_PART3
#define SLJIT_CPUINFO_PART1 " 32bit ("
#define SLJIT_CPUINFO_PART2 "little endian + "
#define SLJIT_CPUINFO_PART3 "unaligned)"
#define SLJIT_CURRENT_FLAGS_ALL \
	(SLJIT_CURRENT_FLAGS_32 | SLJIT_CURRENT_FLAGS_ADD_SUB | SLJIT_CURRENT_FLAGS_COMPARE)
#define SLJIT_NEEDS_COMPILER_INIT 1
#define SLJIT_UPDATE_WX_FLAGS(from, to, enable_exec)
#define SSIZE_OF(type) ((sljit_s32)sizeof(sljit_ ## type))
#define TO_OFFS_REG(reg)	((reg) << 8)
#define TYPE_CAST_NEEDED(op) \
	((op) >= SLJIT_MOV_U8 && (op) <= SLJIT_MOV_S32)
#define VARIABLE_FLAG_MASK (0x3f << VARIABLE_FLAG_SHIFT)
#define VARIABLE_FLAG_SHIFT (10)
#define BSR_DEFAULT PCRE2_BSR_ANYCRLF
#define CHAR_0                      '0'
#define CHAR_1                      '\061'
#define CHAR_2                      '\062'
#define CHAR_3                      '\063'
#define CHAR_4                      '\064'
#define CHAR_5                      '\065'
#define CHAR_6                      '\066'
#define CHAR_7                      '\067'
#define CHAR_8                      '\070'
#define CHAR_9                      '\071'
#define CHAR_A                      '\101'
#define CHAR_AMPERSAND              '&'
#define CHAR_APOSTROPHE             '\''
#define CHAR_ASTERISK               '*'
#define CHAR_B                      '\102'
#define CHAR_BACKSLASH              '\134'
#define CHAR_BEL                    '\a'
#define CHAR_BS                     '\b'
#define CHAR_C                      '\103'
#define CHAR_CIRCUMFLEX_ACCENT      '\136'
#define CHAR_COLON                  '\072'
#define CHAR_COMMA                  ','
#define CHAR_COMMERCIAL_AT          '\100'
#define CHAR_CR                     '\r'
#define CHAR_D                      '\104'
#define CHAR_DEL                    '\007'
#define CHAR_DOLLAR_SIGN            '$'
#define CHAR_DOT                    '.'
#define CHAR_E                      '\105'
#define CHAR_EQUALS_SIGN            '\075'
#define CHAR_ESC                    '\047'
#define CHAR_EXCLAMATION_MARK       '!'
#define CHAR_F                      '\106'
#define CHAR_FF                     '\f'
#define CHAR_G                      '\107'
#define CHAR_GRAVE_ACCENT           '\140'
#define CHAR_GREATER_THAN_SIGN      '\076'
#define CHAR_H                      '\110'
#define CHAR_HT                     '\t'
#define CHAR_I                      '\111'
#define CHAR_J                      '\112'
#define CHAR_K                      '\113'
#define CHAR_L                      '\114'
#define CHAR_LEFT_CURLY_BRACKET     '\173'
#define CHAR_LEFT_PARENTHESIS       '('
#define CHAR_LEFT_SQUARE_BRACKET    '\133'
#define CHAR_LESS_THAN_SIGN         '\074'
#define CHAR_LF                     CHAR_NL
#define CHAR_M                      '\115'
#define CHAR_MINUS                  '-'
#define CHAR_N                      '\116'
#define CHAR_NBSP                   ((unsigned char)'\xa0')
#define CHAR_NEL                    '\x25'
#define CHAR_NL                     '\x15'
#define CHAR_NUL                    '\0'
#define CHAR_NUMBER_SIGN            '#'
#define CHAR_O                      '\117'
#define CHAR_P                      '\120'
#define CHAR_PERCENT_SIGN           '%'
#define CHAR_PLUS                   '+'
#define CHAR_Q                      '\121'
#define CHAR_QUESTION_MARK          '\077'
#define CHAR_QUOTATION_MARK         '"'
#define CHAR_R                      '\122'
#define CHAR_RIGHT_CURLY_BRACKET    '\175'
#define CHAR_RIGHT_PARENTHESIS      ')'
#define CHAR_RIGHT_SQUARE_BRACKET   '\135'
#define CHAR_S                      '\123'
#define CHAR_SEMICOLON              '\073'
#define CHAR_SLASH                  '/'
#define CHAR_SPACE                  ' '
#define CHAR_T                      '\124'
#define CHAR_TILDE                  '\176'
#define CHAR_U                      '\125'
#define CHAR_UNDERSCORE             '\137'
#define CHAR_V                      '\126'
#define CHAR_VERTICAL_LINE          '\174'
#define CHAR_VT                     '\v'
#define CHAR_W                      '\127'
#define CHAR_X                      '\130'
#define CHAR_Y                      '\131'
#define CHAR_Z                      '\132'
#define CHAR_a                      '\141'
#define CHAR_b                      '\142'
#define CHAR_c                      '\143'
#define CHAR_d                      '\144'
#define CHAR_e                      '\145'
#define CHAR_f                      '\146'
#define CHAR_g                      '\147'
#define CHAR_h                      '\150'
#define CHAR_i                      '\151'
#define CHAR_j                      '\152'
#define CHAR_k                      '\153'
#define CHAR_l                      '\154'
#define CHAR_m                      '\155'
#define CHAR_n                      '\156'
#define CHAR_o                      '\157'
#define CHAR_p                      '\160'
#define CHAR_q                      '\161'
#define CHAR_r                      '\162'
#define CHAR_s                      '\163'
#define CHAR_t                      '\164'
#define CHAR_u                      '\165'
#define CHAR_v                      '\166'
#define CHAR_w                      '\167'
#define CHAR_x                      '\170'
#define CHAR_y                      '\171'
#define CHAR_z                      '\172'
#define COMPILE_ERROR_BASE 100
#define DFA_START_RWS_SIZE 30720
#define FALSE   0
#define FIRST_AUTOTAB_OP       OP_NOT_DIGIT
#define GETUTF8(c, eptr) \
    { \
    if ((c & 0x20u) == 0) \
      c = ((c & 0x1fu) << 6) | (eptr[1] & 0x3fu); \
    else if ((c & 0x10u) == 0) \
      c = ((c & 0x0fu) << 12) | ((eptr[1] & 0x3fu) << 6) | (eptr[2] & 0x3fu); \
    else if ((c & 0x08u) == 0) \
      c = ((c & 0x07u) << 18) | ((eptr[1] & 0x3fu) << 12) | \
      ((eptr[2] & 0x3fu) << 6) | (eptr[3] & 0x3fu); \
    else if ((c & 0x04u) == 0) \
      c = ((c & 0x03u) << 24) | ((eptr[1] & 0x3fu) << 18) | \
          ((eptr[2] & 0x3fu) << 12) | ((eptr[3] & 0x3fu) << 6) | \
          (eptr[4] & 0x3fu); \
    else \
      c = ((c & 0x01u) << 30) | ((eptr[1] & 0x3fu) << 24) | \
          ((eptr[2] & 0x3fu) << 18) | ((eptr[3] & 0x3fu) << 12) | \
          ((eptr[4] & 0x3fu) << 6) | (eptr[5] & 0x3fu); \
    }
#define GETUTF8INC(c, eptr) \
    { \
    if ((c & 0x20u) == 0) \
      c = ((c & 0x1fu) << 6) | (*eptr++ & 0x3fu); \
    else if ((c & 0x10u) == 0) \
      { \
      c = ((c & 0x0fu) << 12) | ((*eptr & 0x3fu) << 6) | (eptr[1] & 0x3fu); \
      eptr += 2; \
      } \
    else if ((c & 0x08u) == 0) \
      { \
      c = ((c & 0x07u) << 18) | ((*eptr & 0x3fu) << 12) | \
          ((eptr[1] & 0x3fu) << 6) | (eptr[2] & 0x3fu); \
      eptr += 3; \
      } \
    else if ((c & 0x04u) == 0) \
      { \
      c = ((c & 0x03u) << 24) | ((*eptr & 0x3fu) << 18) | \
          ((eptr[1] & 0x3fu) << 12) | ((eptr[2] & 0x3fu) << 6) | \
          (eptr[3] & 0x3fu); \
      eptr += 4; \
      } \
    else \
      { \
      c = ((c & 0x01u) << 30) | ((*eptr & 0x3fu) << 24) | \
          ((eptr[1] & 0x3fu) << 18) | ((eptr[2] & 0x3fu) << 12) | \
          ((eptr[3] & 0x3fu) << 6) | (eptr[4] & 0x3fu); \
      eptr += 5; \
      } \
    }
#define GETUTF8LEN(c, eptr, len) \
    { \
    if ((c & 0x20u) == 0) \
      { \
      c = ((c & 0x1fu) << 6) | (eptr[1] & 0x3fu); \
      len++; \
      } \
    else if ((c & 0x10u)  == 0) \
      { \
      c = ((c & 0x0fu) << 12) | ((eptr[1] & 0x3fu) << 6) | (eptr[2] & 0x3fu); \
      len += 2; \
      } \
    else if ((c & 0x08u)  == 0) \
      {\
      c = ((c & 0x07u) << 18) | ((eptr[1] & 0x3fu) << 12) | \
          ((eptr[2] & 0x3fu) << 6) | (eptr[3] & 0x3fu); \
      len += 3; \
      } \
    else if ((c & 0x04u)  == 0) \
      { \
      c = ((c & 0x03u) << 24) | ((eptr[1] & 0x3fu) << 18) | \
          ((eptr[2] & 0x3fu) << 12) | ((eptr[3] & 0x3fu) << 6) | \
          (eptr[4] & 0x3fu); \
      len += 4; \
      } \
    else \
      {\
      c = ((c & 0x01u) << 30) | ((eptr[1] & 0x3fu) << 24) | \
          ((eptr[2] & 0x3fu) << 18) | ((eptr[3] & 0x3fu) << 12) | \
          ((eptr[4] & 0x3fu) << 6) | (eptr[5] & 0x3fu); \
      len += 5; \
      } \
    }
#define GET_UCD(ch) ((ch > MAX_UTF_CODE_POINT)? \
  PRIV(dummy_ucd_record) : REAL_GET_UCD(ch))
#define HASUTF8EXTRALEN(c) ((c) >= 0xc0)
#define HSPACE_BYTE_CASES \
  case CHAR_HT: \
  case CHAR_SPACE: \
  case CHAR_NBSP
#define HSPACE_CASES \
  HSPACE_BYTE_CASES: \
  HSPACE_MULTIBYTE_CASES
#define HSPACE_LIST \
  CHAR_HT, CHAR_SPACE, CHAR_NBSP, \
  0x1680, 0x180e, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, \
  0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x202f, 0x205f, 0x3000, \
  NOTACHAR
#define HSPACE_MULTIBYTE_CASES \
  case 0x1680:   \
  case 0x180e:   \
  case 0x2000:   \
  case 0x2001:   \
  case 0x2002:   \
  case 0x2003:   \
  case 0x2004:   \
  case 0x2005:   \
  case 0x2006:   \
  case 0x2007:   \
  case 0x2008:   \
  case 0x2009:   \
  case 0x200A:   \
  case 0x202f:   \
  case 0x205f:   \
  case 0x3000   
#define INT64_OR_DOUBLE int64_t
#define IS_NEWLINE(p) \
  ((NLBLOCK->nltype != NLTYPE_FIXED)? \
    ((p) < NLBLOCK->PSEND && \
     PRIV(is_newline)((p), NLBLOCK->nltype, NLBLOCK->PSEND, \
       &(NLBLOCK->nllen), utf)) \
    : \
    ((p) <= NLBLOCK->PSEND - NLBLOCK->nllen && \
     UCHAR21TEST(p) == NLBLOCK->nl[0] && \
     (NLBLOCK->nllen == 1 || UCHAR21TEST(p+1) == NLBLOCK->nl[1])       \
    ) \
  )
#define LAST_AUTOTAB_LEFT_OP   OP_EXTUNI
#define LAST_AUTOTAB_RIGHT_OP  OP_DOLLM
#define MAGIC_NUMBER  0x50435245UL   
#define MAPBIT(map,n) ((map)[(n)/32]&(1u<<((n)%32)))
#define MAPSET(map,n) ((map)[(n)/32]|=(1u<<((n)%32)))
#define MAX_NON_UTF_CHAR (0xffffffffU >> (32 - PCRE2_CODE_UNIT_WIDTH))
#define MAX_UTF_CODE_POINT 0x10ffff
#define NLTYPE_ANY      1     
#define NLTYPE_ANYCRLF  2     
#define NLTYPE_FIXED    0     
#define NOTACHAR 0xffffffff
#define OP_LENGTHS \
  1,                              \
  1, 1, 1, 1, 1,                  \
  1, 1, 1, 1, 1, 1,               \
  1, 1, 1,                        \
  3, 3,                           \
  1, 1, 1, 1, 1,                  \
  1,                              \
  1, 1, 1, 1, 1, 1,               \
  2,                              \
  2,                              \
  2,                              \
  2,                              \
   \
  2, 2, 2, 2, 2, 2,               \
  2+IMM2_SIZE, 2+IMM2_SIZE,       \
  2+IMM2_SIZE,                    \
  2, 2, 2, 2+IMM2_SIZE,           \
  2, 2, 2, 2, 2, 2,               \
  2+IMM2_SIZE, 2+IMM2_SIZE,       \
  2+IMM2_SIZE,                    \
  2, 2, 2, 2+IMM2_SIZE,           \
   \
  2, 2, 2, 2, 2, 2,               \
  2+IMM2_SIZE, 2+IMM2_SIZE,       \
  2+IMM2_SIZE,                    \
  2, 2, 2, 2+IMM2_SIZE,           \
  2, 2, 2, 2, 2, 2,               \
  2+IMM2_SIZE, 2+IMM2_SIZE,       \
  2+IMM2_SIZE,                    \
  2, 2, 2, 2+IMM2_SIZE,           \
   \
  2, 2, 2, 2, 2, 2,               \
  2+IMM2_SIZE, 2+IMM2_SIZE,       \
  2+IMM2_SIZE,                    \
  2, 2, 2, 2+IMM2_SIZE,           \
   \
  1, 1, 1, 1, 1, 1,               \
  1+2*IMM2_SIZE, 1+2*IMM2_SIZE,   \
  1, 1, 1, 1+2*IMM2_SIZE,         \
  1+(32/sizeof(PCRE2_UCHAR)),     \
  1+(32/sizeof(PCRE2_UCHAR)),     \
  0,                              \
  1+IMM2_SIZE,                    \
  1+IMM2_SIZE,                    \
  1+2*IMM2_SIZE,                  \
  1+2*IMM2_SIZE,                  \
  1+LINK_SIZE,                    \
  1+2*LINK_SIZE+1,                \
  0,                              \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE+IMM2_SIZE,          \
  1+LINK_SIZE+IMM2_SIZE,          \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE,                    \
  1+LINK_SIZE+IMM2_SIZE,          \
  1+LINK_SIZE+IMM2_SIZE,          \
  1+LINK_SIZE,                    \
  1+IMM2_SIZE, 1+2*IMM2_SIZE,     \
  1+IMM2_SIZE, 1+2*IMM2_SIZE,     \
  1, 1,                           \
  1, 1, 1,                        \
  3, 1, 3,                        \
  1, 3,                           \
  1, 3,                           \
  1, 3,                           \
  1, 1, 1,                        \
  1+IMM2_SIZE, 1,                 \
  1                              
#define OP_NAME_LIST \
  "End", "\\A", "\\G", "\\K", "\\B", "\\b", "\\D", "\\d",         \
  "\\S", "\\s", "\\W", "\\w", "Any", "AllAny", "Anybyte",         \
  "notprop", "prop", "\\R", "\\H", "\\h", "\\V", "\\v",           \
  "extuni",  "\\Z", "\\z",                                        \
  "$", "$", "^", "^", "char", "chari", "not", "noti",             \
  "*", "*?", "+", "+?", "?", "??",                                \
  "{", "{", "{",                                                  \
  "*+","++", "?+", "{",                                           \
  "*", "*?", "+", "+?", "?", "??",                                \
  "{", "{", "{",                                                  \
  "*+","++", "?+", "{",                                           \
  "*", "*?", "+", "+?", "?", "??",                                \
  "{", "{", "{",                                                  \
  "*+","++", "?+", "{",                                           \
  "*", "*?", "+", "+?", "?", "??",                                \
  "{", "{", "{",                                                  \
  "*+","++", "?+", "{",                                           \
  "*", "*?", "+", "+?", "?", "??", "{", "{", "{",                 \
  "*+","++", "?+", "{",                                           \
  "*", "*?", "+", "+?", "?", "??", "{", "{",                      \
  "*+","++", "?+", "{",                                           \
  "class", "nclass", "xclass", "Ref", "Refi", "DnRef", "DnRefi",  \
  "Recurse", "Callout", "CalloutStr",                             \
  "Alt", "Ket", "KetRmax", "KetRmin", "KetRpos",                  \
  "Reverse", "Assert", "Assert not",                              \
  "Assert back", "Assert back not",                               \
  "Non-atomic assert", "Non-atomic assert back",                  \
  "Once",                                                         \
  "Script run",                                                   \
  "Bra", "BraPos", "CBra", "CBraPos",                             \
  "Cond",                                                         \
  "SBra", "SBraPos", "SCBra", "SCBraPos",                         \
  "SCond",                                                        \
  "Cond ref", "Cond dnref", "Cond rec", "Cond dnrec",             \
  "Cond false", "Cond true",                                      \
  "Brazero", "Braminzero", "Braposzero",                          \
  "*MARK", "*PRUNE", "*PRUNE", "*SKIP", "*SKIP",                  \
  "*THEN", "*THEN", "*COMMIT", "*COMMIT", "*FAIL",                \
  "*ACCEPT", "*ASSERT_ACCEPT",                                    \
  "Close", "Skip zero", "Define"
#define PCRE2_BSR_SET       0x00004000  
#define PCRE2_DEREF_TABLES  0x00040000  
#define PCRE2_DUPCAPUSED    0x00200000  
#      define PCRE2_EXP_DECL       extern __declspec(dllexport)
#      define PCRE2_EXP_DEFN       __declspec(dllexport)
#define PCRE2_FIRSTCASELESS 0x00000020  
#define PCRE2_FIRSTMAPSET   0x00000040  
#define PCRE2_FIRSTSET      0x00000010  
#define PCRE2_HASACCEPT     0x00800000  
#define PCRE2_HASBKC        0x00400000  
#define PCRE2_HASBKPORX     0x00100000  
#define PCRE2_HASCRORLF     0x00000800  
#define PCRE2_HASTHEN       0x00001000  

#define PCRE2_JCHANGED      0x00000400  
#define PCRE2_KEEP_UNINITIALIZED __attribute__((uninitialized))
#define PCRE2_LASTCASELESS  0x00000100  
#define PCRE2_LASTSET       0x00000080  
#define PCRE2_MATCH_EMPTY   0x00002000  
#define PCRE2_MD_COPIED_SUBJECT  0x01u
#define PCRE2_MODE16        0x00000002  
#define PCRE2_MODE32        0x00000004  
#define PCRE2_MODE8         0x00000001  
#define PCRE2_MODE_MASK     (PCRE2_MODE8 | PCRE2_MODE16 | PCRE2_MODE32)
#define PCRE2_NE_ATST_SET   0x00020000  
#define PCRE2_NL_SET        0x00008000  
#define PCRE2_NOJIT         0x00080000  
#define PCRE2_NOTEMPTY_SET  0x00010000  
#define PCRE2_SPTR CUSTOM_SUBJECT_PTR
#define PCRE2_STARTLINE     0x00000200  
#define PRIV(name) _pcre2_##name
#define PT_ALNUM      6    
#define PT_ANY        0    
#define PT_BIDICL    12    
#define PT_BOOL      13    
#define PT_CLIST     10    
#define PT_GC         2    
#define PT_LAMP       1    
#define PT_NOTSCRIPT 255
#define PT_PC         3    
#define PT_PXGRAPH   14    
#define PT_PXPRINT   15    
#define PT_PXPUNCT   16    
#define PT_PXSPACE    8    
#define PT_SC         4    
#define PT_SCX        5    
#define PT_SPACE      7    
#define PT_TABSIZE   14    
#define PT_UCNC      11    
#define PT_WORD       9    
#define REAL_GET_UCD(ch) (PRIV(ucd_records) + \
        PRIV(ucd_stage2)[PRIV(ucd_stage1)[(int)(ch) / UCD_BLOCK_SIZE] * \
        UCD_BLOCK_SIZE + (int)(ch) % UCD_BLOCK_SIZE])
#define REQ_CU_MAX       5000
#define RREF_ANY  0xffff
#define START_FRAMES_SIZE 20480
#define STRING_ACCEPT0               STR_A STR_C STR_C STR_E STR_P STR_T "\0"
#define STRING_ANYCRLF_RIGHTPAR           STR_A STR_N STR_Y STR_C STR_R STR_L STR_F STR_RIGHT_PARENTHESIS
#define STRING_ANY_RIGHTPAR               STR_A STR_N STR_Y STR_RIGHT_PARENTHESIS
#define STRING_BSR_ANYCRLF_RIGHTPAR       STR_B STR_S STR_R STR_UNDERSCORE STR_A STR_N STR_Y STR_C STR_R STR_L STR_F STR_RIGHT_PARENTHESIS
#define STRING_BSR_UNICODE_RIGHTPAR       STR_B STR_S STR_R STR_UNDERSCORE STR_U STR_N STR_I STR_C STR_O STR_D STR_E STR_RIGHT_PARENTHESIS
#define STRING_COMMIT0               STR_C STR_O STR_M STR_M STR_I STR_T "\0"
#define STRING_CRLF_RIGHTPAR              STR_C STR_R STR_L STR_F STR_RIGHT_PARENTHESIS
#define STRING_CR_RIGHTPAR                STR_C STR_R STR_RIGHT_PARENTHESIS
#define STRING_DEFINE                STR_D STR_E STR_F STR_I STR_N STR_E
#define STRING_F0                    STR_F "\0"
#define STRING_FAIL0                 STR_F STR_A STR_I STR_L "\0"
#define STRING_LF_RIGHTPAR                STR_L STR_F STR_RIGHT_PARENTHESIS
#define STRING_LIMIT_DEPTH_EQ             STR_L STR_I STR_M STR_I STR_T STR_UNDERSCORE STR_D STR_E STR_P STR_T STR_H STR_EQUALS_SIGN
#define STRING_LIMIT_HEAP_EQ              STR_L STR_I STR_M STR_I STR_T STR_UNDERSCORE STR_H STR_E STR_A STR_P STR_EQUALS_SIGN
#define STRING_LIMIT_MATCH_EQ             STR_L STR_I STR_M STR_I STR_T STR_UNDERSCORE STR_M STR_A STR_T STR_C STR_H STR_EQUALS_SIGN
#define STRING_LIMIT_RECURSION_EQ         STR_L STR_I STR_M STR_I STR_T STR_UNDERSCORE STR_R STR_E STR_C STR_U STR_R STR_S STR_I STR_O STR_N STR_EQUALS_SIGN
#define STRING_MARK                       STR_M STR_A STR_R STR_K
#define STRING_MARK0                 STR_M STR_A STR_R STR_K "\0"
#define STRING_NOTEMPTY_ATSTART_RIGHTPAR  STR_N STR_O STR_T STR_E STR_M STR_P STR_T STR_Y STR_UNDERSCORE STR_A STR_T STR_S STR_T STR_A STR_R STR_T STR_RIGHT_PARENTHESIS
#define STRING_NOTEMPTY_RIGHTPAR          STR_N STR_O STR_T STR_E STR_M STR_P STR_T STR_Y STR_RIGHT_PARENTHESIS
#define STRING_NO_AUTO_POSSESS_RIGHTPAR   STR_N STR_O STR_UNDERSCORE STR_A STR_U STR_T STR_O STR_UNDERSCORE STR_P STR_O STR_S STR_S STR_E STR_S STR_S STR_RIGHT_PARENTHESIS
#define STRING_NO_DOTSTAR_ANCHOR_RIGHTPAR STR_N STR_O STR_UNDERSCORE STR_D STR_O STR_T STR_S STR_T STR_A STR_R STR_UNDERSCORE STR_A STR_N STR_C STR_H STR_O STR_R STR_RIGHT_PARENTHESIS
#define STRING_NO_JIT_RIGHTPAR            STR_N STR_O STR_UNDERSCORE STR_J STR_I STR_T STR_RIGHT_PARENTHESIS
#define STRING_NO_START_OPT_RIGHTPAR      STR_N STR_O STR_UNDERSCORE STR_S STR_T STR_A STR_R STR_T STR_UNDERSCORE STR_O STR_P STR_T STR_RIGHT_PARENTHESIS
#define STRING_NUL_RIGHTPAR               STR_N STR_U STR_L STR_RIGHT_PARENTHESIS
#define STRING_PRUNE0                STR_P STR_R STR_U STR_N STR_E "\0"
#define STRING_SKIP0                 STR_S STR_K STR_I STR_P "\0"
#define STRING_THEN                  STR_T STR_H STR_E STR_N
#define STRING_UCP_RIGHTPAR               STR_U STR_C STR_P STR_RIGHT_PARENTHESIS
#define STRING_UTF16_RIGHTPAR             STR_U STR_T STR_F STR_1 STR_6 STR_RIGHT_PARENTHESIS
#define STRING_UTF32_RIGHTPAR             STR_U STR_T STR_F STR_3 STR_2 STR_RIGHT_PARENTHESIS
#define STRING_UTF8_RIGHTPAR              STR_U STR_T STR_F STR_8 STR_RIGHT_PARENTHESIS
#define STRING_UTF_RIGHTPAR               STR_U STR_T STR_F STR_RIGHT_PARENTHESIS
#define STRING_VERSION               STR_V STR_E STR_R STR_S STR_I STR_O STR_N
#define STRING_WEIRD_ENDWORD         STR_LEFT_SQUARE_BRACKET STR_COLON STR_GREATER_THAN_SIGN STR_COLON STR_RIGHT_SQUARE_BRACKET STR_RIGHT_SQUARE_BRACKET
#define STRING_WEIRD_STARTWORD       STR_LEFT_SQUARE_BRACKET STR_COLON STR_LESS_THAN_SIGN STR_COLON STR_RIGHT_SQUARE_BRACKET STR_RIGHT_SQUARE_BRACKET
#define STRING_alnum0                STR_a STR_l STR_n STR_u STR_m "\0"
#define STRING_alpha0                STR_a STR_l STR_p STR_h STR_a "\0"
#define STRING_ascii0                STR_a STR_s STR_c STR_i STR_i "\0"
#define STRING_asr0                  STR_a STR_s STR_r "\0"
#define STRING_atomic0               STR_a STR_t STR_o STR_m STR_i STR_c "\0"
#define STRING_atomic_script_run     STR_a STR_t STR_o STR_m STR_i STR_c STR_UNDERSCORE STR_s STR_c STR_r STR_i STR_p STR_t STR_UNDERSCORE STR_r STR_u STR_n
#define STRING_bc                         STR_b STR_c
#define STRING_bidiclass                  STR_b STR_i STR_d STR_i STR_c STR_l STR_a STR_s STR_s
#define STRING_blank0                STR_b STR_l STR_a STR_n STR_k "\0"
#define STRING_cntrl0                STR_c STR_n STR_t STR_r STR_l "\0"
#define STRING_digit0                STR_d STR_i STR_g STR_i STR_t "\0"
#define STRING_graph0                STR_g STR_r STR_a STR_p STR_h "\0"
#define STRING_lower0                STR_l STR_o STR_w STR_e STR_r "\0"
#define STRING_napla0                STR_n STR_a STR_p STR_l STR_a "\0"
#define STRING_naplb0                STR_n STR_a STR_p STR_l STR_b "\0"
#define STRING_negative_lookahead0   STR_n STR_e STR_g STR_a STR_t STR_i STR_v STR_e STR_UNDERSCORE STR_l STR_o STR_o STR_k STR_a STR_h STR_e STR_a STR_d "\0"
#define STRING_negative_lookbehind0  STR_n STR_e STR_g STR_a STR_t STR_i STR_v STR_e STR_UNDERSCORE STR_l STR_o STR_o STR_k STR_b STR_e STR_h STR_i STR_n STR_d "\0"
#define STRING_nla0                  STR_n STR_l STR_a "\0"
#define STRING_nlb0                  STR_n STR_l STR_b "\0"
#define STRING_non_atomic_positive_lookahead0   STR_n STR_o STR_n STR_UNDERSCORE STR_a STR_t STR_o STR_m STR_i STR_c STR_UNDERSCORE STR_p STR_o STR_s STR_i STR_t STR_i STR_v STR_e STR_UNDERSCORE STR_l STR_o STR_o STR_k STR_a STR_h STR_e STR_a STR_d "\0"
#define STRING_non_atomic_positive_lookbehind0  STR_n STR_o STR_n STR_UNDERSCORE STR_a STR_t STR_o STR_m STR_i STR_c STR_UNDERSCORE STR_p STR_o STR_s STR_i STR_t STR_i STR_v STR_e STR_UNDERSCORE STR_l STR_o STR_o STR_k STR_b STR_e STR_h STR_i STR_n STR_d "\0"
#define STRING_pla0                  STR_p STR_l STR_a "\0"
#define STRING_plb0                  STR_p STR_l STR_b "\0"
#define STRING_positive_lookahead0   STR_p STR_o STR_s STR_i STR_t STR_i STR_v STR_e STR_UNDERSCORE STR_l STR_o STR_o STR_k STR_a STR_h STR_e STR_a STR_d "\0"
#define STRING_positive_lookbehind0  STR_p STR_o STR_s STR_i STR_t STR_i STR_v STR_e STR_UNDERSCORE STR_l STR_o STR_o STR_k STR_b STR_e STR_h STR_i STR_n STR_d "\0"
#define STRING_print0                STR_p STR_r STR_i STR_n STR_t "\0"
#define STRING_punct0                STR_p STR_u STR_n STR_c STR_t "\0"
#define STRING_sc                         STR_s STR_c
#define STRING_script                     STR_s STR_c STR_r STR_i STR_p STR_t
#define STRING_script_run0           STR_s STR_c STR_r STR_i STR_p STR_t STR_UNDERSCORE STR_r STR_u STR_n "\0"
#define STRING_scriptextensions           STR_s STR_c STR_r STR_i STR_p STR_t STR_e STR_x STR_t STR_e STR_n STR_s STR_i STR_o STR_n STR_s
#define STRING_scx                        STR_s STR_c STR_x
#define STRING_space0                STR_s STR_p STR_a STR_c STR_e "\0"
#define STRING_sr0                   STR_s STR_r "\0"
#define STRING_upper0                STR_u STR_p STR_p STR_e STR_r "\0"
#define STRING_word0                 STR_w STR_o STR_r STR_d       "\0"
#define STRING_xdigit                STR_x STR_d STR_i STR_g STR_i STR_t
#define STR_0                       "\060"
#define STR_1                       "\061"
#define STR_2                       "\062"
#define STR_3                       "\063"
#define STR_4                       "\064"
#define STR_5                       "\065"
#define STR_6                       "\066"
#define STR_7                       "\067"
#define STR_8                       "\070"
#define STR_9                       "\071"
#define STR_A                       "\101"
#define STR_AMPERSAND               "\046"
#define STR_APOSTROPHE              "\047"
#define STR_ASTERISK                "\052"
#define STR_B                       "\102"
#define STR_BACKSLASH               "\134"
#define STR_BEL                     "\007"
#define STR_BS                      "\010"
#define STR_C                       "\103"
#define STR_CIRCUMFLEX_ACCENT       "\136"
#define STR_COLON                   "\072"
#define STR_COMMA                   "\054"
#define STR_COMMERCIAL_AT           "\100"
#define STR_CR                      "\015"
#define STR_D                       "\104"
#define STR_DEL                     "\177"
#define STR_DOLLAR_SIGN             "\044"
#define STR_DOT                     "\056"
#define STR_E                       "\105"
#define STR_EQUALS_SIGN             "\075"
#define STR_ESC                     "\033"
#define STR_EXCLAMATION_MARK        "\041"
#define STR_F                       "\106"
#define STR_FF                      "\014"
#define STR_G                       "\107"
#define STR_GRAVE_ACCENT            "\140"
#define STR_GREATER_THAN_SIGN       "\076"
#define STR_H                       "\110"
#define STR_HT                      "\011"
#define STR_I                       "\111"
#define STR_J                       "\112"
#define STR_K                       "\113"
#define STR_L                       "\114"
#define STR_LEFT_CURLY_BRACKET      "\173"
#define STR_LEFT_PARENTHESIS        "\050"
#define STR_LEFT_SQUARE_BRACKET     "\133"
#define STR_LESS_THAN_SIGN          "\074"
#define STR_LF                      STR_NL
#define STR_M                       "\115"
#define STR_MINUS                   "\055"
#define STR_N                       "\116"
#define STR_NEL                     "\x25"
#define STR_NL                      "\012"
#define STR_NUMBER_SIGN             "\043"
#define STR_O                       "\117"
#define STR_P                       "\120"
#define STR_PERCENT_SIGN            "\045"
#define STR_PLUS                    "\053"
#define STR_Q                       "\121"
#define STR_QUESTION_MARK           "\077"
#define STR_QUOTATION_MARK          "\042"
#define STR_R                       "\122"
#define STR_RIGHT_CURLY_BRACKET     "\175"
#define STR_RIGHT_PARENTHESIS       "\051"
#define STR_RIGHT_SQUARE_BRACKET    "\135"
#define STR_S                       "\123"
#define STR_SEMICOLON               "\073"
#define STR_SLASH                   "\057"
#define STR_SPACE                   "\040"
#define STR_T                       "\124"
#define STR_TILDE                   "\176"
#define STR_U                       "\125"
#define STR_UNDERSCORE              "\137"
#define STR_V                       "\126"
#define STR_VERTICAL_LINE           "\174"
#define STR_VT                      "\013"
#define STR_W                       "\127"
#define STR_X                       "\130"
#define STR_Y                       "\131"
#define STR_Z                       "\132"
#define STR_a                       "\141"
#define STR_b                       "\142"
#define STR_c                       "\143"
#define STR_d                       "\144"
#define STR_e                       "\145"
#define STR_f                       "\146"
#define STR_g                       "\147"
#define STR_h                       "\150"
#define STR_i                       "\151"
#define STR_j                       "\152"
#define STR_k                       "\153"
#define STR_l                       "\154"
#define STR_m                       "\155"
#define STR_n                       "\156"
#define STR_o                       "\157"
#define STR_p                       "\160"
#define STR_q                       "\161"
#define STR_r                       "\162"
#define STR_s                       "\163"
#define STR_t                       "\164"
#define STR_u                       "\165"
#define STR_v                       "\166"
#define STR_w                       "\167"
#define STR_x                       "\170"
#define STR_y                       "\171"
#define STR_z                       "\172"
#define TABLES_LENGTH (ctypes_offset + 256)
#define TRUE    1
#define UCD_BIDICLASS(ch)   UCD_BIDICLASS_PROP(GET_UCD(ch))
#define UCD_BIDICLASS_PROP(prop) ((prop)->scriptx_bidiclass >> UCD_BIDICLASS_SHIFT)
#define UCD_BIDICLASS_SHIFT 11
#define UCD_BLOCK_SIZE 128
#define UCD_BPROPS(ch)      UCD_BPROPS_PROP(GET_UCD(ch))
#define UCD_BPROPS_MASK 0xfff
#define UCD_BPROPS_PROP(prop) ((prop)->bprops & UCD_BPROPS_MASK)
#define UCD_CASESET(ch)     GET_UCD(ch)->caseset
#define UCD_CATEGORY(ch)    PRIV(ucp_gentype)[UCD_CHARTYPE(ch)]
#define UCD_CHARTYPE(ch)    GET_UCD(ch)->chartype
#define UCD_GRAPHBREAK(ch)  GET_UCD(ch)->gbprop
#define UCD_OTHERCASE(ch)   ((uint32_t)((int)ch + (int)(GET_UCD(ch)->other_case)))
#define UCD_SCRIPT(ch)      GET_UCD(ch)->script
#define UCD_SCRIPTX(ch)     UCD_SCRIPTX_PROP(GET_UCD(ch))
#define UCD_SCRIPTX_MASK 0x3ff
#define UCD_SCRIPTX_PROP(prop) ((prop)->scriptx_bidiclass & UCD_SCRIPTX_MASK)
#define VSPACE_BYTE_CASES \
  case CHAR_LF: \
  case CHAR_VT: \
  case CHAR_FF: \
  case CHAR_CR: \
  case CHAR_NEL
#define VSPACE_CASES \
  VSPACE_BYTE_CASES: \
  VSPACE_MULTIBYTE_CASES
#define VSPACE_LIST \
  CHAR_LF, CHAR_VT, CHAR_FF, CHAR_CR, CHAR_NEL, 0x2028, 0x2029, NOTACHAR
#define VSPACE_MULTIBYTE_CASES \
  case 0x2028:     \
  case 0x2029     
#define WAS_NEWLINE(p) \
  ((NLBLOCK->nltype != NLTYPE_FIXED)? \
    ((p) > NLBLOCK->PSSTART && \
     PRIV(was_newline)((p), NLBLOCK->nltype, NLBLOCK->PSSTART, \
       &(NLBLOCK->nllen), utf)) \
    : \
    ((p) >= NLBLOCK->PSSTART + NLBLOCK->nllen && \
     UCHAR21TEST(p - NLBLOCK->nllen) == NLBLOCK->nl[0] &&              \
     (NLBLOCK->nllen == 1 || UCHAR21TEST(p - NLBLOCK->nllen + 1) == NLBLOCK->nl[1]) \
    ) \
  )
#define XCL_END      0     
#define XCL_HASPROP  0x04  
#define XCL_MAP      0x02  
#define XCL_NOT      0x01  
#define XCL_NOTPROP  4     
#define XCL_PROP     3     
#define XCL_RANGE    2     
#define XCL_SINGLE   1     
#define _pcre2_OP_lengths              PCRE2_SUFFIX(_pcre2_OP_lengths_)
#define _pcre2_auto_possessify       PCRE2_SUFFIX(_pcre2_auto_possessify_)
#define _pcre2_callout_end_delims      PCRE2_SUFFIX(_pcre2_callout_end_delims_)
#define _pcre2_callout_start_delims    PCRE2_SUFFIX(_pcre2_callout_start_delims_)
#define _pcre2_check_escape          PCRE2_SUFFIX(_pcre2_check_escape_)
#define _pcre2_default_compile_context PCRE2_SUFFIX(_pcre2_default_compile_context_)
#define _pcre2_default_convert_context PCRE2_SUFFIX(_pcre2_default_convert_context_)
#define _pcre2_default_match_context   PCRE2_SUFFIX(_pcre2_default_match_context_)
#define _pcre2_default_tables          PCRE2_SUFFIX(_pcre2_default_tables_)
#define _pcre2_dummy_ucd_record        PCRE2_SUFFIX(_pcre2_dummy_ucd_record_)
#define _pcre2_extuni                PCRE2_SUFFIX(_pcre2_extuni_)
#define _pcre2_find_bracket          PCRE2_SUFFIX(_pcre2_find_bracket_)
#define _pcre2_hspace_list             PCRE2_SUFFIX(_pcre2_hspace_list_)
#define _pcre2_is_newline            PCRE2_SUFFIX(_pcre2_is_newline_)
#define _pcre2_jit_free              PCRE2_SUFFIX(_pcre2_jit_free_)
#define _pcre2_jit_free_rodata       PCRE2_SUFFIX(_pcre2_jit_free_rodata_)
#define _pcre2_jit_get_size          PCRE2_SUFFIX(_pcre2_jit_get_size_)
#define _pcre2_jit_get_target        PCRE2_SUFFIX(_pcre2_jit_get_target_)
#define _pcre2_memctl_malloc         PCRE2_SUFFIX(_pcre2_memctl_malloc_)
#define _pcre2_memmove               PCRE2_SUFFIX(_pcre2_memmove)
#define _pcre2_ord2utf               PCRE2_SUFFIX(_pcre2_ord2utf_)
#define _pcre2_script_run            PCRE2_SUFFIX(_pcre2_script_run_)
#define _pcre2_strcmp                PCRE2_SUFFIX(_pcre2_strcmp_)
#define _pcre2_strcmp_c8             PCRE2_SUFFIX(_pcre2_strcmp_c8_)
#define _pcre2_strcpy_c8             PCRE2_SUFFIX(_pcre2_strcpy_c8_)
#define _pcre2_strlen                PCRE2_SUFFIX(_pcre2_strlen_)
#define _pcre2_strncmp               PCRE2_SUFFIX(_pcre2_strncmp_)
#define _pcre2_strncmp_c8            PCRE2_SUFFIX(_pcre2_strncmp_c8_)
#define _pcre2_study                 PCRE2_SUFFIX(_pcre2_study_)
#define _pcre2_ucd_boolprop_sets       PCRE2_SUFFIX(_pcre2_ucd_boolprop_sets_)
#define _pcre2_ucd_caseless_sets       PCRE2_SUFFIX(_pcre2_ucd_caseless_sets_)
#define _pcre2_ucd_digit_sets          PCRE2_SUFFIX(_pcre2_ucd_digit_sets_)
#define _pcre2_ucd_records             PCRE2_SUFFIX(_pcre2_ucd_records_)
#define _pcre2_ucd_script_sets         PCRE2_SUFFIX(_pcre2_ucd_script_sets_)
#define _pcre2_ucd_stage1              PCRE2_SUFFIX(_pcre2_ucd_stage1_)
#define _pcre2_ucd_stage2              PCRE2_SUFFIX(_pcre2_ucd_stage2_)
#define _pcre2_ucp_gbtable             PCRE2_SUFFIX(_pcre2_ucp_gbtable_)
#define _pcre2_ucp_gentype             PCRE2_SUFFIX(_pcre2_ucp_gentype_)
#define _pcre2_ucp_typerange           PCRE2_SUFFIX(_pcre2_ucp_typerange_)
#define _pcre2_unicode_version         PCRE2_SUFFIX(_pcre2_unicode_version_)
#define _pcre2_utt                     PCRE2_SUFFIX(_pcre2_utt_)
#define _pcre2_utt_names               PCRE2_SUFFIX(_pcre2_utt_names_)
#define _pcre2_utt_size                PCRE2_SUFFIX(_pcre2_utt_size_)
#define _pcre2_valid_utf             PCRE2_SUFFIX(_pcre2_valid_utf_)
#define _pcre2_vspace_list             PCRE2_SUFFIX(_pcre2_vspace_list_)
#define _pcre2_was_newline           PCRE2_SUFFIX(_pcre2_was_newline_)
#define _pcre2_xclass                PCRE2_SUFFIX(_pcre2_xclass_)
#define branch_chain                 PCRE2_SUFFIX(branch_chain_)
#define cbit_cntrl   288      
#define cbit_digit    64      
#define cbit_graph   192      
#define cbit_length  320      
#define cbit_lower   128      
#define cbit_print   224      
#define cbit_punct   256      
#define cbit_space     0      
#define cbit_upper    96      
#define cbit_word    160      
#define cbit_xdigit   32      
#define cbits_offset  512                           
#define compile_block                PCRE2_SUFFIX(compile_block_)
#define ctype_digit    0x08
#define ctype_lcletter 0x04
#define ctype_letter   0x02
#define ctype_space    0x01
#define ctype_word     0x10    
#define ctypes_offset (cbits_offset + cbit_length)  
#define dfa_match_block              PCRE2_SUFFIX(dfa_match_block_)
#define fcc_offset    256                           
#define lcc_offset      0                           
#define match_block                  PCRE2_SUFFIX(match_block_)
#define memcmp(s,c,n)    _memcmp(s,c,n)
#define memcpy(d,s,n)    _memcpy(d,s,n)
#define memmove(a, b, c) PRIV(memmove)(a, b, c)
#define memset(s,c,n)    _memset(s,c,n)
#define named_group                  PCRE2_SUFFIX(named_group_)
#define snprintf _snprintf
#define strlen(s)        _strlen(s)
#define strncmp(s1,s2,m) _strncmp(s1,s2,m)
#define ACROSSCHAR(condition, eptr, action) \
  while((condition) && ((*eptr) & 0xc0u) == 0x80u) action
#define BACKCHAR(eptr) while((*eptr & 0xc0u) == 0x80u) eptr--
#define BYTES2CU(x)     ((x)/((PCRE2_CODE_UNIT_WIDTH/8)))
#define CHMAX_255(c) ((c) <= 255u)
#define CODE_BLOCKSIZE_TYPE size_t
#define CU2BYTES(x)     ((x)*((PCRE2_CODE_UNIT_WIDTH/8)))
#define FORWARDCHAR(eptr) while((*eptr & 0xc0u) == 0x80u) eptr++
#define FORWARDCHARTEST(eptr,end) while(eptr < end && (*eptr & 0xc0u) == 0x80u) eptr++
#define GET(a,n) \
  (unsigned int)(((a)[n] << 8) | (a)[(n)+1])
#define GET2(a,n) (unsigned int)(((a)[n] << 8) | (a)[(n)+1])
#define GETCHAR(c, eptr) c = *eptr;
#define GETCHARINC(c, eptr) c = *eptr++;
#define GETCHARINCTEST(c, eptr) c = *eptr++;
#define GETCHARLEN(c, eptr, len) c = *eptr;
#define GETCHARLENTEST(c, eptr, len) \
  c = *eptr; \
  if (utf && c >= 0xc0u) GETUTF8LEN(c, eptr, len);
#define GETCHARTEST(c, eptr) c = *eptr;
#define GETUTF16(c, eptr) \
   { c = (((c & 0x3ffu) << 10) | (eptr[1] & 0x3ffu)) + 0x10000u; }
#define GETUTF16INC(c, eptr) \
   { c = (((c & 0x3ffu) << 10) | (*eptr++ & 0x3ffu)) + 0x10000u; }
#define GETUTF16LEN(c, eptr, len) \
   { c = (((c & 0x3ffu) << 10) | (eptr[1] & 0x3ffu)) + 0x10000u; len++; }
#define GET_EXTRALEN(c) (PRIV(utf8_table4)[(c) & 0x3fu])
#define HAS_EXTRALEN(c) HASUTF8EXTRALEN(c)
#define HEAPFRAME_ALIGNMENT offsetof(heapframe_align, frame)
#define IMM2_SIZE 2
#define LINK_SIZE 1
#define LOOKBEHIND_MAX UINT16_MAX
#define MAX_255(c) TRUE
#define MAX_MARK ((1u << 8) - 1)
#define MAX_PATTERN_SIZE (1 << 16)
#define MAX_UTF_SINGLE_CU 127
#define MAYBE_UTF_MULTI          
#define NOT_FIRSTCU(c) (((c) & 0xc0u) == 0x80u)
#define PUT(a,n,d)   \
  (a[n] = (PCRE2_UCHAR)((d) >> 8)), \
  (a[(n)+1] = (PCRE2_UCHAR)((d) & 255))
#define PUT2(a,n,d) a[n] = (d) >> 8, a[(n)+1] = (d) & 255
#define PUT2INC(a,n,d)  PUT2(a,n,d), a += IMM2_SIZE
#define PUTCHAR(c, p) (*p = c, 1)
#define PUTINC(a,n,d)   PUT(a,n,d), a += LINK_SIZE

#define TABLE_GET(c, table, default) ((table)[c])
#define UCHAR21(eptr)        (*(eptr))
#define UCHAR21INC(eptr)     (*(eptr)++)
#define UCHAR21INCTEST(eptr) (*(eptr)++)
#define UCHAR21TEST(eptr)    (*(eptr))

#define ucd_boolprop_sets_item_size 2
#define ucd_script_sets_item_size 3
