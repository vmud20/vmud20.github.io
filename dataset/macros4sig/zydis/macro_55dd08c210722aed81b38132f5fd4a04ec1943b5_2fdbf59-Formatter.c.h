













#define ZYDIS_STRING_ASSERT_NULLTERMINATION(string) \
      ZYAN_ASSERT(*(char*)((ZyanU8*)(string)->vector.data + (string)->vector.size - 1) == '\0');
#define ZYDIS_STRING_NULLTERMINATE(string) \
      *(char*)((ZyanU8*)(string)->vector.data + (string)->vector.size - 1) = '\0';
#define ZYAN_MODULE_ZYDIS   0x002u
#define ZYDIS_STATUS_BAD_REGISTER \
    ZYAN_MAKE_STATUS(1u, ZYAN_MODULE_ZYDIS, 0x03u)
#define ZYDIS_STATUS_DECODING_ERROR \
    ZYAN_MAKE_STATUS(1u, ZYAN_MODULE_ZYDIS, 0x01u)

#define ZYDIS_STATUS_ILLEGAL_LEGACY_PFX \
    ZYAN_MAKE_STATUS(1u, ZYAN_MODULE_ZYDIS, 0x05u)
#define ZYDIS_STATUS_ILLEGAL_LOCK \
    ZYAN_MAKE_STATUS(1u, ZYAN_MODULE_ZYDIS, 0x04u)
#define ZYDIS_STATUS_ILLEGAL_REX \
    ZYAN_MAKE_STATUS(1u, ZYAN_MODULE_ZYDIS, 0x06u)
#define ZYDIS_STATUS_INSTRUCTION_TOO_LONG \
    ZYAN_MAKE_STATUS(1u, ZYAN_MODULE_ZYDIS, 0x02u)
#define ZYDIS_STATUS_INVALID_MAP \
    ZYAN_MAKE_STATUS(1u, ZYAN_MODULE_ZYDIS, 0x07u)
#define ZYDIS_STATUS_INVALID_MASK \
    ZYAN_MAKE_STATUS(1u, ZYAN_MODULE_ZYDIS, 0x0Au)
#define ZYDIS_STATUS_MALFORMED_EVEX \
    ZYAN_MAKE_STATUS(1u, ZYAN_MODULE_ZYDIS, 0x08u)
#define ZYDIS_STATUS_MALFORMED_MVEX \
    ZYAN_MAKE_STATUS(1u, ZYAN_MODULE_ZYDIS, 0x09u)
#define ZYDIS_STATUS_NO_MORE_DATA \
    ZYAN_MAKE_STATUS(1u, ZYAN_MODULE_ZYDIS, 0x00u)
#define ZYDIS_STATUS_SKIP_TOKEN \
    ZYAN_MAKE_STATUS(0u, ZYAN_MODULE_ZYDIS, 0x0Bu)
#define ZYDIS_MAKE_SHORTSTRING(string) \
    { string, sizeof(string) - 1 }


#define ZYDIS_BUFFER_APPEND(buffer, name) \
    if ((buffer)->is_token_list) \
    { \
        ZYAN_CHECK(ZydisFormatterBufferAppendPredefined(buffer, TOK_ ## name)); \
    } else \
    { \
        ZYAN_CHECK(ZydisStringAppendShort(&buffer->string, &STR_ ## name)); \
    }
#define ZYDIS_BUFFER_APPEND_CASE(buffer, name, letter_case) \
    if ((buffer)->is_token_list) \
    { \
        ZYAN_CHECK(ZydisFormatterBufferAppendPredefined(buffer, TOK_ ## name)); \
    } else \
    { \
        ZYAN_CHECK(ZydisStringAppendShortCase(&buffer->string, &STR_ ## name, letter_case)); \
    }
#define ZYDIS_BUFFER_APPEND_TOKEN(buffer, type) \
    if ((buffer)->is_token_list) \
    { \
        ZYAN_CHECK(ZydisFormatterBufferAppend(buffer, type)); \
    }
#define ZYDIS_BUFFER_REMEMBER(buffer, state) \
    if ((buffer)->is_token_list) \
    { \
        (state) = (ZyanUPointer)(buffer)->string.vector.data; \
    } else \
    { \
        (state) = (ZyanUPointer)(buffer)->string.vector.size; \
    }

#define ZYDIS_STRING_APPEND_NUM_S(formatter, base, str, value, padding_length, force_sign) \
    switch (base) \
    { \
    case ZYDIS_NUMERIC_BASE_DEC: \
        ZYAN_CHECK(ZydisStringAppendDecS(str, value, padding_length, force_sign, \
            (formatter)->number_format[base][0].string, \
            (formatter)->number_format[base][1].string)); \
        break; \
    case ZYDIS_NUMERIC_BASE_HEX: \
        ZYAN_CHECK(ZydisStringAppendHexS(str, value, padding_length,  \
            (formatter)->hex_uppercase, force_sign, \
            (formatter)->number_format[base][0].string, \
            (formatter)->number_format[base][1].string)); \
        break; \
    default: \
        return ZYAN_STATUS_INVALID_ARGUMENT; \
    }
#define ZYDIS_STRING_APPEND_NUM_U(formatter, base, str, value, padding_length) \
    switch (base) \
    { \
    case ZYDIS_NUMERIC_BASE_DEC: \
        ZYAN_CHECK(ZydisStringAppendDecU(str, value, padding_length, \
            (formatter)->number_format[base][0].string, \
            (formatter)->number_format[base][1].string)); \
        break; \
    case ZYDIS_NUMERIC_BASE_HEX: \
        ZYAN_CHECK(ZydisStringAppendHexU(str, value, padding_length, \
            (formatter)->hex_uppercase, \
            (formatter)->number_format[base][0].string, \
            (formatter)->number_format[base][1].string)); \
        break; \
    default: \
        return ZYAN_STATUS_INVALID_ARGUMENT; \
    }

#define ZYDIS_RUNTIME_ADDRESS_NONE (ZyanU64)(-1)

#define ZYDIS_TOKEN_ADDRESS_ABS         0x08
#define ZYDIS_TOKEN_ADDRESS_REL         0x09
#define ZYDIS_TOKEN_DECORATOR           0x0D
#define ZYDIS_TOKEN_DELIMITER           0x02
#define ZYDIS_TOKEN_DISPLACEMENT        0x0A
#define ZYDIS_TOKEN_IMMEDIATE           0x0B
#define ZYDIS_TOKEN_INVALID             0x00
#define ZYDIS_TOKEN_MNEMONIC            0x06
#define ZYDIS_TOKEN_PARENTHESIS_CLOSE   0x04
#define ZYDIS_TOKEN_PARENTHESIS_OPEN    0x03
#define ZYDIS_TOKEN_PREFIX              0x05
#define ZYDIS_TOKEN_REGISTER            0x07
#define ZYDIS_TOKEN_SYMBOL              0x0E
#define ZYDIS_TOKEN_TYPECAST            0x0C
#define ZYDIS_TOKEN_USER                0x80
#define ZYDIS_TOKEN_WHITESPACE          0x01
#define ZYDIS_ATTRIB_ACCEPTS_BND                0x0000000000002000 
#define ZYDIS_ATTRIB_ACCEPTS_BRANCH_HINTS       0x0000000000020000 
#define ZYDIS_ATTRIB_ACCEPTS_HLE_WITHOUT_LOCK   0x0000000000010000 
#define ZYDIS_ATTRIB_ACCEPTS_LOCK               0x0000000000000200 
#define ZYDIS_ATTRIB_ACCEPTS_NOTRACK            0x0000080000000000 
#define ZYDIS_ATTRIB_ACCEPTS_REP                0x0000000000000400 
#define ZYDIS_ATTRIB_ACCEPTS_REPE               0x0000000000000800 
#define ZYDIS_ATTRIB_ACCEPTS_REPNE              0x0000000000001000 
#define ZYDIS_ATTRIB_ACCEPTS_REPNZ              0x0000000000001000 
#define ZYDIS_ATTRIB_ACCEPTS_REPZ               0x0000000000000800 
#define ZYDIS_ATTRIB_ACCEPTS_SEGMENT            0x0000000000040000 
#define ZYDIS_ATTRIB_ACCEPTS_XACQUIRE           0x0000000000004000 
#define ZYDIS_ATTRIB_ACCEPTS_XRELEASE           0x0000000000008000 
#define ZYDIS_ATTRIB_CPUFLAG_ACCESS             0x0000001000000000 
#define ZYDIS_ATTRIB_CPU_STATE_CR               0x0000002000000000 
#define ZYDIS_ATTRIB_CPU_STATE_CW               0x0000004000000000 
#define ZYDIS_ATTRIB_FPU_STATE_CR               0x0000008000000000 
#define ZYDIS_ATTRIB_FPU_STATE_CW               0x0000010000000000 
#define ZYDIS_ATTRIB_HAS_ADDRESSSIZE            0x0000000800000000 
#define ZYDIS_ATTRIB_HAS_BND                    0x0000000000800000 
#define ZYDIS_ATTRIB_HAS_BRANCH_NOT_TAKEN       0x0000000004000000 
#define ZYDIS_ATTRIB_HAS_BRANCH_TAKEN           0x0000000008000000 
#define ZYDIS_ATTRIB_HAS_EVEX                   0x0000000000000020 
#define ZYDIS_ATTRIB_HAS_LOCK                   0x0000000000080000 
#define ZYDIS_ATTRIB_HAS_MODRM                  0x0000000000000001 
#define ZYDIS_ATTRIB_HAS_MVEX                   0x0000000000000040 
#define ZYDIS_ATTRIB_HAS_NOTRACK                0x0000100000000000 
#define ZYDIS_ATTRIB_HAS_OPERANDSIZE            0x0000000400000000 
#define ZYDIS_ATTRIB_HAS_REP                    0x0000000000100000 
#define ZYDIS_ATTRIB_HAS_REPE                   0x0000000000200000 
#define ZYDIS_ATTRIB_HAS_REPNE                  0x0000000000400000 
#define ZYDIS_ATTRIB_HAS_REPNZ                  0x0000000000400000 
#define ZYDIS_ATTRIB_HAS_REPZ                   0x0000000000200000 
#define ZYDIS_ATTRIB_HAS_REX                    0x0000000000000004 
#define ZYDIS_ATTRIB_HAS_SEGMENT                0x00000003F0000000
#define ZYDIS_ATTRIB_HAS_SEGMENT_CS             0x0000000010000000 
#define ZYDIS_ATTRIB_HAS_SEGMENT_DS             0x0000000040000000 
#define ZYDIS_ATTRIB_HAS_SEGMENT_ES             0x0000000080000000 
#define ZYDIS_ATTRIB_HAS_SEGMENT_FS             0x0000000100000000 
#define ZYDIS_ATTRIB_HAS_SEGMENT_GS             0x0000000200000000 
#define ZYDIS_ATTRIB_HAS_SEGMENT_SS             0x0000000020000000 
#define ZYDIS_ATTRIB_HAS_SIB                    0x0000000000000002 
#define ZYDIS_ATTRIB_HAS_VEX                    0x0000000000000010 
#define ZYDIS_ATTRIB_HAS_XACQUIRE               0x0000000001000000 
#define ZYDIS_ATTRIB_HAS_XOP                    0x0000000000000008 
#define ZYDIS_ATTRIB_HAS_XRELEASE               0x0000000002000000 
#define ZYDIS_ATTRIB_IS_PRIVILEGED              0x0000000000000100 
#define ZYDIS_ATTRIB_IS_RELATIVE                0x0000000000000080 
#define ZYDIS_ATTRIB_XMM_STATE_CR               0x0000020000000000 
#define ZYDIS_ATTRIB_XMM_STATE_CW               0x0000040000000000 
#define ZYDIS_CPUFLAG_AC    18
#define ZYDIS_CPUFLAG_AF     4
#define ZYDIS_CPUFLAG_C0    22
#define ZYDIS_CPUFLAG_C1    23
#define ZYDIS_CPUFLAG_C2    24
#define ZYDIS_CPUFLAG_C3    25
#define ZYDIS_CPUFLAG_CF     0
#define ZYDIS_CPUFLAG_DF    10
#define ZYDIS_CPUFLAG_ID    21
#define ZYDIS_CPUFLAG_IF     9
#define ZYDIS_CPUFLAG_IOPL  12
#define ZYDIS_CPUFLAG_MAX_VALUE     ZYDIS_CPUFLAG_C3
#define ZYDIS_CPUFLAG_NT    14
#define ZYDIS_CPUFLAG_OF    11
#define ZYDIS_CPUFLAG_PF     2
#define ZYDIS_CPUFLAG_RF    16
#define ZYDIS_CPUFLAG_SF     7
#define ZYDIS_CPUFLAG_TF     8
#define ZYDIS_CPUFLAG_VIF   19
#define ZYDIS_CPUFLAG_VIP   20
#define ZYDIS_CPUFLAG_VM    17
#define ZYDIS_CPUFLAG_ZF     6
#define ZYDIS_FPUFLAG_C0    0x00 
#define ZYDIS_FPUFLAG_C1    0x01 
#define ZYDIS_FPUFLAG_C2    0x02 
#define ZYDIS_FPUFLAG_C3    0x04 

#define ZYDIS_OATTRIB_IS_MULTISOURCE4   0x01 
#define ZYDIS_MAX_INSTRUCTION_LENGTH 15
#define ZYDIS_MAX_OPERAND_COUNT      10





