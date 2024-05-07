














#include<stdio.h>




#include<errno.h>

#include<ctype.h>
#include<sys/stat.h>
#include<time.h>



#include<string.h>


#include<sys/time.h>
#define BER_CLASS_ANY   99			
#define BER_NOT_DECODED_YET(x) \
proto_tree_add_text(tree, tvb, offset, 0, "something unknown here [%s]",x); \
fprintf(stderr,"Not decoded yet in packet : %d  [%s]\n", pinfo->fd->num,x); \
if (check_col(pinfo->cinfo, COL_INFO)){ \
	col_append_fstr(pinfo->cinfo, COL_INFO, "[UNKNOWN BER: %s]", x); \
} \
tvb_get_guint8(tvb, 9999);
#define NO_BOUND -1

#define ASN1_CTX_SIGNATURE 0x41435458  
#define ASN1_DFLT     0x08
#define ASN1_EXT_EXT  0x02
#define ASN1_EXT_ROOT 0x01
#define ASN1_HAS_EXT(f) ((f)&(ASN1_EXT_ROOT|ASN1_EXT_EXT))
#define ASN1_OPT      0x04
#define ROSE_CTX_SIGNATURE 0x524F5345  

#define GUID_STR_LEN 37
#define MAX_ADDR_STR_LEN 256
#define MAX_IP_STR_LEN 16

#define address_to_str ep_address_to_str
#define DESEGMENT_ONE_MORE_SEGMENT 0x0fffffff
#define DESEGMENT_UNTIL_FIN        0x0ffffffe
#define MAX_NUMBER_OF_PPIDS     2
#define PINFO_EOF_INVALID       0x40
#define PINFO_EOF_LAST_FRAME    0x80
#define PINFO_SOF_FIRST_FRAME   0x1
#define PINFO_SOF_SOFF          0x2

#define BASE_DISPLAY_E_MASK 0x0F
#define BASE_EXT_STRING 0x20
#define BASE_RANGE_STRING 0x10
#define CHECK_DISPLAY_AS_X(x_handle,index, tvb, pinfo, tree) {	\
	if (!proto_is_protocol_enabled(find_protocol_by_id(index))) {	\
		call_dissector(x_handle,tvb, pinfo, tree);		\
		return;							\
	}								\
  }
#define DISSECTOR_ASSERT(expression)  \
  ((void) ((expression) ? (void)0 : \
   __DISSECTOR_ASSERT (expression, "__FILE__", "__LINE__")))
#define DISSECTOR_ASSERT_NOT_REACHED()  \
  (REPORT_DISSECTOR_BUG( \
    ep_strdup_printf("%s:%u: failed assertion \"DISSECTOR_ASSERT_NOT_REACHED\"", \
     "__FILE__", "__LINE__")))
#define FI_BIG_ENDIAN           0x00000010
#define FI_BITS_OFFSET(n)        ((n & 7) << 5) 
#define FI_BITS_SIZE(n)         ((n & 63) << 8)
#define FI_GET_BITS_OFFSET(fi) (FI_GET_FLAG(fi, FI_BITS_OFFSET(7)) >> 5)
#define FI_GET_BITS_SIZE(fi)   (FI_GET_FLAG(fi, FI_BITS_SIZE(63)) >> 8)
#define FI_GET_FLAG(fi, flag) ((fi) ? (fi->flags & flag) : 0)
#define FI_LITTLE_ENDIAN        0x00000008
#define FI_SET_FLAG(fi, flag) \
    do { \
      if (fi) \
        (fi)->flags = (fi)->flags | (flag); \
    } while(0)
#define FI_URL                  0x00000004
#define HFILL 0, 0, HF_REF_TYPE_NONE, 0, NULL, NULL
#define IS_BASE_DUAL(b) ((b)==BASE_DEC_HEX||(b)==BASE_HEX_DEC)
#define PITEM_FINFO(proto_item)  PNODE_FINFO(proto_item)
#define PI_PROTOCOL             0x09000000
#define PNODE_FINFO(proto_node)  ((proto_node)->finfo)
#define PROTO_ITEM_IS_GENERATED(proto_item)	\
	((proto_item) ? FI_GET_FLAG(PITEM_FINFO(proto_item), FI_GENERATED) : 0)
#define PROTO_ITEM_IS_HIDDEN(proto_item)        \
	((proto_item) ? FI_GET_FLAG(PITEM_FINFO(proto_item), FI_HIDDEN) : 0)
#define PROTO_ITEM_IS_URL(proto_item)	\
	((proto_item) ? FI_GET_FLAG(PITEM_FINFO(proto_item), FI_URL) : 0)
#define PROTO_ITEM_SET_GENERATED(proto_item)	\
    do { \
      if (proto_item) \
        FI_SET_FLAG(PITEM_FINFO(proto_item), FI_GENERATED); \
    } while(0)
#define PROTO_ITEM_SET_HIDDEN(proto_item)       \
  do { \
    if (proto_item) \
      FI_SET_FLAG(PITEM_FINFO(proto_item), FI_HIDDEN); \
	} while(0)
#define PROTO_ITEM_SET_URL(proto_item)	\
    do { \
      if (proto_item) \
        FI_SET_FLAG(PITEM_FINFO(proto_item), FI_URL); \
    } while(0)
#define PTREE_DATA(proto_tree)   ((proto_tree)->tree_data)
#define PTREE_FINFO(proto_tree)  PNODE_FINFO(proto_tree)
#define REPORT_DISSECTOR_BUG(message)  \
  ((getenv("WIRESHARK_ABORT_ON_DISSECTOR_BUG") != NULL) ? \
    abort() : \
    THROW_MESSAGE(DissectorError, message))
#define RVALS(x) (const struct _range_string*)(x)
#define TFS(x)	(const struct true_false_string*)(x)
#define VALS(x)	(const struct _value_string*)(x)
#define __DISSECTOR_ASSERT(expression, file, lineno)  \
  (REPORT_DISSECTOR_BUG( \
    ep_strdup_printf("%s:%u: failed assertion \"%s\"", \
     file, lineno, __DISSECTOR_ASSERT_STRINGIFY(expression))))
#define __DISSECTOR_ASSERT_STRINGIFY(s)	# s

#define g_ptr_array_len(a)      ((a)?(a)->len:0)


#define ws_close close
#define ws_dir_get_name(dirent)	dirent
#define ws_dup   dup
#define ws_lseek lseek
#define ws_read  read
#define ws_write write
#define DEFAULT_PROFILE      "Default"

#define CHK_STR_IS_DECL(what) \
gboolean uat_fld_chk_str_ ## what (void*, const char*, unsigned, const void*, const void*, const char**)
#define CHK_STR_IS_DEF(what) \
gboolean uat_fld_chk_str_ ## what (void* u1 _U_, const char* strptr, unsigned len, const void* u2 _U_, const void* u3 _U_, const char** err) { \
	guint i; for (i=0;i<len;i++) { \
		char c = strptr[i]; \
			if (! what((int)c)) { \
				*err = ep_strdup_printf("invalid char pos=%d value=%.2x",i,c); return FALSE;  } } \
		*err = NULL; return TRUE; }
#define FLDFILL NULL
#define UAT_BUFFER_CB_DEF(basename,field_name,rec_t,ptr_element,len_element) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) {\
        char* new_buf = len ? g_memdup(buf,len) : NULL; \
	g_free((((rec_t*)rec)->ptr_element)); \
	(((rec_t*)rec)->ptr_element) = new_buf; \
	(((rec_t*)rec)->len_element) = len; } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
	*out_ptr = ((rec_t*)rec)->ptr_element ? ep_memdup(((rec_t*)rec)->ptr_element,((rec_t*)rec)->len_element) : ""; \
	*out_len = ((rec_t*)rec)->len_element; }
#define UAT_CAT_CRYPTO "Decryption"
#define UAT_CAT_FFMT "File Formats"
#define UAT_CAT_GENERAL "General"
#define UAT_CAT_PORTS "Port Assignments"
#define UAT_CSTRING_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) {\
    char* new_buf = g_strndup(buf,len); \
	g_free((((rec_t*)rec)->field_name)); \
	(((rec_t*)rec)->field_name) = new_buf; } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
		if (((rec_t*)rec)->field_name ) { \
			*out_ptr = (((rec_t*)rec)->field_name); \
			*out_len = (unsigned)strlen((((rec_t*)rec)->field_name)); \
		} else { \
			*out_ptr = ""; *out_len = 0; } }
#define UAT_DEC_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) {\
	((rec_t*)rec)->field_name = strtol(ep_strndup(buf,len),NULL,10); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
	*out_ptr = ep_strdup_printf("%d",((rec_t*)rec)->field_name); \
	*out_len = (unsigned)strlen(*out_ptr); }
#define UAT_END_FIELDS {NULL,NULL,PT_TXTMOD_NONE,{0,0,0},{0,0,0},0,0,FLDFILL}
#define UAT_FLD_BUFFER(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_HEXBYTES,{0,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}
#define UAT_FLD_CSTRING(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_str,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}
#define UAT_FLD_CSTRING_ISPRINT(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_str_isprint,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}
#define UAT_FLD_CSTRING_OTHER(basename,field_name,title,chk,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{ chk ,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}
#define UAT_FLD_DEC(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_num_dec,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}
#define UAT_FLD_HEX(basename,field_name,title,desc) \
{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_num_hex,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}
#define UAT_FLD_LSTRING(basename,field_name,title, desc) \
{#field_name, title, PT_TXTMOD_STRING,{0,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}
#define UAT_FLD_OID(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_oid,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}
#define UAT_FLD_PATHNAME(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_str,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}
#define UAT_FLD_PROTO(basename,field_name,title,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_proto,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}
#define UAT_FLD_RANGE(basename,field_name,title,max,desc) \
	{#field_name, title, PT_TXTMOD_STRING,{uat_fld_chk_range,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},\
	  {GUINT_TO_POINTER(max),GUINT_TO_POINTER(max),GUINT_TO_POINTER(max)},0,desc,FLDFILL}
#define UAT_FLD_VS(basename,field_name,title,enum,desc) \
	{#field_name, title, PT_TXTMOD_ENUM,{uat_fld_chk_enum,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{&(enum),&(enum),&(enum)},&(enum),desc,FLDFILL}
#define UAT_HEX_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) {\
	((rec_t*)rec)->field_name = strtol(ep_strndup(buf,len),NULL,16); } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
	*out_ptr = ep_strdup_printf("%x",((rec_t*)rec)->field_name); \
	*out_len = (unsigned)strlen(*out_ptr); }
#define UAT_LSTRING_CB_DEF(basename,field_name,rec_t,ptr_element,len_element) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) {\
	char* new_val = uat_unesc(buf,len,&(((rec_t*)rec)->len_element)); \
        g_free((((rec_t*)rec)->ptr_element)); \
	(((rec_t*)rec)->ptr_element) = new_val; }\
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
	if (((rec_t*)rec)->ptr_element ) { \
		*out_ptr = uat_esc(((rec_t*)rec)->ptr_element, (((rec_t*)rec)->len_element)); \
		*out_len = (unsigned)strlen(*out_ptr); \
	} else { \
		*out_ptr = ""; *out_len = 0; } }
#define UAT_PROTO_DEF(basename, field_name, dissector_field, name_field, rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2 _U_) {\
	if (len) { \
		((rec_t*)rec)->name_field = g_strndup(buf,len); g_ascii_strdown(((rec_t*)rec)->name_field, -1); g_strchug(((rec_t*)rec)->name_field); \
		((rec_t*)rec)->dissector_field = find_dissector(((rec_t*)rec)->name_field); \
	} else { \
		((rec_t*)rec)->dissector_field = find_dissector("data"); \
		((rec_t*)rec)->name_field = NULL; \
		} } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
	if ( ((rec_t*)rec)->name_field ) { \
		*out_ptr = (((rec_t*)rec)->name_field); \
		*out_len = (unsigned)strlen(*out_ptr); \
	} else { \
		*out_ptr = ""; *out_len = 0; } }
#define UAT_RANGE_CB_DEF(basename,field_name,rec_t) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* u1 _U_, const void* u2) {\
	char* rng = ep_strndup(buf,len);\
		range_convert_str(&(((rec_t*)rec)->field_name), rng,GPOINTER_TO_UINT(u2)); \
	} \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* u1 _U_, const void* u2 _U_) {\
	if ( ((rec_t*)rec)->field_name ) { \
		*out_ptr = range_convert_range(((rec_t*)rec)->field_name); \
		*out_len = (unsigned)strlen(*out_ptr); \
	} else { \
		*out_ptr = ""; *out_len = 0; } }
#define UAT_VS_CSTRING_DEF(basename,field_name,rec_t,default_val,default_str) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* vs, const void* u2 _U_) {\
	guint i; \
	char* str = ep_strndup(buf,len); \
	const char* cstr; ((rec_t*)rec)->field_name = default_val; \
	for(i=0; ( cstr = ((value_string*)vs)[i].strptr ) ;i++) { \
		if (g_str_equal(cstr,str)) { \
		  ((rec_t*)rec)->field_name = g_strdup(((value_string*)vs)[i].strptr); return; } } } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* vs _U_, const void* u2 _U_) {\
		if (((rec_t*)rec)->field_name ) { \
			*out_ptr = (((rec_t*)rec)->field_name); \
			*out_len = (unsigned)strlen((((rec_t*)rec)->field_name)); \
		} else { \
			*out_ptr = ""; *out_len = 0; } }
#define UAT_VS_DEF(basename,field_name,rec_t,default_val,default_str) \
static void basename ## _ ## field_name ## _set_cb(void* rec, const char* buf, unsigned len, const void* vs, const void* u2 _U_) {\
	guint i; \
	char* str = ep_strndup(buf,len); \
	const char* cstr; ((rec_t*)rec)->field_name = default_val; \
	for(i=0; ( cstr = ((value_string*)vs)[i].strptr ) ;i++) { \
		if (g_str_equal(cstr,str)) { \
			((rec_t*)rec)->field_name = ((value_string*)vs)[i].value; return; } } } \
static void basename ## _ ## field_name ## _tostr_cb(void* rec, const char** out_ptr, unsigned* out_len, const void* vs, const void* u2 _U_) {\
	guint i; \
	*out_ptr = ep_strdup(default_str); \
	*out_len = (unsigned)strlen(default_str);\
	for(i=0;((value_string*)vs)[i].strptr;i++) { \
		if ( ((value_string*)vs)[i].value == ((rec_t*)rec)->field_name ) { \
			*out_ptr = ep_strdup(((value_string*)vs)[i].strptr); \
			*out_len = (unsigned)strlen(*out_ptr); return; } } }


#define BER_TAG_ANY -1

#define add_oid_debug_subtree(a,b) ((void)0)
#define oid_resolv_cleanup() ((void)0)
#define subid_t guint32

#define FT_ETHER_LEN        6
#define FT_GUID_LEN         16
#define FT_IPXNET_LEN       4
#define FT_IPv4_LEN         4
#define FT_IPv6_LEN         16
#define FVALUE_CLEANUP(fv)					\
	{							\
		register FvalueFreeFunc	free_value;		\
		free_value = (fv)->ftype->free_value;	\
		if (free_value) {				\
			free_value((fv));			\
		}						\
	}
#define FVALUE_FREE(fv)						\
	{							\
		FVALUE_CLEANUP(fv)				\
		SLAB_FREE(fv, fvalue_t);			\
	}
#define IS_FT_INT(ft)    ((ft)==FT_INT8||(ft)==FT_INT16||(ft)==FT_INT24||(ft)==FT_INT32||(ft)==FT_INT64)
#define IS_FT_STRING(ft) ((ft)==FT_STRING||(ft)==FT_STRINGZ)
#define IS_FT_TIME(ft)   ((ft)==FT_ABSOLUTE_TIME||(ft)==FT_RELATIVE_TIME)
#define IS_FT_UINT(ft)   ((ft)==FT_UINT8||(ft)==FT_UINT16||(ft)==FT_UINT24||(ft)==FT_UINT32||(ft)==FT_UINT64||(ft)==FT_FRAMENUM)


#define nstime_add(sum, a) nstime_sum(sum, sum, a)
#define ASCEND_MAX_STR_LEN 64
#define ASCEND_PFX_ETHER 6
#define ASCEND_PFX_ISDN_R 5
#define ASCEND_PFX_ISDN_X 4
#define ASCEND_PFX_WDD   3
#define ASCEND_PFX_WDS_R 2
#define ASCEND_PFX_WDS_X 1
#define BTHCI_CHANNEL_ACL     2
#define BTHCI_CHANNEL_COMMAND 1
#define BTHCI_CHANNEL_EVENT   4
#define BTHCI_CHANNEL_SCO     3
#define COSINE_DIR_RX 2
#define COSINE_DIR_TX 1
#define IRDA_CLASS_FRAME    0x0000
#define IRDA_CLASS_LOG      0x0100
#define IRDA_CLASS_MASK     0xFF00
#define IRDA_INCOMING       0x0000
#define IRDA_LOG_MESSAGE    0x0100  
#define IRDA_MISSED_MSG     0x0101  
#define IRDA_OUTGOING       0x0004
#define K12_PORT_ATMPVC    0x01020000
#define K12_PORT_DS0S      0x00010008
#define K12_PORT_DS1       0x00100008
#define LIBPCAP_BT_PHDR_RECV    1
#define LIBPCAP_BT_PHDR_SENT    0
#define LIBPCAP_PPP_PHDR_RECV    0
#define LIBPCAP_PPP_PHDR_SENT    1
#define MTP2_ANNEX_A_NOT_USED      0
#define MTP2_ANNEX_A_USED          1
#define MTP2_ANNEX_A_USED_UNKNOWN  2
#define WTAP_ENCAP_APPLE_IP_OVER_IEEE1394       62
#define WTAP_ENCAP_ARCNET                       8
#define WTAP_ENCAP_ARCNET_LINUX                 9
#define WTAP_ENCAP_ASCEND                       16
#define WTAP_ENCAP_ATM_PDUS                     13
#define WTAP_ENCAP_ATM_PDUS_UNTRUNCATED         14
#define WTAP_ENCAP_ATM_RFC1483                  10
#define WTAP_ENCAP_BACNET_MS_TP                 63
#define WTAP_ENCAP_BER                          90
#define WTAP_ENCAP_BLUETOOTH_H4                 41
#define WTAP_ENCAP_BLUETOOTH_H4_WITH_PHDR       99
#define WTAP_ENCAP_BLUETOOTH_HCI                102 
#define WTAP_ENCAP_CAN20B                       109
#define WTAP_ENCAP_CATAPULT_DCT2000             89
#define WTAP_ENCAP_CHDLC                        28
#define WTAP_ENCAP_CHDLC_WITH_PHDR              40
#define WTAP_ENCAP_CISCO_IOS                    29
#define WTAP_ENCAP_COSINE                       34
#define WTAP_ENCAP_DOCSIS                       33
#define WTAP_ENCAP_DPNSS                        117
#define WTAP_ENCAP_ENC                          38
#define WTAP_ENCAP_ERF                          98
#define WTAP_ENCAP_ETHERNET                     1
#define WTAP_ENCAP_FDDI                         5
#define WTAP_ENCAP_FDDI_BITSWAPPED              6
#define WTAP_ENCAP_FIBRE_CHANNEL_FC2            121
#define WTAP_ENCAP_FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS 122
#define WTAP_ENCAP_FLEXRAY                      106
#define WTAP_ENCAP_FRELAY                       26
#define WTAP_ENCAP_FRELAY_WITH_PHDR             27
#define WTAP_ENCAP_GCOM_SERIAL                  78
#define WTAP_ENCAP_GCOM_TIE1                    77
#define WTAP_ENCAP_GPRS_LLC                     66
#define WTAP_ENCAP_GSM_UM                       116
#define WTAP_ENCAP_HHDLC                        32
#define WTAP_ENCAP_I2C                          112
#define WTAP_ENCAP_IEEE802_15_4                 104
#define WTAP_ENCAP_IEEE802_15_4_NONASK_PHY      113
#define WTAP_ENCAP_IEEE802_16_MAC_CPS           93
#define WTAP_ENCAP_IEEE_802_11                  20
#define WTAP_ENCAP_IEEE_802_11_WITH_RADIO       22
#define WTAP_ENCAP_IEEE_802_11_WLAN_AVS         24
#define WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP    23
#define WTAP_ENCAP_IPMB                         103
#define WTAP_ENCAP_IPNET                        124
#define WTAP_ENCAP_IP_OVER_FC                   18
#define WTAP_ENCAP_IRDA                         44
#define WTAP_ENCAP_ISDN                         17
#define WTAP_ENCAP_JPEG_JFIF                    123
#define WTAP_ENCAP_JUNIPER_ATM1                 67
#define WTAP_ENCAP_JUNIPER_ATM2                 68
#define WTAP_ENCAP_JUNIPER_CHDLC                86
#define WTAP_ENCAP_JUNIPER_ETHER                83
#define WTAP_ENCAP_JUNIPER_FRELAY               85
#define WTAP_ENCAP_JUNIPER_GGSN                 87
#define WTAP_ENCAP_JUNIPER_MLFR                 82
#define WTAP_ENCAP_JUNIPER_MLPPP                81
#define WTAP_ENCAP_JUNIPER_PPP                  84
#define WTAP_ENCAP_JUNIPER_PPPOE                76
#define WTAP_ENCAP_JUNIPER_VP                   91
#define WTAP_ENCAP_K12                          80
#define WTAP_ENCAP_LAPB                         12
#define WTAP_ENCAP_LAYER1_EVENT                 110
#define WTAP_ENCAP_LIN                          107
#define WTAP_ENCAP_LINUX_ATM_CLIP               11
#define WTAP_ENCAP_LINUX_LAPD                   88
#define WTAP_ENCAP_LOCALTALK                    30
#define WTAP_ENCAP_MOST                         108
#define WTAP_ENCAP_MPEG                         96
#define WTAP_ENCAP_MTP2                         42
#define WTAP_ENCAP_MTP2_WITH_PHDR               75
#define WTAP_ENCAP_MTP3                         43
#define WTAP_ENCAP_NETTL_ETHERNET               71
#define WTAP_ENCAP_NETTL_FDDI                   73
#define WTAP_ENCAP_NETTL_RAW_ICMP               64
#define WTAP_ENCAP_NETTL_RAW_ICMPV6             65
#define WTAP_ENCAP_NETTL_RAW_IP                 70
#define WTAP_ENCAP_NETTL_RAW_TELNET             94
#define WTAP_ENCAP_NETTL_TOKEN_RING             72
#define WTAP_ENCAP_NETTL_UNKNOWN                74
#define WTAP_ENCAP_NETTL_X25                    79
#define WTAP_ENCAP_NSTRACE_1_0                  119
#define WTAP_ENCAP_NSTRACE_2_0                  120
#define WTAP_ENCAP_NULL                         15
#define WTAP_ENCAP_OLD_PFLOG                    31
#define WTAP_ENCAP_PACKETLOGGER                 118
#define WTAP_ENCAP_PER_PACKET                   -1
#define WTAP_ENCAP_PFLOG                        39
#define WTAP_ENCAP_PPI                          97
#define WTAP_ENCAP_PPP                          4
#define WTAP_ENCAP_PPP_WITH_PHDR                19
#define WTAP_ENCAP_PRISM_HEADER                 21
#define WTAP_ENCAP_RAW_IP                       7
#define WTAP_ENCAP_REDBACK                      69
#define WTAP_ENCAP_SCCP                         101
#define WTAP_ENCAP_SDLC                         36
#define WTAP_ENCAP_SITA                         100
#define WTAP_ENCAP_SLIP                         3
#define WTAP_ENCAP_SLL                          25
#define WTAP_ENCAP_SOCKETCAN                    125
#define WTAP_ENCAP_SYMANTEC                     61
#define WTAP_ENCAP_TNEF                         114
#define WTAP_ENCAP_TOKEN_RING                   2
#define WTAP_ENCAP_TZSP                         37
#define WTAP_ENCAP_UNKNOWN                      0
#define WTAP_ENCAP_USB                          92
#define WTAP_ENCAP_USB_LINUX                    95
#define WTAP_ENCAP_USB_LINUX_MMAPPED            115
#define WTAP_ENCAP_USER0                        45
#define WTAP_ENCAP_USER1                        46
#define WTAP_ENCAP_USER10                       55
#define WTAP_ENCAP_USER11                       56
#define WTAP_ENCAP_USER12                       57
#define WTAP_ENCAP_USER13                       58
#define WTAP_ENCAP_USER14                       59
#define WTAP_ENCAP_USER15                       60
#define WTAP_ENCAP_USER2                        47
#define WTAP_ENCAP_USER3                        48
#define WTAP_ENCAP_USER4                        49
#define WTAP_ENCAP_USER5                        50
#define WTAP_ENCAP_USER6                        51
#define WTAP_ENCAP_USER7                        52
#define WTAP_ENCAP_USER8                        53
#define WTAP_ENCAP_USER9                        54
#define WTAP_ENCAP_WFLEET_HDLC                  35
#define WTAP_ENCAP_X2E_SERIAL                   111
#define WTAP_ENCAP_X2E_XORAYA                   105
#define WTAP_ERR_COMPRESSION_NOT_SUPPORTED -19
#define WTAP_FILE_5VIEWS                        9
#define WTAP_FILE_AIROPEEK_V9                   45
#define WTAP_FILE_ASCEND                        26
#define WTAP_FILE_BER                           12
#define WTAP_FILE_BTSNOOP                       51
#define WTAP_FILE_CATAPULT_DCT2000              14
#define WTAP_FILE_COMMVIEW                      49
#define WTAP_FILE_COSINE                        17
#define WTAP_FILE_CSIDS                         18
#define WTAP_FILE_DAINTREE_SNA                  56
#define WTAP_FILE_DBS_ETHERWATCH                19
#define WTAP_FILE_DCT3TRACE                     54
#define WTAP_FILE_ERF                           20
#define WTAP_FILE_ETHERPEEK_V56                 43
#define WTAP_FILE_ETHERPEEK_V7                  44
#define WTAP_FILE_EYESDN                        21
#define WTAP_FILE_HCIDUMP                       13
#define WTAP_FILE_I4BTRACE                      25
#define WTAP_FILE_IPTRACE_1_0                   10
#define WTAP_FILE_IPTRACE_2_0                   11
#define WTAP_FILE_ISERIES                       23
#define WTAP_FILE_ISERIES_UNICODE               24
#define WTAP_FILE_JPEG_JFIF                     59
#define WTAP_FILE_K12                           40
#define WTAP_FILE_K12TEXT                       47
#define WTAP_FILE_LANALYZER                     34
#define WTAP_FILE_MPEG                          46
#define WTAP_FILE_NETMON_1_x                    27
#define WTAP_FILE_NETMON_2_x                    28
#define WTAP_FILE_NETSCALER_1_0                 57
#define WTAP_FILE_NETSCALER_2_0                 58
#define WTAP_FILE_NETSCREEN                     48
#define WTAP_FILE_NETTL                         22
#define WTAP_FILE_NETWORK_INSTRUMENTS_V9        33
#define WTAP_FILE_NETXRAY_1_0                   16
#define WTAP_FILE_NETXRAY_1_1                   31
#define WTAP_FILE_NETXRAY_2_00x                 32
#define WTAP_FILE_NETXRAY_OLD                   15
#define WTAP_FILE_NGSNIFFER_COMPRESSED          30
#define WTAP_FILE_NGSNIFFER_UNCOMPRESSED        29
#define WTAP_FILE_PACKETLOGGER                  55
#define WTAP_FILE_PCAP                          2
#define WTAP_FILE_PCAPNG                        50
#define WTAP_FILE_PCAP_AIX                      4
#define WTAP_FILE_PCAP_NOKIA                    6
#define WTAP_FILE_PCAP_NSEC                     3
#define WTAP_FILE_PCAP_SS990417                 7
#define WTAP_FILE_PCAP_SS990915                 8
#define WTAP_FILE_PCAP_SS991029                 5
#define WTAP_FILE_PPPDUMP                       35
#define WTAP_FILE_RADCOM                        36
#define WTAP_FILE_SHOMITI                       38
#define WTAP_FILE_SNOOP                         37
#define WTAP_FILE_TNEF                          53
#define WTAP_FILE_TOSHIBA                       41
#define WTAP_FILE_UNKNOWN                       0
#define WTAP_FILE_VISUAL_NETWORKS               42
#define WTAP_FILE_VMS                           39
#define WTAP_FILE_WTAP                          1
#define WTAP_FILE_X2E_XORAYA                    52
#define WTAP_NUM_ENCAP_TYPES                    wtap_get_num_encap_types()
#define WTAP_NUM_FILE_TYPES                     wtap_get_num_file_types()

#define TVB_GET_DS_TVB(tvb)		\
	(tvb->ds_tvb)
#define TVB_RAW_OFFSET(tvb)			\
	((tvb->raw_offset==-1)?(tvb->raw_offset = tvb_offset_from_real_beginning(tvb)):tvb->raw_offset)


#define guids_add_uuid(uuid, name) guids_add_guid((e_guid_t *) (uuid), (name))
#define guids_get_uuid_name(uuid) guids_get_guid_name((e_guid_t *) (uuid))
#define guids_resolve_uuid_to_str(uuid) guids_resolve_guid_to_str((e_guid_t *) (uuid))
#define E_IN6_IS_ADDR_LINKLOCAL(a)	\
	(((a)->bytes[0] == 0xfe) && (((a)->bytes[1] & 0xc0) == 0x80))
#define E_IN6_IS_ADDR_MULTICAST(a)	((a)->bytes[0] == 0xff)
#define E_IN6_IS_ADDR_SITELOCAL(a)	\
	(((a)->bytes[0] == 0xfe) && (((a)->bytes[1] & 0xc0) == 0xc0))


#define ipv4_addr_ne(a,b) !ipv4_addr_eq((a),(b))
#define FD_BLOCKSEQUENCE        0x0100
#define FD_NOT_MALLOCED         0x0020
#define FD_PARTIAL_REASSEMBLY   0x0040
#define DEF_HEIGHT 550
#define DEF_WIDTH 750
#define MAX_VAL_LEN  1024

#define PR_DEST_CMD  0
#define PR_DEST_FILE 1
#define RTP_PLAYER_DEFAULT_VISIBLE 4
#define TAP_UPDATE_DEFAULT_INTERVAL 3000

#define MAX_DCCP_PORT 65535
#define MAX_SCTP_PORT 65535
#define MAX_TCP_PORT 65535
#define MAX_UDP_PORT 65535


#define STRINGIFY(a)            _STRINGIFY(a)
#define _STRINGIFY(a)           # a

#define PACKET_COUNTS_SIZE sizeof(packet_counts) / sizeof (gint)

#define array_length(x)	(sizeof x / sizeof x[0])
#define hi_nibble(b) (((b) & 0xf0) >> 4)
#define lo_nibble(b) ((b) & 0x0f)
#define plurality(d,s,p) ((d) == 1 ? (s) : (p))
