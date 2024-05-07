































static gint proto_ber = -1;
static gint hf_ber_id_class = -1;
static gint hf_ber_id_pc = -1;
static gint hf_ber_id_uni_tag = -1;
static gint hf_ber_id_uni_tag_ext = -1;
static gint hf_ber_id_tag = -1;
static gint hf_ber_id_tag_ext = -1;
static gint hf_ber_length = -1;
static gint hf_ber_bitstring_padding = -1;
static gint hf_ber_bitstring_empty = -1;
static gint hf_ber_unknown_OID = -1;
static gint hf_ber_unknown_BOOLEAN = -1;
static gint hf_ber_unknown_OCTETSTRING = -1;
static gint hf_ber_unknown_BER_OCTETSTRING = -1;
static gint hf_ber_unknown_BER_primitive = -1;
static gint hf_ber_unknown_GraphicString = -1;
static gint hf_ber_unknown_NumericString = -1;
static gint hf_ber_unknown_PrintableString = -1;
static gint hf_ber_unknown_TeletexString = -1;
static gint hf_ber_unknown_VisibleString = -1;
static gint hf_ber_unknown_GeneralString = -1;
static gint hf_ber_unknown_UniversalString = -1;
static gint hf_ber_unknown_BMPString = -1;
static gint hf_ber_unknown_IA5String = -1;
static gint hf_ber_unknown_UTCTime = -1;
static gint hf_ber_unknown_UTF8String = -1;
static gint hf_ber_unknown_GeneralizedTime = -1;
static gint hf_ber_unknown_INTEGER = -1;
static gint hf_ber_unknown_BITSTRING = -1;
static gint hf_ber_unknown_ENUMERATED = -1;
static gint hf_ber_constructed_OCTETSTRING = -1;
static gint hf_ber_no_oid = -1;
static gint hf_ber_no_syntax = -1;
static gint hf_ber_oid_not_implemented = -1;
static gint hf_ber_syntax_not_implemented = -1;
static gint hf_ber_direct_reference = -1;         
static gint hf_ber_indirect_reference = -1;       
static gint hf_ber_data_value_descriptor = -1;    
static gint hf_ber_encoding = -1;                 
static gint hf_ber_single_ASN1_type = -1;         
static gint hf_ber_octet_aligned = -1;            
static gint hf_ber_arbitrary = -1;                

static gint ett_ber_octet_string = -1;
static gint ett_ber_primitive = -1;
static gint ett_ber_unknown = -1;
static gint ett_ber_SEQUENCE = -1;
static gint ett_ber_EXTERNAL = -1;
static gint ett_ber_T_encoding = -1;

static gboolean show_internal_ber_fields = FALSE;
static gboolean decode_octetstring_as_ber = FALSE;
static gboolean decode_primitive_as_ber = FALSE;
static gboolean decode_unexpected = FALSE;

static gchar *decode_as_syntax = NULL;
static gchar *ber_filename = NULL;

static dissector_table_t ber_oid_dissector_table=NULL;
static dissector_table_t ber_syntax_dissector_table=NULL;
static GHashTable *syntax_table=NULL;

static gint8 last_class;
static gboolean last_pc;
static gint32 last_tag;
static guint32 last_length;
static gboolean last_ind;

static const value_string ber_class_codes[] = {
	{ BER_CLASS_UNI,	"UNIVERSAL" }, { BER_CLASS_APP,	"APPLICATION" }, { BER_CLASS_CON,	"CONTEXT" }, { BER_CLASS_PRI,	"PRIVATE" }, { 0, NULL }



};

static const true_false_string ber_pc_codes = {
	"Constructed Encoding", "Primitive Encoding" };


static const true_false_string ber_pc_codes_short = {
	"constructed", "primitive" };


static const value_string ber_uni_tag_codes[] = {
	{ BER_UNI_TAG_EOC, 				"'end-of-content'" }, { BER_UNI_TAG_BOOLEAN, 			"BOOLEAN" }, { BER_UNI_TAG_INTEGER,			"INTEGER" }, { BER_UNI_TAG_BITSTRING,		"BIT STRING" }, { BER_UNI_TAG_OCTETSTRING,		"OCTET STRING" }, { BER_UNI_TAG_NULL,				"NULL" }, { BER_UNI_TAG_OID,				"OBJECT IDENTIFIER" }, { BER_UNI_TAG_ObjectDescriptor, "ObjectDescriptor" }, { BER_UNI_TAG_EXTERNAL,			"EXTERNAL" }, { BER_UNI_TAG_REAL,				"REAL" }, { BER_UNI_TAG_ENUMERATED,		"ENUMERATED" }, { BER_UNI_TAG_EMBEDDED_PDV,		"EMBEDDED PDV" }, { BER_UNI_TAG_UTF8String,		"UTF8String" }, { BER_UNI_TAG_RELATIVE_OID,		"RELATIVE-OID" },  { BER_UNI_TAG_SEQUENCE,			"SEQUENCE" }, { BER_UNI_TAG_SET,				"SET" }, { BER_UNI_TAG_NumericString,	"NumericString" }, { BER_UNI_TAG_PrintableString,	"PrintableString" }, { BER_UNI_TAG_TeletexString,	"TeletexString, T61String" }, { BER_UNI_TAG_VideotexString,	"VideotexString" }, { BER_UNI_TAG_IA5String,		"IA5String" }, { BER_UNI_TAG_UTCTime,			"UTCTime" }, { BER_UNI_TAG_GeneralizedTime,	"GeneralizedTime" }, { BER_UNI_TAG_GraphicString,	"GraphicString" }, { BER_UNI_TAG_VisibleString,	"VisibleString, ISO64String" }, { BER_UNI_TAG_GeneralString,	"GeneralString" }, { BER_UNI_TAG_UniversalString,	"UniversalString" }, { BER_UNI_TAG_CHARACTERSTRING,	"CHARACTER STRING" }, { BER_UNI_TAG_BMPString,		"BMPString" }, { 31,							"Continued" }, { 0, NULL }






























};

static const true_false_string ber_real_binary_vals = {
	"Binary encoding", "Decimal encoding" };


static const true_false_string ber_real_decimal_vals = {
	"SpecialRealValue", "Decimal encoding " };


typedef struct _da_data {
  GHFunc   func;
  gpointer user_data;
} da_data;

typedef struct _oid_user_t {
  char *oid;
  char *name;
  char *syntax;
} oid_user_t;

UAT_CSTRING_CB_DEF(oid_users, oid, oid_user_t);
UAT_CSTRING_CB_DEF(oid_users, name, oid_user_t);
UAT_VS_CSTRING_DEF(oid_users, syntax, oid_user_t, 0, "");

static oid_user_t *oid_users;
static guint num_oid_users;




static non_const_value_string syntax_names[MAX_SYNTAX_NAMES+1] = {
  {0, "", {0, NULL}
};

static void * oid_copy_cb(void *dest, const void *orig, unsigned len _U_)
{
	oid_user_t *u = dest;
	const oid_user_t *o = orig;

	u->oid = g_strdup(o->oid);
	u->name = g_strdup(o->name);
	u->syntax = o->syntax;

	return dest;
}

static void oid_free_cb(void *r)
{
	oid_user_t *u = r;

	g_free(u->oid);
	g_free(u->name);
}

static int cmp_value_string(const void *v1, const void *v2)
{
  value_string *vs1 = (value_string *)v1;
  value_string *vs2 = (value_string *)v2;

  return strcmp(vs1->strptr, vs2->strptr);
}

static uat_field_t users_flds[] = {
  UAT_FLD_OID(oid_users, oid, "OID", "Object Identifier"), UAT_FLD_CSTRING(oid_users, name, "Name", "Human readable name for the OID"), UAT_FLD_VS(oid_users, syntax, "Syntax", syntax_names, "Syntax of values associated with the OID"), UAT_END_FIELDS };




void dissect_ber_oid_NULL_callback(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_)
{
	return;
}


void register_ber_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name)
{
	dissector_add_string("ber.oid", oid, dissector);
	oid_add_from_string(name, oid);
}

void register_ber_oid_dissector(const char *oid, dissector_t dissector, int proto, const char *name)
{
	dissector_handle_t dissector_handle;

	dissector_handle=create_dissector_handle(dissector, proto);
	dissector_add_string("ber.oid", oid, dissector_handle);
	oid_add_from_string(name, oid);
}

void register_ber_syntax_dissector(const char *syntax, int proto, dissector_t dissector)
{
  dissector_handle_t dissector_handle;

  dissector_handle=create_dissector_handle(dissector, proto);
  dissector_add_string("ber.syntax", syntax, dissector_handle);

}

void register_ber_oid_syntax(const char *oid, const char *name, const char *syntax)
{

  if(syntax && *syntax)
    g_hash_table_insert(syntax_table, (const gpointer)g_strdup(oid), (const gpointer)g_strdup(syntax));

  if(name && *name)
    register_ber_oid_name(oid, name);
}


void register_ber_oid_name(const char *oid, const char *name)
{
	oid_add_from_string(name, oid);
}

static void ber_add_syntax_name(gpointer key, gpointer value _U_, gpointer user_data)
{
  guint *i = (guint*)user_data;

  if(*i < MAX_SYNTAX_NAMES) {
    syntax_names[*i].value = *i;
    syntax_names[*i].strptr = (const gchar*)key;

    (*i)++;
  }

}

static void ber_decode_as_dt(const gchar *table_name _U_, ftenum_t selector_type _U_, gpointer key, gpointer value, gpointer user_data)
{
  da_data *decode_as_data;

  decode_as_data = (da_data *)user_data;

  decode_as_data->func(key, value, decode_as_data->user_data);
}

void ber_decode_as_foreach(GHFunc func, gpointer user_data)
{
  da_data decode_as_data;

  decode_as_data.func = func;
  decode_as_data.user_data = user_data;

  dissector_table_foreach("ber.syntax",  ber_decode_as_dt, &decode_as_data);

}

void ber_decode_as(const gchar *syntax)
{

  if(decode_as_syntax) {
    g_free(decode_as_syntax);
    decode_as_syntax = NULL;
  }

  if(syntax)
    decode_as_syntax = g_strdup(syntax);
}


static const gchar * get_ber_oid_syntax(const char *oid)
{
       return g_hash_table_lookup(syntax_table, oid);
}

void ber_set_filename(gchar *filename)
{
  gchar      *ptr;

  if(ber_filename) {
    g_free(ber_filename);
    ber_filename = NULL;
  }

  if(filename) {

    ber_filename = g_strdup(filename);

    if((ptr = strrchr(ber_filename, '.')) != NULL) {

      ber_decode_as(get_ber_oid_syntax(ptr));

    }
  }
}


static void ber_update_oids(void)
{
  guint i;

  for(i = 0; i < num_oid_users; i++)
    register_ber_oid_syntax(oid_users[i].oid, oid_users[i].name, oid_users[i].syntax);
}

static void ber_check_length (guint32 length, gint32 min_len, gint32 max_len, asn1_ctx_t *actx, proto_item *item, gboolean bit)
{
  if (min_len != -1 && length < (guint32)min_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: %sstring too short: %d (%d .. %d)", bit ? "bit " : "", length, min_len, max_len);
  } else if (max_len != -1 && length > (guint32)max_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: %sstring too long: %d (%d .. %d)", bit ? "bit " : "", length, min_len, max_len);
  }
}

static void ber_check_value64 (gint64 value, gint64 min_len, gint64 max_len, asn1_ctx_t *actx, proto_item *item)
{
  if (min_len != -1 && value < min_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: value too small: %" G_GINT64_MODIFIER "d (%" G_GINT64_MODIFIER "d .. %" G_GINT64_MODIFIER "d)", value, min_len, max_len);
  } else if (max_len != -1 && value > max_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: value too big: %" G_GINT64_MODIFIER "d (%" G_GINT64_MODIFIER "d .. %" G_GINT64_MODIFIER "d)", value, min_len, max_len);
  }
}

static void ber_check_value (guint32 value, gint32 min_len, gint32 max_len, asn1_ctx_t *actx, proto_item *item)
{
  if (min_len != -1 && value < (guint32)min_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: value too small: %d (%d .. %d)", value, min_len, max_len);
  } else if (max_len != -1 && value > (guint32)max_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: value too big: %d (%d .. %d)", value, min_len, max_len);
  }
}

static void ber_check_items (int cnt, gint32 min_len, gint32 max_len, asn1_ctx_t *actx, proto_item *item)
{
  if (min_len != -1 && cnt < min_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: too few items: %d (%d .. %d)", cnt, min_len, max_len);
  } else if (max_len != -1 && cnt > max_len) {
    expert_add_info_format(actx->pinfo, item, PI_PROTOCOL, PI_WARN, "Size constraint: too many items: %d (%d .. %d)", cnt, min_len, max_len);
  }
}

int dissect_ber_tagged_type(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, gint8 tag_cls, gint32 tag_tag, gboolean tag_impl, ber_type_fn type)
{
 gint8 tmp_cls;
 gint32 tmp_tag;
 guint32 tmp_len;
 tvbuff_t *next_tvb = tvb;
 proto_item *cause;


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("dissect_ber_tagged_type(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("dissect_ber_tagged_type(%s) entered\n",name);
}
}


 if (implicit_tag) {
	offset = type(tag_impl, tvb, offset, actx, tree, hf_id);
	return offset;
 }

 offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &tmp_cls, NULL, &tmp_tag);
 offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &tmp_len, NULL);

 if ((tmp_cls != tag_cls) || (tmp_tag != tag_tag)) {
   cause = proto_tree_add_text(tree, tvb, offset, tmp_len, "BER Error: Wrong tag in tagged type - expected class:%s(%d) tag:%d (%s) but found class:%s(%d) tag:%d", val_to_str(tag_cls, ber_class_codes, "Unknown"), tag_cls, tag_tag, val_to_str(tag_tag, ber_uni_tag_codes,"Unknown"), val_to_str(tmp_cls, ber_class_codes, "Unknown"), tmp_cls, tmp_tag);


   proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
   expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong tag in tagged type");
 }

 if (tag_impl) {
	next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), tmp_len);
	type(tag_impl, next_tvb, 0, actx, tree, hf_id);
	offset += tmp_len;
 } else {
	offset = type(tag_impl, tvb, offset, actx, tree, hf_id);
 }

 return offset;
}

int dissect_unknown_ber(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree)
{
	int start_offset;
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;
	int hdr_len;
	proto_item *item=NULL;
	proto_tree *next_tree=NULL;
	guint8 c;
	guint32 i;
	gboolean is_printable, is_decoded_as;
	proto_item *pi, *cause;
	asn1_ctx_t asn1_ctx;

	start_offset=offset;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	offset=get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset=get_ber_length(tvb, offset, &len, &ind);

	if(len>(guint32)tvb_length_remaining(tvb, offset)){
		

	        if(show_internal_ber_fields) {
		  offset=dissect_ber_identifier(pinfo, tree, tvb, start_offset, &class, &pc, &tag);
		  offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	        }
		cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: length:%u longer than tvb_length_ramaining:%d",len, tvb_length_remaining(tvb, offset));
		proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		expert_add_info_format(pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error length");
		return tvb_length(tvb);
	}

	switch(pc){

	case FALSE: 

	  switch(class) { 
	  case BER_CLASS_UNI: 
		switch(tag){
		case BER_UNI_TAG_EOC:
		  
		  break;
		case BER_UNI_TAG_INTEGER:
			offset = dissect_ber_integer(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_INTEGER, NULL);
			break;
		case BER_UNI_TAG_BITSTRING:
			offset = dissect_ber_bitstring(FALSE, &asn1_ctx, tree, tvb, start_offset, NULL, hf_ber_unknown_BITSTRING, -1, NULL);
			break;
		case BER_UNI_TAG_ENUMERATED:
			offset = dissect_ber_integer(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_ENUMERATED, NULL);
			break;
		case BER_UNI_TAG_GraphicString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_GraphicString, NULL);
			break;
		case BER_UNI_TAG_OCTETSTRING:
			is_decoded_as = FALSE;
			if (decode_octetstring_as_ber) {
				int ber_offset;
				guint32 ber_len;
				ber_offset = get_ber_identifier(tvb, offset, NULL, &pc, NULL);
				ber_offset = get_ber_length(tvb, ber_offset, &ber_len, NULL);
				if (pc && (ber_len > 0) && (ber_len + (ber_offset - offset) == len)) {
					
					is_decoded_as = TRUE;
					if (show_internal_ber_fields) {
						offset = dissect_ber_identifier(pinfo, tree, tvb, start_offset, NULL, NULL, NULL);
						offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
					}
					item = proto_tree_add_item(tree, hf_ber_unknown_BER_OCTETSTRING, tvb, offset, len, FALSE);
					next_tree = proto_item_add_subtree(item, ett_ber_octet_string);
					offset = dissect_unknown_ber(pinfo, tvb, offset, next_tree);
				}
			}
			if (!is_decoded_as) {
				offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_OCTETSTRING, NULL);
			}
			break;
		case BER_UNI_TAG_OID:
			offset=dissect_ber_object_identifier_str(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_OID, NULL);
			break;
		case BER_UNI_TAG_NumericString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_NumericString, NULL);
			break;
		case BER_UNI_TAG_PrintableString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_PrintableString, NULL);
			break;
		case BER_UNI_TAG_TeletexString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_TeletexString, NULL);
			break;
		case BER_UNI_TAG_VisibleString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_VisibleString, NULL);
			break;
		case BER_UNI_TAG_GeneralString:
			offset = dissect_ber_GeneralString(&asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_GeneralString, NULL, 0);
			break;
		case BER_UNI_TAG_BMPString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_BMPString, NULL);
			break;
		case BER_UNI_TAG_UniversalString:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_UniversalString, NULL);
			break;
		case BER_UNI_TAG_IA5String:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_IA5String, NULL);
			break;
		case BER_UNI_TAG_UTCTime:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_UTCTime, NULL);
			break;
		case BER_UNI_TAG_NULL:
			proto_tree_add_text(tree, tvb, offset, len, "NULL tag");
			break;
		case BER_UNI_TAG_UTF8String:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_UTF8String, NULL);
			break;
		case BER_UNI_TAG_GeneralizedTime:
			offset = dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_GeneralizedTime, NULL);
			break;
		case BER_UNI_TAG_BOOLEAN:
			offset = dissect_ber_boolean(FALSE, &asn1_ctx, tree, tvb, start_offset, hf_ber_unknown_BOOLEAN, NULL);
			break;
		default:
			offset=dissect_ber_identifier(pinfo, tree, tvb, start_offset, &class, &pc, &tag);
			offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
			cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: can not handle universal tag:%d",tag);
			proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
			expert_add_info_format(pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: can not handle universal");
			offset += len;
		}
		break;
	  case BER_CLASS_APP:
	  case BER_CLASS_CON:
	  case BER_CLASS_PRI:
	  default:
	    
	    if(show_internal_ber_fields) {
	      offset=dissect_ber_identifier(pinfo, tree, tvb, start_offset, &class, &pc, &tag);
	      offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	    }

	    
	    pi = proto_tree_add_none_format(tree, hf_ber_unknown_BER_primitive, tvb, offset, len, "[%s %d] ", val_to_str(class,ber_class_codes,"Unknown"), tag);

	    is_decoded_as = FALSE;
	    if (decode_primitive_as_ber) {
	      int ber_offset;
	      guint32 ber_len;
	      ber_offset = get_ber_identifier(tvb, offset, NULL, &pc, NULL);
	      ber_offset = get_ber_length(tvb, ber_offset, &ber_len, NULL);
	      if (pc && (ber_len > 0) && (ber_len + (ber_offset - offset) == len)) {
		
		is_decoded_as = TRUE;
		proto_item_append_text (pi, "[BER encoded]");
		next_tree = proto_item_add_subtree(pi, ett_ber_primitive);
		offset = dissect_unknown_ber(pinfo, tvb, offset, next_tree);
	      }
	    }

	    if (!is_decoded_as && len) {
	      
	      is_printable = TRUE;
	      for(i=0;i<len;i++){
		c = tvb_get_guint8(tvb, offset+i);

		if(is_printable && !g_ascii_isprint(c))
		  is_printable=FALSE;

		proto_item_append_text(pi,"%02x",c);
	      }

	      if(is_printable) { 
		proto_item_append_text(pi," (");
		for(i=0;i<len;i++){
		  proto_item_append_text(pi,"%c",tvb_get_guint8(tvb, offset+i));
		}
		proto_item_append_text(pi,")");
	      }
	      offset += len;
	    }

	    break;
	  }
	  break;

	case TRUE: 

	  
	  if(show_internal_ber_fields) {
	    offset=dissect_ber_identifier(pinfo, tree, tvb, start_offset, &class, &pc, &tag);
	    offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);
	  }

	  hdr_len=offset-start_offset;

	  switch(class) {
	  case BER_CLASS_UNI:
       	    item=proto_tree_add_text(tree, tvb, offset, len, "%s", val_to_str(tag,ber_uni_tag_codes,"Unknown"));
		if(item){
			next_tree=proto_item_add_subtree(item, ett_ber_SEQUENCE);
		}
		while(offset < (int)(start_offset + len + hdr_len))
		  offset=dissect_unknown_ber(pinfo, tvb, offset, next_tree);
		break;
	  case BER_CLASS_APP:
	  case BER_CLASS_CON:
	  case BER_CLASS_PRI:
	  default:
       	    item=proto_tree_add_text(tree, tvb, offset, len, "[%s %d]", val_to_str(class,ber_class_codes,"Unknown"), tag);
		if(item){
			next_tree=proto_item_add_subtree(item, ett_ber_SEQUENCE);
		}
		while(offset < (int)(start_offset + len + hdr_len))
		  offset=dissect_unknown_ber(pinfo, tvb, offset, next_tree);
		break;

	  }
	  break;

	}

	return offset;
}


int call_ber_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;
	const char *syntax = NULL;

	if (!tvb) {
		return offset;
	}

	next_tvb = tvb_new_subset_remaining(tvb, offset);
	if(oid == NULL || ((((syntax = get_ber_oid_syntax(oid)) == NULL) ||  !dissector_try_string(ber_syntax_dissector_table, syntax, next_tvb, pinfo, tree)) &&  (!dissector_try_string(ber_oid_dissector_table, oid, next_tvb, pinfo, tree)))) {




		proto_item *item=NULL;
		proto_tree *next_tree=NULL;
		gint length_remaining;

		length_remaining = tvb_length_remaining(tvb, offset);

		if (oid == NULL) {
		  item=proto_tree_add_none_format(tree, hf_ber_no_oid, next_tvb, 0, length_remaining, "BER: No OID supplied to call_ber_oid_callback");
		  proto_item_set_expert_flags(item, PI_MALFORMED, PI_WARN);
		  expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "BER Error: No OID supplied");
		} else if (tvb_get_ntohs (tvb, offset) != 0x0500) { 
		  if(syntax)
		    item=proto_tree_add_none_format(tree, hf_ber_syntax_not_implemented, next_tvb, 0, length_remaining, "BER: Dissector for syntax:%s not implemented. Contact Wireshark developers if you want this supported", syntax);
		  else item=proto_tree_add_none_format(tree, hf_ber_oid_not_implemented, next_tvb, 0, length_remaining, "BER: Dissector for OID:%s not implemented. Contact Wireshark developers if you want this supported", oid);
		  proto_item_set_expert_flags(item, PI_MALFORMED, PI_WARN);
		  expert_add_info_format(pinfo, item, PI_UNDECODED, PI_WARN, "BER: Dissector for OID %s not implemented", oid);
		} else {
		  next_tree=tree;
		}
	        if (decode_unexpected) {
		  int ber_offset;
		  gint32 ber_len;

		  if(item){
			next_tree=proto_item_add_subtree(item, ett_ber_unknown);
		  }
		  ber_offset = get_ber_identifier(next_tvb, 0, NULL, NULL, NULL);
		  ber_offset = get_ber_length(next_tvb, ber_offset, &ber_len, NULL);
		  if ((ber_len + ber_offset) == length_remaining) {
		    
		    dissect_unknown_ber(pinfo, next_tvb, 0, next_tree);
		  } else {
		    proto_tree_add_text(next_tree, next_tvb, 0, length_remaining, "Unknown Data (%d byte%s)", length_remaining, plurality(length_remaining, "", "s"));

		  }
		}

	}

	
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}

static int call_ber_syntax_callback(const char *syntax, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;

	next_tvb = tvb_new_subset_remaining(tvb, offset);
	if(syntax == NULL || !dissector_try_string(ber_syntax_dissector_table, syntax, next_tvb, pinfo, tree)){
	  proto_item *item=NULL;
	  proto_tree *next_tree=NULL;

	  if (syntax == NULL)
	    item=proto_tree_add_none_format(tree, hf_ber_no_syntax, next_tvb, 0, tvb_length_remaining(tvb, offset), "BER: No syntax supplied to call_ber_syntax_callback");
	  else item=proto_tree_add_none_format(tree, hf_ber_syntax_not_implemented, next_tvb, 0, tvb_length_remaining(tvb, offset), "BER: Dissector for syntax: %s not implemented. Contact Wireshark developers if you want this supported", syntax);
	  if(item){
	    next_tree=proto_item_add_subtree(item, ett_ber_unknown);
	  }
	  dissect_unknown_ber(pinfo, next_tvb, 0, next_tree);
	}

	
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}





int get_ber_identifier(tvbuff_t *tvb, int offset, gint8 *class, gboolean *pc, gint32 *tag) {
	guint8 id, t;
	gint8 tmp_class;
	gboolean tmp_pc;
	gint32 tmp_tag;

	id = tvb_get_guint8(tvb, offset);
	offset += 1;

printf ("BER ID=%02x", id);

	
	tmp_class = (id>>6) & 0x03;
	tmp_pc = (id>>5) & 0x01;
	tmp_tag = id&0x1F;
	
	if (tmp_tag == 0x1F) {
		tmp_tag = 0;
		while (tvb_length_remaining(tvb, offset) > 0) {
			t = tvb_get_guint8(tvb, offset);

printf (" %02x", t);

			offset += 1;
			tmp_tag <<= 7;
			tmp_tag |= t & 0x7F;
			if (!(t & 0x80)) break;
		}
	}


printf ("\n");

	if (class)
		*class = tmp_class;
	if (pc)
		*pc = tmp_pc;
	if (tag)
		*tag = tmp_tag;

	last_class = tmp_class;
	last_pc = tmp_pc;
	last_tag = tmp_tag;

	return offset;
}

static void get_last_ber_identifier(gint8 *class, gboolean *pc, gint32 *tag)
{
	if (class)
		*class = last_class;
	if (pc)
		*pc = last_pc;
	if (tag)
		*tag = last_tag;

}

int dissect_ber_identifier(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, gint8 *class, gboolean *pc, gint32 *tag)
{
	int old_offset = offset;
	gint8 tmp_class;
	gboolean tmp_pc;
	gint32 tmp_tag;

	offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);

	if(show_internal_ber_fields){
		proto_tree_add_uint(tree, hf_ber_id_class, tvb, old_offset, 1, tmp_class<<6);
		proto_tree_add_boolean(tree, hf_ber_id_pc, tvb, old_offset, 1, (tmp_pc)?0x20:0x00);
		if(tmp_tag>0x1F){
			if(tmp_class==BER_CLASS_UNI){
				proto_tree_add_uint(tree, hf_ber_id_uni_tag_ext, tvb, old_offset + 1, offset - (old_offset + 1), tmp_tag);
			} else {
				proto_tree_add_uint(tree, hf_ber_id_tag_ext, tvb, old_offset + 1, offset - (old_offset + 1), tmp_tag);
			}
		} else {
			if(tmp_class==BER_CLASS_UNI){
				proto_tree_add_uint(tree, hf_ber_id_uni_tag, tvb, old_offset, 1, tmp_tag);
			} else {
				proto_tree_add_uint(tree, hf_ber_id_tag, tvb, old_offset, 1, tmp_tag);
			}
		}
	}

	if(class)
		*class = tmp_class;
	if(pc)
		*pc = tmp_pc;
	if(tag)
		*tag = tmp_tag;

	return offset;
}






static gboolean try_get_ber_length(tvbuff_t *tvb, int *bl_offset, gboolean pc, guint32 *length, gboolean *ind, gint nest_level) {
	int offset = *bl_offset;
	guint8 oct, len;
	guint32 tmp_len;
	gint8 tclass;
	gint32 ttag;
	gboolean tpc;
	guint32 tmp_length;
	gboolean tmp_ind;
	int tmp_offset;
	tmp_length = 0;
	tmp_ind = FALSE;
	
	if (nest_level > BER_MAX_INDEFINITE_NESTING) {
		
		THROW(ReportedBoundsError);
	}

	oct = tvb_get_guint8(tvb, offset);
	offset += 1;

	if(!(oct&0x80)) {
		
		tmp_length = oct;
	} else {
		len = oct & 0x7F;
		if(len) {
			
			while (len--) {
				oct = tvb_get_guint8(tvb, offset);
				offset++;
				tmp_length = (tmp_length<<8) + oct;
			}
		} else {
		    
		    

		    if(!pc)
			return FALSE;

		    tmp_offset = offset;

		    do {
			tmp_offset = get_ber_identifier(tvb, tmp_offset, &tclass, &tpc, &ttag);

			
			if(tmp_offset > offset && try_get_ber_length(tvb, &tmp_offset, tpc, &tmp_len, &tmp_ind, nest_level+1)) {
			    if (tmp_len > 0) {
				tmp_offset += tmp_len;
				continue;
			    }
			}

			return FALSE;

		    } while (!((tclass == BER_CLASS_UNI) && (ttag == 0) && (tmp_len == 0)));

		    tmp_length = tmp_offset - offset;
		    tmp_ind = TRUE;
		}
	}

	if (length)
		*length = tmp_length;
	if (ind)
		*ind = tmp_ind;


printf("get BER length %d, offset %d (remaining %d)\n", tmp_length, offset, tvb_length_remaining(tvb, offset));


	*bl_offset = offset;
	return TRUE;
}

int get_ber_length(tvbuff_t *tvb, int offset, guint32 *length, gboolean *ind)
{
	int bl_offset = offset;
	guint32 bl_length = 0;

	gint8 save_class;
	gboolean save_pc;
	gint32 save_tag;

	
	save_class = last_class;
	save_pc = last_pc;
	save_tag = last_tag;

	if(!try_get_ber_length(tvb, &bl_offset, last_pc, &bl_length, ind, 0)) {
	  
	  bl_offset = offset;
	}
	if (length)
	  *length = bl_length;

	
	last_class = save_class;
	last_pc = save_pc;
	last_tag = save_tag;


	return bl_offset;
}

static void get_last_ber_length(guint32 *length, gboolean *ind)
{
	if (length)
		*length = last_length;
	if (ind)
		*ind = last_ind;
}


int dissect_ber_length(packet_info *pinfo _U_, proto_tree *tree, tvbuff_t *tvb, int offset, guint32 *length, gboolean *ind)
{
	int old_offset = offset;
	guint32 tmp_length;
	gboolean tmp_ind;

	offset = get_ber_length(tvb, offset, &tmp_length, &tmp_ind);

	if(show_internal_ber_fields){
		if(tmp_ind){
			proto_tree_add_text(tree, tvb, old_offset, 1, "Length: Indefinite length %d", tmp_length);
		} else {
			proto_tree_add_uint(tree, hf_ber_length, tvb, old_offset, offset - old_offset, tmp_length);
		}
	}
	if(length)
		*length = tmp_length;
	if(ind)
		*ind = tmp_ind;


printf("dissect BER length %d, offset %d (remaining %d)\n", tmp_length, offset, tvb_length_remaining(tvb, offset));


 last_length = tmp_length;
 last_ind = tmp_ind;

	return offset;
}

static GHashTable *octet_segment_table = NULL;
static GHashTable *octet_reassembled_table = NULL;

static void ber_defragment_init(void) {
  fragment_table_init(&octet_segment_table);
  reassembled_table_init(&octet_reassembled_table);
}

int reassemble_octet_string(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, guint32 con_len, gboolean ind, tvbuff_t **out_tvb)
{
  fragment_data *fd_head = NULL;
  tvbuff_t *next_tvb = NULL;
  tvbuff_t *reassembled_tvb = NULL;
  guint16 dst_ref = 0;
  int start_offset = offset;
  gboolean fragment = TRUE;
  gboolean firstFragment = TRUE;

  

  
  actx->pinfo->fragmented = TRUE;

  if(out_tvb)
    *out_tvb=NULL;

  while(!fd_head) {

    offset = dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_ber_constructed_OCTETSTRING, &next_tvb);

    if (next_tvb == NULL) {
      
      THROW(ReportedBoundsError);
    }

    if(ind) {
      

      if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)) {
	fragment = FALSE;
	
	offset +=2;
      }
    } else {

    if((guint32)(offset - start_offset) >= con_len)
	fragment = FALSE;
    }

    if(!fragment && firstFragment) {
      
      
      reassembled_tvb = next_tvb;
      break;
    }


    if (tvb_length(next_tvb) < 1) {
      
      THROW(ReportedBoundsError);
    }
    fd_head = fragment_add_seq_next(next_tvb, 0, actx->pinfo, dst_ref, octet_segment_table, octet_reassembled_table, tvb_length(next_tvb), fragment);




    firstFragment = FALSE;
  }

  if(fd_head) {
    if(fd_head->next) {
      reassembled_tvb = tvb_new_child_real_data(next_tvb, fd_head->data, fd_head->len, fd_head->len);


      
      add_new_data_source(actx->pinfo, reassembled_tvb, "Reassembled OCTET STRING");

    }
  }

  if(out_tvb)
    *out_tvb = reassembled_tvb;

  
  actx->pinfo->fragmented = FALSE;

  return offset;

}


int dissect_ber_constrained_octet_string(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, gint hf_id, tvbuff_t **out_tvb) {
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;
	int hoffset;
	int end_offset;
	proto_item *it, *cause;
  guint32 i;
  guint32 len_remain;


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("OCTET STRING dissect_ber_octet string(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("OCTET STRING dissect_ber_octet_string(%s) entered\n",name);
}
}


	if(out_tvb)
		*out_tvb=NULL;

	if (!implicit_tag) {
		hoffset = offset;
		
		offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
		end_offset=offset+len;

		
		if ((class!=BER_CLASS_APP)&&(class!=BER_CLASS_PRI))

		if( (class!=BER_CLASS_UNI)
		  ||((tag<BER_UNI_TAG_NumericString)&&(tag!=BER_UNI_TAG_OCTETSTRING)&&(tag!=BER_UNI_TAG_UTF8String)) ){
		    tvb_ensure_bytes_exist(tvb, hoffset, 2);
		    cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: OctetString expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
		    proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: OctetString expected");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			return end_offset;
		}
	} else {
	  

	  get_last_ber_identifier(&class, &pc, &tag);
	  get_last_ber_length(&len, &ind);

	  end_offset=offset+len;

	  
	  len_remain = (guint32)tvb_length_remaining(tvb, offset);
	  if((ind) && (len_remain == len - 2)) {
			
			len -=2;
			end_offset -= 2;
			ind = FALSE;
	  } else if (len_remain < len) {
			
		  cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: length:%u longer than tvb_length_remaining:%d", len, len_remain);
		  proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		  expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error length");
		  return end_offset;
	  }

	}

	actx->created_item = NULL;

	if (pc) {
		
		end_offset = reassemble_octet_string(actx, tree, tvb, offset, len, ind, out_tvb);
	} else {
		
		gint length_remaining;

		length_remaining = tvb_length_remaining(tvb, offset);

		if(length_remaining<1){
			return end_offset;
		}


		if(len<=(guint32)length_remaining){
			length_remaining=len;
		}
		if(hf_id >= 0) {
			it = proto_tree_add_item(tree, hf_id, tvb, offset, length_remaining, FALSE);
			actx->created_item = it;
			ber_check_length(length_remaining, min_len, max_len, actx, it, FALSE);
		} else {
			proto_item *pi;

			pi=proto_tree_add_text(tree, tvb, offset, len, "Unknown OctetString: Length: 0x%02x, Value: 0x", len);
			if(pi){
				for(i=0;i<len;i++){
					proto_item_append_text(pi,"%02x",tvb_get_guint8(tvb, offset));
					offset++;
				}
			}
		}

		if(out_tvb) {
			*out_tvb = tvb_new_subset(tvb, offset, length_remaining, len);
		}
	}
	return end_offset;
}

int dissect_ber_octet_string(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **out_tvb) {
  return dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset, NO_BOUND, NO_BOUND, hf_id, out_tvb);
}

int dissect_ber_octet_string_wcb(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, ber_callback func)
{
	tvbuff_t *out_tvb = NULL;

	offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_id, (func)?&out_tvb:NULL);
	if (func && out_tvb && (tvb_length(out_tvb)>0)) {
		if (hf_id >= 0)
			tree = proto_item_add_subtree(actx->created_item, ett_ber_octet_string);
		
		func(FALSE, out_tvb, 0, actx, tree, -1);
	}
	return offset;
}

int dissect_ber_old_octet_string_wcb(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, ber_old_callback func)
{
	tvbuff_t *out_tvb = NULL;

	offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_id, (func)?&out_tvb:NULL);
	if (func && out_tvb && (tvb_length(out_tvb)>0)) {
		if (hf_id >= 0)
			tree = proto_item_add_subtree(actx->created_item, ett_ber_octet_string);
		
		func(tree, out_tvb, 0, actx);
	}
	return offset;
}

int dissect_ber_null(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id) {
  gint8 class;
  gboolean pc;
  gint32 tag;
  guint32 len;
  int offset_old;
  proto_item* cause;

if (!implicit_tag)
{
  offset_old = offset;
  offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
  if((pc) || (!implicit_tag && ((class != BER_CLASS_UNI) || (tag != BER_UNI_TAG_NULL)))) {
    cause = proto_tree_add_text(tree, tvb, offset_old, offset - offset_old, "BER Error: NULL expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
    proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: NULL expected");
  }

  offset_old = offset;
  offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
  if(len) {
    proto_tree_add_text(tree, tvb, offset_old, offset - offset_old, "BER Error: NULL expect zero length but Length=%d", len);
    cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: unexpected data in NULL type");
    proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: NULL expect zero length");
    offset += len;
  }
}
  if (hf_id >= 0)
	  proto_tree_add_item(tree, hf_id, tvb, offset, 0, FALSE);
  return offset;
}

int dissect_ber_integer64(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, gint64 *value)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	gint64 val;
	guint32 i;


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("INTEGERnew dissect_ber_integer(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("INTEGERnew dissect_ber_integer(%s) entered implicit_tag:%d \n",name,implicit_tag);
}
}



	if(value){
		*value=0;
	}

	if(!implicit_tag){
	  offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
	  offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
	} else {
	  gint32 remaining=tvb_length_remaining(tvb, offset);
	  len=remaining>0 ? remaining : 0;
	}

	
	if(len>8){
		header_field_info *hfinfo;
		proto_item *pi = NULL;

		if (hf_id >= 0) {
			hfinfo = proto_registrar_get_nth(hf_id);
			pi=proto_tree_add_text(tree, tvb, offset, len, "%s : 0x", hfinfo->name);
		}
		if(pi){
			for(i=0;i<len;i++){
				proto_item_append_text(pi,"%02x",tvb_get_guint8(tvb, offset));
				offset++;
			}
		} else {
			offset += len;
		}
		return offset;
	}

	val=0;
	if(len > 0) {
		
		if(tvb_get_guint8(tvb, offset)&0x80){
			val=-1;
		}
		for(i=0;i<len;i++){
			val=(val<<8)|tvb_get_guint8(tvb, offset);
			offset++;
		}
	}

	actx->created_item=NULL;

	if(hf_id >= 0){
		
		if(len < 1 || len > 8) {
			proto_tree_add_text(tree, tvb, offset-len, len, "Can't handle integer length: %u", len);
		} else {
			header_field_info* hfi;

			hfi = proto_registrar_get_nth(hf_id);
			switch(hfi->type){
			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
				actx->created_item=proto_tree_add_uint(tree, hf_id, tvb, offset-len, len, (guint32)val);
				break;
			case FT_INT8:
			case FT_INT16:
			case FT_INT24:
			case FT_INT32:
				actx->created_item=proto_tree_add_int(tree, hf_id, tvb, offset-len, len, (gint32)val);
				break;
			case FT_INT64:
				actx->created_item=proto_tree_add_int64(tree, hf_id, tvb, offset-len, len, val);
				break;
			case FT_UINT64:
				actx->created_item=proto_tree_add_uint64(tree, hf_id, tvb, offset-len, len, (guint64)val);
				break;
			default:
				DISSECTOR_ASSERT_NOT_REACHED();
			}
		}
	}

	if(value){
		*value=val;
	}

	return offset;
}

int dissect_ber_constrained_integer64(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint64 min_len, gint64 max_len, gint hf_id, gint64 *value)
{
	gint64 val;

	offset=dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_id, &val);
	if(value){
		*value=val;
	}

	ber_check_value64 (val, min_len, max_len, actx, actx->created_item);

	return offset;
}

int dissect_ber_integer(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, guint32 *value)
{
	gint64 val;

	offset=dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_id, &val);
	if(value){
		*value=(guint32)val;
	}

	return offset;
}

int dissect_ber_constrained_integer(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, gint hf_id, guint32 *value)
{
	gint64 val;

	offset=dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_id, &val);
	if(value){
		*value=(guint32)val;
	}

	ber_check_value ((guint32)val, min_len, max_len, actx, actx->created_item);

	return offset;
}

int dissect_ber_boolean(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, gboolean *value)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	guint8 val;
	header_field_info *hfi;

	if(!implicit_tag){
		offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
		
	} else {
		
	}

	val=tvb_get_guint8(tvb, offset);
	offset+=1;

	actx->created_item=NULL;

	if(hf_id >= 0){
		hfi = proto_registrar_get_nth(hf_id);
		if(hfi->type == FT_BOOLEAN)
			actx->created_item=proto_tree_add_boolean(tree, hf_id, tvb, offset-1, 1, val);
		else actx->created_item=proto_tree_add_uint(tree, hf_id, tvb, offset-1, 1, val?1:0);
	}

	if(value){
		*value=(val?TRUE:FALSE);
	}

	return offset;
}




int dissect_ber_real(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id _U_, double *value)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 val_length, end_offset;
	double val = 0;

	if(!implicit_tag){
		offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &val_length, NULL);
	} else {
		
		DISSECTOR_ASSERT_NOT_REACHED();
	}
	
	if (val_length==0){
		if (value)
			*value = 0;
		return offset;
	}
	end_offset = offset + val_length;

	val = asn1_get_real(tvb_get_ptr(tvb, offset, val_length), val_length);
	actx->created_item = proto_tree_add_double(tree, hf_id, tvb, offset, val_length, val);

	if (value) *value = val;

	return end_offset;

}

int dissect_ber_sequence(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	gint8 classx;
	gboolean pcx, ind = 0, ind_field, imp_tag=FALSE;
	gint32 tagx;
	guint32 lenx;
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	proto_item *cause;
	int end_offset = 0;
	int s_offset;
	int hoffset;
	gint length_remaining;
	tvbuff_t *next_tvb;

	s_offset = offset;

{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SEQUENCE dissect_ber_sequence(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SEQUENCE dissect_ber_sequence(%s) entered\n",name);
}
}

	hoffset = offset;
	if(!implicit_tag) {
		offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
		offset = get_ber_length(tvb, offset, &lenx, NULL);
	} else {
		
		lenx=tvb_length_remaining(tvb,offset);
		end_offset=offset+lenx;
	}
	
	if(hf_id >= 0) {
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, hoffset, lenx + offset - hoffset, FALSE);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}
	offset = hoffset;

	if(!implicit_tag){
		
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &classx, &pcx, &tagx);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &lenx, &ind);
		if(ind){
		
		  end_offset = offset + lenx -2;
		} else {
		  end_offset = offset + lenx;
		}

		
		if((classx!=BER_CLASS_APP)&&(classx!=BER_CLASS_PRI))
		if((!pcx)
		||(!implicit_tag&&((classx!=BER_CLASS_UNI)
					||(tagx!=BER_UNI_TAG_SEQUENCE)))) {
			tvb_ensure_bytes_exist(tvb, hoffset, 2);
			cause = proto_tree_add_text(tree, tvb, offset, lenx, "BER Error: Sequence expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(classx,ber_class_codes,"Unknown"), classx, pcx ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tagx);
			proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
			expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Sequence expected");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			return end_offset;
		}
	}
	
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset, count;

		
			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				
				offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
				offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
				proto_item_append_text(item," 0 items");
				return end_offset;
				
			}
		
		hoffset = offset;
		
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;
                
		if (eoffset <= hoffset)
			THROW(ReportedBoundsError);

		

ber_sequence_try_again:
		
		if(!seq->func) {
			
			offset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, NULL, NULL);
			cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: This field lies beyond the end of the known sequence definition.");
			proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
			expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Unknown field in Sequence");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			offset = eoffset;
			continue;
		}

		

		if( ((seq->class==BER_CLASS_CON)||(seq->class==BER_CLASS_APP)||(seq->class==BER_CLASS_PRI)) && (!(seq->flags&BER_FLAGS_NOOWNTAG)) ){
		  if( (seq->class!=BER_CLASS_ANY)
		  &&  (seq->tag!=-1)
		  &&( (seq->class!=class)
		    ||(seq->tag!=tag) ) ){
			
			if(seq->flags&BER_FLAGS_OPTIONAL){
				
				seq++;
				goto ber_sequence_try_again;
			}
			offset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, NULL, NULL);
			if( seq->class == BER_CLASS_UNI){
			  cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in SEQUENCE  expected class:%s(%d) tag:%d (%s) but found class:%s(%d) tag:%d", val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class, seq->tag,val_to_str(seq->tag,ber_uni_tag_codes,"Unknown"), val_to_str(class,ber_class_codes,"Unknown"),class,tag);



				proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in SEQUENCE");
			}else{
			  cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in SEQUENCE  expected class:%s(%d) tag:%d but found class:%s(%d) tag:%d", val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class, seq->tag,val_to_str(class,ber_class_codes,"Unknown"),class,tag);


				proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in SEQUENCE");
			}
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			seq++;
			offset=eoffset;
			continue;
		  }
	        } else if(!(seq->flags & BER_FLAGS_NOTCHKTAG)) {
		  if( (seq->class!=BER_CLASS_ANY)
		  &&  (seq->tag!=-1)
		  &&( (seq->class!=class)
		    ||(seq->tag!=tag) ) ){
			
			if(seq->flags&BER_FLAGS_OPTIONAL){
				
				seq++;
				goto ber_sequence_try_again;
			}

			offset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, NULL, NULL);
			if( seq->class == BER_CLASS_UNI){
			  cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in sequence  expected class:%s(%d) tag:%d(%s) but found class:%s(%d) tag:%d",val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class,seq->tag,val_to_str(seq->tag,ber_uni_tag_codes,"Unknown"),val_to_str(class,ber_class_codes,"Unknown"),class,tag);
				proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in sequence");
			}else{
			  cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in sequence  expected class:%s(%d) tag:%d but found class:%s(%d) tag:%d",val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class,seq->tag,val_to_str(class,ber_class_codes,"Unknown"),class,tag);
				proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in sequence");
			}
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			seq++;
			offset=eoffset;
			continue;
		  }
		}

		if(!(seq->flags & BER_FLAGS_NOOWNTAG) ) {
			
			if(ind_field && (len == 2)){
				
				next_tvb = tvb_new_subset(tvb, offset, len, len);
				hoffset = eoffset;
			}else{
				hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset-(2*ind_field))
					length_remaining=eoffset-hoffset-(2*ind_field);
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset-(2*ind_field));
			}
		}
		else {
			length_remaining=tvb_length_remaining(tvb, hoffset);
			if (length_remaining>eoffset-hoffset)
				length_remaining=eoffset-hoffset;
			next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);
		}

		
		
			
			
		

		


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("SEQUENCE dissect_ber_sequence(%s) calling subdissector offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("SEQUENCE dissect_ber_sequence(%s) calling subdissector\n",name);
}
}

		if (next_tvb == NULL) {
			
			THROW(ReportedBoundsError);
		}
		imp_tag=FALSE;
		if (seq->flags & BER_FLAGS_IMPLTAG){
			imp_tag = TRUE;
		}

		count=seq->func(imp_tag, next_tvb, 0, actx, tree, *seq->p_id);


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("SEQUENCE dissect_ber_sequence(%s) subdissector ate %d bytes\n",name,count);
}

		
		
		if((len!=0)&&(count==0)&&(seq->flags&BER_FLAGS_OPTIONAL)){
			seq++;
			goto ber_sequence_try_again;
		
		}
		offset = eoffset;
		if(!(seq->flags & BER_FLAGS_NOOWNTAG) ) {
			
			if((ind_field == 1)&&(len>2))
			{
				
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, offset, count, "SEQ FIELD EOC");
				}
			}
		}
		seq++;
	}

	
	if(offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		cause = proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: Sequence ate %d too many bytes", offset-end_offset);
		proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: too many bytes in Sequence");
	}
	if(ind){
		
		end_offset += 2;
		if(show_internal_ber_fields){
			proto_tree_add_text(tree, tvb, end_offset-2,2 , "SEQ EOC");
		}
	}
	return end_offset;
}

int dissect_ber_old_sequence(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_old_sequence_t *seq, gint hf_id, gint ett_id) {
	gint8 classx;
	gboolean pcx, ind = 0, ind_field;
	gint32 tagx;
	guint32 lenx;
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	proto_item *cause;
	int end_offset = 0;
	int s_offset;
	int hoffset;
	gint length_remaining;
	tvbuff_t *next_tvb;

	s_offset = offset;

{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SEQUENCE dissect_ber_old_sequence(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SEQUENCE dissect_ber_old_sequence(%s) entered\n",name);
}
}

	hoffset = offset;
	if(!implicit_tag) {
		offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
		offset = get_ber_length(tvb, offset, &lenx, NULL);
	} else {
		
		lenx=tvb_length_remaining(tvb,offset);
		end_offset=offset+lenx;
	}
	
	if(hf_id >= 0) {
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, hoffset, lenx + offset - hoffset, FALSE);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}
	offset = hoffset;

	if(!implicit_tag){
		
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &classx, &pcx, &tagx);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &lenx, &ind);
		if(ind){
		
		  end_offset = offset + lenx -2;
		} else {
		  end_offset = offset + lenx;
		}

		
		if((classx!=BER_CLASS_APP)&&(classx!=BER_CLASS_PRI))
		if((!pcx)
		||(!implicit_tag&&((classx!=BER_CLASS_UNI)
					||(tagx!=BER_UNI_TAG_SEQUENCE)))) {
			tvb_ensure_bytes_exist(tvb, hoffset, 2);
			cause = proto_tree_add_text(tree, tvb, offset, lenx, "BER Error: Sequence expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(classx,ber_class_codes,"Unknown"), classx, pcx ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tagx);
			proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
			expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Sequence expected");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			return end_offset;
		}
	}
	
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset, count;

		
			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				
				offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
				offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
				proto_item_append_text(item," 0 items");
				return end_offset;
				
			}
		
		hoffset = offset;
		
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;
                
		if (eoffset <= hoffset)
			THROW(ReportedBoundsError);

		

ber_old_sequence_try_again:
		
		if(!seq->func) {
			
			offset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, NULL, NULL);
			cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: This field lies beyond the end of the known sequence definition.");
			proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
			expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Unknown field in Sequence");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			offset = eoffset;
			continue;
		}

		

		if( ((seq->class==BER_CLASS_CON)||(seq->class==BER_CLASS_APP)||(seq->class==BER_CLASS_PRI)) && (!(seq->flags&BER_FLAGS_NOOWNTAG)) ){
		  if( (seq->class!=BER_CLASS_ANY)
		  &&  (seq->tag!=-1)
		  &&( (seq->class!=class)
		    ||(seq->tag!=tag) ) ){
			
			if(seq->flags&BER_FLAGS_OPTIONAL){
				
				seq++;
				goto ber_old_sequence_try_again;
			}
			offset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, NULL, NULL);
			if( seq->class == BER_CLASS_UNI){
			  cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in SEQUENCE  expected class:%s(%d) tag:%d (%s) but found class:%s(%d) tag:%d", val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class, seq->tag,val_to_str(seq->tag,ber_uni_tag_codes,"Unknown"), val_to_str(class,ber_class_codes,"Unknown"),class,tag);



				proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in SEQUENCE");
			}else{
			  cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in SEQUENCE  expected class:%s(%d) tag:%d but found class:%s(%d) tag:%d", val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class, seq->tag,val_to_str(class,ber_class_codes,"Unknown"),class,tag);


				proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in SEQUENCE");
			}
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			seq++;
			offset=eoffset;
			continue;
		  }
	        } else if(!(seq->flags & BER_FLAGS_NOTCHKTAG)) {
		  if( (seq->class!=BER_CLASS_ANY)
		  &&  (seq->tag!=-1)
		  &&( (seq->class!=class)
		    ||(seq->tag!=tag) ) ){
			
			if(seq->flags&BER_FLAGS_OPTIONAL){
				
				seq++;
				goto ber_old_sequence_try_again;
			}

			offset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, NULL, NULL);
			if( seq->class == BER_CLASS_UNI){
			  cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in sequence  expected class:%s(%d) tag:%d(%s) but found class:%s(%d) tag:%d",val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class,seq->tag,val_to_str(seq->tag,ber_uni_tag_codes,"Unknown"),val_to_str(class,ber_class_codes,"Unknown"),class,tag);
				proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in sequence");
			}else{
			  cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in sequence  expected class:%s(%d) tag:%d but found class:%s(%d) tag:%d",val_to_str(seq->class,ber_class_codes,"Unknown"),seq->class,seq->tag,val_to_str(class,ber_class_codes,"Unknown"),class,tag);
				proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in sequence");
			}
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			seq++;
			offset=eoffset;
			continue;
		  }
		}

		if(!(seq->flags & BER_FLAGS_NOOWNTAG) ) {
			
			if(ind_field && (len == 2)){
				
				next_tvb = tvb_new_subset(tvb, offset, len, len);
				hoffset = eoffset;
			}else{
				hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset-(2*ind_field))
					length_remaining=eoffset-hoffset-(2*ind_field);
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset-(2*ind_field));
			}
		}
		else {
			length_remaining=tvb_length_remaining(tvb, hoffset);
			if (length_remaining>eoffset-hoffset)
				length_remaining=eoffset-hoffset;
			next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);
		}

		
		
			
			
		

		


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("SEQUENCE dissect_ber_old_sequence(%s) calling subdissector offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("SEQUENCE dissect_ber_old_sequence(%s) calling subdissector\n",name);
}
}

		if (next_tvb == NULL) {
			
			THROW(ReportedBoundsError);
		}
		count=seq->func(tree, next_tvb, 0, actx);


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("SEQUENCE dissect_ber_old_sequence(%s) subdissector ate %d bytes\n",name,count);
}

		
		
		if((len!=0)&&(count==0)&&(seq->flags&BER_FLAGS_OPTIONAL)){
			seq++;
			goto ber_old_sequence_try_again;
		
		}
		offset = eoffset;
		seq++;
		if(!(seq->flags & BER_FLAGS_NOOWNTAG) ) {
			
			if((ind_field == 1)&&(len>2))
			{
				
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, offset, count, "SEQ FIELD EOC");
				}
			}
		}
	}

	
	if(offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		cause = proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: Sequence ate %d too many bytes", offset-end_offset);
		proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: too many bytes in Sequence");
	}
	if(ind){
		
		end_offset += 2;
		if(show_internal_ber_fields){
			proto_tree_add_text(tree, tvb, end_offset-2,2 , "SEQ EOC");
		}
	}
	return end_offset;
}


int dissect_ber_set(gboolean implicit_tag,asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *set, gint hf_id, gint ett_id) {
	gint8 classx;
	gboolean pcx, ind = 0, ind_field, imp_tag = FALSE;
	gint32 tagx;
	guint32 lenx;
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	proto_item *cause;
	int end_offset, s_offset;
	int hoffset;
	gint length_remaining;
	tvbuff_t *next_tvb;
	const ber_sequence_t *cset = NULL;

	guint32   mandatory_fields = 0;
	guint8   set_idx;
	gboolean first_pass;
	s_offset = offset;

	{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SET dissect_ber_set(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SET dissect_ber_set(%s) entered\n",name);
}
}


	if(!implicit_tag){
		hoffset = offset;
		
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &classx, &pcx, &tagx);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &lenx, &ind);
		if(ind){
		
		  end_offset = offset + lenx -2;
		} else {
		  end_offset = offset + lenx;
		}

		
		if ((classx!=BER_CLASS_APP)&&(classx!=BER_CLASS_PRI))
		if ((!pcx)
		||(!implicit_tag&&((classx!=BER_CLASS_UNI)
							||(tagx!=BER_UNI_TAG_SET)))) {
		  tvb_ensure_bytes_exist(tvb, hoffset, 2);
		  cause = proto_tree_add_text(tree, tvb, offset, lenx, "BER Error: SET expected but class:%s(%d) %s tag:%d was found", val_to_str(classx,ber_class_codes,"Unknown"), classx, pcx ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tagx);
		  proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		  expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: SET expected");
		  if (decode_unexpected) {
		    proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		    dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		  }
		  return end_offset;
		}
	} else {
		
		lenx=tvb_length_remaining(tvb,offset);
		end_offset=offset+lenx;
	}

	
	if (hf_id >= 0) {
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, lenx, FALSE);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}

	
	for(set_idx = 0; (cset=&set[set_idx])->func && (set_idx < MAX_SET_ELEMENTS); set_idx++) {

	  if(!(cset->flags & BER_FLAGS_OPTIONAL))
	      mandatory_fields |= 1 << set_idx;

	}

	
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset, count;

		

			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, s_offset, offset+2, "SEQ EOC");
				}
				return end_offset;
			}
			
		hoffset = offset;
		
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;

		


		for(first_pass=TRUE, cset = set, set_idx = 0; cset->func || first_pass; cset++, set_idx++) {

		  
		  if(!cset->func) {
		    first_pass = FALSE;

		    cset=set; 
		    set_idx = 0;
		  }

		  if((first_pass && ((cset->class==class) && (cset->tag==tag))) || (!first_pass && ((cset->class== BER_CLASS_ANY) && (cset->tag == -1))) )
		  {

			if (!(cset->flags & BER_FLAGS_NOOWNTAG) ) {
		      
				hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset-(2*ind_field))
					length_remaining=eoffset-hoffset-(2*ind_field);
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset-(2*ind_field));
		    }
			else {
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset)
					length_remaining=eoffset-hoffset;
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);
			}


			
			
				
				
			

			


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("SET dissect_ber_set(%s) calling subdissector offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("SET dissect_ber_set(%s) calling subdissector\n",name);
}
}

			if (next_tvb == NULL) {
				
				THROW(ReportedBoundsError);
			}
			imp_tag = FALSE;
			if ((cset->flags & BER_FLAGS_IMPLTAG))
				imp_tag = TRUE;
			count=cset->func(imp_tag, next_tvb, 0, actx, tree, *cset->p_id);

			
			if(count || (first_pass && (len == 0 || (ind_field == 1 && len == 2)))) {
			    
			    if(set_idx < MAX_SET_ELEMENTS)
				  mandatory_fields &= ~(1 << set_idx);

				offset = eoffset;

				if(!(cset->flags & BER_FLAGS_NOOWNTAG) ) {
				  
				  if(ind_field == 1){
					  
					  if(show_internal_ber_fields){
						  proto_tree_add_text(tree, tvb, offset, count, "SET FIELD EOC");
					  }
				  }
				}
				break;
			}
		  }
		}

		if(!cset->func) {
		  
		  cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Unknown field in SET class:%s(%d) tag:%d",val_to_str(class,ber_class_codes,"Unknown"),class,tag);
		  proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		  expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Unknown field in SET");
		  if (decode_unexpected) {
		    proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		    dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		  }
		  offset = eoffset;
		}
	}

	if(mandatory_fields) {

	  

	  for(set_idx = 0;  (cset = &set[set_idx])->func && (set_idx < MAX_SET_ELEMENTS); set_idx++) {

	    if(mandatory_fields & (1 << set_idx)) {

	      
	      cause = proto_tree_add_text(tree, tvb, offset, lenx, "BER Error: Missing field in SET class:%s(%d) tag:%d expected", val_to_str(cset->class,ber_class_codes,"Unknown"),cset->class, cset->tag);


	      proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
	      expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Missing field in SET");

	    }

	  }
	}

	
	if (offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		cause = proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: SET ate %d too many bytes", offset-end_offset);
		proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: too many bytes in SET");
	}

	if(ind){
		
		  end_offset += 2;
		  if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, end_offset-2,2 , "SET EOC");
		  }
	}

	return end_offset;

}

int dissect_ber_old_set(gboolean implicit_tag,asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_old_sequence_t *set, gint hf_id, gint ett_id) {
	gint8 classx;
	gboolean pcx, ind = 0, ind_field;
	gint32 tagx;
	guint32 lenx;
	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	proto_item *cause;
	int end_offset, s_offset;
	int hoffset;
	gint length_remaining;
	tvbuff_t *next_tvb;
	const ber_old_sequence_t *cset = NULL;

	guint32   mandatory_fields = 0;
	guint8   set_idx;
	gboolean first_pass;
	s_offset = offset;

	{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SET dissect_old_ber_set(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SET dissect_old_ber_set(%s) entered\n",name);
}
}


	if(!implicit_tag){
		hoffset = offset;
		
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &classx, &pcx, &tagx);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &lenx, &ind);
		if(ind){
		
		  end_offset = offset + lenx -2;
		} else {
		  end_offset = offset + lenx;
		}

		
		if ((classx!=BER_CLASS_APP)&&(classx!=BER_CLASS_PRI))
		if ((!pcx)
		||(!implicit_tag&&((classx!=BER_CLASS_UNI)
							||(tagx!=BER_UNI_TAG_SET)))) {
		  tvb_ensure_bytes_exist(tvb, hoffset, 2);
		  cause = proto_tree_add_text(tree, tvb, offset, lenx, "BER Error: SET expected but class:%s(%d) %s tag:%d was found", val_to_str(classx,ber_class_codes,"Unknown"), classx, pcx ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tagx);
		  proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		  expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: SET expected");
		  if (decode_unexpected) {
		    proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		    dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		  }
		  return end_offset;
		}
	} else {
		
		lenx=tvb_length_remaining(tvb,offset);
		end_offset=offset+lenx;
	}

	
	if (hf_id >= 0) {
		if(parent_tree){
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, lenx, FALSE);
			tree = proto_item_add_subtree(item, ett_id);
		}
	}

	
	for(set_idx = 0; (cset=&set[set_idx])->func && (set_idx < MAX_SET_ELEMENTS); set_idx++) {

	  if(!(cset->flags & BER_FLAGS_OPTIONAL))
	      mandatory_fields |= 1 << set_idx;

	}

	
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset, count;

		

			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, s_offset, offset+2, "SEQ EOC");
				}
				return end_offset;
			}
			
		hoffset = offset;
		
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;

		


		for(first_pass=TRUE, cset = set, set_idx = 0; cset->func || first_pass; cset++, set_idx++) {

		  
		  if(!cset->func) {
		    first_pass = FALSE;

		    cset=set; 
		    set_idx = 0;
		  }

		  if((first_pass && ((cset->class==class) && (cset->tag==tag))) || (!first_pass && ((cset->class== BER_CLASS_ANY) && (cset->tag == -1))) )
		  {

			if (!(cset->flags & BER_FLAGS_NOOWNTAG) ) {
		      
				hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset-(2*ind_field))
					length_remaining=eoffset-hoffset-(2*ind_field);
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset-(2*ind_field));
		    }
			else {
				length_remaining=tvb_length_remaining(tvb, hoffset);
				if (length_remaining>eoffset-hoffset)
					length_remaining=eoffset-hoffset;
				next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);
			}


			
			
				
				
			

			


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("SET dissect_old_ber_set(%s) calling subdissector offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("SET dissect_old_ber_set(%s) calling subdissector\n",name);
}
}

			if (next_tvb == NULL) {
				
				THROW(ReportedBoundsError);
			}
			count=cset->func(tree, next_tvb, 0, actx);

			
			if(count || (first_pass && (len == 0 || (ind_field == 1 && len == 2)))) {
			    
			    if(set_idx < MAX_SET_ELEMENTS)
				  mandatory_fields &= ~(1 << set_idx);

				offset = eoffset;

				if(!(cset->flags & BER_FLAGS_NOOWNTAG) ) {
				  
				  if(ind_field == 1){
					  
					  if(show_internal_ber_fields){
						  proto_tree_add_text(tree, tvb, offset, count, "SET FIELD EOC");
					  }
				  }
				}
				break;
			}
		  }
		}

		if(!cset->func) {
		  
		  cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Unknown field in SET class:%s(%d) tag:%d",val_to_str(class,ber_class_codes,"Unknown"),class,tag);
		  proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		  expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Unknown field in SET");
		  if (decode_unexpected) {
		    proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		    dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		  }
		  offset = eoffset;
		}
	}

	if(mandatory_fields) {

	  

	  for(set_idx = 0;  (cset = &set[set_idx])->func && (set_idx < MAX_SET_ELEMENTS); set_idx++) {

	    if(mandatory_fields & (1 << set_idx)) {

	      
	      cause = proto_tree_add_text(tree, tvb, offset, lenx, "BER Error: Missing field in SET class:%s(%d) tag:%d expected", val_to_str(cset->class,ber_class_codes,"Unknown"),cset->class, cset->tag);


	      proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
	      expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Missing field in SET");

	    }

	  }
	}

	
	if (offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		cause = proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: SET ate %d too many bytes", offset-end_offset);
		proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: too many bytes in SET");
	}

	if(ind){
		
		  end_offset += 2;
		  if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, end_offset-2,2 , "SET EOC");
		  }
	}

	return end_offset;

}





int dissect_ber_choice(asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_choice_t *choice, gint hf_id, gint ett_id, gint *branch_taken)
{
	gint8 class;
	gboolean pc, ind, imp_tag = FALSE;
	gint32 tag;
	guint32 len;
	const ber_choice_t *ch;
	proto_tree *tree=parent_tree;
	proto_item *item=NULL;
	int end_offset, start_offset, count;
	int hoffset = offset;
	header_field_info	*hfinfo;
	gint length, length_remaining;
	tvbuff_t *next_tvb;
	gboolean first_pass;


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("CHOICE dissect_ber_choice(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("CHOICE dissect_ber_choice(%s) entered len:%d\n",name,tvb_length_remaining(tvb,offset));
}
}

	start_offset=offset;

        if(tvb_length_remaining(tvb,offset) == 0) {
                item = proto_tree_add_text(parent_tree, tvb, offset, 0, "BER Error: Empty choice was found");
                proto_item_set_expert_flags(item, PI_MALFORMED, PI_WARN);
                expert_add_info_format(actx->pinfo, item, PI_MALFORMED, PI_WARN, "BER Error: Empty choice was found");
                return offset;
        }

	
	offset=get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset=get_ber_length(tvb, offset, &len, &ind);
	  end_offset = offset + len ;

	
	if(hf_id >= 0){
		hfinfo=proto_registrar_get_nth(hf_id);
		switch(hfinfo->type) {
			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
				break;
		default:
			proto_tree_add_text(tree, tvb, offset, len,"dissect_ber_choice(): Was passed a HF field that was not integer type : %s",hfinfo->abbrev);
			fprintf(stderr,"dissect_ber_choice(): frame:%u offset:%d Was passed a HF field that was not integer type : %s\n",actx->pinfo->fd->num,offset,hfinfo->abbrev);
			return end_offset;
		}
	}



	
	ch = choice;
	if(branch_taken){
		*branch_taken=-1;
	}
	first_pass = TRUE;
	while(ch->func || first_pass){
		if(branch_taken){
			(*branch_taken)++;
		}
	  
	  if(!ch->func) {
	    first_pass = FALSE;
	    ch = choice; 
		if(branch_taken){
			*branch_taken=-1;
		}
	  }

choice_try_again:

printf("CHOICE testing potential subdissector class[%p]:%d:(expected)%d  tag:%d:(expected)%d flags:%d\n",ch,class,ch->class,tag,ch->tag,ch->flags);

		if( (first_pass && (((ch->class==class)&&(ch->tag==tag))
		     ||  ((ch->class==class)&&(ch->tag==-1)&&(ch->flags&BER_FLAGS_NOOWNTAG)))) || (!first_pass && (((ch->class == BER_CLASS_ANY) && (ch->tag == -1))))
		){
			if(!(ch->flags & BER_FLAGS_NOOWNTAG)){
				
				hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, start_offset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
				start_offset=hoffset;
				if (ind)
					{
					length = len-2;
					}
				else {
					length = len;
					}
			}
			else length = end_offset- hoffset;
			
			if(hf_id >= 0){
				if(parent_tree){
					item = proto_tree_add_uint(parent_tree, hf_id, tvb, hoffset, end_offset - hoffset, ch->value);
					tree = proto_item_add_subtree(item, ett_id);
				}
			}

			length_remaining=tvb_length_remaining(tvb, hoffset);
			if(length_remaining>length)
				length_remaining=length;


			
			if(first_pass)
			next_tvb=tvb_new_subset(tvb, hoffset, length_remaining, length);
			else next_tvb = tvb;

			next_tvb=tvb_new_subset(tvb, hoffset, length_remaining, length);



{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("CHOICE dissect_ber_choice(%s) calling subdissector start_offset:%d offset:%d len:%d %02x:%02x:%02x\n",name,start_offset,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("CHOICE dissect_ber_choice(%s) calling subdissector len:%d\n",name,tvb_length(next_tvb));
}
}

			if (next_tvb == NULL) {
				
				THROW(ReportedBoundsError);
			}
			imp_tag = FALSE;
			if ((ch->flags & BER_FLAGS_IMPLTAG))
				imp_tag = TRUE;
			count=ch->func(imp_tag, next_tvb, 0, actx, tree, *ch->p_id);

{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("CHOICE dissect_ber_choice(%s) subdissector ate %d bytes\n",name,count);
}

			if((count==0)&&(((ch->class==class)&&(ch->tag==-1)&&(ch->flags&BER_FLAGS_NOOWNTAG)) || !first_pass)){
				
				ch++;

{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("CHOICE dissect_ber_choice(%s) trying again\n",name);
}

				goto choice_try_again;
			}
			if(!(ch->flags & BER_FLAGS_NOOWNTAG)){
			 if(ind)
			 	{
			 	
			 	
			 	if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, start_offset, count+2, "CHOICE EOC");
				}
			 }
			}
			return end_offset;
		}
		ch++;
	}
	if(branch_taken){
		
		*branch_taken=-1;
	}


	

	
	item = proto_tree_add_text(tree, tvb, offset, len, "BER Error: This choice field was not found.");
	proto_item_set_expert_flags(item, PI_MALFORMED, PI_WARN);
	expert_add_info_format(actx->pinfo, item, PI_MALFORMED, PI_WARN, "BER Error: This choice field was not found");
	return end_offset;


	return start_offset;
}

int dissect_ber_old_choice(asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_old_choice_t *choice, gint hf_id, gint ett_id, gint *branch_taken)
{
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len;
	const ber_old_choice_t *ch;
	proto_tree *tree=parent_tree;
	proto_item *item=NULL;
	int end_offset, start_offset, count;
	int hoffset = offset;
	header_field_info	*hfinfo;
	gint length, length_remaining;
	tvbuff_t *next_tvb;
	gboolean first_pass;


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("CHOICE dissect_ber_old_choice(%s) entered offset:%d len:%d %02x:%02x:%02x\n",name,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("CHOICE dissect_ber_old_choice(%s) entered len:%d\n",name,tvb_length_remaining(tvb,offset));
}
}

	start_offset=offset;

        if(tvb_length_remaining(tvb,offset) == 0) {
                item = proto_tree_add_text(parent_tree, tvb, offset, 0, "BER Error: Empty choice was found");
                proto_item_set_expert_flags(item, PI_MALFORMED, PI_WARN);
                expert_add_info_format(actx->pinfo, item, PI_MALFORMED, PI_WARN, "BER Error: Empty choice was found");
                return offset;
        }

	
	offset=get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset=get_ber_length(tvb, offset, &len, &ind);
	  end_offset = offset + len ;

	
	if(hf_id >= 0){
		hfinfo=proto_registrar_get_nth(hf_id);
		switch(hfinfo->type) {
			case FT_UINT8:
			case FT_UINT16:
			case FT_UINT24:
			case FT_UINT32:
				break;
		default:
			proto_tree_add_text(tree, tvb, offset, len,"dissect_ber_old_choice(): Was passed a HF field that was not integer type : %s",hfinfo->abbrev);
			fprintf(stderr,"dissect_ber_old_choice(): frame:%u offset:%d Was passed a HF field that was not integer type : %s\n",actx->pinfo->fd->num,offset,hfinfo->abbrev);
			return end_offset;
		}
	}



	
	ch = choice;
	if(branch_taken){
		*branch_taken=-1;
	}
	first_pass = TRUE;
	while(ch->func || first_pass){
		if(branch_taken){
			(*branch_taken)++;
		}
	  
	  if(!ch->func) {
	    first_pass = FALSE;
	    ch = choice; 
		if(branch_taken){
			*branch_taken=-1;
		}
	  }

choice_try_again:

printf("CHOICE testing potential subdissector class[%p]:%d:(expected)%d  tag:%d:(expected)%d flags:%d\n",ch,class,ch->class,tag,ch->tag,ch->flags);

		if( (first_pass && (((ch->class==class)&&(ch->tag==tag))
		     ||  ((ch->class==class)&&(ch->tag==-1)&&(ch->flags&BER_FLAGS_NOOWNTAG)))) || (!first_pass && (((ch->class == BER_CLASS_ANY) && (ch->tag == -1))))
		){
			if(!(ch->flags & BER_FLAGS_NOOWNTAG)){
				
				hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, start_offset, NULL, NULL, NULL);
				hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
				start_offset=hoffset;
				if (ind)
					{
					length = len-2;
					}
				else {
					length = len;
					}
			}
			else length = end_offset- hoffset;
			
			if(hf_id >= 0){
				if(parent_tree){
					item = proto_tree_add_uint(parent_tree, hf_id, tvb, hoffset, end_offset - hoffset, ch->value);
					tree = proto_item_add_subtree(item, ett_id);
				}
			}

			length_remaining=tvb_length_remaining(tvb, hoffset);
			if(length_remaining>length)
				length_remaining=length;


			
			if(first_pass)
			next_tvb=tvb_new_subset(tvb, hoffset, length_remaining, length);
			else next_tvb = tvb;

			next_tvb=tvb_new_subset(tvb, hoffset, length_remaining, length);



{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(next_tvb,0)>3){
printf("CHOICE dissect_ber_old_choice(%s) calling subdissector start_offset:%d offset:%d len:%d %02x:%02x:%02x\n",name,start_offset,offset,tvb_length_remaining(next_tvb,0),tvb_get_guint8(next_tvb,0),tvb_get_guint8(next_tvb,1),tvb_get_guint8(next_tvb,2));
}else{
printf("CHOICE dissect_ber_old_choice(%s) calling subdissector len:%d\n",name,tvb_length(next_tvb));
}
}

			if (next_tvb == NULL) {
				
				THROW(ReportedBoundsError);
			}
			count=ch->func(tree, next_tvb, 0, actx);

{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("CHOICE dissect_ber_old_choice(%s) subdissector ate %d bytes\n",name,count);
}

			if((count==0)&&(((ch->class==class)&&(ch->tag==-1)&&(ch->flags&BER_FLAGS_NOOWNTAG)) || !first_pass)){
				
				ch++;

{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
printf("CHOICE dissect_ber_old_choice(%s) trying again\n",name);
}

				goto choice_try_again;
			}
			if(!(ch->flags & BER_FLAGS_NOOWNTAG)){
			 if(ind)
			 	{
			 	
			 	
			 	if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, start_offset, count+2, "CHOICE EOC");
				}
			 }
			}
			return end_offset;
		}
		ch++;
	}
	if(branch_taken){
		
		*branch_taken=-1;
	}


	

	
	cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: This choice field was not found.");
	proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
	expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: This choice field was not found");
	return end_offset;


	return start_offset;
}



int dissect_ber_GeneralString(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, char *name_string, int name_len)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	int end_offset;
	int hoffset;
	char str_arr[256];
	guint32 max_len;
	char *str;
	proto_item *cause;

	str=str_arr;
	max_len=255;
	if(name_string){
		str=name_string;
		max_len=name_len;
	}

	hoffset = offset;
	
	offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
	end_offset=offset+len;

	
	if( (class!=BER_CLASS_UNI)
	  ||(tag!=BER_UNI_TAG_GENSTR) ){
		tvb_ensure_bytes_exist(tvb, hoffset, 2);
		cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: GeneralString expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
		proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: GeneralString expected");
		if (decode_unexpected) {
		  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		}
		return end_offset;
	}

	if(len>=(max_len-1)){
		len=max_len-1;
	}

	tvb_memcpy(tvb, str, offset, len);
	str[len]=0;

	if(hf_id >= 0){
		proto_tree_add_string(tree, hf_id, tvb, offset, len, str);
	}

	return end_offset;
}


int dissect_ber_constrained_restricted_string(gboolean implicit_tag, gint32 type,  asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, gint hf_id, tvbuff_t **out_tvb) {
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	int eoffset;
	int hoffset = offset;
	proto_item *cause;


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("RESTRICTED STRING dissect_ber_octet string(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("RESTRICTED STRING dissect_ber_octet_string(%s) entered\n",name);
}
}


	if(!implicit_tag) {
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, NULL);
		eoffset = offset + len;

		
		if( (class!=BER_CLASS_UNI)
		  ||(tag != type) ){
	            tvb_ensure_bytes_exist(tvb, hoffset, 2);
		    cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: String with tag=%d expected but class:%s(%d) %s tag:%d was unexpected", type, val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
		    proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: String expected");
		    if (decode_unexpected) {
		      proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		      dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		    }
		    return eoffset;
		}
	}

	
	return dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, hoffset, min_len, max_len, hf_id, out_tvb);
}

int dissect_ber_restricted_string(gboolean implicit_tag, gint32 type, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **out_tvb)
{
	return dissect_ber_constrained_restricted_string(implicit_tag, type, actx, tree, tvb, offset, NO_BOUND, NO_BOUND, hf_id, out_tvb);
}

int dissect_ber_GeneralString(asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, char *name_string, guint name_len)
{
	tvbuff_t *out_tvb = NULL;
	gint tvb_len;

	offset = dissect_ber_restricted_string(FALSE, BER_UNI_TAG_GeneralString, actx, tree, tvb, offset, hf_id, (name_string)?&out_tvb:NULL);

	if(name_string) {
		
		if(out_tvb) {
			tvb_len = tvb_length(out_tvb);
			if((guint)tvb_len >= name_len) {
				tvb_memcpy(out_tvb, (guint8*)name_string, 0, name_len-1);
				name_string[name_len-1] = '\0';
			} else {
				tvb_memcpy(out_tvb, (guint8*)name_string, 0, tvb_len);
				name_string[tvb_len] = '\0';
			}
		}
	}

	return offset;
}


int dissect_ber_object_identifier(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, tvbuff_t **value_tvb)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	int eoffset;
	int hoffset;
	const char *str;
	proto_item *cause;
	header_field_info *hfi;
	const gchar *name;


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("OBJECT IDENTIFIER dissect_ber_object_identifier(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("OBJECT IDENTIFIER dissect_ber_object_identifier(%s) entered\n",name);
}
}


	if(!implicit_tag) {
		hoffset = offset;
		
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
		eoffset = offset + len;
		if( (class!=BER_CLASS_UNI)
		  ||(tag != BER_UNI_TAG_OID) ){
	            tvb_ensure_bytes_exist(tvb, hoffset, 2);
		    cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Object Identifier expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
		    proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Object Identifier expected");
		    if (decode_unexpected) {
		      proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		      dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		    }
		    return eoffset;
		}
	} else {
		len=tvb_length_remaining(tvb,offset);
		eoffset=offset+len;
	}

	actx->created_item=NULL;
	hfi = proto_registrar_get_nth(hf_id);
	if (hfi->type == FT_OID) {
		actx->created_item = proto_tree_add_item(tree, hf_id, tvb, offset, len, FALSE);
	} else if (IS_FT_STRING(hfi->type)) {
		str = oid_encoded2string(tvb_get_ptr(tvb, offset, len), len);
		actx->created_item = proto_tree_add_string(tree, hf_id, tvb, offset, len, str);
		if(actx->created_item){
			
			name = oid_resolved_from_encoded(tvb_get_ptr(tvb, offset, len), len);
			if(name){
				proto_item_append_text(actx->created_item, " (%s)", name);
			}
		}
	} else {
		DISSECTOR_ASSERT_NOT_REACHED();
	}

	if (value_tvb)
		*value_tvb = tvb_new_subset(tvb, offset, len, len);

	return eoffset;
}

int dissect_ber_object_identifier_str(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id, const char **value_stringx)
{
  tvbuff_t *value_tvb = NULL;
  guint length;

  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_id, (value_stringx) ? &value_tvb : NULL);

  if (value_stringx) {
    if (value_tvb && (length = tvb_length(value_tvb))) {
      *value_stringx = oid_encoded2string(tvb_get_ptr(value_tvb, 0, length), length);
    } else {
      *value_stringx = "";
    }
  }

  return offset;
}





static int dissect_ber_sq_of(gboolean implicit_tag, gint32 type, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	gint8 classx;
	gboolean pcx, ind = FALSE, ind_field;
	gint32 tagx;
	guint32 lenx;

	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	proto_item *causex;
	int cnt, hoffsetx, end_offset;
	header_field_info *hfi;
	gint length_remaining;
	tvbuff_t *next_tvb;


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SQ OF dissect_ber_sq_of(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SQ OF dissect_ber_sq_of(%s) entered\n",name);
}
}


	if(!implicit_tag){
		hoffsetx = offset;
		
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &classx, &pcx, &tagx);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &lenx, &ind);
		if(ind){
		  
		  end_offset = offset + lenx;
		} else {
		  end_offset = offset + lenx;
		}

		
		if((classx!=BER_CLASS_APP)&&(classx!=BER_CLASS_PRI))
		if(!pcx ||(!implicit_tag&&((classx!=BER_CLASS_UNI)
							||(tagx!=type)))) {
			tvb_ensure_bytes_exist(tvb, hoffsetx, 2);
			causex = proto_tree_add_text(tree, tvb, offset, lenx, "BER Error: %s Of expected but class:%s(%d) %s tag:%d was unexpected", (type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence", val_to_str(classx,ber_class_codes,"Unknown"), classx, pcx ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tagx);
			proto_item_set_expert_flags(causex, PI_MALFORMED, PI_WARN);
			expert_add_info_format(actx->pinfo, causex, PI_MALFORMED, PI_WARN, "BER Error: %s Of expected",(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(causex, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffsetx, unknown_tree);
			}
			return end_offset;
		}
	} else {
		
		lenx=tvb_length_remaining(tvb,offset);
		end_offset = offset + lenx;
	}

	
	cnt = 0;
	hoffsetx = offset;
	
	
	if(tvb_length_remaining(tvb, offset)==tvb_reported_length_remaining(tvb, offset)){
		while (offset < end_offset){
			guint32 len;
                        gint s_offset;

                        s_offset = offset;

			
				if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
					break;
				}
			

			
			offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
			offset = get_ber_length(tvb, offset, &len, &ind);
			
			
			offset += len;
			cnt++;
			if (offset <= s_offset)
				THROW(ReportedBoundsError);
		}
	}
	offset = hoffsetx;

	
	if(hf_id >= 0) {
		hfi = proto_registrar_get_nth(hf_id);
		if(parent_tree){
			if(hfi->type == FT_NONE) {
				item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, lenx, FALSE);
				proto_item_append_text(item, ":");
			} else {
				item = proto_tree_add_uint(parent_tree, hf_id, tvb, offset, lenx, cnt);
				proto_item_append_text(item, (cnt==1)?" item":" items");
			}
			tree = proto_item_add_subtree(item, ett_id);
			ber_check_items (cnt, min_len, max_len, actx, item);
		}
	}

	
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset;
		int hoffset, count;
		proto_item *cause;
		gboolean imp_tag;

		hoffset = offset;
		
			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, hoffset, end_offset-hoffset, "SEQ OF EOC");
				}
				return offset+2;
			}
		
		
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;
                
		if (eoffset <= hoffset)
			THROW(ReportedBoundsError);

		if((class==BER_CLASS_UNI)&&(tag==BER_UNI_TAG_EOC)){
			
			hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
			return eoffset;
		}
		
		
		if(seq->class!=BER_CLASS_ANY){
		  if((seq->class!=class)
			||(seq->tag!=tag) ){
			if(!(seq->flags & BER_FLAGS_NOTCHKTAG)) {
				cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in SQ OF(tag %u expected %u)",tag,seq->tag);
				proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in Sequence Of");
				if (decode_unexpected) {
				  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
				  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
				}
				offset = eoffset;
				continue;
				
			}
		  }
		}

		if(!(seq->flags & BER_FLAGS_NOOWNTAG) && !(seq->flags & BER_FLAGS_IMPLTAG)) {
			
			hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
		}
		if((seq->flags == BER_FLAGS_IMPLTAG)&&(seq->class==BER_CLASS_CON)) {
			
			
			hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
			
		}

		length_remaining=tvb_length_remaining(tvb, hoffset);
		if (length_remaining>eoffset-hoffset)
			length_remaining=eoffset-hoffset;
		next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);

		imp_tag = FALSE;
		if(seq->flags == BER_FLAGS_IMPLTAG)
			imp_tag = TRUE;
		
		count=seq->func(imp_tag, next_tvb, 0, actx, tree, *seq->p_id)-hoffset;
				
		cnt++; 
		offset = eoffset;
	}

	
	if(offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		causex =proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: %s Of ate %d too many bytes", (type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence", offset-end_offset);
		proto_item_set_expert_flags(causex, PI_MALFORMED, PI_WARN);
		expert_add_info_format(actx->pinfo, causex, PI_MALFORMED, PI_WARN, "BER Error:too many byte in %s",(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence");
	}

	return end_offset;
}

static int dissect_ber_old_sq_of(gboolean implicit_tag, gint32 type, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_old_sequence_t *seq, gint hf_id, gint ett_id) {
	gint8 classx;
	gboolean pcx, ind = FALSE, ind_field;
	gint32 tagx;
	guint32 lenx;

	proto_tree *tree = parent_tree;
	proto_item *item = NULL;
	proto_item *causex;
	int cnt, hoffsetx, end_offset;
	header_field_info *hfi;
	gint length_remaining;
	tvbuff_t *next_tvb;


{
const char *name;
header_field_info *hfinfo;
if(hf_id>=0){
hfinfo = proto_registrar_get_nth(hf_id);
name=hfinfo->name;
} else {
name="unnamed";
}
if(tvb_length_remaining(tvb,offset)>3){
printf("SQ OF dissect_ber_old_sq_of(%s) entered implicit_tag:%d offset:%d len:%d %02x:%02x:%02x\n",name,implicit_tag,offset,tvb_length_remaining(tvb,offset),tvb_get_guint8(tvb,offset),tvb_get_guint8(tvb,offset+1),tvb_get_guint8(tvb,offset+2));
}else{
printf("SQ OF dissect_ber_old_sq_of(%s) entered\n",name);
}
}


	if(!implicit_tag){
		hoffsetx = offset;
		
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &classx, &pcx, &tagx);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &lenx, &ind);
		if(ind){
		  
		  end_offset = offset + lenx;
		} else {
		  end_offset = offset + lenx;
		}

		
		if((classx!=BER_CLASS_APP)&&(classx!=BER_CLASS_PRI))
		if(!pcx ||(!implicit_tag&&((classx!=BER_CLASS_UNI)
							||(tagx!=type)))) {
			tvb_ensure_bytes_exist(tvb, hoffsetx, 2);
			causex = proto_tree_add_text(tree, tvb, offset, lenx, "BER Error: %s Of expected but class:%s(%d) %s tag:%d was unexpected", (type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence", val_to_str(classx,ber_class_codes,"Unknown"), classx, pcx ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tagx);
			proto_item_set_expert_flags(causex, PI_MALFORMED, PI_WARN);
			expert_add_info_format(actx->pinfo, causex, PI_MALFORMED, PI_WARN, "BER Error: %s Of expected",(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence");
			if (decode_unexpected) {
			  proto_tree *unknown_tree = proto_item_add_subtree(causex, ett_ber_unknown);
			  dissect_unknown_ber(actx->pinfo, tvb, hoffsetx, unknown_tree);
			}
			return end_offset;
		}
	} else {
		
		lenx=tvb_length_remaining(tvb,offset);
		end_offset = offset + lenx;
	}

	
	cnt = 0;
	hoffsetx = offset;
	
	
	if(tvb_length_remaining(tvb, offset)==tvb_reported_length_remaining(tvb, offset)){
		while (offset < end_offset){
			guint32 len;
                        gint s_offset;

                        s_offset = offset;

			if(ind){ 
				if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
					break;
				}
			}

			
			offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
			offset = get_ber_length(tvb, offset, &len, &ind);
			
			
			offset += len;
			cnt++;
			if (offset <= s_offset)
				THROW(ReportedBoundsError);
		}
	}
	offset = hoffsetx;

	
	if(hf_id >= 0) {
		hfi = proto_registrar_get_nth(hf_id);
		if(parent_tree){
			if(hfi->type == FT_NONE) {
				item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, lenx, FALSE);
				proto_item_append_text(item, ":");
			} else {
				item = proto_tree_add_uint(parent_tree, hf_id, tvb, offset, lenx, cnt);
				proto_item_append_text(item, (cnt==1)?" item":" items");
			}
			tree = proto_item_add_subtree(item, ett_id);
		}
	}

	
	while (offset < end_offset){
		gint8 class;
		gboolean pc;
		gint32 tag;
		guint32 len;
		int eoffset;
		int hoffset, count;
		proto_item *cause;

		hoffset = offset;
	 	if(ind){ 
			if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0)){
				if(show_internal_ber_fields){
					proto_tree_add_text(tree, tvb, hoffset, end_offset-hoffset, "SEQ OF EOC");
				}
				return offset+2;
			}
		}
		
		offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
		offset = get_ber_length(tvb, offset, &len, &ind_field);
		eoffset = offset + len;
                
		if (eoffset <= hoffset)
			THROW(ReportedBoundsError);

		if((class==BER_CLASS_UNI)&&(tag==BER_UNI_TAG_EOC)){
			
			hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
			return eoffset;
		}
		
		
		if(seq->class!=BER_CLASS_ANY){
		  if((seq->class!=class)
			||(seq->tag!=tag) ){
			if(!(seq->flags & BER_FLAGS_NOTCHKTAG)) {
				cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: Wrong field in SQ OF");
				proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: Wrong field in Sequence Of");
				if (decode_unexpected) {
				  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
				  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
				}
				offset = eoffset;
				continue;
				
			}
		  }
		}

		if(!(seq->flags & BER_FLAGS_NOOWNTAG) && !(seq->flags & BER_FLAGS_IMPLTAG)) {
			
			hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
		}
		if((seq->flags == BER_FLAGS_IMPLTAG)&&(seq->class==BER_CLASS_CON)) {
			
			
			hoffset = dissect_ber_identifier(actx->pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
			hoffset = dissect_ber_length(actx->pinfo, tree, tvb, hoffset, NULL, NULL);
		}

		length_remaining=tvb_length_remaining(tvb, hoffset);
		if (length_remaining>eoffset-hoffset)
			length_remaining=eoffset-hoffset;
		next_tvb = tvb_new_subset(tvb, hoffset, length_remaining, eoffset-hoffset);


		
		count=seq->func(tree, tvb, hoffset, actx)-hoffset;
				
		cnt++; 
		offset = eoffset;
	}

	
	if(offset != end_offset) {
		tvb_ensure_bytes_exist(tvb, offset-2, 2);
		causex =proto_tree_add_text(tree, tvb, offset-2, 2, "BER Error: %s Of ate %d too many bytes", (type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence", offset-end_offset);
		proto_item_set_expert_flags(causex, PI_MALFORMED, PI_WARN);
		expert_add_info_format(actx->pinfo, causex, PI_MALFORMED, PI_WARN, "BER Error:too many byte in %s",(type==BER_UNI_TAG_SEQUENCE)?"Set":"Sequence");
	}

	return end_offset;
}

int dissect_ber_constrained_sequence_of(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_sq_of(implicit_tag, BER_UNI_TAG_SEQUENCE, actx, parent_tree, tvb, offset, min_len, max_len, seq, hf_id, ett_id);
}

int dissect_ber_sequence_of(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_sq_of(implicit_tag, BER_UNI_TAG_SEQUENCE, actx, parent_tree, tvb, offset, NO_BOUND, NO_BOUND, seq, hf_id, ett_id);
}

int dissect_ber_constrained_set_of(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_sq_of(implicit_tag, BER_UNI_TAG_SET, actx, parent_tree, tvb, offset, min_len, max_len, seq, hf_id, ett_id);
}

int dissect_ber_set_of(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_sq_of(implicit_tag, BER_UNI_TAG_SET, actx, parent_tree, tvb, offset, NO_BOUND, NO_BOUND, seq, hf_id, ett_id);
}

int dissect_ber_old_sequence_of(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_old_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_old_sq_of(implicit_tag, BER_UNI_TAG_SEQUENCE, actx, parent_tree, tvb, offset, seq, hf_id, ett_id);
}

int dissect_ber_old_set_of(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const ber_old_sequence_t *seq, gint hf_id, gint ett_id) {
	return dissect_ber_old_sq_of(implicit_tag, BER_UNI_TAG_SET, actx, parent_tree, tvb, offset, seq, hf_id, ett_id);
}

int dissect_ber_GeneralizedTime(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id)
{
	char str[35];
	const guint8 *tmpstr;
	char *strptr;
	char first_delim[2];
	int first_digits;
	char second_delim[2];
	int second_digits;
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	int end_offset;
	int hoffset;
	proto_item *cause;

	if(!implicit_tag){
	  hoffset = offset;
	  offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
	  offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
	  end_offset=offset+len;

	  
	  if( (class!=BER_CLASS_UNI)
	  ||(tag!=BER_UNI_TAG_GeneralizedTime)){
		tvb_ensure_bytes_exist(tvb, hoffset, 2);
		cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: GeneralizedTime expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
		proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: GeneralizedTime expected");
		if (decode_unexpected) {
		  proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		  dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		}
		return end_offset;
	  }
        } else {
	  len=tvb_length_remaining(tvb,offset);
	  end_offset=offset+len;
	}

	if (len < 14 || len > 23) {
		cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: GeneralizedTime invalid length: %u", len);
		proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: GeneralizedTime invalid length");
		if (decode_unexpected) {
			proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
			dissect_unknown_ber(actx->pinfo, tvb, offset, unknown_tree);
		}
		return end_offset;
	}

	tmpstr=tvb_get_ephemeral_string(tvb, offset, len);
	strptr = str;
	
	strptr += g_snprintf(str, 20, "%.4s-%.2s-%.2s %.2s:%.2s:%.2s", tmpstr, tmpstr+4, tmpstr+6, tmpstr+8, tmpstr+10, tmpstr+12);


	first_delim[0]=0;
	second_delim[0]=0;
	sscanf( tmpstr, "%*14d%1[.,+-Z]%4d%1[+-Z]%4d", first_delim, &first_digits, second_delim, &second_digits);

	switch (first_delim[0]) {
		case '.':
		case ',':
			strptr += g_snprintf(strptr, 5, "%c%.3d", first_delim[0], first_digits);
			switch (second_delim[0]) {
				case '+':
				case '-':
					g_snprintf(strptr, 12, " (UTC%c%.4d)", second_delim[0], second_digits);
					break;
				case 'Z':
					g_snprintf(strptr, 7, " (UTC)");
					break;
				case 0:
					break;
				default:
					
					break;
			}
			break;
		case '+':
		case '-':
			g_snprintf(strptr, 12, " (UTC%c%.4d)", first_delim[0], first_digits);
			break;
		case 'Z':
			g_snprintf(strptr, 7, " (UTC)");
			break;
		case 0:
			break;
		default:
			
			break;
	}

	if(hf_id >= 0){
		proto_tree_add_string(tree, hf_id, tvb, offset, len, str);
	}

	offset+=len;
	return offset;
}


int dissect_ber_UTCTime(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *tree, tvbuff_t *tvb, int offset, gint hf_id)
{
	char outstr[33];
	char *outstrptr = outstr;
	const guint8 *instr;
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len, i, n;
	int hoffset;
	proto_item *cause;

	if(!implicit_tag){
		hoffset = offset;
		offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
		offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);

		
		if( (class!=BER_CLASS_UNI) || (tag!=BER_UNI_TAG_UTCTime) ) {
			tvb_ensure_bytes_exist(tvb, hoffset, 2);
			cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: UTCTime expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);


			proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
			expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: UTCTime expected");
			if (decode_unexpected) {
				proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
				dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
			}
			return offset+len;
		}
	} else {
		len = tvb_length_remaining(tvb,offset);
	}

	if (len < 10 || len > 19) {
		cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: UTCTime invalid length: %u", len);
		instr = tvb_get_ephemeral_string(tvb, offset, len > 19 ? 19 : len);
		goto malformed;
	}

	instr = tvb_get_ephemeral_string(tvb, offset, len);

	
	for(i=0;i<10;i++) {
		if(instr[i] < '0' || instr[i] > '9') {
			cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: malformed UTCTime encoding, " "first 10 octets have to contain YYMMDDhhmm in digits");

			goto malformed;
		}
	}
	g_snprintf(outstrptr, 15, "%.2s-%.2s-%.2s %.2s:%.2s", instr, instr+2, instr+4, instr+6, instr+8);
	outstrptr+= 14;

	
	if(len >= 12) {
		if(instr[i] >= '0' && instr[i] <= '9') {
			i++;
			if(instr[i] >= '0' && instr[i] <= '9') {
				i++;
				g_snprintf(outstrptr, 4, ":%.2s", instr+10);
				outstrptr+=3;
			} else {
				cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: malformed UTCTime encoding, " "if 11th octet is a digit for seconds, " "the 12th octet has to be a digit, too");


				goto malformed;
			}
		}
	}

	
	switch (instr[i]) {
		case 'Z':
			if(len!=i+1) {
				cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: malformed UTCTime encoding, " "there must be no further octets after \'Z\'");

				goto malformed;
			}
			g_snprintf(outstrptr, 7, " (UTC)");
			i++;
			break;
		case '-':
		case '+':
			if(len!=i+5) {
				cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: malformed UTCTime encoding, " "4 digits must follow on \'+\' resp. \'-\'");

				goto malformed;
			}
			for(n=i+1;n<i+5;n++) {
				if(instr[n] < '0' || instr[n] > '9') {
					cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: malformed UTCTime encoding, " "4 digits must follow on \'+\' resp. \'-\'");

					goto malformed;
				}
			}
			g_snprintf(outstrptr, 12, " (UTC%c%.4s)", instr[i], instr+i+1);
			i+=5;
			break;
		default:
			cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: malformed UTCTime encoding, " "unexpected character in %dth octet, " "must be \'Z\', \'+\' or \'-\'", i+1);


			goto malformed;
			break;
	}

	if(len!=i) {
		cause = proto_tree_add_text(tree, tvb, offset, len, "BER Error: malformed UTCTime encoding, " "%d unexpected character%s after %dth octet", len-i, (len==i-1?"s":""), i);


		goto malformed;
	}

	if(hf_id >= 0){
		proto_tree_add_string(tree, hf_id, tvb, offset, len, outstr);
	}

	return offset+len;
malformed:
	proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
	expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: malformed UTCTime encoding");
	if(hf_id >= 0){
		proto_tree_add_string(tree, hf_id, tvb, offset, len, instr);
	}
	return offset+len;
}



int dissect_ber_constrained_bitstring(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, gint32 min_len, gint32 max_len, const asn_namedbit *named_bits, gint hf_id, gint ett_id, tvbuff_t **out_tvb)
{
	gint8 class;
	gboolean pc, ind;
	gint32 tag;
	guint32 len, byteno;
	guint8 pad=0, b0, b1, val, *bitstring;
	int end_offset;
	int hoffset;
	proto_item *item = NULL;
	proto_item *cause;
	proto_tree *tree = NULL;
	const asn_namedbit *nb;
	const char *sep;
	gboolean term;

	if(!implicit_tag){
	  hoffset = offset;
	  
	  offset = dissect_ber_identifier(actx->pinfo, parent_tree, tvb, offset, &class, &pc, &tag);
	  offset = dissect_ber_length(actx->pinfo, parent_tree, tvb, offset, &len, &ind);
	  end_offset = offset + len;

	  

	  

	  if(!implicit_tag && (class!=BER_CLASS_APP)) {
		if( (class!=BER_CLASS_UNI)
		  ||(tag!=BER_UNI_TAG_BITSTRING) ){
		    tvb_ensure_bytes_exist(tvb, hoffset, 2);
		    cause = proto_tree_add_text(parent_tree, tvb, offset, len, "BER Error: BitString expected but class:%s(%d) %s tag:%d was unexpected", val_to_str(class,ber_class_codes,"Unknown"), class, pc ? ber_pc_codes_short.true_string : ber_pc_codes_short.false_string, tag);
		    proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
		    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "BER Error: BitString expected");
		    if (decode_unexpected) {
		      proto_tree *unknown_tree = proto_item_add_subtree(cause, ett_ber_unknown);
		      dissect_unknown_ber(actx->pinfo, tvb, hoffset, unknown_tree);
		    }
		    return end_offset;
		}
	  }
	} else {
	  pc=0;
	  len=tvb_length_remaining(tvb,offset);
	  end_offset=offset+len;
	}

	actx->created_item = NULL;

	if(pc) {
		
		
	} else {
		
		pad = tvb_get_guint8(tvb, offset);
		if(pad == 0 && len == 1) {
			
			proto_tree_add_item(parent_tree, hf_ber_bitstring_empty, tvb, offset, 1, FALSE);
		} else {
			
			proto_item *pad_item = proto_tree_add_item(parent_tree, hf_ber_bitstring_padding, tvb, offset, 1, FALSE);
			if (pad > 7) {
				expert_add_info_format(actx->pinfo, pad_item, PI_UNDECODED, PI_WARN, "Illegal padding (0 .. 7): %d", pad);
			}
		}
		offset++;
		len--;
		if(hf_id >= 0) {
			item = proto_tree_add_item(parent_tree, hf_id, tvb, offset, len, FALSE);
			actx->created_item = item;
			if(ett_id != -1) {
				tree = proto_item_add_subtree(item, ett_id);
			}
		}
		if(out_tvb) {
			if(len<=(guint32)tvb_length_remaining(tvb, offset)){
				*out_tvb = tvb_new_subset(tvb, offset, len, len);
			} else {
				*out_tvb = tvb_new_subset_remaining(tvb, offset);
			}
		}
	}

	if(named_bits) {
		sep = " (";
		term = FALSE;
		nb = named_bits;
		bitstring = tvb_get_ephemeral_string(tvb, offset, len);

		while (nb->p_id) {
			if(nb->bit < (8*len-pad)) {
				val = tvb_get_guint8(tvb, offset + nb->bit/8);
				bitstring[(nb->bit/8)] &= ~(0x80 >> (nb->bit%8));
				val &= 0x80 >> (nb->bit%8);
				b0 = (nb->gb0 == -1) ? nb->bit/8 :
						       ((guint32)nb->gb0)/8;
				b1 = (nb->gb1 == -1) ? nb->bit/8 :
						       ((guint32)nb->gb1)/8;
				proto_tree_add_item(tree, *(nb->p_id), tvb, offset + b0, b1 - b0 + 1, FALSE);
			} else {  
				val = 0;
				proto_tree_add_boolean(tree, *(nb->p_id), tvb, offset + len, 0, 0x00);
			}
			if(val) {
				if(item && nb->tstr) {
					proto_item_append_text(item, "%s%s", sep, nb->tstr);
					sep = ", ";
					term = TRUE;
				}
			} else {
				if(item && nb->fstr) {
					proto_item_append_text(item, "%s%s", sep, nb->fstr);
					sep = ", ";
					term = TRUE;
				}
			}
			nb++;
		}
		if(term)
			proto_item_append_text(item, ")");

		for (byteno = 0; byteno < len; byteno++) {
			if (bitstring[byteno]) {
				expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_WARN, "Unknown bit(s): 0x%s", bytes_to_str(bitstring, len));
				break;
			}
		}
	}

	if (pad > 0 && pad < 8 && len > 0) {
		guint8 bits_in_pad = tvb_get_guint8(tvb, offset + len - 1) & (0xFF >> (8-pad));
		if (bits_in_pad) {
			expert_add_info_format(actx->pinfo, item, PI_UNDECODED, PI_WARN, "Bits set in padded area: 0x%02x", bits_in_pad);
		}
	}

	ber_check_length(8*len-pad, min_len, max_len, actx, item, TRUE);

	return end_offset;
}

int dissect_ber_bitstring(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, const asn_namedbit *named_bits, gint hf_id, gint ett_id, tvbuff_t **out_tvb)
{
  return dissect_ber_constrained_bitstring(implicit_tag, actx, parent_tree, tvb, offset, -1, -1, named_bits, hf_id, ett_id, out_tvb);
}

int dissect_ber_bitstring32(gboolean implicit_tag, asn1_ctx_t *actx, proto_tree *parent_tree, tvbuff_t *tvb, int offset, int **bit_fields, gint hf_id, gint ett_id, tvbuff_t **out_tvb)
{
	tvbuff_t *tmp_tvb = NULL;
	proto_tree *tree;
	guint32 val;
	int **bf;
	header_field_info *hfi;
	const char *sep;
	gboolean term;
	unsigned int i, tvb_len;

	offset = dissect_ber_bitstring(implicit_tag, actx, parent_tree, tvb, offset, NULL, hf_id, ett_id, &tmp_tvb);

	tree = proto_item_get_subtree(actx->created_item);
	if(bit_fields && tree && tmp_tvb) {
		
		val=0;
		tvb_len=tvb_length(tmp_tvb);
		for(i=0;i<4;i++){
			val<<=8;
			if(i<tvb_len){
				val|=tvb_get_guint8(tmp_tvb,i);
			}
		}
		bf = bit_fields;
		sep = " (";
		term = FALSE;
		while (*bf) {
			proto_tree_add_boolean(tree, **bf, tmp_tvb, 0, tvb_len, val);
			if (**bf >= 0) {
				hfi = proto_registrar_get_nth(**bf);
				if(val & hfi->bitmask) {
					proto_item_append_text(actx->created_item, "%s%s", sep, hfi->name);
					sep = ", ";
					term = TRUE;
				}
			}
			bf++;
		}
		if(term)
			proto_item_append_text(actx->created_item, ")");
	}

	if(out_tvb)
		*out_tvb = tmp_tvb;

	return offset;
}



static int dissect_ber_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.indirect_reference);
  actx->external.indirect_ref_present = TRUE;

  return offset;
}

static int dissect_ber_T_octet_aligned(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
  if (actx->external.u.ber.ber_callback) {
    offset = actx->external.u.ber.ber_callback(FALSE, tvb, offset, actx, tree, hf_index);
  } else if (actx->external.direct_ref_present && dissector_get_string_handle(ber_oid_dissector_table, actx->external.direct_reference)) {
    offset = call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree);
  } else {
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.octet_aligned);
  }

  return offset;
}
static int dissect_ber_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.direct_reference);
  actx->external.direct_ref_present = TRUE;

  return offset;
}

static int dissect_ber_ObjectDescriptor(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_ObjectDescriptor, actx, tree, tvb, offset, hf_index, &actx->external.data_value_descriptor);


  return offset;
}

static int dissect_ber_T_single_ASN1_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
  if (actx->external.u.ber.ber_callback) {
    offset = actx->external.u.ber.ber_callback(FALSE, tvb, offset, actx, tree, hf_index);
  } else {
    offset = call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree);
  }

  return offset;
}

static int dissect_ber_T_arbitrary(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
  if (actx->external.u.ber.ber_callback) {
    offset = actx->external.u.ber.ber_callback(FALSE, tvb, offset, actx, tree, hf_index);
  } else {
    offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset, NULL, hf_index, -1, &actx->external.arbitrary);
  }

  return offset;
}

static const value_string ber_T_encoding_vals[] = {
  {   0, "single-ASN1-type" }, {   1, "octet-aligned" }, {   2, "arbitrary" }, { 0, NULL }


};

static const ber_choice_t T_encoding_choice[] = {
  {   0, &hf_ber_single_ASN1_type, BER_CLASS_CON, 0, 0, dissect_ber_T_single_ASN1_type }, {   1, &hf_ber_octet_aligned  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ber_T_octet_aligned }, {   2, &hf_ber_arbitrary      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ber_T_arbitrary }, { 0, NULL, 0, 0, 0, NULL }


};


static int dissect_ber_T_encoding(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset, T_encoding_choice, hf_index, ett_ber_T_encoding, &actx->external.encoding);


  return offset;
}


static const ber_sequence_t external_U_sequence[] = {
  { &hf_ber_direct_reference, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ber_OBJECT_IDENTIFIER }, { &hf_ber_indirect_reference, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ber_INTEGER }, { &hf_ber_data_value_descriptor, BER_CLASS_UNI, BER_UNI_TAG_ObjectDescriptor, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ber_ObjectDescriptor }, { &hf_ber_encoding       , BER_CLASS_ANY, -1, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ber_T_encoding }, { NULL, 0, 0, 0, NULL }



};
static int dissect_ber_external_U(gboolean implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_ , proto_tree *tree, int hf_index _U_)
{
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset, external_U_sequence, hf_index, ett_ber_EXTERNAL);
  return offset;
}

int dissect_ber_external_type(gboolean implicit_tag, proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, gint hf_id, ber_callback func){

	actx->external.u.ber.ber_callback =  func;

	offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset, hf_id, BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, TRUE, dissect_ber_external_U);

	asn1_ctx_clean_external(actx);

	return offset;
}

int dissect_ber_EmbeddedPDV_Type(gboolean implicit_tag, proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, gint hf_id, ber_callback func _U_){


  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset, hf_id, BER_CLASS_UNI, BER_UNI_TAG_EMBEDDED_PDV, TRUE, dissect_ber_external_U);

	return offset;
}

static void dissect_ber_syntax(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  (void) dissect_unknown_ber(pinfo, tvb, 0, tree);
}

static void dissect_ber(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  const char *name;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BER");

  col_set_str(pinfo->cinfo, COL_DEF_SRC, "BER encoded file");

  if(!decode_as_syntax) {

    
    col_set_str(pinfo->cinfo, COL_INFO, "Unknown BER");

    (void) dissect_unknown_ber(pinfo, tvb, 0, tree);

  } else {

    (void) call_ber_syntax_callback(decode_as_syntax, tvb, 0, pinfo, tree);

    if (check_col(pinfo->cinfo, COL_INFO)) {

      
      name = get_ber_oid_syntax(decode_as_syntax);

      col_add_fstr(pinfo->cinfo, COL_INFO, "Decoded as %s", name ? name : decode_as_syntax);
    }
  }
}

void proto_register_ber(void)
{
    static hf_register_info hf[] = {
	{ &hf_ber_id_class, {
	    "Class", "ber.id.class", FT_UINT8, BASE_DEC, VALS(ber_class_codes), 0xc0, "Class of BER TLV Identifier", HFILL }}, { &hf_ber_bitstring_padding, {

	    "Padding", "ber.bitstring.padding", FT_UINT8, BASE_DEC, NULL, 0x0, "Number of unused bits in the last octet of the bitstring", HFILL }}, { &hf_ber_bitstring_empty, {

	    "Empty", "ber.bitstring.empty", FT_UINT8, BASE_DEC, NULL, 0x0, "This is an empty bitstring", HFILL }}, { &hf_ber_id_pc, {

	    "P/C", "ber.id.pc", FT_BOOLEAN, 8, TFS(&ber_pc_codes), 0x20, "Primitive or Constructed BER encoding", HFILL }}, { &hf_ber_id_uni_tag, {

	    "Tag", "ber.id.uni_tag", FT_UINT8, BASE_DEC, VALS(ber_uni_tag_codes), 0x1f, "Universal tag type", HFILL }}, { &hf_ber_id_uni_tag_ext, {

	    "Tag", "ber.id.uni_tag", FT_UINT32, BASE_DEC, NULL, 0, "Universal tag type", HFILL }}, { &hf_ber_id_tag, {

	    "Tag", "ber.id.tag", FT_UINT8, BASE_DEC, NULL, 0x1f, "Tag value for non-Universal classes", HFILL }}, { &hf_ber_id_tag_ext, {

	    "Tag", "ber.id.tag", FT_UINT32, BASE_DEC, NULL, 0, "Tag value for non-Universal classes", HFILL }}, { &hf_ber_length, {

	    "Length", "ber.length", FT_UINT32, BASE_DEC, NULL, 0, "Length of contents", HFILL }}, { &hf_ber_unknown_OCTETSTRING, {

	    "OCTETSTRING", "ber.unknown.OCTETSTRING", FT_BYTES, BASE_NONE, NULL, 0, "This is an unknown OCTETSTRING", HFILL }}, { &hf_ber_unknown_BER_OCTETSTRING, {

	    "OCTETSTRING [BER encoded]", "ber.unknown.OCTETSTRING", FT_NONE, BASE_NONE, NULL, 0, "This is an BER encoded OCTETSTRING", HFILL }}, { &hf_ber_unknown_BER_primitive, {

	    "Primitive [BER encoded]", "ber.unknown.primitive", FT_NONE, BASE_NONE, NULL, 0, "This is a BER encoded Primitive", HFILL }}, { &hf_ber_unknown_OID, {

	    "OID", "ber.unknown.OID", FT_OID, BASE_NONE, NULL, 0, "This is an unknown Object Identifier", HFILL }}, { &hf_ber_unknown_GraphicString, {

	    "GRAPHICSTRING", "ber.unknown.GRAPHICSTRING", FT_STRING, BASE_NONE, NULL, 0, "This is an unknown GRAPHICSTRING", HFILL }}, { &hf_ber_unknown_NumericString, {

	    "NumericString", "ber.unknown.NumericString", FT_STRING, BASE_NONE, NULL, 0, "This is an unknown NumericString", HFILL }}, { &hf_ber_unknown_PrintableString, {

	    "PrintableString", "ber.unknown.PrintableString", FT_STRING, BASE_NONE, NULL, 0, "This is an unknown PrintableString", HFILL }}, { &hf_ber_unknown_TeletexString, {

	    "TeletexString", "ber.unknown.TeletexString", FT_STRING, BASE_NONE, NULL, 0, "This is an unknown TeletexString", HFILL }}, { &hf_ber_unknown_VisibleString, {

	    "VisibleString", "ber.unknown.VisibleString", FT_STRING, BASE_NONE, NULL, 0, "This is an unknown VisibleString", HFILL }}, { &hf_ber_unknown_GeneralString, {

	    "GeneralString", "ber.unknown.GeneralString", FT_STRING, BASE_NONE, NULL, 0, "This is an unknown GeneralString", HFILL }}, { &hf_ber_unknown_UniversalString, {

	    "UniversalString", "ber.unknown.UniversalString", FT_STRING, BASE_NONE, NULL, 0, "This is an unknown UniversalString", HFILL }}, { &hf_ber_unknown_BMPString, {

	    "BMPString", "ber.unknown.BMPString", FT_STRING, BASE_NONE, NULL, 0, "This is an unknown BMPString", HFILL }}, { &hf_ber_unknown_IA5String, {

	    "IA5String", "ber.unknown.IA5String", FT_STRING, BASE_NONE, NULL, 0, "This is an unknown IA5String", HFILL }}, { &hf_ber_unknown_UTCTime, {

	    "UTCTime", "ber.unknown.UTCTime", FT_STRING, BASE_NONE, NULL, 0, "This is an unknown UTCTime", HFILL }}, { &hf_ber_unknown_UTF8String, {

	    "UTF8String", "ber.unknown.UTF8String", FT_STRING, BASE_NONE, NULL, 0, "This is an unknown UTF8String", HFILL }}, { &hf_ber_unknown_GeneralizedTime, {

	    "GeneralizedTime", "ber.unknown.GeneralizedTime", FT_STRING, BASE_NONE, NULL, 0, "This is an unknown GeneralizedTime", HFILL }}, { &hf_ber_unknown_INTEGER, {

	    "INTEGER", "ber.unknown.INTEGER", FT_UINT32, BASE_DEC, NULL, 0, "This is an unknown INTEGER", HFILL }}, { &hf_ber_unknown_BITSTRING, {

	    "BITSTRING", "ber.unknown.BITSTRING", FT_BYTES, BASE_NONE, NULL, 0, "This is an unknown BITSTRING", HFILL }}, { &hf_ber_unknown_BOOLEAN, {

	    "BOOLEAN", "ber.unknown.BOOLEAN", FT_UINT8, BASE_HEX, NULL, 0, "This is an unknown BOOLEAN", HFILL }}, { &hf_ber_unknown_ENUMERATED, {

	    "ENUMERATED", "ber.unknown.ENUMERATED", FT_UINT32, BASE_DEC, NULL, 0, "This is an unknown ENUMERATED", HFILL }}, { &hf_ber_constructed_OCTETSTRING, {

	    "OCTETSTRING", "ber.constructed.OCTETSTRING", FT_BYTES, BASE_NONE, NULL, 0, "This is a component of an constructed OCTETSTRING", HFILL }}, { &hf_ber_no_oid, {

	    "No OID", "ber.no_oid", FT_NONE, BASE_NONE, NULL, 0, "No OID supplied to call_ber_oid_callback", HFILL }}, { &hf_ber_oid_not_implemented, {

	    "OID not implemented", "ber.oid_not_implemented", FT_NONE, BASE_NONE, NULL, 0, "Dissector for OID not implemented", HFILL }}, { &hf_ber_no_syntax, {

	    "No OID", "ber.no_oid", FT_NONE, BASE_NONE, NULL, 0, "No syntax supplied to call_ber_syntax_callback", HFILL }}, { &hf_ber_syntax_not_implemented, {

	    "Syntax not implemented", "ber.syntax_not_implemented", FT_NONE, BASE_NONE, NULL, 0, "Dissector for OID not implemented", HFILL }}, { &hf_ber_direct_reference, { "direct-reference", "ber.direct_reference", FT_OID, BASE_NONE, NULL, 0, "ber.OBJECT_IDENTIFIER", HFILL }}, { &hf_ber_indirect_reference, { "indirect-reference", "ber.indirect_reference", FT_INT32, BASE_DEC, NULL, 0, "ber.INTEGER", HFILL }}, { &hf_ber_data_value_descriptor, { "data-value-descriptor", "ber.data_value_descriptor", FT_STRING, BASE_NONE, NULL, 0, "ber.ObjectDescriptor", HFILL }}, { &hf_ber_encoding, { "encoding", "ber.encoding", FT_UINT32, BASE_DEC, VALS(ber_T_encoding_vals), 0, "ber.T_encoding", HFILL }}, { &hf_ber_octet_aligned, { "octet-aligned", "ber.octet_aligned", FT_BYTES, BASE_NONE, NULL, 0, "ber.T_octet_aligned", HFILL }}, { &hf_ber_arbitrary, { "arbitrary", "ber.arbitrary", FT_BYTES, BASE_NONE, NULL, 0, "ber.T_arbitrary", HFILL }}, { &hf_ber_single_ASN1_type, { "single-ASN1-type", "ber.single_ASN1_type", FT_NONE, BASE_NONE, NULL, 0, "ber.T_single_ASN1_type", HFILL }}, };































    static gint *ett[] = {
	&ett_ber_octet_string, &ett_ber_primitive, &ett_ber_unknown, &ett_ber_SEQUENCE, &ett_ber_EXTERNAL, &ett_ber_T_encoding, };





    module_t *ber_module;
    uat_t* users_uat = uat_new("OID Tables", sizeof(oid_user_t), "oid", FALSE, (void*) &oid_users, &num_oid_users, UAT_CAT_GENERAL, "ChObjectIdentifiers", oid_copy_cb, NULL, oid_free_cb, ber_update_oids, users_flds);












    proto_ber = proto_register_protocol("Basic Encoding Rules (ASN.1 X.690)", "BER", "ber");
    register_dissector ("ber", dissect_ber, proto_ber);
    proto_register_field_array(proto_ber, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    proto_set_cant_toggle(proto_ber);

    
    ber_module = prefs_register_protocol(proto_ber, NULL);

    prefs_register_bool_preference(ber_module, "show_internals", "Show internal BER encapsulation tokens", "Whether the dissector should also display internal" " ASN.1 BER details such as Identifier and Length fields", &show_internal_ber_fields);


    prefs_register_bool_preference(ber_module, "decode_unexpected", "Decode unexpected tags as BER encoded data", "Whether the dissector should decode unexpected tags as" " ASN.1 BER encoded data", &decode_unexpected);


    prefs_register_bool_preference(ber_module, "decode_octetstring", "Decode OCTET STRING as BER encoded data", "Whether the dissector should try decoding OCTET STRINGs as" " constructed ASN.1 BER encoded data", &decode_octetstring_as_ber);



    prefs_register_bool_preference(ber_module, "decode_primitive", "Decode Primitive as BER encoded data", "Whether the dissector should try decoding unknown primitive as" " constructed ASN.1 BER encoded data", &decode_primitive_as_ber);



    prefs_register_uat_preference(ber_module, "oid_table", "Object Identifiers", "A table that provides names for object identifiers" " and the syntax of any associated values", users_uat);



    ber_oid_dissector_table = register_dissector_table("ber.oid", "BER OID Dissectors", FT_STRING, BASE_NONE);
    ber_syntax_dissector_table = register_dissector_table("ber.syntax", "BER Syntax Dissectors", FT_STRING, BASE_NONE);
    syntax_table=g_hash_table_new(g_str_hash, g_str_equal); 

    register_ber_syntax_dissector("ASN.1", proto_ber, dissect_ber_syntax);

    register_init_routine(ber_defragment_init);
}

void proto_reg_handoff_ber(void)
{
  guint i = 1;
        dissector_handle_t ber_handle;

	oid_add_from_string("asn1","2.1");
	oid_add_from_string("basic-encoding","2.1.1");

	ber_handle = create_dissector_handle(dissect_ber, proto_ber);
	dissector_add("wtap_encap", WTAP_ENCAP_BER, ber_handle);

	ber_decode_as_foreach(ber_add_syntax_name, &i);

	if(i > 1)
	  qsort(&syntax_names[1], i - 1, sizeof(value_string), cmp_value_string);
	syntax_names[i].value = 0;
	syntax_names[i].strptr = NULL;



	ber_update_oids();
}

gboolean oid_has_dissector(const char *oid) {
  return(dissector_get_string_handle(ber_oid_dissector_table, oid) != NULL);
}
