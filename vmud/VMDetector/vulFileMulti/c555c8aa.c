









































bool is_dwg_object (const char *name);
bool is_dwg_entity (const char *name);
int dwg_dynapi_entity_size (const char *restrict name);

BITCODE_T dwg_add_u8_input (Dwg_Data *restrict dwg, const char *restrict u8str);
Dwg_Object_APPID *dwg_add_APPID (Dwg_Data *restrict dwg, const char *restrict name);
unsigned long dwg_obj_generic_handlevalue (void *_obj);


static unsigned int loglevel;

static unsigned int cur_ver = 0;
static BITCODE_BL rcount1 = 0, rcount2 = 0;



static bool env_var_checked_p;


































































































































































































































































































































































































































































































































































































































static void obj_flush_hdlstream (Dwg_Object *restrict obj, Bit_Chain *restrict dat, Bit_Chain *restrict hdl_dat)

{
  unsigned long datpos = bit_position (dat);
  unsigned long hdlpos = bit_position (hdl_dat);
  unsigned long objpos = obj->address * 8;
  LOG_TRACE ("Flush handle stream of size %lu (@%lu.%u) to @%lu.%lu\n", hdlpos, hdl_dat->byte, hdl_dat->bit, (datpos - objpos) / 8, (datpos - objpos) % 8);

  bit_copy_chain (dat, hdl_dat);
}



EXPORT long dwg_add_##token (Dwg_Data * dwg)     { Bit_Chain dat = { 0 }; BITCODE_BL num_objs  = dwg->num_objects; int error = 0; dat.size = sizeof(Dwg_Entity_##token) + 40; LOG_INFO ("Add entity " #token " ") dat.chain = calloc (dat.size, 1); dat.version = dwg->header.version; dat.from_version = dwg->header.from_version; bit_write_MS (&dat, dat.size); if (dat.version >= R_2010) {  bit_write_UMC (&dat, 8*sizeof(Dwg_Entity_##token)); bit_write_BOT &dat, DWG_TYPE_##token); } else { bit_write_BS (&dat, DWG_TYPE_##token); } bit_set_position (&dat, 0); error = dwg_decode_add_object (dwg, &dat, &dat, 0); if (-1 == error) dwg_resolve_objectrefs_silent (dwg); if (num_objs == dwg->num_objects) return -1; else return (long)dwg->num_objects; 


























EXPORT long dwg_add_##token (Dwg_Data * dwg)      { Bit_Chain dat = { 0 }; int error = 0; BITCODE_BL num_objs  = dwg->num_objects; dat.size = sizeof(Dwg_Object_##token) + 40; LOG_INFO ("Add object " #token " ") dat.chain = calloc (dat.size, 1); dat.version = dwg->header.version; dat.from_version = dwg->header.from_version; bit_write_MS (&dat, dat.size); if (dat.version >= R_2010) {  bit_write_UMC (&dat, 8*sizeof(Dwg_Object_##token)); bit_write_BOT (&dat, DWG_TYPE_##token); } else { bit_write_BS (&dat, DWG_TYPE_##token); } bit_set_position(&dat, 0); error = dwg_decode_add_object(dwg, &dat, &dat, 0); if (-1 ==  error) dwg_resolve_objectrefs_silent(dwg); if (num_objs == dwg->num_objects) return -1; else return (long)dwg->num_objects; 



















































































































































typedef struct {
  unsigned long handle;
  long address;
  BITCODE_BL index;
} Object_Map;


static int encode_preR13 (Dwg_Data *restrict dwg, Bit_Chain *restrict dat);

static int dwg_encode_entity (Dwg_Object *restrict obj, Bit_Chain *dat, Bit_Chain *restrict hdl_dat, Bit_Chain *str_dat);
static int dwg_encode_object (Dwg_Object *restrict obj, Bit_Chain *dat, Bit_Chain *restrict hdl_dat, Bit_Chain *str_dat);
static int dwg_encode_common_entity_handle_data (Bit_Chain *dat, Bit_Chain *hdl_dat, Dwg_Object *restrict obj);

static int dwg_encode_header_variables (Bit_Chain *dat, Bit_Chain *hdl_dat, Bit_Chain *str_dat, Dwg_Data *restrict dwg);

static int dwg_encode_variable_type (Dwg_Data *restrict dwg, Bit_Chain *restrict dat, Dwg_Object *restrict obj);

void dwg_encode_handleref (Bit_Chain *hdl_dat, Dwg_Object *restrict obj, Dwg_Data *restrict dwg, Dwg_Object_Ref *restrict ref);

void dwg_encode_handleref_with_code (Bit_Chain *hdl_dat, Dwg_Object *restrict obj, Dwg_Data *restrict dwg, Dwg_Object_Ref *restrict ref, unsigned int code);



int dwg_encode_add_object (Dwg_Object *restrict obj, Bit_Chain *restrict dat, unsigned long address);

static int dwg_encode_xdata (Bit_Chain *restrict dat, Dwg_Object_XRECORD *restrict obj, unsigned size);
static unsigned long add_LibreDWG_APPID (Dwg_Data *dwg);
static BITCODE_BL add_DUMMY_eed (Dwg_Object *obj);
static void fixup_NOD (Dwg_Data *restrict dwg, Dwg_Object *restrict obj);


BITCODE_H dwg_find_tablehandle_silent (Dwg_Data *restrict dwg, const char *restrict name, const char *restrict table);

void set_handle_size (Dwg_Handle *restrict hdl);



static BITCODE_RL encode_patch_RLsize (Bit_Chain *dat, long unsigned int pvzadr)
{
  unsigned long pos;
  BITCODE_RL size;
  if (dat->bit) 
    {
      dat->bit = 0;
      dat->byte++;
    }
  size = dat->byte - pvzadr - 4; 
  pos = bit_position (dat);
  assert (pvzadr);
  bit_set_position (dat, pvzadr * 8);
  bit_write_RL (dat, size);
  LOG_TRACE ("size: " FORMAT_RL " [RL] @%lu\n", size, pvzadr);
  bit_set_position (dat, pos);
  return size;
}



static bool is_section_critical (Dwg_Section_Type i)
{
  return (i == SECTION_OBJECTS || i == SECTION_HEADER || i == SECTION_CLASSES || i == SECTION_HANDLES) ? true : false;
}

static bool is_section_r13_critical (Dwg_Section_Type_R13 i)
{
  return i <= SECTION_HANDLES_R13 ? true : false;
}



static unsigned long add_LibreDWG_APPID (Dwg_Data *dwg)
{
  BITCODE_H appid = dwg_find_tablehandle_silent (dwg, "LibreDWG", "APPID");
  BITCODE_H appctl;
  Dwg_Object *obj;
  Dwg_Object_APPID *_obj;
  Dwg_Object_APPID_CONTROL *o;
  unsigned long absref;
  

  if (appid)
    return appid->absolute_ref;

  
  
  

  


  _obj = dwg_add_APPID (dwg, "LibreDWG");
  return dwg_obj_generic_handlevalue (_obj);


  if (!(appctl = dwg->header_vars.APPID_CONTROL_OBJECT))
    appctl = dwg_find_table_control (dwg, "APPID_CONTROL");
  if (!appctl)
    {
      LOG_ERROR ("APPID_CONTROL not found")
      return 0;
    }
  absref = dwg->object[dwg->num_objects - 1].handle.value + 1;
  dwg_add_object (dwg);
  obj = &dwg->object[dwg->num_objects - 1];
  if (dwg_setup_APPID (obj) >= DWG_ERR_CRITICAL)
    return 0;
  dwg_add_handle (&obj->handle, 0, absref, obj);
  
  _obj = obj->tio.object->tio.APPID;
  
  obj->size = 25;
  obj->bitsize = 164;
  obj->tio.object->ownerhandle = dwg_add_handleref (dwg, 4, appctl->absolute_ref, NULL);
  obj->tio.object->xdicobjhandle = dwg_add_handleref (dwg, 3, 0, NULL);

  _obj->name = dwg_add_u8_input (dwg, "LibreDWG");
  _obj->is_xref_ref = 1;
  _obj->xref = dwg_add_handleref (dwg, 5, 0, NULL);

  
  obj = dwg_ref_object (dwg, appctl);
  if (!obj)
    {
      LOG_ERROR ("APPID_CONTROL not found")
      return 0;
    }
  o = obj->tio.object->tio.APPID_CONTROL;
  PUSH_HV (o, num_entries, entries, dwg_add_handleref (dwg, 2, absref, NULL));
  return absref;



  return 0x12; 
}

static BITCODE_BL add_DUMMY_eed (Dwg_Object *obj)
{
  Dwg_Object_Entity *ent = obj->tio.entity;
  
  const BITCODE_BL num_eed = ent->num_eed; 
  Dwg_Data *dwg = obj->parent;
  char *name = obj->dxfname;
  BITCODE_H appid;
  Dwg_Eed_Data *data;
  int i = 1, off = 0;
  int len, size;
  const bool is_tu = dwg->header.version >= R_2007;

  


  return 0;




  assert (offsetof (Dwg_Object_Object, num_eed) == offsetof (Dwg_Object_Entity, num_eed));
  assert (offsetof (Dwg_Object_Object, eed) == offsetof (Dwg_Object_Entity, eed));


  if (num_eed) 
    dwg_free_eed (obj);
  appid = dwg_find_tablehandle_silent (dwg, "LibreDWG", "APPID");
  if (!appid)
    {
      LOG_WARN ("APPID LibreDWG not found, no EED added");
      ent->num_eed = 0;
      return 0;
    }
  ent->num_eed = 1;
  ent->eed = calloc (2, sizeof (Dwg_Eed));
  len = strlen (name);
  size = is_tu ? 1 + 2 + ((len + 1) * 2) 
               : 1 + 3 + len + 1;        
  data = ent->eed[0].data = (Dwg_Eed_Data *)calloc (size + 3, 1);
  ent->eed[0].size = size;
  dwg_add_handle (&ent->eed[0].handle, 5, appid->absolute_ref, NULL);
  data->code = 0; 
  if (is_tu) 
    {
      BITCODE_TU wstr = bit_utf8_to_TU (name, 0);
      data->u.eed_0_r2007.is_tu = 1;
      data->u.eed_0_r2007.length = len; 
      memcpy (data->u.eed_0_r2007.string, wstr, len * 2);
    }
  else {
      data->u.eed_0.is_tu = 0;
      data->u.eed_0.length = len;  
      data->u.eed_0.codepage = 30; 
      memcpy (data->u.eed_0.string, name, len);
    }
  LOG_TRACE ("-EED[0]: code: 0, string: %s (len: %d)\n", name, len);

  if (!obj->num_unknown_bits)
    return 1;
  
  len = obj->num_unknown_bits / 8;
  if (obj->num_unknown_bits % 8)
    len++;
  size = (len / 256) + 1;
  if (size > 1) 
    {
      ent->eed = realloc (ent->eed, (1 + size) * sizeof (Dwg_Eed));
      memset (&ent->eed[1], 0, size * sizeof (Dwg_Eed));
    }
  do {
      int l = len > 255 ? 255 : len;
      ent->num_eed++;
      ent->eed[i].size = 0;
      ent->eed[0].size += l + 2;
      data = ent->eed[i].data = (Dwg_Eed_Data *)calloc (l + 2, 1);
      data->code = 4;           
      data->u.eed_4.length = l; 
      memcpy (data->u.eed_4.data, &obj->unknown_bits[off], data->u.eed_4.length);
      LOG_TRACE ("-EED[%d]: code: 4, unknown_bits: %d\n", i, data->u.eed_4.length);
      if (len > 255)
        {
          len -= 256;
          off += 256;
          i++;
        }
      else break;
    }
  while (1);
  return i;

}




static void encode_unknown_as_dummy (Bit_Chain *restrict dat, Dwg_Object *restrict obj, BITCODE_BS placeholder_type)

{
  Dwg_Data *dwg = obj->parent;
  int is_entity = obj->supertype == DWG_SUPERTYPE_ENTITY;
  
  obj->size = 0;
  obj->bitsize = 0;

  if (is_entity)
    { 
      
      Dwg_Entity_POINT *_obj = obj->tio.entity->tio.POINT;
      LOG_WARN ("fixup unsupported %s %lX as POINT", obj->dxfname, obj->handle.value);
      if (!obj->tio.entity->xdicobjhandle)
        obj->tio.entity->xdicobjhandle = dwg_add_handleref (dwg, 3, 0, NULL);
      
      add_DUMMY_eed (obj); 
      dwg_free_object_private (obj);
      free (obj->unknown_bits);
      obj->tio.entity->tio.POINT = _obj = realloc (_obj, sizeof (Dwg_Entity_POINT));
      
      _obj->parent = obj->tio.entity;
      _obj->x = 0.0;
      _obj->y = 0.0;
      _obj->z = 0.0;
      _obj->thickness = 1e25; 
      _obj->extrusion.x = 0.0;
      _obj->extrusion.y = 0.0;
      _obj->extrusion.z = 1.0;
      _obj->x_ang = 0.0;
      obj->type = DWG_TYPE_POINT;
      obj->fixedtype = DWG_TYPE_POINT;
      if (dwg->opts & DWG_OPTS_INJSON)
        {
          free (obj->name);
          obj->name = strdup ("POINT");
        }
      else obj->name = (char *)"POINT";
      if (dwg->opts & DWG_OPTS_IN)
        {
          free (obj->dxfname);
          obj->dxfname = strdup ("POINT");
        }
      else obj->dxfname = (char *)"POINT";
    }
  else {
      const char *name;
      const char *dxfname;

      add_DUMMY_eed (obj); 
      dwg_free_object_private (obj);
      
      
      if (placeholder_type)
        {
          obj->type = placeholder_type;
          obj->fixedtype = DWG_TYPE_PLACEHOLDER;
          name = "PLACEHOLDER";
          dxfname = "ACDBPLACEHOLDER";
        }
      else {
          obj->type = DWG_TYPE_DUMMY;
          obj->fixedtype = DWG_TYPE_DUMMY;
          name = "DUMMY";
          dxfname = "DUMMY";
        }
      LOG_INFO ("fixup unsupported %s %lX as %s, Type %d\n", obj->dxfname, obj->handle.value, name, obj->type);
      if (!obj->tio.object->xdicobjhandle)
        obj->tio.object->xdicobjhandle = dwg_add_handleref (dwg, 3, 0, NULL);
      
      if (dwg->opts & DWG_OPTS_INJSON)
        {
          free (obj->name);
          obj->name = strdup (name);
        }
      else obj->name = (char *)name;
      if (dwg->opts & DWG_OPTS_IN)
        {
          free (obj->dxfname);
          obj->dxfname = strdup (dxfname);
        }
      else obj->dxfname = (char *)dxfname;
      free (obj->unknown_bits);
    }
  obj->hdlpos = 0;
}




static void remove_NOD_item (Dwg_Object_DICTIONARY *_obj, const int i, const char *name)
{
  int last = _obj->numitems - 1;
  LOG_TRACE ("Disable link to " FORMAT_REF " for NOD.%s\n", ARGS_REF (_obj->itemhandles[i]), name);
  if (i < last)
    {
      free (_obj->texts[i]);
      if (!_obj->itemhandles[i]->handleref.is_global)
        free (_obj->itemhandles[i]);
      memmove (&_obj->texts[i], &_obj->texts[i+1], (last - i) * sizeof (BITCODE_T));
      memmove (&_obj->itemhandles[i], &_obj->itemhandles[i+1], (last - i) * sizeof (BITCODE_H));
    }
  _obj->numitems--;
  return;
}




static void fixup_NOD (Dwg_Data *restrict dwg, Dwg_Object *restrict obj)
{
  Dwg_Object_DICTIONARY *_obj;
  int is_tu = dwg->header.version >= R_2007;
  if (obj->handle.value != 0xC)
    return;
  _obj = obj->tio.object->tio.DICTIONARY;
  
  












  
  for (BITCODE_BL i = 0; i < _obj->numitems; i++)
    {
      DISABLE_NODSTYLE (ASSOCNETWORK)
      else DISABLE_NODSTYLE (ASSOCPERSSUBENTMANAGER)
      else DISABLE_NODSTYLE (DETAILVIEWSTYLE)
      else DISABLE_NODSTYLE (MATERIAL)
      else DISABLE_NODSTYLE (MLEADERSTYLE)
      else DISABLE_NODSTYLE (MLINESTYLE)
      else DISABLE_NODSTYLE (PERSUBENTMGR)
      else DISABLE_NODSTYLE (PLOTSETTINGS)
      
      else DISABLE_NODSTYLE (SECTIONVIEWSTYLE)
      else DISABLE_NODSTYLE (TABLESTYLE)
      else DISABLE_NODSTYLE (VISUALSTYLE)
    }

}


static int copy_R2004_section (Bit_Chain *restrict dat, BITCODE_RC *restrict decomp, uint32_t decomp_data_size, uint32_t *comp_data_size)
{
  if (dat->byte + decomp_data_size >= dat->size)
    {
      dat->size = dat->byte + decomp_data_size;
      bit_chain_alloc (dat);
    }
  assert (!dat->bit);
  memcpy (&dat->chain[dat->byte], decomp, decomp_data_size);
  dat->byte += decomp_data_size;
  *comp_data_size = decomp_data_size;
  return 0;
}


static int section_encrypted (const Dwg_Data *dwg, const Dwg_Section_Type id)
{
  switch (id)
    {
    case SECTION_SECURITY: 
    case SECTION_FILEDEPLIST:
    case SECTION_APPINFO:
      return 1;
    case SECTION_UNKNOWN:
    case SECTION_HEADER:
    case SECTION_REVHISTORY:
    case SECTION_OBJECTS:
    case SECTION_OBJFREESPACE:
    case SECTION_TEMPLATE:
    case SECTION_HANDLES:
    case SECTION_CLASSES:
    case SECTION_AUXHEADER:
    case SECTION_SUMMARYINFO:
    case SECTION_PREVIEW:
    case SECTION_APPINFOHISTORY:
    case SECTION_VBAPROJECT:
    case SECTION_SIGNATURE:
    case SECTION_ACDS:
    case SECTION_SYSTEM_MAP:
    case SECTION_INFO:
    default:
      return 0;
    }
}


static int section_compressed (const Dwg_Data *dwg, const Dwg_Section_Type id)
{
  switch (id)
    {
    case SECTION_UNKNOWN:
    case SECTION_HEADER:
    case SECTION_REVHISTORY:
    case SECTION_OBJECTS:
    case SECTION_OBJFREESPACE:
    case SECTION_TEMPLATE:
    case SECTION_HANDLES:
    case SECTION_CLASSES:
    case SECTION_AUXHEADER:
    case SECTION_SYSTEM_MAP:
    case SECTION_INFO:
      return 1;
    case SECTION_SUMMARYINFO:
    case SECTION_PREVIEW:
    case SECTION_APPINFO:
    case SECTION_APPINFOHISTORY:
    case SECTION_FILEDEPLIST:
    case SECTION_SECURITY:
    case SECTION_VBAPROJECT:
    case SECTION_SIGNATURE:
    case SECTION_ACDS:
    default:
      return 0;
    }
}







static void write_length (Bit_Chain *dat, uint32_t u1, uint32_t match, uint32_t u2);


static unsigned char write_literal_length (Bit_Chain *restrict dat, BITCODE_RC *restrict buf, uint32_t len)
{

  if (len <= (0x0F + 3)) 
    {
      bit_write_RC (dat, len - 3);
      return 0;
    }
  else if (len < 0xf0)
    {
      bit_write_RC (dat, len);
      return length & 0xff;
    }
  else {
      uint32_t total = 0x0f;
      while (leng >= 0xf0)
        {
          bit_write_RC (dat, 0);
          len -= 0xFF;
          total += 0xFF;
        }
      bit_write_RC (dat, len - 3); 
      return 0;
    }

  if (len)
    {
      if (len > 3) {
        write_length (dat, 0, len - 1, 0x11);
      }
      LOG_INSANE ("LIT %x\n", len)
      bit_write_TF (dat, buf, len);
    }
  return 0;

}


static void write_long_compression_offset (Bit_Chain *dat, uint32_t offset)
{
  while (offset > 0xff)
    {
      bit_write_RC (dat, 0);
      offset -= 0xff;
    }
  LOG_INSANE (">O 00 %x", offset)
  bit_write_RC (dat, (unsigned char)offset);
}

static void write_length (Bit_Chain *dat, uint32_t u1, uint32_t match, uint32_t u2)
{
  if (u2 < match)
    {
      LOG_INSANE (">L %x ", u1 & 0xff)
      bit_write_RC (dat, u1 & 0xff);
      write_long_compression_offset (dat, match - u2);
      LOG_INSANE ("\n")
    }
  else {
      LOG_INSANE (">L %x\n", (u1 | (match - 2)) & 0xff);
      bit_write_RC (dat, (u1 | (match - 2)) & 0xff);
    }
}



static unsigned int write_two_byte_offset (Bit_Chain *restrict dat, uint32_t offset)
{
  BITCODE_RC b1, b2;
  b1 = offset << 2;
  b2 = offset >> 6;
  
  bit_write_RC (dat, b1);
  bit_write_RC (dat, b2);
  
  return b1 & 0x03;
}


static void write_two_byte_offset (Bit_Chain *restrict dat, uint32_t oldlen, uint32_t offset, uint32_t len)
{
  const unsigned lookahead_buffer_size = COMPRESSION_BUFFER_SIZE;
  uint32_t b1, b2;

  LOG_INSANE ("2O %x %x %x: ", oldlen, offset, len)
  if ((offset < 0xf) && (oldlen < 0x401))
    {
      b1 = (offset + 1) * 0x10 | ((oldlen - 1U) & 3) << 2;
      b2 = (oldlen - 1U) >> 2;
    }
  else {
      if (oldlen <= lookahead_buffer_size)
        {
          b2 = oldlen - 1;
          write_length (dat, 0x20, offset, 0x21);
        }
      else {
          b2 = oldlen - lookahead_buffer_size;
          write_length (dat, ((b2 >> 0xb) & 8U) | 0x10, offset, 9);
        }
      b1 = (b2 & 0xff) << 2;
      b2 = b2 >> 6;
    }
  if (len < 4)
    b1 = b1 | len;
  LOG_INSANE ("> %x %x\n", b1, b2)
  bit_write_RC (dat, b1 & 0xff);
  bit_write_RC (dat, b2 & 0xff);
}


static int find_longest_match (BITCODE_RC *restrict decomp, uint32_t decomp_data_size, uint32_t i, uint32_t *lenp)
{
  const unsigned lookahead_buffer_size = COMPRESSION_BUFFER_SIZE;
  const unsigned window_size = COMPRESSION_WINDOW_SIZE;
  int offset = 0;
  uint32_t bufend = MIN (i + lookahead_buffer_size, decomp_data_size + 1);
  *lenp = 0;
  
  for (uint32_t j = i + 2; j < bufend; j++)
    {
      int start = MAX (0, (int)(i - window_size));
      BITCODE_RC *s = &decomp[i];
      uint32_t slen = j - i;
      for (int k = start; k < (int)i; k++)
        {
          int curr_offset = i - k;
          
          
          BITCODE_RC *match = &decomp[k]; 
          
          if ((memcmp (s, match, slen) == 0)
              && slen > *lenp)
            {
              offset = curr_offset;
              *lenp = slen;
            }
        }
    }
  if (offset)
    {
      LOG_INSANE (">M %u (%u)\n", offset, *lenp)
    }
  return offset;
}


static int compress_R2004_section (Bit_Chain *restrict dat, BITCODE_RC *restrict decomp, uint32_t decomp_data_size, uint32_t *comp_data_size)
{
  uint32_t i = 0;
  uint32_t match = 0, oldlen = 0;
  uint32_t len = 0;
  unsigned long pos = bit_position (dat);
  LOG_WARN ("compress_R2004_section %d", decomp_data_size);
  assert (decomp_data_size > MIN_COMPRESSED_SECTION);
  while (i < decomp_data_size - MIN_COMPRESSED_SECTION)
    {
      int offset = find_longest_match (decomp, decomp_data_size, i, &len);
      if (offset)
        {
          
          if (match)
            write_two_byte_offset (dat, oldlen, match, len);
          write_literal_length (dat, &decomp[i], len);
          i += match;
          match = offset;
          oldlen = len;
        }
      else {
          i += 1; 
        }
    }
  len = decomp_data_size - i;
  if (match)
    write_two_byte_offset (dat, oldlen, match, len);
  write_literal_length (dat, &decomp[i], len);
  bit_write_RC (dat, 0x11);
  bit_write_RC (dat, 0);
  bit_write_RC (dat, 0);
  *comp_data_size = bit_position (dat) - pos;
  LOG_INSANE ("> 11 0 => %u\n", *comp_data_size)
  return 0;
}

static Dwg_Section_Info * find_section_info_type (const Dwg_Data *restrict dwg, Dwg_Section_Type type)
{
  for (unsigned i = 0; i < dwg->header.section_infohdr.num_desc; i++)
    {
      Dwg_Section_Info *info = &dwg->header.section_info[i];
      if (info->fixedtype == type)
        return info;
    }
  return NULL;
}


static void section_info_rebuild (Dwg_Data *dwg, Dwg_Section_Type lasttype)
{
  Dwg_Section_Type type;
  
  for (type = 0; type <= lasttype; type++)
    {
      Dwg_Section_Info *info = find_section_info_type (dwg, type);
      if (info)
        {
          unsigned ssi = 0;
          for (unsigned i = 0; i < dwg->header.num_sections; i++)
            {
              Dwg_Section *sec = &dwg->header.section[i];
              if (sec->type == type) 
                {
                  info->sections[ssi] = sec;
                  ssi++;
                }
              else if (sec->type > type) 
                break;
            }
        }
    }
}


AFL_GCC_TOOBIG EXPORT int dwg_encode (Dwg_Data *restrict dwg, Bit_Chain *restrict dat)

{
  int ckr_missing = 1;
  int error = 0;
  BITCODE_BL i, j;
  long unsigned int section_address;
  long unsigned int pvzadr;
  unsigned int ckr;
  unsigned int sec_size = 0;
  long unsigned int last_offset;
  BITCODE_BL last_handle;
  Object_Map *omap;
  Bit_Chain *old_dat = NULL, *str_dat, *hdl_dat;
  int sec_id;
  Dwg_Version_Type orig_from_version = dwg->header.from_version;
  Bit_Chain sec_dat[SECTION_SYSTEM_MAP + 1]; 

  if (dwg->opts)
    loglevel = dwg->opts & DWG_OPTS_LOGLEVEL;

  
  if (!env_var_checked_p)
    {
      char *probe = getenv ("LIBREDWG_TRACE");
      if (probe)
        loglevel = atoi (probe);
      env_var_checked_p = true;
    }


  if (dwg->header.version != dwg->header.from_version)
    LOG_TRACE ("Encode version %s (%s) from version %s (%s)\n", version_codes[dwg->header.version], dwg_version_type (dwg->header.version), version_codes[dwg->header.from_version], dwg_version_type (dwg->header.from_version))



  else LOG_TRACE ("Encode version %s (%s)\n", version_codes[dwg->header.version], dwg_version_type (dwg->header.version))



  
  
  
  
  if (dwg->header.version != dwg->header.from_version || (dwg->opts & DWG_OPTS_IN))
    {
      int fixup = 0;
      
      
      LOG_TRACE ("Scan for unsupported objects\n");
      for (i = 0; i < dwg->num_objects; i++)
        {
          Dwg_Object *obj = &dwg->object[i];
          if (obj->fixedtype == DWG_TYPE_UNKNOWN_OBJ || obj->fixedtype == DWG_TYPE_UNKNOWN_ENT  || (dwg->opts & DWG_OPTS_IN && (obj->fixedtype == DWG_TYPE_WIPEOUT || obj->fixedtype == DWG_TYPE_TABLEGEOMETRY)))




            {
              fixup++;
              break;
            }
        }
      if (fixup)
        {
          unsigned long new_appid;
          BITCODE_BS placeholder_type = 0;
          LOG_TRACE ("Found unsupported objects, add APPID LibreDWG\n");
          new_appid = add_LibreDWG_APPID (dwg);
          if (new_appid)
            {
              fixup = 0;
              
              dwg_find_class (dwg, "ACDBPLACEHOLDER", &placeholder_type);
              for (i = 0; i < dwg->num_objects; i++)
                {
                  Dwg_Object *obj = &dwg->object[i];
                  if (obj->fixedtype == DWG_TYPE_UNKNOWN_OBJ || obj->fixedtype == DWG_TYPE_UNKNOWN_ENT || (dwg->opts & DWG_OPTS_IN && (obj->fixedtype == DWG_TYPE_WIPEOUT || obj->fixedtype == DWG_TYPE_TABLEGEOMETRY)))



                    {
                      fixup++;
                      
                      
                      encode_unknown_as_dummy (dat, obj, placeholder_type);
                    }
                  
                  if (obj->handle.value == 0xC && obj->fixedtype == DWG_TYPE_DICTIONARY)
                    fixup_NOD (dwg, obj); 
                }
              LOG_TRACE ("Fixed %d unsupported objects\n\n", fixup);
            }
        }
    }


  bit_chain_alloc (dat);
  hdl_dat = dat; 
  if (!dat->version)
    {
      dat->version = dwg->header.version;
      dat->from_version = dwg->header.from_version;
      dat->opts = dwg->opts;
    }

  
  strcpy ((char *)dat->chain, version_codes[dwg->header.version]);
  dat->byte += 6;

  {
    Dwg_Header *_obj = &dwg->header;
    Dwg_Object *obj = NULL;
    if (!_obj->dwg_version) 
      {
        _obj->zero_one_or_three = 1;
        _obj->dwg_version = 0x21;
        _obj->is_maint = 0xf;
        _obj->maint_version = 29;
        if (dwg->header.version < R_13)
          {
            _obj->dwg_version = 0x14;
          }
        
        if (!_obj->app_dwg_version)
          _obj->app_dwg_version = _obj->dwg_version;
      }
    if (!_obj->codepage)
      _obj->codepage = 30;

    
    #include "header.spec"
    
  }
  section_address = dat->byte;




  PRE (R_13)
  {
    
    LOG_ERROR (WE_CAN "We don't encode preR13 tables, entities, blocks yet")

    return encode_preR13 (dwg, dat);

  }

  PRE (R_2004)
  {
    
    
    if (!dwg->header.num_sections || (dat->from_version >= R_2004 && dwg->header.num_sections > 6))
      {
        dwg->header.num_sections = dwg->header.version < R_2000 ? 5 : 6;
        
        if (!dwg->header_vars.HANDSEED || !dwg->header_vars.TDCREATE.days)
          {
            dwg->header.num_sections = 5;
            
            
            dat->from_version = R_11;
            if (dat->version <= dat->from_version)
              dat->from_version = (Dwg_Version_Type)((int)dat->version - 1);
          }
      }
    LOG_TRACE ("num_sections: " FORMAT_RL " [RL]\n", dwg->header.num_sections);
    bit_write_RL (dat, dwg->header.num_sections);
    if (!dwg->header.section)
      dwg->header.section = (Dwg_Section*)calloc (dwg->header.num_sections, sizeof (Dwg_Section));
    if (!dwg->header.section)
      {
        LOG_ERROR ("Out of memory");
        return DWG_ERR_OUTOFMEM;
      }
    section_address = dat->byte;                 
    dat->byte += (dwg->header.num_sections * 9); 
    bit_write_CRC (dat, 0, 0xC0C1);
    bit_write_sentinel (dat, dwg_sentinel (DWG_SENTINEL_HEADER_END));

    
    if (dwg->header.num_sections > 5)
      {
        Dwg_AuxHeader *_obj = &dwg->auxheader;
        Dwg_Object *obj = NULL;
        BITCODE_BL vcount;
        assert (!dat->bit);
        LOG_INFO ("\n=======> AuxHeader: %8u\n", (unsigned)dat->byte);

        dwg->header.section[SECTION_AUXHEADER_R2000].number = 5;
        dwg->header.section[SECTION_AUXHEADER_R2000].address = dat->byte;

        if (!_obj->dwg_version) 
          {
            BITCODE_RS def_unknown_6rs[] = { 4, 0x565, 0, 0, 2, 1 };
            LOG_TRACE ("Use AuxHeader defaults...\n");
            FIELD_VALUE (aux_intro[0]) = 0xff;
            FIELD_VALUE (aux_intro[1]) = 0x77;
            FIELD_VALUE (aux_intro[2]) = 0x01;
            FIELD_VALUE (minus_1) = -1;
            FIELD_VALUE (dwg_version) = dwg->header.dwg_version;
            FIELD_VALUE (maint_version) = dwg->header.maint_version;
            FIELD_VALUE (dwg_version_1) = dwg->header.dwg_version;
            FIELD_VALUE (dwg_version_2) = dwg->header.dwg_version;
            FIELD_VALUE (maint_version_1) = dwg->header.maint_version;
            FIELD_VALUE (maint_version_2) = dwg->header.maint_version;
            memcpy (FIELD_VALUE (unknown_6rs), def_unknown_6rs, sizeof (def_unknown_6rs));
            FIELD_VALUE (TDCREATE) = dwg->header_vars.TDCREATE.value;
            FIELD_VALUE (TDUPDATE) = dwg->header_vars.TDUPDATE.value;
            if (dwg->header_vars.HANDSEED)
              FIELD_VALUE (HANDSEED) = dwg->header_vars.HANDSEED->absolute_ref;
          }

          
        #include "auxheader.spec"
        

        assert (!dat->bit);
        dwg->header.section[SECTION_AUXHEADER_R2000].size = dat->byte - dwg->header.section[SECTION_AUXHEADER_R2000].address;
      }
  }

  VERSION (R_2007)
  {
    LOG_ERROR (WE_CAN "We don't encode R2007 sections yet");
    dat->version = dwg->header.version = R_2010; 
    
  }

  
  SINCE (R_2004)
  {
    LOG_INFO ("\n");
    LOG_ERROR (WE_CAN "Writing R2004 sections not yet finished");

    memset (&sec_dat, 0, (SECTION_SYSTEM_MAP + 1) * sizeof (Bit_Chain));
    if (dwg->header.section_infohdr.num_desc && !dwg->header.section_info)
      dwg->header.section_info = (Dwg_Section_Info *)calloc ( dwg->header.section_infohdr.num_desc, sizeof (Dwg_Section_Info));
    LOG_TRACE ("\n#### r2004 File Header ####\n");
    if (dat->byte + 0x80 >= dat->size - 1)
      {
        dwg->header.num_sections = 28; 
        dwg->header.section = calloc (28, sizeof (Dwg_Section));
      }
    if (!dwg->header.section_info)
      {
        dwg->header.section_infohdr.num_desc = SECTION_SYSTEM_MAP + 1;
        dwg->header.section_info = calloc (SECTION_SYSTEM_MAP + 1, sizeof (Dwg_Section_Info));
      }
  }

  
  old_dat = dat;
  SINCE (R_2004)
  {
    bit_chain_init_dat (&sec_dat[SECTION_PREVIEW], dwg->thumbnail.size + 64, dat);
    str_dat = hdl_dat = dat = &sec_dat[SECTION_PREVIEW];
  }
  else {
    if (!dwg->header.thumbnail_address)
      dwg->header.thumbnail_address = dat->byte;
  }
  dat->bit = 0;
  LOG_TRACE ("\n=======> Thumbnail:       %4u\n", (unsigned)dat->byte);
  
  bit_write_sentinel (dat, dwg_sentinel (DWG_SENTINEL_THUMBNAIL_BEGIN));
  if (dwg->thumbnail.size == 0)
    {
      bit_write_RL (dat, 5); 
      LOG_TRACE ("Thumbnail size: 5 [RL]\n");
      bit_write_RC (dat, 0); 
      LOG_TRACE ("Thumbnail num_pictures: 0 [RC]\n");
    }
  else {
      bit_write_TF (dat, dwg->thumbnail.chain, dwg->thumbnail.size);
    }
  bit_write_sentinel (dat, dwg_sentinel (DWG_SENTINEL_THUMBNAIL_END));

  {
    BITCODE_RL bmpsize;
    dwg_bmp (dwg, &bmpsize);
    if (bmpsize > dwg->thumbnail.size)
      LOG_ERROR ("BMP size overflow: %i > %lu\n", bmpsize, dwg->thumbnail.size);
  }
  LOG_TRACE ("         Thumbnail (end): %4u\n", (unsigned)dat->byte);

  
  SINCE (R_2004)
  {
    sec_id = SECTION_HEADER;
    bit_chain_init_dat (&sec_dat[sec_id], sizeof (Dwg_Header) + 64, dat);
    str_dat = hdl_dat = dat = &sec_dat[sec_id];
  }
  assert (!dat->bit);
  LOG_INFO ("\n=======> Header Variables:   %4u\n", (unsigned)dat->byte);
  if (!dwg->header.section)
    {
      LOG_ERROR ("Empty header.section");
      return DWG_ERR_OUTOFMEM;
    }
  dwg->header.section[0].number = 0;
  dwg->header.section[0].address = dat->byte;
  bit_write_sentinel (dat, dwg_sentinel (DWG_SENTINEL_VARIABLE_BEGIN));

  pvzadr = dat->byte;      
  bit_write_RL (dat, 540); 
  
  
  dwg_encode_header_variables (dat, hdl_dat, dat, dwg);
  
  if (dat->from_version != orig_from_version)
    dat->from_version = orig_from_version;
  encode_patch_RLsize (dat, pvzadr);
  bit_write_CRC (dat, pvzadr, 0xC0C1);

  
  
  bit_write_sentinel (dat, dwg_sentinel (DWG_SENTINEL_VARIABLE_END));
  assert ((long)dat->byte > (long)dwg->header.section[0].address);
  dwg->header.section[0].size = (BITCODE_RL) ((long)dat->byte - (long)dwg->header.section[0].address);
  LOG_TRACE ("         Header Variables (end): %4u\n", (unsigned)dat->byte);

  
  SINCE (R_2004)
  {
    sec_id = SECTION_CLASSES;
    bit_chain_init_dat (&sec_dat[sec_id], (sizeof (Dwg_Class) * dwg->num_classes) + 32, dat);
    str_dat = hdl_dat = dat = &sec_dat[sec_id];
  }
  else sec_id = SECTION_CLASSES_R13;
  LOG_INFO ("\n=======> Classes: %4u (%d)\n", (unsigned)dat->byte, dwg->num_classes);
  if (dwg->num_classes > 5000)
    {
      LOG_ERROR ("Invalid dwg->num_classes %d", dwg->num_classes)
      dwg->num_classes = 0;
      error |= DWG_ERR_VALUEOUTOFBOUNDS | DWG_ERR_CLASSESNOTFOUND;
    }
  dwg->header.section[sec_id].number = 1;
  dwg->header.section[sec_id].address = dat->byte; 
  bit_write_sentinel (dat, dwg_sentinel (DWG_SENTINEL_CLASS_BEGIN));
  pvzadr = dat->byte;    
  bit_write_RL (dat, 0); 

  for (j = 0; j < dwg->num_classes; j++)
    {
      Dwg_Class *klass;
      klass = &dwg->dwg_class[j];
      bit_write_BS (dat, klass->number);
      bit_write_BS (dat, klass->proxyflag);
      SINCE (R_2007) {
        bit_write_T (dat, klass->appname);
        bit_write_T (dat, klass->cppname);
      } else {
        bit_write_TV (dat, klass->appname);
        bit_write_TV (dat, klass->cppname);
      }
      SINCE (R_2007) 
                     
      {
        if (klass->dxfname_u)
          bit_write_TU (dat, klass->dxfname_u);
        else bit_write_T (dat, klass->dxfname);
      }
      else  bit_write_TV (dat, klass->dxfname);
      bit_write_B (dat, klass->is_zombie);
      bit_write_BS (dat, klass->item_class_id);
      LOG_TRACE ("Class %d 0x%x %s\n" " %s \"%s\" %d 0x%x\n", klass->number, klass->proxyflag, klass->dxfname, klass->cppname, klass->appname, klass->is_zombie, klass->item_class_id)




      SINCE (R_2007)
      {
        if (dat->from_version < R_2007 && !klass->dwg_version) {
          
          klass->dwg_version = (BITCODE_BL)dwg->header.dwg_version;
          klass->maint_version = (BITCODE_BL)dwg->header.maint_version;
          
        }
        bit_write_BL (dat, klass->num_instances);
        bit_write_BL (dat, klass->dwg_version);
        bit_write_BL (dat, klass->maint_version);
        bit_write_BL (dat, klass->unknown_1);
        bit_write_BL (dat, klass->unknown_2);
        LOG_TRACE (" %d %d\n", (int)klass->num_instances, (int)klass->dwg_version);
      }
    }

  
  assert (pvzadr);
  encode_patch_RLsize (dat, pvzadr);
  bit_write_CRC (dat, pvzadr, 0xC0C1);
  bit_write_sentinel (dat, dwg_sentinel (DWG_SENTINEL_CLASS_END));
  dwg->header.section[SECTION_CLASSES_R13].size = dat->byte - dwg->header.section[SECTION_CLASSES_R13].address;
  LOG_TRACE ("       Classes (end): %4u\n", (unsigned)dat->byte);

  bit_write_RL (dat, 0x0DCA); 
  LOG_TRACE ("unknown: %04X [RL]\n", 0x0DCA);

  

  SINCE (R_2004)
  {
    sec_id = SECTION_OBJECTS;
    bit_chain_alloc (&sec_dat[sec_id]);
    str_dat = hdl_dat = dat = &sec_dat[sec_id];
    bit_chain_set_version (dat, old_dat);
  }
  LOG_INFO ("\n=======> Objects: %4u\n", (unsigned)dat->byte);
  pvzadr = dat->byte;

  
  LOG_TRACE ("num_objects: %i\n", dwg->num_objects);
  LOG_TRACE ("num_object_refs: %i\n", dwg->num_object_refs);
  omap = (Object_Map *)calloc (dwg->num_objects, sizeof (Object_Map));
  if (!omap)
    {
      LOG_ERROR ("Out of memory");
      return DWG_ERR_OUTOFMEM;
    }
  if (DWG_LOGLEVEL >= DWG_LOGLEVEL_HANDLE)
    {
      LOG_HANDLE ("\nSorting objects...\n");
      for (i = 0; i < dwg->num_objects; i++)
        fprintf (OUTPUT, "Object(%3i): %4lX / idx: %u\n", i, dwg->object[i].handle.value, dwg->object[i].index);
    }
  
  for (i = 0; i < dwg->num_objects; i++)
    {
      omap[i].index = i; 
      omap[i].handle = dwg->object[i].handle.value;
    }
  
  for (i = 0; i < dwg->num_objects; i++)
    {
      Object_Map tmap;
      j = i;
      tmap = omap[i];
      while (j > 0 && omap[j - 1].handle > tmap.handle)
        {
          omap[j] = omap[j - 1];
          j--;
        }
      omap[j] = tmap;
    }
  if (DWG_LOGLEVEL >= DWG_LOGLEVEL_HANDLE)
    {
      LOG_HANDLE ("\nSorted handles:\n");
      for (i = 0; i < dwg->num_objects; i++)
        fprintf (OUTPUT, "Handle(%3i): %4lX / idx: %u\n", i, omap[i].handle, omap[i].index);
    }

  
  for (i = 0; i < dwg->num_objects; i++)
    {
      Dwg_Object *obj;
      BITCODE_BL index = omap[i].index;
      unsigned long hdloff = omap[i].handle - (i ? omap[i - 1].handle : 0);
      int off = dat->byte - (i ? omap[i - 1].address : 0);
      unsigned long end_address;
      LOG_TRACE ("\n> Next object: " FORMAT_BL " Handleoff: %lX [UMC] Offset: %d [MC] @%lu\n" "==========================================\n", i, hdloff, off, dat->byte);


      omap[i].address = dat->byte;
      if (index > dwg->num_objects)
        {
          LOG_ERROR ("Invalid object map index " FORMAT_BL ", max " FORMAT_BL ". Skipping", index, dwg->num_objects)

          error |= DWG_ERR_VALUEOUTOFBOUNDS;
          continue;
        }
      obj = &dwg->object[index];
      

      PRE (R_2004)
        assert (dat->byte);

      if (!obj->parent)
        obj->parent = dwg;
      error |= dwg_encode_add_object (obj, dat, dat->byte);


      
      
      if (dwg->header.version >= R_1_2 && dwg->header.version < R_2004)
        {
          if (dat->size < 6 || dat->chain[0] != 'A' || dat->chain[1] != 'C')
            {
              LOG_ERROR ("Encode overwrite pos 0, invalid DWG magic");
              return DWG_ERR_INVALIDDWG;
            }
          assert (dat->size > 6);
          assert (dat->chain[0] == 'A');
          assert (dat->chain[1] == 'C');
        }

      end_address = omap[i].address + (unsigned long)obj->size; 
      if (end_address > dat->size)
        {
          dat->size = end_address;
          bit_chain_alloc (dat);
        }
    }

  if (DWG_LOGLEVEL >= DWG_LOGLEVEL_HANDLE)
    {
      LOG_HANDLE ("\nSorted objects:\n");
      for (i = 0; i < dwg->num_objects; i++)
        LOG_HANDLE ("Object(%d): %lX / Address: %ld / Idx: %d\n", i, omap[i].handle, omap[i].address, omap[i].index);
    }

  
  bit_write_RS (dat, 0);
  LOG_TRACE ("unknown crc?: %04X [RS]\n", 0);

  
  LOG_INFO ("\n=======> Object Map: %4u\n", (unsigned)dat->byte);
  SINCE (R_2004)
  {
    sec_id = SECTION_HANDLES;
    bit_chain_init_dat (&sec_dat[sec_id], (8 * dwg->num_objects) + 32, dat);
    str_dat = hdl_dat = dat = &sec_dat[sec_id];
  }
  else {
    sec_id = SECTION_HANDLES_R13;
    dwg->header.section[sec_id].number = 2;
    dwg->header.section[sec_id].address = dat->byte;
    pvzadr = dat->byte; 
    dat->byte += 2;
  }

  last_offset = 0;
  last_handle = 0;
  for (i = 0; i < dwg->num_objects; i++)
    {
      BITCODE_BL index;
      BITCODE_UMC handleoff;
      BITCODE_MC offset;

      index = omap[i].index;
      handleoff = omap[i].handle - last_handle;
      bit_write_UMC (dat, handleoff);
      LOG_HANDLE ("Handleoff(%3i): %4lX [UMC] (%4lX), ", index, handleoff, omap[i].handle)
      last_handle = omap[i].handle;

      offset = omap[i].address - last_offset;
      bit_write_MC (dat, offset);
      last_offset = omap[i].address;
      LOG_HANDLE ("Offset: %8d [MC] @%lu\n", (int)offset, last_offset);

      ckr_missing = 1;
      if (dat->byte - pvzadr > 2030) 
        {
          ckr_missing = 0;
          sec_size = dat->byte - pvzadr;
          assert (pvzadr);
          
          dat->chain[pvzadr] = sec_size >> 8;
          dat->chain[pvzadr + 1] = sec_size & 0xFF;
          LOG_TRACE ("Handles page size: %u [RS_LE] @%lu\n", sec_size, pvzadr);
          bit_write_CRC_LE (dat, pvzadr, 0xC0C1);

          pvzadr = dat->byte;
          dat->byte += 2;
          last_offset = 0;
          last_handle = 0;
        }
    }
  
  if (ckr_missing)
    {
      sec_size = dat->byte - pvzadr;

      PRE (R_2004)
        assert (pvzadr);

      if (pvzadr + 1 >= dat->size)
        bit_chain_alloc(dat);
      
      dat->chain[pvzadr] = sec_size >> 8;
      dat->chain[pvzadr + 1] = sec_size & 0xFF;
      LOG_TRACE ("Handles page size: %u [RS_LE] @%lu\n", sec_size, pvzadr);
      bit_write_CRC_LE (dat, pvzadr, 0xC0C1);
    }

  if (dwg->header.version >= R_1_2 && dwg->header.version < R_2004)
    {
      if (dat->size < 4 || dat->chain[0] != 'A' || dat->chain[1] != 'C')
        {
          LOG_ERROR ("Encode overwrite pos 0");
          return DWG_ERR_INVALIDDWG;
        }
      assert (dat->chain[0] == 'A');
      assert (dat->chain[1] == 'C');
    }
  PRE (R_2004)
    assert (dat->byte);

  pvzadr = dat->byte;
  bit_write_RS_LE (dat, 2); 
  LOG_TRACE ("Handles page size: %u [RS_LE] @%lu\n", 2, pvzadr);
  bit_write_CRC_LE (dat, pvzadr, 0xC0C1);

  
  dwg->header.section[sec_id].size = dat->byte - dwg->header.section[sec_id].address;
  free (omap);

  
  if (dwg->header.version >= R_13 && dwg->header.version < R_2004  && dwg->second_header.num_sections > 3)
    {
      struct _dwg_second_header *_obj = &dwg->second_header;
      Dwg_Object *obj = NULL;
      BITCODE_BL vcount;

      assert (dat->byte);
      if (!_obj->address)
        _obj->address = dat->byte;
      dwg->header.section[SECTION_2NDHEADER_R13].number = 3;
      dwg->header.section[SECTION_2NDHEADER_R13].address = _obj->address;
      dwg->header.section[SECTION_2NDHEADER_R13].size = _obj->size;
      LOG_INFO ("\n=======> Second Header: %4u\n", (unsigned)dat->byte);
      bit_write_sentinel (dat, dwg_sentinel (DWG_SENTINEL_SECOND_HEADER_BEGIN));

      pvzadr = dat->byte; 
                          
      LOG_TRACE ("pvzadr: %u\n", (unsigned)pvzadr);
      if (!_obj->size && !_obj->num_sections)
        {
          LOG_TRACE ("Use second_header defaults...\n");
          strcpy ((char *)&_obj->version[0], &version_codes[dwg->header.version][0]);
          memset (&_obj->version[7], 0, 4);
          _obj->version[11] = '\n';
          _obj->unknown_10 = 0x10;
          _obj->unknown_rc4[0] = 0x84;
          _obj->unknown_rc4[1] = 0x74;
          _obj->unknown_rc4[2] = 0x78;
          _obj->unknown_rc4[3] = 0x1;
          _obj->junk_r14_1 = 1957593121; 
          _obj->junk_r14_2 = 2559919056; 
          
        }
      
      if (dwg->header.version <= R_2000)
        {
          _obj->num_sections = dwg->header.num_sections;
          for (i = 0; i < _obj->num_sections; i++)
            {
              _obj->section[i].nr = dwg->header.section[i].number;
              _obj->section[i].address = dwg->header.section[i].address;
              _obj->section[i].size = dwg->header.section[i].size;
            }
        }
      FIELD_RL (size, 0);
      if (FIELD_VALUE (address) != (BITCODE_RL) (pvzadr - 16))
        {
          LOG_WARN ("second_header->address %u != %u", FIELD_VALUE (address), (unsigned)(pvzadr - 16));
          FIELD_VALUE (address) = pvzadr - 16;
          dwg->header.section[SECTION_2NDHEADER_R13].address = _obj->address;
          dwg->header.section[SECTION_2NDHEADER_R13].size = _obj->size;
        }
      FIELD_BL (address, 0);

      
      
      bit_write_TF (dat, (BITCODE_TF)_obj->version, 12);
      LOG_TRACE ("version: %s [TFF 12]\n", _obj->version)

      for (i = 0; i < 4; i++)
        FIELD_B (null_b[i], 0);
      FIELD_RC (unknown_10, 0); 
      for (i = 0; i < 4; i++)
        FIELD_RC (unknown_rc4[i], 0);

      UNTIL (R_2000)
      {
        FIELD_RC (num_sections, 0); 
        for (i = 0; i < FIELD_VALUE (num_sections); i++)
          {
            FIELD_RC (section[i].nr, 0);
            FIELD_BL (section[i].address, 0);
            FIELD_BLd (section[i].size, 0);
          }

        FIELD_BS (num_handlers, 0); 
        if (FIELD_VALUE (num_handlers) > 16)
          {
            LOG_ERROR ("Second header num_handlers > 16: %d\n", FIELD_VALUE (num_handlers));
            FIELD_VALUE (num_handlers) = 14;
          }
        for (i = 0; i < FIELD_VALUE (num_handlers); i++)
          {
            FIELD_RC (handlers[i].size, 0);
            FIELD_RC (handlers[i].nr, 0);
            FIELD_VECTOR (handlers[i].data, RC, handlers[i].size, 0);
          }

        _obj->size = encode_patch_RLsize (dat, pvzadr);
        bit_write_CRC (dat, pvzadr, 0xC0C1);

        VERSION (R_14)
        {
          FIELD_RL (junk_r14_1, 0);
          FIELD_RL (junk_r14_2, 0);
        }
      }
      bit_write_sentinel (dat, dwg_sentinel (DWG_SENTINEL_SECOND_HEADER_END));
      dwg->header.section[SECTION_2NDHEADER_R13].size = dat->byte - _obj->address;
    }
  else if (dwg->header.num_sections > SECTION_2NDHEADER_R13 && dwg->header.version < R_2004)
    {
      dwg->header.section[SECTION_2NDHEADER_R13].number = 3;
      dwg->header.section[SECTION_2NDHEADER_R13].address = 0;
      dwg->header.section[SECTION_2NDHEADER_R13].size = 0;
    }

  
  SINCE (R_2004)
  {
    sec_id = SECTION_TEMPLATE;
    bit_chain_init_dat (&sec_dat[sec_id], 16, dat);
    str_dat = hdl_dat = dat = &sec_dat[sec_id];
  }
  else sec_id = SECTION_MEASUREMENT_R13;

  if (dwg->header.version >= R_2004 || (int)dwg->header.num_sections > sec_id)
    {
      LOG_INFO ("\n=======> MEASUREMENT: %4u\n", (unsigned)dat->byte);
      dwg->header.section[sec_id].number = 4;
      dwg->header.section[sec_id].address = dat->byte;
      dwg->header.section[sec_id].size = 4;
      
      bit_write_RL_LE (dat, (BITCODE_RL)dwg->header_vars.MEASUREMENT ? 256 : 0);
      LOG_TRACE ("HEADER.MEASUREMENT: %d [RL_LE]\n", dwg->header_vars.MEASUREMENT);
    }

  
  dat->size = dat->byte;
  SINCE (R_2004)
  {
    Dwg_Section_Type type;
    Dwg_Object *obj = NULL;
    BITCODE_BL vcount, rcount3;
    size_t size;
    unsigned total_size = 0;

    
    for (type = SECTION_OBJFREESPACE; type < SECTION_SYSTEM_MAP; type++)
      {
        if (type != SECTION_OBJECTS && type != SECTION_PREVIEW)
          LOG_TRACE ("\n=== Section %s ===\n", dwg_section_name (dwg, type))
        switch (type)
          {
          case SECTION_HEADER: 
          case SECTION_AUXHEADER:
          case SECTION_CLASSES:
          case SECTION_HANDLES:
          case SECTION_TEMPLATE:
          case SECTION_PREVIEW:
          case SECTION_OBJECTS:
          case SECTION_UNKNOWN: 
          case SECTION_INFO:
          case SECTION_SYSTEM_MAP:
            break;
          case SECTION_OBJFREESPACE:
            {
              Dwg_ObjFreeSpace *_obj = &dwg->objfreespace;
              bit_chain_alloc (&sec_dat[type]);
              str_dat = hdl_dat = dat = &sec_dat[type];
              bit_chain_set_version (dat, old_dat);

              LOG_TRACE ("-size: %lu\n", dat->byte)
            }
            break;
          case SECTION_REVHISTORY:
            {
              Dwg_RevHistory *_obj = &dwg->revhistory;
              bit_chain_alloc (&sec_dat[type]);
              str_dat = hdl_dat = dat = &sec_dat[type];
              bit_chain_set_version (dat, old_dat);

              LOG_TRACE ("-size: %lu\n", dat->byte)
            }
            break;
          case SECTION_SUMMARYINFO:
            {
              Dwg_SummaryInfo *_obj = &dwg->summaryinfo;
              bit_chain_alloc (&sec_dat[type]);
              str_dat = hdl_dat = dat = &sec_dat[type];
              bit_chain_set_version (dat, old_dat);

              LOG_TRACE ("-size: %lu\n", dat->byte)
            }
            break;
          case SECTION_APPINFO:
            {
              Dwg_AppInfo *_obj = &dwg->appinfo;
              bit_chain_alloc (&sec_dat[type]);
              str_dat = hdl_dat = dat = &sec_dat[type];
              bit_chain_set_version (dat, old_dat);

              LOG_TRACE ("-size: %lu\n", dat->byte)
            }
            break;
          case SECTION_APPINFOHISTORY:
            {

              Dwg_AppInfoHistory *_obj = &dwg->appinfohistory;
              bit_chain_alloc (&sec_dat[type]);
              str_dat = hdl_dat = dat = &sec_dat[type];
              bit_chain_set_version (dat, old_dat);

              LOG_TRACE ("-size: %lu\n", dat->byte)

            }
            break;
          case SECTION_FILEDEPLIST:
            {
              Dwg_FileDepList *_obj = &dwg->filedeplist;
              bit_chain_alloc (&sec_dat[type]);
              str_dat = hdl_dat = dat = &sec_dat[type];
              bit_chain_set_version (dat, old_dat);

              LOG_TRACE ("-size: %lu\n", dat->byte)
            }
            break;
          case SECTION_SECURITY:
            {
              Dwg_Security *_obj = &dwg->security;
              bit_chain_alloc (&sec_dat[type]);
              str_dat = hdl_dat = dat = &sec_dat[type];
              bit_chain_set_version (dat, old_dat);

              LOG_TRACE ("-size: %lu\n", dat->byte)
            }
            break;
          case SECTION_SIGNATURE:
            {

              Dwg_Signature *_obj = &dwg->signature;
              bit_chain_alloc (&sec_dat[type]);
              str_dat = hdl_dat = dat = &sec_dat[type];
              bit_chain_set_version (dat, old_dat);
              {

              }
              LOG_TRACE ("-size: %lu\n", dat->byte)

            }
            break;
          case SECTION_ACDS:
            {

              Dwg_AcDs *_obj = &dwg->acds;
              bit_chain_alloc (&sec_dat[type]);
              str_dat = hdl_dat = dat = &sec_dat[type];
              bit_chain_set_version (dat, old_dat);
              {

              }
              LOG_TRACE ("-size: %lu\n", dat->byte)

            }
            break;
          case SECTION_VBAPROJECT: 
          default:
            break;
          }
      }
    
    dat = old_dat;

    
    
    
    {
      int ssize;
      int si, info_id;
      unsigned address;

      const Dwg_Section_Type section_map_order[] = {
        
        SECTION_UNKNOWN,  SECTION_SECURITY,       SECTION_FILEDEPLIST, SECTION_ACDS, SECTION_VBAPROJECT, SECTION_APPINFOHISTORY, SECTION_APPINFO,        SECTION_PREVIEW, SECTION_SUMMARYINFO, SECTION_REVHISTORY,     SECTION_OBJECTS,     SECTION_OBJFREESPACE, SECTION_TEMPLATE,       SECTION_HANDLES,     SECTION_CLASSES, SECTION_AUXHEADER,      SECTION_HEADER,      SECTION_SIGNATURE,  SECTION_INFO,           SECTION_SYSTEM_MAP };











      
      const Dwg_Section_Type stream_order[] = {
              SECTION_UNKNOWN,  SECTION_SUMMARYINFO, SECTION_PREVIEW,        SECTION_VBAPROJECT, SECTION_APPINFO,     SECTION_APPINFOHISTORY, SECTION_FILEDEPLIST, SECTION_ACDS,        SECTION_REVHISTORY,     SECTION_SECURITY, SECTION_OBJECTS,     SECTION_OBJFREESPACE,   SECTION_TEMPLATE, SECTION_HANDLES,     SECTION_CLASSES,        SECTION_AUXHEADER, SECTION_HEADER,  SECTION_SIGNATURE,  SECTION_INFO,        SECTION_SYSTEM_MAP };











      dwg->r2004_header.numsections = 0;
      dwg->r2004_header.numgaps = 0;

      
      sec_dat[SECTION_INFO].byte = 10 + (dwg->header.section_infohdr.num_desc * sizeof (Dwg_Section_Info));

      
      sec_dat[SECTION_SYSTEM_MAP].byte = (4 * 20 * sizeof (Dwg_Section));

      section_address = 0x100;
      
      
      
      LOG_TRACE ("\n=== Section map and info page sizes ===\n");
      for (si = 0, info_id = 0, type = 0; type <= SECTION_SYSTEM_MAP;
           type++, i++)
        {
          if (sec_dat[type].byte)
            {
              const unsigned int max_decomp_size = section_max_decomp_size (dwg, type);
              const char *name = dwg_section_name (dwg, type);
              Dwg_Section_Info *info;
              if (sec_dat[type].bit)
                {
                  LOG_WARN ("Unpadded section %d", type);
                  sec_dat[type].byte++;
                }
              ssize = (int)sec_dat[type].byte;
              sec_dat[type].size = ssize;
              if (info_id >= (int)dwg->header.section_infohdr.num_desc)
                {
                  dwg->header.section_infohdr.num_desc = info_id + 1;
                  dwg->header.section_info = realloc (dwg->header.section_info, (info_id + 1) * sizeof (Dwg_Section));

                }
              info = &dwg->header.section_info[info_id];
              info->fixedtype = type;
              info->type = type;
              info->unknown = 1;
              if (name && si && type < SECTION_INFO) 
                strcpy (info->name, name);
              else memset (info->name, 0, 64);
              info->size = ssize;
              info->max_decomp_size = max_decomp_size;
              info->encrypted = section_encrypted (dwg, type);
              info->compressed = 1 + section_compressed (dwg, type);

              info->compressed = 1;

              
              if ((unsigned)ssize <= max_decomp_size)
                info->num_sections = 1;
              else {
                  info->num_sections = (unsigned)ssize / max_decomp_size;
                  if ((unsigned)ssize % max_decomp_size)
                    info->num_sections++;
                }
              info->sections = calloc (info->num_sections, sizeof (Dwg_Section*));
              
              if (si + info->num_sections > dwg->header.num_sections)
                {
                  Dwg_Section *oldsecs = dwg->header.section;
                  dwg->header.num_sections = si + info->num_sections;
                  dwg->header.section = realloc (dwg->header.section, dwg->header.num_sections * sizeof (Dwg_Section));

                  if (dwg->header.section != oldsecs)
                    
                    section_info_rebuild (dwg, type);
                }
              {
                int ssi = 0;
                do {
                    Dwg_Section *sec = &dwg->header.section[si];
                    total_size += ssize;
                    sec->number = si + 1; 
                    sec->size = MIN (max_decomp_size, (unsigned)ssize);
                    sec->decomp_data_size = sec->size;
                    sec->type = type;
                    sec->compression_type = info->compressed;
                    info->sections[ssi] = sec;
                    LOG_TRACE ("section[%d] %s[%d].sections[%d]: number=%d " "size=%d\n", si, dwg_section_name (dwg, type), info_id, ssi, sec->number, (int)sec->size);


                    ssize -= max_decomp_size;
                    ssi++; 
                    si++;  
                  }
                while (ssize > (int)max_decomp_size); 
              }
              info_id++;
            }
          else LOG_TRACE ("section_info %s is empty, skipped. size=0\n", dwg_section_name (dwg, type));

        }
      dwg->r2004_header.numsections = si;
      
      if ((unsigned)si > dwg->header.num_sections) 
        {
          Dwg_Section *oldsecs = dwg->header.section;
          dwg->header.num_sections = si;
          dwg->header.section = realloc (dwg->header.section, si * sizeof (Dwg_Section));
          if (dwg->header.section != oldsecs)
            section_info_rebuild (dwg, SECTION_SYSTEM_MAP);
        }
      dwg->r2004_header.section_info_id = dwg->r2004_header.numsections + 1; 
      dwg->r2004_header.section_map_id = dwg->r2004_header.numsections + 2;
      dwg->r2004_header.section_array_size = dwg->r2004_header.numsections + 2;
      dwg->r2004_header.last_section_id = dwg->r2004_header.section_map_id;
      dwg->header.section[si - 2].number = dwg->r2004_header.section_info_id; 
      dwg->header.section[si - 1].number = dwg->r2004_header.section_map_id;

      LOG_TRACE ("\n=== Section Info %d in map order ===\n", dwg->r2004_header.section_info_id);
      
      sec_id = SECTION_INFO;
      sec_dat[sec_id].size = sec_dat[sec_id].byte;
      bit_chain_alloc (&sec_dat[sec_id]);
      dat = &sec_dat[sec_id];
      bit_chain_set_version (dat, old_dat);
      bit_set_position (dat, 0); 

      {
        Dwg_Section_InfoHdr *_obj = &dwg->header.section_infohdr;
        Dwg_Section *sec = &dwg->header.section[si - 2];
        Dwg_Section_Info *info = find_section_info_type (dwg, sec_id);
        
        sec->number = dwg->r2004_header.section_info_id;
        sec->size = MIN (0x7400, sec->size);
        sec->decomp_data_size = sec->size;
        sec->type = type;
        if (info)
          {
            sec->compression_type = info->compressed;
            
            info->sections[0] = sec;
          }
        if (_obj->compressed == 2 && sec->size <= MIN_COMPRESSED_SECTION)
          _obj->compressed = 1;

        _obj->compressed = 1;

        LOG_HANDLE ("InfoHdr @%lu.0\n", dat->byte);
        FIELD_RL (num_desc, 0);
        FIELD_RL (compressed, 0);
        FIELD_RL (max_size, 0);
        FIELD_RL (encrypted, 0);
        FIELD_RL (num_desc2, 0);
      }
      for (i = 0; i < ARRAY_SIZE (section_map_order); i++)
        {
          Dwg_Section_Info *_obj;
          type = section_map_order[i];
          _obj = find_section_info_type (dwg, type);
          if (_obj)
            {
              assert (type == _obj->fixedtype);
              LOG_TRACE ("\nSection_Info %s [%d]\n", dwg_section_name (dwg, type), i);
              FIELD_RLLu (size, 0);
              FIELD_RL (num_sections, 0);
              FIELD_RL (max_decomp_size, 0);
              FIELD_RL (unknown, 0);
              FIELD_RL (compressed, 0);
              FIELD_RL (type, 0);
              FIELD_RL (encrypted, 0);
              bit_write_TF (dat, (unsigned char *)_obj->name, 64);
              LOG_TRACE ("name: %s\n", *_obj->name ? _obj->name : "");
            }
        }

      LOG_TRACE ("\n=== Section System Map %d in map order ===\n", dwg->r2004_header.section_map_id);
      sec_id = type = SECTION_SYSTEM_MAP;
      {
        
        Dwg_Section *sec = &dwg->header.section[si - 1];
        Dwg_Section_Info *info = find_section_info_type (dwg, type);
        if (!info || !info->sections)
          {
            LOG_ERROR ("SECTION_SYSTEM_MAP not found");
            return DWG_ERR_SECTIONNOTFOUND;
          }

        sec_dat[sec_id].size = sec_dat[sec_id].byte;
        bit_chain_alloc (&sec_dat[sec_id]);
        str_dat = hdl_dat = dat = &sec_dat[sec_id];
        bit_chain_set_version (dat, old_dat);
        bit_set_position (dat, 0); 

        
        sec->number = dwg->r2004_header.section_map_id;
        sec->size = MIN (0x7400, sec->size);
        sec->decomp_data_size = sec->size;
        sec->type = type;
        sec->compression_type = info->compressed;
        
        info->sections[0] = sec;
      }
      
      address = 0x100;
      for (i = 0; i < dwg->header.num_sections; i++)
        {
          Dwg_Section *_obj = &dwg->header.section[i];

          FIELD_RL (number, 0);
          FIELD_RL (size, 0);
          _obj->address = address;
          FIELD_RLL (address, 0);
          address += _obj->size;
          if (_obj->number < 0) 
            {
              FIELD_RL (parent, 0);
              FIELD_RL (left, 0);
              FIELD_RL (right, 0);
              FIELD_RL (x00, 0);
            }
        }
      dwg->r2004_header.decomp_data_size = dat->byte; 
      LOG_TRACE ("-size: %lu\n", dat->byte);

      dat = old_dat;

      if (dwg->header.version >= R_1_2)
        {
          if (dat->size < 4 || dat->chain[0] != 'A' || dat->chain[1] != 'C')
            {
              LOG_ERROR ("Encode overwrite pos 0");
              return DWG_ERR_INVALIDDWG;
            }
          assert (dat->chain[0] == 'A');
          assert (dat->chain[1] == 'C');
          assert (dat->byte <= 0x100);
        }


      
      LOG_TRACE ("\n=== Write sections in stream order ===\n");
      size = total_size + (8 * ((dwg->r2004_header.numsections + 2) * 24));
      dat->byte = section_address;
      if (dat->byte + size >= dat->size)
        {
          dat->size = dat->byte + size;
          bit_chain_alloc (dat);
        }
      LOG_HANDLE ("@%lu.0\n", dat->byte);
      for (i = 0; i < ARRAY_SIZE (stream_order); i++)
        {
          Dwg_Section_Info *info;
          type = stream_order[i];
          info = find_section_info_type (dwg, type);
          if (info)
            {
              LOG_TRACE ("Write %s pages @%lu (%u/%lu)\n", dwg_section_name (dwg, type), dat->byte, info->num_sections, sec_dat[type].size);

              for (unsigned k = 0; k < info->num_sections; k++)
                {
                  Dwg_Section *sec = info->sections[k];
                  if (!sec)
                    {
                      LOG_ERROR ("empty info->sections[%u]", k);
                      continue;
                    }
                  if (!sec_dat[type].chain)
                    {
                      LOG_ERROR ("empty %s.chain", dwg_section_name (dwg, type));
                      continue;
                    }

                  if (info->fixedtype < SECTION_INFO)
                    assert (info->fixedtype == sec->type);

                  if (info->fixedtype == SECTION_SUMMARYINFO)
                    dwg->header.summaryinfo_address = dat->byte;
                  else if (info->fixedtype == SECTION_PREVIEW)
                    dwg->header.thumbnail_address = dat->byte;
                  else if (info->fixedtype == SECTION_VBAPROJECT)
                    dwg->header.vbaproj_address = dat->byte;
                  else if (info->fixedtype == SECTION_SYSTEM_MAP)
                    {
                      dwg->r2004_header.section_map_address = dat->byte - 0x100;
                      dwg->r2004_header.last_section_address = dat->byte + sec->size - 0x100;
                      dwg->r2004_header.second_header_address = 0; 
                    }
                  sec->address = dat->byte;

                  if (info->encrypted)
                    {
                      BITCODE_RC *decr = calloc (sec->size, 1);
                      LOG_HANDLE ("Encrypt %s (%u/%d)\n", info->name, k, sec->size);
                      decrypt_R2004_header (decr, sec_dat[type].chain, sec->size);
                      free (sec_dat[type].chain);
                      sec_dat[type].chain = decr;
                    }
                  assert (sec->size <= MIN_COMPRESSED_SECTION ? info->compressed == 1 : 1);
                  if (info->compressed == 2)
                    {
                      LOG_HANDLE ("Compress %s (%u/%d)\n", info->name, k, sec->size);
                      compress_R2004_section (dat, sec_dat[type].chain, sec->size, &sec->comp_data_size);
                      LOG_TRACE ("sec->comp_data_size: " FORMAT_RL "\n", sec->comp_data_size);
                    }
                  else {
                      LOG_HANDLE ("Copy uncompressed %s (%u/%d)\n", info->name, k, sec->size);
                      copy_R2004_section (dat, sec_dat[type].chain, sec->size, &sec->comp_data_size);
                    }
                }
              bit_chain_free (&sec_dat[type]);
            }
        }
    }

    {
      Dwg_R2004_Header *_obj = &dwg->r2004_header;
      Bit_Chain file_dat = { NULL, sizeof (Dwg_R2004_Header), 0UL, 0, 0, 0, 0, NULL };
      Bit_Chain *orig_dat = dat;
      
      const unsigned char enc_file_ID_string[] = { '\x68', '\x40', '\xF8', '\xF7', '\x92', '\x2A', '\xB5', '\xEF', '\x18', '\xDD', '\x0B', '\xF1' };

      uint32_t checksum;

      file_dat.chain = calloc (1, sizeof (Dwg_R2004_Header));
      dat = &file_dat;
      LOG_TRACE ("\nSection R2004_Header @0x100\n");

      checksum = _obj->crc32;
      LOG_HANDLE ("old crc32: 0x%x\n", _obj->crc32);
      _obj->crc32 = 0;
      
      _obj->crc32 = bit_calc_CRC32 (0, (unsigned char *)&dwg->r2004_header, 0x6c);
      LOG_HANDLE ("calc crc32: 0x%x\n", _obj->crc32);

      
      #include "r2004_file_header.spec"
      

      
      dat = orig_dat;
      decrypt_R2004_header (&dat->chain[0x80], file_dat.chain, sizeof (Dwg_R2004_Header));
      bit_chain_free (&file_dat);
      LOG_HANDLE ("encrypted R2004_Header:\n");
      LOG_TF (HANDLE, &dat->chain[0x80], (int)sizeof (Dwg_R2004_Header));
      if (memcmp (&dat->chain[0x80], enc_file_ID_string, sizeof (enc_file_ID_string)))
        {
          LOG_ERROR ("r2004_file_header encryption error");
          return error | DWG_ERR_INVALIDDWG;
        }
    } 
  } 

  assert (!dat->bit);
  dat->size = dat->byte;
  LOG_INFO ("\nFinal DWG size: %u\n", (unsigned)dat->size);

  UNTIL (R_2000)
  {
    
    assert (section_address);
    dat->byte = section_address;
    dat->bit = 0;
    LOG_INFO ("\n=======> section addresses: %4u\n", (unsigned)dat->byte);
    for (j = 0; j < dwg->header.num_sections; j++)
      {
        LOG_TRACE ("section[%u].number: %4d [RC] %s\n", j, (int)dwg->header.section[j].number, j < 6 ? dwg_section_name (dwg, j) : "");

        LOG_TRACE ("section[%u].offset: %4u [RL]\n", j, (unsigned)dwg->header.section[j].address);
        LOG_TRACE ("section[%u].size:   %4u [RL]\n", j, (int)dwg->header.section[j].size);
        if ((unsigned long)dwg->header.section[j].address + dwg->header.section[j].size > dat->size)

          {
            if (is_section_r13_critical (j))
              {
                LOG_ERROR ("section[%u] %s address or size overflow", j, j < 6 ? dwg_section_name (dwg, j) : "");
                return DWG_ERR_INVALIDDWG;
              }
            else {
                LOG_WARN ("section[%u] %s address or size overflow, skipped", j, j < 6 ? dwg_section_name (dwg, j) : "");
                dwg->header.section[j].address = 0;
                dwg->header.section[j].size = 0;
              }
          }
        bit_write_RC (dat, dwg->header.section[j].number);
        bit_write_RL (dat, dwg->header.section[j].address);
        bit_write_RL (dat, dwg->header.section[j].size);
      }

    
    bit_write_CRC (dat, 0, 0);
    dat->byte -= 2;
    ckr = bit_read_CRC (dat);
    dat->byte -= 2;
    
    switch (dwg->header.num_sections)
      {
      case 3:
        ckr ^= 0xA598;
        break;
      case 4:
        ckr ^= 0x8101;
        break;
      case 5:
        ckr ^= 0x3CC4;
        break;
      case 6:
        ckr ^= 0x8461;
        break;
      default:
        break;
      }
    bit_write_RS (dat, ckr);
    LOG_TRACE ("crc: %04X (from 0)\n", ckr);
  }

  return 0;
  }
  AFL_GCC_POP  static int encode_preR13 (Dwg_Data * restrict dwg, Bit_Chain * restrict dat)

  {
    return DWG_ERR_NOTYETSUPPORTED;
  }




static const char * dxf_encode_alias (char *restrict name)
{
  if (strEQc (name, "DICTIONARYWDFLT"))
    return "ACDBDICTIONARYWDFLT";
  else if (strEQc (name, "SECTIONVIEWSTYLE"))
    return "ACDBSECTIONVIEWSTYLE";
  else if (strEQc (name, "PLACEHOLDER"))
    return "ACDBPLACEHOLDER";
  else if (strEQc (name, "DETAILVIEWSTYLE"))
    return "ACDBDETAILVIEWSTYLE";
  else if (strEQc (name, "ASSOCPERSSUBENTMANAGER"))
    return "ACDBASSOCPERSSUBENTMANAGER";
  else if (strEQc (name, "EVALUATION_GRAPH"))
    return "ACAD_EVALUATION_GRAPH";
  else if (strEQc (name, "ASSOCACTION"))
    return "ACDBASSOCACTION";
  else if (strEQc (name, "ASSOCALIGNEDDIMACTIONBODY"))
    return "ACDBASSOCALIGNEDDIMACTIONBODY";
  else if (strEQc (name, "ASSOCOSNAPPOINTREFACTIONPARAM"))
    return "ACDBASSOCOSNAPPOINTREFACTIONPARAM";
  else if (strEQc (name, "ASSOCVERTEXACTIONPARAM"))
    return "ACDBASSOCVERTEXACTIONPARAM";
  else if (strEQc (name, "ASSOCGEOMDEPENDENCY"))
    return "ACDBASSOCGEOMDEPENDENCY";
  else if (strEQc (name, "ASSOCDEPENDENCY"))
    return "ACDBASSOCDEPENDENCY";
  else if (strEQc (name, "TABLE"))
    return "ACAD_TABLE";
  else return NULL;
}

Dwg_Class * dwg_encode_get_class (Dwg_Data *dwg, Dwg_Object *obj)
{
  int i;
  Dwg_Class *klass = NULL;
  if (!dwg || !dwg->dwg_class)
    return NULL;
  
  if (obj->dxfname) 
    {
      int invalid_klass = 0;
      for (i = 0; i < dwg->num_classes; i++)
        {
          klass = &dwg->dwg_class[i];
          if (!klass->dxfname)
            {
              invalid_klass++;
              continue;
            }
          if (strEQ (obj->dxfname, klass->dxfname))
            {
              obj->type = 500 + i;
              break;
            }
          else {
              
              const char *alias = dxf_encode_alias (obj->dxfname);
              if (alias && klass->dxfname && strEQ (alias, klass->dxfname))
                {
                  
                  
                  if (dwg->opts & DWG_OPTS_IN)
                    obj->dxfname = strdup ((char *)alias);
                  else obj->dxfname = (char *)alias;
                  obj->type = 500 + i;
                  break;
                }
              klass = NULL; 

              if (invalid_klass > 2 && !(dwg->opts & DWG_OPTS_IN))
                goto search_by_index;
            }
        }
    }
  else  {
    search_by_index:
      i = obj->type - 500;
      if (i < 0 || i >= (int)dwg->num_classes)
        {
          LOG_WARN ("Invalid object type %d, only %u classes", obj->type, dwg->num_classes);
          return NULL;
        }

      klass = &dwg->dwg_class[i];
      if (!klass->dxfname)
        return NULL;
      obj->dxfname = klass->dxfname;
    }
  return klass;
}


static int dwg_encode_variable_type (Dwg_Data *restrict dwg, Bit_Chain *restrict dat, Dwg_Object *restrict obj)

{
  
  int is_entity;
  Dwg_Class *klass = dwg_encode_get_class (dwg, obj);

  if (!klass)
    return DWG_ERR_INVALIDTYPE;
  is_entity = dwg_class_is_entity (klass);
  
  if ((is_entity && obj->supertype == DWG_SUPERTYPE_OBJECT)
      || (!is_entity && obj->supertype == DWG_SUPERTYPE_ENTITY))
    {
      if (is_dwg_object (obj->name))
        {
          if (is_entity)
            {
              LOG_INFO ("Fixup Class %s item_class_id to %s for %s\n", klass->dxfname, "OBJECT", obj->name);
              klass->item_class_id = 0x1f2;
              if (!klass->dxfname || strNE (klass->dxfname, obj->dxfname))
                {
                  free (klass->dxfname);
                  klass->dxfname = strdup (obj->dxfname);
                }
              is_entity = 0;
            }
          else {
              LOG_INFO ("Fixup %s.supertype to %s\n", obj->name, "OBJECT");
              obj->supertype = DWG_SUPERTYPE_OBJECT;
            }
        }
      else if (is_dwg_entity (obj->name))
        {
          if (!is_entity)
            {
              LOG_INFO ("Fixup Class %s item_class_id to %s for %s\n", klass->dxfname, "ENTITY", obj->name);
              klass->item_class_id = 0x1f3;
              if (!klass->dxfname || strNE (klass->dxfname, obj->dxfname))
                {
                  free (klass->dxfname);
                  klass->dxfname = strdup (obj->dxfname);
                }
              is_entity = 1;
            }
          else {
              LOG_INFO ("Fixup %s.supertype to %s", obj->name, "ENTITY");
              obj->supertype = DWG_SUPERTYPE_ENTITY;
            }
        }
      else {
          LOG_ERROR ("Illegal Class %s is_%s item_class_id for %s", klass->dxfname, is_entity ? "entity" : "object", obj->name);

          return DWG_ERR_INVALIDTYPE;
        }
    }

  if (dwg->opts & DWG_OPTS_IN) 
    {
      unsigned long pos = bit_position (dat);

      
      if (is_type_unstable (obj->fixedtype) && (obj->fixedtype == DWG_TYPE_WIPEOUT || obj->fixedtype == DWG_TYPE_TABLEGEOMETRY))

        {
          LOG_WARN ("Skip broken %s", obj->name); 
          obj->type = is_entity ? DWG_TYPE_UNKNOWN_ENT : DWG_TYPE_PLACEHOLDER;
          klass->dxfname = strdup (is_entity ? "UNKNOWN_ENT" : "UNKNOWN_OBJ");
        }
      dat->byte = obj->address;
      dat->bit = 0;
      LOG_TRACE ("fixup Type: %d [BS] @%lu\n", obj->type, obj->address);
      bit_write_BS (dat, obj->type); 
      bit_set_position (dat, pos);
    }

  
  #include "classes.inc"
  

  LOG_WARN ("Unknown Class %s %d %s (0x%x%s)", is_entity ? "entity" : "object", klass->number, klass->dxfname, klass->proxyflag, klass->is_zombie ? "is_zombie" : "")





  return DWG_ERR_UNHANDLEDCLASS;
}

int dwg_encode_add_object (Dwg_Object *restrict obj, Bit_Chain *restrict dat, unsigned long address)

{
  int error = 0;
  
  unsigned long end_address = address + obj->size;
  Dwg_Data *dwg = obj->parent;

  
  PRE (R_2004)
    {
      if (!address)
        return DWG_ERR_INVALIDDWG;
      assert (address);
    }
  dat->byte = address;
  dat->bit = 0;

  LOG_INFO ("Object number: %lu", (unsigned long)obj->index);
  if (obj->size > 0x100000)
    {
      LOG_ERROR ("Object size %u overflow", obj->size);
      return DWG_ERR_VALUEOUTOFBOUNDS;
    }
  while (dat->byte + obj->size >= dat->size)
    bit_chain_alloc (dat);

  
  
  
  bit_write_MS (dat, obj->size);
  obj->address = dat->byte;
  PRE (R_2010)
  {
    bit_write_BS (dat, obj->type);
    LOG_INFO (", Size: %d [MS], Type: %d [BS], Address: %lu\n", obj->size, obj->type, obj->address)
  }
  LATER_VERSIONS {
    if (!obj->handlestream_size && obj->bitsize)
      obj->handlestream_size = obj->size * 8 - obj->bitsize;
    bit_write_UMC (dat, obj->handlestream_size);
    obj->address = dat->byte;
    bit_write_BOT (dat, obj->type);
    LOG_INFO (", Size: %d [MS], Hdlsize: %lu [UMC], Type: %d [BOT], Address: %lu\n", obj->size, (unsigned long)obj->handlestream_size, obj->type, obj->address)
  }

  
  switch (obj->type)
    {
    case DWG_TYPE_TEXT:
      error = dwg_encode_TEXT (dat, obj);
      break;
    case DWG_TYPE_ATTRIB:
      error = dwg_encode_ATTRIB (dat, obj);
      break;
    case DWG_TYPE_ATTDEF:
      error = dwg_encode_ATTDEF (dat, obj);
      break;
    case DWG_TYPE_BLOCK:
      error = dwg_encode_BLOCK (dat, obj);
      break;
    case DWG_TYPE_ENDBLK:
      error = dwg_encode_ENDBLK (dat, obj);
      break;
    case DWG_TYPE_SEQEND:
      error = dwg_encode_SEQEND (dat, obj);
      break;
    case DWG_TYPE_INSERT:
      error = dwg_encode_INSERT (dat, obj);
      break;
    case DWG_TYPE_MINSERT:
      error = dwg_encode_MINSERT (dat, obj);
      break;
    case DWG_TYPE_VERTEX_2D:
      error = dwg_encode_VERTEX_2D (dat, obj);
      break;
    case DWG_TYPE_VERTEX_3D:
      error = dwg_encode_VERTEX_3D (dat, obj);
      break;
    case DWG_TYPE_VERTEX_MESH:
      error = dwg_encode_VERTEX_MESH (dat, obj);
      break;
    case DWG_TYPE_VERTEX_PFACE:
      error = dwg_encode_VERTEX_PFACE (dat, obj);
      break;
    case DWG_TYPE_VERTEX_PFACE_FACE:
      error = dwg_encode_VERTEX_PFACE_FACE (dat, obj);
      break;
    case DWG_TYPE_POLYLINE_2D:
      error = dwg_encode_POLYLINE_2D (dat, obj);
      break;
    case DWG_TYPE_POLYLINE_3D:
      error = dwg_encode_POLYLINE_3D (dat, obj);
      break;
    case DWG_TYPE_ARC:
      error = dwg_encode_ARC (dat, obj);
      break;
    case DWG_TYPE_CIRCLE:
      error = dwg_encode_CIRCLE (dat, obj);
      break;
    case DWG_TYPE_LINE:
      error = dwg_encode_LINE (dat, obj);
      break;
    case DWG_TYPE_DIMENSION_ORDINATE:
      error = dwg_encode_DIMENSION_ORDINATE (dat, obj);
      break;
    case DWG_TYPE_DIMENSION_LINEAR:
      error = dwg_encode_DIMENSION_LINEAR (dat, obj);
      break;
    case DWG_TYPE_DIMENSION_ALIGNED:
      error = dwg_encode_DIMENSION_ALIGNED (dat, obj);
      break;
    case DWG_TYPE_DIMENSION_ANG3PT:
      error = dwg_encode_DIMENSION_ANG3PT (dat, obj);
      break;
    case DWG_TYPE_DIMENSION_ANG2LN:
      error = dwg_encode_DIMENSION_ANG2LN (dat, obj);
      break;
    case DWG_TYPE_DIMENSION_RADIUS:
      error = dwg_encode_DIMENSION_RADIUS (dat, obj);
      break;
    case DWG_TYPE_DIMENSION_DIAMETER:
      error = dwg_encode_DIMENSION_DIAMETER (dat, obj);
      break;
    case DWG_TYPE_POINT:
      error = dwg_encode_POINT (dat, obj);
      break;
    case DWG_TYPE__3DFACE:
      error = dwg_encode__3DFACE (dat, obj);
      break;
    case DWG_TYPE_POLYLINE_PFACE:
      error = dwg_encode_POLYLINE_PFACE (dat, obj);
      break;
    case DWG_TYPE_POLYLINE_MESH:
      error = dwg_encode_POLYLINE_MESH (dat, obj);
      break;
    case DWG_TYPE_SOLID:
      error = dwg_encode_SOLID (dat, obj);
      break;
    case DWG_TYPE_TRACE:
      error = dwg_encode_TRACE (dat, obj);
      break;
    case DWG_TYPE_SHAPE:
      error = dwg_encode_SHAPE (dat, obj);
      break;
    case DWG_TYPE_VIEWPORT:
      error = dwg_encode_VIEWPORT (dat, obj);
      break;
    case DWG_TYPE_ELLIPSE:
      error = dwg_encode_ELLIPSE (dat, obj);
      break;
    case DWG_TYPE_SPLINE:
      error = dwg_encode_SPLINE (dat, obj);
      break;
    case DWG_TYPE_REGION:
      error = dwg_encode_REGION (dat, obj);
      break;
    case DWG_TYPE__3DSOLID:
      error = dwg_encode__3DSOLID (dat, obj);
      break;
    case DWG_TYPE_BODY:
      error = dwg_encode_BODY (dat, obj);
      break;
    case DWG_TYPE_RAY:
      error = dwg_encode_RAY (dat, obj);
      break;
    case DWG_TYPE_XLINE:
      error = dwg_encode_XLINE (dat, obj);
      break;
    case DWG_TYPE_DICTIONARY:
      error = dwg_encode_DICTIONARY (dat, obj);
      break;
    case DWG_TYPE_MTEXT:
      error = dwg_encode_MTEXT (dat, obj);
      break;
    case DWG_TYPE_LEADER:
      error = dwg_encode_LEADER (dat, obj);
      break;
    case DWG_TYPE_TOLERANCE:
      error = dwg_encode_TOLERANCE (dat, obj);
      break;
    case DWG_TYPE_MLINE:
      error = dwg_encode_MLINE (dat, obj);
      break;
    case DWG_TYPE_BLOCK_CONTROL:
      error = dwg_encode_BLOCK_CONTROL (dat, obj);
      break;
    case DWG_TYPE_BLOCK_HEADER:
      error = dwg_encode_BLOCK_HEADER (dat, obj);
      break;
    case DWG_TYPE_LAYER_CONTROL:
      error = dwg_encode_LAYER_CONTROL (dat, obj);
      break;
    case DWG_TYPE_LAYER:
      error = dwg_encode_LAYER (dat, obj);
      break;
    case DWG_TYPE_STYLE_CONTROL:
      error = dwg_encode_STYLE_CONTROL (dat, obj);
      break;
    case DWG_TYPE_STYLE:
      error = dwg_encode_STYLE (dat, obj);
      break;
    case DWG_TYPE_LTYPE_CONTROL:
      error = dwg_encode_LTYPE_CONTROL (dat, obj);
      break;
    case DWG_TYPE_LTYPE:
      error = dwg_encode_LTYPE (dat, obj);
      break;
    case DWG_TYPE_VIEW_CONTROL:
      error = dwg_encode_VIEW_CONTROL (dat, obj);
      break;
    case DWG_TYPE_VIEW:
      error = dwg_encode_VIEW (dat, obj);
      break;
    case DWG_TYPE_UCS_CONTROL:
      error = dwg_encode_UCS_CONTROL (dat, obj);
      break;
    case DWG_TYPE_UCS:
      error = dwg_encode_UCS (dat, obj);
      break;
    case DWG_TYPE_VPORT_CONTROL:
      error = dwg_encode_VPORT_CONTROL (dat, obj);
      break;
    case DWG_TYPE_VPORT:
      error = dwg_encode_VPORT (dat, obj);
      break;
    case DWG_TYPE_APPID_CONTROL:
      error = dwg_encode_APPID_CONTROL (dat, obj);
      break;
    case DWG_TYPE_APPID:
      error = dwg_encode_APPID (dat, obj);
      break;
    case DWG_TYPE_DIMSTYLE_CONTROL:
      error = dwg_encode_DIMSTYLE_CONTROL (dat, obj);
      break;
    case DWG_TYPE_DIMSTYLE:
      error = dwg_encode_DIMSTYLE (dat, obj);
      break;
    case DWG_TYPE_VX_CONTROL:
      error = dwg_encode_VX_CONTROL (dat, obj);
      break;
    case DWG_TYPE_VX_TABLE_RECORD:
      error = dwg_encode_VX_TABLE_RECORD (dat, obj);
      break;
    case DWG_TYPE_GROUP:
      error = dwg_encode_GROUP (dat, obj);
      break;
    case DWG_TYPE_MLINESTYLE:
      error = dwg_encode_MLINESTYLE (dat, obj);
      (void)dwg_encode_get_class (dwg, obj);
      break;
    case DWG_TYPE_OLE2FRAME:
      error = dwg_encode_OLE2FRAME (dat, obj);
      (void)dwg_encode_get_class (dwg, obj);
      break;
    case DWG_TYPE_DUMMY:
      error = dwg_encode_DUMMY (dat, obj);
      break;
    case DWG_TYPE_LONG_TRANSACTION:
      error = dwg_encode_LONG_TRANSACTION (dat, obj);
      break;
    case DWG_TYPE_LWPOLYLINE:
      error = dwg_encode_LWPOLYLINE (dat, obj);
      (void)dwg_encode_get_class (dwg, obj);
      break;
    case DWG_TYPE_HATCH:
      error = dwg_encode_HATCH (dat, obj);
      (void)dwg_encode_get_class (dwg, obj);
      break;
    case DWG_TYPE_XRECORD:
      error = dwg_encode_XRECORD (dat, obj);
      (void)dwg_encode_get_class (dwg, obj);
      break;
    case DWG_TYPE_PLACEHOLDER:
      error = dwg_encode_PLACEHOLDER (dat, obj);
      (void)dwg_encode_get_class (dwg, obj);
      break;
    case DWG_TYPE_OLEFRAME:
      error = dwg_encode_OLEFRAME (dat, obj);
      (void)dwg_encode_get_class (dwg, obj);
      break;
    case DWG_TYPE_VBA_PROJECT:
      
      error = dwg_encode_VBA_PROJECT (dat, obj);
      (void)dwg_encode_get_class (dwg, obj);
      break;
    case DWG_TYPE_LAYOUT:
      error |= dwg_encode_LAYOUT (dat, obj);
      (void)dwg_encode_get_class (dwg, obj);
      break;
    case DWG_TYPE_PROXY_ENTITY:
      error = dwg_encode_PROXY_ENTITY (dat, obj);
      break;
    case DWG_TYPE_PROXY_OBJECT:
      error = dwg_encode_PROXY_OBJECT (dat, obj);
      break;
    default:
      if (dwg && obj->type == dwg->layout_type && obj->fixedtype == DWG_TYPE_LAYOUT)
        {
          error = dwg_encode_LAYOUT (dat, obj);
          (void)dwg_encode_get_class (dwg, obj);
        }
      else if (dwg != NULL && (error = dwg_encode_variable_type (dwg, dat, obj))
                      & DWG_ERR_UNHANDLEDCLASS)
        {
          int is_entity;
          Dwg_Class *klass = dwg_encode_get_class (dwg, obj);
          if (klass)
            is_entity = klass->item_class_id == 0x1f2 && obj->supertype == DWG_SUPERTYPE_ENTITY;
          else is_entity = obj->supertype == DWG_SUPERTYPE_ENTITY;

          assert (address);
          dat->byte = address; 
          dat->bit = 0;

          bit_write_MS (dat, obj->size); 
          if (dat->version >= R_2010)
            {
              bit_write_UMC (dat, obj->handlestream_size);
              bit_write_BOT (dat, obj->type);
            }
          else bit_write_BS (dat, obj->type);

          
          if (is_entity)
            {
              if (obj->bitsize && dwg->header.version == dwg->header.from_version)
                obj->was_bitsize_set = 1;
              error = dwg_encode_UNKNOWN_ENT (dat, obj);
            }
          else {
              
              
              if (!obj->hdlpos)
                {
                  if (obj->bitsize)
                    {
                      obj->hdlpos = (obj->address * 8) + obj->bitsize;
                      if (dwg->header.version == dwg->header.from_version)
                        obj->was_bitsize_set = 1;
                    }
                  else obj->hdlpos = (obj->address * 8) + obj->num_unknown_bits;
                }
              error = dwg_encode_UNKNOWN_OBJ (dat, obj);
            }

          if (dwg->header.version == dwg->header.from_version && obj->unknown_bits && obj->num_unknown_bits)
            {
              int len = obj->num_unknown_bits / 8;
              const int mod = obj->num_unknown_bits % 8;
              if (mod)
                len++;
              bit_write_TF (dat, obj->unknown_bits, len);
              LOG_TRACE ("unknown_bits: %d/%u [TF]\n", len, (unsigned)obj->num_unknown_bits);
              LOG_TRACE_TF (obj->unknown_bits, len);
              if (mod)
                bit_advance_position (dat, mod - 8);
              obj->was_bitsize_set = 1;
            }
        }
    }

  
  
  if (!obj->size || dwg->header.from_version != dwg->header.version || obj->was_bitsize_set)
    {
      BITCODE_BL pos = bit_position (dat);
      BITCODE_RL old_size = obj->size;
      if (dwg->header.version < R_2004 || obj->index)
        {
          if (!address)
            return DWG_ERR_INVALIDDWG;
          assert (address);
        }
      if (dat->byte > obj->address)
        {
          
          obj->size = dat->byte - obj->address;
          if (dat->bit)
            obj->size++;
        }
      if (dat->byte >= dat->size)
        bit_chain_alloc (dat);
      
      if (!obj->bitsize || (dwg->header.from_version != dwg->header.version  && !obj->was_bitsize_set))


        {
          LOG_TRACE ("-bitsize calc from address (no handle) @%lu.%u\n", dat->byte - obj->address, dat->bit);
          obj->bitsize = pos - (obj->address * 8);
        }
      bit_set_position (dat, address * 8);
      if (obj->size > 0x7fff && old_size <= 0x7fff)
        {
          
          LOG_INFO ("overlarge size %u > 0x7fff @%lu\n", (unsigned)obj->size, dat->byte);
          if (dat->byte + obj->size + 2 >= dat->size)
            bit_chain_alloc (dat);
          memmove (&dat->chain[dat->byte + 2], &dat->chain[dat->byte], obj->size);
          obj->size += 2;
          obj->bitsize += 16;
          obj->bitsize_pos += 16;
          pos += 16;
        }
      if (obj->size <= 0x7fff && old_size > 0x7fff)
        {
          
          LOG_INFO ("was overlarge size %u < 0x7fff @%lu\n", (unsigned)old_size, dat->byte);
          memmove (&dat->chain[dat->byte], &dat->chain[dat->byte + 2], obj->size);
          obj->size -= 2;
          obj->bitsize -= 16;
          obj->bitsize_pos -= 16;
          pos -= 16;
        }
      bit_write_MS (dat, obj->size);
      LOG_TRACE ("-size: %u [MS] @%lu\n", obj->size, address);
      SINCE (R_2013)
      {
        if (!obj->handlestream_size && obj->bitsize)
          obj->handlestream_size = (obj->size * 8) - obj->bitsize;
        bit_write_UMC (dat, obj->handlestream_size);
        LOG_TRACE ("-handlestream_size: %lu [UMC]\n", obj->handlestream_size);
      }
      SINCE (R_2000)
      {
        if (obj->bitsize_pos && obj->bitsize)
          {
            bit_set_position (dat, obj->bitsize_pos);
            bit_write_RL (dat, obj->bitsize);
            LOG_TRACE ("-bitsize: %u [RL] @%lu.%lu\n", obj->bitsize, obj->bitsize_pos / 8, obj->bitsize_pos % 8);
          }
      }
      bit_set_position (dat, pos);
    }

  
  if (dat->bit)
    LOG_TRACE ("padding: +%d [*B]\n", 8 - dat->bit)
  while (dat->bit)
    bit_write_B (dat, 1);
  end_address = obj->address + obj->size;
  if (end_address != dat->byte)
    {
      if (obj->size)
        LOG_WARN ("Wrong object size: %lu + %u = %lu != %lu: %ld off", address, obj->size, end_address, dat->byte, (long)(end_address - dat->byte));

      
    }
  assert (!dat->bit);
  bit_write_CRC (dat, address, 0xC0C1);
  return error;
}


static int dwg_encode_eed_data (Bit_Chain *restrict dat, Dwg_Eed_Data *restrict data, const int i)
{
  unsigned long pos = bit_position (dat);
  unsigned long size;
  bit_write_RC (dat, data->code);
  LOG_TRACE ("EED[%d] code: %d [RC] ", i, data->code);
  switch (data->code)
    {
    case 0:
      {
        PRE (R_2007)
        {
          
          if (data->u.eed_0.is_tu)
            {
              BITCODE_RS length = data->u.eed_0_r2007.length;
              BITCODE_RS *s = (BITCODE_RS *)&data->u.eed_0_r2007.string;
              BITCODE_RS codepage = 30; 
              char *dest;
              if (length + 5 + dat->byte >= dat->size)
                bit_chain_alloc (dat);
              if (length > 255)
                {
                  LOG_ERROR ("eed: overlong string %d stripped", (int)length);
                  length = 255;
                }
              dest = bit_embed_TU_size (s, length);
              bit_write_RC (dat, length);
              bit_write_RS_LE (dat, codepage);
              bit_write_TF (dat, (unsigned char *)dest, length);
              LOG_TRACE ("string: len=%d [RC] cp=%d [RS_LE] \"%s\" [TF]", length, codepage, dest);
              free (dest);
            }
          else {
              if (!*data->u.eed_0.string)
                data->u.eed_0.length = 0;
              if (data->u.eed_0.length + 5 + dat->byte >= dat->size)
                bit_chain_alloc (dat);
              bit_write_RC (dat, data->u.eed_0.length);
              bit_write_RS_LE (dat, data->u.eed_0.codepage);
              bit_write_TF (dat, (BITCODE_TF)data->u.eed_0.string, data->u.eed_0.length);
              LOG_TRACE ("string: len=%d [RC] cp=%d [RS_LE] \"%s\" [TF]", data->u.eed_0.length, data->u.eed_0.codepage, data->u.eed_0.string);

            }
        }
        LATER_VERSIONS {
          
          if (!data->u.eed_0.is_tu)
            {
              BITCODE_RS length = data->u.eed_0.length;
              BITCODE_TU dest = bit_utf8_to_TU (data->u.eed_0.string, 0);
              if ((length * 2) + 5 + dat->byte >= dat->size)
                bit_chain_alloc (dat);
              bit_write_RS (dat, length);
              for (int j = 0; j < length; j++)
                bit_write_RS (dat, *dest++);
              data->u.eed_0_r2007.length = length;
              LOG_TRACE ("wstring: len=%d [RS] \"%s\" [TU]", (int)length, data->u.eed_0.string);
            }
          else {
              BITCODE_RS length = data->u.eed_0_r2007.length;
              BITCODE_RS *s = (BITCODE_RS *)&data->u.eed_0_r2007.string;
              if ((length * 2) + 5 + dat->byte >= dat->size)
                bit_chain_alloc (dat);
              bit_write_RS (dat, length);
              for (int j = 0; j < length; j++)
                bit_write_RS (dat, *s++);

              LOG_TRACE ("wstring: len=%d [RS] \"" FORMAT_TU "\" [TU]", (int)data->u.eed_0_r2007.length, data->u.eed_0_r2007.string);


              if (DWG_LOGLEVEL >= DWG_LOGLEVEL_TRACE)
                {
                  char *u8 = bit_TU_to_utf8_len (data->u.eed_0_r2007.string, data->u.eed_0_r2007.length);
                  LOG_TRACE ("wstring: len=%d [RS] \"%s\" [TU]", (int)data->u.eed_0_r2007.length, u8);
                  free (u8);
                }

            }
        }
      }
      break;
    case 2:
      bit_write_RC (dat, data->u.eed_2.close);
      LOG_TRACE ("close: %d [RC]", (int)data->u.eed_2.close);
      break;
    case 3:
      bit_write_RLL (dat, data->u.eed_3.layer);
      LOG_TRACE ("layer: 0x%lX [RLL]", (unsigned long)data->u.eed_3.layer);
      break;
    case 4:
      bit_write_RC (dat, data->u.eed_4.length);
      bit_write_TF (dat, (BITCODE_TF)data->u.eed_4.data, data->u.eed_4.length);
      LOG_TRACE ("binary: ");
      LOG_TRACE_TF (data->u.eed_4.data, data->u.eed_4.length);
      break;
    case 5:
      bit_write_RLL (dat, (BITCODE_RLL)data->u.eed_5.entity);
      LOG_TRACE ("entity: 0x%lX [ulong]", data->u.eed_5.entity);
      break;
    case 10:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
      bit_write_RD (dat, data->u.eed_10.point.x);
      bit_write_RD (dat, data->u.eed_10.point.y);
      bit_write_RD (dat, data->u.eed_10.point.z);
      LOG_TRACE ("3dpoint: (%f, %f, %f) [3RD]", data->u.eed_10.point.x, data->u.eed_10.point.y, data->u.eed_10.point.z);
      break;
    case 40:
    case 41:
    case 42:
      bit_write_RD (dat, data->u.eed_40.real);
      LOG_TRACE ("real: %f [RD]", data->u.eed_40.real);
      break;
    case 70:
      bit_write_RS (dat, data->u.eed_70.rs);
      LOG_TRACE ("short: " FORMAT_RS " [RS]", data->u.eed_70.rs);
      break;
    case 71:
      bit_write_RL (dat, data->u.eed_71.rl);
      LOG_TRACE ("long: " FORMAT_RL " [RL]", data->u.eed_71.rl);
      break;
    default:
      dat->byte--;
      LOG_ERROR ("unknown EED code %d", data->code);
    }
  size = bit_position (dat) - pos;
  return (size % 8) ? (int)(size / 8) + 1 : (int)(size / 8);
}




static int dwg_encode_eed (Bit_Chain *restrict dat, Dwg_Object *restrict obj)
{
  
  
  Dwg_Handle *last_handle = NULL;
  Bit_Chain dat1 = { 0 };
  int i, num_eed = obj->tio.object->num_eed;
  BITCODE_BS size = 0;
  int last_size = 0;
  int new_size = 0;
  int did_raw = 0;
  int need_recalc = does_cross_unicode_datversion (dat);

  bit_chain_init (&dat1, 1024);
  dat1.from_version = dat->from_version;
  dat1.version = dat->version;
  dat1.opts = dat->opts;

  
  if (dat->opts & DWG_OPTS_INDXF && dat->version < R_2007 && obj->fixedtype == DWG_TYPE_DICTIONARY && num_eed == 1)


    {
      Dwg_Eed *eed = &obj->tio.object->eed[0];
      if (eed->handle.value == 0x12 && eed->data->code == 70 && eed->data->u.eed_70.rs > 1)

        {
          LOG_TRACE ("skip AcDs DICTIONARY EED to use ACIS ver 2\n");
          num_eed = 0;
        }
    }

  for (i = 0; i < num_eed; i++)
    {
      Dwg_Eed *eed = &obj->tio.object->eed[i];
      if (eed->size) 
        {
          size = eed->size;
          if (eed->raw && !need_recalc)
            {
              did_raw = 1;
              bit_write_BS (dat, size);
              LOG_TRACE ("EED[%d] size: " FORMAT_BS " [BS]", i, size); LOG_POS bit_write_H (dat, &eed->handle);
              LOG_TRACE ("EED[%d] handle: " FORMAT_H " [H]", i, ARGS_H (eed->handle)); LOG_POS LOG_TRACE ("EED[%d] raw [TF %d]\n", i, size);

              bit_write_TF (dat, eed->raw, size);
              LOG_TRACE_TF (eed->raw, size);
              new_size = 0;
            }
          
          else if (eed->data)
            {
              did_raw = 0;
              if (new_size) 
                {





                  if (EED_ALLOWED)
                    {
                      eed->size = new_size;
                      bit_write_BS (dat, new_size);
                      LOG_TRACE ("EED[%d] size: " FORMAT_BS " [BS]", last_size, new_size); LOG_POS;
                      bit_write_H (dat, last_handle);
                      LOG_TRACE ("EED[%d] handle: " FORMAT_H " [H]", last_size, ARGS_H (*last_handle)); LOG_POS;
                      LOG_TRACE ("flush eed_data %lu.%d\n", dat1.byte, dat1.bit);
                      dat_flush (dat, &dat1);
                    }
                  else {
                      LOG_WARN ("skip EED[%d] handle: " FORMAT_H " [H] for DesignCenter Data", last_size, ARGS_H (*last_handle)); LOG_POS;
                      dat1.byte = 0;
                    }
                  new_size = 0;
                }
              new_size = dwg_encode_eed_data (&dat1, eed->data, i);
              LOG_POS;
            }
          last_size = i;
          last_handle = &eed->handle;
        }
      
      else if (!did_raw && eed->data)
        {
          new_size += dwg_encode_eed_data (&dat1, eed->data, i);
          LOG_POS;
        }
    }
  if (new_size && last_handle) 
    {
      
      if (EED_ALLOWED)
        {
          bit_write_BS (dat, new_size);
          LOG_TRACE ("EED[%d] size: " FORMAT_BS " [BS]", last_size, new_size); LOG_POS;
          bit_write_H (dat, last_handle);
          LOG_TRACE ("EED[%d] handle: " FORMAT_H " [H]", last_size, ARGS_H (*last_handle)); LOG_POS;
          last_handle = NULL;
        }
      else {
          LOG_TRACE ("skip EED[%d] handle: " FORMAT_H " [H] for DesignCenter Data", last_size, ARGS_H (*last_handle)); LOG_POS;
          dat1.byte = 0;
        }
    }
  if (dat1.byte)
    LOG_TRACE ("flush eed_data %lu.%d\n", dat1.byte, dat1.bit);
  dat_flush (dat, &dat1);
  bit_write_BS (dat, 0);
  if (i)
    LOG_TRACE ("EED[%d] size: 0 [BS] (end)\n", i);
  LOG_TRACE ("num_eed: %d\n", num_eed);
  bit_chain_free (&dat1);
  return 0;
}


static int dwg_encode_entity (Dwg_Object *restrict obj, Bit_Chain *dat, Bit_Chain *restrict hdl_dat, Bit_Chain *str_dat)

{
  int error = 0;
  Dwg_Object_Entity *ent = obj->tio.entity;
  Dwg_Object_Entity *_obj = ent;
  Dwg_Data *dwg = ent->dwg;

  if (!obj || !dat || !ent)
    return DWG_ERR_INVALIDDWG;

  hdl_dat->from_version = dat->from_version;
  hdl_dat->version = dat->version;
  hdl_dat->opts = dat->opts;

  PRE (R_13)
  {

    if (FIELD_VALUE (flag_r11) & 4 && FIELD_VALUE (kind_r11) > 2 && FIELD_VALUE (kind_r11) != 22)
      FIELD_RD (elevation_r11, 30);
    if (FIELD_VALUE (flag_r11) & 8)
      FIELD_RD (thickness_r11, 39);
    if (FIELD_VALUE (flag_r11) & 0x20)
      {
        Dwg_Object_Ref *hdl = dwg_decode_handleref_with_code (dat, obj, dwg, 0);
        if (hdl)
          obj->handle = hdl->handleref;
      }
    if (FIELD_VALUE (extra_r11) & 4)
      FIELD_RS (paper_r11, 0);
  }

  SINCE (R_2007) { *str_dat = *dat; }
  VERSIONS (R_2000, R_2007)
  {
    obj->bitsize_pos = bit_position (dat);
    bit_write_RL (dat, obj->bitsize);
    LOG_TRACE ("bitsize: %u [RL] (@%lu.%lu)\n", obj->bitsize, obj->bitsize_pos / 8, obj->bitsize_pos % 8);
  }
  obj->was_bitsize_set = 0;
  if (obj->bitsize)
    {
      obj->hdlpos = (obj->address * 8) + obj->bitsize;
    }
  SINCE (R_2007)
  {
    
    
    SINCE (R_2010)
    {
      if (obj->bitsize)
        {
          obj->hdlpos += 8;
          
          LOG_HANDLE ("hdlpos: %lu\n", obj->hdlpos);
        }
    }
    
    error |= obj_string_stream (dat, obj, str_dat);
  }

  bit_write_H (dat, &obj->handle);
  LOG_TRACE ("handle: " FORMAT_H " [H 5]", ARGS_H (obj->handle))
  LOG_INSANE (" @%lu.%u", dat->byte - obj->address, dat->bit)
  LOG_TRACE ("\n")
  PRE (R_13) { return DWG_ERR_NOTYETSUPPORTED; }

  error |= dwg_encode_eed (dat, obj);
  
  

  
  #include "common_entity_data.spec"
  

  return error;
}

static int dwg_encode_common_entity_handle_data (Bit_Chain *dat, Bit_Chain *hdl_dat, Dwg_Object *restrict obj)

{
  Dwg_Object_Entity *ent;
  
  Dwg_Object_Entity *_obj;
  BITCODE_BL vcount;
  int error = 0;
  ent = obj->tio.entity;
  _obj = ent;

  
  #include "common_entity_handle_data.spec"
  

  return error;
}


void dwg_encode_handleref (Bit_Chain *hdl_dat, Dwg_Object *restrict obj, Dwg_Data *restrict dwg, Dwg_Object_Ref *restrict ref)

{
  
  
  
  assert (obj);
}


void dwg_encode_handleref_with_code (Bit_Chain *hdl_dat, Dwg_Object *restrict obj, Dwg_Data *restrict dwg, Dwg_Object_Ref *restrict ref, unsigned int code)



{
  
  
  dwg_encode_handleref (hdl_dat, obj, dwg, ref);
  if (ref->absolute_ref == 0 && ref->handleref.code != code)
    {
      
      switch (ref->handleref.code)
        {
        case 0x06:
          ref->absolute_ref = (obj->handle.value + 1);
          break;
        case 0x08:
          ref->absolute_ref = (obj->handle.value - 1);
          break;
        case 0x0A:
          ref->absolute_ref = (obj->handle.value + ref->handleref.value);
          break;
        case 0x0C:
          ref->absolute_ref = (obj->handle.value - ref->handleref.value);
          break;
        case 2:
        case 3:
        case 4:
        case 5:
          ref->absolute_ref = ref->handleref.value;
          break;
        case 0: 
          ref->absolute_ref = ref->handleref.value;
          break;
        default:
          LOG_WARN ("Invalid handle pointer code %d", ref->handleref.code);
          break;
        }
    }
}


static int dwg_encode_object (Dwg_Object *restrict obj, Bit_Chain *dat, Bit_Chain *restrict hdl_dat, Bit_Chain *str_dat)

{
  int error = 0;
  BITCODE_BL vcount;

  hdl_dat->from_version = dat->from_version;
  hdl_dat->version = dat->version;
  hdl_dat->opts = dat->opts;

  {
    Dwg_Object *_obj = obj;
    VERSIONS (R_2000, R_2007)
    {
      obj->bitsize_pos = bit_position (dat);
      FIELD_RL (bitsize, 0);
    }
    obj->was_bitsize_set = 0;
    if (obj->bitsize)
      
      obj->hdlpos = bit_position (dat) + obj->bitsize;
    SINCE (R_2007) { obj_string_stream (dat, obj, str_dat); }
    if (!_obj || !obj->tio.object)
      return DWG_ERR_INVALIDDWG;

    bit_write_H (dat, &obj->handle);
    LOG_TRACE ("handle: " FORMAT_H " [H 5]\n", ARGS_H (obj->handle));
    error |= dwg_encode_eed (dat, obj);

    VERSIONS (R_13, R_14)
    {
      obj->bitsize_pos = bit_position (dat);
      FIELD_RL (bitsize, 0);
    }
  }

  SINCE (R_13) {
    Dwg_Object_Object *_obj = obj->tio.object;
    FIELD_BL (num_reactors, 0);
    SINCE (R_2004) { FIELD_B (is_xdic_missing, 0); }
    SINCE (R_2013) { FIELD_B (has_ds_data, 0); } 
  }
  return error;
}

AFL_GCC_TOOBIG static int dwg_encode_header_variables (Bit_Chain *dat, Bit_Chain *hdl_dat, Bit_Chain *str_dat, Dwg_Data *restrict dwg)


{
  Dwg_Header_Variables *_obj = &dwg->header_vars;
  Dwg_Object *obj = NULL;
  Dwg_Version_Type old_from = dat->from_version;

  if (!_obj->HANDSEED) 
    {
      BITCODE_H last_hdl;
      unsigned long seed = 0;
      dwg->opts |= DWG_OPTS_MINIMAL;
      dat->from_version = (Dwg_Version_Type)((int)dat->version - 1);
      LOG_TRACE ("encode from minimal DXF\n");

      _obj->HANDSEED = (Dwg_Object_Ref*)calloc (1, sizeof (Dwg_Object_Ref));
      
      last_hdl = dwg->num_object_refs ? dwg->object_ref[ dwg->num_object_refs - 1] : NULL;
      if (last_hdl)
        {
          
          seed = last_hdl->absolute_ref;
          LOG_TRACE ("compute HANDSEED %lu ", seed);
          for (unsigned i = 0; i < dwg->num_object_refs; i++)
            {
              Dwg_Object_Ref *ref = dwg->object_ref[i];
              if (ref->absolute_ref > seed)
                seed = ref->absolute_ref;
            }
          _obj->HANDSEED->absolute_ref = seed + 1;
          LOG_TRACE ("-> %lu\n", seed);
        }
      else _obj->HANDSEED->absolute_ref = 0x72E;
    }

    
  #include "header_variables.spec"
  

  dat->from_version = old_from;
  return 0;
}
AFL_GCC_POP  static int dwg_encode_xdata (Bit_Chain *restrict dat, Dwg_Object_XRECORD *restrict _obj, unsigned xdata_size)



{
  Dwg_Resbuf *rbuf = _obj->xdata;
  enum RESBUF_VALUE_TYPE type;
  int error = 0;
  int i;
  unsigned j = 0;
  
  unsigned long start = dat->byte, end = start + xdata_size;
  Dwg_Data *dwg = _obj->parent->dwg;
  Dwg_Object *obj = &dwg->object[_obj->parent->objid];

  if (dat->opts & DWG_OPTS_IN) 
    end += xdata_size;

  while (rbuf)
    {
      bit_write_RS (dat, rbuf->type);
      LOG_INSANE ("xdata[%u] type: " FORMAT_RS " [RS] @%lu.%u\n", j, rbuf->type, dat->byte - obj->address, dat->bit)
      type = dwg_resbuf_value_type (rbuf->type);
      switch (type)
        {
        case DWG_VT_STRING:
          PRE (R_2007)
          {
            if (dat->byte + 3 + rbuf->value.str.size > end)
              break;
            
            if (rbuf->value.str.size && rbuf->value.str.is_tu)
              {
                BITCODE_TV new = bit_embed_TU_size (rbuf->value.str.u.wdata, rbuf->value.str.size);
                int len = strlen(new);
                bit_write_RS (dat, len);
                bit_write_RC (dat, rbuf->value.str.codepage);
                if (rbuf->value.str.u.data)
                  bit_write_TF (dat, (BITCODE_TF)new, len);
                else bit_write_TF (dat, (BITCODE_TF)"", 0);
                LOG_TRACE ("xdata[%u]: \"%s\" [TF %d %d]", j, rbuf->value.str.u.data, len, rbuf->type);
                free (new);
              }
            else {
                bit_write_RS (dat, rbuf->value.str.size);
                bit_write_RC (dat, rbuf->value.str.codepage);
                if (rbuf->value.str.u.data)
                  bit_write_TF (dat, (BITCODE_TF)rbuf->value.str.u.data, rbuf->value.str.size);
                else bit_write_TF (dat, (BITCODE_TF)"", 0);
                LOG_TRACE ("xdata[%u]: \"%s\" [TF %d %d]", j, rbuf->value.str.u.data, rbuf->value.str.size, rbuf->type);
              }
            LOG_POS;
          }
          LATER_VERSIONS {
            if (dat->byte + 2 + (2 * rbuf->value.str.size) > end)
              break;
            if (rbuf->value.str.size && !rbuf->value.str.is_tu)
              {
                
                BITCODE_TU new = bit_utf8_to_TU (rbuf->value.str.u.data, 0);
                bit_write_RS (dat, rbuf->value.str.size);
                for (i = 0; i < rbuf->value.str.size; i++)
                  bit_write_RS (dat, new[i]);
                LOG_TRACE_TU ("xdata", new, rbuf->type);
                free (new);
              }
            else {
                bit_write_RS (dat, rbuf->value.str.size);
                for (i = 0; i < rbuf->value.str.size; i++)
                  bit_write_RS (dat, rbuf->value.str.u.wdata[i]);
                LOG_TRACE_TU ("xdata", rbuf->value.str.u.wdata, rbuf->type);
              }
            LOG_POS;
          }
          break;
        case DWG_VT_REAL:
          if (dat->byte + 8 > end)
            break;
          bit_write_RD (dat, rbuf->value.dbl);
          LOG_TRACE ("xdata[%u]: %f [RD %d]", j, rbuf->value.dbl, rbuf->type);
          LOG_POS;
          break;
        case DWG_VT_BOOL:
        case DWG_VT_INT8:
          bit_write_RC (dat, rbuf->value.i8);
          LOG_TRACE ("xdata[%u]: %d [RC %d]", j, (int)rbuf->value.i8, rbuf->type);
          LOG_POS;
          break;
        case DWG_VT_INT16:
          if (dat->byte + 2 > end)
            break;
          bit_write_RS (dat, rbuf->value.i16);
          LOG_TRACE ("xdata[%u]: %d [RS %d]", j, (int)rbuf->value.i16, rbuf->type);
          LOG_POS;
          break;
        case DWG_VT_INT32:
          if (dat->byte + 4 > end)
            break;
          bit_write_RL (dat, rbuf->value.i32);
          LOG_TRACE ("xdata[%d]: %ld [RL %d]", j, (long)rbuf->value.i32, rbuf->type);
          LOG_POS;
          break;
        case DWG_VT_INT64:
          if (dat->byte + 8 > end)
            break;
          bit_write_RLL (dat, rbuf->value.i64);
          LOG_TRACE ("xdata[%u]: " FORMAT_RLL " [RLL %d]", j, rbuf->value.i64, rbuf->type);
          LOG_POS;
          break;
        case DWG_VT_POINT3D:
          if (dat->byte + 24 > end)
            break;
          bit_write_RD (dat, rbuf->value.pt[0]);
          bit_write_RD (dat, rbuf->value.pt[1]);
          bit_write_RD (dat, rbuf->value.pt[2]);
          LOG_TRACE ("xdata[%u]: (%f,%f,%f) [3RD %d]", j, rbuf->value.pt[0], rbuf->value.pt[1], rbuf->value.pt[2], rbuf->type);
          LOG_POS;
          break;
        case DWG_VT_BINARY:
          if (dat->byte + rbuf->value.str.size > end)
            break;
          bit_write_RC (dat, rbuf->value.str.size);
          bit_write_TF (dat, (BITCODE_TF)rbuf->value.str.u.data, rbuf->value.str.size);
          LOG_TRACE ("xdata[%u]: [TF %d %d] ", j, rbuf->value.str.size, rbuf->type);
          LOG_TRACE_TF (rbuf->value.str.u.data, rbuf->value.str.size);
          LOG_POS;
          break;
        case DWG_VT_HANDLE:
        case DWG_VT_OBJECTID:
          if (dat->byte + 8 > end)
            break;
          for (i = 0; i < 8; i++)
            bit_write_RC (dat, rbuf->value.hdl[i]);
          LOG_TRACE ("xdata[%u]: " FORMAT_H " [H %d]", j, ARGS_H (rbuf->value.h), rbuf->type);
          LOG_POS;
          break;
        case DWG_VT_INVALID:
        default:
          LOG_ERROR ("Invalid group code in xdata: %d", rbuf->type);
          error = DWG_ERR_INVALIDEED;
          break;
        }
      rbuf = rbuf->nextrb;
      j++;
      if (j >= _obj->num_xdata)
        break;
      if (dat->byte >= end)
        {
          LOG_WARN ("xdata overflow %u", xdata_size);
          break;
        }
    }
  if (_obj->xdata_size != dat->byte - start)
    {
      if (dat->opts & DWG_OPTS_IN) 
        {
          _obj->xdata_size = dat->byte - start;
          LOG_TRACE ("-xdata_size: " FORMAT_BL " (calculated)\n", _obj->xdata_size);
          return error;
        }
      else {
          LOG_WARN ("xdata Written %lu, expected " FORMAT_BL, dat->byte - start, _obj->xdata_size);
          _obj->xdata_size = dat->byte - start;
          return error ? error : 1;
        }
    }
  return 0;
}


