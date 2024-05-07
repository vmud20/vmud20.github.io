


#include<assert.h>
#include<stdio.h>
#include<stddef.h>

#include<inttypes.h>
#include<stdint.h>

#include<string.h>
#include<stdlib.h>
#include<stdbool.h>
#  define BLOCK_NAME(nam, dxf) FIELD_T (nam, dxf)
#define CALL_ENTITY(name, xobj)                                               \
  error |= DWG_PRIVATE_N (ACTION, name) (dat, hdl_dat, str_dat,               \
                                             (Dwg_Object *)xobj)
#define CALL_SUBCLASS(_xobj, parenttype, subtype)                             \
  error |= DWG_PRIVATE_N (ACTION, parenttype##_##subtype) (_xobj, dat,        \
               hdl_dat, str_dat, (Dwg_Object *)obj)
#define CALL_SUBCURVE(hdl, curvetype)
#define CALL_SUBENT(hdl, dxf)
#    define CLEARFIRST
#  define COMMON_TABLE_FLAGS(acdbname)                                        \
    assert (obj->supertype == DWG_SUPERTYPE_OBJECT);                          \
    PRE (R_13)                                                                \
    {                                                                         \
      if (strcmp (#acdbname, "Layer") == 0)                                   \
        {                                                                     \
          FIELD_CAST (flag, RC, RS, 70);                                      \
        }                                                                     \
      else                                                                    \
        {                                                                     \
          FIELD_CAST (flag, RC, RC, 70);                                      \
        }                                                                     \
      FIELD_TFv (name, 32, 2);                                                \
      FIELD_RS (used, 0);                                                     \
    }                                                                         \
    LATER_VERSIONS                                                            \
    {                                                                         \
      FIELD_T (name, 2);                                                      \
      UNTIL (R_2004)                                                          \
      {                                                                       \
        FIELD_B (is_xref_ref, 0);                     \
        FIELD_BS (is_xref_resolved, 0);                         \
        FIELD_B (is_xref_dep, 0);                               \
      }                                                                       \
      LATER_VERSIONS                                                          \
      {                                                                       \
        FIELD_VALUE (is_xref_ref) = 1;                                        \
        FIELD_BS (is_xref_resolved, 0);                         \
        if (FIELD_VALUE (is_xref_resolved) == 256)                            \
          FIELD_VALUE (is_xref_dep) = 1;                                      \
      }                                                                       \
      FIELD_HANDLE (xref, 5, 0);             \
      FIELD_VALUE (flag)                                                      \
          |= FIELD_VALUE (is_xref_dep) << 4 | FIELD_VALUE (is_xref_ref) << 6; \
    }                                                                         \
    RESET_VER
#  define CONTROL_HANDLE_STREAM                                               \
    assert (obj->supertype == DWG_SUPERTYPE_OBJECT);                          \
    PRE (R_2007) {                                                            \
      hdl_dat->byte = dat->byte;                                              \
      hdl_dat->bit = dat->bit;                                                \
    }                                                                         \
    SINCE (R_13) {                                                            \
      VALUE_HANDLE (obj->tio.object->ownerhandle, ownerhandle, 4, 0);         \
      REACTORS (4)                                                            \
      XDICOBJHANDLE (3)                                                       \
    }
#  define DECODER if (0)
#  define DECODER_OR_ENCODER if (0)
#define DECODE_UNKNOWN_BITS                                                   \
  DECODER { dwg_decode_unknown (dat, (Dwg_Object * restrict) obj); }          \
  FREE { VALUE_TF (obj->unknown_bits, 0); }
#  define DWG_FUNC_N(ACTION, name) _DWG_FUNC_N (ACTION, name)
#  define DWG_PRIVATE_N(ACTION, name) _DWG_PRIVATE_N (ACTION, name)
#define DWG_SUBCLASS(parenttype, subtype)                                     \
  static int DWG_PRIVATE_N (ACTION, parenttype##_##subtype)                   \
    (Dwg_Object_##parenttype *restrict _obj, Bit_Chain *dat,                  \
     Bit_Chain *hdl_dat,                                                      \
     Bit_Chain *str_dat, Dwg_Object *restrict obj)                            \
  {                                                                           \
    BITCODE_BL vcount, rcount3, rcount4;                                      \
    Dwg_Data *dwg = obj->parent;                                              \
    int error = 0;                                                            \
    subtype##_fields;                                                         \
    return error;                                                             \
  }
#define DWG_SUBCLASS_DECL(parenttype, subtype)                                \
  static int DWG_PRIVATE_N (ACTION, parenttype##_##subtype)                   \
    (Dwg_Object_##parenttype *restrict _obj, Bit_Chain *dat,                  \
     Bit_Chain *hdl_dat,                                                      \
     Bit_Chain *str_dat, Dwg_Object *restrict obj)                            \

#  define DXF if (0)
#  define DXF_3DSOLID
#  define DXF_OR_PRINT if (0)
#  define ENCODER if (0)
#    define END_REPEAT(field)
#  define END_REPEAT_BLOCK }
#  define FIELDG(nam, type, dxf) FIELD (nam, type)
#  define FIELD_2PT_TRACE(name, type, dxf)                                    \
    LOG_TRACE (#name ": (" FORMAT_BD ", " FORMAT_BD ") [" #type " %d]\n",     \
               _obj->name.x, _obj->name.y, dxf)
#  define FIELD_2RD0(name, dxf) FIELD_2RD (name, dxf)
#  define FIELD_3PT_TRACE(name, type, dxf)                                    \
    LOG_TRACE (#name ": (" FORMAT_BD ", " FORMAT_BD ", " FORMAT_BD            \
                     ") [" #type " %d]\n",                                    \
               _obj->name.x, _obj->name.y, _obj->name.z, dxf)
#  define FIELD_B0(name, dxf) FIELD_B (name, dxf)
#  define FIELD_BD0(name, dxf) FIELD_BD (name, dxf)
#  define FIELD_BD1(name, dxf) FIELD_BD (name, dxf)
#  define FIELD_BINARY(name, len, dxf) FIELD_TF (name, len, dxf)
#  define FIELD_BL0(name, dxf) FIELD_BL (name, dxf)
#  define FIELD_BLd(name, dxf) FIELD_BL (name, dxf)
#  define FIELD_BLx(name, dxf) FIELD_BL (name, dxf)
#  define FIELD_BS0(name, dxf) FIELD_BS (name, dxf)
#  define FIELD_BS1(name, dxf) FIELD_BS (name, dxf)
#  define FIELD_BSd(name, dxf) FIELD_BS (name, dxf)
#  define FIELD_BSx(name, dxf) FIELD_BS (name, dxf)
#  define FIELD_BT0(name, dxf) FIELD_BT (name, dxf)
#  define FIELD_CMC0(color, dxf) FIELD_CMC (color, dxf)
#  define FIELD_CMTC(name, dxf)                                               \
    {                                                                         \
      Dwg_Version_Type _ver = dat->version;                                   \
      if (dat->version < R_2004)                                              \
        dat->version = R_2004;                                                \
      FIELD_CMC (name, dxf);                                                  \
      dat->version = _ver;                                                    \
    }
#  define FIELD_D2T(name, dxf) FIELD_TV (name, dxf)
#  define FIELD_ENC(a, b, c) FIELD_CMC (a, b, c)
#  define FIELD_HANDLE0(name, code, dxf) FIELD_HANDLE (name, code, dxf)
#  define FIELD_RC0(name, dxf) FIELD_RC (name, dxf)
#  define FIELD_RCd(name, dxf) FIELD_RC (name, dxf)
#  define FIELD_RCu(name, dxf) FIELD_RC (name, dxf)
#  define FIELD_RCx(name, dxf) FIELD_RC (name, dxf)
#  define FIELD_RD0(name, dxf) FIELD_RD (name, dxf)
#  define FIELD_RD1(name, dxf) FIELD_RD (name, dxf)
#  define FIELD_RL0(name, dxf) FIELD_RL (name, dxf)
#  define FIELD_RLd(name, dxf) FIELD_RL (name, dxf)
#  define FIELD_RLx(name, dxf) FIELD_RL (name, dxf)
#  define FIELD_RS0(name, dxf) FIELD_RS (name, dxf)
#  define FIELD_RSx(name, dxf) FIELD_RS (name, dxf)
#  define FIELD_T0(name, dxf) FIELD_T (name, dxf)
#  define FIELD_TFFx(name, len, dxf) FIELD_TFF (name, len, dxf)
#  define FIELD_TFv(name, len, dxf) FIELD_TF (name, len, dxf)
#  define FIELD_TU32(name, dxf) FIELD_TV (name, dxf)
#  define FIELD_TV0(name, dxf) FIELD_TV (name, dxf)
#  define FIELD_VECTOR_INL(o, nam, type, size, dxf)                           \
  FIELD_VECTOR_N(o, nam, type, size, dxf)
#  define FIELD_VECTOR_N1(name, type, size, dxf)                              \
    FIELD_VECTOR_N (name, type, size, dxf)
#  define FREE if (0)
#  define IF_ENCODE_FROM_EARLIER if (0)
#  define IF_ENCODE_FROM_EARLIER_OR_DXF if (0)
#  define IF_ENCODE_FROM_PRE_R13 if (0)
#  define IF_ENCODE_FROM_SINCE_R13 if (0)
#  define IF_ENCODE_SINCE_R13                                                 \
    if (dat->from_version && dat->from_version >= R_13)
#  define IF_FREE_OR_SINCE(x) SINCE (x)
#  define IF_FREE_OR_VERSIONS(x,y) VERSIONS(x, y)
#  define IF_IS_DECODER 0
#  define IF_IS_DXF 0
#  define IF_IS_ENCODER 0
#  define IF_IS_FREE 0
#    define ISFIRST
#  define JSON if (0)
#  define JSON_3DSOLID
#  define KEY(nam)
#  define LOG_INSANE_TF(var, len)
#  define LOG_TRACE_TF(var, len)
#  define PRINT if (0)
#  define R11FLAG(b) _ent->flag_r11 &b
#  define R11OPTS(b) _ent->opts_r11 &b
#  define REPEAT(times, name, type) _REPEAT (times, name, type, 1)
#  define REPEAT2(times, name, type) _REPEAT (times, name, type, 2)
#  define REPEAT2_C(times, name, type) _REPEAT_C (times, name, type, 2)
#  define REPEAT3(times, name, type) _REPEAT (times, name, type, 3)
#  define REPEAT3_C(times, name, type) _REPEAT_C (times, name, type, 3)
#  define REPEAT4(times, name, type) _REPEAT (times, name, type, 4)
#  define REPEAT4_C(times, name, type) _REPEAT_C (times, name, type, 4)
#  define REPEAT_BLOCK {
#  define REPEAT_C(times, name, type) _REPEAT_C (times, name, type, 1)
#  define REPEAT_CN(times, name, type)                                        \
    if (_obj->name != NULL)                                                   \
      for (rcount1 = 0; rcount1 < (BITCODE_BL)times; rcount1++)
#  define REPEAT_N(times, name, type)                                         \
    if (dat->version >= R_2000 && (BITCODE_BL)times > 20000)                  \
      {                                                                       \
        LOG_ERROR ("Invalid %s." #name " rcount1 %ld", SAFEDXFNAME,           \
                   (long)times);                                              \
        return DWG_ERR_VALUEOUTOFBOUNDS;                                      \
      }                                                                       \
    if (_obj->name != NULL)                                                   \
      for (rcount1 = 0; rcount1 < (BITCODE_BL)times; rcount1++)
#    define SETFIRST
#  define SET_PARENT(field, to)                                               \
    _obj->field.parent = to
#  define SET_PARENT_FIELD(field, what_parent, to)                            \
    _obj->field.what_parent = to
#  define SET_PARENT_OBJ(field)                                               \
    SET_PARENT (field, _obj)
#  define SPEC_H
#  define START_OBJECT_HANDLE_STREAM                                          \
    START_HANDLE_STREAM;                                                      \
    assert (obj->supertype == DWG_SUPERTYPE_OBJECT)
#  define SUBCLASS(text)
#  define SUB_FIELD_2BD(o, nam, dxf) FIELD_2BD (o.nam, dxf)
#  define SUB_FIELD_2BD_1(o, nam, dxf) FIELD_2BD_1 (o.nam, dxf)
#  define SUB_FIELD_2RD(o, nam, dxf) FIELD_2RD (o.nam, dxf)
#  define SUB_FIELD_2RD_VECTOR(o,name, size, dxf)                             \
  if (_obj->o.size > 0)                                                       \
    {                                                                         \
      for (vcount = 0; vcount < (BITCODE_BL)_obj->o.size; vcount++)           \
        {                                                                     \
          SUB_FIELD_2RD (o,name[vcount], dxf);                                \
        }                                                                     \
    }
#  define SUB_FIELD_3B(o, nam, dxf) FIELDG (o.nam, 3B, dxf)
#  define SUB_FIELD_3BD(o, nam, dxf) FIELD_3BD (o.nam, dxf)
#  define SUB_FIELD_3BD_VECTOR(o,name, size, dxf)                             \
  if (_obj->o.size > 0)                                                       \
    {                                                                         \
      for (vcount = 0; vcount < (BITCODE_BL)_obj->o.size; vcount++)           \
        {                                                                     \
          SUB_FIELD_3BD (o,name[vcount], dxf);                                \
        }                                                                     \
    }
#  define SUB_FIELD_3BD_inl(o, nam, dxf) FIELD_3BD (o, dxf)
#  define SUB_FIELD_3DPOINT(o, nam, dxf) FIELD_3BD (o.nam, dxf)
#  define SUB_FIELD_3RD(o, nam, dxf) FIELD_3RD (o.nam, dxf)
#  define SUB_FIELD_B(o, nam, dxf) FIELDG (o.nam, B, dxf)
#  define SUB_FIELD_BB(o, nam, dxf) FIELDG (o.nam, BB, dxf)
#  define SUB_FIELD_BD(o, nam, dxf) FIELD_BD (o.nam, dxf)
#  define SUB_FIELD_BL(o, nam, dxf) FIELDG (o.nam, BL, dxf)
#  define SUB_FIELD_BL0(o, name, dxf) SUB_FIELD_BL (o, name, dxf)
#  define SUB_FIELD_BLL(o, nam, dxf) FIELDG (o.nam, BLL, dxf)
#  define SUB_FIELD_BLd(o, nam, dxf) FIELD_BLd (o.nam, dxf)
#  define SUB_FIELD_BLx(o, nam, dxf) FIELD_BLx (o.nam, dxf)
#  define SUB_FIELD_BS(o, nam, dxf) FIELDG (o.nam, BS, dxf)
#  define SUB_FIELD_BSd(o, nam, dxf) FIELD_BSd (o.nam, dxf)
#  define SUB_FIELD_BSx(o, nam, dxf) FIELD_BSx (o.nam, dxf)
#  define SUB_FIELD_CMTC(o, name, dxf)                                        \
    {                                                                         \
      Dwg_Version_Type _ver = dat->version;                                   \
      if (dat->version < R_2004)                                              \
        dat->version = R_2004;                                                \
      SUB_FIELD_CMC (o, name, dxf);                                           \
      dat->version = _ver;                                                    \
    }
#  define SUB_FIELD_ENC(a, b, c, d) SUB_FIELD_CMC (a, b, c, d)
#  define SUB_FIELD_HANDLE0(o, name, code, dxf) SUB_FIELD_HANDLE (o, name, code, dxf)
#  define SUB_FIELD_RC(o, nam, dxf) FIELDG (o.nam, RC, dxf)
#  define SUB_FIELD_RD(o, nam, dxf) FIELD_RD (o.nam, dxf)
#  define SUB_FIELD_RL(o, nam, dxf) FIELDG (o.nam, RL, dxf)
#  define SUB_FIELD_RLL(o, nam, dxf) FIELDG (o.nam, RLL, dxf)
#  define SUB_FIELD_RS(o, nam, dxf) FIELDG (o.nam, RS, dxf)
#  define SUB_FIELD_RSx(o, nam, dxf) FIELD_RSx (o.nam, dxf)
#  define SUB_FIELD_T(o, nam, dxf) FIELD_T (o.nam, dxf)
#  define SUB_FIELD_TF(o, nam, len, dxf) FIELD_TF (o.nam, _obj->o.len, dxf)
#  define SUB_FIELD_TU(o, nam, dxf) FIELD_TU (o.nam, dxf)
#  define SUB_FIELD_TV(o, nam, dxf) FIELD_TV (o.nam, dxf)
#  define SUB_FIELD_VECTOR(o, nam, sizefield, type, dxf)                      \
  if (_obj->o.sizefield && _obj->o.nam)                                       \
    {                                                                         \
      BITCODE_BL _size = _obj->o.sizefield;                                   \
      for (vcount = 0; vcount < _size; vcount++)                              \
        {                                                                     \
          SUB_FIELD (o, nam[vcount], type, dxf);                              \
        }                                                                     \
    }
#  define SUB_FIELD_VECTOR_INL(o, nam, type, size, dxf)                       \
  SUB_FIELD_VECTOR_N(o, nam, type, size, dxf)
#  define SUB_FIELD_VECTOR_N(o, nam, type, size, dxf)                         \
  if (size > 0 && _obj->o.nam != NULL)                                        \
    {                                                                         \
      BITCODE_BL _size = (BITCODE_BL)size;                                    \
      for (vcount = 0; vcount < _size; vcount++)                              \
        {                                                                     \
          SUB_FIELD (o, nam[vcount], type, dxf);                              \
        }                                                                     \
    }
#  define SUB_FIELD_VECTOR_TYPESIZE(o, nam, size, typesize, dxf)              \
  if (_obj->o.size && _obj->o.nam)                                            \
    {                                                                         \
      for (vcount = 0; vcount < (BITCODE_BL)_obj->o.size; vcount++)           \
      {                                                                       \
        switch (typesize)                                                     \
          {                                                                   \
          case 0:                                                             \
            break;                                                            \
          case 1:                                                             \
            SUB_FIELD (o, nam[vcount], RC, dxf);                              \
            break;                                                            \
          case 2:                                                             \
            SUB_FIELD (o, nam[vcount], RS, dxf);                              \
            break;                                                            \
          case 4:                                                             \
            SUB_FIELD (o, nam[vcount], RL, dxf);                              \
            break;                                                            \
          case 8:                                                             \
            SUB_FIELD (o, nam[vcount], RLL, dxf);                             \
            break;                                                            \
          default:                                                            \
            LOG_ERROR ("Unkown SUB_FIELD_VECTOR_TYPE " #nam " typesize %d",   \
                       typesize);                                             \
            break;                                                            \
          }                                                                   \
      }                                                                       \
    }
#  define SUB_HANDLE_VECTOR(o, nam, sizefield, code, dxf)                     \
  if (_obj->o.sizefield && _obj->o.nam)                                       \
    {                                                                         \
      BITCODE_BL _size = _obj->o.sizefield;                                   \
      for (vcount = 0; vcount < _size; vcount++)                              \
        {                                                                     \
          SUB_FIELD_HANDLE (o, nam[vcount], code, dxf);                       \
        }                                                                     \
    }
#    define SUB_VALUEOUTOFBOUNDS(o,field, maxvalue)                           \
      if (_IN_RANGE (_obj->o.field, maxvalue)                                 \
          && _obj->o.field > maxvalue)                                        \
        {                                                                     \
          LOG_ERROR ("Invalid %s." #field " %lu", obj->name,                  \
                     (unsigned long)_obj->o.field);                           \
          _obj->o.field = 0;                                                  \
          return DWG_ERR_VALUEOUTOFBOUNDS;                                    \
        }
#  define TRACE_DD
#    define VALUEOUTOFBOUNDS(field, maxvalue)                                 \
      if (_IN_RANGE (_obj->field, maxvalue)                                   \
          && _obj->field > maxvalue)                                          \
        {                                                                     \
          LOG_ERROR ("Invalid %s." #field " %lu", obj->name,                  \
                     (unsigned long)_obj->field);                             \
          _obj->field = 0;                                                    \
          return DWG_ERR_VALUEOUTOFBOUNDS;                                    \
        }
#  define VALUE_2BD(value, dxf) VALUE_2RD(value, dxf)
#  define VALUE_2RD(value, dxf)
#  define VALUE_3BD(value, dxf)
#  define VALUE_3RD(value, dxf) VALUE_3BD (value, dxf)
#  define VALUE_B(value, dxf)
#  define VALUE_BINARY(value, len, dxf)
#  define VALUE_BL(value, dxf)
#  define VALUE_BS(value, dxf)
#  define VALUE_BSd(value, dxf)
#  define VALUE_HANDLE(value, nam, handle_code, dxf)
#  define VALUE_T0(name, dxf) VALUE_T (name, dxf)
#  define VALUE_TF(value, dxf)
#  define VALUE_TFF(value, dxf)
#  define VALUE_TV(value, dxf)
#  define VALUE_TV0(name, dxf) VALUE_TV (name, dxf)
#  define _DWG_FUNC_N(ACTION, name) dwg_##ACTION##_##name
#  define _DWG_PRIVATE_N(ACTION, name) dwg_##ACTION##_##name##_private
#  define _GNU_SOURCE
#  define _IN_RANGE(var, n)                                                   \
    ((sizeof (var) == 1 && n <= 0xff) || (sizeof (var) == 2 && n <= 0xffff)   \
     || (sizeof (var) >= 4))
#  define _REPEAT(times, name, type, idx)                                     \
    if (dat->version >= R_2000 && (BITCODE_BL)_obj->times > 20000)            \
      {                                                                       \
        LOG_ERROR ("Invalid %s." #name " rcount" #idx " %ld", SAFEDXFNAME,    \
                   (long)_obj->times);                                        \
        return DWG_ERR_VALUEOUTOFBOUNDS;                                      \
      }                                                                       \
    if (_obj->times > 0 && _obj->name != NULL)                                \
      for (rcount##idx = 0; rcount##idx < (BITCODE_BL)_obj->times;            \
           rcount##idx++)
#    define _REPEAT_C(times, name, type, idx)                                 \
      if (_obj->times > 0 && _obj->name != NULL)                              \
        for (rcount##idx = 0; rcount##idx < (BITCODE_BL)_obj->times;          \
             rcount##idx++)
#  define _REPEAT_CN(times, name, type, idx)                                  \
    if (_obj->name != NULL)                                                   \
      for (rcount##idx = 0; rcount##idx < (BITCODE_BL)times; rcount##idx++)
#  define _REPEAT_CNF(times, name, type, idx)                                 \
    if (_obj->name != NULL)                                                   \
      for (rcount##idx = 0; rcount##idx < (BITCODE_BL)times; rcount##idx++)
#  define _REPEAT_NF(times, name, type, idx)                                  \
    if (dat->version >= R_2000 && times > 0x7ff)                              \
      {                                                                       \
        LOG_ERROR ("Invalid %s." #name " rcount" #idx " %ld", SAFEDXFNAME,    \
                   (long)times);                                              \
        return DWG_ERR_VALUEOUTOFBOUNDS;                                      \
      }                                                                       \
    if (_obj->name != NULL)                                                   \
      for (rcount##idx = 0; rcount##idx < (BITCODE_BL)times; rcount##idx++)
#  define DWG_LOGLEVEL DWG_LOGLEVEL_ERROR
#define DWG_LOGLEVEL_ALL 9
#define DWG_LOGLEVEL_ERROR 1  
#define DWG_LOGLEVEL_HANDLE 4 
#define DWG_LOGLEVEL_INFO 2   
#define DWG_LOGLEVEL_INSANE 5 
#define DWG_LOGLEVEL_NONE 0   
#define DWG_LOGLEVEL_TRACE 3  
#define HANDLER fprintf
#  define LOG(args...) {}

#define LOG_ALL(args...) LOG (ALL, args)
#  define LOG_ERROR(args...) {}
#define LOG_HANDLE(args...) LOG (HANDLE, args)
#define LOG_INFO(args...) LOG (INFO, args)
#define LOG_INSANE(args...) LOG (INSANE, args)
#define LOG_TEXT32(level, wstr)                                               \
    {                                                                         \
      if (DWG_LOGLEVEL >= DWG_LOGLEVEL_##level && wstr)                       \
        {                                                                     \
          char *_u8 = bit_convert_TU (wstr);                                  \
          HANDLER (OUTPUT, "%s", _u8);                                        \
          free (_u8);                                                         \
        }                                                                     \
    }
#  define LOG_TEXT_UNICODE(level, args) LOG (level, args)
#define LOG_TRACE(args...) LOG (TRACE, args)
#  define LOG_TRACE_TU(s, wstr, dxf)                                          \
    LOG_TRACE ("%s: \"%ls\" [TU %d]", s, (wchar_t *)wstr, dxf)
#  define LOG_TRACE_TU_I(s, i, wstr, type, dxf)                               \
    LOG_TRACE ("%s[%d]: \"%ls\" [%s %d]", s, (int)i, (wchar_t *)wstr, #type, dxf)
#define LOG_TRACE_TW(s, wstr, dxf)                                            \
    LOG_TRACE ("%s: \"", s)                                                   \
    LOG_TEXT32 (TRACE, (BITCODE_TW)wstr)                                      \
    LOG_TRACE ("\" [TW %d]\n", dxf)
#  define LOG_WARN(args...) {}
#define OUTPUT stderr


#define EMPTY_CHAIN(size) { NULL, size, 0L, 0, 0, 0, 0, NULL }
#  define EXPORT
#define IS_FROM_TU(dat) (dat->from_version >= R_2007) && !(dat->opts & DWG_OPTS_IN)
#define IS_FROM_TU_DWG(dwg) (dwg->header.from_version >= R_2007) && !(dwg->opts & DWG_OPTS_IN)
#define TU_to_int(b) ((b[1] << 8) + b[0])
#define bit_chain_set_version(to, from)                                       \
  (to)->opts = (from)->opts;                                                  \
  (to)->version = (from)->version;                                            \
  (to)->from_version = (from)->from_version;                                  \
  (to)->fh = (from)->fh
#  define bit_wcs2cmp(dest, src) wcscmp (s1, s2)
#  define bit_wcs2cpy(dest, src) wcscpy (dest, src)
#  define bit_wcs2len(wstr) wcslen (wstr)
#    define bit_wcs2nlen(wstr, maxlen) wcsnlen (wstr, maxlen)
#define strnlen (str, maxlen) bit_strnlen(str, maxlen)
#define ACANGLECONSTRAINT_fields                \
  ACEXPLICITCONSTRAINT_fields;                  \
  BITCODE_RC sector_type  
#define ACCONSTRAINEDBOUNDEDELLIPSE_fields       \
  ACCONSTRAINEDELLIPSE_fields;                   \
  BITCODE_3BD start_pt;                  \
  BITCODE_3BD end_pt      
#define ACCONSTRAINEDELLIPSE_fields              \
  ACGEOMCONSTRAINT_fields;                       \
  BITCODE_3BD center;                    \
  BITCODE_3BD sm_axis;                   \
  BITCODE_BD axis_ratio 
#define ACCONSTRAINTGEOMETRY_fields(node)      \
  Dwg_CONSTRAINTGROUPNODE node;                \
  BITCODE_H geom_dep;              \
  BITCODE_BL nodeid   
#define ACCONSTRAINTIMPLICITPOINT_fields(node) \
  ACCONSTRAINTPOINT_fields (node);             \
      \
  BITCODE_RC point_type;              \
  BITCODE_BLd point_idx;   \
  BITCODE_BLd curve_id   
#define ACCONSTRAINTPOINT_fields(node)         \
  ACCONSTRAINTGEOMETRY_fields (node);          \
  SUBCLASS (AcConstraintPoint);                \
  BITCODE_3BD point 
#define ACDISTANCECONSTRAINT_fields              \
  ACEXPLICITCONSTRAINT_fields;                   \
  BITCODE_RC dir_type;  \
  BITCODE_3BD distance 
#define ACEXPLICITCONSTRAINT_fields            \
  ACGEOMCONSTRAINT_fields;                     \
  BITCODE_H value_dep;             \
  BITCODE_H dim_dep    
#define ACGEOMCONSTRAINT_fields                 \
  Dwg_CONSTRAINTGROUPNODE node;                 \
  BITCODE_BL ownerid;               \
  BITCODE_B is_implied;            \
  BITCODE_B is_active; 
#define ACPARALLELCONSTRAINT_fields             \
  ACGEOMCONSTRAINT_fields;                      \
  BITCODE_BLd datum_line_idx  
#define ANNOTSCALEOBJECTCONTEXTDATA_fields                                    \
  OBJECTCONTEXTDATA_fields;                                                   \
  BITCODE_H scale	
#define ARGS_H(hdl) (hdl).code, (hdl).size, (hdl).value
#define ARGS_REF(ref) (ref)->handleref.code, (ref)->handleref.size, \
    (ref)->handleref.value, (ref)->absolute_ref
#define ASSOCACTIONBODY_fields         \
  BITCODE_BL aab_version 
#define ASSOCACTIONPARAM_fields        \
  BITCODE_BS is_r2013;                 \
  BITCODE_BL aap_version;  \
  BITCODE_T  name         
#define ASSOCACTION_fields                                  \
                              \
  BITCODE_BS class_version;                         \
                                    \
  BITCODE_BL geometry_status;                       \
  BITCODE_H owningnetwork;                         \
  BITCODE_H actionbody;                            \
  BITCODE_BL action_index;                          \
  BITCODE_BL max_assoc_dep_index;                   \
  BITCODE_BL num_deps;                              \
  Dwg_ASSOCACTION_Deps *deps;               \
  BITCODE_BL num_owned_params;                      \
  BITCODE_H *owned_params;                         \
  BITCODE_BL num_values;                            \
  struct _dwg_VALUEPARAM *values
#define ASSOCANNOTATIONACTIONBODY_fields \
  BITCODE_BS aaab_version; \
  BITCODE_H assoc_dep; \
  BITCODE_BS aab_version; \
  BITCODE_H actionbody
#define ASSOCARRAYACTIONBODY_fields            \
  ASSOCACTIONBODY_fields;                      \
  Dwg_ASSOCPARAMBASEDACTIONBODY pab;           \
  BITCODE_BL aaab_version;                     \
  BITCODE_T paramblock;  \
  BITCODE_BD *transmatrix
#define ASSOCARRAYPARAMETERS_fields                           \
  BITCODE_BL aap_version;                                     \
  BITCODE_BL num_items;                                       \
  BITCODE_T classname;                                        \
  Dwg_ASSOCARRAYITEM *items
#define ASSOCCOMPOUNDACTIONPARAM_fields \
  BITCODE_BS class_version; \
  BITCODE_BS bs1; \
  BITCODE_BL num_params; \
  BITCODE_H *params; \
  BITCODE_B has_child_param; \
  BITCODE_BS child_status; \
  BITCODE_BL child_id; \
  BITCODE_H child_param; \
  BITCODE_H h330_2; \
  BITCODE_BL bl2; \
  BITCODE_H h330_3
#define ASSOCEDGEPERSSUBENTID_fields            \
  BITCODE_T classname;              \
  BITCODE_B has_classname;                      \
  BITCODE_BL bl1;                               \
  BITCODE_BS class_version;                     \
  BITCODE_BL index1;                            \
  BITCODE_BL index2;                            \
  BITCODE_B dependent_on_compound_object 
#define ASSOCINDEXPERSSUBENTID_fields            \
  BITCODE_T classname;              \
  BITCODE_B has_classname;                      \
  BITCODE_BL bl1;                               \
  BITCODE_BS class_version;                     \
  BITCODE_BL subent_type;                       \
  BITCODE_BL subent_index;                      \
  BITCODE_B dependent_on_compound_object 
#define ASSOCPARAMBASEDACTIONBODY_fields        \
  Dwg_ASSOCPARAMBASEDACTIONBODY pab
#define ASSOCPATHBASEDSURFACEACTIONBODY_fields \
  ASSOCACTIONBODY_fields;                      \
  Dwg_ASSOCPARAMBASEDACTIONBODY pab;           \
  Dwg_ASSOCSURFACEACTIONBODY sab;              \
      \
  BITCODE_BL pbsab_status 
#define ASSOCPERSSUBENTID_fields                \
  BITCODE_T classname;              \
  BITCODE_B dependent_on_compound_object 
#define BITCODE_3DVECTOR BITCODE_3BD_1
#define BITCODE_DOUBLE double
#define BITCODE_T  BITCODE_TV
#define BITCODE_T16 BITCODE_TV
#define BITCODE_T32 BITCODE_TV
#define BITCODE_TU32 BITCODE_TV
#define BLOCK1PTPARAMETER_fields                  \
  BLOCKPARAMETER_fields;                          \
  BITCODE_3BD def_pt;                             \
  BITCODE_BL num_propinfos;                \
  Dwg_BLOCKPARAMETER_PropInfo prop1;              \
  Dwg_BLOCKPARAMETER_PropInfo prop2
#define BLOCK2PTPARAMETER_fields                  \
  BLOCKPARAMETER_fields;                          \
  BITCODE_3BD def_basept;                         \
  BITCODE_3BD def_endpt;                          \
  Dwg_BLOCKPARAMETER_PropInfo prop1;              \
  Dwg_BLOCKPARAMETER_PropInfo prop2;              \
  Dwg_BLOCKPARAMETER_PropInfo prop3;              \
  Dwg_BLOCKPARAMETER_PropInfo prop4;              \
  BITCODE_BL *prop_states;                        \
  BITCODE_BS parameter_base_location;             \
  BITCODE_3BD upd_basept;                         \
  BITCODE_3BD basept;                             \
  BITCODE_3BD upd_endpt;                          \
  BITCODE_3BD endpt
#define BLOCKACTION_WITHBASEPT_fields(n)        \
  BLOCKACTION_fields;                           \
  BITCODE_3BD offset;                           \
  Dwg_BLOCKACTION_connectionpts conn_pts[n];    \
  BITCODE_B dependent;                          \
  BITCODE_3BD base_pt
#define BLOCKACTION_doubles_fields              \
  BITCODE_BD action_offset_x;                   \
  BITCODE_BD action_offset_y;                   \
  BITCODE_BD angle_offset
#define BLOCKACTION_fields                      \
  BLOCKELEMENT_fields;                          \
  BITCODE_3BD display_location;                 \
  BITCODE_BL num_actions;                       \
  BITCODE_BL *actions;                          \
  BITCODE_BL num_deps;                          \
  BITCODE_H *deps
#define BLOCKCONSTRAINTPARAMETER_fields         \
  BLOCK2PTPARAMETER_fields;                     \
  BITCODE_H dependency
#define BLOCKELEMENT_fields                     \
  Dwg_EvalExpr evalexpr;                        \
  BITCODE_T name;                               \
  BITCODE_BL be_major;                          \
  BITCODE_BL be_minor;                          \
  BITCODE_BL eed1071
#define BLOCKGRIP_fields                        \
  BLOCKELEMENT_fields;                          \
  BITCODE_BL bg_bl91;                           \
  BITCODE_BL bg_bl92;                           \
  BITCODE_3BD bg_location;                      \
  BITCODE_B bg_insert_cycling;                  \
  BITCODE_BLd bg_insert_cycling_weight
#define BLOCKLINEARCONSTRAINTPARAMETER_fields    \
  BLOCKCONSTRAINTPARAMETER_fields;               \
  BITCODE_T expr_name;                           \
  BITCODE_T expr_description;                    \
  BITCODE_BD value;                              \
  BLOCKPARAMVALUESET_fields
#define BLOCKPARAMETER_fields               \
  BLOCKELEMENT_fields;                      \
  BITCODE_B show_properties;   \
  BITCODE_B chain_actions    
#define BLOCKPARAMVALUESET_fields               \
  Dwg_BLOCKPARAMVALUESET value_set
#define CMLContent_fields                                                     \
  BITCODE_RC type;                                 \
  BITCODE_3BD normal;                                                         \
  BITCODE_3BD location;                                                       \
  BITCODE_BD rotation
#define COMMON_ENTITY_POLYLINE                                                \
  struct _dwg_object_entity *parent;                                          \
  BITCODE_B has_vertex;                                                       \
  BITCODE_BL num_owned;                                                       \
  BITCODE_H first_vertex;                                                     \
  BITCODE_H last_vertex;                                                      \
  BITCODE_H *vertex;                                                          \
  BITCODE_H seqend
#define COMMON_TABLE_CONTROL_FIELDS  \
  struct _dwg_object_object *parent; \
  BITCODE_BS num_entries;            \
  BITCODE_H* entries
#define COMMON_TABLE_FIELDS(laytype)      \
  struct _dwg_object_object *parent;      \
  BITCODE_##laytype flag;                 \
  BITCODE_T  name;                        \
  BITCODE_RS used;                        \
          \
  BITCODE_B  is_xref_ref;                 \
                \
  BITCODE_BS is_xref_resolved;  \
               \
  BITCODE_B  is_xref_dep;                 \
  BITCODE_H  xref
#define DIMENSION_COMMON                         \
  struct _dwg_object_entity *parent;             \
  BITCODE_RC class_version;          \
  BITCODE_BE extrusion;                          \
  BITCODE_3BD def_pt;                            \
  BITCODE_2RD text_midpt;                        \
  BITCODE_BD elevation;                          \
  BITCODE_RC flag;  \
  BITCODE_RC flag1;           \
  BITCODE_T user_text;                           \
  BITCODE_BD text_rotation;                      \
  BITCODE_BD horiz_dir;                          \
  BITCODE_3BD ins_scale;                         \
  BITCODE_BD ins_rotation;                       \
  BITCODE_BS attachment;                         \
  BITCODE_BS lspace_style;                       \
  BITCODE_BD lspace_factor;                      \
  BITCODE_BD act_measurement;                    \
  BITCODE_B unknown;                             \
  BITCODE_B flip_arrow1;                         \
  BITCODE_B flip_arrow2;                         \
  BITCODE_2RD clone_ins_pt;                      \
  BITCODE_H dimstyle;                            \
  BITCODE_H block
#  define DWGCHAR wchar_t
#define DWG_ERR_CRITICAL DWG_ERR_CLASSESNOTFOUND

#define DWG_OPTS_DXFB     0x20
#define DWG_OPTS_IN       (DWG_OPTS_INDXF | DWG_OPTS_INJSON)
#define DWG_OPTS_INDXF    0x40
#define DWG_OPTS_INJSON   0x80
#define DWG_OPTS_JSONFIRST 0x20
#define DWG_OPTS_LOGLEVEL 0xf
#define DWG_OPTS_MINIMAL  0x10
#define DWG_VERSIONS (int)(R_AFTER+1)
#define Dwg_Entity_3DSOLID Dwg_Entity__3DSOLID
#define FORMAT_3B "%u"
#define FORMAT_4BITS "%1x"
#define FORMAT_B "%d"
#define FORMAT_BB "%u"
#define FORMAT_BD "%f"
#define FORMAT_BL "%" PRIu32
#define FORMAT_BLL "%" PRIu64
#define FORMAT_BLX "%" PRIX32
#define FORMAT_BLd "%" PRId32
#define FORMAT_BLx "0x%" PRIx32
#define FORMAT_BS "%" PRIu16
#define FORMAT_BSd "%" PRId16
#define FORMAT_BSx "0x%" PRIx16
#define FORMAT_BT "%f"
#define FORMAT_D2T "%s"
#define FORMAT_DD "%f"
#define FORMAT_H "%u.%u.%lX"
#define FORMAT_MC  "%ld"
#define FORMAT_MS FORMAT_BL
# define FORMAT_RC "0x%2x"
#define FORMAT_RCd "%d"
#define FORMAT_RCu "%u"
#define FORMAT_RCx "0x%x"
#define FORMAT_RD "%f"
#define FORMAT_REF "(%u.%u.%lX) abs:%lX"
#define FORMAT_RL "%" PRIu32
#define FORMAT_RLL "0x%" PRIx64
#define FORMAT_RLd "%" PRId32
#define FORMAT_RLx "0x%" PRIx32
#define FORMAT_RS "%" PRIu16
#define FORMAT_RSx "0x%" PRIx16
#define FORMAT_T16 "\"%s\""
#define FORMAT_T32 "\"%s\""
#define FORMAT_TF "\"%s\""
# define FORMAT_TU "\"%ls\""
#define FORMAT_TU32 "\"%s\""
#define FORMAT_TV "\"%s\""
#define FORMAT_UMC "%lu"
#  define HAVE_NATIVE_WCHAR2
#define LIBREDWG_SO_VERSION    0:10:0
#define LIBREDWG_VERSION       ((LIBREDWG_VERSION_MAJOR * 100) + LIBREDWG_VERSION_MINOR)
#define LIBREDWG_VERSION_MAJOR 0
#define LIBREDWG_VERSION_MINOR 10
#define OBJECTCONTEXTDATA_fields                                              \
  struct _dwg_object_object *parent;                                          \
  BITCODE_BS class_version;                        \
  BITCODE_B is_default     
#define RENDERSETTINGS_fields                                                 \
                                                      \
  BITCODE_BL class_version;                         \
  BITCODE_T name;                                                \
  BITCODE_B fog_enabled;                                       \
  BITCODE_B fog_background_enabled;                            \
  BITCODE_B backfaces_enabled;                                 \
  BITCODE_B environ_image_enabled;                             \
  BITCODE_T environ_image_filename;                              \
  BITCODE_T description;                                         \
  BITCODE_BL display_index;                                    \
  BITCODE_B has_predefined          
# define SCANF_2X "%2X"
#define SWEEPOPTIONS_fields  \
  BITCODE_BD draft_angle;   	    \
  BITCODE_BD draft_start_distance;  \
  BITCODE_BD draft_end_distance;    \
  BITCODE_BD twist_angle;   	    \
  BITCODE_BD scale_factor;   \
  BITCODE_BD align_angle;    \
  BITCODE_BD* sweep_entity_transmatrix;  \
  BITCODE_BD* path_entity_transmatrix;   \
  BITCODE_B is_solid;           \
  BITCODE_BS sweep_alignment_flags;  \
  BITCODE_BS path_flags;                                  \
  BITCODE_B align_start;                         \
  BITCODE_B bank;                                \
  BITCODE_B base_point_set;                      \
  BITCODE_B sweep_entity_transform_computed;     \
  BITCODE_B path_entity_transform_computed;      \
  BITCODE_3BD reference_vector_for_controlling_twist;  \
  BITCODE_H sweep_entity; \
  BITCODE_H path_entity
#define TABLECONTENT_fields                                                   \
  Dwg_LinkedData ldata;                                                       \
  Dwg_LinkedTableData tdata;                                                  \
  Dwg_FormattedTableData fdata;                                               \
  BITCODE_H tablestyle
#define TEXTOBJECTCONTEXTDATA_fields \
  BITCODE_BS horizontal_mode;	 \
  BITCODE_BD rotation;		 \
  BITCODE_2RD ins_pt; 		 \
  BITCODE_2RD alignment_pt 	
#define _3DSOLID_FIELDS                                                 \
  BITCODE_B acis_empty;                                                 \
  BITCODE_B unknown;                                                    \
  BITCODE_BS version;                                                   \
  BITCODE_BL num_blocks;                                                \
  BITCODE_BL* block_size;                                               \
  char** encr_sat_data;                                                 \
  BITCODE_BL sab_size;                                                  \
  BITCODE_RC* acis_data;  \
  BITCODE_B wireframe_data_present;                                     \
  BITCODE_B point_present;                                              \
  BITCODE_3BD point;                                                    \
  BITCODE_BL isolines;                                  \
  BITCODE_B isoline_present;                         \
  BITCODE_BL num_wires;                                                 \
  Dwg_3DSOLID_wire * wires;                                             \
  BITCODE_BL num_silhouettes;                                           \
  Dwg_3DSOLID_silhouette * silhouettes;                                 \
  BITCODE_B _dxf_sab_converted;              \
  BITCODE_B acis_empty2;                                                \
  struct _dwg_entity_3DSOLID* extra_acis_data;                          \
  BITCODE_BL num_materials;                                             \
  Dwg_3DSOLID_material *materials;                                      \
  BITCODE_RC revision_guid[39];                                         \
  BITCODE_BL revision_major;                                            \
  BITCODE_BS revision_minor1;                                           \
  BITCODE_BS revision_minor2;                                           \
  BITCODE_RC revision_bytes[9];                                         \
  BITCODE_BL end_marker;                                                \
  BITCODE_H history_id;                                                 \
  BITCODE_B has_revision_guid;                                          \
  BITCODE_B acis_empty_bit
#  define dwg_wchar_t wchar_t
# define restrict __restrict
#  define AFL_GCC_POP \
    _Pragma ("GCC pop_options")
#  define AFL_GCC_TOOBIG __attribute__((optnone))
#define ARRAY_SIZE(arr) (int)(sizeof (arr) / sizeof ((arr)[0]))
#  define ATTRIBUTE_MALLOC __attribute__ ((malloc))
#  define ATTRIBUTE_NORETURN __attribute__ ((noreturn))
#  define CC_DIAG_PRAGMA(x) _Pragma (#x)
#  define CLANG_DIAG_IGNORE(x)                                                \
    _Pragma ("clang diagnostic push")                                         \
    CC_DIAG_PRAGMA (clang diagnostic ignored #x)
#  define CLANG_DIAG_RESTORE _Pragma ("clang diagnostic pop")





#  define GCC30_DIAG_IGNORE(x) CC_DIAG_PRAGMA (GCC diagnostic ignored #x)
#  define GCC31_DIAG_IGNORE(x) CC_DIAG_PRAGMA (GCC diagnostic ignored #x)
#  define GCC33_DIAG_IGNORE(x) CC_DIAG_PRAGMA (GCC diagnostic ignored #x)
#  define GCC46_DIAG_IGNORE(x)                                                \
     _Pragma ("GCC diagnostic push")                                          \
     CC_DIAG_PRAGMA (GCC diagnostic ignored #x)
#  define GCC46_DIAG_RESTORE _Pragma ("GCC diagnostic pop")
#  define HAVE_CC_DIAG_STACK
#  define HAVE_CLANG
#  define HAVE_NONNULL
#define LATER_VERSIONS else
#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#  define M_PI 3.14159265358979323846
#  define M_PI_2 1.57079632679489661923132169163975144
#define NOT_VERSION(v)                                                        \
  cur_ver = v;                                                                \
  if (dat->version != v)
#define OTHER_VERSIONS else
#define POP_HV(_obj, numfield, hvfield) _obj->hvfield[--_obj->numfield]
#define PRE(v)                                                                \
  cur_ver = v;                                                                \
  if (dat->version < v)
#define PRIOR_VERSIONS else
#define PUSH_HV(_obj, numfield, hvfield, ref)                                 \
  {                                                                           \
    _obj->hvfield = (BITCODE_H *)realloc (                                    \
        _obj->hvfield, (_obj->numfield + 1) * sizeof (BITCODE_H));            \
    _obj->hvfield[_obj->numfield] = ref;                                      \
    LOG_TRACE ("%s[%d] = " FORMAT_REF " [H]\n", #hvfield, _obj->numfield,     \
               ARGS_REF (_obj->hvfield[_obj->numfield]));                     \
    _obj->numfield++;                                                         \
  }
#define RESET_VER cur_ver = dat->version;
#  define RETURNS_NONNULL __attribute__ ((returns_nonnull))
#define SAFEDXFNAME (obj && obj->dxfname ? obj->dxfname : "")
#define SAFENAME(name) (name) ? (name) : ""
#define SHIFT_HV(_obj, numfield, hvfield) shift_hv (_obj->hvfield, &_obj->numfield)
#define SINCE(v)                                                              \
  cur_ver = v;                                                                \
  if (dat->version >= v)
#define TODO_DECODER HANDLER (OUTPUT, "TODO: Decoder\n");
#define TODO_ENCODER HANDLER (OUTPUT, "TODO: Encoder\n");
#define UNTIL(v)                                                              \
  cur_ver = v;                                                                \
  if (dat->version <= v)
#define VERSION(v)                                                            \
  cur_ver = v;                                                                \
  if (dat->version == v)
#define VERSIONS(v1, v2)                                                      \
  cur_ver = v1;                                                               \
  if (dat->version >= v1 && dat->version <= v2)
#  define _GNUC_VERSION (("__GNUC__" * 100) + "__GNUC_MINOR__")
#  define __has_feature(x) 0
#  define __nonnull(params)
#  define __nonnull_all __attribute__ ((__nonnull__))
#define deg2rad(ang) (ang) * M_PI_2 / 90.0
#define memBEGIN(s1, s2, len) (strlen (s1) >= len && !memcmp (s1, s2, len))
#define memBEGINc(s1, s2)                                                     \
  (strlen (s1) >= sizeof (s2 "") - 1 && !memcmp (s1, s2, sizeof (s2 "") - 1))
#define memmem my_memmem
#define rad2deg(ang) (ang) * 90.0 / M_PI_2
#define strEQ(s1, s2) !strcmp ((s1), (s2))
#define strEQc(s1, s2) !strcmp ((s1), s2 "")
#define strNE(s1, s2) strcmp ((s1), (s2))
#define strNEc(s1, s2) strcmp ((s1), s2 "")


#define REFS_PER_REALLOC 128


