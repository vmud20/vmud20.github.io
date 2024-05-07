








#include<memory>
#include<assert.h>






#include<typeinfo>
#include<set>
#include<map>








#include<algorithm>

#include<vector>






#define S3Protocol _S3Protocol

#define DERIVE_EXT_EXCEPTION(NAME, BASE) \
  class NAME : public BASE \
  { \
    EXT_EXCEPTION_METHODS(NAME, BASE) \
  };
#define DERIVE_FATAL_EXCEPTION(NAME, BASE) \
  class NAME : public BASE \
  { \
  public: \
    inline __fastcall NAME(Exception* E, UnicodeString Msg, UnicodeString HelpKeyword = L"") : \
      BASE(E, Msg, HelpKeyword) \
    { \
    } \
    virtual ExtException * __fastcall Clone() \
    { \
      return new NAME(this, L""); \
    } \
  };
#define EXT_EXCEPTION_METHODS(NAME, BASE) \
  public: \
    inline __fastcall NAME(Exception* E, UnicodeString Msg, UnicodeString HelpKeyword = L"") : \
      BASE(E, Msg, HelpKeyword) \
    { \
    } \
    inline __fastcall NAME(Exception* E, int Ident) : \
      BASE(E, Ident) \
    { \
    } \
    inline __fastcall virtual ~NAME(void) \
    { \
    } \
    inline __fastcall NAME(const UnicodeString Msg, const TVarRec * Args, const int Args_Size) : \
      BASE(Msg, Args, Args_Size) \
    { \
    } \
    inline __fastcall NAME(int Ident, const TVarRec * Args, const int Args_Size) : \
      BASE(Ident, Args, Args_Size) \
    { \
    } \
    inline __fastcall NAME(const UnicodeString Msg, int AHelpContext) : \
      BASE(Msg, AHelpContext) \
    { \
    } \
    inline __fastcall NAME(const UnicodeString Msg, const TVarRec * Args, const int Args_Size, int AHelpContext) : \
      BASE(Msg, Args, Args_Size, AHelpContext) \
    { \
    } \
    inline __fastcall NAME(int Ident, int AHelpContext) : \
      BASE(Ident, AHelpContext) \
    { \
    } \
    inline __fastcall NAME(PResStringRec ResStringRec, const TVarRec * Args, const int Args_Size, int AHelpContext) : \
      BASE(ResStringRec, Args, Args_Size, AHelpContext) \
    { \
    } \
    virtual ExtException * __fastcall Clone() \
    { \
      return new NAME(this, L""); \
    } \
    virtual void __fastcall Rethrow() \
    { \
      throw NAME(this, L""); \
    }


#define COMMAND_SWITCH L"Command"
#define DELETE_SWITCH L"delete"
#define FILEMASK_SWITCH L"filemask"
#define HELP_NONE ""
#define INI_NUL L"nul"

#define NEWERONLY_SWICH L"neweronly"
#define NEWPASSWORD_SWITCH L"newpassword"
#define NONEWERONLY_SWICH L"noneweronly"
#define NOPERMISSIONS_SWITCH L"nopermissions"
#define NOPRESERVETIME_SWITCH L"nopreservetime"
#define PERMISSIONS_SWITCH L"permissions"
#define PRESERVETIMEDIRS_SWITCH_VALUE L"all"
#define PRESERVETIME_SWITCH L"preservetime"
#define RAWTRANSFERSETTINGS_SWITCH L"rawtransfersettings"
#define REFRESH_SWITCH L"refresh"
#define RESUMESUPPORT_SWITCH L"resumesupport"
#define SCRIPT_SWITCH "script"
#define SESSIONNAME_SWICH L"SessionName"
#define SPEED_SWITCH L"speed"
#define TRANSFER_SWITCH L"transfer"
#define BUG_COUNT (sbChanReq+1)
#define CIPHER_COUNT (cipChaCha20+1)
#define FSPROTOCOL_COUNT (fsS3+1)
#define GSSLIB_COUNT (gssCustom+1)
#define HOSTKEY_COUNT (hkMax)
#define KEX_COUNT (kexECDH+1)
#define SFTP_BUG_COUNT (sbSignedTS+1)


#define SET_CONFIG_PROPERTY(PROPERTY) \
  SET_CONFIG_PROPERTY_EX(PROPERTY, )
#define SET_CONFIG_PROPERTY_EX(PROPERTY, APPLY) \
  if (PROPERTY != value) { F ## PROPERTY = value; Changed(); APPLY; }



#define FILETYPE_DEFAULT L'-'
#define FILETYPE_DIRECTORY L'D'
#define FILETYPE_SYMLINK L'L'
#define PARTIAL_EXT L".filepart"
#define ROOTDIRECTORY L"/"

#define SYMLINKSTR L" -> "


#define ASCOPY(dest, source) \
  { \
    AnsiString CopyBuf = source; \
    strncpy(dest, CopyBuf.c_str(), LENOF(dest)); \
    dest[LENOF(dest)-1] = '\0'; \
  }

#define EXCEPTION throw ExtException(NULL, L"")
#define NULL_TERMINATE(S) S[LENOF(S) - 1] = L'\0'
#define PARENTDIRECTORY L".."
#define SAFE_DESTROY(OBJ) SAFE_DESTROY_EX(TObject, OBJ)
#define SAFE_DESTROY_EX(CLASS, OBJ) { CLASS * PObj = OBJ; OBJ = NULL; delete PObj; }
#define SWAP(TYPE, FIRST, SECOND) \
  { TYPE __Backup = FIRST; FIRST = SECOND; SECOND = __Backup; }
#define THISDIRECTORY L"."
#define THROWOSIFFALSE(C) { if (!(C)) RaiseLastOSError(); }
#define ACCESS_VIOLATION_TEST { (*((int*)NULL)) = 0; }
#define DebugAlwaysFalse(p) (p)
#define DebugAlwaysTrue(p) (p)
#define DebugAssert(p)   ((void)0)
#define DebugCheck(p) (p)

#define DebugNotNull(p) (p)

#define DebugUsedParam(p) ((&p) == (&p))
#define FLAGCLEAR(SET, FLAG) (((SET) & (FLAG)) == 0)
#define FLAGMASK(ENABLE, FLAG) ((ENABLE) ? (FLAG) : 0)
#define FLAGSET(SET, FLAG) (((SET) & (FLAG)) == (FLAG))
#define FMTLOAD(I, F) FmtLoadStr(I, ARRAYOFCONST(F))
#define FORMAT(S, F) Format(S, ARRAYOFCONST(F))

#define LENOF(x) ( (sizeof((x))) / (sizeof(*(x))))
#define TraceInitPtr(p) (p)
#define TraceInitStr(p) (p)


#define new _new_


