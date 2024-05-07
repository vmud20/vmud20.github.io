


#include<stdio.h>
































#define BROWSE_SWITCH L"Browse"
#define COMREGISTRATION_SWITCH L"ComRegistration"
#define DEFAULTS_SWITCH L"Defaults"
#define DESKTOP_SWITCH L"Desktop"
#define DUMPCALLSTACK_EVENT L"WinSCPCallstack%d"
#define DUMPCALLSTACK_SWITCH L"DumpCallstack"
#define FINGERPRINTSCAN_SWITCH L"FingerprintScan"
#define HIDDEN_WINDOW_NAME L"WinSCPHiddenWindow3"
#define INFO_SWITCH L"Info"
#define INI_SWITCH L"Ini"
#define JUMPLIST_SWITCH L"JumpList"
#define KEEP_UP_TO_DATE_SWITCH L"KeepUpToDate"
#define KEYGEN_CHANGE_PASSPHRASE_SWITCH L"ChangePassphrase"
#define KEYGEN_COMMENT_SWITCH L"Comment"
#define KEYGEN_OUTPUT_SWITCH L"Output"
#define KEYGEN_SWITCH L"KeyGen"
#define LOGSIZE_SEPARATOR L"*"
#define LOGSIZE_SWITCH L"LogSize"
#define LOG_SWITCH L"Log"
#define NEWINSTANCE_SWICH L"NewInstance"
#define RAW_CONFIG_SWITCH L"RawConfig"
#define SEND_TO_HOOK_SWITCH L"SendToHook"
#define SITE_FOLDER_ICON 2
#define SITE_ICON 1
#define SYNCHRONIZE_SWITCH L"Synchronize"
#define UNSAFE_SWITCH L"Unsafe"
#define UPLOAD_IF_ANY_SWITCH L"UploadIfAny"
#define UPLOAD_SWITCH L"Upload"
#define WORKSPACE_ICON 3


#define C(Property) (Property != rhc.Property) ||


#define WM_CAN_DISPLAY_UPDATES (WM_WINSCP_USER + 9)
#define WM_MANAGES_CAPTION (WM_WINSCP_USER + 7)
#define WM_WANTS_MOUSEWHEEL (WM_WINSCP_USER + 8)
#define WM_WANTS_MOUSEWHEEL_INACTIVE (WM_WINSCP_USER + 11)
#define WM_WANTS_SCREEN_TIPS (WM_WINSCP_USER + 12)
#define WM_WINSCP_USER   (WM_USER + 0x2000)



#define INTERFACE_HOOK INTERFACE_HOOK_CUSTOM(TForm)
#define INTERFACE_HOOK_CUSTOM(PARENT) \
  protected: \
    virtual void __fastcall ReadState(TReader * Reader) \
    { \
      Reader->OnFindComponentClass = MakeMethod<TFindComponentClassEvent>(NULL, FindComponentClass); \
      PARENT::ReadState(Reader); \
    }

#define IUNKNOWN \
  virtual HRESULT __stdcall QueryInterface(const GUID& IID, void **Obj) \
  { \
    return TInterfacedObject::QueryInterface(IID, (void *)Obj); \
  } \
  \
  virtual ULONG __stdcall AddRef() \
  { \
    return TInterfacedObject::_AddRef(); \
  } \
  \
  virtual ULONG __stdcall Release() \
  { \
    return TInterfacedObject::_Release(); \
  }

