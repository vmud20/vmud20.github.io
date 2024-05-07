

#include<stdlib.h>































































#include<time.h>














#define PTR_MSG_TYPE_CACHED 0x0007
#define PTR_MSG_TYPE_COLOR 0x0006
#define PTR_MSG_TYPE_POINTER 0x0008
#define PTR_MSG_TYPE_POINTER_LARGE 0x0009
#define PTR_MSG_TYPE_POSITION 0x0003
#define PTR_MSG_TYPE_SYSTEM 0x0001
#define SYSPTR_DEFAULT 0x00007F00
#define SYSPTR_NULL 0x00000000

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define AltSecUpdate_Class (Update_Base + 4)
#define AltSecUpdate_CreateNineGridBitmap 3
#define AltSecUpdate_CreateOffscreenBitmap 1
#define AltSecUpdate_DrawGdiPlusCacheEnd 12
#define AltSecUpdate_DrawGdiPlusCacheFirst 10
#define AltSecUpdate_DrawGdiPlusCacheNext 11
#define AltSecUpdate_DrawGdiPlusEnd 9
#define AltSecUpdate_DrawGdiPlusFirst 7
#define AltSecUpdate_DrawGdiPlusNext 8
#define AltSecUpdate_FrameMarker 4
#define AltSecUpdate_StreamBitmapFirst 5
#define AltSecUpdate_StreamBitmapNext 6
#define AltSecUpdate_SwitchSurface 2
#define Channel_Base 20
#define CliprdrChannel_Class (Channel_Base + 2)
#define CliprdrChannel_ClipCaps 5
#define CliprdrChannel_DataRequest 3
#define CliprdrChannel_DataResponse 4
#define CliprdrChannel_FilecontentsRequest 6
#define CliprdrChannel_FilecontentsResponse 7
#define CliprdrChannel_FormatList 2
#define CliprdrChannel_LockClipdata 8
#define CliprdrChannel_MonitorReady 1
#define CliprdrChannel_TemporaryDirectory 10
#define CliprdrChannel_UnLockClipdata 9
#define DebugChannel_Class (Channel_Base + 1)
#define FREERDP_ALTSEC_UPDATE_CREATE_NINE_GRID_BITMAP \
	MakeMessageId(AltSecUpdate, CreateNineGridBitmap)
#define FREERDP_ALTSEC_UPDATE_CREATE_OFFSCREEN_BITMAP \
	MakeMessageId(AltSecUpdate, CreateOffscreenBitmap)
#define FREERDP_ALTSEC_UPDATE_DRAW_GDI_PLUS_CACHE_END \
	MakeMessageId(AltSecUpdate, DrawGdiPlusCacheEnd)
#define FREERDP_ALTSEC_UPDATE_DRAW_GDI_PLUS_CACHE_FIRST \
	MakeMessageId(AltSecUpdate, DrawGdiPlusCacheFirst)
#define FREERDP_ALTSEC_UPDATE_DRAW_GDI_PLUS_CACHE_NEXT \
	MakeMessageId(AltSecUpdate, DrawGdiPlusCacheNext)
#define FREERDP_ALTSEC_UPDATE_DRAW_GDI_PLUS_END MakeMessageId(AltSecUpdate, DrawGdiPlusEnd)
#define FREERDP_ALTSEC_UPDATE_DRAW_GDI_PLUS_FIRST MakeMessageId(AltSecUpdate, DrawGdiPlusFirst)
#define FREERDP_ALTSEC_UPDATE_DRAW_GDI_PLUS_NEXT MakeMessageId(AltSecUpdate, DrawGdiPlusNext)
#define FREERDP_ALTSEC_UPDATE_FRAME_MARKER MakeMessageId(AltSecUpdate, FrameMarker)
#define FREERDP_ALTSEC_UPDATE_STREAM_BITMAP_FIRST MakeMessageId(AltSecUpdate, StreamBitmapFirst)
#define FREERDP_ALTSEC_UPDATE_STREAM_BITMAP_NEXT MakeMessageId(AltSecUpdate, StreamBitmapNext)
#define FREERDP_ALTSEC_UPDATE_SWITCH_SURFACE MakeMessageId(AltSecUpdate, SwitchSurface)
#define FREERDP_CHANNEL_MESSAGE_QUEUE 3
#define FREERDP_CLIPRDR_CHANNEL_CLIP_CAPS MakeMessageId(CliprdrChannel, ClipCaps)
#define FREERDP_CLIPRDR_CHANNEL_DATA_REQUEST MakeMessageId(CliprdrChannel, DataRequest)
#define FREERDP_CLIPRDR_CHANNEL_DATA_RESPONSE MakeMessageId(CliprdrChannel, DataResponse)
#define FREERDP_CLIPRDR_CHANNEL_FORMAT_LIST MakeMessageId(CliprdrChannel, FormatList)
#define FREERDP_CLIPRDR_CHANNEL_MONITOR_READY MakeMessageId(CliprdrChannel, MonitorReady)

#define FREERDP_INPUT_EXTENDED_MOUSE_EVENT MakeMessageId(Input, ExtendedMouseEvent)
#define FREERDP_INPUT_FOCUS_IN_EVENT MakeMessageId(Input, FocusInEvent)
#define FREERDP_INPUT_KEYBOARD_EVENT MakeMessageId(Input, KeyboardEvent)
#define FREERDP_INPUT_KEYBOARD_PAUSE_EVENT MakeMessageId(Input, KeyboardPauseEvent)
#define FREERDP_INPUT_MESSAGE_QUEUE 2
#define FREERDP_INPUT_MOUSE_EVENT MakeMessageId(Input, MouseEvent)
#define FREERDP_INPUT_SYNCHRONIZE_EVENT MakeMessageId(Input, SynchronizeEvent)
#define FREERDP_INPUT_UNICODE_KEYBOARD_EVENT MakeMessageId(Input, UnicodeKeyboardEvent)
#define FREERDP_POINTER_UPDATE_ POINTER_POSITION MakeMessageId(PointerUpdate, PointerPosition)
#define FREERDP_POINTER_UPDATE_POINTER_CACHED MakeMessageId(PointerUpdate, PointerCached)
#define FREERDP_POINTER_UPDATE_POINTER_COLOR MakeMessageId(PointerUpdate, PointerColor)
#define FREERDP_POINTER_UPDATE_POINTER_LARGE MakeMessageId(PointerUpdate, PointerLarge)
#define FREERDP_POINTER_UPDATE_POINTER_NEW MakeMessageId(PointerUpdate, PointerNew)
#define FREERDP_POINTER_UPDATE_POINTER_SYSTEM MakeMessageId(PointerUpdate, PointerSystem)
#define FREERDP_PRIMARY_UPDATE_DRAW_NINE_GRID MakeMessageId(PrimaryUpdate, DrawNineGrid)
#define FREERDP_PRIMARY_UPDATE_DSTBLT MakeMessageId(PrimaryUpdate, DstBlt)
#define FREERDP_PRIMARY_UPDATE_ELLIPSE_CB MakeMessageId(PrimaryUpdate, EllipseCB)
#define FREERDP_PRIMARY_UPDATE_ELLIPSE_SC MakeMessageId(PrimaryUpdate, EllipseSC)
#define FREERDP_PRIMARY_UPDATE_FAST_GLYPH MakeMessageId(PrimaryUpdate, FastGlyph)
#define FREERDP_PRIMARY_UPDATE_FAST_INDEX MakeMessageId(PrimaryUpdate, FastIndex)
#define FREERDP_PRIMARY_UPDATE_GLYPH_INDEX MakeMessageId(PrimaryUpdate, GlyphIndex)
#define FREERDP_PRIMARY_UPDATE_LINE_TO MakeMessageId(PrimaryUpdate, LineTo)
#define FREERDP_PRIMARY_UPDATE_MEM3BLT MakeMessageId(PrimaryUpdate, Mem3Blt)
#define FREERDP_PRIMARY_UPDATE_MEMBLT MakeMessageId(PrimaryUpdate, MemBlt)
#define FREERDP_PRIMARY_UPDATE_MULTI_DRAW_NINE_GRID MakeMessageId(PrimaryUpdate, MultiDrawNineGrid)
#define FREERDP_PRIMARY_UPDATE_MULTI_DSTBLT MakeMessageId(PrimaryUpdate, MultiDstBlt)
#define FREERDP_PRIMARY_UPDATE_MULTI_OPAQUE_RECT MakeMessageId(PrimaryUpdate, MultiOpaqueRect)
#define FREERDP_PRIMARY_UPDATE_MULTI_PATBLT MakeMessageId(PrimaryUpdate, MultiPatBlt)
#define FREERDP_PRIMARY_UPDATE_MULTI_SCRBLT MakeMessageId(PrimaryUpdate, MultiScrBlt)
#define FREERDP_PRIMARY_UPDATE_OPAQUE_RECT MakeMessageId(PrimaryUpdate, OpaqueRect)
#define FREERDP_PRIMARY_UPDATE_PATBLT MakeMessageId(PrimaryUpdate, PatBlt)
#define FREERDP_PRIMARY_UPDATE_POLYGON_CB MakeMessageId(PrimaryUpdate, PolygonCB)
#define FREERDP_PRIMARY_UPDATE_POLYGON_SC MakeMessageId(PrimaryUpdate, PolygonSC)
#define FREERDP_PRIMARY_UPDATE_POLYLINE MakeMessageId(PrimaryUpdate, Polyline)
#define FREERDP_PRIMARY_UPDATE_SAVE_BITMAP MakeMessageId(PrimaryUpdate, SaveBitmap)
#define FREERDP_PRIMARY_UPDATE_SCRBLT MakeMessageId(PrimaryUpdate, ScrBlt)
#define FREERDP_RAIL_CHANNEL_CLIENT_ACTIVATE MakeMessageId(RailChannel, ClientActivate)
#define FREERDP_RAIL_CHANNEL_CLIENT_EXECUTE MakeMessageId(RailChannel, ClientExecute)
#define FREERDP_RAIL_CHANNEL_CLIENT_GET_APP_ID_REQUEST \
	MakeMessageId(RailChannel, ClientGetAppIdRequest)
#define FREERDP_RAIL_CHANNEL_CLIENT_HANDSHAKE MakeMessageId(RailChannel, ClientHandshake)
#define FREERDP_RAIL_CHANNEL_CLIENT_HANDSHAKE_EX MakeMessageId(RailChannel, ClientHandshakeEx)
#define FREERDP_RAIL_CHANNEL_CLIENT_INFORMATION MakeMessageId(RailChannel, ClientInformation)
#define FREERDP_RAIL_CHANNEL_CLIENT_LANGUAGE_BAR_INFO \
	MakeMessageId(RailChannel, ClientLanguageBarInfo)
#define FREERDP_RAIL_CHANNEL_CLIENT_NOTIFY_EVENT MakeMessageId(RailChannel, ClientNotifyEvent)
#define FREERDP_RAIL_CHANNEL_CLIENT_SYSTEM_COMMAND MakeMessageId(RailChannel, ClientSystemCommand)
#define FREERDP_RAIL_CHANNEL_CLIENT_SYSTEM_MENU MakeMessageId(RailChannel, ClientSystemMenu)
#define FREERDP_RAIL_CHANNEL_CLIENT_SYSTEM_PARAM MakeMessageId(RailChannel, ClientSystemParam)
#define FREERDP_RAIL_CHANNEL_CLIENT_WINDOW_MOVE MakeMessageId(RailChannel, ClientWindowMove)
#define FREERDP_RAIL_CHANNEL_GET_SYSTEM_PARAM MakeMessageId(RailChannel, GetSystemParam)
#define FREERDP_RAIL_CHANNEL_SERVER_EXECUTE_RESULT MakeMessageId(RailChannel, ServerExecuteResult)
#define FREERDP_RAIL_CHANNEL_SERVER_GET_APP_ID_RESPONSE \
	MakeMessageId(RailChannel, ServerGetAppIdResponse)
#define FREERDP_RAIL_CHANNEL_SERVER_HANDSHAKE MakeMessageId(RailChannel, ServerHandshake)
#define FREERDP_RAIL_CHANNEL_SERVER_HANDSHAKE_EX MakeMessageId(RailChannel, ServerHandshakeEx)
#define FREERDP_RAIL_CHANNEL_SERVER_LANGUAGE_BAR_INFO \
	MakeMessageId(RailChannel, ServerLanguageBarInfo)
#define FREERDP_RAIL_CHANNEL_SERVER_LOCAL_MOVE_SIZE MakeMessageId(RailChannel, ServerLocalMoveSize)
#define FREERDP_RAIL_CHANNEL_SERVER_MIN_MAX_INFO MakeMessageId(RailChannel, ServerMinMaxInfo)
#define FREERDP_RAIL_CHANNEL_SERVER_SYSTEM_PARAM MakeMessageId(RailChannel, ClientSystemParam)
#define FREERDP_RDPEI_CHANNEL_CLIENT_READY MakeMessageId(RdpeiChannel, ClientReady)
#define FREERDP_RDPEI_CHANNEL_DISMISS_HOVERING_CONTACT \
	MakeMessageId(RdpeiChannel, DismissHoveringContact)
#define FREERDP_RDPEI_CHANNEL_RESUME_TOUCH MakeMessageId(RdpeiChannel, ResumeTouch)
#define FREERDP_RDPEI_CHANNEL_SERVER_READY MakeMessageId(RdpeiChannel, ServerReady)
#define FREERDP_RDPEI_CHANNEL_SUSPEND_TOUCH MakeMessageId(RdpeiChannel, SuspendTouch)
#define FREERDP_RDPEI_CHANNEL_TOUCH_EVENT MakeMessageId(RdpeiChannel, TouchEvent)
#define FREERDP_SECONDARY_UPDATE_CACHE_BITMAP MakeMessageId(SecondaryUpdate, CacheBitmap)
#define FREERDP_SECONDARY_UPDATE_CACHE_BITMAP_V2 MakeMessageId(SecondaryUpdate, CacheBitmapV2)
#define FREERDP_SECONDARY_UPDATE_CACHE_BITMAP_V3 MakeMessageId(SecondaryUpdate, CacheBitmapV3)
#define FREERDP_SECONDARY_UPDATE_CACHE_BRUSH MakeMessageId(SecondaryUpdate, CacheBrush)
#define FREERDP_SECONDARY_UPDATE_CACHE_COLOR_TABLE MakeMessageId(SecondaryUpdate, CacheColorTable)
#define FREERDP_SECONDARY_UPDATE_CACHE_GLYPH MakeMessageId(SecondaryUpdate, CacheGlyph)
#define FREERDP_SECONDARY_UPDATE_CACHE_GLYPH_V2 MakeMessageId(SecondaryUpdate, CacheGlyphV2)
#define FREERDP_TSMF_CHANNEL_REDRAW MakeMessageId(TsmfChannel, Redraw)
#define FREERDP_TSMF_CHANNEL_VIDEO_FRAME MakeMessageId(TsmfChannel, VideoFrame)
#define FREERDP_UPDATE_ END_PAINT MakeMessageId(Update, EndPaint)
#define FREERDP_UPDATE_BEGIN_PAINT MakeMessageId(Update, BeginPaint)
#define FREERDP_UPDATE_BITMAP_UPDATE MakeMessageId(Update, BitmapUpdate)
#define FREERDP_UPDATE_DESKTOP_RESIZE MakeMessageId(Update, DesktopResize)
#define FREERDP_UPDATE_MESSAGE_QUEUE 1
#define FREERDP_UPDATE_PALETTE MakeMessageId(Update, Palette)
#define FREERDP_UPDATE_PLAY_SOUND MakeMessageId(Update, PlaySound)
#define FREERDP_UPDATE_REFRESH_RECT MakeMessageId(Update, RefreshRect)
#define FREERDP_UPDATE_SET_BOUNDS MakeMessageId(Update, SetBounds)
#define FREERDP_UPDATE_SET_KEYBOARD_INDICATORS MakeMessageId(Update, SetKeyboardIndicators)
#define FREERDP_UPDATE_SUPPRESS_OUTPUT MakeMessageId(Update, SuppressOutput)
#define FREERDP_UPDATE_SURFACE_BITS MakeMessageId(Update, SurfaceBits)
#define FREERDP_UPDATE_SURFACE_COMMAND MakeMessageId(Update, SurfaceCommand)
#define FREERDP_UPDATE_SURFACE_FRAME_ACKNOWLEDGE MakeMessageId(Update, SurfaceFrameAcknowledge)
#define FREERDP_UPDATE_SURFACE_FRAME_MARKER MakeMessageId(Update, SurfaceFrameMarker)
#define FREERDP_UPDATE_SYNCHRONIZE MakeMessageId(Update, Synchronize)
#define FREERDP_WINDOW_UPDATE_MONITORED_DESKTOP MakeMessageId(WindowUpdate, MonitoredDesktop)
#define FREERDP_WINDOW_UPDATE_NON_MONITORED_DESKTOP MakeMessageId(WindowUpdate, NonMonitoredDesktop)
#define FREERDP_WINDOW_UPDATE_NOTIFY_ICON_CREATE MakeMessageId(WindowUpdate, NotifyIconCreate)
#define FREERDP_WINDOW_UPDATE_NOTIFY_ICON_DELETE MakeMessageId(WindowUpdate, NotifyIconDelete)
#define FREERDP_WINDOW_UPDATE_NOTIFY_ICON_UPDATE MakeMessageId(WindowUpdate, NotifyIconUpdate)
#define FREERDP_WINDOW_UPDATE_WINDOW_CACHED_ICON MakeMessageId(WindowUpdate, WindowCachedIcon)
#define FREERDP_WINDOW_UPDATE_WINDOW_CREATE MakeMessageId(WindowUpdate, WindowCreate)
#define FREERDP_WINDOW_UPDATE_WINDOW_DELETE MakeMessageId(WindowUpdate, WindowDelete)
#define FREERDP_WINDOW_UPDATE_WINDOW_ICON MakeMessageId(WindowUpdate, WindowIcon)
#define FREERDP_WINDOW_UPDATE_WINDOW_UPDATE MakeMessageId(WindowUpdate, WindowUpdate)
#define GetMessageClass(_id) ((_id >> 16) & 0xFF)
#define GetMessageId(_class, _type) ((_class << 16) | _type)
#define GetMessageType(_id) (_id & 0xFF)
#define Input_Base 16
#define Input_Class (Input_Base + 1)
#define Input_ExtendedMouseEvent 5
#define Input_FocusInEvent 6
#define Input_KeyboardEvent 2
#define Input_KeyboardPauseEvent 7
#define Input_MouseEvent 4
#define Input_SynchronizeEvent 1
#define Input_UnicodeKeyboardEvent 3
#define MakeMessageId(_class, _type) (((_class##_Class) << 16) | (_class##_##_type))
#define PointerUpdate_Class (Update_Base + 6)
#define PointerUpdate_PointerCached 5
#define PointerUpdate_PointerColor 3
#define PointerUpdate_PointerLarge 6
#define PointerUpdate_PointerNew 4
#define PointerUpdate_PointerPosition 1
#define PointerUpdate_PointerSystem 2
#define PrimaryUpdate_Class (Update_Base + 2)
#define PrimaryUpdate_DrawNineGrid 5
#define PrimaryUpdate_DstBlt 1
#define PrimaryUpdate_EllipseCB 22
#define PrimaryUpdate_EllipseSC 21
#define PrimaryUpdate_FastGlyph 18
#define PrimaryUpdate_FastIndex 17
#define PrimaryUpdate_GlyphIndex 16
#define PrimaryUpdate_LineTo 11
#define PrimaryUpdate_Mem3Blt 14
#define PrimaryUpdate_MemBlt 13
#define PrimaryUpdate_MultiDrawNineGrid 10
#define PrimaryUpdate_MultiDstBlt 6
#define PrimaryUpdate_MultiOpaqueRect 9
#define PrimaryUpdate_MultiPatBlt 7
#define PrimaryUpdate_MultiScrBlt 8
#define PrimaryUpdate_OpaqueRect 4
#define PrimaryUpdate_PatBlt 2
#define PrimaryUpdate_PolygonCB 20
#define PrimaryUpdate_PolygonSC 19
#define PrimaryUpdate_Polyline 12
#define PrimaryUpdate_SaveBitmap 15
#define PrimaryUpdate_ScrBlt 3
#define RailChannel_Class (Channel_Base + 4)
#define RailChannel_ClientActivate 2
#define RailChannel_ClientExecute 1
#define RailChannel_ClientGetAppIdRequest 18
#define RailChannel_ClientHandshake 7
#define RailChannel_ClientHandshakeEx 20
#define RailChannel_ClientInformation 13
#define RailChannel_ClientLanguageBarInfo 15
#define RailChannel_ClientNotifyEvent 9
#define RailChannel_ClientSystemCommand 6
#define RailChannel_ClientSystemMenu 14
#define RailChannel_ClientSystemParam 4
#define RailChannel_ClientWindowMove 10
#define RailChannel_GetSystemParam 3
#define RailChannel_ServerExecuteResult 17
#define RailChannel_ServerGetAppIdResponse 19
#define RailChannel_ServerHandshake 8
#define RailChannel_ServerHandshakeEx 21
#define RailChannel_ServerLanguageBarInfo 16
#define RailChannel_ServerLocalMoveSize 11
#define RailChannel_ServerMinMaxInfo 12
#define RailChannel_ServerSystemParam 5
#define RdpeiChannel_Class (Channel_Base + 5)
#define RdpeiChannel_ClientReady 2
#define RdpeiChannel_DismissHoveringContact 6
#define RdpeiChannel_ResumeTouch 5
#define RdpeiChannel_ServerReady 1
#define RdpeiChannel_SuspendTouch 4
#define RdpeiChannel_TouchEvent 3
#define SecondaryUpdate_CacheBitmap 1
#define SecondaryUpdate_CacheBitmapV2 2
#define SecondaryUpdate_CacheBitmapV3 3
#define SecondaryUpdate_CacheBrush 7
#define SecondaryUpdate_CacheColorTable 4
#define SecondaryUpdate_CacheGlyph 5
#define SecondaryUpdate_CacheGlyphV2 6
#define SecondaryUpdate_Class (Update_Base + 3)
#define TsmfChannel_Class (Channel_Base + 3)
#define TsmfChannel_Redraw 2
#define TsmfChannel_VideoFrame 1
#define Update_Base 0
#define Update_BeginPaint 1
#define Update_BitmapUpdate 6
#define Update_Class (Update_Base + 1)
#define Update_DesktopResize 5
#define Update_EndPaint 2
#define Update_Palette 7
#define Update_PlaySound 8
#define Update_RefreshRect 9
#define Update_SetBounds 3
#define Update_SetKeyboardImeStatus 16
#define Update_SetKeyboardIndicators 15
#define Update_SuppressOutput 10
#define Update_SurfaceBits 12
#define Update_SurfaceCommand 11
#define Update_SurfaceFrameAcknowledge 14
#define Update_SurfaceFrameMarker 13
#define Update_Synchronize 4
#define WindowUpdate_Class (Update_Base + 5)
#define WindowUpdate_MonitoredDesktop 9
#define WindowUpdate_NonMonitoredDesktop 10
#define WindowUpdate_NotifyIconCreate 6
#define WindowUpdate_NotifyIconDelete 8
#define WindowUpdate_NotifyIconUpdate 7
#define WindowUpdate_WindowCachedIcon 4
#define WindowUpdate_WindowCreate 1
#define WindowUpdate_WindowDelete 5
#define WindowUpdate_WindowIcon 3
#define WindowUpdate_WindowUpdate 2
#define ALIGN64 __attribute__((aligned(8)))
#define AUDIO_MODE_NONE 2           
#define AUDIO_MODE_PLAY_ON_SERVER 1 
#define AUDIO_MODE_REDIRECT 0       
#define AUTO_RECONNECT_VERSION_1 0x00000001
#define CHANNEL_OPTION_COMPRESS 0x00400000
#define CHANNEL_OPTION_COMPRESS_RDP 0x00800000
#define CHANNEL_OPTION_ENCRYPT_CS 0x10000000
#define CHANNEL_OPTION_ENCRYPT_RDP 0x40000000
#define CHANNEL_OPTION_ENCRYPT_SC 0x20000000
#define CHANNEL_OPTION_INITIALIZED 0x80000000
#define CHANNEL_OPTION_PRI_HIGH 0x08000000
#define CHANNEL_OPTION_PRI_LOW 0x02000000
#define CHANNEL_OPTION_PRI_MED 0x04000000
#define CHANNEL_OPTION_SHOW_PROTOCOL 0x00200000
#define CHANNEL_REMOTE_CONTROL_PERSISTENT 0x00100000
#define CONNECTION_TYPE_AUTODETECT 0x07
#define CONNECTION_TYPE_BROADBAND_HIGH 0x04
#define CONNECTION_TYPE_BROADBAND_LOW 0x02
#define CONNECTION_TYPE_LAN 0x06
#define CONNECTION_TYPE_MODEM 0x01
#define CONNECTION_TYPE_SATELLITE 0x03
#define CONNECTION_TYPE_WAN 0x05
#define CS_CLUSTER 0xC004
#define CS_CORE 0xC001
#define CS_MCS_MSGCHANNEL 0xC006
#define CS_MONITOR 0xC005
#define CS_MONITOR_EX 0xC008
#define CS_MULTITRANSPORT 0xC00A
#define CS_NET 0xC003
#define CS_SECURITY 0xC002
#define DEFAULT_COOKIE_MAX_LENGTH 0xFF
#define ENCRYPTION_LEVEL_CLIENT_COMPATIBLE 0x00000002
#define ENCRYPTION_LEVEL_FIPS 0x00000004
#define ENCRYPTION_LEVEL_HIGH 0x00000003
#define ENCRYPTION_LEVEL_LOW 0x00000001
#define ENCRYPTION_LEVEL_NONE 0x00000000
#define ENCRYPTION_METHOD_128BIT 0x00000002
#define ENCRYPTION_METHOD_40BIT 0x00000001
#define ENCRYPTION_METHOD_56BIT 0x00000008
#define ENCRYPTION_METHOD_FIPS 0x00000010
#define ENCRYPTION_METHOD_NONE 0x00000000

#define FREERDP_SETTINGS_SERVER_MODE 0x00000001
#define FreeRDP_AcceptedCert (27)
#define FreeRDP_AcceptedCertLength (28)
#define FreeRDP_AllowCacheWaitingList (2499)
#define FreeRDP_AllowDesktopComposition (968)
#define FreeRDP_AllowFontSmoothing (961)
#define FreeRDP_AllowUnanouncedOrdersFromServer (2435)
#define FreeRDP_AllowedTlsCiphers (1101)
#define FreeRDP_AltSecFrameMarkerSupport (2434)
#define FreeRDP_AlternateShell (640)
#define FreeRDP_AssistanceFile (1729)
#define FreeRDP_AsyncChannels (1546)
#define FreeRDP_AsyncInput (1544)
#define FreeRDP_AsyncUpdate (1545)
#define FreeRDP_AudioCapture (715)
#define FreeRDP_AudioPlayback (714)
#define FreeRDP_Authentication (1092)
#define FreeRDP_AuthenticationLevel (1100)
#define FreeRDP_AuthenticationOnly (1603)
#define FreeRDP_AuthenticationServiceClass (1098)
#define FreeRDP_AutoAcceptCertificate (1419)
#define FreeRDP_AutoDenyCertificate (1420)
#define FreeRDP_AutoLogonEnabled (704)
#define FreeRDP_AutoReconnectMaxRetries (833)
#define FreeRDP_AutoReconnectionEnabled (832)
#define FreeRDP_BitmapCacheEnabled (2497)
#define FreeRDP_BitmapCachePersistEnabled (2500)
#define FreeRDP_BitmapCacheV2CellInfo (2502)
#define FreeRDP_BitmapCacheV2NumCells (2501)
#define FreeRDP_BitmapCacheV3CodecId (3904)
#define FreeRDP_BitmapCacheV3Enabled (2433)
#define FreeRDP_BitmapCacheVersion (2498)
#define FreeRDP_BitmapCompressionDisabled (2312)
#define FreeRDP_BrushSupportLevel (2688)
#define FreeRDP_CertificateAcceptedFingerprints (1421)
#define FreeRDP_CertificateContent (1416)
#define FreeRDP_CertificateFile (1410)
#define FreeRDP_CertificateName (1409)
#define FreeRDP_ChannelCount (256)
#define FreeRDP_ChannelDefArray (258)
#define FreeRDP_ChannelDefArraySize (257)
#define FreeRDP_ClientAddress (769)
#define FreeRDP_ClientAutoReconnectCookie (834)
#define FreeRDP_ClientBuild (133)
#define FreeRDP_ClientDir (770)
#define FreeRDP_ClientHostname (134)
#define FreeRDP_ClientProductId (135)
#define FreeRDP_ClientRandom (200)
#define FreeRDP_ClientRandomLength (201)
#define FreeRDP_ClientTimeZone (896)
#define FreeRDP_ClusterInfoFlags (320)
#define FreeRDP_ColorDepth (131)
#define FreeRDP_ColorPointerFlag (2560)
#define FreeRDP_CompDeskSupportLevel (3456)
#define FreeRDP_CompressionEnabled (705)
#define FreeRDP_CompressionLevel (721)
#define FreeRDP_ComputerName (1664)
#define FreeRDP_ConfigPath (1793)
#define FreeRDP_ConnectionFile (1728)
#define FreeRDP_ConnectionType (132)
#define FreeRDP_ConsoleSession (322)
#define FreeRDP_CookieMaxLength (1153)
#define FreeRDP_CredentialsFromStdin (1604)
#define FreeRDP_CurrentPath (1794)
#define FreeRDP_Decorations (1540)
#define FreeRDP_DesktopHeight (130)
#define FreeRDP_DesktopOrientation (147)
#define FreeRDP_DesktopPhysicalHeight (146)
#define FreeRDP_DesktopPhysicalWidth (145)
#define FreeRDP_DesktopPosX (390)
#define FreeRDP_DesktopPosY (391)
#define FreeRDP_DesktopResize (2368)
#define FreeRDP_DesktopScaleFactor (148)
#define FreeRDP_DesktopWidth (129)
#define FreeRDP_DeviceArray (4163)
#define FreeRDP_DeviceArraySize (4162)
#define FreeRDP_DeviceCount (4161)
#define FreeRDP_DeviceRedirection (4160)
#define FreeRDP_DeviceScaleFactor (149)
#define FreeRDP_DisableCredentialsDelegation (1099)
#define FreeRDP_DisableCtrlAltDel (706)
#define FreeRDP_DisableCursorBlinking (967)
#define FreeRDP_DisableCursorShadow (966)
#define FreeRDP_DisableFullWindowDrag (963)
#define FreeRDP_DisableMenuAnims (964)
#define FreeRDP_DisableRemoteAppCapsCheck (2121)
#define FreeRDP_DisableThemes (965)
#define FreeRDP_DisableWallpaper (962)
#define FreeRDP_Domain (23)
#define FreeRDP_DrawAllowColorSubsampling (2370)
#define FreeRDP_DrawAllowDynamicColorFidelity (2369)
#define FreeRDP_DrawAllowSkipAlpha (2371)
#define FreeRDP_DrawGdiPlusCacheEnabled (4033)
#define FreeRDP_DrawGdiPlusEnabled (4032)
#define FreeRDP_DrawNineGridCacheEntries (3970)
#define FreeRDP_DrawNineGridCacheSize (3969)
#define FreeRDP_DrawNineGridEnabled (3968)
#define FreeRDP_DrivesToRedirect (4290)
#define FreeRDP_DumpRemoteFx (1856)
#define FreeRDP_DumpRemoteFxFile (1858)
#define FreeRDP_DynamicChannelArray (5058)
#define FreeRDP_DynamicChannelArraySize (5057)
#define FreeRDP_DynamicChannelCount (5056)
#define FreeRDP_DynamicDSTTimeZoneKeyName (897)
#define FreeRDP_DynamicDaylightTimeDisabled (898)
#define FreeRDP_DynamicResolutionUpdate (1558)
#define FreeRDP_EarlyCapabilityFlags (136)
#define FreeRDP_EmbeddedWindow (1550)
#define FreeRDP_EnableWindowsKey (707)
#define FreeRDP_EncomspVirtualChannel (1029)
#define FreeRDP_EncryptionLevel (195)
#define FreeRDP_EncryptionMethods (193)
#define FreeRDP_ExtEncryptionMethods (194)
#define FreeRDP_ExtSecurity (1091)
#define FreeRDP_ExternalCertificateManagement (1415)
#define FreeRDP_FIPSMode (1104)
#define FreeRDP_FastPathInput (2630)
#define FreeRDP_FastPathOutput (2308)
#define FreeRDP_ForceEncryptedCsPdu (719)
#define FreeRDP_ForceMultimon (389)
#define FreeRDP_FragCache (2754)
#define FreeRDP_FrameAcknowledge (3714)
#define FreeRDP_FrameMarkerCommandEnabled (3521)
#define FreeRDP_Fullscreen (1537)
#define FreeRDP_GatewayAcceptedCert (1998)
#define FreeRDP_GatewayAcceptedCertLength (1999)
#define FreeRDP_GatewayAccessToken (1997)
#define FreeRDP_GatewayBypassLocal (1993)
#define FreeRDP_GatewayCredentialsSource (1990)
#define FreeRDP_GatewayDomain (1989)
#define FreeRDP_GatewayEnabled (1992)
#define FreeRDP_GatewayHostname (1986)
#define FreeRDP_GatewayHttpTransport (1995)
#define FreeRDP_GatewayPassword (1988)
#define FreeRDP_GatewayPort (1985)
#define FreeRDP_GatewayRpcTransport (1994)
#define FreeRDP_GatewayUdpTransport (1996)
#define FreeRDP_GatewayUsageMethod (1984)
#define FreeRDP_GatewayUseSameCredentials (1991)
#define FreeRDP_GatewayUsername (1987)
#define FreeRDP_GfxAVC444 (3845)
#define FreeRDP_GfxAVC444v2 (3847)
#define FreeRDP_GfxCapsFilter (3848)
#define FreeRDP_GfxH264 (3844)
#define FreeRDP_GfxProgressive (3842)
#define FreeRDP_GfxProgressiveV2 (3843)
#define FreeRDP_GfxSendQoeAck (3846)
#define FreeRDP_GfxSmallCache (3841)
#define FreeRDP_GfxThinClient (3840)
#define FreeRDP_GlyphCache (2753)
#define FreeRDP_GlyphSupportLevel (2752)
#define FreeRDP_GrabKeyboard (1539)
#define FreeRDP_HasExtendedMouseEvent (2635)
#define FreeRDP_HasHorizontalWheel (2634)
#define FreeRDP_HasMonitorAttributes (397)
#define FreeRDP_HiDefRemoteApp (720)
#define FreeRDP_HomePath (1792)
#define FreeRDP_IPv6Enabled (768)
#define FreeRDP_IgnoreCertificate (1408)
#define FreeRDP_ImeFileName (2628)
#define FreeRDP_JpegCodec (3776)
#define FreeRDP_JpegCodecId (3777)
#define FreeRDP_JpegQuality (3778)
#define FreeRDP_KerberosKdc (1344)
#define FreeRDP_KerberosRealm (1345)
#define FreeRDP_KeyboardCodePage (2623)
#define FreeRDP_KeyboardFunctionKey (2627)
#define FreeRDP_KeyboardHook (2633)
#define FreeRDP_KeyboardLayout (2624)
#define FreeRDP_KeyboardSubType (2626)
#define FreeRDP_KeyboardType (2625)
#define FreeRDP_LargePointerFlag (3392)
#define FreeRDP_ListMonitors (392)
#define FreeRDP_LoadBalanceInfo (1218)
#define FreeRDP_LoadBalanceInfoLength (1219)
#define FreeRDP_LocalConnection (1602)
#define FreeRDP_LogonErrors (710)
#define FreeRDP_LogonNotify (709)
#define FreeRDP_LongCredentialsSupported (2310)
#define FreeRDP_LyncRdpMode (1031)
#define FreeRDP_MaxTimeInCheckLoop (26)
#define FreeRDP_MaximizeShell (708)
#define FreeRDP_MonitorCount (384)
#define FreeRDP_MonitorDefArray (386)
#define FreeRDP_MonitorDefArraySize (385)
#define FreeRDP_MonitorIds (393)
#define FreeRDP_MonitorLocalShiftX (395)
#define FreeRDP_MonitorLocalShiftY (396)
#define FreeRDP_MouseAttached (711)
#define FreeRDP_MouseHasWheel (712)
#define FreeRDP_MouseMotion (1541)
#define FreeRDP_MstscCookieMode (1152)
#define FreeRDP_MultiTouchGestures (2632)
#define FreeRDP_MultiTouchInput (2631)
#define FreeRDP_MultifragMaxRequestSize (3328)
#define FreeRDP_MultitransportFlags (512)
#define FreeRDP_NSCodec (3712)
#define FreeRDP_NSCodecAllowDynamicColorFidelity (3717)
#define FreeRDP_NSCodecAllowSubsampling (3716)
#define FreeRDP_NSCodecColorLossLevel (3715)
#define FreeRDP_NSCodecId (3713)
#define FreeRDP_NegotiateSecurityLayer (1096)
#define FreeRDP_NegotiationFlags (1095)
#define FreeRDP_NetworkAutoDetect (137)
#define FreeRDP_NlaSecurity (1089)
#define FreeRDP_NoBitmapCompressionHeader (2311)
#define FreeRDP_NtlmSamFile (1103)
#define FreeRDP_NumMonitorIds (394)
#define FreeRDP_OffscreenCacheEntries (2818)
#define FreeRDP_OffscreenCacheSize (2817)
#define FreeRDP_OffscreenSupportLevel (2816)
#define FreeRDP_OldLicenseBehaviour (1606)
#define FreeRDP_OrderSupport (2432)
#define FreeRDP_OsMajorType (2304)
#define FreeRDP_OsMinorType (2305)
#define FreeRDP_ParentWindowId (1543)
#define FreeRDP_Password (22)
#define FreeRDP_Password51 (1280)
#define FreeRDP_Password51Length (1281)
#define FreeRDP_PasswordHash (24)
#define FreeRDP_PasswordIsSmartcardPin (717)
#define FreeRDP_PduSource (18)
#define FreeRDP_PercentScreen (1538)
#define FreeRDP_PercentScreenUseHeight (1557)
#define FreeRDP_PercentScreenUseWidth (1556)
#define FreeRDP_PerformanceFlags (960)
#define FreeRDP_PlayRemoteFx (1857)
#define FreeRDP_PlayRemoteFxFile (1859)
#define FreeRDP_PointerCacheSize (2561)
#define FreeRDP_PreconnectionBlob (1155)
#define FreeRDP_PreconnectionId (1154)
#define FreeRDP_PreferIPv6OverIPv4 (4674)
#define FreeRDP_PrintReconnectCookie (836)
#define FreeRDP_PrivateKeyContent (1417)
#define FreeRDP_PrivateKeyFile (1411)
#define FreeRDP_PromptForCredentials (1283)
#define FreeRDP_ProxyHostname (2016)
#define FreeRDP_ProxyPassword (2019)
#define FreeRDP_ProxyPort (2017)
#define FreeRDP_ProxyType (2015)
#define FreeRDP_ProxyUsername (2018)
#define FreeRDP_RDP2TCPArgs (5189)
#define FreeRDP_RdpKeyContent (1418)
#define FreeRDP_RdpKeyFile (1412)
#define FreeRDP_RdpSecurity (1090)
#define FreeRDP_RdpServerCertificate (1414)
#define FreeRDP_RdpServerRsaKey (1413)
#define FreeRDP_RdpVersion (128)
#define FreeRDP_ReceivedCapabilities (2240)
#define FreeRDP_ReceivedCapabilitiesSize (2241)
#define FreeRDP_RedirectClipboard (4800)
#define FreeRDP_RedirectDrives (4288)
#define FreeRDP_RedirectHomeDrive (4289)
#define FreeRDP_RedirectParallelPorts (4673)
#define FreeRDP_RedirectPrinters (4544)
#define FreeRDP_RedirectSerialPorts (4672)
#define FreeRDP_RedirectSmartCards (4416)
#define FreeRDP_RedirectedSessionId (321)
#define FreeRDP_RedirectionAcceptedCert (1231)
#define FreeRDP_RedirectionAcceptedCertLength (1232)
#define FreeRDP_RedirectionDomain (1221)
#define FreeRDP_RedirectionFlags (1216)
#define FreeRDP_RedirectionPassword (1222)
#define FreeRDP_RedirectionPasswordLength (1223)
#define FreeRDP_RedirectionPreferType (1233)
#define FreeRDP_RedirectionTargetFQDN (1224)
#define FreeRDP_RedirectionTargetNetBiosName (1225)
#define FreeRDP_RedirectionTsvUrl (1226)
#define FreeRDP_RedirectionTsvUrlLength (1227)
#define FreeRDP_RedirectionUsername (1220)
#define FreeRDP_RefreshRect (2306)
#define FreeRDP_RemdeskVirtualChannel (1030)
#define FreeRDP_RemoteAppLanguageBarSupported (2124)
#define FreeRDP_RemoteAppNumIconCacheEntries (2123)
#define FreeRDP_RemoteAppNumIconCaches (2122)
#define FreeRDP_RemoteApplicationCmdLine (2118)
#define FreeRDP_RemoteApplicationExpandCmdLine (2119)
#define FreeRDP_RemoteApplicationExpandWorkingDir (2120)
#define FreeRDP_RemoteApplicationFile (2116)
#define FreeRDP_RemoteApplicationGuid (2117)
#define FreeRDP_RemoteApplicationIcon (2114)
#define FreeRDP_RemoteApplicationMode (2112)
#define FreeRDP_RemoteApplicationName (2113)
#define FreeRDP_RemoteApplicationProgram (2115)
#define FreeRDP_RemoteApplicationSupportLevel (2126)
#define FreeRDP_RemoteApplicationSupportMask (2127)
#define FreeRDP_RemoteApplicationWorkingDir (2128)
#define FreeRDP_RemoteAssistanceMode (1024)
#define FreeRDP_RemoteAssistancePassStub (1026)
#define FreeRDP_RemoteAssistancePassword (1027)
#define FreeRDP_RemoteAssistanceRCTicket (1028)
#define FreeRDP_RemoteAssistanceRequestControl (1032)
#define FreeRDP_RemoteAssistanceSessionId (1025)
#define FreeRDP_RemoteConsoleAudio (713)
#define FreeRDP_RemoteFxCaptureFlags (3653)
#define FreeRDP_RemoteFxCodec (3649)
#define FreeRDP_RemoteFxCodecId (3650)
#define FreeRDP_RemoteFxCodecMode (3651)
#define FreeRDP_RemoteFxImageCodec (3652)
#define FreeRDP_RemoteFxOnly (3648)
#define FreeRDP_RemoteWndSupportLevel (2125)
#define FreeRDP_RequestedProtocols (1093)
#define FreeRDP_RestrictedAdminModeRequired (1097)
#define FreeRDP_SaltedChecksum (2309)
#define FreeRDP_SelectedProtocol (1094)
#define FreeRDP_SendPreconnectionPdu (1156)
#define FreeRDP_ServerAutoReconnectCookie (835)
#define FreeRDP_ServerCertificate (198)
#define FreeRDP_ServerCertificateLength (199)
#define FreeRDP_ServerHostname (20)
#define FreeRDP_ServerMode (16)
#define FreeRDP_ServerPort (19)
#define FreeRDP_ServerRandom (196)
#define FreeRDP_ServerRandomLength (197)
#define FreeRDP_ShareId (17)
#define FreeRDP_ShellWorkingDirectory (641)
#define FreeRDP_SmartSizing (1551)
#define FreeRDP_SmartSizingHeight (1555)
#define FreeRDP_SmartSizingWidth (1554)
#define FreeRDP_SmartcardLogon (1282)
#define FreeRDP_SoftwareGdi (1601)
#define FreeRDP_SoundBeepsEnabled (2944)
#define FreeRDP_SpanMonitors (387)
#define FreeRDP_StaticChannelArray (4930)
#define FreeRDP_StaticChannelArraySize (4929)
#define FreeRDP_StaticChannelCount (4928)
#define FreeRDP_SupportAsymetricKeys (138)
#define FreeRDP_SupportDisplayControl (5185)
#define FreeRDP_SupportDynamicChannels (5059)
#define FreeRDP_SupportDynamicTimeZone (143)
#define FreeRDP_SupportEchoChannel (5184)
#define FreeRDP_SupportErrorInfoPdu (139)
#define FreeRDP_SupportGeometryTracking (5186)
#define FreeRDP_SupportGraphicsPipeline (142)
#define FreeRDP_SupportHeartbeatPdu (144)
#define FreeRDP_SupportMonitorLayoutPdu (141)
#define FreeRDP_SupportMultitransport (513)
#define FreeRDP_SupportSSHAgentChannel (5187)
#define FreeRDP_SupportStatusInfoPdu (140)
#define FreeRDP_SupportVideoOptimized (5188)
#define FreeRDP_SuppressOutput (2307)
#define FreeRDP_SurfaceCommandsEnabled (3520)
#define FreeRDP_SurfaceFrameMarkerEnabled (3522)
#define FreeRDP_TargetNetAddress (1217)
#define FreeRDP_TargetNetAddressCount (1228)
#define FreeRDP_TargetNetAddresses (1229)
#define FreeRDP_TargetNetPorts (1230)
#define FreeRDP_TcpAckTimeout (5194)
#define FreeRDP_TcpKeepAlive (5190)
#define FreeRDP_TcpKeepAliveDelay (5192)
#define FreeRDP_TcpKeepAliveInterval (5193)
#define FreeRDP_TcpKeepAliveRetries (5191)
#define FreeRDP_TlsSecLevel (1105)
#define FreeRDP_TlsSecurity (1088)
#define FreeRDP_ToggleFullscreen (1548)
#define FreeRDP_UnicodeInput (2629)
#define FreeRDP_UnmapButtons (1605)
#define FreeRDP_UseMultimon (388)
#define FreeRDP_UseRdpSecurityLayer (192)
#define FreeRDP_Username (21)
#define FreeRDP_UsingSavedCredentials (718)
#define FreeRDP_VideoDisable (716)
#define FreeRDP_VirtualChannelChunkSize (2881)
#define FreeRDP_VirtualChannelCompressionFlags (2880)
#define FreeRDP_VmConnectMode (1102)
#define FreeRDP_WaitForOutputBufferFlush (25)
#define FreeRDP_WindowTitle (1542)
#define FreeRDP_WmClass (1549)
#define FreeRDP_Workarea (1536)
#define FreeRDP_XPan (1552)
#define FreeRDP_YPan (1553)
#define FreeRDP_instance (0)
#define GLYPH_SUPPORT_ENCODE 0x0003
#define GLYPH_SUPPORT_FULL 0x0002
#define GLYPH_SUPPORT_NONE 0x0000
#define GLYPH_SUPPORT_PARTIAL 0x0001
#define KEYBOARD_HOOK_FULLSCREEN_ONLY 2
#define KEYBOARD_HOOK_LOCAL 0
#define KEYBOARD_HOOK_REMOTE 1
#define LB_CLIENT_TSV_URL 0x00001000
#define LB_DOMAIN 0x00000008
#define LB_DONTSTOREUSERNAME 0x00000020
#define LB_LOAD_BALANCE_INFO 0x00000002
#define LB_NOREDIRECT 0x00000080
#define LB_PASSWORD 0x00000010
#define LB_PASSWORD_MAX_LENGTH 512
#define LB_SERVER_TSV_CAPABLE 0x00002000
#define LB_SMARTCARD_LOGON 0x00000040
#define LB_TARGET_FQDN 0x00000100
#define LB_TARGET_NETBIOS_NAME 0x00000200
#define LB_TARGET_NET_ADDRESS 0x00000001
#define LB_TARGET_NET_ADDRESSES 0x00000800
#define LB_USERNAME 0x00000004
#define LOGON_FAILED_BAD_PASSWORD 0x00000000
#define LOGON_FAILED_OTHER 0x00000002
#define LOGON_FAILED_UPDATE_PASSWORD 0x00000001
#define LOGON_MSG_BUMP_OPTIONS 0xFFFFFFFB
#define LOGON_MSG_DISCONNECT_REFUSED 0xFFFFFFF9
#define LOGON_MSG_NO_PERMISSION 0xFFFFFFFA
#define LOGON_MSG_RECONNECT_OPTIONS 0xFFFFFFFC
#define LOGON_MSG_SESSION_CONTINUE 0xFFFFFFFE
#define LOGON_MSG_SESSION_TERMINATE 0xFFFFFFFD
#define LOGON_WARNING 0x00000003
#define MONITOR_PRIMARY 0x00000001
#define MSTSC_COOKIE_MAX_LENGTH 9
#define NEG_AEXTTEXTOUT_INDEX 0x06  
#define NEG_ATEXTOUT_INDEX 0x05
#define NEG_DRAWNINEGRID_INDEX 0x07 
#define NEG_DSTBLT_INDEX 0x00
#define NEG_ELLIPSE_CB_INDEX 0x1A
#define NEG_ELLIPSE_SC_INDEX 0x19
#define NEG_FAST_GLYPH_INDEX 0x18
#define NEG_FAST_INDEX_INDEX 0x13
#define NEG_GLYPH_INDEX_INDEX 0x1B
#define NEG_GLYPH_WEXTTEXTOUT_INDEX 0x1C     
#define NEG_GLYPH_WLONGEXTTEXTOUT_INDEX 0x1E 
#define NEG_GLYPH_WLONGTEXTOUT_INDEX 0x1D    
#define NEG_LINETO_INDEX 0x08
#define NEG_MEM3BLT_INDEX 0x04
#define NEG_MEM3BLT_V2_INDEX 0x0E 
#define NEG_MEMBLT_INDEX 0x03
#define NEG_MEMBLT_V2_INDEX 0x0D  
#define NEG_MULTIDSTBLT_INDEX 0x0F
#define NEG_MULTIOPAQUERECT_INDEX 0x12
#define NEG_MULTIPATBLT_INDEX 0x10
#define NEG_MULTISCRBLT_INDEX 0x11
#define NEG_MULTI_DRAWNINEGRID_INDEX 0x09
#define NEG_OPAQUE_RECT_INDEX 0x0A 
#define NEG_PATBLT_INDEX 0x01
#define NEG_POLYGON_CB_INDEX 0x15
#define NEG_POLYGON_SC_INDEX 0x14
#define NEG_POLYLINE_INDEX 0x16
#define NEG_SAVEBITMAP_INDEX 0x0B
#define NEG_SCRBLT_INDEX 0x02
#define NEG_UNUSED23_INDEX 0x17 
#define NEG_UNUSED31_INDEX 0x1F              
#define NEG_WTEXTOUT_INDEX 0x0C   
#define ORIENTATION_LANDSCAPE 0
#define ORIENTATION_LANDSCAPE_FLIPPED 180
#define ORIENTATION_PORTRAIT 90
#define ORIENTATION_PORTRAIT_FLIPPED 270
#define PACKET_COMPR_TYPE_64K 0x01
#define PACKET_COMPR_TYPE_8K 0x00
#define PACKET_COMPR_TYPE_RDP6 0x02
#define PACKET_COMPR_TYPE_RDP61 0x03
#define PACKET_COMPR_TYPE_RDP8 0x04
#define PERF_DISABLE_CURSORSETTINGS 0x00000040
#define PERF_DISABLE_CURSOR_SHADOW 0x00000020
#define PERF_DISABLE_FULLWINDOWDRAG 0x00000002
#define PERF_DISABLE_MENUANIMATIONS 0x00000004
#define PERF_DISABLE_THEMING 0x00000008
#define PERF_DISABLE_WALLPAPER 0x00000001
#define PERF_ENABLE_DESKTOP_COMPOSITION 0x00000100
#define PERF_ENABLE_FONT_SMOOTHING 0x00000080
#define PERF_FLAG_NONE 0x00000000
#define PROXY_TYPE_HTTP 1
#define PROXY_TYPE_IGNORE 0xFFFF
#define PROXY_TYPE_NONE 0
#define PROXY_TYPE_SOCKS 2
#define RAIL_LEVEL_DOCKED_LANGBAR_SUPPORTED 0x00000002
#define RAIL_LEVEL_HANDSHAKE_EX_SUPPORTED 0x00000080
#define RAIL_LEVEL_HIDE_MINIMIZED_APPS_SUPPORTED 0x00000020
#define RAIL_LEVEL_LANGUAGE_IME_SYNC_SUPPORTED 0x00000008
#define RAIL_LEVEL_SERVER_TO_CLIENT_IME_SYNC_SUPPORTED 0x00000010
#define RAIL_LEVEL_SHELL_INTEGRATION_SUPPORTED 0x00000004
#define RAIL_LEVEL_SUPPORTED 0x00000001
#define RAIL_LEVEL_WINDOW_CLOAKING_SUPPORTED 0x00000040
#define RDPDR_DTYP_FILESYSTEM 0x00000008
#define RDPDR_DTYP_PARALLEL 0x00000002
#define RDPDR_DTYP_PRINT 0x00000004
#define RDPDR_DTYP_SERIAL 0x00000001
#define RDPDR_DTYP_SMARTCARD 0x00000020
#define REDIRECTED_SESSIONID_FIELD_VALID 0x00000002
#define REDIRECTED_SMARTCARD 0x00000040
#define REDIRECTION_SUPPORTED 0x00000001
#define REDIRECTION_VERSION1 0x00
#define REDIRECTION_VERSION2 0x01
#define REDIRECTION_VERSION3 0x02
#define REDIRECTION_VERSION4 0x03
#define REDIRECTION_VERSION5 0x04
#define REDIRECTION_VERSION6 0x05
#define RNS_UD_15BPP_SUPPORT 0x0004
#define RNS_UD_16BPP_SUPPORT 0x0002
#define RNS_UD_24BPP_SUPPORT 0x0001
#define RNS_UD_32BPP_SUPPORT 0x0008
#define RNS_UD_COLOR_16BPP_555 0xCA02
#define RNS_UD_COLOR_16BPP_565 0xCA03
#define RNS_UD_COLOR_24BPP 0xCA04
#define RNS_UD_COLOR_4BPP 0xCA00
#define RNS_UD_COLOR_8BPP 0xCA01
#define RNS_UD_CS_STRONG_ASYMMETRIC_KEYS 0x0008
#define RNS_UD_CS_SUPPORT_DYNAMIC_TIME_ZONE 0x0200
#define RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL 0x0100
#define RNS_UD_CS_SUPPORT_ERRINFO_PDU 0x0001
#define RNS_UD_CS_SUPPORT_HEARTBEAT_PDU 0x0400
#define RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU 0x0040
#define RNS_UD_CS_SUPPORT_NETWORK_AUTODETECT 0x0080
#define RNS_UD_CS_SUPPORT_STATUSINFO_PDU 0x0004
#define RNS_UD_CS_VALID_CONNECTION_TYPE 0x0020
#define RNS_UD_CS_WANT_32BPP_SESSION 0x0002
#define RNS_UD_SAS_DEL 0xAA03
#define RNS_UD_SC_DYNAMIC_DST_SUPPORTED 0x00000002
#define RNS_UD_SC_EDGE_ACTIONS_SUPPORTED 0x00000001
#define SC_CORE 0x0C01
#define SC_MCS_MSGCHANNEL 0x0C04
#define SC_MULTITRANSPORT 0x0C08
#define SC_NET 0x0C03
#define SC_SECURITY 0x0C02
#define STATUS_BRINGING_SESSION_ONLINE 0x00000403
#define STATUS_FINDING_DESTINATION 0x00000401
#define STATUS_LOADING_DESTINATION 0x00000402
#define STATUS_REDIRECTING_TO_DESTINATION 0x00000404
#define STATUS_VM_BOOTING 0x00000503
#define STATUS_VM_LOADING 0x00000501
#define STATUS_VM_WAKING 0x00000502
#define TRANSPORT_TYPE_UDP_FECL 0x00000004
#define TRANSPORT_TYPE_UDP_FECR 0x00000001
#define TRANSPORT_TYPE_UDP_PREFERRED 0x00000100
#define TSC_PROXY_CREDS_MODE_ANY 0x2
#define TSC_PROXY_CREDS_MODE_SMARTCARD 0x1
#define TSC_PROXY_CREDS_MODE_USERPASS 0x0
#define TSC_PROXY_MODE_DEFAULT 0x3
#define TSC_PROXY_MODE_DETECT 0x2
#define TSC_PROXY_MODE_DIRECT 0x1
#define TSC_PROXY_MODE_NONE_DETECT 0x4
#define TSC_PROXY_MODE_NONE_DIRECT 0x0
#define FREERDP_API __attribute__((dllexport))

#define FREERDP_CC __cdecl
#define FREERDP_LOCAL FREERDP_API
#define FREERDP_TEST_API FREERDP_API
#define IFCALL(_cb, ...)      \
	do                        \
	{                         \
		if (_cb != NULL)      \
		{                     \
			_cb(__VA_ARGS__); \
		}                     \
	} while (0)
#define IFCALLRESULT(_default_return, _cb, ...) \
	((_cb != NULL) ? _cb(__VA_ARGS__) : (_default_return))
#define IFCALLRET(_cb, _ret, ...)    \
	do                               \
	{                                \
		if (_cb != NULL)             \
		{                            \
			_ret = _cb(__VA_ARGS__); \
		}                            \
	} while (0)
#define INLINE __inline
#define __func__ __FUNCTION__

#define VERIFY_CERT_FLAG_CHANGED 0x40
#define VERIFY_CERT_FLAG_GATEWAY 0x20
#define VERIFY_CERT_FLAG_LEGACY 0x02
#define VERIFY_CERT_FLAG_MISMATCH 0x80
#define VERIFY_CERT_FLAG_NONE 0x00
#define VERIFY_CERT_FLAG_REDIRECT 0x10
#define freerdp_set_last_error_if_not(context, lastError)             \
	do                                                                \
	{                                                                 \
		if (freerdp_get_last_error(context) == FREERDP_ERROR_SUCCESS) \
			freerdp_set_last_error_log(context, lastError);           \
	} while (0)
#define freerdp_set_last_error_log(context, lastError) \
	freerdp_set_last_error_ex((context), (lastError), __FUNCTION__, "__FILE__", "__LINE__")
#define DEFINE_RDP_CLIENT_COMMON() HANDLE thread

#define RDP_CLIENT_ENTRY_POINT_NAME "RdpClientEntry"
#define RDP_CLIENT_INTERFACE_VERSION 1

#define EX_COMPRESSED_BITMAP_HEADER_PRESENT 0x01


#define WINDOW_HIDE 0x00
#define WINDOW_ORDER_CACHED_ICON 0x80000000
#define WINDOW_ORDER_FIELD_APPBAR_EDGE 0x00000001
#define WINDOW_ORDER_FIELD_APPBAR_STATE 0x00000040
#define WINDOW_ORDER_FIELD_CLIENT_AREA_OFFSET 0x00004000
#define WINDOW_ORDER_FIELD_CLIENT_AREA_SIZE 0x00010000
#define WINDOW_ORDER_FIELD_DESKTOP_ACTIVE_WND 0x00000020
#define WINDOW_ORDER_FIELD_DESKTOP_ARC_BEGAN 0x00000008
#define WINDOW_ORDER_FIELD_DESKTOP_ARC_COMPLETED 0x00000004
#define WINDOW_ORDER_FIELD_DESKTOP_HOOKED 0x00000002
#define WINDOW_ORDER_FIELD_DESKTOP_NONE 0x00000001
#define WINDOW_ORDER_FIELD_DESKTOP_ZORDER 0x00000010
#define WINDOW_ORDER_FIELD_ENFORCE_SERVER_ZORDER 0x00080000
#define WINDOW_ORDER_FIELD_ICON_BIG 0x00002000
#define WINDOW_ORDER_FIELD_ICON_OVERLAY 0x00100000
#define WINDOW_ORDER_FIELD_ICON_OVERLAY_NULL 0x00200000
#define WINDOW_ORDER_FIELD_NOTIFY_INFO_TIP 0x00000002
#define WINDOW_ORDER_FIELD_NOTIFY_STATE 0x00000004
#define WINDOW_ORDER_FIELD_NOTIFY_TIP 0x00000001
#define WINDOW_ORDER_FIELD_NOTIFY_VERSION 0x00000008
#define WINDOW_ORDER_FIELD_OVERLAY_DESCRIPTION 0x00400000
#define WINDOW_ORDER_FIELD_OWNER 0x00000002
#define WINDOW_ORDER_FIELD_RESIZE_MARGIN_X 0x00000080
#define WINDOW_ORDER_FIELD_RESIZE_MARGIN_Y 0x08000000
#define WINDOW_ORDER_FIELD_ROOT_PARENT 0x00040000
#define WINDOW_ORDER_FIELD_RP_CONTENT 0x00020000
#define WINDOW_ORDER_FIELD_SHOW 0x00000010
#define WINDOW_ORDER_FIELD_STYLE 0x00000008
#define WINDOW_ORDER_FIELD_TASKBAR_BUTTON 0x00800000
#define WINDOW_ORDER_FIELD_TITLE 0x00000004
#define WINDOW_ORDER_FIELD_VISIBILITY 0x00000200
#define WINDOW_ORDER_FIELD_VIS_OFFSET 0x00001000
#define WINDOW_ORDER_FIELD_WND_CLIENT_DELTA 0x00008000
#define WINDOW_ORDER_FIELD_WND_OFFSET 0x00000800
#define WINDOW_ORDER_FIELD_WND_RECTS 0x00000100
#define WINDOW_ORDER_FIELD_WND_SIZE 0x00000400
#define WINDOW_ORDER_ICON 0x40000000
#define WINDOW_ORDER_STATE_DELETED 0x20000000
#define WINDOW_ORDER_STATE_NEW 0x10000000
#define WINDOW_ORDER_TYPE_DESKTOP 0x04000000
#define WINDOW_ORDER_TYPE_NOTIFY 0x02000000
#define WINDOW_ORDER_TYPE_WINDOW 0x01000000
#define WINDOW_SHOW 0x05
#define WINDOW_SHOW_MAXIMIZED 0x03
#define WINDOW_SHOW_MINIMIZED 0x02
#define WS_BORDER 0x00800000
#define WS_CAPTION 0x00C00000
#define WS_CHILD 0x40000000
#define WS_CLIPCHILDREN 0x02000000
#define WS_CLIPSIBLINGS 0x04000000
#define WS_DISABLED 0x08000000
#define WS_DLGFRAME 0x00400000
#define WS_EX_ACCEPTFILES 0x00000010
#define WS_EX_APPWINDOW 0x00040000
#define WS_EX_CLIENTEDGE 0x00000200
#define WS_EX_COMPOSITED 0x02000000
#define WS_EX_CONTEXTHELP 0x00000400
#define WS_EX_CONTROLPARENT 0x00010000
#define WS_EX_DECORATIONS 0x40000000
#define WS_EX_DLGMODALFRAME 0x00000001
#define WS_EX_LAYERED 0x00080000
#define WS_EX_LAYOUTRTL 0x00400000
#define WS_EX_LEFT 0x00000000
#define WS_EX_LEFTSCROLLBAR 0x00004000
#define WS_EX_LTRREADING 0x00000000
#define WS_EX_MDICHILD 0x00000040
#define WS_EX_NOACTIVATE 0x08000000
#define WS_EX_NOINHERITLAYOUT 0x00100000
#define WS_EX_NOPARENTNOTIFY 0x00000004
#define WS_EX_OVERLAPPEDWINDOW (WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE)
#define WS_EX_PALETTEWINDOW (WS_EX_WINDOWEDGE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST)
#define WS_EX_RIGHT 0x00001000
#define WS_EX_RIGHTSCROLLBAR 0x00000000
#define WS_EX_RTLREADING 0x00002000
#define WS_EX_STATICEDGE 0x00020000
#define WS_EX_TOOLWINDOW 0x00000080
#define WS_EX_TOPMOST 0x00000008
#define WS_EX_TRANSPARENT 0x00000020
#define WS_EX_WINDOWEDGE 0x00000100
#define WS_GROUP 0x00020000
#define WS_HSCROLL 0x00100000
#define WS_ICONIC 0x20000000
#define WS_MAXIMIZE 0x01000000
#define WS_MAXIMIZEBOX 0x00010000
#define WS_MINIMIZE 0x20000000
#define WS_MINIMIZEBOX 0x00020000
#define WS_OVERLAPPED 0x00000000
#define WS_OVERLAPPEDWINDOW \
	(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX)
#define WS_POPUP 0x80000000
#define WS_POPUPWINDOW (WS_POPUP | WS_BORDER | WS_SYSMENU)
#define WS_SIZEBOX 0x00040000
#define WS_SYSMENU 0x00080000
#define WS_TABSTOP 0x00010000
#define WS_THICKFRAME 0x00040000
#define WS_VISIBLE 0x10000000
#define WS_VSCROLL 0x00200000
#define DSDNG_MUSTFLIP 0x00000010
#define DSDNG_PERPIXELALPHA 0x00000004
#define DSDNG_STRETCH 0x00000001
#define DSDNG_TILE 0x00000002
#define DSDNG_TRANSPARENT 0x00000008
#define DSDNG_TRUESIZE 0x00000020
#define FRAME_END 0x00000001
#define FRAME_START 0x00000000

#define STREAM_BITMAP_COMPRESSED 0x02
#define STREAM_BITMAP_END 0x01
#define STREAM_BITMAP_V2 0x04
#define BITMAP_CACHE_WAITING_LIST_INDEX 0x7FFF
#define BMF_16BPP 0x4
#define BMF_1BPP 0x1
#define BMF_24BPP 0x5
#define BMF_32BPP 0x6
#define BMF_8BPP 0x3
#define BS_HATCHED 0x02
#define BS_NULL 0x01
#define BS_PATTERN 0x03
#define BS_SOLID 0x00
#define CACHED_BRUSH 0x80
#define CBR2_DO_NOT_CACHE 0x10
#define CBR2_HEIGHT_SAME_AS_WIDTH 0x01
#define CBR2_NO_BITMAP_COMPRESSION_HDR 0x08
#define CBR2_PERSISTENT_KEY_PRESENT 0x02

#define GLYPH_FRAGMENT_ADD 0xFF
#define GLYPH_FRAGMENT_NOP 0x00
#define GLYPH_FRAGMENT_USE 0xFE
#define HS_BDIAGONAL 0x03
#define HS_CROSS 0x04
#define HS_DIAGCROSS 0x05
#define HS_FDIAGONAL 0x02
#define HS_HORIZONTAL 0x00
#define HS_VERTICAL 0x01
#define SCREEN_BITMAP_SURFACE 0xFFFF
#define SO_CHAR_INC_EQUAL_BM_BASE 0x20
#define SO_FLAG_DEFAULT_PLACEMENT 0x01
#define SO_HORIZONTAL 0x02
#define SO_MAXEXT_EQUAL_BM_SIDE 0x40
#define SO_REVERSED 0x08
#define SO_VERTICAL 0x04
#define SO_ZERO_BEARINGS 0x10
#define BACKMODE_OPAQUE 0x0002
#define BACKMODE_TRANSPARENT 0x0001




#define GUID_CHSIME                                                                \
	{                                                                              \
		0x81D4E9C9, 0x1D3B, 0x41BC, 0x9E, 0x6C, 0x4B, 0x40, 0xBF, 0x79, 0xE3, 0x5E \
	}
#define GUID_CHTIME                                                                \
	{                                                                              \
		0x531FDEBF, 0x9B4C, 0x4A43, 0xA2, 0xAA, 0x96, 0x0E, 0x8F, 0xCD, 0xC7, 0x32 \
	}
#define GUID_GUID_PROFILE_MSIME_JPN                                                \
	{                                                                              \
		0xA76C93D9, 0x5523, 0x4E90, 0xAA, 0xFA, 0x4D, 0xB1, 0x12, 0xF9, 0xAC, 0x76 \
	}
#define GUID_MSIME_JPN                                                             \
	{                                                                              \
		0x03B5835F, 0xF03C, 0x411B, 0x9C, 0xE2, 0xAA, 0x23, 0xE1, 0x17, 0x1E, 0x36 \
	}
#define GUID_MSIME_KOR                                                             \
	{                                                                              \
		0xA028AE76, 0x01B1, 0x46C2, 0x99, 0xC4, 0xAC, 0xD9, 0x85, 0x8A, 0xE0, 0x02 \
	}
#define GUID_NULL                                                                  \
	{                                                                              \
		0x00000000, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
	}
#define GUID_PROFILE_CANTONESE                                                     \
	{                                                                              \
		0x0AEC109C, 0x7E96, 0x11D4, 0xB2, 0xEF, 0x00, 0x80, 0xC8, 0x82, 0x68, 0x7E \
	}
#define GUID_PROFILE_CHANGJIE                                                      \
	{                                                                              \
		0x4BDF9F03, 0xC7D3, 0x11D4, 0xB2, 0xAB, 0x00, 0x80, 0xC8, 0x82, 0x68, 0x7E \
	}
#define GUID_PROFILE_MSIME_KOR                                                     \
	{                                                                              \
		0xB5FE1F02, 0xD5F2, 0x4445, 0x9C, 0x03, 0xC5, 0x68, 0xF2, 0x3C, 0x99, 0xA1 \
	}
#define GUID_PROFILE_NEWPHONETIC                                                   \
	{                                                                              \
		0xB2F9C502, 0x1742, 0x11D4, 0x97, 0x90, 0x00, 0x80, 0xC8, 0x82, 0x68, 0x7E \
	}
#define GUID_PROFILE_PINYIN                                                        \
	{                                                                              \
		0xF3BA9077, 0x6C7E, 0x11D4, 0x97, 0xFA, 0x00, 0x80, 0xC8, 0x82, 0x68, 0x7E \
	}
#define GUID_PROFILE_QUICK                                                         \
	{                                                                              \
		0x6024B45F, 0x5C54, 0x11D4, 0xB9, 0x21, 0x00, 0x80, 0xC8, 0x82, 0x68, 0x7E \
	}
#define GUID_PROFILE_SIMPLEFAST                                                    \
	{                                                                              \
		0xFA550B04, 0x5AD7, 0x411F, 0xA5, 0xAC, 0xCA, 0x03, 0x8E, 0xC5, 0x15, 0xD7 \
	}
#define IME_CMODE_CHARCODE 0x00000020
#define IME_CMODE_EUDC 0x00000200
#define IME_CMODE_FIXED 0x00000800
#define IME_CMODE_FULLSHAPE 0x00000008
#define IME_CMODE_HANJACONVERT 0x00000040
#define IME_CMODE_KATAKANA 0x00000002
#define IME_CMODE_NATIVE 0x00000001
#define IME_CMODE_NOCONVERSION 0x00000100
#define IME_CMODE_ROMAN 0x00000010
#define IME_CMODE_SOFTKBD 0x00000080
#define IME_CMODE_SYMBOL 0x00000400
#define IME_SMODE_AUTOMATIC 0x00000004
#define IME_SMODE_CONVERSATION 0x00000010
#define IME_SMODE_NONE 0x00000000
#define IME_SMODE_PHRASEPREDICT 0x00000008
#define IME_SMODE_PLURALCASE 0x00000001
#define IME_SMODE_SINGLECONVERT 0x00000002
#define IME_STATE_CLOSED 0x00000000
#define IME_STATE_OPEN 0x00000001
#define KANA_MODE_OFF 0x00000000
#define KANA_MODE_ON 0x00000001
#define NIIF_ERROR 0x00000003
#define NIIF_INFO 0x00000001
#define NIIF_LARGE_ICON 0x00000020
#define NIIF_NONE 0x00000000
#define NIIF_NOSOUND 0x00000010
#define NIIF_WARNING 0x00000002
#define NIN_BALLOONHIDE 0x00000403
#define NIN_BALLOONSHOW 0x00000402
#define NIN_BALLOONTIMEOUT 0x00000404
#define NIN_BALLOONUSERCLICK 0x00000405
#define NIN_KEYSELECT 0x00000401
#define NIN_SELECT 0x00000400
#define RAIL_CLIENTSTATUS_ALLOWLOCALMOVESIZE 0x00000001
#define RAIL_CLIENTSTATUS_AUTORECONNECT 0x00000002
#define RAIL_EXEC_E_DECODE_FAILED 0x0002
#define RAIL_EXEC_E_FAIL 0x0006
#define RAIL_EXEC_E_FILE_NOT_FOUND 0x0005
#define RAIL_EXEC_E_HOOK_NOT_LOADED 0x0001
#define RAIL_EXEC_E_NOT_IN_ALLOWLIST 0x0003
#define RAIL_EXEC_E_SESSION_LOCKED 0x0007
#define RAIL_EXEC_FLAG_APP_USER_MODEL_ID 0x0010
#define RAIL_EXEC_FLAG_EXPAND_ARGUMENTS 0x0008
#define RAIL_EXEC_FLAG_EXPAND_WORKINGDIRECTORY 0x0001
#define RAIL_EXEC_FLAG_EXPAND_WORKING_DIRECTORY 0x0001
#define RAIL_EXEC_FLAG_FILE 0x0004
#define RAIL_EXEC_FLAG_TRANSLATE_FILES 0x0002
#define RAIL_EXEC_S_OK 0x0000
#define RAIL_ORDER_HANDSHAKEEX_FLAGS_HIDEF 0x00000001
#define RAIL_ORDER_HANDSHAKE_EX_FLAGS_EXTENDED_SPI_SUPPORTED 0x00000002
#define RAIL_ORDER_HANDSHAKE_EX_FLAGS_SNAP_ARRANGE_SUPPORTED 0x00000004
#define RAIL_SVC_CHANNEL_NAME "rail"
#define RAIL_TASKBAR_MSG_TAB_ACTIVE 0x00000004
#define RAIL_TASKBAR_MSG_TAB_ORDER 0x00000003
#define RAIL_TASKBAR_MSG_TAB_PROPERTIES 0x00000005
#define RAIL_TASKBAR_MSG_TAB_REGISTER 0x00000001
#define RAIL_TASKBAR_MSG_TAB_UNREGISTER 0x00000002
#define RAIL_WMSZ_BOTTOM 0x0006
#define RAIL_WMSZ_BOTTOMLEFT 0x0007
#define RAIL_WMSZ_BOTTOMRIGHT 0x0008
#define RAIL_WMSZ_KEYMOVE 0x000A
#define RAIL_WMSZ_KEYSIZE 0x000B
#define RAIL_WMSZ_LEFT 0x0001
#define RAIL_WMSZ_MOVE 0x0009
#define RAIL_WMSZ_RIGHT 0x0002
#define RAIL_WMSZ_TOP 0x0003
#define RAIL_WMSZ_TOPLEFT 0x0004
#define RAIL_WMSZ_TOPRIGHT 0x0005
#define RDP_RAIL_ORDER_ACTIVATE 0x0002
#define RDP_RAIL_ORDER_CLIENTSTATUS 0x000B
#define RDP_RAIL_ORDER_CLOAK 0x0015
#define RDP_RAIL_ORDER_COMPARTMENTINFO 0x0012
#define RDP_RAIL_ORDER_EXEC 0x0001
#define RDP_RAIL_ORDER_EXEC_RESULT 0x0080
#define RDP_RAIL_ORDER_GET_APPID_REQ 0x000E
#define RDP_RAIL_ORDER_GET_APPID_RESP 0x000F
#define RDP_RAIL_ORDER_GET_APPID_RESP_EX 0x0018
#define RDP_RAIL_ORDER_HANDSHAKE 0x0005
#define RDP_RAIL_ORDER_HANDSHAKE_EX 0x0013
#define RDP_RAIL_ORDER_LANGBARINFO 0x000D
#define RDP_RAIL_ORDER_LANGUAGEIMEINFO 0x0011
#define RDP_RAIL_ORDER_LOCALMOVESIZE 0x0009
#define RDP_RAIL_ORDER_MINMAXINFO 0x000A
#define RDP_RAIL_ORDER_NOTIFY_EVENT 0x0006
#define RDP_RAIL_ORDER_POWER_DISPLAY_REQUEST 0x0016
#define RDP_RAIL_ORDER_SNAP_ARRANGE 0x0017
#define RDP_RAIL_ORDER_SYSCOMMAND 0x0004
#define RDP_RAIL_ORDER_SYSMENU 0x000C
#define RDP_RAIL_ORDER_SYSPARAM 0x0003
#define RDP_RAIL_ORDER_WINDOWMOVE 0x0008
#define RDP_RAIL_ORDER_ZORDER_SYNC 0x0014
#define SC_CLOSE 0xF060
#define SC_DEFAULT 0xF160
#define SC_KEYMENU 0xF100
#define SC_MAXIMIZE 0xF030
#define SC_MINIMIZE 0xF020
#define SC_MOVE 0xF010
#define SC_RESTORE 0xF120
#define SC_SIZE 0xF000
#define SPI_DISPLAY_CHANGE 0x0000F001
#define SPI_SET_DRAG_FULL_WINDOWS 0x00000025
#define SPI_SET_HIGH_CONTRAST 0x00000043
#define SPI_SET_KEYBOARD_CUES 0x0000100B
#define SPI_SET_KEYBOARD_PREF 0x00000045
#define SPI_SET_MOUSE_BUTTON_SWAP 0x00000021
#define SPI_SET_SCREEN_SAVE_ACTIVE 0x00000011
#define SPI_SET_SCREEN_SAVE_SECURE 0x00000077
#define SPI_SET_WORK_AREA 0x0000002F
#define SPI_TASKBAR_POS 0x0000F000
#define TF_PROFILETYPE_INPUTPROCESSOR 0x00000001
#define TF_PROFILETYPE_KEYBOARDLAYOUT 0x00000002
#define TF_SFT_DESKBAND 0x00000800
#define TF_SFT_DOCK 0x00000002
#define TF_SFT_EXTRAICONSONMINIMIZED 0x00000200
#define TF_SFT_HIDDEN 0x00000008
#define TF_SFT_HIGHTRANSPARENCY 0x00000040
#define TF_SFT_LABELS 0x00000080
#define TF_SFT_LOWTRANSPARENCY 0x00000020
#define TF_SFT_MINIMIZED 0x00000004
#define TF_SFT_NOEXTRAICONSONMINIMIZED 0x00000400
#define TF_SFT_NOLABELS 0x00000100
#define TF_SFT_NOTRANSPARENCY 0x00000010
#define TF_SFT_SHOWNORMAL 0x00000001
#define TS_RAIL_CLIENTSTATUS_ALLOWLOCALMOVESIZE 0x00000001
#define TS_RAIL_CLIENTSTATUS_APPBAR_REMOTING_SUPPORTED 0x00000040
#define TS_RAIL_CLIENTSTATUS_AUTORECONNECT 0x00000002
#define TS_RAIL_CLIENTSTATUS_BIDIRECTIONAL_CLOAK_SUPPORTED 0x00000200
#define TS_RAIL_CLIENTSTATUS_HIGH_DPI_ICONS_SUPPORTED 0x00000020
#define TS_RAIL_CLIENTSTATUS_POWER_DISPLAY_REQUEST_SUPPORTED 0x00000080
#define TS_RAIL_CLIENTSTATUS_WINDOW_RESIZE_MARGIN_SUPPORTED 0x00000010
#define TS_RAIL_CLIENTSTATUS_ZORDER_SYNC 0x00000004
#define TS_RAIL_EXEC_FLAG_APP_USER_MODEL_ID 0x0010
#define TS_RAIL_EXEC_FLAG_EXPAND_ARGUMENTS 0x0008
#define TS_RAIL_EXEC_FLAG_EXPAND_WORKINGDIRECTORY 0x0001
#define TS_RAIL_EXEC_FLAG_FILE 0x0004
#define TS_RAIL_EXEC_FLAG_TRANSLATE_FILES 0x0002
#define TS_RAIL_ORDER_ACTIVATE 0x0002
#define TS_RAIL_ORDER_CLIENTSTATUS 0x000B
#define TS_RAIL_ORDER_CLOAK 0x0015
#define TS_RAIL_ORDER_COMPARTMENTINFO 0x0012
#define TS_RAIL_ORDER_EXEC 0x0001
#define TS_RAIL_ORDER_EXEC_RESULT 0x0080
#define TS_RAIL_ORDER_GET_APPID_REQ 0x000E
#define TS_RAIL_ORDER_GET_APPID_RESP 0x000F
#define TS_RAIL_ORDER_GET_APPID_RESP_EX 0x0018
#define TS_RAIL_ORDER_HANDSHAKE 0x0005
#define TS_RAIL_ORDER_HANDSHAKEEX_FLAGS_HIDEF 0x00000001
#define TS_RAIL_ORDER_HANDSHAKE_EX 0x0013
#define TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_EXTENDED_SPI_SUPPORTED 0x00000002
#define TS_RAIL_ORDER_HANDSHAKE_EX_FLAGS_SNAP_ARRANGE_SUPPORTED 0x00000004
#define TS_RAIL_ORDER_LANGBARINFO 0x000D
#define TS_RAIL_ORDER_LANGUAGEIMEINFO 0x0011
#define TS_RAIL_ORDER_LOCALMOVESIZE 0x0009
#define TS_RAIL_ORDER_MINMAXINFO 0x000A
#define TS_RAIL_ORDER_NOTIFY_EVENT 0x0006
#define TS_RAIL_ORDER_POWER_DISPLAY_REQUEST 0x0016
#define TS_RAIL_ORDER_SNAP_ARRANGE 0x0017
#define TS_RAIL_ORDER_SYSCOMMAND 0x0004
#define TS_RAIL_ORDER_SYSMENU 0x000C
#define TS_RAIL_ORDER_SYSPARAM 0x0003
#define TS_RAIL_ORDER_TASKBARINFO 0x0010
#define TS_RAIL_ORDER_WINDOWMOVE 0x0008
#define TS_RAIL_ORDER_ZORDER_SYNC 0x0014

#define KBD_FLAGS_DOWN 0x4000
#define KBD_FLAGS_EXTENDED 0x0100
#define KBD_FLAGS_EXTENDED1 0x0200
#define KBD_FLAGS_RELEASE 0x8000
#define KBD_SYNC_CAPS_LOCK 0x00000004
#define KBD_SYNC_KANA_LOCK 0x00000008
#define KBD_SYNC_NUM_LOCK 0x00000002
#define KBD_SYNC_SCROLL_LOCK 0x00000001
#define PTR_FLAGS_BUTTON1 0x1000 
#define PTR_FLAGS_BUTTON2 0x2000 
#define PTR_FLAGS_BUTTON3 0x4000 
#define PTR_FLAGS_DOWN 0x8000
#define PTR_FLAGS_HWHEEL 0x0400
#define PTR_FLAGS_MOVE 0x0800
#define PTR_FLAGS_WHEEL 0x0200
#define PTR_FLAGS_WHEEL_NEGATIVE 0x0100
#define PTR_XFLAGS_BUTTON1 0x0001
#define PTR_XFLAGS_BUTTON2 0x0002
#define PTR_XFLAGS_DOWN 0x8000
#define RDP_CLIENT_INPUT_PDU_HEADER_LENGTH 4
#define WheelRotationMask 0x01FF

#define MAKE_RDP_SCANCODE(_code, _extended) (((_code)&0xFF) | ((_extended) ? KBDEXT : 0))
#define RDP_SCANCODE_ABNT_C1 MAKE_RDP_SCANCODE(0x73, FALSE)       
#define RDP_SCANCODE_ABNT_C2 MAKE_RDP_SCANCODE(0x7E, FALSE)       
#define RDP_SCANCODE_ADD MAKE_RDP_SCANCODE(0x4E, FALSE)      
#define RDP_SCANCODE_APPS MAKE_RDP_SCANCODE(0x5D, TRUE)     
#define RDP_SCANCODE_BACKSLASH_JP MAKE_RDP_SCANCODE(0x7D, FALSE)  
#define RDP_SCANCODE_BACKSPACE MAKE_RDP_SCANCODE(0x0E, FALSE) 
#define RDP_SCANCODE_BROWSER_BACK MAKE_RDP_SCANCODE(0x6A, TRUE)      
#define RDP_SCANCODE_BROWSER_FAVORITES MAKE_RDP_SCANCODE(0x66, TRUE) 
#define RDP_SCANCODE_BROWSER_FORWARD MAKE_RDP_SCANCODE(0x69, TRUE)   
#define RDP_SCANCODE_BROWSER_HOME MAKE_RDP_SCANCODE(0x32, TRUE)      
#define RDP_SCANCODE_BROWSER_REFRESH MAKE_RDP_SCANCODE(0x67, TRUE)   
#define RDP_SCANCODE_BROWSER_SEARCH MAKE_RDP_SCANCODE(0x65, TRUE)    
#define RDP_SCANCODE_BROWSER_STOP MAKE_RDP_SCANCODE(0x68, TRUE)      
#define RDP_SCANCODE_CAPSLOCK \
	MAKE_RDP_SCANCODE(0x3A, FALSE) 
#define RDP_SCANCODE_CODE(_rdp_scancode) ((BYTE)(_rdp_scancode & 0xFF))
#define RDP_SCANCODE_CONVERT_JP MAKE_RDP_SCANCODE(0x79, FALSE)    
#define RDP_SCANCODE_DECIMAL MAKE_RDP_SCANCODE(0x53, FALSE)  
#define RDP_SCANCODE_DELETE MAKE_RDP_SCANCODE(0x53, TRUE) 
#define RDP_SCANCODE_DIVIDE MAKE_RDP_SCANCODE(0x35, TRUE)   
#define RDP_SCANCODE_DOWN MAKE_RDP_SCANCODE(0x50, TRUE)   
#define RDP_SCANCODE_END MAKE_RDP_SCANCODE(0x4F, TRUE)    
#define RDP_SCANCODE_ESCAPE MAKE_RDP_SCANCODE(0x01, FALSE)    
#define RDP_SCANCODE_EXTENDED(_rdp_scancode) (((_rdp_scancode)&KBDEXT) ? TRUE : FALSE)
#define RDP_SCANCODE_F1 MAKE_RDP_SCANCODE(0x3B, FALSE)  
#define RDP_SCANCODE_F10 MAKE_RDP_SCANCODE(0x44, FALSE) 
#define RDP_SCANCODE_F11 MAKE_RDP_SCANCODE(0x57, FALSE)      
#define RDP_SCANCODE_F12 MAKE_RDP_SCANCODE(0x58, FALSE)      
#define RDP_SCANCODE_F13 \
	MAKE_RDP_SCANCODE(0x64, FALSE)  
#define RDP_SCANCODE_F14 MAKE_RDP_SCANCODE(0x65, FALSE)              
#define RDP_SCANCODE_F15 MAKE_RDP_SCANCODE(0x66, FALSE)              
#define RDP_SCANCODE_F16 MAKE_RDP_SCANCODE(0x67, FALSE)              
#define RDP_SCANCODE_F17 MAKE_RDP_SCANCODE(0x68, FALSE)              
#define RDP_SCANCODE_F18 MAKE_RDP_SCANCODE(0x69, FALSE)              
#define RDP_SCANCODE_F19 MAKE_RDP_SCANCODE(0x6A, FALSE)              
#define RDP_SCANCODE_F2 MAKE_RDP_SCANCODE(0x3C, FALSE)  
#define RDP_SCANCODE_F20 MAKE_RDP_SCANCODE(0x6B, FALSE)              
#define RDP_SCANCODE_F21 MAKE_RDP_SCANCODE(0x6C, FALSE)              
#define RDP_SCANCODE_F22 MAKE_RDP_SCANCODE(0x6D, FALSE)              
#define RDP_SCANCODE_F23 MAKE_RDP_SCANCODE(0x6E, FALSE)  
#define RDP_SCANCODE_F24 \
	MAKE_RDP_SCANCODE(0x6F, FALSE)  
#define RDP_SCANCODE_F24_JP MAKE_RDP_SCANCODE(0x76, FALSE)        
#define RDP_SCANCODE_F3 MAKE_RDP_SCANCODE(0x3D, FALSE)  
#define RDP_SCANCODE_F4 MAKE_RDP_SCANCODE(0x3E, FALSE)  
#define RDP_SCANCODE_F5 MAKE_RDP_SCANCODE(0x3F, FALSE)  
#define RDP_SCANCODE_F6 MAKE_RDP_SCANCODE(0x40, FALSE)  
#define RDP_SCANCODE_F7 MAKE_RDP_SCANCODE(0x41, FALSE)  
#define RDP_SCANCODE_F8 MAKE_RDP_SCANCODE(0x42, FALSE)  
#define RDP_SCANCODE_F9 MAKE_RDP_SCANCODE(0x43, FALSE)  
#define RDP_SCANCODE_HANGUL MAKE_RDP_SCANCODE(0x72, FALSE)        
#define RDP_SCANCODE_HANJA MAKE_RDP_SCANCODE(0x71, FALSE)         
#define RDP_SCANCODE_HANJA_KANJI \
	MAKE_RDP_SCANCODE(0x71, FALSE) 
#define RDP_SCANCODE_HELP MAKE_RDP_SCANCODE(0x63, FALSE) 
#define RDP_SCANCODE_HELP2 \
	MAKE_RDP_SCANCODE(0x56, TRUE) 
#define RDP_SCANCODE_HIRAGANA MAKE_RDP_SCANCODE(0x70, FALSE) 
#define RDP_SCANCODE_HOME MAKE_RDP_SCANCODE(0x47, TRUE)   
#define RDP_SCANCODE_INSERT MAKE_RDP_SCANCODE(0x52, TRUE) 
#define RDP_SCANCODE_KANA_HANGUL \
	MAKE_RDP_SCANCODE(0x72, FALSE) 
#define RDP_SCANCODE_KEY_0 MAKE_RDP_SCANCODE(0x0B, FALSE)     
#define RDP_SCANCODE_KEY_1 MAKE_RDP_SCANCODE(0x02, FALSE)     
#define RDP_SCANCODE_KEY_2 MAKE_RDP_SCANCODE(0x03, FALSE)     
#define RDP_SCANCODE_KEY_3 MAKE_RDP_SCANCODE(0x04, FALSE)     
#define RDP_SCANCODE_KEY_4 MAKE_RDP_SCANCODE(0x05, FALSE)     
#define RDP_SCANCODE_KEY_5 MAKE_RDP_SCANCODE(0x06, FALSE)     
#define RDP_SCANCODE_KEY_6 MAKE_RDP_SCANCODE(0x07, FALSE)     
#define RDP_SCANCODE_KEY_7 MAKE_RDP_SCANCODE(0x08, FALSE)     
#define RDP_SCANCODE_KEY_8 MAKE_RDP_SCANCODE(0x09, FALSE)     
#define RDP_SCANCODE_KEY_9 MAKE_RDP_SCANCODE(0x0A, FALSE)     
#define RDP_SCANCODE_KEY_A MAKE_RDP_SCANCODE(0x1E, FALSE)     
#define RDP_SCANCODE_KEY_B MAKE_RDP_SCANCODE(0x30, FALSE)  
#define RDP_SCANCODE_KEY_C MAKE_RDP_SCANCODE(0x2E, FALSE)  
#define RDP_SCANCODE_KEY_D MAKE_RDP_SCANCODE(0x20, FALSE)     
#define RDP_SCANCODE_KEY_E MAKE_RDP_SCANCODE(0x12, FALSE)     
#define RDP_SCANCODE_KEY_F MAKE_RDP_SCANCODE(0x21, FALSE)     
#define RDP_SCANCODE_KEY_G MAKE_RDP_SCANCODE(0x22, FALSE)     
#define RDP_SCANCODE_KEY_H MAKE_RDP_SCANCODE(0x23, FALSE)     
#define RDP_SCANCODE_KEY_I MAKE_RDP_SCANCODE(0x17, FALSE)     
#define RDP_SCANCODE_KEY_J MAKE_RDP_SCANCODE(0x24, FALSE)     
#define RDP_SCANCODE_KEY_K MAKE_RDP_SCANCODE(0x25, FALSE)     
#define RDP_SCANCODE_KEY_L MAKE_RDP_SCANCODE(0x26, FALSE)     
#define RDP_SCANCODE_KEY_M MAKE_RDP_SCANCODE(0x32, FALSE)  
#define RDP_SCANCODE_KEY_N MAKE_RDP_SCANCODE(0x31, FALSE)  
#define RDP_SCANCODE_KEY_O MAKE_RDP_SCANCODE(0x18, FALSE)     
#define RDP_SCANCODE_KEY_P MAKE_RDP_SCANCODE(0x19, FALSE)     
#define RDP_SCANCODE_KEY_Q MAKE_RDP_SCANCODE(0x10, FALSE)     
#define RDP_SCANCODE_KEY_R MAKE_RDP_SCANCODE(0x13, FALSE)     
#define RDP_SCANCODE_KEY_S MAKE_RDP_SCANCODE(0x1F, FALSE)     
#define RDP_SCANCODE_KEY_T MAKE_RDP_SCANCODE(0x14, FALSE)     
#define RDP_SCANCODE_KEY_U MAKE_RDP_SCANCODE(0x16, FALSE)     
#define RDP_SCANCODE_KEY_V MAKE_RDP_SCANCODE(0x2F, FALSE)  
#define RDP_SCANCODE_KEY_W MAKE_RDP_SCANCODE(0x11, FALSE)     
#define RDP_SCANCODE_KEY_X MAKE_RDP_SCANCODE(0x2D, FALSE)  
#define RDP_SCANCODE_KEY_Y MAKE_RDP_SCANCODE(0x15, FALSE)     
#define RDP_SCANCODE_KEY_Z MAKE_RDP_SCANCODE(0x2C, FALSE)  
#define RDP_SCANCODE_LAUNCH_MAIL MAKE_RDP_SCANCODE(0x6C, TRUE) 
#define RDP_SCANCODE_LCONTROL MAKE_RDP_SCANCODE(0x1D, FALSE)  
#define RDP_SCANCODE_LEFT MAKE_RDP_SCANCODE(0x4B, TRUE)   
#define RDP_SCANCODE_LMENU MAKE_RDP_SCANCODE(0x38, FALSE)      
#define RDP_SCANCODE_LSHIFT MAKE_RDP_SCANCODE(0x2A, FALSE) 
#define RDP_SCANCODE_LWIN MAKE_RDP_SCANCODE(0x5B, TRUE)     
#define RDP_SCANCODE_MEDIA_NEXT_TRACK MAKE_RDP_SCANCODE(0x19, TRUE) 
#define RDP_SCANCODE_MEDIA_PLAY_PAUSE                          \
	MAKE_RDP_SCANCODE(0x22, TRUE) 
#define RDP_SCANCODE_MEDIA_PREV_TRACK MAKE_RDP_SCANCODE(0x10, TRUE) 
#define RDP_SCANCODE_MEDIA_STOP MAKE_RDP_SCANCODE(0x24, TRUE)       
#define RDP_SCANCODE_MULTIPLY MAKE_RDP_SCANCODE(0x37, FALSE)   
#define RDP_SCANCODE_NEXT MAKE_RDP_SCANCODE(0x51, TRUE)   
#define RDP_SCANCODE_NONCONVERT_JP MAKE_RDP_SCANCODE(0x7B, FALSE) 
#define RDP_SCANCODE_NULL MAKE_RDP_SCANCODE(0x54, TRUE)   
#define RDP_SCANCODE_NUMLOCK                                                                     \
	MAKE_RDP_SCANCODE(0x45, FALSE)                                                               \
	 
#define RDP_SCANCODE_NUMLOCK_EXTENDED \
	MAKE_RDP_SCANCODE(0x45, TRUE) 
#define RDP_SCANCODE_NUMPAD0 MAKE_RDP_SCANCODE(0x52, FALSE)  
#define RDP_SCANCODE_NUMPAD1 MAKE_RDP_SCANCODE(0x4F, FALSE)  
#define RDP_SCANCODE_NUMPAD2 MAKE_RDP_SCANCODE(0x50, FALSE)  
#define RDP_SCANCODE_NUMPAD3 MAKE_RDP_SCANCODE(0x51, FALSE)  
#define RDP_SCANCODE_NUMPAD4 MAKE_RDP_SCANCODE(0x4B, FALSE)  
#define RDP_SCANCODE_NUMPAD5 MAKE_RDP_SCANCODE(0x4C, FALSE)  
#define RDP_SCANCODE_NUMPAD6 MAKE_RDP_SCANCODE(0x4D, FALSE)  
#define RDP_SCANCODE_NUMPAD7 MAKE_RDP_SCANCODE(0x47, FALSE)  
#define RDP_SCANCODE_NUMPAD8 MAKE_RDP_SCANCODE(0x48, FALSE)  
#define RDP_SCANCODE_NUMPAD9 MAKE_RDP_SCANCODE(0x49, FALSE)  
#define RDP_SCANCODE_OEM_1 MAKE_RDP_SCANCODE(0x27, FALSE)     
#define RDP_SCANCODE_OEM_102 MAKE_RDP_SCANCODE(0x56, FALSE)  
#define RDP_SCANCODE_OEM_2 MAKE_RDP_SCANCODE(0x35, FALSE)      
#define RDP_SCANCODE_OEM_3 \
	MAKE_RDP_SCANCODE(0x29, FALSE) 
#define RDP_SCANCODE_OEM_4 MAKE_RDP_SCANCODE(0x1A, FALSE)     
#define RDP_SCANCODE_OEM_5 MAKE_RDP_SCANCODE(0x2B, FALSE)  
#define RDP_SCANCODE_OEM_6 MAKE_RDP_SCANCODE(0x1B, FALSE)     
#define RDP_SCANCODE_OEM_7 MAKE_RDP_SCANCODE(0x28, FALSE)     
#define RDP_SCANCODE_OEM_COMMA MAKE_RDP_SCANCODE(0x33, FALSE)  
#define RDP_SCANCODE_OEM_MINUS MAKE_RDP_SCANCODE(0x0C, FALSE) 
#define RDP_SCANCODE_OEM_PERIOD MAKE_RDP_SCANCODE(0x34, FALSE) 
#define RDP_SCANCODE_OEM_PLUS MAKE_RDP_SCANCODE(0x0D, FALSE)  
#define RDP_SCANCODE_PAUSE \
	MAKE_RDP_SCANCODE(0x46, TRUE) 
#define RDP_SCANCODE_POWER_JP MAKE_RDP_SCANCODE(0x5E, TRUE) 
#define RDP_SCANCODE_PRINTSCREEN \
	MAKE_RDP_SCANCODE(0x37, TRUE) 
#define RDP_SCANCODE_PRIOR MAKE_RDP_SCANCODE(0x49, TRUE)  
#define RDP_SCANCODE_RCONTROL MAKE_RDP_SCANCODE(0x1D, TRUE) 
#define RDP_SCANCODE_RETURN MAKE_RDP_SCANCODE(0x1C, FALSE)    
#define RDP_SCANCODE_RETURN_KP \
	MAKE_RDP_SCANCODE(0x1C, TRUE) 
#define RDP_SCANCODE_RIGHT MAKE_RDP_SCANCODE(0x4D, TRUE)  
#define RDP_SCANCODE_RMENU MAKE_RDP_SCANCODE(0x38, TRUE) 
#define RDP_SCANCODE_RSHIFT MAKE_RDP_SCANCODE(0x36, FALSE)     
#define RDP_SCANCODE_RSHIFT_EXTENDED \
	MAKE_RDP_SCANCODE(0x36, TRUE) 
#define RDP_SCANCODE_RWIN MAKE_RDP_SCANCODE(0x5C, TRUE)     
#define RDP_SCANCODE_SCROLLLOCK \
	MAKE_RDP_SCANCODE(0x46, FALSE) 
#define RDP_SCANCODE_SLEEP                                                                       \
	MAKE_RDP_SCANCODE(0x5F, FALSE)                       
#define RDP_SCANCODE_SLEEP_JP MAKE_RDP_SCANCODE(0x5F, TRUE) 
#define RDP_SCANCODE_SPACE MAKE_RDP_SCANCODE(0x39, FALSE)      
#define RDP_SCANCODE_SUBTRACT MAKE_RDP_SCANCODE(0x4A, FALSE) 
#define RDP_SCANCODE_SYSREQ MAKE_RDP_SCANCODE(0x54, FALSE)   
#define RDP_SCANCODE_TAB MAKE_RDP_SCANCODE(0x0F, FALSE)       
#define RDP_SCANCODE_TAB_JP MAKE_RDP_SCANCODE(0x7C, FALSE)        
#define RDP_SCANCODE_UNKNOWN MAKE_RDP_SCANCODE(0x00, FALSE)
#define RDP_SCANCODE_UP MAKE_RDP_SCANCODE(0x48, TRUE)     
#define RDP_SCANCODE_VOLUME_DOWN MAKE_RDP_SCANCODE(0x2E, TRUE) 
#define RDP_SCANCODE_VOLUME_MUTE MAKE_RDP_SCANCODE(0x20, TRUE) 
#define RDP_SCANCODE_VOLUME_UP MAKE_RDP_SCANCODE(0x30, TRUE)   
#define RDP_SCANCODE_ZOOM MAKE_RDP_SCANCODE(0x62, FALSE) 

#define FREERDP_EXT_EXPORT_FUNC_NAME "FreeRDPExtensionEntry"


#define FREERDP_CODEC_ALL 0xFFFFFFFF
#define FREERDP_CODEC_ALPHACODEC 0x00000020
#define FREERDP_CODEC_AVC420 0x00000080
#define FREERDP_CODEC_AVC444 0x00000100
#define FREERDP_CODEC_CLEARCODEC 0x00000010
#define FREERDP_CODEC_INTERLEAVED 0x00000001
#define FREERDP_CODEC_NSCODEC 0x00000004
#define FREERDP_CODEC_PLANAR 0x00000002
#define FREERDP_CODEC_PROGRESSIVE 0x00000040
#define FREERDP_CODEC_REMOTEFX 0x00000008


#define CTAG FREERDP_TAG("codec.color")
#define ConvertColor FreeRDPConvertColor

#define FREERDP_FLIP_HORIZONTAL 2
#define FREERDP_FLIP_NONE 0
#define FREERDP_FLIP_VERTICAL 1
#define FREERDP_PIXEL_FORMAT(_bpp, _type, _a, _r, _g, _b) \
	((_bpp << 24) | (_type << 16) | (_a << 12) | (_r << 8) | (_g << 4) | (_b))
#define FREERDP_PIXEL_FORMAT_IS_ABGR(_format) \
	(FREERDP_PIXEL_FORMAT_TYPE(_format) == FREERDP_PIXEL_FORMAT_TYPE_ABGR)
#define FREERDP_PIXEL_FORMAT_TYPE(_format) (((_format) >> 16) & 0x07)
#define FREERDP_PIXEL_FORMAT_TYPE_A 0
#define FREERDP_PIXEL_FORMAT_TYPE_ABGR 2
#define FREERDP_PIXEL_FORMAT_TYPE_ARGB 1
#define FREERDP_PIXEL_FORMAT_TYPE_BGRA 4
#define FREERDP_PIXEL_FORMAT_TYPE_RGBA 3
#define GetColor FreeRDPGetColor
#define GetColorFormatName FreeRDPGetColorFormatName
#define PIXEL_FORMAT_A4 FREERDP_PIXEL_FORMAT(4, FREERDP_PIXEL_FORMAT_TYPE_A, 4, 0, 0, 0)
#define PIXEL_FORMAT_ABGR15 FREERDP_PIXEL_FORMAT(16, FREERDP_PIXEL_FORMAT_TYPE_ABGR, 1, 5, 5, 5)
#define PIXEL_FORMAT_ABGR32 FREERDP_PIXEL_FORMAT(32, FREERDP_PIXEL_FORMAT_TYPE_ABGR, 8, 8, 8, 8)
#define PIXEL_FORMAT_ARGB15 FREERDP_PIXEL_FORMAT(16, FREERDP_PIXEL_FORMAT_TYPE_ARGB, 1, 5, 5, 5)
#define PIXEL_FORMAT_ARGB32 FREERDP_PIXEL_FORMAT(32, FREERDP_PIXEL_FORMAT_TYPE_ARGB, 8, 8, 8, 8)
#define PIXEL_FORMAT_BGR15 FREERDP_PIXEL_FORMAT(15, FREERDP_PIXEL_FORMAT_TYPE_ABGR, 0, 5, 5, 5)
#define PIXEL_FORMAT_BGR16 FREERDP_PIXEL_FORMAT(16, FREERDP_PIXEL_FORMAT_TYPE_ABGR, 0, 5, 6, 5)
#define PIXEL_FORMAT_BGR24 FREERDP_PIXEL_FORMAT(24, FREERDP_PIXEL_FORMAT_TYPE_ABGR, 0, 8, 8, 8)
#define PIXEL_FORMAT_BGRA32 FREERDP_PIXEL_FORMAT(32, FREERDP_PIXEL_FORMAT_TYPE_BGRA, 8, 8, 8, 8)
#define PIXEL_FORMAT_BGRX32 FREERDP_PIXEL_FORMAT(32, FREERDP_PIXEL_FORMAT_TYPE_BGRA, 0, 8, 8, 8)
#define PIXEL_FORMAT_MONO FREERDP_PIXEL_FORMAT(1, FREERDP_PIXEL_FORMAT_TYPE_A, 1, 0, 0, 0)
#define PIXEL_FORMAT_RGB15 FREERDP_PIXEL_FORMAT(15, FREERDP_PIXEL_FORMAT_TYPE_ARGB, 0, 5, 5, 5)
#define PIXEL_FORMAT_RGB16 FREERDP_PIXEL_FORMAT(16, FREERDP_PIXEL_FORMAT_TYPE_ARGB, 0, 5, 6, 5)
#define PIXEL_FORMAT_RGB24 FREERDP_PIXEL_FORMAT(24, FREERDP_PIXEL_FORMAT_TYPE_ARGB, 0, 8, 8, 8)
#define PIXEL_FORMAT_RGB8 FREERDP_PIXEL_FORMAT(8, FREERDP_PIXEL_FORMAT_TYPE_A, 8, 0, 0, 0)
#define PIXEL_FORMAT_RGBA32 FREERDP_PIXEL_FORMAT(32, FREERDP_PIXEL_FORMAT_TYPE_RGBA, 8, 8, 8, 8)
#define PIXEL_FORMAT_RGBX32 FREERDP_PIXEL_FORMAT(32, FREERDP_PIXEL_FORMAT_TYPE_RGBA, 0, 8, 8, 8)
#define PIXEL_FORMAT_XBGR32 FREERDP_PIXEL_FORMAT(32, FREERDP_PIXEL_FORMAT_TYPE_ABGR, 0, 8, 8, 8)
#define PIXEL_FORMAT_XRGB32 FREERDP_PIXEL_FORMAT(32, FREERDP_PIXEL_FORMAT_TYPE_ARGB, 0, 8, 8, 8)
#define CLIENT_TAG(tag) FREERDP_TAG("client.") tag

#define FREERDP_TAG(tag) "com.freerdp." tag
#define SERVER_TAG(tag) FREERDP_TAG("server.") tag

#define _RFX_DECODED_CHANNELS 0x00000008
#define _RFX_DECODED_CONTEXT 0x00000002
#define _RFX_DECODED_HEADERS 0x0000000F
#define _RFX_DECODED_SYNC 0x00000001
#define _RFX_DECODED_VERSIONS 0x00000004
#define CPU_SSE2 0x1

#define OSMAJORTYPE_MACINTOSH 0x0003
#define OSMAJORTYPE_OS2 0x0002
#define OSMAJORTYPE_UNIX 0x0004
#define OSMAJORTYPE_UNSPECIFIED 0x0000
#define OSMAJORTYPE_WINDOWS 0x0001
#define OSMINORTYPE_MACINTOSH 0x0006
#define OSMINORTYPE_NATIVE_WAYLAND 0x0009
#define OSMINORTYPE_NATIVE_XSERVER 0x0007
#define OSMINORTYPE_OS2_V21 0x0004
#define OSMINORTYPE_POWER_PC 0x0005
#define OSMINORTYPE_PSEUDO_XSERVER 0x0008
#define OSMINORTYPE_UNSPECIFIED 0x0000
#define OSMINORTYPE_WINDOWS_31X 0x0001
#define OSMINORTYPE_WINDOWS_95 0x0002
#define OSMINORTYPE_WINDOWS_NT 0x0003



#define PLANAR_CONTROL_BYTE(_nRunLength, _cRawBytes) \
	(_nRunLength & 0x0F) | ((_cRawBytes & 0x0F) << 4)
#define PLANAR_CONTROL_BYTE_RAW_BYTES(_controlByte) ((_controlByte >> 4) & 0x0F)
#define PLANAR_CONTROL_BYTE_RUN_LENGTH(_controlByte) (_controlByte & 0x0F)
#define PLANAR_FORMAT_HEADER_CLL_MASK 0x07
#define PLANAR_FORMAT_HEADER_CS (1 << 3)
#define PLANAR_FORMAT_HEADER_NA (1 << 5)
#define PLANAR_FORMAT_HEADER_RLE (1 << 4)




#define GFX_PIXEL_FORMAT_ARGB_8888 0x21
#define GFX_PIXEL_FORMAT_XRGB_8888 0x20
#define QUEUE_DEPTH_UNAVAILABLE 0x00000000
#define RDPGFX_CAPSET_BASE_SIZE 8
#define RDPGFX_CAPS_FLAG_AVC420_ENABLED 0x00000010U 
#define RDPGFX_CAPS_FLAG_AVC_DISABLED 0x00000020U   
#define RDPGFX_CAPS_FLAG_AVC_THINCLIENT 0x00000040U 
#define RDPGFX_CAPS_FLAG_SMALL_CACHE 0x00000002U    
#define RDPGFX_CAPS_FLAG_THINCLIENT 0x00000001U     
#define RDPGFX_CAPVERSION_10 0x000A0002  
#define RDPGFX_CAPVERSION_101 0x000A0100 
#define RDPGFX_CAPVERSION_102 0x000A0200 
#define RDPGFX_CAPVERSION_103 0x000A0301 
#define RDPGFX_CAPVERSION_104 0x000A0400 
#define RDPGFX_CAPVERSION_105 0x000A0502 
#define RDPGFX_CAPVERSION_106                                           \
	0x000A0600 
#define RDPGFX_CAPVERSION_8 0x00080004   
#define RDPGFX_CAPVERSION_81 0x00080105  
#define RDPGFX_CMDID_CACHEIMPORTOFFER 0x0010
#define RDPGFX_CMDID_CACHEIMPORTREPLY 0x0011
#define RDPGFX_CMDID_CACHETOSURFACE 0x0007
#define RDPGFX_CMDID_CAPSADVERTISE 0x0012
#define RDPGFX_CMDID_CAPSCONFIRM 0x0013
#define RDPGFX_CMDID_CREATESURFACE 0x0009
#define RDPGFX_CMDID_DELETEENCODINGCONTEXT 0x0003
#define RDPGFX_CMDID_DELETESURFACE 0x000A
#define RDPGFX_CMDID_ENDFRAME 0x000C
#define RDPGFX_CMDID_EVICTCACHEENTRY 0x0008
#define RDPGFX_CMDID_FRAMEACKNOWLEDGE 0x000D
#define RDPGFX_CMDID_MAPSURFACETOOUTPUT 0x000F
#define RDPGFX_CMDID_MAPSURFACETOSCALEDOUTPUT 0x0017
#define RDPGFX_CMDID_MAPSURFACETOSCALEDWINDOW 0x0018
#define RDPGFX_CMDID_MAPSURFACETOWINDOW 0x0015
#define RDPGFX_CMDID_QOEFRAMEACKNOWLEDGE 0x0016
#define RDPGFX_CMDID_RESETGRAPHICS 0x000E
#define RDPGFX_CMDID_SOLIDFILL 0x0004
#define RDPGFX_CMDID_STARTFRAME 0x000B
#define RDPGFX_CMDID_SURFACETOCACHE 0x0006
#define RDPGFX_CMDID_SURFACETOSURFACE 0x0005
#define RDPGFX_CMDID_UNUSED_0000 0x0000
#define RDPGFX_CMDID_UNUSED_0014 0x0014
#define RDPGFX_CMDID_WIRETOSURFACE_1 0x0001
#define RDPGFX_CMDID_WIRETOSURFACE_2 0x0002
#define RDPGFX_CODECID_ALPHA 0x000C
#define RDPGFX_CODECID_AVC420 0x000B
#define RDPGFX_CODECID_AVC444 0x000E
#define RDPGFX_CODECID_AVC444v2 0x000F
#define RDPGFX_CODECID_CAPROGRESSIVE 0x0009
#define RDPGFX_CODECID_CAPROGRESSIVE_V2 0x000D
#define RDPGFX_CODECID_CAVIDEO 0x0003
#define RDPGFX_CODECID_CLEARCODEC 0x0008
#define RDPGFX_CODECID_PLANAR 0x000A
#define RDPGFX_CODECID_UNCOMPRESSED 0x0000
#define RDPGFX_DVC_CHANNEL_NAME "Microsoft::Windows::RDS::Graphics"
#define RDPGFX_END_FRAME_PDU_SIZE 4
#define RDPGFX_HEADER_SIZE 8
#define RDPGFX_NUMBER_CAPSETS 9
#define RDPGFX_START_FRAME_PDU_SIZE 8
#define RDPGFX_WIRE_TO_SURFACE_PDU_1_SIZE 17
#define RDPGFX_WIRE_TO_SURFACE_PDU_2_SIZE 13
#define SUSPEND_FRAME_ACKNOWLEDGEMENT 0xFFFFFFFF

#define FREERDP_ADDIN_CHANNEL_DEVICE 0x00004000
#define FREERDP_ADDIN_CHANNEL_DYNAMIC 0x00002000
#define FREERDP_ADDIN_CHANNEL_ENTRYEX 0x00008000
#define FREERDP_ADDIN_CHANNEL_STATIC 0x00001000
#define FREERDP_ADDIN_CLIENT 0x00000001
#define FREERDP_ADDIN_DYNAMIC 0x00000020
#define FREERDP_ADDIN_NAME 0x00000100
#define FREERDP_ADDIN_SERVER 0x00000002
#define FREERDP_ADDIN_STATIC 0x00000010
#define FREERDP_ADDIN_SUBSYSTEM 0x00000200
#define FREERDP_ADDIN_TYPE 0x00000400


#define FREERDP_WINDOW_STATE_ACTIVE 4
#define FREERDP_WINDOW_STATE_FULLSCREEN 3
#define FREERDP_WINDOW_STATE_MAXIMIZED 2
#define FREERDP_WINDOW_STATE_MINIMIZED 1
#define FREERDP_WINDOW_STATE_NORMAL 0
#define AUTHENTICATIONERROR ERRORSTART + 9
#define CANCELEDBYUSER ERRORSTART + 11
#define CAT_ADMIN "administrative"
#define CAT_BROKER "broker"
#define CAT_CONFIG "config"
#define CAT_GATEWAY "gateway"
#define CAT_LICENSING "licensing"
#define CAT_NONE "success"
#define CAT_PROTOCOL "protocol"
#define CAT_SERVER "server"
#define CAT_USE "use"
#define CONNECTERROR                                                            \
	ERRORSTART + 6 
#define DNSERROR ERRORSTART + 4        
#define DNSNAMENOTFOUND ERRORSTART + 5 
#define ERRBASE_NONE ERRINFO_NONE
#define ERRBASE_SUCCESS ERRINFO_SUCCESS
#define ERRCONNECT_ACCESS_DENIED 0x00000016
#define ERRCONNECT_ACCOUNT_DISABLED 0x00000012
#define ERRCONNECT_ACCOUNT_EXPIRED 0x00000019
#define ERRCONNECT_ACCOUNT_LOCKED_OUT 0x00000018
#define ERRCONNECT_ACCOUNT_RESTRICTION 0x00000017
#define ERRCONNECT_AUTHENTICATION_FAILED 0x00000009
#define ERRCONNECT_CLIENT_REVOKED 0x00000010
#define ERRCONNECT_CONNECT_CANCELLED 0x0000000B
#define ERRCONNECT_CONNECT_FAILED 0x00000006
#define ERRCONNECT_CONNECT_TRANSPORT_FAILED 0x0000000D
#define ERRCONNECT_CONNECT_UNDEFINED 0x00000002
#define ERRCONNECT_DNS_ERROR 0x00000004
#define ERRCONNECT_DNS_NAME_NOT_FOUND 0x00000005
#define ERRCONNECT_INSUFFICIENT_PRIVILEGES 0x0000000A
#define ERRCONNECT_KDC_UNREACHABLE 0x00000011
#define ERRCONNECT_LOGON_FAILURE 0x00000014
#define ERRCONNECT_LOGON_TYPE_NOT_GRANTED 0x0000001A
#define ERRCONNECT_MCS_CONNECT_INITIAL_ERROR 0x00000007
#define ERRCONNECT_NONE ERRINFO_NONE
#define ERRCONNECT_NO_OR_MISSING_CREDENTIALS 0x0000001B
#define ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED 0x0000000F
#define ERRCONNECT_PASSWORD_EXPIRED 0x0000000E
#define ERRCONNECT_PASSWORD_MUST_CHANGE 0x00000013
#define ERRCONNECT_POST_CONNECT_FAILED 0x00000003
#define ERRCONNECT_PRE_CONNECT_FAILED 0x00000001
#define ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED 0x0000000C
#define ERRCONNECT_SUCCESS ERRINFO_SUCCESS
#define ERRCONNECT_TLS_CONNECT_FAILED 0x00000008
#define ERRCONNECT_WRONG_PASSWORD 0x00000015
#define ERRINFO_BAD_CAPABILITIES 0x000010EA
#define ERRINFO_BAD_FRAME_ACK_DATA 0x0000112C
#define ERRINFO_BAD_MONITOR_DATA 0x00001129
#define ERRINFO_BAD_SUPPRESS_OUTPUT_PDU 0x000010E3
#define ERRINFO_BITMAP_CACHE_ERROR_PDU_BAD_LENGTH 0x000010DF
#define ERRINFO_BITMAP_CACHE_ERROR_PDU_BAD_LENGTH2 0x000010F5
#define ERRINFO_CACHE_CAP_NOT_SET 0x000010F4
#define ERRINFO_CAPABILITY_SET_TOO_LARGE 0x000010E8
#define ERRINFO_CAPABILITY_SET_TOO_SMALL 0x000010E7
#define ERRINFO_CB_CONNECTION_CANCELLED 0x0000409
#define ERRINFO_CB_CONNECTION_ERROR_INVALID_SETTINGS 0x0000410
#define ERRINFO_CB_DESTINATION_NOT_FOUND 0x0000400
#define ERRINFO_CB_DESTINATION_POOL_NOT_FREE 0x0000408
#define ERRINFO_CB_LOADING_DESTINATION 0x0000402
#define ERRINFO_CB_REDIRECTING_TO_DESTINATION 0x0000404
#define ERRINFO_CB_SESSION_ONLINE_VM_BOOT 0x0000406
#define ERRINFO_CB_SESSION_ONLINE_VM_BOOT_TIMEOUT 0x0000411
#define ERRINFO_CB_SESSION_ONLINE_VM_NO_DNS 0x0000407
#define ERRINFO_CB_SESSION_ONLINE_VM_SESSMON_FAILED 0x0000412
#define ERRINFO_CB_SESSION_ONLINE_VM_WAKE 0x0000405
#define ERRINFO_CLOSE_STACK_ON_DRIVER_FAILURE 0x00000011
#define ERRINFO_CLOSE_STACK_ON_DRIVER_IFACE_FAILURE 0x00000012
#define ERRINFO_CLOSE_STACK_ON_DRIVER_NOT_READY 0x0000000F
#define ERRINFO_CONFIRM_ACTIVE_HAS_WRONG_ORIGINATOR 0x000010D5
#define ERRINFO_CONFIRM_ACTIVE_HAS_WRONG_SHAREID 0x000010D4
#define ERRINFO_CONFIRM_ACTIVE_PDU_TOO_SHORT 0x000010E5
#define ERRINFO_CONNECT_FAILED 0x000010D3
#define ERRINFO_CONTROL_PDU_SEQUENCE 0x000010CD
#define ERRINFO_CREATE_USER_DATA_FAILED 0x000010D2
#define ERRINFO_DATA_PDU_SEQUENCE 0x000010CB
#define ERRINFO_DECRYPT_FAILED 0x00001192
#define ERRINFO_DECRYPT_FAILED2 0x00001195
#define ERRINFO_DISCONNECTED_BY_OTHER_CONNECTION 0x00000005
#define ERRINFO_DRAWNINEGRID_CACHE_ERROR_PDU_BAD_LENGTH 0x000010F7
#define ERRINFO_DYNAMIC_DST_DISABLED_FIELD_MISSING 0x00001132
#define ERRINFO_ENCRYPTION_PACKAGE_MISMATCH 0x00001194
#define ERRINFO_ENCRYPT_FAILED 0x00001193
#define ERRINFO_GDIPLUS_PDU_BAD_LENGTH 0x000010F8
#define ERRINFO_GRAPHICS_MODE_NOT_SUPPORTED 0x0000112D
#define ERRINFO_GRAPHICS_SUBSYSTEM_FAILED 0x0000112F
#define ERRINFO_GRAPHICS_SUBSYSTEM_RESET_FAILED 0x0000112E
#define ERRINFO_IDLE_TIMEOUT 0x00000003
#define ERRINFO_INPUT_PDU_BAD_LENGTH 0x000010DE
#define ERRINFO_INVALIDMONITORCOUNT 0x00001136
#define ERRINFO_INVALID_CHANNEL_ID 0x000010EF
#define ERRINFO_INVALID_CONTROL_PDU_ACTION 0x000010CE
#define ERRINFO_INVALID_INPUT_PDU_MOUSE 0x000010D0
#define ERRINFO_INVALID_INPUT_PDU_TYPE 0x000010CF
#define ERRINFO_INVALID_REFRESH_RECT_PDU 0x000010D1
#define ERRINFO_INVALID_VC_COMPRESSION_TYPE 0x000010ED
#define ERRINFO_LICENSE_BAD_CLIENT_ENCRYPTION 0x00000108
#define ERRINFO_LICENSE_BAD_CLIENT_LICENSE 0x00000105
#define ERRINFO_LICENSE_BAD_CLIENT_MSG 0x00000103
#define ERRINFO_LICENSE_CANT_FINISH_PROTOCOL 0x00000106
#define ERRINFO_LICENSE_CANT_UPGRADE_LICENSE 0x00000109
#define ERRINFO_LICENSE_CLIENT_ENDED_PROTOCOL 0x00000107
#define ERRINFO_LICENSE_HWID_DOESNT_MATCH_LICENSE 0x00000104
#define ERRINFO_LICENSE_INTERNAL 0x00000100
#define ERRINFO_LICENSE_NO_LICENSE 0x00000102
#define ERRINFO_LICENSE_NO_LICENSE_SERVER 0x00000101
#define ERRINFO_LICENSE_NO_REMOTE_CONNECTIONS 0x0000010A
#define ERRINFO_LOGOFF_BY_USER 0x0000000C
#define ERRINFO_LOGON_TIMEOUT 0x00000004
#define ERRINFO_MONITORGEOMETRYVALIDATIONFAILED 0x00001135
#define ERRINFO_NONE 0xFFFFFFFF
#define ERRINFO_NO_CURSOR_CACHE 0x000010E9
#define ERRINFO_OFFSCREEN_CACHE_ERROR_PDU_BAD_LENGTH 0x000010F6
#define ERRINFO_OUT_OF_MEMORY 0x00000006
#define ERRINFO_PEER_DISCONNECTED 0x00001196
#define ERRINFO_PERSISTENT_KEY_PDU_BAD_LENGTH 0x000010DA
#define ERRINFO_PERSISTENT_KEY_PDU_ILLEGAL_FIRST 0x000010DB
#define ERRINFO_PERSISTENT_KEY_PDU_TOO_MANY_CACHE_KEYS 0x000010DD
#define ERRINFO_PERSISTENT_KEY_PDU_TOO_MANY_TOTAL_KEYS 0x000010DC
#define ERRINFO_REMOTEAPP_NOT_ENABLED 0x000010F3
#define ERRINFO_RPC_INITIATED_DISCONNECT 0x00000001
#define ERRINFO_RPC_INITIATED_DISCONNECT_BY_USER 0x0000000B
#define ERRINFO_RPC_INITIATED_LOGOFF 0x00000002
#define ERRINFO_SECURITY_DATA_TOO_SHORT 0x000010E0
#define ERRINFO_SECURITY_DATA_TOO_SHORT10 0x00001119
#define ERRINFO_SECURITY_DATA_TOO_SHORT11 0x0000111A
#define ERRINFO_SECURITY_DATA_TOO_SHORT12 0x0000111B
#define ERRINFO_SECURITY_DATA_TOO_SHORT13 0x0000111C
#define ERRINFO_SECURITY_DATA_TOO_SHORT14 0x0000111D
#define ERRINFO_SECURITY_DATA_TOO_SHORT15 0x0000111E
#define ERRINFO_SECURITY_DATA_TOO_SHORT16 0x0000111F
#define ERRINFO_SECURITY_DATA_TOO_SHORT17 0x00001120
#define ERRINFO_SECURITY_DATA_TOO_SHORT18 0x00001121
#define ERRINFO_SECURITY_DATA_TOO_SHORT19 0x00001122
#define ERRINFO_SECURITY_DATA_TOO_SHORT2 0x00001111
#define ERRINFO_SECURITY_DATA_TOO_SHORT20 0x00001123
#define ERRINFO_SECURITY_DATA_TOO_SHORT21 0x00001124
#define ERRINFO_SECURITY_DATA_TOO_SHORT22 0x00001125
#define ERRINFO_SECURITY_DATA_TOO_SHORT23 0x00001126
#define ERRINFO_SECURITY_DATA_TOO_SHORT3 0x00001112
#define ERRINFO_SECURITY_DATA_TOO_SHORT4 0x00001113
#define ERRINFO_SECURITY_DATA_TOO_SHORT5 0x00001114
#define ERRINFO_SECURITY_DATA_TOO_SHORT6 0x00001115
#define ERRINFO_SECURITY_DATA_TOO_SHORT7 0x00001116
#define ERRINFO_SECURITY_DATA_TOO_SHORT8 0x00001117
#define ERRINFO_SECURITY_DATA_TOO_SHORT9 0x00001118
#define ERRINFO_SERVER_CSRSS_CRASH 0x00000018
#define ERRINFO_SERVER_DENIED_CONNECTION 0x00000007
#define ERRINFO_SERVER_DWM_CRASH 0x00000010
#define ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED 0x0000000A
#define ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES 0x00000009
#define ERRINFO_SERVER_WINLOGON_CRASH 0x00000017
#define ERRINFO_SHARE_DATA_TOO_SHORT 0x000010E2
#define ERRINFO_SUCCESS 0x00000000
#define ERRINFO_TIMEZONE_KEY_NAME_LENGTH_TOO_LONG 0x00001131
#define ERRINFO_TIMEZONE_KEY_NAME_LENGTH_TOO_SHORT 0x00001130
#define ERRINFO_UNKNOWN_DATA_PDU_TYPE 0x000010C9
#define ERRINFO_UNKNOWN_PDU_TYPE 0x000010CA
#define ERRINFO_UPDATE_SESSION_KEY_FAILED 0x00001191
#define ERRINFO_VCHANNELS_TOO_MANY 0x000010F0
#define ERRINFO_VCHANNEL_DATA_TOO_SHORT 0x000010E1
#define ERRINFO_VC_DATA_TOO_LONG 0x0000112B
#define ERRINFO_VC_DECODING_ERROR 0x00001133
#define ERRINFO_VC_DECOMPRESSED_REASSEMBLE_FAILED 0x0000112A
#define ERRINFO_VIRTUALDESKTOPTOOLARGE 0x00001134
#define ERRINFO_VIRTUAL_CHANNEL_DECOMPRESSION 0x000010EC
#define ERRORSTART 10000
#define FREERDP_ERROR_AUTHENTICATION_FAILED \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_AUTHENTICATION_FAILED)
#define FREERDP_ERROR_BASE 0
#define FREERDP_ERROR_CLOSE_STACK_ON_DRIVER_FAILURE \
	MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_CLOSE_STACK_ON_DRIVER_FAILURE)
#define FREERDP_ERROR_CLOSE_STACK_ON_DRIVER_IFACE_FAILURE \
	MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_CLOSE_STACK_ON_DRIVER_IFACE_FAILURE)
#define FREERDP_ERROR_CLOSE_STACK_ON_DRIVER_NOT_READY \
	MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_CLOSE_STACK_ON_DRIVER_NOT_READY)
#define FREERDP_ERROR_CONNECT_ACCESS_DENIED MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_ACCESS_DENIED)
#define FREERDP_ERROR_CONNECT_ACCOUNT_DISABLED \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_ACCOUNT_DISABLED)
#define FREERDP_ERROR_CONNECT_ACCOUNT_EXPIRED \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_ACCOUNT_EXPIRED)
#define FREERDP_ERROR_CONNECT_ACCOUNT_LOCKED_OUT \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_ACCOUNT_LOCKED_OUT)
#define FREERDP_ERROR_CONNECT_ACCOUNT_RESTRICTION \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_ACCOUNT_RESTRICTION)
#define FREERDP_ERROR_CONNECT_CANCELLED MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_CONNECT_CANCELLED)
#define FREERDP_ERROR_CONNECT_CLASS (FREERDP_ERROR_BASE + 2)
#define FREERDP_ERROR_CONNECT_CLIENT_REVOKED MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_CLIENT_REVOKED)
#define FREERDP_ERROR_CONNECT_FAILED MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_CONNECT_FAILED)
#define FREERDP_ERROR_CONNECT_KDC_UNREACHABLE \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_KDC_UNREACHABLE)
#define FREERDP_ERROR_CONNECT_LOGON_FAILURE MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_LOGON_FAILURE)
#define FREERDP_ERROR_CONNECT_LOGON_TYPE_NOT_GRANTED \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_LOGON_TYPE_NOT_GRANTED)
#define FREERDP_ERROR_CONNECT_NO_OR_MISSING_CREDENTIALS \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_NO_OR_MISSING_CREDENTIALS)
#define FREERDP_ERROR_CONNECT_PASSWORD_CERTAINLY_EXPIRED \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED)
#define FREERDP_ERROR_CONNECT_PASSWORD_EXPIRED \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_PASSWORD_EXPIRED)
#define FREERDP_ERROR_CONNECT_PASSWORD_MUST_CHANGE \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_PASSWORD_MUST_CHANGE)
#define FREERDP_ERROR_CONNECT_TRANSPORT_FAILED \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_CONNECT_TRANSPORT_FAILED)
#define FREERDP_ERROR_CONNECT_UNDEFINED MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_CONNECT_UNDEFINED)
#define FREERDP_ERROR_CONNECT_WRONG_PASSWORD MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_WRONG_PASSWORD)
#define FREERDP_ERROR_DISCONNECTED_BY_OTHER_CONNECTION \
	MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_DISCONNECTED_BY_OTHER_CONNECTION)
#define FREERDP_ERROR_DNS_ERROR MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_DNS_ERROR)
#define FREERDP_ERROR_DNS_NAME_NOT_FOUND MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_DNS_NAME_NOT_FOUND)
#define FREERDP_ERROR_ERRBASE_CLASS (FREERDP_ERROR_BASE + 0)
#define FREERDP_ERROR_ERRINFO_CLASS (FREERDP_ERROR_BASE + 1)

#define FREERDP_ERROR_IDLE_TIMEOUT MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_IDLE_TIMEOUT)
#define FREERDP_ERROR_INSUFFICIENT_PRIVILEGES \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_INSUFFICIENT_PRIVILEGES)
#define FREERDP_ERROR_LOGOFF_BY_USER MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_LOGOFF_BY_USER)
#define FREERDP_ERROR_LOGON_TIMEOUT MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_LOGON_TIMEOUT)
#define FREERDP_ERROR_MCS_CONNECT_INITIAL_ERROR \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_MCS_CONNECT_INITIAL_ERROR)
#define FREERDP_ERROR_NONE ERRINFO_NONE
#define FREERDP_ERROR_OUT_OF_MEMORY MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_OUT_OF_MEMORY)
#define FREERDP_ERROR_POST_CONNECT_FAILED \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_POST_CONNECT_FAILED)
#define FREERDP_ERROR_PRE_CONNECT_FAILED MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_PRE_CONNECT_FAILED)
#define FREERDP_ERROR_RPC_INITIATED_DISCONNECT \
	MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_RPC_INITIATED_DISCONNECT)
#define FREERDP_ERROR_RPC_INITIATED_DISCONNECT_BY_USER \
	MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_RPC_INITIATED_DISCONNECT_BY_USER)
#define FREERDP_ERROR_RPC_INITIATED_LOGOFF MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_RPC_INITIATED_LOGOFF)
#define FREERDP_ERROR_SECURITY_NEGO_CONNECT_FAILED \
	MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED)
#define FREERDP_ERROR_SERVER_CSRSS_CRASH MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_SERVER_CSRSS_CRASH)
#define FREERDP_ERROR_SERVER_DENIED_CONNECTION \
	MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_SERVER_DENIED_CONNECTION)
#define FREERDP_ERROR_SERVER_DWM_CRASH MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_SERVER_DWM_CRASH)
#define FREERDP_ERROR_SERVER_FRESH_CREDENTIALS_REQUIRED \
	MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED)
#define FREERDP_ERROR_SERVER_INSUFFICIENT_PRIVILEGES \
	MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES)
#define FREERDP_ERROR_SERVER_WINLOGON_CRASH \
	MAKE_FREERDP_ERROR(ERRINFO, ERRINFO_SERVER_WINLOGON_CRASH)
#define FREERDP_ERROR_SUCCESS ERRINFO_SUCCESS
#define FREERDP_ERROR_TLS_CONNECT_FAILED MAKE_FREERDP_ERROR(CONNECT, ERRCONNECT_TLS_CONNECT_FAILED)
#define GET_FREERDP_ERROR_CLASS(_errorCode) ((_errorCode >> 16) & 0xFFFF)

#define GET_FREERDP_ERROR_TYPE(_errorCode) (_errorCode & 0xFFFF)
#define INSUFFICIENTPRIVILEGESERROR ERRORSTART + 10
#define MAKE_FREERDP_ERROR(_class, _type) (((FREERDP_ERROR_##_class##_CLASS) << 16) | (_type))
#define MCSCONNECTINITIALERROR ERRORSTART + 7
#define POSTCONNECTERROR ERRORSTART + 3
#define PREECONNECTERROR ERRORSTART + 1
#define TLSCONNECTERROR ERRORSTART + 8
#define UNDEFINEDCONNECTERROR ERRORSTART + 2



#define BOUND_BOTTOM 0x08
#define BOUND_DELTA_BOTTOM 0x80
#define BOUND_DELTA_LEFT 0x10
#define BOUND_DELTA_RIGHT 0x40
#define BOUND_DELTA_TOP 0x20
#define BOUND_LEFT 0x01
#define BOUND_RIGHT 0x04
#define BOUND_TOP 0x02
#define CBR23_16BPP 0x4
#define CBR23_24BPP 0x5
#define CBR23_32BPP 0x6
#define CBR23_8BPP 0x3
#define CBR2_16BPP 0x4
#define CBR2_24BPP 0x5
#define CBR2_32BPP 0x6
#define CBR2_8BPP 0x3
#define CBR3_DO_NOT_CACHE 0x10
#define CBR3_IGNORABLE_FLAG 0x08
#define CG_GLYPH_UNICODE_PRESENT 0x0010
#define DRAW_NINE_GRID_ORDER_FIELDS 5
#define DRAW_NINE_GRID_ORDER_FIELD_BYTES 1
#define DSTBLT_ORDER_FIELDS 5
#define DSTBLT_ORDER_FIELD_BYTES 1
#define ELLIPSE_CB_ORDER_FIELDS 13
#define ELLIPSE_CB_ORDER_FIELD_BYTES 2
#define ELLIPSE_SC_ORDER_FIELDS 7
#define ELLIPSE_SC_ORDER_FIELD_BYTES 1
#define FAST_GLYPH_ORDER_FIELDS 15
#define FAST_GLYPH_ORDER_FIELD_BYTES 2
#define FAST_INDEX_ORDER_FIELDS 15
#define FAST_INDEX_ORDER_FIELD_BYTES 2

#define GLYPH_INDEX_ORDER_FIELDS 22
#define GLYPH_INDEX_ORDER_FIELD_BYTES 3
#define LINE_TO_ORDER_FIELDS 10
#define LINE_TO_ORDER_FIELD_BYTES 2
#define MEM3BLT_ORDER_FIELDS 16
#define MEM3BLT_ORDER_FIELD_BYTES 3
#define MEMBLT_ORDER_FIELDS 9
#define MEMBLT_ORDER_FIELD_BYTES 2
#define MULTI_DRAW_NINE_GRID_ORDER_FIELDS 7
#define MULTI_DRAW_NINE_GRID_ORDER_FIELD_BYTES 1
#define MULTI_DSTBLT_ORDER_FIELDS 7
#define MULTI_DSTBLT_ORDER_FIELD_BYTES 1
#define MULTI_OPAQUE_RECT_ORDER_FIELDS 9
#define MULTI_OPAQUE_RECT_ORDER_FIELD_BYTES 2
#define MULTI_PATBLT_ORDER_FIELDS 14
#define MULTI_PATBLT_ORDER_FIELD_BYTES 2
#define MULTI_SCRBLT_ORDER_FIELDS 9
#define MULTI_SCRBLT_ORDER_FIELD_BYTES 2
#define OPAQUE_RECT_ORDER_FIELDS 7
#define OPAQUE_RECT_ORDER_FIELD_BYTES 1
#define ORDER_BOUNDS 0x04
#define ORDER_DELTA_COORDINATES 0x10
#define ORDER_FIELD_01 0x000001
#define ORDER_FIELD_02 0x000002
#define ORDER_FIELD_03 0x000004
#define ORDER_FIELD_04 0x000008
#define ORDER_FIELD_05 0x000010
#define ORDER_FIELD_06 0x000020
#define ORDER_FIELD_07 0x000040
#define ORDER_FIELD_08 0x000080
#define ORDER_FIELD_09 0x000100
#define ORDER_FIELD_10 0x000200
#define ORDER_FIELD_11 0x000400
#define ORDER_FIELD_12 0x000800
#define ORDER_FIELD_13 0x001000
#define ORDER_FIELD_14 0x002000
#define ORDER_FIELD_15 0x004000
#define ORDER_FIELD_16 0x008000
#define ORDER_FIELD_17 0x010000
#define ORDER_FIELD_18 0x020000
#define ORDER_FIELD_19 0x040000
#define ORDER_FIELD_20 0x080000
#define ORDER_FIELD_21 0x100000
#define ORDER_FIELD_22 0x200000
#define ORDER_FIELD_23 0x400000
#define ORDER_SECONDARY 0x02
#define ORDER_STANDARD 0x01
#define ORDER_TYPE_BITMAP_COMPRESSED_V2 0x05
#define ORDER_TYPE_BITMAP_COMPRESSED_V3 0x08
#define ORDER_TYPE_BITMAP_UNCOMPRESSED 0x00
#define ORDER_TYPE_BITMAP_UNCOMPRESSED_V2 0x04
#define ORDER_TYPE_CACHE_BITMAP_COMPRESSED 0x02
#define ORDER_TYPE_CACHE_BRUSH 0x07
#define ORDER_TYPE_CACHE_COLOR_TABLE 0x01
#define ORDER_TYPE_CACHE_GLYPH 0x03
#define ORDER_TYPE_CHANGE 0x08
#define ORDER_TYPE_COMPDESK_FIRST 0x0C
#define ORDER_TYPE_CREATE_NINE_GRID_BITMAP 0x04
#define ORDER_TYPE_CREATE_OFFSCREEN_BITMAP 0x01
#define ORDER_TYPE_DRAW_NINE_GRID 0x07
#define ORDER_TYPE_DSTBLT 0x00
#define ORDER_TYPE_ELLIPSE_CB 0x1A
#define ORDER_TYPE_ELLIPSE_SC 0x19
#define ORDER_TYPE_FAST_GLYPH 0x18
#define ORDER_TYPE_FAST_INDEX 0x13
#define ORDER_TYPE_FRAME_MARKER 0x0D
#define ORDER_TYPE_GDIPLUS_CACHE_END 0x0A
#define ORDER_TYPE_GDIPLUS_CACHE_FIRST 0x08
#define ORDER_TYPE_GDIPLUS_CACHE_NEXT 0x09
#define ORDER_TYPE_GDIPLUS_END 0x07
#define ORDER_TYPE_GDIPLUS_FIRST 0x05
#define ORDER_TYPE_GDIPLUS_NEXT 0x06
#define ORDER_TYPE_GLYPH_INDEX 0x1B
#define ORDER_TYPE_LINE_TO 0x09
#define ORDER_TYPE_MEM3BLT 0x0E
#define ORDER_TYPE_MEMBLT 0x0D
#define ORDER_TYPE_MULTI_DRAW_NINE_GRID 0x08
#define ORDER_TYPE_MULTI_DSTBLT 0x0F
#define ORDER_TYPE_MULTI_OPAQUE_RECT 0x12
#define ORDER_TYPE_MULTI_PATBLT 0x10
#define ORDER_TYPE_MULTI_SCRBLT 0x11
#define ORDER_TYPE_OPAQUE_RECT 0x0A
#define ORDER_TYPE_PATBLT 0x01
#define ORDER_TYPE_POLYGON_CB 0x15
#define ORDER_TYPE_POLYGON_SC 0x14
#define ORDER_TYPE_POLYLINE 0x16
#define ORDER_TYPE_SAVE_BITMAP 0x0B
#define ORDER_TYPE_SCRBLT 0x02
#define ORDER_TYPE_STREAM_BITMAP_FIRST 0x02
#define ORDER_TYPE_STREAM_BITMAP_NEXT 0x03
#define ORDER_TYPE_SWITCH_SURFACE 0x00
#define ORDER_TYPE_WINDOW 0x0B
#define ORDER_ZERO_BOUNDS_DELTAS 0x20
#define ORDER_ZERO_FIELD_BYTE_BIT0 0x40
#define ORDER_ZERO_FIELD_BYTE_BIT1 0x80
#define PATBLT_ORDER_FIELDS 12
#define PATBLT_ORDER_FIELD_BYTES 2
#define POLYGON_CB_ORDER_FIELDS 13
#define POLYGON_CB_ORDER_FIELD_BYTES 2
#define POLYGON_SC_ORDER_FIELDS 7
#define POLYGON_SC_ORDER_FIELD_BYTES 1
#define POLYLINE_ORDER_FIELDS 7
#define POLYLINE_ORDER_FIELD_BYTES 1
#define SAVE_BITMAP_ORDER_FIELDS 6
#define SAVE_BITMAP_ORDER_FIELD_BYTES 1
#define SCRBLT_ORDER_FIELDS 7
#define SCRBLT_ORDER_FIELD_BYTES 1
#define DATA_PDU_TYPE_ARC_STATUS 0x32
#define DATA_PDU_TYPE_BITMAP_CACHE_ERROR 0x2C
#define DATA_PDU_TYPE_BITMAP_CACHE_PERSISTENT_LIST 0x2B
#define DATA_PDU_TYPE_CONTROL 0x14
#define DATA_PDU_TYPE_DRAW_GDIPLUS_ERROR 0x31
#define DATA_PDU_TYPE_DRAW_NINEGRID_ERROR 0x30
#define DATA_PDU_TYPE_FONT_LIST 0x27
#define DATA_PDU_TYPE_FONT_MAP 0x28
#define DATA_PDU_TYPE_FRAME_ACKNOWLEDGE 0x38
#define DATA_PDU_TYPE_INPUT 0x1C
#define DATA_PDU_TYPE_MONITOR_LAYOUT 0x37
#define DATA_PDU_TYPE_OFFSCREEN_CACHE_ERROR 0x2E
#define DATA_PDU_TYPE_PLAY_SOUND 0x22
#define DATA_PDU_TYPE_POINTER 0x1B
#define DATA_PDU_TYPE_REFRESH_RECT 0x21
#define DATA_PDU_TYPE_SAVE_SESSION_INFO 0x26
#define DATA_PDU_TYPE_SET_ERROR_INFO 0x2F
#define DATA_PDU_TYPE_SET_KEYBOARD_IME_STATUS 0x2D
#define DATA_PDU_TYPE_SET_KEYBOARD_INDICATORS 0x29
#define DATA_PDU_TYPE_SHUTDOWN_DENIED 0x25
#define DATA_PDU_TYPE_SHUTDOWN_REQUEST 0x24
#define DATA_PDU_TYPE_STATUS_INFO 0x36
#define DATA_PDU_TYPE_SUPPRESS_OUTPUT 0x23
#define DATA_PDU_TYPE_SYNCHRONIZE 0x1F
#define DATA_PDU_TYPE_UPDATE 0x02
#define DEBUG_RDP(...) WLog_DBG(RDP_TAG, __VA_ARGS__)
#define FINALIZE_SC_COMPLETE 0x0F
#define FINALIZE_SC_CONTROL_COOPERATE_PDU 0x02
#define FINALIZE_SC_CONTROL_GRANTED_PDU 0x04
#define FINALIZE_SC_FONT_MAP_PDU 0x08
#define FINALIZE_SC_SYNCHRONIZE_PDU 0x01

#define PDU_TYPE_CONFIRM_ACTIVE 0x3
#define PDU_TYPE_DATA 0x7
#define PDU_TYPE_DEACTIVATE_ALL 0x6
#define PDU_TYPE_DEMAND_ACTIVE 0x1
#define PDU_TYPE_FLOW_RESPONSE 0x42
#define PDU_TYPE_FLOW_STOP 0x43
#define PDU_TYPE_FLOW_TEST 0x41
#define PDU_TYPE_SERVER_REDIRECTION 0xA
#define RDP_PACKET_HEADER_MAX_LENGTH (TPDU_DATA_LENGTH + MCS_SEND_DATA_HEADER_MAX_LENGTH)
#define RDP_SECURITY_HEADER_LENGTH 4
#define RDP_SHARE_CONTROL_HEADER_LENGTH 6
#define RDP_SHARE_DATA_HEADER_LENGTH 12
#define RDP_TAG FREERDP_TAG("core.rdp")
#define SEC_AUTODETECT_REQ 0x1000
#define SEC_AUTODETECT_RSP 0x2000
#define SEC_ENCRYPT 0x0008
#define SEC_EXCHANGE_PKT 0x0001
#define SEC_FLAGSHI_VALID 0x8000
#define SEC_HEARTBEAT 0x4000
#define SEC_IGNORE_SEQNO 0x0020
#define SEC_INFO_PKT 0x0040
#define SEC_LICENSE_ENCRYPT_CS 0x0200
#define SEC_LICENSE_ENCRYPT_SC 0x0200
#define SEC_LICENSE_PKT 0x0080
#define SEC_PKT_CS_MASK (SEC_EXCHANGE_PKT | SEC_INFO_PKT)
#define SEC_PKT_MASK (SEC_PKT_CS_MASK | SEC_PKT_SC_MASK)
#define SEC_PKT_SC_MASK (SEC_LICENSE_PKT | SEC_REDIRECTION_PKT)
#define SEC_REDIRECTION_PKT 0x0400
#define SEC_RESET_SEQNO 0x0010
#define SEC_SECURE_CHECKSUM 0x0800
#define SEC_TRANSPORT_REQ 0x0002
#define SEC_TRANSPORT_RSP 0x0004
#define STREAM_HI 0x04
#define STREAM_LOW 0x01
#define STREAM_MED 0x02
#define STREAM_UNDEFINED 0x00

#define CHANNEL_MAX_COUNT 30





#define CHANNEL_EVENT_USER 1000
#define CHANNEL_EXPORT_FUNC_NAME "VirtualChannelEntry"
#define CHANNEL_EXPORT_FUNC_NAME_EX "VirtualChannelEntryEx"
#define FREERDP_CHANNEL_MAGIC_NUMBER 0x46524450

#define ALLOW_CACHE_WAITING_LIST_FLAG 0x0002
#define ALTSEC_FRAME_MARKER_SUPPORT 0x0004
#define AUTORECONNECT_SUPPORTED 0x0008
#define BITMAP_CACHE_V2 0x01
#define BRUSH_COLOR_8x8 0x00000001
#define BRUSH_COLOR_FULL 0x00000002
#define BRUSH_DEFAULT 0x00000000
#define CACHE_BITMAP_V3_SUPPORT 0x0002
#define CAPSET_HEADER_LENGTH 4
#define CAPSET_TYPE_ACTIVATION 0x0007
#define CAPSET_TYPE_BITMAP 0x0002
#define CAPSET_TYPE_BITMAP_CACHE 0x0004
#define CAPSET_TYPE_BITMAP_CACHE_HOST_SUPPORT 0x0012
#define CAPSET_TYPE_BITMAP_CACHE_V2 0x0013
#define CAPSET_TYPE_BITMAP_CACHE_V3_CODEC_ID 0x0006
#define CAPSET_TYPE_BITMAP_CODECS 0x001D
#define CAPSET_TYPE_BRUSH 0x000F
#define CAPSET_TYPE_COLOR_CACHE 0x000A
#define CAPSET_TYPE_COMP_DESK 0x0019
#define CAPSET_TYPE_CONTROL 0x0005
#define CAPSET_TYPE_DRAW_GDI_PLUS 0x0016
#define CAPSET_TYPE_DRAW_NINE_GRID_CACHE 0x0015
#define CAPSET_TYPE_FONT 0x000E
#define CAPSET_TYPE_FRAME_ACKNOWLEDGE 0x001E
#define CAPSET_TYPE_GENERAL 0x0001
#define CAPSET_TYPE_GLYPH_CACHE 0x0010
#define CAPSET_TYPE_INPUT 0x000D
#define CAPSET_TYPE_LARGE_POINTER 0x001B
#define CAPSET_TYPE_MULTI_FRAGMENT_UPDATE 0x001A
#define CAPSET_TYPE_OFFSCREEN_CACHE 0x0011
#define CAPSET_TYPE_ORDER 0x0003
#define CAPSET_TYPE_POINTER 0x0008
#define CAPSET_TYPE_RAIL 0x0017
#define CAPSET_TYPE_SHARE 0x0009
#define CAPSET_TYPE_SOUND 0x000C
#define CAPSET_TYPE_SURFACE_COMMANDS 0x001C
#define CAPSET_TYPE_VIRTUAL_CHANNEL 0x0014
#define CAPSET_TYPE_WINDOW 0x0018
#define CAPS_PROTOCOL_VERSION 0x0200
#define CARDP_CAPS_CAPTURE_NON_CAC 0x00000001
#define CBY_CAPS 0xCBC0
#define CBY_CAPSET 0xCBC1
#define CLW_COL_CONV_ICT 0x1
#define CLW_ENTROPY_RLGR1 0x01
#define CLW_ENTROPY_RLGR3 0x04
#define CLW_VERSION_1_0 0x0100
#define CLW_XFORM_DWT_53_A 0x1
#define CLY_CAPSET 0xCFC0
#define COLOR_INDEX_SUPPORT 0x0020
#define COMPDESK_NOT_SUPPORTED 0x0000
#define COMPDESK_SUPPORTED 0x0001
#define CT_TILE_64x64 0x0040
#define DRAW_ALLOW_COLOR_SUBSAMPLING 0x04
#define DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY 0x02
#define DRAW_ALLOW_SKIP_ALPHA 0x08
#define DRAW_GDIPLUS_CACHE_LEVEL_DEFAULT 0x00000000
#define DRAW_GDIPLUS_CACHE_LEVEL_ONE 0x00000001
#define DRAW_GDIPLUS_DEFAULT 0x00000000
#define DRAW_GDIPLUS_SUPPORTED 0x00000001
#define DRAW_NINEGRID_NO_SUPPORT 0x00000000
#define DRAW_NINEGRID_SUPPORTED 0x00000001
#define DRAW_NINEGRID_SUPPORTED_V2 0x00000002
#define ENC_SALTED_CHECKSUM 0x0010
#define FASTPATH_OUTPUT_SUPPORTED 0x0001
#define FONTSUPPORT_FONTLIST 0x0001

#define INPUT_FLAG_FASTPATH_INPUT 0x0008
#define INPUT_FLAG_FASTPATH_INPUT2 0x0020
#define INPUT_FLAG_MOUSEX 0x0004
#define INPUT_FLAG_SCANCODES 0x0001
#define INPUT_FLAG_UNICODE 0x0010
#define LARGE_POINTER_FLAG_384x384 0x00000002
#define LARGE_POINTER_FLAG_96x96 0x00000001
#define LONG_CREDENTIALS_SUPPORTED 0x0004
#define NEGOTIATE_ORDER_SUPPORT 0x0002
#define NO_BITMAP_COMPRESSION_HDR 0x0400
#define ORDER_FLAGS_EXTRA_SUPPORT 0x0080
#define PERSISTENT_KEYS_EXPECTED_FLAG 0x0001
#define SOLID_PATTERN_BRUSH_ONLY 0x0040
#define SOUND_BEEPS_FLAG 0x0001
#define SOURCE_DESCRIPTOR "FREERDP"
#define SURFCMDS_FRAME_MARKER 0x00000010
#define SURFCMDS_SET_SURFACE_BITS 0x00000002
#define SURFCMDS_STREAM_SURFACE_BITS 0x00000040
#define TS_INPUT_FLAG_MOUSE_HWHEEL 0x0100
#define TS_INPUT_FLAG_QOE_TIMESTAMPS 0x0200
#define VCCAPS_COMPR_CS_8K 0x00000002
#define VCCAPS_COMPR_SC 0x00000001
#define VCCAPS_NO_COMPR 0x00000000
#define WINDOW_LEVEL_NOT_SUPPORTED 0x00000000
#define WINDOW_LEVEL_SUPPORTED 0x00000001
#define WINDOW_LEVEL_SUPPORTED_EX 0x00000002
#define ZERO_BOUNDS_DELTA_SUPPORT 0x0008
#define DEBUG_REDIR(...) WLog_DBG(REDIR_TAG, __VA_ARGS__)

#define REDIR_TAG FREERDP_TAG("core.redirection")

#define CTRLACTION_COOPERATE 0x0004
#define CTRLACTION_DETACH 0x0003
#define CTRLACTION_GRANTED_CONTROL 0x0002
#define CTRLACTION_REQUEST_CONTROL 0x0001
#define FONTLIST_FIRST 0x0001
#define FONTLIST_LAST 0x0002

#define PERSIST_FIRST_PDU 0x01
#define PERSIST_LAST_PDU 0x02
#define SYNCMSGTYPE_SYNC 0x0001

#define MCS_BASE_CHANNEL_ID 1001
#define MCS_GLOBAL_CHANNEL_ID 1003
#define MCS_SEND_DATA_HEADER_MAX_LENGTH 8
#define MCS_TYPE_CONNECT_INITIAL 0x65
#define MCS_TYPE_CONNECT_RESPONSE 0x66
#define BER_CLASS_APPL 0x40 
#define BER_CLASS_CTXT 0x80 
#define BER_CLASS_MASK 0xC0
#define BER_CLASS_PRIV 0xC0 
#define BER_CLASS_UNIV 0x00 
#define BER_CONSTRUCT 0x20 
#define BER_PC(_pc) (_pc ? BER_CONSTRUCT : BER_PRIMITIVE)
#define BER_PC_MASK 0x20
#define BER_PRIMITIVE 0x00 
#define BER_TAG_BIT_STRING 0x03
#define BER_TAG_BOOLEAN 0x01
#define BER_TAG_ENUMERATED 0x0A
#define BER_TAG_INTEGER 0x02
#define BER_TAG_MASK 0x1F
#define BER_TAG_OBJECT_IDENFIER 0x06
#define BER_TAG_OCTET_STRING 0x04
#define BER_TAG_SEQUENCE 0x10
#define BER_TAG_SEQUENCE_OF 0x10



#define TLS_ALERT_DESCRIPTION_ACCESS_DENIED 49
#define TLS_ALERT_DESCRIPTION_BAD_CERTIFICATE 42
#define TLS_ALERT_DESCRIPTION_BAD_RECORD_MAC 20
#define TLS_ALERT_DESCRIPTION_CERTIFICATE_EXPIRED 45
#define TLS_ALERT_DESCRIPTION_CERTIFICATE_REVOKED 44
#define TLS_ALERT_DESCRIPTION_CERTIFICATE_UNKNOWN 46
#define TLS_ALERT_DESCRIPTION_CLOSE_NOTIFY 0
#define TLS_ALERT_DESCRIPTION_DECODE_ERROR 50
#define TLS_ALERT_DESCRIPTION_DECOMPRESSION_FAILURE 30
#define TLS_ALERT_DESCRIPTION_DECRYPTION_FAILED 21
#define TLS_ALERT_DESCRIPTION_DECRYPT_ERROR 51
#define TLS_ALERT_DESCRIPTION_EXPORT_RESTRICTION 60
#define TLS_ALERT_DESCRIPTION_HANSHAKE_FAILURE 40
#define TLS_ALERT_DESCRIPTION_ILLEGAL_PARAMETER 47
#define TLS_ALERT_DESCRIPTION_INSUFFICIENT_SECURITY 71
#define TLS_ALERT_DESCRIPTION_INTERNAL_ERROR 80
#define TLS_ALERT_DESCRIPTION_NO_CERTIFICATE 41
#define TLS_ALERT_DESCRIPTION_NO_RENEGOTIATION 100
#define TLS_ALERT_DESCRIPTION_PROTOCOL_VERSION 70
#define TLS_ALERT_DESCRIPTION_RECORD_OVERFLOW 22
#define TLS_ALERT_DESCRIPTION_UNEXPECTED_MESSAGE 10
#define TLS_ALERT_DESCRIPTION_UNKNOWN_CA 48
#define TLS_ALERT_DESCRIPTION_UNSUPPORTED_CERTIFICATE 43
#define TLS_ALERT_DESCRIPTION_UNSUPPORTED_EXTENSION 110
#define TLS_ALERT_DESCRIPTION_USER_CANCELED 90
#define TLS_ALERT_LEVEL_FATAL 2
#define TLS_ALERT_LEVEL_WARNING 1


#define E_PROXY_ALREADYDISCONNECTED 0x800759DF
#define E_PROXY_CAPABILITYMISMATCH 0x800759E9
#define E_PROXY_CONNECTIONABORTED 0x000004D4
#define E_PROXY_COOKIE_AUTHENTICATION_ACCESS_DENIED 0x800759F8
#define E_PROXY_COOKIE_BADPACKET 0x800759F7
#define E_PROXY_INTERNALERROR 0x800759D8
#define E_PROXY_MAXCONNECTIONSREACHED 0x000059E6
#define E_PROXY_NAP_ACCESSDENIED 0x800759DB
#define E_PROXY_NOCERTAVAILABLE 0x800759EE
#define E_PROXY_NOTSUPPORTED 0x000059E8
#define E_PROXY_QUARANTINE_ACCESSDENIED 0x800759ED
#define E_PROXY_RAP_ACCESSDENIED 0x800759DA
#define E_PROXY_REAUTH_AUTHN_FAILED 0x000059FA
#define E_PROXY_REAUTH_CAP_FAILED 0x000059FB
#define E_PROXY_REAUTH_NAP_FAILED 0x00005A00
#define E_PROXY_REAUTH_RAP_FAILED 0x000059FC
#define E_PROXY_SDR_NOT_SUPPORTED_BY_TS 0x000059FD
#define E_PROXY_SESSIONTIMEOUT 0x000059F6
#define E_PROXY_TS_CONNECTFAILED 0x800759DD
#define E_PROXY_UNSUPPORTED_AUTHENTICATION_METHOD 0x800759F9

#define MAX_RESOURCE_NAMES 50
#define TSG_ASYNC_MESSAGE_CONSENT_MESSAGE 0x00000001
#define TSG_ASYNC_MESSAGE_REAUTH 0x00000003
#define TSG_ASYNC_MESSAGE_SERVICE_MESSAGE 0x00000002
#define TSG_CAPABILITY_TYPE_NAP 0x00000001
#define TSG_MESSAGING_CAP_CONSENT_SIGN 0x00000004
#define TSG_MESSAGING_CAP_REAUTH 0x00000010
#define TSG_MESSAGING_CAP_SERVICE_MSG 0x00000008
#define TSG_MESSAGING_MAX_MESSAGE_LENGTH 65536
#define TSG_NAP_CAPABILITY_IDLE_TIMEOUT 0x00000002
#define TSG_NAP_CAPABILITY_QUAR_SOH 0x00000001
#define TSG_PACKET_TYPE_AUTH 0x00004054
#define TSG_PACKET_TYPE_CAPS_RESPONSE 0x00004350
#define TSG_PACKET_TYPE_HEADER 0x00004844
#define TSG_PACKET_TYPE_MESSAGE_PACKET 0x00004750
#define TSG_PACKET_TYPE_MSGREQUEST_PACKET 0x00004752
#define TSG_PACKET_TYPE_QUARCONFIGREQUEST 0x00005143
#define TSG_PACKET_TYPE_QUARENC_RESPONSE 0x00004552
#define TSG_PACKET_TYPE_QUARREQUEST 0x00005152
#define TSG_PACKET_TYPE_REAUTH 0x00005250
#define TSG_PACKET_TYPE_RESPONSE 0x00005052
#define TSG_PACKET_TYPE_VERSIONCAPS 0x00005643
#define TSG_TUNNEL_CALL_ASYNC_MSG_REQUEST 0x00000001
#define TSG_TUNNEL_CANCEL_ASYNC_MSG_REQUEST 0x00000002
#define TS_GATEWAY_TRANSPORT 0x5452
#define TsProxyAuthorizeTunnelOpnum 2
#define TsProxyCloseChannelOpnum 6
#define TsProxyCloseTunnelOpnum 7
#define TsProxyCreateChannelOpnum 4
#define TsProxyCreateTunnelOpnum 1
#define TsProxyMakeTunnelCallOpnum 3
#define TsProxySendToServerOpnum 9
#define TsProxySetupReceivePipeOpnum 8
#define TsProxyUnused5Opnum 5

#define D2I_X509_CONST const
#define EXPONENT_MAX_SIZE 4

#define TSSK_KEY_LENGTH 64


#define ER_CLASS_APPL 0x40 
#define ER_CLASS_CTXT 0x80 
#define ER_CLASS_MASK 0xC0
#define ER_CLASS_PRIV 0xC0 
#define ER_CLASS_UNIV 0x00 
#define ER_CONSTRUCT 0x20 
#define ER_PC(_pc) (_pc ? ER_CONSTRUCT : ER_PRIMITIVE)
#define ER_PC_MASK 0x20
#define ER_PRIMITIVE 0x00 
#define ER_TAG_BIT_STRING 0x03
#define ER_TAG_BOOLEAN 0x01
#define ER_TAG_ENUMERATED 0x0A
#define ER_TAG_GENERALIZED_TIME 0x18
#define ER_TAG_GENERAL_STRING 0x1B
#define ER_TAG_INTEGER 0x02
#define ER_TAG_MASK 0x1F
#define ER_TAG_OBJECT_IDENFIER 0x06
#define ER_TAG_OCTET_STRING 0x04
#define ER_TAG_SEQUENCE 0x10
#define ER_TAG_SEQUENCE_OF 0x10

#define BIO_C_GET_EVENT 1103
#define BIO_C_GET_SOCKET 1102
#define BIO_C_READ_BLOCKED 1105
#define BIO_C_SET_NONBLOCK 1104
#define BIO_C_SET_SOCKET 1101
#define BIO_C_WAIT_READ 1107
#define BIO_C_WAIT_WRITE 1108
#define BIO_C_WRITE_BLOCKED 1106
#define BIO_TYPE_BUFFERED 67
#define BIO_TYPE_SIMPLE 66
#define BIO_TYPE_TSG 65
#define BIO_get_event(b, c) BIO_ctrl(b, BIO_C_GET_EVENT, 0, (char*)c)
#define BIO_get_socket(b, c) BIO_ctrl(b, BIO_C_GET_SOCKET, 0, (char*)c)
#define BIO_read_blocked(b) BIO_ctrl(b, BIO_C_READ_BLOCKED, 0, NULL)
#define BIO_set_nonblock(b, c) BIO_ctrl(b, BIO_C_SET_NONBLOCK, c, NULL)
#define BIO_set_socket(b, s, c) BIO_ctrl(b, BIO_C_SET_SOCKET, c, s);
#define BIO_wait_read(b, c) BIO_ctrl(b, BIO_C_WAIT_READ, c, NULL)
#define BIO_wait_write(b, c) BIO_ctrl(b, BIO_C_WAIT_WRITE, c, NULL)
#define BIO_write_blocked(b) BIO_ctrl(b, BIO_C_WRITE_BLOCKED, 0, NULL)

#define AUTHZ_ACCESS_DENIED 0x0000052E
#define AUTHZ_SUCCESS 0x00000000
#define CORRELATION_INFO_PRESENT 0x08
#define DYNVC_GFX_PROTOCOL_SUPPORTED 0x02
#define EXTENDED_CLIENT_DATA_SUPPORTED 0x01

#define PRECONNECTION_PDU_V1 1
#define PRECONNECTION_PDU_V1_SIZE 16
#define PRECONNECTION_PDU_V2 2
#define PRECONNECTION_PDU_V2_MIN_SIZE (PRECONNECTION_PDU_V1_SIZE + 2)
#define PROTOCOL_FAILED_NEGO 0x80000000 
#define PROTOCOL_HYBRID 0x00000002
#define PROTOCOL_HYBRID_EX 0x00000008
#define PROTOCOL_RDP 0x00000000
#define PROTOCOL_RDSTLS 0x00000004
#define PROTOCOL_SSL 0x00000001
#define RDP_NEGRSP_RESERVED 0x04
#define REDIRECTED_AUTHENTICATION_MODE_REQUIRED 0x02
#define RESTRICTED_ADMIN_MODE_REQUIRED 0x01
#define RESTRICTED_ADMIN_MODE_SUPPORTED 0x08

#define TPDU_CONNECTION_CONFIRM_HEADER_LENGTH 7
#define TPDU_CONNECTION_CONFIRM_LENGTH (TPKT_HEADER_LENGTH + TPDU_CONNECTION_CONFIRM_HEADER_LENGTH)
#define TPDU_CONNECTION_REQUEST_HEADER_LENGTH 7
#define TPDU_CONNECTION_REQUEST_LENGTH (TPKT_HEADER_LENGTH + TPDU_CONNECTION_REQUEST_HEADER_LENGTH)
#define TPDU_DATA_HEADER_LENGTH 3
#define TPDU_DATA_LENGTH (TPKT_HEADER_LENGTH + TPDU_DATA_HEADER_LENGTH)
#define TPDU_DISCONNECT_REQUEST_HEADER_LENGTH 7
#define TPDU_DISCONNECT_REQUEST_LENGTH (TPKT_HEADER_LENGTH + TPDU_DISCONNECT_REQUEST_HEADER_LENGTH)

#define TPKT_HEADER_LENGTH 4
#define tpkt_ensure_stream_consumed(s, length) \
	tpkt_ensure_stream_consumed_((s), (length), __FUNCTION__)



#define HEARTBEAT_TAG FREERDP_TAG("core.heartbeat")
#define AUTODETECT_TAG FREERDP_TAG("core.autodetect")

#define TYPE_ID_AUTODETECT_REQUEST 0x00
#define TYPE_ID_AUTODETECT_RESPONSE 0x01

#define DEBUG_LICENSE(...) WLog_DBG(LICENSE_TAG, __VA_ARGS__)

#define LICENSE_TAG FREERDP_TAG("core.license")
#define CLIENT_RANDOM_LENGTH 32
#define EXTENDED_ERROR_MSG_SUPPORTED 0x80

#define HWID_LENGTH 20
#define HWID_PLATFORM_ID_LENGTH 4
#define HWID_UNIQUE_DATA_LENGTH 16
#define KEY_EXCHANGE_ALG_RSA 0x00000001
#define LICENSE_PKT_CS_MASK \
	(LICENSE_INFO | NEW_LICENSE_REQUEST | PLATFORM_CHALLENGE_RESPONSE | ERROR_ALERT)
#define LICENSE_PKT_MASK (LICENSE_PKT_CS_MASK | LICENSE_PKT_SC_MASK)
#define LICENSE_PKT_SC_MASK \
	(LICENSE_REQUEST | PLATFORM_CHALLENGE | NEW_LICENSE | UPGRADE_LICENSE | ERROR_ALERT)
#define LICENSE_PREAMBLE_LENGTH 4
#define LICENSING_ENCRYPTION_KEY_LENGTH 16
#define LICENSING_PADDING_SIZE 8
#define LicenseProtocolVersionMask 0x0F
#define MAC_SALT_KEY_LENGTH 16
#define MASTER_SECRET_LENGTH 48
#define PREAMBLE_VERSION_2_0 0x02
#define PREAMBLE_VERSION_3_0 0x03
#define PREMASTER_SECRET_LENGTH 48
#define SERVER_RANDOM_LENGTH 32
#define SESSION_KEY_BLOB_LENGTH 48
#define BITMAP_COMPRESSION 0x0001

#define UPDATE_TYPE_BITMAP 0x0001
#define UPDATE_TYPE_ORDERS 0x0000
#define UPDATE_TYPE_PALETTE 0x0002
#define UPDATE_TYPE_SYNCHRONIZE 0x0003


#define FASTPATH_FRAGMENT_SAFE_SIZE 0x3F80
#define FASTPATH_MAX_PACKET_SIZE 0x3FFF

#define BULK_COMPRESSION_FLAGS_MASK 0xE0
#define BULK_COMPRESSION_TYPE_MASK 0x0F




#define L1_COMPRESSED 0x01
#define L1_INNER_COMPRESSION 0x10
#define L1_NO_COMPRESSION 0x02
#define L1_PACKET_AT_FRONT 0x04
#define PACKET_AT_FRONT 0x40
#define PACKET_COMPRESSED 0x20
#define PACKET_FLUSHED 0x80

#define COMPLEXREGION 0x03

#define GDIOBJECT_BITMAP 0x00
#define GDIOBJECT_BRUSH 0x03
#define GDIOBJECT_PALETTE 0x02
#define GDIOBJECT_PEN 0x01
#define GDIOBJECT_RECT 0x04
#define GDIOBJECT_REGION 0x05
#define GDI_BLACKNESS 0x00000042
#define GDI_BS_HATCHED 0x02
#define GDI_BS_NULL 0x01
#define GDI_BS_PATTERN 0x03
#define GDI_BS_SOLID 0x00
#define GDI_DPSDPaoxx 0x00B616E9
#define GDI_DPSDPoaxx 0x009217A9
#define GDI_DPSDanax 0x00DA1CE9
#define GDI_DPSDaox 0x005206C9
#define GDI_DPSDaoxn 0x00AD06E9
#define GDI_DPSDnaox 0x005E1B29
#define GDI_DPSDnoax 0x007A1E29
#define GDI_DPSDoax 0x004A0789
#define GDI_DPSDoaxn 0x00B507A9
#define GDI_DPSDonox 0x005B18A9
#define GDI_DPSDxax 0x00CA0749
#define GDI_DPSDxox 0x005C0649
#define GDI_DPSDxoxn 0x00A30669
#define GDI_DPSaa 0x008003E9
#define GDI_DPSaan 0x007F03C9
#define GDI_DPSana 0x002A0CC9
#define GDI_DPSanan 0x00D50CE9
#define GDI_DPSano 0x00BF08C9
#define GDI_DPSao 0x00EA02E9
#define GDI_DPSaon 0x001502C9
#define GDI_DPSax 0x006A01E9
#define GDI_DPSaxn 0x009501C9
#define GDI_DPSnaa 0x00200F09
#define GDI_DPSnao 0x00BA0B09
#define GDI_DPSnaon 0x00450B29
#define GDI_DPSnax 0x009A0709
#define GDI_DPSnoa 0x00A20E09
#define GDI_DPSnoan 0x005D0E29
#define GDI_DPSnox 0x00590609
#define GDI_DPSoa 0x00A803A9
#define GDI_DPSoan 0x00570389
#define GDI_DPSona 0x00020C89
#define GDI_DPSono 0x00AB0889
#define GDI_DPSonon 0x005408A9
#define GDI_DPSoo 0x00FE02A9
#define GDI_DPSoon 0x00010289
#define GDI_DPSox 0x005601A9
#define GDI_DPSoxn 0x00A90189
#define GDI_DPSxa 0x00280369
#define GDI_DPSxan 0x00D70349
#define GDI_DPSxna 0x00820C49
#define GDI_DPSxnan 0x007D0C69
#define GDI_DPSxno 0x00EB0849
#define GDI_DPSxnon 0x00140869
#define GDI_DPSxo 0x00BE0269
#define GDI_DPSxon 0x00410249
#define GDI_DPSxx 0x00960169
#define GDI_DPa 0x00A000C9
#define GDI_DPan 0x005F00E9
#define GDI_DPna 0x000A0329
#define GDI_DPno 0x00AF0229
#define GDI_DPo 0x00FA0089
#define GDI_DPon 0x000500A9
#define GDI_DSPDSanaxxn 0x00E95CE6
#define GDI_DSPDSaoxx 0x009E16E6
#define GDI_DSPDSaoxxn 0x006116C6
#define GDI_DSPDSoaxx 0x008617A6
#define GDI_DSPDSoaxxn 0x00791786
#define GDI_DSPDSonoxxn 0x006858A6
#define GDI_DSPDaox 0x004606C6
#define GDI_DSPDaoxn 0x00B906E6
#define GDI_DSPDoax 0x00620786
#define GDI_DSPDoaxn 0x009D07A6
#define GDI_DSPDxax 0x00E20746
#define GDI_DSPDxaxn 0x001D0766
#define GDI_DSPDxox 0x00740646
#define GDI_DSPDxoxn 0x008B0666
#define GDI_DSPnao 0x00AE0B06
#define GDI_DSPnaon 0x00510B26
#define GDI_DSPnax 0x00A60706
#define GDI_DSPnoa 0x008A0E06
#define GDI_DSPnoan 0x00750E26
#define GDI_DSPnox 0x00650606
#define GDI_DSTCOPY 0x00AA0029
#define GDI_DSTINVERT 0x00550009
#define GDI_DSan 0x007700E6
#define GDI_DSna 0x00220326
#define GDI_DSxn 0x00990066
#define GDI_FILL_ALTERNATE 0x01
#define GDI_FILL_WINDING 0x02
#define GDI_GLYPH_ORDER 0xFFFFFFFF
#define GDI_HS_BDIAGONAL 0x03
#define GDI_HS_CROSS 0x04
#define GDI_HS_DIAGCROSS 0x05
#define GDI_HS_FDIAGONAL 0x02
#define GDI_HS_HORIZONTAL 0x00
#define GDI_HS_VERTICAL 0x01
#define GDI_MERGECOPY 0x00C000CA
#define GDI_MERGEPAINT 0x00BB0226
#define GDI_NOTSRCCOPY 0x00330008
#define GDI_NOTSRCERASE 0x001100A6
#define GDI_OPAQUE 0x00000001
#define GDI_PATCOPY 0x00F00021
#define GDI_PATINVERT 0x005A0049
#define GDI_PATPAINT 0x00FB0A09
#define GDI_PDSPDaoxxn 0x004916C5
#define GDI_PDSPDoaxxn 0x006D1785
#define GDI_PDSPanaxn 0x00251CC5
#define GDI_PDSPaox 0x001A06C5
#define GDI_PDSPaoxn 0x00E506E5
#define GDI_PDSPnaoxn 0x00A11B05
#define GDI_PDSPnoaxn 0x00851E05
#define GDI_PDSPoax 0x00580785
#define GDI_PDSPoaxn 0x00A707A5
#define GDI_PDSPonoxn 0x00A41885
#define GDI_PDSPxax 0x00D80745
#define GDI_PDSPxox 0x004E0645
#define GDI_PDSPxoxn 0x00B10665
#define GDI_PDSana 0x00700CC5
#define GDI_PDSanan 0x008F0CE5
#define GDI_PDSano 0x00F708C5
#define GDI_PDSao 0x00F802E5
#define GDI_PDSaon 0x000702C5
#define GDI_PDSax 0x007801E5
#define GDI_PDSaxn 0x008701C5
#define GDI_PDSnao 0x00F20B05
#define GDI_PDSnaon 0x000D0B25
#define GDI_PDSnax 0x00D20705
#define GDI_PDSnoa 0x00B00E05
#define GDI_PDSnoan 0x004F0E25
#define GDI_PDSnox 0x004B0605
#define GDI_PDSoa 0x00E003A5
#define GDI_PDSoan 0x001F0385
#define GDI_PDSona 0x00100C85
#define GDI_PDSono 0x00F10885
#define GDI_PDSonon 0x000E08A5
#define GDI_PDSox 0x001E01A5
#define GDI_PDSoxn 0x00E10185
#define GDI_PDSxa 0x00600365
#define GDI_PDSxan 0x009F0345
#define GDI_PDSxna 0x00900C45
#define GDI_PDSxnan 0x006F0C65
#define GDI_PDSxno 0x00F90845
#define GDI_PDSxnon 0x00060865
#define GDI_PDSxo 0x00F60265
#define GDI_PDSxon 0x00090245
#define GDI_PDSxxn 0x00690145
#define GDI_PDna 0x00500325
#define GDI_PDno 0x00F50225
#define GDI_PDxn 0x00A50065
#define GDI_PSDPSanaxx 0x00165CCA
#define GDI_PSDPSaoxx 0x00D616EA
#define GDI_PSDPSaoxxn 0x002916CA
#define GDI_PSDPSoaxx 0x009417AA
#define GDI_PSDPSoaxxn 0x006B178A
#define GDI_PSDPSonoxx 0x0097588A
#define GDI_PSDPaox 0x001C06CA
#define GDI_PSDPaoxn 0x00E306EA
#define GDI_PSDPoax 0x0038078A
#define GDI_PSDPoaxn 0x00C707AA
#define GDI_PSDPxax 0x00B8074A
#define GDI_PSDPxaxn 0x0047076A
#define GDI_PSDPxox 0x002E064A
#define GDI_PSDPxoxn 0x00D1066A
#define GDI_PSDnaa 0x00400F0A
#define GDI_PSDnao 0x00F40B0A
#define GDI_PSDnaon 0x000B0B2A
#define GDI_PSDnax 0x00B4070A
#define GDI_PSDnoa 0x00D00E0A
#define GDI_PSDnoan 0x002F0E2A
#define GDI_PSDnoo 0x00FD0A0A
#define GDI_PSDnox 0x002D060A
#define GDI_PS_DASH 0x01
#define GDI_PS_NULL 0x05
#define GDI_PS_SOLID 0x00
#define GDI_PSan 0x003F00EA
#define GDI_PSna 0x0030032A
#define GDI_PSno 0x00F3022A
#define GDI_PSo 0x00FC008A
#define GDI_PSon 0x000300AA
#define GDI_PSx 0x003C004A
#define GDI_PSxn 0x00C3006A
#define GDI_Pn 0x000F0001
#define GDI_R2_BLACK 0x01       
#define GDI_R2_COPYPEN 0x0D     
#define GDI_R2_MASKNOTPEN 0x03  
#define GDI_R2_MASKPEN 0x09     
#define GDI_R2_MASKPENNOT 0x05  
#define GDI_R2_MERGENOTPEN 0x0C 
#define GDI_R2_MERGEPEN 0x0F    
#define GDI_R2_MERGEPENNOT 0x0E 
#define GDI_R2_NOP 0x0B         
#define GDI_R2_NOT 0x06         
#define GDI_R2_NOTCOPYPEN 0x04  
#define GDI_R2_NOTMASKPEN 0x08  
#define GDI_R2_NOTMERGEPEN 0x02 
#define GDI_R2_NOTXORPEN 0x0A   
#define GDI_R2_WHITE 0x10       
#define GDI_R2_XORPEN 0x07      
#define GDI_SDPSanax 0x00E61CE8
#define GDI_SDPSanaxn 0x00191CC8
#define GDI_SDPSaox 0x002606C8
#define GDI_SDPSaoxn 0x00D906E8
#define GDI_SDPSnaox 0x00761B28
#define GDI_SDPSnaoxn 0x00891B08
#define GDI_SDPSnoax 0x006E1E28
#define GDI_SDPSnoaxn 0x00911E08
#define GDI_SDPSoax 0x00640788
#define GDI_SDPSoaxn 0x009B07A8
#define GDI_SDPSonox 0x006718A8
#define GDI_SDPSonoxn 0x00981888
#define GDI_SDPSoox 0x00320688
#define GDI_SDPSxax 0x00E40748
#define GDI_SDPSxaxn 0x001B0768
#define GDI_SDPSxnox 0x00271868
#define GDI_SDPSxox 0x00720648
#define GDI_SDPSxoxn 0x008D0668
#define GDI_SDPana 0x004C0CC8
#define GDI_SDPanan 0x00B30CE8
#define GDI_SDPano 0x00DF08C8
#define GDI_SDPao 0x00EC02E8
#define GDI_SDPaon 0x001302C8
#define GDI_SDPax 0x006C01E8
#define GDI_SDPnaa 0x00080F08
#define GDI_SDPnao 0x00CE0B08
#define GDI_SDPnaon 0x00310B28
#define GDI_SDPnax 0x00C60708
#define GDI_SDPnoa 0x008C0E08
#define GDI_SDPnoan 0x00730E28
#define GDI_SDPnoo 0x00EF0A08
#define GDI_SDPnox 0x00630608
#define GDI_SDPoa 0x00C803A8
#define GDI_SDPoan 0x00370388
#define GDI_SDPona 0x00040C88
#define GDI_SDPono 0x00CD0888
#define GDI_SDPox 0x003601A8
#define GDI_SDPxa 0x00480368
#define GDI_SDPxan 0x00B70348
#define GDI_SDPxna 0x00840C48
#define GDI_SDPxnan 0x007B0C68
#define GDI_SDPxno 0x00ED0848
#define GDI_SDPxnon 0x00120868
#define GDI_SDPxo 0x00DE0268
#define GDI_SDPxon 0x00210248
#define GDI_SDno 0x00DD0228
#define GDI_SDxPDxa 0x00420D5D
#define GDI_SDxPDxan 0x00BD0D7D
#define GDI_SPDSanax 0x00BC1CE4
#define GDI_SPDSanaxn 0x00431CC4
#define GDI_SPDSaox 0x003406C4
#define GDI_SPDSaoxn 0x00CB06E4
#define GDI_SPDSnaox 0x003E1B24
#define GDI_SPDSnaoxn 0x00C11B04
#define GDI_SPDSnoax 0x007C1E24
#define GDI_SPDSnoaxn 0x00831E04
#define GDI_SPDSoax 0x002C0784
#define GDI_SPDSoaxn 0x00D307A4
#define GDI_SPDSonox 0x003D18A4
#define GDI_SPDSonoxn 0x00C21884
#define GDI_SPDSxax 0x00AC0744
#define GDI_SPDSxaxn 0x00530764
#define GDI_SPDSxnox 0x00351864
#define GDI_SPDSxox 0x003A0644
#define GDI_SPDSxoxn 0x00C50664
#define GDI_SPDaxn 0x009301C4
#define GDI_SPDnao 0x00DC0B04
#define GDI_SPDnaon 0x00230B24
#define GDI_SPDnax 0x009C0704
#define GDI_SPDnoa 0x00C40E04
#define GDI_SPDnoan 0x003B0E24
#define GDI_SPDnox 0x00390604
#define GDI_SPDoxn 0x00C90184
#define GDI_SPna 0x000C0324
#define GDI_SPno 0x00CF0224
#define GDI_SPxDSxa 0x00240D55
#define GDI_SPxDSxan 0x00DB0D75
#define GDI_SPxDSxo 0x007E0955
#define GDI_SPxDSxon 0x00810975
#define GDI_SPxPDxa 0x00180D59
#define GDI_SPxPDxan 0x00E70D79
#define GDI_SRCAND 0x008800C6
#define GDI_SRCCOPY 0x00CC0020
#define GDI_SRCERASE 0x00440328
#define GDI_SRCINVERT 0x00660046
#define GDI_SRCPAINT 0x00EE0086
#define GDI_SSDxPDxax 0x008E1D7C
#define GDI_SSDxPDxaxn 0x00711D5C
#define GDI_SSPxDSxax 0x00E81D74
#define GDI_SSPxDSxaxn 0x00171D54
#define GDI_SSPxDSxox 0x00B21974
#define GDI_SSPxDSxoxn 0x004D1954
#define GDI_SSPxPDxax 0x00D41D78
#define GDI_SSPxPDxaxn 0x002B1D58
#define GDI_TRANSPARENT 0x00000002
#define GDI_WHITENESS 0x00FF0062
#define NULLREGION 0x01
#define SIMPLEREGION 0x02


#define VIDEO_CONTROL_DVC_CHANNEL_NAME "Microsoft::Windows::RDS::Video::Control::v08.01"
#define VIDEO_DATA_DVC_CHANNEL_NAME "Microsoft::Windows::RDS::Video::Data::v08.01"


#define GEOMETRY_DVC_CHANNEL_NAME "Microsoft::Windows::RDS::Geometry::v08.01"


#define PROFILER_CREATE(prof, name) prof = profiler_create(name);
#define PROFILER_DEFINE(prof) PROFILER* prof;
#define PROFILER_ENTER(prof) profiler_enter(prof);
#define PROFILER_EXIT(prof) profiler_exit(prof);
#define PROFILER_FREE(prof) profiler_free(prof);
#define PROFILER_PRINT(prof) profiler_print(prof);
#define PROFILER_PRINT_FOOTER profiler_print_footer();
#define PROFILER_PRINT_HEADER profiler_print_header();
#define PROFILER_RENAME(prof, name)   \
	do                                \
	{                                 \
		profiler_free(prof);          \
		prof = profiler_create(name); \
	} while (0)









#define DEBUG_WND(...) WLog_DBG(WND_TAG, __VA_ARGS__)

#define WND_TAG FREERDP_TAG("core.wnd")
