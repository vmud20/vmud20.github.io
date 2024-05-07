













#define CLIENT_TAG(tag) FREERDP_TAG("client.") tag

#define FREERDP_TAG(tag) "com.freerdp." tag
#define SERVER_TAG(tag) FREERDP_TAG("server.") tag


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
