














#define MAX(x,y)	(((x) > (y)) ? (x) : (y))
#define MIN(x,y)	(((x) < (y)) ? (x) : (y))

#define GetMessageClass(_id)		((_id >> 16) & 0xFF)
#define GetMessageId(_class, _type)	((_class << 16) | _type)
#define GetMessageType(_id) 		(_id & 0xFF)
#define MakeMessageId(_class, _type) \
	(((_class ##_Class) << 16) | (_class ## _ ## _type))


#define FreeRDP_AcceptedCert                                       (  27)
#define FreeRDP_AcceptedCertLength                                 (  28)
#define FreeRDP_AllowCacheWaitingList                              (2499)
#define FreeRDP_AllowDesktopComposition                            ( 968)
#define FreeRDP_AllowFontSmoothing                                 ( 961)
#define FreeRDP_AllowUnanouncedOrdersFromServer                    (2435)
#define FreeRDP_AllowedTlsCiphers                                  (1101)
#define FreeRDP_AltSecFrameMarkerSupport                           (2434)
#define FreeRDP_AlternateShell                                     ( 640)
#define FreeRDP_AssistanceFile                                     (1729)
#define FreeRDP_AsyncChannels                                      (1546)
#define FreeRDP_AsyncInput                                         (1544)
#define FreeRDP_AsyncUpdate                                        (1545)
#define FreeRDP_AudioCapture                                       ( 715)
#define FreeRDP_AudioPlayback                                      ( 714)
#define FreeRDP_Authentication                                     (1092)
#define FreeRDP_AuthenticationLevel                                (1100)
#define FreeRDP_AuthenticationOnly                                 (1603)
#define FreeRDP_AuthenticationServiceClass                         (1098)
#define FreeRDP_AutoAcceptCertificate                              (1419)
#define FreeRDP_AutoLogonEnabled                                   ( 704)
#define FreeRDP_AutoReconnectMaxRetries                            ( 833)
#define FreeRDP_AutoReconnectionEnabled                            ( 832)
#define FreeRDP_BitmapCacheEnabled                                 (2497)
#define FreeRDP_BitmapCachePersistEnabled                          (2500)
#define FreeRDP_BitmapCacheV2CellInfo                              (2502)
#define FreeRDP_BitmapCacheV2NumCells                              (2501)
#define FreeRDP_BitmapCacheV3CodecId                               (3904)
#define FreeRDP_BitmapCacheV3Enabled                               (2433)
#define FreeRDP_BitmapCacheVersion                                 (2498)
#define FreeRDP_BitmapCompressionDisabled                          (2312)
#define FreeRDP_BrushSupportLevel                                  (2688)
#define FreeRDP_CertificateContent                                 (1416)
#define FreeRDP_CertificateFile                                    (1410)
#define FreeRDP_CertificateName                                    (1409)
#define FreeRDP_ChannelCount                                       ( 256)
#define FreeRDP_ChannelDefArray                                    ( 258)
#define FreeRDP_ChannelDefArraySize                                ( 257)
#define FreeRDP_ClientAddress                                      ( 769)
#define FreeRDP_ClientAutoReconnectCookie                          ( 834)
#define FreeRDP_ClientBuild                                        ( 133)
#define FreeRDP_ClientDir                                          ( 770)
#define FreeRDP_ClientHostname                                     ( 134)
#define FreeRDP_ClientProductId                                    ( 135)
#define FreeRDP_ClientRandom                                       ( 200)
#define FreeRDP_ClientRandomLength                                 ( 201)
#define FreeRDP_ClientTimeZone                                     ( 896)
#define FreeRDP_ClusterInfoFlags                                   ( 320)
#define FreeRDP_ColorDepth                                         ( 131)
#define FreeRDP_ColorPointerFlag                                   (2560)
#define FreeRDP_CompDeskSupportLevel                               (3456)
#define FreeRDP_CompressionEnabled                                 ( 705)
#define FreeRDP_CompressionLevel                                   ( 721)
#define FreeRDP_ComputerName                                       (1664)
#define FreeRDP_ConfigPath                                         (1793)
#define FreeRDP_ConnectionFile                                     (1728)
#define FreeRDP_ConnectionType                                     ( 132)
#define FreeRDP_ConsoleSession                                     ( 322)
#define FreeRDP_CookieMaxLength                                    (1153)
#define FreeRDP_CredentialsFromStdin                               (1604)
#define FreeRDP_CurrentPath                                        (1794)
#define FreeRDP_Decorations                                        (1540)
#define FreeRDP_DesktopHeight                                      ( 130)
#define FreeRDP_DesktopOrientation                                 ( 147)
#define FreeRDP_DesktopPhysicalHeight                              ( 146)
#define FreeRDP_DesktopPhysicalWidth                               ( 145)
#define FreeRDP_DesktopPosX                                        ( 390)
#define FreeRDP_DesktopPosY                                        ( 391)
#define FreeRDP_DesktopResize                                      (2368)
#define FreeRDP_DesktopScaleFactor                                 ( 148)
#define FreeRDP_DesktopWidth                                       ( 129)
#define FreeRDP_DeviceArray                                        (4163)
#define FreeRDP_DeviceArraySize                                    (4162)
#define FreeRDP_DeviceCount                                        (4161)
#define FreeRDP_DeviceRedirection                                  (4160)
#define FreeRDP_DeviceScaleFactor                                  ( 149)
#define FreeRDP_DisableCredentialsDelegation                       (1099)
#define FreeRDP_DisableCtrlAltDel                                  ( 706)
#define FreeRDP_DisableCursorBlinking                              ( 967)
#define FreeRDP_DisableCursorShadow                                ( 966)
#define FreeRDP_DisableFullWindowDrag                              ( 963)
#define FreeRDP_DisableMenuAnims                                   ( 964)
#define FreeRDP_DisableRemoteAppCapsCheck                          (2121)
#define FreeRDP_DisableThemes                                      ( 965)
#define FreeRDP_DisableWallpaper                                   ( 962)
#define FreeRDP_Domain                                             (  23)
#define FreeRDP_DrawAllowColorSubsampling                          (2370)
#define FreeRDP_DrawAllowDynamicColorFidelity                      (2369)
#define FreeRDP_DrawAllowSkipAlpha                                 (2371)
#define FreeRDP_DrawGdiPlusCacheEnabled                            (4033)
#define FreeRDP_DrawGdiPlusEnabled                                 (4032)
#define FreeRDP_DrawNineGridCacheEntries                           (3970)
#define FreeRDP_DrawNineGridCacheSize                              (3969)
#define FreeRDP_DrawNineGridEnabled                                (3968)
#define FreeRDP_DrivesToRedirect                                   (4290)
#define FreeRDP_DumpRemoteFx                                       (1856)
#define FreeRDP_DumpRemoteFxFile                                   (1858)
#define FreeRDP_DynamicChannelArray                                (5058)
#define FreeRDP_DynamicChannelArraySize                            (5057)
#define FreeRDP_DynamicChannelCount                                (5056)
#define FreeRDP_DynamicDSTTimeZoneKeyName                          ( 897)
#define FreeRDP_DynamicDaylightTimeDisabled                        ( 898)
#define FreeRDP_DynamicResolutionUpdate                            (1558)
#define FreeRDP_EarlyCapabilityFlags                               ( 136)
#define FreeRDP_EmbeddedWindow                                     (1550)
#define FreeRDP_EnableWindowsKey                                   ( 707)
#define FreeRDP_EncomspVirtualChannel                              (1029)
#define FreeRDP_EncryptionLevel                                    ( 195)
#define FreeRDP_EncryptionMethods                                  ( 193)
#define FreeRDP_ExtEncryptionMethods                               ( 194)
#define FreeRDP_ExtSecurity                                        (1091)
#define FreeRDP_ExternalCertificateManagement                      (1415)
#define FreeRDP_FIPSMode                                           (1104)
#define FreeRDP_FastPathInput                                      (2630)
#define FreeRDP_FastPathOutput                                     (2308)
#define FreeRDP_ForceEncryptedCsPdu                                ( 719)
#define FreeRDP_ForceMultimon                                      ( 389)
#define FreeRDP_FragCache                                          (2754)
#define FreeRDP_FrameAcknowledge                                   (3714)
#define FreeRDP_FrameMarkerCommandEnabled                          (3521)
#define FreeRDP_Fullscreen                                         (1537)
#define FreeRDP_GatewayAcceptedCert                                (1998)
#define FreeRDP_GatewayAcceptedCertLength                          (1999)
#define FreeRDP_GatewayAccessToken                                 (1997)
#define FreeRDP_GatewayBypassLocal                                 (1993)
#define FreeRDP_GatewayCredentialsSource                           (1990)
#define FreeRDP_GatewayDomain                                      (1989)
#define FreeRDP_GatewayEnabled                                     (1992)
#define FreeRDP_GatewayHostname                                    (1986)
#define FreeRDP_GatewayHttpTransport                               (1995)
#define FreeRDP_GatewayPassword                                    (1988)
#define FreeRDP_GatewayPort                                        (1985)
#define FreeRDP_GatewayRpcTransport                                (1994)
#define FreeRDP_GatewayUdpTransport                                (1996)
#define FreeRDP_GatewayUsageMethod                                 (1984)
#define FreeRDP_GatewayUseSameCredentials                          (1991)
#define FreeRDP_GatewayUsername                                    (1987)
#define FreeRDP_GfxAVC444                                          (3845)
#define FreeRDP_GfxAVC444v2                                        (3847)
#define FreeRDP_GfxH264                                            (3844)
#define FreeRDP_GfxProgressive                                     (3842)
#define FreeRDP_GfxProgressiveV2                                   (3843)
#define FreeRDP_GfxSendQoeAck                                      (3846)
#define FreeRDP_GfxSmallCache                                      (3841)
#define FreeRDP_GfxThinClient                                      (3840)
#define FreeRDP_GlyphCache                                         (2753)
#define FreeRDP_GlyphSupportLevel                                  (2752)
#define FreeRDP_GrabKeyboard                                       (1539)
#define FreeRDP_HasExtendedMouseEvent                              (2635)
#define FreeRDP_HasHorizontalWheel                                 (2634)
#define FreeRDP_HasMonitorAttributes                               ( 397)
#define FreeRDP_HiDefRemoteApp                                     ( 720)
#define FreeRDP_HomePath                                           (1792)
#define FreeRDP_IPv6Enabled                                        ( 768)
#define FreeRDP_IgnoreCertificate                                  (1408)
#define FreeRDP_ImeFileName                                        (2628)
#define FreeRDP_JpegCodec                                          (3776)
#define FreeRDP_JpegCodecId                                        (3777)
#define FreeRDP_JpegQuality                                        (3778)
#define FreeRDP_KerberosKdc                                        (1344)
#define FreeRDP_KerberosRealm                                      (1345)
#define FreeRDP_KeyboardFunctionKey                                (2627)
#define FreeRDP_KeyboardHook                                       (2633)
#define FreeRDP_KeyboardLayout                                     (2624)
#define FreeRDP_KeyboardSubType                                    (2626)
#define FreeRDP_KeyboardType                                       (2625)
#define FreeRDP_LargePointerFlag                                   (3392)
#define FreeRDP_ListMonitors                                       ( 392)
#define FreeRDP_LoadBalanceInfo                                    (1218)
#define FreeRDP_LoadBalanceInfoLength                              (1219)
#define FreeRDP_LocalConnection                                    (1602)
#define FreeRDP_LogonErrors                                        ( 710)
#define FreeRDP_LogonNotify                                        ( 709)
#define FreeRDP_LongCredentialsSupported                           (2310)
#define FreeRDP_LyncRdpMode                                        (1031)
#define FreeRDP_MaxTimeInCheckLoop                                 (  26)
#define FreeRDP_MaximizeShell                                      ( 708)
#define FreeRDP_MonitorCount                                       ( 384)
#define FreeRDP_MonitorDefArray                                    ( 386)
#define FreeRDP_MonitorDefArraySize                                ( 385)
#define FreeRDP_MonitorIds                                         ( 393)
#define FreeRDP_MonitorLocalShiftX                                 ( 395)
#define FreeRDP_MonitorLocalShiftY                                 ( 396)
#define FreeRDP_MouseAttached                                      ( 711)
#define FreeRDP_MouseHasWheel                                      ( 712)
#define FreeRDP_MouseMotion                                        (1541)
#define FreeRDP_MstscCookieMode                                    (1152)
#define FreeRDP_MultiTouchGestures                                 (2632)
#define FreeRDP_MultiTouchInput                                    (2631)
#define FreeRDP_MultifragMaxRequestSize                            (3328)
#define FreeRDP_MultitransportFlags                                ( 512)
#define FreeRDP_NSCodec                                            (3712)
#define FreeRDP_NSCodecAllowDynamicColorFidelity                   (3717)
#define FreeRDP_NSCodecAllowSubsampling                            (3716)
#define FreeRDP_NSCodecColorLossLevel                              (3715)
#define FreeRDP_NSCodecId                                          (3713)
#define FreeRDP_NegotiateSecurityLayer                             (1096)
#define FreeRDP_NegotiationFlags                                   (1095)
#define FreeRDP_NetworkAutoDetect                                  ( 137)
#define FreeRDP_NlaSecurity                                        (1089)
#define FreeRDP_NoBitmapCompressionHeader                          (2311)
#define FreeRDP_NtlmSamFile                                        (1103)
#define FreeRDP_NumMonitorIds                                      ( 394)
#define FreeRDP_OffscreenCacheEntries                              (2818)
#define FreeRDP_OffscreenCacheSize                                 (2817)
#define FreeRDP_OffscreenSupportLevel                              (2816)
#define FreeRDP_OrderSupport                                       (2432)
#define FreeRDP_OsMajorType                                        (2304)
#define FreeRDP_OsMinorType                                        (2305)
#define FreeRDP_ParentWindowId                                     (1543)
#define FreeRDP_Password                                           (  22)
#define FreeRDP_Password51                                         (1280)
#define FreeRDP_Password51Length                                   (1281)
#define FreeRDP_PasswordHash                                       (  24)
#define FreeRDP_PasswordIsSmartcardPin                             ( 717)
#define FreeRDP_PduSource                                          (  18)
#define FreeRDP_PercentScreen                                      (1538)
#define FreeRDP_PercentScreenUseHeight                             (1557)
#define FreeRDP_PercentScreenUseWidth                              (1556)
#define FreeRDP_PerformanceFlags                                   ( 960)
#define FreeRDP_PlayRemoteFx                                       (1857)
#define FreeRDP_PlayRemoteFxFile                                   (1859)
#define FreeRDP_PointerCacheSize                                   (2561)
#define FreeRDP_PreconnectionBlob                                  (1155)
#define FreeRDP_PreconnectionId                                    (1154)
#define FreeRDP_PreferIPv6OverIPv4                                 (4674)
#define FreeRDP_PrintReconnectCookie                               ( 836)
#define FreeRDP_PrivateKeyContent                                  (1417)
#define FreeRDP_PrivateKeyFile                                     (1411)
#define FreeRDP_ProxyHostname                                      (2016)
#define FreeRDP_ProxyPassword                                      (2019)
#define FreeRDP_ProxyPort                                          (2017)
#define FreeRDP_ProxyType                                          (2015)
#define FreeRDP_ProxyUsername                                      (2018)
#define FreeRDP_RdpKeyContent                                      (1418)
#define FreeRDP_RdpKeyFile                                         (1412)
#define FreeRDP_RdpSecurity                                        (1090)
#define FreeRDP_RdpServerCertificate                               (1414)
#define FreeRDP_RdpServerRsaKey                                    (1413)
#define FreeRDP_RdpVersion                                         ( 128)
#define FreeRDP_ReceivedCapabilities                               (2240)
#define FreeRDP_ReceivedCapabilitiesSize                           (2241)
#define FreeRDP_RedirectClipboard                                  (4800)
#define FreeRDP_RedirectDrives                                     (4288)
#define FreeRDP_RedirectHomeDrive                                  (4289)
#define FreeRDP_RedirectParallelPorts                              (4673)
#define FreeRDP_RedirectPrinters                                   (4544)
#define FreeRDP_RedirectSerialPorts                                (4672)
#define FreeRDP_RedirectSmartCards                                 (4416)
#define FreeRDP_RedirectedSessionId                                ( 321)
#define FreeRDP_RedirectionAcceptedCert                            (1231)
#define FreeRDP_RedirectionAcceptedCertLength                      (1232)
#define FreeRDP_RedirectionDomain                                  (1221)
#define FreeRDP_RedirectionFlags                                   (1216)
#define FreeRDP_RedirectionPassword                                (1222)
#define FreeRDP_RedirectionPasswordLength                          (1223)
#define FreeRDP_RedirectionPreferType                              (1233)
#define FreeRDP_RedirectionTargetFQDN                              (1224)
#define FreeRDP_RedirectionTargetNetBiosName                       (1225)
#define FreeRDP_RedirectionTsvUrl                                  (1226)
#define FreeRDP_RedirectionTsvUrlLength                            (1227)
#define FreeRDP_RedirectionUsername                                (1220)
#define FreeRDP_RefreshRect                                        (2306)
#define FreeRDP_RemdeskVirtualChannel                              (1030)
#define FreeRDP_RemoteAppLanguageBarSupported                      (2124)
#define FreeRDP_RemoteAppNumIconCacheEntries                       (2123)
#define FreeRDP_RemoteAppNumIconCaches                             (2122)
#define FreeRDP_RemoteApplicationCmdLine                           (2118)
#define FreeRDP_RemoteApplicationExpandCmdLine                     (2119)
#define FreeRDP_RemoteApplicationExpandWorkingDir                  (2120)
#define FreeRDP_RemoteApplicationFile                              (2116)
#define FreeRDP_RemoteApplicationGuid                              (2117)
#define FreeRDP_RemoteApplicationIcon                              (2114)
#define FreeRDP_RemoteApplicationMode                              (2112)
#define FreeRDP_RemoteApplicationName                              (2113)
#define FreeRDP_RemoteApplicationProgram                           (2115)
#define FreeRDP_RemoteAssistanceMode                               (1024)
#define FreeRDP_RemoteAssistancePassStub                           (1026)
#define FreeRDP_RemoteAssistancePassword                           (1027)
#define FreeRDP_RemoteAssistanceRCTicket                           (1028)
#define FreeRDP_RemoteAssistanceSessionId                          (1025)
#define FreeRDP_RemoteConsoleAudio                                 ( 713)
#define FreeRDP_RemoteFxCaptureFlags                               (3653)
#define FreeRDP_RemoteFxCodec                                      (3649)
#define FreeRDP_RemoteFxCodecId                                    (3650)
#define FreeRDP_RemoteFxCodecMode                                  (3651)
#define FreeRDP_RemoteFxImageCodec                                 (3652)
#define FreeRDP_RemoteFxOnly                                       (3648)
#define FreeRDP_RemoteWndSupportLevel                              (2125)
#define FreeRDP_RequestedProtocols                                 (1093)
#define FreeRDP_RestrictedAdminModeRequired                        (1097)
#define FreeRDP_SaltedChecksum                                     (2309)
#define FreeRDP_SelectedProtocol                                   (1094)
#define FreeRDP_SendPreconnectionPdu                               (1156)
#define FreeRDP_ServerAutoReconnectCookie                          ( 835)
#define FreeRDP_ServerCertificate                                  ( 198)
#define FreeRDP_ServerCertificateLength                            ( 199)
#define FreeRDP_ServerHostname                                     (  20)
#define FreeRDP_ServerMode                                         (  16)
#define FreeRDP_ServerPort                                         (  19)
#define FreeRDP_ServerRandom                                       ( 196)
#define FreeRDP_ServerRandomLength                                 ( 197)
#define FreeRDP_ShareId                                            (  17)
#define FreeRDP_ShellWorkingDirectory                              ( 641)
#define FreeRDP_SmartSizing                                        (1551)
#define FreeRDP_SmartSizingHeight                                  (1555)
#define FreeRDP_SmartSizingWidth                                   (1554)
#define FreeRDP_SmartcardLogon                                     (1282)
#define FreeRDP_SoftwareGdi                                        (1601)
#define FreeRDP_SoundBeepsEnabled                                  (2944)
#define FreeRDP_SpanMonitors                                       ( 387)
#define FreeRDP_StaticChannelArray                                 (4930)
#define FreeRDP_StaticChannelArraySize                             (4929)
#define FreeRDP_StaticChannelCount                                 (4928)
#define FreeRDP_SupportAsymetricKeys                               ( 138)
#define FreeRDP_SupportDisplayControl                              (5185)
#define FreeRDP_SupportDynamicChannels                             (5059)
#define FreeRDP_SupportDynamicTimeZone                             ( 143)
#define FreeRDP_SupportEchoChannel                                 (5184)
#define FreeRDP_SupportErrorInfoPdu                                ( 139)
#define FreeRDP_SupportGeometryTracking                            (5186)
#define FreeRDP_SupportGraphicsPipeline                            ( 142)
#define FreeRDP_SupportHeartbeatPdu                                ( 144)
#define FreeRDP_SupportMonitorLayoutPdu                            ( 141)
#define FreeRDP_SupportMultitransport                              ( 513)
#define FreeRDP_SupportSSHAgentChannel                             (5187)
#define FreeRDP_SupportStatusInfoPdu                               ( 140)
#define FreeRDP_SupportVideoOptimized                              (5188)
#define FreeRDP_SuppressOutput                                     (2307)
#define FreeRDP_SurfaceCommandsEnabled                             (3520)
#define FreeRDP_SurfaceFrameMarkerEnabled                          (3522)
#define FreeRDP_TargetNetAddress                                   (1217)
#define FreeRDP_TargetNetAddressCount                              (1228)
#define FreeRDP_TargetNetAddresses                                 (1229)
#define FreeRDP_TargetNetPorts                                     (1230)
#define FreeRDP_TlsSecLevel                                        (1105)
#define FreeRDP_TlsSecurity                                        (1088)
#define FreeRDP_ToggleFullscreen                                   (1548)
#define FreeRDP_UnicodeInput                                       (2629)
#define FreeRDP_UnmapButtons                                       (1605)
#define FreeRDP_UseMultimon                                        ( 388)
#define FreeRDP_UseRdpSecurityLayer                                ( 192)
#define FreeRDP_Username                                           (  21)
#define FreeRDP_UsingSavedCredentials                              ( 718)
#define FreeRDP_VideoDisable                                       ( 716)
#define FreeRDP_VirtualChannelChunkSize                            (2881)
#define FreeRDP_VirtualChannelCompressionFlags                     (2880)
#define FreeRDP_VmConnectMode                                      (1102)
#define FreeRDP_WaitForOutputBufferFlush                           (  25)
#define FreeRDP_WindowTitle                                        (1542)
#define FreeRDP_WmClass                                            (1549)
#define FreeRDP_Workarea                                           (1536)
#define FreeRDP_XPan                                               (1552)
#define FreeRDP_YPan                                               (1553)
#define FreeRDP_instance                                           (   0)
#define PERF_DISABLE_CURSORSETTINGS     	0x00000040
#define PERF_DISABLE_CURSOR_SHADOW      	0x00000020
#define PERF_DISABLE_FULLWINDOWDRAG    		0x00000002
#define PERF_DISABLE_MENUANIMATIONS     	0x00000004
#define PERF_DISABLE_THEMING            	0x00000008
#define PERF_DISABLE_WALLPAPER          	0x00000001
#define PERF_ENABLE_DESKTOP_COMPOSITION 	0x00000100
#define PERF_ENABLE_FONT_SMOOTHING      	0x00000080
#define PERF_FLAG_NONE                  	0x00000000
#define FREERDP_API __attribute__((dllexport))

#define FREERDP_CC __cdecl
#define FREERDP_LOCAL FREERDP_API

#define IFCALL(_cb, ...) do { if (_cb != NULL) { _cb( __VA_ARGS__ ); } } while (0)
#define IFCALLRESULT(_default_return, _cb, ...) ((_cb != NULL) ? _cb( __VA_ARGS__ ) : (_default_return))
#define IFCALLRET(_cb, _ret, ...) do { if (_cb != NULL) { _ret = _cb( __VA_ARGS__ ); } } while (0)
#define __func__ __FUNCTION__
#define CLIENT_TAG(tag) FREERDP_TAG("client.") tag

#define FREERDP_TAG(tag) "com.freerdp." tag
#define SERVER_TAG(tag) FREERDP_TAG("server.") tag
