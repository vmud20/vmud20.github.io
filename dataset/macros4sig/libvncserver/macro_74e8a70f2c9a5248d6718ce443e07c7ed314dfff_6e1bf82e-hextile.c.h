#include<arpa/inet.h>
#include<stdio.h>
#include<zlib.h>
#include<sys/types.h>
#include<sys/timeb.h>


#include<stdint.h>


#include<string.h>
#include<stdlib.h>
#include<sys/select.h>
#include<netinet/in.h>
#include<sys/time.h>
#define FB_UPDATE_PENDING(cl)                                              \
     (((cl)->enableCursorShapeUpdates && (cl)->cursorWasChanged) ||        \
     (((cl)->enableCursorShapeUpdates == FALSE &&                          \
       ((cl)->cursorX != (cl)->screen->cursorX ||                          \
	(cl)->cursorY != (cl)->screen->cursorY))) ||                       \
     ((cl)->useNewFBSize && (cl)->newFBSizePending) ||                     \
     ((cl)->enableCursorPosUpdates && (cl)->cursorWasMoved) ||             \
     !sraRgnEmpty((cl)->copyRegion) || !sraRgnEmpty((cl)->modifiedRegion))


#define Swap16(s) ((((s) & 0xff) << 8) | (((s) >> 8) & 0xff))
#define Swap16IfBE(s) (rfbEndianTest ? (s) : Swap16(s))
#define Swap16IfLE(s) (rfbEndianTest ? Swap16(s) : (s))
#define Swap24(l) ((((l) & 0xff) << 16) | (((l) >> 16) & 0xff) | \
                   (((l) & 0x00ff00)))
#define Swap24IfBE(l) (rfbEndianTest ? (l) : Swap24(l))
#define Swap24IfLE(l) (rfbEndianTest ? Swap24(l) : (l))
#define Swap32(l) ((((l) >> 24) & 0x000000ff)| \
                   (((l) & 0x00ff0000) >> 8)  | \
                   (((l) & 0x0000ff00) << 8)  | \
                   (((l) & 0x000000ff) << 24))
#define Swap32IfBE(l) (rfbEndianTest ? (l) : Swap32(l))
#define Swap32IfLE(l) (rfbEndianTest ? Swap32(l) : (l))
#define TIGHT_DEFAULT_COMPRESSION  6
#define TURBO_DEFAULT_SUBSAMP 0
#define ULTRA_MAX_RECT_SIZE (128*256)
#define ULTRA_MAX_SIZE(min) ((( min * 2 ) > ULTRA_MAX_RECT_SIZE ) ? \
                            ( min * 2 ) : ULTRA_MAX_RECT_SIZE )
#define UPDATE_BUF_SIZE 30000
#define VNC_ENCODE_ZLIB_MIN_COMP_SIZE (17)
#define ZLIB_MAX_RECT_SIZE (128*256)
#define ZLIB_MAX_SIZE(min) ((( min * 2 ) > ZLIB_MAX_RECT_SIZE ) ? \
			    ( min * 2 ) : ZLIB_MAX_RECT_SIZE )
#define rfbInitServer rfbInitServerWithPthreadsAndZRLE
#define CHALLENGESIZE 16
#define FALSE 0
#define                INADDR_NONE     ((in_addr_t) 0xffffffff)
#  define LIBVNCSERVER_WORDS_BIGENDIAN 1
#define MAXPWLEN 8
#define MAX_ENCODINGS 64

#define RFB_INVALID_SOCKET (-1)
#define SOCKET int 
#define TRUE -1
#define Z_NULL NULL
#define rfbARD 30
#define rfbBell 2
#define rfbButton1Mask 1
#define rfbButton2Mask 2
#define rfbButton3Mask 4
#define rfbButton4Mask 8
#define rfbButton5Mask 16
#define rfbClientCutText 6
#define rfbCloseSocket close
#define rfbConnFailed 0
#define rfbEncodingCache                 0xFFFF0000
#define rfbEncodingCacheEnable           0xFFFF0001
#define rfbEncodingCacheZip              0xFFFF0007
#define rfbEncodingCoRRE 4
#define rfbEncodingCompressLevel0  0xFFFFFF00
#define rfbEncodingCompressLevel1  0xFFFFFF01
#define rfbEncodingCompressLevel2  0xFFFFFF02
#define rfbEncodingCompressLevel3  0xFFFFFF03
#define rfbEncodingCompressLevel4  0xFFFFFF04
#define rfbEncodingCompressLevel5  0xFFFFFF05
#define rfbEncodingCompressLevel6  0xFFFFFF06
#define rfbEncodingCompressLevel7  0xFFFFFF07
#define rfbEncodingCompressLevel8  0xFFFFFF08
#define rfbEncodingCompressLevel9  0xFFFFFF09
#define rfbEncodingCopyRect 1
#define rfbEncodingExtDesktopSize     0xFFFFFECC
#define rfbEncodingFineQualityLevel0   0xFFFFFE00
#define rfbEncodingFineQualityLevel100 0xFFFFFE64
#define rfbEncodingH264               0x48323634
#define rfbEncodingHextile 5
#define rfbEncodingKeyboardLedState   0xFFFE0000
#define rfbEncodingLastRect           0xFFFFFF20
#define rfbEncodingNewFBSize          0xFFFFFF21
#define rfbEncodingPointerPos      0xFFFFFF18
#define rfbEncodingQualityLevel0   0xFFFFFFE0
#define rfbEncodingQualityLevel1   0xFFFFFFE1
#define rfbEncodingQualityLevel2   0xFFFFFFE2
#define rfbEncodingQualityLevel3   0xFFFFFFE3
#define rfbEncodingQualityLevel4   0xFFFFFFE4
#define rfbEncodingQualityLevel5   0xFFFFFFE5
#define rfbEncodingQualityLevel6   0xFFFFFFE6
#define rfbEncodingQualityLevel7   0xFFFFFFE7
#define rfbEncodingQualityLevel8   0xFFFFFFE8
#define rfbEncodingQualityLevel9   0xFFFFFFE9
#define rfbEncodingRRE 2
#define rfbEncodingRaw 0
#define rfbEncodingRichCursor      0xFFFFFF11
#define rfbEncodingServerIdentity     0xFFFE0003
#define rfbEncodingSolMonoZip            0xFFFF0008
#define rfbEncodingSolidColor            0xFFFF0005
#define rfbEncodingSubsamp16X          0xFFFFFD05
#define rfbEncodingSubsamp1X           0xFFFFFD00
#define rfbEncodingSubsamp2X           0xFFFFFD02
#define rfbEncodingSubsamp4X           0xFFFFFD01
#define rfbEncodingSubsamp8X           0xFFFFFD04
#define rfbEncodingSubsampGray         0xFFFFFD03
#define rfbEncodingSupportedEncodings 0xFFFE0002
#define rfbEncodingSupportedMessages  0xFFFE0001
#define rfbEncodingTRLE 15
#define rfbEncodingTight 7
#define rfbEncodingTightPng 0xFFFFFEFC 
#define rfbEncodingUltra 9
#define rfbEncodingUltraZip              0xFFFF0009
#define rfbEncodingXCursor         0xFFFFFF10
#define rfbEncodingXOREnable             0xFFFF0006
#define rfbEncodingXORMonoColor_Zlib     0xFFFF0003
#define rfbEncodingXORMultiColor_Zlib    0xFFFF0004
#define rfbEncodingXOR_Zlib              0xFFFF0002
#define rfbEncodingXvp 			 0xFFFFFECB
#define rfbEncodingZRLE 16
#define rfbEncodingZYWRLE 17
#define rfbEncodingZlib 6
#define rfbEncodingZlibHex 8
#define rfbExtDesktopSize_ClientRequestedChange 1
#define rfbExtDesktopSize_GenericChange 0
#define rfbExtDesktopSize_InvalidScreenLayout 3
#define rfbExtDesktopSize_OtherClientRequestedChange 2
#define rfbExtDesktopSize_OutOfResources 2
#define rfbExtDesktopSize_ResizeProhibited 1
#define rfbExtDesktopSize_Success 0
#define rfbFileTransfer 7
#define rfbFileTransferVersion  2 
#define rfbFixColourMapEntries 1	
#define rfbFramebufferUpdate 0
#define rfbFramebufferUpdateRequest 3
#define rfbHextileExtractH(byte) (((byte) & 0xf) + 1)
#define rfbHextileExtractW(byte) (((byte) >> 4) + 1)
#define rfbHextileExtractX(byte) ((byte) >> 4)
#define rfbHextileExtractY(byte) ((byte) & 0xf)
#define rfbHextilePackWH(w,h) ((((w)-1) << 4) | ((h)-1))
#define rfbHextilePackXY(x,y) (((x) << 4) | (y))
#define rfbKeyEvent 4
#define rfbKeyboardMaskAlt          8
#define rfbKeyboardMaskAltGraph   512
#define rfbKeyboardMaskCapsLock     2
#define rfbKeyboardMaskControl      4
#define rfbKeyboardMaskHyper       64
#define rfbKeyboardMaskMeta        16
#define rfbKeyboardMaskNumLock    128
#define rfbKeyboardMaskScrollLock 256
#define rfbKeyboardMaskShift        1
#define rfbKeyboardMaskSuper       32
#define rfbMSLogon 0xfffffffa
#define rfbMax(a,b) (((a)>(b))?(a):(b))
#define rfbNoAuth 1
#define rfbPalmVNCReSizeFrameBuffer 0xF
#define rfbPalmVNCSetScaleFactor 0xF
#define rfbPointerEvent 5
#define rfbProtocolMajorVersion 3
#define rfbProtocolMinorVersion 8
#define rfbProtocolVersionFormat "RFB %03d.%03d\n"
#define rfbRA2 5
#define rfbRA2ne 6
#define rfbRErrorUnknownCmd     1  
#define rfbResizeFrameBuffer 4
#define rfbSASL 20
#define rfbSSPI 7
#define rfbSSPIne 8
#define rfbSecTypeInvalid 0
#define rfbSecTypeNone 1
#define rfbSecTypeVncAuth 2
#define rfbServerCutText 3
#define rfbSetColourMapEntries 1
#define rfbSetDesktopSize 251
#define rfbSetEncodings 2
#define rfbSetPixelFormat 0
#define rfbSetScale 8
#define rfbSocket int
#define rfbTLS 18
#define rfbTextChatFinished 0xFFFFFFFD  
#define rfbTight 16
#define rfbTightExplicitFilter         0x04
#define rfbTightFill                   0x08
#define rfbTightFilterCopy             0x00
#define rfbTightFilterGradient         0x02
#define rfbTightFilterPalette          0x01
#define rfbTightJpeg                   0x09
#define rfbTightMaxSubencoding         0x0A
#define rfbTightNoZlib                 0x0A
#define rfbTightPng                    0x0A
#define rfbUltra 17
#define rfbVeNCrypt 19
#define rfbVeNCryptPlain 256
#define rfbVeNCryptTLSNone 257
#define rfbVeNCryptTLSPlain 259
#define rfbVeNCryptTLSSASL 264
#define rfbVeNCryptTLSVNC 258
#define rfbVeNCryptX509None 260
#define rfbVeNCryptX509Plain 262
#define rfbVeNCryptX509SASL 263
#define rfbVeNCryptX509VNC 261
#define rfbVncAuth 2
#define rfbVncAuthFailed 1
#define rfbVncAuthOK 0
#define rfbVncAuthTooMany 2
#define rfbWheelDownMask rfbButton5Mask
#define rfbWheelUpMask rfbButton4Mask
#define rfbXvp 250
#define rfbXvp_Fail 0
#define rfbXvp_Init 1
#define rfbXvp_Reboot 3
#define rfbXvp_Reset 4
#define rfbXvp_Shutdown 2
#define rfbZRLETileHeight 64
#define rfbZRLETileWidth 64
#define rfbZipDirectoryPrefix   "!UVNCDIR-\0" 
#define strncasecmp _strnicmp
#define sz_rfbBellMsg 1
#define sz_rfbCacheRect 2
#define sz_rfbClientCutTextMsg 8
#define sz_rfbClientInitMsg 1
#define sz_rfbCoRRERectangle 4
#define sz_rfbCopyRect 4
#define sz_rfbExtDesktopScreen (16)
#define sz_rfbExtDesktopSizeMsg (4)
#define sz_rfbFixColourMapEntriesMsg 6
#define sz_rfbFramebufferUpdateMsg 4
#define sz_rfbFramebufferUpdateRectHeader (sz_rfbRectangle + 4)
#define sz_rfbFramebufferUpdateRequestMsg 10
#define sz_rfbKeyEventMsg 8
#define sz_rfbPalmVNCReSizeFrameBufferMsg (12)
#define sz_rfbPalmVNCSetScaleFactorMsg (4)
#define sz_rfbPixelFormat 16
#define sz_rfbPointerEventMsg 6
#define sz_rfbProtocolVersionMsg 12
#define sz_rfbRREHeader 4
#define sz_rfbRectangle 8
#define sz_rfbResizeFrameBufferMsg 6
#define sz_rfbServerCutTextMsg 8
#define sz_rfbServerInitMsg (8 + sz_rfbPixelFormat)
#define sz_rfbSetColourMapEntriesMsg 6
#define sz_rfbSetDesktopSizeMsg (8)
#define sz_rfbSetEncodingsMsg 4
#define sz_rfbSetPixelFormatMsg (sz_rfbPixelFormat + 4)
#define sz_rfbSetSWMsg 6
#define sz_rfbSetScaleMsg 4
#define sz_rfbSetServerInputMsg 4
#define sz_rfbSupportedMessages 64
#define sz_rfbTextChatMsg 8
#define sz_rfbXCursorColors 6
#define sz_rfbXvpMsg (4)
#define sz_rfbZRLEHeader 4
#define sz_rfbZipDirectoryPrefix 9 
#define sz_rfbZlibHeader 4
