#include<stdarg.h>
#include<stdlib.h>

#include<stdio.h>
#include<string.h>
#include<assert.h>
#include<inttypes.h>

#include<stddef.h>
#include<sys/stat.h>
#define ITEM_ARTURL_FETCHED  2
#define ITEM_ART_FETCHED     4
#define ITEM_ART_NOTFOUND    8
#define ITEM_PREPARSED       1
#define VLC_META_ALBUM              vlc_meta_TypeToLocalizedString( vlc_meta_Album )
#define VLC_META_ARTIST             vlc_meta_TypeToLocalizedString( vlc_meta_Artist )
#define VLC_META_ART_URL            vlc_meta_TypeToLocalizedString( vlc_meta_ArtworkURL )
#define VLC_META_COPYRIGHT          vlc_meta_TypeToLocalizedString( vlc_meta_Copyright )
#define VLC_META_DATE               vlc_meta_TypeToLocalizedString( vlc_meta_Date )
#define VLC_META_DESCRIPTION        vlc_meta_TypeToLocalizedString( vlc_meta_Description )
#define VLC_META_ENCODED_BY         vlc_meta_TypeToLocalizedString( vlc_meta_EncodedBy )
#define VLC_META_GENRE              vlc_meta_TypeToLocalizedString( vlc_meta_Genre )
#define VLC_META_H 1
#define VLC_META_LANGUAGE           vlc_meta_TypeToLocalizedString( vlc_meta_Language )
#define VLC_META_NOW_PLAYING        vlc_meta_TypeToLocalizedString( vlc_meta_NowPlaying )
#define VLC_META_PUBLISHER          vlc_meta_TypeToLocalizedString( vlc_meta_Publisher )
#define VLC_META_RATING             vlc_meta_TypeToLocalizedString( vlc_meta_Rating )
#define VLC_META_SETTING            vlc_meta_TypeToLocalizedString( vlc_meta_Setting )
#define VLC_META_TITLE              vlc_meta_TypeToLocalizedString( vlc_meta_Title )
#define VLC_META_TRACKID            vlc_meta_TypeToLocalizedString( vlc_meta_TrackID )
#define VLC_META_TRACK_NUMBER       vlc_meta_TypeToLocalizedString( vlc_meta_TrackNumber )
#define VLC_META_TYPE_COUNT 17
#define VLC_META_URL                vlc_meta_TypeToLocalizedString( vlc_meta_URL )
#define vlc_meta_SetAlbum( meta, b )       vlc_meta_Set( meta, vlc_meta_Album, b )
#define vlc_meta_SetArtURL( meta, b )      vlc_meta_Set( meta, vlc_meta_ArtworkURL, b )
#define vlc_meta_SetArtist( meta, b )      vlc_meta_Set( meta, vlc_meta_Artist, b )
#define vlc_meta_SetCopyright( meta, b )   vlc_meta_Set( meta, vlc_meta_Copyright, b )
#define vlc_meta_SetDate( meta, b )        vlc_meta_Set( meta, vlc_meta_Date, b )
#define vlc_meta_SetDescription( meta, b ) vlc_meta_Set( meta, vlc_meta_Description, b )
#define vlc_meta_SetEncodedBy( meta, b )   vlc_meta_Set( meta, vlc_meta_EncodedBy, b )
#define vlc_meta_SetGenre( meta, b )       vlc_meta_Set( meta, vlc_meta_Genre, b )
#define vlc_meta_SetLanguage( meta, b )    vlc_meta_Set( meta, vlc_meta_Language, b )
#define vlc_meta_SetNowPlaying( meta, b )  vlc_meta_Set( meta, vlc_meta_NowPlaying, b )
#define vlc_meta_SetPublisher( meta, b )   vlc_meta_Set( meta, vlc_meta_Publisher, b )
#define vlc_meta_SetRating( meta, b )      vlc_meta_Set( meta, vlc_meta_Rating, b )
#define vlc_meta_SetSetting( meta, b )     vlc_meta_Set( meta, vlc_meta_Setting, b )
#define vlc_meta_SetTitle( meta, b )       vlc_meta_Set( meta, vlc_meta_Title, b )
#define vlc_meta_SetTrackID( meta, b )     vlc_meta_Set( meta, vlc_meta_TrackID, b )
#define vlc_meta_SetTrackNum( meta, b )    vlc_meta_Set( meta, vlc_meta_TrackNumber, b )
#define vlc_meta_SetURL( meta, b )         vlc_meta_Set( meta, vlc_meta_URL, b )
#define VLC_CHARSET_H 1
#define DEMUX_INIT_COMMON() do {            \
    p_demux->pf_control = Control;          \
    p_demux->pf_demux = Demux;              \
    p_demux->p_sys = calloc( 1, sizeof( demux_sys_t ) ); \
    if( !p_demux->p_sys ) return VLC_ENOMEM;\
    } while(0)
#define VLC_DEMUX_H 1
#define VLC_ES_OUT_H 1
#define VLC_STREAM_H 1
#define stream_MemoryNew( a, b, c, d ) stream_MemoryNew( VLC_OBJECT(a), b, c, d )
#define stream_UrlNew( a, b ) stream_UrlNew( VLC_OBJECT(a), b )
#define BLOCK_FLAG_BOTTOM_FIELD_FIRST 0x4000
#define BLOCK_FLAG_CLOCK         0x0200
#define BLOCK_FLAG_CORE_PRIVATE_MASK  0x00ff0000
#define BLOCK_FLAG_CORE_PRIVATE_SHIFT 16
#define BLOCK_FLAG_CORRUPTED     0x1000
#define BLOCK_FLAG_DISCONTINUITY 0x0001
#define BLOCK_FLAG_END_OF_FRAME  0x0040
#define BLOCK_FLAG_END_OF_SEQUENCE 0x0100
#define BLOCK_FLAG_HEADER        0x0020
#define BLOCK_FLAG_INTERLACED_MASK \
    (BLOCK_FLAG_TOP_FIELD_FIRST|BLOCK_FLAG_BOTTOM_FIELD_FIRST)
#define BLOCK_FLAG_NO_KEYFRAME   0x0080
#define BLOCK_FLAG_PREROLL       0x0800
#define BLOCK_FLAG_PRIVATE_MASK  0xff000000
#define BLOCK_FLAG_PRIVATE_SHIFT 24
#define BLOCK_FLAG_SCRAMBLED     0x0400
#define BLOCK_FLAG_TOP_FIELD_FIRST 0x2000
#define BLOCK_FLAG_TYPE_B        0x0008
#define BLOCK_FLAG_TYPE_I        0x0002
#define BLOCK_FLAG_TYPE_MASK \
    (BLOCK_FLAG_TYPE_I|BLOCK_FLAG_TYPE_P|BLOCK_FLAG_TYPE_B|BLOCK_FLAG_TYPE_PB)
#define BLOCK_FLAG_TYPE_P        0x0004
#define BLOCK_FLAG_TYPE_PB       0x0010
#define VLC_BLOCK_H 1
#define block_New( dummy, size ) block_Alloc(size)
#define block_cleanup_push( block ) vlc_cleanup_push (block_Cleanup, block)
#define AUDIO_REPLAY_GAIN_ALBUM (1)
#define AUDIO_REPLAY_GAIN_MAX (2)
#define AUDIO_REPLAY_GAIN_TRACK (0)
#define VLC_ES_H 1
#define VLC_CODEC_302M      VLC_FOURCC('3','0','2','m')
#define VLC_CODEC_4XM       VLC_FOURCC('4','X','M','V')
#define VLC_CODEC_8BPS      VLC_FOURCC('8','B','P','S')
#define VLC_CODEC_A52       VLC_FOURCC('a','5','2',' ')
#define VLC_CODEC_AASC      VLC_FOURCC('A','A','S','C')
#define VLC_CODEC_ADPCM_4XM VLC_FOURCC('4','x','m','a')
#define VLC_CODEC_ADPCM_ADX VLC_FOURCC('a','d','x',' ')
#define VLC_CODEC_ADPCM_EA  VLC_FOURCC('A','D','E','A')
#define VLC_CODEC_ADPCM_G722 VLC_FOURCC('g','7','2','2')
#define VLC_CODEC_ADPCM_G726 VLC_FOURCC('g','7','2','6')
#define VLC_CODEC_ADPCM_IMA_AMV VLC_FOURCC('i','m','a','v')
#define VLC_CODEC_ADPCM_IMA_WAV VLC_FOURCC('m','s',0x00,0x11)
#define VLC_CODEC_ADPCM_IMA_WS VLC_FOURCC('A','I','W','S')
#define VLC_CODEC_ADPCM_MS  VLC_FOURCC('m','s',0x00,0x02)
#define VLC_CODEC_ADPCM_SWF VLC_FOURCC('S','W','F','a')
#define VLC_CODEC_ADPCM_XA  VLC_FOURCC('x','a',' ',' ')
#define VLC_CODEC_ALAC      VLC_FOURCC('a','l','a','c')
#define VLC_CODEC_ALAW      VLC_FOURCC('a','l','a','w')
#define VLC_CODEC_ALS       VLC_FOURCC('a','l','s',' ')
#define VLC_CODEC_AMR_NB    VLC_FOURCC('s','a','m','r')
#define VLC_CODEC_AMR_WB    VLC_FOURCC('s','a','w','b')
#define VLC_CODEC_AMV       VLC_FOURCC('A','M','V',' ')
#define VLC_CODEC_APE       VLC_FOURCC('A','P','E',' ')
#define VLC_CODEC_ASV1      VLC_FOURCC('A','S','V','1')
#define VLC_CODEC_ASV2      VLC_FOURCC('A','S','V','2')
#define VLC_CODEC_ATRAC1    VLC_FOURCC('a','t','r','1')
#define VLC_CODEC_ATRAC3    VLC_FOURCC('a','t','r','c')
#define VLC_CODEC_BD_LPCM   VLC_FOURCC('b','p','c','m')
#define VLC_CODEC_BD_PG     VLC_FOURCC('b','d','p','g')
#define VLC_CODEC_BMP       VLC_FOURCC('b','m','p',' ')
#define VLC_CODEC_CAVS      VLC_FOURCC('C','A','V','S')
#define VLC_CODEC_CDG       VLC_FOURCC('C','D','G',' ')
#define VLC_CODEC_CINEPAK   VLC_FOURCC('C','V','I','D')
#define VLC_CODEC_CLJR      VLC_FOURCC('C','L','J','R')
#define VLC_CODEC_CMML      VLC_FOURCC('c','m','m','l')
#define VLC_CODEC_COOK      VLC_FOURCC('c','o','o','k')
#define VLC_CODEC_CSCD      VLC_FOURCC('C','S','C','D')
#define VLC_CODEC_CVD       VLC_FOURCC('c','v','d',' ')
#define VLC_CODEC_CYUV      VLC_FOURCC('c','y','u','v')
#define VLC_CODEC_DIRAC     VLC_FOURCC('d','r','a','c')
#define VLC_CODEC_DIV1      VLC_FOURCC('D','I','V','1')
#define VLC_CODEC_DIV2      VLC_FOURCC('D','I','V','2')
#define VLC_CODEC_DIV3      VLC_FOURCC('D','I','V','3')
#define VLC_CODEC_DNXHD     VLC_FOURCC('A','V','d','n')
#define VLC_CODEC_DSICINAUDIO VLC_FOURCC('D','C','I','A')
#define VLC_CODEC_DTS       VLC_FOURCC('d','t','s',' ')
#define VLC_CODEC_DV        VLC_FOURCC('d','v',' ',' ')
#define VLC_CODEC_DVAUDIO   VLC_FOURCC('d','v','a','u')
#define VLC_CODEC_DVBS      VLC_FOURCC('d','v','b','s')
#define VLC_CODEC_DVDA_LPCM VLC_FOURCC('a','p','c','m')
#define VLC_CODEC_DVD_LPCM  VLC_FOURCC('l','p','c','m')
#define VLC_CODEC_EAC3      VLC_FOURCC('e','a','c','3')
#define VLC_CODEC_F32B      VLC_FOURCC('f','3','2','b')
#define VLC_CODEC_F32L      VLC_FOURCC('f','3','2','l')
#define VLC_CODEC_F64B      VLC_FOURCC('f','6','4','b')
#define VLC_CODEC_F64L      VLC_FOURCC('f','6','4','l')
#define VLC_CODEC_FFV1      VLC_FOURCC('F','F','V','1')
#define VLC_CODEC_FFVHUFF   VLC_FOURCC('F','F','V','H')
#define VLC_CODEC_FI32      VLC_FOURCC('f','i','3','2')
#   define VLC_CODEC_FL32 VLC_CODEC_F32B
#   define VLC_CODEC_FL64 VLC_CODEC_F64B
#define VLC_CODEC_FLAC      VLC_FOURCC('f','l','a','c')
#define VLC_CODEC_FLASHSV   VLC_FOURCC('F','S','V','1')
#define VLC_CODEC_FLIC      VLC_FOURCC('F','L','I','C')
#define VLC_CODEC_FLV1      VLC_FOURCC('F','L','V','1')
#define VLC_CODEC_FRAPS     VLC_FOURCC('F','P','S','1')
#define VLC_CODEC_FRWU      VLC_FOURCC('F','R','W','U')
#define VLC_CODEC_GIF       VLC_FOURCC('g','i','f',' ')
#define VLC_CODEC_GREY      VLC_FOURCC('G','R','E','Y')
#define VLC_CODEC_GSM       VLC_FOURCC('g','s','m',' ')
#define VLC_CODEC_GSM_MS    VLC_FOURCC('a','g','s','m')
#define VLC_CODEC_H261      VLC_FOURCC('h','2','6','1')
#define VLC_CODEC_H263      VLC_FOURCC('h','2','6','3')
#define VLC_CODEC_H263I     VLC_FOURCC('I','2','6','3')
#define VLC_CODEC_H263P     VLC_FOURCC('I','L','V','R')
#define VLC_CODEC_H264      VLC_FOURCC('h','2','6','4')
#define VLC_CODEC_HUFFYUV   VLC_FOURCC('H','F','Y','U')
#define VLC_CODEC_I410      VLC_FOURCC('I','4','1','0')
#define VLC_CODEC_I411      VLC_FOURCC('I','4','1','1')
#define VLC_CODEC_I420      VLC_FOURCC('I','4','2','0')
#define VLC_CODEC_I422      VLC_FOURCC('I','4','2','2')
#define VLC_CODEC_I440      VLC_FOURCC('I','4','4','0')
#define VLC_CODEC_I444      VLC_FOURCC('I','4','4','4')
#define VLC_CODEC_IDCIN     VLC_FOURCC('I','D','C','I')
#define VLC_CODEC_IMC       VLC_FOURCC(0x1,0x4,0x0,0x0)
#define VLC_CODEC_INDEO2    VLC_FOURCC('I','V','2','0')
#define VLC_CODEC_INDEO3    VLC_FOURCC('I','V','3','1')
#define VLC_CODEC_INDEO5    VLC_FOURCC('I','V','5','0')
#define VLC_CODEC_INTERPLAY VLC_FOURCC('i','m','v','e')
#define VLC_CODEC_INTERPLAY_DPCM VLC_FOURCC('i','d','p','c')
#define VLC_CODEC_ITU_T140  VLC_FOURCC('t','1','4','0')
#define VLC_CODEC_J420      VLC_FOURCC('J','4','2','0')
#define VLC_CODEC_J422      VLC_FOURCC('J','4','2','2')
#define VLC_CODEC_J440      VLC_FOURCC('J','4','4','0')
#define VLC_CODEC_J444      VLC_FOURCC('J','4','4','4')
#define VLC_CODEC_JPEG      VLC_FOURCC('j','p','e','g')
#define VLC_CODEC_JPEG2000  VLC_FOURCC('J','P','2','K')
#define VLC_CODEC_JPEGLS    VLC_FOURCC('M','J','L','S')
#define VLC_CODEC_KATE      VLC_FOURCC('k','a','t','e')
#define VLC_CODEC_KMVC      VLC_FOURCC('K','M','V','C')
#define VLC_CODEC_LJPG      VLC_FOURCC('L','J','P','G')
#define VLC_CODEC_LOCO      VLC_FOURCC('L','O','C','O')
#define VLC_CODEC_MACE3     VLC_FOURCC('M','A','C','3')
#define VLC_CODEC_MACE6     VLC_FOURCC('M','A','C','6')
#define VLC_CODEC_MDEC      VLC_FOURCC('M','D','E','C')
#define VLC_CODEC_MIDI      VLC_FOURCC('M','I','D','I')
#define VLC_CODEC_MIMIC     VLC_FOURCC('M','L','2','O')
#define VLC_CODEC_MJPG      VLC_FOURCC('M','J','P','G')
#define VLC_CODEC_MJPGB     VLC_FOURCC('m','j','p','b')
#define VLC_CODEC_MLP       VLC_FOURCC('m','l','p',' ')
#define VLC_CODEC_MP1V      VLC_FOURCC('m','p','1','v')
#define VLC_CODEC_MP2V      VLC_FOURCC('m','p','2','v')
#define VLC_CODEC_MP3       VLC_FOURCC('m','p','3',' ')
#define VLC_CODEC_MP4A      VLC_FOURCC('m','p','4','a')
#define VLC_CODEC_MP4V      VLC_FOURCC('m','p','4','v')
#define VLC_CODEC_MPGA      VLC_FOURCC('m','p','g','a')
#define VLC_CODEC_MPGV      VLC_FOURCC('m','p','g','v')
#define VLC_CODEC_MSRLE     VLC_FOURCC('m','r','l','e')
#define VLC_CODEC_MSVIDEO1  VLC_FOURCC('M','S','V','C')
#define VLC_CODEC_MULAW     VLC_FOURCC('m','l','a','w')
#define VLC_CODEC_MUSEPACK7 VLC_FOURCC('M','P','C',' ')
#define VLC_CODEC_MUSEPACK8 VLC_FOURCC('M','P','C','K')
#define VLC_CODEC_NELLYMOSER VLC_FOURCC('N','E','L','L')
#define VLC_CODEC_NUV       VLC_FOURCC('N','J','P','G')
#define VLC_CODEC_NV12      VLC_FOURCC('N','V','1','2')
#define VLC_CODEC_OGT       VLC_FOURCC('o','g','t',' ')
#define VLC_CODEC_PAM       VLC_FOURCC('p','a','m',' ')
#define VLC_CODEC_PCX       VLC_FOURCC('p','c','x',' ')
#define VLC_CODEC_PGM       VLC_FOURCC('p','g','m',' ')
#define VLC_CODEC_PGMYUV    VLC_FOURCC('p','g','m','y')
#define VLC_CODEC_PNG       VLC_FOURCC('p','n','g',' ')
#define VLC_CODEC_PNM       VLC_FOURCC('p','n','m',' ')
#define VLC_CODEC_PPM       VLC_FOURCC('p','p','m',' ')
#define VLC_CODEC_QCELP     VLC_FOURCC('Q','c','l','p')
#define VLC_CODEC_QDM2      VLC_FOURCC('Q','D','M','2')
#define VLC_CODEC_QDRAW     VLC_FOURCC('q','d','r','w')
#define VLC_CODEC_QPEG      VLC_FOURCC('Q','P','E','G')
#define VLC_CODEC_QTRLE     VLC_FOURCC('r','l','e',' ')
#define VLC_CODEC_RA_144    VLC_FOURCC('1','4','_','4')
#define VLC_CODEC_RA_288    VLC_FOURCC('2','8','_','8')
#define VLC_CODEC_RGB15     VLC_FOURCC('R','V','1','5')
#define VLC_CODEC_RGB16     VLC_FOURCC('R','V','1','6')
#define VLC_CODEC_RGB24     VLC_FOURCC('R','V','2','4')
#define VLC_CODEC_RGB32     VLC_FOURCC('R','V','3','2')
#define VLC_CODEC_RGB8      VLC_FOURCC('R','G','B','8')
#define VLC_CODEC_RGBA      VLC_FOURCC('R','G','B','A')
#define VLC_CODEC_RGBP      VLC_FOURCC('R','G','B','P')
#define VLC_CODEC_ROQ       VLC_FOURCC('R','o','Q','v')
#define VLC_CODEC_ROQ_DPCM  VLC_FOURCC('R','o','Q','a')
#define VLC_CODEC_RPZA      VLC_FOURCC('r','p','z','a')
#define VLC_CODEC_RV10      VLC_FOURCC('R','V','1','0')
#define VLC_CODEC_RV13      VLC_FOURCC('R','V','1','3')
#define VLC_CODEC_RV20      VLC_FOURCC('R','V','2','0')
#define VLC_CODEC_RV30      VLC_FOURCC('R','V','3','0')
#define VLC_CODEC_RV40      VLC_FOURCC('R','V','4','0')
#define VLC_CODEC_S16B      VLC_FOURCC('s','1','6','b')
#   define VLC_CODEC_S16I VLC_CODEC_S16L
#define VLC_CODEC_S16L      VLC_FOURCC('s','1','6','l')
#   define VLC_CODEC_S16N VLC_CODEC_S16B
#define VLC_CODEC_S24B      VLC_FOURCC('s','2','4','b')
#define VLC_CODEC_S24DAUD   VLC_FOURCC('d','a','u','d')
#   define VLC_CODEC_S24I VLC_CODEC_S24L
#define VLC_CODEC_S24L      VLC_FOURCC('s','2','4','l')
#   define VLC_CODEC_S24N VLC_CODEC_S24B
#define VLC_CODEC_S32B      VLC_FOURCC('s','3','2','b')
#   define VLC_CODEC_S32I VLC_CODEC_S32L
#define VLC_CODEC_S32L      VLC_FOURCC('s','3','2','l')
#   define VLC_CODEC_S32N VLC_CODEC_S32B
#define VLC_CODEC_S8        VLC_FOURCC('s','8',' ',' ')
#define VLC_CODEC_SDDS      VLC_FOURCC('s','d','d','s')
#define VLC_CODEC_SGI       VLC_FOURCC('s','g','i',' ')
#define VLC_CODEC_SHORTEN   VLC_FOURCC('s','h','n',' ')
#define VLC_CODEC_SIPR      VLC_FOURCC('s','i','p','r')
#define VLC_CODEC_SMACKVIDEO VLC_FOURCC('S','M','K','2')
#define VLC_CODEC_SMC       VLC_FOURCC('s','m','c',' ')
#define VLC_CODEC_SNOW      VLC_FOURCC('S','N','O','W')
#define VLC_CODEC_SONIC     VLC_FOURCC('S','O','N','C')
#define VLC_CODEC_SP5X      VLC_FOURCC('S','P','5','X')
#define VLC_CODEC_SPEEX     VLC_FOURCC('s','p','x',' ')
#define VLC_CODEC_SPU       VLC_FOURCC('s','p','u',' ')
#define VLC_CODEC_SSA       VLC_FOURCC('s','s','a',' ')
#define VLC_CODEC_SUBT      VLC_FOURCC('s','u','b','t')
#define VLC_CODEC_SVQ1      VLC_FOURCC('S','V','Q','1')
#define VLC_CODEC_SVQ3      VLC_FOURCC('S','V','Q','3')
#define VLC_CODEC_TARGA     VLC_FOURCC('t','g','a',' ')
#define VLC_CODEC_TARKIN    VLC_FOURCC('t','a','r','k')
#define VLC_CODEC_TELETEXT  VLC_FOURCC('t','e','l','x')
#define VLC_CODEC_TEXT      VLC_FOURCC('T','E','X','T')
#define VLC_CODEC_THEORA    VLC_FOURCC('t','h','e','o')
#define VLC_CODEC_TIFF      VLC_FOURCC('t','i','f','f')
#define VLC_CODEC_TRUEHD    VLC_FOURCC('t','r','h','d')
#define VLC_CODEC_TRUEMOTION1 VLC_FOURCC('D','U','C','K')
#define VLC_CODEC_TRUEMOTION2 VLC_FOURCC('T','M','2','0')
#define VLC_CODEC_TRUESPEECH VLC_FOURCC(0x22,0x0,0x0,0x0)
#define VLC_CODEC_TSCC      VLC_FOURCC('T','S','C','C')
#define VLC_CODEC_TTA       VLC_FOURCC('T','T','A','1')
#define VLC_CODEC_TWINVQ    VLC_FOURCC('T','W','I','N')
#define VLC_CODEC_U16B      VLC_FOURCC('u','1','6','b')
#   define VLC_CODEC_U16I VLC_CODEC_U16L
#define VLC_CODEC_U16L      VLC_FOURCC('u','1','6','l')
#   define VLC_CODEC_U16N VLC_CODEC_U16B
#define VLC_CODEC_U24B      VLC_FOURCC('u','2','4','b')
#define VLC_CODEC_U24L      VLC_FOURCC('u','2','4','l')
#define VLC_CODEC_U32B      VLC_FOURCC('u','3','2','b')
#define VLC_CODEC_U32L      VLC_FOURCC('u','3','2','l')
#define VLC_CODEC_U8        VLC_FOURCC('u','8',' ',' ')
#define VLC_CODEC_ULTI      VLC_FOURCC('U','L','T','I')
#define VLC_CODEC_USF       VLC_FOURCC('u','s','f',' ')
#define VLC_CODEC_UYVY      VLC_FOURCC('U','Y','V','Y')
#define VLC_CODEC_V210      VLC_FOURCC('v','2','1','0')
#define VLC_CODEC_VC1       VLC_FOURCC('V','C','-','1')
#define VLC_CODEC_VCR1      VLC_FOURCC('V','C','R','1')
#define VLC_CODEC_VIXL      VLC_FOURCC('V','I','X','L')
#define VLC_CODEC_VMDAUDIO  VLC_FOURCC('v','m','d','a')
#define VLC_CODEC_VMDVIDEO  VLC_FOURCC('V','M','D','V')
#define VLC_CODEC_VMNC      VLC_FOURCC('V','M','n','c')
#define VLC_CODEC_VORBIS    VLC_FOURCC('v','o','r','b')
#define VLC_CODEC_VP3       VLC_FOURCC('V','P','3',' ')
#define VLC_CODEC_VP5       VLC_FOURCC('V','P','5',' ')
#define VLC_CODEC_VP6       VLC_FOURCC('V','P','6','2')
#define VLC_CODEC_VP6A      VLC_FOURCC('V','P','6','A')
#define VLC_CODEC_VP6F      VLC_FOURCC('V','P','6','F')
#define VLC_CODEC_VP8       VLC_FOURCC('V','P','8','0')
#define VLC_CODEC_VYUY      VLC_FOURCC('V','Y','U','Y')
#define VLC_CODEC_WAVPACK   VLC_FOURCC('W','V','P','K')
#define VLC_CODEC_WMA1      VLC_FOURCC('W','M','A','1')
#define VLC_CODEC_WMA2      VLC_FOURCC('W','M','A','2')
#define VLC_CODEC_WMAL      VLC_FOURCC('W','M','A','L')
#define VLC_CODEC_WMAP      VLC_FOURCC('W','M','A','P')
#define VLC_CODEC_WMAS      VLC_FOURCC('W','M','A','S')
#define VLC_CODEC_WMV1      VLC_FOURCC('W','M','V','1')
#define VLC_CODEC_WMV2      VLC_FOURCC('W','M','V','2')
#define VLC_CODEC_WMV3      VLC_FOURCC('W','M','V','3')
#define VLC_CODEC_WMVA      VLC_FOURCC('W','M','V','A')
#define VLC_CODEC_WMVP      VLC_FOURCC('W','M','V','P')
#define VLC_CODEC_WNV1      VLC_FOURCC('W','N','V','1')
#define VLC_CODEC_XSUB      VLC_FOURCC('X','S','U','B')
#define VLC_CODEC_Y211      VLC_FOURCC('Y','2','1','1')
#define VLC_CODEC_YUVA      VLC_FOURCC('Y','U','V','A')
#define VLC_CODEC_YUVP      VLC_FOURCC('Y','U','V','P')
#define VLC_CODEC_YUYV      VLC_FOURCC('Y','U','Y','2')
#define VLC_CODEC_YV12      VLC_FOURCC('Y','V','1','2')
#define VLC_CODEC_YV9       VLC_FOURCC('Y','V','U','9')
#define VLC_CODEC_YVYU      VLC_FOURCC('Y','V','Y','U')
#define VLC_CODEC_ZMBV      VLC_FOURCC('Z','M','B','V')
#define VLC_FOURCC_H 1
#define CEIL(n, d)  ( ((n) / (d)) + ( ((n) % (d)) ? 1 : 0) )
#   define DIR_SEP "\\"
#   define DIR_SEP_CHAR '\\'
#define EMPTY_STR(str) (!str || !*str)
#define FREENULL(a) do { free( a ); a = NULL; } while(0)
#define GetDWBE( p )    U32_AT( p )
#define GetQWBE( p )    U64_AT( p )
#define GetWBE( p )     U16_AT( p )
# define LIBVLC_EXPORT __declspec(dllexport)
# define LIBVLC_EXTERN extern "C"
#     define LIBVLC_FORMAT(x,y) __attribute__ ((format(gnu_printf,x,y)))
#   define LIBVLC_FORMAT_ARG(x) __attribute__ ((format_arg(x)))
#   define LIBVLC_MALLOC __attribute__ ((malloc))
#     define LIBVLC_USED __attribute__ ((warn_unused_result))
#define LICENSE_MSG \
  _("This program comes with NO WARRANTY, to the extent permitted by " \
    "law.\nYou may redistribute it under the terms of the GNU General " \
    "Public License;\nsee the file named COPYING for details.\n" \
    "Written by the VideoLAN team; see the AUTHORS file.\n")
#       define O_NONBLOCK 0
#define PAD(n, d)   ( ((n) % (d)) ? ((((n) / (d)) + 1) * (d)) : (n) )
#       define PATH_MAX MAX_PATH
#   define PATH_SEP ";"
#   define PATH_SEP_CHAR ';'
 #define PRId64 "lld"
 #define PRIi64 "lli"
 #define PRIo64 "llo"
 #define PRIu64 "llu"
 #define PRIx64 "llx"
#       define S_IFBLK         0x3000  
#       define S_ISBLK(m)      (0)
#       define S_ISCHR(m)      (0)
#       define S_ISFIFO(m)     (((m)&_S_IFMT) == _S_IFIFO)
#       define S_ISREG(m)      (((m)&_S_IFMT) == _S_IFREG)
#define SetDWBE( p, v ) _SetDWBE( (uint8_t*)(p), v)
#define SetDWLE( p, v ) _SetDWLE( (uint8_t*)(p), v)
#define SetQWBE( p, v ) _SetQWBE( (uint8_t*)(p), v)
#define SetQWLE( p, v ) _SetQWLE( (uint8_t*)(p), v)
#define SetWBE( p, v ) _SetWBE( (uint8_t*)(p), v)
#define SetWLE( p, v ) _SetWLE( (uint8_t*)(p), v)
# define VLC_COMMON_H 1
#define VLC_COMMON_MEMBERS                                                  \
                                                                         \
                                                                     \
    const char *psz_object_type;                                            \
                                                                            \
                                                       \
    char *psz_header;                                                       \
    int  i_flags;                                                           \
                                                                            \
                                                     \
    volatile bool b_die;                    \
    bool b_force;       \
                                                                            \
                                 \
    libvlc_int_t *p_libvlc;                   \
                                                                            \
    vlc_object_t *  p_parent;                             \
                                                                            \
                                                                     \

#define VLC_EBADVAR        -31                         
#define VLC_EEXIT         -255                             
#define VLC_EEXITSUCCESS  -999                
#define VLC_EGENERIC      -666                              
#define VLC_ENOITEM        -40                           
#define VLC_ENOMEM          -1                          
#define VLC_ENOMOD         -10                           
#define VLC_ENOOBJ         -20                           
#define VLC_ENOVAR         -30                         
#define VLC_ETIMEOUT        -3                                    
#define VLC_EXPORT( type, name, args ) \
                        LIBVLC_EXTERN LIBVLC_EXPORT type name args
#   define VLC_FOURCC( a, b, c, d ) \
        ( ((uint32_t)d) | ( ((uint32_t)c) << 8 ) \
           | ( ((uint32_t)b) << 16 ) | ( ((uint32_t)a) << 24 ) )
#define VLC_GC_MEMBERS gc_object_t vlc_gc_data;
#  define VLC_OBJECT( x ) \
    __builtin_choose_expr(__builtin_offsetof(__typeof__(*x), psz_object_type), \
                          (void)0 , (vlc_object_t *)(x))
#define VLC_SUCCESS         -0                                   
#   define VLC_TWOCC( a, b ) \
        ( (uint16_t)(b) | ( (uint16_t)(a) << 8 ) )
#define VLC_UNUSED(x) (void)(x)
#define VLC_VAR_ADDRESS   0x0070
#define VLC_VAR_BOOL      0x0020
#define VLC_VAR_COORDS    0x00A0
#define VLC_VAR_FLOAT     0x0050
#define VLC_VAR_HOTKEY    0x0031
#define VLC_VAR_INTEGER   0x0030
#define VLC_VAR_MUTEX     0x0080
#define VLC_VAR_STRING    0x0040
#define VLC_VAR_TIME      0x0060
#define VLC_VAR_VARIABLE  0x0044
#define VLC_VAR_VOID      0x0010
#   define WIN32_LEAN_AND_MEAN
#           define _OFF_T_
#           define _OFF_T_DEFINED
#   define __MAX(a, b)   ( ((a) > (b)) ? (a) : (b) )
#   define __MIN(a, b)   ( ((a) < (b)) ? (a) : (b) )
#       define __attribute__(x)
#       define __inline__      __inline
#       define alloca _alloca
#define clz16( x ) (clz(x) - ((sizeof(unsigned) - sizeof (uint16_t)) * 8))
#define clz32( x ) (clz(x) - ((sizeof(unsigned) - sizeof (uint32_t)) * 8))
#define clz8( x ) (clz(x) - ((sizeof(unsigned) - sizeof (uint8_t)) * 8))
#define fstat _fstati64
#define hton16(i) htons(i)
#define hton32(i) htonl(i)
#define hton64(i) ntoh64(i)
#   define likely(p)   (!!(p))
#define ntoh16(i) ntohs(i)
#define ntoh32(i) ntohl(i)
#           define off_t long long
 #define snprintf        __mingw_snprintf
#define stat _stati64
#   define unlikely(p) (!!(p))
#define vlc_execve(a,b,c,d,e,f,g,h,i) vlc_execve(VLC_OBJECT(a),b,c,d,e,f,g,h,i)
#define vlc_fourcc_to_char( a, b ) \
        vlc_fourcc_to_char( (vlc_fourcc_t)(a), (char *)(b) )
#define vlc_gc_decref( a ) vlc_release( &(a)->vlc_gc_data )
#define vlc_gc_incref( a ) vlc_hold( &(a)->vlc_gc_data )
#define vlc_gc_init( a,b ) vlc_gc_init( &(a)->vlc_gc_data, (b) )
#define vlc_pgettext( ctx, id ) \
        vlc_pgettext_aux( ctx "\004" id, id )
#define vlc_priv( gc, t ) ((t *)(((char *)(gc)) - offsetof(t, vlc_gc_data)))
 #define vsnprintf       __mingw_vsnprintf
#define CAT_ADVANCED 6
#define CAT_AUDIO 2
#define CAT_INPUT 4
#define CAT_INTERFACE 1
#define CAT_OSD 8
#define CAT_PLAYLIST 7
#define CAT_SOUT 5
#define CAT_VIDEO 3
#define CONFIG_CATEGORY                     0x0006 
#define CONFIG_HINT                         0x000F
#define CONFIG_HINT_CATEGORY                0x0002  
#define CONFIG_HINT_SUBCATEGORY             0x0003  
#define CONFIG_HINT_SUBCATEGORY_END         0x0004  
#define CONFIG_HINT_USAGE                   0x0005  
#define CONFIG_ITEM                         0x00F0
#define CONFIG_ITEM_BOOL                    0x0050  
#define CONFIG_ITEM_DIRECTORY               0x0070  
#define CONFIG_ITEM_FLOAT                   0x0060  
#define CONFIG_ITEM_FONT                    0x00C0  
#define CONFIG_ITEM_INTEGER                 0x0040  
#define CONFIG_ITEM_KEY                     0x0080  
#define CONFIG_ITEM_LOADFILE                0x00E0  
#define CONFIG_ITEM_MODULE                  0x0030  
#define CONFIG_ITEM_MODULE_CAT              0x0090  
#define CONFIG_ITEM_MODULE_LIST             0x00A0  
#define CONFIG_ITEM_MODULE_LIST_CAT         0x00B0  
#define CONFIG_ITEM_PASSWORD                0x00D0  
#define CONFIG_ITEM_SAVEFILE                0x00F0  
#define CONFIG_ITEM_STRING                  0x0010  
#define CONFIG_SECTION                      0x0008 
#define CONFIG_SUBCATEGORY                  0x0007 
   #define SUBCAT_ADVANCED_CPU 601
   #define SUBCAT_ADVANCED_MISC 602
   #define SUBCAT_ADVANCED_NETWORK 603
   #define SUBCAT_ADVANCED_XML 604
   #define SUBCAT_AUDIO_AFILTER 203
   #define SUBCAT_AUDIO_AOUT 202
   #define SUBCAT_AUDIO_GENERAL 201
   #define SUBCAT_AUDIO_MISC 205
   #define SUBCAT_AUDIO_VISUAL 204
   #define SUBCAT_INPUT_ACCESS 402
   #define SUBCAT_INPUT_ACODEC 405
   #define SUBCAT_INPUT_DEMUX 403
   #define SUBCAT_INPUT_GENERAL 401
   #define SUBCAT_INPUT_SCODEC 406
   #define SUBCAT_INPUT_STREAM_FILTER 407
   #define SUBCAT_INPUT_VCODEC 404
   #define SUBCAT_INTERFACE_CONTROL 103
   #define SUBCAT_INTERFACE_GENERAL 101
   #define SUBCAT_INTERFACE_HOTKEYS 104
   #define SUBCAT_INTERFACE_MAIN 102
   #define SUBCAT_OSD_IMPORT 801
   #define SUBCAT_PLAYLIST_EXPORT 703
   #define SUBCAT_PLAYLIST_GENERAL 701
   #define SUBCAT_PLAYLIST_SD 702
   #define SUBCAT_SOUT_ACO 504
   #define SUBCAT_SOUT_GENERAL 501
   #define SUBCAT_SOUT_MUX 503
   #define SUBCAT_SOUT_PACKETIZER 505
   #define SUBCAT_SOUT_SAP 506
   #define SUBCAT_SOUT_STREAM 502
   #define SUBCAT_SOUT_VOD 507
   #define SUBCAT_VIDEO_GENERAL 301
   #define SUBCAT_VIDEO_SUBPIC 305
   #define SUBCAT_VIDEO_TEXT 304
   #define SUBCAT_VIDEO_VFILTER 303
   #define SUBCAT_VIDEO_VFILTER2 306
   #define SUBCAT_VIDEO_VOUT 302
#define VLC_CONFIGURATION_H 1
#define config_AddIntf(a,b) config_AddIntf(VLC_OBJECT(a),b)
#define config_ChainParse( a, b, c, d ) config_ChainParse( VLC_OBJECT(a), b, c, d )
#define config_ExistIntf(a,b) config_ExistIntf(VLC_OBJECT(a),b)
#define config_GetDataDir(a) config_GetDataDir(VLC_OBJECT(a))
#define config_GetFloat(a,b) config_GetFloat(VLC_OBJECT(a),b)
#define config_GetInt(a,b) config_GetInt(VLC_OBJECT(a),b)
#define config_GetPsz(a,b) config_GetPsz(VLC_OBJECT(a),b)
#define config_GetType(a,b) config_GetType(VLC_OBJECT(a),b)
#define config_PutFloat(a,b,c) config_PutFloat(VLC_OBJECT(a),b,c)
#define config_PutInt(a,b,c) config_PutInt(VLC_OBJECT(a),b,c)
#define config_PutPsz(a,b,c) config_PutPsz(VLC_OBJECT(a),b,c)
#define config_RemoveIntf(a,b) config_RemoveIntf(VLC_OBJECT(a),b)
#define config_ResetAll(a) config_ResetAll(VLC_OBJECT(a))
#define config_SaveConfigFile(a,b) config_SaveConfigFile(VLC_OBJECT(a),b)
#define VLC_VARIABLES_H 1
#define VLC_VAR_ADDCHOICE           0x0020
#define VLC_VAR_CHOICESCOUNT        0x0026
#define VLC_VAR_CLASS     0x00f0
#define VLC_VAR_CLEARCHOICES        0x0022
#define VLC_VAR_DELCHOICE           0x0021
#define VLC_VAR_DOINHERIT 0x8000
#define VLC_VAR_FLAGS     0xff00
#define VLC_VAR_GETCHOICES          0x0024
#define VLC_VAR_GETLIST             0x0025
#define VLC_VAR_GETMAX              0x0017
#define VLC_VAR_GETMIN              0x0016
#define VLC_VAR_GETSTEP             0x0018
#define VLC_VAR_GETTEXT             0x0015
#define VLC_VAR_HASCHOICE 0x0100
#define VLC_VAR_HASMAX    0x0400
#define VLC_VAR_HASMIN    0x0200
#define VLC_VAR_HASSTEP   0x0800
#define VLC_VAR_ISCOMMAND 0x2000
#define VLC_VAR_SETDEFAULT          0x0023
#define VLC_VAR_SETISCOMMAND        0x0040
#define VLC_VAR_SETMAX              0x0011
#define VLC_VAR_SETMIN              0x0010
#define VLC_VAR_SETSTEP             0x0012
#define VLC_VAR_SETTEXT             0x0014
#define VLC_VAR_SETVALUE            0x0013
#define VLC_VAR_TYPE      0x00ff
#define var_AddCallback(a,b,c,d) var_AddCallback( VLC_OBJECT(a), b, c, d )
#define var_Change(a,b,c,d,e) var_Change( VLC_OBJECT(a), b, c, d, e )
#define var_Command(a,b,c,d,e) var_Command( VLC_OBJECT( a ), b, c, d, e )
#define var_CountChoices(a,b) var_CountChoices( VLC_OBJECT(a),b)
#define var_Create(a,b,c) var_Create( VLC_OBJECT(a), b, c )
#define var_CreateGetAddress(a,b)  var_CreateGetAddress( VLC_OBJECT(a),b)
#define var_CreateGetBool(a,b)   var_CreateGetBool( VLC_OBJECT(a),b)
#define var_CreateGetBoolCommand(a,b)   var_CreateGetBoolCommand( VLC_OBJECT(a),b)
#define var_CreateGetFloat(a,b)   var_CreateGetFloat( VLC_OBJECT(a),b)
#define var_CreateGetFloatCommand(a,b)   var_CreateGetFloatCommand( VLC_OBJECT(a),b)
#define var_CreateGetInteger(a,b)   var_CreateGetInteger( VLC_OBJECT(a),b)
#define var_CreateGetIntegerCommand(a,b)   var_CreateGetIntegerCommand( VLC_OBJECT(a),b)
#define var_CreateGetNonEmptyString(a,b)   var_CreateGetNonEmptyString( VLC_OBJECT(a),b)
#define var_CreateGetNonEmptyStringCommand(a,b)   var_CreateGetNonEmptyStringCommand( VLC_OBJECT(a),b)
#define var_CreateGetString(a,b)   var_CreateGetString( VLC_OBJECT(a),b)
#define var_CreateGetStringCommand(a,b)   var_CreateGetStringCommand( VLC_OBJECT(a),b)
#define var_CreateGetTime(a,b)   var_CreateGetTime( VLC_OBJECT(a),b)
#define var_CreateGetTimeCommand(a,b)   var_CreateGetTimeCommand( VLC_OBJECT(a),b)
#define var_DecInteger(a,b) var_DecInteger( VLC_OBJECT(a), b )
#define var_DelCallback(a,b,c,d) var_DelCallback( VLC_OBJECT(a), b, c, d )
#define var_Destroy(a,b) var_Destroy( VLC_OBJECT(a), b )
#define var_Get(a,b,c) var_Get( VLC_OBJECT(a), b, c )
#define var_GetAddress(a,b)  var_GetAddress( VLC_OBJECT(a),b)
#define var_GetBool(a,b)   var_GetBool( VLC_OBJECT(a),b)
#define var_GetChecked(o,n,t,v) var_GetChecked(VLC_OBJECT(o),n,t,v)
#define var_GetCoords(o,n,x,y) var_GetCoords(VLC_OBJECT(o),n,x,y)
#define var_GetFloat(a,b)   var_GetFloat( VLC_OBJECT(a),b)
#define var_GetInteger(a,b)   var_GetInteger( VLC_OBJECT(a),b)
#define var_GetNonEmptyString(a,b)   var_GetNonEmptyString( VLC_OBJECT(a),b)
#define var_GetString(a,b)   var_GetString( VLC_OBJECT(a),b)
#define var_GetTime(a,b)   var_GetTime( VLC_OBJECT(a),b)
#define var_IncInteger(a,b) var_IncInteger( VLC_OBJECT(a), b )
#define var_InheritAddress(o, n) var_InheritAddress(VLC_OBJECT(o), n)
#define var_InheritBool(o, n) var_InheritBool(VLC_OBJECT(o), n)
#define var_InheritFloat(o, n) var_InheritFloat(VLC_OBJECT(o), n)
#define var_InheritInteger(o, n) var_InheritInteger(VLC_OBJECT(o), n)
#define var_InheritString(o, n) var_InheritString(VLC_OBJECT(o), n)
#define var_InheritTime(o, n) var_InheritTime(VLC_OBJECT(o), n)
#define var_InheritURational(a,b,c,d) var_InheritURational(VLC_OBJECT(a), b, c, d)
#define var_NAndInteger(a,b,c) var_NAndInteger(VLC_OBJECT(a),b,c)
#define var_OrInteger(a,b,c) var_OrInteger(VLC_OBJECT(a),b,c)
#define var_Set(a,b,c) var_Set( VLC_OBJECT(a), b, c )
#define var_SetAddress(o, n, p) var_SetAddress(VLC_OBJECT(o), n, p)
#define var_SetBool(a,b,c)      var_SetBool( VLC_OBJECT(a),b,c)
#define var_SetChecked(o,n,t,v) var_SetChecked(VLC_OBJECT(o),n,t,v)
#define var_SetCoords(o,n,x,y) var_SetCoords(VLC_OBJECT(o),n,x,y)
#define var_SetFloat(a,b,c)     var_SetFloat( VLC_OBJECT(a),b,c)
#define var_SetInteger(a,b,c)   var_SetInteger( VLC_OBJECT(a),b,c)
#define var_SetString(a,b,c)    var_SetString( VLC_OBJECT(a),b,c)
#define var_SetTime(a,b,c)      var_SetTime( VLC_OBJECT(a),b,c)
#define var_ToggleBool(a,b) var_ToggleBool( VLC_OBJECT(a),b )
#define var_TriggerCallback(a,b) var_TriggerCallback( VLC_OBJECT(a), b )
#define var_Type(a,b) var_Type( VLC_OBJECT(a), b )
#define FIND_ANYWHERE       0x0003
#define FIND_CHILD          0x0002
#define FIND_PARENT         0x0001
#define OBJECT_FLAGS_NODBG       0x0001
#define OBJECT_FLAGS_NOINTERACT  0x0004
#define OBJECT_FLAGS_QUIET       0x0002
#define VLC_OBJECT_AOUT        (-10)
#define VLC_OBJECT_DECODER     (-8)
#define VLC_OBJECT_GENERIC     (-666)
#define VLC_OBJECT_INPUT       (-7)
#define VLC_OBJECT_VOUT        (-9)
#define vlc_list_children(a) \
    vlc_list_children( VLC_OBJECT(a) )
#define vlc_object_alive(a) vlc_object_alive( VLC_OBJECT(a) )
#define vlc_object_attach(a,b) \
    vlc_object_attach( VLC_OBJECT(a), VLC_OBJECT(b) )
#define vlc_object_create(a,b) vlc_object_create( VLC_OBJECT(a), b )
#define vlc_object_find(a,b,c) \
    vlc_object_find( VLC_OBJECT(a),b,c)
#define vlc_object_find_name(a,b,c) \
    vlc_object_find_name( VLC_OBJECT(a),b,c)
#define vlc_object_get_name(o) vlc_object_get_name(VLC_OBJECT(o))
#define vlc_object_hold(a) \
    vlc_object_hold( VLC_OBJECT(a) )
#define vlc_object_kill(a) \
    vlc_object_kill( VLC_OBJECT(a) )
#define vlc_object_release(a) \
    vlc_object_release( VLC_OBJECT(a) )
#define vlc_object_set_destructor(a,b) \
    vlc_object_set_destructor( VLC_OBJECT(a), b )

#define VLC_MSG_DBG   3
#define VLC_MSG_ERR   1
#define VLC_MSG_INFO  0
#define VLC_MSG_WARN  2
#define msg_Dbg( p_this, ... ) \
        msg_Generic( VLC_OBJECT(p_this), VLC_MSG_DBG, \
                     MODULE_STRING, __VA_ARGS__ )
#define msg_DisableObjectPrinting(a,b) msg_DisableObjectPrinting(VLC_OBJECT(a),b)
#define msg_EnableObjectPrinting(a,b) msg_EnableObjectPrinting(VLC_OBJECT(a),b)
#define msg_Err( p_this, ... ) \
        msg_Generic( VLC_OBJECT(p_this), VLC_MSG_ERR, \
                     MODULE_STRING, __VA_ARGS__ )
#define msg_GenericVa(a, b, c, d, e) msg_GenericVa(VLC_OBJECT(a), b, c, d, e)
#define msg_Info( p_this, ... ) \
        msg_Generic( VLC_OBJECT(p_this), VLC_MSG_INFO, \
                     MODULE_STRING, __VA_ARGS__ )
#define msg_Warn( p_this, ... ) \
        msg_Generic( VLC_OBJECT(p_this), VLC_MSG_WARN, \
                     MODULE_STRING, __VA_ARGS__ )
#define stats_TimerClean(a,b) stats_TimerClean( VLC_OBJECT(a), b )
#define stats_TimerDump(a,b) stats_TimerDump( VLC_OBJECT(a), b )
#define stats_TimerStart(a,b,c) stats_TimerStart( VLC_OBJECT(a), b,c )
#define stats_TimerStop(a,b) stats_TimerStop( VLC_OBJECT(a), b )
#define stats_TimersCleanAll(a) stats_TimersCleanAll( VLC_OBJECT(a) )
#define stats_TimersDumpAll(a) stats_TimersDumpAll( VLC_OBJECT(a) )
#define ARRAY_APPEND(array, elem)                                           \
  do {                                                                      \
    _ARRAY_GROW1(array);                                                    \
    (array).p_elems[(array).i_size] = elem;                                 \
    (array).i_size++;                                                       \
  } while(0)
#define ARRAY_BSEARCH(array, elem, zetype, key, answer) \
    BSEARCH( (array).p_elems, (array).i_size, elem, zetype, key, answer)
#define ARRAY_INIT(array)                                                   \
  do {                                                                      \
    (array).i_alloc = 0;                                                    \
    (array).i_size = 0;                                                     \
    (array).p_elems = NULL;                                                 \
  } while(0)
#define ARRAY_INSERT(array,elem,pos)                                        \
  do {                                                                      \
    _ARRAY_GROW1(array);                                                    \
    if( (array).i_size - pos ) {                                            \
        memmove( (array).p_elems + pos + 1, (array).p_elems + pos,          \
                 ((array).i_size-pos) * sizeof(*(array).p_elems) );         \
    }                                                                       \
    (array).p_elems[pos] = elem;                                            \
    (array).i_size++;                                                       \
  } while(0)
#define ARRAY_REMOVE(array,pos)                                             \
  do {                                                                      \
    if( (array).i_size - (pos) - 1 )                                        \
    {                                                                       \
        memmove( (array).p_elems + pos, (array).p_elems + pos + 1,          \
                 ( (array).i_size - pos - 1 ) *sizeof(*(array).p_elems) );  \
    }                                                                       \
    (array).i_size--;                                                       \
    _ARRAY_SHRINK(array);                                                   \
  } while(0)
#define ARRAY_RESET(array)                                                  \
  do {                                                                      \
    (array).i_alloc = 0;                                                    \
    (array).i_size = 0;                                                     \
    free( (array).p_elems ); (array).p_elems = NULL;                        \
  } while(0)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ARRAY_VAL(array, pos) array.p_elems[pos]
#define BSEARCH( entries, count, elem, zetype, key, answer ) \
   do {  \
    int low = 0, high = count - 1;   \
    answer = -1; \
    while( low <= high ) {\
        int mid = (low + high ) / 2;  \
        zetype mid_val = entries[mid] elem;\
        if( mid_val < key ) \
            low = mid + 1; \
        else if ( mid_val > key ) \
            high = mid -1;  \
        else    \
        {   \
            answer = mid;  break;   \
        }\
    } \
 } while(0)
#define DECL_ARRAY(type) struct {                                           \
    int i_alloc;                                                            \
    int i_size;                                                             \
    type *p_elems;                                                          \
}
#define FOREACH_ARRAY( item, array ) { \
    int fe_idx; \
    for( fe_idx = 0 ; fe_idx < (array).i_size ; fe_idx++ ) \
    { \
        item = (array).p_elems[fe_idx];
#define FOREACH_END() } }
#define INSERT_ELEM( p_ar, i_oldsize, i_pos, elem )                           \
    do                                                                        \
    {                                                                         \
        if( !(i_oldsize) ) (p_ar) = NULL;                                       \
        (p_ar) = VLCCVP realloc( p_ar, ((i_oldsize) + 1) * sizeof(*(p_ar)) ); \
        if( !(p_ar) ) abort();                                                \
        if( (i_oldsize) - (i_pos) )                                           \
        {                                                                     \
            memmove( (p_ar) + (i_pos) + 1, (p_ar) + (i_pos),                  \
                     ((i_oldsize) - (i_pos)) * sizeof( *(p_ar) ) );           \
        }                                                                     \
        (p_ar)[(i_pos)] = elem;                                                 \
        (i_oldsize)++;                                                        \
    }                                                                         \
    while( 0 )
#define REMOVE_ELEM( p_ar, i_size, i_pos )                                    \
    do                                                                        \
    {                                                                         \
        if( (i_size) - (i_pos) - 1 )                                          \
        {                                                                     \
            memmove( (p_ar) + (i_pos),                                        \
                     (p_ar) + (i_pos) + 1,                                    \
                     ((i_size) - (i_pos) - 1) * sizeof( *(p_ar) ) );          \
        }                                                                     \
        if( i_size > 1 )                                                      \
            (p_ar) = realloc_down( p_ar, ((i_size) - 1) * sizeof( *(p_ar) ) );\
        else                                                                  \
        {                                                                     \
            free( p_ar );                                                     \
            (p_ar) = NULL;                                                    \
        }                                                                     \
        (i_size)--;                                                           \
    }                                                                         \
    while( 0 )
#define TAB_APPEND( count, tab, p )             \
    TAB_APPEND_CAST( , count, tab, p )
#define TAB_APPEND_CAST( cast, count, tab, p )             \
  do {                                          \
    if( (count) > 0 )                           \
        (tab) = cast realloc( tab, sizeof( void ** ) * ( (count) + 1 ) ); \
    else                                        \
        (tab) = cast malloc( sizeof( void ** ) );    \
    if( !(tab) ) abort();                       \
    (tab)[count] = (p);                         \
    (count)++;                                  \
  } while(0)
#define TAB_APPEND_CPP( type, count, tab, p )   \
    TAB_APPEND_CAST( (type**), count, tab, p )
#define TAB_CLEAN( count, tab )                 \
  do {                                          \
    free( tab );                                \
    (count)= 0;                                 \
    (tab)= NULL;                                \
  } while(0)
#define TAB_FIND( count, tab, p, index )        \
  do {                                          \
        int _i_;                                \
        (index) = -1;                           \
        for( _i_ = 0; _i_ < (count); _i_++ )    \
        {                                       \
            if( (tab)[_i_] == (p) )             \
            {                                   \
                (index) = _i_;                  \
                break;                          \
            }                                   \
        }                                       \
  } while(0)
#define TAB_INIT( count, tab )                  \
  do {                                          \
    (count) = 0;                                \
    (tab) = NULL;                               \
  } while(0)
#define TAB_INSERT( count, tab, p, index )      \
    TAB_INSERT_CAST( , count, tab, p, index )
#define TAB_INSERT_CAST( cast, count, tab, p, index ) do { \
    if( (count) > 0 )                           \
        (tab) = cast realloc( tab, sizeof( void ** ) * ( (count) + 1 ) ); \
    else                                        \
        (tab) = cast malloc( sizeof( void ** ) );       \
    if( !(tab) ) abort();                       \
    if( (count) - (index) > 0 )                 \
        memmove( (void**)(tab) + (index) + 1,   \
                 (void**)(tab) + (index),       \
                 ((count) - (index)) * sizeof(*(tab)) );\
    (tab)[(index)] = (p);                       \
    (count)++;                                  \
} while(0)
#define TAB_REMOVE( count, tab, p )             \
  do {                                          \
        int _i_index_;                          \
        TAB_FIND( count, tab, p, _i_index_ );   \
        if( _i_index_ >= 0 )                    \
        {                                       \
            if( (count) > 1 )                   \
            {                                   \
                memmove( ((void**)(tab) + _i_index_),    \
                         ((void**)(tab) + _i_index_+1),  \
                         ( (count) - _i_index_ - 1 ) * sizeof( void* ) );\
            }                                   \
            (count)--;                          \
            if( (count) == 0 )                  \
            {                                   \
                free( tab );                    \
                (tab) = NULL;                   \
            }                                   \
        }                                       \
  } while(0)
#define TYPEDEF_ARRAY(type, name) typedef DECL_ARRAY(type) name;
#   define VLCCVP (void**) 

#define _ARRAY_ALLOC(array, newsize) {                                      \
    (array).i_alloc = newsize;                                              \
    (array).p_elems = VLCCVP realloc( (array).p_elems, (array).i_alloc *    \
                                    sizeof(*(array).p_elems) );             \
    if( !(array).p_elems ) abort();                                         \
}
#define _ARRAY_GROW(array,additional) {                                     \
     int i_first = (array).i_alloc;                                         \
     while( (array).i_alloc - i_first < additional )                        \
     {                                                                      \
         if( (array).i_alloc < 10 )                                         \
            _ARRAY_ALLOC(array, 10 )                                        \
        else if( (array).i_alloc == (array).i_size )                        \
            _ARRAY_ALLOC(array, (int)((array).i_alloc * 1.5) )              \
        else break;                                                         \
     }                                                                      \
}
#define _ARRAY_GROW1(array) {                                               \
    if( (array).i_alloc < 10 )                                              \
        _ARRAY_ALLOC(array, 10 )                                            \
    else if( (array).i_alloc == (array).i_size )                            \
        _ARRAY_ALLOC(array, (int)(array.i_alloc * 1.5) )                    \
}
#define _ARRAY_SHRINK(array) {                                              \
    if( (array).i_size > 10 && (array).i_size < (int)((array).i_alloc / 1.5) ) {  \
        _ARRAY_ALLOC(array, (array).i_size + 5);                            \
    }                                                                       \
}
#  define ETIMEDOUT 10060 
#   define LIBVLC_USE_PTHREAD 1
#   define LIBVLC_USE_PTHREAD_CANCEL 1
#define VLC_STATIC_COND  PTHREAD_COND_INITIALIZER
#define VLC_STATIC_MUTEX PTHREAD_MUTEX_INITIALIZER

#   define VLC_THREAD_PRIORITY_AUDIO   22
#   define VLC_THREAD_PRIORITY_HIGHEST 22
#   define VLC_THREAD_PRIORITY_INPUT   22
#   define VLC_THREAD_PRIORITY_LOW      0
#   define VLC_THREAD_PRIORITY_OUTPUT  22
#   define VLC_THREAD_PRIORITY_VIDEO    0
#   define _APPLE_C_SOURCE    1 
#define mutex_cleanup_push( lock ) vlc_cleanup_push (vlc_cleanup_lock, lock)
# define vlc_cleanup_pop( ) pthread_cleanup_pop (0)
# define vlc_cleanup_push( routine, arg ) pthread_cleanup_push (routine, arg)
# define vlc_cleanup_run( ) pthread_cleanup_pop (1)
#define vlc_global_lock( n ) vlc_global_mutex( n, true )
#define vlc_global_unlock( n ) vlc_global_mutex( n, false )
# define vlc_spin_destroy vlc_mutex_destroy
# define vlc_spin_lock    vlc_mutex_lock
# define vlc_spin_unlock  vlc_mutex_unlock
#define vlc_thread_create( P_THIS, PSZ_NAME, FUNC, PRIORITY )         \
    vlc_thread_create( VLC_OBJECT(P_THIS), "__FILE__", "__LINE__", PSZ_NAME, FUNC, PRIORITY )
#define vlc_thread_join( P_THIS )                                           \
    vlc_thread_join( VLC_OBJECT(P_THIS) )
#define vlc_thread_set_priority( P_THIS, PRIORITY )                         \
    vlc_thread_set_priority( VLC_OBJECT(P_THIS), "__FILE__", "__LINE__", PRIORITY )
#define LAST_MDATE ((mtime_t)((uint64_t)(-1)/2))
#define MSTRTIME_MAX_SIZE 22
# define VLC_HARD_MIN_SLEEP 10000   
# define VLC_SOFT_MIN_SLEEP 9000000 
# define __VLC_MTIME_H 1
# define check_deadline( d ) \
    (__builtin_constant_p(d) ? impossible_deadline(d) : d)
# define check_delay(d) (d)
#define msleep(d) msleep(check_delay(d))
#define mwait(d) mwait(check_deadline(d))
#define AOUT_MAX_ADVANCE_TIME           (DEFAULT_PTS_DELAY * 5)
#define AOUT_MAX_FILTERS                10
#define AOUT_MAX_INPUTS                 5
#define AOUT_MAX_PREPARE_TIME           (CLOCK_FREQ/2)
#define AOUT_MAX_RESAMPLING             10
#define AOUT_MIN_PREPARE_TIME           (CLOCK_FREQ/25)
#define AOUT_PTS_TOLERANCE              (CLOCK_FREQ/25)
#define AOUT_VOLUME_DEFAULT             256
#define AOUT_VOLUME_MAX                 1024
#define AOUT_VOLUME_MIN                 0
#define AOUT_VOLUME_STEP                32
#define CLOCK_FREQ INT64_C(1000000)
#define DEFAULT_INPUT_ACTIVITY 1
#define DEFAULT_PTS_DELAY               (3*CLOCK_FREQ/10)
#define INPUT_FSTAT_NB_READS            16
#define INPUT_IDLE_SLEEP                (CLOCK_FREQ/10)
#define INTF_GAMMA_LIMIT                3
#define INTF_GAMMA_STEP                 .1
#define INTF_IDLE_SLEEP                 (CLOCK_FREQ/20)
#define INTF_MAX_MSG_SIZE               512
#define MAX_DUMPSTRUCTURE_DEPTH         100
#define SPU_MAX_PREPARE_TIME            (CLOCK_FREQ/2)
#define TRANSCODE_ACTIVITY 10
#define VLC_MSG_QSIZE                   256
#define VLC_TS_0 (1)
#define VLC_TS_INVALID (0)
#define VOUT_ASPECT_FACTOR              432000
#define VOUT_MAX_PLANES                 5
#define VOUT_MAX_WIDTH                  4096
#define VOUT_OUTMEM_SLEEP               (CLOCK_FREQ/50)
#define VOUT_TITLE                      "VLC"
#   define CDECL_SYMBOL            __cdecl
#define CONCATENATE( y, z ) CRUDE_HACK( y, z )
#define CRUDE_HACK( y, z )  y##__##z
#   define DLL_SYMBOL              __declspec(dllexport)
#   define EXTERN_SYMBOL           extern "C"
# define LIBVLC_MODULES_MACROS_H 1
# define MODULE_SUFFIX "__1_2_0f"
# define MODULE_SYMBOL 1_2_0f
# define VLC_COPYRIGHT_EXPORT VLC_META_EXPORT (copyright, \
    "\x43\x6f\x70\x79\x72\x69\x67\x68\x74\x20\x28\x43\x29\x20\x74\x68" \
    "\x65\x20\x56\x69\x64\x65\x6f\x4c\x41\x4e\x20\x56\x4c\x43\x20\x6d" \
    "\x65\x64\x69\x61\x20\x70\x6c\x61\x79\x65\x72\x20\x64\x65\x76\x65" \
    "\x6c\x6f\x70\x65\x72\x73" )
#define VLC_LICENSE_EXPORT VLC_META_EXPORT (license, \
    "\x4c\x69\x63\x65\x6e\x73\x65\x64\x20\x75\x6e\x64\x65\x72\x20\x74" \
    "\x68\x65\x20\x74\x65\x72\x6d\x73\x20\x6f\x66\x20\x74\x68\x65\x20" \
    "\x47\x4e\x55\x20\x47\x65\x6e\x65\x72\x61\x6c\x20\x50\x75\x62\x6c" \
    "\x69\x63\x20\x4c\x69\x63\x65\x6e\x73\x65\x2c\x20\x76\x65\x72\x73" \
    "\x69\x6f\x6e\x20\x32\x20\x6f\x72\x20\x6c\x61\x74\x65\x72\x2e" )
#define VLC_METADATA_EXPORTS \
    VLC_COPYRIGHT_EXPORT \
    VLC_LICENSE_EXPORT
#define VLC_META_EXPORT( name, value ) \
    EXTERN_SYMBOL DLL_SYMBOL const char * CDECL_SYMBOL \
    __VLC_SYMBOL(vlc_entry_ ## name) (void); \
    EXTERN_SYMBOL DLL_SYMBOL const char * CDECL_SYMBOL \
    __VLC_SYMBOL(vlc_entry_ ## name) (void) \
    { \
         return value; \
    }
#   define __VLC_SYMBOL( symbol  ) CONCATENATE( symbol, MODULE_SYMBOL )
#define add_bool( name, v, text, longtext, advc ) \
    add_typename_inner( CONFIG_ITEM_BOOL, name, text, longtext, advc ) \
    if (v) vlc_config_set (p_config, VLC_CONFIG_VALUE, (int64_t)true);
#define add_category_hint( text, longtext, advc ) \
    add_typeadv_inner( CONFIG_HINT_CATEGORY, text, longtext, advc )
#define add_deprecated_alias( name ) \
    vlc_config_set (p_config, VLC_CONFIG_OLDNAME, (const char *)(name));
#define add_directory( name, value, text, longtext, advc ) \
    add_string_inner( CONFIG_ITEM_DIRECTORY, name, text, longtext, advc, \
                      value )
#define add_float( name, v, text, longtext, advc ) \
    add_typename_inner( CONFIG_ITEM_FLOAT, name, text, longtext, advc ) \
    vlc_config_set (p_config, VLC_CONFIG_VALUE, (double)(v));
#define add_float_with_range( name, value, f_min, f_max, p_callback, text, longtext, advc ) \
    add_float( name, value, text, longtext, advc ) \
    change_float_range( f_min, f_max )
#define add_font( name, value, text, longtext, advc )\
    add_string_inner( CONFIG_ITEM_FONT, name, text, longtext, advc, \
                      value )
#define add_int_inner( type, name, text, longtext, advc, v ) \
    add_typename_inner( type, name, text, longtext, advc ) \
    vlc_config_set (p_config, VLC_CONFIG_VALUE, (int64_t)(v));
#define add_integer( name, value, text, longtext, advc ) \
    add_int_inner( CONFIG_ITEM_INTEGER, name, text, longtext, advc, value )
#define add_integer_with_range( name, value, i_min, i_max, p_callback, text, longtext, advc ) \
    add_integer( name, value, text, longtext, advc ) \
    change_integer_range( i_min, i_max )
#define add_key( name, value, text, longtext, advc ) \
    add_int_inner( CONFIG_ITEM_KEY, "global-" name, text, longtext, advc, \
                   KEY_UNSET ) \
    add_int_inner( CONFIG_ITEM_KEY, name, text, longtext, advc, value )
#define add_loadfile( name, value, text, longtext, advc ) \
    add_string_inner( CONFIG_ITEM_LOADFILE, name, text, longtext, advc, \
                      value )
#define add_module( name, psz_caps, value, p_callback, text, longtext, advc ) \
    add_string_inner( CONFIG_ITEM_MODULE, name, text, longtext, advc, \
                      value ) \
    vlc_config_set (p_config, VLC_CONFIG_CAPABILITY, (const char *)(psz_caps));
#define add_module_cat( name, i_subcategory, value, p_callback, text, longtext, advc ) \
    add_string_inner( CONFIG_ITEM_MODULE_CAT, name, text, longtext, advc, \
                      value ) \
    change_integer_range (i_subcategory , 0);
#define add_module_list( name, psz_caps, value, p_callback, text, longtext, advc ) \
    add_string_inner( CONFIG_ITEM_MODULE_LIST, name, text, longtext, advc, \
                      value ) \
    vlc_config_set (p_config, VLC_CONFIG_CAPABILITY, (const char *)(psz_caps));
#define add_module_list_cat( name, i_subcategory, value, p_callback, text, longtext, advc ) \
    add_string_inner( CONFIG_ITEM_MODULE_LIST_CAT, name, text, longtext, \
                      advc, value ) \
    change_integer_range (i_subcategory , 0);
#define add_obsolete_bool( name ) \
        add_obsolete_inner( name, CONFIG_ITEM_BOOL )
#define add_obsolete_float( name ) \
        add_obsolete_inner( name, CONFIG_ITEM_FLOAT )
#define add_obsolete_inner( name, type ) \
    add_type_inner( type ) \
    vlc_config_set (p_config, VLC_CONFIG_NAME, \
                    (const char *)(name)); \
    vlc_config_set (p_config, VLC_CONFIG_REMOVED);
#define add_obsolete_integer( name ) \
        add_obsolete_inner( name, CONFIG_ITEM_INTEGER )
#define add_obsolete_string( name ) \
        add_obsolete_inner( name, CONFIG_ITEM_STRING )
#define add_password( name, value, text, longtext, advc ) \
    add_string_inner( CONFIG_ITEM_PASSWORD, name, text, longtext, advc, \
                      value )
#define add_savefile( name, value, text, longtext, advc ) \
    add_string_inner( CONFIG_ITEM_SAVEFILE, name, text, longtext, advc, \
                      value )
#define add_shortcut( ... ) \
{ \
    const char *shortcuts[] = { __VA_ARGS__ }; \
    if (vlc_module_set (p_submodule, VLC_MODULE_SHORTCUT, \
                        sizeof(shortcuts)/sizeof(shortcuts[0]), shortcuts)) \
        goto error; \
}
#define add_string( name, value, text, longtext, advc ) \
    add_string_inner( CONFIG_ITEM_STRING, name, text, longtext, advc, \
                      value )
#define add_string_inner( type, name, text, longtext, advc, v ) \
    add_typename_inner( type, name, text, longtext, advc ) \
    vlc_config_set (p_config, VLC_CONFIG_VALUE, (const char *)(v));
#define add_subcategory_hint( text, longtext ) \
    add_typedesc_inner( CONFIG_HINT_SUBCATEGORY, text, longtext )
#define add_submodule( ) \
    if (vlc_plugin_set (p_module, NULL, VLC_SUBMODULE_CREATE, &p_submodule)) \
        goto error;
#define add_type_inner( type ) \
    vlc_plugin_set (p_module, NULL, VLC_CONFIG_CREATE, (type), &p_config);
#define add_typeadv_inner( type, text, longtext, advc ) \
    add_typedesc_inner( type, text, longtext ) \
    if (advc) vlc_config_set (p_config, VLC_CONFIG_ADVANCED);
#define add_typedesc_inner( type, text, longtext ) \
    add_type_inner( type ) \
    vlc_config_set (p_config, VLC_CONFIG_DESC, \
                    (const char *)(text), (const char *)(longtext));
#define add_typename_inner( type, name, text, longtext, advc ) \
    add_typeadv_inner( type, text, longtext, advc ) \
    vlc_config_set (p_config, VLC_CONFIG_NAME, \
                    (const char *)(name));
#define add_usage_hint( text ) \
    add_typedesc_inner( CONFIG_HINT_USAGE, text, NULL )
#define cannot_unload_broken_library( ) \
    if (vlc_module_set (p_submodule, VLC_MODULE_NO_UNLOAD)) \
        goto error;
#define change_action_add( pf_action, text ) \
    vlc_config_set (p_config, VLC_CONFIG_ADD_ACTION, \
                    (vlc_callback_t)(pf_action), (const char *)(text));
#define change_autosave() \
    vlc_config_set (p_config, VLC_CONFIG_PERSISTENT);
#define change_float_range( minv, maxv ) \
    vlc_config_set (p_config, VLC_CONFIG_RANGE, \
                    (double)(minv), (double)(maxv));
#define change_integer_list( list, list_text ) \
    vlc_config_set (p_config, VLC_CONFIG_LIST, \
                    (size_t)(sizeof (list) / sizeof (int)), \
                    (const int *)(list), \
                    (const char *const *)(list_text), \
                    (vlc_callback_t)(NULL));
#define change_integer_range( minv, maxv ) \
    vlc_config_set (p_config, VLC_CONFIG_RANGE, \
                    (int64_t)(minv), (int64_t)(maxv));
#define change_need_restart() \
    vlc_config_set (p_config, VLC_CONFIG_RESTART);
#define change_private() \
    vlc_config_set (p_config, VLC_CONFIG_PRIVATE);
#define change_safe() \
    vlc_config_set (p_config, VLC_CONFIG_SAFE);
#define change_short( ch ) \
    vlc_config_set (p_config, VLC_CONFIG_SHORTCUT, (int)(ch));
#define change_string_list( list, list_text, list_update_func ) \
    vlc_config_set (p_config, VLC_CONFIG_LIST, \
                    (size_t)(sizeof (list) / sizeof (char *)), \
                    (const char *const *)(list), \
                    (const char *const *)(list_text), \
                    (vlc_callback_t)(list_update_func));
#define change_volatile() \
    change_private() \
    vlc_config_set (p_config, VLC_CONFIG_VOLATILE);
#define end_subcategory_hint \
    add_type_inner( CONFIG_HINT_SUBCATEGORY_END )
#define set_callbacks( activate, deactivate ) \
    if (vlc_module_set (p_submodule, VLC_MODULE_CB_OPEN, activate) \
     || vlc_module_set (p_submodule, VLC_MODULE_CB_CLOSE, deactivate)) \
        goto error;
#define set_capability( cap, score ) \
    if (vlc_module_set (p_submodule, VLC_MODULE_CAPABILITY, \
                        (const char *)(cap)) \
     || vlc_module_set (p_submodule, VLC_MODULE_SCORE, (int)(score))) \
        goto error;
#define set_category( i_id ) \
    add_type_inner( CONFIG_CATEGORY ) \
    vlc_config_set (p_config, VLC_CONFIG_VALUE, (int64_t)(i_id));
#define set_description( desc ) \
    if (vlc_module_set (p_submodule, VLC_MODULE_DESCRIPTION, \
                        (const char *)(desc))) \
        goto error;
#define set_help( help ) \
    if (vlc_module_set (p_submodule, VLC_MODULE_HELP, \
                        (const char *)(help))) \
        goto error;
#define set_section( text, longtext ) \
    add_typedesc_inner( CONFIG_SECTION, text, longtext )
#define set_shortname( shortname ) \
    if (vlc_module_set (p_submodule, VLC_MODULE_SHORTNAME, \
                        (const char *)(shortname))) \
        goto error;
#define set_subcategory( i_id ) \
    add_type_inner( CONFIG_SUBCATEGORY ) \
    vlc_config_set (p_config, VLC_CONFIG_VALUE, (int64_t)(i_id));
#define set_text_domain( dom ) \
    if (vlc_module_set (p_module, VLC_MODULE_TEXTDOMAIN, (dom))) \
        goto error;
#define vlc_config_set( cfg, ... ) vlc_plugin_set (NULL, (cfg), __VA_ARGS__)
#define vlc_module_begin( )                                                   \
    EXTERN_SYMBOL DLL_SYMBOL int CDECL_SYMBOL                                 \
    __VLC_SYMBOL(vlc_entry) ( module_t *p_module );                           \
                                                                              \
    EXTERN_SYMBOL DLL_SYMBOL int CDECL_SYMBOL                                 \
    __VLC_SYMBOL(vlc_entry) ( module_t *p_module )                            \
    {                                                                         \
        module_config_t *p_config = NULL;                                     \
        if (vlc_module_set (p_module, VLC_MODULE_NAME,                        \
                            (const char *)(MODULE_STRING)))                   \
            goto error;                                                       \
        {                                                                     \
            module_t *p_submodule = p_module;
#define vlc_module_end( )                                                     \
        }                                                                     \
        (void)p_config;                                                       \
        return VLC_SUCCESS;                                                   \
                                                                              \
    error:                                                                    \
        return VLC_EGENERIC;                                                  \
    }                                                                         \
    VLC_METADATA_EXPORTS
#define vlc_module_set( mod, ... ) vlc_plugin_set ((mod), NULL, __VA_ARGS__)
