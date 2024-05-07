





#include<sys/sysctl.h>

























#include<linux/time.h>




#include<sys/select.h>



#include<linux/types.h>




#include<sys/signal.h>

#include<sys/uio.h>
#include<sys/time.h>








#include<sys/resource.h>

#include<net/if.h>

#include<sys/file.h>
#include<sys/queue.h>

#include<sys/socket.h>


#include<sys/param.h>
#include<linux/videodev2.h>
#include<sys/types.h>














#include<sys/cdefs.h>

#include<sys/fcntl.h>
#include<sys/ucontext.h>


#include<linux/ioctl.h>












#define SG_MAX_SENSE 16

#define V4L2_BUF_FLAG_INPUT     0x0200  
#define V4L2_CAP_ASYNCIO                0x02000000  
#define V4L2_CAP_READWRITE              0x01000000  
#define V4L2_CAP_STREAMING              0x04000000  
#define V4L2_CHIP_MATCH_AC97       3  
#define V4L2_CHIP_MATCH_HOST       0  
#define V4L2_CHIP_MATCH_I2C_ADDR   2  
#define V4L2_CHIP_MATCH_I2C_DRIVER 1  
#define V4L2_CID_BACKLIGHT_COMPENSATION 	(V4L2_CID_BASE+28)
#define V4L2_CID_CAMERA_CLASS 		(V4L2_CTRL_CLASS_CAMERA | 1)
#define V4L2_CID_CAMERA_CLASS_BASE 	(V4L2_CTRL_CLASS_CAMERA | 0x900)
#define V4L2_CID_CHROMA_AGC                     (V4L2_CID_BASE+29)
#define V4L2_CID_COLOR_KILLER                   (V4L2_CID_BASE+30)
#define V4L2_CID_LASTP1                         (V4L2_CID_BASE+36)
#define V4L2_CID_MPEG_AUDIO_CRC 		(V4L2_CID_MPEG_BASE+108)
#define V4L2_CID_MPEG_AUDIO_EMPHASIS 		(V4L2_CID_MPEG_BASE+107)
#define V4L2_CID_MPEG_AUDIO_ENCODING 		(V4L2_CID_MPEG_BASE+101)
#define V4L2_CID_MPEG_AUDIO_L1_BITRATE 		(V4L2_CID_MPEG_BASE+102)
#define V4L2_CID_MPEG_AUDIO_L2_BITRATE 		(V4L2_CID_MPEG_BASE+103)
#define V4L2_CID_MPEG_AUDIO_L3_BITRATE 		(V4L2_CID_MPEG_BASE+104)
#define V4L2_CID_MPEG_AUDIO_MODE 		(V4L2_CID_MPEG_BASE+105)
#define V4L2_CID_MPEG_AUDIO_MODE_EXTENSION 	(V4L2_CID_MPEG_BASE+106)
#define V4L2_CID_MPEG_AUDIO_MUTE 		(V4L2_CID_MPEG_BASE+109)
#define V4L2_CID_MPEG_AUDIO_SAMPLING_FREQ 	(V4L2_CID_MPEG_BASE+100)
#define V4L2_CID_MPEG_BASE 			(V4L2_CTRL_CLASS_MPEG | 0x900)
#define V4L2_CID_MPEG_CLASS 			(V4L2_CTRL_CLASS_MPEG | 1)
#define V4L2_CID_MPEG_CX2341X_BASE 				(V4L2_CTRL_CLASS_MPEG | 0x1000)
#define V4L2_CID_MPEG_CX2341X_STREAM_INSERT_NAV_PACKETS 	(V4L2_CID_MPEG_CX2341X_BASE+11)
#define V4L2_CID_MPEG_CX2341X_VIDEO_CHROMA_MEDIAN_FILTER_TOP 	(V4L2_CID_MPEG_CX2341X_BASE+10)
#define V4L2_CID_MPEG_CX2341X_VIDEO_CHROMA_SPATIAL_FILTER_TYPE 	(V4L2_CID_MPEG_CX2341X_BASE+3)
#define V4L2_CID_MPEG_CX2341X_VIDEO_LUMA_MEDIAN_FILTER_BOTTOM 	(V4L2_CID_MPEG_CX2341X_BASE+7)
#define V4L2_CID_MPEG_CX2341X_VIDEO_LUMA_MEDIAN_FILTER_TOP 	(V4L2_CID_MPEG_CX2341X_BASE+8)
#define V4L2_CID_MPEG_CX2341X_VIDEO_LUMA_SPATIAL_FILTER_TYPE 	(V4L2_CID_MPEG_CX2341X_BASE+2)
#define V4L2_CID_MPEG_CX2341X_VIDEO_MEDIAN_FILTER_TYPE 		(V4L2_CID_MPEG_CX2341X_BASE+6)
#define V4L2_CID_MPEG_CX2341X_VIDEO_SPATIAL_FILTER 		(V4L2_CID_MPEG_CX2341X_BASE+1)
#define V4L2_CID_MPEG_CX2341X_VIDEO_SPATIAL_FILTER_MODE 	(V4L2_CID_MPEG_CX2341X_BASE+0)
#define V4L2_CID_MPEG_CX2341X_VIDEO_TEMPORAL_FILTER 		(V4L2_CID_MPEG_CX2341X_BASE+5)
#define V4L2_CID_MPEG_CX2341X_VIDEO_TEMPORAL_FILTER_MODE 	(V4L2_CID_MPEG_CX2341X_BASE+4)
#define V4L2_CID_MPEG_STREAM_PES_ID_AUDIO 	(V4L2_CID_MPEG_BASE+5)
#define V4L2_CID_MPEG_STREAM_PES_ID_VIDEO 	(V4L2_CID_MPEG_BASE+6)
#define V4L2_CID_MPEG_STREAM_PID_AUDIO 		(V4L2_CID_MPEG_BASE+2)
#define V4L2_CID_MPEG_STREAM_PID_PCR 		(V4L2_CID_MPEG_BASE+4)
#define V4L2_CID_MPEG_STREAM_PID_PMT 		(V4L2_CID_MPEG_BASE+1)
#define V4L2_CID_MPEG_STREAM_PID_VIDEO 		(V4L2_CID_MPEG_BASE+3)
#define V4L2_CID_MPEG_STREAM_TYPE 		(V4L2_CID_MPEG_BASE+0)
#define V4L2_CID_MPEG_STREAM_VBI_FMT 		(V4L2_CID_MPEG_BASE+7)
#define V4L2_CID_MPEG_VIDEO_ASPECT 		(V4L2_CID_MPEG_BASE+201)
#define V4L2_CID_MPEG_VIDEO_BITRATE 		(V4L2_CID_MPEG_BASE+207)
#define V4L2_CID_MPEG_VIDEO_BITRATE_MODE 	(V4L2_CID_MPEG_BASE+206)
#define V4L2_CID_MPEG_VIDEO_BITRATE_PEAK 	(V4L2_CID_MPEG_BASE+208)
#define V4L2_CID_MPEG_VIDEO_B_FRAMES 		(V4L2_CID_MPEG_BASE+202)
#define V4L2_CID_MPEG_VIDEO_ENCODING 		(V4L2_CID_MPEG_BASE+200)
#define V4L2_CID_MPEG_VIDEO_GOP_CLOSURE 	(V4L2_CID_MPEG_BASE+204)
#define V4L2_CID_MPEG_VIDEO_GOP_SIZE 		(V4L2_CID_MPEG_BASE+203)
#define V4L2_CID_MPEG_VIDEO_MUTE 		(V4L2_CID_MPEG_BASE+210)
#define V4L2_CID_MPEG_VIDEO_MUTE_YUV 		(V4L2_CID_MPEG_BASE+211)
#define V4L2_CID_MPEG_VIDEO_PULLDOWN 		(V4L2_CID_MPEG_BASE+205)
#define V4L2_CID_MPEG_VIDEO_TEMPORAL_DECIMATION (V4L2_CID_MPEG_BASE+209)
#define V4L2_CID_USER_BASE 		V4L2_CID_BASE
#define V4L2_CID_USER_CLASS 		(V4L2_CTRL_CLASS_USER | 1)
#define V4L2_CTRL_CLASS_CAMERA 0x009a0000	
#define V4L2_CTRL_CLASS_FM_TX 0x009b0000	
#define V4L2_CTRL_CLASS_MPEG 0x00990000	
#define V4L2_CTRL_CLASS_USER 0x00980000	
#define V4L2_CTRL_DRIVER_PRIV(id) (((id) & 0xffff) >= 0x1000)
#define V4L2_CTRL_FLAG_INACTIVE 	0x0010
#define V4L2_CTRL_FLAG_READ_ONLY 	0x0004
#define V4L2_CTRL_FLAG_SLIDER 		0x0020
#define V4L2_CTRL_FLAG_UPDATE 		0x0008
#define V4L2_CTRL_FLAG_WRITE_ONLY 	0x0040
#define V4L2_CTRL_ID2CLASS(id)    ((id) & 0x0fff0000UL)
#define V4L2_CTRL_ID_MASK      	  (0x0fffffff)
#define V4L2_ENC_CMD_PAUSE      (2)
#define V4L2_ENC_CMD_RESUME     (3)
#define V4L2_ENC_CMD_START      (0)
#define V4L2_ENC_CMD_STOP       (1)
#define V4L2_ENC_CMD_STOP_AT_GOP_END    (1 << 0)
#define V4L2_ENC_IDX_ENTRIES (64)
#define V4L2_ENC_IDX_FRAME_B    (2)
#define V4L2_ENC_IDX_FRAME_I    (0)
#define V4L2_ENC_IDX_FRAME_MASK (0xf)
#define V4L2_ENC_IDX_FRAME_P    (1)
#define V4L2_FBUF_CAP_LIST_CLIPPING     0x0004
#define V4L2_FIELD_HAS_BOTH(field)	\
	((field) == V4L2_FIELD_INTERLACED ||\
	 (field) == V4L2_FIELD_INTERLACED_TB ||\
	 (field) == V4L2_FIELD_INTERLACED_BT ||\
	 (field) == V4L2_FIELD_SEQ_TB ||\
	 (field) == V4L2_FIELD_SEQ_BT)
#define V4L2_FIELD_HAS_BOTTOM(field)	\
	((field) == V4L2_FIELD_BOTTOM 	||\
	 (field) == V4L2_FIELD_INTERLACED ||\
	 (field) == V4L2_FIELD_INTERLACED_TB ||\
	 (field) == V4L2_FIELD_INTERLACED_BT ||\
	 (field) == V4L2_FIELD_SEQ_TB	||\
	 (field) == V4L2_FIELD_SEQ_BT)
#define V4L2_FIELD_HAS_TOP(field)	\
	((field) == V4L2_FIELD_TOP 	||\
	 (field) == V4L2_FIELD_INTERLACED ||\
	 (field) == V4L2_FIELD_INTERLACED_TB ||\
	 (field) == V4L2_FIELD_INTERLACED_BT ||\
	 (field) == V4L2_FIELD_SEQ_TB	||\
	 (field) == V4L2_FIELD_SEQ_BT)
#define V4L2_FMT_FLAG_COMPRESSED 0x0001
#define V4L2_FMT_FLAG_EMULATED   0x0002
#define V4L2_IN_ST_COLOR_KILL  0x00000200  
#define V4L2_IN_ST_HFLIP       0x00000010 
#define V4L2_IN_ST_MACROVISION 0x01000000  
#define V4L2_IN_ST_NO_ACCESS   0x02000000  
#define V4L2_IN_ST_NO_CARRIER  0x00040000  
#define V4L2_IN_ST_NO_COLOR    0x00000004
#define V4L2_IN_ST_NO_EQU      0x00020000  
#define V4L2_IN_ST_NO_H_LOCK   0x00000100  
#define V4L2_IN_ST_NO_POWER    0x00000001  
#define V4L2_IN_ST_NO_SIGNAL   0x00000002
#define V4L2_IN_ST_NO_SYNC     0x00010000  
#define V4L2_IN_ST_VFLIP       0x00000020 
#define V4L2_IN_ST_VTR         0x04000000  
#define V4L2_JPEG_MARKER_APP (1<<7)    
#define V4L2_JPEG_MARKER_COM (1<<6)    
#define V4L2_JPEG_MARKER_DHT (1<<3)    
#define V4L2_JPEG_MARKER_DQT (1<<4)    
#define V4L2_JPEG_MARKER_DRI (1<<5)    
#define V4L2_MPEG_VBI_IVTV_CAPTION_525    (4)
#define V4L2_MPEG_VBI_IVTV_TELETEXT_B     (1)
#define V4L2_MPEG_VBI_IVTV_VPS            (7)
#define V4L2_MPEG_VBI_IVTV_WSS_625        (5)
#define V4L2_PIX_FMT_BGR24   v4l2_fourcc('B', 'G', 'R', '3') 
#define V4L2_PIX_FMT_BGR32   v4l2_fourcc('B', 'G', 'R', '4') 
#define V4L2_PIX_FMT_CPIA1    v4l2_fourcc('C', 'P', 'I', 'A') 
#define V4L2_PIX_FMT_DV       v4l2_fourcc('d', 'v', 's', 'd') 
#define V4L2_PIX_FMT_ET61X251 v4l2_fourcc('E', '6', '2', '5') 
#define V4L2_PIX_FMT_GREY    v4l2_fourcc('G', 'R', 'E', 'Y') 
#define V4L2_PIX_FMT_HI240   v4l2_fourcc('H', 'I', '2', '4') 
#define V4L2_PIX_FMT_HM12    v4l2_fourcc('H', 'M', '1', '2') 
#define V4L2_PIX_FMT_JPEG     v4l2_fourcc('J', 'P', 'E', 'G') 
#define V4L2_PIX_FMT_MJPEG    v4l2_fourcc('M', 'J', 'P', 'G') 
#define V4L2_PIX_FMT_MPEG     v4l2_fourcc('M', 'P', 'E', 'G') 
#define V4L2_PIX_FMT_MR97310A v4l2_fourcc('M', '3', '1', '0') 
#define V4L2_PIX_FMT_NV12    v4l2_fourcc('N', 'V', '1', '2') 
#define V4L2_PIX_FMT_NV16    v4l2_fourcc('N', 'V', '1', '6') 
#define V4L2_PIX_FMT_NV21    v4l2_fourcc('N', 'V', '2', '1') 
#define V4L2_PIX_FMT_NV61    v4l2_fourcc('N', 'V', '6', '1') 
#define V4L2_PIX_FMT_OV511    v4l2_fourcc('O', '5', '1', '1') 
#define V4L2_PIX_FMT_OV518    v4l2_fourcc('O', '5', '1', '8') 
#define V4L2_PIX_FMT_PAC207   v4l2_fourcc('P', '2', '0', '7') 
#define V4L2_PIX_FMT_PAL8    v4l2_fourcc('P', 'A', 'L', '8') 
#define V4L2_PIX_FMT_PJPG     v4l2_fourcc('P', 'J', 'P', 'G') 
#define V4L2_PIX_FMT_PWC1     v4l2_fourcc('P', 'W', 'C', '1') 
#define V4L2_PIX_FMT_PWC2     v4l2_fourcc('P', 'W', 'C', '2') 
#define V4L2_PIX_FMT_RGB24   v4l2_fourcc('R', 'G', 'B', '3') 
#define V4L2_PIX_FMT_RGB32   v4l2_fourcc('R', 'G', 'B', '4') 
#define V4L2_PIX_FMT_RGB332  v4l2_fourcc('R', 'G', 'B', '1') 
#define V4L2_PIX_FMT_RGB444  v4l2_fourcc('R', '4', '4', '4') 
#define V4L2_PIX_FMT_RGB555  v4l2_fourcc('R', 'G', 'B', 'O') 
#define V4L2_PIX_FMT_RGB555X v4l2_fourcc('R', 'G', 'B', 'Q') 
#define V4L2_PIX_FMT_RGB565  v4l2_fourcc('R', 'G', 'B', 'P') 
#define V4L2_PIX_FMT_RGB565X v4l2_fourcc('R', 'G', 'B', 'R') 
#define V4L2_PIX_FMT_SBGGR10 v4l2_fourcc('B', 'G', '1', '0') 
#define V4L2_PIX_FMT_SBGGR16 v4l2_fourcc('B', 'Y', 'R', '2') 
#define V4L2_PIX_FMT_SBGGR8  v4l2_fourcc('B', 'A', '8', '1') 
#define V4L2_PIX_FMT_SGBRG10 v4l2_fourcc('G', 'B', '1', '0') 
#define V4L2_PIX_FMT_SGBRG8  v4l2_fourcc('G', 'B', 'R', 'G') 
#define V4L2_PIX_FMT_SGRBG10 v4l2_fourcc('B', 'A', '1', '0') 
#define V4L2_PIX_FMT_SGRBG10DPCM8 v4l2_fourcc('B', 'D', '1', '0')
#define V4L2_PIX_FMT_SGRBG8  v4l2_fourcc('G', 'R', 'B', 'G') 
#define V4L2_PIX_FMT_SN9C10X  v4l2_fourcc('S', '9', '1', '0') 
#define V4L2_PIX_FMT_SN9C2028 v4l2_fourcc('S', 'O', 'N', 'X') 
#define V4L2_PIX_FMT_SN9C20X_I420 v4l2_fourcc('S', '9', '2', '0') 
#define V4L2_PIX_FMT_SPCA501  v4l2_fourcc('S', '5', '0', '1') 
#define V4L2_PIX_FMT_SPCA505  v4l2_fourcc('S', '5', '0', '5') 
#define V4L2_PIX_FMT_SPCA508  v4l2_fourcc('S', '5', '0', '8') 
#define V4L2_PIX_FMT_SPCA561  v4l2_fourcc('S', '5', '6', '1') 
#define V4L2_PIX_FMT_SQ905C   v4l2_fourcc('9', '0', '5', 'C') 
#define V4L2_PIX_FMT_SRGGB10 v4l2_fourcc('R', 'G', '1', '0') 
#define V4L2_PIX_FMT_SRGGB8  v4l2_fourcc('R', 'G', 'G', 'B') 
#define V4L2_PIX_FMT_STV0680  v4l2_fourcc('S', '6', '8', '0') 
#define V4L2_PIX_FMT_UYVY    v4l2_fourcc('U', 'Y', 'V', 'Y') 
#define V4L2_PIX_FMT_VYUY    v4l2_fourcc('V', 'Y', 'U', 'Y') 
#define V4L2_PIX_FMT_WNVA     v4l2_fourcc('W', 'N', 'V', 'A') 
#define V4L2_PIX_FMT_Y10     v4l2_fourcc('Y', '1', '0', ' ') 
#define V4L2_PIX_FMT_Y16     v4l2_fourcc('Y', '1', '6', ' ') 
#define V4L2_PIX_FMT_Y41P    v4l2_fourcc('Y', '4', '1', 'P') 
#define V4L2_PIX_FMT_YUV32   v4l2_fourcc('Y', 'U', 'V', '4') 
#define V4L2_PIX_FMT_YUV410  v4l2_fourcc('Y', 'U', 'V', '9') 
#define V4L2_PIX_FMT_YUV411P v4l2_fourcc('4', '1', '1', 'P') 
#define V4L2_PIX_FMT_YUV420  v4l2_fourcc('Y', 'U', '1', '2') 
#define V4L2_PIX_FMT_YUV422P v4l2_fourcc('4', '2', '2', 'P') 
#define V4L2_PIX_FMT_YUV444  v4l2_fourcc('Y', '4', '4', '4') 
#define V4L2_PIX_FMT_YUV555  v4l2_fourcc('Y', 'U', 'V', 'O') 
#define V4L2_PIX_FMT_YUV565  v4l2_fourcc('Y', 'U', 'V', 'P') 
#define V4L2_PIX_FMT_YUYV    v4l2_fourcc('Y', 'U', 'Y', 'V') 
#define V4L2_PIX_FMT_YVU410  v4l2_fourcc('Y', 'V', 'U', '9') 
#define V4L2_PIX_FMT_YVU420  v4l2_fourcc('Y', 'V', '1', '2') 
#define V4L2_PIX_FMT_YVYU    v4l2_fourcc('Y', 'V', 'Y', 'U') 
#define V4L2_PIX_FMT_YYUV    v4l2_fourcc('Y', 'Y', 'U', 'V') 
#define V4L2_RDS_BLOCK_A 	 0
#define V4L2_RDS_BLOCK_B 	 1
#define V4L2_RDS_BLOCK_C 	 2
#define V4L2_RDS_BLOCK_CORRECTED 0x40
#define V4L2_RDS_BLOCK_C_ALT 	 4
#define V4L2_RDS_BLOCK_D 	 3
#define V4L2_RDS_BLOCK_ERROR 	 0x80
#define V4L2_RDS_BLOCK_INVALID 	 7
#define V4L2_RDS_BLOCK_MSK 	 0x7
#define V4L2_SLICED_CAPTION_525         (0x1000)
#define V4L2_SLICED_TELETEXT_B          (0x0001)
#define V4L2_SLICED_VBI_525             (V4L2_SLICED_CAPTION_525)
#define V4L2_SLICED_VBI_625             (V4L2_SLICED_TELETEXT_B | V4L2_SLICED_VPS | V4L2_SLICED_WSS_625)
#define V4L2_SLICED_VPS                 (0x0400)
#define V4L2_SLICED_WSS_625             (0x4000)
#define V4L2_STD_ALL            (V4L2_STD_525_60	|\
				 V4L2_STD_625_50)
#define V4L2_STD_ATSC           (V4L2_STD_ATSC_8_VSB    |\
				 V4L2_STD_ATSC_16_VSB)
#define V4L2_STD_ATSC_16_VSB    ((v4l2_std_id)0x02000000)
#define V4L2_STD_ATSC_8_VSB     ((v4l2_std_id)0x01000000)
#define V4L2_STD_NTSC           (V4L2_STD_NTSC_M	|\
				 V4L2_STD_NTSC_M_JP     |\
				 V4L2_STD_NTSC_M_KR)
#define V4L2_STD_NTSC_443       ((v4l2_std_id)0x00004000)
#define V4L2_STD_NTSC_M         ((v4l2_std_id)0x00001000)
#define V4L2_STD_NTSC_M_JP      ((v4l2_std_id)0x00002000)
#define V4L2_STD_NTSC_M_KR      ((v4l2_std_id)0x00008000)
#define V4L2_STD_PAL_60         ((v4l2_std_id)0x00000800)
#define V4L2_STD_PAL_B          ((v4l2_std_id)0x00000001)
#define V4L2_STD_PAL_B1         ((v4l2_std_id)0x00000002)
#define V4L2_STD_PAL_D          ((v4l2_std_id)0x00000020)
#define V4L2_STD_PAL_D1         ((v4l2_std_id)0x00000040)
#define V4L2_STD_PAL_G          ((v4l2_std_id)0x00000004)
#define V4L2_STD_PAL_H          ((v4l2_std_id)0x00000008)
#define V4L2_STD_PAL_I          ((v4l2_std_id)0x00000010)
#define V4L2_STD_PAL_K          ((v4l2_std_id)0x00000080)
#define V4L2_STD_PAL_M          ((v4l2_std_id)0x00000100)
#define V4L2_STD_PAL_N          ((v4l2_std_id)0x00000200)
#define V4L2_STD_PAL_Nc         ((v4l2_std_id)0x00000400)
#define V4L2_STD_SECAM_B        ((v4l2_std_id)0x00010000)
#define V4L2_STD_SECAM_D        ((v4l2_std_id)0x00020000)
#define V4L2_STD_SECAM_DK      	(V4L2_STD_SECAM_D	|\
				 V4L2_STD_SECAM_K	|\
				 V4L2_STD_SECAM_K1)
#define V4L2_STD_SECAM_G        ((v4l2_std_id)0x00040000)
#define V4L2_STD_SECAM_H        ((v4l2_std_id)0x00080000)
#define V4L2_STD_SECAM_K        ((v4l2_std_id)0x00100000)
#define V4L2_STD_SECAM_K1       ((v4l2_std_id)0x00200000)
#define V4L2_STD_SECAM_L        ((v4l2_std_id)0x00400000)
#define V4L2_STD_SECAM_LC       ((v4l2_std_id)0x00800000)
#define V4L2_STD_UNKNOWN        0
#define VIDEO_MAX_FRAME               32
#define VIDIOC_CROPCAP_OLD     	 _IOR('V', 58, struct v4l2_cropcap)
#define VIDIOC_DBG_G_CHIP_IDENT _IOWR('V', 81, struct v4l2_dbg_chip_ident)
#define VIDIOC_ENCODER_CMD      _IOWR('V', 77, struct v4l2_encoder_cmd)
#define VIDIOC_ENUM_FMT         _IOWR('V',  2, struct v4l2_fmtdesc)
#define VIDIOC_ENUM_FRAMEINTERVALS _IOWR('V', 75, struct v4l2_frmivalenum)
#define VIDIOC_G_AUDIO_OLD     	_IOWR('V', 33, struct v4l2_audio)
#define VIDIOC_G_AUDOUT_OLD    	_IOWR('V', 49, struct v4l2_audioout)
#define VIDIOC_G_ENC_INDEX       _IOR('V', 76, struct v4l2_enc_idx)
#define VIDIOC_G_PRIORITY        _IOR('V', 67, enum v4l2_priority)
#define VIDIOC_G_SLICED_VBI_CAP _IOWR('V', 69, struct v4l2_sliced_vbi_cap)
#define VIDIOC_LOG_STATUS         _IO('V', 70)
#define VIDIOC_OVERLAY_OLD     	_IOWR('V', 14, int)
#define VIDIOC_QUERYSTD      	 _IOR('V', 63, v4l2_std_id)
#define VIDIOC_S_CTRL_OLD      	 _IOW('V', 28, struct v4l2_control)
#define VIDIOC_S_PARM_OLD      	 _IOW('V', 22, struct v4l2_streamparm)
#define VIDIOC_S_PRIORITY        _IOW('V', 68, enum v4l2_priority)
#define VIDIOC_TRY_ENCODER_CMD  _IOWR('V', 78, struct v4l2_encoder_cmd)
#define VIDIOC_TRY_FMT      	_IOWR('V', 64, struct v4l2_format)


#define v4l2_fourcc(a, b, c, d)\
	((__u32)(a) | ((__u32)(b) << 8) | ((__u32)(c) << 16) | ((__u32)(d) << 24))
#define MSEC_2_TICKS(m) max(1, (uint32_t)((hz == 1000) ? \
	  (m) : ((uint64_t)(m) * (uint64_t)hz)/(uint64_t)1000))
#define TICKS_2_MSEC(t) max(1, (uint32_t)(hz == 1000) ? \
	  (t) : (((uint64_t)(t) * (uint64_t)1000)/(uint64_t)hz))
#define TICKS_2_USEC(t) max(1, (uint32_t)(hz == 1000) ? \
	  ((t) * 1000) : (((uint64_t)(t) * (uint64_t)1000000)/(uint64_t)hz))
#define USEC_2_TICKS(u) max(1, (uint32_t)((hz == 1000) ? \
	 ((u) / 1000) : ((uint64_t)(u) * (uint64_t)hz)/(uint64_t)1000000))



#define __min_size(x)	static (x)




#define offsetof(type, field) __offsetof(type, field)


#define VIDEO_PALETTE_COMPONENT 7	
#define VIDEO_TUNER_MBS_ON      512     
#define VIDEO_TUNER_RDS_ON      256     
#define VID_HARDWARE_SAA7114H   37
#define VID_HARDWARE_SAA7146    11
#define VID_HARDWARE_VICAM      34

#define DUMMY(s)							\
LIN_SDT_PROBE_DEFINE0(dummy, s, entry);					\
LIN_SDT_PROBE_DEFINE0(dummy, s, not_implemented);			\
LIN_SDT_PROBE_DEFINE1(dummy, s, return, "int");				\
int									\
linux_ ## s(struct thread *td, struct linux_ ## s ## _args *args)	\
{									\
	static pid_t pid;						\
									\
	LIN_SDT_PROBE0(dummy, s, entry);				\
									\
	if (pid != td->td_proc->p_pid) {				\
		linux_msg(td, "syscall %s not implemented", #s);	\
		LIN_SDT_PROBE0(dummy, s, not_implemented);		\
		pid = td->td_proc->p_pid;				\
	};								\
									\
	LIN_SDT_PROBE1(dummy, s, return, ENOSYS);			\
	return (ENOSYS);						\
}									\
struct __hack
#define LCONVPATH(td, upath, pathp, i)	\
   LCONVPATH_AT(td, upath, pathp, i, AT_FDCWD)
#define LCONVPATHCREAT(td, upath, pathp) LCONVPATH(td, upath, pathp, 1)
#define LCONVPATHCREAT_AT(td, upath, pathp, dfd) LCONVPATH_AT(td, upath, pathp, 1, dfd)
#define LCONVPATHEXIST(td, upath, pathp) LCONVPATH(td, upath, pathp, 0)
#define LCONVPATHEXIST_AT(td, upath, pathp, dfd) LCONVPATH_AT(td, upath, pathp, 0, dfd)
#define LCONVPATH_AT(td, upath, pathp, i, dfd)				\
	do {								\
		int _error;						\
									\
		_error = linux_emul_convpath(td, upath, UIO_USERSPACE,	\
		    pathp, i, dfd);					\
		if (*(pathp) == NULL)					\
			return (_error);				\
	} while (0)
#define LFREEPATH(path)	free(path, M_TEMP)


#define INIT_SYSENTVEC(name, sv)					\
    SYSINIT(name, SI_SUB_EXEC, SI_ORDER_ANY,				\
	(sysinit_cfunc_t)exec_sysvec_init, sv);
#define SYSCALL_INIT_HELPER(syscallname)			\
    SYSCALL_INIT_HELPER_F(syscallname, 0)
#define SYSCALL_INIT_HELPER_COMPAT(syscallname)			\
    SYSCALL_INIT_HELPER_COMPAT_F(syscallname, 0)
#define SYSCALL_INIT_HELPER_COMPAT_F(syscallname, flags) {	\
    .new_sysent = {						\
	.sy_narg = (sizeof(struct syscallname ## _args )	\
	    / sizeof(register_t)),				\
	.sy_call = (sy_call_t *)& syscallname,			\
	.sy_auevent = SYS_AUE_##syscallname,			\
	.sy_flags = (flags)					\
    },								\
    .syscall_no = SYS_##syscallname				\
}
#define SYSCALL_INIT_HELPER_F(syscallname, flags) {		\
    .new_sysent = {						\
	.sy_narg = (sizeof(struct syscallname ## _args )	\
	    / sizeof(register_t)),				\
	.sy_call = (sy_call_t *)& sys_ ## syscallname,		\
	.sy_auevent = SYS_AUE_##syscallname,			\
	.sy_flags = (flags)					\
    },								\
    .syscall_no = SYS_##syscallname				\
}
#define SYSCALL_INIT_LAST {					\
    .syscall_no = NO_SYSCALL					\
}
#define SYSCALL_MODULE(name, offset, new_sysent, evh, arg)	\
static struct syscall_module_data name##_syscall_mod = {	\
	evh, arg, offset, new_sysent, { 0, NULL, AUE_NULL }	\
};								\
								\
static moduledata_t name##_mod = {				\
	"sys/" #name,						\
	syscall_module_handler,					\
	&name##_syscall_mod					\
};								\
DECLARE_MODULE(name, name##_mod, SI_SUB_SYSCALLS, SI_ORDER_MIDDLE)
#define SYSENT_INIT_VALS(_syscallname) {			\
	.sy_narg = (sizeof(struct _syscallname ## _args )	\
	    / sizeof(register_t)),				\
	.sy_call = (sy_call_t *)&sys_##_syscallname,		\
	.sy_auevent = SYS_AUE_##_syscallname,			\
	.sy_systrace_args_func = NULL,				\
	.sy_entry = 0,						\
	.sy_return = 0,						\
	.sy_flags = 0,						\
	.sy_thrcnt = 0						\
}							
#define BLKDEV_IOSIZE  PAGE_SIZE	


#define __FreeBSD_version 1300034	
#define __PAST_END(array, offset) (((__typeof__(*(array)) *)(array))[offset])
#define btoc(x)	(((vm_offset_t)(x)+PAGE_MASK)>>PAGE_SHIFT)
#define btodb(bytes)	 		 \
	(sizeof (bytes) > sizeof(long) \
	 ? (daddr_t)((unsigned long long)(bytes) >> DEV_BSHIFT) \
	 : (daddr_t)((unsigned long)(bytes) >> DEV_BSHIFT))
#define ctob(x)	((x)<<PAGE_SHIFT)
#define ctodb(db)			 \
	((db) << (PAGE_SHIFT - DEV_BSHIFT))
#define dbtob(db)			 \
	((off_t)(db) << DEV_BSHIFT)
#define dbtoc(db)			 \
	((db + (ctodb(1) - 1)) >> (PAGE_SHIFT - DEV_BSHIFT))
#define powerof2(x)	((((x)-1)&(x))==0)
#define ILL_BADSTK 	8	
#define ILL_COPROC 	7	
#define ILL_ILLADR 	3	
#define ILL_ILLOPC 	1	
#define ILL_ILLOPN 	2	
#define ILL_ILLTRP 	4	
#define ILL_PRVOPC 	5	
#define ILL_PRVREG 	6	
#define SIG_HOLD        ((__sighandler_t *)3)




#define EXEC_SET(name, execsw_arg) \
	static int __CONCAT(name,_modevent)(module_t mod, int type, \
	    void *data) \
	{ \
		struct execsw *exec = (struct execsw *)data; \
		int error = 0; \
		switch (type) { \
		case MOD_LOAD: \
			 \
			error = exec_register(exec); \
			if (error) \
				printf(__XSTRING(name) "register failed\n"); \
			break; \
		case MOD_UNLOAD: \
			 \
			error = exec_unregister(exec); \
			if (error) \
				printf(__XSTRING(name) " unregister failed\n");\
			break; \
		default: \
			error = EOPNOTSUPP; \
			break; \
		} \
		return error; \
	} \
	static moduledata_t __CONCAT(name,_mod) = { \
		__XSTRING(name), \
		__CONCAT(name,_modevent), \
		(void *)& execsw_arg \
	}; \
	DECLARE_MODULE_TIED(name, __CONCAT(name,_mod), SI_SUB_EXEC, \
	    SI_ORDER_ANY)


#define ABS_SET(set, sym)	__MAKE_SET(set, sym)
#define BSS_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_SET(set, sym)	__MAKE_SET(set, sym)
#define DATA_WSET(set, sym)	__MAKE_SET_QV(set, sym, )
#define SET_BEGIN(set)							\
	(&__CONCAT(__start_set_,set))
#define SET_COUNT(set)							\
	(SET_LIMIT(set) - SET_BEGIN(set))
#define SET_DECLARE(set, ptype)					\
	extern ptype __weak_symbol *__CONCAT(__start_set_,set);	\
	extern ptype __weak_symbol *__CONCAT(__stop_set_,set)
#define SET_ENTRY(set, sym)	__MAKE_SET(set, sym)
#define SET_FOREACH(pvar, set)						\
	for (pvar = SET_BEGIN(set); pvar < SET_LIMIT(set); pvar++)
#define SET_ITEM(set, i)						\
	((SET_BEGIN(set))[i])
#define SET_LIMIT(set)							\
	(&__CONCAT(__stop_set_,set))
#define TEXT_SET(set, sym)	__MAKE_SET(set, sym)

#define __MAKE_SET(set, sym)	__MAKE_SET_QV(set, sym, __MAKE_SET_CONST)
#define __MAKE_SET_QV(set, sym, qv)			\
	__GLOBL(__CONCAT(__start_set_,set));		\
	__GLOBL(__CONCAT(__stop_set_,set));		\
	static void const * qv				\
	__set_##set##_sym_##sym __section("set_" #set)	\
	__used = &(sym)
#define num_pages(x) \
	((vm_offset_t)((((vm_offset_t)(x)) + PAGE_MASK) >> PAGE_SHIFT))

#define LINUX_CMSG_ALIGN(len)	roundup2(len, sizeof(l_ulong))
#define LINUX_CMSG_DATA(cmsg)	((void *)((char *)(cmsg) + \
				    LINUX_CMSG_ALIGN(sizeof(struct l_cmsghdr))))
#define LINUX_CMSG_FIRSTHDR(msg) \
				((msg)->msg_controllen >= \
				    sizeof(struct l_cmsghdr) ? \
				    (struct l_cmsghdr *) \
				        PTRIN((msg)->msg_control) : \
				    (struct l_cmsghdr *)(NULL))
#define LINUX_CMSG_LEN(len)	(LINUX_CMSG_ALIGN(sizeof(struct l_cmsghdr)) + \
				    (len))
#define LINUX_CMSG_NXTHDR(msg, cmsg) \
				((((char *)(cmsg) + \
				    LINUX_CMSG_ALIGN((cmsg)->cmsg_len) + \
				    sizeof(*(cmsg))) > \
				    (((char *)PTRIN((msg)->msg_control)) + \
				    (msg)->msg_controllen)) ? \
				    (struct l_cmsghdr *) NULL : \
				    (struct l_cmsghdr *)((char *)(cmsg) + \
				    LINUX_CMSG_ALIGN((cmsg)->cmsg_len)))
#define LINUX_CMSG_SPACE(len)	(LINUX_CMSG_ALIGN(sizeof(struct l_cmsghdr)) + \
				    LINUX_CMSG_ALIGN(len))


#define LINUX_IOCTL_DISK_MAX    LINUX_BLKSSZGET
#define LINUX_IOCTL_DISK_MIN    LINUX_BLKROSET


#define RSIZE_MAX (SIZE_MAX >> 1)



#define LIST_CONCAT(head1, head2, type, field) do {			      \
	QUEUE_TYPEOF(type) *curelm = LIST_FIRST(head1);			      \
	if (curelm == NULL) {						      \
		if ((LIST_FIRST(head1) = LIST_FIRST(head2)) != NULL) {	      \
			LIST_FIRST(head2)->field.le_prev =		      \
			    &LIST_FIRST((head1));			      \
			LIST_INIT(head2);				      \
		}							      \
	} else if (LIST_FIRST(head2) != NULL) {				      \
		while (LIST_NEXT(curelm, field) != NULL)		      \
			curelm = LIST_NEXT(curelm, field);		      \
		LIST_NEXT(curelm, field) = LIST_FIRST(head2);		      \
		LIST_FIRST(head2)->field.le_prev = &LIST_NEXT(curelm, field); \
		LIST_INIT(head2);					      \
	}								      \
} while (0)
#define LIST_SWAP(head1, head2, type, field) do {			\
	QUEUE_TYPEOF(type) *swap_tmp = LIST_FIRST(head1);		\
	LIST_FIRST((head1)) = LIST_FIRST((head2));			\
	LIST_FIRST((head2)) = swap_tmp;					\
	if ((swap_tmp = LIST_FIRST((head1))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head1));		\
	if ((swap_tmp = LIST_FIRST((head2))) != NULL)			\
		swap_tmp->field.le_prev = &LIST_FIRST((head2));		\
} while (0)
#define SLIST_CONCAT(head1, head2, type, field) do {			\
	QUEUE_TYPEOF(type) *curelm = SLIST_FIRST(head1);		\
	if (curelm == NULL) {						\
		if ((SLIST_FIRST(head1) = SLIST_FIRST(head2)) != NULL)	\
			SLIST_INIT(head2);				\
	} else if (SLIST_FIRST(head2) != NULL) {			\
		while (SLIST_NEXT(curelm, field) != NULL)		\
			curelm = SLIST_NEXT(curelm, field);		\
		SLIST_NEXT(curelm, field) = SLIST_FIRST(head2);		\
		SLIST_INIT(head2);					\
	}								\
} while (0)
#define SLIST_REMOVE_AFTER(elm, field) do {				\
	SLIST_NEXT(elm, field) =					\
	    SLIST_NEXT(SLIST_NEXT(elm, field), field);			\
} while (0)
#define SLIST_SWAP(head1, head2, type) do {				\
	QUEUE_TYPEOF(type) *swap_first = SLIST_FIRST(head1);		\
	SLIST_FIRST(head1) = SLIST_FIRST(head2);			\
	SLIST_FIRST(head2) = swap_first;				\
} while (0)
#define STAILQ_REMOVE_AFTER(head, elm, field) do {			\
	if ((STAILQ_NEXT(elm, field) =					\
	     STAILQ_NEXT(STAILQ_NEXT(elm, field), field)) == NULL)	\
		(head)->stqh_last = &STAILQ_NEXT((elm), field);		\
} while (0)
#define STAILQ_SWAP(head1, head2, type) do {				\
	QUEUE_TYPEOF(type) *swap_first = STAILQ_FIRST(head1);		\
	QUEUE_TYPEOF(type) **swap_last = (head1)->stqh_last;		\
	STAILQ_FIRST(head1) = STAILQ_FIRST(head2);			\
	(head1)->stqh_last = (head2)->stqh_last;			\
	STAILQ_FIRST(head2) = swap_first;				\
	(head2)->stqh_last = swap_last;					\
	if (STAILQ_EMPTY(head1))					\
		(head1)->stqh_last = &STAILQ_FIRST(head1);		\
	if (STAILQ_EMPTY(head2))					\
		(head2)->stqh_last = &STAILQ_FIRST(head2);		\
} while (0)
#define TAILQ_SWAP(head1, head2, type, field) do {			\
	QUEUE_TYPEOF(type) *swap_first = (head1)->tqh_first;		\
	QUEUE_TYPEOF(type) **swap_last = (head1)->tqh_last;		\
	(head1)->tqh_first = (head2)->tqh_first;			\
	(head1)->tqh_last = (head2)->tqh_last;				\
	(head2)->tqh_first = swap_first;				\
	(head2)->tqh_last = swap_last;					\
	if ((swap_first = (head1)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head1)->tqh_first;	\
	else								\
		(head1)->tqh_last = &(head1)->tqh_first;		\
	if ((swap_first = (head2)->tqh_first) != NULL)			\
		swap_first->field.tqe_prev = &(head2)->tqh_first;	\
	else								\
		(head2)->tqh_last = &(head2)->tqh_first;		\
} while (0)
#define CALLOUT_HANDLE_INITIALIZER(handle)	\
	{ NULL }

#define __gone_ok(m, msg)					 \
	_Static_assert(m < P_OSREL_MAJOR(__FreeBSD_version)),	 \
	    "Obsolete code" msg);
#define bcmp(b1, b2, len) __builtin_memcmp((b1), (b2), (len))
#define bcopy(from, to, len) __builtin_memmove((to), (from), (len))
#define bcopy_early(from, to, len) memmove_early((to), (from), (len))
#define bzero(buf, len) __builtin_memset((buf), 0, (len))
#define bzero_early(buf, len) memset_early((buf), 0, (len))
#define critical_enter() critical_enter_KBI()
#define critical_exit() critical_exit_KBI()
#define gone_in(major, msg)		__gone_ok(major, msg) _gone_in(major, msg)
#define gone_in_dev(dev, major, msg)	__gone_ok(major, msg) _gone_in_dev(dev, major, msg)
#define memcmp(b1, b2, len) __builtin_memcmp((b1), (b2), (len))
#define memcpy(to, from, len) __builtin_memcpy((to), (from), (len))
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#define memset(buf, c, len) __builtin_memset((buf), (c), (len))
#define ovbcopy(f, t, l) bcopy((f), (t), (l))

#define BITSET_DEFINE_VAR(t)	BITSET_DEFINE(t, 1)

#define callout_async_drain(c, d)					\
    _callout_stop_safe(c, 0, d)

#define CLLADDR(s) ((c_caddr_t)((s)->sdl_data + (s)->sdl_nlen))
#define LLADDR(s) ((caddr_t)((s)->sdl_data + (s)->sdl_nlen))
#define LLINDEX(s) ((s)->sdl_index)

#define IF_LLADDR(ifp)							\
    LLADDR((struct sockaddr_dl *)((ifp)->if_addr->ifa_addr))
#define MCDPRINTF printf
#define IF_DEQUEUE(ifq, m) do { 				\
	IF_LOCK(ifq); 						\
	_IF_DEQUEUE(ifq, m); 					\
	IF_UNLOCK(ifq); 					\
} while (0)
#define IF_DRAIN(ifq) do {					\
	IF_LOCK(ifq);						\
	_IF_DRAIN(ifq);						\
	IF_UNLOCK(ifq);						\
} while(0)
#define IF_ENQUEUE(ifq, m) do {					\
	IF_LOCK(ifq); 						\
	_IF_ENQUEUE(ifq, m); 					\
	IF_UNLOCK(ifq); 					\
} while (0)
#define IF_LOCK(ifq)		mtx_lock(&(ifq)->ifq_mtx)
#define IF_PREPEND(ifq, m) do {		 			\
	IF_LOCK(ifq); 						\
	_IF_PREPEND(ifq, m); 					\
	IF_UNLOCK(ifq); 					\
} while (0)
#define IF_UNLOCK(ifq)		mtx_unlock(&(ifq)->ifq_mtx)
#define _IF_DRAIN(ifq) do { 					\
	struct mbuf *m; 					\
	for (;;) { 						\
		_IF_DEQUEUE(ifq, m); 				\
		if (m == NULL) 					\
			break; 					\
		m_freem(m); 					\
	} 							\
} while (0)
#define EV_SET(kevp_, a, b, c, d, e, f) do {	\
	struct kevent *kevp = (kevp_);		\
	(kevp)->ident = (a);			\
	(kevp)->filter = (b);			\
	(kevp)->flags = (c);			\
	(kevp)->fflags = (d);			\
	(kevp)->data = (e);			\
	(kevp)->udata = (f);			\
	(kevp)->ext[0] = 0;			\
	(kevp)->ext[1] = 0;			\
	(kevp)->ext[2] = 0;			\
	(kevp)->ext[3] = 0;			\
} while(0)
#define KNOTE(list, hint, flags)	knote(list, hint, flags)
#define KNOTE_LOCKED(list, hint)	knote(list, hint, KNF_LISTLOCKED)
#define KNOTE_UNLOCKED(list, hint)	knote(list, hint, 0)

#define knlist_clear(knl, islocked)				\
	knlist_cleardel((knl), NULL, (islocked), 0)
#define knlist_delete(knl, td, islocked)			\
	knlist_cleardel((knl), (td), (islocked), 1)
#define DROP_GIANT()							\
do {									\
	int _giantcnt = 0;						\
	WITNESS_SAVE_DECL(Giant);					\
									\
	if (__predict_false(mtx_owned(&Giant))) {			\
		WITNESS_SAVE(&Giant.lock_object, Giant);		\
		for (_giantcnt = 0; mtx_owned(&Giant) &&		\
		    !SCHEDULER_STOPPED(); _giantcnt++)			\
			mtx_unlock(&Giant);				\
	}

#define MTX_NOPROFILE   0x00000020	
#define PARTIAL_PICKUP_GIANT()						\
	mtx_assert(&Giant, MA_NOTOWNED);				\
	if (__predict_false(_giantcnt > 0)) {				\
		while (_giantcnt--)					\
			mtx_lock(&Giant);				\
		WITNESS_RESTORE(&Giant.lock_object, Giant);		\
	}
#define PICKUP_GIANT()							\
	PARTIAL_PICKUP_GIANT();						\
} while (0)

#define __mtx_lock(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
	uintptr_t _v = MTX_UNOWNED;					\
									\
	if (__predict_false(LOCKSTAT_PROFILE_ENABLED(adaptive__acquire) ||\
	    !_mtx_obtain_lock_fetch((mp), &_v, _tid)))			\
		_mtx_lock_sleep((mp), _v, (opts), (file), (line));	\
} while (0)
#define __mtx_lock_spin(mp, tid, opts, file, line) do {			\
	uintptr_t _tid = (uintptr_t)(tid);				\
	uintptr_t _v = MTX_UNOWNED;					\
									\
	spinlock_enter();						\
	if (__predict_false(LOCKSTAT_PROFILE_ENABLED(spin__acquire) ||	\
	    !_mtx_obtain_lock_fetch((mp), &_v, _tid))) 			\
		_mtx_lock_spin((mp), _v, (opts), (file), (line)); 	\
} while (0)
#define __mtx_trylock_spin(mp, tid, opts, file, line) __extension__  ({	\
	uintptr_t _tid = (uintptr_t)(tid);				\
	int _ret;							\
									\
	spinlock_enter();						\
	if (((mp)->mtx_lock != MTX_UNOWNED || !_mtx_obtain_lock((mp), _tid))) {\
		spinlock_exit();					\
		_ret = 0;						\
	} else {							\
		LOCKSTAT_PROFILE_OBTAIN_LOCK_SUCCESS(spin__acquire,	\
		    mp, 0, 0, file, line);				\
		_ret = 1;						\
	}								\
	_ret;								\
})
#define __mtx_unlock(mp, tid, opts, file, line) do {			\
	uintptr_t _v = (uintptr_t)(tid);				\
									\
	if (__predict_false(LOCKSTAT_PROFILE_ENABLED(adaptive__release) ||\
	    !_mtx_release_lock_fetch((mp), &_v)))			\
		_mtx_unlock_sleep((mp), _v, (opts), (file), (line));	\
} while (0)
#define __mtx_unlock_spin(mp) do {					\
	if (mtx_recursed((mp)))						\
		(mp)->mtx_recurse--;					\
	else {								\
		LOCKSTAT_PROFILE_RELEASE_LOCK(spin__release, mp);	\
		_mtx_release_lock_quick((mp));				\
	}								\
	spinlock_exit();						\
} while (0)
#define _mtx_obtain_lock(mp, tid)					\
	atomic_cmpset_acq_ptr(&(mp)->mtx_lock, MTX_UNOWNED, (tid))
#define _mtx_obtain_lock_fetch(mp, vp, tid)				\
	atomic_fcmpset_acq_ptr(&(mp)->mtx_lock, vp, (tid))
#define _mtx_release_lock(mp, tid)					\
	atomic_cmpset_rel_ptr(&(mp)->mtx_lock, (tid), MTX_UNOWNED)
#define _mtx_release_lock_quick(mp)					\
	atomic_store_rel_ptr(&(mp)->mtx_lock, MTX_UNOWNED)
#define lv_mtx_owner(v)	((struct thread *)((v) & ~MTX_FLAGMASK))
#define mtx_assert_(m, what, file, line)	(void)0
#define mtx_lock(m)		mtx_lock_flags((m), 0)
#define mtx_lock_spin(m)	mtx_lock_spin_flags((m), 0)
#define mtx_name(m)	((m)->lock_object.lo_name)
#define mtx_owned(m)	(mtx_owner(m) == curthread)
#define mtx_owner(m)	lv_mtx_owner(MTX_READ_VALUE(m))
#define mtx_pool_lock(pool, ptr)					\
	mtx_lock(mtx_pool_find((pool), (ptr)))
#define mtx_pool_lock_spin(pool, ptr)					\
	mtx_lock_spin(mtx_pool_find((pool), (ptr)))
#define mtx_pool_unlock(pool, ptr)					\
	mtx_unlock(mtx_pool_find((pool), (ptr)))
#define mtx_pool_unlock_spin(pool, ptr)					\
	mtx_unlock_spin(mtx_pool_find((pool), (ptr)))
#define mtx_recursed(m)	((m)->mtx_recurse != 0)
#define mtx_trylock(m)		mtx_trylock_flags((m), 0)
#define mtx_trylock_flags(m, opts)					\
	mtx_trylock_flags_((m), (opts), LOCK_FILE, LOCK_LINE)
#define mtx_trylock_spin(m)	mtx_trylock_spin_flags((m), 0)
#define mtx_trylock_spin_flags(m, opts)					\
	mtx_trylock_spin_flags_((m), (opts), LOCK_FILE, LOCK_LINE)
#define mtx_unlock(m)		mtx_unlock_flags((m), 0)
#define mtx_unlock_spin(m)	mtx_unlock_spin_flags((m), 0)
#define DTRACE_PROBE(name)						\
	DTRACE_PROBE_IMPL_START(name, 0, 0, 0, 0, 0)			\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE1(name, type0, arg0)				\
	DTRACE_PROBE_IMPL_START(name, arg0, 0, 0, 0, 0) 		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE2(name, type0, arg0, type1, arg1)			\
	DTRACE_PROBE_IMPL_START(name, arg0, arg1, 0, 0, 0) 		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 1, #type1, NULL);		\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE3(name, type0, arg0, type1, arg1, type2, arg2)	\
	DTRACE_PROBE_IMPL_START(name, arg0, arg1, arg2, 0, 0)	 	\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 1, #type1, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 2, #type2, NULL);		\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE4(name, type0, arg0, type1, arg1, type2, arg2, type3, arg3)	\
	DTRACE_PROBE_IMPL_START(name, arg0, arg1, arg2, arg3, 0) 	\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 1, #type1, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 2, #type2, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 3, #type3, NULL);		\
	DTRACE_PROBE_IMPL_END
#define DTRACE_PROBE5(name, type0, arg0, type1, arg1, type2, arg2, type3, arg3,	\
    type4, arg4)								\
	DTRACE_PROBE_IMPL_START(name, arg0, arg1, arg2, arg3, arg4) 	\
	SDT_PROBE_ARGTYPE(sdt, , , name, 0, #type0, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 1, #type1, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 2, #type2, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 3, #type3, NULL);		\
	SDT_PROBE_ARGTYPE(sdt, , , name, 4, #type4, NULL);		\
	DTRACE_PROBE_IMPL_END
#define SDT_PROBE(prov, mod, func, name, arg0, arg1, arg2, arg3, arg4)	do {	\
	if (SDT_PROBES_ENABLED()) {						\
		if (__predict_false(sdt_##prov##_##mod##_##func##_##name->id))	\
		(*sdt_probe_func)(sdt_##prov##_##mod##_##func##_##name->id,	\
		    (uintptr_t) arg0, (uintptr_t) arg1, (uintptr_t) arg2,	\
		    (uintptr_t) arg3, (uintptr_t) arg4);			\
	} \
} while (0)
#define SDT_PROBES_ENABLED()	0
#define SDT_PROBE_ARGTYPE(prov, mod, func, name, num, type, xtype)		\
	static struct sdt_argtype sdta_##prov##_##mod##_##func##_##name##num[1]	\
	    = { { num, type, xtype, { NULL, NULL },				\
	    sdt_##prov##_##mod##_##func##_##name }				\
	};									\
	DATA_SET(sdt_argtypes_set, sdta_##prov##_##mod##_##func##_##name##num);
#define SDT_PROBE_DECLARE(prov, mod, func, name)				\
	extern struct sdt_probe sdt_##prov##_##mod##_##func##_##name[1]
#define SDT_PROBE_DEFINE(prov, mod, func, name)					\
	struct sdt_probe sdt_##prov##_##mod##_##func##_##name[1] = {		\
		{ sizeof(struct sdt_probe), sdt_provider_##prov,		\
		    { NULL, NULL }, { NULL, NULL }, #mod, #func, #name, 0, 0,	\
		    NULL }							\
	};									\
	DATA_SET(sdt_probes_set, sdt_##prov##_##mod##_##func##_##name);
#define SDT_PROBE_DEFINE4_XLATE(prov, mod, func, name, arg0, xarg0,     \
    arg1, xarg1, arg2, xarg2, arg3, xarg3)
#define SDT_PROVIDER_DECLARE(prov)						\
	extern struct sdt_provider sdt_provider_##prov[1]
#define SDT_PROVIDER_DEFINE(prov)						\
	struct sdt_provider sdt_provider_##prov[1] = {				\
		{ #prov, { NULL, NULL }, 0, 0 }					\
	};									\
	DATA_SET(sdt_providers_set, sdt_provider_##prov);

#define lock_profile_obtain_lock_failed(lo, contested, waittime)	(void)0
#define lock_profile_obtain_lock_success(lo, contested, waittime, file, line)	(void)0
#define LO_NOPROFILE    0x10000000      
#define MPASS(ex)		MPASS4(ex, #ex, "__FILE__", "__LINE__")
#define MPASS2(ex, what)	MPASS4(ex, what, "__FILE__", "__LINE__")
#define MPASS3(ex, file, line)	MPASS4(ex, #ex, file, line)
#define MPASS4(ex, what, file, line)					\
	KASSERT((ex), ("Assertion %s failed at %s:%d", what, file, line))
#define WITNESS_DESTROY(lock)						\
	witness_destroy(lock)

#define lock_delay_spin(n)	do {	\
	u_int _i;			\
					\
	for (_i = (n); _i > 0; _i--)	\
		cpu_spinwait();		\
} while (0)
#define KTR_COMPILE 0

#define VNET_GLOBAL_EVENTHANDLER_REGISTER(name, func, arg, priority)	\
do {									\
	if (IS_DEFAULT_VNET(curvnet)) {					\
		vimage_eventhandler_register(NULL, #name, func,		\
		    arg, priority,					\
		    vnet_global_eventhandler_iterator_func);		\
	}								\
} while(0)
#define VNET_GLOBAL_EVENTHANDLER_REGISTER_TAG(tag, name, func, arg, priority) \
do {									\
	if (IS_DEFAULT_VNET(curvnet)) {					\
		(tag) = vimage_eventhandler_register(NULL, #name, func,	\
		    arg, priority,					\
		    vnet_global_eventhandler_iterator_func);		\
	}								\
} while(0)
#define EVENTHANDLER_DEFINE(name, func, arg, priority)			\
	static eventhandler_tag name ## _tag;				\
	static void name ## _evh_init(void *ctx)			\
	{								\
		name ## _tag = EVENTHANDLER_REGISTER(name, func, ctx,	\
		    priority);						\
	}								\
	SYSINIT(name ## _evh_init, SI_SUB_CONFIGURE, SI_ORDER_ANY,	\
	    name ## _evh_init, arg);					\
	struct __hack
#define EVENTHANDLER_DEREGISTER(name, tag) 				\
do {									\
	struct eventhandler_list *_el;					\
									\
	if ((_el = eventhandler_find_list(#name)) != NULL)		\
		eventhandler_deregister(_el, tag);			\
} while(0)
#define EVENTHANDLER_DEREGISTER_NOWAIT(name, tag)			\
do {									\
	struct eventhandler_list *_el;					\
									\
	if ((_el = eventhandler_find_list(#name)) != NULL)		\
		eventhandler_deregister_nowait(_el, tag);		\
} while(0)
#define EVENTHANDLER_INVOKE(name, ...)					\
do {									\
	struct eventhandler_list *_el;					\
									\
	if ((_el = eventhandler_find_list(#name)) != NULL) 		\
		_EVENTHANDLER_INVOKE(name, _el , ## __VA_ARGS__);	\
} while (0)
#define EVENTHANDLER_REGISTER(name, func, arg, priority)		\
	eventhandler_register(NULL, #name, func, arg, priority)
#define _EVENTHANDLER_INVOKE(name, list, ...) do {			\
	struct eventhandler_entry *_ep;					\
	struct eventhandler_entry_ ## name *_t;				\
									\
	EHL_LOCK_ASSERT((list), MA_OWNED);				\
	(list)->el_runcount++;						\
	KASSERT((list)->el_runcount > 0,				\
	    ("eventhandler_invoke: runcount overflow"));		\
	CTR0(KTR_EVH, "eventhandler_invoke(\"" __STRING(name) "\")");	\
	TAILQ_FOREACH(_ep, &((list)->el_entries), ee_link) {		\
		if (_ep->ee_priority != EHE_DEAD_PRIORITY) {		\
			EHL_UNLOCK((list));				\
			_t = (struct eventhandler_entry_ ## name *)_ep;	\
			CTR1(KTR_EVH, "eventhandler_invoke: executing %p", \
 			    (void *)_t->eh_func);			\
			_t->eh_func(_ep->ee_arg , ## __VA_ARGS__);	\
			EHL_LOCK((list));				\
		}							\
	}								\
	KASSERT((list)->el_runcount > 0,				\
	    ("eventhandler_invoke: runcount underflow"));		\
	(list)->el_runcount--;						\
	if ((list)->el_runcount == 0)					\
		eventhandler_prune_list(list);				\
	EHL_UNLOCK((list));						\
} while (0)

#define CTR0(m, format)			CTR6(m, format, 0, 0, 0, 0, 0, 0)
#define CTR1(m, format, p1)		CTR6(m, format, p1, 0, 0, 0, 0, 0)
#define CTR6(m, format, p1, p2, p3, p4, p5, p6) do {			\
	if (KTR_COMPILE & (m))						\
		ktr_tracepoint((m), "__FILE__", "__LINE__", format,		\
		    (u_long)(p1), (u_long)(p2), (u_long)(p3),		\
		    (u_long)(p4), (u_long)(p5), (u_long)(p6));		\
	} while(0)
#define KTR_STATE0(m, egroup, ident, state)				\
	KTR_EVENT0(m, egroup, ident, "state:\"%s\"", state)
#define KTR_STATE1(m, egroup, ident, state, a0, v0)			\
	KTR_EVENT1(m, egroup, ident, "state:\"%s\"", state, a0, (v0))
#define KTR_STATE2(m, egroup, ident, state, a0, v0, a1, v1)		\
	KTR_EVENT2(m, egroup, ident, "state:\"%s\"", state, a0, (v0), a1, (v1))
#define KTR_STATE3(m, egroup, ident, state, a0, v0, a1, v1, a2, v2)	\
	KTR_EVENT3(m, egroup, ident, "state:\"%s\"",			\
	    state, a0, (v0), a1, (v1), a2, (v2))
#define KTR_STATE4(m, egroup, ident, state, a0, v0, a1, v1, a2, v2, a3, v3)\
	KTR_EVENT4(m, egroup, ident, "state:\"%s\"",			\
	    state, a0, (v0), a1, (v1), a2, (v2), a3, (v3))

#define EVENTHANDLER_DECLARE(name, type)				\
struct eventhandler_entry_ ## name 					\
{									\
	struct eventhandler_entry	ee;				\
	type				eh_func;			\
};									\
struct __hack

#define TSENTER() TSRAW(curthread, TS_ENTER, __func__, NULL)
#define TSENTER2(x) TSRAW(curthread, TS_ENTER, __func__, x)
#define TSEVENT(x) TSRAW(curthread, TS_EVENT, x, NULL)
#define TSEVENT2(x, y) TSRAW(curthread, TS_EVENT, x, y)
#define TSEXIT() TSRAW(curthread, TS_EXIT, __func__, NULL)
#define TSEXIT2(x) TSRAW(curthread, TS_EXIT, __func__, x)
#define TSHOLD(x) TSEVENT2("HOLD", x);
#define TSLINE() TSEVENT2("__FILE__", __XSTRING("__LINE__"))
#define TSRAW(a, b, c, d) tslog(a, b, c, d)
#define TSRELEASE(x) TSEVENT2("RELEASE", x);
#define TSTHREAD(td, x) TSRAW(td, TS_THREAD, x, NULL)
#define TSUNWAIT(x) TSEVENT2("UNWAIT", x);
#define TSWAIT(x) TSEVENT2("WAIT", x);

#define TD_IS_IDLETHREAD(td)	((td)->td_flags & TDF_IDLETD)
#define ucontext4 ucontext

#define RTP_PRIO_BASE(P)	PRI_BASE(P)
#define RTP_PRIO_IS_REALTIME(P) PRI_IS_REALTIME(P)
#define RTP_PRIO_NEED_RR(P)	PRI_NEED_RR(P)



#define cv_broadcast(cvp)	cv_broadcastpri(cvp, 0)
#define MBUF_EXT_PGS_ASSERT(m)						\
	KASSERT((((m)->m_flags & M_EXT) != 0) &&			\
	    ((m)->m_ext.ext_type == EXT_PGS),				\
	    ("%s: m %p !M_EXT or !EXT_PGS", __func__, m))
#define M_COPYFLAGS \
    (M_PKTHDR|M_EOR|M_RDONLY|M_BCAST|M_MCAST|M_PROMISC|M_VLANTAG|M_TSTMP| \
     M_TSTMP_HPREC|M_PROTOFLAGS)
#define M_GETFIB(_m)   rt_m_getfib(_m)
 #define M_PROFILE(m) m_profile(m)
#define M_SETFIB(_m, _fib) do {						\
        KASSERT((_m)->m_flags & M_PKTHDR, ("Attempt to set FIB on non header mbuf."));	\
	((_m)->m_pkthdr.fibnum) = (_fib);				\
} while (0)
#define UMA_SMALLEST_UNIT       (PAGE_SIZE / 256) 



#define EPOCH_LOCKED 0x2
#define EPOCH_MAGIC0 0xFADECAFEF00DD00D
#define EPOCH_MAGIC1 0xBADDBABEDEEDFEED
#define EPOCH_PREEMPT 0x1


#define CK_LIST_ENTRY LIST_ENTRY
#define CK_LIST_HEAD LIST_HEAD
#define CK_STAILQ_ENTRY STAILQ_ENTRY
#define CK_STAILQ_HEAD STAILQ_HEAD
#define ACCEPT4_COMPAT  0x2
#define ACCEPT4_INHERIT 0x1
#define AF_VENDOR00 39
#define AF_VENDOR01 41
#define AF_VENDOR02 43
#define AF_VENDOR03 45
#define AF_VENDOR04 47
#define AF_VENDOR05 49
#define AF_VENDOR06 51
#define AF_VENDOR07 53
#define AF_VENDOR08 55
#define AF_VENDOR09 57
#define AF_VENDOR10 59
#define AF_VENDOR11 61
#define AF_VENDOR12 63
#define AF_VENDOR13 65
#define AF_VENDOR14 67
#define AF_VENDOR15 69
#define AF_VENDOR16 71
#define AF_VENDOR17 73
#define AF_VENDOR18 75
#define AF_VENDOR19 77
#define AF_VENDOR20 79
#define AF_VENDOR21 81
#define AF_VENDOR22 83
#define AF_VENDOR23 85
#define AF_VENDOR24 87
#define AF_VENDOR25 89
#define AF_VENDOR26 91
#define AF_VENDOR27 93
#define AF_VENDOR28 95
#define AF_VENDOR29 97
#define AF_VENDOR30 99
#define AF_VENDOR31 101
#define AF_VENDOR32 103
#define AF_VENDOR33 105
#define AF_VENDOR34 107
#define AF_VENDOR35 109
#define AF_VENDOR36 111
#define AF_VENDOR37 113
#define AF_VENDOR38 115
#define AF_VENDOR39 117
#define AF_VENDOR40 119
#define AF_VENDOR41 121
#define AF_VENDOR42 123
#define AF_VENDOR43 125
#define AF_VENDOR44 127
#define AF_VENDOR45 129
#define AF_VENDOR46 131
#define AF_VENDOR47 133
#define CMGROUP_MAX 16
#define PRU_FLUSH_RD     SHUT_RD
#define PRU_FLUSH_RDWR   SHUT_RDWR
#define PRU_FLUSH_WR     SHUT_WR
#define pseudo_AF_HDRCMPLT 31		
#define lim_cur(td, which)	({					\
	rlim_t _rlim;							\
	struct thread *_td = (td);					\
	int _which = (which);						\
	if (__builtin_constant_p(which) && which != RLIMIT_DATA &&	\
	    which != RLIMIT_STACK && which != RLIMIT_VMEM) {		\
		_rlim = td->td_limit->pl_rlimit[which].rlim_cur;	\
	} else {							\
		_rlim = lim_cur(_td, _which);				\
	}								\
	_rlim;								\
})

#define ttydisc_can_bypass(tp) ((tp)->t_flags & TF_BYPASS)
#define TTYINQ_DATASIZE 128
#define TTYOUTQ_DATASIZE (256 - sizeof(struct ttyoutq_block *))
#define		UIOCCMD(n)	_IO('u', n)	
#       define CHID_C           3
#       define CHID_L           1
#       define CHID_LFE         4
#       define CHID_LR          7
#       define CHID_LS          5
#       define CHID_R           2
#       define CHID_RR          8
#       define CHID_RS          6
#       define CHID_UNDEF       0
#define CHNORDER_NORMAL         0x0000000087654321ULL
#define CHNORDER_UNDEF          0x0000000000000000ULL
#define MIXER_READ(dev)		_IOR('M', dev, int)
#define MIXER_WRITE(dev)		_IOWR('M', dev, int)
#define OPEN_READ       PCM_ENABLE_INPUT
#define OPEN_READWRITE  (OPEN_READ|OPEN_WRITE)
#define OPEN_WRITE      PCM_ENABLE_OUTPUT
#define OSS_DEVNODE_SIZE        32
#define OSS_ENUM_MAXVALUE       255
#define OSS_GETVERSION                  _IOR ('M', 118, int)
#define OSS_SYSINFO             SNDCTL_SYSINFO 
#define PM_GET_PGM_PATCHES 4	
#define PM_LOAD_PATCH(dev, bank, pgm)	\
	(SEQ_DUMPBUF(), _pm_info.command = _PM_LOAD_PATCH, \
	_pm_info.device=dev, _pm_info.data.data8[0]=pgm, \
	_pm_info.parm1 = bank, _pm_info.parm2 = 1, \
	ioctl(seqfd, SNDCTL_PMGR_ACCESS, &_pm_info))
#define PM_LOAD_PATCHES(dev, bank, pgm) \
	(SEQ_DUMPBUF(), _pm_info.command = _PM_LOAD_PATCH, \
	_pm_info.device=dev, bcopy( pgm, _pm_info.data.data8,  128), \
	_pm_info.parm1 = bank, _pm_info.parm2 = 128, \
	ioctl(seqfd, SNDCTL_PMGR_ACCESS, &_pm_info))
#define SEQ_BENDER(dev, chn, value) \
	_CHN_COMMON(dev, MIDI_PITCH_BEND, chn, 0, 0, value)
#define SEQ_BENDER_RANGE(dev, voice, value) \
	SEQ_V2_X_CONTROL(dev, voice, CTRL_PITCH_BENDER_RANGE, value)
#define SEQ_CHN_PRESSURE(dev, chn, pressure) \
	_CHN_COMMON(dev, MIDI_CHN_PRESSURE, chn, pressure, 0, 0)
#define SEQ_CONTINUE_TIMER()		_TIMER_EVENT(TMR_CONTINUE, 0)
#define SEQ_CONTROL(dev, chn, controller, value) \
	_CHN_COMMON(dev, MIDI_CTL_CHANGE, chn, controller, 0, value)
#define SEQ_DECLAREBUF()		SEQ_USE_EXTBUF()
#define SEQ_DEFINEBUF(len)		\
	u_char _seqbuf[len]; int _seqbuflen = len;int _seqbufptr = 0
#define SEQ_DELTA_TIME(ticks)		_TIMER_EVENT(TMR_WAIT_REL, ticks)
#define SEQ_ECHO_BACK(key)		_TIMER_EVENT(TMR_ECHO, key)
#define SEQ_EXPRESSION(dev, voice, value) \
	SEQ_CONTROL(dev, voice, CTL_EXPRESSION, value*128)
#define SEQ_KEY_PRESSURE(dev, chn, note, pressure) \
		_CHN_VOICE(dev, MIDI_KEY_PRESSURE, chn, note, pressure)
#define SEQ_MAIN_VOLUME(dev, voice, value) \
	SEQ_CONTROL(dev, voice, CTL_MAIN_VOLUME, (value*16383)/100)
#define SEQ_MIDIOUT(device, byte)	{ \
	_SEQ_NEEDBUF(4);\
	_seqbuf[_seqbufptr] = SEQ_MIDIPUTC;\
	_seqbuf[_seqbufptr+1] = (byte);\
	_seqbuf[_seqbufptr+2] = (device);\
	_seqbuf[_seqbufptr+3] = 0;\
	_SEQ_ADVBUF(4);}
#define SEQ_PANNING(dev, voice, pos) \
	SEQ_CONTROL(dev, voice, CTL_PAN, (pos+128) / 2)
#define SEQ_PITCHBEND(dev, voice, value) \
	SEQ_V2_X_CONTROL(dev, voice, CTRL_PITCH_BENDER, value)
#define SEQ_PLAYAUDIO(devmask)		_LOCAL_EVENT(LOCL_STARTAUDIO, devmask)
#define SEQ_SET_PATCH(dev, chn, patch) \
	_CHN_COMMON(dev, MIDI_PGM_CHANGE, chn, patch, 0, 0)
#define SEQ_SET_TEMPO(value)		_TIMER_EVENT(TMR_TEMPO, value)
#define SEQ_SONGPOS(pos)		_TIMER_EVENT(TMR_SPP, pos)
#define SEQ_START_NOTE(dev, chn, note, vol) \
		_CHN_VOICE(dev, MIDI_NOTEON, chn, note, vol)
#define SEQ_START_TIMER()		_TIMER_EVENT(TMR_START, 0)
#define SEQ_STOP_NOTE(dev, chn, note, vol) \
		_CHN_VOICE(dev, MIDI_NOTEOFF, chn, note, vol)
#define SEQ_STOP_TIMER()		_TIMER_EVENT(TMR_STOP, 0)
#define SEQ_SYSEX(dev, buf, len) { \
	int i, l=(len); if (l>6)l=6;\
	_SEQ_NEEDBUF(8);\
	_seqbuf[_seqbufptr] = EV_SYSEX;\
	for(i=0;i<l;i++)_seqbuf[_seqbufptr+i+1] = (buf)[i];\
	for(i=l;i<6;i++)_seqbuf[_seqbufptr+i+1] = 0xff;\
	_SEQ_ADVBUF(8);}
#define SEQ_TIME_SIGNATURE(sig)		_TIMER_EVENT(TMR_TIMESIG, sig)
#define SEQ_USE_EXTBUF()		\
	extern u_char _seqbuf[]; \
	extern int _seqbuflen;extern int _seqbufptr
#define SEQ_V2_X_CONTROL(dev, voice, controller, value)	{ \
	_SEQ_NEEDBUF(8);\
	_seqbuf[_seqbufptr] = SEQ_EXTENDED;\
	_seqbuf[_seqbufptr+1] = SEQ_CONTROLLER;\
	_seqbuf[_seqbufptr+2] = (dev);\
	_seqbuf[_seqbufptr+3] = (voice);\
	_seqbuf[_seqbufptr+4] = (controller);\
	*(short *)&_seqbuf[_seqbufptr+5] = (value);\
	_seqbuf[_seqbufptr+7] = 0;\
	_SEQ_ADVBUF(8);}
#define SEQ_VOLMODE             12
#define SEQ_VOLUME_MODE(dev, mode)	{ \
	_SEQ_NEEDBUF(8);\
	_seqbuf[_seqbufptr] = SEQ_EXTENDED;\
	_seqbuf[_seqbufptr+1] = SEQ_VOLMODE;\
	_seqbuf[_seqbufptr+2] = (dev);\
	_seqbuf[_seqbufptr+3] = (mode);\
	_seqbuf[_seqbufptr+4] = 0;\
	_seqbuf[_seqbufptr+5] = 0;\
	_seqbuf[_seqbufptr+6] = 0;\
	_seqbuf[_seqbufptr+7] = 0;\
	_SEQ_ADVBUF(8);}
#define SEQ_WAIT_TIME(ticks)		_TIMER_EVENT(TMR_WAIT_ABS, ticks)
#define SEQ_WRPATCH(patchx, len)	{ \
	if (_seqbufptr) seqbuf_dump(); \
	if (write(seqfd, (char*)(patchx), len)==-1) \
	   perror("Write patch: /dev/sequencer"); \
	}
#define SEQ_WRPATCH2(patchx, len)	\
	( seqbuf_dump(), write(seqfd, (char*)(patchx), len) )
#define SNDCARD_ADLIB          1
#define SNDCARD_AWE32          25
#define SNDCARD_CS4232         21
#define SNDCARD_CS4232_MPU     22
#define SNDCARD_GUS            4
#define SNDCARD_GUS16          9
#define SNDCARD_MAD16          19
#define SNDCARD_MAD16_MPU      20
#define SNDCARD_MAUI           23
#define SNDCARD_MPU401         5
#define SNDCARD_MSS            10
#define SNDCARD_NSS            26
#define SNDCARD_OPL            28
#define SNDCARD_PAS            3
#define SNDCARD_PSEUDO_MSS     24
#define SNDCARD_PSS            11
#define SNDCARD_PSS_MPU        13
#define SNDCARD_PSS_MSS        14
#define SNDCARD_SB             2
#define SNDCARD_SB16           6
#define SNDCARD_SB16MIDI       7
#define SNDCARD_SSCAPE         12
#define SNDCARD_SSCAPE_MSS     15
#define SNDCARD_TRXPRO         16
#define SNDCARD_TRXPRO_MPU     18
#define SNDCARD_TRXPRO_SB      17
#define SNDCARD_UART16550      27
#define SNDCARD_UART6850       8
#define SNDCTL_COPR_RESET       _IO  ('C',  0)
#define SNDCTL_DSP_COOKEDMODE           _IOW ('P', 30, int)
#define SNDCTL_DSP_GETERROR             _IOR ('P', 25, audio_errinfo)
#define SNDCTL_DSP_GETPLAYVOL           _IOR ('P', 24, int)
#define SNDCTL_DSP_GETRECVOL            _IOR ('P', 41, int)
#define SNDCTL_DSP_GET_CHNORDER         _IOR ('P', 42, unsigned long long)
#define SNDCTL_DSP_GET_PLAYTGT          _IOR ('P', 40, int)
#define SNDCTL_DSP_GET_PLAYTGT_NAMES    _IOR ('P', 39, oss_mixer_enuminfo)
#define SNDCTL_DSP_GET_RECSRC           _IOR ('P', 38, int)
#define SNDCTL_DSP_GET_RECSRC_NAMES     _IOR ('P', 37, oss_mixer_enuminfo)
#define SNDCTL_DSP_POLICY               _IOW('P', 45, int)    
#define SNDCTL_DSP_SETBLKSIZE   _IOW('P', 4, int)
#define SNDCTL_DSP_SETPLAYVOL           _IOWR('P', 24, int)
#define SNDCTL_DSP_SETRECVOL            _IOWR('P', 41, int)
#define SNDCTL_DSP_SET_CHNORDER         _IOWR('P', 42, unsigned long long)
#define SNDCTL_DSP_SET_PLAYTGT          _IOWR('P', 40, int)
#define SNDCTL_DSP_SET_RECSRC           _IOWR('P', 38, int)
#define SNDCTL_DSP_SILENCE              _IO  ('P', 31)
#define SNDCTL_DSP_SKIP                 _IO  ('P', 32)
#define SNDCTL_DSP_SYNCGROUP            _IOWR('P', 28, oss_syncgroup)
#define SNDCTL_DSP_SYNCSTART            _IOW ('P', 29, int)
#define SNDCTL_GETLABEL         _IOR ('Y', 4, oss_label_t)
#define SNDCTL_GETSONG          _IOR ('Y', 2, oss_longname_t)
#define SNDCTL_SETLABEL         _IOW ('Y', 4, oss_label_t)
#define SNDCTL_SETNAME          _IOW ('Y', 3, oss_longname_t)
#define SNDCTL_SETSONG          _IOW ('Y', 2, oss_longname_t)
#define SNDCTL_SYSINFO          _IOR ('X', 1, oss_sysinfo)
#define SOUND_MASK_DIGITAL1     (1 << SOUND_MIXER_DIGITAL1)
#define SOUND_MASK_DIGITAL2     (1 << SOUND_MIXER_DIGITAL2)
#define SOUND_MASK_DIGITAL3     (1 << SOUND_MIXER_DIGITAL3)
#define SOUND_MASK_MONITOR      (1 << SOUND_MIXER_MONITOR)
#define SOUND_MASK_PHONEIN      (1 << SOUND_MIXER_PHONEIN)
#define SOUND_MASK_PHONEOUT     (1 << SOUND_MIXER_PHONEOUT)
#define SOUND_MASK_RADIO        (1 << SOUND_MIXER_RADIO)
#define SOUND_MASK_VIDEO        (1 << SOUND_MIXER_VIDEO)
#define SOUND_MIXER_DIGITAL1    17      
#define SOUND_MIXER_DIGITAL2    18      
#define SOUND_MIXER_DIGITAL3    19      
#define SOUND_MIXER_MONITOR     24      
#define SOUND_MIXER_NONE        31
#define SOUND_MIXER_PHONEIN     20      
#define SOUND_MIXER_PHONEOUT    21      
#define SOUND_MIXER_RADIO       23      
#define SOUND_MIXER_READ_PHONEIN      	MIXER_READ(SOUND_MIXER_PHONEIN)
#define SOUND_MIXER_VIDEO       22      
#define SOUND_MIXER_WRITE_PHONEIN      	MIXER_WRITE(SOUND_MIXER_PHONEIN)
#define SOUND_VERSION  301
#define _CHN_COMMON(dev, event, chn, p1, p2, w14) { \
	_SEQ_NEEDBUF(8);\
	_seqbuf[_seqbufptr] = EV_CHN_COMMON;\
	_seqbuf[_seqbufptr+1] = (dev);\
	_seqbuf[_seqbufptr+2] = (event);\
	_seqbuf[_seqbufptr+3] = (chn);\
	_seqbuf[_seqbufptr+4] = (p1);\
	_seqbuf[_seqbufptr+5] = (p2);\
	*(short *)&_seqbuf[_seqbufptr+6] = (w14);\
	_SEQ_ADVBUF(8);}
#define _CHN_VOICE(dev, event, chn, note, parm)  { \
	_SEQ_NEEDBUF(8);\
	_seqbuf[_seqbufptr] = EV_CHN_VOICE;\
	_seqbuf[_seqbufptr+1] = (dev);\
	_seqbuf[_seqbufptr+2] = (event);\
	_seqbuf[_seqbufptr+3] = (chn);\
	_seqbuf[_seqbufptr+4] = (note);\
	_seqbuf[_seqbufptr+5] = (parm);\
	_seqbuf[_seqbufptr+6] = (0);\
	_seqbuf[_seqbufptr+7] = 0;\
	_SEQ_ADVBUF(8);}
#define _LOCAL_EVENT(ev, parm)		{ \
	_SEQ_NEEDBUF(8);\
	_seqbuf[_seqbufptr+0] = EV_SEQ_LOCAL; \
	_seqbuf[_seqbufptr+1] = (ev); \
	_seqbuf[_seqbufptr+2] = 0;\
	_seqbuf[_seqbufptr+3] = 0;\
	*(u_int *)&_seqbuf[_seqbufptr+4] = (parm); \
	_SEQ_ADVBUF(8); \
	}
#  define _PATCHKEY(id) (0xfd00|id)
#define _SEQ_ADVBUF(len)		_seqbufptr += len
#define _SEQ_NEEDBUF(len)		\
	if ((_seqbufptr+(len)) > _seqbuflen) \
		seqbuf_dump()

#define _TIMER_EVENT(ev, parm)		{ \
	_SEQ_NEEDBUF(8);\
	_seqbuf[_seqbufptr+0] = EV_TIMING; \
	_seqbuf[_seqbufptr+1] = (ev); \
	_seqbuf[_seqbufptr+2] = 0;\
	_seqbuf[_seqbufptr+3] = 0;\
	*(u_int *)&_seqbuf[_seqbufptr+4] = (parm); \
	_SEQ_ADVBUF(8); \
	}
#define		 sbuf_new_auto()				\
	sbuf_new(NULL, NULL, 0, SBUF_AUTOEXTEND)
#define ACC(x)		((x)+F_ACC)
#define F(x)		((x)+F_FN-1)
#define GIO_DEADKEYMAP 	_IOR('k', 8, accentmap_t)
#define GIO_KEYMAP 	 _IO('k', 6)
#define GIO_KEYMAPENT 	_IOWR('k', 10, keyarg_t)
#define KDGKBMODE 	_IOR('K', 6, int)
#define KDSKBMODE 	_IOWINT('K', 7)
#define KEYCHAR(c)	((c) & 0x00ffffff)
#define KEYFLAGS(c)	((c) & ~0x00ffffff)
#define OGIO_KEYMAP 	_IOR('k', 6, okeymap_t)
#define OPIO_KEYMAP 	_IOW('k', 7, okeymap_t)
#define PIO_DEADKEYMAP 	_IOW('k', 9, accentmap_t)
#define PIO_KEYMAP 	 _IO('k', 7)
#define PIO_KEYMAPENT 	_IOW('k', 11, keyarg_t)

#define CONS_GETCURSORSHAPE _IOWR('c', 14, struct cshape)
#define CONS_GETINFO    _IOWR('c', 73, vid_info_t)
#define CONS_SETCURSORSHAPE _IOW('c', 15, struct cshape)
#define CONS_VISUAL_BELL (1 << 0)
#define PIO_VFONT_DEFAULT _IO('c', 72)
#define SW_B40x25 	_IO('S', M_B40x25)
#define SW_B80x25  	_IO('S', M_B80x25)
#define SW_BG320   	_IO('S', M_BG320)
#define SW_BG640   	_IO('S', M_BG640)
#define SW_C40x25  	_IO('S', M_C40x25)
#define SW_C80x25  	_IO('S', M_C80x25)
#define SW_CG320   	_IO('S', M_CG320)
#define SW_CG320_D    	_IO('S', M_CG320_D)
#define SW_CG640_E    	_IO('S', M_CG640_E)
#define SW_CG640x350  	_IO('S', M_CG640x350)
#define SW_EGAMONO80x25 _IO('S', M_EGAMONO80x25)
#define SW_EGAMONOAPA 	_IO('S', M_EGAMONOAPA)
#define SW_ENH_B40x25  	_IO('S', M_ENH_B40x25)
#define SW_ENH_B80x25  	_IO('S', M_ENH_B80x25)
#define SW_ENH_B80x43  	_IO('S', M_ENH_B80x43)
#define SW_ENH_C40x25  	_IO('S', M_ENH_C40x25)
#define SW_ENH_C80x25  	_IO('S', M_ENH_C80x25)
#define SW_ENH_C80x43  	_IO('S', M_ENH_C80x43)
#define SW_ENH_CG640  	_IO('S', M_ENH_CG640)
#define SW_ENH_MONOAPA2 _IO('S', M_ENHMONOAPA2)
#define SW_MCAMODE    	_IO('S', M_MCA_MODE)
#define IN_LINKLOCAL(i)		(((in_addr_t)(i) & 0xffff0000) == 0xa9fe0000)
#define IN_LOOPBACK(i)		(((in_addr_t)(i) & 0xff000000) == 0x7f000000)
#define IN_ZERONET(i)		(((in_addr_t)(i) & 0xff000000) == 0)
#define IP_FW_NAT_CFG           56   
#define IP_FW_NAT_DEL           57   
#define IP_FW_NAT_GET_CONFIG    58   
#define IP_FW_NAT_GET_LOG       59   

#define IFA6_IS_DEPRECATED(a) \
	((a)->ia6_lifetime.ia6t_pltime != ND6_INFINITE_LIFETIME && \
	 (u_int32_t)((time_uptime - (a)->ia6_updatetime)) > \
	 (a)->ia6_lifetime.ia6t_pltime)
#define IFA6_IS_INVALID(a) \
	((a)->ia6_lifetime.ia6t_vltime != ND6_INFINITE_LIFETIME && \
	 (u_int32_t)((time_uptime - (a)->ia6_updatetime)) > \
	 (a)->ia6_lifetime.ia6t_vltime)
#define IN6ADDR_ANY_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }}}
#define IN6ADDR_INTFACELOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_LINKLOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }}}
#define IN6ADDR_LINKLOCAL_ALLV2ROUTERS_INIT \
	{{{ 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16 }}}
#define IN6ADDR_LOOPBACK_INIT \
	{{{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6ADDR_NODELOCAL_ALLNODES_INIT \
	{{{ 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }}}
#define IN6_ARE_ADDR_EQUAL(a, b)			\
    (bcmp(&(a)->s6_addr[0], &(b)->s6_addr[0], sizeof(struct in6_addr)) == 0)
#define IN6_IS_ADDR_LINKLOCAL(a)	\
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0x80))
#define IN6_IS_ADDR_LOOPBACK(a)		\
	((a)->__u6_addr.__u6_addr32[0] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[1] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[2] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[3] == ntohl(1))
#define IN6_IS_ADDR_MC_GLOBAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_GLOBAL))
#define IN6_IS_ADDR_MC_INTFACELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_INTFACELOCAL))
#define IN6_IS_ADDR_MC_LINKLOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_LINKLOCAL))
#define IN6_IS_ADDR_MC_NODELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_NODELOCAL))
#define IN6_IS_ADDR_MC_ORGLOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_ORGLOCAL))
#define IN6_IS_ADDR_MC_SITELOCAL(a)	\
	(IN6_IS_ADDR_MULTICAST(a) &&	\
	 (IPV6_ADDR_MC_SCOPE(a) == IPV6_ADDR_SCOPE_SITELOCAL))
#define IN6_IS_ADDR_MULTICAST(a)	((a)->s6_addr[0] == 0xff)
#define IN6_IS_ADDR_SITELOCAL(a)	\
	(((a)->s6_addr[0] == 0xfe) && (((a)->s6_addr[1] & 0xc0) == 0xc0))
#define IN6_IS_ADDR_UNSPECIFIED(a)	\
	((a)->__u6_addr.__u6_addr32[0] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[1] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[2] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[3] == 0)
#define IN6_IS_ADDR_V4COMPAT(a)		\
	((a)->__u6_addr.__u6_addr32[0] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[1] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[2] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[3] != 0 &&	\
	 (a)->__u6_addr.__u6_addr32[3] != ntohl(1))
#define IN6_IS_ADDR_V4MAPPED(a)		      \
	((a)->__u6_addr.__u6_addr32[0] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[1] == 0 &&	\
	 (a)->__u6_addr.__u6_addr32[2] == ntohl(0x0000ffff))
#define IN6_IS_SCOPE_LINKLOCAL(a)	\
	((IN6_IS_ADDR_LINKLOCAL(a)) ||	\
	 (IN6_IS_ADDR_MC_LINKLOCAL(a)))
#define IPV6CTL_SOURCECHECK_LOGINT 11	
#define IPV6_ADDR_MC_SCOPE(a)		((a)->s6_addr[1] & 0x0f)
#define IPV6_DEFAULT_MULTICAST_HOPS 1	
#define IPV6_DEFAULT_MULTICAST_LOOP 1	
#define IPV6_RTHDR_LOOSE     0 
#define IPV6_RTHDR_STRICT    1 
#define IPV6_RTHDR_TYPE_0    0 


#define __IPV6_ADDR_MC_SCOPE(a)		((a)->s6_addr[1] & 0x0f)

#define s6_addr   __u6_addr.__u6_addr8
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32
#define s6_addr8  __u6_addr.__u6_addr8



#define CDIOCREADSUBCHANNEL _IOWR('c', 3 , struct ioc_read_subchannel )
#define CDIOREADTOCENTRY _IOWR('c',6,struct ioc_read_toc_single_entry)
#define CDIOREADTOCENTRYS _IOWR('c',5,struct ioc_read_toc_entry)
#define CDIOREADTOCHEADER _IOR('c',4,struct ioc_toc_header)
#define CD_AS_AUDIO_INVALID        0x00
#define CD_AS_NO_STATUS            0x15
#define CD_AS_PLAY_COMPLETED       0x13
#define CD_AS_PLAY_ERROR           0x14
#define CD_AS_PLAY_IN_PROGRESS     0x11
#define CD_AS_PLAY_PAUSED          0x12
#define CAP_RIGHTS_DEFINE1(name, value)								\
	__read_mostly cap_rights_t name;					\
	CAP_RIGHTS_SYSINIT1(name, name, value);
#define CAP_RIGHTS_SYSINIT0(name, rights)		   \
		static struct cap_rights_init_args name##_args = { \
			&(rights)										\
		};																\
		SYSINIT(name##_cap_rights_sysinit, SI_SUB_COPYRIGHT+1, SI_ORDER_ANY, \
		    __cap_rights_sysinit, &name##_args);
#define CAP_RIGHTS_SYSINIT1(name, rights, value1)		   \
		static struct cap_rights_init_args name##_args = { \
			&(rights),										\
			(value1)										\
		};																\
		SYSINIT(name##_cap_rights_sysinit, SI_SUB_COPYRIGHT+1, SI_ORDER_ANY, \
		    __cap_rights_sysinit, &name##_args);
#define CAP_RIGHTS_SYSINIT2(name, rights, value1, value2)		   \
		static struct cap_rights_init_args name##_args = { \
			&(rights),										\
			(value1),										\
			(value2)													\
		};																\
		SYSINIT(name##_cap_rights_sysinit, SI_SUB_COPYRIGHT, SI_ORDER_ANY, \
		    __cap_rights_sysinit, &name##_args);
#define CAP_RIGHTS_SYSINIT3(name, rights, value1, value2, value3) \
		static struct cap_rights_init_args name##_args = { \
			&(rights),										\
			(value1),										\
			(value2),										\
			(value3)													\
		};																\
		SYSINIT(name##_cap_rights_sysinit, SI_SUB_COPYRIGHT, SI_ORDER_ANY, \
		    __cap_rights_sysinit, &name##_args);
#define CAP_RIGHTS_SYSINIT4(name, rights, value1, value2, value3, value4)	\
		static struct cap_rights_init_args name##_args = { \
			&(rights),										\
			(value1),										\
			(value2),										\
			(value3),										\
			(value4)													\
		};																\
		SYSINIT(name##_cap_rights_sysinit, SI_SUB_COPYRIGHT, SI_ORDER_ANY, \
		    __cap_rights_sysinit, &name##_args);
#define IN_CAPABILITY_MODE(td) (((td)->td_ucred->cr_flags & CRED_FLAG_CAPMODE) != 0)
#define cap_rights_fde_inline(fdep)	(&(fdep)->fde_rights)

#define SEM_VALUE_MAX  __INT_MAX


#define BITSET_ALLOC(_s, mt, mf)					\
	malloc(__bitset_words(_s) * sizeof(long), mt, (mf))
#define CPU_SET_RDONLY  0x0002  
#define CPU_SET_ROOT    0x0001  
