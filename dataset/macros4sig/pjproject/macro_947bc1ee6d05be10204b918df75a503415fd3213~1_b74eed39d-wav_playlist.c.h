



















#   define PJMEDIA_WAVE_NORMALIZE_SUBCHUNK(ch)  \
	    do { \
		(ch)->id = pj_swap32((ch)->id); \
		(ch)->len = pj_swap32((ch)->len); \
	    } while (0)

#define PJMEDIA_FOURCC(C1, C2, C3, C4) ( C4<<24 | C3<<16 | C2<<8 | C1 )
#define PJMEDIA_TP_PROTO_HAS_FLAG(TP_PROTO, FLAGS) \
				    (((TP_PROTO) & (FLAGS)) == (FLAGS))
#define PJMEDIA_TP_PROTO_TRIM_FLAG(TP_PROTO, FLAGS) ((TP_PROTO) &= ~(FLAGS))

#   define PJMEDIA_CLOCK_SYNC_MAX_RESYNC_DURATION 2000
#   define PJMEDIA_CLOCK_SYNC_MAX_SYNC_MSEC         20000
#   define PJMEDIA_CONF_SWITCH_BOARD_BUF_SIZE    PJMEDIA_MAX_MTU
#   define PJMEDIA_CONF_USE_AGC    	    1
#   define PJMEDIA_CONF_USE_SWITCH_BOARD    0
#   define PJMEDIA_MAX_FRAME_DURATION_MS   	200
#   define PJMEDIA_MAX_PLC_DURATION_MSEC    240
#     define PJMEDIA_MAX_VID_PAYLOAD_SIZE     (PJMEDIA_MAX_MTU - 20 - (128+16))
#   define PJMEDIA_SND_DEFAULT_REC_LATENCY  100
#   define PJMEDIA_SRTP_CHECK_ROC_ON_RESTART        1
#   define PJMEDIA_SRTP_CHECK_RTP_SEQ_ON_RESTART    1
#   define PJMEDIA_SRTP_HAS_AES_CM_128    	    1
#   define PJMEDIA_SRTP_HAS_AES_GCM_128    	    0
#   define PJMEDIA_STREAM_START_KA_INTERVAL_MSEC  1000
#   define PJMEDIA_TELEPHONE_EVENT_ALL_CLOCKRATES   1
#   define PJMEDIA_TONEGEN_FIXED_POINT_CORDIC_LOOP  10
#   define PJMEDIA_TRANSPORT_SPECIFIC_INFO_MAXCNT   4
#   define PJMEDIA_TRANSPORT_SPECIFIC_INFO_MAXSIZE  (50*sizeof(long))
#   define PJMEDIA_VID_STREAM_MIN_KEYFRAME_INTERVAL_MSEC    1000
#   define PJMEDIA_VID_STREAM_START_KEYFRAME_INTERVAL_MSEC  1000
#   define PJMEDIA_WEBRTC_AEC_USE_MOBILE 	0
#   define PJMEDIA_WSOLA_IMP		    PJMEDIA_WSOLA_IMP_WSOLA
#   define PJMEDIA_WSOLA_MAX_EXPAND_MSEC    80

#define PJMEDIA_CODEC_EBADBITSTREAM (PJMEDIA_ERRNO_START+87)    
#define PJMEDIA_CODEC_EFRMTOOSHORT  (PJMEDIA_ERRNO_START+82)    
#define PJMEDIA_CODEC_EPCMFRMINLEN  (PJMEDIA_ERRNO_START+85)    
#define PJMEDIA_CODEC_EPCMTOOSHORT  (PJMEDIA_ERRNO_START+83)    
#define PJMEDIA_EBADFMT             (PJMEDIA_ERRNO_START+108)    
#define PJMEDIA_EINVALIMEDIATYPE    (PJMEDIA_ERRNO_START+104)    
#define PJMEDIA_ENCSAMPLESPFRAME    (PJMEDIA_ERRNO_START+162)    
#define PJMEDIA_ERRNO_END         (PJMEDIA_ERRNO_START + PJ_ERRNO_SPACE_SIZE - 1)
#define PJMEDIA_ERRNO_FROM_LIBSRTP(err)   (PJMEDIA_LIBSRTP_ERRNO_START+err)
#define PJMEDIA_ERRNO_FROM_PORTAUDIO(err)   ((int)PJMEDIA_PORTAUDIO_ERRNO_START-err)
#define PJMEDIA_ERRNO_START       (PJ_ERRNO_START_USER + PJ_ERRNO_SPACE_SIZE)
#define PJMEDIA_EUNSUPMEDIATYPE     (PJMEDIA_ERRNO_START+109)    
#define PJMEDIA_LIBSRTP_ERRNO_END   (PJMEDIA_LIBSRTP_ERRNO_START + 200 - 1)
#define PJMEDIA_LIBSRTP_ERRNO_START (PJMEDIA_ERRNO_END-10200)
#define PJMEDIA_PORTAUDIO_ERRNO_END   (PJMEDIA_PORTAUDIO_ERRNO_START + 10000 -1)
#define PJMEDIA_PORTAUDIO_ERRNO_START (PJMEDIA_ERRNO_END-10000)
#define PJMEDIA_RTP_EREMNORFC2833   (PJMEDIA_ERRNO_START+107)    
#define PJMEDIA_RTP_ESESSPROBATION  (PJMEDIA_ERRNO_START+131)    
#define PJMEDIA_RTP_ESESSRESTART    (PJMEDIA_ERRNO_START+130)    
#define PJMEDIA_SDPNEG_EANSNOMEDIA  (PJMEDIA_ERRNO_START+47)    
#define PJMEDIA_SDPNEG_EINVANSMEDIA (PJMEDIA_ERRNO_START+45)    
#define PJMEDIA_SDPNEG_EINVANSTP    (PJMEDIA_ERRNO_START+46)    
#define PJMEDIA_SDPNEG_EMISMEDIA    (PJMEDIA_ERRNO_START+44)    
#define PJMEDIA_SDPNEG_ENOACTIVE    (PJMEDIA_ERRNO_START+42)    
#define PJMEDIA_SDPNEG_ENOINITIAL   (PJMEDIA_ERRNO_START+41)    
#define PJMEDIA_SDPNEG_NOANSCODEC   (PJMEDIA_ERRNO_START+49)    
#define PJMEDIA_SDPNEG_NOANSTELEVENT (PJMEDIA_ERRNO_START+50)   
#define PJMEDIA_SDPNEG_NOANSUNKNOWN (PJMEDIA_ERRNO_START+51)    
#define PJMEDIA_SDP_EATTRNOTEQUAL   (PJMEDIA_ERRNO_START+65)    
#define PJMEDIA_SDP_ECONNNOTEQUAL   (PJMEDIA_ERRNO_START+64)    
#define PJMEDIA_SDP_EDIRNOTEQUAL    (PJMEDIA_ERRNO_START+66)    
#define PJMEDIA_SDP_EFMTPNOTEQUAL   (PJMEDIA_ERRNO_START+67)    
#define PJMEDIA_SDP_EFORMATNOTEQUAL (PJMEDIA_ERRNO_START+63)    
#define PJMEDIA_SDP_EMEDIANOTEQUAL  (PJMEDIA_ERRNO_START+60)    
#define PJMEDIA_SDP_EMISSINGCONN    (PJMEDIA_ERRNO_START+26)    
#define PJMEDIA_SDP_EMISSINGRTPMAP  (PJMEDIA_ERRNO_START+30)    
#define PJMEDIA_SDP_ENAMENOTEQUAL   (PJMEDIA_ERRNO_START+71)    
#define PJMEDIA_SDP_EORIGINNOTEQUAL (PJMEDIA_ERRNO_START+70)    
#define PJMEDIA_SDP_EPORTNOTEQUAL   (PJMEDIA_ERRNO_START+61)    
#define PJMEDIA_SDP_ERTPMAPNOTEQUAL (PJMEDIA_ERRNO_START+68)    
#define PJMEDIA_SDP_ERTPMAPTOOLONG  (PJMEDIA_ERRNO_START+29)    
#define PJMEDIA_SDP_ESESSNOTEQUAL   (PJMEDIA_ERRNO_START+69)    
#define PJMEDIA_SDP_ETIMENOTEQUAL   (PJMEDIA_ERRNO_START+72)    
#define PJMEDIA_SDP_ETPORTNOTEQUAL  (PJMEDIA_ERRNO_START+62)    
#define PJMEDIA_SRTP_DTLS_EFPNOTMATCH (PJMEDIA_ERRNO_START+242)  
#define PJMEDIA_SRTP_DTLS_ENOCRYPTO (PJMEDIA_ERRNO_START+240)    
#define PJMEDIA_SRTP_DTLS_ENOFPRINT (PJMEDIA_ERRNO_START+243)	
#define PJMEDIA_SRTP_DTLS_ENOPROFILE (PJMEDIA_ERRNO_START+244)   
#define PJMEDIA_SRTP_DTLS_EPEERNOCERT (PJMEDIA_ERRNO_START+241)  
#define PJMEDIA_SRTP_ECRYPTONOTMATCH (PJMEDIA_ERRNO_START+220)   
#define PJMEDIA_SRTP_EKEYNOTREADY   (PJMEDIA_ERRNO_START+230)	 
#define PJMEDIA_SRTP_ENOTSUPCRYPTO  (PJMEDIA_ERRNO_START+222)    
#define PJMEDIA_SRTP_ESDPAMBIGUEANS (PJMEDIA_ERRNO_START+223)    
#define PJMEDIA_SRTP_ESDPDUPCRYPTOTAG (PJMEDIA_ERRNO_START+224)  
#define PJMEDIA_SRTP_ESDPINCRYPTO   (PJMEDIA_ERRNO_START+225)    
#define PJMEDIA_SRTP_ESDPINCRYPTOTAG (PJMEDIA_ERRNO_START+226)   
#define PJMEDIA_SRTP_ESDPINTRANSPORT (PJMEDIA_ERRNO_START+227)   
#define PJMEDIA_SRTP_ESDPREQCRYPTO  (PJMEDIA_ERRNO_START+228)    
#define PJMEDIA_SRTP_ESDPREQSECTP   (PJMEDIA_ERRNO_START+229)    



#define PJMEDIA_PORT_SIG(a,b,c,d)	    	PJMEDIA_OBJ_SIG(a,b,c,d)

#define PJMEDIA_SIGNATURE(a,b,c,d)	PJMEDIA_FOURCC(d,c,b,a)
#define PJMEDIA_SIG_CLASS_APP(b,c,d)	PJMEDIA_SIGNATURE('A',b,c,d)
#define PJMEDIA_SIG_CLASS_AUD_CODEC(c,d) PJMEDIA_SIG_CLASS_CODEC('A',c,d)
#define PJMEDIA_SIG_CLASS_CODEC(b,c,d)	PJMEDIA_SIGNATURE('C',b,c,d)
#define PJMEDIA_SIG_CLASS_PORT(b,c,d)	PJMEDIA_SIGNATURE('P',b,c,d)
#define PJMEDIA_SIG_CLASS_PORT_AUD(c,d)	PJMEDIA_SIG_CLASS_PORT('A',c,d)
#define PJMEDIA_SIG_CLASS_PORT_VID(c,d)	PJMEDIA_SIG_CLASS_PORT('V',c,d)
#define PJMEDIA_SIG_CLASS_VID_CODEC(c,d) PJMEDIA_SIG_CLASS_CODEC('V',c,d)
#define PJMEDIA_SIG_CLASS_VID_DEV(c,d)	PJMEDIA_SIGNATURE('V','D',c,d)
#define PJMEDIA_SIG_CLASS_VID_OTHER(c,d) PJMEDIA_SIGNATURE('V','O',c,d)
#define PJMEDIA_SIG_IS_CLASS_APP(s)	((s)>>24=='A')
#define PJMEDIA_SIG_IS_CLASS_AUD_CODEC(s) ((s)>>24=='C' && (((s)>>16)&0xff)=='A')
#define PJMEDIA_SIG_IS_CLASS_CODEC(sig)	((sig) >> 24 == 'C')
#define PJMEDIA_SIG_IS_CLASS_PORT(sig)	((sig) >> 24 == 'P')
#define PJMEDIA_SIG_IS_CLASS_PORT_AUD(s) ((s)>>24=='P' && (((s)>>16)&0xff)=='A')
#define PJMEDIA_SIG_IS_CLASS_PORT_VID(s) ((s)>>24=='P' && (((s)>>16)&0xff)=='V')
#define PJMEDIA_SIG_IS_CLASS_VID_CODEC(sig) ((s)>>24=='C' && (((s)>>16)&0xff)=='V')
#define PJMEDIA_SIG_IS_CLASS_VID_DEV(s) ((s)>>24=='V' && (((s)>>16)&0xff)=='D')
#define PJMEDIA_SIG_IS_CLASS_VID_OTHER(s) ((s)>>24=='V' && (((s)>>16)&0xff)=='O')


#define PJMEDIA_FORMAT_PACK(C1, C2, C3, C4) PJMEDIA_FOURCC(C1, C2, C3, C4)



#define PJMEDIA_VIDEODEV_ERRNO_END   \
	    (PJMEDIA_VIDEODEV_ERRNO_START + PJ_ERRNO_SPACE_SIZE - 1)
#define PJMEDIA_VIDEODEV_ERRNO_START \
	    (PJ_ERRNO_START_USER + PJ_ERRNO_SPACE_SIZE*7)

#       define PJMEDIA_VID_DEV_INFO_FMT_CNT 128
#   define PJMEDIA_VID_DEV_MAX_DEVS 16
#   define PJMEDIA_VID_DEV_MAX_DRIVERS 8




#define PJMEDIA_RTP_DTMF_EVENT_END_MASK     0x80
#define PJMEDIA_RTP_DTMF_EVENT_VOLUME_MASK  0x3F

#define PJMEDIA_RTCP_XR_BUF_SIZE \
    sizeof(pjmedia_rtcp_xr_rb_rr_time) + \
    sizeof(pjmedia_rtcp_xr_rb_dlrr) + \
    sizeof(pjmedia_rtcp_xr_rb_stats) + \
    sizeof(pjmedia_rtcp_xr_rb_voip_mtc)

#define PJMEDIA_AUD_DEFAULT_CAPTURE_DEV  -1
#define PJMEDIA_AUD_DEFAULT_PLAYBACK_DEV -2

#define PJMEDIA_AUDIODEV_COREAUDIO_ERRNO_END   \
	    (PJMEDIA_AUDIODEV_COREAUDIO_ERRNO_START + 20000 -1)
#define PJMEDIA_AUDIODEV_COREAUDIO_ERRNO_START \
	    (PJMEDIA_AUDIODEV_ERRNO_START+20000)
#define PJMEDIA_AUDIODEV_ERRNO_END   \
	    (PJMEDIA_AUDIODEV_ERRNO_START + PJ_ERRNO_SPACE_SIZE - 1)
#define PJMEDIA_AUDIODEV_ERRNO_FROM_BDIMAD(err) \
	    ((int)PJMEDIA_AUDIODEV_BDIMAD_ERROR_START+err)
#define PJMEDIA_AUDIODEV_ERRNO_FROM_COREAUDIO(err) \
	    ((int)PJMEDIA_AUDIODEV_COREAUDIO_ERRNO_START-err)
#define PJMEDIA_AUDIODEV_ERRNO_FROM_PORTAUDIO(err) \
	    ((int)PJMEDIA_AUDIODEV_PORTAUDIO_ERRNO_START-err)
#define PJMEDIA_AUDIODEV_ERRNO_FROM_WMME_IN(err) \
	    ((int)PJMEDIA_AUDIODEV_WMME_IN_ERROR_START+err)
#define PJMEDIA_AUDIODEV_ERRNO_FROM_WMME_OUT(err) \
	    ((int)PJMEDIA_AUDIODEV_WMME_OUT_ERROR_START+err)
#define PJMEDIA_AUDIODEV_ERRNO_START \
	    (PJ_ERRNO_START_USER + PJ_ERRNO_SPACE_SIZE*5)
#define PJMEDIA_AUDIODEV_PORTAUDIO_ERRNO_END   \
	    (PJMEDIA_AUDIODEV_PORTAUDIO_ERRNO_START + 10000 -1)
#define PJMEDIA_AUDIODEV_PORTAUDIO_ERRNO_START \
	    (PJMEDIA_AUDIODEV_ERRNO_END-10000)
#define PJMEDIA_EAUD_WASAPI_ERROR \
				(PJMEDIA_AUDIODEV_ERRNO_START+13) 

#   define PJMEDIA_AUDIO_DEV_HAS_ANDROID_JNI    PJ_ANDROID
#   define PJMEDIA_AUDIO_DEV_SYMB_APS_DETECTS_CODEC 1






