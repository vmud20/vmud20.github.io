#include<string.h>
#include<stdlib.h>
#include<inttypes.h>

#   define lprintf printf

#define CONT_TAG  FOURCC_TAG('C', 'O', 'N', 'T')
#define DATA_TAG  FOURCC_TAG('D', 'A', 'T', 'A')
#define FOURCC_TAG( ch0, ch1, ch2, ch3 ) \
        (((long)(unsigned char)(ch3)       ) | \
        ( (long)(unsigned char)(ch2) << 8  ) | \
        ( (long)(unsigned char)(ch1) << 16 ) | \
        ( (long)(unsigned char)(ch0) << 24 ) )

#define INDX_TAG  FOURCC_TAG('I', 'N', 'D', 'X')
#define MDPR_TAG  FOURCC_TAG('M', 'D', 'P', 'R')
#define MLTI_TAG  FOURCC_TAG('M', 'L', 'T', 'I')
#define PNA_TAG   FOURCC_TAG('P', 'N', 'A',  0 )
#define PN_LIVE_BROADCAST       0x04
#define PN_PERFECT_PLAY_ENABLED 0x02
#define PN_SAVE_ENABLED         0x01
#define PROP_TAG  FOURCC_TAG('P', 'R', 'O', 'P')
#define RMFF_HEADER_SIZE 0x12
#define RMF_TAG   FOURCC_TAG('.', 'R', 'M', 'F')

#define RTSP_STATUS_OK            200
#define RTSP_STATUS_SET_PARAMETER  10
#define LICENSE_MSG \
  _("This program comes with NO WARRANTY, to the extent permitted by " \
    "law.\nYou may redistribute it under the terms of the GNU General " \
    "Public License;\nsee the file named COPYING for details.\n" \
    "Written by the VideoLAN team; see the AUTHORS file.\n")
#define PLAYLIST_APPEND          0x0002
#define PLAYLIST_END           -666
#define PLAYLIST_GO              0x0004
#define PLAYLIST_INSERT          0x0001
#define PLAYLIST_NO_REBUILD      0x0020
#define PLAYLIST_PREPARSE        0x0008
#define PLAYLIST_SPREPARSE       0x0010
#define VLC_EBADOBJ        -21                            
#define VLC_EBADVAR        -31                         
#define VLC_EEXIT         -255                             
#define VLC_EEXITSUCCESS  -999                
#define VLC_EGENERIC      -666                              
#define VLC_ENOITEM        -40                           
#define VLC_ENOMEM          -1                          
#define VLC_ENOMOD         -10                           
#define VLC_ENOOBJ         -20                           
#define VLC_ENOVAR         -30                         
#define VLC_ETHREAD         -2                               
#define VLC_ETIMEOUT        -3                                    
#define VLC_FALSE 0
#  define VLC_PUBLIC_API extern
#define VLC_SUCCESS         -0                                   
#define VLC_TRUE  1
#define VLC_VAR_ADDRESS   0x0070
#define VLC_VAR_BOOL      0x0020
#define VLC_VAR_DIRECTORY 0x0043
#define VLC_VAR_FILE      0x0042
#define VLC_VAR_FLOAT     0x0050
#define VLC_VAR_HOTKEY    0x0031
#define VLC_VAR_INTEGER   0x0030
#define VLC_VAR_LIST      0x0090
#define VLC_VAR_MODULE    0x0041
#define VLC_VAR_MUTEX     0x0080
#define VLC_VAR_STRING    0x0040
#define VLC_VAR_TIME      0x0060
#define VLC_VAR_VARIABLE  0x0044
#define VLC_VAR_VOID      0x0010
#define _VLC_VLC_H 1
