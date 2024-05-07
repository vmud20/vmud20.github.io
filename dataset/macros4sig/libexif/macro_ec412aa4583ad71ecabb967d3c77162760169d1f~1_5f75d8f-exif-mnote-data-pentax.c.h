





#include<stdlib.h>


#include<stdarg.h>


#include<stdio.h>



#include<string.h>
#define EXIF_TAG_SUBSEC_TIME EXIF_TAG_SUB_SEC_TIME
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))






#define exif_data_get_entry(d,t)					\
	(exif_content_get_entry(d->ifd[EXIF_IFD_0],t) ?			\
	 exif_content_get_entry(d->ifd[EXIF_IFD_0],t) :			\
	 exif_content_get_entry(d->ifd[EXIF_IFD_1],t) ?			\
	 exif_content_get_entry(d->ifd[EXIF_IFD_1],t) :			\
	 exif_content_get_entry(d->ifd[EXIF_IFD_EXIF],t) ?		\
	 exif_content_get_entry(d->ifd[EXIF_IFD_EXIF],t) :		\
	 exif_content_get_entry(d->ifd[EXIF_IFD_GPS],t) ?		\
	 exif_content_get_entry(d->ifd[EXIF_IFD_GPS],t) :		\
	 exif_content_get_entry(d->ifd[EXIF_IFD_INTEROPERABILITY],t) ?	\
	 exif_content_get_entry(d->ifd[EXIF_IFD_INTEROPERABILITY],t) : NULL)

#define EXIF_LOG_NO_MEMORY(l,d,s) exif_log ((l), EXIF_LOG_CODE_NO_MEMORY, (d), "Could not allocate %lu byte(s).", (unsigned long)(s))

#define exif_log (void)

#define exif_content_get_value(c,t,v,m)					\
	(exif_content_get_entry (c,t) ?					\
	 exif_entry_get_value (exif_content_get_entry (c,t),v,m) : NULL)

#define exif_entry_get_ifd(e) ((e)?exif_content_get_ifd((e)->parent):EXIF_IFD_COUNT)
#define EXIF_TAG_GPS_ALTITUDE          0x0006
#define EXIF_TAG_GPS_ALTITUDE_REF      0x0005
#define EXIF_TAG_GPS_AREA_INFORMATION   0x001c
#define EXIF_TAG_GPS_DATE_STAMP         0x001d
#define EXIF_TAG_GPS_DEST_BEARING       0x0018
#define EXIF_TAG_GPS_DEST_BEARING_REF   0x0017
#define EXIF_TAG_GPS_DEST_DISTANCE      0x001a
#define EXIF_TAG_GPS_DEST_DISTANCE_REF  0x0019
#define EXIF_TAG_GPS_DEST_LATITUDE     0x0014
#define EXIF_TAG_GPS_DEST_LATITUDE_REF 0x0013
#define EXIF_TAG_GPS_DEST_LONGITUDE     0x0016
#define EXIF_TAG_GPS_DEST_LONGITUDE_REF 0x0015
#define EXIF_TAG_GPS_DIFFERENTIAL       0x001e
#define EXIF_TAG_GPS_DOP               0x000b
#define EXIF_TAG_GPS_H_POSITIONING_ERROR 0x001f
#define EXIF_TAG_GPS_IMG_DIRECTION     0x0011
#define EXIF_TAG_GPS_IMG_DIRECTION_REF 0x0010
#define EXIF_TAG_GPS_LATITUDE          0x0002 
#define EXIF_TAG_GPS_LATITUDE_REF      0x0001 
#define EXIF_TAG_GPS_LONGITUDE         0x0004
#define EXIF_TAG_GPS_LONGITUDE_REF     0x0003
#define EXIF_TAG_GPS_MAP_DATUM         0x0012
#define EXIF_TAG_GPS_MEASURE_MODE      0x000a
#define EXIF_TAG_GPS_PROCESSING_METHOD  0x001b
#define EXIF_TAG_GPS_SATELLITES        0x0008
#define EXIF_TAG_GPS_SPEED             0x000d
#define EXIF_TAG_GPS_SPEED_REF         0x000c
#define EXIF_TAG_GPS_STATUS            0x0009
#define EXIF_TAG_GPS_TIME_STAMP        0x0007
#define EXIF_TAG_GPS_TRACK             0x000f
#define EXIF_TAG_GPS_TRACK_REF         0x000e
#define EXIF_TAG_GPS_VERSION_ID        0x0000
#define EXIF_TAG_UNKNOWN_C4A5 EXIF_TAG_PRINT_IMAGE_MATCHING






