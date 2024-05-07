#include<sys/stat.h>

#include<stdint.h>
#include<inttypes.h>

#include<dirent.h>
#include<stdarg.h>
#include<syslog.h>

#include<stdlib.h>


#include<byteswap.h>
#include<alloca.h>
#include<stdbool.h>
#include<endian.h>

#include<sys/ioctl.h>

#include<netinet/in.h>
#include<string.h>


#include<stdio.h>
#include<sys/file.h>

#include<sys/uio.h>
#include<errno.h>

#include<unistd.h>
#define EIR_BREDR_UNSUP             0x04 
#define EIR_CLASS_OF_DEV            0x0D  
#define EIR_CONTROLLER              0x08 
#define EIR_DEVICE_ID               0x10  
#define EIR_FLAGS                   0x01  
#define EIR_GAP_APPEARANCE          0x19  
#define EIR_GEN_DISC                0x02 
#define EIR_LIM_DISC                0x01 
#define EIR_MANUFACTURER_DATA       0xFF  
#define EIR_MSD_MAX_LEN             236  
#define EIR_NAME_COMPLETE           0x09  
#define EIR_NAME_SHORT              0x08  
#define EIR_PUB_TRGT_ADDR           0x17  
#define EIR_RND_TRGT_ADDR           0x18  
#define EIR_SD_MAX_LEN              238  
#define EIR_SIM_HOST                0x10 
#define EIR_SOLICIT128              0x15  
#define EIR_SOLICIT16               0x14  
#define EIR_SOLICIT32               0x1F  
#define EIR_SSP_HASH                0x0E  
#define EIR_SSP_RANDOMIZER          0x0F  
#define EIR_SVC_DATA128             0x21  
#define EIR_SVC_DATA16              0x16  
#define EIR_SVC_DATA32              0x20  
#define EIR_TRANSPORT_DISCOVERY     0x26  
#define EIR_TX_POWER                0x0A  
#define EIR_UUID128_ALL             0x07  
#define EIR_UUID128_SOME            0x06  
#define EIR_UUID16_ALL              0x03  
#define EIR_UUID16_SOME             0x02  
#define EIR_UUID32_ALL              0x05  
#define EIR_UUID32_SOME             0x04  
#define SDP_IS_ALT(x)  ((x) == SDP_ALT8 || (x) == SDP_ALT16 || (x) == SDP_ALT32)
#define SDP_IS_SEQ(x)  ((x) == SDP_SEQ8 || (x) == SDP_SEQ16 || (x) == SDP_SEQ32)
#define SDP_IS_TEXT_STR(x) ((x) == SDP_TEXT_STR8 || (x) == SDP_TEXT_STR16 || \
							(x) == SDP_TEXT_STR32)
#define SDP_IS_UUID(x) ((x) == SDP_UUID16 || (x) == SDP_UUID32 || \
							(x) == SDP_UUID128)
#define SDP_UNIX_PATH "/var/run/sdp"


#define MAX_LEN_UUID_STR 37

#define BDADDR_ALL   (&(bdaddr_t) {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}})
#define BDADDR_ANY   (&(bdaddr_t) {{0, 0, 0, 0, 0, 0}})
#define BDADDR_BREDR           0x00
#define BDADDR_LE_PUBLIC       0x01
#define BDADDR_LE_RANDOM       0x02
#define BDADDR_LOCAL (&(bdaddr_t) {{0, 0, 0, 0xff, 0xff, 0xff}})
#define BT_POWER_FORCE_ACTIVE_OFF 0
#define BT_POWER_FORCE_ACTIVE_ON  1

#define bt_get_unaligned(ptr)			\
__extension__ ({				\
	struct __attribute__((packed)) {	\
		__typeof__(*(ptr)) __v;		\
	} *__p = (__typeof__(__p)) (ptr);	\
	__p->__v;				\
})
#define bt_put_unaligned(val, ptr)		\
do {						\
	struct __attribute__((packed)) {	\
		__typeof__(*(ptr)) __v;		\
	} *__p = (__typeof__(__p)) (ptr);	\
	__p->__v = (val);			\
} while(0)
#define btohl(d)  (d)
#define btohll(d) (d)
#define btohs(d)  (d)
#define htob128(x, y) btoh128(x, y)
#define htobl(d)  (d)
#define htobll(d) (d)
#define htobs(d)  (d)
#define hton128(x, y) ntoh128(x, y)
#define hton64(x)     ntoh64(x)
#define ntoh64(x) (x)
#define GATTRIB_ALL_HANDLES 0x0000
#define GATTRIB_ALL_REQS 0xFE

#define ERROR_INTERFACE "org.bluez.Error"
#define SDPDBG(fmt, arg...) syslog(LOG_DEBUG, "%s: " fmt "\n", __func__ , ## arg)
#define SDP_SERVER_COMPAT (1 << 0)
#define SDP_SERVER_MASTER (1 << 1)
#define BT_IO_ERROR bt_io_error_quark()

#define bt_att_chan_send_rsp(chan, opcode, pdu, len) \
	bt_att_chan_send(chan, opcode, pdu, len, NULL, NULL, NULL)
#define BT_ATT_ALL_REQUESTS 0x00
#define BT_ERROR_ALREADY_IN_PROGRESS            0xfe
#define BT_ERROR_CCC_IMPROPERLY_CONFIGURED      0xfd
#define BT_ERROR_OUT_OF_RANGE                   0xff
#define __packed __attribute__((packed))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define BIT(n)  (1 << (n))
#define INT_TO_PTR(u) ((void *) ((intptr_t) (u)))
#define PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define PTR_TO_UINT(p) ((unsigned int) ((uintptr_t) (p)))
#define UINT_TO_PTR(u) ((void *) ((uintptr_t) (u)))
#define be16_to_cpu(val) bswap_16(val)
#define be32_to_cpu(val) bswap_32(val)
#define be64_to_cpu(val) bswap_64(val)
#define cpu_to_be16(val) bswap_16(val)
#define cpu_to_be32(val) bswap_32(val)
#define cpu_to_be64(val) bswap_64(val)
#define cpu_to_le16(val) (val)
#define cpu_to_le32(val) (val)
#define cpu_to_le64(val) (val)
#define get_unaligned(ptr)			\
__extension__ ({				\
	struct __attribute__((packed)) {	\
		__typeof__(*(ptr)) __v;		\
	} *__p = (__typeof__(__p)) (ptr);	\
	__p->__v;				\
})
#define le16_to_cpu(val) (val)
#define le32_to_cpu(val) (val)
#define le64_to_cpu(val) (val)
#define malloc0(n) (calloc((n), 1))
#define new0(type, count)			\
	(type *) (__extension__ ({		\
		size_t __n = (size_t) (count);	\
		size_t __s = sizeof(type);	\
		void *__p;			\
		__p = btd_malloc(__n * __s);	\
		memset(__p, 0, __n * __s);	\
		__p;				\
	}))
#define newa(t, n) ((t*) alloca(sizeof(t)*(n)))
#define put_unaligned(val, ptr)			\
do {						\
	struct __attribute__((packed)) {	\
		__typeof__(*(ptr)) __v;		\
	} *__p = (__typeof__(__p)) (ptr);	\
	__p->__v = (val);			\
} while (0)
#define MGMT_VERSION(v, r) (((v) << 16) + (r))
#define mgmt_tlv_add_fixed(_list, _type, _value) \
	mgmt_tlv_add(_list, _type, sizeof(*(_value)), _value)
#define BTD_DEBUG_FLAG_DEFAULT (0)
#define BTD_DEBUG_FLAG_PRINT   (1 << 0)
#define DBG(fmt, arg...) DBG_IDX(0xffff, fmt, ## arg)
#define DBG_IDX(idx, fmt, arg...) do { \
	static struct btd_debug_desc __btd_debug_desc \
	__attribute__((used, section("__debug"), aligned(8))) = { \
		.file = "__FILE__", .flags = BTD_DEBUG_FLAG_DEFAULT, \
	}; \
	if (__btd_debug_desc.flags & BTD_DEBUG_FLAG_PRINT) \
		btd_debug(idx, "%s:%s() " fmt, "__FILE__", __func__ , ## arg); \
} while (0)
#define error(fmt, arg...) \
	btd_error(0xffff, "%s:%s() " fmt, "__FILE__", __func__, ## arg)
#define warn(fmt, arg...) \
	btd_warn(0xffff, "%s:%s() " fmt, "__FILE__", __func__, ## arg)
#define GDBUS_ARGS(args...) (const GDBusArgInfo[]) { args, { } }
#define GDBUS_ASYNC_METHOD(_name, _in_args, _out_args, _function) \
	.name = _name, \
	.in_args = _in_args, \
	.out_args = _out_args, \
	.function = _function, \
	.flags = G_DBUS_METHOD_FLAG_ASYNC
#define GDBUS_DEPRECATED_ASYNC_METHOD(_name, _in_args, _out_args, _function) \
	.name = _name, \
	.in_args = _in_args, \
	.out_args = _out_args, \
	.function = _function, \
	.flags = G_DBUS_METHOD_FLAG_ASYNC | G_DBUS_METHOD_FLAG_DEPRECATED
#define GDBUS_DEPRECATED_METHOD(_name, _in_args, _out_args, _function) \
	.name = _name, \
	.in_args = _in_args, \
	.out_args = _out_args, \
	.function = _function, \
	.flags = G_DBUS_METHOD_FLAG_DEPRECATED
#define GDBUS_DEPRECATED_SIGNAL(_name, _args) \
	.name = _name, \
	.args = _args, \
	.flags = G_DBUS_SIGNAL_FLAG_DEPRECATED
#define GDBUS_EXPERIMENTAL_ASYNC_METHOD(_name, _in_args, _out_args, _function) \
	.name = _name, \
	.in_args = _in_args, \
	.out_args = _out_args, \
	.function = _function, \
	.flags = G_DBUS_METHOD_FLAG_ASYNC | G_DBUS_METHOD_FLAG_EXPERIMENTAL
#define GDBUS_EXPERIMENTAL_METHOD(_name, _in_args, _out_args, _function) \
	.name = _name, \
	.in_args = _in_args, \
	.out_args = _out_args, \
	.function = _function, \
	.flags = G_DBUS_METHOD_FLAG_EXPERIMENTAL
#define GDBUS_EXPERIMENTAL_SIGNAL(_name, _args) \
	.name = _name, \
	.args = _args, \
	.flags = G_DBUS_SIGNAL_FLAG_EXPERIMENTAL
#define GDBUS_METHOD(_name, _in_args, _out_args, _function) \
	.name = _name, \
	.in_args = _in_args, \
	.out_args = _out_args, \
	.function = _function
#define GDBUS_NOREPLY_METHOD(_name, _in_args, _out_args, _function) \
	.name = _name, \
	.in_args = _in_args, \
	.out_args = _out_args, \
	.function = _function, \
	.flags = G_DBUS_METHOD_FLAG_NOREPLY
#define GDBUS_SIGNAL(_name, _args) \
	.name = _name, \
	.args = _args

#define MGMT_PHY_LE_RX_MASK (MGMT_PHY_LE_1M_RX | MGMT_PHY_LE_2M_RX | \
			     MGMT_PHY_LE_CODED_RX)
#define MGMT_PHY_LE_TX_MASK (MGMT_PHY_LE_1M_TX | MGMT_PHY_LE_2M_TX | \
			     MGMT_PHY_LE_CODED_TX)
#define NELEM(x) (sizeof(x) / sizeof((x)[0]))
#define __packed __attribute__((packed))
