#include<stdio.h>
#include<endian.h>
#include<unistd.h>
#include<errno.h>
#include<string.h>
#include<stdlib.h>
#include<alloca.h>
#include<netinet/in.h>
#include<stdint.h>

#include<sys/socket.h>
#include<byteswap.h>
#include<sys/uio.h>
#include<stdbool.h>
#define bt_att_chan_send_rsp(chan, opcode, pdu, len) \
	bt_att_chan_send(chan, opcode, pdu, len, NULL, NULL, NULL)
#define BT_ATT_ALL_REQUESTS 0x00
#define BT_ERROR_ALREADY_IN_PROGRESS            0xfe
#define BT_ERROR_CCC_IMPROPERLY_CONFIGURED      0xfd
#define BT_ERROR_OUT_OF_RANGE                   0xff
#define __packed __attribute__((packed))
#define MAX_LEN_UUID_STR 37

#define L2CAP_CMD_HDR_SIZE 4
#define L2CAP_CMD_REJ_SIZE 2
#define L2CAP_CONF_OPT_SIZE 2
#define L2CAP_CONF_REQ_SIZE 4
#define L2CAP_CONF_RSP_SIZE 6
#define L2CAP_CONN_REQ_SIZE 4
#define L2CAP_CONN_RSP_SIZE 8
#define L2CAP_CREATE_REQ_SIZE 5
#define L2CAP_CREATE_RSP_SIZE 8
#define L2CAP_DISCONN_REQ_SIZE 4
#define L2CAP_DISCONN_RSP_SIZE 4
#define L2CAP_HDR_SIZE 4
#define L2CAP_INFO_REQ_SIZE 2
#define L2CAP_INFO_RSP_SIZE 4
#define L2CAP_MOVE_CFM_RSP_SIZE 2
#define L2CAP_MOVE_CFM_SIZE 4
#define L2CAP_MOVE_REQ_SIZE 3
#define L2CAP_MOVE_RSP_SIZE 4

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
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
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
