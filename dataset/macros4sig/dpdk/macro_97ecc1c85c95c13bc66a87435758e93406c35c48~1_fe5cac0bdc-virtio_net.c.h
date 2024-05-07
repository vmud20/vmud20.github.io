

#include<sys/socket.h>


#include<linux/virtio_net.h>

#include<sys/types.h>

#include<stdio.h>




#include<sys/queue.h>


#include<stdint.h>
#include<sys/eventfd.h>
#include<unistd.h>



#include<linux/virtio_ring.h>


#include<linux/vhost.h>
#include<stdbool.h>
#include<linux/if.h>
#define BUF_VECTOR_MAX 256
#define IF_NAME_SZ (PATH_MAX > IFNAMSIZ ? PATH_MAX : IFNAMSIZ)
#define PACKED_BATCH_MASK (PACKED_BATCH_SIZE - 1)
#define PACKED_BATCH_SIZE (RTE_CACHE_LINE_SIZE / \
			    sizeof(struct vring_packed_desc))
#define PACKED_DESC_DEQUEUE_USED_FLAG(w)	\
	((w) ? (VRING_DESC_F_AVAIL | VRING_DESC_F_USED) : 0x0)
#define PACKED_DESC_ENQUEUE_USED_FLAG(w)	\
	((w) ? (VRING_DESC_F_AVAIL | VRING_DESC_F_USED | VRING_DESC_F_WRITE) : \
		VRING_DESC_F_WRITE)
#define PACKED_DESC_SINGLE_DEQUEUE_FLAG (VRING_DESC_F_NEXT | \
					 VRING_DESC_F_INDIRECT)
#define PRINT_PACKET(device, addr, size, header) do { \
	char *pkt_addr = (char *)(addr); \
	unsigned int index; \
	char packet[VHOST_MAX_PRINT_BUFF]; \
	\
	if ((header)) \
		snprintf(packet, VHOST_MAX_PRINT_BUFF, "(%d) Header size %d: ", (device->vid), (size)); \
	else \
		snprintf(packet, VHOST_MAX_PRINT_BUFF, "(%d) Packet size %d: ", (device->vid), (size)); \
	for (index = 0; index < (size); index++) { \
		snprintf(packet + strnlen(packet, VHOST_MAX_PRINT_BUFF), VHOST_MAX_PRINT_BUFF - strnlen(packet, VHOST_MAX_PRINT_BUFF), \
			"%02hhx ", pkt_addr[index]); \
	} \
	snprintf(packet + strnlen(packet, VHOST_MAX_PRINT_BUFF), VHOST_MAX_PRINT_BUFF - strnlen(packet, VHOST_MAX_PRINT_BUFF), "\n"); \
	\
	VHOST_LOG_DATA(DEBUG, "%s", packet); \
} while (0)
#define VHOST_ACCESS_RO      0x1
#define VHOST_ACCESS_RW      0x3
#define VHOST_ACCESS_WO      0x2
#define VHOST_BINARY_SEARCH_THRESH 256
#define VHOST_IOTLB_ACCESS_FAIL    4
#define VHOST_IOTLB_INVALIDATE     3
#define VHOST_IOTLB_MISS           1
#define VHOST_IOTLB_MSG 0x1
#define VHOST_IOTLB_UPDATE         2
#define VHOST_LOG_CACHE_NR 32
#define VHOST_LOG_CONFIG(level, fmt, args...)			\
	rte_log(RTE_LOG_ ## level, vhost_config_log_level,	\
		"VHOST_CONFIG: " fmt, ##args)
#define VHOST_LOG_DATA(level, fmt, args...) \
	(void)((RTE_LOG_ ## level <= RTE_LOG_DP_LEVEL) ?	\
	 rte_log(RTE_LOG_ ## level,  vhost_data_log_level,	\
		"VHOST_DATA : " fmt, ##args) :			\
	 0)
#define VHOST_MAX_PRINT_BUFF 6072
#define VIRTIO_DEV_BUILTIN_VIRTIO_NET 4
#define VIRTIO_DEV_READY 2
#define VIRTIO_DEV_RUNNING 1
#define VIRTIO_DEV_STOPPED -1
#define VIRTIO_DEV_VDPA_CONFIGURED 8
#define VIRTIO_F_IN_ORDER      35
#define VIRTIO_F_IOMMU_PLATFORM 33
#define VIRTIO_F_RING_PACKED 34
 #define VIRTIO_F_VERSION_1 32
 #define VIRTIO_NET_F_GUEST_ANNOUNCE 21
 #define VIRTIO_NET_F_MTU 3
#define VIRTIO_NET_SUPPORTED_FEATURES ((1ULL << VIRTIO_NET_F_MRG_RXBUF) | \
				(1ULL << VIRTIO_F_ANY_LAYOUT) | \
				(1ULL << VIRTIO_NET_F_CTRL_VQ) | \
				(1ULL << VIRTIO_NET_F_CTRL_RX) | \
				(1ULL << VIRTIO_NET_F_GUEST_ANNOUNCE) | \
				(1ULL << VIRTIO_NET_F_MQ)      | \
				(1ULL << VIRTIO_F_VERSION_1)   | \
				(1ULL << VHOST_F_LOG_ALL)      | \
				(1ULL << VHOST_USER_F_PROTOCOL_FEATURES) | \
				(1ULL << VIRTIO_NET_F_GSO) | \
				(1ULL << VIRTIO_NET_F_HOST_TSO4) | \
				(1ULL << VIRTIO_NET_F_HOST_TSO6) | \
				(1ULL << VIRTIO_NET_F_HOST_UFO) | \
				(1ULL << VIRTIO_NET_F_HOST_ECN) | \
				(1ULL << VIRTIO_NET_F_CSUM)    | \
				(1ULL << VIRTIO_NET_F_GUEST_CSUM) | \
				(1ULL << VIRTIO_NET_F_GUEST_TSO4) | \
				(1ULL << VIRTIO_NET_F_GUEST_TSO6) | \
				(1ULL << VIRTIO_NET_F_GUEST_UFO) | \
				(1ULL << VIRTIO_NET_F_GUEST_ECN) | \
				(1ULL << VIRTIO_RING_F_INDIRECT_DESC) | \
				(1ULL << VIRTIO_RING_F_EVENT_IDX) | \
				(1ULL << VIRTIO_NET_F_MTU)  | \
				(1ULL << VIRTIO_F_IN_ORDER) | \
				(1ULL << VIRTIO_F_IOMMU_PLATFORM) | \
				(1ULL << VIRTIO_F_RING_PACKED))
#define VRING_EVENT_F_DESC 0x2
#define VRING_EVENT_F_DISABLE 0x1
#define VRING_EVENT_F_ENABLE 0x0

#define vhost_avail_event(vr) \
	(*(volatile uint16_t*)&(vr)->used->ring[(vr)->size])
#define vhost_for_each_try_unroll(iter, val, size) _Pragma("GCC unroll 4") \
	for (iter = val; iter < size; iter++)
#define vhost_used_event(vr) \
	(*(volatile uint16_t*)&(vr)->avail->ring[(vr)->size])
#define MAX_VDPA_NAME_LEN 128

#define RTE_VHOST_NEED_LOG(features)	((features) & (1ULL << VHOST_F_LOG_ALL))
#define VHOST_USER_PROTOCOL_F_CONFIG 9
#define VHOST_USER_PROTOCOL_F_CRYPTO_SESSION 7
#define VHOST_USER_PROTOCOL_F_HOST_NOTIFIER 11
#define VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD 12
#define VHOST_USER_PROTOCOL_F_PAGEFAULT 8
#define VHOST_USER_PROTOCOL_F_SLAVE_SEND_FD 10


