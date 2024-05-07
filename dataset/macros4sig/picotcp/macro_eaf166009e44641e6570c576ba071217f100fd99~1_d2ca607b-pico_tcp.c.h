








#include<stdlib.h>



#include<stddef.h>






#include<string.h>


#include<stdint.h>

#include<linux/types.h>


#define ATTACH_QUEUES(St, pname, P) \
    do { \
       P.q_in =  &((St)->q_ ## pname.in); \
       P.q_out = &((St)->q_ ## pname.out); \
       ATTACH_QUEUES_LISTENERS(St, pname, P); \
    } while(0)
    #define ATTACH_QUEUES_LISTENERS(St, pname, P) \
        do { \
        pico_queue_register_listener(St, &((St->q_ ## pname.in, proto_full_loop_in, P); \
        pico_queue_register_listener(St, &((St->q_ ## pname.out, proto_full_loop_out, P); \
    } while(0)
#define DECLARE_QUEUES(proto) \
    struct s_q_ ## proto { \
        struct pico_queue in, out; \
    }  q_ ## proto
#define EMPTY_TREE(name,comp) \
     do { name.root = &LEAF; name.compare = comp;} while(0)

#define PICO_ETH_MRU (1514u)
#define PICO_IP_MRU (1500u)
#define PICO_MAX_TIMERS 20
#define PROTO_DEF_AVG_NR  4
#define PROTO_DEF_NR      11
#define PROTO_DEF_SCORE   32
#define PROTO_LAT_IND     3   
#define PROTO_MAX_LOOP    (PROTO_MAX_SCORE << PROTO_LAT_IND) 
#define PROTO_MAX_SCORE   128
#define PROTO_MIN_SCORE   32
#   define pico_ethernet_receive(f) (-1)
#   define pico_ethernet_send(f)    (-1)
#define DECLARE_HEAP(type, orderby) \
    struct heap_ ## type {   \
        uint32_t size;    \
        uint32_t n;       \
        type *top[MAX_BLOCK_COUNT];        \
    }; \
    typedef struct heap_ ## type heap_ ## type; \
    static inline type* heap_get_element(struct heap_ ## type *heap, uint32_t idx) \
    { \
        uint32_t elements_per_block = MAX_BLOCK_SIZE/sizeof(type); \
        return &heap->top[idx/elements_per_block][idx%elements_per_block];\
    } \
    static inline int8_t heap_increase_size(struct heap_ ## type *heap) \
    {\
        type *newTop; \
        uint32_t elements_per_block = MAX_BLOCK_SIZE/sizeof(type); \
        uint32_t elements = (heap->n + 1)%elements_per_block;\
        elements = elements?elements:elements_per_block;\
        if (heap->n+1 > elements_per_block * MAX_BLOCK_COUNT){\
            return -1;\
        }\
        newTop = PICO_ZALLOC(elements*sizeof(type)); \
        if(!newTop) { \
            return -1; \
        } \
        if (heap->top[heap->n/elements_per_block])  { \
            memcpy(newTop, heap->top[heap->n/elements_per_block], (elements - 1) * sizeof(type)); \
            PICO_FREE(heap->top[heap->n/elements_per_block]); \
        } \
        heap->top[heap->n/elements_per_block] = newTop;             \
        heap->size++;                                                               \
        return 0;                                                               \
    }\
    static inline int heap_insert(struct heap_ ## type *heap, type * el) \
    { \
        type *half;                                                                 \
        uint32_t i; \
        if (++heap->n >= heap->size) {                                                \
            if (heap_increase_size(heap)){                                                    \
                heap->n--;                                                           \
                return -1;                                                           \
            }                                                                       \
        }                                                                             \
        if (heap->n == 1) {                                                       \
            memcpy(heap_get_element(heap, 1), el, sizeof(type));                                    \
            return 0;                                                                   \
        }                                                                             \
        i = heap->n;                                                                    \
        half = heap_get_element(heap, i/2);                                                   \
        while ( (i > 1) && (half->orderby > el->orderby) ) {        \
            memcpy(heap_get_element(heap, i), heap_get_element(heap, i / 2), sizeof(type));                     \
            i /= 2;                                                                     \
            half = heap_get_element(heap, i/2);                                                   \
        }             \
        memcpy(heap_get_element(heap, i), el, sizeof(type));                                      \
        return 0;                                                                     \
    } \
    static inline int heap_peek(struct heap_ ## type *heap, type * first) \
    { \
        type *last;           \
        type *left_child;           \
        type *right_child;           \
        uint32_t i, child;        \
        if(heap->n == 0) {    \
            return -1;          \
        }                     \
        memcpy(first, heap_get_element(heap, 1), sizeof(type));   \
        last = heap_get_element(heap, heap->n--);                 \
        for(i = 1; (i * 2u) <= heap->n; i = child) {   \
            child = 2u * i;                              \
            right_child = heap_get_element(heap, child+1);     \
            left_child = heap_get_element(heap, child);      \
            if ((child != heap->n) &&                   \
                (right_child->orderby          \
                < left_child->orderby))           \
                child++;                                \
            left_child = heap_get_element(heap, child);      \
            if (last->orderby >                         \
                left_child->orderby)               \
                memcpy(heap_get_element(heap,i), heap_get_element(heap,child), \
                       sizeof(type));                  \
            else                                        \
                break;                                  \
        }                                             \
        memcpy(heap_get_element(heap, i), last, sizeof(type));    \
        return 0;                                     \
    } \
    static inline type *heap_first(heap_ ## type * heap)  \
    { \
        if (heap->n == 0)     \
            return NULL;        \
        return heap_get_element(heap, 1);  \
    } \
    static inline heap_ ## type *heap_init(void) \
    { \
        heap_ ## type * p = (heap_ ## type *)PICO_ZALLOC(sizeof(heap_ ## type));  \
        return p;     \
    } \

#define MAX_BLOCK_COUNT 16
#define MAX_BLOCK_SIZE 1600

#define NULL ((void *)0)
#define PICOTCP_MUTEX_DEL(x) pico_mutex_deinit(x)
#define PICOTCP_MUTEX_LOCK(x) { \
        if (x == NULL) \
            x = pico_mutex_init(); \
        pico_mutex_lock(x); \
}
#define PICOTCP_MUTEX_UNLOCK(x) pico_mutex_unlock(x)
#define Q_LIMIT 0
#define debug_q(x) do {} while(0)
#define pico_queue_register_listener(S, q, fn, arg) do{}while(0)
#define pico_queue_wakeup(q) do{}while(0)

#define IS_BCAST(f) ((f->flags & PICO_FRAME_FLAG_BCAST) == PICO_FRAME_FLAG_BCAST)
#define PICO_FRAME_FLAG_BCAST               (0x01)
#define PICO_FRAME_FLAG_EXT_BUFFER          (0x02)
#define PICO_FRAME_FLAG_EXT_USAGE_COUNTER   (0x04)
#define PICO_FRAME_FLAG_LL_SEC              (0x40)
#define PICO_FRAME_FLAG_SACKED              (0x80)
#define PICO_FRAME_FLAG_SLP_FRAG            (0x20)
#           define BYTESWAP_GCC
#       define GCC_VERSION ("__GNUC__" * 10000 + "__GNUC_MINOR__" * 100 + "__GNUC_PATCHLEVEL__")
#define IGNORE_PARAMETER(x)  ((void)x)

#   define MOCKABLE __attribute__((weak))
#   define PACKED __packed
#   define PACKED_STRUCT_DEF __packed struct
#   define PACKED_UNION_DEF  __packed union
#   define PEDANTIC_STRUCT_DEF __packed struct
# define PICO_ARP_HTYPE_ETH 0x0100
# define PICO_ARP_REPLY   0x0200
# define PICO_ARP_REQUEST 0x0100
#define PICO_FREE(x) pico_mem_free(x)
# define PICO_IDETH_ARP 0x0608
# define PICO_IDETH_IPV4 0x0008
# define PICO_IDETH_IPV6 0xDD86
#define PICO_MAX_SLAB_SIZE 1600
#define PICO_MEM_DEFAULT_SLAB_SIZE 1600
#define PICO_MEM_MINIMUM_OBJECT_SIZE 4
#define PICO_MEM_PAGE_LIFETIME 100
#define PICO_MEM_PAGE_SIZE 4096
#define PICO_MIN_HEAP_SIZE 600
#define PICO_MIN_SLAB_SIZE 1200
#    define PICO_THREAD_LOCAL  __thread
#define PICO_ZALLOC(x) pico_mem_zalloc(x)
#   define WEAK __attribute__((weak))
#define be_to_host_long(x) (x)
#define long_be(x) (x)
#define long_long_be(x) (x)
#define short_be(x) (x)

#define PICO_ARP_INTERVAL 1000
#define PICO_ARP_MAX_RATE 1
#define PICO_IEEE802154_BCAST (0xffffu)
#define PICO_IP4_ANY (0x00000000U)
#define PICO_IP4_BCAST (0xffffffffU)
#define PICO_SIZE_ETH    6
#define PICO_SIZE_IEEE802154_EXT (8u)
#define PICO_SIZE_IEEE802154_SHORT (2u)
#define PICO_SIZE_IP4    4
#define PICO_SIZE_IP6   16
#define PICO_SIZE_TRANS  8
#define AM_6LOWPAN_EXT       (3u)
#define AM_6LOWPAN_NONE      (0u)
#define AM_6LOWPAN_RES       (1u)
#define AM_6LOWPAN_SHORT     (2u)
#define IID_16(iid) (0 == (iid)[2] && 0xff == (iid)[3] && 0xfe == (iid)[4] && 0 == (iid)[5])

#define PICO_PROTO_ICMP4  1
#define PICO_PROTO_ICMP6  58
#define PICO_PROTO_IGMP  2
#define PICO_PROTO_IPV4   0
#define PICO_PROTO_IPV6   41
#define PICO_PROTO_RAWSOCKET (3 << 8)
#define PICO_PROTO_TCP    6
#define PICO_PROTO_UDP    17
#define PICO_RAWSOCKET_RAW 255
#define SIZE_6LOWPAN(m) (((m) == 2) ? (2) : (((m) == 3) ? (8) : (0)))
#define SIZE_6LOWPAN_EXT     (8u)
#define SIZE_6LOWPAN_SHORT   (2u)

#define USE_PICO_PAGE0_ZALLOC (1)
#define USE_PICO_ZALLOC (2)
#define pico_tree_foreach(idx, tree) \
    for ((idx) = pico_tree_firstNode((tree)->root); \
         (idx) != &LEAF; \
         (idx) = pico_tree_next(idx))
#define pico_tree_foreach_reverse(idx, tree) \
    for ((idx) = pico_tree_lastNode((tree)->root); \
         (idx) != &LEAF; \
         (idx) = pico_tree_prev(idx))
#define pico_tree_foreach_reverse_safe(idx, tree, idx2) \
    for ((idx) = pico_tree_lastNode((tree)->root); \
         ((idx) != &LEAF) && ((idx2) = pico_tree_prev(idx), 1); \
         (idx) = (idx2))
#define pico_tree_foreach_safe(idx, tree, idx2) \
    for ((idx) = pico_tree_firstNode((tree)->root); \
         ((idx) != &LEAF) && ((idx2) = pico_tree_next(idx), 1); \
         (idx) = (idx2))
#   define IS_NAGLE_ENABLED(s) (0)

#   define pico_getsockopt_tcp(...) (-1)
#   define pico_setsockopt_tcp(...) (-1)
#   define pico_socket_tcp_cleanup(...) do {} while(0)
#   define pico_socket_tcp_delete(...) do {} while(0)
#   define pico_socket_tcp_deliver(...) (-1)
#   define pico_socket_tcp_open(f) (NULL)
#   define pico_socket_tcp_read(...) (-1)
#   define transport_flags_update(...) do {} while(0)

# define IS_SOCK_IPV4(s) ((s->net == &pico_proto_ipv4))
# define IS_SOCK_IPV6(s) ((s->net == &pico_proto_ipv6))
# define IS_SOCK_PACKET(s) ((s->net == &pico_proto_ll))
    #define PICO_DEFAULT_SOCKETQ (16 * 1024) 
# define PICO_IP_ADD_MEMBERSHIP               35
# define PICO_IP_ADD_SOURCE_MEMBERSHIP        39
# define PICO_IP_BLOCK_SOURCE                 38
# define PICO_IP_DEFAULT_MULTICAST_LOOP       1
# define PICO_IP_DEFAULT_MULTICAST_TTL        1
# define PICO_IP_DROP_MEMBERSHIP              36
# define PICO_IP_DROP_SOURCE_MEMBERSHIP       40
# define PICO_IP_MULTICAST_EXCLUDE            0
# define PICO_IP_MULTICAST_IF                 32
# define PICO_IP_MULTICAST_INCLUDE            1
# define PICO_IP_MULTICAST_LOOP               34
# define PICO_IP_MULTICAST_TTL                33
# define PICO_IP_UNBLOCK_SOURCE               37
#define PICO_SHUT_RD   1
#define PICO_SHUT_RDWR 3
#define PICO_SHUT_WR   2
#define PICO_SOCKET_BOUND_TIMEOUT             30000u 
#define PICO_SOCKET_GETOPT(socket, index) ((socket->opt_flags & (1u << index)) != 0)
#define PICO_SOCKET_LINGER_TIMEOUT            3000u 
# define PICO_SOCKET_OPT_IP_BINDTODEVICE      25
# define PICO_SOCKET_OPT_IP_DONTROUTE         5
# define PICO_SOCKET_OPT_IP_HDRINCL           3
# define PICO_SOCKET_OPT_KEEPCNT               6
# define PICO_SOCKET_OPT_KEEPIDLE              4
# define PICO_SOCKET_OPT_KEEPINTVL             5
#define PICO_SOCKET_OPT_LINGER                13
# define PICO_SOCKET_OPT_MULTICAST_LOOP       1
# define PICO_SOCKET_OPT_RCVBUF               52
# define PICO_SOCKET_OPT_SNDBUF               53
# define PICO_SOCKET_OPT_TCPNODELAY           0x0000u
#define PICO_SOCKET_SETOPT_DIS(socket, index) (socket->opt_flags &= (uint16_t) ~(1 << index))
#define PICO_SOCKET_SETOPT_EN(socket, index)  (socket->opt_flags |=  (1 << index))
#define PICO_SOCKET_SHUTDOWN_READ  0x02u
#define PICO_SOCKET_SHUTDOWN_WRITE 0x01u
#define PICO_SOCKET_STATE_BOUND           0x0004u
#define PICO_SOCKET_STATE_CLOSED          0x0020u
#define PICO_SOCKET_STATE_CLOSING         0x0010u
#define PICO_SOCKET_STATE_CONNECTED       0x0008u
#define PICO_SOCKET_STATE_SHUT_LOCAL      0x0001u
#define PICO_SOCKET_STATE_SHUT_REMOTE     0x0002u
# define PICO_SOCKET_STATE_TCP                0xFF00u
# define PICO_SOCKET_STATE_TCP_ARRAYSIZ       0x0cu
# define PICO_SOCKET_STATE_TCP_CLOSED         0x0100u
# define PICO_SOCKET_STATE_TCP_CLOSE_WAIT     0x0600u
# define PICO_SOCKET_STATE_TCP_CLOSING        0x0a00u
# define PICO_SOCKET_STATE_TCP_ESTABLISHED    0x0500u
# define PICO_SOCKET_STATE_TCP_FIN_WAIT1      0x0800u
# define PICO_SOCKET_STATE_TCP_FIN_WAIT2      0x0900u
# define PICO_SOCKET_STATE_TCP_LAST_ACK       0x0700u
# define PICO_SOCKET_STATE_TCP_LISTEN         0x0200u
# define PICO_SOCKET_STATE_TCP_SYN_RECV       0x0400u
# define PICO_SOCKET_STATE_TCP_SYN_SENT       0x0300u
# define PICO_SOCKET_STATE_TCP_TIME_WAIT      0x0b00u
# define PICO_SOCKET_STATE_TCP_UNDEF          0x00FFu
#define PICO_SOCKET_STATE_UNDEFINED       0x0000u
#define PICO_SOCKET_TIMEOUT                   5000u 
#define PICO_SOCK_EV_CLOSE 8u
#define PICO_SOCK_EV_CONN 4u
#define PICO_SOCK_EV_ERR 0x80u
#define PICO_SOCK_EV_FIN 0x10u
#define PICO_SOCK_EV_RD 1u
#define PICO_SOCK_EV_WR 2u
# define PICO_TCP_NODELAY                     1
#define TCPSTATE(s) ((s)->state & PICO_SOCKET_STATE_TCP)
# define is_sock_ipv4(x) (x->net == &pico_proto_ipv4)
# define is_sock_ipv6(x) (x->net == &pico_proto_ipv6)
# define is_sock_ll(x) (x->net == &pico_proto_ll)
# define is_sock_tcp(x) (x->proto == &pico_proto_tcp)
# define is_sock_udp(x) (x->proto == &pico_proto_udp)

#define IS_IPV4(f) (f && f->net_hdr && ((((uint8_t *)(f->net_hdr))[0] & 0xf0) == 0x40))
#define IS_IPV6(f) (f && f->net_hdr && ((((uint8_t *)(f->net_hdr))[0] & 0xf0) == 0x60))
#define MAX_PROTOCOL_NAME 16
#define PICO_LOOP_DIR_IN   1
#define PICO_LOOP_DIR_OUT  2

#define PICO_SIZE_ETHHDR 14

#define PICO_SIZE_TCPHDR (uint32_t)(sizeof(struct pico_tcp_hdr))
#define PICO_SIZE_TCPOPT_SYN 20
#define PICO_TCPHDR_SIZE 20
#define PICO_TCPOPTLEN_END        1u
#define PICO_TCPOPTLEN_MSS        4
#define PICO_TCPOPTLEN_NOOP       1
#define PICO_TCPOPTLEN_SACK       2 
#define PICO_TCPOPTLEN_SACK_OK       2
#define PICO_TCPOPTLEN_TIMESTAMP  10u
#define PICO_TCPOPTLEN_WS         3u
#define PICO_TCP_ACK 0x10u
#define PICO_TCP_CWR 0x80u
#define PICO_TCP_ECN 0x40u
#define PICO_TCP_FIN 0x01u
#define PICO_TCP_FINACK    (PICO_TCP_FIN | PICO_TCP_ACK)
#define PICO_TCP_FINPSHACK (PICO_TCP_FIN | PICO_TCP_PSH | PICO_TCP_ACK)
#define PICO_TCP_OPTION_END         0x00
#define PICO_TCP_OPTION_MSS         0x02
#define PICO_TCP_OPTION_NOOP        0x01
#define PICO_TCP_OPTION_SACK        0x05
#define PICO_TCP_OPTION_SACK_OK        0x04
#define PICO_TCP_OPTION_TIMESTAMP   0x08
#define PICO_TCP_OPTION_WS          0x03
#define PICO_TCP_PSH 0x08u
#define PICO_TCP_PSHACK    (PICO_TCP_PSH | PICO_TCP_ACK)
#define PICO_TCP_RST 0x04u
#define PICO_TCP_RSTACK    (PICO_TCP_RST | PICO_TCP_ACK)
#define PICO_TCP_SYN 0x02u
#define PICO_TCP_SYNACK    (PICO_TCP_SYN | PICO_TCP_ACK)
#define PICO_TCP_URG 0x20u
