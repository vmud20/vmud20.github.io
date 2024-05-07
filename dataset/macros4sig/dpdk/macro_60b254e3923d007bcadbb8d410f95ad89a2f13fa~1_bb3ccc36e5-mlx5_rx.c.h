#include<stdlib.h>








#include<stdio.h>
#include<string.h>




#include<stdbool.h>








#include<errno.h>


#include<stdint.h>
#include<limits.h>





#include<sys/queue.h>



#include<stddef.h>






#define LWM_COOKIE_PORTID_MASK 0xffff
#define LWM_COOKIE_PORTID_OFFSET 16
#define LWM_COOKIE_RXQID_MASK 0xffff
#define LWM_COOKIE_RXQID_OFFSET 0
#define MLX5_FLOW_TUNNEL 10
#define MLX5_MIN_SINGLE_STRIDE_LOG_NUM_BYTES 6
#define MLX5_MIN_SINGLE_WQE_LOG_NUM_STRIDES 9

#define RXQ_DEV(rxq_ctrl) ETH_DEV(RXQ_PORT(rxq_ctrl))
#define RXQ_PORT(rxq_ctrl) LIST_FIRST(&(rxq_ctrl)->owners)->priv
#define RXQ_PORT_ID(rxq_ctrl) PORT_ID(RXQ_PORT(rxq_ctrl))
#define mlx5_mprq_buf_addr(ptr, strd_n) (RTE_PTR_ADD((ptr), \
				sizeof(struct mlx5_mprq_buf) + \
				(strd_n) * \
				sizeof(struct rte_mbuf_ext_shared_info) + \
				RTE_PKTMBUF_HEADROOM))
#define mlx5_mr_btree_len(bt) ((bt)->len - 1)
#define MLX5_EXTERNAL_RX_QUEUE_ID_MIN (UINT16_MAX - 1000 + 1)
#define MLX5_HOST_SHAPER_FLAG_AVAIL_THRESH_TRIGGERED 0
#define RTE_PMD_MLX5_FINE_GRANULARITY_INLINE "mlx5_fine_granularity_inline"

#define BUF_SIZE 1024
#define ETH_DEV(priv) (&rte_eth_devices[PORT_ID(priv)])
#define GET_PORT_AGE_INFO(priv) \
	(&((priv)->sh->port[(priv)->dev_port - 1].age_info))
#define IS_BATCH_CNT(cnt) (((cnt) & (MLX5_CNT_SHARED_OFFSET - 1)) >= \
			   MLX5_CNT_BATCH_OFFSET)
#define MLX5_AGE_GET(age_info, BIT) \
	((age_info)->flags & (1 << (BIT)))
#define MLX5_AGE_SET(age_info, BIT) \
	((age_info)->flags |= (1 << (BIT)))
#define MLX5_AGE_SIZE (sizeof(struct mlx5_age_param))
#define MLX5_AGE_UNSET(age_info, BIT) \
	((age_info)->flags &= ~(1 << (BIT)))
#define MLX5_ASO_AGE_ACTIONS_PER_POOL 512
#define MLX5_ASO_CT_ACTIONS_PER_POOL 64
#define MLX5_ASO_CT_UPDATE_STATE(c, s) \
	__atomic_store_n(&((c)->state), (s), __ATOMIC_RELAXED)
#define MLX5_ASO_QUEUE_LOG_DESC 10
#define MLX5_BOND_MAX_PORTS 2
#define MLX5_CNT_ARRAY_IDX(pool, cnt) \
	((int)(((uint8_t *)(cnt) - (uint8_t *)((pool) + 1)) / \
	MLX5_CNT_LEN(pool)))
#define MLX5_CNT_CONTAINER_RESIZE 64
#define MLX5_CNT_LEN(pool) \
	(MLX5_CNT_SIZE + \
	((pool)->is_aged ? MLX5_AGE_SIZE : 0))
#define MLX5_CNT_SHARED_OFFSET 0x80000000
#define MLX5_CNT_SIZE (sizeof(struct mlx5_flow_counter))
#define MLX5_CNT_TO_AGE(cnt) \
	((struct mlx5_age_param *)((cnt) + 1))
#define MLX5_COUNTERS_PER_POOL 512
#define MLX5_DV_MAX_NUMBER_OF_ACTIONS 8
#define MLX5_ETH_FOREACH_DEV(port_id, dev) \
	for (port_id = mlx5_eth_find_next(0, dev); \
	     port_id < RTE_MAX_ETHPORTS; \
	     port_id = mlx5_eth_find_next(port_id + 1, dev))
#define MLX5_FLOW_MREG_ACT_TABLE_GROUP (MLX5_MAX_TABLES - 1)
#define MLX5_FLOW_MREG_CP_TABLE_GROUP (MLX5_MAX_TABLES - 2)
#define MLX5_FLOW_TABLE_FACTOR 10
#define MLX5_FLOW_TABLE_LEVEL_METER (MLX5_MAX_TABLES - 3)
#define MLX5_FLOW_TABLE_LEVEL_POLICY (MLX5_MAX_TABLES - 4)
#define MLX5_HAIRPIN_TX_TABLE (UINT16_MAX - 1)
#define MLX5_INVALID_POLICY_ID UINT32_MAX
#define MLX5_INVALID_SAMPLE_REG_ID 0x1F
#define MLX5_MAKE_CNT_IDX(pi, offset) \
	((pi) * MLX5_COUNTERS_PER_POOL + (offset) + 1)
#define MLX5_MAKE_CT_IDX(pool, offset) \
	((pool) * MLX5_ASO_CT_ACTIONS_PER_POOL + (offset) + 1)
#define MLX5_MAKE_MTR_IDX(pi, offset) \
		((pi) * MLX5_ASO_MTRS_PER_POOL + (offset) + 1)
#define MLX5_MAX_LRO_SIZE (UINT8_MAX * MLX5_LRO_SEG_CHUNK_SIZE)
#define MLX5_MAX_PENDING_QUERIES 4
#define MLX5_MAX_RXQ_NSEG (1u << MLX5_MAX_LOG_RQ_SEGS)
#define MLX5_MAX_SUB_POLICY_TBL_NUM 0x3FFFFF
#define MLX5_MAX_TABLES UINT16_MAX
#define MLX5_MAX_TABLES_EXTERNAL MLX5_FLOW_TABLE_LEVEL_POLICY
#define MLX5_MAX_TABLES_FDB UINT16_MAX
#define MLX5_MTRS_CONTAINER_RESIZE 64
#define MLX5_MTRS_DEFAULT_RULE_PRIORITY 0xFFFF
#define MLX5_MTRS_PPS_MAP_BPS_SHIFT 7
#define MLX5_MTR_ALL_DOMAIN_BIT      (MLX5_MTR_DOMAIN_INGRESS_BIT | \
					MLX5_MTR_DOMAIN_EGRESS_BIT | \
					MLX5_MTR_DOMAIN_TRANSFER_BIT)
#define MLX5_MTR_CHAIN_MAX_NUM 8
#define MLX5_MTR_DOMAIN_EGRESS_BIT   (1 << MLX5_MTR_DOMAIN_EGRESS)
#define MLX5_MTR_DOMAIN_INGRESS_BIT  (1 << MLX5_MTR_DOMAIN_INGRESS)
#define MLX5_MTR_DOMAIN_TRANSFER_BIT (1 << MLX5_MTR_DOMAIN_TRANSFER)
#define MLX5_MTR_POLICY_MATCHER_PRIO 0
#define MLX5_MTR_POLICY_MODE_ALL 0
#define MLX5_MTR_POLICY_MODE_DEF 1
#define MLX5_MTR_POLICY_MODE_OG 2
#define MLX5_MTR_POLICY_MODE_OY 3
#define MLX5_MTR_RSS_MAX_SUB_POLICY 7
#define MLX5_MTR_RTE_COLORS (RTE_COLOR_YELLOW + 1)
#define MLX5_MTR_SUB_POLICY_NUM_MASK  0x7
#define MLX5_MTR_SUB_POLICY_NUM_SHIFT  3
#define MLX5_MTR_TABLE_ID_DROP 2
#define MLX5_MTR_TABLE_ID_SUFFIX 1
#define MLX5_POOL_GET_CNT(pool, index) \
	((struct mlx5_flow_counter *) \
	((uint8_t *)((pool) + 1) + (index) * (MLX5_CNT_LEN(pool))))
#define MLX5_PROC_PRIV(port_id) \
	((struct mlx5_proc_priv *)rte_eth_devices[port_id].process_private)
#define MLX5_REPRESENTOR_ID(pf, type, repr) \
		(((pf) << 14) + ((type) << 12) + ((repr) & 0xfff))
#define MLX5_REPRESENTOR_REPR(repr_id) \
		((repr_id) & 0xfff)
#define MLX5_REPRESENTOR_TYPE(repr_id) \
		(((repr_id) >> 12) & 3)
#define MLX5_RSS_HASH_FIELDS_LEN RTE_DIM(mlx5_rss_hash_fields)
#define MLX5_SH(dev) (((struct mlx5_priv *)(dev)->data->dev_private)->sh)
#define MLX5_TS_MASK_SECS 8ull
#define POOL_IDX_INVALID UINT16_MAX
#define PORT_ID(priv) ((priv)->dev_data->port_id)
#define RTE_MTR_DROPPED RTE_COLORS


#define DATA_LEN(m) ((m)->data_len)
#define DATA_OFF(m) ((m)->data_off)
#define DRV_LOG(level, ...) \
	PMD_DRV_LOG_(level, mlx5_logtype, MLX5_NET_LOG_PREFIX, \
		__VA_ARGS__ PMD_DRV_LOG_STRIP PMD_DRV_LOG_OPAREN, \
		PMD_DRV_LOG_CPAREN)
#define ERRNO_SAFE(x) ((errno = (int []){ errno, ((x), 0) }[0]))
#define ILIST_ENTRY(type)						\
struct {								\
	type prev; 			\
	type next; 				\
}
#define ILIST_FOREACH(pool, head, idx, elem, field)			\
	for ((idx) = (head), (elem) =					\
	     (idx) ? mlx5_ipool_get(pool, (idx)) : NULL; (elem);	\
	     idx = (elem)->field.next, (elem) =				\
	     (idx) ? mlx5_ipool_get(pool, idx) : NULL)
#define ILIST_INSERT(pool, head, idx, elem, field)			\
	do {								\
		typeof(elem) peer;					\
		MLX5_ASSERT((elem) && (idx));				\
		(elem)->field.next = *(head);				\
		(elem)->field.prev = 0;					\
		if (*(head)) {						\
			(peer) = mlx5_ipool_get(pool, *(head));		\
			if (peer)					\
				(peer)->field.prev = (idx);		\
		}							\
		*(head) = (idx);					\
	} while (0)
#define ILIST_REMOVE(pool, head, idx, elem, field)			\
	do {								\
		typeof(elem) peer;					\
		MLX5_ASSERT(elem);					\
		MLX5_ASSERT(head);					\
		if ((elem)->field.prev) {				\
			(peer) = mlx5_ipool_get				\
				 (pool, (elem)->field.prev);		\
			if (peer)					\
				(peer)->field.next = (elem)->field.next;\
		}							\
		if ((elem)->field.next) {				\
			(peer) = mlx5_ipool_get				\
				 (pool, (elem)->field.next);		\
			if (peer)					\
				(peer)->field.prev = (elem)->field.prev;\
		}							\
		if (*(head) == (idx))					\
			*(head) = (elem)->field.next;			\
	} while (0)
#define MLX5_BITSHIFT(v) (UINT64_C(1) << (v))
#define MLX5_IPOOL_DEFAULT_TRUNK_SIZE (1 << (28 - TRUNK_IDX_BITS))
#define MLX5_IPOOL_FOREACH(ipool, idx, entry)				\
	for ((idx) = 0, mlx5_ipool_flush_cache((ipool)),		\
	    (entry) = mlx5_ipool_get_next((ipool), &idx);		\
	    (entry); idx++, (entry) = mlx5_ipool_get_next((ipool), &idx))
#define MLX5_L3T_ET_MASK (MLX5_L3T_ET_SIZE - 1)
#define MLX5_L3T_ET_OFFSET 0
#define MLX5_L3T_ET_SIZE (1 << 12)
#define MLX5_L3T_FOREACH(tbl, idx, entry)				\
	for (idx = 0, (entry) = mlx5_l3t_get_next((tbl), &idx);		\
	     (entry);							\
	     idx++, (entry) = mlx5_l3t_get_next((tbl), &idx))
#define MLX5_L3T_GT_MASK (MLX5_L3T_GT_SIZE - 1)
#define MLX5_L3T_GT_OFFSET 22
#define MLX5_L3T_GT_SIZE (1 << 10)
#define MLX5_L3T_MT_MASK (MLX5_L3T_MT_SIZE - 1)
#define MLX5_L3T_MT_OFFSET 12
#define MLX5_L3T_MT_SIZE (1 << 10)
#define MLX5_NET_LOG_PREFIX "mlx5_net"
#define NB_SEGS(m) ((m)->nb_segs)
#define NEXT(m) ((m)->next)
#define PKT_LEN(m) ((m)->pkt_len)
#define POOL_DEBUG 1
#define PORT(m) ((m)->port)

#define SET_DATA_OFF(m, o) ((m)->data_off = (o))
#define SILIST_ENTRY(type)						\
struct {								\
	type next; 				\
}
#define SILIST_FOREACH(pool, head, idx, elem, field)			\
	for ((idx) = (head), (elem) =					\
	     (idx) ? mlx5_ipool_get(pool, (idx)) : NULL; (elem);	\
	     idx = (elem)->field.next, (elem) =				\
	     (idx) ? mlx5_ipool_get(pool, idx) : NULL)
#define SILIST_INSERT(head, idx, elem, field)				\
	do {								\
		MLX5_ASSERT((elem) && (idx));				\
		(elem)->field.next = *(head);				\
		*(head) = (idx);					\
	} while (0)
#define TRANSPOSE(val, from, to) \
	(((from) >= (to)) ? \
	 (((val) & (from)) / ((from) / (to))) : \
	 (((val) & (from)) * ((to) / (from))))
#define TRUNK_IDX_BITS 16
#define TRUNK_INVALID TRUNK_MAX_IDX
#define TRUNK_MAX_IDX ((1 << TRUNK_IDX_BITS) - 1)
#define MLX5_ALARM_TIMEOUT_US 100000
#define MLX5_DEFAULT_COPY_ID UINT32_MAX
#define MLX5_FLOW_ENCAP_DECAP_HTABLE_SZ (1 << 12)
#define MLX5_FLOW_HDR_MODIFY_HTABLE_SZ (1 << 15)
#define MLX5_FLOW_MREG_HNAME "MARK_COPY_TABLE"
#define MLX5_FLOW_MREG_HTABLE_SZ 64
#define MLX5_GET_LINK_STATUS_RETRY_COUNT 3
#define MLX5_HAIRPIN_JUMBO_LOG_SIZE (14 + 2)
#define MLX5_HAIRPIN_QUEUE_STRIDE 6
#define MLX5_INLINE_HSIZE_INNER_L2 (MLX5_INLINE_HSIZE_L3 + \
				    sizeof(struct rte_udp_hdr) + \
				    sizeof(struct rte_vxlan_hdr) + \
				    sizeof(struct rte_ether_hdr) + \
				    sizeof(struct rte_vlan_hdr))
#define MLX5_INLINE_HSIZE_INNER_L3 (MLX5_INLINE_HSIZE_INNER_L2 + \
				    sizeof(struct rte_ipv6_hdr))
#define MLX5_INLINE_HSIZE_INNER_L4 (MLX5_INLINE_HSIZE_INNER_L3 + \
				    sizeof(struct rte_tcp_hdr))
#define MLX5_INLINE_HSIZE_L2 (sizeof(struct rte_ether_hdr) + \
			      sizeof(struct rte_vlan_hdr))
#define MLX5_INLINE_HSIZE_L3 (MLX5_INLINE_HSIZE_L2 + \
			      sizeof(struct rte_ipv6_hdr))
#define MLX5_INLINE_HSIZE_L4 (MLX5_INLINE_HSIZE_L3 + \
			      sizeof(struct rte_tcp_hdr))
#define MLX5_INLINE_HSIZE_NONE 0
#define MLX5_LINK_STATUS_TIMEOUT 10
#define MLX5_MAX_EXT_RX_QUEUES (UINT16_MAX - MLX5_EXTERNAL_RX_QUEUE_ID_MIN + 1)
#define MLX5_MAX_INDIRECT_ACTIONS 3
#define MLX5_MAX_TSO_HEADER 192U
#define MLX5_MAX_VLAN_IDS 128
#define MLX5_MAX_XSTATS 64
#define MLX5_MPRQ_DEFAULT_LOG_STRIDE_NUM 6U
#define MLX5_MPRQ_DEFAULT_LOG_STRIDE_SIZE 11U
#define MLX5_MPRQ_MEMCPY_DEFAULT_LEN 128
#define MLX5_MPRQ_MIN_RXQS 12
#define MLX5_MPRQ_MP_CACHE_SZ 32U
#define MLX5_MPRQ_TWO_BYTE_SHIFT 0
#define MLX5_PMD_SOFT_COUNTERS 1
#define MLX5_RSS_HF_MASK (~(RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP | \
			    MLX5_RSS_SRC_DST_ONLY | RTE_ETH_RSS_ESP))
#define MLX5_RSS_SRC_DST_ONLY (RTE_ETH_RSS_L3_SRC_ONLY | RTE_ETH_RSS_L3_DST_ONLY | \
			       RTE_ETH_RSS_L4_SRC_ONLY | RTE_ETH_RSS_L4_DST_ONLY)
#define MLX5_RX_DEFAULT_BURST 64U
#define MLX5_TXPP_CLKQ_SIZE 1
#define MLX5_TXPP_REARM_CQ_SIZE (MLX5_TXPP_REARM_SQ_SIZE / 2)
#define MLX5_TXPP_REARM_SQ_SIZE (((1UL << MLX5_CQ_INDEX_WIDTH) / \
				  MLX5_TXPP_REARM) * 2)
#define MLX5_TXPP_TEST_PKT_SIZE (sizeof(struct rte_ether_hdr) +	\
				 sizeof(struct rte_ipv4_hdr))
#define MLX5_TXPP_WAIT_INIT_TS 1000ul 
#define MLX5_TX_COMP_MAX_CQE 2u
#define MLX5_TX_COMP_THRESH 32u
#define MLX5_TX_COMP_THRESH_INLINE_DIV (1 << 3)
#define MLX5_TX_DEFAULT_BURST 64U
#define MLX5_UAR_PAGE_NUM_MASK ((MLX5_UAR_PAGE_NUM_MAX) - 1)
#define MLX5_UAR_PAGE_NUM_MAX 64
#define MLX5_VPMD_DESCS_PER_LOOP      4
#define MLX5_VPMD_RXQ_RPLNSH_THRESH(n) \
	(RTE_MIN(MLX5_VPMD_RX_MAX_BURST, (unsigned int)(n) >> 2))
#define MLX5_VPMD_RX_MAX_BURST 64U
#define MLX5_XMETA_MODE_LEGACY 0
#define MLX5_XMETA_MODE_META16 1
#define MLX5_XMETA_MODE_META32 2
#define MLX5_XMETA_MODE_MISS_INFO 3

#define static_assert _Static_assert


