
























char e1000e_driver_name[] = "e1000e";
const char e1000e_driver_version[] = DRV_VERSION;

static const struct e1000_info *e1000_info_tbl[] = {
	[board_82571]		= &e1000_82571_info, [board_82572]		= &e1000_82572_info, [board_82573]		= &e1000_82573_info, [board_82574]		= &e1000_82574_info, [board_82583]		= &e1000_82583_info, [board_80003es2lan]	= &e1000_es2_info, [board_ich8lan]		= &e1000_ich8_info, [board_ich9lan]		= &e1000_ich9_info, [board_ich10lan]	= &e1000_ich10_info, [board_pchlan]		= &e1000_pch_info, };











static int e1000_desc_unused(struct e1000_ring *ring)
{
	if (ring->next_to_clean > ring->next_to_use)
		return ring->next_to_clean - ring->next_to_use - 1;

	return ring->count + ring->next_to_clean - ring->next_to_use - 1;
}


static void e1000_receive_skb(struct e1000_adapter *adapter, struct net_device *netdev, struct sk_buff *skb, u8 status, __le16 vlan)


{
	skb->protocol = eth_type_trans(skb, netdev);

	if (adapter->vlgrp && (status & E1000_RXD_STAT_VP))
		vlan_gro_receive(&adapter->napi, adapter->vlgrp, le16_to_cpu(vlan), skb);
	else napi_gro_receive(&adapter->napi, skb);
}


static void e1000_rx_checksum(struct e1000_adapter *adapter, u32 status_err, u32 csum, struct sk_buff *skb)
{
	u16 status = (u16)status_err;
	u8 errors = (u8)(status_err >> 24);
	skb->ip_summed = CHECKSUM_NONE;

	
	if (status & E1000_RXD_STAT_IXSM)
		return;
	
	if (errors & E1000_RXD_ERR_TCPE) {
		
		adapter->hw_csum_err++;
		return;
	}

	
	if (!(status & (E1000_RXD_STAT_TCPCS | E1000_RXD_STAT_UDPCS)))
		return;

	
	if (status & E1000_RXD_STAT_TCPCS) {
		
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else {
		
		__sum16 sum = (__force __sum16)htons(csum);
		skb->csum = csum_unfold(~sum);
		skb->ip_summed = CHECKSUM_COMPLETE;
	}
	adapter->hw_csum_good++;
}


static void e1000_alloc_rx_buffers(struct e1000_adapter *adapter, int cleaned_count)
{
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_ring *rx_ring = adapter->rx_ring;
	struct e1000_rx_desc *rx_desc;
	struct e1000_buffer *buffer_info;
	struct sk_buff *skb;
	unsigned int i;
	unsigned int bufsz = adapter->rx_buffer_len;

	i = rx_ring->next_to_use;
	buffer_info = &rx_ring->buffer_info[i];

	while (cleaned_count--) {
		skb = buffer_info->skb;
		if (skb) {
			skb_trim(skb, 0);
			goto map_skb;
		}

		skb = netdev_alloc_skb_ip_align(netdev, bufsz);
		if (!skb) {
			
			adapter->alloc_rx_buff_failed++;
			break;
		}

		buffer_info->skb = skb;
map_skb:
		buffer_info->dma = pci_map_single(pdev, skb->data, adapter->rx_buffer_len, PCI_DMA_FROMDEVICE);

		if (pci_dma_mapping_error(pdev, buffer_info->dma)) {
			dev_err(&pdev->dev, "RX DMA map failed\n");
			adapter->rx_dma_failed++;
			break;
		}

		rx_desc = E1000_RX_DESC(*rx_ring, i);
		rx_desc->buffer_addr = cpu_to_le64(buffer_info->dma);

		i++;
		if (i == rx_ring->count)
			i = 0;
		buffer_info = &rx_ring->buffer_info[i];
	}

	if (rx_ring->next_to_use != i) {
		rx_ring->next_to_use = i;
		if (i-- == 0)
			i = (rx_ring->count - 1);

		
		wmb();
		writel(i, adapter->hw.hw_addr + rx_ring->tail);
	}
}


static void e1000_alloc_rx_buffers_ps(struct e1000_adapter *adapter, int cleaned_count)
{
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	union e1000_rx_desc_packet_split *rx_desc;
	struct e1000_ring *rx_ring = adapter->rx_ring;
	struct e1000_buffer *buffer_info;
	struct e1000_ps_page *ps_page;
	struct sk_buff *skb;
	unsigned int i, j;

	i = rx_ring->next_to_use;
	buffer_info = &rx_ring->buffer_info[i];

	while (cleaned_count--) {
		rx_desc = E1000_RX_DESC_PS(*rx_ring, i);

		for (j = 0; j < PS_PAGE_BUFFERS; j++) {
			ps_page = &buffer_info->ps_pages[j];
			if (j >= adapter->rx_ps_pages) {
				
				rx_desc->read.buffer_addr[j+1] = ~cpu_to_le64(0);
				continue;
			}
			if (!ps_page->page) {
				ps_page->page = alloc_page(GFP_ATOMIC);
				if (!ps_page->page) {
					adapter->alloc_rx_buff_failed++;
					goto no_buffers;
				}
				ps_page->dma = pci_map_page(pdev, ps_page->page, 0, PAGE_SIZE, PCI_DMA_FROMDEVICE);


				if (pci_dma_mapping_error(pdev, ps_page->dma)) {
					dev_err(&adapter->pdev->dev, "RX DMA page map failed\n");
					adapter->rx_dma_failed++;
					goto no_buffers;
				}
			}
			
			rx_desc->read.buffer_addr[j+1] = cpu_to_le64(ps_page->dma);
		}

		skb = netdev_alloc_skb_ip_align(netdev, adapter->rx_ps_bsize0);

		if (!skb) {
			adapter->alloc_rx_buff_failed++;
			break;
		}

		buffer_info->skb = skb;
		buffer_info->dma = pci_map_single(pdev, skb->data, adapter->rx_ps_bsize0, PCI_DMA_FROMDEVICE);

		if (pci_dma_mapping_error(pdev, buffer_info->dma)) {
			dev_err(&pdev->dev, "RX DMA map failed\n");
			adapter->rx_dma_failed++;
			
			dev_kfree_skb_any(skb);
			buffer_info->skb = NULL;
			break;
		}

		rx_desc->read.buffer_addr[0] = cpu_to_le64(buffer_info->dma);

		i++;
		if (i == rx_ring->count)
			i = 0;
		buffer_info = &rx_ring->buffer_info[i];
	}

no_buffers:
	if (rx_ring->next_to_use != i) {
		rx_ring->next_to_use = i;

		if (!(i--))
			i = (rx_ring->count - 1);

		
		wmb();
		
		writel(i<<1, adapter->hw.hw_addr + rx_ring->tail);
	}
}



static void e1000_alloc_jumbo_rx_buffers(struct e1000_adapter *adapter, int cleaned_count)
{
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_rx_desc *rx_desc;
	struct e1000_ring *rx_ring = adapter->rx_ring;
	struct e1000_buffer *buffer_info;
	struct sk_buff *skb;
	unsigned int i;
	unsigned int bufsz = 256 - 16 ;

	i = rx_ring->next_to_use;
	buffer_info = &rx_ring->buffer_info[i];

	while (cleaned_count--) {
		skb = buffer_info->skb;
		if (skb) {
			skb_trim(skb, 0);
			goto check_page;
		}

		skb = netdev_alloc_skb_ip_align(netdev, bufsz);
		if (unlikely(!skb)) {
			
			adapter->alloc_rx_buff_failed++;
			break;
		}

		buffer_info->skb = skb;
check_page:
		
		if (!buffer_info->page) {
			buffer_info->page = alloc_page(GFP_ATOMIC);
			if (unlikely(!buffer_info->page)) {
				adapter->alloc_rx_buff_failed++;
				break;
			}
		}

		if (!buffer_info->dma)
			buffer_info->dma = pci_map_page(pdev, buffer_info->page, 0, PAGE_SIZE, PCI_DMA_FROMDEVICE);



		rx_desc = E1000_RX_DESC(*rx_ring, i);
		rx_desc->buffer_addr = cpu_to_le64(buffer_info->dma);

		if (unlikely(++i == rx_ring->count))
			i = 0;
		buffer_info = &rx_ring->buffer_info[i];
	}

	if (likely(rx_ring->next_to_use != i)) {
		rx_ring->next_to_use = i;
		if (unlikely(i-- == 0))
			i = (rx_ring->count - 1);

		
		wmb();
		writel(i, adapter->hw.hw_addr + rx_ring->tail);
	}
}


static bool e1000_clean_rx_irq(struct e1000_adapter *adapter, int *work_done, int work_to_do)
{
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_ring *rx_ring = adapter->rx_ring;
	struct e1000_rx_desc *rx_desc, *next_rxd;
	struct e1000_buffer *buffer_info, *next_buffer;
	u32 length;
	unsigned int i;
	int cleaned_count = 0;
	bool cleaned = 0;
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;

	i = rx_ring->next_to_clean;
	rx_desc = E1000_RX_DESC(*rx_ring, i);
	buffer_info = &rx_ring->buffer_info[i];

	while (rx_desc->status & E1000_RXD_STAT_DD) {
		struct sk_buff *skb;
		u8 status;

		if (*work_done >= work_to_do)
			break;
		(*work_done)++;

		status = rx_desc->status;
		skb = buffer_info->skb;
		buffer_info->skb = NULL;

		prefetch(skb->data - NET_IP_ALIGN);

		i++;
		if (i == rx_ring->count)
			i = 0;
		next_rxd = E1000_RX_DESC(*rx_ring, i);
		prefetch(next_rxd);

		next_buffer = &rx_ring->buffer_info[i];

		cleaned = 1;
		cleaned_count++;
		pci_unmap_single(pdev, buffer_info->dma, adapter->rx_buffer_len, PCI_DMA_FROMDEVICE);


		buffer_info->dma = 0;

		length = le16_to_cpu(rx_desc->length);

		
		if (!(status & E1000_RXD_STAT_EOP) || (length <= 4)) {
			
			e_dbg("Receive packet consumed multiple buffers\n");
			
			buffer_info->skb = skb;
			goto next_desc;
		}

		if (rx_desc->errors & E1000_RXD_ERR_FRAME_ERR_MASK) {
			
			buffer_info->skb = skb;
			goto next_desc;
		}

		
		if (!(adapter->flags2 & FLAG2_CRC_STRIPPING))
			length -= 4;

		total_rx_bytes += length;
		total_rx_packets++;

		
		if (length < copybreak) {
			struct sk_buff *new_skb = netdev_alloc_skb_ip_align(netdev, length);
			if (new_skb) {
				skb_copy_to_linear_data_offset(new_skb, -NET_IP_ALIGN, (skb->data - NET_IP_ALIGN), (length + NET_IP_ALIGN));




				
				buffer_info->skb = skb;
				skb = new_skb;
			}
			
		}
		
		skb_put(skb, length);

		
		e1000_rx_checksum(adapter, (u32)(status) | ((u32)(rx_desc->errors) << 24), le16_to_cpu(rx_desc->csum), skb);



		e1000_receive_skb(adapter, netdev, skb,status,rx_desc->special);

next_desc:
		rx_desc->status = 0;

		
		if (cleaned_count >= E1000_RX_BUFFER_WRITE) {
			adapter->alloc_rx_buf(adapter, cleaned_count);
			cleaned_count = 0;
		}

		
		rx_desc = next_rxd;
		buffer_info = next_buffer;
	}
	rx_ring->next_to_clean = i;

	cleaned_count = e1000_desc_unused(rx_ring);
	if (cleaned_count)
		adapter->alloc_rx_buf(adapter, cleaned_count);

	adapter->total_rx_bytes += total_rx_bytes;
	adapter->total_rx_packets += total_rx_packets;
	netdev->stats.rx_bytes += total_rx_bytes;
	netdev->stats.rx_packets += total_rx_packets;
	return cleaned;
}

static void e1000_put_txbuf(struct e1000_adapter *adapter, struct e1000_buffer *buffer_info)
{
	if (buffer_info->dma) {
		if (buffer_info->mapped_as_page)
			pci_unmap_page(adapter->pdev, buffer_info->dma, buffer_info->length, PCI_DMA_TODEVICE);
		else pci_unmap_single(adapter->pdev,	buffer_info->dma, buffer_info->length, PCI_DMA_TODEVICE);


		buffer_info->dma = 0;
	}
	if (buffer_info->skb) {
		dev_kfree_skb_any(buffer_info->skb);
		buffer_info->skb = NULL;
	}
	buffer_info->time_stamp = 0;
}

static void e1000_print_hw_hang(struct work_struct *work)
{
	struct e1000_adapter *adapter = container_of(work, struct e1000_adapter, print_hang_task);

	struct e1000_ring *tx_ring = adapter->tx_ring;
	unsigned int i = tx_ring->next_to_clean;
	unsigned int eop = tx_ring->buffer_info[i].next_to_watch;
	struct e1000_tx_desc *eop_desc = E1000_TX_DESC(*tx_ring, eop);
	struct e1000_hw *hw = &adapter->hw;
	u16 phy_status, phy_1000t_status, phy_ext_status;
	u16 pci_status;

	e1e_rphy(hw, PHY_STATUS, &phy_status);
	e1e_rphy(hw, PHY_1000T_STATUS, &phy_1000t_status);
	e1e_rphy(hw, PHY_EXT_STATUS, &phy_ext_status);

	pci_read_config_word(adapter->pdev, PCI_STATUS, &pci_status);

	
	e_err("Detected Hardware Unit Hang:\n" "  TDH                  <%x>\n" "  TDT                  <%x>\n" "  next_to_use          <%x>\n" "  next_to_clean        <%x>\n" "buffer_info[next_to_clean]:\n" "  time_stamp           <%lx>\n" "  next_to_watch        <%x>\n" "  jiffies              <%lx>\n" "  next_to_watch.status <%x>\n" "MAC Status             <%x>\n" "PHY Status             <%x>\n" "PHY 1000BASE-T Status  <%x>\n" "PHY Extended Status    <%x>\n" "PCI Status             <%x>\n", readl(adapter->hw.hw_addr + tx_ring->head), readl(adapter->hw.hw_addr + tx_ring->tail), tx_ring->next_to_use, tx_ring->next_to_clean, tx_ring->buffer_info[eop].time_stamp, eop, jiffies, eop_desc->upper.fields.status, er32(STATUS), phy_status, phy_1000t_status, phy_ext_status, pci_status);


























}


static bool e1000_clean_tx_irq(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_ring *tx_ring = adapter->tx_ring;
	struct e1000_tx_desc *tx_desc, *eop_desc;
	struct e1000_buffer *buffer_info;
	unsigned int i, eop;
	unsigned int count = 0;
	unsigned int total_tx_bytes = 0, total_tx_packets = 0;

	i = tx_ring->next_to_clean;
	eop = tx_ring->buffer_info[i].next_to_watch;
	eop_desc = E1000_TX_DESC(*tx_ring, eop);

	while ((eop_desc->upper.data & cpu_to_le32(E1000_TXD_STAT_DD)) && (count < tx_ring->count)) {
		bool cleaned = false;
		for (; !cleaned; count++) {
			tx_desc = E1000_TX_DESC(*tx_ring, i);
			buffer_info = &tx_ring->buffer_info[i];
			cleaned = (i == eop);

			if (cleaned) {
				struct sk_buff *skb = buffer_info->skb;
				unsigned int segs, bytecount;
				segs = skb_shinfo(skb)->gso_segs ?: 1;
				
				bytecount = ((segs - 1) * skb_headlen(skb)) + skb->len;
				total_tx_packets += segs;
				total_tx_bytes += bytecount;
			}

			e1000_put_txbuf(adapter, buffer_info);
			tx_desc->upper.data = 0;

			i++;
			if (i == tx_ring->count)
				i = 0;
		}

		eop = tx_ring->buffer_info[i].next_to_watch;
		eop_desc = E1000_TX_DESC(*tx_ring, eop);
	}

	tx_ring->next_to_clean = i;


	if (count && netif_carrier_ok(netdev) && e1000_desc_unused(tx_ring) >= TX_WAKE_THRESHOLD) {
		
		smp_mb();

		if (netif_queue_stopped(netdev) && !(test_bit(__E1000_DOWN, &adapter->state))) {
			netif_wake_queue(netdev);
			++adapter->restart_queue;
		}
	}

	if (adapter->detect_tx_hung) {
		
		adapter->detect_tx_hung = 0;
		if (tx_ring->buffer_info[i].time_stamp && time_after(jiffies, tx_ring->buffer_info[i].time_stamp + (adapter->tx_timeout_factor * HZ)) && !(er32(STATUS) & E1000_STATUS_TXOFF)) {


			schedule_work(&adapter->print_hang_task);
			netif_stop_queue(netdev);
		}
	}
	adapter->total_tx_bytes += total_tx_bytes;
	adapter->total_tx_packets += total_tx_packets;
	netdev->stats.tx_bytes += total_tx_bytes;
	netdev->stats.tx_packets += total_tx_packets;
	return (count < tx_ring->count);
}


static bool e1000_clean_rx_irq_ps(struct e1000_adapter *adapter, int *work_done, int work_to_do)
{
	struct e1000_hw *hw = &adapter->hw;
	union e1000_rx_desc_packet_split *rx_desc, *next_rxd;
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_ring *rx_ring = adapter->rx_ring;
	struct e1000_buffer *buffer_info, *next_buffer;
	struct e1000_ps_page *ps_page;
	struct sk_buff *skb;
	unsigned int i, j;
	u32 length, staterr;
	int cleaned_count = 0;
	bool cleaned = 0;
	unsigned int total_rx_bytes = 0, total_rx_packets = 0;

	i = rx_ring->next_to_clean;
	rx_desc = E1000_RX_DESC_PS(*rx_ring, i);
	staterr = le32_to_cpu(rx_desc->wb.middle.status_error);
	buffer_info = &rx_ring->buffer_info[i];

	while (staterr & E1000_RXD_STAT_DD) {
		if (*work_done >= work_to_do)
			break;
		(*work_done)++;
		skb = buffer_info->skb;

		
		prefetch(skb->data - NET_IP_ALIGN);

		i++;
		if (i == rx_ring->count)
			i = 0;
		next_rxd = E1000_RX_DESC_PS(*rx_ring, i);
		prefetch(next_rxd);

		next_buffer = &rx_ring->buffer_info[i];

		cleaned = 1;
		cleaned_count++;
		pci_unmap_single(pdev, buffer_info->dma, adapter->rx_ps_bsize0, PCI_DMA_FROMDEVICE);

		buffer_info->dma = 0;

		if (!(staterr & E1000_RXD_STAT_EOP)) {
			e_dbg("Packet Split buffers didn't pick up the full " "packet\n");
			dev_kfree_skb_irq(skb);
			goto next_desc;
		}

		if (staterr & E1000_RXDEXT_ERR_FRAME_ERR_MASK) {
			dev_kfree_skb_irq(skb);
			goto next_desc;
		}

		length = le16_to_cpu(rx_desc->wb.middle.length0);

		if (!length) {
			e_dbg("Last part of the packet spanning multiple " "descriptors\n");
			dev_kfree_skb_irq(skb);
			goto next_desc;
		}

		
		skb_put(skb, length);

		{
		
		int l1 = le16_to_cpu(rx_desc->wb.upper.length[0]);

		
		if (l1 && (l1 <= copybreak) && ((length + l1) <= adapter->rx_ps_bsize0)) {
			u8 *vaddr;

			ps_page = &buffer_info->ps_pages[0];

			
			pci_dma_sync_single_for_cpu(pdev, ps_page->dma, PAGE_SIZE, PCI_DMA_FROMDEVICE);
			vaddr = kmap_atomic(ps_page->page, KM_SKB_DATA_SOFTIRQ);
			memcpy(skb_tail_pointer(skb), vaddr, l1);
			kunmap_atomic(vaddr, KM_SKB_DATA_SOFTIRQ);
			pci_dma_sync_single_for_device(pdev, ps_page->dma, PAGE_SIZE, PCI_DMA_FROMDEVICE);

			
			if (!(adapter->flags2 & FLAG2_CRC_STRIPPING))
				l1 -= 4;

			skb_put(skb, l1);
			goto copydone;
		} 
		}

		for (j = 0; j < PS_PAGE_BUFFERS; j++) {
			length = le16_to_cpu(rx_desc->wb.upper.length[j]);
			if (!length)
				break;

			ps_page = &buffer_info->ps_pages[j];
			pci_unmap_page(pdev, ps_page->dma, PAGE_SIZE, PCI_DMA_FROMDEVICE);
			ps_page->dma = 0;
			skb_fill_page_desc(skb, j, ps_page->page, 0, length);
			ps_page->page = NULL;
			skb->len += length;
			skb->data_len += length;
			skb->truesize += length;
		}

		
		if (!(adapter->flags2 & FLAG2_CRC_STRIPPING))
			pskb_trim(skb, skb->len - 4);

copydone:
		total_rx_bytes += skb->len;
		total_rx_packets++;

		e1000_rx_checksum(adapter, staterr, le16_to_cpu( rx_desc->wb.lower.hi_dword.csum_ip.csum), skb);

		if (rx_desc->wb.upper.header_status & cpu_to_le16(E1000_RXDPS_HDRSTAT_HDRSP))
			adapter->rx_hdr_split++;

		e1000_receive_skb(adapter, netdev, skb, staterr, rx_desc->wb.middle.vlan);

next_desc:
		rx_desc->wb.middle.status_error &= cpu_to_le32(~0xFF);
		buffer_info->skb = NULL;

		
		if (cleaned_count >= E1000_RX_BUFFER_WRITE) {
			adapter->alloc_rx_buf(adapter, cleaned_count);
			cleaned_count = 0;
		}

		
		rx_desc = next_rxd;
		buffer_info = next_buffer;

		staterr = le32_to_cpu(rx_desc->wb.middle.status_error);
	}
	rx_ring->next_to_clean = i;

	cleaned_count = e1000_desc_unused(rx_ring);
	if (cleaned_count)
		adapter->alloc_rx_buf(adapter, cleaned_count);

	adapter->total_rx_bytes += total_rx_bytes;
	adapter->total_rx_packets += total_rx_packets;
	netdev->stats.rx_bytes += total_rx_bytes;
	netdev->stats.rx_packets += total_rx_packets;
	return cleaned;
}


static void e1000_consume_page(struct e1000_buffer *bi, struct sk_buff *skb, u16 length)
{
	bi->page = NULL;
	skb->len += length;
	skb->data_len += length;
	skb->truesize += length;
}



static bool e1000_clean_jumbo_rx_irq(struct e1000_adapter *adapter, int *work_done, int work_to_do)
{
	struct net_device *netdev = adapter->netdev;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_ring *rx_ring = adapter->rx_ring;
	struct e1000_rx_desc *rx_desc, *next_rxd;
	struct e1000_buffer *buffer_info, *next_buffer;
	u32 length;
	unsigned int i;
	int cleaned_count = 0;
	bool cleaned = false;
	unsigned int total_rx_bytes=0, total_rx_packets=0;

	i = rx_ring->next_to_clean;
	rx_desc = E1000_RX_DESC(*rx_ring, i);
	buffer_info = &rx_ring->buffer_info[i];

	while (rx_desc->status & E1000_RXD_STAT_DD) {
		struct sk_buff *skb;
		u8 status;

		if (*work_done >= work_to_do)
			break;
		(*work_done)++;

		status = rx_desc->status;
		skb = buffer_info->skb;
		buffer_info->skb = NULL;

		++i;
		if (i == rx_ring->count)
			i = 0;
		next_rxd = E1000_RX_DESC(*rx_ring, i);
		prefetch(next_rxd);

		next_buffer = &rx_ring->buffer_info[i];

		cleaned = true;
		cleaned_count++;
		pci_unmap_page(pdev, buffer_info->dma, PAGE_SIZE, PCI_DMA_FROMDEVICE);
		buffer_info->dma = 0;

		length = le16_to_cpu(rx_desc->length);

		
		if (unlikely((status & E1000_RXD_STAT_EOP) && (rx_desc->errors & E1000_RXD_ERR_FRAME_ERR_MASK))) {
				
				buffer_info->skb = skb;
				
				if (rx_ring->rx_skb_top)
					dev_kfree_skb(rx_ring->rx_skb_top);
				rx_ring->rx_skb_top = NULL;
				goto next_desc;
		}


		if (!(status & E1000_RXD_STAT_EOP)) {
			
			if (!rxtop) {
				
				rxtop = skb;
				skb_fill_page_desc(rxtop, 0, buffer_info->page, 0, length);
			} else {
				
				skb_fill_page_desc(rxtop, skb_shinfo(rxtop)->nr_frags, buffer_info->page, 0, length);

				
				buffer_info->skb = skb;
			}
			e1000_consume_page(buffer_info, rxtop, length);
			goto next_desc;
		} else {
			if (rxtop) {
				
				skb_fill_page_desc(rxtop, skb_shinfo(rxtop)->nr_frags, buffer_info->page, 0, length);

				
				buffer_info->skb = skb;
				skb = rxtop;
				rxtop = NULL;
				e1000_consume_page(buffer_info, skb, length);
			} else {
				
				if (length <= copybreak && skb_tailroom(skb) >= length) {
					u8 *vaddr;
					vaddr = kmap_atomic(buffer_info->page, KM_SKB_DATA_SOFTIRQ);
					memcpy(skb_tail_pointer(skb), vaddr, length);
					kunmap_atomic(vaddr, KM_SKB_DATA_SOFTIRQ);
					
					skb_put(skb, length);
				} else {
					skb_fill_page_desc(skb, 0, buffer_info->page, 0, length);

					e1000_consume_page(buffer_info, skb, length);
				}
			}
		}

		
		e1000_rx_checksum(adapter, (u32)(status) | ((u32)(rx_desc->errors) << 24), le16_to_cpu(rx_desc->csum), skb);



		
		total_rx_bytes += skb->len;
		total_rx_packets++;

		
		if (!pskb_may_pull(skb, ETH_HLEN)) {
			e_err("pskb_may_pull failed.\n");
			dev_kfree_skb(skb);
			goto next_desc;
		}

		e1000_receive_skb(adapter, netdev, skb, status, rx_desc->special);

next_desc:
		rx_desc->status = 0;

		
		if (unlikely(cleaned_count >= E1000_RX_BUFFER_WRITE)) {
			adapter->alloc_rx_buf(adapter, cleaned_count);
			cleaned_count = 0;
		}

		
		rx_desc = next_rxd;
		buffer_info = next_buffer;
	}
	rx_ring->next_to_clean = i;

	cleaned_count = e1000_desc_unused(rx_ring);
	if (cleaned_count)
		adapter->alloc_rx_buf(adapter, cleaned_count);

	adapter->total_rx_bytes += total_rx_bytes;
	adapter->total_rx_packets += total_rx_packets;
	netdev->stats.rx_bytes += total_rx_bytes;
	netdev->stats.rx_packets += total_rx_packets;
	return cleaned;
}


static void e1000_clean_rx_ring(struct e1000_adapter *adapter)
{
	struct e1000_ring *rx_ring = adapter->rx_ring;
	struct e1000_buffer *buffer_info;
	struct e1000_ps_page *ps_page;
	struct pci_dev *pdev = adapter->pdev;
	unsigned int i, j;

	
	for (i = 0; i < rx_ring->count; i++) {
		buffer_info = &rx_ring->buffer_info[i];
		if (buffer_info->dma) {
			if (adapter->clean_rx == e1000_clean_rx_irq)
				pci_unmap_single(pdev, buffer_info->dma, adapter->rx_buffer_len, PCI_DMA_FROMDEVICE);

			else if (adapter->clean_rx == e1000_clean_jumbo_rx_irq)
				pci_unmap_page(pdev, buffer_info->dma, PAGE_SIZE, PCI_DMA_FROMDEVICE);

			else if (adapter->clean_rx == e1000_clean_rx_irq_ps)
				pci_unmap_single(pdev, buffer_info->dma, adapter->rx_ps_bsize0, PCI_DMA_FROMDEVICE);

			buffer_info->dma = 0;
		}

		if (buffer_info->page) {
			put_page(buffer_info->page);
			buffer_info->page = NULL;
		}

		if (buffer_info->skb) {
			dev_kfree_skb(buffer_info->skb);
			buffer_info->skb = NULL;
		}

		for (j = 0; j < PS_PAGE_BUFFERS; j++) {
			ps_page = &buffer_info->ps_pages[j];
			if (!ps_page->page)
				break;
			pci_unmap_page(pdev, ps_page->dma, PAGE_SIZE, PCI_DMA_FROMDEVICE);
			ps_page->dma = 0;
			put_page(ps_page->page);
			ps_page->page = NULL;
		}
	}

	
	if (rx_ring->rx_skb_top) {
		dev_kfree_skb(rx_ring->rx_skb_top);
		rx_ring->rx_skb_top = NULL;
	}

	
	memset(rx_ring->desc, 0, rx_ring->size);

	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;

	writel(0, adapter->hw.hw_addr + rx_ring->head);
	writel(0, adapter->hw.hw_addr + rx_ring->tail);
}

static void e1000e_downshift_workaround(struct work_struct *work)
{
	struct e1000_adapter *adapter = container_of(work, struct e1000_adapter, downshift_task);

	e1000e_gig_downshift_workaround_ich8lan(&adapter->hw);
}


static irqreturn_t e1000_intr_msi(int irq, void *data)
{
	struct net_device *netdev = data;
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 icr = er32(ICR);

	

	if (icr & E1000_ICR_LSC) {
		hw->mac.get_link_status = 1;
		
		if ((adapter->flags & FLAG_LSC_GIG_SPEED_DROP) && (!(er32(STATUS) & E1000_STATUS_LU)))
			schedule_work(&adapter->downshift_task);

		
		if (netif_carrier_ok(netdev) && adapter->flags & FLAG_RX_NEEDS_RESTART) {
			
			u32 rctl = er32(RCTL);
			ew32(RCTL, rctl & ~E1000_RCTL_EN);
			adapter->flags |= FLAG_RX_RESTART_NOW;
		}
		
		if (!test_bit(__E1000_DOWN, &adapter->state))
			mod_timer(&adapter->watchdog_timer, jiffies + 1);
	}

	if (napi_schedule_prep(&adapter->napi)) {
		adapter->total_tx_bytes = 0;
		adapter->total_tx_packets = 0;
		adapter->total_rx_bytes = 0;
		adapter->total_rx_packets = 0;
		__napi_schedule(&adapter->napi);
	}

	return IRQ_HANDLED;
}


static irqreturn_t e1000_intr(int irq, void *data)
{
	struct net_device *netdev = data;
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 rctl, icr = er32(ICR);

	if (!icr || test_bit(__E1000_DOWN, &adapter->state))
		return IRQ_NONE;  

	
	if (!(icr & E1000_ICR_INT_ASSERTED))
		return IRQ_NONE;

	

	if (icr & E1000_ICR_LSC) {
		hw->mac.get_link_status = 1;
		
		if ((adapter->flags & FLAG_LSC_GIG_SPEED_DROP) && (!(er32(STATUS) & E1000_STATUS_LU)))
			schedule_work(&adapter->downshift_task);

		
		if (netif_carrier_ok(netdev) && (adapter->flags & FLAG_RX_NEEDS_RESTART)) {
			
			rctl = er32(RCTL);
			ew32(RCTL, rctl & ~E1000_RCTL_EN);
			adapter->flags |= FLAG_RX_RESTART_NOW;
		}
		
		if (!test_bit(__E1000_DOWN, &adapter->state))
			mod_timer(&adapter->watchdog_timer, jiffies + 1);
	}

	if (napi_schedule_prep(&adapter->napi)) {
		adapter->total_tx_bytes = 0;
		adapter->total_tx_packets = 0;
		adapter->total_rx_bytes = 0;
		adapter->total_rx_packets = 0;
		__napi_schedule(&adapter->napi);
	}

	return IRQ_HANDLED;
}

static irqreturn_t e1000_msix_other(int irq, void *data)
{
	struct net_device *netdev = data;
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 icr = er32(ICR);

	if (!(icr & E1000_ICR_INT_ASSERTED)) {
		if (!test_bit(__E1000_DOWN, &adapter->state))
			ew32(IMS, E1000_IMS_OTHER);
		return IRQ_NONE;
	}

	if (icr & adapter->eiac_mask)
		ew32(ICS, (icr & adapter->eiac_mask));

	if (icr & E1000_ICR_OTHER) {
		if (!(icr & E1000_ICR_LSC))
			goto no_link_interrupt;
		hw->mac.get_link_status = 1;
		
		if (!test_bit(__E1000_DOWN, &adapter->state))
			mod_timer(&adapter->watchdog_timer, jiffies + 1);
	}

no_link_interrupt:
	if (!test_bit(__E1000_DOWN, &adapter->state))
		ew32(IMS, E1000_IMS_LSC | E1000_IMS_OTHER);

	return IRQ_HANDLED;
}


static irqreturn_t e1000_intr_msix_tx(int irq, void *data)
{
	struct net_device *netdev = data;
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_ring *tx_ring = adapter->tx_ring;


	adapter->total_tx_bytes = 0;
	adapter->total_tx_packets = 0;

	if (!e1000_clean_tx_irq(adapter))
		
		ew32(ICS, tx_ring->ims_val);

	return IRQ_HANDLED;
}

static irqreturn_t e1000_intr_msix_rx(int irq, void *data)
{
	struct net_device *netdev = data;
	struct e1000_adapter *adapter = netdev_priv(netdev);

	
	if (adapter->rx_ring->set_itr) {
		writel(1000000000 / (adapter->rx_ring->itr_val * 256), adapter->hw.hw_addr + adapter->rx_ring->itr_register);
		adapter->rx_ring->set_itr = 0;
	}

	if (napi_schedule_prep(&adapter->napi)) {
		adapter->total_rx_bytes = 0;
		adapter->total_rx_packets = 0;
		__napi_schedule(&adapter->napi);
	}
	return IRQ_HANDLED;
}


static void e1000_configure_msix(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_ring *rx_ring = adapter->rx_ring;
	struct e1000_ring *tx_ring = adapter->tx_ring;
	int vector = 0;
	u32 ctrl_ext, ivar = 0;

	adapter->eiac_mask = 0;

	
	if (hw->mac.type == e1000_82574) {
		u32 rfctl = er32(RFCTL);
		rfctl |= E1000_RFCTL_ACK_DIS;
		ew32(RFCTL, rfctl);
	}


	
	rx_ring->ims_val = E1000_IMS_RXQ0;
	adapter->eiac_mask |= rx_ring->ims_val;
	if (rx_ring->itr_val)
		writel(1000000000 / (rx_ring->itr_val * 256), hw->hw_addr + rx_ring->itr_register);
	else writel(1, hw->hw_addr + rx_ring->itr_register);
	ivar = E1000_IVAR_INT_ALLOC_VALID | vector;

	
	tx_ring->ims_val = E1000_IMS_TXQ0;
	vector++;
	if (tx_ring->itr_val)
		writel(1000000000 / (tx_ring->itr_val * 256), hw->hw_addr + tx_ring->itr_register);
	else writel(1, hw->hw_addr + tx_ring->itr_register);
	adapter->eiac_mask |= tx_ring->ims_val;
	ivar |= ((E1000_IVAR_INT_ALLOC_VALID | vector) << 8);

	
	vector++;
	ivar |= ((E1000_IVAR_INT_ALLOC_VALID | vector) << 16);
	if (rx_ring->itr_val)
		writel(1000000000 / (rx_ring->itr_val * 256), hw->hw_addr + E1000_EITR_82574(vector));
	else writel(1, hw->hw_addr + E1000_EITR_82574(vector));

	
	ivar |= (1 << 31);

	ew32(IVAR, ivar);

	
	ctrl_ext = er32(CTRL_EXT);
	ctrl_ext |= E1000_CTRL_EXT_PBA_CLR;

	

	ew32(IAM, ~E1000_EIAC_MASK_82574 | E1000_IMS_OTHER);
	ctrl_ext |= E1000_CTRL_EXT_EIAME;
	ew32(CTRL_EXT, ctrl_ext);
	e1e_flush();
}

void e1000e_reset_interrupt_capability(struct e1000_adapter *adapter)
{
	if (adapter->msix_entries) {
		pci_disable_msix(adapter->pdev);
		kfree(adapter->msix_entries);
		adapter->msix_entries = NULL;
	} else if (adapter->flags & FLAG_MSI_ENABLED) {
		pci_disable_msi(adapter->pdev);
		adapter->flags &= ~FLAG_MSI_ENABLED;
	}

	return;
}


void e1000e_set_interrupt_capability(struct e1000_adapter *adapter)
{
	int err;
	int numvecs, i;


	switch (adapter->int_mode) {
	case E1000E_INT_MODE_MSIX:
		if (adapter->flags & FLAG_HAS_MSIX) {
			numvecs = 3; 
			adapter->msix_entries = kcalloc(numvecs, sizeof(struct msix_entry), GFP_KERNEL);

			if (adapter->msix_entries) {
				for (i = 0; i < numvecs; i++)
					adapter->msix_entries[i].entry = i;

				err = pci_enable_msix(adapter->pdev, adapter->msix_entries, numvecs);

				if (err == 0)
					return;
			}
			
			e_err("Failed to initialize MSI-X interrupts.  " "Falling back to MSI interrupts.\n");
			e1000e_reset_interrupt_capability(adapter);
		}
		adapter->int_mode = E1000E_INT_MODE_MSI;
		
	case E1000E_INT_MODE_MSI:
		if (!pci_enable_msi(adapter->pdev)) {
			adapter->flags |= FLAG_MSI_ENABLED;
		} else {
			adapter->int_mode = E1000E_INT_MODE_LEGACY;
			e_err("Failed to initialize MSI interrupts.  Falling " "back to legacy interrupts.\n");
		}
		
	case E1000E_INT_MODE_LEGACY:
		
		break;
	}

	return;
}


static int e1000_request_msix(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int err = 0, vector = 0;

	if (strlen(netdev->name) < (IFNAMSIZ - 5))
		sprintf(adapter->rx_ring->name, "%s-rx-0", netdev->name);
	else memcpy(adapter->rx_ring->name, netdev->name, IFNAMSIZ);
	err = request_irq(adapter->msix_entries[vector].vector, e1000_intr_msix_rx, 0, adapter->rx_ring->name, netdev);

	if (err)
		goto out;
	adapter->rx_ring->itr_register = E1000_EITR_82574(vector);
	adapter->rx_ring->itr_val = adapter->itr;
	vector++;

	if (strlen(netdev->name) < (IFNAMSIZ - 5))
		sprintf(adapter->tx_ring->name, "%s-tx-0", netdev->name);
	else memcpy(adapter->tx_ring->name, netdev->name, IFNAMSIZ);
	err = request_irq(adapter->msix_entries[vector].vector, e1000_intr_msix_tx, 0, adapter->tx_ring->name, netdev);

	if (err)
		goto out;
	adapter->tx_ring->itr_register = E1000_EITR_82574(vector);
	adapter->tx_ring->itr_val = adapter->itr;
	vector++;

	err = request_irq(adapter->msix_entries[vector].vector, e1000_msix_other, 0, netdev->name, netdev);
	if (err)
		goto out;

	e1000_configure_msix(adapter);
	return 0;
out:
	return err;
}


static int e1000_request_irq(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	int err;

	if (adapter->msix_entries) {
		err = e1000_request_msix(adapter);
		if (!err)
			return err;
		
		e1000e_reset_interrupt_capability(adapter);
		adapter->int_mode = E1000E_INT_MODE_MSI;
		e1000e_set_interrupt_capability(adapter);
	}
	if (adapter->flags & FLAG_MSI_ENABLED) {
		err = request_irq(adapter->pdev->irq, e1000_intr_msi, 0, netdev->name, netdev);
		if (!err)
			return err;

		
		e1000e_reset_interrupt_capability(adapter);
		adapter->int_mode = E1000E_INT_MODE_LEGACY;
	}

	err = request_irq(adapter->pdev->irq, e1000_intr, IRQF_SHARED, netdev->name, netdev);
	if (err)
		e_err("Unable to allocate interrupt, Error: %d\n", err);

	return err;
}

static void e1000_free_irq(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	if (adapter->msix_entries) {
		int vector = 0;

		free_irq(adapter->msix_entries[vector].vector, netdev);
		vector++;

		free_irq(adapter->msix_entries[vector].vector, netdev);
		vector++;

		
		free_irq(adapter->msix_entries[vector].vector, netdev);
		return;
	}

	free_irq(adapter->pdev->irq, netdev);
}


static void e1000_irq_disable(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	ew32(IMC, ~0);
	if (adapter->msix_entries)
		ew32(EIAC_82574, 0);
	e1e_flush();
	synchronize_irq(adapter->pdev->irq);
}


static void e1000_irq_enable(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	if (adapter->msix_entries) {
		ew32(EIAC_82574, adapter->eiac_mask & E1000_EIAC_MASK_82574);
		ew32(IMS, adapter->eiac_mask | E1000_IMS_OTHER | E1000_IMS_LSC);
	} else {
		ew32(IMS, IMS_ENABLE_MASK);
	}
	e1e_flush();
}


static void e1000_get_hw_control(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 ctrl_ext;
	u32 swsm;

	
	if (adapter->flags & FLAG_HAS_SWSM_ON_LOAD) {
		swsm = er32(SWSM);
		ew32(SWSM, swsm | E1000_SWSM_DRV_LOAD);
	} else if (adapter->flags & FLAG_HAS_CTRLEXT_ON_LOAD) {
		ctrl_ext = er32(CTRL_EXT);
		ew32(CTRL_EXT, ctrl_ext | E1000_CTRL_EXT_DRV_LOAD);
	}
}


static void e1000_release_hw_control(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 ctrl_ext;
	u32 swsm;

	
	if (adapter->flags & FLAG_HAS_SWSM_ON_LOAD) {
		swsm = er32(SWSM);
		ew32(SWSM, swsm & ~E1000_SWSM_DRV_LOAD);
	} else if (adapter->flags & FLAG_HAS_CTRLEXT_ON_LOAD) {
		ctrl_ext = er32(CTRL_EXT);
		ew32(CTRL_EXT, ctrl_ext & ~E1000_CTRL_EXT_DRV_LOAD);
	}
}


static int e1000_alloc_ring_dma(struct e1000_adapter *adapter, struct e1000_ring *ring)
{
	struct pci_dev *pdev = adapter->pdev;

	ring->desc = dma_alloc_coherent(&pdev->dev, ring->size, &ring->dma, GFP_KERNEL);
	if (!ring->desc)
		return -ENOMEM;

	return 0;
}


int e1000e_setup_tx_resources(struct e1000_adapter *adapter)
{
	struct e1000_ring *tx_ring = adapter->tx_ring;
	int err = -ENOMEM, size;

	size = sizeof(struct e1000_buffer) * tx_ring->count;
	tx_ring->buffer_info = vmalloc(size);
	if (!tx_ring->buffer_info)
		goto err;
	memset(tx_ring->buffer_info, 0, size);

	
	tx_ring->size = tx_ring->count * sizeof(struct e1000_tx_desc);
	tx_ring->size = ALIGN(tx_ring->size, 4096);

	err = e1000_alloc_ring_dma(adapter, tx_ring);
	if (err)
		goto err;

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	return 0;
err:
	vfree(tx_ring->buffer_info);
	e_err("Unable to allocate memory for the transmit descriptor ring\n");
	return err;
}


int e1000e_setup_rx_resources(struct e1000_adapter *adapter)
{
	struct e1000_ring *rx_ring = adapter->rx_ring;
	struct e1000_buffer *buffer_info;
	int i, size, desc_len, err = -ENOMEM;

	size = sizeof(struct e1000_buffer) * rx_ring->count;
	rx_ring->buffer_info = vmalloc(size);
	if (!rx_ring->buffer_info)
		goto err;
	memset(rx_ring->buffer_info, 0, size);

	for (i = 0; i < rx_ring->count; i++) {
		buffer_info = &rx_ring->buffer_info[i];
		buffer_info->ps_pages = kcalloc(PS_PAGE_BUFFERS, sizeof(struct e1000_ps_page), GFP_KERNEL);

		if (!buffer_info->ps_pages)
			goto err_pages;
	}

	desc_len = sizeof(union e1000_rx_desc_packet_split);

	
	rx_ring->size = rx_ring->count * desc_len;
	rx_ring->size = ALIGN(rx_ring->size, 4096);

	err = e1000_alloc_ring_dma(adapter, rx_ring);
	if (err)
		goto err_pages;

	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;
	rx_ring->rx_skb_top = NULL;

	return 0;

err_pages:
	for (i = 0; i < rx_ring->count; i++) {
		buffer_info = &rx_ring->buffer_info[i];
		kfree(buffer_info->ps_pages);
	}
err:
	vfree(rx_ring->buffer_info);
	e_err("Unable to allocate memory for the transmit descriptor ring\n");
	return err;
}


static void e1000_clean_tx_ring(struct e1000_adapter *adapter)
{
	struct e1000_ring *tx_ring = adapter->tx_ring;
	struct e1000_buffer *buffer_info;
	unsigned long size;
	unsigned int i;

	for (i = 0; i < tx_ring->count; i++) {
		buffer_info = &tx_ring->buffer_info[i];
		e1000_put_txbuf(adapter, buffer_info);
	}

	size = sizeof(struct e1000_buffer) * tx_ring->count;
	memset(tx_ring->buffer_info, 0, size);

	memset(tx_ring->desc, 0, tx_ring->size);

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	writel(0, adapter->hw.hw_addr + tx_ring->head);
	writel(0, adapter->hw.hw_addr + tx_ring->tail);
}


void e1000e_free_tx_resources(struct e1000_adapter *adapter)
{
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_ring *tx_ring = adapter->tx_ring;

	e1000_clean_tx_ring(adapter);

	vfree(tx_ring->buffer_info);
	tx_ring->buffer_info = NULL;

	dma_free_coherent(&pdev->dev, tx_ring->size, tx_ring->desc, tx_ring->dma);
	tx_ring->desc = NULL;
}



void e1000e_free_rx_resources(struct e1000_adapter *adapter)
{
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_ring *rx_ring = adapter->rx_ring;
	int i;

	e1000_clean_rx_ring(adapter);

	for (i = 0; i < rx_ring->count; i++) {
		kfree(rx_ring->buffer_info[i].ps_pages);
	}

	vfree(rx_ring->buffer_info);
	rx_ring->buffer_info = NULL;

	dma_free_coherent(&pdev->dev, rx_ring->size, rx_ring->desc, rx_ring->dma);
	rx_ring->desc = NULL;
}


static unsigned int e1000_update_itr(struct e1000_adapter *adapter, u16 itr_setting, int packets, int bytes)

{
	unsigned int retval = itr_setting;

	if (packets == 0)
		goto update_itr_done;

	switch (itr_setting) {
	case lowest_latency:
		
		if (bytes/packets > 8000)
			retval = bulk_latency;
		else if ((packets < 5) && (bytes > 512)) {
			retval = low_latency;
		}
		break;
	case low_latency:  
		if (bytes > 10000) {
			
			if (bytes/packets > 8000) {
				retval = bulk_latency;
			} else if ((packets < 10) || ((bytes/packets) > 1200)) {
				retval = bulk_latency;
			} else if ((packets > 35)) {
				retval = lowest_latency;
			}
		} else if (bytes/packets > 2000) {
			retval = bulk_latency;
		} else if (packets <= 2 && bytes < 512) {
			retval = lowest_latency;
		}
		break;
	case bulk_latency: 
		if (bytes > 25000) {
			if (packets > 35) {
				retval = low_latency;
			}
		} else if (bytes < 6000) {
			retval = low_latency;
		}
		break;
	}

update_itr_done:
	return retval;
}

static void e1000_set_itr(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u16 current_itr;
	u32 new_itr = adapter->itr;

	
	if (adapter->link_speed != SPEED_1000) {
		current_itr = 0;
		new_itr = 4000;
		goto set_itr_now;
	}

	adapter->tx_itr = e1000_update_itr(adapter, adapter->tx_itr, adapter->total_tx_packets, adapter->total_tx_bytes);


	
	if (adapter->itr_setting == 3 && adapter->tx_itr == lowest_latency)
		adapter->tx_itr = low_latency;

	adapter->rx_itr = e1000_update_itr(adapter, adapter->rx_itr, adapter->total_rx_packets, adapter->total_rx_bytes);


	
	if (adapter->itr_setting == 3 && adapter->rx_itr == lowest_latency)
		adapter->rx_itr = low_latency;

	current_itr = max(adapter->rx_itr, adapter->tx_itr);

	switch (current_itr) {
	
	case lowest_latency:
		new_itr = 70000;
		break;
	case low_latency:
		new_itr = 20000; 
		break;
	case bulk_latency:
		new_itr = 4000;
		break;
	default:
		break;
	}

set_itr_now:
	if (new_itr != adapter->itr) {
		
		new_itr = new_itr > adapter->itr ? min(adapter->itr + (new_itr >> 2), new_itr) :
			     new_itr;
		adapter->itr = new_itr;
		adapter->rx_ring->itr_val = new_itr;
		if (adapter->msix_entries)
			adapter->rx_ring->set_itr = 1;
		else ew32(ITR, 1000000000 / (new_itr * 256));
	}
}


static int __devinit e1000_alloc_queues(struct e1000_adapter *adapter)
{
	adapter->tx_ring = kzalloc(sizeof(struct e1000_ring), GFP_KERNEL);
	if (!adapter->tx_ring)
		goto err;

	adapter->rx_ring = kzalloc(sizeof(struct e1000_ring), GFP_KERNEL);
	if (!adapter->rx_ring)
		goto err;

	return 0;
err:
	e_err("Unable to allocate memory for queues\n");
	kfree(adapter->rx_ring);
	kfree(adapter->tx_ring);
	return -ENOMEM;
}


static int e1000_clean(struct napi_struct *napi, int budget)
{
	struct e1000_adapter *adapter = container_of(napi, struct e1000_adapter, napi);
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *poll_dev = adapter->netdev;
	int tx_cleaned = 1, work_done = 0;

	adapter = netdev_priv(poll_dev);

	if (adapter->msix_entries && !(adapter->rx_ring->ims_val & adapter->tx_ring->ims_val))
		goto clean_rx;

	tx_cleaned = e1000_clean_tx_irq(adapter);

clean_rx:
	adapter->clean_rx(adapter, &work_done, budget);

	if (!tx_cleaned)
		work_done = budget;

	
	if (work_done < budget) {
		if (adapter->itr_setting & 3)
			e1000_set_itr(adapter);
		napi_complete(napi);
		if (!test_bit(__E1000_DOWN, &adapter->state)) {
			if (adapter->msix_entries)
				ew32(IMS, adapter->rx_ring->ims_val);
			else e1000_irq_enable(adapter);
		}
	}

	return work_done;
}

static void e1000_vlan_rx_add_vid(struct net_device *netdev, u16 vid)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 vfta, index;

	
	if ((adapter->hw.mng_cookie.status & E1000_MNG_DHCP_COOKIE_STATUS_VLAN) && (vid == adapter->mng_vlan_id))

		return;

	
	if (adapter->flags & FLAG_HAS_HW_VLAN_FILTER) {
		index = (vid >> 5) & 0x7F;
		vfta = E1000_READ_REG_ARRAY(hw, E1000_VFTA, index);
		vfta |= (1 << (vid & 0x1F));
		hw->mac.ops.write_vfta(hw, index, vfta);
	}
}

static void e1000_vlan_rx_kill_vid(struct net_device *netdev, u16 vid)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 vfta, index;

	if (!test_bit(__E1000_DOWN, &adapter->state))
		e1000_irq_disable(adapter);
	vlan_group_set_device(adapter->vlgrp, vid, NULL);

	if (!test_bit(__E1000_DOWN, &adapter->state))
		e1000_irq_enable(adapter);

	if ((adapter->hw.mng_cookie.status & E1000_MNG_DHCP_COOKIE_STATUS_VLAN) && (vid == adapter->mng_vlan_id)) {

		
		e1000_release_hw_control(adapter);
		return;
	}

	
	if (adapter->flags & FLAG_HAS_HW_VLAN_FILTER) {
		index = (vid >> 5) & 0x7F;
		vfta = E1000_READ_REG_ARRAY(hw, E1000_VFTA, index);
		vfta &= ~(1 << (vid & 0x1F));
		hw->mac.ops.write_vfta(hw, index, vfta);
	}
}

static void e1000_update_mng_vlan(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	u16 vid = adapter->hw.mng_cookie.vlan_id;
	u16 old_vid = adapter->mng_vlan_id;

	if (!adapter->vlgrp)
		return;

	if (!vlan_group_get_device(adapter->vlgrp, vid)) {
		adapter->mng_vlan_id = E1000_MNG_VLAN_NONE;
		if (adapter->hw.mng_cookie.status & E1000_MNG_DHCP_COOKIE_STATUS_VLAN) {
			e1000_vlan_rx_add_vid(netdev, vid);
			adapter->mng_vlan_id = vid;
		}

		if ((old_vid != (u16)E1000_MNG_VLAN_NONE) && (vid != old_vid) && !vlan_group_get_device(adapter->vlgrp, old_vid))

			e1000_vlan_rx_kill_vid(netdev, old_vid);
	} else {
		adapter->mng_vlan_id = vid;
	}
}


static void e1000_vlan_rx_register(struct net_device *netdev, struct vlan_group *grp)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 ctrl, rctl;

	if (!test_bit(__E1000_DOWN, &adapter->state))
		e1000_irq_disable(adapter);
	adapter->vlgrp = grp;

	if (grp) {
		
		ctrl = er32(CTRL);
		ctrl |= E1000_CTRL_VME;
		ew32(CTRL, ctrl);

		if (adapter->flags & FLAG_HAS_HW_VLAN_FILTER) {
			
			rctl = er32(RCTL);
			rctl &= ~E1000_RCTL_CFIEN;
			ew32(RCTL, rctl);
			e1000_update_mng_vlan(adapter);
		}
	} else {
		
		ctrl = er32(CTRL);
		ctrl &= ~E1000_CTRL_VME;
		ew32(CTRL, ctrl);

		if (adapter->flags & FLAG_HAS_HW_VLAN_FILTER) {
			if (adapter->mng_vlan_id != (u16)E1000_MNG_VLAN_NONE) {
				e1000_vlan_rx_kill_vid(netdev, adapter->mng_vlan_id);
				adapter->mng_vlan_id = E1000_MNG_VLAN_NONE;
			}
		}
	}

	if (!test_bit(__E1000_DOWN, &adapter->state))
		e1000_irq_enable(adapter);
}

static void e1000_restore_vlan(struct e1000_adapter *adapter)
{
	u16 vid;

	e1000_vlan_rx_register(adapter->netdev, adapter->vlgrp);

	if (!adapter->vlgrp)
		return;

	for (vid = 0; vid < VLAN_GROUP_ARRAY_LEN; vid++) {
		if (!vlan_group_get_device(adapter->vlgrp, vid))
			continue;
		e1000_vlan_rx_add_vid(adapter->netdev, vid);
	}
}

static void e1000_init_manageability(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 manc, manc2h;

	if (!(adapter->flags & FLAG_MNG_PT_ENABLED))
		return;

	manc = er32(MANC);

	
	manc |= E1000_MANC_EN_MNG2HOST;
	manc2h = er32(MANC2H);


	manc2h |= E1000_MNG2HOST_PORT_623;
	manc2h |= E1000_MNG2HOST_PORT_664;
	ew32(MANC2H, manc2h);
	ew32(MANC, manc);
}


static void e1000_configure_tx(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_ring *tx_ring = adapter->tx_ring;
	u64 tdba;
	u32 tdlen, tctl, tipg, tarc;
	u32 ipgr1, ipgr2;

	
	tdba = tx_ring->dma;
	tdlen = tx_ring->count * sizeof(struct e1000_tx_desc);
	ew32(TDBAL, (tdba & DMA_BIT_MASK(32)));
	ew32(TDBAH, (tdba >> 32));
	ew32(TDLEN, tdlen);
	ew32(TDH, 0);
	ew32(TDT, 0);
	tx_ring->head = E1000_TDH;
	tx_ring->tail = E1000_TDT;

	
	tipg = DEFAULT_82543_TIPG_IPGT_COPPER;          
	ipgr1 = DEFAULT_82543_TIPG_IPGR1;               
	ipgr2 = DEFAULT_82543_TIPG_IPGR2;               

	if (adapter->flags & FLAG_TIPG_MEDIUM_FOR_80003ESLAN)
		ipgr2 = DEFAULT_80003ES2LAN_TIPG_IPGR2; 

	tipg |= ipgr1 << E1000_TIPG_IPGR1_SHIFT;
	tipg |= ipgr2 << E1000_TIPG_IPGR2_SHIFT;
	ew32(TIPG, tipg);

	
	ew32(TIDV, adapter->tx_int_delay);
	
	ew32(TADV, adapter->tx_abs_int_delay);

	
	tctl = er32(TCTL);
	tctl &= ~E1000_TCTL_CT;
	tctl |= E1000_TCTL_PSP | E1000_TCTL_RTLC | (E1000_COLLISION_THRESHOLD << E1000_CT_SHIFT);

	if (adapter->flags & FLAG_TARC_SPEED_MODE_BIT) {
		tarc = er32(TARC(0));
		

		tarc |= SPEED_MODE_BIT;
		ew32(TARC(0), tarc);
	}

	
	if (adapter->flags & FLAG_TARC_SET_BIT_ZERO) {
		tarc = er32(TARC(0));
		tarc |= 1;
		ew32(TARC(0), tarc);
		tarc = er32(TARC(1));
		tarc |= 1;
		ew32(TARC(1), tarc);
	}

	
	adapter->txd_cmd = E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS;

	
	if (adapter->tx_int_delay)
		adapter->txd_cmd |= E1000_TXD_CMD_IDE;

	
	adapter->txd_cmd |= E1000_TXD_CMD_RS;

	ew32(TCTL, tctl);

	e1000e_config_collision_dist(hw);

	adapter->tx_queue_len = adapter->netdev->tx_queue_len;
}



static void e1000_setup_rctl(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 rctl, rfctl;
	u32 psrctl = 0;
	u32 pages = 0;

	
	rctl = er32(RCTL);
	rctl &= ~(3 << E1000_RCTL_MO_SHIFT);
	rctl |= E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_LBM_NO | E1000_RCTL_RDMTS_HALF | (adapter->hw.mac.mc_filter_type << E1000_RCTL_MO_SHIFT);


	
	rctl &= ~E1000_RCTL_SBP;

	
	if (adapter->netdev->mtu <= ETH_DATA_LEN)
		rctl &= ~E1000_RCTL_LPE;
	else rctl |= E1000_RCTL_LPE;

	
	if (adapter->flags2 & FLAG2_CRC_STRIPPING)
		rctl |= E1000_RCTL_SECRC;

	
	if ((hw->phy.type == e1000_phy_82577) && (rctl & E1000_RCTL_LPE)) {
		u16 phy_data;

		e1e_rphy(hw, PHY_REG(770, 26), &phy_data);
		phy_data &= 0xfff8;
		phy_data |= (1 << 2);
		e1e_wphy(hw, PHY_REG(770, 26), phy_data);

		e1e_rphy(hw, 22, &phy_data);
		phy_data &= 0x0fff;
		phy_data |= (1 << 14);
		e1e_wphy(hw, 0x10, 0x2823);
		e1e_wphy(hw, 0x11, 0x0003);
		e1e_wphy(hw, 22, phy_data);
	}

	
	rctl &= ~E1000_RCTL_SZ_4096;
	rctl |= E1000_RCTL_BSEX;
	switch (adapter->rx_buffer_len) {
	case 256:
		rctl |= E1000_RCTL_SZ_256;
		rctl &= ~E1000_RCTL_BSEX;
		break;
	case 512:
		rctl |= E1000_RCTL_SZ_512;
		rctl &= ~E1000_RCTL_BSEX;
		break;
	case 1024:
		rctl |= E1000_RCTL_SZ_1024;
		rctl &= ~E1000_RCTL_BSEX;
		break;
	case 2048:
	default:
		rctl |= E1000_RCTL_SZ_2048;
		rctl &= ~E1000_RCTL_BSEX;
		break;
	case 4096:
		rctl |= E1000_RCTL_SZ_4096;
		break;
	case 8192:
		rctl |= E1000_RCTL_SZ_8192;
		break;
	case 16384:
		rctl |= E1000_RCTL_SZ_16384;
		break;
	}

	
	pages = PAGE_USE_COUNT(adapter->netdev->mtu);
	if (!(adapter->flags & FLAG_IS_ICH) && (pages <= 3) && (PAGE_SIZE <= 16384) && (rctl & E1000_RCTL_LPE))
		adapter->rx_ps_pages = pages;
	else adapter->rx_ps_pages = 0;

	if (adapter->rx_ps_pages) {
		
		rfctl = er32(RFCTL);
		rfctl |= E1000_RFCTL_EXTEN;
		
		rfctl |= (E1000_RFCTL_IPV6_EX_DIS | E1000_RFCTL_NEW_IPV6_EXT_DIS);

		ew32(RFCTL, rfctl);

		
		rctl |= E1000_RCTL_DTYP_PS;

		psrctl |= adapter->rx_ps_bsize0 >> E1000_PSRCTL_BSIZE0_SHIFT;

		switch (adapter->rx_ps_pages) {
		case 3:
			psrctl |= PAGE_SIZE << E1000_PSRCTL_BSIZE3_SHIFT;
		case 2:
			psrctl |= PAGE_SIZE << E1000_PSRCTL_BSIZE2_SHIFT;
		case 1:
			psrctl |= PAGE_SIZE >> E1000_PSRCTL_BSIZE1_SHIFT;
			break;
		}

		ew32(PSRCTL, psrctl);
	}

	ew32(RCTL, rctl);
	
	adapter->flags &= ~FLAG_RX_RESTART_NOW;
}


static void e1000_configure_rx(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_ring *rx_ring = adapter->rx_ring;
	u64 rdba;
	u32 rdlen, rctl, rxcsum, ctrl_ext;

	if (adapter->rx_ps_pages) {
		
		rdlen = rx_ring->count * sizeof(union e1000_rx_desc_packet_split);
		adapter->clean_rx = e1000_clean_rx_irq_ps;
		adapter->alloc_rx_buf = e1000_alloc_rx_buffers_ps;
	} else if (adapter->netdev->mtu > ETH_FRAME_LEN + ETH_FCS_LEN) {
		rdlen = rx_ring->count * sizeof(struct e1000_rx_desc);
		adapter->clean_rx = e1000_clean_jumbo_rx_irq;
		adapter->alloc_rx_buf = e1000_alloc_jumbo_rx_buffers;
	} else {
		rdlen = rx_ring->count * sizeof(struct e1000_rx_desc);
		adapter->clean_rx = e1000_clean_rx_irq;
		adapter->alloc_rx_buf = e1000_alloc_rx_buffers;
	}

	
	rctl = er32(RCTL);
	ew32(RCTL, rctl & ~E1000_RCTL_EN);
	e1e_flush();
	msleep(10);

	
	ew32(RDTR, adapter->rx_int_delay);

	
	ew32(RADV, adapter->rx_abs_int_delay);
	if (adapter->itr_setting != 0)
		ew32(ITR, 1000000000 / (adapter->itr * 256));

	ctrl_ext = er32(CTRL_EXT);
	
	ctrl_ext |= E1000_CTRL_EXT_IAME;
	ew32(IAM, 0xffffffff);
	ew32(CTRL_EXT, ctrl_ext);
	e1e_flush();

	
	rdba = rx_ring->dma;
	ew32(RDBAL, (rdba & DMA_BIT_MASK(32)));
	ew32(RDBAH, (rdba >> 32));
	ew32(RDLEN, rdlen);
	ew32(RDH, 0);
	ew32(RDT, 0);
	rx_ring->head = E1000_RDH;
	rx_ring->tail = E1000_RDT;

	
	rxcsum = er32(RXCSUM);
	if (adapter->flags & FLAG_RX_CSUM_ENABLED) {
		rxcsum |= E1000_RXCSUM_TUOFL;

		
		if (adapter->rx_ps_pages)
			rxcsum |= E1000_RXCSUM_IPPCSE;
	} else {
		rxcsum &= ~E1000_RXCSUM_TUOFL;
		
	}
	ew32(RXCSUM, rxcsum);

	
	if (adapter->flags & FLAG_HAS_ERT) {
		if (adapter->netdev->mtu > ETH_DATA_LEN) {
			u32 rxdctl = er32(RXDCTL(0));
			ew32(RXDCTL(0), rxdctl | 0x3);
			ew32(ERT, E1000_ERT_2048 | (1 << 13));
			
			pm_qos_update_requirement(PM_QOS_CPU_DMA_LATENCY, adapter->netdev->name, 55);
		} else {
			pm_qos_update_requirement(PM_QOS_CPU_DMA_LATENCY, adapter->netdev->name, PM_QOS_DEFAULT_VALUE);

		}
	}

	
	ew32(RCTL, rctl);
}


static void e1000_update_mc_addr_list(struct e1000_hw *hw, u8 *mc_addr_list, u32 mc_addr_count, u32 rar_used_count, u32 rar_count)

{
	hw->mac.ops.update_mc_addr_list(hw, mc_addr_list, mc_addr_count, rar_used_count, rar_count);
}


static void e1000_set_multi(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_mac_info *mac = &hw->mac;
	struct dev_mc_list *mc_ptr;
	u8  *mta_list;
	u32 rctl;
	int i;

	

	rctl = er32(RCTL);

	if (netdev->flags & IFF_PROMISC) {
		rctl |= (E1000_RCTL_UPE | E1000_RCTL_MPE);
		rctl &= ~E1000_RCTL_VFE;
	} else {
		if (netdev->flags & IFF_ALLMULTI) {
			rctl |= E1000_RCTL_MPE;
			rctl &= ~E1000_RCTL_UPE;
		} else {
			rctl &= ~(E1000_RCTL_UPE | E1000_RCTL_MPE);
		}
		if (adapter->flags & FLAG_HAS_HW_VLAN_FILTER)
			rctl |= E1000_RCTL_VFE;
	}

	ew32(RCTL, rctl);

	if (netdev->mc_count) {
		mta_list = kmalloc(netdev->mc_count * 6, GFP_ATOMIC);
		if (!mta_list)
			return;

		
		mc_ptr = netdev->mc_list;

		for (i = 0; i < netdev->mc_count; i++) {
			if (!mc_ptr)
				break;
			memcpy(mta_list + (i*ETH_ALEN), mc_ptr->dmi_addr, ETH_ALEN);
			mc_ptr = mc_ptr->next;
		}

		e1000_update_mc_addr_list(hw, mta_list, i, 1, mac->rar_entry_count);
		kfree(mta_list);
	} else {
		
		e1000_update_mc_addr_list(hw, NULL, 0, 1, mac->rar_entry_count);
	}
}


static void e1000_configure(struct e1000_adapter *adapter)
{
	e1000_set_multi(adapter->netdev);

	e1000_restore_vlan(adapter);
	e1000_init_manageability(adapter);

	e1000_configure_tx(adapter);
	e1000_setup_rctl(adapter);
	e1000_configure_rx(adapter);
	adapter->alloc_rx_buf(adapter, e1000_desc_unused(adapter->rx_ring));
}


void e1000e_power_up_phy(struct e1000_adapter *adapter)
{
	if (adapter->hw.phy.ops.power_up)
		adapter->hw.phy.ops.power_up(&adapter->hw);

	adapter->hw.mac.ops.setup_link(&adapter->hw);
}


static void e1000_power_down_phy(struct e1000_adapter *adapter)
{
	
	if (adapter->wol)
		return;

	if (adapter->hw.phy.ops.power_down)
		adapter->hw.phy.ops.power_down(&adapter->hw);
}


void e1000e_reset(struct e1000_adapter *adapter)
{
	struct e1000_mac_info *mac = &adapter->hw.mac;
	struct e1000_fc_info *fc = &adapter->hw.fc;
	struct e1000_hw *hw = &adapter->hw;
	u32 tx_space, min_tx_space, min_rx_space;
	u32 pba = adapter->pba;
	u16 hwm;

	
	ew32(PBA, pba);

	if (adapter->max_frame_size > ETH_FRAME_LEN + ETH_FCS_LEN) {
		
		pba = er32(PBA);
		
		tx_space = pba >> 16;
		
		pba &= 0xffff;
		
		min_tx_space = (adapter->max_frame_size + sizeof(struct e1000_tx_desc) - ETH_FCS_LEN) * 2;

		min_tx_space = ALIGN(min_tx_space, 1024);
		min_tx_space >>= 10;
		
		min_rx_space = adapter->max_frame_size;
		min_rx_space = ALIGN(min_rx_space, 1024);
		min_rx_space >>= 10;

		
		if ((tx_space < min_tx_space) && ((min_tx_space - tx_space) < pba)) {
			pba -= min_tx_space - tx_space;

			
			if ((pba < min_rx_space) && (!(adapter->flags & FLAG_HAS_ERT)))
				
				pba = min_rx_space;
		}

		ew32(PBA, pba);
	}


	
	if (hw->mac.type == e1000_pchlan) {
		
		if (adapter->netdev->mtu > ETH_DATA_LEN) {
			fc->high_water = 0x3500;
			fc->low_water  = 0x1500;
		} else {
			fc->high_water = 0x5000;
			fc->low_water  = 0x3000;
		}
	} else {
		if ((adapter->flags & FLAG_HAS_ERT) && (adapter->netdev->mtu > ETH_DATA_LEN))
			hwm = min(((pba << 10) * 9 / 10), ((pba << 10) - (E1000_ERT_2048 << 3)));
		else hwm = min(((pba << 10) * 9 / 10), ((pba << 10) - adapter->max_frame_size));


		fc->high_water = hwm & E1000_FCRTH_RTH; 
		fc->low_water = fc->high_water - 8;
	}

	if (adapter->flags & FLAG_DISABLE_FC_PAUSE_TIME)
		fc->pause_time = 0xFFFF;
	else fc->pause_time = E1000_FC_PAUSE_TIME;
	fc->send_xon = 1;
	fc->current_mode = fc->requested_mode;

	
	mac->ops.reset_hw(hw);

	
	if (adapter->flags & FLAG_HAS_AMT)
		e1000_get_hw_control(adapter);

	ew32(WUC, 0);
	if (adapter->flags2 & FLAG2_HAS_PHY_WAKEUP)
		e1e_wphy(&adapter->hw, BM_WUC, 0);

	if (mac->ops.init_hw(hw))
		e_err("Hardware Error\n");

	
	if (hw->mac.type == e1000_pchlan)
		ew32(FCRTV_PCH, 0x1000);

	e1000_update_mng_vlan(adapter);

	
	ew32(VET, ETH_P_8021Q);

	e1000e_reset_adaptive(hw);
	e1000_get_phy_info(hw);

	if ((adapter->flags & FLAG_HAS_SMART_POWER_DOWN) && !(adapter->flags & FLAG_SMART_POWER_DOWN)) {
		u16 phy_data = 0;
		
		e1e_rphy(hw, IGP02E1000_PHY_POWER_MGMT, &phy_data);
		phy_data &= ~IGP02E1000_PM_SPD;
		e1e_wphy(hw, IGP02E1000_PHY_POWER_MGMT, phy_data);
	}
}

int e1000e_up(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;

	
	if (adapter->flags & FLAG_HAS_ERT)
		pm_qos_add_requirement(PM_QOS_CPU_DMA_LATENCY, adapter->netdev->name, PM_QOS_DEFAULT_VALUE);


	
	e1000_configure(adapter);

	clear_bit(__E1000_DOWN, &adapter->state);

	napi_enable(&adapter->napi);
	if (adapter->msix_entries)
		e1000_configure_msix(adapter);
	e1000_irq_enable(adapter);

	netif_wake_queue(adapter->netdev);

	
	ew32(ICS, E1000_ICS_LSC);
	return 0;
}

void e1000e_down(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct e1000_hw *hw = &adapter->hw;
	u32 tctl, rctl;

	
	set_bit(__E1000_DOWN, &adapter->state);

	
	rctl = er32(RCTL);
	ew32(RCTL, rctl & ~E1000_RCTL_EN);
	

	netif_stop_queue(netdev);

	
	tctl = er32(TCTL);
	tctl &= ~E1000_TCTL_EN;
	ew32(TCTL, tctl);
	
	e1e_flush();
	msleep(10);

	napi_disable(&adapter->napi);
	e1000_irq_disable(adapter);

	del_timer_sync(&adapter->watchdog_timer);
	del_timer_sync(&adapter->phy_info_timer);

	netdev->tx_queue_len = adapter->tx_queue_len;
	netif_carrier_off(netdev);
	adapter->link_speed = 0;
	adapter->link_duplex = 0;

	if (!pci_channel_offline(adapter->pdev))
		e1000e_reset(adapter);
	e1000_clean_tx_ring(adapter);
	e1000_clean_rx_ring(adapter);

	if (adapter->flags & FLAG_HAS_ERT)
		pm_qos_remove_requirement(PM_QOS_CPU_DMA_LATENCY, adapter->netdev->name);

	
}

void e1000e_reinit_locked(struct e1000_adapter *adapter)
{
	might_sleep();
	while (test_and_set_bit(__E1000_RESETTING, &adapter->state))
		msleep(1);
	e1000e_down(adapter);
	e1000e_up(adapter);
	clear_bit(__E1000_RESETTING, &adapter->state);
}


static int __devinit e1000_sw_init(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;

	adapter->rx_buffer_len = ETH_FRAME_LEN + VLAN_HLEN + ETH_FCS_LEN;
	adapter->rx_ps_bsize0 = 128;
	adapter->max_frame_size = netdev->mtu + ETH_HLEN + ETH_FCS_LEN;
	adapter->min_frame_size = ETH_ZLEN + ETH_FCS_LEN;

	e1000e_set_interrupt_capability(adapter);

	if (e1000_alloc_queues(adapter))
		return -ENOMEM;

	
	e1000_irq_disable(adapter);

	set_bit(__E1000_DOWN, &adapter->state);
	return 0;
}


static irqreturn_t e1000_intr_msi_test(int irq, void *data)
{
	struct net_device *netdev = data;
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 icr = er32(ICR);

	e_dbg("icr is %08X\n", icr);
	if (icr & E1000_ICR_RXSEQ) {
		adapter->flags &= ~FLAG_MSI_TEST_FAILED;
		wmb();
	}

	return IRQ_HANDLED;
}


static int e1000_test_msi_interrupt(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct e1000_hw *hw = &adapter->hw;
	int err;

	
	
	er32(ICR);

	
	e1000_free_irq(adapter);
	e1000e_reset_interrupt_capability(adapter);

	
	adapter->flags |= FLAG_MSI_TEST_FAILED;

	err = pci_enable_msi(adapter->pdev);
	if (err)
		goto msi_test_failed;

	err = request_irq(adapter->pdev->irq, e1000_intr_msi_test, 0, netdev->name, netdev);
	if (err) {
		pci_disable_msi(adapter->pdev);
		goto msi_test_failed;
	}

	wmb();

	e1000_irq_enable(adapter);

	
	ew32(ICS, E1000_ICS_RXSEQ);
	e1e_flush();
	msleep(50);

	e1000_irq_disable(adapter);

	rmb();

	if (adapter->flags & FLAG_MSI_TEST_FAILED) {
		adapter->int_mode = E1000E_INT_MODE_LEGACY;
		err = -EIO;
		e_info("MSI interrupt test failed!\n");
	}

	free_irq(adapter->pdev->irq, netdev);
	pci_disable_msi(adapter->pdev);

	if (err == -EIO)
		goto msi_test_failed;

	
	e_dbg("MSI interrupt test succeeded!\n");
msi_test_failed:
	e1000e_set_interrupt_capability(adapter);
	e1000_request_irq(adapter);
	return err;
}


static int e1000_test_msi(struct e1000_adapter *adapter)
{
	int err;
	u16 pci_cmd;

	if (!(adapter->flags & FLAG_MSI_ENABLED))
		return 0;

	
	pci_read_config_word(adapter->pdev, PCI_COMMAND, &pci_cmd);
	pci_write_config_word(adapter->pdev, PCI_COMMAND, pci_cmd & ~PCI_COMMAND_SERR);

	err = e1000_test_msi_interrupt(adapter);

	
	pci_write_config_word(adapter->pdev, PCI_COMMAND, pci_cmd);

	
	if (!err)
		return 0;

	
	if (err != -EIO)
		return err;

	
	e_warn("MSI interrupt test failed, using legacy interrupt.\n");

	e1000_free_irq(adapter);

	err = e1000_request_irq(adapter);

	return err;
}


static int e1000_open(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	int err;

	
	if (test_bit(__E1000_TESTING, &adapter->state))
		return -EBUSY;

	netif_carrier_off(netdev);

	
	err = e1000e_setup_tx_resources(adapter);
	if (err)
		goto err_setup_tx;

	
	err = e1000e_setup_rx_resources(adapter);
	if (err)
		goto err_setup_rx;

	e1000e_power_up_phy(adapter);

	adapter->mng_vlan_id = E1000_MNG_VLAN_NONE;
	if ((adapter->hw.mng_cookie.status & E1000_MNG_DHCP_COOKIE_STATUS_VLAN))
		e1000_update_mng_vlan(adapter);

	
	if (adapter->flags & FLAG_HAS_AMT)
		e1000_get_hw_control(adapter);

	
	e1000_configure(adapter);

	err = e1000_request_irq(adapter);
	if (err)
		goto err_req_irq;

	
	if (adapter->int_mode != E1000E_INT_MODE_LEGACY) {
		err = e1000_test_msi(adapter);
		if (err) {
			e_err("Interrupt allocation failed\n");
			goto err_req_irq;
		}
	}

	
	clear_bit(__E1000_DOWN, &adapter->state);

	napi_enable(&adapter->napi);

	e1000_irq_enable(adapter);

	netif_start_queue(netdev);

	
	ew32(ICS, E1000_ICS_LSC);

	return 0;

err_req_irq:
	e1000_release_hw_control(adapter);
	e1000_power_down_phy(adapter);
	e1000e_free_rx_resources(adapter);
err_setup_rx:
	e1000e_free_tx_resources(adapter);
err_setup_tx:
	e1000e_reset(adapter);

	return err;
}


static int e1000_close(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	WARN_ON(test_bit(__E1000_RESETTING, &adapter->state));
	e1000e_down(adapter);
	e1000_power_down_phy(adapter);
	e1000_free_irq(adapter);

	e1000e_free_tx_resources(adapter);
	e1000e_free_rx_resources(adapter);

	
	if ((adapter->hw.mng_cookie.status & E1000_MNG_DHCP_COOKIE_STATUS_VLAN) && !(adapter->vlgrp && vlan_group_get_device(adapter->vlgrp, adapter->mng_vlan_id)))


		e1000_vlan_rx_kill_vid(netdev, adapter->mng_vlan_id);

	
	if (adapter->flags & FLAG_HAS_AMT)
		e1000_release_hw_control(adapter);

	return 0;
}

static int e1000_set_mac(struct net_device *netdev, void *p)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);
	memcpy(adapter->hw.mac.addr, addr->sa_data, netdev->addr_len);

	e1000e_rar_set(&adapter->hw, adapter->hw.mac.addr, 0);

	if (adapter->flags & FLAG_RESET_OVERWRITES_LAA) {
		
		e1000e_set_laa_state_82571(&adapter->hw, 1);

		
		e1000e_rar_set(&adapter->hw, adapter->hw.mac.addr, adapter->hw.mac.rar_entry_count - 1);

	}

	return 0;
}


static void e1000e_update_phy_task(struct work_struct *work)
{
	struct e1000_adapter *adapter = container_of(work, struct e1000_adapter, update_phy_task);
	e1000_get_phy_info(&adapter->hw);
}


static void e1000_update_phy_info(unsigned long data)
{
	struct e1000_adapter *adapter = (struct e1000_adapter *) data;
	schedule_work(&adapter->update_phy_task);
}


void e1000e_update_stats(struct e1000_adapter *adapter)
{
	struct net_device *netdev = adapter->netdev;
	struct e1000_hw *hw = &adapter->hw;
	struct pci_dev *pdev = adapter->pdev;
	u16 phy_data;

	
	if (adapter->link_speed == 0)
		return;
	if (pci_channel_offline(pdev))
		return;

	adapter->stats.crcerrs += er32(CRCERRS);
	adapter->stats.gprc += er32(GPRC);
	adapter->stats.gorc += er32(GORCL);
	er32(GORCH); 
	adapter->stats.bprc += er32(BPRC);
	adapter->stats.mprc += er32(MPRC);
	adapter->stats.roc += er32(ROC);

	adapter->stats.mpc += er32(MPC);
	if ((hw->phy.type == e1000_phy_82578) || (hw->phy.type == e1000_phy_82577)) {
		e1e_rphy(hw, HV_SCC_UPPER, &phy_data);
		if (!e1e_rphy(hw, HV_SCC_LOWER, &phy_data))
			adapter->stats.scc += phy_data;

		e1e_rphy(hw, HV_ECOL_UPPER, &phy_data);
		if (!e1e_rphy(hw, HV_ECOL_LOWER, &phy_data))
			adapter->stats.ecol += phy_data;

		e1e_rphy(hw, HV_MCC_UPPER, &phy_data);
		if (!e1e_rphy(hw, HV_MCC_LOWER, &phy_data))
			adapter->stats.mcc += phy_data;

		e1e_rphy(hw, HV_LATECOL_UPPER, &phy_data);
		if (!e1e_rphy(hw, HV_LATECOL_LOWER, &phy_data))
			adapter->stats.latecol += phy_data;

		e1e_rphy(hw, HV_DC_UPPER, &phy_data);
		if (!e1e_rphy(hw, HV_DC_LOWER, &phy_data))
			adapter->stats.dc += phy_data;
	} else {
		adapter->stats.scc += er32(SCC);
		adapter->stats.ecol += er32(ECOL);
		adapter->stats.mcc += er32(MCC);
		adapter->stats.latecol += er32(LATECOL);
		adapter->stats.dc += er32(DC);
	}
	adapter->stats.xonrxc += er32(XONRXC);
	adapter->stats.xontxc += er32(XONTXC);
	adapter->stats.xoffrxc += er32(XOFFRXC);
	adapter->stats.xofftxc += er32(XOFFTXC);
	adapter->stats.gptc += er32(GPTC);
	adapter->stats.gotc += er32(GOTCL);
	er32(GOTCH); 
	adapter->stats.rnbc += er32(RNBC);
	adapter->stats.ruc += er32(RUC);

	adapter->stats.mptc += er32(MPTC);
	adapter->stats.bptc += er32(BPTC);

	

	hw->mac.tx_packet_delta = er32(TPT);
	adapter->stats.tpt += hw->mac.tx_packet_delta;
	if ((hw->phy.type == e1000_phy_82578) || (hw->phy.type == e1000_phy_82577)) {
		e1e_rphy(hw, HV_COLC_UPPER, &phy_data);
		if (!e1e_rphy(hw, HV_COLC_LOWER, &phy_data))
			hw->mac.collision_delta = phy_data;
	} else {
		hw->mac.collision_delta = er32(COLC);
	}
	adapter->stats.colc += hw->mac.collision_delta;

	adapter->stats.algnerrc += er32(ALGNERRC);
	adapter->stats.rxerrc += er32(RXERRC);
	if ((hw->phy.type == e1000_phy_82578) || (hw->phy.type == e1000_phy_82577)) {
		e1e_rphy(hw, HV_TNCRS_UPPER, &phy_data);
		if (!e1e_rphy(hw, HV_TNCRS_LOWER, &phy_data))
			adapter->stats.tncrs += phy_data;
	} else {
		if ((hw->mac.type != e1000_82574) && (hw->mac.type != e1000_82583))
			adapter->stats.tncrs += er32(TNCRS);
	}
	adapter->stats.cexterr += er32(CEXTERR);
	adapter->stats.tsctc += er32(TSCTC);
	adapter->stats.tsctfc += er32(TSCTFC);

	
	netdev->stats.multicast = adapter->stats.mprc;
	netdev->stats.collisions = adapter->stats.colc;

	

	
	netdev->stats.rx_errors = adapter->stats.rxerrc + adapter->stats.crcerrs + adapter->stats.algnerrc + adapter->stats.ruc + adapter->stats.roc + adapter->stats.cexterr;


	netdev->stats.rx_length_errors = adapter->stats.ruc + adapter->stats.roc;
	netdev->stats.rx_crc_errors = adapter->stats.crcerrs;
	netdev->stats.rx_frame_errors = adapter->stats.algnerrc;
	netdev->stats.rx_missed_errors = adapter->stats.mpc;

	
	netdev->stats.tx_errors = adapter->stats.ecol + adapter->stats.latecol;
	netdev->stats.tx_aborted_errors = adapter->stats.ecol;
	netdev->stats.tx_window_errors = adapter->stats.latecol;
	netdev->stats.tx_carrier_errors = adapter->stats.tncrs;

	

	
	adapter->stats.mgptc += er32(MGTPTC);
	adapter->stats.mgprc += er32(MGTPRC);
	adapter->stats.mgpdc += er32(MGTPDC);
}


static void e1000_phy_read_status(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct e1000_phy_regs *phy = &adapter->phy_regs;
	int ret_val;

	if ((er32(STATUS) & E1000_STATUS_LU) && (adapter->hw.phy.media_type == e1000_media_type_copper)) {
		ret_val  = e1e_rphy(hw, PHY_CONTROL, &phy->bmcr);
		ret_val |= e1e_rphy(hw, PHY_STATUS, &phy->bmsr);
		ret_val |= e1e_rphy(hw, PHY_AUTONEG_ADV, &phy->advertise);
		ret_val |= e1e_rphy(hw, PHY_LP_ABILITY, &phy->lpa);
		ret_val |= e1e_rphy(hw, PHY_AUTONEG_EXP, &phy->expansion);
		ret_val |= e1e_rphy(hw, PHY_1000T_CTRL, &phy->ctrl1000);
		ret_val |= e1e_rphy(hw, PHY_1000T_STATUS, &phy->stat1000);
		ret_val |= e1e_rphy(hw, PHY_EXT_STATUS, &phy->estatus);
		if (ret_val)
			e_warn("Error reading PHY register\n");
	} else {
		
		phy->bmcr = (BMCR_SPEED1000 | BMCR_ANENABLE | BMCR_FULLDPLX);
		phy->bmsr = (BMSR_100FULL | BMSR_100HALF | BMSR_10FULL | BMSR_10HALF | BMSR_ESTATEN | BMSR_ANEGCAPABLE | BMSR_ERCAP);

		phy->advertise = (ADVERTISE_PAUSE_ASYM | ADVERTISE_PAUSE_CAP | ADVERTISE_ALL | ADVERTISE_CSMA);
		phy->lpa = 0;
		phy->expansion = EXPANSION_ENABLENPAGE;
		phy->ctrl1000 = ADVERTISE_1000FULL;
		phy->stat1000 = 0;
		phy->estatus = (ESTATUS_1000_TFULL | ESTATUS_1000_THALF);
	}
}

static void e1000_print_link_info(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 ctrl = er32(CTRL);

	
	printk(KERN_INFO "e1000e: %s NIC Link is Up %d Mbps %s, " "Flow Control: %s\n", adapter->netdev->name, adapter->link_speed, (adapter->link_duplex == FULL_DUPLEX) ? "Full Duplex" : "Half Duplex", ((ctrl & E1000_CTRL_TFCE) && (ctrl & E1000_CTRL_RFCE)) ? "RX/TX" :






	       ((ctrl & E1000_CTRL_RFCE) ? "RX" :
	       ((ctrl & E1000_CTRL_TFCE) ? "TX" : "None" )));
}

bool e1000_has_link(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	bool link_active = 0;
	s32 ret_val = 0;

	
	switch (hw->phy.media_type) {
	case e1000_media_type_copper:
		if (hw->mac.get_link_status) {
			ret_val = hw->mac.ops.check_for_link(hw);
			link_active = !hw->mac.get_link_status;
		} else {
			link_active = 1;
		}
		break;
	case e1000_media_type_fiber:
		ret_val = hw->mac.ops.check_for_link(hw);
		link_active = !!(er32(STATUS) & E1000_STATUS_LU);
		break;
	case e1000_media_type_internal_serdes:
		ret_val = hw->mac.ops.check_for_link(hw);
		link_active = adapter->hw.mac.serdes_has_link;
		break;
	default:
	case e1000_media_type_unknown:
		break;
	}

	if ((ret_val == E1000_ERR_PHY) && (hw->phy.type == e1000_phy_igp_3) && (er32(CTRL) & E1000_PHY_CTRL_GBE_DISABLE)) {
		
		e_info("Gigabit has been disabled, downgrading speed\n");
	}

	return link_active;
}

static void e1000e_enable_receives(struct e1000_adapter *adapter)
{
	
	if ((adapter->flags & FLAG_RX_NEEDS_RESTART) && (adapter->flags & FLAG_RX_RESTART_NOW)) {
		struct e1000_hw *hw = &adapter->hw;
		u32 rctl = er32(RCTL);
		ew32(RCTL, rctl | E1000_RCTL_EN);
		adapter->flags &= ~FLAG_RX_RESTART_NOW;
	}
}


static void e1000_watchdog(unsigned long data)
{
	struct e1000_adapter *adapter = (struct e1000_adapter *) data;

	
	schedule_work(&adapter->watchdog_task);

	
}

static void e1000_watchdog_task(struct work_struct *work)
{
	struct e1000_adapter *adapter = container_of(work, struct e1000_adapter, watchdog_task);
	struct net_device *netdev = adapter->netdev;
	struct e1000_mac_info *mac = &adapter->hw.mac;
	struct e1000_phy_info *phy = &adapter->hw.phy;
	struct e1000_ring *tx_ring = adapter->tx_ring;
	struct e1000_hw *hw = &adapter->hw;
	u32 link, tctl;
	int tx_pending = 0;

	link = e1000_has_link(adapter);
	if ((netif_carrier_ok(netdev)) && link) {
		e1000e_enable_receives(adapter);
		goto link_up;
	}

	if ((e1000e_enable_tx_pkt_filtering(hw)) && (adapter->mng_vlan_id != adapter->hw.mng_cookie.vlan_id))
		e1000_update_mng_vlan(adapter);

	if (link) {
		if (!netif_carrier_ok(netdev)) {
			bool txb2b = 1;
			
			e1000_phy_read_status(adapter);
			mac->ops.get_link_up_info(&adapter->hw, &adapter->link_speed, &adapter->link_duplex);

			e1000_print_link_info(adapter);
			
			if ((hw->phy.type == e1000_phy_igp_3 || hw->phy.type == e1000_phy_bm) && (hw->mac.autoneg == true) && (adapter->link_speed == SPEED_10 || adapter->link_speed == SPEED_100) && (adapter->link_duplex == HALF_DUPLEX)) {




				u16 autoneg_exp;

				e1e_rphy(hw, PHY_AUTONEG_EXP, &autoneg_exp);

				if (!(autoneg_exp & NWAY_ER_LP_NWAY_CAPS))
					e_info("Autonegotiated half duplex but" " link partner cannot autoneg. " " Try forcing full duplex if " "link gets many collisions.\n");


			}

			
			netdev->tx_queue_len = adapter->tx_queue_len;
			adapter->tx_timeout_factor = 1;
			switch (adapter->link_speed) {
			case SPEED_10:
				txb2b = 0;
				netdev->tx_queue_len = 10;
				adapter->tx_timeout_factor = 16;
				break;
			case SPEED_100:
				txb2b = 0;
				netdev->tx_queue_len = 100;
				adapter->tx_timeout_factor = 10;
				break;
			}

			
			if ((adapter->flags & FLAG_TARC_SPEED_MODE_BIT) && !txb2b) {
				u32 tarc0;
				tarc0 = er32(TARC(0));
				tarc0 &= ~SPEED_MODE_BIT;
				ew32(TARC(0), tarc0);
			}

			
			if (!(adapter->flags & FLAG_TSO_FORCE)) {
				switch (adapter->link_speed) {
				case SPEED_10:
				case SPEED_100:
					e_info("10/100 speed: disabling TSO\n");
					netdev->features &= ~NETIF_F_TSO;
					netdev->features &= ~NETIF_F_TSO6;
					break;
				case SPEED_1000:
					netdev->features |= NETIF_F_TSO;
					netdev->features |= NETIF_F_TSO6;
					break;
				default:
					
					break;
				}
			}

			
			tctl = er32(TCTL);
			tctl |= E1000_TCTL_EN;
			ew32(TCTL, tctl);

                        
			if (phy->ops.cfg_on_link_up)
				phy->ops.cfg_on_link_up(hw);

			netif_carrier_on(netdev);

			if (!test_bit(__E1000_DOWN, &adapter->state))
				mod_timer(&adapter->phy_info_timer, round_jiffies(jiffies + 2 * HZ));
		}
	} else {
		if (netif_carrier_ok(netdev)) {
			adapter->link_speed = 0;
			adapter->link_duplex = 0;
			
			printk(KERN_INFO "e1000e: %s NIC Link is Down\n", adapter->netdev->name);
			netif_carrier_off(netdev);
			if (!test_bit(__E1000_DOWN, &adapter->state))
				mod_timer(&adapter->phy_info_timer, round_jiffies(jiffies + 2 * HZ));

			if (adapter->flags & FLAG_RX_NEEDS_RESTART)
				schedule_work(&adapter->reset_task);
		}
	}

link_up:
	e1000e_update_stats(adapter);

	mac->tx_packet_delta = adapter->stats.tpt - adapter->tpt_old;
	adapter->tpt_old = adapter->stats.tpt;
	mac->collision_delta = adapter->stats.colc - adapter->colc_old;
	adapter->colc_old = adapter->stats.colc;

	adapter->gorc = adapter->stats.gorc - adapter->gorc_old;
	adapter->gorc_old = adapter->stats.gorc;
	adapter->gotc = adapter->stats.gotc - adapter->gotc_old;
	adapter->gotc_old = adapter->stats.gotc;

	e1000e_update_adaptive(&adapter->hw);

	if (!netif_carrier_ok(netdev)) {
		tx_pending = (e1000_desc_unused(tx_ring) + 1 < tx_ring->count);
		if (tx_pending) {
			
			adapter->tx_timeout_count++;
			schedule_work(&adapter->reset_task);
			
			return;
		}
	}

	
	if (adapter->msix_entries)
		ew32(ICS, adapter->rx_ring->ims_val);
	else ew32(ICS, E1000_ICS_RXDMT0);

	
	adapter->detect_tx_hung = 1;

	
	if (e1000e_get_laa_state_82571(hw))
		e1000e_rar_set(hw, adapter->hw.mac.addr, 0);

	
	if (!test_bit(__E1000_DOWN, &adapter->state))
		mod_timer(&adapter->watchdog_timer, round_jiffies(jiffies + 2 * HZ));
}








static int e1000_tso(struct e1000_adapter *adapter, struct sk_buff *skb)
{
	struct e1000_ring *tx_ring = adapter->tx_ring;
	struct e1000_context_desc *context_desc;
	struct e1000_buffer *buffer_info;
	unsigned int i;
	u32 cmd_length = 0;
	u16 ipcse = 0, tucse, mss;
	u8 ipcss, ipcso, tucss, tucso, hdr_len;
	int err;

	if (!skb_is_gso(skb))
		return 0;

	if (skb_header_cloned(skb)) {
		err = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
		if (err)
			return err;
	}

	hdr_len = skb_transport_offset(skb) + tcp_hdrlen(skb);
	mss = skb_shinfo(skb)->gso_size;
	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = ip_hdr(skb);
		iph->tot_len = 0;
		iph->check = 0;
		tcp_hdr(skb)->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, 0, IPPROTO_TCP, 0);
		cmd_length = E1000_TXD_CMD_IP;
		ipcse = skb_transport_offset(skb) - 1;
	} else if (skb_shinfo(skb)->gso_type == SKB_GSO_TCPV6) {
		ipv6_hdr(skb)->payload_len = 0;
		tcp_hdr(skb)->check = ~csum_ipv6_magic(&ipv6_hdr(skb)->saddr, &ipv6_hdr(skb)->daddr, 0, IPPROTO_TCP, 0);

		ipcse = 0;
	}
	ipcss = skb_network_offset(skb);
	ipcso = (void *)&(ip_hdr(skb)->check) - (void *)skb->data;
	tucss = skb_transport_offset(skb);
	tucso = (void *)&(tcp_hdr(skb)->check) - (void *)skb->data;
	tucse = 0;

	cmd_length |= (E1000_TXD_CMD_DEXT | E1000_TXD_CMD_TSE | E1000_TXD_CMD_TCP | (skb->len - (hdr_len)));

	i = tx_ring->next_to_use;
	context_desc = E1000_CONTEXT_DESC(*tx_ring, i);
	buffer_info = &tx_ring->buffer_info[i];

	context_desc->lower_setup.ip_fields.ipcss  = ipcss;
	context_desc->lower_setup.ip_fields.ipcso  = ipcso;
	context_desc->lower_setup.ip_fields.ipcse  = cpu_to_le16(ipcse);
	context_desc->upper_setup.tcp_fields.tucss = tucss;
	context_desc->upper_setup.tcp_fields.tucso = tucso;
	context_desc->upper_setup.tcp_fields.tucse = cpu_to_le16(tucse);
	context_desc->tcp_seg_setup.fields.mss     = cpu_to_le16(mss);
	context_desc->tcp_seg_setup.fields.hdr_len = hdr_len;
	context_desc->cmd_and_length = cpu_to_le32(cmd_length);

	buffer_info->time_stamp = jiffies;
	buffer_info->next_to_watch = i;

	i++;
	if (i == tx_ring->count)
		i = 0;
	tx_ring->next_to_use = i;

	return 1;
}

static bool e1000_tx_csum(struct e1000_adapter *adapter, struct sk_buff *skb)
{
	struct e1000_ring *tx_ring = adapter->tx_ring;
	struct e1000_context_desc *context_desc;
	struct e1000_buffer *buffer_info;
	unsigned int i;
	u8 css;
	u32 cmd_len = E1000_TXD_CMD_DEXT;
	__be16 protocol;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;

	if (skb->protocol == cpu_to_be16(ETH_P_8021Q))
		protocol = vlan_eth_hdr(skb)->h_vlan_encapsulated_proto;
	else protocol = skb->protocol;

	switch (protocol) {
	case cpu_to_be16(ETH_P_IP):
		if (ip_hdr(skb)->protocol == IPPROTO_TCP)
			cmd_len |= E1000_TXD_CMD_TCP;
		break;
	case cpu_to_be16(ETH_P_IPV6):
		
		if (ipv6_hdr(skb)->nexthdr == IPPROTO_TCP)
			cmd_len |= E1000_TXD_CMD_TCP;
		break;
	default:
		if (unlikely(net_ratelimit()))
			e_warn("checksum_partial proto=%x!\n", be16_to_cpu(protocol));
		break;
	}

	css = skb_transport_offset(skb);

	i = tx_ring->next_to_use;
	buffer_info = &tx_ring->buffer_info[i];
	context_desc = E1000_CONTEXT_DESC(*tx_ring, i);

	context_desc->lower_setup.ip_config = 0;
	context_desc->upper_setup.tcp_fields.tucss = css;
	context_desc->upper_setup.tcp_fields.tucso = css + skb->csum_offset;
	context_desc->upper_setup.tcp_fields.tucse = 0;
	context_desc->tcp_seg_setup.data = 0;
	context_desc->cmd_and_length = cpu_to_le32(cmd_len);

	buffer_info->time_stamp = jiffies;
	buffer_info->next_to_watch = i;

	i++;
	if (i == tx_ring->count)
		i = 0;
	tx_ring->next_to_use = i;

	return 1;
}




static int e1000_tx_map(struct e1000_adapter *adapter, struct sk_buff *skb, unsigned int first, unsigned int max_per_txd, unsigned int nr_frags, unsigned int mss)


{
	struct e1000_ring *tx_ring = adapter->tx_ring;
	struct pci_dev *pdev = adapter->pdev;
	struct e1000_buffer *buffer_info;
	unsigned int len = skb_headlen(skb);
	unsigned int offset = 0, size, count = 0, i;
	unsigned int f;

	i = tx_ring->next_to_use;

	while (len) {
		buffer_info = &tx_ring->buffer_info[i];
		size = min(len, max_per_txd);

		buffer_info->length = size;
		buffer_info->time_stamp = jiffies;
		buffer_info->next_to_watch = i;
		buffer_info->dma = pci_map_single(pdev,	skb->data + offset, size,	PCI_DMA_TODEVICE);
		buffer_info->mapped_as_page = false;
		if (pci_dma_mapping_error(pdev, buffer_info->dma))
			goto dma_error;

		len -= size;
		offset += size;
		count++;

		if (len) {
			i++;
			if (i == tx_ring->count)
				i = 0;
		}
	}

	for (f = 0; f < nr_frags; f++) {
		struct skb_frag_struct *frag;

		frag = &skb_shinfo(skb)->frags[f];
		len = frag->size;
		offset = frag->page_offset;

		while (len) {
			i++;
			if (i == tx_ring->count)
				i = 0;

			buffer_info = &tx_ring->buffer_info[i];
			size = min(len, max_per_txd);

			buffer_info->length = size;
			buffer_info->time_stamp = jiffies;
			buffer_info->next_to_watch = i;
			buffer_info->dma = pci_map_page(pdev, frag->page, offset, size, PCI_DMA_TODEVICE);

			buffer_info->mapped_as_page = true;
			if (pci_dma_mapping_error(pdev, buffer_info->dma))
				goto dma_error;

			len -= size;
			offset += size;
			count++;
		}
	}

	tx_ring->buffer_info[i].skb = skb;
	tx_ring->buffer_info[first].next_to_watch = i;

	return count;

dma_error:
	dev_err(&pdev->dev, "TX DMA map failed\n");
	buffer_info->dma = 0;
	if (count)
		count--;

	while (count--) {
		if (i==0)
			i += tx_ring->count;
		i--;
		buffer_info = &tx_ring->buffer_info[i];
		e1000_put_txbuf(adapter, buffer_info);;
	}

	return 0;
}

static void e1000_tx_queue(struct e1000_adapter *adapter, int tx_flags, int count)
{
	struct e1000_ring *tx_ring = adapter->tx_ring;
	struct e1000_tx_desc *tx_desc = NULL;
	struct e1000_buffer *buffer_info;
	u32 txd_upper = 0, txd_lower = E1000_TXD_CMD_IFCS;
	unsigned int i;

	if (tx_flags & E1000_TX_FLAGS_TSO) {
		txd_lower |= E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D | E1000_TXD_CMD_TSE;
		txd_upper |= E1000_TXD_POPTS_TXSM << 8;

		if (tx_flags & E1000_TX_FLAGS_IPV4)
			txd_upper |= E1000_TXD_POPTS_IXSM << 8;
	}

	if (tx_flags & E1000_TX_FLAGS_CSUM) {
		txd_lower |= E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D;
		txd_upper |= E1000_TXD_POPTS_TXSM << 8;
	}

	if (tx_flags & E1000_TX_FLAGS_VLAN) {
		txd_lower |= E1000_TXD_CMD_VLE;
		txd_upper |= (tx_flags & E1000_TX_FLAGS_VLAN_MASK);
	}

	i = tx_ring->next_to_use;

	while (count--) {
		buffer_info = &tx_ring->buffer_info[i];
		tx_desc = E1000_TX_DESC(*tx_ring, i);
		tx_desc->buffer_addr = cpu_to_le64(buffer_info->dma);
		tx_desc->lower.data = cpu_to_le32(txd_lower | buffer_info->length);
		tx_desc->upper.data = cpu_to_le32(txd_upper);

		i++;
		if (i == tx_ring->count)
			i = 0;
	}

	tx_desc->lower.data |= cpu_to_le32(adapter->txd_cmd);

	
	wmb();

	tx_ring->next_to_use = i;
	writel(i, adapter->hw.hw_addr + tx_ring->tail);
	
	mmiowb();
}


static int e1000_transfer_dhcp_info(struct e1000_adapter *adapter, struct sk_buff *skb)
{
	struct e1000_hw *hw =  &adapter->hw;
	u16 length, offset;

	if (vlan_tx_tag_present(skb)) {
		if (!((vlan_tx_tag_get(skb) == adapter->hw.mng_cookie.vlan_id) && (adapter->hw.mng_cookie.status & E1000_MNG_DHCP_COOKIE_STATUS_VLAN)))

			return 0;
	}

	if (skb->len <= MINIMUM_DHCP_PACKET_SIZE)
		return 0;

	if (((struct ethhdr *) skb->data)->h_proto != htons(ETH_P_IP))
		return 0;

	{
		const struct iphdr *ip = (struct iphdr *)((u8 *)skb->data+14);
		struct udphdr *udp;

		if (ip->protocol != IPPROTO_UDP)
			return 0;

		udp = (struct udphdr *)((u8 *)ip + (ip->ihl << 2));
		if (ntohs(udp->dest) != 67)
			return 0;

		offset = (u8 *)udp + 8 - skb->data;
		length = skb->len - offset;
		return e1000e_mng_write_dhcp_info(hw, (u8 *)udp + 8, length);
	}

	return 0;
}

static int __e1000_maybe_stop_tx(struct net_device *netdev, int size)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	netif_stop_queue(netdev);
	
	smp_mb();

	
	if (e1000_desc_unused(adapter->tx_ring) < size)
		return -EBUSY;

	
	netif_start_queue(netdev);
	++adapter->restart_queue;
	return 0;
}

static int e1000_maybe_stop_tx(struct net_device *netdev, int size)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	if (e1000_desc_unused(adapter->tx_ring) >= size)
		return 0;
	return __e1000_maybe_stop_tx(netdev, size);
}


static netdev_tx_t e1000_xmit_frame(struct sk_buff *skb, struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_ring *tx_ring = adapter->tx_ring;
	unsigned int first;
	unsigned int max_per_txd = E1000_MAX_PER_TXD;
	unsigned int max_txd_pwr = E1000_MAX_TXD_PWR;
	unsigned int tx_flags = 0;
	unsigned int len = skb->len - skb->data_len;
	unsigned int nr_frags;
	unsigned int mss;
	int count = 0;
	int tso;
	unsigned int f;

	if (test_bit(__E1000_DOWN, &adapter->state)) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (skb->len <= 0) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	mss = skb_shinfo(skb)->gso_size;
	
	if (mss) {
		u8 hdr_len;
		max_per_txd = min(mss << 2, max_per_txd);
		max_txd_pwr = fls(max_per_txd) - 1;

		
		hdr_len = skb_transport_offset(skb) + tcp_hdrlen(skb);
		
		if (skb->data_len && (hdr_len == len)) {
			unsigned int pull_size;

			pull_size = min((unsigned int)4, skb->data_len);
			if (!__pskb_pull_tail(skb, pull_size)) {
				e_err("__pskb_pull_tail failed.\n");
				dev_kfree_skb_any(skb);
				return NETDEV_TX_OK;
			}
			len = skb->len - skb->data_len;
		}
	}

	
	if ((mss) || (skb->ip_summed == CHECKSUM_PARTIAL))
		count++;
	count++;

	count += TXD_USE_COUNT(len, max_txd_pwr);

	nr_frags = skb_shinfo(skb)->nr_frags;
	for (f = 0; f < nr_frags; f++)
		count += TXD_USE_COUNT(skb_shinfo(skb)->frags[f].size, max_txd_pwr);

	if (adapter->hw.mac.tx_pkt_filtering)
		e1000_transfer_dhcp_info(adapter, skb);

	
	if (e1000_maybe_stop_tx(netdev, count + 2))
		return NETDEV_TX_BUSY;

	if (adapter->vlgrp && vlan_tx_tag_present(skb)) {
		tx_flags |= E1000_TX_FLAGS_VLAN;
		tx_flags |= (vlan_tx_tag_get(skb) << E1000_TX_FLAGS_VLAN_SHIFT);
	}

	first = tx_ring->next_to_use;

	tso = e1000_tso(adapter, skb);
	if (tso < 0) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_OK;
	}

	if (tso)
		tx_flags |= E1000_TX_FLAGS_TSO;
	else if (e1000_tx_csum(adapter, skb))
		tx_flags |= E1000_TX_FLAGS_CSUM;

	
	if (skb->protocol == htons(ETH_P_IP))
		tx_flags |= E1000_TX_FLAGS_IPV4;

	
	count = e1000_tx_map(adapter, skb, first, max_per_txd, nr_frags, mss);
	if (count) {
		e1000_tx_queue(adapter, tx_flags, count);
		
		e1000_maybe_stop_tx(netdev, MAX_SKB_FRAGS + 2);

	} else {
		dev_kfree_skb_any(skb);
		tx_ring->buffer_info[first].time_stamp = 0;
		tx_ring->next_to_use = first;
	}

	return NETDEV_TX_OK;
}


static void e1000_tx_timeout(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	
	adapter->tx_timeout_count++;
	schedule_work(&adapter->reset_task);
}

static void e1000_reset_task(struct work_struct *work)
{
	struct e1000_adapter *adapter;
	adapter = container_of(work, struct e1000_adapter, reset_task);

	e1000e_reinit_locked(adapter);
}


static struct net_device_stats *e1000_get_stats(struct net_device *netdev)
{
	
	return &netdev->stats;
}


static int e1000_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN;

	
	if ((max_frame > ETH_FRAME_LEN + ETH_FCS_LEN) && !(adapter->flags & FLAG_HAS_JUMBO_FRAMES)) {
		e_err("Jumbo Frames not supported.\n");
		return -EINVAL;
	}

	
	if ((new_mtu < ETH_ZLEN + ETH_FCS_LEN + VLAN_HLEN) || (max_frame > adapter->max_hw_frame_size)) {
		e_err("Unsupported MTU setting\n");
		return -EINVAL;
	}

	while (test_and_set_bit(__E1000_RESETTING, &adapter->state))
		msleep(1);
	
	adapter->max_frame_size = max_frame;
	e_info("changing MTU from %d to %d\n", netdev->mtu, new_mtu);
	netdev->mtu = new_mtu;
	if (netif_running(netdev))
		e1000e_down(adapter);

	

	if (max_frame <= 256)
		adapter->rx_buffer_len = 256;
	else if (max_frame <= 512)
		adapter->rx_buffer_len = 512;
	else if (max_frame <= 1024)
		adapter->rx_buffer_len = 1024;
	else if (max_frame <= 2048)
		adapter->rx_buffer_len = 2048;
	else adapter->rx_buffer_len = 4096;

	
	if ((max_frame == ETH_FRAME_LEN + ETH_FCS_LEN) || (max_frame == ETH_FRAME_LEN + VLAN_HLEN + ETH_FCS_LEN))
		adapter->rx_buffer_len = ETH_FRAME_LEN + VLAN_HLEN + ETH_FCS_LEN;

	if (netif_running(netdev))
		e1000e_up(adapter);
	else e1000e_reset(adapter);

	clear_bit(__E1000_RESETTING, &adapter->state);

	return 0;
}

static int e1000_mii_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct mii_ioctl_data *data = if_mii(ifr);

	if (adapter->hw.phy.media_type != e1000_media_type_copper)
		return -EOPNOTSUPP;

	switch (cmd) {
	case SIOCGMIIPHY:
		data->phy_id = adapter->hw.phy.addr;
		break;
	case SIOCGMIIREG:
		e1000_phy_read_status(adapter);

		switch (data->reg_num & 0x1F) {
		case MII_BMCR:
			data->val_out = adapter->phy_regs.bmcr;
			break;
		case MII_BMSR:
			data->val_out = adapter->phy_regs.bmsr;
			break;
		case MII_PHYSID1:
			data->val_out = (adapter->hw.phy.id >> 16);
			break;
		case MII_PHYSID2:
			data->val_out = (adapter->hw.phy.id & 0xFFFF);
			break;
		case MII_ADVERTISE:
			data->val_out = adapter->phy_regs.advertise;
			break;
		case MII_LPA:
			data->val_out = adapter->phy_regs.lpa;
			break;
		case MII_EXPANSION:
			data->val_out = adapter->phy_regs.expansion;
			break;
		case MII_CTRL1000:
			data->val_out = adapter->phy_regs.ctrl1000;
			break;
		case MII_STAT1000:
			data->val_out = adapter->phy_regs.stat1000;
			break;
		case MII_ESTATUS:
			data->val_out = adapter->phy_regs.estatus;
			break;
		default:
			return -EIO;
		}
		break;
	case SIOCSMIIREG:
	default:
		return -EOPNOTSUPP;
	}
	return 0;
}

static int e1000_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	switch (cmd) {
	case SIOCGMIIPHY:
	case SIOCGMIIREG:
	case SIOCSMIIREG:
		return e1000_mii_ioctl(netdev, ifr, cmd);
	default:
		return -EOPNOTSUPP;
	}
}

static int e1000_init_phy_wakeup(struct e1000_adapter *adapter, u32 wufc)
{
	struct e1000_hw *hw = &adapter->hw;
	u32 i, mac_reg;
	u16 phy_reg;
	int retval = 0;

	
	for (i = 0; i < adapter->hw.mac.rar_entry_count; i++) {
		mac_reg = er32(RAL(i));
		e1e_wphy(hw, BM_RAR_L(i), (u16)(mac_reg & 0xFFFF));
		e1e_wphy(hw, BM_RAR_M(i), (u16)((mac_reg >> 16) & 0xFFFF));
		mac_reg = er32(RAH(i));
		e1e_wphy(hw, BM_RAR_H(i), (u16)(mac_reg & 0xFFFF));
		e1e_wphy(hw, BM_RAR_CTRL(i), (u16)((mac_reg >> 16) & 0xFFFF));
	}

	
	for (i = 0; i < adapter->hw.mac.mta_reg_count; i++) {
		mac_reg = E1000_READ_REG_ARRAY(hw, E1000_MTA, i);
		e1e_wphy(hw, BM_MTA(i), (u16)(mac_reg & 0xFFFF));
		e1e_wphy(hw, BM_MTA(i) + 1, (u16)((mac_reg >> 16) & 0xFFFF));
	}

	
	e1e_rphy(&adapter->hw, BM_RCTL, &phy_reg);
	mac_reg = er32(RCTL);
	if (mac_reg & E1000_RCTL_UPE)
		phy_reg |= BM_RCTL_UPE;
	if (mac_reg & E1000_RCTL_MPE)
		phy_reg |= BM_RCTL_MPE;
	phy_reg &= ~(BM_RCTL_MO_MASK);
	if (mac_reg & E1000_RCTL_MO_3)
		phy_reg |= (((mac_reg & E1000_RCTL_MO_3) >> E1000_RCTL_MO_SHIFT)
				<< BM_RCTL_MO_SHIFT);
	if (mac_reg & E1000_RCTL_BAM)
		phy_reg |= BM_RCTL_BAM;
	if (mac_reg & E1000_RCTL_PMCF)
		phy_reg |= BM_RCTL_PMCF;
	mac_reg = er32(CTRL);
	if (mac_reg & E1000_CTRL_RFCE)
		phy_reg |= BM_RCTL_RFCE;
	e1e_wphy(&adapter->hw, BM_RCTL, phy_reg);

	
	ew32(WUFC, wufc);
	ew32(WUC, E1000_WUC_PHY_WAKE | E1000_WUC_PME_EN);

	
	e1e_wphy(&adapter->hw, BM_WUFC, wufc);
	e1e_wphy(&adapter->hw, BM_WUC, E1000_WUC_PME_EN);

	
	retval = hw->phy.ops.acquire(hw);
	if (retval) {
		e_err("Could not acquire PHY\n");
		return retval;
	}
	e1000e_write_phy_reg_mdic(hw, IGP01E1000_PHY_PAGE_SELECT, (BM_WUC_ENABLE_PAGE << IGP_PAGE_SHIFT));
	retval = e1000e_read_phy_reg_mdic(hw, BM_WUC_ENABLE_REG, &phy_reg);
	if (retval) {
		e_err("Could not read PHY page 769\n");
		goto out;
	}
	phy_reg |= BM_WUC_ENABLE_BIT | BM_WUC_HOST_WU_BIT;
	retval = e1000e_write_phy_reg_mdic(hw, BM_WUC_ENABLE_REG, phy_reg);
	if (retval)
		e_err("Could not set PHY Host Wakeup bit\n");
out:
	hw->phy.ops.release(hw);

	return retval;
}

static int __e1000_shutdown(struct pci_dev *pdev, bool *enable_wake)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 ctrl, ctrl_ext, rctl, status;
	u32 wufc = adapter->wol;
	int retval = 0;

	netif_device_detach(netdev);

	if (netif_running(netdev)) {
		WARN_ON(test_bit(__E1000_RESETTING, &adapter->state));
		e1000e_down(adapter);
		e1000_free_irq(adapter);
	}
	e1000e_reset_interrupt_capability(adapter);

	retval = pci_save_state(pdev);
	if (retval)
		return retval;

	status = er32(STATUS);
	if (status & E1000_STATUS_LU)
		wufc &= ~E1000_WUFC_LNKC;

	if (wufc) {
		e1000_setup_rctl(adapter);
		e1000_set_multi(netdev);

		
		if (wufc & E1000_WUFC_MC) {
			rctl = er32(RCTL);
			rctl |= E1000_RCTL_MPE;
			ew32(RCTL, rctl);
		}

		ctrl = er32(CTRL);
		
		#define E1000_CTRL_ADVD3WUC 0x00100000
		
		#define E1000_CTRL_EN_PHY_PWR_MGMT 0x00200000
		ctrl |= E1000_CTRL_ADVD3WUC;
		if (!(adapter->flags2 & FLAG2_HAS_PHY_WAKEUP))
			ctrl |= E1000_CTRL_EN_PHY_PWR_MGMT;
		ew32(CTRL, ctrl);

		if (adapter->hw.phy.media_type == e1000_media_type_fiber || adapter->hw.phy.media_type == e1000_media_type_internal_serdes) {

			
			ctrl_ext = er32(CTRL_EXT);
			ctrl_ext |= E1000_CTRL_EXT_SDP3_DATA;
			ew32(CTRL_EXT, ctrl_ext);
		}

		if (adapter->flags & FLAG_IS_ICH)
			e1000e_disable_gig_wol_ich8lan(&adapter->hw);

		
		e1000e_disable_pcie_master(&adapter->hw);

		if (adapter->flags2 & FLAG2_HAS_PHY_WAKEUP) {
			
			retval = e1000_init_phy_wakeup(adapter, wufc);
			if (retval)
				return retval;
		} else {
			
			ew32(WUFC, wufc);
			ew32(WUC, E1000_WUC_PME_EN);
		}
	} else {
		ew32(WUC, 0);
		ew32(WUFC, 0);
	}

	*enable_wake = !!wufc;

	
	if ((adapter->flags & FLAG_MNG_PT_ENABLED) || (hw->mac.ops.check_mng_mode(hw)))
		*enable_wake = true;

	if (adapter->hw.phy.type == e1000_phy_igp_3)
		e1000e_igp3_phy_powerdown_workaround_ich8lan(&adapter->hw);

	
	e1000_release_hw_control(adapter);

	pci_disable_device(pdev);

	return 0;
}

static void e1000_power_off(struct pci_dev *pdev, bool sleep, bool wake)
{
	if (sleep && wake) {
		pci_prepare_to_sleep(pdev);
		return;
	}

	pci_wake_from_d3(pdev, wake);
	pci_set_power_state(pdev, PCI_D3hot);
}

static void e1000_complete_shutdown(struct pci_dev *pdev, bool sleep, bool wake)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);

	
	if (adapter->flags & FLAG_IS_QUAD_PORT) {
		struct pci_dev *us_dev = pdev->bus->self;
		int pos = pci_find_capability(us_dev, PCI_CAP_ID_EXP);
		u16 devctl;

		pci_read_config_word(us_dev, pos + PCI_EXP_DEVCTL, &devctl);
		pci_write_config_word(us_dev, pos + PCI_EXP_DEVCTL, (devctl & ~PCI_EXP_DEVCTL_CERE));

		e1000_power_off(pdev, sleep, wake);

		pci_write_config_word(us_dev, pos + PCI_EXP_DEVCTL, devctl);
	} else {
		e1000_power_off(pdev, sleep, wake);
	}
}

static void e1000e_disable_l1aspm(struct pci_dev *pdev)
{
	int pos;
	u16 val;

	
	pos = pci_find_capability(pdev, PCI_CAP_ID_EXP);
	pci_read_config_word(pdev, pos + PCI_EXP_LNKCTL, &val);
	if (val & 0x2) {
		dev_warn(&pdev->dev, "Disabling L1 ASPM\n");
		val &= ~0x2;
		pci_write_config_word(pdev, pos + PCI_EXP_LNKCTL, val);
	}
}


static int e1000_suspend(struct pci_dev *pdev, pm_message_t state)
{
	int retval;
	bool wake;

	retval = __e1000_shutdown(pdev, &wake);
	if (!retval)
		e1000_complete_shutdown(pdev, true, wake);

	return retval;
}

static int e1000_resume(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	u32 err;

	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);
	pci_save_state(pdev);
	e1000e_disable_l1aspm(pdev);

	err = pci_enable_device_mem(pdev);
	if (err) {
		dev_err(&pdev->dev, "Cannot enable PCI device from suspend\n");
		return err;
	}

	pci_set_master(pdev);

	pci_enable_wake(pdev, PCI_D3hot, 0);
	pci_enable_wake(pdev, PCI_D3cold, 0);

	e1000e_set_interrupt_capability(adapter);
	if (netif_running(netdev)) {
		err = e1000_request_irq(adapter);
		if (err)
			return err;
	}

	e1000e_power_up_phy(adapter);

	
	if (adapter->flags2 & FLAG2_HAS_PHY_WAKEUP) {
		u16 phy_data;

		e1e_rphy(&adapter->hw, BM_WUS, &phy_data);
		if (phy_data) {
			e_info("PHY Wakeup cause - %s\n", phy_data & E1000_WUS_EX ? "Unicast Packet" :
				phy_data & E1000_WUS_MC ? "Multicast Packet" :
				phy_data & E1000_WUS_BC ? "Broadcast Packet" :
				phy_data & E1000_WUS_MAG ? "Magic Packet" :
				phy_data & E1000_WUS_LNKC ? "Link Status " " Change" : "other");
		}
		e1e_wphy(&adapter->hw, BM_WUS, ~0);
	} else {
		u32 wus = er32(WUS);
		if (wus) {
			e_info("MAC Wakeup cause - %s\n", wus & E1000_WUS_EX ? "Unicast Packet" :
				wus & E1000_WUS_MC ? "Multicast Packet" :
				wus & E1000_WUS_BC ? "Broadcast Packet" :
				wus & E1000_WUS_MAG ? "Magic Packet" :
				wus & E1000_WUS_LNKC ? "Link Status Change" :
				"other");
		}
		ew32(WUS, ~0);
	}

	e1000e_reset(adapter);

	e1000_init_manageability(adapter);

	if (netif_running(netdev))
		e1000e_up(adapter);

	netif_device_attach(netdev);

	
	if (!(adapter->flags & FLAG_HAS_AMT))
		e1000_get_hw_control(adapter);

	return 0;
}


static void e1000_shutdown(struct pci_dev *pdev)
{
	bool wake = false;

	__e1000_shutdown(pdev, &wake);

	if (system_state == SYSTEM_POWER_OFF)
		e1000_complete_shutdown(pdev, false, wake);
}



static void e1000_netpoll(struct net_device *netdev)
{
	struct e1000_adapter *adapter = netdev_priv(netdev);

	disable_irq(adapter->pdev->irq);
	e1000_intr(adapter->pdev->irq, netdev);

	enable_irq(adapter->pdev->irq);
}



static pci_ers_result_t e1000_io_error_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);

	netif_device_detach(netdev);

	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	if (netif_running(netdev))
		e1000e_down(adapter);
	pci_disable_device(pdev);

	
	return PCI_ERS_RESULT_NEED_RESET;
}


static pci_ers_result_t e1000_io_slot_reset(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);
	struct e1000_hw *hw = &adapter->hw;
	int err;
	pci_ers_result_t result;

	e1000e_disable_l1aspm(pdev);
	err = pci_enable_device_mem(pdev);
	if (err) {
		dev_err(&pdev->dev, "Cannot re-enable PCI device after reset.\n");
		result = PCI_ERS_RESULT_DISCONNECT;
	} else {
		pci_set_master(pdev);
		pci_restore_state(pdev);
		pci_save_state(pdev);

		pci_enable_wake(pdev, PCI_D3hot, 0);
		pci_enable_wake(pdev, PCI_D3cold, 0);

		e1000e_reset(adapter);
		ew32(WUS, ~0);
		result = PCI_ERS_RESULT_RECOVERED;
	}

	pci_cleanup_aer_uncorrect_error_status(pdev);

	return result;
}


static void e1000_io_resume(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);

	e1000_init_manageability(adapter);

	if (netif_running(netdev)) {
		if (e1000e_up(adapter)) {
			dev_err(&pdev->dev, "can't bring device back up after reset\n");
			return;
		}
	}

	netif_device_attach(netdev);

	
	if (!(adapter->flags & FLAG_HAS_AMT))
		e1000_get_hw_control(adapter);

}

static void e1000_print_device_info(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	struct net_device *netdev = adapter->netdev;
	u32 pba_num;

	
	e_info("(PCI Express:2.5GB/s:%s) %pM\n",  ((hw->bus.width == e1000_bus_width_pcie_x4) ? "Width x4" :

	        "Width x1"),  netdev->dev_addr);

	e_info("Intel(R) PRO/%s Network Connection\n", (hw->phy.type == e1000_phy_ife) ? "10/100" : "1000");
	e1000e_read_pba_num(hw, &pba_num);
	e_info("MAC: %d, PHY: %d, PBA No: %06x-%03x\n", hw->mac.type, hw->phy.type, (pba_num >> 8), (pba_num & 0xff));
}

static void e1000_eeprom_checks(struct e1000_adapter *adapter)
{
	struct e1000_hw *hw = &adapter->hw;
	int ret_val;
	u16 buf = 0;

	if (hw->mac.type != e1000_82573)
		return;

	ret_val = e1000_read_nvm(hw, NVM_INIT_CONTROL2_REG, 1, &buf);
	if (!ret_val && (!(le16_to_cpu(buf) & (1 << 0)))) {
		
		dev_warn(&adapter->pdev->dev, "Warning: detected DSPD enabled in EEPROM\n");
	}

	ret_val = e1000_read_nvm(hw, NVM_INIT_3GIO_3, 1, &buf);
	if (!ret_val && (le16_to_cpu(buf) & (3 << 2))) {
		
		dev_warn(&adapter->pdev->dev, "Warning: detected ASPM enabled in EEPROM\n");
	}
}

static const struct net_device_ops e1000e_netdev_ops = {
	.ndo_open		= e1000_open, .ndo_stop		= e1000_close, .ndo_start_xmit		= e1000_xmit_frame, .ndo_get_stats		= e1000_get_stats, .ndo_set_multicast_list	= e1000_set_multi, .ndo_set_mac_address	= e1000_set_mac, .ndo_change_mtu		= e1000_change_mtu, .ndo_do_ioctl		= e1000_ioctl, .ndo_tx_timeout		= e1000_tx_timeout, .ndo_validate_addr	= eth_validate_addr,  .ndo_vlan_rx_register	= e1000_vlan_rx_register, .ndo_vlan_rx_add_vid	= e1000_vlan_rx_add_vid, .ndo_vlan_rx_kill_vid	= e1000_vlan_rx_kill_vid,  .ndo_poll_controller	= e1000_netpoll,  };


















static int __devinit e1000_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct net_device *netdev;
	struct e1000_adapter *adapter;
	struct e1000_hw *hw;
	const struct e1000_info *ei = e1000_info_tbl[ent->driver_data];
	resource_size_t mmio_start, mmio_len;
	resource_size_t flash_start, flash_len;

	static int cards_found;
	int i, err, pci_using_dac;
	u16 eeprom_data = 0;
	u16 eeprom_apme_mask = E1000_EEPROM_APME;

	e1000e_disable_l1aspm(pdev);

	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	pci_using_dac = 0;
	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (!err) {
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
		if (!err)
			pci_using_dac = 1;
	} else {
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
			if (err) {
				dev_err(&pdev->dev, "No usable DMA " "configuration, aborting\n");
				goto err_dma;
			}
		}
	}

	err = pci_request_selected_regions_exclusive(pdev, pci_select_bars(pdev, IORESOURCE_MEM), e1000e_driver_name);

	if (err)
		goto err_pci_reg;

	
	pci_enable_pcie_error_reporting(pdev);

	pci_set_master(pdev);
	
	err = pci_save_state(pdev);
	if (err)
		goto err_alloc_etherdev;

	err = -ENOMEM;
	netdev = alloc_etherdev(sizeof(struct e1000_adapter));
	if (!netdev)
		goto err_alloc_etherdev;

	SET_NETDEV_DEV(netdev, &pdev->dev);

	pci_set_drvdata(pdev, netdev);
	adapter = netdev_priv(netdev);
	hw = &adapter->hw;
	adapter->netdev = netdev;
	adapter->pdev = pdev;
	adapter->ei = ei;
	adapter->pba = ei->pba;
	adapter->flags = ei->flags;
	adapter->flags2 = ei->flags2;
	adapter->hw.adapter = adapter;
	adapter->hw.mac.type = ei->mac;
	adapter->max_hw_frame_size = ei->max_hw_frame_size;
	adapter->msg_enable = (1 << NETIF_MSG_DRV | NETIF_MSG_PROBE) - 1;

	mmio_start = pci_resource_start(pdev, 0);
	mmio_len = pci_resource_len(pdev, 0);

	err = -EIO;
	adapter->hw.hw_addr = ioremap(mmio_start, mmio_len);
	if (!adapter->hw.hw_addr)
		goto err_ioremap;

	if ((adapter->flags & FLAG_HAS_FLASH) && (pci_resource_flags(pdev, 1) & IORESOURCE_MEM)) {
		flash_start = pci_resource_start(pdev, 1);
		flash_len = pci_resource_len(pdev, 1);
		adapter->hw.flash_address = ioremap(flash_start, flash_len);
		if (!adapter->hw.flash_address)
			goto err_flashmap;
	}

	
	netdev->netdev_ops		= &e1000e_netdev_ops;
	e1000e_set_ethtool_ops(netdev);
	netdev->watchdog_timeo		= 5 * HZ;
	netif_napi_add(netdev, &adapter->napi, e1000_clean, 64);
	strncpy(netdev->name, pci_name(pdev), sizeof(netdev->name) - 1);

	netdev->mem_start = mmio_start;
	netdev->mem_end = mmio_start + mmio_len;

	adapter->bd_number = cards_found++;

	e1000e_check_options(adapter);

	
	err = e1000_sw_init(adapter);
	if (err)
		goto err_sw_init;

	err = -EIO;

	memcpy(&hw->mac.ops, ei->mac_ops, sizeof(hw->mac.ops));
	memcpy(&hw->nvm.ops, ei->nvm_ops, sizeof(hw->nvm.ops));
	memcpy(&hw->phy.ops, ei->phy_ops, sizeof(hw->phy.ops));

	err = ei->get_variants(adapter);
	if (err)
		goto err_hw_init;

	if ((adapter->flags & FLAG_IS_ICH) && (adapter->flags & FLAG_READ_ONLY_NVM))
		e1000e_write_protect_nvm_ich8lan(&adapter->hw);

	hw->mac.ops.get_bus_info(&adapter->hw);

	adapter->hw.phy.autoneg_wait_to_complete = 0;

	
	if (adapter->hw.phy.media_type == e1000_media_type_copper) {
		adapter->hw.phy.mdix = AUTO_ALL_MODES;
		adapter->hw.phy.disable_polarity_correction = 0;
		adapter->hw.phy.ms_type = e1000_ms_hw_default;
	}

	if (e1000_check_reset_block(&adapter->hw))
		e_info("PHY reset is blocked due to SOL/IDER session.\n");

	netdev->features = NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX;



	if (adapter->flags & FLAG_HAS_HW_VLAN_FILTER)
		netdev->features |= NETIF_F_HW_VLAN_FILTER;

	netdev->features |= NETIF_F_TSO;
	netdev->features |= NETIF_F_TSO6;

	netdev->vlan_features |= NETIF_F_TSO;
	netdev->vlan_features |= NETIF_F_TSO6;
	netdev->vlan_features |= NETIF_F_HW_CSUM;
	netdev->vlan_features |= NETIF_F_SG;

	if (pci_using_dac)
		netdev->features |= NETIF_F_HIGHDMA;

	if (e1000e_enable_mng_pass_thru(&adapter->hw))
		adapter->flags |= FLAG_MNG_PT_ENABLED;

	
	adapter->hw.mac.ops.reset_hw(&adapter->hw);

	
	for (i = 0;; i++) {
		if (e1000_validate_nvm_checksum(&adapter->hw) >= 0)
			break;
		if (i == 2) {
			e_err("The NVM Checksum Is Not Valid\n");
			err = -EIO;
			goto err_eeprom;
		}
	}

	e1000_eeprom_checks(adapter);

	
	if (e1000e_read_mac_addr(&adapter->hw))
		e_err("NVM Read Error while reading MAC address\n");

	memcpy(netdev->dev_addr, adapter->hw.mac.addr, netdev->addr_len);
	memcpy(netdev->perm_addr, adapter->hw.mac.addr, netdev->addr_len);

	if (!is_valid_ether_addr(netdev->perm_addr)) {
		e_err("Invalid MAC Address: %pM\n", netdev->perm_addr);
		err = -EIO;
		goto err_eeprom;
	}

	init_timer(&adapter->watchdog_timer);
	adapter->watchdog_timer.function = &e1000_watchdog;
	adapter->watchdog_timer.data = (unsigned long) adapter;

	init_timer(&adapter->phy_info_timer);
	adapter->phy_info_timer.function = &e1000_update_phy_info;
	adapter->phy_info_timer.data = (unsigned long) adapter;

	INIT_WORK(&adapter->reset_task, e1000_reset_task);
	INIT_WORK(&adapter->watchdog_task, e1000_watchdog_task);
	INIT_WORK(&adapter->downshift_task, e1000e_downshift_workaround);
	INIT_WORK(&adapter->update_phy_task, e1000e_update_phy_task);
	INIT_WORK(&adapter->print_hang_task, e1000_print_hw_hang);

	
	adapter->hw.mac.autoneg = 1;
	adapter->fc_autoneg = 1;
	adapter->hw.fc.requested_mode = e1000_fc_default;
	adapter->hw.fc.current_mode = e1000_fc_default;
	adapter->hw.phy.autoneg_advertised = 0x2f;

	
	adapter->rx_ring->count = 256;
	adapter->tx_ring->count = 256;

	
	if (adapter->flags & FLAG_APME_IN_WUC) {
		
		eeprom_data = er32(WUC);
		eeprom_apme_mask = E1000_WUC_APME;
		if (eeprom_data & E1000_WUC_PHY_WAKE)
			adapter->flags2 |= FLAG2_HAS_PHY_WAKEUP;
	} else if (adapter->flags & FLAG_APME_IN_CTRL3) {
		if (adapter->flags & FLAG_APME_CHECK_PORT_B && (adapter->hw.bus.func == 1))
			e1000_read_nvm(&adapter->hw, NVM_INIT_CONTROL3_PORT_B, 1, &eeprom_data);
		else e1000_read_nvm(&adapter->hw, NVM_INIT_CONTROL3_PORT_A, 1, &eeprom_data);

	}

	
	if (eeprom_data & eeprom_apme_mask)
		adapter->eeprom_wol |= E1000_WUFC_MAG;

	
	if (!(adapter->flags & FLAG_HAS_WOL))
		adapter->eeprom_wol = 0;

	
	adapter->wol = adapter->eeprom_wol;
	device_set_wakeup_enable(&adapter->pdev->dev, adapter->wol);

	
	e1000_read_nvm(&adapter->hw, 5, 1, &adapter->eeprom_vers);

	
	e1000e_reset(adapter);

	
	if (!(adapter->flags & FLAG_HAS_AMT))
		e1000_get_hw_control(adapter);

	strcpy(netdev->name, "eth%d");
	err = register_netdev(netdev);
	if (err)
		goto err_register;

	
	netif_carrier_off(netdev);

	e1000_print_device_info(adapter);

	return 0;

err_register:
	if (!(adapter->flags & FLAG_HAS_AMT))
		e1000_release_hw_control(adapter);
err_eeprom:
	if (!e1000_check_reset_block(&adapter->hw))
		e1000_phy_hw_reset(&adapter->hw);
err_hw_init:

	kfree(adapter->tx_ring);
	kfree(adapter->rx_ring);
err_sw_init:
	if (adapter->hw.flash_address)
		iounmap(adapter->hw.flash_address);
	e1000e_reset_interrupt_capability(adapter);
err_flashmap:
	iounmap(adapter->hw.hw_addr);
err_ioremap:
	free_netdev(netdev);
err_alloc_etherdev:
	pci_release_selected_regions(pdev, pci_select_bars(pdev, IORESOURCE_MEM));
err_pci_reg:
err_dma:
	pci_disable_device(pdev);
	return err;
}


static void __devexit e1000_remove(struct pci_dev *pdev)
{
	struct net_device *netdev = pci_get_drvdata(pdev);
	struct e1000_adapter *adapter = netdev_priv(netdev);

	
	set_bit(__E1000_DOWN, &adapter->state);
	del_timer_sync(&adapter->watchdog_timer);
	del_timer_sync(&adapter->phy_info_timer);

	cancel_work_sync(&adapter->reset_task);
	cancel_work_sync(&adapter->watchdog_task);
	cancel_work_sync(&adapter->downshift_task);
	cancel_work_sync(&adapter->update_phy_task);
	cancel_work_sync(&adapter->print_hang_task);
	flush_scheduled_work();

	if (!(netdev->flags & IFF_UP))
		e1000_power_down_phy(adapter);

	unregister_netdev(netdev);

	
	e1000_release_hw_control(adapter);

	e1000e_reset_interrupt_capability(adapter);
	kfree(adapter->tx_ring);
	kfree(adapter->rx_ring);

	iounmap(adapter->hw.hw_addr);
	if (adapter->hw.flash_address)
		iounmap(adapter->hw.flash_address);
	pci_release_selected_regions(pdev, pci_select_bars(pdev, IORESOURCE_MEM));

	free_netdev(netdev);

	
	pci_disable_pcie_error_reporting(pdev);

	pci_disable_device(pdev);
}


static struct pci_error_handlers e1000_err_handler = {
	.error_detected = e1000_io_error_detected, .slot_reset = e1000_io_slot_reset, .resume = e1000_io_resume, };



static struct pci_device_id e1000_pci_tbl[] = {
	{ PCI_VDEVICE(INTEL, E1000_DEV_ID_82571EB_COPPER), board_82571 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82571EB_FIBER), board_82571 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82571EB_QUAD_COPPER), board_82571 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82571EB_QUAD_COPPER_LP), board_82571 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82571EB_QUAD_FIBER), board_82571 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82571EB_SERDES), board_82571 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82571EB_SERDES_DUAL), board_82571 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82571EB_SERDES_QUAD), board_82571 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82571PT_QUAD_COPPER), board_82571 },  { PCI_VDEVICE(INTEL, E1000_DEV_ID_82572EI), board_82572 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82572EI_COPPER), board_82572 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82572EI_FIBER), board_82572 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82572EI_SERDES), board_82572 },  { PCI_VDEVICE(INTEL, E1000_DEV_ID_82573E), board_82573 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82573E_IAMT), board_82573 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82573L), board_82573 },  { PCI_VDEVICE(INTEL, E1000_DEV_ID_82574L), board_82574 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82574LA), board_82574 }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_82583V), board_82583 },  { PCI_VDEVICE(INTEL, E1000_DEV_ID_80003ES2LAN_COPPER_DPT), board_80003es2lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_80003ES2LAN_COPPER_SPT), board_80003es2lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_80003ES2LAN_SERDES_DPT), board_80003es2lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_80003ES2LAN_SERDES_SPT), board_80003es2lan },  { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH8_IFE), board_ich8lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH8_IFE_G), board_ich8lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH8_IFE_GT), board_ich8lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH8_IGP_AMT), board_ich8lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH8_IGP_C), board_ich8lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH8_IGP_M), board_ich8lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH8_IGP_M_AMT), board_ich8lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH8_82567V_3), board_ich8lan },  { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH9_IFE), board_ich9lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH9_IFE_G), board_ich9lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH9_IFE_GT), board_ich9lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH9_IGP_AMT), board_ich9lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH9_IGP_C), board_ich9lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH9_BM), board_ich9lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH9_IGP_M), board_ich9lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH9_IGP_M_AMT), board_ich9lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH9_IGP_M_V), board_ich9lan },  { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH10_R_BM_LM), board_ich9lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH10_R_BM_LF), board_ich9lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH10_R_BM_V), board_ich9lan },  { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH10_D_BM_LM), board_ich10lan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_ICH10_D_BM_LF), board_ich10lan },  { PCI_VDEVICE(INTEL, E1000_DEV_ID_PCH_M_HV_LM), board_pchlan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_PCH_M_HV_LC), board_pchlan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_PCH_D_HV_DM), board_pchlan }, { PCI_VDEVICE(INTEL, E1000_DEV_ID_PCH_D_HV_DC), board_pchlan },  { }






























































};
MODULE_DEVICE_TABLE(pci, e1000_pci_tbl);


static struct pci_driver e1000_driver = {
	.name     = e1000e_driver_name, .id_table = e1000_pci_tbl, .probe    = e1000_probe, .remove   = __devexit_p(e1000_remove),   .suspend  = e1000_suspend, .resume   = e1000_resume,  .shutdown = e1000_shutdown, .err_handler = &e1000_err_handler };












static int __init e1000_init_module(void)
{
	int ret;
	printk(KERN_INFO "%s: Intel(R) PRO/1000 Network Driver - %s\n", e1000e_driver_name, e1000e_driver_version);
	printk(KERN_INFO "%s: Copyright (c) 1999 - 2009 Intel Corporation.\n", e1000e_driver_name);
	ret = pci_register_driver(&e1000_driver);

	return ret;
}
module_init(e1000_init_module);


static void __exit e1000_exit_module(void)
{
	pci_unregister_driver(&e1000_driver);
}
module_exit(e1000_exit_module);


MODULE_AUTHOR("Intel Corporation, <linux.nics@intel.com>");
MODULE_DESCRIPTION("Intel(R) PRO/1000 Network Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);


