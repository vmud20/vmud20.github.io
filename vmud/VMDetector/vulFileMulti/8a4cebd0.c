




























int keylifetime = 0;

static char lzo_wrkmem[LZO1X_999_MEM_COMPRESS > LZO1X_1_MEM_COMPRESS ? LZO1X_999_MEM_COMPRESS : LZO1X_1_MEM_COMPRESS];


static void send_udppacket(node_t *, vpn_packet_t *);

unsigned replaywin = 16;
bool localdiscovery = false;





static void send_mtu_probe_handler(void *data) {
	node_t *n = data;
	int timeout = 1;

	n->mtuprobes++;

	if(!n->status.reachable || !n->status.validkey) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Trying to send MTU probe to unreachable or rekeying node %s (%s)", n->name, n->hostname);
		n->mtuprobes = 0;
		return;
	}

	if(n->mtuprobes > 32) {
		if(!n->minmtu) {
			n->mtuprobes = 31;
			timeout = pinginterval;
			goto end;
		}

		logger(DEBUG_TRAFFIC, LOG_INFO, "%s (%s) did not respond to UDP ping, restarting PMTU discovery", n->name, n->hostname);
		n->status.udp_confirmed = false;
		n->mtuprobes = 1;
		n->minmtu = 0;
		n->maxmtu = MTU;
	}

	if(n->mtuprobes >= 10 && n->mtuprobes < 32 && !n->minmtu) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "No response to MTU probes from %s (%s)", n->name, n->hostname);
		n->mtuprobes = 31;
	}

	if(n->mtuprobes == 30 || (n->mtuprobes < 30 && n->minmtu >= n->maxmtu)) {
		if(n->minmtu > n->maxmtu)
			n->minmtu = n->maxmtu;
		else n->maxmtu = n->minmtu;
		n->mtu = n->minmtu;
		logger(DEBUG_TRAFFIC, LOG_INFO, "Fixing MTU of %s (%s) to %d after %d probes", n->name, n->hostname, n->mtu, n->mtuprobes);
		n->mtuprobes = 31;
	}

	if(n->mtuprobes == 31) {
		timeout = pinginterval;
		goto end;
	} else if(n->mtuprobes == 32) {
		timeout = pingtimeout;
	}

	for(int i = 0; i < 4 + localdiscovery; i++) {
		int len;

		if(i == 0) {
			if(n->mtuprobes < 30 || n->maxmtu + 8 >= MTU)
				continue;
			len = n->maxmtu + 8;
		} else if(n->maxmtu <= n->minmtu) {
			len = n->maxmtu;
		} else {
			len = n->minmtu + 1 + rand() % (n->maxmtu - n->minmtu);
		}

		if(len < 64)
			len = 64;

		vpn_packet_t packet;
		memset(packet.data, 0, 14);
		randomize(packet.data + 14, len - 14);
		packet.len = len;
		if(i >= 4 && n->mtuprobes <= 10)
			packet.priority = -1;
		else packet.priority = 0;

		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending MTU probe length %d to %s (%s)", len, n->name, n->hostname);

		send_udppacket(n, &packet);
	}

	n->probe_counter = 0;
	gettimeofday(&n->probe_time, NULL);

	

	if(n->received > n->prev_received)
		n->packetloss = 1.0 - (n->received - n->prev_received) / (float)(n->received_seqno - n->prev_received_seqno);
	else n->packetloss = n->received_seqno <= n->prev_received_seqno;

	n->prev_received_seqno = n->received_seqno;
	n->prev_received = n->received;

end:
	timeout_set(&n->mtutimeout, &(struct timeval){timeout, rand() % 100000});
}

void send_mtu_probe(node_t *n) {
	timeout_add(&n->mtutimeout, send_mtu_probe_handler, n, &(struct timeval){1, 0});
	send_mtu_probe_handler(n);
}

static void mtu_probe_h(node_t *n, vpn_packet_t *packet, length_t len) {
	logger(DEBUG_TRAFFIC, LOG_INFO, "Got MTU probe length %d from %s (%s)", packet->len, n->name, n->hostname);

	if(!packet->data[0]) {
		

		packet->data[0] = 1;

		

		bool udp_confirmed = n->status.udp_confirmed;
		n->status.udp_confirmed = true;
		send_udppacket(n, packet);
		n->status.udp_confirmed = udp_confirmed;
	} else {
		

		n->status.udp_confirmed = true;

		

		if(n->mtuprobes > 30) {
			if (len == n->maxmtu + 8) {
				logger(DEBUG_TRAFFIC, LOG_INFO, "Increase in PMTU to %s (%s) detected, restarting PMTU discovery", n->name, n->hostname);
				n->maxmtu = MTU;
				n->mtuprobes = 10;
				return;
			}

			if(n->minmtu)
				n->mtuprobes = 30;
			else n->mtuprobes = 1;
		}

		

		if(len > n->maxmtu)
			len = n->maxmtu;
		if(n->minmtu < len)
			n->minmtu = len;

		

		struct timeval now, diff;
		gettimeofday(&now, NULL);
		timersub(&now, &n->probe_time, &diff);
		n->probe_counter++;

		if(n->probe_counter == 1) {
			n->rtt = diff.tv_sec + diff.tv_usec * 1e-6;
			n->probe_time = now;
		} else if(n->probe_counter == 3) {
			n->bandwidth = 2.0 * len / (diff.tv_sec + diff.tv_usec * 1e-6);
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "%s (%s) RTT %.2f ms, burst bandwidth %.3f Mbit/s, rx packet loss %.2f %%", n->name, n->hostname, n->rtt * 1e3, n->bandwidth * 8e-6, n->packetloss * 1e2);
		}
	}
}

static length_t compress_packet(uint8_t *dest, const uint8_t *source, length_t len, int level) {
	if(level == 0) {
		memcpy(dest, source, len);
		return len;
	} else if(level == 10) {

		lzo_uint lzolen = MAXSIZE;
		lzo1x_1_compress(source, len, dest, &lzolen, lzo_wrkmem);
		return lzolen;

		return -1;

	} else if(level < 10) {

		unsigned long destlen = MAXSIZE;
		if(compress2(dest, &destlen, source, len, level) == Z_OK)
			return destlen;
		else  return -1;

	} else {

		lzo_uint lzolen = MAXSIZE;
		lzo1x_999_compress(source, len, dest, &lzolen, lzo_wrkmem);
		return lzolen;

		return -1;

	}

	return -1;
}

static length_t uncompress_packet(uint8_t *dest, const uint8_t *source, length_t len, int level) {
	if(level == 0) {
		memcpy(dest, source, len);
		return len;
	} else if(level > 9) {

		lzo_uint lzolen = MAXSIZE;
		if(lzo1x_decompress_safe(source, len, dest, &lzolen, NULL) == LZO_E_OK)
			return lzolen;
		else  return -1;

	}

	else {
		unsigned long destlen = MAXSIZE;
		if(uncompress(dest, &destlen, source, len) == Z_OK)
			return destlen;
		else return -1;
	}


	return -1;
}



static void receive_packet(node_t *n, vpn_packet_t *packet) {
	logger(DEBUG_TRAFFIC, LOG_DEBUG, "Received packet of %d bytes from %s (%s)", packet->len, n->name, n->hostname);

	n->in_packets++;
	n->in_bytes += packet->len;

	route(n, packet);
}

static bool try_mac(node_t *n, const vpn_packet_t *inpkt) {
	if(n->status.sptps)
		return sptps_verify_datagram(&n->sptps, (char *)&inpkt->seqno, inpkt->len);

	if(!digest_active(&n->indigest) || inpkt->len < sizeof inpkt->seqno + digest_length(&n->indigest))
		return false;

	return digest_verify(&n->indigest, &inpkt->seqno, inpkt->len - n->indigest.maclength, (const char *)&inpkt->seqno + inpkt->len - n->indigest.maclength);
}

static void receive_udppacket(node_t *n, vpn_packet_t *inpkt) {
	vpn_packet_t pkt1, pkt2;
	vpn_packet_t *pkt[] = { &pkt1, &pkt2, &pkt1, &pkt2 };
	int nextpkt = 0;
	vpn_packet_t *outpkt = pkt[0];
	size_t outlen;

	if(n->status.sptps) {
		sptps_receive_data(&n->sptps, (char *)&inpkt->seqno, inpkt->len);
		return;
	}

	if(!cipher_active(&n->incipher)) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got packet from %s (%s) but he hasn't got our key yet", n->name, n->hostname);
		return;
	}

	

	if(inpkt->len < sizeof inpkt->seqno + digest_length(&n->indigest)) {
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got too short packet from %s (%s)", n->name, n->hostname);
		return;
	}

	

	if(digest_active(&n->indigest)) {
		inpkt->len -= n->indigest.maclength;
		if(!digest_verify(&n->indigest, &inpkt->seqno, inpkt->len, (const char *)&inpkt->seqno + inpkt->len)) {
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Got unauthenticated packet from %s (%s)", n->name, n->hostname);
			return;
		}
	}
	

	if(cipher_active(&n->incipher)) {
		outpkt = pkt[nextpkt++];
		outlen = MAXSIZE;

		if(!cipher_decrypt(&n->incipher, &inpkt->seqno, inpkt->len, &outpkt->seqno, &outlen, true)) {
			logger(DEBUG_TRAFFIC, LOG_DEBUG, "Error decrypting packet from %s (%s)", n->name, n->hostname);
			return;
		}

		outpkt->len = outlen;
		inpkt = outpkt;
	}

	

	inpkt->len -= sizeof inpkt->seqno;
	inpkt->seqno = ntohl(inpkt->seqno);

	if(replaywin) {
		if(inpkt->seqno != n->received_seqno + 1) {
			if(inpkt->seqno >= n->received_seqno + replaywin * 8) {
				if(n->farfuture++ < replaywin >> 2) {
					logger(DEBUG_ALWAYS, LOG_WARNING, "Packet from %s (%s) is %d seqs in the future, dropped (%u)", n->name, n->hostname, inpkt->seqno - n->received_seqno - 1, n->farfuture);
					return;
				}
				logger(DEBUG_ALWAYS, LOG_WARNING, "Lost %d packets from %s (%s)", inpkt->seqno - n->received_seqno - 1, n->name, n->hostname);
				memset(n->late, 0, replaywin);
			} else if (inpkt->seqno <= n->received_seqno) {
				if((n->received_seqno >= replaywin * 8 && inpkt->seqno <= n->received_seqno - replaywin * 8) || !(n->late[(inpkt->seqno / 8) % replaywin] & (1 << inpkt->seqno % 8))) {
					logger(DEBUG_ALWAYS, LOG_WARNING, "Got late or replayed packet from %s (%s), seqno %d, last received %d", n->name, n->hostname, inpkt->seqno, n->received_seqno);
					return;
				}
			} else {
				for(int i = n->received_seqno + 1; i < inpkt->seqno; i++)
					n->late[(i / 8) % replaywin] |= 1 << i % 8;
			}
		}

		n->farfuture = 0;
		n->late[(inpkt->seqno / 8) % replaywin] &= ~(1 << inpkt->seqno % 8);
	}

	if(inpkt->seqno > n->received_seqno)
		n->received_seqno = inpkt->seqno;

	n->received++;

	if(n->received_seqno > MAX_SEQNO)
		regenerate_key();

	

	length_t origlen = inpkt->len;

	if(n->incompression) {
		outpkt = pkt[nextpkt++];

		if((outpkt->len = uncompress_packet(outpkt->data, inpkt->data, inpkt->len, n->incompression)) < 0) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while uncompressing packet from %s (%s)", n->name, n->hostname);
			return;
		}

		inpkt = outpkt;

		origlen -= MTU/64 + 20;
	}

	inpkt->priority = 0;

	if(!inpkt->data[12] && !inpkt->data[13])
		mtu_probe_h(n, inpkt, origlen);
	else receive_packet(n, inpkt);
}

void receive_tcppacket(connection_t *c, const char *buffer, int len) {
	vpn_packet_t outpkt;

	outpkt.len = len;
	if(c->options & OPTION_TCPONLY)
		outpkt.priority = 0;
	else outpkt.priority = -1;
	memcpy(outpkt.data, buffer, len);

	receive_packet(c->node, &outpkt);
}

static void send_sptps_packet(node_t *n, vpn_packet_t *origpkt) {
	if(!n->status.validkey) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "No valid key known yet for %s (%s)", n->name, n->hostname);
		if(!n->status.waitingforkey)
			send_req_key(n);
		else if(n->last_req_key + 10 < now.tv_sec) {
			logger(DEBUG_ALWAYS, LOG_DEBUG, "No key from %s after 10 seconds, restarting SPTPS", n->name);
			sptps_stop(&n->sptps);
			n->status.waitingforkey = false;
			send_req_key(n);
		}
		return;
	}

	uint8_t type = 0;
	int offset = 0;

	if(!(origpkt->data[12] | origpkt->data[13])) {
		sptps_send_record(&n->sptps, PKT_PROBE, (char *)origpkt->data, origpkt->len);
		return;
	}

	if(routing_mode == RMODE_ROUTER)
		offset = 14;
	else type = PKT_MAC;

	if(origpkt->len < offset)
		return;

	vpn_packet_t outpkt;

	if(n->outcompression) {
		int len = compress_packet(outpkt.data + offset, origpkt->data + offset, origpkt->len - offset, n->outcompression);
		if(len < 0) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while compressing packet to %s (%s)", n->name, n->hostname);
		} else if(len < origpkt->len - offset) {
			outpkt.len = len + offset;
			origpkt = &outpkt;
			type |= PKT_COMPRESSED;
		}
	}

	sptps_send_record(&n->sptps, type, (char *)origpkt->data + offset, origpkt->len - offset);
	return;
}

static void choose_udp_address(const node_t *n, const sockaddr_t **sa, int *sock) {
	
	*sa = &n->address;
	*sock = n->sock;

	
	if(n->status.udp_confirmed)
		return;

	

	static int x = 0;
	if(++x >= 3) {
		x = 0;
		return;
	}

	

	int i = 0;
	int j = rand() % n->edge_tree->count;
	edge_t *candidate = NULL;

	for splay_each(edge_t, e, n->edge_tree) {
		if(i++ == j) {
			candidate = e->reverse;
			break;
		}
	}

	if(candidate) {
		*sa = &candidate->address;
		*sock = rand() % listen_sockets;
	}

	
	if(listen_socket[*sock].sa.sa.sa_family != (*sa)->sa.sa_family) {
		for(int i = 0; i < listen_sockets; i++) {
			if(listen_socket[i].sa.sa.sa_family == (*sa)->sa.sa_family) {
				*sock = i;
				break;
			}
		}
	}
}

static void choose_broadcast_address(const node_t *n, const sockaddr_t **sa, int *sock) {
	static sockaddr_t broadcast_ipv4 = {
		.in = {
			.sin_family = AF_INET, .sin_addr.s_addr = -1, }

	};

	static sockaddr_t broadcast_ipv6 = {
		.in6 = {
			.sin6_family = AF_INET6, .sin6_addr.s6_addr[0x0] = 0xff, .sin6_addr.s6_addr[0x1] = 0x02, .sin6_addr.s6_addr[0xf] = 0x01, }



	};

	*sock = rand() % listen_sockets;

	if(listen_socket[*sock].sa.sa.sa_family == AF_INET6) {
		broadcast_ipv6.in6.sin6_port = n->prevedge->address.in.sin_port;
		broadcast_ipv6.in6.sin6_scope_id = listen_socket[*sock].sa.in6.sin6_scope_id;
		*sa = &broadcast_ipv6;
	} else {
		broadcast_ipv4.in.sin_port = n->prevedge->address.in.sin_port;
		*sa = &broadcast_ipv4;
	}
}

static void send_udppacket(node_t *n, vpn_packet_t *origpkt) {
	vpn_packet_t pkt1, pkt2;
	vpn_packet_t *pkt[] = { &pkt1, &pkt2, &pkt1, &pkt2 };
	vpn_packet_t *inpkt = origpkt;
	int nextpkt = 0;
	vpn_packet_t *outpkt;
	int origlen = origpkt->len;
	size_t outlen;

	static int priority = 0;

	int origpriority = origpkt->priority;

	if(!n->status.reachable) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Trying to send UDP packet to unreachable node %s (%s)", n->name, n->hostname);
		return;
	}

	if(n->status.sptps)
		return send_sptps_packet(n, origpkt);

	

	if(!n->status.validkey) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "No valid key known yet for %s (%s), forwarding via TCP", n->name, n->hostname);


		if(n->last_req_key + 10 <= now.tv_sec) {
			send_req_key(n);
			n->last_req_key = now.tv_sec;
		}

		send_tcppacket(n->nexthop->connection, origpkt);

		return;
	}

	if(n->options & OPTION_PMTU_DISCOVERY && inpkt->len > n->minmtu && (inpkt->data[12] | inpkt->data[13])) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Packet for %s (%s) larger than minimum MTU, forwarding via %s", n->name, n->hostname, n != n->nexthop ? n->nexthop->name : "TCP");


		if(n != n->nexthop)
			send_packet(n->nexthop, origpkt);
		else send_tcppacket(n->nexthop->connection, origpkt);

		return;
	}

	

	if(n->outcompression) {
		outpkt = pkt[nextpkt++];

		if((outpkt->len = compress_packet(outpkt->data, inpkt->data, inpkt->len, n->outcompression)) < 0) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while compressing packet to %s (%s)", n->name, n->hostname);
			return;
		}

		inpkt = outpkt;
	}

	

	inpkt->seqno = htonl(++(n->sent_seqno));
	inpkt->len += sizeof inpkt->seqno;

	

	if(cipher_active(&n->outcipher)) {
		outpkt = pkt[nextpkt++];
		outlen = MAXSIZE;

		if(!cipher_encrypt(&n->outcipher, &inpkt->seqno, inpkt->len, &outpkt->seqno, &outlen, true)) {
			logger(DEBUG_TRAFFIC, LOG_ERR, "Error while encrypting packet to %s (%s)", n->name, n->hostname);
			goto end;
		}

		outpkt->len = outlen;
		inpkt = outpkt;
	}

	

	if(digest_active(&n->outdigest)) {
		digest_create(&n->outdigest, &inpkt->seqno, inpkt->len, (char *)&inpkt->seqno + inpkt->len);
		inpkt->len += digest_length(&n->outdigest);
	}

	

	const sockaddr_t *sa;
	int sock;

	

	if(origpriority == -1 && n->prevedge)
		choose_broadcast_address(n, &sa, &sock);
	else choose_udp_address(n, &sa, &sock);


	if(priorityinheritance && origpriority != priority && listen_socket[n->sock].sa.sa.sa_family == AF_INET) {
		priority = origpriority;
		logger(DEBUG_TRAFFIC, LOG_DEBUG, "Setting outgoing packet priority to %d", priority);
		if(setsockopt(listen_socket[n->sock].udp.fd, SOL_IP, IP_TOS, &priority, sizeof(priority))) 
			logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "setsockopt", strerror(errno));
	}


	if(sendto(listen_socket[sock].udp.fd, (char *) &inpkt->seqno, inpkt->len, 0, &sa->sa, SALEN(sa->sa)) < 0 && !sockwouldblock(sockerrno)) {
		if(sockmsgsize(sockerrno)) {
			if(n->maxmtu >= origlen)
				n->maxmtu = origlen - 1;
			if(n->mtu >= origlen)
				n->mtu = origlen - 1;
		} else logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending packet to %s (%s): %s", n->name, n->hostname, sockstrerror(sockerrno));
	}

end:
	origpkt->len = origlen;
}

bool send_sptps_data(void *handle, uint8_t type, const char *data, size_t len) {
	node_t *to = handle;

	

	if(type >= SPTPS_HANDSHAKE || ((myself->options | to->options) & OPTION_TCPONLY) || (type != PKT_PROBE && len > to->minmtu)) {
		char buf[len * 4 / 3 + 5];
		b64encode(data, buf, len);
		
		if(!to->status.validkey)
			return send_request(to->nexthop->connection, "%d %s %s %s -1 -1 -1 %d", ANS_KEY, myself->name, to->name, buf, myself->incompression);
		else return send_request(to->nexthop->connection, "%d %s %s %d %s", REQ_KEY, myself->name, to->name, REQ_SPTPS, buf);
	}

	

	const sockaddr_t *sa;
	int sock;

	choose_udp_address(to, &sa, &sock);

	if(sendto(listen_socket[sock].udp.fd, data, len, 0, &sa->sa, SALEN(sa->sa)) < 0 && !sockwouldblock(sockerrno)) {
		if(sockmsgsize(sockerrno)) {
			if(to->maxmtu >= len)
				to->maxmtu = len - 1;
			if(to->mtu >= len)
				to->mtu = len - 1;
		} else {
			logger(DEBUG_TRAFFIC, LOG_WARNING, "Error sending UDP SPTPS packet to %s (%s): %s", to->name, to->hostname, sockstrerror(sockerrno));
			return false;
		}
	}

	return true;
}

bool receive_sptps_record(void *handle, uint8_t type, const char *data, uint16_t len) {
	node_t *from = handle;

	if(type == SPTPS_HANDSHAKE) {
		if(!from->status.validkey) {
			from->status.validkey = true;
			from->status.waitingforkey = false;
			logger(DEBUG_META, LOG_INFO, "SPTPS key exchange with %s (%s) succesful", from->name, from->hostname);
		}
		return true;
	}

	if(len > MTU) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Packet from %s (%s) larger than maximum supported size (%d > %d)", from->name, from->hostname, len, MTU);
		return false;
	}

	vpn_packet_t inpkt;

	if(type == PKT_PROBE) {
		inpkt.len = len;
		memcpy(inpkt.data, data, len);
		mtu_probe_h(from, &inpkt, len);
		return true;
	}

	if(type & ~(PKT_COMPRESSED | PKT_MAC)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unexpected SPTPS record type %d len %d from %s (%s)", type, len, from->name, from->hostname);
		return false;
	}

	
	if(routing_mode != RMODE_ROUTER && !(type & PKT_MAC)) {
		logger(DEBUG_TRAFFIC, LOG_ERR, "Received packet from %s (%s) without MAC header (maybe Mode is not set correctly)", from->name, from->hostname);
		return false;
	} else if(routing_mode == RMODE_ROUTER && (type & PKT_MAC)) {
		logger(DEBUG_TRAFFIC, LOG_WARNING, "Received packet from %s (%s) with MAC header (maybe Mode is not set correctly)", from->name, from->hostname);
	}

	int offset = (type & PKT_MAC) ? 0 : 14;
	if(type & PKT_COMPRESSED) {
		length_t ulen = uncompress_packet(inpkt.data + offset, (const uint8_t *)data, len, from->incompression);
		if(ulen < 0) {
			return false;
		} else {
			inpkt.len = ulen + offset;
		}
		if(inpkt.len > MAXSIZE)
			abort();
	} else {
		memcpy(inpkt.data + offset, data, len);
		inpkt.len = len + offset;
	}

	
	if(offset) {
		switch(inpkt.data[14] >> 4) {
			case 4:
				inpkt.data[12] = 0x08;
				inpkt.data[13] = 0x00;
				break;
			case 6:
				inpkt.data[12] = 0x86;
				inpkt.data[13] = 0xDD;
				break;
			default:
				logger(DEBUG_TRAFFIC, LOG_ERR, "Unknown IP version %d while reading packet from %s (%s)", inpkt.data[14] >> 4, from->name, from->hostname);

				return false;
		}
	}

	receive_packet(from, &inpkt);
	return true;
}


void send_packet(node_t *n, vpn_packet_t *packet) {
	node_t *via;

	if(n == myself) {
		if(overwrite_mac)
			 memcpy(packet->data, mymac.x, ETH_ALEN);
		n->out_packets++;
		n->out_bytes += packet->len;
		devops.write(packet);
		return;
	}

	logger(DEBUG_TRAFFIC, LOG_ERR, "Sending packet of %d bytes to %s (%s)", packet->len, n->name, n->hostname);

	if(!n->status.reachable) {
		logger(DEBUG_TRAFFIC, LOG_INFO, "Node %s (%s) is not reachable", n->name, n->hostname);
		return;
	}

	n->out_packets++;
	n->out_bytes += packet->len;

	if(n->status.sptps) {
		send_sptps_packet(n, packet);
		return;
	}

	via = (packet->priority == -1 || n->via == myself) ? n->nexthop : n->via;

	if(via != n)
		logger(DEBUG_TRAFFIC, LOG_INFO, "Sending packet to %s via %s (%s)", n->name, via->name, n->via->hostname);

	if(packet->priority == -1 || ((myself->options | via->options) & OPTION_TCPONLY)) {
		if(!send_tcppacket(via->connection, packet))
			terminate_connection(via->connection, true);
	} else send_udppacket(via, packet);
}



void broadcast_packet(const node_t *from, vpn_packet_t *packet) {
	
	if(from != myself)
		send_packet(myself, packet);

	
	
	if(tunnelserver || broadcast_mode == BMODE_NONE)
		return;

	logger(DEBUG_TRAFFIC, LOG_INFO, "Broadcasting packet of %d bytes from %s (%s)", packet->len, from->name, from->hostname);

	switch(broadcast_mode) {
		
		
		
		case BMODE_MST:
			for list_each(connection_t, c, connection_list)
				if(c->status.active && c->status.mst && c != from->nexthop->connection)
					send_packet(c->node, packet);
			break;

		
		
		
		case BMODE_DIRECT:
			if(from != myself)
				break;

			for splay_each(node_t, n, node_tree)
				if(n->status.reachable && ((n->via == myself && n->nexthop == n) || n->via == n))
					send_packet(n, packet);
			break;

		default:
			break;
	}
}

static node_t *try_harder(const sockaddr_t *from, const vpn_packet_t *pkt) {
	node_t *n = NULL;
	bool hard = false;
	static time_t last_hard_try = 0;

	for splay_each(edge_t, e, edge_weight_tree) {
		if(!e->to->status.reachable || e->to == myself)
			continue;

		if(sockaddrcmp_noport(from, &e->address)) {
			if(last_hard_try == now.tv_sec)
				continue;
			hard = true;
		}

		if(!try_mac(e->to, pkt))
			continue;

		n = e->to;
		break;
	}

	if(hard)
		last_hard_try = now.tv_sec;

	last_hard_try = now.tv_sec;
	return n;
}

void handle_incoming_vpn_data(void *data, int flags) {
	listen_socket_t *ls = data;
	vpn_packet_t pkt;
	char *hostname;
	sockaddr_t from = {{0}};
	socklen_t fromlen = sizeof from;
	node_t *n;
	int len;

	len = recvfrom(ls->udp.fd, (char *) &pkt.seqno, MAXSIZE, 0, &from.sa, &fromlen);

	if(len <= 0 || len > MAXSIZE) {
		if(!sockwouldblock(sockerrno))
			logger(DEBUG_ALWAYS, LOG_ERR, "Receiving packet failed: %s", sockstrerror(sockerrno));
		return;
	}

	pkt.len = len;

	sockaddrunmap(&from); 

	n = lookup_node_udp(&from);

	if(!n) {
		n = try_harder(&from, &pkt);
		if(n)
			update_node_udp(n, &from);
		else if(debug_level >= DEBUG_PROTOCOL) {
			hostname = sockaddr2hostname(&from);
			logger(DEBUG_PROTOCOL, LOG_WARNING, "Received UDP packet from unknown source %s", hostname);
			free(hostname);
			return;
		}
		else return;
	}

	n->sock = ls - listen_socket;

	receive_udppacket(n, &pkt);
}

void handle_device_data(void *data, int flags) {
	vpn_packet_t packet;

	packet.priority = 0;

	if(devops.read(&packet)) {
		myself->in_packets++;
		myself->in_bytes += packet.len;
		route(myself, &packet);
	}
}