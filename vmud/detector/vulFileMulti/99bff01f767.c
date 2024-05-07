












u_int32_t	checksum(unsigned char *, unsigned, u_int32_t);
u_int32_t	wrapsum(u_int32_t);

u_int32_t checksum(unsigned char *buf, unsigned nbytes, u_int32_t sum)
{
	int i;

	
	for (i = 0; i < (nbytes & ~1U); i += 2) {
		sum += (u_int16_t)ntohs(*((u_int16_t *)(buf + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	
	if (i < nbytes) {
		sum += buf[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}

	return (sum);
}

u_int32_t wrapsum(u_int32_t sum)
{
	sum = ~sum & 0xFFFF;
	return (htons(sum));
}

void assemble_hw_header(struct interface_info *interface, unsigned char *buf, int *bufix, struct hardware *to)

{
	struct ether_header eh;

	if (to != NULL && to->hlen == 6) 
		memcpy(eh.ether_dhost, to->haddr, sizeof(eh.ether_dhost));
	else memset(eh.ether_dhost, 0xff, sizeof(eh.ether_dhost));

	
	memset(eh.ether_shost, 0x00, sizeof(eh.ether_shost));

	eh.ether_type = htons(ETHERTYPE_IP);

	memcpy(&buf[*bufix], &eh, ETHER_HDR_LEN);
	*bufix += ETHER_HDR_LEN;
}

void assemble_udp_ip_header(struct interface_info *interface, unsigned char *buf, int *bufix, u_int32_t from, u_int32_t to, unsigned int port, unsigned char *data, int len)


{
	struct ip ip;
	struct udphdr udp;

	ip.ip_v = 4;
	ip.ip_hl = 5;
	ip.ip_tos = IPTOS_LOWDELAY;
	ip.ip_len = htons(sizeof(ip) + sizeof(udp) + len);
	ip.ip_id = 0;
	ip.ip_off = 0;
	ip.ip_ttl = 16;
	ip.ip_p = IPPROTO_UDP;
	ip.ip_sum = 0;
	ip.ip_src.s_addr = from;
	ip.ip_dst.s_addr = to;

	ip.ip_sum = wrapsum(checksum((unsigned char *)&ip, sizeof(ip), 0));
	memcpy(&buf[*bufix], &ip, sizeof(ip));
	*bufix += sizeof(ip);

	udp.uh_sport = server_port;	
	udp.uh_dport = port;			
	udp.uh_ulen = htons(sizeof(udp) + len);
	memset(&udp.uh_sum, 0, sizeof(udp.uh_sum));

	udp.uh_sum = wrapsum(checksum((unsigned char *)&udp, sizeof(udp), checksum(data, len, checksum((unsigned char *)&ip.ip_src, 2 * sizeof(ip.ip_src), IPPROTO_UDP + (u_int32_t)ntohs(udp.uh_ulen)))));



	memcpy(&buf[*bufix], &udp, sizeof(udp));
	*bufix += sizeof(udp);
}

ssize_t decode_hw_header(struct interface_info *interface, unsigned char *buf, int bufix, struct hardware *from)

{
	struct ether_header eh;
	size_t offset = 0;

	if (interface->hw_address.htype == HTYPE_IPSEC_TUNNEL) {
		u_int32_t ip_len;
		struct ip *ip;

		bufix += ENC_HDRLEN;
		ip_len = (buf[bufix] & 0xf) << 2;
		ip = (struct ip *)(buf + bufix);

		
		if (ip->ip_p != IPPROTO_IPIP)
			return (-1);

		bzero(&eh, sizeof(eh));
		offset = ENC_HDRLEN + ip_len;
	} else {	
		memcpy(&eh, buf + bufix, ETHER_HDR_LEN);
		offset = sizeof(eh);
	}

	memcpy(from->haddr, eh.ether_shost, sizeof(eh.ether_shost));
	from->htype = ARPHRD_ETHER;
	from->hlen = sizeof(eh.ether_shost);

	return (offset);
}

ssize_t decode_udp_ip_header(struct interface_info *interface, unsigned char *buf, int bufix, struct sockaddr_in *from, int buflen)

{
	struct ip *ip;
	struct udphdr *udp;
	unsigned char *data;
	u_int32_t ip_len = (buf[bufix] & 0xf) << 2;
	u_int32_t sum, usum;
	static unsigned int ip_packets_seen;
	static unsigned int ip_packets_bad_checksum;
	static unsigned int udp_packets_seen;
	static unsigned int udp_packets_bad_checksum;
	static unsigned int udp_packets_length_checked;
	static unsigned int udp_packets_length_overflow;
	int len;

	ip = (struct ip *)(buf + bufix);
	udp = (struct udphdr *)(buf + bufix + ip_len);

	
	ip_packets_seen++;
	if (wrapsum(checksum(buf + bufix, ip_len, 0)) != 0) {
		ip_packets_bad_checksum++;
		if (ip_packets_seen > 4 && ip_packets_bad_checksum != 0 && (ip_packets_seen / ip_packets_bad_checksum) < 2) {
			note("%u bad IP checksums seen in %u packets", ip_packets_bad_checksum, ip_packets_seen);
			ip_packets_seen = ip_packets_bad_checksum = 0;
		}
		return (-1);
	}

	if (ntohs(ip->ip_len) != buflen)
		debug("ip length %d disagrees with bytes received %d.", ntohs(ip->ip_len), buflen);

	memcpy(&from->sin_addr, &ip->ip_src, 4);

	
	data = buf + bufix + ip_len + sizeof(*udp);
	len = ntohs(udp->uh_ulen) - sizeof(*udp);
	udp_packets_length_checked++;
	if ((len < 0) || (len + data > buf + bufix + buflen)) {
		udp_packets_length_overflow++;
		if (udp_packets_length_checked > 4 && udp_packets_length_overflow != 0 && (udp_packets_length_checked / udp_packets_length_overflow) < 2) {


			note("%u udp packets in %u too long - dropped", udp_packets_length_overflow, udp_packets_length_checked);

			udp_packets_length_overflow = udp_packets_length_checked = 0;
		}
		return (-1);
	}
	if (len + data != buf + bufix + buflen)
		debug("accepting packet with data after udp payload.");

	usum = udp->uh_sum;
	udp->uh_sum = 0;

	sum = wrapsum(checksum((unsigned char *)udp, sizeof(*udp), checksum(data, len, checksum((unsigned char *)&ip->ip_src, 2 * sizeof(ip->ip_src), IPPROTO_UDP + (u_int32_t)ntohs(udp->uh_ulen)))));



	udp_packets_seen++;
	if (usum && usum != sum) {
		udp_packets_bad_checksum++;
		if (udp_packets_seen > 4 && udp_packets_bad_checksum != 0 && (udp_packets_seen / udp_packets_bad_checksum) < 2) {
			note("%u bad udp checksums in %u packets", udp_packets_bad_checksum, udp_packets_seen);
			udp_packets_seen = udp_packets_bad_checksum = 0;
		}
		return (-1);
	}

	memcpy(&from->sin_port, &udp->uh_sport, sizeof(udp->uh_sport));

	return (ip_len + sizeof(*udp));
}
