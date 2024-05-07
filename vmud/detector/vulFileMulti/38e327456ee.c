










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

void assemble_eh_header(struct ether_header *eh)
{
	memset(eh->ether_dhost, 0xff, sizeof(eh->ether_dhost));

	memcpy(eh->ether_shost, ifi->hw_address.ether_addr_octet, sizeof(eh->ether_shost));

	eh->ether_type = htons(ETHERTYPE_IP);
}

ssize_t decode_hw_header(unsigned char *buf, int bufix, struct ether_addr *from)
{
	struct ether_header eh;

	memcpy(&eh, buf + bufix, ETHER_HDR_LEN);

	memcpy(from->ether_addr_octet, eh.ether_shost, ETHER_ADDR_LEN);

	return (sizeof(eh));
}

ssize_t decode_udp_ip_header(unsigned char *buf, int bufix, struct sockaddr_in *from, int buflen)

{
	struct ip *ip;
	struct udphdr *udp;
	unsigned char *data;
	u_int32_t ip_len = (buf[bufix] & 0xf) << 2;
	u_int32_t sum, usum;
	static int ip_packets_seen;
	static int ip_packets_bad_checksum;
	static int udp_packets_seen;
	static int udp_packets_bad_checksum;
	static int udp_packets_length_checked;
	static int udp_packets_length_overflow;
	int len;

	ip = (struct ip *)(buf + bufix);
	udp = (struct udphdr *)(buf + bufix + ip_len);

	
	ip_packets_seen++;
	if (wrapsum(checksum(buf + bufix, ip_len, 0)) != 0) {
		ip_packets_bad_checksum++;
		if (ip_packets_seen > 4 && ip_packets_bad_checksum != 0 && (ip_packets_seen / ip_packets_bad_checksum) < 2) {
			note("%d bad IP checksums seen in %d packets", ip_packets_bad_checksum, ip_packets_seen);
			ip_packets_seen = ip_packets_bad_checksum = 0;
		}
		return (-1);
	}


	if (ntohs(ip->ip_len) != buflen)
		debug("ip length %hu disagrees with bytes received %d.", ntohs(ip->ip_len), buflen);


	memcpy(&from->sin_addr, &ip->ip_src, sizeof(from->sin_addr));

	
	data = buf + bufix + ip_len + sizeof(*udp);
	len = ntohs(udp->uh_ulen) - sizeof(*udp);
	udp_packets_length_checked++;
	if ((len < 0) || (len + data > buf + bufix + buflen)) {
		udp_packets_length_overflow++;
		if (udp_packets_length_checked > 4 && udp_packets_length_overflow != 0 && (udp_packets_length_checked / udp_packets_length_overflow) < 2) {


			note("%d udp packets in %d too long - dropped", udp_packets_length_overflow, udp_packets_length_checked);

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
			note("%d bad udp checksums in %d packets", udp_packets_bad_checksum, udp_packets_seen);
			udp_packets_seen = udp_packets_bad_checksum = 0;
		}
		return (-1);
	}

	memcpy(&from->sin_port, &udp->uh_sport, sizeof(udp->uh_sport));

	return (ip_len + sizeof(*udp));
}
