











size_t pex_send(FILE * sock, unsigned int rcpt, size_t size, char * blob) {
	assert(size <= MAX_PACKET_SIZE);
	pex_header_t * broadcast = malloc(sizeof(pex_header_t) + size);
	broadcast->target = rcpt;
	memcpy(broadcast->data, blob, size);
	size_t out = write(fileno(sock), broadcast, sizeof(pex_header_t) + size);
	free(broadcast);
	return out;
}

size_t pex_broadcast(FILE * sock, size_t size, char * blob) {
	return pex_send(sock, 0, size, blob);
}

size_t pex_listen(FILE * sock, pex_packet_t * packet) {
	return read(fileno(sock), packet, PACKET_SIZE);
}

size_t pex_reply(FILE * sock, size_t size, char * blob) {
	return write(fileno(sock), blob, size);
}

size_t pex_recv(FILE * sock, char * blob) {
	memset(blob, 0, MAX_PACKET_SIZE);
	return read(fileno(sock), blob, MAX_PACKET_SIZE);
}

FILE * pex_connect(char * target) {
	char tmp[100];
	sprintf(tmp, "/dev/pex/%s", target);
	FILE * out = fopen(tmp, "r+");
	if (out) {
		setbuf(out, NULL);
	}
	return out;
}

FILE * pex_bind(char * target) {
	char tmp[100];
	sprintf(tmp, "/dev/pex/%s", target);
	FILE * out = fopen(tmp, "a+");
	if (out) {
		setbuf(out, NULL);
	}
	return out;
}

size_t pex_query(FILE * sock) {
	return ioctl(fileno(sock), IOCTL_PACKETFS_QUEUED, NULL);
}
