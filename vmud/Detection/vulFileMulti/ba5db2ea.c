
























static bool send_proxyrequest(connection_t *c) {
	switch(proxytype) {
		case PROXY_HTTP: {
			char *host;
			char *port;

			sockaddr2str(&c->address, &host, &port);
			send_request(c, "CONNECT %s:%s HTTP/1.1\r\n\r", host, port);
			free(host);
			free(port);
			return true;
		}
		case PROXY_SOCKS4: {
			if(c->address.sa.sa_family != AF_INET) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Cannot connect to an IPv6 host through a SOCKS 4 proxy!");
				return false;
			}
			char s4req[9 + (proxyuser ? strlen(proxyuser) : 0)];
			s4req[0] = 4;
			s4req[1] = 1;
			memcpy(s4req + 2, &c->address.in.sin_port, 2);
			memcpy(s4req + 4, &c->address.in.sin_addr, 4);
			if(proxyuser)
				memcpy(s4req + 8, proxyuser, strlen(proxyuser));
			s4req[sizeof s4req - 1] = 0;
			c->tcplen = 8;
			return send_meta(c, s4req, sizeof s4req);
		}
		case PROXY_SOCKS5: {
			int len = 3 + 6 + (c->address.sa.sa_family == AF_INET ? 4 : 16);
			c->tcplen = 2;
			if(proxypass)
				len += 3 + strlen(proxyuser) + strlen(proxypass);
			char s5req[len];
			int i = 0;
			s5req[i++] = 5;
			s5req[i++] = 1;
			if(proxypass) {
				s5req[i++] = 2;
				s5req[i++] = 1;
				s5req[i++] = strlen(proxyuser);
				memcpy(s5req + i, proxyuser, strlen(proxyuser));
				i += strlen(proxyuser);
				s5req[i++] = strlen(proxypass);
				memcpy(s5req + i, proxypass, strlen(proxypass));
				i += strlen(proxypass);
				c->tcplen += 2;
			} else {
				s5req[i++] = 0;
			}
			s5req[i++] = 5;
			s5req[i++] = 1;
			s5req[i++] = 0;
			if(c->address.sa.sa_family == AF_INET) {
				s5req[i++] = 1;
				memcpy(s5req + i, &c->address.in.sin_addr, 4);
				i += 4;
				memcpy(s5req + i, &c->address.in.sin_port, 2);
				i += 2;
				c->tcplen += 10;
			} else if(c->address.sa.sa_family == AF_INET6) {
				s5req[i++] = 3;
				memcpy(s5req + i, &c->address.in6.sin6_addr, 16);
				i += 16;
				memcpy(s5req + i, &c->address.in6.sin6_port, 2);
				i += 2;
				c->tcplen += 22;
			} else {
				logger(DEBUG_ALWAYS, LOG_ERR, "Address family %hx not supported for SOCKS 5 proxies!", c->address.sa.sa_family);
				return false;
			}
			if(i > len)
				abort();
			return send_meta(c, s5req, sizeof s5req);
		}
		case PROXY_SOCKS4A:
			logger(DEBUG_ALWAYS, LOG_ERR, "Proxy type not implemented yet");
			return false;
		case PROXY_EXEC:
			return true;
		default:
			logger(DEBUG_ALWAYS, LOG_ERR, "Unknown proxy type");
			return false;
	}
}

bool send_id(connection_t *c) {
	gettimeofday(&c->start, NULL);

	int minor = 0;

	if(experimental) {
		if(c->config_tree && !read_ecdsa_public_key(c))
			minor = 1;
		else minor = myself->connection->protocol_minor;
	}

	if(proxytype && c->outgoing)
		if(!send_proxyrequest(c))
			return false;

	return send_request(c, "%d %s %d.%d", ID, myself->connection->name, myself->connection->protocol_major, minor);
}

bool id_h(connection_t *c, const char *request) {
	char name[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING " %d.%d", name, &c->protocol_major, &c->protocol_minor) < 2) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ID", c->name, c->hostname);
		return false;
	}

	

	if(name[0] == '^' && !strcmp(name + 1, controlcookie)) {
		c->status.control = true;
		c->allow_request = CONTROL;
		c->last_ping_time = now.tv_sec + 3600;

		free(c->name);
		c->name = xstrdup("<control>");

		return send_request(c, "%d %d %d", ACK, TINC_CTL_VERSION_CURRENT, getpid());
	}

	

	if(!check_id(name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s): %s", "ID", c->name, c->hostname, "invalid name");
		return false;
	}

	

	if(c->outgoing) {
		if(strcmp(c->name, name)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s is %s instead of %s", c->hostname, name, c->name);
			return false;
		}
	} else {
		if(c->name)
			free(c->name);
		c->name = xstrdup(name);
	}

	

	if(c->protocol_major != myself->connection->protocol_major) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s (%s) uses incompatible version %d.%d", c->name, c->hostname, c->protocol_major, c->protocol_minor);
		return false;
	}

	if(bypass_security) {
		if(!c->config_tree)
			init_configuration(&c->config_tree);
		c->allow_request = ACK;
		return send_ack(c);
	}

	if(!experimental)
		c->protocol_minor = 0;

	if(!c->config_tree) {
		init_configuration(&c->config_tree);

		if(!read_host_config(c->config_tree, c->name)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Peer %s had unknown identity (%s)", c->hostname, c->name);
			return false;
		}

		if(experimental && c->protocol_minor >= 2) {
			if(!read_ecdsa_public_key(c))
				return false;
		}
	} else {
		if(c->protocol_minor && !ecdsa_active(&c->ecdsa))
			c->protocol_minor = 1;
	}

	c->allow_request = METAKEY;

	if(c->protocol_minor >= 2) {
		c->allow_request = ACK;
		char label[25 + strlen(myself->name) + strlen(c->name)];

		if(c->outgoing)
			snprintf(label, sizeof label, "tinc TCP key expansion %s %s", myself->name, c->name);
		else snprintf(label, sizeof label, "tinc TCP key expansion %s %s", c->name, myself->name);

		return sptps_start(&c->sptps, c, c->outgoing, false, myself->connection->ecdsa, c->ecdsa, label, sizeof label, send_meta_sptps, receive_meta_sptps);
	} else {
		return send_metakey(c);
	}
}

bool send_metakey(connection_t *c) {
	if(!read_rsa_public_key(c))
		return false;

	if(!cipher_open_blowfish_ofb(&c->outcipher))
		return false;

	if(!digest_open_sha1(&c->outdigest, -1))
		return false;

	size_t len = rsa_size(&c->rsa);
	char key[len];
	char enckey[len];
	char hexkey[2 * len + 1];

	

	randomize(key, len);

	

	key[0] &= 0x7F;

	cipher_set_key_from_rsa(&c->outcipher, key, len, true);

	if(debug_level >= DEBUG_SCARY_THINGS) {
		bin2hex(key, hexkey, len);
		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, "Generated random meta key (unencrypted): %s", hexkey);
	}

	

	if(!rsa_public_encrypt(&c->rsa, key, len, enckey)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error during encryption of meta key for %s (%s)", c->name, c->hostname);
		return false;
	}

	

	bin2hex(enckey, hexkey, len);

	

	bool result = send_request(c, "%d %d %d %d %d %s", METAKEY, cipher_get_nid(&c->outcipher), digest_get_nid(&c->outdigest), c->outmaclength, c->outcompression, hexkey);



	c->status.encryptout = true;
	return result;
}

bool metakey_h(connection_t *c, const char *request) {
	char hexkey[MAX_STRING_SIZE];
	int cipher, digest, maclength, compression;
	size_t len = rsa_size(&myself->connection->rsa);
	char enckey[len];
	char key[len];

	if(sscanf(request, "%*d %d %d %d %d " MAX_STRING, &cipher, &digest, &maclength, &compression, hexkey) != 5) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "METAKEY", c->name, c->hostname);
		return false;
	}

	

	int inlen = hex2bin(hexkey, enckey, sizeof enckey);

	

	if(inlen != len) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong keylength");
		return false;
	}

	

	if(!rsa_private_decrypt(&myself->connection->rsa, enckey, len, key)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error during decryption of meta key for %s (%s)", c->name, c->hostname);
		return false;
	}

	if(debug_level >= DEBUG_SCARY_THINGS) {
		bin2hex(key, hexkey, len);
		logger(DEBUG_SCARY_THINGS, LOG_DEBUG, "Received random meta key (unencrypted): %s", hexkey);
	}

	

	if(!cipher_open_by_nid(&c->incipher, cipher) || !cipher_set_key_from_rsa(&c->incipher, key, len, false)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error during initialisation of cipher from %s (%s)", c->name, c->hostname);
		return false;
	}

	if(!digest_open_by_nid(&c->indigest, digest, -1)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error during initialisation of digest from %s (%s)", c->name, c->hostname);
		return false;
	}

	c->status.decryptin = true;

	c->allow_request = CHALLENGE;

	return send_challenge(c);
}

bool send_challenge(connection_t *c) {
	size_t len = rsa_size(&c->rsa);
	char buffer[len * 2 + 1];

	if(!c->hischallenge)
		c->hischallenge = xrealloc(c->hischallenge, len);

	

	randomize(c->hischallenge, len);

	

	bin2hex(c->hischallenge, buffer, len);

	

	return send_request(c, "%d %s", CHALLENGE, buffer);
}

bool challenge_h(connection_t *c, const char *request) {
	char buffer[MAX_STRING_SIZE];
	size_t len = rsa_size(&myself->connection->rsa);
	size_t digestlen = digest_length(&c->indigest);
	char digest[digestlen];

	if(sscanf(request, "%*d " MAX_STRING, buffer) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "CHALLENGE", c->name, c->hostname);
		return false;
	}

	

	int inlen = hex2bin(buffer, buffer, sizeof buffer);

	

	if(inlen != len) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong challenge length");
		return false;
	}

	c->allow_request = CHAL_REPLY;

	

	digest_create(&c->indigest, buffer, len, digest);

	

	bin2hex(digest, buffer, digestlen);

	

	return send_request(c, "%d %s", CHAL_REPLY, buffer);
}

bool chal_reply_h(connection_t *c, const char *request) {
	char hishash[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING, hishash) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "CHAL_REPLY", c->name, c->hostname);
		return false;
	}

	

	int inlen = hex2bin(hishash, hishash, sizeof hishash);

	

	if(inlen != digest_length(&c->outdigest)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong challenge reply length");
		return false;
	}


	

	if(!digest_verify(&c->outdigest, c->hischallenge, rsa_size(&c->rsa), hishash)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Possible intruder %s (%s): %s", c->name, c->hostname, "wrong challenge reply");
		return false;
	}

	

	free(c->hischallenge);
	c->hischallenge = NULL;
	c->allow_request = ACK;

	return send_ack(c);
}

static bool send_upgrade(connection_t *c) {
	

	char *pubkey = ecdsa_get_base64_public_key(&myself->connection->ecdsa);

	if(!pubkey)
		return false;

	bool result = send_request(c, "%d %s", ACK, pubkey);
	free(pubkey);
	return result;
}

bool send_ack(connection_t *c) {
	if(c->protocol_minor == 1)
		return send_upgrade(c);

	

	struct timeval now;
	bool choice;

	

	gettimeofday(&now, NULL);
	c->estimated_weight = (now.tv_sec - c->start.tv_sec) * 1000 + (now.tv_usec - c->start.tv_usec) / 1000;

	

	if((get_config_bool(lookup_config(c->config_tree, "IndirectData"), &choice) && choice) || myself->options & OPTION_INDIRECT)
		c->options |= OPTION_INDIRECT;

	if((get_config_bool(lookup_config(c->config_tree, "TCPOnly"), &choice) && choice) || myself->options & OPTION_TCPONLY)
		c->options |= OPTION_TCPONLY | OPTION_INDIRECT;

	if(myself->options & OPTION_PMTU_DISCOVERY)
		c->options |= OPTION_PMTU_DISCOVERY;

	choice = myself->options & OPTION_CLAMP_MSS;
	get_config_bool(lookup_config(c->config_tree, "ClampMSS"), &choice);
	if(choice)
		c->options |= OPTION_CLAMP_MSS;

	get_config_int(lookup_config(c->config_tree, "Weight"), &c->estimated_weight);

	return send_request(c, "%d %s %d %x", ACK, myport, c->estimated_weight, (c->options & 0xffffff) | (experimental ? (PROT_MINOR << 24) : 0));
}

static void send_everything(connection_t *c) {
	

	if(tunnelserver) {
		for splay_each(subnet_t, s, myself->subnet_tree)
			send_add_subnet(c, s);

		return;
	}

	for splay_each(node_t, n, node_tree) {
		for splay_each(subnet_t, s, n->subnet_tree)
			send_add_subnet(c, s);

		for splay_each(edge_t, e, n->edge_tree)
			send_add_edge(c, e);
	}
}

static bool upgrade_h(connection_t *c, const char *request) {
	char pubkey[MAX_STRING_SIZE];

	if(sscanf(request, "%*d " MAX_STRING, pubkey) != 1) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ACK", c->name, c->hostname);
		return false;
	}

	if(ecdsa_active(&c->ecdsa) || read_ecdsa_public_key(c)) {
		logger(DEBUG_ALWAYS, LOG_INFO, "Already have ECDSA public key from %s (%s), not upgrading.", c->name, c->hostname);
		return false;
	}

	logger(DEBUG_ALWAYS, LOG_INFO, "Got ECDSA public key from %s (%s), upgrading!", c->name, c->hostname);
	append_config_file(c->name, "ECDSAPublicKey", pubkey);
	c->allow_request = TERMREQ;
	return send_termreq(c);
}

bool ack_h(connection_t *c, const char *request) {
	if(c->protocol_minor == 1)
		return upgrade_h(c, request);

	char hisport[MAX_STRING_SIZE];
	char *hisaddress;
	int weight, mtu;
	uint32_t options;
	node_t *n;
	bool choice;

	if(sscanf(request, "%*d " MAX_STRING " %d %x", hisport, &weight, &options) != 3) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Got bad %s from %s (%s)", "ACK", c->name, c->hostname);
		return false;
	}

	

	n = lookup_node(c->name);

	if(!n) {
		n = new_node();
		n->name = xstrdup(c->name);
		node_add(n);
	} else {
		if(n->connection) {
			
			logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Established a second connection with %s (%s), closing old connection", n->connection->name, n->connection->hostname);

			if(n->connection->outgoing) {
				if(c->outgoing)
					logger(DEBUG_ALWAYS, LOG_WARNING, "Two outgoing connections to the same node!");
				else c->outgoing = n->connection->outgoing;

				n->connection->outgoing = NULL;
			}

			terminate_connection(n->connection, false);
			
			graph();
		}
	}

	n->connection = c;
	c->node = n;
	if(!(c->options & options & OPTION_PMTU_DISCOVERY)) {
		c->options &= ~OPTION_PMTU_DISCOVERY;
		options &= ~OPTION_PMTU_DISCOVERY;
	}
	c->options |= options;

	if(get_config_int(lookup_config(c->config_tree, "PMTU"), &mtu) && mtu < n->mtu)
		n->mtu = mtu;

	if(get_config_int(lookup_config(config_tree, "PMTU"), &mtu) && mtu < n->mtu)
		n->mtu = mtu;

	if(get_config_bool(lookup_config(c->config_tree, "ClampMSS"), &choice)) {
		if(choice)
			c->options |= OPTION_CLAMP_MSS;
		else c->options &= ~OPTION_CLAMP_MSS;
	}

	

	c->allow_request = ALL;
	c->status.active = true;

	logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Connection with %s (%s) activated", c->name, c->hostname);

	

	send_everything(c);

	

	c->edge = new_edge();
	c->edge->from = myself;
	c->edge->to = n;
	sockaddr2str(&c->address, &hisaddress, NULL);
	c->edge->address = str2sockaddr(hisaddress, hisport);
	free(hisaddress);
	c->edge->weight = (weight + c->estimated_weight) / 2;
	c->edge->connection = c;
	c->edge->options = c->options;

	edge_add(c->edge);

	

	if(tunnelserver)
		send_add_edge(c, c->edge);
	else send_add_edge(everyone, c->edge);

	

	graph();

	return true;
}
