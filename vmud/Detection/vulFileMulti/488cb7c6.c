























char *myport;
static io_t device_io;
devops_t devops;

char *proxyhost;
char *proxyport;
char *proxyuser;
char *proxypass;
proxytype_t proxytype;
int autoconnect;

char *scriptinterpreter;
char *scriptextension;

bool node_read_ecdsa_public_key(node_t *n) {
	if(ecdsa_active(&n->ecdsa))
		return true;

	splay_tree_t *config_tree;
	FILE *fp;
	char *pubname = NULL, *hcfname = NULL;
	char *p;
	bool result = false;

	xasprintf(&hcfname, "%s" SLASH "hosts" SLASH "%s", confbase, n->name);

	init_configuration(&config_tree);
	if(!read_config_file(config_tree, hcfname))
		goto exit;

	

	if(get_config_string(lookup_config(config_tree, "ECDSAPublicKey"), &p)) {
		result = ecdsa_set_base64_public_key(&n->ecdsa, p);
		free(p);
		goto exit;
	}

	

	if(!get_config_string(lookup_config(config_tree, "ECDSAPublicKeyFile"), &pubname))
		xasprintf(&pubname, "%s" SLASH "hosts" SLASH "%s", confbase, n->name);

	fp = fopen(pubname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading ECDSA public key file `%s': %s", pubname, strerror(errno));
		goto exit;
	}

	result = ecdsa_read_pem_public_key(&n->ecdsa, fp);
	fclose(fp);

exit:
	exit_configuration(&config_tree);
	free(hcfname);
	free(pubname);
	return result;
}

bool read_ecdsa_public_key(connection_t *c) {
	FILE *fp;
	char *fname;
	char *p;
	bool result;

	

	if(get_config_string(lookup_config(c->config_tree, "ECDSAPublicKey"), &p)) {
		result = ecdsa_set_base64_public_key(&c->ecdsa, p);
		free(p);
		return result;
	}

	

	if(!get_config_string(lookup_config(c->config_tree, "ECDSAPublicKeyFile"), &fname))
		xasprintf(&fname, "%s" SLASH "hosts" SLASH "%s", confbase, c->name);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading ECDSA public key file `%s': %s", fname, strerror(errno));
		free(fname);
		return false;
	}

	result = ecdsa_read_pem_public_key(&c->ecdsa, fp);
	fclose(fp);

	if(!result)
		logger(DEBUG_ALWAYS, LOG_ERR, "Parsing ECDSA public key file `%s' failed.", fname);
	free(fname);
	return result;
}

bool read_rsa_public_key(connection_t *c) {
	FILE *fp;
	char *fname;
	char *n;
	bool result;

	

	if(get_config_string(lookup_config(c->config_tree, "PublicKey"), &n)) {
		result = rsa_set_hex_public_key(&c->rsa, n, "FFFF");
		free(n);
		return result;
	}

	

	if(!get_config_string(lookup_config(c->config_tree, "PublicKeyFile"), &fname))
		xasprintf(&fname, "%s" SLASH "hosts" SLASH "%s", confbase, c->name);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading RSA public key file `%s': %s", fname, strerror(errno));
		free(fname);
		return false;
	}

	result = rsa_read_pem_public_key(&c->rsa, fp);
	fclose(fp);

	if(!result)
		logger(DEBUG_ALWAYS, LOG_ERR, "Reading RSA public key file `%s' failed: %s", fname, strerror(errno));
	free(fname);
	return result;
}

static bool read_ecdsa_private_key(void) {
	FILE *fp;
	char *fname;
	bool result;

	

	if(!get_config_string(lookup_config(config_tree, "ECDSAPrivateKeyFile"), &fname))
		xasprintf(&fname, "%s" SLASH "ecdsa_key.priv", confbase);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading ECDSA private key file `%s': %s", fname, strerror(errno));
		free(fname);
		return false;
	}


	struct stat s;

	if(fstat(fileno(fp), &s)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not stat ECDSA private key file `%s': %s'", fname, strerror(errno));
		free(fname);
		return false;
	}

	if(s.st_mode & ~0100700)
		logger(DEBUG_ALWAYS, LOG_WARNING, "Warning: insecure file permissions for ECDSA private key file `%s'!", fname);


	result = ecdsa_read_pem_private_key(&myself->connection->ecdsa, fp);
	fclose(fp);

	if(!result)
		logger(DEBUG_ALWAYS, LOG_ERR, "Reading ECDSA private key file `%s' failed: %s", fname, strerror(errno));
	free(fname);
	return result;
}

static bool read_rsa_private_key(void) {
	FILE *fp;
	char *fname;
	char *n, *d;
	bool result;

	

	if(get_config_string(lookup_config(config_tree, "PrivateKey"), &d)) {
		if(!get_config_string(lookup_config(config_tree, "PublicKey"), &n)) {
			logger(DEBUG_ALWAYS, LOG_ERR, "PrivateKey used but no PublicKey found!");
			free(d);
			return false;
		}
		result = rsa_set_hex_private_key(&myself->connection->rsa, n, "FFFF", d);
		free(n);
		free(d);
		return result;
	}

	

	if(!get_config_string(lookup_config(config_tree, "PrivateKeyFile"), &fname))
		xasprintf(&fname, "%s" SLASH "rsa_key.priv", confbase);

	fp = fopen(fname, "r");

	if(!fp) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Error reading RSA private key file `%s': %s", fname, strerror(errno));
		free(fname);
		return false;
	}


	struct stat s;

	if(fstat(fileno(fp), &s)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not stat RSA private key file `%s': %s'", fname, strerror(errno));
		free(fname);
		return false;
	}

	if(s.st_mode & ~0100700)
		logger(DEBUG_ALWAYS, LOG_WARNING, "Warning: insecure file permissions for RSA private key file `%s'!", fname);


	result = rsa_read_pem_private_key(&myself->connection->rsa, fp);
	fclose(fp);

	if(!result)
		logger(DEBUG_ALWAYS, LOG_ERR, "Reading RSA private key file `%s' failed: %s", fname, strerror(errno));
	free(fname);
	return result;
}

static timeout_t keyexpire_timeout;

static void keyexpire_handler(void *data) {
	regenerate_key();
	timeout_set(data, &(struct timeval){keylifetime, rand() % 100000});
}

void regenerate_key(void) {
	logger(DEBUG_STATUS, LOG_INFO, "Expiring symmetric keys");
	send_key_changed();
}


void load_all_subnets(void) {
	DIR *dir;
	struct dirent *ent;
	char *dname;

	xasprintf(&dname, "%s" SLASH "hosts", confbase);
	dir = opendir(dname);
	if(!dir) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s", dname, strerror(errno));
		free(dname);
		return;
	}

	while((ent = readdir(dir))) {
		if(!check_id(ent->d_name))
			continue;

		node_t *n = lookup_node(ent->d_name);
		#ifdef _DIRENT_HAVE_D_TYPE
		
		
		#endif

		char *fname;
		xasprintf(&fname, "%s" SLASH "hosts" SLASH "%s", confbase, ent->d_name);

		splay_tree_t *config_tree;
		init_configuration(&config_tree);
		read_config_options(config_tree, ent->d_name);
		read_config_file(config_tree, fname);
		free(fname);

		if(!n) {
			n = new_node();
			n->name = xstrdup(ent->d_name);
			node_add(n);
		}

		for(config_t *cfg = lookup_config(config_tree, "Subnet"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
			subnet_t *s, *s2;

			if(!get_config_subnet(cfg, &s))
				continue;

			if((s2 = lookup_subnet(n, s))) {
				s2->expires = -1;
			} else {
				subnet_add(n, s);
			}
		}

		exit_configuration(&config_tree);
	}

	closedir(dir);
}

void load_all_nodes(void) {
	DIR *dir;
	struct dirent *ent;
	char *dname;

	xasprintf(&dname, "%s" SLASH "hosts", confbase);
	dir = opendir(dname);
	if(!dir) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not open %s: %s", dname, strerror(errno));
		free(dname);
		return;
	}

	while((ent = readdir(dir))) {
		if(!check_id(ent->d_name))
			continue;

		node_t *n = lookup_node(ent->d_name);
		if(n)
			continue;

		n = new_node();
		n->name = xstrdup(ent->d_name);
		node_add(n);
	}

	closedir(dir);
}


char *get_name(void) {
	char *name = NULL;

	get_config_string(lookup_config(config_tree, "Name"), &name);

	if(!name)
		return NULL;

	if(*name == '$') {
		char *envname = getenv(name + 1);
		if(!envname) {
			if(strcmp(name + 1, "HOST")) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Invalid Name: environment variable %s does not exist\n", name + 1);
				return false;
			}
			char envname[32];
			if(gethostname(envname, 32)) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Could not get hostname: %s\n", strerror(errno));
				return false;
			}
			envname[31] = 0;
		}
		free(name);
		name = xstrdup(envname);
		for(char *c = name; *c; c++)
			if(!isalnum(*c))
				*c = '_';
	}

	if(!check_id(name)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Invalid name for myself!");
		free(name);
		return false;
	}

	return name;
}

bool setup_myself_reloadable(void) {
	char *proxy = NULL;
	char *rmode = NULL;
	char *fmode = NULL;
	char *bmode = NULL;
	char *afname = NULL;
	char *space;
	bool choice;

	free(scriptinterpreter);
	scriptinterpreter = NULL;
	get_config_string(lookup_config(config_tree, "ScriptsInterpreter"), &scriptinterpreter);


	free(scriptextension);
	if(!get_config_string(lookup_config(config_tree, "ScriptsExtension"), &scriptextension))

		scriptextension = xstrdup(".bat");

		scriptextension = xstrdup("");


	get_config_string(lookup_config(config_tree, "Proxy"), &proxy);
	if(proxy) {
		if((space = strchr(proxy, ' ')))
			*space++ = 0;

		if(!strcasecmp(proxy, "none")) {
			proxytype = PROXY_NONE;
		} else if(!strcasecmp(proxy, "socks4")) {
			proxytype = PROXY_SOCKS4;
		} else if(!strcasecmp(proxy, "socks4a")) {
			proxytype = PROXY_SOCKS4A;
		} else if(!strcasecmp(proxy, "socks5")) {
			proxytype = PROXY_SOCKS5;
		} else if(!strcasecmp(proxy, "http")) {
			proxytype = PROXY_HTTP;
		} else if(!strcasecmp(proxy, "exec")) {
			proxytype = PROXY_EXEC;
		} else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Unknown proxy type %s!", proxy);
			return false;
		}

		switch(proxytype) {
			case PROXY_NONE:
			default:
				break;

			case PROXY_EXEC:
				if(!space || !*space) {
					logger(DEBUG_ALWAYS, LOG_ERR, "Argument expected for proxy type exec!");
					return false;
				}
				proxyhost =  xstrdup(space);
				break;

			case PROXY_SOCKS4:
			case PROXY_SOCKS4A:
			case PROXY_SOCKS5:
			case PROXY_HTTP:
				proxyhost = space;
				if(space && (space = strchr(space, ' ')))
					*space++ = 0, proxyport = space;
				if(space && (space = strchr(space, ' ')))
					*space++ = 0, proxyuser = space;
				if(space && (space = strchr(space, ' ')))
					*space++ = 0, proxypass = space;
				if(!proxyhost || !*proxyhost || !proxyport || !*proxyport) {
					logger(DEBUG_ALWAYS, LOG_ERR, "Host and port argument expected for proxy!");
					return false;
				}
				proxyhost = xstrdup(proxyhost);
				proxyport = xstrdup(proxyport);
				if(proxyuser && *proxyuser)
					proxyuser = xstrdup(proxyuser);
				if(proxypass && *proxypass)
					proxypass = xstrdup(proxypass);
				break;
		}

		free(proxy);
	}

	if(get_config_bool(lookup_config(config_tree, "IndirectData"), &choice) && choice)
		myself->options |= OPTION_INDIRECT;

	if(get_config_bool(lookup_config(config_tree, "TCPOnly"), &choice) && choice)
		myself->options |= OPTION_TCPONLY;

	if(myself->options & OPTION_TCPONLY)
		myself->options |= OPTION_INDIRECT;

	get_config_bool(lookup_config(config_tree, "DirectOnly"), &directonly);
	get_config_bool(lookup_config(config_tree, "LocalDiscovery"), &localdiscovery);

	if(get_config_string(lookup_config(config_tree, "Mode"), &rmode)) {
		if(!strcasecmp(rmode, "router"))
			routing_mode = RMODE_ROUTER;
		else if(!strcasecmp(rmode, "switch"))
			routing_mode = RMODE_SWITCH;
		else if(!strcasecmp(rmode, "hub"))
			routing_mode = RMODE_HUB;
		else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid routing mode!");
			return false;
		}
		free(rmode);
	}

	if(get_config_string(lookup_config(config_tree, "Forwarding"), &fmode)) {
		if(!strcasecmp(fmode, "off"))
			forwarding_mode = FMODE_OFF;
		else if(!strcasecmp(fmode, "internal"))
			forwarding_mode = FMODE_INTERNAL;
		else if(!strcasecmp(fmode, "kernel"))
			forwarding_mode = FMODE_KERNEL;
		else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid forwarding mode!");
			return false;
		}
		free(fmode);
	}

	choice = true;
	get_config_bool(lookup_config(config_tree, "PMTUDiscovery"), &choice);
	if(choice)
		myself->options |= OPTION_PMTU_DISCOVERY;

	choice = true;
	get_config_bool(lookup_config(config_tree, "ClampMSS"), &choice);
	if(choice)
		myself->options |= OPTION_CLAMP_MSS;

	get_config_bool(lookup_config(config_tree, "PriorityInheritance"), &priorityinheritance);
	get_config_bool(lookup_config(config_tree, "DecrementTTL"), &decrement_ttl);
	if(get_config_string(lookup_config(config_tree, "Broadcast"), &bmode)) {
		if(!strcasecmp(bmode, "no"))
			broadcast_mode = BMODE_NONE;
		else if(!strcasecmp(bmode, "yes") || !strcasecmp(bmode, "mst"))
			broadcast_mode = BMODE_MST;
		else if(!strcasecmp(bmode, "direct"))
			broadcast_mode = BMODE_DIRECT;
		else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid broadcast mode!");
			return false;
		}
		free(bmode);
	}


	if(priorityinheritance)
		logger(DEBUG_ALWAYS, LOG_WARNING, "%s not supported on this platform", "PriorityInheritance");


	if(!get_config_int(lookup_config(config_tree, "MACExpire"), &macexpire))
		macexpire = 600;

	if(get_config_int(lookup_config(config_tree, "MaxTimeout"), &maxtimeout)) {
		if(maxtimeout <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Bogus maximum timeout!");
			return false;
		}
	} else maxtimeout = 900;

	if(get_config_string(lookup_config(config_tree, "AddressFamily"), &afname)) {
		if(!strcasecmp(afname, "IPv4"))
			addressfamily = AF_INET;
		else if(!strcasecmp(afname, "IPv6"))
			addressfamily = AF_INET6;
		else if(!strcasecmp(afname, "any"))
			addressfamily = AF_UNSPEC;
		else {
			logger(DEBUG_ALWAYS, LOG_ERR, "Invalid address family!");
			return false;
		}
		free(afname);
	}

	get_config_bool(lookup_config(config_tree, "Hostnames"), &hostnames);

	if(!get_config_int(lookup_config(config_tree, "KeyExpire"), &keylifetime))
		keylifetime = 3600;

	get_config_int(lookup_config(config_tree, "AutoConnect"), &autoconnect);

	return true;
}


static bool setup_myself(void) {
	char *name, *hostname, *cipher, *digest, *type;
	char *fname = NULL;
	char *address = NULL;

	if(!(name = get_name())) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Name for tinc daemon required!");
		return false;
	}

	myself = new_node();
	myself->connection = new_connection();
	myself->name = name;
	myself->connection->name = xstrdup(name);
	xasprintf(&fname, "%s" SLASH "hosts" SLASH "%s", confbase, name);
	read_config_options(config_tree, name);
	read_config_file(config_tree, fname);
	free(fname);

	if(!get_config_string(lookup_config(config_tree, "Port"), &myport))
		myport = xstrdup("655");

	xasprintf(&myself->hostname, "MYSELF port %s", myport);
	myself->connection->hostname = xstrdup(myself->hostname);

	myself->connection->options = 0;
	myself->connection->protocol_major = PROT_MAJOR;
	myself->connection->protocol_minor = PROT_MINOR;

	myself->options |= PROT_MINOR << 24;

	get_config_bool(lookup_config(config_tree, "ExperimentalProtocol"), &experimental);

	if(experimental && !read_ecdsa_private_key())
		return false;

	if(!read_rsa_private_key())
		return false;

	if(!atoi(myport)) {
		struct addrinfo *ai = str2addrinfo("localhost", myport, SOCK_DGRAM);
		sockaddr_t sa;
		if(!ai || !ai->ai_addr)
			return false;
		free(myport);
		memcpy(&sa, ai->ai_addr, ai->ai_addrlen);
		sockaddr2str(&sa, NULL, &myport);
	}

	

	for(config_t *cfg = lookup_config(config_tree, "Subnet"); cfg; cfg = lookup_config_next(config_tree, cfg)) {
		subnet_t *subnet;

		if(!get_config_subnet(cfg, &subnet))
			return false;

		subnet_add(myself, subnet);
	}

	

	if(!setup_myself_reloadable())
		return false;

	get_config_bool(lookup_config(config_tree, "StrictSubnets"), &strictsubnets);
	get_config_bool(lookup_config(config_tree, "TunnelServer"), &tunnelserver);
	strictsubnets |= tunnelserver;



	if(get_config_int(lookup_config(config_tree, "UDPRcvBuf"), &udp_rcvbuf)) {
		if(udp_rcvbuf <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "UDPRcvBuf cannot be negative!");
			return false;
		}
	}

	if(get_config_int(lookup_config(config_tree, "UDPSndBuf"), &udp_sndbuf)) {
		if(udp_sndbuf <= 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "UDPSndBuf cannot be negative!");
			return false;
		}
	}

	int replaywin_int;
	if(get_config_int(lookup_config(config_tree, "ReplayWindow"), &replaywin_int)) {
		if(replaywin_int < 0) {
			logger(DEBUG_ALWAYS, LOG_ERR, "ReplayWindow cannot be negative!");
			return false;
		}
		replaywin = (unsigned)replaywin_int;
		sptps_replaywin = replaywin;
	}

	

	if(!get_config_string(lookup_config(config_tree, "Cipher"), &cipher))
		cipher = xstrdup("blowfish");

	if(!cipher_open_by_name(&myself->incipher, cipher)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unrecognized cipher type!");
		return false;
	}

	free(cipher);

	send_key_changed();
	timeout_add(&keyexpire_timeout, keyexpire_handler, &keyexpire_timeout, &(struct timeval){keylifetime, rand() % 100000});

	

	int maclength = 4;
	get_config_int(lookup_config(config_tree, "MACLength"), &maclength);

	if(maclength < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Bogus MAC length!");
		return false;
	}

	if(!get_config_string(lookup_config(config_tree, "Digest"), &digest))
		digest = xstrdup("sha1");

	if(!digest_open_by_name(&myself->indigest, digest, maclength)) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unrecognized digest type!");
		return false;
	}

	free(digest);

	

	if(get_config_int(lookup_config(config_tree, "Compression"), &myself->incompression)) {
		if(myself->incompression < 0 || myself->incompression > 11) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Bogus compression level!");
			return false;
		}
	} else myself->incompression = 0;

	myself->connection->outcompression = 0;

	

	myself->nexthop = myself;
	myself->via = myself;
	myself->status.reachable = true;
	myself->last_state_change = now.tv_sec;
	myself->status.sptps = experimental;
	node_add(myself);

	graph();

	if(strictsubnets)
		load_all_subnets();
	else if(autoconnect)
		load_all_nodes();

	

	devops = os_devops;

	if(get_config_string(lookup_config(config_tree, "DeviceType"), &type)) {
		if(!strcasecmp(type, "dummy"))
			devops = dummy_devops;
		else if(!strcasecmp(type, "raw_socket"))
			devops = raw_socket_devops;
		else if(!strcasecmp(type, "multicast"))
			devops = multicast_devops;

		else if(!strcasecmp(type, "uml"))
			devops = uml_devops;


		else if(!strcasecmp(type, "vde"))
			devops = vde_devops;

	}

	if(!devops.setup())
		return false;

	if(device_fd >= 0)
		io_add(&device_io, handle_device_data, NULL, device_fd, IO_READ);

	
	char *envp[5];
	xasprintf(&envp[0], "NETNAME=%s", netname ? : "");
	xasprintf(&envp[1], "DEVICE=%s", device ? : "");
	xasprintf(&envp[2], "INTERFACE=%s", iface ? : "");
	xasprintf(&envp[3], "NAME=%s", myself->name);
	envp[4] = NULL;

	execute_script("tinc-up", envp);

	for(int i = 0; i < 4; i++)
		free(envp[i]);

	

	subnet_update(myself, NULL, true);

	


	int unix_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if(unix_fd < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not create UNIX socket: %s", sockstrerror(errno));
		return false;
	}

	struct sockaddr_un sa;
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, unixsocketname, sizeof sa.sun_path);

	if(connect(unix_fd, (struct sockaddr *)&sa, sizeof sa) >= 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "UNIX socket %s is still in use!", unixsocketname);
		return false;
	}

	unlink(unixsocketname);

	if(bind(unix_fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not bind UNIX socket to %s: %s", unixsocketname, sockstrerror(errno));
		return false;
	}

	if(listen(unix_fd, 3) < 0) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Could not listen on UNIX socket %s: %s", unixsocketname, sockstrerror(errno));
		return false;
	}

	io_add(&unix_socket, handle_new_unix_connection, &unix_socket, unix_fd, IO_READ);


	if(!do_detach && getenv("LISTEN_FDS")) {
		sockaddr_t sa;
		socklen_t salen;

		listen_sockets = atoi(getenv("LISTEN_FDS"));

		unsetenv("LISTEN_FDS");


		if(listen_sockets > MAXSOCKETS) {
			logger(DEBUG_ALWAYS, LOG_ERR, "Too many listening sockets");
			return false;
		}

		for(int i = 0; i < listen_sockets; i++) {
			salen = sizeof sa;
			if(getsockname(i + 3, &sa.sa, &salen) < 0) {
				logger(DEBUG_ALWAYS, LOG_ERR, "Could not get address of listen fd %d: %s", i + 3, sockstrerror(errno));
				return false;
			}


			fcntl(i + 3, F_SETFD, FD_CLOEXEC);


			int udp_fd = setup_vpn_in_socket(&sa);
			if(udp_fd < 0)
				return false;

			io_add(&listen_socket[i].tcp, (io_cb_t)handle_new_meta_connection, &listen_socket[i], i + 3, IO_READ);
			io_add(&listen_socket[i].udp, (io_cb_t)handle_incoming_vpn_data, &listen_socket[i], udp_fd, IO_READ);

			if(debug_level >= DEBUG_CONNECTIONS) {
				hostname = sockaddr2hostname(&sa);
				logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Listening on %s", hostname);
				free(hostname);
			}

			memcpy(&listen_socket[i].sa, &sa, salen);
		}
	} else {
		listen_sockets = 0;
		config_t *cfg = lookup_config(config_tree, "BindToAddress");

		do {
			get_config_string(cfg, &address);
			if(cfg)
				cfg = lookup_config_next(config_tree, cfg);

			char *port = myport;

			if(address) {
				char *space = strchr(address, ' ');
				if(space) {
					*space++ = 0;
					port = space;
				}

				if(!strcmp(address, "*"))
					*address = 0;
			}

			struct addrinfo *ai, hint = {0};
			hint.ai_family = addressfamily;
			hint.ai_socktype = SOCK_STREAM;
			hint.ai_protocol = IPPROTO_TCP;
			hint.ai_flags = AI_PASSIVE;

			int err = getaddrinfo(address && *address ? address : NULL, port, &hint, &ai);
			free(address);

			if(err || !ai) {
				logger(DEBUG_ALWAYS, LOG_ERR, "System call `%s' failed: %s", "getaddrinfo", gai_strerror(err));
				return false;
			}

			for(struct addrinfo *aip = ai; aip; aip = aip->ai_next) {
				if(listen_sockets >= MAXSOCKETS) {
					logger(DEBUG_ALWAYS, LOG_ERR, "Too many listening sockets");
					return false;
				}

				int tcp_fd = setup_listen_socket((sockaddr_t *) aip->ai_addr);

				if(tcp_fd < 0)
					continue;

				int udp_fd = setup_vpn_in_socket((sockaddr_t *) aip->ai_addr);

				if(tcp_fd < 0) {
					close(tcp_fd);
					continue;
				}

				io_add(&listen_socket[listen_sockets].tcp, handle_new_meta_connection, &listen_socket[listen_sockets], tcp_fd, IO_READ);
				io_add(&listen_socket[listen_sockets].udp, handle_incoming_vpn_data, &listen_socket[listen_sockets], udp_fd, IO_READ);

				if(debug_level >= DEBUG_CONNECTIONS) {
					hostname = sockaddr2hostname((sockaddr_t *) aip->ai_addr);
					logger(DEBUG_CONNECTIONS, LOG_NOTICE, "Listening on %s", hostname);
					free(hostname);
				}

				memcpy(&listen_socket[listen_sockets].sa, aip->ai_addr, aip->ai_addrlen);
				listen_sockets++;
			}

			freeaddrinfo(ai);
		} while(cfg);
	}

	if(listen_sockets)
		logger(DEBUG_ALWAYS, LOG_NOTICE, "Ready");
	else {
		logger(DEBUG_ALWAYS, LOG_ERR, "Unable to create any listening socket!");
		return false;
	}

	last_config_check = now.tv_sec;

	return true;
}


bool setup_network(void) {
	init_connections();
	init_subnets();
	init_nodes();
	init_edges();
	init_requests();

	if(get_config_int(lookup_config(config_tree, "PingInterval"), &pinginterval)) {
		if(pinginterval < 1) {
			pinginterval = 86400;
		}
	} else pinginterval = 60;

	if(!get_config_int(lookup_config(config_tree, "PingTimeout"), &pingtimeout))
		pingtimeout = 5;
	if(pingtimeout < 1 || pingtimeout > pinginterval)
		pingtimeout = pinginterval;

	if(!get_config_int(lookup_config(config_tree, "MaxOutputBufferSize"), &maxoutbufsize))
		maxoutbufsize = 10 * MTU;

	if(!setup_myself())
		return false;

	return true;
}


void close_network_connections(void) {
	for(list_node_t *node = connection_list->head, *next; node; node = next) {
		next = node->next;
		connection_t *c = node->data;
		
		if(c->status.control)
			c->socket = -1;
		c->outgoing = NULL;
		terminate_connection(c, false);
	}

	list_delete_list(outgoing_list);

	if(myself && myself->connection) {
		subnet_update(myself, NULL, false);
		terminate_connection(myself->connection, false);
		free_connection(myself->connection);
	}

	for(int i = 0; i < listen_sockets; i++) {
		io_del(&listen_socket[i].tcp);
		io_del(&listen_socket[i].udp);
		close(listen_socket[i].tcp.fd);
		close(listen_socket[i].udp.fd);
	}


	io_del(&unix_socket);
	close(unix_socket.fd);


	char *envp[5];
	xasprintf(&envp[0], "NETNAME=%s", netname ? : "");
	xasprintf(&envp[1], "DEVICE=%s", device ? : "");
	xasprintf(&envp[2], "INTERFACE=%s", iface ? : "");
	xasprintf(&envp[3], "NAME=%s", myself->name);
	envp[4] = NULL;

	exit_requests();
	exit_edges();
	exit_subnets();
	exit_nodes();
	exit_connections();

	execute_script("tinc-down", envp);

	if(myport) free(myport);

	for(int i = 0; i < 4; i++)
		free(envp[i]);

	devops.close();

	return;
}
