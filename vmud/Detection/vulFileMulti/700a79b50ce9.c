



__RCSID("$FreeBSD$");

















































typedef enum {
	oBadOption, oHost, oMatch, oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout, oGatewayPorts, oExitOnForwardFailure, oPasswordAuthentication, oRSAAuthentication, oChallengeResponseAuthentication, oXAuthLocation, oIdentityFile, oHostName, oPort, oCipher, oRemoteForward, oLocalForward, oUser, oEscapeChar, oRhostsRSAAuthentication, oProxyCommand, oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts, oBatchMode, oCheckHostIP, oStrictHostKeyChecking, oCompression, oCompressionLevel, oTCPKeepAlive, oNumberOfPasswordPrompts, oUsePrivilegedPort, oLogLevel, oCiphers, oProtocol, oMacs, oGlobalKnownHostsFile2, oUserKnownHostsFile2, oPubkeyAuthentication, oKbdInteractiveAuthentication, oKbdInteractiveDevices, oHostKeyAlias, oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication, oHostKeyAlgorithms, oBindAddress, oPKCS11Provider, oClearAllForwardings, oNoHostAuthenticationForLocalhost, oEnableSSHKeysign, oRekeyLimit, oVerifyHostKeyDNS, oConnectTimeout, oAddressFamily, oGssAuthentication, oGssDelegateCreds, oServerAliveInterval, oServerAliveCountMax, oIdentitiesOnly, oSendEnv, oControlPath, oControlMaster, oControlPersist, oHashKnownHosts, oTunnel, oTunnelDevice, oLocalCommand, oPermitLocalCommand, oVisualHostKey, oUseRoaming, oKexAlgorithms, oIPQoS, oRequestTTY, oIgnoreUnknown, oProxyUseFdpass, oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots, oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs, oIgnoredUnknownOption, oHPNDisabled, oHPNBufferSize, oTcpRcvBufPoll, oTcpRcvBuf, oVersionAddendum, oDeprecated, oUnsupported } OpCodes;
































static struct {
	const char *name;
	OpCodes opcode;
} keywords[] = {
	{ "forwardagent", oForwardAgent }, { "forwardx11", oForwardX11 }, { "forwardx11trusted", oForwardX11Trusted }, { "forwardx11timeout", oForwardX11Timeout }, { "exitonforwardfailure", oExitOnForwardFailure }, { "xauthlocation", oXAuthLocation }, { "gatewayports", oGatewayPorts }, { "useprivilegedport", oUsePrivilegedPort }, { "rhostsauthentication", oDeprecated }, { "passwordauthentication", oPasswordAuthentication }, { "kbdinteractiveauthentication", oKbdInteractiveAuthentication }, { "kbdinteractivedevices", oKbdInteractiveDevices }, { "rsaauthentication", oRSAAuthentication }, { "pubkeyauthentication", oPubkeyAuthentication }, { "dsaauthentication", oPubkeyAuthentication }, { "rhostsrsaauthentication", oRhostsRSAAuthentication }, { "hostbasedauthentication", oHostbasedAuthentication }, { "challengeresponseauthentication", oChallengeResponseAuthentication }, { "skeyauthentication", oChallengeResponseAuthentication }, { "tisauthentication", oChallengeResponseAuthentication }, { "kerberosauthentication", oUnsupported }, { "kerberostgtpassing", oUnsupported }, { "afstokenpassing", oUnsupported },  { "gssapiauthentication", oGssAuthentication }, { "gssapidelegatecredentials", oGssDelegateCreds },  { "gssapiauthentication", oUnsupported }, { "gssapidelegatecredentials", oUnsupported },  { "fallbacktorsh", oDeprecated }, { "usersh", oDeprecated }, { "identityfile", oIdentityFile }, { "identityfile2", oIdentityFile }, { "identitiesonly", oIdentitiesOnly }, { "hostname", oHostName }, { "hostkeyalias", oHostKeyAlias }, { "proxycommand", oProxyCommand }, { "port", oPort }, { "cipher", oCipher }, { "ciphers", oCiphers }, { "macs", oMacs }, { "protocol", oProtocol }, { "remoteforward", oRemoteForward }, { "localforward", oLocalForward }, { "user", oUser }, { "host", oHost }, { "match", oMatch }, { "escapechar", oEscapeChar }, { "globalknownhostsfile", oGlobalKnownHostsFile }, { "globalknownhostsfile2", oDeprecated }, { "userknownhostsfile", oUserKnownHostsFile }, { "userknownhostsfile2", oDeprecated }, { "connectionattempts", oConnectionAttempts }, { "batchmode", oBatchMode }, { "checkhostip", oCheckHostIP }, { "stricthostkeychecking", oStrictHostKeyChecking }, { "compression", oCompression }, { "compressionlevel", oCompressionLevel }, { "tcpkeepalive", oTCPKeepAlive }, { "keepalive", oTCPKeepAlive }, { "numberofpasswordprompts", oNumberOfPasswordPrompts }, { "loglevel", oLogLevel }, { "dynamicforward", oDynamicForward }, { "preferredauthentications", oPreferredAuthentications }, { "hostkeyalgorithms", oHostKeyAlgorithms }, { "bindaddress", oBindAddress },  { "smartcarddevice", oPKCS11Provider }, { "pkcs11provider", oPKCS11Provider },  { "smartcarddevice", oUnsupported }, { "pkcs11provider", oUnsupported },  { "clearallforwardings", oClearAllForwardings }, { "enablesshkeysign", oEnableSSHKeysign }, { "verifyhostkeydns", oVerifyHostKeyDNS }, { "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost }, { "rekeylimit", oRekeyLimit }, { "connecttimeout", oConnectTimeout }, { "addressfamily", oAddressFamily }, { "serveraliveinterval", oServerAliveInterval }, { "serveralivecountmax", oServerAliveCountMax }, { "sendenv", oSendEnv }, { "controlpath", oControlPath }, { "controlmaster", oControlMaster }, { "controlpersist", oControlPersist }, { "hashknownhosts", oHashKnownHosts }, { "tunnel", oTunnel }, { "tunneldevice", oTunnelDevice }, { "localcommand", oLocalCommand }, { "permitlocalcommand", oPermitLocalCommand }, { "visualhostkey", oVisualHostKey }, { "useroaming", oUseRoaming }, { "kexalgorithms", oKexAlgorithms }, { "ipqos", oIPQoS }, { "requesttty", oRequestTTY }, { "proxyusefdpass", oProxyUseFdpass }, { "canonicaldomains", oCanonicalDomains }, { "canonicalizefallbacklocal", oCanonicalizeFallbackLocal }, { "canonicalizehostname", oCanonicalizeHostname }, { "canonicalizemaxdots", oCanonicalizeMaxDots }, { "canonicalizepermittedcnames", oCanonicalizePermittedCNAMEs }, { "ignoreunknown", oIgnoreUnknown }, { "hpndisabled", oHPNDisabled }, { "hpnbuffersize", oHPNBufferSize }, { "tcprcvbufpoll", oTcpRcvBufPoll }, { "tcprcvbuf", oTcpRcvBuf }, { "versionaddendum", oVersionAddendum },  { NULL, oBadOption }













































































































};



void add_local_forward(Options *options, const Forward *newfwd)
{
	Forward *fwd;

	extern uid_t original_real_uid;
	int ipport_reserved;

	size_t len_ipport_reserved = sizeof(ipport_reserved);

	if (sysctlbyname("net.inet.ip.portrange.reservedhigh", &ipport_reserved, &len_ipport_reserved, NULL, 0) != 0)
		ipport_reserved = IPPORT_RESERVED;
	else ipport_reserved++;

	ipport_reserved = IPPORT_RESERVED;

	if (newfwd->listen_port < ipport_reserved && original_real_uid != 0)
		fatal("Privileged ports can only be forwarded by root.");

	options->local_forwards = xrealloc(options->local_forwards, options->num_local_forwards + 1, sizeof(*options->local_forwards));

	fwd = &options->local_forwards[options->num_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
}



void add_remote_forward(Options *options, const Forward *newfwd)
{
	Forward *fwd;

	options->remote_forwards = xrealloc(options->remote_forwards, options->num_remote_forwards + 1, sizeof(*options->remote_forwards));

	fwd = &options->remote_forwards[options->num_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

static void clear_forwardings(Options *options)
{
	int i;

	for (i = 0; i < options->num_local_forwards; i++) {
		free(options->local_forwards[i].listen_host);
		free(options->local_forwards[i].connect_host);
	}
	if (options->num_local_forwards > 0) {
		free(options->local_forwards);
		options->local_forwards = NULL;
	}
	options->num_local_forwards = 0;
	for (i = 0; i < options->num_remote_forwards; i++) {
		free(options->remote_forwards[i].listen_host);
		free(options->remote_forwards[i].connect_host);
	}
	if (options->num_remote_forwards > 0) {
		free(options->remote_forwards);
		options->remote_forwards = NULL;
	}
	options->num_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

void add_identity_file(Options *options, const char *dir, const char *filename, int userprovided)

{
	char *path;

	if (options->num_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)", SSH_MAX_IDENTITY_FILES);

	if (dir == NULL) 
		path = xstrdup(filename);
	else (void)xasprintf(&path, "%.100s%.100s", dir, filename);

	options->identity_file_userprovided[options->num_identity_files] = userprovided;
	options->identity_files[options->num_identity_files++] = path;
}

int default_ssh_port(void)
{
	static int port;
	struct servent *sp;

	if (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	return port;
}


static int execute_in_shell(const char *cmd)
{
	char *shell, *command_string;
	pid_t pid;
	int devnull, status;
	extern uid_t original_real_uid;

	if ((shell = getenv("SHELL")) == NULL)
		shell = _PATH_BSHELL;

	
	xasprintf(&command_string, "exec %s", cmd);

	
	if ((devnull = open(_PATH_DEVNULL, O_RDWR)) == -1)
		fatal("open(/dev/null): %s", strerror(errno));

	debug("Executing command: '%.500s'", cmd);

	
	if ((pid = fork()) == 0) {
		char *argv[4];

		
		permanently_drop_suid(original_real_uid);

		
		if (dup2(devnull, STDIN_FILENO) == -1)
			fatal("dup2: %s", strerror(errno));
		if (dup2(devnull, STDOUT_FILENO) == -1)
			fatal("dup2: %s", strerror(errno));
		if (devnull > STDERR_FILENO)
			close(devnull);
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = command_string;
		argv[3] = NULL;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		
		signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	
	if (pid < 0)
		fatal("%s: fork: %.100s", __func__, strerror(errno));

	close(devnull);
	free(command_string);

	while (waitpid(pid, &status, 0) == -1) {
		if (errno != EINTR && errno != EAGAIN)
			fatal("%s: waitpid: %s", __func__, strerror(errno));
	}
	if (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		return -1;
	} 
	debug3("command returned status %d", WEXITSTATUS(status));
	return WEXITSTATUS(status);
}


static int match_cfg_line(Options *options, char **condition, struct passwd *pw, const char *host_arg, const char *filename, int linenum)

{
	char *arg, *attrib, *cmd, *cp = *condition, *host;
	const char *ruser;
	int r, port, result = 1, attributes = 0;
	size_t len;
	char thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];

	
	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == NULL ? pw->pw_name : options->user;
	if (options->hostname != NULL) {
		
		host = percent_expand(options->hostname, "h", host_arg, (char *)NULL);
	} else host = xstrdup(host_arg);

	debug3("checking match for '%s' host %s", cp, host);
	while ((attrib = strdelim(&cp)) && *attrib != '\0') {
		attributes++;
		if (strcasecmp(attrib, "all") == 0) {
			if (attributes != 1 || ((arg = strdelim(&cp)) != NULL && *arg != '\0')) {
				error("'all' cannot be combined with other " "Match attributes");
				result = -1;
				goto out;
			}
			*condition = cp;
			result = 1;
			goto out;
		}
		if ((arg = strdelim(&cp)) == NULL || *arg == '\0') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			goto out;
		}
		len = strlen(arg);
		if (strcasecmp(attrib, "host") == 0) {
			if (match_hostname(host, arg, len) != 1)
				result = 0;
			else debug("%.200s line %d: matched 'Host %.100s' ", filename, linenum, host);

		} else if (strcasecmp(attrib, "originalhost") == 0) {
			if (match_hostname(host_arg, arg, len) != 1)
				result = 0;
			else debug("%.200s line %d: matched " "'OriginalHost %.100s' ", filename, linenum, host_arg);


		} else if (strcasecmp(attrib, "user") == 0) {
			if (match_pattern_list(ruser, arg, len, 0) != 1)
				result = 0;
			else debug("%.200s line %d: matched 'User %.100s' ", filename, linenum, ruser);

		} else if (strcasecmp(attrib, "localuser") == 0) {
			if (match_pattern_list(pw->pw_name, arg, len, 0) != 1)
				result = 0;
			else debug("%.200s line %d: matched " "'LocalUser %.100s' ", filename, linenum, pw->pw_name);


		} else if (strcasecmp(attrib, "exec") == 0) {
			if (gethostname(thishost, sizeof(thishost)) == -1)
				fatal("gethostname: %s", strerror(errno));
			strlcpy(shorthost, thishost, sizeof(shorthost));
			shorthost[strcspn(thishost, ".")] = '\0';
			snprintf(portstr, sizeof(portstr), "%d", port);

			cmd = percent_expand(arg, "L", shorthost, "d", pw->pw_dir, "h", host, "l", thishost, "n", host_arg, "p", portstr, "r", ruser, "u", pw->pw_name, (char *)NULL);








			if (result != 1) {
				
				debug("%.200s line %d: skipped exec \"%.100s\"", filename, linenum, cmd);
			} else {
				r = execute_in_shell(cmd);
				if (r == -1) {
					fatal("%.200s line %d: match exec " "'%.100s' error", filename, linenum, cmd);

				} else if (r == 0) {
					debug("%.200s line %d: matched " "'exec \"%.100s\"'", filename, linenum, cmd);

				} else {
					debug("%.200s line %d: no match " "'exec \"%.100s\"'", filename, linenum, cmd);

					result = 0;
				}
			}
			free(cmd);
		} else {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			goto out;
		}
	}
	if (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		goto out;
	}
	debug3("match %sfound", result ? "" : "not ");
	*condition = cp;
 out:
	free(host);
	return result;
}


static void valid_domain(char *name, const char *filename, int linenum)
{
	size_t i, l = strlen(name);
	u_char c, last = '\0';

	if (l == 0)
		fatal("%s line %d: empty hostname suffix", filename, linenum);
	if (!isalpha((u_char)name[0]) && !isdigit((u_char)name[0]))
		fatal("%s line %d: hostname suffix \"%.100s\" " "starts with invalid character", filename, linenum, name);
	for (i = 0; i < l; i++) {
		c = tolower((u_char)name[i]);
		name[i] = (char)c;
		if (last == '.' && c == '.')
			fatal("%s line %d: hostname suffix \"%.100s\" contains " "consecutive separators", filename, linenum, name);
		if (c != '.' && c != '-' && !isalnum(c) && c != '_')
			fatal("%s line %d: hostname suffix \"%.100s\" contains " "invalid characters", filename, linenum, name);
		last = c;
	}
	if (name[l - 1] == '.')
		name[l - 1] = '\0';
}


static OpCodes parse_token(const char *cp, const char *filename, int linenum, const char *ignored_unknown)

{
	int i;

	for (i = 0; keywords[i].name; i++)
		if (strcmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;
	if (ignored_unknown != NULL && match_pattern_list(cp, ignored_unknown, strlen(ignored_unknown), 1) == 1)
		return oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s", filename, linenum, cp);
	return oBadOption;
}


struct multistate {
	char *key;
	int value;
};
static const struct multistate multistate_flag[] = {
	{ "true",			1 }, { "false",			0 }, { "yes",			1 }, { "no",				0 }, { NULL, -1 }



};
static const struct multistate multistate_yesnoask[] = {
	{ "true",			1 }, { "false",			0 }, { "yes",			1 }, { "no",				0 }, { "ask",			2 }, { NULL, -1 }




};
static const struct multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET }, { "inet6",			AF_INET6 }, { "any",			AF_UNSPEC }, { NULL, -1 }


};
static const struct multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES }, { "yes",			SSHCTL_MASTER_YES }, { "false",			SSHCTL_MASTER_NO }, { "no",				SSHCTL_MASTER_NO }, { "auto",			SSHCTL_MASTER_AUTO }, { "ask",			SSHCTL_MASTER_ASK }, { "autoask",			SSHCTL_MASTER_AUTO_ASK }, { NULL, -1 }






};
static const struct multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET }, { "point-to-point",		SSH_TUNMODE_POINTOPOINT }, { "true",			SSH_TUNMODE_DEFAULT }, { "yes",			SSH_TUNMODE_DEFAULT }, { "false",			SSH_TUNMODE_NO }, { "no",				SSH_TUNMODE_NO }, { NULL, -1 }





};
static const struct multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES }, { "yes",			REQUEST_TTY_YES }, { "false",			REQUEST_TTY_NO }, { "no",				REQUEST_TTY_NO }, { "force",			REQUEST_TTY_FORCE }, { "auto",			REQUEST_TTY_AUTO }, { NULL, -1 }





};
static const struct multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES }, { "false",			SSH_CANONICALISE_NO }, { "yes",			SSH_CANONICALISE_YES }, { "no",				SSH_CANONICALISE_NO }, { "always",			SSH_CANONICALISE_ALWAYS }, { NULL, -1 }




};



int process_config_line(Options *options, struct passwd *pw, const char *host, char *line, const char *filename, int linenum, int *activep, int userconfig)

{
	char *s, **charptr, *endofnumber, *keyword, *arg, *arg2;
	char **cpptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	int negated, opcode, *intptr, value, value2, cmdline = 0;
	LogLevel *log_level_ptr;
	long long val64;
	size_t len;
	Forward fwd;
	const struct multistate *multistate_ptr;
	struct allowed_cname *cname;

	if (activep == NULL) { 
		cmdline = 1;
		activep = &cmdline;
	}

	
	for (len = strlen(line) - 1; len > 0; len--) {
		if (strchr(WHITESPACE, line[len]) == NULL)
			break;
		line[len] = '\0';
	}

	s = line;
	
	if ((keyword = strdelim(&s)) == NULL)
		return 0;
	
	if (*keyword == '\0')
		keyword = strdelim(&s);
	if (keyword == NULL || !*keyword || *keyword == '\n' || *keyword == '#')
		return 0;
	
	lowercase(keyword);

	opcode = parse_token(keyword, filename, linenum, options->ignored_unknown);

	switch (opcode) {
	case oBadOption:
		
		return -1;
		
	case oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"", filename, linenum, keyword);
		return 0;
	case oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.", filename, linenum);
		if ((value = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.", filename, linenum);
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case oForwardAgent:
		intptr = &options->forward_agent;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.", filename, linenum);
		value = -1;
		for (i = 0; multistate_ptr[i].key != NULL; i++) {
			if (strcasecmp(arg, multistate_ptr[i].key) == 0) {
				value = multistate_ptr[i].value;
				break;
			}
		}
		if (value == -1)
			fatal("%s line %d: unsupported option \"%s\".", filename, linenum, arg);
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case oForwardX11:
		intptr = &options->forward_x11;
		goto parse_flag;

	case oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		goto parse_flag;
	
	case oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		goto parse_time;

	case oGatewayPorts:
		intptr = &options->gateway_ports;
		goto parse_flag;

	case oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		goto parse_flag;

	case oUsePrivilegedPort:
		intptr = &options->use_privileged_port;
		goto parse_flag;

	case oPasswordAuthentication:
		intptr = &options->password_authentication;
		goto parse_flag;

	case oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		goto parse_flag;

	case oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		goto parse_string;

	case oPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		goto parse_flag;

	case oRSAAuthentication:
		intptr = &options->rsa_authentication;
		goto parse_flag;

	case oRhostsRSAAuthentication:
		intptr = &options->rhosts_rsa_authentication;
		goto parse_flag;

	case oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		goto parse_flag;

	case oChallengeResponseAuthentication:
		intptr = &options->challenge_response_authentication;
		goto parse_flag;

	case oGssAuthentication:
		intptr = &options->gss_authentication;
		goto parse_flag;

	case oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		goto parse_flag;

	case oBatchMode:
		intptr = &options->batch_mode;
		goto parse_flag;

	case oCheckHostIP:
		intptr = &options->check_host_ip;
		goto parse_flag;

	case oVerifyHostKeyDNS:
		intptr = &options->verify_host_key_dns;
		multistate_ptr = multistate_yesnoask;
		goto parse_multistate;

	case oStrictHostKeyChecking:
		intptr = &options->strict_host_key_checking;
		multistate_ptr = multistate_yesnoask;
		goto parse_multistate;

	case oCompression:
		intptr = &options->compression;
		goto parse_flag;

	case oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		goto parse_flag;

	case oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		goto parse_flag;

	case oNumberOfPasswordPrompts:
		intptr = &options->number_of_password_prompts;
		goto parse_int;

	case oCompressionLevel:
		intptr = &options->compression_level;
		goto parse_int;

	case oRekeyLimit:
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		if (strcmp(arg, "default") == 0) {
			val64 = 0;
		} else {
			if (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad number '%s': %s", filename, linenum, arg, strerror(errno));
			
			if (val64 > UINT_MAX)
				fatal("%.200s line %d: RekeyLimit too large", filename, linenum);
			if (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: RekeyLimit too small", filename, linenum);
		}
		if (*activep && options->rekey_limit == -1)
			options->rekey_limit = (u_int32_t)val64;
		if (s != NULL) { 
			if (strcmp(s, "none") == 0) {
				(void)strdelim(&s);	
				break;
			}
			intptr = &options->rekey_interval;
			goto parse_time;
		}
		break;

	case oIdentityFile:
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		if (*activep) {
			intptr = &options->num_identity_files;
			if (*intptr >= SSH_MAX_IDENTITY_FILES)
				fatal("%.200s line %d: Too many identity files specified (max %d).", filename, linenum, SSH_MAX_IDENTITY_FILES);
			add_identity_file(options, NULL, arg, userconfig);
		}
		break;

	case oXAuthLocation:
		charptr=&options->xauth_location;
		goto parse_string;

	case oUser:
		charptr = &options->user;
parse_string:
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		if (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		break;

	case oGlobalKnownHostsFile:
		cpptr = (char **)&options->system_hostfiles;
		uintptr = &options->num_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		if (*activep && *uintptr == 0) {
			while ((arg = strdelim(&s)) != NULL && *arg != '\0') {
				if ((*uintptr) >= max_entries)
					fatal("%s line %d: " "too many authorized keys files.", filename, linenum);

				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		return 0;

	case oUserKnownHostsFile:
		cpptr = (char **)&options->user_hostfiles;
		uintptr = &options->num_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		goto parse_char_array;

	case oHostName:
		charptr = &options->hostname;
		goto parse_string;

	case oHostKeyAlias:
		charptr = &options->host_key_alias;
		goto parse_string;

	case oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		goto parse_string;

	case oBindAddress:
		charptr = &options->bind_address;
		goto parse_string;

	case oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		goto parse_string;

	case oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		if (s == NULL)
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		len = strspn(s, WHITESPACE "=");
		if (*activep && *charptr == NULL)
			*charptr = xstrdup(s + len);
		return 0;

	case oPort:
		intptr = &options->port;
parse_int:
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		if (arg[0] < '0' || arg[0] > '9')
			fatal("%.200s line %d: Bad number.", filename, linenum);

		
		value = strtol(arg, &endofnumber, 0);
		if (arg == endofnumber)
			fatal("%.200s line %d: Bad number.", filename, linenum);
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case oConnectionAttempts:
		intptr = &options->connection_attempts;
		goto parse_int;

	case oCipher:
		intptr = &options->cipher;
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		value = cipher_number(arg);
		if (value == -1)
			fatal("%.200s line %d: Bad cipher '%s'.", filename, linenum, arg ? arg : "<NONE>");
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case oCiphers:
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		if (!ciphers_valid(arg))
			fatal("%.200s line %d: Bad SSH2 cipher spec '%s'.", filename, linenum, arg ? arg : "<NONE>");
		if (*activep && options->ciphers == NULL)
			options->ciphers = xstrdup(arg);
		break;

	case oMacs:
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		if (!mac_valid(arg))
			fatal("%.200s line %d: Bad SSH2 Mac spec '%s'.", filename, linenum, arg ? arg : "<NONE>");
		if (*activep && options->macs == NULL)
			options->macs = xstrdup(arg);
		break;

	case oKexAlgorithms:
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		if (!kex_names_valid(arg))
			fatal("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.", filename, linenum, arg ? arg : "<NONE>");
		if (*activep && options->kex_algorithms == NULL)
			options->kex_algorithms = xstrdup(arg);
		break;

	case oHostKeyAlgorithms:
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		if (!key_names_valid2(arg))
			fatal("%.200s line %d: Bad protocol 2 host key algorithms '%s'.", filename, linenum, arg ? arg : "<NONE>");
		if (*activep && options->hostkeyalgorithms == NULL)
			options->hostkeyalgorithms = xstrdup(arg);
		break;

	case oProtocol:
		intptr = &options->protocol;
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		value = proto_spec(arg);
		if (value == SSH_PROTO_UNKNOWN)
			fatal("%.200s line %d: Bad protocol spec '%s'.", filename, linenum, arg ? arg : "<NONE>");
		if (*activep && *intptr == SSH_PROTO_UNKNOWN)
			*intptr = value;
		break;

	case oLogLevel:
		log_level_ptr = &options->log_level;
		arg = strdelim(&s);
		value = log_level_number(arg);
		if (value == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'", filename, linenum, arg ? arg : "<NONE>");
		if (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) value;
		break;

	case oLocalForward:
	case oRemoteForward:
	case oDynamicForward:
		arg = strdelim(&s);
		if (arg == NULL || *arg == '\0')
			fatal("%.200s line %d: Missing port argument.", filename, linenum);

		if (opcode == oLocalForward || opcode == oRemoteForward) {
			arg2 = strdelim(&s);
			if (arg2 == NULL || *arg2 == '\0')
				fatal("%.200s line %d: Missing target argument.", filename, linenum);

			
			snprintf(fwdarg, sizeof(fwdarg), "%s:%s", arg, arg2);
		} else if (opcode == oDynamicForward) {
			strlcpy(fwdarg, arg, sizeof(fwdarg));
		}

		if (parse_forward(&fwd, fwdarg, opcode == oDynamicForward ? 1 : 0, opcode == oRemoteForward ? 1 : 0) == 0)

			fatal("%.200s line %d: Bad forwarding specification.", filename, linenum);

		if (*activep) {
			if (opcode == oLocalForward || opcode == oDynamicForward)
				add_local_forward(options, &fwd);
			else if (opcode == oRemoteForward)
				add_remote_forward(options, &fwd);
		}
		break;

	case oClearAllForwardings:
		intptr = &options->clear_forwardings;
		goto parse_flag;

	case oHost:
		if (cmdline)
			fatal("Host directive not supported as a command-line " "option");
		*activep = 0;
		arg2 = NULL;
		while ((arg = strdelim(&s)) != NULL && *arg != '\0') {
			negated = *arg == '!';
			if (negated)
				arg++;
			if (match_pattern(host, arg)) {
				if (negated) {
					debug("%.200s line %d: Skipping Host " "block because of negated match " "for %.100s", filename, linenum, arg);


					*activep = 0;
					break;
				}
				if (!*activep)
					arg2 = arg; 
				*activep = 1;
			}
		}
		if (*activep)
			debug("%.200s line %d: Applying options for %.100s", filename, linenum, arg2);
		
		return 0;

	case oMatch:
		if (cmdline)
			fatal("Host directive not supported as a command-line " "option");
		value = match_cfg_line(options, &s, pw, host, filename, linenum);
		if (value < 0)
			fatal("%.200s line %d: Bad Match condition", filename, linenum);
		*activep = value;
		break;

	case oEscapeChar:
		intptr = &options->escape_char;
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		if (arg[0] == '^' && arg[2] == 0 && (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			value = (u_char) arg[1] & 31;
		else if (strlen(arg) == 1)
			value = (u_char) arg[0];
		else if (strcmp(arg, "none") == 0)
			value = SSH_ESCAPECHAR_NONE;
		else {
			fatal("%.200s line %d: Bad escape character.", filename, linenum);
			
			value = 0;	
		}
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		goto parse_multistate;

	case oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		goto parse_flag;

	case oIdentitiesOnly:
		intptr = &options->identities_only;
		goto parse_flag;

	case oServerAliveInterval:
		intptr = &options->server_alive_interval;
		goto parse_time;

	case oServerAliveCountMax:
		intptr = &options->server_alive_count_max;
		goto parse_int;

	case oSendEnv:
		while ((arg = strdelim(&s)) != NULL && *arg != '\0') {
			if (strchr(arg, '=') != NULL)
				fatal("%s line %d: Invalid environment name.", filename, linenum);
			if (!*activep)
				continue;
			if (options->num_send_env >= MAX_SEND_ENV)
				fatal("%s line %d: too many send env.", filename, linenum);
			options->send_env[options->num_send_env++] = xstrdup(arg);
		}
		break;

	case oControlPath:
		charptr = &options->control_path;
		goto parse_string;

	case oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		goto parse_multistate;

	case oControlPersist:
		
		intptr = &options->control_persist;
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing ControlPersist" " argument.", filename, linenum);
		value = 0;
		value2 = 0;	
		if (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			value = 0;
		else if (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			value = 1;
		else if ((value2 = convtime(arg)) >= 0)
			value = 1;
		else fatal("%.200s line %d: Bad ControlPersist argument.", filename, linenum);

		if (*activep && *intptr == -1) {
			*intptr = value;
			options->control_persist_timeout = value2;
		}
		break;

	case oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		goto parse_flag;

	case oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		goto parse_multistate;

	case oTunnelDevice:
		arg = strdelim(&s);
		if (!arg || *arg == '\0')
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		value = a2tun(arg, &value2);
		if (value == SSH_TUNID_ERR)
			fatal("%.200s line %d: Bad tun device.", filename, linenum);
		if (*activep) {
			options->tun_local = value;
			options->tun_remote = value2;
		}
		break;

	case oLocalCommand:
		charptr = &options->local_command;
		goto parse_command;

	case oPermitLocalCommand:
		intptr = &options->permit_local_command;
		goto parse_flag;

	case oVisualHostKey:
		intptr = &options->visual_host_key;
		goto parse_flag;

	case oIPQoS:
		arg = strdelim(&s);
		if ((value = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad IPQoS value: %s", filename, linenum, arg);
		arg = strdelim(&s);
		if (arg == NULL)
			value2 = value;
		else if ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad IPQoS value: %s", filename, linenum, arg);
		if (*activep) {
			options->ip_qos_interactive = value;
			options->ip_qos_bulk = value2;
		}
		break;

	case oUseRoaming:
		intptr = &options->use_roaming;
		goto parse_flag;

	case oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		goto parse_multistate;

	case oHPNDisabled:
		intptr = &options->hpn_disabled;
		goto parse_flag;

	case oHPNBufferSize:
		intptr = &options->hpn_buffer_size;
		goto parse_int;

	case oTcpRcvBufPoll:
		intptr = &options->tcp_rcv_buf_poll;
		goto parse_flag;

	case oTcpRcvBuf:
		intptr = &options->tcp_rcv_buf;
		goto parse_int;

	case oVersionAddendum:
		if (s == NULL)
			fatal("%.200s line %d: Missing argument.", filename, linenum);
		len = strspn(s, WHITESPACE);
		if (*activep && options->version_addendum == NULL) {
			if (strcasecmp(s + len, "none") == 0)
				options->version_addendum = xstrdup("");
			else if (strchr(s + len, '\r') != NULL)
				fatal("%.200s line %d: Invalid argument", filename, linenum);
			else options->version_addendum = xstrdup(s + len);
		}
		return 0;

	case oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		goto parse_string;

	case oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		goto parse_flag;

	case oCanonicalDomains:
		value = options->num_canonical_domains != 0;
		while ((arg = strdelim(&s)) != NULL && *arg != '\0') {
			valid_domain(arg, filename, linenum);
			if (!*activep || value)
				continue;
			if (options->num_canonical_domains >= MAX_CANON_DOMAINS)
				fatal("%s line %d: too many hostname suffixes.", filename, linenum);
			options->canonical_domains[ options->num_canonical_domains++] = xstrdup(arg);
		}
		break;

	case oCanonicalizePermittedCNAMEs:
		value = options->num_permitted_cnames != 0;
		while ((arg = strdelim(&s)) != NULL && *arg != '\0') {
			
			if (strcmp(arg, "*") == 0)
				arg2 = arg;
			else {
				lowercase(arg);
				if ((arg2 = strchr(arg, ':')) == NULL || arg2[1] == '\0') {
					fatal("%s line %d: " "Invalid permitted CNAME \"%s\"", filename, linenum, arg);

				}
				*arg2 = '\0';
				arg2++;
			}
			if (!*activep || value)
				continue;
			if (options->num_permitted_cnames >= MAX_CANON_DOMAINS)
				fatal("%s line %d: too many permitted CNAMEs.", filename, linenum);
			cname = options->permitted_cnames + options->num_permitted_cnames++;
			cname->source_list = xstrdup(arg);
			cname->target_list = xstrdup(arg2);
		}
		break;

	case oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		goto parse_multistate;

	case oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		goto parse_int;

	case oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		goto parse_flag;

	case oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"", filename, linenum, keyword);
		return 0;

	case oUnsupported:
		error("%s line %d: Unsupported option \"%s\"", filename, linenum, keyword);
		return 0;

	default:
		fatal("process_config_line: Unimplemented opcode %d", opcode);
	}

	
	if ((arg = strdelim(&s)) != NULL && *arg != '\0') {
		fatal("%.200s line %d: garbage at end of line; \"%.200s\".", filename, linenum, arg);
	}
	return 0;
}




int read_config_file(const char *filename, struct passwd *pw, const char *host, Options *options, int flags)

{
	FILE *f;
	char line[1024];
	int active, linenum;
	int bad_options = 0;

	if ((f = fopen(filename, "r")) == NULL)
		return 0;

	if (flags & SSHCONF_CHECKPERM) {
		struct stat sb;

		if (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		if (((sb.st_uid != 0 && sb.st_uid != getuid()) || (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	
	active = 1;
	linenum = 0;
	while (fgets(line, sizeof(line), f)) {
		
		linenum++;
		if (process_config_line(options, pw, host, line, filename, linenum, &active, flags & SSHCONF_USERCONF) != 0)
			bad_options++;
	}
	fclose(f);
	if (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options", filename, bad_options);
	return 1;
}


int option_clear_or_none(const char *o)
{
	return o == NULL || strcasecmp(o, "none") == 0;
}



void initialize_options(Options * options)
{
	memset(options, 'X', sizeof(*options));
	options->forward_agent = -1;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = NULL;
	options->gateway_ports = -1;
	options->use_privileged_port = -1;
	options->rsa_authentication = -1;
	options->pubkey_authentication = -1;
	options->challenge_response_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = NULL;
	options->rhosts_rsa_authentication = -1;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_key_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->compression_level = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->number_of_password_prompts = -1;
	options->cipher = -1;
	options->ciphers = NULL;
	options->macs = NULL;
	options->kex_algorithms = NULL;
	options->hostkeyalgorithms = NULL;
	options->protocol = SSH_PROTO_UNKNOWN;
	options->num_identity_files = 0;
	options->hostname = NULL;
	options->host_key_alias = NULL;
	options->proxy_command = NULL;
	options->user = NULL;
	options->escape_char = -1;
	options->num_system_hostfiles = 0;
	options->num_user_hostfiles = 0;
	options->local_forwards = NULL;
	options->num_local_forwards = 0;
	options->remote_forwards = NULL;
	options->num_remote_forwards = 0;
	options->clear_forwardings = -1;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->preferred_authentications = NULL;
	options->bind_address = NULL;
	options->pkcs11_provider = NULL;
	options->enable_ssh_keysign = - 1;
	options->no_host_authentication_for_localhost = - 1;
	options->identities_only = - 1;
	options->rekey_limit = - 1;
	options->rekey_interval = -1;
	options->verify_host_key_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_count_max = -1;
	options->num_send_env = 0;
	options->control_path = NULL;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = NULL;
	options->permit_local_command = -1;
	options->use_roaming = -1;
	options->visual_host_key = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = NULL;
	options->num_canonical_domains = 0;
	options->num_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->version_addendum = NULL;
	options->hpn_disabled = -1;
	options->hpn_buffer_size = -1;
	options->tcp_rcv_buf_poll = -1;
	options->tcp_rcv_buf = -1;
}


void fill_default_options_for_canonicalization(Options *options)
{
	if (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	if (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	if (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}


void fill_default_options(Options * options)
{
	if (options->forward_agent == -1)
		options->forward_agent = 0;
	if (options->forward_x11 == -1)
		options->forward_x11 = 0;
	if (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	if (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	if (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure = 0;
	if (options->xauth_location == NULL)
		options->xauth_location = _PATH_XAUTH;
	if (options->gateway_ports == -1)
		options->gateway_ports = 0;
	if (options->use_privileged_port == -1)
		options->use_privileged_port = 0;
	if (options->rsa_authentication == -1)
		options->rsa_authentication = 1;
	if (options->pubkey_authentication == -1)
		options->pubkey_authentication = 1;
	if (options->challenge_response_authentication == -1)
		options->challenge_response_authentication = 1;
	if (options->gss_authentication == -1)
		options->gss_authentication = 0;
	if (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	if (options->password_authentication == -1)
		options->password_authentication = 1;
	if (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	if (options->rhosts_rsa_authentication == -1)
		options->rhosts_rsa_authentication = 0;
	if (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	if (options->batch_mode == -1)
		options->batch_mode = 0;
	if (options->check_host_ip == -1)
		options->check_host_ip = 0;
	if (options->strict_host_key_checking == -1)
		options->strict_host_key_checking = 2;	
	if (options->compression == -1)
		options->compression = 0;
	if (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = 1;
	if (options->compression_level == -1)
		options->compression_level = 6;
	if (options->port == -1)
		options->port = 0;	
	if (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	if (options->connection_attempts == -1)
		options->connection_attempts = 1;
	if (options->number_of_password_prompts == -1)
		options->number_of_password_prompts = 3;
	
	if (options->cipher == -1)
		options->cipher = SSH_CIPHER_NOT_SET;
	
	
	
	
	if (options->protocol == SSH_PROTO_UNKNOWN)
		options->protocol = SSH_PROTO_2;
	if (options->num_identity_files == 0) {
		if (options->protocol & SSH_PROTO_1) {
			add_identity_file(options, "~/", _PATH_SSH_CLIENT_IDENTITY, 0);
		}
		if (options->protocol & SSH_PROTO_2) {
			add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_RSA, 0);
			add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_DSA, 0);

			add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_ECDSA, 0);

			add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_ED25519, 0);
		}
	}
	if (options->escape_char == -1)
		options->escape_char = '~';
	if (options->num_system_hostfiles == 0) {
		options->system_hostfiles[options->num_system_hostfiles++] = xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->num_system_hostfiles++] = xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	if (options->num_user_hostfiles == 0) {
		options->user_hostfiles[options->num_user_hostfiles++] = xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->num_user_hostfiles++] = xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	if (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	if (options->clear_forwardings == 1)
		clear_forwardings(options);
	if (options->no_host_authentication_for_localhost == - 1)
		options->no_host_authentication_for_localhost = 0;
	if (options->identities_only == -1)
		options->identities_only = 0;
	if (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	if (options->rekey_limit == -1)
		options->rekey_limit = 0;
	if (options->rekey_interval == -1)
		options->rekey_interval = 0;

	if (options->verify_host_key_dns == -1)
		
		options->verify_host_key_dns = 1;

	if (options->verify_host_key_dns == -1)
		options->verify_host_key_dns = 0;

	if (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	if (options->server_alive_count_max == -1)
		options->server_alive_count_max = 3;
	if (options->control_master == -1)
		options->control_master = 0;
	if (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	if (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	if (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	if (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	if (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	if (options->permit_local_command == -1)
		options->permit_local_command = 0;
	if (options->use_roaming == -1)
		options->use_roaming = 1;
	if (options->visual_host_key == -1)
		options->visual_host_key = 0;
	if (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_LOWDELAY;
	if (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_THROUGHPUT;
	if (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	if (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	if (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	if (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	if (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;






	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	
	
	
	
	if (options->version_addendum == NULL)
		options->version_addendum = xstrdup(SSH_VERSION_FREEBSD);
	if (options->hpn_disabled == -1)
		options->hpn_disabled = 0;
	if (options->hpn_buffer_size > -1)
	{
		u_int maxlen;

		
		if (options->hpn_buffer_size == 0)
			options->hpn_buffer_size = 1024;
		
		maxlen = buffer_get_max_len();
		if (options->hpn_buffer_size > (maxlen / 1024)) {
			debug("User requested buffer larger than %ub: %ub. " "Request reverted to %ub", maxlen, options->hpn_buffer_size * 1024, maxlen);

			options->hpn_buffer_size = maxlen;
		}
		debug("hpn_buffer_size set to %d", options->hpn_buffer_size);
	}
	if (options->tcp_rcv_buf == 0)
		options->tcp_rcv_buf = 1;
	if (options->tcp_rcv_buf > -1)
		options->tcp_rcv_buf *= 1024;
	if (options->tcp_rcv_buf_poll == -1)
		options->tcp_rcv_buf_poll = 1;
}


int parse_forward(Forward *fwd, const char *fwdspec, int dynamicfwd, int remotefwd)
{
	int i;
	char *p, *cp, *fwdarg[4];

	memset(fwd, '\0', sizeof(*fwd));

	cp = p = xstrdup(fwdspec);

	
	while (isspace((u_char)*cp))
		cp++;

	for (i = 0; i < 4; ++i)
		if ((fwdarg[i] = hpdelim(&cp)) == NULL)
			break;

	
	if (cp != NULL)
		i = 0;	

	switch (i) {
	case 1:
		fwd->listen_host = NULL;
		fwd->listen_port = a2port(fwdarg[0]);
		fwd->connect_host = xstrdup("socks");
		break;

	case 2:
		fwd->listen_host = xstrdup(cleanhostname(fwdarg[0]));
		fwd->listen_port = a2port(fwdarg[1]);
		fwd->connect_host = xstrdup("socks");
		break;

	case 3:
		fwd->listen_host = NULL;
		fwd->listen_port = a2port(fwdarg[0]);
		fwd->connect_host = xstrdup(cleanhostname(fwdarg[1]));
		fwd->connect_port = a2port(fwdarg[2]);
		break;

	case 4:
		fwd->listen_host = xstrdup(cleanhostname(fwdarg[0]));
		fwd->listen_port = a2port(fwdarg[1]);
		fwd->connect_host = xstrdup(cleanhostname(fwdarg[2]));
		fwd->connect_port = a2port(fwdarg[3]);
		break;
	default:
		i = 0; 
	}

	free(p);

	if (dynamicfwd) {
		if (!(i == 1 || i == 2))
			goto fail_free;
	} else {
		if (!(i == 3 || i == 4))
			goto fail_free;
		if (fwd->connect_port <= 0)
			goto fail_free;
	}

	if (fwd->listen_port < 0 || (!remotefwd && fwd->listen_port == 0))
		goto fail_free;

	if (fwd->connect_host != NULL && strlen(fwd->connect_host) >= NI_MAXHOST)
		goto fail_free;
	if (fwd->listen_host != NULL && strlen(fwd->listen_host) >= NI_MAXHOST)
		goto fail_free;


	return (i);

 fail_free:
	free(fwd->connect_host);
	fwd->connect_host = NULL;
	free(fwd->listen_host);
	fwd->listen_host = NULL;
	return (0);
}
