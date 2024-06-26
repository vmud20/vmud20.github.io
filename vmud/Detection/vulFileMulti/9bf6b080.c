






































































typedef enum {
	AUTH_UNUSED = 0, AUTH_SOCKET = 1, AUTH_CONNECTION = 2, } sock_type;



typedef struct socket_entry {
	int fd;
	sock_type type;
	struct sshbuf *input;
	struct sshbuf *output;
	struct sshbuf *request;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = NULL;

typedef struct identity {
	TAILQ_ENTRY(identity) next;
	struct sshkey *key;
	char *comment;
	char *provider;
	time_t death;
	u_int confirm;
	char *sk_provider;
} Identity;

struct idtable {
	int nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};


struct idtable *idtab;

int max_fd = 0;


pid_t parent_pid = -1;
time_t parent_alive_interval = 0;


pid_t cleanup_pid = 0;


char socket_name[PATH_MAX];
char socket_dir[PATH_MAX];


static char *allowed_providers;





int locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

extern char *__progname;


static int lifetime = 0;

static int fingerprint_hash = SSH_FP_HASH_DEFAULT;


static int restrict_websafe = 1;

static void close_socket(SocketEntry *e)
{
	close(e->fd);
	sshbuf_free(e->input);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	memset(e, '\0', sizeof(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

static void idtab_init(void)
{
	idtab = xcalloc(1, sizeof(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

static void free_identity(Identity *id)
{
	sshkey_free(id->key);
	free(id->provider);
	free(id->comment);
	free(id->sk_provider);
	free(id);
}


static Identity * lookup_identity(struct sshkey *key)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		if (sshkey_equal(key, id->key))
			return (id);
	}
	return (NULL);
}


static int confirm_key(Identity *id, const char *extra)
{
	char *p;
	int ret = -1;

	p = sshkey_fingerprint(id->key, fingerprint_hash, SSH_FP_DEFAULT);
	if (p != NULL && ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s", id->comment, p, extra == NULL ? "" : "\n", extra == NULL ? "" : extra))


		ret = 0;
	free(p);

	return (ret);
}

static void send_status(SocketEntry *e, int success)
{
	int r;

	if ((r = sshbuf_put_u32(e->output, 1)) != 0 || (r = sshbuf_put_u8(e->output, success ? SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE)) != 0)

		fatal_fr(r, "compose");
}


static void process_request_identities(SocketEntry *e)
{
	Identity *id;
	struct sshbuf *msg;
	int r;

	debug2_f("entering");

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 || (r = sshbuf_put_u32(msg, idtab->nentries)) != 0)
		fatal_fr(r, "compose");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		if ((r = sshkey_puts_opts(id->key, msg, SSHKEY_SERIALIZE_INFO))
		     != 0 || (r = sshbuf_put_cstring(msg, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			continue;
		}
	}
	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(msg);
}


static char * agent_decode_alg(struct sshkey *key, u_int flags)
{
	if (key->type == KEY_RSA) {
		if (flags & SSH_AGENT_RSA_SHA2_256)
			return "rsa-sha2-256";
		else if (flags & SSH_AGENT_RSA_SHA2_512)
			return "rsa-sha2-512";
	} else if (key->type == KEY_RSA_CERT) {
		if (flags & SSH_AGENT_RSA_SHA2_256)
			return "rsa-sha2-256-cert-v01@openssh.com";
		else if (flags & SSH_AGENT_RSA_SHA2_512)
			return "rsa-sha2-512-cert-v01@openssh.com";
	}
	return NULL;
}


static int parse_userauth_request(struct sshbuf *msg, const struct sshkey *expected_key, char **userp, struct sshbuf **sess_idp)

{
	struct sshbuf *b = NULL, *sess_id = NULL;
	char *user = NULL, *service = NULL, *method = NULL, *pkalg = NULL;
	int r;
	u_char t, sig_follows;
	struct sshkey *mkey = NULL;

	if (userp != NULL)
		*userp = NULL;
	if (sess_idp != NULL)
		*sess_idp = NULL;
	if ((b = sshbuf_fromb(msg)) == NULL)
		fatal_f("sshbuf_fromb");

	
	if ((r = sshbuf_froms(b, &sess_id)) != 0)
		goto out;
	if (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((r = sshbuf_get_u8(b, &t)) != 0 ||  (r = sshbuf_get_cstring(b, &user, NULL)) != 0 || (r = sshbuf_get_cstring(b, &service, NULL)) != 0 || (r = sshbuf_get_cstring(b, &method, NULL)) != 0 || (r = sshbuf_get_u8(b, &sig_follows)) != 0 || (r = sshbuf_get_cstring(b, &pkalg, NULL)) != 0 || (r = sshkey_froms(b, &mkey)) != 0)





		goto out;
	if (t != SSH2_MSG_USERAUTH_REQUEST || sig_follows != 1 || strcmp(service, "ssh-connection") != 0 || !sshkey_equal(expected_key, mkey) || sshkey_type_from_name(pkalg) != expected_key->type) {



		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	
	r = 0;
	debug3_f("well formed userauth");
	if (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	if (sess_idp != NULL) {
		*sess_idp = sess_id;
		sess_id = NULL;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	free(user);
	free(service);
	free(method);
	free(pkalg);
	sshkey_free(mkey);
	return r;
}


static int parse_sshsig_request(struct sshbuf *msg)
{
	int r;
	struct sshbuf *b;

	if ((b = sshbuf_fromb(msg)) == NULL)
		fatal_f("sshbuf_fromb");

	if ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 || (r = sshbuf_consume(b, 6)) != 0 || (r = sshbuf_get_cstring(b, NULL, NULL)) != 0 || (r = sshbuf_get_string_direct(b, NULL, NULL)) != 0 || (r = sshbuf_get_cstring(b, NULL, NULL)) != 0 || (r = sshbuf_get_string_direct(b, NULL, NULL)) != 0)




		goto out;
	if (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	
	r = 0;
 out:
	sshbuf_free(b);
	return r;
}


static int check_websafe_message_contents(struct sshkey *key, struct sshbuf *data)
{
	if (parse_userauth_request(data, key, NULL, NULL) == 0) {
		debug_f("signed data matches public key userauth request");
		return 1;
	}
	if (parse_sshsig_request(data) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		return 1;
	}

	

	error("web-origin key attempting to sign non-SSH message");
	return 0;
}


static void process_sign_request2(SocketEntry *e)
{
	u_char *signature = NULL;
	size_t slen = 0;
	u_int compat = 0, flags;
	int r, ok = -1;
	char *fp = NULL;
	struct sshbuf *msg = NULL, *data = NULL;
	struct sshkey *key = NULL;
	struct identity *id;
	struct notifier_ctx *notifier = NULL;

	debug_f("entering");

	if ((msg = sshbuf_new()) == NULL || (data = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshkey_froms(e->request, &key)) != 0 || (r = sshbuf_get_stringb(e->request, data)) != 0 || (r = sshbuf_get_u32(e->request, &flags)) != 0) {

		error_fr(r, "parse");
		goto send;
	}

	if ((id = lookup_identity(key)) == NULL) {
		verbose_f("%s key not found", sshkey_type(key));
		goto send;
	}
	if (id->confirm && confirm_key(id, NULL) != 0) {
		verbose_f("user refused key");
		goto send;
	}
	if (sshkey_is_sk(id->key)) {
		if (strncmp(id->key->sk_application, "ssh:", 4) != 0 && !check_websafe_message_contents(key, data)) {
			
			goto send;
		}
		if ((id->key->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
			if ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL)
				fatal_f("fingerprint failed");
			notifier = notify_start(0, "Confirm user presence for key %s %s", sshkey_type(id->key), fp);

		}
	}
	
	if ((r = sshkey_sign(id->key, &signature, &slen, sshbuf_ptr(data), sshbuf_len(data), agent_decode_alg(key, flags), id->sk_provider, NULL, compat)) != 0) {

		error_fr(r, "sshkey_sign");
		goto send;
	}
	
	ok = 0;
 send:
	notify_complete(notifier, "User presence confirmed");

	if (ok == 0) {
		if ((r = sshbuf_put_u8(msg, SSH2_AGENT_SIGN_RESPONSE)) != 0 || (r = sshbuf_put_string(msg, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} else if ((r = sshbuf_put_u8(msg, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(data);
	sshbuf_free(msg);
	sshkey_free(key);
	free(fp);
	free(signature);
}


static void process_remove_identity(SocketEntry *e)
{
	int r, success = 0;
	struct sshkey *key = NULL;
	Identity *id;

	debug2_f("entering");
	if ((r = sshkey_froms(e->request, &key)) != 0) {
		error_fr(r, "parse key");
		goto done;
	}
	if ((id = lookup_identity(key)) == NULL) {
		debug_f("key not found");
		goto done;
	}
	
	if (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(key);
	send_status(e, success);
}

static void process_remove_all_identities(SocketEntry *e)
{
	Identity *id;

	debug2_f("entering");
	
	for (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	
	idtab->nentries = 0;

	
	send_status(e, 1);
}


static time_t reaper(void)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	for (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		if (id->death == 0)
			continue;
		if (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} else deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	if (deadline == 0 || deadline <= now)
		return 0;
	else return (deadline - now);
}

static int parse_key_constraints(struct sshbuf *m, struct sshkey *k, time_t *deathp, u_int *secondsp, int *confirmp, char **sk_providerp)

{
	u_char ctype;
	int r;
	u_int seconds, maxsign = 0;
	char *ext_name = NULL;
	struct sshbuf *b = NULL;

	while (sshbuf_len(m)) {
		if ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			goto err;
		}
		switch (ctype) {
		case SSH_AGENT_CONSTRAIN_LIFETIME:
			if (*deathp != 0) {
				error_f("lifetime already set");
				goto err;
			}
			if ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				goto err;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			break;
		case SSH_AGENT_CONSTRAIN_CONFIRM:
			if (*confirmp != 0) {
				error_f("confirm already set");
				goto err;
			}
			*confirmp = 1;
			break;
		case SSH_AGENT_CONSTRAIN_MAXSIGN:
			if (k == NULL) {
				error_f("maxsign not valid here");
				goto err;
			}
			if (maxsign != 0) {
				error_f("maxsign already set");
				goto err;
			}
			if ((r = sshbuf_get_u32(m, &maxsign)) != 0) {
				error_fr(r, "parse maxsign constraint");
				goto err;
			}
			if ((r = sshkey_enable_maxsign(k, maxsign)) != 0) {
				error_fr(r, "enable maxsign");
				goto err;
			}
			break;
		case SSH_AGENT_CONSTRAIN_EXTENSION:
			if ((r = sshbuf_get_cstring(m, &ext_name, NULL)) != 0) {
				error_fr(r, "parse constraint extension");
				goto err;
			}
			debug_f("constraint ext %s", ext_name);
			if (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
				if (sk_providerp == NULL) {
					error_f("%s not valid here", ext_name);
					goto err;
				}
				if (*sk_providerp != NULL) {
					error_f("%s already set", ext_name);
					goto err;
				}
				if ((r = sshbuf_get_cstring(m, sk_providerp, NULL)) != 0) {
					error_fr(r, "parse %s", ext_name);
					goto err;
				}
			} else {
				error_f("unsupported constraint \"%s\"", ext_name);
				goto err;
			}
			free(ext_name);
			break;
		default:
			error_f("Unknown constraint %d", ctype);
 err:
			free(ext_name);
			sshbuf_free(b);
			return -1;
		}
	}
	
	return 0;
}

static void process_add_identity(SocketEntry *e)
{
	Identity *id;
	int success = 0, confirm = 0;
	char *fp, *comment = NULL, *sk_provider = NULL;
	char canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	struct sshkey *k = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	if ((r = sshkey_private_deserialize(e->request, &k)) != 0 || k == NULL || (r = sshbuf_get_cstring(e->request, &comment, NULL)) != 0) {

		error_fr(r, "parse");
		goto out;
	}
	if (parse_key_constraints(e->request, k, &death, &seconds, &confirm, &sk_provider) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		goto out;
	}

	if (sk_provider != NULL) {
		if (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an " "authenticator-hosted key", sshkey_type(k));
			goto out;
		}
		if (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} else {
			if (realpath(sk_provider, canonical_provider) == NULL) {
				verbose("failed provider \"%.100s\": " "realpath: %s", sk_provider, strerror(errno));

				goto out;
			}
			free(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			if (match_pattern_list(sk_provider, allowed_providers, 0) != 1) {
				error("Refusing add key: " "provider %s not allowed", sk_provider);
				goto out;
			}
		}
	}
	if ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		goto out;
	}
	if (lifetime && !death)
		death = monotime() + lifetime;
	if ((id = lookup_identity(k)) == NULL) {
		id = xcalloc(1, sizeof(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		
		idtab->nentries++;
	} else {
		
		sshkey_free(id->key);
		free(id->comment);
		free(id->sk_provider);
	}
	
	id->key = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;

	if ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) " "(provider: %s)", sshkey_ssh_name(k), fp, comment, seconds, confirm, sk_provider == NULL ? "none" : sk_provider);

	free(fp);
	
	k = NULL;
	comment = NULL;
	sk_provider = NULL;
	success = 1;
 out:
	free(sk_provider);
	free(comment);
	sshkey_free(k);
	send_status(e, success);
}


static void process_lock_agent(SocketEntry *e, int lock)
{
	int r, success = 0, delay;
	char *passwd;
	u_char passwdhash[LOCK_SIZE];
	static u_int fail_count = 0;
	size_t pwlen;

	debug2_f("entering");
	
	if ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	if (pwlen == 0) {
		debug("empty password not supported");
	} else if (locked && !lock) {
		if (bcrypt_pbkdf(passwd, pwlen, lock_salt, sizeof(lock_salt), passwdhash, sizeof(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		if (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_count = 0;
			explicit_bzero(lock_pwhash, sizeof(lock_pwhash));
			success = 1;
		} else {
			
			if (fail_count < 100)
				fail_count++;
			delay = 100000 * fail_count;
			debug("unlock failed, delaying %0.1lf seconds", (double)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, sizeof(passwdhash));
	} else if (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, sizeof(lock_salt));
		if (bcrypt_pbkdf(passwd, pwlen, lock_salt, sizeof(lock_salt), lock_pwhash, sizeof(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

static void no_identities(SocketEntry *e)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 || (r = sshbuf_put_u32(msg, 0)) != 0 || (r = sshbuf_put_stringb(e->output, msg)) != 0)

		fatal_fr(r, "compose");
	sshbuf_free(msg);
}


static void process_add_smartcard_key(SocketEntry *e)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	char **comments = NULL;
	int r, i, count = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	struct sshkey **keys = NULL, *k;
	Identity *id;

	debug2_f("entering");
	if ((r = sshbuf_get_cstring(e->request, &provider, NULL)) != 0 || (r = sshbuf_get_cstring(e->request, &pin, NULL)) != 0) {
		error_fr(r, "parse");
		goto send;
	}
	if (parse_key_constraints(e->request, NULL, &death, &seconds, &confirm, NULL) != 0) {
		error_f("failed to parse constraints");
		goto send;
	}
	if (realpath(provider, canonical_provider) == NULL) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s", provider, strerror(errno));
		goto send;
	}
	if (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": " "provider not allowed", canonical_provider);
		goto send;
	}
	debug_f("add %.100s", canonical_provider);
	if (lifetime && !death)
		death = monotime() + lifetime;

	count = pkcs11_add_provider(canonical_provider, pin, &keys, &comments);
	for (i = 0; i < count; i++) {
		k = keys[i];
		if (lookup_identity(k) == NULL) {
			id = xcalloc(1, sizeof(Identity));
			id->key = k;
			keys[i] = NULL; 
			id->provider = xstrdup(canonical_provider);
			if (*comments[i] != '\0') {
				id->comment = comments[i];
				comments[i] = NULL; 
			} else {
				id->comment = xstrdup(canonical_provider);
			}
			id->death = death;
			id->confirm = confirm;
			TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
			idtab->nentries++;
			success = 1;
		}
		
		sshkey_free(keys[i]);
		free(comments[i]);
	}
send:
	free(pin);
	free(provider);
	free(keys);
	free(comments);
	send_status(e, success);
}

static void process_remove_smartcard_key(SocketEntry *e)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	int r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	if ((r = sshbuf_get_cstring(e->request, &provider, NULL)) != 0 || (r = sshbuf_get_cstring(e->request, &pin, NULL)) != 0) {
		error_fr(r, "parse");
		goto send;
	}
	free(pin);

	if (realpath(provider, canonical_provider) == NULL) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s", provider, strerror(errno));
		goto send;
	}

	debug_f("remove %.100s", canonical_provider);
	for (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		
		if (id->provider == NULL)
			continue;
		if (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	if (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	else error_f("pkcs11_del_provider failed");
send:
	free(provider);
	send_status(e, success);
}



static int process_message(u_int socknum)
{
	u_int msg_len;
	u_char type;
	const u_char *cp;
	int r;
	SocketEntry *e;

	if (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	if (sshbuf_len(e->input) < 5)
		return 0;		
	cp = sshbuf_ptr(e->input);
	msg_len = PEEK_U32(cp);
	if (msg_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u", socknum, e->fd, msg_len, AGENT_MAX_LEN);
		return -1;
	}
	if (sshbuf_len(e->input) < msg_len + 4)
		return 0;		

	
	sshbuf_reset(e->request);
	if ((r = sshbuf_get_stringb(e->input, e->request)) != 0 || (r = sshbuf_get_u8(e->request, &type)) != 0) {
		if (r == SSH_ERR_MESSAGE_INCOMPLETE || r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			return -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	
	if (locked && type != SSH_AGENTC_UNLOCK) {
		sshbuf_reset(e->request);
		switch (type) {
		case SSH2_AGENTC_REQUEST_IDENTITIES:
			
			no_identities(e);
			break;
		default:
			
			send_status(e, 0);
		}
		return 1;
	}

	switch (type) {
	case SSH_AGENTC_LOCK:
	case SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		break;
	case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); 
		break;
	
	case SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		break;
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		break;
	case SSH2_AGENTC_ADD_IDENTITY:
	case SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		break;
	case SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		break;
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		break;

	case SSH_AGENTC_ADD_SMARTCARD_KEY:
	case SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED:
		process_add_smartcard_key(e);
		break;
	case SSH_AGENTC_REMOVE_SMARTCARD_KEY:
		process_remove_smartcard_key(e);
		break;

	default:
		
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		break;
	}
	return 1;
}

static void new_socket(sock_type type, int fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	if (fd > max_fd)
		max_fd = fd;

	for (i = 0; i < sockets_alloc; i++)
		if (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			if ((sockets[i].input = sshbuf_new()) == NULL || (sockets[i].output = sshbuf_new()) == NULL || (sockets[i].request = sshbuf_new()) == NULL)

				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			return;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc, sizeof(sockets[0]));
	for (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	if ((sockets[old_alloc].input = sshbuf_new()) == NULL || (sockets[old_alloc].output = sshbuf_new()) == NULL || (sockets[old_alloc].request = sshbuf_new()) == NULL)

		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

static int handle_socket_read(u_int socknum)
{
	struct sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	int fd;

	slen = sizeof(sunaddr);
	fd = accept(sockets[socknum].fd, (struct sockaddr *)&sunaddr, &slen);
	if (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		return -1;
	}
	if (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		return -1;
	}
	if ((euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u", (u_int) euid, (u_int) getuid());
		close(fd);
		return -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	return 0;
}

static int handle_conn_read(u_int socknum)
{
	char buf[AGENT_RBUF_LEN];
	ssize_t len;
	int r;

	if ((len = read(sockets[socknum].fd, buf, sizeof(buf))) <= 0) {
		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			error_f("read error on socket %u (fd %d): %s", socknum, sockets[socknum].fd, strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_put(sockets[socknum].input, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, sizeof(buf));
	for (;;) {
		if ((r = process_message(socknum)) == -1)
			return -1;
		else if (r == 0)
			break;
	}
	return 0;
}

static int handle_conn_write(u_int socknum)
{
	ssize_t len;
	int r;

	if (sshbuf_len(sockets[socknum].output) == 0)
		return 0; 
	if ((len = write(sockets[socknum].fd, sshbuf_ptr(sockets[socknum].output), sshbuf_len(sockets[socknum].output))) <= 0) {

		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			error_f("read error on socket %u (fd %d): %s", socknum, sockets[socknum].fd, strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	return 0;
}

static void after_poll(struct pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	for (i = 0; i < npfd; i++) {
		if (pfd[i].revents == 0)
			continue;
		
		for (socknum = 0; socknum < sockets_alloc; socknum++) {
			if (sockets[socknum].type != AUTH_SOCKET && sockets[socknum].type != AUTH_CONNECTION)
				continue;
			if (pfd[i].fd == sockets[socknum].fd)
				break;
		}
		if (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			continue;
		}
		
		switch (sockets[socknum].type) {
		case AUTH_SOCKET:
			if ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				break;
			if (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); " "skipping accept", activefds, maxfds);
				break;
			}
			if (handle_socket_read(socknum) == 0)
				activefds++;
			break;
		case AUTH_CONNECTION:
			if ((pfd[i].revents & (POLLIN|POLLERR)) != 0 && handle_conn_read(socknum) != 0) {
				goto close_sock;
			}
			if ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 && handle_conn_write(socknum) != 0) {
 close_sock:
				if (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				break;
			}
			break;
		default:
			break;
		}
	}
}

static int prepare_poll(struct pollfd **pfdp, size_t *npfdp, int *timeoutp, u_int maxfds)
{
	struct pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	int r;

	
	for (i = 0; i < sockets_alloc; i++) {
		switch (sockets[i].type) {
		case AUTH_SOCKET:
		case AUTH_CONNECTION:
			npfd++;
			break;
		case AUTH_UNUSED:
			break;
		default:
			fatal("Unknown socket type %d", sockets[i].type);
			break;
		}
	}
	if (npfd != *npfdp && (pfd = recallocarray(pfd, *npfdp, npfd, sizeof(*pfd))) == NULL)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	for (i = j = 0; i < sockets_alloc; i++) {
		switch (sockets[i].type) {
		case AUTH_SOCKET:
			if (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); " "skipping arming listener", npfd, maxfds);
				break;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			break;
		case AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			
			if ((r = sshbuf_check_reserve(sockets[i].input, AGENT_RBUF_LEN)) == 0 && (r = sshbuf_check_reserve(sockets[i].output, AGENT_MAX_LEN)) == 0)


				pfd[j].events = POLLIN;
			else if (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			if (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			break;
		default:
			break;
		}
	}
	deadline = reaper();
	if (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	if (deadline == 0) {
		*timeoutp = -1; 
	} else {
		if (deadline > INT_MAX / 1000)
			*timeoutp = INT_MAX / 1000;
		else *timeoutp = deadline * 1000;
	}
	return (1);
}

static void cleanup_socket(void)
{
	if (cleanup_pid != 0 && getpid() != cleanup_pid)
		return;
	debug_f("cleanup");
	if (socket_name[0])
		unlink(socket_name);
	if (socket_dir[0])
		rmdir(socket_dir);
}

void cleanup_exit(int i)
{
	cleanup_socket();
	_exit(i);
}


static void cleanup_handler(int sig)
{
	cleanup_socket();

	pkcs11_terminate();

	_exit(2);
}

static void check_parent_exists(void)
{
	
	if (parent_pid != -1 && getppid() != parent_pid) {
		
		cleanup_socket();
		_exit(2);
	}
}

static void usage(void)
{
	fprintf(stderr, "usage: ssh-agent [-c | -s] [-Dd] [-a bind_address] [-E fingerprint_hash]\n" "                 [-P allowed_providers] [-t life]\n" "       ssh-agent [-a bind_address] [-E fingerprint_hash] [-P allowed_providers]\n" "                 [-t life] command [arg ...]\n" "       ssh-agent [-c | -s] -k\n");




	exit(1);
}

int main(int ac, char **av)
{
	int c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0, s_flag = 0;
	int sock, ch, result, saved_errno;
	char *shell, *format, *pidstr, *agentsocket = NULL;

	struct rlimit rlim;

	extern int optind;
	extern char *optarg;
	pid_t pid;
	char pidstrbuf[1 + 3 * sizeof pid];
	size_t len;
	mode_t prev_mask;
	int timeout = -1; 
	struct pollfd *pfd = NULL;
	size_t npfd = 0;
	u_int maxfds;

	
	sanitise_stdfd();

	
	setegid(getgid());
	setgid(getgid());

	platform_disable_tracing(0);	


	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));


	__progname = ssh_get_progname(av[0]);
	seed_rng();

	while ((ch = getopt(ac, av, "cDdksE:a:O:P:t:")) != -1) {
		switch (ch) {
		case 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			if (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			break;
		case 'c':
			if (s_flag)
				usage();
			c_flag++;
			break;
		case 'k':
			k_flag++;
			break;
		case 'O':
			if (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe  = 0;
			else fatal("Unknown -O option");
			break;
		case 'P':
			if (allowed_providers != NULL)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			break;
		case 's':
			if (c_flag)
				usage();
			s_flag++;
			break;
		case 'd':
			if (d_flag || D_flag)
				usage();
			d_flag++;
			break;
		case 'D':
			if (d_flag || D_flag)
				usage();
			D_flag++;
			break;
		case 'a':
			agentsocket = optarg;
			break;
		case 't':
			if ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			break;
		default:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	if (ac > 0 && (c_flag || k_flag || s_flag || d_flag || D_flag))
		usage();

	if (allowed_providers == NULL)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);

	if (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		if (shell != NULL && (len = strlen(shell)) > 2 && strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	if (k_flag) {
		const char *errstr = NULL;

		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		if (pidstr == NULL) {
			fprintf(stderr, "%s not set, cannot kill agent\n", SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (int)strtonum(pidstr, 2, INT_MAX, &errstr);
		if (errstr) {
			fprintf(stderr, "%s=\"%s\", which is not a good PID: %s\n", SSH_AGENTPID_ENV_NAME, pidstr, errstr);

			exit(1);
		}
		if (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}

	

	if (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)", __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	if (agentsocket == NULL) {
		
		mktemp_proto(socket_dir, sizeof(socket_dir));
		if (mkdtemp(socket_dir) == NULL) {
			perror("mkdtemp: private socket dir");
			exit(1);
		}
		snprintf(socket_name, sizeof socket_name, "%s/agent.%ld", socket_dir, (long)parent_pid);
	} else {
		
		socket_dir[0] = '\0';
		strlcpy(socket_name, agentsocket, sizeof socket_name);
	}

	
	prev_mask = umask(0177);
	sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
	if (sock < 0) {
		
		*socket_name = '\0'; 
		cleanup_exit(1);
	}
	umask(prev_mask);

	
	if (D_flag || d_flag) {
		log_init(__progname, d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 1);

		format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name, SSH_AUTHSOCKET_ENV_NAME);
		printf("echo Agent pid %ld;\n", (long)parent_pid);
		fflush(stdout);
		goto skip;
	}
	pid = fork();
	if (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	if (pid != 0) {		
		close(sock);
		snprintf(pidstrbuf, sizeof pidstrbuf, "%ld", (long)pid);
		if (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name, SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf, SSH_AGENTPID_ENV_NAME);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		if (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 || setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			exit(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		exit(1);
	}
	
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	if (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(void)chdir("/");
	if (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");


	
	rlim.rlim_cur = rlim.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}


skip:

	cleanup_pid = getpid();


	pkcs11_init(0);

	new_socket(AUTH_SOCKET, sock);
	if (ac > 0)
		parent_alive_interval = 10;
	idtab_init();
	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGINT, (d_flag | D_flag) ? cleanup_handler : SIG_IGN);
	ssh_signal(SIGHUP, cleanup_handler);
	ssh_signal(SIGTERM, cleanup_handler);

	if (pledge("stdio rpath cpath unix id proc exec", NULL) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	while (1) {
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = poll(pfd, npfd, timeout);
		saved_errno = errno;
		if (parent_alive_interval != 0)
			check_parent_exists();
		(void) reaper();	
		if (result == -1) {
			if (saved_errno == EINTR)
				continue;
			fatal("poll: %s", strerror(saved_errno));
		} else if (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	
}
