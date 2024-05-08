






























static DH  *load_dh_file(int keylength);
static DH  *load_dh_buffer(const char *, size_t);
static DH  *tmp_dh_cb(SSL *s, int is_export, int keylength);
static int	verify_cb(int, X509_STORE_CTX *);
static void info_cb(const SSL *ssl, int type, int args);
static void initialize_SSL(void);
static int	open_server_SSL(Port *);
static void close_SSL(Port *);
static const char *SSLerrmessage(void);


char *ssl_cert_file;
char *ssl_key_file;
char *ssl_ca_file;
char *ssl_crl_file;


int			ssl_renegotiation_limit;


static SSL_CTX *SSL_context = NULL;
static bool ssl_loaded_verify_locations = false;



char	   *SSLCipherSuites = NULL;








static const char file_dh512[] = "-----BEGIN DH PARAMETERS-----\n MEYCQQD1Kv884bEpQBgRjXyEpwpy1obEAxnIByl6ypUM2Zafq9AKUJsCRtMIPWak\n XUGfnHy9iUsiGSa6q6Jew1XpKgVfAgEC\n -----END DH PARAMETERS-----\n"    static const char file_dh1024[] = "-----BEGIN DH PARAMETERS-----\n MIGHAoGBAPSI/VhOSdvNILSd5JEHNmszbDgNRR0PfIizHHxbLY7288kjwEPwpVsY\n jY67VYy4XTjTNP18F1dDox0YbN4zISy1Kv884bEpQBgRjXyEpwpy1obEAxnIByl6\n ypUM2Zafq9AKUJsCRtMIPWakXUGfnHy9iUsiGSa6q6Jew1XpL3jHAgEC\n -----END DH PARAMETERS-----\n"     static const char file_dh2048[] = "-----BEGIN DH PARAMETERS-----\n MIIBCAKCAQEA9kJXtwh/CBdyorrWqULzBej5UxE5T7bxbrlLOCDaAadWoxTpj0BV\n 89AHxstDqZSt90xkhkn4DIO9ZekX1KHTUPj1WV/cdlJPPT2N286Z4VeSWc39uK50\n T8X8dryDxUcwYc58yWb/Ffm7/ZFexwGq01uejaClcjrUGvC/RgBYK+X0iP1YTknb\n zSC0neSRBzZrM2w4DUUdD3yIsxx8Wy2O9vPJI8BD8KVbGI2Ou1WMuF040zT9fBdX\n Q6MdGGzeMyEstSr/POGxKUAYEY18hKcKctaGxAMZyAcpesqVDNmWn6vQClCbAkbT\n CD1mpF1Bn5x8vYlLIhkmuquiXsNV6TILOwIBAg==\n -----END DH PARAMETERS-----\n"        static const char file_dh4096[] = "-----BEGIN DH PARAMETERS-----\n MIICCAKCAgEA+hRyUsFN4VpJ1O8JLcCo/VWr19k3BCgJ4uk+d+KhehjdRqNDNyOQ\n l/MOyQNQfWXPeGKmOmIig6Ev/nm6Nf9Z2B1h3R4hExf+zTiHnvVPeRBhjdQi81rt\n Xeoh6TNrSBIKIHfUJWBh3va0TxxjQIs6IZOLeVNRLMqzeylWqMf49HsIXqbcokUS\n Vt1BkvLdW48j8PPv5DsKRN3tloTxqDJGo9tKvj1Fuk74A+Xda1kNhB7KFlqMyN98\n VETEJ6c7KpfOo30mnK30wqw3S8OtaIR/maYX72tGOno2ehFDkq3pnPtEbD2CScxc\n alJC+EL7RPk5c/tgeTvCngvc1KZn92Y//EI7G9tPZtylj2b56sHtMftIoYJ9+ODM\n sccD5Piz/rejE3Ome8EOOceUSCYAhXn8b3qvxVI1ddd1pED6FHRhFvLrZxFvBEM9\n ERRMp5QqOaHJkM+Dxv8Cj6MqrCbfC4u+ZErxodzuusgDgvZiLF22uxMZbobFWyte\n OvOzKGtwcTqO/1wV5gKkzu1ZVswVUQd5Gg8lJicwqRWyyNRczDDoG9jVDxmogKTH\n AaqLulO7R8Ifa1SwF2DteSGVtgWEN8gDpN3RBmmPTDngyF2DHb5qmpnznwtFKdTL\n KWbuHn491xNO25CQWMtem80uKw+pTnisBRF/454n1Jnhub144YRBoN8CAQI=\n -----END DH PARAMETERS-----\n"                   int secure_initialize(void)








































{

	initialize_SSL();


	return 0;
}


bool secure_loaded_verify_locations(void)
{

	return ssl_loaded_verify_locations;


	return false;
}


int secure_open_server(Port *port)
{
	int			r = 0;


	r = open_server_SSL(port);


	return r;
}


void secure_close(Port *port)
{

	if (port->ssl)
		close_SSL(port);

}


ssize_t secure_read(Port *port, void *ptr, size_t len)
{
	ssize_t		n;


	if (port->ssl)
	{
		int			err;

rloop:
		errno = 0;
		n = SSL_read(port->ssl, ptr, len);
		err = SSL_get_error(port->ssl, n);
		switch (err)
		{
			case SSL_ERROR_NONE:
				port->count += n;
				break;
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				if (port->noblock)
				{
					errno = EWOULDBLOCK;
					n = -1;
					break;
				}

				pgwin32_waitforsinglesocket(SSL_get_fd(port->ssl), (err == SSL_ERROR_WANT_READ) ? FD_READ | FD_CLOSE : FD_WRITE | FD_CLOSE, INFINITE);



				goto rloop;
			case SSL_ERROR_SYSCALL:
				
				if (n != -1)
				{
					errno = ECONNRESET;
					n = -1;
				}
				break;
			case SSL_ERROR_SSL:
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("SSL error: %s", SSLerrmessage())));

				
			case SSL_ERROR_ZERO_RETURN:
				errno = ECONNRESET;
				n = -1;
				break;
			default:
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("unrecognized SSL error code: %d", err)));


				n = -1;
				break;
		}
	}
	else  {

		prepare_for_client_read();

		n = recv(port->sock, ptr, len, 0);

		client_read_ended();
	}

	return n;
}


ssize_t secure_write(Port *port, void *ptr, size_t len)
{
	ssize_t		n;


	if (port->ssl)
	{
		int			err;

		if (ssl_renegotiation_limit && port->count > ssl_renegotiation_limit * 1024L)
		{
			SSL_set_session_id_context(port->ssl, (void *) &SSL_context, sizeof(SSL_context));
			if (SSL_renegotiate(port->ssl) <= 0)
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("SSL renegotiation failure")));

			if (SSL_do_handshake(port->ssl) <= 0)
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("SSL renegotiation failure")));

			if (port->ssl->state != SSL_ST_OK)
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("SSL failed to send renegotiation request")));

			port->ssl->state |= SSL_ST_ACCEPT;
			SSL_do_handshake(port->ssl);
			if (port->ssl->state != SSL_ST_OK)
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("SSL renegotiation failure")));

			port->count = 0;
		}

wloop:
		errno = 0;
		n = SSL_write(port->ssl, ptr, len);
		err = SSL_get_error(port->ssl, n);
		switch (err)
		{
			case SSL_ERROR_NONE:
				port->count += n;
				break;
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:

				pgwin32_waitforsinglesocket(SSL_get_fd(port->ssl), (err == SSL_ERROR_WANT_READ) ? FD_READ | FD_CLOSE : FD_WRITE | FD_CLOSE, INFINITE);



				goto wloop;
			case SSL_ERROR_SYSCALL:
				
				if (n != -1)
				{
					errno = ECONNRESET;
					n = -1;
				}
				break;
			case SSL_ERROR_SSL:
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("SSL error: %s", SSLerrmessage())));

				
			case SSL_ERROR_ZERO_RETURN:
				errno = ECONNRESET;
				n = -1;
				break;
			default:
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("unrecognized SSL error code: %d", err)));


				n = -1;
				break;
		}
	}
	else  n = send(port->sock, ptr, len, 0);


	return n;
}








static bool my_bio_initialized = false;
static BIO_METHOD my_bio_methods;

static int my_sock_read(BIO *h, char *buf, int size)
{
	int			res = 0;

	prepare_for_client_read();

	if (buf != NULL)
	{
		res = recv(h->num, buf, size, 0);
		BIO_clear_retry_flags(h);
		if (res <= 0)
		{
			
			if (errno == EINTR)
			{
				BIO_set_retry_read(h);
			}
		}
	}

	client_read_ended();

	return res;
}

static int my_sock_write(BIO *h, const char *buf, int size)
{
	int			res = 0;

	res = send(h->num, buf, size, 0);
	if (res <= 0)
	{
		if (errno == EINTR)
		{
			BIO_set_retry_write(h);
		}
	}

	return res;
}

static BIO_METHOD * my_BIO_s_socket(void)
{
	if (!my_bio_initialized)
	{
		memcpy(&my_bio_methods, BIO_s_socket(), sizeof(BIO_METHOD));
		my_bio_methods.bread = my_sock_read;
		my_bio_methods.bwrite = my_sock_write;
		my_bio_initialized = true;
	}
	return &my_bio_methods;
}


static int my_SSL_set_fd(SSL *s, int fd)
{
	int			ret = 0;
	BIO		   *bio = NULL;

	bio = BIO_new(my_BIO_s_socket());

	if (bio == NULL)
	{
		SSLerr(SSL_F_SSL_SET_FD, ERR_R_BUF_LIB);
		goto err;
	}
	BIO_set_fd(bio, fd, BIO_NOCLOSE);
	SSL_set_bio(s, bio, bio);
	ret = 1;
err:
	return ret;
}


static DH  * load_dh_file(int keylength)
{
	FILE	   *fp;
	char		fnbuf[MAXPGPATH];
	DH		   *dh = NULL;
	int			codes;

	
	snprintf(fnbuf, sizeof(fnbuf), "dh%d.pem", keylength);
	if ((fp = fopen(fnbuf, "r")) == NULL)
		return NULL;


	dh = PEM_read_DHparams(fp, NULL, NULL, NULL);

	fclose(fp);

	
	if (dh != NULL && 8 * DH_size(dh) < keylength)
	{
		elog(LOG, "DH errors (%s): %d bits expected, %d bits found", fnbuf, keylength, 8 * DH_size(dh));
		dh = NULL;
	}

	
	if (dh != NULL)
	{
		if (DH_check(dh, &codes) == 0)
		{
			elog(LOG, "DH_check error (%s): %s", fnbuf, SSLerrmessage());
			return NULL;
		}
		if (codes & DH_CHECK_P_NOT_PRIME)
		{
			elog(LOG, "DH error (%s): p is not prime", fnbuf);
			return NULL;
		}
		if ((codes & DH_NOT_SUITABLE_GENERATOR) && (codes & DH_CHECK_P_NOT_SAFE_PRIME))
		{
			elog(LOG, "DH error (%s): neither suitable generator or safe prime", fnbuf);

			return NULL;
		}
	}

	return dh;
}


static DH  * load_dh_buffer(const char *buffer, size_t len)
{
	BIO		   *bio;
	DH		   *dh = NULL;

	bio = BIO_new_mem_buf((char *) buffer, len);
	if (bio == NULL)
		return NULL;
	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	if (dh == NULL)
		ereport(DEBUG2, (errmsg_internal("DH load buffer: %s", SSLerrmessage())));

	BIO_free(bio);

	return dh;
}


static DH  * tmp_dh_cb(SSL *s, int is_export, int keylength)
{
	DH		   *r = NULL;
	static DH  *dh = NULL;
	static DH  *dh512 = NULL;
	static DH  *dh1024 = NULL;
	static DH  *dh2048 = NULL;
	static DH  *dh4096 = NULL;

	switch (keylength)
	{
		case 512:
			if (dh512 == NULL)
				dh512 = load_dh_file(keylength);
			if (dh512 == NULL)
				dh512 = load_dh_buffer(file_dh512, sizeof file_dh512);
			r = dh512;
			break;

		case 1024:
			if (dh1024 == NULL)
				dh1024 = load_dh_file(keylength);
			if (dh1024 == NULL)
				dh1024 = load_dh_buffer(file_dh1024, sizeof file_dh1024);
			r = dh1024;
			break;

		case 2048:
			if (dh2048 == NULL)
				dh2048 = load_dh_file(keylength);
			if (dh2048 == NULL)
				dh2048 = load_dh_buffer(file_dh2048, sizeof file_dh2048);
			r = dh2048;
			break;

		case 4096:
			if (dh4096 == NULL)
				dh4096 = load_dh_file(keylength);
			if (dh4096 == NULL)
				dh4096 = load_dh_buffer(file_dh4096, sizeof file_dh4096);
			r = dh4096;
			break;

		default:
			if (dh == NULL)
				dh = load_dh_file(keylength);
			r = dh;
	}

	
	if (r == NULL || 8 * DH_size(r) < keylength)
	{
		ereport(DEBUG2, (errmsg_internal("DH: generating parameters (%d bits)", keylength)));

		r = DH_generate_parameters(keylength, DH_GENERATOR_2, NULL, NULL);
	}

	return r;
}


static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
	return ok;
}


static void info_cb(const SSL *ssl, int type, int args)
{
	switch (type)
	{
		case SSL_CB_HANDSHAKE_START:
			ereport(DEBUG4, (errmsg_internal("SSL: handshake start")));
			break;
		case SSL_CB_HANDSHAKE_DONE:
			ereport(DEBUG4, (errmsg_internal("SSL: handshake done")));
			break;
		case SSL_CB_ACCEPT_LOOP:
			ereport(DEBUG4, (errmsg_internal("SSL: accept loop")));
			break;
		case SSL_CB_ACCEPT_EXIT:
			ereport(DEBUG4, (errmsg_internal("SSL: accept exit (%d)", args)));
			break;
		case SSL_CB_CONNECT_LOOP:
			ereport(DEBUG4, (errmsg_internal("SSL: connect loop")));
			break;
		case SSL_CB_CONNECT_EXIT:
			ereport(DEBUG4, (errmsg_internal("SSL: connect exit (%d)", args)));
			break;
		case SSL_CB_READ_ALERT:
			ereport(DEBUG4, (errmsg_internal("SSL: read alert (0x%04x)", args)));
			break;
		case SSL_CB_WRITE_ALERT:
			ereport(DEBUG4, (errmsg_internal("SSL: write alert (0x%04x)", args)));
			break;
	}
}


static void initialize_SSL(void)
{
	struct stat buf;

	STACK_OF(X509_NAME) *root_cert_list = NULL;

	if (!SSL_context)
	{

		OPENSSL_config(NULL);

		SSL_library_init();
		SSL_load_error_strings();
		SSL_context = SSL_CTX_new(SSLv23_method());
		if (!SSL_context)
			ereport(FATAL, (errmsg("could not create SSL context: %s", SSLerrmessage())));


		
		SSL_CTX_set_mode(SSL_context, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

		
		if (SSL_CTX_use_certificate_chain_file(SSL_context, ssl_cert_file) != 1)
			ereport(FATAL, (errcode(ERRCODE_CONFIG_FILE_ERROR), errmsg("could not load server certificate file \"%s\": %s", ssl_cert_file, SSLerrmessage())));



		if (stat(ssl_key_file, &buf) != 0)
			ereport(FATAL, (errcode_for_file_access(), errmsg("could not access private key file \"%s\": %m", ssl_key_file)));



		

		if (!S_ISREG(buf.st_mode) || buf.st_mode & (S_IRWXG | S_IRWXO))
			ereport(FATAL, (errcode(ERRCODE_CONFIG_FILE_ERROR), errmsg("private key file \"%s\" has group or world access", ssl_key_file), errdetail("Permissions should be u=rw (0600) or less.")));





		if (SSL_CTX_use_PrivateKey_file(SSL_context, ssl_key_file, SSL_FILETYPE_PEM) != 1)

			ereport(FATAL, (errmsg("could not load private key file \"%s\": %s", ssl_key_file, SSLerrmessage())));


		if (SSL_CTX_check_private_key(SSL_context) != 1)
			ereport(FATAL, (errmsg("check of private key failed: %s", SSLerrmessage())));

	}

	
	SSL_CTX_set_tmp_dh_callback(SSL_context, tmp_dh_cb);
	SSL_CTX_set_options(SSL_context, SSL_OP_SINGLE_DH_USE | SSL_OP_NO_SSLv2);

	
	if (SSL_CTX_set_cipher_list(SSL_context, SSLCipherSuites) != 1)
		elog(FATAL, "could not set the cipher list (no valid ciphers available)");

	
	if (ssl_ca_file[0])
	{
		if (SSL_CTX_load_verify_locations(SSL_context, ssl_ca_file, NULL) != 1 || (root_cert_list = SSL_load_client_CA_file(ssl_ca_file)) == NULL)
			ereport(FATAL, (errmsg("could not load root certificate file \"%s\": %s", ssl_ca_file, SSLerrmessage())));

	}

	
	if (ssl_crl_file[0])
	{
		X509_STORE *cvstore = SSL_CTX_get_cert_store(SSL_context);

		if (cvstore)
		{
			
			if (X509_STORE_load_locations(cvstore, ssl_crl_file, NULL) == 1)
			{
				

				X509_STORE_set_flags(cvstore, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

				ereport(LOG, (errmsg("SSL certificate revocation list file \"%s\" ignored", ssl_crl_file), errdetail("SSL library does not support certificate revocation lists.")));



			}
			else ereport(FATAL, (errmsg("could not load SSL certificate revocation list file \"%s\": %s", ssl_crl_file, SSLerrmessage())));


		}
	}

	if (ssl_ca_file[0])
	{
		
		SSL_CTX_set_verify(SSL_context, (SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE), verify_cb);



		
		ssl_loaded_verify_locations = true;

		
		SSL_CTX_set_client_CA_list(SSL_context, root_cert_list);
	}
}


static int open_server_SSL(Port *port)
{
	int			r;
	int			err;

	Assert(!port->ssl);
	Assert(!port->peer);

	if (!(port->ssl = SSL_new(SSL_context)))
	{
		ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("could not initialize SSL connection: %s", SSLerrmessage())));


		close_SSL(port);
		return -1;
	}
	if (!my_SSL_set_fd(port->ssl, port->sock))
	{
		ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("could not set SSL socket: %s", SSLerrmessage())));


		close_SSL(port);
		return -1;
	}

aloop:
	r = SSL_accept(port->ssl);
	if (r <= 0)
	{
		err = SSL_get_error(port->ssl, r);
		switch (err)
		{
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:

				pgwin32_waitforsinglesocket(SSL_get_fd(port->ssl), (err == SSL_ERROR_WANT_READ) ? FD_READ | FD_CLOSE | FD_ACCEPT : FD_WRITE | FD_CLOSE, INFINITE);



				goto aloop;
			case SSL_ERROR_SYSCALL:
				if (r < 0)
					ereport(COMMERROR, (errcode_for_socket_access(), errmsg("could not accept SSL connection: %m")));

				else ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("could not accept SSL connection: EOF detected")));


				break;
			case SSL_ERROR_SSL:
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("could not accept SSL connection: %s", SSLerrmessage())));


				break;
			case SSL_ERROR_ZERO_RETURN:
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("could not accept SSL connection: EOF detected")));

				break;
			default:
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("unrecognized SSL error code: %d", err)));


				break;
		}
		close_SSL(port);
		return -1;
	}

	port->count = 0;

	
	port->peer = SSL_get_peer_certificate(port->ssl);
	if (port->peer == NULL)
	{
		strlcpy(port->peer_dn, "(anonymous)", sizeof(port->peer_dn));
		strlcpy(port->peer_cn, "(anonymous)", sizeof(port->peer_cn));
	}
	else {
		X509_NAME_oneline(X509_get_subject_name(port->peer), port->peer_dn, sizeof(port->peer_dn));
		port->peer_dn[sizeof(port->peer_dn) - 1] = '\0';
		r = X509_NAME_get_text_by_NID(X509_get_subject_name(port->peer), NID_commonName, port->peer_cn, sizeof(port->peer_cn));
		port->peer_cn[sizeof(port->peer_cn) - 1] = '\0';
		if (r == -1)
		{
			
			port->peer_cn[0] = '\0';
		}
		else {
			
			if (r != strlen(port->peer_cn))
			{
				ereport(COMMERROR, (errcode(ERRCODE_PROTOCOL_VIOLATION), errmsg("SSL certificate's common name contains embedded null")));

				close_SSL(port);
				return -1;
			}
		}
	}
	ereport(DEBUG2, (errmsg("SSL connection from \"%s\"", port->peer_cn)));

	
	SSL_CTX_set_info_callback(SSL_context, info_cb);

	return 0;
}


static void close_SSL(Port *port)
{
	if (port->ssl)
	{
		SSL_shutdown(port->ssl);
		SSL_free(port->ssl);
		port->ssl = NULL;
	}

	if (port->peer)
	{
		X509_free(port->peer);
		port->peer = NULL;
	}
}


static const char * SSLerrmessage(void)
{
	unsigned long errcode;
	const char *errreason;
	static char errbuf[32];

	errcode = ERR_get_error();
	if (errcode == 0)
		return _("no SSL error reported");
	errreason = ERR_reason_error_string(errcode);
	if (errreason != NULL)
		return errreason;
	snprintf(errbuf, sizeof(errbuf), _("SSL error code %lu"), errcode);
	return errbuf;
}


