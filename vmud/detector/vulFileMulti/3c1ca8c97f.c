



























































static bool verify_peer_name_matches_certificate(PGconn *);
static int	verify_cb(int ok, X509_STORE_CTX *ctx);
static int	init_ssl_system(PGconn *conn);
static void destroy_ssl_system(void);
static int	initialize_SSL(PGconn *conn);
static void destroySSL(void);
static PostgresPollingStatusType open_client_SSL(PGconn *);
static void close_SSL(PGconn *);
static char *SSLerrmessage(void);
static void SSLerrfree(char *buf);

static bool pq_init_ssl_lib = true;
static bool pq_init_crypto_lib = true;
static SSL_CTX *SSL_context = NULL;


static long ssl_open_connections = 0;


static pthread_mutex_t ssl_config_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t ssl_config_mutex = NULL;
static long win32_ssl_create_mutex = 0;













struct sigpipe_info {
	sigset_t	oldsigmask;
	bool		sigpipe_pending;
	bool		got_epipe;
};





















































void PQinitSSL(int do_init)
{
	PQinitOpenSSL(do_init, do_init);
}


void PQinitOpenSSL(int do_ssl, int do_crypto)
{



	
	if (ssl_open_connections != 0)
		return;


	pq_init_ssl_lib = do_ssl;
	pq_init_crypto_lib = do_crypto;

}


int pqsecure_initialize(PGconn *conn)
{
	int			r = 0;


	r = init_ssl_system(conn);


	return r;
}


void pqsecure_destroy(void)
{

	destroySSL();

}


PostgresPollingStatusType pqsecure_open_client(PGconn *conn)
{

	
	if (conn->ssl == NULL)
	{
		
		conn->sigpipe_flag = false;

		
		if (!(conn->ssl = SSL_new(SSL_context)) || !SSL_set_app_data(conn->ssl, conn) || !SSL_set_fd(conn->ssl, conn->sock))

		{
			char	   *err = SSLerrmessage();

			printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not establish SSL connection: %s\n"), err);

			SSLerrfree(err);
			close_SSL(conn);
			return PGRES_POLLING_FAILED;
		}

		
		if (initialize_SSL(conn) != 0)
		{
			
			close_SSL(conn);
			return PGRES_POLLING_FAILED;
		}
	}

	
	return open_client_SSL(conn);

	
	return PGRES_POLLING_FAILED;

}


void pqsecure_close(PGconn *conn)
{

	if (conn->ssl)
		close_SSL(conn);

}


ssize_t pqsecure_read(PGconn *conn, void *ptr, size_t len)
{
	ssize_t		n;
	int			result_errno = 0;
	char		sebuf[256];


	if (conn->ssl)
	{
		int			err;

		DECLARE_SIGPIPE_INFO(spinfo);

		
		DISABLE_SIGPIPE(conn, spinfo, return -1);

rloop:
		SOCK_ERRNO_SET(0);
		n = SSL_read(conn->ssl, ptr, len);
		err = SSL_get_error(conn->ssl, n);
		switch (err)
		{
			case SSL_ERROR_NONE:
				if (n < 0)
				{
					
					printfPQExpBuffer(&conn->errorMessage, "SSL_read failed but did not provide error information\n");
					
					result_errno = ECONNRESET;
				}
				break;
			case SSL_ERROR_WANT_READ:
				n = 0;
				break;
			case SSL_ERROR_WANT_WRITE:

				
				goto rloop;
			case SSL_ERROR_SYSCALL:
				if (n < 0)
				{
					result_errno = SOCK_ERRNO;
					REMEMBER_EPIPE(spinfo, result_errno == EPIPE);
					if (result_errno == EPIPE || result_errno == ECONNRESET)
						printfPQExpBuffer(&conn->errorMessage, libpq_gettext( "server closed the connection unexpectedly\n" "\tThis probably means the server terminated abnormally\n" "\tbefore or while processing the request.\n"));



					else printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL SYSCALL error: %s\n"), SOCK_STRERROR(result_errno, sebuf, sizeof(sebuf)));



				}
				else {
					printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL SYSCALL error: EOF detected\n"));
					
					result_errno = ECONNRESET;
					n = -1;
				}
				break;
			case SSL_ERROR_SSL:
				{
					char	   *errm = SSLerrmessage();

					printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL error: %s\n"), errm);
					SSLerrfree(errm);
					
					result_errno = ECONNRESET;
					n = -1;
					break;
				}
			case SSL_ERROR_ZERO_RETURN:
				
				printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL connection has been closed unexpectedly\n"));
				result_errno = ECONNRESET;
				n = -1;
				break;
			default:
				printfPQExpBuffer(&conn->errorMessage, libpq_gettext("unrecognized SSL error code: %d\n"), err);

				
				result_errno = ECONNRESET;
				n = -1;
				break;
		}

		RESTORE_SIGPIPE(conn, spinfo);
	}
	else  {

		n = recv(conn->sock, ptr, len, 0);

		if (n < 0)
		{
			result_errno = SOCK_ERRNO;

			
			switch (result_errno)
			{

				case EAGAIN:


				case EWOULDBLOCK:

				case EINTR:
					
					break;


				case ECONNRESET:
					printfPQExpBuffer(&conn->errorMessage, libpq_gettext( "server closed the connection unexpectedly\n" "\tThis probably means the server terminated abnormally\n" "\tbefore or while processing the request.\n"));



					break;


				default:
					printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not receive data from server: %s\n"), SOCK_STRERROR(result_errno, sebuf, sizeof(sebuf)));


					break;
			}
		}
	}

	
	SOCK_ERRNO_SET(result_errno);

	return n;
}


ssize_t pqsecure_write(PGconn *conn, const void *ptr, size_t len)
{
	ssize_t		n;
	int			result_errno = 0;
	char		sebuf[256];

	DECLARE_SIGPIPE_INFO(spinfo);


	if (conn->ssl)
	{
		int			err;

		DISABLE_SIGPIPE(conn, spinfo, return -1);

		SOCK_ERRNO_SET(0);
		n = SSL_write(conn->ssl, ptr, len);
		err = SSL_get_error(conn->ssl, n);
		switch (err)
		{
			case SSL_ERROR_NONE:
				if (n < 0)
				{
					
					printfPQExpBuffer(&conn->errorMessage, "SSL_write failed but did not provide error information\n");
					
					result_errno = ECONNRESET;
				}
				break;
			case SSL_ERROR_WANT_READ:

				
				n = 0;
				break;
			case SSL_ERROR_WANT_WRITE:
				n = 0;
				break;
			case SSL_ERROR_SYSCALL:
				if (n < 0)
				{
					result_errno = SOCK_ERRNO;
					REMEMBER_EPIPE(spinfo, result_errno == EPIPE);
					if (result_errno == EPIPE || result_errno == ECONNRESET)
						printfPQExpBuffer(&conn->errorMessage, libpq_gettext( "server closed the connection unexpectedly\n" "\tThis probably means the server terminated abnormally\n" "\tbefore or while processing the request.\n"));



					else printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL SYSCALL error: %s\n"), SOCK_STRERROR(result_errno, sebuf, sizeof(sebuf)));



				}
				else {
					printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL SYSCALL error: EOF detected\n"));
					
					result_errno = ECONNRESET;
					n = -1;
				}
				break;
			case SSL_ERROR_SSL:
				{
					char	   *errm = SSLerrmessage();

					printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL error: %s\n"), errm);
					SSLerrfree(errm);
					
					result_errno = ECONNRESET;
					n = -1;
					break;
				}
			case SSL_ERROR_ZERO_RETURN:
				
				printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL connection has been closed unexpectedly\n"));
				result_errno = ECONNRESET;
				n = -1;
				break;
			default:
				printfPQExpBuffer(&conn->errorMessage, libpq_gettext("unrecognized SSL error code: %d\n"), err);

				
				result_errno = ECONNRESET;
				n = -1;
				break;
		}
	}
	else  {

		int			flags = 0;


		if (conn->sigpipe_flag)
			flags |= MSG_NOSIGNAL;

retry_masked:


		DISABLE_SIGPIPE(conn, spinfo, return -1);

		n = send(conn->sock, ptr, len, flags);

		if (n < 0)
		{
			result_errno = SOCK_ERRNO;

			

			if (flags != 0 && result_errno == EINVAL)
			{
				conn->sigpipe_flag = false;
				flags = 0;
				goto retry_masked;
			}


			
			switch (result_errno)
			{

				case EAGAIN:


				case EWOULDBLOCK:

				case EINTR:
					
					break;

				case EPIPE:
					
					REMEMBER_EPIPE(spinfo, true);
					


				case ECONNRESET:

					printfPQExpBuffer(&conn->errorMessage, libpq_gettext( "server closed the connection unexpectedly\n" "\tThis probably means the server terminated abnormally\n" "\tbefore or while processing the request.\n"));



					break;

				default:
					printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not send data to server: %s\n"), SOCK_STRERROR(result_errno, sebuf, sizeof(sebuf)));


					break;
			}
		}
	}

	RESTORE_SIGPIPE(conn, spinfo);

	
	SOCK_ERRNO_SET(result_errno);

	return n;
}







static int verify_cb(int ok, X509_STORE_CTX *ctx)
{
	return ok;
}



static int wildcard_certificate_match(const char *pattern, const char *string)
{
	int			lenpat = strlen(pattern);
	int			lenstr = strlen(string);

	
	if (lenpat < 3 || pattern[0] != '*' || pattern[1] != '.')

		return 0;

	if (lenpat > lenstr)
		
		return 0;

	if (pg_strcasecmp(pattern + 1, string + lenstr - lenpat + 1) != 0)

		
		return 0;

	if (strchr(string, '.') < string + lenstr - lenpat)

		
		return 0;

	
	return 1;
}



static bool verify_peer_name_matches_certificate(PGconn *conn)
{
	
	if (strcmp(conn->sslmode, "verify-full") != 0)
		return true;

	if (!(conn->pghost && conn->pghost[0] != '\0'))
	{
		printfPQExpBuffer(&conn->errorMessage, libpq_gettext("host name must be specified for a verified SSL connection\n"));
		return false;
	}
	else {
		
		if (pg_strcasecmp(conn->peer_cn, conn->pghost) == 0)
			
			return true;
		else if (wildcard_certificate_match(conn->peer_cn, conn->pghost))
			
			return true;
		else {
			printfPQExpBuffer(&conn->errorMessage, libpq_gettext("server common name \"%s\" does not match host name \"%s\"\n"), conn->peer_cn, conn->pghost);

			return false;
		}
	}
}




static unsigned long pq_threadidcallback(void)
{
	
	return (unsigned long) pthread_self();
}

static pthread_mutex_t *pq_lockarray;

static void pq_lockingcallback(int mode, int n, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
	{
		if (pthread_mutex_lock(&pq_lockarray[n]))
			PGTHREAD_ERROR("failed to lock mutex");
	}
	else {
		if (pthread_mutex_unlock(&pq_lockarray[n]))
			PGTHREAD_ERROR("failed to unlock mutex");
	}
}



static int init_ssl_system(PGconn *conn)
{


	
	if (ssl_config_mutex == NULL)
	{
		while (InterlockedExchange(&win32_ssl_create_mutex, 1) == 1)
			  ;
		if (ssl_config_mutex == NULL)
		{
			if (pthread_mutex_init(&ssl_config_mutex, NULL))
				return -1;
		}
		InterlockedExchange(&win32_ssl_create_mutex, 0);
	}

	if (pthread_mutex_lock(&ssl_config_mutex))
		return -1;

	if (pq_init_crypto_lib)
	{
		
		if (pq_lockarray == NULL)
		{
			int			i;

			pq_lockarray = malloc(sizeof(pthread_mutex_t) * CRYPTO_num_locks());
			if (!pq_lockarray)
			{
				pthread_mutex_unlock(&ssl_config_mutex);
				return -1;
			}
			for (i = 0; i < CRYPTO_num_locks(); i++)
			{
				if (pthread_mutex_init(&pq_lockarray[i], NULL))
				{
					free(pq_lockarray);
					pq_lockarray = NULL;
					pthread_mutex_unlock(&ssl_config_mutex);
					return -1;
				}
			}
		}

		if (ssl_open_connections++ == 0)
		{
			
			CRYPTO_set_id_callback(pq_threadidcallback);
			CRYPTO_set_locking_callback(pq_lockingcallback);
		}
	}


	if (!SSL_context)
	{
		if (pq_init_ssl_lib)
		{

			OPENSSL_config(NULL);

			SSL_library_init();
			SSL_load_error_strings();
		}

		SSL_context = SSL_CTX_new(TLSv1_method());
		if (!SSL_context)
		{
			char	   *err = SSLerrmessage();

			printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not create SSL context: %s\n"), err);

			SSLerrfree(err);

			pthread_mutex_unlock(&ssl_config_mutex);

			return -1;
		}

		
		SSL_CTX_set_mode(SSL_context, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	}


	pthread_mutex_unlock(&ssl_config_mutex);

	return 0;
}


static void destroy_ssl_system(void)
{

	
	if (pthread_mutex_lock(&ssl_config_mutex))
		return;

	if (pq_init_crypto_lib && ssl_open_connections > 0)
		--ssl_open_connections;

	if (pq_init_crypto_lib && ssl_open_connections == 0)
	{
		
		CRYPTO_set_locking_callback(NULL);
		CRYPTO_set_id_callback(NULL);

		
	}

	pthread_mutex_unlock(&ssl_config_mutex);

}


static int initialize_SSL(PGconn *conn)
{
	struct stat buf;
	char		homedir[MAXPGPATH];
	char		fnbuf[MAXPGPATH];
	char		sebuf[256];
	bool		have_homedir;
	bool		have_cert;
	EVP_PKEY   *pkey = NULL;

	
	if (!(conn->sslcert && strlen(conn->sslcert) > 0) || !(conn->sslkey && strlen(conn->sslkey) > 0) || !(conn->sslrootcert && strlen(conn->sslrootcert) > 0) || !(conn->sslcrl && strlen(conn->sslcrl) > 0))


		have_homedir = pqGetHomeDirectory(homedir, sizeof(homedir));
	else	 have_homedir = false;

	
	if (conn->sslcert && strlen(conn->sslcert) > 0)
		strncpy(fnbuf, conn->sslcert, sizeof(fnbuf));
	else if (have_homedir)
		snprintf(fnbuf, sizeof(fnbuf), "%s/%s", homedir, USER_CERT_FILE);
	else fnbuf[0] = '\0';

	if (fnbuf[0] == '\0')
	{
		
		have_cert = false;
	}
	else if (stat(fnbuf, &buf) != 0)
	{
		
		if (errno != ENOENT && errno != ENOTDIR)
		{
			printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not open certificate file \"%s\": %s\n"), fnbuf, pqStrerror(errno, sebuf, sizeof(sebuf)));

			return -1;
		}
		have_cert = false;
	}
	else {
		
		if (SSL_CTX_use_certificate_chain_file(SSL_context, fnbuf) != 1)
		{
			char	   *err = SSLerrmessage();

			printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not read certificate file \"%s\": %s\n"), fnbuf, err);

			SSLerrfree(err);
			return -1;
		}
		if (SSL_use_certificate_file(conn->ssl, fnbuf, SSL_FILETYPE_PEM) != 1)
		{
			char	   *err = SSLerrmessage();

			printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not read certificate file \"%s\": %s\n"), fnbuf, err);

			SSLerrfree(err);
			return -1;
		}
		
		have_cert = true;
	}

	
	if (have_cert && conn->sslkey && strlen(conn->sslkey) > 0)
	{

		if (strchr(conn->sslkey, ':')

			&& conn->sslkey[1] != ':'  )

		{
			
			char	   *engine_str = strdup(conn->sslkey);
			char	   *engine_colon = strchr(engine_str, ':');

			*engine_colon = '\0';		
			engine_colon++;		

			conn->engine = ENGINE_by_id(engine_str);
			if (conn->engine == NULL)
			{
				char	   *err = SSLerrmessage();

				printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not load SSL engine \"%s\": %s\n"), engine_str, err);

				SSLerrfree(err);
				free(engine_str);
				return -1;
			}

			if (ENGINE_init(conn->engine) == 0)
			{
				char	   *err = SSLerrmessage();

				printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not initialize SSL engine \"%s\": %s\n"), engine_str, err);

				SSLerrfree(err);
				ENGINE_free(conn->engine);
				conn->engine = NULL;
				free(engine_str);
				return -1;
			}

			pkey = ENGINE_load_private_key(conn->engine, engine_colon, NULL, NULL);
			if (pkey == NULL)
			{
				char	   *err = SSLerrmessage();

				printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not read private SSL key \"%s\" from engine \"%s\": %s\n"), engine_colon, engine_str, err);

				SSLerrfree(err);
				ENGINE_finish(conn->engine);
				ENGINE_free(conn->engine);
				conn->engine = NULL;
				free(engine_str);
				return -1;
			}
			if (SSL_use_PrivateKey(conn->ssl, pkey) != 1)
			{
				char	   *err = SSLerrmessage();

				printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not load private SSL key \"%s\" from engine \"%s\": %s\n"), engine_colon, engine_str, err);

				SSLerrfree(err);
				ENGINE_finish(conn->engine);
				ENGINE_free(conn->engine);
				conn->engine = NULL;
				free(engine_str);
				return -1;
			}

			free(engine_str);

			fnbuf[0] = '\0';	
		}
		else  {

			
			strncpy(fnbuf, conn->sslkey, sizeof(fnbuf));
		}
	}
	else if (have_homedir)
	{
		
		snprintf(fnbuf, sizeof(fnbuf), "%s/%s", homedir, USER_KEY_FILE);
	}
	else fnbuf[0] = '\0';

	if (have_cert && fnbuf[0] != '\0')
	{
		

		if (stat(fnbuf, &buf) != 0)
		{
			printfPQExpBuffer(&conn->errorMessage, libpq_gettext("certificate present, but not private key file \"%s\"\n"), fnbuf);

			return -1;
		}

		if (!S_ISREG(buf.st_mode) || buf.st_mode & (S_IRWXG | S_IRWXO))
		{
			printfPQExpBuffer(&conn->errorMessage, libpq_gettext("private key file \"%s\" has group or world access; permissions should be u=rw (0600) or less\n"), fnbuf);

			return -1;
		}


		if (SSL_use_PrivateKey_file(conn->ssl, fnbuf, SSL_FILETYPE_PEM) != 1)
		{
			char	   *err = SSLerrmessage();

			printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not load private key file \"%s\": %s\n"), fnbuf, err);

			SSLerrfree(err);
			return -1;
		}
	}

	
	if (have_cert && SSL_check_private_key(conn->ssl) != 1)
	{
		char	   *err = SSLerrmessage();

		printfPQExpBuffer(&conn->errorMessage, libpq_gettext("certificate does not match private key file \"%s\": %s\n"), fnbuf, err);

		SSLerrfree(err);
		return -1;
	}

	
	if (conn->sslrootcert && strlen(conn->sslrootcert) > 0)
		strncpy(fnbuf, conn->sslrootcert, sizeof(fnbuf));
	else if (have_homedir)
		snprintf(fnbuf, sizeof(fnbuf), "%s/%s", homedir, ROOT_CERT_FILE);
	else fnbuf[0] = '\0';

	if (fnbuf[0] != '\0' && stat(fnbuf, &buf) == 0)
	{
		X509_STORE *cvstore;

		if (SSL_CTX_load_verify_locations(SSL_context, fnbuf, NULL) != 1)
		{
			char	   *err = SSLerrmessage();

			printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not read root certificate file \"%s\": %s\n"), fnbuf, err);

			SSLerrfree(err);
			return -1;
		}

		if ((cvstore = SSL_CTX_get_cert_store(SSL_context)) != NULL)
		{
			if (conn->sslcrl && strlen(conn->sslcrl) > 0)
				strncpy(fnbuf, conn->sslcrl, sizeof(fnbuf));
			else if (have_homedir)
				snprintf(fnbuf, sizeof(fnbuf), "%s/%s", homedir, ROOT_CRL_FILE);
			else fnbuf[0] = '\0';

			
			if (fnbuf[0] != '\0' && X509_STORE_load_locations(cvstore, fnbuf, NULL) == 1)
			{
				

				X509_STORE_set_flags(cvstore, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);

				char	   *err = SSLerrmessage();

				printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL library does not support CRL certificates (file \"%s\")\n"), fnbuf);

				SSLerrfree(err);
				return -1;

			}
			
		}

		SSL_set_verify(conn->ssl, SSL_VERIFY_PEER, verify_cb);
	}
	else {
		
		if (conn->sslmode[0] == 'v')	
		{
			
			if (fnbuf[0] == '\0')
				printfPQExpBuffer(&conn->errorMessage, libpq_gettext("could not get home directory to locate root certificate file\n" "Either provide the file or change sslmode to disable server certificate verification.\n"));

			else printfPQExpBuffer(&conn->errorMessage, libpq_gettext("root certificate file \"%s\" does not exist\n" "Either provide the file or change sslmode to disable server certificate verification.\n"), fnbuf);


			return -1;
		}
	}

	

	if (conn->sslcompression && conn->sslcompression[0] == '0') {
		SSL_set_options(conn->ssl, SSL_OP_NO_COMPRESSION);
	}


	return 0;
}

static void destroySSL(void)
{
	destroy_ssl_system();
}


static PostgresPollingStatusType open_client_SSL(PGconn *conn)
{
	int			r;

	r = SSL_connect(conn->ssl);
	if (r <= 0)
	{
		int			err = SSL_get_error(conn->ssl, r);

		switch (err)
		{
			case SSL_ERROR_WANT_READ:
				return PGRES_POLLING_READING;

			case SSL_ERROR_WANT_WRITE:
				return PGRES_POLLING_WRITING;

			case SSL_ERROR_SYSCALL:
				{
					char		sebuf[256];

					if (r == -1)
						printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL SYSCALL error: %s\n"), SOCK_STRERROR(SOCK_ERRNO, sebuf, sizeof(sebuf)));

					else printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL SYSCALL error: EOF detected\n"));

					close_SSL(conn);
					return PGRES_POLLING_FAILED;
				}
			case SSL_ERROR_SSL:
				{
					char	   *err = SSLerrmessage();

					printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL error: %s\n"), err);

					SSLerrfree(err);
					close_SSL(conn);
					return PGRES_POLLING_FAILED;
				}

			default:
				printfPQExpBuffer(&conn->errorMessage, libpq_gettext("unrecognized SSL error code: %d\n"), err);

				close_SSL(conn);
				return PGRES_POLLING_FAILED;
		}
	}

	

	
	conn->peer = SSL_get_peer_certificate(conn->ssl);
	if (conn->peer == NULL)
	{
		char	   *err = SSLerrmessage();

		printfPQExpBuffer(&conn->errorMessage, libpq_gettext("certificate could not be obtained: %s\n"), err);

		SSLerrfree(err);
		close_SSL(conn);
		return PGRES_POLLING_FAILED;
	}

	X509_NAME_oneline(X509_get_subject_name(conn->peer), conn->peer_dn, sizeof(conn->peer_dn));
	conn->peer_dn[sizeof(conn->peer_dn) - 1] = '\0';

	r = X509_NAME_get_text_by_NID(X509_get_subject_name(conn->peer), NID_commonName, conn->peer_cn, SM_USER);
	conn->peer_cn[SM_USER] = '\0';		
	if (r == -1)
	{
		
		conn->peer_cn[0] = '\0';
	}
	else {
		
		if (r != strlen(conn->peer_cn))
		{
			printfPQExpBuffer(&conn->errorMessage, libpq_gettext("SSL certificate's common name contains embedded null\n"));
			close_SSL(conn);
			return PGRES_POLLING_FAILED;
		}
	}

	if (!verify_peer_name_matches_certificate(conn))
	{
		close_SSL(conn);
		return PGRES_POLLING_FAILED;
	}

	
	return PGRES_POLLING_OK;
}


static void close_SSL(PGconn *conn)
{
	if (conn->ssl)
	{
		DECLARE_SIGPIPE_INFO(spinfo);

		DISABLE_SIGPIPE(conn, spinfo, (void) 0);
		SSL_shutdown(conn->ssl);
		SSL_free(conn->ssl);
		conn->ssl = NULL;
		pqsecure_destroy();
		
		REMEMBER_EPIPE(spinfo, true);
		RESTORE_SIGPIPE(conn, spinfo);
	}

	if (conn->peer)
	{
		X509_free(conn->peer);
		conn->peer = NULL;
	}


	if (conn->engine)
	{
		ENGINE_finish(conn->engine);
		ENGINE_free(conn->engine);
		conn->engine = NULL;
	}

}


static char ssl_nomem[] = "out of memory allocating error description";



static char * SSLerrmessage(void)
{
	unsigned long errcode;
	const char *errreason;
	char	   *errbuf;

	errbuf = malloc(SSL_ERR_LEN);
	if (!errbuf)
		return ssl_nomem;
	errcode = ERR_get_error();
	if (errcode == 0)
	{
		snprintf(errbuf, SSL_ERR_LEN, libpq_gettext("no SSL error reported"));
		return errbuf;
	}
	errreason = ERR_reason_error_string(errcode);
	if (errreason != NULL)
	{
		strlcpy(errbuf, errreason, SSL_ERR_LEN);
		return errbuf;
	}
	snprintf(errbuf, SSL_ERR_LEN, libpq_gettext("SSL error code %lu"), errcode);
	return errbuf;
}

static void SSLerrfree(char *buf)
{
	if (buf != ssl_nomem)
		free(buf);
}


void * PQgetssl(PGconn *conn)
{
	if (!conn)
		return NULL;
	return conn->ssl;
}


void * PQgetssl(PGconn *conn)
{
	return NULL;
}






int pq_block_sigpipe(sigset_t *osigset, bool *sigpipe_pending)
{
	sigset_t	sigpipe_sigset;
	sigset_t	sigset;

	sigemptyset(&sigpipe_sigset);
	sigaddset(&sigpipe_sigset, SIGPIPE);

	
	SOCK_ERRNO_SET(pthread_sigmask(SIG_BLOCK, &sigpipe_sigset, osigset));
	if (SOCK_ERRNO)
		return -1;

	
	if (sigismember(osigset, SIGPIPE))
	{
		
		if (sigpending(&sigset) != 0)
			return -1;

		if (sigismember(&sigset, SIGPIPE))
			*sigpipe_pending = true;
		else *sigpipe_pending = false;
	}
	else *sigpipe_pending = false;

	return 0;
}


void pq_reset_sigpipe(sigset_t *osigset, bool sigpipe_pending, bool got_epipe)
{
	int			save_errno = SOCK_ERRNO;
	int			signo;
	sigset_t	sigset;

	
	if (got_epipe && !sigpipe_pending)
	{
		if (sigpending(&sigset) == 0 && sigismember(&sigset, SIGPIPE))
		{
			sigset_t	sigpipe_sigset;

			sigemptyset(&sigpipe_sigset);
			sigaddset(&sigpipe_sigset, SIGPIPE);

			sigwait(&sigpipe_sigset, &signo);
		}
	}

	
	pthread_sigmask(SIG_SETMASK, osigset, NULL);

	SOCK_ERRNO_SET(save_errno);
}


