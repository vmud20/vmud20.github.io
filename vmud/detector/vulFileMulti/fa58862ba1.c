










static const SSL_METHOD *ssl23_get_client_method(int ver);
static int ssl23_client_hello(SSL *s);
static int ssl23_get_server_hello(SSL *s);
static const SSL_METHOD *ssl23_get_client_method(int ver)
	{

	if (ver == SSL2_VERSION)
		return(SSLv2_client_method());

	if (ver == SSL3_VERSION)
		return(SSLv3_client_method());
	else if (ver == TLS1_VERSION)
		return(TLSv1_client_method());
	else if (ver == TLS1_1_VERSION)
		return(TLSv1_1_client_method());
	else if (ver == TLS1_2_VERSION)
		return(TLSv1_2_client_method());
	else return(NULL);
	}

IMPLEMENT_ssl23_meth_func(SSLv23_client_method, ssl_undefined_function, ssl23_connect, ssl23_get_client_method)



int ssl23_connect(SSL *s)
	{
	BUF_MEM *buf=NULL;
	unsigned long Time=(unsigned long)time(NULL);
	void (*cb)(const SSL *ssl,int type,int val)=NULL;
	int ret= -1;
	int new_state,state;

	RAND_add(&Time,sizeof(Time),0);
	ERR_clear_error();
	clear_sys_error();

	if (s->info_callback != NULL)
		cb=s->info_callback;
	else if (s->ctx->info_callback != NULL)
		cb=s->ctx->info_callback;
	
	s->in_handshake++;
	if (!SSL_in_init(s) || SSL_in_before(s)) SSL_clear(s); 

	for (;;)
		{
		state=s->state;

		switch(s->state)
			{
		case SSL_ST_BEFORE:
		case SSL_ST_CONNECT:
		case SSL_ST_BEFORE|SSL_ST_CONNECT:
		case SSL_ST_OK|SSL_ST_CONNECT:

			if (s->session != NULL)
				{
				SSLerr(SSL_F_SSL23_CONNECT,SSL_R_SSL23_DOING_SESSION_ID_REUSE);
				ret= -1;
				goto end;
				}
			s->server=0;
			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_START,1);

			
			s->type=SSL_ST_CONNECT;

			if (s->init_buf == NULL)
				{
				if ((buf=BUF_MEM_new()) == NULL)
					{
					ret= -1;
					goto end;
					}
				if (!BUF_MEM_grow(buf,SSL3_RT_MAX_PLAIN_LENGTH))
					{
					ret= -1;
					goto end;
					}
				s->init_buf=buf;
				buf=NULL;
				}

			if (!ssl3_setup_buffers(s)) { ret= -1; goto end; }

			ssl3_init_finished_mac(s);

			s->state=SSL23_ST_CW_CLNT_HELLO_A;
			s->ctx->stats.sess_connect++;
			s->init_num=0;
			break;

		case SSL23_ST_CW_CLNT_HELLO_A:
		case SSL23_ST_CW_CLNT_HELLO_B:

			s->shutdown=0;
			ret=ssl23_client_hello(s);
			if (ret <= 0) goto end;
			s->state=SSL23_ST_CR_SRVR_HELLO_A;
			s->init_num=0;

			break;

		case SSL23_ST_CR_SRVR_HELLO_A:
		case SSL23_ST_CR_SRVR_HELLO_B:
			ret=ssl23_get_server_hello(s);
			if (ret >= 0) cb=NULL;
			goto end;
			

		default:
			SSLerr(SSL_F_SSL23_CONNECT,SSL_R_UNKNOWN_STATE);
			ret= -1;
			goto end;
			
			}

		if (s->debug) { (void)BIO_flush(s->wbio); }

		if ((cb != NULL) && (s->state != state))
			{
			new_state=s->state;
			s->state=state;
			cb(s,SSL_CB_CONNECT_LOOP,1);
			s->state=new_state;
			}
		}
end:
	s->in_handshake--;
	if (buf != NULL)
		BUF_MEM_free(buf);
	if (cb != NULL)
		cb(s,SSL_CB_CONNECT_EXIT,ret);
	return(ret);
	}

static int ssl23_no_ssl2_ciphers(SSL *s)
	{
	SSL_CIPHER *cipher;
	STACK_OF(SSL_CIPHER) *ciphers;
	int i;
	ssl_set_client_disabled(s);
	ciphers = SSL_get_ciphers(s);
	for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++)
		{
		cipher = sk_SSL_CIPHER_value(ciphers, i);
		if (ssl_cipher_disabled(s, cipher, SSL_SECOP_CIPHER_SUPPORTED))
			continue;
		if (cipher->algorithm_ssl == SSL_SSLV2)
			return 0;
		}
	return 1;
	}


int ssl_fill_hello_random(SSL *s, int server, unsigned char *result, int len)
	{
		int send_time = 0;
		if (len < 4)
			return 0;
		if (server)
			send_time = (s->mode & SSL_MODE_SEND_SERVERHELLO_TIME) != 0;
		else send_time = (s->mode & SSL_MODE_SEND_CLIENTHELLO_TIME) != 0;
		if (send_time)
			{
			unsigned long Time = (unsigned long)time(NULL);
			unsigned char *p = result;
			l2n(Time, p);
			return RAND_pseudo_bytes(p, len-4);
			}
		else return RAND_pseudo_bytes(result, len);
	}

static int ssl23_client_hello(SSL *s)
	{
	unsigned char *buf;
	unsigned char *p,*d;
	int i,ch_len;
	unsigned long l;
	int ssl2_compat;
	int version = 0, version_major, version_minor;
	int al = 0;

	int j;
	SSL_COMP *comp;

	int ret;
	unsigned long mask, options = s->options;

	ssl2_compat = (options & SSL_OP_NO_SSLv2) ? 0 : 1;

	if (ssl2_compat && !ssl_security(s, SSL_SECOP_SSL2_COMPAT, 0, 0, NULL))
		ssl2_compat = 0;
	if (ssl2_compat && ssl23_no_ssl2_ciphers(s))
		ssl2_compat = 0;

	
	mask =	SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1  |SSL_OP_NO_SSLv3   |(ssl2_compat?SSL_OP_NO_SSLv2:0)





		;

	version = TLS1_2_VERSION;

	if ((options & SSL_OP_NO_TLSv1_2) && (options & mask) != mask)
		version = TLS1_1_VERSION;

	version = TLS1_1_VERSION;

	mask &= ~SSL_OP_NO_TLSv1_1;
	if ((options & SSL_OP_NO_TLSv1_1) && (options & mask) != mask)
		version = TLS1_VERSION;
	mask &= ~SSL_OP_NO_TLSv1;

	if ((options & SSL_OP_NO_TLSv1) && (options & mask) != mask)
		version = SSL3_VERSION;
	mask &= ~SSL_OP_NO_SSLv3;


	if ((options & SSL_OP_NO_SSLv3) && (options & mask) != mask)
		version = SSL2_VERSION;



	if (version != SSL2_VERSION)
		{
		

		if (s->tlsext_hostname != NULL)
			ssl2_compat = 0;
		if (s->tlsext_status_type != -1)
			ssl2_compat = 0;

		if (s->ctx->tlsext_opaque_prf_input_callback != 0 || s->tlsext_opaque_prf_input != NULL)
			ssl2_compat = 0;

		if (s->cert->cli_ext.meths_count != 0)
			ssl2_compat = 0;
		}


	buf=(unsigned char *)s->init_buf->data;
	if (s->state == SSL23_ST_CW_CLNT_HELLO_A)
		{

		
		if (!ssl_get_new_session(s,0))
			{
			return(-1);
			}


		p=s->s3->client_random;
		if (ssl_fill_hello_random(s, 0, p, SSL3_RANDOM_SIZE) <= 0)
			return -1;

		if (version == TLS1_2_VERSION)
			{
			version_major = TLS1_2_VERSION_MAJOR;
			version_minor = TLS1_2_VERSION_MINOR;
			}
		else if (tls1_suiteb(s))
			{
			SSLerr(SSL_F_SSL23_CLIENT_HELLO, SSL_R_ONLY_TLS_1_2_ALLOWED_IN_SUITEB_MODE);
			return -1;
			}
		else if (version == TLS1_1_VERSION)
			{
			version_major = TLS1_1_VERSION_MAJOR;
			version_minor = TLS1_1_VERSION_MINOR;
			}
		else if (version == TLS1_VERSION)
			{
			version_major = TLS1_VERSION_MAJOR;
			version_minor = TLS1_VERSION_MINOR;
			}

		else if(FIPS_mode())
			{
			SSLerr(SSL_F_SSL23_CLIENT_HELLO, SSL_R_ONLY_TLS_ALLOWED_IN_FIPS_MODE);
			return -1;
			}

		else if (version == SSL3_VERSION)
			{
			version_major = SSL3_VERSION_MAJOR;
			version_minor = SSL3_VERSION_MINOR;
			}
		else if (version == SSL2_VERSION)
			{
			version_major = SSL2_VERSION_MAJOR;
			version_minor = SSL2_VERSION_MINOR;
			}
		else {
			SSLerr(SSL_F_SSL23_CLIENT_HELLO,SSL_R_NO_PROTOCOLS_AVAILABLE);
			return(-1);
			}

		s->client_version = version;

		if (ssl2_compat)
			{
			

			
			d = &(buf[2]);
			p = d + 9; 

			*(d++) = SSL2_MT_CLIENT_HELLO;
			*(d++) = version_major;
			*(d++) = version_minor;
			
			
			i=ssl_cipher_list_to_bytes(s,SSL_get_ciphers(s),p,0);
			if (i == 0)
				{
				
				SSLerr(SSL_F_SSL23_CLIENT_HELLO,SSL_R_NO_CIPHERS_AVAILABLE);
				return -1;
				}
			s2n(i,d);
			p+=i;
			
			

			s->session->session_id_length=0;

			s2n(0,d);

			if (s->options & SSL_OP_NETSCAPE_CHALLENGE_BUG)
				ch_len=SSL2_CHALLENGE_LENGTH;
			else ch_len=SSL2_MAX_CHALLENGE_LENGTH;

			
			
			if (SSL3_RANDOM_SIZE < ch_len)
				i=SSL3_RANDOM_SIZE;
			else i=ch_len;
			s2n(i,d);
			memset(&(s->s3->client_random[0]),0,SSL3_RANDOM_SIZE);
			if (RAND_pseudo_bytes(&(s->s3->client_random[SSL3_RANDOM_SIZE-i]),i) <= 0)
				return -1;

			memcpy(p,&(s->s3->client_random[SSL3_RANDOM_SIZE-i]),i);
			p+=i;

			i= p- &(buf[2]);
			buf[0]=((i>>8)&0xff)|0x80;
			buf[1]=(i&0xff);

			
			s->init_num=i+2;
			s->init_off=0;

			ssl3_finish_mac(s,&(buf[2]),i);
			}
		else {
			

			
			d = p = &(buf[9]);
			
			*(p++) = version_major;
			*(p++) = version_minor;

			
			memcpy(p, s->s3->client_random, SSL3_RANDOM_SIZE);
			p += SSL3_RANDOM_SIZE;

			
			*(p++) = 0;

			
			i=ssl_cipher_list_to_bytes(s,SSL_get_ciphers(s),&(p[2]),ssl3_put_cipher_by_char);
			if (i == 0)
				{
				SSLerr(SSL_F_SSL23_CLIENT_HELLO,SSL_R_NO_CIPHERS_AVAILABLE);
				return -1;
				}

			
			if (TLS1_get_version(s) >= TLS1_2_VERSION && i > OPENSSL_MAX_TLS1_2_CIPHER_LENGTH)
				i = OPENSSL_MAX_TLS1_2_CIPHER_LENGTH & ~1;

			s2n(i,p);
			p+=i;

			

			*(p++)=1;

			if (!ssl_allow_compression(s) || !s->ctx->comp_methods)
				j=0;
			else j=sk_SSL_COMP_num(s->ctx->comp_methods);
			*(p++)=1+j;
			for (i=0; i<j; i++)
				{
				comp=sk_SSL_COMP_value(s->ctx->comp_methods,i);
				*(p++)=comp->id;
				}

			*(p++)=0; 


			
			if (ssl_prepare_clienthello_tlsext(s) <= 0)
				{
				SSLerr(SSL_F_SSL23_CLIENT_HELLO,SSL_R_CLIENTHELLO_TLSEXT);
				return -1;
				}
			if ((p = ssl_add_clienthello_tlsext(s, p, buf+SSL3_RT_MAX_PLAIN_LENGTH, &al)) == NULL)
				{
				ssl3_send_alert(s,SSL3_AL_FATAL,al);
				SSLerr(SSL_F_SSL23_CLIENT_HELLO,ERR_R_INTERNAL_ERROR);
				return -1;
				}

			
			l = p-d;

			
			d=&(buf[5]);
			*(d++)=SSL3_MT_CLIENT_HELLO;
			l2n3(l,d);

			l += 4;

			if (l > SSL3_RT_MAX_PLAIN_LENGTH)
				{
				SSLerr(SSL_F_SSL23_CLIENT_HELLO,ERR_R_INTERNAL_ERROR);
				return -1;
				}
			
			
			d=buf;
			*(d++) = SSL3_RT_HANDSHAKE;
			*(d++) = version_major;
			
			if (TLS1_get_client_version(s) > TLS1_VERSION)
				*(d++) = 1;
			else *(d++) = version_minor;
			s2n((int)l,d);

			
			s->init_num=p-buf;
			s->init_off=0;

			ssl3_finish_mac(s,&(buf[5]), s->init_num - 5);
			}

		s->state=SSL23_ST_CW_CLNT_HELLO_B;
		s->init_off=0;
		}

	
	ret = ssl23_write_bytes(s);

	if ((ret >= 2) && s->msg_callback)
		{
		

		if (ssl2_compat)
			s->msg_callback(1, SSL2_VERSION, 0, s->init_buf->data+2, ret-2, s, s->msg_callback_arg);
		else {
			s->msg_callback(1, version, SSL3_RT_HEADER, s->init_buf->data, 5, s, s->msg_callback_arg);
			s->msg_callback(1, version, SSL3_RT_HANDSHAKE, s->init_buf->data+5, ret-5, s, s->msg_callback_arg);
			}
		}

	return ret;
	}

static int ssl23_get_server_hello(SSL *s)
	{
	char buf[8];
	unsigned char *p;
	int i;
	int n;

	n=ssl23_read_bytes(s,7);

	if (n != 7) return(n);
	p=s->packet;

	memcpy(buf,p,n);

	if ((p[0] & 0x80) && (p[2] == SSL2_MT_SERVER_HELLO) && (p[5] == 0x00) && (p[6] == 0x02))
		{

		SSLerr(SSL_F_SSL23_GET_SERVER_HELLO,SSL_R_UNSUPPORTED_PROTOCOL);
		goto err;

		
		
		int ch_len;

		if (s->options & SSL_OP_NO_SSLv2)
			{
			SSLerr(SSL_F_SSL23_GET_SERVER_HELLO,SSL_R_UNSUPPORTED_PROTOCOL);
			goto err;
			}
		if (s->s2 == NULL)
			{
			if (!ssl2_new(s))
				goto err;
			}
		else ssl2_clear(s);

		if (s->options & SSL_OP_NETSCAPE_CHALLENGE_BUG)
			ch_len=SSL2_CHALLENGE_LENGTH;
		else ch_len=SSL2_MAX_CHALLENGE_LENGTH;

		
		
		i=(SSL3_RANDOM_SIZE < ch_len)
			?SSL3_RANDOM_SIZE:ch_len;
		s->s2->challenge_length=i;
		memcpy(s->s2->challenge, &(s->s3->client_random[SSL3_RANDOM_SIZE-i]),i);

		if (s->s3 != NULL) ssl3_free(s);

		if (!BUF_MEM_grow_clean(s->init_buf, SSL2_MAX_RECORD_LENGTH_3_BYTE_HEADER))
			{
			SSLerr(SSL_F_SSL23_GET_SERVER_HELLO,ERR_R_BUF_LIB);
			goto err;
			}

		s->state=SSL2_ST_GET_SERVER_HELLO_A;
		if (!(s->client_version == SSL2_VERSION))
			
			s->s2->ssl2_rollback=1;

		
		s->rstate=SSL_ST_READ_HEADER;
		s->packet_length=n;
		s->packet= &(s->s2->rbuf[0]);
		memcpy(s->packet,buf,n);
		s->s2->rbuf_left=n;
		s->s2->rbuf_offs=0;

		
		s->s2->write_sequence=1;

		s->method=SSLv2_client_method();
		s->handshake_func=s->method->ssl_connect;

		}
	else if (p[1] == SSL3_VERSION_MAJOR && p[2] <= TLS1_2_VERSION_MINOR && ((p[0] == SSL3_RT_HANDSHAKE && p[5] == SSL3_MT_SERVER_HELLO) || (p[0] == SSL3_RT_ALERT && p[3] == 0 && p[4] == 2)))


		{
		

		if ((p[2] == SSL3_VERSION_MINOR) && !(s->options & SSL_OP_NO_SSLv3))
			{

			if(FIPS_mode())
				{
				SSLerr(SSL_F_SSL23_GET_SERVER_HELLO, SSL_R_ONLY_TLS_ALLOWED_IN_FIPS_MODE);
				goto err;
				}

			s->version=SSL3_VERSION;
			s->method=SSLv3_client_method();
			}
		else if ((p[2] == TLS1_VERSION_MINOR) && !(s->options & SSL_OP_NO_TLSv1))
			{
			s->version=TLS1_VERSION;
			s->method=TLSv1_client_method();
			}
		else if ((p[2] == TLS1_1_VERSION_MINOR) && !(s->options & SSL_OP_NO_TLSv1_1))
			{
			s->version=TLS1_1_VERSION;
			s->method=TLSv1_1_client_method();
			}
		else if ((p[2] == TLS1_2_VERSION_MINOR) && !(s->options & SSL_OP_NO_TLSv1_2))
			{
			s->version=TLS1_2_VERSION;
			s->method=TLSv1_2_client_method();
			}
		else {
			SSLerr(SSL_F_SSL23_GET_SERVER_HELLO,SSL_R_UNSUPPORTED_PROTOCOL);
			goto err;
			}

		
		OPENSSL_assert(s->version <= TLS_MAX_VERSION);

		if (!ssl_security(s, SSL_SECOP_VERSION, 0, s->version, NULL))
			{
			SSLerr(SSL_F_SSL23_GET_SERVER_HELLO,SSL_R_VERSION_TOO_LOW);
			goto err;
			}

		if (p[0] == SSL3_RT_ALERT && p[5] != SSL3_AL_WARNING)
			{
			

			void (*cb)(const SSL *ssl,int type,int val)=NULL;
			int j;

			if (s->info_callback != NULL)
				cb=s->info_callback;
			else if (s->ctx->info_callback != NULL)
				cb=s->ctx->info_callback;
 
			i=p[5];
			if (cb != NULL)
				{
				j=(i<<8)|p[6];
				cb(s,SSL_CB_READ_ALERT,j);
				}
			
			if (s->msg_callback)
				{
				s->msg_callback(0, s->version, SSL3_RT_HEADER, p, 5, s, s->msg_callback_arg);
				s->msg_callback(0, s->version, SSL3_RT_ALERT, p+5, 2, s, s->msg_callback_arg);
				}

			s->rwstate=SSL_NOTHING;
			SSLerr(SSL_F_SSL23_GET_SERVER_HELLO,SSL_AD_REASON_OFFSET+p[6]);
			goto err;
			}

		if (!ssl_init_wbio_buffer(s,1)) goto err;

		
		s->state=SSL3_ST_CR_SRVR_HELLO_A;

		
		s->rstate=SSL_ST_READ_HEADER;
		s->packet_length=n;
		if (s->s3->rbuf.buf == NULL)
			if (!ssl3_setup_read_buffer(s))
				goto err;
		s->packet= &(s->s3->rbuf.buf[0]);
		memcpy(s->packet,buf,n);
		s->s3->rbuf.left=n;
		s->s3->rbuf.offset=0;

		s->handshake_func=s->method->ssl_connect;
		}
	else {
		SSLerr(SSL_F_SSL23_GET_SERVER_HELLO,SSL_R_UNKNOWN_PROTOCOL);
		goto err;
		}
	s->init_num=0;

	
	if (!ssl_get_new_session(s,0))
		goto err;

	return(SSL_connect(s));
err:
	return(-1);
	}
