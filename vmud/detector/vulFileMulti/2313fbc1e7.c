





















static int ca_dn_cmp(const X509_NAME * const *a,const X509_NAME * const *b);


static const SSL_METHOD *ssl3_get_client_method(int ver)
	{
	if (ver == SSL3_VERSION)
		return(SSLv3_client_method());
	else return(NULL);
	}

IMPLEMENT_ssl3_meth_func(SSLv3_client_method, ssl_undefined_function, ssl3_connect, ssl3_get_client_method)




int ssl3_connect(SSL *s)
	{
	BUF_MEM *buf=NULL;
	unsigned long Time=(unsigned long)time(NULL);
	void (*cb)(const SSL *ssl,int type,int val)=NULL;
	int ret= -1;
	int new_state,state,skip=0;

	RAND_add(&Time,sizeof(Time),0);
	ERR_clear_error();
	clear_sys_error();

	if (s->info_callback != NULL)
		cb=s->info_callback;
	else if (s->ctx->info_callback != NULL)
		cb=s->ctx->info_callback;
	
	s->in_handshake++;
	if (!SSL_in_init(s) || SSL_in_before(s)) SSL_clear(s); 


	
	if (s->tlsext_hb_pending)
		{
		s->tlsext_hb_pending = 0;
		s->tlsext_hb_seq++;
		}


	for (;;)
		{
		state=s->state;

		switch(s->state)
			{
		case SSL_ST_RENEGOTIATE:
			s->renegotiate=1;
			s->state=SSL_ST_CONNECT;
			s->ctx->stats.sess_connect_renegotiate++;
			
		case SSL_ST_BEFORE:
		case SSL_ST_CONNECT:
		case SSL_ST_BEFORE|SSL_ST_CONNECT:
		case SSL_ST_OK|SSL_ST_CONNECT:

			s->server=0;
			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_START,1);

			if ((s->version & 0xff00 ) != 0x0300)
				{
				SSLerr(SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
				ret = -1;
				goto end;
				}

			if (!ssl_security(s, SSL_SECOP_VERSION, 0, s->version, NULL))
				{
				SSLerr(SSL_F_SSL3_CONNECT, SSL_R_VERSION_TOO_LOW);
				return -1;
				}
				
			
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

			
			if (!ssl_init_wbio_buffer(s,0)) { ret= -1; goto end; }

			

			ssl3_init_finished_mac(s);

			s->state=SSL3_ST_CW_CLNT_HELLO_A;
			s->ctx->stats.sess_connect++;
			s->init_num=0;
			s->s3->flags &= ~SSL3_FLAGS_CCS_OK;
			
			s->s3->change_cipher_spec = 0;
			break;

		case SSL3_ST_CW_CLNT_HELLO_A:
		case SSL3_ST_CW_CLNT_HELLO_B:

			s->shutdown=0;
			ret=ssl3_client_hello(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CR_SRVR_HELLO_A;
			s->init_num=0;

			
			if (s->bbio != s->wbio)
				s->wbio=BIO_push(s->bbio,s->wbio);

			break;

		case SSL3_ST_CR_SRVR_HELLO_A:
		case SSL3_ST_CR_SRVR_HELLO_B:
			ret=ssl3_get_server_hello(s);
			if (ret <= 0) goto end;

			if (s->hit)
				{
				s->state=SSL3_ST_CR_FINISHED_A;

				if (s->tlsext_ticket_expected)
					{
					
					s->state=SSL3_ST_CR_SESSION_TICKET_A;
					}

				}
			else {
					s->state=SSL3_ST_CR_CERT_A;
				}
			s->init_num=0;
			break;
		case SSL3_ST_CR_CERT_A:
		case SSL3_ST_CR_CERT_B:
			
			
			if (!(s->s3->tmp.new_cipher->algorithm_auth & (SSL_aNULL|SSL_aSRP)) && !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK))
				{
				ret=ssl3_get_server_certificate(s);
				if (ret <= 0) goto end;

				if (s->tlsext_status_expected)
					s->state=SSL3_ST_CR_CERT_STATUS_A;
				else s->state=SSL3_ST_CR_KEY_EXCH_A;
				}
			else {
				skip = 1;
				s->state=SSL3_ST_CR_KEY_EXCH_A;
				}

				}
			else skip=1;

			s->state=SSL3_ST_CR_KEY_EXCH_A;

			s->init_num=0;
			break;

		case SSL3_ST_CR_KEY_EXCH_A:
		case SSL3_ST_CR_KEY_EXCH_B:
			ret=ssl3_get_key_exchange(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CR_CERT_REQ_A;
			s->init_num=0;

			
			if (!ssl3_check_cert_and_algorithm(s))
				{
				ret= -1;
				goto end;
				}
			break;

		case SSL3_ST_CR_CERT_REQ_A:
		case SSL3_ST_CR_CERT_REQ_B:
			ret=ssl3_get_certificate_request(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CR_SRVR_DONE_A;
			s->init_num=0;
			break;

		case SSL3_ST_CR_SRVR_DONE_A:
		case SSL3_ST_CR_SRVR_DONE_B:
			ret=ssl3_get_server_done(s);
			if (ret <= 0) goto end;

			if (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kSRP)
				{
				if ((ret = SRP_Calc_A_param(s))<=0)
					{
					SSLerr(SSL_F_SSL3_CONNECT,SSL_R_SRP_A_CALC);
					ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_INTERNAL_ERROR);
					goto end;
					}
				}

			if (s->s3->tmp.cert_req)
				s->state=SSL3_ST_CW_CERT_A;
			else s->state=SSL3_ST_CW_KEY_EXCH_A;
			s->init_num=0;

			break;

		case SSL3_ST_CW_CERT_A:
		case SSL3_ST_CW_CERT_B:
		case SSL3_ST_CW_CERT_C:
		case SSL3_ST_CW_CERT_D:
			ret=ssl3_send_client_certificate(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CW_KEY_EXCH_A;
			s->init_num=0;
			break;

		case SSL3_ST_CW_KEY_EXCH_A:
		case SSL3_ST_CW_KEY_EXCH_B:
			ret=ssl3_send_client_key_exchange(s);
			if (ret <= 0) goto end;
			
			
			
			if (s->s3->tmp.cert_req == 1)
				{
				s->state=SSL3_ST_CW_CERT_VRFY_A;
				}
			else {
				s->state=SSL3_ST_CW_CHANGE_A;
				}
			if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY)
				{
				s->state=SSL3_ST_CW_CHANGE_A;
				}

			s->init_num=0;
			break;

		case SSL3_ST_CW_CERT_VRFY_A:
		case SSL3_ST_CW_CERT_VRFY_B:
			ret=ssl3_send_client_verify(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CW_CHANGE_A;
			s->init_num=0;
			break;

		case SSL3_ST_CW_CHANGE_A:
		case SSL3_ST_CW_CHANGE_B:
			ret=ssl3_send_change_cipher_spec(s, SSL3_ST_CW_CHANGE_A,SSL3_ST_CW_CHANGE_B);
			if (ret <= 0) goto end;


			s->state=SSL3_ST_CW_FINISHED_A;

			if (s->s3->next_proto_neg_seen)
				s->state=SSL3_ST_CW_NEXT_PROTO_A;
			else s->state=SSL3_ST_CW_FINISHED_A;

			s->init_num=0;

			s->session->cipher=s->s3->tmp.new_cipher;

			s->session->compress_meth=0;

			if (s->s3->tmp.new_compression == NULL)
				s->session->compress_meth=0;
			else s->session->compress_meth= s->s3->tmp.new_compression->id;


			if (!s->method->ssl3_enc->setup_key_block(s))
				{
				ret= -1;
				goto end;
				}

			if (!s->method->ssl3_enc->change_cipher_state(s, SSL3_CHANGE_CIPHER_CLIENT_WRITE))
				{
				ret= -1;
				goto end;
				}

			break;


		case SSL3_ST_CW_NEXT_PROTO_A:
		case SSL3_ST_CW_NEXT_PROTO_B:
			ret=ssl3_send_next_proto(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CW_FINISHED_A;
			break;


		case SSL3_ST_CW_FINISHED_A:
		case SSL3_ST_CW_FINISHED_B:
			ret=ssl3_send_finished(s, SSL3_ST_CW_FINISHED_A,SSL3_ST_CW_FINISHED_B, s->method->ssl3_enc->client_finished_label, s->method->ssl3_enc->client_finished_label_len);


			if (ret <= 0) goto end;
			s->state=SSL3_ST_CW_FLUSH;

			
			s->s3->flags&= ~SSL3_FLAGS_POP_BUFFER;
			if (s->hit)
				{
				s->s3->tmp.next_state=SSL_ST_OK;
				if (s->s3->flags & SSL3_FLAGS_DELAY_CLIENT_FINISHED)
					{
					s->state=SSL_ST_OK;
					s->s3->flags|=SSL3_FLAGS_POP_BUFFER;
					s->s3->delay_buf_pop_ret=0;
					}
				}
			else {

				
				if (s->tlsext_ticket_expected)
					s->s3->tmp.next_state=SSL3_ST_CR_SESSION_TICKET_A;
				else   s->s3->tmp.next_state=SSL3_ST_CR_FINISHED_A;


				}
			s->init_num=0;
			break;


		case SSL3_ST_CR_SESSION_TICKET_A:
		case SSL3_ST_CR_SESSION_TICKET_B:
			ret=ssl3_get_new_session_ticket(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CR_FINISHED_A;
			s->init_num=0;
		break;

		case SSL3_ST_CR_CERT_STATUS_A:
		case SSL3_ST_CR_CERT_STATUS_B:
			ret=ssl3_get_cert_status(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_CR_KEY_EXCH_A;
			s->init_num=0;
		break;


		case SSL3_ST_CR_FINISHED_A:
		case SSL3_ST_CR_FINISHED_B:
			s->s3->flags |= SSL3_FLAGS_CCS_OK;
			ret=ssl3_get_finished(s,SSL3_ST_CR_FINISHED_A, SSL3_ST_CR_FINISHED_B);
			if (ret <= 0) goto end;

			if (s->hit)
				s->state=SSL3_ST_CW_CHANGE_A;
			else s->state=SSL_ST_OK;
			s->init_num=0;
			break;

		case SSL3_ST_CW_FLUSH:
			s->rwstate=SSL_WRITING;
			if (BIO_flush(s->wbio) <= 0)
				{
				ret= -1;
				goto end;
				}
			s->rwstate=SSL_NOTHING;
			s->state=s->s3->tmp.next_state;
			break;

		case SSL_ST_OK:
			
			ssl3_cleanup_key_block(s);

			if (s->init_buf != NULL)
				{
				BUF_MEM_free(s->init_buf);
				s->init_buf=NULL;
				}

			
			if (!(s->s3->flags & SSL3_FLAGS_POP_BUFFER))
				ssl_free_wbio_buffer(s);
			

			s->init_num=0;
			s->renegotiate=0;
			s->new_session=0;

			ssl_update_cache(s,SSL_SESS_CACHE_CLIENT);
			if (s->hit) s->ctx->stats.sess_hit++;

			ret=1;
			
			s->handshake_func=ssl3_connect;
			s->ctx->stats.sess_connect_good++;

			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_DONE,1);

			goto end;
			
			
		default:
			SSLerr(SSL_F_SSL3_CONNECT,SSL_R_UNKNOWN_STATE);
			ret= -1;
			goto end;
			
			}

		
		if (!s->s3->tmp.reuse_message && !skip)
			{
			if (s->debug)
				{
				if ((ret=BIO_flush(s->wbio)) <= 0)
					goto end;
				}

			if ((cb != NULL) && (s->state != state))
				{
				new_state=s->state;
				s->state=state;
				cb(s,SSL_CB_CONNECT_LOOP,1);
				s->state=new_state;
				}
			}
		skip=0;
		}
end:
	s->in_handshake--;
	if (buf != NULL)
		BUF_MEM_free(buf);
	if (cb != NULL)
		cb(s,SSL_CB_CONNECT_EXIT,ret);
	return(ret);
	}


int ssl3_client_hello(SSL *s)
	{
	unsigned char *buf;
	unsigned char *p,*d;
	int i;
	unsigned long l;
	int al = 0;

	int j;
	SSL_COMP *comp;


	buf=(unsigned char *)s->init_buf->data;
	if (s->state == SSL3_ST_CW_CLNT_HELLO_A)
		{
		SSL_SESSION *sess = s->session;
		if ((sess == NULL) || (sess->ssl_version != s->version) || !sess->session_id_length || (sess->not_resumable))


			{
			if (!ssl_get_new_session(s,0))
				goto err;
			}
		if (s->method->version == DTLS_ANY_VERSION)
			{
			
			int options = s->options;
			
			if (options & SSL_OP_NO_DTLSv1_2)
				{
				if (tls1_suiteb(s))
					{
					SSLerr(SSL_F_SSL3_CLIENT_HELLO, SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE);
					goto err;
					}
				
				if (options & SSL_OP_NO_DTLSv1)
					{
					SSLerr(SSL_F_SSL3_CLIENT_HELLO,SSL_R_WRONG_SSL_VERSION);
					goto err;
					}
				
				s->method = DTLSv1_client_method();
				s->version = DTLS1_VERSION;
				}
			else {
				
				if (options & SSL_OP_NO_DTLSv1)
					s->method = DTLSv1_2_client_method();
				s->version = DTLS1_2_VERSION;
				}
			s->client_version = s->version;
			}
		

		p=s->s3->client_random;

		
		if (SSL_IS_DTLS(s))
			{
			size_t idx;
			i = 1;
			for (idx=0; idx < sizeof(s->s3->client_random); idx++)
				{
				if (p[idx])
					{
					i = 0;
					break;
					}
				}
			}
		else  i = 1;

		if (i)
			ssl_fill_hello_random(s, 0, p, sizeof(s->s3->client_random));

		
		d=p= ssl_handshake_start(s);

		

		*(p++)=s->version>>8;
		*(p++)=s->version&0xff;
		s->client_version=s->version;

		*(p++)=s->client_version>>8;
		*(p++)=s->client_version&0xff;


		
		memcpy(p,s->s3->client_random,SSL3_RANDOM_SIZE);
		p+=SSL3_RANDOM_SIZE;

		
		if (s->new_session)
			i=0;
		else i=s->session->session_id_length;
		*(p++)=i;
		if (i != 0)
			{
			if (i > (int)sizeof(s->session->session_id))
				{
				SSLerr(SSL_F_SSL3_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
				goto err;
				}
			memcpy(p,s->session->session_id,i);
			p+=i;
			}
		
		
		if (SSL_IS_DTLS(s))
			{
			if ( s->d1->cookie_len > sizeof(s->d1->cookie))
				{
				SSLerr(SSL_F_SSL3_CLIENT_HELLO, ERR_R_INTERNAL_ERROR);
				goto err;
				}
			*(p++) = s->d1->cookie_len;
			memcpy(p, s->d1->cookie, s->d1->cookie_len);
			p += s->d1->cookie_len;
			}
		
		
		i=ssl_cipher_list_to_bytes(s,SSL_get_ciphers(s),&(p[2]),0);
		if (i == 0)
			{
			SSLerr(SSL_F_SSL3_CLIENT_HELLO,SSL_R_NO_CIPHERS_AVAILABLE);
			goto err;
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
			SSLerr(SSL_F_SSL3_CLIENT_HELLO,SSL_R_CLIENTHELLO_TLSEXT);
			goto err;
			}
		if ((p = ssl_add_clienthello_tlsext(s, p, buf+SSL3_RT_MAX_PLAIN_LENGTH, &al)) == NULL)
			{
			ssl3_send_alert(s,SSL3_AL_FATAL,al);
			SSLerr(SSL_F_SSL3_CLIENT_HELLO,ERR_R_INTERNAL_ERROR);
			goto err;
			}

		
		l= p-d;
		ssl_set_handshake_header(s, SSL3_MT_CLIENT_HELLO, l);
		s->state=SSL3_ST_CW_CLNT_HELLO_B;
		}

	
	return ssl_do_write(s);
err:
	return(-1);
	}

int ssl3_get_server_hello(SSL *s)
	{
	STACK_OF(SSL_CIPHER) *sk;
	const SSL_CIPHER *c;
	CERT *ct = s->cert;
	unsigned char *p,*d;
	int i,al=SSL_AD_INTERNAL_ERROR,ok;
	unsigned int j;
	long n;

	SSL_COMP *comp;

	
	if (SSL_IS_DTLS(s))
		s->first_packet = 1;

	n=s->method->ssl_get_message(s, SSL3_ST_CR_SRVR_HELLO_A, SSL3_ST_CR_SRVR_HELLO_B, -1, 20000, &ok);





	if (!ok) return((int)n);

	if (SSL_IS_DTLS(s))
		{
		s->first_packet = 0;
		if ( s->s3->tmp.message_type == DTLS1_MT_HELLO_VERIFY_REQUEST)
			{
			if ( s->d1->send_cookie == 0)
				{
				s->s3->tmp.reuse_message = 1;
				return 1;
				}
			else  {
				al=SSL_AD_UNEXPECTED_MESSAGE;
				SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_BAD_MESSAGE_TYPE);
				goto f_err;
				}
			}
		}
	
	if ( s->s3->tmp.message_type != SSL3_MT_SERVER_HELLO)
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_BAD_MESSAGE_TYPE);
		goto f_err;
		}

	d=p=(unsigned char *)s->init_msg;
	if (s->method->version == DTLS_ANY_VERSION)
		{
		
		int hversion = (p[0] << 8)|p[1];
		int options = s->options;
		if (hversion == DTLS1_2_VERSION && !(options & SSL_OP_NO_DTLSv1_2))
			s->method = DTLSv1_2_client_method();
		else if (tls1_suiteb(s))
			{
			SSLerr(SSL_F_SSL3_GET_SERVER_HELLO, SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE);
			s->version = hversion;
			al = SSL_AD_PROTOCOL_VERSION;
			goto f_err;
			}
		else if (hversion == DTLS1_VERSION && !(options & SSL_OP_NO_DTLSv1))
			s->method = DTLSv1_client_method();
		else {
			SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_WRONG_SSL_VERSION);
			s->version = hversion;
			al = SSL_AD_PROTOCOL_VERSION;
			goto f_err;
			}
		s->version = s->method->version;
		}

	if ((p[0] != (s->version>>8)) || (p[1] != (s->version&0xff)))
		{
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_WRONG_SSL_VERSION);
		s->version=(s->version&0xff00)|p[1];
		al=SSL_AD_PROTOCOL_VERSION;
		goto f_err;
		}
	p+=2;

	
	
	memcpy(s->s3->server_random,p,SSL3_RANDOM_SIZE);
	p+=SSL3_RANDOM_SIZE;

	s->hit = 0;

	
	j= *(p++);

	if ((j > sizeof s->session->session_id) || (j > SSL3_SESSION_ID_SIZE))
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_SSL3_SESSION_ID_TOO_LONG);
		goto f_err;
		}


	
	if (s->version >= TLS1_VERSION && s->tls_session_secret_cb)
		{
		SSL_CIPHER *pref_cipher=NULL;
		s->session->master_key_length=sizeof(s->session->master_key);
		if (s->tls_session_secret_cb(s, s->session->master_key, &s->session->master_key_length, NULL, &pref_cipher, s->tls_session_secret_cb_arg))


			{
			s->session->cipher = pref_cipher ? pref_cipher : ssl_get_cipher_by_char(s, p+j);
			s->hit = 1;
			}
		}


	if (!s->hit && j != 0 && j == s->session->session_id_length && memcmp(p,s->session->session_id,j) == 0)
	    {
	    if(s->sid_ctx_length != s->session->sid_ctx_length || memcmp(s->session->sid_ctx,s->sid_ctx,s->sid_ctx_length))
		{
		
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT);
		goto f_err;
		}
	    s->hit=1;
	    }
	
	if (!s->hit)
		{
		
		if (s->session->session_id_length > 0)
			{
			if (!ssl_get_new_session(s,0))
				{
				goto f_err;
				}
			}
		s->session->session_id_length=j;
		memcpy(s->session->session_id,p,j); 
		}
	p+=j;
	c=ssl_get_cipher_by_char(s,p);
	if (c == NULL)
		{
		
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_UNKNOWN_CIPHER_RETURNED);
		goto f_err;
		}
	
	if (!SSL_USE_TLS1_2_CIPHERS(s))
		ct->mask_ssl = SSL_TLSV1_2;
	else ct->mask_ssl = 0;
	
	if (ssl_cipher_disabled(s, c, SSL_SECOP_CIPHER_CHECK))
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_WRONG_CIPHER_RETURNED);
		goto f_err;
		}
	p+=ssl_put_cipher_by_char(s,NULL,NULL);

	sk=ssl_get_ciphers_by_id(s);
	i=sk_SSL_CIPHER_find(sk,c);
	if (i < 0)
		{
		
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_WRONG_CIPHER_RETURNED);
		goto f_err;
		}

	
	if (s->session->cipher)
		s->session->cipher_id = s->session->cipher->id;
	if (s->hit && (s->session->cipher_id != c->id))
		{


		if (!(s->options & SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG))

			{
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED);
			goto f_err;
			}
		}
	s->s3->tmp.new_cipher=c;
	
	if (!SSL_USE_SIGALGS(s) && !ssl3_digest_cached_records(s))
		goto f_err;
	
	

	if (*(p++) != 0)
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
		goto f_err;
		}
	
	if (s->session->compress_meth != 0)
		{
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_INCONSISTENT_COMPRESSION);
		goto f_err;
		}

	j= *(p++);
	if (s->hit && j != s->session->compress_meth)
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED);
		goto f_err;
		}
	if (j == 0)
		comp=NULL;
	else if (!ssl_allow_compression(s))
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_COMPRESSION_DISABLED);
		goto f_err;
		}
	else comp=ssl3_comp_find(s->ctx->comp_methods,j);
	
	if ((j != 0) && (comp == NULL))
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
		goto f_err;
		}
	else {
		s->s3->tmp.new_compression=comp;
		}



	
	if (!ssl_parse_serverhello_tlsext(s,&p,d,n))
		{
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_PARSE_TLSEXT);
		goto err; 
		}


	if (p != (d+n))
		{
		
		al=SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_SERVER_HELLO,SSL_R_BAD_PACKET_LENGTH);
		goto f_err;
		}

	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	return(-1);
	}

int ssl3_get_server_certificate(SSL *s)
	{
	int al,i,ok,ret= -1;
	unsigned long n,nc,llen,l;
	X509 *x=NULL;
	const unsigned char *q,*p;
	unsigned char *d;
	STACK_OF(X509) *sk=NULL;
	SESS_CERT *sc;
	EVP_PKEY *pkey=NULL;
	int need_cert = 1; 

	n=s->method->ssl_get_message(s, SSL3_ST_CR_CERT_A, SSL3_ST_CR_CERT_B, -1, s->max_cert_list, &ok);





	if (!ok) return((int)n);

	if ((s->s3->tmp.message_type == SSL3_MT_SERVER_KEY_EXCHANGE) || ((s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5) && (s->s3->tmp.message_type == SSL3_MT_SERVER_DONE)))

		{
		s->s3->tmp.reuse_message=1;
		return(1);
		}

	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE)
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_BAD_MESSAGE_TYPE);
		goto f_err;
		}
	p=d=(unsigned char *)s->init_msg;

	if ((sk=sk_X509_new_null()) == NULL)
		{
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	n2l3(p,llen);
	if (llen+3 != n)
		{
		al=SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_LENGTH_MISMATCH);
		goto f_err;
		}
	for (nc=0; nc<llen; )
		{
		n2l3(p,l);
		if ((l+nc+3) > llen)
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_CERT_LENGTH_MISMATCH);
			goto f_err;
			}

		q=p;
		x=d2i_X509(NULL,&q,l);
		if (x == NULL)
			{
			al=SSL_AD_BAD_CERTIFICATE;
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,ERR_R_ASN1_LIB);
			goto f_err;
			}
		if (q != (p+l))
			{
			al=SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_CERT_LENGTH_MISMATCH);
			goto f_err;
			}
		if (!sk_X509_push(sk,x))
			{
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		x=NULL;
		nc+=l+3;
		p=q;
		}

	i=ssl_verify_cert_chain(s,sk);
	if ((s->verify_mode != SSL_VERIFY_NONE) && (i <= 0)

	    && !((s->s3->tmp.new_cipher->algorithm_mkey & SSL_kKRB5) && (s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5))

		)
		{
		al=ssl_verify_alarm_type(s->verify_result);
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE,SSL_R_CERTIFICATE_VERIFY_FAILED);
		goto f_err; 
		}
	ERR_clear_error(); 
	if (i > 1)
		{
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, i);
		al = SSL_AD_HANDSHAKE_FAILURE;
		goto f_err;
		}

	sc=ssl_sess_cert_new();
	if (sc == NULL) goto err;

	if (s->session->sess_cert) ssl_sess_cert_free(s->session->sess_cert);
	s->session->sess_cert=sc;

	sc->cert_chain=sk;
	
	x=sk_X509_value(sk,0);
	sk=NULL;
 	

	pkey=X509_get_pubkey(x);

	
	need_cert = ((s->s3->tmp.new_cipher->algorithm_mkey & SSL_kKRB5) && (s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5))
	            ? 0 : 1;


	fprintf(stderr,"pkey,x = %p, %p\n", pkey,x);
	fprintf(stderr,"ssl_cert_type(x,pkey) = %d\n", ssl_cert_type(x,pkey));
	fprintf(stderr,"cipher, alg, nc = %s, %lx, %lx, %d\n", s->s3->tmp.new_cipher->name, s->s3->tmp.new_cipher->algorithm_mkey, s->s3->tmp.new_cipher->algorithm_auth, need_cert);


	if (need_cert && ((pkey == NULL) || EVP_PKEY_missing_parameters(pkey)))
		{
		x=NULL;
		al=SSL3_AL_FATAL;
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS);
		goto f_err;
		}

	i=ssl_cert_type(x,pkey);
	if (need_cert && i < 0)
		{
		x=NULL;
		al=SSL3_AL_FATAL;
		SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
		goto f_err;
		}

	if (need_cert)
		{
		int exp_idx = ssl_cipher_get_cert_index(s->s3->tmp.new_cipher);
		if (exp_idx >= 0 && i != exp_idx)
			{
			x=NULL;
			al=SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_SERVER_CERTIFICATE, SSL_R_WRONG_CERTIFICATE_TYPE);
			goto f_err;
			}
		sc->peer_cert_type=i;
		CRYPTO_add(&x->references,1,CRYPTO_LOCK_X509);
		
		if (sc->peer_pkeys[i].x509 != NULL)
			X509_free(sc->peer_pkeys[i].x509);
		sc->peer_pkeys[i].x509=x;
		sc->peer_key= &(sc->peer_pkeys[i]);

		if (s->session->peer != NULL)
			X509_free(s->session->peer);
		CRYPTO_add(&x->references,1,CRYPTO_LOCK_X509);
		s->session->peer=x;
		}
	else {
		sc->peer_cert_type=i;
		sc->peer_key= NULL;

		if (s->session->peer != NULL)
			X509_free(s->session->peer);
		s->session->peer=NULL;
		}
	s->session->verify_result = s->verify_result;

	x=NULL;
	ret=1;
	if (0)
		{
f_err:
		ssl3_send_alert(s,SSL3_AL_FATAL,al);
		}
err:
	EVP_PKEY_free(pkey);
	X509_free(x);
	sk_X509_pop_free(sk,X509_free);
	return(ret);
	}

int ssl3_get_key_exchange(SSL *s)
	{

	unsigned char *q,md_buf[EVP_MAX_MD_SIZE*2];

	EVP_MD_CTX md_ctx;
	unsigned char *param,*p;
	int al,j,ok;
	long i,param_len,n,alg_k,alg_a;
	EVP_PKEY *pkey=NULL;
	const EVP_MD *md = NULL;

	RSA *rsa=NULL;


	DH *dh=NULL;


	EC_KEY *ecdh = NULL;
	BN_CTX *bn_ctx = NULL;
	EC_POINT *srvr_ecpoint = NULL;
	int curve_nid = 0;
	int encoded_pt_len = 0;


	EVP_MD_CTX_init(&md_ctx);

	
	n=s->method->ssl_get_message(s, SSL3_ST_CR_KEY_EXCH_A, SSL3_ST_CR_KEY_EXCH_B, -1, s->max_cert_list, &ok);




	if (!ok) return((int)n);

	alg_k=s->s3->tmp.new_cipher->algorithm_mkey;

	if (s->s3->tmp.message_type != SSL3_MT_SERVER_KEY_EXCHANGE)
		{
		
		if (alg_k & (SSL_kDHE|SSL_kECDHE))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_UNEXPECTED_MESSAGE);
			al = SSL_AD_UNEXPECTED_MESSAGE;
			goto f_err;
			}

		
		if (alg_k & SSL_kPSK)
			{
			s->session->sess_cert=ssl_sess_cert_new();
			if (s->ctx->psk_identity_hint)
				OPENSSL_free(s->ctx->psk_identity_hint);
			s->ctx->psk_identity_hint = NULL;
			}

		s->s3->tmp.reuse_message=1;
		return(1);
		}

	param=p=(unsigned char *)s->init_msg;
	if (s->session->sess_cert != NULL)
		{

		if (s->session->sess_cert->peer_rsa_tmp != NULL)
			{
			RSA_free(s->session->sess_cert->peer_rsa_tmp);
			s->session->sess_cert->peer_rsa_tmp=NULL;
			}


		if (s->session->sess_cert->peer_dh_tmp)
			{
			DH_free(s->session->sess_cert->peer_dh_tmp);
			s->session->sess_cert->peer_dh_tmp=NULL;
			}


		if (s->session->sess_cert->peer_ecdh_tmp)
			{
			EC_KEY_free(s->session->sess_cert->peer_ecdh_tmp);
			s->session->sess_cert->peer_ecdh_tmp=NULL;
			}

		}
	else {
		s->session->sess_cert=ssl_sess_cert_new();
		}

	
	param_len=0;

	alg_a=s->s3->tmp.new_cipher->algorithm_auth;

	al=SSL_AD_DECODE_ERROR;


	if (alg_k & SSL_kPSK)
		{
		char tmp_id_hint[PSK_MAX_IDENTITY_LEN+1];

		param_len = 2;
		if (param_len > n)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		n2s(p,i);

		
		if (i > PSK_MAX_IDENTITY_LEN)
			{
			al=SSL_AD_HANDSHAKE_FAILURE;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_DATA_LENGTH_TOO_LONG);
			goto f_err;
			}
		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_BAD_PSK_IDENTITY_HINT_LENGTH);
			goto f_err;
			}
		param_len += i;

		
		memcpy(tmp_id_hint, p, i);
		memset(tmp_id_hint+i, 0, PSK_MAX_IDENTITY_LEN+1-i);
		if (s->ctx->psk_identity_hint != NULL)
			OPENSSL_free(s->ctx->psk_identity_hint);
		s->ctx->psk_identity_hint = BUF_strdup(tmp_id_hint);
		if (s->ctx->psk_identity_hint == NULL)
			{
			al=SSL_AD_HANDSHAKE_FAILURE;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
			goto f_err;
			}	   

		p+=i;
		n-=param_len;
		}
	else   if (alg_k & SSL_kSRP)


		{
		param_len = 2;
		if (param_len > n)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		n2s(p,i);

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SRP_N_LENGTH);
			goto f_err;
			}
		param_len += i;

		if (!(s->srp_ctx.N=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;


		if (2 > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		param_len += 2;

		n2s(p,i);

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SRP_G_LENGTH);
			goto f_err;
			}
		param_len += i;

		if (!(s->srp_ctx.g=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;


		if (1 > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		param_len += 1;

		i = (unsigned int)(p[0]);
		p++;

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SRP_S_LENGTH);
			goto f_err;
			}
		param_len += i;

		if (!(s->srp_ctx.s=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;

		if (2 > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		param_len += 2;

		n2s(p,i);

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SRP_B_LENGTH);
			goto f_err;
			}
		param_len += i;

		if (!(s->srp_ctx.B=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;
		n-=param_len;

		if (!srp_verify_server_param(s, &al))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SRP_PARAMETERS);
			goto f_err;
			}



		if (alg_a & SSL_aRSA)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);

		if (0)
			;


		else if (alg_a & SSL_aDSS)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_DSA_SIGN].x509);

		}
	else   if (alg_k & SSL_kRSA)


		{
		if ((rsa=RSA_new()) == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
			goto err;
			}

		param_len = 2;
		if (param_len > n)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		n2s(p,i);

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_RSA_MODULUS_LENGTH);
			goto f_err;
			}
		param_len += i;

		if (!(rsa->n=BN_bin2bn(p,i,rsa->n)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;

		if (2 > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		param_len += 2;

		n2s(p,i);

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_RSA_E_LENGTH);
			goto f_err;
			}
		param_len += i;

		if (!(rsa->e=BN_bin2bn(p,i,rsa->e)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;
		n-=param_len;

		
		if (alg_a & SSL_aRSA)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
		else {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
			goto err;
			}
		s->session->sess_cert->peer_rsa_tmp=rsa;
		rsa=NULL;
		}

	if (0)
		;


	else if (alg_k & SSL_kDHE)
		{
		if ((dh=DH_new()) == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_DH_LIB);
			goto err;
			}

		param_len = 2;
		if (param_len > n)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		n2s(p,i);

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_DH_P_LENGTH);
			goto f_err;
			}
		param_len += i;

		if (!(dh->p=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;

		if (2 > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		param_len += 2;

		n2s(p,i);

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_DH_G_LENGTH);
			goto f_err;
			}
		param_len += i;

		if (!(dh->g=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;

		if (2 > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		param_len += 2;

		n2s(p,i);

		if (i > n - param_len)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_DH_PUB_KEY_LENGTH);
			goto f_err;
			}
		param_len += i;

		if (!(dh->pub_key=BN_bin2bn(p,i,NULL)))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_BN_LIB);
			goto err;
			}
		p+=i;
		n-=param_len;

		if (!ssl_security(s, SSL_SECOP_TMP_DH, DH_security_bits(dh), 0, dh))
			{
			al=SSL_AD_HANDSHAKE_FAILURE;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_DH_KEY_TOO_SMALL);
			goto f_err;
			}


		if (alg_a & SSL_aRSA)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);

		if (0)
			;


		else if (alg_a & SSL_aDSS)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_DSA_SIGN].x509);

		

		s->session->sess_cert->peer_dh_tmp=dh;
		dh=NULL;
		}
	else if ((alg_k & SSL_kDHr) || (alg_k & SSL_kDHd))
		{
		al=SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER);
		goto f_err;
		}



	else if (alg_k & SSL_kECDHE)
		{
		EC_GROUP *ngroup;
		const EC_GROUP *group;

		if ((ecdh=EC_KEY_new()) == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
			goto err;
			}

		

		
		param_len=4;
		if (param_len > n)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		
		if (!tls1_check_curve(s, p, 3))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_WRONG_CURVE);
			goto f_err;
			}

		if ((curve_nid = tls1_ec_curve_id2nid(*(p + 2))) == 0) 
			{
			al=SSL_AD_INTERNAL_ERROR;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
			goto f_err;
			}

		ngroup = EC_GROUP_new_by_curve_name(curve_nid);
		if (ngroup == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_EC_LIB);
			goto err;
			}
		if (EC_KEY_set_group(ecdh, ngroup) == 0)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_EC_LIB);
			goto err;
			}
		EC_GROUP_free(ngroup);

		group = EC_KEY_get0_group(ecdh);

		if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) && (EC_GROUP_get_degree(group) > 163))
			{
			al=SSL_AD_EXPORT_RESTRICTION;
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER);
			goto f_err;
			}

		p+=3;

		
		if (((srvr_ecpoint = EC_POINT_new(group)) == NULL) || ((bn_ctx = BN_CTX_new()) == NULL))
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
			goto err;
			}

		encoded_pt_len = *p;  
		p+=1;

		if ((encoded_pt_len > n - param_len) || (EC_POINT_oct2point(group, srvr_ecpoint, p, encoded_pt_len, bn_ctx) == 0))

			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_ECPOINT);
			goto f_err;
			}
		param_len += encoded_pt_len;

		n-=param_len;
		p+=encoded_pt_len;

		
		if (0) ;

		else if (alg_a & SSL_aRSA)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);


		else if (alg_a & SSL_aECDSA)
			pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_ECC].x509);

		
		EC_KEY_set_public_key(ecdh, srvr_ecpoint);
		s->session->sess_cert->peer_ecdh_tmp=ecdh;
		ecdh=NULL;
		BN_CTX_free(bn_ctx);
		bn_ctx = NULL;
		EC_POINT_free(srvr_ecpoint);
		srvr_ecpoint = NULL;
		}
	else if (alg_k)
		{
		al=SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_UNEXPECTED_MESSAGE);
		goto f_err;
		}



	

	
	if (pkey != NULL)
		{
		if (SSL_USE_SIGALGS(s))
			{
			int rv;
			if (2 > n)
				{
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
				goto f_err;
				}
			rv = tls12_check_peer_sigalg(&md, s, p, pkey);
			if (rv == -1)
				goto err;
			else if (rv == 0)
				{
				goto f_err;
				}

fprintf(stderr, "USING TLSv1.2 HASH %s\n", EVP_MD_name(md));

			p += 2;
			n -= 2;
			}
		else md = EVP_sha1();

		if (2 > n)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, SSL_R_LENGTH_TOO_SHORT);
			goto f_err;
			}
		n2s(p,i);
		n-=2;
		j=EVP_PKEY_size(pkey);

		
		if ((i != n) || (n > j) || (n <= 0))
			{
			
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_WRONG_SIGNATURE_LENGTH);
			goto f_err;
			}


		if (pkey->type == EVP_PKEY_RSA && !SSL_USE_SIGALGS(s))
			{
			int num;
			unsigned int size;

			j=0;
			q=md_buf;
			for (num=2; num > 0; num--)
				{
				EVP_MD_CTX_set_flags(&md_ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
				EVP_DigestInit_ex(&md_ctx,(num == 2)
					?s->ctx->md5:s->ctx->sha1, NULL);
				EVP_DigestUpdate(&md_ctx,&(s->s3->client_random[0]),SSL3_RANDOM_SIZE);
				EVP_DigestUpdate(&md_ctx,&(s->s3->server_random[0]),SSL3_RANDOM_SIZE);
				EVP_DigestUpdate(&md_ctx,param,param_len);
				EVP_DigestFinal_ex(&md_ctx,q,&size);
				q+=size;
				j+=size;
				}
			i=RSA_verify(NID_md5_sha1, md_buf, j, p, n, pkey->pkey.rsa);
			if (i < 0)
				{
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_RSA_DECRYPT);
				goto f_err;
				}
			if (i == 0)
				{
				
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SIGNATURE);
				goto f_err;
				}
			}
		else  {

			EVP_VerifyInit_ex(&md_ctx, md, NULL);
			EVP_VerifyUpdate(&md_ctx,&(s->s3->client_random[0]),SSL3_RANDOM_SIZE);
			EVP_VerifyUpdate(&md_ctx,&(s->s3->server_random[0]),SSL3_RANDOM_SIZE);
			EVP_VerifyUpdate(&md_ctx,param,param_len);
			if (EVP_VerifyFinal(&md_ctx,p,(int)n,pkey) <= 0)
				{
				
				al=SSL_AD_DECRYPT_ERROR;
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_BAD_SIGNATURE);
				goto f_err;
				}
			}
		}
	else {
		
		if (!(alg_a & (SSL_aNULL|SSL_aSRP)) && !(alg_k & SSL_kPSK))
			{
			
			if (ssl3_check_cert_and_algorithm(s))
				
				SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
			goto err;
			}
		
		if (n != 0)
			{
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE,SSL_R_EXTRA_DATA_IN_MESSAGE);
			goto f_err;
			}
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_cleanup(&md_ctx);
	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	EVP_PKEY_free(pkey);

	if (rsa != NULL)
		RSA_free(rsa);


	if (dh != NULL)
		DH_free(dh);


	BN_CTX_free(bn_ctx);
	EC_POINT_free(srvr_ecpoint);
	if (ecdh != NULL)
		EC_KEY_free(ecdh);

	EVP_MD_CTX_cleanup(&md_ctx);
	return(-1);
	}

int ssl3_get_certificate_request(SSL *s)
	{
	int ok,ret=0;
	unsigned long n,nc,l;
	unsigned int llen, ctype_num,i;
	X509_NAME *xn=NULL;
	const unsigned char *p,*q;
	unsigned char *d;
	STACK_OF(X509_NAME) *ca_sk=NULL;

	n=s->method->ssl_get_message(s, SSL3_ST_CR_CERT_REQ_A, SSL3_ST_CR_CERT_REQ_B, -1, s->max_cert_list, &ok);





	if (!ok) return((int)n);

	s->s3->tmp.cert_req=0;

	if (s->s3->tmp.message_type == SSL3_MT_SERVER_DONE)
		{
		s->s3->tmp.reuse_message=1;
		
		if (s->s3->handshake_buffer)
			{
			if (!ssl3_digest_cached_records(s))
				goto err;
			}
		return(1);
		}

	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_REQUEST)
		{
		ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_UNEXPECTED_MESSAGE);
		SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,SSL_R_WRONG_MESSAGE_TYPE);
		goto err;
		}

	
	if (s->version > SSL3_VERSION)
		{
		if (s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL)
			{
			ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_UNEXPECTED_MESSAGE);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER);
			goto err;
			}
		}

	p=d=(unsigned char *)s->init_msg;

	if ((ca_sk=sk_X509_NAME_new(ca_dn_cmp)) == NULL)
		{
		SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,ERR_R_MALLOC_FAILURE);
		goto err;
		}

	
	ctype_num= *(p++);
	if (s->cert->ctypes)
		{
		OPENSSL_free(s->cert->ctypes);
		s->cert->ctypes = NULL;
		}
	if (ctype_num > SSL3_CT_NUMBER)
		{
		
		s->cert->ctypes = OPENSSL_malloc(ctype_num);
		if (s->cert->ctypes == NULL)
			{
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,ERR_R_MALLOC_FAILURE);
			goto err;
			}
		memcpy(s->cert->ctypes, p, ctype_num);
		s->cert->ctype_num = (size_t)ctype_num;
		ctype_num=SSL3_CT_NUMBER;
		}
	for (i=0; i<ctype_num; i++)
		s->s3->tmp.ctype[i]= p[i];
	p+=p[-1];
	if (SSL_USE_SIGALGS(s))
		{
		n2s(p, llen);
		
		if ((unsigned long)(p - d + llen + 2) > n)
			{
			ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,SSL_R_DATA_LENGTH_TOO_LONG);
			goto err;
			}
		
		for (i = 0; i < SSL_PKEY_NUM; i++)
			{
			s->cert->pkeys[i].digest = NULL;
			s->cert->pkeys[i].valid_flags = 0;
			}
		if ((llen & 1) || !tls1_save_sigalgs(s, p, llen))
			{
			ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,SSL_R_SIGNATURE_ALGORITHMS_ERROR);
			goto err;
			}
		if (!tls1_process_sigalgs(s))
			{
			ssl3_send_alert(s,SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
			goto err;
			}
		p += llen;
		}

	
	n2s(p,llen);

{
FILE *out;
out=fopen("/tmp/vsign.der","w");
fwrite(p,1,llen,out);
fclose(out);
}


	if ((unsigned long)(p - d + llen) != n)
		{
		ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
		SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,SSL_R_LENGTH_MISMATCH);
		goto err;
		}

	for (nc=0; nc<llen; )
		{
		n2s(p,l);
		if ((l+nc+2) > llen)
			{
			if ((s->options & SSL_OP_NETSCAPE_CA_DN_BUG))
				goto cont; 
			ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,SSL_R_CA_DN_TOO_LONG);
			goto err;
			}

		q=p;

		if ((xn=d2i_X509_NAME(NULL,&q,l)) == NULL)
			{
			
			if (s->options & SSL_OP_NETSCAPE_CA_DN_BUG)
				goto cont;
			else {
				ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
				SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,ERR_R_ASN1_LIB);
				goto err;
				}
			}

		if (q != (p+l))
			{
			ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,SSL_R_CA_DN_LENGTH_MISMATCH);
			goto err;
			}
		if (!sk_X509_NAME_push(ca_sk,xn))
			{
			SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST,ERR_R_MALLOC_FAILURE);
			goto err;
			}

		p+=l;
		nc+=l+2;
		}

	if (0)
		{
cont:
		ERR_clear_error();
		}

	
	s->s3->tmp.cert_req=1;
	s->s3->tmp.ctype_num=ctype_num;
	if (s->s3->tmp.ca_names != NULL)
		sk_X509_NAME_pop_free(s->s3->tmp.ca_names,X509_NAME_free);
	s->s3->tmp.ca_names=ca_sk;
	ca_sk=NULL;

	ret=1;
err:
	if (ca_sk != NULL) sk_X509_NAME_pop_free(ca_sk,X509_NAME_free);
	return(ret);
	}

static int ca_dn_cmp(const X509_NAME * const *a, const X509_NAME * const *b)
	{
	return(X509_NAME_cmp(*a,*b));
	}

int ssl3_get_new_session_ticket(SSL *s)
	{
	int ok,al,ret=0, ticklen;
	long n;
	const unsigned char *p;
	unsigned char *d;

	n=s->method->ssl_get_message(s, SSL3_ST_CR_SESSION_TICKET_A, SSL3_ST_CR_SESSION_TICKET_B, SSL3_MT_NEWSESSION_TICKET, 16384, &ok);





	if (!ok)
		return((int)n);

	if (n < 6)
		{
		
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET,SSL_R_LENGTH_MISMATCH);
		goto f_err;
		}

	p=d=(unsigned char *)s->init_msg;
	n2l(p, s->session->tlsext_tick_lifetime_hint);
	n2s(p, ticklen);
	
	if (ticklen + 6 != n)
		{
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET,SSL_R_LENGTH_MISMATCH);
		goto f_err;
		}
	if (s->session->tlsext_tick)
		{
		OPENSSL_free(s->session->tlsext_tick);
		s->session->tlsext_ticklen = 0;
		}
	s->session->tlsext_tick = OPENSSL_malloc(ticklen);
	if (!s->session->tlsext_tick)
		{
		SSLerr(SSL_F_SSL3_GET_NEW_SESSION_TICKET,ERR_R_MALLOC_FAILURE);
		goto err;
		}
	memcpy(s->session->tlsext_tick, p, ticklen);
	s->session->tlsext_ticklen = ticklen;
	 
	EVP_Digest(p, ticklen, s->session->session_id, &s->session->session_id_length,  EVP_sha256(), NULL);



							EVP_sha1(), NULL);

	ret=1;
	return(ret);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
err:
	return(-1);
	}

int ssl3_get_cert_status(SSL *s)
	{
	int ok, al;
	unsigned long resplen,n;
	const unsigned char *p;

	n=s->method->ssl_get_message(s, SSL3_ST_CR_CERT_STATUS_A, SSL3_ST_CR_CERT_STATUS_B, SSL3_MT_CERTIFICATE_STATUS, 16384, &ok);





	if (!ok) return((int)n);
	if (n < 4)
		{
		
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CERT_STATUS,SSL_R_LENGTH_MISMATCH);
		goto f_err;
		}
	p = (unsigned char *)s->init_msg;
	if (*p++ != TLSEXT_STATUSTYPE_ocsp)
		{
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CERT_STATUS,SSL_R_UNSUPPORTED_STATUS_TYPE);
		goto f_err;
		}
	n2l3(p, resplen);
	if (resplen + 4 != n)
		{
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CERT_STATUS,SSL_R_LENGTH_MISMATCH);
		goto f_err;
		}
	if (s->tlsext_ocsp_resp)
		OPENSSL_free(s->tlsext_ocsp_resp);
	s->tlsext_ocsp_resp = BUF_memdup(p, resplen);
	if (!s->tlsext_ocsp_resp)
		{
		al = SSL_AD_INTERNAL_ERROR;
		SSLerr(SSL_F_SSL3_GET_CERT_STATUS,ERR_R_MALLOC_FAILURE);
		goto f_err;
		}
	s->tlsext_ocsp_resplen = resplen;
	if (s->ctx->tlsext_status_cb)
		{
		int ret;
		ret = s->ctx->tlsext_status_cb(s, s->ctx->tlsext_status_arg);
		if (ret == 0)
			{
			al = SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
			SSLerr(SSL_F_SSL3_GET_CERT_STATUS,SSL_R_INVALID_STATUS_RESPONSE);
			goto f_err;
			}
		if (ret < 0)
			{
			al = SSL_AD_INTERNAL_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_STATUS,ERR_R_MALLOC_FAILURE);
			goto f_err;
			}
		}
	return 1;
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,al);
	return(-1);
	}


int ssl3_get_server_done(SSL *s)
	{
	int ok,ret=0;
	long n;

	n=s->method->ssl_get_message(s, SSL3_ST_CR_SRVR_DONE_A, SSL3_ST_CR_SRVR_DONE_B, SSL3_MT_SERVER_DONE, 30, &ok);





	if (!ok) return((int)n);
	if (n > 0)
		{
		
		ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_DECODE_ERROR);
		SSLerr(SSL_F_SSL3_GET_SERVER_DONE,SSL_R_LENGTH_MISMATCH);
		return -1;
		}
	ret=1;
	return(ret);
	}


int ssl3_send_client_key_exchange(SSL *s)
	{
	unsigned char *p;
	int n;
	unsigned long alg_k;

	unsigned char *q;
	EVP_PKEY *pkey=NULL;


	KSSL_ERR kssl_err;


	EC_KEY *clnt_ecdh = NULL;
	const EC_POINT *srvr_ecpoint = NULL;
	EVP_PKEY *srvr_pub_pkey = NULL;
	unsigned char *encodedPoint = NULL;
	int encoded_pt_len = 0;
	BN_CTX * bn_ctx = NULL;


	if (s->state == SSL3_ST_CW_KEY_EXCH_A)
		{
		p = ssl_handshake_start(s);

		alg_k=s->s3->tmp.new_cipher->algorithm_mkey;

		
		if (0) {}

		else if (alg_k & SSL_kRSA)
			{
			RSA *rsa;
			unsigned char tmp_buf[SSL_MAX_MASTER_KEY_LENGTH];

			if (s->session->sess_cert == NULL)
				{
				
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
				goto err;
				}

			if (s->session->sess_cert->peer_rsa_tmp != NULL)
				rsa=s->session->sess_cert->peer_rsa_tmp;
			else {
				pkey=X509_get_pubkey(s->session->sess_cert->peer_pkeys[SSL_PKEY_RSA_ENC].x509);
				if ((pkey == NULL) || (pkey->type != EVP_PKEY_RSA) || (pkey->pkey.rsa == NULL))

					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
					goto err;
					}
				rsa=pkey->pkey.rsa;
				EVP_PKEY_free(pkey);
				}
				
			tmp_buf[0]=s->client_version>>8;
			tmp_buf[1]=s->client_version&0xff;
			if (RAND_bytes(&(tmp_buf[2]),sizeof tmp_buf-2) <= 0)
					goto err;

			s->session->master_key_length=sizeof tmp_buf;

			q=p;
			
			if (s->version > SSL3_VERSION)
				p+=2;
			n=RSA_public_encrypt(sizeof tmp_buf, tmp_buf,p,rsa,RSA_PKCS1_PADDING);

			if (s->options & SSL_OP_PKCS1_CHECK_1) p[1]++;
			if (s->options & SSL_OP_PKCS1_CHECK_2) tmp_buf[0]=0x70;

			if (n <= 0)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_BAD_RSA_ENCRYPT);
				goto err;
				}

			
			if (s->version > SSL3_VERSION)
				{
				s2n(n,q);
				n+=2;
				}

			s->session->master_key_length= s->method->ssl3_enc->generate_master_secret(s, s->session->master_key, tmp_buf,sizeof tmp_buf);


			OPENSSL_cleanse(tmp_buf,sizeof tmp_buf);
			}


		else if (alg_k & SSL_kKRB5)
			{
			krb5_error_code	krb5rc;
			KSSL_CTX	*kssl_ctx = s->kssl_ctx;
			
			krb5_data	*enc_ticket;
			krb5_data	authenticator, *authp = NULL;
			EVP_CIPHER_CTX	ciph_ctx;
			const EVP_CIPHER *enc = NULL;
			unsigned char	iv[EVP_MAX_IV_LENGTH];
			unsigned char	tmp_buf[SSL_MAX_MASTER_KEY_LENGTH];
			unsigned char	epms[SSL_MAX_MASTER_KEY_LENGTH  + EVP_MAX_IV_LENGTH];
			int 		padl, outl = sizeof(epms);

			EVP_CIPHER_CTX_init(&ciph_ctx);


			fprintf(stderr,"ssl3_send_client_key_exchange(%lx & %lx)\n", alg_k, SSL_kKRB5);


			authp = NULL;

			if (KRB5SENDAUTH)  authp = &authenticator;


			krb5rc = kssl_cget_tkt(kssl_ctx, &enc_ticket, authp, &kssl_err);
			enc = kssl_map_enc(kssl_ctx->enctype);
			if (enc == NULL)
			    goto err;

			{
			fprintf(stderr,"kssl_cget_tkt rtn %d\n", krb5rc);
			if (krb5rc && kssl_err.text)
			  fprintf(stderr,"kssl_cget_tkt kssl_err=%s\n", kssl_err.text);
			}


			if (krb5rc)
				{
				ssl3_send_alert(s,SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, kssl_err.reason);
				goto err;
				}

			

			
			s2n(enc_ticket->length,p);
			memcpy(p, enc_ticket->data, enc_ticket->length);
			p+= enc_ticket->length;
			n = enc_ticket->length + 2;

			
			if (authp  &&  authp->length)  
				{
				s2n(authp->length,p);
				memcpy(p, authp->data, authp->length);
				p+= authp->length;
				n+= authp->length + 2;
				
				free(authp->data);
				authp->data = NULL;
				authp->length = 0;
				}
			else {
				s2n(0,p);
				n+=2;
				}
 
			    tmp_buf[0]=s->client_version>>8;
			    tmp_buf[1]=s->client_version&0xff;
			    if (RAND_bytes(&(tmp_buf[2]),sizeof tmp_buf-2) <= 0)
				goto err;

			

			memset(iv, 0, sizeof iv);  
			EVP_EncryptInit_ex(&ciph_ctx,enc, NULL, kssl_ctx->key,iv);
			EVP_EncryptUpdate(&ciph_ctx,epms,&outl,tmp_buf, sizeof tmp_buf);
			EVP_EncryptFinal_ex(&ciph_ctx,&(epms[outl]),&padl);
			outl += padl;
			if (outl > (int)sizeof epms)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
				goto err;
				}
			EVP_CIPHER_CTX_cleanup(&ciph_ctx);

			
			s2n(outl,p);
			memcpy(p, epms, outl);
			p+=outl;
			n+=outl + 2;

			s->session->master_key_length= s->method->ssl3_enc->generate_master_secret(s, s->session->master_key, tmp_buf, sizeof tmp_buf);



			OPENSSL_cleanse(tmp_buf, sizeof tmp_buf);
			OPENSSL_cleanse(epms, outl);
			}


		else if (alg_k & (SSL_kDHE|SSL_kDHr|SSL_kDHd))
			{
			DH *dh_srvr,*dh_clnt;
			SESS_CERT *scert = s->session->sess_cert;

			if (scert == NULL) 
				{
				ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_UNEXPECTED_MESSAGE);
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_UNEXPECTED_MESSAGE);
				goto err;
				}

			if (scert->peer_dh_tmp != NULL)
				dh_srvr=scert->peer_dh_tmp;
			else {
				
				int idx = scert->peer_cert_type;
				EVP_PKEY *spkey = NULL;
				dh_srvr = NULL;
				if (idx >= 0)
					spkey = X509_get_pubkey( scert->peer_pkeys[idx].x509);
				if (spkey)
					{
					dh_srvr = EVP_PKEY_get1_DH(spkey);
					EVP_PKEY_free(spkey);
					}
				if (dh_srvr == NULL)
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
					goto err;
					}
				}
			if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY)
				{
				
				EVP_PKEY *clkey = s->cert->key->privatekey;
				dh_clnt = NULL;
				if (clkey)
					dh_clnt = EVP_PKEY_get1_DH(clkey);
				if (dh_clnt == NULL)
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
					goto err;
					}
				}
			else {
				
				if ((dh_clnt=DHparams_dup(dh_srvr)) == NULL)
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_DH_LIB);
					goto err;
					}
				if (!DH_generate_key(dh_clnt))
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_DH_LIB);
					DH_free(dh_clnt);
					goto err;
					}
				}

			

			n=DH_compute_key(p,dh_srvr->pub_key,dh_clnt);
			if (scert->peer_dh_tmp == NULL)
				DH_free(dh_srvr);

			if (n <= 0)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_DH_LIB);
				DH_free(dh_clnt);
				goto err;
				}

			
			s->session->master_key_length= s->method->ssl3_enc->generate_master_secret(s, s->session->master_key,p,n);

			
			memset(p,0,n);

			if (s->s3->flags & TLS1_FLAGS_SKIP_CERT_VERIFY)
				n = 0;
			else {
				
				n=BN_num_bytes(dh_clnt->pub_key);
				s2n(n,p);
				BN_bn2bin(dh_clnt->pub_key,p);
				n+=2;
				}

			DH_free(dh_clnt);

			
			}



		else if (alg_k & (SSL_kECDHE|SSL_kECDHr|SSL_kECDHe))
			{
			const EC_GROUP *srvr_group = NULL;
			EC_KEY *tkey;
			int ecdh_clnt_cert = 0;
			int field_size = 0;

			if (s->session->sess_cert == NULL) 
				{
				ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_UNEXPECTED_MESSAGE);
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_UNEXPECTED_MESSAGE);
				goto err;
				}

			
			if ((alg_k & (SSL_kECDHr|SSL_kECDHe)) && (s->cert != NULL)) 
				{
				
				}

			if (s->session->sess_cert->peer_ecdh_tmp != NULL)
				{
				tkey = s->session->sess_cert->peer_ecdh_tmp;
				}
			else {
				
				srvr_pub_pkey = X509_get_pubkey(s->session->  sess_cert->peer_pkeys[SSL_PKEY_ECC].x509)
				if ((srvr_pub_pkey == NULL) || (srvr_pub_pkey->type != EVP_PKEY_EC) || (srvr_pub_pkey->pkey.ec == NULL))

					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
					goto err;
					}

				tkey = srvr_pub_pkey->pkey.ec;
				}

			srvr_group   = EC_KEY_get0_group(tkey);
			srvr_ecpoint = EC_KEY_get0_public_key(tkey);

			if ((srvr_group == NULL) || (srvr_ecpoint == NULL))
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
				goto err;
				}

			if ((clnt_ecdh=EC_KEY_new()) == NULL) 
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
				goto err;
				}

			if (!EC_KEY_set_group(clnt_ecdh, srvr_group))
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_EC_LIB);
				goto err;
				}
			if (ecdh_clnt_cert) 
				{ 
				
				const BIGNUM *priv_key;
				tkey = s->cert->key->privatekey->pkey.ec;
				priv_key = EC_KEY_get0_private_key(tkey);
				if (priv_key == NULL)
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
					goto err;
					}
				if (!EC_KEY_set_private_key(clnt_ecdh, priv_key))
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_EC_LIB);
					goto err;
					}
				}
			else  {
				
				if (!(EC_KEY_generate_key(clnt_ecdh)))
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
					goto err;
					}
				}

			

			field_size = EC_GROUP_get_degree(srvr_group);
			if (field_size <= 0)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,  ERR_R_ECDH_LIB);
				goto err;
				}
			n=ECDH_compute_key(p, (field_size+7)/8, srvr_ecpoint, clnt_ecdh, NULL);
			if (n <= 0)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,  ERR_R_ECDH_LIB);
				goto err;
				}

			
			s->session->master_key_length = s->method->ssl3_enc  -> generate_master_secret(s, s->session->master_key, p, n);


			memset(p, 0, n); 

			if (ecdh_clnt_cert) 
				{
				
				n = 0;
				}
			else  {
				
				encoded_pt_len =  EC_POINT_point2oct(srvr_group, EC_KEY_get0_public_key(clnt_ecdh), POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);




				encodedPoint = (unsigned char *) 
				    OPENSSL_malloc(encoded_pt_len *  sizeof(unsigned char));
				bn_ctx = BN_CTX_new();
				if ((encodedPoint == NULL) ||  (bn_ctx == NULL))
					{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_MALLOC_FAILURE);
					goto err;
					}

				
				n = EC_POINT_point2oct(srvr_group,  EC_KEY_get0_public_key(clnt_ecdh), POINT_CONVERSION_UNCOMPRESSED, encodedPoint, encoded_pt_len, bn_ctx);



				*p = n; 
				
				p += 1; 
				
				memcpy((unsigned char *)p, encodedPoint, n);
				
				n += 1; 
				}

			
			BN_CTX_free(bn_ctx);
			if (encodedPoint != NULL) OPENSSL_free(encodedPoint);
			if (clnt_ecdh != NULL) 
				 EC_KEY_free(clnt_ecdh);
			EVP_PKEY_free(srvr_pub_pkey);
			}

		else if (alg_k & SSL_kGOST) 
			{
			
			EVP_PKEY_CTX *pkey_ctx;
			X509 *peer_cert; 
			size_t msglen;
			unsigned int md_len;
			int keytype;
			unsigned char premaster_secret[32],shared_ukm[32], tmp[256];
			EVP_MD_CTX *ukm_hash;
			EVP_PKEY *pub_key;

			
			peer_cert=s->session->sess_cert->peer_pkeys[(keytype=SSL_PKEY_GOST01)].x509;
			if (!peer_cert) 
				peer_cert=s->session->sess_cert->peer_pkeys[(keytype=SSL_PKEY_GOST94)].x509;
			if (!peer_cert)		{
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER);
					goto err;
				}	
				
			pkey_ctx=EVP_PKEY_CTX_new(pub_key=X509_get_pubkey(peer_cert),NULL);
			

			 
					
			EVP_PKEY_encrypt_init(pkey_ctx);
			  	
		    RAND_bytes(premaster_secret,32);
			
			if (s->s3->tmp.cert_req && s->cert->key->privatekey) {
				if (EVP_PKEY_derive_set_peer(pkey_ctx,s->cert->key->privatekey) <=0) {
					
					ERR_clear_error();
				}
			}			
			
			ukm_hash = EVP_MD_CTX_create();
			EVP_DigestInit(ukm_hash,EVP_get_digestbynid(NID_id_GostR3411_94));
			EVP_DigestUpdate(ukm_hash,s->s3->client_random,SSL3_RANDOM_SIZE);
			EVP_DigestUpdate(ukm_hash,s->s3->server_random,SSL3_RANDOM_SIZE);
			EVP_DigestFinal_ex(ukm_hash, shared_ukm, &md_len);
			EVP_MD_CTX_destroy(ukm_hash);
			if (EVP_PKEY_CTX_ctrl(pkey_ctx,-1,EVP_PKEY_OP_ENCRYPT,EVP_PKEY_CTRL_SET_IV, 8,shared_ukm)<0) {
					SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, SSL_R_LIBRARY_BUG);
					goto err;
				}	
			
			
			*(p++)=V_ASN1_SEQUENCE | V_ASN1_CONSTRUCTED;
			msglen=255;
			if (EVP_PKEY_encrypt(pkey_ctx,tmp,&msglen,premaster_secret,32)<0) {
			SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, SSL_R_LIBRARY_BUG);
				goto err;
			}
			if (msglen >= 0x80)
				{
				*(p++)=0x81;
				*(p++)= msglen & 0xff;
				n=msglen+3;
				}
			else {
				*(p++)= msglen & 0xff;
				n=msglen+2;
				}
			memcpy(p, tmp, msglen);
			
			if (EVP_PKEY_CTX_ctrl(pkey_ctx, -1, -1, EVP_PKEY_CTRL_PEER_KEY, 2, NULL) > 0)
				{
				
				s->s3->flags |= TLS1_FLAGS_SKIP_CERT_VERIFY;
				}
			EVP_PKEY_CTX_free(pkey_ctx);
			s->session->master_key_length= s->method->ssl3_enc->generate_master_secret(s, s->session->master_key,premaster_secret,32);

			EVP_PKEY_free(pub_key);

			}

		else if (alg_k & SSL_kSRP)
			{
			if (s->srp_ctx.A != NULL)
				{
				
				n=BN_num_bytes(s->srp_ctx.A);
				s2n(n,p);
				BN_bn2bin(s->srp_ctx.A,p);
				n+=2;
				}
			else {
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
				goto err;
				}
			if (s->session->srp_username != NULL)
				OPENSSL_free(s->session->srp_username);
			s->session->srp_username = BUF_strdup(s->srp_ctx.login);
			if (s->session->srp_username == NULL)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
				goto err;
				}

			if ((s->session->master_key_length = SRP_generate_client_master_secret(s,s->session->master_key))<0)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE,ERR_R_INTERNAL_ERROR);
				goto err;
				}
			}


		else if (alg_k & SSL_kPSK)
			{
			
			char identity[PSK_MAX_IDENTITY_LEN + 2];
			size_t identity_len;
			unsigned char *t = NULL;
			unsigned char psk_or_pre_ms[PSK_MAX_PSK_LEN*2+4];
			unsigned int pre_ms_len = 0, psk_len = 0;
			int psk_err = 1;

			n = 0;
			if (s->psk_client_callback == NULL)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, SSL_R_PSK_NO_CLIENT_CB);
				goto err;
				}

			memset(identity, 0, sizeof(identity));
			psk_len = s->psk_client_callback(s, s->ctx->psk_identity_hint, identity, sizeof(identity) - 1, psk_or_pre_ms, sizeof(psk_or_pre_ms));

			if (psk_len > PSK_MAX_PSK_LEN)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
				goto psk_err;
				}
			else if (psk_len == 0)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, SSL_R_PSK_IDENTITY_NOT_FOUND);
				goto psk_err;
				}
			identity[PSK_MAX_IDENTITY_LEN + 1] = '\0';
			identity_len = strlen(identity);
			if (identity_len > PSK_MAX_IDENTITY_LEN)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
				goto psk_err;
				}
			
			pre_ms_len = 2+psk_len+2+psk_len;
			t = psk_or_pre_ms;
			memmove(psk_or_pre_ms+psk_len+4, psk_or_pre_ms, psk_len);
			s2n(psk_len, t);
			memset(t, 0, psk_len);
			t+=psk_len;
			s2n(psk_len, t);

			if (s->session->psk_identity_hint != NULL)
				OPENSSL_free(s->session->psk_identity_hint);
			s->session->psk_identity_hint = BUF_strdup(s->ctx->psk_identity_hint);
			if (s->ctx->psk_identity_hint != NULL && s->session->psk_identity_hint == NULL)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
				goto psk_err;
				}

			if (s->session->psk_identity != NULL)
				OPENSSL_free(s->session->psk_identity);
			s->session->psk_identity = BUF_strdup(identity);
			if (s->session->psk_identity == NULL)
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
				goto psk_err;
				}

			s->session->master_key_length = s->method->ssl3_enc->generate_master_secret(s, s->session->master_key, psk_or_pre_ms, pre_ms_len);


			s2n(identity_len, p);
			memcpy(p, identity, identity_len);
			n = 2 + identity_len;
			psk_err = 0;
		psk_err:
			OPENSSL_cleanse(identity, sizeof(identity));
			OPENSSL_cleanse(psk_or_pre_ms, sizeof(psk_or_pre_ms));
			if (psk_err != 0)
				{
				ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
				goto err;
				}
			}

		else {
			ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
			SSLerr(SSL_F_SSL3_SEND_CLIENT_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
			goto err;
			}

		ssl_set_handshake_header(s, SSL3_MT_CLIENT_KEY_EXCHANGE, n);
		s->state=SSL3_ST_CW_KEY_EXCH_B;
		}

	
	return ssl_do_write(s);
err:

	BN_CTX_free(bn_ctx);
	if (encodedPoint != NULL) OPENSSL_free(encodedPoint);
	if (clnt_ecdh != NULL) 
		EC_KEY_free(clnt_ecdh);
	EVP_PKEY_free(srvr_pub_pkey);

	return(-1);
	}

int ssl3_send_client_verify(SSL *s)
	{
	unsigned char *p;
	unsigned char data[MD5_DIGEST_LENGTH+SHA_DIGEST_LENGTH];
	EVP_PKEY *pkey;
	EVP_PKEY_CTX *pctx=NULL;
	EVP_MD_CTX mctx;
	unsigned u=0;
	unsigned long n;
	int j;

	EVP_MD_CTX_init(&mctx);

	if (s->state == SSL3_ST_CW_CERT_VRFY_A)
		{
		p= ssl_handshake_start(s);
		pkey=s->cert->key->privatekey;

		pctx = EVP_PKEY_CTX_new(pkey,NULL);
		EVP_PKEY_sign_init(pctx);
		if (EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha1())>0)
			{
			if (!SSL_USE_SIGALGS(s))
				s->method->ssl3_enc->cert_verify_mac(s, NID_sha1, &(data[MD5_DIGEST_LENGTH]));

			}
		else {
			ERR_clear_error();
			}
		
		if (SSL_USE_SIGALGS(s))
			{
			long hdatalen = 0;
			void *hdata;
			const EVP_MD *md = s->cert->key->digest;
			hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
			if (hdatalen <= 0 || !tls12_get_sigandhash(p, pkey, md))
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
				goto err;
				}
			p += 2;

			fprintf(stderr, "Using TLS 1.2 with client alg %s\n", EVP_MD_name(md));

			if (!EVP_SignInit_ex(&mctx, md, NULL)
				|| !EVP_SignUpdate(&mctx, hdata, hdatalen)
				|| !EVP_SignFinal(&mctx, p + 2, &u, pkey))
				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_EVP_LIB);
				goto err;
				}
			s2n(u,p);
			n = u + 4;
			if (!ssl3_digest_cached_records(s))
				goto err;
			}
		else  if (pkey->type == EVP_PKEY_RSA)

			{
			s->method->ssl3_enc->cert_verify_mac(s, NID_md5, &(data[0]));

			if (RSA_sign(NID_md5_sha1, data, MD5_DIGEST_LENGTH+SHA_DIGEST_LENGTH, &(p[2]), &u, pkey->pkey.rsa) <= 0 )

				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,ERR_R_RSA_LIB);
				goto err;
				}
			s2n(u,p);
			n=u+2;
			}
		else   if (pkey->type == EVP_PKEY_DSA)


			{
			if (!DSA_sign(pkey->save_type, &(data[MD5_DIGEST_LENGTH]), SHA_DIGEST_LENGTH,&(p[2]), (unsigned int *)&j,pkey->pkey.dsa))


				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,ERR_R_DSA_LIB);
				goto err;
				}
			s2n(j,p);
			n=j+2;
			}
		else   if (pkey->type == EVP_PKEY_EC)


			{
			if (!ECDSA_sign(pkey->save_type, &(data[MD5_DIGEST_LENGTH]), SHA_DIGEST_LENGTH,&(p[2]), (unsigned int *)&j,pkey->pkey.ec))


				{
				SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_ECDSA_LIB);
				goto err;
				}
			s2n(j,p);
			n=j+2;
			}
		else  if (pkey->type == NID_id_GostR3410_94 || pkey->type == NID_id_GostR3410_2001)

		{
		unsigned char signbuf[64];
		int i;
		size_t sigsize=64;
		s->method->ssl3_enc->cert_verify_mac(s, NID_id_GostR3411_94, data);

		if (EVP_PKEY_sign(pctx, signbuf, &sigsize, data, 32) <= 0) {
			SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY, ERR_R_INTERNAL_ERROR);
			goto err;
		}
		for (i=63,j=0; i>=0; j++, i--) {
			p[2+j]=signbuf[i];
		}	
		s2n(j,p);
		n=j+2;
		}
		else {
			SSLerr(SSL_F_SSL3_SEND_CLIENT_VERIFY,ERR_R_INTERNAL_ERROR);
			goto err;
		}
		ssl_set_handshake_header(s, SSL3_MT_CERTIFICATE_VERIFY, n);
		s->state=SSL3_ST_CW_CERT_VRFY_B;
		}
	EVP_MD_CTX_cleanup(&mctx);
	EVP_PKEY_CTX_free(pctx);
	return ssl_do_write(s);
err:
	EVP_MD_CTX_cleanup(&mctx);
	EVP_PKEY_CTX_free(pctx);
	return(-1);
	}


static int ssl3_check_client_certificate(SSL *s)
	{
	unsigned long alg_k;
	if (!s->cert || !s->cert->key->x509 || !s->cert->key->privatekey)
		return 0;
	
	if (SSL_USE_SIGALGS(s) && !s->cert->key->digest)
		return 0;
	
	if (s->cert->cert_flags & SSL_CERT_FLAGS_CHECK_TLS_STRICT && !tls1_check_chain(s, NULL, NULL, NULL, -2))
		return 0;
	alg_k=s->s3->tmp.new_cipher->algorithm_mkey;
	
	if (alg_k & (SSL_kDHr|SSL_kDHd))
		{
		SESS_CERT *scert = s->session->sess_cert;
		int i = scert->peer_cert_type;
		EVP_PKEY *clkey = NULL, *spkey = NULL;
		clkey = s->cert->key->privatekey;
		
		if (EVP_PKEY_id(clkey) != EVP_PKEY_DH)
			return 1;
		if (i >= 0)
			spkey = X509_get_pubkey(scert->peer_pkeys[i].x509);
		if (spkey)
			{
			
			i = EVP_PKEY_cmp_parameters(clkey, spkey);
			EVP_PKEY_free(spkey);
			if (i != 1)
				return 0;
			}
		s->s3->flags |= TLS1_FLAGS_SKIP_CERT_VERIFY;
		}
	return 1;
	}

int ssl3_send_client_certificate(SSL *s)
	{
	X509 *x509=NULL;
	EVP_PKEY *pkey=NULL;
	int i;

	if (s->state ==	SSL3_ST_CW_CERT_A)
		{
		
		if (s->cert->cert_cb)
			{
			i = s->cert->cert_cb(s, s->cert->cert_cb_arg);
			if (i < 0)
				{
				s->rwstate=SSL_X509_LOOKUP;
				return -1;
				}
			if (i == 0)
				{
				ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_INTERNAL_ERROR);
				return 0;
				}
			s->rwstate=SSL_NOTHING;
			}
		if (ssl3_check_client_certificate(s))
			s->state=SSL3_ST_CW_CERT_C;
		else s->state=SSL3_ST_CW_CERT_B;
		}

	
	if (s->state == SSL3_ST_CW_CERT_B)
		{
		
		i=0;
		i = ssl_do_client_cert_cb(s, &x509, &pkey);
		if (i < 0)
			{
			s->rwstate=SSL_X509_LOOKUP;
			return(-1);
			}
		s->rwstate=SSL_NOTHING;
		if ((i == 1) && (pkey != NULL) && (x509 != NULL))
			{
			s->state=SSL3_ST_CW_CERT_B;
			if (	!SSL_use_certificate(s,x509) || !SSL_use_PrivateKey(s,pkey))
				i=0;
			}
		else if (i == 1)
			{
			i=0;
			SSLerr(SSL_F_SSL3_SEND_CLIENT_CERTIFICATE,SSL_R_BAD_DATA_RETURNED_BY_CALLBACK);
			}

		if (x509 != NULL) X509_free(x509);
		if (pkey != NULL) EVP_PKEY_free(pkey);
		if (i && !ssl3_check_client_certificate(s))
			i = 0;
		if (i == 0)
			{
			if (s->version == SSL3_VERSION)
				{
				s->s3->tmp.cert_req=0;
				ssl3_send_alert(s,SSL3_AL_WARNING,SSL_AD_NO_CERTIFICATE);
				return(1);
				}
			else {
				s->s3->tmp.cert_req=2;
				}
			}

		
		s->state=SSL3_ST_CW_CERT_C;
		}

	if (s->state == SSL3_ST_CW_CERT_C)
		{
		s->state=SSL3_ST_CW_CERT_D;
		if (!ssl3_output_cert_chain(s, (s->s3->tmp.cert_req == 2)?NULL:s->cert->key))
			{
			SSLerr(SSL_F_SSL3_SEND_CLIENT_CERTIFICATE, ERR_R_INTERNAL_ERROR);
			ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_INTERNAL_ERROR);
			return 0;
			}
		}
	
	return ssl_do_write(s);
	}



int ssl3_check_cert_and_algorithm(SSL *s)
	{
	int i,idx;
	long alg_k,alg_a;
	EVP_PKEY *pkey=NULL;
	SESS_CERT *sc;

	RSA *rsa;


	DH *dh;


	alg_k=s->s3->tmp.new_cipher->algorithm_mkey;
	alg_a=s->s3->tmp.new_cipher->algorithm_auth;

	
	if ((alg_a & (SSL_aNULL|SSL_aKRB5)) || (alg_k & SSL_kPSK))
		return(1);

	sc=s->session->sess_cert;
	if (sc == NULL)
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,ERR_R_INTERNAL_ERROR);
		goto err;
		}


	rsa=s->session->sess_cert->peer_rsa_tmp;


	dh=s->session->sess_cert->peer_dh_tmp;


	

	idx=sc->peer_cert_type;

	if (idx == SSL_PKEY_ECC)
		{
		if (ssl_check_srvr_ecc_cert_and_alg(sc->peer_pkeys[idx].x509, s) == 0)
			{ 
			SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_BAD_ECC_CERT);
			goto f_err;
			}
		else  {
			return 1;
			}
		}
	else if (alg_a & SSL_aECDSA)
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_ECDSA_SIGNING_CERT);
		goto f_err;
		}
	else if (alg_k & (SSL_kECDHr|SSL_kECDHe))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_ECDH_CERT);
		goto f_err;
		}

	pkey=X509_get_pubkey(sc->peer_pkeys[idx].x509);
	i=X509_certificate_type(sc->peer_pkeys[idx].x509,pkey);
	EVP_PKEY_free(pkey);

	
	
	if ((alg_a & SSL_aRSA) && !has_bits(i,EVP_PK_RSA|EVP_PKT_SIGN))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_RSA_SIGNING_CERT);
		goto f_err;
		}

	else if ((alg_a & SSL_aDSS) && !has_bits(i,EVP_PK_DSA|EVP_PKT_SIGN))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_DSA_SIGNING_CERT);
		goto f_err;
		}


	if ((alg_k & SSL_kRSA) && !(has_bits(i,EVP_PK_RSA|EVP_PKT_ENC) || (rsa != NULL)))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_RSA_ENCRYPTING_CERT);
		goto f_err;
		}


	if ((alg_k & SSL_kDHE) &&  !(has_bits(i,EVP_PK_DH|EVP_PKT_EXCH) || (dh != NULL)))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_DH_KEY);
		goto f_err;
		}
	else if ((alg_k & SSL_kDHr) && !SSL_USE_SIGALGS(s) && !has_bits(i,EVP_PK_DH|EVP_PKS_RSA))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_DH_RSA_CERT);
		goto f_err;
		}

	else if ((alg_k & SSL_kDHd) && !SSL_USE_SIGALGS(s) && !has_bits(i,EVP_PK_DH|EVP_PKS_DSA))
		{
		SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_DH_DSA_CERT);
		goto f_err;
		}



	if (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher) && !has_bits(i,EVP_PKT_EXP))
		{

		if (alg_k & SSL_kRSA)
			{
			if (rsa == NULL || RSA_size(rsa)*8 > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher))
				{
				SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_EXPORT_TMP_RSA_KEY);
				goto f_err;
				}
			}
		else   if (alg_k & (SSL_kDHE|SSL_kDHr|SSL_kDHd))


			    {
			    if (dh == NULL || DH_size(dh)*8 > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher))
				{
				SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_MISSING_EXPORT_TMP_DH_KEY);
				goto f_err;
				}
			}
		else  {

			SSLerr(SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM,SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE);
			goto f_err;
			}
		}
	return(1);
f_err:
	ssl3_send_alert(s,SSL3_AL_FATAL,SSL_AD_HANDSHAKE_FAILURE);
err:
	return(0);
	}





int ssl3_send_next_proto(SSL *s)
	{
	unsigned int len, padding_len;
	unsigned char *d;

	if (s->state == SSL3_ST_CW_NEXT_PROTO_A)
		{
		len = s->next_proto_negotiated_len;
		padding_len = 32 - ((len + 2) % 32);
		d = (unsigned char *)s->init_buf->data;
		d[4] = len;
		memcpy(d + 5, s->next_proto_negotiated, len);
		d[5 + len] = padding_len;
		memset(d + 6 + len, 0, padding_len);
		*(d++)=SSL3_MT_NEXT_PROTO;
		l2n3(2 + len + padding_len, d);
		s->state = SSL3_ST_CW_NEXT_PROTO_B;
		s->init_num = 4 + 2 + len + padding_len;
		s->init_off = 0;
		}

	return ssl3_do_write(s, SSL3_RT_HANDSHAKE);
	}



int ssl_do_client_cert_cb(SSL *s, X509 **px509, EVP_PKEY **ppkey)
	{
	int i = 0;

	if (s->ctx->client_cert_engine)
		{
		i = ENGINE_load_ssl_client_cert(s->ctx->client_cert_engine, s, SSL_get_client_CA_list(s), px509, ppkey, NULL, NULL, NULL);

		if (i != 0)
			return i;
		}

	if (s->ctx->client_cert_cb)
		i = s->ctx->client_cert_cb(s,px509,ppkey);
	return i;
	}
