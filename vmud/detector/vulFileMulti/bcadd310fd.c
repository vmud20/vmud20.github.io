

















static const SSL_METHOD *dtls1_get_server_method(int ver);
static int dtls1_send_hello_verify_request(SSL *s);

static const SSL_METHOD *dtls1_get_server_method(int ver)
	{
	if (ver == DTLS1_VERSION)
		return(DTLSv1_server_method());
	else if (ver == DTLS1_2_VERSION)
		return(DTLSv1_2_server_method());
	else return(NULL);
	}

IMPLEMENT_dtls1_meth_func(DTLS1_VERSION, DTLSv1_server_method, dtls1_accept, ssl_undefined_function, dtls1_get_server_method, DTLSv1_enc_data)





IMPLEMENT_dtls1_meth_func(DTLS1_2_VERSION, DTLSv1_2_server_method, dtls1_accept, ssl_undefined_function, dtls1_get_server_method, DTLSv1_2_enc_data)





IMPLEMENT_dtls1_meth_func(DTLS_ANY_VERSION, DTLS_server_method, dtls1_accept, ssl_undefined_function, dtls1_get_server_method, DTLSv1_2_enc_data)





int dtls1_accept(SSL *s)
	{
	BUF_MEM *buf;
	unsigned long Time=(unsigned long)time(NULL);
	void (*cb)(const SSL *ssl,int type,int val)=NULL;
	unsigned long alg_k;
	int ret= -1;
	int new_state,state,skip=0;
	int listen;

	unsigned char sctpauthkey[64];
	char labelbuffer[sizeof(DTLS1_SCTP_AUTH_LABEL)];


	RAND_add(&Time,sizeof(Time),0);
	ERR_clear_error();
	clear_sys_error();

	if (s->info_callback != NULL)
		cb=s->info_callback;
	else if (s->ctx->info_callback != NULL)
		cb=s->ctx->info_callback;
	
	listen = s->d1->listen;

	
	s->in_handshake++;
	if (!SSL_in_init(s) || SSL_in_before(s)) SSL_clear(s);

	s->d1->listen = listen;

	
	BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE, s->in_handshake, NULL);


	if (s->cert == NULL)
		{
		SSLerr(SSL_F_DTLS1_ACCEPT,SSL_R_NO_CERTIFICATE_SET);
		return(-1);
		}


	
	if (s->tlsext_hb_pending)
		{
		dtls1_stop_timer(s);
		s->tlsext_hb_pending = 0;
		s->tlsext_hb_seq++;
		}


	for (;;)
		{
		state=s->state;

		switch (s->state)
			{
		case SSL_ST_RENEGOTIATE:
			s->renegotiate=1;
			

		case SSL_ST_BEFORE:
		case SSL_ST_ACCEPT:
		case SSL_ST_BEFORE|SSL_ST_ACCEPT:
		case SSL_ST_OK|SSL_ST_ACCEPT:

			s->server=1;
			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_START,1);

			if ((s->version & 0xff00) != (DTLS1_VERSION & 0xff00))
				{
				SSLerr(SSL_F_DTLS1_ACCEPT, ERR_R_INTERNAL_ERROR);
				return -1;
				}
			s->type=SSL_ST_ACCEPT;

			if (s->init_buf == NULL)
				{
				if ((buf=BUF_MEM_new()) == NULL)
					{
					ret= -1;
					goto end;
					}
				if (!BUF_MEM_grow(buf,SSL3_RT_MAX_PLAIN_LENGTH))
					{
					BUF_MEM_free(buf);
					ret= -1;
					goto end;
					}
				s->init_buf=buf;
				}

			if (!ssl3_setup_buffers(s))
				{
				ret= -1;
				goto end;
				}

			s->init_num=0;
			s->d1->change_cipher_spec_ok = 0;
			
			s->s3->change_cipher_spec = 0;

			if (s->state != SSL_ST_RENEGOTIATE)
				{
				

				if (!BIO_dgram_is_sctp(SSL_get_wbio(s)))

					if (!ssl_init_wbio_buffer(s,1)) { ret= -1; goto end; }

				ssl3_init_finished_mac(s);
				s->state=SSL3_ST_SR_CLNT_HELLO_A;
				s->ctx->stats.sess_accept++;
				}
			else {
				
				s->ctx->stats.sess_accept_renegotiate++;
				s->state=SSL3_ST_SW_HELLO_REQ_A;
				}

			break;

		case SSL3_ST_SW_HELLO_REQ_A:
		case SSL3_ST_SW_HELLO_REQ_B:

			s->shutdown=0;
			dtls1_clear_record_buffer(s);
			dtls1_start_timer(s);
			ret=ssl3_send_hello_request(s);
			if (ret <= 0) goto end;
			s->s3->tmp.next_state=SSL3_ST_SR_CLNT_HELLO_A;
			s->state=SSL3_ST_SW_FLUSH;
			s->init_num=0;

			ssl3_init_finished_mac(s);
			break;

		case SSL3_ST_SW_HELLO_REQ_C:
			s->state=SSL_ST_OK;
			break;

		case SSL3_ST_SR_CLNT_HELLO_A:
		case SSL3_ST_SR_CLNT_HELLO_B:
		case SSL3_ST_SR_CLNT_HELLO_C:

			s->shutdown=0;
			ret=ssl3_get_client_hello(s);
			if (ret <= 0) goto end;
			dtls1_stop_timer(s);

			if (ret == 1 && (SSL_get_options(s) & SSL_OP_COOKIE_EXCHANGE))
				s->state = DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A;
			else s->state = SSL3_ST_SW_SRVR_HELLO_A;

			s->init_num=0;

			
			if (listen)
				{
				memcpy(s->s3->write_sequence, s->s3->read_sequence, sizeof(s->s3->write_sequence));
				}

			
			if (listen && s->state == SSL3_ST_SW_SRVR_HELLO_A)
				{
				ret = 2;
				s->d1->listen = 0;
				
				s->d1->handshake_read_seq = 2;
				s->d1->handshake_write_seq = 1;
				s->d1->next_handshake_write_seq = 1;
				goto end;
				}
			
			break;
			
		case DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A:
		case DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B:

			ret = dtls1_send_hello_verify_request(s);
			if ( ret <= 0) goto end;
			s->state=SSL3_ST_SW_FLUSH;
			s->s3->tmp.next_state=SSL3_ST_SR_CLNT_HELLO_A;

			
			if (s->version != DTLS1_BAD_VER)
				ssl3_init_finished_mac(s);
			break;
			

		case DTLS1_SCTP_ST_SR_READ_SOCK:
			
			if (BIO_dgram_sctp_msg_waiting(SSL_get_rbio(s)))		
				{
				s->s3->in_read_app_data=2;
				s->rwstate=SSL_READING;
				BIO_clear_retry_flags(SSL_get_rbio(s));
				BIO_set_retry_read(SSL_get_rbio(s));
				ret = -1;
				goto end;
				}
			
			s->state=SSL3_ST_SR_FINISHED_A;
			break;
			
		case DTLS1_SCTP_ST_SW_WRITE_SOCK:
			ret = BIO_dgram_sctp_wait_for_dry(SSL_get_wbio(s));
			if (ret < 0) goto end;
			
			if (ret == 0)
				{
				if (s->d1->next_state != SSL_ST_OK)
					{
					s->s3->in_read_app_data=2;
					s->rwstate=SSL_READING;
					BIO_clear_retry_flags(SSL_get_rbio(s));
					BIO_set_retry_read(SSL_get_rbio(s));
					ret = -1;
					goto end;
					}
				}

			s->state=s->d1->next_state;
			break;


		case SSL3_ST_SW_SRVR_HELLO_A:
		case SSL3_ST_SW_SRVR_HELLO_B:
			s->renegotiate = 2;
			dtls1_start_timer(s);
			ret=ssl3_send_server_hello(s);
			if (ret <= 0) goto end;

			if (s->hit)
				{

				
				snprintf((char*) labelbuffer, sizeof(DTLS1_SCTP_AUTH_LABEL), DTLS1_SCTP_AUTH_LABEL);

				SSL_export_keying_material(s, sctpauthkey, sizeof(sctpauthkey), labelbuffer, sizeof(labelbuffer), NULL, 0, 0);

				
				BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY, sizeof(sctpauthkey), sctpauthkey);


				if (s->tlsext_ticket_expected)
					s->state=SSL3_ST_SW_SESSION_TICKET_A;
				else s->state=SSL3_ST_SW_CHANGE_A;

				s->state=SSL3_ST_SW_CHANGE_A;

				}
			else s->state=SSL3_ST_SW_CERT_A;
			s->init_num=0;
			break;

		case SSL3_ST_SW_CERT_A:
		case SSL3_ST_SW_CERT_B:
			
			if (!(s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL)
				&& !(s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK))
				{
				dtls1_start_timer(s);
				ret=ssl3_send_server_certificate(s);
				if (ret <= 0) goto end;

				if (s->tlsext_status_expected)
					s->state=SSL3_ST_SW_CERT_STATUS_A;
				else s->state=SSL3_ST_SW_KEY_EXCH_A;
				}
			else {
				skip = 1;
				s->state=SSL3_ST_SW_KEY_EXCH_A;
				}

				}
			else skip=1;

			s->state=SSL3_ST_SW_KEY_EXCH_A;

			s->init_num=0;
			break;

		case SSL3_ST_SW_KEY_EXCH_A:
		case SSL3_ST_SW_KEY_EXCH_B:
			alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

			
			if ((s->options & SSL_OP_EPHEMERAL_RSA)

				&& !(alg_k & SSL_kKRB5)

				)
				
				s->s3->tmp.use_rsa_tmp=1;
			else s->s3->tmp.use_rsa_tmp=0;

			
			if (s->s3->tmp.use_rsa_tmp   || ((alg_k & SSL_kPSK) && s->ctx->psk_identity_hint)



			    || (alg_k & (SSL_kDHE|SSL_kDHr|SSL_kDHd))
			    || (alg_k & SSL_kECDHE)
			    || ((alg_k & SSL_kRSA)
				&& (s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey == NULL || (SSL_C_IS_EXPORT(s->s3->tmp.new_cipher)
					&& EVP_PKEY_size(s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey)*8 > SSL_C_EXPORT_PKEYLENGTH(s->s3->tmp.new_cipher)
					)
				    )
				)
			    )
				{
				dtls1_start_timer(s);
				ret=ssl3_send_server_key_exchange(s);
				if (ret <= 0) goto end;
				}
			else skip=1;

			s->state=SSL3_ST_SW_CERT_REQ_A;
			s->init_num=0;
			break;

		case SSL3_ST_SW_CERT_REQ_A:
		case SSL3_ST_SW_CERT_REQ_B:
			if ( !(s->verify_mode & SSL_VERIFY_PEER) ||  ((s->session->peer != NULL) && (s->verify_mode & SSL_VERIFY_CLIENT_ONCE)) ||  ((s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) &&  !(s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) ||  (s->s3->tmp.new_cipher->algorithm_auth & SSL_aKRB5)









				
				|| (s->s3->tmp.new_cipher->algorithm_mkey & SSL_kPSK))
				{
				
				skip=1;
				s->s3->tmp.cert_request=0;
				s->state=SSL3_ST_SW_SRVR_DONE_A;

				if (BIO_dgram_is_sctp(SSL_get_wbio(s)))
					{
					s->d1->next_state = SSL3_ST_SW_SRVR_DONE_A;
					s->state = DTLS1_SCTP_ST_SW_WRITE_SOCK;
					}

				}
			else {
				s->s3->tmp.cert_request=1;
				dtls1_start_timer(s);
				ret=ssl3_send_certificate_request(s);
				if (ret <= 0) goto end;

				s->state=SSL3_ST_SW_SRVR_DONE_A;

				if (BIO_dgram_is_sctp(SSL_get_wbio(s)))
					{
					s->d1->next_state = SSL3_ST_SW_SRVR_DONE_A;
					s->state = DTLS1_SCTP_ST_SW_WRITE_SOCK;
					}


				s->state=SSL3_ST_SW_FLUSH;
				s->s3->tmp.next_state=SSL3_ST_SR_CERT_A;

				if (BIO_dgram_is_sctp(SSL_get_wbio(s)))
					{
					s->d1->next_state = s->s3->tmp.next_state;
					s->s3->tmp.next_state=DTLS1_SCTP_ST_SW_WRITE_SOCK;
					}


				s->init_num=0;
				}
			break;

		case SSL3_ST_SW_SRVR_DONE_A:
		case SSL3_ST_SW_SRVR_DONE_B:
			dtls1_start_timer(s);
			ret=ssl3_send_server_done(s);
			if (ret <= 0) goto end;
			s->s3->tmp.next_state=SSL3_ST_SR_CERT_A;
			s->state=SSL3_ST_SW_FLUSH;
			s->init_num=0;
			break;
		
		case SSL3_ST_SW_FLUSH:
			s->rwstate=SSL_WRITING;
			if (BIO_flush(s->wbio) <= 0)
				{
				
				if (!BIO_should_retry(s->wbio))
					{
					s->rwstate=SSL_NOTHING;
					s->state=s->s3->tmp.next_state;
					}
				
				ret= -1;
				goto end;
				}
			s->rwstate=SSL_NOTHING;
			s->state=s->s3->tmp.next_state;
			break;

		case SSL3_ST_SR_CERT_A:
		case SSL3_ST_SR_CERT_B:
			if (s->s3->tmp.cert_request)
				{
				ret=ssl3_get_client_certificate(s);
				if (ret <= 0) goto end;
				}
			s->init_num=0;
			s->state=SSL3_ST_SR_KEY_EXCH_A;
			break;

		case SSL3_ST_SR_KEY_EXCH_A:
		case SSL3_ST_SR_KEY_EXCH_B:
			ret=ssl3_get_client_key_exchange(s);
			if (ret <= 0) goto end;

			
			snprintf((char *) labelbuffer, sizeof(DTLS1_SCTP_AUTH_LABEL), DTLS1_SCTP_AUTH_LABEL);

			SSL_export_keying_material(s, sctpauthkey, sizeof(sctpauthkey), labelbuffer, sizeof(labelbuffer), NULL, 0, 0);


			BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY, sizeof(sctpauthkey), sctpauthkey);


			s->state=SSL3_ST_SR_CERT_VRFY_A;
			s->init_num=0;

			if (ret == 2)
				{
				
				s->state=SSL3_ST_SR_FINISHED_A;
				s->init_num = 0;
				}
			else if (SSL_USE_SIGALGS(s))
				{
				s->state=SSL3_ST_SR_CERT_VRFY_A;
				s->init_num=0;
				if (!s->session->peer)
					break;
				
				if (!s->s3->handshake_buffer)
					{
					SSLerr(SSL_F_DTLS1_ACCEPT,ERR_R_INTERNAL_ERROR);
					return -1;
					}
				s->s3->flags |= TLS1_FLAGS_KEEP_HANDSHAKE;
				if (!ssl3_digest_cached_records(s))
					return -1;
				}
			else {
				s->state=SSL3_ST_SR_CERT_VRFY_A;
				s->init_num=0;

				 
				s->method->ssl3_enc->cert_verify_mac(s, NID_md5, &(s->s3->tmp.cert_verify_md[0]));

				s->method->ssl3_enc->cert_verify_mac(s, NID_sha1, &(s->s3->tmp.cert_verify_md[MD5_DIGEST_LENGTH]));

				}
			break;

		case SSL3_ST_SR_CERT_VRFY_A:
		case SSL3_ST_SR_CERT_VRFY_B:
			
			if (!s->s3->change_cipher_spec)
				s->d1->change_cipher_spec_ok = 1;
			
			ret=ssl3_get_cert_verify(s);
			if (ret <= 0) goto end;

			if (BIO_dgram_is_sctp(SSL_get_wbio(s)) && state == SSL_ST_RENEGOTIATE)
				s->state=DTLS1_SCTP_ST_SR_READ_SOCK;
			else  s->state=SSL3_ST_SR_FINISHED_A;

			s->init_num=0;
			break;

		case SSL3_ST_SR_FINISHED_A:
		case SSL3_ST_SR_FINISHED_B:
			
			if (!s->s3->change_cipher_spec)
				s->d1->change_cipher_spec_ok = 1;
			ret=ssl3_get_finished(s,SSL3_ST_SR_FINISHED_A, SSL3_ST_SR_FINISHED_B);
			if (ret <= 0) goto end;
			dtls1_stop_timer(s);
			if (s->hit)
				s->state=SSL_ST_OK;

			else if (s->tlsext_ticket_expected)
				s->state=SSL3_ST_SW_SESSION_TICKET_A;

			else s->state=SSL3_ST_SW_CHANGE_A;
			s->init_num=0;
			break;


		case SSL3_ST_SW_SESSION_TICKET_A:
		case SSL3_ST_SW_SESSION_TICKET_B:
			ret=ssl3_send_newsession_ticket(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_SW_CHANGE_A;
			s->init_num=0;
			break;

		case SSL3_ST_SW_CERT_STATUS_A:
		case SSL3_ST_SW_CERT_STATUS_B:
			ret=ssl3_send_cert_status(s);
			if (ret <= 0) goto end;
			s->state=SSL3_ST_SW_KEY_EXCH_A;
			s->init_num=0;
			break;



		case SSL3_ST_SW_CHANGE_A:
		case SSL3_ST_SW_CHANGE_B:

			s->session->cipher=s->s3->tmp.new_cipher;
			if (!s->method->ssl3_enc->setup_key_block(s))
				{ ret= -1; goto end; }

			ret=dtls1_send_change_cipher_spec(s, SSL3_ST_SW_CHANGE_A,SSL3_ST_SW_CHANGE_B);

			if (ret <= 0) goto end;


			if (!s->hit)
				{
				
				BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY, 0, NULL);
				}


			s->state=SSL3_ST_SW_FINISHED_A;
			s->init_num=0;

			if (!s->method->ssl3_enc->change_cipher_state(s, SSL3_CHANGE_CIPHER_SERVER_WRITE))
				{
				ret= -1;
				goto end;
				}

			dtls1_reset_seq_numbers(s, SSL3_CC_WRITE);
			break;

		case SSL3_ST_SW_FINISHED_A:
		case SSL3_ST_SW_FINISHED_B:
			ret=ssl3_send_finished(s, SSL3_ST_SW_FINISHED_A,SSL3_ST_SW_FINISHED_B, s->method->ssl3_enc->server_finished_label, s->method->ssl3_enc->server_finished_label_len);


			if (ret <= 0) goto end;
			s->state=SSL3_ST_SW_FLUSH;
			if (s->hit)
				{
				s->s3->tmp.next_state=SSL3_ST_SR_FINISHED_A;


				
				BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY, 0, NULL);

				}
			else {
				s->s3->tmp.next_state=SSL_ST_OK;

				if (BIO_dgram_is_sctp(SSL_get_wbio(s)))
					{
					s->d1->next_state = s->s3->tmp.next_state;
					s->s3->tmp.next_state=DTLS1_SCTP_ST_SW_WRITE_SOCK;
					}

				}
			s->init_num=0;
			break;

		case SSL_ST_OK:
			
			ssl3_cleanup_key_block(s);


			BUF_MEM_free(s->init_buf);
			s->init_buf=NULL;


			
			ssl_free_wbio_buffer(s);

			s->init_num=0;

			if (s->renegotiate == 2) 
				{
				s->renegotiate=0;
				s->new_session=0;
				
				ssl_update_cache(s,SSL_SESS_CACHE_SERVER);
				
				s->ctx->stats.sess_accept_good++;
				
				s->handshake_func=dtls1_accept;

				if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_DONE,1);
				}
			
			ret = 1;

			
			s->d1->handshake_read_seq = 0;
			
			s->d1->handshake_write_seq = 0;
			s->d1->next_handshake_write_seq = 0;
			goto end;
			

		default:
			SSLerr(SSL_F_DTLS1_ACCEPT,SSL_R_UNKNOWN_STATE);
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
				cb(s,SSL_CB_ACCEPT_LOOP,1);
				s->state=new_state;
				}
			}
		skip=0;
		}
end:
	

	s->in_handshake--;

		
		BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_SCTP_SET_IN_HANDSHAKE, s->in_handshake, NULL);


	if (cb != NULL)
		cb(s,SSL_CB_ACCEPT_EXIT,ret);
	return(ret);
	}

int dtls1_send_hello_verify_request(SSL *s)
	{
	unsigned int msg_len;
	unsigned char *msg, *buf, *p;

	if (s->state == DTLS1_ST_SW_HELLO_VERIFY_REQUEST_A)
		{
		buf = (unsigned char *)s->init_buf->data;

		msg = p = &(buf[DTLS1_HM_HEADER_LENGTH]);
		
		*(p++) = DTLS1_VERSION >> 8;
		*(p++) = DTLS1_VERSION & 0xFF;

		if (s->ctx->app_gen_cookie_cb == NULL || s->ctx->app_gen_cookie_cb(s, s->d1->cookie, &(s->d1->cookie_len)) == 0)

			{
			SSLerr(SSL_F_DTLS1_SEND_HELLO_VERIFY_REQUEST,ERR_R_INTERNAL_ERROR);
			return 0;
			}

		*(p++) = (unsigned char) s->d1->cookie_len;
		memcpy(p, s->d1->cookie, s->d1->cookie_len);
		p += s->d1->cookie_len;
		msg_len = p - msg;

		dtls1_set_message_header(s, buf, DTLS1_MT_HELLO_VERIFY_REQUEST, msg_len, 0, msg_len);

		s->state=DTLS1_ST_SW_HELLO_VERIFY_REQUEST_B;
		
		s->init_num=p-buf;
		s->init_off=0;
		}

	
	return(dtls1_do_write(s,SSL3_RT_HANDSHAKE));
	}
