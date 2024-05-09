























static const SSL_METHOD *ssl3_get_server_method(int ver);

const SSL_METHOD SSLv3_server_method_data = {
	.version = SSL3_VERSION, .ssl_new = ssl3_new, .ssl_clear = ssl3_clear, .ssl_free = ssl3_free, .ssl_accept = ssl3_accept, .ssl_connect = ssl_undefined_function, .ssl_read = ssl3_read, .ssl_peek = ssl3_peek, .ssl_write = ssl3_write, .ssl_shutdown = ssl3_shutdown, .ssl_renegotiate = ssl3_renegotiate, .ssl_renegotiate_check = ssl3_renegotiate_check, .ssl_get_message = ssl3_get_message, .ssl_read_bytes = ssl3_read_bytes, .ssl_write_bytes = ssl3_write_bytes, .ssl_dispatch_alert = ssl3_dispatch_alert, .ssl_ctrl = ssl3_ctrl, .ssl_ctx_ctrl = ssl3_ctx_ctrl, .get_cipher_by_char = ssl3_get_cipher_by_char, .put_cipher_by_char = ssl3_put_cipher_by_char, .ssl_pending = ssl3_pending, .num_ciphers = ssl3_num_ciphers, .get_cipher = ssl3_get_cipher, .get_ssl_method = ssl3_get_server_method, .get_timeout = ssl3_default_timeout, .ssl3_enc = &SSLv3_enc_data, .ssl_version = ssl_undefined_void_function, .ssl_callback_ctrl = ssl3_callback_ctrl, .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl, };





























const SSL_METHOD * SSLv3_server_method(void)
{
	return &SSLv3_server_method_data;
}

static const SSL_METHOD * ssl3_get_server_method(int ver)
{
	if (ver == SSL3_VERSION)
		return (SSLv3_server_method());
	return (NULL);
}

int ssl3_accept(SSL *s)
{
	unsigned long alg_k;
	void (*cb)(const SSL *ssl, int type, int val) = NULL;
	int ret = -1;
	int new_state, state, skip = 0;

	ERR_clear_error();
	errno = 0;

	if (s->info_callback != NULL)
		cb = s->info_callback;
	else if (s->ctx->info_callback != NULL)
		cb = s->ctx->info_callback;

	
	s->in_handshake++;
	if (!SSL_in_init(s) || SSL_in_before(s))
		SSL_clear(s);

	if (s->cert == NULL) {
		SSLerr(SSL_F_SSL3_ACCEPT, SSL_R_NO_CERTIFICATE_SET);
		return (-1);
	}

	for (;;) {
		state = s->state;

		switch (s->state) {
		case SSL_ST_RENEGOTIATE:
			s->renegotiate = 1;
			

		case SSL_ST_BEFORE:
		case SSL_ST_ACCEPT:
		case SSL_ST_BEFORE|SSL_ST_ACCEPT:
		case SSL_ST_OK|SSL_ST_ACCEPT:

			s->server = 1;
			if (cb != NULL)
				cb(s, SSL_CB_HANDSHAKE_START, 1);

			if ((s->version >> 8) != 3) {
				SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
				return (-1);
			}
			s->type = SSL_ST_ACCEPT;

			if (s->init_buf == NULL) {
				BUF_MEM *buf;
				if ((buf = BUF_MEM_new()) == NULL) {
					ret = -1;
					goto end;
				}
				if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
					BUF_MEM_free(buf);
					ret = -1;
					goto end;
				}
				s->init_buf = buf;
			}

			if (!ssl3_setup_buffers(s)) {
				ret = -1;
				goto end;
			}

			s->init_num = 0;
			s->s3->flags &= ~SSL3_FLAGS_SGC_RESTART_DONE;

			if (s->state != SSL_ST_RENEGOTIATE) {
				
				if (!ssl_init_wbio_buffer(s, 1)) {
					ret = -1;
					goto end;
				}

				if (!ssl3_init_finished_mac(s)) {
					ret = -1;
					goto end;
				}

				s->state = SSL3_ST_SR_CLNT_HELLO_A;
				s->ctx->stats.sess_accept++;
			} else if (!s->s3->send_connection_binding) {
				
				SSLerr(SSL_F_SSL3_ACCEPT, SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
				ssl3_send_alert(s, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
				ret = -1;
				goto end;
			} else {
				
				s->ctx->stats.sess_accept_renegotiate++;
				s->state = SSL3_ST_SW_HELLO_REQ_A;
			}
			break;

		case SSL3_ST_SW_HELLO_REQ_A:
		case SSL3_ST_SW_HELLO_REQ_B:

			s->shutdown = 0;
			ret = ssl3_send_hello_request(s);
			if (ret <= 0)
				goto end;
			s->s3->tmp.next_state = SSL3_ST_SW_HELLO_REQ_C;
			s->state = SSL3_ST_SW_FLUSH;
			s->init_num = 0;

			if (!ssl3_init_finished_mac(s)) {
				ret = -1;
				goto end;
			}
			break;

		case SSL3_ST_SW_HELLO_REQ_C:
			s->state = SSL_ST_OK;
			break;

		case SSL3_ST_SR_CLNT_HELLO_A:
		case SSL3_ST_SR_CLNT_HELLO_B:
		case SSL3_ST_SR_CLNT_HELLO_C:

			s->shutdown = 0;
			if (s->rwstate != SSL_X509_LOOKUP) {
				ret = ssl3_get_client_hello(s);
				if (ret <= 0)
					goto end;
			}

			s->renegotiate = 2;
			s->state = SSL3_ST_SW_SRVR_HELLO_A;
			s->init_num = 0;
			break;

		case SSL3_ST_SW_SRVR_HELLO_A:
		case SSL3_ST_SW_SRVR_HELLO_B:
			ret = ssl3_send_server_hello(s);
			if (ret <= 0)
				goto end;
			if (s->hit) {
				if (s->tlsext_ticket_expected)
					s->state = SSL3_ST_SW_SESSION_TICKET_A;
				else s->state = SSL3_ST_SW_CHANGE_A;
			}
			else s->state = SSL3_ST_SW_CERT_A;
			s->init_num = 0;
			break;

		case SSL3_ST_SW_CERT_A:
		case SSL3_ST_SW_CERT_B:
			
			if (!(s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL)) {
				ret = ssl3_send_server_certificate(s);
				if (ret <= 0)
					goto end;
				if (s->tlsext_status_expected)
					s->state = SSL3_ST_SW_CERT_STATUS_A;
				else s->state = SSL3_ST_SW_KEY_EXCH_A;
			} else {
				skip = 1;
				s->state = SSL3_ST_SW_KEY_EXCH_A;
			}
			s->init_num = 0;
			break;

		case SSL3_ST_SW_KEY_EXCH_A:
		case SSL3_ST_SW_KEY_EXCH_B:
			alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

			
			if (alg_k & (SSL_kDHE|SSL_kECDHE)) {
				ret = ssl3_send_server_key_exchange(s);
				if (ret <= 0)
					goto end;
			} else skip = 1;

			s->state = SSL3_ST_SW_CERT_REQ_A;
			s->init_num = 0;
			break;

		case SSL3_ST_SW_CERT_REQ_A:
		case SSL3_ST_SW_CERT_REQ_B:
			
			if (!(s->verify_mode & SSL_VERIFY_PEER) || ((s->session->peer != NULL) && (s->verify_mode & SSL_VERIFY_CLIENT_ONCE)) || ((s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL) && !(s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT))) {




				
				skip = 1;
				s->s3->tmp.cert_request = 0;
				s->state = SSL3_ST_SW_SRVR_DONE_A;
				if (s->s3->handshake_buffer)
					if (!ssl3_digest_cached_records(s))
						return (-1);
			} else {
				s->s3->tmp.cert_request = 1;
				ret = ssl3_send_certificate_request(s);
				if (ret <= 0)
					goto end;
				s->state = SSL3_ST_SW_SRVR_DONE_A;
				s->init_num = 0;
			}
			break;

		case SSL3_ST_SW_SRVR_DONE_A:
		case SSL3_ST_SW_SRVR_DONE_B:
			ret = ssl3_send_server_done(s);
			if (ret <= 0)
				goto end;
			s->s3->tmp.next_state = SSL3_ST_SR_CERT_A;
			s->state = SSL3_ST_SW_FLUSH;
			s->init_num = 0;
			break;

		case SSL3_ST_SW_FLUSH:

			

			s->rwstate = SSL_WRITING;
			if (BIO_flush(s->wbio) <= 0) {
				ret = -1;
				goto end;
			}
			s->rwstate = SSL_NOTHING;

			s->state = s->s3->tmp.next_state;
			break;

		case SSL3_ST_SR_CERT_A:
		case SSL3_ST_SR_CERT_B:
			
			ret = ssl3_check_client_hello(s);
			if (ret <= 0)
				goto end;
			if (ret == 2)
				s->state = SSL3_ST_SR_CLNT_HELLO_C;
			else {
				if (s->s3->tmp.cert_request) {
					ret = ssl3_get_client_certificate(s);
					if (ret <= 0)
						goto end;
				}
				s->init_num = 0;
				s->state = SSL3_ST_SR_KEY_EXCH_A;
			}
			break;

		case SSL3_ST_SR_KEY_EXCH_A:
		case SSL3_ST_SR_KEY_EXCH_B:
			ret = ssl3_get_client_key_exchange(s);
			if (ret <= 0)
				goto end;
			alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
			if (ret == 2) {
				
				if (s->s3->next_proto_neg_seen)
					s->state = SSL3_ST_SR_NEXT_PROTO_A;
				else s->state = SSL3_ST_SR_FINISHED_A;
				s->init_num = 0;
			} else if (SSL_USE_SIGALGS(s) || (alg_k & SSL_kGOST)) {
				s->state = SSL3_ST_SR_CERT_VRFY_A;
				s->init_num = 0;
				if (!s->session->peer)
					break;
				
				if (!s->s3->handshake_buffer) {
					SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
					return (-1);
				}
				s->s3->flags |= TLS1_FLAGS_KEEP_HANDSHAKE;
				if (!ssl3_digest_cached_records(s))
					return (-1);
			} else {
				int offset = 0;
				int dgst_num;

				s->state = SSL3_ST_SR_CERT_VRFY_A;
				s->init_num = 0;

				
				if (s->s3->handshake_buffer)
					if (!ssl3_digest_cached_records(s))
						return (-1);
				for (dgst_num = 0; dgst_num < SSL_MAX_DIGEST;
				    dgst_num++)
					if (s->s3->handshake_dgst[dgst_num]) {
					int dgst_size;

					s->method->ssl3_enc->cert_verify_mac(s, EVP_MD_CTX_type( s->s3->handshake_dgst[dgst_num]), &(s->s3->tmp.cert_verify_md[offset]));


					dgst_size = EVP_MD_CTX_size( s->s3->handshake_dgst[dgst_num]);
					if (dgst_size < 0) {
						ret = -1;
						goto end;
					}
					offset += dgst_size;
				}
			}
			break;

		case SSL3_ST_SR_CERT_VRFY_A:
		case SSL3_ST_SR_CERT_VRFY_B:
			s->s3->flags |= SSL3_FLAGS_CCS_OK;

			
			ret = ssl3_get_cert_verify(s);
			if (ret <= 0)
				goto end;

			if (s->s3->next_proto_neg_seen)
				s->state = SSL3_ST_SR_NEXT_PROTO_A;
			else s->state = SSL3_ST_SR_FINISHED_A;
			s->init_num = 0;
			break;

		case SSL3_ST_SR_NEXT_PROTO_A:
		case SSL3_ST_SR_NEXT_PROTO_B:
			ret = ssl3_get_next_proto(s);
			if (ret <= 0)
				goto end;
			s->init_num = 0;
			s->state = SSL3_ST_SR_FINISHED_A;
			break;

		case SSL3_ST_SR_FINISHED_A:
		case SSL3_ST_SR_FINISHED_B:
			s->s3->flags |= SSL3_FLAGS_CCS_OK;
			ret = ssl3_get_finished(s, SSL3_ST_SR_FINISHED_A, SSL3_ST_SR_FINISHED_B);
			if (ret <= 0)
				goto end;
			if (s->hit)
				s->state = SSL_ST_OK;
			else if (s->tlsext_ticket_expected)
				s->state = SSL3_ST_SW_SESSION_TICKET_A;
			else s->state = SSL3_ST_SW_CHANGE_A;
			s->init_num = 0;
			break;

		case SSL3_ST_SW_SESSION_TICKET_A:
		case SSL3_ST_SW_SESSION_TICKET_B:
			ret = ssl3_send_newsession_ticket(s);
			if (ret <= 0)
				goto end;
			s->state = SSL3_ST_SW_CHANGE_A;
			s->init_num = 0;
			break;

		case SSL3_ST_SW_CERT_STATUS_A:
		case SSL3_ST_SW_CERT_STATUS_B:
			ret = ssl3_send_cert_status(s);
			if (ret <= 0)
				goto end;
			s->state = SSL3_ST_SW_KEY_EXCH_A;
			s->init_num = 0;
			break;


		case SSL3_ST_SW_CHANGE_A:
		case SSL3_ST_SW_CHANGE_B:

			s->session->cipher = s->s3->tmp.new_cipher;
			if (!s->method->ssl3_enc->setup_key_block(s)) {
				ret = -1;
				goto end;
			}

			ret = ssl3_send_change_cipher_spec(s, SSL3_ST_SW_CHANGE_A, SSL3_ST_SW_CHANGE_B);

			if (ret <= 0)
				goto end;
			s->state = SSL3_ST_SW_FINISHED_A;
			s->init_num = 0;

			if (!s->method->ssl3_enc->change_cipher_state( s, SSL3_CHANGE_CIPHER_SERVER_WRITE)) {
				ret = -1;
				goto end;
			}

			break;

		case SSL3_ST_SW_FINISHED_A:
		case SSL3_ST_SW_FINISHED_B:
			ret = ssl3_send_finished(s, SSL3_ST_SW_FINISHED_A, SSL3_ST_SW_FINISHED_B, s->method->ssl3_enc->server_finished_label, s->method->ssl3_enc->server_finished_label_len);


			if (ret <= 0)
				goto end;
			s->state = SSL3_ST_SW_FLUSH;
			if (s->hit) {
				if (s->s3->next_proto_neg_seen) {
					s->s3->flags |= SSL3_FLAGS_CCS_OK;
					s->s3->tmp.next_state = SSL3_ST_SR_NEXT_PROTO_A;
				} else s->s3->tmp.next_state = SSL3_ST_SR_FINISHED_A;

			} else s->s3->tmp.next_state = SSL_ST_OK;
			s->init_num = 0;
			break;

		case SSL_ST_OK:
			
			ssl3_cleanup_key_block(s);

			BUF_MEM_free(s->init_buf);
			s->init_buf = NULL;

			
			ssl_free_wbio_buffer(s);

			s->init_num = 0;

			
			if (s->renegotiate == 2) {
				s->renegotiate = 0;
				s->new_session = 0;

				ssl_update_cache(s, SSL_SESS_CACHE_SERVER);

				s->ctx->stats.sess_accept_good++;
				
				s->handshake_func = ssl3_accept;

				if (cb != NULL)
					cb(s, SSL_CB_HANDSHAKE_DONE, 1);
			}

			ret = 1;
			goto end;
			

		default:
			SSLerr(SSL_F_SSL3_ACCEPT, SSL_R_UNKNOWN_STATE);
			ret = -1;
			goto end;
			
		}

		if (!s->s3->tmp.reuse_message && !skip) {
			if (s->debug) {
				if ((ret = BIO_flush(s->wbio)) <= 0)
					goto end;
			}


			if ((cb != NULL) && (s->state != state)) {
				new_state = s->state;
				s->state = state;
				cb(s, SSL_CB_ACCEPT_LOOP, 1);
				s->state = new_state;
			}
		}
		skip = 0;
	}
end:
	

	s->in_handshake--;
	if (cb != NULL)
		cb(s, SSL_CB_ACCEPT_EXIT, ret);
	return (ret);
}

int ssl3_send_hello_request(SSL *s)
{
	if (s->state == SSL3_ST_SW_HELLO_REQ_A) {
		ssl3_handshake_msg_start(s, SSL3_MT_HELLO_REQUEST);
		ssl3_handshake_msg_finish(s, 0);

		s->state = SSL3_ST_SW_HELLO_REQ_B;
	}

	
	return (ssl3_handshake_write(s));
}

int ssl3_check_client_hello(SSL *s)
{
	int ok;
	long n;

	
	n = s->method->ssl_get_message(s, SSL3_ST_SR_CERT_A, SSL3_ST_SR_CERT_B, -1, s->max_cert_list, &ok);
	if (!ok)
		return ((int)n);
	s->s3->tmp.reuse_message = 1;
	if (s->s3->tmp.message_type == SSL3_MT_CLIENT_HELLO) {
		
		if (s->s3->flags & SSL3_FLAGS_SGC_RESTART_DONE) {
			SSLerr(SSL_F_SSL3_CHECK_CLIENT_HELLO, SSL_R_MULTIPLE_SGC_RESTARTS);
			return (-1);
		}
		
		DH_free(s->s3->tmp.dh);
		s->s3->tmp.dh = NULL;
		EC_KEY_free(s->s3->tmp.ecdh);
		s->s3->tmp.ecdh = NULL;
		s->s3->flags |= SSL3_FLAGS_SGC_RESTART_DONE;
		return (2);
	}
	return (1);
}

int ssl3_get_client_hello(SSL *s)
{
	int i, j, ok, al, ret = -1;
	unsigned int cookie_len;
	long n;
	unsigned long id;
	unsigned char *p, *d;
	SSL_CIPHER *c;
	STACK_OF(SSL_CIPHER) *ciphers = NULL;
	unsigned long alg_k;

	
	if (s->state == SSL3_ST_SR_CLNT_HELLO_A) {
		s->state = SSL3_ST_SR_CLNT_HELLO_B;
	}
	s->first_packet = 1;
	n = s->method->ssl_get_message(s, SSL3_ST_SR_CLNT_HELLO_B, SSL3_ST_SR_CLNT_HELLO_C, SSL3_MT_CLIENT_HELLO, SSL3_RT_MAX_PLAIN_LENGTH, &ok);


	if (!ok)
		return ((int)n);
	s->first_packet = 0;
	d = p = (unsigned char *)s->init_msg;

	if (2 > n)
		goto truncated;
	
	s->client_version = (((int)p[0]) << 8)|(int)p[1];
	p += 2;

	if ((s->version == DTLS1_VERSION && s->client_version > s->version) || (s->version != DTLS1_VERSION && s->client_version < s->version)) {
		SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_WRONG_VERSION_NUMBER);
		if ((s->client_version >> 8) == SSL3_VERSION_MAJOR && !s->enc_write_ctx && !s->write_hash) {
			
			s->version = s->client_version;
		}
		al = SSL_AD_PROTOCOL_VERSION;
		goto f_err;
	}

	
	if (SSL_get_options(s) & SSL_OP_COOKIE_EXCHANGE) {
		unsigned int session_length, cookie_length;

		session_length = *(p + SSL3_RANDOM_SIZE);
		cookie_length = *(p + SSL3_RANDOM_SIZE + session_length + 1);

		if (cookie_length == 0)
			return (1);
	}

	if (p + SSL3_RANDOM_SIZE + 1 - d > n)
		goto truncated;

	
	memcpy(s->s3->client_random, p, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;

	
	j= *(p++);
	if (p + j - d > n)
		goto truncated;

	s->hit = 0;
	
	if ((s->new_session && (s->options & SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION))) {
		if (!ssl_get_new_session(s, 1))
			goto err;
	} else {
		i = ssl_get_prev_session(s, p, j, d + n);
		if (i == 1) { 
			s->hit = 1;
		} else if (i == -1)
			goto err;
		else {
			
			if (!ssl_get_new_session(s, 1))
				goto err;
		}
	}

	p += j;

	if (SSL_IS_DTLS(s)) {
		
		if (p + 1 - d > n)
			goto truncated;
		cookie_len = *(p++);

		
		if (cookie_len > sizeof(s->d1->rcvd_cookie)) {
			
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_COOKIE_MISMATCH);
			goto f_err;
		}

		if (p + cookie_len - d > n)
			goto truncated;

		
		if ((SSL_get_options(s) & SSL_OP_COOKIE_EXCHANGE) && cookie_len > 0) {
			memcpy(s->d1->rcvd_cookie, p, cookie_len);

			if (s->ctx->app_verify_cookie_cb != NULL) {
				if (s->ctx->app_verify_cookie_cb(s, s->d1->rcvd_cookie, cookie_len) == 0) {
					al = SSL_AD_HANDSHAKE_FAILURE;
					SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_COOKIE_MISMATCH);
					goto f_err;
				}
				
			} else if (timingsafe_memcmp(s->d1->rcvd_cookie, s->d1->cookie, s->d1->cookie_len) != 0) {
				
				al = SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_COOKIE_MISMATCH);
				goto f_err;
			}

			ret = 2;
		}

		p += cookie_len;
	}

	if (p + 2 - d > n)
		goto truncated;
	n2s(p, i);
	if ((i == 0) && (j != 0)) {
		
		al = SSL_AD_ILLEGAL_PARAMETER;
		SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_NO_CIPHERS_SPECIFIED);
		goto f_err;
	}
	if (p + i - d > n)
		goto truncated;
	if ((i > 0) && (ssl_bytes_to_cipher_list(s, p, i, &(ciphers)) == NULL)) {
		goto err;
	}
	p += i;

	
	if ((s->hit) && (i > 0)) {
		j = 0;
		id = s->session->cipher->id;

		for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
			c = sk_SSL_CIPHER_value(ciphers, i);
			if (c->id == id) {
				j = 1;
				break;
			}
		}
		if (j == 0) {
			
			al = SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_REQUIRED_CIPHER_MISSING);
			goto f_err;
		}
	}

	
	if (p + 1 - d > n)
		goto truncated;
	i= *(p++);
	if (p + i - d > n)
		goto truncated;
	for (j = 0; j < i; j++) {
		if (p[j] == 0)
			break;
	}

	p += i;
	if (j >= i) {
		
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_NO_COMPRESSION_SPECIFIED);
		goto f_err;
	}

	
	if (s->version >= SSL3_VERSION) {
		if (!ssl_parse_clienthello_tlsext(s, &p, d, n, &al)) {
			
			SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_PARSE_TLSEXT);
			goto f_err;
		}
	}
	if (ssl_check_clienthello_tlsext_early(s) <= 0) {
		SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_CLIENTHELLO_TLSEXT);
		goto err;
	}

	
	arc4random_buf(s->s3->server_random, SSL3_RANDOM_SIZE);

	if (!s->hit && s->version >= TLS1_VERSION && s->tls_session_secret_cb) {
		SSL_CIPHER *pref_cipher = NULL;

		s->session->master_key_length = sizeof(s->session->master_key);
		if (s->tls_session_secret_cb(s, s->session->master_key, &s->session->master_key_length, ciphers, &pref_cipher, s->tls_session_secret_cb_arg)) {

			s->hit = 1;
			s->session->ciphers = ciphers;
			s->session->verify_result = X509_V_OK;

			ciphers = NULL;

			
			pref_cipher = pref_cipher ? pref_cipher :
			    ssl3_choose_cipher(s, s->session->ciphers, SSL_get_ciphers(s));
			if (pref_cipher == NULL) {
				al = SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_NO_SHARED_CIPHER);
				goto f_err;
			}

			s->session->cipher = pref_cipher;

			if (s->cipher_list)
				sk_SSL_CIPHER_free(s->cipher_list);

			if (s->cipher_list_by_id)
				sk_SSL_CIPHER_free(s->cipher_list_by_id);

			s->cipher_list = sk_SSL_CIPHER_dup(s->session->ciphers);
			s->cipher_list_by_id = sk_SSL_CIPHER_dup(s->session->ciphers);
		}
	}

	

	if (!s->hit) {
		if (s->session->ciphers != NULL)
			sk_SSL_CIPHER_free(s->session->ciphers);
		s->session->ciphers = ciphers;
		if (ciphers == NULL) {
			al = SSL_AD_ILLEGAL_PARAMETER;
			SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_NO_CIPHERS_PASSED);
			goto f_err;
		}
		ciphers = NULL;
		c = ssl3_choose_cipher(s, s->session->ciphers, SSL_get_ciphers(s));

		if (c == NULL) {
			al = SSL_AD_HANDSHAKE_FAILURE;
			SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_NO_SHARED_CIPHER);
			goto f_err;
		}
		s->s3->tmp.new_cipher = c;
	} else {
		

		STACK_OF(SSL_CIPHER) *sk;
		SSL_CIPHER *nc = NULL;
		SSL_CIPHER *ec = NULL;

		if (s->options & SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG) {
			sk = s->session->ciphers;
			for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
				c = sk_SSL_CIPHER_value(sk, i);
				if (c->algorithm_enc & SSL_eNULL)
					nc = c;
			}
			if (nc != NULL)
				s->s3->tmp.new_cipher = nc;
			else if (ec != NULL)
				s->s3->tmp.new_cipher = ec;
			else s->s3->tmp.new_cipher = s->session->cipher;
		} else  s->s3->tmp.new_cipher = s->session->cipher;

	}

	alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
	if (!(SSL_USE_SIGALGS(s) || (alg_k & SSL_kGOST)) || !(s->verify_mode & SSL_VERIFY_PEER)) {
		if (!ssl3_digest_cached_records(s)) {
			al = SSL_AD_INTERNAL_ERROR;
			goto f_err;
		}
	}

	

	
	if (s->version >= SSL3_VERSION) {
		if (ssl_check_clienthello_tlsext_late(s) <= 0) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_CLIENTHELLO_TLSEXT);
			goto err;
		}
	}

	if (ret < 0)
		ret = 1;
	if (0) {
truncated:
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CLIENT_HELLO, SSL_R_BAD_PACKET_LENGTH);
f_err:
		ssl3_send_alert(s, SSL3_AL_FATAL, al);
	}
err:
	if (ciphers != NULL)
		sk_SSL_CIPHER_free(ciphers);
	return (ret);
}

int ssl3_send_server_hello(SSL *s)
{
	unsigned char *bufend;
	unsigned char *p, *d;
	int sl;

	if (s->state == SSL3_ST_SW_SRVR_HELLO_A) {
		d = p = ssl3_handshake_msg_start(s, SSL3_MT_SERVER_HELLO);

		*(p++) = s->version >> 8;
		*(p++) = s->version & 0xff;

		
		memcpy(p, s->s3->server_random, SSL3_RANDOM_SIZE);
		p += SSL3_RANDOM_SIZE;

		
		if (!(s->ctx->session_cache_mode & SSL_SESS_CACHE_SERVER)
		    && !s->hit)
			s->session->session_id_length = 0;

		sl = s->session->session_id_length;
		if (sl > (int)sizeof(s->session->session_id)) {
			SSLerr(SSL_F_SSL3_SEND_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
			return (-1);
		}
		*(p++) = sl;
		memcpy(p, s->session->session_id, sl);
		p += sl;

		
		s2n(ssl3_cipher_get_value(s->s3->tmp.new_cipher), p);

		
		*(p++) = 0;

		if (ssl_prepare_serverhello_tlsext(s) <= 0) {
			SSLerr(SSL_F_SSL3_SEND_SERVER_HELLO, SSL_R_SERVERHELLO_TLSEXT);
			return (-1);
		}
		bufend = (unsigned char *)s->init_buf->data + SSL3_RT_MAX_PLAIN_LENGTH;
		if ((p = ssl_add_serverhello_tlsext(s, p, bufend)) == NULL) {
			SSLerr(SSL_F_SSL3_SEND_SERVER_HELLO, ERR_R_INTERNAL_ERROR);
			return (-1);
		}

		ssl3_handshake_msg_finish(s, p - d);
	}

	
	return (ssl3_handshake_write(s));
}

int ssl3_send_server_done(SSL *s)
{
	if (s->state == SSL3_ST_SW_SRVR_DONE_A) {
		ssl3_handshake_msg_start(s, SSL3_MT_SERVER_DONE);
		ssl3_handshake_msg_finish(s, 0);

		s->state = SSL3_ST_SW_SRVR_DONE_B;
	}

	
	return (ssl3_handshake_write(s));
}

int ssl3_send_server_key_exchange(SSL *s)
{
	unsigned char *q;
	int j, num;
	unsigned char md_buf[MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH];
	unsigned int u;
	DH *dh = NULL, *dhp;
	EC_KEY *ecdh = NULL, *ecdhp;
	unsigned char *encodedPoint = NULL;
	int encodedlen = 0;
	int curve_id = 0;
	BN_CTX *bn_ctx = NULL;

	EVP_PKEY *pkey;
	const EVP_MD *md = NULL;
	unsigned char *p, *d;
	int al, i;
	unsigned long type;
	int n;
	CERT *cert;
	BIGNUM *r[4];
	int nr[4], kn;
	BUF_MEM *buf;
	EVP_MD_CTX md_ctx;

	EVP_MD_CTX_init(&md_ctx);
	if (s->state == SSL3_ST_SW_KEY_EXCH_A) {
		type = s->s3->tmp.new_cipher->algorithm_mkey;
		cert = s->cert;

		buf = s->init_buf;

		r[0] = r[1] = r[2] = r[3] = NULL;
		n = 0;
		if (type & SSL_kDHE) {
			if (s->cert->dh_tmp_auto != 0) {
				if ((dhp = ssl_get_auto_dh(s)) == NULL) {
					al = SSL_AD_INTERNAL_ERROR;
					SSLerr( SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);

					goto f_err;
				}
			} else dhp = cert->dh_tmp;

			if (dhp == NULL && s->cert->dh_tmp_cb != NULL)
				dhp = s->cert->dh_tmp_cb(s, 0, SSL_C_PKEYLENGTH(s->s3->tmp.new_cipher));

			if (dhp == NULL) {
				al = SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, SSL_R_MISSING_TMP_DH_KEY);
				goto f_err;
			}

			if (s->s3->tmp.dh != NULL) {
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
				goto err;
			}

			if (s->cert->dh_tmp_auto != 0) {
				dh = dhp;
			} else if ((dh = DHparams_dup(dhp)) == NULL) {
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_DH_LIB);
				goto err;
			}
			s->s3->tmp.dh = dh;

			if ((dhp->pub_key == NULL || dhp->priv_key == NULL || (s->options & SSL_OP_SINGLE_DH_USE))) {
				if (!DH_generate_key(dh)) {
					SSLerr( SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_DH_LIB);

					goto err;
				}
			} else {
				dh->pub_key = BN_dup(dhp->pub_key);
				dh->priv_key = BN_dup(dhp->priv_key);
				if ((dh->pub_key == NULL) || (dh->priv_key == NULL)) {
					SSLerr( SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_DH_LIB);

					goto err;
				}
			}
			r[0] = dh->p;
			r[1] = dh->g;
			r[2] = dh->pub_key;
		} else if (type & SSL_kECDHE) {
			const EC_GROUP *group;

			ecdhp = cert->ecdh_tmp;
			if (s->cert->ecdh_tmp_auto != 0) {
				int nid = tls1_get_shared_curve(s);
				if (nid != NID_undef)
					ecdhp = EC_KEY_new_by_curve_name(nid);
			} else if (ecdhp == NULL && s->cert->ecdh_tmp_cb != NULL) {
				ecdhp = s->cert->ecdh_tmp_cb(s, 0, SSL_C_PKEYLENGTH(s->s3->tmp.new_cipher));
			}
			if (ecdhp == NULL) {
				al = SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, SSL_R_MISSING_TMP_ECDH_KEY);
				goto f_err;
			}

			if (s->s3->tmp.ecdh != NULL) {
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);
				goto err;
			}

			
			if (s->cert->ecdh_tmp_auto != 0) {
				ecdh = ecdhp;
			} else if ((ecdh = EC_KEY_dup(ecdhp)) == NULL) {
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_ECDH_LIB);
				goto err;
			}
			s->s3->tmp.ecdh = ecdh;

			if ((EC_KEY_get0_public_key(ecdh) == NULL) || (EC_KEY_get0_private_key(ecdh) == NULL) || (s->options & SSL_OP_SINGLE_ECDH_USE)) {

				if (!EC_KEY_generate_key(ecdh)) {
					SSLerr( SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_ECDH_LIB);

					goto err;
				}
			}

			if (((group = EC_KEY_get0_group(ecdh)) == NULL) || (EC_KEY_get0_public_key(ecdh)  == NULL) || (EC_KEY_get0_private_key(ecdh) == NULL)) {

				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE,					    ERR_R_ECDH_LIB);
				goto err;
			}

			
			if ((curve_id = tls1_ec_nid2curve_id( EC_GROUP_get_curve_name(group))) == 0) {
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, SSL_R_UNSUPPORTED_ELLIPTIC_CURVE);
				goto err;
			}

			
			encodedlen = EC_POINT_point2oct(group, EC_KEY_get0_public_key(ecdh), POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);



			encodedPoint = malloc(encodedlen);

			bn_ctx = BN_CTX_new();
			if ((encodedPoint == NULL) || (bn_ctx == NULL)) {
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
				goto err;
			}


			encodedlen = EC_POINT_point2oct(group, EC_KEY_get0_public_key(ecdh), POINT_CONVERSION_UNCOMPRESSED, encodedPoint, encodedlen, bn_ctx);



			if (encodedlen == 0) {
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_ECDH_LIB);
				goto err;
			}

			BN_CTX_free(bn_ctx);
			bn_ctx = NULL;

			
			n = 4 + encodedlen;

			
			r[0] = NULL;
			r[1] = NULL;
			r[2] = NULL;
			r[3] = NULL;
		} else {
			al = SSL_AD_HANDSHAKE_FAILURE;
			SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE);
			goto f_err;
		}
		for (i = 0; i < 4 && r[i] != NULL; i++) {
			nr[i] = BN_num_bytes(r[i]);
			n += 2 + nr[i];
		}

		if (!(s->s3->tmp.new_cipher->algorithm_auth & SSL_aNULL)) {
			if ((pkey = ssl_get_sign_pkey( s, s->s3->tmp.new_cipher, &md)) == NULL) {
				al = SSL_AD_DECODE_ERROR;
				goto f_err;
			}
			kn = EVP_PKEY_size(pkey);
		} else {
			pkey = NULL;
			kn = 0;
		}

		if (!BUF_MEM_grow_clean(buf, n + 4 + kn)) {
			SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_LIB_BUF);
			goto err;
		}
		d = (unsigned char *)s->init_buf->data;
		p = &d[4];

		for (i = 0; i < 4 && r[i] != NULL; i++) {
			s2n(nr[i], p);
			BN_bn2bin(r[i], p);
			p += nr[i];
		}

		if (type & SSL_kECDHE) {
			
			*p = NAMED_CURVE_TYPE;
			p += 1;
			*p = 0;
			p += 1;
			*p = curve_id;
			p += 1;
			*p = encodedlen;
			p += 1;
			memcpy((unsigned char*)p, (unsigned char *)encodedPoint, encodedlen);
			free(encodedPoint);
			encodedPoint = NULL;
			p += encodedlen;
		}


		
		if (pkey != NULL) {
			
			if (pkey->type == EVP_PKEY_RSA && !SSL_USE_SIGALGS(s)) {
				q = md_buf;
				j = 0;
				for (num = 2; num > 0; num--) {
					if (!EVP_DigestInit_ex(&md_ctx, (num == 2) ? s->ctx->md5 :
					    s->ctx->sha1, NULL))
						goto err;
					EVP_DigestUpdate(&md_ctx, s->s3->client_random, SSL3_RANDOM_SIZE);

					EVP_DigestUpdate(&md_ctx, s->s3->server_random, SSL3_RANDOM_SIZE);

					EVP_DigestUpdate(&md_ctx, &d[4], n);
					EVP_DigestFinal_ex(&md_ctx, q, (unsigned int *)&i);
					q += i;
					j += i;
				}
				if (RSA_sign(NID_md5_sha1, md_buf, j, &(p[2]), &u, pkey->pkey.rsa) <= 0) {
					SSLerr( SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_LIB_RSA);

					goto err;
				}
				s2n(u, p);
				n += u + 2;
			} else if (md) {
				
				if (SSL_USE_SIGALGS(s)) {
					if (!tls12_get_sigandhash(p, pkey, md)) {
						
						al = SSL_AD_INTERNAL_ERROR;
						SSLerr( SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_R_INTERNAL_ERROR);

						goto f_err;
					}
					p += 2;
				}
				EVP_SignInit_ex(&md_ctx, md, NULL);
				EVP_SignUpdate(&md_ctx, s->s3->client_random, SSL3_RANDOM_SIZE);

				EVP_SignUpdate(&md_ctx, s->s3->server_random, SSL3_RANDOM_SIZE);

				EVP_SignUpdate(&md_ctx, &d[4], n);
				if (!EVP_SignFinal(&md_ctx, &p[2], (unsigned int *)&i, pkey)) {
					SSLerr( SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, ERR_LIB_EVP);

					goto err;
				}
				s2n(i, p);
				n += i + 2;
				if (SSL_USE_SIGALGS(s))
					n += 2;
			} else {
				
				al = SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_SEND_SERVER_KEY_EXCHANGE, SSL_R_UNKNOWN_PKEY_TYPE);
				goto f_err;
			}
		}

		*(d++) = SSL3_MT_SERVER_KEY_EXCHANGE;
		l2n3(n, d);

		
		s->init_num = n + 4;
		s->init_off = 0;
	}

	s->state = SSL3_ST_SW_KEY_EXCH_B;
	EVP_MD_CTX_cleanup(&md_ctx);
	return (ssl3_do_write(s, SSL3_RT_HANDSHAKE));
f_err:
	ssl3_send_alert(s, SSL3_AL_FATAL, al);
err:
	free(encodedPoint);
	BN_CTX_free(bn_ctx);
	EVP_MD_CTX_cleanup(&md_ctx);
	return (-1);
}

int ssl3_send_certificate_request(SSL *s)
{
	unsigned char *p, *d;
	int i, j, nl, off, n;
	STACK_OF(X509_NAME) *sk = NULL;
	X509_NAME *name;
	BUF_MEM *buf;

	if (s->state == SSL3_ST_SW_CERT_REQ_A) {
		buf = s->init_buf;

		d = p = (unsigned char *)&(buf->data[4]);

		
		p++;
		n = ssl3_get_req_cert_type(s, p);
		d[0] = n;
		p += n;
		n++;

		if (SSL_USE_SIGALGS(s)) {
			nl = tls12_get_req_sig_algs(s, p + 2);
			s2n(nl, p);
			p += nl + 2;
			n += nl + 2;
		}

		off = n;
		p += 2;
		n += 2;

		sk = SSL_get_client_CA_list(s);
		nl = 0;
		if (sk != NULL) {
			for (i = 0; i < sk_X509_NAME_num(sk); i++) {
				name = sk_X509_NAME_value(sk, i);
				j = i2d_X509_NAME(name, NULL);
				if (!BUF_MEM_grow_clean(buf, 4 + n + j + 2)) {
					SSLerr( SSL_F_SSL3_SEND_CERTIFICATE_REQUEST, ERR_R_BUF_LIB);

					goto err;
				}
				p = (unsigned char *)&(buf->data[4 + n]);
				if (!(s->options & SSL_OP_NETSCAPE_CA_DN_BUG)) {
					s2n(j, p);
					i2d_X509_NAME(name, &p);
					n += 2 + j;
					nl += 2 + j;
				} else {
					d = p;
					i2d_X509_NAME(name, &p);
					j -= 2;
					s2n(j, d);
					j += 2;
					n += j;
					nl += j;
				}
			}
		}
		
		p = (unsigned char *)&(buf->data[4 + off]);
		s2n(nl, p);

		d = (unsigned char *)buf->data;
		*(d++) = SSL3_MT_CERTIFICATE_REQUEST;
		l2n3(n, d);

		
		s->init_num = n + 4;
		s->init_off = 0;

		s->state = SSL3_ST_SW_CERT_REQ_B;
	}

	
	return (ssl3_do_write(s, SSL3_RT_HANDSHAKE));
err:
	return (-1);
}

int ssl3_get_client_key_exchange(SSL *s)
{
	int i, al, ok;
	long n;
	unsigned long alg_k;
	unsigned char *d, *p;
	RSA *rsa = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *pub = NULL;
	DH *dh_srvr;

	EC_KEY *srvr_ecdh = NULL;
	EVP_PKEY *clnt_pub_pkey = NULL;
	EC_POINT *clnt_ecpoint = NULL;
	BN_CTX *bn_ctx = NULL;

	
	n = s->method->ssl_get_message(s, SSL3_ST_SR_KEY_EXCH_A, SSL3_ST_SR_KEY_EXCH_B, SSL3_MT_CLIENT_KEY_EXCHANGE, 2048, &ok);
	if (!ok)
		return ((int)n);
	d = p = (unsigned char *)s->init_msg;

	alg_k = s->s3->tmp.new_cipher->algorithm_mkey;

	if (alg_k & SSL_kRSA) {
		char fakekey[SSL_MAX_MASTER_KEY_LENGTH];

		arc4random_buf(fakekey, sizeof(fakekey));
		fakekey[0] = s->client_version >> 8;
		fakekey[1] = s->client_version & 0xff;

		pkey = s->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey;
		if ((pkey == NULL) || (pkey->type != EVP_PKEY_RSA) || (pkey->pkey.rsa == NULL)) {
			al = SSL_AD_HANDSHAKE_FAILURE;
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_MISSING_RSA_CERTIFICATE);
			goto f_err;
		}
		rsa = pkey->pkey.rsa;

		
		if (s->version > SSL3_VERSION && s->version != DTLS1_BAD_VER) {
			if (2 > n)
				goto truncated;
			n2s(p, i);
			if (n != i + 2) {
				if (!(s->options & SSL_OP_TLS_D5_BUG)) {
					SSLerr( SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG);

					goto err;
				} else p -= 2;
			} else n = i;
		}

		i = RSA_private_decrypt((int)n, p, p, rsa, RSA_PKCS1_PADDING);

		ERR_clear_error();

		al = -1;

		if (i != SSL_MAX_MASTER_KEY_LENGTH) {
			al = SSL_AD_DECODE_ERROR;
			
		}

		if (p + 2 - d > n)	
			goto truncated;
		if ((al == -1) && !((p[0] == (s->client_version >> 8)) && (p[1] == (s->client_version & 0xff)))) {
			
			if (!((s->options & SSL_OP_TLS_ROLLBACK_BUG) && (p[0] == (s->version >> 8)) && (p[1] == (s->version & 0xff)))) {

				al = SSL_AD_DECODE_ERROR;
				

				
			}
		}

		if (al != -1) {
			
			i = SSL_MAX_MASTER_KEY_LENGTH;
			p = fakekey;
		}

		s->session->master_key_length = s->method->ssl3_enc->generate_master_secret(s, s->session->master_key, p, i);


		OPENSSL_cleanse(p, i);
	} else if (alg_k & SSL_kDHE) {
		if (2 > n)
			goto truncated;
		n2s(p, i);
		if (n != i + 2) {
			if (!(s->options & SSL_OP_SSLEAY_080_CLIENT_DH_BUG)) {
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG);
				goto err;
			} else {
				p -= 2;
				i = (int)n;
			}
		}

		if (n == 0L) {
			
			al = SSL_AD_HANDSHAKE_FAILURE;
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_UNABLE_TO_DECODE_DH_CERTS);
			goto f_err;
		} else {
			if (s->s3->tmp.dh == NULL) {
				al = SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_MISSING_TMP_DH_KEY);
				goto f_err;
			} else dh_srvr = s->s3->tmp.dh;
		}

		pub = BN_bin2bn(p, i, NULL);
		if (pub == NULL) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_BN_LIB);
			goto err;
		}

		i = DH_compute_key(p, pub, dh_srvr);

		if (i <= 0) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_DH_LIB);
			BN_clear_free(pub);
			goto err;
		}

		DH_free(s->s3->tmp.dh);
		s->s3->tmp.dh = NULL;

		BN_clear_free(pub);
		pub = NULL;
		s->session->master_key_length = s->method->ssl3_enc->generate_master_secret( s, s->session->master_key, p, i);

		OPENSSL_cleanse(p, i);
	} else  if (alg_k & (SSL_kECDHE|SSL_kECDHr|SSL_kECDHe)) {

		int ret = 1;
		int field_size = 0;
		const EC_KEY   *tkey;
		const EC_GROUP *group;
		const BIGNUM *priv_key;

		
		if ((srvr_ecdh = EC_KEY_new()) == NULL) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
			goto err;
		}

		
		if (alg_k & (SSL_kECDHr|SSL_kECDHe)) {
			
			tkey = s->cert->pkeys[SSL_PKEY_ECC].privatekey->pkey.ec;
		} else {
			
			tkey = s->s3->tmp.ecdh;
		}

		group = EC_KEY_get0_group(tkey);
		priv_key = EC_KEY_get0_private_key(tkey);

		if (!EC_KEY_set_group(srvr_ecdh, group) || !EC_KEY_set_private_key(srvr_ecdh, priv_key)) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
			goto err;
		}

		
		if ((clnt_ecpoint = EC_POINT_new(group)) == NULL) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
			goto err;
		}

		if (n == 0L) {
			

			if (alg_k & SSL_kECDHE) {
				al = SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_MISSING_TMP_ECDH_KEY);
				goto f_err;
			}
			if (((clnt_pub_pkey = X509_get_pubkey( s->session->peer)) == NULL) || (clnt_pub_pkey->type != EVP_PKEY_EC)) {

				
				al = SSL_AD_HANDSHAKE_FAILURE;
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_UNABLE_TO_DECODE_ECDH_CERTS);
				goto f_err;
			}

			if (EC_POINT_copy(clnt_ecpoint, EC_KEY_get0_public_key(clnt_pub_pkey->pkey.ec))
			    == 0) {
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
				goto err;
			}
			ret = 2; 
		} else {
			
			if ((bn_ctx = BN_CTX_new()) == NULL) {
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
				goto err;
			}

			
			i = *p;

			p += 1;
			if (n != 1 + i) {
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
				goto err;
			}
			if (EC_POINT_oct2point(group, clnt_ecpoint, p, i, bn_ctx) == 0) {
				SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_EC_LIB);
				goto err;
			}
			
			p = (unsigned char *)s->init_buf->data;
		}

		
		field_size = EC_GROUP_get_degree(group);
		if (field_size <= 0) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
			goto err;
		}
		i = ECDH_compute_key(p, (field_size + 7)/8, clnt_ecpoint, srvr_ecdh, NULL);
		if (i <= 0) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, ERR_R_ECDH_LIB);
			goto err;
		}

		EVP_PKEY_free(clnt_pub_pkey);
		EC_POINT_free(clnt_ecpoint);
		EC_KEY_free(srvr_ecdh);
		BN_CTX_free(bn_ctx);
		EC_KEY_free(s->s3->tmp.ecdh);
		s->s3->tmp.ecdh = NULL;


		
		s->session->master_key_length = s->method->ssl3_enc->  generate_master_secret(s, s->session->master_key, p, i)

		OPENSSL_cleanse(p, i);
		return (ret);
	} else if (alg_k & SSL_kGOST) {
		int ret = 0;
		EVP_PKEY_CTX *pkey_ctx;
		EVP_PKEY *client_pub_pkey = NULL, *pk = NULL;
		unsigned char premaster_secret[32], *start;
		size_t outlen = 32, inlen;
		unsigned long alg_a;
		int Ttag, Tclass;
		long Tlen;

		
		alg_a = s->s3->tmp.new_cipher->algorithm_auth;
		if (alg_a & SSL_aGOST01)
			pk = s->cert->pkeys[SSL_PKEY_GOST01].privatekey;

		pkey_ctx = EVP_PKEY_CTX_new(pk, NULL);
		EVP_PKEY_decrypt_init(pkey_ctx);
		
		client_pub_pkey = X509_get_pubkey(s->session->peer);
		if (client_pub_pkey) {
			if (EVP_PKEY_derive_set_peer(pkey_ctx, client_pub_pkey) <= 0)
				ERR_clear_error();
		}
		if (2 > n)
			goto truncated;
		
		if (ASN1_get_object((const unsigned char **)&p, &Tlen, &Ttag, &Tclass, n) != V_ASN1_CONSTRUCTED || Ttag != V_ASN1_SEQUENCE || Tclass != V_ASN1_UNIVERSAL) {

			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_DECRYPTION_FAILED);
			goto gerr;
		}
		start = p;
		inlen = Tlen;
		if (EVP_PKEY_decrypt(pkey_ctx, premaster_secret, &outlen, start, inlen) <=0) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_DECRYPTION_FAILED);
			goto gerr;
		}
		
		s->session->master_key_length = s->method->ssl3_enc->generate_master_secret( s, s->session->master_key, premaster_secret, 32);

		
		if (EVP_PKEY_CTX_ctrl(pkey_ctx, -1, -1, EVP_PKEY_CTRL_PEER_KEY, 2, NULL) > 0)
			ret = 2;
		else ret = 1;
gerr:
		EVP_PKEY_free(client_pub_pkey);
		EVP_PKEY_CTX_free(pkey_ctx);
		if (ret)
			return (ret);
		else goto err;
	} else {
		al = SSL_AD_HANDSHAKE_FAILURE;
		SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_UNKNOWN_CIPHER_TYPE);
		goto f_err;
	}

	return (1);
truncated:
	al = SSL_AD_DECODE_ERROR;
	SSLerr(SSL_F_SSL3_GET_CLIENT_KEY_EXCHANGE, SSL_R_BAD_PACKET_LENGTH);
f_err:
	ssl3_send_alert(s, SSL3_AL_FATAL, al);
err:
	EVP_PKEY_free(clnt_pub_pkey);
	EC_POINT_free(clnt_ecpoint);
	EC_KEY_free(srvr_ecdh);
	BN_CTX_free(bn_ctx);
	return (-1);
}

int ssl3_get_cert_verify(SSL *s)
{
	EVP_PKEY *pkey = NULL;
	unsigned char *p;
	int al, ok, ret = 0;
	long n;
	int type = 0, i, j;
	X509 *peer;
	const EVP_MD *md = NULL;
	EVP_MD_CTX mctx;
	EVP_MD_CTX_init(&mctx);

	n = s->method->ssl_get_message(s, SSL3_ST_SR_CERT_VRFY_A, SSL3_ST_SR_CERT_VRFY_B, -1, SSL3_RT_MAX_PLAIN_LENGTH, &ok);
	if (!ok)
		return ((int)n);

	if (s->session->peer != NULL) {
		peer = s->session->peer;
		pkey = X509_get_pubkey(peer);
		type = X509_certificate_type(peer, pkey);
	} else {
		peer = NULL;
		pkey = NULL;
	}

	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE_VERIFY) {
		s->s3->tmp.reuse_message = 1;
		if ((peer != NULL) && (type & EVP_PKT_SIGN)) {
			al = SSL_AD_UNEXPECTED_MESSAGE;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_MISSING_VERIFY_MESSAGE);
			goto f_err;
		}
		ret = 1;
		goto end;
	}

	if (peer == NULL) {
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_NO_CLIENT_CERT_RECEIVED);
		al = SSL_AD_UNEXPECTED_MESSAGE;
		goto f_err;
	}

	if (!(type & EVP_PKT_SIGN)) {
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE);
		al = SSL_AD_ILLEGAL_PARAMETER;
		goto f_err;
	}

	if (s->s3->change_cipher_spec) {
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_CCS_RECEIVED_EARLY);
		al = SSL_AD_UNEXPECTED_MESSAGE;
		goto f_err;
	}

	
	p = (unsigned char *)s->init_msg;
	
	if (n == 64 && (pkey->type == NID_id_GostR3410_94 || pkey->type == NID_id_GostR3410_2001) ) {
		i = 64;
	} else {
		if (SSL_USE_SIGALGS(s)) {
			int sigalg = tls12_get_sigid(pkey);
			
			if (sigalg == -1) {
				SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_INTERNAL_ERROR);
				al = SSL_AD_INTERNAL_ERROR;
				goto f_err;
			}
			if (2 > n)
				goto truncated;
			
			if (sigalg != (int)p[1]) {
				SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_WRONG_SIGNATURE_TYPE);
				al = SSL_AD_DECODE_ERROR;
				goto f_err;
			}
			md = tls12_get_hash(p[0]);
			if (md == NULL) {
				SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_UNKNOWN_DIGEST);
				al = SSL_AD_DECODE_ERROR;
				goto f_err;
			}
			p += 2;
			n -= 2;
		}
		if (2 > n)
			goto truncated;
		n2s(p, i);
		n -= 2;
		if (i > n)
			goto truncated;
	}
	j = EVP_PKEY_size(pkey);
	if ((i > j) || (n > j) || (n <= 0)) {
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_WRONG_SIGNATURE_SIZE);
		al = SSL_AD_DECODE_ERROR;
		goto f_err;
	}

	if (SSL_USE_SIGALGS(s)) {
		long hdatalen = 0;
		void *hdata;
		hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
		if (hdatalen <= 0) {
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_INTERNAL_ERROR);
			al = SSL_AD_INTERNAL_ERROR;
			goto f_err;
		}
		if (!EVP_VerifyInit_ex(&mctx, md, NULL) || !EVP_VerifyUpdate(&mctx, hdata, hdatalen)) {
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_EVP_LIB);
			al = SSL_AD_INTERNAL_ERROR;
			goto f_err;
		}

		if (EVP_VerifyFinal(&mctx, p, i, pkey) <= 0) {
			al = SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_SIGNATURE);
			goto f_err;
		}
	} else if (pkey->type == EVP_PKEY_RSA) {
		i = RSA_verify(NID_md5_sha1, s->s3->tmp.cert_verify_md, MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH, p, i, pkey->pkey.rsa);

		if (i < 0) {
			al = SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_RSA_DECRYPT);
			goto f_err;
		}
		if (i == 0) {
			al = SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_RSA_SIGNATURE);
			goto f_err;
		}
	} else if (pkey->type == EVP_PKEY_DSA) {
		j = DSA_verify(pkey->save_type, &(s->s3->tmp.cert_verify_md[MD5_DIGEST_LENGTH]), SHA_DIGEST_LENGTH, p, i, pkey->pkey.dsa);

		if (j <= 0) {
			
			al = SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_DSA_SIGNATURE);
			goto f_err;
		}
	} else if (pkey->type == EVP_PKEY_EC) {
		j = ECDSA_verify(pkey->save_type, &(s->s3->tmp.cert_verify_md[MD5_DIGEST_LENGTH]), SHA_DIGEST_LENGTH, p, i, pkey->pkey.ec);

		if (j <= 0) {
			
			al = SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_ECDSA_SIGNATURE);
			goto f_err;
		}
	} else  if (pkey->type == NID_id_GostR3410_94 || pkey->type == NID_id_GostR3410_2001) {


		long hdatalen = 0;
		void *hdata;
		unsigned char signature[128];
		unsigned int siglen = sizeof(signature);
		int nid;
		EVP_PKEY_CTX *pctx;

		hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
		if (hdatalen <= 0) {
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_INTERNAL_ERROR);
			al = SSL_AD_INTERNAL_ERROR;
			goto f_err;
		}
		if (!EVP_PKEY_get_default_digest_nid(pkey, &nid) || !(md = EVP_get_digestbynid(nid))) {
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_EVP_LIB);
			al = SSL_AD_INTERNAL_ERROR;
			goto f_err;
		}
		pctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (!pctx) {
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_EVP_LIB);
			al = SSL_AD_INTERNAL_ERROR;
			goto f_err;
		}
		if (!EVP_DigestInit_ex(&mctx, md, NULL) || !EVP_DigestUpdate(&mctx, hdata, hdatalen) || !EVP_DigestFinal(&mctx, signature, &siglen) || (EVP_PKEY_verify_init(pctx) <= 0) || (EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0) || (EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_VERIFY, EVP_PKEY_CTRL_GOST_SIG_FORMAT, GOST_SIG_FORMAT_RS_LE, NULL) <= 0)) {







			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_EVP_LIB);
			al = SSL_AD_INTERNAL_ERROR;
			EVP_PKEY_CTX_free(pctx);
			goto f_err;
		}

		if (EVP_PKEY_verify(pctx, p, i, signature, siglen) <= 0) {
			al = SSL_AD_DECRYPT_ERROR;
			SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_SIGNATURE);
			EVP_PKEY_CTX_free(pctx);
			goto f_err;
		}

		EVP_PKEY_CTX_free(pctx);
	} else  {

		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, ERR_R_INTERNAL_ERROR);
		al = SSL_AD_UNSUPPORTED_CERTIFICATE;
		goto f_err;
	}


	ret = 1;
	if (0) {
truncated:
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CERT_VERIFY, SSL_R_BAD_PACKET_LENGTH);
f_err:
		ssl3_send_alert(s, SSL3_AL_FATAL, al);
	}
end:
	if (s->s3->handshake_buffer) {
		BIO_free(s->s3->handshake_buffer);
		s->s3->handshake_buffer = NULL;
		s->s3->flags &= ~TLS1_FLAGS_KEEP_HANDSHAKE;
	}
	EVP_MD_CTX_cleanup(&mctx);
	EVP_PKEY_free(pkey);
	return (ret);
}

int ssl3_get_client_certificate(SSL *s)
{
	int i, ok, al, ret = -1;
	X509 *x = NULL;
	unsigned long l, nc, llen, n;
	const unsigned char *p, *q;
	STACK_OF(X509) *sk = NULL;

	n = s->method->ssl_get_message(s, SSL3_ST_SR_CERT_A, SSL3_ST_SR_CERT_B, -1, s->max_cert_list, &ok);

	if (!ok)
		return ((int)n);

	if (s->s3->tmp.message_type == SSL3_MT_CLIENT_KEY_EXCHANGE) {
		if ((s->verify_mode & SSL_VERIFY_PEER) && (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
		    	SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
			al = SSL_AD_HANDSHAKE_FAILURE;
			goto f_err;
		}
		
		if ((s->version > SSL3_VERSION) && s->s3->tmp.cert_request) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST );

			al = SSL_AD_UNEXPECTED_MESSAGE;
			goto f_err;
		}
		s->s3->tmp.reuse_message = 1;
		return (1);
	}

	if (s->s3->tmp.message_type != SSL3_MT_CERTIFICATE) {
		al = SSL_AD_UNEXPECTED_MESSAGE;
		SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_WRONG_MESSAGE_TYPE);
		goto f_err;
	}
	p = (const unsigned char *)s->init_msg;

	if ((sk = sk_X509_new_null()) == NULL) {
		SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (3 > n)
		goto truncated;
	n2l3(p, llen);
	if (llen + 3 != n)
		goto truncated;
	for (nc = 0; nc < llen;) {
		n2l3(p, l);
		if (l + nc + 3 > llen) {
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_CERT_LENGTH_MISMATCH);
			goto f_err;
		}

		q = p;
		x = d2i_X509(NULL, &p, l);
		if (x == NULL) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_ASN1_LIB);
			goto err;
		}
		if (p != (q + l)) {
			al = SSL_AD_DECODE_ERROR;
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_CERT_LENGTH_MISMATCH);
			goto f_err;
		}
		if (!sk_X509_push(sk, x)) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_MALLOC_FAILURE);
			goto err;
		}
		x = NULL;
		nc += l + 3;
	}

	if (sk_X509_num(sk) <= 0) {
		
		if (s->version == SSL3_VERSION) {
			al = SSL_AD_HANDSHAKE_FAILURE;
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_NO_CERTIFICATES_RETURNED);
			goto f_err;
		}
		
		else if ((s->verify_mode & SSL_VERIFY_PEER) && (s->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT)) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
			al = SSL_AD_HANDSHAKE_FAILURE;
			goto f_err;
		}
		
		if (s->s3->handshake_buffer && !ssl3_digest_cached_records(s)) {
			al = SSL_AD_INTERNAL_ERROR;
			goto f_err;
		}
	} else {
		i = ssl_verify_cert_chain(s, sk);
		if (i <= 0) {
			al = ssl_verify_alarm_type(s->verify_result);
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_NO_CERTIFICATE_RETURNED);
			goto f_err;
		}
	}

	if (s->session->peer != NULL) 
		X509_free(s->session->peer);
	s->session->peer = sk_X509_shift(sk);
	s->session->verify_result = s->verify_result;

	
	if (s->session->sess_cert == NULL) {
		s->session->sess_cert = ssl_sess_cert_new();
		if (s->session->sess_cert == NULL) {
			SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, ERR_R_MALLOC_FAILURE);
			goto err;
		}
	}
	if (s->session->sess_cert->cert_chain != NULL)
		sk_X509_pop_free(s->session->sess_cert->cert_chain, X509_free);
	s->session->sess_cert->cert_chain = sk;

	

	sk = NULL;

	ret = 1;
	if (0) {
truncated:
		al = SSL_AD_DECODE_ERROR;
		SSLerr(SSL_F_SSL3_GET_CLIENT_CERTIFICATE, SSL_R_BAD_PACKET_LENGTH);
f_err:
		ssl3_send_alert(s, SSL3_AL_FATAL, al);
	}
err:
	if (x != NULL)
		X509_free(x);
	if (sk != NULL)
		sk_X509_pop_free(sk, X509_free);
	return (ret);
}

int ssl3_send_server_certificate(SSL *s)
{
	unsigned long l;
	X509 *x;

	if (s->state == SSL3_ST_SW_CERT_A) {
		x = ssl_get_server_send_cert(s);
		if (x == NULL) {
			SSLerr(SSL_F_SSL3_SEND_SERVER_CERTIFICATE, ERR_R_INTERNAL_ERROR);
			return (0);
		}

		l = ssl3_output_cert_chain(s, x);
		s->state = SSL3_ST_SW_CERT_B;
		s->init_num = (int)l;
		s->init_off = 0;
	}

	
	return (ssl3_do_write(s, SSL3_RT_HANDSHAKE));
}


int ssl3_send_newsession_ticket(SSL *s)
{
	if (s->state == SSL3_ST_SW_SESSION_TICKET_A) {
		unsigned char *p, *senc, *macstart;
		const unsigned char *const_p;
		int len, slen_full, slen;
		SSL_SESSION *sess;
		unsigned int hlen;
		EVP_CIPHER_CTX ctx;
		HMAC_CTX hctx;
		SSL_CTX *tctx = s->initial_ctx;
		unsigned char iv[EVP_MAX_IV_LENGTH];
		unsigned char key_name[16];

		
		slen_full = i2d_SSL_SESSION(s->session, NULL);
		
		if (slen_full > 0xFF00)
			return (-1);
		senc = malloc(slen_full);
		if (!senc)
			return (-1);
		p = senc;
		i2d_SSL_SESSION(s->session, &p);

		
		const_p = senc;
		sess = d2i_SSL_SESSION(NULL, &const_p, slen_full);
		if (sess == NULL) {
			free(senc);
			return (-1);
		}

		
		sess->session_id_length = 0;

		slen = i2d_SSL_SESSION(sess, NULL);
		if (slen > slen_full) {
			
			free(senc);
			return (-1);
		}
		p = senc;
		i2d_SSL_SESSION(sess, &p);
		SSL_SESSION_free(sess);

		
		if (!BUF_MEM_grow(s->init_buf, 26 + EVP_MAX_IV_LENGTH + EVP_MAX_BLOCK_LENGTH + EVP_MAX_MD_SIZE + slen)) {

			free(senc);
			return (-1);
		}

		p = (unsigned char *)s->init_buf->data;
		
		*(p++) = SSL3_MT_NEWSESSION_TICKET;
		
		p += 3;
		EVP_CIPHER_CTX_init(&ctx);
		HMAC_CTX_init(&hctx);
		
		if (tctx->tlsext_ticket_key_cb) {
			if (tctx->tlsext_ticket_key_cb(s, key_name, iv, &ctx, &hctx, 1) < 0) {
				free(senc);
				return (-1);
			}
		} else {
			arc4random_buf(iv, 16);
			EVP_EncryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL, tctx->tlsext_tick_aes_key, iv);
			HMAC_Init_ex(&hctx, tctx->tlsext_tick_hmac_key, 16, tlsext_tick_md(), NULL);
			memcpy(key_name, tctx->tlsext_tick_key_name, 16);
		}

		
		l2n(s->hit ? 0 : s->session->timeout, p);

		
		p += 2;
		
		macstart = p;
		memcpy(p, key_name, 16);
		p += 16;
		
		memcpy(p, iv, EVP_CIPHER_CTX_iv_length(&ctx));
		p += EVP_CIPHER_CTX_iv_length(&ctx);
		
		EVP_EncryptUpdate(&ctx, p, &len, senc, slen);
		p += len;
		EVP_EncryptFinal(&ctx, p, &len);
		p += len;
		EVP_CIPHER_CTX_cleanup(&ctx);

		HMAC_Update(&hctx, macstart, p - macstart);
		HMAC_Final(&hctx, p, &hlen);
		HMAC_CTX_cleanup(&hctx);

		p += hlen;
		
		
		len = p - (unsigned char *)s->init_buf->data;
		p = (unsigned char *)s->init_buf->data + 1;
		l2n3(len - 4, p); 
		p += 4;
		s2n(len - 10, p);
		

		
		s->init_num = len;
		s->state = SSL3_ST_SW_SESSION_TICKET_B;
		s->init_off = 0;
		free(senc);
	}

	
	return (ssl3_do_write(s, SSL3_RT_HANDSHAKE));
}

int ssl3_send_cert_status(SSL *s)
{
	unsigned char *p;

	if (s->state == SSL3_ST_SW_CERT_STATUS_A) {
		
		if (!BUF_MEM_grow(s->init_buf, SSL3_HM_HEADER_LENGTH + 4 + s->tlsext_ocsp_resplen))
			return (-1);

		p = ssl3_handshake_msg_start(s, SSL3_MT_CERTIFICATE_STATUS);

		*(p++) = s->tlsext_status_type;
		l2n3(s->tlsext_ocsp_resplen, p);
		memcpy(p, s->tlsext_ocsp_resp, s->tlsext_ocsp_resplen);

		ssl3_handshake_msg_finish(s, s->tlsext_ocsp_resplen + 4);

		s->state = SSL3_ST_SW_CERT_STATUS_B;
	}

	
	return (ssl3_handshake_write(s));
}


int ssl3_get_next_proto(SSL *s)
{
	int ok;
	int proto_len, padding_len;
	long n;
	const unsigned char *p;

	
	if (!s->s3->next_proto_neg_seen) {
		SSLerr(SSL_F_SSL3_GET_NEXT_PROTO, SSL_R_GOT_NEXT_PROTO_WITHOUT_EXTENSION);
		return (-1);
	}

	
	n = s->method->ssl_get_message(s, SSL3_ST_SR_NEXT_PROTO_A, SSL3_ST_SR_NEXT_PROTO_B, SSL3_MT_NEXT_PROTO, 514, &ok);
	if (!ok)
		return ((int)n);

	
	if (!s->s3->change_cipher_spec) {
		SSLerr(SSL_F_SSL3_GET_NEXT_PROTO, SSL_R_GOT_NEXT_PROTO_BEFORE_A_CCS);
		return (-1);
	}

	if (n < 2)
		return (0);
	

	p = (unsigned char *)s->init_msg;

	
	proto_len = p[0];
	if (proto_len + 2 > s->init_num)
		return (0);
	padding_len = p[proto_len + 1];
	if (proto_len + padding_len + 2 != s->init_num)
		return (0);

	s->next_proto_negotiated = malloc(proto_len);
	if (!s->next_proto_negotiated) {
		SSLerr(SSL_F_SSL3_GET_NEXT_PROTO, ERR_R_MALLOC_FAILURE);
		return (0);
	}
	memcpy(s->next_proto_negotiated, p + 1, proto_len);
	s->next_proto_negotiated_len = proto_len;

	return (1);
}
