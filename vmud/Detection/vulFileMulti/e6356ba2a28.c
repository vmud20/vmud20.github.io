










static const SSL_METHOD *ssl23_get_server_method(int ver);
int ssl23_get_client_hello(SSL *s);

const SSL_METHOD SSLv23_server_method_data = {
	.version = TLS1_2_VERSION, .ssl_new = tls1_new, .ssl_clear = tls1_clear, .ssl_free = tls1_free, .ssl_accept = ssl23_accept, .ssl_connect = ssl_undefined_function, .ssl_read = ssl23_read, .ssl_peek = ssl23_peek, .ssl_write = ssl23_write, .ssl_shutdown = ssl_undefined_function, .ssl_renegotiate = ssl_undefined_function, .ssl_renegotiate_check = ssl_ok, .ssl_get_message = ssl3_get_message, .ssl_read_bytes = ssl3_read_bytes, .ssl_write_bytes = ssl3_write_bytes, .ssl_dispatch_alert = ssl3_dispatch_alert, .ssl_ctrl = ssl3_ctrl, .ssl_ctx_ctrl = ssl3_ctx_ctrl, .get_cipher_by_char = ssl3_get_cipher_by_char, .put_cipher_by_char = ssl23_put_cipher_by_char, .ssl_pending = ssl_undefined_const_function, .num_ciphers = ssl3_num_ciphers, .get_cipher = ssl3_get_cipher, .get_ssl_method = ssl23_get_server_method, .get_timeout = ssl23_default_timeout, .ssl3_enc = &ssl3_undef_enc_method, .ssl_version = ssl_undefined_void_function, .ssl_callback_ctrl = ssl3_callback_ctrl, .ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl, };





























const SSL_METHOD * SSLv23_server_method(void)
{
	return &SSLv23_server_method_data;
}

static const SSL_METHOD * ssl23_get_server_method(int ver)
{
	if (ver == SSL3_VERSION)
		return (SSLv3_server_method());
	if (ver == TLS1_VERSION)
		return (TLSv1_server_method());
	if (ver == TLS1_1_VERSION)
		return (TLSv1_1_server_method());
	if (ver == TLS1_2_VERSION)
		return (TLSv1_2_server_method());
	return (NULL);
}

int ssl23_accept(SSL *s)
{
	void (*cb)(const SSL *ssl, int type, int val) = NULL;
	int ret = -1;
	int new_state, state;

	ERR_clear_error();
	errno = 0;

	if (s->info_callback != NULL)
		cb = s->info_callback;
	else if (s->ctx->info_callback != NULL)
		cb = s->ctx->info_callback;

	s->in_handshake++;
	if (!SSL_in_init(s) || SSL_in_before(s))
		SSL_clear(s);

	for (;;) {
		state = s->state;

		switch (s->state) {
		case SSL_ST_BEFORE:
		case SSL_ST_ACCEPT:
		case SSL_ST_BEFORE|SSL_ST_ACCEPT:
		case SSL_ST_OK|SSL_ST_ACCEPT:

			s->server = 1;
			if (cb != NULL)
				cb(s, SSL_CB_HANDSHAKE_START, 1);

			
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

			ssl3_init_finished_mac(s);

			s->state = SSL23_ST_SR_CLNT_HELLO_A;
			s->ctx->stats.sess_accept++;
			s->init_num = 0;
			break;

		case SSL23_ST_SR_CLNT_HELLO_A:
		case SSL23_ST_SR_CLNT_HELLO_B:

			s->shutdown = 0;
			ret = ssl23_get_client_hello(s);
			if (ret >= 0)
				cb = NULL;
			goto end;
			

		default:
			SSLerr(SSL_F_SSL23_ACCEPT, SSL_R_UNKNOWN_STATE);
			ret = -1;
			goto end;
			
		}

		if ((cb != NULL) && (s->state != state)) {
			new_state = s->state;
			s->state = state;
			cb(s, SSL_CB_ACCEPT_LOOP, 1);
			s->state = new_state;
		}
	}
end:
	s->in_handshake--;
	if (cb != NULL)
		cb(s, SSL_CB_ACCEPT_EXIT, ret);
	return (ret);
}


int ssl23_get_client_hello(SSL *s)
{
	char buf[11];
	
	unsigned char *p, *d, *d_len, *dd;
	unsigned int i;
	unsigned int csl, sil, cl;
	int n = 0, j;
	int type = 0;
	int v[2];

	if (s->state ==	SSL23_ST_SR_CLNT_HELLO_A) {
		
		v[0] = v[1] = 0;

		if (!ssl3_setup_buffers(s))
			return -1;

		n = ssl23_read_bytes(s, sizeof buf);
		if (n != sizeof buf)
			return(n);

		p = s->packet;

		memcpy(buf, p, n);

		if ((p[0] & 0x80) && (p[2] == SSL2_MT_CLIENT_HELLO)) {
			
			if ((p[3] == 0x00) && (p[4] == 0x02)) {
				v[0] = p[3];
				v[1] = p[4];
				
				if (!(s->options & SSL_OP_NO_SSLv2))
					type = 1;
			} else if (p[3] == SSL3_VERSION_MAJOR) {
				v[0] = p[3];
				v[1] = p[4];
				
				if (p[4] >= TLS1_VERSION_MINOR) {
					if (p[4] >= TLS1_2_VERSION_MINOR && !(s->options & SSL_OP_NO_TLSv1_2)) {
						s->version = TLS1_2_VERSION;
						s->state = SSL23_ST_SR_CLNT_HELLO_B;
					} else if (p[4] >= TLS1_1_VERSION_MINOR && !(s->options & SSL_OP_NO_TLSv1_1)) {
						s->version = TLS1_1_VERSION;
						 
						s->state = SSL23_ST_SR_CLNT_HELLO_B;
					} else if (!(s->options & SSL_OP_NO_TLSv1)) {
						s->version = TLS1_VERSION;
						 
						s->state = SSL23_ST_SR_CLNT_HELLO_B;
					} else if (!(s->options & SSL_OP_NO_SSLv3)) {
						s->version = SSL3_VERSION;
						
						s->state = SSL23_ST_SR_CLNT_HELLO_B;
					} else if (!(s->options & SSL_OP_NO_SSLv2)) {
						type = 1;
					}
				} else if (!(s->options & SSL_OP_NO_SSLv3)) {
					s->version = SSL3_VERSION;
					
					s->state = SSL23_ST_SR_CLNT_HELLO_B;
				} else if (!(s->options & SSL_OP_NO_SSLv2))
					type = 1;

			}
		} else if ((p[0] == SSL3_RT_HANDSHAKE) && (p[1] == SSL3_VERSION_MAJOR) && (p[5] == SSL3_MT_CLIENT_HELLO) && ((p[3] == 0 && p[4] < 5 ) || (p[9] >= p[1]))) {



			

			v[0] = p[1]; 
			
			if (p[3] == 0 && p[4] < 6) {
				v[1] = TLS1_VERSION_MINOR;
			}
			
			else if (p[9] > SSL3_VERSION_MAJOR)
				v[1] = 0xff;
			else v[1] = p[10];
			if (v[1] >= TLS1_VERSION_MINOR) {
				if (v[1] >= TLS1_2_VERSION_MINOR && !(s->options & SSL_OP_NO_TLSv1_2)) {
					s->version = TLS1_2_VERSION;
					type = 3;
				} else if (v[1] >= TLS1_1_VERSION_MINOR && !(s->options & SSL_OP_NO_TLSv1_1)) {
					s->version = TLS1_1_VERSION;
					type = 3;
				} else if (!(s->options & SSL_OP_NO_TLSv1)) {
					s->version = TLS1_VERSION;
					type = 3;
				} else if (!(s->options & SSL_OP_NO_SSLv3)) {
					s->version = SSL3_VERSION;
					type = 3;
				}
			} else {
				
				if (!(s->options & SSL_OP_NO_SSLv3)) {
					s->version = SSL3_VERSION;
					type = 3;
				} else if (!(s->options & SSL_OP_NO_TLSv1)) {
					
					s->version = TLS1_VERSION;
					type = 3;
				}
			}
		}
		else if ((strncmp("GET ", (char *)p, 4) == 0) || (strncmp("POST ",(char *)p, 5) == 0) || (strncmp("HEAD ",(char *)p, 5) == 0) || (strncmp("PUT ", (char *)p, 4) == 0)) {


			SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_HTTP_REQUEST);
			return -1;
		} else if (strncmp("CONNECT", (char *)p, 7) == 0) {
			SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_HTTPS_PROXY_REQUEST);
			return -1;
		}
	}

	if (s->state == SSL23_ST_SR_CLNT_HELLO_B) {
		

		type = 2;
		p = s->packet;
		v[0] = p[3]; 
		v[1] = p[4];

		n = ((p[0] & 0x7f) << 8) | p[1];
		if (n > (1024 * 4)) {
			SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_RECORD_TOO_LARGE);
			return -1;
		}

		j = ssl23_read_bytes(s, n + 2);
		if (j <= 0)
			return (j);

		ssl3_finish_mac(s, s->packet + 2, s->packet_length - 2);
		if (s->msg_callback)
			s->msg_callback(0, SSL2_VERSION, 0, s->packet + 2, s->packet_length - 2, s, s->msg_callback_arg);

		p = s->packet;
		p += 5;
		n2s(p, csl);
		n2s(p, sil);
		n2s(p, cl);
		d = (unsigned char *)s->init_buf->data;
		if ((csl + sil + cl + 11) != s->packet_length) {
			
			SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_RECORD_LENGTH_MISMATCH);
			return -1;
		}

		
		*(d++) = SSL3_MT_CLIENT_HELLO;
		
		d_len = d;
		d += 3;

		
		*(d++) = SSL3_VERSION_MAJOR; 
		*(d++) = v[1];

		
		
		i = (cl > SSL3_RANDOM_SIZE) ? SSL3_RANDOM_SIZE : cl;
		memset(d, 0, SSL3_RANDOM_SIZE);
		memcpy(&(d[SSL3_RANDOM_SIZE - i]), &(p[csl + sil]), i);
		d += SSL3_RANDOM_SIZE;

		
		*(d++) = 0;

		
		j = 0;
		dd = d;
		d += 2;
		for (i = 0; i < csl; i += 3) {
			if (p[i] != 0)
				continue;
			*(d++) = p[i + 1];
			*(d++) = p[i + 2];
			j += 2;
		}
		s2n(j, dd);

		
		*(d++) = 1;
		*(d++) = 0;

		i = (d - (unsigned char *)s->init_buf->data) - 4;
		l2n3((long)i, d_len);

		
		s->s3->tmp.reuse_message = 1;
		s->s3->tmp.message_type = SSL3_MT_CLIENT_HELLO;
		s->s3->tmp.message_size = i;
	}

	
	

	if (type == 1) {
		SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_UNSUPPORTED_PROTOCOL);
		return -1;
	}

	if ((type == 2) || (type == 3)) {
		

		if (!ssl_init_wbio_buffer(s, 1))
			return -1;

		
		s->state = SSL3_ST_SR_CLNT_HELLO_A;

		if (type == 3) {
			
			s->rstate = SSL_ST_READ_HEADER;
			s->packet_length = n;
			if (s->s3->rbuf.buf == NULL)
				if (!ssl3_setup_read_buffer(s))
					return -1;

			s->packet = &(s->s3->rbuf.buf[0]);
			memcpy(s->packet, buf, n);
			s->s3->rbuf.left = n;
			s->s3->rbuf.offset = 0;
		} else {
			s->packet_length = 0;
			s->s3->rbuf.left = 0;
			s->s3->rbuf.offset = 0;
		}
		if (s->version == TLS1_2_VERSION)
			s->method = TLSv1_2_server_method();
		else if (s->version == TLS1_1_VERSION)
			s->method = TLSv1_1_server_method();
		else if (s->version == TLS1_VERSION)
			s->method = TLSv1_server_method();
		else s->method = SSLv3_server_method();
		s->handshake_func = s->method->ssl_accept;
	}

	if ((type < 1) || (type > 3)) {
		
		SSLerr(SSL_F_SSL23_GET_CLIENT_HELLO, SSL_R_UNKNOWN_PROTOCOL);
		return -1;
	}
	s->init_num = 0;

	return (SSL_accept(s));
}
