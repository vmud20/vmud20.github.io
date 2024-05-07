




#define NGX_IMAP_AUTHENTICATE  7
#define NGX_IMAP_CAPABILITY    3
#define NGX_IMAP_LOGIN         1
#define NGX_IMAP_LOGOUT        2
#define NGX_IMAP_NEXT          6
#define NGX_IMAP_NOOP          4
#define NGX_IMAP_STARTTLS      5
#define NGX_MAIL_AUTH_APOP              3
#define NGX_MAIL_AUTH_APOP_ENABLED      0x0008
#define NGX_MAIL_AUTH_CRAM_MD5          4
#define NGX_MAIL_AUTH_CRAM_MD5_ENABLED  0x0010
#define NGX_MAIL_AUTH_EXTERNAL          5
#define NGX_MAIL_AUTH_EXTERNAL_ENABLED  0x0020
#define NGX_MAIL_AUTH_LOGIN             1
#define NGX_MAIL_AUTH_LOGIN_ENABLED     0x0004
#define NGX_MAIL_AUTH_LOGIN_USERNAME    2
#define NGX_MAIL_AUTH_NONE              6
#define NGX_MAIL_AUTH_NONE_ENABLED      0x0040
#define NGX_MAIL_AUTH_PLAIN             0
#define NGX_MAIL_AUTH_PLAIN_ENABLED     0x0002
#define NGX_MAIL_IMAP_PROTOCOL  1
#define NGX_MAIL_MAIN_CONF      0x02000000
#define NGX_MAIL_MAIN_CONF_OFFSET  offsetof(ngx_mail_conf_ctx_t, main_conf)
#define NGX_MAIL_MODULE         0x4C49414D     
#define NGX_MAIL_PARSE_INVALID_COMMAND  20
#define NGX_MAIL_POP3_PROTOCOL  0
#define NGX_MAIL_SMTP_PROTOCOL  2
#define NGX_MAIL_SRV_CONF       0x04000000
#define NGX_MAIL_SRV_CONF_OFFSET   offsetof(ngx_mail_conf_ctx_t, srv_conf)
#define NGX_POP3_APOP          7
#define NGX_POP3_AUTH          8
#define NGX_POP3_CAPA          3
#define NGX_POP3_DELE          12
#define NGX_POP3_LIST          10
#define NGX_POP3_NOOP          5
#define NGX_POP3_PASS          2
#define NGX_POP3_QUIT          4
#define NGX_POP3_RETR          11
#define NGX_POP3_RSET          13
#define NGX_POP3_STAT          9
#define NGX_POP3_STLS          6
#define NGX_POP3_TOP           14
#define NGX_POP3_UIDL          15
#define NGX_POP3_USER          1
#define NGX_SMTP_AUTH          3
#define NGX_SMTP_DATA          9
#define NGX_SMTP_EHLO          2
#define NGX_SMTP_EXPN          11
#define NGX_SMTP_HELO          1
#define NGX_SMTP_HELP          12
#define NGX_SMTP_MAIL          6
#define NGX_SMTP_NOOP          5
#define NGX_SMTP_QUIT          4
#define NGX_SMTP_RCPT          8
#define NGX_SMTP_RSET          7
#define NGX_SMTP_STARTTLS      13
#define NGX_SMTP_VRFY          10

#define ngx_mail_conf_get_module_main_conf(cf, module)                       \
    ((ngx_mail_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_mail_conf_get_module_srv_conf(cf, module)                        \
    ((ngx_mail_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_mail_delete_ctx(s, module)         s->ctx[module.ctx_index] = NULL;
#define ngx_mail_get_module_ctx(s, module)     (s)->ctx[module.ctx_index]
#define ngx_mail_get_module_main_conf(s, module)                             \
    (s)->main_conf[module.ctx_index]
#define ngx_mail_get_module_srv_conf(s, module)  (s)->srv_conf[module.ctx_index]
#define ngx_mail_set_ctx(s, c, module)         s->ctx[module.ctx_index] = c;
#define NGX_MAIL_STARTTLS_OFF   0
#define NGX_MAIL_STARTTLS_ON    1
#define NGX_MAIL_STARTTLS_ONLY  2

