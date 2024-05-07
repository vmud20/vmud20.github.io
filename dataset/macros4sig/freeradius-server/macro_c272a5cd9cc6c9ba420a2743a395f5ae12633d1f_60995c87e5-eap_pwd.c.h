








#define EAP_PWD_GET_EXCHANGE(x)	 ((x)->lm_exchange & 0x3f)
#define EAP_PWD_GET_LENGTH_BIT(x)       ((x)->lm_exchange & 0x80)
#define EAP_PWD_GET_MORE_BIT(x)	 ((x)->lm_exchange & 0x40)
#define EAP_PWD_SET_EXCHANGE(x,y)       ((x)->lm_exchange |= (y))
#define EAP_PWD_SET_LENGTH_BIT(x)       ((x)->lm_exchange |= 0x80)
#define EAP_PWD_SET_MORE_BIT(x)	 ((x)->lm_exchange |= 0x40)

#define EAP_STATE_LEN (AUTH_VECTOR_LEN)
#define REQUEST_DATA_EAP_MSCHAP_TUNNEL_CALLBACK ((PW_EAP_MESSAGE << 16) | PW_EAP_MSCHAPV2)
#define REQUEST_DATA_EAP_TUNNEL_CALLBACK PW_EAP_MESSAGE
#define TLS_CONFIG_SECTION "tls-config"

