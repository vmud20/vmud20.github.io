





























static bool ethereum_signing = false;
static uint32_t data_total, data_left;
static EthereumTxRequest msg_tx_request;
static CONFIDENTIAL uint8_t privkey[32];
static uint32_t chain_id;
static uint32_t tx_type;
struct SHA3_CTX keccak_ctx;

bool ethereum_isStandardERC20Transfer(const EthereumSignTx *msg) {
  if (msg->has_to && msg->to.size == 20 && msg->value.size == 0 && msg->data_initial_chunk.size == 68 && memcmp(msg->data_initial_chunk.bytes, "\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) == 0) {



    return true;
  }
  return false;
}

bool ethereum_isStandardERC20Approve(const EthereumSignTx *msg) {
  if (msg->has_to && msg->to.size == 20 && msg->value.size == 0 && msg->data_initial_chunk.size == 68 && memcmp(msg->data_initial_chunk.bytes, "\x09\x5e\xa7\xb3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) == 0) {



    return true;
  }
  return false;
}

bool ethereum_isThorchainTx(const EthereumSignTx *msg) {
  if (msg->has_to && msg->to.size == 20 && memcmp(msg->data_initial_chunk.bytes, "\x1f\xec\xe7\xb4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) == 0) {


    return true;
  }
  return false;
}

uint8_t ethereum_extractThorchainData(const EthereumSignTx *msg, char *buffer) {
  
  
  uint16_t offset = 4 + (5 * 32);
  int16_t len = msg->data_length - offset;
  if (msg->has_data_length && len > 0) {
    memcpy(buffer, msg->data_initial_chunk.bytes + offset, len);
    
    return len < 256 ? (uint8_t)len : 0;
  }
  return 0;
}

bool ethereum_getStandardERC20Recipient(const EthereumSignTx *msg, char *address, size_t len) {
  if (len < 2 * 20 + 1) return false;

  data2hex(msg->data_initial_chunk.bytes + 16, 20, address);
  return true;
}

bool ethereum_getStandardERC20Coin(const EthereumSignTx *msg, CoinType *coin) {
  const CoinType *found = coinByChainAddress(msg->has_chain_id ? msg->chain_id : 1, msg->to.bytes);
  if (found) {
    memcpy(coin, found, sizeof(*coin));
    return true;
  }

  const TokenType *token = tokenByChainAddress(msg->has_chain_id ? msg->chain_id : 1, msg->to.bytes);
  if (token == UnknownToken) return false;

  coinFromToken(coin, token);
  return true;
}

bool ethereum_getStandardERC20Amount(const EthereumSignTx *msg, void **tx_out_amount) {
  const ExchangeType *exchange = &msg->exchange_type;
  size_t size = exchange->signed_exchange_response.responseV2.deposit_amount.size;
  if (32 < size) return false;

  
  
  char *value = (char *)msg->data_initial_chunk.bytes + 36;
  if (memcmp(value, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 32 - size) != 0)


    return false;

  *tx_out_amount = value + (32 - size);
  return true;
}

void bn_from_bytes(const uint8_t *value, size_t value_len, bignum256 *val) {
  uint8_t pad_val[32];
  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - value_len), value, value_len);
  bn_read_be(pad_val, val);
  memzero(pad_val, sizeof(pad_val));
}

static inline void hash_data(const uint8_t *buf, size_t size) {
  sha3_Update(&keccak_ctx, buf, size);
}


static void hash_rlp_length(uint32_t length, uint8_t firstbyte) {
  uint8_t buf[4];
  if (length == 1 && firstbyte <= 0x7f) {
    
  } else if (length <= 55) {
    buf[0] = 0x80 + length;
    hash_data(buf, 1);
  } else if (length <= 0xff) {
    buf[0] = 0xb7 + 1;
    buf[1] = length;
    hash_data(buf, 2);
  } else if (length <= 0xffff) {
    buf[0] = 0xb7 + 2;
    buf[1] = length >> 8;
    buf[2] = length & 0xff;
    hash_data(buf, 3);
  } else {
    buf[0] = 0xb7 + 3;
    buf[1] = length >> 16;
    buf[2] = length >> 8;
    buf[3] = length & 0xff;
    hash_data(buf, 4);
  }
}


static void hash_rlp_list_length(uint32_t length) {
  uint8_t buf[4];
  if (length <= 55) {
    buf[0] = 0xc0 + length;
    hash_data(buf, 1);
  } else if (length <= 0xff) {
    buf[0] = 0xf7 + 1;
    buf[1] = length;
    hash_data(buf, 2);
  } else if (length <= 0xffff) {
    buf[0] = 0xf7 + 2;
    buf[1] = length >> 8;
    buf[2] = length & 0xff;
    hash_data(buf, 3);
  } else {
    buf[0] = 0xf7 + 3;
    buf[1] = length >> 16;
    buf[2] = length >> 8;
    buf[3] = length & 0xff;
    hash_data(buf, 4);
  }
}


static void hash_rlp_field(const uint8_t *buf, size_t size) {
  hash_rlp_length(size, buf[0]);
  hash_data(buf, size);
}


static void hash_rlp_number(uint32_t number) {
  if (!number) {
    return;
  }
  uint8_t data[4];
  data[0] = (number >> 24) & 0xff;
  data[1] = (number >> 16) & 0xff;
  data[2] = (number >> 8) & 0xff;
  data[3] = (number)&0xff;
  int offset = 0;
  while (!data[offset]) {
    offset++;
  }
  hash_rlp_field(data + offset, 4 - offset);
}


static int rlp_calculate_length(int length, uint8_t firstbyte) {
  if (length == 1 && firstbyte <= 0x7f) {
    return 1;
  } else if (length <= 55) {
    return 1 + length;
  } else if (length <= 0xff) {
    return 2 + length;
  } else if (length <= 0xffff) {
    return 3 + length;
  } else {
    return 4 + length;
  }
}

static int rlp_calculate_number_length(uint32_t number) {
  if (number <= 0x7f) {
    return 1;
  } else if (number <= 0xff) {
    return 2;
  } else if (number <= 0xffff) {
    return 3;
  } else if (number <= 0xffffff) {
    return 4;
  } else {
    return 5;
  }
}

static void send_request_chunk(void) {
  layoutProgress(_("Signing"), (data_total - data_left) * 1000 / data_total);
  msg_tx_request.has_data_length = true;
  msg_tx_request.data_length = data_left <= 1024 ? data_left : 1024;
  msg_write(MessageType_MessageType_EthereumTxRequest, &msg_tx_request);
}

static int ethereum_is_canonic(uint8_t v, uint8_t signature[64]) {
  (void)signature;
  return (v & 2) == 0;
}

static void send_signature(void) {
  uint8_t hash[32], sig[64];
  uint8_t v;
  layoutProgress(_("Signing"), 1000);

  
  if (chain_id) {
    
    hash_rlp_number(chain_id);
    hash_rlp_length(0, 0);
    hash_rlp_length(0, 0);
  }

  keccak_Final(&keccak_ctx, hash);
  if (ecdsa_sign_digest(&secp256k1, privkey, hash, sig, &v, ethereum_is_canonic) != 0) {
    fsm_sendFailure(FailureType_Failure_Other, "Signing failed");
    ethereum_signing_abort();
    return;
  }

  memzero(privkey, sizeof(privkey));

  
  msg_tx_request.has_data_length = false;

  msg_tx_request.has_signature_v = true;
  if (chain_id > MAX_CHAIN_ID) {
    msg_tx_request.signature_v = v;
  } else if (chain_id) {
    msg_tx_request.signature_v = v + 2 * chain_id + 35;
  } else {
    msg_tx_request.signature_v = v + 27;
  }

  msg_tx_request.has_signature_r = true;
  msg_tx_request.signature_r.size = 32;
  memcpy(msg_tx_request.signature_r.bytes, sig, 32);

  msg_tx_request.has_signature_s = true;
  msg_tx_request.signature_s.size = 32;
  memcpy(msg_tx_request.signature_s.bytes, sig + 32, 32);

  
  msg_tx_request.has_hash = true;
  msg_tx_request.hash.size = sizeof(msg_tx_request.hash.bytes);
  memcpy(msg_tx_request.hash.bytes, hash, msg_tx_request.hash.size);
  msg_tx_request.has_signature_der = true;
  msg_tx_request.signature_der.size = ecdsa_sig_to_der(sig, msg_tx_request.signature_der.bytes);

  msg_write(MessageType_MessageType_EthereumTxRequest, &msg_tx_request);

  ethereum_signing_abort();
}

void ethereumFormatAmount(const bignum256 *amnt, const TokenType *token, uint32_t cid, char *buf, int buflen) {
  bignum256 bn1e9;
  bn_read_uint32(1000000000, &bn1e9);
  const char *suffix = NULL;
  int decimals = 18;
  if (token == UnknownToken) {
    strlcpy(buf, "Unknown token value", buflen);
    return;
  } else if (token != NULL) {
    suffix = token->ticker;
    decimals = token->decimals;
  } else if (bn_is_less(amnt, &bn1e9)) {
    suffix = " Wei";
    decimals = 0;
  } else {
    if (tx_type == 1 || tx_type == 6) {
      suffix = " WAN";
    } else {
      
      switch (cid) {
        case 1:
          suffix = " ETH";
          break;  
        case 2:
          suffix = " EXP";
          break;  
        case 3:
          suffix = " tROP";
          break;  
        case 4:
          suffix = " tRIN";
          break;  
        case 8:
          suffix = " UBQ";
          break;  
        case 20:
          suffix = " EOSC";
          break;  
        case 28:
          suffix = " ETSC";
          break;  
        case 30:
          suffix = " RBTC";
          break;  
        case 31:
          suffix = " tRBTC";
          break;  
        case 42:
          suffix = " tKOV";
          break;  
        case 61:
          suffix = " ETC";
          break;  
        case 62:
          suffix = " tETC";
          break;  
        case 64:
          suffix = " ELLA";
          break;  
        case 820:
          suffix = " CLO";
          break;  
        case 1987:
          suffix = " EGEM";
          break;  
        default:
          suffix = " UNKN";
          break;  
      }
    }
  }
  bn_format(amnt, NULL, suffix, decimals, 0, false, buf, buflen);
}

static void layoutEthereumConfirmTx(const uint8_t *to, uint32_t to_len, const uint8_t *value, uint32_t value_len, const TokenType *token, char *out_str, size_t out_str_len, bool approve) {


  bignum256 val;
  uint8_t pad_val[32];
  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - value_len), value, value_len);
  bn_read_be(pad_val, &val);

  char amount[32];
  if (token == NULL) {
    if (bn_is_zero(&val)) {
      strcpy(amount, _("message"));
    } else {
      ethereumFormatAmount(&val, NULL, chain_id, amount, sizeof(amount));
    }
  } else {
    ethereumFormatAmount(&val, token, chain_id, amount, sizeof(amount));
  }

  char addr[43] = "0x";
  if (to_len) {
    ethereum_address_checksum(to, addr + 2, false, chain_id);
  }

  bool approve_all = approve && value_len == 32 && memcmp(value, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0 && memcmp(value + 8, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0 && memcmp(value + 16, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0 && memcmp(value + 24, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0;





  const char *address = addr;
  if (to_len && makerdao_isOasisDEXAddress(to, chain_id)) {
    address = "OasisDEX";
  }

  int cx;
  if (approve && bn_is_zero(&val) && token) {
    cx = snprintf(out_str, out_str_len, "Remove ability for %s to withdraw %s?", address, token->ticker + 1);
  } else if (approve_all) {
    cx = snprintf(out_str, out_str_len, "Unlock full %s balance for withdrawal by %s?", token->ticker + 1, address);

  } else if (approve) {
    cx = snprintf(out_str, out_str_len, "Approve withdrawal of up to %s by %s?", amount, address);
  } else {
    cx = snprintf(out_str, out_str_len, "Send %s to %s", amount, to_len ? address : "new contract?");
  }

  if (out_str_len <= (size_t)cx) {
    
    memset(out_str, 0, out_str_len);
  }
}

static void layoutEthereumData(const uint8_t *data, uint32_t len, uint32_t total_len, char *out_str, size_t out_str_len) {

  char hexdata[3][17];
  char summary[20];
  uint32_t printed = 0;
  for (int i = 0; i < 3; i++) {
    uint32_t linelen = len - printed;
    if (linelen > 8) {
      linelen = 8;
    }
    data2hex(data, linelen, hexdata[i]);
    data += linelen;
    printed += linelen;
  }

  strcpy(summary, "...          bytes");
  char *p = summary + 11;
  uint32_t number = total_len;
  while (number > 0) {
    *p-- = '0' + number % 10;
    number = number / 10;
  }
  char *summarystart = summary;
  if (total_len == printed) summarystart = summary + 4;

  if ((uint32_t)snprintf(out_str, out_str_len, "%s%s\n%s%s", hexdata[0], hexdata[1], hexdata[2], summarystart) >= out_str_len) {
    
    memset(out_str, 0, out_str_len);
  }
}

static void layoutEthereumFee(const uint8_t *value, uint32_t value_len, const uint8_t *gas_price, uint32_t gas_price_len, const uint8_t *gas_limit, uint32_t gas_limit_len, bool is_token, char *out_str, size_t out_str_len) {



  bignum256 val, gas;
  uint8_t pad_val[32];
  char tx_value[32];
  char gas_value[32];

  memzero(tx_value, sizeof(tx_value));
  memzero(gas_value, sizeof(gas_value));

  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - gas_price_len), gas_price, gas_price_len);
  bn_read_be(pad_val, &val);

  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - gas_limit_len), gas_limit, gas_limit_len);
  bn_read_be(pad_val, &gas);
  bn_multiply(&val, &gas, &secp256k1.prime);

  ethereumFormatAmount(&gas, NULL, chain_id, gas_value, sizeof(gas_value));

  memset(pad_val, 0, sizeof(pad_val));
  memcpy(pad_val + (32 - value_len), value, value_len);
  bn_read_be(pad_val, &val);

  if (bn_is_zero(&val)) {
    strcpy(tx_value, is_token ? _("the tokens") : _("the message"));
  } else {
    ethereumFormatAmount(&val, NULL, chain_id, tx_value, sizeof(tx_value));
  }

  if ((uint32_t)snprintf( out_str, out_str_len, _("Send %s from your wallet, paying up to %s for gas?"), tx_value, gas_value) >= out_str_len) {


    
    memset(out_str, 0, out_str_len);
  }
}



static bool ethereum_signing_check(EthereumSignTx *msg) {
  if (!msg->has_gas_price || !msg->has_gas_limit) {
    return false;
  }

  if (msg->to.size != 20 && msg->to.size != 0) {
    
    return false;
  }

  
  if (msg->to.size == 0 && (!msg->has_data_length || msg->data_length == 0)) {
    return false;
  }

  if (msg->gas_price.size + msg->gas_limit.size > 30) {
    
    return false;
  }

  return true;
}

void ethereum_signing_init(EthereumSignTx *msg, const HDNode *node, bool needs_confirm) {
  ethereum_signing = true;
  sha3_256_Init(&keccak_ctx);

  memset(&msg_tx_request, 0, sizeof(EthereumTxRequest));
  
  if (!msg->has_value) msg->value.size = 0;
  if (!msg->has_data_initial_chunk) msg->data_initial_chunk.size = 0;
  if (!msg->has_to) msg->to.size = 0;
  if (!msg->has_nonce) msg->nonce.size = 0;

  
  if (msg->has_chain_id) {
    if (msg->chain_id < 1) {
      fsm_sendFailure(FailureType_Failure_SyntaxError, _("Chain Id out of bounds"));
      ethereum_signing_abort();
      return;
    }
    chain_id = msg->chain_id;
  } else {
    chain_id = 0;
  }

  
  if (msg->has_tx_type) {
    if (msg->tx_type == 1 || msg->tx_type == 6) {
      tx_type = msg->tx_type;
    } else {
      fsm_sendFailure(FailureType_Failure_SyntaxError, _("Txtype out of bounds"));
      ethereum_signing_abort();
      return;
    }
  } else {
    tx_type = 0;
  }

  if (msg->has_data_length && msg->data_length > 0) {
    if (!msg->has_data_initial_chunk || msg->data_initial_chunk.size == 0) {
      fsm_sendFailure(FailureType_Failure_Other, _("Data length provided, but no initial chunk"));
      ethereum_signing_abort();
      return;
    }
    
    if (msg->data_length > 16000000) {
      fsm_sendFailure(FailureType_Failure_SyntaxError, _("Data length exceeds limit"));
      ethereum_signing_abort();
      return;
    }
    data_total = msg->data_length;
  } else {
    data_total = 0;
  }
  if (msg->data_initial_chunk.size > data_total) {
    fsm_sendFailure(FailureType_Failure_Other, _("Invalid size of initial chunk"));
    ethereum_signing_abort();
    return;
  }

  const TokenType *token = NULL;

  
  if (!ethereum_signing_check(msg)) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Safety check failed"));
    ethereum_signing_abort();
    return;
  }

  bool data_needs_confirm = true;
  if (ethereum_contractHandled(data_total, msg, node)) {
    if (!ethereum_contractConfirmed(data_total, msg, node)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled by user");
      ethereum_signing_abort();
      return;
    }
    needs_confirm = false;
    data_needs_confirm = false;
  }

  
  if (ethereum_isThorchainTx(msg)) {
    if (token == NULL && data_total > 0 && data_needs_confirm) {
      char swap_data[256] = {'\0';
      uint8_t swap_data_len = ethereum_extractThorchainData(msg, swap_data);
      if (!thorchain_parseConfirmMemo(swap_data, swap_data_len)) {
        fsm_sendFailure(FailureType_Failure_Other, _("Malformed THORChain swap data"));
        ethereum_signing_abort();
        return;
      }
      needs_confirm = false;
      data_needs_confirm = false;
    }
  }

  
  if (data_total == 68 && ethereum_isStandardERC20Transfer(msg)) {
    token = tokenByChainAddress(chain_id, msg->to.bytes);
  }

  bool is_approve = false;
  if (data_total == 68 && ethereum_isStandardERC20Approve(msg)) {
    token = tokenByChainAddress(chain_id, msg->to.bytes);
    is_approve = true;
  }

  char confirm_body_message[BODY_CHAR_MAX];
  if (needs_confirm) {
    memset(confirm_body_message, 0, sizeof(confirm_body_message));
    if (token != NULL) {
      layoutEthereumConfirmTx( msg->data_initial_chunk.bytes + 16, 20, msg->data_initial_chunk.bytes + 36, 32, token, confirm_body_message, sizeof(confirm_body_message), is_approve);


    } else {
      layoutEthereumConfirmTx(msg->to.bytes, msg->to.size, msg->value.bytes, msg->value.size, NULL, confirm_body_message, sizeof(confirm_body_message), false);

    }
    bool is_transfer = msg->address_type == OutputAddressType_TRANSFER;
    const char *title;
    ButtonRequestType BRT;
    if (is_approve) {
      title = "Approve";
      BRT = ButtonRequestType_ButtonRequest_ConfirmOutput;
    } else if (is_transfer) {
      title = "Transfer";
      BRT = ButtonRequestType_ButtonRequest_ConfirmTransferToAccount;
    } else {
      title = "Send";
      BRT = ButtonRequestType_ButtonRequest_ConfirmOutput;
    }
    if (!confirm(BRT, title, "%s", confirm_body_message)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled by user");
      ethereum_signing_abort();
      return;
    }
  }

  memset(confirm_body_message, 0, sizeof(confirm_body_message));
  if (token == NULL && data_total > 0 && data_needs_confirm) {
    
    
    
    
    if (!storage_isPolicyEnabled("AdvancedMode")) {
      (void)review( ButtonRequestType_ButtonRequest_Other, "Warning", "Signing of arbitrary ETH contract data is recommended only for " "experienced users. Enable 'AdvancedMode' policy to dismiss.");


    }

    layoutEthereumData(msg->data_initial_chunk.bytes, msg->data_initial_chunk.size, data_total, confirm_body_message, sizeof(confirm_body_message));

    if (!confirm(ButtonRequestType_ButtonRequest_ConfirmOutput, "Confirm Ethereum Data", "%s", confirm_body_message)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      ethereum_signing_abort();
      return;
    }
  }

  if (is_approve) {
    token = NULL;
  }

  memset(confirm_body_message, 0, sizeof(confirm_body_message));
  layoutEthereumFee(msg->value.bytes, msg->value.size, msg->gas_price.bytes, msg->gas_price.size, msg->gas_limit.bytes, msg->gas_limit.size, token != NULL, confirm_body_message, sizeof(confirm_body_message));


  if (!confirm(ButtonRequestType_ButtonRequest_SignTx, "Transaction", "%s", confirm_body_message)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled by user");
    ethereum_signing_abort();
    return;
  }

  
  uint32_t rlp_length = 0;
  layoutProgress(_("Signing"), 0);

  rlp_length += rlp_calculate_length(msg->nonce.size, msg->nonce.bytes[0]);
  rlp_length += rlp_calculate_length(msg->gas_price.size, msg->gas_price.bytes[0]);
  rlp_length += rlp_calculate_length(msg->gas_limit.size, msg->gas_limit.bytes[0]);
  rlp_length += rlp_calculate_length(msg->to.size, msg->to.bytes[0]);
  rlp_length += rlp_calculate_length(msg->value.size, msg->value.bytes[0]);
  rlp_length += rlp_calculate_length(data_total, msg->data_initial_chunk.bytes[0]);
  if (tx_type) {
    rlp_length += rlp_calculate_number_length(tx_type);
  }
  if (chain_id) {
    rlp_length += rlp_calculate_number_length(chain_id);
    rlp_length += rlp_calculate_length(0, 0);
    rlp_length += rlp_calculate_length(0, 0);
  }

  
  hash_rlp_list_length(rlp_length);
  layoutProgress(_("Signing"), 100);

  if (tx_type) {
    hash_rlp_number(tx_type);
  }
  hash_rlp_field(msg->nonce.bytes, msg->nonce.size);
  hash_rlp_field(msg->gas_price.bytes, msg->gas_price.size);
  hash_rlp_field(msg->gas_limit.bytes, msg->gas_limit.size);
  hash_rlp_field(msg->to.bytes, msg->to.size);
  hash_rlp_field(msg->value.bytes, msg->value.size);
  hash_rlp_length(data_total, msg->data_initial_chunk.bytes[0]);
  hash_data(msg->data_initial_chunk.bytes, msg->data_initial_chunk.size);
  data_left = data_total - msg->data_initial_chunk.size;

  memcpy(privkey, node->private_key, 32);

  if (data_left > 0) {
    send_request_chunk();
  } else {
    send_signature();
  }
}

void ethereum_signing_txack(EthereumTxAck *tx) {
  if (!ethereum_signing) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage, _("Not in Ethereum signing mode"));
    layoutHome();
    return;
  }

  if (tx->data_chunk.size > data_left) {
    fsm_sendFailure(FailureType_Failure_Other, _("Too much data"));
    ethereum_signing_abort();
    return;
  }

  if (data_left > 0 && (!tx->has_data_chunk || tx->data_chunk.size == 0)) {
    fsm_sendFailure(FailureType_Failure_Other, _("Empty data chunk received"));
    ethereum_signing_abort();
    return;
  }

  hash_data(tx->data_chunk.bytes, tx->data_chunk.size);

  data_left -= tx->data_chunk.size;

  if (data_left > 0) {
    send_request_chunk();
  } else {
    send_signature();
  }
}

void ethereum_signing_abort(void) {
  if (ethereum_signing) {
    memzero(privkey, sizeof(privkey));
    layoutHome();
    ethereum_signing = false;
  }
}

static void ethereum_message_hash(const uint8_t *message, size_t message_len, uint8_t hash[32]) {
  struct SHA3_CTX ctx;
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t *)"\x19" "Ethereum Signed Message:\n", 26);
  uint8_t c;
  if (message_len >= 1000000000) {
    c = '0' + message_len / 1000000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 100000000) {
    c = '0' + message_len / 100000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 10000000) {
    c = '0' + message_len / 10000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 1000000) {
    c = '0' + message_len / 1000000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 100000) {
    c = '0' + message_len / 100000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 10000) {
    c = '0' + message_len / 10000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 1000) {
    c = '0' + message_len / 1000 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 100) {
    c = '0' + message_len / 100 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  if (message_len >= 10) {
    c = '0' + message_len / 10 % 10;
    sha3_Update(&ctx, &c, 1);
  }
  c = '0' + message_len % 10;
  sha3_Update(&ctx, &c, 1);
  sha3_Update(&ctx, message, message_len);
  keccak_Final(&ctx, hash);
}

void ethereum_message_sign(const EthereumSignMessage *msg, const HDNode *node, EthereumMessageSignature *resp) {
  uint8_t hash[32];

  if (!hdnode_get_ethereum_pubkeyhash(node, resp->address.bytes)) {
    return;
  }
  resp->has_address = true;
  resp->address.size = 20;
  ethereum_message_hash(msg->message.bytes, msg->message.size, hash);

  uint8_t v;
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash, resp->signature.bytes, &v, ethereum_is_canonic) != 0) {
    fsm_sendFailure(FailureType_Failure_Other, _("Signing failed"));
    return;
  }

  resp->has_signature = true;
  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  msg_write(MessageType_MessageType_EthereumMessageSignature, resp);
}

int ethereum_message_verify(const EthereumVerifyMessage *msg) {
  if (msg->signature.size != 65 || msg->address.size != 20) {
    fsm_sendFailure(FailureType_Failure_SyntaxError, _("Malformed data"));
    return 1;
  }

  uint8_t pubkey[65];
  uint8_t hash[32];

  ethereum_message_hash(msg->message.bytes, msg->message.size, hash);

  
  uint8_t v = msg->signature.bytes[64];
  if (v >= 27) {
    v -= 27;
  }
  if (v >= 2 || ecdsa_recover_pub_from_sig( &secp256k1, pubkey, msg->signature.bytes, hash, v) != 0) {
    return 2;
  }

  struct SHA3_CTX ctx;
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, pubkey + 1, 64);
  keccak_Final(&ctx, hash);

  
  if (memcmp(msg->address.bytes, hash + 12, 20) != 0) {
    return 2;
  }
  return 0;
}