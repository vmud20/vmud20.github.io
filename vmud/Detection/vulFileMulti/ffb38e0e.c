








static inline void init_keys(at91_aes_key_size_t *key_size, unsigned int *cipher_key, unsigned int *cmac_key, unsigned int *iv)


{

	*key_size = AT91_AES_KEY_SIZE_128;

	*key_size = AT91_AES_KEY_SIZE_192;

	*key_size = AT91_AES_KEY_SIZE_256;




	iv[0]		= CONFIG_AES_IV_WORD0;
	iv[1]		= CONFIG_AES_IV_WORD1;
	iv[2]		= CONFIG_AES_IV_WORD2;
	iv[3]		= CONFIG_AES_IV_WORD3;

	cipher_key[0]	= CONFIG_AES_CIPHER_KEY_WORD0;
	cmac_key[0]	= CONFIG_AES_CMAC_KEY_WORD0;
	cipher_key[1]	= CONFIG_AES_CIPHER_KEY_WORD1;
	cmac_key[1]	= CONFIG_AES_CMAC_KEY_WORD1;
	cipher_key[2]	= CONFIG_AES_CIPHER_KEY_WORD2;
	cmac_key[2]	= CONFIG_AES_CMAC_KEY_WORD2;
	cipher_key[3]	= CONFIG_AES_CIPHER_KEY_WORD3;
	cmac_key[3]	= CONFIG_AES_CMAC_KEY_WORD3;


	cipher_key[4]	= CONFIG_AES_CIPHER_KEY_WORD4;
	cmac_key[4]	= CONFIG_AES_CMAC_KEY_WORD4;
	cipher_key[5]	= CONFIG_AES_CIPHER_KEY_WORD5;
	cmac_key[5]	= CONFIG_AES_CMAC_KEY_WORD5;



	cipher_key[6]	= CONFIG_AES_CIPHER_KEY_WORD6;
	cmac_key[6]	= CONFIG_AES_CMAC_KEY_WORD6;
	cipher_key[7]	= CONFIG_AES_CIPHER_KEY_WORD7;
	cmac_key[7]	= CONFIG_AES_CMAC_KEY_WORD7;

}

int secure_decrypt(void *data, unsigned int data_length, int is_signed)
{
	at91_aes_key_size_t key_size;
	unsigned int cmac_key[8], cipher_key[8];
	unsigned int iv[AT91_AES_IV_SIZE_WORD];
	unsigned int computed_cmac[AT91_AES_BLOCK_SIZE_WORD];
	unsigned int fixed_length;
	const unsigned int *cmac;
	int rc = -1;

	
	init_keys(&key_size, cipher_key, cmac_key, iv);

	
	at91_aes_init();

	
	if (is_signed) {
		
		if (at91_aes_cmac(data_length, data, computed_cmac, key_size, cmac_key))
			goto exit;

		
		fixed_length = at91_aes_roundup(data_length);
		cmac = (const unsigned int *)((char *)data + fixed_length);
		if (!consttime_memequal(cmac, computed_cmac, AT91_AES_BLOCK_SIZE_BYTE))
			goto exit;
	}

	
	if (at91_aes_cbc(data_length, data, data, 0, key_size, cipher_key, iv))
		goto exit;

	rc = 0;
exit:
	
	at91_aes_cleanup();

	
	memset(cmac_key, 0, sizeof(cmac_key));
	memset(cipher_key, 0, sizeof(cipher_key));
	memset(iv, 0, sizeof(iv));

	return rc;
}

int secure_check(void *data)
{
	const at91_secure_header_t *header;
	void *file;

	if (secure_decrypt(data, sizeof(*header), 0))
		return -1;

	header = (const at91_secure_header_t *)data;
	if (header->magic != AT91_SECURE_MAGIC)
		return -1;

	file = (unsigned char *)data + sizeof(*header);
	return secure_decrypt(file, header->file_size, 1);
}
