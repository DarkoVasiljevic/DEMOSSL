#include "Symmetric.h"

void Symmetric::getCipher(const EVP_CIPHER** cipher) {
	 
if (!(strcmp(getType(), "AES128")) && !strcmp(getMode(), "CBC"))
	*cipher = EVP_aes_128_cbc();
else if (!strcmp(getType(), "AES128") && !strcmp(getMode(), "ECB"))
	*cipher = EVP_aes_128_ecb();
else if (!strcmp(getType(), "AES256") && !strcmp(getMode(), "ECB"))
	*cipher = EVP_aes_256_ecb();
else if (!(strcmp(getType(), "AES256")) && !strcmp(getMode(), "CBC"))
	*cipher = EVP_aes_256_cbc();
else if (!strcmp(getType(), "DES") && !strcmp(getMode(), "CBC"))
	*cipher = EVP_des_cbc();
else if (!strcmp(getType(), "DES") && !strcmp(getMode(), "ECB"))
	*cipher = EVP_des_ecb();
else if (!strcmp(getType(), "TDES") && !strcmp(getMode(), "CBC"))
	*cipher = EVP_des_ede_cbc();
else if (!strcmp(getType(), "TDES") && !strcmp(getMode(), "ECB"))
	*cipher = EVP_des_ede_ecb();
else if (!strcmp(getType(), "RC4"))
	*cipher = EVP_rc4();
}

void Symmetric::generateRandom(unsigned char* param, const int len) { 
	RAND_bytes(param, len); 
}

void Symmetric::generateKey(int* len) {
	
	unsigned char* key = (unsigned char*)malloc(*len);
	if (key == NULL) throw std::runtime_error(__func__);

	generateRandom(key, *len);
	setKeyLen(*len);
	setKey(key);

	free(key);
}

void Symmetric::generateIv(int* len) {

	unsigned char* iv = (unsigned char*)malloc(*len);
	if (iv == NULL) throw std::runtime_error(__func__);

	generateRandom(iv, *len);
	setIvLen(*len);
	setIv(iv);

	free(iv);
}

void Symmetric::encrypt() {

	int error = 0;
		
	OpenSSL_add_all_ciphers();

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) throw std::runtime_error(__func__);

	const EVP_CIPHER* cipher = NULL;
	getCipher(&cipher);
	if (cipher == NULL) throw std::runtime_error(__func__);
		
	int key_len = EVP_CIPHER_key_length(cipher);
	if (!getEnterKey())
		generateKey(&key_len);
		
	int iv_len = EVP_CIPHER_iv_length(cipher);
	generateIv(&iv_len);
		
	error = EVP_EncryptInit_ex(ctx, cipher, NULL, getKey(), getIv());
	if (error < 1) throw std::runtime_error(__func__);

	error = EVP_CIPHER_CTX_set_key_length(ctx, getKeyLen());
	if (error < 1) throw std::runtime_error(__func__);

	if (getPadding())
		error = EVP_CIPHER_CTX_set_padding(ctx, 0);
		
	int out_len = 0;
	int block_size = EVP_CIPHER_block_size(cipher);
	unsigned char* out_text = (unsigned char*)malloc(BUFFER);
	if (out_text == NULL) throw std::runtime_error(__func__);

	error = EVP_EncryptUpdate(ctx, out_text, &out_len, getInText(), getInLen());
	if (error < 1) throw std::runtime_error(__func__);

	int len = 0;
	error = EVP_EncryptFinal_ex(ctx, out_text + out_len, &len);
	if (error < 1) throw std::runtime_error(__func__);

	out_len += len;

	setOutLen(out_len);
	setOutText(out_text);

	free(out_text);
		
	EVP_CIPHER_CTX_free(ctx);
	EVP_cleanup();
}

void Symmetric::decrypt() {

	int error = 0;

	OpenSSL_add_all_ciphers();

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) throw std::runtime_error(__func__);

	const EVP_CIPHER* cipher = NULL;
	getCipher(&cipher);

	error = EVP_DecryptInit_ex(ctx, cipher, NULL, getKey(), getIv());
	if (error < 1) throw std::runtime_error(__func__);

	error = EVP_CIPHER_CTX_set_key_length(ctx, getKeyLen());
	if (error < 1) throw std::runtime_error(__func__);

	if (getPadding())
		error = EVP_CIPHER_CTX_set_padding(ctx, 0);

	int out_len = 0;
	int block_size = EVP_CIPHER_block_size(cipher);
	unsigned char* out_text = (unsigned char*)malloc(BUFFER);
	if (out_text == NULL) throw std::runtime_error(__func__);

	error = EVP_DecryptUpdate(ctx, out_text, &out_len, getInText(), getOutLen());
	if (error < 1) throw std::runtime_error(__func__);

	int len = 0;
	error = EVP_DecryptFinal_ex(ctx, out_text + out_len, &len);
	if (error < 1) throw std::runtime_error(__func__);

	out_len += len;

	setOutLen(out_len);
	setOutText(out_text);

	free(out_text);

	EVP_CIPHER_CTX_free(ctx);
	EVP_cleanup();
}

