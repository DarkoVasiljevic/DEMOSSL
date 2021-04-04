#include "Mac.h"

void Mac::getMacId(int* macid) {

	if (!strcmp(getMacType(), "HMAC"))
		*macid = EVP_PKEY_HMAC;
	else if (!strcmp(getMacType(), "CMAC"))
		*macid = EVP_PKEY_CMAC;
}

void Mac::getMd(const EVP_MD** md) {

	if (!strcmp(getHashType(), "MD5"))
		*md = EVP_md5();
	else if (!strcmp(getHashType(), "SHA1"))
		*md = EVP_sha1();
	else if (!strcmp(getHashType(), "SHA256"))
		*md = EVP_sha256();
	else if (!strcmp(getHashType(), "SHA384"))
		*md = EVP_sha384();
	else if (!strcmp(getHashType(), "SHA512"))
		*md = EVP_sha512();
}

void Mac::generateRandom(unsigned char* param, const int len) { 
	RAND_bytes(param, len); 
}

void Mac::generateKey(int* len) {

	unsigned char* key = (unsigned char*)malloc(*len);
	if (key == NULL) throw std::runtime_error(__func__);

	generateRandom(key, *len);
	setKeyLen(*len);
	setKey(key);

	free(key);
}

void Mac::generateIv(int* len) {

	unsigned char* iv = (unsigned char*)malloc(*len);
	if (iv == NULL) throw std::runtime_error(__func__);

	generateRandom(iv, *len);
	setIv(iv);
	setIvLen(*len);

	free(iv);
}

EVP_PKEY* Mac::generateMacKey() {

	EVP_PKEY* mackey = NULL;

	int error = 0;
	const EVP_CIPHER* cipher = EVP_aes_256_cbc();
	if (cipher == NULL) throw std::runtime_error(__func__);

	int macid = NULL;
	getMacId(&macid);
	if (macid == NULL) throw std::runtime_error(__func__);

	const EVP_MD* md = NULL;
	getMd(&md);
	if (md == NULL) throw std::runtime_error(__func__);

	int md_size = EVP_MD_size(md);

	int key_len = EVP_CIPHER_key_length(cipher);
	generateKey(&key_len);

	if(macid == EVP_PKEY_HMAC)
		mackey = EVP_PKEY_new_mac_key(macid, NULL, getKey(), getKeyLen());
	else if (macid == EVP_PKEY_CMAC) {
		
		EVP_PKEY_CTX* ctx = NULL;
		ctx = EVP_PKEY_CTX_new_id(macid, NULL);
		if (ctx == NULL) throw std::runtime_error(__func__);

		error = EVP_PKEY_keygen_init(ctx);
		if (error < 1) throw std::runtime_error(__func__);

		error = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_CIPHER, 
									0, (void*)cipher);
		if (error < 1) throw std::runtime_error(__func__);

		error = EVP_PKEY_CTX_ctrl(ctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SET_MAC_KEY,
									getKeyLen(), getKey());
		if (error < 1) throw std::runtime_error(__func__);

		error = EVP_PKEY_keygen(ctx, &mackey);
		if (error < 1) throw std::runtime_error(__func__);

		if (ctx)
			EVP_PKEY_CTX_free(ctx);
	}

	return mackey;
}

void Mac::signMac(EVP_PKEY* mackey) {
	
	int error = 0;

	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	if (ctx == NULL) throw std::runtime_error(__func__);

	const EVP_MD* md = NULL;
	getMd(&md);
	if (md == NULL) throw std::runtime_error(__func__);

	error = EVP_DigestInit_ex(ctx, md, NULL);
	if (error < 1) throw std::runtime_error(__func__);

	error = EVP_DigestSignInit(ctx, NULL, md, NULL, mackey);
	if (error < 1) throw std::runtime_error(__func__);

	error = EVP_DigestSignUpdate(ctx, getInText(), getInLen());
	if (error < 1) throw std::runtime_error(__func__);

	size_t len = 0;
	error = EVP_DigestSignFinal(ctx, NULL, &len);
	if (error < 1) throw std::runtime_error(__func__);

	unsigned char* sign = (unsigned char*)OPENSSL_malloc(len);
	if (sign == NULL) throw std::runtime_error(__func__);

	error = EVP_DigestSignFinal(ctx, sign, (size_t*)&len);
	if (error < 1) throw std::runtime_error(__func__);

	setOutLen(len);
	setOutText(sign);

	OPENSSL_free(sign);

	EVP_MD_CTX_destroy(ctx);
}

void Mac::generateMac() {
	
	int error = 0;

	OpenSSL_add_all_algorithms();

	EVP_PKEY* mackey = generateMacKey();
	if (mackey == NULL) throw std::runtime_error(__func__);

	signMac(mackey);

	EVP_PKEY_free(mackey);
}

