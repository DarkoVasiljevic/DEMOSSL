#include "Sign.h"

void Sign::getMd(const EVP_MD** md) {

	if (!strcmp(getMdType(), "MD5"))
		*md = EVP_md5();
	else if (!strcmp(getMdType(), "SHA1"))
		*md = EVP_sha1();
	else if (!strcmp(getMdType(), "SHA256"))
		*md = EVP_sha256();
	else if (!strcmp(getMdType(), "SHA384"))
		*md = EVP_sha384();
	else if (!strcmp(getMdType(), "SHA512"))
		*md = EVP_sha512();
}

int Sign::getNid() {
		
	if (!strcmp(getCurve(), "secp256k1")) {
		return NID_secp256k1;
	}
	else if (!strcmp(getCurve(), "brainpool256r1")) {
		return NID_brainpoolP256r1;
	}
	else
		return NID_X9_62_prime256v1;
}

void Sign::generateECPublicKey(EC_KEY* key) {
		
	writePublicKey(key);
		
	int len = 0;
	unsigned char public_key[BUFFER];
	readPublicKeyFromFile(public_key, &len);

	setPublicKeyLen(len);
	setECPublicKey(readPublicKey());
}

void Sign::generateECPrivateKey(EC_KEY* key) {

	writePrivateKey(key);

	int len = 0;
	unsigned char private_key[BUFFER];
	readPrivateKeyFromFile(private_key, &len);

	setPrivateKeyLen(len);
	setECPrivateKey(readPrivateKey());
}

void Sign::writePublicKey(EC_KEY* key) {
	
	FILE* fp = fopen(getPublicKeyPath(), "w");
	if (fp == NULL) throw std::runtime_error(__func__);

	int error = PEM_write_EC_PUBKEY(fp, key);
	if (error < 1) throw std::runtime_error(__func__);

	fclose(fp);
}

void Sign::writePrivateKey(EC_KEY* key) {
	
	FILE* fp = fopen(getPrivateKeyPath(), "w");
	if (fp == NULL) throw std::runtime_error(__func__);

	int error = PEM_write_ECPrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
	if (error < 1) throw std::runtime_error(__func__);

	fclose(fp);
}

EC_KEY* Sign::readPublicKey() {

	FILE* fp = fopen(getPublicKeyPath(), "r");
	if (fp == NULL) throw std::runtime_error(__func__);

	EC_KEY* EC_public = PEM_read_EC_PUBKEY(fp, NULL, NULL, NULL);
	if (EC_public == NULL) throw std::runtime_error(__func__);

	fclose(fp);

	return EC_public;
}

EC_KEY* Sign::readPrivateKey() {

	FILE* fp = fopen(getPrivateKeyPath(), "r");
	if (fp == NULL) throw std::runtime_error(__func__);

	EC_KEY* EC_private = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
	if (EC_private == NULL) throw std::runtime_error(__func__);

	fclose(fp);

	return EC_private;
}

void Sign::generateECKeys() {
	
	int error = 1;

	EC_KEY* key = EC_KEY_new_by_curve_name(getNid());
	EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
	if (key == NULL) throw std::runtime_error(__func__);

	error = EC_KEY_generate_key(key);
	if (error < 1) throw std::runtime_error(__func__);

	error = EC_KEY_check_key(key);
	if (error < 1) throw std::runtime_error(__func__);
		
	/*
	const EC_GROUP* private_key = EC_KEY_get0_group(key);
	if (private_key == NULL) throw std::runtime_error(__func__);
	int bits = EC_GROUP_get_degree(private_key);
	setPrivateKeyLen(bits);

	const EC_POINT* public_key = EC_KEY_get0_public_key(key);
	if (public_key == NULL) throw std::runtime_error(__func__);
	*/

	generateECPublicKey(key);
	generateECPrivateKey(key);

	EC_KEY_free(key);
}

void Sign::readPublicKeyFromFile(unsigned char* buffer, int* len) {

	FILE* fp = fopen(getPublicKeyPath(), "r");
	if (fp == NULL) throw std::runtime_error(__func__);

	char c;
	while ((c = fgetc(fp)) != EOF)
		buffer[(*len)++] = c;

	buffer[*len] = '\0';

	fclose(fp);
}

void Sign::readPrivateKeyFromFile(unsigned char* buffer, int* len) {

	FILE* fp = fopen(getPrivateKeyPath(), "r");
	if (fp == NULL) throw std::runtime_error(__func__);

	char c;
	while ((c = fgetc(fp)) != EOF)
		buffer[(*len)++] = c;

	buffer[*len] = '\0';

	fclose(fp);
}

void Sign::rsaSign() {
	
	int error = 0;

	OpenSSL_add_all_digests();

	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	if (ctx == NULL) throw std::runtime_error(__func__);
		
	const EVP_MD* md = NULL;
	getMd(&md);
	if (md == NULL) throw std::runtime_error(__func__);

	error = EVP_DigestSignInit(ctx, NULL, md, NULL, getRsaPrivateKey());
	if (error < 1) throw std::runtime_error(__func__);

	error = EVP_DigestSignUpdate(ctx, getInText(), getInLen());
	if (error < 1) throw std::runtime_error(__func__);

	size_t out_len = 0;
	error = EVP_DigestSignFinal(ctx, NULL, &out_len);
	if (error < 1) throw std::runtime_error(__func__);

	unsigned char* out_text = (unsigned char*)malloc(out_len);
	if (out_text == NULL) throw std::runtime_error(__func__);

	error = EVP_DigestSignFinal(ctx, out_text, &out_len);
	if (error < 1) throw std::runtime_error(__func__);

	setOutLen((int)out_len);
	setOutText(out_text);

	free(out_text);
	EVP_MD_CTX_destroy(ctx);
}

void Sign::rsaVerify() {
	
	int error = 0;

	OpenSSL_add_all_digests();

	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	if (ctx == NULL) throw std::runtime_error(__func__);

	const EVP_MD* md = NULL;
	getMd(&md);
	if (md == NULL) throw std::runtime_error(__func__);

	error = EVP_DigestVerifyInit(ctx, NULL, md, NULL, getRsaPublicKey());
	if (error < 1) throw std::runtime_error(__func__);

	error = EVP_DigestVerifyUpdate(ctx, getInText(), getInLen());
	if (error < 1) throw std::runtime_error(__func__);

	error = EVP_DigestVerifyFinal(ctx, getOutText(), getOutLen());
	if (error < 0) throw std::runtime_error(__func__);
		
	setRsaVerified(error == 1 ? true : false);

	EVP_MD_CTX_destroy(ctx);
}

void Sign::ecSign() {
	
	int error = 0;

	OpenSSL_add_all_digests();
		
	EC_KEY* ec_private_key = readPrivateKey();
	error = EC_KEY_check_key(ec_private_key);
	if (error < 1) throw std::runtime_error(__func__);

	EVP_PKEY* evp_private_key = EVP_PKEY_new();
	if (evp_private_key == NULL) throw std::runtime_error(__func__);

	error = EVP_PKEY_assign_EC_KEY(evp_private_key, ec_private_key);
	if (error < 1) throw std::runtime_error(__func__);
		
	const EVP_MD* md = EVP_sha256();

	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	if (ctx == NULL) throw std::runtime_error(__func__);

	//const EVP_MD* md = NULL;
	//getMd(&md);
	//if (md == NULL) throw std::runtime_error(__func__);
		
	error = EVP_DigestSignInit(ctx, NULL, md, NULL, evp_private_key);
	if (error < 1) throw std::runtime_error(__func__);
		
	error = EVP_DigestSignUpdate(ctx, getInText(), getInLen());
	if (error < 1) throw std::runtime_error(__func__);
		
	size_t out_len = 0;
	error = EVP_DigestSignFinal(ctx, NULL, &out_len);
	if (error < 1) throw std::runtime_error(__func__);
		
	unsigned char* out_text = (unsigned char*)malloc(out_len);
	if (out_text == NULL) throw std::runtime_error(__func__);
		
	error = EVP_DigestSignFinal(ctx, out_text, &out_len);
	if (error < 1) throw std::runtime_error(__func__);
		
	setOutLen((int)out_len);
	setOutText(out_text);
		
	free(out_text);
	EVP_PKEY_free(evp_private_key);
	EVP_MD_CTX_destroy(ctx);
}

void Sign::ecVerify() {
	
	int error = 1;

	OpenSSL_add_all_digests();

	EVP_PKEY* evp_public_key = EVP_PKEY_new();
	if (evp_public_key == NULL) throw std::runtime_error(__func__);

	EC_KEY* ec_public_key = readPublicKey();
	error = EC_KEY_check_key(ec_public_key);
	if (error < 1) throw std::runtime_error(__func__);
		
	error = EVP_PKEY_assign_EC_KEY(evp_public_key, ec_public_key);
	if (error < 1) throw std::runtime_error(__func__);
		
	EVP_MD_CTX* ctx = EVP_MD_CTX_create();
	if (ctx == NULL) throw std::runtime_error(__func__);

	const EVP_MD* md = EVP_sha256();

	//const EVP_MD* md = NULL;
	//getMd(&md);
	//if (md == NULL) throw std::runtime_error(__func__);

	error = EVP_DigestVerifyInit(ctx, NULL, md, NULL, evp_public_key);
	if (error < 1) throw std::runtime_error(__func__);
		
	error = EVP_DigestVerifyUpdate(ctx, getInText(), getInLen());
	if (error < 1) throw std::runtime_error(__func__);

	error = EVP_DigestVerifyFinal(ctx, getOutText(), getOutLen());
	if (error < 0) throw std::runtime_error(__func__);

	setEcVerified(error == 1 ? true : false);

	EVP_PKEY_free(evp_public_key);
	EVP_MD_CTX_free(ctx);
}











