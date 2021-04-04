#include "Asymmetric.h"

void Asymmetric::generateRsaPublicKey(EVP_PKEY* keyPair) {

	int error = 0;

	EVP_PKEY* publicKey = NULL;

	unsigned char* tmp_buf, * p1;
	int tmp_len = i2d_PUBKEY(keyPair, NULL);
	tmp_buf = (unsigned char*)malloc(tmp_len);
	if (tmp_buf == NULL) throw std::runtime_error(__func__);

	p1 = tmp_buf;
	int pbk_len = i2d_PUBKEY(keyPair, &p1);

	const unsigned char* p2 = tmp_buf;
	publicKey = d2i_PUBKEY(NULL, &p2, pbk_len);
	if (publicKey == NULL) throw std::runtime_error(__func__);

	writePublicKey(tmp_buf, &pbk_len);

	setPublicKeyLen(pbk_len);
	setRsaPublicKey(readPublicKey());

	free(tmp_buf);
	EVP_PKEY_free(publicKey);
}

void Asymmetric::generateRsaPrivateKey(EVP_PKEY* keyPair) {

	int error = 0;

	EVP_PKEY* privateKey = NULL;
		
	unsigned char* tmp_buf, * p1;
	int tmp_len = i2d_PrivateKey(keyPair, NULL);
	tmp_buf = (unsigned char*)malloc(tmp_len);
	if (tmp_buf == NULL) throw std::runtime_error(__func__);
		
	p1 = tmp_buf;
	int pbk_len = i2d_PrivateKey(keyPair, &p1);
		
	const unsigned char* p2 = tmp_buf;
	privateKey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p2, pbk_len);
	if (privateKey == NULL) throw std::runtime_error(__func__);
		
	writePrivateKey(tmp_buf, &pbk_len);
		
	setPrivateKeyLen(pbk_len);
	setRsaPrivateKey(readPrivateKey());
		
	free(tmp_buf);
	EVP_PKEY_free(privateKey);	
}

void Asymmetric::writePublicKey(unsigned char* buffer, int* len) {

	int error = 0;

	FILE* fpriv = fopen(getPublicKeyPathPem(), "wb");
	if (fpriv == NULL) throw std::runtime_error(__func__);

	error = PEM_write_PUBKEY(fpriv, getRsaKeyPair());
	if (error < 1) throw std::runtime_error(__func__);

	fclose(fpriv);

	FILE* fpub = fopen(getPublicKeyPathDer(), "wb");
	if (fpub == NULL) throw std::runtime_error(__func__);

	fwrite(buffer, *len, 1, fpub);

	fclose(fpub);
}

void Asymmetric::writePrivateKey(unsigned char* buffer, int* len) {

	FILE* fpriv = fopen(getPrivateKeyPathPem(), "wb");
	if (fpriv == NULL) throw std::runtime_error(__func__);

	int error = PEM_write_PrivateKey(fpriv, getRsaKeyPair(), NULL, NULL, 0, NULL, NULL);
	if (error < 1) throw std::runtime_error(__func__);

	fclose(fpriv);

	FILE* fpub = fopen(getPrivateKeyPathDer(), "wb");
	if (fpub == NULL) throw std::runtime_error(__func__);

	fwrite(buffer, *len, 1, fpub);

	fclose(fpub);
}

EVP_PKEY* Asymmetric::readPublicKey() {
	
	FILE* fp = fopen(getPublicKeyPathPem(), "rb");
	if (fp == NULL) throw std::runtime_error(__func__);

	EVP_PKEY* EVP_public = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	if (EVP_public == NULL) throw std::runtime_error(__func__);

	fclose(fp);

	return EVP_public;
}

EVP_PKEY* Asymmetric::readPrivateKey() {

	FILE* fp = fopen(getPrivateKeyPathPem(), "rb");
	if (fp == NULL) throw std::runtime_error(__func__);

	EVP_PKEY* EVP_private = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	if (EVP_private == NULL) throw std::runtime_error(__func__);

	fclose(fp);

	return EVP_private;
}

void Asymmetric::generateRsaKeyPair() {

	int error = 0;

	EVP_PKEY* keyPair = NULL;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (ctx == NULL) throw std::runtime_error(__func__);

	error = EVP_PKEY_keygen_init(ctx);
	if (error < 1) throw std::runtime_error(__func__);

	error = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, getKeyLenBits());
	if (error < 1) throw std::runtime_error(__func__);

	error = EVP_PKEY_keygen(ctx, &keyPair);
	if (error < 1) throw std::runtime_error(__func__);

	setRsaKeyPair(keyPair);

	generateRsaPrivateKey(keyPair);
	generateRsaPublicKey(keyPair);

	EVP_PKEY_free(keyPair);
	EVP_PKEY_CTX_free(ctx);
}

void Asymmetric::readPublicKeyFromFile(unsigned char* buffer) {
	
	FILE* fp = fopen(getPublicKeyPathPem(), "r");
	if (fp == NULL) throw std::runtime_error(__func__);

	char c;
	int i = 0;
	while ((c = fgetc(fp)) != EOF)
		buffer[i++] = c;

	buffer[i] = '\0';

	fclose(fp);
}

void Asymmetric::readPrivateKeyFromFile(unsigned char* buffer) {
	
	FILE* fp = fopen(getPrivateKeyPathPem(), "r");
	if (fp == NULL) throw std::runtime_error(__func__);

	char c;
	int i = 0;
	while ((c = fgetc(fp)) != EOF)
		buffer[i++] = c;

	buffer[i] = '\0';

	fclose(fp);
}

void Asymmetric::encryptRsa() {
	
	int error = 0;

	EVP_PKEY* publicKey = readPublicKey();
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, NULL);
		
	EVP_PKEY_encrypt_init(ctx);

	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

	size_t out_len = 0;
	EVP_PKEY_encrypt(ctx, NULL, (size_t*)&out_len, getInText(), (size_t)getInLen());

	unsigned char* out_text = (unsigned char*)OPENSSL_malloc(out_len);
	if (out_text == NULL) throw std::runtime_error(__func__);

	EVP_PKEY_encrypt(ctx, out_text, (size_t*)&out_len, getInText(), (size_t)getInLen());

	setOutLen((int)out_len);
	setOutText(out_text);
	setInLen((int)out_len);

	OPENSSL_free(out_text);
}

void Asymmetric::decryptRsa() {
	
	int error = 0;

	EVP_PKEY* privateKey = readPrivateKey();
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, NULL);

	EVP_PKEY_decrypt_init(ctx);

	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

	size_t out_len = 0;
	EVP_PKEY_decrypt(ctx, NULL, (size_t*)&out_len, getInText(), (size_t)getInLen());

	unsigned char* out_text = (unsigned char*)OPENSSL_malloc(out_len);
	if (out_text == NULL) throw std::runtime_error(__func__);

	EVP_PKEY_decrypt(ctx, out_text, (size_t*)&out_len, getInText(), (size_t)getInLen());

	setOutLen((int)out_len);
	setOutText(out_text);

	OPENSSL_free(out_text);
}

