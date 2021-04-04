#include "Hash.h"

void Hash::getMd(const EVP_MD** md) {
	
	if (!strcmp(getType(), "MD5"))
		*md = EVP_md5();
	else if (!strcmp(getType(), "SHA1"))
		*md = EVP_sha1();
	else if (!strcmp(getType(), "SHA256"))
		*md = EVP_sha256();
	else if (!strcmp(getType(), "SHA384"))
		*md = EVP_sha384();
	else if (!strcmp(getType(), "SHA512"))
		*md = EVP_sha512();
}

void Hash::hashText() {
		
	int error = 0;

	OpenSSL_add_all_digests();

	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	if (ctx == NULL) throw std::runtime_error(__func__);

	EVP_MD_CTX_init(ctx);

	const EVP_MD* md = NULL;
	getMd(&md);
	if (md == NULL) throw std::runtime_error(__func__);

	error = EVP_DigestInit_ex(ctx, md, NULL);
	if (error < 1) throw std::runtime_error(__func__);

	error = EVP_DigestUpdate(ctx, getInText(),  getInLen());
	if (error < 1) throw std::runtime_error(__func__);

	unsigned char* out_text = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
	if (out_text == NULL) throw std::runtime_error(__func__);

	unsigned int out_len = 0;
	error = EVP_DigestFinal_ex(ctx, out_text, &out_len);
	if (error < 1) throw std::runtime_error(__func__);

	setOutLen(out_len);
	setOutText(out_text);

	free(out_text);
		
	EVP_cleanup();
}

