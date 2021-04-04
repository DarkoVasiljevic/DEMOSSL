#pragma once

#define _CRT_SECURE_NO_WARNINGS

#ifndef _ASYMMETRIC_HPP
#define _ASYMMETRIC_HPP

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <openssl/applink.c>
#include <string>
#include <stdexcept>


#define KEY_LEN_BITS (2048)
#define IV_LEN (8)
#define BUFFER (2048)

#define ERROR(e, p) ((e) = ((p) == NULL) ? (-1) : (0))

class Asymmetric {

private:
	unsigned char* _in_text;
	int _in_len = 0;
	unsigned char _out_text[BUFFER * 2];
	int _out_len = 0;
	int _key_len_bits = KEY_LEN_BITS;
	unsigned char _iv[BUFFER];
	int _iv_len = IV_LEN;
	int _padding;
	EVP_PKEY* _rsa_key_pair = NULL;
	EVP_PKEY* _rsa_private_key = NULL;
	EVP_PKEY* _rsa_public_key = NULL;
	char* _public_key_path_pem = NULL;
	char* _public_key_path_der = NULL;
	int _public_key_len = 0;
	char* _private_key_path_pem = NULL;
	char* _private_key_path_der = NULL;
	int _private_key_len = 0;

public:
	Asymmetric() {};

	void setInText(unsigned char* p) { this->_in_text = p; }
	unsigned char* getInText() { return this->_in_text; }

	void setInLen(int p) { this->_in_len = p; }
	int getInLen() { return this->_in_len; }

	void setOutText(unsigned char* p) { memcpy(this->_out_text, p, this->getOutLen()); }
	unsigned char* getOutText() { return this->_out_text; }

	void setOutLen(int p) { this->_out_len = p; }
	int getOutLen() { return this->_out_len; }

	void setKeyLenBits(int p) { this->_key_len_bits = KEY_LEN_BITS; }
	int getKeyLenBits() { return this->_key_len_bits; }

	void setIv(unsigned char* p) { memcpy(this->_iv, p, this->getIvLen()); }
	unsigned char* getIv() { return this->_iv; }

	void setIvLen(int p) { this->_iv_len = p; }
	int getIvLen() { return this->_iv_len; }

	void setPadding(int p) { this->_padding = p; }
	int getPadding() { return this->_padding; }

	void setPublicKeyPathPem(char* p) { this->_public_key_path_pem = p; }
	char* getPublicKeyPathPem() { return this->_public_key_path_pem; }

	void setPublicKeyPathDer(char* p) { this->_public_key_path_der = p; }
	char* getPublicKeyPathDer() { return this->_public_key_path_der; }

	void setPrivateKeyPathPem(char* p) { this->_private_key_path_pem = p; }
	char* getPrivateKeyPathPem() { return this->_private_key_path_pem; }

	void setPrivateKeyPathDer(char* p) { this->_private_key_path_der = p; }
	char* getPrivateKeyPathDer() { return this->_private_key_path_der; }

	void setPublicKeyLen(int p) { this->_public_key_len = p; }
	int getPublicKeyLen() { return this->_public_key_len; }

	void setPrivateKeyLen(int p) { this->_private_key_len = p; }
	int getPrivateKeyLen() { return this->_private_key_len; }

	void setRsaKeyPair(EVP_PKEY* p) {

		this->_rsa_key_pair = (EVP_PKEY*)malloc(this->getKeyLenBits() / 8);
		memcpy(this->_rsa_key_pair, p, this->getKeyLenBits() / 8);
	}
	EVP_PKEY* getRsaKeyPair() { return this->_rsa_key_pair; }

	void setRsaPrivateKey(EVP_PKEY* p) {

		this->_rsa_private_key = (EVP_PKEY*)malloc(this->getPrivateKeyLen());
		memcpy(this->_rsa_private_key, p, this->getPrivateKeyLen());
	}
	EVP_PKEY* getRsaPrivateKey() { return this->_rsa_private_key; }

	void setRsaPublicKey(EVP_PKEY* p) {

		this->_rsa_public_key = (EVP_PKEY*)malloc(this->getPublicKeyLen());
		memcpy(this->_rsa_public_key, p, this->getPublicKeyLen());
	}
	EVP_PKEY* getRsaPublicKey() { return this->_rsa_public_key; }

private:

	void generateRsaPrivateKey(EVP_PKEY*);
	void generateRsaPublicKey(EVP_PKEY*);
	void writePublicKey(unsigned char*, int*);
	void writePrivateKey(unsigned char*, int*);

public:

	void generateRsaKeyPair();
	void readPublicKeyFromFile(unsigned char*);
	void readPrivateKeyFromFile(unsigned char*);
	EVP_PKEY* readPublicKey();
	EVP_PKEY* readPrivateKey();
	void encryptRsa();
	void decryptRsa();

	~Asymmetric() {
		free(_rsa_key_pair);
		free(_rsa_private_key);
		free(_rsa_public_key);
	}
};

#endif //_ASYMMETRIC_HPP
