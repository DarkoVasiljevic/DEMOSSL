#pragma once

#define _CRT_SECURE_NO_WARNINGS

#ifndef _SIGN_HPP
#define _SIGN_HPP

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <stdexcept>

#define BUFFER (2048)
#define EC_KEY_LEN (16)

class Sign {

private:
	unsigned char* _in_text = NULL;
	int _in_len = 0;
	unsigned char _out_text[BUFFER];
	unsigned char _ec_out_text[BUFFER];
	int _out_len = 0;
	int _ec_out_len = 0;
	const char* _mdType = NULL;
	EVP_PKEY* _rsa_private_key = NULL;
	EVP_PKEY* _rsa_public_key = NULL;
	EC_KEY* _ec_key_pair = NULL;
	EC_KEY* _ec_private_key = NULL;
	char* _private_ec_key_path = NULL;
	int _private_ec_key_len = 0;
	EC_KEY* _ec_public_key = NULL;
	char* _public_ec_key_path = NULL;
	int _public_ec_key_len = 0;
	char* _nid = NULL;
	bool _is_rsa_verified = false;
	bool _is_ec_verified = false;

public:
	Sign() {}

	void setMdType(const char* p) { this->_mdType = p; }
	const char* getMdType() { return this->_mdType; }

	void setInText(unsigned char* p) { this->_in_text = p; }
	unsigned char* getInText() { return this->_in_text; }

	void setInLen(int p) { this->_in_len = p; }
	int getInLen() { return this->_in_len; }

	void setOutText(unsigned char* p) { memcpy(this->_out_text, p, this->getOutLen()); }
	unsigned char* getOutText() { return this->_out_text; }

	void setEcOutText(unsigned char* p) { memcpy(this->_ec_out_text, p, this->getEcOutLen()); }
	unsigned char* getEcOutText() { return this->_ec_out_text; }

	void setOutLen(int p) { this->_out_len = p; }
	int getOutLen() { return this->_out_len; }

	void setEcOutLen(int p) { this->_ec_out_len = p; }
	int getEcOutLen() { return this->_ec_out_len; }

	void setPrivateKeyPath(char* p) { this->_private_ec_key_path = p; }
	char* getPrivateKeyPath() { return this->_private_ec_key_path; }

	void setPublicKeyPath(char* p) { this->_public_ec_key_path = p; }
	char* getPublicKeyPath() { return this->_public_ec_key_path; }

	void setRsaPrivateKey(EVP_PKEY* p) { this->_rsa_private_key = p; }
	EVP_PKEY* getRsaPrivateKey() { return this->_rsa_private_key; }

	void setRsaPublicKey(EVP_PKEY* p) { this->_rsa_public_key = p; }
	EVP_PKEY* getRsaPublicKey() { return this->_rsa_public_key; }

	void setRsaVerified(bool p) { this->_is_rsa_verified = p; }
	bool getRsaVerified() { return this->_is_rsa_verified; }

	void setEcVerified(bool p) { this->_is_ec_verified = p; }
	bool getEcVerified() { return this->_is_ec_verified; }

	void setPublicKeyLen(int p) { this->_public_ec_key_len = p; }
	int getPublicKeyLen() { return this->_public_ec_key_len; }

	void setPrivateKeyLen(int p) { this->_private_ec_key_len = p; }
	int getPrivateKeyLen() { return this->_private_ec_key_len; }

	void setCurve(char* p) { this->_nid = p; }
	char* getCurve() { return this->_nid; }

	void setECKeyPair(EC_KEY* p) {

		this->_ec_key_pair = (EC_KEY*)malloc(EC_KEY_LEN);
		memcpy(this->_ec_key_pair, p, EC_KEY_LEN);
	}
	EC_KEY* getECKeyPair() { return this->_ec_key_pair; }

	void setECPrivateKey(EC_KEY* p) {

		this->_ec_private_key = (EC_KEY*)malloc(this->getPrivateKeyLen());
		memcpy(this->_ec_private_key, p, this->getPrivateKeyLen());
	}
	EC_KEY* getECPrivateKey() { return this->_ec_private_key; }

	void setECPublicKey(EC_KEY* p) {

		this->_ec_public_key = (EC_KEY*)malloc(this->getPublicKeyLen());
		memcpy(this->_ec_public_key, p, this->getPublicKeyLen());
	}
	EC_KEY* getECPublicKey() { return this->_ec_public_key; }

private:

	void getMd(const EVP_MD**);
	int getNid();
	void generateECPublicKey(EC_KEY*);
	void generateECPrivateKey(EC_KEY*);
	void writePublicKey(EC_KEY*);
	void writePrivateKey(EC_KEY*);
	EC_KEY* readPrivateKey();
	EC_KEY* readPublicKey();

public:

	void generateECKeys();
	void readPublicKeyFromFile(unsigned char*, int*);
	void readPrivateKeyFromFile(unsigned char*, int*);
	void rsaSign();
	void rsaVerify();
	void ecSign();
	void ecVerify();

	~Sign() {

		free(_ec_key_pair);
		free(_ec_private_key);
		free(_ec_public_key);
	}
};

#endif //_SIGN_HPP
