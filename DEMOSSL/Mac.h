#pragma once

#define _CRT_SECURE_NO_WARNINGS

#ifndef _MAC_HPP
#define _MAC_HPP

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#define BUFFER (2048)
#define KEY_LEN (16)

class Mac {

private:
	const char* _hash_type = NULL;
	const char* _mac_type = NULL;
	unsigned char* _in_text = NULL;
	unsigned int _in_len = 0;
	unsigned char _out_text[BUFFER];
	unsigned int _out_len = 0;
	unsigned char _key[BUFFER];
	int _key_len = KEY_LEN;
	unsigned char _iv[BUFFER];
	int _iv_len = 0;
	int _padding = 0;

public:
	Mac() {};

	Mac(const char* hash_type, const char* mac_type, unsigned char* in_text, int in_len)
		: _hash_type(hash_type), _mac_type(mac_type), _in_text(in_text), _in_len(in_len)
	{};

	void setHashType(const char* p) { this->_hash_type = p; }
	const char* getHashType() { return this->_hash_type; }

	void setMacType(const char* p) { this->_mac_type = p; }
	const char* getMacType() { return this->_mac_type; }

	void setInText(unsigned char* p) { this->_in_text = p; }
	unsigned char* getInText() { return this->_in_text; }

	void setInLen(int p) { this->_in_len = p; }
	unsigned int getInLen() { return this->_in_len; }

	void setOutText(unsigned char* p) { memcpy(this->_out_text, p, this->getOutLen()); }
	unsigned char* getOutText() { return this->_out_text; }

	void setOutLen(int p) { this->_out_len = p; }
	int getOutLen() { return this->_out_len; }

	void setKey(unsigned char* p) { memcpy(this->_key, p, this->getKeyLen()); }
	unsigned char* getKey() { return this->_key; }

	void setKeyLen(int p) { this->_key_len = p; }
	int getKeyLen() { return this->_key_len; }

	void setIv(unsigned char* p) { memcpy(this->_iv, p, this->getIvLen()); }
	unsigned char* getIv() { return this->_iv; }

	void setIvLen(int p) { this->_iv_len = p; }
	int getIvLen() { return this->_iv_len; }

	void setPadding(int p) { this->_padding = p; }
	int getPadding() { return this->_padding; }

private:

	void getMacId(int*);
	void getMd(const EVP_MD**);
	void generateRandom(unsigned char*, const int);
	void generateKey(int*);
	void generateIv(int*);
	EVP_PKEY* generateMacKey();
	void signMac(EVP_PKEY*);

public:

	void generateMac();

	~Mac() {};
};

#endif //_MAC_HPP