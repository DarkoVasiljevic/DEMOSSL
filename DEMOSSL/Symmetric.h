#pragma once

#define _CRT_SECURE_NO_WARNINGS

#ifndef _SYMMETRIC_HPP
#define _SYMMETRIC_HPP

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#define KEY_LEN (8)
#define IV_LEN (8)
#define BUFFER (2048)
#define FNAME (__func__)

class Symmetric {

private:
	const char* _type = NULL;
	const char* _mode = NULL;
	unsigned char* _in_text = NULL;
	int _in_len = 0;
	unsigned char _out_text[BUFFER];
	int _out_len = 0;
	unsigned char _key[BUFFER];
	int _key_len = KEY_LEN;
	int _enter_key = 0;
	unsigned char _iv[BUFFER];
	int _iv_len = IV_LEN;
	int _padding = 0;

public:
	Symmetric() {}

	Symmetric(const char* type, const char* mode, int padding, unsigned char* in_text)
		: _type(type), _mode(mode), _padding(padding), _in_text(in_text)
	{}

	void setType(const char* p) { this->_type = p; }
	const char* getType() { return this->_type; }

	void setMode(const char* p) { this->_mode = p; }
	const char* getMode() { return this->_mode; }

	void setInText(unsigned char* p) { this->_in_text = p; }
	unsigned char* getInText() { return this->_in_text; }

	void setInLen(int p) { this->_in_len = p; }
	int getInLen() { return this->_in_len; }

	void setOutText(unsigned char* p) { memcpy(this->_out_text, p, this->getOutLen()); }
	unsigned char* getOutText() { return this->_out_text; }

	void setOutLen(int p) { this->_out_len = p; }
	int getOutLen() { return this->_out_len; }

	void setKey(unsigned char* p) { memcpy(this->_key, p, this->getKeyLen()); }
	unsigned char* getKey() { return this->_key; }
	void restartKey() { memcpy(this->_key, "0", 16); }

	void setKeyLen(int p) { this->_key_len = p; }
	int getKeyLen() { return this->_key_len; }

	void setIv(unsigned char* p) { memcpy(this->_iv, p, this->getIvLen()); }
	unsigned char* getIv() { return this->_iv; }

	void setIvLen(int p) { this->_iv_len = p; }
	int getIvLen() { return this->_iv_len; }

	void setPadding(int p) { this->_padding = p; }
	int getPadding() { return this->_padding; }

	void setEnterKey(int p) { this->_enter_key = p; }
	int getEnterKey() { return this->_enter_key; }

	void setEnterKeyLen(int p) { this->_key_len = p; }
	int getEnterKeyLen() { return this->_key_len; }

private:

	void getCipher(const EVP_CIPHER**);
	void generateRandom(unsigned char*, const int);
	void generateKey(int*);
	void generateIv(int*);

public:

	void encrypt();
	void  decrypt();

	~Symmetric() {}
};

#endif //_SYMMETRIC_HPP
