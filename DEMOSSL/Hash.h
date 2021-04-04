#pragma once

#define _CRT_SECURE_NO_WARNINGS

#ifndef _HASH_HPP
#define _HASH_HPP

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#define BUFFER (2048)

class Hash {

private:
	const char* _type = NULL;
	unsigned char* _in_text = NULL;
	unsigned int _in_len = 0;
	unsigned char _out_text[EVP_MAX_MD_SIZE];
	unsigned int _out_len = 0;

public:
	Hash() {};

	Hash(const char* type, unsigned char* in_text, int in_len)
		: _type(type), _in_text(in_text), _in_len(in_len)
	{};

	void setType(const char* p) { this->_type = p; }
	const char* getType() { return this->_type; }

	void setInText(unsigned char* p) { this->_in_text = p; }
	unsigned char* getInText() { return this->_in_text; }

	void setInLen(int p) { this->_in_len = p; }
	unsigned int getInLen() { return this->_in_len; }

	void setOutText(unsigned char* p) { memcpy(this->_out_text, p, this->getOutLen()); }
	unsigned char* getOutText() { return this->_out_text; }

	void setOutLen(int p) { this->_out_len = p; }
	int getOutLen() { return this->_out_len; }

private:

	void getMd(const EVP_MD**);

public:

	void hashText();

	~Hash() {};
};

#endif //_HASH_HPP