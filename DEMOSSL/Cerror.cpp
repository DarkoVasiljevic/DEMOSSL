#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <string>

typedef struct {
	int ret_value = 0;
	const char* c_name = NULL;
	const char* f_name = NULL;
}Error;

class Cerror {

private:
	Error _e;

public:
	Cerror(Error e): _e(e) {}

	~Cerror() {}
};