#pragma once
#include <Windows.h>
#include <stdint.h>

uint32_t adler32(const unsigned char* buf, size_t buf_length);