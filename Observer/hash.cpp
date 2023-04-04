#include "hash.h"

uint32_t adler32(const unsigned char* buf, size_t buf_length)
{
    uint32_t s1 = 1;
    uint32_t s2 = 0;

    while (buf_length--)
    {
        s1 = (s1 + *(buf++)) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    return (s2 << 16) + s1;
}