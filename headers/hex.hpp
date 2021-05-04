#pragma once
#include <cstdint>

struct hexByte {
    char h;
    char t;
};

hexByte hex(const unsigned char x);
unsigned char unhex(const char *in);