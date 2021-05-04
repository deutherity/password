#include "hex.hpp"

hexByte hex(const unsigned char x) {
    hexByte res;
    unsigned char first(x / 16);
    unsigned char last(x % 16);
    res.h = static_cast<char>(48 + first + (first > 9) * 7);
    res.t = static_cast<char>(48 + last + (last > 9) * 7);
    return res;
}

unsigned char unhex(const char *in) {
    return 16 * ((in[0] - 48) - (in[0] > 64) * 7) +
           ((in[1] - 48) - (in[1] > 64) * 7);
}
