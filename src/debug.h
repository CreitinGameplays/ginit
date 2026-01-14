#ifndef DEBUG_H
#define DEBUG_H

#include <iostream>
#include <cstring>
#include <cstdio>

#ifdef DEBUG_MODE
    #define LOG_DEBUG(x) std::cerr << "[DEBUG] " << x << std::endl
    #define LOG_HEX(desc, buf, len) do { \
        printf("[DEBUG] %s: ", desc); \
        for(int i=0; i<len; i++) printf("%02X ", (unsigned char)buf[i]); \
        printf("\n"); \
    } while(0)
#else
    #define LOG_DEBUG(x)
    #define LOG_HEX(desc, buf, len)
#endif

#endif