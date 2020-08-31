// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_H
#define BITCOIN_UTIL_H

#include <tinyformat.h>
#include <util/time.h>
#include <cstdint>
#include <vector>
#include <logging.h>
#include <sys/time.h>

void RandAddSeed();
void RandAddSeedPerfmon();

static inline int errorN(int n, const char* format)
{
    LogPrintf(format);
    return n;
}

inline int64_t GetPerformanceCounter()
{
    int64_t nCounter = 0;
#ifdef WIN32
    QueryPerformanceCounter((LARGE_INTEGER*)&nCounter);
#else
    timeval t;
    gettimeofday(&t, NULL);
    nCounter = (int64_t) t.tv_sec * 1000000 + t.tv_usec;
#endif
    return nCounter;
}

#endif
