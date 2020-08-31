// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>































// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <openssl/bn.h>

#include <stdexcept>
#include <vector>

#include <stdint.h>

/** Errors thrown by the bignum class */
class bignum_error : public std::runtime_error
{
public:
    explicit bignum_error(const std::string& str) : std::runtime_error(str) {}
};


/** RAII encapsulated BN_CTX (OpenSSL bignum context) */
class CAutoBN_CTX
{
protected:
    BN_CTX* pctx;
    BN_CTX* operator=(BN_CTX* pnew) { return pctx = pnew; }

public:
    CAutoBN_CTX()
    {
        pctx = BN_CTX_new();
        if (pctx == NULL)
            throw bignum_error("CAutoBN_CTX : BN_CTX_new() returned NULL");
    }

    ~CAutoBN_CTX()
    {
        if (pctx != NULL)
            BN_CTX_free(pctx);
    }

    operator BN_CTX*() { return pctx; }
    BN_CTX& operator*() { return *pctx; }
    BN_CTX** operator&() { return &pctx; }
    bool operator!() { return (pctx == NULL); }
};


/** C++ wrapper for BIGNUM (OpenSSL bignum) */
class CBigNum
{
public:
    BIGNUM* pbn;

    CBigNum()
    {
        this->pbn = BN_new();
    }

    CBigNum(const CBigNum& b)
    {
        this->pbn = BN_new();
        if (!BN_copy(this->pbn, b.pbn))
        {
            BN_clear_free(this->pbn);
            throw bignum_error("CBigNum::CBigNum(const CBigNum&) : BN_copy failed");
        }
    }

    CBigNum& operator=(const CBigNum& b)
    {
        if (!BN_copy(this->pbn, b.pbn))
            throw bignum_error("CBigNum::operator= : BN_copy failed");
        return (*this);
    }

    ~CBigNum()
    {
        BN_clear_free(this->pbn);
    }

    //CBigNum(char n) is not portable.  Use 'signed char' or 'unsigned char'.
    CBigNum(signed char n)        { this->pbn = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(short n)              { this->pbn = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(int n)                { this->pbn = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(long n)               { this->pbn = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(long long n)          { this->pbn = BN_new(); setint64(n); }
    CBigNum(unsigned char n)      { this->pbn = BN_new(); setulong(n); }
    CBigNum(unsigned short n)     { this->pbn = BN_new(); setulong(n); }
    CBigNum(unsigned int n)       { this->pbn = BN_new(); setulong(n); }
    CBigNum(unsigned long n)      { this->pbn = BN_new(); setulong(n); }
    CBigNum(unsigned long long n) { this->pbn = BN_new(); setuint64(n); }
    explicit CBigNum(uint256 n)   { this->pbn = BN_new(); setuint256(n); }

    explicit CBigNum(const std::vector<unsigned char>& vch)
    {
        this->pbn = BN_new();
        setvch(vch);
    }

    /** Generates a cryptographically secure random number between zero and range exclusive
    * i.e. 0 < returned number < range
    * @param range The upper bound on the number.
    * @return
    */
    static CBigNum randBignum(const CBigNum& range)
    {
        CBigNum ret;
        if(!BN_rand_range(ret.pbn, range.pbn)){
            throw bignum_error("CBigNum:rand element : BN_rand_range failed");
        }
        return ret;
    }

    /** Generates a cryptographically secure random k-bit number
    * @param k The bit length of the number.
    * @return
    */
    static CBigNum RandKBitBigum(const uint32_t k)
    {
        CBigNum ret;
        if(!BN_rand(ret.pbn, k, -1, 0))
        {
            throw bignum_error("CBigNum:rand element : BN_rand failed");
        }
        return ret;
    }

    /**Returns the size in bits of the underlying bignum.
     *
     * @return the size
     */
    int bitSize() const{
        return BN_num_bits(this->pbn);
    }


    void setulong(unsigned long n)
    {
        if (!BN_set_word(this->pbn, n))
            throw bignum_error("CBigNum conversion from unsigned long : BN_set_word failed");
    }

    unsigned long getulong() const
    {
        return BN_get_word(this->pbn);
    }

    unsigned int getuint() const
    {
        return BN_get_word(this->pbn);
    }

    int getint() const
    {
        unsigned long n = BN_get_word(this->pbn);
        if (!BN_is_negative(this->pbn))
            return (n > (unsigned long)std::numeric_limits<int>::max() ? std::numeric_limits<int>::max() : n);
        else
            return (n > (unsigned long)std::numeric_limits<int>::max() ? std::numeric_limits<int>::min() : -(int)n);
    }

    void setint64(int64_t sn)
    {
        unsigned char pch[sizeof(sn) + 6];
        unsigned char* p = pch + 4;
        bool fNegative;
        uint64_t n;

        if (sn < (int64_t)0)
        {
            // Since the minimum signed integer cannot be represented as positive so long as its
            // type is signed, and it's not well-defined what happens if you make it unsigned
            // before negating it, we instead increment the negative integer by 1, convert it,
            // then increment the (now positive) unsigned integer by 1 to compensate
            n = -(sn + 1);
            ++n;
            fNegative = true;
        } else
        {
            n = sn;
            fNegative = false;
        }

        bool fLeadingZeroes = true;
        for (int i = 0; i < 8; i++)
        {
            unsigned char c = (n >> 56) & 0xff;
            n <<= 8;
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = (fNegative ? 0x80 : 0);
                else if (fNegative)
                    c |= 0x80;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        unsigned int nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, p - pch, this->pbn);
    }

    uint64_t getuint64()
    {
        unsigned int nSize = BN_bn2mpi(this->pbn, NULL);
        if (nSize < 4)
            return 0;
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(this->pbn, &vch[0]);
        if (vch.size() > 4)
            vch[4] &= 0x7f;
        uint64_t n = 0;
        for (unsigned int i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
            ((unsigned char*)&n)[i] = vch[j];
        return n;
    }

    void setuint64(uint64_t n)
    {
        unsigned char pch[sizeof(n) + 6];
        unsigned char* p = pch + 4;
        bool fLeadingZeroes = true;
        for (int i = 0; i < 8; i++)
        {
            unsigned char c = (n >> 56) & 0xff;
            n <<= 8;
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        unsigned int nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, p - pch, this->pbn);
    }

    void setuint256(uint256 n)
    {
        unsigned char pch[sizeof(n) + 6];
        unsigned char* p = pch + 4;
        bool fLeadingZeroes = true;
        unsigned char* pbegin = (unsigned char*)&n;
        unsigned char* psrc = pbegin + sizeof(n);
        while (psrc != pbegin)
        {
            unsigned char c = *(--psrc);
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        unsigned int nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize >> 0) & 0xff;
        BN_mpi2bn(pch, p - pch, this->pbn);
    }

    uint256 getuint256() const
    {
        unsigned int nSize = BN_bn2mpi(this->pbn, NULL);
        if (nSize < 4)
            return uint256();
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(this->pbn, &vch[0]);
        if (vch.size() > 4)
            vch[4] &= 0x7f;
        uint256 n{};
        for (unsigned int i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
            ((unsigned char*)&n)[i] = vch[j];
        return n;
    }

    void setvch(const std::vector<unsigned char>& vch)
    {
        std::vector<unsigned char> vch2(vch.size() + 4);
        unsigned int nSize = vch.size();
        // BIGNUM's byte stream format expects 4 bytes of
        // big endian size data info at the front
        vch2[0] = (nSize >> 24) & 0xff;
        vch2[1] = (nSize >> 16) & 0xff;
        vch2[2] = (nSize >> 8) & 0xff;
        vch2[3] = (nSize >> 0) & 0xff;
        // swap data to big endian
        reverse_copy(vch.begin(), vch.end(), vch2.begin() + 4);
        BN_mpi2bn(&vch2[0], vch2.size(), this->pbn);
    }

    std::vector<unsigned char> getvch() const
    {
        unsigned int nSize = BN_bn2mpi(this->pbn, NULL);
        if (nSize <= 4)
            return std::vector<unsigned char>();
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(this->pbn, &vch[0]);
        vch.erase(vch.begin(), vch.begin() + 4);
        reverse(vch.begin(), vch.end());
        return vch;
    }

    CBigNum& SetCompact(unsigned int nCompact)
    {
        unsigned int nSize = nCompact >> 24;
        std::vector<unsigned char> vch(4 + nSize);
        vch[3] = nSize;
        if (nSize >= 1) vch[4] = (nCompact >> 16) & 0xff;
        if (nSize >= 2) vch[5] = (nCompact >> 8) & 0xff;
        if (nSize >= 3) vch[6] = (nCompact >> 0) & 0xff;
        BN_mpi2bn(&vch[0], vch.size(), this->pbn);
        return *this;
    }

    unsigned int GetCompact() const
    {
        unsigned int nSize = BN_bn2mpi(this->pbn, NULL);
        std::vector<unsigned char> vch(nSize);
        nSize -= 4;
        BN_bn2mpi(this->pbn, &vch[0]);
        unsigned int nCompact = nSize << 24;
        if (nSize >= 1) nCompact |= (vch[4] << 16);
        if (nSize >= 2) nCompact |= (vch[5] << 8);
        if (nSize >= 3) nCompact |= (vch[6] << 0);
        return nCompact;
    }

    void SetHex(const std::string& str)
    {
        // skip 0x
        const char* psz = str.c_str();
        while (isspace(*psz))
            psz++;
        bool fNegative = false;
        if (*psz == '-')
        {
            fNegative = true;
            psz++;
        }
        if (psz[0] == '0' && tolower(psz[1]) == 'x')
            psz += 2;
        while (isspace(*psz))
            psz++;

        // hex string to bignum
        static const signed char phexdigit[256] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0 };
        *this = 0;
        while (isxdigit(*psz))
        {
            *this <<= 4;
            int n = phexdigit[(unsigned char)*psz++];
            *this += n;
        }
        if (fNegative)
            *this = 0 - *this;
    }

    std::string ToString(int nBase=10) const
    {
        CAutoBN_CTX pctx;
        CBigNum bnBase = nBase;
        CBigNum bn0 = 0;
        std::string str;
        CBigNum bn = *this;
        BN_set_negative(bn.pbn, false);
        CBigNum dv;
        CBigNum rem;
        if (BN_cmp(bn.pbn, bn0.pbn) == 0)
            return "0";
        while (BN_cmp(bn.pbn, bn0.pbn) > 0)
        {
            if (!BN_div(dv.pbn, rem.pbn, bn.pbn, bnBase.pbn, pctx))
                throw bignum_error("CBigNum::ToString() : BN_div failed");
            bn = dv;
            unsigned int c = rem.getulong();
            str += "0123456789abcdef"[c];
        }

        if (BN_is_negative(this->pbn))
            str += "-";
        reverse(str.begin(), str.end());
        return str;
    }

    std::string GetHex() const
    {
        return ToString(16);
    }

    template<typename Stream>
    void Serialize(Stream& s, int nType=0, int nVersion=PROTOCOL_VERSION) const
    {
        ::Serialize(s, getvch(), nType, nVersion);
    }

    template<typename Stream>
    void Unserialize(Stream& s, int nType=0, int nVersion=PROTOCOL_VERSION)
    {
        std::vector<unsigned char> vch;
        ::Unserialize(s, vch, nType, nVersion);
        setvch(vch);
    }

    /**
    * exponentiation with an int. this^e
    * @param e the exponent as an int
    * @return
    */
    CBigNum pow(const int e) const {
        return this->pow(CBigNum(e));
    }

    /**
     * exponentiation this^e
     * @param e the exponent
     * @return
     */
    CBigNum pow(const CBigNum& e) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_exp(ret.pbn, this->pbn, e.pbn, pctx))
            throw bignum_error("CBigNum::pow : BN_exp failed");
        return ret;
    }

    /**
     * modular multiplication: (this * b) mod m
     * @param b operand
     * @param m modulus
     */
    CBigNum mul_mod(const CBigNum& b, const CBigNum& m) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_mod_mul(ret.pbn, this->pbn, b.pbn, m.pbn, pctx))
            throw bignum_error("CBigNum::mul_mod : BN_mod_mul failed");

        return ret;
    }

    /**
     * modular exponentiation: this^e mod n
     * @param e exponent
     * @param m modulus
     */
    CBigNum pow_mod(const CBigNum& e, const CBigNum& m) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (e < 0) {
            // g^-x = (g^-1)^x
            CBigNum inv = this->inverse(m);
            CBigNum posE = e * -1;
            if (!BN_mod_exp(ret.pbn, inv.pbn, posE.pbn, m.pbn, pctx))
                throw bignum_error("CBigNum::pow_mod: BN_mod_exp failed on negative exponent");
        } else
        if (!BN_mod_exp(ret.pbn, this->pbn, e.pbn, m.pbn, pctx))
            throw bignum_error("CBigNum::pow_mod : BN_mod_exp failed");

        return ret;
    }

    /**
    * Calculates the inverse of this element mod m.
    * i.e. i such this*i = 1 mod m
    * @param m the modu
    * @return the inverse
    */
    CBigNum inverse(const CBigNum& m) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_mod_inverse(ret.pbn, this->pbn, m.pbn, pctx))
            throw bignum_error("CBigNum::inverse*= :BN_mod_inverse");
        return ret;
    }

    /**
     * Generates a random (safe) prime of numBits bits
     * @param numBits the number of bits
     * @param safe true for a safe prime
     * @return the prime
     */
    static CBigNum generatePrime(const unsigned int numBits, bool safe = false)
    {
        CBigNum ret;
        if(!BN_generate_prime_ex(ret.pbn, numBits, (safe == true), NULL, NULL, NULL))
            throw bignum_error("CBigNum::generatePrime*= :BN_generate_prime_ex");
        return ret;
    }

    /**
     * Calculates the greatest common divisor (GCD) of two numbers.
     * @param m the second element
     * @return the GCD
     */
    CBigNum gcd( const CBigNum& b) const{
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_gcd(ret.pbn, this->pbn, b.pbn, pctx))
            throw bignum_error("CBigNum::gcd*= :BN_gcd");
        return ret;
    }

    /**
    * Miller-Rabin primality test on this element
    * @param checks: optional, the number of Miller-Rabin tests to run
    * default causes error rate of 2^-80.
    * @return true if prime
    */
    bool isPrime(const int checks=BN_prime_checks) const {
        CAutoBN_CTX pctx;
        int ret = BN_is_prime_ex(this->pbn, checks, pctx, NULL);
        if (ret < 0) {
            throw bignum_error("CBigNum::isPrime :BN_is_prime");
        }
        return ret;
    }

    bool isOne() const {
        return BN_is_one(this->pbn);
    }


    bool operator!() const
    {
        return BN_is_zero(this->pbn);
    }

    CBigNum& operator+=(const CBigNum& b)
    {
        if (!BN_add(this->pbn, this->pbn, b.pbn))
            throw bignum_error("CBigNum::operator+= : BN_add failed");
        return *this;
    }

    CBigNum& operator-=(const CBigNum& b)
    {
        *this = *this - b;
        return *this;
    }

    CBigNum& operator*=(const CBigNum& b)
    {
        CAutoBN_CTX pctx;
        if (!BN_mul(this->pbn, this->pbn, b.pbn, pctx))
            throw bignum_error("CBigNum::operator*= : BN_mul failed");
        return *this;
    }

    CBigNum& operator/=(const CBigNum& b)
    {
        *this = *this / b;
        return *this;
    }

    CBigNum& operator%=(const CBigNum& b)
    {
        *this = *this % b;
        return *this;
    }

    CBigNum& operator<<=(unsigned int shift)
    {
        if (!BN_lshift(this->pbn, this->pbn, shift))
            throw bignum_error("CBigNum:operator<<= : BN_lshift failed");
        return *this;
    }

    CBigNum& operator>>=(unsigned int shift)
    {
        // Note: BN_rshift segfaults on 64-bit if 2^shift is greater than the number
        //   if built on ubuntu 9.04 or 9.10, probably depends on version of OpenSSL
        CBigNum a = 1;
        a <<= shift;
        if (BN_cmp(a.pbn, this->pbn) > 0)
        {
            *this = 0;
            return *this;
        }

        if (!BN_rshift(this->pbn, this->pbn, shift))
            throw bignum_error("CBigNum:operator>>= : BN_rshift failed");
        return *this;
    }


    CBigNum& operator++()
    {
        // prefix operator
        if (!BN_add(this->pbn, this->pbn, BN_value_one()))
            throw bignum_error("CBigNum::operator++ : BN_add failed");
        return *this;
    }

    const CBigNum operator++(int)
    {
        // postfix operator
        const CBigNum ret = *this;
        ++(*this);
        return ret;
    }

    CBigNum& operator--()
    {
        // prefix operator
        CBigNum r;
        if (!BN_sub(r.pbn, this->pbn, BN_value_one()))
            throw bignum_error("CBigNum::operator-- : BN_sub failed");
        *this = r;
        return *this;
    }

    const CBigNum operator--(int)
    {
        // postfix operator
        const CBigNum ret = *this;
        --(*this);
        return ret;
    }


    friend inline const CBigNum operator-(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator/(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator%(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator*(const CBigNum& a, const CBigNum& b);
    friend inline bool operator<(const CBigNum& a, const CBigNum& b);
};



inline const CBigNum operator+(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;
    if (!BN_add(r.pbn, a.pbn, b.pbn))
        throw bignum_error("CBigNum::operator+ : BN_add failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;
    if (!BN_sub(r.pbn, a.pbn, b.pbn))
        throw bignum_error("CBigNum::operator- : BN_sub failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a)
{
    CBigNum r(a);
    BN_set_negative(r.pbn, !BN_is_negative(r.pbn));
    return r;
}

inline const CBigNum operator*(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_mul(r.pbn, a.pbn, b.pbn, pctx))
        throw bignum_error("CBigNum::operator* : BN_mul failed");
    return r;
}

inline const CBigNum operator/(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_div(r.pbn, NULL, a.pbn, b.pbn, pctx))
        throw bignum_error("CBigNum::operator/ : BN_div failed");
    return r;
}

inline const CBigNum operator%(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_nnmod(r.pbn, a.pbn, b.pbn, pctx))
        throw bignum_error("CBigNum::operator% : BN_div failed");
    return r;
}

inline const CBigNum operator<<(const CBigNum& a, unsigned int shift)
{
    CBigNum r;
    if (!BN_lshift(r.pbn, a.pbn, shift))
        throw bignum_error("CBigNum:operator<< : BN_lshift failed");
    return r;
}

inline const CBigNum operator>>(const CBigNum& a, unsigned int shift)
{
    CBigNum r = a;
    r >>= shift;
    return r;
}

inline bool operator==(const CBigNum& a, const CBigNum& b) { return (BN_cmp(a.pbn, b.pbn) == 0); }
inline bool operator!=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(a.pbn, b.pbn) != 0); }
inline bool operator<=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(a.pbn, b.pbn) <= 0); }
inline bool operator>=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(a.pbn, b.pbn) >= 0); }
inline bool operator<(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(a.pbn, b.pbn) < 0); }
inline bool operator>(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(a.pbn, b.pbn) > 0); }

inline std::ostream& operator<<(std::ostream &strm, const CBigNum &b) { return strm << b.ToString(10); }

typedef  CBigNum Bignum;

#endif



#include <iostream>
#include <algorithm>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>

#include <openssl/sha.h>
#include <openssl/ripemd.h>

namespace
{

    using UInt64 = uint64_t;
    using Int64 = int64_t;
    using UInt32 = uint32_t;
    using Int32 = int32_t;
    using UInt16 = uint16_t;
    using Int16 = int16_t;
    using UInt8 = uint8_t;
    using Int8 = int8_t;

    using Byte = UInt8;
    using RawByteArray = Byte*;
    using ByteArray = std::vector<Byte>;

    template<typename ContainerT>
    class ReverseIterator
    {
    public:
        ReverseIterator(ContainerT& iContainer)
        : m_container{ iContainer }
        {

        }

        typename ContainerT::reverse_iterator begin()
        {
            return m_container.rbegin();
        }

        typename ContainerT::reverse_iterator end()
        {
            return m_container.rend();
        }

    private:
        ContainerT& m_container;
    };

    template<typename ContainerT>
    ReverseIterator<ContainerT> Reverse(ContainerT& iContainer)
    {
        return ReverseIterator<ContainerT>(iContainer);
    }

    template<typename OutputItrT>
    class HexOstreamIterator : public std::iterator<std::output_iterator_tag , void , void , void , void>
    {
    public:
        HexOstreamIterator(OutputItrT iOutItr);

        ~HexOstreamIterator();

        HexOstreamIterator<OutputItrT>& operator=(char iCharacter);

        HexOstreamIterator<OutputItrT>& operator*();

        HexOstreamIterator<OutputItrT>& operator++();

        HexOstreamIterator<OutputItrT>& operator++(int);

    private:
        UInt32 m_number;
        UInt8 m_digitCount;
        OutputItrT m_outItr;
    };

    template<typename OutputItrT>
    HexOstreamIterator<OutputItrT> HexIterator(OutputItrT iOutItr)
    {
        return HexOstreamIterator<OutputItrT>(iOutItr);
    }

    ByteArray sha256(const ByteArray& iData)
    {
        ByteArray oResult(32);
        SHA256(iData.data() , iData.size() , oResult.data());

        return oResult;
    }

    namespace utils
    {
        namespace converters
        {
            UInt8 Char2Int(char iCharacter)
            {
                static const std::string C_HEX_CHARS{ "0123456789abcdef" };

                auto oResult = C_HEX_CHARS.find(std::tolower(iCharacter));
                if (std::string::npos == oResult)
                {
                    throw std::runtime_error{ "Invalid hex digit " + std::string{ 1 , iCharacter } };
                }

                return static_cast<UInt8>(oResult);
            }

            ByteArray Hex2ByteArray(const std::string& iHex)
            {
                if (0 != iHex.length() % 2)
                {
                    throw std::runtime_error{ "Invalid hex number " + iHex };
                }

                ByteArray oResult;
                std::copy(iHex.begin() , iHex.end() , HexIterator(std::back_inserter(oResult)));

                return oResult;
            }

            std::string ByteArray2Hex(const ByteArray& iData)
            {
                std::stringstream stream;

                stream << std::setfill('0');
                for (auto itr : iData)
                {
                    stream << std::hex << std::setw(2) << static_cast<int>(itr);
                }

                return stream.str();
            }

            std::string RawByteArray2Hex(RawByteArray iData , UInt32 iSize)
            {
                std::stringstream stream;

                stream << std::setfill('0');
                for (auto itr = 0; itr < iSize; ++itr)
                {
                    stream << std::hex << std::setw(2) << static_cast<int>(iData[itr]);
                }

                return stream.str();
            }
        }
    }

    template<typename OutputItrT>
    HexOstreamIterator<OutputItrT>::HexOstreamIterator(OutputItrT iOutItr)
    : m_number{ 0 } ,
      m_digitCount{ 0 } ,
      m_outItr(iOutItr)
    {

    }

    template<typename OutputItrT>
    HexOstreamIterator<OutputItrT>::~HexOstreamIterator()
    {

    }

    template<typename OutputItrT>
    HexOstreamIterator<OutputItrT>& HexOstreamIterator<OutputItrT>::operator=(char iCharacter)
    {
        m_number = (m_number << 4) | utils::converters::Char2Int(iCharacter);
        ++m_digitCount;

        if (2 == m_digitCount)
        {
            *m_outItr++ = m_number;

            m_number = 0;
            m_digitCount = 0;
        }

        return *this;
    }

    template<typename OutputItrT>
    HexOstreamIterator<OutputItrT>& HexOstreamIterator<OutputItrT>::operator*()
    {
        return *this;
    }

    template<typename OutputItrT>
    HexOstreamIterator<OutputItrT>& HexOstreamIterator<OutputItrT>::operator++()
    {
        return *this;
    }

    template<typename OutputItrT>
    HexOstreamIterator<OutputItrT>& HexOstreamIterator<OutputItrT>::operator++(int)
    {
        return *this;
    }

    std::string ToString(const std::vector<unsigned char>& iParam)
    {
        return utils::converters::ByteArray2Hex(iParam);
    }

    std::string ToString(const CBigNum& iParam)
    {
        iParam.getvch();
        ByteArray byteArray((BN_num_bytes(iParam.pbn)));
        BN_bn2bin(iParam.pbn, &(*byteArray.begin()));

        return utils::converters::ByteArray2Hex(byteArray) + ", getvch:=" + utils::converters::ByteArray2Hex(iParam.getvch()) + ", gethex=" + iParam.GetHex();
    }


}

































unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    // TokenPay: this function should not be called
    //
    assert(false);

    assert(pindexLast != nullptr);

    // TokenPay: powLimit should not be used directly
    //
    unsigned int nProofOfWorkLimit; // = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        // TokenPay: allow
        //
        // if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int GetTargetSpacing(const Consensus::Params& params, int nHeight) { return params.IsProtocolV2(nHeight) ? 64 : 60; }

const CBlockIndex*  GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;

    return pindex;
}

namespace
{
    const int64_t C_TARGET_TIMESPAN = 24 * 60 * 60;  // 24 hours
}

unsigned int GetNextWorkRequiredTPAY(const CBlockIndex* pindexLast, bool fProofOfStake, const Consensus::Params& params)
{
    if (nullptr == pindexLast || pindexLast->nHeight < 2)
    {
        return UintToArith256(params.powLimit).GetCompact();
    }

    const auto C_PREV_INDEX{GetLastBlockIndex(pindexLast, fProofOfStake)};
    assert(nullptr != C_PREV_INDEX);

    auto proofLimit{&params.powLimit};
    if (fProofOfStake)
    {
        if (params.IsProtocolV2(pindexLast->nHeight))
        {
            proofLimit = &params.posV2Limit;
        }
        else
        {
            proofLimit = &params.posLimit;
        }
    }

    if (nullptr == C_PREV_INDEX->pprev)
    {
        return UintToArith256(*proofLimit).GetCompact();
    }

    const auto C_PREV_PREV_INDEX{GetLastBlockIndex(C_PREV_INDEX->pprev, fProofOfStake)};
    assert(nullptr != C_PREV_PREV_INDEX);

    if (nullptr == C_PREV_PREV_INDEX->pprev)
    {
        return UintToArith256(*proofLimit).GetCompact();
    }

    int64_t nTargetSpacing = GetTargetSpacing(params, pindexLast->nHeight);
    int64_t nActualSpacing = C_PREV_INDEX->GetBlockTime() - C_PREV_PREV_INDEX->GetBlockTime();
    if (nActualSpacing < 0)
        nActualSpacing = nTargetSpacing;

    if (params.IsProtocolV3(pindexLast->nHeight))
    {
        if (nActualSpacing > nTargetSpacing * 10)
            nActualSpacing = nTargetSpacing * 10;
    }

    CBigNum diffInArith{};
    diffInArith.SetCompact(C_PREV_INDEX->nBits);

    int64_t nInterval = C_TARGET_TIMESPAN / nTargetSpacing;

    diffInArith *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);

    diffInArith /= ((nInterval + 1) * nTargetSpacing);

    if (diffInArith <= 0 || diffInArith > CBigNum(*proofLimit))
        diffInArith = CBigNum(*proofLimit);

    return diffInArith.GetCompact();
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    // TokenPay: this function should not be called
    //
    assert(false);

    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget

    // TokenPay: powLimit should not be used directly
    //
    const arith_uint256 bnPowLimit; // = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
    {
        return false;
    }

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
