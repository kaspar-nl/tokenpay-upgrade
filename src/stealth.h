/**
 * Copyright (c) 2014 ShadowCoin
 * Copyright (c) 2019 TokenPay
 *
 * Distributed under the MIT/X11 software license,
 * see the accompanying file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef STEALTH_H
#define STEALTH_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdlib.h> 
#include <stdio.h> 
#include <vector>
#include <inttypes.h>
#include <util.h>
#include <serialize.h>
#include <key.h>
#include <hash.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

extern bool fDebug;
extern bool fDebugRingSig;

enum ringsigType
{
    RING_SIG_1 = 1,
    RING_SIG_2,
};

const std::size_t EC_SECRET_SIZE = 32;
const std::size_t EC_COMPRESSED_SIZE = 33;
const std::size_t EC_UNCOMPRESSED_SIZE = 65;

using data_chunk = std::vector<uint8_t>;
using ec_point = data_chunk;

struct ec_secret
{
    uint8_t e[EC_SECRET_SIZE];

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(e);
    }
};

const uint32_t MIN_ANON_OUT_SIZE = 1 + 1 + 1 + 33 + 1 + 33; // OP_RETURN ANON_TOKEN lenPk pkTo lenR R [lenEnarr enarr]
const uint32_t MIN_ANON_IN_SIZE = 2 + (33 + 32 + 32); // 2-byte marker (cpubkey + sigc + sigr)
const uint32_t MAX_ANON_NARRATION_SIZE = 48;
const uint32_t MIN_RING_SIZE = 1;
const uint32_t MAX_RING_SIZE_OLD = 200;
const uint32_t MAX_RING_SIZE = 32;

const int MIN_ANON_SPEND_DEPTH = 10;
const int ANON_TXN_VERSION = 1000;

const uint32_t MAX_STEALTH_NARRATION_SIZE = 48;

using stealth_bitfield = uint32_t;

struct stealth_prefix
{
    uint8_t number_bits;
    stealth_bitfield bitfield;
};

const uint256 MAX_SECRET = uint256S("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
const uint256 MIN_SECRET = uint256S("3E80"); // increase? min valid key is 1. (3E80 = 16000 in decimal)

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

uint32_t BitcoinChecksum(uint8_t* p, uint32_t nBytes);
bool VerifyChecksum(const std::vector<uint8_t>& data);
void AppendChecksum(std::vector<uint8_t>& data);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CStealthAddress
{
public:
    CStealthAddress()
    {
        options = 0;
    };
    
    uint8_t options;
    ec_point scan_pubkey;
    ec_point spend_pubkey;
    //std::vector<ec_point> spend_pubkeys;
    size_t number_signatures;
    stealth_prefix prefix;
    
    mutable std::string label;
    data_chunk scan_secret;
    data_chunk spend_secret;
    
    bool SetEncoded(const std::string& encodedAddress);
    std::string Encoded() const;
    
    int SetScanPubKey(CPubKey pk);
    
    
    bool operator<(const CStealthAddress& y) const
    {
        return memcmp(&scan_pubkey[0], &y.scan_pubkey[0], EC_COMPRESSED_SIZE) < 0;
    };
    
    bool operator==(const CStealthAddress& y) const
    {
        return memcmp(&scan_pubkey[0], &y.scan_pubkey[0], EC_COMPRESSED_SIZE) == 0;
    };

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(options);
        READWRITE(scan_pubkey);
        READWRITE(spend_pubkey);
        READWRITE(label);
        READWRITE(scan_secret);
        READWRITE(spend_secret);
    }
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int GenerateRandomSecret(ec_secret& out);
int SecretToPublicKey(const ec_secret& secret, ec_point& out);
int StealthSecret(ec_secret& secret, ec_point& pubkey, const ec_point& pkSpend, ec_secret& sharedSOut, ec_point& pkOut);
int StealthSecretSpend(ec_secret& scanSecret, ec_point& ephemPubkey, ec_secret& spendSecret, ec_secret& secretOut);
int StealthSharedToSecretSpend(const ec_secret& sharedS, const ec_secret& spendSecret, ec_secret& secretOut);
int StealthSharedToPublicKey(const ec_point& pkSpend, const ec_secret &sharedS, ec_point &pkOut);
bool IsStealthAddress(const std::string& encodedAddress);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif  // STEALTH_H
