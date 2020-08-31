/**
 * Copyright (c) 2019 TokenPay
 *
 * Distributed under the MIT/X11 software license,
 * see the accompanying file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef ANONYMOUS_H
#define ANONYMOUS_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <cstdint>
#include <serialize.h>
#include <stealth.h>
#include <primitives/transaction.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class uint256;
class CBlockTreeDB;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Stored in txdb, key is keyimage
 */
class CKeyImageSpent
{
public:
    CKeyImageSpent()
    : txnHash{},
      inputNo{},
      nValue{}
    {

    }

    CKeyImageSpent(const uint256& txnHash_, uint32_t inputNo_, int64_t nValue_)
    {
        txnHash = txnHash_;
        inputNo = inputNo_;
        nValue  = nValue_;
    }

    uint256 txnHash;    // hash of spending transaction
    uint32_t inputNo;   // keyimage is for inputNo of txnHash
    int64_t nValue;     // reporting only

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(txnHash);
        READWRITE(inputNo);
        READWRITE(nValue);
    }
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Stored in txdb, key is pubkey
 */
class CAnonOutput
{
public:
    CAnonOutput()
    : outpoint{},
      nValue{},
      nBlockHeight{},
      nCompromised{}
    {

    }

    CAnonOutput(const COutPoint& outpoint_, int64_t nValue_, int nBlockHeight_, uint8_t nCompromised_)
    : outpoint{outpoint_},
      nValue{nValue_},
      nBlockHeight{nBlockHeight_},
      nCompromised{nCompromised_}
    {

    }

    COutPoint outpoint;
    int64_t nValue;         // rather store 2 bytes, digit + power 10 ?
    int nBlockHeight;
    uint8_t nCompromised;   // TODO: mark if output can be identified (spent with ringsig 1)

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(outpoint);
        READWRITE(nValue);
        READWRITE(nBlockHeight);
        READWRITE(nCompromised);
    }
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Used to get secret for keys created by stealth transaction with wallet locked
 */
class CStealthKeyMetadata
{
public:
    CStealthKeyMetadata()
    : r_pkEphem{},
      r_pkScan{}
    {

    }

    CStealthKeyMetadata(CPubKey pkEphem_, CPubKey pkScan_)
    : r_pkEphem{pkEphem_},
      r_pkScan{pkScan_}
    {

    }

    CPubKey r_pkEphem;
    CPubKey r_pkScan;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(r_pkEphem);
        READWRITE(r_pkScan);
    }
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Expand key for anon output received with wallet locked
 *
 * Stored in walletdb, key is pubkey hash160
 */
class CLockedAnonOutput
{
public:
    CLockedAnonOutput()
    : r_pkEphem{},
      r_pkScan{},
      r_outpoint{}
    {

    }

    CLockedAnonOutput(CPubKey pkEphem_, CPubKey pkScan_, COutPoint outpoint_)
    : r_pkEphem{pkEphem_},
      r_pkScan{pkScan_},
      r_outpoint{outpoint_}
    {

    }

    CPubKey   r_pkEphem;
    CPubKey   r_pkScan;
    COutPoint r_outpoint;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(r_pkEphem);
        READWRITE(r_pkScan);
        READWRITE(r_outpoint);
    }
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Stored in walletdb, key is keyimage
 *
 * TODO: store nValue?
 */
class COwnedAnonOutput
{
public:
    COwnedAnonOutput()
    : r_vchImage{},
      r_nValue{},
      r_outpoint{},
      r_spent{}
    {

    }

    COwnedAnonOutput(const COutPoint& outpoint_, bool fSpent_)
    : r_vchImage{},
      r_nValue{},
      r_outpoint{outpoint_},
      r_spent{fSpent_}
    {

    }

    ec_point r_vchImage;
    int64_t r_nValue;
    COutPoint r_outpoint;
    bool r_spent;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(r_outpoint);
        READWRITE(r_spent);
    }
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int GetTxnPreImage(const CTransaction& iTx, uint256& oPreImage);

bool GetKeyImage(CBlockTreeDB& iTxDb, const ec_point& keyImage, CKeyImageSpent& keyImageSpent, bool& fInMempool);

bool TxnHashInSystem(CBlockTreeDB& iTxDb, const uint256& iTxHash);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // ANONYMOUS_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
