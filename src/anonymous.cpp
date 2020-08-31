/**
 * Copyright (c) 2019 TokenPay
 *
 * Distributed under the MIT/X11 software license,
 * see the accompanying file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <anonymous.h>
#include <txdb.h>
#include <uint256.h>
#include <validation.h>
#include <hash.h>
#include <txmempool.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int GetTxnPreImage(const CTransaction& iTx, uint256& oPreImage)
{
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << iTx.nVersion;
    ss << iTx.nTime;
    for (uint32_t i = 0; i < iTx.vin.size(); ++i)
    {
        const CTxIn& txin = iTx.vin[i];
        ss << txin.prevout; // keyimage only

        int ringSize = txin.ExtractRingSize();

        // TODO: is it neccessary to include the ring members in the hash?

        if (txin.scriptSig.size() < 2 + ringSize * EC_COMPRESSED_SIZE)
        {
            LogPrintf("scriptSig is too small, input %u, ring size %d.\n", i, ringSize);
            return 1;
        }

        ss.write((const char*)&txin.scriptSig[2], ringSize * EC_COMPRESSED_SIZE);
    }

    for (const auto& txout : iTx.vout)
    {
        ss << txout;
    }

    ss << iTx.nLockTime;

    oPreImage = ss.GetHash();

    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool GetKeyImage(CBlockTreeDB& iTxDb, const ec_point& keyImage, CKeyImageSpent& keyImageSpent, bool& fInMempool)
{
    AssertLockHeld(cs_main);

    // -- check txdb first
    fInMempool = false;
    if (iTxDb.ReadKeyImage(keyImage, keyImageSpent))
        return true;

    if (mempool.findKeyImage(keyImage, keyImageSpent))
    {
        fInMempool = true;
        return true;
    }

    return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool TxnHashInSystem(CBlockTreeDB& iTxDb, const uint256& iTxHash)
{
    // -- is the transaction hash known in the system

    AssertLockHeld(cs_main);

    if (mempool.exists(iTxHash))
        return true;

    // TODO -> remove this return true
    return true;

    // TODO TSB

    /*
    CTxIndex txnIndex;
    if (ptxdb->ReadTxIndex(txnHash, txnIndex))
    {
        if (txnIndex.GetDepthInMainChainFromIndex() > 0)
            return true;
    }

    return false;
    */
}
