// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <timedata.h>
#include <policy/feerate.h>
#include <consensus/consensus.h>

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0), nTime{GetAdjustedTime()} {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), nTime{tx.nTime} {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeWitnessHash() const
{
    if (!HasWitness()) {
        return hash;
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}

/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */
CTransaction::CTransaction() : vin(), vout(), nVersion(CTransaction::CURRENT_VERSION), nLockTime(0), nTime{GetAdjustedTime()}, hash{}, m_witness_hash{} {}
CTransaction::CTransaction(const CMutableTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), nTime{tx.nTime}, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
CTransaction::CTransaction(CMutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion), nLockTime(tx.nLockTime), nTime{tx.nTime}, hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        nValueOut += tx_out.nValue;
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nValueOut;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, PROTOCOL_VERSION);
}

bool CTransaction::HasStealthOutput() const
{
    // -- todo: scan without using GetOp

    std::vector<uint8_t> vchEphemPK;
    opcodetype opCode;

    for (std::vector<CTxOut>::const_iterator it = vout.begin(); it != vout.end(); ++it)
    {
        if (IsAnon() && it->IsAnonOutput())
        {
            continue;
        }

        CScript::const_iterator itScript = it->scriptPubKey.begin();

        if (!it->scriptPubKey.GetOp(itScript, opCode, vchEphemPK) ||
            opCode != OP_RETURN ||
            !it->scriptPubKey.GetOp(itScript, opCode, vchEphemPK) || // rule out np narrations
            vchEphemPK.size() != EC_COMPRESSED_SIZE)
        {
            continue;
        }

        return true;
    }

    return false;
}

int64_t CTransaction::GetMinFee(uint32_t blockSize, uint32_t txSize) const
{
    const auto C_BASE_FEE{IsAnon() ? MIN_ANON_TX_FEE : MIN_TX_FEE};
    auto minFee{C_BASE_FEE * (1 + txSize / 1000)};

    // to limit dust spam, require MIN_TX_FEE if any output is less than 0.01
    //
    if (minFee < C_BASE_FEE)
    {
        for (const auto& txout : vout)
        {
            if (txout.nValue < CENT)
            {
                minFee = C_BASE_FEE;
                break;
            }
        }
    }

    // raise the fee as the block approaches full
    //
    auto newBlockSize{blockSize + txSize};
    if (!IsAnon() && blockSize != 1 && newBlockSize >= MAX_BLOCK_WEIGHT_GEN / 2)
    {
        if (newBlockSize >= MAX_BLOCK_WEIGHT_GEN)
        {
            return MAX_MONEY;
        }

        minFee *= MAX_BLOCK_WEIGHT_GEN / (MAX_BLOCK_WEIGHT_GEN - newBlockSize);
    }

    if (!MoneyRange(minFee))
    {
        minFee = MAX_MONEY;
    }

    return minFee;
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    return str;
}
