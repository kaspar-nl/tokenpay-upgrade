// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <consensus/validation.h>
#include <txdb.h>
#include <chainparams.h>
#include <validation.h>
#include <anonymous.h>
#include <txmempool.h>
#include <RingSignatureMgr.h>

// TODO remove the following dependencies
#include <chain.h>
#include <coins.h>
#include <util/moneystr.h>

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2
                      && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight-1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        if (tx.IsAnon() && tx.vin[i].IsAnonInput())
        {
            continue;
        }

        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, int flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        if (tx.IsAnon() && tx.vin[i].IsAnonInput())
        {
            continue;
        }

        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);
    }

    return nSigOps;
}

bool CheckTransaction(const CTransaction& tx, CValidationState &state, bool fCheckDuplicateInputs)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(tx, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs - note that this check is slow so we skip it in CheckBlock
    if (fCheckDuplicateInputs) {
        std::set<COutPoint> vInOutPoints;
        for (const auto& txin : tx.vin)
        {
            if (tx.IsAnon() && txin.IsAnonInput())
            {
                // -- blank the upper 3 bytes of n to prevent the same keyimage passing with different ring sizes
                COutPoint opTest = txin.prevout;
                opTest.n &= static_cast<std::uint8_t>(0xFF);

                if (!vInOutPoints.insert(opTest).second)
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-anon-duplicate");
            }
            else if (!vInOutPoints.insert(txin.prevout).second)
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        }
    }

    if (tx.IsAnon())
    {
        // check for duplicate anon outputs: if they're sent to the same one-time-address, only 1 will ever be spendable
        //
        std::set<CPubKey> vAnonOutPubkeys;
        for (const auto& txout : tx.vout)
        {
            if (!txout.IsAnonOutput())
            {
                continue;
            }

            // 3 = op_return + op_anon_marker + op_push_33
            //
            if (!vAnonOutPubkeys.insert(CPubKey(&txout.scriptPubKey[3], 33)).second)
            {
                return state.DoS(1, false, REJECT_INVALID, "bad-txns-outputs-anon-duplicate");
            }
        }
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }

    return true;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee)
{
    // are the actual inputs available?
    if (!inputs.HaveInputs(tx)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-missingorspent", false,
                         strprintf("%s: inputs missing/spent", __func__));
    }

    CAmount nValueIn = 0;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {

        if (tx.vin[i].IsAnonInput())
        {
            continue;
        }

        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase, check that it's matured
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < Params().nCoinbaseMaturity) {
            return state.Invalid(false,
                REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // If prev is coinstake, check that it's matured
        if (coin.IsCoinStake() && nSpendHeight - coin.nHeight < Params().nCoinstakeMaturity) {
            return state.Invalid(false,
                                 REJECT_INVALID, "bad-txns-premature-spend-of-coinstake",
                                 strprintf("tried to spend coinstake at depth %d", nSpendHeight - coin.nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
        }
    }

    const CAmount value_out = tx.GetValueOut();

    if (tx.IsAnon())
    {
        int64_t nSumAnon;
        bool    isInvalid;

        if (!CheckAnonymousTxInputs(*pblocktree, tx, state, nSumAnon, isInvalid))
        {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-check-anon-tx-inputs");
        }

        nValueIn += nSumAnon;
    }

    if (nValueIn < value_out)
    {
        return state.DoS(100,
                         false,
                         REJECT_INVALID,
                         "bad-txns-in-belowout",
                         false,
                         strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(value_out)));
    }

    // Tally transaction fees
    const CAmount txfee_aux = nValueIn - value_out;
    if (!MoneyRange(txfee_aux))
    {
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    }

    txfee = txfee_aux;

    return true;
}

static bool CheckAnonInputAB(CBlockTreeDB& iTxDb, const CTxIn &txin, int nRingSize, std::vector<uint8_t> &vchImage, uint256 &preimage, int64_t &nCoinValue)
{
    const CScript &s = txin.scriptSig;

    CPubKey pkRingCoin;
    CAnonOutput ao;

    ec_point pSigC;
    pSigC.resize(EC_SECRET_SIZE);
    std::memcpy(&pSigC[0], &s[2], EC_SECRET_SIZE);

    const unsigned char *pSigS    = &s[2 + EC_SECRET_SIZE];
    const unsigned char *pPubkeys = &s[2 + EC_SECRET_SIZE + EC_SECRET_SIZE * nRingSize];

    for (int ri = 0; ri < nRingSize; ++ri)
    {
        pkRingCoin = CPubKey(&pPubkeys[ri * EC_COMPRESSED_SIZE], EC_COMPRESSED_SIZE);
        if (!iTxDb.ReadAnonOutput(pkRingCoin, ao))
        {
            LogPrintf("CheckAnonInputsAB(): Error input %s, element %d AnonOutput %s not found.\n", txin.ToString().c_str(), ri, HexStr(pkRingCoin).c_str());
            return false;
        }

        if (nCoinValue == -1)
        {
            nCoinValue = ao.nValue;
        }
        else if (nCoinValue != ao.nValue)
        {
            LogPrintf("CheckAnonInputsAB(): Error input %s, element %d ring amount mismatch %d, %d.\n", txin.ToString().c_str(), ri, nCoinValue, ao.nValue);
            return false;
        }

        if (ao.nBlockHeight == 0 || (((pindexBestHeader ? pindexBestHeader->nHeight : 0) - ao.nBlockHeight) < MIN_ANON_SPEND_DEPTH))
        {
            LogPrintf("CheckAnonInputsAB(): Error input %s, element %d depth < MIN_ANON_SPEND_DEPTH.\n", txin.ToString().c_str(), ri);
            return false;
        }
    }

    if (RingSignatureMgr::GetInstance().verifyRingSignatureAB(vchImage, preimage, nRingSize, pPubkeys, pSigC, pSigS) != 0)
    {
        LogPrintf("CheckAnonInputsAB(): Error input %s verifyRingSignatureAB() failed.\n", txin.ToString().c_str());
        return false;
    }

    return true;
}

bool Consensus::CheckAnonymousTxInputs(CBlockTreeDB&       iTxDb,
                                       const CTransaction& iTx,
                                       CValidationState&   oState,
                                       int64_t&            oSumValue,
                                       bool&               oInvalid)
{
    AssertLockHeld(cs_main);

    oSumValue = 0;
    uint256 preimage;

    if (GetTxnPreImage(iTx, preimage) != 0)
    {
        LogPrintf("CheckAnonymousTxInputs(): Error GetTxnPreImage() failed.\n");
        oInvalid = true;
        return false;
    }

    for (const auto& txin : iTx.vin)
    {
        if (false == txin.IsAnonInput())
        {
            continue;
        }

        const CScript &s = txin.scriptSig;

        ec_point vchImage;
        txin.ExtractKeyImage(vchImage);

        CKeyImageSpent spentKeyImage;
        bool fInMemPool;
        if (GetKeyImage(iTxDb, vchImage, spentKeyImage, fInMemPool))
        {
            // -- this can happen for transactions created by the local node
            if (spentKeyImage.txnHash == iTx.GetHash())
            {
                if (fDebugRingSig)
                    LogPrintf("Input %s keyimage %s matches txn %s.\n", txin.ToString().c_str(), HexStr(vchImage).c_str(), spentKeyImage.txnHash.ToString().c_str());
            }
            else
            {
                if (!TxnHashInSystem(iTxDb, spentKeyImage.txnHash))
                {
                    if (fDebugRingSig)
                        LogPrintf("Input %s keyimage %s matches unknown txn %s, continuing.\n", txin.ToString().c_str(), HexStr(vchImage).c_str(), spentKeyImage.txnHash.ToString().c_str());

                    // -- spentKeyImage is invalid as points to unknown txnHash
                    //    continue
                }
                else
                {
                    LogPrintf("CheckAnonInputs(): Error input %s keyimage %s already spent.\n", txin.ToString().c_str(), HexStr(vchImage).c_str());
                    oInvalid = true;
                    return false;
                }
            }
        }

        int64_t nCoinValue = -1;
        int nRingSize = txin.ExtractRingSize();

        if (nRingSize < 1 ||
            nRingSize > (::Params().GetConsensus().IsProtocolV3(pindexBestHeader ? pindexBestHeader->nHeight : 0) ? (int)MAX_RING_SIZE : (int)MAX_RING_SIZE_OLD))
        {
            LogPrintf("CheckAnonInputs(): Error input %s ringsize %d not in range [%d, %d].\n", txin.ToString().c_str(), nRingSize, MIN_RING_SIZE, MAX_RING_SIZE);
            oInvalid = true;
            return false;
        }

        if (nRingSize > 1 && s.size() == 2 + EC_SECRET_SIZE + (EC_SECRET_SIZE + EC_COMPRESSED_SIZE) * nRingSize)
        {
            // ringsig AB
            if (!CheckAnonInputAB(iTxDb, txin, nRingSize, vchImage, preimage, nCoinValue))
            {
                oInvalid = true;
                return false;
            }

            oSumValue += nCoinValue;
            continue;
        }

        if (s.size() < 2 + (EC_COMPRESSED_SIZE + EC_SECRET_SIZE + EC_SECRET_SIZE) * nRingSize)
        {
            LogPrintf("CheckAnonInputs(): Error input %s scriptSig too small.\n", txin.ToString().c_str());
            oInvalid = true;
            return false;
        }


        CPubKey pkRingCoin;
        CAnonOutput ao;

        const unsigned char* pPubkeys = &s[2];
        const unsigned char* pSigc    = &s[2 + EC_COMPRESSED_SIZE * nRingSize];
        const unsigned char* pSigr    = &s[2 + (EC_COMPRESSED_SIZE + EC_SECRET_SIZE) * nRingSize];
        for (int ri = 0; ri < nRingSize; ++ri)
        {
            pkRingCoin = CPubKey(&pPubkeys[ri * EC_COMPRESSED_SIZE], EC_COMPRESSED_SIZE);
            if (!iTxDb.ReadAnonOutput(pkRingCoin, ao))
            {
                LogPrintf("CheckAnonInputs(): Error input %s, element %d AnonOutput %s not found.\n", txin.ToString().c_str(), ri, HexStr(pkRingCoin).c_str());
                oInvalid = true;
                return false;
            }

            if (nCoinValue == -1)
            {
                nCoinValue = ao.nValue;
            }
            else if (nCoinValue != ao.nValue)
            {
                LogPrintf("CheckAnonInputs(): Error input %s, element %d ring amount mismatch %d, %d.\n", txin.ToString().c_str(), ri, nCoinValue, ao.nValue);
                oInvalid = true;
                return false;
            }

            if (ao.nBlockHeight == 0 || (((pindexBestHeader ? pindexBestHeader->nHeight : 0) - ao.nBlockHeight) < MIN_ANON_SPEND_DEPTH))
            {
                LogPrintf("CheckAnonInputs(): Error input %s, element %d depth < MIN_ANON_SPEND_DEPTH.\n", txin.ToString().c_str(), ri);
                oInvalid = true;
                return false;
            }
        }

        if (RingSignatureMgr::GetInstance().verifyRingSignature(vchImage, preimage, nRingSize, pPubkeys, pSigc, pSigr) != 0)
        {
            LogPrintf("CheckAnonInputs(): Error input %s verifyRingSignature() failed.\n", txin.ToString().c_str());
            oInvalid = true;
            return false;
        }

        oSumValue += nCoinValue;
    }

    return true;
}
