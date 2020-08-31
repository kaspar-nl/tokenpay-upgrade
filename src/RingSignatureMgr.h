/**
 * Copyright (c) 2014 ShadowCoin
 * Copyright (c) 2019 TokenPay
 *
 * Distributed under the MIT/X11 software license,
 * see the accompanying file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef RING_SIGNATURE_MGR_H
#define RING_SIGNATURE_MGR_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <vector>
#include <cstdint>
#include <uint256.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <stealth.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CPubKey;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * TODO TSB
 */
class RingSignatureMgr
{
public:
    using Self = RingSignatureMgr;

    ~RingSignatureMgr();

    /**
     * TODO TSB
     */
    static Self& GetInstance();

    /**
     * TODO TSB
     */
    int splitAmount(int64_t nValue, std::vector<int64_t> &vOut);

    /**
     * TODO TSB
     */
    int getOldKeyImage(CPubKey &pubkey, ec_point &keyImage);

    /**
     * TODO TSB
     */
    int generateKeyImage(ec_point &publicKey, ec_secret secret, ec_point &keyImage);

    /**
     * TODO TSB
     */
    int generateRingSignature(data_chunk&    keyImage,
                              uint256&       txnHash,
                              int            nRingSize,
                              int            nSecretOffset,
                              ec_secret      secret,
                              const uint8_t* pPubkeys,
                              uint8_t*       pSigc,
                              uint8_t*       pSigr);

    /**
     * TODO TSB
     */
    int verifyRingSignature(data_chunk&    keyImage,
                            uint256&       txnHash,
                            int            nRingSize,
                            const uint8_t* pPubkeys,
                            const uint8_t* pSigc,
                            const uint8_t* pSigr);

    /**
     * TODO TSB
     */
    int generateRingSignatureAB(data_chunk&    keyImage,
                                uint256&       txnHash,
                                int            nRingSize,
                                int            nSecretOffset,
                                ec_secret      secret,
                                const uint8_t* pPubkeys,
                                data_chunk&    sigC,
                                uint8_t*       pSigS);

    /**
     * TODO TSB
     */
    int verifyRingSignatureAB(data_chunk&       keyImage,
                              uint256&          txnHash,
                              int               nRingSize,
                              const uint8_t*    pPubkeys,
                              const data_chunk& sigC,
                              const uint8_t*    pSigS);

private:
    EC_GROUP* r_ecGrp;
    BN_CTX*   r_bnCtx;
    BIGNUM*   r_bnOrder;

    RingSignatureMgr();

    int hashToEC(const uint8_t *p, uint32_t len, BIGNUM *bnTmp, EC_POINT *ptRet, bool fNew = false);
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // RING_SIGNATURE_MGR_H
