// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * TODO TSB
 *
 * @param iHeadline
 * @param iTimestamp
 * @param iNonce
 * @param iBits
 * @return
 */
static CBlock CreateTokenPayGenesisBlock(const std::string& iHeadline,
                                         std::uint32_t      iTimestamp,
                                         std::uint32_t      iNonce,
                                         std::uint32_t      iBits)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.nTime = iTimestamp;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vout[0].SetEmpty();

    txNew.vin[0].scriptSig = CScript() << 0
                                       << std::vector<std::uint8_t>{42}
                                       << std::vector<std::uint8_t>{iHeadline.c_str(),
                                                                    iHeadline.c_str() + iHeadline.length()};

    CBlock genesis;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    genesis.nVersion = 1;
    genesis.nTime = iTimestamp;
    genesis.nBits = iBits;
    genesis.nNonce = iNonce;

    return genesis;
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        //consensus.nSubsidyHalvingInterval = 210000;
        //consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        //consensus.BIP34Height = 227931;
        //consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        //consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        //consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931

        // TokenPay: adjust pow limit to the TPAY network, add proof limits for pos
        //
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posV2Limit = uint256S("000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        //consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000028822fef1c230963535a90d");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000008b71ab32e585a23f0de642dc113740144e94c0ece047751e9781f953ae9"); // 0 -- genesis

        consensus.nCoinbaseMaturity = 105;
        consensus.nCoinstakeMaturity = 105;

        consensus.nFirstPosv2Block = 20001;
        consensus.nFirstPosv3Block = 20011;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xf1;
        pchMessageStart[2] = 0xe2;
        pchMessageStart[3] = 0xb1;

        nDefaultPort = 8801;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 200;
        m_assumed_chain_state_size = 3;

        // TokenPay: create and use the TPAY genesis block
        //
        genesis = CreateTokenPayGenesisBlock("TokenPay - August 2017", 1503628005, 517899, 504365055);

        consensus.hashGenesisBlock = genesis.GetHash();
        // TokenPay: assert the adjusted TPAY genesis block's hash and merkle root
        //
        assert(consensus.hashGenesisBlock == uint256S("0x000008b71ab32e585a23f0de642dc113740144e94c0ece047751e9781f953ae9"));
        assert(genesis.hashMerkleRoot == uint256S("0x0a2d4ac9cc16ab3d88ddcb53b368cfd866692d05ccdf79da4ad94efcf471e254"));

        vSeeds.emplace_back("cvb2ovc6tcntozc5.onion");
        vSeeds.emplace_back("xfkfn7vszswzito2.onion");

        base58Prefixes[PUBKEY_ADDRESS]      = { 65 };
        base58Prefixes[SCRIPT_ADDRESS]      = { 126 };
        base58Prefixes[SECRET_KEY]          = { 179 };
        base58Prefixes[STEALTH_ADDRESS]     = { 40 };
        base58Prefixes[EXT_PUBLIC_KEY]      = { 0x2C, 0x51, 0x3B, 0xD7 };
        base58Prefixes[EXT_SECRET_KEY]      = { 0x2C, 0x51, 0xC1, 0x5A };
        base58Prefixes[EXT_KEY_HASH]        = { 137 }; // x
        base58Prefixes[EXT_ACC_HASH]        = { 83 };  // a
        base58Prefixes[EXT_PUBLIC_KEY_BTC]  = { 0x04, 0x88, 0xB2, 0x1E }; // xprv
        base58Prefixes[EXT_SECRET_KEY_BTC]  = { 0x04, 0x88, 0xAD, 0xE4 }; // xpub

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                { 11111, uint256S("0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")},
                { 33333, uint256S("0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")},
                { 74000, uint256S("0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")},
                {105000, uint256S("0x00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")},
                {134444, uint256S("0x00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")},
                {168000, uint256S("0x000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")},
                {193000, uint256S("0x000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")},
                {210000, uint256S("0x000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")},
                {216116, uint256S("0x00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e")},
                {225430, uint256S("0x00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932")},
                {250000, uint256S("0x000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
                {279000, uint256S("0x0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40")},
                {295000, uint256S("0x00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000000002e63058c023a9a1de233554f28c7b21380b6c9003f36a8
            /* nTime    */ 1532884444,
            /* nTxCount */ 331282217,
            /* dTxRate  */ 2.4
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }
};

/**
 * TokenPay TestNet -- deployed 22/01/19 by Th. S.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        //consensus.nSubsidyHalvingInterval = 210000;
        //consensus.BIP16Exception = uint256S("0x00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105");
        //consensus.BIP34Height = 21111;
        //consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        //consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        //consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.powLimit =   uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit =   uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posV2Limit = uint256S("000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        //consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000007dbe94253893cbd463");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x04f622af0c331e6e6b2477468f7c33202a607b865daa3536a3dbe3fb61714d6d"); // 0 -- genesis

        consensus.nCoinbaseMaturity = 15;
        consensus.nCoinstakeMaturity = 15;

        consensus.nFirstPosv2Block = 190;
        consensus.nFirstPosv3Block = 199;

        pchMessageStart[0] = 0xa3;
        pchMessageStart[1] = 0x2c;
        pchMessageStart[2] = 0x44;
        pchMessageStart[3] = 0xb4;
        
        nDefaultPort = 16601;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 20;
        m_assumed_chain_state_size = 2;

        // TokenPay: create and use the TPAY TestNet genesis block
        //
        genesis = CreateTokenPayGenesisBlock("TokenPay Testnet - 22nd of January 2019 - The Times 22/Jan/2019 Dozens of ministers ready to quit over no‑deal Brexit", 1548152946, 120930, 537395199);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x04f622af0c331e6e6b2477468f7c33202a607b865daa3536a3dbe3fb61714d6d"));
        assert(genesis.hashMerkleRoot == uint256S("0x2369d11bba0ebb4dde473781031188b0a4b27170e240e9ebcdac92df787664e4"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.emplace_back("kcy3d3t2xcmrv4kr.onion");
        vSeeds.emplace_back("hyfl7waai5jhpz6y.onion");

        base58Prefixes[PUBKEY_ADDRESS]      = { 127 };
        base58Prefixes[SCRIPT_ADDRESS]      = { 196 };
        base58Prefixes[SECRET_KEY]          = { 255 };
        base58Prefixes[STEALTH_ADDRESS]     = { 40 };
        base58Prefixes[EXT_PUBLIC_KEY]      = { 0x76, 0xC0, 0xFD, 0xFB };
        base58Prefixes[EXT_SECRET_KEY]      = { 0x76, 0xC1, 0x07, 0x7A };
        base58Prefixes[EXT_KEY_HASH]        = { 75 }; // X
        base58Prefixes[EXT_ACC_HASH]        = { 23 };  // A
        base58Prefixes[EXT_PUBLIC_KEY_BTC]  = { 0x04, 0x35, 0x87, 0xCF }; // tprv
        base58Prefixes[EXT_SECRET_KEY_BTC]  = { 0x04, 0x35, 0x83, 0x94 }; // tpub

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        throw std::runtime_error("Regtest not supported");

    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
