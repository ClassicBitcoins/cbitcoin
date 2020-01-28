// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
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
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'ClassicBitcoin' + blake2s(b'CBTC new opportunities for Online payments. BTC #609249 - 000000000000000000010e923a926afd529ddc6967a916d67e26f05be3cf191b').hexdigest()
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "ClassicBitcoinf43c7624a7561333fe66a00b5fc5f30d91fadd87fc3b153b045e74775126b1d9";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));


class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "CBTC";
        bip44CoinType = 177; // As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 13;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 34;
        consensus.nPowMaxAdjustUp = 34;
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 790009;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 169;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 790009;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 169;

        // The best chain should have at least this much work.
        // consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000a95cc5099213e3");

        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0xe8;
        pchMessageStart[1] = 0xb2;
        pchMessageStart[2] = 0x2d;
        pchMessageStart[3] = 0x2f;
        vAlertPubKey = ParseHex("04d5212ed0303c64db1840e799d31953eb362fd71d8e742dccd9aa78c4713d6d26b44974b44e2ac71aa38b06ef60c020207b85d270e4bdf8c797f3216f969960dc");
        nDefaultPort = 2050;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;
        newTimeRule = 159300;
        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_1_endblock = 2160010;
        eh_epoch_2_startblock = 2160000;

        genesis = CreateGenesisBlock(
            1576996750,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000aaf"),
            ParseHex("001f9d1d3ef5579bd80f3301ff4f7fcf2cab99a3e40f6fa75e7fc682fe85eb54423469bd394437d01ae2048cc989a18bb2e47652550982aeff6642bbd7ee5f0a1ce690d9589f27591712a02bed4eb4fd2de90f9407a3a4a2d99d4c7d9345e294c42e0bd8aac494331d3faaa31cd01a9b59cc3da4b8a4eda9868c09db9d810bea86dae716e68f3a3a0a52e7f524a3b02d1fbcfc18cc0b3cfa86985b8786665554798cbea6bc37726b00ff66135f9ae55ff41ea37629226cc9da12fd9af36c47c513ef9c8b9f165c76e8743d2f2eea733d13d1173ae4aba80b14c3874946cb925a313698eb7d4a652f5f39f4899e523fb62104d2f47dc23e9d8dfc7109020927f55de34d19f771e0a3e4e5ee04cd0434cd4b1d91b1cc402ad625a7ea71f94bdea75cc6ef0cce48053ab72456d90ecdbd1c464a93715b23aefb1fab9d23296a6c60fc74f5ecfea97e6c73261a76d553bad10084a4a760e61693670e9264921683094851ce75c5216b22482056b8df23b543a4cf72ed4a565ff2e28e013af4c0a90e3a1be0c5d26cefbbd7a8df7a333f66409cbe5a07d0990fc63de43da6d9b79384f7fda491089921545302932d91bfc8d106626532bbefdaf942132c936d5c0a9bc76bb757e262d9c757a0a5fe566c150bbeff5354d4cd2fcdc174beadb2046abedc6564172b22eaf9199589da84f2586244268183da9601d600ee869db29488c38583b04f10f9bea8ec8db68832081509c34777a21dc629b5595e76f77d9e74f0b5a903e3453c419f474765cf538d5a757c5b69d7bea4fe3d2e6302ce1898f5eb31641330def719126b90d33605244209a7c7be63daa773356fb678811ee42a102c1d8c93aaef92ad77b048c3b309d9b36d14ae297ad80a966b2f2f185e01a0e280d63c948785ea247a2dc059bb7c358b6dfccbb5d08694b553d04b1966f8f50b01a27a78bc5a60d15d8981db7f750b7abe30b862fb139a3d2118acda5dc49fe3c3e745be6113f6ff6b5d243f1c8a579b57cd3f788382165cdfd61086f169177329ec50c429dca75ed78ca7b8fc019b48a65ca9400e473a8b7b0c260aa072c423226c20875d40fe7c96281aeceea15282e35a16c2a26879b940a9991d6a6f20a5e90d55ef9921e09ed60dde517f85e7ac73cd462c466f3212563cf34cb1a6ed17633a8e19c17c71af03db03921555c43b4cc913d2e9d90fe1cb92be3d221de2b2fb3a67e52f67a6c296ee6ca3d1c4b27e4a470c629ebc0d4c8b7f917392f811599aa338e81d99fc1beabeb874cc8c29c78323bff25654553f03af4e8809327082cc10d62b6738ac2f33f504df1697fc198016088eb070a9c951898c820dd95826994d895c5461114ffc137b0a47dba3f0a35004cf0085c4f39d36a14a265de19fb29f3def041a8298fab87771d5fb913702d63163fdf7426bf9e630a80747500c87f13ca11b09a24bf47a55f8e4b358d7e0b3d02a2effecdcc5610f5a71db59d81bf3a84441b737ee72b9f3401115a814f6b2b859539607391511534a316578bcdd9f013a153299786e4aa0913aed366f50d4f7f368555f8e683fc1f69796a5d6abb3fdd6af04bb216616e856acf71b4dbc7f3694524fd11bf70779d56d9ebdabf5feb523ddc4c6bceeefffd37b939cc541cb062921551fd403ef4e53f76a8e3975a084c29a48460d3968f330e927a5b2f717dc67df6849d479cde5cb11c6bcb31b81133631ad4ae639df9636e45f475c8061f849f03145330121db22dd1e01eb46f3359a3dd81cd2d3d08454096961da35862aac74ff71dc183600d4f6ff9472b91624cbd6bf33b5c9a7715333c47ab924f8f2f303b61a3a6ca3ede106bf81af93f98d442c15cae37600f021e4e1dcee93854d75b354c730a6b9ba83a81e0c65"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0006cb3c450b5c354da33e42065505f67b2a227d524baaed793bbc79219fec58")); //incremented by 1 making 2
        assert(genesis.hashMerkleRoot == uint256S("0x1f71b51754b20cf71276520a27bbf039c33fd7d2d79f75d97b7460b171e12aaa"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // use name as: echo -n hostname | sha256sum
        vSeeds.push_back(CDNSSeedData("classicbitcoin.info", "dnsseed.classicbitcoin.info"));
        vSeeds.push_back(CDNSSeedData("bitclassic.info", "dnsseed.bitclassic.info"));


        // guarantees the first 2 characters, when base58 encoded, are "t1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1c,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1c,0xAF};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("0x0006cb3c450b5c354da33e42065505f67b2a227d524baaed793bbc79219fec58"))
            ( 100, uint256S("0x00008e4b585ad61b7637369695de306638817d87a58464dc089ef0bab1eb51e9"))
            ( 475, uint256S("0x00009c5163f7817b2ca16ec7acc4a054a94bd036148ccb7c9d6d34d4993270e0")),
            //( 20675, uint256S("0x00000004804df1618f984fef70c1a210988ade5093b6947c691422fc93013a63")) // Thaddeus Kosciuszko - 200th death anniversary (October 15 2017)
            //( 40000, uint256S("0x00000005a2d9a94e2e16f9c1e578a2eb46cc267ab7a51539d22ff8aa0096140b"))  //18-06-17  8am UTC Hooray for Zhash!
            //( 166500, uint256S("0x0000002b640d62dd0c2ab68774b05297d2aa72bd63997d3a73ad959963b148d8")),

            1577745139,     // * UNIX timestamp of last checkpoint block
            615,         // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            1500.912865  // * estimated number of transactions per day after checkpoint
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };

        // Community Fee script expects a vector of 2-of-3 multisig addresses
        vCommunityFeeAddress = {
            "swzaebQB4jVzESmoDp9WzLmBWo4GVy84PZq",
            "sws9DWZ1aRRPfNb2bUALBfQdhm9ebPVho7T"
        };
        vCommunityFeeStartHeight = 50000;
        vCommunityFeeLastHeight = 2400000;
        assert(vCommunityFeeAddress.size() <= GetLastCommunityFeeBlockHeight());
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TCB";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 840000;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow = 13;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 34;
        consensus.nPowMaxAdjustUp = 34;
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 790009;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 1500;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 790009;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 1500;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000005000");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("048679fb891b15d0cada9692047fd0ae26ad8bfb83fabddbb50334ee5bc0683294deb410be20513c5af6e7b9cec717ade82b27080ee6ef9a245c36a795ab044bb3");
        nDefaultPort = 12050;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 1000;
        newTimeRule = 159300;
        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_1_endblock = 1210;
        eh_epoch_2_startblock = 1200;

        genesis = CreateGenesisBlock(
            1576996750,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000010"),
            ParseHex("011a295b400450566408c2b54846fa733e003f1f16026c7989b2dd4b23e603830a5c360be2e3899964ca037f4124020851f17f2722333f9f6a49e1be3b45b916e8bbebfc4da8e0d798b16f1f65fb6a04b59639470414cd2a58549aed353dc0aa57d0ba2d6820cc33870c660c60c6181fa170d790dce39d2659dee554f8690a37c960d8e8070fcedb0173783ed539d13290f6784125823672dbeba321774429344068a129dfccddff092450c3b2f3a53bea2527282e4d420232719dad621418dc13d9b4aaa3b42ce18d7ca4c4e8b4820aef313665cd1318edc4b7fdf186ee78cca66a0f53fecce24502d456eee4fcb3f117b66c8cf7b3efcc549ff4290a4ea0fda7054654fbce53044e669e294115d95fbc2c2167a5e98e5942ede7a80ff047142ec5613ec738200bd1be24cb88f4f9761236ed4f9658ec7bb9f44c24203dc533595f40dbc857a43ce8d6baf3e15c0eb70131dfb458942764e351467d906bfd6a5afb978c360d017644f7a1e0a35296b65f2f55ed2a38a8bc57a41bd1a60af549531999f0c2a741b7d662c77d9cb8e129c121fd2bf4da09c7bf75836066fde19452fc774503a03c886111ceeb18f887fe7b703fe64aa1d35fae2ab8bce582e65f519d80940da246ad42ee975955360832dc1f720d3e491f2e232c7fa7dbd92cb273b1a21f08596cb473ea03a631161fef78d57aa117bde0410550a2aee2dd1847ef22f16c01183cdcdea6f88f5c2f2d9f78169bcbeee89aaada20ee94674e9c1d829e0b6bf1897f8382964c4122ad014e03a9ddae7cec2451b61ae103657d3ddc481646f5b61521a516b65bdd05afc154fa2bca45fd7227150cc4653ad6cc796da21473096ea64dee18f3edc59c11e6631e26ff3e2f6b18e86a04c83db4dbf33c31e3b1afe6f643f19dbd0b30e62f4d9975c9a7db90b3b058b2bbb53e8a4bf73802d1d1beca8907ccbd86f4949c499c42ffa83eed980489fb85b4d81757a9a4704a613f8d95c4043787e811c638fc630c72d1689633a242c8e976c101ff969a46d11c8fc353ff22f439882b8153265e920894cf810c14dcffec0866f3f57e324f4f6790016b7df57ee315235e0fa590fbc6d52c641f38cc5e620b6c57040a26c1ca4d719c4ebf55be73ec44aafb6204e3b5bfeb354783e873999abee31e07d51363a7a710eb38f8280500a04f45e698279177d4ba31bef8ad37a87e4e403347bc0885a0538d48e0f518bc548a46e7517fcb9612ae01040c97ea79b18911fb582eafb0ed26111c032dc0117c4ed7f5a12ee783be5973ceb29ac919c50905c3d417175458ab96ae19f16efae0b6d162b9ee63299b73b49656b19cce36a46c6ec6450d64d4b4d7a01bf9dfe05dd2b54591b57916dd751dbb5f17ff188b2120bbf8fc9d4ff7c17f33de34a9e232347c9247c104355888e4909713898b443d9d518b31a5bd17caf3052d21fd4b9c20c37184f237085bf07cb6a6785fea0a78dcba2cd03d05b49e856366e1eff962a9f934df0c20bfaf3a518439d41705e381d7d1b5b91438d121179811750a564f99181ec57702ffc8027c7d98d8eb1ae147b7bfed8fa1997b527a396ded527c4b1f33da1a4f7b16550cc619eff93299b86f7630fff3587acf1be89d83bf5039de956f1281d3bffbfa494b3ef3e80625c2887754c444fcde68dd5be8f4d27ede17ce1424015228a859479d920934fe4dd6266e602bd7091617574efae08e11336392350a643c7ed5ab65fad75331c447886bb6622bd1de549ea0db7f8653f778b8a806d594068f30dc1dc9602e81a1fd8e77ca807fbb370a31911e96c887e0898b81d22062e13f178ef95ca0233c647b9698c8a1428086b44c5b2a4afa3ffa2d982f50e19d7bae1b03e03ea9a2957765d6edde9fa7b6"),
            0x2007ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x01f9c2c68fc794fd28b4128ed344c7b5d6b4e868da57c85962c21f83a3ce3f95"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("978b674532d58328c4da63ab138c476ffa2f8a8b2b5a023a668fd3a97eb7c48b.TZB", "testnetseed.bitclassic.info"));
        //vSeeds.push_back(CDNSSeedData("rotorproject.org", "test-dnsseed.rotorproject.org")); // Zclassic

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, consensus.hashGenesisBlock),
            genesis.nTime,
            0,
            0
        };

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vCommunityFeeAddress = {
            "t2FpKCWt95LAPVRed61YbBny9yz5nqexLGN",
            "t2RqJNenxiDjC5NiVo84xgfHcYuwsPcpCie",
            "t2MsHkAug2oEiqj4L5ZGZH1vHmdogTSb9km",
            "t2EwBFfC96DCiCAcJuEqGUbUes8rTNmaD6Q",
            "t2JqYXRoTsKb9r1rTLLwDs5jMXzsRBV317k",
            "t2RocidGU4ReKPK2uTPYfNFgeZEWDCd3jsj",
            "t2Mu8ToNiVow92PfETBk5Z6HWuAEG7RVXVD",
            "t2MSLT1n4eQ87QC2FAxMvuTZ84zDzEj7FhQ",
            "t2JZNFrWv1c4RqkCmDN9iRkPsG8xAZFdyGS",
            "t2AyjEVUCf5jthGHZjwfbztDBHQbztkJB5v",
            "t2Gs6dTYCzaFdHSeT91zaFLKmYzyqYY3NnP",
            "t2FXfNK7iQhTdMFcGUyrizqXQE5qbmPK6zc",
            "t2UqLwQ85pR1fdFMoUzXadXRB97JxP6vTWY",
            "t2BocGBq7iBXQP8UQiousNVwU8M6AqUtaRx",
            "t2VGGdXhspjF3iQvbWZW2zPNSDRSYauBcM3",
            "t2HTNHicoeEXxsX1wVhsqsX3LgzRq2pYgWH",
            "t2UiVSyM1vuvs6xP3157ytuYMKN6MuqmgJE",
            "t2UmPyNoWSVUgyPzEXzFGN5GS96jMH2kreW",
            "t2MQWZJHxZF5zSw6LbZ3S7jqoLX1y6SWLHQ",
            "t2VUR1c1aFaTUo93uhi7rfFVRRZaT1aQYbv",
            "t2NgLU6QCJhCKgBsR5uX6R4ds82jymzMoMJ",
            "t2RorFwMUEb7NamvXFi3jCXitAdRoQtU1Hs",
            "t2FFtmwePBnYaRVRVg1wsoBPxDzGMLrz3Jv",
            "t2GH3734fKEhPo3NvvAZQazsFf3V51oR4c2",
            "t2Ev3twAmUmono3gM2Q6RsfhRiryy7TnX5E",
            "t2EmhhAjh6cLpyw6Yc9QEXvsjm7qdKpgFQP",
            "t2Gy5N7DYbEZmiHqm3m8Re25a8Bxu7e36ju",
            "t2LVSaxizciFWfc5gr1xccHXT115RSnQ13r",
            "t28zy3Qiq3FtMeB2PCEysF7R5TgW5UfZN1N",
            "t2FcN7o26gRCc8ZuSZcc7X7APPRqWQ5a3W2",
            "t27QTHP9qoi5HkiTqx4JV86MGG37aikK51s",
            "t2CwQ6H9GPT77nqRwkHCuVcyGvtbhxWHfAk",
            "t2HLUDaoimaaSpQhHnvbqpKg6Fi37rAo6cx",
            "t2Ebuq1FX7Qzi3ur1FnwsDMvfNBFjqVqDGX",
            "t2Bca3HbSbwgQp1ZhzheNvGfpwBoU6Syt8G",
            "t2EurfAqyJMsCyx6ujYecQSxrPPY7xxTqcB",
            "t2R1kJGeNhLpKx1dKNCnBUq1BkxBVJjQdcp",
            "t2M3x9koBJWJS1F9bGtWXTsVfr5pesWSTbR",
            "t2La4mEMruVTtBqhndS7zRvmi2WsqWUjPQz",
            "t29GwTHLXxYgF5k7SSj7XFaHB7JsocM9bDU",
            "t2Awpdv7yG2QFeHeq17J1qCSXRw1AM3mfmz",
            "t2BfotpLdNhhewRp9nXpBBYViBaq4y1Lnj5",
            "t2F4CH89prySyGZHUiPYJUjnZk9UPXgLBbf",
            "t2DNx1KzP8a2S3kZgAPngso9ptva5gE7Jbn",
            "t2Eb7orwhjGcu4wYwHBzN5BoXzroPGq3CoM",
            "t2BXYmM21WCdHiC1KiwQVHxaTvLQJpqXTvH",
            "t27Y6774dwAcCFvYrhDKTXgaxtUewAdZdtz",
            "t2JvmRjZnViBZXJJBekDygdvGTCRNWgFEK2",
            "t2PL5W7qy1DKNRPWECbaZ6gV9GEzMn8h97Z",
            "t2S1JaefdSNwaUexdr6ZtNJhqZS8uDGSNFg",
            "t2BTunj4VB44Q22crWpT1ykoBvNGFKMnD7N",
            "t2G7DkSoEUJGaEBH6erKsXemoHFqqTRaSiZ",
            "t2Ldg8Bc6AWDuESqPgUoumWfCYw3zqKF8s9",
            "t2Ft4QMMiJfKXVbhyGBrkwjnfn5ua73VuLo",
            "t26xLxd4Fabbotkc9gfFwpCVHoZG1W9rmN7",
            "t2DyghJMpK6rRKPEAL3DBKmCntUcj8bUiHg",
            "t2RSYhCsgw2AdBiUUyXBCkFf2xE9ddwyESD",
            "t26fv5NLiFYXMmfQnvqcJXcYnt5NY41eqrv",
            "t2Ppht55eXKC1BX7pfusJxZqbHnkp9oWbBW",
            "t2P4AWJ5C4ySU3KzfehAeppH2BV4Y87w34z",
            "t28zjDUH2Gkvt8Ytb8UrW7L6G5U1QMwJFM3",
            "t2JXDd9pumryTAXqDD98vDLS2ZLSQCNQrYZ",
            "t2BNuNGnGq49MZzr7SH8WtEE7sSwZ9n3bsz",
            "t2QumKdHZhkFD6ntrzJ9zJAga2QemEgqc9r",
            "t2UKz2L7V3C6GTeBPDXmQnwMyqKEbgMpuXg",
            "t2CyVugoafiDYpeSNd9DGZEng6Bpr4tqa3d",
            "t2GR9eEen8KUDjhQG1opC1aFt27zxdtufnF",
            "t2JKYuSRNupdHdTR91tqR4xsaU6friVJJgv",
            "t2D2yMZEM3K8ap6iLo3FX2g1Ch9coPSVq2R",
            "t2SeFu34eiE2rCPFpxrN8im6ZvcwMpdKnit",
            "t2KH46EXQy5wnZHDGVDA7Q13FdRkdQ3LUou",
            "t2UsTpuVqP6ZubtN8tQGPnh7Cqjjf1hoefd",
            "t2Dd119xiqDbF9QzWwYfnYWUPfqgnL1CNFu",
            "t29PjecMhv6EygD8W6smcMHAB8MSHQY3YnQ",
            "t2BDZpxgcMRzqgKbDBiXRXrvL3VwD7G8cLc",
            "t2MwiKqfCMdy7o96bXvbZ5aGCrRmVfVWVfA",
            "t2Vhkny4jNjy6ZD53jeQzsdgZiZyejwRsgY",
            "t2K3ouBrLAbYwZv6beoHjzfsE1AbYVa6PuE",
            "t2DskMSpWs8i9vK2PhNpi9Mu2qJSvEDi8UZ",
            "t2JB2Uz3eVWrxFhas1B1cSXLP22JHbRNYtL",
            "t2ArYKW1L8hRoCDK9odNmD4piRwFheErWL1",
            "t2K1zKGHrkibiFoYJ5GtfHe5xJecJPEvFwQ",
            "t2VnABknMprtMk8y5AdDCBr2R9QZnMhfqSm",
            "t2FbjEsP9eeQr5PmP7yC3fopPTuYS9E9VgN",
            "t2Sn2XUPZEnFcggB77jvxBqX6LcjdCzcJUs",
            "t2SEK3Tw5FYYUaeZcF5QemfeG3tiorrxNKp",
            "t2D78THpHVodnhiREjF22A3KRznor5pPnR1",
            "t2GyqFdkf6FoQTShEhLGsNrTxAWqmeq4pui",
            "t2HnNgFLznEqaokYq8PBV44uzRwAmJXQeKd",
            "t2PpHVStdHvWkzXsyuyPYQQq96ZRQu7ALpE",
            "t2FHbHM9rKKHZe74HRBNozwNdRsExug8tCw",
            "t29tM6DkMPSVp9R3g7UjZjvsobKhsbsRqFL",
            "t2K2KixLVJo19phPJMv9ApSiFmxQCSQUvc9",
            "t2AWJcGVUMWFC8A9KC3PL7qoCb1vxSzxbJP",
            "t26p8FyjHmhqZ6duzhRFLCQcExh1TuCD1sC",
            "t27x5n41uRNF3tJkb3Lg1CMomUjTNZwtUfm",
            "t2VhRQJ9xeVkVVk7ic21CtDePKmHnrDyF8Z",
            "t27hL1iAsTHBPWrdc1qYGSSTc3pTyBqohd4",
            "t2RqLYWG8Eo4hopDsn1m8GUoAWtjZQEPE9s",
            "t2V1osVDkcwYFL4PF9qG8t9Ez1XRVMAkAb6"
        };
        vCommunityFeeStartHeight = 1500;
        vCommunityFeeLastHeight = 1400000;
        assert(vCommunityFeeAddress.size() <= GetLastCommunityFeeBlockHeight());
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow = 13;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nPowMaxAdjustUp = 0; // Turn off adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 770006;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nDefaultPort = 12050;
        nMaxTipAge = 24 * 60 * 60;
        //assert(consensus.hashGenesisBlock == uint256S("0x0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a"));
        nPruneAfterHeight = 1000;
        newTimeRule = 159300;
        eh_epoch_1 = eh48_5;
        eh_epoch_2 = eh48_5;
        eh_epoch_1_endblock = 1;
        eh_epoch_2_startblock = 1;

        genesis = CreateGenesisBlock(
            1482971059,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000009"),
            ParseHex("05ffd6ad016271ade20cfce093959c3addb2079629f9f123c52ef920caa316531af5af3f"),
            0x200f0f0f, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327"));
        //assert(genesis.hashMerkleRoot == uint256S("0xc4eaa58879081de3c24a7b117ed2b28300e7ec4c4c1dff1d3f1268b7857a4ddb"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.
        vSeeds.push_back(CDNSSeedData("978b674532d58328c4da63ab138c476ffa2f8a8b2b5a023a668fd3a97eb7c48b.TZB", "testnetseed.bitclassic.info"));
        //vSeeds.push_back(CDNSSeedData("rotorproject.org", "test-dnsseed.rotorproject.org")); // Zclassic

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x0575f78ee8dc057deee78ef691876e3be29833aaee5e189bb0459c087451305a")),
            0,
            0,
            0
        };

                // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";

        // Founders reward script expects a vector of 2-of-3 multisig addresses
        vCommunityFeeAddress = {
            "t2FpKCWt95LAPVRed61YbBny9yz5nqexLGN",
            "t2RqJNenxiDjC5NiVo84xgfHcYuwsPcpCie",
            "t2MsHkAug2oEiqj4L5ZGZH1vHmdogTSb9km",
            "t2EwBFfC96DCiCAcJuEqGUbUes8rTNmaD6Q",
            "t2JqYXRoTsKb9r1rTLLwDs5jMXzsRBV317k",
            "t2RocidGU4ReKPK2uTPYfNFgeZEWDCd3jsj",
            "t2Mu8ToNiVow92PfETBk5Z6HWuAEG7RVXVD",
            "t2MSLT1n4eQ87QC2FAxMvuTZ84zDzEj7FhQ",
            "t2JZNFrWv1c4RqkCmDN9iRkPsG8xAZFdyGS",
            "t2AyjEVUCf5jthGHZjwfbztDBHQbztkJB5v",
            "t2Gs6dTYCzaFdHSeT91zaFLKmYzyqYY3NnP",
            "t2FXfNK7iQhTdMFcGUyrizqXQE5qbmPK6zc",
            "t2UqLwQ85pR1fdFMoUzXadXRB97JxP6vTWY",
            "t2BocGBq7iBXQP8UQiousNVwU8M6AqUtaRx",
            "t2VGGdXhspjF3iQvbWZW2zPNSDRSYauBcM3",
            "t2HTNHicoeEXxsX1wVhsqsX3LgzRq2pYgWH",
            "t2UiVSyM1vuvs6xP3157ytuYMKN6MuqmgJE",
            "t2UmPyNoWSVUgyPzEXzFGN5GS96jMH2kreW",
            "t2MQWZJHxZF5zSw6LbZ3S7jqoLX1y6SWLHQ",
            "t2VUR1c1aFaTUo93uhi7rfFVRRZaT1aQYbv",
            "t2NgLU6QCJhCKgBsR5uX6R4ds82jymzMoMJ",
            "t2RorFwMUEb7NamvXFi3jCXitAdRoQtU1Hs",
            "t2FFtmwePBnYaRVRVg1wsoBPxDzGMLrz3Jv",
            "t2GH3734fKEhPo3NvvAZQazsFf3V51oR4c2",
            "t2Ev3twAmUmono3gM2Q6RsfhRiryy7TnX5E",
            "t2EmhhAjh6cLpyw6Yc9QEXvsjm7qdKpgFQP",
            "t2Gy5N7DYbEZmiHqm3m8Re25a8Bxu7e36ju",
            "t2LVSaxizciFWfc5gr1xccHXT115RSnQ13r",
            "t28zy3Qiq3FtMeB2PCEysF7R5TgW5UfZN1N",
            "t2FcN7o26gRCc8ZuSZcc7X7APPRqWQ5a3W2",
            "t27QTHP9qoi5HkiTqx4JV86MGG37aikK51s",
            "t2CwQ6H9GPT77nqRwkHCuVcyGvtbhxWHfAk",
            "t2HLUDaoimaaSpQhHnvbqpKg6Fi37rAo6cx",
            "t2Ebuq1FX7Qzi3ur1FnwsDMvfNBFjqVqDGX",
            "t2Bca3HbSbwgQp1ZhzheNvGfpwBoU6Syt8G",
            "t2EurfAqyJMsCyx6ujYecQSxrPPY7xxTqcB",
            "t2R1kJGeNhLpKx1dKNCnBUq1BkxBVJjQdcp",
            "t2M3x9koBJWJS1F9bGtWXTsVfr5pesWSTbR",
            "t2La4mEMruVTtBqhndS7zRvmi2WsqWUjPQz",
            "t29GwTHLXxYgF5k7SSj7XFaHB7JsocM9bDU",
            "t2Awpdv7yG2QFeHeq17J1qCSXRw1AM3mfmz",
            "t2BfotpLdNhhewRp9nXpBBYViBaq4y1Lnj5",
            "t2F4CH89prySyGZHUiPYJUjnZk9UPXgLBbf",
            "t2DNx1KzP8a2S3kZgAPngso9ptva5gE7Jbn",
            "t2Eb7orwhjGcu4wYwHBzN5BoXzroPGq3CoM",
            "t2BXYmM21WCdHiC1KiwQVHxaTvLQJpqXTvH",
            "t27Y6774dwAcCFvYrhDKTXgaxtUewAdZdtz",
            "t2JvmRjZnViBZXJJBekDygdvGTCRNWgFEK2",
            "t2PL5W7qy1DKNRPWECbaZ6gV9GEzMn8h97Z",
            "t2S1JaefdSNwaUexdr6ZtNJhqZS8uDGSNFg",
            "t2BTunj4VB44Q22crWpT1ykoBvNGFKMnD7N",
            "t2G7DkSoEUJGaEBH6erKsXemoHFqqTRaSiZ",
            "t2Ldg8Bc6AWDuESqPgUoumWfCYw3zqKF8s9",
            "t2Ft4QMMiJfKXVbhyGBrkwjnfn5ua73VuLo",
            "t26xLxd4Fabbotkc9gfFwpCVHoZG1W9rmN7",
            "t2DyghJMpK6rRKPEAL3DBKmCntUcj8bUiHg",
            "t2RSYhCsgw2AdBiUUyXBCkFf2xE9ddwyESD",
            "t26fv5NLiFYXMmfQnvqcJXcYnt5NY41eqrv",
            "t2Ppht55eXKC1BX7pfusJxZqbHnkp9oWbBW",
            "t2P4AWJ5C4ySU3KzfehAeppH2BV4Y87w34z",
            "t28zjDUH2Gkvt8Ytb8UrW7L6G5U1QMwJFM3",
            "t2JXDd9pumryTAXqDD98vDLS2ZLSQCNQrYZ",
            "t2BNuNGnGq49MZzr7SH8WtEE7sSwZ9n3bsz",
            "t2QumKdHZhkFD6ntrzJ9zJAga2QemEgqc9r",
            "t2UKz2L7V3C6GTeBPDXmQnwMyqKEbgMpuXg",
            "t2CyVugoafiDYpeSNd9DGZEng6Bpr4tqa3d",
            "t2GR9eEen8KUDjhQG1opC1aFt27zxdtufnF",
            "t2JKYuSRNupdHdTR91tqR4xsaU6friVJJgv",
            "t2D2yMZEM3K8ap6iLo3FX2g1Ch9coPSVq2R",
            "t2SeFu34eiE2rCPFpxrN8im6ZvcwMpdKnit",
            "t2KH46EXQy5wnZHDGVDA7Q13FdRkdQ3LUou",
            "t2UsTpuVqP6ZubtN8tQGPnh7Cqjjf1hoefd",
            "t2Dd119xiqDbF9QzWwYfnYWUPfqgnL1CNFu",
            "t29PjecMhv6EygD8W6smcMHAB8MSHQY3YnQ",
            "t2BDZpxgcMRzqgKbDBiXRXrvL3VwD7G8cLc",
            "t2MwiKqfCMdy7o96bXvbZ5aGCrRmVfVWVfA",
            "t2Vhkny4jNjy6ZD53jeQzsdgZiZyejwRsgY",
            "t2K3ouBrLAbYwZv6beoHjzfsE1AbYVa6PuE",
            "t2DskMSpWs8i9vK2PhNpi9Mu2qJSvEDi8UZ",
            "t2JB2Uz3eVWrxFhas1B1cSXLP22JHbRNYtL",
            "t2ArYKW1L8hRoCDK9odNmD4piRwFheErWL1",
            "t2K1zKGHrkibiFoYJ5GtfHe5xJecJPEvFwQ",
            "t2VnABknMprtMk8y5AdDCBr2R9QZnMhfqSm",
            "t2FbjEsP9eeQr5PmP7yC3fopPTuYS9E9VgN",
            "t2Sn2XUPZEnFcggB77jvxBqX6LcjdCzcJUs",
            "t2SEK3Tw5FYYUaeZcF5QemfeG3tiorrxNKp",
            "t2D78THpHVodnhiREjF22A3KRznor5pPnR1",
            "t2GyqFdkf6FoQTShEhLGsNrTxAWqmeq4pui",
            "t2HnNgFLznEqaokYq8PBV44uzRwAmJXQeKd",
            "t2PpHVStdHvWkzXsyuyPYQQq96ZRQu7ALpE",
            "t2FHbHM9rKKHZe74HRBNozwNdRsExug8tCw",
            "t29tM6DkMPSVp9R3g7UjZjvsobKhsbsRqFL",
            "t2K2KixLVJo19phPJMv9ApSiFmxQCSQUvc9",
            "t2AWJcGVUMWFC8A9KC3PL7qoCb1vxSzxbJP",
            "t26p8FyjHmhqZ6duzhRFLCQcExh1TuCD1sC",
            "t27x5n41uRNF3tJkb3Lg1CMomUjTNZwtUfm",
            "t2VhRQJ9xeVkVVk7ic21CtDePKmHnrDyF8Z",
            "t27hL1iAsTHBPWrdc1qYGSSTc3pTyBqohd4",
            "t2RqLYWG8Eo4hopDsn1m8GUoAWtjZQEPE9s",
            "t2V1osVDkcwYFL4PF9qG8t9Ez1XRVMAkAb6"
        };
        vCommunityFeeStartHeight = 200;
        vCommunityFeeLastHeight = 1400000;
        assert(vCommunityFeeAddress.size() <= GetLastCommunityFeeBlockHeight());
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}

// Index variable i ranges from 0 - (vCommunityFeeAddress.size()-1)
std::string CChainParams::GetCommunityFeeAddressAtHeight(int nHeight) const {
    int maxHeight = GetLastCommunityFeeBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vCommunityFeeAddress.size()) / vCommunityFeeAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vCommunityFeeAddress[i];
}

// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetCommunityFeeScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= GetLastCommunityFeeBlockHeight());

    CTxDestination address = DecodeDestination(GetCommunityFeeAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetCommunityFeeAddressAtIndex(int i) const {
    assert(i >= 0 && i < vCommunityFeeAddress.size());
    return vCommunityFeeAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

int validEHparameterList(EHparameters *ehparams, unsigned long blockheight, const CChainParams& params){
    //if in overlap period, there will be two valid solutions, else 1.
    //The upcoming version of EH is preferred so will always be first element
    //returns number of elements in list
    if(blockheight >= params.eh_epoch_2_start() && blockheight > params.eh_epoch_1_end()){
        ehparams[0] = params.eh_epoch_2_params();
        return 1;
    }
    if(blockheight < params.eh_epoch_2_start()){
        ehparams[0] = params.eh_epoch_1_params();
        return 1;
    }
    ehparams[0] = params.eh_epoch_2_params();
    ehparams[1] = params.eh_epoch_1_params();
    return 2;
}

bool checkEHParamaters(int solSize, int height, const CChainParams& params) {
    // Block will be validated prior to mining, and will have a zero length
    // equihash solution. These need to be let through.
    if (height == 0) {
        return true;
    }

    //allocate on-stack space for parameters list
    EHparameters ehparams[MAX_EH_PARAM_LIST_LEN];
    int listlength = validEHparameterList(ehparams, height, params);
    for(int i = 0; i < listlength; i++){
        LogPrint("pow", "checkEHParamaters height: %d n:%d k:%d solsize: %d \n", 
            height, ehparams[i].n, ehparams[i].k, ehparams[i].nSolSize);
        if (ehparams[i].nSolSize == solSize)
            return true;
    }

    return false;
}
