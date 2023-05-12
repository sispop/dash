// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2014-2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <miner.h>

#include <amount.h>
#include <chain.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <timedata.h>
#include <util/moneystr.h>
#include <util/system.h>
#include <util/validation.h>
#include <validation.h>
#include <evo/specialtx.h>
#include <evo/cbtx.h>
#include <evo/simplifiedmns.h>
#include <llmq/blockprocessor.h>
#include <llmq/chainlocks.h>
#include <llmq/utils.h>
#include <masternode/payments.h>

#include <crypto/randomx/randomx.h>
#include <boost/thread.hpp>
#include <algorithm>
#include <utility>
#include <vector>

const char * RANDOMX_STRING = "randomx";

bool fGenerateActive = false;

bool GenerateActive() { return fGenerateActive; };

int nMiningAlgorithm = MINE_RANDOMX;

void setGenerate(bool fGenerate) { fGenerateActive = fGenerate; };

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;
    int nPoWType;
    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams, nPoWType);

    return nNewTime - nOldTime;
}

BlockAssembler::Options::Options() {
    blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    nBlockMaxSize = DEFAULT_BLOCK_MAX_SIZE;
}

BlockAssembler::BlockAssembler(const CChainParams& params, const Options& options) : chainparams(params)
{
    blockMinFeeRate = options.blockMinFeeRate;
    // Limit size to between 1K and MaxBlockSize()-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MaxBlockSize(fDIP0001ActiveAtTip) - 1000), (unsigned int)options.nBlockMaxSize));
}

static BlockAssembler::Options DefaultOptions()
{
    // Block resource limits
    BlockAssembler::Options options;
    options.nBlockMaxSize = DEFAULT_BLOCK_MAX_SIZE;
    if (gArgs.IsArgSet("-blockmaxsize")) {
        options.nBlockMaxSize = gArgs.GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    }
    CAmount n = 0;
    if (gArgs.IsArgSet("-blockmintxfee") && ParseMoney(gArgs.GetArg("-blockmintxfee", ""), n)) {
        options.blockMinFeeRate = CFeeRate(n);
    } else {
        options.blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    }
    return options;
}

BlockAssembler::BlockAssembler(const CChainParams& params) : BlockAssembler(params, DefaultOptions()) {}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockSize = 1000;
    nBlockSigOps = 100;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

Optional<int64_t> BlockAssembler::m_last_block_num_txs{nullopt};
Optional<int64_t> BlockAssembler::m_last_block_size{nullopt};

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, int nPoWType)
{
    int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    CBlock* const pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    LOCK2(cs_main, mempool.cs);

    CBlockIndex* pindexPrev = ::ChainActive().Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    bool fDIP0003Active_context = nHeight >= chainparams.GetConsensus().DIP0003Height;
    bool fDIP0008Active_context = nHeight >= chainparams.GetConsensus().DIP0008Height;

    pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus(), chainparams.BIP9CheckMasternodesUpgraded());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);

    pblock->nTime = GetAdjustedTime();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    if (fDIP0003Active_context) {
        for (const Consensus::LLMQParams& params : llmq::CLLMQUtils::GetEnabledQuorumParams(pindexPrev)) {
            std::vector<CTransactionRef> vqcTx;
            if (llmq::quorumBlockProcessor->GetMineableCommitmentsTx(params,
                                                                     nHeight,
                                                                     vqcTx)) {
                for (const auto& qcTx : vqcTx) {
                    pblock->vtx.emplace_back(qcTx);
                    pblocktemplate->vTxFees.emplace_back(0);
                    pblocktemplate->vTxSigOps.emplace_back(0);
                    nBlockSize += qcTx->GetTotalSize();
                    ++nBlockTx;
                }
            }
        }
    }

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    addPackageTxs(nPackagesSelected, nDescendantsUpdated);

    int64_t nTime1 = GetTimeMicros();

    m_last_block_num_txs = nBlockTx;
    m_last_block_size = nBlockSize;
    LogPrintf("CreateNewBlock(): total size %u txs: %u fees: %ld sigops %d\n", nBlockSize, nBlockTx, nFees, nBlockSigOps);

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;

    // NOTE: unlike in bitcoin, we need to pass PREVIOUS block height here
    CAmount blockReward = nFees + GetBlockSubsidy(pindexPrev->nBits, pindexPrev->nHeight, Params().GetConsensus());

    // Compute regular coinbase transaction.
    coinbaseTx.vout[0].nValue = blockReward;

    if (!fDIP0003Active_context) {
        coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    } else {
        coinbaseTx.vin[0].scriptSig = CScript() << OP_RETURN;

        coinbaseTx.nVersion = 3;
        coinbaseTx.nType = TRANSACTION_COINBASE;

        CCbTx cbTx;

        if (fDIP0008Active_context) {
            cbTx.nVersion = 2;
        } else {
            cbTx.nVersion = 1;
        }

        cbTx.nHeight = nHeight;

        CValidationState state;
        if (!CalcCbTxMerkleRootMNList(*pblock, pindexPrev, cbTx.merkleRootMNList, state, ::ChainstateActive().CoinsTip())) {
            throw std::runtime_error(strprintf("%s: CalcCbTxMerkleRootMNList failed: %s", __func__, FormatStateMessage(state)));
        }
        if (fDIP0008Active_context) {
            if (!CalcCbTxMerkleRootQuorums(*pblock, pindexPrev, cbTx.merkleRootQuorums, state)) {
                throw std::runtime_error(strprintf("%s: CalcCbTxMerkleRootQuorums failed: %s", __func__, FormatStateMessage(state)));
            }
        }

        SetTxPayload(coinbaseTx, cbTx);
    }

    // Update coinbase transaction with additional info about masternode and governance payments,
    // get some info back to pass to getblocktemplate
    FillBlockPayments(coinbaseTx, nHeight, blockReward, pblocktemplate->voutMasternodePayments, pblocktemplate->voutSuperblockPayments);

    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vTxFees[0] = -nFees;

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus(), nPoWType);
    pblock->nNonce         = 0;
    pblocktemplate->nPrevBits = pindexPrev->nBits;
    pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(*pblock->vtx[0]);

    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }
    int64_t nTime2 = GetTimeMicros();

    LogPrint(BCLog::BENCHMARK, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n", 0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated, 0.001 * (nTime2 - nTime1), 0.001 * (nTime2 - nTimeStart));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, unsigned int packageSigOps) const
{
    if (nBlockSize + packageSize >= nBlockMaxSize)
        return false;
    if (nBlockSigOps + packageSigOps >= MaxBlockSigOps(fDIP0001ActiveAtTip))
        return false;
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - safe TXs in regard to ChainLocks
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    for (CTxMemPool::txiter it : package) {
        if (!IsFinalTx(it->GetTx(), nHeight, nLockTimeCutoff))
            return false;
        if (!llmq::chainLocksHandler->IsTxSafeForMining(it->GetTx().GetHash())) {
            return false;
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblocktemplate->block.vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOps.push_back(iter->GetSigOpCount());
    nBlockSize += iter->GetTxSize();
    ++nBlockTx;
    nBlockSigOps += iter->GetSigOpCount();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        LogPrintf("fee %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

int BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    int nDescendantsUpdated = 0;
    for (CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc))
                continue;
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCountWithAncestors -= it->GetSigOpCount();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
    return nDescendantsUpdated;
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BlockAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert (it != mempool.mapTx.end());
    return mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it);
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated)
{
    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
        // First try to find a new transaction in mapTx to evaluate.
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
                SkipMapTxEntry(mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        unsigned int packageSigOps = iter->GetSigOpCountWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOps = modit->nSigOpCountWithAncestors;
        }

        if (packageFees < blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOps)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockSize > nBlockMaxSize - 1000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final and safe
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, sortedEntries);

        for (size_t i=0; i<sortedEntries.size(); ++i) {
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce));
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}



CCriticalSection cs_nonce;
static int32_t nNonce_base = 0;
static arith_uint256 nHashes = 0;
static int32_t nTimeStart = 0;
static int32_t nTimeDuration = 0;

double GetHashSpeed() {
    LOCK(cs_nonce);
    if (!nTimeDuration) return 0;
    return arith_uint256(nHashes/nTimeDuration).getdouble();
}

class ThreadHashSpeed {
  public:
    ThreadHashSpeed() {}
    ThreadHashSpeed(ThreadHashSpeed&& ths) {
        LOCK(ths.cs);
        nHashes = ths.nHashes;
        nTimeDuration = ths.nTimeDuration;
    }
    CCriticalSection cs;
    arith_uint256 nHashes = 0;
    int32_t nTimeDuration = 0;
};

CCriticalSection cs_hashspeeds;
std::vector<ThreadHashSpeed> vHashSpeeds;

void ClearHashSpeed() {
    {
        LOCK(cs_nonce);
        nHashes = 0;
        nTimeStart = 0;
        nTimeDuration = 0;
    }
    {
        LOCK(cs_hashspeeds);
        for (auto& ths : vHashSpeeds) {
            LOCK(ths.cs);
            ths.nHashes = 0;
            ths.nTimeDuration = 0;
        }
    }
}

double GetRecentHashSpeed() {
    LOCK(cs_hashspeeds);
    double nTotalHashSpeed = 0.0;
    for (auto& hs : vHashSpeeds) {
        LOCK(hs.cs);
        if (hs.nTimeDuration > 0)
            nTotalHashSpeed += hs.nHashes.getdouble() / hs.nTimeDuration;
    }
    return nTotalHashSpeed;
}

void BitcoinRandomXMiner(std::shared_ptr<CReserveScript> coinbaseScript, int vm_index, uint32_t startNonce, ThreadHashSpeed* pThreadHashSpeed) {
    LogPrintf("Quagba RandomX Miner started\n");

    unsigned int nExtraNonce = 0;
    static const int nInnerLoopCount = RANDOMX_INNER_LOOP_COUNT;
    int32_t nLocalStartTime = 0;
    bool fBlockFoundAlready = false;

    while (GenerateActive())
    {
        boost::this_thread::interruption_point();

        if (GenerateActive()) { // If the miner was turned on and we are in IsInitialBlockDownload(), sleep 60 seconds, before trying again
            if (::ChainstateActive().IsInitialBlockDownload() && !gArgs.GetBoolArg("-genoverride", false)) {
                UninterruptibleSleep(std::chrono::milliseconds{60000});
                continue;
            }
        }

        CScript scriptMining;
        if (coinbaseScript)
            scriptMining = coinbaseScript->reserveScript;
        std::unique_ptr<CBlockTemplate> pblocktemplate(BlockAssembler(Params()).CreateNewBlock(scriptMining, false));
        if (!pblocktemplate || !pblocktemplate.get())
            continue;
        if (!(pblocktemplate->nFlags & TF_SUCCESS)) {
            continue;
        }

        if (fKeyBlockedChanged)
            continue;

        CBlock *pblock = &pblocktemplate->block;

        {
            LOCK(cs_nonce);
            nExtraNonce = nNonce_base++;
            nLocalStartTime = GetTime();
            if (!nTimeStart)
                nTimeStart = nLocalStartTime;
        }

        pblock->nNonce = startNonce;
        IncrementExtraNonce(pblock, ::ChainActive().Tip(), nExtraNonce);

        int nTries = 0;
        if (pblock->IsRandomX() ) {
            arith_uint256 bnTarget;
            bool fNegative;
            bool fOverflow;

            if (fKeyBlockedChanged || CheckIfMiningKeyShouldChange(GetKeyBlock(pblock->nHeight))) {
                fKeyBlockedChanged = true;
                continue;
            }

            bnTarget.SetCompact(pblock->nBits, &fNegative, &fOverflow);

            while (nTries < nInnerLoopCount) {
                boost::this_thread::interruption_point();

                if (fKeyBlockedChanged || CheckIfMiningKeyShouldChange(GetKeyBlock(pblock->nHeight))) {
                    fKeyBlockedChanged = true;
                    break;
                }

                if (pblock->nHeight <= ::ChainActive().Height()) {
                    fBlockFoundAlready = true;
                    break;
                }

                char hash[RANDOMX_HASH_SIZE];
                // Build the header_hash
                uint256 nHeaderHash = pblock->GetRandomXHeaderHash();

                randomx_calculate_hash(vecRandomXVM[vm_index], &nHeaderHash, sizeof uint256(), hash);

                uint256 nHash = RandomXHashToUint256(hash);

                // Bypass regtest check, actually allows us to generate blocks in regtest mode instantly
                if (Params().NetworkIDString() == "regtest") {
                    break;
                }

                // Check proof of work matches claimed amount
                if (UintToArith256(nHash) < bnTarget) {
                    break;
                }

                ++nTries;
                ++pblock->nNonce;
            }
        }

        double nHashSpeed = 0;
        {
            LOCK(cs_nonce);
            nTimeDuration = GetTime() - nTimeStart;
            if (!nTimeDuration) nTimeDuration = 1;
            {
                nHashes += nTries;
                nHashSpeed = arith_uint256(nHashes/nTimeDuration).getdouble();
            }
        }
        if (pThreadHashSpeed != nullptr) {
            double nRecentHashSpeed = 0;
            {
                LOCK(pThreadHashSpeed->cs);
                pThreadHashSpeed->nHashes = nTries;
                pThreadHashSpeed->nTimeDuration = std::max<int32_t>(GetTime() - nLocalStartTime, 1);
                nRecentHashSpeed = pThreadHashSpeed->nHashes.getdouble() / pThreadHashSpeed->nTimeDuration;
            }
            LogPrint(BCLog::MINING, "%s: RandomX PoW Hashspeed %d hashes/s (this thread this round: %.03f hashes/s\n", __func__, nHashSpeed, nRecentHashSpeed);
        } else {
            LogPrint(BCLog::MINING, "%s: RandomX PoW Hashspeed %d hashes/s\n", __func__, nHashSpeed);
        }

        if (nTries == nInnerLoopCount) {
            continue;
        }

        if (fBlockFoundAlready) {
            fBlockFoundAlready = false;
            continue;
        }

        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
        if (!ProcessNewBlock(Params(), shared_pblock, true, nullptr)) {
            LogPrint(BCLog::MINING, "%s: Failed to process new block\n", __func__);
            continue;
        }

        coinbaseScript->KeepScript();
    }
}


void ThreadRandomXBitcoinMiner(std::shared_ptr<CReserveScript> coinbaseScript, const int vm_index, const uint32_t startNonce)
{
    LogPrintf("%s: starting\n", __func__);
    boost::this_thread::interruption_point();
    try {
        ThreadHashSpeed* pThreadHashSpeed = nullptr;
        {
            LOCK(cs_hashspeeds);
            if (0 <= vm_index && vm_index < vHashSpeeds.size())
                pThreadHashSpeed = &vHashSpeeds[vm_index];
        }
        BitcoinRandomXMiner(coinbaseScript, vm_index, startNonce, pThreadHashSpeed);
        boost::this_thread::interruption_point();
    } catch (std::exception& e) {
        LogPrintf("%s: exception\n", __func__);
    } catch (boost::thread_interrupted) {
       LogPrintf("%s: interrupted\n", __func__);
    }

    LogPrintf("%s: exiting\n", __func__);
}

boost::thread_group* pthreadGroupPoW;
void LinkPoWThreadGroup(void* pthreadgroup)
{
    pthreadGroupPoW = (boost::thread_group*)pthreadgroup;
}

boost::thread_group* pthreadGroupRandomX;
void LinkRandomXThreadGroup(void* pthreadgroup)
{
    pthreadGroupRandomX = (boost::thread_group*)pthreadgroup;
}

void GenerateBitcoins(bool fGenerate, int nThreads, std::shared_ptr<CReserveScript> coinbaseScript)
{
    if (!pthreadGroupPoW) {
        error("%s: pthreadGroupPoW is null! Cannot mine.", __func__);
        return;
    }
    setGenerate(fGenerate);

    if (nThreads < 0) {
        // In regtest threads defaults to 1
        nThreads = 1;
    }

    // Set a minimum of 4 threads when mining randomx
    if (GetMiningAlgorithm() == MINE_RANDOMX && nThreads < 4) {
        nThreads = 1;
    }

    // Close any active mining threads before starting new threads
    if (pthreadGroupPoW->size() > 0) {
        pthreadGroupPoW->interrupt_all();
        pthreadGroupPoW->join_all();

        DeallocateVMVector();
        DeallocateDataSet();
    }

    if (pthreadGroupRandomX->size() > 0) {
        pthreadGroupRandomX->interrupt_all();
        pthreadGroupRandomX->join_all();
    }

    if (nThreads == 0 || !fGenerate)
        return;

    LOCK(cs_hashspeeds);
    vHashSpeeds.resize(nThreads);

    // XXX - Todo - find a way to clean out the old threads or reuse the threads already created
  /*  if (GetMiningAlgorithm() == MINE_RANDOMX) {
        pthreadGroupRandomX->create_thread(boost::bind(&StartRandomXMining, pthreadGroupPoW,
                                           nThreads, coinbaseScript));
  //      pthreadGroupRandomX->create_thread(std::bind(&StartRandomXMining, pthreadGroupPoW, nThreads, coinbaseScript));
    } else {
        for (int i = 0; i < nThreads; i++)
            pthreadGroupPoW->create_thread(std::bind(&ThreadRandomXBitcoinMiner, coinbaseScript, &vHashSpeeds[i]));
    }*/
}

int GetMiningAlgorithm() {
    return nMiningAlgorithm;
}

bool SetMiningAlgorithm(const std::string& algo, bool fSet) {
    int setAlgo = -1;

    if (algo == RANDOMX_STRING) setAlgo = MINE_RANDOMX;

    if (setAlgo != -1) {
        if (fSet) nMiningAlgorithm = setAlgo;
        return true;
    }

    return false;
}
