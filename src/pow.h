// Copyright (c) 2019 Veil developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>
#include <sync.h>
#include <stdint.h>
#include <memory>
#include <arith_uint256.h>

class CBlockHeader;
class CBlockIndex;
class uint256;
class randomx_vm;
class randomx_dataset;
class randomx_cache;
class CReserveScript;

extern std::vector<randomx_vm*> vecRandomXVM;
extern bool fKeyBlockedChanged;
extern  CCriticalSection cs_randomx_validator;

arith_uint256 GetPowLimit(int nPoWType);
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&, int nPoWType);
unsigned int DarkGravityWave(const CBlockIndex* pindexLast, const Consensus::Params& params, int nPoWType);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&, int algo = 0);

bool IsRandomXLightInit();
void InitRandomXLightCache(const int32_t& height);
void KeyBlockChanged(const uint256& new_block);
bool CheckIfMiningKeyShouldChange(const uint256& check_block);
void CheckIfValidationKeyShouldChangeAndUpdate(const uint256& check_block);
void DeallocateRandomXLightCache();
uint256 GetCurrentKeyBlock();
uint256 GetKeyBlock(const uint32_t& nHeight);
randomx_vm* GetMyMachineValidating();

/** Check whether a block hash satisfies the randomx-proof-of-work requirement specified by nBits */
bool CheckRandomXProofOfWork(const CBlockHeader& block, unsigned int nBits, const Consensus::Params&);
uint256 RandomXHashToUint256(const char* p_char);

void DeallocateVMVector();
void DeallocateDataSet();
void DeallocateCache();
void StartRandomXMining(void* pPowThreadGroup, const int nThreads, std::shared_ptr<CReserveScript> pCoinbaseScript);
void CreateRandomXInitDataSet(int nThreads, randomx_dataset* dataset, randomx_cache* cache);

#endif // BITCOIN_POW_H
