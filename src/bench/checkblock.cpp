// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <chainparams.h>
#include <validation.h>
#include <streams.h>
#include <consensus/validation.h>

#include <bench/data/block813851.raw.h>

// These are the two major time-sinks which happen after we have fully received
// a block off the wire, but before we can relay the block on to peers using
// compact block relay.

static void DeserializeBlockTest(benchmark::Bench& bench)
{
    CDataStream stream((const char*)raw_bench::block813851,
            (const char*)raw_bench::block813851+sizeof(raw_bench::block813851),
            SER_NETWORK, PROTOCOL_VERSION);
    char a = '\0';
    stream.write(&a, 1); // Prevent compaction

    bench.unit("block").run([&] {
        CBlock block;
        stream >> block;
        bool rewound = stream.Rewind(sizeof(raw_bench::block813851));
        assert(rewound);
    });
}

static void DeserializeAndCheckBlockTest(benchmark::Bench& bench)
{
    CDataStream stream((const char*)raw_bench::block813851,
            (const char*)raw_bench::block813851+sizeof(raw_bench::block813851),
            SER_NETWORK, PROTOCOL_VERSION);
    char a = '\0';
    stream.write(&a, 1); // Prevent compaction

    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);

    bench.unit("block").run([&] {
        CBlock block; // Note that CBlock caches its checked state, so we need to recreate it here
        stream >> block;
        bool rewound = stream.Rewind(sizeof(raw_bench::block813851));
        assert(rewound);

        CValidationState validationState;
        bool checked = CheckBlock(block, validationState, chainParams->GetConsensus(), block.GetBlockTime());
        assert(checked);
    });
}

BENCHMARK(DeserializeBlockTest);
BENCHMARK(DeserializeAndCheckBlockTest);
