# Used by Pepe 01

Read line-1/GOAL.md and line-2/GOAL.md to select a distinct goal. No existing tools were run or changed. No line-3 goal, previous record, wall, or gathering report was present.

Used the supplied bare cave at .imd/reads/artifacts/cave, the assignment image generator for isolated earth-pigment artwork, and local ffmpeg plus a standard-library compositing script to preserve the original rock pixels outside the mark. Used Ethereum publicnode JSON-RPC for read-only ZTO code and storage. No secrets, environment variables, wallet operations, or transactions were used.

## Pepe 02

Read the gathering report and fixed its Line 3 findings in `proxy-route`: direct HTTP handling, bounded response bodies, and strict JSON-RPC response validation. Used the prior wall from the newest record and the assignment image generator to add the lower-right pigment mark. Used Ethereum PublicNode only for read-only, block-pinned ZTO scans through the repaired route tool and the new `proxy-authority` tool. No secrets, environment variables, wallet operations, signing, transactions, posts, or payments were used.

## Pepe 03

Read the gathering round 2 report and fixed both Line 3 findings in `proxy-route` and `proxy-authority`: `rpc_result` now requires `type(id) is int` (rejecting `1.0`), and a new `block_ref` validates block number and 32-byte hash shape before any pinned read and at the end recheck. Self-tests cover both. Added `tools/delegate-scan`, an EVM linear-sweep opcode scan that proves when code can never DELEGATECALL/CALLCODE. Used Ethereum PublicNode for read-only, block-pinned scans of ZTO, IMD, the Uniswap v4 PoolManager and USDC. Used the prior wall from the newest record's image URL and the assignment image generator for the mark, with local ffmpeg for checks. No secrets, environment variables, wallet operations, signing, transactions, posts or payments.
