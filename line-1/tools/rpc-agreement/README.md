# RPC Agreement

Compare Ethereum mainnet providers at the same height before trusting a read. Uses Python standard library and the predecessor RPC Health transport, including bounded responses, strict envelopes, custom User-Agent and disabled proxy environment discovery. No installation, keys, signing, writes to the chain or configuration reads.

Run from the workspace root, offline:

```sh
python3 -B line-1/tools/rpc-agreement/compare.py --demo
```

For actual chain reads, omit `--demo`. Repeat `--endpoint https://...` to choose at least two distinct endpoints. Defaults are PublicNode and dRPC. Each provider is checked for mainnet and a fresh latest block, then asked explicitly for the lowest observed head height. Returned height and hash are checked. Status is `agreement`, `disagreement`, `lagging`, or `inconclusive`; only agreement exits 0. Head spread above `--max-lag` (default 3 blocks) is lagging. `--max-age` defaults to 120 seconds and `--timeout` to 12 seconds per request. Stale, missing, wrong-chain and failed responses cannot produce agreement.

## Tried

Seven offline cases passed: agreement across adjacent heads, conflicting hashes, excessive lag, transport failure, wrong requested height, stale blocks and wrong chain. Live PublicNode and dRPC both returned fresh mainnet block 26135598, then independently returned the requested height with hash `0xd0815022052fbbf8790e13921c5701943db12e2ebbd0d036eec8f7604e6c23df`. Status was agreement; head spread 0. RPC Health's original demo also passed.

## Limits

A sampled comparison is not ongoing availability measurement, consensus verification or proof of provider independence. A reorg between sequential requests can cause disagreement; retry and investigate. Freshness depends on the local clock. Shared infrastructure or dishonest providers can agree. No coin is needed for endpoint assessment.

## Round 03: reusable boundary repaired

Reproduced the gathering report: `compare(['only'], call=fixture, now=1000)`
returned `agreement`. The reusable function now raises `ValueError` before
transport for fewer than two distinct endpoint strings, empty names, non-string
entries, and a bare string/bytes argument. It materializes iterables once so a
generator supplies both the head and common-height passes. Endpoint names may
remain fixture labels for injected transports; the CLI still requires HTTPS.
Different strings do not prove different providers or infrastructure.

One command, from the repository root, exercises the repair without network:

```sh
python3 -B line-1/tools/rpc-agreement/compare.py --demo
```

Tried: all seven inherited scenarios, seven invalid provider sets (with a
transport that fails if called), and a two-provider generator passed. The
predecessor RPC Health demo also passed. A real read-only PublicNode/dRPC run
returned agreement at block 26136777, head spread 0, hash
`0xb7f87c2bd088518c72fc2e0d34e1323071bf123ba9454f55fe679cae5b423a78`.
These are local observations, not independent certification or future uptime.
