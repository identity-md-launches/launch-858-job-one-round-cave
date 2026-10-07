# Compiler Trailer

Tells you which compiler built a deployed contract, and where its metadata lives,
even when nobody has published the source. Solidity and Vyper append a small CBOR
map to runtime bytecode (`solc` version, `ipfs` / `bzzr0` / `bzzr1` metadata hash).
This tool reads the code at one pinned block and decodes that trailer. When Sourcify
has the contract, it checks three things against what the chain returned: the
declared compiler version, Sourcify's copy of the on-chain bytecode, and the trailer
in Sourcify's recompiled bytecode.

Python 3 standard library only. Read-only: `eth_getBlockByNumber` then `eth_getCode`
pinned by block hash (EIP-1898, `requireCanonical`), PublicNode first and dRPC as
fallback, then one Sourcify GET. Uses an explicit empty proxy mapping, refuses redirects,
sets its own User-Agent, a 30 s timeout and an 8 MiB response cap, and requires
`jsonrpc == "2.0"` and an integer `id` that matches the request (`1.0` and `true` are
rejected). Reads no credentials, environment variables or files; signs and sends nothing.

Run it on ZTO, the default, from the repository root:

```sh
python3 -B line-4/tools/compiler-trailer/trailer.py
```

Offline demonstration, with no network:

```sh
python3 -B line-4/tools/compiler-trailer/trailer.py --self-test
```

Other contracts: `--address 0x...`. Skip Sourcify with `--no-sourcify`. Exit 0 means a
JSON report was printed, including `"trailer": null` for code with no trailer and
`"kind": "no_code"` for an empty account. Exit 1 means every RPC failed. Exit 2 means a bad address.

## What happened when I tried it (2026-10-07)

`--self-test`: all three PASS groups. Fixtures are real trailers read from mainnet
(ZTO, IMD, USDT) plus one synthetic Vyper-style array. Malformed, truncated, trailing-byte
and compiler-less CBOR are rejected, the IPFS hash is base58-encoded, and the fake transport
confirms that the code read is pinned by block hash and that proxy discovery never runs.

Live, every read pinned to a block hash:

| Contract | Block | Trailer | Sourcify cross-check |
| --- | --- | --- | --- |
| ZTO `0xd782…a68e` | 26136786 | solc 0.8.26, no metadata hash (`bytecodeHash: none`) | not verified at provider |
| IMD `0xd34a…63b7` | 26136787 | solc 0.8.26, IPFS `QmbeUgrzSGcxFDjsbhXyXzpvxuwqguRFsuPftmxTbkV3P6` | `exact_match`, all three checks agree → `consistent` |
| Uniswap v4 PoolManager | 26136787 | solc 0.8.26, no metadata hash | `match`, all three agree → `consistent` |
| USDT `0xdAC1…1ec7` | 26136789 | bzzr0 only (pre-0.5.9 solc writes no version) | `match`, code agrees, recompiled trailer differs → `code_agrees_metadata_differs` |
| `0x…0001` precompile | 26136787 | no code → `no_code` | skipped |

For ZTO this is new review context. Source Check (the sibling tool) finds no source at
Sourcify, but the chain itself says ZTO was built with solc 0.8.26 and
`bytecodeHash: none`. A reviewer reproducing it should start from that compiler and
setting. With no metadata hash, no IPFS lookup can recover the source.

The USDT row fixed a mislabel in my first draft, which marked any trailer difference
`inconsistent`. A Sourcify partial `match` *means* the code agrees and the metadata hash
does not, so that case now has its own status. A differing trailer on an `exact_match`,
a differing compiler version, or differing on-chain bytecode is still `inconsistent`.

## Limits

The trailer is written by the compiler and can be omitted (`appendCBOR: false`) or
imitated. It is a hint about the build, not proof of authorship, source or safety.
An IPFS CID points to a metadata JSON. This tool does not fetch it. Vyper support
recognises the map/array shapes but was checked only on a synthetic fixture. Only
Ethereum mainnet (chain 1) is supported. `codeSha256` is SHA-256, not keccak.
