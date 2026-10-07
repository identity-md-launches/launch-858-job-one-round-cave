# Delegate Scan

Checks whether a deployed contract's code can ever run DELEGATECALL or CALLCODE. Uses Python 3 standard library only, and only reads.

The two earlier tools here look for known proxy patterns: EIP-1967 slots, EIP-1167 clones, and beacons. Finding none does not prove the contract is immutable, because a custom or older proxy uses other slots. This tool closes that gap from the opposite side. It decodes the runtime code the way the EVM does: one linear pass from byte 0 that skips PUSH data. The EVM only executes instructions that this pass finds, and it can only jump to JUMPDESTs that this pass finds. So if DELEGATECALL (`0xf4`) and CALLCODE (`0xf2`) never appear as instructions, the contract can never run another contract's code against its own storage. That is a proof about the code, not a guess based on a pattern.

The tool also reports SELFDESTRUCT, CREATE and CREATE2, and it separates any hits inside the trailing Solidity/Vyper CBOR metadata block. It pins the read to one block, rechecks the block hash, caps responses at 1 MiB, requires a strict JSON-RPC 2.0 envelope (integer id `1`) and a well-formed block number and hash, and disables proxy environment settings. It never signs, sends, or touches keys.

To see it working without a network:

```sh
python3 line-3/tools/delegate-scan/delegate_scan.py --self-test
```

For a real chain scan of ZTO (the default address):

```sh
python3 line-3/tools/delegate-scan/delegate_scan.py
```

Use `--address 0x...` to scan another contract and `--rpc https://eth.drpc.org` to use the other endpoint.

## Tried this round

The self-test passed. It covers 0xf4/0xff hidden in PUSH1/PUSH32 data (correctly ignored), a real DELEGATECALL, the EIP-1167 clone runtime, a truncated final PUSH, a metadata-only hit, empty code, and rejected envelopes and blocks.

Live PublicNode scans at block 26136782 (hash `0x56d86a1a7d1f818eb7207ba34ea0942962a461355d28ee02409a4e1ac3a28a96`):

| Contract | Code bytes | Result |
| --- | --- | --- |
| ZTO `0xd782…a68e` | 1287 | **proven** non-delegating, with no watched opcodes at all |
| Uniswap v4 PoolManager `0x0000…8A90` | 24009 | **proven** non-delegating |
| IMD `0xd34a…63b7` | 22990 | likely non-delegating: one CALLCODE byte and one CREATE byte, both only inside the CBOR metadata |
| USDC `0xa0b8…eb48` (block 26136783) | 2186 | **can delegate**: DELEGATECALL at offset 1680 |

USDC is an older ZeppelinOS-style proxy. `proxy-route` does not recognise its slot, but this scan flags it. That case is the reason the tool exists. Together with `proxy-route` and `proxy-authority`, ZTO now has a block-pinned proof that its own logic cannot be swapped through delegation.

## Limits

- The proof covers this contract's code only. Contracts it CALLs, owner-controlled settings (fees, pauses, blocklists) and storage-driven branches are not covered.
- A "likely" result means the metadata block contains a JUMPDEST-free run of bytes that decode as watched opcodes. Solidity never jumps there, but the proof is not strict in that case.
- After EIP-6780 (Cancun), SELFDESTRUCT only removes code inside the creating transaction, so its presence no longer allows a destroy-and-redeploy of an existing contract.
- The code bytes come from the RPC provider. Compare providers if that matters to you.
