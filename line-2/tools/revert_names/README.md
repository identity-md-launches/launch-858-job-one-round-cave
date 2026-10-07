# Revert names

`revert_names.py` turns the bare custom-error selector a call preview leaves behind (for example `0xdb42144d`) into a named, decoded error such as `InsufficientBalance(address,uint256,uint256)` with its argument values. It uses only the Python standard library, including its own Keccak-256, so selectors are computed rather than looked up on a third-party site.

What it does:

- Hashes a built-in catalog of 136 widely deployed error signatures: ERC-6093 / OpenZeppelin v5, common unprefixed token errors, Solady, Uniswap v4 core, Permit2 and the Universal Router, plus `Error(string)` and `Panic(uint256)` with panic-code meanings. `--signature 'MyError(address,uint256)'` adds your contract's own errors (repeatable). `--list` prints the catalog with its selectors.
- Strictly decodes arguments (address, bool, uintN, intN, bytesN, bytes, string). It rejects dirty padding, out-of-range values and truncated data instead of guessing.
- Names nested reasons recursively, up to three levels: a Uniswap v4 `WrappedError(hook, selector, reason, details)` or router `ExecutionFailed(index, bytes)` gets its inner `reason` named too.
- `--code-of ADDRESS` reads the deployed bytecode with `eth_getCode` and lists which catalog errors appear as PUSH4 constants or as left-aligned PUSH32 constants. Push data is skipped and the Solidity metadata trailer is dropped. This tells you which errors that contract can actually raise. It also reports whether the selector you are decoding is present.
- `--demo` is a live demo. It pins the latest block, then uses the sibling `call_preview` module to `eth_call` a one-base-unit ZTO transfer from an empty address. It names the revert and confirms the selector against ZTO's own bytecode.

Nothing is signed or sent, and no keys or environment variables are read. Proxies are bypassed explicitly, responses are capped at 262144 bytes, and the JSON-RPC envelope is validated the same way `call_preview` does.

Run from the repository root:

```sh
python3 -B line-2/tools/revert_names/revert_names.py --demo
```

Offline checks (no network): `python3 -B line-2/tools/revert_names/revert_names.py --self-test`. Other examples: `--data 0x4e487b71…11` names an arithmetic-overflow panic. `--code-of 0x000000000004444c5dc75cB358380D2e3dE08A90` lists the Uniswap v4 errors present in the PoolManager.

## What happened when I tried it

- `--self-test`: all 19 checks passed. They cover Keccak vectors (the empty string, `transfer(address,uint256)` → `0xa9059cbb`, `Error(string)`, `Panic(uint256)`, ERC-6093), decoding of strings, panics, negative `int24` values, malformed and truncated words, user signatures, nested `WrappedError`, and the bytecode push-data scanner.
- `--demo` against PublicNode at block 26136786: the preview reverted with `0xdb42144d`. That is `InsufficientBalance(address,uint256,uint256)` = (`0x…0001`, balance `0`, needed `1`), and the selector is present in ZTO's 1287-byte bytecode. The only other catalog error in ZTO is `InvalidReceiver(address)`. Before this tool, line 2's preview could only say "custom error 0xdb42144d".
- `--code-of` on the Uniswap v4 PoolManager (24009 code bytes) found 36 catalog v4 errors, including `CurrencyNotSettled()`, `PoolNotInitialized()`, `PriceLimitAlreadyExceeded(uint160,uint160)` and `WrappedError(address,bytes4,bytes,bytes)`.
- ZTO has two more 4-byte constants (`0x0c95cf27`, `0x270af7ed`) that no catalog signature I tried matches. They may be other errors or plain constants.

## Limits

A selector match is a hash match, not proof of which source the error came from: different signatures can collide, and several catalog entries may match, in which case all are shown. Presence in bytecode is evidence that the contract can emit an error, not proof. Errors raised by a contract it calls will not be in its own bytecode, and a 4-byte constant may not be an error at all. Errors outside the catalog stay as bare selectors until you supply `--signature`. Arrays and tuples are not decoded.
