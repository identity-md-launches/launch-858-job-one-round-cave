#!/usr/bin/env python3
"""Name and decode the custom error inside Ethereum revert data, offline or after a live preview.

A custom-error revert is a 4-byte selector (keccak256 of the error signature)
followed by ABI-encoded arguments. This tool hashes a built-in catalog of
widely deployed error signatures (ERC-6093/OpenZeppelin, Solady, Uniswap v4,
Permit2, Universal Router) plus any you supply, decodes the arguments, and can
check which catalog selectors appear as PUSH4/PUSH32 constants in a contract's
deployed bytecode. Read-only: it sends no transaction and reads no keys.
"""

import argparse
import importlib.util
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

USER_AGENT = "IdentityMD-revert-names/1.0 (read-only)"
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"
MAX_RESPONSE_BYTES = 262144
ZTO = "0xd782bdea4ef02a0bd391eb9089470c8080f0a68e"

# --- Keccak-256 (Ethereum's pre-standard SHA-3 padding), standard library only.
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
       0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
       0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
       0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_MASK = (1 << 64) - 1


def _rotl(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _permute(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) for y in range(5)]
             for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data):
    rate = 136
    padded = bytearray(data) + b"\x01"
    padded += b"\x00" * (-len(padded) % rate)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for start in range(0, len(padded), rate):
        block = padded[start:start + rate]
        for i in range(rate // 8):
            state[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        state = _permute(state)
    return b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


# --- Catalog. Signatures are canonical (no spaces, no names, uint not shortened).
CATALOG = {
    "ERC-6093 / OpenZeppelin v5 tokens": [
        "ERC20InsufficientBalance(address,uint256,uint256)", "ERC20InvalidSender(address)",
        "ERC20InvalidReceiver(address)", "ERC20InsufficientAllowance(address,uint256,uint256)",
        "ERC20InvalidApprover(address)", "ERC20InvalidSpender(address)",
        "ERC20ExceededCap(uint256,uint256)", "ERC20InvalidCap(uint256)",
        "ERC2612ExpiredSignature(uint256)", "ERC2612InvalidSigner(address,address)",
        "ERC721InvalidOwner(address)", "ERC721NonexistentToken(uint256)",
        "ERC721IncorrectOwner(address,uint256,address)", "ERC721InvalidSender(address)",
        "ERC721InvalidReceiver(address)", "ERC721InsufficientApproval(address,uint256)",
        "ERC721InvalidApprover(address)", "ERC721InvalidOperator(address)",
        "ERC1155InsufficientBalance(address,uint256,uint256,uint256)",
        "ERC1155InvalidSender(address)", "ERC1155InvalidReceiver(address)",
        "ERC1155MissingApprovalForAll(address,address)", "ERC1155InvalidApprover(address)",
        "ERC1155InvalidOperator(address)", "ERC1155InvalidArrayLength(uint256,uint256)",
    ],
    "Unprefixed token errors (seen in ZTO bytecode)": [
        "InsufficientBalance(address,uint256,uint256)", "InvalidReceiver(address)",
        "InsufficientAllowance(address,uint256,uint256)", "InvalidSender(address)",
        "InvalidSpender(address)", "InvalidApprover(address)",
    ],
    "OpenZeppelin v5 access, proxy and utils": [
        "OwnableUnauthorizedAccount(address)", "OwnableInvalidOwner(address)",
        "AccessControlUnauthorizedAccount(address,bytes32)", "AccessControlBadConfirmation()",
        "EnforcedPause()", "ExpectedPause()", "ReentrancyGuardReentrantCall()",
        "SafeERC20FailedOperation(address)",
        "SafeERC20FailedDecreaseAllowance(address,uint256,uint256)",
        "AddressEmptyCode(address)", "AddressInsufficientBalance(address)", "FailedInnerCall()",
        "FailedCall()", "InsufficientBalance(uint256,uint256)", "InvalidAccountNonce(address,uint256)",
        "ECDSAInvalidSignature()", "ECDSAInvalidSignatureLength(uint256)",
        "ECDSAInvalidSignatureS(bytes32)", "InvalidInitialization()", "NotInitializing()",
        "ERC1967InvalidImplementation(address)", "ERC1967InvalidAdmin(address)",
        "ERC1967InvalidBeacon(address)", "ERC1967NonPayable()",
        "UUPSUnauthorizedCallContext()", "UUPSUnsupportedProxiableUUID(bytes32)",
        "SafeCastOverflowedUintDowncast(uint8,uint256)", "SafeCastOverflowedIntToUint(int256)",
    ],
    "Solady": [
        "TotalSupplyOverflow()", "AllowanceOverflow()", "AllowanceUnderflow()",
        "InsufficientBalance()", "InsufficientAllowance()", "InvalidPermit()", "PermitExpired()",
        "Unauthorized()", "NewOwnerIsZeroAddress()", "NoHandoverRequest()", "AlreadyInitialized()",
        "TransferFailed()", "TransferFromFailed()", "ApproveFailed()", "ETHTransferFailed()",
        "Reentrancy()",
    ],
    "Uniswap v4 core": [
        "CurrencyNotSettled()", "PoolNotInitialized()", "AlreadyUnlocked()", "ManagerLocked()",
        "TickSpacingTooLarge(int24)", "TickSpacingTooSmall(int24)",
        "CurrenciesOutOfOrderOrEqual(address,address)", "UnauthorizedDynamicLPFeeUpdate()",
        "SwapAmountCannotBeZero()", "NonzeroNativeValue()", "MustClearExactPositiveDelta()",
        "InvalidCaller()", "ProtocolFeeTooLarge(uint24)", "ProtocolFeeCurrencySynced()",
        "InvalidTick(int24)", "InvalidSqrtPrice(uint160)", "TicksMisordered(int24,int24)",
        "TickLowerOutOfBounds(int24)", "TickUpperOutOfBounds(int24)",
        "TickLiquidityOverflow(int24)", "PoolAlreadyInitialized()",
        "PriceLimitAlreadyExceeded(uint160,uint160)", "PriceLimitOutOfBounds(uint160)",
        "NoLiquidityToReceiveFees()", "InvalidFeeForExactOut()", "CannotUpdateEmptyPosition()",
        "DelegateCallNotAllowed()", "HookAddressNotValid(address)", "InvalidHookResponse()",
        "HookCallFailed()", "HookDeltaExceedsSwapAmount()", "LPFeeTooLarge(uint24)",
        "WrappedError(address,bytes4,bytes,bytes)", "NativeTransferFailed()",
        "ERC20TransferFailed()", "SafeCastOverflow()",
    ],
    "Uniswap Permit2 and routers": [
        "AllowanceExpired(uint256)", "InsufficientAllowance(uint256)", "ExcessiveInvalidation()",
        "InvalidNonce()", "SignatureExpired(uint256)", "InvalidSignature()",
        "InvalidSignatureLength()", "InvalidSigner()", "InvalidContractSignature()",
        "LengthMismatch()", "InvalidAmount(uint256)", "V4TooLittleReceived(uint256,uint256)",
        "V4TooMuchRequested(uint256,uint256)", "ExecutionFailed(uint256,bytes)",
        "TransactionDeadlinePassed()", "DeadlinePassed(uint256)", "V3TooLittleReceived()",
        "V3TooMuchRequested()", "V2TooLittleReceived()", "V2TooMuchRequested()",
        "V3InvalidSwap()", "InvalidPath()", "InvalidCommandType(uint256)",
    ],
    "Builtin Solidity reverts": ["Error(string)", "Panic(uint256)"],
}

PANIC_CODES = {0x00: "generic compiler panic", 0x01: "assert failed", 0x11: "arithmetic overflow or underflow",
               0x12: "division or modulo by zero", 0x21: "invalid enum value",
               0x22: "bad storage byte array encoding", 0x31: "pop on empty array",
               0x32: "array index out of bounds", 0x41: "memory allocation too large",
               0x51: "call to uninitialized internal function"}

SIGNATURE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\(([a-z0-9,\[\]]*)\)")
TYPE = re.compile(r"address|bool|string|bytes([1-9]|[12][0-9]|3[0-2])?|u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?")


def selector(signature):
    return "0x" + keccak256(signature.encode()).hex()[:8]


def param_types(signature):
    match = SIGNATURE.fullmatch(signature)
    if not match:
        raise ValueError(f"not a canonical error signature: {signature!r}")
    types = match.group(1).split(",") if match.group(1) else []
    for kind in types:
        if not TYPE.fullmatch(kind):
            raise ValueError(f"unsupported parameter type {kind!r} in {signature!r}")
    return types


def build_index(extra=()):
    index = {}
    for source, signatures in CATALOG.items():
        for signature in signatures:
            index.setdefault(selector(signature), []).append({"signature": signature, "source": source})
    for signature in extra:
        param_types(signature)
        index.setdefault(selector(signature), []).insert(0, {"signature": signature, "source": "user"})
    return index


def _word(data, offset):
    if offset + 32 > len(data):
        raise ValueError("argument data is truncated")
    return data[offset:offset + 32]


def decode_args(types, data):
    """Strictly decode ABI arguments; raises ValueError on any malformed encoding."""
    values = []
    for i, kind in enumerate(types):
        word = _word(data, 32 * i)
        number = int.from_bytes(word, "big")
        if kind in ("string", "bytes"):
            if number % 32 or number < 32 * len(types):
                raise ValueError("dynamic argument offset is malformed")
            length = int.from_bytes(_word(data, number), "big")
            end = number + 32 + length
            if end > len(data):
                raise ValueError("dynamic argument is truncated")
            raw = data[number + 32:end]
            if kind == "string":
                values.append(raw.decode("utf-8", "replace"))
            else:
                values.append("0x" + raw.hex())
        elif kind == "address":
            if number >> 160:
                raise ValueError("address word has nonzero high bytes")
            values.append("0x" + word[12:].hex())
        elif kind == "bool":
            if number not in (0, 1):
                raise ValueError("bool word must be 0 or 1")
            values.append(bool(number))
        elif kind.startswith("bytes"):
            size = int(kind[5:])
            if int.from_bytes(word[size:], "big"):
                raise ValueError(f"{kind} word has nonzero padding")
            values.append("0x" + word[:size].hex())
        else:
            bits = int(kind.lstrip("uint") or 256)
            if kind.startswith("u"):
                if number >> bits:
                    raise ValueError(f"{kind} value out of range")
                values.append(str(number))
            else:
                signed = number - (1 << 256) if number >> 255 else number
                if not -(1 << (bits - 1)) <= signed < (1 << (bits - 1)):
                    raise ValueError(f"{kind} value out of range")
                values.append(str(signed))
    return values


def name_revert(payload, index, depth=0):
    """Return every catalog interpretation of a revert payload, decoded where possible.

    Bytes arguments that themselves carry a catalog selector (Uniswap v4
    WrappedError, router ExecutionFailed) are named recursively, three levels deep.
    """
    if not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", payload or ""):
        raise ValueError("revert data must be even-length 0x hex")
    data = bytes.fromhex(payload[2:])
    if len(data) < 4:
        return {"selector": None, "matches": [], "note": "no selector: empty or short revert data"}
    sel = "0x" + data[:4].hex()
    matches = []
    for entry in index.get(sel, []):
        found = dict(entry)
        try:
            found["args"] = decode_args(param_types(entry["signature"]), data[4:])
            found["decoded"] = True
            types = param_types(entry["signature"])
            nested = [name_revert(value, index, depth + 1) for kind, value in zip(types, found["args"])
                      if kind == "bytes" and depth < 3 and len(value) >= 10 and value[:10] in index]
            if nested:
                found["nested"] = nested
            if entry["signature"] == "Panic(uint256)":
                found["meaning"] = PANIC_CODES.get(int(found["args"][0]), "unknown panic code")
        except ValueError as exc:
            found["decoded"] = False
            found["decode_error"] = str(exc)
        matches.append(found)
    return {"selector": sel, "argument_bytes": len(data) - 4, "matches": matches}


def code_constants(code_hex):
    """Collect 4-byte constants pushed by PUSH4, or left-aligned in PUSH32, skipping push data."""
    code = bytes.fromhex(code_hex[2:])
    # Drop the Solidity CBOR metadata trailer when its declared length fits.
    if len(code) >= 2:
        tail = int.from_bytes(code[-2:], "big")
        if 0 < tail <= len(code) - 2 and code[-2 - tail] in (0xa1, 0xa2, 0xa3):
            code = code[:-2 - tail]
    found = set()
    i = 0
    while i < len(code):
        op = code[i]
        if 0x60 <= op <= 0x7f:
            size = op - 0x5f
            push = code[i + 1:i + 1 + size]
            if size == 4 and len(push) == 4:
                found.add("0x" + push.hex())
            elif size == 32 and len(push) == 32 and not any(push[4:]):
                found.add("0x" + push[:4].hex())
            i += 1 + size
        else:
            i += 1
    return found


def rpc(url, method, params):
    request = urllib.request.Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                        separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=20) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("JSON-RPC response exceeds size limit")
    payload = json.loads(raw)
    if (not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0"
            or type(payload.get("id")) is not int or payload["id"] != 1
            or (("result" in payload) == ("error" in payload))):
        raise ValueError("malformed JSON-RPC response envelope")
    if "error" in payload and (not isinstance(payload["error"], dict)
                               or type(payload["error"].get("code")) is not int
                               or not isinstance(payload["error"].get("message"), str)):
        raise ValueError("malformed JSON-RPC error")
    return payload


def fetch_code(url, address, block):
    payload = rpc(url, "eth_getCode", [address, block])
    if "error" in payload:
        raise ValueError("eth_getCode failed: " + payload["error"]["message"])
    code = payload["result"]
    if not isinstance(code, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", code):
        raise ValueError("invalid eth_getCode result")
    return code.lower()


def load_preview():
    from . import call_preview
    return call_preview


def code_report(code, index, sel=None):
    constants = code_constants(code)
    present = sorted({entry["signature"] for s, entries in index.items() if s in constants
                      for entry in entries if entry["source"] != "Builtin Solidity reverts"})
    report = {"code_bytes": (len(code) - 2) // 2, "catalog_errors_in_code": present}
    if sel:
        report["selector_in_code"] = sel in constants
    return report


def self_test():
    checks = [
        keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        keccak256(b"a" * 136).hex() == keccak256(bytearray(b"a" * 136)).hex(),
        selector("transfer(address,uint256)") == "0xa9059cbb",
        selector("Error(string)") == "0x08c379a0",
        selector("Panic(uint256)") == "0x4e487b71",
        selector("ERC20InsufficientBalance(address,uint256,uint256)") == "0xe450d38c",
    ]
    index = build_index()
    err = ("0x08c379a0" + (32).to_bytes(32, "big").hex() + (5).to_bytes(32, "big").hex()
           + b"hello".hex().ljust(64, "0"))
    checks.append(name_revert(err, index)["matches"][0]["args"] == ["hello"])
    panic = "0x4e487b71" + (0x11).to_bytes(32, "big").hex()
    checks.append(name_revert(panic, index)["matches"][0]["meaning"] == "arithmetic overflow or underflow")
    owner = "0x" + "11" * 20
    erc = ("0xe450d38c" + owner[2:].rjust(64, "0") + (3).to_bytes(32, "big").hex()
           + (9).to_bytes(32, "big").hex())
    checks.append(name_revert(erc, index)["matches"][0]["args"] == [owner, "3", "9"])
    checks.append(name_revert(erc[:-2], index)["matches"][0]["decoded"] is False)
    dirty = "0xe450d38c" + "ff" * 32 + (3).to_bytes(32, "big").hex() + (9).to_bytes(32, "big").hex()
    checks.append(name_revert(dirty, index)["matches"][0]["decoded"] is False)
    tick = "0x" + selector("InvalidTick(int24)")[2:] + ((1 << 256) - 5).to_bytes(32, "big").hex()
    checks.append(name_revert(tick, index)["matches"][0]["args"] == ["-5"])
    checks.append(name_revert("0x", index)["selector"] is None)
    # WrappedError(hook, bytes4, reason=ERC20InsufficientBalance(...), details=0x) names the inner reason.
    inner = bytes.fromhex(erc[2:])
    wrapped = (selector("WrappedError(address,bytes4,bytes,bytes)") + owner[2:].rjust(64, "0")
               + "deadbeef".ljust(64, "0") + (128).to_bytes(32, "big").hex()
               + (128 + 32 + 128).to_bytes(32, "big").hex() + len(inner).to_bytes(32, "big").hex()
               + inner.hex().ljust(256, "0") + (0).to_bytes(32, "big").hex())
    outer = name_revert(wrapped, index)["matches"][0]
    checks.append(outer["nested"][0]["matches"][0]["args"] == [owner, "3", "9"])
    user = build_index(["Custom(uint8)"])
    checks.append(name_revert(selector("Custom(uint8)") + "00" * 31 + "07", user)["matches"][0]["args"] == ["7"])
    # PUSH1 0x63 (data looks like PUSH4) must be skipped; PUSH4 and left-aligned PUSH32 found.
    code = "0x6063" + "63deadbeef" + "7f" + "cafebabe" + "00" * 28 + "00"
    checks.append(code_constants(code) == {"0xdeadbeef", "0xcafebabe"})
    for bad in ("Bad(uint7)", "Bad (uint256)", "Bad(address[])"):
        try:
            param_types(bad)
            checks.append(False)
        except ValueError:
            checks.append(True)
    print(json.dumps({"self_test": "passed" if all(checks) else "failed",
                      "checks": len(checks), "failed": [i for i, ok in enumerate(checks) if not ok]}))
    return 0 if all(checks) else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", help="revert data (0x selector + ABI arguments) to name")
    parser.add_argument("--signature", action="append", default=[],
                        help="extra canonical error signature, e.g. 'MyError(address,uint256)'; repeatable")
    parser.add_argument("--code-of", help="contract address whose deployed bytecode is scanned for catalog selectors")
    parser.add_argument("--block", default="latest", help="block tag or hex height for --code-of")
    parser.add_argument("--rpc", default=DEFAULT_RPC)
    parser.add_argument("--demo", action="store_true",
                        help="live: preview an unfunded ZTO transfer with call_preview, then name its revert")
    parser.add_argument("--self-test", action="store_true", help="offline checks; no network")
    parser.add_argument("--list", action="store_true", help="print the catalog with selectors")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.rpc.startswith("https://"):
        parser.error("--rpc must be an HTTPS URL")
    if args.code_of and not re.fullmatch(r"0x[0-9a-fA-F]{40}", args.code_of):
        parser.error("--code-of must be a 20-byte 0x address")
    try:
        index = build_index(args.signature)
    except ValueError as exc:
        parser.error(str(exc))
    if args.list:
        print(json.dumps({s: [e["signature"] for e in entries] for s, entries in sorted(index.items())}, indent=2))
        return 0
    report = {"sent": False}
    try:
        if args.demo:
            if args.data or args.code_of:
                parser.error("--demo cannot be combined with --data or --code-of")
            preview = load_preview()
            data = ("0xa9059cbb" + preview.POOL_MANAGER[2:].rjust(64, "0")
                    + (1).to_bytes(32, "big").hex())
            tx = {"to": ZTO, "from": preview.DEMO_FROM, "data": data, "value": "0x0"}
            block = rpc(args.rpc, "eth_blockNumber", [])
            if "error" in block or not re.fullmatch(r"0x[0-9a-f]+", str(block.get("result"))):
                raise ValueError("could not pin a block height")
            args.block = block["result"]
            response = preview.rpc_call(args.rpc, tx, args.block)
            report["preview"] = {"transaction": tx, "block": int(args.block, 16)}
            if "result" in response:
                report["preview"]["status"] = "succeeded"
                print(json.dumps(report, indent=2))
                return 0
            args.data = preview.revert_data(response["error"])
            report["preview"]["status"] = "reverted"
            report["preview"]["rpc_message"] = response["error"]["message"]
            args.code_of = ZTO
            if not args.data:
                report["note"] = "the RPC returned no revert data to name"
        if not args.data and not args.code_of:
            parser.error("give --data, --code-of, --demo, --list or --self-test")
        sel = None
        if args.data:
            try:
                report["revert"] = name_revert(args.data.lower(), index)
            except ValueError as exc:
                parser.error(str(exc))
            sel = report["revert"]["selector"]
            if sel and not report["revert"]["matches"]:
                report["revert"]["note"] = ("selector not in catalog; supply the contract's error "
                                            "signature with --signature")
        if args.code_of:
            code = fetch_code(args.rpc, args.code_of.lower(), args.block)
            report["code"] = dict(address=args.code_of.lower(), block=args.block,
                                  **code_report(code, index, sel))
            if report["code"]["code_bytes"] == 0:
                report["code"]["note"] = "no code at this address and block"
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        report["status"] = "rpc_error"
        report["error"] = str(exc)
        print(json.dumps(report, indent=2))
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
