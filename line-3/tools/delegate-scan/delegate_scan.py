#!/usr/bin/env python3
"""Read-only opcode scan: can this contract's runtime code ever delegate or self-destruct?

The EVM decodes code with one linear sweep from byte 0, skipping PUSH data, and
only jumps to JUMPDEST bytes found by that sweep. So an opcode absent from the
sweep can never execute. Absence of DELEGATECALL and CALLCODE therefore proves
the contract cannot run another contract's logic in its own storage context.
"""
import argparse
import json
import re
import sys
import urllib.request

ZTO = '0xd782bdea4ef02a0bd391eb9089470c8080f0a68e'
WATCHED = {0xf4: 'DELEGATECALL', 0xf2: 'CALLCODE', 0xff: 'SELFDESTRUCT',
           0xf0: 'CREATE', 0xf5: 'CREATE2'}
MAX_RESPONSE_BYTES = 1024 * 1024
DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def hex_bytes(value):
    if not isinstance(value, str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', value):
        raise ValueError('Malformed RPC byte string')
    return bytes.fromhex(value[2:])


def rpc_result(body):
    if not isinstance(body, dict) or body.get('jsonrpc') != '2.0':
        raise ValueError('Malformed JSON-RPC response envelope')
    request_id = body.get('id')
    if type(request_id) is not int or request_id != 1:
        raise ValueError('Mismatched JSON-RPC response id')
    if 'error' in body:
        raise ValueError('RPC error: ' + json.dumps(body['error']))
    if 'result' not in body:
        raise ValueError('JSON-RPC response has no result')
    return body['result']


def block_ref(block):
    if not isinstance(block, dict):
        raise ValueError('Malformed block object')
    number, block_hash = block.get('number'), block.get('hash')
    if not isinstance(number, str) or not re.fullmatch(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)', number):
        raise ValueError('Malformed block number')
    if not isinstance(block_hash, str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}', block_hash):
        raise ValueError('Malformed block hash')
    return number, block_hash.lower()


def rpc(endpoint, method, params):
    payload = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    request = urllib.request.Request(endpoint, data=payload, headers={
        'Content-Type': 'application/json', 'User-Agent': 'Pepeolithic-DelegateScan/1.0'})
    with DIRECT_OPENER.open(request, timeout=30) as response:
        data = response.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise ValueError('RPC response exceeds size limit')
    try:
        return rpc_result(json.loads(data.decode('utf-8')))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('Malformed JSON-RPC response body') from exc


def metadata_start(code):
    """Offset of a trailing Solidity/Vyper CBOR metadata block, or None."""
    if len(code) < 2:
        return None
    length = int.from_bytes(code[-2:], 'big')
    start = len(code) - 2 - length
    # CBOR map header (0xa1..0xa5) as emitted by solc/vyper
    if 0 < length < len(code) - 2 and 0xa1 <= code[start] <= 0xa5:
        return start
    return None


def sweep(code):
    """EVM linear sweep: list (offset, opcode) for every instruction boundary."""
    out, pc = [], 0
    while pc < len(code):
        op = code[pc]
        out.append((pc, op))
        pc += 1 + (op - 0x5f if 0x60 <= op <= 0x7f else 0)
    return out


def analyse(code):
    meta = metadata_start(code)
    hits = {name: [] for name in WATCHED.values()}
    jumpdests = 0
    for pc, op in sweep(code):
        if op == 0x5b:
            jumpdests += 1
        if op in WATCHED:
            hits[WATCHED[op]].append(pc)

    def split(offsets):
        body = [pc for pc in offsets if meta is None or pc < meta]
        return {'count': len(offsets), 'outside_metadata': len(body),
                'first_offsets': offsets[:8]}

    found = {name: split(offs) for name, offs in hits.items() if offs}
    delegates = sum(found.get(n, {}).get('outside_metadata', 0) for n in ('DELEGATECALL', 'CALLCODE'))
    in_meta = sum(found.get(n, {}).get('count', 0) for n in ('DELEGATECALL', 'CALLCODE')) - delegates
    if not code:
        verdict = 'no code: nothing to execute (an EOA, or a destroyed/undeployed contract)'
    elif not delegates and not in_meta:
        verdict = 'proven: code can never execute DELEGATECALL or CALLCODE; its logic cannot be swapped by delegation'
    elif not delegates:
        verdict = ('likely non-delegating: DELEGATECALL/CALLCODE bytes occur only inside the trailing metadata; '
                   'unreachable unless a jump lands on a JUMPDEST there')
    else:
        verdict = ('can delegate: DELEGATECALL/CALLCODE is decodable code; behaviour may depend on other '
                   'contracts (proxy, library, or module); inspect the targets')
    return {'code_bytes': len(code), 'instructions': len(sweep(code)), 'jumpdests': jumpdests,
            'metadata_offset': meta, 'watched_opcodes': found, 'verdict': verdict,
            'notes': ['SELFDESTRUCT after EIP-6780 (Cancun) only removes code when called in the creating '
                      'transaction, so it no longer enables destroy-and-redeploy of an existing contract.',
                      'CREATE/CREATE2 mean the contract can deploy others; it does not change its own code.',
                      'Proof covers this code only: called contracts, owner powers and storage-driven '
                      'behaviour (fees, pauses, blacklists) are not covered.']}


def inspect(endpoint, address):
    if int(rpc(endpoint, 'eth_chainId', []), 16) != 1:
        raise ValueError('Expected Ethereum mainnet chainId 1')
    number, block_hash = block_ref(rpc(endpoint, 'eth_getBlockByNumber', ['latest', False]))
    code = hex_bytes(rpc(endpoint, 'eth_getCode', [address, number]))
    end_number, end_hash = block_ref(rpc(endpoint, 'eth_getBlockByNumber', [number, False]))
    if end_number != number or end_hash != block_hash:
        raise ValueError('Block changed during read; retry')
    return {'chain_id': 1, 'address': address, 'block_number': int(number, 16),
            'block_hash': block_hash, **analyse(code)}


def expect_error(fn, arg):
    try:
        fn(arg)
    except ValueError:
        return
    raise AssertionError('accepted invalid input: %r' % (arg,))


def self_test():
    # PUSH1 0xf4 PUSH1 0x00 STOP: the 0xf4 byte is push data, never executed
    assert analyse(bytes.fromhex('60f4600000'))['verdict'].startswith('proven')
    # PUSH32 hiding f4/ff, then a real STOP
    assert analyse(bytes.fromhex('7f' + 'f4ff' * 16 + '00'))['verdict'].startswith('proven')
    # GAS ... DELEGATECALL as a real instruction
    real = analyse(bytes.fromhex('5af4'))
    assert real['verdict'].startswith('can delegate')
    assert real['watched_opcodes']['DELEGATECALL']['first_offsets'] == [1]
    # EIP-1167 minimal proxy runtime must be flagged
    clone = '363d3d373d3d3d363d73' + '11' * 20 + '5af43d82803e903d91602b57fd5bf3'
    assert analyse(bytes.fromhex(clone))['verdict'].startswith('can delegate')
    # PUSH20 at end with truncated data: sweep must stop cleanly
    assert analyse(bytes.fromhex('5b73f4'))['instructions'] == 2
    # CALLCODE and SELFDESTRUCT are counted separately
    mixed = analyse(bytes.fromhex('f2ff00'))['watched_opcodes']
    assert mixed['CALLCODE']['count'] == 1 and mixed['SELFDESTRUCT']['count'] == 1
    # f4 only inside a solc-style CBOR metadata trailer
    meta = bytes.fromhex('6000' + 'fe' + 'a1' + 'f4' * 3 + '0004')
    result = analyse(meta)
    assert result['metadata_offset'] == 3 and result['verdict'].startswith('likely')
    assert analyse(b'')['verdict'].startswith('no code')
    for bad in ['0x0', 'f4', None]:
        expect_error(hex_bytes, bad)
    assert rpc_result({'jsonrpc': '2.0', 'id': 1, 'result': 'ok'}) == 'ok'
    for bad in [{}, {'jsonrpc': '2.0', 'id': True, 'result': 'ok'},
                {'jsonrpc': '2.0', 'id': 1.0, 'result': 'ok'},
                {'jsonrpc': '2.0', 'id': 1}]:
        expect_error(rpc_result, bad)
    good = '0x' + 'ab' * 32
    assert block_ref({'number': '0x1', 'hash': good}) == ('0x1', good)
    for bad in [None, {'number': '0x01', 'hash': good}, {'number': '0x1', 'hash': '0x12'}]:
        expect_error(block_ref, bad)
    print('PASS: push-data skipping, real delegatecall, minimal proxy, metadata trailer, '
          'truncated push, strict envelopes, block shape')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--address', default=ZTO)
    parser.add_argument('--rpc', default='https://ethereum-rpc.publicnode.com')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not re.fullmatch(r'0x[0-9a-fA-F]{40}', args.address):
        parser.error('address must be 20-byte hexadecimal')
    if not args.rpc.startswith('https://'):
        parser.error('RPC endpoint must use HTTPS')
    try:
        print(json.dumps(inspect(args.rpc, args.address.lower()), indent=2))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print('delegate-scan: ' + str(exc), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
