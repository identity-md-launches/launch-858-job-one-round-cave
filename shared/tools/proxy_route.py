#!/usr/bin/env python3
"""Read-only proxy routing reconnaissance. Standard library only."""
import argparse
import json
import re
import sys
import urllib.request

ZTO = '0xd782bdea4ef02a0bd391eb9089470c8080f0a68e'
SLOTS = {
    'implementation': '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
    'beacon': '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50',
}
PREFIX = '363d3d373d3d3d363d73'
SUFFIX = '5af43d82803e903d91602b57fd5bf3'
MAX_RESPONSE_BYTES = 1024 * 1024
DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def rpc_result(body):
    """Validate a JSON-RPC 2.0 reply for this tool's fixed request id."""
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
    """Validate a block object's number and hash before pinning reads to it."""
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
        'Content-Type': 'application/json', 'User-Agent': 'Pepeolithic-ProxyRoute/1.0'})
    with DIRECT_OPENER.open(request, timeout=30) as response:
        data = response.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise ValueError('RPC response exceeds size limit')
    try:
        body = json.loads(data.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('Malformed JSON-RPC response body') from exc
    return rpc_result(body)


def hex_bytes(value, length=None):
    if not isinstance(value, str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', value):
        raise ValueError('Malformed RPC byte string')
    result = bytes.fromhex(value[2:])
    if length is not None and len(result) != length:
        raise ValueError('Incorrect RPC byte string length')
    return result


def slot_address(word):
    raw = hex_bytes(word, 32)
    if raw == bytes(32):
        return None
    if any(raw[:12]):
        raise ValueError('Non-address data in proxy slot')
    return '0x' + raw[12:].hex()


def classify(code, slots):
    raw = hex_bytes(code)
    routes = {key: slot_address(slots[key]) for key in SLOTS}
    match = re.fullmatch(PREFIX + '([0-9a-f]{40})' + SUFFIX, raw.hex())
    if match:
        routes['minimal_proxy'] = '0x' + match.group(1)
    return {'code_bytes': len(raw), 'routes': routes,
            'assessment': ('proxy routing indicators found' if any(routes.values()) else
                           'no recognized proxy routing indicators'),
            'limitations': 'Indicators are not proof of dispatch. Absence does not prove immutability; custom proxies, diamonds and upgrade authorization require further inspection.'}


def inspect(endpoint, address):
    chain = rpc(endpoint, 'eth_chainId', [])
    if int(chain, 16) != 1:
        raise ValueError('Expected Ethereum mainnet chainId 1')
    number, block_hash = block_ref(rpc(endpoint, 'eth_getBlockByNumber', ['latest', False]))
    code = rpc(endpoint, 'eth_getCode', [address, number])
    slots = {key: rpc(endpoint, 'eth_getStorageAt', [address, slot, number])
             for key, slot in SLOTS.items()}
    result = classify(code, slots)
    targets = {key: {'address': target, 'code_bytes': len(hex_bytes(
        rpc(endpoint, 'eth_getCode', [target, number])))}
        for key, target in result['routes'].items() if target}
    end_number, end_hash = block_ref(rpc(endpoint, 'eth_getBlockByNumber', [number, False]))
    if end_number != number or end_hash != block_hash:
        raise ValueError('Block changed during read; retry')
    return {'chain_id': 1, 'address': address, 'block_number': int(number, 16),
            'block_hash': block_hash, 'raw_slots': slots, **result, 'targets': targets}


def self_test():
    zero = {key: '0x' + '00' * 32 for key in SLOTS}
    assert not any(classify('0x6000', zero)['routes'].values())
    word = dict(zero, implementation='0x' + '00' * 12 + ZTO[2:])
    assert classify('0x6000', word)['routes']['implementation'] == ZTO
    clone = '0x' + PREFIX + ZTO[2:] + SUFFIX
    assert classify(clone, zero)['routes']['minimal_proxy'] == ZTO
    assert 'minimal_proxy' not in classify(clone + '00', zero)['routes']
    assert classify('0x', zero)['code_bytes'] == 0
    for bad in ['0x01', '0x' + '01' * 32, 'wrong']:
        try:
            slot_address(bad)
        except ValueError:
            pass
        else:
            raise AssertionError('Invalid slot accepted')
    assert rpc_result({'jsonrpc': '2.0', 'id': 1, 'result': 'ok'}) == 'ok'
    for bad_response in [
            {}, {'jsonrpc': '1.0', 'id': 1, 'result': 'ok'},
            {'jsonrpc': '2.0', 'id': True, 'result': 'ok'},
            {'jsonrpc': '2.0', 'id': 1.0, 'result': 'ok'},
            {'jsonrpc': '2.0', 'id': 2, 'result': 'ok'},
            {'jsonrpc': '2.0', 'id': 1},
    ]:
        try:
            rpc_result(bad_response)
        except ValueError:
            pass
        else:
            raise AssertionError('Invalid RPC envelope accepted')
    good_hash = '0x' + 'ab' * 32
    assert block_ref({'number': '0x1a', 'hash': good_hash}) == ('0x1a', good_hash)
    for bad_block in [None, {'number': '0x1a'}, {'number': 26, 'hash': good_hash},
                      {'number': '0x01a', 'hash': good_hash}, {'number': '0x', 'hash': good_hash},
                      {'number': '0x1a', 'hash': '0x' + 'ab' * 31}]:
        try:
            block_ref(bad_block)
        except ValueError:
            pass
        else:
            raise AssertionError('Invalid block accepted')
    print('PASS: routes, malformed slots, strict JSON-RPC envelope and block shape')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
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
        print('proxy-route: ' + str(exc), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
