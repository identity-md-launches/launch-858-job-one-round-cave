#!/usr/bin/env python3
"""Read-only EIP-1967 authority and beacon reconnaissance for Ethereum."""
import argparse
import json
import re
import sys
import urllib.request

ZTO = '0xd782bdea4ef02a0bd391eb9089470c8080f0a68e'
SLOTS = {
    'admin': '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
    'beacon': '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50',
}
IMPLEMENTATION_SELECTOR = '0x5c60da1b'
OWNER_SELECTOR = '0x8da5cb5b'
MAX_RESPONSE_BYTES = 1024 * 1024
DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def hex_bytes(value, length=None):
    if not isinstance(value, str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', value):
        raise ValueError('Malformed RPC byte string')
    result = bytes.fromhex(value[2:])
    if length is not None and len(result) != length:
        raise ValueError('Incorrect RPC byte string length')
    return result


def address_word(value):
    raw = hex_bytes(value, 32)
    if raw == bytes(32):
        return None
    if any(raw[:12]):
        raise ValueError('Non-address data in EIP-1967 slot or address result')
    return '0x' + raw[12:].hex()


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
        'Content-Type': 'application/json', 'User-Agent': 'Pepeolithic-ProxyAuthority/1.0'})
    with DIRECT_OPENER.open(request, timeout=30) as response:
        data = response.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise ValueError('RPC response exceeds size limit')
    try:
        return rpc_result(json.loads(data.decode('utf-8')))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError('Malformed JSON-RPC response body') from exc


def code_bytes(endpoint, address, block):
    return len(hex_bytes(rpc(endpoint, 'eth_getCode', [address, block])))


def optional_address_call(endpoint, address, selector, block):
    """Return an ABI-address result or a bounded diagnostic; never infer from arbitrary bytes."""
    try:
        result = rpc(endpoint, 'eth_call', [{'to': address, 'data': selector}, block])
        return {'address': address_word(result), 'error': None}
    except (ValueError, OSError, KeyError, TypeError) as exc:
        return {'address': None, 'error': str(exc)}


def assess(admin, beacon, beacon_implementation, owner):
    candidates = []
    if admin:
        candidates.append({'kind': 'eip1967_admin', 'address': admin})
    if beacon:
        candidates.append({'kind': 'eip1967_beacon', 'address': beacon})
    if owner:
        candidates.append({'kind': 'beacon_owner_return', 'address': owner})
    return {
        'authority_candidates': candidates,
        'beacon_implementation': beacon_implementation,
        'assessment': ('potentially upgradeable via observable EIP-1967 routing'
                       if admin or beacon else
                       'no EIP-1967 admin or beacon authority was observed'),
        'limitations': ('This is evidence, not proof of upgrade authorization or immutability. '
                        'Custom proxies, diamonds, multisigs, timelocks and access-control '
                        'rules require separate inspection. owner() is only a reported return value.'),
    }


def inspect(endpoint, address):
    if int(rpc(endpoint, 'eth_chainId', []), 16) != 1:
        raise ValueError('Expected Ethereum mainnet chainId 1')
    block, block_hash = block_ref(rpc(endpoint, 'eth_getBlockByNumber', ['latest', False]))
    slots = {name: rpc(endpoint, 'eth_getStorageAt', [address, slot, block])
             for name, slot in SLOTS.items()}
    admin, beacon = address_word(slots['admin']), address_word(slots['beacon'])
    result = {'admin': admin, 'beacon': beacon}
    if admin:
        result['admin_code_bytes'] = code_bytes(endpoint, admin, block)
    if beacon:
        result['beacon_code_bytes'] = code_bytes(endpoint, beacon, block)
        implementation = optional_address_call(endpoint, beacon, IMPLEMENTATION_SELECTOR, block)
        owner = optional_address_call(endpoint, beacon, OWNER_SELECTOR, block)
        result['beacon_implementation_call'] = implementation
        result['beacon_owner_call'] = owner
        if implementation['address']:
            result['beacon_implementation_code_bytes'] = code_bytes(
                endpoint, implementation['address'], block)
        result.update(assess(admin, beacon, implementation['address'], owner['address']))
    else:
        result.update(assess(admin, None, None, None))
    end_block, end_hash = block_ref(rpc(endpoint, 'eth_getBlockByNumber', [block, False]))
    if end_block != block or end_hash != block_hash:
        raise ValueError('Block changed during read; retry')
    return {'chain_id': 1, 'address': address, 'block_number': int(block, 16),
            'block_hash': block_hash, 'raw_slots': slots, **result}


def self_test():
    zero = '0x' + '00' * 32
    address = '0x' + '11' * 20
    word = '0x' + '00' * 12 + address[2:]
    assert address_word(zero) is None
    assert address_word(word) == address
    try:
        address_word('0x' + '01' * 32)
    except ValueError:
        pass
    else:
        raise AssertionError('Non-address word accepted')
    assert assess(address, None, None, None)['authority_candidates'][0]['kind'] == 'eip1967_admin'
    beacon = assess(None, address, address, address)
    assert len(beacon['authority_candidates']) == 2
    assert beacon['beacon_implementation'] == address
    assert rpc_result({'jsonrpc': '2.0', 'id': 1, 'result': 'ok'}) == 'ok'
    for response in [{}, {'jsonrpc': '2.0', 'id': True, 'result': 'ok'},
                     {'jsonrpc': '2.0', 'id': 1.0, 'result': 'ok'},
                     {'jsonrpc': '2.0', 'id': 2, 'result': 'ok'},
                     {'jsonrpc': '2.0', 'id': 1}]:
        try:
            rpc_result(response)
        except ValueError:
            pass
        else:
            raise AssertionError('Invalid RPC envelope accepted')
    good_hash = '0x' + 'ab' * 32
    assert block_ref({'number': '0x1a', 'hash': good_hash}) == ('0x1a', good_hash)
    for bad_block in [None, {'number': '0x1a'}, {'number': 26, 'hash': good_hash},
                      {'number': '0x01a', 'hash': good_hash},
                      {'number': '0x1a', 'hash': '0x' + 'ab' * 31}]:
        try:
            block_ref(bad_block)
        except ValueError:
            pass
        else:
            raise AssertionError('Invalid block accepted')
    print('PASS: EIP-1967 admin/beacon, beacon authority, address words, strict envelopes, block shape')


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
        print('proxy-authority: ' + str(exc), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
