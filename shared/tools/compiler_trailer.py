#!/usr/bin/env python3
"""Read the compiler metadata trailer from deployed Ethereum bytecode.

Read-only: pins one block, reads runtime code by block hash (EIP-1898), decodes
the CBOR trailer Solidity/Vyper append (compiler version, IPFS/Swarm metadata
hash) and, when Sourcify has the contract, checks that its recompiled trailer,
compiler version and on-chain bytecode agree with what the chain returned.
No credentials, environment settings or files are read; nothing is signed or sent.
"""
import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request

ZTO = '0xd782bdea4ef02a0bd391eb9089470c8080f0a68e'
RPCS = ('https://ethereum-rpc.publicnode.com', 'https://eth.drpc.org')
SOURCIFY = 'https://sourcify.dev/server/v2/contract/1/'
FIELDS = ('?fields=compilation.compilerVersion,compilation.compilerSettings,'
          'runtimeBytecode.cborAuxdata,runtimeBytecode.onchainBytecode')
AGENT = 'Pepeolithic-Line4-CompilerTrailer/1.0'
LIMIT = 8 * 1024 * 1024
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
ADDRESS = re.compile(r'0x[0-9a-fA-F]{40}')
HASH32 = re.compile(r'0x[0-9a-f]{64}')


# ---------- decoding (pure, offline) ----------

def cbor(data, pos=0, depth=0):
    """Decode one definite-length CBOR item; return (value, next position)."""
    if depth > 8 or pos >= len(data):
        raise ValueError('CBOR truncated or too deep')
    head = data[pos]
    major, info = head >> 5, head & 31
    pos += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if pos + size > len(data):
            raise ValueError('CBOR truncated')
        arg = int.from_bytes(data[pos:pos + size], 'big')
        pos += size
    else:
        raise ValueError('Indefinite or reserved CBOR item')
    if major == 0:
        return arg, pos
    if major in (2, 3):
        if pos + arg > len(data):
            raise ValueError('CBOR string truncated')
        raw = bytes(data[pos:pos + arg])
        return (raw if major == 2 else raw.decode('utf-8')), pos + arg
    if major == 4:
        items = []
        for _ in range(arg):
            item, pos = cbor(data, pos, depth + 1)
            items.append(item)
        return items, pos
    if major == 5:
        out = {}
        for _ in range(arg):
            key, pos = cbor(data, pos, depth + 1)
            if not isinstance(key, str):
                raise ValueError('Non-text CBOR map key')
            out[key], pos = cbor(data, pos, depth + 1)
        return out, pos
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], pos
    raise ValueError('Unsupported CBOR item')


def base58(raw):
    n = int.from_bytes(raw, 'big')
    out = ''
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return '1' * (len(raw) - len(raw.lstrip(b'\0'))) + out


def version(value):
    if isinstance(value, bytes) and len(value) == 3:
        return '%d.%d.%d' % tuple(value)
    if isinstance(value, list) and len(value) == 3 and all(type(v) is int for v in value):
        return '%d.%d.%d' % tuple(value)
    if isinstance(value, str):
        return value
    raise ValueError('Unrecognized compiler version encoding')


def trailer(code):
    """Decode the length-suffixed CBOR trailer; None when the code has none."""
    if len(code) < 3:
        return None
    size = int.from_bytes(code[-2:], 'big')
    if size == 0 or size + 2 > len(code):
        return None
    body = code[-2 - size:-2]
    try:
        value, end = cbor(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if end != size:
        return None
    # Solidity appends a map; Vyper >= 0.3.10 appends an array ending in a map.
    meta = value if isinstance(value, dict) else (
        value[-1] if isinstance(value, list) and value and isinstance(value[-1], dict) else None)
    # Solidity before 0.5.9 wrote only a Swarm hash, with no compiler key.
    if meta is None or not ({'solc', 'vyper', 'ipfs', 'bzzr0', 'bzzr1'} & set(meta)):
        return None
    out = {'offset': len(code) - 2 - size, 'length': size + 2,
           'hex': '0x' + code[-2 - size:].hex(), 'keys': sorted(meta)}
    for name in ('solc', 'vyper'):
        if name in meta:
            out['compiler'], out['version'] = name, version(meta[name])
    if isinstance(meta.get('ipfs'), bytes):
        out['metadataHash'] = {'kind': 'ipfs', 'hex': '0x' + meta['ipfs'].hex(),
                               'cid': base58(meta['ipfs'])}
    for name in ('bzzr1', 'bzzr0'):
        if isinstance(meta.get(name), bytes):
            out['metadataHash'] = {'kind': name, 'hex': '0x' + meta[name].hex()}
    if 'metadataHash' not in out:
        out['metadataHash'] = None
    if meta.get('experimental') is True:
        out['experimental'] = True
    return out


def compare(code, found, source):
    """Cross-check a decoded trailer against a Sourcify v2 response object."""
    if not isinstance(source, dict) or source.get('match') is None:
        return {'match': None, 'status': 'not_verified_at_provider'}
    if source['match'] not in ('exact_match', 'match'):
        raise ValueError('Unrecognized Sourcify match')
    comp = source.get('compilation') or {}
    runtime = source.get('runtimeBytecode') or {}
    checks = {}
    declared = comp.get('compilerVersion')
    if isinstance(declared, str) and found and 'version' in found:
        checks['compilerVersion'] = 'agree' if declared.split('+')[0].lstrip('v') == \
            found['version'].split('+')[0] else 'differ'
    onchain = runtime.get('onchainBytecode')
    if isinstance(onchain, str) and re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', onchain):
        checks['providerOnchainBytecode'] = 'agree' if bytes.fromhex(onchain[2:]) == code else 'differ'
    aux = runtime.get('cborAuxdata')
    if isinstance(aux, dict):
        values = [v.get('value', '').lower() for v in aux.values() if isinstance(v, dict)]
        if found:
            checks['recompiledTrailer'] = 'agree' if found['hex'] in values else 'differ'
        else:
            checks['recompiledTrailer'] = 'absent_on_chain' if values else 'absent_both'
    settings = comp.get('compilerSettings') or {}
    meta = settings.get('metadata') if isinstance(settings, dict) else None
    hard = [k for k in ('compilerVersion', 'providerOnchainBytecode') if checks.get(k) == 'differ']
    if hard or (checks.get('recompiledTrailer') in ('differ', 'absent_on_chain') and source['match'] == 'exact_match'):
        status = 'inconsistent'
    elif checks.get('recompiledTrailer') in ('differ', 'absent_on_chain'):
        # A Sourcify partial "match" means exactly this: code agrees, metadata does not.
        status = 'code_agrees_metadata_differs'
    elif checks and set(checks.values()) <= {'agree', 'absent_both'}:
        status = 'consistent'
    else:
        status = 'incomplete'
    return {'match': source['match'], 'compilerVersion': declared,
            'bytecodeHashSetting': meta.get('bytecodeHash') if isinstance(meta, dict) else None,
            'checks': checks, 'status': status}


# ---------- transport ----------

def opener():
    # Empty proxy mapping: never discover proxy settings. Refuse redirects.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError('Redirect refused')
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def read(request, allow404=False):
    try:
        response = opener().open(request, timeout=30)
    except urllib.error.HTTPError as error:
        if not (allow404 and error.code == 404):
            raise
        response = error
    with response:
        raw = response.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('Response exceeds 8 MiB limit')
    return json.loads(raw)


def rpc_result(reply, ident):
    if not isinstance(reply, dict) or reply.get('jsonrpc') != '2.0' or \
            type(reply.get('id')) is not int or reply['id'] != ident:
        raise ValueError('Malformed JSON-RPC reply')
    if 'error' in reply or 'result' not in reply:
        raise ValueError('RPC error: %s' % json.dumps(reply.get('error'))[:200])
    return reply['result']


def rpc(url, method, params, ident):
    body = json.dumps({'jsonrpc': '2.0', 'id': ident, 'method': method, 'params': params}).encode()
    request = urllib.request.Request(url, body, {'User-Agent': AGENT, 'Content-Type': 'application/json'})
    return rpc_result(read(request), ident)


def pinned_code(address, url):
    block = rpc(url, 'eth_getBlockByNumber', ['latest', False], 1)
    if not isinstance(block, dict) or not isinstance(block.get('number'), str) or \
            not re.fullmatch(r'0x[0-9a-f]+', block['number']) or \
            not isinstance(block.get('hash'), str) or not HASH32.fullmatch(block['hash']):
        raise ValueError('Malformed block')
    code = rpc(url, 'eth_getCode', [address, {'blockHash': block['hash'], 'requireCanonical': True}], 2)
    if not isinstance(code, str) or not re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', code):
        raise ValueError('Malformed code')
    return {'number': int(block['number'], 16), 'hash': block['hash']}, bytes.fromhex(code[2:])


def inspect(address, rpcs=RPCS, sourcify=True):
    if not isinstance(address, str) or not ADDRESS.fullmatch(address):
        raise ValueError('address must be a 20-byte hex address')
    errors = []
    for url in rpcs:
        try:
            block, code = pinned_code(address.lower(), url)
            break
        except (ValueError, urllib.error.URLError, TimeoutError) as error:
            errors.append('%s: %s' % (url, error))
    else:
        raise ValueError('All RPC endpoints failed: ' + '; '.join(errors))
    found = trailer(code) if code else None
    out = {'chainId': 1, 'address': address.lower(), 'rpc': url, 'block': block,
           'codeSize': len(code), 'codeSha256': hashlib.sha256(code).hexdigest(),
           'kind': 'no_code' if not code else 'contract', 'trailer': found,
           'limitation': 'The trailer is a compiler-written hint, not proof of authorship or safety; '
                         'a missing trailer is legal (appendCBOR=false, other compilers).'}
    if errors:
        out['rpcFallbackErrors'] = errors
    if sourcify and code:
        request = urllib.request.Request(SOURCIFY + address + FIELDS,
                                         headers={'User-Agent': AGENT, 'Accept': 'application/json'})
        try:
            out['sourcify'] = compare(code, found, read(request, allow404=True))
        except (ValueError, urllib.error.URLError, TimeoutError) as error:
            out['sourcify'] = {'status': 'lookup_failed', 'error': str(error)[:200]}
    return out


# ---------- offline demonstration ----------

def self_test():
    from io import BytesIO
    from unittest.mock import patch
    # Real trailers read from mainnet on 2026-10-07.
    zto = bytes.fromhex('6104e38361042c565b9050925092905056fea164736f6c634300081a000a')
    imd = bytes.fromhex('56fea2646970667358221220c5b90da65cf00d90c56d2e172bbb6442c6881e07'
                        '55c799a13ebb411adf53f29964736f6c634300081a0033')
    usdt = bytes.fromhex('5600a165627a7a72305820645ee12d73db47fd78ba77fa1f824c3c8f9184061b3b'
                         '10386beb4dc9236abb280029')
    vyper = bytes.fromhex('00') + bytes.fromhex('8419012c80820a14a165767970657283000400') + b'\x00\x13'
    t = trailer(zto)
    assert t['compiler'] == 'solc' and t['version'] == '0.8.26' and t['metadataHash'] is None
    t = trailer(imd)
    assert t['version'] == '0.8.26' and t['metadataHash']['kind'] == 'ipfs'
    assert t['metadataHash']['cid'].startswith('Qm') and len(t['metadataHash']['cid']) == 46
    t = trailer(usdt)
    assert t['metadataHash']['kind'] == 'bzzr0' and 'version' not in t
    t = trailer(vyper)
    assert t['compiler'] == 'vyper' and t['version'] == '0.4.0'
    assert base58(b'hello world') == 'StV1DL6CwTryKyV' and base58(b'\0\0\x01') == '112'
    for bad in (b'', b'\x00\x00', zto[:-3] + b'\x00\x0a', b'\x60\x00\x00\x05',
                bytes.fromhex('a1636162630100') + b'\x00\x07',          # map without compiler key
                bytes.fromhex('a164736f6c6343000801ff') + b'\x00\x0b'):  # trailing byte
        assert trailer(bad) is None, bad.hex()
    print('PASS: trailer decoding (ZTO none-hash, IMD ipfs CID, USDT bzzr0, Vyper array), base58, malformed rejection')

    full = trailer(imd)
    source = {'match': 'exact_match', 'compilation': {'compilerVersion': '0.8.26+commit.8a97fa7a',
              'compilerSettings': {'metadata': {'bytecodeHash': 'ipfs'}}},
              'runtimeBytecode': {'onchainBytecode': '0x' + imd.hex(),
                                  'cborAuxdata': {'1': {'value': full['hex'], 'offset': full['offset']}}}}
    assert compare(imd, full, source)['status'] == 'consistent'
    other = json.loads(json.dumps(source))
    other['compilation']['compilerVersion'] = '0.8.25+commit.b61c2a91'
    other['runtimeBytecode']['onchainBytecode'] = '0x00'
    result = compare(imd, full, other)
    assert result['status'] == 'inconsistent' and result['checks']['providerOnchainBytecode'] == 'differ'
    assert compare(zto, trailer(zto), {'match': None})['status'] == 'not_verified_at_provider'
    partial = json.loads(json.dumps(source))
    partial['match'] = 'match'
    partial['runtimeBytecode']['cborAuxdata']['1']['value'] = '0xa1'
    assert compare(imd, full, partial)['status'] == 'code_agrees_metadata_differs'
    partial['match'] = 'exact_match'
    assert compare(imd, full, partial)['status'] == 'inconsistent'
    print('PASS: Sourcify cross-check agree, version/bytecode disagreement, partial metadata, unverified')

    for reply in ({'jsonrpc': '2.0', 'id': 1.0, 'result': '0x'}, {'jsonrpc': '2.0', 'id': True, 'result': '0x'},
                  {'jsonrpc': '2.0', 'id': 2, 'result': '0x'}, {'jsonrpc': '2.0', 'id': 1, 'error': {}}, []):
        try:
            rpc_result(reply, 1)
        except ValueError:
            continue
        raise AssertionError('Bad RPC reply accepted')
    head = {'number': '0x18f0000', 'hash': '0x' + 'ab' * 32}
    replies = iter([{'jsonrpc': '2.0', 'id': 1, 'result': head},
                    {'jsonrpc': '2.0', 'id': 2, 'result': '0x' + zto.hex()},
                    {'chainId': '1', 'address': ZTO, 'match': None}])
    calls = []

    def fake_open(self, request, timeout=None):
        calls.append(request)
        assert timeout == 30 and request.get_header('User-agent') == AGENT
        return BytesIO(json.dumps(next(replies)).encode())
    with patch.object(urllib.request, 'getproxies', side_effect=AssertionError('Proxy discovery')), \
            patch.object(urllib.request.OpenerDirector, 'open', fake_open):
        out = inspect(ZTO)
        assert out['block']['number'] == 0x18f0000 and out['trailer']['version'] == '0.8.26'
        assert json.loads(calls[1].data)['params'][1]['blockHash'] == head['hash']
        assert out['sourcify']['status'] == 'not_verified_at_provider'
        try:
            inspect('../etc/passwd')
        except ValueError:
            pass
        else:
            raise AssertionError('Bad address accepted')
    print('PASS: strict JSON-RPC ids, block-hash pinned read, no proxy discovery, address validation')


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--address', default=ZTO, help='contract address (default: ZTO)')
    parser.add_argument('--no-sourcify', action='store_true', help='skip the Sourcify cross-check')
    parser.add_argument('--self-test', action='store_true', help='offline demonstration')
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not ADDRESS.fullmatch(args.address):
        parser.error('address must be a 20-byte hex address')
    try:
        print(json.dumps(inspect(args.address, sourcify=not args.no_sourcify), indent=2, sort_keys=True))
        return 0
    except (ValueError, urllib.error.URLError, TimeoutError) as error:
        print('Trailer lookup failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
