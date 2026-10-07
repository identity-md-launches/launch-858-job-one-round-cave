"""Compare public Ethereum providers at a common height; no dependencies."""
import argparse
import importlib.util
import json
import math
from pathlib import Path
import time

from . import rpc_health as health


def compare(endpoints, timeout=12, max_age=120, max_lag=3, call=None, now=None):
    # Validate at the reusable boundary, before making any network requests.
    # Materialize once so generators also survive both observation passes.
    if isinstance(endpoints, (str, bytes)):
        raise ValueError('require at least two distinct endpoint strings')
    endpoints = list(endpoints)
    if (any(not isinstance(endpoint, str) or not endpoint.strip() for endpoint in endpoints)
            or len(set(endpoints)) < 2):
        raise ValueError('require at least two distinct endpoint strings')
    call = call or health.rpc
    now = time.time() if now is None else now
    observations = []
    for endpoint in endpoints:
        try:
            chain = call(endpoint, 'eth_chainId', [], 1, timeout)
            block = call(endpoint, 'eth_getBlockByNumber', ['latest', False], 2, timeout)
            observation = health.assess(chain, block, now, max_age)
        except (ValueError, TypeError, OSError) as exc:
            observation = {'status': 'error', 'error': str(exc)}
        observations.append({'endpoint': endpoint, **observation})
    result = {'status': 'inconclusive', 'observations': observations}
    if any(o['status'] != 'fresh' for o in observations):
        return result
    heights = [o['block_number'] for o in observations]
    target = min(heights)
    result.update(common_height=target, head_spread=max(heights) - target)
    pinned = []
    for endpoint in endpoints:
        try:
            block = call(endpoint, 'eth_getBlockByNumber', [hex(target), False], 3, timeout)
            item = health.assess('0x1', block, now, max_age)
            if item['block_number'] != target:
                raise ValueError('provider returned the wrong requested height')
            pinned.append({'endpoint': endpoint, **item})
        except (ValueError, TypeError, OSError) as exc:
            pinned.append({'endpoint': endpoint, 'status': 'error', 'error': str(exc)})
    result['common_blocks'] = pinned
    if any(p['status'] != 'fresh' for p in pinned):
        return result
    if len({p['block_hash'].lower() for p in pinned}) != 1:
        result['status'] = 'disagreement'
    elif result['head_spread'] > max_lag:
        result['status'] = 'lagging'
    else:
        result['status'] = 'agreement'
    return result


def demo():
    def fixture(mode):
        def call(endpoint, method, params, request_id, timeout):
            if mode == 'error' and endpoint == 'b':
                raise OSError('unavailable')
            if method == 'eth_chainId':
                return '0x2' if mode == 'wrong-chain' else '0x1'
            height = (101 if endpoint == 'a' else 100) if params[0] == 'latest' else int(params[0], 16)
            if mode == 'lag' and params[0] == 'latest' and endpoint == 'a':
                height = 110
            if mode == 'wrong-height' and params[0] != 'latest':
                height += 1
            return {'number': hex(height), 'timestamp': hex(800 if mode == 'stale' else 990),
                    'hash': '0x' + ('bb' if mode == 'fork' and endpoint == 'b' else 'aa') * 32}
        return call
    cases = {'normal': 'agreement', 'fork': 'disagreement', 'lag': 'lagging',
             'error': 'inconclusive', 'wrong-height': 'inconclusive',
             'stale': 'inconclusive', 'wrong-chain': 'inconclusive'}
    for mode, expected in cases.items():
        actual = compare(['a', 'b'], call=fixture(mode), now=1000)
        assert actual['status'] == expected, (mode, actual)
        if mode == 'normal':
            assert actual['common_height'] == 100 and actual['head_spread'] == 1
    def forbidden_call(*args):
        raise AssertionError('invalid provider set reached transport')
    invalid = [[], ['only'], ['same', 'same'], 'ab', b'ab', ['', 'b'], [None, 'b']]
    for endpoints in invalid:
        try:
            compare(endpoints, call=forbidden_call, now=1000)
        except ValueError:
            continue
        raise AssertionError(('invalid providers accepted', endpoints))
    generated = compare(iter(['a', 'b']), call=fixture('normal'), now=1000)
    assert generated['status'] == 'agreement' and len(generated['common_blocks']) == 2
    print(json.dumps({'demo': 'passed', 'cases': cases,
                      'invalid_provider_sets_rejected_before_transport': len(invalid),
                      'generator_checked_in_both_passes': True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--demo', action='store_true')
    parser.add_argument('--endpoint', action='append')
    parser.add_argument('--timeout', type=float, default=12)
    parser.add_argument('--max-age', type=float, default=120)
    parser.add_argument('--max-lag', type=int, default=3)
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0 or not math.isfinite(args.max_age) or args.max_age < 0 or args.max_lag < 0:
        parser.error('require finite positive timeout and nonnegative age/lag')
    if args.demo:
        demo()
        return 0
    endpoints = args.endpoint or health.DEFAULTS
    if len(set(endpoints)) < 2 or any(not url.startswith('https://') for url in endpoints):
        parser.error('require at least two distinct HTTPS endpoints')
    result = compare(endpoints, args.timeout, args.max_age, args.max_lag)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'agreement' else 1


if __name__ == '__main__':
    raise SystemExit(main())
