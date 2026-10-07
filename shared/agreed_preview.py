"""Preview a ZTO call at a height agreed by two public Ethereum providers."""
import argparse
import json
from tools import rpc_agreement as agreement, rpc_health, call_preview, revert_names


def preview(endpoints, address=call_preview.ZTO, data='0x18160ddd', result_type='uint256'):
    if isinstance(endpoints, (str, bytes)):
        raise ValueError('require endpoint collection')
    endpoints = list(endpoints)
    if any(not isinstance(url, str) or not url.startswith('https://') for url in endpoints) or len(set(endpoints)) < 2:
        raise ValueError('require at least two distinct HTTPS endpoints')
    address = call_preview.address(address)
    data = call_preview.calldata(data)
    sample = agreement.compare(endpoints)
    report = {'status': 'blocked', 'sent': False, 'agreement': sample}
    if sample['status'] != 'agreement':
        return report
    height = sample['common_height']
    block = hex(height)
    expected = sample['common_blocks'][0]['block_hash'].lower()
    transaction = {'to': address, 'data': data, 'value': '0x0'}
    response = call_preview.rpc_call(endpoints[0], transaction, block)
    # Every provider must still report the same height and hash after eth_call.
    for endpoint in endpoints:
        end = rpc_health.rpc(endpoint, 'eth_getBlockByNumber', [block, False], 4, 12)
        if (not isinstance(end, dict) or rpc_health.quantity(end.get('number')) != height
                or not isinstance(end.get('hash'), str) or end['hash'].lower() != expected):
            raise ValueError('Block identity changed after preview; discard and retry')
    result = {'block_number': height, 'block_hash': expected, 'transaction': transaction,
              'endpoint': endpoints[0]}
    if 'error' in response:
        error = response['error']
        raw = call_preview.revert_data(error)
        result.update(status='reverted' if raw or 'revert' in error['message'].lower() else 'rpc_error',
                      error=error, decoded=call_preview.explain_revert(raw))
        if result['status'] == 'reverted' and raw:
            result['named_revert'] = revert_names.name_revert(raw, revert_names.build_index())
    else:
        result.update(status='succeeded', return_data=response['result'])
        try:
            result['decoded'] = call_preview.decode_result(response['result'], result_type)
        except ValueError as exc:
            result['decode_error'] = str(exc)
    report.update(status='observed', preview=result,
                  limitations='Provider agreement is not consensus proof. Only the first provider '
                  'executes eth_call; rechecks cannot eliminate every reorg race. '
                  'No sender or value overrides; future transactions can differ.')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', action='append')
    parser.add_argument('--address', default=call_preview.ZTO, type=call_preview.address)
    parser.add_argument('--data', default='0x18160ddd', type=call_preview.calldata)
    parser.add_argument('--result-type', default='uint256', choices=['raw', 'uint256', 'bool', 'address'])
    args = parser.parse_args()
    try:
        result = preview(args.endpoint or rpc_health.DEFAULTS, args.address, args.data, args.result_type)
        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'observed' and result['preview']['status'] != 'rpc_error' else 1
    except (ValueError, OSError, TypeError, KeyError, RecursionError, argparse.ArgumentTypeError) as exc:
        print(json.dumps({'status': 'error', 'sent': False, 'error': str(exc)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
