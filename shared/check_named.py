"""Offline integration regression: name complete, truncated and unknown reverts."""
from unittest.mock import patch
import agreed_preview as p


def check():
    endpoints = ['https://a.invalid', 'https://b.invalid']
    block_hash = '0x' + 'ab' * 32
    sample = {'status': 'agreement', 'common_height': 100,
              'common_blocks': [{'block_hash': block_hash}] * 2}
    payload = '0xdb42144d' + ''.join(n.to_bytes(32, 'big').hex() for n in (1, 0, 1))
    with patch.object(p.agreement, 'compare', return_value=sample), \
         patch.object(p.call_preview, 'rpc_call') as call, \
         patch.object(p.rpc_health, 'rpc', return_value={'number': '0x64', 'hash': block_hash}):
        for raw in (payload, payload[:10], '0xdeadbeef'):
            call.return_value = {'error': {'code': 3, 'message': 'execution reverted', 'data': raw}}
            result = p.preview(iter(endpoints))
            named = result['preview']['named_revert']
            assert result['sent'] is False
            assert call.call_args.args[2] == '0x64'
            if raw == payload:
                assert named['matches'][0]['signature'] == 'InsufficientBalance(address,uint256,uint256)'
                assert named['matches'][0]['args'] == ['0x' + '0' * 39 + '1', '0', '1']
                assert named['matches'][0]['decoded']
            elif raw == payload[:10]:
                assert not named['matches'][0]['decoded']
            else:
                assert named['matches'] == []
    print('PASS: generator providers, pinned call, named ZTO error, truncated rejection, unknown selector')


if __name__ == '__main__':
    check()
