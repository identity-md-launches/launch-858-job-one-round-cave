"""Offline integration checks: gating, pinned call, routes and reorganization."""
import sys
sys.dont_write_bytecode = True
from unittest.mock import patch
import preflight as p
import urllib.request


def check():
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, *args): return b'{"id":true,"result":"0x"}'
    class Opener:
        def open(self, *args, **kwargs): return Response()
    with patch.object(urllib.request, 'build_opener', return_value=Opener()), \
         patch.object(p.proxy_route, 'DIRECT_OPENER', Opener()):
        for function, args in [(p.call_preview.rpc_call, ('https://example.invalid', {}, 'latest')),
                               (p.proxy_route.rpc, ('https://example.invalid', 'eth_chainId', []))]:
            try:
                function(*args)
            except ValueError:
                pass
            else:
                raise AssertionError('malformed envelope accepted')
    routing = {'block_number': 100, 'block_hash': '0x' + 'ab' * 32,
               'routes': {'implementation': '0x' + '22' * 20, 'beacon': '0x' + '33' * 20}}
    fresh = {'status': 'fresh', 'endpoint': 'https://example.invalid', 'latency_ms': 1}
    with patch.object(p.rpc_health, 'probe', return_value={'status': 'error'}), \
         patch.object(p.proxy_route, 'inspect') as inspect:
        assert p.preflight(p.call_preview.ZTO, '0x', ['https://example.invalid'])['status'] == 'blocked'
        inspect.assert_not_called()
    with patch.object(p.rpc_health, 'probe', return_value=fresh), \
         patch.object(p.proxy_route, 'inspect', return_value=routing), \
         patch.object(p.source_check, 'fetch', return_value={'status': 'unverified', 'sources': {}}) as source, \
         patch.object(p.call_preview, 'rpc_call', return_value={'result': '0x' + (42).to_bytes(32, 'big').hex()}) as call, \
         patch.object(p.proxy_route, 'rpc', return_value={'number': '0x64', 'hash': routing['block_hash']}) as rpc:
        result = p.preflight(p.call_preview.ZTO, '0x18160ddd', [fresh['endpoint']], 'uint256')
        assert result['preview']['decoded'] == '42' and not result['sent']
        assert call.call_args.args[2] == hex(100)
        assert [x.args[0] for x in source.call_args_list] == [p.call_preview.ZTO, routing['routes']['implementation']]
        rpc.return_value = {'number': '0x64', 'hash': '0x' + 'cd' * 32}
        try:
            p.preflight(p.call_preview.ZTO, '0x', [fresh['endpoint']])
        except ValueError as error:
            assert 'identity changed' in str(error)
        else:
            raise AssertionError('reorganization was accepted')
    print('PASS: envelope rejection, unhealthy gate, pinned call, implementation source leads, beacon exclusion, reorganization rejection')


if __name__ == '__main__':
    check()
