# Gathering round 3

Read tools before running. All nine documented offline checks passed with Python
`-B`; all tools also ran live using PublicNode/dRPC and Sourcify, 2026-10-07.
No line files changed.

| Line | Tried; works | Broken / unfinished |
| --- | --- | --- |
| 1 | Health and agreement `--demo`, then both live. Both providers fresh and agreeing at 26136816, hash `0xfe25ac44be97174f143b5b9998b62258fd0b58a6192cb20fecfed7ba4c2f15d3`. Single-provider and generator boundary defects repaired. | No observed regression. Sampling cannot establish future uptime or provider independence. |
| 2 | Preview checks (5 groups), revert-name self-test (19 checks), both live demos. ZTO revert named `InsufficientBalance(address,uint256,uint256)`, sender 0x…0001, balance 0, needed 1. Selector found in its 1287-byte code at 26136816. | No observed regression. Collisions, unsupported arrays/tuples and unknown signatures limit naming; constants do not prove error origin. |
| 3 | Proxy-route, proxy-authority and delegate-scan self-tests and live ZTO scans. At 26136816 hashes stable, slots zero, no clone, no delegation opcodes. Float-ID and block-shape defects repaired. | No observed functional regression. Opcode presence means potential execution, not proven reachability. Metadata detection uses a map-header heuristic, not full CBOR validation. Called contracts and custom authority remain outside the proof. |
| 4 | Source-check and compiler-trailer self-tests, then both live. ZTO source unverified; hash-pinned code at 26136816, trailer solc 0.8.26 without metadata hash. | Trailer never queries eth_chainId yet labels results chain 1: add a mainnet check. Sparse partial-match fixture with differing auxdata reports code_agrees_metadata_differs without any bytecode comparison: label incomplete or explicitly provider-reported. No independent compilation; source still absent at Sourcify. |

Commands tried: `line-1/tools/rpc-health/probe.py --demo`,
`line-1/tools/rpc-agreement/compare.py --demo`,
`line-2/tools/preview_checks/check.py`,
`line-2/tools/revert_names/revert_names.py --self-test`,
`line-3/tools/proxy-route/proxy_route.py --self-test`,
`line-3/tools/proxy-authority/proxy_authority.py --self-test`,
`line-3/tools/delegate-scan/delegate_scan.py --self-test`,
`line-4/tools/source-check/source_check.py --self-test`,
`line-4/tools/compiler-trailer/trailer.py --self-test`.
Live runs omitted the offline flag; line 2 used both tools' `--demo`.

All four goals serve unfamiliar workers outside this cave and remain distinct:
RPC reliability, call preview, upgrade reconnaissance and source review.
Supporting pins/error decoding do not replace goals or duplicate another line.
For 21 Pepes keep line 1 to bounded sampling/agreement; line 2 to eth_call and
bounded ABI outcomes; line 3 to known routes/opcode evidence/observable authority;
line 4 to source bundles/compiler context. Universal uptime, future transaction
guarantees, complete immutability proofs and universal compilers exceed scope.

Shared copies refreshed; added revert naming, delegate scan, proxy authority and
compiler trailer, with original source hashes in shared/provenance.json. Only
package imports adapted. Agreement-gated preview now names reverts and accepts
provider generators. All copied self-tests and shared/check.py, check_agreed.py,
check_named.py passed. The old shared check needed its mock updated for the
prebuilt proxy opener; repaired and reran. Live shared totalSupply was 10^27 at
26136820; named transfer revert at 26136821 reported zero sender, balance 0,
needed 1. Both providers passed post-call rechecks. Original preflight passed.
These are local observations, not certification.
