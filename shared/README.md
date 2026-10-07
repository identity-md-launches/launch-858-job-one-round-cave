# Read-only contract preflight

Reusable Python standard-library copies of RPC Health (line 1), Call Preview
(line 2), Proxy Route (line 3), and Source Check (line 4) are in `tools/`.
Original line files remain untouched. Copies of lines 3 and 4 explicitly disable
environment-based HTTP proxy discovery, matching lines 1 and 2.
Shared copies of lines 2 and 3 also require JSON-RPC 2.0, an integer matching
request ID, exactly one result/error field, and a response of at most 1 MiB.

From the workspace root:

```sh
python3 -B shared/preflight.py --result-type uint256
python3 -B shared/check.py
```

The first command uses real ZTO: choose a fresh mainnet endpoint, inspect routing,
retrieve Sourcify status for the contract and any implementation/clone leads,
and preview `totalSupply()` at the routing scan's block. Recheck that block's
number and hash after the call. The second command checks the composition offline.
No network or dependencies are needed for the offline checks.

`--address`, `--data`, `--result-type`, and repeated `--endpoint` customize the
lookup. This narrow workflow previews zero-value calls without a sender.
Source failures are explicit per-address observations and do not prevent calls;
no fresh endpoint prevents all subsequent work. Contract-call RPC failures make
the command fail. An observed revert is a completed preview, not approval to send.

Source is not extracted, compiled, or executed. Beacon addresses are not treated
as implementations. This reports review leads rather than safety, upgrade
authorization, or independent source verification. Provider honesty, transient
availability and changes between reads remain limitations. It never signs,
sends transactions, discovers credentials, or accesses environment settings.

Live validation returned ZTO supply `1000000000000000000000000000`, zero
recognized proxy routes, and unverified Sourcify status. No new coin is needed.

## Round 2: agreement before a call

`agreed_preview.py` reuses line 1's new RPC Agreement with line 2's repaired
Call Preview. It requires two distinct HTTPS endpoint URLs, previews ZTO
`totalSupply()` at their agreed height, then rechecks that block's identity at
every endpoint. A disagreement, lag, stale response, or unavailable provider
blocks the call. Different URLs do not prove independent infrastructure.

```sh
python3 -B shared/check_agreed.py
python3 -B shared/agreed_preview.py
```

The first command works offline with standard Python alone. It tests gating,
the exact call height, both post-call checks, hash/height changes at the second
provider, reverts, RPC errors and decoding failures. The second uses read-only
public JSON-RPC. Options: repeated `--endpoint`, `--address`, `--data`, and
`--result-type`. No sender or value overrides are provided. Only the first
provider executes the call; agreeing block headers do not validate its execution.

Tried: the initial live run blocked on PublicNode HTTP 429. A later retry
succeeded at block 26135639, hash
`0x6ebe12c97cb4af43e9836383b6079cf5272214f1cb4c3e832c403267a99a3b7e`,
returning ZTO supply `1000000000000000000000000000`; both rechecks matched.
Existing preflight also passed, falling back to dRPC during the rate limit.

Provenance: `tools/rpc_agreement.py` comes from
`line-1/tools/rpc-agreement/compare.py`, with a local shared import and an added
provider-count guard for direct callers. Shared Call Preview and Source Check
were refreshed from their round-2 line originals: 256 KiB strict call replies,
address validation, no proxy discovery, and source redirect rejection.
Existing shared Proxy Route retains its strict integer-ID guard. All original
line folders remain untouched. These are source copies, with no dependencies
or downloads required for the offline commands.

## Gathering round 3 additions

Refreshed modules and new `revert_names`, `delegate_scan`, `proxy_authority`,
`compiler_trailer` copies use only Python's standard library. `provenance.json`
records original paths and hashes; agreement/revert imports are package-local.
Line 2 can reuse line 3's opcode scanner for proxy context; line 4 can use it on
retrieved bytecode. Compiler metadata is review context, not a safety proof;
known limitations are in gathering/REPORT.md.

Agreement-gated preview now adds `preview.named_revert`: all catalog matches,
decoded arguments when complete, explicit decode failures when truncated, and
empty matches for unknown selectors. It retains raw error data. Provider
collections can be generators. Run from the workspace root:

```sh
python3 -B shared/check_named.py
```

Complete ZTO errors, truncated data, unknown selectors, generators and pinned
calls passed offline. Existing check.py/check_agreed.py and copied self-tests
passed too. Live ZTO transfer preview at 26136821 named InsufficientBalance,
zero sender, balance 0, needed 1; both provider block rechecks matched. Supply
preview returned 10^27 at 26136820. Hash collisions prevent proving error origin.
Nothing was signed or submitted; no installation is needed.
