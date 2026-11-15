# Notices in HQ's broker mailbox

The HQ broker plugin pulls GitHub notices through HQ's identity-service host
service. It stores each notice in the plugin's durable HQ store transaction
before acknowledging the service's lease. This implements the ingestion gate
in [HQ plan §4.8 and row 11](https://github.com/true-line/agent-bot-hq/blob/main/docs/daemon-plugin-split.md).
Tracking: [agent-bot-comms #313](https://github.com/true-line/agent-bot-comms/issues/313)
and [agent-bot-hq #123](https://github.com/true-line/agent-bot-hq/issues/123).

## Enable and inspect

HQ's owner-written config enables ingestion explicitly:

```json
{
  "notices": {
    "harnesses": ["example-codex-agent"],
    "pollIntervalMs": 30000,
    "count": 10,
    "leaseSeconds": 300,
    "wakeClass": "none",
    "maxMessages": 1000,
    "maxBytes": 16777216,
    "retentionMs": 691200000
  }
}
```

The queue names must also be in the enrolled device's scope; the identity
service enforces that scope. A reply naming a different queue is refused.
The plugin declares only the notice take and ack identity-service routes.
No configuration means no pulls. Starting the broker never waits for the uplink.

The trusted host can use the plugin's `provides.notices` object:

- `pull()` performs one bounded pass across the configured queues. Concurrent
  callers share the pass. `reconnect()` requests the same pass immediately.
- `list(harness)` reads ready mailbox records. Each record's `message_id` is
  the notice ID; the durable key also names the queue, since one GitHub event
  can be addressed to more than one harness.
- `acknowledge(harness, messageIds)` records local consumption after the
  trusted consumer finishes handling the messages. This is separate from
  acknowledging the upstream lease.
- `status()` reports configuration, running/revoked state, consecutive failures,
  the last successful pass and a bounded failure category. `mailbox_full`
  means local consumption or capacity needs attention.

These are host-side plugin methods. This module registers no member wire
operation and adds no public CLI. HQ owns the caller binding and grant checks;
a member request cannot supply the host's harness or repository scope.

## Scoped local mailbox

[PDR-0062](https://github.com/true-line/agent-bot-platform/blob/main/docs/04-decisions/PDR-0062-hq-notice-scope-and-legacy-consume-one.md)
assigns caller authority to HQ and mailbox mechanics to comms. The host-private
`provides.notices` object also exposes:

- `peek({harness, repo, count = 1})`: return up to 50 eligible sanitized
  notice envelopes from durable local custody. This transaction performs no
  writes, network requests, acknowledgements or custody notifications.
- `consumeOne({harness, repo}, prepareResult)`: select at most one eligible
  notice, call the required synchronous host validator with the immutable
  result array, then tombstone that selection in the same durable transaction.
  The returned array is the exact one validated. The validator also runs for an
  empty result. A throw or thenable return refuses consumption without writing;
  a persist failure rolls the transaction back and returns no handoff.

HQ supplies the scope only after checking the bound runtime's frozen scope,
installation epoch and current lease. These private arguments confer no agent
permission. Comms applies exact harness and case-insensitive repository equality
before selection; it preserves the notice's repository spelling. It orders by
ascending durable custody sequence, not source timestamps or table iteration.
Concurrent consumers sharing the HQ store serialize selection and tombstoning.
No query takes or acknowledges upstream, and no direct-upstream fallback exists.
The existing `list` and `acknowledge` methods are operator recovery tools, not
an implementation of atomic member consume-one.

The single home of the public payload, field compatibility table, byte oracle
and errors is the [shared notice contract](https://github.com/true-line/soul-contracts/blob/main/schemas/hq/v1/notices.md).
The read path re-sanitizes restored records, verifies the sanitized source
against its stored ingestion digest, omits storage/transport fields, and creates
fixed external-untrusted provenance. It bounds canonical UTF-8
source content to 64 KiB and its returned notice array to 512 KiB, stopping
before an additional peek entry would exceed that array limit. A source notice
above its limit refuses before mutation; content is never truncated to fit.
HQ validates its actual complete correlated result against the pinned shared
schema and full-result budget inside `prepareResult` before consumption. For
read-only peek, HQ trims trailing entries when needed and revalidates the
complete result before returning it. The private comms array is not the public
result record and does not contain correlation or wrapper fields.
Callbacks are host-only, synchronous, side-effect-free validation; they must
not open another store transaction while this one holds the store lock.

### Retained records and operator recovery

Missing, invalid or out-of-scope repository metadata is neither returned nor
consumed. No repository is inferred from the caller. Invalid restored content,
identity/sequence metadata, missing or mismatched content digests, or wake
classification also stays withheld. These
records remain ready, retain their dedup evidence and count against the existing
message/byte limits; queries never silently discard, repair or reassign them.
Oversized restored content in the selected scope refuses with `frame_too_large`
and remains available for operator handling.

The owner can inspect retained ready rows through the existing host-only
`list(harness)`, investigate source routing, and explicitly discard reviewed
message IDs through `acknowledge(harness, ids)`. Discard removes content but
retains the normal dedup tombstone. There is no query-side repository override
or automatic replay/reassignment. Ready records have no expiry; consumed
tombstones keep the configured retention horizon and still count toward the
message cap. If retained records fill capacity, ingestion reports
`mailbox_full`, takes no new custody and leaves new upstream leases
unacknowledged. Recovery must preserve live tombstones and may require an
owner-reviewed capacity change; reading a different scope cannot clear the
pressure.

## Custody and recovery

A notice is always `external-untrusted`, with wake class `none` or `notify`
chosen by the owner's configuration. Source-supplied authority and wake fields
are ignored. Ingestion publishes a custody event after the durable commit;
it never launches a Soul or treats notice text as a directive.
The event is an in-process hint, not custody itself: if publishing fails, the
message remains available through `list(harness)` for the consumer to recover.

The mailbox stores only known notice content fields, bounded to 64 KiB per
message. Lease tokens, lease expiry and attempts stay in memory. Logs contain
fixed failure categories, never notice text, upstream response bodies or
exception messages.

- Before a durable commit, a failure sends no upstream ack. The lease expires
  and the notice can return.
- After a commit, an ack failure leaves the mailbox record intact. A replay
  returns its existing sequence and acknowledges the new lease without a
  second committed transition or custody event.
- The same ID with different content is refused without overwriting custody.
- A storage failure rolls back the transaction. Message and byte caps refuse
  new custody, leave the upstream notice unacknowledged, and report pressure.
  Already-held duplicates can still be acknowledged while the mailbox is full.
  The message cap includes both ready records and retained tombstones, so
  overload cannot evict dedup evidence before its retention horizon.
- Local consumption removes the content and keeps a compact dedup tombstone.
  Tombstones are retained for at least seven days (eight by default), covering
  the service's seven-day queue retention. Only consumed records beyond that
  horizon are pruned. Ready messages and live dedup evidence are never evicted
  to make room.
- Start, scheduled polls and reconnect/on-demand pulls use the same path.
  Transient failures retry with a one-second exponential backoff capped at
  one minute. Revocation stops remote requests until a new plugin lifecycle.
  Stop cancels polling and invalidates late responses before custody or ack.

## Compatibility and evidence

This storage slice does not activate the HQ-backed identity CLI/MCP alias.
The legacy direct-upstream `take_inbox` path still requires the coordinated
shim and service custody gate before migration. A lost response after a local
consume commit may lose that caller handoff: do not automatically retry a
destructive query, and do not claim acknowledged local delivery. Tombstones
survive restart and prevent an upstream redelivery from resurrecting the
consumed message within the retention horizon.

Tracking: [agent-bot-comms #317](https://github.com/true-line/agent-bot-comms/issues/317).
The shared source is reviewed at `60c540ea71a720148f6733afc7b29fa1ec255753`,
but the candidate `v0.5.0` is not yet released. This change creates no tag,
release, copied contract or fabricated consumer pin. Final integration against
the verified published release remains required; see
[service #216](https://github.com/true-line/agent-bot/issues/216).
[HQ #13](https://github.com/true-line/agent-bot-hq/issues/13) remains the overall
alias acceptance tracker.

`tests/hq-notices.test.mjs` uses the real HQ store at the vendored SDK's pinned
revision. It covers persistence failures, restart after custody and before
ack, duplicate/content-conflict handling, caps, retention, late responses,
revocation and retry. Local mailbox regressions cover scope filtering, reversed
source timestamps and table iteration, read-only peek, concurrent consume,
result validation before mutation, persistence rollback, restart/redelivery,
retained invalid records and canonical byte limits. Existing broker tests
continue to exercise real HQ admission and task commits over its member socket.
