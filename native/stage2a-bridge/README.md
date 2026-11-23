# Stage 2a B relay candidate

Source candidate for Platform Discussion #120. The Comms package and HQ release builders do not build, install, or launch this command. It has no sandbox installer and grants no qualification authority.

Build on Darwin with cgo enabled and a pinned Go/SDK toolchain.

```sh
CGO_ENABLED=1 go build -trimpath -o agent-comms-stage2a-bridge .
CGO_ENABLED=1 go test -race ./...
```

The measured command is the absolute installed binary followed by the literal arguments below, with an empty environment.

```text
--assignment-fd 3 --proof-fd 4 --status-fd 5
```

The fixed launch rule must run the executable under its provisioned B UID/GID and confined profile and pass private anonymous pipes. FD 3 is a bounded JSON assignment followed by EOF. The `assignment`, `selectors`, `endpoint` and `identity` structs in relay.go define the exact field names. The v2 assignment identifies all three accounts, the broker socket and its parent, the uncreated relay socket and its parent, exact plan digests, current HQ epoch, pre-bind expiration, pinned model, normalized request and header digests, client API key digest, HTTP host, and literal Messages query. On the relay socket identity use zero device and inode, with the intended owner, group and mode. Supply device and inode as unsigned JSON integers, preserving full integer precision across the sending implementation.

Only the authenticated fixed launcher may populate those descriptors. This executable relies on the launcher to authenticate the Machine-signed assignment, prove the installed artifact and profile, check endpoint ancestry and ACLs, apply exact socket confinement, restrict groups and inherited descriptors, and associate the process with the live reservation. The assignment crosses no runner-controlled socket. FD 4 is 32 raw proof-key bytes followed by EOF. Relay diagnostics do not print assignment or proof data.

The executable checks broker peer UID in the kernel, pins the broker identity, sends `bridge.bind.v2.challenge` and `bridge.bind.v2` over one Unix stream, then binds the Unix relay and writes one JSON object to FD 5 with `bind_receipt_sha256` and the actual `relay_socket` identity. The launch supervisor must recheck that socket and resolve the digest against HQ's current B binding before Machine finalization and R startup. B does not start R. The source default-off HQ dispatch patch and Comms plugin gate are independent prerequisites. After owner approval a trusted HQ entry point must verify Machine finalization, apply the two transport gates, and install the one-use local provider authorizer.

Each accepted Unix stream must have the assigned R peer UID. A literal policy-limits GET is answered locally. A POST for the exact assigned Messages path has one bounded strict JSON body, pinned model, exact host, headers and query. The v2 relay recognizes the pinned stock Claude ACP v0.109.0 macOS first streaming request (nine top-level fields and one user message) and the earlier eleven-field, two-message shape. The relay refuses duplicate or unknown JSON fields and requires every nonvolatile body field to match the signed normalized request digest. It removes only `metadata.user_id` before the Go `encoding/json` compact, sorted-top-level-key digest; that field's nested account, device and session IDs are shape-checked and never forwarded. Version, beta and other nonvolatile headers are bound by the signed header digest. The client API key and session header are checked and discarded. The request uses `application/json` and a single canonical Content-Length. The same bound broker stream receives at most one call to `bridge.relay.ingress.v1`, with `{model,prompt_sha256}` only; `prompt_sha256` is the normalized full request digest, which HQ must match to its installed plan before obtaining Machine's one-use local provider response. The synthetic `bridge.qualification.messages.v1` route is not used by the installed relay. Bind calls and HTTP reads have five-second deadlines. The relay allows twenty seconds for the provider round trip and sets a fresh five-second write deadline for every response. Broker EOF, path replacement or provider refusal shuts the relay down. The executable only removes its own verified socket and reports uncertain cleanup to its supervisor.

This executable changes the earlier proposed Node/addon package to a single Go/cgo native artifact. A revised owner-reviewed measurement contract must bind the exact binary, native runtime/system dependencies, fixed arguments, empty environment, and launcher/profile. macOS source tests cover native same-account peer discovery and a Unix-socket fixture with injected role UIDs. They establish neither distinct-account host custody nor sandbox egress, signing, installed invocation or physical qualification.
