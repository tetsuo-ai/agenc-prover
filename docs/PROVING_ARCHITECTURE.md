# Proving Architecture

This file explains how the checked-in proving surfaces fit together.

## Component Split

- `guest/` - shared journal and witness-layout helpers
- `methods/guest/` - zkVM guest entrypoint
- `server/` - HTTP proving service, auth, readiness, rate limiting, and image pinning

## `/prove` Lifecycle

1. `server/src/main.rs` accepts the request and enforces auth, rate limits, and timeout policy.
2. `server/src/prover.rs` recomputes witness-derived fields and rejects mismatches.
3. The proving flow checks the compiled guest image against the pinned trusted image id.
4. The server runs the real Groth16 proving path and returns `seal_bytes`, `journal`, and `image_id`.

## Shared Journal Model

The shared journal logic in `guest/src/lib.rs` is the source of truth for:

- field count
- field byte length
- serialized 192-byte journal layout

That layout must remain compatible with the protocol-owned private-completion contract in `agenc-protocol`.

## Feature And Trust Model

- `production-prover` is the real proving path for production verification
- the image-id command is used to confirm the compiled guest matches the pinned trusted value
- startup should fail closed for unsafe exposure patterns, especially unauthenticated non-loopback binds

