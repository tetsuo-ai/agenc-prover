# agenc-prover

Separate prover service for AgenC private task completion.

## Scope

This repository is intentionally narrow:

- expose a small `/prove` HTTP API for AgenC
- keep prover-specific code isolated from the main AgenC repo
- make security review and auditing easier

The AgenC client already expects this contract:

### `POST /prove`

Request JSON:

```json
{
  "task_pda": [32 bytes],
  "agent_authority": [32 bytes],
  "constraint_hash": [32 bytes],
  "output_commitment": [32 bytes],
  "binding": [32 bytes],
  "nullifier": [32 bytes]
}
```

Response JSON:

```json
{
  "seal_bytes": [...],
  "journal": [...],
  "image_id": [...]
}
```

## Current Status

This repository currently contains the audited-friendly service skeleton only:

- request validation
- health check endpoint
- fixed API contract
- Docker packaging

The actual RISC Zero proving implementation is not wired in yet.

## Local Run

```bash
cargo run -p agenc-prover-server
```

By default the server binds to `127.0.0.1:8787`.

## Docker Run

```bash
docker build -t agenc-prover .
docker run --rm -p 8787:8787 agenc-prover
```

## Planned Direction

- local sidecar mode for Linux x86_64 operators
- later swap `http://127.0.0.1:8787` to hosted endpoints like `https://prover.agenc.tech`
- add auth, rate limiting, billing, and full RISC Zero proof generation without changing the AgenC client contract

