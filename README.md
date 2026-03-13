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
  "nullifier": [32 bytes],
  "output": [
    [32 bytes],
    [32 bytes],
    [32 bytes],
    [32 bytes]
  ],
  "salt": [32 bytes],
  "agent_secret": [32 bytes]
}
```

The request now includes the private witness needed to prove the statement:

- `constraint_hash` must be recomputed from `output`
- `output_commitment` must be recomputed from `output + salt`
- `binding` must be recomputed from `task_pda + agent_authority + output_commitment`
- `nullifier` must be recomputed from `constraint_hash + output_commitment + agent_secret`

If any public field does not match the witness-derived value, `/prove` returns `400`.

Authentication:

- `/prove` requires `Authorization: Bearer <token>` by default
- set `PROVER_API_KEY` on the server to define that token
- only explicit local sidecar mode can disable auth: `PROVER_LOCAL_DEV_MODE=true`
- local sidecar mode is only allowed when the server binds to loopback
- `/healthz` stays unauthenticated

Response JSON:

```json
{
  "seal_bytes": [...],
  "journal": [...],
  "image_id": [...]
}
```

## Current Status

This repository now contains the real proving path:

- fixed `/prove` HTTP contract for AgenC
- embedded RISC Zero guest/method build
- Groth16 proof generation
- witness-based validation of the public journal fields before proving
- fail-closed guard if the compiled guest image ID drifts from AgenC's pinned trusted image
- explicit auth on `/prove`, with startup failure if the service is exposed without credentials
- health check endpoint
- Docker packaging

## Local Run

Protected mode is now the default:

```bash
PROVER_API_KEY=change-me \
cargo run -p agenc-prover-server --features production-prover
```

That starts the server on `127.0.0.1:8787` and requires:

```text
Authorization: Bearer change-me
```

Explicit local sidecar mode keeps `/prove` unauthenticated, but only on loopback:

```bash
PROVER_LOCAL_DEV_MODE=true \
cargo run -p agenc-prover-server --features production-prover
```

Print the compiled image ID:

```bash
cargo run -p agenc-prover-server --features production-prover -- image-id
```

## Docker Run

```bash
docker build -t agenc-prover .
docker run --rm \
  -e PROVER_API_KEY=change-me \
  -p 8787:8787 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  agenc-prover
```

Notes:

- the current RISC Zero Groth16 path needs Linux `x86_64`
- the container needs the host Docker socket because local Groth16 proving uses Docker under the hood
- this is meant to run as a local sidecar or an operator-managed prover service, not inside the main AgenC app process
<<<<<<< HEAD
- the Docker build pins the prover toolchain instead of bootstrapping it from a floating installer script
- pinned Docker toolchain versions:
  - `rzup 0.5.1`
  - RISC Zero Rust toolchain `1.91.1`
  - RISC Zero C++ toolchain `2024.01.05`
  - `cargo-risczero 3.0.5`
  - `r0vm 3.0.5`
  - `risc0-groth16 0.1.0`
- those pins match the current `risc0-zkvm 3.0.5` / `risc0-build 3.0.5` generation used by this repo
=======
- because the Docker image binds `0.0.0.0`, it will refuse to start without `PROVER_API_KEY`
>>>>>>> origin/main

## Planned Direction

- local sidecar mode for Linux x86_64 operators
- later swap `http://127.0.0.1:8787` to hosted endpoints like `https://prover.agenc.tech`
- add rate limiting and billing without changing the response contract
