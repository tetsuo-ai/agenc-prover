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
- `/healthz`, `/readyz`, and `/metrics` stay unauthenticated

Execution controls:

- `PROVER_MAX_IN_FLIGHT` limits how many proof requests can run at once
- `PROVER_REQUEST_TIMEOUT_SECS` bounds how long the HTTP request waits for a proof result
- `PROVER_RATE_LIMIT_MAX_REQUESTS` caps how many `/prove` calls are accepted per window
- `PROVER_RATE_LIMIT_WINDOW_SECS` defines that fixed rate-limit window
- once the rate limit is exceeded, `/prove` returns `429`
- the server does not queue extra work; once saturated, `/prove` fails fast with `503`
- timed out requests return `504`
- `429`, `503`, and `504` include `Retry-After`

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
- in-memory fixed-window rate limiting on `/prove`
- health, readiness, and metrics endpoints
- Docker packaging

## Operational Endpoints

### `GET /healthz`

Liveness only. This returns `200` when the process is up.

### `GET /readyz`

Admission readiness. This returns:

- `200` when the prover can admit at least one more proof job
- `503` when all execution slots are saturated

Response JSON:

```json
{
  "ok": true,
  "service": "agenc-prover-server",
  "ready": true,
  "available_slots": 1,
  "max_in_flight": 1
}
```

`ready` is based on proof admission capacity, not just process liveness.

### `GET /metrics`

Prometheus-style plaintext metrics with:

- build identity, including the pinned guest `image_id`
- readiness and available execution slots
- configured timeout and rate-limit policy
- `/prove` request counters for auth failures, bad requests, rate limits, overload, and timeouts
- proof lifecycle counters for started, completed, succeeded, invalid, and failed jobs
- aggregate proof duration counters

## Local Run

Protected mode is now the default:

```bash
PROVER_API_KEY=change-me \
PROVER_MAX_IN_FLIGHT=1 \
PROVER_REQUEST_TIMEOUT_SECS=900 \
PROVER_RATE_LIMIT_MAX_REQUESTS=10 \
PROVER_RATE_LIMIT_WINDOW_SECS=60 \
cargo run -p agenc-prover-server --features production-prover
```

That starts the server on `127.0.0.1:8787` and requires:

```text
Authorization: Bearer change-me
```

Example checks:

```bash
curl http://127.0.0.1:8787/healthz
curl http://127.0.0.1:8787/readyz
curl http://127.0.0.1:8787/metrics
curl -H 'Authorization: Bearer change-me' http://127.0.0.1:8787/prove
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
- because the Docker image binds `0.0.0.0`, it will refuse to start without `PROVER_API_KEY`
- the Docker build pins the prover toolchain instead of bootstrapping it from a floating installer script
- pinned Docker toolchain versions:
  - `rzup 0.5.1`
  - RISC Zero Rust toolchain `1.91.1`
  - RISC Zero C++ toolchain `2024.01.05`
  - `cargo-risczero 3.0.5`
  - `r0vm 3.0.5`
  - `risc0-groth16 0.1.0`
- those pins match the current `risc0-zkvm 3.0.5` / `risc0-build 3.0.5` generation used by this repo
- default execution policy is one in-flight proof, a 15 minute request timeout, and 10 requests per 60 second window
- timed out HTTP requests do not cancel the in-progress proof; the work continues until the prover finishes and the slot frees
- `/readyz` will return `503` whenever that in-flight limit is fully occupied

## Production Verification Gate

Release verification for the production prover is now pinned to the shared assumptions in:

```text
scripts/production-toolchain.env
```

That file is consumed by:

- the Docker build
- local Linux `x86_64` verification scripts
- the GitHub Actions production verification workflow

Reproduce the release gate locally on Linux `x86_64`:

```bash
rustup toolchain install 1.90.0 --profile minimal --component rustfmt --component clippy
rustup default 1.90.0
./scripts/install-production-toolchain.sh
cargo build --release -p agenc-prover-server --features production-prover
./scripts/verify-production-image-id.sh ./target/release/agenc-prover-server
./scripts/write-build-metadata.sh dist/production-build-metadata.json ./target/release/agenc-prover-server
sha256sum ./target/release/agenc-prover-server > dist/agenc-prover-server.sha256
```

The GitHub Actions workflow at `.github/workflows/production-prover-verification.yml` rebuilds the prover on Linux `x86_64`, checks the computed image ID against `TRUSTED_RISC0_IMAGE_ID`, and uploads:

- `dist/production-build-metadata.json`
- `dist/agenc-prover-image-id.txt`
- `dist/agenc-prover-server.sha256`

## Planned Direction

- local sidecar mode for Linux x86_64 operators
- later swap `http://127.0.0.1:8787` to hosted endpoints like `https://prover.agenc.tech`
- add distributed quotas and billing without changing the response contract
