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
- health check endpoint
- Docker packaging

## Local Run

```bash
cargo run -p agenc-prover-server --features production-prover
```

By default the server binds to `127.0.0.1:8787`.

Print the compiled image ID:

```bash
cargo run -p agenc-prover-server --features production-prover -- image-id
```

## Docker Run

```bash
docker build -t agenc-prover .
docker run --rm \
  -p 8787:8787 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  agenc-prover
```

Notes:

- the current RISC Zero Groth16 path needs Linux `x86_64`
- the container needs the host Docker socket because local Groth16 proving uses Docker under the hood
- this is meant to run as a local sidecar or an operator-managed prover service, not inside the main AgenC app process

## Planned Direction

- local sidecar mode for Linux x86_64 operators
- later swap `http://127.0.0.1:8787` to hosted endpoints like `https://prover.agenc.tech`
- add auth, rate limiting, and billing without changing the response contract
