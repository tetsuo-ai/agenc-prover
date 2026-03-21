# Prover Codebase Map

This file maps the full `agenc-prover` repo for developers and AI agents.

## Top-Level Layout

```text
agenc-prover/
  server/              HTTP proving service
  guest/               shared witness and journal math
  methods/             zkVM guest entry and build integration
  admin-tools/         private admin TypeScript package
  scripts/             benchmark and production-verification helpers
  docs/                repo-level developer docs
  .github/workflows/   CI and production verification
  README.md
  Cargo.toml
  Dockerfile
```

## Source Map

- `server/src/main.rs` - HTTP routes, auth, readiness, metrics, and image-id command
- `server/src/prover.rs` - witness validation, trusted image pinning, Groth16 proving, and seal encoding
- `guest/src/lib.rs` - shared journal/witness field logic
- `methods/guest/src/main.rs` - zkVM guest entry
- `admin-tools/zk-config-admin.ts` - zk-config administration flow
- `admin-tools/zk-config-admin-cli.ts` - CLI parsing and help text
- `admin-tools/devnet-preflight.ts` - synthetic compatibility probe for private submission surfaces

## Automation

- `scripts/check-admin-bootstrap-boundary.mjs` - guard the admin/bootstrap boundary
- `scripts/benchmark-prove.sh` - checked-in `/prove` benchmark entrypoint
- `scripts/install-production-toolchain.sh` - pinned production toolchain installer
- `scripts/verify-production-image-id.sh` - production image verification
- `scripts/write-build-metadata.sh` - build metadata capture
- `.github/workflows/ci.yml` - Rust server and admin-tools checks
- `.github/workflows/production-prover-verification.yml` - pinned Linux `x86_64` production build verification

## Ownership Boundaries

- This repo owns the proving server and private admin flows.
- Protocol source of truth belongs in `agenc-protocol`.
- Client-facing helper APIs belong in `agenc-sdk`.
- Runtime/operator orchestration belongs in `agenc-core`.

The shared proof-harness work in `agenc-core/tools/proof-harness` is separate from this repo's proving-server ownership.

