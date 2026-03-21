# Prover Commands And Validation

This file maps the local validation and workflow surface for `agenc-prover`.

## Core Local Checks

```bash
cargo test -p agenc-prover-server
cargo build --release -p agenc-prover-server --features production-prover
node scripts/check-admin-bootstrap-boundary.mjs
npm ci --prefix admin-tools
npm --prefix admin-tools run typecheck
npm --prefix admin-tools run test
```

Those are the same checks enforced by `.github/workflows/ci.yml`.

## Production Verification Workflow

`.github/workflows/production-prover-verification.yml` additionally checks:

- pinned Linux `x86_64` production build
- production toolchain installation
- trusted image-id verification
- captured build metadata

## Script Inventory

- `scripts/check-admin-bootstrap-boundary.mjs` - boundary guard
- `scripts/benchmark-prove.sh` - benchmark `/prove`
- `scripts/install-production-toolchain.sh` - install pinned production toolchain
- `scripts/verify-production-image-id.sh` - verify trusted image id
- `scripts/write-build-metadata.sh` - capture metadata for release artifacts

## Admin Package Commands

```bash
npm --prefix admin-tools run zk:config -- show
npm --prefix admin-tools run devnet:preflight
```

