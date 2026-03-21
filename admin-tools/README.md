# Admin Tools

This package is the first private `agenc-prover` bootstrap slice.

It owns:

- zk config administration
- protocol program helpers for admin flows
- devnet preflight checks for private submission surfaces

It does **not** own:

- `verifier-localnet`
- private-proof benchmark entrypoints or helpers
- root verifier/bootstrap scripts or tests
- protocol-owned `scripts/idl/**` artifacts

Run locally from the repository root:

```bash
npm --prefix admin-tools install
npm --prefix admin-tools run typecheck
npm --prefix admin-tools run test
npm --prefix admin-tools run zk:config -- show
npm --prefix admin-tools run devnet:preflight
```

Environment baseline:

- Node.js 22+
- npm 11.7.0
- committed `admin-tools/package-lock.json` for deterministic installs

Use [../docs/ADMIN_TOOLS.md](../docs/ADMIN_TOOLS.md) for the full command reference, image-id input formats, signer defaults, and the `devnet:preflight` caveat that it is a synthetic compatibility probe rather than the production prover contract.
