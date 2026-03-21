# Admin Tools

This file documents the private admin surface shipped under `admin-tools/`.

## Commands

### `zk:config`

```bash
npm --prefix admin-tools run zk:config -- <show|init|rotate> [options]
```

Supported commands:

- `show` - print protocol and `zk_config` state
- `init` - create `zk_config` with the provided image id
- `rotate` - update `zk_config.active_image_id`

Supported options:

- `--rpc-url <url>`
- `--program-id <pubkey>`
- `--authority-keypair <path>`
- `--image-id <value>`

Accepted image-id formats:

- comma-separated bytes
- JSON array
- hex string with or without `0x`

Defaults come from `ANCHOR_PROVIDER_URL` and `ANCHOR_WALLET` when set, otherwise from local Solana defaults.

### `devnet:preflight`

```bash
npm --prefix admin-tools run devnet:preflight
```

This is a synthetic compatibility probe for router-based private submission surfaces. It validates payload shape and PDA derivation against known IDs. It is not the production prover contract and should not be treated as proof of a live operator deployment.

## Cross-Repo Dependencies

`admin-tools` consumes:

- `@tetsuo-ai/protocol` for protocol artifacts
- `@tetsuo-ai/sdk` for shared IDs and helpers

Change the protocol contract in `agenc-protocol` or the client helper layer in `agenc-sdk` first when the admin tools only consume those surfaces.

