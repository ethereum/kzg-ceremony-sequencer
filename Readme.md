# KZG Ceremony Rest API

![lines of code](https://img.shields.io/tokei/lines/github/ethereum/kzg-ceremony-sequencer)
[![dependency status](https://deps.rs/repo/github/ethereum/kzg-ceremony-sequencer/status.svg)](https://deps.rs/repo/github/ethereum/kzg-ceremony-sequencer)
[![codecov](https://codecov.io/gh/ethereum/kzg-ceremony-sequencer/branch/main/graph/badge.svg?token=WBPZ9U4TTO)](https://codecov.io/gh/ethereum/kzg-ceremony-sequencer)
[![CI](https://github.com/ethereum/kzg-ceremony-sequencer/actions/workflows/build-test-deploy.yml/badge.svg)](https://github.com/ethereum/kzg-ceremony-sequencer/actions/workflows/build-test-deploy.yml)

This implements [KZG Ceremony Specification](https://github.com/ethereum/kzg-ceremony-specs).

The latest build is available as a container on [ghcr.io/ethereum/kzg-ceremony-sequencer](https://github.com/ethereum/kzg-ceremony-sequencer/pkgs/container/kzg-ceremony-sequencer):

```shell
docker run ghcr.io/ethereum/kzg-ceremony-sequencer:latest
```

## Setup

### Build, lint, test, run

```shell
cargo fmt && cargo clippy --workspace --all-targets --all-features && cargo build --workspace --all-targets --all-features && cargo test --workspace --all-targets --all-features && cargo run -- -vvv
```

## Requirements

- OAuth Client App : Currently we require users to sign in with either Ethereum or Github, which requires an OAuth client application that the user gives read access to their profile to.

## Live URL

- <https://kzg-ceremony-sequencer-dev.fly.dev/info/status>

## Registering for GitHub OAuth

Register for Github OAuth access [here](https://github.com/settings/developers).

## Registering for Sign-in-with-Ethereum

See the documentation [here](https://docs.login.xyz/servers/oidc-provider/hosted-oidc-provider).

To register, use the REST API:

```shell
curl -X POST https://oidc.signinwithethereum.org/register \
   -H 'Content-Type: application/json' \
   -d '{"redirect_uris": ["http://127.0.0.1:3000/auth/callback/eth", "https://kzg-ceremony-sequencer-dev.fly.dev/auth/callback/eth"]}'
```

```json
{
  "client_id": "9b49de48-d198-47e7-afff-7ee26cbcbc95",
  "client_secret": "...",
  "registration_access_token": "....",
  "registration_client_uri": "https://oidc.signinwithethereum.org/client/9b49de48-d198-47e7-afff-7ee26cbcbc95",
  "redirect_uris": [
    "http://127.0.0.1:3000/auth/callback/eth",
    "https://kzg-ceremony-sequencer-dev.fly.dev/auth/callback/eth"
  ]
}
```

```shell
fly secrets set ETH_RPC_URL="..."
fly secrets set ETH_CLIENT_ID="..."
fly secrets set ETH_CLIENT_SECRET="..."
fly secrets set GH_CLIENT_ID="..."
fly secrets set GH_CLIENT_SECRET="..."
fly volumes create kzg_ceremony_sequencer_dev_data --size 5
```

* Fly server: <https://kzg-ceremony-sequencer-dev.fly.dev/info/status>
* Fly dashboard: <https://fly.io/apps/kzg-ceremony-sequencer-dev>
