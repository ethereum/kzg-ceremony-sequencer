# KZG Ceremony Rest API

![lines of code](https://img.shields.io/tokei/lines/github/ethereum/kzg-ceremony-sequencer)
[![dependency status](https://deps.rs/repo/github/ethereum/kzg-ceremony-sequencer/status.svg)](https://deps.rs/repo/github/ethereum/kzg-ceremony-sequencer)
[![codecov](https://codecov.io/gh/ethereum/kzg-ceremony-sequencer/branch/main/graph/badge.svg?token=WBPZ9U4TTO)](https://codecov.io/gh/ethereum/kzg-ceremony-sequencer)
[![CI](https://github.com/ethereum/kzg-ceremony-sequencer/actions/workflows/build-test-deploy.yml/badge.svg)](https://github.com/ethereum/kzg-ceremony-sequencer/actions/workflows/build-test-deploy.yml)

This implements [KZG Ceremony Specification](https://github.com/ethereum/kzg-ceremony-specs).

## Setup

### Database

1. Run `cargo install sqlx-cli`
2. Set `DATABASE_URL=sqlite:/path/to/sequencer.db`
3. Run `sqlx database create`
4. Migrations will be run automatically on server startup

## Requirements

- OAuth Client App : Currently we require users to sign in with either Ethereum or Github, which requires an OAuth client application that the user gives read access to their profile to.

- Keypair generation algorithm : The sequencer signs JWTs that can be verified by external parties. [Openssl is recommended](https://hackmd.io/PidEKWJEQpaYQ6qtTRALWQ?both).

## Live URL

- kzg-ceremony-poc.fly.dev
- You can use the endpoint `/hello_world` to check that the server is running
