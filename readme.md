# KZG Ceremony Rest API

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