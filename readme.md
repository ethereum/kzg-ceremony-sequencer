## KZG Ceremony Rest API


## Endpoints

This implements all of the endpoints located [here](https://hackmd.io/vTOy8-XwSOO4ugLHTyA5pw) . Much of the rationale is also located in that file.

## Requirements

- OAuth Client App : Currently we require users to sign in with either Ethereum or Github, which requires an OAuth client application that the user gives read access to their profile to.

- Keypair generation algorithm : The coordinator signs JWTs that can be verified by external parties. [Openssl is recommended](https://hackmd.io/PidEKWJEQpaYQ6qtTRALWQ?both).

## Live URL

- kzg-ceremony-poc.fly.dev
- You can use the endpoint `/hello_world` to check that the server is running