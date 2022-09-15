# KZG Ceremony Library

Implements the formats and cryptography for the [Ethereum KZG Ceremony](https://github.com/ethereum/kzg-ceremony-specs/).

## Hints

Lint, build and test

```shell
cargo fmt && cargo clippy --all-targets --all-features && cargo build --release --all-targets --all-features && cargo test --all-targets --all-features
```

Run benchmarks

```shell
cargo bench --bench=criterion --features=bench
```
