# KZG Ceremony Library

Implements the formats and cryptography for the [Ethereum KZG Ceremony](https://github.com/ethereum/kzg-ceremony-specs/).

## Hints

Lint, build and test

```shell
cargo fmt && cargo clippy --workspace --all-targets --all-features && cargo build --release --all-targets --all-features && cargo test --workspace --all-targets --all-features
```

Run benchmarks

```shell
cargo bench --workspace --bench=criterion --features=bench,arkworks
```

The report will be produced at [`../target/criterion/index.html`](../target/criterion/index.html).
