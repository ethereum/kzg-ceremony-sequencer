FROM rust:1.62 as build

# create a new empty shell project
RUN USER=root cargo new --bin sequencer
WORKDIR /sequencer

# copy private key and public key
COPY ./private.key ./private.key
COPY ./publickey.pem ./publickey.pem

# copy over your manifests
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# this build step will cache your dependencies
RUN cargo build --release
RUN rm src/*.rs

# copy your source tree
COPY ./src ./src

# build for release
RUN rm ./target/release/deps/kzg_ceremony_sequencer*
RUN cargo build --release

# our final base
FROM debian:buster-slim

# copy the build artifact from the build stage
COPY --from=build /sequencer/target/release/kzg_ceremony_sequencer .

# set the startup command to run your binary
ENTRYPOINT ./sequencer