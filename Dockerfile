# FROM rust:1.62.1-buster

# COPY ./target/release/coordinator-rest /opt/coordinator-rest

# RUN /opt/coordinator-rest

# Other way below

# FROM rust:1.43 as builder

# RUN USER=root cargo new --bin coordinator-rest
# WORKDIR ./coordinator-rest
# COPY ./Cargo.toml ./Cargo.toml
# RUN cargo build --release
# RUN rm src/*.rs

# ADD . ./

# RUN rm ./target/release/deps/coordinator-rest*
# RUN cargo build --release


# FROM debian:buster-slim
# ARG APP=/usr/src/app


# 1. This tells docker to use the Rust official image
# FROM rust:1.62

# # 2. Copy the files in your machine to the Docker image
# COPY ./ ./

# # Build your program for release
# RUN cargo build --release

# # Run the binary
# CMD ["./target/release/coordinator-rest"]

FROM rust:1.62 as build

# create a new empty shell project
RUN USER=root cargo new --bin coordinator_rest
WORKDIR /coordinator_rest

# copy over your manifests
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# this build step will cache your dependencies
RUN cargo build --release
RUN rm src/*.rs

# copy your source tree
COPY ./src ./src

# build for release
RUN rm ./target/release/deps/coordinator_rest*
RUN cargo build --release

# our final base
FROM debian:buster-slim

# copy the build artifact from the build stage
COPY --from=build /coordinator_rest/target/release/coordinator_rest .

# set the startup command to run your binary
ENTRYPOINT ./coordinator_rest