FROM rust:1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --bin ferrodns-live

FROM debian:bookworm-slim
COPY --from=build /build/target/release/ferrodns-live /usr/local/bin/ferrodns-live
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ferrodns-live"]
CMD ["--bind", "0.0.0.0:8080"]
