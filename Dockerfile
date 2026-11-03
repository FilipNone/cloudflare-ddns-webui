# ---- Build ----
FROM rust:1.99.1-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY web ./web
RUN cargo build --locked --release
RUN apk add --no-cache upx && upx --best --lzma target/release/cloudflare-ddns-webui
RUN mkdir /runtime-data && chown 65534:65534 /runtime-data && chmod 700 /runtime-data

# ---- Release ----
FROM scratch AS release
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/target/release/cloudflare-ddns-webui /cloudflare-ddns-webui
# Writable data dir for state.json / ui settings (mount a volume here).
COPY --from=builder --chown=65534:65534 /runtime-data /data
USER 65534:65534
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/cloudflare-ddns-webui"]
