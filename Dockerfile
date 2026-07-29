# ---- Build ----
FROM rust:alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY web ./web
RUN cargo build --release
RUN apk add --no-cache upx && upx --best --lzma target/release/cloudflare-ddns-webui

# ---- Release ----
FROM scratch AS release
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/target/release/cloudflare-ddns-webui /cloudflare-ddns-webui
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/cloudflare-ddns-webui"]
