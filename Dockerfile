# Cloud Run 用マルチステージビルド。

FROM rust:1.92-slim AS build
WORKDIR /app
# 依存だけ先にビルドしてレイヤキャッシュを効かせる。
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release && rm -rf src
COPY src ./src
# touch でソース更新を確実に検知させてから本ビルド。
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/rust-idp /usr/local/bin/rust-idp
ENV PORT=8080
EXPOSE 8080
CMD ["rust-idp"]
