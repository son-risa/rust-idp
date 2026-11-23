# Cloud Run 用マルチステージビルド。
# Firebase Functions は Rust ランタイム非対応のため、Cloud Run コンテナとして
# デプロイし Firebase Hosting から rewrite で繋ぐ（現行 TS の Cloud Run 構成と同じ）。

# 版は rust-toolchain.toml と同じにする。実行イメージと Debian の版（trixie）を揃える（glibc の版ずれを避ける）。
FROM rust:1.100.0-slim-trixie AS build
WORKDIR /app
# 依存だけ先にビルドしてレイヤキャッシュを効かせる。
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release && rm -rf src
COPY src ./src
# touch でソース更新を確実に検知させてから本ビルド。
RUN touch src/main.rs && cargo build --release

# 実行イメージは Debian slim（distroless でも可だが glibc 依存の調整が要るため slim を既定に）。
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/rust-idp /usr/local/bin/rust-idp
ENV PORT=8080
EXPOSE 8080
CMD ["rust-idp"]
