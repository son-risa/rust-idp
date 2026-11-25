# Cloud Run 用マルチステージビルド。
# Firebase Functions は Rust ランタイム非対応のため、Cloud Run コンテナとして
# デプロイし Firebase Hosting から rewrite で繋ぐ（現行 TS の Cloud Run 構成と同じ）。

# 版は rust-toolchain.toml と同じにする。実行イメージと Debian の版（trixie）を揃える（glibc の版ずれを避ける）。
FROM rust:1.100.0-slim-trixie AS build
WORKDIR /app
# 依存だけ先にビルドしてレイヤキャッシュを効かせる。
# 本番は Firestore・KMS などへ出る実装を入れた gcp の feature で build する（Cargo.toml の [features]）。
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release --features gcp && rm -rf src
COPY src ./src
# touch でソース更新を確実に検知させてから本ビルド。
RUN touch src/main.rs src/lib.rs && cargo build --release --features gcp
# gcp 無しの binary を載せると、Cloud Run で起動を断る（src/main.rs）。その文言は gcp 無しの build にだけ入るので、
# 在れば build を止める。起動して確かめないのは、Cloud Build の中では metadata に届き本番の設定で動きうるため。
RUN ! grep -aq 'built without the gcp feature' target/release/rust-idp

# 実行イメージは Debian slim（distroless でも可だが glibc 依存の調整が要るため slim を既定に）。
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/rust-idp /usr/local/bin/rust-idp
ENV PORT=8080
EXPOSE 8080
CMD ["rust-idp"]
