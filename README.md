# rust-idp

A passkey-first OpenID Provider in Rust. It runs as a single Cloud Run service, lets you choose how strict each client must be, and publishes every security claim together with the assumptions it rests on.

**Website: https://docs.amate.ai/idp/** (English / 日本語)

Status: v0.1.0 · running in one production deployment · MIT · not certified. The API may change. Not yet on crates.io.

パスキーでログインする OpenID Provider（Rust 製）。紹介・特徴・検証の範囲は、上のサイトにまとめている（日本語版あり）。

## Try it

```sh
cargo run --example in_memory   # starts a provider on localhost and walks discovery → authorization code → token
```

Build a `rust_idp::Provider` and turn it into an axum `Router` with `rust_idp::router`. Storage, signing keys and mail are traits you can replace (`Store`, `JwsSigner`, `Mailer`, `ClientAuthMethod`, `GrantHandler`, and others).

Passkey sign-in, PAR, dynamic client registration and the admin pages need the `gcp` feature (Firestore, Cloud KMS, Secret Manager, FCM, Resend). It is off by default; the production binary is built with it (`Dockerfile`).

## Documents

- Website: [Get started](https://docs.amate.ai/idp/get-started/) · [Verification](https://docs.amate.ai/idp/verification/)
- [docs/verification-map.md](docs/verification-map.md): which models, tests and premises apply to each client profile
- [docs/routes.md](docs/routes.md): every HTTP route
- [docs/development.md](docs/development.md): running locally, the FIDO2 conformance tool, heavy fuzzing, static clients, deploy notes (Japanese)
- [docs/operations.md](docs/operations.md): environment variables, what to do when a user can no longer use their passkey, and the former name (Japanese)
- [formal/README.md](formal/README.md): Tamarin models and Kani harnesses
- [docs/security-ladder.md](docs/security-ladder.md), [docs/zero-trust-assessment.md](docs/zero-trust-assessment.md), [docs/crypto-assumptions.md](docs/crypto-assumptions.md)

The site's source is in [`site/`](site/) (built with Zensical; see `site/build.sh`).

## Checks

```sh
cargo test --features gcp   # all tests, same configuration as production
formal/check.sh             # Tamarin models against formal/expected.tsv
formal/check-kani.sh        # Kani harnesses against formal/kani-harnesses.txt
cargo deny check            # advisories and licences
```

## License

MIT ([`LICENSE`](LICENSE)). rust-idp is an independent Rust implementation and does not copy source code from other projects. Acknowledgements (node-oidc-provider, SimpleWebAuthn, webauthn-rs and others) are in [`CREDITS.md`](CREDITS.md); runtime dependency licences are in [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md).
