# Get started

There are two ways to run rust-idp: embed it in your own axum application, or deploy the bundled binary to Cloud Run.

## Embed it as a library

rust-idp is one crate. Build a `rust_idp::Provider` and turn it into an axum `Router` with `rust_idp::router`. Storage, signing keys and mail are traits; the defaults are in-memory storage and a signing key generated at start-up.

The crate is not on crates.io yet. Depend on the repository:

```toml
[dependencies]
rust-idp = { git = "https://github.com/son-risa/rust-idp" }
```

Run the example. It starts a provider on localhost and walks discovery, `/authorize`, the authorization code and `/token` in one process:

```sh
cargo run --example in_memory
```

The example puts a signed-in session straight into the store, because passkey sign-in needs the user store in Firestore.

### What needs the `gcp` feature

The implementations that talk to Firestore, Cloud KMS, Secret Manager, FCM and Resend are behind the `gcp` feature, which is off by default. Without it, these answer with an error such as 503:

- passkey registration and sign-in
- PAR and dynamic client registration
- the admin pages

## Deploy it to Cloud Run

The `Dockerfile` builds the production binary with `--features gcp`. Cloud Build builds it from source, so you do not need Docker locally.

```sh
gcloud run deploy <service> --source . --region <region>
```

You need:

- a Firestore database
- ES256 and RS256 signing keys in Cloud KMS (`KMS_ES256_KEY`, `KMS_RS256_KEY`). Without them it falls back to keys in Secret Manager
- `RESEND_API_KEY`, for sign-up and recovery mail
- a runtime service account with `cloudkms.signerVerifier` and `datastore.user`
- `ORIGIN` and `BASE_PATH`; the issuer is `ORIGIN + BASE_PATH`

On Cloud Run, the binary refuses to start if it cannot load both signing keys. A binary built without `gcp` refuses to start on Cloud Run at all.

Map your custom domain directly to the Cloud Run service. No load balancer is needed.

## Run it locally

```sh
cargo run                                    # http://localhost:8080
FIRESTORE_EMULATOR_HOST=127.0.0.1:8180 cargo run --features gcp   # Firestore emulator only
```

Locally, Firestore, Resend and KMS are off: storage is in memory, mail goes to the log, and the signing key is new on every start.
