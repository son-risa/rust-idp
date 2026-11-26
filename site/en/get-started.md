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

The example puts a signed-in session straight into the store. It does not pass a `DocumentStore`, so passkey sign-in is not available in it.

### What needs the `gcp` feature

The implementations that talk to Firestore, Cloud KMS, Secret Manager, FCM and Resend are behind the `gcp` feature. The feature is off by default.

Without it, the bundled binary keeps users and passkeys in a `MemoryDocumentStore`. Passkey registration and sign-in work. Everything is lost when the process stops.

A provider built with `Provider::new` alone has no `DocumentStore`. Pass one with `with_document_store`. Without one, these answer 503:

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

### What it costs {#costs}

For a small organization, running rust-idp this way costs almost nothing, but it is not entirely free.

**You must enable billing.** The Google Cloud project needs a billing account. Cloud Run does not run without one, and Firestore's TTL (deleting expired documents) does not work without one.

**What fits in the free tier.** Firestore has a daily free quota per project. Within it, these cost nothing:

| Firestore (Tokyo, `asia-northeast1`) | Free each day | Price above the free quota |
|---|---|---|
| Document reads | 50,000 | USD 0.38 per million |
| Document writes | 20,000 | USD 1.15 per million |
| Document deletes | 20,000 | USD 0.13 per million |
| Stored data | 1 GiB | USD 0.115 per GiB per month |

Cloud Run's first 2 million requests each month are free for each billing account. For the free amounts of CPU and memory, see the [Cloud Run pricing page](https://cloud.google.com/run/pricing). rust-idp runs with a minimum of 0 instances, so nothing runs while nobody signs in.

**What has no free tier.** These are charged from the first unit, so a deployment that otherwise stays in the free tier still gets a small bill:

| Firestore (Tokyo, `asia-northeast1`) | Price |
|---|---|
| TTL deletes (documents deleted by a TTL policy after they expire) | USD 0.13 per million |
| Point-in-time recovery (PITR) storage | USD 0.115 per GiB per month |

rust-idp sets an expiry on short-lived records, such as sessions and authorization codes, and Firestore's TTL deletes them. Google's [TTL page](https://cloud.google.com/firestore/docs/ttl) says: "TTL delete operations count towards your document delete costs." It also says: "Data is typically deleted within 24 hours after its expiration date."

An estimate for 30 people: if each person signs in 10 times a day and, to be generous, every document written is later deleted by TTL, that is about 100,000 TTL deletes a month, or about USD 0.013 (about 2 yen at 150 yen to the dollar). As an observed example, one production deployment had about 2,000 TTL deletes over 30 days, from a handful to several hundred a day, which comes to about USD 0.0003 (Cloud Monitoring metric `firestore.googleapis.com/document/ttl_deletion_count`, checked on 2026-11-26).

PITR keeps 7 days of history. At rust-idp's scale the stored data is very small, so the PITR storage charge is very small too.

**Prices can change.** The prices above are from Google's price list, checked on 2026-11-26 (Cloud Billing Catalog API, Firestore Standard edition, Tokyo). Check the current prices on the [Firestore pricing page](https://cloud.google.com/firestore/pricing) and the [Cloud Run pricing page](https://cloud.google.com/run/pricing). To check them yourself from the catalog:

```sh
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  'https://cloudbilling.googleapis.com/v1/services/EE2C-7FAC-5E08/skus?pageSize=5000&currencyCode=USD'
```

**If you want to be told about charges**, set a [budget and budget alerts](https://cloud.google.com/billing/docs/how-to/budgets) in Cloud Billing. A budget sends a notice when spending reaches the amounts you set. It does not stop the charges by itself.

### TTL policies {#ttl}

rust-idp writes an expiry time on short-lived records, but on Firestore it does not delete them itself. You set the TTL policies yourself. Without them, expired records are never deleted and stay in the database. They are no longer used, but they keep taking up storage.

Set a policy on each of these collections and fields:

| Field | Collections |
|---|---|
| `expiresAt` | `accessTokens`, `accountLocks`, `authCodes`, `cibaRequests`, `emailChallenges`, `fidoChallenges`, `interactions`, `nonces`, `parRequests`, `refreshFamilyRevocations`, `refreshTokens`, `sessions`, `webauthnChallenges` |
| `expireAt` | `cibaHistory`, `rateLimits` |

For example, for `sessions` in the `(default)` database:

```sh
gcloud firestore fields ttls update expiresAt \
  --collection-group=sessions --enable-ttl --database='(default)'
```

Run it once for each row and collection above. `gcloud firestore fields ttls list --database='(default)'` shows the policies you have.

## Run it locally

```sh
cargo run                                    # http://localhost:8080
FIRESTORE_EMULATOR_HOST=127.0.0.1:8180 cargo run --features gcp   # Firestore emulator only
```

Locally, Firestore, Resend and KMS are off: storage is in memory, mail goes to the log, and the signing key is new on every start.
