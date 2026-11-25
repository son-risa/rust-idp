# Extending

This page is for developers who want to adapt rust-idp to their own environment. It says what you can replace, what you cannot replace yet, and how to change it safely.

## Terms

- **Extension point**: a place where you can plug in your own implementation. Most are traits. You plug them in with the `with_*` functions of `Provider`.
- **Contract tests**: a set of tests for the promises of a trait. The same tests run against every implementation. They live in `src/*_contract.rs`. One macro call runs all of them against an implementation.
- **No extension point yet**: the current code has no place to plug in. To add one, first decide its shape: the trait's functions and its promises.

## Extension axes

| Axis | Examples | Extension point | Contract tests |
|---|---|---|---|
| Where it runs | Cloud Run, VPS, k8s | Where the parts are assembled. The binary is assembled in `src/main.rs` and `src/gcp.rs`. As a library, you build the `Provider` in your own `main` | None |
| Storage | In memory, Firestore → PostgreSQL, SQLite | `DocumentStore` (`with_document_store`), `Store` (`with_store`), `CibaStore` (`with_ciba`), `FidoStore` (chosen inside `FidoState::from_env`; there is no `with_*`) | Yes: `document_store_contract.rs`, `store_contract.rs`, `ciba_store_contract.rs`, `fido_store_contract.rs` |
| Keys and signing | Cloud KMS → key file, Vault, other KMS, HSM | `JwsSigner` (`with_signer`, `add_signer`) | Yes: `jws_signer_contract.rs` |
| How users are verified | Passkeys → an existing password DB, LDAP/AD, an upstream IdP | No extension point yet. Passkey verification is written directly in `src/webauthn.rs` and the registration flow | None |
| Where users come from | Own sign-up → an existing user DB, SCIM | No extension point yet. The user list is the `accounts` collection in `DocumentStore`. Sign-up, deactivation and token issuance read it directly. Claims for the id_token and similar come from `Store::find_account` | None. `find_account` is not in the `Store` contract tests |
| How messages are sent | Resend → SMTP, SES | `Mailer` (`with_mailer`) | Yes: `mailer_contract.rs` |
| What it connects to | OIDC RPs, API introspection → forward-auth in front of an existing site that uses Basic auth, SAML | No extension point yet. `rust_idp::router` builds the routes | None |
| Authorization types | Grant types, request checks | `GrantHandler` (`with_grant`), `AuthorizationCheck` (`with_check`), `ResponseMode` (`with_response_mode`) | None |
| Client authentication | private_key_jwt, Basic → mTLS | `ClientAuthMethod` (`with_client_auth`), `DpopVerifier` (`with_dpop`). For mTLS, the input `ClientAuthInput` has no field for the client certificate. Start by extending the input | None |
| Observability | OpenTelemetry and others | No extension point yet. rust-idp writes its logs with `tracing`. As a library, your application chooses the `tracing` subscriber. The binary sets its subscriber in `src/main.rs` | None |
| Multi-tenancy | Several issuers in one process | No extension point yet. One `Provider` has exactly one issuer | None |

The contract test modules are `#[cfg(test)]`, and their macros are visible only inside the crate. So an implementation that should run the contract tests goes inside this crate. For example, create `src/sqlite_store.rs` and call the macro from its test module.

## What works today without the gcp feature

A binary built without the `gcp` feature is assembled like this (`src/main.rs`):

- Storage: `MemoryDocumentStore`, and a `MemoryStore` that reads it. CIBA uses `MemoryCibaStore`. All of them are lost when the process stops.
- Signing key: a new ES256 key on every start. There is no RS256 key.
- Mail: `LogMailer`. It sends nothing and writes the link to the log.
- Passkey sign-up and sign-in: they work, in memory.
- What does not work: the admin subcommands (they use Firestore), and CIBA push notifications (FCM).
- Listening: only on `127.0.0.1` and `[::1]`. To accept outside traffic, put a reverse proxy in front.
- If `K_SERVICE` is set (on Cloud Run), it refuses to start.

As a library, `Provider::new` alone has no `DocumentStore`. Then passkey sign-up and sign-in, PAR, dynamic client registration and the admin pages answer with 503 or a similar error. Calling `with_document_store` makes them work.

The in-memory setup is only for trying rust-idp out. A restart deletes the registered users and their passkeys.

## Example 1: Run on a VPS without a database server

Use one SQLite file as storage. Build without the `gcp` feature.

There is no SQLite implementation yet. Add the following.

1. **Write three or four storage implementations.**
    - `DocumentStore`: users, passkeys, sign-up tokens, PAR, DCR and more. Document contents arrive as JSON in the value format of the Firestore REST API. One table can hold them: collection name, id, JSON and version.
    - `Store`: sessions, authorization codes and tokens. Like `MemoryStore`, its `find_account` reads the user from the same `DocumentStore`.
    - `CibaStore`: CIBA requests.
    - `FidoStore`: storage for the FIDO2 conformance endpoints (`/fido/*`). They are mounted only when `FIDO_CONFORMANCE_ENABLED` is set. Production passkey sign-in uses `DocumentStore`. If you do not expose those endpoints, you do not need `FidoStore`.
2. **Call the contract tests.** Call one macro per implementation and make the tests pass.

    ```rust
    #[cfg(test)]
    mod tests {
        async fn store() -> super::SqliteDocumentStore {
            super::SqliteDocumentStore::open_in_memory().unwrap()
        }
        crate::document_store_contract::document_store_contract_tests!(store);
    }
    ```

    For `Store`, call `store_contract_tests!`. For `CibaStore`, call `ciba_store_contract_tests!`. For `FidoStore`, call `fido_store_contract_tests!`. `SqliteDocumentStore` is an example name for the implementation you will write.
3. **Read the keys from files.** `Es256Signer::from_scalar_b64` and `Rs256Signer::from_pkcs8_pem` exist. Read the file and plug the signer in with `with_signer` and `add_signer`. Both types already run `jws_signer_contract_tests!`. The code that reads the file does not exist yet.
4. **Send mail over SMTP.** Implement `Mailer` with SMTP and call `mailer_contract_tests!`. Pass it an `Outbox` that reads what arrived from the recipient's side. If delivery can fail, also pass an `Outbox` whose recipient refuses.
5. **Assemble the start-up.** Without `gcp`, the current `src/main.rs` always assembles the in-memory storage. You need an assembly that uses SQLite: add a feature, or write your own `main`.

Decide first:

- Most SQLite crates include the C SQLite library. rust-idp is written only in Rust, so choose the crate first.
- The record that lets each JAR, DPoP and `private_key_jwt` jti through only once (`NonceStore`) is not a trait. It is either in memory or in Firestore. On one machine, memory is enough. A restart clears it, though.

## Example 2: Run with PostgreSQL

Implement the same extension points as in Example 1 with PostgreSQL. The tests are the same too: call `document_store_contract_tests!`, `store_contract_tests!` and `ciba_store_contract_tests!` (and `fido_store_contract_tests!` if you expose `/fido/*`), and make them pass.

With PostgreSQL, check these points.

- Single-use operations (`take_doc`, `take_code`, `mark_refresh_used` and others) let only one caller through, even under concurrent calls. The contract tests include concurrent tests (`racing_*`). Use row locks, or a conditional `UPDATE ... RETURNING`.
- `*_if_unchanged` writes only when the version matches the one that was read. Keep a version column.
- With several processes, anything in memory is separate per process. This applies to the jti record (`NonceStore`) and to the rate limits. To keep the jti record in PostgreSQL, start by turning `NonceStore` into a trait.

## Example 3: Connect a site that has its own user DB and uses Basic auth

This example spans three axes. None of them has an extension point yet. For each one, this section gives a possible shape and examples of promises to decide first.

### Verify with existing passwords, then move users to passkeys (how users are verified)

A possible shape:

```rust
#[async_trait]
pub trait PasswordVerifier: Send + Sync {
    /// Returns the account_id on a match, None otherwise.
    async fn verify(&self, login: &str, password: &str) -> Result<Option<String>, String>;
}
```

Add a password field to the sign-in page. After a successful check, lead the user to register a passkey.

Examples of promises to decide first:

- Compare passwords in constant time (`subtle` is already a dependency).
- Limit the number of failures. Count per user and per source IP.
- Never write a password to the logs. Do not put it in error messages either.
- Return the same response for an unknown user and for a wrong password.
- Once a user has registered a passkey, stop accepting their password.

### Read the user list from the existing DB (where users come from)

A possible shape:

```rust
#[async_trait]
pub trait AccountDirectory: Send + Sync {
    async fn find(&self, account_id: &str) -> Result<Option<Account>, String>;
    async fn is_active(&self, account_id: &str) -> Result<bool, String>;
}
```

Today, sign-up, deactivation and token issuance read the `accounts` collection directly. Change those reads to go through the extension point.

Examples of promises to decide first:

- Do not issue new tokens to a user who is disabled in the existing DB.
- Keep the mapping from the existing DB's id to the id_token `sub` stable.
- If the existing DB does not answer, refuse and issue no token.

### Put the site behind rust-idp (what it connects to)

There are two shapes.

- **forward-auth**: on every request, the reverse proxy asks rust-idp whether the session in the cookie is valid. If it is, the proxy passes the user's id to the site in a header. The site stops using Basic auth and reads that header. On the rust-idp side, add a route that checks the session and returns the header.
- **OIDC RP**: add an OIDC RP library to the site and let rust-idp handle sign-in. rust-idp needs no change. The site needs larger changes.

Examples of promises to decide first for forward-auth:

- The proxy overwrites the user id header on every request. It drops any header with the same name that comes from outside.
- Only requests that went through the proxy reach the site.
- If the session check fails, the request does not go through.

## How to extend safely

This flow assumes an AI writes the implementation.

1. **Write the promise as a sentence.** A person decides it. Write it so that anyone can tell whether it was kept, for example "never write a password to the logs".
2. **Turn it into tests.** Write at least one test per promise. At this point the tests fail.
3. **Implement.** You are done when two things hold: the new tests pass, and every existing test still passes.
4. **Break the code on purpose and check that the tests fail.** Delete a line that keeps the promise, or invert a condition. If the tests still pass, they have a gap. Fix the tests and break the code again.
5. **For an extension point with contract tests, call the macro in one line.** The promises that the earlier implementations had to keep then apply to the new one in the same way.

## Related pages

- [Get started](get-started.md)
- [Verification](verification.md)
- [Design documents](design-docs.md)
