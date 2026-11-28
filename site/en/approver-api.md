---
title: Approver API
description: How an app on the user's own device lists, approves and rejects CIBA requests on rust-idp.
---

# Approver API

This page is for developers who build an app that approves CIBA requests on the user's own device. It describes the endpoints such an app calls, and what each one requires.

CIBA Core defines how a client starts a request and polls for the result. It does not define how the user's device learns about the request or sends the approval back to the OP. The endpoints on this page fill that gap. They are specific to rust-idp, not part of any standard, and no general-purpose SDK speaks them.

Users can also approve without an app. The browser page `/ciba` lists the signed-in user's pending requests and approves them with a passkey. It uses the sign-in cookie, not an access token.

## Terms

- **Approver app**: the app on the user's device that shows pending requests and approves or rejects them.
- **`ciba:approve`**: the scope an access token must carry to call the approver endpoints.
- **`{i}`**: the issuer, for example `https://idp.example/oidc`. Every path below is relative to it.

## Before you start

### Register the app and allow the scope

1. Register the app as a client that uses the authorization code grant with PKCE.
2. Ask the operator to allow `ciba:approve` for the client. A client may request this scope only when its registration lists it in `scope` (the RFC 7591 field).
    - Dynamic Client Registration never adds this scope. Whatever the request says, the new registration has no `scope`.
    - On a Firestore deployment, the operator sets it with the admin subcommand:

    ```sh
    rust-idp set-client-scope --client <client_id> --scope ciba:approve
    ```

    `--scope ""` removes it again. The subcommand changes only `scope` and leaves the rest of the registration as it is.

A client without the scope that asks for `ciba:approve` gets `invalid_scope` ("ciba:approve is not allowed for this client"). This applies to `/authorize` and `/backchannel-authentication`. With PAR, `POST /par` accepts the request; the error comes when `/authorize` uses the `request_uri`.

### Sign the user in

Sign the user in with the authorization code flow and PKCE, and include `ciba:approve` in `scope`, for example `openid offline_access ciba:approve`.

- A refresh cannot add the scope later. A user who signed in without it must sign in again.
- The approver endpoints check the client's registration on every call. If the operator removes the scope, tokens already issued to that client stop working there (403).

### DPoP

If the access token is bound to a DPoP key, every call with it must use the `DPoP` scheme (`Authorization: DPoP <token>`) and carry a fresh `DPoP` proof with:

- `htm`: the method of the call
- `htu`: the issuer plus the path, for example `https://idp.example/oidc/ciba/pending`
- `ath`: the hash of the access token

A token that is not bound may use `Authorization: Bearer <token>`.

### Find the endpoint URLs

The discovery document (`{i}/.well-known/openid-configuration`) lists three of these endpoints under `custom_endpoints`, so an app does not have to hard-code their paths:

| Key | URL |
|---|---|
| `ciba_pending` | `{i}/ciba/pending` |
| `ciba_history` | `{i}/ciba/history` |
| `fcm_token` | `{i}/ciba/fcm-tokens` |

The per-request endpoints are built from the `auth_req_id`: `{i}/ciba/{auth_req_id}/passkey-options`, `/approve` and `/reject`.

## Endpoints

| Method | Path | Authorization |
|---|---|---|
| GET | `/ciba/pending` | Access token with `ciba:approve` |
| GET | `/ciba/history` | Access token with `ciba:approve` |
| POST | `/ciba/fcm-tokens` | Access token with `ciba:approve` |
| POST | `/ciba/{auth_req_id}/passkey-options` | Access token with `ciba:approve`, or the browser sign-in cookie. Only the user the request is addressed to |
| POST | `/ciba/{auth_req_id}/approve` | A passkey assertion. No access token |
| POST | `/ciba/{auth_req_id}/reject` | Access token with `ciba:approve`, or the browser sign-in cookie. Only the user the request is addressed to |

Errors common to the endpoints that take an access token:

| Status | Body | Meaning |
|---|---|---|
| 401 | `access token required` | No `Authorization` header, or it is not in the `Bearer <token>` or `DPoP <token>` form |
| 401 | `invalid token` | The token is unknown or expired |
| 401 | `DPoP scheme required`, `DPoP proof required`, `DPoP jkt mismatch`, `DPoP: …` | The token is DPoP-bound and the call did not prove the key |
| 403 | `forbidden` | The token lacks `ciba:approve`, or the client's registration no longer allows it |
| 503 | `temporarily unavailable` | The token store could not be read. Keep the token and retry |

A deployment without the document store (Firestore) returns 503 `no firestore` from `fcm-tokens`, `passkey-options` and `approve`.

### GET /ciba/pending

Returns the pending requests addressed to the token's user, as a JSON array. Expired requests are moved to the history first.

```json
[
  {
    "auth_req_id": "4f1c…",
    "client_id": "example-rp",
    "scope": "openid",
    "binding_message": "Pay 100",
    "authorization_details": [{ "type": "payment_initiation", "…": "…" }]
  }
]
```

`authorization_details` is the RAR content of the request as JSON, or `null`. Show it, or `binding_message` when it is `null`, so the user sees exactly what they approve.

### GET /ciba/history

Returns up to 50 resolved requests of the token's user, newest first. Each entry has the fields above plus `outcome` (`approved`, `denied` or `expired`) and `resolved_at` (seconds since the epoch).

### POST /ciba/fcm-tokens

Registers the device's Firebase Cloud Messaging token, so rust-idp can notify the device of new requests.

```json
{ "token": "<FCM registration token>", "platform": "ios" }
```

`platform` is optional and defaults to `ios`. Returns 204. Push notifications need the Firestore deployment.

### POST /ciba/{auth_req_id}/passkey-options

Starts an approval. Returns the options for a WebAuthn assertion:

```json
{
  "challenge": "…",
  "rpId": "idp.example",
  "timeout": 60000,
  "userVerification": "required",
  "allowCredentials": [{ "type": "public-key", "id": "…", "transports": ["internal", "hybrid"] }]
}
```

The challenge is tied to this request and to the user.

| Status | Meaning |
|---|---|
| 401 `sign-in required` | Neither an access token nor a sign-in cookie was sent |
| 403 `forbidden` | Signed in with the cookie, but the `Origin` (or `Referer`) is not the OP's own origin |
| 404 | No such request, it has expired, or it is addressed to another user |
| 400 `no passkey` | The user has no passkey |

### POST /ciba/{auth_req_id}/approve

Sends the passkey assertion made with the options above. Send it without an access token; the assertion is what proves the user.

```json
{
  "id": "<credential id>",
  "response": {
    "clientDataJSON": "…",
    "authenticatorData": "…",
    "signature": "…",
    "userHandle": "…"
  }
}
```

rust-idp checks that the challenge was issued for this request, that the request belongs to the same user, and that the assertion is valid with user verification. The `origin` in `clientDataJSON` must equal the OP's origin exactly, and the RP ID is the issuer's host. For an iOS app, the OP serves `https://<host>/.well-known/apple-app-site-association` at the origin's root, not under `{i}`. It lists the configured app (`APPLE_APP_ID`) under `webcredentials`, and it is served only when `APP_NAME`, `APP_SCHEME`, `APP_ANDROID_PACKAGE` and `APPLE_APP_ID` are all set (404 otherwise). The OP does not serve `assetlinks.json` and does not accept `android:apk-key-hash:` origins today.

| Status | Meaning |
|---|---|
| 200 `{"ok": true}` | Approved. The client's next poll receives the tokens |
| 400 | The challenge is missing, unknown, expired or for another request, or the credential does not belong to the user |
| 401 | The assertion did not verify |
| 403 `account disabled` | The account is disabled |
| 404 | No such request, it has expired, or it is addressed to another user |
| 409 `already handled` | The request was already approved or rejected |

### POST /ciba/{auth_req_id}/reject

Rejects the request. No body and no passkey are needed: rejecting fails safe. The client's next poll receives `access_denied`.

| Status | Meaning |
|---|---|
| 204 | Rejected |
| 401 `sign-in required` | Neither an access token nor a sign-in cookie was sent |
| 403 `forbidden` | Signed in with the cookie, but the `Origin` (or `Referer`) is not the OP's own origin |
| 404 | No such request, or it is addressed to another user |
| 409 `expired` | The request has expired. It is recorded as expired, not as rejected |
| 409 `already handled` | The request was already approved or rejected |

## Sources

- Endpoints: [src/web/ciba.rs](https://github.com/son-risa/rust-idp/blob/main/src/web/ciba.rs)
- Token check and DPoP: `authenticate_token` in [src/web/mod.rs](https://github.com/son-risa/rust-idp/blob/main/src/web/mod.rs)
- Discovery: `custom_endpoints` in [src/web/oidc.rs](https://github.com/son-risa/rust-idp/blob/main/src/web/oidc.rs)
- Route table: [docs/routes.md](https://github.com/son-risa/rust-idp/blob/main/docs/routes.md) (Japanese)
