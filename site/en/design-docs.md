# Design documents

The detailed design documents live in the repository, in Japanese. They are the source for the claims on this site.

| Document | What it covers |
|---|---|
| [Verification map](https://github.com/son-risa/rust-idp/blob/main/docs/verification-map.md) | Which Tamarin models, conformance tests and premises apply to each client profile |
| [Security ladder](https://github.com/son-risa/rust-idp/blob/main/docs/security-ladder.md) | The threat model, step by step: which attacker each mechanism answers |
| [Zero Trust self-assessment](https://github.com/son-risa/rust-idp/blob/main/docs/zero-trust-assessment.md) | Self-assessment, and the ledger of premises the security depends on |
| [Crypto assumptions](https://github.com/son-risa/rust-idp/blob/main/docs/crypto-assumptions.md) | What is assumed about the cryptographic libraries |
| [Routes](https://github.com/son-risa/rust-idp/blob/main/docs/routes.md) | Every HTTP route, checked against the router by a test |
| [Formal verification](https://github.com/son-risa/rust-idp/blob/main/formal/README.md) | The Tamarin models and Kani harnesses, with results and limits |
| [Premise ledger](https://github.com/son-risa/rust-idp/blob/main/formal/premises.json) | Each premise with the code, test or reason that backs it |

The API reference will be on docs.rs once the crate is published.
