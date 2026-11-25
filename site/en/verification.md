# Verification

rust-idp states each security claim as "promise Z holds against attacker X under premises Y", and checks it at the layer that can check it. This page says what each layer covers and, just as important, what it does not.

## Layers

| Method | Covers | Does not cover |
|---|---|---|
| Tamarin | 13 protocol models. 19 variants, each with one defence removed, must be falsified | Whether the code matches the models |
| Kani | 9 functions in the code | The rest of the code |
| Tests | Externally visible behaviour, and every premise that can be tested | Premises that cannot be tested |
| Conformance tools | FIDO Alliance server tests on the `/fido` surface; OpenID Foundation FAPI 2.0 tests on the FAPI 2.0 client shape | Other client shapes. Production sign-in is a separate code path from `/fido` |

The Tamarin results are compared with an expected table on every pull request that touches the code or the models; any difference fails the check. The Kani harnesses are compared with a list in the same way. Both checks are required for merging to `main`.

## Premises

The premise ledger has 44 entries. 25 name the test that guards them. 19 cannot be tested and say why, for example "TLS to the token endpoint authenticates the server".

## By client profile

What a verification result means depends on the client's profile. The full table, with lemma names and premise IDs, is the [verification map](https://github.com/son-risa/rust-idp/blob/main/docs/verification-map.md).

| Client profile | Auth / PAR / token | Tamarin models | Conformance-tested | In production |
|---|---|---|---|---|
| `Public` | none / no / DPoP | code + PKCE, DPoP, ID token, composition #8 | No | Test RPs only |
| `ConfidentialSecret` | client_secret_basic / no / Bearer | composition #11, including what cannot hold (a stolen Bearer token is usable) | No | Main RP |
| `ConfidentialKey` (FAPI 2.0 shape) | private_key_jwt / yes / DPoP | #1, #2, #5, composition #6. PAR is in no model | FAPI 2.0 test plan; records not yet published | None |
| CIBA | client_secret_basic / — / Bearer | #3 (binding, single use) | No | One RP |

## Not certified

rust-idp has no certification from the OpenID Foundation or the FIDO Alliance. The conformance tools are used as development checks. The evidence (test plan ID, date, suite version, commit) is being prepared and will be published in the repository.

## Sources

- [formal/expected.tsv](https://github.com/son-risa/rust-idp/blob/main/formal/expected.tsv): the expected result for every model and lemma
- [formal/kani-harnesses.txt](https://github.com/son-risa/rust-idp/blob/main/formal/kani-harnesses.txt): the 9 Kani harnesses
- [formal/premises.json](https://github.com/son-risa/rust-idp/blob/main/formal/premises.json): the premise ledger
- [.github/workflows/formal.yml](https://github.com/son-risa/rust-idp/blob/main/.github/workflows/formal.yml): the CI job
