---
title: Use cases
description: What rust-idp is used for today, which specifications each use case relies on, and the AI-agent use cases it plans to support next.
---

# Use cases

This page has two parts. Part 1 lists what rust-idp does today. Part 2 lists use cases for AI agents that it does not support yet, and the specifications they would need.

When a specification is implemented, its row moves from Part 2 to Part 1. Pull requests that add a specification update this page.

## Part 1. Use cases today {#today}

| Use case | What happens | Specifications |
|---|---|---|
| Sign in to a business app with a passkey | A user signs in to a web app (in production: AMATE, a multi-tenant business app) without a password. | OpenID Connect authorization code flow, PKCE, WebAuthn (passkeys) |
| Join by invitation | An app the admin has allowed asks rust-idp for a sign-up link and sends it in its own email. The invitee registers a passkey from the link. | Confidential client authentication (`client_secret_basic` or `private_key_jwt`) |
| Approve a risky action on another device | The app asks the user to approve one specific action. The user approves on their own device with a passkey. The approval names exactly what was approved. | CIBA (poll mode), Rich Authorization Requests (RAR) |
| Protect a high-value API | A client must prove possession of its key when it signs in, starts a request and calls the API. A stolen token alone is not enough. This applies when the admin gives the client the FAPI 2.0 profile; no production client uses it yet. | `private_key_jwt`, Pushed Authorization Requests (PAR), PKCE, DPoP |
| Register clients under admin control | A client is registered through a protocol. The admin decides how strict it must be; the client cannot weaken that. | Dynamic Client Registration (RFC 7591) |

What is formally verified for each of these is on [Verification](verification.md). In short: the passkey sign-in with PKCE, DPoP, `private_key_jwt`, PAR, and CIBA with RAR are checked both by ordinary tests and by formal verification (Tamarin models). The PAR model covers the shape without DPoP (`private_key_jwt`, PKCE and PAR); there is no model of PAR combined with DPoP. Nothing here is certified.

## Part 2. Use cases for AI agents (planned) {#agents}

AI agents increasingly act for people and for organisations: they read, ask, order and pay. An identity provider then has to answer three questions that a password or a shared secret cannot answer well:

- **Which agent is this?** The software, and the running instance, not only "someone with the key".
- **On whose behalf is it acting?** The person or organisation responsible, recorded in the token.
- **What is it allowed to do, and for how long?** Narrow, short-lived permission, not a copy of the user's full access.

The use cases below are examples written to show what each specification is for. They are not descriptions of existing products.

### Organisation to organisation

| Use case | What happens | What must hold | Specifications |
|---|---|---|---|
| Request for quotation | A retailer's project invites the agents of two manufacturers. Each manufacturer's agent takes the request home, works on it with its own staff, and returns a quote before the deadline. | The retailer does not register the manufacturers' agents as its own users. It trusts the manufacturers' identity providers instead, and gives each agent a token limited to this project. | Identity Chaining, Token Exchange (`act`), RAR, DPoP |
| Automatic restocking | A shop's agent checks a wholesaler's stock and orders automatically up to an agreed amount. | Orders above the limit need a person's approval. | RAR, CIBA |
| Handing over audit documents | An accounting firm's agent collects year-end documents from a client's accounting system. | Only the listed documents, only during the audit, and the record shows which firm and which person the agent acted for. | Resource Indicators, RAR, Token Exchange (`act`) |
| Shared research data | Agents at a university and a company fetch experiment data from each other. | Neither side adds the other's people to its own directory. | Identity Chaining |
| Incident notice | A cloud provider's agent tells a customer's operations agent about an outage and reads the customer's status to narrow down the cause. | It runs unattended at night, so the instance must be identified and a stolen token must be useless. | WIMSE workload identity, DPoP |

### Person to organisation

| Use case | What happens | What must hold | Specifications |
|---|---|---|---|
| Travel booking | A person's agent visits airline and hotel sites, checks availability and books. | Browsing needs no sign-in; booking and payment do, and payment needs the person's approval. | Poppy (Personal Agent Protocol), CIMD, CIBA |
| Administrative procedures | A person's agent files a change of address and the related utility changes. | The office can see that the agent acts for that person. | Token Exchange (`act`), `private_key_jwt` |
| Customer support | A person's agent talks to a telecom company's support agent, checks the bill and changes the plan. | The person never gives their password to the agent. | CIMD, Token Exchange |
| Medical appointments | A person's agent books a clinic and passes earlier test results to the new clinic. | The results are visible only to that clinic, only for that visit. | RAR, Resource Indicators |
| An employee's own agent at work | An employee's assistant agent uses the company's attendance and expense systems. | The company's identity provider issues a token for the employee's agent, not the employee's own session. | ID-JAG, Token Exchange |

### Person to person

| Use case | What happens | What must hold | Specifications |
|---|---|---|---|
| Scheduling | Two people's agents compare free time and fix a meeting. | Only free/busy is shared, not the content of the calendar. | RAR |
| Splitting a bill | The organiser's agent asks the others' agents to settle up. | Nothing above the agreed amount is sent without the payer's approval. | RAR, CIBA |
| Second-hand sale | A buyer's agent negotiates with a seller's agent. | The buyer can check that the agent really belongs to that seller. | CIMD, Token Exchange (`act`) |
| Family check-in | A parent's agent receives a child's location and arrival notices. | The child decides what is shared and for how long. | RAR, CIBA |

### Specifications and their status in rust-idp {#specs}

Status: **Available** is implemented today. **Planned** is intended next. **Considering** depends on how the use cases above develop. **Watching** is not planned.

Maturity: **Standard** is an RFC or an OpenID Final specification. **WG draft** is adopted by an IETF working group and may still change. **Individual draft** is a proposal by its authors. **Industry** is published outside a standards body.

| Area | Specification | What it does | Maturity | rust-idp |
|---|---|---|---|---|
| Agent identity | `private_key_jwt` (RFC 7523) | A client signs in with its own key | Standard | Available |
| Agent identity | Dynamic Client Registration (RFC 7591) | Registers a client through a protocol | Standard | Available |
| Agent identity | Client ID Metadata Document (CIMD) | The client ID is a URL; the server fetches the client's metadata from it | WG draft | Planned |
| Agent identity | OAuth Client Attestation | Proves that the client is a genuine instance of the software | WG draft | Considering |
| Delegation | CIBA | Asks a person for approval on another device | Standard | Available |
| Delegation | Rich Authorization Requests (RFC 9396) | Puts detailed conditions (amount, period, items) into the authorization | Standard | Available |
| Delegation | DPoP (RFC 9449) | Binds a token to a key, so a stolen token alone is useless | Standard | Available |
| Delegation | Token Exchange (RFC 8693) | Exchanges a token for a narrower one; `act` records who acts for whom | Standard | Planned |
| Delegation | Identity Chaining | Carries identity and authorization across trust domains | WG draft | Considering |
| Delegation | Identity Assertion JWT Authorization Grant (ID-JAG) | An organisation's identity provider vouches for a user so another app can issue a token | WG draft | Considering |
| Delegation | Transaction Tokens | Carries the caller's context between internal services | WG draft | Watching |
| Audience and discovery | Resource Indicators (RFC 8707) | Limits a token to one service | Standard | Partly available; review planned |
| Audience and discovery | Authorization Server Metadata (RFC 8414) | Publishes the server's endpoints for OAuth clients | Standard | Planned (OpenID Connect discovery is available) |
| Audience and discovery | Protected Resource Metadata (RFC 9728) | A resource server tells clients which authorization server to use | Standard | Not applicable (resource-server side) |
| Policy | AuthZEN Authorization API 1.0 | Asks an external policy engine for a decision | Standard | Watching |
| Profiles | WIMSE AI agent identity (AIMS) | How to combine workload identity and OAuth for agents | WG draft | Watching |
| Profiles | PACT (draft-valverde-oauth-pact) | Agent delegation with CIBA, Token Exchange and client attestation | Individual draft | Watching |
| Profiles | Poppy (Personal Agent Protocol) | A front door for personal agents: guest access first, sign-in and narrow scopes when needed | Industry | Watching (`private_key_jwt` and DPoP are available; CIMD is planned) |

Draft specifications may change before they are published. Where rust-idp implements one, this page will name the draft version.
