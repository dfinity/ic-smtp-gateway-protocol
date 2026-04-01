# Internet Computer SMTP Gateway Protocol (PoC)

> **Note:** This project is a proof of concept (PoC) and is under active development.

## Overview

This repository defines the **SMTP Gateway Protocol** for the [Internet Computer](https://internetcomputer.org/) (ICP). The SMTP Gateway is an off-chain service that receives emails via SMTP and forwards them to canisters by calling the conventional `smtp_request` Candid API. This is analogous to the existing [HTTP Gateway](https://github.com/dfinity/ic-http-gateway-protocol) that calls `http_request` upon receiving an HTTP request for a particular canister.

The goal is to establish email as a first-class, asynchronous communication channel between users and applications on the Internet Computer — enabling canisters to receive and process emails as part of on-chain logic.

## How It Works

```
┌──────┐    email     ┌──────────────┐  smtp_request  ┌─────────────────┐     ┌─────────────┐
│ User │ ──────────►  │ SMTP Gateway │ ─────────────► │  Boundary Node  │ ──► │ IC Canister │
└──────┘              └──────────────┘                └─────────────────┘     └─────────────┘
                        │                                                        │
                        ◄── bounce ───────────────────────────────────────────────┘
                            (on error)
```

1. A user sends an email to a canister address (e.g., `user@rdmx6-jaaaa-aaaaa-aaadq-cai.icp0.io` or `user@id.ai`).
2. The **SMTP Gateway** receives and validates the email.
3. The Gateway calls `smtp_request_validate` (query) to pre-validate the request.
4. If validation succeeds, the Gateway calls `smtp_request` (update) to deliver the message.
5. On error, the Gateway logs the failure and performs a best-effort bounce.

### Addressing

Canisters can be addressed in two ways:

- **Via canister ID**: `user@<canister-id>.icp0.io` (e.g., `user@rdmx6-jaaaa-aaaaa-aaadq-cai.icp0.io`)
- **Via custom domain**: `user@<custom-domain>` (e.g., `user@id.ai`)

## Repository Structure

```
├── candid/                     # Candid interface specification
│   └── smtp_gateway.did        # SMTP Gateway Protocol Candid API
├── examples/
│   └── mock-canister/          # Example Rust canister implementing the protocol
└── .github/workflows/          # CI configuration
```

## Candid API

The full Candid interface is defined in [`candid/smtp_gateway.did`](./candid/smtp_gateway.did). A canister must implement the following service to receive emails:

- `smtp_request_validate(SmtpRequest) -> (SmtpResponse) query` — Pre-validates an upcoming email delivery.
- `smtp_request(SmtpRequest) -> (SmtpResponse)` — Processes and delivers the email to the canister.

## Related Projects

- [IC HTTP Gateway Protocol](https://github.com/dfinity/ic-http-gateway-protocol) — The analogous protocol for HTTP requests.
- [Internet Identity](https://github.com/dfinity/internet-identity) — The first canister to support SMTP Gateway integration.

## Contributing

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (stable toolchain)

### Setup

```sh
git clone https://github.com/dfinity/ic-smtp-gateway-protocol.git
cd ic-smtp-gateway-protocol
cargo test
```

### Running checks

```sh
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```
