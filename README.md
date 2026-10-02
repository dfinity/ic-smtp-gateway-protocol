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
                        │                                                         │
                        ◄── bounce ───────────────────────────────────────────────┘
                            (on error)
```

1. A user sends an email to a canister address (e.g., `user@rdmx6-jaaaa-aaaaa-aaadq-cai.icp0.io` or `user@id.ai`).
2. The **SMTP Gateway** receives and validates the email.
3. The Gateway calls `smtp_request_validate` (query) to pre-validate the request.
4. If validation succeeds, the Gateway calls `smtp_request` (update) to deliver the message.
5. On error, the Gateway logs the failure and performs a best-effort bounce.

### Large messages

An ingress message to the Internet Computer is capped at roughly 2 MiB, so a message larger than that cannot be delivered with a single `smtp_request`. For those, the Gateway uses the **chunked upload** protocol: it asks the canister what it accepts (`smtp_capabilities`), uploads the body as a series of slices (`smtp_upload_chunk`), and finalizes with one `smtp_upload_commit` — the only call that delivers.

```
smtp_capabilities ──► advertises version + max size
smtp_upload_chunk ──► 0..n, submitted concurrently, order-independent
smtp_upload_commit ─► verifies the digest chain, then delivers
```

Implementing it is **optional**. A canister that does not is unaffected: it keeps receiving `smtp_request` as before, and oversize mail addressed to it is refused with a clear error so the sender gets a normal bounce. The obligations for a canister that does implement it — digest verification before storing, idempotent commit, resource bounds — are documented in [`candid/smtp_gateway.did`](./candid/smtp_gateway.did).

### Addressing

Canisters can be addressed in two ways:

- **Via canister ID**: `user@<canister-id>.icp0.io` (e.g., `user@rdmx6-jaaaa-aaaaa-aaadq-cai.icp0.io`)
- **Via custom domain**: `user@<custom-domain>` (e.g., `user@id.ai`)

## Repository Structure

```
├── candid/                     # Candid interface specification (normative)
│   └── smtp_gateway.did        # SMTP Gateway Protocol Candid API
├── crates/
│   └── protocol/               # ic-smtp-gateway-protocol: Rust definitions of the protocol
├── examples/
│   └── mock-canister/          # Example Rust canister implementing the protocol
└── .github/workflows/          # CI configuration
```

## Rust crate

[`ic-smtp-gateway-protocol`](./crates/protocol) provides the protocol's types as Candid-derived Rust structs, so the Gateway, receiving canisters and their tests all share one definition instead of re-declaring the wire format:

```toml
[dependencies]
ic-smtp-gateway-protocol = "0.1"
```

It depends only on `candid`, `serde` and `sha2`, so it builds for `wasm32-unknown-unknown` and can be used from a canister directly. It also exports `body_sha256()`, the commit digest construction — the one part of the protocol where sender and canister must produce byte-identical output from separate implementations.

The crate's test module doubles as an executable specification: it pins the Candid traps an implementer needs to know about (integer widths, case-sensitive variant labels, and which records are deliberately permissive versus strict).

## Candid API

The full Candid interface is defined in [`candid/smtp_gateway.did`](./candid/smtp_gateway.did). A canister must implement the following service to receive emails:

- `smtp_request_validate(SmtpRequest) -> (SmtpResponse) query` — Pre-validates an upcoming email delivery.
- `smtp_request(SmtpRequest) -> (SmtpResponse)` — Processes and delivers the email to the canister.

Optionally, to receive messages too large for a single ingress message:

- `smtp_capabilities() -> (SmtpCapabilities) query` — Advertises the supported upload version and maximum message size.
- `smtp_upload_chunk(SmtpUploadChunk) -> (SmtpUploadChunkResponse)` — Uploads one slice of the body.
- `smtp_upload_commit(SmtpUploadCommit) -> (SmtpResponse)` — Finalizes an upload and delivers the message.
- `smtp_upload_status(SmtpUploadId) -> (SmtpUploadStatusResponse) query` — Reports whether an upload was committed.
- `smtp_upload_abort(SmtpUploadId) -> (SmtpResponse)` — Releases an abandoned upload.

## Related Projects

- [IC HTTP Gateway Protocol](https://github.com/dfinity/ic-http-gateway-protocol) — The analogous protocol for HTTP requests.
- [Internet Identity](https://github.com/dfinity/internet-identity) — The first canister to support SMTP Gateway integration.

## Contributing

Contributions are welcome! Please read the [contribution guidelines](.github/CONTRIBUTING.md) and the [Code of Conduct](.github/CODE_OF_CONDUCT.md) before opening an issue or pull request.

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

# The example canister must also build for the IC's target
cargo build -p mock-canister --target wasm32-unknown-unknown --release
```

After an intentional change to the example canister's interface, regenerate its Candid with:

```sh
UPDATE_DID=1 cargo test -p mock-canister
```

## Security

If you believe you have found a security vulnerability, please report it as described in our [security policy](SECURITY.md) instead of opening a public issue.

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE).
