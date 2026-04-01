use candid::{CandidType, Deserialize};

#[derive(CandidType, Deserialize, Clone, Debug)]
struct Header {
    name: String,
    value: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct Message {
    headers: Vec<Header>,
    body: Vec<u8>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct Address {
    user: String,
    domain: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct Envelope {
    from: Address,
    to: Address,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct SmtpRequest {
    message: Option<Message>,
    envelope: Option<Envelope>,
    gateway_flags: Option<Vec<String>>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
struct SmtpRequestError {
    code: u64,
    message: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
enum SmtpResponse {
    Ok {},
    Err(SmtpRequestError),
}

#[ic_cdk::query]
fn smtp_request_validate(request: SmtpRequest) -> SmtpResponse {
    // Mock validation: check that an envelope is present.
    match &request.envelope {
        Some(envelope) if envelope.to.user.is_empty() => SmtpResponse::Err(SmtpRequestError {
            code: 551,
            message: "User doesn't exist".to_string(),
        }),
        _ => SmtpResponse::Ok {},
    }
}

#[ic_cdk::update]
fn smtp_request(request: SmtpRequest) -> SmtpResponse {
    // Mock processing: perform the same validation, then accept.
    match &request.envelope {
        Some(envelope) if envelope.to.user.is_empty() => SmtpResponse::Err(SmtpRequestError {
            code: 551,
            message: "User doesn't exist".to_string(),
        }),
        _ => SmtpResponse::Ok {},
    }
}

// Export the Candid interface.
candid::export_service!();

#[test]
fn generate_candid() {
    let actual = __export_service();
    let expected = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("mock_canister.did"),
    )
    .expect("Could not read mock_canister.did");
    assert_eq!(
        actual.trim(),
        expected.trim(),
        "Generated Candid does not match mock_canister.did. \
         Run `cargo test` and update the .did file if needed.\n\
         Generated:\n{actual}"
    );
}
