use std::{ffi::OsStr, fmt};

#[cfg(feature = "production-prover")]
use agenc_zkvm_guest::{serialize_journal, JOURNAL_TOTAL_LEN};
use agenc_zkvm_guest::{JournalField, JournalFields, PrivateWitness};

pub const IMAGE_ID_LEN: usize = 32;
#[cfg_attr(not(any(test, feature = "production-prover")), allow(dead_code))]
pub const SEAL_SELECTOR_LEN: usize = 4;
#[cfg_attr(not(any(test, feature = "production-prover")), allow(dead_code))]
pub const SEAL_PROOF_LEN: usize = 256;
#[cfg_attr(not(any(test, feature = "production-prover")), allow(dead_code))]
pub const SEAL_BYTES_LEN: usize = 260;
#[cfg_attr(not(any(test, feature = "production-prover")), allow(dead_code))]
pub const TRUSTED_SEAL_SELECTOR: [u8; SEAL_SELECTOR_LEN] = [0x52, 0x5a, 0x56, 0x4d];
#[cfg_attr(not(any(test, feature = "production-prover")), allow(dead_code))]
const GROTH16_PI_A_LEN: usize = 64;
#[cfg_attr(not(any(test, feature = "production-prover")), allow(dead_code))]
const BN254_FIELD_MODULUS_Q: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
    0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
    0xfd, 0x47,
];
pub const DEV_MODE_ENV_VAR: &str = "RISC0_DEV_MODE";
pub const TRUSTED_RISC0_IMAGE_ID: [u8; IMAGE_ID_LEN] = [
    163, 162, 235, 60, 222, 160, 40, 184, 182, 95, 135, 53, 39, 239, 42, 88, 52, 171, 21, 130, 15,
    219, 143, 17, 216, 26, 185, 77, 94, 34, 68, 20,
];

pub type ImageId = [u8; IMAGE_ID_LEN];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProveRequest {
    pub task_pda: JournalField,
    pub agent_authority: JournalField,
    pub constraint_hash: JournalField,
    pub output_commitment: JournalField,
    pub binding: JournalField,
    pub nullifier: JournalField,
    pub output: [JournalField; 4],
    pub salt: JournalField,
    pub agent_secret: JournalField,
}

impl ProveRequest {
    pub fn journal_fields(&self) -> JournalFields {
        JournalFields {
            task_pda: self.task_pda,
            agent_authority: self.agent_authority,
            constraint_hash: self.constraint_hash,
            output_commitment: self.output_commitment,
            binding: self.binding,
            nullifier: self.nullifier,
        }
    }

    pub fn private_witness(&self) -> PrivateWitness {
        PrivateWitness {
            output: self.output,
            salt: self.salt,
            agent_secret: self.agent_secret,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProveResponse {
    pub seal_bytes: Vec<u8>,
    pub journal: Vec<u8>,
    pub image_id: ImageId,
}

#[cfg_attr(not(feature = "production-prover"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProveError {
    UnexpectedJournalLength { expected: usize, actual: usize },
    UntrustedImageId { expected: ImageId, actual: ImageId },
    DevModeEnabled { variable: &'static str },
    InvalidRequest(String),
    ProverFailed(String),
    ReceiptTypeMismatch(String),
}

impl fmt::Display for ProveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedJournalLength { expected, actual } => {
                write!(
                    f,
                    "unexpected journal length: expected {expected}, got {actual}"
                )
            }
            Self::UntrustedImageId { expected, actual } => {
                write!(
                    f,
                    "compiled guest image_id does not match trusted pinned image_id: expected {:?}, got {:?}",
                    expected, actual
                )
            }
            Self::DevModeEnabled { variable } => {
                write!(f, "{variable} is set; refusing to generate proof output")
            }
            Self::InvalidRequest(message) => write!(f, "invalid prove request: {message}"),
            Self::ProverFailed(message) => write!(f, "prover failed: {message}"),
            Self::ReceiptTypeMismatch(message) => {
                write!(f, "receipt type mismatch: {message}")
            }
        }
    }
}

impl std::error::Error for ProveError {}

pub fn generate_proof(request: &ProveRequest) -> Result<ProveResponse, ProveError> {
    let dev_mode_value = std::env::var_os(DEV_MODE_ENV_VAR);
    generate_proof_with_dev_mode(request, dev_mode_value.as_deref())
}

#[cfg(feature = "production-prover")]
pub fn image_id() -> ImageId {
    guest_id_to_image_id(&agenc_zkvm_methods::AGENC_GUEST_ID)
}

#[cfg(not(feature = "production-prover"))]
pub fn image_id() -> ImageId {
    TRUSTED_RISC0_IMAGE_ID
}

pub fn render_image_id(image_id: ImageId) -> String {
    image_id
        .iter()
        .map(|byte| byte.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn generate_proof_with_dev_mode(
    request: &ProveRequest,
    dev_mode_value: Option<&OsStr>,
) -> Result<ProveResponse, ProveError> {
    validate_request_semantics(request)?;
    ensure_dev_mode_disabled(dev_mode_value)?;

    #[cfg(feature = "production-prover")]
    {
        generate_proof_real(request)
    }

    #[cfg(not(feature = "production-prover"))]
    {
        let _ = request;
        Err(ProveError::ProverFailed(
            "proof generation requires building with --features production-prover".into(),
        ))
    }
}

#[cfg(feature = "production-prover")]
fn generate_proof_real(request: &ProveRequest) -> Result<ProveResponse, ProveError> {
    use agenc_zkvm_guest::JOURNAL_FIELD_LEN;
    use agenc_zkvm_methods::AGENC_GUEST_ELF;
    use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

    let current_image_id = image_id();
    if current_image_id != TRUSTED_RISC0_IMAGE_ID {
        return Err(ProveError::UntrustedImageId {
            expected: TRUSTED_RISC0_IMAGE_ID,
            actual: current_image_id,
        });
    }

    let mut builder = ExecutorEnv::builder();
    let public_fields: &[(&str, &[u8; JOURNAL_FIELD_LEN])] = &[
        ("task_pda", &request.task_pda),
        ("agent_authority", &request.agent_authority),
        ("constraint_hash", &request.constraint_hash),
        ("output_commitment", &request.output_commitment),
        ("binding", &request.binding),
        ("nullifier", &request.nullifier),
    ];
    for (name, field) in public_fields {
        builder
            .write(*field)
            .map_err(|err| ProveError::ProverFailed(format!("failed to write {name}: {err}")))?;
    }

    let witness_fields: &[(&str, &[u8; JOURNAL_FIELD_LEN])] = &[
        ("output[0]", &request.output[0]),
        ("output[1]", &request.output[1]),
        ("output[2]", &request.output[2]),
        ("output[3]", &request.output[3]),
        ("salt", &request.salt),
        ("agent_secret", &request.agent_secret),
    ];
    for (name, field) in witness_fields {
        builder
            .write(*field)
            .map_err(|err| ProveError::ProverFailed(format!("failed to write {name}: {err}")))?;
    }

    let env = builder
        .build()
        .map_err(|err| ProveError::ProverFailed(format!("failed to build executor env: {err}")))?;

    let receipt = default_prover()
        .prove_with_opts(env, AGENC_GUEST_ELF, &ProverOpts::groth16())
        .map_err(|err| ProveError::ProverFailed(format!("Groth16 proving failed: {err}")))?
        .receipt;

    let groth16 = receipt.inner.groth16().map_err(|err| {
        ProveError::ReceiptTypeMismatch(format!("expected Groth16 receipt: {err}"))
    })?;

    let raw_seal: [u8; SEAL_PROOF_LEN] =
        groth16.seal.clone().try_into().map_err(|seal: Vec<u8>| {
            ProveError::ProverFailed(format!(
                "Groth16 seal is {} bytes, expected {}",
                seal.len(),
                SEAL_PROOF_LEN
            ))
        })?;

    let seal_bytes = encode_seal(&raw_seal);
    let journal = receipt.journal.bytes.clone();
    if journal.len() != JOURNAL_TOTAL_LEN {
        return Err(ProveError::UnexpectedJournalLength {
            expected: JOURNAL_TOTAL_LEN,
            actual: journal.len(),
        });
    }

    let expected_journal = serialize_journal(&request.journal_fields());
    if journal.as_slice() != expected_journal {
        return Err(ProveError::ProverFailed(
            "prover returned journal that does not match expected fields".into(),
        ));
    }

    Ok(ProveResponse {
        seal_bytes,
        journal,
        image_id: current_image_id,
    })
}

fn ensure_dev_mode_disabled(dev_mode_value: Option<&OsStr>) -> Result<(), ProveError> {
    if dev_mode_value.is_some() {
        return Err(ProveError::DevModeEnabled {
            variable: DEV_MODE_ENV_VAR,
        });
    }
    Ok(())
}

#[cfg_attr(not(any(test, feature = "production-prover")), allow(dead_code))]
pub fn guest_id_to_image_id(guest_id: &[u32; 8]) -> ImageId {
    let mut out = [0u8; IMAGE_ID_LEN];
    for (chunk, word) in out.chunks_exact_mut(SEAL_SELECTOR_LEN).zip(guest_id.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[cfg_attr(not(any(test, feature = "production-prover")), allow(dead_code))]
fn encode_seal(proof_bytes: &[u8; SEAL_PROOF_LEN]) -> Vec<u8> {
    let mut seal_bytes = Vec::with_capacity(SEAL_BYTES_LEN);
    seal_bytes.extend_from_slice(&TRUSTED_SEAL_SELECTOR);
    seal_bytes.extend_from_slice(&negate_pi_a(proof_bytes));
    seal_bytes
}

#[cfg_attr(not(any(test, feature = "production-prover")), allow(dead_code))]
fn negate_pi_a(proof_bytes: &[u8; SEAL_PROOF_LEN]) -> [u8; SEAL_PROOF_LEN] {
    let mut encoded = *proof_bytes;
    let pi_a: [u8; GROTH16_PI_A_LEN] = encoded[..GROTH16_PI_A_LEN]
        .try_into()
        .expect("pi_a length is fixed");
    encoded[..GROTH16_PI_A_LEN].copy_from_slice(&negate_g1(&pi_a));
    encoded
}

#[cfg_attr(not(any(test, feature = "production-prover")), allow(dead_code))]
fn negate_g1(point: &[u8; GROTH16_PI_A_LEN]) -> [u8; GROTH16_PI_A_LEN] {
    let mut negated = [0u8; GROTH16_PI_A_LEN];
    negated[..32].copy_from_slice(&point[..32]);

    let mut y = [0u8; 32];
    y.copy_from_slice(&point[32..]);

    let negated_y = if y.iter().all(|byte| *byte == 0) {
        [0u8; 32]
    } else {
        let mut value = BN254_FIELD_MODULUS_Q;
        subtract_be_bytes(&mut value, &y);
        value
    };
    negated[32..].copy_from_slice(&negated_y);

    negated
}

#[cfg_attr(not(any(test, feature = "production-prover")), allow(dead_code))]
fn subtract_be_bytes(a: &mut [u8; 32], b: &[u8; 32]) {
    let mut borrow: u32 = 0;
    for (ai, bi) in a.iter_mut().zip(b.iter()).rev() {
        let result = (*ai as u32).wrapping_sub(*bi as u32).wrapping_sub(borrow);
        *ai = result as u8;
        borrow = (result >> 31) & 1;
    }
}

fn validate_request_semantics(request: &ProveRequest) -> Result<(), ProveError> {
    request
        .journal_fields()
        .validate_against_witness(&request.private_witness())
        .map_err(|err| ProveError::InvalidRequest(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_zkvm_guest::{
        compute_binding, compute_constraint_hash, compute_nullifier_from_agent_secret,
        compute_output_commitment,
    };

    fn field_from_u32(value: u32) -> JournalField {
        let mut out = [0_u8; 32];
        out[28..].copy_from_slice(&value.to_be_bytes());
        out
    }

    fn default_prove_request() -> ProveRequest {
        let mut task_pda = [0_u8; 32];
        task_pda[31] = 0x2a;
        let agent_authority = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let output = [
            field_from_u32(1),
            field_from_u32(2),
            field_from_u32(3),
            field_from_u32(4),
        ];
        let salt = field_from_u32(12345);
        let agent_secret = field_from_u32(67890);
        let constraint_hash = compute_constraint_hash(&output);
        let output_commitment = compute_output_commitment(&output, &salt);
        let binding = compute_binding(&task_pda, &agent_authority, &output_commitment);
        let nullifier =
            compute_nullifier_from_agent_secret(&constraint_hash, &output_commitment, &agent_secret);

        ProveRequest {
            task_pda,
            agent_authority,
            constraint_hash,
            output_commitment,
            binding,
            nullifier,
            output,
            salt,
            agent_secret,
        }
    }

    #[test]
    fn dev_mode_guard_is_fail_closed() {
        let request = default_prove_request();
        let err = generate_proof_with_dev_mode(&request, Some(OsStr::new("1")))
            .expect_err("dev mode must be rejected");

        assert_eq!(
            err,
            ProveError::DevModeEnabled {
                variable: DEV_MODE_ENV_VAR,
            }
        );
    }

    #[test]
    fn encode_seal_prefixes_trusted_selector() {
        let mut raw = [9u8; SEAL_PROOF_LEN];
        raw[32..64].fill(1);
        let encoded = encode_seal(&raw);
        assert_eq!(encoded.len(), SEAL_BYTES_LEN);
        assert_eq!(&encoded[..SEAL_SELECTOR_LEN], &TRUSTED_SEAL_SELECTOR);
        assert_eq!(&encoded[SEAL_SELECTOR_LEN..32 + SEAL_SELECTOR_LEN], &raw[..32]);

        let mut expected_y = BN254_FIELD_MODULUS_Q;
        let y = [1u8; 32];
        subtract_be_bytes(&mut expected_y, &y);
        assert_eq!(
            &encoded[SEAL_SELECTOR_LEN + 32..SEAL_SELECTOR_LEN + 64],
            &expected_y
        );
        assert_eq!(&encoded[SEAL_SELECTOR_LEN + 64..], &raw[64..]);
    }

    #[test]
    fn encode_seal_preserves_zero_pi_a_y_coordinate() {
        let raw = [0u8; SEAL_PROOF_LEN];
        let encoded = encode_seal(&raw);

        assert_eq!(
            &encoded[SEAL_SELECTOR_LEN + 32..SEAL_SELECTOR_LEN + 64],
            &[0u8; 32]
        );
    }

    #[test]
    fn guest_id_to_image_id_converts_little_endian_words() {
        let guest_id: [u32; 8] = [
            0x04030201, 0x08070605, 0x0c0b0a09, 0x100f0e0d, 0x14131211, 0x18171615, 0x1c1b1a19,
            0x201f1e1d,
        ];
        let image_id = guest_id_to_image_id(&guest_id);
        assert_eq!(image_id[0], 0x01);
        assert_eq!(image_id[1], 0x02);
        assert_eq!(image_id[2], 0x03);
        assert_eq!(image_id[3], 0x04);
        assert_eq!(image_id[31], 0x20);
    }

    #[test]
    fn without_production_feature_returns_guidance_error() {
        #[cfg(not(feature = "production-prover"))]
        {
            let request = default_prove_request();
            let err = generate_proof_with_dev_mode(&request, None)
                .expect_err("must fail without feature");
            match err {
                ProveError::ProverFailed(message) => {
                    assert!(message.contains("--features production-prover"));
                }
                other => panic!("unexpected error: {other}"),
            }
        }
    }

    #[test]
    fn zero_salt_is_rejected_before_proving() {
        let mut request = default_prove_request();
        request.salt = [0_u8; 32];

        let err = generate_proof_with_dev_mode(&request, None)
            .expect_err("zero salt must be rejected");

        assert_eq!(
            err,
            ProveError::InvalidRequest("salt must be non-zero".into())
        );
    }

    #[test]
    fn invalid_constraint_hash_is_rejected_before_proving() {
        let mut request = default_prove_request();
        request.constraint_hash[0] ^= 0xff;

        let err = generate_proof_with_dev_mode(&request, None)
            .expect_err("invalid constraint hash must be rejected");

        assert_eq!(
            err,
            ProveError::InvalidRequest("constraint_hash does not match derived value".into())
        );
    }

    #[test]
    fn invalid_output_commitment_is_rejected_before_proving() {
        let mut request = default_prove_request();
        request.output_commitment[0] ^= 0xff;

        let err = generate_proof_with_dev_mode(&request, None)
            .expect_err("invalid output commitment must be rejected");

        assert_eq!(
            err,
            ProveError::InvalidRequest("output_commitment does not match derived value".into())
        );
    }

    #[test]
    fn invalid_binding_is_rejected_before_proving() {
        let mut request = default_prove_request();
        request.binding[0] ^= 0xff;

        let err = generate_proof_with_dev_mode(&request, None)
            .expect_err("invalid binding must be rejected");

        assert_eq!(
            err,
            ProveError::InvalidRequest("binding does not match derived value".into())
        );
    }

    #[test]
    fn invalid_nullifier_is_rejected_before_proving() {
        let mut request = default_prove_request();
        request.nullifier[0] ^= 0xff;

        let err = generate_proof_with_dev_mode(&request, None)
            .expect_err("invalid nullifier must be rejected");

        assert_eq!(
            err,
            ProveError::InvalidRequest("nullifier does not match derived value".into())
        );
    }

    #[cfg(feature = "production-prover")]
    #[test]
    fn compiled_guest_image_matches_pinned_image() {
        assert_eq!(image_id(), TRUSTED_RISC0_IMAGE_ID);
    }

    #[cfg(feature = "production-prover")]
    #[test]
    fn real_proof_generation_returns_router_payload() {
        let response =
            generate_proof(&default_prove_request()).expect("proof generation must work");
        assert_eq!(response.seal_bytes.len(), SEAL_BYTES_LEN);
        assert_eq!(response.journal.len(), JOURNAL_TOTAL_LEN);
        assert_eq!(response.image_id, image_id());
    }
}
