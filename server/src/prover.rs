use std::{ffi::OsStr, fmt};

#[cfg(feature = "production-prover")]
use agenc_zkvm_guest::{serialize_journal, JOURNAL_TOTAL_LEN};
use agenc_zkvm_guest::{JournalField, JournalFields};

pub const IMAGE_ID_LEN: usize = 32;
pub const SEAL_SELECTOR_LEN: usize = 4;
pub const SEAL_PROOF_LEN: usize = 256;
pub const SEAL_BYTES_LEN: usize = 260;
pub const TRUSTED_SEAL_SELECTOR: [u8; SEAL_SELECTOR_LEN] = [0x52, 0x5a, 0x56, 0x4d];
pub const DEV_MODE_ENV_VAR: &str = "RISC0_DEV_MODE";
pub const TRUSTED_RISC0_IMAGE_ID: [u8; IMAGE_ID_LEN] = [
    234, 105, 58, 154, 139, 43, 119, 65, 97, 133, 45, 254, 201, 178, 175, 71, 73, 230, 18, 17, 243,
    3, 22, 193, 47, 173, 107, 173, 215, 208, 1, 82,
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
}

impl From<ProveRequest> for JournalFields {
    fn from(request: ProveRequest) -> Self {
        Self {
            task_pda: request.task_pda,
            agent_authority: request.agent_authority,
            constraint_hash: request.constraint_hash,
            output_commitment: request.output_commitment,
            binding: request.binding,
            nullifier: request.nullifier,
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
                    expected,
                    actual
                )
            }
            Self::DevModeEnabled { variable } => {
                write!(f, "{variable} is set; refusing to generate proof output")
            }
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

    let fields: &[(&str, &[u8; JOURNAL_FIELD_LEN])] = &[
        ("task_pda", &request.task_pda),
        ("agent_authority", &request.agent_authority),
        ("constraint_hash", &request.constraint_hash),
        ("output_commitment", &request.output_commitment),
        ("binding", &request.binding),
        ("nullifier", &request.nullifier),
    ];

    let mut builder = ExecutorEnv::builder();
    for (name, field) in fields {
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

    let expected_journal = serialize_journal(&JournalFields::from(*request));
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

pub fn guest_id_to_image_id(guest_id: &[u32; 8]) -> ImageId {
    let mut out = [0u8; IMAGE_ID_LEN];
    for (chunk, word) in out.chunks_exact_mut(SEAL_SELECTOR_LEN).zip(guest_id.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn encode_seal(proof_bytes: &[u8; SEAL_PROOF_LEN]) -> Vec<u8> {
    let mut seal_bytes = Vec::with_capacity(SEAL_BYTES_LEN);
    seal_bytes.extend_from_slice(&TRUSTED_SEAL_SELECTOR);
    seal_bytes.extend_from_slice(proof_bytes);
    seal_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_prove_request() -> ProveRequest {
        ProveRequest {
            task_pda: [1_u8; 32],
            agent_authority: [2_u8; 32],
            constraint_hash: [3_u8; 32],
            output_commitment: [4_u8; 32],
            binding: [5_u8; 32],
            nullifier: [6_u8; 32],
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
        let raw = [9u8; SEAL_PROOF_LEN];
        let encoded = encode_seal(&raw);
        assert_eq!(encoded.len(), SEAL_BYTES_LEN);
        assert_eq!(&encoded[..SEAL_SELECTOR_LEN], &TRUSTED_SEAL_SELECTOR);
        assert_eq!(&encoded[SEAL_SELECTOR_LEN..], &raw);
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
        assert_eq!(response.image_id, TRUSTED_RISC0_IMAGE_ID);
        assert_eq!(
            &response.seal_bytes[..SEAL_SELECTOR_LEN],
            &TRUSTED_SEAL_SELECTOR
        );
    }
}
