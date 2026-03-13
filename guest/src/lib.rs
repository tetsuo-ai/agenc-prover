#![forbid(unsafe_code)]

use core::fmt;

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

pub const JOURNAL_FIELD_LEN: usize = 32;
pub const JOURNAL_FIELD_COUNT: usize = 6;
pub const OUTPUT_FIELD_COUNT: usize = 4;
pub const JOURNAL_TOTAL_LEN: usize = JOURNAL_FIELD_LEN * JOURNAL_FIELD_COUNT;
pub const CONSTRAINT_HASH_DOMAIN_TAG: &[u8] = b"AGENC_V2_CONSTRAINT_HASH";
pub const OUTPUT_COMMITMENT_DOMAIN_TAG: &[u8] = b"AGENC_V2_OUTPUT_COMMITMENT";
pub const BINDING_BASE_DOMAIN_TAG: &[u8] = b"AGENC_V2_BINDING_BASE";
pub const BINDING_DOMAIN_TAG: &[u8] = b"AGENC_V2_BINDING";
pub const NULLIFIER_DOMAIN_TAG: &[u8] = b"AGENC_V2_NULLIFIER";
pub const FIELD_MODULUS_BYTES: JournalField = [
    48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93, 40, 51, 232, 72,
    121, 185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 1,
];

pub type JournalField = [u8; JOURNAL_FIELD_LEN];
pub type JournalBytes = [u8; JOURNAL_TOTAL_LEN];
pub type OutputFields = [JournalField; OUTPUT_FIELD_COUNT];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalFields {
    pub task_pda: JournalField,
    pub agent_authority: JournalField,
    pub constraint_hash: JournalField,
    pub output_commitment: JournalField,
    pub binding: JournalField,
    pub nullifier: JournalField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateWitness {
    pub output: OutputFields,
    pub salt: JournalField,
    pub agent_secret: JournalField,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalError {
    InvalidFieldLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalValidationError {
    ZeroField {
        field: &'static str,
    },
    ConstraintHashMismatch {
        expected: JournalField,
        actual: JournalField,
    },
    OutputCommitmentMismatch {
        expected: JournalField,
        actual: JournalField,
    },
    BindingMismatch {
        expected: JournalField,
        actual: JournalField,
    },
    NullifierMismatch {
        expected: JournalField,
        actual: JournalField,
    },
}

impl fmt::Display for JournalValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroField { field } => write!(f, "{field} must be non-zero"),
            Self::ConstraintHashMismatch { .. } => {
                write!(f, "constraint_hash does not match derived value")
            }
            Self::OutputCommitmentMismatch { .. } => {
                write!(f, "output_commitment does not match derived value")
            }
            Self::BindingMismatch { .. } => {
                write!(f, "binding does not match derived value")
            }
            Self::NullifierMismatch { .. } => {
                write!(f, "nullifier does not match derived value")
            }
        }
    }
}

impl JournalFields {
    pub fn try_from_slices(
        task_pda: &[u8],
        agent_authority: &[u8],
        constraint_hash: &[u8],
        output_commitment: &[u8],
        binding: &[u8],
        nullifier: &[u8],
    ) -> Result<Self, JournalError> {
        Ok(Self {
            task_pda: copy_field("task_pda", task_pda)?,
            agent_authority: copy_field("agent_authority", agent_authority)?,
            constraint_hash: copy_field("constraint_hash", constraint_hash)?,
            output_commitment: copy_field("output_commitment", output_commitment)?,
            binding: copy_field("binding", binding)?,
            nullifier: copy_field("nullifier", nullifier)?,
        })
    }

    pub fn validate_against_witness(
        &self,
        witness: &PrivateWitness,
    ) -> Result<(), JournalValidationError> {
        require_non_zero("salt", &witness.salt)?;

        let expected_constraint_hash = compute_constraint_hash(&witness.output);
        if self.constraint_hash != expected_constraint_hash {
            return Err(JournalValidationError::ConstraintHashMismatch {
                expected: expected_constraint_hash,
                actual: self.constraint_hash,
            });
        }

        let expected_output_commitment =
            compute_output_commitment(&witness.output, &witness.salt);
        if self.output_commitment != expected_output_commitment {
            return Err(JournalValidationError::OutputCommitmentMismatch {
                expected: expected_output_commitment,
                actual: self.output_commitment,
            });
        }

        let expected_binding =
            compute_binding(&self.task_pda, &self.agent_authority, &expected_output_commitment);
        if self.binding != expected_binding {
            return Err(JournalValidationError::BindingMismatch {
                expected: expected_binding,
                actual: self.binding,
            });
        }

        let expected_nullifier = compute_nullifier_from_agent_secret(
            &expected_constraint_hash,
            &expected_output_commitment,
            &witness.agent_secret,
        );
        if self.nullifier != expected_nullifier {
            return Err(JournalValidationError::NullifierMismatch {
                expected: expected_nullifier,
                actual: self.nullifier,
            });
        }

        Ok(())
    }

    pub fn to_bytes(&self) -> JournalBytes {
        let mut out = [0_u8; JOURNAL_TOTAL_LEN];
        let fields: [&JournalField; JOURNAL_FIELD_COUNT] = [
            &self.task_pda,
            &self.agent_authority,
            &self.constraint_hash,
            &self.output_commitment,
            &self.binding,
            &self.nullifier,
        ];
        for (chunk, field) in out.chunks_exact_mut(JOURNAL_FIELD_LEN).zip(fields.iter()) {
            chunk.copy_from_slice(*field);
        }
        out
    }
}

impl PrivateWitness {
    pub fn try_from_slices(
        output_0: &[u8],
        output_1: &[u8],
        output_2: &[u8],
        output_3: &[u8],
        salt: &[u8],
        agent_secret: &[u8],
    ) -> Result<Self, JournalError> {
        Ok(Self {
            output: [
                copy_field("output[0]", output_0)?,
                copy_field("output[1]", output_1)?,
                copy_field("output[2]", output_2)?,
                copy_field("output[3]", output_3)?,
            ],
            salt: copy_field("salt", salt)?,
            agent_secret: copy_field("agent_secret", agent_secret)?,
        })
    }
}

pub fn serialize_journal(fields: &JournalFields) -> JournalBytes {
    fields.to_bytes()
}

pub fn compute_constraint_hash(output: &OutputFields) -> JournalField {
    hash_fields_to_field(CONSTRAINT_HASH_DOMAIN_TAG, output)
}

pub fn compute_output_commitment(output: &OutputFields, salt: &JournalField) -> JournalField {
    let mut hasher = Sha256::new();
    hasher.update(OUTPUT_COMMITMENT_DOMAIN_TAG);
    for value in output {
        hasher.update(normalize_field_bytes(value));
    }
    hasher.update(normalize_field_bytes(salt));
    digest_to_field_bytes(&hasher.finalize())
}

pub fn compute_binding(
    task_pda: &JournalField,
    agent_authority: &JournalField,
    output_commitment: &JournalField,
) -> JournalField {
    let binding_base = hash_fields_to_field(BINDING_BASE_DOMAIN_TAG, &[*task_pda, *agent_authority]);
    hash_fields_to_field(BINDING_DOMAIN_TAG, &[binding_base, *output_commitment])
}

pub fn compute_nullifier_from_agent_secret(
    constraint_hash: &JournalField,
    output_commitment: &JournalField,
    agent_secret: &JournalField,
) -> JournalField {
    let mut hasher = Sha256::new();
    hasher.update(NULLIFIER_DOMAIN_TAG);
    hasher.update(normalize_field_bytes(constraint_hash));
    hasher.update(normalize_field_bytes(output_commitment));
    hasher.update(normalize_field_bytes(agent_secret));
    hasher.finalize().into()
}

fn copy_field(field: &'static str, value: &[u8]) -> Result<JournalField, JournalError> {
    if value.len() != JOURNAL_FIELD_LEN {
        return Err(JournalError::InvalidFieldLength {
            field,
            expected: JOURNAL_FIELD_LEN,
            actual: value.len(),
        });
    }

    let mut out = [0_u8; JOURNAL_FIELD_LEN];
    out.copy_from_slice(value);
    Ok(out)
}

fn hash_fields_to_field(domain_tag: &[u8], values: &[JournalField]) -> JournalField {
    let mut hasher = Sha256::new();
    hasher.update(domain_tag);
    for value in values {
        hasher.update(normalize_field_bytes(value));
    }
    digest_to_field_bytes(&hasher.finalize())
}

fn digest_to_field_bytes(digest: &[u8]) -> JournalField {
    let reduced = BigUint::from_bytes_be(digest) % field_modulus();
    biguint_to_bytes32(&reduced)
}

fn normalize_field_bytes(value: &JournalField) -> JournalField {
    let reduced = BigUint::from_bytes_be(value) % field_modulus();
    biguint_to_bytes32(&reduced)
}

fn biguint_to_bytes32(value: &BigUint) -> JournalField {
    let bytes = value.to_bytes_be();
    debug_assert!(bytes.len() <= JOURNAL_FIELD_LEN);

    let mut out = [0_u8; JOURNAL_FIELD_LEN];
    let start = JOURNAL_FIELD_LEN.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes);
    out
}

fn field_modulus() -> BigUint {
    BigUint::from_bytes_be(&FIELD_MODULUS_BYTES)
}

fn require_non_zero(
    field: &'static str,
    value: &JournalField,
) -> Result<(), JournalValidationError> {
    if *value == [0_u8; JOURNAL_FIELD_LEN] {
        return Err(JournalValidationError::ZeroField { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness_bytes() -> PrivateWitness {
        let mut output_0 = [0_u8; JOURNAL_FIELD_LEN];
        output_0[31] = 1;
        let mut output_1 = [0_u8; JOURNAL_FIELD_LEN];
        output_1[31] = 2;
        let mut output_2 = [0_u8; JOURNAL_FIELD_LEN];
        output_2[31] = 3;
        let mut output_3 = [0_u8; JOURNAL_FIELD_LEN];
        output_3[31] = 4;
        let mut salt = [0_u8; JOURNAL_FIELD_LEN];
        salt[30] = 0x30;
        salt[31] = 0x39;
        let mut agent_secret = [0_u8; JOURNAL_FIELD_LEN];
        agent_secret[29] = 0x01;
        agent_secret[30] = 0x09;
        agent_secret[31] = 0x32;

        PrivateWitness {
            output: [output_0, output_1, output_2, output_3],
            salt,
            agent_secret,
        }
    }

    fn public_fields() -> JournalFields {
        let witness = witness_bytes();
        let mut task_pda = [0_u8; JOURNAL_FIELD_LEN];
        task_pda[31] = 0x2a;
        let agent_authority = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let constraint_hash = compute_constraint_hash(&witness.output);
        let output_commitment = compute_output_commitment(&witness.output, &witness.salt);
        let binding = compute_binding(&task_pda, &agent_authority, &output_commitment);
        let nullifier = compute_nullifier_from_agent_secret(
            &constraint_hash,
            &output_commitment,
            &witness.agent_secret,
        );

        JournalFields {
            task_pda,
            agent_authority,
            constraint_hash,
            output_commitment,
            binding,
            nullifier,
        }
    }

    #[test]
    fn compute_constraint_hash_matches_sdk_vector() {
        let actual = compute_constraint_hash(&witness_bytes().output);
        let expected = [
            27, 5, 2, 84, 39, 22, 233, 180, 224, 118, 227, 90, 187, 207, 226, 180, 153, 111, 89,
            65, 177, 42, 115, 94, 20, 181, 98, 20, 142, 87, 84, 23,
        ];

        assert_eq!(actual, expected);
    }

    #[test]
    fn compute_output_commitment_matches_sdk_vector() {
        let witness = witness_bytes();
        let actual = compute_output_commitment(&witness.output, &witness.salt);
        let expected = [
            5, 68, 147, 77, 26, 229, 129, 70, 252, 91, 137, 194, 187, 112, 184, 206, 175, 196,
            126, 146, 18, 138, 165, 201, 188, 180, 31, 10, 74, 50, 36, 30,
        ];

        assert_eq!(actual, expected);
    }

    #[test]
    fn compute_binding_matches_sdk_vector() {
        let fields = public_fields();
        let actual = compute_binding(
            &fields.task_pda,
            &fields.agent_authority,
            &fields.output_commitment,
        );
        let expected = [
            21, 13, 226, 197, 153, 150, 34, 181, 237, 51, 113, 126, 95, 159, 255, 117, 59, 155, 2,
            13, 16, 26, 14, 104, 94, 149, 113, 116, 45, 24, 164, 247,
        ];

        assert_eq!(actual, expected);
    }

    #[test]
    fn compute_nullifier_matches_sdk_vector() {
        let witness = witness_bytes();
        let fields = public_fields();
        let actual = compute_nullifier_from_agent_secret(
            &fields.constraint_hash,
            &fields.output_commitment,
            &witness.agent_secret,
        );
        let expected = [
            244, 234, 41, 112, 18, 33, 223, 173, 165, 57, 218, 176, 51, 26, 185, 6, 68, 155, 203,
            55, 112, 100, 87, 191, 241, 141, 85, 247, 244, 9, 238, 159,
        ];

        assert_eq!(actual, expected);
    }

    #[test]
    fn validate_against_witness_accepts_matching_fields() {
        let witness = witness_bytes();
        assert_eq!(public_fields().validate_against_witness(&witness), Ok(()));
    }

    #[test]
    fn validate_against_witness_rejects_zero_salt() {
        let mut witness = witness_bytes();
        witness.salt = [0_u8; JOURNAL_FIELD_LEN];

        assert_eq!(
            public_fields().validate_against_witness(&witness),
            Err(JournalValidationError::ZeroField { field: "salt" })
        );
    }

    #[test]
    fn validate_against_witness_rejects_constraint_hash_mismatch() {
        let witness = witness_bytes();
        let mut fields = public_fields();
        let expected = fields.constraint_hash;
        fields.constraint_hash[0] ^= 0xff;

        assert_eq!(
            fields.validate_against_witness(&witness),
            Err(JournalValidationError::ConstraintHashMismatch {
                expected,
                actual: fields.constraint_hash,
            })
        );
    }

    #[test]
    fn validate_against_witness_rejects_output_commitment_mismatch() {
        let witness = witness_bytes();
        let mut fields = public_fields();
        let expected = fields.output_commitment;
        fields.output_commitment[0] ^= 0xff;

        assert_eq!(
            fields.validate_against_witness(&witness),
            Err(JournalValidationError::OutputCommitmentMismatch {
                expected,
                actual: fields.output_commitment,
            })
        );
    }

    #[test]
    fn validate_against_witness_rejects_binding_mismatch() {
        let witness = witness_bytes();
        let mut fields = public_fields();
        let expected = fields.binding;
        fields.binding[0] ^= 0xff;

        assert_eq!(
            fields.validate_against_witness(&witness),
            Err(JournalValidationError::BindingMismatch {
                expected,
                actual: fields.binding,
            })
        );
    }

    #[test]
    fn validate_against_witness_rejects_nullifier_mismatch() {
        let witness = witness_bytes();
        let mut fields = public_fields();
        let expected = fields.nullifier;
        fields.nullifier[0] ^= 0xff;

        assert_eq!(
            fields.validate_against_witness(&witness),
            Err(JournalValidationError::NullifierMismatch {
                expected,
                actual: fields.nullifier,
            })
        );
    }
}
