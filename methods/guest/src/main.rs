#![forbid(unsafe_code)]

use agenc_zkvm_guest::{serialize_journal, JournalFields, PrivateWitness, JOURNAL_FIELD_LEN};
use risc0_zkvm::guest::env;

fn main() {
    let task_pda: [u8; JOURNAL_FIELD_LEN] = env::read();
    let agent_authority: [u8; JOURNAL_FIELD_LEN] = env::read();
    let constraint_hash: [u8; JOURNAL_FIELD_LEN] = env::read();
    let output_commitment: [u8; JOURNAL_FIELD_LEN] = env::read();
    let binding: [u8; JOURNAL_FIELD_LEN] = env::read();
    let nullifier: [u8; JOURNAL_FIELD_LEN] = env::read();
    let output_0: [u8; JOURNAL_FIELD_LEN] = env::read();
    let output_1: [u8; JOURNAL_FIELD_LEN] = env::read();
    let output_2: [u8; JOURNAL_FIELD_LEN] = env::read();
    let output_3: [u8; JOURNAL_FIELD_LEN] = env::read();
    let salt: [u8; JOURNAL_FIELD_LEN] = env::read();
    let agent_secret: [u8; JOURNAL_FIELD_LEN] = env::read();

    let fields = JournalFields {
        task_pda,
        agent_authority,
        constraint_hash,
        output_commitment,
        binding,
        nullifier,
    };
    let witness = PrivateWitness {
        output: [output_0, output_1, output_2, output_3],
        salt,
        agent_secret,
    };

    if let Err(err) = fields.validate_against_witness(&witness) {
        panic!("{err}");
    }

    env::commit_slice(&serialize_journal(&fields));
}
