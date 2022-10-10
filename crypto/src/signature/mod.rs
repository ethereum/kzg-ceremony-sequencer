//! Implements the binding the contribution to participants.
//! https://github.com/ethereum/kzg-ceremony-specs/blob/master/docs/cryptography/contributionSigning.md
//! https://github.com/gakonst/ethers-rs/blob/e89c7a378bba6587e3f525982785c59a33c14d9b/ethers-core/ethers-derive-eip712/tests/derive_eip712.rs

mod identity;

use crate::G1;
use ethers;

pub enum BlsSignature {
    None,
    G1(G1),
    String(String),
}

pub enum EcdsaSignature {
    None,
    G1(G1),
    String(String),
}


#[derive(Debug, Clone, Eip712, EthAbiType)]
#[eip712(
    name = "Radicle",
    version = "1",
    chain_id = 1,
    verifying_contract = "0x0000000000000000000000000000000000000001"
)]
pub struct Puzzle {
    pub organization: H160,
    pub contributor: H160,
    pub commit: String,
    pub project: String,
}
