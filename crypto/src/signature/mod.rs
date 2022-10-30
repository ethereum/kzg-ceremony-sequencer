//! Implements the binding the contribution to participants.
//! <https://github.com/ethereum/kzg-ceremony-specs/blob/master/docs/cryptography/contributionSigning.md>
//! <https://github.com/gakonst/ethers-rs/blob/e89c7a378bba6587e3f525982785c59a33c14d9b/ethers-core/ethers-derive-eip712/tests/derive_eip712.rs>

mod identity;

use crate::G1;

#[allow(unused)]
pub enum BlsSignature {
    None,
    G1(G1),
    String(String),
}

#[allow(unused)]
pub enum EcdsaSignature {
    None,
    G1(G1),
    String(String),
}
