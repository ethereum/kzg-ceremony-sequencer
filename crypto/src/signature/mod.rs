mod identity;

use crate::G1;

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
