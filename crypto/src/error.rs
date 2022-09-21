use thiserror::Error;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum CeremoniesError {
    #[error("Unexpected number of contributions: expected {0}, got {1}")]
    UnexpectedNumContributions(usize, usize),
    #[error("Error in contribution {0}: {1}")]
    InvalidCeremony(usize, #[source] CeremonyError),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum CeremonyError {
    #[error("Unexpected number of G1 powers: expected {0}, got {1}")]
    UnexpectedNumG1Powers(usize, usize),
    #[error("Unexpected number of G2 powers: expected {0}, got {1}")]
    UnexpectedNumG2Powers(usize, usize),
    #[error("Inconsistent number of G1 powers: numG1Powers = {0}, len = {1}")]
    InconsistentNumG1Powers(usize, usize),
    #[error("Inconsistent number of G2 powers: numG2Powers = {0}, len = {1}")]
    InconsistentNumG2Powers(usize, usize),
    #[error("Error parsing G1 power {0}: {1}")]
    InvalidG1Power(usize, #[source] ParseError),
    #[error("Error parsing G2 power {0}: {1}")]
    InvalidG2Power(usize, #[source] ParseError),
    #[error("Parse error in unknown point: {0}")]
    ParserError(#[from] ParseError),
    #[error("Error parsing potPubkey: {0}")]
    InvalidPubKey(#[source] ParseError),
    #[error("Error parsing running product {0}: {1}")]
    InvalidWitnessProduct(usize, #[source] ParseError),
    #[error("Error parsing potPubkey {0}: {1}")]
    InvalidWitnessPubKey(usize, #[source] ParseError),
    #[error("Pubkey pairing check failed")]
    PubKeyPairingFailed,
    #[error("G1 pairing check failed")]
    G1PairingFailed,
    #[error("G2 pairing check failed")]
    G2PairingFailed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum ParseError {
    #[error("Invalid x coordinate")]
    BigIntError,
    #[error("Point is not compressed")]
    NotCompressed,
    #[error("Point at infinity must have zero x coordinate")]
    InvalidInfinity,
    #[error("Error in extension field component {0}: Number is too large for the prime field")]
    InvalidPrimeField(usize),
    #[error("Error in extension field element")]
    InvalidExtensionField,
    #[error("not a valid x coordinate")]
    InvalidXCoordinate,
    #[error("curve point is not in prime order subgroup")]
    InvalidSubgroup,
}
