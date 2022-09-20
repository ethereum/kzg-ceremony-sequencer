//! Abstraction over the backend used for cryptographic operations.

mod arkworks;

use crate::types::{CeremonyError, G1, G2};

pub trait Engine {
    /// Verifies that the given G1 points are valid.
    fn validate_g1(points: &[G1]) -> Result<(), CeremonyError>;

    /// Verifies that the given G2 points are valid.
    fn validate_g2(points: &[G2]) -> Result<(), CeremonyError>;

    /// Verify that the pubkey contains the contribution added
    /// from `previous` to `tau`.
    fn verify_pubkey(tau: G1, previous: G1, pubkey: G2) -> Result<(), CeremonyError>;

    /// Verify that `powers` containts a sequence of powers of `tau`.
    fn verify_g1(powers: &[G1], tau: G2) -> Result<(), CeremonyError>;

    /// Verify that `g1` and `g2` contain the same values.
    fn verify_g2(g1: &[G1], g2: &[G2]) -> Result<(), CeremonyError>;
}
