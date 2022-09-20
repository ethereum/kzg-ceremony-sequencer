mod endomorphism;
mod zcash_format;

use super::Engine;
use crate::types::{CeremonyError, G1, G2};

struct Arkworks;

impl Engine for Arkworks {
    fn validate_g1(points: &[G1]) -> Result<(), CeremonyError> {
        todo!()
    }

    fn validate_g2(points: &[G2]) -> Result<(), CeremonyError> {
        todo!()
    }

    fn verify_pubkey(tau: G1, previous: G1, pubkey: G2) -> Result<(), CeremonyError> {
        todo!()
    }

    fn verify_g1(powers: &[G1], tau: G2) -> Result<(), CeremonyError> {
        todo!()
    }

    fn verify_g2(g1: &[G1], g2: &[G2]) -> Result<(), CeremonyError> {
        todo!()
    }
}
