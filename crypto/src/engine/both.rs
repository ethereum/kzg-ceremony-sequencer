use super::Engine;
use crate::{CeremonyError, Entropy, Tau, G1, G2};
use rayon::join;
use std::marker::PhantomData;

/// Implementation of [`Engine`] that combines two existing engines for
/// redundancy.
pub struct Both<A: Engine, B: Engine> {
    _a: PhantomData<A>,
    _b: PhantomData<B>,
}

impl<A: Engine, B: Engine> Engine for Both<A, B> {
    fn validate_g1(points: &[G1]) -> Result<(), CeremonyError> {
        let (a, b) = join(|| A::validate_g1(points), || B::validate_g1(points));
        a?;
        b?;
        Ok(())
    }

    fn validate_g2(points: &[G2]) -> Result<(), CeremonyError> {
        let (a, b) = join(|| A::validate_g2(points), || B::validate_g2(points));
        a?;
        b?;
        Ok(())
    }

    fn verify_pubkey(tau: G1, previous: G1, pubkey: G2) -> Result<(), CeremonyError> {
        let (a, b) = join(
            || A::verify_pubkey(tau, previous, pubkey),
            || B::verify_pubkey(tau, previous, pubkey),
        );
        a?;
        b?;
        Ok(())
    }

    fn verify_g1(powers: &[G1], tau: G2) -> Result<(), CeremonyError> {
        let (a, b) = join(|| A::verify_g1(powers, tau), || B::verify_g1(powers, tau));
        a?;
        b?;
        Ok(())
    }

    fn verify_g2(g1: &[G1], g2: &[G2]) -> Result<(), CeremonyError> {
        let (a, b) = join(|| A::verify_g2(g1, g2), || B::verify_g2(g1, g2));
        a?;
        b?;
        Ok(())
    }

    fn generate_tau(entropy: &Entropy) -> Tau {
        let (a, _b) = join(|| A::generate_tau(entropy), || B::generate_tau(entropy));

        // TODO: Standardize the derivation so we can check this
        // assert_eq!(a.expose_secret(), b.expose_secret());
        a
    }

    fn add_tau_g1(tau: &Tau, powers: &mut [G1]) -> Result<(), CeremonyError> {
        let mut b = powers.to_vec();
        let (ra, rb) = join(|| A::add_tau_g1(tau, powers), || B::add_tau_g1(tau, &mut b));
        ra?;
        rb?;
        assert_eq!(powers, &b[..]);
        Ok(())
    }

    fn add_tau_g2(tau: &Tau, powers: &mut [G2]) -> Result<(), CeremonyError> {
        let mut b = powers.to_vec();
        let (ra, rb) = join(|| A::add_tau_g2(tau, powers), || B::add_tau_g2(tau, &mut b));
        ra?;
        rb?;
        assert_eq!(powers, &b[..]);
        Ok(())
    }

    fn sign_message(tau: &Tau, message: &[u8]) -> Option<G1> {
        let a = A::sign_message(tau, message);
        let b = B::sign_message(tau, message);
        assert_eq!(a, b);
        a
    }

    fn verify_signature(sig: G1, message: &[u8], pk: G2) -> bool {
        let a = A::verify_signature(sig, message, pk);
        let b = B::verify_signature(sig, message, pk);
        assert_eq!(a, b);
        a
    }
}
