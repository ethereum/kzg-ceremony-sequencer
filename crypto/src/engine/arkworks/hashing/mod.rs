pub mod hash_to_curve;
pub mod hash_to_field;
mod xmd_expander;

#[cfg(all(test, feature = "arkworks", feature = "blst"))]
mod tests {
    use crate::{
        engine::arkworks::hashing::{
            hash_to_curve::{HashToCurve, MapToCurveBasedHasher, WBMap},
            hash_to_field::DefaultFieldHasher,
        },
        group::G1,
    };
    use ark_bls12_381::g1::Parameters as G1Parameters;
    use blst::{blst_hash_to_g1, blst_p1};
    use proptest::proptest;
    use sha2::Sha256;

    #[test]
    fn test() {
        proptest!(|(msg in ".*")| {
            let suite = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
            let msg = msg.as_bytes();
            let g1_mapper = MapToCurveBasedHasher::<
                G1Parameters,
                DefaultFieldHasher<Sha256, 128>,
                WBMap<G1Parameters>,
            >::new(suite)
            .unwrap();

            let g1_ark = G1::from(g1_mapper.hash(msg).unwrap());
            let g1_blst = unsafe {
                let mut out = blst_p1::default();
                blst_hash_to_g1(
                    &mut out,
                    msg.as_ptr(),
                    msg.len(),
                    suite.as_ptr(),
                    suite.len(),
                    [0 as u8; 0].as_ptr(),
                    0,
                );
                G1::try_from(out).unwrap()
            };
            assert_eq!(g1_ark, g1_blst);
        });
    }
}
