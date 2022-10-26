pub mod hash_to_curve;
pub mod hash_to_field;
mod xmd_expander;

#[cfg(all(test, feature = "arkworks", feature = "blst"))]
mod tests {
    use crate::{
        engine::arkworks::hashing::{
            hash_to_curve::{HashToCurve, MapToCurveBasedHasher, WBMap},
            hash_to_field::{DefaultFieldHasher, HashToField},
        },
        F, G1,
    };
    use ark_bls12_381::{g1::Parameters as G1Parameters, Fq, Fr, G1Affine};
    use ark_ff::{BigInteger, PrimeField};
    use blst::{blst_hash_to_g1, blst_p1, blst_scalar};
    use sha2::Sha256;

    #[test]
    fn testX() {
        let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
        let m = 1;
        let hasher = <DefaultFieldHasher<Sha256, 128> as HashToField<Fq>>::new(dst);
        let got: Vec<Fq> = hasher.hash_to_field(b"hello world", 2 * m);
        println!("got: {:?}", got);
    }

    #[test]
    fn test() {
        let suite = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
        let m = 1;
        let g1_mapper = MapToCurveBasedHasher::<
            G1Parameters,
            DefaultFieldHasher<Sha256, 128>,
            WBMap<G1Parameters>,
        >::new(suite)
        .unwrap();

        let msg = b"hello world";
        let g1 = g1_mapper.hash(msg).unwrap();
        println!("g1: {:?}", g1);
        let enc1 = G1::from(g1);

        println!("{:?}", enc1);

        let g2 = unsafe {
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
            out
        };
        let enc2 = G1::try_from(g2).unwrap();

        println!("{:?}", enc2);
    }
}
