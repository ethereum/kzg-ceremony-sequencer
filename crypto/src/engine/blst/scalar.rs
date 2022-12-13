use crate::F;
use blst::{
    blst_fr, blst_fr_add, blst_fr_from_scalar, blst_fr_mul, blst_keygen, blst_lendian_from_scalar,
    blst_scalar, blst_scalar_from_fr, blst_scalar_from_lendian, blst_scalar_from_uint64,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub fn random_fr(entropy: [u8; 32]) -> blst_fr {
    // Use ChaCha20 CPRNG
    let mut rng = ChaCha20Rng::from_seed(entropy);

    // Generate tau by reducing 512 bits of entropy modulo prime.
    let mut buffer = [0u8; 64];
    rng.fill(&mut buffer);

    let mut scalar = blst_scalar::default();
    let mut ret = blst_fr::default();

    unsafe {
        blst_keygen(
            &mut scalar,
            buffer.as_ptr(),
            buffer.len(),
            [0; 0].as_ptr(),
            0,
        );
        blst_fr_from_scalar(&mut ret, &scalar);
    }

    ret
}

#[allow(dead_code)] // Currently only used in tests
pub fn fr_add(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    unsafe {
        blst_fr_add(&mut out, a, b);
    }
    out
}

pub fn fr_mul(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    unsafe {
        blst_fr_mul(&mut out, a, b);
    }
    out
}

#[allow(dead_code)] // Currently only used in tests
pub fn fr_zero() -> blst_fr {
    fr_from_scalar(&scalar_from_u64(0u64))
}

pub fn fr_one() -> blst_fr {
    fr_from_scalar(&scalar_from_u64(1u64))
}

pub fn scalar_from_fr(a: &blst_fr) -> blst_scalar {
    let mut ret = blst_scalar::default();
    unsafe {
        blst_scalar_from_fr(&mut ret, a);
    }
    ret
}

pub fn fr_from_scalar(a: &blst_scalar) -> blst_fr {
    let mut ret = blst_fr::default();
    unsafe {
        blst_fr_from_scalar(&mut ret, a);
    }
    ret
}

pub fn scalar_from_u64(a: u64) -> blst_scalar {
    let mut scalar = blst_scalar::default();
    let input = [a, 0, 0, 0];
    unsafe {
        blst_scalar_from_uint64(&mut scalar, input.as_ptr());
    }
    scalar
}

impl From<&F> for blst_scalar {
    fn from(n: &F) -> Self {
        let mut out = Self::default();
        unsafe {
            blst_scalar_from_lendian(&mut out, n.0.as_ptr());
        }
        out
    }
}

impl From<&F> for blst_fr {
    fn from(n: &F) -> Self {
        // TODO: Zeroize the temps
        let mut scalar = blst_scalar::default();
        let mut ret = Self::default();
        unsafe {
            blst_scalar_from_lendian(&mut scalar, n.0.as_ptr());
            blst_fr_from_scalar(&mut ret, &scalar);
        }
        ret
    }
}

impl From<&blst_fr> for F {
    fn from(n: &blst_fr) -> Self {
        let mut scalar = blst_scalar::default();
        let mut ret = [0u8; 32];
        unsafe {
            blst_scalar_from_fr(&mut scalar, n);
            blst_lendian_from_scalar(ret.as_mut_ptr(), &scalar);
        }
        Self(ret)
    }
}
