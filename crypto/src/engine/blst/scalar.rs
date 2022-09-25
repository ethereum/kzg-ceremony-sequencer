use blst::{
    blst_fr, blst_fr_from_scalar, blst_fr_mul, blst_scalar, blst_scalar_from_be_bytes,
    blst_scalar_from_fr, blst_scalar_from_uint64,
};
use rand::{rngs::StdRng, RngCore, SeedableRng};

pub fn random_fr(entropy: [u8; 32]) -> blst_fr {
    let mut buffer = [0u8; 32];
    let mut rng = StdRng::from_seed(entropy);
    rng.fill_bytes(&mut buffer);

    let mut scalar = blst_scalar::default();
    let mut ret = blst_fr::default();

    unsafe {
        blst_scalar_from_be_bytes(&mut scalar, buffer.as_ptr(), 32);
        blst_fr_from_scalar(&mut ret, &scalar);
    }

    ret
}

pub fn fr_mul(a: &blst_fr, b: &blst_fr) -> blst_fr {
    let mut out = blst_fr::default();
    unsafe {
        blst_fr_mul(&mut out, a, b);
    }
    out
}

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
