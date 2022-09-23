use std::mem::MaybeUninit;

use blst::{blst_scalar, blst_scalar_from_be_bytes, blst_scalar_from_uint64, blst_sk_mul_n_check};
use rand::{rngs::StdRng, RngCore, SeedableRng};

pub fn scalar_from_be_bytes(buffer: [u8; 32]) -> blst_scalar {
    unsafe {
        let mut scalar = std::mem::MaybeUninit::<blst_scalar>::zeroed();
        blst_scalar_from_be_bytes(scalar.as_mut_ptr(), buffer.as_ptr(), 32);
        // (&*(scalar.as_ptr())).to_owned()
        scalar.as_ptr().read()
    }
}

pub fn scalar_from_u64(a: u64) -> blst_scalar {
    unsafe {
        let mut scalar = std::mem::MaybeUninit::<blst_scalar>::zeroed();
        let input = [a, 0, 0, 0];
        blst_scalar_from_uint64(scalar.as_mut_ptr(), input.as_ptr());
        scalar.as_ptr().read()
    }
}

pub fn random_scalar(entropy: [u8; 32]) -> [u8; 32] {
    // TODO: Use an explicit cryptographic rng.
    let mut data = [0u8; 32];
    let mut rng = StdRng::from_seed(entropy);
    rng.fill_bytes(&mut data);
    data
}

pub fn scalar_mul(a: &blst_scalar, b: &blst_scalar) -> blst_scalar {
    unsafe {
        let mut out = MaybeUninit::<blst_scalar>::zeroed();
        if !blst_sk_mul_n_check(out.as_mut_ptr(), a, b) {
            todo!()
        }
        out.as_ptr().read()
    }
}
