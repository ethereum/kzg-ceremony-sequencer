use std::mem::MaybeUninit;

use blst::{blst_scalar, blst_scalar_from_be_bytes, blst_scalar_from_uint64, blst_sk_mul_n_check};
use rand::{rngs::StdRng, RngCore, SeedableRng};

use crate::ParseError;

pub struct ScalarBlst(pub MaybeUninit<blst_scalar>);

impl TryFrom<[u8; 32]> for ScalarBlst {
    type Error = ParseError;

    fn try_from(buffer: [u8; 32]) -> Result<Self, Self::Error> {
        let mut scalar = std::mem::MaybeUninit::<blst_scalar>::zeroed();
        unsafe {
            blst_scalar_from_be_bytes(scalar.as_mut_ptr(), buffer.as_ptr(), 32);
        }
        Ok(Self(scalar))
    }
}

impl TryFrom<u64> for ScalarBlst {
    type Error = ParseError;

    fn try_from(a: u64) -> Result<Self, Self::Error> {
        let mut scalar = std::mem::MaybeUninit::<blst_scalar>::zeroed();
        let input = [a, 0, 0, 0];
        unsafe {
            blst_scalar_from_uint64(scalar.as_mut_ptr(), input.as_ptr());
        }
        Ok(Self(scalar))
    }
}

pub fn random_scalar(entropy: [u8; 32]) -> [u8; 32] {
    // TODO: Use an explicit cryptographic rng.
    let mut data = [0u8; 32];
    let mut rng = StdRng::from_seed(entropy);
    rng.fill_bytes(&mut data);
    data
}

pub fn scalar_mul(a: &ScalarBlst, b: &ScalarBlst) -> ScalarBlst {
    let mut out = MaybeUninit::<blst_scalar>::zeroed();
    unsafe {
        if !blst_sk_mul_n_check(out.as_mut_ptr(), a.0.as_ptr(), b.0.as_ptr()) {
            todo!()
        }
    }
    ScalarBlst(out)
}
