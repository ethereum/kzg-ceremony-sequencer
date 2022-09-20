mod contribution;
mod error;
mod transcript;
mod utils;

pub use self::{
    contribution::{Contribution, SubContribution},
    error::{CeremoniesError, CeremonyError},
    transcript::{SubTranscript, Transcript},
};

#[cfg(test)]
pub mod test {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;

    #[test]
    fn verify() {
        let transcript = SubTranscript::new(32768, 65);
        let mut contrib = SubContribution::new(32768, 65);
        assert!(contrib.verify(&transcript));
        let mut rng = rand::thread_rng();
        contrib.add_tau(&Fr::rand(&mut rng));
        assert!(contrib.verify(&transcript));
    }
}

#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod bench {
    use super::*;
    use criterion::Criterion;

    pub fn group(criterion: &mut Criterion) {
        contribution::bench::group(criterion);
    }
}
