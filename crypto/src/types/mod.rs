mod contribution;
mod error;
mod transcript;
mod utils;

pub use self::{
    contribution::{BatchContribution, Contribution},
    error::{CeremoniesError, CeremonyError},
    transcript::{BatchTranscript, Transcript},
};

#[cfg(test)]
pub mod test {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;

    #[test]
    fn verify() {
        let transcript = Transcript::new(32768, 65);
        let mut contrib = Contribution::new(32768, 65);
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
