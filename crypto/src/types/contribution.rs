use super::{
    utils::{random_factors, read_vector_of_points},
    CeremoniesError, CeremonyError, Transcript,
};
use crate::{
    crypto::g1_mul_glv, g1_subgroup_check, g2_subgroup_check, parse_g, zcash_format::write_g,
};
use ark_bls12_381::{g2, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, Zero};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::cmp::max;
use tracing::instrument;
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct Contribution {
    pub pubkey:    G2Affine,
    pub g1_powers: Vec<G1Affine>,
    pub g2_powers: Vec<G2Affine>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubContributionJson {
    pub num_g1_powers: usize,
    pub num_g2_powers: usize,
    pub powers_of_tau: PowersOfTau,
    pub pot_pubkey:    Option<String>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PowersOfTau {
    pub g1_powers: Vec<String>,
    pub g2_powers: Vec<String>,
}

impl From<BatchContribution> for ContributionJson {
    fn from(contributions: BatchContribution) -> Self {
        Self {
            sub_contributions: contributions
                .sub_contributions
                .into_iter()
                .map(std::convert::Into::into)
                .collect(),
        }
    }
}

impl From<Contribution> for SubContributionJson {
    fn from(contribution: Contribution) -> Self {
        let powers_of_tau = PowersOfTau {
            g1_powers: contribution.g1_powers.iter().map(write_g).collect(),
            g2_powers: contribution.g2_powers.iter().map(write_g).collect(),
        };
        Self {
            num_g1_powers: contribution.g1_powers.len(),
            num_g2_powers: contribution.g2_powers.len(),
            pot_pubkey: Some(write_g(&contribution.pubkey)),
            powers_of_tau,
        }
    }
}

impl ContributionJson {
    #[must_use]
    pub fn initial() -> Self {
        Self {
            sub_contributions: crate::SIZES
                .iter()
                .map(|(num_g1, num_g2)| SubContributionJson::initial(*num_g1, *num_g2))
                .collect(),
        }
    }

    /// # Errors
    ///
    /// Errors may be reported when any of the contributions cannot be parsed.
    pub fn parse(&self) -> Result<Vec<Contribution>, CeremoniesError> {
        if self.sub_contributions.len() != crate::SIZES.len() {
            return Err(CeremoniesError::InvalidCeremoniesCount(
                4,
                self.sub_contributions.len(),
            ));
        }
        self.sub_contributions
            .iter()
            .zip(crate::SIZES.iter())
            .map(|(c, (num_g1, num_g2))| {
                if c.num_g1_powers != *num_g1 {
                    return Err(CeremonyError::UnexpectedNumG1Powers(
                        *num_g1,
                        c.num_g1_powers,
                    ));
                }
                if c.num_g2_powers != *num_g2 {
                    return Err(CeremonyError::UnexpectedNumG1Powers(
                        *num_g1,
                        c.num_g1_powers,
                    ));
                }
                Ok(())
            })
            .enumerate()
            .try_for_each(|(i, result)| {
                result.map_err(|e| CeremoniesError::InvalidCeremony(i, e))
            })?;
        self.sub_contributions
            .par_iter()
            .enumerate()
            .map(|(i, c)| {
                c.parse()
                    .map_err(|e| CeremoniesError::InvalidCeremony(i, e))
            })
            .collect::<Result<Vec<_>, _>>()
    }
}

impl SubContributionJson {
    #[must_use]
    pub fn initial(num_g1_powers: usize, num_g2_powers: usize) -> Self {
        Self {
            num_g1_powers,
            num_g2_powers,
            powers_of_tau: PowersOfTau::initial(num_g1_powers, num_g2_powers),
            pot_pubkey: None,
        }
    }

    /// # Errors
    ///
    /// Errors may be reported when the contribution cannot be parsed.
    pub fn parse(&self) -> Result<Contribution, CeremonyError> {
        if self.powers_of_tau.g1_powers.len() != self.num_g1_powers {
            return Err(CeremonyError::InconsistentNumG1Powers(
                self.num_g1_powers,
                self.powers_of_tau.g1_powers.len(),
            ));
        }
        if self.powers_of_tau.g2_powers.len() != self.num_g2_powers {
            return Err(CeremonyError::InconsistentNumG2Powers(
                self.num_g2_powers,
                self.powers_of_tau.g2_powers.len(),
            ));
        }
        let g1_powers =
            read_vector_of_points(&self.powers_of_tau.g1_powers, CeremonyError::InvalidG1Power)?;

        let g2_powers =
            read_vector_of_points(&self.powers_of_tau.g2_powers, CeremonyError::InvalidG2Power)?;

        let pubkey = if let Some(pubkey) = &self.pot_pubkey {
            parse_g::<g2::Parameters>(pubkey).map_err(CeremonyError::InvalidPubKey)?
        } else {
            G2Affine::zero()
        };
        Ok(Contribution {
            pubkey,
            g1_powers,
            g2_powers,
        })
    }
}

impl PowersOfTau {
    pub fn initial(num_g1_powers: usize, num_g2_powers: usize) -> Self {
        Self {
            g1_powers: vec!["0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb".to_string(); num_g1_powers],
            g2_powers: vec!["0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8".to_string(); num_g2_powers],
        }
    }
}

impl Contribution {
    #[must_use]
    pub fn new(num_g1: usize, num_g2: usize) -> Self {
        Self {
            pubkey:    G2Affine::prime_subgroup_generator(),
            g1_powers: vec![G1Affine::prime_subgroup_generator(); num_g1],
            g2_powers: vec![G2Affine::prime_subgroup_generator(); num_g2],
        }
    }

    #[instrument(level = "info", skip_all, fields(n1=self.g1_powers.len(), n2=self.g2_powers.len()))]
    pub fn subgroup_check(&self) -> bool {
        self.pubkey.is_in_correct_subgroup_assuming_on_curve()
            && !self.g1_powers.par_iter().any(|p| !g1_subgroup_check(p))
            && !self.g2_powers.par_iter().any(|p| !g2_subgroup_check(p))
    }

    #[instrument(level = "info", skip_all)]
    pub fn add_tau(&mut self, tau: &Fr) {
        let n_tau = max(self.g1_powers.len(), self.g2_powers.len());
        let powers = Self::pow_table(tau, n_tau);
        self.mul_g1(&powers[0..self.g1_powers.len()]);
        self.mul_g2(&powers[0..self.g2_powers.len()]);
        self.pubkey = self.pubkey.mul(*tau).into_affine();
    }

    #[instrument(level = "info", skip_all)]
    fn pow_table(tau: &Fr, n: usize) -> Zeroizing<Vec<Fr>> {
        let mut powers = Zeroizing::new(Vec::with_capacity(n));
        let mut pow_tau = Zeroizing::new(Fr::one());
        powers.push(*pow_tau);
        for _ in 1..n {
            *pow_tau *= *tau;
            powers.push(*pow_tau);
        }
        powers
    }

    #[instrument(level = "info", skip_all)]
    fn mul_g1(&mut self, scalars: &[Fr]) {
        let projective = self
            .g1_powers
            .par_iter()
            .zip(scalars.par_iter())
            .map(|(c, pow_tau)| g1_mul_glv(c, *pow_tau))
            .collect::<Vec<_>>();
        self.g1_powers = G1Projective::batch_normalization_into_affine(&projective[..]);
    }

    #[instrument(level = "info", skip_all)]
    fn mul_g2(&mut self, scalars: &[Fr]) {
        let projective = self
            .g2_powers
            .par_iter()
            .zip(scalars.par_iter())
            .map(|(c, pow_tau)| c.mul(*pow_tau))
            .collect::<Vec<_>>();
        self.g2_powers = G2Projective::batch_normalization_into_affine(&projective[..]);
    }

    #[instrument(level = "info", skip_all)]
    pub fn verify(&self, transcript: &Transcript) -> bool {
        self.g1_powers.len() == transcript.g1_powers.len()
            && self.g2_powers.len() == transcript.g2_powers.len()
            && self.verify_pubkey(transcript.products.last().unwrap())
            && self.verify_g1()
            && self.verify_g2()
    }

    #[instrument(level = "info", skip_all)]
    fn verify_pubkey(&self, prev_product: &G1Affine) -> bool {
        Bls12_381::pairing(self.g1_powers[1], G2Affine::prime_subgroup_generator())
            == Bls12_381::pairing(*prev_product, self.pubkey)
    }

    #[instrument(level = "info", skip_all)]
    fn verify_g1(&self) -> bool {
        let (factors, sum) = random_factors(self.g1_powers.len() - 1);
        let lhs_g1 = VariableBaseMSM::multi_scalar_mul(&self.g1_powers[1..], &factors[..]);
        let lhs_g2 = G2Affine::prime_subgroup_generator().mul(sum);
        let rhs_g1 =
            VariableBaseMSM::multi_scalar_mul(&self.g1_powers[..factors.len()], &factors[..]);
        let rhs_g2 = self.g2_powers[1].mul(sum);
        Bls12_381::pairing(lhs_g1, lhs_g2) == Bls12_381::pairing(rhs_g1, rhs_g2)
    }

    #[instrument(level = "info", skip_all)]
    fn verify_g2(&self) -> bool {
        let (factors, sum) = random_factors(self.g2_powers.len());
        let lhs_g1 =
            VariableBaseMSM::multi_scalar_mul(&self.g1_powers[..factors.len()], &factors[..]);
        let lhs_g2 = G2Affine::prime_subgroup_generator().mul(sum);
        let rhs_g1 = G1Affine::prime_subgroup_generator().mul(sum);
        let rhs_g2 = VariableBaseMSM::multi_scalar_mul(&self.g2_powers[..], &factors[..]);
        Bls12_381::pairing(lhs_g1, lhs_g2) == Bls12_381::pairing(rhs_g1, rhs_g2)
    }
}

impl crate::interface::Contribution for BatchContribution {
    type Receipt = Vec<String>;

    fn get_receipt(&self) -> Self::Receipt {
        self.sub_contributions
            .iter()
            .map(|c| write_g(&c.pubkey))
            .collect()
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
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
    use crate::bench::rand_fr;
    use ark_ff::UniformRand;
    use criterion::{black_box, BatchSize, BenchmarkId, Criterion};

    pub fn group(criterion: &mut Criterion) {
        bench_pow_tau(criterion);
        bench_add_tau(criterion);
        bench_verify(criterion);
    }

    fn bench_pow_tau(criterion: &mut Criterion) {
        criterion.bench_function("contribution/pow_tau", move |bencher| {
            let mut rng = rand::thread_rng();
            let tau = Zeroizing::new(Fr::rand(&mut rng));
            bencher.iter(|| black_box(Contribution::pow_table(black_box(&tau), 32768)));
        });
    }

    fn bench_add_tau(criterion: &mut Criterion) {
        for size in crate::SIZES {
            criterion.bench_with_input(
                BenchmarkId::new("contribution/add_tau", format!("{:?}", size)),
                &size,
                move |bencher, (n1, n2)| {
                    let mut contrib = Contribution::new(*n1, *n2);
                    bencher.iter_batched(
                        rand_fr,
                        |tau| contrib.add_tau(&tau),
                        BatchSize::SmallInput,
                    );
                },
            );
        }
    }

    fn bench_verify(criterion: &mut Criterion) {
        for size in crate::SIZES {
            criterion.bench_with_input(
                BenchmarkId::new("contribution/verify", format!("{:?}", size)),
                &size,
                move |bencher, (n1, n2)| {
                    let transcript = Transcript::new(*n1, *n2);
                    let mut contrib = Contribution::new(*n1, *n2);
                    contrib.add_tau(&rand_fr());
                    bencher.iter(|| black_box(contrib.verify(&transcript)));
                },
            );
        }
    }
}
