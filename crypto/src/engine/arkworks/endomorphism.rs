/// Optimized subgroup checks.
///
/// Endomorphism and subgroup checks taken from latest (unreleased) arkworks-rs:
/// See [`bls12_381/src/curves/g1.rs`](https://github.com/arkworks-rs/curves/blob/dc555882cd867b1e5b6fb16f840ebb0b336136d1/bls12_381/src/curves/g1.rs#L48)
/// See [`bls12_381/src/curves/g2.rs`](https://github.com/arkworks-rs/curves/blob/dc555882cd867b1e5b6fb16f840ebb0b336136d1/bls12_381/src/curves/g2.rs#L112)
use ark_bls12_381::{Fq, Fr, G1Affine, G1Projective, G2Projective, Parameters};
use ark_bls12_381::{Fq2, G2Affine};
use ark_ec::{bls12::Bls12Parameters, AffineCurve, ProjectiveCurve};
use ark_ff::{field_new, Field, PrimeField, Zero};
use std::ops::{AddAssign, Neg};

/// `is_in_correct_subgroup_assuming_on_curve` from arkworks
#[inline]
#[must_use]
pub fn g1_subgroup_check(p: &G1Affine) -> bool {
    // Algorithm from Section 6 of https://eprint.iacr.org/2021/1130.
    //
    // Check that endomorphism_p(P) == -[X^2]P

    // An early-out optimization described in Section 6.
    // If uP == P but P != point of infinity, then the point is not in the right
    // subgroup.
    let x_times_p = g1_mul_bigint(p, Parameters::X);
    if x_times_p.eq(p) && !p.infinity {
        return false;
    }

    let minus_x_squared_times_p = g1_mul_bigint_proj(&x_times_p, Parameters::X).neg();
    let endomorphism_p = g1_endomorphism(p);
    minus_x_squared_times_p.eq(&endomorphism_p)
}

#[inline]
#[must_use]
pub fn g2_subgroup_check(point: &G2Affine) -> bool {
    // Algorithm from Section 4 of https://eprint.iacr.org/2021/1130.
    //
    // Checks that [p]P = [X]P

    let mut x_times_point = g2_mul_bigint(point, Parameters::X);
    if Parameters::X_IS_NEGATIVE {
        x_times_point = -x_times_point;
    }

    let p_times_point = g2_endomorphism(point);

    x_times_point.eq(&p_times_point)
}

#[inline]
fn g1_mul_bigint(base: &G1Affine, scalar: &[u64]) -> G1Projective {
    // TODO: Small WNAF
    let mut res = G1Projective::zero();
    for b in ark_ff::BitIteratorBE::without_leading_zeros(scalar) {
        res.double_in_place();
        if b {
            res.add_assign_mixed(base);
        }
    }
    res
}

#[inline]
fn g1_mul_bigint_proj(base: &G1Projective, scalar: &[u64]) -> G1Projective {
    // TODO: Small WNAF
    let mut res = G1Projective::zero();
    for b in ark_ff::BitIteratorBE::without_leading_zeros(scalar) {
        res.double_in_place();
        if b {
            res += base;
        }
    }
    res
}

#[inline]
fn g2_mul_bigint(base: &G2Affine, scalar: &[u64]) -> G2Projective {
    // TODO: Small WNAF
    let mut res = G2Projective::zero();
    for b in ark_ff::BitIteratorBE::without_leading_zeros(scalar) {
        res.double_in_place();
        if b {
            res.add_assign_mixed(base);
        }
    }
    res
}

#[inline]
pub fn g1_endomorphism(p: &G1Affine) -> G1Affine {
    /// BETA is a non-trivial cubic root of unity in Fq.
    const BETA: Fq = field_new!(Fq, "793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350");

    // Endomorphism of the points on the curve.
    // endomorphism_p(x,y) = (BETA * x, y)
    // where BETA is a non-trivial cubic root of unity in Fq.
    let mut res = *p;
    res.x *= BETA;
    res
}

#[inline]
fn g2_endomorphism(p: &G2Affine) -> G2Affine {
    // The p-power endomorphism for G2 is defined as follows:
    // 1. Note that G2 is defined on curve E': y^2 = x^3 + 4(u+1).
    //    To map a point (x, y) in E' to (s, t) in E,
    //    one set s = x / ((u+1) ^ (1/3)), t = y / ((u+1) ^ (1/2)),
    //    because E: y^2 = x^3 + 4.
    // 2. Apply the Frobenius endomorphism (s, t) => (s', t'),
    //    another point on curve E, where s' = s^p, t' = t^p.
    // 3. Map the point from E back to E'; that is,
    //    one set x' = s' * ((u+1) ^ (1/3)), y' = t' * ((u+1) ^ (1/2)).
    //
    // To sum up, it maps
    // (x,y) -> (x^p / ((u+1)^((p-1)/3)), y^p / ((u+1)^((p-1)/2)))
    // as implemented in the code as follows.

    // PSI_X = 1/(u+1)^((p-1)/3)
    const P_POWER_ENDOMORPHISM_COEFF_0_1: Fq =
        field_new!(Fq,
            "4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437"
        );
    // PSI_Y = 1/(u+1)^((p-1)/2)
    const P_POWER_ENDOMORPHISM_COEFF_1_0: Fq = field_new!(Fq,
            "2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530");
    const P_POWER_ENDOMORPHISM_COEFF_1_1: Fq = field_new!(Fq,
            "1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257");

    let mut res = *p;
    res.x.frobenius_map(1);
    res.y.frobenius_map(1);

    let tmp_x = res.x;
    res.x.c0 = -P_POWER_ENDOMORPHISM_COEFF_0_1 * tmp_x.c1;
    res.x.c1 = P_POWER_ENDOMORPHISM_COEFF_0_1 * tmp_x.c0;
    res.y *= Fq2::new(
        P_POWER_ENDOMORPHISM_COEFF_1_0,
        P_POWER_ENDOMORPHISM_COEFF_1_1,
    );

    res
}

// const G1_LAMBDA: u64 = 0xd201_0000_0001_0000;
const G1_LAMBDA_2: [u64; 2] = [0x0000_0001_0000_0000, 0xac45_a401_0001_a402];

#[inline]
#[must_use]
fn g1_split(tau: Fr) -> (u128, u128) {
    let mut tau = tau.into_repr().0;
    let mut divisor = G1_LAMBDA_2;
    ruint::algorithms::div(&mut tau, &mut divisor);
    let k0 = (divisor[0] as u128) | (divisor[1] as u128) << 64;
    let k1 = (tau[0] as u128) | (tau[1] as u128) << 64;
    (k0, k1)
}

/// Implements scalar-point multiplication using Gallant-Lambert-Vanstone (GLV).
pub fn g1_mul_glv(p: &G1Affine, tau: Fr) -> G1Projective {
    let (k0, k1) = g1_split(tau);

    // Find first bit set
    if k0 | k1 == 0 {
        return G1Projective::zero();
    }
    let mut bit = 1_u128 << (127 - (k0 | k1).leading_zeros());

    // Compute endomorphism
    let q = g1_endomorphism(p).neg();
    let pq = p.into_projective().add_mixed(&q);
    // TODO: Small WNAF

    let mut res = G1Projective::zero();
    loop {
        let b0 = bit & k0 != 0;
        let b1 = bit & k1 != 0;
        match (b0, b1) {
            (true, true) => res.add_assign(&pq),
            (true, false) => res.add_assign_mixed(p),
            (false, true) => res.add_assign_mixed(&q),
            (false, false) => {}
        }
        bit >>= 1;
        if bit == 0 {
            break;
        }
        res.double_in_place();
    }
    res
}

#[cfg(test)]
pub mod test {
    use super::{
        super::test::{arb_fr, arb_g1, arb_g2},
        *,
    };
    use crate::engine::arkworks::test::{
        arb_g1_probably_not_in_subgroup, arb_g2_probably_not_in_subgroup,
    };
    use ark_ec::AffineCurve;
    use ark_ff::{BigInteger256, PrimeField};
    use proptest::proptest;

    #[test]
    fn test_g1_endomorphism() {
        proptest!(|(p in arb_g1())| {
            let expected = g1_mul_bigint(&p, &G1_LAMBDA_2).neg().into_affine();
            let value = g1_endomorphism(&p);
            assert_eq!(value, expected);
        });
    }

    #[test]
    fn test_negative_g1_check() {
        proptest!(|(p in arb_g1_probably_not_in_subgroup())| {
            let expected = p.is_in_correct_subgroup_assuming_on_curve();
            let value = g1_subgroup_check(&p);
            assert_eq!(value, expected);
        });
    }

    #[test]
    fn test_positive_g1_check() {
        proptest!(|(p in arb_g1())| {
            let expected = p.is_in_correct_subgroup_assuming_on_curve();
            let value = g1_subgroup_check(&p);
            assert_eq!(value, expected);
        });
    }

    #[test]
    fn test_g1_split() {
        let lambda = Fr::from_repr(BigInteger256([G1_LAMBDA_2[0], G1_LAMBDA_2[1], 0, 0])).unwrap();
        proptest!(|(s in arb_fr())| {
            let (k0, k1) = g1_split(s);
            let value = Fr::from(k0) + Fr::from(k1) * lambda;
            assert_eq!(value, s);
        });
    }

    #[test]
    fn test_g1_mul_glv() {
        proptest!(|(p in arb_g1(), s in arb_fr())| {
            let expected = p.mul(s);
            let value = g1_mul_glv(&p, s);
            assert_eq!(value, expected);
        });
    }

    #[test]
    fn test_positive_g2_check() {
        proptest!(|(p in arb_g2())| {
            let value = g2_subgroup_check(&p);
            let expected = p.is_in_correct_subgroup_assuming_on_curve();
            assert_eq!(value, expected);
        });
    }

    #[test]
    fn test_negative_g2_check() {
        proptest!(|(p in arb_g2_probably_not_in_subgroup())| {
            let value = g2_subgroup_check(&p);
            let expected = p.is_in_correct_subgroup_assuming_on_curve();
            assert_eq!(value, expected);
        });
    }
}

#[cfg(feature = "bench")]
#[cfg(not(tarpaulin_include))]
#[doc(hidden)]
pub mod bench {
    use super::{
        super::bench::{rand_fr, rand_g1, rand_g2},
        *,
    };
    use criterion::{black_box, BatchSize, Criterion};

    pub fn group(criterion: &mut Criterion) {
        bench_g1_endo(criterion);
        bench_g1_check(criterion);
        bench_g1_check_endo(criterion);
        bench_g1_mul(criterion);
        bench_g1_split(criterion);
        bench_g1_mul_glv(criterion);
        bench_g2_endo(criterion);
        bench_g2_check(criterion);
        bench_g2_check_endo(criterion);
        bench_g2_mul(criterion);
    }

    fn bench_g1_endo(criterion: &mut Criterion) {
        criterion.bench_function("g1_endomorphism", move |bencher| {
            bencher.iter_batched(
                rand_g1,
                |p| black_box(g1_endomorphism(&p)),
                BatchSize::SmallInput,
            );
        });
    }

    fn bench_g1_check(criterion: &mut Criterion) {
        criterion.bench_function("g1_subgroup_check", move |bencher| {
            bencher.iter_batched(
                rand_g1,
                |p| black_box(p.is_in_correct_subgroup_assuming_on_curve()),
                BatchSize::SmallInput,
            );
        });
    }

    fn bench_g1_check_endo(criterion: &mut Criterion) {
        criterion.bench_function("g1_subgroup_check_endo", move |bencher| {
            bencher.iter_batched(
                rand_g1,
                |p| black_box(g1_subgroup_check(&p)),
                BatchSize::SmallInput,
            );
        });
    }

    fn bench_g1_mul(criterion: &mut Criterion) {
        criterion.bench_function("g1_mul", move |bencher| {
            bencher.iter_batched(
                || (rand_g1(), rand_fr()),
                |(p, s)| black_box(p.mul(black_box(s))),
                BatchSize::SmallInput,
            );
        });
    }

    fn bench_g1_split(criterion: &mut Criterion) {
        criterion.bench_function("g1_split", move |bencher| {
            bencher.iter_batched(rand_fr, |s| black_box(g1_split(s)), BatchSize::SmallInput);
        });
    }

    fn bench_g1_mul_glv(criterion: &mut Criterion) {
        criterion.bench_function("g1_mul_glv", move |bencher| {
            bencher.iter_batched(
                || (rand_g1(), rand_fr()),
                |(p, s)| black_box(g1_mul_glv(black_box(&p), black_box(s))),
                BatchSize::SmallInput,
            );
        });
    }

    fn bench_g2_endo(criterion: &mut Criterion) {
        criterion.bench_function("g2_endomorphism", move |bencher| {
            bencher.iter_batched(
                rand_g2,
                |p| black_box(g2_endomorphism(&p)),
                BatchSize::SmallInput,
            );
        });
    }

    fn bench_g2_check(criterion: &mut Criterion) {
        criterion.bench_function("g2_subgroup_check", move |bencher| {
            bencher.iter_batched(
                rand_g2,
                |p| black_box(p.is_in_correct_subgroup_assuming_on_curve()),
                BatchSize::SmallInput,
            );
        });
    }

    fn bench_g2_check_endo(criterion: &mut Criterion) {
        criterion.bench_function("g2_subgroup_check_endo", move |bencher| {
            bencher.iter_batched(
                rand_g2,
                |p| black_box(g2_subgroup_check(&p)),
                BatchSize::SmallInput,
            );
        });
    }

    fn bench_g2_mul(criterion: &mut Criterion) {
        criterion.bench_function("g2_mul", move |bencher| {
            bencher.iter_batched(
                || (rand_g2(), rand_fr()),
                |(p, s)| black_box(p.mul(black_box(s))),
                BatchSize::SmallInput,
            );
        });
    }
}
