use halo2_proofs::halo2curves::{group::ff::PrimeField, pasta};
pub(crate) use pasta::pallas;
pub(crate) use pasta::Fp;
pub(crate) mod fp;
pub(crate) mod test_vectors;

use super::Mds;

impl super::p128pow5t3::P128Pow5T3Constants for Fp {
    fn round_constants() -> Vec<[Self; 3]> {
        fp::ROUND_CONSTANTS.to_vec()
    }
    fn mds() -> Mds<Self, 3> {
        fp::MDS
    }
    fn mds_inv() -> Mds<Self, 3> {
        fp::MDS_INV
    }
}

fn sqrt_tonelli_shanks<F: PrimeField, S: AsRef<[u64]>>(f: &F, tm1d2: S) -> subtle::CtOption<F> {
    use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

    // w = self^((t - 1) // 2)
    let w = f.pow_vartime(tm1d2);

    let mut v = F::S;
    let mut x = w * f;
    let mut b = x * w;

    // Initialize z as the 2^S root of unity.
    let mut z = F::root_of_unity();

    for max_v in (1..=F::S).rev() {
        let mut k = 1;
        let mut tmp = b.square();
        let mut j_less_than_v: Choice = 1.into();

        for j in 2..max_v {
            let tmp_is_one = tmp.ct_eq(&F::one());
            let squared = F::conditional_select(&tmp, &z, tmp_is_one).square();
            tmp = F::conditional_select(&squared, &tmp, tmp_is_one);
            let new_z = F::conditional_select(&z, &squared, tmp_is_one);
            j_less_than_v &= !j.ct_eq(&v);
            k = u32::conditional_select(&j, &k, tmp_is_one);
            z = F::conditional_select(&z, &new_z, j_less_than_v);
        }

        let result = x * z;
        x = F::conditional_select(&result, &x, b.ct_eq(&F::one()));
        z = z.square();
        b *= z;
        v = k;
    }

    subtle::CtOption::new(
        x,
        (x * x).ct_eq(f), // Only return Some if it's the square root.
    )
}
