use std::marker::PhantomData;

use halo2curves::ff::{FromUniformBytes, PrimeField};

use super::p128pow5t3::P128Pow5T3Constants;
use super::{Mds, Spec};

/// Poseidon-128 using the $x^5$ S-box, with a width of 3 field elements, and the
/// standard number of rounds for 128-bit security "with margin".
///
#[derive(Debug, Copy, Clone)]
pub struct P128Pow5T3Compact<Fp> {
    _marker: PhantomData<Fp>,
}

impl<Fp: P128Pow5T3Constants + FromUniformBytes<64> + Ord> Spec<Fp, 3, 2>
    for P128Pow5T3Compact<Fp>
{
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        Fp::partial_rounds()
    }

    fn sbox(val: Fp) -> Fp {
        // much faster than val.pow_vartime([5])
        let a = val * val;
        let b = a * a;
        b * val
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[Fp; 3]>, Mds<Fp, 3>, Mds<Fp, 3>) {
        let (mut rc, mds, inv) = (Fp::round_constants(), Fp::mds(), Fp::mds_inv());

        let first_partial = Self::full_rounds() / 2;
        let after_partials = first_partial + Self::partial_rounds();

        // Propagate the constants of each partial round into the next.
        for i in first_partial..after_partials {
            // Extract the constants rc[i][1] and rc[i][2] that do not pass through the S-box.
            // Leave the value 0 in their place.
            // rc[i][0] stays in place.
            let rc_tail = vec_remove_tail(&mut rc[i]);

            // Pass forward through the MDS matrix.
            let rc_carry = mat_mul(&mds, &rc_tail);

            // Accumulate the carried constants into the next round.
            vec_accumulate(&mut rc[i + 1], &rc_carry);
        }
        // Now constants have accumulated into the next full round.

        (rc, mds, inv)
    }
}

fn mat_mul<Fp: PrimeField, const T: usize>(mat: &Mds<Fp, T>, input: &[Fp; T]) -> [Fp; T] {
    let mut out = [Fp::ZERO; T];
    #[allow(clippy::needless_range_loop)]
    for i in 0..T {
        for j in 0..T {
            out[i] += mat[i][j] * input[j];
        }
    }
    out
}

fn vec_accumulate<Fp: PrimeField, const T: usize>(a: &mut [Fp; T], b: &[Fp; T]) {
    for i in 0..T {
        a[i] += b[i];
    }
}

fn vec_remove_tail<Fp: PrimeField, const T: usize>(a: &mut [Fp; T]) -> [Fp; T] {
    let mut tail = [Fp::ZERO; T];
    for i in 1..T {
        tail[i] = a[i];
        a[i] = Fp::ZERO;
    }
    tail
}
