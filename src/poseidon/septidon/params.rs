use super::super::primitives::{Mds as MdsT, P128Pow5T3Constants};

/// This implementation can be limited to gate degree 5. However, this mode will not work with
/// blinding or inactive rows. Enable only with a prover that supports assignments to all n rows.
pub const GATE_DEGREE_5: bool = false;

/// This is the base "hashable" type requirement for septidon
pub trait CachedConstants: P128Pow5T3Constants {
    /// cached round constants
    fn cached_round_constants() -> &'static [[Self; 3]];
    /// cached mds
    fn cached_mds() -> &'static Mds<Self>;
    /// cached inversed mds
    fn cached_mds_inv() -> &'static Mds<Self>;
    /// cached pow5 calc result
    fn cached_pow5(self) -> (Self, Option<Self>) {
        (self, None)
    }
    /// cached muladd calc result
    fn cached_muladd(vector: [Self; 3]) -> ([Self; 3], Option<[Self; 3]>) {
        (vector, None)
    }
}

/// Wrap Fr as Hash key
#[derive(Eq, PartialEq, Debug, Hash)]
pub struct KeyConstant<T: CachedConstants>(T);

pub mod calc {
    use super::CachedConstants;
    use halo2_proofs::plonk::Expression;

    pub mod sbox {
        use super::super::super::util::pow_5;
        use super::*;
        pub fn expr<F: CachedConstants>(
            input: Expression<F>,
            round_constant: Expression<F>,
        ) -> Expression<F> {
            pow_5::expr(input + round_constant)
        }

        pub fn value<F: CachedConstants>(input: F, round_constant: F) -> F {
            let val_added = input + round_constant;
            let (val_added, ret) = val_added.cached_pow5();
            ret.unwrap_or_else(|| pow_5::value(val_added))
        }
    }

    pub mod matmul {
        use super::super::super::util::matmul;
        use super::*;

        /// Multiply a vector of expressions by a constant matrix.
        pub fn expr<F: CachedConstants>(vector: [Expression<F>; 3]) -> [Expression<F>; 3] {
            matmul::expr(F::cached_mds(), vector)
        }

        /// Multiply a vector of values by a constant matrix.
        pub fn value<F: CachedConstants>(vector: [F; 3]) -> [F; 3] {
            let (vector, ret) = F::cached_muladd(vector);
            ret.unwrap_or_else(|| matmul::value(F::cached_mds(), vector))
        }
    }
}

pub type Mds<F> = MdsT<F, 3>;

mod bn254 {
    use super::super::util::{matmul, pow_5};
    use super::*;
    use crate::poseidon::primitives::{P128Pow5T3Compact, Spec};
    use halo2_proofs::halo2curves::bn256::Fr as F;
    use lazy_static::lazy_static;
    use std::iter;

    type Pow5CacheMap = std::collections::HashMap<KeyConstant<F>, F>;
    type MulAddCacheMap = std::collections::HashMap<[KeyConstant<F>; 3], [F; 3]>;

    lazy_static! {
        // Cache the round constants and the MDS matrix (and unused inverse MDS matrix).
        static ref CONSTANTS: (Vec<[F; 3]>, Mds<F>, Mds<F>) =  P128Pow5T3Compact::<F>::constants();
        pub static ref POW5_CONSTANTS: Pow5CacheMap =  {

            let r_f = P128Pow5T3Compact::<F>::full_rounds() / 2;
            let r_p = P128Pow5T3Compact::<F>::partial_rounds();
            let mds = &CONSTANTS.1;

            let full_round = |ret: &mut Pow5CacheMap, state: &mut [F; 3], rcs: &[F; 3]| {
                for (word, rc) in state.iter_mut().zip(rcs.iter()) {
                    let key = KeyConstant(*word + rc);
                    *word = pow_5::value(*word + rc);
                    ret.insert(key, *word);
                }
                *state = matmul::value(mds, *state);
            };

            let part_round = |ret: &mut Pow5CacheMap, state: &mut [F; 3], rcs: &[F; 3]| {
                // In a partial round, the S-box is only applied to the first state word.
                // and the compact constants has only first rc is not zero
                let key = KeyConstant(state[0]+rcs[0]);
                state[0] = pow_5::value(state[0]+rcs[0]);
                ret.insert(key, state[0]);
                *state = matmul::value(mds, *state);
            };

            let (ret, _) = iter::empty()
            .chain(iter::repeat(&full_round as &dyn Fn(&mut Pow5CacheMap, &mut [F; 3], &[F; 3])).take(r_f))
            .chain(iter::repeat(&part_round as &dyn Fn(&mut Pow5CacheMap, &mut [F; 3], &[F; 3])).take(r_p))
            .chain(iter::repeat(&full_round as &dyn Fn(&mut Pow5CacheMap, &mut [F; 3], &[F; 3])).take(r_f))
            .zip(CONSTANTS.0.iter())
            .fold((Pow5CacheMap::new(), [F::zero();3]), |(mut ret, mut state), (round, rcs)| {
                round(&mut ret, &mut state, rcs);
                (ret, state)
            });

            //let mut t_state = [F::zero(); 3];
            //crate::poseidon::primitives::permute::<F, P128Pow5T3Compact<F>, 3, 2>(&mut t_state, mds, &CONSTANTS.0);
            //assert_eq!(t_state, state);
            ret
        };
        static ref MULADD_CONSTANTS: MulAddCacheMap =  {
            let r_f = P128Pow5T3Compact::<F>::full_rounds() / 2;
            let r_p = P128Pow5T3Compact::<F>::partial_rounds();
            let mds = &CONSTANTS.1;

            let full_round = |ret: &mut MulAddCacheMap, state: &mut [F; 3], rcs: &[F; 3]| {
                for (word, rc) in state.iter_mut().zip(rcs.iter()) {
                    *word = pow_5::value(*word + rc);
                }
                let key = state.map(KeyConstant);
                *state = matmul::value(mds, *state);
                ret.insert(key, *state);
            };

            let part_round = |ret: &mut MulAddCacheMap, state: &mut [F; 3], rcs: &[F; 3]| {
                // In a partial round, the S-box is only applied to the first state word.
                // and the compact constants has only first rc is not zero
                state[0] = pow_5::value(state[0]+rcs[0]);
                let key = state.map(KeyConstant);
                *state = matmul::value(mds, *state);
                ret.insert(key, *state);
            };

            let (ret, _) = iter::empty()
            .chain(iter::repeat(&full_round as &dyn Fn(&mut MulAddCacheMap, &mut [F; 3], &[F; 3])).take(r_f))
            .chain(iter::repeat(&part_round as &dyn Fn(&mut MulAddCacheMap, &mut [F; 3], &[F; 3])).take(r_p))
            .chain(iter::repeat(&full_round as &dyn Fn(&mut MulAddCacheMap, &mut [F; 3], &[F; 3])).take(r_f))
            .zip(CONSTANTS.0.iter())
            .fold((MulAddCacheMap::new(), [F::zero();3]), |(mut ret, mut state), (round, rcs)| {
                round(&mut ret, &mut state, rcs);
                (ret, state)
            });

            ret
        };

    }

    impl CachedConstants for F {
        fn cached_round_constants() -> &'static [[Self; 3]] {
            &CONSTANTS.0
        }
        fn cached_mds() -> &'static Mds<Self> {
            &CONSTANTS.1
        }
        fn cached_mds_inv() -> &'static Mds<Self> {
            &CONSTANTS.2
        }
        #[cfg(feature = "cached")]
        fn cached_pow5(self) -> (Self, Option<Self>) {
            let key = KeyConstant(self);
            let ret = POW5_CONSTANTS.get(&key).copied();
            (key.0, ret)
        }
        #[cfg(feature = "cached")]
        fn cached_muladd(vector: [Self; 3]) -> ([Self; 3], Option<[Self; 3]>) {
            let key = vector.map(KeyConstant);
            let ret = MULADD_CONSTANTS.get(&key).copied();
            (key.map(|k| k.0), ret)
        }
    }
}

pub fn round_constant<F: CachedConstants>(index: usize) -> [F; 3] {
    F::cached_round_constants()[index]
}

pub fn mds<F: CachedConstants>() -> &'static Mds<F> {
    F::cached_mds()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        println!(
            "{:?},{:?}",
            bn254::POW5_CONSTANTS.keys(),
            bn254::POW5_CONSTANTS.values()
        );
    }
}
