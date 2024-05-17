use crate::primitives::{Mds as MdsT, P128Pow5T3Constants};

pub type Mds<F> = MdsT<F, 3>;

/// This is the base "hashable" type requirement for septidon
pub trait CachedConstants: P128Pow5T3Constants {
    /// cached round constants
    fn cached_round_constants() -> &'static [[Self; 3]];
    /// cached mds
    fn cached_mds() -> &'static Mds<Self>;
    /// cached inversed mds
    fn cached_mds_inv() -> &'static Mds<Self>;
}

mod bn254 {
    use super::{CachedConstants, Mds};
    use crate::hash::HashSpec;
    use crate::primitives::{CachedSpec, P128Pow5T3Compact, Spec};
    use ::halo2curves::bn256::Fr as F;
    use lazy_static::lazy_static;
    lazy_static! {
        // Cache the round constants and the MDS matrix (and unused inverse MDS matrix).
        static ref CONSTANTS: (Vec<[F; 3]>, Mds<F>, Mds<F>) =  P128Pow5T3Compact::<F>::constants();
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
    }

    impl CachedSpec<F, 3, 2> for HashSpec<F> {
        fn cached_round_constants() -> &'static [[F; 3]] {
            &CONSTANTS.0
        }
        fn cached_mds() -> &'static Mds<F> {
            &CONSTANTS.1
        }
        fn cached_mds_inv() -> &'static Mds<F> {
            &CONSTANTS.2
        }
    }
}

pub fn round_constant<F: CachedConstants>(index: usize) -> [F; 3] {
    F::cached_round_constants()[index]
}

pub fn mds<F: CachedConstants>() -> &'static Mds<F> {
    F::cached_mds()
}
