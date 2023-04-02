use super::super::primitives::{Mds as MdsT, P128Pow5T3Constants};

/// This implementation can be limited to gate degree 5. However, this mode will not work with
/// blinding or inactive rows. Enable only with a prover that supports assignments to all n rows.
pub const GATE_DEGREE_5: bool = false;

/// This is the base "hashable" type requirement for septidon
pub trait CachedConstants : P128Pow5T3Constants {
    /// cached round constants
    fn cached_round_constants() -> &'static [[Self; 3]];
    /// cached mds
    fn cached_mds() -> &'static Mds<Self>;
    /// cached inversed mds
    fn cached_mds_inv() -> &'static Mds<Self>;
}


pub mod sbox {
    use super::super::util::pow_5;
    use halo2_proofs::arithmetic::FieldExt;
    use halo2_proofs::plonk::Expression;

    pub fn expr<F:FieldExt>(input: Expression<F>, round_constant: Expression<F>) -> Expression<F> {
        pow_5::expr(input + round_constant)
    }

    pub fn value<F:FieldExt>(input: F, round_constant: F) -> F {
        pow_5::value(input + round_constant)
    }
}

pub type Mds<F> = MdsT<F, 3>;

mod bn254 {
    use lazy_static::lazy_static;
    use super::{Mds, CachedConstants};
    use crate::poseidon::primitives::{P128Pow5T3Compact, Spec};
    use halo2_proofs::halo2curves::bn256::Fr as F;
    lazy_static! {
        // Cache the round constants and the MDS matrix (and unused inverse MDS matrix).
        static ref CONSTANTS: (Vec<[F; 3]>, Mds<F>, Mds<F>) =  P128Pow5T3Compact::<F>::constants();
    }

    impl CachedConstants for F {
        fn cached_round_constants() -> &'static [[Self; 3]]{
            &CONSTANTS.0
        }
        fn cached_mds() -> &'static Mds<Self>{
            &CONSTANTS.1
        }
        fn cached_mds_inv() -> &'static Mds<Self>{
            &CONSTANTS.2
        }
    }
}

pub fn round_constant<F:CachedConstants>(index: usize) -> [F; 3] {
    F::cached_round_constants()[index]
}

pub fn mds<F:CachedConstants>() -> &'static Mds<F> {
    F::cached_mds()
}
