use super::super::primitives::{Mds as MdsT, P128Pow5T3Compact, Spec};
use lazy_static::lazy_static;

/// This implementation can be limited to gate degree 5. However, this mode will not work with
/// blinding or inactive rows. Enable only with a prover that supports assignments to all n rows.
pub const GATE_DEGREE_5: bool = false;

/// This implementation supports only the scalar field of BN254 at the moment.
///
/// To implement for the Pasta curves, adjust the parameters below, and replace the transition round
/// by a copy, to get 56 rounds instead of 57.
pub use halo2_proofs::halo2curves::bn256::Fr as F;

pub mod sbox {
    use super::super::util::pow_5;
    use super::F;
    use halo2_proofs::plonk::Expression;

    pub fn expr(input: Expression<F>, round_constant: Expression<F>) -> Expression<F> {
        pow_5::expr(input + round_constant)
    }

    pub fn value(input: F, round_constant: F) -> F {
        pow_5::value(input + round_constant)
    }
}

pub type Mds = MdsT<F, 3>;

lazy_static! {
    // Cache the round constants and the MDS matrix (and unused inverse MDS matrix).
    static ref CONSTANTS: (Vec<[F; 3]>, Mds, Mds) = P128Pow5T3Compact::<F>::constants();
}

pub fn round_constant(index: usize) -> [F; 3] {
    CONSTANTS.0[index]
}

pub fn mds() -> &'static Mds {
    &CONSTANTS.1
}
