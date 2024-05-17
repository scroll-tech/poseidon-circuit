/// This implementation can be limited to gate degree 5. However, this mode will not work with
/// blinding or inactive rows. Enable only with a prover that supports assignments to all n rows.
pub const GATE_DEGREE_5: bool = false;

pub mod sbox {
    use super::super::util::pow_5;

    use ff::PrimeField;
    use halo2_proofs::plonk::Expression;

    pub fn expr<F: PrimeField>(
        input: Expression<F>,
        round_constant: Expression<F>,
    ) -> Expression<F> {
        pow_5::expr(input + round_constant)
    }

    pub fn value<F: PrimeField>(input: F, round_constant: F) -> F {
        pow_5::value(input + round_constant)
    }
}

pub use poseidon_base::params::*;
