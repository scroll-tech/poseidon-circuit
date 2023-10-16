use super::params::GATE_DEGREE_5;
use super::util::query;

use ff::PrimeField;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;

#[derive(Clone, Debug)]
pub struct ControlChip {
    is_last: Column<Fixed>,
}

pub struct ControlSignals<F: PrimeField> {
    // Signals that control the switches between steps of the permutation.
    pub break_full_rounds: Expression<F>,
    pub transition_round: Expression<F>,
    pub break_partial_rounds: Expression<F>,

    // A selector that can disable all chips on all rows.
    pub selector: Expression<F>,
}

impl ControlChip {
    pub fn configure<F: PrimeField>(cs: &mut ConstraintSystem<F>) -> (Self, ControlSignals<F>) {
        let is_last = cs.fixed_column();

        let signals = query(cs, |meta| {
            let signal_middle = meta.query_fixed(is_last, Rotation(4)); // Seen from the middle row.
            let signal_last = meta.query_fixed(is_last, Rotation::cur());
            let middle_or_last = signal_middle.clone() + signal_last.clone(); // Assume no overlap.

            ControlSignals {
                break_full_rounds: middle_or_last,
                transition_round: signal_middle,
                break_partial_rounds: signal_last,
                selector: Self::derive_selector(is_last, meta),
            }
        });

        let chip = Self { is_last };
        (chip, signals)
    }

    /// Assign the fixed positions of the last row of permutations for a new region.
    pub fn assign<F: PrimeField>(&self, region: &mut Region<'_, F>) -> Result<(), Error> {
        self.assign_with_offset(region, 0)
    }

    /// Assign the fixed positions of the last row of permutations.
    pub fn assign_with_offset<F: PrimeField>(
        &self,
        region: &mut Region<'_, F>,
        begin_offset: usize,
    ) -> Result<(), Error> {
        region.assign_fixed(
            || "",
            self.is_last,
            7 + begin_offset,
            || Value::known(F::ONE),
        )?;
        Ok(())
    }

    fn derive_selector<F: PrimeField>(
        is_last: Column<Fixed>,
        meta: &mut VirtualCells<'_, F>,
    ) -> Expression<F> {
        if GATE_DEGREE_5 {
            // Variant with no selector. Do not disable gates, do not increase the gate degree.
            Expression::Constant(F::ONE)
        } else {
            // Variant with a selector enabled on all rows of valid permutations.
            // Detect is_last=1, seen from its own row or up to 7 rows below.
            (0..8_i32)
                .map(|i| meta.query_fixed(is_last, Rotation(i)))
                .reduce(|acc, x| acc + x)
                .unwrap() // Boolean any.
        }
    }
}
