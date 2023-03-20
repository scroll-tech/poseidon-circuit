use super::params;
use super::params::{mds, round_constant};
use super::state::Cell;
use super::util::{join_values, matmul, split_values};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::halo2curves::bn256::Fr as F;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression};

#[derive(Clone, Debug)]
pub struct TransitionRoundChip {
    column: Column<Advice>,
}

impl TransitionRoundChip {
    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        signal: Expression<F>,
        next_state: [Cell; 3],
    ) -> Self {
        let chip = Self {
            column: cs.advice_column(),
        };

        cs.create_gate("transition round", |meta| {
            // The input cells are relative to the signal.
            let input = chip.input();
            let input = [
                input[0].query(meta, 0),
                input[1].query(meta, 0),
                input[2].query(meta, 0),
            ];

            let output = Self::first_partial_round_expr(&input);

            // Get the next_state from the point of view of the signal.
            let next_state = [
                next_state[0].query(meta, -3),
                next_state[1].query(meta, -3),
                next_state[2].query(meta, -3),
            ];

            let constraints = vec![
                output[0].clone() - next_state[0].clone(),
                output[1].clone() - next_state[1].clone(),
                output[2].clone() - next_state[2].clone(),
            ];

            Constraints::with_selector(signal, constraints)
        });

        chip
    }

    // Return an expression of the state after the first partial round given the state before.
    // TODO: implement with with degree <= 5 using the helper cell.
    fn first_partial_round_expr(input: &[Expression<F>; 3]) -> [Expression<F>; 3] {
        let rc = Expression::Constant(Self::round_constant());
        let sbox_out = [
            params::sbox::expr(input[0].clone(), rc),
            input[1].clone(),
            input[2].clone(),
        ];
        matmul::expr(&mds(), sbox_out)
    }

    fn round_constant() -> F {
        round_constant(4)[0]
    }

    /// Return the input cells of this round, relative to the signal.
    // TODO: rename because it is also used as final state.
    pub fn input(&self) -> [Cell; 3] {
        // The input to the transition round is vertical in the transition column.
        [
            Cell::new(self.column, -2),
            Cell::new(self.column, -1),
            Cell::new(self.column, 0),
        ]
    }

    pub fn helper_cell(&self) -> Cell {
        Cell::new(self.column, -3)
    }

    /// Assign the state of the first partial round, and return the round output.
    pub fn assign_first_partial_state(
        &self,
        region: &mut Region<'_, F>,
        middle_break_offset: usize,
        input: [Value<F>; 3],
    ) -> Result<[Value<F>; 3], Error> {
        let output = Self::first_partial_round(&input);
        for (value, cell) in input.into_iter().zip(self.input()) {
            cell.assign(region, middle_break_offset, value)?;
        }
        self.helper_cell()
            .assign(region, middle_break_offset, Value::known(F::zero()))?;
        Ok(output)
    }

    fn first_partial_round(input: &[Value<F>; 3]) -> [Value<F>; 3] {
        let sbox_out = [
            input[0].map(|f| params::sbox::value(f, Self::round_constant())),
            input[1],
            input[2],
        ];
        let output = join_values(sbox_out).map(|s| matmul::value(&mds(), s));
        split_values(output)
    }

    /// Assign the final state. This has the same layout as the first partial state, at another offset.
    pub fn assign_final_state(
        &self,
        region: &mut Region<'_, F>,
        final_break_offset: usize,
        input: [Value<F>; 3],
    ) -> Result<(), Error> {
        for (value, cell) in input.into_iter().zip(self.input()) {
            cell.assign(region, final_break_offset, value)?;
        }
        self.helper_cell()
            .assign(region, final_break_offset, Value::known(F::zero()))?;
        Ok(())
    }
}
