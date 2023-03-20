use super::loop_chip::LoopBody;
use super::params::mds;
use super::state::{Cell, SBox};
use super::util::{join_values, matmul, query, split_values};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::halo2curves::bn256::Fr as F;
use halo2_proofs::plonk::{ConstraintSystem, Constraints, Error, Expression, VirtualCells};

#[derive(Clone, Debug)]
pub struct SeptupleRoundChip {
    first_sbox: SBox,
    first_linears: [Cell; 2],
    following_sboxes: [SBox; 6],
}

impl SeptupleRoundChip {
    pub fn configure(cs: &mut ConstraintSystem<F>, q: Expression<F>) -> (Self, LoopBody) {
        let chip = Self {
            first_sbox: SBox::configure(cs),
            first_linears: [Cell::configure(cs), Cell::configure(cs)],
            following_sboxes: (0..6)
                .map(|_| SBox::configure(cs))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        };

        let input = chip.input();
        let (input_state, next_state) = query(cs, |meta| {
            (
                [
                    input[0].query(meta, 0), // Not read directly but via first_sbox.output_expr.
                    input[1].query(meta, 0),
                    input[2].query(meta, 0),
                ],
                [
                    input[0].query(meta, 1),
                    input[1].query(meta, 1),
                    input[2].query(meta, 1),
                ],
            )
        });

        let output = {
            // The input state is constrained by another chip (TransitionRoundChip).
            let mut checked_sbox = &chip.first_sbox;
            let mut state = input_state;

            cs.create_gate("septuple_round", |meta| {
                let mut constraints = vec![];

                for sbox_to_check in &chip.following_sboxes {
                    // Calculate the expression of the next state.
                    state = Self::partial_round_expr(meta, checked_sbox, &state);

                    // Compare the high-degree expression of the state with the equivalent witness.
                    let witness = sbox_to_check.input_expr(meta);
                    constraints.push(state[0].clone() - witness.clone());
                    // We validated the S-Box input, so we can use next_sbox.output_expr.
                    checked_sbox = sbox_to_check;
                }

                // Output the last round as an expression.
                state = Self::partial_round_expr(meta, checked_sbox, &state);

                Constraints::with_selector(q, constraints)
            });
            state
        };

        let loop_body = LoopBody { next_state, output };

        (chip, loop_body)
    }

    fn partial_round_expr(
        meta: &mut VirtualCells<'_, F>,
        sbox: &SBox,
        input: &[Expression<F>; 3],
    ) -> [Expression<F>; 3] {
        let sbox_out = [sbox.output_expr(meta), input[1].clone(), input[2].clone()];
        matmul::expr(&mds(), sbox_out)
    }

    pub fn input(&self) -> [Cell; 3] {
        [
            self.first_sbox.input.clone(),
            self.first_linears[0].clone(),
            self.first_linears[1].clone(),
        ]
    }

    /// Assign the witness.
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        round_constants: &[F],
        input: [Value<F>; 3],
    ) -> Result<[Value<F>; 3], Error> {
        // Assign the first non-S-Box cells.
        for i in 0..2 {
            self.first_linears[i].assign(region, offset, input[1 + i])?;
        }

        let mut state = input;
        let mut assign_partial_round = |i: usize, sbox: &SBox| -> Result<(), Error> {
            // Assign the following S-Boxes.
            state[0] = sbox.assign(region, offset, round_constants[i], state[0])?;
            // Apply the matrix.
            state = split_values(join_values(state).map(|s| matmul::value(&mds(), s)));
            Ok(())
        };

        assign_partial_round(0, &self.first_sbox)?;

        for (i, sbox) in self.following_sboxes.iter().enumerate() {
            assign_partial_round(1 + i, sbox)?;
        }

        Ok(state)
    }
}
