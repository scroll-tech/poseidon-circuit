use super::state::Cell;
use super::util::select;

use ff::PrimeField;
use halo2_proofs::plonk::{ConstraintSystem, Constraints, Expression};

#[derive(Clone, Debug)]
pub struct LoopChip {}

pub struct LoopBody<F> {
    pub next_state: [Expression<F>; 3],
    /// Cells where the output is, relative to the break signal.
    pub output: [Expression<F>; 3],
}

impl LoopChip {
    pub fn configure<F: PrimeField>(
        cs: &mut ConstraintSystem<F>,
        q: Expression<F>,
        body: LoopBody<F>,
        break_signal: Expression<F>,
        output: [Cell; 3],
    ) -> Self {
        cs.create_gate("loop", |meta| {
            let constraints = (0..3)
                .map(|i| {
                    let destination = select::expr(
                        break_signal.clone(),
                        output[i].query(meta, 0),
                        body.next_state[i].clone(),
                    );

                    destination - body.output[i].clone()
                })
                .collect::<Vec<_>>();

            Constraints::with_selector(q, constraints)
        });

        Self {}
    }
}
