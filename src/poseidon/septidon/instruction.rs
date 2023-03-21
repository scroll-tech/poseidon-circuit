use super::super::{
    primitives::{Spec, State},
    PermuteChip, PoseidonInstructions, StateWord, Var,
};
use super::{params::F, util::map_array, SeptidonChip};
use halo2_proofs::{
    circuit::{Chip, Layouter},
    plonk::{ConstraintSystem, Error},
};

const WIDTH: usize = 3;
const RATE: usize = 2;

impl PermuteChip<F> for SeptidonChip {
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let chip = Self::configure(meta);

        // Enable equality on the input/output columns, required by the function permute.
        for cell in chip.initial_state_cells() {
            meta.enable_equality(cell.column);
        }
        for cell in chip.final_state_cells() {
            meta.enable_equality(cell.column);
        }

        chip
    }

    fn construct(config: Self::Config) -> Self {
        config
    }
}

impl<S: Spec<F, WIDTH, RATE>> PoseidonInstructions<F, S, WIDTH, RATE> for SeptidonChip {
    type Word = StateWord<F>;

    fn permute(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_state: &State<Self::Word, WIDTH>,
    ) -> Result<State<Self::Word, WIDTH>, Error> {
        layouter.assign_region(
            || "permute state",
            |mut region| {
                let region = &mut region;

                // Copy the given initial_state into the permutation chip.
                let chip_input = self.initial_state_cells();
                for i in 0..WIDTH {
                    initial_state[i].0.copy_advice(
                        || format!("load state_{}", i),
                        region,
                        chip_input[i].column,
                        chip_input[i].offset as usize,
                    )?;
                }

                // Assign the internal witness of the permutation.
                let initial_values = map_array(&initial_state, |word| word.value());
                let final_values = self.assign_permutation(region, initial_values)?;

                // Return the cells containing the final state.
                let chip_output = self.final_state_cells();
                let final_state: Vec<StateWord<F>> = (0..WIDTH)
                    .map(|i| {
                        region
                            .assign_advice(
                                || format!("output {i}"),
                                chip_output[i].column,
                                chip_output[i].offset as usize,
                                || final_values[i],
                            )
                            .map(StateWord)
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                Ok(final_state.try_into().unwrap())
            },
        )
    }
}

impl Chip<F> for SeptidonChip {
    type Config = Self;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        self
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
