use super::super::{PermuteChip, PoseidonInstructions, StateWord, Var};
use super::{util::map_array, SeptidonChip};
use ff::PrimeField;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::{
    circuit::{Chip, Layouter},
    plonk::{ConstraintSystem, Error},
};
use poseidon_base::{
    params::CachedConstants,
    primitives::{Spec, State},
};

const WIDTH: usize = 3;
const RATE: usize = 2;

impl<F: CachedConstants, S: Spec<F, WIDTH, RATE>> PermuteChip<F, S, WIDTH, RATE> for SeptidonChip {
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

impl<F: CachedConstants, S: Spec<F, WIDTH, RATE>> PoseidonInstructions<F, S, WIDTH, RATE>
    for SeptidonChip
{
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
                        || format!("load state_{i}"),
                        region,
                        chip_input[i].column,
                        chip_input[i].offset as usize,
                    )?;
                }

                // Assign the internal witness of the permutation.
                let initial_values = map_array(initial_state, |word| word.value());
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

    fn permute_batch(
        &self,
        layouter: &mut impl Layouter<F>,
        initial_states: &[State<Self::Word, WIDTH>],
    ) -> Result<Vec<State<Self::Word, WIDTH>>, Error> {
        let chunks_count = std::thread::available_parallelism()
            .map(|e| e.get())
            .unwrap_or(32);
        let chunks_len = initial_states.len() / chunks_count + 2;

        let assignments = initial_states
            .chunks(chunks_len)
            .map(|initial_states| {
                let mut is_first_pass = true;
                move |mut region: Region<'_, F>| -> Result<Vec<State<Self::Word, WIDTH>>, Error> {
                    let region = &mut region;
                    let mut final_states = vec![];
                    let mut last_offset = 0;

                    if is_first_pass {
                        is_first_pass = false;
                        let col = self.final_state_cells().first().unwrap().column;
                        region.assign_advice(
                            || "First pass dummy assign",
                            col,
                            initial_states.len() * 8 - 1,
                            || Value::known(F::ZERO),
                        )?;
                        return Ok(final_states);
                    }

                    for initial_state in initial_states.iter() {
                        // Copy the given initial_state into the permutation chip.
                        let chip_input = self.initial_state_cells();
                        for i in 0..WIDTH {
                            initial_state[i].0.copy_advice(
                                || format!("load state_{i}"),
                                region,
                                chip_input[i].column,
                                last_offset + chip_input[i].offset as usize,
                            )?;
                        }

                        // Assign the internal witness of the permutation.
                        let initial_values = map_array(initial_state, |word| word.value());
                        let final_values = self.assign_permutation_with_offset(
                            region,
                            initial_values,
                            last_offset,
                        )?;

                        // Return the cells containing the final state.
                        let chip_output = self.final_state_cells();
                        let final_state: Vec<StateWord<F>> = (0..WIDTH)
                            .map(|i| {
                                region
                                    .assign_advice(
                                        || format!("output {i}"),
                                        chip_output[i].column,
                                        last_offset + chip_output[i].offset as usize,
                                        || final_values[i],
                                    )
                                    .map(StateWord)
                            })
                            .collect::<Result<Vec<_>, _>>()?;

                        last_offset += 8;
                        final_states.push(final_state.try_into().unwrap());
                    }
                    Ok(final_states)
                }
            })
            .collect::<Vec<_>>();
        layouter
            .assign_regions(|| "permute state", assignments)
            .map(|e| e.into_iter().flatten().collect::<Vec<_>>())
    }
}

impl<F: PrimeField> Chip<F> for SeptidonChip {
    type Config = Self;

    type Loaded = ();

    fn config(&self) -> &Self::Config {
        self
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
