use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::halo2curves::bn256::Fr as F;
use halo2_proofs::plonk::{ConstraintSystem, Error};

use super::control::ControlChip;
use super::full_round::FullRoundChip;
use super::loop_chip::LoopChip;
use super::params::round_constant;
use super::septuple_round::SeptupleRoundChip;
use super::state::Cell;
use super::transition_round::TransitionRoundChip;
use super::util::map_array;

/// The configuration of the permutation chip.
///
/// ```
/// use halo2_proofs::halo2curves::bn256::Fr as F;
/// use halo2_proofs::plonk::ConstraintSystem;
/// use poseidon_circuit::poseidon::SeptidonChip;
///
/// let mut cs = ConstraintSystem::<F>::default();
/// let config = SeptidonChip::configure(&mut cs);
/// ```
#[derive(Clone, Debug)]
pub struct SeptidonChip {
    control_chip: ControlChip,

    transition_chip: TransitionRoundChip,

    full_round_chip: FullRoundChip,

    partial_round_chip: SeptupleRoundChip,
}

impl SeptidonChip {
    /// Create a new chip.
    pub fn configure(cs: &mut ConstraintSystem<F>) -> Self {
        let (control_chip, signals) = ControlChip::configure(cs);
        let q = || signals.selector.clone();

        let (full_round_chip, full_round_loop_body) = FullRoundChip::configure(cs);

        let (partial_round_chip, partial_round_loop_body) = SeptupleRoundChip::configure(cs, q());

        let transition_chip = {
            // The output of the transition round is the input of the partial rounds loop.
            let output = partial_round_chip.input();
            TransitionRoundChip::configure(cs, signals.transition_round, output)
        };

        {
            // The output of full rounds go into the transition round.
            let output = transition_chip.input();

            LoopChip::configure(
                cs,
                q(),
                full_round_loop_body,
                signals.break_full_rounds,
                output,
            )
        };

        {
            // The output of partial rounds go horizontally into the second loop of full rounds,
            // which runs parallel to the last 4 partials rounds (indexed [-3; 0]).
            let full_round_sboxes = &full_round_chip.0 .0;
            let output: [Cell; 3] = [
                full_round_sboxes[0].input.rotated(-3),
                full_round_sboxes[1].input.rotated(-3),
                full_round_sboxes[2].input.rotated(-3),
            ];

            LoopChip::configure(
                cs,
                q(),
                partial_round_loop_body,
                signals.break_partial_rounds,
                output,
            )
        };

        let chip = Self {
            control_chip,
            transition_chip,
            full_round_chip,
            partial_round_chip,
        };

        chip
    }

    /// How many rows are used per permutation.
    pub fn height_per_permutation() -> usize {
        8
    }

    fn final_offset() -> usize {
        Self::height_per_permutation() - 1
    }

    /// Return the cells containing the initial state. The parent chip must constrain these cells.
    /// Cells are relative to the row 0 of a region of a permutation.
    pub fn initial_state_cells(&self) -> [Cell; 3] {
        self.full_round_chip.input_cells()
    }

    /// Return the cells containing the final state. The parent chip must constrain these cells.
    /// Cells are relative to the row 0 of a region of a permutation.
    pub fn final_state_cells(&self) -> [Cell; 3] {
        let relative_cells = self.transition_chip.input();
        map_array(&relative_cells, |cell| {
            cell.rotated(Self::final_offset() as i32)
        })
    }

    /// Assign the witness of a permutation into the given region.
    pub fn assign_permutation(
        &self,
        region: &mut Region<'_, F>,
        initial_state: [Value<F>; 3],
    ) -> Result<[Value<F>; 3], Error> {
        self.control_chip.assign(region)?;

        let mut state = initial_state;

        // First half of full rounds.
        for offset in 0..4 {
            state = self
                .full_round_chip
                .assign(region, offset, round_constant(offset), state)?;
        }

        // First partial round.
        // Its round constant is part of the gate (not a fixed column).
        let middle_offset = 3;
        state = self
            .transition_chip
            .assign_first_partial_state(region, middle_offset, state)?;

        // The rest of partial rounds.
        for offset in 0..8 {
            let round_index = 5 + offset * 7;
            let round_constants = (round_index..round_index + 7)
                .map(|idx| round_constant(idx)[0])
                .collect::<Vec<_>>();
            state = self
                .partial_round_chip
                .assign(region, offset, &round_constants, state)?;
        }

        // The second half of full rounds.
        for offset in 4..8 {
            state =
                self.full_round_chip
                    .assign(region, offset, round_constant(offset + 57), state)?;
        }

        // Put the final state into its place.
        let final_offset = 7;
        self.transition_chip
            .assign_final_state(region, final_offset, state)?;

        Ok(state)
    }
}
