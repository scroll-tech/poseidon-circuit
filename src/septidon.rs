//! An implementation using septuple rounds.
//! See: src/README.md

mod control;
mod full_round;
mod instruction;
mod loop_chip;
mod params;
mod septidon_chip;
mod septuple_round;
mod state;
#[cfg(test)]
mod tests;
mod transition_round;
mod util;

pub use septidon_chip::SeptidonChip;
