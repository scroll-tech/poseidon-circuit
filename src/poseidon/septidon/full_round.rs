use super::loop_chip::LoopBody;
use super::params::mds;
use super::state::{Cell, FullState, SBox};
use super::util::{join_values, matmul, query, split_values};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::halo2curves::bn256::Fr as F;
use halo2_proofs::plonk::{ConstraintSystem, Error, Expression, VirtualCells};

#[derive(Clone, Debug)]
pub struct FullRoundChip(pub FullState);

impl FullRoundChip {
    pub fn configure(cs: &mut ConstraintSystem<F>) -> (Self, LoopBody) {
        let chip = Self(FullState::configure(cs));

        let loop_body = query(cs, |meta| {
            let next_state = chip.0.map(|sbox| sbox.input.query(meta, 1));
            let output = chip.full_round_expr(meta);
            LoopBody { next_state, output }
        });

        (chip, loop_body)
    }

    fn full_round_expr(&self, meta: &mut VirtualCells<'_, F>) -> [Expression<F>; 3] {
        let sbox_out = self.0.map(|sbox: &SBox| sbox.output_expr(meta));
        matmul::expr(&mds(), sbox_out)
    }

    pub fn input_cells(&self) -> [Cell; 3] {
        self.0.map(|sbox| sbox.input.clone())
    }

    /// Assign the witness.
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        round_constants: [F; 3],
        input: [Value<F>; 3],
    ) -> Result<[Value<F>; 3], Error> {
        let mut sbox_out = [Value::unknown(); 3];
        for i in 0..3 {
            let sbox: &SBox = &self.0 .0[i];
            sbox_out[i] = sbox.assign(region, offset, round_constants[i], input[i])?;
        }
        let output = join_values(sbox_out).map(|sbox_out| matmul::value(&mds(), sbox_out));
        Ok(split_values(output))
    }
}
