use super::params;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::halo2curves::bn256::Fr as F;
use halo2_proofs::plonk::{
    Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells,
};
use halo2_proofs::poly::Rotation;

/// Cell remembers the relative position of a cell in the region of a permutation.
/// It can be used in configuration and synthesis.
#[derive(Clone, Debug)]
pub struct Cell {
    pub column: Column<Advice>,
    /// An offset relative to the owner of this Cell.
    pub offset: i32,
}

impl Cell {
    pub fn configure(cs: &mut ConstraintSystem<F>) -> Self {
        Cell {
            column: cs.advice_column(),
            offset: 0,
        }
    }

    pub fn new(column: Column<Advice>, offset: i32) -> Self {
        Self { column, offset }
    }

    pub fn rotated(&self, offset: i32) -> Self {
        Self {
            column: self.column,
            offset: self.offset + offset,
        }
    }

    pub fn query(&self, meta: &mut VirtualCells<F>, offset: i32) -> Expression<F> {
        meta.query_advice(self.column, Rotation(self.offset + offset))
    }

    pub fn region_offset(&self) -> usize {
        assert!(self.offset >= 0);
        self.offset as usize
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        origin_offset: usize,
        input: Value<F>,
    ) -> Result<(), Error> {
        let offset = origin_offset as i32 + self.offset;
        assert!(offset >= 0, "cannot assign to a cell outside of its region");
        region.assign_advice(|| "cell", self.column, offset as usize, || input)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SBox {
    pub input: Cell,
    round_constant: Column<Fixed>,
}

impl SBox {
    pub fn configure(cs: &mut ConstraintSystem<F>) -> Self {
        SBox {
            input: Cell::configure(cs),
            round_constant: cs.fixed_column(),
        }
    }

    /// Assign the witness of the input.
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        round_constant: F,
        input: Value<F>,
    ) -> Result<Value<F>, Error> {
        region.assign_fixed(
            || "round_constant",
            self.round_constant,
            offset + self.input.region_offset(),
            || Value::known(round_constant),
        )?;
        region.assign_advice(
            || "initial_state",
            self.input.column,
            offset + self.input.region_offset(),
            || input,
        )?;
        let output = input.map(|i| params::sbox::value(i, round_constant));
        Ok(output)
    }

    pub fn input_expr(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        self.input.query(meta, 0)
    }

    pub fn rc_expr(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        meta.query_fixed(self.round_constant, Rotation(self.input.offset))
    }

    pub fn output_expr(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        let input = self.input_expr(meta);
        let round_constant = self.rc_expr(meta);
        params::sbox::expr(input, round_constant)
    }
}

#[derive(Clone, Debug)]
pub struct FullState(pub [SBox; 3]);

impl FullState {
    pub fn configure(cs: &mut ConstraintSystem<F>) -> Self {
        Self([
            SBox::configure(cs),
            SBox::configure(cs),
            SBox::configure(cs),
        ])
    }

    pub fn map<T, F>(&self, mut f: F) -> [T; 3]
    where
        F: FnMut(&SBox) -> T,
    {
        let a = f(&self.0[0]);
        let b = f(&self.0[1]);
        let c = f(&self.0[2]);
        [a, b, c]
    }
}
