use halo2_proofs::circuit::{Layouter, Region, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr as F;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

use super::{util::join_values, SeptidonChip};

#[test]
fn septidon_permutation() {
    let k = 5;
    let inactive_rows = 6; // Assume default in this test.

    let circuit = TestCircuit {
        height: (1 << k) - inactive_rows,
    };
    let prover = MockProver::run(k as u32, &circuit, vec![]).unwrap();
    prover.verify_at_rows(0..1, 0..0).unwrap();
}

#[derive(Clone)]
struct TestCircuit {
    height: usize,
}

impl Circuit<F> for TestCircuit {
    type Config = SeptidonChip;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        SeptidonChip::configure(cs)
    }

    fn synthesize(
        &self,
        config: SeptidonChip,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let num_permutations = self.height / 8;

        for _ in 0..num_permutations {
            let initial_state = [
                Value::known(F::from(0)),
                Value::known(F::from(1)),
                Value::known(F::from(2)),
            ];

            let final_state = layouter.assign_region(
                || "SeptidonChip",
                |mut region: Region<'_, F>| config.assign_permutation(&mut region, initial_state),
            )?;

            let got = format!("{:?}", join_values(final_state).inner.unwrap());

            // For input 0,1,2.
            let expect = "[0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a, 0x0fca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29, 0x0e7ae82e40091e63cbd4f16a6d16310b3729d4b6e138fcf54110e2867045a30c]";
            assert_eq!(got, expect);
        }

        Ok(())
    }
}
