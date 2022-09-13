//! The hash circuit base on poseidon.

use crate::poseidon::primitives::{ConstantLengthIden3, Hash, P128Pow5T3, Spec};
use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::{arithmetic::FieldExt, circuit::Chip};

trait PoseidonChip<Fp: FieldExt>: Chip<Fp> {
    fn construct(config: &Self::Config) -> Self;
}

/// indicate an field can be hashed in merkle tree (2 Fields to 1 Field)
pub trait Hashable: FieldExt {
    /// the spec type used in circuit for this hashable field
    type SpecType: Spec<Self, 3, 2>;
    /// execute hash for any sequence of fields
    fn hash(inp: [Self; 2]) -> Self;
    /// obtain the rows consumed by each circuit block
    fn hash_block_size() -> usize {
        1 + Self::SpecType::full_rounds() + (Self::SpecType::partial_rounds() + 1) / 2
    }
}

type Poseidon = Hash<Fr, P128Pow5T3<Fr>, ConstantLengthIden3<2>, 3, 2>;

impl Hashable for Fr {
    type SpecType = P128Pow5T3<Self>;
    fn hash(inp: [Self; 2]) -> Self {
        Poseidon::init().hash(inp)
    }
}

use crate::poseidon::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord, Var};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed},
};

/// The config for hash circuit
#[derive(Clone, Debug)]
pub struct HashConfig<Fp: FieldExt> {
    permute_config: Pow5Config<Fp, 3, 2>,
    hash_table: [Column<Advice>; 3],
    constants: [Column<Fixed>; 6],
}

impl<Fp: FieldExt> HashConfig<Fp> {
    pub(crate) fn commitment_index(&self) -> [usize; 3] {
        self.hash_table.map(|col| col.index())
    }
}

/// Hash circuit
#[derive(Clone, Default)]
pub struct HashCircuit<Fp> {
    /// the records in circuits
    pub calcs: usize,
    /// the input messages for hashes
    pub inputs: Vec<[Fp; 2]>,
    /// the expected hash output for checking
    pub checks: Vec<Option<Fp>>,
}

impl<'d, Fp: Copy> HashCircuit<Fp> {
    /// create circuit from traces
    pub fn new(calcs: usize, src: &[&'d (Fp, Fp, Fp)]) -> Self {
        let inputs: Vec<_> = src.iter().take(calcs).map(|(a, b, _)| [*a, *b]).collect();

        let checks: Vec<_> = src
            .iter()
            .take(calcs)
            .map(|(_, _, c)| Some(*c))
            .chain([None])
            .collect();

        Self {
            calcs,
            inputs,
            checks,
        }
    }
}

impl<Fp: Hashable> Circuit<Fp> for HashCircuit<Fp> {
    type Config = HashConfig<Fp>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            calcs: self.calcs,
            ..Default::default()
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state = [0; 3].map(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let constants = [0; 6].map(|_| meta.fixed_column());

        let hash_table = [0; 3].map(|_| meta.advice_column());
        for col in hash_table {
            meta.enable_equality(col);
        }
        meta.enable_equality(constants[0]);

        HashConfig {
            permute_config: Pow5Chip::configure::<Fp::SpecType>(
                meta,
                state,
                partial_sbox,
                constants[..3].try_into().unwrap(), //rc_a
                constants[3..].try_into().unwrap(), //rc_b
            ),
            hash_table,
            constants,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let constant_cells = layouter.assign_region(
            || "constant heading",
            |mut region| {
                let c0 = region.assign_fixed(
                    || "constant zero",
                    config.constants[0],
                    0,
                    || Ok(Fp::zero()),
                )?;

                Ok([StateWord::from(c0)])
            },
        )?;

        let zero_cell = &constant_cells[0];

        let (states, hashes) = layouter.assign_region(
            || "hash table",
            |mut region| {
                let mut states = Vec::new();
                let mut hashes = Vec::new();

                let dummy_input: [Option<&[Fp; 2]>; 1] = [None];
                let dummy_check: [Option<&Fp>; 1] = [None];
                let inputs_i = self
                    .inputs
                    .iter()
                    .map(Some)
                    .chain(dummy_input.into_iter().cycle())
                    .take(self.calcs);
                let checks_i = self
                    .checks
                    .iter()
                    .map(|i| i.as_ref())
                    .chain(dummy_check.into_iter().cycle())
                    .take(self.calcs);

                // notice our hash table has a (0, 0, 0) at the beginning
                for col in config.hash_table {
                    region.assign_advice(|| "dummy inputs", col, 0, || Ok(Fp::zero()))?;
                }

                for (i, (inp, check)) in inputs_i.zip(checks_i).enumerate() {
                    let inp = inp
                        .map(|[a, b]| [*a, *b])
                        .unwrap_or_else(|| [Fp::zero(), Fp::zero()]);
                    let offset = i + 1;

                    let c1 = region.assign_advice(
                        || format!("hash input first_{}", i),
                        config.hash_table[0],
                        offset,
                        || Ok(inp[0]),
                    )?;

                    let c2 = region.assign_advice(
                        || format!("hash input second_{}", i),
                        config.hash_table[1],
                        offset,
                        || Ok(inp[1]),
                    )?;

                    let c3 = region.assign_advice(
                        || format!("hash output_{}", i),
                        config.hash_table[2],
                        offset,
                        || {
                            Ok(if let Some(v) = check {
                                *v
                            } else {
                                Hashable::hash(inp)
                            })
                        },
                    )?;

                    //we directly specify the init state of permutation
                    states.push([zero_cell.clone(), StateWord::from(c1), StateWord::from(c2)]);
                    hashes.push(StateWord::from(c3));
                }

                Ok((states, hashes))
            },
        )?;

        let mut chip_finals = Vec::new();

        for state in states {
            let chip = Pow5Chip::construct(config.permute_config.clone());

            let final_state = <Pow5Chip<_, 3, 2> as PoseidonInstructions<
                Fp,
                Fp::SpecType,
                3,
                2,
            >>::permute(&chip, &mut layouter, &state)?;

            chip_finals.push(final_state);
        }

        layouter.assign_region(
            || "final state dummy",
            |mut region| {
                for (hash, final_state) in hashes.iter().zip(chip_finals.iter()) {
                    region.constrain_equal(hash.cell(), final_state[0].cell())?;
                }

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;

    #[test]
    fn poseidon_hash() {
        let b1: Fr = Fr::from_str_vartime("1").unwrap();
        let b2: Fr = Fr::from_str_vartime("2").unwrap();

        let h = Fr::hash([b1, b2]);
        assert_eq!(
            h.to_string(),
            "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a" // "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );
    }

    use halo2_proofs::dev::MockProver;

    #[cfg(feature = "print_layout")]
    #[test]
    fn print_circuit() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("layouts/hash-layout.png", (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Hash circuit Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = HashCircuit::<Fr> {
            calcs: 1,
            ..Default::default()
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_equality_constraints(true)
            .render(6, &circuit, &root)
            .unwrap();
    }

    #[test]
    fn poseidon_hash_circuit() {
        let message = [
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
        ];

        let k = 6;
        let circuit = HashCircuit::<Fr> {
            calcs: 1,
            inputs: vec![message],
            ..Default::default()
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
