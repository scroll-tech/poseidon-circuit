//! The hash circuit base on poseidon.

use crate::poseidon::primitives::{ConstantLengthIden3, VariableLengthIden3, Hash, P128Pow5T3, Spec};
use halo2_proofs::halo2curves::bn256::Fr;
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
type PoseidonBytes = Hash<Fr, P128Pow5T3<Fr>, VariableLengthIden3, 3, 2>;

impl Hashable for Fr {
    type SpecType = P128Pow5T3<Self>;
    fn hash(inp: [Self; 2]) -> Self {
        Poseidon::init().hash(inp)
    }
}

use crate::poseidon::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord, Var};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed},
};

/// The config for hash circuit
#[derive(Clone, Debug)]
pub struct HashConfig<Fp: FieldExt> {
    permute_config: Pow5Config<Fp, 3, 2>,
    hash_table: [Column<Advice>; 3],
    hash_table_aux: [Column<Advice>; 6],
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
    /// the control flag for each permutation
    pub controls: Vec<Fp>,
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
            controls: Vec::new(),
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
        let hash_table_aux = [0; 6].map(|_| meta.advice_column());
        for col in hash_table_aux.iter().chain(hash_table_aux.iter()) {
            meta.enable_equality(*col);
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
            hash_table_aux,
            constants,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "constant heading",
            |mut region| {
                let c0 = region.assign_fixed(
                    || "constant zero",
                    config.constants[0],
                    0,
                    || Value::known(Fp::zero()),
                )?;

                let c_ctrl = region.assign_advice(
                    || "control head",
                    config.hash_table_aux[0],
                    0,
                    || Value::known(Fp::zero()),
                )?;

                region.constrain_equal(c_ctrl.cell(), c0.cell())
            },
        )?;

        let (states_in, states_out) = layouter.assign_region(
            || "hash table",
            |mut region| {
                let mut states_in = Vec::new();
                let mut states_out = Vec::new();
                let hash_helper = Hash::<Fp, Fp::SpecType, VariableLengthIden3, 3, 2>::init();

                let dummy_input: [Option<&[Fp; 2]>; 1] = [None];
                let dummy_item: [Option<&Fp>; 1] = [None];
                let inputs_i = self
                    .inputs
                    .iter()
                    .map(Some)
                    .chain(dummy_input.into_iter().cycle())
                    .take(self.calcs);
                let controls_i = self
                    .controls
                    .iter()
                    .map(|i| Some(i))
                    .chain(dummy_item.into_iter().cycle())
                    .take(self.calcs);

                let checks_i = self
                    .checks
                    .iter()
                    .map(|i| i.as_ref())
                    .chain(dummy_item.into_iter().cycle())
                    .take(self.calcs);

                // notice our hash table has a (0, 0, 0) at the beginning
                for col in config.hash_table {
                    region.assign_advice(|| "dummy inputs", col, 0, || Value::known(Fp::zero()))?;
                }

                let mut is_new_sponge = true;
                let mut state : [Fp; 3] = [Fp::zero(); 3];

                for (i, ((inp, control), check)) in inputs_i.zip(controls_i).zip(checks_i).enumerate() {

                    let control = control.map(|c|*c).unwrap_or_else(Fp::zero);

                    if is_new_sponge {
                        state[0] = control;
                    }

                    let inp = inp
                        .map(|[a, b]| [*a, *b])
                        .unwrap_or_else(|| [Fp::zero(), Fp::zero()]);

                    (&mut state).into_iter().skip(1).zip(inp).for_each(|(s, inp)|{
                        if is_new_sponge {
                            *s = inp;
                        }else {
                            *s += inp;
                        }
                    });

                    is_new_sponge = Fp::zero() == control;

                    let offset = i + 1;
                    let state_start = state.clone();
                    hash_helper.permute(&mut state); //here we calculate the hash

                    //and sanity check ...
                    if let Some(ck) = check {
                        assert_eq!(*ck, state[0]);
                    }

                    let c_start = [
                        region.assign_advice(
                            || format!("state input 0_{}", i),
                            config.hash_table_aux[1],
                            offset,
                            || Value::known(state_start[0]),
                        )?,
                        region.assign_advice(
                            || format!("state input 1_{}", i),
                            config.hash_table_aux[2],
                            offset,
                            || Value::known(state_start[1]),
                        )?,
                        region.assign_advice(
                            || format!("state input 2_{}", i),
                            config.hash_table_aux[3],
                            offset,
                            || Value::known(state_start[2]),
                        )?,
                    ];

                    let c_end = [
                        region.assign_advice(
                            || format!("state output hash_{}", i),
                            config.hash_table[0],
                            offset,
                            || Value::known(state[0]),
                        )?,
                        region.assign_advice(
                            || format!("state output 1_{}", i),
                            config.hash_table_aux[4],
                            offset,
                            || Value::known(state[1]),
                        )?,
                        region.assign_advice(
                            || format!("state output 2_{}", i),
                            config.hash_table_aux[5],
                            offset,
                            || Value::known(state[2]),
                        )?,                        
                    ];

                    region.assign_advice(
                        || format!("state input control_{}", i),
                        config.hash_table_aux[0],
                        offset,
                        || Value::known(control),
                    )?;

                    region.assign_advice(
                        || format!("hash input first_{}", i),
                        config.hash_table[1],
                        offset,
                        || Value::known(inp[0]),
                    )?;

                    region.assign_advice(
                        || format!("hahs input second_{}", i),
                        config.hash_table[2],
                        offset,
                        || Value::known(inp[1]),
                    )?;

                    //we directly specify the init state of permutation
                    states_in.push(c_start.map(StateWord::from));
                    states_out.push(c_end.map(StateWord::from));
                }

                Ok((states_in, states_out))
            },
        )?;

        let mut chip_finals = Vec::new();

        for state in states_in {
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
                for (state, final_state) in states_out.iter().zip(chip_finals.iter()) {
                    for (s_cell, final_cell) in state.iter().zip(final_state.iter()){
                        region.constrain_equal(s_cell.cell(), final_cell.cell())?;
                    }
                }

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::halo2curves::group::ff::PrimeField;

    #[test]
    fn poseidon_hash() {
        let b1: Fr = Fr::from_str_vartime("1").unwrap();
        let b2: Fr = Fr::from_str_vartime("2").unwrap();

        let h = Fr::hash([b1, b2]);
        assert_eq!(
            format!("{:?}", h),
            "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a" // "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );
    }

    #[test]
    fn poseidon_hash_bytes() {
        let hasher = PoseidonBytes::init();
        let msg = vec![
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
            Fr::from_str_vartime("50331648").unwrap(), //0x3000000
        ];

        let supposed_bytes = 45;

        let h = hasher.hash_with_cap(&msg, supposed_bytes);
        assert_eq!(
            format!("{:?}", h),
            "0x212b546f9c67c4fdcba131035644aa1d8baa8943f84b0a27e8f65b5bd532213e"
        );

        let hasher = PoseidonBytes::init();
        let msg = vec![
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
            Fr::from_str_vartime("3").unwrap(),
            Fr::zero(),
        ];

        let supposed_bytes = 50;

        let h = hasher.hash_with_cap(&msg, supposed_bytes);
        assert_eq!(
            format!("{:?}", h),
            "0x066397f309d55f6caf6419cbb4120f5ada8e54254061b4b448359de388ab5526"
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
            calcs: 2,
            ..Default::default()
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_equality_constraints(true)
            .render(7, &circuit, &root)
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
