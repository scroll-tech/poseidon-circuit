//! The hash circuit base on poseidon.

use crate::poseidon::primitives::{
    ConstantLengthIden3, Domain, Hash, P128Pow5T3, Spec, VariableLengthIden3,
};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::{arithmetic::FieldExt, circuit::AssignedCell};

mod chip_long {
    use super::{SpongeChip, SpongeConfig};
    use crate::poseidon::Pow5Chip;
    /// The configuration of the Poseidon hash chip.
    pub type PoseidonHashConfig<F> = SpongeConfig<F, Pow5Chip<F, 3, 2>>;
    /// The Poseidon hash chip.
    pub type PoseidonHashChip<'d, F, const STEP: usize> =
        SpongeChip<'d, F, STEP, Pow5Chip<F, 3, 2>>;
}

mod chip_short {
    use super::{SpongeChip, SpongeConfig};
    use crate::poseidon::SeptidonChip;
    /// The configuration of the Poseidon hash chip.
    pub type PoseidonHashConfig<F> = SpongeConfig<F, SeptidonChip>;
    /// The Poseidon hash chip.
    pub type PoseidonHashChip<'d, F, const STEP: usize> = SpongeChip<'d, F, STEP, SeptidonChip>;
}

// By default, use a chip with double rounds over 38 rows.
#[cfg(not(feature = "short"))]
pub use chip_long::*;

// If feature `short` is enabled, use the chip with septuple rounds on 8 rows.
#[cfg(feature = "short")]
pub use chip_short::*;

/// indicate an field can be hashed in merkle tree (2 Fields to 1 Field)
pub trait Hashable: FieldExt {
    /// the spec type used in circuit for this hashable field
    type SpecType: Spec<Self, 3, 2>;
    /// the domain type used for hash calculation
    type DomainType: Domain<Self, 2>;

    /// execute hash for any sequence of fields
    fn hash(inp: [Self; 2]) -> Self;
    /// obtain the rows consumed by each circuit block
    fn hash_block_size() -> usize {
        1 + Self::SpecType::full_rounds() + (Self::SpecType::partial_rounds() + 1) / 2
    }
    /// init a hasher used for hash
    fn hasher() -> Hash<Self, Self::SpecType, Self::DomainType, 3, 2> {
        Hash::<Self, Self::SpecType, Self::DomainType, 3, 2>::init()
    }
}

/// indicate an message stream constructed by the field can be hashed, commonly
/// it just need to update the Domain
pub trait MessageHashable: Hashable {
    /// the domain type used for message hash
    type DomainType: Domain<Self, 2>;
    /// hash message, if cap is not provided, it commonly use the len of msg
    fn hash_msg(msg: &[Self], cap: Option<u64>) -> Self;
    /// init a hasher used for hash message
    fn msg_hasher(
    ) -> Hash<Self, <Self as Hashable>::SpecType, <Self as MessageHashable>::DomainType, 3, 2> {
        Hash::<Self, <Self as Hashable>::SpecType, <Self as MessageHashable>::DomainType, 3, 2>::init()
    }
}

impl Hashable for Fr {
    type SpecType = P128Pow5T3<Self>;
    type DomainType = ConstantLengthIden3<2>;

    fn hash(inp: [Self; 2]) -> Self {
        Self::hasher().hash(inp)
    }
}

impl MessageHashable for Fr {
    type DomainType = VariableLengthIden3;

    fn hash_msg(msg: &[Self], cap: Option<u64>) -> Self {
        Self::msg_hasher().hash_with_cap(msg, cap.unwrap_or(msg.len() as u64))
    }
}

use crate::poseidon::{PermuteChip, PoseidonInstructions};
use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn},
    poly::Rotation,
};

/// The config for poseidon hash circuit
#[derive(Clone, Debug)]
pub struct SpongeConfig<Fp: FieldExt, PC: PermuteChip<Fp>> {
    permute_config: PC::Config,
    hash_table: [Column<Advice>; 5],
    hash_table_aux: [Column<Advice>; 6],
    control_aux: Column<Advice>,
    s_sponge_continue: Column<Advice>,
    control_step_range: TableColumn,
    s_table: Selector,
    s_custom: Selector,
}

impl<Fp: Hashable, PC: PermuteChip<Fp>> SpongeConfig<Fp, PC> {
    /// obtain the commitment index of hash table
    pub fn commitment_index(&self) -> [usize; 5] {
        self.hash_table.map(|col| col.index())
    }

    /// obtain the hash_table columns
    pub fn hash_tbl_cols(&self) -> [Column<Advice>; 5] {
        self.hash_table
    }

    /// build configure for sub circuit
    pub fn configure_sub(
        meta: &mut ConstraintSystem<Fp>,
        hash_table: [Column<Advice>; 5],
        step: usize,
    ) -> Self {
        let s_table = meta.selector();
        let s_custom = meta.selector();

        let hash_table_aux = [0, 1, 2, 3, 4, 5].map(|idx| {
            if idx < 5 {
                meta.advice_column()
            } else {
                meta.advice_column_in(halo2_proofs::plonk::SecondPhase)
            }
        });
        for col in hash_table_aux.iter().chain(hash_table[0..1].iter()) {
            meta.enable_equality(*col);
        }

        let control = hash_table[3];
        let s_sponge_continue = meta.advice_column();
        meta.enable_equality(s_sponge_continue);
        let control_aux = meta.advice_column();
        let control_step_range = meta.lookup_table_column();

        let state_in = &hash_table_aux[0..3];
        let state_for_next_in = &hash_table_aux[3..5];
        let hash_out = hash_table_aux[5];
        let hash_inp = &hash_table[1..3];
        let hash_index = hash_table[0];
        let header_mark = hash_table[4];

        meta.create_gate("custom row", |meta| {
            let s_enable = meta.query_selector(s_custom);

            vec![
                s_enable.clone() * meta.query_advice(hash_inp[0], Rotation::cur()),
                s_enable.clone() * meta.query_advice(hash_inp[1], Rotation::cur()),
                s_enable * meta.query_advice(control, Rotation::cur()),
            ]
        });

        meta.create_gate("control constrain", |meta| {
            /*
               s_continue must be bool
               s_continue must be false on each row which control is 0 (MPT mode)
               header_mark is just not(s_continue)
            */
            let s_enable = meta.query_selector(s_table);
            let ctrl = meta.query_advice(control, Rotation::cur());
            let ctrl_bool = ctrl.clone() * meta.query_advice(control_aux, Rotation::cur());
            let s_continue = meta.query_advice(s_sponge_continue, Rotation::cur());

            vec![
                s_enable.clone()
                    * s_continue.clone()
                    * (Expression::Constant(Fp::one()) - s_continue.clone()),
                s_enable.clone() * ctrl * (Expression::Constant(Fp::one()) - ctrl_bool.clone()),
                s_enable.clone()
                    * s_continue.clone()
                    * (Expression::Constant(Fp::one()) - ctrl_bool),
                s_enable
                    * (Expression::Constant(Fp::one())
                        - s_continue
                        - meta.query_advice(header_mark, Rotation::cur())),
            ]
        });

        meta.create_gate("control step", |meta| {
            /*
               when s_continue is true, it trigger a RANGE checking on the ctrl_prev
               to less than or equal to **step**
               and current ctrl can not be 0
            */
            let s_continue = meta.query_advice(s_sponge_continue, Rotation::cur());
            let s_enable = meta.query_selector(s_table) * s_continue;
            let ctrl = meta.query_advice(control, Rotation::cur());
            let ctrl_prev = meta.query_advice(control, Rotation::prev());
            let ctrl_bool = ctrl.clone() * meta.query_advice(control_aux, Rotation::cur());

            vec![
                s_enable.clone()
                    * (ctrl + Expression::Constant(Fp::from_u128(step as u128)) - ctrl_prev),
                s_enable * (Expression::Constant(Fp::one()) - ctrl_bool),
            ]
        });

        meta.lookup("control range check", |meta| {
            let s_enable = meta.query_advice(header_mark, Rotation::cur());
            let ctrl = meta.query_advice(control, Rotation::prev());

            vec![(s_enable * ctrl, control_step_range)]
        });

        meta.create_gate("hash index constrain", |meta| {
            let s_enable = meta.query_selector(s_table);
            let s_continue_hash = meta.query_advice(s_sponge_continue, Rotation::cur());
            let hash_ind = meta.query_advice(hash_index, Rotation::cur());
            let hash_prev = meta.query_advice(hash_index, Rotation::prev());
            let hash_out = meta.query_advice(hash_out, Rotation::prev());

            vec![
                s_enable.clone() * s_continue_hash.clone() * (hash_ind - hash_prev.clone()),
                s_enable
                    * (Expression::Constant(Fp::one()) - s_continue_hash)
                    * (hash_out - hash_prev),
            ]
        });

        meta.create_gate("input constrain", |meta| {
            let s_enable = meta.query_selector(s_table);
            let s_continue_hash = meta.query_advice(s_sponge_continue, Rotation::cur());

            // external input: if not new hash, input must add prev state
            let mut ret: Vec<_> = state_in[1..]
                .iter()
                .zip(state_for_next_in.iter())
                .zip(hash_inp.iter())
                .map(|((inp, prev_inp), ext_inp)| {
                    let inp = meta.query_advice(*inp, Rotation::cur());
                    let prev_inp = meta.query_advice(*prev_inp, Rotation::prev());
                    let ext_inp = meta.query_advice(*ext_inp, Rotation::cur());

                    s_enable.clone() * (prev_inp * s_continue_hash.clone() + ext_inp - inp)
                })
                .collect();

            assert_eq!(hash_inp.len(), ret.len());

            let inp_hash = meta.query_advice(state_in[0], Rotation::cur());
            let inp_hash_prev = meta.query_advice(hash_out, Rotation::prev());
            let inp_hash_init = meta.query_advice(control, Rotation::cur());

            // hash output: must inherit prev state or apply current control flag (for new hash)
            ret.push(
                s_enable.clone()
                    * (Expression::Constant(Fp::one()) - s_continue_hash.clone())
                    * (inp_hash.clone() - inp_hash_init),
            );
            ret.push(s_enable * s_continue_hash * (inp_hash - inp_hash_prev));
            ret
        });

        Self {
            permute_config: PC::configure(meta),
            hash_table,
            hash_table_aux,
            control_aux,
            control_step_range,
            s_table,
            s_custom,
            s_sponge_continue,
        }
    }
}

/// Poseidon hash table
#[derive(Clone, Default, Debug)]
pub struct PoseidonHashTable<Fp> {
    /// the input messages for hashes
    pub inputs: Vec<[Fp; 2]>,
    /// the control flag for each permutation
    pub controls: Vec<Fp>,
    /// the expected hash output for checking
    pub checks: Vec<Option<Fp>>,
    /// the custom hash for nil message
    pub nil_msg_hash: Option<Fp>,
}

impl<Fp: FieldExt> PoseidonHashTable<Fp> {
    /// Add common inputs
    pub fn constant_inputs<'d>(&mut self, src: impl IntoIterator<Item = &'d [Fp; 2]>) {
        let mut new_inps: Vec<_> = src.into_iter().copied().collect();
        self.inputs.append(&mut new_inps);
    }

    /// Add common inputs with expected hash as check
    pub fn constant_inputs_with_check<'d>(
        &mut self,
        src: impl IntoIterator<Item = &'d (Fp, Fp, Fp)>,
    ) {
        // align input and checks
        self.checks.resize(self.inputs.len(), None);

        for (a, b, c) in src {
            self.inputs.push([*a, *b]);
            self.checks.push(Some(*c));
            self.controls.push(Fp::zero());
        }
    }

    /// Add a series of inputs from a field stream
    pub fn stream_inputs<'d>(
        &mut self,
        src: impl IntoIterator<Item = &'d [Fp; 2]>,
        ctrl_start: u64,
        step: usize,
    ) {
        let mut new_inps: Vec<_> = src.into_iter().copied().collect();
        let mut ctrl_series: Vec<_> = std::iter::successors(Some(ctrl_start), |n| {
            if *n > (step as u64) {
                Some(n - step as u64)
            } else {
                None
            }
        })
        .map(Fp::from)
        .take(new_inps.len())
        .collect();

        assert_eq!(new_inps.len(), ctrl_series.len());
        self.inputs.append(&mut new_inps);
        self.controls.append(&mut ctrl_series);
        assert_eq!(self.inputs.len(), self.controls.len());
    }

    /// return the row which poseidon table use (notice it maybe much smaller
    /// than the actual circuit row required)
    pub fn table_size(&self) -> usize {
        self.inputs.len()
    }
}

impl<Fp: Hashable> PoseidonHashTable<Fp> {
    /// return minimum required the circuit rows\
    /// (size of hashes * rows required by each hash)
    pub fn minimum_row_require(&self) -> usize {
        self.inputs.len() * Fp::hash_block_size()
    }
}

/// Represent the chip for Poseidon hash table
#[derive(Debug)]
pub struct SpongeChip<'d, Fp: FieldExt, const STEP: usize, PC: PermuteChip<Fp>> {
    calcs: usize,
    nil_msg_hash: Option<Fp>,
    mpt_only: bool,
    data: &'d PoseidonHashTable<Fp>,
    config: SpongeConfig<Fp, PC>,
}

type PermutedState<Word> = Vec<[Word; 3]>;

impl<
        'd,
        Fp: Hashable,
        const STEP: usize,
        PC: PermuteChip<Fp> + PoseidonInstructions<Fp, Fp::SpecType, 3, 2>,
    > SpongeChip<'d, Fp, STEP, PC>
{
    ///construct the chip
    pub fn construct(
        config: SpongeConfig<Fp, PC>,
        data: &'d PoseidonHashTable<Fp>,
        calcs: usize,
        mpt_only: bool,
        nil_msg_hash: Option<Fp>,
    ) -> Self {
        Self {
            calcs,
            mpt_only,
            nil_msg_hash,
            data,
            config,
        }
    }

    fn fill_hash_tbl_custom(&self, region: &mut Region<'_, Fp>) -> Result<usize, Error> {
        let config = &self.config;

        config.s_custom.enable(region, 0)?;
        // all zero row
        for (tip, cols) in [
            ("dummy inputs", config.hash_table.as_slice()),
            ("dummy aux inputs", config.hash_table_aux.as_slice()),
            ("control aux head", [config.control_aux].as_slice()),
            (
                "control sponge continue head",
                [config.s_sponge_continue].as_slice(),
            ),
        ] {
            for col in cols {
                region.assign_advice(|| tip, *col, 0, || Value::known(Fp::zero()))?;
            }
        }

        config.s_custom.enable(region, 1)?;
        if self.mpt_only {
            return Ok(1);
        }

        // custom
        for (tip, cols) in [
            ("custom inputs", &config.hash_table[1..4]),
            ("custom aux inputs", config.hash_table_aux.as_slice()),
            ("control aux head custom", [config.control_aux].as_slice()),
            (
                "control sponge continue head custom",
                [config.s_sponge_continue].as_slice(),
            ),
        ] {
            for col in cols {
                region.assign_advice(|| tip, *col, 1, || Value::known(Fp::zero()))?;
            }
        }

        // input, notice hash index constrain require we also assign hash_out col
        for col in [config.hash_table_aux[5], config.hash_table[0]] {
            region.assign_advice(
                || "custom hash for nil",
                col,
                1,
                || {
                    self.nil_msg_hash
                        .map(Value::known)
                        .unwrap_or_else(Value::unknown)
                },
            )?;
        }
        region.assign_advice(
            || "custom mark",
            config.hash_table[4],
            1,
            || Value::known(Fp::one()),
        )?;

        Ok(2)
    }

    fn fill_hash_tbl_body(
        &self,
        region: &mut Region<'_, Fp>,
        begin_offset: usize,
    ) -> Result<(PermutedState<PC::Word>, PermutedState<PC::Word>), Error> {
        let config = &self.config;
        let data = self.data;

        let mut states_in = Vec::new();
        let mut states_out = Vec::new();
        let hash_helper = Fp::hasher();

        let inputs_i = data
            .inputs
            .iter()
            .map(Some)
            .chain(std::iter::repeat(None))
            .take(self.calcs);
        let controls_i = data
            .controls
            .iter()
            .map(Some)
            .chain(std::iter::repeat(None))
            .take(self.calcs);

        let checks_i = data
            .checks
            .iter()
            .map(|i| i.as_ref())
            .chain(std::iter::repeat(None))
            .take(self.calcs);

        let mut is_new_sponge = true;
        let mut process_start = 0;
        let mut state: [Fp; 3] = [Fp::zero(); 3];
        let mut last_offset = 0;

        for (i, ((inp, control), check)) in inputs_i.zip(controls_i).zip(checks_i).enumerate() {
            let control = control.copied().unwrap_or_else(Fp::zero);
            let offset = i + begin_offset;
            last_offset = offset;

            if is_new_sponge {
                state[0] = control;
                process_start = offset;
            }

            let inp = inp
                .map(|[a, b]| [*a, *b])
                .unwrap_or_else(|| [Fp::zero(), Fp::zero()]);

            state.iter_mut().skip(1).zip(inp).for_each(|(s, inp)| {
                if is_new_sponge {
                    *s = inp;
                } else {
                    *s += inp;
                }
            });

            let state_start = state;
            hash_helper.permute(&mut state); //here we calculate the hash

            //and sanity check ...
            if let Some(ck) = check {
                assert_eq!(
                    *ck, state[0],
                    "hash output not match with expected at {offset}"
                );
            }

            let current_hash = state[0];

            //assignment ...
            config.s_table.enable(region, offset)?;

            let c_start = [0; 3]
                .into_iter()
                .enumerate()
                .map(|(i, _)| {
                    region.assign_advice(
                        || format!("state input {i}_{offset}"),
                        config.hash_table_aux[i],
                        offset,
                        || Value::known(state_start[i]),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;

            let c_end = [5, 3, 4]
                .into_iter()
                .enumerate()
                .map(|(i, j)| {
                    region.assign_advice(
                        || format!("state output {i}_{offset}"),
                        config.hash_table_aux[j],
                        offset,
                        || Value::known(state[i]),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;

            for (tip, col, val) in [
                ("hash input first", config.hash_table[1], inp[0]),
                ("hash input second", config.hash_table[2], inp[1]),
                ("state input control", config.hash_table[3], control),
                (
                    "state beginning flag",
                    config.hash_table[4],
                    if is_new_sponge { Fp::one() } else { Fp::zero() },
                ),
                (
                    "state input control_aux",
                    config.control_aux,
                    control.invert().unwrap_or_else(Fp::zero),
                ),
                (
                    "state continue control",
                    config.s_sponge_continue,
                    if is_new_sponge { Fp::zero() } else { Fp::one() },
                ),
            ] {
                region.assign_advice(
                    || format!("{tip}_{offset}"),
                    col,
                    offset,
                    || Value::known(val),
                )?;
            }

            is_new_sponge = control <= Fp::from_u128(STEP as u128);

            //fill all the hash_table[0] with result hash
            if is_new_sponge {
                (process_start..=offset).try_for_each(|ith| {
                    region
                        .assign_advice(
                            || format!("hash index_{ith}"),
                            config.hash_table[0],
                            ith,
                            || Value::known(current_hash),
                        )
                        .map(|_| ())
                })?;
            }

            //we directly specify the init state of permutation
            let c_start_arr: [_; 3] = c_start.try_into().expect("same size");
            states_in.push(c_start_arr.map(PC::Word::from));
            let c_end_arr: [_; 3] = c_end.try_into().expect("same size");
            states_out.push(c_end_arr.map(PC::Word::from));
        }

        // set the last row is "custom", a row both enabled and customed
        // can only fill a padding row ([0, 0] in MPT mode)
        config.s_custom.enable(region, last_offset)?;
        Ok((states_in, states_out))
    }

    /// load the table into circuit under the specified config
    pub fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        let config = &self.config;

        layouter.assign_table(
            || "STEP range check",
            |mut table| {
                (0..STEP + 1).into_iter().try_for_each(|i| {
                    table
                        .assign_cell(
                            || "STEP range check",
                            config.control_step_range,
                            i,
                            || Value::known(Fp::from_u128(i as u128)),
                        )
                        .map(|_| ())
                })
            },
        )?;

        let (states_in, states_out) = layouter.assign_region(
            || "hash table",
            |mut region| {
                let offset = self.fill_hash_tbl_custom(&mut region)?;
                self.fill_hash_tbl_body(&mut region, offset)
            },
        )?;

        let mut chip_finals = Vec::new();
        for state in states_in {
            let chip = PC::construct(config.permute_config.clone());

            let final_state = <PC as PoseidonInstructions<Fp, Fp::SpecType, 3, 2>>::permute(
                &chip, layouter, &state,
            )?;

            chip_finals.push(final_state);
        }

        layouter.assign_region(
            || "final state dummy",
            |mut region| {
                for (state, final_state) in states_out.iter().zip(chip_finals.iter()) {
                    for (s_cell, final_cell) in state.iter().zip(final_state.iter()) {
                        let s_cell: AssignedCell<Fp, Fp> = s_cell.clone().into();
                        let final_cell: AssignedCell<Fp, Fp> = final_cell.clone().into();
                        region.constrain_equal(s_cell.cell(), final_cell.cell())?;
                    }
                }

                Ok(())
            },
        )
    }
}

impl<Fp: FieldExt, const STEP: usize, PC: PermuteChip<Fp>> Chip<Fp>
    for SpongeChip<'_, Fp, STEP, PC>
{
    type Config = SpongeConfig<Fp, PC>;
    type Loaded = PoseidonHashTable<Fp>;

    fn config(&self) -> &Self::Config {
        &self.config
    }
    fn loaded(&self) -> &Self::Loaded {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use crate::poseidon::{Pow5Chip, SeptidonChip};

    use super::*;
    use halo2_proofs::halo2curves::group::ff::PrimeField;
    use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};

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
        let msg = vec![
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
            Fr::from_str_vartime("50331648").unwrap(), //0x3000000
        ];

        let supposed_bytes = 45u64;

        let h = Fr::hash_msg(&msg, Some(supposed_bytes));
        assert_eq!(
            format!("{:?}", h),
            "0x212b546f9c67c4fdcba131035644aa1d8baa8943f84b0a27e8f65b5bd532213e"
        );

        let msg = vec![
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
            Fr::from_str_vartime("3").unwrap(),
            Fr::zero(),
        ];

        let supposed_bytes = 50u64;

        let h = Fr::hash_msg(&msg, Some(supposed_bytes));
        assert_eq!(
            format!("{:?}", h),
            "0x066397f309d55f6caf6419cbb4120f5ada8e54254061b4b448359de388ab5526"
        );
    }

    use halo2_proofs::dev::MockProver;
    const TEST_STEP: usize = 32;

    // test circuit derived from table data
    //#[derive(Clone, Default, Debug)]
    struct TestCircuit<PC: PermuteChip<Fr>> {
        table: PoseidonHashTable<Fr>,
        _phantom: PhantomData<PC>,
    }

    impl<PC: PermuteChip<Fr>> TestCircuit<PC> {
        pub fn new(table: PoseidonHashTable<Fr>) -> Self {
            TestCircuit {
                table,
                _phantom: PhantomData,
            }
        }
    }

    impl<PC: PermuteChip<Fr> + PoseidonInstructions<Fr, <Fr as Hashable>::SpecType, 3, 2>>
        Circuit<Fr> for TestCircuit<PC>
    {
        type Config = (SpongeConfig<Fr, PC>, usize);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::new(Default::default())
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let hash_tbl = [0; 5].map(|_| meta.advice_column());
            (SpongeConfig::configure_sub(meta, hash_tbl, TEST_STEP), 4)
        }

        fn synthesize(
            &self,
            (config, max_rows): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let chip = SpongeChip::<Fr, TEST_STEP, PC>::construct(
                config,
                &self.table,
                max_rows,
                false,
                Some(Fr::from(42u64)),
            );
            chip.load(&mut layouter)
        }
    }

    #[cfg(feature = "print_layout")]
    #[test]
    fn print_circuit() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("layouts/hash-layout.png", (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Hash circuit Layout", ("sans-serif", 60))
            .unwrap();

        let message1 = [
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
        ];

        let message2 = [
            Fr::from_str_vartime("2").unwrap(),
            Fr::from_str_vartime("3").unwrap(),
        ];

        let k = 8;
        let circuit = PoseidonHashTable {
            inputs: vec![message1, message2],
            ..Default::default()
        };
        halo2_proofs::dev::CircuitLayout::default()
            .show_equality_constraints(true)
            .render(k, &circuit, &root)
            .unwrap();
    }

    #[test]
    fn poseidon_hash_circuit() {
        poseidon_hash_circuit_impl::<Pow5Chip<Fr, 3, 2>>();
        poseidon_hash_circuit_impl::<SeptidonChip>();
    }

    fn poseidon_hash_circuit_impl<
        PC: PermuteChip<Fr> + PoseidonInstructions<Fr, <Fr as Hashable>::SpecType, 3, 2>,
    >() {
        let message1 = [
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
        ];

        let message2 = [
            Fr::from_str_vartime("2").unwrap(),
            Fr::from_str_vartime("3").unwrap(),
        ];

        let k = 8;
        let circuit = TestCircuit::<PC>::new(PoseidonHashTable {
            inputs: vec![message1, message2],
            ..Default::default()
        });
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn poseidon_var_len_hash_circuit() {
        poseidon_var_len_hash_circuit_impl::<Pow5Chip<Fr, 3, 2>>();
        poseidon_var_len_hash_circuit_impl::<SeptidonChip>();
    }

    fn poseidon_var_len_hash_circuit_impl<
        PC: PermuteChip<Fr> + PoseidonInstructions<Fr, <Fr as Hashable>::SpecType, 3, 2>,
    >() {
        let message1 = [
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
        ];

        let message2 = [Fr::from_str_vartime("50331648").unwrap(), Fr::zero()];

        let k = 8;
        let circuit = TestCircuit::<PC>::new( PoseidonHashTable {
            inputs: vec![message1, message2],
            controls: vec![Fr::from_u128(45), Fr::from_u128(13)],
            checks: vec![None, Some(Fr::from_str_vartime("15002881182751877599173281392790087382867290792048832034781070831698029191486").unwrap())],
            ..Default::default()
        });
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let circuit = TestCircuit::<PC>::new(PoseidonHashTable {
            inputs: vec![message1, message2, message1],
            controls: vec![Fr::from_u128(64), Fr::from_u128(32), Fr::zero()],
            checks: Vec::new(),
            ..Default::default()
        });
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let circuit = TestCircuit::<PC>::new(PoseidonHashTable::<Fr> {
            inputs: vec![message2],
            controls: vec![Fr::from_u128(13)],
            ..Default::default()
        });
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
        let circuit = TestCircuit::<PC>::new(PoseidonHashTable::<Fr> {
            ..Default::default()
        });
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
