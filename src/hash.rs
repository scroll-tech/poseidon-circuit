//! The hash circuit base on poseidon.

use crate::poseidon::primitives::{ConstantLengthIden3, Domain, Hash, Spec, VariableLengthIden3};
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::Fixed;
use halo2_proofs::{arithmetic::FieldExt, circuit::AssignedCell};
use log;
use std::time::Instant;

mod chip_long {
    use super::{SpongeChip, SpongeConfig};
    use crate::poseidon::primitives::{P128Pow5T3, P128Pow5T3Constants};
    use crate::poseidon::Pow5Chip;
    /// The specified base hashable trait
    pub trait Hashablebase: P128Pow5T3Constants {}
    /// Set the spec type as P128Pow5T3
    pub type HashSpec<F> = P128Pow5T3<F>;
    /// The configuration of the Poseidon hash chip.
    pub type PoseidonHashConfig<F> = SpongeConfig<F, Pow5Chip<F, 3, 2>>;
    /// The Poseidon hash chip.
    pub type PoseidonHashChip<'d, F, const STEP: usize> =
        SpongeChip<'d, F, STEP, Pow5Chip<F, 3, 2>>;
}

mod chip_short {
    use super::{SpongeChip, SpongeConfig};
    use crate::poseidon::primitives::P128Pow5T3Compact;
    use crate::poseidon::{CachedConstants, SeptidonChip};
    /// The specified base hashable trait
    pub trait Hashablebase: CachedConstants {}
    /// Set the spec type as P128Pow5T3Compact
    pub type HashSpec<F> = P128Pow5T3Compact<F>;
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
pub trait Hashable: Hashablebase {
    /// the spec type used in circuit for this hashable field
    type SpecType: Spec<Self, 3, 2>;
    /// the domain type used for hash calculation
    type DomainType: Domain<Self, 2>;

    /// execute hash for any sequence of fields
    fn hash(inp: [Self; 2]) -> Self;
    /// obtain the rows consumed by each circuit block
    fn hash_block_size() -> usize {
        #[cfg(feature = "short")]
        {
            1 + Self::SpecType::full_rounds()
        }
        #[cfg(not(feature = "short"))]
        {
            1 + Self::SpecType::full_rounds() + (Self::SpecType::partial_rounds() + 1) / 2
        }
    }
    /// init a hasher used for hash
    fn hasher() -> Hash<Self, Self::SpecType, Self::DomainType, 3, 2> {
        Hash::<Self, Self::SpecType, Self::DomainType, 3, 2>::init()
    }
}

/// the domain factor applied to var-len mode hash
#[cfg(not(feature = "legacy"))]
pub const HASHABLE_DOMAIN_SPEC: u128 = 0x10000000000000000;
#[cfg(feature = "legacy")]
pub const HASHABLE_DOMAIN_SPEC: u128 = 1;

/// indicate an message stream constructed by the field can be hashed, commonly
/// it just need to update the Domain
pub trait MessageHashable: Hashable {
    /// the domain type used for message hash
    type DomainType: Domain<Self, 2>;
    /// hash message, if cap is not provided, it use the basic spec: (len of msg * 2^64, or len of msg in legacy mode)
    fn hash_msg(msg: &[Self], cap: Option<u128>) -> Self;
    /// init a hasher used for hash message
    fn msg_hasher(
    ) -> Hash<Self, <Self as Hashable>::SpecType, <Self as MessageHashable>::DomainType, 3, 2> {
        Hash::<Self, <Self as Hashable>::SpecType, <Self as MessageHashable>::DomainType, 3, 2>::init()
    }
}

impl Hashablebase for Fr {}

impl Hashable for Fr {
    type SpecType = HashSpec<Self>;
    type DomainType = ConstantLengthIden3<2>;

    fn hash(inp: [Self; 2]) -> Self {
        Self::hasher().hash(inp)
    }
}

impl MessageHashable for Fr {
    type DomainType = VariableLengthIden3;

    fn hash_msg(msg: &[Self], cap: Option<u128>) -> Self {
        Self::msg_hasher()
            .hash_with_cap(msg, cap.unwrap_or(msg.len() as u128 * HASHABLE_DOMAIN_SPEC))
    }
}

use crate::poseidon::{PermuteChip, PoseidonInstructions};
use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn},
    poly::Rotation,
};
use std::fmt::Debug as DebugT;

/// The config for poseidon hash circuit
#[derive(Clone, Debug)]
pub struct SpongeConfig<F: FieldExt, PC: Chip<F> + Clone + DebugT> {
    permute_config: PC::Config,
    hash_table: [Column<Advice>; 5],
    hash_table_aux: [Column<Advice>; 6],
    control_aux: Column<Advice>,
    s_sponge_continue: Column<Advice>,
    control_step_range: TableColumn,
    q_enable: Column<Fixed>,
    s_custom: Selector,
    /// the configured step in var-len mode, i.e (`input_width * bytes in each field`)
    pub step: usize,
}

impl<F: Hashable, PC: PermuteChip<F, F::SpecType, 3, 2>> SpongeConfig<F, PC> {
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
        meta: &mut ConstraintSystem<F>,
        (q_enable, hash_table): (Column<Fixed>, [Column<Advice>; 5]),
        step: usize,
    ) -> Self {
        let s_custom = meta.complex_selector();

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
            let q_custom = meta.query_selector(s_custom);

            vec![
                q_custom.clone() * meta.query_advice(hash_inp[0], Rotation::cur()),
                q_custom.clone() * meta.query_advice(hash_inp[1], Rotation::cur()),
                q_custom * meta.query_advice(control, Rotation::cur()),
            ]
        });

        meta.create_gate("control constrain", |meta| {
            /*
               s_continue must be bool
               s_continue must be false on each row which control is 0 (MPT mode)
               header_mark is just not(s_continue)
            */
            let q_enable = meta.query_fixed(q_enable, Rotation::cur());
            let ctrl = meta.query_advice(control, Rotation::cur());
            let ctrl_bool = ctrl.clone() * meta.query_advice(control_aux, Rotation::cur());
            let s_continue = meta.query_advice(s_sponge_continue, Rotation::cur());

            vec![
                q_enable.clone()
                    * s_continue.clone()
                    * (Expression::Constant(F::one()) - s_continue.clone()),
                q_enable.clone() * ctrl * (Expression::Constant(F::one()) - ctrl_bool.clone()),
                q_enable.clone()
                    * s_continue.clone()
                    * (Expression::Constant(F::one()) - ctrl_bool),
                q_enable
                    * (Expression::Constant(F::one())
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
            let q_enable = meta.query_fixed(q_enable, Rotation::cur()) * s_continue;
            let ctrl = meta.query_advice(control, Rotation::cur());
            let ctrl_prev = meta.query_advice(control, Rotation::prev());
            let ctrl_bool = ctrl.clone() * meta.query_advice(control_aux, Rotation::cur());

            vec![
                q_enable.clone()
                    * (ctrl
                        + Expression::Constant(F::from_u128(step as u128 * HASHABLE_DOMAIN_SPEC))
                        - ctrl_prev),
                q_enable * (Expression::Constant(F::one()) - ctrl_bool),
            ]
        });

        meta.lookup("control range check", |meta| {
            let q_enable = meta.query_advice(header_mark, Rotation::cur());
            let ctrl = meta.query_advice(control, Rotation::prev());

            vec![(q_enable * ctrl, control_step_range)]
        });

        meta.create_gate("hash index constrain", |meta| {
            let q_enable = meta.query_fixed(q_enable, Rotation::cur());
            let s_continue_hash = meta.query_advice(s_sponge_continue, Rotation::cur());
            let hash_ind = meta.query_advice(hash_index, Rotation::cur());
            let hash_prev = meta.query_advice(hash_index, Rotation::prev());
            let hash_out = meta.query_advice(hash_out, Rotation::prev());

            vec![
                q_enable.clone() * s_continue_hash.clone() * (hash_ind - hash_prev.clone()),
                q_enable
                    * (Expression::Constant(F::one()) - s_continue_hash)
                    * (hash_out - hash_prev),
            ]
        });

        meta.create_gate("input constrain", |meta| {
            let q_enable = meta.query_fixed(q_enable, Rotation::cur());
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

                    q_enable.clone() * (prev_inp * s_continue_hash.clone() + ext_inp - inp)
                })
                .collect();

            assert_eq!(hash_inp.len(), ret.len());

            let inp_hash = meta.query_advice(state_in[0], Rotation::cur());
            let inp_hash_prev = meta.query_advice(hash_out, Rotation::prev());
            let inp_hash_init = meta.query_advice(control, Rotation::cur());

            // hash output: must inherit prev state or apply current control flag (for new hash)
            ret.push(
                q_enable.clone()
                    * (Expression::Constant(F::one()) - s_continue_hash.clone())
                    * (inp_hash.clone() - inp_hash_init),
            );
            ret.push(q_enable * s_continue_hash * (inp_hash - inp_hash_prev));
            ret
        });

        Self {
            permute_config: PC::configure(meta),
            hash_table,
            hash_table_aux,
            control_aux,
            control_step_range,
            q_enable,
            s_custom,
            s_sponge_continue,
            step,
        }
    }
}

/// Poseidon hash table
#[derive(Clone, Default, Debug)]
pub struct PoseidonHashTable<F> {
    /// the input messages for hashes
    pub inputs: Vec<[F; 2]>,
    /// the control flag for each permutation
    pub controls: Vec<u64>,
    /// the expected hash output for checking
    pub checks: Vec<Option<F>>,
}

impl<F: FieldExt> PoseidonHashTable<F> {
    /// Add common inputs
    pub fn constant_inputs<'d>(&mut self, src: impl IntoIterator<Item = &'d [F; 2]>) {
        let mut new_inps: Vec<_> = src.into_iter().copied().collect();
        self.inputs.append(&mut new_inps);
    }

    /// Add common inputs with expected hash as check
    pub fn constant_inputs_with_check<'d>(&mut self, src: impl IntoIterator<Item = &'d (F, F, F)>) {
        // align input and checks
        self.checks.resize(self.inputs.len(), None);

        for (a, b, c) in src {
            self.inputs.push([*a, *b]);
            self.checks.push(Some(*c));
            self.controls.push(0);
        }
    }

    /// Add a series of inputs from a field stream
    pub fn stream_inputs<'d>(
        &mut self,
        src: impl IntoIterator<Item = &'d [F; 2]>,
        ctrl_start: u64,
        step: usize,
    ) {
        self.stream_inputs_with_check(src, None, ctrl_start, step)
    }

    /// Add a series of inputs from a field stream with checking of the final hash
    pub fn stream_inputs_with_check<'d>(
        &mut self,
        src: impl IntoIterator<Item = &'d [F; 2]>,
        check: Option<F>,
        ctrl_start: u64,
        step: usize,
    ) {
        let mut new_inps: Vec<_> = src.into_iter().copied().collect();
        assert_ne!(0, new_inps.len());
        let mut ctrl_series: Vec<_> = std::iter::successors(Some(ctrl_start), |n| {
            if *n > (step as u64) {
                Some(n - step as u64)
            } else {
                None
            }
        })
        .take(new_inps.len())
        .collect();

        assert_eq!(new_inps.len(), ctrl_series.len());
        self.inputs.append(&mut new_inps);
        self.controls.append(&mut ctrl_series);
        assert_eq!(self.inputs.len(), self.controls.len());
        self.checks.resize(self.inputs.len() - 1, None);
        self.checks.push(check);
    }

    /// return the row which poseidon table use (notice it maybe much smaller
    /// than the actual circuit row required)
    pub fn table_size(&self) -> usize {
        self.inputs.len()
    }
}

impl<F: Hashable> PoseidonHashTable<F> {
    /// return minimum required the circuit rows\
    /// (size of hashes * rows required by each hash)
    pub fn minimum_row_require(&self) -> usize {
        self.inputs.len() * F::hash_block_size()
    }
}

/// Represent the chip for Poseidon hash table
#[derive(Debug)]
pub struct SpongeChip<'d, F: FieldExt, const STEP: usize, PC: Chip<F> + Clone + DebugT>
where
    PC::Config: Sync,
{
    calcs: usize,
    data: &'d PoseidonHashTable<F>,
    config: SpongeConfig<F, PC>,
}

type PermutedState<Word> = Vec<[Word; 3]>;
type PermutedStatePair<Word> = (PermutedState<Word>, PermutedState<Word>);

impl<'d, F: Hashable, const STEP: usize, PC: PermuteChip<F, F::SpecType, 3, 2>>
    SpongeChip<'d, F, STEP, PC>
where
    PC::Config: Sync,
{
    ///construct the chip
    pub fn construct(
        config: SpongeConfig<F, PC>,
        data: &'d PoseidonHashTable<F>,
        calcs: usize,
    ) -> Self {
        Self {
            calcs,
            data,
            config,
        }
    }

    fn fill_hash_tbl_custom(&self, region: &mut Region<'_, F>) -> Result<usize, Error> {
        let config = &self.config;

        config.s_custom.enable(region, 0)?;
        // all zero row without enable
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
                region.assign_advice(|| tip, *col, 0, || Value::known(F::zero()))?;
            }
        }

        Ok(1)
    }

    fn fill_hash_tbl_body(
        &self,
        region: &mut Region<'_, F>,
        begin_offset: usize,
    ) -> Result<PermutedStatePair<PC::Word>, Error> {
        let config = &self.config;
        let data = self.data;

        let mut states_in = Vec::new();
        let mut states_out = Vec::new();
        let hash_helper = F::hasher();

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

        assert!(self.calcs >= data.inputs.len() && self.calcs >= data.controls.len());

        let mut is_new_sponge = true;
        let mut process_start = 0;
        let mut state: [F; 3] = [F::zero(); 3];
        let mut last_offset = 0;

        for (i, ((inp, control), check)) in inputs_i.zip(controls_i).zip(checks_i).enumerate() {
            let control = control.copied().unwrap_or(0);
            let offset = i + begin_offset;
            last_offset = offset;

            let control_as_flag = F::from_u128(control as u128 * HASHABLE_DOMAIN_SPEC);

            if is_new_sponge {
                state[0] = control_as_flag;
                process_start = offset;
            }

            let inp = inp
                .map(|[a, b]| [*a, *b])
                .unwrap_or_else(|| [F::zero(), F::zero()]);

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
            region.assign_fixed(
                || "assign q_enable",
                self.config.q_enable,
                offset,
                || Value::known(F::one()),
            )?;

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
                ("state input control", config.hash_table[3], control_as_flag),
                (
                    "state beginning flag",
                    config.hash_table[4],
                    if is_new_sponge { F::one() } else { F::zero() },
                ),
                (
                    "state input control_aux",
                    config.control_aux,
                    control_as_flag.invert().unwrap_or_else(F::zero),
                ),
                (
                    "state continue control",
                    config.s_sponge_continue,
                    if is_new_sponge { F::zero() } else { F::one() },
                ),
            ] {
                region.assign_advice(
                    || format!("{tip}_{offset}"),
                    col,
                    offset,
                    || Value::known(val),
                )?;
            }

            is_new_sponge = control <= STEP as u64;

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
        self.config.s_custom.enable(region, last_offset)?;
        Ok((states_in, states_out))
    }

    #[allow(clippy::type_complexity)]
    fn fill_hash_tbl_body_partial(
        &self,
        region: &mut Region<'_, F>,
        data: &[((Option<&[F; 2]>, Option<&u64>), Option<&F>)],
        is_first_pass: &mut bool,
        is_last_sub_region: bool,
    ) -> Result<PermutedStatePair<PC::Word>, Error> {
        let config = &self.config;
        let mut states_in = Vec::new();
        let mut states_out = Vec::new();

        if *is_first_pass {
            *is_first_pass = false;
            region.assign_advice(
                || "region shape dummy column",
                // any advice that we access in this region can be used
                config.hash_table_aux[0],
                data.len() - 1,
                || Value::known(F::zero()),
            )?;
            *is_first_pass = false;
            return Ok((states_in, states_out));
        }

        let hash_helper = F::hasher();

        let mut is_new_sponge = true;
        let mut process_start = 0;
        let mut state = [F::zero(); 3];

        for (i, ((inp, control), check)) in data.iter().enumerate() {
            let control = control.copied().unwrap_or(0u64);
            let offset = i;

            let control_as_flag = F::from_u128(control as u128 * HASHABLE_DOMAIN_SPEC);

            if is_new_sponge {
                state[0] = control_as_flag;
                process_start = offset;
            }

            let inp = inp
                .map(|[a, b]| [*a, *b])
                .unwrap_or_else(|| [F::zero(), F::zero()]);

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
                    **ck, state[0],
                    "hash output not match with expected at {offset}"
                );
            }

            let current_hash = state[0];

            //assignment ...
            region.assign_fixed(
                || "assign q_enable",
                self.config.q_enable,
                offset,
                || Value::known(F::one()),
            )?;

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
                ("state input control", config.hash_table[3], control_as_flag),
                (
                    "state beginning flag",
                    config.hash_table[4],
                    if is_new_sponge { F::one() } else { F::zero() },
                ),
                (
                    "state input control_aux",
                    config.control_aux,
                    control_as_flag.invert().unwrap_or_else(F::zero),
                ),
                (
                    "state continue control",
                    config.s_sponge_continue,
                    if is_new_sponge { F::zero() } else { F::one() },
                ),
            ] {
                region.assign_advice(
                    || format!("{tip}_{offset}"),
                    col,
                    offset,
                    || Value::known(val),
                )?;
            }

            //we directly specify the init state of permutation
            let c_start_arr: [_; 3] = c_start.try_into().expect("same size");
            states_in.push(c_start_arr.map(PC::Word::from));
            let c_end_arr: [_; 3] = c_end.try_into().expect("same size");
            states_out.push(c_end_arr.map(PC::Word::from));

            is_new_sponge = control <= STEP as u64;

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
        }

        if is_last_sub_region {
            self.config.s_custom.enable(region, data.len() - 1)?;
        }
        Ok((states_in, states_out))
    }

    /// load the table into circuit under the specified config
    #[allow(clippy::type_complexity)]
    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
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
                            || Value::known(F::from_u128(i as u128 * HASHABLE_DOMAIN_SPEC)),
                        )
                        .map(|_| ())
                })
            },
        )?;

        #[cfg(not(feature = "parallel_syn"))]
        let (states_in, states_out) = {
            layouter.assign_region(
                || "hash table",
                |mut region| {
                    let begin_offset = self.fill_hash_tbl_custom(&mut region)?;
                    self.fill_hash_tbl_body(&mut region, begin_offset)
                },
            )?
        };
        #[cfg(not(feature = "parallel_syn"))]
        let chip_finals = {
            let mut chip_finals = Vec::new();
            for state in states_in {
                let chip = PC::construct(config.permute_config.clone());

                let final_state = <PC as PoseidonInstructions<F, F::SpecType, 3, 2>>::permute(
                    &chip, layouter, &state,
                )?;

                chip_finals.push(final_state);
            }
            chip_finals
        };

        // if feature "parallel_syn" is enabled,
        // `parallel` assignment is turned on by default
        // we can turn it off by set the environment variable
        // `CIRCUIT_ASSIGNMENT_TYPE=serial`
        #[cfg(feature = "parallel_syn")]
        let is_parallel_assignment = {
            let assignment_type = std::env::var("CIRCUIT_ASSIGNMENT_TYPE")
                .ok()
                .unwrap_or_default();
            match assignment_type.as_str() {
                "serial" => false,
                "parallel" => true,
                &_ => true,
            }
        };
        #[cfg(feature = "parallel_syn")]
        let (states_in, states_out) = if is_parallel_assignment == false {
            layouter.assign_region(
                || "hash table",
                |mut region| {
                    let begin_offset = self.fill_hash_tbl_custom(&mut region)?;
                    self.fill_hash_tbl_body(&mut region, begin_offset)
                },
            )?
        } else {
            let hash_table_par_time = Instant::now();
            layouter.assign_region(
                || "hash table custom",
                |mut region| self.fill_hash_tbl_custom(&mut region),
            )?;
            let data = self.data;

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

            let chunks_count = std::thread::available_parallelism()
                .map(|e| e.get())
                .unwrap_or(32);
            let min_len = self.calcs / chunks_count + 1;
            let mut chunk_len = 0;

            let data: Vec<((Option<&[F; 2]>, Option<&u64>), Option<&F>)> =
                inputs_i.zip(controls_i).zip(checks_i).collect();

            // Split `data` into chunks and ensure each chunks is longer thant `min_len` and ends
            // with a new sponge.
            //
            // Each chunk would be processed in a separate thread.
            let assignments = data
                .group_by(|((_, control), _), _| {
                    chunk_len += 1;
                    if control.copied().unwrap_or(0) > STEP as u64 || chunk_len < min_len {
                        true
                    } else {
                        chunk_len = 0;
                        false
                    }
                })
                .collect::<Vec<_>>();
            let assignments_len = assignments.len();
            let assignments = assignments
                .into_iter()
                .enumerate()
                .map(|(i, data)| {
                    let mut is_first_pass = true;
                    let is_last_sub_region = i == assignments_len - 1;
                    move |mut region: Region<'_, F>| -> Result<PermutedStatePair<PC::Word>, Error> {
                        self.fill_hash_tbl_body_partial(
                            &mut region,
                            data,
                            &mut is_first_pass,
                            is_last_sub_region,
                        )
                    }
                })
                .collect::<Vec<_>>();
            let ret = layouter.assign_regions(|| "hash table", assignments)?;

            let mut states_in = vec![];
            let mut states_out = vec![];
            for (s_in, s_out) in ret.into_iter() {
                states_in.extend(s_in);
                states_out.extend(s_out);
            }
            log::info!(
                "hash table parallel version took {:?}",
                hash_table_par_time.elapsed()
            );
            (states_in, states_out)
        };
        #[cfg(feature = "parallel_syn")]
        let chip_finals = if is_parallel_assignment == false {
            let mut chip_finals = Vec::new();
            for state in states_in {
                let chip = PC::construct(config.permute_config.clone());

                let final_state = <PC as PoseidonInstructions<F, F::SpecType, 3, 2>>::permute(
                    &chip, layouter, &state,
                )?;

                chip_finals.push(final_state);
            }
            chip_finals
        } else {
            let chip = PC::construct(config.permute_config.clone());
            <PC as PoseidonInstructions<F, F::SpecType, 3, 2>>::permute_batch(
                &chip, layouter, &states_in,
            )?
        };

        layouter.assign_region(
            || "final state dummy",
            |mut region| {
                for (state, final_state) in states_out.iter().zip(chip_finals.iter()) {
                    for (s_cell, final_cell) in state.iter().zip(final_state.iter()) {
                        let s_cell: AssignedCell<F, F> = s_cell.clone().into();
                        let final_cell: AssignedCell<F, F> = final_cell.clone().into();
                        region.constrain_equal(s_cell.cell(), final_cell.cell())?;
                    }
                }

                Ok(())
            },
        )
    }
}

impl<F: FieldExt, const STEP: usize, PC: Chip<F> + Clone + DebugT> Chip<F>
    for SpongeChip<'_, F, STEP, PC>
where
    PC::Config: Sync,
{
    type Config = SpongeConfig<F, PC>;
    type Loaded = PoseidonHashTable<F>;

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
    use halo2_proofs::halo2curves::bn256::{Bn256, G1Affine};
    use halo2_proofs::halo2curves::group::ff::PrimeField;
    use halo2_proofs::plonk::{create_proof, keygen_pk2, verify_proof};
    use halo2_proofs::poly::commitment::ParamsProver;
    use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
    use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
    use halo2_proofs::poly::kzg::strategy::SingleStrategy;
    use halo2_proofs::transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    };
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

        let supposed_bytes = 45u128;

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

        let supposed_bytes = 50u128;

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
    struct TestCircuit<PC> {
        table: PoseidonHashTable<Fr>,
        _phantom: PhantomData<PC>,
    }

    impl<PC: PermuteChip<Fr, <Fr as Hashable>::SpecType, 3, 2>> TestCircuit<PC> {
        pub fn new(table: PoseidonHashTable<Fr>) -> Self {
            TestCircuit {
                table,
                _phantom: PhantomData,
            }
        }
    }

    impl<PC: PermuteChip<Fr, <Fr as Hashable>::SpecType, 3, 2>> Circuit<Fr> for TestCircuit<PC>
    where
        PC::Config: Sync,
    {
        type Config = (SpongeConfig<Fr, PC>, usize);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::new(Default::default())
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let q_enable = meta.fixed_column();
            let hash_tbl = [0; 5].map(|_| meta.advice_column());
            (
                SpongeConfig::configure_sub(meta, (q_enable, hash_tbl), TEST_STEP),
                4,
            )
        }

        fn synthesize(
            &self,
            (config, max_rows): Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let chip = SpongeChip::<Fr, TEST_STEP, PC>::construct(config, &self.table, max_rows);
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

    fn poseidon_hash_circuit_impl<PC: PermuteChip<Fr, <Fr as Hashable>::SpecType, 3, 2>>()
    where
        PC::Config: Sync,
    {
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

    fn poseidon_var_len_hash_circuit_impl<PC: PermuteChip<Fr, <Fr as Hashable>::SpecType, 3, 2>>()
    where
        PC::Config: Sync,
    {
        let message1 = [
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
        ];

        let message2 = [Fr::from_str_vartime("50331648").unwrap(), Fr::zero()];

        let k = 8;
        let circuit = TestCircuit::<PC>::new(PoseidonHashTable {
            inputs: vec![message1, message2],
            controls: vec![45, 13],
            //checks: vec![None, Some(Fr::from_str_vartime("15002881182751877599173281392790087382867290792048832034781070831698029191486").unwrap())],
            ..Default::default()
        });
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let circuit = TestCircuit::<PC>::new(PoseidonHashTable {
            inputs: vec![message1, message2, message1],
            controls: vec![64, 32],
            checks: Vec::new(),
            ..Default::default()
        });
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        let circuit = TestCircuit::<PC>::new(PoseidonHashTable::<Fr> {
            inputs: vec![message2],
            controls: vec![13],
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

    #[test]
    fn poseidon_parallel_synthesis() {
        poseidon_parallel_synthesis_impl::<Pow5Chip<Fr, 3, 2>>();
        poseidon_parallel_synthesis_impl::<SeptidonChip>();
    }

    fn set_assignment_env_var(value: &str) {
        std::env::set_var("CIRCUIT_ASSIGNMENT_TYPE", value);
        let assign_var = std::env::var("CIRCUIT_ASSIGNMENT_TYPE")
            .ok()
            .unwrap_or_default();
        log::info!("CIRCUIT_ASSIGNMENT_TYPE: {}", assign_var);
    }

    fn poseidon_parallel_synthesis_impl<PC: PermuteChip<Fr, <Fr as Hashable>::SpecType, 3, 2>>()
    where
        PC::Config: Sync,
    {
        use rand::SeedableRng;
        use rand_xorshift::XorShiftRng;

        let message1 = [
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
        ];

        let message2 = [Fr::from_str_vartime("50331648").unwrap(), Fr::zero()];

        let k = 8;

        set_assignment_env_var("serial");
        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let general_params = ParamsKZG::<Bn256>::setup(k, &mut rng);
        let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();

        let circuit = TestCircuit::<PC>::new(PoseidonHashTable {
            inputs: vec![message1, message2],
            controls: vec![45, 13],
            //checks: vec![None, Some(Fr::from_str_vartime("15002881182751877599173281392790087382867290792048832034781070831698029191486").unwrap())],
            ..Default::default()
        });

        let pk = keygen_pk2(&general_params, &circuit).expect("keygen_pk shouldn't fail");

        set_assignment_env_var("parallel");
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            XorShiftRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            TestCircuit<PC>,
        >(
            &general_params,
            &pk,
            &[circuit],
            &[&[]],
            rng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();

        set_assignment_env_var("");
        let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleStrategy::new(&general_params);
        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            &verifier_params,
            pk.get_vk(),
            strategy,
            &[&[]],
            &mut verifier_transcript,
        )
        .expect("failed to verify bench circuit");
    }
}
