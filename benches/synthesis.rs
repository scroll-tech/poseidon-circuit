#[macro_use]
extern crate bencher;
use bencher::Bencher;

use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::{bn256::Fr as Fp, group::ff::PrimeField};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use poseidon_circuit::{hash::*, DEFAULT_STEP};

struct TestCircuit(PoseidonHashTable<Fp>, usize);

// test circuit derived from table data
impl Circuit<Fp> for TestCircuit {
    type Config = PoseidonHashConfig<Fp>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self(PoseidonHashTable::default(), self.1)
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let hash_tbl = [0; 5].map(|_| meta.advice_column());
        SpongeConfig::configure_sub(meta, hash_tbl, DEFAULT_STEP)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = PoseidonHashChip::<Fp, DEFAULT_STEP>::construct(
            config,
            &self.0,
            self.1,
            false,
            Some(Fp::from(42u64)),
        );
        chip.load(&mut layouter)
    }
}

fn synthesis(bench: &mut Bencher) {
    let message1 = [
        Fp::from_str_vartime("1").unwrap(),
        Fp::from_str_vartime("2").unwrap(),
    ];
    let message2 = [
        Fp::from_str_vartime("0").unwrap(),
        Fp::from_str_vartime("1").unwrap(),
    ];

    let k = 12;
    let circuit = TestCircuit(
        PoseidonHashTable {
            inputs: vec![message1, message2],
            ..Default::default()
        },
        500,
    );

    bench.iter(|| {
        MockProver::run(k, &circuit, vec![]).unwrap();
    });
}

fn synthesis_limited(bench: &mut Bencher) {
    bench.bench_n(1, synthesis);
}

benchmark_group!(syth_bench, synthesis_limited);

benchmark_main!(syth_bench);
