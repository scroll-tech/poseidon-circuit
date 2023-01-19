#[macro_use]
extern crate bencher;

use bencher::Bencher;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::bn256::Fr;
use lazy_static::lazy_static;
use poseidon_circuit::poseidon::primitives::{ConstantLengthIden3, Hash, P128Pow5T3};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

lazy_static! {
    static ref RNDFRS: [Fr; 16] = {
        let rng = ChaCha8Rng::from_seed([101u8; 32]);
        [(); 16].map(|_| Fr::random(rng.clone()))
    };
}

macro_rules! hashes {
    ( $fname:ident, $n:expr ) => {
        fn $fname(bench: &mut Bencher) {
            bench.iter(|| {
                Hash::<Fr, P128Pow5T3<Fr>, ConstantLengthIden3<$n>, 3, 2>::init()
                    .hash(Vec::from(&RNDFRS.as_slice()[..$n]).try_into().unwrap())
            });
        }
    };
}

hashes!(h02, 2);
hashes!(h03, 3);
hashes!(h04, 4);
hashes!(h05, 5);
hashes!(h06, 6);
hashes!(h07, 7);

fn vec_ref(bench: &mut Bencher) {
    bench.iter(|| Vec::from(&RNDFRS.as_slice()[..8]));
}

fn init_ref(bench: &mut Bencher) {
    bench.iter(|| Hash::<Fr, P128Pow5T3<Fr>, ConstantLengthIden3<3>, 3, 2>::init());
}

benchmark_group!(
    hashes_bench,
    h02,
    h03,
    h04,
    h05,
    h06,
    h07,
    vec_ref,
    init_ref
);
benchmark_main!(hashes_bench);
