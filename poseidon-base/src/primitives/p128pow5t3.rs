use std::marker::PhantomData;
use std::mem::MaybeUninit;

use halo2curves::ff::{FromUniformBytes, ExtraArithmetic};

use super::{Mds, Spec};

/// The trait required for fields can handle a pow5 sbox, 3 field, 2 rate permutation
pub trait P128Pow5T3Constants: FromUniformBytes<64> + Ord + ExtraArithmetic {
    fn partial_rounds() -> usize {
        56
    }
    fn round_constants() -> Vec<[Self; 3]>;
    fn mds() -> Mds<Self, 3>;
    fn mds_inv() -> Mds<Self, 3>;
}

/// Poseidon-128 using the $x^5$ S-box, with a width of 3 field elements, and the
/// standard number of rounds for 128-bit security "with margin".
///
/// The standard specification for this set of parameters (on either of the Pasta
/// fields) uses $R_F = 8, R_P = 56$. This is conveniently an even number of
/// partial rounds, making it easier to construct a Halo 2 circuit.
#[derive(Debug)]
pub struct P128Pow5T3<C> {
    _marker: PhantomData<C>,
}

impl<Fp: P128Pow5T3Constants> Spec<Fp, 3, 2> for P128Pow5T3<Fp> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        Fp::partial_rounds()
    }

    fn sbox(val: Fp) -> Fp {
        #[cfg(not(all(target_os = "zkvm", target_vendor = "succinct")))]
        {
            val.pow_vartime([5])
        }
        #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
        {
            unimplemented!()
        }
    }

    #[cfg(all(target_os = "zkvm", target_vendor = "succinct"))]
    fn sbox_inplace(val: &mut Fp) {
        const MEMCPY_32: u32 = 0x00_00_01_30;
        const BN254_SCALAR_MUL: u32 = 0x00_01_01_20;

        let mut a = MaybeUninit::<Fp>::uninit();

        unsafe {
            core::arch::asm!(
                "ecall",
                in("t0") MEMCPY_32,
                in("a0") val,
                in("a1") a.as_mut_ptr(),
            );
            core::arch::asm!(
                "ecall",
                in("t0") BN254_SCALAR_MUL,
                in("a0") &mut a,
                in("a1") val,
            );
            core::arch::asm!(
                "ecall",
                in("t0") BN254_SCALAR_MUL,
                in("a0") &mut a,
                in("a1") val,
            );
            core::arch::asm!(
                "ecall",
                in("t0") BN254_SCALAR_MUL,
                in("a0") &mut a,
                in("a1") val,
            );
            core::arch::asm!(
                "ecall",
                in("t0") BN254_SCALAR_MUL,
                in("a0") &mut a,
                in("a1") val,
            );
            core::arch::asm!(
                "ecall",
                in("t0") MEMCPY_32,
                in("a0") &a,
                in("a1") val,
            );
        };
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[Fp; 3]>, Mds<Fp, 3>, Mds<Fp, 3>) {
        (Fp::round_constants(), Fp::mds(), Fp::mds_inv())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use halo2curves::ff::{FromUniformBytes, PrimeField};

    use super::super::pasta::{fp, test_vectors, Fp};
    use crate::primitives::{permute, ConstantLength, Hash, Spec};

    /// The same Poseidon specification as poseidon::P128Pow5T3, but constructed
    /// such that its constants will be generated at runtime.
    #[derive(Debug)]
    pub struct P128Pow5T3Gen<F: PrimeField, const SECURE_MDS: usize>(PhantomData<F>);

    type P128Pow5T3Pasta = super::P128Pow5T3<Fp>;

    impl<F: PrimeField, const SECURE_MDS: usize> P128Pow5T3Gen<F, SECURE_MDS> {
        pub fn new() -> Self {
            P128Pow5T3Gen(PhantomData::default())
        }
    }

    impl<F: FromUniformBytes<64> + Ord + ExtraArithmetic, const SECURE_MDS: usize> Spec<F, 3, 2>
        for P128Pow5T3Gen<F, SECURE_MDS>
    {
        fn full_rounds() -> usize {
            8
        }

        fn partial_rounds() -> usize {
            56
        }

        fn sbox(val: F) -> F {
            val.pow_vartime(&[5])
        }

        fn secure_mds() -> usize {
            SECURE_MDS
        }
    }

    #[test]
    fn verify_constants() {
        fn verify_constants_helper<F: FromUniformBytes<64> + Ord + ExtraArithmetic>(
            expected_round_constants: [[F; 3]; 64],
            expected_mds: [[F; 3]; 3],
            expected_mds_inv: [[F; 3]; 3],
        ) {
            let (round_constants, mds, mds_inv) = P128Pow5T3Gen::<F, 0>::constants();

            for (actual, expected) in round_constants
                .iter()
                .flatten()
                .zip(expected_round_constants.iter().flatten())
            {
                assert_eq!(actual, expected);
            }

            for (actual, expected) in mds.iter().flatten().zip(expected_mds.iter().flatten()) {
                assert_eq!(actual, expected);
            }

            for (actual, expected) in mds_inv
                .iter()
                .flatten()
                .zip(expected_mds_inv.iter().flatten())
            {
                assert_eq!(actual, expected);
            }
        }

        verify_constants_helper(fp::ROUND_CONSTANTS, fp::MDS, fp::MDS_INV);
        //verify_constants_helper(fq::ROUND_CONSTANTS, fq::MDS, fq::MDS_INV);
    }

    #[test]
    fn test_against_reference() {
        {
            // <https://github.com/daira/pasta-hadeshash>, using parameters from
            // `generate_parameters_grain.sage 1 0 255 3 8 56 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`.
            // The test vector is generated by `sage poseidonperm_x5_pallas_3.sage --rust`

            let mut input = [
                Fp::from_raw([
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                Fp::from_raw([
                    0x0000_0000_0000_0001,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                Fp::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
            ];

            let expected_output = [
                Fp::from_raw([
                    0xaeb1_bc02_4aec_a456,
                    0xf7e6_9a71_d0b6_42a0,
                    0x94ef_b364_f966_240f,
                    0x2a52_6acd_0b64_b453,
                ]),
                Fp::from_raw([
                    0x012a_3e96_28e5_b82a,
                    0xdcd4_2e7f_bed9_dafe,
                    0x76ff_7dae_343d_5512,
                    0x13c5_d156_8b4a_a430,
                ]),
                Fp::from_raw([
                    0x3590_29a1_d34e_9ddd,
                    0xf7cf_dfe1_bda4_2c7b,
                    0x256f_cd59_7984_561a,
                    0x0a49_c868_c697_6544,
                ]),
            ];

            permute::<Fp, P128Pow5T3Gen<Fp, 0>, 3, 2>(&mut input, &fp::MDS, &fp::ROUND_CONSTANTS);
            assert_eq!(input, expected_output);
        }

        /*        {
                    // <https://github.com/daira/pasta-hadeshash>, using parameters from
                    // `generate_parameters_grain.sage 1 0 255 3 8 56 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001`.
                    // The test vector is generated by `sage poseidonperm_x5_vesta_3.sage --rust`

                    let mut input = [
                        Fq::from_raw([
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                        ]),
                        Fq::from_raw([
                            0x0000_0000_0000_0001,
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                        ]),
                        Fq::from_raw([
                            0x0000_0000_0000_0002,
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                            0x0000_0000_0000_0000,
                        ]),
                    ];

                    let expected_output = [
                        Fq::from_raw([
                            0x0eb0_8ea8_13be_be59,
                            0x4d43_d197_3dd3_36c6,
                            0xeddd_74f2_2f8f_2ff7,
                            0x315a_1f4c_db94_2f7c,
                        ]),
                        Fq::from_raw([
                            0xf9f1_26e6_1ea1_65f1,
                            0x413e_e0eb_7bbd_2198,
                            0x642a_dee0_dd13_aa48,
                            0x3be4_75f2_d764_2bde,
                        ]),
                        Fq::from_raw([
                            0x14d5_4237_2a7b_a0d9,
                            0x5019_bfd4_e042_3fa0,
                            0x117f_db24_20d8_ea60,
                            0x25ab_8aec_e953_7168,
                        ]),
                    ];

                    permute::<Fq, P128Pow5T3Gen<Fq, 0>, 3, 2>(&mut input, &fq::MDS, &fq::ROUND_CONSTANTS);
                    assert_eq!(input, expected_output);
                }
        */
    }

    #[test]
    fn permute_test_vectors() {
        {
            let (round_constants, mds, _) = P128Pow5T3Pasta::constants();

            for tv in test_vectors::fp::permute() {
                let mut state = [
                    Fp::from_repr(tv.initial_state[0]).unwrap(),
                    Fp::from_repr(tv.initial_state[1]).unwrap(),
                    Fp::from_repr(tv.initial_state[2]).unwrap(),
                ];

                permute::<Fp, P128Pow5T3Pasta, 3, 2>(&mut state, &mds, &round_constants);

                for (expected, actual) in tv.final_state.iter().zip(state.iter()) {
                    assert_eq!(&actual.to_repr(), expected);
                }
            }
        }
        /*
                {
                    let (round_constants, mds, _) = super::P128Pow5T3::constants();

                    for tv in crate::poseidon::primitives::test_vectors::fq::permute() {
                        let mut state = [
                            Fq::from_repr(tv.initial_state[0]).unwrap(),
                            Fq::from_repr(tv.initial_state[1]).unwrap(),
                            Fq::from_repr(tv.initial_state[2]).unwrap(),
                        ];

                        permute::<Fq, super::P128Pow5T3, 3, 2>(&mut state, &mds, &round_constants);

                        for (expected, actual) in tv.final_state.iter().zip(state.iter()) {
                            assert_eq!(&actual.to_repr(), expected);
                        }
                    }
                }
        */
    }

    #[test]
    fn hash_test_vectors() {
        for tv in test_vectors::fp::hash() {
            let message = [
                Fp::from_repr(tv.input[0]).unwrap(),
                Fp::from_repr(tv.input[1]).unwrap(),
            ];

            let result = Hash::<_, P128Pow5T3Pasta, ConstantLength<2>, 3, 2>::init().hash(message);

            assert_eq!(result.to_repr(), tv.output);
        }

        /*        for tv in crate::poseidon::primitives::test_vectors::fq::hash() {
                    let message = [
                        Fq::from_repr(tv.input[0]).unwrap(),
                        Fq::from_repr(tv.input[1]).unwrap(),
                    ];

                    let result =
                        Hash::<_, super::P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash(message);

                    assert_eq!(result.to_repr(), tv.output);
                }
        */
    }
}
