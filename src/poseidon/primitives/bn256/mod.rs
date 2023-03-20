pub(crate) use halo2_proofs::halo2curves::bn256::Fr as Fp;

use super::p128pow5t3::P128Pow5T3Constants;
use super::Mds;

pub(crate) mod fp;

impl P128Pow5T3Constants for Fp {
    fn partial_rounds() -> usize {
        57
    }

    fn round_constants() -> Vec<[Fp; 3]> {
        fp::ROUND_CONSTANTS.to_vec()
    }
    fn mds() -> Mds<Fp, 3> {
        *fp::MDS
    }
    fn mds_inv() -> Mds<Fp, 3> {
        *fp::MDS_INV
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use crate::poseidon::primitives::{permute, P128Pow5T3, P128Pow5T3Compact, Spec};

    use super::*;

    /// The same Poseidon specification as poseidon::P128Pow5T3, but constructed
    /// such that its constants will be generated at runtime.
    #[derive(Debug)]
    pub struct P128Pow5T3Gen<F: P128Pow5T3Constants>(PhantomData<F>);

    impl<F: P128Pow5T3Constants> P128Pow5T3Gen<F> {
        pub fn new() -> Self {
            P128Pow5T3Gen(PhantomData::default())
        }
    }

    impl<F: P128Pow5T3Constants> Spec<F, 3, 2> for P128Pow5T3Gen<F> {
        fn full_rounds() -> usize {
            P128Pow5T3::<F>::full_rounds()
        }

        fn partial_rounds() -> usize {
            P128Pow5T3::<F>::partial_rounds()
        }

        fn sbox(val: F) -> F {
            P128Pow5T3::<F>::sbox(val)
        }

        fn secure_mds() -> usize {
            0
        }

        // fn constants(): default implementation that generates the parameters.
    }

    #[test]
    fn verify_constants_generation() {
        let (round_constants, mds, mds_inv) = P128Pow5T3Gen::<Fp>::constants();
        let (round_constants2, mds2, mds_inv2) = P128Pow5T3::<Fp>::constants();

        assert_eq!(round_constants.len(), 57 + 8);
        assert_eq!(round_constants, round_constants2);
        assert_eq!(mds, mds2);
        assert_eq!(mds_inv, mds_inv2);
    }

    #[test]
    fn verify_constants() {
        let c = fp::ROUND_CONSTANTS.to_vec();
        let m = *fp::MDS;

        assert_eq!(
            format!("{:?}", c[0][0]),
            "0x0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e"
        );
        assert_eq!(
            format!("{:?}", c[c.len() - 1][2]),
            "0x1da55cc900f0d21f4a3e694391918a1b3c23b2ac773c6b3ef88e2e4228325161"
        );
        assert_eq!(
            format!("{:?}", m[0][0]),
            "0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b"
        );
        assert_eq!(
            format!("{:?}", m[m.len() - 1][0]),
            "0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7"
        );
    }

    // Verify that MDS * MDS^-1 = I.
    #[test]
    fn verify_mds() {
        let mds = <Fp as P128Pow5T3Constants>::mds();
        let mds_inv = <Fp as P128Pow5T3Constants>::mds_inv();

        #[allow(clippy::needless_range_loop)]
        for i in 0..3 {
            for j in 0..3 {
                let expected = if i == j { Fp::one() } else { Fp::zero() };
                assert_eq!(
                    (0..3).fold(Fp::zero(), |acc, k| acc + (mds[i][k] * mds_inv[k][j])),
                    expected
                );
            }
        }
    }

    #[test]
    fn test_compact_constants() {
        let input = [
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

        let output = {
            let mut state = input.clone();

            let (rc, mds, _inv) = P128Pow5T3::<Fp>::constants();
            permute::<Fp, P128Pow5T3<Fp>, 3, 2>(&mut state, &mds, &rc[..]);

            // This is the raw form with 3 constants per round.
            assert_ne!(rc[4][1], Fp::zero());

            state
        };

        let output_compact = {
            let mut state = input.clone();

            let (rc, mds, _inv) = P128Pow5T3Compact::<Fp>::constants();
            permute::<Fp, P128Pow5T3Compact<Fp>, 3, 2>(&mut state, &mds, &rc[..]);

            // This is the compact form with 1 constant per partial round.
            for i in 4..4 + 57 {
                assert_eq!(rc[i][1], Fp::zero());
                assert_eq!(rc[i][2], Fp::zero());
            }

            state
        };

        assert_eq!(output, output_compact);
    }
}
