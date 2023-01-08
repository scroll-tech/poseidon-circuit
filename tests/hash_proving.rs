use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::{
    bn256::{Bn256, Fr as Fp, G1Affine},
    group::ff::PrimeField,
};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::kzg::commitment::{
    KZGCommitmentScheme, ParamsKZG as Params, ParamsVerifierKZG as ParamsVerifier,
};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
};
use poseidon_circuit::{hash, DEFAULT_STEP};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[test]
fn hash_circuit() {
    let message1 = [
        Fp::from_str_vartime("1").unwrap(),
        Fp::from_str_vartime("2").unwrap(),
    ];
    let message2 = [
        Fp::from_str_vartime("0").unwrap(),
        Fp::from_str_vartime("1").unwrap(),
    ];

    let k = 7;
    let circuit = hash::HashCircuit::<Fp, DEFAULT_STEP> {
        inputs: vec![message1, message2],
        calcs: 3,
        ..Default::default()
    };
    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn vk_validity() {
    let params = Params::<Bn256>::unsafe_setup(8);

    let circuit = hash::HashCircuit::<Fp, DEFAULT_STEP> {
        calcs: 3,
        ..Default::default()
    };
    let vk1 = keygen_vk(&params, &circuit).unwrap();

    let mut vk1_buf: Vec<u8> = Vec::new();
    vk1.write(&mut vk1_buf).unwrap();

    let circuit = hash::HashCircuit::<Fp, DEFAULT_STEP> {
        inputs: vec![
            [
                Fp::from_str_vartime("1").unwrap(),
                Fp::from_str_vartime("2").unwrap(),
            ],
            [
                Fp::from_str_vartime("0").unwrap(),
                Fp::from_str_vartime("1").unwrap(),
            ],
        ],
        calcs: 3,
        ..Default::default()
    };
    let vk2 = keygen_vk(&params, &circuit).unwrap();

    let mut vk2_buf: Vec<u8> = Vec::new();
    vk2.write(&mut vk2_buf).unwrap();

    assert_eq!(vk1_buf, vk2_buf);
}

#[test]
fn proof_and_verify() {
    let k = 8;

    let params = Params::<Bn256>::unsafe_setup(k);
    let os_rng = ChaCha8Rng::from_seed([101u8; 32]);
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    let circuit = hash::HashCircuit::<Fp, DEFAULT_STEP> {
        inputs: vec![
            [
                Fp::from_str_vartime("1").unwrap(),
                Fp::from_str_vartime("2").unwrap(),
            ],
            [
                Fp::from_str_vartime("0").unwrap(),
                Fp::from_str_vartime("1").unwrap(),
            ],
        ],
        calcs: 3,
        ..Default::default()
    };

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        os_rng,
        &mut transcript,
    )
    .unwrap();

    let proof_script = transcript.finalize();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_script[..]);
    let verifier_params: ParamsVerifier<Bn256> = params.verifier_params().clone();
    let strategy = SingleStrategy::new(&params);
    let circuit = hash::HashCircuit::<Fp, DEFAULT_STEP> {
        calcs: 3,
        ..Default::default()
    };
    let vk = keygen_vk(&params, &circuit).unwrap();

    assert!(
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &verifier_params,
            &vk,
            strategy,
            &[&[]],
            &mut transcript
        )
        .is_ok()
    );
}
