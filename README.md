# poseidon-circuit

Poseidon hash circuit and primitives. It integrated several poseidon hash schemes from [zcash](https://github.com/zcash/halo2/tree/main/halo2_gadgets/src/poseidon) and [iden3](https://github.com/iden3/go-iden3-crypto/tree/master/poseidon) and support sponge progress for hashing messages in any length.


## Usage

To connect to the hash circuit, see `spec/hash-table.md`.

The circuit code can be implied with field which have satisified `Hashable` trait and currently only `poseidon-circuit::Bn256Fr` (the alias of `halo2_proofs::halo2curves::bn256::Fr`) has satisified this trait.

The circuit type under `hash::HashCircuit` prove poseidon hash progress base on permutation with 3 fields and a 2 fields rate. You also need to set a fixed step size for proving message hashing with variable length. A message has to be complied with an initial capacity size and for each sponge step the capacity would be substracted by the fixed step size. In the final step the capacity has to be equal or less than the fixed step.

For example, when we hashing a message with 19 fields:

1. You can use a circuit with fixed step size as `2`, and set the initialized capacity as `19` (i.e. the field len of input message). In each sponge progess the capacity is reduced by `2` and in final step it became `1`;

2. You can use a circuit with fixed step size as `32` and a initialized capacity between `298` to `320`.

The `DEFAULT_STEP` being decalred in the crate is `32`.


## Installation

Add `Cargo.toml` under `[dependencies]`:

```toml
[dependencies]
poseidon-circuit = { git = "https://github.com/scroll-tech/poseidon-circuit.git" }
```

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
