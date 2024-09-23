use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigInt;

fn bigint_to_fr(input: &BigInt) -> Fr {
    let (_, bytes) = input.to_bytes_be();
    Fr::from_be_bytes_mod_order(&bytes)
}

pub fn hash_bigints(inputs: &[BigInt]) -> Result<BigInt, &'static str> {
    if inputs.is_empty() {
        return Err("At least one input is required");
    }

    let mut poseidon =
        Poseidon::<Fr>::new_circom(inputs.len()).map_err(|_| "Failed to initialize Poseidon")?;

    let fr_inputs: Vec<Fr> = inputs.iter().map(bigint_to_fr).collect();

    let hash = poseidon.hash(&fr_inputs).map_err(|_| "Hashing failed")?;
    let big_int_ark = hash.into_bigint();
    let bytes = big_int_ark.to_bytes_be();
    Ok(BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes))
}
