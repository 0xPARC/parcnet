#[macro_use]
extern crate lazy_static;

pub mod crypto;
use crate::crypto::poseidon_hash;
use num_bigint::BigInt;
use std::str::FromStr;

fn main() {
    // Example usage with multiple inputs
    let input_strs = vec!["10"];
    let inputs: Vec<BigInt> = input_strs
        .iter()
        .map(|s| BigInt::from_str(s).unwrap())
        .collect();

    match poseidon_hash::hash_bigints(&inputs) {
        Ok(result) => println!("Hash result: {:?}", result),
        Err(e) => eprintln!("Error: {}", e),
    }
}
