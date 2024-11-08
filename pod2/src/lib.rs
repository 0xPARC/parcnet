#![feature(array_try_from_fn)]
#![feature(generic_const_exprs)]
#![allow(clippy::new_without_default)]
#![allow(incomplete_features)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::Proof;

pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;
pub const D: usize = 2;
pub type PlonkyProof = Proof<F, PoseidonGoldilocksConfig, D>;

// For the purposes of inequality checks, we assume values are of type
// u32.
pub const NUM_BITS: usize = 32;

pub mod plonky2_u32;
pub mod pod;
pub mod recursion;
pub mod signature;

// expose the main structs & traits at the high level
pub use pod::{PODProof, POD};
