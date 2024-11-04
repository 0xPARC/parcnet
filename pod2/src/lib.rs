#![feature(array_try_from_fn)]
#![feature(generic_const_exprs)]
#![allow(clippy::new_without_default)]
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

pub mod pod;
pub mod recursion;
pub mod signature;
