use std::collections::HashMap;

use crate::schnorr_prover::{
    MessageTarget, SchnorrBuilder, SchnorrPublicKeyTarget, SchnorrSignatureTarget,
    SignatureVerifierBuilder,
};
use anyhow::{anyhow, Result};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::{self, CircuitBuilder};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::util::log2_ceil;
use statement::StatementTarget;

use super::util::hash_string_to_field;
use super::PODProof;
use super::{HashablePayload, POD};

pub mod origin;
pub mod pod;
pub mod statement;
mod util;
