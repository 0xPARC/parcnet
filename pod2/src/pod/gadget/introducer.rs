use anyhow::{anyhow, Result};
use hashbrown::HashMap;
use plonky2::field::types::Field;
use plonky2::gates::noop::NoopGate;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, ProverCircuitData, VerifierCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use std::array;
use std::marker::PhantomData;
use std::time::Instant;

use crate::{PlonkyProof, C, D, F};

pub struct IntroducerCircuit {}

impl IntroducerCircuit {
    pub fn circuit_data() -> Result<CircuitData<F, C, D>> {
        todo!();
    }

    pub fn dummy_proof(circuit_data: CircuitData<F, C, D>) -> Result<PlonkyProof> {
        todo!();
    }
}
