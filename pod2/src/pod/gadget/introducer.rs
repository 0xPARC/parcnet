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

/// IntroducerCircuit defines the circuit whose plonky2 proof is verified in the RecursiveCircuit
/// (1-level recursion). This is, the POD1-Introducer circuit.
// TODO probably traitify this, and in the RecursionCircuit use the trait and not this specific
// struct directly.
// But for the moment we can implement here the circuit that verifies a POD1 (POD1-Introducer).
impl IntroducerCircuit {
    pub fn circuit_data() -> Result<CircuitData<F, C, D>> {
        let config = CircuitConfig::standard_recursion_zk_config();

        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        Self::circuit_logic(&mut builder);

        let data = builder.build::<C>();
        Ok(data)
    }

    pub fn dummy_proof(circuit_data: CircuitData<F, C, D>) -> Result<PlonkyProof> {
        let inputs = PartialWitness::new();
        let proof = circuit_data.prove(inputs)?;
        Ok(proof.proof)
    }

    pub fn circuit_logic(builder: &mut CircuitBuilder<F, D>) {
        let num_dummy_gates = 5_000;
        for _ in 0..num_dummy_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }
}
