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

use crate::pod::gadget::SchnorrPODGadget;
use crate::recursion::IntroducerCircuitTrait;
use crate::{PlonkyProof, C, D, F};

pub struct IntroducerCircuit {}

/// IntroducerCircuit defines the circuit whose plonky2 proof is verified in the RecursiveCircuit
/// (1-level recursion). This is, the POD1-Introducer circuit.
impl IntroducerCircuitTrait for IntroducerCircuit {
    type Input = (); // TODO
    type Targets = ();

    /// return dummy inputs that will satisfy the circuit. This is used to generate the
    /// dummy_proof.
    fn dummy_inputs() -> Result<Self::Input> {
        todo!();
    }

    /// set up the circuit logic
    fn add_targets(builder: &mut CircuitBuilder<F, D>) -> Result<Self::Targets> {
        todo!();
    }

    /// set the actual witness values for the current instance of the circuit. Returns a Vec<F>
    /// containing the values that will be set as public inputs
    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
    ) -> Result<()> {
        todo!();
    }
}
