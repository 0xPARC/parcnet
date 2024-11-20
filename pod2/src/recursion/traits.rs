use anyhow::Result;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use plonky2::gates::noop::NoopGate;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, ProverCircuitData};

use crate::{PlonkyProof, C, D, F};

/// IntroducerCircuitTrait defines the circuit whose plonky2 proof is verified in the
/// RecursiveCircuit (1-level recursion). This is, the POD1-Introducer circuit.
///
/// Notice that the methods `circuit_data`, `dummy_proof`, `build_prover` are already implemented
/// at the trait level, in a generic way agnostic to the specific logic of the circuit. So the only
/// methods that need to be implemented are `add_targets` and `set_targets`.
pub trait IntroducerCircuitTrait {
    type Targets;
    type Input;

    /// return dummy inputs that will satisfy the circuit. This is used to generate the
    /// dummy_proof.
    fn dummy_inputs() -> Result<Self::Input>;

    /// set up the circuit logic
    fn add_targets(builder: &mut CircuitBuilder<F, D>) -> Result<Self::Targets>;

    /// set the actual witness values for the current instance of the circuit
    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
    ) -> Result<()>;

    /// Note: the following methods are implemented at trait level, hence don't need to be
    /// implemented in the concrete structs that implement the trait.

    fn circuit_data() -> Result<CircuitData<F, C, D>> {
        // let config = CircuitConfig::standard_recursion_zk_config(); // TODO rm
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        Self::add_targets(&mut builder)?;

        // pad min gates
        while builder.num_gates() < 1 << 12 {
            builder.add_gate(NoopGate, vec![]);
        }

        let data = builder.build::<C>();
        Ok(data)
    }
    fn dummy_proof(circuit_data: CircuitData<F, C, D>) -> Result<PlonkyProof> {
        // fn dummy_proof(prover: ProverCircuitData<F, C, D>) -> Result<PlonkyProof> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);

        // prepare some dummy signature
        let input = Self::dummy_inputs()?;

        let targets = Self::add_targets(&mut builder)?;
        // pad min gates
        while builder.num_gates() < 1 << 12 {
            builder.add_gate(NoopGate, vec![]);
        }

        let mut pw = PartialWitness::new();
        Self::set_targets(&mut pw, &targets, &input)?;

        let proof = circuit_data.prove(pw)?;
        Ok(proof.proof)
    }
    fn build_prover() -> Result<ProverCircuitData<F, C, D>> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::new(config);

        let _ = Self::add_targets(&mut builder)?;
        // pad min gates
        while builder.num_gates() < 1 << 12 {
            builder.add_gate(NoopGate, vec![]);
        }

        Ok(builder.build_prover::<C>())
    }
}

/// InnerCircuit is the trait that is used to define the logic of the circuit that is used at each
/// node of the recursive tree.
///
/// Each node of the recursion tree verifies N times
/// `(InnerCircuit OR recursive-proof-verification)`.
///
/// An example implementing the InnerCircuit can be found at `./example_innercircuit.rs`
pub trait InnerCircuitTrait {
    type Targets;
    type Input;

    /// set up the circuit logic
    fn add_targets(
        builder: &mut CircuitBuilder<F, D>,
        selector_booltarg: &BoolTarget,
    ) -> Result<Self::Targets>;

    /// set the actual witness values for the current instance of the circuit. Returns a Vec<F>
    /// containing the values that will be set as public inputs
    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
    ) -> Result<Vec<F>>;
}

pub trait OpsExecutorTrait {
    type Input;
    type Output;
    type Targets;

    /// sets up the circuit logic
    fn add_targets(builder: &mut CircuitBuilder<F, D>) -> Result<Self::Targets>;

    /// assigns the given Input to the given Targets. Returns a Vec<F> containing the values that
    /// will be set as public inputs
    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
        output: &Self::Output,
    ) -> Result<Vec<F>>;
}
