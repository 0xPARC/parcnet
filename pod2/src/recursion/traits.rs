use anyhow::Result;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::pod::{circuit::statement::StatementTarget, gadget::GadgetID};
use crate::{D, F};

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
        // hash_targ: &HashOutTarget,
    ) -> Result<Self::Targets>;

    /// set the actual witness values for the current instance of the circuit
    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
    ) -> Result<()>;
}

pub trait OpsExecutorTrait {
    // NP is the associated constant to set the maximum Number of PODs that the OpsExecutor references
    const NP: usize;

    // NS is the associated constant to set the Number of Statements that the OpsExecutor uses
    const NS: usize;
    
    type Input;
    type Output;
    type Targets;

    /// sets up the circuit logic
    fn add_targets(builder: &mut CircuitBuilder<F, D>) -> Result<Self::Targets>;

    /// assigns the given Input to the given Targets
    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
        output: &Self::Output
    ) -> Result<()>;
}
