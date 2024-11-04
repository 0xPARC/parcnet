use anyhow::Result;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

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
