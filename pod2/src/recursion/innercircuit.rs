use anyhow::Result;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, NUM_HASH_OUT_ELTS};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::{C, D, F};

/// InnerCircuit is the trait that is used to define the logic of the circuit that is used at each
/// node of the recursive tree.
///
/// Each node of the recursion tree verifies N times
/// `(InnerCircuit OR recursive-proof-verification)`.
///
/// An example implementing the InnerCircuit can be found at `./example_innercircuit.rs`
pub trait InnerCircuit {
    type Input;
    type Targets;

    /// set up the circuit logic
    fn add_targets(
        builder: &mut CircuitBuilder<F, D>,
        selector_booltarg: &BoolTarget,
        hash_targ: &HashOutTarget,
    ) -> Result<Self::Targets>;

    /// set the actual witness values for the current instance of the circuit
    fn set_targets(
        pw: &mut PartialWitness<F>,
        targets: &Self::Targets,
        input: &Self::Input,
    ) -> Result<()>;
}
