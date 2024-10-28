pub mod recursion_framework;
pub mod traits;
pub mod traits_examples;
pub mod utils;

// expose at the recursion module level the objects needed to use it
pub use recursion_framework::{RecursionCircuit, RecursionTree};
pub use traits::{InnerCircuitTrait, OpsExecutorTrait};
