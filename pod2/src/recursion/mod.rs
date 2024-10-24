pub mod example_innercircuit;
pub mod innercircuit;
pub mod recursion_framework;
pub mod utils;

// expose at the recursion module level the objects needed to use it
pub use innercircuit::InnerCircuit;
pub use recursion_framework::{RecursionCircuit, RecursionTree};
