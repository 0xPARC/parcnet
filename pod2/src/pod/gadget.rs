use core::fmt;

use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum GadgetID {
    NONE = 0,
    SCHNORR16 = 1,
    ORACLE = 2,
    PLONKY = 3, // plonky2 recursive proof
}

impl fmt::Display for GadgetID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GadgetID::NONE => write!(f, "NONE"),
            GadgetID::SCHNORR16 => write!(f, "SCHNORR16"),
            GadgetID::ORACLE => write!(f, "ORACLE"),
            GadgetID::PLONKY => write!(f, "PLONKY")
        }
    }
}
