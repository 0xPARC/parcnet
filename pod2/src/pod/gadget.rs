use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum GadgetID {
    NONE = 0,
    SCHNORR16 = 1,
    ORACLE = 2,
}
