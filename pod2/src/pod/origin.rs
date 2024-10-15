use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

use super::gadget::GadgetID;

// An Origin, which represents a reference to an ancestor POD.
#[derive(Clone, Debug, PartialEq)]
pub struct Origin {
    pub origin_id: GoldilocksField, // reserve 0 for NONE, 1 for SELF
    pub origin_name: String,
    pub gadget_id: GadgetID, // if origin_id is SELF, this is none; otherwise, it's the gadget_id
}

impl Origin {
    pub fn new(origin_id: GoldilocksField, origin_name: String, gadget_id: GadgetID) -> Self {
        Origin {
            origin_id,
            origin_name,
            gadget_id,
        }
    }
    pub const NONE: Self = Origin {
        origin_id: GoldilocksField::ZERO,
        origin_name: String::new(),
        gadget_id: GadgetID::NONE,
    };
    pub const SELF: Self = Origin {
        origin_id: GoldilocksField(1),
        origin_name: String::new(),
        gadget_id: GadgetID::NONE,
    };
    pub fn none(origin_name: String, gadget_id: GadgetID) -> Self {
        Self::new(Self::NONE.origin_id, origin_name, gadget_id)
    }
    /// 'auto' for 'self', because 'self' is a reserved keyword!
    pub fn auto(origin_name: String, gadget_id: GadgetID) -> Self {
        Self::new(Self::SELF.origin_id, origin_name, gadget_id)
    }
}
