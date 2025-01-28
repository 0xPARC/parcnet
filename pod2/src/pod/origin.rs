use anyhow::Result;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
use serde::{Deserialize, Serialize};

use super::{gadget::GadgetID, ContentID};

pub type OriginID = ContentID;

pub const ORIGIN_ID_NONE: OriginID = [GoldilocksField::ZERO,GoldilocksField::ZERO, GoldilocksField::ZERO, GoldilocksField::ZERO];
pub const ORIGIN_ID_SELF: OriginID = [GoldilocksField::ONE,GoldilocksField::ZERO, GoldilocksField::ZERO, GoldilocksField::ZERO];

pub const ORIGIN_NAME_NONE: &'static str = "_NONE";
pub const ORIGIN_NAME_SELF: &'static str = "_SELF ";

// An Origin, which represents a reference to an ancestor POD.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
pub struct Origin {
    pub origin_id: OriginID, // reserve 0 for NONE, 1 for SELF
    pub origin_name: String,
    pub gadget_id: GadgetID, // if origin_id is SELF, this is none; otherwise, it's the gadget_id
}

impl Origin {
    pub fn new(origin_id: OriginID, origin_name: String, gadget_id: GadgetID) -> Self {
        Origin {
            origin_id,
            origin_name,
            gadget_id,
        }
    }
    pub const NONE: Self = Origin {
        origin_id: ORIGIN_ID_NONE,
        origin_name: String::new(),
        gadget_id: GadgetID::NONE,
    };
    pub const SELF: Self = Origin {
        origin_id: ORIGIN_ID_SELF,
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
    pub fn is_self(&self) -> bool {
        self.origin_id == ORIGIN_ID_SELF
    }
    /// Field representation as a vector of length 2.
    pub fn to_fields(&self) -> Vec<GoldilocksField> {
        [self.origin_id.to_vec(),vec![
            GoldilocksField::from_canonical_u64(self.gadget_id as u64),
        ]].concat()
    }
    // Remap origin according to name-based rule.
    pub fn remap(&self, f: &dyn Fn(&str) -> Result<(String, OriginID)>) -> Result<Self> {
        let (new_origin_name, new_origin_id) = f(&self.origin_name)?;
        Ok(Self::new(new_origin_id, new_origin_name, self.gadget_id))
    }
}
