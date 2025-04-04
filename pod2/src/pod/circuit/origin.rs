use std::array;

use anyhow::Result;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use super::util::{matrix_ref, target_slice_eq};
use crate::pod::{
    gadget::GadgetID,
    origin::{Origin, ORIGIN_ID_SELF},
};
use crate::{D, F};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct OriginTarget {
    pub origin_id: [Target; 4],
    pub gadget_id: Target,
}

impl OriginTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            origin_id: builder.add_virtual_target_arr(),
            gadget_id: builder.add_virtual_target(),
        }
    }
    pub fn register_as_public_input(&self, builder: &mut CircuitBuilder<F, D>) {
        builder.register_public_inputs(&self.origin_id);
        builder.register_public_input(self.gadget_id);
    }
    pub fn to_targets(&self) -> Vec<Target> {
        [self.origin_id.to_vec(), vec![self.gadget_id]].concat()
    }
    pub fn from_targets(v: &[Target]) -> Self {
        Self {
            origin_id: array::from_fn(|i| v[i]),
            gadget_id: v[4],
        }
    }
    pub fn set_witness(&self, pw: &mut PartialWitness<F>, origin: &Origin) -> Result<()> {
        pw.set_target_arr(&self.origin_id, &origin.origin_id)?;
        pw.set_target(
            self.gadget_id,
            F::from_canonical_u64(origin.gadget_id as usize as u64),
        )?;
        Ok(())
    }
    pub fn none(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            origin_id: [builder.zero(); 4],
            gadget_id: builder.zero(),
        }
    }
    pub fn auto(builder: &mut CircuitBuilder<F, D>, gadget_id: GadgetID) -> Self {
        Self {
            origin_id: array::from_fn(|i| builder.constant(ORIGIN_ID_SELF[i])),
            gadget_id: builder.constant(GoldilocksField(gadget_id as u64)),
        }
    }
    pub fn is_self(&self, builder: &mut CircuitBuilder<F, D>) -> BoolTarget {
        let self_origin_id: [Target; 4] = array::from_fn(|i| builder.constant(ORIGIN_ID_SELF[i]));
        target_slice_eq(builder, &self.origin_id, &self_origin_id)
    }
}
