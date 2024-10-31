use anyhow::Result;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use super::util::matrix_ref;
use crate::pod::{gadget::GadgetID, origin::Origin};
use crate::{D, F};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct OriginTarget {
    pub origin_id: Target,
    pub gadget_id: Target,
}

impl OriginTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            origin_id: builder.add_virtual_target(),
            gadget_id: builder.add_virtual_target(),
        }
    }
    pub fn register_as_public_input(&self, builder: &mut CircuitBuilder<F, D>) {
        builder.register_public_input(self.origin_id);
        builder.register_public_input(self.gadget_id);
    }
    pub fn to_targets(&self) -> Vec<Target> {
        vec![self.origin_id, self.gadget_id]
    }
    pub fn from_targets(v: &[Target]) -> Self {
        Self {
            origin_id: v[0],
            gadget_id: v[1],
        }
    }
    pub fn set_witness(&self, pw: &mut PartialWitness<F>, origin: &Origin) -> Result<()> {
        pw.set_target(self.origin_id, origin.origin_id)?;
        pw.set_target(
            self.gadget_id,
            F::from_canonical_u64(origin.gadget_id as usize as u64),
        )?;
        Ok(())
    }
    pub fn none(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            origin_id: builder.zero(),
            gadget_id: builder.zero(),
        }
    }
    pub fn auto(builder: &mut CircuitBuilder<F, D>, gadget_id: GadgetID) -> Self {
        Self {
            origin_id: builder.constant(Origin::SELF.origin_id),
            gadget_id: builder.constant(GoldilocksField(gadget_id as u64)),
        }
    }

    pub fn remap(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        origin_id_map: &[Vec<Target>],
        pod_index: Target,
    ) -> Result<Self> {
        Ok(Self {
            origin_id: matrix_ref(builder, &origin_id_map, pod_index, self.origin_id)?,
            gadget_id: self.gadget_id,
        })
    }
}
