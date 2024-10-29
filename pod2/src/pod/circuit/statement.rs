use anyhow::{anyhow, Result};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};
use std::collections::HashMap;

use crate::pod::{
    gadget::GadgetID,
    statement::{AnchoredKey, Statement, StatementRef},
    util::hash_string_to_field,
    value::HashableEntryValue,
};
use crate::{C, D, F};

use super::{entry::EntryTarget, origin::OriginTarget};

// TODO: Maybe use this?
#[derive(Clone, Debug, PartialEq)]
pub struct AnchoredKeyTarget(pub OriginTarget, pub Target);

impl AnchoredKeyTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self(
            OriginTarget::new_virtual(builder),
            builder.add_virtual_target(),
        )
    }

    pub fn set_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        anchkey: &AnchoredKey,
    ) -> Result<()> {
        let Self(origin_target, key_target) = self;
        let AnchoredKey(origin, key) = anchkey;
        origin_target.set_witness(pw, origin)?;
        pw.set_target(*key_target, hash_string_to_field(key))?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StatementTarget {
    // Statement target as a vector of length 11.
    // Such a vector is of the form
    // [predicate] ++ origin1 ++ [key1] ++ origin2 ++ [key2] ++  origin3 ++ [key3] ++ [value]
    pub predicate: Target,
    pub origin1: OriginTarget,
    pub key1: Target,
    pub origin2: OriginTarget,
    pub key2: Target,
    pub origin3: OriginTarget,
    pub key3: Target,
    pub value: Target,
}

impl StatementTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            predicate: builder.add_virtual_target(),
            origin1: OriginTarget::new_virtual(builder),
            key1: builder.add_virtual_target(),
            origin2: OriginTarget::new_virtual(builder),
            key2: builder.add_virtual_target(),
            origin3: OriginTarget::new_virtual(builder),
            key3: builder.add_virtual_target(),
            value: builder.add_virtual_target(),
        }
    }
    pub fn to_targets(&self) -> Vec<Target> {
        [
            vec![self.predicate],
            self.origin1.to_targets(),
            vec![self.key1],
            self.origin2.to_targets(),
            vec![self.key2],
            self.origin3.to_targets(),
            vec![self.key3],
            vec![self.value],
        ]
        .concat()
    }
    pub fn from_targets(v: &[Target]) -> Self {
        Self {
            predicate: v[0],
            origin1: OriginTarget::from_targets(&[v[1], v[2]]),
            key1: v[3],
            origin2: OriginTarget::from_targets(&[v[4], v[5]]),
            key2: v[6],
            origin3: OriginTarget::from_targets(&[v[7], v[8]]),
            key3: v[9],
            value: v[10],
        }
    }
    pub fn set_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        statement: &Statement,
    ) -> Result<()> {
        pw.set_target_arr(&self.to_targets(), &statement.to_fields())
    }
    pub fn len() -> GoldilocksField {
        GoldilocksField(11)
    }
    // Constructors for statements?
    pub fn none(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            predicate: builder.constant(Statement::NONE),
            origin1: OriginTarget::none(builder),
            key1: builder.zero(),
            origin2: OriginTarget::none(builder),
            key2: builder.zero(),
            origin3: OriginTarget::none(builder),
            key3: builder.zero(),
            value: builder.zero(),
        }
    }
    pub fn value_of(
        builder: &mut CircuitBuilder<F, D>,
        origin: OriginTarget,
        key: Target,
        value: Target,
    ) -> Self {
        Self {
            predicate: builder.constant(Statement::VALUE_OF),
            origin1: origin,
            key1: key,
            origin2: OriginTarget::none(builder),
            key2: builder.zero(),
            origin3: OriginTarget::none(builder),
            key3: builder.zero(),
            value,
        }
    }
    pub fn equal(
        builder: &mut CircuitBuilder<F, D>,
        statement1_target: StatementTarget,
        statement2_target: StatementTarget,
    ) -> Self {
        Self {
            predicate: builder.constant(Statement::EQUAL),
            origin1: statement1_target.origin1,
            key1: statement1_target.key1,
            origin2: statement2_target.origin1,
            key2: statement2_target.key1,
            origin3: OriginTarget::none(builder),
            key3: builder.zero(),
            value: builder.zero(),
        }
    }
    pub fn not_equal(
        builder: &mut CircuitBuilder<F, D>,
        statement1_target: StatementTarget,
        statement2_target: StatementTarget,
    ) -> Self {
        Self {
            predicate: builder.constant(Statement::NOT_EQUAL),
            origin1: statement1_target.origin1,
            key1: statement1_target.key1,
            origin2: statement2_target.origin1,
            key2: statement2_target.key1,
            origin3: OriginTarget::none(builder),
            key3: builder.zero(),
            value: builder.zero(),
        }
    }
    pub fn from_entry(
        builder: &mut CircuitBuilder<F, D>,
        entry_target: &EntryTarget,
        this_gadget_id: GadgetID,
    ) -> Self {
        let origin = OriginTarget::auto(builder, this_gadget_id);
        Self::value_of(builder, origin, entry_target.key, entry_target.value)
    }

    pub fn constant(builder: &mut CircuitBuilder<F, D>, statement: &Statement) -> Self {
        Self::from_targets(
            &statement
                .to_fields()
                .into_iter()
                .map(|x| builder.constant(x))
                .collect::<Vec<_>>(),
        )
    }

    pub fn connect(&self, builder: &mut CircuitBuilder<F, D>, statement_target: &Self) {
        std::iter::zip(Self::to_targets(self), Self::to_targets(statement_target))
            .for_each(|(s1, s2)| builder.connect(s1, s2));
    }

    pub fn remap_origins(
        self,
        builder: &mut CircuitBuilder<F, D>,
        origin_id_map: &[Vec<Target>],
        pod_index: Target,
    ) -> Result<Self> {
        Ok(Self {
            predicate: self.predicate,
            origin1: self.origin1.remap(builder, origin_id_map, pod_index)?,
            key1: self.key1,
            origin2: self.origin2.remap(builder, origin_id_map, pod_index)?,
            key2: self.key2,
            origin3: self.origin3.remap(builder, origin_id_map, pod_index)?,
            key3: self.key3,
            value: self.value,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StatementRefTarget {
    pub pod_index: Target,
    pub statement_index: Target,
}

impl StatementRefTarget {
    pub fn new_virtual(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            pod_index: builder.add_virtual_target(),
            statement_index: builder.add_virtual_target(),
        }
    }
    pub fn set_witness(
        &self,
        pw: &mut PartialWitness<GoldilocksField>,
        (pod_index, statement_index): (usize, usize),
    ) -> Result<()> {
        pw.set_target_arr(
            &[self.pod_index, self.statement_index],
            &[
                GoldilocksField::from_canonical_u64(pod_index as u64),
                GoldilocksField::from_canonical_u64(statement_index as u64),
            ],
        )
    }
}
