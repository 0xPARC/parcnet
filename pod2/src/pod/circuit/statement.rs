use std::array;

use anyhow::Result;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::HashOutTarget,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::pod::{
    gadget::GadgetID,
    statement::{AnchoredKey, Statement},
    util::hash_string_to_field,
};
use crate::{D, F};

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
    pub fn register_as_public_input(&self, builder: &mut CircuitBuilder<F, D>) {
        builder.register_public_input(self.predicate);
        self.origin1.register_as_public_input(builder);
        builder.register_public_input(self.key1);
        self.origin2.register_as_public_input(builder);
        builder.register_public_input(self.key2);
        self.origin3.register_as_public_input(builder);
        builder.register_public_input(self.key3);
        builder.register_public_input(self.value);
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
            origin1: OriginTarget::from_targets(&v[1..6]),
            key1: v[6],
            origin2: OriginTarget::from_targets(&v[7..12]),
            key2: v[12],
            origin3: OriginTarget::from_targets(&v[13..18]),
            key3: v[18],
            value: v[19],
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

    pub fn gt(
        builder: &mut CircuitBuilder<F, D>,
        statement1_target: StatementTarget,
        statement2_target: StatementTarget,
    ) -> Self {
        Self {
            predicate: builder.constant(Statement::GT),
            origin1: statement1_target.origin1,
            key1: statement1_target.key1,
            origin2: statement2_target.origin1,
            key2: statement2_target.key1,
            origin3: OriginTarget::none(builder),
            key3: builder.zero(),
            value: builder.zero(),
        }
    }

    pub fn contains(
        builder: &mut CircuitBuilder<F, D>,
        statement1_target: StatementTarget,
        statement2_target: StatementTarget,
    ) -> Self {
        Self {
            predicate: builder.constant(Statement::CONTAINS),
            origin1: statement1_target.origin1,
            key1: statement1_target.key1,
            origin2: statement2_target.origin1,
            key2: statement2_target.key1,
            origin3: OriginTarget::none(builder),
            key3: builder.zero(),
            value: builder.zero(),
        }
    }

    pub fn rename_contained_by(
        builder: &mut CircuitBuilder<F, D>,
        statement1_target: StatementTarget,
        statement2_target: StatementTarget,
    ) -> Self {
        Self {
            predicate: builder.constant(Statement::CONTAINS),
            origin1: statement2_target.origin2,
            key1: statement2_target.key2,
            origin2: statement1_target.origin2,
            key2: statement1_target.key2,
            origin3: OriginTarget::none(builder),
            key3: builder.zero(),
            value: builder.zero(),
        }
    }

    pub fn sum_of(
        builder: &mut CircuitBuilder<F, D>,
        statement1_target: StatementTarget,
        statement2_target: StatementTarget,
        statement3_target: StatementTarget,
    ) -> Self {
        Self {
            predicate: builder.constant(Statement::SUM_OF),
            origin1: statement1_target.origin1,
            key1: statement1_target.key1,
            origin2: statement2_target.origin1,
            key2: statement2_target.key1,
            origin3: statement3_target.origin1,
            key3: statement3_target.key1,
            value: builder.zero(),
        }
    }

    pub fn product_of(
        builder: &mut CircuitBuilder<F, D>,
        statement1_target: StatementTarget,
        statement2_target: StatementTarget,
        statement3_target: StatementTarget,
    ) -> Self {
        Self {
            predicate: builder.constant(Statement::PRODUCT_OF),
            origin1: statement1_target.origin1,
            key1: statement1_target.key1,
            origin2: statement2_target.origin1,
            key2: statement2_target.key1,
            origin3: statement3_target.origin1,
            key3: statement3_target.key1,
            value: builder.zero(),
        }
    }

    pub fn max_of(
        builder: &mut CircuitBuilder<F, D>,
        statement1_target: StatementTarget,
        statement2_target: StatementTarget,
        statement3_target: StatementTarget,
    ) -> Self {
        Self {
            predicate: builder.constant(Statement::MAX_OF),
            origin1: statement1_target.origin1,
            key1: statement1_target.key1,
            origin2: statement2_target.origin1,
            key2: statement2_target.key1,
            origin3: statement3_target.origin1,
            key3: statement3_target.key1,
            value: builder.zero(),
        }
    }

    pub fn lt(
        builder: &mut CircuitBuilder<F, D>,
        statement1_target: StatementTarget,
        statement2_target: StatementTarget,
    ) -> Self {
        Self {
            predicate: builder.constant(Statement::LT),
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

    pub fn has_code(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        code: GoldilocksField,
    ) -> BoolTarget {
        let code_target = builder.constant(code);
        builder.is_equal(self.predicate, code_target)
    }

    pub fn connect(&self, builder: &mut CircuitBuilder<F, D>, statement_target: &Self) {
        std::iter::zip(Self::to_targets(self), Self::to_targets(statement_target))
            .for_each(|(s1, s2)| builder.connect(s1, s2));
    }

    pub fn remap_origins(
        self,
        builder: &mut CircuitBuilder<F, D>,
        content_id_target: HashOutTarget,
    ) -> Result<Self> {
        let remapped_origin = [self.origin1, self.origin2, self.origin2]
            .iter()
            .map(|o| {
                let origin_is_self = o.is_self(builder);
                OriginTarget {
                    origin_id: array::from_fn(|i| {
                        builder.select(
                            origin_is_self,
                            content_id_target.elements[i],
                            o.origin_id[i],
                        )
                    }),
                    gadget_id: o.gadget_id,
                }
            })
            .collect::<Vec<_>>();

        Ok(Self {
            predicate: self.predicate,
            origin1: remapped_origin[0],
            key1: self.key1,
            origin2: remapped_origin[1],
            key2: self.key2,
            origin3: remapped_origin[2],
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
