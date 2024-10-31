use core::fmt;
use std::{collections::HashMap, fmt::Debug};

use anyhow::{anyhow, Result};
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
use serde::{Deserialize, Serialize};

use super::{
    entry::Entry,
    gadget::GadgetID,
    origin::Origin,
    util::hash_string_to_field,
    value::{HashableEntryValue, ScalarOrVec},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AnchoredKey(pub Origin, pub String);

impl Default for AnchoredKey {
    fn default() -> Self {
        AnchoredKey(Origin::default(), String::new())
    }
}

impl AnchoredKey {
    pub fn eq(&self, ak: &AnchoredKey) -> bool {
        let AnchoredKey(self_origin, self_key) = self;
        let AnchoredKey(other_origin, other_key) = ak;
        (self_origin.origin_id == other_origin.origin_id) && (self_key == other_key)
    }
    /// Field representation as a vector of length 3.
    pub fn to_fields(&self) -> Vec<GoldilocksField> {
        let AnchoredKey(origin, key) = self;
        [origin.to_fields(), vec![hash_string_to_field(key)]].concat()
    }
    pub fn remap_origin(
        &self,
        f: &dyn Fn(&str) -> Result<(String, GoldilocksField)>,
    ) -> Result<Self> {
        let AnchoredKey(origin, key) = self;
        Ok(AnchoredKey(origin.remap(f)?, key.clone()))
    }
}

impl fmt::Display for AnchoredKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let AnchoredKey(origin, key) = self;
        if origin.origin_name == "_SELF" {
            write!(f, "{}", key)
        } else {
            write!(f, "{}:{}", origin.origin_name, key)
        }
    }
}

impl fmt::Display for Statement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Statement::None => write!(f, "None"),
            Statement::ValueOf(key, value) => write!(f, "ValueOf({} = {:?})", key, value),
            Statement::Equal(op1, op2) => write!(f, "Equal({} = {})", op1, op2),
            Statement::NotEqual(op1, op2) => write!(f, "NotEqual({} ≠ {})", op1, op2),
            Statement::Gt(op1, op2) => write!(f, "Gt({} > {})", op1, op2),
            Statement::Lt(op1, op2) => write!(f, "Lt({} > {})", op1, op2),
            Statement::Contains(op1, op2) => write!(f, "Contains({} ∈ {})", op1, op2),
            Statement::SumOf(result, op1, op2) => {
                write!(f, "SumOf({} = {} + {})", result, op1, op2)
            }
            Statement::ProductOf(result, op1, op2) => {
                write!(f, "ProductOf({} = {} × {})", result, op1, op2)
            }
            Statement::MaxOf(result, op1, op2) => {
                write!(f, "MaxOf({} = max({}, {}))", result, op1, op2)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum Statement {
    None,
    ValueOf(AnchoredKey, ScalarOrVec),
    Equal(AnchoredKey, AnchoredKey),
    NotEqual(AnchoredKey, AnchoredKey),
    Gt(AnchoredKey, AnchoredKey),
    Lt(AnchoredKey, AnchoredKey),
    Contains(AnchoredKey, AnchoredKey),
    SumOf(AnchoredKey, AnchoredKey, AnchoredKey),
    ProductOf(AnchoredKey, AnchoredKey, AnchoredKey),
    MaxOf(AnchoredKey, AnchoredKey, AnchoredKey),
}

impl Statement {
    pub fn predicate(&self) -> &'static str {
        match self {
            Statement::None => "NONE",
            Statement::ValueOf(_, _) => "VALUEOF",
            Statement::Equal(_, _) => "EQUAL",
            Statement::NotEqual(_, _) => "NOTEQUAL",
            Statement::Gt(_, _) => "GT",
            Statement::Lt(_, _) => "LT",
            Statement::Contains(_, _) => "CONTAINS",
            Statement::SumOf(_, _, _) => "SUMOF",
            Statement::ProductOf(_, _, _) => "PRODUCTOF",
            Statement::MaxOf(_, _, _) => "MAXOF",
        }
    }
    pub fn from_entry(entry: &Entry, this_gadget_id: GadgetID) -> Self {
        Statement::ValueOf(
            AnchoredKey(
                Origin::auto("_SELF".to_string(), this_gadget_id),
                entry.key.to_string(),
            ),
            entry.value.clone(),
        )
    }
    pub fn code(&self) -> GoldilocksField {
        GoldilocksField::from_canonical_u64(match self {
            Self::None => 0,
            Self::ValueOf(_, _) => 1,
            Self::Equal(_, _) => 2,
            Self::NotEqual(_, _) => 3,
            Self::Gt(_, _) => 4,
            Self::Contains(_, _) => 5,
            Self::SumOf(_, _, _) => 6,
            Self::ProductOf(_, _, _) => 7,
            Self::MaxOf(_, _, _) => 8,
            Self::Lt(_, _) => 9,
        })
    }
    /// Field representation as a vector of length 11.
    /// Each statement is arranged as
    /// [code] ++ anchored_key1 ++ anchored_key2 ++ anchored_key3 ++ [value],
    /// where the leftmost keys are populated first and 0s are substituted in
    /// for empty fields.
    pub fn to_fields(&self) -> Vec<GoldilocksField> {
        [
            vec![self.code()],
            match self {
                Self::None => vec![GoldilocksField::ZERO; 10],
                Self::ValueOf(anchkey, value) => vec![
                    anchkey.to_fields(),
                    vec![GoldilocksField::ZERO; 6],
                    vec![value.hash_or_value()],
                ]
                .concat(),
                Self::Equal(anchkey1, anchkey2) => vec![
                    anchkey1.to_fields(),
                    anchkey2.to_fields(),
                    vec![GoldilocksField::ZERO; 4],
                ]
                .concat(),
                Self::NotEqual(anchkey1, anchkey2) => vec![
                    anchkey1.to_fields(),
                    anchkey2.to_fields(),
                    vec![GoldilocksField::ZERO; 4],
                ]
                .concat(),
                Self::Gt(anchkey1, anchkey2) => vec![
                    anchkey1.to_fields(),
                    anchkey2.to_fields(),
                    vec![GoldilocksField::ZERO; 4],
                ]
                .concat(),
                Self::Lt(anchkey1, anchkey2) => vec![
                    anchkey1.to_fields(),
                    anchkey2.to_fields(),
                    vec![GoldilocksField::ZERO; 4],
                ]
                .concat(),
                Self::Contains(anchkey1, anchkey2) => vec![
                    anchkey1.to_fields(),
                    anchkey2.to_fields(),
                    vec![GoldilocksField::ZERO; 4],
                ]
                .concat(),
                Self::SumOf(anchkey1, anchkey2, anchkey3) => vec![
                    anchkey1.to_fields(),
                    anchkey2.to_fields(),
                    anchkey3.to_fields(),
                    vec![GoldilocksField::ZERO],
                ]
                .concat(),
                Self::ProductOf(anchkey1, anchkey2, anchkey3) => vec![
                    anchkey1.to_fields(),
                    anchkey2.to_fields(),
                    anchkey3.to_fields(),
                    vec![GoldilocksField::ZERO],
                ]
                .concat(),
                Self::MaxOf(anchkey1, anchkey2, anchkey3) => vec![
                    anchkey1.to_fields(),
                    anchkey2.to_fields(),
                    anchkey3.to_fields(),
                    vec![GoldilocksField::ZERO],
                ]
                .concat(),
            },
        ]
        .concat()
    }
    pub fn remap_origins(
        &self,
        f: &dyn Fn(&str) -> Result<(String, GoldilocksField)>,
    ) -> Result<Self> {
        match self {
            Self::None => Ok(Self::None),
            Self::ValueOf(anchkey1, v) => Ok(Self::ValueOf(anchkey1.remap_origin(f)?, v.clone())),
            Self::Equal(anchkey1, anchkey2) => Ok(Self::Equal(
                anchkey1.remap_origin(f)?,
                anchkey2.remap_origin(f)?,
            )),
            Self::NotEqual(anchkey1, anchkey2) => Ok(Self::NotEqual(
                anchkey1.remap_origin(f)?,
                anchkey2.remap_origin(f)?,
            )),
            Self::Gt(anchkey1, anchkey2) => Ok(Self::Gt(
                anchkey1.remap_origin(f)?,
                anchkey2.remap_origin(f)?,
            )),
            Self::Lt(anchkey1, anchkey2) => Ok(Self::Lt(
                anchkey1.remap_origin(f)?,
                anchkey2.remap_origin(f)?,
            )),
            Self::Contains(anchkey1, anchkey2) => Ok(Self::Contains(
                anchkey1.remap_origin(f)?,
                anchkey2.remap_origin(f)?,
            )),
            Self::SumOf(anchkey1, anchkey2, anchkey3) => Ok(Self::SumOf(
                anchkey1.remap_origin(f)?,
                anchkey2.remap_origin(f)?,
                anchkey3.remap_origin(f)?,
            )),
            Self::ProductOf(anchkey1, anchkey2, anchkey3) => Ok(Self::ProductOf(
                anchkey1.remap_origin(f)?,
                anchkey2.remap_origin(f)?,
                anchkey3.remap_origin(f)?,
            )),
            Self::MaxOf(anchkey1, anchkey2, anchkey3) => Ok(Self::MaxOf(
                anchkey1.remap_origin(f)?,
                anchkey2.remap_origin(f)?,
                anchkey3.remap_origin(f)?,
            )),
        }
    }
    // Misc helpers
    pub fn value(&self) -> Result<ScalarOrVec> {
        match self {
            Self::ValueOf(_, v) => Ok(v.clone()),
            _ => Err(anyhow!("Statement {:?} does not contain a value.", self)),
        }
    }
    pub fn anchored_keys(&self) -> Vec<AnchoredKey> {
        match self {
            Self::None => vec![],
            Self::ValueOf(anchkey, _) => vec![anchkey.clone()],
            Self::Equal(anchkey1, anchkey2) => vec![anchkey1.clone(), anchkey2.clone()],
            Self::NotEqual(anchkey1, anchkey2) => vec![anchkey1.clone(), anchkey2.clone()],
            Self::Gt(anchkey1, anchkey2) => vec![anchkey1.clone(), anchkey2.clone()],
            Self::Lt(anchkey1, anchkey2) => vec![anchkey1.clone(), anchkey2.clone()],
            Self::Contains(anchkey1, anchkey2) => vec![anchkey1.clone(), anchkey2.clone()],
            Self::SumOf(anchkey1, anchkey2, anchkey3) => {
                vec![anchkey1.clone(), anchkey2.clone(), anchkey3.clone()]
            }
            Self::ProductOf(anchkey1, anchkey2, anchkey3) => {
                vec![anchkey1.clone(), anchkey2.clone(), anchkey3.clone()]
            }
            Self::MaxOf(anchkey1, anchkey2, anchkey3) => {
                vec![anchkey1.clone(), anchkey2.clone(), anchkey3.clone()]
            }
        }
    }
    // Helper to get the anchoredkey of a value of statement
    pub fn value_of_anchored_key(&self) -> Option<AnchoredKey> {
        match self {
            Statement::ValueOf(key, _) => Some(key.clone()),
            _ => None,
        }
    }
    // Helper to get the result key if it's a ternary statement
    pub fn result_anchored_key(&self) -> Option<AnchoredKey> {
        match self {
            Statement::SumOf(result, _, _)
            | Statement::ProductOf(result, _, _)
            | Statement::MaxOf(result, _, _) => Some(result.clone()),
            _ => None,
        }
    }
}

// Statements in operations may either be specified directly or as 'references', where
// a reference could be a hash or a string to be looked up in a table. We define a
// trait for this.
pub trait StatementOrRef: Clone + Debug {
    /// Type of table.
    type StatementTable;
    /// Resolution procedure.
    fn deref_cloned(&self, table: &Self::StatementTable) -> Result<Statement>;
}

impl StatementOrRef for Statement {
    type StatementTable = ();
    fn deref_cloned(&self, _table: &Self::StatementTable) -> Result<Statement> {
        Ok(self.clone())
    }
}

/// Typical statement ref type.
#[derive(Clone, Debug)]
pub struct StatementRef<'a, 'b>(pub &'a str, pub &'b str);

impl<'a, 'b> StatementOrRef for StatementRef<'a, 'b> {
    type StatementTable = HashMap<String, HashMap<String, Statement>>;
    fn deref_cloned(&self, table: &Self::StatementTable) -> Result<Statement> {
        let StatementRef(parent_name, statement_name) = self;
        table
            .get(*parent_name)
            .ok_or(anyhow!(
                "Statement parent {} missing from statement table!",
                parent_name
            ))?
            .get(*statement_name)
            .ok_or(anyhow!(
                "Statement {} with parent {} missing from statement table!",
                statement_name,
                parent_name
            ))
            .cloned()
    }
}
