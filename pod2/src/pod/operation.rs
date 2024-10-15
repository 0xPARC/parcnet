use std::collections::HashMap;

use anyhow::{anyhow, Result};
use plonky2::field::types::PrimeField64;

use super::{
    entry::Entry,
    gadget::GadgetID,
    statement::{AnchoredKey, Statement},
    value::ScalarOrVec,
};

#[derive(Clone, Debug)]
pub enum Operation {
    None,
    NewEntry(Entry),
    CopyStatement(Statement),
    EqualityFromEntries(Statement, Statement),
    NonequalityFromEntries(Statement, Statement),
    GtFromEntries(Statement, Statement),
    TransitiveEqualityFromStatements(Statement, Statement),
    GtToNonequality(Statement),
    ContainsFromEntries(Statement, Statement),
    RenameContainedBy(Statement, Statement),
    SumOf(Statement, Statement, Statement),
    ProductOf(Statement, Statement, Statement),
    MaxOf(Statement, Statement, Statement),
}

impl Operation {
    fn eval_with_gadget_id(&self, gadget_id: GadgetID) -> Result<Statement> {
        match self {
            Self::None => Ok(Statement::None),
            Self::NewEntry(entry) => Ok(Statement::from_entry(&entry, gadget_id)),
            Self::CopyStatement(s) => Ok(s.clone()),
            Self::EqualityFromEntries(
                Statement::ValueOf(anchkey1, v1),
                Statement::ValueOf(anchkey2, v2),
            ) if v1 == v2 => Ok(Statement::Equal(anchkey1.clone(), anchkey2.clone())),
            Self::NonequalityFromEntries(
                Statement::ValueOf(anchkey1, v1),
                Statement::ValueOf(anchkey2, v2),
            ) if v1 != v2 => Ok(Statement::NotEqual(anchkey1.clone(), anchkey2.clone())),
            Self::GtFromEntries(
                Statement::ValueOf(anchkey1, ScalarOrVec::Scalar(v1)),
                Statement::ValueOf(anchkey2, ScalarOrVec::Scalar(v2)),
            ) if v1.to_canonical_u64() > v2.to_canonical_u64() => {
                Ok(Statement::Gt(anchkey1.clone(), anchkey2.clone()))
            }
            Self::TransitiveEqualityFromStatements(
                Statement::Equal(anchkey1, anchkey2),
                Statement::Equal(anchkey3, anchkey4),
            ) if anchkey2.eq(&anchkey3) => Ok(Statement::Equal(anchkey1.clone(), anchkey4.clone())),
            Self::GtToNonequality(Statement::Gt(anchkey1, anchkey2)) => {
                Ok(Statement::NotEqual(anchkey1.clone(), anchkey2.clone()))
            }
            Self::ContainsFromEntries(
                Statement::ValueOf(anchkey1, ScalarOrVec::Vector(vec)),
                Statement::ValueOf(anchkey2, ScalarOrVec::Scalar(scal)),
            ) if vec.contains(scal) => Ok(Statement::Contains(anchkey1.clone(), anchkey2.clone())),
            Self::RenameContainedBy(
                Statement::Contains(anchkey1, anchkey2),
                Statement::Equal(anchkey3, anchkey4),
            ) if anchkey1.eq(&anchkey3) => {
                Ok(Statement::Contains(anchkey4.clone(), anchkey2.clone()))
            }
            Self::SumOf(
                Statement::ValueOf(anchkey1, ScalarOrVec::Scalar(x1)),
                Statement::ValueOf(anchkey2, ScalarOrVec::Scalar(x2)),
                Statement::ValueOf(anchkey3, ScalarOrVec::Scalar(x3)),
            ) if *x1 == *x2 + *x3 => Ok(Statement::SumOf(
                anchkey1.clone(),
                anchkey2.clone(),
                anchkey3.clone(),
            )),
            Self::ProductOf(
                Statement::ValueOf(anchkey1, ScalarOrVec::Scalar(x1)),
                Statement::ValueOf(anchkey2, ScalarOrVec::Scalar(x2)),
                Statement::ValueOf(anchkey3, ScalarOrVec::Scalar(x3)),
            ) if *x1 == *x2 * *x3 => Ok(Statement::ProductOf(
                anchkey1.clone(),
                anchkey2.clone(),
                anchkey3.clone(),
            )),
            Self::MaxOf(
                Statement::ValueOf(anchkey1, ScalarOrVec::Scalar(x1)),
                Statement::ValueOf(anchkey2, ScalarOrVec::Scalar(x2)),
                Statement::ValueOf(anchkey3, ScalarOrVec::Scalar(x3)),
            ) if x1.to_canonical_u64()
                == Ord::max(x2.to_canonical_u64(), x3.to_canonical_u64()) =>
            {
                Ok(Statement::MaxOf(
                    anchkey1.clone(),
                    anchkey2.clone(),
                    anchkey3.clone(),
                ))
            }
            _ => Err(anyhow!("Invalid arguments.")),
        }
    }
}
