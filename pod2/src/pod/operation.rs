use std::fmt::Debug;

use anyhow::{anyhow, Result};
use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField64},
};

use super::{
    entry::Entry,
    gadget::GadgetID,
    statement::{Statement, StatementOrRef, StatementRef},
    value::ScalarOrVec,
};

#[derive(Clone, Debug)]
pub enum Operation<S: StatementOrRef> {
    None,
    NewEntry(Entry),
    CopyStatement(S),
    EqualityFromEntries(S, S),
    NonequalityFromEntries(S, S),
    GtFromEntries(S, S),
    TransitiveEqualityFromStatements(S, S),
    GtToNonequality(S),
    ContainsFromEntries(S, S),
    RenameContainedBy(S, S),
    SumOf(S, S, S),
    ProductOf(S, S, S),
    MaxOf(S, S, S),
}

impl Operation<Statement> {
    /// Operation evaluation when statements are directly specified.
    pub fn eval_with_gadget_id(&self, gadget_id: GadgetID) -> Result<Statement> {
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
            _ => Err(anyhow!("Invalid claim.")),
        }
    }
}

impl<S: StatementOrRef> Operation<S> {
    /// Resolution of indirect operation specification.
    pub fn deref_args(&self, table: &S::StatementTable) -> Result<Operation<Statement>> {
        type Op = Operation<Statement>;
        match self {
            Self::None => Ok(Op::None),
            Self::NewEntry(e) => Ok(Op::NewEntry(e.clone())),
            Self::CopyStatement(s) => Ok(Op::CopyStatement(s.deref_cloned(table)?)),
            Self::EqualityFromEntries(s1, s2) => Ok(Op::EqualityFromEntries(
                s1.deref_cloned(table)?,
                s2.deref_cloned(table)?,
            )),
            Self::NonequalityFromEntries(s1, s2) => Ok(Op::NonequalityFromEntries(
                s1.deref_cloned(table)?,
                s2.deref_cloned(table)?,
            )),
            Self::GtFromEntries(s1, s2) => Ok(Op::GtFromEntries(
                s1.deref_cloned(table)?,
                s2.deref_cloned(table)?,
            )),
            Self::TransitiveEqualityFromStatements(s1, s2) => {
                Ok(Op::TransitiveEqualityFromStatements(
                    s1.deref_cloned(table)?,
                    s2.deref_cloned(table)?,
                ))
            }
            Self::GtToNonequality(s) => Ok(Op::GtToNonequality(s.deref_cloned(table)?)),
            Self::ContainsFromEntries(s1, s2) => Ok(Op::ContainsFromEntries(
                s1.deref_cloned(table)?,
                s2.deref_cloned(table)?,
            )),
            Self::RenameContainedBy(s1, s2) => Ok(Op::RenameContainedBy(
                s1.deref_cloned(table)?,
                s2.deref_cloned(table)?,
            )),
            Self::SumOf(s1, s2, s3) => Ok(Op::SumOf(
                s1.deref_cloned(table)?,
                s2.deref_cloned(table)?,
                s3.deref_cloned(table)?,
            )),
            Self::ProductOf(s1, s2, s3) => Ok(Op::ProductOf(
                s1.deref_cloned(table)?,
                s2.deref_cloned(table)?,
                s3.deref_cloned(table)?,
            )),
            Self::MaxOf(s1, s2, s3) => Ok(Op::MaxOf(
                s1.deref_cloned(table)?,
                s2.deref_cloned(table)?,
                s3.deref_cloned(table)?,
            )),
        }
    }
    /// Method specifying opcodes.
    pub fn code(&self) -> GoldilocksField {
        GoldilocksField::from_canonical_u64(match self {
            Self::None => 0,
            Self::NewEntry(_) => 1,
            Self::CopyStatement(_) => 2,
            Self::EqualityFromEntries(_, _) => 3,
            Self::NonequalityFromEntries(_, _) => 4,
            Self::GtFromEntries(_, _) => 5,
            Self::TransitiveEqualityFromStatements(_, _) => 6,
            Self::GtToNonequality(_) => 7,
            Self::ContainsFromEntries(_, _) => 8,
            Self::RenameContainedBy(_, _) => 9,
            Self::SumOf(_, _, _) => 10,
            Self::ProductOf(_, _, _) => 11,
            Self::MaxOf(_, _, _) => 12,
        })
    }
    pub fn execute(&self, gadget_id: GadgetID, table: &S::StatementTable) -> Result<Statement> {
        self.deref_args(table)?.eval_with_gadget_id(gadget_id)
    }
}

/// Named operation struct
#[derive(Clone, Debug)]
pub struct OperationCmd<'a, 'b, 'c>(pub Operation<StatementRef<'a, 'b>>, pub &'c str);
