use std::{collections::HashMap, fmt::Debug};

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
    POD,
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
            Self::NewEntry(entry) => Ok(Statement::from_entry(entry, gadget_id)),
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
            ) if anchkey2.eq(anchkey3) => Ok(Statement::Equal(anchkey1.clone(), anchkey4.clone())),
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
            ) if anchkey1.eq(anchkey3) => {
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
    /// Opcodes
    pub const NONE: GoldilocksField = GoldilocksField(0);
    pub const NEW_ENTRY: GoldilocksField = GoldilocksField(1);
    pub const COPY_STATEMENT: GoldilocksField = GoldilocksField(2);
    pub const EQUALITY_FROM_ENTRIES: GoldilocksField = GoldilocksField(3);
    pub const NONEQUALITY_FROM_ENTRIES: GoldilocksField = GoldilocksField(4);
    pub const GT_FROM_ENTRIES: GoldilocksField = GoldilocksField(5);
    pub const TRANSITIVE_EQUALITY_FROM_STATEMENTS: GoldilocksField = GoldilocksField(6);
    pub const GT_TO_NONEQUALITY: GoldilocksField = GoldilocksField(7);
    pub const CONTAINS_FROM_ENTRIES: GoldilocksField = GoldilocksField(8);
    pub const RENAME_CONTAINED_BY: GoldilocksField = GoldilocksField(9);
    pub const SUM_OF: GoldilocksField = GoldilocksField(10);
    pub const PRODUCT_OF: GoldilocksField = GoldilocksField(11);
    pub const MAX_OF: GoldilocksField = GoldilocksField(12);

    /// Method specifying opcodes.
    pub fn code(&self) -> GoldilocksField {
        (match self {
            Self::None => Self::NONE,
            Self::NewEntry(_) => Self::NEW_ENTRY,
            Self::CopyStatement(_) => Self::COPY_STATEMENT,
            Self::EqualityFromEntries(_, _) => Self::EQUALITY_FROM_ENTRIES,
            Self::NonequalityFromEntries(_, _) => Self::NONEQUALITY_FROM_ENTRIES,
            Self::GtFromEntries(_, _) => Self::GT_FROM_ENTRIES,
            Self::TransitiveEqualityFromStatements(_, _) => {
                Self::TRANSITIVE_EQUALITY_FROM_STATEMENTS
            }
            Self::GtToNonequality(_) => Self::GT_TO_NONEQUALITY,
            Self::ContainsFromEntries(_, _) => Self::CONTAINS_FROM_ENTRIES,
            Self::RenameContainedBy(_, _) => Self::RENAME_CONTAINED_BY,
            Self::SumOf(_, _, _) => Self::SUM_OF,
            Self::ProductOf(_, _, _) => Self::PRODUCT_OF,
            Self::MaxOf(_, _, _) => Self::MAX_OF,
        })
    }
    /// Method specifying operands.
    pub fn operands(&self) -> Vec<&S> {
        match self {
            Self::CopyStatement(s) => vec![s],
            Self::EqualityFromEntries(s1, s2) => vec![s1, s2],
            Self::NonequalityFromEntries(s1, s2) => vec![s1, s2],
            Self::GtFromEntries(s1, s2) => vec![s1, s2],
            Self::TransitiveEqualityFromStatements(s1, s2) => vec![s1, s2],
            Self::GtToNonequality(s) => vec![s],
            Self::ContainsFromEntries(s1, s2) => vec![s1, s2],
            Self::RenameContainedBy(s1, s2) => vec![s1, s2],
            Self::SumOf(s1, s2, s3) => vec![s1, s2, s3],
            Self::ProductOf(s1, s2, s3) => vec![s1, s2, s3],
            Self::MaxOf(s1, s2, s3) => vec![s1, s2, s3],
            _ => vec![],
        }
    }
    /// Method specifying entry
    pub fn entry(&self) -> Result<&Entry> {
        match self {
            Self::NewEntry(e) => Ok(e),
            _ => Err(anyhow!("Operator {:?} does not have an entry.", self)),
        }
    }
    pub fn execute(&self, gadget_id: GadgetID, table: &S::StatementTable) -> Result<Statement> {
        self.deref_args(table)?.eval_with_gadget_id(gadget_id)
    }
}

/// Named operation struct
#[derive(Clone, Debug)]
pub struct OperationCmd<'a>(pub Operation<StatementRef<'a>>, pub &'a str);

impl<'a> Operation<StatementRef<'a>> {
    /// Representation of operation command as field vector of length
    /// 9 of the form
    /// [code] ++ [pod_num1, statement_num1] ++ [pod_num2,
    ///   statement_num2] ++ [pod_num3, statement_num3] ++ [entry],
    /// where we substitute 0s for unused operands and entries.
    pub fn to_fields(
        &self,
        ref_index_map: &HashMap<StatementRef<'a>, (usize, usize)>,
    ) -> Result<Vec<GoldilocksField>> {
        // Enumerate operands, substitute indices and pad with 0s.
        let operands = self
            .operands()
            .into_iter()
            .map(|s_ref| -> Result<_> {
                let (pod_num, statement_num) = ref_index_map
                    .get(s_ref)
                    .ok_or(anyhow!("Missing statement reference {:?}!", s_ref))?;
                Ok(vec![*pod_num, *statement_num])
            })
            .collect::<Result<Vec<Vec<_>>>>()?;
        let num_operands = operands.len();
        let padded_operands = [
            operands.into_iter().flatten().collect::<Vec<_>>(),
            (0..(2 * (3 - num_operands))).map(|_| 0).collect(),
        ]
        .concat()
        .into_iter()
        .map(|x| GoldilocksField(x as u64))
        .collect::<Vec<_>>();

        // Check for entry.
        let entry = self
            .entry()
            .map_or(vec![GoldilocksField::ZERO; 2], |e| e.to_fields());

        Ok([vec![self.code()], padded_operands, entry].concat())
    }
}

// Op list type. TODO.
struct OpList<'a>(Vec<OperationCmd<'a>>);

impl<'a> OpList<'a> {
    pub fn to_fields(&self, pods_list: &[(String, POD)]) -> Result<Vec<Vec<GoldilocksField>>> {
        // Map from StatementRef to pair of the form (pod index, statement index)
        let ref_index_map = StatementRef::index_map(pods_list);

        // Arrange OpCmds by output statement name and convert.
        // TODO: Factor out
        let mut sorted_opcmds = self.0.clone();
        let return_type = |op| {
            Statement::code_to_predicate(GoldilocksField(match op {
                Operation::None => 0,
                Operation::NewEntry(_) => 1,
                Operation::CopyStatement(s_ref) => {
                    let (pod_index, statement_index) = ref_index_map.get(&s_ref).unwrap();
                    pods_list[*pod_index].1.payload.statements_list[*statement_index]
                        .1
                        .code()
                        .to_canonical_u64()
                }
                Operation::EqualityFromEntries(_, _) => 2,
                Operation::NonequalityFromEntries(_, _) => 3,
                Operation::GtFromEntries(_, _) => 4,
                Operation::TransitiveEqualityFromStatements(_, _) => 2,
                Operation::GtToNonequality(_) => 3,
                Operation::ContainsFromEntries(_, _) => 5,
                Operation::RenameContainedBy(_, _) => 5,
                Operation::SumOf(_, _, _) => 6,
                Operation::ProductOf(_, _, _) => 7,
                Operation::MaxOf(_, _, _) => 8,
                _ => 0,
            }))
        };

        sorted_opcmds.sort_by(|a, b| {
            format!("{}:{}", return_type(a.0.clone()), a.1).cmp(&format!(
                "{}:{}",
                return_type(b.0.clone()),
                b.1
            ))
        });
        sorted_opcmds
            .iter()
            .map(|OperationCmd(op, _)| op.to_fields(&ref_index_map))
            .collect::<Result<Vec<Vec<_>>>>()
    }
}
