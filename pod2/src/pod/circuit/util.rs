use anyhow::{anyhow, Result};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
    util::log2_ceil,
};
use std::collections::HashMap;

use super::statement::StatementTarget;
use crate::pod::statement::{StatementOrRef, StatementRef};
use crate::{D, F};

const NUM_BITS: usize = 32;

/// Pads the end of the vector with its final element until its length
/// is a power of two. Needed for Plonky2 RAM.
fn pad_to_power_of_two<A: Clone>(v: &[A]) -> Result<Vec<A>> {
    let v_len = v.len();
    let bits = log2_ceil(v_len);
    let padding = (0..2usize.pow(bits as u32) - v_len)
        .map(|_| v.last().cloned())
        .collect::<Option<Vec<_>>>()
        .ok_or(anyhow!("Vector is empty"))?;
    Ok([v.to_vec(), padding].concat())
}

/// Helper for random access. Includes a range check.
pub fn vector_ref(builder: &mut CircuitBuilder<F, D>, v: &[Target], i: Target) -> Result<Target> {
    builder.range_check(i, NUM_BITS);
    // Form v.len() - 1 - i
    let minus_ind_target = builder.neg(i);
    let expr_target = builder.add_const(
        minus_ind_target,
        GoldilocksField::from_canonical_u64(v.len() as u64 - 1),
    );
    builder.range_check(expr_target, NUM_BITS);
    Ok(builder.random_access(i, pad_to_power_of_two(v)?))
}

/// Helper for matrix element access, where a 'matrix' is a slice of
/// vectors, each of which represents a row.
pub fn matrix_ref(
    builder: &mut CircuitBuilder<F, D>,
    a: &[Vec<Target>],
    i: Target,
    j: Target,
) -> Result<Target> {
    let num_columns = a.first().ok_or(anyhow!("Matrix is empty!"))?.len();
    if num_columns
        != a.iter()
            .map(|row| row.len())
            .max()
            .ok_or(anyhow!("Matrix is empty!"))?
    {
        return Err(anyhow!("Array {:?} has rows of varying length!", a));
    }
    // i*num_columns + j
    let num_columns_target = builder.constant(GoldilocksField(num_columns as u64));
    let index = builder.mul_add(i, num_columns_target, j);
    let v = a.iter().flatten().cloned().collect::<Vec<_>>();
    vector_ref(builder, &v, index)
}

/// Helper for random access of a statement in a matrix of statements.
pub fn statement_matrix_ref(
    builder: &mut CircuitBuilder<F, D>,
    statement_matrix: &[Vec<StatementTarget>],
    i: Target,
    j: Target,
) -> Result<StatementTarget> {
    // Separate the statement matrix into a vector (of length 11) of
    // matrices of targets.
    let transposed_target_matrices = statement_matrix
        .iter()
        .map(|s_vec| s_vec.iter().map(|s| s.to_targets()).collect())
        .collect::<Vec<Vec<Vec<Target>>>>();
    let target_matrices: Vec<Vec<Vec<Target>>> = (0..11)
        .map(|i| {
            transposed_target_matrices
                .iter()
                .map(|m| m.iter().map(|v| v[i]).collect())
                .collect()
        })
        .collect();
    Ok(StatementTarget::from_targets(
        target_matrices
            .iter()
            .map(|a| matrix_ref(builder, a, i, j))
            .collect::<Result<Vec<Target>>>()?
            .as_ref(),
    ))
}
