use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::Hasher,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::statement::Statement;
use crate::F;

pub type StatementList = Vec<(String, Statement)>;

// HashablePayload trait, and PODPayload which implements it.
pub trait HashablePayload: Clone + PartialEq {
    fn to_field_vec(&self) -> Vec<GoldilocksField>;

    fn hash_payload(&self) -> HashOut<F> {
        let ins = self.to_field_vec();
        PoseidonHash::hash_no_pad(&ins)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PODPayload {
    pub statements_list: Vec<(String, Statement)>, // ORDERED list of statements, ordered by names
    pub statements_map: HashMap<String, Statement>,
}

impl PODPayload {
    pub fn new(statements: &HashMap<String, Statement>) -> Self {
        let mut statements_and_names_list = Vec::new();
        for (name, statement) in statements.iter() {
            statements_and_names_list.push((name.clone(), statement.clone()));
        }
        statements_and_names_list.sort_by(|a, b| a.0.cmp(&b.0));
        Self {
            statements_list: statements_and_names_list,
            statements_map: statements.clone(),
        }
    }
}

impl HashablePayload for Vec<Statement> {
    fn to_field_vec(&self) -> Vec<GoldilocksField> {
        self.iter()
            .map(|statement| statement.to_fields())
            .collect::<Vec<Vec<GoldilocksField>>>()
            .concat()
    }
}

impl HashablePayload for PODPayload {
    fn to_field_vec(&self) -> Vec<GoldilocksField> {
        let mut statements_vec = Vec::new();
        for (_, statement) in self.statements_list.iter() {
            statements_vec.push(statement.clone());
        }
        statements_vec.to_field_vec()
    }
}
