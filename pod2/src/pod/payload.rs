use std::collections::HashMap;

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::poseidon::PoseidonHash,
    plonk::config::{GenericHashOut, Hasher},
};
use serde::{Deserialize, Serialize};

use super::statement::Statement;

// HashablePayload trait, and PODPayload which implements it.
pub trait HashablePayload: Clone + PartialEq {
    fn to_field_vec(&self) -> Vec<GoldilocksField>;

    fn hash_payload(&self) -> GoldilocksField {
        let ins = self.to_field_vec();
        PoseidonHash::hash_no_pad(&ins).to_vec()[0]
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
