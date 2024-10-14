use std::collections::HashMap;

//use circuit::pod2_circuit;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::field::types::PrimeField64;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::GenericHashOut;
use plonky2::plonk::config::Hasher;
use util::hash_string_to_field;

use crate::schnorr::SchnorrPublicKey;
use crate::schnorr::SchnorrSecretKey;
use crate::schnorr::SchnorrSignature;
use crate::schnorr::SchnorrSigner;

//mod circuit;
mod util;

pub(crate) type Error = Box<dyn std::error::Error>;

// EntryValue trait, and ScalarOrVec type which implements it.
// This is a field element or array of field elements.
pub trait HashableEntryValue: Clone + PartialEq {
    fn hash_or_value(&self) -> GoldilocksField;
}

impl HashableEntryValue for GoldilocksField {
    fn hash_or_value(&self) -> GoldilocksField {
        *self
    }
}

impl HashableEntryValue for Vec<GoldilocksField> {
    fn hash_or_value(&self) -> GoldilocksField {
        PoseidonHash::hash_no_pad(self).to_vec()[0]
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ScalarOrVec {
    Scalar(GoldilocksField),
    Vector(Vec<GoldilocksField>),
}

impl HashableEntryValue for ScalarOrVec {
    fn hash_or_value(&self) -> GoldilocksField {
        match self {
            Self::Scalar(s) => s.hash_or_value(),
            Self::Vector(v) => v.hash_or_value(),
        }
    }
}

// An Entry, which is just a key-value pair.

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub key: String,
    pub value: ScalarOrVec,
}

impl Entry {
    pub fn new_from_scalar(key: String, value: GoldilocksField) -> Self {
        Entry {
            key,
            value: ScalarOrVec::Scalar(value),
        }
    }

    pub fn new_from_vec(key: String, value: Vec<GoldilocksField>) -> Self {
        Entry {
            key,
            value: ScalarOrVec::Vector(value),
        }
    }
}

// An Origin, which represents a reference to an ancestor POD.

#[derive(Clone, Debug, PartialEq)]
pub struct Origin {
    pub origin_id: GoldilocksField, // reserve 0 for NONE, 1 for SELF
    pub origin_name: String,
    pub gadget_id: GadgetID, // if origin_id is SELF, this is none; otherwise, it's the gadget_id
}

impl Origin {
    pub const NONE: Self = Origin {
        origin_id: GoldilocksField::ZERO,
        origin_name: String::new(),
        gadget_id: GadgetID::NONE,
    };
}

// A Statement, which is a claim about one or more entries.
// Entries are ValueOf statements.

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u64)]
pub enum StatementPredicate {
    None = 0,
    ValueOf = 1,
    Equal = 2,
    NotEqual = 3,
    Gt = 4,
    Contains = 5,
    SumOf = 6,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Statement {
    pub predicate: StatementPredicate,
    pub origin1: Origin,
    pub key1: String,
    pub origin2: Option<Origin>,
    pub key2: Option<String>,
    pub origin3: Option<Origin>,
    pub key3: Option<String>,
    pub optional_value: Option<ScalarOrVec>, // todo: figure out how to allow this to be any EntryValue
}

impl Statement {
    pub fn from_entry(entry: &Entry, this_gadget_id: GadgetID) -> Self {
        Statement {
            predicate: StatementPredicate::ValueOf,
            origin1: Origin {
                origin_id: GoldilocksField(1),
                origin_name: "_SELF".to_string(),
                gadget_id: this_gadget_id,
            },
            key1: entry.key.to_string(),
            origin2: None,
            key2: None,
            origin3: None,
            key3: None,
            optional_value: Some(entry.value.clone()),
        }
    }
}

// HashablePayload trait, and PODPayload which implements it.

pub trait HashablePayload: Clone + PartialEq {
    fn to_field_vec(&self) -> Vec<GoldilocksField>;

    fn hash_payload(&self) -> GoldilocksField {
        let ins = self.to_field_vec();
        PoseidonHash::hash_no_pad(&ins).to_vec()[0]
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PODPayload {
    statements_list: Vec<(String, Statement)>, // ORDERED list of statements, ordered by names
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
            .map(|statement| {
                [
                    vec![
                        GoldilocksField(statement.predicate as u64),
                        statement.origin1.origin_id,
                        GoldilocksField(statement.origin1.gadget_id as u64),
                        hash_string_to_field(&statement.key1),
                    ],
                    match &statement.origin2 {
                        Some(o) => vec![o.origin_id, GoldilocksField(o.gadget_id as u64)],
                        _ => vec![GoldilocksField(0), GoldilocksField(0)],
                    },
                    match &statement.key2 {
                        Some(kn) => vec![hash_string_to_field(kn)],
                        _ => vec![GoldilocksField::ZERO],
                    },
                    match &statement.origin3 {
                        Some(o) => vec![o.origin_id, GoldilocksField(o.gadget_id as u64)],
                        _ => vec![GoldilocksField(0), GoldilocksField(0)],
                    },
                    match &statement.key3 {
                        Some(kn) => vec![hash_string_to_field(kn)],
                        _ => vec![GoldilocksField::ZERO],
                    },
                    match &statement.optional_value {
                        Some(x) => vec![x.hash_or_value()],
                        _ => vec![GoldilocksField::ZERO],
                    },
                ]
                .concat()
            })
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum GadgetID {
    NONE = 0,
    SCHNORR16 = 1,
    ORACLE = 2,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PODProof {
    Schnorr(SchnorrSignature),
    Oracle(SchnorrSignature),
}

#[derive(Clone, Debug, PartialEq)]
pub struct POD {
    pub payload: PODPayload,
    proof: PODProof,
    pub proof_type: GadgetID,
}

impl POD {
    pub fn verify(&self) -> Result<bool, Error> {
        match self.proof {
            PODProof::Schnorr(p) => {
                if self.proof_type != GadgetID::SCHNORR16 {
                    return Err("Proof and POD proofType mismatch".into());
                }

                let payload_hash = self.payload.hash_payload();
                let payload_hash_vec = vec![payload_hash];
                let protocol = SchnorrSigner::new();

                let wrapped_pk = self.payload.statements_map.get("entry-_signer");

                if wrapped_pk.is_none() {
                    return Err("No signer found in payload".into());
                }

                let pk = match wrapped_pk.unwrap().optional_value {
                    Some(ScalarOrVec::Vector(_)) => Err(Error::from("Signer is a vector")),
                    Some(ScalarOrVec::Scalar(s)) => Ok(s),
                    _ => Err("_signer key found but no corresponding value".into()),
                }?;
                Ok(protocol.verify(&p, &payload_hash_vec, &SchnorrPublicKey { pk }))
            }
            PODProof::Oracle(p) => {
                if self.proof_type != GadgetID::ORACLE {
                    return Err("Proof and POD proofType mismatch".into());
                }

                let payload_hash = self.payload.hash_payload();
                let payload_hash_vec = vec![payload_hash];
                let protocol = SchnorrSigner::new();

                Ok(protocol.verify(
                    &p,
                    &payload_hash_vec,
                    &protocol.keygen(&SchnorrSecretKey { sk: 0 }), // hardcoded secret key
                ))
            }
        }
    }

    pub fn execute_schnorr_gadget(entries: &Vec<Entry>, sk: &SchnorrSecretKey) -> Self {
        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let protocol = SchnorrSigner::new();

        let mut kv_pairs = entries.clone();
        kv_pairs.push(Entry {
            key: "_signer".to_string(),
            value: ScalarOrVec::Scalar(protocol.keygen(sk).pk),
        });
        let mut statement_map: HashMap<String, Statement> = HashMap::new();

        for entry in kv_pairs {
            statement_map.insert(
                "entry-".to_owned() + &entry.key,
                Statement::from_entry(&entry, GadgetID::SCHNORR16),
            );
        }

        let payload = PODPayload::new(&statement_map);
        let payload_hash = payload.hash_payload();
        let payload_hash_vec = vec![payload_hash];
        let proof = protocol.sign(&payload_hash_vec, sk, &mut rng);
        Self {
            payload,
            proof: PODProof::Schnorr(proof),
            proof_type: GadgetID::SCHNORR16,
        }
    }

    pub fn execute_oracle_gadget(
        input: &GPGInput,
        cmds: &Vec<OperationCmd>,
    ) -> Result<Self, Error> {
        let mut statements = input.remap_origin_ids_by_name();
        match &mut statements {
            Ok(statements) => {
                statements.insert("_SELF".to_string(), HashMap::new());
                for cmd in cmds {
                    let new_statement = cmd.execute(GadgetID::ORACLE, statements);
                    match new_statement {
                        Some(new_statement) => {
                            statements
                                .get_mut("_SELF")
                                .unwrap()
                                .insert(cmd.output_statement_name.clone(), new_statement);
                        }
                        None => {
                            print!("{:?}", cmd);
                            return Err("operation failed to execute".into());
                        }
                    }
                }
                let out_statements = statements.get("_SELF").unwrap();
                let out_payload = PODPayload::new(out_statements);
                let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
                let protocol = SchnorrSigner::new();
                let payload_hash = out_payload.hash_payload();
                let payload_hash_vec = vec![payload_hash];

                // signature is a hardcoded skey (currently 0)
                // todo is to build a limited version of this with a ZKP
                // would start by making it so that the ZKP only allows
                // a max number of input PODs, max number of entries/statements per input POD,
                // max number of statements for output POD, and some max number of each type of operation
                let proof = protocol.sign(&payload_hash_vec, &SchnorrSecretKey { sk: 0 }, &mut rng);
                Ok(Self {
                    payload: out_payload,
                    proof: PODProof::Oracle(proof),
                    proof_type: GadgetID::ORACLE,
                })
            }
            Err(e) => panic!("Error: {:?}", e),
        }
    }
}

// Operations

#[derive(Clone, Debug)]
pub struct GPGInput {
    pub pods_list: Vec<(String, POD)>, // ORDERED list of pods, ordered by names

    // map from (pod name, old origin name) to new origin name
    pub origin_renaming_map: HashMap<(String, String), String>,
}

impl GPGInput {
    pub fn new(
        named_pods: HashMap<String, POD>,
        origin_renaming_map: HashMap<(String, String), String>,
    ) -> Self {
        let mut pods_and_names_list = Vec::new();
        for (name, pod) in named_pods.iter() {
            pods_and_names_list.push((name.clone(), pod.clone()));
        }
        pods_and_names_list.sort_by(|a, b| a.0.cmp(&b.0));

        Self {
            pods_list: pods_and_names_list.clone(),
            origin_renaming_map: origin_renaming_map.clone(),
        }
    }

    // returns a map from input POD name to (map from statement name to statement)
    // the inner statements have their old origin names and IDs are replaced with
    // the new origin names as specified by inputs.origin_renaming_map
    // and with new origin IDs which correspond to the lexicographic order of the new origin names
    fn remap_origin_ids_by_name(
        &self,
    ) -> Result<HashMap<String, HashMap<String, Statement>>, Error> {
        let mut new_origin_name_list = Vec::new();
        for (_, new_name) in self.origin_renaming_map.iter() {
            new_origin_name_list.push(new_name.clone());
        }
        new_origin_name_list.sort();

        let mut new_origin_name_to_id_map = HashMap::new();
        for (idx, new_name) in new_origin_name_list.iter().enumerate() {
            new_origin_name_to_id_map.insert(new_name.clone(), idx + 2); // 0 reserved for none, 1 reserved for _SELF
        }

        let mut statements_with_renamed_origins = HashMap::new();

        for (pod_name, pod) in self.pods_list.iter() {
            let mut inner_map = HashMap::new();

            for (name, statement) in pod.payload.statements_map.iter() {
                let mut statement_with_remapped_origins = statement.clone();
                // origin 1
                let new_origin1_name = self
                    .origin_renaming_map
                    .get(&(pod_name.clone(), statement.origin1.origin_name.clone()));
                match new_origin1_name {
                    Some(new_origin1_name) => {
                        let new_origin1_id = new_origin_name_to_id_map.get(new_origin1_name);
                        match new_origin1_id {
                            Some(&new_origin1_id) => {
                                statement_with_remapped_origins.origin1 = Origin {
                                    origin_id: GoldilocksField(new_origin1_id as u64),
                                    origin_name: new_origin1_name.clone(),
                                    gadget_id: statement.origin1.gadget_id,
                                }
                            }
                            None => {
                                return Err(("couldn't find id for new origin: ".to_string()
                                    + new_origin1_name)
                                    .into());
                            }
                        }
                    }
                    None => {
                        return Err(("couldn't find new origin name for origin: ".to_string()
                            + &pod_name.clone()
                            + "."
                            + &statement.origin1.origin_name.clone())
                            .into())
                    }
                }
                // origin 2
                if let Some(old_origin2) = &statement.origin2 {
                    let new_origin2_name = self
                        .origin_renaming_map
                        .get(&(pod_name.clone(), old_origin2.origin_name.clone()));
                    match new_origin2_name {
                        Some(new_origin2_name) => {
                            let new_origin2_id = new_origin_name_to_id_map.get(new_origin2_name);
                            match new_origin2_id {
                                Some(&new_origin2_id) => {
                                    statement_with_remapped_origins.origin2 = Some(Origin {
                                        origin_id: GoldilocksField(new_origin2_id as u64),
                                        origin_name: new_origin2_name.clone(),
                                        gadget_id: old_origin2.gadget_id,
                                    })
                                }
                                None => {
                                    return Err(("couldn't find id for new origin: ".to_string()
                                        + new_origin2_name)
                                        .into());
                                }
                            }
                        }
                        None => {
                            return Err(("couldn't find new origin name for origin: ".to_string()
                                + &pod_name.clone()
                                + "."
                                + &old_origin2.origin_name.clone())
                                .into())
                        }
                    }
                }
                // origin 3
                if let Some(old_origin3) = &statement.origin3 {
                    let new_origin3_name = self
                        .origin_renaming_map
                        .get(&(pod_name.clone(), old_origin3.origin_name.clone()));
                    match new_origin3_name {
                        Some(new_origin3_name) => {
                            let new_origin3_id = new_origin_name_to_id_map.get(new_origin3_name);
                            match new_origin3_id {
                                Some(&new_origin3_id) => {
                                    statement_with_remapped_origins.origin3 = Some(Origin {
                                        origin_id: GoldilocksField(new_origin3_id as u64),
                                        origin_name: new_origin3_name.clone(),
                                        gadget_id: old_origin3.gadget_id,
                                    })
                                }
                                None => {
                                    return Err(("couldn't find id for new origin: ".to_string()
                                        + new_origin3_name)
                                        .into());
                                }
                            }
                        }
                        None => {
                            return Err(("couldn't find new origin name for origin: ".to_string()
                                + &pod_name.clone()
                                + "."
                                + &old_origin3.origin_name.clone())
                                .into())
                        }
                    }
                }

                inner_map.insert(name.clone(), statement_with_remapped_origins);
            }
            statements_with_renamed_origins.insert(pod_name.clone(), inner_map);
        }

        Ok(statements_with_renamed_origins)
    }
}

#[derive(Copy, Clone, Debug)]
pub enum OperationType {
    None = 0,
    NewEntry = 1,
    CopyStatement = 2,
    EqualityFromEntries = 3,
    NonequalityFromEntries = 4,
    GtFromEntries = 5,
    TransitiveEqualityFromStatements = 6,
    GtToNonequality = 7,
    ContainsFromEntries = 8,
    SumOf = 9,
}

#[derive(Clone, Debug)]
pub struct OperationCmd {
    pub operation_type: OperationType,
    pub statement_1_parent: Option<String>,
    pub statement_1_name: Option<String>,
    pub statement_2_parent: Option<String>,
    pub statement_2_name: Option<String>,
    pub statement_3_parent: Option<String>,
    pub statement_3_name: Option<String>,
    pub optional_entry: Option<Entry>,
    pub output_statement_name: String,
}

impl OperationCmd {
    fn get_statement_with_origin_and_name(
        statements: &HashMap<String, HashMap<String, Statement>>,
        origin: Option<String>,
        name: Option<String>,
    ) -> Option<Statement> {
        if let Some(origin) = origin {
            if let Some(name) = name {
                if let Some(map) = statements.get(&origin) {
                    if let Some(statement) = map.get(&name) {
                        return Some(statement.clone());
                    }
                }
            }
        }
        None
    }

    pub fn execute(
        &self,
        gadget_id: GadgetID,
        statements: &HashMap<String, HashMap<String, Statement>>,
    ) -> Option<Statement> {
        let statement1 = OperationCmd::get_statement_with_origin_and_name(
            statements,
            self.statement_1_parent.clone(),
            self.statement_1_name.clone(),
        );
        let statement2 = OperationCmd::get_statement_with_origin_and_name(
            statements,
            self.statement_2_parent.clone(),
            self.statement_2_name.clone(),
        );
        let statement3 = OperationCmd::get_statement_with_origin_and_name(
            statements,
            self.statement_3_parent.clone(),
            self.statement_3_name.clone(),
        );
        let optional_entry = self.optional_entry.clone();

        self.operation_type.apply_operation(
            gadget_id,
            statement1,
            statement2,
            statement3,
            optional_entry,
        )
    }
}

impl OperationType {
    pub fn apply_operation(
        &self,
        gadget_id: GadgetID,
        statement1: Option<Statement>,
        statement2: Option<Statement>,
        statement3: Option<Statement>,
        optional_entry: Option<Entry>,
    ) -> Option<Statement> {
        match (self, statement1, statement2, statement3, optional_entry) {
            // A new statement is created from a single `Entry`.
            (OperationType::NewEntry, _, _, _, Some(entry)) => {
                Some(Statement::from_entry(&entry, gadget_id))
            }
            // A statement is copied from a single (left) statement.
            (OperationType::CopyStatement, Some(statement), _, _, _) => {
                let cloned = statement.clone();
                Some(cloned)
            }
            // Eq <=> Left entry = right entry
            (OperationType::EqualityFromEntries, Some(left_entry), Some(right_entry), _, _) => {
                match (left_entry.predicate, right_entry.predicate) {
                    (StatementPredicate::ValueOf, StatementPredicate::ValueOf)
                        if left_entry.optional_value == right_entry.optional_value =>
                    {
                        Some(Statement {
                            predicate: StatementPredicate::Equal,
                            origin1: left_entry.origin1,
                            key1: left_entry.key1.clone(),
                            origin2: Some(right_entry.origin1),
                            key2: Some(right_entry.key1.clone()),
                            origin3: None,
                            key3: None,
                            optional_value: None,
                        })
                    }
                    _ => None,
                }
            }
            // Neq <=> Left entry != right entry
            (OperationType::NonequalityFromEntries, Some(left_entry), Some(right_entry), _, _) => {
                match (left_entry.predicate, right_entry.predicate) {
                    (StatementPredicate::ValueOf, StatementPredicate::ValueOf)
                        if left_entry.optional_value != right_entry.optional_value =>
                    {
                        Some(Statement {
                            predicate: StatementPredicate::NotEqual,
                            origin1: left_entry.origin1,
                            key1: left_entry.key1.clone(),
                            origin2: Some(right_entry.origin1),
                            key2: Some(right_entry.key1.clone()),
                            origin3: None,
                            key3: None,
                            optional_value: None,
                        })
                    }
                    _ => None,
                }
            }
            // Gt <=> Left entry > right entry
            (OperationType::GtFromEntries, Some(left_entry), Some(right_entry), _, _) => {
                match (
                    left_entry.predicate,
                    left_entry.optional_value,
                    right_entry.predicate,
                    right_entry.optional_value,
                ) {
                    (
                        StatementPredicate::ValueOf,
                        Some(ScalarOrVec::Scalar(left_value)),
                        StatementPredicate::ValueOf,
                        Some(ScalarOrVec::Scalar(right_value)),
                    ) if left_value.to_canonical_u64() > right_value.to_canonical_u64() => {
                        Some(Statement {
                            predicate: StatementPredicate::Gt,
                            origin1: left_entry.origin1,
                            key1: left_entry.key1.clone(),
                            origin2: Some(right_entry.origin1),
                            key2: Some(right_entry.key1.clone()),
                            origin3: None,
                            key3: None,
                            optional_value: None,
                        })
                    }
                    _ => None,
                }
            }
            // Equality deduction: a = b ∧ b = c => a = c.
            // TODO: Allow for permutations of left/right values.
            (
                OperationType::TransitiveEqualityFromStatements,
                Some(left_statement),
                Some(right_statement),
                _,
                _,
            ) => match (left_statement, right_statement) {
                (
                    Statement {
                        predicate: StatementPredicate::Equal,
                        origin1: ll_origin,
                        key1: ll_key_name,
                        origin2:
                            Some(Origin {
                                origin_id: lr_origin_id,
                                origin_name: _,
                                gadget_id: _,
                            }),
                        key2: Some(lr_key_name),
                        origin3: None,
                        key3: None,
                        optional_value: _,
                    },
                    Statement {
                        predicate: StatementPredicate::Equal,
                        origin1:
                            Origin {
                                origin_id: rl_origin_id,
                                origin_name: _,
                                gadget_id: _,
                            },
                        key1: rl_key_name,
                        origin2: rr_origin @ Some(_),
                        key2: rr_key_name @ Some(_),
                        origin3: None,
                        key3: None,
                        optional_value: _,
                    },
                ) if (lr_origin_id, &lr_key_name) == ((rl_origin_id, &rl_key_name)) => {
                    Some(Statement {
                        predicate: StatementPredicate::Equal,
                        origin1: ll_origin.clone(),
                        key1: ll_key_name.clone(),
                        origin2: rr_origin.clone(),
                        key2: rr_key_name.clone(),
                        origin3: None,
                        key3: None,
                        optional_value: None,
                    })
                }
                _ => None,
            },
            (OperationType::GtToNonequality, Some(left_statement), _, _, _) => match left_statement
            {
                Statement {
                    predicate: StatementPredicate::Gt,
                    origin1: left_origin,
                    key1: left_key_name,
                    origin2: right_origin,
                    key2: right_key_name,
                    origin3: None,
                    key3: None,
                    optional_value: _,
                } => Some(Statement {
                    predicate: StatementPredicate::NotEqual,
                    origin1: left_origin.clone(),
                    key1: left_key_name.clone(),
                    origin2: right_origin.clone(),
                    key2: right_key_name.clone(),
                    origin3: None,
                    key3: None,
                    optional_value: None,
                }),
                _ => None,
            },
            (OperationType::ContainsFromEntries, Some(left_entry), Some(right_entry), _, _) => {
                match (
                    left_entry.predicate,
                    left_entry.optional_value,
                    right_entry.predicate,
                    right_entry.optional_value,
                ) {
                    (
                        StatementPredicate::ValueOf,
                        Some(ScalarOrVec::Vector(vec1)),
                        StatementPredicate::ValueOf,
                        Some(ScalarOrVec::Scalar(val)),
                    ) => {
                        if vec1.contains(&val) {
                            return Some(Statement {
                                predicate: StatementPredicate::Contains,
                                origin1: left_entry.origin1,
                                key1: left_entry.key1.clone(),
                                origin2: Some(right_entry.origin1),
                                key2: Some(right_entry.key1.clone()),
                                origin3: None,
                                key3: None,
                                optional_value: None,
                            });
                        }
                        None
                    }
                    _ => None,
                }
            }
            // SumOf <=> statement 1's value = statement 2's value + statement 3's value
            (OperationType::SumOf, Some(statement1), Some(statement2), Some(statement3), _) => {
                match (
                    statement1.predicate,
                    statement1.optional_value,
                    statement2.predicate,
                    statement2.optional_value,
                    statement3.predicate,
                    statement3.optional_value,
                ) {
                    (
                        StatementPredicate::ValueOf,
                        Some(ScalarOrVec::Scalar(sum)),
                        StatementPredicate::ValueOf,
                        Some(ScalarOrVec::Scalar(left_addend)),
                        StatementPredicate::ValueOf,
                        Some(ScalarOrVec::Scalar(right_addend)),
                    ) if (sum == left_addend + right_addend) => Some(Statement {
                        predicate: StatementPredicate::SumOf,
                        origin1: statement1.origin1,
                        key1: statement1.key1.clone(),
                        origin2: Some(statement2.origin1),
                        key2: Some(statement2.key1.clone()),
                        origin3: Some(statement3.origin1),
                        key3: Some(statement3.key1.clone()),
                        optional_value: None,
                    }),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

#[test]
fn op_test() -> Result<(), Error> {
    // Start with some values.
    let scalar1 = GoldilocksField(36);
    let scalar2 = GoldilocksField(52);
    let scalar3 = GoldilocksField(16);
    let vector_value = vec![scalar1, scalar2];

    // Create entries
    let entry1 = Entry::new_from_scalar("some key".to_string(), scalar1);
    let entry2 = Entry::new_from_scalar("some other key".to_string(), scalar2);
    let entry3 = Entry::new_from_vec("vector entry".to_string(), vector_value.clone());
    let entry4 = Entry::new_from_scalar("another scalar1".to_string(), scalar1);
    let entry5 = Entry::new_from_scalar("yet another scalar1".to_string(), scalar1);
    let entry6 = Entry::new_from_scalar("scalar3".to_string(), scalar3);

    // Create entry statements.
    let entry_statement1 = Statement::from_entry(&entry1, GadgetID::NONE);
    let entry_statement2 = Statement::from_entry(&entry2, GadgetID::NONE);
    let entry_statement3 = Statement::from_entry(&entry3, GadgetID::NONE);
    let entry_statement4 = Statement::from_entry(&entry4, GadgetID::NONE);
    let entry_statement5 = Statement::from_entry(&entry5, GadgetID::NONE);
    let entry_statement6 = Statement::from_entry(&entry6, GadgetID::NONE);

    // Entry 2's value = entry 1's value + entry 6's value
    let sum_of_statement = OperationType::SumOf
        .apply_operation(
            GadgetID::ORACLE,
            Some(entry_statement2.clone()),
            Some(entry_statement1.clone()),
            Some(entry_statement6.clone()),
            <Option<Entry>>::None,
        )
        .unwrap();
    assert!(
        sum_of_statement
            == Statement {
                predicate: StatementPredicate::SumOf,
                origin1: entry_statement2.origin1.clone(),
                key1: entry_statement2.key1.clone(),
                origin2: Some(entry_statement1.origin1.clone()),
                key2: Some(entry_statement1.key1.clone()),
                origin3: Some(entry_statement6.origin1.clone()),
                key3: Some(entry_statement6.key1.clone()),
                optional_value: None
            }
    );

    let entries = [&entry_statement1, &entry_statement2, &entry_statement3];

    // Copy statements and check for equality of entries.
    entries.into_iter().for_each(|statement| {
        let copy = OperationType::CopyStatement
            .apply_operation(GadgetID::NONE, Some(statement.clone()), None, None, None)
            .expect("This value should exist.");
        assert!(&copy == statement);
    });

    // Equality checks
    assert!(
        OperationType::EqualityFromEntries.apply_operation(
            GadgetID::NONE,
            Some(entry_statement1.clone()),
            Some(entry_statement4.clone()),
            None,
            None,
        ) == Some(Statement {
            predicate: StatementPredicate::Equal,
            origin1: entry_statement1.origin1.clone(),
            key1: entry_statement1.key1.clone(),
            origin2: Some(entry_statement4.origin1.clone()),
            key2: Some(entry_statement4.key1.clone()),
            origin3: None,
            key3: None,
            optional_value: None
        })
    );
    entries.into_iter().for_each(|statement| {
        assert!(
            OperationType::EqualityFromEntries.apply_operation(
                GadgetID::NONE,
                Some(statement.clone()),
                Some(statement.clone()),
                None,
                None,
            ) == Some(Statement {
                predicate: StatementPredicate::Equal,
                origin1: statement.origin1.clone(),
                key1: statement.key1.clone(),
                origin2: Some(statement.origin1.clone()),
                key2: Some(statement.key1.clone()),
                origin3: None,
                key3: None,
                optional_value: None
            })
        );
    });
    assert!(
        OperationType::NonequalityFromEntries.apply_operation(
            GadgetID::NONE,
            Some(entry_statement1.clone()),
            Some(entry_statement2.clone()),
            None,
            None
        ) == Some(Statement {
            predicate: StatementPredicate::NotEqual,
            origin1: entry_statement1.origin1.clone(),
            key1: entry_statement1.key1.clone(),
            origin2: Some(entry_statement2.origin1.clone()),
            key2: Some(entry_statement2.key1.clone()),
            origin3: None,
            key3: None,
            optional_value: None
        })
    );
    assert!(OperationType::EqualityFromEntries
        .apply_operation(
            GadgetID::NONE,
            Some(entry_statement1.clone()),
            Some(entry_statement2.clone()),
            None,
            None
        )
        .is_none());

    // Gt check
    let gt_statement = OperationType::GtFromEntries.apply_operation(
        GadgetID::NONE,
        Some(entry_statement2.clone()),
        Some(entry_statement1.clone()),
        None,
        None,
    );
    assert!(
        gt_statement
            == Some(Statement {
                predicate: StatementPredicate::Gt,
                origin1: entry_statement2.origin1.clone(),
                key1: entry_statement2.key1.clone(),
                origin2: Some(entry_statement1.origin1.clone()),
                key2: Some(entry_statement1.key1.clone()),
                origin3: None,
                key3: None,
                optional_value: None
            })
    );

    // Eq transitivity check
    let eq_statement1 = OperationType::EqualityFromEntries
        .apply_operation(
            GadgetID::NONE,
            Some(entry_statement4.clone()),
            Some(entry_statement1.clone()),
            None,
            None,
        )
        .unwrap();
    let eq_statement2 = OperationType::EqualityFromEntries
        .apply_operation(
            GadgetID::NONE,
            Some(entry_statement1.clone()),
            Some(entry_statement5.clone()),
            None,
            None,
        )
        .unwrap();
    let eq_statement3 = OperationType::EqualityFromEntries
        .apply_operation(
            GadgetID::NONE,
            Some(entry_statement4.clone()),
            Some(entry_statement5.clone()),
            None,
            None,
        )
        .unwrap();

    assert!(
        OperationType::TransitiveEqualityFromStatements.apply_operation(
            GadgetID::NONE,
            Some(eq_statement1.clone()),
            Some(eq_statement2.clone()),
            None,
            None
        ) == Some(eq_statement3)
    );

    // Gt->Nonequality conversion check
    let unwrapped_gt_statement = gt_statement.unwrap();
    let mut expected_statement = unwrapped_gt_statement.clone();
    expected_statement.predicate = StatementPredicate::NotEqual;
    assert!(
        OperationType::GtToNonequality.apply_operation(
            GadgetID::NONE,
            Some(unwrapped_gt_statement.clone()),
            None,
            None,
            None
        ) == Some(expected_statement)
    );
    Ok(())
}

#[test]
fn schnorr_pod_test() -> Result<(), Error> {
    // Start with some values.
    let scalar1 = GoldilocksField(36);
    let scalar2 = GoldilocksField(52);
    let vector_value = vec![scalar1, scalar2];

    let entry1 = Entry::new_from_scalar("some key".to_string(), scalar1);
    let entry2 = Entry::new_from_scalar("some other key".to_string(), scalar2);
    let entry3 = Entry::new_from_vec("vector entry".to_string(), vector_value.clone());

    let schnorr_pod1 = POD::execute_schnorr_gadget(
        &vec![entry1.clone(), entry2.clone()],
        &SchnorrSecretKey { sk: 25 },
    );

    let schnorr_pod2 = POD::execute_schnorr_gadget(
        &vec![entry2.clone(), entry3.clone()],
        &SchnorrSecretKey { sk: 42 },
    );

    assert!(schnorr_pod1.verify()?);
    assert!(schnorr_pod2.verify()?);

    let mut schnorr_pod3 =
        POD::execute_schnorr_gadget(&vec![entry1.clone()], &SchnorrSecretKey { sk: 25 });

    // modify the internal value of the valueOf statement in schnorrPOD3
    let stmt_in_map = schnorr_pod3
        .payload
        .statements_map
        .get_mut("entry-some key");
    stmt_in_map.unwrap().optional_value = Some(ScalarOrVec::Scalar(GoldilocksField(37)));
    schnorr_pod3.payload.statements_list[1].1.optional_value =
        Some(ScalarOrVec::Scalar(GoldilocksField(37)));

    // now signature shouldn't verify
    assert!(!(schnorr_pod3.verify()?));

    // // ZK verification of SchnorrPOD 3.
    // let (builder, targets) = pod2_circuit(1, 2, 0, 0)?;

    // // Assign witnesses
    // const D: usize = 2;
    // type C = PoseidonGoldilocksConfig;
    // type F = <C as GenericConfig<D>>::F;
    // let mut pw: PartialWitness<F> = PartialWitness::new();
    // pw.set_target(targets.input_is_schnorr[0], GoldilocksField(1))?;
    // pw.set_target(targets.input_is_gpg[0], GoldilocksField::ZERO)?;
    // pw.set_target(
    //     targets.input_payload_hash[0],
    //     schnorrPOD3.payload.hash_payload(),
    // )?;
    // pw.set_target(targets.pk_index[0], GoldilocksField(1))?;
    // targets.input_proof[0].set_witness(&mut pw, &schnorrPOD3.proof)?;
    // targets.input_entries[0][0].set_witness(&mut pw, &schnorrPOD3.payload[0])?;
    // targets.input_entries[0][1].set_witness(&mut pw, &schnorrPOD3.payload[1])?;
    // let data = builder.build::<C>();
    // let proof = data.prove(pw)?;

    Ok(())
}

#[test]
fn god_pod_from_schnorr_test() -> Result<(), Error> {
    println!("god_pod_from_schnorr_test");
    // Start with some values.
    let scalar1 = GoldilocksField(36);
    let scalar2 = GoldilocksField(52);
    let scalar3 = GoldilocksField(90);
    let vector_value = vec![scalar1, scalar2];

    // make entries
    let entry1 = Entry::new_from_scalar("some key".to_string(), scalar1);
    let entry2 = Entry::new_from_scalar("some other key".to_string(), scalar2);
    let entry3 = Entry::new_from_vec("vector entry".to_string(), vector_value.clone());
    let entry4 = Entry::new_from_scalar("new key".to_string(), scalar2);
    let entry5 = Entry::new_from_scalar("foo".to_string(), GoldilocksField(100));
    let entry6 = Entry::new_from_scalar("baz".to_string(), GoldilocksField(120));
    let entry7 = Entry::new_from_scalar("yum".to_string(), scalar2);
    let _entry9 = Entry::new_from_scalar("godpod introduced entry key".to_string(), scalar3);

    // three schnorr pods
    let schnorr_pod1 = POD::execute_schnorr_gadget(
        &vec![entry1.clone(), entry2.clone()],
        &SchnorrSecretKey { sk: 25 },
    );

    let schnorr_pod2 = POD::execute_schnorr_gadget(
        &vec![entry3.clone(), entry4.clone()],
        &SchnorrSecretKey { sk: 42 },
    );

    let schnorr_pod3 = POD::execute_schnorr_gadget(
        &vec![entry5.clone(), entry6.clone(), entry7.clone()],
        &SchnorrSecretKey { sk: 83 },
    );

    // make an OraclePOD using from_pods called on the two schnorr PODs

    // first make the GPG input

    // make a map of named POD inputs
    let mut named_input_pods = HashMap::new();
    named_input_pods.insert("schnorrPOD1".to_string(), schnorr_pod1.clone());
    named_input_pods.insert("schnorrPOD2".to_string(), schnorr_pod2.clone());
    named_input_pods.insert("schnorrPOD3".to_string(), schnorr_pod3.clone());

    // make a map of (pod name, old origin name) to new origin name
    let mut origin_renaming_map = HashMap::new();
    origin_renaming_map.insert(
        ("schnorrPOD1".to_string(), "_SELF".to_string()),
        "schnorrPOD1".to_string(),
    );
    origin_renaming_map.insert(
        ("schnorrPOD2".to_string(), "_SELF".to_string()),
        "schnorrPOD2".to_string(),
    );
    origin_renaming_map.insert(
        ("schnorrPOD3".to_string(), "_SELF".to_string()),
        "schnorrPOD3".to_string(),
    );

    let gpg_input = GPGInput::new(named_input_pods, origin_renaming_map);

    // make a list of the operations we want to call
    let ops = vec![
        OperationCmd {
            operation_type: OperationType::CopyStatement,
            statement_1_parent: Some("schnorrPOD1".to_string()),
            statement_1_name: Some("entry-some key".to_string()),
            statement_2_parent: None,
            statement_2_name: None,
            statement_3_parent: None,
            statement_3_name: None,
            optional_entry: None,
            output_statement_name: "schnorrPOD1-some key".to_string(),
        },
        OperationCmd {
            operation_type: OperationType::CopyStatement,
            statement_1_parent: Some("schnorrPOD1".to_string()),
            statement_1_name: Some("entry-some other key".to_string()),
            statement_2_parent: None,
            statement_2_name: None,
            statement_3_parent: None,
            statement_3_name: None,
            optional_entry: None,
            output_statement_name: "schnorrPOD1-some other key".to_string(),
        },
        OperationCmd {
            operation_type: OperationType::CopyStatement,
            statement_1_parent: Some("schnorrPOD1".to_string()),
            statement_1_name: Some("entry-_signer".to_string()),
            statement_2_parent: None,
            statement_2_name: None,
            statement_3_parent: None,
            statement_3_name: None,
            optional_entry: None,
            output_statement_name: "schnorrPOD1-signer".to_string(),
        },
        OperationCmd {
            operation_type: OperationType::CopyStatement,
            statement_1_parent: Some("schnorrPOD2".to_string()),
            statement_1_name: Some("entry-vector entry".to_string()),
            statement_2_parent: None,
            statement_2_name: None,
            statement_3_parent: None,
            statement_3_name: None,
            optional_entry: None,
            output_statement_name: "schnorrPOD2-vec-entry".to_string(),
        },
        OperationCmd {
            operation_type: OperationType::CopyStatement,
            statement_1_parent: Some("schnorrPOD2".to_string()),
            statement_1_name: Some("entry-new key".to_string()),
            statement_2_parent: None,
            statement_2_name: None,
            statement_3_parent: None,
            statement_3_name: None,
            optional_entry: None,
            output_statement_name: "schnorrPOD2-new key".to_string(),
        },
        OperationCmd {
            operation_type: OperationType::CopyStatement,
            statement_1_parent: Some("schnorrPOD2".to_string()),
            statement_1_name: Some("entry-_signer".to_string()),
            statement_2_parent: None,
            statement_2_name: None,
            statement_3_parent: None,
            statement_3_name: None,
            optional_entry: None,
            output_statement_name: "schnorrPOD2-signer".to_string(),
        },
        OperationCmd {
            operation_type: OperationType::CopyStatement,
            statement_1_parent: Some("schnorrPOD3".to_string()),
            statement_1_name: Some("entry-yum".to_string()),
            statement_2_parent: None,
            statement_2_name: None,
            statement_3_parent: None,
            statement_3_name: None,
            optional_entry: None,
            output_statement_name: "schnorrPOD3-yum".to_string(),
        },
        OperationCmd {
            operation_type: OperationType::EqualityFromEntries,
            statement_1_parent: Some("schnorrPOD1".to_string()),
            statement_1_name: Some("entry-some other key".to_string()),
            statement_2_parent: Some("schnorrPOD2".to_string()),
            statement_2_name: Some("entry-new key".to_string()),
            statement_3_parent: None,
            statement_3_name: None,
            optional_entry: None,
            output_statement_name: "eq1".to_string(),
        },
        OperationCmd {
            operation_type: OperationType::ContainsFromEntries,
            statement_1_parent: Some("_SELF".to_string()),
            statement_1_name: Some("schnorrPOD2-vec-entry".to_string()),
            statement_2_parent: Some("schnorrPOD1".to_string()),
            statement_2_name: Some("entry-some key".to_string()),
            statement_3_parent: None,
            statement_3_name: None,
            optional_entry: None,
            output_statement_name: "contains test".to_string(),
        },
    ];

    let oracle_pod = POD::execute_oracle_gadget(&gpg_input, &ops);
    let statements = &oracle_pod.unwrap();
    for statement in statements.payload.statements_list.iter() {
        println!("statement: {:?}", statement);
    }
    Ok(())
}
