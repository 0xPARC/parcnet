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
    ProductOf = 7,
    MaxOf = 8,
}

pub fn predicate_name(predicate: StatementPredicate) -> String {
    match predicate {
        StatementPredicate::None => "NONE".to_string(),
        StatementPredicate::ValueOf => "VALUEOF".to_string(),
        StatementPredicate::Equal => "EQUAL".to_string(),
        StatementPredicate::NotEqual => "NOTEQUAL".to_string(),
        StatementPredicate::Gt => "GT".to_string(),
        StatementPredicate::Contains => "CONTAINS".to_string(),
        StatementPredicate::SumOf => "SUMOF".to_string(),
        StatementPredicate::ProductOf => "PRODUCTOF".to_string(),
        StatementPredicate::MaxOf => "MAXOF".to_string(),
    }
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

                let wrapped_pk = self.payload.statements_map.get("VALUEOF:_signer");

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
                "VALUEOF:".to_owned() + &entry.key,
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
                            statements.get_mut("_SELF").unwrap().insert(
                                predicate_name(new_statement.predicate)
                                    + ":"
                                    + &cmd.output_statement_name,
                                new_statement,
                            );
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
        let mut origin_renaming_map_clone = origin_renaming_map.clone();
        for (name, pod) in named_pods.iter() {
            pods_and_names_list.push((name.clone(), pod.clone()));
            origin_renaming_map_clone.insert((name.clone(), "_SELF".to_string()), name.clone());
        }
        pods_and_names_list.sort_by(|a, b| a.0.cmp(&b.0));

        Self {
            pods_list: pods_and_names_list.clone(),
            origin_renaming_map: origin_renaming_map_clone,
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
    RenameContainedBy = 9,
    SumOf = 10,
    ProductOf = 11,
    MaxOf = 12,
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
            (
                OperationType::RenameContainedBy,
                Some(left_statement),
                Some(right_statement),
                _,
                _,
            ) => match (left_statement, right_statement) {
                (
                    Statement {
                        predicate: StatementPredicate::Contains,
                        origin1: ll_origin,
                        key1: ll_key_name,
                        origin2: Some(lr_origin),
                        key2: Some(lr_key_name),
                        origin3: None,
                        key3: None,
                        optional_value: None,
                    },
                    Statement {
                        predicate: StatementPredicate::Equal,
                        origin1: rl_origin,
                        key1: rl_key_name,
                        origin2: Some(rr_origin),
                        key2: Some(rr_key_name),
                        origin3: None,
                        key3: None,
                        optional_value: None,
                    },
                ) if (ll_origin.origin_id, &ll_key_name)
                    == ((rl_origin.origin_id, &rl_key_name)) =>
                {
                    Some(Statement {
                        predicate: StatementPredicate::Contains,
                        origin1: rr_origin.clone(),
                        key1: rr_key_name.clone(),
                        origin2: Some(lr_origin.clone()),
                        key2: Some(lr_key_name.clone()),
                        origin3: None,
                        key3: None,
                        optional_value: None,
                    })
                }
                _ => None,
            },
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
            (OperationType::ProductOf, Some(statement1), Some(statement2), Some(statement3), _) => {
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
                        Some(ScalarOrVec::Scalar(product)),
                        StatementPredicate::ValueOf,
                        Some(ScalarOrVec::Scalar(left_product)),
                        StatementPredicate::ValueOf,
                        Some(ScalarOrVec::Scalar(right_product)),
                    ) if (product == left_product * right_product) => Some(Statement {
                        predicate: StatementPredicate::ProductOf,
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
            (OperationType::MaxOf, Some(statement1), Some(statement2), Some(statement3), _) => {
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
                        Some(ScalarOrVec::Scalar(max)),
                        StatementPredicate::ValueOf,
                        Some(ScalarOrVec::Scalar(left_value)),
                        StatementPredicate::ValueOf,
                        Some(ScalarOrVec::Scalar(right_value)),
                    ) if (max
                        == if left_value.to_canonical_u64() > right_value.to_canonical_u64() {
                            left_value
                        } else {
                            right_value
                        }) =>
                    {
                        Some(Statement {
                            predicate: StatementPredicate::MaxOf,
                            origin1: statement1.origin1,
                            key1: statement1.key1.clone(),
                            origin2: Some(statement2.origin1),
                            key2: Some(statement2.key1.clone()),
                            origin3: Some(statement3.origin1),
                            key3: Some(statement3.key1.clone()),
                            optional_value: None,
                        })
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            .get_mut("VALUEOF:some key");
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

    // i haven't written asserts yet to check the correctness of oracle and oracle2 pods
    // but i've manually inspected output and it looks good
    #[test]
    fn oracle_pod_from_schnorr_test() -> Result<(), Error> {
        println!("oracle_pod_from_schnorr_test");
        // Start with some values.
        let scalar1 = GoldilocksField(36);
        let scalar2 = GoldilocksField(52);
        let scalar3 = GoldilocksField(88);
        let vector_value = vec![scalar1, scalar2];

        // make entries
        let entry1 = Entry::new_from_scalar("apple".to_string(), scalar1);
        let entry2 = Entry::new_from_scalar("banana".to_string(), scalar2);
        let entry3 = Entry::new_from_vec("vector entry".to_string(), vector_value.clone());
        let entry4 = Entry::new_from_scalar("scalar entry".to_string(), scalar2);
        let entry5 = Entry::new_from_scalar("foo".to_string(), GoldilocksField(100));
        let entry6 = Entry::new_from_scalar("baz".to_string(), GoldilocksField(120));
        let entry7 = Entry::new_from_scalar("bar".to_string(), scalar2);
        let entry9 = Entry::new_from_scalar("claimed sum".to_string(), scalar3);

        // three schnorr pods
        let schnorr_pod1 = POD::execute_schnorr_gadget(
            &vec![entry1.clone(), entry2.clone()],
            &SchnorrSecretKey { sk: 25 },
        );

        let schnorr_pod2 = POD::execute_schnorr_gadget(
            &vec![entry3.clone(), entry4.clone()],
            &SchnorrSecretKey { sk: 42 },
        );
        // make an OraclePOD using from_pods called on the two schnorr PODs

        // first make the GPG input

        // make a map of named POD inputs
        let mut named_input_pods = HashMap::new();
        named_input_pods.insert("p1".to_string(), schnorr_pod1.clone());
        named_input_pods.insert("schnorrPOD2".to_string(), schnorr_pod2.clone());

        // make a map of (pod name, old origin name) to new origin name
        let origin_renaming_map = HashMap::new();
        // all the inputs are schnorr PODs whose only referenced origin is _SELF
        // _SELF is taken care of automatically so origin_renaming_map can be empty

        let gpg_input = GPGInput::new(named_input_pods, origin_renaming_map);

        // make a list of the operations we want to call
        let ops = vec![
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("p1".to_string()),
                statement_1_name: Some("VALUEOF:apple".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "p1-apple".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("p1".to_string()),
                statement_1_name: Some("VALUEOF:banana".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "p1-banana".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("p1".to_string()),
                statement_1_name: Some("VALUEOF:_signer".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "p1-signer".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("schnorrPOD2".to_string()),
                statement_1_name: Some("VALUEOF:vector entry".to_string()),
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
                statement_1_name: Some("VALUEOF:scalar entry".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "a scalar entry".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("schnorrPOD2".to_string()),
                statement_1_name: Some("VALUEOF:_signer".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "schnorrPOD2-signer".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::EqualityFromEntries,
                statement_1_parent: Some("p1".to_string()),
                statement_1_name: Some("VALUEOF:banana".to_string()),
                statement_2_parent: Some("schnorrPOD2".to_string()),
                statement_2_name: Some("VALUEOF:scalar entry".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "eq1".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::GtFromEntries,
                statement_1_parent: Some("p1".to_string()),
                statement_1_name: Some("VALUEOF:banana".to_string()),
                statement_2_parent: Some("p1".to_string()),
                statement_2_name: Some("VALUEOF:apple".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "apple banana comparison".to_string(),
            },
            // this operation creates a statement on top of a statement
            // created by an earlier operation
            OperationCmd {
                operation_type: OperationType::ContainsFromEntries,
                statement_1_parent: Some("_SELF".to_string()),
                statement_1_name: Some("VALUEOF:schnorrPOD2-vec-entry".to_string()),
                statement_2_parent: Some("p1".to_string()),
                statement_2_name: Some("VALUEOF:apple".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "CONTAINS:contains1".to_string(),
            },
        ];

        let oracle_pod = POD::execute_oracle_gadget(&gpg_input, &ops).unwrap();
        assert!(oracle_pod.verify()? == true);

        // make another oracle POD which takes that oracle POD and a schnorr POD

        let schnorr_pod3 = POD::execute_schnorr_gadget(
            &vec![entry5.clone(), entry6.clone(), entry7.clone()],
            &SchnorrSecretKey { sk: 83 },
        );

        // make the GPG input

        // make a map of named POD inputs
        let mut named_input_pods2 = HashMap::new();
        named_input_pods2.insert("oraclePODParent".to_string(), oracle_pod.clone());
        named_input_pods2.insert("p3".to_string(), schnorr_pod3.clone());

        // make a map of (pod name, old origin name) to new origin name
        let mut origin_renaming_map2 = HashMap::new();
        // let's keep the name of the first origin and shorten the name of the second origin
        origin_renaming_map2.insert(
            ("oraclePODParent".to_string(), "p1".to_string()),
            "p1".to_string(),
        );
        origin_renaming_map2.insert(
            ("oraclePODParent".to_string(), "schnorrPOD2".to_string()),
            "p2".to_string(),
        );

        let gpg_input = GPGInput::new(named_input_pods2, origin_renaming_map2);

        // make a list of the operations we want to call

        let ops = vec![
            OperationCmd {
                operation_type: OperationType::EqualityFromEntries,
                statement_1_parent: Some("oraclePODParent".to_string()),
                statement_1_name: Some("VALUEOF:a scalar entry".to_string()),
                statement_2_parent: Some("p3".to_string()),
                statement_2_name: Some("VALUEOF:bar".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "eq2".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::TransitiveEqualityFromStatements,
                statement_1_parent: Some("oraclePODParent".to_string()),
                statement_1_name: Some("EQUAL:eq1".to_string()),
                statement_2_parent: Some("_SELF".to_string()),
                statement_2_name: Some("EQUAL:eq2".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "EQUAL:transitive eq".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NewEntry,
                statement_1_parent: None,
                statement_1_name: None,
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(entry9.clone()),
                output_statement_name: "entry for claimed sum".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::SumOf,
                statement_1_parent: Some("_SELF".to_string()),
                statement_1_name: Some("VALUEOF:entry for claimed sum".to_string()),
                statement_2_parent: Some("oraclePODParent".to_string()),
                statement_2_name: Some("VALUEOF:p1-apple".to_string()),
                statement_3_parent: Some("oraclePODParent".to_string()),
                statement_3_name: Some("VALUEOF:a scalar entry".to_string()),
                optional_entry: None,
                output_statement_name: "sumof entry".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("oraclePODParent".to_string()),
                statement_1_name: Some("VALUEOF:schnorrPOD2-signer".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "p2-signer".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::GtToNonequality,
                statement_1_parent: Some("oraclePODParent".to_string()),
                statement_1_name: Some("GT:apple banana comparison".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "apple banana nonequality".to_string(),
            },
        ];

        let oracle_pod2 = POD::execute_oracle_gadget(&gpg_input, &ops).unwrap();
        for statement in oracle_pod2.payload.statements_list.iter() {
            println!("{:?}", statement);
        }
        assert!(oracle_pod2.verify()? == true);
        Ok(())
    }

    #[test]
    fn goodboy_test() -> Result<(), Error> {
        // A HackMD detailing execution and how each statement gets deduced is available here https://hackmd.io/@gubsheep/B1Rajmik1g

        let protocol = SchnorrSigner::new();

        let alice_sk = SchnorrSecretKey { sk: 25 };
        let alice_pk = protocol.keygen(&alice_sk).pk;
        let bob_sk = SchnorrSecretKey { sk: 26 };
        let bob_pk = protocol.keygen(&bob_sk).pk;
        let charlie_sk = SchnorrSecretKey { sk: 27 };
        let charlie_pk = protocol.keygen(&charlie_sk).pk;

        let goog_sk = SchnorrSecretKey { sk: 28 };
        let goog_pk = protocol.keygen(&goog_sk).pk;
        let msft_sk = SchnorrSecretKey { sk: 29 };
        let msft_pk = protocol.keygen(&msft_sk).pk;
        let fb_sk = SchnorrSecretKey { sk: 30 };
        let fb_pk = protocol.keygen(&fb_sk).pk;

        let known_attestors = vec![goog_pk, msft_pk, fb_pk];

        let gb1_user = Entry::new_from_scalar("user".to_string(), bob_pk);
        let gb1_age = Entry::new_from_scalar("age".to_string(), GoldilocksField(27));
        let gb1 = POD::execute_schnorr_gadget(&vec![gb1_user.clone(), gb1_age.clone()], &goog_sk);

        let gb2_user = Entry::new_from_scalar("user".to_string(), bob_pk);
        let gb2 = POD::execute_schnorr_gadget(&vec![gb2_user.clone()], &msft_sk);

        let gb3_user = Entry::new_from_scalar("user".to_string(), charlie_pk);
        let gb3_age = Entry::new_from_scalar("age".to_string(), GoldilocksField(18));
        let gb3 = POD::execute_schnorr_gadget(&vec![gb3_user.clone(), gb3_age.clone()], &msft_sk);

        let gb4_user = Entry::new_from_scalar("user".to_string(), charlie_pk);
        let gb4 = POD::execute_schnorr_gadget(&vec![gb4_user.clone()], &fb_sk);

        let alice_user_entry = Entry::new_from_scalar("user".to_string(), alice_pk);
        let known_attestors_entry =
            Entry::new_from_vec("known_attestors".to_string(), known_attestors.clone());

        let bob_alice = POD::execute_schnorr_gadget(&vec![alice_user_entry.clone()], &bob_sk);
        let charlie_alice =
            POD::execute_schnorr_gadget(&vec![alice_user_entry.clone()], &charlie_sk);

        // make the "bob trusted friend" POD
        let mut bob_tf_input_pods = HashMap::new();
        bob_tf_input_pods.insert("bob-gb1".to_string(), gb1.clone());
        bob_tf_input_pods.insert("bob-gb2".to_string(), gb2.clone());
        bob_tf_input_pods.insert("bob-alice".to_string(), bob_alice.clone());

        let bob_tf_input = GPGInput::new(bob_tf_input_pods, HashMap::new());

        let bob_tf_ops = vec![
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("bob-alice".to_string()),
                statement_1_name: Some("VALUEOF:_signer".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "bob-alice signer".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("bob-alice".to_string()),
                statement_1_name: Some("VALUEOF:user".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "bob-alice user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("bob-gb1".to_string()),
                statement_1_name: Some("VALUEOF:age".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "bob age".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NewEntry,
                statement_1_parent: None,
                statement_1_name: None,
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "known_attestors".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::EqualityFromEntries,
                statement_1_parent: Some("bob-alice".to_string()),
                statement_1_name: Some("VALUEOF:_signer".to_string()),
                statement_2_parent: Some("bob-gb1".to_string()),
                statement_2_name: Some("VALUEOF:user".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "gb1 attests to correct user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::EqualityFromEntries,
                statement_1_parent: Some("bob-alice".to_string()),
                statement_1_name: Some("VALUEOF:_signer".to_string()),
                statement_2_parent: Some("bob-gb2".to_string()),
                statement_2_name: Some("VALUEOF:user".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "gb2 attests to correct user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NonequalityFromEntries,
                statement_1_parent: Some("bob-gb1".to_string()),
                statement_1_name: Some("VALUEOF:_signer".to_string()),
                statement_2_parent: Some("bob-gb2".to_string()),
                statement_2_name: Some("VALUEOF:_signer".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "gb1 and gb2 are different".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::ContainsFromEntries,
                statement_1_parent: Some("_SELF".to_string()),
                statement_1_name: Some("VALUEOF:known_attestors".to_string()),
                statement_2_parent: Some("bob-gb1".to_string()),
                statement_2_name: Some("VALUEOF:_signer".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "gb1 has known signer".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::ContainsFromEntries,
                statement_1_parent: Some("_SELF".to_string()),
                statement_1_name: Some("VALUEOF:known_attestors".to_string()),
                statement_2_parent: Some("bob-gb2".to_string()),
                statement_2_name: Some("VALUEOF:_signer".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "gb2 has known signer".to_string(),
            },
        ];

        let bob_tf = POD::execute_oracle_gadget(&bob_tf_input, &bob_tf_ops).unwrap();
        assert!(bob_tf.verify()? == true);

        // make the "bob trusted friend" POD
        let mut charlie_tf_input_pods = HashMap::new();
        charlie_tf_input_pods.insert("charlie-gb3".to_string(), gb3.clone());
        charlie_tf_input_pods.insert("charlie-gb4".to_string(), gb4.clone());
        charlie_tf_input_pods.insert("charlie-alice".to_string(), charlie_alice.clone());

        let charlie_tf_input = GPGInput::new(charlie_tf_input_pods, HashMap::new());

        let charlie_tf_ops = vec![
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("charlie-alice".to_string()),
                statement_1_name: Some("VALUEOF:_signer".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "charlie-alice signer".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("charlie-alice".to_string()),
                statement_1_name: Some("VALUEOF:user".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "charlie-alice user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("charlie-gb3".to_string()),
                statement_1_name: Some("VALUEOF:age".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "charlie age".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NewEntry,
                statement_1_parent: None,
                statement_1_name: None,
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "known_attestors".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::EqualityFromEntries,
                statement_1_parent: Some("charlie-alice".to_string()),
                statement_1_name: Some("VALUEOF:_signer".to_string()),
                statement_2_parent: Some("charlie-gb3".to_string()),
                statement_2_name: Some("VALUEOF:user".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "gb3 attests to correct user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::EqualityFromEntries,
                statement_1_parent: Some("charlie-alice".to_string()),
                statement_1_name: Some("VALUEOF:_signer".to_string()),
                statement_2_parent: Some("charlie-gb4".to_string()),
                statement_2_name: Some("VALUEOF:user".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "gb4 attests to correct user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NonequalityFromEntries,
                statement_1_parent: Some("charlie-gb3".to_string()),
                statement_1_name: Some("VALUEOF:_signer".to_string()),
                statement_2_parent: Some("charlie-gb4".to_string()),
                statement_2_name: Some("VALUEOF:_signer".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "gb3 and gb4 are different".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::ContainsFromEntries,
                statement_1_parent: Some("_SELF".to_string()),
                statement_1_name: Some("VALUEOF:known_attestors".to_string()),
                statement_2_parent: Some("charlie-gb3".to_string()),
                statement_2_name: Some("VALUEOF:_signer".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "gb3 has known signer".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::ContainsFromEntries,
                statement_1_parent: Some("_SELF".to_string()),
                statement_1_name: Some("VALUEOF:known_attestors".to_string()),
                statement_2_parent: Some("charlie-gb4".to_string()),
                statement_2_name: Some("VALUEOF:_signer".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "gb4 has known signer".to_string(),
            },
        ];

        let charlie_tf = POD::execute_oracle_gadget(&charlie_tf_input, &charlie_tf_ops).unwrap();
        assert!(charlie_tf.verify()? == true);

        // make the "great boy" POD
        let age_bound_entry =
            Entry::new_from_scalar("known_attestors".to_string(), GoldilocksField(17));
        let age_sum_entry = Entry::new_from_scalar("age_sum".to_string(), GoldilocksField(45));
        let mut grb_input_pods = HashMap::new();
        grb_input_pods.insert("friend1".to_string(), bob_tf.clone());
        grb_input_pods.insert("friend2".to_string(), charlie_tf.clone());

        // make a map of (pod name, old origin name) to new origin name
        let mut grb_origin_rename_map = HashMap::new();
        // let's keep the name of the first origin and shorten the name of the second origin
        grb_origin_rename_map.insert(
            ("friend1".to_string(), "bob-gb1".to_string()),
            "gb1".to_string(),
        );
        grb_origin_rename_map.insert(
            ("friend1".to_string(), "bob-gb2".to_string()),
            "gb2".to_string(),
        );
        grb_origin_rename_map.insert(
            ("friend1".to_string(), "bob-alice".to_string()),
            "friend1-attest".to_string(),
        );
        grb_origin_rename_map.insert(
            ("friend2".to_string(), "charlie-gb3".to_string()),
            "gb3".to_string(),
        );
        grb_origin_rename_map.insert(
            ("friend2".to_string(), "charlie-gb4".to_string()),
            "gb4".to_string(),
        );
        grb_origin_rename_map.insert(
            ("friend2".to_string(), "charlie-alice".to_string()),
            "friend2-attest".to_string(),
        );

        let grb_input = GPGInput::new(grb_input_pods, grb_origin_rename_map);

        let grb_ops = vec![
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("friend1".to_string()),
                statement_1_name: Some("VALUEOF:bob-alice user".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "friend1 attested user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("friend2".to_string()),
                statement_1_name: Some("VALUEOF:charlie-alice user".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "friend2 attested user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NewEntry,
                statement_1_parent: None,
                statement_1_name: None,
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(age_bound_entry.clone()),
                output_statement_name: "age_bound".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NewEntry,
                statement_1_parent: None,
                statement_1_name: None,
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(age_sum_entry.clone()),
                output_statement_name: "age_sum".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NewEntry,
                statement_1_parent: None,
                statement_1_name: None,
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(known_attestors_entry.clone()),
                output_statement_name: "known_attestors".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::EqualityFromEntries,
                statement_1_parent: Some("friend1".to_string()),
                statement_1_name: Some("VALUEOF:known_attestors".to_string()),
                statement_2_parent: Some("_SELF".to_string()),
                statement_2_name: Some("VALUEOF:known_attestors".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "friend1 known_attestors same as _SELF".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::EqualityFromEntries,
                statement_1_parent: Some("friend2".to_string()),
                statement_1_name: Some("VALUEOF:known_attestors".to_string()),
                statement_2_parent: Some("_SELF".to_string()),
                statement_2_name: Some("VALUEOF:known_attestors".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "friend2 known_attestors same as _SELF".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("friend1".to_string()),
                statement_1_name: Some("EQUAL:gb1 attests to correct user".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "gb1 attests to correct user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::RenameContainedBy,
                statement_1_parent: Some("friend1".to_string()),
                statement_1_name: Some("CONTAINS:gb1 has known signer".to_string()),
                statement_2_parent: Some("_SELF".to_string()),
                statement_2_name: Some("EQUAL:friend1 known_attestors same as _SELF".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "gb1 has known signer".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("friend1".to_string()),
                statement_1_name: Some("EQUAL:gb2 attests to correct user".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "gb2 attests to correct user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::RenameContainedBy,
                statement_1_parent: Some("friend1".to_string()),
                statement_1_name: Some("CONTAINS:gb2 has known signer".to_string()),
                statement_2_parent: Some("_SELF".to_string()),
                statement_2_name: Some("EQUAL:friend1 known_attestors same as _SELF".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "gb2 has known signer".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("friend1".to_string()),
                statement_1_name: Some("NOTEQUAL:gb1 and gb2 are different".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "gb1 and gb2 are different".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("friend2".to_string()),
                statement_1_name: Some("EQUAL:gb3 attests to correct user".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "gb3 attests to correct user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::RenameContainedBy,
                statement_1_parent: Some("friend2".to_string()),
                statement_1_name: Some("CONTAINS:gb3 has known signer".to_string()),
                statement_2_parent: Some("_SELF".to_string()),
                statement_2_name: Some("EQUAL:friend2 known_attestors same as _SELF".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "gb3 has known signer".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("friend2".to_string()),
                statement_1_name: Some("EQUAL:gb4 attests to correct user".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "gb4 attests to correct user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::RenameContainedBy,
                statement_1_parent: Some("friend2".to_string()),
                statement_1_name: Some("CONTAINS:gb4 has known signer".to_string()),
                statement_2_parent: Some("_SELF".to_string()),
                statement_2_name: Some("EQUAL:friend2 known_attestors same as _SELF".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "gb4 has known signer".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("friend2".to_string()),
                statement_1_name: Some("NOTEQUAL:gb3 and gb4 are different".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "gb4 attests to correct user".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NonequalityFromEntries,
                statement_1_parent: Some("friend1".to_string()),
                statement_1_name: Some("VALUEOF:bob-alice signer".to_string()),
                statement_2_parent: Some("friend2".to_string()),
                statement_2_name: Some("VALUEOF:charlie-alice signer".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "friend1 and friend2 are different".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::GtFromEntries,
                statement_1_parent: Some("friend1".to_string()),
                statement_1_name: Some("VALUEOF:bob age".to_string()),
                statement_2_parent: Some("_SELF".to_string()),
                statement_2_name: Some("VALUEOF:age_bound".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "friend1 is at least 18".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::GtFromEntries,
                statement_1_parent: Some("friend2".to_string()),
                statement_1_name: Some("VALUEOF:charlie age".to_string()),
                statement_2_parent: Some("_SELF".to_string()),
                statement_2_name: Some("VALUEOF:age_bound".to_string()),
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "friend2 is at least 18".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::SumOf,
                statement_1_parent: Some("_SELF".to_string()),
                statement_1_name: Some("VALUEOF:age_sum".to_string()),
                statement_2_parent: Some("friend1".to_string()),
                statement_2_name: Some("VALUEOF:bob age".to_string()),
                statement_3_parent: Some("friend2".to_string()),
                statement_3_name: Some("VALUEOF:charlie age".to_string()),
                optional_entry: None,
                output_statement_name: "sum of friend1 and friend2 ages".to_string(),
            },
        ];

        let alice_grb = POD::execute_oracle_gadget(&grb_input, &grb_ops).unwrap();
        assert!(alice_grb.verify()? == true);

        for statement in alice_grb.payload.statements_list {
            println!("{:?}", statement);
        }

        Ok(())
    }

    #[test]
    fn final_pod_test() -> Result<(), Error> {
        // In this test we will execute this PEX script below and generate final-pod using
        // The oracle gadget on 4 different SchnorrPOD assigned to Alice, Bob, and Charlie

        // [createpod final-pod  ; Charlie's pod (multiplayer execution from Alice and Bob)
        //  remote-max [max [from @alice [pod? [result [+ [pod? [x]] [pod? [z]]]]]]
        //                  [from @bob [pod? [result [* [pod? [a]] [pod? [b]]]]]]]
        //
        //  local-sum [+ [pod? [local-value]] 42]
        //
        //  overall-max [max remote-max
        //                   local-sum]]

        let alice_sk = SchnorrSecretKey { sk: 25 };
        let bob_sk = SchnorrSecretKey { sk: 26 };
        let charlie_sk = SchnorrSecretKey { sk: 27 };
        // Let's create simple-pod-1

        // [createpod simple-pod-1  ; Alice's first pod
        //   x 10
        //   y 20]

        let simple_pod_1_x = Entry::new_from_scalar("x".to_string(), GoldilocksField(10));
        let simple_pod_1_y = Entry::new_from_scalar("y".to_string(), GoldilocksField(20));

        let simple_pod_1 = POD::execute_schnorr_gadget(
            &vec![simple_pod_1_x.clone(), simple_pod_1_y.clone()],
            &alice_sk,
        );

        // ^
        // [defpod simple-pod-1
        //   x 10
        //   y 20
        //   :meta [[user @alice]]]

        // Let's create simple-pod-2

        // [createpod simple-pod-2  ; Alice's second pod
        //   z 15
        //   w 25]

        let simple_pod_2_z = Entry::new_from_scalar("z".to_string(), GoldilocksField(15));
        let simple_pod_2_w = Entry::new_from_scalar("w".to_string(), GoldilocksField(25));

        let simple_pod_2 = POD::execute_schnorr_gadget(
            &vec![simple_pod_2_z.clone(), simple_pod_2_w.clone()],
            &alice_sk,
        );

        // [defpod simple-pod-2
        //   z 15
        //   w 25
        //   :meta [[user @alice]]]

        // Let's create simple-pod-3

        // [createpod simple-pod-3  ; Bob's pod
        //   a 30
        //   b 40]

        let simple_pod_3_a = Entry::new_from_scalar("a".to_string(), GoldilocksField(30));
        let simple_pod_3_b = Entry::new_from_scalar("b".to_string(), GoldilocksField(40));

        let simple_pod_3 = POD::execute_schnorr_gadget(
            &vec![simple_pod_3_a.clone(), simple_pod_3_b.clone()],
            &bob_sk,
        );

        // [defpod simple-pod-3
        //   a 30
        //   b 40
        //   :meta [[user @bob]]]

        // Let's create Charlie's local pod

        // [createpod simple-pod-4  ; Charlie's pod
        //   local-value 100]

        let simple_pod_4_local_value =
            Entry::new_from_scalar("local-value".to_string(), GoldilocksField(100));

        let simple_pod_4 =
            POD::execute_schnorr_gadget(&vec![simple_pod_4_local_value.clone()], &charlie_sk);

        // Now let's create the sum-pod using the Oracle gadget

        // [createpod sum-pod  ; Alice's sum pod
        //   result [+ [pod? [x]]    ; Get x from Alice's simple-pod-1
        //             [pod? [z]]]]  ; Get z from Alice's simple-pod-2

        let mut sum_pod_input_pods = HashMap::new();
        sum_pod_input_pods.insert("pod-1".to_string(), simple_pod_1.clone());
        sum_pod_input_pods.insert("pod-2".to_string(), simple_pod_2.clone());

        // No need to do origin remapping because it's all SELF
        let sum_pod_input = GPGInput::new(sum_pod_input_pods, HashMap::new());

        // Note to Ryan: a better way to do these OperationCmd is to have an enum with different
        // Fields inside it for each operation
        // In fact we could probably do the same for statement where it would be a big enum type
        // We wouldn't have as many Some and None everywhere.

        let sum_pod_ops = vec![
            // If we have this operation, we would copy X and reveal it. Here we don't copy X (we just prove that 25 is the sum of x and z)
            // OperationCmd {
            //     operation_type: OperationType::CopyStatement,
            //     statement_1_parent: Some("pod-1".to_string()), // a pointer to simple_pod_1, using the sum_pod_input_pods HashMap
            //     statement_1_name: Some("VALUEOF:x".to_string()), // a pointer to the value of statement in simple_pod_1
            //                                                     // this name comes from applying the predicate name (from predicate_name) followed by the
            //                                                     // statement name
            //     statement_2_parent: None,
            //     statement_2_name: None,
            //     statement_3_name: None,
            //     statement_3_parent: None,
            //     optional_entry: None,
            //     output_statement_name: "pod-1-value-of-x".to_string()
            // },
            OperationCmd {
                operation_type: OperationType::NewEntry,
                statement_1_parent: None,
                statement_1_name: None,
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(Entry::new_from_scalar(
                    "result".to_string(),
                    GoldilocksField(10 + 15),
                )), // We store simple-pod-1.x + simple-pod-2.z in a new entry
                output_statement_name: "result".to_string(), // statement name are only used to have operations point at statement (poor man's pointer)
                                                             // they are not cryptographic, hence why we need another name beyond the optional entry
            },
            OperationCmd {
                operation_type: OperationType::SumOf,
                statement_1_parent: Some("_SELF".to_string()),
                statement_1_name: Some("VALUEOF:result".to_string()),
                statement_2_parent: Some("pod-2".to_string()),
                statement_2_name: Some("VALUEOF:z".to_string()),
                statement_3_parent: Some("pod-1".to_string()),
                statement_3_name: Some("VALUEOF:x".to_string()),
                optional_entry: None,
                output_statement_name: "sum-of-pod-1-x-and-pod-2-z".to_string(),
            },
        ];

        let sum_pod = POD::execute_oracle_gadget(&sum_pod_input, &sum_pod_ops).unwrap();
        assert!(sum_pod.verify()? == true);

        // [defpod sum-pod
        //   result 25
        //   :meta [[user @alice]
        //          [result [+ [pod? [x]] [pod? [z]]]]]]

        // Now let's create the product-pod using the Oracle gadget

        // [createpod product-pod  ; Bob's product pod
        //   result [* [pod? [a]]    ; Get a from Bob's simple-pod-3
        //             [pod? [b]]]]  ; Get b from Bob's simple-pod-3

        let mut product_pod_input_pods = HashMap::new();
        product_pod_input_pods.insert("pod-3".to_string(), simple_pod_3.clone());

        // No need to do origin remapping because it's all SELF
        let product_pod_input = GPGInput::new(product_pod_input_pods, HashMap::new());

        let product_pod_ops = vec![
            OperationCmd {
                operation_type: OperationType::NewEntry,
                statement_1_parent: None,
                statement_1_name: None,
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(Entry::new_from_scalar(
                    "result".to_string(),
                    GoldilocksField(30 * 40),
                )), // We store simple-pod-1.x + simple-pod-2.z in a new entry
                output_statement_name: "result".to_string(), // statement name are only used to have operations point at statement (poor man's pointer)
                                                             // they are not cryptographic, hence why we need another name beyond the optional entry
            },
            OperationCmd {
                operation_type: OperationType::ProductOf,
                statement_1_parent: Some("_SELF".to_string()),
                statement_1_name: Some("VALUEOF:result".to_string()),
                statement_2_parent: Some("pod-3".to_string()),
                statement_2_name: Some("VALUEOF:a".to_string()),
                statement_3_parent: Some("pod-3".to_string()),
                statement_3_name: Some("VALUEOF:b".to_string()),
                optional_entry: None,
                output_statement_name: "product-of-pod-3-a-and-pod-3-b".to_string(),
            },
        ];

        let product_pod = POD::execute_oracle_gadget(&product_pod_input, &product_pod_ops).unwrap();
        assert!(product_pod.verify()? == true);

        // [defpod product-pod
        //   result 1200
        //   :meta [[user @bob]
        //          [result [* [pod? [a]] [pod? [b]]]]]]

        // And finally, now let's put together the final POD
        // Because the Oracle Gadget is meant to receive all the PODs involved in the computation
        // Details on where the POD comes from (like from @alice or from @bob) will not be visible in the operations below
        // You can think of the Oracle gadget as a magic box into which we put all the input PODs and we compute the output

        // [createpod final-pod  ; Charlie's pod (multiplayer execution from Alice and Bob)
        //   remote-max [max [from @alice [pod? [result [+ [pod? [x]] [pod? [z]]]]]]
        //                   [from @bob [pod? [result [* [pod? [a]] [pod? [b]]]]]]]
        //
        //   local-sum [+ [pod? [local-value]] 42]
        //
        //   overall-max [max remote-max
        //                    local-sum]]

        let mut final_pod_input_pods = HashMap::new();
        final_pod_input_pods.insert("sum-pod".to_string(), sum_pod.clone());
        final_pod_input_pods.insert("product-pod".to_string(), product_pod.clone());
        final_pod_input_pods.insert("simple-pod-4".to_string(), simple_pod_4.clone());

        // We need to remap the origins that are in product-pod and sum-pod. They can't just
        // become product-pod and sum-pod, they need their own name
        // We'll simply collapse them to pod-1, pod-2, pod-3 given there is no name clash here
        // (ie: an origin in sum-pod doesn't clash with an origin in product-pod)
        let mut final_pod_origin_renaming_map = HashMap::new();
        final_pod_origin_renaming_map.insert(
            ("sum-pod".to_string(), "pod-1".to_string()),
            "pod-1".to_string(),
        );
        final_pod_origin_renaming_map.insert(
            ("sum-pod".to_string(), "pod-2".to_string()),
            "pod-2".to_string(),
        );
        final_pod_origin_renaming_map.insert(
            ("product-pod".to_string(), "pod-3".to_string()),
            "pod-3".to_string(),
        );
        // Note to Ryan: remapping is unnecessary if we don't have strings as poor man's pointer
        // It would never be ambiguous what we are referring to
        // However the serialization story is unknown. Maybe we use content ID as origin.
        // The issue with content ID is they can leak data because you can brute force a hidden
        // value if you happen to know all of them but that one (keep hashing different value till you get to the same ID)
        let final_pod_input = GPGInput::new(final_pod_input_pods, final_pod_origin_renaming_map);

        let final_pod_ops = vec![
            // We copy the ProductOf and SumOf statement from product-pod and sum-pod
            // To carry over that part of the computational graph
            // We want final-pod's remote-max to be clearly the max of two entries called
            // "result" that came from the sum and the product of other pods
            // We could have remote-max be the max of two pod (and stop there)
            // But this is not what is being expressed in the createpod of final-pod
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("sum-pod".to_string()),
                statement_1_name: Some("SUMOF:sum-of-pod-1-x-and-pod-2-z".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "sum-of-pod-1-x-and-pod-2-z".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::CopyStatement,
                statement_1_parent: Some("product-pod".to_string()),
                statement_1_name: Some("PRODUCTOF:product-of-pod-3-a-and-pod-3-b".to_string()),
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: None,
                output_statement_name: "product-of-pod-3-a-and-pod-3-b".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NewEntry,
                statement_1_parent: None,
                statement_1_name: None,
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(Entry::new_from_scalar(
                    "remote-max".to_string(),
                    GoldilocksField(1200),
                )),
                output_statement_name: "remote-max".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::MaxOf,
                statement_1_parent: Some("_SELF".to_string()),
                statement_1_name: Some("VALUEOF:remote-max".to_string()),
                statement_2_parent: Some("sum-pod".to_string()),
                statement_2_name: Some("VALUEOF:result".to_string()),
                statement_3_parent: Some("product-pod".to_string()),
                statement_3_name: Some("VALUEOF:result".to_string()),
                optional_entry: None,
                output_statement_name: "max-sum-pod-and-product-pod".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NewEntry,
                statement_1_parent: None,
                statement_1_name: None,
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(Entry::new_from_scalar(
                    "42".to_string(),
                    GoldilocksField(42),
                )),
                output_statement_name: "42".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NewEntry,
                statement_1_parent: None,
                statement_1_name: None,
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(Entry::new_from_scalar(
                    "local-sum".to_string(),
                    GoldilocksField(142),
                )),
                output_statement_name: "local-sum".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::SumOf,
                statement_1_parent: Some("_SELF".to_string()),
                statement_1_name: Some("VALUEOF:local-sum".to_string()),
                statement_2_parent: Some("simple-pod-4".to_string()),
                statement_2_name: Some("VALUEOF:local-value".to_string()),
                statement_3_parent: Some("_SELF".to_string()),
                statement_3_name: Some("VALUEOF:42".to_string()),
                optional_entry: None,
                output_statement_name: "sum-of-simple-pod-4-local-value-and-42".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::NewEntry,
                statement_1_parent: None,
                statement_1_name: None,
                statement_2_parent: None,
                statement_2_name: None,
                statement_3_parent: None,
                statement_3_name: None,
                optional_entry: Some(Entry::new_from_scalar(
                    "overall-max".to_string(),
                    GoldilocksField(1200),
                )),
                output_statement_name: "overall-max".to_string(),
            },
            OperationCmd {
                operation_type: OperationType::MaxOf,
                statement_1_parent: Some("_SELF".to_string()),
                statement_1_name: Some("VALUEOF:overall-max".to_string()),
                statement_2_parent: Some("_SELF".to_string()),
                statement_2_name: Some("VALUEOF:remote-max".to_string()),
                statement_3_parent: Some("_SELF".to_string()),
                statement_3_name: Some("VALUEOF:local-sum".to_string()),
                optional_entry: None,
                output_statement_name: "max-of-remote-max-and-local-max".to_string(),
            },
        ];

        let final_pod = POD::execute_oracle_gadget(&final_pod_input, &final_pod_ops).unwrap();
        assert!(final_pod.verify()? == true);

        // If you are curious what the statements in this POD are
        // for statement in final_pod.payload.statements_list {
        //     println!("{:?}", statement);
        // }

        // [defpod final-pod
        //   remote-max 1200
        //   local-sum 142
        //   overall-max 1200
        //   :meta [[user @charlie]
        //          [remote-max [max [pod? [result [+ [pod? [x]] [pod? [z]]]]]
        //                           [pod? [result [* [pod? [a]] [pod? [b]]]]]]]
        //          [local-sum [+ [pod? [local-value]] 42]]
        //          [overall-max [max local-sum
        //                            custom-sum]]]]

        Ok(())
    }
}
