mod macros;
mod pex_constants;
use constants::{NS, VL};
pub mod repl;
pub mod store;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use pex_constants::*;

use tracing::info;

use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};

use pod2::{
    pod::{
        entry::Entry,
        gadget::GadgetID,
        origin::Origin,
        payload::HashablePayload,
        statement::{AnchoredKey, StatementRef},
        value::ScalarOrVec,
        GPGInput, Op, OpCmd, Statement, POD,
    },
    signature::schnorr::SchnorrSecretKey,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]

pub enum ORef {
    S,
    P(String),
    Q(usize),
}

impl From<ORef> for String {
    fn from(oref: ORef) -> String {
        match oref {
            ORef::S => SELF_ORIGIN_NAME.to_string(),
            ORef::P(s) => s,
            ORef::Q(_) => "query".to_string(),
        }
    }
}

impl From<ORef> for Origin {
    fn from(oref: ORef) -> Self {
        match oref {
            ORef::S => Origin::SELF,
            ORef::P(name) => Origin::new(GoldilocksField(0), name.clone(), GadgetID::ORACLE), // TOOD: figure out if its fine to have Id 0
            ORef::Q(id) => Origin::new(
                GoldilocksField(id as u64),
                format!("query_{}", id),
                GadgetID::ORACLE,
            ),
        }
    }
}

impl From<Origin> for ORef {
    fn from(origin: Origin) -> Self {
        if origin.is_self() {
            ORef::S
        } else if origin.origin_name == "query" {
            ORef::Q(origin.origin_id.to_canonical_u64() as usize)
        } else {
            ORef::P(origin.origin_name)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SRef(pub ORef, pub String);

impl SRef {
    pub fn new(pod_id: impl Into<String>, statement_id: impl Into<String>) -> Self {
        Self(ORef::P(pod_id.into()), statement_id.into())
    }

    pub fn self_ref(statement_id: impl Into<String>) -> Self {
        Self(ORef::S, statement_id.into())
    }
}

impl From<SRef> for StatementRef {
    fn from(sref: SRef) -> StatementRef {
        StatementRef(sref.0.into(), sref.1)
    }
}

impl<'a> From<&'a SRef> for StatementRef {
    fn from(sref: &'a SRef) -> StatementRef {
        StatementRef(sref.0.clone().into(), sref.1.clone())
    }
}

#[derive(Default)]
pub struct MyPods {
    pub pods: Vec<POD>,
}

impl MyPods {
    pub fn add_pod(&mut self, pod: POD) {
        self.pods.push(pod);
    }
}

pub type User = String;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct ScriptId(String);

impl ScriptId {
    // TODO: Hash after lexing
    pub fn from_script(script: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(script.as_bytes());
        let result = hasher.finalize();
        Self(hex::encode(result))
    }
}

#[async_trait]
pub trait SharedStore: Send + Sync {
    async fn get_value(&self, script_id: &ScriptId, aid: u64) -> Option<Value>;
    fn set_value(&self, script_id: &ScriptId, aid: u64, value: Value);
    async fn get_pod(&self, id: &String) -> Option<POD>;
    fn store_pod(&self, pod: POD) -> String;
}

pub struct InMemoryStore {
    values: Arc<Mutex<HashMap<(ScriptId, u64), Value>>>,
    pods: Arc<Mutex<HashMap<String, POD>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            values: Arc::new(Mutex::new(HashMap::new())),
            pods: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl SharedStore for InMemoryStore {
    async fn get_value(&self, script_id: &ScriptId, id: u64) -> Option<Value> {
        let mut counter = 0;
        loop {
            if let Some(v) = self
                .values
                .lock()
                .unwrap()
                .get(&(script_id.clone(), id))
                .cloned()
            {
                return Some(v);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            counter += 1;
            if counter > 10 {
                return None;
            }
        }
    }

    fn set_value(&self, script_id: &ScriptId, id: u64, value: Value) {
        self.values
            .lock()
            .unwrap()
            .insert((script_id.clone(), id), value);
    }

    async fn get_pod(&self, id: &String) -> Option<POD> {
        let mut counter = 0;
        loop {
            if let Some(v) = self.pods.lock().unwrap().get(id).cloned() {
                return Some(v);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            counter += 1;
            if counter > 10 {
                return None;
            }
        }
    }

    fn store_pod(&self, pod: POD) -> String {
        let id = PodBuilder::pod_id(&pod);
        self.pods.lock().unwrap().insert(id.clone(), pod);
        id
    }
}

#[derive(Clone)]
pub struct Env {
    user: User,
    pub pod_store: Arc<Mutex<MyPods>>,
    pub current_builder: Option<Arc<Mutex<PodBuilder>>>,
    pub current_query: Option<Arc<Mutex<PodQueryBuilder>>>,
    shared: Arc<dyn SharedStore>,
    bindings: Arc<Mutex<HashMap<String, Value>>>,
    sk: Option<SchnorrSecretKey>,
    script_id: Option<ScriptId>,
}

#[derive(Clone, Debug)]
pub struct PodBuilder {
    pub pending_operations: Vec<(String, OpCmd)>,
    pub input_pods: HashMap<String, POD>,
    pub matched_statements: Vec<SRef>,
    pub next_origin_id: usize,
    pub next_result_key_id: usize,
    pub next_statement_id: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Value {
    String(String),
    Scalar(GoldilocksField),
    PodRef(POD),
    SRef(SRef),
    Operation(Box<Operation>),
    Assert(Box<Assert>),
    List(Vec<Value>),
}

#[derive(Clone, Copy, Debug)]
pub enum AssertType {
    Gt,
    Lt,
    Eq,
    Neq,
}

impl AssertType {
    fn from_str(s: &str) -> Result<Self> {
        match s {
            ">" => Ok(AssertType::Gt),
            "<" => Ok(AssertType::Lt),
            "=" => Ok(AssertType::Eq),
            "!=" => Ok(AssertType::Neq),
            _ => Err(anyhow!("Unknown operation type: {}", s)),
        }
    }
}

impl From<(AssertType, Value, Value)> for Assert {
    fn from((assert_type, op1, op2): (AssertType, Value, Value)) -> Self {
        match assert_type {
            AssertType::Gt => Assert::Gt(op1, op2),
            AssertType::Lt => Assert::Lt(op1, op2),
            AssertType::Eq => Assert::Eq(op1, op2),
            AssertType::Neq => Assert::Neq(op1, op2),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Assert {
    Gt(Value, Value),
    Lt(Value, Value),
    Eq(Value, Value),
    Neq(Value, Value),
}

impl Assert {
    fn extract_value(value: &Value, env: Option<&Env>) -> Result<GoldilocksField> {
        match value {
            Value::Scalar(s) => Ok(*s),
            Value::SRef(r) if env.is_some() => get_value_from_sref(r, env.unwrap()),
            _ => Err(anyhow!("Invalid operand type")),
        }
    }

    fn evaluate_values(&self, env: Option<&Env>) -> Result<(GoldilocksField, GoldilocksField)> {
        match self {
            Assert::Gt(a, b) | Assert::Lt(a, b) | Assert::Eq(a, b) | Assert::Neq(a, b) => {
                let value1 = Self::extract_value(a, env)?;
                let value2 = Self::extract_value(b, env)?;
                Ok((value1, value2))
            }
        }
    }

    fn apply_assert(&self, value1: GoldilocksField, value2: GoldilocksField) -> GoldilocksField {
        match self {
            Assert::Gt(_, _) => {
                if value1.to_canonical_u64() > value2.to_canonical_u64() {
                    GoldilocksField(1)
                } else {
                    GoldilocksField(0)
                }
            }
            Assert::Lt(_, _) => {
                if value1.to_canonical_u64() < value2.to_canonical_u64() {
                    GoldilocksField(1)
                } else {
                    GoldilocksField(0)
                }
            }
            Assert::Eq(_, _) => {
                if value1.to_canonical_u64() == value2.to_canonical_u64() {
                    GoldilocksField(1)
                } else {
                    GoldilocksField(0)
                }
            }
            Assert::Neq(_, _) => {
                if value1.to_canonical_u64() != value2.to_canonical_u64() {
                    GoldilocksField(1)
                } else {
                    GoldilocksField(0)
                }
            }
        }
    }

    fn eval(&self) -> Result<GoldilocksField> {
        let (value1, value2) = self.evaluate_values(None)?;
        Ok(self.apply_assert(value1, value2))
    }

    fn predicate_from_op(assert_type: AssertType) -> String {
        match assert_type {
            AssertType::Gt => "GT".to_string(),
            AssertType::Lt => "LT".to_string(),
            AssertType::Eq => "EQUAL".to_string(),
            AssertType::Neq => "NOTEQUAL".to_string(),
        }
    }
    fn into_pod_op(assert_type: AssertType, op1: SRef, op2: SRef) -> Op<StatementRef> {
        match assert_type {
            AssertType::Gt => Op::GtFromEntries(op1.into(), op2.into()),
            AssertType::Lt => Op::LtFromEntries(op1.into(), op2.into()),
            AssertType::Eq => Op::EqualityFromEntries(op1.into(), op2.into()),
            AssertType::Neq => Op::NonequalityFromEntries(op1.into(), op2.into()),
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum OpType {
    Add,
    Multiply,
    Max,
}

impl OpType {
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "+" => Ok(OpType::Add),
            "*" => Ok(OpType::Multiply),
            "max" => Ok(OpType::Max),
            _ => Err(anyhow!("Unknown operation type: {}", s)),
        }
    }
}

impl From<(OpType, Value, Value)> for Operation {
    fn from((op_type, op1, op2): (OpType, Value, Value)) -> Self {
        match op_type {
            OpType::Add => Operation::Sum(op1, op2),
            OpType::Multiply => Operation::Product(op1, op2),
            OpType::Max => Operation::Max(op1, op2),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Operation {
    Sum(Value, Value),
    Product(Value, Value),
    Max(Value, Value),
}

impl Operation {
    fn extract_value(value: &Value, env: Option<&Env>) -> Result<GoldilocksField> {
        match value {
            Value::Scalar(s) => Ok(*s),
            Value::SRef(r) if env.is_some() => get_value_from_sref(r, env.unwrap()),
            _ => Err(anyhow!("Invalid operand type")),
        }
    }

    fn evaluate_values(&self, env: Option<&Env>) -> Result<(GoldilocksField, GoldilocksField)> {
        match self {
            Operation::Sum(a, b) | Operation::Product(a, b) | Operation::Max(a, b) => {
                let value1 = Self::extract_value(a, env)?;
                let value2 = Self::extract_value(b, env)?;
                Ok((value1, value2))
            }
        }
    }

    fn apply_operation(&self, value1: GoldilocksField, value2: GoldilocksField) -> GoldilocksField {
        match self {
            Operation::Sum(_, _) => value1 + value2,
            Operation::Product(_, _) => value1 * value2,
            Operation::Max(_, _) => {
                if value1.to_canonical_u64() > value2.to_canonical_u64() {
                    value1
                } else {
                    value2
                }
            }
        }
    }

    fn eval(&self) -> Result<GoldilocksField> {
        let (value1, value2) = self.evaluate_values(None)?;
        Ok(self.apply_operation(value1, value2))
    }

    fn eval_with_env(&self, env: &Env) -> Result<GoldilocksField> {
        let (value1, value2) = self.evaluate_values(Some(env))?;
        Ok(self.apply_operation(value1, value2))
    }
    fn into_pod_op(op_type: OpType, result_ref: SRef, op1: SRef, op2: SRef) -> Op<StatementRef> {
        match op_type {
            OpType::Add => Op::SumOf(result_ref.into(), op1.into(), op2.into()),
            OpType::Multiply => Op::ProductOf(result_ref.into(), op1.into(), op2.into()),
            OpType::Max => Op::MaxOf(result_ref.into(), op1.into(), op2.into()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PodQueryBuilder {
    // srefs are the bindings we are interested in
    srefs: Vec<SRef>,
    constraints: Vec<QueryConstraint>,
    current_origin_id: usize,
}

#[derive(Debug, Clone)]
enum QueryConstraint {
    HasKey {
        key: String,
    },
    ExactValue {
        key: String,
        value: ScalarOrVec,
    },
    Operation {
        result_key: String,
        operation: OperationConstraint,
    },
    Assert {
        assert_type: AssertType,
        operands: (Box<OperandConstraint>, Box<OperandConstraint>),
    },
}

#[derive(Debug, Clone)]
struct OperationConstraint {
    op_type: OpType,
    operands: (Box<OperandConstraint>, Box<OperandConstraint>),
}

#[derive(Debug, Clone)]
enum OperandConstraint {
    EntryRef(String),
    Constant(ScalarOrVec),
    Operation(Box<OperationConstraint>),
}

impl PodQueryBuilder {
    fn new() -> Self {
        Self {
            srefs: Vec::new(),
            constraints: Vec::new(),
            current_origin_id: 1,
        }
    }
    fn add_assert(&mut self, assert: &Assert) -> Result<()> {
        let (op1, op2) = match assert {
            Assert::Eq(v1, v2) | Assert::Neq(v1, v2) | Assert::Gt(v1, v2) | Assert::Lt(v1, v2) => {
                (v1, v2)
            }
        };
        let op1_constraint = self.add_value(op1)?;
        let op2_constraint = self.add_value(op2)?;

        let assert_type = match assert {
            Assert::Eq(_, _) => AssertType::Eq,
            Assert::Neq(_, _) => AssertType::Neq,
            Assert::Gt(_, _) => AssertType::Gt,
            Assert::Lt(_, _) => AssertType::Lt,
        };

        self.constraints.push(QueryConstraint::Assert {
            assert_type,
            operands: (Box::new(op1_constraint), Box::new(op2_constraint)),
        });
        Ok(())
    }

    fn add_operation(&mut self, op: &Operation) -> Result<OperandConstraint> {
        let (op1, op2) = match op {
            Operation::Sum(v1, v2) | Operation::Product(v1, v2) | Operation::Max(v1, v2) => {
                (v1, v2)
            }
        };

        let op1_constraint = self.add_value(op1)?;
        let op2_constraint = self.add_value(op2)?;

        let op_type = match op {
            Operation::Sum(_, _) => OpType::Add,
            Operation::Product(_, _) => OpType::Multiply,
            Operation::Max(_, _) => OpType::Max,
        };

        Ok(OperandConstraint::Operation(Box::new(
            OperationConstraint {
                op_type,
                operands: (Box::new(op1_constraint), Box::new(op2_constraint)),
            },
        )))
    }

    fn add_value(&mut self, value: &Value) -> Result<OperandConstraint> {
        match value {
            Value::Scalar(s) => Ok(OperandConstraint::Constant(ScalarOrVec::Scalar(*s))),
            Value::Operation(op) => self.add_operation(op),
            Value::SRef(sref) => {
                let key = sref.1.split(':').last().unwrap().to_string();
                Ok(OperandConstraint::EntryRef(key))
            }
            _ => Err(anyhow!("Invalid value type")),
        }
    }

    fn add_key_constraint(&mut self, key: String) {
        self.constraints.push(QueryConstraint::HasKey { key });
    }

    fn add_constraint(&mut self, key: String, constraint: OperandConstraint) {
        match constraint {
            OperandConstraint::Constant(value) => {
                self.constraints
                    .push(QueryConstraint::ExactValue { key, value });
            }
            OperandConstraint::Operation(op) => {
                self.constraints.push(QueryConstraint::Operation {
                    result_key: key,
                    operation: *op,
                });
            }
            OperandConstraint::EntryRef(_) => {
                self.constraints.push(QueryConstraint::HasKey { key });
            }
        }
    }

    fn build_constraints(&self) -> Vec<QueryConstraint> {
        self.constraints.clone()
    }
}

impl PodBuilder {
    pub fn new() -> Self {
        Self {
            pending_operations: Vec::new(),
            matched_statements: Vec::new(),
            input_pods: HashMap::new(),
            next_origin_id: 2,
            next_result_key_id: 0,
            next_statement_id: 0,
        }
    }
    pub fn pod_id(pod: &POD) -> String {
        let pod_hash = pod.payload.hash_payload();
        let name = format!("{}{:?}", POD_PREFIX, pod_hash);
        name
    }
    pub fn register_input_pod(&mut self, pod: &POD) -> String {
        let name = PodBuilder::pod_id(pod);
        if let Some(_) = self.input_pods.get(&name) {
            name.clone()
        } else {
            self.input_pods.insert(name.clone(), pod.clone());
            name.clone()
        }
    }

    pub fn extend_matched_statements(&mut self, matched_statements: Vec<SRef>) {
        self.matched_statements.extend(matched_statements);
    }

    pub fn next_result_key_id(&mut self) -> String {
        let key = format!("{}{}", STATEMENT_PREFIX_RESULT, self.next_result_key_id);
        self.next_result_key_id += 1;
        key
    }

    pub fn next_statement_id(&mut self) -> String {
        let id = format!("{}{}", STATEMENT_PREFIX_OTHER, self.next_statement_id);
        self.next_statement_id += 1;
        id
    }

    pub fn add_operation(&mut self, op: Op<StatementRef>, statement_id: String) {
        self.pending_operations
            .push((statement_id.clone(), OpCmd(op, statement_id)));
    }

    fn get_or_create_constant_ref(&mut self, value: GoldilocksField) -> SRef {
        let key = value.to_string();

        // Only match against other constants (statements starting with "constant_")
        if let Some((statement_id, _)) =
            self.pending_operations.iter().find(|(statement_id, op)| {
                statement_id.starts_with(STATEMENT_PREFIX_CONSTANT)
                    && if let Op::NewEntry(entry) = &op.0 {
                        entry.key == key && entry.value == ScalarOrVec::Scalar(value)
                    } else {
                        false
                    }
            })
        {
            return SRef::self_ref(format!("{}:{}", PREDICATE_VALUEOF, statement_id));
        }

        // Create new constant if it doesn't exist
        let statement_name = format!("{}{}", STATEMENT_PREFIX_CONSTANT, key);
        self.add_operation(
            Op::NewEntry(Entry {
                key: key.clone(),
                value: ScalarOrVec::Scalar(value),
            }),
            statement_name.clone(),
        );
        SRef::self_ref(format!("{}:{}", PREDICATE_VALUEOF, statement_name))
    }

    pub fn finalize(&mut self, env: &Env) -> Result<POD> {
        let could_be_schnorr = self.input_pods.is_empty()
            && self
                .pending_operations
                .iter()
                .all(|(_, op)| matches!(op.0, Op::NewEntry(_)))
            && env.sk.is_some();

        if could_be_schnorr {
            // Convert pending operations into entries
            let entries = self
                .pending_operations
                .iter()
                .filter_map(|(_, op)| {
                    if let Op::NewEntry(entry) = &op.0 {
                        Some(entry.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            Ok(POD::execute_schnorr_gadget::<NS, VL>(&entries, &env.sk.unwrap()).unwrap())
        } else {
            let mut origin_renaming_map = HashMap::new();
            let mut used_origin_names = HashSet::new();
            let mut next_id = 1;

            for (pod_id, pod) in &self.input_pods {
                // For _SELF origins, use the pod's payload hash
                let pod_hash = format!("{:?}", pod.payload.hash_payload());
                if !used_origin_names.insert(pod_hash.clone()) {
                    while used_origin_names.contains(&format!("origin_{}", next_id)) {
                        next_id += 1;
                    }
                    let fallback_name = format!("origin_{}", next_id);
                    origin_renaming_map.insert(
                        (pod_id.clone(), SELF_ORIGIN_NAME.to_string()),
                        fallback_name.clone(),
                    );
                    used_origin_names.insert(fallback_name);
                    next_id += 1;
                } else {
                    origin_renaming_map.insert(
                        (pod_id.clone(), SELF_ORIGIN_NAME.to_string()),
                        format!("{}{}", POD_PREFIX, pod_hash),
                    );
                }

                for (_, statement) in &pod.payload.statements_list {
                    // Check all anchored keys in the statement
                    for anchored_key in statement.anchored_keys() {
                        if !anchored_key.0.is_self() {
                            let origin_name = anchored_key.0.origin_name.clone();
                            if !used_origin_names.insert(origin_name.clone()) {
                                // Name clash - fallback to incremental ID
                                while used_origin_names.contains(&format!("origin_{}", next_id)) {
                                    next_id += 1;
                                }
                                let fallback_name = format!("origin_{}", next_id);
                                origin_renaming_map
                                    .insert((pod_id.clone(), origin_name), fallback_name.clone());
                                used_origin_names.insert(fallback_name);
                                next_id += 1;
                            } else {
                                // Can keep the original name
                                origin_renaming_map
                                    .insert((pod_id.clone(), origin_name.clone()), origin_name);
                            }
                        }
                    }
                }
            }

            let mut copy_statements = Vec::new();
            for matched_statement in &self.matched_statements {
                let op = Op::CopyStatement(matched_statement.into());
                let origin_str: String = matched_statement.0.clone().into();
                let statement_id = format!(
                    "from_{}_{}",
                    origin_str,
                    matched_statement.1.split(':').last().unwrap().to_string()
                );
                copy_statements.push((op, statement_id))
            }
            for (op, statement_id) in copy_statements {
                self.add_operation(op, statement_id);
            }

            let gpg_input = GPGInput::new(self.input_pods.clone(), origin_renaming_map);
            let pending_ops: &[OpCmd] = &self
                .pending_operations
                .iter()
                .map(|(_, ops)| ops.clone())
                .collect::<Vec<OpCmd>>()[..];
            POD::execute_oracle_gadget(&gpg_input, pending_ops)
        }
    }
}

impl Env {
    pub fn new(
        user: User,
        shared: Arc<dyn SharedStore>,
        pod_store: Arc<Mutex<MyPods>>,
        sk: Option<SchnorrSecretKey>,
        script_id: Option<ScriptId>,
    ) -> Self {
        Self {
            user,
            shared,
            pod_store,
            current_builder: None,
            current_query: None,
            bindings: Arc::new(Mutex::new(HashMap::new())),
            sk,
            script_id,
        }
    }

    pub fn extend(&self) -> Self {
        // TODO: scoping
        Self {
            user: self.user.clone(),
            shared: self.shared.clone(),
            pod_store: self.pod_store.clone(),
            current_builder: self.current_builder.clone(),
            current_query: self.current_query.clone(),
            bindings: Arc::new(Mutex::new(self.bindings.lock().unwrap().clone())),
            sk: self.sk.clone(),
            script_id: self.script_id.clone(),
        }
    }

    pub async fn get_remote(&self, id: u64) -> Option<Value> {
        self.shared
            .get_value(self.script_id.as_ref().unwrap(), id)
            .await
    }

    pub fn set_remote(&self, id: u64, value: Value) {
        self.shared
            .set_value(self.script_id.as_ref().unwrap(), id, value);
    }
    pub fn get_binding(&self, name: &str) -> Option<Value> {
        self.bindings.lock().unwrap().get(name).cloned()
    }

    pub fn set_binding(&self, name: String, value: Value) {
        self.bindings.lock().unwrap().insert(name, value);
    }
}

type Id = u64;

struct Token {
    val: String,
    pos: Id,
}

fn scan(source: &str) -> Vec<Token> {
    source
        .replace("[", " [ ")
        .replace("]", " ] ")
        .split_whitespace()
        .enumerate()
        .map(|(pos, val)| Token {
            pos: pos as u64,
            val: val.to_string(),
        })
        .collect()
}

fn parse(tokens: &mut Vec<Token>) -> Result<Expr> {
    if tokens[0].val != "[" {
        return Err(anyhow!("must start with ["));
    }
    let token = tokens.remove(0);
    let mut list: Vec<Expr> = Vec::new();
    while !tokens.is_empty() {
        match tokens[0].val.as_str() {
            "]" => {
                tokens.remove(0);
                break;
            }
            "[" => {
                list.push(parse(tokens)?);
            }
            _ => {
                let token = tokens.remove(0);
                list.push(Expr::Atom(token.pos, token.val));
            }
        }
    }
    Ok(Expr::List(token.pos, list))
}

pub async fn eval(source: &str, env: Env) -> Result<Value> {
    let env = Env {
        script_id: Some(ScriptId::from_script(source)),
        ..env
    };
    parse(&mut scan(source))?.eval(env).await
}

#[derive(Debug, PartialEq)]
enum Expr {
    Atom(Id, String),
    List(Id, Vec<Expr>),
}

impl Expr {
    #[async_recursion]
    async fn eval(&self, env: Env) -> Result<Value> {
        match self {
            Expr::List(_, exprs) => {
                if exprs.is_empty() {
                    return Err(anyhow!("Empty expression"));
                }
                match &exprs[0] {
                    Expr::Atom(aid, op) => {
                        // Handle asserts which can be tracked inside PODs
                        if let Ok(assert_type) = AssertType::from_str(op) {
                            return self.eval_assert(assert_type, &exprs[1..], env).await;
                        }
                        // Handle operation which can be tracked inside PODs
                        else if let Ok(op_type) = OpType::from_str(op) {
                            return self.eval_operation(op_type, &exprs[1..], env).await;
                        } else {
                            match op.as_str() {
                                "from" => {
                                    let user_name = if let Expr::Atom(_, op) = &exprs[1] {
                                        Some(op)
                                    } else {
                                        None
                                    };
                                    if let Some(user) = user_name {
                                        if user == &env.user {
                                            let res = exprs[2].eval(env.clone()).await?;
                                            env.set_remote(*aid, res.clone());
                                            Ok(res)
                                        } else {
                                            let remote_value =
                                                env.get_remote(*aid).await.ok_or_else(|| {
                                                    anyhow!("couldn't find on the remote")
                                                })?;

                                            match &remote_value {
                                                // Value::PodRef(pod_id) => {
                                                //     if let Some(pod) =
                                                //         env.shared.get_pod(pod_id).await
                                                //     {
                                                //         env.pod_store.lock().unwrap().add_pod(pod);
                                                //     }
                                                // }
                                                Value::SRef(sref) => {
                                                    if let ORef::P(pod_id) = &sref.0 {
                                                        if let Some(pod) =
                                                            env.shared.get_pod(pod_id).await
                                                        {
                                                            env.pod_store
                                                                .lock()
                                                                .unwrap()
                                                                .add_pod(pod.clone());
                                                            if let Some(ref builder) =
                                                                env.current_builder
                                                            {
                                                                builder
                                                                    .lock()
                                                                    .unwrap()
                                                                    .register_input_pod(&pod);
                                                            }
                                                        }
                                                    }
                                                }
                                                Value::List(values) => {
                                                    // Handle lists of SRefs from pod queries
                                                    for value in values {
                                                        if let Value::SRef(sref) = value {
                                                            if let ORef::P(pod_id) = &sref.0 {
                                                                if let Some(pod) =
                                                                    env.shared.get_pod(pod_id).await
                                                                {
                                                                    env.pod_store
                                                                        .lock()
                                                                        .unwrap()
                                                                        .add_pod(pod.clone());
                                                                    if let Some(ref builder) =
                                                                        env.current_builder
                                                                    {
                                                                        builder
                                                                            .lock()
                                                                            .unwrap()
                                                                            .register_input_pod(
                                                                                &pod,
                                                                            );
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                            Ok(remote_value)
                                        }
                                    } else {
                                        return Err(anyhow!(
                                            "first argument to 'from' must be a user"
                                        ));
                                    }
                                }
                                "createpod" => {
                                    if exprs.len() < 2 {
                                        return Err(anyhow!("createpod requires a body"));
                                    }
                                    self.eval_create_pod(&exprs[1..], env).await
                                }
                                "pod?" => {
                                    if exprs.len() < 2 {
                                        return Err(anyhow!("pod? requires at least one argument"));
                                    }
                                    self.eval_pod_query(&exprs[1..], env).await
                                }
                                "define" => {
                                    if exprs.len() != 3 {
                                        return Err(anyhow!(
                                            "define requires exactly two arguments"
                                        ));
                                    }

                                    let value = exprs[2].eval(env.clone()).await?;

                                    match &exprs[1] {
                                        // Single binding
                                        Expr::Atom(_, name) => {
                                            env.set_binding(name.clone(), value.clone());
                                            Ok(value)
                                        }

                                        // List destructuring
                                        Expr::List(_, names) => {
                                            if let Value::List(values) = value {
                                                if names.len() != values.len() {
                                                    return Err(anyhow!(
                                                        "Destructuring pattern length mismatch"
                                                    ));
                                                }

                                                for (name_expr, value) in
                                                    names.iter().zip(values.iter())
                                                {
                                                    if let Expr::Atom(_, name) = name_expr {
                                                        env.set_binding(
                                                            name.clone(),
                                                            value.clone(),
                                                        );
                                                    } else {
                                                        return Err(anyhow!(
                                                            "Invalid destructuring pattern"
                                                        ));
                                                    }
                                                }
                                                Ok(Value::List(values))
                                            } else {
                                                Err(anyhow!("Cannot destructure non-list value"))
                                            }
                                        }
                                    }
                                }
                                "list" => {
                                    let mut values = Vec::new();
                                    for expr in &exprs[1..] {
                                        values.push(expr.eval(env.clone()).await?);
                                    }
                                    Ok(Value::List(values))
                                }
                                "car" => {
                                    if exprs.len() != 2 {
                                        return Err(anyhow!("car requires exactly one argument"));
                                    }
                                    match exprs[1].eval(env).await? {
                                        Value::List(values) => values
                                            .first()
                                            .cloned()
                                            .ok_or_else(|| anyhow!("Empty list")),
                                        _ => Err(anyhow!("car requires a list argument")),
                                    }
                                }
                                "cdr" => {
                                    if exprs.len() != 2 {
                                        return Err(anyhow!("cdr requires exactly one argument"));
                                    }
                                    match exprs[1].eval(env).await? {
                                        Value::List(values) => {
                                            if values.is_empty() {
                                                Err(anyhow!("Empty list"))
                                            } else {
                                                Ok(Value::List(values[1..].to_vec()))
                                            }
                                        }
                                        _ => Err(anyhow!("cdr requires a list argument")),
                                    }
                                }
                                "cons" => {
                                    if exprs.len() != 3 {
                                        return Err(anyhow!("cons requires exactly two arguments"));
                                    }
                                    let head = exprs[1].eval(env.clone()).await?;
                                    match exprs[2].eval(env).await? {
                                        Value::List(mut values) => {
                                            values.insert(0, head);
                                            Ok(Value::List(values))
                                        }
                                        _ => {
                                            Err(anyhow!("cons requires a list as second argument"))
                                        }
                                    }
                                }
                                op => Err(anyhow!("Unknown operation: {}", op)),
                            }
                        }
                    }
                    _ => Err(anyhow!("First item must be an atom")),
                }
            }
            Expr::Atom(_, a) => {
                // First try to resolve as binding
                if let Some(value) = env.get_binding(a) {
                    Ok(value)
                } else if let Ok(num) = a.parse::<u64>() {
                    // Existing number parsing
                    Ok(Value::Scalar(GoldilocksField(num)))
                } else if env.current_query.is_some() {
                    // Create an SRef to current pod being created
                    Ok(Value::SRef(SRef(
                        ORef::Q(
                            env.current_query
                                .as_ref()
                                .unwrap()
                                .lock()
                                .unwrap()
                                .current_origin_id,
                        ),
                        format!("{}:{}", PREDICATE_VALUEOF, a),
                    )))
                } else {
                    Err(anyhow!("Unknown identifier: {}", a))
                }
            }
        }
    }
    async fn eval_create_pod(&self, body: &[Expr], env: Env) -> Result<Value> {
        let mut pod_env = env.extend();
        let builder = Arc::new(Mutex::new(PodBuilder::new()));
        pod_env.current_builder = Some(builder.clone());

        let pod_name = if let Expr::Atom(_, op) = &body[0] {
            Some(op)
        } else {
            None
        };
        info!("creating pod {}", pod_name.expect("No pod name"));
        // First process defines
        let mut i = 1;
        while i < body.len() {
            match &body[i] {
                Expr::List(_, exprs) => {
                    if let Some(Expr::Atom(_, op)) = exprs.first() {
                        if op == "define" {
                            body[i].eval(pod_env.clone()).await?;
                            i += 1;
                            continue;
                        }
                    }
                    break;
                }
                _ => break,
            }
        }

        // Then process key-value pairs until we hit an assertion or end
        let mut j = i;
        while j < body.len() {
            match &body[j] {
                Expr::List(_, exprs) => {
                    if let Some(Expr::Atom(_, op)) = exprs.first() {
                        if matches!(op.as_str(), "<" | ">" | "=" | "!=") {
                            break;
                        }
                    }
                }
                _ => {}
            }
            j += 1;
        }

        let key_value_pairs = &body[i..j];
        if key_value_pairs.len() % 2 != 0 {
            return Err(anyhow!("Odd number of key-value expressions"));
        }

        for chunk in key_value_pairs.chunks(2) {
            let (key_expr, value_expr) = (&chunk[0], &chunk[1]);
            match key_expr {
                Expr::Atom(_, key) => {
                    let value = value_expr.eval(pod_env.clone()).await?;
                    match value {
                        Value::Scalar(s) => {
                            let entry = Entry {
                                key: key.clone(),
                                value: ScalarOrVec::Scalar(s),
                            };

                            let mut builder_guard = builder.lock().unwrap();
                            builder_guard.add_operation(Op::NewEntry(entry), key.clone());
                            // add a binding to that SRef
                            pod_env.set_binding(
                                key.clone(),
                                Value::SRef(SRef::self_ref(format!(
                                    "{}:{}",
                                    PREDICATE_VALUEOF, key
                                ))),
                            );
                        }
                        Value::SRef(sref) => match sref {
                            SRef(ORef::S, statement) => {
                                // In case we are pointing to a statement on _SELF, we'll go in our list of pending operation and rename the entry to the entry the user wants to create with createpod
                                // Eg: [createpod x [+ 1 [pod? z]]] will have a randomly named entry for the result of 1 + pod.z (where pod is the result of the query)
                                // We will rename that entry to the key (`key` in our case)
                                let statement_id =
                                    statement.split(':').collect::<Vec<&str>>()[1].to_string();
                                let mut builder_guard = builder.lock().unwrap();
                                if let Some((index, (_, operation))) = builder_guard
                                    .pending_operations
                                    .iter()
                                    .enumerate()
                                    .find(|(_, (s, _))| s == &statement_id)
                                {
                                    if let Op::NewEntry(entry) = &operation.0 {
                                        let new_entry = Entry {
                                            key: key.clone(),
                                            value: entry.value.clone(),
                                        };
                                        let op_cmd =
                                            OpCmd(Op::NewEntry(new_entry), statement_id.clone());
                                        builder_guard.pending_operations[index] =
                                            (statement_id.clone(), op_cmd);

                                        pod_env.set_binding(
                                            key.clone(),
                                            Value::SRef(SRef::self_ref(format!(
                                                "{}:{}",
                                                PREDICATE_VALUEOF, statement_id
                                            ))),
                                        );
                                    } else {
                                        return Err(anyhow!(format!(
                                                "Found statement id {} that is not a NewEntry while creating a POD entry",
                                                statement_id
                                            )));
                                    }
                                } else {
                                    return Err(anyhow!(format!("No statement found with statement id {} while creating a POD entry", statement_id)));
                                }
                            }
                            SRef(ORef::P(pod_id), statement) => {
                                // The user wants to create a new entry that is equal to an entry in another pod
                                // Eg: [createpod x [pod? z]]
                                // We will read the value from that POD's entry, copy it in our new POD, and queue an EqualityFromEntries operation
                                // Given we don't copy entries from previous PODs unless explicitly instructed with 'keep' (TODO: this doesn't exit yet)
                                let mut builder_guard = builder.lock().unwrap();

                                if let Some(source_pod) = builder_guard.input_pods.get(&pod_id) {
                                    if let Some(statement_value) =
                                        source_pod.payload.statements_map.get(&statement)
                                    {
                                        if let Ok(value_of) = statement_value.value() {
                                            let new_entry = Entry {
                                                key: key.clone(),
                                                value: value_of,
                                            };

                                            let new_entry_statement_id =
                                                builder_guard.next_statement_id();
                                            builder_guard.add_operation(
                                                Op::NewEntry(new_entry),
                                                new_entry_statement_id.clone(),
                                            );

                                            let eq_from_entries_statement_id =
                                                builder_guard.next_statement_id();
                                            builder_guard.add_operation(
                                                Op::EqualityFromEntries(
                                                    SRef(
                                                        ORef::P(pod_id.clone()),
                                                        statement.clone(),
                                                    )
                                                    .into(),
                                                    SRef::self_ref(format!(
                                                        "{}:{}",
                                                        PREDICATE_VALUEOF, new_entry_statement_id
                                                    ))
                                                    .into(),
                                                ),
                                                eq_from_entries_statement_id,
                                            );
                                            pod_env.set_binding(
                                                key.clone(),
                                                Value::SRef(SRef::self_ref(format!(
                                                    "{}:{}",
                                                    PREDICATE_VALUEOF, new_entry_statement_id
                                                ))),
                                            );
                                        } else {
                                            return Err(anyhow!(
                                                "Could not extract value from source statement"
                                            ));
                                        }
                                    } else {
                                        return Err(anyhow!("Statement not found in source pod"));
                                    }
                                } else {
                                    return Err(anyhow!("Source pod not found in input pods"));
                                }
                            }
                            _ => todo!(),
                        },
                        _ => {
                            return Err(anyhow!(
                                "Can't assign a non scalar or non SRef to POD entry"
                            ))
                        }
                    }
                }
                _ => return Err(anyhow!("Expected key-value pair")),
            }
        }
        for assertion in &body[j..] {
            if let Expr::List(_, exprs) = assertion {
                if let Some(Expr::Atom(_, op)) = exprs.first() {
                    if matches!(op.as_str(), ">" | "=" | "!=") {
                        assertion.eval(pod_env.clone()).await?;
                    }
                }
            }
        }
        let pod = builder.lock().unwrap().finalize(&env)?;
        Ok(Value::PodRef(pod))
    }

    async fn eval_pod_query(&self, args: &[Expr], env: Env) -> Result<Value> {
        let query_builder = Arc::new(Mutex::new(PodQueryBuilder::new()));
        let mut query_env = env.clone();
        query_env.current_query = Some(query_builder.clone());

        // First process all defines
        for arg in args {
            if let Expr::List(_, exprs) = arg {
                if let Some(Expr::Atom(_, op)) = exprs.first() {
                    if op == "define" {
                        arg.eval(query_env.clone()).await?;
                        continue;
                    }
                }
            }
        }

        // Then process all other constraints (key-value pairs and assertions)
        for arg in args {
            match arg {
                Expr::List(_, exprs) => {
                    if let Some(Expr::Atom(_, op)) = exprs.first() {
                        if op == "define" {
                            continue; // Skip defines as we've already processed them
                        }

                        // Handle assertions
                        if matches!(op.as_str(), ">" | "=" | "!=") {
                            if exprs.len() != 3 {
                                return Err(anyhow!("Assert requires exactly two operands"));
                            }
                            let assert_type = AssertType::from_str(op)?;
                            let op1 = exprs[1].eval(query_env.clone()).await?;
                            let op2 = exprs[2].eval(query_env.clone()).await?;
                            let assert = (assert_type, op1, op2).into();
                            query_builder.lock().unwrap().add_assert(&assert)?;
                            continue;
                        }
                    }

                    // Handle key-value constraints
                    let key = match &exprs[0] {
                        Expr::Atom(_, k) => k.clone(),
                        _ => return Err(anyhow!("Key must be an atom")),
                    };

                    let current_origin_id = {
                        let builder = query_builder.lock().unwrap();
                        builder.current_origin_id
                    };

                    let statement_id = format!("{}:{}", PREDICATE_VALUEOF, key.clone());

                    {
                        let mut builder = query_builder.lock().unwrap();
                        builder
                            .srefs
                            .push(SRef(ORef::Q(current_origin_id), statement_id.clone()));
                        builder.add_key_constraint(key.clone());
                        query_env.set_binding(
                            key.clone(),
                            Value::SRef(SRef(ORef::Q(current_origin_id), statement_id)),
                        );
                    }

                    if exprs.len() > 1 {
                        let pattern = exprs[1].eval(query_env.clone()).await?;
                        let mut builder = query_builder.lock().unwrap();
                        let constraint = builder.add_value(&pattern)?;
                        builder.add_constraint(key, constraint);
                    } else {
                        let mut builder = query_builder.lock().unwrap();
                        builder
                            .add_constraint(key.clone(), OperandConstraint::EntryRef(key.clone()));
                    }
                }
                _ => return Err(anyhow!("Invalid query syntax")),
            }
        }

        let query = {
            let builder = query_builder.lock().unwrap();
            builder.clone()
        };

        find_matching_pod(query, env)
    }

    async fn eval_operation(&self, op_type: OpType, operands: &[Expr], env: Env) -> Result<Value> {
        if operands.len() != 2 {
            return Err(anyhow!("Operations require exactly two operands"));
        }
        let op1 = operands[0].eval(env.clone()).await?;
        let op2 = operands[1].eval(env.clone()).await?;

        let operation: Operation = (op_type, op1.clone(), op2.clone()).into();
        if let Some(ref _query) = env.current_query {
            match (&op1, &op2) {
                (Value::Scalar(s1), Value::Scalar(s2)) => {
                    Ok(Value::Scalar(operation.apply_operation(*s1, *s2)))
                }
                _ => Ok(Value::Operation(Box::new(operation))),
            }
        } else if let Some(ref builder) = env.current_builder {
            let result_value = operation.eval_with_env(&env)?;
            let mut builder = builder.lock().unwrap();

            // Create refs for any values that need tracking
            match (&op1, &op2) {
                (Value::SRef(_), _) | (_, Value::SRef(_)) => {
                    // Convert operands to SRefs if they're scalars
                    let op1_sref = match op1 {
                        Value::Scalar(s) => builder.get_or_create_constant_ref(s),
                        Value::SRef(r) => r,
                        _ => return Err(anyhow!("Invalid operand type")),
                    };

                    let op2_sref = match op2 {
                        Value::Scalar(s) => builder.get_or_create_constant_ref(s),
                        Value::SRef(r) => r,
                        _ => return Err(anyhow!("Invalid operand type")),
                    };

                    // We need to create a new entry for the result
                    let result_key = builder.next_result_key_id();
                    let new_entry_statement_id = builder.next_statement_id();
                    let result_sref =
                        SRef::self_ref(format!("{}:{}", PREDICATE_VALUEOF, new_entry_statement_id));
                    let pod_op =
                        Operation::into_pod_op(op_type, result_sref.clone(), op1_sref, op2_sref);
                    // Create the result entry. We use our result_key which was also used in creating the operation.
                    builder.add_operation(
                        Op::NewEntry(Entry {
                            key: result_key.clone(),
                            value: ScalarOrVec::Scalar(result_value),
                        }),
                        new_entry_statement_id,
                    );

                    // Then add the operation
                    let op_statement_id = builder.next_statement_id();
                    builder.add_operation(pod_op, op_statement_id);

                    Ok(Value::SRef(result_sref))
                }
                _ => Ok(Value::Scalar(result_value)),
            }
        } else {
            // Direct evaluation
            // TODO: In the future we might want to evaluate with env in case we allow computation on statement ref outside of create pod
            // We would also need to make get_value_from_sref work outside a builder context, by fetching the refs in the store directly
            // as an example if createpod returns a list of statementref (like pod?) that enables to then do further computation on it
            Ok(Value::Scalar(operation.eval()?))
        }
    }
    async fn eval_assert(
        &self,
        assert_type: AssertType,
        operands: &[Expr],
        env: Env,
    ) -> Result<Value> {
        if operands.len() != 2 {
            return Err(anyhow!("Asserts require exactly two operands"));
        }
        let op1 = operands[0].eval(env.clone()).await?;
        let op2 = operands[1].eval(env.clone()).await?;

        let assert: Assert = (assert_type, op1.clone(), op2.clone()).into();
        if let Some(ref _query) = env.current_query {
            match (&op1, &op2) {
                (Value::Scalar(s1), Value::Scalar(s2)) => {
                    Ok(Value::Scalar(assert.apply_assert(*s1, *s2)))
                }
                _ => Ok(Value::Assert(Box::new(assert))),
            }
        } else if let Some(ref builder) = env.current_builder {
            let mut builder = builder.lock().unwrap();

            // Create refs for any values that need tracking
            match (&op1, &op2) {
                (Value::SRef(_), _) | (_, Value::SRef(_)) => {
                    // Convert operands to SRefs if they're scalars
                    let op1_sref = match op1 {
                        Value::Scalar(s) => builder.get_or_create_constant_ref(s),
                        Value::SRef(r) => r,
                        _ => return Err(anyhow!("Invalid operand type")),
                    };

                    let op2_sref = match op2 {
                        Value::Scalar(s) => builder.get_or_create_constant_ref(s),
                        Value::SRef(r) => r,
                        _ => return Err(anyhow!("Invalid operand type")),
                    };

                    // We need to create a new entry for the result
                    let pod_op = Assert::into_pod_op(assert_type, op1_sref, op2_sref);
                    let op_statement_id = builder.next_statement_id();
                    builder.add_operation(pod_op, op_statement_id.clone());
                    let assert_sref = SRef::self_ref(format!(
                        "{}:{}",
                        Assert::predicate_from_op(assert_type),
                        op_statement_id.clone()
                    ));

                    Ok(Value::SRef(assert_sref))
                }
                _ => Ok(Value::Scalar(assert.eval()?)),
            }
        } else {
            // Direct evaluation
            Ok(Value::Scalar(assert.eval()?))
        }
    }
}

fn get_value_from_sref(sref: &SRef, env: &Env) -> Result<GoldilocksField> {
    if let Some(ref builder) = env.current_builder {
        let builder = builder.lock().unwrap();
        if sref.0.eq(&ORef::S) {
            if let Some((_, op_cmd)) =
                builder.pending_operations.iter().find(|(statement_id, _)| {
                    statement_id == &sref.1.split(':').collect::<Vec<&str>>()[1].to_string()
                })
            {
                if let Op::NewEntry(entry) = &op_cmd.0 {
                    if let ScalarOrVec::Scalar(value) = entry.value {
                        return Ok(value);
                    }
                }
            }
            return Err(anyhow!("Value not found in current pod operations"));
        }
        // Look up value in input pods using origin mapping
        let key: String = sref.0.clone().into();
        if let Some(pod) = builder.input_pods.get(&key) {
            if let Some(Statement::ValueOf(_, ScalarOrVec::Scalar(value))) =
                pod.payload.statements_map.get(&sref.1)
            {
                Ok(*value)
            } else {
                Err(anyhow!("Value not found or not scalar"))
            }
        } else {
            Err(anyhow!("Pod not found for ref"))
        }
    } else {
        // We might want to support finding the refs inside the POD store
        Err(anyhow!("No active pod builder"))
    }
}

fn find_matching_pod(query: PodQueryBuilder, env: Env) -> Result<Value> {
    let constraints = query.build_constraints();
    let store = env.pod_store.lock().unwrap();
    for pod in store.pods.iter() {
        let pod_id = PodBuilder::pod_id(pod);

        if let Some(ref builder) = env.current_builder {
            if builder.lock().unwrap().input_pods.contains_key(&pod_id) {
                continue;
            }
        }
        if let Some(matched_statements) = matches_constraints(pod, &constraints) {
            if let Some(ref builder) = env.current_builder {
                builder.lock().unwrap().register_input_pod(pod);
            }
            if let Some(ref builder) = env.current_builder {
                builder
                    .lock()
                    .unwrap()
                    .extend_matched_statements(matched_statements);
            }
            env.shared.store_pod(pod.clone());

            let refs: Vec<Value> = query
                .srefs
                .iter()
                .map(|sref| {
                    // Find the actual statement ID in the pod for this key
                    let key = sref.1.split(':').last().unwrap();
                    let statement_id = pod
                        .payload
                        .statements_list
                        .iter()
                        .find(|(_, stmt)| {
                            if let Statement::ValueOf(ak, _) = stmt {
                                ak.1 == key
                            } else {
                                false
                            }
                        })
                        .map(|(id, _)| id.clone())
                        .ok_or_else(|| anyhow!("Statement not found in pod for key {}", key))?;

                    Ok(Value::SRef(SRef(ORef::P(pod_id.clone()), statement_id)))
                })
                .collect::<Result<Vec<Value>>>()?;

            return if refs.len() == 1 {
                Ok(refs.into_iter().next().unwrap())
            } else {
                Ok(Value::List(refs))
            };
        }
    }

    Err(anyhow!("No matching pod found"))
}

fn matches_constraints(pod: &POD, constraints: &[QueryConstraint]) -> Option<Vec<SRef>> {
    // We collect statements that are implictly copied here
    // For now this includes constants matched in operations & asserts; and the operation and asserts statement themselves
    // We do not copy constraints on HashKey and ExactValue given are returned out of the pod? and it's on the user to decided what to do with them (compute new stuff, keep them using the `keep` keyword, etc)
    let mut matched_statements = Vec::new();
    for constraint in constraints {
        match constraint {
            QueryConstraint::HasKey { key } => {
                if !pod.payload.statements_list.iter().any(|(_, stmt)| {
                    if let Statement::ValueOf(ak, _) = stmt {
                        &ak.1 == key
                    } else {
                        false
                    }
                }) {
                    return None;
                }
            }
            QueryConstraint::ExactValue { key, value } => {
                if !pod.payload.statements_list.iter().any(|(_, stmt)| {
                    if let Statement::ValueOf(ak, v) = stmt {
                        &ak.1 == key && v == value
                    } else {
                        false
                    }
                }) {
                    return None;
                }
            }
            QueryConstraint::Operation {
                result_key,
                operation,
            } => {
                // Find statements that match the operation
                let matching_ops = pod
                    .payload
                    .statements_list
                    .iter()
                    .filter_map(|(id, stmt)| {
                        matches_operation_constraint(pod, operation, stmt, &mut matched_statements)
                            .map(|result_ak| (id.clone(), result_ak))
                    })
                    .collect::<Vec<_>>();

                // Verify that one of the matching operations has its result
                // stored under result_key
                if !matching_ops
                    .iter()
                    .any(|(_, result_ak)| &result_ak.1 == result_key)
                {
                    return None;
                }

                // Add the operation statement itself
                if let Some((stmt_id, _)) = matching_ops.first() {
                    matched_statements
                        .push(SRef(ORef::P(PodBuilder::pod_id(pod)), stmt_id.clone()));
                }
            }
            QueryConstraint::Assert {
                assert_type,
                operands,
            } => {
                // Find statements that match the assertion
                let matching_asserts = pod
                    .payload
                    .statements_list
                    .iter()
                    .filter_map(|(id, stmt)| {
                        matches_assert_constraint(
                            pod,
                            *assert_type,
                            operands,
                            stmt,
                            &mut matched_statements,
                        )
                        .map(|_| id.clone())
                    })
                    .collect::<Vec<_>>();

                if matching_asserts.is_empty() {
                    return None;
                }

                // Add the assert statement itself
                if let Some(stmt_id) = matching_asserts.first() {
                    matched_statements
                        .push(SRef(ORef::P(PodBuilder::pod_id(pod)), stmt_id.clone()));
                }
            }
        }
    }
    Some(matched_statements)
}

fn matches_assert_constraint(
    pod: &POD,
    assert_type: AssertType,
    operands: &(Box<OperandConstraint>, Box<OperandConstraint>),
    statement: &Statement,
    matched_statements: &mut Vec<SRef>,
) -> Option<bool> {
    let (op1, op2) = match (assert_type, statement) {
        (AssertType::Gt, Statement::Gt(l, r))
        | (AssertType::Lt, Statement::Lt(l, r))
        | (AssertType::Eq, Statement::Equal(l, r))
        | (AssertType::Neq, Statement::NotEqual(l, r)) => (l, r),
        _ => return None,
    };

    let (op1_constraint, op2_constraint) = operands;

    if let Some(left_res) = matches_operand_constraint(pod, op1_constraint, op1, matched_statements)
    {
        if let Some(right_res) =
            matches_operand_constraint(pod, op2_constraint, op2, matched_statements)
        {
            if op1 == &left_res && op2 == &right_res {
                return Some(true);
            }
        }
    }

    None
}

fn matches_operation_constraint(
    pod: &POD,
    op_constraint: &OperationConstraint,
    statement: &Statement,
    matched_statements: &mut Vec<SRef>,
) -> Option<AnchoredKey> {
    let (result, left, right) = match (op_constraint.op_type, statement) {
        (OpType::Add, Statement::SumOf(res, l, r))
        | (OpType::Multiply, Statement::ProductOf(res, l, r))
        | (OpType::Max, Statement::MaxOf(res, l, r)) => (res, l, r),
        _ => return None,
    };

    let (op1, op2) = &op_constraint.operands;

    if let Some(left_res) = matches_operand_constraint(pod, op1, left, matched_statements) {
        if let Some(right_res) = matches_operand_constraint(pod, op2, right, matched_statements) {
            if left == &left_res && right == &right_res {
                return Some(result.clone());
            }
        }
    }

    // Try reverse order for commutative operations
    if let Some(left_res) = matches_operand_constraint(pod, op2, left, matched_statements) {
        if let Some(right_res) = matches_operand_constraint(pod, op1, right, matched_statements) {
            if left == &left_res && right == &right_res {
                return Some(result.clone());
            }
        }
    }

    None
}

fn matches_operand_constraint(
    pod: &POD,
    constraint: &OperandConstraint,
    operand: &AnchoredKey,
    matched_statements: &mut Vec<SRef>,
) -> Option<AnchoredKey> {
    match constraint {
        OperandConstraint::EntryRef(key) => {
            if &operand.1 == key {
                Some(operand.clone())
            } else {
                None
            }
        }
        OperandConstraint::Constant(value) => {
            pod.payload.statements_list.iter().find_map(|(id, stmt)| {
                if let Statement::ValueOf(ak, val) = stmt {
                    if ak == operand && val == value {
                        matched_statements.push(SRef(ORef::P(PodBuilder::pod_id(pod)), id.clone()));
                        Some(ak.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
        }
        OperandConstraint::Operation(op) => {
            for (id, stmt) in &pod.payload.statements_list {
                match stmt {
                    Statement::SumOf(res, _, _)
                    | Statement::ProductOf(res, _, _)
                    | Statement::MaxOf(res, _, _) => {
                        if operand == res {
                            if let Some(matched_res) =
                                matches_operation_constraint(pod, op, stmt, matched_statements)
                            {
                                matched_statements
                                    .push(SRef(ORef::P(PodBuilder::pod_id(pod)), id.clone()));
                                return Some(matched_res);
                            }
                        }
                    }
                    _ => continue,
                }
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pod2::pod::statement::AnchoredKey;
    pub fn get_self_entry_value(pod: &POD, key: &str) -> Option<ScalarOrVec> {
        pod.payload
            .statements_list
            .iter()
            .find(|(_, s)| {
                if let Statement::ValueOf(AnchoredKey(origin, k), _) = s {
                    k == key && origin.origin_name == "_SELF"
                } else {
                    false
                }
            })
            .and_then(|(_, s)| s.value().ok())
    }
    async fn setup_env() -> (Env, Arc<Mutex<MyPods>>) {
        let shared = Arc::new(InMemoryStore::new());
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new(
            "test_user".to_string(),
            shared,
            pod_store.clone(),
            Some(SchnorrSecretKey { sk: 42 }),
            None,
        );
        (env, pod_store)
    }
    #[test]
    fn test_parse() {
        assert_eq!(
            parse(&mut scan("[+ [+ 20 20] [+ 1 [1]]]")).unwrap(),
            Expr::List(
                0,
                vec![
                    Expr::Atom(1, String::from("+")),
                    Expr::List(
                        2,
                        vec![
                            Expr::Atom(3, String::from("+")),
                            Expr::Atom(4, String::from("20")),
                            Expr::Atom(5, String::from("20")),
                        ]
                    ),
                    Expr::List(
                        7,
                        vec![
                            Expr::Atom(8, String::from("+")),
                            Expr::Atom(9, String::from("1")),
                            Expr::List(10, vec![Expr::Atom(11, String::from("1")),]),
                        ]
                    )
                ]
            )
        )
    }
    #[tokio::test]
    async fn test_create_pod_simple() -> Result<()> {
        let (env, _) = setup_env().await;

        let result = eval("[createpod test_pod x [+ 40 2] y 123]", env).await?;

        match result {
            Value::PodRef(pod) => {
                assert_eq!(
                    get_self_entry_value(&pod, "x").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(42))
                );
                assert_eq!(
                    get_self_entry_value(&pod, "y").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(123))
                );
                Ok(())
            }
            _ => Err(anyhow!("Expected PodRef, got something else")),
        }
    }

    #[tokio::test]
    async fn test_create_pod_with_pod_basic() -> Result<()> {
        let (env, pod_store) = setup_env().await;
        let first_pod_eval = eval("[createpod test_pod x [+ 40 2] y 12", env.clone()).await?;
        let first_pod = match first_pod_eval {
            Value::PodRef(pod) => pod,
            _ => panic!("Expected PodRef"),
        };
        pod_store.lock().unwrap().add_pod(first_pod);

        let second_pod_eval = eval("[createpod test_pod_2 z 1616]", env.clone()).await?;
        let second_pod = match second_pod_eval {
            Value::PodRef(pod) => pod,
            _ => panic!("Expected PodRef"),
        };
        pod_store.lock().unwrap().add_pod(second_pod);

        let result = eval(
            "[createpod final x [+ 40 2] y [+ [pod? [x]] 66] z_prime [+ [pod? [z]] 66]]",
            env.clone(),
        )
        .await?;

        match result {
            Value::PodRef(pod) => {
                assert_eq!(
                    get_self_entry_value(&pod, "x").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(42))
                );
                assert_eq!(
                    get_self_entry_value(&pod, "y").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(108))
                );
                Ok(())
            }
            _ => Err(anyhow!("Expected PodRef, got something else")),
        }
    }
    #[tokio::test]
    async fn test_nested_pod() -> Result<()> {
        let (env, pod_store) = setup_env().await;
        let first_pod_eval = eval("[createpod test_pod x 10]", env.clone()).await?;
        let first_pod = match first_pod_eval {
            Value::PodRef(pod) => pod,
            _ => panic!("Expected PodRef"),
        };
        pod_store.lock().unwrap().add_pod(first_pod);

        let second_pod_eval =
            eval("[createpod test_pod_2 z [+ [pod? [x]] 10]]", env.clone()).await?;
        let second_pod = match second_pod_eval {
            Value::PodRef(pod) => pod,
            _ => panic!("Expected PodRef"),
        };
        pod_store.lock().unwrap().add_pod(second_pod);

        let result = eval("[createpod final final-key [+ 10 [pod? [z]]]]", env.clone()).await?;

        match result {
            Value::PodRef(pod) => {
                assert_eq!(
                    get_self_entry_value(&pod, "final-key").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(30))
                );
                Ok(())
            }
            _ => Err(anyhow!("Expected PodRef, got something else")),
        }
    }
    #[tokio::test]
    async fn test_pod_query_unique_matching() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create two identical pods
        let pod1 = eval("[createpod test_pod1 x 10]", env.clone()).await?;
        let pod2 = eval("[createpod test_pod2 x 12]", env.clone()).await?;

        if let (Value::PodRef(pod1), Value::PodRef(pod2)) = (pod1, pod2) {
            pod_store.lock().unwrap().add_pod(pod1);
            pod_store.lock().unwrap().add_pod(pod2);

            // This should succeed because it uses two different pods
            eval(
                "[createpod final a [+ [pod? [x]] 1] b [+ [pod? [x]] 2]]",
                env.clone(),
            )
            .await?;
            Ok(())
        } else {
            Err(anyhow!("Failed to create test pods"))
        }
    }
    #[tokio::test]
    async fn test_pod_query_fails_on_reuse() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        let pod1 = eval("[createpod test_pod1 x 10]", env.clone()).await?;
        if let Value::PodRef(pod1) = pod1 {
            pod_store.lock().unwrap().add_pod(pod1);

            // This should fail because there's only one pod with x=10,
            // but we're trying to match it twice
            let result = eval(
                "[createpod final a [+ [pod? [x]] 1] b [+ [pod? [x]] 2]]",
                env.clone(),
            )
            .await;

            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("No matching pod found"));
            }
            Ok(())
        } else {
            Err(anyhow!("Failed to create test pod"))
        }
    }
    #[tokio::test]
    async fn test_operation_key_matching() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create a pod with the same operation ([+ x y]) stored under different keys
        let pod = eval(
            "[createpod example
                x 10
                y 20
                sum1 [+ x y]
                sum2 [+ x y]
                other [+ x 5]]",
            env.clone(),
        )
        .await?;

        if let Value::PodRef(pod) = pod {
            pod_store.lock().unwrap().add_pod(pod);

            // Should match when querying with correct key
            let result = eval("[pod? [sum1 [+ x y]]]", env.clone()).await?;
            assert!(matches!(result, Value::SRef(_)));

            // Should match with the other key too
            let result = eval("[pod? [sum2 [+ x y]]]", env.clone()).await?;
            assert!(matches!(result, Value::SRef(_)));

            // Should NOT match when querying with wrong key
            let result = eval("[pod? [wrong_key [+ x y]]]", env.clone()).await;
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("No matching pod found"));

            // Should match specific operation under specific key
            let result = eval("[pod? [other [+ x 5]]]", env.clone()).await?;
            assert!(matches!(result, Value::SRef(_)));

            // Should NOT match wrong operation under correct key
            let result = eval("[pod? [sum1 [+ x 5]]]", env.clone()).await;
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("No matching pod found"));

            Ok(())
        } else {
            Err(anyhow!("Failed to create test pod"))
        }
    }
    #[tokio::test]
    async fn test_pod_query_with_defines() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create a pod with some values
        let pod = eval(
            "[createpod test_pod
                value1 15
                value2 [+ value1 15]]",
            env.clone(),
        )
        .await?;

        if let Value::PodRef(pod) = pod {
            pod_store.lock().unwrap().add_pod(pod);

            // Query using defines
            let result = eval(
                "[pod?
                    [define x [* 5 3]]
                    [define y [+ x 15]]
                    [value1 x]
                    [value2 y]]",
                env.clone(),
            )
            .await?;

            assert!(matches!(result, Value::List(_)));
            Ok(())
        } else {
            Err(anyhow!("Failed to create test pod"))
        }
    }
    #[tokio::test]
    async fn test_pod_query_destructuring() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create a pod with two values
        let pod1 = eval("[createpod test_pod1 x 10 y 20]", env.clone()).await?;
        if let Value::PodRef(pod1) = pod1 {
            pod_store.lock().unwrap().add_pod(pod1);

            // Test destructuring pod query results
            let result = eval(
                "[createpod final
                    [define [a b] [pod? [x] [y]]]
                    sum [+ a b]
                    double-x [* a 2]]",
                env.clone(),
            )
            .await?;

            match result {
                Value::PodRef(pod) => {
                    assert_eq!(
                        get_self_entry_value(&pod, "sum").unwrap(),
                        ScalarOrVec::Scalar(GoldilocksField(30))
                    );
                    assert_eq!(
                        get_self_entry_value(&pod, "double-x").unwrap(),
                        ScalarOrVec::Scalar(GoldilocksField(20))
                    );
                    Ok(())
                }
                _ => Err(anyhow!("Expected PodRef")),
            }
        } else {
            Err(anyhow!("Failed to create test pod"))
        }
    }
    #[tokio::test]
    async fn test_pod_query_single_ref() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create a pod with a single value
        let pod1 = eval("[createpod test_pod1 value1 10]", env.clone()).await?;
        if let Value::PodRef(pod1) = pod1 {
            pod_store.lock().unwrap().add_pod(pod1);

            // Test querying single value returns SRef directly, not in a list
            let result = eval(
                "[createpod final
                    [define x [pod? [value1]]]
                    a [+ x 1]]",
                env.clone(),
            )
            .await?;

            match result {
                Value::PodRef(pod) => {
                    assert_eq!(
                        get_self_entry_value(&pod, "a").unwrap(),
                        ScalarOrVec::Scalar(GoldilocksField(11))
                    );
                    Ok(())
                }
                _ => Err(anyhow!("Expected PodRef")),
            }
        } else {
            Err(anyhow!("Failed to create test pod"))
        }
    }
    #[tokio::test]
    async fn test_simple_scalar_query() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create pod with simple scalar value
        let pod = eval("[createpod test_pod x 10]", env.clone()).await?;
        if let Value::PodRef(pod) = pod {
            pod_store.lock().unwrap().add_pod(pod);
        }

        // Query for exact value match
        let result = eval("[pod? [x 10]]", env.clone()).await?;
        match result {
            Value::SRef(sref) => {
                assert!(sref.1.contains("VALUEOF:x"));
                Ok(())
            }
            _ => Err(anyhow!("Expected SRef")),
        }
    }

    #[tokio::test]
    async fn test_operation_query() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create pod with operation result
        let pod = eval("[createpod test_pod x [+ 10 20]]", env.clone()).await?;
        if let Value::PodRef(pod) = pod {
            pod_store.lock().unwrap().add_pod(pod);
        }

        // Query using same operation
        let result = eval("[pod? [x [+ 10 20]]]", env.clone()).await?;
        assert!(matches!(result, Value::SRef(_)));

        // Query using final value
        let result = eval("[pod? [x 30]]", env.clone()).await?;
        assert!(matches!(result, Value::SRef(_)));

        // Query using a wrong value
        let result = eval("[pod? [x 31]]", env.clone()).await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("No matching pod found"));
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_value_query() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create pod with multiple values
        let pod = eval("[createpod test_pod x 10 y 20]", env.clone()).await?;
        if let Value::PodRef(pod) = pod {
            pod_store.lock().unwrap().add_pod(pod);
        }

        // Query for multiple values
        let result = eval("[pod? [x 10] [y 20]]", env.clone()).await?;
        match result {
            Value::List(values) => {
                assert_eq!(values.len(), 2);
                assert!(matches!(&values[0], Value::SRef(_)));
                assert!(matches!(&values[1], Value::SRef(_)));
                Ok(())
            }
            _ => Err(anyhow!("Expected List")),
        }
    }

    #[tokio::test]
    async fn test_refer_to_other_key_not_revealed_query() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create pod with multiple values
        let pod = eval("[createpod test_pod x 11 y [+ 12 x]]", env.clone()).await?;
        if let Value::PodRef(pod) = pod {
            pod_store.lock().unwrap().add_pod(pod);
        }

        // Query for multiple values
        let result = eval("[pod? [y [+ 12 x]]]", env.clone()).await?;
        assert!(matches!(result, Value::SRef(_)));
        Ok(())
    }

    #[tokio::test]
    async fn test_refer_to_other_keys_query() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create pod with multiple values
        let pod = eval("[createpod test_pod x 11 y [+ 12 x]]", env.clone()).await?;
        if let Value::PodRef(pod) = pod {
            pod_store.lock().unwrap().add_pod(pod);
        }

        // Query for multiple values
        let result = eval("[pod? [x 11] [y [+ 12 x]]]", env.clone()).await?;
        match result {
            Value::List(values) => {
                assert_eq!(values.len(), 2);
                assert!(matches!(&values[0], Value::SRef(_)));
                assert!(matches!(&values[1], Value::SRef(_)));
                Ok(())
            }
            _ => Err(anyhow!("Expected List")),
        }
    }

    #[tokio::test]
    async fn test_nested_operation_query() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create pod with nested operations
        let pod = eval(
            "[createpod test_pod result [+ [* 10 2] [* 3 4]]]",
            env.clone(),
        )
        .await?;
        if let Value::PodRef(pod) = pod {
            pod_store.lock().unwrap().add_pod(pod);
        }

        // Query using same nested operation structure
        let result = eval("[pod? [result [+ [* 10 2] [* 3 4]]]]", env.clone()).await?;
        assert!(matches!(result, Value::SRef(_)));

        // Query using final value
        let result = eval("[pod? [result 32]]", env.clone()).await?;
        assert!(matches!(result, Value::SRef(_)));

        Ok(())
    }

    #[tokio::test]
    async fn test_deeply_nested_operation_query() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create a pod with deeply nested operations
        let pod = eval(
            "[createpod test_pod
                x 10
                y 20
                z 15
                result [+ [* 2 x] [max y z]]]",
            env.clone(),
        )
        .await?;

        if let Value::PodRef(pod) = pod {
            pod_store.lock().unwrap().add_pod(pod);

            // Query matching the exact nested structure
            let result = eval("[pod? [result [+ [* 2 x] [max y z]]]]", env.clone()).await?;
            assert!(matches!(result, Value::SRef(_)));

            // Also try querying with just the final value
            let expected_value = (2 * 10) + 20; // [* 2 x] + max(y, z) = 20 + 20 = 40
            let result = eval(&format!("[pod? [result {}]]", expected_value), env.clone()).await?;

            assert!(matches!(result, Value::SRef(_)));
        }

        Ok(())
    }

    // #[tokio::test]
    // async fn test_recursive_pod_query() -> Result<()> {
    //     let (env, pod_store) = setup_env().await;

    //     // Create two pods with related values
    //     let pod1 = eval("[createpod pod1 value 10]", env.clone()).await?;
    //     if let Value::PodRef(pod1) = pod1 {
    //         pod_store.lock().unwrap().add_pod(pod1);
    //     }

    //     let pod2 = eval("[createpod pod2 result [+ [pod? value] 5]]", env.clone()).await?;
    //     if let Value::PodRef(pod2) = pod2 {
    //         pod_store.lock().unwrap().add_pod(pod2);
    //     }

    //     // Query for pod that references first pod's value
    //     let result = eval("[pod? [result 15]]", env.clone()).await?;
    //     assert!(matches!(result, Value::SRef(_)));

    //     // Query using the same structure
    //     let result = eval("[pod? [result [+ [pod? value] 5]]]", env.clone()).await?;
    //     assert!(matches!(result, Value::SRef(_)));

    //     Ok(())
    // }

    #[tokio::test]
    async fn test_no_match_query() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create pod
        let pod = eval("[createpod test_pod x 10]", env.clone()).await?;
        if let Value::PodRef(pod) = pod {
            pod_store.lock().unwrap().add_pod(pod);
        }

        // Query for non-existent value
        let result = eval("[pod? [x 20]]", env.clone()).await;
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_max_operation_query() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create pod with max operation
        let pod = eval("[createpod test_pod result [max 30 20]]", env.clone()).await?;
        if let Value::PodRef(pod) = pod {
            pod_store.lock().unwrap().add_pod(pod);
        }

        // Query using same operation
        let result = eval("[pod? [result [max 30 20]]]", env.clone()).await?;
        assert!(matches!(result, Value::SRef(_)));

        // Query using final value
        let result = eval("[pod? [result 30]]", env.clone()).await?;
        assert!(matches!(result, Value::SRef(_)));

        Ok(())
    }

    #[tokio::test]
    async fn test_pod_query_operation_matching() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        let pod1 = eval(
            "[createpod test_pod1 value1 10 value2 [+ 10 value1] value3 [* 2 value2]]",
            env.clone(),
        )
        .await?;
        if let Value::PodRef(pod1) = pod1 {
            pod_store.lock().unwrap().add_pod(pod1);

            let result = eval(
                "[createpod final
                    [define x [pod? [value3 [* 2 [+ 10 value1]]]]]
                    a [+ x 1]]",
                env.clone(),
            )
            .await?;

            match result {
                Value::PodRef(pod) => {
                    assert_eq!(
                        get_self_entry_value(&pod, "a").unwrap(),
                        ScalarOrVec::Scalar(GoldilocksField(41))
                    );
                }
                _ => return Err(anyhow!("Expected PodRef")),
            }

            // Both of these queries should work
            let result = eval(
                "[createpod final
                    [define x [pod? [value3 [* 2 value2]]]]
                    a [+ x 1]]",
                env.clone(),
            )
            .await?;

            match result {
                Value::PodRef(pod) => {
                    assert_eq!(
                        get_self_entry_value(&pod, "a").unwrap(),
                        ScalarOrVec::Scalar(GoldilocksField(41))
                    );
                    Ok(())
                }
                _ => Err(anyhow!("Expected PodRef")),
            }
        } else {
            Err(anyhow!("Failed to create test pod"))
        }
    }
    #[tokio::test]
    async fn test_pod_refer_to_previously_created_key() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create a pod with a single value
        let pod1 = eval("[createpod test_pod1 value1 10]", env.clone()).await?;
        if let Value::PodRef(pod1) = pod1 {
            pod_store.lock().unwrap().add_pod(pod1);

            // Test querying single value returns SRef directly, not in a list
            let result = eval(
                "[createpod final
                    [define x [pod? [value1]]]
                    a 10
                    b [+ [* x 10] a]]",
                env.clone(),
            )
            .await?;

            match result {
                Value::PodRef(pod) => {
                    assert_eq!(
                        get_self_entry_value(&pod, "b").unwrap(),
                        ScalarOrVec::Scalar(GoldilocksField(110))
                    );
                    Ok(())
                }
                _ => Err(anyhow!("Expected PodRef")),
            }
        } else {
            Err(anyhow!("Failed to create test pod"))
        }
    }
    #[tokio::test]
    async fn test_pod_operations_with_refs() -> Result<()> {
        let (env, _) = setup_env().await;

        let result = eval(
            "[createpod test
                base 10
                double [* base 2]
                triple [* base 3]
                sum [+ double triple]
                max_val [max double triple]]",
            env,
        )
        .await?;

        match result {
            Value::PodRef(pod) => {
                assert_eq!(
                    get_self_entry_value(&pod, "base").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(10))
                );
                assert_eq!(
                    get_self_entry_value(&pod, "double").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(20))
                );
                assert_eq!(
                    get_self_entry_value(&pod, "triple").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(30))
                );
                assert_eq!(
                    get_self_entry_value(&pod, "sum").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(50))
                );
                assert_eq!(
                    get_self_entry_value(&pod, "max_val").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(30))
                );
                Ok(())
            }
            _ => Err(anyhow!("Expected PodRef")),
        }
    }
    #[tokio::test]
    async fn test_complex_pod_creation_with_defines() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // First create a pod with some values we'll reference
        let source_pod = eval("[createpod source value1 10 value2 20]", env.clone()).await?;
        if let Value::PodRef(source_pod) = source_pod {
            pod_store.lock().unwrap().add_pod(source_pod);

            // Now create a complex pod using defines and references
            let result = eval(
                "[createpod test
                    [define [x y] [pod? [value1] [value2]]]
                    [define z 42]
                    key1 [+ x 10]
                    key2 [max y 100]
                    key3 z]",
                env.clone(),
            )
            .await?;

            match result {
                Value::PodRef(pod) => {
                    // Test that key1 = value1 + 10 = 20
                    assert_eq!(
                        get_self_entry_value(&pod, "key1").unwrap(),
                        ScalarOrVec::Scalar(GoldilocksField(20))
                    );

                    // Test that key2 = max(value2, 100) = 100
                    assert_eq!(
                        get_self_entry_value(&pod, "key2").unwrap(),
                        ScalarOrVec::Scalar(GoldilocksField(100))
                    );

                    // Test that key3 = z = 42
                    assert_eq!(
                        get_self_entry_value(&pod, "key3").unwrap(),
                        ScalarOrVec::Scalar(GoldilocksField(42))
                    );

                    Ok(())
                }
                _ => Err(anyhow!("Expected PodRef")),
            }
        } else {
            Err(anyhow!("Failed to create source pod"))
        }
    }
    #[tokio::test]
    async fn test_pod_with_assertions_after_kv() -> Result<()> {
        let (env, _) = setup_env().await;

        // Create a pod with assertions after key-value definitions
        let result = eval(
            "[createpod test
                x 10
                y [+ x 12]
                z [* x 2]
                [> y x]
                [= z 20]
                [!= y z]]",
            env.clone(),
        )
        .await?;

        match result {
            Value::PodRef(pod) => {
                assert_eq!(
                    get_self_entry_value(&pod, "x").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(10))
                );
                assert_eq!(
                    get_self_entry_value(&pod, "y").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(22))
                );
                assert_eq!(
                    get_self_entry_value(&pod, "z").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(20))
                );
                Ok(())
            }
            _ => Err(anyhow!("Expected PodRef")),
        }
    }

    #[tokio::test]
    async fn test_pod_with_failing_assertion_after_kv() -> Result<()> {
        let (env, _) = setup_env().await;

        // This should fail because y is not greater than z
        let result = eval(
            "[createpod test
                x 10
                y [+ x 5]
                z [* x 2]
                [> y z]]", // y=15, z=20, so this assertion fails
            env.clone(),
        )
        .await;

        assert!(result.is_err());
        Ok(())
    }
    #[tokio::test]
    async fn test_pod_query_with_operation_and_assert() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create a pod with operations and assertions
        let source_pod = eval(
            "[createpod source
                y 15
                x [+ y 2]
                [> y 10]]",
            env.clone(),
        )
        .await?;
        if let Value::PodRef(source_pod) = source_pod {
            pod_store.lock().unwrap().add_pod(source_pod);
        }

        // Query for pods matching both operation and assertion
        let result = eval(
            "[pod?
                [x [+ y 2]]
                [> y 10]]",
            env.clone(),
        )
        .await?;

        match result {
            Value::SRef(_) => Ok(()),
            _ => Err(anyhow!("Expected SRef")),
        }
    }

    #[tokio::test]
    async fn test_pod_query_with_failing_assert() -> Result<()> {
        let (env, pod_store) = setup_env().await;

        // Create a pod that won't match the assertion
        let source_pod = eval(
            "[createpod source
                y 5
                x [+ y 2]]",
            env.clone(),
        )
        .await?;
        if let Value::PodRef(source_pod) = source_pod {
            pod_store.lock().unwrap().add_pod(source_pod);
        }

        // Query should fail because there is no y > 5 statement (even if y is over 5; in a future version the POD store will be able to make this POD JIT)
        let result = eval(
            "[pod?
                [x [+ y 2]]
                [> y 5]]",
            env.clone(),
        )
        .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No matching pod found"));
        Ok(())
    }
    #[tokio::test]
    async fn test_basic_from_operation() -> Result<()> {
        let shared = Arc::new(InMemoryStore::new());

        // Create Alice's environment
        let alice_env = Env::new(
            "alice".to_string(),
            shared.clone(),
            Arc::new(Mutex::new(MyPods::default())),
            Some(SchnorrSecretKey { sk: 42 }),
            None,
        );

        // Create Bob's environment
        let bob_env = Env::new(
            "bob".to_string(),
            shared.clone(),
            Arc::new(Mutex::new(MyPods::default())),
            Some(SchnorrSecretKey { sk: 43 }),
            None,
        );

        // Alice creates a value
        eval("[from alice 42]", alice_env.clone()).await?;

        // Bob retrieves Alice's value
        eval("[from alice 42]", bob_env.clone()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_cross_user_pod_query() -> Result<()> {
        let shared = Arc::new(InMemoryStore::new());
        let alice_pod_store = Arc::new(Mutex::new(MyPods::default()));
        let bob_pod_store = Arc::new(Mutex::new(MyPods::default()));

        // Create environments for Alice and Bob
        let alice_env = Env::new(
            "alice".to_string(),
            shared.clone(),
            alice_pod_store.clone(),
            Some(SchnorrSecretKey { sk: 42 }),
            None,
        );

        let bob_env = Env::new(
            "bob".to_string(),
            shared.clone(),
            bob_pod_store.clone(),
            Some(SchnorrSecretKey { sk: 43 }),
            None,
        );

        // First, Alice creates her initial pod
        let alice_pod = eval("[createpod source x 40]", alice_env.clone()).await?;
        if let Value::PodRef(pod) = alice_pod.clone() {
            // Clone here
            alice_pod_store.lock().unwrap().add_pod(pod);
        }

        // Both Alice and Bob run the exact same script
        let script = r#"[createpod test
            [define x [from alice [pod? [x]]]]
            new_value [+ x 2]]"#;

        // Alice runs it - she'll execute the pod? query and share the result
        let alice_result = eval(script, alice_env.clone()).await?;
        if let Value::PodRef(pod) = alice_result.clone() {
            // Clone here
            alice_pod_store.lock().unwrap().add_pod(pod);
        }

        // Bob runs the same script - he'll use Alice's shared query result
        let bob_result = eval(script, bob_env.clone()).await?;
        if let Value::PodRef(pod) = bob_result.clone() {
            // Clone here
            bob_pod_store.lock().unwrap().add_pod(pod.clone()); // Clone here too

            assert_eq!(
                get_self_entry_value(&pod, "new_value").unwrap(),
                ScalarOrVec::Scalar(GoldilocksField(42))
            );
            Ok(())
        } else {
            Err(anyhow!("Expected PodRef"))
        }
    }

    #[tokio::test]
    async fn test_from_wrong_user() -> Result<()> {
        let shared = Arc::new(InMemoryStore::new());

        let alice_env = Env::new(
            "alice".to_string(),
            shared.clone(),
            Arc::new(Mutex::new(MyPods::default())),
            Some(SchnorrSecretKey { sk: 42 }),
            None,
        );

        // Try to get a value from Bob that doesn't exist
        let result = eval("[from bob 42]", alice_env.clone()).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("couldn't find on the remote"));

        Ok(())
    }

    #[tokio::test]
    async fn test_complex_cross_user_pod_query() -> Result<()> {
        let shared = Arc::new(InMemoryStore::new());
        let alice_pod_store = Arc::new(Mutex::new(MyPods::default()));
        let bob_pod_store = Arc::new(Mutex::new(MyPods::default()));

        let alice_env = Env::new(
            "alice".to_string(),
            shared.clone(),
            alice_pod_store.clone(),
            Some(SchnorrSecretKey { sk: 42 }),
            None,
        );

        let bob_env = Env::new(
            "bob".to_string(),
            shared.clone(),
            bob_pod_store.clone(),
            Some(SchnorrSecretKey { sk: 43 }),
            None,
        );

        // Alice creates a complex pod
        let alice_pod = eval(
            "[createpod test
                x 40
                y [+ x 5]
                z [* y 2]
                [> y 42]]",
            alice_env.clone(),
        )
        .await?;
        if let Value::PodRef(pod) = alice_pod {
            alice_pod_store.lock().unwrap().add_pod(pod);
        }

        // Alice shares the pod query result
        eval(
            "[createpod test
                [define result [from alice [pod? [z] [> y 42]]]]
                new_value [+ result 10]]",
            alice_env.clone(),
        )
        .await?;
        // Bob creates a pod using Alice's complex pod query result
        let result = eval(
            "[createpod test
                [define result [from alice [pod? [z] [> y 42]]]]
                new_value [+ result 10]]",
            bob_env.clone(),
        )
        .await?;

        match result {
            Value::PodRef(pod) => {
                assert_eq!(
                    get_self_entry_value(&pod, "new_value").unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(100)) // (40 + 5) * 2 + 10 = 100
                );
                Ok(())
            }
            _ => Err(anyhow!("Expected PodRef")),
        }
    }
    #[tokio::test]
    async fn test_list_creation() -> Result<()> {
        let (env, _) = setup_env().await;

        let result = eval("[list 1 2 3 4]", env).await?;

        match result {
            Value::List(values) => {
                assert_eq!(values.len(), 4);
                assert!(matches!(values[0], Value::Scalar(GoldilocksField(1))));
                assert!(matches!(values[1], Value::Scalar(GoldilocksField(2))));
                assert!(matches!(values[2], Value::Scalar(GoldilocksField(3))));
                assert!(matches!(values[3], Value::Scalar(GoldilocksField(4))));
                Ok(())
            }
            _ => Err(anyhow!("Expected List, got something else")),
        }
    }

    #[tokio::test]
    async fn test_car() -> Result<()> {
        let (env, _) = setup_env().await;

        let result = eval("[car [list 42 2 3]]", env).await?;

        match result {
            Value::Scalar(GoldilocksField(42)) => Ok(()),
            _ => Err(anyhow!("Expected Scalar(42), got something else")),
        }
    }

    #[tokio::test]
    async fn test_car_empty_list_error() -> Result<()> {
        let (env, _) = setup_env().await;
        let result = eval("[car [list]]", env).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_cdr() -> Result<()> {
        let (env, _) = setup_env().await;
        let result = eval("[cdr [list 1 2 3]]", env).await?;

        match result {
            Value::List(values) => {
                assert_eq!(values.len(), 2);
                assert!(matches!(values[0], Value::Scalar(GoldilocksField(2))));
                assert!(matches!(values[1], Value::Scalar(GoldilocksField(3))));
                Ok(())
            }
            _ => Err(anyhow!("Expected List, got something else")),
        }
    }

    #[tokio::test]
    async fn test_cdr_empty_list_error() -> Result<()> {
        let (env, _) = setup_env().await;

        let result = eval("[cdr [list]]", env).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_cons() -> Result<()> {
        let (env, _) = setup_env().await;

        let result = eval("[cons 1 [list 2 3]]", env).await?;

        match result {
            Value::List(values) => {
                assert_eq!(values.len(), 3);
                assert!(matches!(values[0], Value::Scalar(GoldilocksField(1))));
                assert!(matches!(values[1], Value::Scalar(GoldilocksField(2))));
                assert!(matches!(values[2], Value::Scalar(GoldilocksField(3))));
                Ok(())
            }
            _ => Err(anyhow!("Expected List, got something else")),
        }
    }

    #[tokio::test]
    async fn test_cons_to_empty_list() -> Result<()> {
        let (env, _) = setup_env().await;

        let result = eval("[cons 42 [list]]", env).await?;

        match result {
            Value::List(values) => {
                assert_eq!(values.len(), 1);
                assert!(matches!(values[0], Value::Scalar(GoldilocksField(42))));
                Ok(())
            }
            _ => Err(anyhow!("Expected List, got something else")),
        }
    }

    #[tokio::test]
    async fn test_nested_list_operations() -> Result<()> {
        let (env, _) = setup_env().await;

        let result = eval("[cons [car [list 1 2]] [cdr [list 3 4 5]]]", env).await?;

        match result {
            Value::List(values) => {
                assert_eq!(values.len(), 3);
                assert!(matches!(values[0], Value::Scalar(GoldilocksField(1))));
                assert!(matches!(values[1], Value::Scalar(GoldilocksField(4))));
                assert!(matches!(values[2], Value::Scalar(GoldilocksField(5))));
                Ok(())
            }
            _ => Err(anyhow!("Expected List, got something else")),
        }
    }

    #[tokio::test]
    async fn test_list_with_arithmetic() -> Result<()> {
        let (env, _) = setup_env().await;

        let result = eval("[list [+ 1 2] [* 3 4] [max 5 2]]", env).await?;

        match result {
            Value::List(values) => {
                assert_eq!(values.len(), 3);
                assert!(matches!(values[0], Value::Scalar(GoldilocksField(3))));
                assert!(matches!(values[1], Value::Scalar(GoldilocksField(12))));
                assert!(matches!(values[2], Value::Scalar(GoldilocksField(5))));
                Ok(())
            }
            _ => Err(anyhow!("Expected List, got something else")),
        }
    }
}
