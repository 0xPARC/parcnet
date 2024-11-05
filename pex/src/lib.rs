mod constants;
mod macros;
pub mod repl;

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use constants::*;

use tracing::info;

use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};

use pod2::pod::{
    entry::Entry, payload::HashablePayload, statement::StatementRef, value::ScalarOrVec, GPGInput,
    Op, OpCmd, Statement, POD,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ORef {
    S,
    P(String),
}

impl From<ORef> for String {
    fn from(oref: ORef) -> String {
        match oref {
            ORef::S => SELF_ORIGIN_NAME.to_string(),
            ORef::P(s) => s,
        }
    }
}

#[derive(Clone, Debug)]
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

#[derive(Default)]
pub struct MyPods {
    pub pods: Vec<POD>,
}

impl MyPods {
    pub fn find(&self, key: &str) -> Option<&Statement> {
        for pod in &self.pods {
            if let Some(value) = pod.payload.statements_map.get(key) {
                return Some(value);
            }
        }
        None
    }
    pub fn add_pod(&mut self, pod: POD) {
        self.pods.push(pod);
    }
}

pub type User = String;

#[derive(Clone, Default)]
pub struct Env {
    user: User,
    pub pod_store: Arc<Mutex<MyPods>>,
    pub current_builder: Option<Arc<Mutex<PodBuilder>>>,
    shared: Arc<Mutex<HashMap<u64, Value>>>,
    bindings: Arc<Mutex<HashMap<String, Value>>>,
}

#[derive(Clone, Debug)]
pub struct PodBuilder {
    pub pending_operations: Vec<(String, OpCmd)>,
    pub input_pods: HashMap<String, POD>,
    pub next_origin_id: usize,
    pub next_result_key_id: usize,
    pub next_statement_id: usize,
}

#[derive(Clone, Debug)]
pub enum Value {
    String(String),
    Scalar(GoldilocksField),
    PodRef(POD),
    SRef(SRef),
    Operation(Box<Operation>),
    List(Vec<Value>),
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

#[derive(Clone, Debug)]
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

impl Default for PodBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PodBuilder {
    pub fn new() -> Self {
        Self {
            pending_operations: Vec::new(),
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
        if self.input_pods.get(&name).is_some() {
            name.clone()
        } else {
            self.input_pods.insert(name.clone(), pod.clone());
            name.clone()
        }
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

    pub fn finalize(&self) -> Result<POD> {
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
        let gpg_input = GPGInput::new(self.input_pods.clone(), origin_renaming_map);
        let pending_ops: &[OpCmd] = &self
            .pending_operations
            .iter()
            .map(|(_, ops)| ops.clone())
            .collect::<Vec<OpCmd>>()[..];
        POD::execute_oracle_gadget(&gpg_input, pending_ops)
    }
}

impl Env {
    pub fn new(
        user: User,
        shared: Arc<Mutex<HashMap<u64, Value>>>,
        pod_store: Arc<Mutex<MyPods>>,
    ) -> Self {
        Self {
            user,
            shared,
            pod_store,
            current_builder: None,
            bindings: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn extend(&self) -> Self {
        Self {
            user: self.user.clone(),
            shared: self.shared.clone(),
            pod_store: self.pod_store.clone(),
            current_builder: self.current_builder.clone(),
            bindings: Arc::new(Mutex::new(self.bindings.lock().unwrap().clone())),
        }
    }

    pub async fn get_remote(&self, id: u64) -> Option<Value> {
        loop {
            if let Some(v) = self.shared.lock().unwrap().get(&id).cloned() {
                return Some(v);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    pub fn set_remote(&self, id: u64, value: Value) {
        self.shared.lock().unwrap().insert(id, value);
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
                    Expr::Atom(_, op) => {
                        // Handle operation which can be tracked inside PODs
                        if let Ok(op_type) = OpType::from_str(op) {
                            return self.eval_operation(op_type, &exprs[1..], env).await;
                        }
                        match op.as_str() {
                            "createpod" => {
                                if exprs.len() < 2 {
                                    return Err(anyhow!("createpod requires a body"));
                                }
                                return self.eval_create_pod(&exprs[1..], env).await;
                            }
                            "pod?" => {
                                if exprs.len() < 2 {
                                    return Err(anyhow!("pod? requires at least one argument"));
                                }
                                return self.eval_pod_query(&exprs[1..], env).await;
                            }
                            "define" => {
                                if exprs.len() != 3 {
                                    return Err(anyhow!("define requires exactly two arguments"));
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
                                                    env.set_binding(name.clone(), value.clone());
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
                                    Value::List(values) => {
                                        values.first().cloned().ok_or_else(|| anyhow!("Empty list"))
                                    }
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
                                    _ => Err(anyhow!("cons requires a list as second argument")),
                                }
                            }
                            op => Err(anyhow!("Unknown operation: {}", op)),
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
        // First evaluate all expressions that aren't key-value pairs
        // This includes defines and other forms
        let mut i = 1;
        while i < body.len() {
            match &body[i] {
                Expr::List(_, _) => {
                    // Evaluate any list expression (define, etc)
                    body[i].eval(pod_env.clone()).await?;
                    i += 1;
                }
                Expr::Atom(_, _) => {
                    // Found what should be start of k/v pairs
                    break;
                }
            }
        }

        // Now process remaining expressions as key-value pairs
        let remaining = &body[i..];
        if remaining.len() % 2 != 0 {
            return Err(anyhow!("Odd number of key-value expressions"));
        }

        for chunk in remaining.chunks(2) {
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
                                            (statement_id.to_string(), op_cmd);
                                    } else {
                                        return Err(anyhow!(format!(
                                                "Couldn't find a statement with statement id {} while editing a NewEntry in createpod",
                                                statement_id
                                            )));
                                    }
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

                                            let new_statement_id =
                                                builder_guard.next_statement_id();
                                            builder_guard.add_operation(
                                                Op::NewEntry(new_entry),
                                                new_statement_id.clone(),
                                            );

                                            let next_statement_id =
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
                                                        PREDICATE_VALUEOF, new_statement_id
                                                    ))
                                                    .into(),
                                                ),
                                                next_statement_id,
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
                        },
                        _ => return Err(anyhow!("Can't assign a non scalar to pod entry")),
                    }
                }
                _ => return Err(anyhow!("Expected key-value pair")),
            }
        }
        let pod = builder.lock().unwrap().finalize()?;
        Ok(Value::PodRef(pod))
    }
    async fn eval_pod_query(&self, parts: &[Expr], env: Env) -> Result<Value> {
        let store = env.pod_store.lock().unwrap();
        'outer: for pod in store.pods.iter() {
            let pod_hash = format!("{:?}", pod.payload.hash_payload());
            let pod_id = format!("{}{}", POD_PREFIX, pod_hash);

            // Skip if this pod has already been used as an input pod
            if let Some(ref builder) = env.current_builder {
                let builder = builder.lock().unwrap();
                if builder.input_pods.contains_key(&pod_id) {
                    continue 'outer;
                }
            }

            let mut matched_refs = Vec::new();
            for part in parts {
                match part {
                    Expr::Atom(_, key) => {
                        // Find a ValueOf statement on _SELF that matches the key we are looking for
                        if let Some(statement_key) = pod
                            .payload
                            .statements_map
                            .iter()
                            .find(|(_, s)| {
                                s.value_of_anchored_key().map(|k| k.0.is_self() && k.1 == *key)
                                    .filter(|&x| x)
                                    .unwrap_or(false)
                            })
                            .map(|(key, _s)| key)
                        {
                            matched_refs.push(SRef(
                                // the origin will be corrected later
                                ORef::P("_placeholder".to_string()),
                                statement_key.clone(),
                            ));
                        } else {
                            continue 'outer;
                        }
                    }
                    Expr::List(_, _pattern) => todo!(),
                }
            }
            if let Some(ref builder) = env.current_builder {
                let mut builder = builder.lock().unwrap();
                let pod_id = builder.register_input_pod(pod);
                let srefs: Vec<SRef> = matched_refs
                    .into_iter()
                    .map(|sref| SRef::new(pod_id.clone(), sref.1))
                    .collect();
                // If only one key was queried, return single SRef
                // Otherwise return a List of SRefs
                return if srefs.len() == 1 {
                    Ok(Value::SRef(srefs.into_iter().next().unwrap()))
                } else {
                    Ok(Value::List(srefs.into_iter().map(Value::SRef).collect()))
                };
            } else {
                return Err(anyhow!("pod? not in createpod context"));
            }
        }
        Err(anyhow!("No pod found matching statements"))
    }
    async fn eval_operation(&self, op_type: OpType, operands: &[Expr], env: Env) -> Result<Value> {
        if operands.len() != 2 {
            return Err(anyhow!("Operations require exactly two operands"));
        }
        let op1 = operands[0].eval(env.clone()).await?;
        let op2 = operands[1].eval(env.clone()).await?;

        let operation: Operation = (op_type, op1.clone(), op2.clone()).into();

        if let Some(ref builder) = env.current_builder {
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

                    // We need to create a new entry for the result, and also for any operand if it's a new scalar
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
            // We would also need to make get_value_from_ref work outside a builder context, by fetching the refs in the store directly
            // as an example if createpod returns a list of statementref (like pod?) that enables to then do further computation on it
            Ok(Value::Scalar(operation.eval()?))
        }
    }
}

fn get_value_from_sref(sref: &SRef, env: &Env) -> Result<GoldilocksField> {
    if let Some(ref builder) = env.current_builder {
        let builder = builder.lock().unwrap();
        if sref.0.eq(&ORef::S) {
            // TODO: we might want to enable this in case we support doing stuff with our ValueOf statement right after having defined them
            // eg:
            // [createpod test
            //     x 10
            //     y [+ x 20]
            //  ]
            return Err(anyhow!("Cannot get value from a SELF statement"));
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
    async fn test_create_pod() -> Result<()> {
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store);

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
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store.clone());
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
            "[createpod final x [+ 40 2] y [+ [pod? x] 66] z [+ [pod? z] 66]]",
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
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store.clone());
        let first_pod_eval = eval("[createpod test_pod x 10]", env.clone()).await?;
        let first_pod = match first_pod_eval {
            Value::PodRef(pod) => pod,
            _ => panic!("Expected PodRef"),
        };
        pod_store.lock().unwrap().add_pod(first_pod);

        let second_pod_eval = eval("[createpod test_pod_2 z [+ [pod? x] 10]]", env.clone()).await?;
        let second_pod = match second_pod_eval {
            Value::PodRef(pod) => pod,
            _ => panic!("Expected PodRef"),
        };
        pod_store.lock().unwrap().add_pod(second_pod);

        let result = eval("[createpod final final-key [+ 10 [pod? z]]]", env.clone()).await?;

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
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store.clone());

        // Create two identical pods
        let pod1 = eval("[createpod test_pod1 x 10]", env.clone()).await?;
        let pod2 = eval("[createpod test_pod2 x 12]", env.clone()).await?;

        if let (Value::PodRef(pod1), Value::PodRef(pod2)) = (pod1, pod2) {
            pod_store.lock().unwrap().add_pod(pod1);
            pod_store.lock().unwrap().add_pod(pod2);

            // This should succeed because it uses two different pods
            eval(
                "[createpod final a [+ [pod? x] 1] b [+ [pod? x] 2]]",
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
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store.clone());

        let pod1 = eval("[createpod test_pod1 x 10]", env.clone()).await?;
        if let Value::PodRef(pod1) = pod1 {
            pod_store.lock().unwrap().add_pod(pod1);

            // This should fail because there's only one pod with x=10,
            // but we're trying to match it twice
            let result = eval(
                "[createpod final a [+ [pod? x] 1] b [+ [pod? x] 2]]",
                env.clone(),
            )
            .await;

            assert!(result.is_err());
            if let Err(e) = result {
                assert!(e.to_string().contains("No pod found matching statements"));
            }
            Ok(())
        } else {
            Err(anyhow!("Failed to create test pod"))
        }
    }
    #[tokio::test]
    async fn test_pod_query_destructuring() -> Result<()> {
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store.clone());

        // Create a pod with two values
        let pod1 = eval("[createpod test_pod1 x 10 y 20]", env.clone()).await?;
        if let Value::PodRef(pod1) = pod1 {
            pod_store.lock().unwrap().add_pod(pod1);

            // Test destructuring pod query results
            let result = eval(
                "[createpod final
                    [define [a b] [pod? x y]]
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
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store.clone());

        // Create a pod with a single value
        let pod1 = eval("[createpod test_pod1 value1 10]", env.clone()).await?;
        if let Value::PodRef(pod1) = pod1 {
            pod_store.lock().unwrap().add_pod(pod1);

            // Test querying single value returns SRef directly, not in a list
            let result = eval(
                "[createpod final
                    [define x [pod? value1]]
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
    async fn test_complex_pod_creation_with_defines() -> Result<()> {
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store.clone());

        // First create a pod with some values we'll reference
        let source_pod = eval("[createpod source value1 10 value2 20]", env.clone()).await?;
        if let Value::PodRef(source_pod) = source_pod {
            pod_store.lock().unwrap().add_pod(source_pod);

            // Now create a complex pod using defines and references
            let result = eval(
                "[createpod test
                    [define [x y] [pod? value1 value2]]
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
    async fn test_list_creation() -> Result<()> {
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store);

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
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store);

        let result = eval("[car [list 42 2 3]]", env).await?;

        match result {
            Value::Scalar(GoldilocksField(42)) => Ok(()),
            _ => Err(anyhow!("Expected Scalar(42), got something else")),
        }
    }

    #[tokio::test]
    async fn test_car_empty_list_error() -> Result<()> {
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store);

        let result = eval("[car [list]]", env).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_cdr() -> Result<()> {
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store);

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
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store);

        let result = eval("[cdr [list]]", env).await;
        assert!(result.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_cons() -> Result<()> {
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store);

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
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store);

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
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store);

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
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(Mutex::new(MyPods::default()));
        let env = Env::new("test_user".to_string(), shared, pod_store);

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
