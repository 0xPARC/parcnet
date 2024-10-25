mod macros;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use tracing::info;

use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};

use pod2::pod::{
    Entry, GPGInput, HashablePayload, Op, OpCmd, ScalarOrVec, Statement, StatementRef, POD,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ORef {
    S,
    P(String),
}

impl ORef {
    fn as_str(&self) -> &str {
        match self {
            ORef::S => "_SELF",
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

impl From<SRef> for StatementRef<'static, 'static> {
    fn from(sref: SRef) -> StatementRef<'static, 'static> {
        StatementRef(
            Box::leak(sref.0.as_str().to_string().into_boxed_str()),
            Box::leak(sref.1.into_boxed_str()),
        )
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
}

#[derive(Clone, Debug)]
pub struct PodBuilder {
    pub pending_operations: HashMap<String, OpCmd<'static, 'static, 'static>>,
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

#[derive(Clone, Debug)]
pub enum Operation {
    Sum(Value, Value),
    Product(Value, Value),
    Max(Value, Value),
}

impl Operation {
    fn from_op_type(op_type: OpType, op1: Value, op2: Value) -> Self {
        match op_type {
            OpType::Add => Operation::Sum(op1, op2),
            OpType::Multiply => Operation::Product(op1, op2),
            OpType::Max => Operation::Max(op1, op2),
        }
    }
    fn to_op_type(&self) -> OpType {
        match self {
            Operation::Sum(_, _) => OpType::Add,
            Operation::Product(_, _) => OpType::Multiply,
            Operation::Max(_, _) => OpType::Max,
        }
    }
    fn eval(&self) -> Result<GoldilocksField> {
        match self {
            Operation::Sum(Value::Scalar(a), Value::Scalar(b)) => Ok(*a + *b),
            Operation::Product(Value::Scalar(a), Value::Scalar(b)) => Ok(*a * *b),
            Operation::Max(Value::Scalar(a), Value::Scalar(b)) => {
                Ok(if a.to_canonical_u64() > b.to_canonical_u64() {
                    *a
                } else {
                    *b
                })
            }
            _ => Err(anyhow!(
                "Cannot eval operation with non-scalar values directly"
            )),
        }
    }
    fn eval_with_env(&self, env: &Env) -> Result<GoldilocksField> {
        match self {
            Operation::Sum(a, b) | Operation::Product(a, b) | Operation::Max(a, b) => {
                let value1 = match a {
                    Value::Scalar(s) => *s,
                    Value::SRef(r) => get_value_from_ref(r, env)?,
                    _ => return Err(anyhow!("Invalid operand type")),
                };
                let value2 = match b {
                    Value::Scalar(s) => *s,
                    Value::SRef(r) => get_value_from_ref(r, env)?,
                    _ => return Err(anyhow!("Invalid operand type")),
                };

                Ok(match self {
                    Operation::Sum(_, _) => value1 + value2,
                    Operation::Product(_, _) => value1 * value2,
                    Operation::Max(_, _) => {
                        if value1.to_canonical_u64() > value2.to_canonical_u64() {
                            value1
                        } else {
                            value2
                        }
                    }
                })
            }
        }
    }
    fn eval_pattern(&self) -> Result<Value> {
        match self {
            Operation::Sum(a, b) | Operation::Product(a, b) | Operation::Max(a, b) => {
                let eval_a = match a {
                    Value::Operation(nested_op) => nested_op.eval_pattern()?,
                    Value::Scalar(_) | Value::String(_) => a.clone(),
                    _ => return Err(anyhow!("Invalid pattern operand")),
                };

                let eval_b = match b {
                    Value::Operation(nested_op) => nested_op.eval_pattern()?,
                    Value::Scalar(_) | Value::String(_) => b.clone(),
                    _ => return Err(anyhow!("Invalid pattern operand")),
                };

                match (&eval_a, &eval_b) {
                    (Value::Scalar(s1), Value::Scalar(s2)) => {
                        let result = match self {
                            Operation::Sum(_, _) => *s1 + *s2,
                            Operation::Product(_, _) => *s1 * *s2,
                            Operation::Max(_, _) => {
                                if s1.to_canonical_u64() > s2.to_canonical_u64() {
                                    *s1
                                } else {
                                    *s2
                                }
                            }
                        };
                        Ok(Value::Scalar(result))
                    }
                    _ => Ok(Value::Operation(Box::new(Operation::from_op_type(
                        self.to_op_type(),
                        eval_a,
                        eval_b,
                    )))),
                }
            }
        }
    }

    fn into_pod_op(
        op_type: OpType,
        result_ref: SRef,
        op1: SRef,
        op2: SRef,
    ) -> Op<StatementRef<'static, 'static>> {
        match op_type {
            OpType::Add => Op::SumOf(result_ref.into(), op1.into(), op2.into()),
            OpType::Multiply => Op::ProductOf(result_ref.into(), op1.into(), op2.into()),
            OpType::Max => Op::MaxOf(result_ref.into(), op1.into(), op2.into()),
        }
    }
}

impl PodBuilder {
    pub fn new() -> Self {
        Self {
            pending_operations: HashMap::new(),
            input_pods: HashMap::new(),
            next_origin_id: 2,
            next_result_key_id: 0,
            next_statement_id: 0,
        }
    }
    pub fn pod_id(pod: &POD) -> String {
        let pod_hash = pod.payload.hash_payload();
        let name = format!("pod_{}", pod_hash);
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

    pub fn next_result_key_id(&mut self) -> String {
        let key = format!("result_{}", self.next_result_key_id);
        self.next_result_key_id += 1;
        key
    }

    pub fn next_statement_id(&mut self) -> String {
        let id = format!("statement_{}", self.next_statement_id);
        self.next_statement_id += 1;
        id
    }

    pub fn add_operation(&mut self, op: Op<StatementRef<'static, 'static>>, statement_id: String) {
        let static_str = Box::leak(statement_id.to_owned().into_boxed_str());
        self.pending_operations
            .insert(statement_id.clone(), OpCmd(op, static_str));
    }

    pub fn finalize(&self) -> Result<POD> {
        let gpg_input = GPGInput::new(self.input_pods.clone(), HashMap::new());
        let pending_ops: &[OpCmd] = &self
            .pending_operations
            .values()
            .cloned()
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
        }
    }

    pub fn extend(&self) -> Self {
        Self {
            user: self.user.clone(),
            shared: self.shared.clone(),
            pod_store: self.pod_store.clone(),
            current_builder: self.current_builder.clone(),
        }
    }

    pub async fn get(&self, id: u64) -> Option<Value> {
        loop {
            if let Some(v) = self.shared.lock().unwrap().get(&id).cloned() {
                return Some(v);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    pub fn set(&self, id: u64, value: Value) {
        self.shared.lock().unwrap().insert(id, value);
    }
    // pub fn local(&self, key: &str) -> Option<Value> {
    //     self.pods.find(key)
    // }
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
                        // Handle pod? query
                        if op == "pod?" {
                            if exprs.len() < 2 {
                                return Err(anyhow!("pod? requires at least one argument"));
                            }
                            return self.eval_pod_query(&exprs[1..], env).await;
                        }
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
                            op => Err(anyhow!("Unknown operation: {}", op)),
                        }
                    }
                    _ => Err(anyhow!("First item must be an atom")),
                }
            }
            Expr::Atom(_, a) => {
                if let Ok(a) = a.parse::<u64>() {
                    Ok(Value::Scalar(GoldilocksField(a)))
                } else {
                    Err(anyhow!("Not an u64"))
                }
            }
        }
    }
    async fn eval_create_pod(&self, body: &[Expr], env: Env) -> Result<Value> {
        let mut pod_env = env.extend();
        let pod_name = if let Expr::Atom(_, op) = &body[0] {
            Some(op)
        } else {
            None
        };
        info!("creating pod {}", pod_name.expect("No pod name"));
        let builder = Arc::new(Mutex::new(PodBuilder::new()));
        pod_env.current_builder = Some(builder.clone());
        for chunk in body[1..].chunks(2) {
            if chunk.len() != 2 {
                return Err(anyhow!("Odd number of key-value pairs"));
            }

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
                                let statement_id =
                                    statement.split(':').collect::<Vec<&str>>()[1].to_string();
                                let mut builder_guard = builder.lock().unwrap();
                                if let Some(operation) =
                                    builder_guard.pending_operations.get(&statement_id)
                                {
                                    if let Op::NewEntry(entry) = &operation.0 {
                                        let new_entry = Entry {
                                            key: key.clone(),
                                            value: entry.value.clone(),
                                        };
                                        let op_cmd = OpCmd(
                                            Op::NewEntry(new_entry),
                                            Box::leak(statement_id.clone().into_boxed_str()),
                                        );
                                        builder_guard
                                            .pending_operations
                                            .insert(statement_id.to_string(), op_cmd);
                                    } else {
                                        return Err(anyhow!(format!(
                                                "Couldn't find a statement with statement id {} while editing a NewEntry in createpod",
                                                statement_id
                                            )));
                                    }
                                }
                            }
                            SRef(ORef::P(pod_id), statement) => {
                                todo!();
                            }
                        },
                        _ => return Err(anyhow!("Can't assign a non scalar to pod entry")),
                    }
                }
                _ => return Err(anyhow!("Expected key-value pair")),
            }
        }
        // Finalize pod
        let pod = builder.lock().unwrap().finalize()?;
        Ok(Value::PodRef(pod))
    }
    async fn eval_pod_query(&self, parts: &[Expr], env: Env) -> Result<Value> {
        // From operands I want to put together a list a query, which is a list of keys, operations, and asserts
        // keys will be checked on ValueOf on _SELF that have the corresponding entry name
        // each operation will be linked to one of the key (it's a tree of operations that get unrolled into a serie of statements and entries whose values will need to be checked)
        // asserts will be checked one by one as binary statements
        let store = env.pod_store.lock().unwrap();
        'outer: for pod in store.pods.iter() {
            let mut matched_refs = Vec::new();
            for part in parts {
                match part {
                    Expr::Atom(_, key) => {
                        // Find a ValueOf statement on _SELF that matches the key we are looking for
                        if let Some(statement_key) = pod
                            .payload
                            .statements_map
                            .iter()
                            .find(|(_key, s)| {
                                s.value_of_key()
                                    .and_then(|k| Some(k.0.is_self() && k.1 == *key))
                                    .is_some()
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
                    Expr::List(_, pattern) => todo!(),
                }
            }
            if let Some(ref builder) = env.current_builder {
                let mut builder = builder.lock().unwrap();
                let pod_id = builder.register_input_pod(pod);
                let srefs: Vec<SRef> = matched_refs
                    .into_iter()
                    .map(|sref| SRef::new(pod_id.clone(), sref.1))
                    .collect();
                // TODO: for now return the first sref while we don't support lists
                return Ok(Value::SRef(srefs[0].clone()));
            } else {
                return Err(anyhow!("pod? not in createpod context"));
            }
        }
        return Err(anyhow!("No pod found matching statements"));
    }
    async fn eval_operation(&self, op_type: OpType, operands: &[Expr], env: Env) -> Result<Value> {
        if operands.len() != 2 {
            return Err(anyhow!("Operations require exactly two operands"));
        }
        let op1 = operands[0].eval(env.clone()).await?;
        let op2 = operands[1].eval(env.clone()).await?;

        let operation = Operation::from_op_type(op_type, op1.clone(), op2.clone());

        if let Some(ref builder) = env.current_builder {
            let result_value = operation.eval_with_env(&env)?;
            let mut builder = builder.lock().unwrap();

            // Create refs for any values that need tracking
            match (&op1, &op2) {
                (Value::SRef(_), _) | (_, Value::SRef(_)) => {
                    // Convert operands to SRefs if they're scalars
                    let op1_sref = match op1 {
                        Value::Scalar(s) => {
                            let key = s.to_string();
                            // TODO: Check if that constant already exist, and if it does, don't add a new operation
                            let statement_name = format!("constant_{}", key);
                            builder.add_operation(
                                Op::NewEntry(Entry {
                                    // the entry name is the same as the constant (eg: "42" for 42)
                                    key: key.clone(),
                                    value: ScalarOrVec::Scalar(s),
                                }),
                                statement_name.clone(),
                            );
                            SRef::self_ref(format!("VALUEOF:{}", statement_name))
                        }
                        Value::SRef(r) => r,
                        _ => return Err(anyhow!("Invalid operand type")),
                    };

                    let op2_sref = match op2 {
                        Value::Scalar(s) => {
                            let key = s.to_string();
                            // TODO: Check if that constant already exist, and if it does, don't add a new operation
                            let statement_name = format!("constant_{}", key);
                            builder.add_operation(
                                Op::NewEntry(Entry {
                                    // the entry name is the same as the constant (eg: "42" for 42)
                                    key: key.clone(),
                                    value: ScalarOrVec::Scalar(s),
                                }),
                                statement_name.clone(),
                            );
                            SRef::self_ref(format!("VALUEOF:{}", statement_name))
                        }
                        Value::SRef(r) => r,
                        _ => return Err(anyhow!("Invalid operand type")),
                    };

                    // We need to create a new entry for the result, and also for any operand if it's a new scalar
                    let result_key = builder.next_result_key_id();
                    let new_entry_statement_id = builder.next_statement_id();
                    let result_sref = SRef::self_ref(format!("VALUEOF:{}", new_entry_statement_id));
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
            // as an example if createpod returns a list of statementref (like pod?) that enables to then do further computation on it
            Ok(Value::Scalar(operation.eval()?))
        }
    }
}

fn get_value_from_ref(sref: &SRef, env: &Env) -> Result<GoldilocksField> {
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
        if let Some(pod) = builder.input_pods.get(sref.0.as_str()) {
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
        Err(anyhow!("No active pod builder"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pod2::pod::AnchoredKey;
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

        // Create a pod with two scalar values
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
            "[createpod final x [+ 40 2] y [+ [pod? x] 66]]",
            env.clone(),
        )
        .await?;

        match result {
            Value::PodRef(pod) => {
                dbg!(&pod.payload.statements_map);
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
}
