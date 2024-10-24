mod macros;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

// Some thoughts on StatementRef
// I technically do not need them. I can refer to statement by bundling the pod payload hash which I use
// to track my input pods and the statement i am referring to
// when constructing my ops, i can create these annoying OP CMD by figuring out which origin I am about to refer to
// which I can do via replacing it with my convention for pod_id -> origin_id (I could keep a mapping)
// With the origin and the statement name, I have a statement ref (and if the API was better I could get a ref to the statement directly)

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
}

pub type User = String;

#[derive(Clone, Default)]
pub struct Env {
    user: User,
    pub pod_store: Arc<MyPods>,
    pub current_builder: Option<Arc<Mutex<PodBuilder>>>,
    shared: Arc<Mutex<HashMap<u64, Value>>>,
}

#[derive(Clone, Debug)]
pub struct PodBuilder {
    pub pending_operations: Vec<OpCmd<'static, 'static, 'static>>,
    pub input_pods: HashMap<String, POD>,
    // pub origin_mapping: HashMap<String, String>,
    pub next_origin_id: usize,
    pub next_result_id: usize,
}

#[derive(Clone, Debug)]
pub enum Value {
    String(String),
    Scalar(GoldilocksField),
    PodRef(POD),
    SRef(SRef),
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

    // Keep the simple eval for when we know we have scalars
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
            pending_operations: Vec::new(),
            input_pods: HashMap::new(),
            // origin_mapping: HashMap::new(),
            next_origin_id: 2,
            next_result_id: 0,
        }
    }
    pub fn register_input_pod(&mut self, pod: &POD) -> String {
        let pod_hash = pod.payload.hash_payload();
        let name = format!("pod_{}", pod_hash);
        if let Some(_) = self.input_pods.get(&name) {
            name.clone()
        } else {
            // let origin = format!("origin_{}", self.next_origin_id);
            // self.next_origin_id += 1;
            // self.origin_mapping.insert(name.clone(), origin.clone());
            self.input_pods.insert(name.clone(), pod.clone());
            name.clone()
        }
    }

    pub fn next_result_key(&mut self) -> String {
        let key = format!("result_{}", self.next_result_id);
        self.next_result_id += 1;
        key
    }

    pub fn add_operation(&mut self, op: Op<StatementRef<'static, 'static>>, output_name: String) {
        let static_str = Box::leak(output_name.to_owned().into_boxed_str());
        self.pending_operations.push(OpCmd(op, static_str));
    }

    pub fn finalize(self) -> Result<POD> {
        let gpg_input = GPGInput::new(self.input_pods, HashMap::new());
        POD::execute_oracle_gadget(&gpg_input, &self.pending_operations)
    }
}

impl Env {
    pub fn new(
        user: User,
        shared: Arc<Mutex<HashMap<u64, Value>>>,
        pod_store: Arc<MyPods>,
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
                        if let Ok(op_type) = OpType::from_str(op) {
                            return self.eval_operation(op_type, &exprs[1..], env).await;
                        }
                        match op.as_str() {
                            "createpod" => {
                                if exprs.len() < 2 {
                                    return Err(anyhow!("createpod requires a body"));
                                }
                                let mut pod_env = env.extend();
                                let pod_name = if let Expr::Atom(_, op) = &exprs[1] {
                                    Some(op)
                                } else {
                                    None
                                };
                                info!("creating pod {}", pod_name.expect("No pod name"));
                                pod_env.current_builder =
                                    Some(Arc::new(Mutex::new(PodBuilder::new())));
                                for chunk in exprs[2..].chunks(2) {
                                    if chunk.len() != 2 {
                                        return Err(anyhow!("Odd number of key-value pairs"));
                                    }

                                    let (key_expr, value_expr) = (&chunk[0], &chunk[1]);
                                    match key_expr {
                                        Expr::Atom(_, key) => {
                                            let value = value_expr.eval(pod_env.clone()).await?;
                                            if let Some(ref builder) = pod_env.current_builder {
                                                let mut builder = builder.lock().unwrap();
                                                match value {
                                                    Value::Scalar(s) => {
                                                        let entry = Entry {
                                                            key: key.clone(),
                                                            value: ScalarOrVec::Scalar(s),
                                                        };
                                                        builder.add_operation(
                                                            Op::NewEntry(entry),
                                                            key.clone(),
                                                        );
                                                    }
                                                    _ => {
                                                        return Err(anyhow!(
                                                            "Can't assign a non scalar to pod entry"
                                                        ))
                                                    }
                                                }
                                            }
                                        }
                                        _ => return Err(anyhow!("Expected key-value pair")),
                                    }
                                }
                                // Finalize pod
                                if let Some(ref builder) = pod_env.current_builder {
                                    let builder = builder.lock().unwrap().clone();
                                    let pod = builder.finalize()?;
                                    Ok(Value::PodRef(pod)) // empty string as we don't have a specific entry
                                } else {
                                    Err(anyhow!("No pod builder in context"))
                                }
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
    async fn eval_operation(&self, op_type: OpType, operands: &[Expr], env: Env) -> Result<Value> {
        if operands.len() != 2 {
            return Err(anyhow!("Operations require exactly two operands"));
        }
        let op1 = operands[0].eval(env.clone()).await?;
        let op2 = operands[1].eval(env.clone()).await?;

        let operation = Operation::from_op_type(op_type, op1.clone(), op2.clone());

        if let Some(ref builder) = env.current_builder {
            let mut builder = builder.lock().unwrap();
            let result_value = operation.eval_with_env(&env)?;

            // Create refs for any values that need tracking
            match (&op1, &op2) {
                (Value::SRef(_), _) | (_, Value::SRef(_)) => {
                    // We need to create a new entry for the result, and also for any operand if it's a new scalar
                    let result_key = builder.next_result_key();
                    let result_sref = SRef::self_ref(format!("VALUEOF:{}", result_key));

                    // Convert operands to SRefs if they're scalars
                    let op1_sref = match op1 {
                        Value::Scalar(s) => {
                            let key = s.to_string();
                            builder.add_operation(
                                Op::NewEntry(Entry {
                                    key: key.clone(),
                                    value: ScalarOrVec::Scalar(s),
                                }),
                                key.clone(),
                            );
                            SRef::self_ref(format!("VALUEOF:{}", key))
                        }
                        Value::SRef(r) => r,
                        _ => return Err(anyhow!("Invalid operand type")),
                    };

                    let op2_sref = match op2 {
                        Value::Scalar(s) => {
                            let key = s.to_string();
                            builder.add_operation(
                                Op::NewEntry(Entry {
                                    key: key.clone(),
                                    value: ScalarOrVec::Scalar(s),
                                }),
                                key.clone(),
                            );
                            SRef::self_ref(format!("VALUEOF:{}", key))
                        }
                        Value::SRef(r) => r,
                        _ => return Err(anyhow!("Invalid operand type")),
                    };

                    let pod_op =
                        Operation::into_pod_op(op_type, result_sref.clone(), op1_sref, op2_sref);

                    // Create the result entry. We use our result_key which was also used in creating the operation
                    // TODO: we need to name our key the same as the binding we create in case this is top of the computation tree, not named result_key
                    builder.add_operation(
                        Op::NewEntry(Entry {
                            key: result_key.clone(),
                            value: ScalarOrVec::Scalar(result_value),
                        }),
                        result_key.clone(),
                    );

                    // Then add the operation
                    builder.add_operation(pod_op, result_key);

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
        // Setup the environment
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let pod_store = Arc::new(MyPods::default());
        let env = Env::new("test_user".to_string(), shared, pod_store);

        // Create a pod with two scalar values
        let result = eval("[createpod test_pod x [+ 40 2] y 123]", env).await?;

        // Verify we got a PodRef back
        match result {
            Value::PodRef(pod) => {
                dbg!(&pod);
                // Check that the pod contains our entries
                assert_eq!(
                    pod.payload
                        .statements_map
                        .get("VALUEOF:x")
                        .unwrap()
                        .value()
                        .unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(42))
                );
                assert_eq!(
                    pod.payload
                        .statements_map
                        .get("VALUEOF:y")
                        .unwrap()
                        .value()
                        .unwrap(),
                    ScalarOrVec::Scalar(GoldilocksField(123))
                );
                Ok(())
            }
            _ => Err(anyhow!("Expected PodRef, got something else")),
        }
    }
}
