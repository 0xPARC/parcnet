mod macros;

use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt::format,
    ops::Add,
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
    StatementRef(StatementRef<'static, 'static>),
}

#[derive(Clone, Debug)]
pub enum Operation {
    Sum(Value, Value),
    Product(Value, Value),
    Max(Value, Value),
}

impl Operation {
    fn eval(&self) -> GoldilocksField {
        match self {
            Operation::Sum(Value::Scalar(a), Value::Scalar(b)) => *a + *b,
            Operation::Product(Value::Scalar(a), Value::Scalar(b)) => *a * *b,
            Operation::Max(Value::Scalar(a), Value::Scalar(b)) => {
                if a.to_canonical_u64() > b.to_canonical_u64() {
                    *a
                } else {
                    *b
                }
            }
            _ => unreachable!("Should only eval scalar values"),
        }
    }
    fn into_pod_op(
        &self,
        result_ref: StatementRef<'static, 'static>,
        op1: StatementRef<'static, 'static>,
        op2: StatementRef<'static, 'static>,
    ) -> Op<StatementRef> {
        match self {
            Operation::Sum(..) => Op::SumOf(result_ref, op1, op2),
            Operation::Product(..) => Op::ProductOf(result_ref, op1, op2),
            Operation::Max(..) => Op::MaxOf(result_ref, op1, op2),
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

    pub fn add_operation_with_result(
        &mut self,
        operation: Op<StatementRef<'static, 'static>>,
        result_value: GoldilocksField,
    ) -> StatementRef<'static, 'static> {
        let result_key = self.next_result_key();
        self.add_operation(
            Op::NewEntry(Entry {
                key: result_key.clone(),
                value: ScalarOrVec::Scalar(result_value),
            }),
            result_key.clone(),
        );

        self.add_operation(operation, result_key.clone());
        StatementRef(
            "_SELF",
            Box::leak(
                format!("VALUEOF:{}", result_key)
                    .to_owned()
                    .into_boxed_str(),
            ),
        )
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
                    Expr::Atom(_, op) => match op.as_str() {
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
                            pod_env.current_builder = Some(Arc::new(Mutex::new(PodBuilder::new())));
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
                        _ => todo!(),
                    },
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            parse(&mut scan("[add [add 20 20] [add 1 [1]]]")).unwrap(),
            Expr::List(
                0,
                vec![
                    Expr::Atom(1, String::from("add")),
                    Expr::List(
                        2,
                        vec![
                            Expr::Atom(3, String::from("add")),
                            Expr::Atom(4, String::from("20")),
                            Expr::Atom(5, String::from("20")),
                        ]
                    ),
                    Expr::List(
                        7,
                        vec![
                            Expr::Atom(8, String::from("add")),
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
        let result = eval("[createpod test_pod x 42 y 123]", env).await?;

        // Verify we got a PodRef back
        match result {
            Value::PodRef(pod) => {
                dbg!("{:?}", pod.payload.statements_map.clone());
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
