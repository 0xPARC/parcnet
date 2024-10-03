use std::{
    cmp::Ordering,
    collections::HashMap,
    ops::{Add, BitXor},
};

use eyre::{eyre, OptionExt, Result};

pub type User = String;

#[derive(Debug)]
pub struct Entry {
    pub key: String,
    pub value: Value,
}

#[derive(Debug)]
pub struct EntryRequest {
    pub key: String,
    pub value_desc: ValueDesc,
}

impl EntryRequest {
    fn matches(&self, entry: &Entry) -> bool {
        if self.key != entry.key {
            false
        } else {
            match self.value_desc {
                ValueDesc::Bool => matches!(entry.value, Value::Bool(_)),
                ValueDesc::Uint64 => matches!(entry.value, Value::Uint64(_)),
            }
        }
    }
}

#[derive(Debug)]
pub struct Pod {
    pub entries: Vec<Entry>,
}

impl Pod {
    fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|entry| entry.key == key)
            .map(|e| &e.value)
    }
}

#[derive(Debug)]
pub struct PodRequest {
    pub entries: Vec<EntryRequest>,
    pub from: User,
}

#[derive(Debug)]
pub enum InputItem {
    Data(Pod),
    Request(PodRequest),
}

pub struct Input {
    pub name: String,
    pub item: InputItem,
}

#[derive(Clone, Debug)]
pub enum ValueDesc {
    Bool,
    Uint64,
}

#[derive(Clone, Debug, Eq)]
pub enum Value {
    Bool(bool),
    Uint64(u64),
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> Ordering {
        match self {
            Value::Bool(a) => match other {
                Value::Bool(b) => a.cmp(b),
                Value::Uint64(b) => a.cmp(&(*b == 1)),
            },
            Value::Uint64(a) => match other {
                Value::Bool(b) => {
                    if *b {
                        a.cmp(&1)
                    } else {
                        a.cmp(&0)
                    }
                }
                Value::Uint64(b) => a.cmp(b),
            },
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Self::Uint64(a) => match other {
                Self::Uint64(b) => a.eq(b),
                Self::Bool(b) => {
                    if *b {
                        a.eq(&1)
                    } else {
                        a.eq(&0)
                    }
                }
            },
            Self::Bool(a) => match other {
                Self::Uint64(b) => a.eq(&(*b != 0)),
                Self::Bool(b) => a.eq(b),
            },
        }
    }
}

impl Add for Value {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        match self {
            Value::Uint64(a) => match other {
                Value::Uint64(b) => Value::Uint64(a + b),
                _ => todo!(),
            },
            _ => todo!(),
        }
    }
}

fn uint64_to_bool(i: u64) -> bool {
    i == 0
}

fn bool_to_uint64(b: bool) -> u64 {
    if b {
        1
    } else {
        0
    }
}

impl BitXor for Value {
    type Output = Self;

    fn bitxor(self, other: Self) -> Self::Output {
        match self {
            Value::Bool(a) => match other {
                Value::Bool(b) => Value::Bool(a ^ b),
                Value::Uint64(b) => Value::Bool(a ^ uint64_to_bool(b)),
            },
            Value::Uint64(a) => match other {
                Value::Bool(b) => Value::Uint64(a ^ bool_to_uint64(b)),
                Value::Uint64(b) => Value::Uint64(a ^ b),
            },
        }
    }
}

pub enum BinaryOp {
    Gt,
    Lt,
    Eq,
    Ne,
    Add,
    Xor,
}

impl BinaryOp {
    fn eval(&self, left: &Value, right: &Value) -> Value {
        match self {
            Self::Eq => Value::Bool(left.ne(right)),
            Self::Ne => Value::Bool(left.eq(right)),
            Self::Gt => Value::Bool(left.gt(right)),
            Self::Lt => Value::Bool(left.lt(right)),
            Self::Add => left.clone().add(right.clone()),
            Self::Xor => left.clone() ^ right.clone(),
        }
    }
}

pub enum Expression {
    Reference {
        pod: String,
        key: String,
    },
    Binary {
        left: Box<Expression>,
        op: BinaryOp,
        right: Box<Expression>,
    },
}

impl Expression {
    pub fn eval(&self, pods: &HashMap<String, &Pod>) -> Result<Value> {
        match self {
            Self::Reference { pod, key } => pods
                .get(pod)
                .ok_or_eyre("missing pod")?
                .get(key)
                .ok_or_eyre("missing entry")
                .cloned(),
            Self::Binary { left, op, right } => Ok(op.eval(&left.eval(pods)?, &right.eval(pods)?)),
        }
    }
}

pub struct NamedExpression {
    pub name: String,
    pub expr: Expression,
    pub to: Vec<User>,
}

pub struct Script {
    pub inputs: Vec<Input>,
    pub expressions: Vec<NamedExpression>,
}

pub struct MyPods {
    pub pods: Vec<Pod>,
}

impl MyPods {
    pub fn find(&self, request: &PodRequest) -> Option<&Pod> {
        self.pods.iter().find(|pod| {
            request.entries.iter().all(|requested_entry| {
                pod.entries
                    .iter()
                    .any(|pod_entry| requested_entry.matches(pod_entry))
            })
        })
    }
}

pub struct Executor<'a> {
    pub user: User,
    pub script: &'a Script,
    pub pods: HashMap<String, &'a Pod>,
}

impl<'a> Executor<'a> {
    pub fn new(user: &str, script: &'a Script, pods: &'a MyPods) -> Result<Executor<'a>> {
        Ok(Executor {
            user: String::from(user),
            script,
            pods: script
                .inputs
                .iter()
                .filter(|input| match &input.item {
                    InputItem::Data(_) => true,
                    InputItem::Request(req) => req.from == user,
                })
                .map(|input| match &input.item {
                    InputItem::Data(pod) => Ok((input.name.clone(), pod)),
                    InputItem::Request(req) => match pods.find(req) {
                        Some(pod) => Ok((input.name.clone(), pod)),
                        None => Err(eyre!("unable to find pod")),
                    },
                })
                .collect::<Result<HashMap<String, &Pod>>>()?,
        })
    }

    pub fn exec(&self) -> Result<Vec<Pod>> {
        Ok(self
            .script
            .expressions
            .iter()
            .filter(|expr| expr.to.contains(&self.user))
            .map(|expr| expr.expr.eval(&self.pods).map(|v| (expr.name.clone(), v)))
            .collect::<Result<HashMap<String, Value>>>()?
            .into_iter()
            .map(|(k, v)| Pod {
                entries: vec![Entry { key: k, value: v }],
            })
            .collect())
    }
}
