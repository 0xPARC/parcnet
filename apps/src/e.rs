use std::collections::HashMap;

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
pub enum Value {
    Bool(bool),
    Uint64(u64),
}

#[derive(Clone, Debug)]
pub enum ValueDesc {
    Bool,
    Uint64,
}

impl Value {
    fn gt(&self, other: &Value) -> bool {
        match self {
            Self::Uint64(a) => {
                if let Self::Uint64(b) = other {
                    a > b
                } else {
                    false
                }
            }
            _ => false,
        }
    }
    fn eq(&self, other: &Value) -> bool {
        match self {
            Self::Uint64(a) => {
                if let Self::Uint64(b) = other {
                    a == b
                } else {
                    false
                }
            }
            _ => false,
        }
    }
    fn xor(&self, other: &Value) -> u64 {
        match self {
            Self::Uint64(a) => {
                if let Self::Uint64(b) = other {
                    a ^ b
                } else {
                    0
                }
            }
            Self::Bool(a) => {
                if let Self::Bool(b) = other {
                    (a ^ b) as u64
                } else {
                    0
                }
            }
            _ => 0,
        }
    }
}

pub enum BinaryOp {
    GT,
    LT,
    EQ,
    XOR,
}

impl BinaryOp {
    fn eval(&self, left: &Value, right: &Value) -> Value {
        match self {
            Self::EQ => Value::Bool(left.eq(right)),
            Self::GT => Value::Bool(left.gt(right)),
            Self::XOR => Value::Uint64(left.xor(right)),
            _ => todo!(),
        }
    }
}

pub enum Expression {
    Value(Value),
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
    fn eval(&self, pods: &HashMap<String, &Pod>) -> Result<Value> {
        match self {
            Self::Reference { pod, key } => {
                let pod = pods.get(pod).ok_or_eyre("missing pod")?;
                pod.get(key).ok_or_eyre("missing entry").cloned()
            }
            Self::Value(v) => Ok(v.clone()),
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
    fn find(&self, request: &PodRequest) -> Option<&Pod> {
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
    user: User,
    script: &'a Script,
    pods: HashMap<String, &'a Pod>,
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
