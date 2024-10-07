use std::{
    cmp::Ordering,
    collections::HashMap,
    ops::{Add, BitXor},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_recursion::async_recursion;
use eyre::{OptionExt, Result};

pub type User = String;

#[derive(Debug)]
pub struct Entry {
    pub key: String,
    pub value: Value,
}

#[derive(Debug)]
pub struct Pod {
    pub entries: Vec<Entry>,
}

impl Pod {
    fn get(&self, key: &str) -> Option<Value> {
        self.entries
            .iter()
            .find(|entry| entry.key == key)
            .map(|e| &e.value)
            .cloned()
    }
}

#[derive(Clone, Debug)]
pub enum ValueDesc {
    Bool,
    Uint64,
}

#[derive(Copy, Clone, Debug, Eq)]
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
                Value::Uint64(b) => a.cmp(&uint64_to_bool(*b)),
            },
            Value::Uint64(a) => match other {
                Value::Bool(b) => a.cmp(&bool_to_uint64(*b)),
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
                Self::Bool(b) => a.eq(&bool_to_uint64(*b)),
            },
            Self::Bool(a) => match other {
                Self::Uint64(b) => a.eq(&uint64_to_bool(*b)),
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BinaryOp {
    Gt,
    Lt,
    Eq,
    Ne,
    Add,
    Xor,
    Min,
    Max,
}

impl BinaryOp {
    fn eval(&self, left: &Value, right: &Value) -> Value {
        match self {
            Self::Eq => Value::Bool(left.ne(right)),
            Self::Ne => Value::Bool(left.eq(right)),
            Self::Gt => Value::Bool(left.gt(right)),
            Self::Lt => Value::Bool(left.lt(right)),
            Self::Add => left.add(*right),
            Self::Xor => *left ^ *right,
            Self::Min => *left.min(right),
            Self::Max => *left.max(right),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expression {
    User {
        id: u64,
        name: String,
        expr: Box<Expression>,
    },
    Pod {
        key: String,
    },
    Binary {
        op: BinaryOp,
        left: Box<Expression>,
        right: Box<Expression>,
    },
}

impl Expression {
    #[async_recursion]
    pub async fn eval(&self, context: Context) -> Result<Value> {
        match self {
            Self::Pod { key } => context.local(key).ok_or_eyre("missing local value"),
            Self::Binary { op, left, right } => Ok(op.eval(
                &left.eval(context.clone()).await?,
                &right.eval(context.clone()).await?,
            )),
            Self::User { id, name, expr } => {
                if name == &context.user {
                    let res = expr.eval(context.clone()).await?;
                    context.set(*id, res);
                    Ok(res)
                } else {
                    context.get(*id).await.ok_or_eyre("missing remote value")
                }
            }
        }
    }
}

pub struct MyPods {
    pub pods: Vec<Pod>,
}

impl MyPods {
    pub fn find(&self, key: &str) -> Option<Value> {
        for pod in &self.pods {
            if let Some(value) = pod.get(key) {
                return Some(value);
            }
        }
        None
    }
}

#[derive(Clone)]
pub struct Context {
    user: User,
    pods: Arc<MyPods>,
    shared: Arc<Mutex<HashMap<u64, Value>>>,
}

impl Context {
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
    pub fn local(&self, key: &str) -> Option<Value> {
        self.pods.find(key)
    }
}

pub struct Executor {
    pub script: Expression,
    context: Context,
}

impl Executor {
    pub fn new(
        user: &str,
        script: Expression,
        pods: Arc<MyPods>,
        shared: Arc<Mutex<HashMap<u64, Value>>>,
    ) -> Result<Executor> {
        Ok(Executor {
            script,
            context: Context {
                user: User::from(user),
                pods,
                shared,
            },
        })
    }

    pub async fn exec(&self) -> Result<Value> {
        self.script.eval(self.context.clone()).await
    }
}

enum Token {
    OpenBracket,
    CloseBracket,
    Keyword(String),
    User(String),
    PodKey(String, String),
}

fn lex(source: &str) -> Result<Vec<Token>> {
    todo!()
}

fn parse(tokens: &mut Vec<Token>) -> Result<Expression> {
    let l = tokens.pop().ok_or_eyre("missing [")?;
    while !tokens.is_empty() {
        match tokens.pop().unwrap() {
            Token::OpenBracket => {
                tokens.push(Token::OpenBracket);
                parse(tokens)
            }
            Token::CloseBracket => {}
            Token::Keyword(word) => todo!(),
            Token::User(name) => todo!(),
            Token::PodKey(key_name, val_desc) => todo!(),
        };
    }
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(
            parse(&mut vec![
                Token::OpenBracket,
                Token::Keyword(String::from("add")),
                Token::OpenBracket,
                Token::User(String::from("alice")),
                Token::OpenBracket,
                Token::Keyword(String::from("pod?")),
                Token::PodKey(String::from("x"), String::from("u64")),
                Token::CloseBracket,
                Token::OpenBracket,
                Token::User(String::from("bob")),
                Token::Keyword(String::from("pod?")),
                Token::PodKey(String::from("x"), String::from("u64")),
                Token::CloseBracket,
                Token::CloseBracket,
            ])
            .unwrap(),
            Expression::Binary {
                op: BinaryOp::Add,
                left: Box::new(Expression::User {
                    id: 1,
                    name: User::from("alice"),
                    expr: Box::new(Expression::Pod {
                        key: String::from("x"),
                    }),
                }),
                right: Box::new(Expression::User {
                    id: 2,
                    name: User::from("bob"),
                    expr: Box::new(Expression::Binary {
                        op: BinaryOp::Max,
                        left: Box::new(Expression::Pod {
                            key: String::from("x"),
                        }),
                        right: Box::new(Expression::Pod {
                            key: String::from("y"),
                        }),
                    }),
                }),
            }
        )
    }
}
