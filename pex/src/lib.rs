mod macros;

use std::{
    cmp::Ordering,
    collections::HashMap,
    ops::{Add, BitXor},
    sync::{Arc, Mutex},
    time::Duration,
};

use async_recursion::async_recursion;
use eyre::{eyre, OptionExt, Result};

#[derive(Default)]
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

pub type User = String;

#[derive(Clone, Default)]
pub struct Context {
    user: User,
    pods: Arc<MyPods>,
    shared: Arc<Mutex<HashMap<u64, Value>>>,
}

impl Context {
    pub fn new(user: User, shared: Arc<Mutex<HashMap<u64, Value>>>, pods: Arc<MyPods>) -> Context {
        Context { user, shared, pods }
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
    pub fn local(&self, key: &str) -> Option<Value> {
        self.pods.find(key)
    }
}

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

#[derive(Clone, Debug, Eq)]
pub enum Value {
    Bool(bool),
    String(String),
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
                Value::String(b) => a.cmp(&string_to_bool(b)),
                Value::Uint64(b) => a.cmp(&uint64_to_bool(*b)),
            },
            Value::String(a) => match other {
                Value::Bool(b) => string_to_bool(a).cmp(b),
                Value::String(b) => a.cmp(b),
                Value::Uint64(b) => a.parse::<u64>().unwrap().cmp(b),
            },
            Value::Uint64(a) => match other {
                Value::Bool(b) => a.cmp(&bool_to_uint64(*b)),
                Value::String(b) => a.cmp(&b.parse().unwrap()),
                Value::Uint64(b) => a.cmp(b),
            },
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Self::Bool(a) => match other {
                Self::Bool(b) => a.eq(b),
                Self::String(b) => a.eq(&string_to_bool(b)),
                Self::Uint64(b) => a.eq(&uint64_to_bool(*b)),
            },
            Self::String(a) => match other {
                Self::Bool(b) => string_to_bool(a).eq(b),
                Self::String(b) => a.eq(b),
                Self::Uint64(b) => a.eq(&b.to_string()),
            },
            Self::Uint64(a) => match other {
                Self::Bool(b) => a.eq(&bool_to_uint64(*b)),
                Self::String(b) => a.eq(&b.parse().unwrap()),
                Self::Uint64(b) => a.eq(b),
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

fn string_to_bool(s: &str) -> bool {
    s == "true"
}

impl BitXor for Value {
    type Output = Self;

    fn bitxor(self, other: Self) -> Self::Output {
        match self {
            Value::Bool(a) => match other {
                Value::Bool(b) => Value::Bool(a ^ b),
                Value::String(b) => Value::Bool(a ^ string_to_bool(&b)),
                Value::Uint64(b) => Value::Bool(a ^ uint64_to_bool(b)),
            },
            Value::Uint64(a) => match other {
                Value::Bool(b) => Value::Uint64(a ^ bool_to_uint64(b)),
                Value::String(b) => Value::Uint64(a ^ b.parse::<u64>().unwrap()),
                Value::Uint64(b) => Value::Uint64(a ^ b),
            },
            Value::String(_) => todo!(),
        }
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
        return Err(eyre!("must start with ["));
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

pub async fn eval(source: &str, context: Context) -> Result<Value> {
    parse(&mut scan(source))?.eval(context).await
}

#[derive(Debug, PartialEq)]
enum Expr {
    Atom(Id, String),
    List(Id, Vec<Expr>),
}

impl Expr {
    #[async_recursion]
    async fn eval(&self, context: Context) -> Result<Value> {
        match self {
            Expr::List(_, exprs) => match &exprs[0] {
                Expr::Atom(aid, a) => match a.as_str() {
                    "add" => Ok(exprs[1]
                        .eval(context.clone())
                        .await?
                        .add(exprs[2].eval(context.clone()).await?)),
                    "xor" => Ok(exprs[1]
                        .eval(context.clone())
                        .await?
                        .bitxor(exprs[2].eval(context.clone()).await?)),
                    "min" => Ok(exprs[1]
                        .eval(context.clone())
                        .await?
                        .min(exprs[2].eval(context.clone()).await?)),
                    "max" => Ok(exprs[1]
                        .eval(context.clone())
                        .await?
                        .max(exprs[2].eval(context.clone()).await?)),
                    "eq" => Ok(Value::Bool(
                        exprs[1]
                            .eval(context.clone())
                            .await?
                            .eq(&exprs[2].eval(context.clone()).await?),
                    )),
                    "ne" => Ok(Value::Bool(
                        exprs[1]
                            .eval(context.clone())
                            .await?
                            .ne(&exprs[2].eval(context.clone()).await?),
                    )),
                    "gt" => Ok(Value::Bool(
                        exprs[1]
                            .eval(context.clone())
                            .await?
                            .gt(&exprs[2].eval(context.clone()).await?),
                    )),
                    "lt" => Ok(Value::Bool(
                        exprs[1]
                            .eval(context.clone())
                            .await?
                            .lt(&exprs[2].eval(context.clone()).await?),
                    )),
                    "from" => {
                        if let Value::String(user) = exprs[1].eval(context.clone()).await? {
                            if user == context.user {
                                let res = exprs[2].eval(context.clone()).await?;
                                context.set(*aid, res.clone());
                                Ok(res)
                            } else {
                                context.get(*aid).await.ok_or_eyre("missing remote value")
                            }
                        } else {
                            return Err(eyre!("first argument to 'from' must be a user"));
                        }
                    }
                    "to" => todo!(),
                    "pod" => todo!(),
                    "pod?" => {
                        let val = if let Value::String(key) = exprs[1].eval(context.clone()).await?
                        {
                            context.local(&key)
                        } else {
                            None
                        };
                        val.ok_or_eyre("missing pod")
                    }
                    _ => todo!(),
                },
                _ => Err(eyre!("first item must be an atom")),
            },
            Expr::Atom(_, a) => {
                if let Ok(a) = a.parse::<u64>() {
                    Ok(Value::Uint64(a))
                } else {
                    Ok(Value::String(a.clone()))
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
    async fn test_eval() {
        assert_eq!(
            eval("[add 1 [add 1 [max 42 1]]]", Context::default())
                .await
                .unwrap(),
            Value::Uint64(44)
        )
    }
}
