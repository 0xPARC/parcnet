use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use executor::{self, BinaryOp, Entry, Executor, Expression, MyPods, Pod, User, Value};
use eyre::{eyre, Result};

#[tokio::main]
async fn main() -> Result<()> {
    /*
        [add
            [@alice [pod? x:u64]]
            [@bob
                [max
                    [pod? x:u64]
                    [pod? y:u64]]]]
    */
    let script = Expression::Binary {
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
    };

    let shared = Arc::new(Mutex::new(HashMap::new()));

    let alice = tokio::spawn(run(
        "alice",
        script.clone(),
        shared.clone(),
        MyPods {
            pods: vec![Pod {
                entries: vec![Entry {
                    key: String::from("x"),
                    value: Value::Uint64(40),
                }],
            }],
        },
    ));
    let bob = tokio::spawn(run(
        "bob",
        script.clone(),
        shared.clone(),
        MyPods {
            pods: vec![Pod {
                entries: vec![
                    Entry {
                        key: String::from("x"),
                        value: Value::Uint64(40),
                    },
                    Entry {
                        key: String::from("y"),
                        value: Value::Uint64(50),
                    },
                ],
            }],
        },
    ));

    match tokio::try_join!(flatten(alice), flatten(bob)) {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

async fn run(
    user: &str,
    script: Expression,
    shared: Arc<Mutex<HashMap<u64, Value>>>,
    pods: MyPods,
) -> Result<()> {
    Executor::new(user, script, Arc::new(pods), shared)?
        .exec()
        .await
        .inspect(|val| println!("output: {:?}", val))?;
    Ok(())
}

async fn flatten<T>(handle: tokio::task::JoinHandle<Result<T>>) -> Result<T> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err),
        Err(err) => Err(eyre!("handle error: {}", err)),
    }
}
