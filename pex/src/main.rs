use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use eyre::{eyre, Result};
use pex::{self, Context, Entry, MyPods, Pod, User, Value};

#[tokio::main]
async fn main() -> Result<()> {
    let script = r#"[add [from alice [pod? x]] [from bob [pod? y]]]"#;
    let shared = Arc::new(Mutex::new(HashMap::new()));

    let alice = tokio::spawn(pex::eval(
        script,
        Context::new(
            User::from("alice"),
            shared.clone(),
            pex::my_pods![{"x" => 22}],
        ),
    ));

    let bob = tokio::spawn(pex::eval(
        script,
        Context::new(
            User::from("bob"),
            shared.clone(),
            pex::my_pods![{"y" => 20}],
        ),
    ));

    match tokio::try_join!(flatten(alice), flatten(bob)) {
        Ok((alice, bob)) => {
            println!("alice: {:?} bob: {:?}", alice, bob);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

async fn flatten<T>(handle: tokio::task::JoinHandle<Result<T>>) -> Result<T> {
    match handle.await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(err)) => Err(err),
        Err(err) => Err(eyre!("handle error: {}", err)),
    }
}
