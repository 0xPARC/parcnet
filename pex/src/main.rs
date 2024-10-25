use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use colored::*;
use eyre::Result;
use pex::{Env, MyPods, Value};
use pod2::pod::{AnchoredKey, Statement, POD};

use rustyline::{error::ReadlineError, DefaultEditor};

fn get_pod_info(pod: &POD) -> HashMap<String, Vec<String>> {
    let mut origin_statements: HashMap<String, Vec<String>> = HashMap::new();

    for (statement_id, statement) in pod.payload.statements_map.iter() {
        let refs = match statement {
            Statement::SumOf(_, op1, op2)
            | Statement::ProductOf(_, op1, op2)
            | Statement::MaxOf(_, op1, op2)
            | Statement::Equal(op1, op2) => vec![op1, op2] // Added Equal here
                .into_iter()
                .filter(|r| !r.0.is_self())
                .map(|r| (statement_id.clone(), r))
                .collect::<Vec<_>>(),
            Statement::ValueOf(key, _) => {
                if !key.0.is_self() {
                    vec![(statement_id.clone(), key)]
                } else {
                    vec![]
                }
            }
            _ => vec![],
        };

        for (stmt_id, r) in refs {
            origin_statements
                .entry(r.0.origin_name.to_string())
                .or_default()
                .push(format!("{}: {}", stmt_id, r.1));
        }
    }

    origin_statements
}

fn format_ref(reference: &AnchoredKey) -> String {
    if reference.0.is_self() {
        reference.1.to_string()
    } else {
        format!("{}:{}", reference.0.origin_name, reference.1)
    }
}

fn print_pod_details(pod: &POD, pod_store: &MyPods) {
    println!("Statements:");

    // Print dependencies first if they exist
    let origin_refs = get_pod_info(pod);
    if !origin_refs.is_empty() {
        println!("\n{}", "Dependencies:".magenta().bold());
        for (origin, statements) in origin_refs.iter() {
            println!("  {} {}:", "From pod".magenta(), origin.yellow());
            // Try to find the referenced pod in the store
            let referenced_values: Vec<String> = pod_store
                .pods
                .iter()
                .filter(|p| {
                    let id = pex::PodBuilder::pod_id(p);
                    id == *origin
                })
                .flat_map(|p| {
                    statements
                        .iter()
                        .filter_map(|s| {
                            let key = s.split(": ").nth(1)?;
                            // Look for ValueOf statements that match our key
                            p.payload
                                .statements_map
                                .iter()
                                .find(|(_, stmt)| {
                                    if let Statement::ValueOf(k, _) = stmt {
                                        k.1 == key
                                    } else {
                                        false
                                    }
                                })
                                .map(|(_stmt_id, stmt)| format!("    in {} = {:?}", s, stmt))
                        })
                        .collect::<Vec<_>>()
                })
                .collect();

            if referenced_values.is_empty() {
                for s in statements {
                    println!("    {} (value not found in store)", s);
                }
            } else {
                for value in referenced_values {
                    println!("{}", value);
                }
            }
        }
        println!();
    }

    // Print statements
    for (statement_id, statement) in pod.payload.statements_map.iter() {
        match statement {
            Statement::SumOf(result, op1, op2) => {
                println!(
                    "{}: {} {} + {} -> {}",
                    statement_id,
                    "SumOf Statement:".red(),
                    format_ref(op1).yellow(),
                    format_ref(op2).yellow(),
                    format_ref(result).bright_green()
                );
            }
            Statement::ProductOf(result, op1, op2) => {
                println!(
                    "{}: {} {} * {} -> {}",
                    statement_id,
                    "ProductOf Statement:".red(),
                    format_ref(op1).yellow(),
                    format_ref(op2).yellow(),
                    format_ref(result).bright_green()
                );
            }
            Statement::MaxOf(result, op1, op2) => {
                println!(
                    "{}: {} max({}, {}) -> {}",
                    statement_id,
                    "MaxOf Statement:".red(),
                    format_ref(op1).yellow(),
                    format_ref(op2).yellow(),
                    format_ref(result).bright_green()
                );
            }
            Statement::Equal(op1, op2) => {
                println!(
                    "{}: {} {} = {}",
                    statement_id,
                    "Equal Statement:".red(),
                    format_ref(op1).yellow(),
                    format_ref(op2).yellow(),
                );
            }
            Statement::ValueOf(key, value) => {
                println!(
                    "{}: {} = {}",
                    statement_id,
                    format_ref(key).blue(),
                    format!("{:?}", value).bright_blue()
                );
            }
            _ => println!("{}: Other Operation", statement_id),
        }
    }
    println!();
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize environment
    let shared = Arc::new(Mutex::new(HashMap::new()));
    let pod_store = Arc::new(Mutex::new(MyPods::default()));
    let env = Env::new("repl_user".to_string(), shared, pod_store.clone());

    // Initialize rustyline editor
    let mut rl = DefaultEditor::new()?;
    if rl.load_history("history.txt").is_err() {
        println!("No previous history.");
    }

    println!("{}", "PARCNET Lisp REPL".green().bold());
    println!("Type 'exit' to quit");
    println!("Commands:");
    println!("  exit          - Exit the REPL");
    println!("  list-pods     - List all stored PODs");
    println!("\nExamples:");
    println!("  [+ 1 2]");
    println!("  [createpod test x 42 y [+ 2 10]]");
    println!("  [createpod test2 z [pod? x]]");
    println!("  [list 1 2 3]");

    loop {
        let readline = rl.readline("> ");
        match readline {
            Ok(line) => {
                let input = line.trim();
                match input {
                    "exit" => break,
                    "list-pods" => {
                        let store = env.pod_store.lock().unwrap();
                        println!("\nStored PODs:");
                        for (i, pod) in store.pods.iter().enumerate() {
                            println!("POD #{}", i + 1);
                            print_pod_details(pod, &store);
                        }
                        continue;
                    }
                    "" => continue,
                    _ => {}
                }

                let _ = rl.add_history_entry(input);

                match pex::eval(input, env.clone()).await {
                    Ok(result) => {
                        match result {
                            Value::PodRef(pod) => {
                                println!("\n{}", "Created new POD:".green());
                                let store = env.pod_store.lock().unwrap();
                                print_pod_details(&pod, &store);
                                drop(store);

                                // Store the pod
                                env.pod_store.lock().unwrap().add_pod(pod);
                            }
                            _ => println!("=> {:?}", result),
                        }
                    }
                    Err(e) => println!("{}: {}", "Error".red().bold(), e),
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }

    rl.save_history("history.txt")?;
    println!("Goodbye!");
    Ok(())
}
