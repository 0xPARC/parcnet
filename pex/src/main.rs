use std::sync::{Arc, Mutex};

use colored::*;
use eyre::{eyre, Result};
use pex::{
    repl::{
        display::print_pod_details,
        reedline::{LispCompleter, LispHighlighter, LispValidator},
    },
    store::iroh::IrohStore,
};
use pex::{Env, MyPods, Value};
use pod2::signature::schnorr::SchnorrSecretKey;
use reedline::{
    default_emacs_keybindings, ColumnarMenu, DefaultPrompt, DefaultPromptSegment, Emacs, KeyCode,
    KeyModifiers, MenuBuilder, Reedline, ReedlineEvent, ReedlineMenu, Signal,
};

use rand::Rng;

fn get_username_from_key(sk: &SchnorrSecretKey) -> String {
    let cosmic_prefixes = [
        "stellar",
        "nova",
        "pulsar",
        "quasar",
        "nebula",
        "cosmic",
        "astro",
        "galaxy",
        "comet",
        "photon",
        "quantum",
        "void",
        "solar",
        "lunar",
        "aurora",
        "celestial",
        "eclipse",
        "meteor",
        "starborn",
        "infinity",
    ];

    let cosmic_suffixes = [
        "walker",
        "rider",
        "weaver",
        "dancer",
        "singer",
        "seeker",
        "drifter",
        "hunter",
        "voyager",
        "explorer",
        "jumper",
        "runner",
        "tracer",
        "dreamer",
        "whisperer",
        "guardian",
        "wanderer",
        "sentinel",
        "sage",
        "mystic",
    ];

    // Use the secret key to deterministically choose prefix and suffix
    let prefix_index = sk.sk % cosmic_prefixes.len() as u64;
    let suffix_index = (sk.sk >> 8) % cosmic_suffixes.len() as u64;

    format!(
        "{}_{}",
        cosmic_prefixes[prefix_index as usize], cosmic_suffixes[suffix_index as usize]
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let random_sk = rand::thread_rng().gen::<u64>() % 10000;
    let schnorr_key = SchnorrSecretKey { sk: random_sk };
    let signer = pod2::schnorr::SchnorrSigner::new();
    let public_key = signer.keygen(&schnorr_key);
    let username = get_username_from_key(&schnorr_key);
    let secret_key = iroh::net::key::SecretKey::generate();
    let shared = Arc::new(IrohStore::new(secret_key));
    let task_bound_shared = shared.clone();
    let (sync_tx, sync_rx) = tokio::sync::oneshot::channel();
    let init_task = tokio::task::spawn(async move { task_bound_shared.initialize(sync_tx).await });
    tokio::select! {
        init_result = init_task => {
            if let Err(e) = init_result {
                println!("Error during initialization: {}", e);
                return Err(eyre!("Initialization failed"));
            }
        }
        sync_result = sync_rx => {
            match sync_result {
                Ok(()) => println!("Store successfully reached sync state"),
                Err(err) => {println!("Failed to receive sync signal"); println!("{:?}", err);},
            }
        }
    }

    let pod_store = Arc::new(Mutex::new(MyPods::default()));
    let env = Env::new(
        username.clone(),
        shared.clone(),
        pod_store.clone(),
        Some(schnorr_key),
        None,
    );

    let commands = vec![
        "createpod".into(),
        "define".into(),
        "pod?".into(),
        "list".into(),
        "car".into(),
        "cdr".into(),
        "cons".into(),
        "+".into(),
        "*".into(),
        "max".into(),
        "exit".into(),
        "list-pods".into(),
    ];

    let completer = Box::new(LispCompleter::new(commands.clone()));
    let completion_menu = Box::new(ColumnarMenu::default().with_name("completion_menu"));

    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );

    let edit_mode = Box::new(Emacs::new(keybindings));

    let mut line_editor = Reedline::create()
        .with_highlighter(Box::new(LispHighlighter::new(commands.clone())))
        .with_completer(completer)
        .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
        .with_edit_mode(edit_mode)
        .with_validator(Box::new(LispValidator));

    let prompt = DefaultPrompt::new(
        DefaultPromptSegment::Basic(">".to_string()),
        DefaultPromptSegment::Basic("..".to_string()),
    );

    println!("{}", "PARCNET Lisp REPL".green().bold());
    println!("Welcome, {}!", username.cyan().bold());
    println!(
        "Public key: {}",
        format!("{:?}", public_key.pk).yellow().bold()
    );
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
        match line_editor.read_line(&prompt) {
            Ok(Signal::Success(line)) => {
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
                    _ => match pex::eval(input, env.clone()).await {
                        Ok(result) => match result {
                            Value::PodRef(pod) => {
                                if !input.contains(&username) {
                                    println!("\n{}", "Created new POD:".green());
                                    let store = env.pod_store.lock().unwrap();
                                    print_pod_details(&pod, &store);
                                    drop(store);
                                    env.pod_store.lock().unwrap().add_pod(pod);
                                } else {
                                    println!("\n{}", "Participated in POD creation".green());
                                };
                            }
                            value if input.trim().starts_with("[pod?") => {
                                println!("\n{}", "Matching POD:".green());
                                let store = env.pod_store.lock().unwrap();

                                // Function to extract statement refs
                                let get_statement_refs = |val: &Value| -> Vec<String> {
                                    match val {
                                        Value::SRef(sref) => vec![sref.1.clone()],
                                        Value::List(values) => values
                                            .iter()
                                            .filter_map(|v| {
                                                if let Value::SRef(sref) = v {
                                                    Some(sref.1.clone())
                                                } else {
                                                    None
                                                }
                                            })
                                            .collect(),
                                        _ => vec![],
                                    }
                                };

                                let statement_refs = get_statement_refs(&value);

                                // Find matching pod
                                if let Some(pod) = store.pods.iter().find(|pod| {
                                    statement_refs.iter().any(|ref_str| {
                                        pod.payload
                                            .statements_list
                                            .iter()
                                            .any(|(id, _)| id == ref_str)
                                    })
                                }) {
                                    print_pod_details(pod, &store);
                                }
                            }
                            _ => println!("=> {:?}", result),
                        },
                        Err(e) => println!("{}: {}", "Error".red().bold(), e),
                    },
                }
            }
            Ok(Signal::CtrlC) => {
                println!("CTRL-C");
                continue;
            }
            Ok(Signal::CtrlD) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {}", err);
                break;
            }
        }
    }

    println!("Goodbye!");
    Ok(())
}
