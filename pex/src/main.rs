use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use colored::*;
use eyre::Result;
use pex::repl::{
    display::print_pod_details,
    reedline::{LispCompleter, LispHighlighter, LispValidator},
};
use pex::{Env, MyPods, Value};
use pod2::schnorr::SchnorrSecretKey;
use reedline::{
    default_emacs_keybindings, ColumnarMenu, DefaultPrompt, DefaultPromptSegment, Emacs, KeyCode,
    KeyModifiers, MenuBuilder, Reedline, ReedlineEvent, ReedlineMenu, Signal,
};

#[tokio::main]
async fn main() -> Result<()> {
    let shared = Arc::new(Mutex::new(HashMap::new()));
    let pod_store = Arc::new(Mutex::new(MyPods::default()));
    let env = Env::new(
        "repl_user".to_string(),
        shared,
        pod_store.clone(),
        Some(SchnorrSecretKey { sk: 42 }),
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
                                println!("\n{}", "Created new POD:".green());
                                let store = env.pod_store.lock().unwrap();
                                print_pod_details(&pod, &store);
                                drop(store);
                                env.pod_store.lock().unwrap().add_pod(pod);
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
