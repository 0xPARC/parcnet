use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use colored::*;
use eyre::Result;
use nu_ansi_term::{Color, Style as AnsiStyle};
use pex::{Env, MyPods, Value};
use pod2::pod::{AnchoredKey, Statement, POD};
use reedline::{
    default_emacs_keybindings, ColumnarMenu, Completer, DefaultPrompt, DefaultPromptSegment, Emacs,
    Highlighter, KeyCode, KeyModifiers, MenuBuilder, Reedline, ReedlineEvent, ReedlineMenu, Signal,
    Span, StyledText, Suggestion, ValidationResult, Validator,
};

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

struct LispHighlighter {
    commands: Vec<String>,
    matching_bracket_style: AnsiStyle,
    keyword_style: AnsiStyle,
    normal_bracket_style: AnsiStyle,
}

impl LispHighlighter {
    fn new(commands: Vec<String>) -> Self {
        Self {
            commands,
            matching_bracket_style: AnsiStyle::new().bold().fg(Color::Green),
            keyword_style: AnsiStyle::new().fg(Color::Purple),
            normal_bracket_style: AnsiStyle::new().fg(Color::Cyan),
        }
    }

    fn find_matching_bracket(&self, line: &str, cursor: usize) -> Option<usize> {
        let chars: Vec<char> = line.chars().collect();

        // If cursor is not on a bracket, return None
        if cursor >= chars.len() || (chars[cursor] != '[' && chars[cursor] != ']') {
            return None;
        }

        let (is_opening, _matching_char, _direction, limit) = if chars[cursor] == '[' {
            (true, ']', 1, chars.len())
        } else {
            (false, '[', -1, 0)
        };

        let mut count = 1;
        let mut pos = cursor;

        while count > 0 {
            pos = if is_opening {
                pos + 1
            } else {
                pos.checked_sub(1)?
            };

            if (is_opening && pos >= limit) || (!is_opening && pos <= limit) {
                return None;
            }

            match chars[pos] {
                '[' if !is_opening => count -= 1,
                ']' if is_opening => count -= 1,
                '[' if is_opening => count += 1,
                ']' if !is_opening => count += 1,
                _ => {}
            }
        }

        Some(pos)
    }
}
impl Highlighter for LispHighlighter {
    fn highlight(&self, line: &str, cursor: usize) -> StyledText {
        let mut styled = StyledText::new();
        let mut in_word = false;
        let mut word_start = 0;

        // Find matching bracket if cursor is on a bracket
        let matching_pos = self.find_matching_bracket(line, cursor);

        for (i, c) in line.chars().enumerate() {
            match c {
                '[' | ']' => {
                    if in_word {
                        let word = &line[word_start..i];
                        if self.commands.contains(&word.to_string()) {
                            styled.push((self.keyword_style, word.to_string()));
                        } else {
                            styled.push((AnsiStyle::new(), word.to_string()));
                        }
                        in_word = false;
                    }

                    // Use matching style if this is either the cursor position or its matching bracket
                    if Some(i) == matching_pos || i == cursor {
                        styled.push((self.matching_bracket_style, line[i..i + 1].to_string()));
                    } else {
                        styled.push((self.normal_bracket_style, line[i..i + 1].to_string()));
                    }
                }
                ' ' | '\t' | '\n' => {
                    if in_word {
                        let word = &line[word_start..i];
                        if self.commands.contains(&word.to_string()) {
                            styled.push((self.keyword_style, word.to_string()));
                        } else {
                            styled.push((AnsiStyle::new(), word.to_string()));
                        }
                        in_word = false;
                    }
                    styled.push((AnsiStyle::new(), line[i..i + 1].to_string()));
                }
                _ => {
                    if !in_word {
                        word_start = i;
                        in_word = true;
                    }
                }
            }
        }

        // Handle the last word if exists
        if in_word {
            let word = &line[word_start..];
            if self.commands.contains(&word.to_string()) {
                styled.push((self.keyword_style, word.to_string()));
            } else {
                styled.push((AnsiStyle::new(), word.to_string()));
            }
        }

        styled
    }
}
struct LispValidator;

impl Validator for LispValidator {
    fn validate(&self, line: &str) -> ValidationResult {
        let mut balance = 0;
        for c in line.chars() {
            match c {
                '[' => balance += 1,
                ']' => balance -= 1,
                _ => (),
            }
        }

        if balance > 0 {
            ValidationResult::Incomplete
        } else {
            ValidationResult::Complete
        }
    }
}

struct LispCompleter {
    commands: Vec<String>,
}

impl LispCompleter {
    fn new(commands: Vec<String>) -> Self {
        Self { commands }
    }

    fn get_word_at_cursor(&self, line: &str, pos: usize) -> (usize, String) {
        let mut start = pos;
        while start > 0 && !line[..start].ends_with(['[', ' ', '\t', '\n']) {
            start -= 1;
        }
        (start, line[start..pos].trim_start().to_string())
    }
}

impl Completer for LispCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let (start, current_word) = self.get_word_at_cursor(line, pos);
        if current_word.is_empty() {
            return vec![];
        }

        self.commands
            .iter()
            .filter(|cmd| cmd.starts_with(&current_word))
            .map(|cmd| Suggestion {
                value: cmd.clone(),
                description: None, // We could add descriptions for commands here
                extra: None,
                span: Span::new(start, pos),
                style: None,
                append_whitespace: true,
            })
            .collect()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize environment
    let shared = Arc::new(Mutex::new(HashMap::new()));
    let pod_store = Arc::new(Mutex::new(MyPods::default()));
    let env = Env::new("repl_user".to_string(), shared, pod_store.clone());

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

    // Set up keybindings
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

    // Create line editor with both highlighting and completion
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
