use std::collections::HashMap;

use colored::Colorize;
use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};
use pod2::pod::{statement::AnchoredKey, Statement, POD};

use crate::{MyPods, PodBuilder};

pub fn get_pod_info(pod: &POD) -> HashMap<String, Vec<String>> {
    let mut origin_statements: HashMap<String, Vec<String>> = HashMap::new();

    for (statement_id, statement) in pod.payload.statements_map.iter() {
        let refs = match statement {
            Statement::SumOf(_, op1, op2)
            | Statement::ProductOf(_, op1, op2)
            | Statement::MaxOf(_, op1, op2)
            | Statement::Equal(op1, op2) => vec![op1, op2]
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

struct StatementFormatter<'a> {
    indent: &'a str,
    statement_id: &'a str,
}

impl<'a> StatementFormatter<'a> {
    fn new(indent: &'a str, statement_id: &'a str) -> Self {
        Self {
            indent,
            statement_id,
        }
    }

    fn prefix(&self) -> String {
        format!(
            "{}{} {}",
            self.indent,
            "└─".bright_black(),
            self.statement_id.bright_black()
        )
    }

    fn binary_op(&self, op1: &AnchoredKey, operator: &str, op2: &AnchoredKey) -> String {
        format!(
            "{} {} {} {}",
            self.prefix(),
            format_ref(op1).yellow(),
            operator,
            format_ref(op2).yellow()
        )
    }

    fn ternary_op(
        &self,
        result: &AnchoredKey,
        op1: &AnchoredKey,
        operator: &str,
        op2: &AnchoredKey,
    ) -> String {
        format!(
            "{} {} {} {} → {}",
            self.prefix(),
            format_ref(op1).yellow(),
            operator,
            format_ref(op2).yellow(),
            format_ref(result).bright_green()
        )
    }

    fn format(&self, statement: &Statement) -> String {
        match statement {
            Statement::SumOf(result, op1, op2) => self.ternary_op(result, op1, "+", op2),

            Statement::ProductOf(result, op1, op2) => self.ternary_op(result, op1, "×", op2),

            Statement::MaxOf(result, op1, op2) => format!(
                "{} max({}, {}) → {}",
                self.prefix(),
                format_ref(op1).yellow(),
                format_ref(op2).yellow(),
                format_ref(result).bright_green()
            ),

            Statement::Equal(op1, op2) => self.binary_op(op1, "=", op2),
            Statement::Gt(op1, op2) => self.binary_op(op1, ">", op2),
            Statement::Lt(op1, op2) => self.binary_op(op1, "<", op2),
            Statement::NotEqual(op1, op2) => self.binary_op(op1, "!=", op2),

            Statement::ValueOf(key, value) => format!(
                "{} {} = {}",
                self.prefix(),
                format_ref(key).blue(),
                format!("{:?}", value).bright_blue()
            ),

            _ => format!("{} Other Operation", self.prefix()),
        }
    }
}

pub fn print_statement(statement_id: &str, statement: &Statement, indent: &str) {
    let formatter = StatementFormatter::new(indent, statement_id);
    println!("{}", formatter.format(statement));
}
pub fn print_section_header(title: &str, gadget_id: Option<&str>) {
    println!(
        "\n{} {}",
        title.magenta().bold(),
        gadget_id.map_or("".to_string(), |id| format!("({})", id.bright_cyan()))
    );
    println!("{}", "─".repeat(40).magenta());
}

pub fn print_pod_details(pod: &POD, pod_store: &MyPods) {
    let origin_refs = get_pod_info(pod);

    if !origin_refs.is_empty() {
        print_section_header("Matched PODs", None);

        for (origin, _) in origin_refs.iter() {
            let matching_pods: Vec<_> = pod_store
                .pods
                .iter()
                .filter(|p| PodBuilder::pod_id(p) == *origin)
                .collect();

            for matched_pod in matching_pods {
                println!(
                    "  {} {} ({})",
                    "POD".magenta(),
                    origin.yellow().bold(),
                    matched_pod.proof_type.to_string().bright_cyan()
                );

                for (stmt_id, stmt) in matched_pod.payload.statements_map.iter() {
                    print_statement(stmt_id, stmt, "    ");
                }
                println!();
            }
        }

        print_section_header("Dependencies", None);
        for (origin, statements) in origin_refs.iter() {
            let gadget_id = pod_store
                .pods
                .iter()
                .find(|p| PodBuilder::pod_id(p) == *origin)
                .map(|p| p.proof_type.to_string())
                .unwrap_or_else(|| "unknown".to_string());

            println!(
                "  {} {} ({})",
                "From".magenta(),
                origin.yellow().bold(),
                gadget_id.bright_cyan()
            );

            let referenced_values: Vec<String> = pod_store
                .pods
                .iter()
                .filter(|p| PodBuilder::pod_id(p) == *origin)
                .flat_map(|p| {
                    statements
                        .iter()
                        .filter_map(|s| {
                            let key = s.split(": ").nth(1)?;
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
                                .map(|(_stmt_id, stmt)| {
                                    format!(
                                        "    └─ in {} → {}",
                                        s.blue(),
                                        stmt.to_string().bright_blue()
                                    )
                                })
                        })
                        .collect::<Vec<_>>()
                })
                .collect();

            if referenced_values.is_empty() {
                for s in statements {
                    println!("    └─ {} (value not found)", s.blue());
                }
            } else {
                for value in referenced_values {
                    println!("{}", value);
                }
            }
        }
    }

    print_section_header("POD Statements", Some(&pod.proof_type.to_string()));
    for (statement_id, statement) in pod
        .payload
        .statements_map
        .iter()
        .filter(|(_, p)| p.code() != GoldilocksField::ZERO)
    {
        print_statement(statement_id, statement, "  ");
    }
    println!();
}
