use executor::*;
use eyre::Result;

pub fn main() -> Result<()> {
    let script = Script {
        inputs: vec![
            Input {
                name: String::from("proof"),
                item: InputItem::Request(PodRequest {
                    from: String::from("bob"),
                    entries: vec![EntryRequest {
                        key: String::from("proof"),
                        value_desc: ValueDesc::Uint64,
                    }],
                }),
            },
            Input {
                name: String::from("ct"),
                item: InputItem::Request(PodRequest {
                    from: String::from("bob"),
                    entries: vec![EntryRequest {
                        key: String::from("ct"),
                        value_desc: ValueDesc::Uint64,
                    }],
                }),
            },
        ],
        expressions: vec![NamedExpression {
            name: String::from("dec"),
            to: vec![User::from("alice"), User::from("bob")],
            expr: Expression::Binary {
                left: Box::new(Expression::Reference {
                    pod: String::from("proof"),
                    key: String::from("proof"),
                }),
                op: BinaryOp::Xor,
                right: Box::new(Expression::Reference {
                    pod: String::from("ct"),
                    key: String::from("ct"),
                }),
            },
        }],
    };

    let pods = MyPods {
        pods: vec![
            Pod {
                entries: vec![Entry {
                    key: String::from("height"),
                    value: Value::Uint64(42),
                }],
            },
            Pod {
                entries: vec![Entry {
                    key: String::from("age"),
                    value: Value::Uint64(18),
                }],
            },
            Pod {
                entries: vec![Entry {
                    key: String::from("ct"),
                    value: Value::Uint64(51),
                }],
            },
            Pod {
                entries: vec![Entry {
                    key: String::from("proof"),
                    value: Value::Uint64(25),
                }],
            },
        ],
    };

    Executor::new("bob", &script, &pods)?
        .exec()?
        .iter()
        .for_each(|pod| println!("output pod: {:?}", pod));
    Ok(())
}
