use executor::*;
use eyre::Result;

pub fn main() -> Result<()> {
    let script = Script {
        inputs: vec![
            Input {
                name: String::from("vkey"),
                item: InputItem::Request(PodRequest {
                    from: String::from("alice"),
                    entries: vec![EntryRequest {
                        key: String::from("vkey"),
                        value_desc: ValueDesc::Uint64,
                    }],
                }),
            },
            Input {
                name: String::from("message"),
                item: InputItem::Request(PodRequest {
                    from: String::from("alice"),
                    entries: vec![EntryRequest {
                        key: String::from("message"),
                        value_desc: ValueDesc::Uint64,
                    }],
                }),
            },
        ],
        expressions: vec![NamedExpression {
            name: String::from("ct"),
            to: vec![User::from("alice"), User::from("bob")],
            expr: Expression::Binary {
                left: Box::new(Expression::Reference {
                    pod: String::from("vkey"),
                    key: String::from("vkey"),
                }),
                op: BinaryOp::Xor,
                right: Box::new(Expression::Reference {
                    pod: String::from("message"),
                    key: String::from("message"),
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
                    key: String::from("message"),
                    value: Value::Uint64(42),
                }],
            },
            Pod {
                entries: vec![Entry {
                    key: String::from("vkey"),
                    value: Value::Uint64(25),
                }],
            },
        ],
    };

    Executor::new("alice", &script, &pods)?
        .exec()?
        .iter()
        .for_each(|pod| println!("output pod: {:?}", pod));
    Ok(())
}
