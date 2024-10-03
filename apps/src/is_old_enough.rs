use executor::*;
use eyre::Result;

pub fn main() -> Result<()> {
    let script = Script {
        inputs: vec![
            Input {
                name: String::from("age"),
                item: InputItem::Request(PodRequest {
                    from: String::from("alice"),
                    entries: vec![EntryRequest {
                        key: String::from("age"),
                        value_desc: ValueDesc::Uint64,
                    }],
                }),
            },
            Input {
                name: String::from("OLD_ENOUGH_POD"),
                item: InputItem::Data(Pod {
                    entries: vec![Entry {
                        key: String::from("age"),
                        value: Value::Uint64(18),
                    }],
                }),
            },
        ],
        expressions: vec![NamedExpression {
            name: String::from("isOldEnough"),
            to: vec![User::from("alice")],
            expr: Expression::Binary {
                left: Box::new(Expression::Reference {
                    pod: String::from("age"),
                    key: String::from("age"),
                }),
                op: BinaryOp::Gt,
                right: Box::new(Expression::Reference {
                    pod: String::from("OLD_ENOUGH_POD"),
                    key: String::from("age"),
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
                    value: Value::Uint64(21),
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
