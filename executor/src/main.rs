use executor::{
    self, BinaryOp, Entry, EntryRequest, Executor, Expression, Input, InputItem, MyPods,
    NamedExpression, Pod, PodRequest, Script, User, Value, ValueDesc,
};
use eyre::Result;

fn main() -> Result<()> {
    let script = Script {
        inputs: vec![
            Input {
                name: String::from("a"),
                item: InputItem::Request(PodRequest {
                    from: String::from("alice"),
                    entries: vec![EntryRequest {
                        key: String::from("number"),
                        value_desc: ValueDesc::Uint64,
                    }],
                }),
            },
            Input {
                name: String::from("b"),
                item: InputItem::Request(PodRequest {
                    from: String::from("bob"),
                    entries: vec![EntryRequest {
                        key: String::from("number"),
                        value_desc: ValueDesc::Uint64,
                    }],
                }),
            },
        ],
        expressions: vec![NamedExpression {
            name: String::from("add"),
            to: vec![User::from("alice"), User::from("bob")],
            expr: Expression::Binary {
                left: Box::new(Expression::Reference {
                    pod: String::from("a"),
                    key: String::from("number"),
                }),
                op: BinaryOp::Add,
                right: Box::new(Expression::Reference {
                    pod: String::from("b"),
                    key: String::from("number"),
                }),
            },
        }],
    };

    let pods = MyPods {
        pods: vec![Pod {
            entries: vec![Entry {
                key: String::from("number"),
                value: Value::Uint64(40),
            }],
        }],
    };
    Executor::new("alice", &script, &pods)?
        .exec()?
        .iter()
        .for_each(|pod| println!("output pod: {:?}", pod));
    Ok(())
}
