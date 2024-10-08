#[macro_export]
macro_rules! my_pods {
    ( $( { $($key:expr => $value:expr),* } ),* ) => {
        Arc::new(MyPods {
            pods: vec![
                $(
                    Pod {
                        entries: vec![
                            $(
                                Entry {
                                    key: String::from($key),
                                    value: Value::Uint64($value),
                                },
                            )*
                        ],
                    }
                ),*
            ]
        })
    };
}
