use std::sync::{Arc, RwLock};

use tokio::sync::watch;

pub struct Logic {
    latest_message: Arc<RwLock<String>>,
    message_watch: (watch::Sender<()>, watch::Receiver<()>),
}

impl Logic {
    pub fn new() -> Self {
        let message_watch = watch::channel(());
        Self {
            latest_message: Arc::new(RwLock::new("".to_string())),
            message_watch,
        }
    }

    pub fn start_test_task(&self) {
        let message_watch_sender = self.message_watch.0.clone();
        let latest_message = self.latest_message.clone();

        tokio::spawn(async move {
            let mut i = 0;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                i += 1;
                let message = format!("message {}", i);
                *latest_message.write().unwrap() = message.clone();
                message_watch_sender.send(()).unwrap();
            }
        });
    }

    pub fn get_latest_message(&self) -> String {
        self.latest_message.clone().read().unwrap().clone()
    }

    pub fn get_message_watch(&self) -> watch::Receiver<()> {
        self.message_watch.1.clone()
    }
}
