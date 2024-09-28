mod chat;
use chat::Chat;

mod iroh {}

fn main() {
    tracing_subscriber::fmt().init();
    iced::application("chat", Chat::update, Chat::view)
        .run_with(Chat::new)
        .unwrap();
}
