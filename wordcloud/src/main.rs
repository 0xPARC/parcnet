mod chat;
use chat::Chat;

fn main() {
    iced::run("chat", Chat::update, Chat::view).unwrap();
}
