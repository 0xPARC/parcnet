mod e;
mod is_old_enough;
mod locked_message;
mod unlock_message;

fn main() {
    is_old_enough::main().unwrap();
    locked_message::main().unwrap();
    unlock_message::main().unwrap();
}
