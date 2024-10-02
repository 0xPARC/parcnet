mod input;
use crate::logic::Logic;
use gpui::{
    actions, div, InteractiveElement, IntoElement, KeyBinding, ParentElement, Render, Styled,
    ViewContext,
};
use gpui::{View, VisualContext};
use input::TextInput;

actions!(chat, [Enter]);

pub struct Chat {
    logic: Logic,
    message_input: View<TextInput>,
}

impl Chat {
    pub fn new(cx: &mut ViewContext<Self>) -> Self {
        cx.bind_keys([KeyBinding::new("enter", Enter, None)]);

        let logic = Logic::new();
        logic.run_test_task();
        let mut message_watch = logic.get_message_watch();
        cx.spawn(|view, mut cx| async move {
            while let Ok(_) = message_watch.changed().await {
                let _ = cx.update(|cx| {
                    view.update(cx, |_, cx| {
                        cx.notify();
                    })
                });
            }
        })
        .detach();

        let message_input = cx.new_view(|cx| TextInput::new(cx));

        Self {
            logic,
            message_input,
        }
    }

    fn enter(&mut self, _: &Enter, cx: &mut ViewContext<Self>) {
        let message = self.message_input.read(cx).get_content();
        self.logic.send_message(&message);
        self.message_input.update(cx, |input, _| input.reset());
        cx.notify();
    }
}

impl Render for Chat {
    fn render(&mut self, cx: &mut ViewContext<Self>) -> impl IntoElement {
        let message = self.logic.get_latest_message();
        div()
            .key_context("Chat")
            .on_action(cx.listener(Self::enter))
            .flex()
            .flex_col()
            .justify_between()
            .h_full()
            .w_full()
            .bg(gpui::white())
            .child(format!("latest message: {}", &message))
            .child(self.message_input.clone())
    }
}
