mod input;

use crate::logic::Logic;
use gpui::{
    actions, div, InteractiveElement, IntoElement, KeyBinding, ParentElement, Render, Styled,
    ViewContext,
};
use gpui::{View, VisualContext};
use input::TextInput;
use std::sync::Arc;

actions!(chat, [Enter]);

pub struct Chat {
    logic: Arc<Logic>,
    message_input: View<TextInput>,
}

impl Chat {
    pub fn new(cx: &mut ViewContext<Self>) -> Self {
        let logic = Logic::new();
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

        cx.bind_keys([KeyBinding::new("enter", Enter, None)]);
        let message_input = cx.new_view(|cx| TextInput::new(cx));

        Self {
            logic: Arc::new(logic),
            message_input,
        }
    }

    fn enter(&mut self, _: &Enter, cx: &mut ViewContext<Self>) {
        let message_input = self.message_input.clone();
        let message = message_input.read(cx).get_content().to_string();
        let logic = self.logic.clone();
        cx.spawn(|view, mut cx| async move {
            logic.send_message(&message).await;
            let _ = cx.update(|cx| {
                message_input.update(cx, |input, _| input.reset());
                view.update(cx, |_, cx| {
                    cx.notify();
                });
            });
        });
    }
}

impl Render for Chat {
    fn render(&mut self, cx: &mut ViewContext<Self>) -> impl IntoElement {
        let messages = self.logic.get_messages();
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
