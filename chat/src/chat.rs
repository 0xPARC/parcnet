mod input;

use crate::logic::Logic;
use gpui::{div, rgb, IntoElement, Length, ParentElement, Pixels, Render, Styled, ViewContext};
use gpui::{View, VisualContext};
use input::TextInput;

pub struct Chat {
    logic: Logic,
    message_input: View<TextInput>,
}

impl Chat {
    pub fn new(cx: &mut ViewContext<Self>) -> Self {
        let logic = Logic::new();
        logic.start_test_task();

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
}

impl Render for Chat {
    fn render(&mut self, _cx: &mut ViewContext<Self>) -> impl IntoElement {
        let message = self.logic.get_latest_message();
        div()
            .flex_col()
            .bg(rgb(0x2e7d32))
            .size(Length::Definite(Pixels(300.0).into()))
            .justify_center()
            .items_center()
            .shadow_lg()
            .border_1()
            .border_color(rgb(0x0000ff))
            .text_xl()
            .text_color(rgb(0xffffff))
            .child(format!("latest message: {}", &message))
            .child(self.message_input.clone())
    }
}
