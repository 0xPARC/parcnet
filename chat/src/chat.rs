mod input;

use crate::logic::Logic;
use gpui::{
    actions, div, list, uniform_list, Element, InteractiveElement, IntoElement, KeyBinding,
    ListAlignment, ListSizingBehavior, ListState, ParentElement, Pixels, Render,
    StatefulInteractiveElement, Styled, ViewContext,
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
            while message_watch.changed().await.is_ok() {
                let _ = cx.update(|cx| {
                    view.update(cx, |_, cx| {
                        cx.notify();
                    })
                });
            }
        })
        .detach();

        cx.bind_keys([KeyBinding::new("enter", Enter, None)]);
        let message_input = cx.new_view(TextInput::new);

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
                })
                .unwrap();
            });
        })
        .detach();
    }
}

impl Render for Chat {
    fn render(&mut self, cx: &mut ViewContext<Self>) -> impl IntoElement {
        let view = cx.view().clone();
        let messages = self.logic.get_messages();
        // let list_state = ListState::new(
        //     messages.len(),
        //     ListAlignment::Top,
        //     Pixels(20.),
        //     move |idx, _cx| {
        //         let item = messages.get(idx).unwrap().clone();
        //         div().child(item.text).into_any_element()
        //     },
        // );
        div()
            .key_context("Chat")
            .on_action(cx.listener(Self::enter))
            .flex()
            .flex_col()
            .justify_between()
            .overflow_hidden()
            .relative()
            .size_full()
            .bg(gpui::white())
            .child(
                uniform_list(view, "messages-list", messages.len(), {
                    move |_, visible_range, _| {
                        visible_range
                            .map(|ix| {
                                div()
                                    .child(messages.get(ix).unwrap().clone().text)
                                    .into_any_element()
                            })
                            .collect::<Vec<_>>()
                    }
                })
                .flex_grow()
                .with_sizing_behavior(ListSizingBehavior::Auto),
            )
            .child(self.message_input.clone())
    }
}
