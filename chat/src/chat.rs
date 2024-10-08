mod input;

use crate::logic::Logic;
use gpui::{
    actions, div, uniform_list, InteractiveElement, IntoElement, KeyBinding, ListSizingBehavior,
    ParentElement, Render, Styled, UniformListScrollHandle, ViewContext,
};
use gpui::{View, VisualContext};
use input::TextInput;
use std::sync::Arc;

actions!(chat, [Enter]);

pub struct Chat {
    logic: Arc<Logic>,
    message_input: View<TextInput>,
    scroll_handle: UniformListScrollHandle,
}

impl Chat {
    pub fn new(cx: &mut ViewContext<Self>) -> Self {
        let logic = Logic::new();
        let mut message_watch = logic.get_message_watch();

        cx.spawn(|view, mut cx| async move {
            while message_watch.changed().await.is_ok() {
                let _ = cx.update(|cx| {
                    view.update(cx, |this, cx| {
                        this.scroll_to_bottom();
                        cx.notify();
                    })
                });
            }
        })
        .detach();

        cx.bind_keys([KeyBinding::new("enter", Enter, None)]);
        let message_input = cx.new_view(TextInput::new);
        let scroll_handle = UniformListScrollHandle::new();

        Self {
            logic: Arc::new(logic),
            message_input,
            scroll_handle,
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

    fn scroll_to_bottom(&mut self) {
        let messages_len = self.logic.get_messages().len();
        if messages_len > 0 {
            self.scroll_handle.scroll_to_item(messages_len - 1);
        }
    }
}

impl Render for Chat {
    fn render(&mut self, cx: &mut ViewContext<Self>) -> impl IntoElement {
        let view = cx.view().clone();
        let messages = self.logic.get_messages();
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
                .with_sizing_behavior(ListSizingBehavior::Auto)
                .track_scroll(self.scroll_handle.clone()),
            )
            .child(self.message_input.clone())
    }
}