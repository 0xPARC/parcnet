mod input;
mod loader;
mod name;

use crate::logic::{get_current_version, Logic};
use gpui::{
    actions, div, px, rgba, uniform_list, InteractiveElement, IntoElement, KeyBinding,
    ListSizingBehavior, ParentElement, Render, Styled, UniformListScrollHandle, ViewContext,
};
use gpui::{View, VisualContext};
use input::TextInput;
use loader::Loader;
use name::Name;
use std::sync::Arc;

actions!(chat, [Enter]);

pub struct Chat {
    logic: Arc<Logic>,
    message_input: View<TextInput>,
    loader: View<Loader>,
    scroll_handle: UniformListScrollHandle,
}

impl Chat {
    pub fn new(cx: &mut ViewContext<Self>) -> Self {
        let logic = Arc::new(Logic::new());
        let logic_initialize = logic.clone();
        cx.spawn(|_view, mut _cx| async move {
            let _ = logic_initialize.initialize().await;
        })
        .detach();

        let mut message_watch = logic.get_message_watch();
        let mut initial_sync_watch = logic.get_initial_sync_watch();

        let logic_quit = logic.clone();
        cx.on_app_quit(move |_| {
            let logic_quit = logic_quit.clone();
            async move {
                let _ = logic_quit.cleanup().await;
            }
        })
        .detach();

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

        cx.spawn(|view, mut cx| async move {
            while initial_sync_watch.changed().await.is_ok() {
                let _ = cx.update(|cx| {
                    view.update(cx, |_this, cx| {
                        cx.notify();
                    })
                });
            }
        })
        .detach();

        cx.bind_keys([KeyBinding::new("enter", Enter, None)]);
        let message_input = cx.new_view(TextInput::new);
        let loader = cx.new_view(Loader::new);
        let scroll_handle = UniformListScrollHandle::new();

        Self {
            logic,
            message_input,
            loader,
            scroll_handle,
        }
    }

    fn enter(&mut self, _: &Enter, cx: &mut ViewContext<Self>) {
        let message_input = self.message_input.clone();
        let message = message_input.read(cx).get_content().to_string();
        let logic = self.logic.clone();
        cx.spawn(|view, mut cx| async move {
            let _ = logic.send_message(&message).await;
            let _ = cx.update(|cx| {
                message_input.update(cx, |input, _| input.reset());
                view.update(cx, |this, cx| {
                    this.scroll_to_bottom();
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
        let initial_sync = self.logic.get_initial_sync();
        let logic = self.logic.clone();

        let name_views: Vec<View<Name>> = messages
            .iter()
            .map(|(pubkey, _)| cx.new_view(|cx| Name::new(cx, *pubkey, logic.clone())))
            .collect();

        if initial_sync {
            div()
                .child(
                    div()
                        .flex()
                        .h(px(32.))
                        .px_4()
                        .bg(gpui::white())
                        .text_color(gpui::black())
                        .w_full()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_center()
                                .size_full()
                                .text_xs()
                                .text_color(rgba(0x00000030))
                                .child(format!("chat v{}", get_current_version())),
                        ),
                )
                .key_context("Chat")
                .flex()
                .flex_col()
                .justify_between()
                .overflow_hidden()
                .relative()
                .size_full()
                .bg(gpui::white())
                .child(self.loader.clone())
        } else {
            div()
                .child(
                    div()
                        .flex()
                        .h(px(32.))
                        .px_4()
                        .bg(gpui::white())
                        .text_color(gpui::black())
                        .w_full()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .justify_center()
                                .size_full()
                                .text_xs()
                                .text_color(rgba(0x00000030))
                                .child(format!("chat v{}", get_current_version())),
                        ),
                )
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
                        let name_views = name_views.clone();
                        move |_, visible_range, _| {
                            visible_range
                                .map(|ix| {
                                    let (_, message) = messages.get(ix).unwrap();
                                    let name_view = &name_views[ix];
                                    div()
                                        .flex()
                                        .flex_row()
                                        .gap_1()
                                        .child(name_view.clone())
                                        .child(message.clone())
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
}
