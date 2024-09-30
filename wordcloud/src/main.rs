use gpui::{
    px, size, App, AppContext, Bounds, ViewContext, VisualContext, WindowBounds, WindowOptions,
};

mod chat {
    use gpui::{
        div, rgb, IntoElement, Length, ParentElement, Pixels, Render, Styled, ViewContext,
        VisualContext,
    };

    pub struct Chat {
        message: String,
    }

    impl Chat {
        pub fn new() -> Self {
            Self {
                message: "start".into(),
            }
        }
    }

    impl Render for Chat {
        fn render(&mut self, _cx: &mut ViewContext<Self>) -> impl IntoElement {
            div()
                .flex()
                .bg(rgb(0x2e7d32))
                .size(Length::Definite(Pixels(300.0).into()))
                .justify_center()
                .items_center()
                .shadow_lg()
                .border_1()
                .border_color(rgb(0x0000ff))
                .text_xl()
                .text_color(rgb(0xffffff))
                .child(format!("latest message: {}", &self.message))
        }
    }
}

fn main() {
    tracing_subscriber::fmt().init();
    App::new().run(|cx: &mut AppContext| {
        let bounds = Bounds::centered(None, size(px(600.0), px(480.0)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            |cx| cx.new_view(|_cx| chat::Chat::new()),
        )
        .unwrap();
    });
}
