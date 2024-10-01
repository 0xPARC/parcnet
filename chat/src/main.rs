mod chat;
mod logic;
use chat::Chat;
use gpui::{px, size, App, AppContext, Bounds, VisualContext, WindowBounds, WindowOptions};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    App::new().run(|cx: &mut AppContext| {
        cx.activate(true);
        let bounds = Bounds::centered(None, size(px(300.0), px(300.0)), cx);

        let _ = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            |cx| cx.new_view(|cx| Chat::new(cx)),
        );
    });
}
