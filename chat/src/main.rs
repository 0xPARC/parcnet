mod chat;
mod logic;
use chat::Chat;
use gpui::{
    actions, px, size, App, AppContext, Bounds, KeyBinding, VisualContext, WindowBounds,
    WindowOptions,
};

actions!(chat, [Quit]);

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    App::new().run(|cx: &mut AppContext| {
        cx.activate(true);
        cx.on_action(quit);
        cx.bind_keys([KeyBinding::new("cmd-q", Quit, None)]);

        let bounds = Bounds::centered(None, size(px(300.0), px(300.0)), cx);

        let _ = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            |cx| cx.new_view(Chat::new),
        );
    });
}

fn quit(_: &Quit, cx: &mut gpui::AppContext) {
    cx.quit();
}
