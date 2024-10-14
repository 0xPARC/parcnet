mod chat;
mod logic;
use chat::Chat;
use gpui::{
    actions, point, px, size, App, AppContext, Bounds, KeyBinding, TitlebarOptions, VisualContext,
    WindowBounds, WindowOptions,
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
                titlebar: Some(TitlebarOptions {
                    title: None,
                    appears_transparent: true,
                    traffic_light_position: Some(point(px(9.0), px(9.0))),
                }),
                ..Default::default()
            },
            |cx| cx.new_view(Chat::new),
        );
    });
}

fn quit(_: &Quit, cx: &mut gpui::AppContext) {
    cx.quit();
}
