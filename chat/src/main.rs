mod chat;
mod logic;

use chat::Chat;
use gpui::{
    actions, point, px, size, App, AppContext, Application, Bounds, KeyBinding, TitlebarOptions,
    WindowBounds, WindowOptions,
};
use logic::{get_app_path, is_dev};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

actions!(chat, [Quit]);

#[tokio::main]
async fn main() {
    let app_dir = get_app_path();
    let file_appender = RollingFileAppender::new(Rotation::NEVER, app_dir, "chat.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(if is_dev() {
            Some(fmt::layer().with_writer(non_blocking))
        } else {
            None
        })
        .with(fmt::layer().with_writer(std::io::stdout))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    Application::new()
        .with_assets(assets::Assets {})
        .run(|cx: &mut App| {
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
                |_, cx| cx.new(Chat::new),
            );
        })
}

fn quit(_: &Quit, cx: &mut gpui::App) {
    cx.quit();
}
