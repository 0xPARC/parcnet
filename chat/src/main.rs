mod chat;
mod logic;
use chat::Chat;
use gpui::{px, size, App, AppContext, Bounds, VisualContext, WindowBounds, WindowOptions};

// mod update {
//     use futures::lock::Mutex;
//     use gpui::{AppContext, AsyncAppContext, Model, ModelContext, SemanticVersion};
//     use std::{path::PathBuf, sync::Arc, time::Duration};

//     const POLL_INTERVAL: Duration = Duration::from_secs(60 * 60);

//     #[derive(Clone, PartialEq)]
//     pub enum AutoUpdateStatus {
//         Idle,
//         Checking,
//         Downloading,
//         Installing,
//         Updated { binary_path: PathBuf },
//         Errored,
//     }

//     pub struct AutoUpdater {
//         status: Arc<Mutex<AutoUpdateStatus>>,
//         current_version: SemanticVersion,
//         http_client: reqwest::Client,
//     }

//     struct Release {
//         version: String,
//         url: String,
//     }

//     impl AutoUpdater {
//         pub fn new(current_version: SemanticVersion) -> Model<Self> {
//             let updater = Self {
//                 status: Arc::new(Mutex::new(AutoUpdateStatus::Idle)),
//                 current_version,
//                 http_client: reqwest::Client::new(),
//             };

//             tokio::spawn(async move {
//                 loop {
//                     tokio::time::sleep(POLL_INTERVAL).await;
//                     updater.check_for_update();
//                 }
//             });

//             updater
//         }

//         async fn check_for_update(&self) {
//             if matches!(self.status.clone().lock().await, AutoUpdateStatus::Idle) {
//                 self.status = AutoUpdateStatus::Checking;
//             }
//         }

//         async fn update(
//             this: Model<Self>,
//             mut cx: AsyncAppContext,
//         ) -> Result<(), Box<dyn std::error::Error>> {
//             let (client, current_version) = this.read_with(&cx, |this, _| {
//                 (this.http_client.clone(), this.current_version.clone())
//             })?;

//             this.update(&mut cx, |this, cx| {
//                 this.status = AutoUpdateStatus::Checking;
//                 cx.notify();
//             })?;

//             let release: Release = client
//                 .get("https://api.example.com/latest-release")
//                 .send()
//                 .await?
//                 .json()
//                 .await?;

//             if release.version.parse::<SemanticVersion>()? <= current_version {
//                 return Ok(());
//             }

//             this.update(&mut cx, |this, cx| {
//                 this.status = AutoUpdateStatus::Downloading;
//                 cx.notify();
//             })?;

//             let response = client.get(&release.url).send().await?;
//             let binary = response.bytes().await?;

//             this.update(&mut cx, |this, cx| {
//                 this.status = AutoUpdateStatus::Installing;
//                 cx.notify();
//             })?;

//             // Implement platform-specific installation logic here
//             // For simplicity, we'll just pretend to install:
//             std::thread::sleep(Duration::from_secs(2));

//             this.update(&mut cx, |this, cx| {
//                 this.status = AutoUpdateStatus::Updated {
//                     binary_path: std::env::current_exe()?,
//                 };
//                 cx.notify();
//             })?;

//             Ok(())
//         }

//         pub fn status(&self) -> AutoUpdateStatus {
//             self.status.clone()
//         }
//     }
// }

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
            |cx| cx.new_view(Chat::new),
        );
    });
}
