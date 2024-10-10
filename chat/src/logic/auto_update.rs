// Much of this is adapted from Zed (https://github.com/zed-industries/zed/blob/c5d252b83713a708b907a8619ee79dbba9f4be4b/crates/auto_update/src/auto_update.rs)
use anyhow::{anyhow, ensure};
use gpui::{Result, SemanticVersion};
use serde_json::Value;
use std::sync::Mutex;
use std::{env, ffi::OsString, path::PathBuf, sync::Arc, time::Duration};
use tempfile::TempDir;
use tokio::process::Command;
use tracing::{error, info};

const POLL_INTERVAL: Duration = Duration::from_secs(60 * 60);
const RELEASES_URL: &str = "https://api.github.com/repos/0xPARC/parcnet/releases/latest";

struct MacOsUnmounter {
    mount_path: PathBuf,
}

impl Drop for MacOsUnmounter {
    fn drop(&mut self) {
        let unmount_output = std::process::Command::new("hdiutil")
            .args(["detach", "-force"])
            .arg(&self.mount_path)
            .output();

        match unmount_output {
            Ok(output) if output.status.success() => {
                info!("successfully unmounted the disk image");
            }
            Ok(output) => {
                error!(
                    "failed to unmount disk image: {:?}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            Err(error) => {
                error!("error while trying to unmount disk image: {:?}", error);
            }
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum AutoUpdateStatus {
    Idle,
    Checking,
    Downloading,
    Installing,
    Updated { binary_path: PathBuf },
}

#[derive(Clone)]
pub struct AutoUpdater {
    status: Arc<Mutex<AutoUpdateStatus>>,
    current_version: SemanticVersion,
}

impl AutoUpdater {
    pub fn new() -> Self {
        let updater = Self {
            status: Arc::new(Mutex::new(AutoUpdateStatus::Idle)),
            current_version: get_current_version(),
        };
        updater.run_update_loop();
        updater
    }

    fn run_update_loop(&self) {
        let status = self.status.clone();
        let current_version = self.current_version;
        tokio::spawn(async move {
            loop {
                check_for_update(status.clone(), current_version)
                    .await
                    .unwrap_or_else(|e| {
                        error!("error while checking for update: {:?}", e);
                    });
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        });
    }
}

async fn check_for_update(
    status: Arc<Mutex<AutoUpdateStatus>>,
    current_version: SemanticVersion,
) -> Result<()> {
    *status.lock().unwrap() = AutoUpdateStatus::Checking;
    let http_client = reqwest::Client::new();
    let release: Value = http_client
        .get(RELEASES_URL)
        .header("User-Agent", "parcnet-auto-updater")
        .send()
        .await?
        .json()
        .await?;
    let latest_version = release["tag_name"]
        .as_str()
        .unwrap()
        .strip_prefix("v")
        .ok_or_else(|| anyhow!("invalid version string"))?
        .parse::<SemanticVersion>()?;
    if latest_version > current_version {
        *status.lock().unwrap() = AutoUpdateStatus::Downloading;
        let asset_url = release["assets"][0]["browser_download_url"]
            .as_str()
            .unwrap();
        // print the url
        println!("asset_url: {}", asset_url);
        let dmg = http_client.get(asset_url).send().await?.bytes().await?;
        let temp_dir = tempfile::Builder::new().prefix("chat-update").tempdir()?;
        let downloaded_asset = temp_dir.path().join("chat.dmg");
        tokio::fs::write(&downloaded_asset, &dmg).await?;

        *status.lock().unwrap() = AutoUpdateStatus::Installing;
        let path = install_release(&temp_dir, downloaded_asset).await?;

        *status.lock().unwrap() = AutoUpdateStatus::Updated {
            binary_path: path.clone(),
        };

        Command::new(path).spawn()?;
        std::process::exit(0);
    } else {
        *status.lock().unwrap() = AutoUpdateStatus::Idle;
    }
    Ok(())
}

async fn install_release(temp_dir: &TempDir, downloaded_dmg: PathBuf) -> Result<PathBuf> {
    let running_app_path = get_app_path();

    let running_app_filename = running_app_path
        .file_name()
        .ok_or_else(|| anyhow!("invalid app path"))?;

    let mount_path = temp_dir.path().join("chat");
    let mut mounted_app_path: OsString = mount_path.join(running_app_filename).into();

    mounted_app_path.push("/");
    let output = Command::new("hdiutil")
        .args(["attach", "-nobrowse"])
        .arg(&downloaded_dmg)
        .arg("-mountroot")
        .arg(temp_dir.path())
        .output()
        .await?;

    ensure!(
        output.status.success(),
        "failed to mount: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _unmounter = MacOsUnmounter {
        mount_path: mount_path.clone(),
    };

    let output = Command::new("rsync")
        .args(["-av", "--delete"])
        .arg(&mounted_app_path)
        .arg(&running_app_path)
        .output()
        .await?;

    ensure!(
        output.status.success(),
        "failed to copy app: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(running_app_path)
}

fn get_app_path() -> PathBuf {
    let mut dir = env::current_exe().unwrap();
    dir.pop();
    dir.pop();
    dir
}

fn get_current_version() -> SemanticVersion {
    // let version_str = env!("CARGO_PKG_VERSION").to_string();
    // version_str
    //     .parse::<SemanticVersion>()
    //     .expect("invalid version format")
    SemanticVersion::new(0, 0, 1)
}
