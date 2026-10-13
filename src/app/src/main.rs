//! Hawk's desktop app: the dashboard (built standalone, see relay.ts) in a
//! window of its own, so the code that holds your keys comes from a signed
//! install rather than from whichever relay served the page.
//!
//! It updates itself from the same signed release feed as everything else:
//! the feed and key the release workflow built it with, unless its settings
//! name others (a fork's, say).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_updater::UpdaterExt;

/// Baked in by the release workflow; `{channel}` is stable or beta.
const DEFAULT_FEED_URL: Option<&str> = option_env!("HAWK_UPDATE_URL");
/// minisign public key (the second line of the .pub file).
const DEFAULT_PUBLIC_KEY: Option<&str> = option_env!("HAWK_UPDATE_PUBKEY");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Settings {
    /// "notify": say so and install when asked; "auto": install when the app
    /// starts, before anything is open; "off": never look.
    policy: String,
    channel: String,
    /// Empty: what this build came with.
    feed_url: String,
    public_key: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self { policy: "notify".into(), channel: "stable".into(), feed_url: String::new(), public_key: String::new() }
    }
}

impl Settings {
    fn path(app: &AppHandle) -> Option<PathBuf> {
        app.path().app_config_dir().ok().map(|dir| dir.join("settings.json"))
    }

    fn load(app: &AppHandle) -> Self {
        Self::path(app)
            .and_then(|path| std::fs::read_to_string(path).ok())
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    fn save(&self, app: &AppHandle) -> Result<(), String> {
        let path = Self::path(app).ok_or("no settings folder")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())
    }

    /// The app's own manifest beside the components' one in the feed:
    /// `…/hawk-{channel}.json` becomes `…/app-{channel}.json`.
    fn endpoint(&self) -> Option<url::Url> {
        let feed = if self.feed_url.is_empty() { DEFAULT_FEED_URL? } else { self.feed_url.as_str() };
        let channel = if self.channel == "beta" { "beta" } else { "stable" };
        let app_feed = feed.replace("hawk-{channel}.json", "app-{channel}.json").replace("{channel}", channel);
        url::Url::parse(&app_feed).ok()
    }

    /// Tauri wants the whole minisign .pub file, base64'd; the feed's key is
    /// its second line.
    fn tauri_public_key(&self) -> Option<String> {
        let key = if self.public_key.is_empty() { DEFAULT_PUBLIC_KEY? } else { self.public_key.as_str() };
        let file = format!("untrusted comment: minisign public key\n{}\n", key.trim());
        Some(base64::engine::general_purpose::STANDARD.encode(file))
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateInfo {
    version: String,
    current: String,
    notes: Option<String>,
}

/// An update found and not yet installed.
#[derive(Default)]
struct Pending(Mutex<Option<tauri_plugin_updater::Update>>);

async fn find_update(app: &AppHandle) -> Result<Option<tauri_plugin_updater::Update>, String> {
    let settings = Settings::load(app);
    let endpoint = settings.endpoint().ok_or("this build has no release feed: set one in Settings")?;
    let key = settings.tauri_public_key().ok_or("this build has no release key: set one in Settings")?;
    let updater = app
        .updater_builder()
        .endpoints(vec![endpoint])
        .map_err(|error| error.to_string())?
        .pubkey(key)
        .build()
        .map_err(|error| error.to_string())?;
    updater.check().await.map_err(|error| error.to_string())
}

#[tauri::command]
fn settings(app: AppHandle) -> Settings {
    Settings::load(&app)
}

#[tauri::command]
fn set_settings(app: AppHandle, settings: Settings) -> Result<(), String> {
    if !matches!(settings.policy.as_str(), "notify" | "auto" | "off") {
        return Err(format!("update policy \"{}\" isn't notify, auto or off", settings.policy));
    }
    if !matches!(settings.channel.as_str(), "stable" | "beta") {
        return Err(format!("channel \"{}\" isn't stable or beta", settings.channel));
    }
    settings.save(&app)
}

#[tauri::command]
async fn check_update(app: AppHandle, pending: State<'_, Pending>) -> Result<Option<UpdateInfo>, String> {
    let update = find_update(&app).await?;
    let info = update.as_ref().map(|update| UpdateInfo {
        version: update.version.clone(),
        current: update.current_version.clone(),
        notes: update.body.clone(),
    });
    *pending.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = update;
    Ok(info)
}

/// Downloads, checks and installs the update found last, then restarts.
#[tauri::command]
async fn install_update(app: AppHandle, pending: State<'_, Pending>) -> Result<(), String> {
    let update = pending.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
    let update = match update {
        Some(update) => update,
        None => find_update(&app).await?.ok_or("already up to date")?,
    };
    update.download_and_install(|_, _| {}, || {}).await.map_err(|error| error.to_string())?;
    app.restart();
}

#[tauri::command]
fn app_version(app: AppHandle) -> String {
    app.package_info().version.to_string()
}

/// At start: with "auto", install a waiting update before anything is
/// open; with "notify", tell the page so it can offer it.
async fn startup_check(app: AppHandle) {
    let settings = Settings::load(&app);
    if settings.policy == "off" {
        return;
    }
    let Ok(Some(update)) = find_update(&app).await else { return };
    if settings.policy == "auto" {
        if update.download_and_install(|_, _| {}, || {}).await.is_ok() {
            app.restart();
        }
        return;
    }
    let info = UpdateInfo {
        version: update.version.clone(),
        current: update.current_version.clone(),
        notes: update.body.clone(),
    };
    if let Some(pending) = app.try_state::<Pending>() {
        *pending.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(update);
    }
    let _ = app.emit("update-available", info);
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(Pending::default())
        .invoke_handler(tauri::generate_handler![settings, set_settings, check_update, install_update, app_version])
        .setup(|app| {
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(startup_check(handle));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running the Hawk app");
}
