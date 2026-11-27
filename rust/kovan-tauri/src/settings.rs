use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    io::Write,
    path::PathBuf,
    sync::Mutex,
};
use tauri::{AppHandle, State};
use tauri_plugin_autostart::ManagerExt;

const UNAVAILABLE: &str = "Bu araç henüz Rust sürümünde yok";
const MAX_VALUE_BYTES: usize = 4_000_000;
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
struct Data {
    start_minimized: bool,
    store: HashMap<String, String>,
}

pub struct Preferences {
    path: PathBuf,
    data: Mutex<Data>,
}

impl Preferences {
    pub fn open(dir: PathBuf) -> Self {
        let path = dir.join("settings.json");
        let data = fs::read(&path)
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default();
        Self { path, data: Mutex::new(data) }
    }

    pub fn start_minimized(&self) -> bool {
        self.data.lock().is_ok_and(|data| data.start_minimized)
    }

    fn update(&self, apply: impl FnOnce(&mut Data)) -> Result<(), String> {
        let mut data = self.data.lock().map_err(|error| error.to_string())?;
        let mut next = data.clone();
        apply(&mut next);
        let dir = self.path.parent().expect("settings directory");
        fs::create_dir_all(dir).map_err(|error| error.to_string())?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|error| error.to_string())?;
        serde_json::to_writer(&mut tmp, &next).map_err(|error| error.to_string())?;
        tmp.flush().map_err(|error| error.to_string())?;
        tmp.as_file().sync_all().map_err(|error| error.to_string())?;
        tmp.persist(&self.path).map_err(|error| error.to_string())?;
        *data = next;
        Ok(())
    }

    fn snapshot(&self, app: &AppHandle) -> Value {
        let login = app.autolaunch().is_enabled();
        let reason = login.as_ref().err().map(ToString::to_string);
        json!({
            "desktop": true,
            "platform": platform(),
            "version": VERSION,
            "autostart": { "supported": login.is_ok(), "reason": reason },
            "openAtLogin": login.unwrap_or(false),
            "startMinimized": self.start_minimized(),
            "autoUpdate": false,
            "feedUrl": "",
        })
    }
}

fn platform() -> &'static str {
    match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        os => os,
    }
}

#[tauri::command]
pub fn app_info(prefs: State<'_, Preferences>) -> Value {
    json!({ "version": VERSION, "platform": platform(), "configPath": prefs.path })
}

#[tauri::command]
pub fn show_config(prefs: State<'_, Preferences>) -> Result<Value, String> {
    if !prefs.path.exists() {
        prefs.update(|_| {})?;
    }
    tauri_plugin_opener::reveal_item_in_dir(&prefs.path).map_err(|error| error.to_string())?;
    Ok(json!({ "ok": true, "path": prefs.path }))
}

#[tauri::command]
pub fn settings_get(app: AppHandle, prefs: State<'_, Preferences>) -> Value {
    prefs.snapshot(&app)
}

#[tauri::command]
pub fn settings_set(
    app: AppHandle,
    prefs: State<'_, Preferences>,
    key: String,
    value: bool,
) -> Result<Value, String> {
    match key.as_str() {
        "autoUpdate" => return Ok(json!({ "error": "unsupported", "message": UNAVAILABLE })),
        "startMinimized" => prefs.update(|data| data.start_minimized = value)?,
        "openAtLogin" => {
            let login = app.autolaunch();
            if login.is_enabled().map_err(|error| error.to_string())? != value {
                let result = if value { login.enable() } else { login.disable() };
                result.map_err(|error| error.to_string())?;
            }
            if login.is_enabled().map_err(|error| error.to_string())? != value {
                return Err("Oturum açma ayarı işletim sisteminde doğrulanamadı.".into());
            }
        }
        _ => return Err("Geçersiz ayar isteği.".into()),
    }
    Ok(prefs.snapshot(&app))
}

#[tauri::command]
pub fn store_get(prefs: State<'_, Preferences>, key: String) -> Result<Option<String>, String> {
    check_key(&key)?;
    let data = prefs.data.lock().map_err(|error| error.to_string())?;
    Ok(data.store.get(&key).cloned())
}

#[tauri::command]
pub fn store_set(prefs: State<'_, Preferences>, key: String, value: String) -> Result<Value, String> {
    check_key(&key)?;
    if value.len() > MAX_VALUE_BYTES {
        return Err("Ayar değeri çok büyük.".into());
    }
    prefs.update(|data| { data.store.insert(key, value); })?;
    Ok(json!({ "ok": true }))
}

fn check_key(key: &str) -> Result<(), String> {
    match key {
        "policy" | "watch" => Ok(()),
        _ => Err("Geçersiz ayar anahtarı.".into()),
    }
}
