#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod qa;
mod scan;
mod settings;

use tauri::{
    Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
    webview::{NewWindowResponse, PageLoadEvent},
    window::Color,
};

#[tauri::command]
fn window_zoom(window: WebviewWindow, zoom: f64) -> Result<(), String> {
    if !(0.4..=3.0).contains(&zoom) {
        return Err("Geçersiz arayüz ölçeği.".into());
    }
    window.set_zoom(zoom).map_err(|error| error.to_string())
}

#[tauri::command]
fn window_route(window: WebviewWindow, title: String) -> Result<(), String> {
    if title.chars().count() > 120 || title.chars().any(char::is_control) {
        return Err("Geçersiz pencere başlığı.".into());
    }
    window.set_title(&title).map_err(|error| error.to_string())
}

fn main() {
    let verify = std::env::args().any(|arg| arg == "--verify-webview2");
    let login = std::env::args().any(|arg| arg == "--autostart");
    let transparent = cfg!(windows) && std::env::args().any(|arg| arg == "--transparent");

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--autostart"]),
        ))
        .manage(scan::Scanner::default())
        .invoke_handler(tauri::generate_handler![
            settings::app_info,
            settings::show_config,
            settings::settings_get,
            settings::settings_set,
            settings::store_get,
            settings::store_set,
            scan::scan_begin,
            scan::scan_append,
            scan::scan_run,
            scan::scan_cancel,
            scan::scan_discard,
            qa::webview2_result,
            window_zoom,
            window_route,
        ])
        .setup(move |app| {
            let preferences = settings::Preferences::open(app.path().app_config_dir()?);
            let minimize = login && preferences.start_minimized();
            app.manage(preferences);

            let window = WebviewWindowBuilder::new(
                app,
                "main",
                WebviewUrl::App("StatScan.html".into()),
            )
            .title("Kovan")
            .inner_size(if verify { 390.0 } else { 1280.0 }, 900.0)
            .min_inner_size(390.0, 540.0)
            .visible(false)
            .transparent(transparent)
            .background_color(if transparent { Color(0, 0, 0, 0) } else { Color(16, 17, 20, 255) })
            .disable_drag_drop_handler()
            .initialization_script(include_str!(concat!(env!("OUT_DIR"), "/bridge.js")))
            .on_page_load(move |window, page| {
                if matches!(page.event(), PageLoadEvent::Started) {
                    window.state::<scan::Scanner>().reset();
                } else if verify {
                    if let Err(error) = window.eval(include_str!("qa.js")) {
                        eprintln!("WebView2 test script could not run: {error}");
                        window.app_handle().exit(1);
                    }
                }
            })
            .on_navigation(|url| {
                let origin = (url.scheme(), url.host_str());
                matches!(origin, ("tauri", Some("localhost")) | ("http", Some("tauri.localhost")))
                    && url.port().is_none()
                    && url.path() == "/StatScan.html"
            })
            .on_new_window(|url, _| {
                if url.scheme() == "https" && url.host_str().is_some() {
                    let _ = tauri_plugin_opener::open_url(url.as_str(), None::<&str>);
                }
                NewWindowResponse::Deny
            })
            .build()?;

            if minimize {
                window.minimize()?;
            }
            window.show()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Kovan penceresi açılamadı");
}
