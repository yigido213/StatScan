#[tauri::command]
pub fn webview2_result(app: tauri::AppHandle, result: String, passed: bool) {
    println!("{result}");
    app.exit(if passed { 0 } else { 1 });
}
