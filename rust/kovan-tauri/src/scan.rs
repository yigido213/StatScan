use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use statscan_core::{
    data,
    engine::{ScanOptions, scan_with_size},
    model::ScanResult,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU32, Ordering},
};
use tauri::{AppHandle, Manager, State};

const CHUNK_BYTES: usize = 512 * 1024;

#[derive(Default)]
pub struct Scanner {
    next_id: AtomicU32,
    active: Mutex<Option<Job>>,
}

impl Scanner {
    pub fn reset(&self) {
        if let Ok(mut active) = self.active.lock() {
            if let Some(job) = active.as_ref() {
                job.cancelled.store(true, Ordering::Relaxed);
                if !job.running {
                    *active = None;
                }
            }
        }
    }
}

struct Job {
    id: u32,
    name: String,
    size: usize,
    upload: bool,
    bytes: Vec<u8>,
    options: ScanOptions,
    cancelled: Arc<AtomicBool>,
    running: bool,
}

#[derive(Serialize)]
pub struct Ticket {
    id: u32,
    upload: bool,
}

#[tauri::command]
pub fn scan_begin(
    scanner: State<'_, Scanner>,
    name: String,
    size: usize,
    mode: String,
    time_limit_ms: Option<u64>,
    java_allowed: bool,
) -> Result<Ticket, String> {
    if !matches!(mode.as_str(), "quick" | "normal" | "deep")
        || name.is_empty() || name.len() > 1024
    {
        return Err("Geçersiz tarama isteği.".into());
    }
    let mut active = scanner.active.lock().map_err(|error| error.to_string())?;
    if active.is_some() {
        return Err("Bir tarama sürüyor.".into());
    }
    let upload = size as f64 <= data::mode(&mode).max_input;
    let id = scanner.next_id.fetch_add(1, Ordering::Relaxed);
    let cancelled = Arc::new(AtomicBool::new(false));
    *active = Some(Job {
        id,
        name,
        size,
        upload,
        bytes: Vec::new(),
        options: ScanOptions {
            mode,
            time_limit_ms,
            cancel: Some(Arc::clone(&cancelled)),
            java_allowed,
        },
        cancelled,
        running: false,
    });
    Ok(Ticket { id, upload })
}

#[tauri::command]
pub fn scan_append(scanner: State<'_, Scanner>, id: u32, chunk: String) -> Result<(), String> {
    if chunk.len() > CHUNK_BYTES.div_ceil(3) * 4 {
        return Err("Tarama parçası çok büyük.".into());
    }
    let mut active = scanner.active.lock().map_err(|error| error.to_string())?;
    let job = active.as_mut().filter(|job| job.id == id && job.upload && !job.running)
        .ok_or("Tarama aktarımı bulunamadı.")?;
    let bytes = STANDARD.decode(chunk).map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > CHUNK_BYTES || bytes.len() > job.size - job.bytes.len() {
        return Err("Tarama parçasının boyutu geçersiz.".into());
    }
    job.bytes.try_reserve(bytes.len()).map_err(|error| error.to_string())?;
    job.bytes.extend_from_slice(&bytes);
    Ok(())
}

#[tauri::command]
pub async fn scan_run(app: AppHandle, id: u32) -> Result<ScanResult, String> {
    let scanner = app.state::<Scanner>();
    let (name, size, bytes, options) = {
        let mut active = scanner.active.lock().map_err(|error| error.to_string())?;
        let job = active.as_mut().filter(|job| job.id == id && !job.running)
            .ok_or("Tarama aktarımı bulunamadı.")?;
        if job.cancelled.load(Ordering::Relaxed) {
            return Err("Tarama iptal edildi.".into());
        }
        if job.upload && job.bytes.len() != job.size {
            return Err("Dosya aktarımı tamamlanmadı.".into());
        }
        job.running = true;
        (job.name.clone(), job.size, std::mem::take(&mut job.bytes), job.options.clone())
    };
    let result = tauri::async_runtime::spawn_blocking(move || {
        scan_with_size(&name, size, || bytes, &options)
    }).await;

    let mut active = scanner.active.lock().map_err(|error| error.to_string())?;
    if active.as_ref().is_some_and(|job| job.id == id) {
        *active = None;
    }
    let mut report = result.map_err(|error| error.to_string())?;
    report.notes.get_or_insert_with(Vec::new).push(
        "Motor: statscan-core (Rust). Rust'a taşınan denetimlerin kapsamı bulgularda belirtilir.".into()
    );
    Ok(report)
}

#[tauri::command]
pub fn scan_cancel(scanner: State<'_, Scanner>, id: u32) -> Result<(), String> {
    let active = scanner.active.lock().map_err(|error| error.to_string())?;
    if let Some(job) = active.as_ref().filter(|job| job.id == id) {
        job.cancelled.store(true, Ordering::Relaxed);
    }
    Ok(())
}

#[tauri::command]
pub fn scan_discard(scanner: State<'_, Scanner>, id: u32) -> Result<(), String> {
    let mut active = scanner.active.lock().map_err(|error| error.to_string())?;
    if let Some(job) = active.as_ref().filter(|job| job.id == id) {
        job.cancelled.store(true, Ordering::Relaxed);
        if !job.running {
            *active = None;
        }
    }
    Ok(())
}
