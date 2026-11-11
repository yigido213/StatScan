//! statscan: komut satiri. Dosyayi ASLA calistirmaz, ag kullanmaz, hicbir dosyayi degistirmez.

use statscan_core::engine::{scan_with_size, ScanOptions};
use statscan_core::report::text_report;
use std::process::ExitCode;

fn usage() -> &'static str {
    "Kullanım: statscan [--mod quick|normal|deep] [--json] [--ozet-json] [--sure SANIYE] DOSYA...\n\
     \n  --mod        hızlı / normal / derin (varsayılan: normal)\n  --json       tam sonucu JSON olarak yaz\n  --ozet-json  karşılaştırma için kısa JSON (id/önem/ağırlık/puan)\n  --sure       süre sınırı (sn, varsayılan 300)"
}

fn main() -> ExitCode {
    let mut mode = "normal".to_string();
    let (mut json, mut brief) = (false, false);
    let mut limit: Option<u64> = Some(300_000);
    let mut files: Vec<String> = vec![];
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--mod" | "--mode" => match it.next() {
                Some(m) => {
                    mode = match m.as_str() {
                        "hizli" | "hızlı" | "quick" => "quick",
                        "normal" => "normal",
                        "derin" | "deep" => "deep",
                        _ => {
                            eprintln!("Bilinmeyen mod: {m}\n{}", usage());
                            return ExitCode::from(2);
                        }
                    }
                    .to_string()
                }
                None => {
                    eprintln!("{}", usage());
                    return ExitCode::from(2);
                }
            },
            "--json" => json = true,
            "--ozet-json" => brief = true,
            "--sure" => match it.next().and_then(|s| s.parse::<u64>().ok()) {
                Some(s) => limit = Some(s * 1000),
                None => {
                    eprintln!("--sure bir sayı ister\n{}", usage());
                    return ExitCode::from(2);
                }
            },
            "-h" | "--help" | "--yardim" => {
                println!("{}", usage());
                return ExitCode::SUCCESS;
            }
            f => files.push(f.to_string()),
        }
    }
    if files.is_empty() {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }
    let opts = ScanOptions { mode, time_limit_ms: limit, ..Default::default() };
    let mut worst = 0i64;
    let mut outs: Vec<serde_json::Value> = vec![];
    for p in &files {
        let name = std::path::Path::new(p).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| p.clone());
        let size = match std::fs::metadata(p) {
            Ok(m) => m.len() as usize,
            Err(e) => {
                eprintln!("{p}: okunamadı: {e}");
                return ExitCode::from(2);
            }
        };
        let path = p.clone();
        let r = scan_with_size(&name, size, || std::fs::read(&path).unwrap_or_default(), &opts);
        worst = worst.max(r.score);
        if brief {
            outs.push(serde_json::json!({
                "name": r.name, "type": r.kind_label, "score": r.score, "ownScore": r.own_score, "verdict": r.verdict,
                "findings": r.findings.iter().map(|f| serde_json::json!({"id": f.id, "sev": f.sev, "w": f.w})).collect::<Vec<_>>(),
                "children": r.children.len(),
            }));
        } else if json {
            outs.push(serde_json::to_value(&r).unwrap_or_default());
        } else {
            println!("{}", text_report(&r));
        }
    }
    if brief || json {
        let v = if outs.len() == 1 { outs.remove(0) } else { serde_json::Value::Array(outs) };
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    }
    // cikis kodu: 0 belirgin bulgu yok / dusuk, 1 supheli ve ustu (puan>=30)
    if worst >= 30 { ExitCode::from(1) } else { ExitCode::SUCCESS }
}
