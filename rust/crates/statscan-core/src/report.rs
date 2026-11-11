//! Turkce metin raporu (JSON ciktisi `ScanResult` ile aynidir).

use crate::model::{Finding, ScanResult, Severity};
use std::fmt::Write;

fn sev_label(s: Severity) -> &'static str {
    match s {
        Severity::Crit => "KRİTİK",
        Severity::High => "YÜKSEK",
        Severity::Med => "ORTA",
        Severity::Low => "DÜŞÜK",
        Severity::Info => "BİLGİ",
    }
}

fn basis_label(b: &str) -> &str {
    match b {
        "fact" => "Gözlem",
        "inference" => "Çıkarım",
        "heuristic" => "Sezgisel",
        o => o,
    }
}

fn write_findings(o: &mut String, fs: &[Finding], indent: &str) {
    for f in fs {
        let _ = writeln!(o, "{indent}[{}] {} (ağırlık {})", sev_label(f.sev), f.title, f.w);
        let _ = writeln!(o, "{indent}    Neden: {}", f.why);
        let _ = writeln!(o, "{indent}    Öneri: {}", f.act);
        if !f.ev.is_empty() {
            let _ = writeln!(o, "{indent}    Kanıt: {}", f.ev.join(" | "));
        }
        if let Some(b) = &f.basis {
            let _ = writeln!(o, "{indent}    Dayanak: {}{}", basis_label(b), f.conf.as_ref().map(|c| format!(" · güven: {c}")).unwrap_or_default());
        }
        if let Some(m) = &f.mitre {
            if !m.is_empty() {
                let _ = writeln!(o, "{indent}    MITRE ATT&CK: {}", m.join(", "));
            }
        }
        if let Some(fp) = &f.fp {
            let _ = writeln!(o, "{indent}    Yanlış alarm ihtimali: {fp}");
        }
    }
}

fn write_tree(o: &mut String, r: &ScanResult, depth: usize) {
    let ind = "  ".repeat(depth);
    let _ = writeln!(o, "{ind}▸ {} — {} · {}/100 ({})", r.name, r.kind_label, r.score, r.verdict);
    if let Some(h) = &r.sha256 {
        if depth == 0 {
            let _ = writeln!(o, "{ind}  SHA-256: {h}");
        }
    }
    write_findings(o, &r.findings, &format!("{ind}  "));
    for c in &r.children {
        write_tree(o, c, depth + 1);
    }
}

pub fn text_report(r: &ScanResult) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "StatScan (Rust) — statik tarama raporu");
    let _ = writeln!(o, "======================================");
    let _ = writeln!(o, "Dosya      : {} ({} bayt)", r.name, r.size);
    let _ = writeln!(o, "Tür        : {}", r.kind_label);
    if let Some(h) = &r.sha256 {
        let _ = writeln!(o, "SHA-256    : {h}");
    }
    if let Some(h) = &r.sha1 {
        let _ = writeln!(o, "SHA-1      : {h}");
    }
    let _ = writeln!(o, "Entropi    : {}", r.entropy);
    if let (Some(m), Some(l)) = (&r.mode, &r.mode_label) {
        let _ = writeln!(o, "Mod        : {l} ({m})");
    }
    let _ = writeln!(o, "\nKÖTÜCÜLLÜK PUANI: {}/100 — {}", r.score, r.verdict);
    if let Some(from) = &r.score_from {
        let _ = writeln!(o, "(puan alt dosyadan geliyor: {from})");
    }
    if r.partial == Some(true) {
        let _ = writeln!(o, "UYARI: Tarama KISMİ kaldı; sonuç eksik olabilir.");
    }
    if !r.profile.is_empty() {
        let _ = writeln!(o, "\nRisk profili:");
        for a in &r.profile {
            let _ = writeln!(o, "  {:<22} {:>3}", a.label, a.value);
        }
    }
    let _ = writeln!(o, "\nBulgular:");
    if r.findings.is_empty() && r.children.is_empty() {
        let _ = writeln!(o, "  Belirgin bulgu yok (bu, dosyanın güvenli olduğunu kanıtlamaz).");
    }
    write_tree(&mut o, r, 0);
    if let Some(l) = &r.limits {
        if !l.is_empty() {
            let _ = writeln!(o, "\nSınırlar / kısmi tarama nedenleri:");
            for x in l {
                let _ = writeln!(o, "  - {}", x.msg);
            }
        }
    }
    if let Some(s) = &r.skipped {
        if !s.is_empty() {
            let _ = writeln!(o, "\nKapsam dışı kalanlar:");
            for x in s {
                let _ = writeln!(o, "  - {} × {}", x.label, x.count);
            }
        }
    }
    if let Some(n) = &r.notes {
        for x in n {
            let _ = writeln!(o, "Not: {x}");
        }
    }
    let _ = writeln!(o, "\nAnaliz defteri (neyin gerçekten yapıldığı):");
    for a in &r.analyses {
        let _ = writeln!(o, "  [{}] {}{}", a.status, a.label, if a.note.is_empty() { String::new() } else { format!(" — {}", a.note) });
    }
    if let Some(c) = &r.coverage {
        if let Some(sk) = c.get("skipped").and_then(|v| v.as_array()) {
            if !sk.is_empty() {
                let _ = writeln!(o, "\nBu modda yapılmayan kontroller:");
                for x in sk.iter().filter_map(|v| v.as_str()) {
                    let _ = writeln!(o, "  - {x}");
                }
            }
        }
    }
    if let Some(d) = &r.disclaimer {
        let _ = writeln!(o, "\n{d}");
    }
    o
}
