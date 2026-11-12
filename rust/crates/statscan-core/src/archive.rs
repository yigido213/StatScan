//! ZIP tabanli kapsayicilar (duz ZIP/APK, Ofis OOXML kismen). JAR/class derin analizi henuz tasinmadi.

use crate::engine::{scan_buffer, xor_decode, xor_find_pe};
use crate::model::{Analysis, Finding, ScanResult, Severity};
use crate::rules::{hits_to_findings, run_rules, Hits, Kind};
use crate::rx::{js, Rx};
use crate::state::St;
use crate::util::{base_name, clip, ext_of, fmt_n, utf8_decode};
use crate::zip::{read_budget, read_zip, Entry};
use serde_json::Value;
use std::sync::LazyLock;

pub const EXE_EXT: [&str; 25] = [
    "exe", "dll", "scr", "com", "pif", "sys", "ocx", "cpl", "msi", "jar", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta",
    "lnk", "so", "dylib", "", "", "",
];
pub const ZTEXT_EXT: [&str; 20] = [
    "json", "yml", "yaml", "toml", "properties", "txt", "xml", "js", "sh", "bat", "cmd", "ps1", "vbs", "py", "cfg", "conf", "info", "mf",
    "html", "htm",
];

pub fn is_exe_ext(x: &str) -> bool {
    !x.is_empty() && EXE_EXT.contains(&x)
}
pub fn is_text_ext(x: &str) -> bool {
    ZTEXT_EXT.contains(&x) || x == "hta"
}

static OFFICE_RE: LazyLock<Rx> =
    LazyLock::new(|| js(r"^(docx|xlsx|pptx|docm|xlsm|pptm|dotx|dotm|xltx|xltm|xlam|ppsx|ppsm|potx|potm|ppam|sldm|sldx)$", ""));
static SLIP: LazyLock<Rx> = LazyLock::new(|| js(r"(^|\/)\.\.(\/|$)|^[\\/]", ""));
static RELS: LazyLock<Rx> = LazyLock::new(|| js(r"_rels\/.*\.rels$", ""));
static VBA: LazyLock<Rx> = LazyLock::new(|| js(r"vbaProject\.bin$", "i"));
static OFFICE_OBJ: LazyLock<Rx> = LazyLock::new(|| js(r"(^|\/)(?:vbaProject\.bin|embeddings\/[^\/]+|activeX\/[^\/]+\.bin|oleObject\d*\.bin)$", "i"));
static REMOTE: LazyLock<Rx> = LazyLock::new(|| js(r#"Target="(https?:[^"]+)"[^>]*TargetMode="External""#, "i"));
static REMOTE_KIND: LazyLock<Rx> = LazyLock::new(|| js(r"attachedTemplate|oleObject|frame", "i"));
static XOR_EXT: LazyLock<Rx> = LazyLock::new(|| js(r"^(dat|bin|tmp|res|cfg|db|)$", ""));
static RISKY: LazyLock<Rx> = LazyLock::new(|| js(r"\.(exe|scr|bat|cmd|ps1|vbs|js|jse|lnk|hta|dll|msi)$", "i"));
static CLASS_RE: LazyLock<Rx> = LazyLock::new(|| js(r"\.class$", ""));

pub struct ZipOut {
    pub type_label: String,
    pub kids: Vec<ScanResult>,
    pub info_kind: String,
    pub analyses: Vec<Analysis>,
    /// true: JAR (class iceren) — derin Java analizi henuz yok
    pub jar_unported: bool,
    /// JAR analizinin ek bilgi alanlari (JS `Object.assign(res.info, r.info)`).
    pub info: serde_json::Map<String, Value>,
}

pub fn analyze_zip(u: &[u8], name: &str, ext: &str, st: &mut St, depth: usize, f: &mut Vec<Finding>) -> Result<ZipOut, String> {
    let cfg = st.cfg;
    let mut entries = read_zip(u)?;
    let has_class = entries.iter().any(|e| CLASS_RE.is_match(&e.name));
    let office = OFFICE_RE.is_match(ext);
    let type_label = if ext == "jar" || has_class {
        "JAR / Java arşivi"
    } else if ext == "apk" {
        "APK"
    } else if office {
        "Ofis belgesi (OOXML)"
    } else {
        "ZIP arşivi"
    }
    .to_string();
    let mut out = ZipOut { info_kind: type_label.clone(), type_label, kids: vec![], analyses: vec![], jar_unported: false, info: serde_json::Map::new() };
    let total: f64 = entries.iter().map(|e| e.size as f64).sum();
    if total > 4e9 || (entries.len() > 20 && total / (u.len().max(1) as f64) > 900.0 && total > 2e8) {
        let ratio = (total / u.len().max(1) as f64).round();
        f.push(Finding::mk("zip_bomb", Severity::High, 30.0, "Zip bombası olasılığı", &format!("Sıkıştırma oranı olağandışı yüksek ({ratio}×). Güvenlik için içerik açılmadı."), "Arşivi açma.", vec![], "arch"));
        st.limit_hit("bomb", "Aşırı sıkıştırma oranı nedeniyle arşiv içeriği açılmadı.");
        return Ok(out);
    }
    if has_class {
        let r = crate::java::analyze_jar(u, &entries, st, depth, name);
        f.extend(r.findings);
        out.kids = r.children;
        out.info = r.info;
        return Ok(out);
    }
    let mut hits = Hits::new();
    if entries.len() > cfg.max_entries {
        st.limit_hit("entries", &format!("Arşivde çok fazla girdi var ({}); ilk {} girdi tarandı.", entries.len(), cfg.max_entries));
        entries.truncate(cfg.max_entries);
    }
    if office {
        if entries.iter().any(|e| VBA.is_match(&e.name)) {
            f.push(
                Finding::mk("office_vba", Severity::High, 18.0, "Ofis belgesinde VBA makrosu", "Belge makro (vbaProject.bin) içeriyor; kaynak kodu aşağıda alt dosya olarak çözümlenir.", "Makroları etkinleştirme.", vec![], "office")
                    .with_basis("fact")
                    .with_mitre(&["T1204.002", "T1059.005"]),
            );
        }
        out.analyses.push(Analysis::led("office", "Ofis belgesi ayrıntı denetimleri (makro kaynağı, uzak şablon dışı)", "unsupported", "Rust motorunda henüz taşınmadı"));
    }
    for e in entries.iter().filter(|e| RELS.is_match(&e.name) && e.size < 200_000) {
        if let Ok(d) = read_budget(u, e, st) {
            let t = utf8_decode(&d);
            if let Some(m) = REMOTE.capture1(&t) {
                if REMOTE_KIND.is_match(&t) {
                    f.push(Finding::mk("office_remote", Severity::High, 20.0, "Belge uzak içerik/şablon çekiyor", "Belge harici bir adrese bağlanıyor (şablon enjeksiyonu kalıbı).", "Belgeyi internetsiz ortamda aç; adresi araştır.", vec![clip(m, 100)], "net"));
                }
            }
        }
    }
    let n = entries.len();
    for (idx, e) in entries.iter().enumerate() {
        if e.dir {
            continue;
        }
        st.tick();
        if st.stop {
            st.partial = true;
            break;
        }
        let _ = idx as f64 / n as f64;
        entry_step(u, e, name, ext, office, st, depth, f, &mut out.kids);
    }
    let risky: Vec<&Entry> = entries.iter().filter(|e| RISKY.is_match(&e.name)).collect();
    if !risky.is_empty() {
        f.push(Finding::mk("arch_exec", Severity::Low, (3 + risky.len()).min(8) as f64, "Arşivde çalıştırılabilir dosyalar", &format!("{} adet çalıştırılabilir/betik dosya içeriyor.", risky.len()), "İçeriklerin sonuçlarına bak.", risky.iter().take(5).map(|e| e.name.clone()).collect(), "arch"));
    }
    hits_to_findings(&hits, f);
    let _ = (&mut hits, run_rules as fn(&str, &mut Hits, &str, Kind, Option<&std::collections::HashSet<&str>>));
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn entry_step(u: &[u8], e: &Entry, name: &str, ext: &str, office: bool, st: &mut St, depth: usize, f: &mut Vec<Finding>, kids: &mut Vec<ScanResult>) {
    let cfg = st.cfg;
    if SLIP.is_match(&e.name) {
        f.push(Finding::mk("zip_slip", Severity::High, 25.0, "Yol atlama (zip‑slip) girdisi", "Arşivde “../” veya mutlak yol içeren girdi var. Bu araç dosyaları diske açmaz.", "Bu arşivi bir arşiv yöneticisiyle açma.", vec![e.name.clone()], "arch"));
    }
    if e.enc {
        st.skip("enc", 1);
        st.note("Şifreli arşiv girdileri taranamadı.");
        f.push(Finding::mk("zip_enc", Severity::Info, 6.0, "Parola korumalı girdiler", "İçerik şifreli olduğu için taranamadı. Zararlılar tarama atlatmak için bunu sık kullanır.", "Parolayı biliyorsan açıp içeriği ayrıca tara.", vec![e.name.clone()], "arch"));
        return;
    }
    let x = ext_of(&e.name);
    let _ = ext;
    let office_obj = office && OFFICE_OBJ.is_match(&e.name);
    let child_name = format!("{name} › {}", e.name);
    if is_exe_ext(&x) || x == "zip" || x == "jar" || x == "rar" || x == "exe" || is_text_ext(&x) || office_obj {
        if depth >= cfg.depth {
            if is_exe_ext(&x) || x == "zip" || x == "jar" {
                st.limit_hit("depth", &format!("İç içe arşiv derinliği sınırına ulaşıldı; daha derindeki dosyalar taranmadı ({}).", base_name(&e.name)));
            }
            return;
        }
        let Ok(d) = read_budget(u, e, st) else { return };
        let kr = scan_buffer(&d, &child_name, st, depth + 1);
        if kr.score > 0 || is_exe_ext(&x) || office_obj {
            kids.push(kr);
        }
    } else if !cfg.parse {
        st.skip("ext", 1);
    } else {
        if !(e.size >= 2 && e.size < 8_000_000) {
            st.skip("ext", 1);
        }
        let d0 = if e.size >= 2 && e.size < 8_000_000 { read_budget(u, e, st).ok() } else { None };
        if let Some(d0) = d0 {
            if d0.len() >= 2 && d0[0] == 0x4d && d0[1] == 0x5a {
                f.push(Finding::mk("pk_hidden_pe", Severity::Crit, 35.0, "Zararsız uzantılı gizli çalıştırılabilir", &format!("{} uzantısı farklı ama içeriği PE.", e.name), "Çıkarıp ayrıca tara.", vec![e.name.clone()], "arch"));
                if depth < cfg.depth {
                    kids.push(scan_buffer(&d0, &child_name, st, depth + 1));
                }
            } else if cfg.xor && d0.len() > 8192 && XOR_EXT.is_match(&x) {
                if let Some((key, start)) = xor_find_pe(&d0, 4_000_000) {
                    f.push(Finding::mk("xor_pe", Severity::Crit, 35.0, "XOR ile gizlenmiş çalıştırılabilir", &format!("{} içinde tek baytlık XOR anahtarıyla (0x{key:x}) gizlenmiş bir PE bulundu.", e.name), "Çözülmüş içerik ayrıca taranır.", vec![format!("{} @ {start}", e.name)], "arch"));
                    if depth < cfg.depth {
                        kids.push(scan_buffer(&xor_decode(&d0, start, key), &format!("{child_name} (XOR çözülmüş)"), st, depth + 1));
                    }
                }
            }
        }
    }
}

pub fn _unused(_: Value, _: usize) -> String {
    fmt_n(0.0)
}
