//! Gizlenmis icerik cozme (yalniz derin mod): Base64/hex/PowerShell -enc/gzip katmanlari. JS `deobf/handleDecoded`.

use crate::engine::scan_buffer;
use crate::model::{Finding, ScanResult, Severity};
use crate::rules::{run_rules, Hits, Kind};
use crate::rx::{js, Rx};
use crate::state::St;
use crate::util::{clip, utf8_decode};
use std::collections::HashSet;
use std::io::Read;
use std::sync::LazyLock;

static B64G: LazyLock<Rx> = LazyLock::new(|| js(r"[A-Za-z0-9+\/]{60,}={0,2}", ""));
static HEXG: LazyLock<Rx> = LazyLock::new(|| js(r"(?:[0-9a-fA-F]{2}){40,}", ""));
static PSENC: LazyLock<Rx> = LazyLock::new(|| js(r"-(?:enc|encodedcommand|ec)\s+([A-Za-z0-9+\/=]{40,})", "i"));

pub struct Ctx<'a> {
    pub hits: &'a mut Hits,
    pub f: &'a mut Vec<Finding>,
    pub kids: &'a mut Vec<ScanResult>,
    pub name: &'a str,
    pub depth: usize,
    pub seen: HashSet<String>,
    pub count: usize,
    pub layer: bool,
}

fn b64_val(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => (c - b'A') as u32,
        b'a'..=b'z' => (c - b'a') as u32 + 26,
        b'0'..=b'9' => (c - b'0') as u32 + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

/// JS: `atob(s.length % 4 ? s + '='.repeat(4 - s.length % 4) : s)`; gecersizse None.
pub fn b64bytes(s: &str) -> Option<Vec<u8>> {
    let mut v: Vec<u8> = s.bytes().collect();
    if v.len() % 4 != 0 {
        let pad = 4 - v.len() % 4;
        v.extend(std::iter::repeat_n(b'=', pad));
    }
    for _ in 0..2 {
        if v.last() == Some(&b'=') {
            v.pop();
        }
    }
    if v.len() % 4 == 1 || v.contains(&b'=') {
        return None;
    }
    let mut out = Vec::with_capacity(v.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in v {
        acc = (acc << 6) | b64_val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn hex_bytes(s: &str) -> Vec<u8> {
    s.as_bytes().chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap_or("0"), 16).unwrap_or(0)).collect()
}

fn printable_ratio(u: &[u8]) -> f64 {
    let n = u.len().min(4000);
    let p = u[..n].iter().filter(|&&b| (32..127).contains(&b) || b == 9 || b == 10 || b == 13).count();
    p as f64 / n.max(1) as f64
}

pub fn gunzip(u: &[u8], cap: u64) -> Result<Vec<u8>, ()> {
    let mut d = flate2::read::MultiGzDecoder::new(u).take(cap + 1);
    let mut out = Vec::new();
    d.read_to_end(&mut out).map_err(|_| ())?;
    if out.len() as u64 > cap {
        return Err(());
    }
    Ok(out)
}

struct Cand {
    u: Vec<u8>,
    label: &'static str,
    utf16: bool,
}

pub fn deobf(text: &str, ctx: &mut Ctx, st: &mut St, depth: usize) {
    if !st.cfg.deobf {
        return;
    }
    if depth > 3 {
        st.limit_hit("deobf", "Gizlenmiş içerik çözme derinliği (3 katman) sınırına ulaşıldı.");
        return;
    }
    if ctx.count >= 60 {
        st.limit_hit("deobf", "Çözülecek gizli blok sayısı sınırına ulaşıldı (60).");
        return;
    }
    let mut cands: Vec<Cand> = vec![];
    if let Some(p) = PSENC.capture1(text) {
        if let Some(u) = b64bytes(p) {
            cands.push(Cand { u, label: "PowerShell -enc", utf16: true });
        }
    }
    let t = if text.len() > 6_000_000 {
        let mut e = 6_000_000;
        while !text.is_char_boundary(e) {
            e -= 1;
        }
        &text[..e]
    } else {
        text
    };
    for m in B64G.find_all(t, usize::MAX) {
        if cands.len() > 40 {
            break;
        }
        let key: String = m.chars().take(80).collect();
        if !ctx.seen.insert(key) {
            continue;
        }
        if let Some(u) = b64bytes(m) {
            if u.len() >= 24 {
                cands.push(Cand { u, label: "Base64", utf16: false });
            }
        }
    }
    for m in HEXG.find_all(t, usize::MAX) {
        if cands.len() > 60 {
            break;
        }
        let key: String = m.chars().take(80).collect();
        if !ctx.seen.insert(key) {
            continue;
        }
        cands.push(Cand { u: hex_bytes(m), label: "Hex", utf16: false });
    }
    for c in cands {
        if st.stop {
            return;
        }
        ctx.count += 1;
        handle_decoded(c, ctx, st, depth);
    }
}

fn handle_decoded(c: Cand, ctx: &mut Ctx, st: &mut St, depth: usize) {
    let mut u = c.u;
    let lbl = c.label;
    if u.len() > 2 && u[0] == 0x1f && u[1] == 0x8b {
        let cap = st.entry_cap.min(st.cfg.max_total - st.bytes).max(0.0) as u64;
        match gunzip(&u, cap) {
            Ok(g) => {
                st.bytes += g.len() as f64;
                u = g;
            }
            Err(_) => return,
        }
    }
    let nested = ctx.depth + 1 <= st.cfg.depth;
    if u.len() > 64 && u[0] == 0x4d && u[1] == 0x5a {
        ctx.f.push(Finding::mk("deobf_pe", Severity::Crit, 35.0, "Kodlanmış içerikten çıkan çalıştırılabilir",
            &format!("Metin içindeki {lbl} bloğu çözüldüğünde bir Windows çalıştırılabilir dosyası (MZ) çıktı."),
            "Çıkan dosya ayrıca taranır; kaynağı güvenilmiyorsa sil.", vec![format!("{lbl}, {} bayt", u.len())], "arch"));
        if nested {
            let k = scan_buffer(&u, &format!("{} › {lbl} (çözülmüş)", ctx.name), st, ctx.depth + 1);
            ctx.kids.push(k);
        } else {
            st.limit_hit("depth", "İç içe tarama derinliği sınırı nedeniyle çözülmüş PE taranmadı.");
        }
        return;
    }
    if u.len() > 30 && u[0] == 0x50 && u[1] == 0x4b && u[2] == 3 {
        ctx.f.push(Finding::mk("deobf_zip", Severity::High, 20.0, "Kodlanmış içerikten çıkan arşiv",
            &format!("Metin içindeki {lbl} bloğu çözüldüğünde bir ZIP/JAR arşivi çıktı."),
            "Çıkan arşiv ayrıca taranır.", vec![format!("{lbl}, {} bayt", u.len())], "arch"));
        if nested {
            let k = scan_buffer(&u, &format!("{} › {lbl} (çözülmüş arşiv)", ctx.name), st, ctx.depth + 1);
            ctx.kids.push(k);
        } else {
            st.limit_hit("depth", "İç içe tarama derinliği sınırı nedeniyle çözülmüş arşiv taranmadı.");
        }
        return;
    }
    let t: Option<String> = if c.utf16 {
        let units: Vec<u16> = u.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect();
        let n = units.len().min(2000);
        let ascii = units[..n].iter().filter(|&&x| x < 128).count();
        if (ascii as f64 / n.max(1) as f64) < 0.85 { None } else { Some(String::from_utf16_lossy(&units)) }
    } else if printable_ratio(&u) > 0.85 {
        Some(utf8_decode(&u))
    } else {
        None
    };
    let Some(t) = t else { return };
    run_rules(&t, ctx.hits, &format!("{lbl}›"), Kind::Script, st_ids(st).as_ref());
    if !ctx.layer {
        ctx.layer = true;
        ctx.f.push(Finding::mk("deobf_layer", Severity::Low, 4.0, "Gizlenmiş içerik çözüldü ve tarandı",
            "Dosya içinde ".to_string().as_str(),
            "Çözülen metnin içeriğine bak.", vec![], "obf"));
        let last = ctx.f.last_mut().unwrap();
        last.why = format!("Dosya içinde {lbl} ile kodlanmış metin bulundu; çözülüp kurallardan geçirildi. Çözülen içerikte eşleşme olduysa ayrı bulgu olarak listelenir.");
        last.ev = vec![format!("{lbl} → {}", clip(&t, 100))];
    }
    deobf(&t, ctx, st, depth + 1);
}

/// Mod kural alt kumesi (hizli mod).
pub fn st_ids(st: &St) -> Option<HashSet<&'static str>> {
    st.cfg.ids.as_ref().map(|v| v.iter().map(|s| s.as_str()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atob_parity() {
        assert_eq!(b64bytes("aGVsbG8gd29ybGQ="), Some(b"hello world".to_vec()));
        assert_eq!(b64bytes("aGVsbG8gd29ybGQ"), Some(b"hello world".to_vec()));
        // uzunluk % 4 == 1 gecersiz
        assert_eq!(b64bytes("aGVsb"), None);
        // ortada '=' gecersiz
        assert_eq!(b64bytes("aG=VsbG8"), None);
    }

    #[test]
    fn gunzip_roundtrip_and_cap() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(&vec![b'A'; 10_000]).unwrap();
        let z = e.finish().unwrap();
        assert_eq!(gunzip(&z, 20_000).unwrap().len(), 10_000);
        assert!(gunzip(&z, 5_000).is_err());
    }
}
