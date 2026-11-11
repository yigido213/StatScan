//! Yardimcilar: entropi, dize cikarma, metin cozme, ozetler. JS motorundaki ayni adli islevlerin birebir karsiliklari.

use regex::Regex;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

pub fn sha1_hex(b: &[u8]) -> String {
    hex(&Sha1::digest(b))
}

pub fn md5_hex(b: &[u8]) -> String {
    use md5::Md5;
    hex(&Md5::digest(b))
}

/// Shannon entropisi (bit/bayt). JS: `entropy(u8, s, e)`; 8 MB ustunde adim atlayarak ornekler.
pub fn entropy(u8: &[u8]) -> f64 {
    let n = u8.len();
    if n == 0 {
        return 0.0;
    }
    let step = if n > 8_000_000 { n / 4_000_000 } else { 1 };
    let step = step.max(1);
    let mut c = [0u32; 256];
    let mut t = 0u64;
    let mut i = 0;
    while i < n {
        c[u8[i] as usize] += 1;
        t += 1;
        i += step;
    }
    let mut h = 0f64;
    for &x in c.iter() {
        if x > 0 {
            let p = x as f64 / t as f64;
            h -= p * p.log2();
        }
    }
    h
}

/// JS `+x.toFixed(2)` karsiligi.
pub fn to_fixed2(x: f64) -> f64 {
    let s = format!("{x:.2}");
    s.parse::<f64>().unwrap_or(x)
}

fn printable(b: u8) -> bool {
    (32..127).contains(&b) || b == 9
}

/// JS `extractStrings(u8, min, cap)`: once ASCII, sonra UTF-16LE (yalniz ASCII karakterli) dizeler.
pub fn extract_strings(u8: &[u8], min: usize, cap: usize) -> Vec<String> {
    let min = if min == 0 { 6 } else { min };
    let cap = if cap == 0 { 6_000_000 } else { cap };
    let mut out: Vec<String> = Vec::new();
    let mut tot = 0usize;
    let mut run: Vec<u8> = Vec::new();
    let flush = |run: &mut Vec<u8>, out: &mut Vec<String>, tot: &mut usize| {
        if run.len() >= min {
            let take = run.len().min(4000);
            let s: String = run[..take].iter().map(|&b| b as char).collect();
            *tot += s.len();
            out.push(s);
        }
        run.clear();
    };
    let mut i = 0;
    while i < u8.len() && tot < cap {
        let b = u8[i];
        if printable(b) {
            run.push(b);
        } else {
            flush(&mut run, &mut out, &mut tot);
        }
        i += 1;
    }
    flush(&mut run, &mut out, &mut tot);
    let lim2 = (cap as f64 * 1.5) as usize;
    let mut r2: Vec<u8> = Vec::new();
    let fl2 = |r2: &mut Vec<u8>, out: &mut Vec<String>| {
        if r2.len() >= min {
            let take = r2.len().min(4000);
            out.push(r2[..take].iter().map(|&b| b as char).collect());
        }
        r2.clear();
    };
    let mut i = 0;
    while i + 1 < u8.len() && tot < lim2 {
        let b = u8[i];
        if u8[i + 1] == 0 && printable(b) {
            r2.push(b);
        } else if !r2.is_empty() {
            fl2(&mut r2, &mut out);
        }
        i += 2;
    }
    fl2(&mut r2, &mut out);
    out
}

/// JS `\s` kumesi (ayrica `trim()` ile ayni).
pub fn is_js_space(c: char) -> bool {
    matches!(c,
        '\t' | '\n' | '\u{0b}' | '\u{0c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}'
        | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}

/// JS `clip(s, n)`: bosluklari tek bosluga indir, kirp, n karakterde kes.
pub fn clip(s: &str, n: usize) -> String {
    let mut out = String::with_capacity(s.len().min(n + 8));
    let mut prev_space = false;
    for c in s.chars() {
        if is_js_space(c) {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    let t = out.trim_matches(is_js_space);
    if t.chars().count() > n {
        let mut r: String = t.chars().take(n).collect();
        r.push('…');
        r
    } else {
        t.to_string()
    }
}

pub fn clip140(s: &str) -> String {
    clip(s, 140)
}

static MASK_WEBHOOK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(webhooks/[0-9]+/)([0-9A-Za-z_-]{6})[0-9A-Za-z_-]+").unwrap());
static MASK_BOT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(bot[0-9]+:)([0-9A-Za-z_-]{4})[0-9A-Za-z_-]+").unwrap());

/// JS `mask(s)`: webhook ve bot belirteclerini kismen gizler (her desenin ilk eslesmesi).
pub fn mask(s: &str) -> String {
    let a = MASK_WEBHOOK.replace(s, "${1}${2}…[gizlendi]");
    MASK_BOT.replace(&a, "${1}${2}…[gizlendi]").into_owned()
}

/// JS `extOf(n)`: son uzanti (kucuk harf), yoksa "".
pub fn ext_of(n: &str) -> String {
    match n.rfind('.') {
        Some(i) => {
            let e = &n[i + 1..];
            if !e.is_empty() && e.chars().all(|c| c.is_ascii_alphanumeric()) {
                e.to_ascii_lowercase()
            } else {
                String::new()
            }
        }
        None => String::new(),
    }
}

/// JS `baseName(n)`.
pub fn base_name(n: &str) -> &str {
    n.rsplit(['\\', '/']).next().unwrap_or(n)
}

/// JS `fmtN`.
pub fn fmt_n(n: f64) -> String {
    if n >= 1e9 {
        format!("{:.1} GB", n / 1e9)
    } else if n >= 1e6 {
        format!("{} MB", js_round(n / 1e6))
    } else {
        format!("{} KB", js_round(n / 1e3))
    }
}

/// JS `Math.round` (yariyi yukari yuvarlar).
pub fn js_round(x: f64) -> i64 {
    (x + 0.5).floor() as i64
}

fn utf16le_to_string(b: &[u8]) -> String {
    let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let mut s = String::from_utf16_lossy(&units);
    if b.len() % 2 == 1 {
        s.push('\u{fffd}');
    }
    s
}

/// JS `td8.decode`: UTF-8 (BOM atilir, gecersiz diziler U+FFFD).
pub fn utf8_decode(b: &[u8]) -> String {
    let b = b.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(b);
    String::from_utf8_lossy(b).into_owned()
}

/// JS `decodeText(u8)`.
pub fn decode_text(u8: &[u8]) -> String {
    if u8.len() > 2 && u8[0] == 0xff && u8[1] == 0xfe {
        return utf16le_to_string(&u8[2..]);
    }
    let mut z = 0;
    let mut i = 1;
    while i < u8.len().min(400) {
        if u8[i] == 0 {
            z += 1;
        }
        i += 2;
    }
    if z > 80 {
        return utf16le_to_string(u8);
    }
    utf8_decode(u8)
}

/// JS `latin1(u8)`: her bayt bir karakter.
pub fn latin1(u8: &[u8]) -> String {
    u8.iter().map(|&b| b as char).collect()
}

/// JS `ascii(u8, a, b)` — sinirlari kirpar.
pub fn ascii(u8: &[u8], a: usize, b: usize) -> String {
    let e = b.min(u8.len());
    if a >= e {
        return String::new();
    }
    u8[a..e].iter().map(|&x| x as char).collect()
}

/// JS `fmtN`/sayi bicimi icin: ondalik kismi olmayan f64'u tam sayi gibi yaz (JSON ciktisi icin).
pub fn num_json(x: f64) -> serde_json::Value {
    if x.fract() == 0.0 && x.abs() < 9e15 {
        serde_json::Value::from(x as i64)
    } else {
        serde_json::Number::from_f64(x).map(serde_json::Value::Number).unwrap_or(serde_json::Value::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_collapses_and_cuts() {
        assert_eq!(clip("  a \n\t b  ", 140), "a b");
        assert_eq!(clip("abcdef", 3), "abc…");
    }

    #[test]
    fn ext_and_base() {
        assert_eq!(ext_of("a/b/Foo.TXT"), "txt");
        assert_eq!(ext_of("noext"), "");
        assert_eq!(base_name("C:\\x\\y.bat"), "y.bat");
    }

    #[test]
    fn strings_ascii_and_utf16() {
        // Genis dize oncesinde iki sifir bayt: aksi halde onceki "d\0" cifti dizeye yapisir (JS motoru da boyle davranir).
        let mut b = b"\x00\x01hello world\x00\x00\x00".to_vec();
        for c in "wide str".encode_utf16() {
            b.extend_from_slice(&c.to_le_bytes());
        }
        let s = extract_strings(&b, 6, 0);
        assert!(s.iter().any(|x| x == "hello world"));
        assert!(s.iter().any(|x| x == "wide str"));
    }

    #[test]
    fn mask_hides_tokens() {
        let m = mask("https://discord.com/api/webhooks/123456/abcdefGHIJKLmnop");
        assert!(m.contains("abcdef…[gizlendi]"), "{m}");
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7u8; 100]), 0.0);
        let v: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&v) - 8.0).abs() < 1e-9);
    }
}

/// JS `td8.decode` ile ayni ama BOM korunur (TextDecoder varsayilani BOM atar; ZIP adlarinda JS de atar -> burada da atilir).
pub fn utf8_decode_keep_bom(b: &[u8]) -> String {
    utf8_decode(b)
}
