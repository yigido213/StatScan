//! Windows PE (EXE/DLL/.NET) cekirdek analizi: baslik/bolum/import ayristirma, paketleyici ve API kalip bulgulari,
//! Authenticode imza blogu ozeti. JS karsiliklari: parsePE, peSignature, analyzePE.
//! Dosya calistirilmaz. Kaynak/surum/manifest (peExtra), .NET (netAnalyze), paketleyici veritabani, guven ve
//! disassembler analizleri HENUZ tasinmadi; arayuzde ve raporda acikca "unsupported" olarak gorunur.

use crate::deobf::{deobf, st_ids, Ctx};
use crate::engine::{find_all_mz, scan_buffer, xor_decode, xor_find_pe};
use crate::ioc::{add_ioc, finalize_ioc, IocSet};
use crate::model::{Analysis, Finding, ScanResult, Severity};
use crate::rules::{hits_to_findings, run_rules, Hits, Kind};
use crate::rx::{js, Rx};
use crate::state::St;
use crate::util::{clip, entropy, extract_strings, hex, js_round, md5_hex, sha1_hex, to_fixed2, utf8_decode};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashSet;
use std::sync::LazyLock;

fn g16(u: &[u8], o: usize) -> Option<u16> {
    u.get(o..o.checked_add(2)?).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn g32(u: &[u8], o: usize) -> Option<u32> {
    u.get(o..o.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn g64(u: &[u8], o: usize) -> Option<u64> {
    u.get(o..o.checked_add(8)?).map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

pub struct Section {
    pub name: String,
    pub vsize: u32,
    pub va: u32,
    pub rsize: u32,
    pub rptr: u32,
    pub ch: u32,
    pub ent: f64,
}

pub struct Pe {
    pub machine: u16,
    pub is64: bool,
    pub ts: u32,
    pub dll: bool,
    pub sections: Vec<Section>,
    pub imports: Vec<(String, Vec<String>)>,
    pub exports: Vec<String>,
    pub ep: u32,
    pub subsystem: u16,
    pub dll_char: u16,
    pub pe_off: usize,
    pub chk_off: usize,
    pub size_of_headers: u32,
    pub sec_dir_off: usize,
    pub cert_off: u32,
    pub cert_size: u32,
    pub overlay: usize,
    pub signed: bool,
    pub clr: bool,
    pub tls: bool,
}

fn cstr(u: &[u8], off: usize) -> String {
    let mut e = off;
    while e < u.len() && u[e] != 0 && e - off < 256 {
        e += 1;
    }
    if off >= e {
        return String::new();
    }
    u[off..e].iter().map(|&b| b as char).collect()
}

/// JS `parsePE`: bozuk/kesik yapida `None` (JS'te istisna -> `pe_bad`).
pub fn parse_pe(u: &[u8]) -> Option<Pe> {
    if u.len() < 0x40 || g16(u, 0)? != 0x5a4d {
        return None;
    }
    let pe = g32(u, 0x3c)? as usize;
    if pe + 24 > u.len() || g32(u, pe)? != 0x4550 {
        return None;
    }
    let machine = g16(u, pe + 4)?;
    let nsec = g16(u, pe + 6)? as usize;
    let ts = g32(u, pe + 8)?;
    let osz = g16(u, pe + 20)? as usize;
    let chr = g16(u, pe + 22)?;
    let oh = pe + 24;
    let is64 = g16(u, oh)? == 0x20b;
    let ep = g32(u, oh + 16)?;
    let subsystem = g16(u, oh + 68)?;
    let dll_char = g16(u, oh + 70)?;
    let size_of_headers = g32(u, oh + 60)?;
    let dd_off = oh + if is64 { 112 } else { 96 };
    let nd = g32(u, oh + if is64 { 108 } else { 92 })? as usize;
    let dd = |i: usize| -> (u32, u32) {
        if i < nd && dd_off + i * 8 + 8 <= u.len() {
            (g32(u, dd_off + i * 8).unwrap_or(0), g32(u, dd_off + i * 8 + 4).unwrap_or(0))
        } else {
            (0, 0)
        }
    };
    let mut sections: Vec<Section> = vec![];
    let mut sp = oh + osz;
    let mut end_raw = 0usize;
    let mut i = 0;
    while i < nsec && sp + 40 <= u.len() {
        let raw = &u[sp..sp + 8];
        let nm_end = raw.iter().position(|&b| b == 0).unwrap_or(8);
        let name: String = raw[..nm_end].iter().map(|&b| b as char).collect();
        let vsize = g32(u, sp + 8)?;
        let va = g32(u, sp + 12)?;
        let rsize = g32(u, sp + 16)?;
        let rptr = g32(u, sp + 20)?;
        let ch = g32(u, sp + 36)?;
        let ent = if rsize > 0 && (rptr as usize) < u.len() {
            let e = u.len().min(rptr as usize + rsize as usize);
            entropy(&u[rptr as usize..e])
        } else {
            0.0
        };
        end_raw = end_raw.max(rptr as usize + rsize as usize);
        sections.push(Section { name, vsize, va, rsize, rptr, ch, ent });
        i += 1;
        sp += 40;
    }
    let overlay = u.len().saturating_sub(end_raw);
    let r2o = |rva: u32| -> i64 {
        for s in &sections {
            let sz = s.vsize.max(s.rsize);
            if rva >= s.va && (rva as u64) < s.va as u64 + sz as u64 {
                return (rva - s.va) as i64 + s.rptr as i64;
            }
        }
        if (rva as usize) < u.len() && sections.is_empty() { rva as i64 } else { -1 }
    };
    let mut imports: Vec<(String, Vec<String>)> = vec![];
    let imp = dd(1);
    let mut io = if imp.0 != 0 { r2o(imp.0) } else { -1 };
    if io >= 0 {
        let mut n = 0;
        while n < 400 && (io as usize) + 20 <= u.len() {
            let iou = io as usize;
            let ot = g32(u, iou)?;
            let name_r = g32(u, iou + 12)?;
            let ft = g32(u, iou + 16)?;
            if name_r == 0 && ft == 0 {
                break;
            }
            let nr0 = if name_r != 0 { r2o(name_r) } else { -1 };
            let dll = if nr0 >= 0 { cstr(u, nr0 as usize).to_lowercase() } else { "?".to_string() };
            let mut to = r2o(if ot != 0 { ot } else { ft });
            let mut fns: Vec<String> = vec![];
            if to >= 0 {
                for _ in 0..3000 {
                    let step = if is64 { 8 } else { 4 };
                    if (to as usize) + step > u.len() {
                        break;
                    }
                    let v: u64 = if is64 { g64(u, to as usize)? } else { g32(u, to as usize)? as u64 };
                    if v == 0 {
                        break;
                    }
                    to += step as i64;
                    let hi = if is64 { v >= 1u64 << 63 } else { v >= 0x8000_0000 };
                    if hi {
                        fns.push(format!("#{}", v & 0xffff));
                        continue;
                    }
                    if v <= u32::MAX as u64 {
                        let no = r2o(v as u32);
                        if no >= 0 {
                            fns.push(cstr(u, no as usize + 2));
                        }
                    }
                }
            }
            match imports.iter_mut().find(|(d, _)| *d == dll) {
                Some(slot) => slot.1 = fns,
                None => imports.push((dll, fns)),
            }
            n += 1;
            io += 20;
        }
    }
    let mut exports: Vec<String> = vec![];
    let ex = dd(0);
    let eo = if ex.0 != 0 { r2o(ex.0) } else { -1 };
    if eo >= 0 && (eo as usize) + 40 <= u.len() {
        let eou = eo as usize;
        let nn = g32(u, eou + 24)? as usize;
        let nr = r2o(g32(u, eou + 32)?);
        if nr >= 0 {
            for i in 0..nn.min(500) {
                let q = r2o(g32(u, nr as usize + i * 4)?);
                if q >= 0 {
                    exports.push(cstr(u, q as usize));
                }
            }
        }
    }
    let sec = dd(4);
    let signed = sec.0 > 0 && sec.1 > 0;
    let (mut sec_dir_off, mut cert_off, mut cert_size) = (0usize, 0u32, 0u32);
    if nd > 4 {
        sec_dir_off = dd_off + 4 * 8;
        cert_off = sec.0;
        cert_size = sec.1;
    }
    Some(Pe {
        machine,
        is64,
        ts,
        dll: chr & 0x2000 != 0,
        sections,
        imports,
        exports,
        ep,
        subsystem,
        dll_char,
        pe_off: pe,
        chk_off: oh + 64,
        size_of_headers,
        sec_dir_off,
        cert_off,
        cert_size,
        overlay,
        signed,
        clr: dd(14).0 > 0,
        tls: dd(9).0 > 0,
    })
}

// ---------------------------------------------------------------- Authenticode imza blogu

#[derive(Clone, Copy)]
struct Der {
    tag: u8,
    s: usize,
    e: usize,
}

fn der_read(b: &[u8], p: usize, end: usize) -> Option<Der> {
    if p + 2 > end || p + 1 >= b.len() {
        return None;
    }
    let tag = b[p];
    let mut l = b[p + 1] as usize;
    let mut q = p + 2;
    if l & 0x80 != 0 {
        let n = l & 0x7f;
        if n == 0 || n > 4 || q + n > end {
            return None;
        }
        l = 0;
        for i in 0..n {
            l = l * 256 + *b.get(q + i)? as usize;
        }
        q += n;
    }
    if q + l > end {
        return None;
    }
    Some(Der { tag, s: q, e: q + l })
}

fn der_kids(b: &[u8], n: Der) -> Vec<Der> {
    let mut out = vec![];
    let mut p = n.s;
    while p < n.e && out.len() < 400 {
        let Some(k) = der_read(b, p, n.e) else { break };
        out.push(k);
        p = k.e;
    }
    out
}

fn der_oid(b: &[u8], n: Option<Der>) -> String {
    let Some(n) = n else { return String::new() };
    if n.tag != 6 || n.e <= n.s {
        return String::new();
    }
    let mut a: Vec<u64> = vec![];
    let mut v: u64 = 0;
    for i in n.s..n.e {
        v = v.wrapping_mul(128).wrapping_add((b[i] & 0x7f) as u64);
        if b[i] & 0x80 == 0 {
            a.push(v);
            v = 0;
        }
    }
    if a.is_empty() {
        return String::new();
    }
    let f = a.remove(0);
    let head = if f < 40 { format!("0.{f}") } else if f < 80 { format!("1.{}", f - 40) } else { format!("2.{}", f - 80) };
    if a.is_empty() { head } else { format!("{head}.{}", a.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(".")) }
}

fn der_str(b: &[u8], n: Option<Der>) -> String {
    let Some(n) = n else { return String::new() };
    let x = &b[n.s..n.e];
    if n.tag == 0x1e {
        let mut s = String::new();
        let mut i = 0;
        while i + 1 < x.len() {
            if let Some(c) = char::from_u32(((x[i] as u32) << 8) | x[i + 1] as u32) {
                s.push(c);
            } else {
                s.push('\u{fffd}');
            }
            i += 2;
        }
        return s;
    }
    utf8_decode(x)
}

fn der_time(b: &[u8], n: Option<Der>) -> String {
    let Some(n) = n else { return String::new() };
    let t: String = b[n.s..n.e].iter().map(|&c| c as char).collect();
    let d = |a: usize, z: usize| t.get(a..z).filter(|x| x.chars().all(|c| c.is_ascii_digit())).map(|x| x.to_string());
    if n.tag == 0x17 {
        if let (Some(y), Some(m), Some(dd)) = (d(0, 2), d(2, 4), d(4, 6)) {
            let yy: u32 = y.parse().unwrap_or(0);
            return format!("{}{y}-{m}-{dd}", if yy < 50 { "20" } else { "19" });
        }
    }
    if n.tag == 0x18 {
        if let (Some(y), Some(m), Some(dd)) = (d(0, 4), d(4, 6), d(6, 8)) {
            return format!("{y}-{m}-{dd}");
        }
    }
    String::new()
}

struct DName {
    s: String,
}

fn der_name(b: &[u8], n: Option<Der>) -> DName {
    let Some(n) = n else { return DName { s: String::new() } };
    let mut o: Vec<(&str, String)> = vec![];
    for rdn in der_kids(b, n) {
        for atv in der_kids(b, rdn) {
            let k = der_kids(b, atv);
            let key = match der_oid(b, k.first().copied()).as_str() {
                "2.5.4.3" => Some("CN"),
                "2.5.4.10" => Some("O"),
                "2.5.4.11" => Some("OU"),
                "2.5.4.6" => Some("C"),
                _ => None,
            };
            if let (Some(key), Some(v)) = (key, k.get(1)) {
                if !o.iter().any(|(kk, _)| *kk == key) {
                    o.push((key, clip(&der_str(b, Some(*v)), 80)));
                }
            }
        }
    }
    let s = ["CN", "O", "OU", "C"]
        .iter()
        .filter_map(|k| o.iter().find(|(kk, v)| kk == k && !v.is_empty()).map(|(kk, v)| format!("{kk}={v}")))
        .collect::<Vec<_>>()
        .join(", ");
    DName { s }
}

struct DCert {
    subject: String,
    issuer: String,
    from: String,
    to: String,
}

fn der_cert(b: &[u8], n: Der) -> Option<DCert> {
    let tbs = *der_kids(b, n).first()?;
    let k = der_kids(b, tbs);
    let i = if k.first()?.tag == 0xa0 { 1 } else { 0 };
    let val = der_kids(b, *k.get(i + 3)?);
    Some(DCert {
        subject: der_name(b, Some(*k.get(i + 4)?)).s,
        issuer: der_name(b, Some(*k.get(i + 2)?)).s,
        from: der_time(b, val.first().copied()),
        to: der_time(b, val.get(1).copied()),
    })
}

fn sig_alg(oid: &str) -> &'static str {
    match oid {
        "1.3.14.3.2.26" => "SHA-1",
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        "1.2.840.113549.2.5" => "MD5",
        _ => "",
    }
}

#[derive(Default)]
pub struct Sig {
    pub present: bool,
    pub err: Option<String>,
    pub note: Option<String>,
    pub alg_oid: String,
    pub alg: String,
    pub embedded: Option<String>,
    pub computed: Option<String>,
    pub matched: Option<bool>,
    pub signer: Option<String>,
    pub issuer: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub cert_count: usize,
    pub self_signed: bool,
}

fn pe_signature(u: &[u8], p: &Pe, st: &mut St) -> Sig {
    let mut out = Sig::default();
    if p.cert_off == 0 || p.cert_size == 0 {
        return out;
    }
    out.present = true;
    let co = p.cert_off as usize;
    let end_c = co + p.cert_size as usize;
    if co + 8 > u.len() || end_c > u.len() {
        out.err = Some("Sertifika tablosu dosya sınırlarının dışına taşıyor".into());
        return out;
    }
    let mut blob: Option<&[u8]> = None;
    let mut q = co;
    let mut nb = 0;
    while q + 8 <= end_c && nb < 8 {
        let len = g32(u, q).unwrap_or(0) as usize;
        let ty = g16(u, q + 6).unwrap_or(0);
        if len < 8 || q + len > end_c {
            break;
        }
        nb += 1;
        if ty == 2 && blob.is_none() {
            blob = Some(&u[q + 8..q + len]);
        }
        q += (len + 7) & !7;
    }
    let Some(blob) = blob else {
        out.err = Some("PKCS#7 (type 2) sertifika girdisi bulunamadı veya biçim bozuk".into());
        return out;
    };
    let parse = |out: &mut Sig| -> Result<(), String> {
        let ci = der_read(blob, 0, blob.len()).ok_or("signedData değil")?;
        let ck = der_kids(blob, ci);
        if ck.is_empty() || der_oid(blob, ck.first().copied()) != "1.2.840.113549.1.7.2" || ck.len() < 2 {
            return Err("signedData değil".into());
        }
        let sd = *der_kids(blob, ck[1]).first().ok_or("signedData gövdesi yok")?;
        let sk = der_kids(blob, sd);
        let content = *sk.get(2).ok_or("içerik yok")?;
        let cc = der_kids(blob, content);
        if der_oid(blob, cc.first().copied()) != "1.3.6.1.4.1.311.2.1.4" || cc.len() < 2 {
            return Err("SpcIndirectDataContent değil".into());
        }
        let spc = der_kids(blob, *der_kids(blob, cc[1]).first().ok_or("SpcIndirectData yok")?);
        let md = der_kids(blob, *spc.get(1).ok_or("özet bilgisi yok")?);
        let alg = der_oid(blob, der_kids(blob, *md.first().ok_or("algoritma yok")?).first().copied());
        out.alg = sig_alg(&alg).to_string();
        out.alg_oid = alg;
        let d = md.get(1).ok_or("özet değeri yok")?;
        out.embedded = Some(hex(&blob[d.s..d.e]));
        let mut certs: Vec<DCert> = vec![];
        for x in sk.iter().skip(3) {
            if x.tag == 0xa0 {
                for c in der_kids(blob, *x) {
                    if let Some(d) = der_cert(blob, c) {
                        certs.push(d);
                    }
                }
            }
        }
        out.cert_count = certs.len();
        if !certs.is_empty() {
            let leaf = certs.iter().find(|c| !certs.iter().any(|o| !std::ptr::eq(o, *c) && o.issuer == c.subject)).unwrap_or(&certs[0]);
            out.signer = Some(leaf.subject.clone());
            out.issuer = Some(leaf.issuer.clone());
            out.from = Some(leaf.from.clone());
            out.to = Some(leaf.to.clone());
            out.self_signed = certs.len() == 1 && leaf.subject == leaf.issuer;
        }
        Ok(())
    };
    if let Err(e) = parse(&mut out) {
        out.err = Some(format!("İmza yapısı ayrıştırılamadı ({e})"));
        return out;
    }
    out.present = true;
    if out.alg.is_empty() {
        out.note = Some(format!("Bilinmeyen özet algoritması ({}); karşılaştırma yapılamadı", out.alg_oid));
        return out;
    }
    if u.len() as f64 > 300e6 {
        st.skip("sighash", 1);
        out.note = Some("Dosya çok büyük; özet hesaplanmadı".into());
        return out;
    }
    let hs = (p.size_of_headers as usize).min(u.len());
    let (cs, sd2) = (p.chk_off, p.sec_dir_off);
    if !(cs > 0 && sd2 > cs && sd2 + 8 <= hs) {
        out.note = Some("Başlık düzeni beklenmedik; özet hesaplanmadı".into());
        return out;
    }
    let mut buf: Vec<u8> = Vec::with_capacity(u.len());
    buf.extend_from_slice(&u[..cs]);
    buf.extend_from_slice(&u[cs + 4..sd2]);
    buf.extend_from_slice(&u[sd2 + 8..hs]);
    let mut sum = hs;
    let mut secs: Vec<&Section> = p.sections.iter().filter(|x| x.rsize > 0).collect();
    secs.sort_by_key(|s| s.rptr);
    for s in secs {
        if s.rptr as usize >= u.len() {
            continue;
        }
        buf.extend_from_slice(&u[s.rptr as usize..u.len().min(s.rptr as usize + s.rsize as usize)]);
        sum += s.rsize as usize;
    }
    let c_end = end_c;
    if u.len() > sum {
        if co >= sum {
            buf.extend_from_slice(&u[sum..co]);
            if c_end < u.len() {
                buf.extend_from_slice(&u[c_end..]);
            }
        } else {
            buf.extend_from_slice(&u[sum..]);
        }
    }
    let computed = match out.alg.as_str() {
        "MD5" => Some(md5_hex(&buf)),
        "SHA-1" => Some(sha1_hex(&buf)),
        "SHA-256" => Some(hex(&Sha256::digest(&buf))),
        "SHA-384" => Some(hex(&Sha384::digest(&buf))),
        "SHA-512" => Some(hex(&Sha512::digest(&buf))),
        _ => None,
    };
    match computed {
        Some(c) => {
            out.matched = Some(Some(&c) == out.embedded.as_ref());
            out.computed = Some(c);
        }
        None => out.note = Some(format!("Bu ortamda {} özeti hesaplanamadı", out.alg)),
    }
    out
}

// ---------------------------------------------------------------- analiz

const GROUPS: [(&str, &[&str]); 17] = [
    ("inject", &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "NtMapViewOfSection", "SetThreadContext", "RtlCreateUserThread"]),
    ("hollow", &["NtUnmapViewOfSection", "ZwUnmapViewOfSection", "WriteProcessMemory", "SetThreadContext", "ResumeThread"]),
    ("keylog", &["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "GetRawInputData"]),
    ("antidbg", &["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "NtSetInformationThread", "OutputDebugString", "ZwQueryInformationProcess"]),
    ("net", &["InternetOpen", "InternetOpenUrl", "InternetReadFile", "HttpSendRequest", "WinHttpOpen", "WinHttpSendRequest", "URLDownloadToFile", "URLDownloadToCacheFile", "WSAStartup", "connect", "send", "recv", "getaddrinfo", "WSASocket"]),
    ("dl", &["URLDownloadToFile", "URLDownloadToCacheFile", "InternetReadFile", "WinHttpReadData"]),
    ("proc", &["CreateProcess", "ShellExecute", "ShellExecuteEx", "WinExec", "CreateProcessAsUser", "CreateProcessWithLogonW"]),
    ("crypt", &["CryptEncrypt", "BCryptEncrypt", "CryptGenKey", "CryptAcquireContext", "CryptImportKey", "CryptDeriveKey"]),
    ("enumf", &["FindFirstFile", "FindNextFile", "FindFirstFileEx"]),
    ("fileop", &["MoveFile", "MoveFileEx", "DeleteFile", "SetEndOfFile"]),
    ("clip", &["OpenClipboard", "GetClipboardData", "SetClipboardData"]),
    ("screen", &["BitBlt", "GetDC", "GetDesktopWindow", "GetWindowDC", "CreateCompatibleBitmap"]),
    ("snap", &["CreateToolhelp32Snapshot", "Process32First", "Process32Next", "Process32FirstW", "EnumProcesses"]),
    ("kill", &["TerminateProcess"]),
    ("priv", &["AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValue"]),
    ("svc", &["CreateService", "StartService", "OpenSCManager"]),
    ("reg", &["RegSetValueEx", "RegCreateKeyEx", "RegOpenKeyEx"]),
];

static SUSP_SECT: LazyLock<Rx> = LazyLock::new(|| {
    js(r"^(?:upx[0-9!]|\.upx|\.vmp\d|\.themida|\.winlice|\.enigma\d|\.aspack|\.adata|\.petite|\.nsp\d|\.mpress\d|\.pec\d?|\.packed|\.boom|\.ndata|\.yp|\.perplex|\.svkp|\.neolite|\.rmnet|\.taz|\.seau|\.shrink\d|\.kkrunchy)$", "i")
});
static PACK_STRONG: LazyLock<Rx> = LazyLock::new(|| js(r"vmp|themida|enigma|winlice", "i"));
static CLR_NAME: LazyLock<Rx> = LazyLock::new(|| js(r"^[A-Za-z_][A-Za-z0-9_]{5,40}$", ""));
static JAVA_EXE: LazyLock<Rx> = LazyLock::new(|| js(r"javaw?(?:\.exe)?", "i"));
static DOT_JAR: LazyLock<Rx> = LazyLock::new(|| js(r"\.jar\b", "i"));
static JAVA_TARGET: LazyLock<Rx> = LazyLock::new(|| js(r"\bjavaw?\.exe\b", "i"));
static PRIV_NAMES: LazyLock<Rx> = LazyLock::new(|| js(r"SeDebugPrivilege|SeBackupPrivilege|SeTcbPrivilege", "i"));
static NET_OBF: LazyLock<Rx> = LazyLock::new(|| js(r"ConfuserEx|Eazfuscator|\.NET Reactor|SmartAssembly|Dotfuscator|Babel Obfuscator|Agile\.NET|CryptoObfuscator|KoiVM|de4dot|ILProtector", "i"));
static NET_LOAD: LazyLock<Rx> = LazyLock::new(|| js(r"Assembly\.Load|Assembly\.LoadFrom|FromBase64String|GetManifestResourceStream", ""));
static FW_PYI: LazyLock<Rx> = LazyLock::new(|| js(r"PyInstaller|_MEIPASS|pyi-windows-manifest", ""));
static FW_GO: LazyLock<Rx> = LazyLock::new(|| js(r"Go build ID|runtime\.main", ""));
static FW_RUST: LazyLock<Rx> = LazyLock::new(|| js(r"rustc|RUST_BACKTRACE", ""));
static RSRC: LazyLock<Rx> = LazyLock::new(|| js(r"^\.rsrc", "i"));

fn civil_date(secs: i64) -> String {
    let z = secs.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{:02}-{:02}", if m <= 2 { y + 1 } else { y }, m, d)
}

pub struct PeOut {
    pub kind: String,
    pub info: Map<String, Value>,
    pub children: Vec<ScanResult>,
    pub analyses: Vec<Analysis>,
}

pub fn analyze_pe(u: &[u8], name: &str, st: &mut St, depth: usize, f: &mut Vec<Finding>) -> PeOut {
    let cfg = st.cfg;
    let mut children: Vec<ScanResult> = vec![];
    let mut info = Map::new();
    let Some(p) = parse_pe(u) else {
        f.push(Finding::mk("pe_bad", Severity::Low, 4.0, "Bozuk PE başlığı", "MZ imzası var ama PE yapısı tutarsız. Bu, bozuk veya elle düzenlenmiş bir dosya olabilir.", "Dosyayı bir PE editörde incele.", vec![], "pe"));
        info.insert("kind".into(), json!("PE?"));
        return PeOut { kind: "PE?".into(), info, children, analyses: vec![] };
    };
    let arch = if p.is64 { "x64".to_string() } else if p.machine == 0x14c { "x86".to_string() } else { format!("0x{:x}", p.machine) };
    let kind = if p.clr {
        format!(".NET assembly ({})", if p.is64 { "x64" } else { "x86" })
    } else {
        format!("{} ({arch})", if p.dll { "PE DLL" } else { "PE EXE" })
    };
    info.insert("kind".into(), json!(kind));
    info.insert(
        "sections".into(),
        Value::Array(
            p.sections
                .iter()
                .map(|s| json!({ "n": s.name, "size": s.rsize, "ent": to_fixed2(s.ent), "rwx": format!("{}{}", if s.ch & 0x2000_0000 != 0 { 'X' } else { '-' }, if s.ch & 0x8000_0000 != 0 { 'W' } else { '-' }) }))
                .collect(),
        ),
    );
    let import_count: usize = p.imports.iter().map(|(_, v)| v.len()).sum();
    let dlls: Vec<String> = p.imports.iter().take(30).map(|(d, _)| d.clone()).collect();
    info.insert("importCount".into(), json!(import_count));
    info.insert("dlls".into(), json!(dlls));
    info.insert("exports".into(), json!(p.exports.iter().take(20).collect::<Vec<_>>()));
    info.insert("signed".into(), json!(p.signed));
    info.insert("timestamp".into(), json!(if p.ts != 0 { civil_date(p.ts as i64) } else { "0".to_string() }));
    info.insert("overlay".into(), json!(p.overlay));
    info.insert("subsystem".into(), if p.subsystem == 2 { json!("GUI") } else if p.subsystem == 3 { json!("Konsol") } else { json!(p.subsystem) });
    let mut apis: HashSet<String> = HashSet::new();
    for (_, fns) in &p.imports {
        for x in fns {
            apis.insert(x.to_lowercase());
        }
    }
    let strs = extract_strings(u, 6, cfg.str_cap as usize);
    let text = strs.join("\n");
    st.tick();
    let ids = st_ids(st);
    let mut hits = Hits::new();
    run_rules(&text, &mut hits, "", Kind::Other, ids.as_ref());
    if cfg.deobf {
        let mut ctx = Ctx { hits: &mut hits, f, kids: &mut children, name, depth, seen: HashSet::new(), count: 0, layer: false };
        deobf(&text, &mut ctx, st, 0);
    }
    if cfg.ioc > 0 {
        let mut io = IocSet::new();
        add_ioc(&mut io, &text, cfg.ioc);
        if let Some(fi) = finalize_ioc(&io) {
            info.insert("iocs".into(), Value::Object(fi));
        }
    }
    if p.clr {
        for s in &strs {
            if CLR_NAME.is_match(s) {
                apis.insert(s.to_lowercase());
            }
        }
    }
    let has = |n: &str| -> bool {
        let l = n.to_lowercase();
        ["", "a", "w", "exa", "exw", "ex"].iter().any(|suf| apis.contains(&format!("{l}{suf}")))
    };
    let cnt = |g: &str| -> Vec<String> { GROUPS.iter().find(|(k, _)| *k == g).map(|(_, v)| v.iter().filter(|n| has(n)).map(|s| s.to_string()).collect()).unwrap_or_default() };
    hits_to_findings(&hits, f);
    let packed: Vec<&Section> = p.sections.iter().filter(|s| SUSP_SECT.is_match(&s.name)).collect();
    if !packed.is_empty() {
        let names: Vec<String> = packed.iter().map(|s| s.name.clone()).collect();
        f.push(Finding::mk("pk_packer", Severity::Med, if PACK_STRONG.is_match(&packed[0].name) { 20.0 } else { 16.0 }, "Paketleyici / koruyucu izi", &format!("Bölüm adı bilinen bir paketleyici/koruyucuya işaret ediyor ({}). Paketleme tek başına zararlı değildir; zararlılar ise analizi zorlaştırmak için sık kullanır.", names.join(", ")), "Orijinal kaynağı doğrula; gerekirse izole ortamda aç (unpack).", names, "pe"));
    }
    let hi_ent: Vec<&Section> = p.sections.iter().filter(|s| s.rsize > 4096 && s.ent > 7.2 && s.ch & 0x2000_0000 != 0).collect();
    if !hi_ent.is_empty() {
        f.push(Finding::mk("pe_highent", Severity::Med, 12.0, "Yüksek entropili kod bölümü", "Çalıştırılabilir bölüm sıkıştırılmış/şifrelenmiş gibi görünüyor (entropi > 7.2). Kod çalışırken kendini açıyor olabilir.", "Paketleyici tespiti yap (Detect It Easy) ve unpack ile incele.", hi_ent.iter().map(|s| format!("{} entropi {:.2}", s.name, s.ent)).collect(), "pe"));
    } else {
        let tot = entropy(u);
        info.insert("entropy".into(), crate::util::num_json(to_fixed2(tot)));
        if tot > 7.4 && u.len() > 50000 {
            f.push(Finding::mk("pe_highent", Severity::Low, 6.0, "Dosya genelinde yüksek entropi", "Dosyanın büyük kısmı rastgele veriye benziyor (şifrelenmiş/sıkıştırılmış olabilir).", "Gömülü kaynakları veya paketleme olasılığını kontrol et.", vec![format!("entropi {tot:.2}")], "pe"));
        }
    }
    let rwx: Vec<&Section> = p.sections.iter().filter(|s| s.ch & 0x2000_0000 != 0 && s.ch & 0x8000_0000 != 0).collect();
    if !rwx.is_empty() {
        f.push(Finding::mk("pe_rwx", Severity::Low, 6.0, "Hem yazılabilir hem çalıştırılabilir bölüm", "Kendi kodunu değiştiren veya paketli programlar bunu kullanır.", "Paketleyici izleriyle birlikte değerlendir.", rwx.iter().map(|s| s.name.clone()).collect(), "pe"));
    }
    if p.ep != 0 {
        let ep_idx = p.sections.iter().position(|s| p.ep >= s.va && (p.ep as u64) < s.va as u64 + s.vsize.max(s.rsize) as u64);
        match ep_idx {
            None => f.push(Finding::mk("pe_ep_out", Severity::Med, 10.0, "Giriş noktası bölümlerin dışında", "Program başlangıcı normal bölümlerin dışında; paketleyici veya elle yama işareti.", "PE editörde giriş noktasını incele.", vec![format!("EP RVA 0x{:x}", p.ep)], "pe")),
            Some(i) => {
                if i != 0 && p.sections.len() > 1 && !p.clr && i == p.sections.len() - 1 && p.sections.len() > 2 {
                    f.push(Finding::mk("pe_ep_last", Severity::Med, 8.0, "Giriş noktası son bölümde", "Program son bölümde başlıyor; paketli veya enfekte dosya belirtisi olabilir.", "Paketleyici tespiti yap.", vec![p.sections[i].name.clone()], "pe"));
                }
            }
        }
    }
    if p.sections.iter().any(|s| s.rsize == 0 && s.vsize > 0x10000) && !packed.is_empty() {
        f.push(Finding::mk("pe_virtual", Severity::Low, 4.0, "Diskte boş, bellekte dolan bölüm", "Paketleyicilerin kullandığı kalıp.", "—", p.sections.iter().filter(|s| s.rsize == 0 && s.vsize > 0x10000).map(|s| s.name.clone()).collect(), "pe"));
    }
    if !p.clr && import_count > 0 && import_count <= 6 && u.len() > 30000 {
        f.push(Finding::mk("pe_fewimp", Severity::Med, 10.0, "Çok az import", "Dosya büyük ama neredeyse hiç API import etmiyor. API’ler çalışma anında gizlice çözülüyor olabilir.", "Paketleyici veya shellcode yükleyici ihtimaline bak.", vec![dlls.join(", ")], "pe"));
    } else if !p.clr && import_count == 0 && u.len() > 20000 && !p.dll {
        f.push(Finding::mk("pe_noimp", Severity::Med, 10.0, "Import tablosu yok", "Çalıştırılabilir dosyada import tablosu bulunamadı.", "Paketli/özel yükleyici olabilir.", vec![], "pe"));
    }
    if p.overlay > 4096 && p.overlay as f64 / u.len() as f64 > 0.3 {
        f.push(Finding::mk("pe_overlay", Severity::Low, 5.0, "Büyük overlay verisi", &format!("Dosyanın %{}’i bölümlerin dışında ek veri. Kurulum paketleri ve yükleyiciler de böyledir.", js_round(100.0 * p.overlay as f64 / u.len() as f64)), "Overlay içinde ek yürütülebilir olup olmadığına bak.", vec![format!("{} bayt", p.overlay)], "pe"));
        if !cfg.deep_jar {
            let tail = &u[u.len() - p.overlay..];
            if let Some(&mz) = find_all_mz(tail, 4, 1).first() {
                f.push(Finding::mk("pe_overlay_mz", Severity::High, 12.0, "Overlay içinde gömülü çalıştırılabilir", "Dosyanın sonuna eklenmiş başka bir PE bulundu.", "Gömülü dosyayı çıkarıp ayrıca tara.", vec![format!("ofset +{mz}")], "pe"));
            }
        }
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
    if p.ts != 0 && !p.clr && p.ts as f64 > now + 86400.0 * 2.0 {
        f.push(Finding::mk("pe_ts_future", Severity::Low, 4.0, "Gelecek tarihli derleme zamanı", "Derleme tarihi gelecekte; sahte damga olabilir.", "—", vec![civil_date(p.ts as i64)], ""));
    }
    if p.ts == 0 {
        f.push(Finding::mk("pe_ts_zero", Severity::Info, 1.0, "Derleme zamanı sıfırlanmış", "Tekrarlanabilir derleme veya zaman damgası silinmiş olabilir.", "—", vec![], ""));
    }
    if p.dll_char & 0x40 == 0 && !p.dll {
        f.push(Finding::mk("pe_noaslr", Severity::Info, 0.0, "ASLR kapalı", "Eski/özel derleme ayarı.", "—", vec![], ""));
    }
    if p.tls {
        f.push(Finding::mk("pe_tls", Severity::Info, 1.0, "TLS callback var", "Program giriş noktasından önce kod çalıştırabilir (analiz karşıtı teknik de olabilir).", "Hata ayıklayıcıda TLS callback’lere bak.", vec![], "pe"));
    }
    if p.signed {
        let sg = if cfg.parse { Some(pe_signature(u, &p, st)) } else { None };
        match sg {
            None => f.push(Finding::mk("pe_signed", Severity::Info, 0.0, "Dijital imza bloğu var (bu modda özet denetlenmedi)", "Hızlı modda imza içeriği ayrıştırılmaz. Geçerlilik hiçbir modda doğrulanmaz; Windows’ta Özellikler → Dijital İmzalar veya signtool/sigcheck ile doğrula.", "Normal/derin modda tara veya imzayı Windows’ta doğrula.", vec![], "pe")),
            Some(sg) => {
                let err_or_note = sg.err.clone().or_else(|| sg.note.clone());
                info.insert("sig".into(), json!({
                    "alg": if sg.alg.is_empty() { Value::Null } else { json!(sg.alg) },
                    "match": sg.matched, "embedded": sg.embedded, "computed": sg.computed, "signer": sg.signer, "issuer": sg.issuer,
                    "from": sg.from, "to": sg.to, "certCount": sg.cert_count, "selfSigned": sg.self_signed, "err": err_or_note,
                }));
                let mut who: Vec<String> = vec![];
                if let Some(s) = sg.signer.as_ref().filter(|s| !s.is_empty()) { who.push(format!("İmzalayan (doğrulanmadı): {s}")); }
                if let Some(s) = sg.issuer.as_ref().filter(|s| !s.is_empty()) { who.push(format!("Veren: {s}")); }
                if let (Some(a), Some(b)) = (sg.from.as_ref().filter(|s| !s.is_empty()), sg.to.as_ref()) { who.push(format!("Sertifika tarihleri: {a} → {b}")); }
                if !sg.alg.is_empty() { who.push(format!("Özet: {}", sg.alg)); }
                const NOTE: &str = " Bu araç sertifika zincirini, iptal durumunu, zaman damgasını ve imza matematiğini DOĞRULAMAZ; yalnızca imzanın içindeki özetin dosyayla tutarlılığına bakar.";
                match sg.matched {
                    Some(true) => f.push(Finding::mk("pe_sig_ok", Severity::Info, 0.0, "İmza özeti dosyayla tutarlı (imza doğrulanmadı)", &format!("İmzanın içindeki Authenticode özeti, dosyadan hesaplanan özetle aynı: dosya imzalandıktan sonra değiştirilmemiş görünüyor.{NOTE} Çalıntı veya sahte sertifikayla atılmış bir imza da bu denetimi geçer; “imza var” güven anlamına gelmez."), "Gerçek doğrulama için Windows’ta Özellikler → Dijital İmzalar veya signtool/sigcheck kullan; imzalayanı tanıyıp tanımadığına bak.", who.clone(), "pe")),
                    Some(false) => {
                        let mut ev = who.clone();
                        ev.push(format!("gömülü: {}…", sg.embedded.as_deref().unwrap_or("").chars().take(24).collect::<String>()));
                        ev.push(format!("hesaplanan: {}…", sg.computed.as_deref().unwrap_or("").chars().take(24).collect::<String>()));
                        f.push(Finding::mk("pe_sig_mismatch", Severity::High, 18.0, "İmza özeti dosya içeriğiyle UYUŞMUYOR", &format!("Dosyada imza bloğu var, ancak imzanın içindeki özet dosyadan hesaplanan Authenticode özetiyle farklı. Dosya imzalandıktan sonra değiştirilmiş (yama/enfeksiyon) ya da başka bir dosyadan kopyalanmış bir imza taşıyor olabilir.{NOTE}"), "İmzalı olduğuna güvenme. Dosyayı resmi kaynaktan yeniden indirip hash’leri karşılaştır; Windows’ta imzayı doğrula.", ev, "pe"));
                    }
                    None => f.push(Finding::mk("pe_sig_bad", Severity::Low, if sg.err.is_some() { 4.0 } else { 0.0 }, "İmza bloğu var ama özet karşılaştırılamadı", &format!("{}.{NOTE}", err_or_note.clone().unwrap_or_else(|| "Bilinmeyen neden".into())), "İmzayı Windows’ta doğrula.", who.clone(), "pe")),
                }
                if sg.self_signed {
                    f.push(Finding::mk("pe_sig_self", Severity::Low, 3.0, "Kendinden imzalı sertifika", "İmza sertifikasının sahibi ile vereni aynı: herkes kendi adına böyle bir sertifika üretebilir.", "İmzalayana güvenmeden önce kaynağı doğrula.", who, "pe"));
                }
            }
        }
    }
    if has("CryptUnprotectData") {
        f.push(Finding::mk("pe_dpapi", Severity::Med, 10.0, "DPAPI ile veri çözme (CryptUnprotectData)", "Windows DPAPI ile şifrelenmiş veriyi çözen API import ediliyor. Tarayıcı şifre/çerez çalan yazılımlar bunu kullanır; tarayıcılar ve parola yöneticileri de kullanır.", "Tarayıcı veri yolları ve ağ göstergeleriyle birlikte değerlendir.", vec![], "cred"));
    }
    if JAVA_EXE.is_match(&text) && DOT_JAR.is_match(&text) && has("CreateProcess") {
        f.push(Finding::mk("pe_java_launcher", Severity::Low, 6.0, "Java ile .jar başlatan çalıştırılabilir", "Dosya javaw ile bir .jar çalıştıracak şekilde süreç oluşturuyor. SilentNet analizlerinde Rust yazılı bir Launcher.exe bir Fabric mod.jar’ı bu şekilde başlatır; Minecraft başlatıcıları da aynısını yapar.", "Başlatılan .jar’ı ayrıca tara; kaynağı güvenilmiyorsa çalıştırma.", vec![], "proc"));
    }
    if has("CertEnumCertificatesInStore") && !cnt("net").is_empty() {
        f.push(Finding::mk("pe_cert_enum", Severity::Low, 3.0, "Sertifika deposu okuma + ağ", "Sistem sertifika deposunu okuyup ağ API’leri kullanıyor. Bazı yükleyiciler sertifika sabitleme/doğrulama için yapar.", "Başka bulgularla birlikte değerlendir.", vec![], "net"));
    }
    if has("VirtualAllocEx") && has("WriteProcessMemory") && (has("CreateRemoteThread") || has("NtCreateThreadEx") || has("QueueUserAPC") || has("RtlCreateUserThread") || has("SetThreadContext")) {
        let mut x = Finding::mk("pe_inject", Severity::Crit, 30.0, "Süreç enjeksiyonu API zinciri", "Başka bir sürecin belleğine yazıp çalıştırmaya yarayan API’ler birlikte import ediliyor. Hile/overlay programları ve zararlılar bunu kullanır.", "Hedef süreçleri ve yazılan veriyi dinamik analizle doğrula.", cnt("inject"), "inject");
        x.java_target = JAVA_TARGET.is_match(&text);
        f.push(x);
    }
    if (has("NtUnmapViewOfSection") || has("ZwUnmapViewOfSection")) && has("WriteProcessMemory") && has("SetThreadContext") && has("ResumeThread") {
        f.push(Finding::mk("pe_hollow", Severity::Crit, 35.0, "Süreç oyma (process hollowing) kalıbı", "Süreci boşaltıp yerine kod yazma API dizisi.", "Zararlı olarak ele al.", cnt("hollow"), "inject"));
    }
    if has("SetWindowsHookEx") && (has("GetAsyncKeyState") || has("GetKeyState") || has("GetKeyboardState") || has("GetRawInputData")) {
        f.push(Finding::mk("pe_keylog", Severity::High, 25.0, "Keylogger API kombinasyonu", "Genel klavye kancası ile tuş okuma API’leri birlikte. Kısayol/oyun araçlarında da olur.", "Tuş verisinin kaydedilip gönderilmediğini kontrol et.", cnt("keylog"), "spy"));
    } else if has("GetAsyncKeyState") {
        f.push(Finding::mk("pe_keystate", Severity::Low, 4.0, "Tuş durumu okuma", "GetAsyncKeyState oyun, kısayol ve macro araçlarında sık kullanılır.", "Başka bulgularla birlikte değerlendir.", vec![], "spy"));
    }
    if (has("URLDownloadToFile") || has("URLDownloadToCacheFile")) && (has("ShellExecute") || has("WinExec") || has("CreateProcess")) {
        let mut ev = cnt("dl");
        ev.extend(cnt("proc"));
        f.push(Finding::mk("pe_dlexec", Severity::High, 25.0, "İndir ve çalıştır API’leri", "URLDownloadToFile ile süreç başlatma birlikte; indirici kalıbı.", "İndirilen adresi bul.", ev, "dl"));
    }
    let anti = cnt("antidbg");
    if anti.len() >= 3 {
        f.push(Finding::mk("pe_antidbg", Severity::Med, 12.0, "Hata ayıklayıcı tespit API’leri", "Birden fazla anti‑debug API’si. Koruma yazılımları ve zararlılar kullanır.", "Analizde hata ayıklayıcıyı gizle (ScyllaHide vb.).", anti, "evade"));
    } else if !anti.is_empty() {
        f.push(Finding::mk("pe_antidbg", Severity::Low, 3.0, "Hata ayıklayıcı tespiti", "Anti‑debug API’si import ediliyor.", "—", anti, "evade"));
    }
    if has("AdjustTokenPrivileges") && has("OpenProcessToken") && PRIV_NAMES.is_match(&text) {
        f.push(Finding::mk("pe_priv", Severity::Med, 8.0, "Ayrıcalık yükseltme (SeDebug vb.)", "Token ayrıcalığı ayarlama ve özel ayrıcalık isimleri.", "Hangi amaçla kullanıldığına bak.", vec![], "priv"));
    }
    if has("CreateService") && has("StartService") {
        f.push(Finding::mk("pe_service", Severity::Low, 6.0, "Windows servisi oluşturma", "Servis kurup başlatma; sürücü/kalıcılık amaçlı olabilir.", "Kurulum sırasında servis adını kontrol et.", vec![], "persist"));
    }
    if (has("CryptEncrypt") || has("BCryptEncrypt")) && has("FindFirstFile") && has("FindNextFile") && (has("MoveFile") || has("DeleteFile")) {
        let mut ev = cnt("crypt");
        ev.extend(cnt("enumf"));
        f.push(Finding::mk("pe_ransom_api", Severity::High, 25.0, "Dosya gezme + şifreleme + yeniden adlandırma", "Fidye yazılımlarının temel API dizisi. Yedekleme/şifreleme araçlarında da görülebilir.", "Fidye notu/uzantı string’lerine bak.", ev, "ransom"));
    }
    if has("CreateToolhelp32Snapshot") && (has("Process32First") || has("Process32Next")) && has("TerminateProcess") {
        f.push(Finding::mk("pe_proc_kill", Severity::Low, 6.0, "Süreç listeleme ve sonlandırma", "Başka programları kapatabiliyor.", "Hangi süreç adlarını aradığına bak.", vec![], "proc"));
    }
    if has("OpenClipboard") && has("GetClipboardData") && has("SetClipboardData") {
        f.push(Finding::mk("pe_clip", Severity::Med, 8.0, "Pano izleme/değiştirme", "Panoyu okuyup yazabilir (kripto adresi değiştirici kalıbı olabilir).", "Cüzdan adresi regex’lerini ara.", vec![], "spy"));
    }
    if has("BitBlt") && has("GetDesktopWindow") {
        f.push(Finding::mk("pe_screen", Severity::Low, 4.0, "Ekran görüntüsü alma", "Ekran yakalama API’leri.", "Yakalanan verinin kullanımına bak.", vec![], "spy"));
    }
    if !p.clr && !p.imports.is_empty() && has("LoadLibrary") && has("GetProcAddress") && import_count < 25 && u.len() > 40000 {
        f.push(Finding::mk("pe_dynapi", Severity::Low, 5.0, "Dinamik API çözümleme", "Yalnızca LoadLibrary/GetProcAddress ile az sayıda import.", "Paketleyici izleriyle birlikte değerlendir.", vec![], "pe"));
    }
    if !cnt("net").is_empty() {
        f.push(Finding::mk("pe_net", Severity::Info, 2.0, "Ağ API’leri", "Dosya ağ üzerinden bağlantı kurabilir.", "Bağlandığı adresleri izole ortamda gözlemle.", cnt("net").into_iter().take(5).collect(), "net"));
    }
    if p.clr {
        if NET_OBF.is_match(&text) {
            f.push(Finding::mk("pe_net_obf", Severity::Low, 8.0, ".NET obfuscator izi", ".NET gizleme araçlarının adı geçiyor. Ticari yazılımlar da kullanır.", "dnSpy/ILSpy ile aç; de4dot ile temizle.", vec![], "obf"));
        }
        if NET_LOAD.is_match(&text) {
            f.push(Finding::mk("pe_net_load", Severity::Low, 6.0, ".NET dinamik yükleme göstergeleri", "Kaynaktan veya Base64’ten assembly yükleme API’leri.", "Yüklenen verinin kaynağını bul.", vec![], "dyn"));
        }
    }
    let fw = if FW_PYI.is_match(&text) {
        "PyInstaller"
    } else if text.contains("Nuitka") {
        "Nuitka"
    } else if FW_GO.is_match(&text) {
        "Go"
    } else if FW_RUST.is_match(&text) {
        "Rust"
    } else if text.contains("Inno Setup") {
        "Inno Setup"
    } else if text.contains("Nullsoft") {
        "NSIS"
    } else {
        ""
    };
    if !fw.is_empty() {
        info.insert("framework".into(), json!(fw));
        let py = fw == "PyInstaller";
        f.push(Finding::mk("pe_fw", Severity::Info, if py { 3.0 } else { 0.0 }, &format!("{fw} ile derlenmiş görünüyor"), if py { "Python programı exe’ye paketlenmiş. İçindeki .pyc dosyaları çıkarılıp incelenebilir (pyinstxtractor)." } else { "Derleyici/paketleyici izi." }, if py { "pyinstxtractor + decompyle3 ile kaynağı çıkar." } else { "—" }, vec![], ""));
    }
    if cfg.deep_jar {
        if !p.imports.is_empty() {
            let mut parts: Vec<String> = vec![];
            for (dll, fns) in &p.imports {
                let lower = dll.to_lowercase();
                let b = ["dll", "ocx", "sys"].iter().find_map(|e| lower.strip_suffix(&format!(".{e}"))).unwrap_or(&lower).to_string();
                let b = if b.len() == lower.len() { dll.clone() } else { dll[..b.len()].to_string() };
                for x in fns {
                    parts.push(format!("{b}.{}", if let Some(o) = x.strip_prefix('#') { format!("ord{o}") } else { x.to_lowercase() }));
                }
            }
            let bytes: Vec<u8> = parts.join(",").chars().map(|c| c as u32 as u8).collect();
            info.insert("imphash".into(), json!(md5_hex(&bytes)));
        }
        let lim = p.pe_off.min(u.len());
        let mut rich = false;
        let mut i = 0x80;
        while i + 4 < lim {
            if &u[i..i + 4] == b"Rich" {
                rich = true;
                break;
            }
            i += 1;
        }
        info.insert("rich".into(), json!(rich));
        if let Some(rs) = p.sections.iter().find(|s| RSRC.is_match(&s.name)) {
            if rs.rsize > 65536 && rs.ent > 7.3 {
                f.push(Finding::mk("pe_rsrc_blob", Severity::Med, 8.0, "Büyük, yüksek entropili kaynak bölümü", &format!("Kaynak (rsrc) bölümü {} KB ve sıkıştırılmış/şifreli veri gibi görünüyor. Gömülü yük (payload) saklamak için kullanılabilir.", js_round(rs.rsize as f64 / 1024.0)), "Kaynakları bir PE aracıyla (Resource Hacker) çıkarıp incele.", vec![format!("entropi {:.2}", rs.ent)], "pe"));
            }
        }
        let mzs = find_all_mz(u, 1, 6);
        if !mzs.is_empty() {
            f.push(Finding::mk("pe_embedded", Severity::High, 14.0, "PE içinde gömülü başka bir PE", &format!("Dosyanın içinde {} adet daha PE başlığı bulundu. Kurulum paketleri meşru olarak başka dosyalar taşır; ancak bu, gizli yük taşımanın da yaygın yoludur.", mzs.len()), "Gömülü dosyalar ayrıca taranıyor; sonuçlarına bak.", mzs.iter().map(|o| format!("ofset 0x{o:x}")).collect(), "pe"));
            for &off in mzs.iter().take(4) {
                if depth < cfg.depth {
                    children.push(scan_buffer(&u[off..], &format!("{name} › gömülü PE @0x{off:x}"), st, depth + 1));
                } else {
                    st.limit_hit("depth", "İç içe tarama derinliği sınırı nedeniyle gömülü PE taranmadı.");
                    break;
                }
            }
        }
        if cfg.xor && (u.len() as f64) <= 24e6 {
            if let Some((key, start)) = xor_find_pe(u, 24_000_000) {
                f.push(Finding::mk("xor_pe", Severity::Crit, 35.0, "XOR ile gizlenmiş çalıştırılabilir", &format!("Dosyada tek baytlık XOR anahtarıyla (0x{key:x}) gizlenmiş bir PE bulundu."), "Çözülmüş içerik ayrıca taranır.", vec![format!("ofset 0x{start:x}")], "pe"));
                if depth < cfg.depth {
                    children.push(scan_buffer(&xor_decode(u, start, key), &format!("{name} › XOR çözülmüş PE"), st, depth + 1));
                }
            }
        }
    }
    info.insert("stringCount".into(), json!(strs.len()));
    let mut analyses = vec![];
    if p.clr {
        analyses.push(Analysis::led("dotnet", ".NET meta veri analizi", "unsupported", "Rust motorunda henüz taşınmadı"));
    }
    analyses.push(Analysis::led("pe-ext", "PE kaynak/sürüm/manifest, gecikmeli import, paketleyici veritabanı, güven analizi", "unsupported", "Rust motorunda henüz taşınmadı"));
    f.push(
        Finding::mk("rs_unported", Severity::Info, 0.0, "PE: bazı ileri analizler bu motor sürümünde yok",
            "PE başlıkları, importlar, bölümler, API kalıpları, paketleyici izleri ve imza özeti çözümlendi; ancak kaynak/sürüm bilgisi, gecikmeli import, paketleyici/koruyucu veritabanı, güven analizi, .NET meta verisi ve disassembler analizi Rust motorunda henüz yazılmadı. Puan eksik kapsamla hesaplandı; bu, dosyanın zararsız olduğu anlamına gelmez.",
            "Tam analiz için JS motorlu StatScan'i de kullan.", vec![], "pe")
        .with_basis("fact"),
    );
    PeOut { kind, info, children, analyses }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_date_known() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(1_700_000_000), "2023-11-14");
    }

    #[test]
    fn rejects_garbage_and_never_panics() {
        assert!(parse_pe(b"MZ").is_none());
        let mut b = vec![0u8; 0x200];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c] = 0x80;
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        let _ = parse_pe(&b);
        let mut x: u32 = 7;
        for _ in 0..5000 {
            let mut c = b.clone();
            for _ in 0..6 {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                let i = (x >> 8) as usize % c.len();
                c[i] = (x >> 24) as u8;
            }
            let _ = parse_pe(&c);
        }
    }
}
