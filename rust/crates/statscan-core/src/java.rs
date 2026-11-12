//! Java class ayristirma, bytecode cagri/akis analizi ve JAR analizi.
//! JS karsiliklari: parseClass, JAVA_APIS, flowAdd/flowFindings, analyzeJar, mcModChecks.
//! Dosya ASLA calistirilmaz; class dosyalari yalniz bayt olarak okunur.

use crate::deobf::{deobf, st_ids, Ctx};
use crate::engine::{scan_buffer, xor_decode, xor_find_pe};
use crate::ioc::{add_ioc, finalize_ioc, IocSet, BENIGN};
use crate::model::{Finding, ScanResult, Severity};
use crate::rules::{hits_to_findings, run_rules, Hits, Kind};
use crate::rx::{js, Rx};
use crate::state::St;
use crate::util::{base_name, clip, entropy, ext_of, js_round, latin1, utf8_decode};
use crate::zip::{read_budget, Entry};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

// ---------------------------------------------------------------- class ayristirma

enum Cp {
    Utf8(String),
    R1 { t: u8, a: u16 },
    R2 { t: u8, a: u16, b: u16 },
}

pub struct CodeM {
    pub n: String,
    pub d: String,
    pub start: usize,
    pub end: usize,
}

pub struct Class {
    pub name: String,
    pub sup: String,
    pub ifaces: Vec<String>,
    pub utf8: Vec<String>,
    pub strings: Vec<String>,
    pub refs: Vec<String>,
    pub methods: Vec<String>,
    pub code: Vec<CodeM>,
    pub major: u16,
    cp: Vec<Option<Cp>>,
}

fn g16(u: &[u8], p: usize) -> Option<u16> {
    u.get(p..p.checked_add(2)?).map(|b| u16::from_be_bytes([b[0], b[1]]))
}
fn g32(u: &[u8], p: usize) -> Option<u32> {
    u.get(p..p.checked_add(4)?).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

impl Class {
    fn u(&self, i: usize) -> &str {
        match self.cp.get(i) {
            Some(Some(Cp::Utf8(s))) => s,
            _ => "",
        }
    }
    fn cls(&self, i: usize) -> &str {
        match self.cp.get(i) {
            Some(Some(Cp::R1 { a, .. })) | Some(Some(Cp::R2 { a, .. })) => self.u(*a as usize),
            _ => "",
        }
    }
    fn nat(&self, i: usize) -> (&str, &str) {
        match self.cp.get(i) {
            Some(Some(Cp::R2 { a, b, .. })) => (self.u(*a as usize), self.u(*b as usize)),
            Some(Some(Cp::R1 { a, .. })) => (self.u(*a as usize), ""),
            _ => ("", ""),
        }
    }
    /// Metot referansi (Methodref/InterfaceMethodref): (sinif, ad, tanimlayici).
    pub fn mref(&self, i: usize) -> Option<(String, String, String)> {
        match self.cp.get(i) {
            Some(Some(Cp::R2 { t, a, b })) if *t == 10 || *t == 11 => {
                let x = self.nat(*b as usize);
                Some((self.cls(*a as usize).to_string(), x.0.to_string(), x.1.to_string()))
            }
            _ => None,
        }
    }
    pub fn cp_str(&self, i: usize) -> &str {
        match self.cp.get(i) {
            Some(Some(Cp::R1 { t: 8, a })) => self.u(*a as usize),
            _ => "",
        }
    }
}

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// JS `parseClass(u8, withCode)`. Gecersiz/bozuk girdide `None` (JS'te null/istisna).
pub fn parse_class(u: &[u8], with_code: bool) -> Option<Class> {
    if u.len() < 10 || g32(u, 0)? != 0xcafe_babe {
        return None;
    }
    let n = g16(u, 8)? as usize;
    let mut cp: Vec<Option<Cp>> = (0..n).map(|_| None).collect();
    let mut p = 10usize;
    let mut i = 1usize;
    while i < n {
        let t = *u.get(p)?;
        p += 1;
        match t {
            1 => {
                let l = g16(u, p)? as usize;
                let s = p + 2;
                let e = (p + 2 + l).min(u.len());
                let b: &[u8] = if s <= e { &u[s..e] } else { &[] };
                cp[i] = Some(Cp::Utf8(utf8_decode(b)));
                p += 2 + l;
            }
            3 | 4 => p += 4,
            5 | 6 => {
                p += 8;
                i += 1;
            }
            7 | 8 | 16 | 19 | 20 => {
                cp[i] = Some(Cp::R1 { t, a: g16(u, p)? });
                p += 2;
            }
            9 | 10 | 11 | 12 | 17 | 18 => {
                cp[i] = Some(Cp::R2 { t, a: g16(u, p)?, b: g16(u, p + 2)? });
                p += 4;
            }
            15 => p += 3,
            _ => return None,
        }
        i += 1;
    }
    let mut c = Class {
        name: String::new(),
        sup: String::new(),
        ifaces: vec![],
        utf8: vec![],
        strings: vec![],
        refs: vec![],
        methods: vec![],
        code: vec![],
        major: g16(u, 6)?,
        cp,
    };
    for i in 1..n {
        match &c.cp[i] {
            Some(Cp::Utf8(s)) => {
                if utf16_len(s) >= 4 {
                    let s = s.clone();
                    c.utf8.push(s);
                }
            }
            Some(Cp::R1 { t: 8, a }) => {
                let s = c.u(*a as usize).to_string();
                c.strings.push(s);
            }
            Some(Cp::R1 { t: 7, a }) => {
                let s = format!("C:{}", c.u(*a as usize));
                c.refs.push(s);
            }
            Some(Cp::R2 { t, a, b }) if *t == 9 || *t == 10 || *t == 11 => {
                let s = format!("{}.{}", c.cls(*a as usize), c.nat(*b as usize).0);
                c.refs.push(s);
            }
            _ => {}
        }
    }
    p += 2;
    c.name = c.cls(g16(u, p)? as usize).to_string();
    p += 2;
    c.sup = c.cls(g16(u, p)? as usize).to_string();
    p += 2;
    let ic = g16(u, p)? as usize;
    p += 2;
    for i in 0..ic {
        let s = c.cls(g16(u, p + i * 2)? as usize).to_string();
        c.ifaces.push(s);
    }
    p += ic * 2;
    let mut code: Vec<CodeM> = vec![];
    let mut methods: Vec<String> = vec![];
    {
        let cr = &c;
        let mut run = || -> Option<()> {
            for k in 0..2 {
                let cnt = g16(u, p)? as usize;
                p += 2;
                for _ in 0..cnt {
                    let nm = cr.u(g16(u, p + 2)? as usize).to_string();
                    let ds = cr.u(g16(u, p + 4)? as usize).to_string();
                    let ac = g16(u, p + 6)? as usize;
                    p += 8;
                    for _ in 0..ac {
                        let len = g32(u, p + 2)? as usize;
                        if with_code && k == 1 && len >= 12 && cr.u(g16(u, p)? as usize) == "Code" {
                            let cl = g32(u, p + 10)? as usize;
                            if cl > 0 && p + 14 + cl <= u.len() {
                                code.push(CodeM { n: nm.clone(), d: ds.clone(), start: p + 14, end: p + 14 + cl });
                            }
                        }
                        p += 6 + len;
                    }
                    if k == 1 {
                        methods.push(format!("{nm}{ds}"));
                    }
                }
            }
            Some(())
        };
        let _ = run();
    }
    c.code = code;
    c.methods = methods;
    if !with_code {
        c.cp.clear();
    }
    Some(c)
}

// ---------------------------------------------------------------- API kaliplari

pub static JAVA_APIS: LazyLock<Vec<(&'static str, Rx)>> = LazyLock::new(|| {
    let t = [
        ("exec", r"^java\/lang\/Runtime\.exec$"),
        ("pb", r"^java\/lang\/ProcessBuilder\.(start|command)$"),
        ("urlcl", r"^java\/net\/URLClassLoader\.<init>$"),
        ("defcls", r"\.(defineClass|defineAnonymousClass|defineHiddenClass)$"),
        ("unsafe", r"^(sun\/misc|jdk\/internal\/misc)\/Unsafe\."),
        ("sock", r"^java\/net\/(Socket|ServerSocket|DatagramSocket)\.<init>$"),
        ("urlconn", r"^java\/net\/URL\.(openConnection|openStream)$"),
        ("httpc", r"^java\/net\/http\/HttpClient\.(newHttpClient|newBuilder)$"),
        ("okhttp", r"^okhttp3\/OkHttpClient\.<init>$"),
        ("cipher", r"^javax\/crypto\/Cipher\.getInstance$"),
        ("b64", r"^java\/util\/Base64\.get(Decoder|MimeDecoder|UrlDecoder)$"),
        ("getenv", r"^java\/lang\/System\.getenv$"),
        ("robot", r"^java\/awt\/Robot\.(<init>|createScreenCapture)$"),
        ("clip", r"^java\/awt\/datatransfer\/Clipboard\.getContents$"),
        ("nativeload", r"^java\/lang\/(System|Runtime)\.(load|loadLibrary)$"),
        ("scripteng", r"^javax\/script\/ScriptEngineManager\.<init>$"),
        ("reflinv", r"^java\/lang\/reflect\/Method\.invoke$"),
        ("forname", r"^java\/lang\/Class\.forName$"),
        ("hook", r"^java\/lang\/Runtime\.addShutdownHook$"),
        ("instr", r"^java\/lang\/instrument\/"),
        ("setop", r"\.setOp$"),
        ("dispatch", r"\.dispatchCommand$"),
        ("fileout", r"^java\/io\/FileOutputStream\.<init>$|^java\/nio\/file\/Files\.(write|copy|newOutputStream|writeString)$"),
        ("filedel", r"^java\/nio\/file\/Files\.(delete|deleteIfExists|walkFileTree)$"),
        ("sqlite", r"^(org\/sqlite\/|java\/sql\/DriverManager\.getConnection)"),
        ("keyhook", r"^com\/github\/kwhat\/jnativehook\/"),
        ("jna", r"^com\/sun\/jna\/Native\."),
        ("desktop", r"^java\/awt\/Desktop\.(browse|open)$"),
        ("tlsmgr", r"^C:javax\/net\/ssl\/X509(?:Extended)?TrustManager$"),
        ("hostver", r"^C:javax\/net\/ssl\/HostnameVerifier$|HttpsURLConnection\.setDefaultHostnameVerifier$"),
        ("zipw", r"^java\/util\/(?:zip\/ZipOutputStream|jar\/JarOutputStream)\.<init>$"),
        ("mctoken", r"\.(getAccessToken|getSessionId)$"),
        ("osname", r"^java\/lang\/System\.getProperty$"),
    ];
    t.iter().map(|(id, re)| (*id, js(re, ""))).collect()
});

// Bytecode akis bitleri
const NET: u32 = 1;
const FILEW: u32 = 2;
const FILER: u32 = 4;
const EXEC: u32 = 8;
const DYN: u32 = 16;
const NAT: u32 = 32;
const B64: u32 = 64;
const CIPHER: u32 = 128;
const TOKEN: u32 = 256;
const SBROWSER: u32 = 512;
const SDISCORD: u32 = 1024;
const SLAUNCH: u32 = 2048;
const SWALLET: u32 = 4096;
const SSH: u32 = 8192;
const SCREEN: u32 = 16384;
const CLIP: u32 = 32768;
const KEY: u32 = 65536;
const ZIPW: u32 = 131072;
const EXFILCH: u32 = 262144;
const DOH: u32 = 524288;

fn flow_of(id: &str) -> u32 {
    match id {
        "sock" | "urlconn" | "httpc" | "okhttp" => NET,
        "fileout" => FILEW,
        "exec" | "pb" => EXEC,
        "urlcl" | "defcls" | "unsafe" => DYN,
        "nativeload" | "jna" => NAT,
        "b64" => B64,
        "cipher" => CIPHER,
        "mctoken" => TOKEN,
        "robot" => SCREEN,
        "clip" => CLIP,
        "keyhook" => KEY,
        "zipw" => ZIPW,
        _ => 0,
    }
}

static FILER_RE: LazyLock<Rx> = LazyLock::new(|| {
    js(r"^java\/io\/FileInputStream\.<init>$|^java\/nio\/file\/Files\.(?:readAllBytes|readString|newInputStream|readAllLines|lines|walk|list|newBufferedReader)$|^java\/io\/File\.(?:listFiles|list)$", "")
});
static STRTAG: LazyLock<Vec<(u32, Rx)>> = LazyLock::new(|| {
    vec![
        (SBROWSER, js(r"Login Data|Local State|[\\/]Cookies\b|Web Data|logins\.json|key4\.db|Chrome[\\/]User Data|BraveSoftware|Opera Software|Microsoft[\\/]Edge", "i")),
        (SDISCORD, js(r"leveldb|[\\/]Local Storage[\\/]|discordcanary|discordptb|discord_desktop_core", "i")),
        (SLAUNCH, js(r"launcher_accounts|launcher_profiles|usercache\.json|\.lunarclient|[\\/]\.feather\b|\baccounts\.json", "i")),
        (SWALLET, js(r"wallet\.dat|[\\/]Exodus[\\/]|Electrum|MetaMask|[\\/]Atomic[\\/]", "")),
        (SSH, js(r"\.ssh[\\/]|\bid_rsa\b|\bid_ed25519\b|\.aws[\\/]credentials|\.git-credentials|\.npmrc", "")),
        (EXFILCH, js(r"discord(?:app)?\.com\/api\/webhooks\/|api\.telegram\.org\/bot|pastebin\.com\/raw|transfer\.sh|anonfiles|gofile\.io|webhook\.site|\.ngrok(?:-free)?\.(?:io|app|dev)", "i")),
        (DOH, js(r"dns\.google\/resolve|cloudflare-dns\.com\/dns-query|application\/dns-json|\beth_(?:call|getStorageAt)\b", "i")),
    ]
});
static URL_HOST: LazyLock<Rx> = LazyLock::new(|| js(r"^https?:\/\/([^\/:?#\s]+)", "i"));
static TM_IFACE: LazyLock<Rx> = LazyLock::new(|| js(r"^javax\/net\/ssl\/X509(?:Extended)?TrustManager$", ""));

const FT_LABEL: [(u32, &str); 18] = [
    (TOKEN, "oturum token’ı"),
    (SBROWSER, "tarayıcı veri yolu"),
    (SDISCORD, "Discord depolama yolu"),
    (SLAUNCH, "launcher hesap dosyası"),
    (SWALLET, "cüzdan yolu"),
    (SSH, "SSH/bulut kimlik dosyası"),
    (NET, "ağ bağlantısı"),
    (EXFILCH, "webhook/bot/paste kanalı"),
    (FILEW, "dosya yazma"),
    (EXEC, "komut çalıştırma"),
    (DYN, "dinamik sınıf yükleme"),
    (NAT, "native yükleme"),
    (B64, "Base64 çözme"),
    (CIPHER, "şifre çözme"),
    (SCREEN, "ekran yakalama"),
    (CLIP, "pano"),
    (KEY, "tuş dinleme"),
    (DOH, "gizli C2 çözümleme"),
];

fn ft_names(m: u32, want: u32) -> Vec<&'static str> {
    FT_LABEL.iter().filter(|(b, _)| m & b != 0 && want & b != 0).map(|(_, l)| *l).collect()
}

/// Bytecode islem kodu uzunluklari (degisken uzunlukluar ayri islenir).
fn oplen() -> [i32; 256] {
    let mut t = [1i32; 256];
    for o in [0x10, 0x12, 0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3a, 0xa9, 0xbc] {
        t[o] = 2;
    }
    for o in [0x11, 0x13, 0x14, 0x84, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xbb, 0xbd, 0xc0, 0xc1, 0xc6, 0xc7] {
        t[o] = 3;
    }
    for o in 0x99..=0xa8 {
        t[o] = 3;
    }
    t[0xc5] = 4;
    for o in [0xb9, 0xba, 0xc8, 0xc9] {
        t[o] = 5;
    }
    t
}
static OPLEN: LazyLock<[i32; 256]> = LazyLock::new(oplen);

fn ref_mask(r: &str, cache: &mut HashMap<String, u32>) -> u32 {
    if let Some(&m) = cache.get(r) {
        return m;
    }
    let mut m = 0;
    for (id, re) in JAVA_APIS.iter() {
        let f = flow_of(id);
        if f != 0 && re.is_match(r) {
            m |= f;
        }
    }
    if FILER_RE.is_match(r) {
        m |= FILER;
    }
    cache.insert(r.to_string(), m);
    m
}

fn str_mask(s: &str) -> (u32, String) {
    let l = utf16_len(s);
    if !(4..=600).contains(&l) {
        return (0, String::new());
    }
    let mut m = 0;
    for (b, re) in STRTAG.iter() {
        if re.is_match(s) {
            m |= b;
        }
    }
    let h = URL_HOST.capture1(s).map(|x| x.to_lowercase()).unwrap_or_default();
    (m, h)
}

#[derive(Default)]
struct Flow {
    keys: Vec<String>,
    index: HashMap<String, usize>,
    mask: Vec<u32>,
    calls: Vec<Vec<String>>,
    hosts: Vec<Vec<String>>,
    indy: Vec<bool>,
    cls_idx: Vec<usize>,
    name_of: Vec<String>,
    cls_names: Vec<String>,
    lam: HashMap<usize, Vec<usize>>,
    trust: Vec<(String, String, String)>,
    cache: HashMap<String, u32>,
    capped: bool,
    skipped: usize,
}

const FLOW_MAX_METHODS: usize = 150_000;

fn i32at(b: &[u8], q: usize) -> i32 {
    let g = |k: usize| b.get(q + k).copied().unwrap_or(0) as u32;
    ((g(0) << 24) | (g(1) << 16) | (g(2) << 8) | g(3)) as i32
}

fn flow_add(fl: &mut Flow, c: &Class, data: &[u8]) {
    let ci = fl.cls_names.len();
    fl.cls_names.push(c.name.clone());
    if c.cp.is_empty() {
        return;
    }
    let is_tm = c.ifaces.iter().any(|x| TM_IFACE.is_match(x)) || c.sup == "javax/net/ssl/X509ExtendedTrustManager";
    let ol = &*OPLEN;
    for m in &c.code {
        if fl.keys.len() >= FLOW_MAX_METHODS {
            fl.capped = true;
            fl.skipped += 1;
            continue;
        }
        let b = &data[m.start..m.end];
        let n = b.len();
        let mut pc = 0usize;
        let mut mask = 0u32;
        let mut indy = false;
        let mut ninv = 0usize;
        let mut athrow = false;
        let mut calls: Vec<String> = vec![];
        let mut hosts: Vec<String> = vec![];
        while pc < n {
            let op = b[pc];
            let mut len = ol[op as usize];
            if (0xb6..=0xb9).contains(&op) {
                if pc + 2 < n {
                    if let Some((o, nn, d)) = c.mref(((b[pc + 1] as usize) << 8) | b[pc + 2] as usize) {
                        ninv += 1;
                        let r = format!("{o}.{nn}");
                        mask |= ref_mask(&r, &mut fl.cache);
                        if calls.len() < 48 {
                            calls.push(format!("{r}{d}"));
                        }
                    }
                }
            } else if op == 0xba {
                indy = true;
                ninv += 1;
            } else if op == 0x12 || op == 0x13 {
                if pc + 2 < n {
                    let idx = if op == 0x12 { b[pc + 1] as usize } else { ((b[pc + 1] as usize) << 8) | b[pc + 2] as usize };
                    let sx = c.cp_str(idx);
                    if !sx.is_empty() {
                        let (tm, h) = str_mask(sx);
                        mask |= tm;
                        if !h.is_empty() && hosts.len() < 6 && !hosts.contains(&h) {
                            hosts.push(h);
                        }
                    }
                }
            } else if op == 0xbf {
                athrow = true;
            } else if op == 0xaa {
                let q = (pc + 4) & !3;
                if q + 12 > n {
                    break;
                }
                let cnt = i32at(b, q + 8) as i64 - i32at(b, q + 4) as i64 + 1;
                if !(0..=65536).contains(&cnt) {
                    break;
                }
                len = (q + 12 + cnt as usize * 4 - pc) as i32;
            } else if op == 0xab {
                let q = (pc + 4) & !3;
                if q + 8 > n {
                    break;
                }
                let np = i32at(b, q + 4) as i64;
                if !(0..=65536).contains(&np) {
                    break;
                }
                len = (q + 8 + np as usize * 8 - pc) as i32;
            } else if op == 0xc4 {
                len = if b.get(pc + 1) == Some(&0x84) { 6 } else { 4 };
            }
            if len <= 0 {
                break;
            }
            pc += len as usize;
        }
        let key = format!("{}.{}{}", c.name, m.n, m.d);
        let i = fl.keys.len();
        fl.keys.push(key.clone());
        fl.index.insert(key, i);
        fl.mask.push(mask);
        fl.calls.push(calls);
        fl.hosts.push(hosts);
        fl.indy.push(indy);
        fl.cls_idx.push(ci);
        fl.name_of.push(m.n.clone());
        if m.n.starts_with("lambda$") {
            fl.lam.entry(ci).or_default().push(i);
        }
        if fl.trust.len() < 12 {
            if is_tm && m.n == "checkServerTrusted" && ninv == 0 && !athrow && n <= 8 {
                fl.trust.push((c.name.clone(), m.n.clone(), "gövde boş: sunucu sertifikası hiç denetlenmiyor".into()));
            }
            if m.d == "(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z" && n == 2 && b[0] == 0x04 && b[1] == 0xac {
                fl.trust.push((c.name.clone(), m.n.clone(), "her zaman true döndürüyor: ana makine adı denetlenmiyor".into()));
            }
        }
    }
}

fn flow_findings(fl: &Flow, d: usize, ctx_mod: bool) -> (Vec<Finding>, Map<String, Value>) {
    let n = fl.keys.len();
    let mut out_f: Vec<Finding> = vec![];
    let mut info = Map::new();
    info.insert("methods".into(), json!(n));
    info.insert("depth".into(), json!(d));
    info.insert("capped".into(), json!(fl.capped));
    info.insert("edges".into(), json!(0));
    info.insert("trust".into(), json!(fl.trust.len()));
    if n == 0 {
        return (out_f, info);
    }
    let mut edges: Vec<Vec<usize>> = Vec::with_capacity(n);
    let mut e_total = 0usize;
    for i in 0..n {
        let mut out: Vec<usize> = vec![];
        for k in &fl.calls[i] {
            if let Some(&j) = fl.index.get(k) {
                if j != i && !out.contains(&j) {
                    out.push(j);
                }
            }
        }
        if fl.indy[i] {
            if let Some(lam) = fl.lam.get(&fl.cls_idx[i]) {
                for &j in lam.iter().take(12) {
                    if j != i && !out.contains(&j) {
                        out.push(j);
                    }
                }
            }
        }
        e_total += out.len();
        edges.push(out);
    }
    info.insert("edges".into(), json!(e_total));

    const SRCM: u32 = TOKEN | SBROWSER | SDISCORD | SLAUNCH | SWALLET | SSH;
    const SINK: u32 = NET | EXFILCH;
    struct Rule {
        id: &'static str,
        want: u32,
        ok: fn(u32) -> bool,
    }
    let rules = [
        Rule { id: "jf_steal", want: SRCM | SINK | DOH, ok: |m| m & SRCM != 0 && m & SINK != 0 },
        Rule { id: "jf_dlexec", want: NET | FILEW | EXEC | DYN | NAT, ok: |m| m & NET != 0 && m & FILEW != 0 && m & (EXEC | DYN | NAT) != 0 },
        Rule { id: "jf_payload", want: B64 | CIPHER | DYN, ok: |m| m & (B64 | CIPHER) != 0 && m & DYN != 0 },
        Rule { id: "jf_spy", want: SCREEN | CLIP | KEY | SINK, ok: |m| m & (SCREEN | CLIP | KEY) != 0 && m & SINK != 0 },
    ];
    let mut levels: Vec<Vec<u32>> = vec![fl.mask.clone()];
    let mut lev: Vec<Vec<i8>> = rules.iter().map(|_| vec![-1i8; n]).collect();
    let mark = |d: usize, levels: &Vec<Vec<u32>>, lev: &mut Vec<Vec<i8>>| {
        let cur = &levels[d];
        for (r, rule) in rules.iter().enumerate() {
            for i in 0..n {
                if lev[r][i] < 0 && (rule.ok)(cur[i]) {
                    lev[r][i] = d as i8;
                }
            }
        }
    };
    mark(0, &levels, &mut lev);
    for dd in 1..=d {
        let prev = &levels[dd - 1];
        let mut nx = prev.clone();
        for i in 0..n {
            for &j in &edges[i] {
                nx[i] |= prev[j];
            }
        }
        levels.push(nx);
        mark(dd, &levels, &mut lev);
    }
    let nm = |i: usize| format!("{}.{}", base_name(&fl.cls_names[fl.cls_idx[i]]), fl.name_of[i]);
    let reach_hosts = |i: usize, l: usize| -> Vec<String> {
        let mut seen: HashSet<usize> = HashSet::new();
        seen.insert(i);
        let mut fr = vec![i];
        let mut hs: Vec<String> = fl.hosts[i].clone();
        for _ in 0..l {
            let mut nx = vec![];
            for &x in &fr {
                for &j in &edges[x] {
                    if seen.insert(j) {
                        nx.push(j);
                        for h in &fl.hosts[j] {
                            if !hs.contains(h) {
                                hs.push(h.clone());
                            }
                        }
                    }
                }
            }
            fr = nx;
        }
        hs
    };
    struct T {
        d: (Severity, f64, &'static str),
        c: (Severity, f64, &'static str),
        cat: &'static str,
    }
    let tmeta = |id: &str| -> T {
        match id {
            "jf_steal" => T { d: (Severity::High, 22.0, "Hassas veri erişimi ve ağ gönderimi aynı metotta"), c: (Severity::Med, 12.0, "Hassas veri erişimi ve ağ gönderimi aynı çağrı zincirinde"), cat: "net" },
            "jf_dlexec" => T { d: (Severity::High, 18.0, "Ağdan indirme + dosya yazma + çalıştırma/yükleme aynı metotta"), c: (Severity::Med, 9.0, "Ağdan indirme + dosya yazma + çalıştırma/yükleme aynı çağrı zincirinde"), cat: "proc" },
            "jf_payload" => T { d: (Severity::Med, 12.0, "Kodlanmış/şifreli veriyi çözüp dinamik sınıf yükleme aynı metotta"), c: (Severity::Low, 5.0, "Kodlanmış/şifreli veriyi çözüp dinamik sınıf yükleme aynı çağrı zincirinde"), cat: "dyn" },
            _ => T { d: (Severity::Med, 10.0, "Ekran/pano/tuş verisi ve ağ gönderimi aynı metotta"), c: (Severity::Low, 4.0, "Ekran/pano/tuş verisi ve ağ gönderimi aynı çağrı zincirinde"), cat: "spy" },
        }
    };
    let why = |id: &str, dd: usize| -> String {
        match id {
            "jf_steal" => format!("Bytecode’da aynı metot (veya en fazla {dd} çağrı adımı) içinde hem hassas veri kaynağı (oturum token’ı; tarayıcı, Discord, launcher, cüzdan veya SSH yolu) hem de ağ gönderim yeteneği bulundu. Bu, verinin gerçekten gönderildiğini KANITLAMAZ (gerçek veri akışı izlenmez); ancak stealer’ların temel kalıbıdır ve dosya düzeyindeki yakınlıktan daha güçlü bir sinyaldir."),
            "jf_dlexec" => "Ağ okuma, dosya yazma ve komut çalıştırma/dinamik yükleme/native yükleme aynı metotta (veya yakın çağrı zincirinde). İndir-yaz-çalıştır, downloader/dropper kalıbıdır. İndirilen verinin ne olduğu ve çalıştırılıp çalıştırılmadığı statik olarak kanıtlanamaz.".into(),
            "jf_payload" => "Base64 veya şifre çözme ile dinamik sınıf yükleme (defineClass/URLClassLoader/Unsafe) aynı metotta. Şifreli yükü çözüp belleğe yükleyen loader kalıbına benzer.".into(),
            _ => "Ekran yakalama, pano okuma veya global tuş dinleme ile ağ gönderimi aynı metotta (veya yakın çağrı zincirinde).".into(),
        }
    };
    let act = |id: &str| -> &'static str {
        match id {
            "jf_steal" => "Kanıt satırlarındaki metotları bir decompiler’da (CFR, Vineflower, JADX) aç; token/yol değerinin istek gövdesine ya da URL’ye yazılıp yazılmadığına ve adresin kime ait olduğuna bak. Çalıştırma.",
            "jf_dlexec" => "İndirilen adresi ve yazılan dosyanın çalıştırılıp çalıştırılmadığını decompiler’da doğrula; hash/imza denetimi var mı bak.",
            "jf_payload" => "Çözülen verinin kaynağını ve yüklenen sınıfı decompiler’da bul.",
            _ => "Yakalanan verinin hangi adrese gittiğine bak.",
        }
    };
    let fpt = |id: &str| -> &'static str {
        match id {
            "jf_steal" => "Alt manager / giriş modları ve Mojang/Microsoft oturumu doğrulayan kodlar oturum bilgisini meşru sunuculara gönderir. Adresler sabit ve bilinen-güvenli listedeyse bulgu otomatik düşürülür (jf_steal_known); dinamik/gizli adres veya webhook/bot/paste kanalı varsa ciddiye al.",
            "jf_dlexec" => "Otomatik güncelleyiciler, kütüphane indiren mod yükleyiciler ve kurulum araçları aynı kalıbı gösterir; asıl soru adresin sabit/güvenilir olup olmadığı ve indirilen dosyanın hash/imza ile doğrulanıp doğrulanmadığıdır.",
            "jf_payload" => "Bazı sınıf yükleyiciler, korumalı ticari mod yükleyicileri ve eklenti sistemleri şifreli/sıkıştırılmış sınıf çözüp yükler.",
            _ => "Ekran görüntüsü yükleme, uzaktan yardım, ekran paylaşımı ve pano paylaşım özellikleri meşru olarak aynı kalıbı gösterir.",
        }
    };
    const STRONG: u32 = SBROWSER | SDISCORD | SWALLET | SSH | EXFILCH;
    for (r, rule) in rules.iter().enumerate() {
        let id = rule.id;
        let mut direct: Vec<usize> = vec![];
        let mut chain: Vec<usize> = vec![];
        for i in 0..n {
            let l = lev[r][i];
            if l < 0 {
                continue;
            }
            if l == 0 {
                direct.push(i);
                continue;
            }
            if !edges[i].iter().any(|&j| lev[r][j] >= 0) {
                chain.push(i);
            }
        }
        if direct.is_empty() && chain.is_empty() {
            continue;
        }
        let lv = |i: usize| lev[r][i].max(0) as usize;
        let pop = |i: usize| (levels[lv(i)][i] & rule.want).count_ones();
        let is_strong = |i: usize| levels[lv(i)][i] & STRONG != 0;
        let t = tmeta(id);
        struct Tier {
            l: Vec<usize>,
            c: (Severity, f64, String),
            weak: bool,
        }
        let tiers: Vec<Tier> = if id == "jf_steal" {
            vec![
                Tier { l: direct.iter().copied().filter(|&i| is_strong(i)).collect(), c: (t.d.0, t.d.1, t.d.2.into()), weak: false },
                Tier { l: chain.iter().copied().filter(|&i| is_strong(i)).collect(), c: (t.c.0, t.c.1, t.c.2.into()), weak: false },
                Tier { l: direct.iter().copied().filter(|&i| !is_strong(i)).collect(), c: (Severity::Med, 10.0, "Minecraft oturum/launcher verisine erişim ve ağ çağrısı aynı metotta (zayıf kaynak)".into()), weak: true },
                Tier { l: chain.iter().copied().filter(|&i| !is_strong(i)).collect(), c: (Severity::Info, 0.0, "Minecraft oturum/launcher verisine erişim ve ağ çağrısı yakın çağrı zincirinde (zayıf kaynak, puansız)".into()), weak: true },
            ]
        } else {
            vec![
                Tier { l: direct.clone(), c: (t.d.0, t.d.1, t.d.2.into()), weak: false },
                Tier { l: chain.clone(), c: (t.c.0, t.c.1, t.c.2.into()), weak: false },
            ]
        };
        let Some(tier) = tiers.into_iter().find(|t| !t.l.is_empty()) else { continue };
        let mut used = tier.l.clone();
        used.sort_by(|&a, &b| pop(b).cmp(&pop(a)));
        let (mut sev, mut w, mut title) = tier.c.clone();
        let mut fid = id.to_string();
        let mut extra = String::new();
        let ev: Vec<String> = used
            .iter()
            .take(5)
            .map(|&i| {
                let l = lev[r][i] as usize;
                let names = ft_names(levels[l][i], rule.want).join(" + ");
                let tail = if l == 0 { " (aynı metot)".to_string() } else { format!(" ({l} çağrı adımı içinde)") };
                format!("{} — {}{}", nm(i), names, tail)
            })
            .collect();
        if id == "jf_steal" {
            let all_known = used.iter().all(|&i| {
                let l = lev[r][i] as usize;
                let hs = reach_hosts(i, l);
                !hs.is_empty() && hs.iter().all(|h| BENIGN.is_match(h)) && levels[l][i] & EXFILCH == 0
            });
            if all_known {
                fid = "jf_steal_known".into();
                sev = Severity::Low;
                w = w.min(3.0);
                title = "Hassas veri erişimi ve ağ çağrısı aynı akışta, ancak adresler bilinen-güvenli listede".into();
                extra = " Bu akıştaki adreslerin tümü bilinen-güvenli alan adı listesinde (ör. Mojang/Microsoft/GitHub); bu yüzden puan düşürüldü. Liste sınırlıdır ve bu bir güvence değildir.".into();
            } else if used.iter().any(|&i| reach_hosts(i, lv(i)).is_empty() && levels[lv(i)][i] & EXFILCH == 0) {
                extra = " Akışta sabit bir adres bulunamadı: adres çalışma anında kuruluyor olabilir.".into();
            }
            if tier.weak {
                extra.push_str(" Kaynak yalnızca Minecraft oturum token’ı veya launcher hesap dosyası: alt manager, hesap değiştirici ve oturum doğrulayan meşru modlar da böyle çalışır; tarayıcı/Discord/cüzdan gibi başka uygulamaların verisi ya da webhook/bot kanalı olmadığı için ağırlık düşük tutuldu.");
            }
        }
        let mut f = Finding::mk(&fid, sev, w, &title, &format!("{}{}", why(id, d), extra), act(id), ev, t.cat);
        f.fp = Some(fpt(id).to_string());
        let mut cl: Vec<String> = vec![];
        for &i in used.iter().take(5) {
            let c = fl.cls_names[fl.cls_idx[i]].clone();
            if !cl.contains(&c) {
                cl.push(c);
            }
        }
        f.cls = Some(cl);
        f.count = Some(used.len());
        out_f.push(f);
        info.insert(id.into(), json!({ "direct": direct.len(), "chain": chain.len(), "strong": !tier.weak }));
    }
    if !fl.trust.is_empty() {
        let mut f = Finding::mk(
            "jf_trustall",
            Severity::Med,
            if ctx_mod { 6.0 } else { 8.0 },
            "TLS sertifika/ana makine doğrulaması devre dışı (bytecode’dan doğrulandı)",
            "Bir TrustManager.checkServerTrusted gövdesi hiçbir denetim yapmıyor (çağrı ve istisna yok) veya bir HostnameVerifier her zaman true dönüyor. Bu, TLS bağlantılarını ortadaki saldırgana açar; SilentNet analizlerinde “null TrustManager” bildirilmiştir. Araç, metot gövdesini gerçekten okuyup doğruladı; ancak bu sınıfın hangi bağlantılarda kullanıldığı çözümlenmedi.",
            "İlgili sınıfı sınıf görüntüleyicide ve decompiler’da incele; hangi SSLContext/bağlantıda kullanıldığına bak.",
            fl.trust.iter().map(|(c, m, note)| format!("{}.{} — {}", base_name(c), m, note)).collect(),
            "net",
        );
        f.fp = Some("Geliştirme/test araçları ve kendi imzalı sertifikalı yerel sunucularla konuşan istemciler bunu kullanır; üretim kodunda yine de risklidir.".into());
        let mut cl: Vec<String> = vec![];
        for (c, _, _) in &fl.trust {
            if !cl.contains(c) {
                cl.push(c.clone());
            }
        }
        f.cls = Some(cl);
        out_f.push(f);
    }
    (out_f, info)
}

// ---------------------------------------------------------------- JAR analizi

pub struct JarOut {
    pub findings: Vec<Finding>,
    pub info: Map<String, Value>,
    pub children: Vec<ScanResult>,
}

const MOD_MARKERS: [(&str, &str); 9] = [
    ("fabric.mod.json", "Fabric modu"),
    ("quilt.mod.json", "Quilt modu"),
    ("META-INF/mods.toml", "Forge modu"),
    ("META-INF/neoforge.mods.toml", "NeoForge modu"),
    ("mcmod.info", "Forge modu (eski)"),
    ("plugin.yml", "Bukkit/Spigot eklentisi"),
    ("paper-plugin.yml", "Paper eklentisi"),
    ("bungee.yml", "BungeeCord eklentisi"),
    ("velocity-plugin.json", "Velocity eklentisi"),
];
const MEDIA_SET: [&str; 21] = [
    "png", "ogg", "wav", "ttf", "otf", "jpg", "jpeg", "gif", "fsh", "vsh", "glsl", "lang", "mcmeta", "nbt", "bin", "dat", "ico", "obj", "mtl", "mp3", "webp",
];
const MEDIA_PROBE: [&str; 9] = ["png", "ogg", "wav", "ttf", "jpg", "dat", "bin", "ico", "nbt"];
const TEXT_EXT: [&str; 21] = [
    "json", "yml", "yaml", "toml", "properties", "txt", "xml", "js", "sh", "bat", "cmd", "ps1", "vbs", "py", "cfg", "conf", "info", "mf", "html", "htm", "hta",
];
const EXE_EXT: [&str; 22] = [
    "exe", "dll", "scr", "com", "pif", "sys", "ocx", "cpl", "msi", "jar", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk", "so", "dylib",
];
const RISKY_API: [&str; 22] = [
    "exec", "pb", "urlcl", "defcls", "unsafe", "mctoken", "sock", "urlconn", "httpc", "okhttp", "nativeload", "jna", "robot", "clip", "keyhook", "setop", "dispatch", "scripteng", "instr", "fileout", "filedel", "sqlite",
];

static SLIP: LazyLock<Rx> = LazyLock::new(|| js(r"(^|\/)\.\.(\/|$)", ""));
static SIGNED: LazyLock<Rx> = LazyLock::new(|| js(r"^META-INF\/[^/]+\.(SF|RSA|DSA|EC)$", "i"));
static DATA_JSON: LazyLock<Rx> = LazyLock::new(|| js(r"^(assets|data)\/.*\.(json)$", ""));
static MANIFEST_NAME: LazyLock<Rx> = LazyLock::new(|| js(r"^META-INF\/MANIFEST", "i"));
static MANIFEST_MF: LazyLock<Rx> = LazyLock::new(|| js(r"^META-INF\/MANIFEST\.MF$", "i"));
static MIXIN_JSON: LazyLock<Rx> = LazyLock::new(|| js(r"\.mixins?\.json$", "i"));
static MIX_SESSION: LazyLock<Rx> = LazyLock::new(|| js(r"Session|GameProfile|Yggdrasil|AuthenticationService|PlayerKeyPair", ""));
static MCSTR: LazyLock<Rx> = LazyLock::new(|| js(r"^(accessToken|access_token|sessionId|ssid)$", ""));
static STRDEC: LazyLock<Rx> = LazyLock::new(|| js(r"\(Ljava\/lang\/String;(?:Ljava\/lang\/String;)?II\)Ljava\/lang\/String;$", ""));
static B64_OR_HEX: LazyLock<Rx> = LazyLock::new(|| js(r"[A-Za-z0-9+\/]{60,}|(?:[0-9a-fA-F]{2}){40,}", ""));
static OBF_NAMES: LazyLock<Rx> = LazyLock::new(|| {
    js(r"allatori|zelix|zkm|paramorphism|radon|skidfuscator|caesium|stringer|dasho|qprotect|branchlock|jnic|superblaubeere|obfuscat|binsecure|bozar|jfuscator|penisguard|protect(?:or)?\b", "i")
});
static MC_POPULAR: LazyLock<Rx> = LazyLock::new(|| {
    js(r"^(?:sodium|iris|lithium|phosphor|optifine|optifabric|xaerominimap|xaeroworldmap|journeymap|jei|justenoughitems|rei|roughlyenoughitems|modmenu|fabricapi|fabric-api|replaymod|litematica|worldedit|essential|lunarclient|badlion|mousetweaks|appleskin|ferritecore|starlight|entityculling|krypton|lazydfu|dynamicfps|zoomify|betterf3|iris-shaders)$", "")
});
static CLASS_END: LazyLock<Rx> = LazyLock::new(|| js(r"\.class$", ""));
static MODID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"modId\s*=\s*["']([^"']+)"#).unwrap());
static PY_MAIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^main:\s*['"]?([A-Za-z0-9_.$]+)"#).unwrap());
static PY_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?m)^name:\s*['"]?([^'"\r\n]+)"#).unwrap());

fn norm_lines(t: &str) -> String {
    t.replace("\r\n", "\n").replace(['\r', '\u{2028}', '\u{2029}'], "\n")
}

/// JS: `new RegExp('^' + key + ':\\s*(.+)$', 'mi')` ilk eslesme (CRLF/CR satir sonlari dahil).
fn line_val(t: &str, key: &str) -> Option<String> {
    let re = Regex::new(&format!(r"(?mi)^{}:\s*(.+)$", regex::escape(key))).ok()?;
    re.captures(&norm_lines(t)).map(|c| c[1].to_string())
}

fn mark_api(api: &mut HashMap<&'static str, usize>, where_: &mut HashMap<&'static str, Vec<String>>, id: &'static str, cn: &str) {
    *api.entry(id).or_insert(0) += 1;
    let a = where_.entry(id).or_default();
    if a.len() < 3 && !a.iter().any(|x| x == cn) {
        a.push(cn.to_string());
    }
}

fn quick_api(t: &str, api: &mut HashMap<&'static str, usize>, w: &mut HashMap<&'static str, Vec<String>>, cn: &str) {
    if t.contains("java/lang/Runtime") && t.contains("exec") {
        mark_api(api, w, "exec", cn);
    }
    if t.contains("java/lang/ProcessBuilder") {
        mark_api(api, w, "pb", cn);
    }
    if t.contains("java/net/URLClassLoader") {
        mark_api(api, w, "urlcl", cn);
    }
    if t.contains("defineClass") || t.contains("defineAnonymousClass") {
        mark_api(api, w, "defcls", cn);
    }
    if t.contains("sun/misc/Unsafe") || t.contains("jdk/internal/misc/Unsafe") {
        mark_api(api, w, "unsafe", cn);
    }
    if t.contains("getAccessToken") || t.contains("getSessionId") {
        mark_api(api, w, "mctoken", cn);
    }
    if t.contains("java/net/Socket") {
        mark_api(api, w, "sock", cn);
    }
    if t.contains("openConnection") || t.contains("java/net/http/HttpClient") {
        mark_api(api, w, "urlconn", cn);
    }
}

fn jstr(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.is_empty(),
        Value::Number(n) => n.as_f64().is_some_and(|x| x != 0.0),
        _ => true,
    }
}

fn read_json(u: &[u8], entries: &[Entry], name: &str, st: &mut St) -> Option<Value> {
    let e = entries.iter().find(|x| x.name == name)?;
    let d = read_budget(u, e, st).ok()?;
    let t = utf8_decode(&d);
    serde_json::from_str(t.trim_start_matches('\u{feff}')).ok()
}

fn concat_vals(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Null => vec![],
        other => vec![other.clone()],
    }
}

fn mc_mod_checks(u: &[u8], entries: &[Entry], names: &[String], st: &mut St, found: &[Finding]) -> Vec<Finding> {
    let mut out: Vec<Finding> = vec![];
    let name_set: HashSet<&str> = names.iter().map(|s| s.as_str()).collect();
    let cls_set: HashSet<&str> = names.iter().filter(|n| CLASS_END.is_match(n)).map(|s| s.as_str()).collect();
    let n_cls = cls_set.len();
    let class_of = |v: &str| -> String { format!("{}.class", v.split("::").next().unwrap_or("").trim().replace('.', "/")) };
    let strip = |s: &str, extra: &[char]| -> String { s.to_lowercase().chars().filter(|c| !(c.is_whitespace() || *c == '_' || extra.contains(c))).collect() };
    let fab = if name_set.contains("fabric.mod.json") {
        read_json(u, entries, "fabric.mod.json", st)
    } else if name_set.contains("quilt.mod.json") {
        read_json(u, entries, "quilt.mod.json", st)
    } else {
        None
    };
    let ids: HashSet<&str> = found.iter().map(|f| f.id.as_str()).collect();
    let mut mod_name = String::new();
    if let Some(fab) = fab {
        let q = fab.get("quilt_loader").filter(|v| truthy(v));
        let pick = |k: &str, qk: &str| -> Value {
            if let Some(v) = fab.get(k).filter(|v| truthy(v)) {
                return v.clone();
            }
            q.and_then(|q| q.get(qk)).filter(|v| truthy(v)).cloned().unwrap_or(Value::Null)
        };
        let id = fab.get("id").filter(|v| truthy(v)).cloned().or_else(|| q.and_then(|q| q.get("id")).cloned()).unwrap_or(Value::Null);
        let nm = fab.get("name").filter(|v| truthy(v)).cloned().unwrap_or(id);
        mod_name = strip(&jstr(&nm), &[]);
        let eps = pick("entrypoints", "entrypoints");
        let mut missing: Vec<String> = vec![];
        if let Value::Object(eo) = &eps {
            for (k, v) in eo {
                for x in concat_vals(v) {
                    let val = match &x {
                        Value::String(s) => s.clone(),
                        Value::Object(o) => o.get("value").map(jstr).unwrap_or_default(),
                        _ => String::new(),
                    };
                    let plain = Regex::new(r"^[a-z][A-Za-z0-9_.]*$").unwrap();
                    let plain_lc = val.chars().next().is_some_and(|c| c.is_ascii_lowercase()) && val.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
                    let _ = &plain;
                    if val.is_empty() || (!plain_lc && !val.chars().any(|c| c.is_ascii_uppercase())) {
                        continue;
                    }
                    let low = val.to_lowercase();
                    if !cls_set.contains(class_of(&val).as_str()) && !(low.starts_with("kotlin") || low.starts_with("scala")) {
                        missing.push(format!("{k}: {val}"));
                    }
                }
            }
        }
        if !missing.is_empty() {
            out.push(
                Finding::mk("mc_ep_missing", Severity::Med, 8.0, "Bildirilen giriş sınıfı jar içinde yok", "Mod meta verisi (fabric/quilt.mod.json) bazı giriş sınıflarını bildiriyor ama bu sınıflar jar içinde bulunamadı. Sınıf başka bir yerden (ağ, gizli jar) yükleniyor olabilir; paketleme hatası da olabilir.", "Eksik sınıfların nereden geldiğini incele; kaynağı belirsizse kullanma.", missing.into_iter().take(8).collect(), "dyn")
                    .with_basis("fact")
                    .with_mitre(&["T1027"]),
            );
        }
        let declared: HashSet<String> = concat_vals(&pick("jars", "jars"))
            .iter()
            .map(|x| match x.get("file").filter(|v| truthy(v)) {
                Some(f) => jstr(f),
                None => jstr(x),
            })
            .collect();
        let jar_re = js(r"^META-INF\/jars\/.+\.jar$", "i");
        let nested: Vec<&String> = names.iter().filter(|n| jar_re.is_match(n)).collect();
        let und: Vec<String> = nested.into_iter().filter(|n| !declared.contains(n.as_str())).take(6).cloned().collect();
        if !und.is_empty() {
            out.push(
                Finding::mk("mc_nested_undeclared", Severity::High, 14.0, "Meta veride bildirilmeyen gömülü jar", "META-INF/jars altında, mod meta verisinde listelenmeyen jar dosyası var. Mod yükleyici bunları kendiliğinden yüklemez; birini başka bir kod yüklüyor olabilir.", "Gömülü jar’ı ayrı tara ve kim tarafından yüklendiğini bul.", und, "dyn")
                    .with_basis("inference")
                    .with_mitre(&["T1027.009"]),
            );
        }
        let mx: Vec<String> = concat_vals(&pick("mixins", "mixin"))
            .iter()
            .filter_map(|m| match m {
                Value::String(s) => Some(s.clone()),
                Value::Object(o) => match o.get("config") {
                    Some(Value::String(s)) => Some(s.clone()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        let (mut mix_missing, mut mix_total) = (0usize, 0usize);
        let mut mm: Vec<String> = vec![];
        for cfg_name in mx.iter().take(6) {
            let cj = read_json(u, entries, cfg_name, st);
            let pkg = cj.as_ref().and_then(|c| c.get("package")).filter(|v| truthy(v)).map(jstr);
            let (Some(cj), Some(pkg)) = (cj, pkg) else {
                if !name_set.contains(cfg_name.as_str()) {
                    mm.push(format!("{cfg_name} (yapılandırma dosyası yok)"));
                }
                continue;
            };
            for key in ["mixins", "client", "server"] {
                for m in concat_vals(cj.get(key).unwrap_or(&Value::Null)) {
                    mix_total += 1;
                    let ms = jstr(&m);
                    if !cls_set.contains(format!("{}/{}.class", pkg.replace('.', "/"), ms.replace('.', "/")).as_str()) {
                        mix_missing += 1;
                        if mm.len() < 6 {
                            mm.push(format!("{pkg}.{ms}"));
                        }
                    }
                }
            }
        }
        if !mm.is_empty() && (mix_total == 0 || mix_missing as f64 / mix_total.max(1) as f64 > 0.3) {
            out.push(Finding::mk("mc_mixin_missing", Severity::Low, 4.0, "Mixin yapılandırması jar’da olmayan sınıflara başvuruyor", "mixin yapılandırmasında listelenen sınıfların bir kısmı jar içinde yok. Bozuk paketleme olabilir; sınıflar sonradan dışarıdan eklenecekse şüphelidir.", "Eksik mixin sınıflarını kontrol et.", mm, "dyn").with_basis("fact"));
        }
    }
    if name_set.contains("plugin.yml") {
        if let Some(e) = entries.iter().find(|x| x.name == "plugin.yml") {
            if let Ok(d) = read_budget(u, e, st) {
                let t = norm_lines(&utf8_decode(&d));
                let main = PY_MAIN.captures(&t).map(|c| c[1].to_string());
                if mod_name.is_empty() {
                    mod_name = strip(PY_NAME.captures(&t).map(|c| c[1].to_string()).unwrap_or_default().as_str(), &[]);
                }
                if let Some(main) = main {
                    if !cls_set.contains(format!("{}.class", main.replace('.', "/")).as_str()) {
                        out.push(
                            Finding::mk("mc_ep_missing", Severity::Med, 8.0, "plugin.yml ana sınıfı jar içinde yok", "plugin.yml içindeki main sınıfı jar’da bulunamadı; sınıf başka yerden yükleniyor olabilir ya da paketleme bozuk.", "main sınıfının kaynağını incele.", vec![format!("main: {main}")], "dyn")
                                .with_basis("fact"),
                        );
                    }
                }
            }
        }
    }
    if name_set.contains("META-INF/mods.toml") || name_set.contains("META-INF/neoforge.mods.toml") {
        if let Some(e) = entries.iter().find(|x| x.name == "META-INF/mods.toml" || x.name == "META-INF/neoforge.mods.toml") {
            if let Ok(d) = read_budget(u, e, st) {
                let t = utf8_decode(&d);
                if mod_name.is_empty() {
                    mod_name = strip(MODID_RE.captures(&t).map(|c| c[1].to_string()).unwrap_or_default().as_str(), &['-']);
                }
            }
        }
    }
    let key: String = mod_name.chars().filter(|c| !(c.is_whitespace() || *c == '_' || *c == '-')).collect();
    let susp: Vec<&str> = ["j_net", "j_dynload", "j_mctoken", "j_exec", "j_agent"].into_iter().filter(|i| ids.contains(i)).collect();
    if !key.is_empty() && MC_POPULAR.is_match(&key) && (n_cls < 10 || !susp.is_empty()) {
        let why = format!(
            "Mod adı yaygın bir moda ({key}) benziyor ama {} Sahte mod sürümleri bu şekilde yayılır.",
            if n_cls < 10 { format!("yalnızca {n_cls} sınıf içeriyor.") } else { "ağ/dinamik yükleme/komut/token erişimi gibi yetenekler taşıyor.".to_string() }
        );
        let mut ev = vec![format!("ad: {key}"), format!("sınıf sayısı: {n_cls}")];
        ev.extend(susp.iter().map(|i| format!("gösterge: {i}")));
        out.push(
            Finding::mk("mc_mimic", Severity::Med, 10.0, "Bilinen mod adını kullanan şüpheli jar", &why, "Modu yalnızca resmi kaynaktan (Modrinth/CurseForge/proje sayfası) indir ve hash’ini karşılaştır.", ev, "dyn")
                .with_basis("heuristic")
                .with_mitre(&["T1036"]),
        );
    }
    out
}

fn child(st: &mut St, d: &[u8], name: &str, depth: usize, out: &mut Vec<ScanResult>) {
    out.push(scan_buffer(d, name, st, depth + 1));
}

fn depth_limit(st: &mut St, msg: &str) {
    st.limit_hit("depth", msg);
}

/// JS `analyzeJar(u8, entries, st, depth, name)`.
#[allow(clippy::cognitive_complexity)]
pub fn analyze_jar(u: &[u8], entries: &[Entry], st: &mut St, depth: usize, name: &str) -> JarOut {
    let cfg = st.cfg;
    let mut f: Vec<Finding> = vec![];
    let mut info = Map::new();
    info.insert("kind".into(), json!("JAR"));
    info.insert("entries".into(), json!(entries.len()));
    info.insert("classes".into(), json!(0));
    let mut classes_n = 0usize;
    let mut hits = Hits::new();
    let mut api: HashMap<&'static str, usize> = HashMap::new();
    let mut api_where: HashMap<&'static str, Vec<String>> = HashMap::new();
    let mut children: Vec<ScanResult> = vec![];
    let names: Vec<String> = {
        let mut seen = HashSet::new();
        entries.iter().filter(|e| seen.insert(e.name.clone())).map(|e| e.name.clone()).collect()
    };
    let name_set: HashSet<&str> = names.iter().map(|s| s.as_str()).collect();
    let mut fl = Flow::default();
    let mut iocs = IocSet::new();
    let mut seen_b: HashSet<String> = HashSet::new();
    let mut deobf_count = 0usize;
    let ids = st_ids(st);

    let list: &[Entry] = if entries.len() > cfg.max_entries {
        st.limit_hit("entries", &format!("Arşivde çok fazla girdi var ({}); ilk {} girdi tarandı.", entries.len(), cfg.max_entries));
        st.skip("entries", entries.len() - cfg.max_entries);
        &entries[..cfg.max_entries]
    } else {
        entries
    };
    let mut mod_label: Option<&str> = None;
    for (k, v) in MOD_MARKERS {
        if name_set.contains(k) {
            mod_label = Some(v);
            info.insert("modType".into(), json!(v));
            break;
        }
    }
    let ctx_mod = mod_label.is_some();
    if name_set.contains("fabric.mod.json") {
        if let Some(j) = read_json(u, entries, "fabric.mod.json", st) {
            let authors: Vec<String> = concat_vals(j.get("authors").unwrap_or(&Value::Null))
                .iter()
                .map(|a| match a.get("name").filter(|v| truthy(v)) {
                    Some(n) => jstr(n),
                    None => jstr(a),
                })
                .collect();
            let mut m = Map::new();
            for (k, v) in [("id", j.get("id")), ("name", j.get("name")), ("version", j.get("version"))] {
                if let Some(v) = v {
                    m.insert(k.into(), v.clone());
                }
            }
            m.insert("authors".into(), json!(authors.join(", ")));
            info.insert("mod".into(), Value::Object(m));
            if let Some(Value::Array(jars)) = j.get("jars").filter(|v| truthy(v)) {
                info.insert("nestedMods".into(), json!(jars.iter().map(|x| x.get("file").cloned().unwrap_or(Value::Null)).collect::<Vec<_>>()));
            }
            if let Some(Value::Object(eo)) = j.get("entrypoints").filter(|v| truthy(v)) {
                let mut eps: Vec<String> = vec![];
                for (k, v) in eo {
                    for x in concat_vals(v) {
                        let s = match &x {
                            Value::String(s) => s.clone(),
                            Value::Object(o) => o.get("value").filter(|v| truthy(v)).map(jstr).unwrap_or_else(|| "?".into()),
                            _ => "?".into(),
                        };
                        eps.push(format!("{k}: {s}"));
                    }
                }
                if !eps.is_empty() {
                    eps.truncate(20);
                    info.insert("entrypoints".into(), json!(eps));
                }
            }
        }
    }
    if name_set.contains("plugin.yml") {
        if let Some(e) = entries.iter().find(|x| x.name == "plugin.yml") {
            if let Ok(d) = read_budget(u, e, st) {
                let t = utf8_decode(&d);
                let g = |k: &str| line_val(&t, k);
                let mut m = Map::new();
                for (k, v) in [("name", g("name")), ("version", g("version")), ("main", g("main")), ("authors", g("author").or_else(|| g("authors")))] {
                    if let Some(v) = v {
                        m.insert(k.into(), json!(v));
                    }
                }
                info.insert("mod".into(), Value::Object(m));
            }
        }
    }
    // tekrar eden adlar
    let mut counts: Vec<(String, usize)> = vec![];
    {
        let mut idx: HashMap<&str, usize> = HashMap::new();
        for e in entries {
            match idx.get(e.name.as_str()) {
                Some(&i) => counts[i].1 += 1,
                None => {
                    idx.insert(e.name.as_str(), counts.len());
                    counts.push((e.name.clone(), 1));
                }
            }
        }
    }
    let dups: Vec<String> = counts.iter().filter(|(_, n)| *n > 1).map(|(k, _)| k.clone()).collect();
    if !dups.is_empty() {
        f.push(Finding::mk("zip_dupe", Severity::Low, 4.0, "Aynı adlı tekrar eden girdiler", "Aynı yola sahip birden fazla girdi var; arşiv ayrıştırıcılarını şaşırtma tekniği olabilir.", "İlk ve son girdinin içeriğini karşılaştır.", dups.into_iter().take(5).collect(), "arch"));
    }
    info.insert("signedJar".into(), json!(entries.iter().any(|e| SIGNED.is_match(&e.name))));
    let mut keep: Vec<(String, Value)> = vec![];
    let mut keep_capped = false;
    let mut class_names: Vec<String> = vec![];
    let (mut bad_ver, mut str_dec, mut blobs) = (0usize, 0usize, 0usize);
    let mut mix_session = false;
    let mut str_dec_ex: Vec<String> = vec![];
    let total = list.len();

    macro_rules! deobf_text {
        ($t:expr) => {{
            let mut ctx = Ctx { hits: &mut hits, f: &mut f, kids: &mut children, name, depth, seen: std::mem::take(&mut seen_b), count: deobf_count, layer: false };
            deobf($t, &mut ctx, st, 0);
            seen_b = ctx.seen;
            deobf_count = ctx.count;
        }};
    }

    for (i0, e) in list.iter().enumerate() {
        let idx = i0 + 1;
        if e.dir {
            continue;
        }
        st.tick();
        if st.stop {
            st.partial = true;
            st.skip("stopped", total - idx + 1);
            break;
        }
        let low = e.name.to_lowercase();
        let ext = ext_of(&low);
        if SLIP.is_match(&e.name) {
            f.push(Finding::mk("zip_slip", Severity::High, 25.0, "Yol atlama (zip‑slip) girdisi", "Arşivde “../” içeren bir yol var; açılırken dışarıya yazabilir. Bu araç hiçbir dosyayı diske açmaz, bellekte okur.", "Bu arşivi bir arşiv yöneticisiyle açma.", vec![e.name.clone()], "arch"));
        }
        if e.enc {
            st.note("Şifreli girdiler var, içerikleri taranamadı.");
            st.skip("enc", 1);
            continue;
        }
        if ext == "class" {
            if st.classes >= cfg.max_classes {
                st.limit_hit("classes", &format!("Sınıf sayısı sınırına ulaşıldı ({}); kalan sınıflar okunmadı.", cfg.max_classes));
                st.skip("classcap", 1);
                continue;
            }
            let Ok(d) = read_budget(u, e, st) else { continue };
            st.classes += 1;
            if !cfg.parse {
                let t = latin1(&d);
                let cn = base_name(&e.name).trim_end_matches(".class").to_string();
                run_rules(&t, &mut hits, &cn, Kind::Other, ids.as_ref());
                quick_api(&t, &mut api, &mut api_where, &cn);
                classes_n += 1;
                class_names.push(e.name.trim_end_matches(".class").to_string());
                continue;
            }
            let Some(c) = parse_class(&d, cfg.flow_depth > 0) else {
                f.push(Finding::mk("j_badclass", Severity::Low, 3.0, "Okunamayan class dosyası", "Bazı class dosyaları standart biçimde ayrıştırılamadı (bozuk veya özel biçim).", "Dosyayı bir decompiler ile aç.", vec![e.name.clone()], "obf"));
                continue;
            };
            classes_n += 1;
            let cname = if c.name.is_empty() { e.name.clone() } else { c.name.clone() };
            class_names.push(cname.clone());
            let mut c_apis: Vec<&'static str> = vec![];
            if cfg.flow_depth > 0 && !c.code.is_empty() {
                flow_add(&mut fl, &c, &d);
            }
            let mut seen_refs: HashSet<&str> = HashSet::new();
            for r in c.refs.iter().filter(|r| seen_refs.insert(r.as_str())) {
                for (id, re) in JAVA_APIS.iter() {
                    if re.is_match(r) {
                        if !c_apis.contains(id) {
                            c_apis.push(id);
                        }
                        mark_api(&mut api, &mut api_where, id, &c.name);
                    }
                }
            }
            let txt = c.utf8.join("\n");
            let ht0 = hits.total();
            run_rules(&txt, &mut hits, base_name(&cname), Kind::Other, ids.as_ref());
            if c_apis.iter().any(|a| RISKY_API.contains(a)) || hits.total() > ht0 {
                if keep.len() < 60 || keep.iter().any(|(k, _)| *k == c.name) {
                    let mut refs: Vec<String> = vec![];
                    for r in c.refs.iter().filter(|x| !x.starts_with("C:")) {
                        if !refs.contains(r) {
                            refs.push(r.clone());
                        }
                    }
                    refs.truncate(60);
                    let v = json!({
                        "name": c.name, "base": base_name(&c.name), "major": c.major, "apis": c_apis,
                        "methods": c.methods.iter().take(40).collect::<Vec<_>>(),
                        "refs": refs,
                        "strings": c.strings.iter().take(50).map(|x| clip(x, 140)).collect::<Vec<_>>(),
                    });
                    match keep.iter_mut().find(|(k, _)| *k == c.name) {
                        Some(slot) => slot.1 = v,
                        None => keep.push((c.name.clone(), v)),
                    }
                } else {
                    keep_capped = true;
                }
            }
            add_ioc(&mut iocs, &txt, cfg.ioc);
            for s in &c.strings {
                if MCSTR.is_match(s) {
                    *api.entry("mcstr").or_insert(0) += 1;
                }
            }
            if c.methods.iter().any(|m| STRDEC.is_match(m)) {
                str_dec += 1;
                if str_dec_ex.len() < 3 {
                    str_dec_ex.push(base_name(&c.name).to_string());
                }
            }
            if cfg.deep_jar {
                if c.major < 45 || c.major > 70 {
                    bad_ver += 1;
                }
                if B64_OR_HEX.is_match(&txt) {
                    deobf_text!(&txt);
                }
            }
        } else if (TEXT_EXT.contains(&ext.as_str()) && e.size < 2_000_000 && !DATA_JSON.is_match(&low)) || MANIFEST_NAME.is_match(&e.name) {
            let Ok(d) = read_budget(u, e, st) else { continue };
            let t = utf8_decode(&d);
            run_rules(&t, &mut hits, &e.name, Kind::Other, ids.as_ref());
            add_ioc(&mut iocs, &t, cfg.ioc);
            if MANIFEST_MF.is_match(&e.name) {
                let mut mf = Map::new();
                for k in ["Main-Class", "Premain-Class", "Agent-Class", "Launcher-Agent-Class", "Can-Redefine-Classes", "Multi-Release"] {
                    if let Some(v) = line_val(&t, k) {
                        mf.insert(k.into(), json!(v.trim()));
                    }
                }
                let agent = ["Premain-Class", "Agent-Class", "Launcher-Agent-Class"].iter().any(|k| mf.contains_key(*k));
                if agent {
                    let ev: Vec<String> = mf.iter().filter(|(k, _)| k.contains("Agent") || k.contains("Premain")).map(|(k, v)| format!("{k}: {}", jstr(v))).collect();
                    f.push(Finding::mk("j_agent", Severity::High, 14.0, "Java agent (Premain/Agent-Class)", "Manifest, JVM’e sonradan müdahale edebilen bir Java agent bildiriyor. Bu, başka sınıfların bytecode’unu değiştirebilir.", "Bir mod/araç değilse ve agent beklemiyorsan kullanma.", ev, "dyn"));
                }
                info.insert("manifest".into(), Value::Object(mf));
            }
            if cfg.deep_jar && MIXIN_JSON.is_match(&low) && MIX_SESSION.is_match(&t) {
                mix_session = true;
            }
            if cfg.deobf && B64_OR_HEX.is_match(&t) {
                deobf_text!(&t);
            }
        } else if MEDIA_SET.contains(&ext.as_str()) {
            let probe = e.size >= 4 && MEDIA_PROBE.contains(&ext.as_str());
            if !probe {
                st.skip("media", 1);
            }
            if probe {
                let d = read_budget(u, e, st).ok();
                if let Some(d) = d {
                    if d.len() >= 2 && d[0] == 0x4d && d[1] == 0x5a {
                        f.push(Finding::mk("pk_hidden_pe", Severity::Crit, 35.0, "Resim/ses uzantılı gizli çalıştırılabilir", &format!("Uzantısı {ext} olan dosyanın içeriği aslında bir Windows çalıştırılabilir dosyası (MZ)."), "Dosyayı çıkarıp ayrıca tara; kaynağı güvenilmiyorsa sil.", vec![e.name.clone()], "arch"));
                        if depth < cfg.depth {
                            child(st, &d, &e.name, depth, &mut children);
                        } else {
                            depth_limit(st, "İç içe tarama derinliği sınırı nedeniyle gizli PE taranmadı.");
                        }
                    } else if cfg.xor && matches!(ext.as_str(), "dat" | "bin" | "nbt") && d.len() > 8192 {
                        if let Some((key, start)) = xor_find_pe(&d, 4_000_000) {
                            f.push(Finding::mk("xor_pe", Severity::Crit, 35.0, "XOR ile gizlenmiş çalıştırılabilir", &format!("Girdinin içinde tek baytlık XOR anahtarıyla (0x{key:x}) gizlenmiş bir PE bulundu."), "Çözülmüş içerik ayrıca taranır; kaynağı güvenilmiyorsa kullanma.", vec![format!("{} @ {start}", e.name)], "arch"));
                            if depth < cfg.depth {
                                let x = xor_decode(&d, start, key);
                                child(st, &x, &format!("{} (XOR çözülmüş)", e.name), depth, &mut children);
                            }
                        }
                    }
                }
            }
        } else if ["jar", "zip", "dll", "exe", "so", "dylib", "xz", "gz", "sys"].contains(&ext.as_str()) {
            if depth < cfg.depth {
                if let Ok(d) = read_budget(u, e, st) {
                    child(st, &d, &e.name, depth, &mut children);
                }
            } else {
                depth_limit(st, &format!("İç içe arşiv derinliği sınırına ulaşıldı; daha derindeki dosyalar taranmadı ({}).", base_name(&e.name)));
            }
        } else if EXE_EXT.contains(&ext.as_str()) {
            f.push(Finding::mk("pk_exe_inside", Severity::Low, 4.0, "Arşiv içinde çalıştırılabilir dosya", &format!("{} bir çalıştırılabilir/betik türünde.", e.name), "Gerçekten gerekli mi kontrol et.", vec![e.name.clone()], "arch"));
            if depth < cfg.depth {
                if let Ok(d) = read_budget(u, e, st) {
                    child(st, &d, &e.name, depth, &mut children);
                }
            }
        } else if !cfg.deep_jar || e.size <= 8 || (e.size as f64) >= cfg.entry_cap {
            st.skip(if TEXT_EXT.contains(&ext.as_str()) { "bigtext" } else { "ext" }, 1);
        } else {
            let Ok(d) = read_budget(u, e, st) else { continue };
            if d.len() >= 4 && d[..4] == [0xca, 0xfe, 0xba, 0xbe] {
                f.push(Finding::mk("j_hidden_class", Severity::High, 14.0, ".class uzantısı olmayan Java class", "Girdi bir Java class imzası taşıyor ama uzantısı farklı. Gizli yüklenen kod olabilir.", "Girdiyi çıkarıp bir decompiler ile aç.", vec![e.name.clone()], "dyn"));
            } else if d.len() >= 2 && d[0] == 0x4d && d[1] == 0x5a {
                f.push(Finding::mk("pk_hidden_pe", Severity::Crit, 35.0, "Zararsız uzantılı gizli çalıştırılabilir", &format!("{} uzantısı farklı ama içeriği PE.", e.name), "Çıkarıp ayrıca tara.", vec![e.name.clone()], "arch"));
                if depth < cfg.depth {
                    child(st, &d, &e.name, depth, &mut children);
                }
            } else if d.len() > 8192 && blobs < 30 {
                let en = entropy(&d);
                if en > 7.5 {
                    blobs += 1;
                    f.push(Finding::mk("j_blob", Severity::Med, 8.0, "Yüksek entropili bilinmeyen girdi", &format!("Tanınmayan uzantılı girdi şifreli/sıkıştırılmış veri gibi görünüyor (entropi {en:.2})."), "Girdinin kod tarafından nasıl yüklendiğine bak.", vec![e.name.clone()], "obf"));
                    if let Some((key, start)) = xor_find_pe(&d, 4_000_000) {
                        f.push(Finding::mk("xor_pe", Severity::Crit, 35.0, "XOR ile gizlenmiş çalıştırılabilir", &format!("Girdinin içinde tek baytlık XOR anahtarıyla (0x{key:x}) gizlenmiş bir PE bulundu."), "Çözülmüş içerik ayrıca taranır.", vec![format!("{} @ {start}", e.name)], "arch"));
                        if depth < cfg.depth {
                            let x = xor_decode(&d, start, key);
                            child(st, &x, &format!("{} (XOR çözülmüş)", e.name), depth, &mut children);
                        }
                    }
                }
            }
        }
    }
    hits_to_findings(&hits, &mut f);

    let a = |id: &str| api.contains_key(id);
    let wh = |ids: &[&str]| -> Vec<String> {
        let mut v: Vec<String> = vec![];
        for i in ids {
            if let Some(x) = api_where.get(i) {
                v.extend(x.iter().cloned());
            }
        }
        v.into_iter().take(4).map(|s| base_name(&s).to_string()).collect()
    };
    let cm = |a: f64, b: f64| if ctx_mod { a } else { b };
    if a("exec") || a("pb") {
        f.push(Finding::mk("j_exec", Severity::Med, cm(5.0, 8.0), "Harici komut/program çalıştırma", "Kod Runtime.exec veya ProcessBuilder ile işletim sistemi komutu çalıştırabiliyor. Klasör açmak gibi zararsız işlerde de kullanılır.", "Hangi komutun çalıştırıldığına bak (sabit mi, dışarıdan mı geliyor).", wh(&["exec", "pb"]), "proc"));
    }
    if a("urlcl") || a("defcls") || a("unsafe") {
        f.push(Finding::mk("j_dynload", Severity::Med, 8.0, "Çalışma anında kod yükleme", "URLClassLoader, defineClass veya Unsafe ile dışarıdan/sonradan kod yükleme yeteneği.", "Yüklenen sınıfın kaynağını (dosya/ağ/gömülü) bul.", wh(&["urlcl", "defcls", "unsafe"]), "dyn"));
    }
    if a("sock") || a("urlconn") || a("httpc") || a("okhttp") {
        f.push(Finding::mk("j_net", Severity::Low, 1.0, "Ağ bağlantısı yeteneği", "Kod ağ üzerinden bağlantı kurabiliyor.", "Bağlandığı adresleri IOC listesinde incele.", wh(&["sock", "urlconn", "httpc", "okhttp"]), "net"));
    }
    if a("mctoken") || a("mcstr") {
        f.push(Finding::mk("j_mctoken", Severity::Med, 12.0, "Minecraft oturum token’ına erişim", "Kod hesap oturum anahtarına (access token/session id) erişen çağrılar içeriyor. Hile istemcilerinde “alt manager” için normal olabilir, ağ gönderimiyle birleşirse tehlikelidir.", "Token’ın nereye gittiğini incele; ağ gönderimi varsa kullanma.", wh(&["mctoken"]), "cred"));
    }
    if a("keyhook") {
        f.push(Finding::mk("j_keylog", Severity::High, 18.0, "Global klavye dinleme", "JNativeHook ile oyun dışında da tuş yakalama mümkün.", "Tuş verisinin kaydedilip gönderilmediğini kontrol et.", vec![], "spy"));
    }
    if a("robot") || a("clip") {
        f.push(Finding::mk("j_spy", Severity::Med, 8.0, "Ekran/pano erişimi", "Robot veya pano okuma çağrıları var.", "Elde edilen verinin kullanımına bak.", wh(&["robot", "clip"]), "spy"));
    }
    if a("nativeload") || a("jna") {
        f.push(Finding::mk("j_native", Severity::Low, cm(3.0, 5.0), "Yerel (native) kütüphane yükleme", "DLL/SO yüklüyor. Gömülü yerel dosyaları ayrıca tara.", "Jar içindeki .dll/.so dosyalarının sonuçlarına bak.", wh(&["nativeload", "jna"]), "dyn"));
    }
    if a("scripteng") {
        f.push(Finding::mk("j_script", Severity::Low, 5.0, "Script motoru", "Çalışma anında betik (JS vb.) çalıştırabilir.", "Hangi betiğin çalıştığını incele.", wh(&["scripteng"]), ""));
    }
    if a("setop") || a("dispatch") {
        f.push(Finding::mk("j_bukkit_op", Severity::Med, cm(8.0, 4.0), "OP verme / komut gönderme", "setOp veya dispatchCommand kullanımı. Bukkit eklentilerinde arka kapı için kötüye kullanılabilir.", "Hangi koşulda OP verdiğini kontrol et (sabit bir oyuncu adı/UUID olup olmadığına bak).", wh(&["setop", "dispatch"]), ""));
    }
    if a("filedel") && a("fileout") {
        f.push(Finding::mk("j_fs", Severity::Info, 0.0, "Dosya yazma/silme", "Dosya sistemi yazma ve silme çağrıları.", "Hangi yolları kullandığına bak.", vec![], ""));
    }
    if a("tlsmgr") || a("hostver") {
        f.push(Finding::mk("j_tls_custom", Severity::Low, 4.0, "Özel TLS TrustManager / HostnameVerifier", "Kod kendi sertifika/ana makine doğrulayıcısını tanımlıyor. SilentNet analizlerinde “her sertifikayı kabul eden” (null) TrustManager bildirilmiştir; bu araç doğrulamanın gerçekten kapatılıp kapatılmadığını çözümlemez.", "İlgili sınıfı sınıf görüntüleyicide incele; checkServerTrusted içeriğini bir decompiler ile doğrula.", wh(&["tlsmgr", "hostver"]), "net"));
    }
    if cfg.flow_depth > 0 && !fl.keys.is_empty() {
        let (ff, finfo) = flow_findings(&fl, cfg.flow_depth, ctx_mod);
        info.insert("flow".into(), Value::Object(finfo));
        let has_trust = ff.iter().any(|x| x.id == "jf_trustall");
        f.extend(ff);
        if has_trust {
            if let Some(k) = f.iter().position(|x| x.id == "j_tls_custom") {
                f.remove(k);
            }
        }
        if fl.capped {
            st.limit_hit("flowcap", &format!("Metot sayısı sınırı ({FLOW_MAX_METHODS}) aşıldı; bytecode akış analizi eksik kaldı."));
            st.skip("flowcap", fl.skipped);
        }
    }
    if a("zipw") && a("fileout") && (a("sock") || a("urlconn") || a("httpc")) {
        f.push(Finding::mk("j_jar_rewrite", Severity::Low, 6.0, "Jar/ZIP yazma + ağ erişimi", "Kod jar/zip dosyası yazabiliyor ve ağa bağlanabiliyor. Fractureiser, diğer .jar dosyalarına kendini enjekte ederek yayılmıştır; güncelleme araçları da benzer kalıp gösterir.", "Hangi jar dosyalarını yazdığını ve kaynağını incele.", wh(&["zipw", "fileout"]), "dyn"));
    }
    if a("sqlite") {
        f.push(Finding::mk("j_sqlite", Severity::Low, 4.0, "SQLite/JDBC erişimi", "Veritabanı okuma. Tarayıcı veri tabanı yollarıyla birleşirse tehlikelidir.", "Tarayıcı yolları bulgusuna bak.", vec![], ""));
    }
    if a("reflinv") && a("forname") {
        f.push(Finding::mk("j_refl", Severity::Low, 3.0, "Yansıma (reflection) kullanımı", "Çağrılar ve sınıflar çalışma anında dinamik çözülüyor.", "Mod/istemci kodunda yaygındır; tek başına bir şey kanıtlamaz.", vec![], ""));
    }
    if str_dec > 0 {
        f.push(Finding::mk("j_strdec", Severity::Info, 0.0, "Metin çözücü (string encryption) metodu", "Şifrelenmiş metinleri çalışma anında çözen bir metod kalıbı bulundu. Bu bir gizleme göstergesidir; şifreli metinler (URL vb.) statik taramada görünmeyebilir.", "Gizlenmiş adresler için derin taramayı veya bir decompiler kullan.", str_dec_ex, "obf"));
    }
    if bad_ver > 0 {
        f.push(Finding::mk("j_ver", Severity::Low, 2.0, "Olağandışı class sürümü", &format!("{bad_ver} class dosyası bilinen Java sürüm aralığının dışında."), "Bozuk veya elle düzenlenmiş class olabilir.", vec![], "obf"));
    }
    if mix_session {
        f.push(Finding::mk("j_mixin_session", Severity::Low, 3.0, "Mixin ile oturum/kimlik sınıfı", "Mixin yapılandırması oturum/kimlik doğrulama sınıflarına müdahale ediyor. Alt manager araçlarında normaldir.", "Token’ın dışarı gönderilip gönderilmediğine bak.", vec![], "cred"));
    }
    for x in mc_mod_checks(u, entries, &names, st, &f) {
        if !f.iter().any(|y| y.id == x.id) {
            f.push(x);
        }
    }
    let io = finalize_ioc(&iocs);
    if let Some(io) = &io {
        info.insert("iocs".into(), Value::Object(io.clone()));
        if cfg.ioc > 0 {
            if let Some(Value::Array(dom)) = io.get("domain") {
                if !dom.is_empty() {
                    let ev: Vec<String> = dom.iter().take(8).map(jstr).collect();
                    f.push(Finding::mk("j_hosts", Severity::Info, dom.len().min(4) as f64, "Bilinmeyen alan adları", "Jar içinde bilinen‑güvenli listesinde olmayan alan adları var.", "Her adresin ne için kullanıldığını kontrol et.", ev, "net"));
                }
            }
        }
    }
    let nm: Vec<&str> = class_names.iter().map(|c| c.rsplit('/').next().unwrap_or(c)).collect();
    let mut rnd = 0usize;
    for n in &nm {
        let base = n.split('$').next().unwrap_or(n);
        let bl = utf16_len(base);
        let upper = base.chars().filter(|c| c.is_ascii_uppercase()).count();
        if bl <= 2 || ((6..=12).contains(&bl) && base.chars().all(|c| c.is_ascii_alphanumeric()) && upper as f64 / bl as f64 > 0.3 && base.chars().any(|c| c.is_ascii_lowercase())) {
            rnd += 1;
        }
    }
    let obf_name: Option<String> = class_names.iter().find_map(|c| OBF_NAMES.find(c).map(|m| m.to_string()));
    if nm.len() >= 20 && rnd as f64 / nm.len() as f64 >= 0.4 {
        let pct = js_round(100.0 * rnd as f64 / nm.len() as f64);
        let tag = obf_name.as_ref().map(|o| format!(" (“{o}” izi)")).unwrap_or_default();
        f.push(Finding::mk("j_obf", Severity::Low, 4.0, "Rastgele sınıf isimleri (gizleme)", &format!("%{pct} oranında anlamsız/rastgele sınıf adı var{tag}. Gizleme tek başına zararlılık değildir; ticari/hile istemcileri sık kullanır ama analizi zorlaştırır."), "Okunabilir kaynak yok; davranışı dikkatle (izole ortamda) doğrula.", vec![nm.iter().take(5).copied().collect::<Vec<_>>().join(", ")], "obf"));
    }
    info.insert("randomNameRatio".into(), json!(if nm.is_empty() { 0 } else { js_round(100.0 * rnd as f64 / nm.len() as f64) }));
    let pk: HashSet<String> = class_names.iter().map(|c| { let mut p: Vec<&str> = c.split('/').collect(); p.pop(); p.join("/") }).collect();
    info.insert("packages".into(), json!(pk.len()));
    info.insert("classes".into(), json!(classes_n));
    info.insert("cov".into(), json!({ "classesRead": classes_n, "classesTotal": entries.iter().filter(|e| CLASS_END.is_match(&e.name)).count() }));
    if let Some(m) = mod_label {
        let ev: Vec<String> = match info.get("mod") {
            Some(Value::Object(o)) => o.iter().filter(|(_, v)| truthy(v)).map(|(k, v)| format!("{k}: {}", clip(&jstr(v), 80))).collect(),
            _ => vec![],
        };
        f.insert(0, Finding::mk("j_modinfo", Severity::Info, 0.0, &format!("{m} tespit edildi"), &format!("Dosya bir Minecraft {}. Mod bağlamında Runtime.exec ve ağ erişimi daha olağandır; bu yüzden ağırlıkları düşürdüm.", m.to_lowercase()), "Mod’u resmi kaynaktan (Modrinth/CurseForge/GitHub) indirdiysen karşılaştır.", ev, ""));
    }
    if !keep.is_empty() {
        info.insert("classView".into(), Value::Array(keep.into_iter().map(|(_, v)| v).collect()));
        if keep_capped {
            info.insert("classViewCapped".into(), json!(true));
        }
    }
    for x in f.iter_mut() {
        if x.id.starts_with("j_") && x.id != "j_hosts" && x.id != "j_modinfo" && !x.ev.is_empty() && x.cls.is_none() {
            x.cls = Some(x.ev.clone());
        }
    }
    JarOut { findings: f, info, children }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{scan_file, ScanOptions};

    const OK: &[u8] = include_bytes!("../testdata/Ok.class");
    const TM: &[u8] = include_bytes!("../testdata/T.class");

    fn scan(bytes: &[u8], name: &str, mode: &str) -> crate::model::ScanResult {
        scan_file(name, bytes, &ScanOptions { mode: mode.into(), time_limit_ms: Some(60_000), cancel: None, java_allowed: false })
    }

    #[test]
    fn parses_simple_class() {
        let c = parse_class(OK, true).expect("Ok.class");
        assert_eq!(c.name, "Ok");
        assert_eq!(c.sup, "java/lang/Object");
        assert!(c.methods.iter().any(|m| m == "add(II)I"));
        assert!(!c.code.is_empty());
    }

    #[test]
    fn never_panics_on_truncated_or_corrupt_class() {
        for n in 0..TM.len() {
            let _ = parse_class(&TM[..n], true);
        }
        let mut x: u32 = 12345;
        for _ in 0..3000 {
            let mut b = TM.to_vec();
            for _ in 0..4 {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                let i = (x >> 8) as usize % b.len();
                b[i] = (x >> 24) as u8;
            }
            let _ = parse_class(&b, true);
            let _ = parse_class(&b, false);
        }
    }

    #[test]
    fn empty_trust_manager_is_found_in_bytecode() {
        let c = parse_class(TM, true).unwrap();
        let mut fl = Flow::default();
        flow_add(&mut fl, &c, TM);
        assert!(!fl.trust.is_empty(), "checkServerTrusted bos govde yakalanmali");
    }

    #[test]
    fn download_and_load_chain_is_flagged() {
        let r = scan(include_bytes!("../testdata/exec.jar"), "exec.jar", "normal");
        let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
        for want in ["j_exec", "j_dynload", "j_net", "jf_dlexec", "jf_payload"] {
            assert!(ids.contains(&want), "{want} yok: {ids:?}");
        }
        assert!(!ids.contains(&"rs_unported"));
    }

    #[test]
    fn fake_popular_mod_is_flagged() {
        let r = scan(include_bytes!("../testdata/fakemod.jar"), "fakemod.jar", "normal");
        let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
        for want in ["mc_ep_missing", "mc_nested_undeclared", "mc_mimic", "j_modinfo"] {
            assert!(ids.contains(&want), "{want} yok: {ids:?}");
        }
    }

    #[test]
    fn trustall_jar_reports_flow_finding() {
        let r = scan(include_bytes!("../testdata/trustall.jar"), "t.jar", "deep");
        assert!(r.findings.iter().any(|f| f.id == "jf_trustall"));
    }
}
