//! Kovan guncelleyicisi.
//!
//! Guvenlik ilkeleri:
//! - Yalniz https; yalniz izinli GitHub ana makineleri; yonlendirmeler de ayni listeden gecmek zorunda.
//! - Her surum Ed25519 imzali olmali; imza, gomulu acik anahtara karsi dogrulanir. Imzasiz/bozuk -> reddedilir.
//! - SHA-256 + boyut dogrulanir; indirme boyut sinirlidir; surum GERI alinmaz (downgrade reddi).
//! - Indirilen dosya YALNIZCA hazirlanir (`*.new`); bu kutuphane hicbir seyi CALISTIRMAZ ve calisan dosyanin ustune yazmaz.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt;
use std::path::{Path, PathBuf};

pub const ALLOWED_HOSTS: [&str; 4] =
    ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com", "raw.githubusercontent.com"];
pub const MAX_MANIFEST: usize = 256 * 1024;
pub const MAX_ASSET: u64 = 400 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum UpdError {
    BadUrl(String),
    Transport(String),
    Manifest(String),
    Version(String),
    NoAsset,
    Size(String),
    Hash,
    Signature(String),
    Io(String),
}

impl fmt::Display for UpdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdError::BadUrl(s) => write!(f, "Güvenli olmayan adres reddedildi: {s}"),
            UpdError::Transport(s) => write!(f, "Ağ hatası: {s}"),
            UpdError::Manifest(s) => write!(f, "Güncelleme bildirimi geçersiz: {s}"),
            UpdError::Version(s) => write!(f, "Sürüm reddedildi: {s}"),
            UpdError::NoAsset => write!(f, "Bu platform için güncelleme dosyası yok."),
            UpdError::Size(s) => write!(f, "Boyut sınırı: {s}"),
            UpdError::Hash => write!(f, "SHA-256 eşleşmedi; dosya atıldı."),
            UpdError::Signature(s) => write!(f, "İmza doğrulanamadı: {s}"),
            UpdError::Io(s) => write!(f, "Dosya hatası: {s}"),
        }
    }
}
impl std::error::Error for UpdError {}

// ---------- surum ----------

#[derive(Debug, Clone)]
pub struct Version(pub Vec<u64>);

impl Version {
    pub fn parse(s: &str) -> Option<Version> {
        let s = s.trim().trim_start_matches('v');
        if s.is_empty() || s.len() > 40 {
            return None;
        }
        let mut v = vec![];
        for p in s.split('.') {
            if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            v.push(p.parse().ok()?);
        }
        (v.len() <= 4).then_some(Version(v))
    }
}
impl PartialEq for Version {
    fn eq(&self, o: &Self) -> bool {
        self.cmp(o) == Ordering::Equal
    }
}
impl Eq for Version {}
impl Ord for Version {
    fn cmp(&self, o: &Self) -> Ordering {
        let n = self.0.len().max(o.0.len());
        for i in 0..n {
            let (a, b) = (self.0.get(i).copied().unwrap_or(0), o.0.get(i).copied().unwrap_or(0));
            if a != b {
                return a.cmp(&b);
            }
        }
        Ordering::Equal
    }
}
impl PartialOrd for Version {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

// ---------- bildirim ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Asset {
    /// Ornek: "kovan-windows-x64.exe"
    pub name: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    /// base64 Ed25519 imzasi (bkz. `signed_message`)
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    #[serde(default)]
    pub notes: String,
    pub assets: Vec<Asset>,
}

/// Imzalanan metin: surum, dosya adi, sha256 ve boyut birbirine baglidir; biri degisirse imza gecmez.
pub fn signed_message(version: &str, a: &Asset) -> Vec<u8> {
    format!("kovan-update/v1\n{}\n{}\n{}\n{}", version.trim().trim_start_matches('v'), a.name, a.sha256.to_ascii_lowercase(), a.size).into_bytes()
}

pub fn sign_asset(key: &SigningKey, version: &str, a: &mut Asset) {
    a.sig = B64.encode(key.sign(&signed_message(version, a)).to_bytes());
}

pub fn verify_asset(pubkey: &VerifyingKey, version: &str, a: &Asset) -> Result<(), UpdError> {
    let raw = B64.decode(a.sig.trim()).map_err(|_| UpdError::Signature("imza base64 değil".into()))?;
    let arr: [u8; 64] = raw.try_into().map_err(|_| UpdError::Signature("imza uzunluğu yanlış".into()))?;
    pubkey
        .verify(&signed_message(version, a), &Signature::from_bytes(&arr))
        .map_err(|_| UpdError::Signature("imza eşleşmedi".into()))
}

pub fn parse_pubkey(b64: &str) -> Result<VerifyingKey, UpdError> {
    let raw = B64.decode(b64.trim()).map_err(|_| UpdError::Signature("açık anahtar base64 değil".into()))?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| UpdError::Signature("açık anahtar uzunluğu yanlış".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|_| UpdError::Signature("açık anahtar geçersiz".into()))
}

pub fn generate_keypair() -> (SigningKey, String) {
    let sk = SigningKey::generate(&mut rand_core::OsRng);
    let pk = B64.encode(sk.verifying_key().to_bytes());
    (sk, pk)
}

// ---------- adres denetimi ----------

pub fn check_url(u: &str) -> Result<url::Url, UpdError> {
    let p = url::Url::parse(u).map_err(|_| UpdError::BadUrl(u.into()))?;
    if p.scheme() != "https" || !p.username().is_empty() || p.password().is_some() || p.port().is_some_and(|x| x != 443) {
        return Err(UpdError::BadUrl(u.into()));
    }
    match p.host_str() {
        Some(h) if ALLOWED_HOSTS.contains(&h) => Ok(p),
        _ => Err(UpdError::BadUrl(u.into())),
    }
}

// ---------- ag katmani ----------

/// Ag soyutlamasi (testte sahte). Gercek uygulama `HttpTransport`.
pub trait Transport {
    /// `max` bayttan fazlasi gelirse `Size` hatasi. Yonlendirme sonrasi adresler de `check_url`dan gecmelidir.
    fn get(&self, url: &str, max: u64) -> Result<Vec<u8>, UpdError>;
}

#[cfg(feature = "http")]
pub struct HttpTransport;

#[cfg(feature = "http")]
impl Transport for HttpTransport {
    fn get(&self, url: &str, max: u64) -> Result<Vec<u8>, UpdError> {
        use std::io::Read;
        check_url(url)?;
        // Yonlendirmeleri elle izle: her adim izinli ana makineye gitmeli.
        let agent = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(60)).user_agent("Kovan-Updater").build();
        let mut cur = url.to_string();
        for _ in 0..5 {
            let r = match agent.get(&cur).call() {
                Ok(r) => r,
                Err(ureq::Error::Status(code, r)) if (300..400).contains(&code) => r,
                Err(e) => return Err(UpdError::Transport(e.to_string())),
            };
            if (300..400).contains(&r.status()) {
                let loc = r.header("location").ok_or_else(|| UpdError::Transport("yönlendirme adresi yok".into()))?;
                let next = url::Url::parse(&cur).and_then(|b| b.join(loc)).map_err(|_| UpdError::BadUrl(loc.into()))?;
                check_url(next.as_str())?;
                cur = next.to_string();
                continue;
            }
            let mut buf = Vec::new();
            r.into_reader().take(max + 1).read_to_end(&mut buf).map_err(|e| UpdError::Transport(e.to_string()))?;
            if buf.len() as u64 > max {
                return Err(UpdError::Size(format!("{max} bayt aşıldı")));
            }
            return Ok(buf);
        }
        Err(UpdError::Transport("çok fazla yönlendirme".into()))
    }
}

// ---------- ana akis ----------

#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    UpToDate { latest: String },
    Available { manifest: Manifest, asset: Asset },
}

pub fn check(t: &dyn Transport, manifest_url: &str, pubkey: &VerifyingKey, current: &str, asset_name: &str) -> Result<Check, UpdError> {
    check_url(manifest_url)?;
    let raw = t.get(manifest_url, MAX_MANIFEST as u64)?;
    let m: Manifest = serde_json::from_slice(&raw).map_err(|e| UpdError::Manifest(e.to_string()))?;
    let cur = Version::parse(current).ok_or_else(|| UpdError::Version(format!("çalışan sürüm okunamadı: {current}")))?;
    let new = Version::parse(&m.version).ok_or_else(|| UpdError::Manifest(format!("sürüm okunamadı: {}", m.version)))?;
    if new <= cur {
        return Ok(Check::UpToDate { latest: m.version });
    }
    let a = m.assets.iter().find(|a| a.name == asset_name).cloned().ok_or(UpdError::NoAsset)?;
    // Imza, "guncel var" demeden ONCE dogrulanir: imzasiz bildirim kullaniciya hic gosterilmez.
    verify_asset(pubkey, &m.version, &a)?;
    Ok(Check::Available { manifest: m, asset: a })
}

fn safe_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 80
        && !n.starts_with('.')
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !n.contains("..")
}

/// Indirir, dogrular ve `dest_dir/<ad>.new` olarak yazar. Hicbir seyi calistirmaz, mevcut dosyalarin ustune yazmaz.
pub fn download_and_stage(t: &dyn Transport, pubkey: &VerifyingKey, version: &str, a: &Asset, dest_dir: &Path) -> Result<PathBuf, UpdError> {
    if !safe_name(&a.name) {
        return Err(UpdError::BadUrl(format!("güvensiz dosya adı: {}", a.name)));
    }
    verify_asset(pubkey, version, a)?;
    if a.size == 0 || a.size > MAX_ASSET {
        return Err(UpdError::Size(format!("bildirilen boyut {}", a.size)));
    }
    check_url(&a.url)?;
    let data = t.get(&a.url, a.size)?;
    if data.len() as u64 != a.size {
        return Err(UpdError::Size(format!("beklenen {} bayt, gelen {}", a.size, data.len())));
    }
    let h = Sha256::digest(&data);
    let got: String = h.iter().map(|b| format!("{b:02x}")).collect();
    if !got.eq_ignore_ascii_case(a.sha256.trim()) {
        return Err(UpdError::Hash);
    }
    std::fs::create_dir_all(dest_dir).map_err(|e| UpdError::Io(e.to_string()))?;
    let final_path = dest_dir.join(format!("{}.new", a.name));
    let tmp = dest_dir.join(format!("{}.part", a.name));
    std::fs::write(&tmp, &data).map_err(|e| UpdError::Io(e.to_string()))?;
    std::fs::rename(&tmp, &final_path).map_err(|e| UpdError::Io(e.to_string()))?;
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct Fake(RefCell<HashMap<String, Vec<u8>>>);
    impl Transport for Fake {
        fn get(&self, url: &str, max: u64) -> Result<Vec<u8>, UpdError> {
            let d = self.0.borrow().get(url).cloned().ok_or_else(|| UpdError::Transport("404".into()))?;
            if d.len() as u64 > max { Err(UpdError::Size("büyük".into())) } else { Ok(d) }
        }
    }

    const MURL: &str = "https://github.com/yigido213/StatScan/releases/latest/download/latest-rust.json";
    const AURL: &str = "https://github.com/yigido213/StatScan/releases/download/v0.2.0/kovan-windows-x64.exe";

    fn setup(version: &str, payload: &[u8]) -> (Fake, VerifyingKey, SigningKey, Manifest) {
        let (sk, _) = generate_keypair();
        let sha: String = Sha256::digest(payload).iter().map(|b| format!("{b:02x}")).collect();
        let mut a = Asset { name: "kovan-windows-x64.exe".into(), url: AURL.into(), sha256: sha, size: payload.len() as u64, sig: String::new() };
        sign_asset(&sk, version, &mut a);
        let m = Manifest { version: version.into(), notes: "n".into(), assets: vec![a] };
        let f = Fake(RefCell::new(HashMap::new()));
        f.0.borrow_mut().insert(MURL.into(), serde_json::to_vec(&m).unwrap());
        f.0.borrow_mut().insert(AURL.into(), payload.to_vec());
        (f, sk.verifying_key(), sk, m)
    }

    #[test]
    fn version_order() {
        let v = |s| Version::parse(s).unwrap();
        assert!(v("0.2.0") > v("0.1.9"));
        assert!(v("0.10.0") > v("0.9.0"));
        assert!(v("1.0") == v("1.0.0"));
        assert!(Version::parse("1.x").is_none());
        assert!(Version::parse("").is_none());
    }

    #[test]
    fn happy_path_stages_file() {
        let (f, pk, _, m) = setup("0.2.0", b"EXE-BYTES");
        let c = check(&f, MURL, &pk, "0.1.0", "kovan-windows-x64.exe").unwrap();
        let Check::Available { asset, .. } = c else { panic!() };
        let dir = std::env::temp_dir().join(format!("kovan-upd-test-{}", std::process::id()));
        let p = download_and_stage(&f, &pk, &m.version, &asset, &dir).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"EXE-BYTES");
        assert!(p.to_string_lossy().ends_with(".new"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn up_to_date_and_downgrade() {
        let (f, pk, _, _) = setup("0.2.0", b"x");
        assert!(matches!(check(&f, MURL, &pk, "0.2.0", "kovan-windows-x64.exe").unwrap(), Check::UpToDate { .. }));
        assert!(matches!(check(&f, MURL, &pk, "0.3.0", "kovan-windows-x64.exe").unwrap(), Check::UpToDate { .. }));
    }

    #[test]
    fn wrong_key_rejected() {
        let (f, _, _, _) = setup("0.2.0", b"x");
        let (_, other) = generate_keypair();
        let pk2 = parse_pubkey(&other).unwrap();
        assert!(matches!(check(&f, MURL, &pk2, "0.1.0", "kovan-windows-x64.exe"), Err(UpdError::Signature(_))));
    }

    #[test]
    fn tampered_payload_rejected() {
        let (f, pk, _, m) = setup("0.2.0", b"GOOD");
        f.0.borrow_mut().insert(AURL.into(), b"EVIL".to_vec());
        let dir = std::env::temp_dir().join("kovan-upd-test-tamper");
        assert_eq!(download_and_stage(&f, &pk, &m.version, &m.assets[0], &dir).unwrap_err(), UpdError::Hash);
        assert!(!dir.join("kovan-windows-x64.exe.new").exists());
    }

    #[test]
    fn tampered_manifest_fields_break_signature() {
        let (_, pk, _, mut m) = setup("0.2.0", b"GOOD");
        m.assets[0].sha256 = "0".repeat(64);
        assert!(verify_asset(&pk, &m.version, &m.assets[0]).is_err());
        let (_, pk, _, mut m) = setup("0.2.0", b"GOOD");
        m.assets[0].size += 1;
        assert!(verify_asset(&pk, &m.version, &m.assets[0]).is_err());
        // surum numarasini yukselterek imzayi tasimak (replay) gecmez
        let (_, pk, _, m) = setup("0.2.0", b"GOOD");
        assert!(verify_asset(&pk, "9.9.9", &m.assets[0]).is_err());
    }

    #[test]
    fn bad_urls_and_names_rejected() {
        assert!(check_url("http://github.com/x").is_err());
        assert!(check_url("https://evil.example.com/x").is_err());
        assert!(check_url("https://github.com.evil.com/x").is_err());
        assert!(check_url("https://user:pw@github.com/x").is_err());
        assert!(check_url("https://github.com:8443/x").is_err());
        assert!(check_url("https://github.com/yigido213/StatScan").is_ok());
        assert!(!safe_name("../x.exe") && !safe_name(".hidden") && !safe_name("a/b.exe") && !safe_name(""));
        assert!(safe_name("kovan-windows-x64.exe"));
    }

    #[test]
    fn size_mismatch_and_cap() {
        let (f, pk, sk, m) = setup("0.2.0", b"12345");
        let mut a = m.assets[0].clone();
        a.size = 3;
        sign_asset(&sk, &m.version, &mut a);
        let dir = std::env::temp_dir().join("kovan-upd-test-size");
        assert!(matches!(download_and_stage(&f, &pk, &m.version, &a, &dir), Err(UpdError::Size(_))));
        let mut big = m.assets[0].clone();
        big.size = MAX_ASSET + 1;
        sign_asset(&sk, &m.version, &mut big);
        assert!(matches!(download_and_stage(&f, &pk, &m.version, &big, &dir), Err(UpdError::Size(_))));
    }

    #[test]
    fn missing_asset_for_platform() {
        let (f, pk, _, _) = setup("0.2.0", b"x");
        assert_eq!(check(&f, MURL, &pk, "0.1.0", "kovan-linux.bin").unwrap_err(), UpdError::NoAsset);
    }
}
