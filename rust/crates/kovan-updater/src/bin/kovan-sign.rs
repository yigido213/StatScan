//! Yayin imzalama araci (YALNIZ yayinci kullanir). Ozel anahtar asla yazdirilmaz/repoya konmaz.
//!   kovan-sign keygen <ozel-anahtar-dosyasi>
//!   kovan-sign manifest <ozel-anahtar> <surum> <asset-dosyasi> <asset-adi> <indirme-adresi> [notlar]

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::SigningKey;
use kovan_updater::{check_url, generate_keypair, sign_asset, Asset, Manifest};
use sha2::{Digest, Sha256};
use std::process::ExitCode;

fn die(m: &str) -> ExitCode {
    eprintln!("{m}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("keygen") if a.len() == 2 => {
            if std::path::Path::new(&a[1]).exists() {
                return die("Hedef dosya var; üzerine yazılmaz.");
            }
            let (sk, pk) = generate_keypair();
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                use std::io::Write;
                match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&a[1]) {
                    Ok(mut f) => {
                        if f.write_all(B64.encode(sk.to_bytes()).as_bytes()).is_err() {
                            return die("Yazılamadı.");
                        }
                    }
                    Err(e) => return die(&format!("Yazılamadı: {e}")),
                }
            }
            #[cfg(not(unix))]
            if let Err(e) = std::fs::write(&a[1], B64.encode(sk.to_bytes())) {
                return die(&format!("Yazılamadı: {e}"));
            }
            println!("AÇIK ANAHTAR (uygulamaya gömülür, paylaşılabilir):\n{pk}\nÖzel anahtar {} dosyasına yazıldı: kimseyle paylaşma, repoya koyma.", a[1]);
            ExitCode::SUCCESS
        }
        Some("manifest") if a.len() >= 6 => {
            let Ok(raw) = std::fs::read_to_string(&a[1]) else { return die("Özel anahtar okunamadı.") };
            let Ok(bytes) = B64.decode(raw.trim()) else { return die("Özel anahtar biçimi yanlış.") };
            let Ok(arr) = <[u8; 32]>::try_from(bytes) else { return die("Özel anahtar uzunluğu yanlış.") };
            let sk = SigningKey::from_bytes(&arr);
            let Ok(data) = std::fs::read(&a[3]) else { return die("Asset okunamadı.") };
            if let Err(e) = check_url(&a[5]) {
                return die(&e.to_string());
            }
            let sha: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
            let mut asset = Asset { name: a[4].clone(), url: a[5].clone(), sha256: sha, size: data.len() as u64, sig: String::new() };
            sign_asset(&sk, &a[2], &mut asset);
            let m = Manifest { version: a[2].trim_start_matches('v').to_string(), notes: a.get(6).cloned().unwrap_or_default(), assets: vec![asset] };
            println!("{}", serde_json::to_string_pretty(&m).unwrap());
            ExitCode::SUCCESS
        }
        _ => die("Kullanım:\n  kovan-sign keygen <özel-anahtar-dosyası>\n  kovan-sign manifest <özel-anahtar> <sürüm> <asset-dosyası> <asset-adı> <indirme-adresi> [notlar]"),
    }
}
