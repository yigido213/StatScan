//! Puanlama, hukum, siralama/zenginlestirme, risk profili ve kombinasyon bulgulari (JS: score/verdict/sortF/profile/applyCombos).

use crate::data::{FACT_IDS, HEUR_IDS, META};
use crate::model::{AxisValue, Finding, Severity};
use crate::util::js_round;
use std::collections::HashSet;

pub fn score(f: &[Finding]) -> i64 {
    let s: f64 = f.iter().map(|x| x.w).sum();
    js_round(s).clamp(0, 100)
}

/// Kesin "temiz" hukmu verilmez: 0-9 araligi "belirgin bulgu yok".
pub fn verdict(s: i64) -> &'static str {
    if s >= 80 {
        "Kritik"
    } else if s >= 55 {
        "Yüksek risk"
    } else if s >= 30 {
        "Şüpheli"
    } else if s >= 10 {
        "Düşük risk"
    } else {
        "Belirgin bulgu yok"
    }
}

pub fn enrich(x: &mut Finding) {
    if x.basis.is_none() {
        let b = if FACT_IDS.contains(x.id.as_str()) {
            "fact"
        } else if HEUR_IDS.contains(x.id.as_str()) {
            "heuristic"
        } else {
            "inference"
        };
        x.basis = Some(b.into());
    }
    if x.mitre.as_ref().is_none_or(|m| m.is_empty()) {
        if let Some(m) = META.mitre.get(&x.id) {
            x.mitre = Some(m.clone());
        }
    }
}

pub fn sort_f(f: &mut Vec<Finding>) {
    for x in f.iter_mut() {
        if let Some(r) = META.refs.get(&x.id) {
            if x.src.is_none() {
                x.src = Some(r.src.clone());
                x.mitre = Some(r.mitre.clone());
                x.conf = Some(r.conf.clone());
            }
        }
        enrich(x);
        if x.fp.is_none() {
            let t = META.fp.get(&x.id).or_else(|| META.fp_cat.get(&x.cat));
            if let Some(t) = t {
                if x.sev != Severity::Info {
                    x.fp = Some(t.clone());
                }
            }
        }
    }
    f.sort_by(|a, b| b.sev.rank().cmp(&a.sev.rank()).then(b.w.partial_cmp(&a.w).unwrap_or(std::cmp::Ordering::Equal)));
}

pub fn profile(findings: &[Finding]) -> Vec<AxisValue> {
    let mut v = std::collections::HashMap::<&str, f64>::new();
    for f in findings {
        if let Some(a) = META.cat_axis.get(&f.cat) {
            if f.w > 0.0 {
                *v.entry(a.as_str()).or_insert(0.0) += f.w;
            }
        }
    }
    META.axes
        .iter()
        .map(|(k, label)| AxisValue {
            key: k.clone(),
            label: label.clone(),
            value: js_round(v.get(k.as_str()).copied().unwrap_or(0.0) * 3.0).min(100),
        })
        .collect()
}

const THEFT_PREFIX: [&str; 8] =
    ["exfil_", "browser_data", "mc_launcher", "mc_token", "j_mctoken", "launcher_tokens", "pe_dpapi", "pe_keylog"];

fn is_theft_id(id: &str) -> bool {
    THEFT_PREFIX.iter().any(|p| id.starts_with(p)) || id.starts_with("combo_stealer") || id.starts_with("silentnet")
}

/// `java_allowed`: kullanici "Kendi dosyalarim" muafiyetini bu dosya icin acmis mi (JS `javaAllowed(policy, ident)`).
pub fn apply_combos(f: &mut Vec<Finding>, java_allowed: bool) {
    for i in 0..f.len() {
        if !(f[i].id == "pe_inject" && f[i].java_target) {
            continue;
        }
        let theft = f.iter().enumerate().any(|(j, y)| {
            j != i && !y.user && (y.cat == "cred" || y.cat == "exfil" || is_theft_id(&y.id))
        });
        let x = &mut f[i];
        if !theft && !java_allowed {
            x.why.push_str(" (java/javaw.exe muafiyeti bu dosya için kapalı: Ayarlar > Kendi dosyalarım. Bulgu normal puanlandı.)");
        } else if !theft {
            x.sev = Severity::Info;
            x.w = 0.0;
            x.title = "java/javaw.exe hedefli bellek erişimi (puanlanmadı)".into();
            x.why = "Dosyada java.exe/javaw.exe adı geçiyor ve süreç belleğine okuma/yazma API’leri var. Çalma/sızdırma belirtisi (tarayıcı verisi, token, webhook vb.) bulunmadığı için bu bulgu puanlanmadı. Bu, dosyanın zararsız olduğunu göstermez: enjeksiyon Minecraft oturumunu okumak için de kullanılabilir.".into();
            x.exempt = true;
        } else {
            x.why.push_str(" Java/javaw.exe hedefi var VE çalma/sızdırma göstergeleri bulundu: muafiyet uygulanmadı.");
        }
    }
    let base: Vec<&Finding> = f.iter().filter(|x| !x.user).collect();
    let mut ids: HashSet<String> = base.iter().map(|x| x.id.clone()).collect();
    let cats: HashSet<&str> = base.iter().map(|x| x.cat.as_str()).filter(|c| !c.is_empty()).collect();
    let hi = base.iter().filter(|x| x.sev.rank() >= 3 && x.w >= 12.0).count();
    let cats: HashSet<String> = cats.into_iter().map(String::from).collect();
    drop(base);
    let has = |ids: &HashSet<String>, a: &[&str]| a.iter().any(|i| ids.contains(*i));
    let exfil = cats.contains("exfil");
    let cred = cats.contains("cred") || has(&ids, &["mc_token", "j_mctoken"]);
    let add = |f: &mut Vec<Finding>, ids: &mut HashSet<String>, x: Finding| {
        if !ids.contains(&x.id) {
            ids.insert(x.id.clone());
            f.push(x);
        }
    };
    use Severity::*;
    let mkc = |id, sev, w, t: &str, why: &str, act: &str, ev: &[&str]| {
        Finding::mk(id, sev, w, t, why, act, ev.iter().map(|s| s.to_string()).collect(), "")
    };
    if exfil && cred {
        add(f, &mut ids, mkc("combo_stealer", Crit, 40.0, "Kimlik / oturum verisi çalma kalıbı", "Hem hassas veri (şifre, token, oturum) erişimi hem de dışarıya gönderim kanalı aynı dosyada bulunuyor. Bu birleşim bir “stealer” davranışıdır.", "Çalıştırma. Çalıştırdıysan tüm şifreleri ve oturumları başka bir cihazdan değiştir.", &["gönderim kanalı + hassas veri erişimi"]));
    }
    if cats.contains("dl") && has(&ids, &["j_exec", "ps_iex", "certutil", "pe_dlexec", "sh_pipe"]) {
        add(f, &mut ids, mkc("combo_dropper", Crit, 25.0, "İndirici / dropper kalıbı", "Uzaktan içerik indirme ve çalıştırma yetenekleri birlikte bulunuyor.", "İndirilen adresi ve çalıştırılan dosyayı tespit et; ağ günlüklerini kontrol et.", &["indirme + çalıştırma"]));
    }
    if has(&ids, &["j_dynload"]) && has(&ids, &["j_net"]) {
        add(f, &mut ids, mkc("combo_loader", High, 20.0, "Dinamik kod yükleyici kalıbı", "Ağ erişimi ile çalışma anında sınıf/kod yükleme birlikte var. Dışarıdan kod çekip çalıştırabilir.", "Yüklenen kodun kaynağını bul; güvenilmiyorsa kullanma.", &["ağ + dinamik yükleme"]));
    }
    if has(&ids, &["persist_run"]) && (exfil || has(&ids, &["j_net", "pe_net"])) {
        add(f, &mut ids, mkc("combo_persist_net", High, 10.0, "Kalıcılık + ağ erişimi", "Kendini sisteme yerleştirme ve ağ iletişimi bir arada.", "Başlangıç girdilerini ve zamanlanmış görevleri kontrol et.", &[]));
    }
    if has(&ids, &["antivm"]) && (exfil || cred) {
        add(f, &mut ids, mkc("combo_evasion", High, 10.0, "Analizden kaçınma + veri toplama", "Sanal makine/analiz aracı kontrolü ile veri toplama aynı yerde.", "Analizi yalnızca izole ortamda yap.", &[]));
    }
    let net = has(&ids, &["j_net", "pe_net", "chain_c2", "doh_resolver"]) || exfil;
    if has(&ids, &["j_mctoken"]) && net && has(&ids, &["mc_logfile", "j_tls_custom", "chain_c2", "doh_resolver", "launcher_tokens", "silentnet_strings"]) {
        add(f, &mut ids, mkc("combo_mc_session_exfil", High, 18.0, "Minecraft oturum verisi + ağ gönderimi + ek C2/log göstergesi", "Oturum token’ına erişim, ağ gönderim yeteneği ve latest.log / özel TLS / gizli C2 çözümleme göstergelerinden en az biri birlikte bulundu. SilentNet gibi sahte mod stealer’larında bildirilen davranış birleşimine benzer; yine de tek başına kesin hüküm değildir.", "Token’ın hangi adrese gittiğini incele; hesabını korumak için şüphede oturumu kapatıp parolayı değiştir.", &["token erişimi + ağ + ek gösterge"]));
    }
    if has(&ids, &["chain_c2", "doh_resolver"]) && (cred || has(&ids, &["j_mctoken", "pe_dpapi"])) {
        add(f, &mut ids, mkc("combo_c2_resolver", High, 15.0, "Gizli C2 çözümleme + hassas veri erişimi", "DoH veya blokzincir RPC ile adres çözümleme, hassas veri erişimiyle aynı dosyada. Bazı stealer’lar C2 adresini bu yolla gizler.", "Çözülen adresi ve verinin nereye gittiğini araştır.", &[]));
    }
    if has(&ids, &["exfil_paste"]) && has(&ids, &["j_dynload", "j_exec", "ps_iex", "ps_download"]) {
        add(f, &mut ids, mkc("combo_paste_loader", High, 18.0, "Paste servisinden yük çekip çalıştırma kalıbı", "Pastebin tipi bir servis ile kod yükleme/çalıştırma birlikte. Stargazers kampanyasında Pastebin’den Base64 yük çekildiği bildirilmiştir.", "Çekilen içeriği ve çalıştırılan komutu tespit et.", &[]));
    }
    if has(&ids, &["addr_regex"]) && has(&ids, &["j_spy", "pe_clip"]) {
        add(f, &mut ids, mkc("combo_clipper", High, 15.0, "Pano + cüzdan adresi kalıbı (clipper)", "Pano erişimi ile kripto adres kalıpları birlikte; Fractureiser benzeri zararlılar panodaki cüzdan adresini değiştirir.", "Panoya yazılan değeri ve adres değiştirme koşulunu incele.", &[]));
    }
    if has(&ids, &["pe_dpapi"]) && has(&ids, &["pe_net"]) && has(&ids, &["browser_data"]) {
        add(f, &mut ids, mkc("combo_dpapi_net", High, 16.0, "Tarayıcı verisi + DPAPI çözme + ağ", "Tarayıcı kimlik veritabanı yolları, DPAPI ile çözme ve ağ erişimi bir arada: tarayıcı şifre/çerez çalan yazılımların tipik birleşimi.", "Verinin nereye gönderildiğini izole ortamda doğrula.", &[]));
    }
    if has(&ids, &["jf_trustall"]) && has(&ids, &["jf_steal", "jf_steal_known", "j_mctoken", "combo_stealer", "combo_mc_session_exfil"]) {
        add(f, &mut ids, mkc("combo_trust_steal", High, 12.0, "Doğrulamasız TLS + hassas veri akışı", "Sertifika/ana makine doğrulamasını kapatan bir sınıf ile hassas veri erişimi aynı dosyada. SilentNet analizlerinde “null TrustManager” ile oturum verisi gönderimi birlikte bildirilmiştir; yine de tek başına kesin hüküm değildir.", "Verinin hangi bağlantıdan, hangi adrese gittiğini decompiler’da doğrula.", &["doğrulanmış boş TrustManager/HostnameVerifier + hassas veri erişimi"]));
    }
    if has(&ids, &["pk_packer", "j_obf", "pe_highent", "js_obf", "bat_obf", "ps_obf"])
        && hi >= 1
        && (cred || has(&ids, &["combo_stealer", "combo_dropper", "pe_inject", "pe_hollow", "powershell_enc", "pe_keylog"]))
    {
        add(f, &mut ids, mkc("combo_obf_risk", Med, 8.0, "Gizleme + riskli davranış", "Kod gizleme veya paketleme ile riskli davranışlar aynı dosyada. Gizleme tek başına zararlı değildir; ama bu birleşim dikkat gerektirir.", "Dosyayı derinlemesine (dinamik ortamda) incele.", &[]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fnd(id: &str, sev: Severity, w: f64, cat: &str) -> Finding {
        Finding::mk(id, sev, w, "t", "w", "a", vec![], cat)
    }

    #[test]
    fn score_and_verdict_thresholds() {
        assert_eq!(score(&[fnd("a", Severity::Low, 9.4, "")]), 9);
        assert_eq!(score(&[fnd("a", Severity::Low, 9.5, "")]), 10);
        assert_eq!(verdict(9), "Belirgin bulgu yok");
        assert_eq!(verdict(10), "Düşük risk");
        assert_eq!(verdict(30), "Şüpheli");
        assert_eq!(verdict(55), "Yüksek risk");
        assert_eq!(verdict(80), "Kritik");
        assert_eq!(score(&[fnd("a", Severity::Crit, 400.0, "")]), 100);
    }

    #[test]
    fn stealer_combo_added_once() {
        let mut f = vec![fnd("x", Severity::High, 15.0, "exfil"), fnd("y", Severity::High, 15.0, "cred")];
        apply_combos(&mut f, false);
        apply_combos(&mut f, false);
        assert_eq!(f.iter().filter(|x| x.id == "combo_stealer").count(), 1);
    }

    #[test]
    fn java_inject_exempt_without_theft() {
        let mut p = fnd("pe_inject", Severity::High, 20.0, "inject");
        p.java_target = true;
        let mut f = vec![p];
        apply_combos(&mut f, true);
        assert_eq!(f[0].w, 0.0);
        assert!(f[0].exempt);
    }

    #[test]
    fn sort_is_stable_by_sev_then_weight() {
        let mut f = vec![fnd("a", Severity::Low, 5.0, ""), fnd("b", Severity::High, 5.0, ""), fnd("c", Severity::High, 9.0, ""), fnd("d", Severity::Low, 5.0, "")];
        sort_f(&mut f);
        let ids: Vec<_> = f.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids, ["c", "b", "a", "d"]);
        assert!(f.iter().all(|x| x.basis.is_some()));
    }

    #[test]
    fn profile_has_six_axes() {
        let p = profile(&[fnd("a", Severity::High, 20.0, "exfil")]);
        assert_eq!(p.len(), 6);
        assert_eq!(p[0].key, "net");
        assert_eq!(p[0].value, 60);
    }
}
