//! IOC (URL/IP/e-posta/kayit defteri/yol/cuzdan/webhook/...) cikarimi: JS `addIoc/finalizeIoc/mergeIoc`.

use crate::data::META;
use crate::rx::Rx;
use crate::util::mask;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::LazyLock;

struct Pat {
    key: &'static str,
    rx: Rx,
}

static PATS: LazyLock<Vec<Pat>> = LazyLock::new(|| {
    META.ioc_pats
        .iter()
        .map(|(k, s)| Pat {
            // anahtarlar sabit kume: 'static ihtiyaci icin sizdirilir (bir kez, surec omru boyunca)
            key: Box::leak(k.clone().into_boxed_str()),
            rx: Rx::new(&s.src, &s.flags).unwrap_or_else(|e| panic!("ioc {k}: {e}")),
        })
        .collect()
});

static BENIGN: LazyLock<Rx> =
    LazyLock::new(|| Rx::new(&META.benign_hosts.src, &META.benign_hosts.flags).expect("benign_hosts"));

static PRIVATE_IP: LazyLock<Rx> = LazyLock::new(|| {
    Rx::new(r"^(?:0\.|127\.|255\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)", "").expect("private ip")
});

#[derive(Default, Clone)]
pub struct IocSet {
    sets: Vec<(&'static str, Vec<String>, HashSet<String>)>,
}

impl IocSet {
    pub fn new() -> Self {
        IocSet { sets: PATS.iter().map(|p| (p.key, Vec::new(), HashSet::new())).collect() }
    }
}

const BASIC: [&str; 5] = ["url", "ip", "webhook", "telegram", "onion"];

/// `level`: 0 kapali, 1 temel (url/ip/webhook/telegram/onion), 2+ tum desenler.
pub fn add_ioc(io: &mut IocSet, text: &str, level: u8) {
    if level == 0 || text.is_empty() {
        return;
    }
    if io.sets.is_empty() {
        *io = IocSet::new();
    }
    let t = if text.len() > 4_000_000 {
        let mut e = 4_000_000;
        while !text.is_char_boundary(e) {
            e -= 1;
        }
        &text[..e]
    } else {
        text
    };
    for (pi, p) in PATS.iter().enumerate() {
        if level < 2 && !BASIC.contains(&p.key) {
            continue;
        }
        let (_, order, set) = &mut io.sets[pi];
        for v in p.rx.find_all(t, 300) {
            if set.len() >= 200 {
                break;
            }
            if p.key == "ip" && PRIVATE_IP.is_match(v) {
                continue;
            }
            if set.insert(v.to_string()) {
                order.push(v.to_string());
            }
        }
    }
}

/// Bos ise `None`. Dizi anahtarlari JS ile ayni sirada; sonda `domain`.
pub fn finalize_ioc(io: &IocSet) -> Option<Map<String, Value>> {
    let mut o = Map::new();
    for (k, order, _) in &io.sets {
        let a: Vec<Value> = order
            .iter()
            .take(40)
            .map(|x| {
                let s = if matches!(*k, "url" | "webhook" | "telegram") { mask(x) } else { x.clone() };
                Value::String(s)
            })
            .collect();
        if !a.is_empty() {
            o.insert((*k).to_string(), Value::Array(a));
        }
    }
    if o.is_empty() {
        return None;
    }
    if let Some((_, urls, _)) = io.sets.iter().find(|s| s.0 == "url") {
        let mut hosts: Vec<String> = Vec::new();
        let mut seen = HashSet::new();
        for u in urls {
            if let Ok(p) = url::Url::parse(u) {
                if let Some(h) = p.host_str() {
                    if seen.insert(h.to_string()) {
                        hosts.push(h.to_string());
                    }
                }
            }
        }
        let d: Vec<Value> = hosts.into_iter().filter(|h| !BENIGN.is_match(h)).take(40).map(Value::String).collect();
        if !d.is_empty() {
            o.insert("domain".into(), Value::Array(d));
        }
    }
    Some(o)
}

pub fn merge_ioc(a: Option<Map<String, Value>>, b: Option<&Map<String, Value>>) -> Option<Map<String, Value>> {
    let Some(b) = b else { return a };
    let mut a = a.unwrap_or_default();
    for (k, bv) in b {
        let mut seen = HashSet::new();
        let mut out: Vec<Value> = Vec::new();
        let old = a.get(k).and_then(|v| v.as_array()).cloned().unwrap_or_default();
        for v in old.into_iter().chain(bv.as_array().cloned().unwrap_or_default()) {
            if let Some(s) = v.as_str() {
                if seen.insert(s.to_string()) {
                    out.push(v);
                }
            }
        }
        out.truncate(40);
        a.insert(k.clone(), Value::Array(out));
    }
    Some(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_and_filters() {
        let mut io = IocSet::new();
        add_ioc(&mut io, "GET http://evil.example.net/a.exe from 8.8.4.4 and 10.0.0.5 or 127.0.0.1", 1);
        let o = finalize_ioc(&io).unwrap();
        assert_eq!(o["ip"].as_array().unwrap().len(), 1);
        assert_eq!(o["url"][0], "http://evil.example.net/a.exe");
        assert_eq!(o["domain"][0], "evil.example.net");
        assert!(!o.contains_key("email"));
    }

    #[test]
    fn level2_adds_email_and_registry() {
        let mut io = IocSet::new();
        add_ioc(&mut io, r"mail bob@example.org HKCU\Software\Microsoft\Windows\Run", 2);
        let o = finalize_ioc(&io).unwrap();
        assert!(o.contains_key("email") && o.contains_key("reg"));
    }

    #[test]
    fn empty_is_none() {
        let mut io = IocSet::new();
        add_ioc(&mut io, "nothing here", 2);
        assert!(finalize_ioc(&io).is_none());
    }
}
