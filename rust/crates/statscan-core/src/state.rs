//! Tarama durumu: sinirlar, notlar, atlananlar, onbellek, sure/iptal denetimi (JS `st`).

use crate::data::{ModeCfg, META};
use crate::model::{LimitNote, ScanResult, SkipNote};
use crate::util::fmt_n;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub struct St {
    pub cfg: &'static ModeCfg,
    pub notes: Vec<String>,
    pub limits: Vec<LimitNote>,
    pub partial: bool,
    pub stop: bool,
    pub cancelled: bool,
    pub cache: HashMap<String, ScanResult>,
    pub files: usize,
    pub classes: usize,
    pub bytes: f64,
    pub unreadable: usize,
    pub skips: Vec<(String, usize)>,
    pub entry_cap: f64,
    pub t0: Instant,
    pub limit_ms: u64,
    pub cancel: Option<Arc<AtomicBool>>,
    pub java_allowed: bool,
}

impl St {
    pub fn new(cfg: &'static ModeCfg, limit_ms: u64, cancel: Option<Arc<AtomicBool>>, java_allowed: bool) -> St {
        St {
            cfg,
            notes: vec![],
            limits: vec![],
            partial: false,
            stop: false,
            cancelled: false,
            cache: HashMap::new(),
            files: 0,
            classes: 0,
            bytes: 0.0,
            unreadable: 0,
            skips: vec![],
            entry_cap: cfg.entry_cap,
            t0: Instant::now(),
            limit_ms,
            cancel,
            java_allowed,
        }
    }

    pub fn note(&mut self, s: &str) {
        if !self.notes.iter().any(|n| n == s) {
            self.notes.push(s.to_string());
        }
    }

    pub fn skip(&mut self, k: &str, n: usize) {
        if let Some(e) = self.skips.iter_mut().find(|e| e.0 == k) {
            e.1 += n;
        } else {
            self.skips.push((k.to_string(), n));
        }
    }

    pub fn limit_hit(&mut self, kind: &str, msg: &str) {
        if kind == "depth" {
            self.skip("depth", 1);
        }
        self.partial = true;
        if !self.limits.iter().any(|l| l.kind == kind) {
            self.limits.push(LimitNote { kind: kind.into(), msg: msg.into() });
        }
    }

    /// Sure ve iptal denetimi (JS `st.tick`).
    pub fn tick(&mut self) {
        if self.t0.elapsed().as_millis() as u64 > self.limit_ms {
            if !self.stop {
                let s = (self.limit_ms as f64 / 1000.0).round();
                self.limit_hit("time", &format!("Süre sınırına ulaşıldı ({s} sn); tarama kısmi kaldı."));
            }
            self.stop = true;
        }
        if self.cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)) {
            if !self.cancelled {
                self.cancelled = true;
                self.limit_hit("cancel", "Tarama kullanıcı tarafından iptal edildi; sonuçlar kısmi.");
            }
            self.stop = true;
        }
    }

    pub fn skip_notes(&self) -> Vec<SkipNote> {
        self.skips
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(k, n)| SkipNote {
                key: k.clone(),
                label: META.skip_labels.get(k).cloned().unwrap_or_else(|| k.clone()),
                count: *n,
            })
            .collect()
    }
}

pub fn fmt_limit(n: f64) -> String {
    fmt_n(n)
}
