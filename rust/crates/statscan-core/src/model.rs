//! Bulgu / sonuc modeli. JSON alan adlari JS motorunun ciktisiyla ayni (arayuz ve raporlar ayni bicimi okur).

use crate::util::num_json;
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Med,
    High,
    Crit,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Med => 2,
            Severity::High => 3,
            Severity::Crit => 4,
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "med" => Severity::Med,
            "high" => Severity::High,
            "crit" => Severity::Crit,
            _ => return None,
        })
    }
}

fn ser_num<S: Serializer>(x: &f64, s: S) -> Result<S::Ok, S::Error> {
    num_json(*x).serialize(s)
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub id: String,
    pub sev: Severity,
    #[serde(serialize_with = "ser_num")]
    pub w: f64,
    pub title: String,
    pub why: String,
    pub act: String,
    pub cat: String,
    pub ev: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conf: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cls: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,
    #[serde(skip_serializing_if = "is_false")]
    pub user: bool,
    #[serde(skip_serializing_if = "is_false")]
    pub exempt: bool,
    #[serde(rename = "javaTarget", skip_serializing_if = "is_false")]
    pub java_target: bool,
}

impl Finding {
    /// JS `mk(id, sev, w, title, why, act, ev, cat)`.
    pub fn mk(id: &str, sev: Severity, w: f64, title: &str, why: &str, act: &str, ev: Vec<String>, cat: &str) -> Self {
        Finding {
            id: id.into(),
            sev,
            w,
            title: title.into(),
            why: why.into(),
            act: act.into(),
            cat: cat.into(),
            ev,
            basis: None,
            src: None,
            mitre: None,
            conf: None,
            fp: None,
            cls: None,
            count: None,
            user: false,
            exempt: false,
            java_target: false,
        }
    }
    pub fn with_basis(mut self, b: &str) -> Self {
        self.basis = Some(b.into());
        self
    }
    pub fn with_mitre(mut self, m: &[&str]) -> Self {
        self.mitre = Some(m.iter().map(|s| s.to_string()).collect());
        self
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Analysis {
    pub id: String,
    pub label: String,
    pub status: String,
    pub note: String,
}

impl Analysis {
    /// JS `led(id, label, status, note)`.
    pub fn led(id: &str, label: &str, status: &str, note: &str) -> Self {
        Analysis { id: id.into(), label: label.into(), status: status.into(), note: note.into() }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AxisValue {
    pub key: String,
    pub label: String,
    pub value: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct LimitNote {
    pub kind: String,
    pub msg: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SkipNote {
    pub key: String,
    pub label: String,
    pub count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanResult {
    pub name: String,
    pub path: String,
    pub size: usize,
    #[serde(rename = "type")]
    pub kind_label: String,
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    #[serde(serialize_with = "ser_num")]
    pub entropy: f64,
    pub score: i64,
    #[serde(rename = "ownScore")]
    pub own_score: i64,
    pub verdict: String,
    pub findings: Vec<Finding>,
    pub info: Map<String, Value>,
    pub children: Vec<ScanResult>,
    pub analyses: Vec<Analysis>,
    pub profile: Vec<AxisValue>,
    #[serde(rename = "scoreFrom", skip_serializing_if = "Option::is_none")]
    pub score_from: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub deduped: bool,
    // ust duzey alanlar (yalniz kok sonucta)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(rename = "modeLabel", skip_serializing_if = "Option::is_none")]
    pub mode_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<Vec<LimitNote>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<Vec<SkipNote>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ms: Option<u64>,
    #[serde(rename = "scannedAt", skip_serializing_if = "Option::is_none")]
    pub scanned_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclaimer: Option<String>,
}

impl ScanResult {
    pub fn new(name: &str, size: usize) -> Self {
        ScanResult {
            name: name.into(),
            path: name.into(),
            size,
            kind_label: String::new(),
            sha256: None,
            sha1: None,
            entropy: 0.0,
            score: 0,
            own_score: 0,
            verdict: String::new(),
            findings: vec![],
            info: Map::new(),
            children: vec![],
            analyses: vec![],
            profile: vec![],
            score_from: None,
            deduped: false,
            mode: None,
            mode_label: None,
            partial: None,
            limits: None,
            notes: None,
            skipped: None,
            coverage: None,
            stats: None,
            ms: None,
            scanned_at: None,
            disclaimer: None,
        }
    }
}
