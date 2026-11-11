//! JS motorundan `rust/tools/dump-data.mjs` ile dokulen veri tablolari (derleme zamaninda gomulur).

use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

#[derive(Debug, Deserialize)]
pub struct RuleRow {
    pub id: String,
    pub re: String,
    pub flags: String,
    pub w: f64,
    pub sev: String,
    pub t: String,
    pub why: String,
    pub act: String,
    pub cat: String,
    pub distinct: usize,
    pub min_count: usize,
    pub scope: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ModeCfg {
    pub id: String,
    pub label: String,
    pub depth: usize,
    pub parse: bool,
    #[serde(rename = "flowDepth")]
    pub flow_depth: usize,
    pub ids: Option<Vec<String>>,
    #[serde(rename = "strCap")]
    pub str_cap: f64,
    pub deobf: bool,
    pub xor: bool,
    pub ioc: u8,
    #[serde(rename = "deepJar")]
    pub deep_jar: bool,
    #[serde(rename = "limitMs")]
    pub limit_ms: f64,
    #[serde(rename = "entryCap")]
    pub entry_cap: f64,
    #[serde(rename = "maxTotal")]
    pub max_total: f64,
    #[serde(rename = "textCap")]
    pub text_cap: f64,
    #[serde(rename = "maxEntries")]
    pub max_entries: usize,
    #[serde(rename = "maxClasses")]
    pub max_classes: usize,
    #[serde(rename = "maxInput")]
    pub max_input: f64,
    pub ran: Vec<String>,
    pub skipped: Vec<String>,
    pub never: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegexSpec {
    pub src: String,
    pub flags: String,
}

#[derive(Debug, Deserialize)]
pub struct RefRow {
    pub src: Vec<String>,
    pub mitre: Vec<String>,
    pub conf: String,
}

#[derive(Debug, Deserialize)]
pub struct NeverLed {
    pub id: String,
    pub label: String,
    pub status: String,
    pub note: String,
}

#[derive(Debug, Deserialize)]
pub struct Meta {
    pub fp: HashMap<String, String>,
    pub fp_cat: HashMap<String, String>,
    pub benign_hosts: RegexSpec,
    pub never_led: Vec<NeverLed>,
    pub office_re: String,
    pub exe_ext: Vec<String>,
    pub text_ext: Vec<String>,
    pub decoy_ext: Vec<String>,
    pub one_magic: Vec<u8>,
    pub fact_ids: Vec<String>,
    pub heur_ids: Vec<String>,
    pub mitre: HashMap<String, Vec<String>>,
    pub skip_labels: HashMap<String, String>,
    pub refs: HashMap<String, RefRow>,
    pub axes: Vec<(String, String)>,
    pub cat_axis: HashMap<String, String>,
    pub ioc_pats: Vec<(String, RegexSpec)>,
    pub version: String,
}

pub static RULE_ROWS: LazyLock<Vec<RuleRow>> =
    LazyLock::new(|| serde_json::from_str(include_str!("../data/str_rules.json")).expect("str_rules.json"));

pub static MODES: LazyLock<HashMap<String, ModeCfg>> =
    LazyLock::new(|| serde_json::from_str(include_str!("../data/modes.json")).expect("modes.json"));

pub static META: LazyLock<Meta> = LazyLock::new(|| {
    // ioc_pats nesne (siralamasi onemli): once ham JSON'dan sirayi koruyarak oku.
    let v: Value = serde_json::from_str(include_str!("../data/meta.json")).expect("meta.json");
    let mut m = v.clone();
    if let Some(o) = m.get_mut("ioc_pats").and_then(|x| x.as_object()).cloned() {
        let arr: Vec<Value> = o.into_iter().map(|(k, val)| Value::Array(vec![Value::String(k), val])).collect();
        m["ioc_pats"] = Value::Array(arr);
    }
    if let Some(a) = m.get("axes").cloned() {
        // axes zaten [[key,label],...]
        m["axes"] = a;
    }
    serde_json::from_value(m).expect("meta.json bicimi")
});

pub static FACT_IDS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| META.fact_ids.iter().map(|s| s.as_str()).collect());
pub static HEUR_IDS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| META.heur_ids.iter().map(|s| s.as_str()).collect());

pub fn mode(name: &str) -> &'static ModeCfg {
    MODES.get(name).unwrap_or_else(|| MODES.get("normal").expect("normal mod"))
}

pub const DISCLAIMER: &str = "Bu sonuç sezgisel statik analizdir; dosya çalıştırılmadı. “Belirgin bulgu yok” sonucu güvenli olduğunu kanıtlamaz; paketlenmiş veya özel yazılmış zararlılar kuralları atlatabilir. Yanlış pozitifler mümkündür; her bulgunun yanındaki açıklamaya bak.";
