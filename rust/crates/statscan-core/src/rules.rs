//! Dize/regex kural motoru: JS `runRules` / `hitsToFindings` karsiligi.

use crate::data::{RuleRow, RULE_ROWS};
use crate::model::{Finding, Severity};
use crate::rx::Rx;
use crate::util::{clip, mask};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

pub struct Rule {
    pub row: &'static RuleRow,
    pub sev: Severity,
    pub rx: Rx,
}

pub static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    RULE_ROWS
        .iter()
        .map(|row| Rule {
            row,
            sev: Severity::parse(&row.sev).unwrap_or_else(|| panic!("kural {}: gecersiz sev {}", row.id, row.sev)),
            rx: Rx::new(&row.re, &row.flags).unwrap_or_else(|e| panic!("kural {}: {e}", row.id)),
        })
        .collect()
});

/// Kural turu: JS'te `kind` ('script' ya da '').
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Script,
    Other,
}

pub struct Hit {
    pub rule: usize,
    pub count: usize,
    pub set: HashSet<String>,
    pub ex: Vec<(String, String)>,
}

/// Eklenme sirasini koruyan eslesme tablosu (JS `Map`).
#[derive(Default)]
pub struct Hits {
    order: Vec<Hit>,
    idx: HashMap<usize, usize>,
}

impl Hits {
    pub fn new() -> Self {
        Self::default()
    }
    fn get_or_add(&mut self, rule: usize) -> &mut Hit {
        let i = match self.idx.get(&rule) {
            Some(&i) => i,
            None => {
                self.order.push(Hit { rule, count: 0, set: HashSet::new(), ex: Vec::new() });
                self.idx.insert(rule, self.order.len() - 1);
                self.order.len() - 1
            }
        };
        &mut self.order[i]
    }
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// Cok buyuk metinlerde regex maliyetini sinirlamak icin 1 MB'lik pencerelerle calisir (JS ile ayni sinir).
pub fn run_rules(text: &str, hits: &mut Hits, where_: &str, kind: Kind, ids: Option<&HashSet<&str>>) {
    const WIN: usize = 1_000_000;
    if text.len() > 2_000_000 {
        let mut i = 0;
        while i < text.len() {
            let start = floor_boundary(text, i);
            let end = floor_boundary(text, (i + WIN + 300).min(text.len()));
            run_rules_one(&text[start..end], hits, where_, kind, ids);
            i += WIN;
        }
        return;
    }
    run_rules_one(text, hits, where_, kind, ids);
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    if i >= s.len() {
        return s.len();
    }
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn run_rules_one(text: &str, hits: &mut Hits, where_: &str, kind: Kind, ids: Option<&HashSet<&str>>) {
    for (ri, r) in RULES.iter().enumerate() {
        let row = r.row;
        if let Some(ids) = ids {
            if !ids.contains(row.id.as_str()) {
                continue;
            }
        }
        if row.scope == "script" && kind != Kind::Script {
            continue;
        }
        if row.scope == "binary" && kind == Kind::Script {
            continue;
        }
        if row.distinct > 0 || row.min_count > 0 {
            let all = r.rx.find_all(text, 201);
            if all.is_empty() {
                continue;
            }
            let h = hits.get_or_add(ri);
            // JS: n sayaci 200'u asinca durur (n > 200 -> break); en fazla 201 eslesme sayilir.
            let mut n = 0usize;
            for m in all {
                n += 1;
                h.set.insert(m.to_lowercase());
                if h.ex.len() < 3 {
                    h.ex.push((where_.to_string(), clip(m, 140)));
                }
                if n > 200 {
                    break;
                }
            }
            h.count += n;
        } else if let Some(m) = r.rx.find(text) {
            let h = hits.get_or_add(ri);
            h.count += 1;
            if h.ex.len() < 3 {
                let shown = if row.id.starts_with("exfil") { clip(&mask(m), 140) } else { clip(m, 140) };
                h.ex.push((where_.to_string(), shown));
            }
        }
    }
}

pub fn hits_to_findings(hits: &Hits, out: &mut Vec<Finding>) {
    for h in &hits.order {
        let r = &RULES[h.rule];
        let row = r.row;
        if row.distinct > 0 && h.set.len() < row.distinct {
            continue;
        }
        if row.min_count > 0 && h.count < row.min_count {
            continue;
        }
        let ev = h
            .ex
            .iter()
            .map(|(w, t)| if w.is_empty() { t.clone() } else { format!("{w}: {t}") })
            .collect();
        out.push(Finding::mk(&row.id, r.sev, row.w, &row.t, &row.why, &row.act, ev, &row.cat));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_is_masked_in_evidence() {
        let mut h = Hits::new();
        run_rules(
            "curl https://discord.com/api/webhooks/123456789/abcdefGHIJKLmnopQRSTuvwx",
            &mut h,
            "",
            Kind::Script,
            None,
        );
        let mut f = vec![];
        hits_to_findings(&h, &mut f);
        let x = f.iter().find(|x| x.id == "exfil_discord").expect("exfil_discord");
        assert!(x.ev[0].contains("…[gizlendi]"), "{:?}", x.ev);
    }

    #[test]
    fn script_scope_rules_skip_in_binary_kind() {
        let mut h = Hits::new();
        run_rules("powershell -enc AAAA", &mut h, "", Kind::Other, None);
        let mut f = vec![];
        hits_to_findings(&h, &mut f);
        assert!(f.iter().all(|x| RULES.iter().find(|r| r.row.id == x.id).unwrap().row.scope != "script"));
    }
}
