//! JS (ECMAScript, `u` bayragi olmadan) regex sozdizimini Rust'a cevirir.
//!
//! Farklar: JS'te `\w \d \s \b` yalniz ASCII (ve `\s` icin ozel bosluk kumesi), `.` satir sonlarini
//! (\n \r U+2028 U+2029) eslemez. Rust `regex` varsayilan olarak Unicode oldugu icin bunlar elle cevrilir.
//! Lookahead gibi ozellikler `fancy-regex` ile derlenir; digerleri dogrusal zamanli `regex` ile calisir
//! (JS motorundaki geri izleme/ReDoS riski yok).

use regex::RegexBuilder;

pub enum Engine {
    Plain(regex::Regex),
    Fancy(fancy_regex::Regex),
}

pub struct Rx {
    eng: Engine,
}

const JS_WS_CLASS: &str =
    r"\t\n\x0B\x0C\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}";

fn hex_lit(c: char) -> String {
    format!("\\x{{{:x}}}", c as u32)
}

/// JS regex kaynagini Rust `regex` sozdizimine cevirir.
pub fn translate(src: &str) -> Result<String, String> {
    let cs: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len() + 16);
    let mut i = 0;
    let mut in_class = false;
    while i < cs.len() {
        let c = cs[i];
        if c == '\\' {
            if i + 1 >= cs.len() {
                return Err("sonda tek ters bolu".into());
            }
            let n = cs[i + 1];
            i += 2;
            match n {
                'w' => out.push_str(if in_class { "A-Za-z0-9_" } else { "[A-Za-z0-9_]" }),
                'W' => out.push_str("[^A-Za-z0-9_]"),
                'd' => out.push_str(if in_class { "0-9" } else { "[0-9]" }),
                'D' => out.push_str("[^0-9]"),
                's' => {
                    if in_class {
                        out.push_str(JS_WS_CLASS)
                    } else {
                        out.push('[');
                        out.push_str(JS_WS_CLASS);
                        out.push(']')
                    }
                }
                'S' => {
                    out.push_str("[^");
                    out.push_str(JS_WS_CLASS);
                    out.push(']')
                }
                'b' if !in_class => out.push_str("(?-u:\\b)"),
                'B' if !in_class => out.push_str("(?-u:\\B)"),
                'b' => out.push_str("\\x08"),
                'n' => out.push_str("\\n"),
                'r' => out.push_str("\\r"),
                't' => out.push_str("\\t"),
                'f' => out.push_str("\\f"),
                'v' => out.push_str("\\v"),
                '0' => out.push_str("\\x00"),
                'x' => {
                    let h: String = cs.get(i..i + 2).map(|s| s.iter().collect()).unwrap_or_default();
                    let v = u32::from_str_radix(&h, 16).map_err(|_| "gecersiz \\x".to_string())?;
                    out.push_str(&format!("\\x{{{v:x}}}"));
                    i += 2;
                }
                'u' => {
                    let h: String = cs.get(i..i + 4).map(|s| s.iter().collect()).unwrap_or_default();
                    let v = u32::from_str_radix(&h, 16).map_err(|_| "gecersiz \\u".to_string())?;
                    out.push_str(&format!("\\x{{{v:x}}}"));
                    i += 4;
                }
                c if c.is_ascii_alphanumeric() => return Err(format!("desteklenmeyen kacis \\{c}")),
                c => out.push_str(&hex_lit(c)),
            }
            continue;
        }
        if in_class {
            match c {
                ']' => {
                    in_class = false;
                    out.push(']');
                }
                '[' | '&' | '~' => out.push_str(&hex_lit(c)),
                _ => out.push(c),
            }
        } else {
            match c {
                '[' => {
                    in_class = true;
                    out.push('[');
                    if cs.get(i + 1) == Some(&'^') {
                        out.push('^');
                        i += 1;
                    }
                }
                '.' => out.push_str("[^\\n\\r\\x{2028}\\x{2029}]"),
                _ => out.push(c),
            }
        }
        i += 1;
    }
    if in_class {
        return Err("kapanmamis sinif".into());
    }
    Ok(out)
}

impl Rx {
    pub fn new(src: &str, flags: &str) -> Result<Rx, String> {
        let tr = translate(src)?;
        let pat = if flags.contains('i') { format!("(?i){tr}") } else { tr };
        match RegexBuilder::new(&pat).size_limit(64 << 20).build() {
            Ok(r) => Ok(Rx { eng: Engine::Plain(r) }),
            Err(_) => fancy_regex::Regex::new(&pat)
                .map(|r| Rx { eng: Engine::Fancy(r) })
                .map_err(|e| format!("regex derlenemedi ({src}): {e}")),
        }
    }

    pub fn is_fancy(&self) -> bool {
        matches!(self.eng, Engine::Fancy(_))
    }

    /// Ilk eslesme metni.
    pub fn find<'t>(&self, t: &'t str) -> Option<&'t str> {
        match &self.eng {
            Engine::Plain(r) => r.find(t).map(|m| m.as_str()),
            Engine::Fancy(r) => r.find(t).ok().flatten().map(|m| m.as_str()),
        }
    }

    pub fn is_match(&self, t: &str) -> bool {
        self.find(t).is_some()
    }

    /// En fazla `max` eslesme (soldan saga, ust uste binmeyen).
    pub fn find_all<'t>(&self, t: &'t str, max: usize) -> Vec<&'t str> {
        let mut v = Vec::new();
        match &self.eng {
            Engine::Plain(r) => {
                for m in r.find_iter(t) {
                    if v.len() >= max {
                        break;
                    }
                    v.push(m.as_str());
                }
            }
            Engine::Fancy(r) => {
                for m in r.find_iter(t) {
                    if v.len() >= max {
                        break;
                    }
                    if let Ok(m) = m {
                        v.push(m.as_str());
                    }
                }
            }
        }
        v
    }

    /// Ilk eslesmede 1. yakalama grubu.
    pub fn capture1<'t>(&self, t: &'t str) -> Option<&'t str> {
        match &self.eng {
            Engine::Plain(r) => r.captures(t).and_then(|c| c.get(1)).map(|m| m.as_str()),
            Engine::Fancy(r) => r.captures(t).ok().flatten().and_then(|c| c.get(1)).map(|m| m.as_str()),
        }
    }
}

/// Kod icinde sabit JS regex'i (bayraklar: "i" veya ""). Derlenemezse panik (yalniz gelistirme zamani hatasi).
pub fn js(src: &str, flags: &str) -> Rx {
    Rx::new(src, flags).unwrap_or_else(|e| panic!("sabit regex hatali: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_word_semantics() {
        let r = js(r"\bfoo\b", "");
        assert!(r.is_match("a foo b"));
        // JS: 'é' kelime karakteri degil -> \b sinir sayilir; Rust (?-u:\b) de ayni.
        assert!(r.is_match("éfooé"));
        assert!(!r.is_match("xfoo"));
    }

    #[test]
    fn dot_excludes_line_breaks() {
        let r = js(r"a.b", "");
        assert!(r.is_match("a-b"));
        assert!(!r.is_match("a\nb"));
        assert!(!r.is_match("a\rb"));
        assert!(!r.is_match("a\u{2028}b"));
    }

    #[test]
    fn js_space_class() {
        let r = js(r"a\sb", "");
        assert!(r.is_match("a\u{a0}b"));
        assert!(r.is_match("a\u{feff}b"));
    }

    #[test]
    fn lookahead_via_fancy() {
        let r = js(r"https?://(?!127\.|10\.)\d{1,3}\.\d{1,3}", "i");
        assert!(r.is_fancy());
        assert!(r.is_match("http://8.8.8.8/x"));
        assert!(!r.is_match("http://127.0.0.1/x"));
    }

    #[test]
    fn escapes_and_classes() {
        let r = js(r#"[^\s"'<>\\)\]\u0000-\u001f]{4,8}"#, "i");
        assert_eq!(r.find("ab cdefgh ij"), Some("cdefgh"));
        let r = js(r"\/shard\/(?:prefireMc|x)", "");
        assert!(r.is_match("/shard/prefireMc"));
        let r = js(r"0x\[a-fA-F0-9\]\{40\}", "");
        assert!(r.is_match("0x[a-fA-F0-9]{40}"));
    }

    #[test]
    fn all_rule_rows_compile() {
        for row in crate::data::RULE_ROWS.iter() {
            Rx::new(&row.re, &row.flags).unwrap_or_else(|e| panic!("{}: {e}", row.id));
        }
        for (k, spec) in crate::data::META.ioc_pats.iter() {
            Rx::new(&spec.src, &spec.flags).unwrap_or_else(|e| panic!("ioc {k}: {e}"));
        }
    }
}
