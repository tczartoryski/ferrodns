//! Structured resolution traces and a dependency-free, HTML-safe JSON writer.
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Event {
    pub t_ms: f64,
    pub dur_ms: f64,
    pub depth: usize,
    pub kind: &'static str,
    pub zone: Option<String>,
    pub server: Option<String>,
    pub ip: Option<String>,
    pub qname: String,
    pub qtype: String,
    /// Final response transport, unknown on failure. TCP duration includes UDP fallback.
    pub transport: Option<&'static str>,
    pub outcome: Option<&'static str>,
    pub detail: String,
}

impl Event {
    pub fn to_json(&self) -> String {
        let json = Trace {
            name: String::new(),
            qtype: String::new(),
            started_at: String::new(),
            total_ms: 0.0,
            rcode: String::new(),
            answers: vec![],
            events: vec![self.clone()],
        }
        .to_json();
        let start = json.find("\"events\":[").unwrap() + 10;
        json[start..json.len() - 2].to_string()
    }

    pub fn text(&self) -> String {
        let detail = if self.kind == "query" {
            let via = if self.transport == Some("tcp") {
                " (TC, retried over TCP)"
            } else {
                ""
            };
            let timing = if self.transport.is_some() {
                format!("  {:.1}ms{via}", self.dur_ms)
            } else {
                String::new()
            };
            format!(
                "[{}] {} ({}) {} {} -> {}{timing}",
                self.zone.as_deref().unwrap_or(""),
                self.server.as_deref().unwrap_or(""),
                self.ip.as_deref().unwrap_or(""),
                self.qname,
                self.qtype,
                self.detail
            )
        } else {
            self.detail.clone()
        };
        format!("{}{detail}", "  ".repeat(self.depth))
    }
}

#[derive(Debug, Clone)]
pub struct Trace {
    pub name: String,
    pub qtype: String,
    pub started_at: String,
    pub total_ms: f64,
    pub rcode: String,
    pub answers: Vec<String>,
    pub events: Vec<Event>,
}

// Escaping '<' prevents the HTML parser from recognizing </script> even inside JSON strings.
pub(crate) fn string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' | '\u{0}'..='\u{1f}' => {
                write!(out, "\\u{:04x}", c as u32).unwrap();
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn number(n: f64) -> String {
    if n.is_finite() {
        format!("{n:.3}")
    } else {
        "null".into()
    }
}

impl Trace {
    /// The same JSON is safe both as a standalone file and as HTML script data.
    pub fn to_json(&self) -> String {
        let mut out = format!(
            "{{\"question\":{{\"name\":{},\"type\":{}}},\"started_at\":{},\"total_ms\":{},\"rcode\":{},\"answers\":[{}],\"events\":[",
            string(&self.name),
            string(&self.qtype),
            string(&self.started_at),
            number(self.total_ms),
            string(&self.rcode),
            self.answers
                .iter()
                .map(|s| string(s))
                .collect::<Vec<_>>()
                .join(",")
        );
        for (i, e) in self.events.iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            write!(
                out,
                "{{\"t_ms\":{},\"dur_ms\":{},\"depth\":{},\"kind\":{}",
                number(e.t_ms),
                number(e.dur_ms),
                e.depth,
                string(e.kind)
            )
            .unwrap();
            for (key, val) in [("zone", &e.zone), ("server", &e.server), ("ip", &e.ip)] {
                if let Some(val) = val {
                    write!(out, ",\"{key}\":{}", string(val)).unwrap();
                }
            }
            write!(
                out,
                ",\"qname\":{},\"qtype\":{}",
                string(&e.qname),
                string(&e.qtype)
            )
            .unwrap();
            if e.kind == "query" {
                write!(
                    out,
                    ",\"transport\":{}",
                    e.transport.map(string).unwrap_or_else(|| "null".into())
                )
                .unwrap();
            }
            if let Some(outcome) = e.outcome {
                write!(out, ",\"outcome\":{}", string(outcome)).unwrap();
            }
            write!(out, ",\"detail\":{}}}", string(&e.detail)).unwrap();
        }
        out.push_str("]}");
        out
    }

    /// Insert before application scripts so the viewer can read the trace on startup.
    pub fn embed_html(&self, template: &str) -> String {
        let script = format!(
            "<script id=\"trace\" type=\"application/json\">{}</script>\n",
            self.to_json()
        );
        // Standalone exports use the embedded trace and have no live backend assets.
        let mut template = template.replace("<script src=\"live.js\"></script>", "");
        if let Some(start) = template.find("<form id=\"live-form\"")
            && let Some(end) = template[start..].find("</form>")
        {
            template.replace_range(start..start + end + "</form>".len(), "");
        }
        // Replace any empty trace element rather than leave duplicate IDs.
        let mut search = 0;
        while let Some(offset) = template[search..].to_ascii_lowercase().find("<script") {
            let start = search + offset;
            let Some(end) = template[start..].find('>') else {
                break;
            };
            let end = start + end + 1;
            let tag = template[start..end].to_ascii_lowercase();
            if tag.contains("id=\"trace\"") || tag.contains("id='trace'") {
                let Some(close) = template[end..].to_ascii_lowercase().find("</script>") else {
                    break;
                };
                template.replace_range(start..end + close + "</script>".len(), "");
                search = start;
            } else {
                search = end;
            }
        }
        if let Some(pos) = template.to_ascii_lowercase().find("<script") {
            format!("{}{script}{}", &template[..pos], &template[pos..])
        } else if let Some(pos) = template.to_ascii_lowercase().find("</head>") {
            format!("{}{script}{}", &template[..pos], &template[pos..])
        } else {
            format!("{script}{template}")
        }
    }

    /// Exclusive creation avoids collisions and overwrites across concurrent requests/restarts.
    pub fn write_in_dir(&self, dir: &Path) -> io::Result<PathBuf> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("trace-{}-{id}.json", std::process::id()));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    if let Err(e) = file.write_all(self.to_json().as_bytes()) {
                        let _ = std::fs::remove_file(&path);
                        return Err(e);
                    }
                    return Ok(path);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

pub(crate) fn timestamp() -> String {
    utc_timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
}

fn utc_timestamp(seconds: u64) -> String {
    // Gregorian civil date from Unix days (400-year eras).
    let days = (seconds / 86400) as i64 + 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let time = seconds % 86400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        time / 60 % 60,
        time % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_dates() {
        assert_eq!(utc_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_timestamp(951827696), "2000-02-29T12:34:56Z");
        assert_eq!(utc_timestamp(1791827100), "2026-10-12T17:45:00Z");
    }

    #[test]
    fn json_strings_are_safe_in_html() {
        assert_eq!(
            string("\"\\\n\r\t\u{8}\u{c}\u{0}</ScRiPt><!-->&\u{2028}\u{2029}é"),
            "\"\\\"\\\\\\n\\r\\t\\u0008\\u000c\\u0000\\u003c/ScRiPt\\u003e\\u003c!--\\u003e\\u0026\\u2028\\u2029é\""
        );
        let trace = Trace {
            name: "</script><script>alert(1)</script>".into(),
            qtype: "A".into(),
            started_at: "epoch".into(),
            total_ms: 0.0,
            rcode: "NOERROR".into(),
            answers: vec!["</SCRIPT>".into()],
            events: vec![],
        };
        let offline = trace.embed_html(include_str!("../site/viz/index.html"));
        assert!(!offline.contains("src=\"live.js\""));
        assert!(!offline.contains("id=\"live-form\""));
        assert!(offline.contains("<script id=\"trace\""));
        let html = trace.embed_html("<html><head><script>viewer()</script></head></html>");
        assert_eq!(html.matches("id=\"trace\"").count(), 1);
        assert_eq!(html.matches("</script>").count(), 2);
        assert!(html.find("id=\"trace\"").unwrap() < html.find("viewer()").unwrap());
        assert!(!trace.to_json().contains('<'));
        let html = trace.embed_html("<head><script id=\"trace\" type=\"application/json\">OLD</script><script>viewer()</script></head>");
        assert_eq!(html.matches("id=\"trace\"").count(), 1);
        assert!(!html.contains("OLD"));
        assert!(html.find("id=\"trace\"").unwrap() < html.find("viewer()").unwrap());
        assert!(
            trace
                .embed_html("<head></head>")
                .contains("</script>\n</head>")
        );
    }
}
