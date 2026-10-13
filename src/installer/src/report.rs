//! How an install tells the person what it's doing: printed lines on a
//! terminal, events in the window, or nothing at all with `--quiet`.

use std::io::{IsTerminal, Write};
use std::sync::Arc;

/// One line of progress. Steps are the headings ("Installing the service"),
/// details what happened under them, warnings what the person should know
/// but doesn't stop the install.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Step,
    Detail,
    Ok,
    Warn,
}

pub trait Sink: Send + Sync {
    fn line(&self, kind: Kind, text: &str);
}

#[derive(Clone)]
pub struct Report(Arc<dyn Sink>);

impl Report {
    pub fn new(sink: impl Sink + 'static) -> Self {
        Self(Arc::new(sink))
    }

    pub fn terminal(quiet: bool) -> Self {
        if quiet { Self::new(Quiet) } else { Self::new(Terminal { color: std::io::stdout().is_terminal() }) }
    }

    pub fn step(&self, text: impl AsRef<str>) {
        self.0.line(Kind::Step, text.as_ref());
    }

    pub fn detail(&self, text: impl AsRef<str>) {
        self.0.line(Kind::Detail, text.as_ref());
    }

    pub fn ok(&self, text: impl AsRef<str>) {
        self.0.line(Kind::Ok, text.as_ref());
    }

    pub fn warn(&self, text: impl AsRef<str>) {
        self.0.line(Kind::Warn, text.as_ref());
    }
}

struct Quiet;

impl Sink for Quiet {
    fn line(&self, kind: Kind, text: &str) {
        // Warnings still matter to whoever reads a scripted run's log.
        if kind == Kind::Warn {
            eprintln!("warning: {text}");
        }
    }
}

struct Terminal {
    color: bool,
}

impl Sink for Terminal {
    fn line(&self, kind: Kind, text: &str) {
        let (mark, color) = match kind {
            Kind::Step => ("==>", "\x1b[1;36m"),
            Kind::Detail => ("   ", "\x1b[2m"),
            Kind::Ok => (" ok", "\x1b[32m"),
            Kind::Warn => (" !!", "\x1b[33m"),
        };
        let mut out = std::io::stdout().lock();
        let _ = if self.color {
            writeln!(out, "{color}{mark}\x1b[0m {text}")
        } else {
            writeln!(out, "{mark} {text}")
        };
    }
}
