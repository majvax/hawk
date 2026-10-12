//! Outgoing email: verification links, and notices when something about an
//! account's security changes. Optional: with no SMTP server configured
//! the relay sends nothing, and email addresses are taken as given.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tracing::{info, warn};

pub const VERIFICATION_TTL: time::Duration = time::Duration::hours(24);

pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    /// Where links in emails point: the dashboard's address.
    base_url: String,
    resends: ResendLimiter,
}

impl Mailer {
    /// `HAWK_SMTP_URL` (e.g. `smtps://user:password@mail.example.com:465`,
    /// or `smtp://...?tls=required` for STARTTLS) and `HAWK_MAIL_FROM`.
    /// Neither set: no mailer. Only one set is a mistake worth stopping for.
    pub fn from_env(base_url: &str) -> Result<Option<Self>, String> {
        let url = std::env::var("HAWK_SMTP_URL").ok().filter(|url| !url.is_empty());
        let from = std::env::var("HAWK_MAIL_FROM").ok().filter(|from| !from.is_empty());
        let (url, from) = match (url, from) {
            (None, None) => {
                info!("no HAWK_SMTP_URL: email addresses are not verified and no notices are sent");
                return Ok(None);
            }
            (Some(url), Some(from)) => (url, from),
            _ => return Err("set both HAWK_SMTP_URL and HAWK_MAIL_FROM, or neither".into()),
        };
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(&url)
            .map_err(|error| format!("invalid HAWK_SMTP_URL: {error}"))?
            .build();
        let from = from.parse().map_err(|error| format!("invalid HAWK_MAIL_FROM: {error}"))?;
        Ok(Some(Self { transport, from, base_url: base_url.to_owned(), resends: ResendLimiter::default() }))
    }

    /// Sends in the background: a slow or broken mail server never holds up
    /// a request, and a failure is logged, not shown.
    fn send(&self, to: &str, subject: &str, body: String) {
        let message = to.parse::<Mailbox>().map_err(|error| error.to_string()).and_then(|to| {
            Message::builder()
                .from(self.from.clone())
                .to(to)
                .subject(subject)
                .header(ContentType::TEXT_PLAIN)
                .body(body)
                .map_err(|error| error.to_string())
        });
        let message = match message {
            Ok(message) => message,
            Err(error) => {
                warn!(%error, "mail: couldn't build message");
                return;
            }
        };
        let transport = self.transport.clone();
        let subject = subject.to_owned();
        tokio::spawn(async move {
            if let Err(error) = transport.send(message).await {
                warn!(%error, %subject, "mail: sending failed");
            }
        });
    }

    pub fn send_verification(&self, to: &str, token: &str) {
        let link = format!("{}/verify/{token}", self.base_url);
        self.send(
            to,
            "Confirm your email address",
            format!(
                "Someone created a Hawk account at {base} with this address.\n\n\
                 If it was you, open this link within 24 hours to confirm it:\n\n{link}\n\n\
                 If it wasn't, ignore this email: the account can't be shared machines until it's confirmed.\n",
                base = self.base_url
            ),
        );
    }

    /// Tells the account holder that something about their sign-in changed,
    /// so a change they didn't make doesn't go unnoticed. No links: a
    /// notice never asks the reader to act through it.
    pub fn send_notice(&self, to: &str, what: &str) {
        self.send(
            to,
            "Security change on your Hawk account",
            format!(
                "{what}\n\nAccount: {to}\nServer: {base}\n\n\
                 If this was you, there's nothing to do. If it wasn't, sign in, check your sessions and \
                 second factors in Settings, and change your password; or ask the server's admin for help.\n",
                base = self.base_url
            ),
        );
    }

    /// Whether this account may be sent a verification link now, counting
    /// it if so.
    pub fn take_send(&self, user_id: i64) -> bool {
        self.resends.take(user_id)
    }
}

/// One verification email a minute and five an hour per account.
#[derive(Default)]
struct ResendLimiter {
    sent: Mutex<HashMap<i64, Vec<Instant>>>,
}

impl ResendLimiter {
    const MIN_GAP: Duration = Duration::from_secs(60);
    const PER_HOUR: usize = 5;

    fn take(&self, user_id: i64) -> bool {
        let mut sent = self.sent.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        sent.retain(|_, times| times.last().is_some_and(|last| last.elapsed() < Duration::from_secs(3600)));
        let times = sent.entry(user_id).or_default();
        times.retain(|at| at.elapsed() < Duration::from_secs(3600));
        if times.len() >= Self::PER_HOUR || times.last().is_some_and(|last| last.elapsed() < Self::MIN_GAP) {
            return false;
        }
        times.push(Instant::now());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resends_are_spaced_out() {
        let limiter = ResendLimiter::default();
        assert!(limiter.take(1));
        assert!(!limiter.take(1));
        assert!(limiter.take(2));
    }
}
