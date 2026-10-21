//! Notification providers.

use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::json;

use super::Notification;
use crate::config::{EmailNotifier, EventKind, NotifierKind, SmtpSecurity, WebhookNotifier};

pub async fn send(http: &reqwest::Client, kind: &NotifierKind, n: &Notification) -> Result<(), String> {
    match kind {
        NotifierKind::Webhook(w) => check(webhook_request(http, w, n)?.send().await).await,
        NotifierKind::Ntfy(c) => {
            let priority = match (n.event, c.priority) {
                (EventKind::Down | EventKind::Reminder, Some(p)) => p.to_string(),
                (EventKind::Down | EventKind::Reminder, None) => "4".into(),
                _ => "3".into(),
            };
            let tag = match n.event {
                EventKind::Down | EventKind::Reminder => "red_circle",
                EventKind::Up => "green_circle",
                EventKind::Degraded => "orange_circle",
                EventKind::Flapping => "yellow_circle",
                EventKind::Test => "bell",
            };
            let mut req = http
                .post(&c.url)
                .header("Title", n.title())
                .header("Priority", priority)
                .header("Tags", tag)
                .body(n.body());
            if let Some(t) = &c.token {
                req = req.bearer_auth(t);
            } else if let Some(u) = &c.username {
                req = req.basic_auth(u, c.password.as_deref());
            }
            check(req.send().await).await
        }
        NotifierKind::Gotify(c) => {
            let priority = c.priority.unwrap_or(match n.event {
                EventKind::Down | EventKind::Reminder => 8,
                _ => 5,
            });
            let url = format!("{}/message", c.url.trim_end_matches('/'));
            let req = http
                .post(url)
                .header("X-Gotify-Key", &c.token)
                .json(&json!({"title": n.title(), "message": n.body(), "priority": priority}));
            check(req.send().await).await
        }
        NotifierKind::Matrix(c) => {
            let txn = format!("pw-{}-{}", n.timestamp, rand::random::<u32>());
            let url = format!(
                "{}/_matrix/client/v3/rooms/{}/send/m.room.message/{txn}",
                c.homeserver.trim_end_matches('/'),
                percent_encode(&c.room_id)
            );
            let text = format!("{} {}\n{}", n.emoji(), n.title(), n.body());
            let html = format!(
                "{} <b>{}</b><br>{}",
                n.emoji(),
                html_escape(&n.title()),
                html_escape(&n.body()).replace('\n', "<br>")
            );
            let req = http.put(url).bearer_auth(&c.access_token).json(&json!({
                "msgtype": "m.text",
                "body": text,
                "format": "org.matrix.custom.html",
                "formatted_body": html,
            }));
            check(req.send().await).await
        }
        NotifierKind::Discord(c) => {
            let color = match n.event {
                EventKind::Down | EventKind::Reminder => 0xd93025,
                EventKind::Up => 0x1e8e3e,
                EventKind::Degraded => 0xf29900,
                _ => 0x5f6368,
            };
            let req = http.post(&c.webhook_url).json(&json!({
                "username": "Pingwarden",
                "embeds": [{"title": format!("{} {}", n.emoji(), n.title()), "description": n.body(), "color": color}],
            }));
            check(req.send().await).await
        }
        NotifierKind::Slack(c) => {
            let req = http
                .post(&c.webhook_url)
                .json(&json!({"text": format!("{} *{}*\n{}", n.emoji(), n.title(), n.body())}));
            check(req.send().await).await
        }
        NotifierKind::Telegram(c) => {
            let url = format!("{}/bot{}/sendMessage", c.api_url.trim_end_matches('/'), c.bot_token);
            let req = http.post(url).json(&json!({
                "chat_id": c.chat_id,
                "text": format!("{} {}\n{}", n.emoji(), n.title(), n.body()),
                "disable_web_page_preview": true,
            }));
            // The URL holds the bot token: never include it in errors.
            check(req.send().await.map_err(|e| e.without_url())).await
        }
        NotifierKind::Pushover(c) => {
            let priority = c.priority.unwrap_or(match n.event {
                EventKind::Down | EventKind::Reminder => 1,
                _ => 0,
            });
            let req = http.post("https://api.pushover.net/1/messages.json").form(&[
                ("token", c.app_token.as_str()),
                ("user", c.user_key.as_str()),
                ("title", &n.title()),
                ("message", &n.body()),
                ("priority", &priority.to_string()),
            ]);
            check(req.send().await).await
        }
        NotifierKind::Email(c) => email(c, n).await,
    }
}

/// The webhook request: the JSON event as body, except for GET and HEAD,
/// which carry none (servers may reject or stall on a GET with a body).
fn webhook_request(
    http: &reqwest::Client,
    w: &WebhookNotifier,
    n: &Notification,
) -> Result<reqwest::RequestBuilder, String> {
    let method = reqwest::Method::from_bytes(w.method.to_ascii_uppercase().as_bytes())
        .map_err(|_| "invalid method".to_owned())?;
    let bodyless = method == reqwest::Method::GET || method == reqwest::Method::HEAD;
    let mut req = http.request(method, &w.url);
    if !bodyless {
        req = req.json(n);
    }
    for (k, v) in &w.headers {
        req = req.header(k, v);
    }
    Ok(req)
}

async fn check(res: Result<reqwest::Response, reqwest::Error>) -> Result<(), String> {
    let resp = res.map_err(|e| e.to_string())?;
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let body = resp.text().await.unwrap_or_default();
    let body: String = body.chars().take(200).collect();
    Err(format!("HTTP {status}: {body}"))
}

async fn email(c: &EmailNotifier, n: &Notification) -> Result<(), String> {
    let from: Mailbox = c.from.parse().map_err(|e| format!("invalid from address: {e}"))?;
    let mut builder = Message::builder()
        .from(from)
        .subject(format!("{} {}", n.emoji(), n.title()))
        .header(ContentType::TEXT_PLAIN);
    for to in &c.to {
        builder = builder.to(to.parse().map_err(|e| format!("invalid address {to:?}: {e}"))?);
    }
    let message = builder.body(n.body()).map_err(|e| e.to_string())?;
    let mut transport = match c.security {
        SmtpSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&c.host),
        SmtpSecurity::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&c.host),
        SmtpSecurity::None => Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&c.host)),
    }
    .map_err(|e| e.to_string())?;
    if let Some(port) = c.port {
        transport = transport.port(port);
    }
    if let (Some(u), Some(p)) = (&c.username, &c.password) {
        transport = transport.credentials(Credentials::new(u.clone(), p.clone()));
    }
    transport
        .timeout(Some(std::time::Duration::from_secs(20)))
        .build()
        .send(message)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_room_ids() {
        assert_eq!(percent_encode("!abc:matrix.org"), "%21abc%3Amatrix.org");
    }

    #[test]
    fn escapes_html() {
        assert_eq!(html_escape("<a & b>"), "&lt;a &amp; b&gt;");
    }
}
