//! Local web panel — Kordon-style settings UI without the cloud.
//!
//! Serves on `127.0.0.1:<random port>` only. Every request must carry the
//! per-run random token (in `?token=…`); the HTML embeds it, so the panel
//! link printed at startup is the only way in. No remote interface, ever.
//!
//! The panel edits only what lives in `state.toml` (allow entries, profile
//! selection) and shows live status; the hand-written `config.toml` is never
//! rewritten — same invariant as the CLI.

use std::{
    path::PathBuf,
    sync::{Arc, RwLock, atomic::AtomicBool},
};

use axum::{
    Json, Router,
    extract::{RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
};

use crate::{allow, config, events, profile};

/// Live snapshot the daemon refreshes every tick.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub country: Option<String>,
    pub quorum: bool,
    pub allowed: bool,
    pub frozen: usize,
    pub apps: Vec<String>,
    pub deny_reason: Option<String>,
}

pub type Shared = Arc<RwLock<Snapshot>>;

pub fn shared() -> Shared {
    Arc::new(RwLock::new(Snapshot::default()))
}

pub struct Panel {
    pub url: String,
    pub quit: Arc<AtomicBool>,
}

/// Bind and spawn the panel. Returns the URL with the token.
pub async fn spawn(shared: Shared, config_path: PathBuf, no_panel: bool) -> Option<Panel> {
    if no_panel {
        return None;
    }

    let token = random_token();
    let quit = Arc::new(AtomicBool::new(false));
    let app = Router::new()
        .route("/", get(index))
        .route("/api/status", get(status))
        .route("/api/allow", post(add_allow).delete(remove_allow))
        .route("/api/profile", post(set_profile))
        .route("/api/leaks", get(run_leaks))
        .route("/api/doctor", get(run_doctor))
        .route("/api/stats", get(run_stats))
        .route("/api/fix", post(run_fix))
        .route("/api/settings", get(get_settings).post(post_settings))
        .route("/api/trust-network", post(trust_network))
        .route("/api/apps", get(get_apps).post(post_app).delete(delete_app))
        .route("/api/processes", get(list_processes))
        .with_state(AppState {
            shared,
            token: token.clone(),
            config_path,
        });

    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(err) => {
            eprintln!("shuang: panel disabled ({err})");
            return None;
        }
    };
    let port = listener.local_addr().ok().map(|a| a.port())?;

    let quit_clone = Arc::clone(&quit);
    tokio::spawn(async move {
        // Serve until the process exits: the panel shares the daemon's
        // lifetime (Shutdown also fires, but the runtime ends first — the
        // flag is kept for a future graceful stop).
        let _ = quit_clone;
        let serve = axum::serve(listener, app);
        if let Err(err) = serve.await {
            eprintln!("shuang: panel stopped ({err})");
        }
    });

    let url = format!("http://127.0.0.1:{port}/?token={token}");
    Some(Panel { url, quit })
}

#[derive(Clone)]
struct AppState {
    shared: Shared,
    token: String,
    config_path: PathBuf,
}

impl AppState {
    /// Token check: query parameter or `X-Shuang-Token` header.
    fn authorized(&self, query: &str, headers: &HeaderMap) -> bool {
        if headers
            .get("x-shuang-token")
            .is_some_and(|v| v.as_bytes() == self.token.as_bytes())
        {
            return true;
        }
        query
            .split('&')
            .filter_map(|p| p.split_once('='))
            .any(|(k, v)| k == "token" && v == self.token)
    }
}

fn percent_decode(s: &str) -> String {
    // JSON already decodes \uXXXX; this only guards a stray %20 from older
    // clients instead of replacing text with itself.
    if s.contains("%20") {
        s.replace("%20", " ")
    } else {
        s.to_string()
    }
}

async fn index(State(app): State<AppState>, RawQuery(q): RawQuery) -> impl IntoResponse {
    if !app.authorized(q.as_deref().unwrap_or(""), &HeaderMap::new()) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    Html(PAGE_HTML).into_response()
}

async fn status(
    State(app): State<AppState>,
    RawQuery(q): RawQuery,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !app.authorized(q.as_deref().unwrap_or(""), &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }
    let snapshot = app.shared.read().ok();
    // Live allowlist/profile from disk: panel edits and other `shuang allow`
    // calls are reflected immediately.
    let state = config::load_state(&app.config_path);
    let cfg = config::load(&app.config_path, false).unwrap_or_default();
    let body = serde_json::json!({
        "ipv4": snapshot.as_ref().and_then(|s| s.ipv4.clone()),
        "ipv6": snapshot.as_ref().and_then(|s| s.ipv6.clone()),
        "country": snapshot.as_ref().and_then(|s| s.country.clone()),
        "quorum": snapshot.as_ref().is_some_and(|s| s.quorum),
        "allowed": snapshot.as_ref().is_some_and(|s| s.allowed),
        "frozen": snapshot.as_ref().map_or(0, |s| s.frozen),
        "deny_reason": snapshot.as_ref().and_then(|s| s.deny_reason.clone()),
        "apps": snapshot.as_ref().map_or(vec![], |s| s.apps.clone()),
        "state_ips": state.allow.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
        "state_nets": state.allow.nets.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
        "state_countries": state.allow.countries,
        "profile": state.active_profile,
        "profiles": cfg.profiles.keys().cloned().collect::<Vec<_>>(),
        "last_events": events::read_tail(&app.config_path, 10).unwrap_or_default(),
    });
    Json(body).into_response()
}

async fn run_leaks(
    State(app): State<AppState>,
    RawQuery(q): RawQuery,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !app.authorized(q.as_deref().unwrap_or(""), &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }
    match crate::leaks::report(&app.config_path, false).await {
        Ok((text, problems)) => Json(serde_json::json!({
            "text": text,
            "problems": problems,
            "fixes": crate::fix::relevant_for(&text),
        }))
        .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{err:#}")})),
        )
            .into_response(),
    }
}

async fn run_doctor(
    State(app): State<AppState>,
    RawQuery(q): RawQuery,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !app.authorized(q.as_deref().unwrap_or(""), &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }
    let (checks, problems) = crate::doctor::check(&app.config_path, false).await;
    Json(serde_json::json!({
        "text": crate::doctor::render_checks(&checks, &problems),
        "problems": problems,
    }))
    .into_response()
}

async fn run_stats(
    State(app): State<AppState>,
    RawQuery(q): RawQuery,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !app.authorized(q.as_deref().unwrap_or(""), &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }
    match crate::stats::summary(&app.config_path, 0) {
        Ok(text) => Json(serde_json::json!({"text": text})).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{err:#}")})),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
struct FixBody {
    kind: String,
}

async fn run_fix(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if !app.authorized("", &headers) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let Ok(parsed) = serde_json::from_str::<FixBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    match crate::fix::Kind::parse(&parsed.kind) {
        Some(kind) => (StatusCode::OK, kind.apply().message()).into_response(),
        None => (StatusCode::BAD_REQUEST, "unknown fix").into_response(),
    }
}

async fn get_settings(
    State(app): State<AppState>,
    RawQuery(q): RawQuery,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !app.authorized(q.as_deref().unwrap_or(""), &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }
    let mut cfg = config::load(&app.config_path, false).unwrap_or_default();
    let state = config::load_state(&app.config_path);
    cfg.apply_overrides(&state);
    Json(serde_json::json!({
        "interval_secs": cfg.ip_check.interval_secs,
        "grace_secs": cfg.timing.grace_secs,
        "close_secs": cfg.timing.close_secs,
        "min_agree": cfg.ip_check.min_agree,
        "notify": state.settings.notify.unwrap_or(true),
        "trusted_networks": state.trusted_networks,
        "gateway_mac": crate::trusted::gateway_mac(),
    }))
    .into_response()
}

#[derive(serde::Deserialize, Default)]
struct SettingsBody {
    interval_secs: Option<u64>,
    grace_secs: Option<u64>,
    close_secs: Option<u64>,
    min_agree: Option<usize>,
    notify: Option<bool>,
}

async fn post_settings(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if !app.authorized("", &headers) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let Ok(parsed) = serde_json::from_str::<SettingsBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    // Validation happens on load (`apply_overrides` runs before the
    // interval check), but guard the obvious nonsense here for a friendly
    // error.
    if parsed.interval_secs == Some(0) {
        return (StatusCode::BAD_REQUEST, "interval_secs must be at least 1").into_response();
    }
    let mut state = config::load_state(&app.config_path);
    let s = &mut state.settings;
    if parsed.interval_secs.is_some() {
        s.interval_secs = parsed.interval_secs;
    }
    if parsed.grace_secs.is_some() {
        s.grace_secs = parsed.grace_secs;
    }
    if parsed.close_secs.is_some() {
        s.close_secs = parsed.close_secs;
    }
    if parsed.min_agree.is_some() {
        s.min_agree = parsed.min_agree;
    }
    if parsed.notify.is_some() {
        s.notify = parsed.notify;
    }
    match config::save_state(&app.config_path, &state) {
        Ok(()) => (StatusCode::OK, "saved — restart the daemon to apply").into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

async fn trust_network(State(app): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if !app.authorized("", &headers) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let Some(mac) = crate::trusted::gateway_mac() else {
        return (
            StatusCode::NOT_FOUND,
            "gateway MAC not detected on this platform",
        )
            .into_response();
    };
    let mut state = config::load_state(&app.config_path);
    if !state.trusted_networks.contains(&mac) {
        state.trusted_networks.push(mac.clone());
    }
    match config::save_state(&app.config_path, &state) {
        Ok(()) => (StatusCode::OK, format!("trusted: {mac}")).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

async fn get_apps(
    State(app): State<AppState>,
    RawQuery(q): RawQuery,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !app.authorized(q.as_deref().unwrap_or(""), &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }
    let cfg = config::load(&app.config_path, false).unwrap_or_default();
    let state = config::load_state(&app.config_path);
    let state_names: Vec<&str> = state.apps.iter().map(|a| a.name.as_str()).collect();
    let apps: Vec<serde_json::Value> = cfg
        .apps
        .iter()
        .map(|a| {
            serde_json::json!({
                "name": a.name,
                "match": a.r#match,
                "countries": a.allow.as_ref().map(|x| x.countries.clone()).unwrap_or_default(),
                "ips": a.allow.as_ref().map(|x| x.ips.iter().map(|i| i.to_string()).collect::<Vec<_>>()).unwrap_or_default(),
                // Panel-added (deletable here) vs hand-written in config.
                "source": if state_names.contains(&a.name.as_str()) { "panel" } else { "config" },
            })
        })
        .collect();
    Json(serde_json::json!({"apps": apps})).into_response()
}

#[derive(serde::Deserialize)]
struct AppBody {
    name: String,
    #[serde(rename = "match")]
    matches: Vec<String>,
    /// Optional per-app allow rules: {"countries": ["NL"], "ips": [...]}.
    allow: Option<config::AllowConfig>,
}

async fn post_app(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if !app.authorized("", &headers) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let Ok(parsed) = serde_json::from_str::<AppBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    if parsed.name.trim().is_empty() || parsed.matches.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "name and at least one pattern are required",
        )
            .into_response();
    }
    let mut state = config::load_state(&app.config_path);
    let app_spec = config::AppSpec {
        name: parsed.name.trim().to_string(),
        r#match: parsed.matches,
        allow: parsed.allow,
    };
    match state.apps.iter().position(|a| a.name == app_spec.name) {
        Some(i) => state.apps[i] = app_spec,
        None => state.apps.push(app_spec),
    }
    match config::save_state(&app.config_path, &state) {
        Ok(()) => (StatusCode::OK, "saved — restart the daemon to apply").into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

async fn delete_app(
    State(app): State<AppState>,
    RawQuery(q): RawQuery,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !app.authorized(q.as_deref().unwrap_or(""), &headers) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let name = q
        .as_deref()
        .unwrap_or_default()
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| *k == "name")
        .map(|(_, v)| v.replace("%20", " "))
        .unwrap_or_default();
    let mut state = config::load_state(&app.config_path);
    let before = state.apps.len();
    state.apps.retain(|a| a.name != name);
    if state.apps.len() == before {
        return (StatusCode::NOT_FOUND, "not a panel-managed app").into_response();
    }
    match config::save_state(&app.config_path, &state) {
        Ok(()) => (StatusCode::OK, "removed".to_string()).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

/// Running processes for the "add app" picker: unique executable names,
/// excluding shuang itself and kernel-ish entries.
async fn list_processes(
    State(app): State<AppState>,
    RawQuery(q): RawQuery,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !app.authorized(q.as_deref().unwrap_or(""), &headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "forbidden"})),
        )
            .into_response();
    }
    let system = sysinfo::System::new_all();
    let me = std::process::id();
    let mut seen = std::collections::BTreeMap::new();
    for (pid, process) in system.processes() {
        let pid_u32 = pid.as_u32();
        if pid_u32 == me || process.exe().is_none() {
            continue;
        }
        let name = process.name().to_string_lossy();
        let name = name.strip_suffix(".exe").unwrap_or(&name).to_string();
        // Pattern hint: bare name; args: form when the cmdline carries a path.
        let args = process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        seen.entry(name).or_insert((pid_u32, args));
    }
    let list: Vec<serde_json::Value> = seen
        .into_iter()
        .take(100)
        .map(|(name, (pid, args))| serde_json::json!({"name": name, "pid": pid, "args": args}))
        .collect();
    Json(serde_json::json!({"processes": list})).into_response()
}

#[derive(serde::Deserialize)]
struct AllowBody {
    value: String,
}

async fn add_allow(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if !app.authorized("", &headers) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let Ok(parsed) = serde_json::from_str::<AllowBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    match allow::run(&app.config_path, &parsed.value) {
        Ok(_) => (StatusCode::OK, format!("allowed {}", parsed.value)).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

async fn remove_allow(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if !app.authorized("", &headers) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let Ok(parsed) = serde_json::from_str::<AllowBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    let value = percent_decode(parsed.value.trim());
    match allow::remove(&app.config_path, &value) {
        Ok(true) => (StatusCode::OK, "removed".to_string()).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "not found".to_string()).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct ProfileBody {
    name: String,
}

async fn set_profile(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if !app.authorized("", &headers) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let Ok(parsed) = serde_json::from_str::<ProfileBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    let name = if parsed.name == "none" {
        None
    } else {
        Some(parsed.name)
    };
    match profile::run(&app.config_path, &name) {
        Ok(_) => (StatusCode::OK, "ok".to_string()).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

/// Random 32-hex-char token from the OS (/dev/urandom on unix, hash fallback).
fn random_token() -> String {
    #[cfg(unix)]
    {
        let mut bytes = [0u8; 16];
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut bytes);
            return bytes.iter().map(|b| format!("{b:02x}")).collect();
        }
    }
    // Fallback: time + pid mix — weak, but the panel is localhost-only.
    let mix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        ^ (u128::from(std::process::id()) << 64);
    format!("{mix:032x}")
}

const PAGE_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>shuang</title>
<style>
  :root { color-scheme: dark; }
  body { font: 15px/1.5 system-ui, sans-serif; background: #14161a; color: #e6e6e6;
         max-width: 640px; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.2rem; } h1 span { color: #7aa2f7; }
  .card { background: #1d2026; border-radius: 10px; padding: 1rem 1.2rem; margin: 1rem 0; }
  .ok { border-left: 4px solid #4caf50; } .bad { border-left: 4px solid #ff9800; }
  .ip { font-size: 1.6rem; font-weight: 600; }
  .muted { color: #9a9a9a; font-size: .85rem; }
  ul { list-style: none; padding: 0; margin: .4rem 0; }
  li { display: flex; justify-content: space-between; align-items: center; padding: .25rem 0;
       border-bottom: 1px solid #2a2e36; }
  button { background: #2a2e36; color: #e6e6e6; border: 0; border-radius: 6px;
           padding: .3rem .7rem; cursor: pointer; }
  button:hover { background: #3a4048; }
  input, select { background: #14161a; color: #e6e6e6; border: 1px solid #2a2e36;
                  border-radius: 6px; padding: .35rem .5rem; }
  form { display: flex; gap: .5rem; margin-top: .6rem; }
  form input[type=text] { flex: 1; }
  pre { background: #14161a; padding: .6rem; border-radius: 8px; overflow-x: auto;
        font-size: .8rem; }
</style>
</head>
<body>
<h1>shuang <span>霜</span></h1>
<div class="card" id="status">loading…</div>
<div class="card"><strong>Protected apps</strong><ul id="apps"></ul>
  <form id="addapp"><input type="text" id="appname" placeholder="name (e.g. claude-code)">
  <input type="text" id="appmatch" placeholder="match pattern (e.g. claude)">
  <input type="text" id="appcountries" placeholder="only from countries (e.g. NL,DE) — optional">
  <button>Add</button></form>
  <div style="margin-top:.5rem"><select id="procpick"></select>
  <button onclick="pickProcess()">Add from running processes</button></div>
  <div class="muted">Panel-added apps live in state.toml; [[apps]] in config.toml still applies. Restart the daemon to apply changes.</div></div>
<div class="card"><strong>Allowed</strong>
  <ul id="allow"></ul>
  <form id="add"><input type="text" id="value" placeholder="IP, subnet (1.2.3.0/24), or country (NL)">
  <button>Add</button></form></div>
<div class="card"><strong>Profile</strong>
  <select id="profile"></select>
  <div class="muted">Profiles come from [profiles.name] in config.toml.</div></div>
<div class="card"><strong>Settings</strong>
  <div>interval <input type="number" id="s_interval" style="width:5rem"> s ·
       grace <input type="number" id="s_grace" style="width:4rem"> s ·
       close <input type="number" id="s_close" style="width:4rem"> s ·
       quorum <input type="number" id="s_min_agree" style="width:3rem"></div>
  <div style="margin-top:.5rem"><label><input type="checkbox" id="s_notify"> desktop notifications</label></div>
  <div style="margin-top:.6rem"><button onclick="saveSettings()">Save settings</button>
       <button onclick="trustNetwork()">Trust this network</button>
       <span class="muted" id="trusted_macs"></span></div></div>
<div class="card"><strong>Leak report</strong>
  <button onclick="run('leaks')">Run checks</button>
  <div id="fixes"></div><pre id="leaks"></pre></div>
<div class="card"><strong>Diagnostics</strong>
  <button onclick="run('doctor')">Run doctor</button><pre id="doctor"></pre></div>
<div class="card"><strong>VPN health (7 days)</strong>
  <button onclick="run('stats')">Refresh</button><pre id="stats"></pre></div>
<div class="card"><strong>Recent events</strong><pre id="events"></pre></div>
<script>
const token = new URLSearchParams(location.search).get('token');
const H = { 'X-Shuang-Token': token };
async function refresh() {
  try {
    const s = await (await fetch('/api/status', { headers: H })).json();
    const st = document.getElementById('status');
    const cls = s.allowed ? 'ok' : 'bad';
    const verdict = s.allowed ? 'allowed' : (s.deny_reason || 'not allowed');
    st.className = 'card ' + cls;
    st.innerHTML = `<div class="ip">${s.ipv4 || 'unknown'} <span class="muted">(${s.country || '??'})</span></div>`
      + `<div>${s.ipv6 ? 'IPv6: ' + s.ipv6 + '<br>' : ''}`
      + `quorum: ${s.quorum ? 'yes' : 'NO'} · ${verdict}${s.frozen ? ' · frozen: ' + s.frozen + ' process(es)' : ''}</div>`;
    document.getElementById('apps').innerHTML =
      (s.apps || []).map(a => `<li>${a}</li>`).join('') || '<li class="muted">none running</li>';
    const entries = [...(s.state_ips||[]).map(v=>['ip',v]), ...(s.state_nets||[]).map(v=>['net',v]),
                     ...(s.state_countries||[]).map(v=>['country',v])];
    document.getElementById('allow').innerHTML = entries.map(([k,v]) =>
      `<li><span>${v} <span class="muted">${k}</span></span>
       <button onclick="del('${v}')">×</button></li>`).join('')
      || '<li class="muted">nothing allowed via state.toml yet</li>';
    const sel = document.getElementById('profile');
    sel.innerHTML = '<option value="none">— none —</option>' +
      (s.profiles||[]).map(p => `<option ${p===s.profile?'selected':''}>${p}</option>`).join('');
    document.getElementById('events').textContent = (s.last_events||[]).join('\n') || 'no events yet';
  } catch (e) { /* panel went away */ }
}
async function run(kind) {
  const el = document.getElementById(kind);
  el.textContent = 'running…';
  const r = await fetch('/api/' + kind, { headers: H });
  const data = await r.json();
  el.textContent = data.text || data.error || 'no output';
  if (kind === 'leaks' && data.fixes) {
    document.getElementById('fixes').innerHTML = data.fixes.map(([k, label]) =>
      `<button style="margin-top:.5rem" onclick="fix('${k}')">${label}</button>`).join(' ');
  }
}
async function fix(kind) {
  const r = await fetch('/api/fix', { method: 'POST', headers: H,
    body: JSON.stringify({ kind }) });
  alert(await r.text());
}
document.getElementById('add').onsubmit = async (e) => {
  e.preventDefault();
  const value = document.getElementById('value').value.trim();
  if (!value) return;
  const r = await fetch('/api/allow', { method: 'POST', headers: H,
    body: JSON.stringify({ value }) });
  if (!r.ok) alert(await r.text());
  document.getElementById('value').value = '';
  refresh();
};
async function del(v) {
  const r = await fetch('/api/allow?token=' + token, { method: 'DELETE', headers: H,
    body: JSON.stringify({ value: v }) });
  if (!r.ok) alert(await r.text());
  refresh();
}
document.getElementById('profile').onchange = async (e) => {
  const r = await fetch('/api/profile', { method: 'POST', headers: H,
    body: JSON.stringify({ name: e.target.value }) });
  if (!r.ok) alert(await r.text());
  refresh();
};
async function loadSettings() {
  const s = await (await fetch('/api/settings', { headers: H })).json();
  document.getElementById('s_interval').value = s.interval_secs;
  document.getElementById('s_grace').value = s.grace_secs;
  document.getElementById('s_close').value = s.close_secs;
  document.getElementById('s_min_agree').value = s.min_agree;
  document.getElementById('s_notify').checked = s.notify;
  document.getElementById('trusted_macs').textContent =
    s.trusted_networks.length ? 'trusted: ' + s.trusted_networks.join(', ') : '';
}
async function saveSettings() {
  const body = {
    interval_secs: +document.getElementById('s_interval').value,
    grace_secs: +document.getElementById('s_grace').value,
    close_secs: +document.getElementById('s_close').value,
    min_agree: +document.getElementById('s_min_agree').value,
    notify: document.getElementById('s_notify').checked,
  };
  const r = await fetch('/api/settings', { method: 'POST', headers: H,
    body: JSON.stringify(body) });
  alert(await r.text());
}
async function loadApps() {
  const r = await (await fetch('/api/apps', { headers: H })).json();
  const ul = document.getElementById('apps');
  ul.innerHTML = (r.apps || []).map(a =>
    `<li><span>${a.name} <span class="muted">${a.match.join(', ')}${(a.countries||[]).length ? ' · only ' + a.countries.join(',') : ''} (${a.source})</span></span>` +
    (a.source === 'panel' ? `<button onclick="delApp('${a.name}')">×</button>` : '') +
    `</li>`).join('') || '<li class="muted">none</li>';
  const p = await (await fetch('/api/processes', { headers: H })).json();
  document.getElementById('procpick').innerHTML = (p.processes || []).map(x =>
    `<option value="${x.name}">${x.name} (${x.args.slice(0, 40)})</option>`).join('');
}
document.getElementById('addapp').onsubmit = async (e) => {
  e.preventDefault();
  const name = document.getElementById('appname').value.trim();
  const m = document.getElementById('appmatch').value.trim();
  if (!name || !m) return;
  const countries = document.getElementById('appcountries').value
    .split(',').map(s => s.trim().toUpperCase()).filter(s => s.length === 2);
  const r = await fetch('/api/apps', { method: 'POST', headers: H,
    body: JSON.stringify({ name, match: [m], allow: countries.length ? { countries } : null }) });
  if (!r.ok) alert(await r.text());
  document.getElementById('appname').value = '';
  document.getElementById('appmatch').value = '';
  document.getElementById('appcountries').value = '';
  loadApps();
};
async function delApp(name) {
  const r = await fetch('/api/apps?name=' + encodeURIComponent(name) + '&token=' + token,
    { method: 'DELETE', headers: H });
  if (!r.ok) alert(await r.text());
  loadApps();
}
async function pickProcess() {
  const name = document.getElementById('procpick').value;
  if (!name) return;
  const r = await fetch('/api/apps', { method: 'POST', headers: H,
    body: JSON.stringify({ name: name, match: [name] }) });
  if (!r.ok) alert(await r.text());
  loadApps();
}
async function trustNetwork() {
  const r = await fetch('/api/trust-network', { method: 'POST', headers: H });
  alert(await r.text());
  loadSettings();
}
refresh(); loadSettings(); loadApps(); setInterval(refresh, 3000);
</script>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn body_string(body: Body) -> String {
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn router_serves_index_and_status_with_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, "").unwrap();

        let state = AppState {
            shared: shared(),
            token: "secret".to_string(),
            config_path,
        };
        let app = Router::new()
            .route("/", get(index))
            .route("/api/status", get(status))
            .with_state(state);

        // Good token → the panel page.
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/?token=secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "index with token");
        let body = body_string(resp.into_body()).await;
        assert!(body.contains("<!doctype html>"));

        // Bad token → 403 (not axum's empty 404 fallback).
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/?token=wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "index wrong token");

        // API with the header token → JSON 200.
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/status")
                    .header("x-shuang-token", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "api/status");
        let body = body_string(resp.into_body()).await;
        assert!(body.contains("\"state_ips\""), "{body}");
    }
}
