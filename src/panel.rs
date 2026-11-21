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
    pub applications: Vec<AppStatus>,
    pub requested_revision: u64,
    pub evaluated_revision: Option<u64>,
    pub checking: bool,
    pub rules_error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AppStatus {
    pub name: String,
    pub state: &'static str,
    pub reason: Option<String>,
    pub seconds_left: Option<u64>,
    pub matched: usize,
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
pub async fn spawn(
    shared: Shared,
    config_path: PathBuf,
    no_panel: bool,
    apply: Arc<tokio::sync::Notify>,
    explicit: bool,
) -> Option<Panel> {
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
        .route("/api/apply", post(apply_now))
        .route("/api/trust-network", post(trust_network))
        .route("/api/apps", get(get_apps).post(post_app).delete(delete_app))
        .route("/api/processes", get(list_processes))
        .route("/api/apps/preview", post(preview_matches))
        .with_state(AppState {
            shared,
            token: token.clone(),
            config_path: config_path.clone(),
            apply,
            explicit,
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
    // Persist for `shuang panel` (the GUI window process) and the tray.
    {
        let _ = config::update_state(&config_path, |state| {
            state.panel_url = Some(url.clone());
            Ok(())
        });
    }
    Some(Panel { url, quit })
}

#[derive(Clone)]
struct AppState {
    shared: Shared,
    token: String,
    config_path: PathBuf,
    apply: Arc<tokio::sync::Notify>,
    explicit: bool,
}

async fn apply_now(State(app): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if !app.authorized("", &headers) {
        return (StatusCode::FORBIDDEN, "forbidden".to_string());
    }
    let config = config::load(&app.config_path, app.explicit).and_then(|mut cfg| {
        let state = config::try_load_state(&app.config_path)?;
        cfg.apply_overrides(&state);
        if cfg.ip_check.interval_secs == 0 || cfg.ip_check.min_agree == 0 {
            anyhow::bail!("interval_secs and min_agree must be at least 1");
        }
        Ok(())
    });
    if let Err(err) = config {
        return (StatusCode::BAD_REQUEST, format!("{err:#}"));
    }
    app.request_apply();
    (StatusCode::OK, "applying rules".to_string())
}

impl AppState {
    fn request_apply(&self) {
        if let Ok(mut snapshot) = self.shared.write() {
            snapshot.requested_revision += 1;
            snapshot.checking = false;
        }
        self.apply.notify_one();
    }

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
    let snapshot = app.shared.read().ok().map(|snapshot| snapshot.clone());
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
        "applications": snapshot.as_ref().map(|s| &s.applications),
        "rules_status": snapshot.as_ref().map_or("checking", |s| {
            if s.evaluated_revision != Some(s.requested_revision) {
                if s.checking || s.requested_revision == 0 { "checking" } else { "saved" }
            } else if s.rules_error.is_some() {
                "error"
            } else if s.checking {
                "checking"
            } else {
                "applied"
            }
        }),
        "rules_pending": snapshot.as_ref().is_none_or(|s| s.evaluated_revision != Some(s.requested_revision)),
        "rules_error": snapshot.as_ref().filter(|s| s.evaluated_revision == Some(s.requested_revision)).and_then(|s| s.rules_error.as_ref()),
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
        "freeze_on_event_first": cfg.timing.freeze_on_event_first,
        "watchdog_processes": cfg.watchdog.processes,
        "reputation_enabled": cfg.reputation.enabled,
        "stability_secs": cfg.timing.stability_secs,
        "probe_enabled": cfg.probe.enabled,
        "probe_via": format!("{:?}", cfg.probe.via).to_lowercase(),
        "app_proxy": cfg.ip_check.proxy,
        "protection_paused": cfg.protection_paused,
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
    freeze_on_event_first: Option<bool>,
    watchdog_processes: Option<Vec<String>>,
    reputation_enabled: Option<bool>,
    stability_secs: Option<u64>,
    probe_enabled: Option<bool>,
    protection_paused: Option<bool>,
    probe_via: Option<String>,
    app_proxy: Option<String>,
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
    if parsed.interval_secs == Some(0) || parsed.min_agree == Some(0) {
        return (
            StatusCode::BAD_REQUEST,
            "interval_secs and min_agree must be at least 1",
        )
            .into_response();
    }
    match config::update_state(&app.config_path, |state| {
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
        if parsed.freeze_on_event_first.is_some() {
            s.freeze_on_event_first = parsed.freeze_on_event_first;
        }
        if let Some(patterns) = parsed.watchdog_processes {
            s.watchdog_processes = Some(
                patterns
                    .iter()
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect(),
            );
        }
        if parsed.reputation_enabled.is_some() {
            s.reputation_enabled = parsed.reputation_enabled;
        }
        if parsed.stability_secs.is_some() {
            s.stability_secs = parsed.stability_secs;
        }
        if parsed.probe_enabled.is_some() {
            s.probe_enabled = parsed.probe_enabled;
        }
        if parsed.protection_paused.is_some() {
            s.protection_paused = parsed.protection_paused;
        }
        if let Some(via) = parsed.probe_via.as_deref()
            && matches!(via, "auto" | "proxy" | "direct")
        {
            s.probe_via = Some(via.to_string());
        }
        s.app_proxy = parsed.app_proxy;
        Ok(())
    }) {
        Ok(()) => {
            app.request_apply();
            (StatusCode::OK, "saved and applying").into_response()
        }
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
    match config::update_state(&app.config_path, |state| {
        if !state.trusted_networks.contains(&mac) {
            state.trusted_networks.push(mac.clone());
        }
        Ok(())
    }) {
        Ok(()) => {
            app.request_apply();
            (StatusCode::OK, format!("trusted: {mac}")).into_response()
        }
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
    let mut cfg = config::load(&app.config_path, false).unwrap_or_default();
    let state = config::load_state(&app.config_path);
    cfg.apply_overrides(&state);
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
    if parsed.name.trim().is_empty() || !valid_patterns(&parsed.matches) {
        return (
            StatusCode::BAD_REQUEST,
            "name and at least one pattern are required",
        )
            .into_response();
    }
    let app_spec = config::AppSpec {
        name: parsed.name.trim().to_string(),
        r#match: parsed
            .matches
            .into_iter()
            .map(|pattern| pattern.trim().to_owned())
            .collect(),
        allow: parsed.allow,
    };
    match config::update_state(&app.config_path, |state| {
        match state.apps.iter().position(|a| a.name == app_spec.name) {
            Some(i) => state.apps[i] = app_spec,
            None => state.apps.push(app_spec),
        }
        Ok(())
    }) {
        Ok(()) => {
            app.request_apply();
            (StatusCode::OK, "saved and applying").into_response()
        }
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
        .and_then(|query| reqwest::Url::parse(&format!("http://localhost/?{query}")).ok())
        .and_then(|url| {
            url.query_pairs()
                .find(|(key, _)| key == "name")
                .map(|(_, value)| value.into_owned())
        })
        .unwrap_or_default();
    let removed = config::update_state(&app.config_path, |state| {
        let before = state.apps.len();
        state.apps.retain(|a| a.name != name);
        Ok(state.apps.len() != before)
    });
    match removed {
        Ok(true) => {
            app.request_apply();
            (StatusCode::OK, "removed".to_string()).into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "not a panel-managed app").into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, format!("{err:#}")).into_response(),
    }
}

fn valid_patterns(patterns: &[String]) -> bool {
    !patterns.is_empty()
        && patterns.iter().all(|pattern| {
            let pattern = pattern.trim();
            !pattern.is_empty() && pattern != "args:"
        })
}

#[derive(serde::Deserialize)]
struct PreviewBody {
    patterns: Vec<String>,
}

async fn preview_matches(
    State(app): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    if !app.authorized("", &headers) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let Ok(parsed) = serde_json::from_str::<PreviewBody>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    if !valid_patterns(&parsed.patterns) {
        return (StatusCode::BAD_REQUEST, "enter a non-empty match pattern").into_response();
    }
    let patterns = parsed
        .patterns
        .into_iter()
        .map(|pattern| pattern.trim().to_owned())
        .collect::<Vec<_>>();
    let system = sysinfo::System::new_all();
    let targets = crate::procs::find_targets(&patterns, &system);
    let mut affected = std::collections::BTreeSet::new();
    for (_, pid) in &targets {
        affected.extend(crate::procs::tree(*pid, &system));
    }
    let matches: Vec<_> = targets
        .iter()
        .take(30)
        .map(|(name, pid)| serde_json::json!({"name": name, "pid": pid}))
        .collect();
    Json(
        serde_json::json!({"matches": matches, "total": targets.len(), "affected": affected.len()}),
    )
    .into_response()
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
    let mut seen = std::collections::BTreeSet::new();
    for (pid, process) in system.processes() {
        if pid.as_u32() == me {
            continue;
        }
        if let Some(path) = process.exe() {
            let name = process.name().to_string_lossy();
            let name = name.strip_suffix(".exe").unwrap_or(&name).to_string();
            seen.insert((name, path.to_string_lossy().into_owned()));
        }
    }
    let list: Vec<_> = seen
        .into_iter()
        .map(|(name, path)| serde_json::json!({"name": name, "path": path}))
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
        Ok(_) => {
            app.request_apply();
            (StatusCode::OK, format!("allowed {}", parsed.value)).into_response()
        }
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
        Ok(true) => {
            app.request_apply();
            (StatusCode::OK, "removed".to_string()).into_response()
        }
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
    let name = Some(parsed.name);
    match profile::run(&app.config_path, &name) {
        Ok(_) => {
            app.request_apply();
            (StatusCode::OK, "ok".to_string()).into_response()
        }
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
  form input[type=text] { flex: 1; min-width: 0; }
  #addapp { flex-wrap: wrap; }
  #process-picker { display: flex; flex-wrap: wrap; gap: .5rem; margin: .6rem 0; }
  #procpick { width: 100%; }
  .app-detail { overflow-wrap: anywhere; }
  .app-state { font-weight: 600; }
  .app-state[data-state="running"] { color: #9ece6a; }
  .app-state[data-state="frozen"], .app-state[data-state="stopped"], .app-state[data-state="denied"] { color: #ffb86c; }
  #rules-status[data-state="error"], #preview[data-state="error"] { color: #ff9e9e; }
  #rules-status { margin-top: .45rem; white-space: pre-wrap; }
  #preview { margin-top: .5rem; }
  button:disabled { opacity: .55; cursor: default; }
  pre { background: #14161a; padding: .6rem; border-radius: 8px; overflow-x: auto;
        font-size: .8rem; }
</style>
</head>
<body>
<h1>shuang <span>霜</span></h1>
<div style="position:absolute;top:1rem;right:1rem">
  <button onclick="setLang('ru')">RU</button>
  <button onclick="setLang('en')">EN</button></div>
<div class="card" id="status"><div id="network-status">loading…</div>
  <div id="rules-status" class="muted" role="status" aria-live="polite"></div>
</div>
<div class="card"><strong>Protected apps</strong><ul id="apps"></ul>
  <details id="process-picker-toggle">
    <summary data-i18n="Find a running process">Find a running process</summary>
    <div id="process-picker">
      <input type="search" id="procsearch" placeholder="Search by name or path">
      <button type="button" onclick="loadProcesses()" data-i18n="Refresh processes">Refresh processes</button>
      <select id="procpick" size="5" aria-label="Running processes"></select>
      <button type="button" id="use-process" onclick="pickProcess()" disabled data-i18n="Use selected process">Use selected process</button>
      <span class="muted" id="process-feedback"></span>
    </div>
  </details>
  <form id="addapp"><input type="text" id="appname" required placeholder="App name">
    <input type="text" id="appmatch" required placeholder="Process name or path">
    <input type="text" id="appcountries" placeholder="also allow countries (e.g. NL,DE) — optional">
    <button type="button" id="preview-button" onclick="previewApp()" data-i18n="Preview matches">Preview matches</button>
    <button id="save-app" disabled data-i18n="Save app">Save app</button>
  </form>
  <div id="preview" class="muted" role="status" aria-live="polite"></div>
</div>
<div class="card"><strong>Allowed</strong>
  <ul id="allow"></ul>
  <form id="add"><input type="text" id="value" placeholder="IP, subnet (1.2.3.0/24), or country (NL)">
  <button>Add</button></form></div>
<div class="card"><strong>Profile</strong>
  <select id="profile"></select>
  <div class="muted">Profiles come from [profiles.name] in config.toml.</div></div>
<div class="card"><strong>Settings</strong>
  <div title="How often the external IP is re-checked">interval <input type="number" id="s_interval" style="width:5rem"> s ·
       grace <input type="number" id="s_grace" style="width:4rem"> s ·
       close <input type="number" id="s_close" style="width:4rem"> s ·
       quorum <input type="number" id="s_min_agree" style="width:3rem"></div>
  <div style="margin-top:.5rem"><label><input type="checkbox" id="s_notify"> desktop notifications</label>
    <label style="margin-left:1rem"><input type="checkbox" id="s_paranoid"> paranoid (freeze on network event first)</label>
    <label style="margin-left:1rem"><input type="checkbox" id="s_reputation"> reputation guard</label></div>
  <div style="margin-top:.5rem">watchdog processes (comma-separated, e.g. v2ray, clash — empty = off)
    <input type="text" id="s_watchdog" style="width:100%"></div>
  <div style="margin-top:.5rem"><label><input type="checkbox" id="s_probe"> fast probe (1s transport check)</label>
    · stability gate <input type="number" id="s_stability" style="width:4rem"> s</div>
  <div style="margin-top:.3rem">probe path: <select id="s_probe_via">
    <option value="auto">auto (proxy when set)</option>
    <option value="proxy">proxy only (the apps' path)</option>
    <option value="direct">direct TCP only</option></select></div>
  <div style="margin-top:.3rem">app proxy — how your apps actually connect (e.g. http://127.0.0.1:10809; empty = environment):
    <input type="text" id="s_app_proxy" style="width:100%"></div>

  <details style="margin-top:.8rem"><summary style="cursor:pointer;color:#7aa2f7">What do all these settings mean?</summary>
  <div class="muted" style="margin-top:.4rem" id="helpbox"></div></details>
  <div style="margin-top:.5rem"><label><input type="checkbox" id="s_paused"> ⏸ PROTECTION PAUSED (no freezing at all)</label></div>
  <div style="margin-top:.6rem"><button onclick="saveSettings()">Save settings</button>
       <button onclick="applyNow()">Apply now</button>
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
const I18N = {
  ru: {
    'Protected apps': 'Защищаемые приложения',
    'Find a running process': 'Найти запущенный процесс',
    'Search by name or path': 'Поиск по имени или пути',
    'Refresh processes': 'Обновить список',
    'Use selected process': 'Выбрать процесс',
    'App name': 'Имя приложения',
    'Process name or path': 'Имя или путь процесса',
    'Preview matches': 'Показать совпадения',
    'Save app': 'Сохранить',
    'No protected apps yet': 'Пока нет защищаемых приложений',
    'No matching processes': 'Подходящих процессов нет',
    'This rule will match when the app starts.': 'Правило сработает, когда приложение запустится.',
    'Matching processes': 'Совпадений',
    'Including descendants': 'Всего с дочерними процессами',
    'Seconds until forced stop': 'Секунд до завершения',
    'Waiting for launch': 'Ожидает запуска',
    'Running': 'Работает',
    'Frozen': 'Заморожено',
    'Stopped': 'Завершено',
    'Suspended': 'Приостановлено',
    'A matching process is still suspended': 'Подходящий процесс всё ещё приостановлен',
    'Remove': 'Удалить',
    'Panel expired. Reopen it from the tray.': 'Ссылка устарела. Откройте панель заново из трея.',
    'Freeze incomplete': 'Часть процессов не заморожена',
    'Waiting for a stable connection': 'Ожидает стабильной сети',
    'Protection paused': 'Защита на паузе',
    'Trusted network': 'Доверенная сеть',
    'Saved. Waiting for the daemon': 'Сохранено. Ожидаем демон',
    'Checking rules': 'Демон проверяет правила',
    'Rules applied': 'Правила действуют',
    'Could not apply rules': 'Не удалось применить правила',
    'Could not reach the daemon': 'Не удалось связаться с демоном',
    'Loading…': 'Загрузка…',
    'Settings': 'Настройки',
    'Leak report': 'Утечки',
    'Diagnostics': 'Диагностика',
    'VPN health (7 days)': 'Здоровье VPN (7 дней)',
    'Recent events': 'События',
    'name (e.g. claude-code)': 'имя (напр. claude-code)',
    'match pattern (e.g. claude)': 'паттерн (напр. claude)',
    'also allow countries (e.g. NL,DE) — optional': 'дополнительно разрешить страны (напр. NL,DE)',
    'Add': 'Добавить',
    'Add from running processes': 'Добавить из запущенных процессов',
    'Panel-added apps live in state.toml; changes apply immediately.':
      'Приложения из панели живут в state.toml; изменения применяются сразу.',
    'none running': 'ничего не запущено',
    'none': 'нет',
    's ·': 'с ·',
    'desktop notifications': 'уведомления на рабочем столе',
    'paranoid (freeze on network event first)': 'паранойя (заморозка при событии сети до проверки)',
    'reputation guard': 'репутация выхода',
    'fast probe (1s transport check)': 'быстрый зонд (проверка транспорта 1с)',
    'PROTECTION PAUSED (no freezing at all)': 'ЗАЩИТА НА ПАУЗЕ (никаких заморозок)',
    'watchdog processes (comma-separated, e.g. v2ray, clash — empty = off)':
      'процессы прокси-клиента (через запятую: v2ray, clash — пусто = выкл)',
    'interval': 'интервал',
    'grace': 'grace',
    'close': 'close',
    'quorum': 'кворум',
    'stability gate': 'гейт стабильности',
    'Save settings': 'Сохранить настройки',
    'Apply now': 'Применить сейчас',
    'Trust this network': 'Доверять этой сети',
    'Run checks': 'Проверить',
    'Run doctor': 'Диагностика',
    'Refresh': 'Обновить',
    'saved and applying': 'сохранено и применяется',
    'IP, subnet (1.2.3.0/24), or country (NL)': 'IP, подсеть (1.2.3.0/24) или страна (NL)',
    'Allowed': 'Разрешено',
    'no events yet': 'событий пока нет',
    'running…': 'выполняется…',
    'Токен панели истёк — демон перезапускался.<br>Откройте панель заново из меню трея (Open panel).':
      'Токен панели истёк — демон перезапускался.<br>Откройте панель заново из меню трея (Open panel).',
  },
  en: {}
};
let LANG = localStorage.getItem('shuang-lang') ||
  ((navigator.language || '').toLowerCase().startsWith('ru') ? 'ru' : 'en');
function t(s) { return (I18N[LANG] && I18N[LANG][s]) || s; }
function setLang(l) {
  LANG = l;
  localStorage.setItem('shuang-lang', l);
  applyI18n();
  renderApps();
  refresh();
}
const HELP = {
  en: `<b>interval</b> — how often the external IP is re-checked (seconds). 5 is a good default.<br>
<b>grace / close</b> — when the IP goes bad the app is frozen; grace and close together set how long it stays frozen before a forced stop.<br>
<b>quorum</b> — how many IP services must agree on the address. Fewer agreeing = "unknown", and unknown is never allowed.<br>
<b>desktop notifications</b> — popups about freezes/recoveries.<br>
<b>paranoid</b> — freeze on a detected network change before re-checking. A network-level kill switch is still needed to block the first packet.<br>
<b>reputation guard</b> — freeze while the exit IP is flagged as proxy/datacenter.<br>
<b>fast probe</b> — a 1-second health ping; freezes the instant the transport dies (instead of waiting for IP-check timeouts).<br>
<b>probe path</b> — which route the probe tests: "proxy only" = the exact route your apps use (recommended when they go via a local proxy).<br>
<b>app proxy</b> — the proxy address your apps use; all checks then see exactly what they see.<br>
<b>stability gate</b> — after a freeze, wait N seconds of stable good verdict before unfreezing (stops IP flapping from reaching the app).<br>
<b>watchdog</b> — names of your proxy-client processes; if that process dies, everything freezes instantly.<br>
<b>PROTECTION PAUSED</b> — the big red button: no freezing at all, everything resumes. Use when something misbehaves.`,
  ru: `<b>интервал</b> — как часто перепроверяется внешний IP (в секундах). 5 — нормальное значение по умолчанию.<br>
<b>grace / close</b> — при плохом IP приложение замораживается; grace и close вместе задают время заморозки до принудительного завершения.<br>
<b>кворум</b> — сколько IP-сервисов должны сойться на адресе. Меньше — «неизвестно», а неизвестное никогда не разрешается.<br>
<b>уведомления</b> — всплывающие сообщения о заморозках и восстановлении.<br>
<b>паранойя</b> — при обнаруженном изменении сети сначала заморозить, потом проверять. Первый пакет блокирует только сетевой kill switch.<br>
<b>репутация</b> — заморозка, пока выходной IP помечен как прокси/датацентр.<br>
<b>быстрый зонд</b> — проверка здоровья раз в секунду; мгновенная заморозка при смерти транспорта (не ждём таймауты IP-проверок).<br>
<b>путь зонда</b> — какой маршрут проверять: «proxy only» = ровно тот путь, которым ходят ваши приложения (рекомендуется при локальном прокси).<br>
<b>app proxy</b> — адрес прокси, которым пользуются ваши приложения; все проверки будут видеть то же, что видят они.<br>
<b>гейт стабильности</b> — после заморозки ждать N секунд стабильного «хорошо» перед разморозкой (скачки IP не доходят до приложения).<br>
<b>watchdog</b> — имена процессов вашего прокси-клиента; если процесс умрёт — мгновенная заморозка всего.<br>
<b>ПАУЗА ЗАЩИТЫ</b> — большая красная кнопка: никаких заморозок, всё разморожено. Когда «что-то странно — сначала выключи, потом разбирайся».`
};
function applyI18n() {
  document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
  const hb = document.getElementById('helpbox');
  if (hb) hb.innerHTML = HELP[LANG] || HELP.en;
  document.querySelectorAll('strong').forEach(e => { if (!e.dataset.orig) e.dataset.orig = e.textContent; e.textContent = t(e.dataset.orig); });
  document.querySelectorAll('input[type=text], input:not([type])').forEach(e => { if (e.placeholder && !e.dataset.p) e.dataset.p = e.placeholder; if (e.dataset.p) e.placeholder = t(e.dataset.p); });
  document.querySelectorAll('button').forEach(e => { if (!e.dataset.orig) e.dataset.orig = e.textContent; const v = t(e.dataset.orig); if (v !== e.dataset.orig || e.dataset.orig !== e.textContent) e.textContent = v; });
  document.querySelectorAll('label').forEach(e => {
    const cb = e.querySelector('input'); const txt = e.textContent.replace(/^\s+|\s+$/g,'');
    if (!e.dataset.orig) e.dataset.orig = txt.replace(/^[^ ]* /,'').trim() || txt;
    if (cb) { e.textContent = ''; e.appendChild(cb); e.appendChild(document.createTextNode(' ' + t(e.dataset.orig))); }
  });
}
applyI18n();
const H = { 'X-Shuang-Token': token };
const byId = id => document.getElementById(id);
let uiError = null;
let appSpecs = [];
let liveStatus = {};
let refreshing = false;
let refreshAgain = false;

function renderRules() {
  const state = uiError ? 'error' : (liveStatus.rules_status || 'checking');
  const labels = {
    saved: 'Saved. Waiting for the daemon', checking: 'Checking rules',
    applied: 'Rules applied', error: 'Could not apply rules',
  };
  const el = byId('rules-status');
  el.dataset.state = state;
  const detail = uiError || liveStatus.rules_error;
  el.textContent = t(labels[state]) + (detail ? '\n' + detail : '');
}

function renderApps() {
  const apps = byId('apps');
  const statuses = new Map((liveStatus.applications || []).map(app => [app.name, app]));
  const labels = {
    waiting: 'Waiting for launch', running: 'Running', frozen: 'Frozen',
    stopped: 'Stopped', suspended: 'Suspended', denied: 'Freeze incomplete', stabilizing: 'Waiting for a stable connection',
    paused: 'Protection paused', trusted: 'Trusted network', checking: 'Checking rules',
  };
  apps.replaceChildren();
  for (const app of appSpecs) {
    const status = statuses.get(app.name);
    const item = document.createElement('li');
    const detail = document.createElement('div');
    detail.className = 'app-detail';
    const name = document.createElement('strong');
    name.textContent = app.name;
    const state = document.createElement('span');
    state.className = 'app-state';
    state.dataset.state = liveStatus.rules_pending ? 'checking' : (status?.state || 'checking');
    state.textContent = ' · ' + t(labels[state.dataset.state]);
    const patterns = document.createElement('div');
    patterns.className = 'muted';
    patterns.textContent = app.match.join(', ');
    detail.append(name, state, patterns);
    if (!liveStatus.rules_pending && (status?.reason || status?.seconds_left != null)) {
      const reason = document.createElement('div');
      reason.className = 'muted';
      const countdown = status.seconds_left == null ? '' :
        t('Seconds until forced stop') + ' · ' + status.seconds_left;
      reason.textContent = [t(status.reason || ''), countdown].filter(Boolean).join(' · ');
      detail.append(reason);
    }
    item.append(detail);
    if (app.source === 'panel') {
      const remove = document.createElement('button');
      remove.textContent = '×';
      remove.setAttribute('aria-label', t('Remove') + ' ' + app.name);
      remove.onclick = () => delApp(app.name);
      item.append(remove);
    }
    apps.append(item);
  }
  if (!apps.childElementCount) {
    const empty = document.createElement('li');
    empty.className = 'muted';
    empty.textContent = t('No protected apps yet');
    apps.append(empty);
  }
}

async function refresh() {
  if (refreshing) {
    refreshAgain = true;
    return;
  }
  refreshing = true;
  try {
    const response = await fetch('/api/status', { headers: H });
    if (response.status === 403) {
      byId('network-status').textContent = t('Panel expired. Reopen it from the tray.');
      clearInterval(refreshTimer);
      return;
    }
    if (!response.ok) throw new Error();
    const status = await response.json();
    liveStatus = status;
    const network = byId('network-status');
    const ip = document.createElement('div');
    ip.className = 'ip';
    ip.textContent = [status.ipv4 || status.ipv6 || '—', status.country].filter(Boolean).join(' · ');
    const verdict = document.createElement('div');
    verdict.textContent = [status.ipv4 && status.ipv6 ? status.ipv6 : '',
      status.allowed ? t('Allowed') : (status.deny_reason || '')].filter(Boolean).join(' · ');
    network.replaceChildren(ip, verdict);
    byId('status').className = 'card ' + (status.allowed ? 'ok' : 'bad');
    renderRules();
    renderApps();

    const entries = [...(status.state_ips || []), ...(status.state_nets || []), ...(status.state_countries || [])];
    const allow = byId('allow');
    allow.replaceChildren(...entries.map(value => {
      const item = document.createElement('li');
      const remove = document.createElement('button');
      remove.textContent = '×';
      remove.onclick = () => del(value);
      item.append(value, remove);
      return item;
    }));
    const profile = byId('profile');
    profile.replaceChildren(new Option('— ' + t('none') + ' —', 'none'),
      ...(status.profiles || []).map(value => new Option(value, value)));
    profile.value = status.profile || 'none';
    byId('events').textContent = (status.last_events || []).join('\n') || t('no events yet');
  } catch {
    byId('rules-status').textContent = t('Could not reach the daemon');
  } finally {
    refreshing = false;
    if (refreshAgain) {
      refreshAgain = false;
      refresh();
    }
  }
}

async function changeRules(path, options = {}) {
  uiError = null;
  try {
    const response = await fetch(path, { headers: H, method: 'POST', ...options });
    if (!response.ok) {
      uiError = await response.text();
      renderRules();
      return false;
    }
    liveStatus = { ...liveStatus, rules_status: 'saved', rules_pending: true, rules_error: null };
    renderRules();
    renderApps();
    refresh();
    return true;
  } catch {
    uiError = t('Could not reach the daemon');
    renderRules();
    return false;
  }
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
  if (await changeRules('/api/allow', { body: JSON.stringify({ value }) })) {
    byId('value').value = '';
  }
};
async function del(value) {
  await changeRules('/api/allow', { method: 'DELETE', body: JSON.stringify({ value }) });
}
byId('profile').onchange = async (event) => {
  if (!await changeRules('/api/profile', { body: JSON.stringify({ name: event.target.value }) })) {
    event.target.value = liveStatus.profile || 'none';
  }
};
async function loadSettings() {
  const s = await (await fetch('/api/settings', { headers: H })).json();
  document.getElementById('s_interval').value = s.interval_secs;
  document.getElementById('s_grace').value = s.grace_secs;
  document.getElementById('s_close').value = s.close_secs;
  document.getElementById('s_min_agree').value = s.min_agree;
  document.getElementById('s_notify').checked = s.notify;
  document.getElementById('s_paranoid').checked = s.freeze_on_event_first;
  document.getElementById('s_reputation').checked = s.reputation_enabled;
  document.getElementById('s_watchdog').value = (s.watchdog_processes || []).join(', ');
  document.getElementById('s_probe').checked = s.probe_enabled;
  document.getElementById('s_paused').checked = s.protection_paused;
  document.getElementById('s_probe_via').value = s.probe_via || 'auto';
  document.getElementById('s_app_proxy').value = s.app_proxy || '';
  document.getElementById('s_stability').value = s.stability_secs;
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
    freeze_on_event_first: document.getElementById('s_paranoid').checked,
    reputation_enabled: document.getElementById('s_reputation').checked,
    watchdog_processes: document.getElementById('s_watchdog').value.split(',')
      .map(s => s.trim()).filter(s => s.length > 0),
    probe_enabled: document.getElementById('s_probe').checked,
    protection_paused: document.getElementById('s_paused').checked,
    probe_via: document.getElementById('s_probe_via').value,
    app_proxy: document.getElementById('s_app_proxy').value.trim(),
    stability_secs: +document.getElementById('s_stability').value,
  };
  if (await changeRules('/api/settings', { body: JSON.stringify(body) })) loadApps();
}
async function applyNow() {
  if (await changeRules('/api/apply')) {
    loadApps();
    loadSettings();
  }
}
async function loadApps() {
  const response = await fetch('/api/apps', { headers: H });
  if (!response.ok) return;
  appSpecs = (await response.json()).apps || [];
  renderApps();
}

let processes = [];
let previewRevision = 0;
let previewedPattern = null;
let savingApp = false;
function renderProcesses() {
  const query = byId('procsearch').value.trim().toLowerCase();
  const picker = byId('procpick');
  const selected = picker.value;
  const matches = processes.filter(process => (process.name + ' ' + process.path).toLowerCase().includes(query));
  picker.replaceChildren(...matches.map(process => {
    const option = new Option(process.path ? process.name + ' · ' + process.path : process.name,
      JSON.stringify([process.name, process.path]));
    return option;
  }));
  picker.value = selected;
  byId('use-process').disabled = !picker.value;
  byId('process-feedback').textContent = matches.length ? '' : t('No matching processes');
}
async function loadProcesses() {
  byId('process-feedback').textContent = t('Loading…');
  try {
    const response = await fetch('/api/processes', { headers: H });
    if (!response.ok) throw new Error();
    processes = (await response.json()).processes || [];
    renderProcesses();
  } catch {
    byId('process-feedback').textContent = t('Could not reach the daemon');
  }
}
byId('process-picker-toggle').ontoggle = event => { if (event.target.open) loadProcesses(); };
byId('procsearch').oninput = renderProcesses;
byId('procpick').onchange = event => { byId('use-process').disabled = !event.target.value; };

function invalidatePreview() {
  previewRevision++;
  previewedPattern = null;
  byId('save-app').disabled = true;
  byId('preview').replaceChildren();
}
byId('appmatch').oninput = invalidatePreview;

async function previewApp() {
  invalidatePreview();
  const revision = previewRevision;
  const pattern = byId('appmatch').value.trim();
  if (!pattern) {
    byId('appmatch').reportValidity();
    return;
  }
  const output = byId('preview');
  output.dataset.state = '';
  output.textContent = t('Loading…');
  try {
    const response = await fetch('/api/apps/preview', { headers: H, method: 'POST',
      body: JSON.stringify({ patterns: [pattern] }) });
    if (!response.ok) throw new Error(await response.text());
    const data = await response.json();
    if (revision !== previewRevision) return;
    if (data.total === 0) {
      output.textContent = t('No matching processes') + '. ' + t('This rule will match when the app starts.');
    } else {
      output.textContent = t('Matching processes') + ' · ' + data.total +
        ' · ' + t('Including descendants') + ' · ' + data.affected;
      const list = document.createElement('div');
      list.textContent = data.matches.map(match => match.name + ' (PID ' + match.pid + ')').join(', ');
      output.append(list);
    }
    previewedPattern = pattern;
    byId('save-app').disabled = savingApp;
  } catch (error) {
    if (revision !== previewRevision) return;
    output.dataset.state = 'error';
    output.textContent = error.message || t('Could not reach the daemon');
  }
}
byId('addapp').onsubmit = async event => {
  event.preventDefault();
  const name = byId('appname').value.trim();
  const pattern = byId('appmatch').value.trim();
  if (!name || previewedPattern !== pattern || savingApp) return;
  const countries = byId('appcountries').value
    .split(',').map(value => value.trim().toUpperCase()).filter(value => value.length === 2);
  const revision = previewRevision;
  savingApp = true;
  byId('save-app').disabled = true;
  const saved = await changeRules('/api/apps', {
    body: JSON.stringify({ name, match: [pattern], allow: countries.length ? { countries } : null }),
  });
  savingApp = false;
  if (saved) {
    if (revision === previewRevision && name === byId('appname').value.trim()) {
      event.target.reset();
      invalidatePreview();
    }
    await loadApps();
  }
  byId('save-app').disabled = previewedPattern === null;
};
async function delApp(name) {
  if (await changeRules('/api/apps?name=' + encodeURIComponent(name), { method: 'DELETE' })) loadApps();
}
async function pickProcess() {
  const selection = byId('procpick').value;
  if (!selection) return;
  const [name, path] = JSON.parse(selection);
  byId('appname').value = name;
  byId('appmatch').value = path.includes('/') ? path : name;
  await previewApp();
}
async function trustNetwork() {
  if (await changeRules('/api/trust-network')) loadSettings();
}
const refreshTimer = setInterval(refresh, 1000);
refresh();
loadSettings();
loadApps();
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
            apply: Arc::new(tokio::sync::Notify::new()),
            explicit: false,
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

    #[tokio::test]
    async fn apply_button_wakes_the_daemon() {
        let apply = Arc::new(tokio::sync::Notify::new());
        let state = AppState {
            shared: shared(),
            token: "secret".to_string(),
            config_path: PathBuf::new(),
            apply: Arc::clone(&apply),
            explicit: false,
        };
        let app = Router::new()
            .route("/api/apply", post(apply_now))
            .with_state(state);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/apply")
                    .header("x-shuang-token", "secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        tokio::time::timeout(std::time::Duration::from_millis(50), apply.notified())
            .await
            .unwrap();
    }
}
