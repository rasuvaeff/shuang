//! Integration tests drive the built binary against a local mock IP service:
//! no real network is touched, the quorum logic runs exactly as in production.

#[cfg(unix)]
use std::time::Duration;
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

/// Minimal HTTP server answering every GET with `body`. Returns the base URL
/// and a request counter, so a test can flip the answer after N requests.
fn mock_service(body: Arc<String>, counter: Arc<AtomicUsize>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            counter.fetch_add(1, Ordering::SeqCst);
            let body = body.clone();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{addr}")
}

/// A config that routes every check through two local mock services.
fn write_config(dir: &std::path::Path, grace_secs: u64, interval_secs: u64) -> String {
    let (a, _) = spawn("203.0.113.7");
    let (b, _) = spawn("203.0.113.7");
    let config = format!(
        r#"
[allow]
ips = ["203.0.113.7"]

[ip_check]
ip_services = ["{a}", "{b}"]
ipv6_services = []
country_services = []
min_agree = 2
interval_secs = {interval_secs}
timeout_secs = 2

[timing]
grace_secs = {grace_secs}
close_secs = 1
"#
    );
    let path = dir.join("config.toml");
    std::fs::write(&path, config).unwrap();
    path.to_string_lossy().into_owned()
}

fn spawn(ip: &str) -> (String, Arc<AtomicUsize>) {
    let counter = Arc::new(AtomicUsize::new(0));
    let url = mock_service(Arc::new(ip.to_string()), counter.clone());
    (url, counter)
}

fn shuang(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_shuang"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn check_reports_allowed_ip() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), 20, 1);
    let out = shuang(&["check", "--json", "--config", &config]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["ipv4"], "203.0.113.7");
    assert_eq!(doc["allowed"], true);
}

#[test]
fn check_reports_not_allowed_ip() {
    let dir = tempfile::tempdir().unwrap();
    let (a, _) = spawn("198.51.100.99"); // different from the allowed one
    let (b, _) = spawn("198.51.100.99");
    let config = format!(
        r#"
[allow]
ips = ["203.0.113.7"]

[ip_check]
ip_services = ["{a}", "{b}"]
ipv6_services = []
country_services = []
min_agree = 2
interval_secs = 1
timeout_secs = 2
"#
    );
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config).unwrap();
    let out = shuang(&["check", "--json", "--config", &path.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(3));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["allowed"], false);
}

#[test]
fn no_quorum_means_not_allowed() {
    let dir = tempfile::tempdir().unwrap();
    // Two services disagree: no quorum, fail closed.
    let (a, _) = spawn("198.51.100.1");
    let (b, _) = spawn("198.51.100.2");
    let config = format!(
        r#"
[allow]
ips = ["198.51.100.1"]

[ip_check]
ip_services = ["{a}", "{b}"]
ipv6_services = []
country_services = []
min_agree = 2
interval_secs = 1
timeout_secs = 2
"#
    );
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config).unwrap();
    let out = shuang(&["check", "--json", "--config", &path.to_string_lossy()]);
    assert_eq!(out.status.code(), Some(3));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["quorum"], false);
    assert_eq!(doc["allowed"], false);
}

#[cfg(unix)]
#[test]
fn run_finishes_when_ip_stays_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), 20, 1);
    let out = shuang(&["run", "--config", &config, "--", "sleep", "0.3"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn run_refuses_to_start_on_a_wrong_ip() {
    let dir = tempfile::tempdir().unwrap();
    let (a, _) = spawn("198.51.100.99");
    let (b, _) = spawn("198.51.100.99");
    let config = format!(
        r#"
[allow]
ips = ["203.0.113.7"]

[ip_check]
ip_services = ["{a}", "{b}"]
ipv6_services = []
country_services = []
min_agree = 2
interval_secs = 1
timeout_secs = 2
"#
    );
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config).unwrap();
    let out = shuang(&[
        "run",
        "--config",
        &path.to_string_lossy(),
        "--",
        "sleep",
        "5",
    ]);
    assert_eq!(out.status.code(), Some(69));
}

#[cfg(unix)]
#[test]
fn run_stops_the_command_when_the_ip_changes_and_never_returns() {
    let dir = tempfile::tempdir().unwrap();
    // The service answers with the allowed IP for the first 2 requests
    // (startup + first tick), then with a foreign one.
    let counter = Arc::new(AtomicUsize::new(0));
    let url = {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let counter = counter.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let body = if n < 2 {
                    "203.0.113.7"
                } else {
                    "198.51.100.50"
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    };
    let config = format!(
        r#"
[allow]
ips = ["203.0.113.7"]

[ip_check]
ip_services = ["{url}", "{url}"]
ipv6_services = []
country_services = []
min_agree = 2
interval_secs = 1
timeout_secs = 2

[timing]
grace_secs = 2
close_secs = 1
"#
    );
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config).unwrap();

    let start = std::time::Instant::now();
    let out = shuang(&[
        "run",
        "--config",
        &path.to_string_lossy(),
        "--",
        "sleep",
        "60",
    ]);
    // The command must be stopped (75), not left running for a minute.
    assert_eq!(
        out.status.code(),
        Some(75),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(start.elapsed() < Duration::from_secs(30));
}

#[test]
fn allow_persists_state_next_to_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "").unwrap();
    let out = shuang(&[
        "allow",
        "203.0.113.77",
        "--config",
        &config.to_string_lossy(),
    ]);
    assert!(out.status.success());
    let state = dir.path().join("state.toml");
    let raw = std::fs::read_to_string(&state).unwrap();
    assert!(raw.contains("203.0.113.77"));
}
