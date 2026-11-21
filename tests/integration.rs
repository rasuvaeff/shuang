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

#[cfg(target_os = "linux")]
struct ManagedChild(std::process::Child);

#[cfg(target_os = "linux")]
impl Drop for ManagedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

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

#[cfg(target_os = "linux")]
#[tokio::test]
async fn panel_profile_change_interrupts_an_inflight_ip_check() {
    use std::io::{BufRead, BufReader};
    use std::sync::mpsc;

    let dir = tempfile::tempdir().unwrap();
    // Hold the first IP request open until the test finishes. A daemon
    // that only listens for Apply while idle will wait the full timeout.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = format!("http://{}", listener.local_addr().unwrap());
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        let mut request = [0; 1024];
        assert!(connection.read(&mut request).unwrap() > 0);
        started_tx.send(()).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(20));
    });
    let (b, _) = spawn("203.0.113.7");
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[[apps]]
name = "live-test"
match = ["args:shuang-live-test"]

[profiles.work]
ips = ["203.0.113.7"]

[ip_check]
ip_services = ["{a}", "{b}"]
ipv6_services = []
country_services = []
min_agree = 2
interval_secs = 60
timeout_secs = 15

[timing]
grace_secs = 60
"#
        ),
    )
    .unwrap();
    let path = config.to_str().unwrap();
    assert!(
        shuang(&["profile", "work", "--config", path])
            .status
            .success()
    );

    let target = ManagedChild(
        Command::new("bash")
            .args(["-c", "exec -a shuang-live-test sleep 30"])
            .spawn()
            .unwrap(),
    );
    let mut daemon = ManagedChild(
        Command::new(env!("CARGO_BIN_EXE_shuang"))
            .args(["daemon", "--no-tray", "--no-notify", "--config", path])
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let (tx, rx) = mpsc::channel();
    let stderr = daemon.0.stderr.take().unwrap();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            eprintln!("daemon: {line}");
            if let Some(url) = line.strip_prefix("shuang: panel: ") {
                let _ = tx.send(url.to_string());
            }
        }
    });
    let url = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let base = reqwest::Url::parse(&url).unwrap();
    let token = base
        .query_pairs()
        .find(|(key, _)| key == "token")
        .unwrap()
        .1;
    let endpoint = base.join("/api/profile").unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let connecting = std::time::Instant::now();
    let response = loop {
        let result = client
            .post(endpoint.clone())
            .header("X-Shuang-Token", token.as_ref())
            .json(&serde_json::json!({"name": "none"}))
            .send()
            .await;
        match result {
            Ok(response) => break response,
            Err(err) if err.is_connect() => {
                assert!(
                    daemon.0.try_wait().unwrap().is_none(),
                    "daemon exited before panel request"
                );
                assert!(
                    connecting.elapsed() < Duration::from_secs(3),
                    "panel never accepted connections"
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) => panic!("panel request failed: {err}"),
        }
    };
    assert!(response.status().is_success());

    let started = std::time::Instant::now();
    loop {
        let status = std::fs::read_to_string(format!("/proc/{}/status", target.0.id())).unwrap();
        if status
            .lines()
            .any(|line| line.starts_with("State:") && line.contains('T'))
        {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "profile change did not freeze the app promptly"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    drop(release_tx);
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
fn check_uses_the_active_profile() {
    let dir = tempfile::tempdir().unwrap();
    let (a, _) = spawn("203.0.113.7");
    let (b, _) = spawn("203.0.113.7");
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[profiles.work]
ips = ["203.0.113.7"]

[ip_check]
ip_services = ["{a}", "{b}"]
ipv6_services = []
country_services = []
min_agree = 2
"#
        ),
    )
    .unwrap();
    let path = path.to_str().unwrap();
    assert!(
        shuang(&["profile", "work", "--config", path])
            .status
            .success()
    );
    let out = shuang(&["check", "--json", "--config", path]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
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

#[cfg(target_os = "linux")]
#[test]
fn app_allowlist_alone_triggers_the_route_check() {
    use std::io::{BufRead, BufReader};
    use std::sync::mpsc;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut request = String::new();
            BufReader::new(&stream).read_line(&mut request).unwrap();
            if request.starts_with("CONNECT shuang-route.test:443 ") {
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
                tx.send(()).unwrap();
                return;
            }
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n203.0.113.7",
            );
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[[apps]]
name = "route-test"
match = ["shuang-route-test"]
[apps.allow]
ips = ["203.0.113.7"]

[ip_check]
ip_services = ["http://ip-one.test", "http://ip-two.test"]
ipv6_services = []
country_services = []
min_agree = 2
interval_secs = 60
timeout_secs = 2
proxy = "{proxy}"

[route_check]
enabled = true
services = ["shuang-route.test"]
"#
        ),
    )
    .unwrap();

    let _daemon = ManagedChild(
        Command::new(env!("CARGO_BIN_EXE_shuang"))
            .args([
                "daemon",
                "--no-tray",
                "--no-notify",
                "--no-panel",
                "--config",
            ])
            .arg(path)
            .spawn()
            .unwrap(),
    );
    rx.recv_timeout(Duration::from_secs(5))
        .expect("the app-only allowance did not trigger a route check");
}
