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

/// Minimal HTTP server choosing an IP for each request.
fn serve_ip(
    counter: Arc<AtomicUsize>,
    answer: impl Fn(usize) -> String + Send + 'static,
) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let body = answer(n);
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
    let ip = ip.to_owned();
    let url = serve_ip(counter.clone(), move |_| ip.clone());
    (url, counter)
}

#[cfg(target_os = "linux")]
#[track_caller]
fn await_condition<T>(mut condition: impl FnMut() -> Option<T>) -> T {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(value) = condition() {
            return value;
        }
        assert!(std::time::Instant::now() < deadline, "condition timed out");
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn run_restores_the_foreground_tty_after_forced_stop() {
    use nix::{pty::openpty, sys::termios::tcgetattr};
    use std::{fs::File, process::Stdio, sync::atomic::AtomicBool};

    let dir = tempfile::tempdir().unwrap();
    let denied = Arc::new(AtomicBool::new(false));
    let switch = denied.clone();
    let url = serve_ip(Arc::new(AtomicUsize::new(0)), move |_| {
        if switch.load(Ordering::SeqCst) {
            "198.51.100.50"
        } else {
            "203.0.113.7"
        }
        .into()
    });
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[allow]
ips = ["203.0.113.7"]
[ip_check]
ip_services = ["{url}"]
ipv6_services = []
country_services = []
min_agree = 1
interval_secs = 1
timeout_secs = 2
[timing]
grace_secs = 0
close_secs = 0
"#
        ),
    )
    .unwrap();
    let tty = openpty(None, None).unwrap();
    let before = tcgetattr(&tty.slave).unwrap();
    let _master = File::from(tty.master).try_clone().unwrap();
    let slave = File::from(tty.slave).try_clone().unwrap();
    let mut run = ManagedChild(
        Command::new("setsid")
            .args(["--ctty", env!("CARGO_BIN_EXE_shuang"), "run", "--config"])
            .arg(config)
            .args(["--", "sh", "-c", "stty raw -echo && exec sleep 30"])
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    await_condition(|| (tcgetattr(&slave).unwrap() != before).then_some(()));
    denied.store(true, Ordering::SeqCst);
    let result = await_condition(|| run.0.try_wait().unwrap());
    assert_eq!(result.code(), Some(75));
    assert_eq!(tcgetattr(&slave).unwrap(), before);
}

#[cfg(target_os = "linux")]
#[test]
fn bash_prompt_recovers_when_daemon_freezes_and_kills_a_direct_launch() {
    use nix::{
        pty::openpty,
        sys::signal::{Signal, kill},
        unistd::{Pid, tcgetpgrp},
    };
    use std::{
        fs::{self, File},
        process::Stdio,
        sync::{atomic::AtomicBool, mpsc},
        time::Instant,
    };

    let dir = tempfile::tempdir().unwrap();
    let marker = format!("shuang-tty-{}", dir.path().file_name().unwrap().display());
    let denied = Arc::new(AtomicBool::new(false));
    let switch = denied.clone();
    let url = serve_ip(Arc::new(AtomicUsize::new(0)), move |_| {
        if switch.load(Ordering::SeqCst) {
            "198.51.100.50"
        } else {
            "203.0.113.7"
        }
        .into()
    });
    let config = dir.path().join("config.toml");
    fs::write(
        &config,
        format!(
            r#"
[allow]
ips = ["203.0.113.7"]
[ip_check]
ip_services = ["{url}"]
ipv6_services = []
country_services = []
min_agree = 1
interval_secs = 1
[timing]
grace_secs = 3
close_secs = 0
[[apps]]
name = "terminal fixture"
match = ["args:{marker}"]
"#
        ),
    )
    .unwrap();

    let tty = openpty(None, None).unwrap();
    let mut master = File::from(tty.master).try_clone().unwrap();
    let slave = File::from(tty.slave).try_clone().unwrap();
    let shell = ManagedChild(
        Command::new("setsid")
            .args(["--ctty", "bash", "--noprofile", "--norc", "-i"])
            .env("PS1", "fixture> ")
            .env("INPUTRC", "/dev/null")
            .env("TERM", "xterm-256color")
            .env("LC_ALL", "C")
            .env("PROMPT_COMMAND", "printf 'status:%d\\n' \"$?\"")
            .env("SHUANG_BIN", env!("CARGO_BIN_EXE_shuang"))
            .env("SHUANG_TEST_MARKER", marker)
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave))
            .spawn()
            .unwrap(),
    );
    let mut reader = master.try_clone().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = [0; 4096];
        while let Ok(n @ 1..) = reader.read(&mut buf) {
            if tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let receive = |needle: &[u8]| {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut result = Vec::new();
        while !result.windows(needle.len()).any(|w| w == needle) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            result.extend(rx.recv_timeout(remaining).unwrap_or_else(|err| {
                panic!(
                    "{err}: terminal output {:?}",
                    String::from_utf8_lossy(&result)
                )
            }));
        }
        result
    };
    let prompt = b"fixture> ";
    let reset = b"\x1b[?1000;1002;1003;1004;1006;1016;2004;2031l";
    receive(prompt);
    master
        .write_all(b"source <(\"$SHUANG_BIN\" shell-hook bash); source <(\"$SHUANG_BIN\" shell-hook bash); false\n")
        .unwrap();
    let output = receive(prompt);
    assert_eq!(
        output.windows(reset.len()).filter(|w| *w == reset).count(),
        1
    );
    assert!(output.windows(10).any(|w| w == b"status:1\r\n"));

    // A real foreground job leaves focus reports enabled when forcibly stopped.
    master.write_all(b"bash -c 'stty raw -echo; printf \"\\033[?1004h\"; exec -a \"$SHUANG_TEST_MARKER\" sleep 30'\n").unwrap();
    receive(b"\x1b[?1004h");
    let shell_pid = Pid::from_raw(shell.0.id() as i32);
    let job = tcgetpgrp(&master).unwrap();
    assert_ne!(job, shell_pid);
    let mut daemon = ManagedChild(
        Command::new(env!("CARGO_BIN_EXE_shuang"))
            .args([
                "daemon",
                "--no-tray",
                "--no-notify",
                "--no-panel",
                "--config",
            ])
            .arg(config)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    denied.store(true, Ordering::SeqCst);
    let output = receive(prompt);
    assert!(output.windows(reset.len()).any(|w| w == reset));
    assert_eq!(tcgetpgrp(&master).unwrap(), shell_pid);
    let proc_status = format!("/proc/{job}/status");
    assert!(
        fs::read_to_string(&proc_status)
            .unwrap()
            .contains("State:\tT")
    );
    master.write_all(b"printf 'shell:%s\\n' usable\n").unwrap();
    receive(b"shell:usable\r\n");
    await_condition(|| (!std::path::Path::new(&proc_status).exists()).then_some(()));
    master
        .write_all(b"printf 'shell:%s\\n' after-kill\n")
        .unwrap();
    receive(b"shell:after-kill\r\n");
    kill(Pid::from_raw(daemon.0.id() as i32), Signal::SIGTERM).unwrap();
    assert!(await_condition(|| daemon.0.try_wait().unwrap()).success());
}

#[cfg(target_os = "linux")]
#[test]
fn daemon_survives_hangup_and_detached_stderr_then_releases_its_hold() {
    use nix::{
        pty::openpty,
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    use std::{
        fs::{self, File},
        process::Stdio,
    };

    let dir = tempfile::tempdir().unwrap();
    let marker = format!("shuang-hup-{}", dir.path().file_name().unwrap().display());
    let config = write_config(dir.path(), 60, 1);
    let mut contents = fs::read_to_string(&config)
        .unwrap()
        .replace("ips = [\"203.0.113.7\"]", "ips = [\"198.51.100.50\"]");
    contents.push_str(&format!(
        "\n[[apps]]\nname = \"hangup\"\nmatch = [\"args:{marker}\"]\n"
    ));
    fs::write(&config, contents).unwrap();
    let target = ManagedChild(
        Command::new("bash")
            .args(["-c", "exec -a \"$1\" sleep 30", "shuang-test", &marker])
            .spawn()
            .unwrap(),
    );
    let target_stopped = || {
        let status = fs::read_to_string(format!("/proc/{}/status", target.0.id())).unwrap();
        status.lines().any(|line| line.starts_with("State:\tT"))
    };
    let tty = openpty(None, None).unwrap();
    // File::try_clone duplicates with close-on-exec. The daemon must not keep
    // a copy of the master open after the test drops its handle.
    let master = File::from(tty.master).try_clone().unwrap();
    let mut stderr = File::from(tty.slave).try_clone().unwrap();
    let mut daemon = ManagedChild(
        Command::new(env!("CARGO_BIN_EXE_shuang"))
            .args([
                "daemon",
                "--no-tray",
                "--no-notify",
                "--no-panel",
                "--config",
                &config,
            ])
            .stderr(Stdio::from(stderr.try_clone().unwrap()))
            .spawn()
            .unwrap(),
    );
    await_condition(|| target_stopped().then_some(()));
    drop(master);
    assert_eq!(
        stderr.write_all(b"probe").unwrap_err().raw_os_error(),
        Some(nix::libc::EIO)
    );
    let pid = Pid::from_raw(daemon.0.id() as i32);
    kill(pid, Signal::SIGHUP).unwrap();
    let log = dir.path().join("daemon.log");
    await_condition(|| {
        fs::read_to_string(&log).ok().and_then(|text| {
            (text.contains("received SIGHUP") && text.contains("left for the allowed IP"))
                .then_some(())
        })
    });
    assert!(target_stopped());
    assert!(daemon.0.try_wait().unwrap().is_none());
    kill(pid, Signal::SIGTERM).unwrap();
    assert!(await_condition(|| daemon.0.try_wait().unwrap()).success());
    await_condition(|| (!target_stopped()).then_some(()));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn panel_profile_change_interrupts_an_inflight_ip_check() {
    use std::io::{BufRead, BufReader};
    use std::sync::mpsc;

    let dir = tempfile::tempdir().unwrap();
    let marker = format!(
        "shuang-preview-{}",
        dir.path().file_name().unwrap().to_string_lossy()
    );
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
        thread::spawn(move || {
            let _ = release_rx.recv_timeout(Duration::from_secs(20));
            drop(connection);
        });
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            if stream.read(&mut request).unwrap_or(0) > 0 {
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n203.0.113.7",
                );
            }
        }
    });
    let (b, _) = spawn("203.0.113.7");
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[[apps]]
name = "live-test"
match = ["args:{marker}"]

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
            .args(["-c", "exec -a \"$1\" sleep 30", "shuang-test", &marker])
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
    let status_url = base.join("/api/status").unwrap();
    let get_status = || async {
        client
            .get(status_url.clone())
            .header("X-Shuang-Token", token.as_ref())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<serde_json::Value>()
            .await
            .unwrap()
    };
    let initial = get_status().await;
    assert_eq!(initial["rules_status"], "checking");

    let preview = client
        .post(base.join("/api/apps/preview").unwrap())
        .header("X-Shuang-Token", token.as_ref())
        .json(&serde_json::json!({"patterns": [format!("args:{marker}")] }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert!(
        preview["matches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["pid"] == target.0.id())
    );
    assert!(preview["affected"].as_u64().unwrap() >= preview["total"].as_u64().unwrap());

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
    loop {
        let status = get_status().await;
        if status["rules_status"] == "applied" {
            let application = &status["applications"][0];
            assert_eq!(application["name"], "live-test");
            assert_eq!(application["state"], "frozen");
            assert!(application["seconds_left"].as_u64().unwrap() > 0);
            assert!(application["reason"].as_str().is_some());
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "new rules never confirmed"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    std::fs::write(&config, "[invalid").unwrap();
    let refused = client
        .post(base.join("/api/apply").unwrap())
        .header("X-Shuang-Token", token.as_ref())
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(refused.text().await.unwrap().contains("invalid config"));
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

#[test]
fn conflicting_ipv6_answers_deny_a_confirmed_ipv4() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(dir.path(), 10, 1);
    let (a, _) = spawn("2001:db8::1");
    let (b, _) = spawn("2001:db8::2");
    let initial = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        initial.replace(
            "ipv6_services = []",
            &format!("ipv6_services = [\"{a}\", \"{b}\"]"),
        ),
    )
    .unwrap();
    let output = shuang(&["check", "--json", "--config", &config]);
    assert_eq!(output.status.code(), Some(3));
    let verdict: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(verdict["quorum"], true);
    assert_eq!(verdict["allowed"], false);
}

#[cfg(target_os = "linux")]
#[test]
fn probe_freezes_udp_sender_while_ip_request_is_pending() {
    use std::{net::UdpSocket, sync::mpsc, time::Instant};

    let dir = tempfile::tempdir().unwrap();
    let marker = format!(
        "udp-preview-{}",
        dir.path().file_name().unwrap().to_string_lossy()
    );
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let probe_addr = probe.local_addr().unwrap();
    let slow = TcpListener::bind("127.0.0.1:0").unwrap();
    let ip_url = format!("http://{}", slow.local_addr().unwrap());
    let (accepted, ready) = mpsc::channel();
    let (release, done) = mpsc::channel::<()>();
    thread::spawn(move || {
        let mut buf = [0; 512];
        let _request = loop {
            let (mut request, _) = slow.accept().unwrap();
            request
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            if request.read(&mut buf).is_ok_and(|read| read > 0) {
                break request;
            }
        };
        accepted.send(()).unwrap();
        let _ = done.recv_timeout(Duration::from_secs(12));
    });

    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut packet = [0; 32];
    let target = ManagedChild(
        Command::new("bash")
            .args([
                "-c",
                "while :; do printf ping >&3; sleep 0.05; done 3>/dev/udp/127.0.0.1/$1",
                &marker,
                &udp.local_addr().unwrap().port().to_string(),
            ])
            .spawn()
            .unwrap(),
    );
    assert_eq!(udp.recv(&mut packet).unwrap(), 4);

    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[[apps]]
name = "udp-sender"
match = ["args:{marker}"]
[allow]
ips = ["203.0.113.7"]
[ip_check]
ip_services = ["{ip_url}"]
ipv6_services = []
country_services = []
min_agree = 1
timeout_secs = 10
interval_secs = 60
[probe]
enabled = true
via = "direct"
hosts = ["{probe_addr}"]
[timing]
grace_secs = 60
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
            .arg(config)
            .spawn()
            .unwrap(),
    );
    ready.recv_timeout(Duration::from_secs(4)).unwrap();
    udp.recv(&mut packet).unwrap();
    drop(probe);
    let failed_at = Instant::now();
    let status = format!("/proc/{}/status", target.0.id());
    while !std::fs::read_to_string(&status)
        .unwrap()
        .lines()
        .any(|line| line.starts_with("State:") && line.contains("T (stopped)"))
    {
        assert!(
            failed_at.elapsed() < Duration::from_secs(4),
            "transport signal did not interrupt the slow IP request"
        );
        thread::sleep(Duration::from_millis(10));
    }

    // Queued packets were sent before the process stopped. Drain the local
    // socket and verify there are no further packets from the frozen sender.
    udp.set_nonblocking(true).unwrap();
    while udp.recv(&mut packet).is_ok() {}
    udp.set_nonblocking(false).unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let error = udp.recv(&mut packet).unwrap_err();
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
    drop(release);
}

#[cfg(target_os = "linux")]
#[test]
fn strict_route_check_freezes_an_app_allowed_by_its_own_rules() {
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
    let marker = format!(
        "route-preview-{}",
        dir.path().file_name().unwrap().to_string_lossy()
    );
    let target = ManagedChild(
        Command::new("bash")
            .args(["-c", "exec -a \"$1\" sleep 30", "shuang-test", &marker])
            .spawn()
            .unwrap(),
    );
    std::fs::write(
        &path,
        format!(
            r#"
[[apps]]
name = "route-test"
match = ["args:{marker}"]
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
strict = true
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
    let started = std::time::Instant::now();
    while !std::fs::read_to_string(format!("/proc/{}/status", target.0.id()))
        .unwrap()
        .lines()
        .any(|line| line.starts_with("State:") && line.contains("T (stopped)"))
    {
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "route failure did not freeze the app"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
