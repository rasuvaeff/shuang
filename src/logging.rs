//! Diagnostic output must not panic when a terminal or pipe disappears.

use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use crate::events::{iso8601_utc, now_secs};

static DAEMON_LOG: OnceLock<PathBuf> = OnceLock::new();

pub fn configure_daemon(config: &Path) {
    let _ = DAEMON_LOG.set(config.with_file_name("daemon.log"));
}

pub fn line(message: fmt::Arguments<'_>) {
    let message = message.to_string();
    emit(
        &mut io::stderr().lock(),
        DAEMON_LOG.get().map(PathBuf::as_path),
        &message,
        &message,
    );
}

pub fn panel_url(url: &str) {
    emit(
        &mut io::stderr().lock(),
        DAEMON_LOG.get().map(PathBuf::as_path),
        &format!("shuang: panel: {url}"),
        "shuang: panel available via shuang panel",
    );
}

fn emit(stderr: &mut impl Write, fallback: Option<&Path>, message: &str, file_message: &str) {
    if stderr.write_all(format!("{message}\n").as_bytes()).is_ok() {
        return;
    }
    let Some(path) = fallback else { return };
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    if let Ok(mut file) = options.open(path)
        && file.metadata().is_ok_and(|meta| meta.is_file())
    {
        let _ = file.write_all(format!("{}\t{file_message}\n", iso8601_utc(now_secs())).as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Gone;

    impl Write for Gone {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn logging_falls_back_without_persisting_the_panel_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        let mut stderr = Vec::new();
        emit(&mut stderr, Some(&path), "panel token", "panel ready");
        assert_eq!(stderr, b"panel token\n");
        assert!(!path.exists());
        emit(&mut Gone, Some(&path), "panel token", "panel ready");
        emit(&mut Gone, Some(&path), "another event", "another event");
        let log = std::fs::read_to_string(path).unwrap();
        let messages: Vec<_> = log
            .lines()
            .map(|line| line.split_once('\t').unwrap().1)
            .collect();
        assert_eq!(messages, ["panel ready", "another event"]);
        emit(&mut Gone, Some(dir.path()), "log failure", "log failure");
    }
}
