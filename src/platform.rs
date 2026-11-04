//! Process control primitives, per platform.
//!
//! Unix suspends with `SIGSTOP` (the same in-kernel pause job control uses);
//! Windows will use `NtSuspendProcess` (0.2, together with the tray). A
//! suspended process runs zero instructions and sends nothing.

use anyhow::Result;

#[cfg(unix)]
mod imp {
    use anyhow::Result;
    use nix::{
        sys::signal::{self, Signal},
        unistd::Pid,
    };

    fn send(pid: u32, sig: Signal) -> Result<()> {
        let pid = Pid::from_raw(pid as i32);
        Ok(signal::kill(pid, Some(sig))?)
    }

    pub fn suspend(pid: u32) -> Result<()> {
        send(pid, Signal::SIGSTOP)
    }

    pub fn resume(pid: u32) -> Result<()> {
        send(pid, Signal::SIGCONT)
    }

    pub fn terminate(pid: u32) -> Result<()> {
        send(pid, Signal::SIGTERM)
    }

    pub fn kill(pid: u32) -> Result<()> {
        send(pid, Signal::SIGKILL)
    }
}

#[cfg(windows)]
mod imp {
    //! Windows support lands together with the tray (0.2): `NtSuspendProcess`
    //! from ntdll via the `windows` crate. Until then every control call is an
    //! explicit error, never a silent no-op.

    use anyhow::{Result, bail};

    fn not_yet(op: &str) -> Result<()> {
        bail!("{op} is not implemented on Windows yet (planned in 0.2)")
    }

    pub fn suspend(_pid: u32) -> Result<()> {
        not_yet("suspend")
    }

    pub fn resume(_pid: u32) -> Result<()> {
        not_yet("resume")
    }

    pub fn terminate(_pid: u32) -> Result<()> {
        not_yet("terminate")
    }

    pub fn kill(_pid: u32) -> Result<()> {
        not_yet("kill")
    }
}

pub fn suspend(pid: u32) -> Result<()> {
    imp::suspend(pid)
}

pub fn resume(pid: u32) -> Result<()> {
    imp::resume(pid)
}

pub fn terminate(pid: u32) -> Result<()> {
    imp::terminate(pid)
}

pub fn kill(pid: u32) -> Result<()> {
    imp::kill(pid)
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use std::{
        process::{Command, Stdio},
        thread,
        time::Duration,
    };

    fn proc_state(pid: u32) -> String {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        status
            .lines()
            .find(|l| l.starts_with("State:"))
            .unwrap()
            .to_string()
    }

    #[test]
    fn suspend_and_resume_roundtrip() {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        // Give the child a moment to exec.
        thread::sleep(Duration::from_millis(100));

        suspend(pid).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert!(proc_state(pid).contains('T'), "expected stopped state");

        resume(pid).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert!(proc_state(pid).contains('S'), "expected sleeping state");

        kill(pid).unwrap();
        let _ = child.wait();
    }
}
