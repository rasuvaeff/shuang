//! Restore input after a supervised command or at an interactive shell prompt.

use std::io::{self, Write};

use nix::{
    sys::termios::{SetArg, Termios, tcgetattr, tcsetattr},
    unistd::{getpgrp, tcgetpgrp},
};

use crate::cli::Shell;

pub fn print_hook(shell: Shell) -> anyhow::Result<u8> {
    let script = match shell {
        Shell::Bash => include_str!("terminal.bash"),
    };
    io::stdout().lock().write_all(script.as_bytes())?;
    Ok(0)
}

pub struct Settings(Termios);

impl Settings {
    pub fn capture() -> Option<Self> {
        let stdin = io::stdin();
        if tcgetpgrp(&stdin).ok()? != getpgrp() {
            return None;
        }
        tcgetattr(&stdin).ok().map(Self)
    }
}

impl Drop for Settings {
    fn drop(&mut self) {
        let stdin = io::stdin();
        if tcgetpgrp(&stdin).ok() == Some(getpgrp())
            && let Ok(current) = tcgetattr(&stdin)
            && current != self.0
        {
            // Discard keystrokes queued for the command before giving the terminal back.
            let _ = tcsetattr(&stdin, SetArg::TCSAFLUSH, &self.0);
        }
    }
}
