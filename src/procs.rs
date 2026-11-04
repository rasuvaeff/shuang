//! Process-tree discovery via `sysinfo`.
//!
//! Freezing a single pid is not enough: Claude Code spawns MCP servers,
//! `curl`, `git`. The whole tree is collected and suspended together.

use std::collections::HashMap;

use sysinfo::{Pid, Process, System};

/// The root pid plus every descendant (children of children included).
/// Pids that disappeared mid-scan are skipped silently — the process is gone,
/// there is nothing to freeze.
pub fn tree(root: u32, system: &System) -> Vec<u32> {
    let root = Pid::from_u32(root);
    let mut by_parent: HashMap<Pid, Vec<Pid>> = HashMap::new();
    for (pid, process) in system.processes() {
        if let Some(parent) = process.parent() {
            by_parent.entry(parent).or_default().push(*pid);
        }
    }

    let mut result = vec![root];
    let mut queue = vec![root];
    while let Some(pid) = queue.pop() {
        if let Some(children) = by_parent.get(&pid) {
            for child in children {
                if !result.contains(child) {
                    result.push(*child);
                    queue.push(*child);
                }
            }
        }
    }
    result.into_iter().map(|p| p.as_u32()).collect()
}

/// Does a running process match a pattern?
///
/// - `name` — equals the process file name (e.g. `claude`, `claude.exe`);
/// - `/myapp/` — substring of the executable path;
/// - `args:fragment` — substring of the full command line (for
///   `node .../claude/cli.js` style invocations).
pub fn matches(process: &Process, pattern: &str) -> bool {
    if let Some(args_pattern) = pattern.strip_prefix("args:") {
        let cmdline = process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        return cmdline.contains(args_pattern);
    }
    if pattern.contains('/') {
        return process
            .exe()
            .is_some_and(|exe| exe.to_string_lossy().contains(pattern));
    }
    // Case-insensitive: Windows reports process names in arbitrary case
    // ("Claude.exe" vs "claude.exe"), and users write patterns in any case.
    let name = process.name().to_string_lossy();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    name.eq_ignore_ascii_case(pattern)
}

/// All pids matching any pattern of any configured app, excluding ourselves.
pub fn find_targets(patterns: &[String], system: &System) -> Vec<(String, u32)> {
    let me = std::process::id();
    let mut out = Vec::new();
    for (pid, process) in system.processes() {
        let pid_u32 = pid.as_u32();
        if pid_u32 == me {
            continue;
        }
        if patterns.iter().any(|p| matches(process, p)) {
            out.push((process.name().to_string_lossy().into_owned(), pid_u32));
        }
    }
    out.sort_by_key(|(_, pid)| *pid);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sysinfo::get_current_pid;

    #[test]
    fn tree_includes_self() {
        let system = System::new_all();
        let me = get_current_pid().unwrap().as_u32();
        let tree = tree(me, &system);
        assert!(tree.contains(&me));
    }

    #[test]
    fn tree_covers_spawned_children() {
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::Duration;

        let mut child = Command::new("sleep")
            .arg("5")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        thread::sleep(Duration::from_millis(150));
        let system = System::new_all();
        let tree = tree(child.id(), &system);
        assert!(tree.contains(&child.id()), "tree: {tree:?}");
        crate::platform::kill(child.id()).unwrap();
        let _ = child.wait();
    }

    #[test]
    fn name_match_ignores_exe_suffix_and_case_of_pattern() {
        let system = System::new_all();
        let me = get_current_pid().unwrap();
        let process = system.process(me).unwrap();
        // The test harness runs the binary as `shuang-<hash>`; the matcher is
        // exact, so pass the real process name.
        let own_name = process.name().to_string_lossy().into_owned();
        assert!(matches(process, &own_name), "name: {own_name}");
        assert!(!matches(process, "definitely-not-a-process"));
        // args: matches the command line we were invoked with (test harness args).
        assert!(!matches(process, "args:zzz-no-such-argument"));
    }

    #[test]
    fn find_targets_excludes_self() {
        let system = System::new_all();
        let targets = find_targets(&["shuang".to_string()], &system);
        let me = std::process::id();
        assert!(targets.iter().all(|(_, pid)| *pid != me));
    }
}
