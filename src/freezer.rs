//! Linux cgroup v2 suspension does not trigger shell job control or SIGCONT
//! handlers. Each claimed process gets its own frozen leaf so overlapping
//! policies can release processes independently. The parent is its original
//! cgroup; moving back restores its resource limits without thawing siblings.

use std::{fs, io, path::PathBuf};

const PREFIX: &str = "shuang-freeze-";

fn current(pid: u32) -> io::Result<PathBuf> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let path = raw
        .lines()
        .find_map(|line| line.strip_prefix("0::/"))
        .filter(|path| !path.contains('\\'))
        .ok_or_else(|| io::Error::other("no usable unified cgroup"))?;
    let path = PathBuf::from("/sys/fs/cgroup").join(path);
    // A cgroup namespace can expose paths outside our mounted hierarchy.
    if path
        .components()
        .any(|part| part == std::path::Component::ParentDir)
    {
        return Err(io::Error::other("cgroup is outside the mounted hierarchy"));
    }
    Ok(path)
}

fn owned(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(PREFIX))
        && fs::symlink_metadata(path).is_ok_and(|meta| {
            meta.is_dir() && fs::metadata("/proc/self").is_ok_and(|me| me.uid() == meta.uid())
        })
}

fn identity(pid: u32) -> io::Result<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let start = stat
        .rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .filter(|start| start.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| io::Error::other("cannot read process start time"))?;
    Ok(format!("{PREFIX}{pid}-{start}"))
}

pub fn suspend(pid: u32) -> io::Result<()> {
    let current = current(pid)?;
    let name = identity(pid)?;
    if current
        .file_name()
        .is_some_and(|part| part == name.as_str())
        && owned(&current)
    {
        return fs::write(current.join("cgroup.freeze"), "1");
    }
    let original = if owned(&current) {
        current
            .parent()
            .ok_or_else(|| io::Error::other("missing original cgroup"))?
    } else {
        &current
    };
    let leaf = original.join(name);
    match fs::create_dir(&leaf) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists && owned(&leaf) => {}
        Err(err) => return Err(err),
    }
    // Freeze before migration, so the process cannot execute inside the new
    // group. A failure before migration leaves the process in its old group.
    let result = fs::write(leaf.join("cgroup.freeze"), "1")
        .and_then(|()| fs::write(leaf.join("cgroup.procs"), pid.to_string()));
    if result.is_err() {
        let _ = fs::remove_dir(&leaf);
    }
    result
}

pub fn is_frozen(pid: u32) -> bool {
    current(pid).is_ok_and(|path| {
        owned(&path)
            && fs::read_to_string(path.join("cgroup.events"))
                .is_ok_and(|events| events.lines().any(|line| line == "frozen 1"))
    })
}

/// A known leaf is recovered from /proc even after its supervisor crashes.
/// Resume only this process; descendants with other claims stay frozen.
pub fn resume(pid: u32) -> Option<io::Result<()>> {
    let path = current(pid).ok()?;
    if !owned(&path) {
        return None;
    }
    Some((|| {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("missing original cgroup"))?;
        fs::write(parent.join("cgroup.procs"), pid.to_string())?;
        let _ = fs::remove_dir(path);
        Ok(())
    })())
}

pub fn group(pid: u32) -> Option<PathBuf> {
    current(pid).ok().filter(|path| owned(path))
}

pub fn cleanup(path: &std::path::Path) {
    // SIGKILL is asynchronous. Removing a still-populated group is harmless
    // (EBUSY); briefly retry so forced closes do not accumulate empty leaves.
    for _ in 0..20 {
        if fs::remove_dir(path).is_ok() || !path.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}
