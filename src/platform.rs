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
    //! Windows process control: `NtSuspendProcess` / `NtResumeProcess` from
    //! ntdll — the same mechanism Process Explorer's Suspend uses. Not on the
    //! public kernel32 API surface, hence the dynamic lookup + unsafe.
    //!
    //! SAFETY invariants for every call below:
    //! - the HANDLE comes from `OpenProcess` on the pid passed in and is
    //!   closed on every path (`CloseHandle` after each call);
    //! - the function pointers are resolved from ntdll by name at most once
    //!   and are the documented NT APIs;
    //! - no handle is stored or shared across threads.
    #![allow(unsafe_code)] // the whole point of this module; see AGENTS.md

    use anyhow::{Result, bail};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Threading::{OpenProcess, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE},
        },
    };

    fn ntdll_fn(name: &[u8]) -> Option<usize> {
        use std::ffi::CStr;
        unsafe {
            let module = GetModuleHandleA(windows_sys::core::s!("ntdll.dll"));
            if module.is_null() {
                return None;
            }
            // `name` arrives already nul-terminated (b"NtSuspendProcess\0").
            let name = CStr::from_bytes_with_nul(name).ok()?;
            GetProcAddress(module, name.as_ptr() as *const u8).map(|f| f as usize)
        }
    }

    type NtSuspendResume = unsafe extern "system" fn(HANDLE) -> i32;

    fn with_handle<T>(pid: u32, access: u32, op: impl FnOnce(HANDLE) -> Option<T>) -> Option<T> {
        unsafe {
            let handle = OpenProcess(access, 0, pid);
            if handle.is_null() {
                return None;
            }
            let out = op(handle);
            CloseHandle(handle);
            out
        }
    }

    pub fn suspend(pid: u32) -> Result<()> {
        let Some(fun) = suspend_fn() else {
            bail!("NtSuspendProcess not found in ntdll");
        };
        let ok = with_handle(pid, PROCESS_SUSPEND_RESUME, |h| {
            Some(unsafe { fun(h) } >= 0)
        });
        if ok == Some(true) {
            Ok(())
        } else {
            bail!("NtSuspendProcess({pid}) failed")
        }
    }

    pub fn resume(pid: u32) -> Result<()> {
        let Some(fun) = resume_fn() else {
            bail!("NtResumeProcess not found in ntdll");
        };
        let ok = with_handle(pid, PROCESS_SUSPEND_RESUME, |h| {
            Some(unsafe { fun(h) } >= 0)
        });
        if ok == Some(true) {
            Ok(())
        } else {
            bail!("NtResumeProcess({pid}) failed")
        }
    }

    pub fn terminate(pid: u32) -> Result<()> {
        let ok = with_handle(pid, PROCESS_TERMINATE, |h| {
            Some(unsafe { terminate_process_thunk(h) } != 0)
        });
        if ok == Some(true) {
            Ok(())
        } else {
            bail!("TerminateProcess({pid}) failed")
        }
    }

    pub fn kill(pid: u32) -> Result<()> {
        terminate(pid)
    }

    unsafe fn terminate_process_thunk(handle: HANDLE) -> i32 {
        // Edition 2024: an `unsafe fn` body is no longer an implicit unsafe block.
        unsafe { windows_sys::Win32::System::Threading::TerminateProcess(handle, 1) }
    }

    fn suspend_fn() -> Option<NtSuspendResume> {
        ntdll_fn(b"NtSuspendProcess\0").map(|a| unsafe { std::mem::transmute(a) })
    }

    fn resume_fn() -> Option<NtSuspendResume> {
        ntdll_fn(b"NtResumeProcess\0").map(|a| unsafe { std::mem::transmute(a) })
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

// ─────────────────────────────────────────────────────────────────────────────
// Windows: default gateway MAC via GetAdaptersAddresses (used by trusted.rs).
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(windows)]
pub mod win_net {
    //! Default-gateway MAC via `GetAdaptersAddresses` — trusted networks on
    //! Windows. Uses the real windows-sys struct (no hand-rolled layouts).

    use windows_sys::Win32::NetworkManagement::IpHelper::GetAdaptersAddresses;
    use windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;

    const GAA_FLAG_SKIP_ANYCAST: u32 = 0x0002;
    const GAA_FLAG_SKIP_MULTICAST: u32 = 0x0004;
    const GAA_FLAG_SKIP_DNS_SERVER: u32 = 0x0008;

    /// The MAC of the adapter that owns the default gateway, lowercase
    /// `aa:bb:cc:dd:ee:ff`.
    pub fn gateway_mac() -> Option<String> {
        #![allow(unsafe_code)] // flat Win32 FFI; see the unsafe policy in AGENTS.md
        unsafe {
            let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
            let mut size: u32 = 0;
            // First call: size discovery (returns ERROR_BUFFER_OVERFLOW).
            GetAdaptersAddresses(
                windows_sys::Win32::Networking::WinSock::AF_INET.0 as u32,
                flags,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            );
            if size == 0 {
                return None;
            }
            let mut buffer = vec![0u8; size as usize];
            let result = GetAdaptersAddresses(
                windows_sys::Win32::Networking::WinSock::AF_INET.0 as u32,
                flags,
                std::ptr::null_mut(),
                buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            );
            if result != 0 {
                return None;
            }
            // Walk the linked list: the first adapter with a gateway wins.
            let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
            while !current.is_null() {
                let adapter = &*current;
                if !adapter.FirstGatewayAddress.is_null() {
                    let len = adapter.PhysicalAddressLength as usize;
                    if len == 6 {
                        let bytes = &adapter.PhysicalAddress[..len];
                        return Some(
                            bytes
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(":"),
                        );
                    }
                }
                current = adapter.Next;
            }
            None
        }
    }
}
