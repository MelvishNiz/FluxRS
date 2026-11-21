//! Proxyless capture on Linux with iptables `REDIRECT`.
//!
//! Outgoing TCP 80/443 is redirected to the local proxy; the proxy reads the
//! real destination with `SO_ORIGINAL_DST`. The proxy's own upstream sockets
//! bind source ports in [`OWN_PORTS`] (outside the default ephemeral range
//! 32768-60999), and the rules skip those ports, so there is no loop.
//! QUIC (UDP 443) and new IPv6 connections to 80/443 are rejected so clients
//! fall back to TCP over IPv4.
//!
//! Rules live in dedicated chains (`FLUXRS*`) and are removed on stop.

use std::ops::RangeInclusive;

pub const OWN_PORTS: RangeInclusive<u16> = 61000..=61999;

const CHAIN_NAT: &str = "FLUXRS";
const CHAIN_FILTER: &str = "FLUXRS_FILTER";

/// Shell script installing the redirect rules (idempotent).
/// `only_dest` limits redirection to one destination (used by tests).
pub fn install_script(proxy_port: u16, only_dest: Option<&str>) -> String {
    let (lo, hi) = (OWN_PORTS.start(), OWN_PORTS.end());
    let dest = only_dest.map(|d| format!(" -d {d}")).unwrap_or_default();
    format!(
        r#"set -e
iptables -t nat -N {CHAIN_NAT} 2>/dev/null || iptables -t nat -F {CHAIN_NAT}
iptables -t nat -A {CHAIN_NAT} -d 127.0.0.0/8 -j RETURN
iptables -t nat -A {CHAIN_NAT} -p tcp --sport {lo}:{hi} -j RETURN
iptables -t nat -A {CHAIN_NAT} -p tcp{dest} -m multiport --dports 80,443 -j REDIRECT --to-ports {proxy_port}
iptables -t nat -C OUTPUT -j {CHAIN_NAT} 2>/dev/null || iptables -t nat -I OUTPUT -j {CHAIN_NAT}
iptables -N {CHAIN_FILTER} 2>/dev/null || iptables -F {CHAIN_FILTER}
iptables -A {CHAIN_FILTER} -p udp{dest} --dport 443 -j REJECT
iptables -C OUTPUT -j {CHAIN_FILTER} 2>/dev/null || iptables -I OUTPUT -j {CHAIN_FILTER}
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -N {CHAIN_FILTER} 2>/dev/null || ip6tables -F {CHAIN_FILTER}
  ip6tables -A {CHAIN_FILTER} -d ::1 -j RETURN
  ip6tables -A {CHAIN_FILTER} -p tcp --sport {lo}:{hi} -j RETURN
  ip6tables -A {CHAIN_FILTER} -p tcp -m multiport --dports 80,443 -j REJECT --reject-with tcp-reset
  ip6tables -A {CHAIN_FILTER} -p udp --dport 443 -j REJECT
  ip6tables -C OUTPUT -j {CHAIN_FILTER} 2>/dev/null || ip6tables -I OUTPUT -j {CHAIN_FILTER}
fi
"#
    )
}

/// Shell script removing every rule installed by [`install_script`].
pub fn remove_script() -> String {
    format!(
        r#"iptables -t nat -D OUTPUT -j {CHAIN_NAT} 2>/dev/null
iptables -t nat -F {CHAIN_NAT} 2>/dev/null
iptables -t nat -X {CHAIN_NAT} 2>/dev/null
iptables -D OUTPUT -j {CHAIN_FILTER} 2>/dev/null
iptables -F {CHAIN_FILTER} 2>/dev/null
iptables -X {CHAIN_FILTER} 2>/dev/null
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -D OUTPUT -j {CHAIN_FILTER} 2>/dev/null
  ip6tables -F {CHAIN_FILTER} 2>/dev/null
  ip6tables -X {CHAIN_FILTER} 2>/dev/null
fi
true
"#
    )
}

#[cfg(target_os = "linux")]
pub use imp::*;

#[cfg(target_os = "linux")]
mod imp {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::fd::AsRawFd;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};

    static ACTIVE: AtomicBool = AtomicBool::new(false);

    /// Remove the rules if this process installed them (for panic hooks).
    pub fn emergency_cleanup() {
        if ACTIVE.swap(false, Ordering::SeqCst) {
            let _ = run_privileged(&super::remove_script());
        }
    }

    /// Remove any FluxRS rules, e.g. left over after a crash (`fluxrs --cleanup`).
    pub fn cleanup_all() -> Result<(), String> {
        ACTIVE.store(false, Ordering::SeqCst);
        run_privileged(&super::remove_script())
    }

    fn is_root() -> bool {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    /// Run a shell script as root: directly when already root, otherwise
    /// through `pkexec` (graphical password prompt on Ubuntu desktop).
    pub fn run_privileged(script: &str) -> Result<(), String> {
        let output = if is_root() {
            Command::new("sh").arg("-c").arg(script).output()
        } else {
            Command::new("pkexec")
                .arg("sh")
                .arg("-c")
                .arg(script)
                .output()
        }
        .map_err(|e| format!("cannot run iptables (is pkexec installed?): {e}"))?;
        if output.status.success() {
            Ok(())
        } else {
            let code = output.status.code().unwrap_or(-1);
            let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(match code {
                126 | 127 if !is_root() => "Administrator authorisation was cancelled".into(),
                _ => format!("iptables setup failed ({code}): {err}"),
            })
        }
    }

    /// Original destination of a REDIRECTed IPv4 connection.
    pub fn original_dst(stream: &tokio::net::TcpStream) -> std::io::Result<SocketAddrV4> {
        const SO_ORIGINAL_DST: libc::c_int = 80;
        let fd = stream.as_raw_fd();
        // SAFETY: zeroed sockaddr_in is valid; buffer and length match.
        unsafe {
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let rc = libc::getsockopt(
                fd,
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            );
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
                u16::from_be(addr.sin_port),
            ))
        }
    }

    /// Installed redirect rules; removed on drop.
    pub struct Redirect {
        active: bool,
    }

    impl Redirect {
        pub fn install(proxy_port: u16, only_dest: Option<&str>) -> Result<Redirect, String> {
            run_privileged(&super::install_script(proxy_port, only_dest))?;
            ACTIVE.store(true, Ordering::SeqCst);
            Ok(Redirect { active: true })
        }

        pub fn remove(&mut self) {
            if std::mem::take(&mut self.active) {
                ACTIVE.store(false, Ordering::SeqCst);
                let _ = run_privileged(&super::remove_script());
            }
        }
    }

    impl Drop for Redirect {
        fn drop(&mut self) {
            self.remove();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_reference_port_and_range() {
        let s = install_script(44344, None);
        assert!(s.contains("REDIRECT --to-ports 44344"));
        assert!(s.contains("--sport 61000:61999 -j RETURN"));
        assert!(s.contains("--dport 443 -j REJECT"));
        assert!(!s.contains(" -d 10."));
        let t = install_script(1, Some("10.9.0.1"));
        assert!(t.contains("-p tcp -d 10.9.0.1 -m multiport"));
        let r = remove_script();
        assert!(r.contains("-X FLUXRS"));
        // ephemeral range on Linux defaults to 32768-60999
        assert!(*OWN_PORTS.start() > 60999);
    }
}
