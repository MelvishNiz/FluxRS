//! Packet reflection logic used by proxyless (transparent) capture.
//!
//! Outbound packets `A:p -> S:443` are rewritten to `S:p -> A:PROXY` and
//! re-injected as inbound, so the local proxy accepts a connection whose
//! peer address is the real server `S`. Replies `A:PROXY -> S:p` are turned
//! back into `S:443 -> A:p`. The original destination port is remembered in
//! a flow table keyed by `(S, p)`.
//!
//! This module is pure (no OS calls) so it is unit tested on every platform.
//! The Windows WinDivert driver loop lives in `divert.rs`.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const FLOW_IDLE: Duration = Duration::from_secs(15 * 60);
const OWNED_GRACE: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Re-inject unchanged.
    Pass,
    /// Packet was rewritten (recompute checksums, use the new direction).
    Modified,
    /// Drop the packet.
    Drop,
}

#[derive(Debug)]
pub struct NatTable {
    proxy_port: u16,
    ports: Vec<u16>,
    flows: Mutex<HashMap<(Ipv4Addr, u16), (u16, Instant)>>,
    owned: Mutex<HashMap<u16, Option<Instant>>>,
    ops: Mutex<u64>,
}

/// Keeps a local port marked as "owned by the proxy" while alive.
#[derive(Debug)]
pub struct PortGuard {
    nat: Arc<NatTable>,
    port: u16,
}

impl Drop for PortGuard {
    fn drop(&mut self) {
        // Late packets (FIN/ACK, TIME_WAIT) must still bypass redirection.
        if let Some(v) = self.nat.owned.lock().get_mut(&self.port) {
            *v = Some(Instant::now() + OWNED_GRACE);
        }
    }
}

impl NatTable {
    pub fn new(proxy_port: u16, ports: Vec<u16>) -> Arc<Self> {
        Arc::new(NatTable {
            proxy_port,
            ports,
            flows: Mutex::new(HashMap::new()),
            owned: Mutex::new(HashMap::new()),
            ops: Mutex::new(0),
        })
    }

    pub fn proxy_port(&self) -> u16 {
        self.proxy_port
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    /// WinDivert filter capturing the packets this table handles.
    pub fn divert_filter(&self) -> String {
        let dst: Vec<String> = self
            .ports
            .iter()
            .map(|p| format!("tcp.DstPort == {p}"))
            .collect();
        format!(
            "outbound and !loopback and ((tcp and ({} or tcp.SrcPort == {})) or (udp and udp.DstPort == 443))",
            dst.join(" or "),
            self.proxy_port
        )
    }

    /// Original destination port for a redirected connection whose peer
    /// (as seen by the proxy) is `remote:port`.
    pub fn original_port(&self, remote: Ipv4Addr, port: u16) -> Option<u16> {
        self.flows.lock().get(&(remote, port)).map(|(p, _)| *p)
    }

    pub fn register_owned_port(self: &Arc<Self>, port: u16) -> PortGuard {
        self.owned.lock().insert(port, None);
        PortGuard {
            nat: self.clone(),
            port,
        }
    }

    fn is_owned(&self, port: u16) -> bool {
        let mut owned = self.owned.lock();
        match owned.get(&port) {
            None => false,
            Some(None) => true,
            Some(Some(exp)) if *exp > Instant::now() => true,
            Some(Some(_)) => {
                owned.remove(&port);
                false
            }
        }
    }

    fn maybe_prune(&self) {
        let mut ops = self.ops.lock();
        *ops += 1;
        if *ops % 4096 != 0 {
            return;
        }
        drop(ops);
        let now = Instant::now();
        self.flows
            .lock()
            .retain(|_, (_, seen)| now.duration_since(*seen) < FLOW_IDLE);
        self.owned
            .lock()
            .retain(|_, exp| exp.is_none_or(|e| e > now));
    }

    /// Process one captured packet in place.
    pub fn process(&self, pkt: &mut [u8], outbound: &mut bool) -> Verdict {
        if pkt.is_empty() || !*outbound {
            return Verdict::Pass;
        }
        match pkt[0] >> 4 {
            4 => self.process_v4(pkt, outbound),
            6 => self.process_v6(pkt),
            _ => Verdict::Pass,
        }
    }

    fn process_v6(&self, pkt: &[u8]) -> Verdict {
        // IPv6 is not redirected: drop new connections to captured ports so
        // clients fall back to IPv4 (happy eyeballs), and drop QUIC.
        if pkt.len() < 44 {
            return Verdict::Pass;
        }
        let next = pkt[6];
        let dst_port = u16::from_be_bytes([pkt[42], pkt[43]]);
        match next {
            6 if self.ports.contains(&dst_port) => Verdict::Drop,
            17 if dst_port == 443 => Verdict::Drop,
            _ => Verdict::Pass,
        }
    }

    fn process_v4(&self, pkt: &mut [u8], outbound: &mut bool) -> Verdict {
        if pkt.len() < 20 {
            return Verdict::Pass;
        }
        let ihl = ((pkt[0] & 0x0f) as usize) * 4;
        let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if ihl < 20 || pkt.len() < ihl + 4 || total > pkt.len() {
            return Verdict::Pass;
        }
        // Fragments (offset != 0) carry no L4 header.
        let frag_offset = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x1fff;
        if frag_offset != 0 {
            return Verdict::Pass;
        }
        let proto = pkt[9];
        let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
        let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
        if proto == 17 {
            // Block QUIC / HTTP3 so browsers use TCP + TLS.
            return if dst_port == 443 {
                Verdict::Drop
            } else {
                Verdict::Pass
            };
        }
        if proto != 6 || pkt.len() < ihl + 20 {
            return Verdict::Pass;
        }
        let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

        if src_port == self.proxy_port {
            // Proxy -> client reply: restore the original server port.
            let orig = {
                let mut flows = self.flows.lock();
                match flows.get_mut(&(dst, dst_port)) {
                    Some(entry) => {
                        entry.1 = Instant::now();
                        entry.0
                    }
                    None => return Verdict::Drop,
                }
            };
            pkt[ihl..ihl + 2].copy_from_slice(&orig.to_be_bytes());
            swap_addrs(pkt);
            *outbound = false;
            return Verdict::Modified;
        }

        if self.ports.contains(&dst_port) && !self.is_owned(src_port) {
            // Client -> server: reflect into the local proxy.
            self.flows
                .lock()
                .insert((dst, src_port), (dst_port, Instant::now()));
            self.maybe_prune();
            pkt[ihl + 2..ihl + 4].copy_from_slice(&self.proxy_port.to_be_bytes());
            swap_addrs(pkt);
            *outbound = false;
            let _ = src;
            return Verdict::Modified;
        }
        Verdict::Pass
    }
}

fn swap_addrs(pkt: &mut [u8]) {
    let mut s = [0u8; 4];
    s.copy_from_slice(&pkt[12..16]);
    pkt.copy_within(16..20, 12);
    pkt[16..20].copy_from_slice(&s);
}

/// Recompute IPv4 header and TCP checksums (used by tests and as a fallback).
pub fn recompute_checksums_v4(pkt: &mut [u8]) {
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    pkt[10] = 0;
    pkt[11] = 0;
    let c = checksum(&[&pkt[..ihl]], 0);
    pkt[10..12].copy_from_slice(&c.to_be_bytes());
    if pkt[9] == 6 && total >= ihl + 20 {
        pkt[ihl + 16] = 0;
        pkt[ihl + 17] = 0;
        let tcp_len = (total - ihl) as u32;
        let mut pseudo = [0u8; 12];
        pseudo[..8].copy_from_slice(&pkt[12..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        let c = checksum(&[&pseudo, &pkt[ihl..total]], 0);
        pkt[ihl + 16..ihl + 18].copy_from_slice(&c.to_be_bytes());
    }
}

fn checksum(parts: &[&[u8]], init: u32) -> u16 {
    let mut sum = init;
    for part in parts {
        let mut chunks = part.chunks_exact(2);
        for c in &mut chunks {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        if let [b] = chunks.remainder() {
            sum += (*b as u32) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_v4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[32] = 0x50;
        p[33] = 0x02; // SYN
        recompute_checksums_v4(&mut p);
        p
    }

    fn ports(p: &[u8]) -> (u16, u16) {
        (
            u16::from_be_bytes([p[20], p[21]]),
            u16::from_be_bytes([p[22], p[23]]),
        )
    }

    #[test]
    fn reflects_client_and_reply() {
        let nat = NatTable::new(34567, vec![80, 443]);
        let client = [192, 168, 1, 10];
        let server = [93, 184, 216, 34];

        let mut p = tcp_v4(client, 50000, server, 443);
        let mut out = true;
        assert_eq!(nat.process(&mut p, &mut out), Verdict::Modified);
        assert!(!out);
        assert_eq!(&p[12..16], &server);
        assert_eq!(&p[16..20], &client);
        assert_eq!(ports(&p), (50000, 34567));
        assert_eq!(nat.original_port(Ipv4Addr::from(server), 50000), Some(443));

        // proxy reply A:34567 -> S:50000
        let mut r = tcp_v4(client, 34567, server, 50000);
        let mut out = true;
        assert_eq!(nat.process(&mut r, &mut out), Verdict::Modified);
        assert!(!out);
        assert_eq!(&r[12..16], &server);
        assert_eq!(&r[16..20], &client);
        assert_eq!(ports(&r), (443, 50000));

        // checksum helper produces a valid header checksum
        recompute_checksums_v4(&mut r);
        assert_eq!(checksum(&[&r[..20]], 0), 0);
    }

    #[test]
    fn owned_ports_and_unknown_replies() {
        let nat = NatTable::new(34567, vec![80, 443]);
        let guard = nat.register_owned_port(40000);
        let mut p = tcp_v4([10, 0, 0, 2], 40000, [1, 1, 1, 1], 443);
        let mut out = true;
        assert_eq!(nat.process(&mut p, &mut out), Verdict::Pass);
        drop(guard);
        // still owned during grace period
        assert_eq!(nat.process(&mut p, &mut out), Verdict::Pass);

        let mut stray = tcp_v4([10, 0, 0, 2], 34567, [1, 1, 1, 1], 1234);
        assert_eq!(nat.process(&mut stray, &mut out), Verdict::Drop);

        let mut other = tcp_v4([10, 0, 0, 2], 5555, [1, 1, 1, 1], 22);
        assert_eq!(nat.process(&mut other, &mut out), Verdict::Pass);

        let mut inbound = false;
        let mut p2 = tcp_v4([10, 0, 0, 2], 5555, [1, 1, 1, 1], 443);
        assert_eq!(nat.process(&mut p2, &mut inbound), Verdict::Pass);
    }

    #[test]
    fn quic_and_ipv6_dropped() {
        let nat = NatTable::new(34567, vec![80, 443]);
        let mut udp = tcp_v4([10, 0, 0, 2], 5555, [1, 1, 1, 1], 443);
        udp[9] = 17;
        let mut out = true;
        assert_eq!(nat.process(&mut udp, &mut out), Verdict::Drop);

        let mut v6 = vec![0u8; 60];
        v6[0] = 0x60;
        v6[6] = 6;
        v6[42..44].copy_from_slice(&443u16.to_be_bytes());
        assert_eq!(nat.process(&mut v6, &mut out), Verdict::Drop);
        v6[42..44].copy_from_slice(&22u16.to_be_bytes());
        assert_eq!(nat.process(&mut v6, &mut out), Verdict::Pass);
    }

    #[test]
    fn filter_string() {
        let nat = NatTable::new(34567, vec![80, 443]);
        assert_eq!(
            nat.divert_filter(),
            "outbound and !loopback and ((tcp and (tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.SrcPort == 34567)) or (udp and udp.DstPort == 443))"
        );
    }
}
