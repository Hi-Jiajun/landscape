use libbpf_rs::{MapCore, MapFlags};

use crate::maps::LandscapeMapPath;

const DNS_FLOW_PROTO_UDP: u8 = 17;
const DNS_FLOW_PROTO_TCP: u8 = 6;

/// Which listener a socket belongs to. Must match `DNS_LISTENER_KIND_*` in
/// `land_dns_dispatcher.bpf.c`.
const DNS_LISTENER_KIND_PLAINTEXT_UDP: u8 = 0;
const DNS_LISTENER_KIND_PLAINTEXT_TCP: u8 = 1;
const DNS_LISTENER_KIND_DOH: u8 = 2;

/// Two bits of listener kind, so the three listeners a flow can have - plaintext
/// UDP, plaintext TCP and DoH - each get their own key.
///
/// It was one bit for UDP-versus-TCP, which left DoH and plaintext TCP sharing a
/// slot; one then overwrote the other and the dispatcher handed a TCP query to a
/// socket from another reuseport group, which the kernel refuses with EBADFD.
#[inline]
fn dns_flow_key(flow_id: u32, proto: u8) -> u32 {
    let kind = if proto == DNS_FLOW_PROTO_TCP {
        DNS_LISTENER_KIND_PLAINTEXT_TCP
    } else {
        DNS_LISTENER_KIND_PLAINTEXT_UDP
    };
    (flow_id << 2) | kind as u32
}

fn setting_dns_sock_map_inner<T: MapCore>(
    dns_flow_socks: &T,
    sock_fd: i32,
    flow_id: u32,
    proto: u8,
) {
    let key = dns_flow_key(flow_id, proto).to_le_bytes();
    let value = (sock_fd as u64).to_le_bytes();
    if let Err(e) = dns_flow_socks.update(&key, &value, MapFlags::ANY) {
        tracing::error!("update dns_flow_socks error: {e:?}");
    }
}

pub fn setting_dns_sock_map(paths: &LandscapeMapPath, sock_fd: i32, flow_id: u32) {
    let Ok(dns_flow_socks) = libbpf_rs::MapHandle::from_pinned_path(&paths.dns_flow_socks) else {
        tracing::warn!(
            "dns_flow_socks map not found at {:?}, skip dns sock map update",
            paths.dns_flow_socks
        );
        return;
    };

    setting_dns_sock_map_inner(&dns_flow_socks, sock_fd, flow_id, DNS_FLOW_PROTO_UDP);
}

pub fn setting_dns_sock_map_tcp(paths: &LandscapeMapPath, sock_fd: i32, flow_id: u32) {
    let Ok(dns_flow_socks) = libbpf_rs::MapHandle::from_pinned_path(&paths.dns_flow_socks) else {
        tracing::warn!(
            "dns_flow_socks map not found at {:?}, skip dns sock map update",
            paths.dns_flow_socks
        );
        return;
    };

    setting_dns_sock_map_inner(&dns_flow_socks, sock_fd, flow_id, DNS_FLOW_PROTO_TCP);
}

/// Register the DoH listener's socket for `flow_id`.
///
/// Its own key namespace, because DoH is TCP like the plaintext DNS listener and
/// the two are on different ports: sharing a key would make them overwrite each
/// other, and the dispatcher would then hand a TCP :53 connection to a socket in
/// another reuseport group - which the kernel refuses with EBADFD.
pub fn setting_doh_sock_map(paths: &LandscapeMapPath, sock_fd: i32, flow_id: u32) {
    let Ok(dns_flow_socks) = libbpf_rs::MapHandle::from_pinned_path(&paths.dns_flow_socks) else {
        tracing::warn!(
            "dns_flow_socks map not found at {:?}, skip DoH sock map update",
            paths.dns_flow_socks
        );
        return;
    };

    let key = ((flow_id << 2) | DNS_LISTENER_KIND_DOH as u32).to_le_bytes();
    let value = (sock_fd as u64).to_le_bytes();
    if let Err(e) = dns_flow_socks.update(&key, &value, MapFlags::ANY) {
        tracing::error!("update DoH dns_flow_socks entry error: {e:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libbpf_rs::{MapHandle, MapType};
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    /// Creates an unnamed temporary SOCKMAP mirroring the `dns_flow_socks`
    /// layout (key u32, value u64, 512 entries). Returns `None` (skip) when
    /// the environment cannot create BPF maps, e.g. no CAP_BPF.
    fn create_test_sockmap() -> Option<MapHandle> {
        #[allow(clippy::needless_update)]
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
            ..Default::default()
        };
        match MapHandle::create(MapType::Sockmap, None::<String>, 4, 8, 512, &opts) {
            Ok(map) => Some(map),
            Err(e) => {
                eprintln!("skipping sockmap test: cannot create BPF sockmap: {e:?}");
                None
            }
        }
    }

    fn bound_udp_socket() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0").expect("bind udp socket")
    }

    fn sockmap_value(map: &MapHandle, key: [u8; 4]) -> Option<u64> {
        map.lookup(&key, MapFlags::ANY)
            .expect("sockmap lookup")
            .map(|value| u64::from_le_bytes(value[..8].try_into().unwrap()))
    }

    /// Sanity: the proto bit is packed into the lowest key bit.
    #[test]
    fn dns_flow_key_packs_the_listener_kind() {
        // Two bits of kind, so plaintext UDP, plaintext TCP and DoH are three
        // distinct keys for one flow - the collision that made TCP unusable was
        // plaintext TCP and DoH sharing a slot.
        assert_eq!(dns_flow_key(5, DNS_FLOW_PROTO_UDP), 20);
        assert_eq!(dns_flow_key(5, DNS_FLOW_PROTO_TCP), 21);
        assert_ne!(dns_flow_key(5, DNS_FLOW_PROTO_UDP), dns_flow_key(5, DNS_FLOW_PROTO_TCP));

        let doh = (5u32 << 2) | DNS_LISTENER_KIND_DOH as u32;
        assert_ne!(doh, dns_flow_key(5, DNS_FLOW_PROTO_TCP), "DoH must not share TCP's key");
        assert_ne!(doh, dns_flow_key(5, DNS_FLOW_PROTO_UDP));

        // ... and the keys stay inside the sockmap, whose key is an index: the
        // kernel refuses one at or beyond max_entries with -E2BIG.
        let highest = (255u32 << 2) | DNS_LISTENER_KIND_DOH as u32;
        assert!(highest < 2048, "flow id 255 must still fit the sockmap: {highest}");
    }

    /// Guards the kernel behavior the no-deregistration design relies on:
    /// a sockmap entry is removed automatically once its socket is closed
    /// (socket teardown unlinks it from the sockmap, via deferred RCU work),
    /// so closing the listener socket cleans up `dns_flow_socks` on its own.
    #[test]
    fn sockmap_entry_auto_removed_on_socket_close() {
        let Some(map) = create_test_sockmap() else { return };
        let sock = bound_udp_socket();
        let flow_id = 21;
        let key = dns_flow_key(flow_id, DNS_FLOW_PROTO_UDP).to_le_bytes();

        setting_dns_sock_map_inner(&map, sock.as_raw_fd(), flow_id, DNS_FLOW_PROTO_UDP);
        // guard against a vacuous pass: the registration must have taken effect
        assert!(sockmap_value(&map, key).is_some());

        drop(sock); // close the only fd owning this socket

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match sockmap_value(&map, key) {
                None => break, // auto-removed by the kernel
                Some(_) if Instant::now() >= deadline => {
                    panic!("sockmap entry still present 5s after socket close")
                }
                Some(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }
}
