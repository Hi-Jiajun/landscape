use std::{mem::MaybeUninit, os::raw::c_void};

pub(crate) mod land_dns_dispatcher {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/land_dns_dispatcher.skel.rs"));
}
use crate::bpf_error::LdEbpfResult;
use crate::landscape::pin_and_reuse_map;
use crate::maps::LandscapeMapPath;
use land_dns_dispatcher::*;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libc::SO_ATTACH_REUSEPORT_EBPF;
use libc::{SOL_SOCKET, setsockopt, socklen_t};
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

/// Which listener this program instance is being loaded for.
///
/// The value travels into the program's read-only data, so each reuseport group
/// carries the key namespace its own sockets were registered under. The plaintext
/// DNS listener and the DoH listener are both TCP, so this is the only thing that
/// can tell them apart - and without it they share one key and a TCP :53 query is
/// dispatched to the DoH socket, which the kernel refuses with EBADFD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerKind {
    Plaintext,
    Doh,
}

impl ListenerKind {
    /// Must match `DNS_LISTENER_KIND_*` in `land_dns_dispatcher.bpf.c`.
    ///
    /// The plaintext value covers both the UDP and the TCP plaintext listener: the
    /// program tells those two apart by protocol, which is what the key's own kind
    /// field needs two bits for. DoH needs the same number as its key kind, because
    /// the program compares this value against it - giving it a different number
    /// here silently routes the DoH group down the plaintext path, which selects a
    /// socket from another reuseport group and is refused with EBADFD.
    fn rodata_value(self) -> u8 {
        match self {
            ListenerKind::Plaintext => 0,
            ListenerKind::Doh => 2,
        }
    }
}

pub fn attach_reuseport_ebpf(
    paths: &LandscapeMapPath,
    sock_fd: i32,
    kind: ListenerKind,
) -> LdEbpfResult<()> {
    let mut open_object = MaybeUninit::zeroed();
    let builder = LandDnsDispatcherSkelBuilder::default();
    let mut open_skel =
        crate::bpf_ctx!(builder.open(&mut open_object), "dns_dispatcher open skeleton failed")?;

    if let Some(rodata) = open_skel.maps.rodata_data.as_deref_mut() {
        rodata.listener_kind = kind.rodata_value();
    }

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.dns_flow_socks, &paths.dns_flow_socks),
        "dns_dispatcher prepare dns_flow_socks failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &paths.flow_match_map),
        "dns_dispatcher prepare flow_match_map failed"
    )?;

    let skel = crate::bpf_ctx!(open_skel.load(), "dns_dispatcher load skeleton failed")?;

    let reuseport_dns_dispatcher = skel.progs.reuseport_dns_dispatcher;
    let prog_fd: i32 = reuseport_dns_dispatcher.as_fd().as_raw_fd();

    // tracing::info!("is_supported {:?}", reuseport_dns_dispatcher.prog_type().is_supported());
    // tracing::info!("{:?}", reuseport_dns_dispatcher.attach_type());

    unsafe {
        let ret = setsockopt(
            sock_fd,
            SOL_SOCKET,
            SO_ATTACH_REUSEPORT_EBPF,
            &prog_fd as *const _ as *const c_void,
            std::mem::size_of::<i32>() as socklen_t,
        );
        if ret != 0 {
            tracing::error!("{:?}", std::io::Error::last_os_error());
        } else {
            tracing::info!("attach DNS eBPF success");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ListenerKind;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// The listener-kind numbers the BPF program compares against.
    fn bpf_listener_kinds() -> BTreeMap<String, u8> {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/land_dns_dispatcher.bpf.c");
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let mut found = BTreeMap::new();
        for line in source.lines() {
            let Some(rest) = line.strip_prefix("#define DNS_LISTENER_KIND_") else { continue };
            let mut parts = rest.split_whitespace();
            let (Some(name), Some(value)) = (parts.next(), parts.next()) else { continue };
            if let Ok(value) = value.parse::<u8>() {
                found.insert(name.to_string(), value);
            }
        }
        found
    }

    /// The value this side writes into the program's read-only data has to be the
    /// number the program compares it against.
    ///
    /// These live in two languages and two files, and getting them out of step is
    /// silent: the program takes the wrong branch, asks the socket map for a key
    /// that belongs to another listener, and the kernel refuses the selection -
    /// which is exactly how DoH broke while the plaintext path kept working.
    #[test]
    fn the_rust_listener_kinds_match_the_program() {
        let kinds = bpf_listener_kinds();
        assert!(
            kinds.contains_key("DOH") && kinds.contains_key("PLAINTEXT"),
            "the program's listener kinds were not found: {kinds:?}"
        );

        assert_eq!(
            ListenerKind::Plaintext.rodata_value(),
            kinds["PLAINTEXT"],
            "the plaintext value must be the number the program tests for plaintext"
        );
        assert_eq!(
            ListenerKind::Doh.rodata_value(),
            kinds["DOH"],
            "the DoH value must be the number the program tests for DoH"
        );
        assert_ne!(
            ListenerKind::Plaintext.rodata_value(),
            ListenerKind::Doh.rodata_value(),
            "the two listeners are both TCP and can only be told apart by this value"
        );
    }
}
