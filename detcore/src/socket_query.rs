//! Certificates for route-socket operations that cannot mutate the other socket domains.
//!
//! This is not a readiness source. Call at the serialized physical attempt: guest inputs
//! must remain stable until injection. Unknown provenance, requests, or memory fail closed.
//! In particular, an explicit kernel destination is required on every send; a previous
//! connect does not establish trusted default-peer state here.

use std::mem::size_of;

use reverie::Guest;
use reverie::syscalls::linux_abi::{Mmsghdr, Msghdr};
use reverie::syscalls::{AddrMut, MemoryAccess, Syscall, SyscallInfo, Sysno};

use crate::Detcore;
use crate::record_or_replay::RecordOrReplay;

const MAX_DATAGRAM: usize = 4096;
const MAX_TOTAL_BYTES: usize = 64 * 1024;
const MAX_MESSAGES: usize = 32;
const MAX_IOVECS: usize = 64;
const MAX_TOTAL_IOVECS: usize = 256;
const NLMSG_HEADER: usize = 16;
const RTM_GETLINK: u16 = 18;
const RTM_GETADDR: u16 = 22;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;

/// Creation alone has no effect on the Unix or TCP socket domains.
pub(crate) fn route_creation(family: i32, kind: i32, protocol: i32) -> bool {
    family == libc::AF_NETLINK
        && protocol == libc::NETLINK_ROUTE
        && matches!(
            kind & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK),
            libc::SOCK_RAW | libc::SOCK_DGRAM
        )
}

/// Inspect only the actual attempt, without changing the syscall, result, or OFD.
pub(crate) fn route_attempt<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &G,
    call: Syscall,
) -> bool {
    let (number, args) = call.into_parts();
    if !guest
        .thread_state()
        .with_detfd(args.arg0 as i32, |file| file.is_netlink_route())
        .unwrap_or(false)
    {
        return false;
    }
    match number {
        Sysno::read
        | Sysno::readv
        | Sysno::recvfrom
        | Sysno::recvmsg
        | Sysno::recvmmsg
        | Sysno::bind
        | Sysno::connect
        | Sysno::shutdown => true,
        Sysno::setsockopt => local_option(args.arg1 as i32, args.arg2 as i32),
        Sysno::sendto | Sysno::sendmsg | Sysno::sendmmsg => {
            let memory = guest.memory();
            let mut budget = Budget::new();
            let mut payload = [0u8; MAX_DATAGRAM];
            let address = args.arg1;
            match number {
                Sysno::sendto => {
                    let (length, destination, destination_length) =
                        (args.arg2, args.arg4, args.arg5);
                    send_flags(args.arg3 as i32)
                        && kernel_destination(&memory, destination, destination_length)
                        && length <= payload.len()
                        && budget.charge_bytes(length)
                        && read_exact(&memory, address, &mut payload[..length])
                        && dump_datagram(&payload[..length])
                }
                Sysno::sendmsg => {
                    send_flags(args.arg2 as i32)
                        && read_record::<Msghdr>(&memory, address).is_some_and(|header| {
                            message(&memory, &header, &mut payload, &mut budget)
                        })
                }
                Sysno::sendmmsg => {
                    let count = args.arg2;
                    if !send_flags(args.arg3 as i32)
                        || !(1..=MAX_MESSAGES).contains(&count)
                        || array_end::<Mmsghdr>(address, count).is_none()
                    {
                        return false;
                    }
                    (0..count).all(|index| {
                        // The full array range was checked, including multiplication.
                        let at = address + index * size_of::<Mmsghdr>();
                        read_record::<Mmsghdr>(&memory, at).is_some_and(|header| {
                            // Each batch entry is a separate datagram, never a stream prefix.
                            message(&memory, &header.msg_hdr, &mut payload, &mut budget)
                        })
                    })
                }
                _ => false,
            }
        }
        // write/writev have no explicit destination. No inferred connected peer.
        _ => false,
    }
}

fn local_option(level: i32, option: i32) -> bool {
    (level == libc::SOL_SOCKET
        && matches!(
            option,
            libc::SO_SNDBUF
                | libc::SO_RCVBUF
                | libc::SO_SNDLOWAT
                | libc::SO_RCVLOWAT
                | libc::SO_SNDTIMEO
                | libc::SO_RCVTIMEO
        ))
        || (level == libc::SOL_NETLINK
            && matches!(
                option,
                libc::NETLINK_EXT_ACK | libc::NETLINK_CAP_ACK | libc::NETLINK_GET_STRICT_CHK
            ))
}

fn send_flags(flags: i32) -> bool {
    flags & !(libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) == 0
}

struct Budget {
    bytes: usize,
    iovecs: usize,
}

impl Budget {
    fn new() -> Self {
        Self {
            bytes: MAX_TOTAL_BYTES,
            iovecs: MAX_TOTAL_IOVECS,
        }
    }

    fn charge_bytes(&mut self, amount: usize) -> bool {
        let Some(remaining) = self.bytes.checked_sub(amount) else {
            return false;
        };
        self.bytes = remaining;
        true
    }

    fn charge_iovecs(&mut self, count: usize) -> bool {
        if !(1..=MAX_IOVECS).contains(&count) {
            return false;
        }
        let Some(remaining) = self.iovecs.checked_sub(count) else {
            return false;
        };
        self.iovecs = remaining;
        true
    }
}

fn array_end<V>(address: usize, count: usize) -> Option<usize> {
    if address == 0 {
        return None;
    }
    address.checked_add(count.checked_mul(size_of::<V>())?)
}

fn read_record<V: Copy>(memory: &impl MemoryAccess, address: usize) -> Option<V> {
    array_end::<V>(address, 1)?;
    memory.read_value(AddrMut::<V>::from_raw(address)?).ok()
}

fn read_exact(memory: &impl MemoryAccess, address: usize, bytes: &mut [u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    if address.checked_add(bytes.len()).is_none() {
        return false;
    }
    let Some(address) = AddrMut::<u8>::from_raw(address) else {
        return false;
    };
    crate::syscalls::read_guest_exact(memory, address, bytes).is_ok()
}

fn kernel_destination(memory: &impl MemoryAccess, address: usize, length: usize) -> bool {
    let mut bytes = [0u8; 12];
    length == bytes.len()
        && read_exact(memory, address, &mut bytes)
        && kernel_address(&bytes)
}

fn kernel_address(bytes: &[u8]) -> bool {
    bytes.len() == 12
        && u16::from_ne_bytes([bytes[0], bytes[1]]) as i32 == libc::AF_NETLINK
        && bytes[2..].iter().all(|byte| *byte == 0)
}

fn message(
    memory: &impl MemoryAccess,
    header: &Msghdr,
    payload: &mut [u8; MAX_DATAGRAM],
    budget: &mut Budget,
) -> bool {
    // msg_flags is an output field for recvmsg, ignored by Linux sendmsg. The
    // syscall's flags were checked above. Nonempty control is never authorized.
    if header.msg_controllen != 0
        || !kernel_destination(memory, header.msg_name as usize, header.msg_namelen as usize)
        || !budget.charge_iovecs(header.msg_iovlen)
        || array_end::<libc::iovec>(header.msg_iov as usize, header.msg_iovlen).is_none()
    {
        return false;
    }
    let mut length = 0usize;
    for index in 0..header.msg_iovlen {
        let address = header.msg_iov as usize + index * size_of::<libc::iovec>();
        let Some(iovec) = read_record::<libc::iovec>(memory, address) else {
            return false;
        };
        let Some(end) = length.checked_add(iovec.iov_len) else {
            return false;
        };
        if end > payload.len()
            || !budget.charge_bytes(iovec.iov_len)
            || !read_exact(memory, iovec.iov_base as usize, &mut payload[length..end])
        {
            return false;
        }
        length = end;
    }
    dump_datagram(&payload[..length])
}

/// Only unfiltered GETLINK/GETADDR dumps, with no attributes or modifiers.
/// glibc uses a four-byte padded rtgenmsg (20 bytes with nlmsghdr), not always
/// the larger ifinfomsg/ifaddrmsg. A one-byte rtgenmsg plus wire alignment is
/// equivalent; all unused body and alignment bytes must be zero.
fn dump_datagram(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_DATAGRAM {
        return false;
    }
    let mut offset = 0usize;
    while offset < bytes.len() {
        let message = &bytes[offset..];
        if message.len() < NLMSG_HEADER {
            return false;
        }
        let length = u32::from_ne_bytes(message[..4].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(message[4..6].try_into().unwrap());
        let flags = u16::from_ne_bytes(message[6..8].try_into().unwrap());
        if length < NLMSG_HEADER + 1
            || length > message.len()
            || flags & (NLM_F_REQUEST | NLM_F_DUMP) != NLM_F_REQUEST | NLM_F_DUMP
            || flags & !(NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK) != 0
        {
            return false;
        }
        let body = &message[NLMSG_HEADER..length];
        let family = i32::from(body[0]);
        let body_valid = match kind {
            RTM_GETLINK => {
                matches!(body.len(), 1 | 4 | 16)
                    && matches!(family, libc::AF_UNSPEC | libc::AF_PACKET)
            }
            RTM_GETADDR => {
                matches!(body.len(), 1 | 4 | 8)
                    && matches!(family, libc::AF_UNSPEC | libc::AF_INET | libc::AF_INET6)
            }
            _ => false,
        };
        if !body_valid || body[1..].iter().any(|byte| *byte != 0) {
            return false;
        }
        let Some(aligned) = length.checked_add(3).map(|length| length & !3) else {
            return false;
        };
        if aligned > message.len() || message[length..aligned].iter().any(|byte| *byte != 0) {
            return false;
        }
        let Some(next) = offset.checked_add(aligned) else {
            return false;
        };
        offset = next;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(kind: u16, family: i32, body_length: usize) -> Vec<u8> {
        let length = NLMSG_HEADER + body_length;
        let mut bytes = vec![0; (length + 3) & !3];
        bytes[..4].copy_from_slice(&(length as u32).to_ne_bytes());
        bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
        bytes[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        bytes[8..12].copy_from_slice(&123u32.to_ne_bytes());
        bytes[12..16].copy_from_slice(&456u32.to_ne_bytes());
        bytes[16] = family as u8;
        bytes
    }

    #[test]
    fn creation_is_exact_route_raw_or_datagram() {
        for kind in [libc::SOCK_RAW, libc::SOCK_DGRAM] {
            assert!(route_creation(libc::AF_NETLINK, kind, libc::NETLINK_ROUTE));
            assert!(route_creation(
                libc::AF_NETLINK,
                kind | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_ROUTE,
            ));
            assert!(!route_creation(libc::AF_UNIX, kind, libc::NETLINK_ROUTE));
            assert!(!route_creation(libc::AF_NETLINK, kind, libc::NETLINK_USERSOCK));
            assert!(!route_creation(libc::AF_NETLINK, kind | 0x1000, libc::NETLINK_ROUTE));
        }
        assert!(!route_creation(libc::AF_NETLINK, libc::SOCK_STREAM, libc::NETLINK_ROUTE));
    }

    #[test]
    fn glibc_minimal_and_full_dump_bodies() {
        for (kind, family, full) in [
            (RTM_GETLINK, libc::AF_UNSPEC, 16),
            (RTM_GETLINK, libc::AF_PACKET, 16),
            (RTM_GETADDR, libc::AF_UNSPEC, 8),
            (RTM_GETADDR, libc::AF_INET, 8),
            (RTM_GETADDR, libc::AF_INET6, 8),
        ] {
            for body_length in [1, 4, full] {
                let mut bytes = request(kind, family, body_length);
                assert!(dump_datagram(&bytes));
                bytes[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK).to_ne_bytes());
                assert!(dump_datagram(&bytes));
            }
        }
    }

    #[test]
    fn every_message_must_be_a_query() {
        let mut bytes = request(RTM_GETLINK, libc::AF_UNSPEC, 4);
        bytes.extend(request(RTM_GETADDR, libc::AF_INET, 8));
        assert!(dump_datagram(&bytes));
        // RTM_NEWADDR in the second message must invalidate the safe prefix.
        bytes[24..26].copy_from_slice(&20u16.to_ne_bytes());
        assert!(!dump_datagram(&bytes));
        for kind in [16, 17, 19, 20, 21, 26, u16::MAX] {
            assert!(!dump_datagram(&request(kind, libc::AF_UNSPEC, 4)));
        }
    }

    #[test]
    fn unknown_or_incomplete_dump_flags_fail_closed() {
        for flags in [0, NLM_F_REQUEST, 0x101, 0x201, 0x309, 0x311, 0x701, 0xb01, 0x8301] {
            let mut bytes = request(RTM_GETLINK, libc::AF_UNSPEC, 4);
            bytes[6..8].copy_from_slice(&flags.to_ne_bytes());
            assert!(!dump_datagram(&bytes));
        }
        assert!(send_flags(0));
        assert!(send_flags(libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL));
        assert!(!send_flags(libc::MSG_MORE));
        assert!(!send_flags(libc::MSG_OOB));
        assert!(!send_flags(-1));
    }

    #[test]
    fn malformed_lengths_suffixes_and_alignment_fail_closed() {
        let valid = request(RTM_GETLINK, libc::AF_UNSPEC, 4);
        for length in [0u32, 15, 16, 18, 19, 21, u32::MAX] {
            let mut bytes = valid.clone();
            bytes[..4].copy_from_slice(&length.to_ne_bytes());
            assert!(!dump_datagram(&bytes));
        }
        for length in 0..valid.len() {
            assert!(!dump_datagram(&valid[..length]));
        }
        for suffix in 1..NLMSG_HEADER {
            let mut bytes = valid.clone();
            bytes.resize(bytes.len() + suffix, 0);
            assert!(!dump_datagram(&bytes));
        }
        let mut aligned = request(RTM_GETLINK, libc::AF_UNSPEC, 1);
        assert!(dump_datagram(&aligned));
        assert!(!dump_datagram(&aligned[..19]));
        aligned[19] = 1;
        assert!(!dump_datagram(&aligned));
    }

    #[test]
    fn attributes_filters_and_unknown_families_are_not_dump_forms() {
        for (kind, full) in [(RTM_GETLINK, 16), (RTM_GETADDR, 8)] {
            let mut bytes = request(kind, libc::AF_UNSPEC, full);
            bytes[NLMSG_HEADER + 1] = 1;
            assert!(!dump_datagram(&bytes));
            assert!(!dump_datagram(&request(kind, libc::AF_UNIX, full)));
            assert!(!dump_datagram(&request(kind, libc::AF_UNSPEC, full + 4)));
            let mut minimal = request(kind, libc::AF_UNSPEC, 4);
            minimal[19] = 1;
            assert!(!dump_datagram(&minimal));
        }
    }

    #[test]
    fn only_explicit_kernel_unicast_destination() {
        let mut bytes = [0u8; 12];
        bytes[..2].copy_from_slice(&(libc::AF_NETLINK as u16).to_ne_bytes());
        assert!(kernel_address(&bytes));
        for offset in [2, 4, 8] {
            bytes[offset] = 1;
            assert!(!kernel_address(&bytes));
            bytes[offset] = 0;
        }
        assert!(!kernel_address(&bytes[..11]));
        let mut oversized = bytes.to_vec();
        oversized.push(0);
        assert!(!kernel_address(&oversized));
        bytes[..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
        assert!(!kernel_address(&bytes));
    }

    #[test]
    fn aggregate_work_and_pointer_geometry_are_bounded() {
        let mut budget = Budget::new();
        for _ in 0..MAX_TOTAL_BYTES / MAX_DATAGRAM {
            assert!(budget.charge_bytes(MAX_DATAGRAM));
        }
        assert!(!budget.charge_bytes(1));
        assert!(!budget.charge_bytes(usize::MAX));
        assert!(!budget.charge_iovecs(0));
        assert!(!budget.charge_iovecs(MAX_IOVECS + 1));
        for _ in 0..MAX_TOTAL_IOVECS / MAX_IOVECS {
            assert!(budget.charge_iovecs(MAX_IOVECS));
        }
        assert!(!budget.charge_iovecs(1));
        assert!(array_end::<Mmsghdr>(16, MAX_MESSAGES).is_some());
        assert!(array_end::<Mmsghdr>(0, 1).is_none());
        assert!(array_end::<Mmsghdr>(usize::MAX - 1, 1).is_none());
        assert!(array_end::<Mmsghdr>(1, usize::MAX).is_none());
        let query = request(RTM_GETLINK, libc::AF_UNSPEC, 16);
        let mut bytes = query.repeat(MAX_DATAGRAM / query.len());
        assert!(dump_datagram(&bytes));
        bytes.extend_from_slice(&query);
        assert!(!dump_datagram(&bytes));
    }

    #[test]
    fn gathering_checks_the_whole_datagram_and_shared_budget() {
        let memory = reverie::syscalls::LocalMemory::new();
        let query = request(RTM_GETLINK, libc::AF_UNSPEC, 4);
        let mut destination = [0u8; 12];
        destination[..2].copy_from_slice(&(libc::AF_NETLINK as u16).to_ne_bytes());
        let mut iovecs = [
            libc::iovec {
                iov_base: query.as_ptr() as *mut libc::c_void,
                iov_len: 7,
            },
            libc::iovec {
                iov_base: query[7..].as_ptr() as *mut libc::c_void,
                iov_len: query.len() - 7,
            },
        ];
        // SAFETY: the Linux message header is a C record whose zeroed fields
        // are valid; every input pointer below refers to a live local buffer.
        let mut header: Msghdr = unsafe { std::mem::zeroed() };
        header.msg_name = destination.as_mut_ptr().cast();
        header.msg_namelen = destination.len() as libc::socklen_t;
        header.msg_iov = iovecs.as_mut_ptr();
        header.msg_iovlen = iovecs.len();
        let mut payload = [0u8; MAX_DATAGRAM];
        assert!(message(&memory, &header, &mut payload, &mut Budget::new()));
        header.msg_controllen = 1;
        assert!(!message(&memory, &header, &mut payload, &mut Budget::new()));
        header.msg_controllen = 0;

        // A safe first iovec cannot excuse a truncated or unreadable suffix.
        iovecs[1].iov_len -= 1;
        assert!(!message(&memory, &header, &mut payload, &mut Budget::new()));
        iovecs[1].iov_len += 1;
        let second = iovecs[1].iov_base;
        iovecs[1].iov_base = std::ptr::null_mut();
        assert!(!message(&memory, &header, &mut payload, &mut Budget::new()));
        iovecs[1].iov_base = second;

        let mut budget = Budget::new();
        assert!(budget.charge_bytes(MAX_TOTAL_BYTES - query.len()));
        assert!(message(&memory, &header, &mut payload, &mut budget));
        assert!(!message(&memory, &header, &mut payload, &mut budget));

        // Distinct batch entries cannot complete each other's partial message.
        header.msg_iovlen = 1;
        assert!(!message(&memory, &header, &mut payload, &mut Budget::new()));
        header.msg_iov = iovecs[1..].as_mut_ptr();
        assert!(!message(&memory, &header, &mut payload, &mut Budget::new()));
    }

    #[test]
    fn option_allowlist_excludes_filters_membership_and_unknowns() {
        assert!(local_option(libc::SOL_SOCKET, libc::SO_RCVBUF));
        assert!(local_option(libc::SOL_SOCKET, libc::SO_SNDTIMEO));
        assert!(local_option(libc::SOL_NETLINK, libc::NETLINK_EXT_ACK));
        assert!(local_option(libc::SOL_NETLINK, libc::NETLINK_CAP_ACK));
        assert!(local_option(libc::SOL_NETLINK, libc::NETLINK_GET_STRICT_CHK));
        assert!(!local_option(libc::SOL_SOCKET, libc::SO_ATTACH_FILTER));
        assert!(!local_option(libc::SOL_NETLINK, libc::NETLINK_ADD_MEMBERSHIP));
        assert!(!local_option(libc::SOL_NETLINK, i32::MAX));
        assert!(!local_option(libc::IPPROTO_IP, libc::SO_RCVBUF));
    }
}
