//! Dependency subscriptions, not a readiness emulator. Linux alone supplies probe results.
//!
//! A snapshot is taken before the physical probe. Registration compares every generation
//! under the scheduler lock. Unknown provenance fails closed to the existing polling loop.
//! Signalfd authority is limited to traced OFDs with exact masks and scheduler-owned
//! private/process signal queues. SIGCHLD, kernel-raised signals, host producers,
//! unknown consumers and inherited epoll ADD contexts fall back. Linux still
//! owns all readiness, records and ET/ONESHOT behavior.
//! Created Unix stream OFDs subscribe to one shared mutation generation;
//! authenticated private addresses keep every producer in scheduler custody.
//! Unused TCP streams subscribe to a separate monotone no-ingress capability,
//! revoked before active traffic. A pristine foreign Unix connect may temporarily
//! suspend authority, but only a synchronous no-effect errno settles that probe.
use std::collections::{BTreeMap, BTreeSet};

use reverie::Guest;
use reverie::syscalls::{MemoryAccess, Syscall, SyscallInfo};
use serde::{Deserialize, Serialize};

use crate::Detcore;
use crate::fd::FdType;
use crate::pipe_wake::ChannelId;
use crate::record_or_replay::RecordOrReplay;
use crate::scheduler::discarded_at_send::QueueId;
use crate::types::{DetPid, DetTid, MmId, OpenFileId};

/// Closed producer sets, not emulated network stacks. Revocation is permanent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SocketDomain {
    Unix,
    TcpNoIngress,
}

/// A single serialized, pristine Unix connect probe. Counters never wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocketProbe {
    pub(crate) file: OpenFileId,
    pub(crate) attempt: u64,
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize
)]
pub enum Key {
    File(OpenFileId),
    Pipe(ChannelId),
    /// Internal dependency, never a descriptor supplied by the guest.
    Signal(QueueId, u8),
    SocketDomain(SocketDomain),
    /// Stable per-file dependency; unlike File, shared by independent opens.
    Flock(OpenFileId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Observer {
    pub(crate) thread: DetTid,
    pub(crate) process: DetPid,
    pub(crate) mm: MmId,
    pub(crate) excluded_signals: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot(pub Vec<(Key, u64)>, pub(crate) Option<Observer>);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Update {
    Create(Key, bool),
    Socket { key: Key, domain: SocketDomain },
    SocketChange(SocketDomain),
    RevokeSocketDomain(SocketDomain),
    SuspendSocketProbe(SocketProbe),
    SettleSocketProbe { probe: SocketProbe, no_effect: bool },
    Observe(Vec<Key>, bool),
    Unsupported,
    Change(Vec<Key>),
    Revoke(Vec<Key>),
    RevokeAll,
    /// Descriptor-table divergence within a thread group defeats table-local
    /// exec/exit revocation. Keep existing and future sources on legacy polling.
    Disable,
    /// Only a traced successful creation may introduce a previously unknown OFD.
    Signalfd { key: Key, mask: Option<u64>, create: bool },
    SignalChange { queue: QueueId, signals: u64 },
    Epoll {
        epoll: Key,
        fd: i32,
        identity: Option<OpenFileId>,
        target: Option<Key>,
        operation: i32,
    },
}

#[derive(Clone, Copy, Debug)]
struct Interest {
    target: Option<Key>,
    /// Exact ADD task/incarnation; MOD never rewrites kernel queue provenance.
    observer: Option<Observer>,
}

#[derive(Debug, Default)]
struct Source {
    generation: u64,
    revoked: bool,
    // Linux identifies a registration by (descriptor number, OFD). None is an
    // unknown target: it prevents parking until the instance is retired.
    interests: Option<BTreeMap<(i32, Option<OpenFileId>), Interest>>,
    signalfd_mask: Option<u64>,
    socket_domain: Option<SocketDomain>,
    pending_socket_probe: Option<SocketProbe>,
    last_socket_probe: u64,
    subscribers: BTreeSet<DetTid>,
}

#[derive(Debug, Default)]
pub(crate) struct Counters {
    observations: u64,
    registrations: u64,
    mutation_wakes: u64,
    canceled: u64,
    stale_snapshots: u64,
    unsupported_waits: u64,
    fallback_unknown_source: u64,
    fallback_revoked_source: u64,
    revoked_sources: u64,
}

enum Unavailable {
    Unknown(Key),
    Revoked(Key),
}

#[derive(Debug, Default)]
pub(crate) struct Dependencies {
    sources: BTreeMap<Key, Source>,
    waits: BTreeMap<DetTid, Snapshot>,
    pub(crate) counters: Counters,
    disabled: bool,
    // Retained even after cancellation: outstanding pre-probe snapshots also
    // need host-producer revocation. Queue generations are never recycled.
    signal_queues: BTreeMap<u8, BTreeMap<DetPid, BTreeSet<QueueId>>>,
    excluded_signals: BTreeMap<DetPid, u64>,
    excluded_signals_everywhere: u64,
}

impl Dependencies {
    fn collect(
        &self,
        key: Key,
        observer: Option<Observer>,
        compatible: bool,
        visited: &mut BTreeSet<(Key, bool)>,
        found: &mut BTreeMap<Key, u64>,
    ) -> Result<(), Unavailable> {
        // A graph revisit under an incompatible ADD chain must still be
        // checked, even if another root already reached the same signalfd.
        if !visited.insert((key, compatible)) {
            return Ok(());
        }
        let source = self.sources.get(&key).ok_or(Unavailable::Unknown(key))?;
        if self.disabled || source.revoked || source.pending_socket_probe.is_some() {
            return Err(Unavailable::Revoked(key));
        }
        found.insert(key, source.generation);
        if let Some(domain) = source.socket_domain {
            self.collect(Key::SocketDomain(domain), observer, compatible, visited, found)?;
        }
        if let Some(mask) = source.signalfd_mask {
            let observer = observer.ok_or(Unavailable::Unknown(key))?;
            let excluded = observer.excluded_signals
                | self.excluded_signals_everywhere
                | self.excluded_signals.get(&observer.process).copied().unwrap_or(0)
                | (1u64 << (libc::SIGCHLD - 1));
            if !compatible || mask & excluded != 0 {
                return Err(Unavailable::Revoked(key));
            }
            for signal in 1..=64 {
                if mask & (1u64 << (signal - 1)) == 0 {
                    continue;
                }
                for queue in [
                    QueueId::Thread(observer.thread),
                    QueueId::Process(observer.process),
                ] {
                    let key = Key::Signal(queue, signal);
                    let generation = match self.sources.get(&key) {
                        Some(source) if source.revoked => return Err(Unavailable::Revoked(key)),
                        Some(source) => source.generation,
                        None => 0,
                    };
                    found.insert(key, generation);
                }
            }
        }
        if let Some(interests) = &source.interests {
            for interest in interests.values() {
                self.collect(
                    interest.target.ok_or(Unavailable::Unknown(key))?,
                    observer,
                    compatible && observer.zip(interest.observer).is_some_and(|(now, add)| {
                        now.thread == add.thread && now.process == add.process && now.mm == add.mm
                    }),
                    visited,
                    found,
                )?;
            }
        }
        Ok(())
    }

    /// Count syscall admissions, not the number of legacy fallback retries,
    /// whose physical host completion can vary independently of guest order.
    pub(crate) fn observe_attempt(&mut self, keys: Vec<Key>, first: bool) -> Option<Snapshot> {
        self.observe_from(keys, first, None)
    }

    pub(crate) fn observe_from(
        &mut self,
        keys: Vec<Key>,
        first: bool,
        observer: Option<Observer>,
    ) -> Option<Snapshot> {
        if first {
            self.counters.observations += 1;
        }
        if keys.is_empty() {
            return None;
        }
        let mut found = BTreeMap::new();
        let mut visited = BTreeSet::new();
        for key in keys {
            match self.collect(key, observer, true, &mut visited, &mut found) {
                Ok(()) => {}
                Err(Unavailable::Unknown(source)) => {
                    if first {
                        self.counters.fallback_unknown_source += 1;
                        tracing::info!(target: "detcore::event_driven_io", "event-driven IO fallback source {:?}: unknown source or epoll interest", source);
                    }
                    return None;
                }
                Err(Unavailable::Revoked(source)) => {
                    if first {
                        self.counters.fallback_revoked_source += 1;
                        tracing::info!(target: "detcore::event_driven_io", "event-driven IO fallback source {:?}: revoked authority", source);
                    }
                    return None;
                }
            }
        }
        if let Some(observer) = observer {
            for key in found.keys() {
                if let Key::Signal(queue, signal) = key {
                    self.sources.entry(*key).or_default();
                    self.signal_queues.entry(*signal).or_default()
                        .entry(observer.process).or_default().insert(*queue);
                }
            }
        }
        Some(Snapshot(found.into_iter().collect(), observer))
    }

    #[cfg(test)]
    fn observe(&mut self, keys: Vec<Key>) -> Option<Snapshot> {
        self.observe_attempt(keys, true)
    }

    pub(crate) fn register(&mut self, tid: DetTid, snapshot: &Snapshot) -> bool {
        self.cancel(tid);
        if self.disabled
            || snapshot.0.is_empty()
            || snapshot.1.is_some_and(|observer| observer.thread != tid)
            || snapshot.0.iter().any(|(key, generation)| {
                self.sources
                    .get(key)
                    .is_none_or(|s| s.revoked || s.pending_socket_probe.is_some() || s.generation != *generation)
            })
        {
            self.counters.stale_snapshots += 1;
            return false;
        }
        for (key, _) in &snapshot.0 {
            self.sources.get_mut(key).unwrap().subscribers.insert(tid);
        }
        self.waits.insert(tid, snapshot.clone());
        self.counters.registrations += 1;
        true
    }

    pub(crate) fn cancel(&mut self, tid: DetTid) -> bool {
        let Some(snapshot) = self.waits.remove(&tid) else {
            return false;
        };
        self.counters.canceled += 1;
        for (key, _) in snapshot.0 {
            if let Some(source) = self.sources.get_mut(&key) {
                source.subscribers.remove(&tid);
            }
        }
        true
    }

    pub(crate) fn update(&mut self, update: Update) -> BTreeSet<DetTid> {
        self.update_from(update, None)
    }

    pub(crate) fn update_from(
        &mut self,
        update: Update,
        observer: Option<Observer>,
    ) -> BTreeSet<DetTid> {
        let (keys, revoke) = match update {
            Update::SuspendSocketProbe(probe) => {
                let trusted = self.sources.get_mut(&Key::File(probe.file)).is_some_and(|source| {
                    if source.revoked || source.socket_domain != Some(SocketDomain::Unix)
                        || probe.attempt <= source.last_socket_probe
                    {
                        return false;
                    }
                    source.last_socket_probe = probe.attempt;
                    true
                });
                let domain = Key::SocketDomain(SocketDomain::Unix);
                let source = self.sources.entry(domain).or_default();
                let conflict = source.pending_socket_probe.is_some() || !trusted;
                if !conflict {
                    source.pending_socket_probe = Some(probe);
                }
                return self.change([domain], conflict);
            }
            Update::SettleSocketProbe { probe, no_effect } => {
                let domain = Key::SocketDomain(SocketDomain::Unix);
                let source = self.sources.entry(domain).or_default();
                let matches = source.pending_socket_probe == Some(probe);
                if matches {
                    source.pending_socket_probe = None;
                }
                // Wrong, stale, double and effectful settlement never reopen
                // authority. Neither does a valid settlement clear revocation.
                return self.change([domain], !matches || !no_effect);
            }
            Update::Socket { key, domain } => {
                if !self.disabled {
                    // Keep the tombstone even when the first unsafe producer
                    // precedes the first eligible socket.
                    self.sources.entry(Key::SocketDomain(domain)).or_default();
                    self.sources.entry(key).or_insert_with(|| Source {
                        socket_domain: Some(domain),
                        ..Source::default()
                    });
                }
                return BTreeSet::new();
            }
            Update::SocketChange(domain) => {
                return self.change([Key::SocketDomain(domain)], false);
            }
            Update::RevokeSocketDomain(domain) => {
                self.sources.entry(Key::SocketDomain(domain)).or_default();
                return self.change([Key::SocketDomain(domain)], true);
            }
            Update::Create(key, epoll) => {
                if self.disabled {
                    return BTreeSet::new();
                }
                self.sources.entry(key).or_insert_with(|| Source {
                    interests: epoll.then(BTreeMap::new),
                    ..Source::default()
                });
                return BTreeSet::new();
            }
            Update::Signalfd { key, mask, create } => {
                if self.disabled || !matches!(key, Key::File(_)) {
                    return BTreeSet::new();
                }
                if create && !self.sources.contains_key(&key) {
                    self.sources.insert(key, Source {
                        signalfd_mask: mask,
                        revoked: mask.is_none(),
                        ..Source::default()
                    });
                    return BTreeSet::new();
                }
                let Some(source) = self.sources.get_mut(&key) else {
                    return BTreeSet::new();
                };
                // A mask update is not provenance for a foreign/generic OFD,
                // and must never restore a revoked source.
                let revoke = source.signalfd_mask.is_none() || mask.is_none();
                source.signalfd_mask = mask;
                (vec![key], revoke)
            }
            Update::SignalChange { queue, mut signals } => {
                return self.change(
                    std::iter::from_fn(move || {
                        if signals == 0 {
                            return None;
                        }
                        let signal = signals.trailing_zeros() as u8 + 1;
                        signals &= signals - 1;
                        Some(Key::Signal(queue, signal))
                    }),
                    false,
                );
            }
            Update::Change(keys) => (keys, false),
            Update::Revoke(keys) => (keys, true),
            Update::RevokeAll => {
                for domain in [SocketDomain::Unix, SocketDomain::TcpNoIngress] {
                    self.sources.entry(Key::SocketDomain(domain)).or_default();
                }
                (self.sources.keys().copied().collect(), true)
            }
            Update::Disable => {
                self.disabled = true;
                (self.sources.keys().copied().collect(), true)
            }
            Update::Epoll {
                epoll,
                fd,
                identity,
                target,
                operation,
            } => {
                if let Some(source) = self.sources.get_mut(&epoll) {
                    if let Some(interests) = &mut source.interests {
                        if operation == libc::EPOLL_CTL_DEL {
                            interests.remove(&(fd, identity));
                        } else if operation == libc::EPOLL_CTL_ADD {
                            interests.insert((fd, identity), Interest {
                                target,
                                observer,
                            });
                        } else if operation == libc::EPOLL_CTL_MOD {
                            // Successful MOD of an untracked registration does
                            // not prove where its original ADD installed hooks.
                            interests.entry((fd, identity)).or_insert(Interest {
                                target,
                                observer: None,
                            });
                        }
                    }
                }
                (vec![epoll], false)
            }
            Update::Unsupported => {
                self.counters.unsupported_waits += 1;
                tracing::info!(target: "detcore::event_driven_io", "event-driven IO fallback source unavailable: unsupported probe geometry or provenance");
                return BTreeSet::new();
            }
            Update::Observe(..) => unreachable!("observation is read-only"),
        };
        self.change(keys, revoke)
    }

    fn change(&mut self, keys: impl IntoIterator<Item = Key>, revoke: bool) -> BTreeSet<DetTid> {
        let mut wake = BTreeSet::new();
        let mut domains = [false; 2];
        for key in keys {
            if let Some(source) = self.sources.get_mut(&key) {
                if let Some(domain) = source.socket_domain {
                    domains[domain as usize] = true;
                }
                // Exhaustion revokes rather than allowing an ABA generation.
                match source.generation.checked_add(1) {
                    Some(next) => source.generation = next,
                    None => source.revoked = true,
                }
                if revoke && !source.revoked {
                    self.counters.revoked_sources += 1;
                }
                source.revoked |= revoke;
                wake.extend(source.subscribers.iter().copied());
            }
        }
        // Domain subscribers are shared: no scan of unrelated socket OFDs.
        for domain in [SocketDomain::Unix, SocketDomain::TcpNoIngress] {
            if !domains[domain as usize] {
                continue;
            }
            let domain = Key::SocketDomain(domain);
            if let Some(source) = self.sources.get_mut(&domain) {
                match source.generation.checked_add(1) {
                    Some(next) => source.generation = next,
                    None => source.revoked = true,
                }
                source.revoked |= revoke;
                wake.extend(source.subscribers.iter().copied());
            }
        }
        for tid in &wake {
            self.cancel(*tid);
        }
        self.counters.mutation_wakes += wake.len() as u64;
        wake
    }

    /// Revoke queued dependencies before a producer/consumer escapes scheduler
    /// custody. Index includes observations that have not registered yet.
    pub(crate) fn exclude_signals(
        &mut self,
        process: Option<DetPid>,
        signals: u64,
    ) -> BTreeSet<DetTid> {
        match process {
            Some(process) => *self.excluded_signals.entry(process).or_default() |= signals,
            None => self.excluded_signals_everywhere |= signals,
        }
        let mut keys = Vec::new();
        for (&signal, processes) in &self.signal_queues {
            if signals & (1u64 << (signal - 1)) == 0 {
                continue;
            }
            if let Some(process) = process {
                if let Some(queues) = processes.get(&process) {
                    keys.extend(queues.iter().map(|queue| Key::Signal(*queue, signal)));
                }
            } else {
                for queues in processes.values() {
                    keys.extend(queues.iter().map(|queue| Key::Signal(*queue, signal)));
                }
            }
        }
        self.update(Update::Revoke(keys))
    }
}

pub(crate) fn key<G: Guest<Detcore<T>>, T: RecordOrReplay>(guest: &G, fd: i32) -> Option<Key> {
    guest
        .thread_state()
        .with_detfd(fd, |file| descriptor_key(file))
        .ok()
        .flatten()
}

fn descriptor_key(file: &crate::fd::DetFd) -> Option<Key> {
    match file.ty() {
        FdType::Regular => file.flock_domain().map(|domain| domain.key),
        FdType::Eventfd | FdType::Epoll | FdType::Signalfd => Some(Key::File(file.open_file_id())),
        FdType::Socket if file.socket_domain().is_some() => Some(Key::File(file.open_file_id())),
        FdType::Pipe => file.channel().map(|end| Key::Pipe(end.channel)),
        _ => None,
    }
}

/// Read each poll's actual input in its granted turn, immediately before injection.
/// No event-mask interpretation is needed: every source mutation permits a probe.
pub(crate) fn probe_keys<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &G,
    call: Syscall,
) -> Option<Vec<Key>> {
    match call {
        Syscall::Read(c) => Some(vec![key(guest, c.fd())?]),
        Syscall::Readv(c) => Some(vec![key(guest, c.fd())?]),
        Syscall::Write(c) => Some(vec![key(guest, c.fd())?]),
        Syscall::Writev(c) => Some(vec![key(guest, c.fd())?]),
        Syscall::Connect(c) => Some(vec![key(guest, c.fd())?]),
        Syscall::Accept(c) => Some(vec![key(guest, c.sockfd())?]),
        Syscall::Accept4(c) => Some(vec![key(guest, c.sockfd())?]),
        Syscall::Sendto(c) => Some(vec![key(guest, c.fd())?]),
        Syscall::Sendmsg(c) => Some(vec![key(guest, c.fd())?]),
        Syscall::Sendmmsg(c) => Some(vec![key(guest, c.sockfd())?]),
        Syscall::Recvfrom(c) => Some(vec![key(guest, c.fd())?]),
        Syscall::Recvmsg(c) => Some(vec![key(guest, c.sockfd())?]),
        Syscall::Recvmmsg(c) => Some(vec![key(guest, c.fd())?]),
        Syscall::EpollWait(c) => Some(vec![key(guest, c.epfd())?]),
        Syscall::EpollPwait(c) => Some(vec![key(guest, c.epfd())?]),
        Syscall::Poll(c) => {
            let count = usize::try_from(c.nfds()).ok()?;
            // Unsupported geometry retains native validation and the legacy path.
            if count == 0 || count > 4096 {
                return None;
            }
            let mut fds = vec![
                libc::pollfd {
                    fd: -1,
                    events: 0,
                    revents: 0
                };
                count
            ];
            guest
                .memory()
                .read_values(c.fds()?.cast().into(), &mut fds)
                .ok()?;
            let mut keys = Vec::with_capacity(count);
            for fd in fds {
                if fd.fd >= 0 {
                    keys.push(key(guest, fd.fd)?);
                }
            }
            Some(keys)
        }
        _ => None,
    }
}

pub(crate) async fn observe<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G,
    call: Syscall,
    attempt: u32,
) -> Option<Box<Snapshot>> {
    if !guest.config().event_driven_io {
        return None;
    }
    let Some(keys) = probe_keys(guest, call) else {
        if attempt == 0 {
            crate::tool_global::event_driven_io(guest, Update::Unsupported).await;
        }
        return None;
    };
    crate::tool_global::event_driven_io(guest, Update::Observe(keys, attempt == 0))
        .await
        .map(Box::new)
}

pub(crate) async fn created<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G,
    fd: i32,
    epoll: bool,
) {
    if guest.config().event_driven_io {
        if let Some(key) = key(guest, fd) {
            crate::tool_global::event_driven_io(guest, Update::Create(key, epoll)).await;
        }
    }
}

pub(crate) fn socket_domain<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &G,
    fd: i32,
) -> Option<SocketDomain> {
    guest.thread_state().with_detfd(fd, |file| file.socket_domain()).ok().flatten()
}

/// Only a traced creation (or accept of a traced listener) calls this.
pub(crate) async fn socket_created<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G,
    fd: i32,
    domain: Option<SocketDomain>,
    pristine: bool,
) {
    if !guest.config().event_driven_io { return; }
    let Some(domain) = domain else { return; };
    let identity = guest.thread_state().with_detfd(fd, |file| {
        file.set_socket_domain(domain, pristine);
        Key::File(file.open_file_id())
    }).ok();
    if let Some(key) = identity {
        crate::tool_global::event_driven_io(guest, Update::Socket { key, domain }).await;
    }
}

pub(crate) fn created_socket_domain(family: i32, kind: i32, protocol: i32) -> Option<SocketDomain> {
    if kind & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) != libc::SOCK_STREAM { return None; }
    match family {
        libc::AF_UNIX if protocol == 0 => Some(SocketDomain::Unix),
        libc::AF_INET | libc::AF_INET6 if matches!(protocol, 0 | libc::IPPROTO_TCP | libc::IPPROTO_MPTCP) =>
            Some(SocketDomain::TcpNoIngress),
        _ => None,
    }
}

pub(crate) fn created_udp_socket(family: i32, kind: i32, protocol: i32) -> bool {
    matches!(family, libc::AF_INET | libc::AF_INET6)
        && kind & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK) == libc::SOCK_DGRAM
        && matches!(protocol, 0 | libc::IPPROTO_UDP)
}

fn local_socket_option(level: i32, option: i32, inet: bool, tcp: bool) -> bool {
    (level == libc::SOL_SOCKET
        && matches!(option, libc::SO_REUSEADDR | libc::SO_REUSEPORT
            | libc::SO_KEEPALIVE | libc::SO_SNDBUF | libc::SO_RCVBUF
            | libc::SO_SNDLOWAT | libc::SO_RCVLOWAT | libc::SO_PASSCRED
            | libc::SO_LINGER | libc::SO_RCVTIMEO | libc::SO_SNDTIMEO
            | libc::SO_PRIORITY))
        || (tcp && level == libc::IPPROTO_TCP
            && matches!(option, libc::TCP_NODELAY | libc::TCP_CORK
                | libc::TCP_KEEPIDLE | libc::TCP_KEEPINTVL | libc::TCP_KEEPCNT
                | libc::TCP_MAXSEG | libc::TCP_USER_TIMEOUT | libc::TCP_SYNCNT
                | libc::TCP_LINGER2 | libc::TCP_WINDOW_CLAMP | libc::TCP_QUICKACK
                | libc::TCP_DEFER_ACCEPT))
        || (inet && level == libc::IPPROTO_IP
            && matches!(option, libc::IP_TOS | libc::IP_TTL | libc::IP_RECVTOS | libc::IP_RECVTTL))
        || (inet && level == libc::IPPROTO_IPV6
            && matches!(option, libc::IPV6_V6ONLY | libc::IPV6_TCLASS
                | libc::IPV6_UNICAST_HOPS))
}

fn ordinary_sendfile_endpoint(file: &crate::fd::DetFd) -> bool {
    matches!(file.ty(), FdType::Regular | FdType::Memfd)
        && file.procfs_position().is_none()
        && file.stat().is_some_and(|stat| stat.mode & libc::S_IFMT == libc::S_IFREG)
}

async fn revoke_socket_domain<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G,
    domain: SocketDomain,
    reason: &str,
) {
    tracing::info!(target: "detcore::event_driven_io", "event-driven socket domain {:?} revoked: {}", domain, reason);
    crate::tool_global::event_driven_io(guest, Update::RevokeSocketDomain(domain)).await;
}

async fn revoke_socket_domains<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G,
    reason: &str,
) {
    for domain in [SocketDomain::Unix, SocketDomain::TcpNoIngress] {
        revoke_socket_domain(guest, domain, reason).await;
    }
}

pub(crate) fn socket_mutation(number: reverie::syscalls::Sysno) -> bool {
    use reverie::syscalls::Sysno;
    matches!(number, Sysno::bind | Sysno::connect | Sysno::listen | Sysno::accept
        | Sysno::accept4 | Sysno::shutdown | Sysno::read | Sysno::readv
        | Sysno::write | Sysno::writev | Sysno::sendto | Sysno::sendmsg
        | Sysno::sendmmsg | Sysno::recvfrom | Sysno::recvmsg | Sysno::recvmmsg
        | Sysno::setsockopt | Sysno::sendfile)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SocketAttemptKind {
    FilesystemChange,
    Create,
    Mutation,
    Close,
    Replace,
    CloseRange,
}

fn socket_attempt_kind(number: reverie::syscalls::Sysno) -> Option<SocketAttemptKind> {
    use reverie::syscalls::Sysno;
    match number {
        Sysno::rename | Sysno::renameat | Sysno::renameat2
        | Sysno::link | Sysno::linkat | Sysno::symlink | Sysno::symlinkat =>
            Some(SocketAttemptKind::FilesystemChange),
        Sysno::socket | Sysno::socketpair => Some(SocketAttemptKind::Create),
        Sysno::close => Some(SocketAttemptKind::Close),
        Sysno::dup2 | Sysno::dup3 => Some(SocketAttemptKind::Replace),
        Sysno::close_range => Some(SocketAttemptKind::CloseRange),
        _ if socket_mutation(number) => Some(SocketAttemptKind::Mutation),
        _ => None,
    }
}

/// Share the attempt hooks' classification with the forwarding fast path.
/// Default-policy and unrelated calls need neither a bookkeeping future nor
/// an allocation to discover that the hooks have nothing to do.
pub(crate) fn may_bookkeep_socket_attempt<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &G,
    call: Syscall,
) -> bool {
    guest.config().event_driven_io && socket_attempt_kind(call.number()).is_some()
}

/// Run in the physical attempt's granted turn, never at an outer handler
/// before that handler can yield. Path proof and injection have no grant gap.
pub(crate) async fn before_socket_attempt<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G,
    call: Syscall,
) -> Option<SocketProbe> {
    use reverie::syscalls::Sysno;
    if !guest.config().event_driven_io { return None; }
    let (number, args) = call.into_parts();
    let kind = socket_attempt_kind(number);
    if kind == Some(SocketAttemptKind::FilesystemChange) {
        if !crate::private_socket_path::filesystem_change_safe(guest, call).await {
            revoke_socket_domain(guest, SocketDomain::Unix, "unproven pathname exposure").await;
        }
        return None;
    }
    if let Syscall::Socket(create) = call {
        if created_socket_domain(create.family(), create.r#type(), create.protocol()).is_none()
            && !created_udp_socket(create.family(), create.r#type(), create.protocol())
            && !crate::socket_query::route_creation(create.family(), create.r#type(), create.protocol())
        {
            revoke_socket_domains(guest, "unsupported socket producer").await;
        }
        return None;
    }
    if let Syscall::Socketpair(create) = call {
        if created_socket_domain(create.family(), create.r#type(), create.protocol()) != Some(SocketDomain::Unix) {
            revoke_socket_domains(guest, "unsupported socketpair producer").await;
        }
        return None;
    }
    if number == Sysno::sendfile {
        // Inspect both current slots after the handler's resource grant. A
        // regular-file copy cannot produce socket readiness; a generic Regular
        // label without physical S_IFREG provenance is not enough.
        let ordinary = [args.arg0 as i32, args.arg1 as i32].into_iter().all(|fd| {
            guest.thread_state().with_detfd(fd, |file| ordinary_sendfile_endpoint(file)).unwrap_or(false)
        });
        if !ordinary {
            revoke_socket_domains(guest, "unproven zero-copy endpoints").await;
        }
        return None;
    }
    if kind != Some(SocketAttemptKind::Mutation) { return None; }
    let fd = args.arg0 as i32;
    let domain = socket_domain(guest, fd);
    if domain.is_none() {
        let socket = guest.thread_state().with_detfd(fd, |file| file.ty() == FdType::Socket)
            .unwrap_or(true);
        if socket {
            if crate::socket_query::route_attempt(guest, call) {
                return None;
            }
            let udp = guest.thread_state().with_detfd(fd, |file| file.is_udp_socket()).unwrap_or(false);
            if udp {
                // UDP stays unowned. Its datagrams cannot deliver bytes or
                // SCM_RIGHTS to streams; ancillary/background guards still run.
                if number == Sysno::setsockopt
                    && !local_socket_option(args.arg1 as i32, args.arg2 as i32, true, false)
                {
                    revoke_socket_domains(guest, "unsupported UDP socket option").await;
                }
                return None;
            }
        }
        if socket || matches!(number, Sysno::bind | Sysno::connect | Sysno::sendto
            | Sysno::sendmsg | Sysno::sendmmsg | Sysno::recvfrom | Sysno::recvmsg
            | Sysno::recvmmsg | Sysno::accept | Sysno::accept4 | Sysno::setsockopt)
        {
            revoke_socket_domains(guest, "unowned socket operation").await;
        }
        return None;
    }
    let domain = domain.unwrap();
    if matches!(number, Sysno::bind | Sysno::connect) && domain == SocketDomain::Unix {
        if !crate::private_socket_path::address_owned(guest, call).await {
            if number == Sysno::connect {
                let probe = guest.thread_state().with_detfd(fd, |file| file.begin_socket_probe())
                    .ok().flatten();
                if let Some(probe) = probe {
                    // No grant until the physical attempt and its settlement.
                    // Existing waiters are woken and new observations refused.
                    crate::tool_global::event_driven_io(guest, Update::SuspendSocketProbe(probe)).await;
                    return Some(probe);
                }
            }
            revoke_socket_domain(guest, domain, "unproven Unix address").await;
        }
    }
    if !matches!(number, Sysno::read | Sysno::readv | Sysno::recvfrom
        | Sysno::recvmsg | Sysno::recvmmsg)
    {
        let _ = guest.thread_state().with_detfd(fd, |file| file.mark_socket_attached());
    }
    if domain == SocketDomain::TcpNoIngress && matches!(number,
        Sysno::connect | Sysno::sendto | Sysno::sendmsg | Sysno::sendmmsg
        | Sysno::write | Sysno::writev | Sysno::sendfile)
    {
        revoke_socket_domain(guest, domain, "active TCP producer").await;
    }
    if number == Sysno::setsockopt {
        // Configuration cannot create traffic on an unused TCP stream.
        // Repair, BPF, device attachment, zerocopy and unknown options fail closed.
        let inet = domain == SocketDomain::TcpNoIngress;
        let safe = local_socket_option(args.arg1 as i32, args.arg2 as i32, inet, inet);
        if !safe {
            revoke_socket_domains(guest, "unsupported socket option").await;
        }
    }
    None
}

/// Native data, EOF and queue transitions publish before a retry can park.
/// An EAGAIN probe transfers nothing and must not invalidate its own snapshot.
/// Other errors can follow a dequeue (e.g. recvmsg output-copy faults).
pub(crate) async fn after_socket_attempt<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G,
    call: Syscall,
    result: &Result<i64, reverie::Error>,
    probe: Option<SocketProbe>,
) {
    if !guest.config().event_driven_io { return; }
    let kind = socket_attempt_kind(call.number());
    if let Some(probe) = probe {
        // These Unix stream errors occur before attaching a peer or enqueuing
        // a connection. EAGAIN/EINPROGRESS/EINTR and every other outcome are
        // deliberately not certificates, even on a brand-new socket.
        let no_effect = matches!(result, Err(reverie::Error::Errno(
            reverie::Errno::ENOENT | reverie::Errno::ENOTDIR
            | reverie::Errno::ENOTSOCK | reverie::Errno::ECONNREFUSED
        )));
        if !no_effect {
            let (_, args) = call.into_parts();
            let _ = guest.thread_state().with_detfd(args.arg0 as i32, |file| file.mark_socket_attached());
        }
        tracing::info!(target: "detcore::event_driven_io", "event-driven Unix connect probe {:?} settled no-effect {}", probe, no_effect);
        crate::tool_global::event_driven_io(guest, Update::SettleSocketProbe { probe, no_effect }).await;
    }
    let (_, args) = call.into_parts();
    let mutated = !matches!(result, Err(reverie::Error::Errno(reverie::Errno::EAGAIN)));
    if kind == Some(SocketAttemptKind::Mutation) && mutated {
        if let Some(domain) = socket_domain(guest, args.arg0 as i32) {
            crate::tool_global::event_driven_io(guest, Update::SocketChange(domain)).await;
        }
    }
    // Descriptor metadata still names the old OFD here, before outer handlers
    // delete or replace it. Capture the physical attempt, not an entry snapshot.
    let replaced = match kind {
        Some(SocketAttemptKind::Close) => Some(args.arg0 as i32),
        Some(SocketAttemptKind::Replace) if result.is_ok() => Some(args.arg1 as i32),
        _ => None,
    };
    if let Some(fd) = replaced {
        if let Some(domain) = socket_domain(guest, fd) {
            crate::tool_global::event_driven_io(guest, Update::SocketChange(domain)).await;
        }
    }
    if kind == Some(SocketAttemptKind::CloseRange) && result.is_ok() {
        let mut unix = false;
        let mut tcp = false;
        for fd in guest.thread_state().open_fds() {
            if (args.arg0 as u32..=args.arg1 as u32).contains(&(fd as u32)) {
                match socket_domain(guest, fd) {
                    Some(SocketDomain::Unix) => unix = true,
                    Some(SocketDomain::TcpNoIngress) => tcp = true,
                    None => {}
                }
            }
        }
        for (domain, changed) in [(SocketDomain::Unix, unix), (SocketDomain::TcpNoIngress, tcp)] {
            if changed {
                crate::tool_global::event_driven_io(guest, Update::SocketChange(domain)).await;
            }
        }
    }
}

/// Capture the whole old table before exit/exec can replace it. Authority is
/// retained only when the scheduler authenticates a native no-turn barrier;
/// otherwise the same keys are revoked. Never infer which alias closes last.
pub(crate) async fn notify_lifecycle<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G,
) {
    if !guest.config().event_driven_io {
        return;
    }
    let keys: BTreeSet<_> = guest
        .thread_state()
        .open_fds()
        .into_iter()
        .filter_map(|fd| key(guest, fd))
        .collect();
    if keys.is_empty() {
        return;
    }
    crate::tool_global::event_driven_io_lifecycle(guest, keys.into_iter().collect()).await;
}

/// Only standard read-only queries on positively identified kernel objects
/// bypass revocation. Unknown character drivers can repurpose these numbers.
fn readonly_ioctl(ty: FdType, stat: Option<(u32, u64)>, request: u64) -> bool {
    let ordinary = matches!(ty, FdType::Pipe | FdType::Eventfd | FdType::Epoll | FdType::Socket)
        || stat.is_some_and(|(mode, _)| {
            matches!(mode & libc::S_IFMT, libc::S_IFREG | libc::S_IFDIR | libc::S_IFIFO | libc::S_IFSOCK)
        });
    // Linux drivers/char/mem.c: null (1:3), zero (1:5), and full (1:7)
    // have no ioctl handler. These terminal queries return ENOTTY without a
    // readiness mutation. Identify the device, never its pathname or fd type.
    let non_tty_memory = stat.is_some_and(|(mode, rdev)| {
        mode & libc::S_IFMT == libc::S_IFCHR
            && libc::major(rdev) == 1
            && matches!(libc::minor(rdev), 3 | 5 | 7)
    });
    (ordinary
        && [libc::TCGETS as u64, libc::TIOCGWINSZ as u64, libc::FIONREAD as u64]
            .contains(&request))
        || (non_tty_memory
            && [libc::TCGETS as u64, libc::TIOCGWINSZ as u64].contains(&request))
}

/// Linux handles these generic descriptor/status flags before dispatching to
/// a device's ioctl implementation. They cannot alter source readiness.
/// `handle_ioctl` already maintains the logical nonblocking/CLOEXEC state.
fn descriptor_flags_ioctl(request: u64) -> bool {
    [libc::FIONBIO as u64, libc::FIOCLEX as u64, libc::FIONCLEX as u64]
        .contains(&request)
}

/// Revoke unproven kernel mutation authority before forwarding. For ordinary
/// descriptor replacement return the old object identities instead: the
/// committed close wakes them without guessing whether a last reference died.
pub(crate) async fn before_syscall<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G,
    call: Syscall,
) -> Vec<Key> {
    use reverie::syscalls::Sysno;
    if !guest.config().event_driven_io {
        return Vec::new();
    }
    let (number, args) = call.into_parts();
    let clone_flags = if number == Sysno::clone {
        Some(args.arg0 as u64)
    } else if number == Sysno::clone3 {
        reverie::syscalls::Addr::<u64>::from_raw(args.arg0 as usize)
            .and_then(|address| guest.memory().read_value(address).ok())
    } else {
        Some(0)
    };
    let escapes = matches!(number, Sysno::setns | Sysno::unshare | Sysno::mount
        | Sysno::umount2 | Sysno::pivot_root | Sysno::chroot
        | Sysno::open_tree | Sysno::move_mount | Sysno::fsopen | Sysno::fsmount
        | Sysno::mount_setattr | Sysno::bpf | Sysno::pidfd_getfd)
        || clone_flags.is_none_or(|flags| flags & (libc::CLONE_UNTRACED
            | libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWUSER
            | libc::CLONE_NEWIPC | libc::CLONE_NEWPID | libc::CLONE_NEWUTS
            | libc::CLONE_NEWCGROUP) as u64 != 0);
    if escapes {
        tracing::info!(target: "detcore::event_driven_io", "event-driven IO disabled before namespace/producer escape {}", number);
        crate::tool_global::event_driven_io(guest, Update::Disable).await;
        return Vec::new();
    }
    if number == Sysno::ioctl
        && (descriptor_flags_ioctl(args.arg1 as u64)
            || guest
                .thread_state()
                .with_detfd(args.arg0 as i32, |fd| {
                    readonly_ioctl(fd.ty(), fd.stat().map(|stat| (stat.mode, stat.rdev)), args.arg1 as u64)
                })
                .unwrap_or(false))
    {
        return Vec::new();
    }
    let global = matches!(
        number,
        Sysno::io_submit
            | Sysno::ioctl
            | Sysno::io_uring_setup
            | Sysno::io_uring_register
            | Sysno::io_uring_enter
    );
    let descriptor = match number {
        Sysno::close | Sysno::ioctl => Some(args.arg0 as i32),
        Sysno::dup2 | Sysno::dup3 => Some(args.arg1 as i32),
        Sysno::fcntl if args.arg1 as i32 == libc::F_SETPIPE_SZ => Some(args.arg0 as i32),
        _ => None,
    };
    let range = number == Sysno::close_range;
    let zero_copy = !guest.config().panic_on_unsupported_syscalls
        && matches!(number, Sysno::splice | Sysno::tee | Sysno::vmsplice);
    let diverges = number == Sysno::unshare && (args.arg0 as i32 & libc::CLONE_FILES) != 0;
    if !(global || descriptor.is_some() || range || zero_copy || diverges) {
        return Vec::new();
    }
    let update = if diverges || zero_copy {
        Update::Disable
    } else if global {
        Update::RevokeAll
    } else {
        let mut keys = BTreeSet::new();
        if range {
            for fd in guest.thread_state().open_fds() {
                if range && !(args.arg0 as u32..=args.arg1 as u32).contains(&(fd as u32)) {
                    continue;
                }
                if let Some(key) = key(guest, fd) {
                    keys.insert(key);
                }
            }
        } else if let Some(fd) = descriptor {
            if let Some(key) = key(guest, fd) {
                keys.insert(key);
            }
        }
        if keys.is_empty() {
            return Vec::new();
        }
        let keys: Vec<_> = keys.into_iter().collect();
        if range || matches!(number, Sysno::close | Sysno::dup2 | Sysno::dup3) {
            return keys;
        }
        Update::Revoke(keys)
    };
    tracing::info!(target: "detcore::event_driven_io", "event-driven IO authority revoked before {}", number);
    crate::tool_global::event_driven_io(guest, update).await;
    Vec::new()
}

pub(crate) async fn after_fd_progress<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G,
    call: Syscall,
    result: &Result<i64, reverie::Error>,
) {
    if !guest.config().event_driven_io || !matches!(result, Ok(n) if *n > 0) {
        return;
    }
    if let Some((fd, _)) = crate::pipe_wake::progress_of(&call) {
        if socket_domain(guest, fd).is_some() { return; }
        // Pipe attempts (including partial writes) already publish through the
        // channel hook. Eventfd reads/writes have no partial-byte success.
        if let Some(Key::File(id)) = key(guest, fd) {
            crate::tool_global::event_driven_io(guest, Update::Change(vec![Key::File(id)])).await;
        }
    }
}

pub(crate) async fn after_epoll_progress<G: Guest<Detcore<T>>, T: RecordOrReplay>(
    guest: &mut G,
    call: Syscall,
    result: &Result<i64, reverie::Error>,
) {
    if !guest.config().event_driven_io || !matches!(result, Ok(n) if *n > 0) {
        return;
    }
    let (number, args) = call.into_parts();
    if matches!(
        number,
        reverie::syscalls::Sysno::epoll_wait
            | reverie::syscalls::Sysno::epoll_pwait
            | reverie::syscalls::Sysno::epoll_pwait2
    ) {
        if let Some(key) = key(guest, args.arg0 as i32) {
            crate::tool_global::event_driven_io(guest, Update::Change(vec![key])).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> Key {
        Key::File(OpenFileId::new(DetTid::from_raw(1), 1))
    }

    fn socket_key(index: u64) -> Key {
        Key::File(OpenFileId::new(DetTid::from_raw(1), index))
    }

    #[test]
    fn udp_provenance_does_not_promote_raw_or_unix_datagram_readiness() {
        for family in [libc::AF_INET, libc::AF_INET6] {
            for protocol in [0, libc::IPPROTO_UDP] {
                assert!(created_udp_socket(family, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, protocol));
            }
            assert!(!created_udp_socket(family, libc::SOCK_RAW, libc::IPPROTO_UDP));
            assert!(!created_udp_socket(family, libc::SOCK_DGRAM, libc::IPPROTO_TCP));
            assert!(!created_udp_socket(family, libc::SOCK_DGRAM | 0x10000, 0));
        }
        assert!(!created_udp_socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0));
        let file = crate::fd::DetFd::new(7, nix::fcntl::OFlag::empty(), FdType::Socket,
            OpenFileId::new(DetTid::from_raw(1), 1));
        let alias = file.clone().with_fd(8);
        file.set_udp_socket();
        assert!(alias.is_udp_socket());
        assert!(descriptor_key(&file).is_none());
        assert!(descriptor_key(&alias).is_none());
    }

    #[test]
    fn local_options_exclude_programmable_and_protocol_mismatched_effects() {
        assert!(local_socket_option(libc::IPPROTO_IP, libc::IP_TOS, true, true));
        assert!(local_socket_option(libc::SOL_SOCKET, libc::SO_PRIORITY, true, true));
        for option in [libc::TCP_MAXSEG, libc::TCP_USER_TIMEOUT, libc::TCP_SYNCNT,
            libc::TCP_LINGER2, libc::TCP_WINDOW_CLAMP, libc::TCP_QUICKACK, libc::TCP_DEFER_ACCEPT] {
            assert!(local_socket_option(libc::IPPROTO_TCP, option, true, true));
            assert!(!local_socket_option(libc::IPPROTO_TCP, option, true, false));
        }
        assert!(!local_socket_option(libc::IPPROTO_IP, libc::IP_TOS, false, false));
        assert!(!local_socket_option(libc::IPPROTO_TCP, libc::TCP_NODELAY, true, false));
        assert!(!local_socket_option(libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, true, true));
        assert!(!local_socket_option(libc::SOL_SOCKET, libc::SO_BINDTODEVICE, true, false));
        assert!(!local_socket_option(libc::IPPROTO_TCP, libc::TCP_REPAIR, true, true));
    }

    #[test]
    fn mptcp_has_only_the_same_passive_no_ingress_authority_as_tcp() {
        for family in [libc::AF_INET, libc::AF_INET6] {
            for protocol in [0, libc::IPPROTO_TCP, libc::IPPROTO_MPTCP] {
                assert_eq!(created_socket_domain(family, libc::SOCK_STREAM
                    | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, protocol),
                    Some(SocketDomain::TcpNoIngress));
                assert_eq!(created_socket_domain(family, libc::SOCK_DGRAM, protocol), None);
                assert_eq!(created_socket_domain(family, libc::SOCK_STREAM | 0x10000, protocol), None);
            }
        }
        assert_eq!(created_socket_domain(libc::AF_UNIX, libc::SOCK_STREAM, libc::IPPROTO_MPTCP), None);
    }

    #[test]
    fn unix_domain_wakes_all_subscribers_without_pairing_and_rejects_raced_probe() {
        let mut deps = Dependencies::default();
        let first = socket_key(1);
        let second = socket_key(2);
        for key in [first, second] {
            deps.update(Update::Socket { key, domain: SocketDomain::Unix });
        }
        let a = DetTid::from_raw(2);
        let b = DetTid::from_raw(3);
        let snapshot_a = deps.observe(vec![first]).unwrap();
        let snapshot_b = deps.observe(vec![second]).unwrap();
        assert!(deps.register(a, &snapshot_a));
        assert!(deps.register(b, &snapshot_b));
        assert_eq!(deps.update(Update::SocketChange(SocketDomain::Unix)), BTreeSet::from([a, b]));
        assert!(!deps.register(a, &snapshot_a));
        assert!(!deps.register(b, &snapshot_b));
        assert!(deps.observe(vec![first, second]).is_some());
    }

    #[test]
    fn tcp_revocation_invalidates_mixed_epoll_and_cannot_be_restored_by_creation() {
        let mut deps = Dependencies::default();
        let epoll = socket_key(1);
        let unix = socket_key(2);
        let tcp = socket_key(3);
        deps.update(Update::Create(epoll, true));
        deps.update(Update::Socket { key: unix, domain: SocketDomain::Unix });
        deps.update(Update::Socket { key: tcp, domain: SocketDomain::TcpNoIngress });
        for (fd, key) in [(7, unix), (8, tcp)] {
            let Key::File(identity) = key else { unreachable!() };
            deps.update(Update::Epoll {
                epoll, fd, identity: Some(identity), target: Some(key), operation: libc::EPOLL_CTL_ADD,
            });
        }
        let tid = DetTid::from_raw(2);
        let snapshot = deps.observe(vec![epoll]).unwrap();
        assert!(deps.register(tid, &snapshot));
        assert_eq!(deps.update(Update::RevokeSocketDomain(SocketDomain::TcpNoIngress)), BTreeSet::from([tid]));
        assert!(!deps.register(tid, &snapshot));
        assert!(deps.observe(vec![epoll]).is_none());
        assert!(deps.observe(vec![unix]).is_some());
        let fresh = socket_key(4);
        deps.update(Update::Socket { key: fresh, domain: SocketDomain::TcpNoIngress });
        assert!(deps.observe(vec![fresh]).is_none());
    }

    #[test]
    fn socket_export_revokes_domain_but_lifecycle_only_reprobes() {
        let mut deps = Dependencies::default();
        let alias = socket_key(1);
        let peer = socket_key(2);
        for key in [alias, peer] {
            deps.update(Update::Socket { key, domain: SocketDomain::Unix });
        }
        let tid = DetTid::from_raw(2);
        let before_close = deps.observe(vec![peer]).unwrap();
        assert!(deps.register(tid, &before_close));
        assert_eq!(deps.update(Update::Change(vec![alias])), BTreeSet::from([tid]));
        assert!(!deps.register(tid, &before_close));
        let before_escape = deps.observe(vec![peer]).unwrap();
        assert!(deps.register(tid, &before_escape));
        assert_eq!(deps.update(Update::Revoke(vec![alias])), BTreeSet::from([tid]));
        assert!(deps.observe(vec![peer]).is_none());
    }

    #[test]
    fn precreation_global_revocation_is_a_socket_domain_tombstone() {
        let mut deps = Dependencies::default();
        deps.update(Update::RevokeAll);
        for (index, domain) in [(1, SocketDomain::Unix), (2, SocketDomain::TcpNoIngress)] {
            let key = socket_key(index);
            deps.update(Update::Socket { key, domain });
            assert!(deps.observe(vec![key]).is_none());
        }
    }

    #[test]
    fn pristine_connect_suspension_wakes_rejects_and_resumes_only_fresh_snapshots() {
        let mut deps = Dependencies::default();
        let key = socket_key(1);
        let Key::File(file) = key else { unreachable!() };
        deps.update(Update::Socket { key, domain: SocketDomain::Unix });
        let tid = DetTid::from_raw(2);
        let old = deps.observe(vec![key]).unwrap();
        assert!(deps.register(tid, &old));
        let probe = SocketProbe { file, attempt: 1 };
        assert_eq!(deps.update(Update::SuspendSocketProbe(probe)), BTreeSet::from([tid]));
        assert!(deps.observe(vec![key]).is_none());
        assert!(!deps.register(tid, &old));
        deps.update(Update::SettleSocketProbe { probe, no_effect: true });
        assert!(!deps.register(tid, &old));
        assert!(deps.observe(vec![key]).is_some());
        // The token cannot be reused after its settlement.
        deps.update(Update::SuspendSocketProbe(probe));
        deps.update(Update::SettleSocketProbe { probe, no_effect: true });
        assert!(deps.observe(vec![key]).is_none());
    }

    #[test]
    fn ambiguous_wrong_and_double_settlement_never_restore_authority() {
        for mode in 0..4 {
            let mut deps = Dependencies::default();
            let key = socket_key(1);
            let Key::File(file) = key else { unreachable!() };
            deps.update(Update::Socket { key, domain: SocketDomain::Unix });
            let probe = SocketProbe { file, attempt: 1 };
            deps.update(Update::SuspendSocketProbe(probe));
            match mode {
                0 => { deps.update(Update::SettleSocketProbe { probe, no_effect: false }); }
                1 => {
                    let wrong = SocketProbe { file: OpenFileId::new(DetTid::from_raw(9), 1), attempt: 1 };
                    deps.update(Update::SettleSocketProbe { probe: wrong, no_effect: true });
                }
                2 => {
                    deps.update(Update::SettleSocketProbe { probe, no_effect: true });
                    deps.update(Update::SettleSocketProbe { probe, no_effect: true });
                }
                _ => { deps.update(Update::RevokeSocketDomain(SocketDomain::Unix)); }
            }
            deps.update(Update::SettleSocketProbe { probe, no_effect: true });
            assert!(deps.observe(vec![key]).is_none());
            let fresh = socket_key(2);
            deps.update(Update::Socket { key: fresh, domain: SocketDomain::Unix });
            assert!(deps.observe(vec![fresh]).is_none());
        }
    }

    #[test]
    fn inherited_and_attached_socket_ofds_cannot_certify_pristine_connects() {
        use crate::fd::DetFd;
        use nix::fcntl::OFlag;
        let file = DetFd::new(7, OFlag::empty(), FdType::Socket,
            OpenFileId::new(DetTid::from_raw(1), 1));
        assert!(descriptor_key(&file).is_none());
        assert!(file.begin_socket_probe().is_none());
        file.set_socket_domain(SocketDomain::Unix, true);
        let alias = file.clone().with_fd(8);
        assert_eq!(file.begin_socket_probe().unwrap().attempt, 1);
        assert_eq!(alias.begin_socket_probe().unwrap().attempt, 2);
        alias.mark_socket_attached();
        assert!(file.begin_socket_probe().is_none());
    }

    #[test]
    fn native_fork_exec_preserves_alias_mutation_keys_and_failed_exec_old_table() {
        use crate::fd::DetFd;
        use crate::pipe_wake::ChannelEnd;
        use crate::tool_local::FileMetadata;
        use nix::fcntl::OFlag;

        let owner = DetTid::from_raw(1);
        let child = DetTid::from_raw(2);
        for ty in [FdType::Eventfd, FdType::Epoll, FdType::Pipe, FdType::Signalfd, FdType::Socket] {
            let id = OpenFileId::new(owner, 1);
            let mut original = FileMetadata::new(owner);
            let file = DetFd::new(7, OFlag::O_CLOEXEC, ty, id);
            if ty == FdType::Socket {
                file.set_socket_domain(SocketDomain::Unix, true);
            }
            if ty == FdType::Pipe {
                file.set_channel(ChannelEnd {
                    channel: ChannelId::Pipe(id), reads: false, writes: true,
                });
            }
            let key = descriptor_key(&file).unwrap();
            original.file_handles.insert(8, file.clone().with_fd(8).with_fd_flags(OFlag::empty()));
            original.file_handles.insert(7, file);
            let forked = original.fork_for(child);
            let replacement = forked.for_exec(child);
            assert!(!replacement.file_handles.contains_key(&7));
            assert_eq!(replacement.file_handles[&8].ty(), ty);
            assert_eq!(descriptor_key(&replacement.file_handles[&8]), Some(key));
            // A failed exec reinstates the captured old table, including CLOEXEC.
            assert_eq!(descriptor_key(&forked.file_handles[&7]), Some(key));
            assert_eq!(descriptor_key(&forked.file_handles[&8]), Some(key));

            let mut deps = Dependencies::default();
            deps.update(Update::Create(key, ty == FdType::Epoll));
            let snapshot = deps.observe(vec![key]).unwrap();
            assert!(deps.register(owner, &snapshot));
            deps.update(Update::Change(vec![key])); // Prepared native exec.
            let after_exec = deps.observe(vec![key]).unwrap();
            assert!(deps.register(owner, &after_exec));
            let survivor_key = descriptor_key(&replacement.file_handles[&8]).unwrap();
            assert_eq!(deps.update(Update::Change(vec![survivor_key])), BTreeSet::from([owner]));
            assert!(deps.observe(vec![key]).is_some());
        }
    }
    #[test]
    fn ioctl_queries_require_known_ordinary_objects_and_readonly_requests() {
        for request in [libc::TCGETS as u64, libc::TIOCGWINSZ as u64, libc::FIONREAD as u64] {
            assert!(readonly_ioctl(FdType::Regular, Some((libc::S_IFREG, 0)), request));
            assert!(readonly_ioctl(FdType::Pipe, None, request));
            assert!(!readonly_ioctl(FdType::Regular, None, request));
            assert!(!readonly_ioctl(FdType::Regular, Some((libc::S_IFCHR, 0)), request));
        }
        assert!(!readonly_ioctl(FdType::Regular, Some((libc::S_IFREG, 0)), libc::FIONBIO as u64));
    }

    #[test]
    fn terminal_queries_on_identified_memory_devices_do_not_revoke_authority() {
        for minor in [3, 5, 7] {
            let stat = Some((libc::S_IFCHR, libc::makedev(1, minor)));
            for request in [libc::TCGETS as u64, libc::TIOCGWINSZ as u64] {
                assert!(readonly_ioctl(FdType::Regular, stat, request));
                assert!(!readonly_ioctl(FdType::Regular, None, request));
                for unknown in [libc::makedev(1, 1), libc::makedev(4, minor)] {
                    assert!(!readonly_ioctl(FdType::Regular, Some((libc::S_IFCHR, unknown)), request));
                }
            }
            for request in [libc::TCSETS as u64, libc::TIOCSWINSZ as u64, libc::FIONREAD as u64, u64::MAX] {
                assert!(!readonly_ioctl(FdType::Regular, stat, request));
            }
        }
    }
    #[test]
    fn descriptor_flag_ioctls_do_not_admit_device_or_signal_mutations() {
        for request in [libc::FIONBIO, libc::FIOCLEX, libc::FIONCLEX] {
            assert!(descriptor_flags_ioctl(request as u64));
        }
        for request in [libc::FIOASYNC, libc::TIOCSTI, libc::TCGETS] {
            assert!(!descriptor_flags_ioctl(request as u64));
        }
    }
    #[test]
    fn generation_change_cancels_every_subscription() {
        let mut deps = Dependencies::default();
        let key = key();
        deps.update(Update::Create(key, false));
        let snapshot = deps.observe(vec![key]).unwrap();
        let tid = DetTid::from_raw(2);
        assert!(deps.register(tid, &snapshot));
        assert_eq!(
            deps.update(Update::Change(vec![key])),
            BTreeSet::from([tid])
        );
        assert!(!deps.register(tid, &snapshot));
        assert!(deps.waits.is_empty());
        assert!(deps.sources[&key].subscribers.is_empty());
    }
    #[test]
    fn cancellation_and_revocation_never_leave_waiters() {
        let mut deps = Dependencies::default();
        let key = key();
        deps.update(Update::Create(key, false));
        let snapshot = deps.observe(vec![key]).unwrap();
        let tid = DetTid::from_raw(2);
        assert!(deps.register(tid, &snapshot));
        assert!(deps.cancel(tid));
        assert!(!deps.cancel(tid));
        assert!(deps.register(tid, &snapshot));
        assert_eq!(
            deps.update(Update::Revoke(vec![key])),
            BTreeSet::from([tid])
        );
        assert!(deps.observe(vec![key]).is_none());
        assert!(!deps.register(tid, &snapshot));
    }
    #[test]
    fn nested_graph_mutation_wakes_all_waiters_in_tid_order() {
        let mut deps = Dependencies::default();
        let leaf = key();
        let inner_id = OpenFileId::new(DetTid::from_raw(1), 2);
        let outer = Key::File(OpenFileId::new(DetTid::from_raw(1), 3));
        let inner = Key::File(inner_id);
        deps.update(Update::Create(leaf, false));
        deps.update(Update::Create(inner, true));
        deps.update(Update::Create(outer, true));
        deps.update(Update::Epoll {
            epoll: inner,
            fd: 7,
            identity: Some(OpenFileId::new(DetTid::from_raw(1), 1)),
            target: Some(leaf),
            operation: libc::EPOLL_CTL_ADD,
        });
        deps.update(Update::Epoll {
            epoll: outer,
            fd: 8,
            identity: Some(inner_id),
            target: Some(inner),
            operation: libc::EPOLL_CTL_ADD,
        });
        let snapshot = deps.observe(vec![outer]).unwrap();
        assert_eq!(snapshot.0.len(), 3);
        for tid in [9, 4, 6] {
            assert!(deps.register(DetTid::from_raw(tid), &snapshot));
        }
        let wake = deps.update(Update::Change(vec![leaf]));
        assert_eq!(
            wake.into_iter().map(|tid| tid.as_raw()).collect::<Vec<_>>(),
            vec![4, 6, 9]
        );
        assert!(
            deps.sources
                .values()
                .all(|source| source.subscribers.is_empty())
        );
        assert!(!deps.register(DetTid::from_raw(4), &snapshot));
    }

    #[test]
    fn epoll_registration_identity_does_not_merge_pipe_ends_or_reused_fds() {
        let mut deps = Dependencies::default();
        let leaf = key();
        let epoll = Key::File(OpenFileId::new(DetTid::from_raw(1), 2));
        deps.update(Update::Create(leaf, false));
        deps.update(Update::Create(epoll, true));
        for sequence in [3, 4] {
            deps.update(Update::Epoll {
                epoll,
                fd: 7,
                identity: Some(OpenFileId::new(DetTid::from_raw(1), sequence)),
                target: Some(leaf),
                operation: libc::EPOLL_CTL_ADD,
            });
        }
        deps.update(Update::Epoll {
            epoll,
            fd: 7,
            identity: Some(OpenFileId::new(DetTid::from_raw(1), 3)),
            target: Some(leaf),
            operation: libc::EPOLL_CTL_DEL,
        });
        assert_eq!(deps.sources[&epoll].interests.as_ref().unwrap().len(), 1);
        assert!(
            deps.observe(vec![epoll])
                .unwrap()
                .0
                .iter()
                .any(|(key, _)| *key == leaf)
        );
    }

    #[test]
    fn unknown_epoll_leaf_falls_back_and_del_restores_authority() {
        let mut deps = Dependencies::default();
        let epoll = key();
        deps.update(Update::Create(epoll, true));
        deps.update(Update::Epoll {
            epoll,
            fd: 7,
            identity: None,
            target: None,
            operation: libc::EPOLL_CTL_ADD,
        });
        assert!(deps.observe(vec![epoll]).is_none());
        deps.update(Update::Epoll {
            epoll,
            fd: 7,
            identity: None,
            target: None,
            operation: libc::EPOLL_CTL_DEL,
        });
        assert!(deps.observe(vec![epoll]).is_some());
    }

    #[test]
    fn generation_exhaustion_revokes_instead_of_reusing_a_snapshot() {
        let mut deps = Dependencies::default();
        let key = key();
        deps.update(Update::Create(key, false));
        deps.sources.get_mut(&key).unwrap().generation = u64::MAX;
        let snapshot = deps.observe(vec![key]).unwrap();
        let tid = DetTid::from_raw(2);
        assert!(deps.register(tid, &snapshot));
        assert_eq!(
            deps.update(Update::Change(vec![key])),
            BTreeSet::from([tid])
        );
        assert!(deps.observe(vec![key]).is_none());
        assert!(!deps.register(tid, &snapshot));
    }

    #[test]
    fn table_divergence_disables_future_objects_and_cancels_existing_waits() {
        let mut deps = Dependencies::default();
        let key = key();
        deps.update(Update::Create(key, false));
        let snapshot = deps.observe(vec![key]).unwrap();
        let tid = DetTid::from_raw(2);
        assert!(deps.register(tid, &snapshot));
        assert_eq!(deps.update(Update::Disable), BTreeSet::from([tid]));
        let fresh = Key::File(OpenFileId::new(DetTid::from_raw(1), 2));
        deps.update(Update::Create(fresh, false));
        assert!(deps.observe(vec![fresh]).is_none());
        assert!(!deps.register(tid, &snapshot));
        assert!(deps.waits.is_empty());
    }
    #[test]
    fn exported_source_does_not_revoke_unrelated_objects() {
        let mut deps = Dependencies::default();
        let exported = key();
        let local = Key::File(OpenFileId::new(DetTid::from_raw(1), 2));
        deps.update(Update::Create(exported, false));
        deps.update(Update::Create(local, false));
        let first = DetTid::from_raw(2);
        let second = DetTid::from_raw(3);
        let exported_snapshot = deps.observe(vec![exported]).unwrap();
        let local_snapshot = deps.observe(vec![local]).unwrap();
        assert!(deps.register(first, &exported_snapshot));
        assert!(deps.register(second, &local_snapshot));
        assert_eq!(
            deps.update(Update::Revoke(vec![exported])),
            BTreeSet::from([first])
        );
        assert!(deps.waits.contains_key(&second));
        assert!(deps.observe(vec![local]).is_some());
        assert!(deps.observe(vec![exported]).is_none());
        assert_eq!(
            deps.update(Update::Change(vec![local])),
            BTreeSet::from([second])
        );
    }
    fn observer(thread: i32, process: i32) -> Observer {
        let thread = DetTid::from_raw(thread);
        Observer {
            thread,
            process: DetPid::from_raw(process),
            mm: MmId::initial(thread),
            excluded_signals: 0,
        }
    }

    fn bit(signal: i32) -> u64 {
        1u64 << (signal - 1)
    }

    fn signalfd(deps: &mut Dependencies, key: Key, mask: u64) {
        deps.update(Update::Signalfd { key, mask: Some(mask), create: true });
    }

    fn signal_snapshot(deps: &mut Dependencies, keys: Vec<Key>, who: Observer) -> Snapshot {
        deps.observe_from(keys, true, Some(who)).unwrap()
    }

    #[test]
    fn signalfd_private_and_process_dependencies_are_observer_relative() {
        let mut deps = Dependencies::default();
        let fd = key();
        signalfd(&mut deps, fd, bit(libc::SIGUSR1));
        let first = observer(10, 10);
        let sibling = observer(11, 10);
        let foreign = observer(20, 20);
        for who in [first, sibling, foreign] {
            let snapshot = signal_snapshot(&mut deps, vec![fd], who);
            assert!(deps.register(who.thread, &snapshot));
        }
        assert!(deps.update(Update::SignalChange {
            queue: QueueId::Thread(first.thread), signals: bit(libc::SIGUSR2),
        }).is_empty());
        assert_eq!(deps.update(Update::SignalChange {
            queue: QueueId::Thread(first.thread), signals: bit(libc::SIGUSR1),
        }), BTreeSet::from([first.thread]));
        let snapshot = signal_snapshot(&mut deps, vec![fd], first);
        assert!(deps.register(first.thread, &snapshot));
        assert_eq!(deps.update(Update::SignalChange {
            queue: QueueId::Process(first.process), signals: bit(libc::SIGUSR1),
        }), BTreeSet::from([first.thread, sibling.thread]));
        assert!(deps.waits.contains_key(&foreign.thread));
    }

    #[test]
    fn signalfd_overlapping_masks_share_only_matching_signal_generations() {
        let mut deps = Dependencies::default();
        let first = key();
        let second = Key::File(OpenFileId::new(DetTid::from_raw(1), 2));
        signalfd(&mut deps, first, bit(libc::SIGUSR1));
        signalfd(&mut deps, second, bit(libc::SIGUSR1) | bit(libc::SIGUSR2));
        let a = observer(10, 10);
        let b = observer(11, 10);
        let sa = signal_snapshot(&mut deps, vec![first], a);
        let sb = signal_snapshot(&mut deps, vec![second], b);
        assert!(deps.register(a.thread, &sa));
        assert!(deps.register(b.thread, &sb));
        assert_eq!(deps.update(Update::SignalChange {
            queue: QueueId::Process(a.process), signals: bit(libc::SIGUSR2),
        }), BTreeSet::from([b.thread]));
        assert!(deps.waits.contains_key(&a.thread));
        assert!(!deps.register(b.thread, &sb));
        let fresh = signal_snapshot(&mut deps, vec![second], b);
        assert!(deps.register(b.thread, &fresh));
        assert_eq!(deps.update(Update::SignalChange {
            queue: QueueId::Process(a.process), signals: bit(libc::SIGUSR1),
        }), BTreeSet::from([a.thread, b.thread]));
    }

    #[test]
    fn signalfd_send_and_mask_replace_invalidate_preprobe_snapshots() {
        let mut deps = Dependencies::default();
        let fd = key();
        let who = observer(10, 10);
        signalfd(&mut deps, fd, bit(libc::SIGUSR1));
        let old = signal_snapshot(&mut deps, vec![fd], who);
        deps.update(Update::SignalChange {
            queue: QueueId::Process(who.process), signals: bit(libc::SIGUSR1),
        });
        assert!(!deps.register(who.thread, &old));
        let old = signal_snapshot(&mut deps, vec![fd], who);
        assert!(deps.register(who.thread, &old));
        assert_eq!(deps.update(Update::Signalfd {
            key: fd, mask: Some(bit(libc::SIGUSR2)), create: false,
        }), BTreeSet::from([who.thread]));
        assert!(!deps.register(who.thread, &old));
        let fresh = signal_snapshot(&mut deps, vec![fd], who);
        assert!(deps.register(who.thread, &fresh));
        assert!(deps.update(Update::SignalChange {
            queue: QueueId::Process(who.process), signals: bit(libc::SIGUSR1),
        }).is_empty());
        assert_eq!(deps.update(Update::SignalChange {
            queue: QueueId::Process(who.process), signals: bit(libc::SIGUSR2),
        }), BTreeSet::from([who.thread]));
    }

    #[test]
    fn signalfd_unknown_masks_updates_and_revoked_ofds_never_gain_authority() {
        let who = observer(10, 10);
        for mask in [None, Some(bit(libc::SIGCHLD))] {
            let mut deps = Dependencies::default();
            deps.update(Update::Signalfd { key: key(), mask, create: true });
            assert!(deps.observe_from(vec![key()], true, Some(who)).is_none());
        }
        let mut deps = Dependencies::default();
        deps.update(Update::Signalfd { key: key(), mask: Some(bit(libc::SIGUSR1)), create: false });
        assert!(deps.observe_from(vec![key()], true, Some(who)).is_none());
        signalfd(&mut deps, key(), bit(libc::SIGUSR1));
        assert!(deps.observe(vec![key()]).is_none());
        deps.update(Update::Revoke(vec![key()]));
        signalfd(&mut deps, key(), bit(libc::SIGUSR2));
        assert!(deps.observe_from(vec![key()], true, Some(who)).is_none());
    }

    #[test]
    fn signalfd_host_exclusion_revokes_registered_and_inflight_dependencies() {
        for container in [false, true] {
            let mut deps = Dependencies::default();
            let fd = key();
            signalfd(&mut deps, fd, bit(libc::SIGUSR1));
            let a = observer(10, 10);
            let b = observer(20, 20);
            let sa = signal_snapshot(&mut deps, vec![fd], a);
            let sb = signal_snapshot(&mut deps, vec![fd], b);
            assert!(deps.register(a.thread, &sa));
            let process = (!container).then_some(a.process);
            assert_eq!(deps.exclude_signals(process, bit(libc::SIGUSR1)), BTreeSet::from([a.thread]));
            assert!(!deps.register(a.thread, &sa));
            assert_eq!(deps.register(b.thread, &sb), !container);
            assert!(deps.observe_from(vec![fd], true, Some(a)).is_none());
            assert_eq!(deps.observe_from(vec![fd], true, Some(b)).is_some(), !container);
        }
        let mut deps = Dependencies::default();
        let who = observer(10, 10);
        deps.exclude_signals(Some(who.process), bit(libc::SIGUSR1));
        signalfd(&mut deps, key(), bit(libc::SIGUSR1));
        assert!(deps.observe_from(vec![key()], true, Some(who)).is_none());
    }

    fn epoll_interest(deps: &mut Dependencies, epoll: Key, target: Key, operation: i32, who: Observer) {
        deps.update_from(Update::Epoll {
            epoll, fd: 7, identity: Some(OpenFileId::new(DetTid::from_raw(1), 1)),
            target: Some(target), operation,
        }, Some(who));
    }

    #[test]
    fn signalfd_epoll_mod_retains_add_context_and_del_allows_fresh_add() {
        let mut deps = Dependencies::default();
        let fd = key();
        let epoll = Key::File(OpenFileId::new(DetTid::from_raw(1), 2));
        let parent = observer(10, 10);
        let child = observer(20, 20);
        signalfd(&mut deps, fd, bit(libc::SIGUSR1));
        deps.update(Update::Create(epoll, true));
        epoll_interest(&mut deps, epoll, fd, libc::EPOLL_CTL_ADD, parent);
        assert!(deps.observe_from(vec![epoll], true, Some(parent)).is_some());
        assert!(deps.observe_from(vec![epoll], true, Some(child)).is_none());
        epoll_interest(&mut deps, epoll, fd, libc::EPOLL_CTL_MOD, child);
        assert!(deps.observe_from(vec![epoll], true, Some(child)).is_none());
        assert!(deps.observe_from(vec![epoll], true, Some(parent)).is_some());
        epoll_interest(&mut deps, epoll, fd, libc::EPOLL_CTL_DEL, child);
        epoll_interest(&mut deps, epoll, fd, libc::EPOLL_CTL_ADD, child);
        assert!(deps.observe_from(vec![epoll], true, Some(child)).is_some());
    }

    #[test]
    fn signalfd_nested_revisits_validate_each_add_context() {
        let mut deps = Dependencies::default();
        let fd = key();
        let inner = Key::File(OpenFileId::new(DetTid::from_raw(1), 2));
        let outer = Key::File(OpenFileId::new(DetTid::from_raw(1), 3));
        let parent = observer(10, 10);
        let child = observer(20, 20);
        signalfd(&mut deps, fd, bit(libc::SIGUSR1));
        deps.update(Update::Create(inner, true));
        deps.update(Update::Create(outer, true));
        epoll_interest(&mut deps, inner, fd, libc::EPOLL_CTL_ADD, child);
        epoll_interest(&mut deps, outer, inner, libc::EPOLL_CTL_ADD, parent);
        // The first root is compatible. The second reaches those same nodes
        // through an inherited edge and must not be skipped as already seen.
        assert!(deps.observe_from(vec![inner, outer], true, Some(child)).is_none());
        assert!(deps.observe_from(vec![fd, outer], true, Some(child)).is_none());
    }
}
