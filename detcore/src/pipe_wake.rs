/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Handing the turn to a thread polling a pipe or FIFO once another thread's
//! action has readied it (`--pipe-wake-latency`,
//! <https://github.com/rrnewton/hermit/issues/4380>).
//!
//! A polled read of a scheduler-managed pipe retries in polling turns that
//! back off in priority. A write that gives it data takes no turn, so without
//! this the reader waits until the writer's slice ends (200 ms of virtual
//! time by default), or for ever where no slice end is set. With the option
//! on:
//!
//! 1. A poll names the channel it waits on and what it wants
//!    (`Resources::polls_channel`).
//! 2. An action that can satisfy such a poll, checked on each attempt's own
//!    result while the acting thread holds the grant, reports the channel to
//!    the scheduler (`ReadyChannel`), which restores the priority of every
//!    queued poller of that channel and want, skipping doomed ones, and
//!    remembers them for the actor.
//! 3. Once the actor's own time is the latency past its first readying
//!    action, at a syscall boundary, the scheduler moves the actor behind
//!    those pollers (`HandOff`) and the actor yields, so they run first.
//!
//! Every input is guest state read in committed turns, so the hand-offs
//! happen at the same turns in every run and in a replay made with the same
//! option. `--event-driven-io` also uses channel identities and committed
//! mutation reports, but indexes parked subscriptions instead of scanning the
//! runnable pollers. With both options unset, no channel or RPC is added.

use detcore_model::fd::OpenFileId;
use serde::Deserialize;
use serde::Serialize;

/// The pipe or FIFO a descriptor is an end of.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize
)]
pub enum ChannelId {
    /// A pipe made by `pipe2`, named by its read end's open file description,
    /// which `pipe2` stores on both ends. Carried across a rediscovering exec
    /// (`ExecFdState::channels`).
    Pipe(OpenFileId),
    /// A FIFO, where the guest's descriptors are visible to the tool
    /// (`fifo_peer::guest_descriptors_are_visible`), named by the ordinal
    /// `fifo_peer::fifo_channel` gives its host `(dev, ino)`: the host numbers
    /// differ between runs, and polls log their channel.
    Fifo(u64),
}

/// One end of a channel, as an open file description holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelEnd {
    /// The pipe or FIFO.
    pub channel: ChannelId,
    /// Whether this end reads (a pipe's read end, a FIFO opened for reading
    /// or for both).
    pub reads: bool,
    /// Whether this end writes.
    pub writes: bool,
}

impl ChannelEnd {
    /// What closing this end readies: the readers of the channel (end of
    /// file) when it writes, and its writers (`EPIPE`) when it reads. It
    /// need not be the last end; a false hand-off changes no result.
    pub fn close_readies(&self) -> impl Iterator<Item = Wants> {
        [(self.writes, Wants::Data), (self.reads, Wants::Space)]
            .into_iter()
            .filter_map(|(applies, wants)| applies.then_some(wants))
    }
}

/// What a poll of a channel waits for, and so which action readies it.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize
)]
pub enum Wants {
    /// A read: data, or the end of file a write end's close gives.
    Data,
    /// A write: room, or the `EPIPE` a read end's close gives.
    Space,
    /// A blocking FIFO open for reading, waiting for a writer.
    PeerWriter,
    /// A blocking FIFO open for writing, waiting for a reader.
    PeerReader,
}

/// What the scheduler answers a readying report (`Scheduler::ready_channel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReadyOutcome {
    /// The acting thread now has pollers to hand the turn to.
    pub has_pending: bool,
    /// This report found the first of them since the acting thread's last
    /// committed turn, so its latency starts now. The scheduler forgets a
    /// thread's pollers at every committed turn of its own, whichever request
    /// that turn granted (a futex wait as well as a resource request), so the
    /// window is the scheduler's, and the thread keeps no copy of it.
    pub starts_window: bool,
}

/// The descriptor a polled `call` waits on, and what for: a read waits for
/// data, a write for room.
pub(crate) fn poll_of(
    call: &reverie::syscalls::Syscall,
) -> Option<(std::os::unix::io::RawFd, Wants)> {
    progress_of(call).map(|(fd, readies)| {
        (
            fd,
            match readies {
                Wants::Data => Wants::Space,
                _ => Wants::Data,
            },
        )
    })
}

/// The descriptor a successful `call` moved bytes through, and what that
/// readies on its channel: a write gives the readers data, a read gives the
/// writers room.
pub(crate) fn progress_of(
    call: &reverie::syscalls::Syscall,
) -> Option<(std::os::unix::io::RawFd, Wants)> {
    use reverie::syscalls::Syscall;
    match call {
        Syscall::Write(write) => Some((write.fd(), Wants::Data)),
        Syscall::Writev(writev) => Some((writev.fd(), Wants::Data)),
        // Only at the current position can these move bytes through a pipe
        // (an explicit offset fails with ESPIPE there), where Detcore runs
        // them as `writev` and `readv`.
        Syscall::Pwritev2(pwritev2) => Some((pwritev2.fd(), Wants::Data)),
        Syscall::Read(read) => Some((read.fd(), Wants::Space)),
        Syscall::Readv(readv) => Some((readv.fd(), Wants::Space)),
        Syscall::Preadv2(preadv2) => Some((preadv2.fd(), Wants::Space)),
        _ => None,
    }
}

/// A fresh kernel witness for an explicit anonymous-pipe close, never a
/// reference-count or cached-readiness guess. Only native ptrace's serialized
/// injection/lifecycle barriers are established here; other backends fall back.
pub(crate) async fn close_keeps_peer<G, T>(
    guest: &mut G,
    channel: ChannelId,
    closed_reads: bool,
    closed_writes: bool,
) -> bool
where
    G: reverie::Guest<crate::Detcore<T>>,
    T: crate::record_or_replay::RecordOrReplay,
{
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (guest, channel, closed_reads, closed_writes);
        false
    }
    #[cfg(target_arch = "x86_64")]
    {
        use crate::event_driven_io::{Key, Update};
        use reverie::syscalls::{Poll, Syscall};

        let ChannelId::Pipe(original_reader) = channel else {
            return false;
        };
        if !guest.config().event_driven_io
            || guest.config().pipe_wake_latency_in_effect().is_some()
            || guest.config().recordreplay_modes
            || !guest.config().sequentialize_threads
            || guest.config().backend != reverie::BackendCapabilities::PTRACE
            || !(closed_reads || closed_writes)
        {
            return false;
        }
        // The table is already updated. In particular a close_range witness
        // must survive the entire range, not merely the first removed alias.
        let (reader, writer) = {
            let table = guest.thread_state().file_metadata.lock().unwrap();
            // A sibling sharing this table may be parked on the replaced
            // descriptor number, even while another alias keeps its OFD alive.
            // Its binding change must wake independently of pipe lifetime.
            let Some(process) = guest.thread_state().detpid else {
                return false;
            };
            if !table.has_only_holder(process) {
                return false;
            }
            let mut reader: Option<i32> = None;
            let mut writer: Option<i32> = None;
            for (&fd, file) in &table.file_handles {
                if !file.is_guest_held() {
                    continue;
                }
                let Some(end) = file.channel().filter(|end| end.channel == channel) else {
                    continue;
                };
                // Linux suppresses HUP for a newly opened FIFO reader before
                // its first writer. Only pipe2's original read OFD (or its
                // aliases) has the established zero-vs-one writer generation.
                if closed_writes && end.reads && !end.writes
                    && file.open_file_id() == original_reader
                {
                    reader = Some(reader.map_or(fd, |old| old.min(fd)));
                }
                if closed_reads && end.writes && !end.reads {
                    writer = Some(writer.map_or(fd, |old| old.min(fd)));
                }
            }
            (reader, writer)
        };
        if (closed_writes && reader.is_none()) || (closed_reads && writer.is_none()) {
            return false;
        }
        // guest_held alone is not authority: SCM_RIGHTS, reopened pipes,
        // untracked producers, async IO and fatal signals revoke dependencies.
        // Observe neither registers a waiter nor grants another guest a turn.
        if crate::tool_global::event_driven_io(
            guest, Update::Observe(vec![Key::Pipe(channel)], false),
        ).await.is_none() {
            return false;
        }
        for fd in [reader, writer].into_iter().flatten() {
            let mut initial = [0u8; std::mem::size_of::<libc::pollfd>()];
            initial[..std::mem::size_of::<i32>()].copy_from_slice(&fd.to_ne_bytes());
            // events=0: HUP/ERR/NVAL are returned unconditionally. No data is
            // read, no space consumed and no persistent poll registration made.
            // Ptrace executes the next injection through userspace: the close's
            // task_work fput has run before this poll. Other implicit releases
            // are covered by native exit/exec barriers or authority revocation.
            let probe = crate::syscalls::scratch::inject_with_scratch(guest, initial, |buffer| {
                Syscall::from(Poll::new().with_fds(Some(buffer.cast())).with_nfds(1).with_timeout(0))
            }).await;
            let Ok((0, bytes)) = probe else {
                return false;
            };
            let offset = std::mem::offset_of!(libc::pollfd, revents);
            if i16::from_ne_bytes([bytes[offset], bytes[offset + 1]]) != 0 {
                return false;
            }
        }
        true
    }
}

impl<T: crate::record_or_replay::RecordOrReplay> crate::Detcore<T> {
    /// The channel end behind `fd` when either pipe handoff or dependency
    /// waiting is enabled and Detcore knows its provenance.
    pub(crate) fn pipe_channel_end<G: reverie::Guest<Self>>(
        &self,
        guest: &G,
        fd: std::os::unix::io::RawFd,
    ) -> Option<ChannelEnd> {
        if self.cfg.pipe_wake_latency_in_effect().is_none() && !self.cfg.event_driven_io {
            return None;
        }
        guest
            .thread_state()
            .with_detfd(fd, |detfd| detfd.channel())
            .ok()
            .flatten()
    }

    /// An action of this thread may satisfy the pollers of `channel` that
    /// want `wants`: report it to the scheduler, and if the report starts a
    /// window of pollers to hand off to, start the latency toward this
    /// thread's hand-off.
    pub(crate) async fn note_pipe_readied<G: reverie::Guest<Self>>(
        &self,
        guest: &mut G,
        channel: ChannelId,
        wants: Wants,
    ) {
        if self.cfg.event_driven_io {
            crate::tool_global::event_driven_io(
                guest,
                crate::event_driven_io::Update::Change(vec![crate::event_driven_io::Key::Pipe(channel)]),
            ).await;
        }
        let Some(latency) = self.cfg.pipe_wake_latency_in_effect() else {
            return;
        };
        let outcome = crate::tool_global::ready_channel(guest, channel, wants).await;
        if outcome.has_pending
            && (outcome.starts_window || guest.thread_state().pipe_handoff_due.is_none())
        {
            let due = guest.thread_state().thread_logical_time.as_nanos()
                + std::time::Duration::from_nanos(latency);
            guest.thread_state_mut().pipe_handoff_due = Some(due);
        }
    }

    /// [`Self::note_pipe_readied`] for an action on the guest descriptor
    /// `fd`, if it is an end of a known channel.
    pub(crate) async fn note_fd_readied<G: reverie::Guest<Self>>(
        &self,
        guest: &mut G,
        fd: std::os::unix::io::RawFd,
        wants: Wants,
    ) {
        if let Some(end) = self.pipe_channel_end(guest, fd) {
            self.note_pipe_readied(guest, end.channel, wants).await;
        }
    }

    /// At a syscall boundary: if this thread's hand-off is due, let the
    /// scheduler move it behind the pollers it readied, and yield to them.
    /// Deferred while the thread holds its turn for a signal to its own
    /// process (`own_signal_turn_hold`). The yield is a turn of its own,
    /// outside the timeslice bookkeeping, as the futex wake's is.
    pub(crate) async fn pipe_hand_off_if_due<G: reverie::Guest<Self>>(&self, guest: &mut G) {
        let Some(due) = guest.thread_state().pipe_handoff_due else {
            return;
        };
        if guest.thread_state().own_signal_turn_hold.is_some()
            || guest.thread_state().thread_logical_time.as_nanos() < due
        {
            return;
        }
        guest.thread_state_mut().pipe_handoff_due = None;
        if crate::tool_global::hand_off_turn(guest).await {
            tracing::trace!(
                "[dtid {}] handing the turn to the pollers it readied",
                guest.thread_state().dettid
            );
            let request = Self::yield_request(guest);
            crate::tool_global::resource_request(guest, request).await;
        }
    }

    /// Known channel ends among `first..=last` in descriptor order, when
    /// pipe handoff or dependency waiting is enabled.
    pub(crate) fn pipe_channel_ends_in<G: reverie::Guest<Self>>(
        &self,
        guest: &G,
        first: u32,
        last: u32,
    ) -> Vec<ChannelEnd> {
        if (self.cfg.pipe_wake_latency_in_effect().is_none() && !self.cfg.event_driven_io) || first > last {
            return Vec::new();
        }
        guest
            .thread_state()
            .open_fds()
            .into_iter()
            .filter(|fd| u32::try_from(*fd).is_ok_and(|fd| (first..=last).contains(&fd)))
            .filter_map(|fd| self.pipe_channel_end(guest, fd))
            .collect()
    }

    /// Keep FIFO notifications and the latency policy at their original point,
    /// including event publication before latency handoff when both are enabled.
    /// Otherwise anonymous-pipe dependency mutations are published once by
    /// `event_driven_io::after_binding_changes`. Exit/exec keeps its own barrier.
    pub(crate) async fn note_channel_end_closed<G: reverie::Guest<Self>>(
        &self,
        guest: &mut G,
        end: Option<ChannelEnd>,
    ) {
        let Some(end) = end else {
            return;
        };
        if matches!(end.channel, ChannelId::Fifo(_))
            || self.cfg.pipe_wake_latency_in_effect().is_some()
        {
            for wants in end.close_readies() {
                self.note_pipe_readied(guest, end.channel, wants).await;
            }
        }
    }
}
