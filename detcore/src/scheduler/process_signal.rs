//! A native process-shared send remains reserved until its actual dequeue.
//!
//! As with `sigchld_takers`, ptrace-stopped peers cannot take a shared copy:
//! only the reserved recipient resumes. Unlike the SIGCHLD preference, this
//! reservation is mandatory and never silently falls back to another thread.

use super::*;

#[derive(Clone, Copy, Debug)]
pub(super) struct ProcessSignalReservation {
    sender: DetTid,
    recipient: DetTid,
    signal: i32,
    interrupt_errno: Option<i32>,
    committed: bool,
    guest_mask: u64,
    private_guard: Option<u64>,
    guard_restored: bool,
    expected_siginfo: Option<signal_lists::KernelSiginfo>,
    held_authenticated: bool,
    dequeue_authenticated: bool,
}

impl Scheduler {
    /// Reserve a caught standard signal for the eligible leader, or for the
    /// sole eligible nonleader. All peers remain stopped through its dequeue.
    /// Its restartable poll, native epoll_wait, or expired CPU slice is supported.
    /// Only a proven plain-epoll guard may replace a native mask; arbitrary
    /// private masks, exiting, group-stopped and kernel-running tasks refuse.
    pub(crate) fn reserve_process_signal(
        &mut self,
        sender: DetTid,
        process: DetPid,
        signal: i32,
    ) -> Option<DetTid> {
        if self.backend != BackendCapabilities::PTRACE
            || !self.models_signal_targets
            || self.in_guest_signal_delivery
            || self.process_signal_reservation.is_some()
            || !self.holds_serial_grant(sender)
            || self.sigchld_process(sender) == process
            || !(1..32).contains(&signal)
            || self.exec_teardowns.contains_key(&process)
            || self.guest_sent_marker_signal
            || self.signalfd_masks.contains_key(&process)
            || !self.thread_tree.unreaped_children_of(process).is_empty()
            || self.blocked.timed_waiters.iter().any(|(_, event)| {
                matches!(event, TimedEvent::SignalEvt(id, _, _) if id.process() == process)
            })
        {
            tracing::debug!(
                ?sender, ?process, signal,
                ptrace = (self.backend == BackendCapabilities::PTRACE),
                models_targets = self.models_signal_targets,
                in_guest = self.in_guest_signal_delivery,
                reserved = self.process_signal_reservation.is_some(),
                serial_grant = self.holds_serial_grant(sender),
                same_process = (self.sigchld_process(sender) == process),
                exec = self.exec_teardowns.contains_key(&process),
                guest_marker = self.guest_sent_marker_signal,
                signalfd = self.signalfd_masks.contains_key(&process),
                children = ?self.thread_tree.unreaped_children_of(process),
                signal_timer = self.blocked.timed_waiters.iter().any(|(_, event)| {
                    matches!(event, TimedEvent::SignalEvt(id, _, _) if id.process() == process)
                }),
                "process_signal_preflight_rejected: process state"
            );
            return None;
        }
        let threads = self.process_signal_targets(process);
        if threads.len() < 2 {
            return None;
        }
        let bit = kernel_signal_bit(signal);
        let marker = kernel_signal_bit(reverie::PERF_EVENT_SIGNAL as i32);
        let mut first = None;
        let mut leader = None;
        let mut eligible = 0;
        for thread in threads {
            let Some(state) = self.reserved_signal_state(thread) else {
                tracing::debug!(
                    ?thread,
                    signal,
                    "process_signal_preflight_rejected: unreadable signal state"
                );
                return None;
            };
            let effective_mask = self.process_signal_effective_mask(thread, &state);
            if !matches!(
                self.sibling_signal_state(thread),
                SiblingSignalState::InSchedule(Some(_))
            ) || effective_mask.is_none()
                || self.sigtimedwait_sets.contains_key(&thread)
                // SIGKILL cannot run a handler or coalesce with this caught
                // signal. Keep its source tracked, but do not confuse arming
                // parent-death termination with a competing caught delivery.
                || self.host_timed_signals(thread) & !kernel_signal_bit(libc::SIGKILL) != 0
                || self.read_task_state(thread) != Ok('t')
                || !self
                    .next_turns
                    .get(&thread)
                    .is_some_and(|next| matches!(next.req.try_read(), Some(Ok(_))))
                || (!cfg!(test) && crate::sigalrm_phase1::process_holds_signalfd(thread.as_raw()))
            {
                tracing::debug!(
                    ?thread, signal,
                    sibling = ?self.sibling_signal_state(thread),
                    saved_mask = ?self.saved_guest_sigmasks.get(&thread),
                    native_blocked = state.blocked,
                    native_epoll_guard = ?self.native_epoll_guards.get(&thread),
                    waiter = self.sigtimedwait_sets.contains_key(&thread),
                    host_signals = self.host_timed_signals(thread),
                    task_state = ?self.read_task_state(thread),
                    request = ?self.next_turns.get(&thread).and_then(|next| next.req.try_read()),
                    signalfd = (!cfg!(test) && crate::sigalrm_phase1::process_holds_signalfd(thread.as_raw())),
                    "process_signal_preflight_rejected: thread state"
                );
                return None;
            }
            if state.caught & bit == 0
                || state.ignored & bit != 0
                || state.shared_pending != 0
                || state.thread_pending & !marker != 0
            {
                tracing::debug!(
                    ?thread,
                    signal,
                    blocked = state.blocked,
                    caught = state.caught,
                    ignored = state.ignored,
                    shared_pending = state.shared_pending,
                    thread_pending = state.thread_pending,
                    "process_signal_preflight_rejected: signal state"
                );
                return None;
            }
            let effective_mask = effective_mask?;
            if effective_mask & bit == 0 {
                // A waiter is not a handler recipient; do not fold its wait set
                // into a mask, as the own-process sibling exclusion can do.
                eligible += 1;
                first.get_or_insert((thread, effective_mask));
                if thread.as_raw() == process.as_raw() {
                    leader = Some((thread, effective_mask));
                }
            }
        }
        // The leader is Linux's preferred process recipient. For a blocked
        // leader, do not invent a policy between several eligible siblings.
        let Some((recipient, guest_mask)) =
            leader.or_else(|| if eligible == 1 { first } else { None })
        else {
            tracing::debug!(
                ?process,
                signal,
                eligible,
                "process_signal_preflight_rejected: recipient ambiguity"
            );
            return None;
        };
        let next = self.next_turns.get(&recipient)?.req.try_read()?.ok()?;
        let poll = next.resources.len() == 1
            && next.resources.get(&ResourceID::InternalIOPolling) == Some(&Permission::W)
            && (next.signal_interrupt_errno() == Some(Errno::ERESTARTSYS.into_raw())
                || (next.signal_interrupt_errno() == Some(Errno::EINTR.into_raw())
                    && next.fyi == "epoll_wait"));
        // The PMU callback is stopped before returning to guest instructions.
        // A processed priority changepoint retains slice_expired on an empty
        // request. Do not admit ordinary yields, sleeps, or syscall requests.
        let cpu_slice = next.slice_expired
            && next.signal_interrupt_errno().is_none()
            && !self.saved_guest_sigmasks.contains_key(&recipient)
            && (next.resources.is_empty()
                || (next.resources.len() == 1
                    && next
                        .resources
                        .get(&ResourceID::SleepUntil(LogicalTime::ZERO))
                        == Some(&Permission::W)));
        if !(poll || cpu_slice) || next.decides_signal_interruption_itself || next.reads_signalfd {
            tracing::debug!(?recipient, signal, request = ?next, "process_signal_preflight_rejected: return boundary");
            return None;
        }
        let private_guard = self
            .native_epoll_guards
            .get(&recipient)
            .map(|(_, physical)| *physical);
        self.process_signal_reservation = Some(ProcessSignalReservation {
            sender,
            recipient,
            signal,
            guest_mask,
            private_guard,
            guard_restored: private_guard.is_none(),
            interrupt_errno: next.signal_interrupt_errno(),
            committed: false,
            expected_siginfo: None,
            held_authenticated: false,
            dequeue_authenticated: false,
        });
        Some(recipient)
    }

    /// The original native kill has returned. A failed send reserves nothing;
    /// a successful one pins the recipient and requires a sender yield.
    pub(crate) fn finish_process_signal(&mut self, sender: DetTid, sent: bool) {
        let Some(reservation) = self.process_signal_reservation.as_mut() else {
            exit_on_scheduler_refusal(
                &"HERMIT_PROCESS_SIGNAL_RESERVATION: missing send reservation",
            );
        };
        if reservation.sender != sender || reservation.committed {
            exit_on_scheduler_refusal(
                &"HERMIT_PROCESS_SIGNAL_RESERVATION: invalid send completion",
            );
        }
        if !sent {
            self.process_signal_reservation = None;
            return;
        }
        if reservation.expected_siginfo.is_none() {
            exit_on_scheduler_refusal(
                &"HERMIT_PROCESS_SIGNAL_RESERVATION: send identity unavailable",
            );
        }
        reservation.committed = true;
        let recipient = reservation.recipient;
        let signal = reservation.signal;
        self.notify_signal_pending(recipient, SigWrapper(signal));
    }

    /// Only an admitted reservation extends the existing restartable-poll
    /// wake path to epoll's nonrestartable EINTR boundary.
    pub(super) fn reserved_process_signal_errno(&self, thread: DetTid) -> Option<Errno> {
        let reservation = self.process_signal_reservation?;
        (reservation.committed && reservation.recipient == thread)
            .then_some(reservation.interrupt_errno)
            .flatten()
            .map(Errno::new)
    }

    /// Called after the pending-send drain, before any alternative selection.
    /// A missing wake is an unsupported state, never permission to run a peer.
    pub(super) fn reserved_process_signal_recipient(&self) -> Option<DetTid> {
        let reservation = self.process_signal_reservation?;
        if !reservation.committed
            || !self
                .run_queue
                .contains_non_polling_tid(reservation.recipient)
        {
            exit_on_scheduler_refusal(
                &"HERMIT_PROCESS_SIGNAL_RESERVATION: recipient cannot resume",
            );
        }
        let request = self
            .next_turns
            .get(&reservation.recipient)
            .and_then(|next| next.req.try_read())
            .and_then(Result::ok);
        // An empty request slot means the recipient is still returning from
        // its stopped boundary (possibly already at the kernel dequeue). Wait for that
        // exact task's request; never sample a queue during its return path.
        let delivery = request.as_ref().is_some_and(|request| {
            request
                .resources
                .get(&ResourceID::InboundSignal(SigWrapper(reservation.signal)))
                == Some(&Permission::RW)
        });
        if request.is_some()
            && !delivery
            && !self
                .reserved_signal_state(reservation.recipient)
                .is_some_and(|state| {
                    let bit = kernel_signal_bit(reservation.signal);
                    let mask_valid = if reservation.guard_restored {
                        state.blocked == reservation.guest_mask
                            && !self
                                .saved_guest_sigmasks
                                .contains_key(&reservation.recipient)
                    } else {
                        reservation.private_guard == Some(state.blocked)
                            && self.native_epoll_guards.get(&reservation.recipient)
                                == Some(&(reservation.guest_mask, state.blocked))
                            && self.saved_guest_sigmasks.get(&reservation.recipient)
                                == Some(&reservation.guest_mask)
                    };
                    (state.shared_pending & bit != 0
                        || reservation.held_authenticated
                        || reservation.dequeue_authenticated)
                        && mask_valid
                })
        {
            exit_on_scheduler_refusal(
                &"HERMIT_PROCESS_SIGNAL_RESERVATION: copy lost or recipient mask changed before dequeue",
            );
        }
        Some(reservation.recipient)
    }

    /// An RW inbound request is the backend's actual dequeue, not the W wake
    /// synthesized to interrupt a poll. No guest handler runs before this grant.
    pub(super) fn receive_reserved_process_signal(&mut self, thread: DetTid, signal: i32) {
        let Some(reservation) = self.process_signal_reservation else {
            return;
        };
        if !reservation.committed
            || !reservation.guard_restored
            || !reservation.dequeue_authenticated
            || reservation.recipient != thread
            || reservation.signal != signal
        {
            exit_on_scheduler_refusal(&"HERMIT_PROCESS_SIGNAL_RESERVATION: unexpected dequeue");
        }
        self.process_signal_reservation = None;
    }

    /// Reuse the send ledger's native-UID SI_USER record, before its fallback
    /// for unknown senders. No virtual credential or sending TID is substituted.
    pub(super) fn note_reserved_send_identity(
        &mut self,
        sender: DetTid,
        token: discarded_at_send::DiscardToken,
        siginfo: Option<signal_lists::KernelSiginfo>,
    ) {
        let Some(reservation) = self.process_signal_reservation else {
            return;
        };
        if reservation.sender != sender || reservation.committed {
            exit_on_scheduler_refusal(&"HERMIT_PROCESS_SIGNAL_RESERVATION: unexpected sender");
        }
        let process = self.sigchld_process(reservation.recipient);
        let sender_process = self.sigchld_process(sender);
        let valid = token.queue == discarded_at_send::QueueId::Process(process)
            && token.signal == reservation.signal
            && !token.discarded
            && !token.present
            && siginfo.is_some_and(|info| {
                info.0[0..4] == reservation.signal.to_ne_bytes()
                    && info.0[8..12] == libc::SI_USER.to_ne_bytes()
                    && info.0[16..20] == sender_process.as_raw().to_ne_bytes()
            });
        if !valid {
            exit_on_scheduler_refusal(&"HERMIT_PROCESS_SIGNAL_RESERVATION: unknown send identity");
        }
        self.process_signal_reservation
            .as_mut()
            .expect("reservation exists")
            .expected_siginfo = siginfo;
    }

    fn reserved_siginfo_matches(
        reservation: ProcessSignalReservation,
        info: Option<signal_lists::KernelSiginfo>,
    ) -> bool {
        reservation
            .expected_siginfo
            .zip(info)
            .is_some_and(|(expected, actual)| {
                expected.0[0..4] == actual.0[0..4]
                    && expected.0[8..12] == actual.0[8..12]
                    && expected.0[16..24] == actual.0[16..24]
            })
    }

    /// Authenticate the backend callback before any inbound scheduling handoff.
    /// This records dequeue, but only its eventual RW request releases the fence.
    pub(crate) fn authenticate_reserved_dequeue(
        &mut self,
        thread: DetTid,
        info: Option<signal_lists::KernelSiginfo>,
    ) {
        let Some(reservation) = self.process_signal_reservation else {
            return;
        };
        if !reservation.committed
            || reservation.recipient != thread
            || reservation.dequeue_authenticated
            || !Self::reserved_siginfo_matches(reservation, info)
        {
            exit_on_scheduler_refusal(
                &"HERMIT_PROCESS_SIGNAL_RESERVATION: unauthenticated dequeue",
            );
        }
        self.process_signal_reservation
            .as_mut()
            .expect("reservation exists")
            .dequeue_authenticated = true;
    }

    /// An unreported native path cannot bypass the authenticated RW receipt.
    /// PERF_EVENT_SIGNAL belongs to the tracer, not this guest reservation.
    pub(super) fn refuse_reserved_unreported(&self, signal: i32) {
        if self.process_signal_reservation.is_some() && signal != reverie::PERF_EVENT_SIGNAL as i32
        {
            exit_on_scheduler_refusal(
                &"HERMIT_PROCESS_SIGNAL_RESERVATION: unreported signal before authenticated dequeue",
            );
        }
    }
}

impl Scheduler {
    /// Called only by the plain EpollWait KernelSignalWait loop after its
    /// private mask is installed, or after restoration and generic-mask clear.
    /// Generic mask publications revoke provenance; only this path establishes it.
    pub(crate) fn set_native_epoll_guard(
        &mut self,
        thread: DetTid,
        guard: Option<(u64, u64)>,
        held: Option<signal_lists::KernelSiginfo>,
    ) {
        if let Some((original, physical)) = guard {
            if self.backend != BackendCapabilities::PTRACE
                || held.is_some()
                || !self.holds_serial_grant(thread)
                || self.saved_guest_sigmasks.get(&thread) != Some(&original)
                || !self
                    .reserved_signal_state(thread)
                    .is_some_and(|state| state.blocked == physical)
            {
                exit_on_scheduler_refusal(
                    &"HERMIT_PROCESS_SIGNAL_RESERVATION: invalid epoll guard publication",
                );
            }
            self.native_epoll_guards
                .insert(thread, (original, physical));
        } else {
            self.native_epoll_guards.remove(&thread);
            if let Some(reservation) = self.process_signal_reservation
                && reservation.recipient == thread
                && reservation.private_guard.is_some()
            {
                if !reservation.committed
                    || !self.holds_serial_grant(thread)
                    || (held.is_some() && !Self::reserved_siginfo_matches(reservation, held))
                    || self.saved_guest_sigmasks.contains_key(&thread)
                    || !self
                        .reserved_signal_state(thread)
                        .is_some_and(|state| state.blocked == reservation.guest_mask)
                {
                    exit_on_scheduler_refusal(
                        &"HERMIT_PROCESS_SIGNAL_RESERVATION: epoll guest mask not restored",
                    );
                }
                let reservation = self
                    .process_signal_reservation
                    .as_mut()
                    .expect("reservation exists");
                reservation.guard_restored = true;
                reservation.held_authenticated = held.is_some();
            }
        }
    }

    fn process_signal_effective_mask(
        &self,
        thread: DetTid,
        state: &KernelSignalState,
    ) -> Option<u64> {
        match self.saved_guest_sigmasks.get(&thread).copied() {
            None if !self.native_epoll_guards.contains_key(&thread) => Some(state.blocked),
            Some(original)
                if self.native_epoll_guards.get(&thread) == Some(&(original, state.blocked)) =>
            {
                let request = self.next_turns.get(&thread)?.req.try_read()?.ok()?;
                (request.resources.len() == 1
                    && request
                        .resources
                        .contains_key(&ResourceID::InternalIOPolling)
                    && request.fyi == "epoll_wait"
                    && request.signal_interrupt_errno() == Some(Errno::EINTR.into_raw())
                    && request.blocked_signal_mask.is_none()
                    && !request.blocked_signal_mask_unknown
                    && !request.decides_signal_interruption_itself
                    && !request.reads_signalfd)
                    .then_some(original)
            }
            _ => None,
        }
    }

    fn reserved_signal_state(&self, thread: DetTid) -> Option<KernelSignalState> {
        #[cfg(test)]
        {
            self.test_kernel_signal_states.get(&thread).copied()
        }
        #[cfg(not(test))]
        {
            read_kernel_signal_state(
                reverie::Pid::from_raw(self.sigchld_process(thread).as_raw()),
                reverie::Pid::from_raw(thread.as_raw()),
            )
            .ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn family() -> (Scheduler, DetTid, DetTid, DetTid, DetTid) {
        let mut scheduler = Scheduler::new(&Config::default());
        scheduler.backend = BackendCapabilities::PTRACE;
        scheduler.models_signal_targets = true;
        scheduler.host_timed_signals_everywhere = 0;
        let sender = DetTid::from_raw(100);
        let leader = DetTid::from_raw(200);
        let first = DetTid::from_raw(201);
        let second = DetTid::from_raw(202);
        scheduler.thread_tree.add_child(sender, sender, true);
        scheduler.thread_tree.add_child(sender, leader, true);
        scheduler.thread_tree.add_child(leader, first, false);
        scheduler.thread_tree.add_child(leader, second, false);
        super::super::test::register_known_thread_for(&mut scheduler, sender);
        scheduler.parked.running = Some(sender);
        let bit = kernel_signal_bit(libc::SIGUSR1);
        for thread in [leader, first, second] {
            super::super::test::register_known_thread_for(&mut scheduler, thread);
            let mut request = Resources::new(thread);
            request.insert(ResourceID::InternalIOPolling, Permission::W);
            request.set_signal_interrupt_errno(Errno::EINTR);
            request.fyi("epoll_wait");
            scheduler.next_turns.get_mut(&thread).unwrap().req = Ivar::full(Ok(request));
            scheduler.runqueue_push_back(thread);
            scheduler.test_task_states.insert(thread, 't');
            scheduler.test_kernel_signal_states.insert(
                thread,
                KernelSignalState {
                    blocked: if thread == leader { 0 } else { bit },
                    caught: bit,
                    ..Default::default()
                },
            );
        }
        (scheduler, sender, leader, first, second)
    }

    fn record_send(scheduler: &mut Scheduler, sender: DetTid) -> signal_lists::KernelSiginfo {
        let reservation = scheduler.process_signal_reservation.unwrap();
        let info = signal_lists::ordinary_siginfo(
            reservation.signal,
            libc::SI_USER,
            scheduler.sigchld_process(sender).as_raw(),
            1000,
        );
        scheduler.note_reserved_send_identity(
            sender,
            discarded_at_send::DiscardToken {
                queue: discarded_at_send::QueueId::Process(
                    scheduler.sigchld_process(reservation.recipient),
                ),
                signal: reservation.signal,
                discarded: false,
                present: false,
                generation: 0,
            },
            Some(info),
        );
        info
    }

    fn install_epoll_guard(scheduler: &mut Scheduler, thread: DetTid, original: u64) -> u64 {
        let running = scheduler.parked.running;
        let request = std::mem::replace(
            &mut scheduler.next_turns.get_mut(&thread).unwrap().req,
            Ivar::new(),
        );
        scheduler.parked.running = Some(thread);
        scheduler.set_saved_guest_sigmask(thread, Some(original));
        let physical = u64::MAX
            & !kernel_signal_bit(libc::SIGKILL)
            & !kernel_signal_bit(libc::SIGSTOP)
            & !kernel_signal_bit(reverie::PERF_EVENT_SIGNAL as i32);
        scheduler
            .test_kernel_signal_states
            .get_mut(&thread)
            .unwrap()
            .blocked = physical;
        scheduler.set_native_epoll_guard(thread, Some((original, physical)), None);
        scheduler.next_turns.get_mut(&thread).unwrap().req = request;
        scheduler.parked.running = running;
        physical
    }

    #[test]
    fn process_signal_reservation_proves_private_epoll_guard_and_restoration() {
        for held_copy in [false, true] {
            let (mut scheduler, sender, leader, peer, _) = family();
            let physical = install_epoll_guard(&mut scheduler, leader, 0);
            install_epoll_guard(&mut scheduler, peer, 0);
            assert_eq!(
                scheduler.reserve_process_signal(sender, leader, libc::SIGUSR1),
                Some(leader)
            );
            assert!(!scheduler.process_signal_reservation.unwrap().guard_restored);
            let bit = kernel_signal_bit(libc::SIGUSR1);
            let state = scheduler
                .test_kernel_signal_states
                .get_mut(&leader)
                .unwrap();
            state.shared_pending = bit;
            state.pending = bit;
            let info = record_send(&mut scheduler, sender);
            scheduler.finish_process_signal(sender, true);
            scheduler.drain_pending_cross_task_signals();
            assert_eq!(
                scheduler.reserved_process_signal_recipient(),
                Some(leader),
                "the original private guard stays installed across the synthetic wake"
            );
            // A callback/administrative request before restore must keep the fence.
            scheduler.next_turns.get_mut(&leader).unwrap().req =
                Ivar::full(Ok(Resources::new(leader)));
            assert_eq!(scheduler.reserved_process_signal_recipient(), Some(leader));
            assert_eq!(scheduler.test_kernel_signal_states[&peer].blocked, physical);
            assert_eq!(
                scheduler.native_epoll_guards.get(&peer),
                Some(&(0, physical))
            );
            // Only the selected thread's own turn may acknowledge restoration.
            scheduler.next_turns.get_mut(&leader).unwrap().req = Ivar::new();
            scheduler.parked.running = Some(leader);
            scheduler
                .test_kernel_signal_states
                .get_mut(&leader)
                .unwrap()
                .blocked = 0;
            scheduler.set_saved_guest_sigmask(leader, None);
            // Restoration either leaves the shared copy pending or takes it into
            // the native backend's held slot. Only captured siginfo proves custody.
            if held_copy {
                scheduler
                    .test_kernel_signal_states
                    .get_mut(&leader)
                    .unwrap()
                    .shared_pending = 0;
                scheduler
                    .test_kernel_signal_states
                    .get_mut(&leader)
                    .unwrap()
                    .pending = 0;
            }
            scheduler.set_native_epoll_guard(leader, None, held_copy.then_some(info));
            assert!(scheduler.process_signal_reservation.unwrap().guard_restored);
            assert!(
                scheduler.process_signal_reservation.is_some(),
                "restoration is not dequeue"
            );
            scheduler.next_turns.get_mut(&leader).unwrap().req =
                Ivar::full(Ok(Resources::new(leader)));
            assert_eq!(scheduler.reserved_process_signal_recipient(), Some(leader));
            assert!(
                !scheduler
                    .process_signal_reservation
                    .unwrap()
                    .dequeue_authenticated
            );
            scheduler.authenticate_reserved_dequeue(leader, Some(info));
            assert!(
                scheduler.process_signal_reservation.is_some(),
                "receipt still awaits its RW grant"
            );
            let mut delivery = Resources::new(leader);
            delivery.insert(
                ResourceID::InboundSignal(SigWrapper(libc::SIGUSR1)),
                Permission::RW,
            );
            scheduler.next_turns.get_mut(&leader).unwrap().req = Ivar::full(Ok(delivery));
            scheduler
                .test_kernel_signal_states
                .get_mut(&leader)
                .unwrap()
                .shared_pending = 0;
            assert_eq!(scheduler.reserved_process_signal_recipient(), Some(leader));
            scheduler.receive_reserved_process_signal(leader, libc::SIGUSR1);
            assert!(scheduler.process_signal_reservation.is_none());
        }
    }

    #[test]
    fn process_signal_reservation_authenticates_native_sender_tgid_uid_and_code() {
        let (mut scheduler, sender, leader, _, _) = family();
        let sender_thread = DetTid::from_raw(101);
        scheduler
            .thread_tree
            .add_child(sender, sender_thread, false);
        super::super::test::register_known_thread_for(&mut scheduler, sender_thread);
        scheduler.parked.running = Some(sender_thread);
        assert_eq!(
            scheduler.reserve_process_signal(sender_thread, leader, libc::SIGUSR1),
            Some(leader)
        );
        let info = record_send(&mut scheduler, sender_thread);
        let reservation = scheduler.process_signal_reservation.unwrap();
        assert!(Scheduler::reserved_siginfo_matches(reservation, Some(info)));
        assert!(!Scheduler::reserved_siginfo_matches(reservation, None));
        for wrong in [
            signal_lists::ordinary_siginfo(
                libc::SIGUSR1,
                libc::SI_USER,
                sender_thread.as_raw(),
                1000,
            ),
            signal_lists::ordinary_siginfo(libc::SIGUSR1, libc::SI_USER, sender.as_raw(), 102),
            signal_lists::ordinary_siginfo(libc::SIGUSR1, libc::SI_TKILL, sender.as_raw(), 1000),
            signal_lists::ordinary_siginfo(libc::SIGUSR2, libc::SI_USER, sender.as_raw(), 1000),
        ] {
            assert!(!Scheduler::reserved_siginfo_matches(
                reservation,
                Some(wrong)
            ));
        }
        scheduler.finish_process_signal(sender_thread, false);
        assert!(
            scheduler.process_signal_reservation.is_none(),
            "failed send cancels identity too"
        );
        assert!(scheduler.pending_cross_task_signals.is_empty());
    }

    #[test]
    fn process_signal_reservation_refuses_unproven_or_changed_private_guards() {
        for case in [
            "missing_provenance",
            "physical_changed",
            "saved_changed",
            "temporary_mask",
            "masked_syscall",
            "generic_republication",
        ] {
            let (mut scheduler, sender, leader, _, _) = family();
            install_epoll_guard(&mut scheduler, leader, 0);
            match case {
                "missing_provenance" => {
                    scheduler.native_epoll_guards.remove(&leader);
                }
                "physical_changed" => {
                    scheduler
                        .test_kernel_signal_states
                        .get_mut(&leader)
                        .unwrap()
                        .blocked = 0;
                }
                "saved_changed" => {
                    scheduler.saved_guest_sigmasks.insert(leader, 1);
                }
                "generic_republication" => {
                    scheduler.set_saved_guest_sigmask(leader, Some(0));
                }
                "temporary_mask" | "masked_syscall" => {
                    let mut request = Resources::new(leader);
                    request.insert(ResourceID::InternalIOPolling, Permission::W);
                    request.set_signal_interrupt_errno(Errno::EINTR);
                    request.fyi(if case == "masked_syscall" {
                        "epoll_pwait"
                    } else {
                        "epoll_wait"
                    });
                    if case == "temporary_mask" {
                        request.blocked_signal_mask = Some(0);
                    }
                    scheduler.next_turns.get_mut(&leader).unwrap().req = Ivar::full(Ok(request));
                }
                _ => unreachable!(),
            }
            assert_eq!(
                scheduler.reserve_process_signal(sender, leader, libc::SIGUSR1),
                None,
                "{case}"
            );
        }
    }

    #[test]
    fn process_signal_reservation_selects_unique_or_preferred_leader() {
        for case in [
            "unique_leader",
            "all_unblocked",
            "unique_sibling",
            "ambiguous",
            "all_blocked",
        ] {
            let (mut scheduler, sender, leader, first, second) = family();
            let bit = kernel_signal_bit(libc::SIGUSR1);
            for thread in [leader, first, second] {
                let blocked = match case {
                    "unique_leader" => thread != leader,
                    "all_unblocked" => false,
                    "unique_sibling" => thread != first,
                    "ambiguous" => thread == leader,
                    _ => true,
                };
                scheduler
                    .test_kernel_signal_states
                    .get_mut(&thread)
                    .unwrap()
                    .blocked = if blocked { bit } else { 0 };
            }
            let expected = match case {
                "unique_leader" | "all_unblocked" => Some(leader),
                "unique_sibling" => Some(first),
                _ => None,
            };
            assert_eq!(
                scheduler.reserve_process_signal(sender, leader, libc::SIGUSR1),
                expected,
                "{case}"
            );
        }
    }

    #[test]
    fn process_signal_reservation_refuses_unmodeled_states() {
        for case in [
            "private_mask",
            "waiter",
            "signalfd",
            "private_pending",
            "shared_pending",
            "unknown_mask",
            "exiting",
            "stopped",
            "host_timed",
            "default",
            "backend",
            "no_grant",
            "outside",
            "private_mask_unknown",
        ] {
            let (mut scheduler, sender, leader, sibling, _) = family();
            let bit = kernel_signal_bit(libc::SIGUSR1);
            match case {
                "private_mask" => {
                    scheduler.saved_guest_sigmasks.insert(sibling, bit);
                }
                "waiter" => {
                    scheduler.sigtimedwait_sets.insert(sibling, bit);
                }
                "outside" => {
                    scheduler.blocked.external_io_blockers.insert(
                        sibling,
                        ExternalOpId {
                            tid: sibling,
                            sequence: 1,
                        },
                    );
                }
                "private_mask_unknown" => {
                    scheduler.saved_guest_sigmasks.insert(sibling, u64::MAX);
                }
                "signalfd" => {
                    scheduler.signalfd_masks.insert(leader, bit);
                }
                "private_pending" => {
                    scheduler
                        .test_kernel_signal_states
                        .get_mut(&sibling)
                        .unwrap()
                        .thread_pending = bit;
                }
                "shared_pending" => {
                    scheduler
                        .test_kernel_signal_states
                        .get_mut(&leader)
                        .unwrap()
                        .shared_pending = bit;
                }
                "unknown_mask" => {
                    scheduler.test_kernel_signal_states.remove(&sibling);
                }
                "exiting" => {
                    scheduler.logically_killed_threads.insert(sibling);
                }
                "stopped" => {
                    scheduler.test_task_states.insert(sibling, 'T');
                }
                "host_timed" => {
                    scheduler.host_timed_signals_everywhere = bit;
                }
                "default" => {
                    scheduler
                        .test_kernel_signal_states
                        .get_mut(&leader)
                        .unwrap()
                        .caught = 0;
                }
                "backend" => {
                    scheduler.backend = BackendCapabilities::DBT;
                }
                "no_grant" => {
                    scheduler.parked.running = None;
                }
                _ => unreachable!(),
            }
            assert_eq!(
                scheduler.reserve_process_signal(sender, leader, libc::SIGUSR1),
                None,
                "{case}"
            );
            assert!(scheduler.process_signal_reservation.is_none(), "{case}");
        }
    }

    #[test]
    fn process_signal_reservation_does_not_admit_arbitrary_eintr_pollers() {
        let (mut scheduler, sender, leader, _, _) = family();
        let mut request = Resources::new(leader);
        request.insert(ResourceID::InternalIOPolling, Permission::W);
        request.set_signal_interrupt_errno(Errno::EINTR);
        request.fyi("poll");
        scheduler.next_turns.get_mut(&leader).unwrap().req = Ivar::full(Ok(request));
        assert_eq!(
            scheduler.reserve_process_signal(sender, leader, libc::SIGUSR1),
            None
        );
        assert!(scheduler.process_signal_reservation.is_none());
    }

    #[test]
    fn process_signal_reservation_cancels_failed_send_and_pins_until_dequeue() {
        let (mut scheduler, sender, leader, sibling, _) = family();
        assert_eq!(
            scheduler.reserve_process_signal(sender, leader, libc::SIGUSR1),
            Some(leader)
        );
        scheduler.finish_process_signal(sender, false);
        assert!(scheduler.process_signal_reservation.is_none());
        assert!(scheduler.pending_cross_task_signals.is_empty());
        assert_eq!(
            scheduler.reserve_process_signal(sender, leader, libc::SIGUSR1),
            Some(leader)
        );
        let bit = kernel_signal_bit(libc::SIGUSR1);
        let state = scheduler
            .test_kernel_signal_states
            .get_mut(&leader)
            .unwrap();
        state.shared_pending = bit;
        state.pending = bit;
        let info = record_send(&mut scheduler, sender);
        scheduler.finish_process_signal(sender, true);
        scheduler.drain_pending_cross_task_signals();
        assert_eq!(
            scheduler.next_turns[&leader]
                .req
                .try_read()
                .unwrap()
                .unwrap()
                .signal_interrupt_errno(),
            Some(Errno::EINTR.into_raw()),
            "epoll's synthetic wake must not turn SA_RESTART into syscall restart",
        );
        // Even an adversarial sibling with highest priority cannot consume the
        // shared copy by unmasking or sigtimedwait before the reserved dequeue.
        scheduler.run_queue.remove_tid(sibling);
        scheduler
            .priorities
            .insert(sibling, runqueue::FIRST_PRIORITY);
        scheduler.runqueue_push_back(sibling);
        let (selected, _, _) = scheduler.step3_peek().unwrap();
        assert_eq!(selected, leader);
        scheduler.run_queue.undo_tentative_pop();
        assert!(
            scheduler.process_signal_reservation.is_some(),
            "a synthetic wake is not a receipt"
        );
        let mut delivery = Resources::new(leader);
        delivery.insert(
            ResourceID::InboundSignal(SigWrapper(libc::SIGUSR1)),
            Permission::RW,
        );
        scheduler.next_turns.get_mut(&leader).unwrap().req = Ivar::full(Ok(delivery));
        scheduler
            .test_kernel_signal_states
            .get_mut(&leader)
            .unwrap()
            .shared_pending = 0;
        assert_eq!(scheduler.reserved_process_signal_recipient(), Some(leader));
        scheduler.authenticate_reserved_dequeue(leader, Some(info));
        scheduler.receive_reserved_process_signal(leader, libc::SIGUSR1);
        assert!(scheduler.process_signal_reservation.is_none());
    }

    #[test]
    fn process_signal_reservation_keeps_catchable_host_sources_excluded() {
        let kill = kernel_signal_bit(libc::SIGKILL);
        let usr1 = kernel_signal_bit(libc::SIGUSR1);
        let usr2 = kernel_signal_bit(libc::SIGUSR2);
        for sources in [0, kill, usr1, usr2, kill | usr1] {
            let (mut scheduler, sender, leader, _, _) = family();
            scheduler.record_host_timed_signals(leader, HostTimedSignalScope::Caller, sources);
            assert_eq!(
                scheduler.reserve_process_signal(sender, leader, libc::SIGUSR1),
                (sources & !kill == 0).then_some(leader),
                "host sources {sources:#x}"
            );
            // Admission must not erase the source used by other signal gates.
            assert_eq!(scheduler.host_timed_signals(leader), sources);
        }
    }

    #[test]
    fn process_signal_reservation_pins_expired_cpu_slices_through_dequeue() {
        for empty in [false, true] {
            let (mut scheduler, sender, leader, sibling, _) = family();
            let mut request = Resources::new(leader);
            request.slice_expired = true;
            if !empty {
                request.insert(ResourceID::SleepUntil(LogicalTime::ZERO), Permission::W);
            }
            scheduler.next_turns.get_mut(&leader).unwrap().req = Ivar::full(Ok(request));
            scheduler.record_host_timed_signals(
                leader,
                HostTimedSignalScope::Caller,
                kernel_signal_bit(libc::SIGKILL),
            );
            assert_eq!(
                scheduler.reserve_process_signal(sender, leader, libc::SIGUSR1),
                Some(leader)
            );
            let info = record_send(&mut scheduler, sender);
            let bit = kernel_signal_bit(libc::SIGUSR1);
            let state = scheduler
                .test_kernel_signal_states
                .get_mut(&leader)
                .unwrap();
            state.shared_pending = bit;
            state.pending = bit;
            scheduler.finish_process_signal(sender, true);
            scheduler.drain_pending_cross_task_signals();
            assert_eq!(scheduler.reserved_process_signal_errno(leader), None);
            scheduler.run_queue.remove_tid(sibling);
            scheduler
                .priorities
                .insert(sibling, runqueue::FIRST_PRIORITY);
            scheduler.runqueue_push_back(sibling);
            let (selected, _, _) = scheduler.step3_peek().unwrap();
            assert_eq!(selected, leader);
            scheduler.run_queue.undo_tentative_pop();
            let mut delivery = Resources::new(leader);
            delivery.insert(
                ResourceID::InboundSignal(SigWrapper(libc::SIGUSR1)),
                Permission::RW,
            );
            scheduler.next_turns.get_mut(&leader).unwrap().req = Ivar::full(Ok(delivery));
            scheduler
                .test_kernel_signal_states
                .get_mut(&leader)
                .unwrap()
                .shared_pending = 0;
            scheduler.authenticate_reserved_dequeue(leader, Some(info));
            scheduler.receive_reserved_process_signal(leader, libc::SIGUSR1);
            assert!(scheduler.process_signal_reservation.is_none());
        }
    }

    #[test]
    fn process_signal_reservation_does_not_turn_other_stops_into_cpu_slices() {
        for (expired, resource) in [
            (false, None),
            (false, Some(ResourceID::SleepUntil(LogicalTime::ZERO))),
            (
                true,
                Some(ResourceID::SleepUntil(LogicalTime::from_nanos(1))),
            ),
            (true, Some(ResourceID::SchedYield)),
        ] {
            let (mut scheduler, sender, leader, _, _) = family();
            let mut request = Resources::new(leader);
            request.slice_expired = expired;
            if let Some(resource) = resource {
                request.insert(resource, Permission::W);
            }
            scheduler.next_turns.get_mut(&leader).unwrap().req = Ivar::full(Ok(request));
            assert_eq!(
                scheduler.reserve_process_signal(sender, leader, libc::SIGUSR1),
                None
            );
        }
    }
}
