//! Dependency waits share the existing timed/signal parking and idle barriers.
use super::{HostTimedSignalScope, Scheduler, SigWrapper, SkipTurn};
use crate::event_driven_io::{Key, Observer, Snapshot, Update};
use crate::resources::{ResourceID, Resources};
use crate::types::{DetPid, DetTid, LogicalTime, MmId};

impl Scheduler {
    /// Admission already requires serialized scheduling. Do not extrapolate
    /// ptrace's terminal-status/reconnect ordering to another backend.
    fn native_io_lifecycle(&self) -> bool {
        self.io_dependencies.is_some() && self.backend == reverie::BackendCapabilities::PTRACE
    }

    pub(super) fn note_io_exit_grant(
        &mut self,
        caller: DetTid,
        process: DetPid,
        mm: MmId,
        group: bool,
        ends_named_process: bool,
        exit_already_published: bool,
    ) {
        if self.native_io_lifecycle()
            && self.registered_process(caller) == Some(process)
            && self.rpc_incarnation_matches(caller, mm)
            && (!group || ends_named_process)
            && (!ends_named_process
                || exit_already_published
                || self.child_exit_publications_pending.contains(&process))
        {
            self.io_exit_grants.insert(caller, mm);
        }
    }

    /// Queue a conservative re-probe, never a claim of EOF/last-close. The
    /// native empty-request barrier holds raw exit through terminal status (or
    /// the early-leader zombie barrier), and exec through reconnect/rollback.
    /// A group exit additionally owns the process-publication barrier installed
    /// at its grant: one member's exit callback cannot establish group closure.
    pub(crate) fn event_driven_io_lifecycle(
        &mut self,
        caller: DetTid,
        mm: MmId,
        keys: Vec<Key>,
    ) -> Option<Snapshot> {
        let exit = self.io_exit_grants.remove(&caller) == Some(mm);
        let prepared_exec = self.registered_process(caller).is_some_and(|process| {
            self.exec_teardowns.get(&process).is_some_and(|exec| {
                exec.caller == caller && exec.mm == mm
            })
        });
        let holds_turn = self.run_queue.contains_tid(caller)
            && !self.pending_run_queue_removals.contains_key(&caller)
            && self.next_turns.get(&caller).is_some_and(|turn| turn.req.try_read().is_none());
        let eligible = self.native_io_lifecycle()
            && self.rpc_incarnation_matches(caller, mm)
            && holds_turn
            && (exit || prepared_exec);
        tracing::info!(
            target: "detcore::event_driven_io",
            "event-driven IO lifecycle dtid {} authority {}: {:?}",
            caller, if eligible { "changed" } else { "revoked (unproven barrier)" }, keys
        );
        self.event_driven_io(if eligible { Update::Change(keys) } else { Update::Revoke(keys) })
    }

    /// Called at the finite idle jump, after the normal step-2 exit, signal
    /// and rejoin barriers. A background completion is not a virtual deadline:
    /// it must be harvested and its continuation run before we can jump.
    pub(super) fn io_idle_time_is_quiescent(&self) -> bool {
        self.blocked.external_io_blockers.is_empty()
            && self.blocked.physical_child_waiters.is_empty()
            && (self.blocked.child_waiters.is_empty() || self.child_waits_quiescent(true))
    }

    fn io_observer(&self, caller: DetTid, mm: MmId) -> Option<Observer> {
        let process = self.registered_process(caller)?;
        if !self.native_io_lifecycle()
            || !self.next_turns.contains_key(&caller)
            || !self.rpc_incarnation_matches(caller, mm)
            || self.thread_mm(caller) != Some(mm)
        {
            return None;
        }
        // Terminal acquisition is not uniformly pre-armed. Kernel-raised and
        // runtime-private signals are not scheduler sends: mirror the exclusions
        // in posix_timer_coalesce::EXCLUDED_SIGNALS, plus child/CPU-limit signals.
        let unsupported = [
            libc::SIGCHLD, libc::SIGILL, libc::SIGTRAP, libc::SIGABRT,
            libc::SIGBUS, libc::SIGFPE, libc::SIGSEGV, libc::SIGSYS,
            libc::SIGKILL, libc::SIGSTOP, libc::SIGPIPE, libc::SIGXFSZ,
            libc::SIGSTKFLT, libc::SIGXCPU,
        ].into_iter().fold(super::terminal_signals() | self.in_guest_reserved_signals, |mask, signal| {
            mask | super::kernel_signal_bit(signal)
        });
        Some(Observer {
            thread: caller,
            process,
            mm,
            excluded_signals: if self.background_call_processes.contains(&process) {
                u64::MAX
            } else {
                self.host_timed_signals(caller) | unsupported
            },
        })
    }

    /// Guest RPCs authenticate task, address-space incarnation and process.
    /// The OFD carries only its mask; queue identity belongs to this observer.
    pub(crate) fn event_driven_io_from(
        &mut self,
        caller: DetTid,
        mm: MmId,
        update: Update,
    ) -> Option<Snapshot> {
        let Some(observer) = self.io_observer(caller, mm) else {
            // An unauthenticated mutation cannot leave old authority usable.
            if !matches!(update, Update::Observe(..) | Update::Unsupported) {
                self.event_driven_io(Update::Disable);
            }
            return None;
        };
        let dependencies = self.io_dependencies.as_mut()?;
        if let Update::Observe(keys, first, timerfds) = update {
            return dependencies.observe_from(keys, first, Some(observer), &timerfds);
        }
        let wake = dependencies.update_from(update, Some(observer));
        self.wake_io_dependencies(wake);
        None
    }

    /// Sticky graph-only exclusions also cover modeled producers whose later
    /// queue transitions are not tracked here, without changing signal custody.
    pub(super) fn event_driven_io_host_signals(
        &mut self,
        caller: DetTid,
        scope: HostTimedSignalScope,
        signals: u64,
    ) {
        if signals == 0 {
            return;
        }
        let process = match scope {
            HostTimedSignalScope::Caller => match self.registered_process(caller) {
                Some(process) => Some(process),
                None => {
                    self.event_driven_io(Update::Disable);
                    return;
                }
            },
            HostTimedSignalScope::Container => None,
        };
        if let Some(dependencies) = self.io_dependencies.as_mut() {
            let wake = dependencies.exclude_signals(process, signals);
            self.wake_io_dependencies(wake);
        }
    }

    pub(crate) fn event_driven_io(&mut self, update: Update) -> Option<Snapshot> {
        if matches!(update, Update::Disable | Update::RevokeAll) {
            if let Some(registry) = &self.flock_waits {
                registry.disable();
            }
        }
        let dependencies = self.io_dependencies.as_mut()?;
        if let Update::Observe(keys, first, timerfds) = update {
            return dependencies.observe_from(keys, first, None, &timerfds);
        }
        let wake = dependencies.update(update);
        self.wake_io_dependencies(wake);
        None
    }

    fn wake_io_dependencies(&mut self, wake: std::collections::BTreeSet<DetTid>) {
        // BTreeSet order, inserted at the back of each existing priority band.
        // Only affected subscribers are visited; no all-thread mutation scan.
        for tid in wake {
            self.blocked.timed_waiters.remove(tid);
            if self.next_turns.contains_key(&tid) && !self.run_queue.contains_tid(tid) {
                self.runqueue_push_back(tid);
                tracing::info!(target: "detcore::event_driven_io", "event-driven IO wake dtid {}", tid);
            }
        }
    }

    pub(super) fn park_io_dependencies(
        &mut self,
        tid: DetTid,
        request: &Resources,
    ) -> Option<Result<(), SkipTurn>> {
        if request.previous_attempt_made_progress
            || self.unresolved_sigkill
            || self.thread_is_doomed(tid)
        {
            return None;
        }
        let snapshot = request.io_dependencies.as_deref()?;
        if let Some(observer) = snapshot.1 {
            let current = self.io_observer(tid, observer.mm)?;
            if current.thread != observer.thread || current.process != observer.process
                || snapshot.0.iter().any(|(key, _)| {
                    matches!(key, Key::Signal(_, signal)
                        if current.excluded_signals & (1u64 << (*signal - 1)) != 0)
                })
            {
                return None;
            }
        }
        let deadline = request.poll_deadline.unwrap_or(LogicalTime::INDEFINITE);
        if deadline <= self.committed_time {
            return None;
        }
        if !self.io_dependencies.as_mut()?.register(tid, snapshot) {
            return None;
        }
        // A send can be drained before this request is selected to park. Its
        // notification is then gone, but the private ledger still owns the
        // copy. Keep probing so the helper can decide under its saved mask;
        // never sleep waiting for a second notification or a data mutation.
        if request.private_sigchld_decides
            && self.private_sigchld(tid) != 0
            && self.poll_mask_admits(tid, SigWrapper(libc::SIGCHLD))
        {
            self.cancel_io_dependencies(tid);
            return None;
        }
        self.note_sigalrm_polling_wait(tid, request);
        self.work_span_note_wait(tid, request);
        // Wakes retry the original operation, with its interruption metadata.
        // Never synthesize bytes, epoll events, readiness, or timeout results.
        self.upgrade_polled_to_runnable(tid, request);
        self.forget_poll_deadline(tid);
        self.blocked.timed_waiters.insert(deadline, tid);
        tracing::info!(target: "detcore::event_driven_io", "event-driven IO registered dtid {} deadline {:?}", tid, deadline);
        Some(self.skip_turn_blocked(tid))
    }

    /// Only a still-parked dependency retry may lift the internal poll's
    /// legacy private-SIGCHLD hold. For an InternalIOPolling request this
    /// timed-waiter membership is installed only after dependency registration;
    /// readiness, timeout and cancellation all remove it before requeueing.
    /// The helper owns the final queue/mask check, not this wake notification.
    pub(super) fn parked_io_private_sigchld(&self, tid: DetTid) -> u64 {
        if self.io_dependencies.is_none()
            || self.blocked.timed_waiters.thread_deadline(tid).is_none()
        {
            return 0;
        }
        let eligible = self
            .next_turns
            .get(&tid)
            .and_then(|turn| turn.req.try_read())
            .and_then(Result::ok)
            .is_some_and(|request| {
                request.private_sigchld_decides
                    && request.io_dependencies.is_some()
                    && request.resources.len() == 1
                    && request.resources.contains_key(&ResourceID::InternalIOPolling)
            });
        if eligible {
            self.private_sigchld(tid)
        } else {
            0
        }
    }

    pub(super) fn cancel_io_dependencies(&mut self, tid: DetTid) {
        if let Some(dependencies) = self.io_dependencies.as_mut() {
            dependencies.cancel(tid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::event_driven_io::Key;
    use crate::event_driven_io::Snapshot;
    use crate::event_driven_io::Update;
    use crate::types::OpenFileId;

    fn fixture() -> (Scheduler, Arc<Mutex<GlobalTime>>, DetTid, DetTid) {
        let config = Config {
            event_driven_io: true,
            backend: reverie::BackendCapabilities::PTRACE,
            sequentialize_threads: true,
            ..Config::default()
        };
        let mut scheduler = Scheduler::new(&config);
        scheduler.backend.supports_parked_write_signal_interruption = true;
        let waiter = DetTid::from_raw(100);
        let producer = DetTid::from_raw(101);
        scheduler.thread_tree.add_child(waiter, waiter, true);
        scheduler.thread_tree.add_child(waiter, producer, true);
        for tid in [waiter, producer] {
            test::register_known_thread_for(&mut scheduler, tid);
            scheduler.record_thread_mm(tid, MmId::initial(tid));
        }
        let global_time = Arc::new(Mutex::new(GlobalTime::new(&config)));
        (scheduler, global_time, waiter, producer)
    }

    fn park_dependency(scheduler: &mut Scheduler, waiter: DetTid, deadline: LogicalTime) -> Key {
        let key = Key::File(OpenFileId::new(waiter, 1));
        park_dependency_on(scheduler, waiter, deadline, key)
    }

    fn park_dependency_on(
        scheduler: &mut Scheduler,
        waiter: DetTid,
        deadline: LogicalTime,
        key: Key,
    ) -> Key {
        scheduler.event_driven_io(Update::Create(key, false));
        let snapshot = scheduler
            .event_driven_io(Update::Observe(vec![key], true, Vec::new()))
            .unwrap();
        let mut request = Resources::new(waiter);
        request.insert(ResourceID::InternalIOPolling, Permission::RW);
        request.poll_attempt = 1;
        request.poll_deadline = Some(deadline);
        request.signal_interrupt_errno = Some(libc::EINTR);
        request.private_sigchld_decides = true;
        request.io_dependencies = Some(Box::new(snapshot));
        scheduler.next_turns.get_mut(&waiter).unwrap().req = Ivar::full(Ok(request.clone()));
        scheduler.runqueue_push_back(waiter);
        assert_eq!(scheduler.run_queue.tentative_pop_tid(waiter), Some(waiter));
        assert!(
            scheduler
                .park_io_dependencies(waiter, &request)
                .unwrap()
                .is_err()
        );
        assert!(!scheduler.run_queue.contains_tid(waiter));
        assert_eq!(
            scheduler.blocked.timed_waiters.thread_deadline(waiter),
            Some(deadline)
        );
        let parked = scheduler.next_turns[&waiter]
            .req
            .try_read()
            .unwrap()
            .unwrap();
        assert_eq!(parked.signal_interrupt_errno(), Some(libc::EINTR));
        assert_eq!(parked.poll_deadline, Some(deadline));
        assert_eq!(
            scheduler.restartable_internal_io_signals(waiter),
            Some(Vec::new())
        );
        key
    }

    fn private_sigchld(scheduler: &mut Scheduler, waiter: DetTid) {
        let chld = kernel_signal_bit(libc::SIGCHLD);
        scheduler.test_kernel_signal_states.insert(
            waiter,
            KernelSignalState {
                pending: chld,
                thread_pending: chld,
                caught: chld,
                ..Default::default()
            },
        );
        scheduler.saved_guest_sigmasks.insert(waiter, 0);
        scheduler.child_exit_sigchld_control(
            waiter,
            child_exit_sigchld::ChildExitSigchldControl::PrivateSent { target: waiter },
        );
    }

    #[test]
    fn recorded_private_sigchld_cancels_dependency_wait_without_committing_the_copy() {
        for errno in [Errno::EINTR.into_raw(), Errno::ERESTARTSYS.into_raw()] {
            for deadline in [LogicalTime::from_nanos(1_000_000), LogicalTime::INDEFINITE] {
                let (mut scheduler, _, waiter, _) = fixture();
                let key = park_dependency(&mut scheduler, waiter, deadline);
                let mut request = scheduler.next_turns[&waiter].req.try_read().unwrap().unwrap();
                request.signal_interrupt_errno = Some(errno);
                scheduler.next_turns.get_mut(&waiter).unwrap().req = Ivar::full(Ok(request));
                private_sigchld(&mut scheduler, waiter);
                scheduler.notify_signal_pending(waiter, SigWrapper(libc::SIGCHLD));
                scheduler.drain_pending_cross_task_signals();

                assert!(scheduler.run_queue.contains_tid(waiter));
                assert_eq!(scheduler.blocked.timed_waiters.thread_deadline(waiter), None);
                assert!(!scheduler.io_dependencies.as_mut().unwrap().cancel(waiter));
                let wake = scheduler.next_turns[&waiter].req.try_read().unwrap().unwrap();
                assert_eq!(wake.signal_interrupt_errno(), Some(errno));
                assert!(wake.private_sigchld_decides);
                assert_eq!(scheduler.inbound_signals(waiter), vec![SigWrapper(libc::SIGCHLD)]);
                assert_eq!(
                    scheduler.blocked.drain_woken_waiters[&waiter],
                    DrainWoken {
                        waiter: DrainWokenWaiter::Poll,
                        scheduler_sent: false,
                    }
                );
                // Cancellation removes subscriptions as well as the timeout.
                // A later mutation cannot enqueue a second retry.
                let queued = scheduler.run_queue.len();
                scheduler.event_driven_io(Update::Change(vec![key]));
                assert_eq!(scheduler.run_queue.len(), queued);
                let response = scheduler.next_turns[&waiter].resp.clone();
                assert!(scheduler.unblock_guest(waiter, &response).is_ok());
                assert!(
                    matches!(response.try_read(), Some(SchedResponse::Signaled(Some(signals))) if signals.is_empty())
                );
                // Only the guest's saved-mask/private-queue check may take it.
                assert_eq!(scheduler.private_sigchld(waiter), kernel_signal_bit(libc::SIGCHLD));
            }
        }
    }

    #[test]
    fn dependency_wait_keeps_unowned_blocked_and_host_timed_sigchld_held() {
        for case in ["shared", "unrecorded private", "blocked", "host timed", "no metadata"] {
            let (mut scheduler, _, waiter, _) = fixture();
            let deadline = LogicalTime::INDEFINITE;
            park_dependency(&mut scheduler, waiter, deadline);
            let chld = kernel_signal_bit(libc::SIGCHLD);
            if matches!(case, "shared" | "unrecorded private") {
                scheduler.test_kernel_signal_states.insert(
                    waiter,
                    KernelSignalState {
                        pending: chld,
                        thread_pending: if case == "shared" { 0 } else { chld },
                        caught: chld,
                        ..Default::default()
                    },
                );
                scheduler.saved_guest_sigmasks.insert(waiter, 0);
            } else {
                private_sigchld(&mut scheduler, waiter);
            }
            match case {
                "blocked" => {
                    scheduler.saved_guest_sigmasks.insert(waiter, chld);
                    scheduler.test_kernel_signal_states.get_mut(&waiter).unwrap().blocked = chld;
                }
                "host timed" => {
                    scheduler.record_host_timed_signals(waiter, HostTimedSignalScope::Caller, chld);
                }
                "no metadata" => {
                    let mut request = scheduler.next_turns[&waiter].req.try_read().unwrap().unwrap();
                    request.private_sigchld_decides = false;
                    scheduler.next_turns.get_mut(&waiter).unwrap().req = Ivar::full(Ok(request));
                }
                _ => {}
            }
            scheduler.notify_signal_pending(waiter, SigWrapper(libc::SIGCHLD));
            scheduler.drain_pending_cross_task_signals();
            assert!(!scheduler.run_queue.contains_tid(waiter), "{case}");
            assert_eq!(scheduler.blocked.timed_waiters.thread_deadline(waiter), Some(deadline), "{case}");
            assert!(scheduler.inbound_signals(waiter).is_empty(), "{case}");
            assert!(scheduler.io_dependencies.as_mut().unwrap().cancel(waiter), "{case}");
        }
    }

    #[test]
    fn private_sigchld_before_registration_cannot_lose_its_wakeup() {
        let (mut scheduler, _, waiter, _) = fixture();
        park_dependency(&mut scheduler, waiter, LogicalTime::INDEFINITE);
        // Recreate the filed-but-not-yet-registered retry, without changing
        // the observed source generation.
        scheduler.cancel_io_dependencies(waiter);
        scheduler.blocked.timed_waiters.remove(waiter);
        scheduler.runqueue_push_back(waiter);
        private_sigchld(&mut scheduler, waiter);
        scheduler.notify_signal_pending(waiter, SigWrapper(libc::SIGCHLD));
        scheduler.drain_pending_cross_task_signals();
        let request = scheduler.next_turns[&waiter].req.try_read().unwrap().unwrap();
        assert!(request.resources.contains_key(&ResourceID::InternalIOPolling));
        assert_eq!(scheduler.run_queue.tentative_pop_tid(waiter), Some(waiter));
        assert!(scheduler.park_io_dependencies(waiter, &request).is_none());
        scheduler.run_queue.undo_tentative_pop();
        assert_eq!(scheduler.blocked.timed_waiters.thread_deadline(waiter), None);
        assert!(!scheduler.io_dependencies.as_mut().unwrap().cancel(waiter));
        assert_eq!(scheduler.private_sigchld(waiter), kernel_signal_bit(libc::SIGCHLD));
    }

    #[test]
    fn readiness_before_private_sigchld_keeps_the_original_retry() {
        let (mut scheduler, _, waiter, _) = fixture();
        let key = park_dependency(&mut scheduler, waiter, LogicalTime::INDEFINITE);
        scheduler.event_driven_io(Update::Change(vec![key]));
        private_sigchld(&mut scheduler, waiter);
        scheduler.notify_signal_pending(waiter, SigWrapper(libc::SIGCHLD));
        scheduler.drain_pending_cross_task_signals();
        assert!(scheduler.run_queue.contains_tid(waiter));
        assert_eq!(scheduler.blocked.timed_waiters.thread_deadline(waiter), None);
        assert!(!scheduler.blocked.drain_woken_waiters.contains_key(&waiter));
        let request = scheduler.next_turns[&waiter].req.try_read().unwrap().unwrap();
        assert!(request.resources.contains_key(&ResourceID::InternalIOPolling));
        assert!(request.private_sigchld_decides);
    }

    fn start_external(scheduler: &mut Scheduler, thread: DetTid) -> ExternalOpId {
        let op = ExternalOpId::new(thread, 1);
        scheduler.runqueue_push_back(thread);
        assert_eq!(scheduler.run_queue.tentative_pop_tid(thread), Some(thread));
        assert!(
            scheduler
                .block_for_one_resource(
                    thread,
                    &ResourceID::BlockingExternalIO(op),
                    &Permission::RW,
                    None,
                    None,
                    &Ivar::new(),
                )
                .is_err()
        );
        assert_eq!(
            scheduler.blocked.external_io_blockers.get(&thread),
            Some(&op)
        );
        op
    }

    #[test]
    fn finite_dependency_wait_defers_to_external_completion_and_its_continuation() {
        for external_started_first in [false, true] {
            let (mut scheduler, global_time, waiter, producer) = fixture();
            let now = global_time.lock().unwrap().as_nanos();
            let deadline = now + LogicalTime::from_nanos(1_000_000);
            let mut op = None;
            if external_started_first {
                op = Some(start_external(&mut scheduler, producer));
            }
            let key = park_dependency(&mut scheduler, waiter, deadline);
            let op = op.unwrap_or_else(|| start_external(&mut scheduler, producer));
            // A later external grant must be caught too: registration alone
            // cannot establish quiescence for the lifetime of a parked wait.
            for _ in 0..3 {
                assert!(scheduler.step2c_process_io_blockers().is_ok());
                assert!(scheduler.step2d_handle_empty_queue(&global_time).is_err());
                assert_eq!(global_time.lock().unwrap().as_nanos(), now);
                assert_eq!(scheduler.empty_queue_wakes, 0);
                assert_eq!(
                    scheduler.blocked.timed_waiters.thread_deadline(waiter),
                    Some(deadline)
                );
                assert!(scheduler.run_queue.is_empty());
                assert!(scheduler.terminal_deadlock.is_none());
            }

            let mut continuation = Resources::new(producer);
            continuation.insert(ResourceID::BlockedExternalContinue(op), Permission::RW);
            scheduler.next_turns[&producer].req.put(Ok(continuation));
            // A filed completion is not yet a granted continuation.
            assert!(scheduler.step2d_handle_empty_queue(&global_time).is_err());
            assert_eq!(global_time.lock().unwrap().as_nanos(), now);
            assert!(scheduler.step2c_process_io_blockers().is_ok());
            assert!(scheduler.blocked.external_io_blockers.is_empty());
            assert!(scheduler.run_queue.contains_tid(producer));
            assert!(scheduler.step2d_handle_empty_queue(&global_time).is_ok());
            assert_eq!(global_time.lock().unwrap().as_nanos(), now);

            // A deterministic source mutation from that continuation wins
            // over the timeout, irrespective of the host completion delay.
            scheduler.event_driven_io(Update::Change(vec![key]));
            assert!(scheduler.run_queue.contains_tid(waiter));
            assert_eq!(
                scheduler.blocked.timed_waiters.thread_deadline(waiter),
                None
            );
            assert_eq!(global_time.lock().unwrap().as_nanos(), now);
        }
    }

    #[test]
    fn finite_dependency_jump_resumes_after_continuation_parks_internally() {
        let (mut scheduler, global_time, waiter, producer) = fixture();
        let now = global_time.lock().unwrap().as_nanos();
        let deadline = now + LogicalTime::from_nanos(1_000_000);
        park_dependency(&mut scheduler, waiter, deadline);
        let op = start_external(&mut scheduler, producer);
        assert!(scheduler.step2d_handle_empty_queue(&global_time).is_err());
        assert_eq!(global_time.lock().unwrap().as_nanos(), now);

        let mut continuation = Resources::new(producer);
        continuation.insert(ResourceID::BlockedExternalContinue(op), Permission::RW);
        scheduler.next_turns[&producer].req.put(Ok(continuation));
        assert!(scheduler.step2c_process_io_blockers().is_ok());
        let sleep = deadline + LogicalTime::from_nanos(1_000_000);
        // Model the readmitted continuation reaching its next internal wait.
        let mut request = Resources::new(producer);
        request.insert(ResourceID::SleepUntil(sleep), Permission::RW);
        scheduler.next_turns.get_mut(&producer).unwrap().req = Ivar::full(Ok(request));
        assert_eq!(
            scheduler.run_queue.tentative_pop_tid(producer),
            Some(producer)
        );
        assert!(
            scheduler
                .block_for_one_resource(
                    producer,
                    &ResourceID::SleepUntil(sleep),
                    &Permission::RW,
                    None,
                    None,
                    &Ivar::new(),
                )
                .is_err()
        );
        assert!(scheduler.step2d_handle_empty_queue(&global_time).is_err());
        assert_eq!(global_time.lock().unwrap().as_nanos(), deadline);
        assert_eq!(scheduler.empty_queue_wakes, 1);
        assert!(scheduler.run_queue.contains_tid(waiter));
        assert!(!scheduler.run_queue.contains_tid(producer));
        assert_eq!(
            scheduler.blocked.timed_waiters.thread_deadline(waiter),
            None
        );
        assert_eq!(
            scheduler.blocked.timed_waiters.thread_deadline(producer),
            Some(sleep)
        );
    }

    #[test]
    fn finite_child_sleep_remains_eligible_but_unresolved_child_completion_does_not() {
        let (mut scheduler, global_time, waiter, producer) = fixture();
        scheduler.complete_child_lineage = true;
        let child = DetTid::from_raw(102);
        scheduler.thread_tree.add_child(producer, child, true);
        test::register_known_thread_for(&mut scheduler, child);
        let now = global_time.lock().unwrap().as_nanos();
        let deadline = now + LogicalTime::from_nanos(2_000_000);
        let child_deadline = now + LogicalTime::from_nanos(1_000_000);
        park_dependency(&mut scheduler, waiter, deadline);
        scheduler.blocked.child_waiters.insert(
            producer,
            (
                DetPid::from_raw(producer.as_raw()),
                ChildWaitSpec {
                    selector: ChildWaitSelector::Any,
                    owner: None,
                    exit_class: ChildWaitExitClass::Sigchld,
                },
            ),
        );
        // A child not yet stopped at a modeled wait may still complete.
        assert!(scheduler.step2d_handle_empty_queue(&global_time).is_err());
        assert_eq!(global_time.lock().unwrap().as_nanos(), now);
        let mut sleep = Resources::new(child);
        sleep.insert(ResourceID::SleepUntil(child_deadline), Permission::RW);
        scheduler.next_turns.get_mut(&child).unwrap().req = Ivar::full(Ok(sleep));
        scheduler
            .blocked
            .timed_waiters
            .insert(child_deadline, child);
        assert!(!scheduler.child_waits_wait_only_on_stuck_children());
        assert!(scheduler.step2d_handle_empty_queue(&global_time).is_err());
        assert_eq!(global_time.lock().unwrap().as_nanos(), child_deadline);
        assert!(scheduler.run_queue.contains_tid(child));
        assert!(!scheduler.run_queue.contains_tid(waiter));
        assert_eq!(
            scheduler.blocked.timed_waiters.thread_deadline(waiter),
            Some(deadline)
        );
    }

    #[test]
    fn disabled_policy_keeps_legacy_finite_jump_with_external_io() {
        let config = Config::default();
        let mut scheduler = Scheduler::new(&config);
        let global_time = Arc::new(Mutex::new(GlobalTime::new(&config)));
        let waiter = DetTid::from_raw(100);
        let producer = DetTid::from_raw(101);
        test::register_known_thread_for(&mut scheduler, waiter);
        scheduler.next_turns.get_mut(&waiter).unwrap().req = Ivar::full(Ok(Resources::new(waiter)));
        let deadline = global_time.lock().unwrap().as_nanos() + LogicalTime::from_nanos(1_000_000);
        scheduler.blocked.timed_waiters.insert(deadline, waiter);
        scheduler
            .blocked
            .external_io_blockers
            .insert(producer, ExternalOpId::new(producer, 1));
        assert!(scheduler.step2d_handle_empty_queue(&global_time).is_err());
        assert_eq!(global_time.lock().unwrap().as_nanos(), deadline);
        assert!(scheduler.run_queue.contains_tid(waiter));
    }

    fn grant_exit(scheduler: &mut Scheduler, caller: DetTid, process: DetPid, group: bool) {
        let mm = MmId::initial(process);
        scheduler.runqueue_push_back(caller);
        let response = scheduler.next_turns[&caller].resp.clone();
        assert!(scheduler.block_for_one_resource(
            caller,
            &ResourceID::Exit { group, process, mm },
            &Permission::RW,
            None,
            None,
            &response,
        ).is_ok());
    }

    #[test]
    fn raw_shared_thread_exit_preserves_authority_behind_empty_request() {
        let (mut scheduler, _, waiter, process) = fixture();
        let worker = DetTid::from_raw(102);
        scheduler.thread_tree.add_child(process, worker, false);
        test::register_known_thread_for(&mut scheduler, worker);
        let key = park_dependency(&mut scheduler, waiter, LogicalTime::INDEFINITE);
        let stale = scheduler.event_driven_io(Update::Observe(vec![key], true, Vec::new())).unwrap();
        grant_exit(&mut scheduler, worker, process, false);
        assert!(scheduler.child_exit_publications_pending.is_empty());
        scheduler.event_driven_io_lifecycle(worker, MmId::initial(process), vec![key]);
        assert!(scheduler.run_queue.contains_tid(waiter));
        assert!(scheduler.are_all_quiesced().is_some());
        assert!(!scheduler.io_dependencies.as_mut().unwrap().register(waiter, &stale));
        let fresh = scheduler.event_driven_io(Update::Observe(vec![key], true, Vec::new())).unwrap();
        assert!(scheduler.io_dependencies.as_mut().unwrap().register(waiter, &fresh));
        // A later mutation from the surviving shared-table owner still notifies.
        scheduler.event_driven_io(Update::Change(vec![key]));
        assert!(!scheduler.io_dependencies.as_mut().unwrap().cancel(waiter));
        assert!(scheduler.event_driven_io(Update::Observe(vec![key], true, Vec::new())).is_some());
    }

    #[test]
    fn group_lifecycle_wake_cannot_cross_physical_close_and_does_not_lose_pipe_eof() {
        use std::os::fd::AsRawFd;
        let (mut scheduler, _, waiter, process) = fixture();
        let sibling = DetTid::from_raw(102);
        scheduler.thread_tree.add_child(process, sibling, false);
        test::register_known_thread_for(&mut scheduler, sibling);
        let (reader, writer) = nix::unistd::pipe2(nix::fcntl::OFlag::O_NONBLOCK).unwrap();
        let sibling_writer = writer.try_clone().unwrap();
        let pipe = Key::Pipe(crate::pipe_wake::ChannelId::Pipe(OpenFileId::new(process, 1)));
        let epoll = Key::File(OpenFileId::new(waiter, 2));
        scheduler.event_driven_io(Update::Create(pipe, false));
        scheduler.event_driven_io(Update::Create(epoll, true));
        scheduler.event_driven_io(Update::Epoll {
            epoll, fd: reader.as_raw_fd(),
            identity: Some(OpenFileId::new(process, 1)),
            target: Some(pipe), operation: libc::EPOLL_CTL_ADD,
        });
        park_dependency_on(&mut scheduler, waiter, LogicalTime::INDEFINITE, epoll);
        grant_exit(&mut scheduler, process, process, true);
        scheduler.event_driven_io_lifecycle(process, MmId::initial(process), vec![pipe]);
        assert!(scheduler.run_queue.contains_tid(waiter));
        assert_eq!(scheduler.blocked.timed_waiters.thread_deadline(waiter), None);
        assert!(scheduler.are_all_quiesced().is_some());
        let mut byte = [0u8; 1];
        // The queued wake is not EOF: the real writer is deliberately still open.
        assert_eq!(unsafe { libc::read(reader.as_raw_fd(), byte.as_mut_ptr().cast(), 1) }, -1);
        assert_eq!(nix::errno::Errno::last(), nix::errno::Errno::EAGAIN);
        // Even if the initiating thread's empty-request hold is removed, group
        // publication independently prevents an awakened peer from probing.
        scheduler.next_turns[&process].req.put(Ok(Resources::new(process)));
        assert!(scheduler.are_all_quiesced().is_none());
        assert!(scheduler.step2_drain_prefix().is_err());
        drop(writer);
        assert!(scheduler.step2_drain_prefix().is_err());
        assert_eq!(unsafe { libc::read(reader.as_raw_fd(), byte.as_mut_ptr().cast(), 1) }, -1);
        assert_eq!(nix::errno::Errno::last(), nix::errno::Errno::EAGAIN);
        drop(sibling_writer);
        assert!(scheduler.complete_child_exit_publication(process));
        assert!(scheduler.step2_drain_prefix().is_ok());
        assert_eq!(unsafe { libc::read(reader.as_raw_fd(), byte.as_mut_ptr().cast(), 1) }, 0);
        assert!(scheduler.event_driven_io(Update::Observe(vec![epoll], true, Vec::new())).is_some());
        assert!(!scheduler.io_dependencies.as_mut().unwrap().cancel(waiter));
    }

    #[test]
    fn failed_exec_keeps_authority_and_the_prepared_empty_request_hold() {
        let (mut scheduler, _, waiter, caller) = fixture();
        let mm = MmId::initial(caller);
        let key = park_dependency(&mut scheduler, waiter, LogicalTime::INDEFINITE);
        scheduler.runqueue_push_back(caller);
        assert!(scheduler.prepare_exec_teardown(caller, caller, mm));
        scheduler.event_driven_io_lifecycle(caller, mm, vec![key]);
        assert!(scheduler.are_all_quiesced().is_some());
        assert!(scheduler.run_queue.contains_tid(waiter));
        // CancelExec runs only after the handler restores old metadata/mm.
        assert!(scheduler.finish_exec_teardown(caller, caller, mm, false).is_empty());
        assert!(scheduler.are_all_quiesced().is_some());
        let fresh = scheduler.event_driven_io(Update::Observe(vec![key], true, Vec::new())).unwrap();
        assert!(scheduler.io_dependencies.as_mut().unwrap().register(waiter, &fresh));
        scheduler.next_turns[&caller].req.put(Ok(Resources::new(caller)));
        assert!(scheduler.are_all_quiesced().is_none());
        scheduler.event_driven_io(Update::Change(vec![key]));
        assert!(!scheduler.io_dependencies.as_mut().unwrap().cancel(waiter));
    }

    #[test]
    fn unproven_lifecycle_identity_backend_or_turn_retains_revocation() {
        for gap in 0..7 {
            let (mut scheduler, _, waiter, caller) = fixture();
            let mm = MmId::initial(caller);
            let key = park_dependency(&mut scheduler, waiter, LogicalTime::INDEFINITE);
            scheduler.runqueue_push_back(caller);
            scheduler.exec_incarnations.insert(caller, mm);
            match gap {
                0 => {} // No grant or prepared cohort.
                1 => scheduler.note_io_exit_grant(caller, waiter, mm, false, false, false),
                2 => scheduler.note_io_exit_grant(caller, caller, mm, true, false, false),
                3 => {
                    assert!(scheduler.prepare_exec_teardown(caller, caller, mm));
                    scheduler.backend.rediscovers_descriptors_after_exec = true;
                }
                4 => {
                    assert!(scheduler.prepare_exec_teardown(caller, caller, mm));
                    scheduler.next_turns[&caller].req.put(Ok(Resources::new(caller)));
                }
                5 => { assert!(scheduler.prepare_exec_teardown(caller, caller, mm)); }
                6 => scheduler.note_io_exit_grant(caller, caller, mm, true, true, false),
                _ => unreachable!(),
            }
            let supplied_mm = if gap == 5 { mm.for_exec(caller) } else { mm };
            scheduler.event_driven_io_lifecycle(caller, supplied_mm, vec![key]);
            assert!(scheduler.run_queue.contains_tid(waiter));
            assert!(scheduler.event_driven_io(Update::Observe(vec![key], true, Vec::new())).is_none());
        }
    }

    #[test]
    fn last_raw_exit_uses_process_publication_and_keeps_source_authority() {
        let (mut scheduler, _, waiter, caller) = fixture();
        let key = park_dependency(&mut scheduler, waiter, LogicalTime::INDEFINITE);
        grant_exit(&mut scheduler, caller, caller, false);
        assert!(scheduler.child_exit_publications_pending.contains(&caller));
        scheduler.event_driven_io_lifecycle(caller, MmId::initial(caller), vec![key]);
        assert!(scheduler.run_queue.contains_tid(waiter));
        assert!(scheduler.step2_drain_prefix().is_err());
        assert!(scheduler.event_driven_io(Update::Observe(vec![key], true, Vec::new())).is_some());
    }

    #[test]
    fn publication_before_exit_grant_preserves_shared_source_authority() {
        for group in [false, true] {
            let (mut scheduler, _, waiter, caller) = fixture();
            let key = park_dependency(&mut scheduler, waiter, LogicalTime::INDEFINITE);
            assert!(!scheduler.complete_child_exit_publication(caller));
            grant_exit(&mut scheduler, caller, caller, group);
            assert!(!scheduler.child_exit_publications_pending.contains(&caller));
            assert!(!scheduler.child_exit_publications_completed.contains(&caller));
            scheduler.event_driven_io_lifecycle(caller, MmId::initial(caller), vec![key]);
            assert!(scheduler.run_queue.contains_tid(waiter));
            assert_eq!(scheduler.blocked.timed_waiters.thread_deadline(waiter), None);
            let fresh = scheduler.event_driven_io(Update::Observe(vec![key], true, Vec::new())).unwrap();
            assert!(scheduler.io_dependencies.as_mut().unwrap().register(waiter, &fresh));
        }
    }

    #[test]
    fn cancellation_before_lifecycle_notification_leaves_no_stale_subscriber() {
        let (mut scheduler, _, waiter, caller) = fixture();
        let mm = MmId::initial(caller);
        let key = park_dependency(&mut scheduler, waiter, LogicalTime::INDEFINITE);
        scheduler.cancel_io_dependencies(waiter);
        scheduler.runqueue_push_back(caller);
        assert!(scheduler.prepare_exec_teardown(caller, caller, mm));
        scheduler.event_driven_io_lifecycle(caller, mm, vec![key]);
        assert!(!scheduler.run_queue.contains_tid(waiter));
        let fresh = scheduler.event_driven_io(Update::Observe(vec![key], true, Vec::new())).unwrap();
        assert!(scheduler.io_dependencies.as_mut().unwrap().register(waiter, &fresh));
        scheduler.event_driven_io(Update::Change(vec![key]));
        assert!(scheduler.run_queue.contains_tid(waiter));
        assert!(!scheduler.io_dependencies.as_mut().unwrap().cancel(waiter));
    }
    fn signalfd_snapshot(scheduler: &mut Scheduler, waiter: DetTid, signal: i32) -> (Key, Snapshot) {
        let key = Key::File(OpenFileId::new(waiter, 19));
        let mm = MmId::initial(waiter);
        scheduler.event_driven_io_from(waiter, mm, Update::Signalfd {
            key, mask: Some(kernel_signal_bit(signal)), create: true,
        });
        let snapshot = scheduler.event_driven_io_from(
            waiter, mm, Update::Observe(vec![key], true, Vec::new()),
        ).unwrap();
        (key, snapshot)
    }

    #[test]
    fn signalfd_observation_authenticates_task_mm_and_process() {
        let (mut scheduler, _, waiter, other) = fixture();
        let (key, _) = signalfd_snapshot(&mut scheduler, waiter, libc::SIGUSR1);
        scheduler.exec_incarnations.insert(waiter, MmId::initial(waiter));
        assert!(scheduler.event_driven_io_from(
            waiter, MmId::initial(other), Update::Observe(vec![key], true, Vec::new()),
        ).is_none());
        let foreign = DetTid::from_raw(999);
        assert!(scheduler.event_driven_io_from(
            foreign, MmId::initial(foreign), Update::Observe(vec![key], true, Vec::new()),
        ).is_none());
        scheduler.thread_tree.thread_to_leader.remove(&waiter);
        assert!(scheduler.event_driven_io_from(
            waiter, MmId::initial(waiter), Update::Observe(vec![key], true, Vec::new()),
        ).is_none());
    }

    #[test]
    fn signalfd_registration_rechecks_observer_incarnation() {
        let (mut scheduler, _, waiter, other) = fixture();
        let (_, snapshot) = signalfd_snapshot(&mut scheduler, waiter, libc::SIGUSR1);
        let mut request = Resources::new(waiter);
        request.insert(ResourceID::InternalIOPolling, Permission::RW);
        request.poll_attempt = 1;
        request.io_dependencies = Some(Box::new(snapshot));
        scheduler.exec_incarnations.insert(waiter, MmId::initial(other));
        assert!(scheduler.park_io_dependencies(waiter, &request).is_none());
    }

    #[test]
    fn signalfd_host_source_wakes_existing_wait_and_rejects_old_snapshot() {
        for scope in [HostTimedSignalScope::Caller, HostTimedSignalScope::Container] {
            let (mut scheduler, _, waiter, _) = fixture();
            let (key, snapshot) = signalfd_snapshot(&mut scheduler, waiter, libc::SIGUSR1);
            assert!(scheduler.io_dependencies.as_mut().unwrap().register(waiter, &snapshot));
            scheduler.blocked.timed_waiters.insert(LogicalTime::INDEFINITE, waiter);
            scheduler.event_driven_io_host_signals(waiter, scope, kernel_signal_bit(libc::SIGUSR1));
            assert!(scheduler.run_queue.contains_tid(waiter));
            assert_eq!(scheduler.blocked.timed_waiters.thread_deadline(waiter), None);
            assert!(!scheduler.io_dependencies.as_mut().unwrap().register(waiter, &snapshot));
            assert!(scheduler.event_driven_io_from(
                waiter, MmId::initial(waiter), Update::Observe(vec![key], true, Vec::new()),
            ).is_none());
            // Graph-only producer exclusions do not alter custody's ledger.
            assert_eq!(scheduler.host_timed_signals(waiter) & kernel_signal_bit(libc::SIGUSR1), 0);
        }
    }

    #[test]
    fn signalfd_unsupported_producers_fall_back_without_affecting_eventfd() {
        for signal in [
            libc::SIGCHLD, libc::SIGWINCH, libc::SIGSEGV, libc::SIGPIPE,
            libc::SIGXFSZ, libc::SIGXCPU, libc::SIGSTKFLT, libc::SIGUSR1,
        ] {
            let (mut scheduler, _, waiter, _) = fixture();
            let key = Key::File(OpenFileId::new(waiter, 19));
            let mm = MmId::initial(waiter);
            if signal == libc::SIGUSR1 {
                scheduler.host_timed_signals_everywhere |= kernel_signal_bit(signal);
            }
            scheduler.event_driven_io_from(waiter, mm, Update::Signalfd {
                key, mask: Some(kernel_signal_bit(signal)), create: true,
            });
            assert!(scheduler.event_driven_io_from(
                waiter, mm, Update::Observe(vec![key], true, Vec::new()),
            ).is_none());
            let eventfd = Key::File(OpenFileId::new(waiter, 20));
            scheduler.event_driven_io_from(waiter, mm, Update::Create(eventfd, false));
            assert!(scheduler.event_driven_io_from(
                waiter, mm, Update::Observe(vec![eventfd], true, Vec::new()),
            ).is_some());
        }
    }
}
