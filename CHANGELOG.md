# Hermit

Notable changes for users. Versions 0.5.0 and 0.5.2 describe crate releases;
0.5.1 and 0.5.3 describe selected development snapshots. The 0.5.2 release
branches from 0.5.0.

## 0.5.3 (Unreleased)

- Integrate upstream Hermit `94cafc22b1ead` and Reverie baseline
  `bca5399182da`, retaining run-local shared memory, event-driven readiness and
  authenticated process-signal dequeue reservations. Forward shared-backing
  capabilities and local state through upstream's `NativeOperationGuest`, so
  supported SysV calls do not incorrectly return `ENOSYS`. Global RPC revision
  23 rejects older, incompatible scheduler messages before decoding them.
  Preserve upstream Linux receiver selection and process-pending group delivery;
  separately queued thread signals keep their own sender identity and lifetime.
  OCI workdir binds cannot claim custody of Hermit's generated private `/tmp`.
- Support scheduler-owned blocking `flock` under `--event-driven-io` on
  native ptrace for regular files in the authenticated private `/tmp` mount
  on supported local filesystems. Kernel nonblocking probes remain authoritative;
  a retained native OFD survives close/reuse of the original fd number.
  Unlock, conversion, close, exit and traced descriptor-transfer transitions
  wake indexed waiters without periodic polling. Preserve shared/exclusive
  exclusion, Linux's non-atomic conversions, interruption and restart.
  Retire lock domains with their last live description/wait so native inode reuse
  cannot change logical lock identities across repeats.
  Native probes reuse the original fd only after exact `KCMP_FILE` validation;
  otherwise a transient imported alias preserves custody and guest lock-owner PID.
  Unproved external producers and unsupported backends remain fail-closed.
  Losing SCM_RIGHTS accounting revokes lock-wait authority and wakes waiters
  into refusal, including bounded-queue eviction and unmatched delivery.
  Managed-lock fdinfo uses the existing structured renderer instead of the legacy
  empty-file sanitizer; unsupported native process-lock/lease attribution is refused.
  The Reverie submodule now points to the revofusion fork.
- Add `hermit run --event-driven-io`, an explicit scheduling/time policy for
  sequential native ptrace runs with isolated local networking. After an empty
  probe, tracked eventfd/anonymous-pipe waits, scheduler-owned signalfd waits,
  owned Unix-stream socket waits, and epoll graphs containing only tracked
  sources park until a dependency changes, a signal interrupts, or the
  original virtual deadline expires. Open-file identities, generation-checked
  registration and indexed subscribers prevent fd reuse and missed wakeups;
  Linux still supplies readiness, bytes and epoll edge/oneshot results.
  Idle deadline jumps wait for unresolved external completions. This policy can
  change schedules and timestamps relative to physical polling; it is refused
  with legacy schedule recording/replay, passthrough interception, host
  networking, in-guest signal delivery and unsupported backends.
  Unix socket authority requires traced OFDs and abstract names or physically
  resolved paths beneath the launch-authenticated private `/tmp`; shared mounts,
  symlinks, descriptor exports and unproved producers retain conservative fallback.
  Unused TCP listeners can park only until an ingress-capable operation revokes
  their authority before execution. This is not a TCP simulator: active TCP,
  other unowned sockets and timerfds retain physical probes.
  Read-only route-interface dumps, traced INET UDP traffic, proven regular-file
  copies and ordinary local socket options no longer revoke unrelated stream
  authority. Passive MPTCP listeners share TCP's no-ingress restriction.
  Passing traced anonymous pipes or managed flock files across a proven traced
  Unix stream channel does not revoke every socket; pipe sources still lose
  authority, while flock transitions keep their per-file dependency. Other
  descriptor transfers close socket authority and unknown exports also withdraw
  flock authority. Proven tool-owned fdinfo reads used for received-descriptor
  lock accounting no longer masquerade as unowned socket operations.
  Netlink mutations, unproven ancillary data and Unix datagrams still fall back.
  Signalfd subscriptions follow the observer's private/process queues and the
  exact shared mask; mask replacement preserves dup/fork identities and flags.
  Epoll signalfd watches require the original ADD task/process/address space.
  Unowned signal producers, SIGCHLD, kernel/terminal signals, POSIX timer masks
  and background reads retain conservative fallback. Blocked signal sends wake
  readiness probes without manufacturing EINTR or signal records.
  Masked/select-family waits and specialized pipe-write waits retain
  their existing paths. Native signal-provenance restrictions remain: a
  process-shared or host-timed SIGCHLD cannot decide a gated wait merely
  because it appears pending in the kernel. Authenticated native exec/exit
  boundaries preserve source authority and queue re-probes behind the existing
  physical-completion barriers; failed exec preserves surviving descriptors.
  Unknown lifecycle boundaries and uncertain kernel mutations revoke affected
  authority; unprovable descriptor-table/transfer lifetimes can disable parking.
  Generic nonblocking/CLOEXEC flag ioctls and terminal queries on positively
  identified null/zero/full devices preserve dependency authority.
  INFO counters and first-attempt fallback diagnostics under
  `detcore::event_driven_io` report registrations, wakes and coverage; positive
  idle-time jumps report their exact nanosecond delta at INFO level.
  Verification records, PMU preemption and syscall validation are not relaxed.
- Add opt-in internal `read`/`readv`/`poll` wait diagnostics with
  `RUST_LOG=detcore::wait_probe=debug`. Begin/probe/end records include the
  deterministic thread, retry index, helper-level probe result and would-block
  classification, descriptor identity/type, and poll event masks. `end` reports
  the retry-loop result before signal restoration; the existing syscall-finish
  record remains authoritative for the guest result. Poll snapshots are bounded
  to 1,024 entries, with truncation and unreadable memory explicitly reported.
  Logging adds no injections, clock observations, or scheduling decisions;
  disabled diagnostics perform no descriptor lookup or guest-memory read.
  Broad DEBUG/TRACE filters also enable it; force it off with
  `RUST_LOG=detcore::wait_probe=off`. Detailed logging adds host overhead and is
  not a wall-time profiler.
- Do not give non-chaos `vfork` children a permanent priority boost after
  exec. The existing vfork barrier still enforces child-first execution until
  exec/exit, but a CPU-busy new image no longer starves its parent or unrelated
  normal-priority services. Chaos and replay priority selection are unchanged.
- Keep debug clock-invariant validation independent without rescanning every
  historical thread on every update. An exact reduction tree validates thread
  updates in logarithmic time and scheduler-only updates in constant time;
  exec and deserialization rebuild it from the unchanged canonical maps.
  Logical time, saturating arithmetic, and serialized clock formats are unchanged.
- Honor per-call `MSG_DONTWAIT` for all six socket send/receive APIs, even
  when the descriptor is logically blocking. Return the kernel's `EAGAIN`
  instead of retrying indefinitely, without changing shared descriptor flags.
- Do not accumulate wall-clock backoff while skipped grants are making
  deterministic scheduler progress. Groups of blocked pollers previously paid
  exponential sleeps while being requeued, before their next probes could run.
  Such transitions still yield; genuinely stalled passes retain timed backoff.
  Queue ordering, logical-time charges and verification records are unchanged.
- Reserve a native cross-process caught signal's recipient through its actual
  dequeue before allowing other guest turns. An eligible leader, or a sole
  eligible sibling, may now receive `kill` while parked in restartable internal
  IO polling, native `epoll_wait` (which retains `EINTR`, even with
  `SA_RESTART`), or an expired CPU slice. Slice returns retain native signal
  dequeue and do not synthesize a syscall interruption. A recorded parent-death
  `SIGKILL` source no longer prevents unrelated caught-signal delivery: it cannot
  run a handler or coalesce with that signal, and its source remains tracked.
  Other host-timed sources still exclude reservations. The original kernel call
  retains `SI_USER`, sender identity and the process-shared queue.
  Conflicting pending copies, signal waiters/signalfds, unproven private masks,
  unstable tasks and unsupported backends cannot use this stronger reservation.
  Supported calls can instead use upstream's checked native receiver selection;
  calls with competing kernel sigwait/signalfd consumers still refuse.
  Plain native epoll's own private mask is admitted only with explicit guard
  provenance, a matching kernel mask and verified restoration before dequeue.
  A copy consumed during restoration retains the reservation through ptrace's
  captured siginfo custody; the final callback must match the send ledger's
  `SI_USER`, sender process and native UID before its delivery grant releases
  peers. Unreported delivery and missing/mismatched custody fail closed, and
  guest temporary-mask calls remain excluded from this reservation. Global RPC
  revision 22 requires the combined upstream receiver-selection and local
  reservation, guard and custody protocol.
- Hold ptrace peer scheduling through a process's complete exit, including
  implicit socket closure by the last exiting thread, regardless of the
  parent's SIGCHLD disposition. Epoll consumers no longer race a nonleader's
  `exit_group` cleanup; descriptor references retained by other processes
  continue to work.
- Consume ignored SIGCHLD notifications without scheduling a signal-delivery
  turn. A parent reaping children can now progress while unrelated services
  remain runnable; caught signals and blocked signal waits retain their
  notification and siginfo semantics.
- Retry signal injections interrupted before execution without resending earlier
  process-group recipients. Group SIGKILL no longer leaves multithreaded
  descendants alive after a partially completed fanout.
- Keep a ptrace group-kill sender's child notifications queued through the
  cohort commit and exit-publication fence, then restore its guest signal mask.
  Caught notifications no longer bypass scheduler admission, and ignored
  notifications are classified using the sender's original mask.
- Select deterministic source ports for native IPv4/IPv6 TCP and UDP `connect`
  using Linux's `IP_LOCAL_PORT_RANGE`, restoring the guest's per-socket range
  before yielding. Both endpoints observe the real selected address; explicit
  binds, invalid-call behavior, narrow user ranges and UDP disconnects retain
  native semantics. Client allocation advances past closed TCP ports and releases
  disconnected UDP reservations. Kernels without the required socket option are
  refused rather than falling back to randomized source ports.
- Advance the global RPC revision for process-group queries, restricted SIGKILL
  reservations and client-port allocation, so incompatible runtimes and
  coordinators refuse each other before decoding messages.
- Include `patches/ssp-route-hints-count.patch` for SSP's existing zero-hint
  setting: disabled hints no longer require managed regtest routing nodes.
- Read the calling process's `/proc/.../cmdline` from its current argument
  memory on ptrace and KVM, including rewritten arguments, thread aliases and
  positioned reads. Reading another process's command line remains a KVM gap.
- Freeze `/etc/ld.so.cache` inside each container when the host has one, so a
  package installation cannot replace the dynamic linker's cache mid-run.
- Reduce temporary allocations in syscall forwarding when no record/replay
  tool is active, while retaining the record/replay tool path for recordings.
- Allow the Redis integration workloads to use explicitly declared
  `redis-server` and `redis-cli` executables through `HERMIT_PREPARED_REDIS`,
  rejecting invalid declarations before starting either executable.
- Preserve interruption and exit requests through cleanup in the experimental
  private-runtime build and packaging tools.
- Align Hermit's package requirements and runtime source identities with the
  matching Reverie 0.5.3 snapshot.

[Selected source](https://github.com/rrnewton/hermit/commit/8d924a294e49a941b3a9c19e08e6bc86363d04ce).

## 0.5.2

- Fix `cargo install hermit-run` when dependency resolution selects libc
  0.2.190 or later.
- Restore `hermit-detcore` builds for wait and queued-signal handlers with
  libc's new `siginfo_t` layout.
- Restore `hermit-replay` builds for SIGPIPE delivery with that layout.
- Republish only `hermit-detcore` and `hermit-replay` at 0.5.2; `hermit-run`
  and the other crates remain at 0.5.0 and accept the compatibility update.
- Keep the locked 0.5.0 installation path usable with libc 0.2.189 and
  preserve the signal bytes presented to the guest.

[Release details](https://github.com/rrnewton/hermit/blob/v0.5.2/docs/releases/0.5.2.md).

## 0.5.1 (Development snapshot)

- Add `--cpu-profile=host-no-rdrand` for intercepted host CPU features with
  hardware randomness hidden. This requires ptrace, CPUID faulting and virtual
  time; results depend on the host CPU model and it is refused for record/replay.
- Add `--signal-at=turn=N:SIGNAL` to send a catchable signal to the run's root
  process after a committed scheduler turn. Supported on ptrace, including
  e9patch preprocessing; unsupported execution modes refuse the option.
- Add `--work-span-report=<path>` to report schedule work and critical-path
  estimates, with the unmodelled dependencies listed in the report.
- Add `--strict-schedule-boundaries` for recording and checking software slice
  boundaries during strict trace replay. Refuse legacy schedules in this mode,
  mismatches, incomplete replays and unrecorded branch fragments.
- Recognize random devices by device identity, including aliases of
  `/dev/random` and `/dev/urandom`, so deterministic reads also cover those
  spellings during record/replay.
- Include stat-family output hashes and decoded metadata fields in INFO I/O
  logs, allowing a metadata divergence to be located at the producing syscall.
- Resolve relative guest program paths before `hermit-verify` changes working
  directory, while preserving bare program names as guest `PATH` lookups.
- Name the CLI Cargo package `hermit-run`, retaining `hermit` as the installed
  executable and Rust library name.

[Selected source](https://github.com/rrnewton/hermit/commit/02a85cc45279b9dbbf83f4decf680bc425918f34).

## 0.5.0

- Ship ptrace as the default and include KVM in the registry package. Optional
  SaBRe support and e9patch preprocessing need external runtimes; e9patch
  executes through ptrace. DBT, LiteInst, in-guest-trap and native-exec remain
  outside the registry release.
- Support `FUTEX_REQUEUE`, `FUTEX_CMP_REQUEUE` and `FUTEX_WAKE_OP` in precise
  futex mode with sequentialized execution. Priority inheritance remains
  unsupported.
- Preserve temporary signal masks across interrupted blocking calls during
  record/replay, and restart interrupted initial mask probes instead of
  exposing a spurious `EINTR`.
- Select filtered procfs views with `--proc=minimal|standard`, defaulting to
  `minimal`. Omitted names return `ENOENT`; exposed files retain their
  individual modelling limits.
- Add experimental `--record-networking=<path>` and
  `--replay-networking=<path>` for outbound TCP recording and offline replay,
  checking sent bytes. UDP sends and listening-server operations are refused;
  remaining host namespace access can still make a recording diverge on replay.
- Extend experimental ptrace syscall recording/replay to `accept` and
  `accept4`, including peer-address output and copyout errors. Recording format
  `0x17e` is incompatible with 0.4.1 recordings.
- Save and load options with `--save-config` and `--config`. Run manifests
  retain resolved epoch/seed inputs; recording commands accept IDs, unique
  prefixes, paths, `last` and `last-run`.
- Capture verification executions separately with `--verify-run` and compare
  them with `hermit log-diff --verify-json`. Verification refuses known
  determinism losses and log-write failures; canonical observation comparison
  requires `--verify-strict`.
- Require an explicit epoch and reproducible seed inputs under `--strict`.
  Strict ptrace runs refuse invalid branch counters when their counts would
  affect execution.
- Add syscall/descriptor occurrence and completion anchors to happens-before
  constraints. Add `--scheduler-turn-cost`, `--futex-wake-yields` and
  `--pipe-wake-latency` for the supported scheduling modes.
- Debug live ptrace runs through `--dap-listen`, the `hermit-dap` adapter and
  GDB, with early refusals for unsupported launch combinations.
- Offer `--cpu-profile=x86-64-v3` on qualified ptrace hosts, retaining
  x86-64-v2 as the default. Record/replay binds and checks host XSAVE facts;
  the qualification does not cover every VM-exit or firmware effect.

[Release source](https://github.com/rrnewton/hermit/tree/v0.5.0).

## 0.4.1

- Fix stable Rust installation of `hermit-run`, including Ubuntu
  libunwind/LZMA linking and default-feature dependency selection.
- Refuse disabled SaBRe and e9patch paths before artifact resolution or
  recording setup, including before captured-stdin preparation. Explain when
  DBT requires a source build.
- Report explicitly when a source revision was not embedded in version output,
  while retaining the published package version.
- Adopt Reverie's adaptive waits, qualified for ptrace on Ubuntu 24.04's Linux
  6.8 kernel. Generic sibling-thread waits need Linux 6.9 thread pidfds;
  Linux 5.15 remains an unqualified design target.
- Document stable installation, scoped AppArmor setup and reuse of reported
  epoch/seed inputs. Precise preemption needs usable performance counters;
  nested KVM qualification remains deferred.

[Release source](https://github.com/rrnewton/hermit/tree/v0.4.1).

## 0.4.0

The earliest tagged baseline covered here targets x86_64 Linux.

- Publish the CLI as the `hermit-run` Cargo package, preserving the `hermit`
  executable and Rust library names, with matching versioned support crates.
- Include ptrace and KVM by default. SaBRe, LiteInst and e9patch preprocessing
  are opt-in and need runtime artifacts; DBT is outside the registry package.
  e9patch preprocessing uses ptrace.
- Provide configurable scheduling, virtual time and randomness. An omitted
  epoch is captured from the host; preserve the reported epoch and seed for
  repeat time-dependent output. Strict mode refuses incompatible opt-outs.
- Compare two runs with `--verify`, including syscall output-buffer hashes by
  default. Use `--verify-strict` for canonical observation comparison; the
  default comparison is diagnostic.
- Provide experimental syscall recording and GDB or autopilot replay, sharing
  run/container configuration and retaining the recording's network mode.
  A replay match does not establish determinism between independent recordings.

[Release source](https://github.com/rrnewton/hermit/tree/v0.4.0).
