# Hermit Users Guide

**Hermit is a a program sandbox for repeatability & concurrency testing.**

Hermit, by the Hermetic Infra Team, launches programs in a special sandbox to control their execution. Hermit translates normal, nondeterministic Linux behavior, into deterministic, repeatable behavior.  This can be used for various applications, including:

- record-replay debugging,
- simple reproducibility,
- "chaos mode" to expose concurrency bugs in a controlled and repeatable way.

Hermit is a middleware (or “sentry”) that sits between the guest process and the OS, accepting guest system call requests on one side, and producing sending system calls to the real Linux kernel on the other side.

Hermit currently supports x86_64 Linux and can be run via:

```
~/fbsource/fbcode/hermetic_infra/hermit/hermit
```

And here's a minimal demo of running inside hermit's deterministic environment:
```
$ cd ~/fbsource/fbcode/hermetic_infra/hermit/
$ ./examples/race.sh
bbbbbbaa (... nondeterministic output...)
$ ./hermit run --strict --epoch=2026-01-01T00:00:00Z ./examples/race.sh
abababab (... deterministic racing processes...)
```

Deterministic execution is the default: `./hermit run ./examples/race.sh`
runs the same way, taking its virtual-time epoch from the host clock and
reporting it so the run can be repeated. `--strict` also requires every input
of the run on the command line, so it needs `--epoch` (or `HERMIT_EPOCH`). See
[USER_GUIDE.md](USER_GUIDE.md) for the full set of mode-selection options.

To debug a run, add `--gdbserver` and attach gdb with
`gdb -ex 'target remote 127.0.0.1:1234' PROGRAM`. This works for a `--strict`
run too: its guest keeps the isolated network, and every strict refusal
applies. What the debugger does is an input of the run; see
[USER_GUIDE.md](USER_GUIDE.md) for what that changes.

Hermit preserves standard input, output and error at CLI entry and closes other
unsolicited file descriptors inherited from its caller. Pass guest inputs through
the documented file, mount and standard-stream options. An operating system that
cannot perform this descriptor cleanup is refused before a guest starts.

## Native hybrid CPUs and non-root identity

Intel Raptor Lake family 6, model `0xb7` is admitted only when the tracing
process starts with affinity to exactly one P-core logical CPU
(`CPUID.1A` core type `0x40`). Its profile uses conditional-branch event
`0x5111c4` and skid margin 125; normal performance-counter validation still
must pass. E-cores and multi-CPU affinity masks are refused rather than sharing
this profile across different PMUs. Pinning is not exclusive CPU reservation.

`--virtual-uid` and `--virtual-gid` select a fixed guest identity. With Hermit's
normal namespaces, the invoking user's real credentials are mapped to those
IDs so newly created files and `stat` agree with the guest's credential calls.
This does not grant host privileges. Without namespaces, kernel file ownership
is unchanged; selecting a different displayed identity does not make files
belong to it.

## System V shared memory

Native ptrace and KVM share the same run-local implementation of `shmget`,
`shmat`, `shmdt`, and `shmctl` (`IPC_STAT`, `IPC_SET`, and `IPC_RMID`). Segments
use real shared memfd bytes rather than the host's System V IPC namespace.
Identifiers, permissions, attachment counts, fork inheritance, exec/exit
detach, deferred removal, and shared-futex identity are maintained by Detcore.
The per-run limits are 4096 segments and 1 GiB of page-rounded backing.

Native ptrace requires serialized guest execution, an x86-64 Linux kernel with
`pidfd_getfd`, and permission to use it on the traced task. Non-leader threads
also require thread pidfds (`PIDFD_THREAD`, Linux 6.9 or later). Container
seccomp/LSM policies must allow ptrace, pidfds, and Unix socket descriptor
transfer. The backend uses temporary descriptors only during the stopped
guest's injected mapping operation, closes them before guest execution resumes,
and fails the run if an interrupted transport cannot safely finish cleanup.
No shared supervisor/guest IPC, PID, mount, or network namespace is needed.

Unsupported backends return `ENOSYS`. Huge pages, executable/remapping
attachments, `SHM_LOCK`/`SHM_UNLOCK`, and operations that split or replace an
attached mapping remain explicitly unsupported. Semaphores and message queues
are still unsupported. PostgreSQL can use its required tiny System V segment
while retaining `shared_memory_type=mmap` for its main shared memory.

## Process-group signals

Native sequentialized ptrace runs deliver `kill(0, sig)` and
`kill(-pgid, sig)` to modeled process-group members, never to a host process
group. Recipients are checked before delivery, ordered by guest PID, and the
sender runs last. Session/group changes, waitable zombies, sender identity,
and group SIGKILL retirement use the same process model as individual signals.
Ambiguous multithreaded recipients, broadcast `kill(-1, sig)`, nested-namespace
group sends, and non-sequentialized nonzero group sends remain refused.
KVM retains singleton-self group SIGKILL, not general group fanout.

## Qualified PostgreSQL example

`examples/postgres-native.sh` runs stock Debian PostgreSQL 17 inside Hermit:
startup, two concurrent committing clients, duplicate-server lock rejection,
fast clean shutdown, restart, and persisted-row checks. It copies a fixed seed
from `/var/lib/hermit-postgres/seed` into Hermit's private `/tmp`; initialize that
seed once with native `initdb`, before verification. Seed creation is an input
preparation step, not part of the determinism claim. The example removes only
its own temporary database. Server and clients both run inside Hermit.

The exercised configuration uses main and dynamic shared memory `mmap`,
8 MiB shared buffers, 10 connections, Unix sockets only, no parallel workers,
autovacuum, huge pages, or JIT. `fsync` remains enabled. This is a bounded
lifecycle qualification, not qualification of every PostgreSQL feature.

On Legion CT2002, run as `postgres`:

```sh
cd /var/lib/hermit-postgres
/usr/local/bin/hermit-postgres --log=info --backend=ptrace run \
  --strict --epoch=2026-01-01T00:00:00Z --verify --verify-strict \
  --base-env=minimal --virtual-uid=102 --virtual-gid=106 -- \
  /workspace/hermit-postgres-build/examples/postgres-native.sh
```

The qualified host is an i7-14650HX (model `0xb7`, microcode `0x132`),
kernel `7.0.14-8-pve`, with the container pinned to P-core logical CPU 3.
CPUID faulting and the exact branch-counter validator both passed. The
privileged lab container has no NIC or host bind mounts, inherited seccomp
is cleared for this container, and its outer AppArmor profile remains enforced.
Host `kernel.perf_event_paranoid=2` permits user-space counters. Normal Hermit
namespaces and counter validation stay enabled; no unsafe-ignore flag is used.
The lifecycle passed strict two-run comparison of 83,664 INFO records with
`BitwiseInfoV1 relaxations=none`. The SysV, non-root file-ownership, and
process-group delivery fixtures also passed strict repeat verification.
The separate ambiguous-recipient refusal test uses compatibility mode only to
observe `ENOSYS` and prove that no earlier recipient received a partial send.

This does not qualify AMD/KVM: the separate pv1 KVM regression attempt still
failed at `perf_event_open` with permission denied, even with timeslices
disabled. No additional pv1 host perf-policy change was made.

## PostgreSQL readiness in multi-service workloads

For scheduler-owned PostgreSQL socket waits, connect every client through the
server's Unix socket directory inside Hermit's private `/tmp`. Active native TCP
still falls back to polling: traced endpoints alone do not prove that every
queued packet or kernel timer is a scheduler-owned producer.

The lab harness cutover is recorded in `patches/fullstack-postgres-unix.patch`.
It changes the existing `fullstack-fix` configuration for SSP, routefinder and
all operators' primary and ephemeral databases to URLs such as:

```text
postgresql://dst@/sparkcore?host=/tmp/hermit-fullstack/pg/sock&port=25732
```

Apply it once from the directory containing the matching `fullstack-fix` harness
with `patch -p1 < /path/to/hermit/patches/fullstack-postgres-unix.patch`.
This is a transport change, not a reduction of leaves, signing, SQL operations,
durability settings or readiness deadlines. Native driver probes confirmed
Unix-socket selection for routefinder and operators; the installed SSP
SQLAlchemy/asyncpg dialect accepted the directory and port.

Producer-local UDP error queues/broadcast options, TCP receive-queue annotation,
and scalar Unix datagrams do not revoke unrelated owned Unix streams. Proven
read-only minimal route dumps also preserve authority. Passing physically
verified ordinary log-file descriptors over a guest-held Unix stream socketpair
does not export a socket capability; the affected descriptors still follow
their existing per-file and flock custody accounting.

Proven Unix stream pairs have a shared connection-local mutation generation.
A read, write, shutdown or close wakes that connection's observers rather than
every unrelated Unix stream. The scheduler owns the mapping by stable
open-file-description identity; aliases and native lifecycle notifications
retain it after descriptor-number reuse or peer-handle destruction.

Domain authority remains a separate dependency: revocation still wakes all
affected connections. Listeners and unpaired endpoints retain conservative
mutation dependencies. A connection is promoted only when the existing
connect/accept custody model proves its peer; ambiguous order, failed dequeue,
dead pending peers, counter exhaustion or post-accept metadata errors prevent
promotion. RPC revision 24 distinguishes this dependency protocol from older
recordings and binaries.

UDP and Unix datagram descriptors remain unowned. Datagram message APIs,
transferred sockets, unknown options, mutating route requests, external
producers and unsupported epoll sources retain fallback. In particular, a
scalar datagram read can discard a queued descriptor and deliver stream EOF;
authority is already revoked before the preceding ancillary send. A Unix
connection therefore improves coverage but does not guarantee that every
PostgreSQL wait can park. Compare polling counts and host-wall intervals
separately from virtual time; preserve strict repeated-result verification.

### Bootstrap initialization and policy epochs

`patches/fullstack-persistent-bootstrap.patch` removes repeated application
imports from the matching lab harness. Apply it from the directory containing
`fullstack-fix` with
`patch -p1 < /path/to/hermit/patches/fullstack-persistent-bootstrap.patch`.

The controller starts one SSP application process inside Hermit. Existing
bootstrap commands become clients of a private, mode-0600 Unix socket.
Commands are serialized and retain their original application contexts,
database commits and session teardown. Balances and readiness are still queried
from the real services; no query results are cached. The controller retains its
service-health checks, per-command deadlines and error handling, including the
initial import in the first command's deadline. Application diagnostics remain
in `ssp_bootstrap.log`; command results and failures retain individual logs.

Use a fixed epoch compatible with the application's dated policies, not merely
one that makes repeated traces match. The evaluated Spark snapshot rejects
tree-node IDs predating 2026-03-17 when selecting liquidity, although its raw
available-leaf count includes those nodes. An epoch of 2026-01-01 can therefore
produce 1,024 available leaves but no selectable payment liquidity.
The lab's corrected epoch is `2026-11-01T00:00:00Z`; generated certificate
validity must also agree with it. Keep that epoch identical across repeats.
Neither a leaf count nor a bootstrap-only repeat qualifies settlement: require
the original bidirectional payment assertions as well.

## Scheduler-owned file locks

`hermit run --event-driven-io` supports blocking `flock` on native ptrace for
regular files in Hermit's launch-authenticated private `/tmp` mount. The
supported filesystems are tmpfs, ext, btrfs, XFS and ZFS. A path prefix is not
authority: shared binds, imported mounts and unproved external owners do not
qualify.

The kernel decides every lock grant. On contention Hermit retains the entry
open-file description and parks the caller on a per-file scheduler dependency.
Closing or reusing the original fd number cannot redirect the blocked call.
Unlock, conversion, last-reference close, process exit and `SCM_RIGHTS` transfers
over proven traced Unix stream channels permit deterministic re-probes. Shared
locks, non-atomic conversions, signal interruption and `SA_RESTART` keep their
Linux semantics. Unknown exports withdraw authority rather than silently
enabling host-dependent waiting. Retired file domains do not survive native
inode reuse, so host inode allocation cannot select an old logical lock key.
If rights bookkeeping loses custody (including queue overflow, out-of-band
delivery, an unmatched receipt or unobserved backend teardown), Hermit also
withdraws authority and wakes existing lock waiters into refusal. It does not
treat a lost model reference as proof that Linux released the OFD.

Fdinfo opened for a managed lock uses a structured view of the actual lock state
and its recorded owner. Native process-lock and lease attribution remains
unsupported in that view and is refused rather than fabricated. Legacy fdinfo
behavior for other descriptors is unchanged.

This policy does not relax PMU preemption, CPUID handling, signals, strict
verification or the external-filesystem boundary. Without this policy, or
outside its proven file domain, contended blocking locks retain the existing
refusal behavior; `LOCK_NB` remains kernel-authoritative.

## Building the fork

Check out the source and its pinned Reverie fork together on x86-64 Linux:

```sh
git clone --recurse-submodules --branch postgres-sysv-shm https://github.com/revofusion/hermit.git
cd hermit
cargo build --locked --profile validate -p hermit-run --bin hermit
```

The historical `patches/postgres-native-hermit.patch` and
`patches/postgres-native-reverie.patch` target the older
`acb5d5f37c9e27b4d8aca95324f9284ed0be3876` and
`2f5eea30da16e3eec145fba33063de24a6dc3c69` bases, respectively.
They are not the installation path for this fork; do not apply them on top of it.


## Further reading

* Find hermit [CLI examples here](https://fb.workplace.com/notes/hermetic-infra-fyi/hermit-tech-preview-a-linux-reproducibility-tool/244656753248444/)
* See demos in [this tech talk](https://fb.workplace.com/groups/591973351138875/permalink/1132872253715646/).
* [This talk](https://fb.workplace.com/groups/591973351138875/posts/1533285603674307) shows concurrency testing with hermit "chaos" mode.
* [This talk](https://fb.workplace.com/groups/hermit.fyi/post
