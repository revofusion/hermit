/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#[path = "common/hermit_binary.rs"]
mod hermit_test;

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::sync::LazyLock;
use std::sync::Mutex;

const VERIFY_RUNS: usize = 3;
static RUN_LOCK: Mutex<()> = Mutex::new(());
static GUEST: LazyLock<PathBuf> = LazyLock::new(build_guest);

// GNU timeout owns the process group, including forked fixture children. The
// kill-after deadline bounds even a tracer/guest that cannot handle SIGTERM.
// This is a hang watchdog, never a performance or virtual-time assertion.
fn watchdog() -> Command {
    let mut command = Command::new("timeout");
    command.args(["--kill-after=5s", "60s"]);
    command
}

fn checked_output(mut command: Command, label: &str) -> Output {
    hermit_test::configure_guest_execution(&mut command);
    let rendered = format!("{command:?}");
    let output = hermit_test::hermit_output(&rendered, &mut command);
    assert!(
        output.status.success(),
        "{label} failed: {rendered}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    output
}

fn build_guest() -> PathBuf {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("hermit-cli is inside the repository");
    // Separate nextest processes cannot share a LazyLock or Mutex.
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("event-driven-io-{}", std::process::id()));
    fs::create_dir_all(&root).expect("create fixture build directory");
    let binary = root.join("event_driven_io");
    let mut command = watchdog();
    command
        .arg("cc")
        .args([
            "-O0",
            "-g",
            "-D_GNU_SOURCE",
            "-std=c11",
            "-pthread",
            "-Wall",
            "-Wextra",
            "-Werror",
        ])
        .arg(repository.join("tests/c/event_driven_io.c"))
        .arg("-o")
        .arg(&binary);
    checked_output(command, "event-driven I/O fixture compilation");
    binary
}

fn guest() -> &'static Path {
    GUEST.as_path()
}

fn hermit_command(scenario: &str, event_driven: bool) -> Command {
    let mut command = watchdog();
    command.arg(hermit_test::hermit_binary()).args([
        "--log=info",
        "--backend=ptrace",
        "run",
        "--strict",
        "--base-env=minimal",
    ]);
    if event_driven {
        command.arg("--event-driven-io");
    }
    if scenario == "timerfd-arm-rearm" {
        command.arg("--env=HERMIT_TEST_TIMER_DEADLINE=1");
    }
    if matches!(scenario, "socket-unrelated-producers" | "socket-rights-regular") {
        command.arg("--clock-multiplier=.001");
    } else if matches!(scenario, "socket-route-mutation-fallback"
        | "socket-rights-socket-fallback" | "socket-datagram-message-fallback"
        | "socket-datagram-discard-fallback") {
        command.arg("--clock-multiplier=.125");
    }
    if scenario == "pipe-shared-bindings" {
        // Cross-thread close/replacement need not wake native poll early.
        // Hermit's numeric-fd retry contract must complete before its deadline.
        command.arg("--env=HERMIT_TEST_BINDING_DEADLINE=1");
    }
    // Deliberately retain CPUID virtualization, PMU preemption, and signal
    // custody defaults. RUST_LOG is not narrowed to hide other INFO records.
    command
}

fn assert_canonical_verdict(path: &Path, scenario: &str) {
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(path).expect("strict verification did not publish its verdict"),
    )
    .expect("verification verdict is valid JSON");
    assert_eq!(report["verdict"], "matched", "{scenario}: {report}");
    assert_eq!(report["verified"], true, "{scenario}: {report}");
    assert_eq!(report["bitwise_parity"], true, "{scenario}: {report}");
    let policy = &report["comparison"];
    for (key, expected) in [
        ("strictness", "canonical"),
        ("display_name", "BitwiseInfoV1"),
        ("log_scope", "info"),
        ("record_envelope", "all_records_v1"),
    ] {
        assert_eq!(policy[key], expected, "{scenario}: {key}: {report}");
    }
    for key in [
        "compare_logs",
        "compare_io_buffers",
        "virtualize_time",
        "exact_remainder",
    ] {
        assert_eq!(policy[key], true, "{scenario}: {key}: {report}");
    }
    for key in ["strip_lines", "ignore_lines", "skip_commit", "skip_detlog"] {
        assert_eq!(policy[key], false, "{scenario}: {key}: {report}");
    }
    for side in ["left", "right"] {
        assert!(
            report["compared_log_messages"][side]
                .as_u64()
                .is_some_and(|count| count > 0),
            "{scenario}: no {side} INFO records compared: {report}",
        );
    }
    if matches!(scenario, "socket-unrelated-producers" | "socket-rights-regular") {
        // At this scenario's clock multiplier, polling through the initial
        // 200ms idle window would cost over 400,000 scheduler turns. Require
        // observable work avoidance in both complete runs, not only parity.
        for run in ["run1", "run2"] {
            let turns = report["runtime"][run]["scheduler_turns"]
                .as_u64()
                .unwrap_or_else(|| panic!("{scenario}: missing {run} scheduler turns: {report}"));
            assert!(
                turns < 10_000,
                "{scenario}: {run} did not preserve idle parking ({turns} turns): {report}",
            );
        }
    }
    if matches!(scenario, "socket-route-mutation-fallback"
        | "socket-rights-socket-fallback" | "socket-datagram-message-fallback"
        | "socket-datagram-discard-fallback")
    {
        // Revocation must keep the real consumer working, but must not retain
        // idle parking across an unproven producer/capability transition.
        for run in ["run1", "run2"] {
            let turns = report["runtime"][run]["scheduler_turns"]
                .as_u64().expect("missing scheduler turns");
            assert!(turns > 1_000, "{scenario}: {run} did not fail closed: {report}");
        }
    }
}

fn assert_scenario(scenario: &str) {
    assert_scenario_output(scenario, None);
}

fn assert_scenario_output(scenario: &str, expected: Option<&str>) {
    let _guard = RUN_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let binary = guest();
    let success = format!("{scenario} success\n");
    let mut native = watchdog();
    native.arg(binary).arg(scenario);
    if scenario == "pipe-shared-bindings" {
        native.env_remove("HERMIT_TEST_BINDING_DEADLINE");
    }
    let native = checked_output(native, &format!("native {scenario}"));
    assert!(native.stdout.ends_with(success.as_bytes()));
    if let Some(expected) = expected {
        assert_eq!(
            native.stdout,
            expected.as_bytes(),
            "{scenario}: unexpected native signal semantics",
        );
    }

    let mut enabled = hermit_command(scenario, true);
    enabled.arg("--").arg(binary).arg(scenario);
    let enabled = checked_output(enabled, &format!("enabled {scenario}"));
    assert_eq!(
        enabled.stdout, native.stdout,
        "{scenario}: enabled policy changed native results or coordinated ordering",
    );

    // Every invocation itself compares two complete runs, including their
    // unfiltered INFO envelope and I/O buffers. Independent invocations catch
    // accidental reliance on a previous run's fd identities or subscriptions.
    // A consumed periodic tick must not reappear even when parking is disabled.
    let repetitions = if scenario == "timerfd-copyout-faults" {
        VERIFY_RUNS * 2
    } else {
        VERIFY_RUNS
    };
    for run in 1..=repetitions {
        let event_driven = run <= VERIFY_RUNS;
        let verdict = binary
            .parent()
            .unwrap()
            .join(format!("{scenario}-{run}.json"));
        let mut command = hermit_command(scenario, event_driven);
        command
            .args(["--verify", "--verify-strict"])
            .arg(format!("--verify-json={}", verdict.display()))
            .arg("--")
            .arg(binary)
            .arg(scenario);
        let output = checked_output(
            command,
            &format!("{scenario} strict verification {run}/{repetitions}, event-driven={event_driven}"),
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(&success),
            "{scenario}: strict run omitted fixture success:\n{}",
            String::from_utf8_lossy(&output.stdout),
        );
        if let Some(expected) = expected {
            assert!(
                String::from_utf8_lossy(&output.stdout).contains(expected),
                "{scenario}: strict run omitted exact signal results:\n{}",
                String::from_utf8_lossy(&output.stdout),
            );
        }
        assert_canonical_verdict(&verdict, scenario);
    }
}

#[test]
fn eventfd_normal_dup_fork_consumer() {
    assert_scenario("eventfd-normal");
}

#[test]
fn eventfd_semaphore_dup_fork_consumer() {
    assert_scenario("eventfd-semaphore");
}

#[test]
fn eventfd_normal_blocked_producer() {
    assert_scenario("eventfd-producer");
}

#[test]
fn eventfd_semaphore_blocked_producer() {
    assert_scenario("eventfd-semaphore-producer");
}

#[test]
fn eventfd_multiple_waiters() {
    assert_scenario("eventfd-waiters");
}

#[test]
fn eventfd_consumer_after_shared_fd_thread_exit() {
    assert_scenario("eventfd-thread-exit");
}

#[test]
fn eventfd_and_pipe_alias_consumers_after_successful_exec() {
    assert_scenario("exec-surviving-aliases");
}

#[test]
fn eventfd_and_pipe_consumers_after_failed_exec() {
    assert_scenario("failed-exec-producer");
}

#[test]
fn pipe_data_before_exit_eof() {
    assert_scenario("pipe-exit");
}

#[test]
fn pipe_data_before_raw_last_thread_exit_eof() {
    assert_scenario("pipe-last-thread-exit");
}

#[test]
fn pipe_cloexec_eof_before_child_exit() {
    assert_scenario("pipe-cloexec");
}

#[test]
fn pipe_capacity_wakes_writer() {
    assert_scenario("pipe-capacity");
}

#[test]
fn pipe_forked_nonlast_closes_and_last_eof_epipe() {
    assert_scenario("pipe-close-lifetime");
}

#[test]
fn pipe_close_range_aliases_and_last_eof_epipe() {
    assert_scenario("pipe-close-range-lifetime");
}

#[test]
fn pipe_dup_replacement_aliases_and_last_eof_epipe() {
    assert_scenario("pipe-close-replace-lifetime");
}

#[test]
fn pipe_reopened_ownership_keeps_close_fallback() {
    assert_scenario("pipe-close-reopened-lifetime");
}

#[test]
fn pipe_missing_opposite_descriptor_keeps_close_fallback() {
    assert_scenario("pipe-close-no-witness");
}

#[test]
fn pipe_shared_table_bindings_wake_without_last_peer_close() {
    assert_scenario("pipe-shared-bindings");
}

#[test]
fn timerfd_arm_rearm_disarm_and_faulted_old_value_wake_aliases() {
    assert_scenario("timerfd-arm-rearm");
}

#[test]
fn timerfd_shared_readers_consume_each_expiration_once() {
    assert_scenario("timerfd-shared-drain");
}

#[test]
fn timerfd_epoll_interests_without_local_descriptors_keep_fallback() {
    assert_scenario("timerfd-foreign-epoll");
}

#[test]
fn timerfd_copyout_faults_preserve_the_actual_consumption_effect() {
    assert_scenario("timerfd-copyout-faults");
}

#[test]
fn timerfd_temporary_signal_masks_interrupt_and_restore() {
    assert_scenario("timerfd-masked-signal");
}

#[test]
fn finite_poll_deadline_uses_event_driven_wait() {
    assert_scenario("poll-timeout");
}

#[test]
fn masked_ppoll_signal_interruption_uses_legacy_fallback() {
    assert_scenario("masked-ppoll-signal-fallback");
}

#[test]
fn parked_poll_signal_interruption_then_readiness() {
    assert_scenario("poll-signal");
}

#[test]
fn parked_eventfd_read_signal_interruption_then_readiness() {
    assert_scenario("eventfd-read-signal");
}

#[test]
fn parked_eventfd_read_guest_sigchld_interrupts_without_data() {
    assert_scenario("eventfd-read-private-sigchld");
}

#[test]
fn parked_poll_guest_sigchld_interrupts_without_data() {
    assert_scenario("poll-private-sigchld");
}

#[test]
fn finite_poll_waits_for_child_completion_before_readiness() {
    assert_scenario("poll-child-gate");
}

#[test]
fn epoll_edge_oneshot_rearm_and_delete() {
    assert_scenario("epoll-rearm");
}

#[test]
fn nested_epoll_rearm_propagates() {
    assert_scenario("epoll-nested");
}

#[test]
fn parked_epoll_close_alias_and_fd_reuse() {
    assert_scenario("epoll-alias-reuse");
}

// These rows retain the native oracle and all three full strict comparisons.
// Positive wait rows also need registration/wake counter inspection: output
// parity alone cannot distinguish event-driven subscriptions from polling.
fn assert_signalfd_scenario(scenario: &str, detail: &str) {
    let expected = format!("{detail}\n{scenario} success\n");
    assert_scenario_output(scenario, Some(&expected));
}

#[test]
fn signalfd_process_shared_poll_consumes_then_resends() {
    assert_signalfd_scenario(
        "signalfd-poll-shared",
        "signalfd: process queue consumed and resent; exact sender records",
    );
}

#[test]
fn signalfd_thread_private_poll_preserves_sibling_queue() {
    assert_signalfd_scenario(
        "signalfd-poll-private",
        "signalfd: targeted thread wakes; sibling private signal stays private",
    );
}

#[test]
fn signalfd_and_anonymous_pipe_wake_same_epoll() {
    assert_signalfd_scenario(
        "signalfd-epoll-pipe",
        "signalfd: epoll signal then anonymous pipe; distinct tags and drained queues",
    );
}

#[test]
fn signalfd_pending_creation_overlap_and_dup_mask_replacement() {
    assert_signalfd_scenario(
        "signalfd-mask-alias",
        "signalfd: pending creation shares queue; dup mask replacement retargets existing watch",
    );
}

#[test]
fn signalfd_finite_poll_and_epoll_deadlines() {
    assert_signalfd_scenario(
        "signalfd-timeout",
        "signalfd: finite poll and epoll deadlines expire with empty queue",
    );
}

#[test]
fn signalfd_inherited_epoll_mod_retains_add_queue_fallback() {
    assert_signalfd_scenario(
        "signalfd-epoll-inherited",
        "signalfd: inherited epoll keeps parent wake queue; child record stays private",
    );
}

#[test]
fn signalfd_fresh_child_epoll_registration_wakes() {
    assert_signalfd_scenario(
        "signalfd-epoll-fresh-child",
        "signalfd: fresh child epoll ADD wakes on child queue",
    );
}

#[test]
fn signalfd_blocked_sigchld_uses_fallback_without_exit_rescue() {
    assert_signalfd_scenario(
        "signalfd-sigchld-fallback",
        "signalfd: private SIGCHLD fallback consumed and resent before sender exit",
    );
}

#[test]
fn socket_private_unix_data_and_eof_with_passive_tcp_listener() {
    assert_scenario("socket-unix-path");
}

#[test]
fn socket_abstract_unix_data_and_eof_with_passive_tcp_listener() {
    assert_scenario("socket-unix-abstract");
}

#[test]
fn socket_tcp_connect_revokes_passive_listener_parking() {
    assert_scenario("socket-tcp-revoke");
}

#[test]
fn socketpair_forked_alias_data_and_shutdown_before_exit() {
    assert_scenario("socketpair-alias");
}

#[test]
fn socket_pathname_connection_groups_preserve_forked_aliases_and_edge_eof() {
    assert_scenario("socket-connection-groups");
}

#[test]
fn socket_failed_accept_never_pairs_the_next_connection_with_a_dequeued_peer() {
    assert_scenario("socket-accept-error-groups");
}

#[test]
fn socket_unrelated_producers_preserve_unix_idle_parking() {
    assert_scenario("socket-unrelated-producers");
}

#[test]
fn socket_unknown_udp_option_keeps_unix_consumer_live_via_fallback() {
    assert_scenario("socket-udp-unknown-option");
}

#[test]
fn socket_mutating_route_request_keeps_unix_consumer_live_via_fallback() {
    assert_scenario("socket-route-mutation-fallback");
}

#[test]
fn socket_transferred_socket_keeps_unix_consumer_live_via_fallback() {
    assert_scenario("socket-rights-socket-fallback");
}

#[test]
fn socket_unix_datagram_message_keeps_stream_consumer_live_via_fallback() {
    assert_scenario("socket-datagram-message-fallback");
}

#[test]
fn socket_regular_stderr_and_pipe_rights_preserve_unix_idle_parking() {
    assert_scenario("socket-rights-regular");
}

#[test]
fn socket_unix_datagram_discarded_right_delivers_eof_after_revocation() {
    assert_scenario("socket-datagram-discard-fallback");
}
