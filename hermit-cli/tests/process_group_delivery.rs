/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#[path = "common/hermit_binary.rs"]
mod hermit_test;

use std::path::Path;
use std::process::Command;

#[test]
fn native_process_groups_preserve_delivery_scope_and_sender_identity() {
    group_fixture(false);
}

#[test]
fn native_blocked_multithreaded_groups_receive_process_pending_signals() {
    group_fixture(true);
}

fn group_fixture(blocked: bool) {
    let scratch = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("create group fixture directory outside isolated /tmp");
    let guest = scratch.path().join("process_group_delivery");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tests/c/process_group_delivery.c");
    let compile = Command::new("cc")
        .args(["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread"])
        .arg(source)
        .arg("-o")
        .arg(&guest)
        .output()
        .expect("compile process-group fixture");
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let mut native = Command::new("timeout");
    native.args(["--kill-after=5s", "60s"]).arg(&guest);
    if blocked {
        native.arg("blocked");
    }
    let native = native.output().expect("run native process-group fixture");
    assert!(
        native.status.success(),
        "native group fixture failed: {}\n{}",
        native.status,
        String::from_utf8_lossy(&native.stderr),
    );

    let mut command = Command::new("timeout");
    command
        .args(["--kill-after=5s", "60s"])
        .arg(hermit_test::hermit_binary())
        .args([
            "--log=info",
            "--backend=ptrace",
            "run",
            "--strict",
            "--verify",
            "--verify-strict",
            "--base-env=minimal",
            "--virtual-uid=1000",
            "--virtual-gid=1000",
            "--epoch=2026-01-01T00:00:00Z",
        ]);
    command.arg("--").arg(&guest);
    if blocked {
        command.arg("blocked");
    }
    hermit_test::configure_guest_execution(&mut command);
    let output = hermit_test::hermit_output("native process-group delivery", &mut command);
    assert!(
        output.status.success(),
        "group fixture failed: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(output.stdout, native.stdout);
}
