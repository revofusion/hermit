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
use std::process::Command;
use std::process::Output;

fn command_output(mut command: Command, label: &str) -> Output {
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

#[test]
fn sysv_and_legacy_filesystem_features_fall_back_deterministically() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("hermit-cli should be inside the repository");
    let build_root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("sysv-legacy-fallbacks-{}", std::process::id()));
    fs::create_dir_all(&build_root).expect("failed to create guest build directory");

    let cases = [
        ("sysv_sem", repository.join("tests/c/sysv_sem_enosys.c")),
        ("ustat", repository.join("tests/c/ustat_enosys.c")),
    ];

    for (syscall, source) in cases {
        let guest = build_root.join(format!("{syscall}_enosys"));
        let mut compile = Command::new("cc");
        compile
            .args(["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg(source)
            .arg("-o")
            .arg(&guest);
        command_output(compile, &format!("{syscall} guest compilation"));

        let mut verify = Command::new("timeout");
        verify
            .args(["--kill-after", "5s", "90s"])
            .arg(env!("CARGO_BIN_EXE_hermit"))
            .args([
                "--log=info",
                "--backend=ptrace",
                "run",
                "--strict",
                "--verify",
                "--panic-on-unsupported-syscalls",
                "--base-env=minimal",
                "--",
            ])
            .arg(&guest);
        let output = command_output(verify, &format!("{syscall} strict verification"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stdout.contains("Determinism verified") || stderr.contains("Determinism verified"),
            "{syscall} omitted Hermit's determinism marker\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}

#[test]
fn kvm_sysv_shared_memory_has_real_bytes_and_mm_lifecycle() {
    if !Path::new("/dev/kvm").exists() {
        eprintln!("skipping KVM SysV shared memory: /dev/kvm is unavailable");
        return;
    }
    shared_memory_lifecycle("kvm");
}

#[test]
fn ptrace_sysv_shared_memory_has_real_bytes_and_mm_lifecycle() {
    shared_memory_lifecycle("ptrace");
}

fn shared_memory_lifecycle(backend: &str) {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let directory = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{backend}-sysv-shm-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let guest = directory.join("sysv_shm");
    let mut compile = Command::new("cc");
    compile
        .args(["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(repository.join("tests/c/sysv_shm.c"))
        .arg("-o")
        .arg(&guest);
    command_output(compile, "SysV shared-memory guest compilation");
    for uid in [0, 1000] {
        let mut run = Command::new("timeout");
        run.args(["--kill-after", "5s", "120s"])
            .arg(env!("CARGO_BIN_EXE_hermit"))
            .arg("--log=info")
            .arg(format!("--backend={backend}"))
            .args(["run", "--strict", "--verify", "--base-env=minimal"]);
        if backend == "kvm" {
            run.args(["--verify-strict", "--max-timeslice=disabled"]);
        }
        run.arg(format!("--virtual-uid={uid}"))
            .arg(format!("--virtual-gid={uid}"))
            .arg("--")
            .arg(&guest);
        let output = command_output(run, &format!("{backend} SysV shared-memory lifecycle"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stdout.contains(
                "sysv-shm shared=fork aliases=ok stat=ok rmid=ok exec=ok exit=ok errors=ok"
            ),
            "missing behavioral contract: {stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("Determinism verified") || stderr.contains("Determinism verified"),
            "missing verification marker: {stdout}\n{stderr}"
        );
        if backend == "kvm" {
            assert!(
                stderr.contains("hermit::kvm: launching guest through reverie-kvm"),
                "test did not exercise KVM: {stderr}"
            );
        }
    }
}
