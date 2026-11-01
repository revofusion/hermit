#[path = "common/hermit_binary.rs"]
mod hermit_test;

use std::path::Path;
use std::process::Command;

#[test]
fn non_root_guest_identity_is_consistent_and_cannot_become_root() {
    guest_identity("ptrace");
}

#[test]
fn kvm_non_root_guest_identity_matches_file_ownership() {
    if !Path::new("/dev/kvm").exists() {
        eprintln!("skipping KVM identity: /dev/kvm is unavailable");
        return;
    }
    guest_identity("kvm");
}

fn guest_identity(backend: &str) {
    let scratch = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("create guest build directory outside isolated /tmp");
    let guest = scratch.path().join("fixed_guest_identity");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tests/c/fixed_guest_identity.c");
    let compile = Command::new("cc")
        .args(["-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(&guest)
        .output()
        .expect("compile identity guest");
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    let mut command = Command::new("timeout");
    command
        .args(["--kill-after=2s", "60s"])
        .arg(hermit_test::hermit_binary())
        .arg("--log=info")
        .args([
            "--backend",
            backend,
            "run",
            "--strict",
            "--verify",
            "--verify-strict",
            "--virtual-uid=1234",
            "--virtual-gid=5678",
            "--epoch=2026-01-01T00:00:00Z",
        ]);
    if backend == "kvm" {
        command.arg("--max-timeslice=disabled");
    }
    command.arg("--").arg(&guest);
    hermit_test::configure_guest_execution(&mut command);
    let output = hermit_test::hermit_output("fixed guest identity", &mut command);
    assert!(
        output.status.success(),
        "guest failed: {}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "fixed-guest-identity-ok"
    );
}
