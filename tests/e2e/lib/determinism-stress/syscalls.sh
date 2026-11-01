#!/usr/bin/env bash

set -euo pipefail
# shellcheck source=common.sh source-path=SCRIPTDIR
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

cases=(
  'quick-wins|tests/c/syscall_quick_wins.c|'
  'file-io|tests/c/syscall_file_io.c|'
  'file-metadata|tests/c/syscall_file_metadata.c|'
  'writev|tests/c/writev_determinism.c|'
  'epoll-multi|tests/c/epoll_determinism.c|multi'
  'epoll-edge|tests/c/epoll_determinism.c|edge'
  'epoll-oneshot|tests/c/epoll_determinism.c|oneshot'
  'epoll-mixed|tests/c/epoll_determinism.c|mixed'
  'epoll-nested|tests/c/epoll_determinism.c|nested'
  'epoll-control-fds|tests/c/epoll_determinism.c|control-fds'
  'epoll-dupfd|tests/c/epoll_determinism.c|dupfd'
  'epoll-tcp-exit|tests/c/epoll_determinism.c|tcp-exit'
  'epoll-tcp-exit-alias|tests/c/epoll_determinism.c|tcp-exit-alias'
  'sigchld-progress|tests/c/sigchld_progress.c|'
  'sigkill-group-progress|tests/c/sigkill_cross_process.c|parentgroup'
  'connect-source-port|tests/c/connect_source_port.c|'
  'connect-source-port-recycle|tests/c/connect_source_port.c|recycle'
  'process-signal-unique|tests/c/process_signal_reservation.c|unique'
  'process-signal-leader|tests/c/process_signal_reservation.c|leader'
  'process-signal-restart|tests/c/process_signal_reservation.c|restart'
  'process-signal-adversary|tests/c/process_signal_reservation.c|adversary'
  'mmap-multiple|tests/c/mmap_determinism.c|multiple'
  'mmap-fixed|tests/c/mmap_determinism.c|fixed'
  'mmap-heap|tests/c/mmap_determinism.c|heap'
  'mmap-shared|tests/c/mmap_determinism.c|shared'
  'mmap-reuse|tests/c/mmap_determinism.c|reuse'
  'resources|tests/c/resource_determinism.c|'
  'ipc-pipe-order|tests/c/ipc_determinism.c|pipe-order'
  'ipc-pipe-capacity|tests/c/ipc_determinism.c|pipe-capacity'
  'ipc-socketpair|tests/c/ipc_determinism.c|socketpair'
  'ipc-eventfd|tests/c/ipc_determinism.c|eventfd'
  'ipc-epoll|tests/c/ipc_determinism.c|epoll'
  'arch-prctl|tests/c/arch_prctl_determinism.c|'
  'getitimer|tests/c/getitimer_determinism_probe.c|'
  'setitimer|tests/c/setitimer_determinism.c|'
  'posix-timer|tests/c/timer_create_determinism.c|'
)

failures=0
for entry in "${cases[@]}"; do
  IFS='|' read -r name source_file arguments <<<"$entry"
  read -r -a guest_args <<<"$arguments"
  compile_flags=(-lrt)
  if [[ $source_file == tests/c/epoll_determinism.c ||
        $source_file == tests/c/ipc_determinism.c ||
        $source_file == tests/c/resource_determinism.c ]]; then
    compile_flags+=(-D_GNU_SOURCE)
  fi
  if [[ $source_file == tests/c/epoll_determinism.c ||
        $source_file == tests/c/sigkill_cross_process.c ]]; then
    compile_flags+=(-pthread)
  fi
  guest=$(compile_c "$source_file" "syscall-$name" "${compile_flags[@]}")
  if ! verify_guest "syscall target: $name" "$guest" "${guest_args[@]}"; then
    failures=$((failures + 1))
  fi
done

((failures == 0)) || fail "$failures syscall target(s) failed verification"
stress_success "targeted syscall matrix"
