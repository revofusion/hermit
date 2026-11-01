/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Default-ignored SIGCHLD must not park a parent until unrelated runnable work
// finishes. The yielding child stays runnable until the parent reaps another
// child and releases it. Its finite turn allowance makes starvation fail
// instead of leaving the deterministic test waiting forever.
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  struct sigaction action = {.sa_handler = SIG_DFL};
  sigemptyset(&action.sa_mask);
  sigset_t unblocked;
  sigemptyset(&unblocked);
  sigaddset(&unblocked, SIGCHLD);
  if (sigaction(SIGCHLD, &action, NULL) != 0 ||
      sigprocmask(SIG_UNBLOCK, &unblocked, NULL) != 0) {
    perror("SIGCHLD setup");
    return 1;
  }
  _Atomic int* done = mmap(NULL, sizeof(*done), PROT_READ | PROT_WRITE,
                          MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (done == MAP_FAILED) {
    perror("mmap");
    return 1;
  }
  atomic_init(done, 0);
  pid_t busy = fork();
  if (busy < 0) {
    perror("fork busy child");
    return 1;
  }
  if (busy == 0) {
    for (unsigned i = 0; i < 4096; ++i) {
      if (atomic_load(done))
        _exit(0);
      sched_yield();
    }
    _exit(99);
  }
  pid_t child = fork();
  if (child < 0) {
    perror("fork exiting child");
    atomic_store(done, 1);
    waitpid(busy, NULL, 0);
    return 1;
  }
  if (child == 0)
    _exit(17);
  int status;
  pid_t observed;
  do {
    observed = waitpid(child, &status, WNOHANG);
    if (observed == 0)
      sched_yield();
  } while (observed == 0);
  int reaped = observed == child && WIFEXITED(status) && WEXITSTATUS(status) == 17;
  atomic_store(done, 1);
  if (waitpid(busy, &status, 0) != busy || !WIFEXITED(status) || !reaped) {
    fputs("child reaping failed\n", stderr);
    return 1;
  }
  if (WEXITSTATUS(status) != 0) {
    fprintf(stderr, "parent starved behind runnable child: status=%d\n", WEXITSTATUS(status));
    return 1;
  }
  munmap(done, sizeof(*done));
  puts("parent progressed while another process remained runnable");
  return 0;
}
