/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void byte_write(int fd, char value) {
  ssize_t n;
  do { n = write(fd, &value, 1); } while (n < 0 && errno == EINTR);
  assert(n == 1);
}

static char byte_read(int fd) {
  char value;
  ssize_t n;
  do { n = read(fd, &value, 1); } while (n < 0 && errno == EINTR);
  assert(n == 1);
  return value;
}

static void wait_term(pid_t child) {
  int status;
  assert(waitpid(child, &status, 0) == child);
  assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
}

static void receive_user_signal(const sigset_t *mask, pid_t sender) {
  siginfo_t info;
  assert(sigwaitinfo(mask, &info) == SIGUSR1);
  assert(info.si_signo == SIGUSR1 && info.si_code == SI_USER);
  assert(info.si_pid == sender && info.si_uid == getuid());
}

static void other_group(const sigset_t *mask) {
  int ready[2], result[2], control[3][2];
  assert(pipe(ready) == 0 && pipe(result) == 0);
  for (int i = 0; i < 3; ++i) assert(pipe(control[i]) == 0);
  pid_t parent = getpid(), children[3];
  for (int i = 0; i < 3; ++i) {
    children[i] = fork();
    assert(children[i] >= 0);
    if (children[i] == 0) {
      close(ready[0]);
      close(result[0]);
      for (int j = 0; j < 3; ++j) {
        close(control[j][1]);
        if (j != i) close(control[j][0]);
      }
      assert(byte_read(control[i][0]) == 'r');
      byte_write(ready[1], (char)i);
      if (i == 2) {
        assert(byte_read(control[i][0]) == 'q');
        sigset_t pending;
        assert(sigpending(&pending) == 0);
        assert(sigismember(&pending, SIGUSR1) == 0);
        byte_write(result[1], (char)i);
        _exit(0);
      }
      receive_user_signal(mask, parent);
      byte_write(result[1], (char)i);
      for (;;) pause();
    }
    assert(setpgid(children[i], i == 1 ? children[0] : children[i]) == 0);
  }
  close(ready[1]);
  close(result[1]);
  for (int i = 0; i < 3; ++i) {
    close(control[i][0]);
    byte_write(control[i][1], 'r');
  }
  unsigned seen = 0;
  for (int i = 0; i < 3; ++i) seen |= 1U << byte_read(ready[0]);
  assert(seen == 7);
  assert(kill(-children[0], 0) == 0);
  assert(kill(-children[0], SIGUSR1) == 0);
  seen = 0;
  for (int i = 0; i < 2; ++i) seen |= 1U << byte_read(result[0]);
  assert(seen == 3);
  assert(kill(-children[0], SIGTERM) == 0);
  wait_term(children[0]);
  wait_term(children[1]);
  errno = 0;
  assert(kill(-children[0], SIGUSR1) == -1 && errno == ESRCH);
  byte_write(control[2][1], 'q');
  assert(byte_read(result[0]) == 2);
  int status;
  assert(waitpid(children[2], &status, 0) == children[2]);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  for (int i = 0; i < 3; ++i) close(control[i][1]);
  close(ready[0]);
  close(result[0]);
}

/* Deliver to every other member before the sender can die. A per-member
 * implementation that kills itself first strands its sibling here. */
static void self_fatal_group(void) {
  int ready[2], control[2][2];
  assert(pipe(ready) == 0);
  for (int i = 0; i < 2; ++i) assert(pipe(control[i]) == 0);
  pid_t children[2];
  for (int i = 0; i < 2; ++i) {
    children[i] = fork();
    assert(children[i] >= 0);
    if (children[i] == 0) {
      close(ready[0]);
      for (int j = 0; j < 2; ++j) {
        close(control[j][1]);
        if (j != i) close(control[j][0]);
      }
      assert(byte_read(control[i][0]) == 'r');
      byte_write(ready[1], (char)i);
      if (i == 0) {
        assert(byte_read(control[i][0]) == 't');
        assert(kill(0, SIGTERM) == 0);
      }
      for (;;) pause();
    }
    assert(setpgid(children[i], children[0]) == 0);
  }
  close(ready[1]);
  for (int i = 0; i < 2; ++i) {
    close(control[i][0]);
    byte_write(control[i][1], 'r');
  }
  unsigned seen = 0;
  for (int i = 0; i < 2; ++i) seen |= 1U << byte_read(ready[0]);
  assert(seen == 3);
  byte_write(control[0][1], 't');
  wait_term(children[0]);
  wait_term(children[1]);
  close(ready[0]);
  for (int i = 0; i < 2; ++i) close(control[i][1]);
}

static void *blocked_sibling(void *ready) {
  byte_write(*(int *)ready, 1);
  for (;;) pause();
  return NULL;
}

/* Every thread blocks SIGUSR1. Group delivery must queue one process-pending
 * signal per member, including a member with multiple blocked threads. */
static void blocked_group(const sigset_t *mask) {
  int ready[2], result[2], control[2][2];
  assert(pipe(ready) == 0 && pipe(result) == 0);
  for (int i = 0; i < 2; ++i) assert(pipe(control[i]) == 0);
  pid_t children[2];
  for (int i = 0; i < 2; ++i) {
    children[i] = fork();
    assert(children[i] >= 0);
    if (children[i] == 0) {
      close(ready[0]);
      close(result[0]);
      for (int j = 0; j < 2; ++j) {
        close(control[j][1]);
        if (j != i) close(control[j][0]);
      }
      assert(byte_read(control[i][0]) == 'r');
      if (i == 1) {
        pthread_t sibling;
        assert(pthread_create(&sibling, NULL, blocked_sibling, &ready[1]) == 0);
      } else {
        byte_write(ready[1], 0);
      }
      assert(byte_read(control[i][0]) == 'q');
      sigset_t pending;
      assert(sigpending(&pending) == 0);
      assert(sigismember(&pending, SIGUSR1) == 1);
      receive_user_signal(mask, getppid());
      assert(sigpending(&pending) == 0);
      assert(sigismember(&pending, SIGUSR1) == 0);
      byte_write(result[1], (char)i);
      _exit(0);
    }
    assert(setpgid(children[i], children[0]) == 0);
  }
  close(ready[1]);
  close(result[1]);
  for (int i = 0; i < 2; ++i) {
    close(control[i][0]);
    byte_write(control[i][1], 'r');
  }
  unsigned seen = 0;
  for (int i = 0; i < 2; ++i) seen |= 1U << byte_read(ready[0]);
  assert(seen == 3);
  assert(kill(-children[0], SIGUSR1) == 0);
  for (int i = 0; i < 2; ++i) byte_write(control[i][1], 'q');
  seen = 0;
  for (int i = 0; i < 2; ++i) seen |= 1U << byte_read(result[0]);
  assert(seen == 3);
  for (int i = 0; i < 2; ++i) {
    int status;
    assert(waitpid(children[i], &status, 0) == children[i]);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(control[i][1]);
  }
  close(ready[0]);
  close(result[0]);
  puts("process-group-delivery blocked=queued sender=ok consumed=once");
}

int main(int argc, char **argv) {
  sigset_t mask;
  assert(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGUSR1) == 0);
  assert(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
  if (argc == 2 && strcmp(argv[1], "blocked") == 0) {
    blocked_group(&mask);
    return 0;
  }
  assert(argc == 1);
  other_group(&mask);
  if (getpgrp() != getpid()) assert(setpgid(0, 0) == 0);
  assert(kill(0, SIGUSR1) == 0);
  receive_user_signal(&mask, getpid());
  errno = 0;
  assert(kill(0, INT_MAX) == -1 && errno == EINVAL);
  errno = 0;
  assert(kill(INT_MIN, SIGUSR1) == -1 && errno == ESRCH);
  self_fatal_group();
  puts("process-group-delivery fanout=ok sender=ok isolation=ok self=ok stale=ok self-termination=ok");
  return 0;
}
