/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* All files are created by the workload inside its private /tmp. The host
 * harness supplies the only timeout; no sleep orders an ownership assertion. */
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s (errno=%d)\n", __FILE__, __LINE__,               \
              #condition, errno);                                              \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static void put(int fd, char byte) { CHECK(write(fd, &byte, 1) == 1); }
static void get(int fd, char expected) {
  char byte = 0;
  CHECK(read(fd, &byte, 1) == 1);
  CHECK(byte == expected);
}
static void joined(pid_t child) {
  int status;
  pid_t result;
  do {
    result = waitpid(child, &status, 0);
  } while (result < 0 && errno == EINTR);
  CHECK(result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static void excluded(int fd, int operation) {
  errno = 0;
  CHECK(flock(fd, operation | LOCK_NB) == -1);
  CHECK(errno == EWOULDBLOCK);
}
static void acquired(int fd, int operation) {
  CHECK(flock(fd, operation | LOCK_NB) == 0);
}

struct file {
  char path[64];
  int owner;
  int waiter;
  int probe;
};
static struct file make_file(void) {
  struct file file = {.path = "/tmp/hermit-flock-wait-XXXXXX"};
  file.owner = mkstemp(file.path);
  CHECK(file.owner >= 0);
  file.waiter = open(file.path, O_RDWR);
  file.probe = open(file.path, O_RDWR);
  CHECK(file.waiter >= 0 && file.probe >= 0);
  return file;
}
static void remove_file(struct file *file) {
  if (file->owner >= 0) CHECK(close(file->owner) == 0);
  if (file->waiter >= 0) CHECK(close(file->waiter) == 0);
  CHECK(close(file->probe) == 0);
  CHECK(unlink(file->path) == 0);
}

struct waiter {
  int fd;
  int operation;
  int release_fd;
  int ready[2];
  int done[2];
  int release[2];
  int result;
  int error;
  pthread_t thread;
};
static void *wait_for_lock(void *argument) {
  struct waiter *waiter = argument;
  put(waiter->ready[1], 'r');
  errno = 0;
  waiter->result = flock(waiter->fd, waiter->operation);
  waiter->error = errno;
  put(waiter->done[1], 'd');
  get(waiter->release[0], 'q');
  if (waiter->result == 0 && waiter->release_fd >= 0) {
    CHECK(flock(waiter->release_fd, LOCK_UN) == 0);
  }
  return NULL;
}
static void start_waiter(struct waiter *waiter, int fd, int operation, int release_fd) {
  waiter->fd = fd;
  waiter->operation = operation;
  waiter->release_fd = release_fd;
  CHECK(pipe(waiter->ready) == 0);
  CHECK(pipe(waiter->done) == 0);
  CHECK(pipe(waiter->release) == 0);
  CHECK(pthread_create(&waiter->thread, NULL, wait_for_lock, waiter) == 0);
  get(waiter->ready[0], 'r');
}
static void not_finished(struct waiter *waiter) {
  struct pollfd fd = {.fd = waiter->done[0], .events = POLLIN};
  CHECK(poll(&fd, 1, 0) == 0);
}
static void finish_waiter(struct waiter *waiter, int result, int error) {
  put(waiter->release[1], 'q');
  CHECK(pthread_join(waiter->thread, NULL) == 0);
  CHECK(waiter->result == result);
  if (result < 0) CHECK(waiter->error == error);
  CHECK(close(waiter->ready[0]) == 0);
  CHECK(close(waiter->ready[1]) == 0);
  CHECK(close(waiter->done[0]) == 0);
  CHECK(close(waiter->done[1]) == 0);
  CHECK(close(waiter->release[0]) == 0);
  CHECK(close(waiter->release[1]) == 0);
}

/* A pipe announcing "about to flock" is NOT proof of syscall entry: another
 * thread could close/reuse the fd or send a signal before flock begins. Linux
 * drops the old SH lock before a blocking conversion. Observe that real kernel
 * side effect through fdinfo before performing those operations. This loop is
 * only a fixture entry barrier, not a simulated lock or a runtime wake source.
 * The owner keeps its SH lock throughout, so the conversion cannot finish.
 * Both native Linux and the deterministic implementation must expose it. */
static int has_lock(int fd) {
  char path[64], contents[4096];
  CHECK(snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd) > 0);
  int info = open(path, O_RDONLY);
  CHECK(info >= 0);
  ssize_t length = read(info, contents, sizeof(contents) - 1);
  CHECK(length >= 0 && length < (ssize_t)sizeof(contents) - 1);
  contents[length] = '\0';
  CHECK(close(info) == 0);
  return strstr(contents, "lock:") != NULL;
}
static void start_conversion(struct file *file, struct waiter *waiter, int release_fd) {
  acquired(file->owner, LOCK_SH);
  acquired(file->waiter, LOCK_SH);
  CHECK(has_lock(file->waiter));
  start_waiter(waiter, file->waiter, LOCK_EX, release_fd);
  unsigned observations = 0;
  while (has_lock(file->waiter)) {
    CHECK(++observations < 100000);
    CHECK(sched_yield() == 0);
  }
  not_finished(waiter);
  excluded(file->probe, LOCK_EX);
}
static void observe_exclusive(struct file *file, struct waiter *waiter) {
  get(waiter->done[0], 'd');
  excluded(file->probe, LOCK_SH);
  excluded(file->probe, LOCK_EX);
}

static void handoff(void) {
  struct file file = make_file();
  struct waiter waiter;
  acquired(file.owner, LOCK_EX);
  excluded(file.waiter, LOCK_EX);
  start_waiter(&waiter, file.waiter, LOCK_EX, file.waiter);
  not_finished(&waiter);
  excluded(file.probe, LOCK_SH);
  CHECK(flock(file.owner, LOCK_UN) == 0);
  observe_exclusive(&file, &waiter);
  finish_waiter(&waiter, 0, 0);
  acquired(file.probe, LOCK_EX);
  CHECK(flock(file.probe, LOCK_UN) == 0);
  remove_file(&file);
}

static void shared_waiters(int downgrade) {
  struct file file = make_file();
  int second = open(file.path, O_RDWR);
  CHECK(second >= 0);
  acquired(file.owner, LOCK_EX);
  excluded(file.waiter, LOCK_SH);
  excluded(second, LOCK_SH);
  struct waiter first, other;
  start_waiter(&first, file.waiter, LOCK_SH, file.waiter);
  start_waiter(&other, second, LOCK_SH, second);
  not_finished(&first);
  not_finished(&other);
  CHECK(flock(file.owner, downgrade ? LOCK_SH : LOCK_UN) == 0);
  get(first.done[0], 'd');
  get(other.done[0], 'd');
  /* Both independent OFDs hold SH simultaneously; neither waiter needs the
   * other to release. No fairness order is asserted. */
  acquired(file.probe, LOCK_SH);
  CHECK(flock(file.probe, LOCK_UN) == 0);
  excluded(file.probe, LOCK_EX);
  finish_waiter(&first, 0, 0);
  excluded(file.probe, LOCK_EX);
  finish_waiter(&other, 0, 0);
  if (downgrade) {
    excluded(file.probe, LOCK_EX);
    CHECK(flock(file.owner, LOCK_UN) == 0);
  }
  acquired(file.probe, LOCK_EX);
  CHECK(flock(file.probe, LOCK_UN) == 0);
  CHECK(close(second) == 0);
  remove_file(&file);
}

static void last_close(void) {
  struct file file = make_file();
  int alias = dup(file.owner);
  CHECK(alias >= 0);
  struct waiter waiter;
  start_conversion(&file, &waiter, file.waiter);
  CHECK(close(file.owner) == 0);
  file.owner = -1;
  not_finished(&waiter);
  excluded(file.probe, LOCK_EX);
  CHECK(close(alias) == 0);
  observe_exclusive(&file, &waiter);
  finish_waiter(&waiter, 0, 0);
  remove_file(&file);
}

static void fork_release(int exit_release) {
  struct file file = make_file();
  int alias = dup(file.owner);
  CHECK(alias >= 0);
  acquired(file.owner, LOCK_SH);
  int gate[2], ready[2];
  CHECK(pipe(gate) == 0 && pipe(ready) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(file.owner) == 0);
    CHECK(close(file.waiter) == 0);
    CHECK(close(file.probe) == 0);
    put(ready[1], 'r');
    get(gate[0], 'q');
    if (!exit_release) {
      CHECK(close(alias) == 0);
      /* Stay alive until the waiter has consumed the wakeup, so process exit
       * cannot rescue a missing last-close notification. */
      get(gate[0], 'a');
    }
    _exit(0);
  }
  get(ready[0], 'r');
  struct waiter waiter;
  start_conversion(&file, &waiter, file.waiter);
  CHECK(close(file.owner) == 0 && close(alias) == 0);
  file.owner = -1;
  not_finished(&waiter);
  excluded(file.probe, LOCK_EX);
  put(gate[1], 'q');
  observe_exclusive(&file, &waiter);
  if (!exit_release) put(gate[1], 'a');
  finish_waiter(&waiter, 0, 0);
  joined(child);
  CHECK(close(gate[0]) == 0 && close(gate[1]) == 0);
  CHECK(close(ready[0]) == 0 && close(ready[1]) == 0);
  remove_file(&file);
}

static void reuse(int keep_alias) {
  struct file file = make_file();
  struct file replacement = make_file();
  int alias = keep_alias ? dup(file.waiter) : -1;
  if (keep_alias) CHECK(alias >= 0);
  acquired(replacement.owner, LOCK_EX);
  struct waiter waiter;
  start_conversion(&file, &waiter, alias);
  int number = file.waiter;
  CHECK(close(number) == 0);
  CHECK(dup2(replacement.waiter, number) == number);
  excluded(number, LOCK_SH);
  not_finished(&waiter);
  /* The replacement remains exclusively locked for the entire old syscall.
   * Retargeting by fd number either hangs or returns the wrong result. */
  CHECK(flock(file.owner, LOCK_UN) == 0);
  get(waiter.done[0], 'd');
  if (keep_alias) {
    excluded(file.probe, LOCK_SH);
  } else {
    /* The in-flight syscall was the last reference. Its completed grant must
     * not leave a tracer-owned pin holding the old lock indefinitely. */
    acquired(file.probe, LOCK_EX);
    CHECK(flock(file.probe, LOCK_UN) == 0);
  }
  excluded(number, LOCK_SH);
  finish_waiter(&waiter, 0, 0);
  if (keep_alias) CHECK(close(alias) == 0);
  CHECK(flock(replacement.owner, LOCK_UN) == 0);
  acquired(number, LOCK_EX);
  excluded(replacement.probe, LOCK_SH);
  CHECK(flock(number, LOCK_UN) == 0);
  remove_file(&file);
  remove_file(&replacement);
}

static void conversions(void) {
  struct file file = make_file();
  acquired(file.owner, LOCK_SH);
  acquired(file.waiter, LOCK_SH);
  /* A failed nonblocking conversion also drops its old SH lock on Linux. */
  excluded(file.waiter, LOCK_EX);
  CHECK(!has_lock(file.waiter));
  acquired(file.owner, LOCK_EX);
  excluded(file.probe, LOCK_SH);
  CHECK(flock(file.owner, LOCK_SH) == 0);
  acquired(file.waiter, LOCK_SH);
  excluded(file.probe, LOCK_EX);
  CHECK(flock(file.owner, LOCK_UN) == 0);
  CHECK(flock(file.waiter, LOCK_EX) == 0);
  excluded(file.probe, LOCK_SH);
  CHECK(flock(file.waiter, LOCK_UN) == 0);
  remove_file(&file);
}

static int signal_pipe;
static volatile sig_atomic_t signal_count;
static void caught_signal(int signo) {
  int saved = errno;
  if (signo != SIGUSR1 || write(signal_pipe, "s", 1) != 1) _exit(1);
  ++signal_count;
  errno = saved;
}
static void signal_wait(int restart) {
  struct file file = make_file();
  int seen[2];
  CHECK(pipe(seen) == 0);
  signal_pipe = seen[1];
  struct sigaction action = {.sa_handler = caught_signal};
  action.sa_flags = restart ? SA_RESTART : 0;
  CHECK(sigemptyset(&action.sa_mask) == 0);
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  sigset_t mask;
  CHECK(sigemptyset(&mask) == 0 && sigaddset(&mask, SIGUSR1) == 0);
  CHECK(pthread_sigmask(SIG_UNBLOCK, &mask, NULL) == 0);
  struct waiter waiter;
  start_conversion(&file, &waiter, file.waiter);
  CHECK(pthread_kill(waiter.thread, SIGUSR1) == 0);
  get(seen[0], 's');
  if (restart) {
    not_finished(&waiter);
    excluded(file.probe, LOCK_EX);
    CHECK(flock(file.owner, LOCK_UN) == 0);
    observe_exclusive(&file, &waiter);
    finish_waiter(&waiter, 0, 0);
  } else {
    get(waiter.done[0], 'd');
    finish_waiter(&waiter, -1, EINTR);
    /* Interrupted conversion must not restore the pre-entry SH lock. */
    CHECK(!has_lock(file.waiter));
    CHECK(flock(file.owner, LOCK_UN) == 0);
    acquired(file.probe, LOCK_EX);
    CHECK(flock(file.probe, LOCK_UN) == 0);
  }
  CHECK(signal_count == 1);
  CHECK(close(seen[0]) == 0 && close(seen[1]) == 0);
  remove_file(&file);
}

static void rights_alias(int mode) {
  struct file file = make_file();
  int sockets[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  char byte = 'f';
  struct iovec iov = {.iov_base = &byte, .iov_len = 1};
  union {
    struct cmsghdr align;
    char bytes[CMSG_SPACE(sizeof(int))];
  } control = {0};
  struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = control.bytes,
                          .msg_controllen = sizeof(control.bytes)};
  struct cmsghdr *header = CMSG_FIRSTHDR(&message);
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(int));
  acquired(file.owner, LOCK_SH);
  memcpy(CMSG_DATA(header), &file.owner, sizeof(int));
  CHECK(sendmsg(sockets[0], &message, mode >= 2 ? MSG_OOB : 0) == 1);
  if (mode >= 2) {
    CHECK(close(file.owner) == 0);
    file.owner = -1;
    /* Linux still holds the OFD in the unreceived out-of-band message. */
    excluded(file.probe, LOCK_EX);
    if (mode == 3) {
      CHECK(flock(file.waiter, LOCK_EX) == 0);
    }
    CHECK(close(sockets[1]) == 0 && close(sockets[0]) == 0);
    acquired(file.probe, LOCK_EX);
    CHECK(flock(file.probe, LOCK_UN) == 0);
    remove_file(&file);
    return;
  }
  if (mode == 1) {
    struct waiter waiter;
    start_conversion(&file, &waiter, file.waiter);
    CHECK(close(file.owner) == 0);
    file.owner = -1;
    excluded(file.probe, LOCK_EX);
    not_finished(&waiter);
    /* The queued SCM_RIGHTS copy is the owner's last reference. */
    CHECK(close(sockets[1]) == 0);
    observe_exclusive(&file, &waiter);
    finish_waiter(&waiter, 0, 0);
    CHECK(close(sockets[0]) == 0);
    remove_file(&file);
    return;
  }
  memset(control.bytes, 0, sizeof(control.bytes));
  CHECK(recvmsg(sockets[1], &message, 0) == 1);
  header = CMSG_FIRSTHDR(&message);
  CHECK(header != NULL && header->cmsg_level == SOL_SOCKET &&
        header->cmsg_type == SCM_RIGHTS && header->cmsg_len == CMSG_LEN(sizeof(int)));
  int alias;
  memcpy(&alias, CMSG_DATA(header), sizeof(alias));
  struct waiter waiter;
  start_conversion(&file, &waiter, file.waiter);
  CHECK(close(file.owner) == 0);
  file.owner = -1;
  excluded(file.probe, LOCK_EX);
  not_finished(&waiter);
  CHECK(flock(alias, LOCK_UN) == 0);
  observe_exclusive(&file, &waiter);
  finish_waiter(&waiter, 0, 0);
  CHECK(close(alias) == 0);
  CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
  remove_file(&file);
}

int main(int argc, char **argv) {
  CHECK(argc >= 2);
  if (strcmp(argv[1], "external-probe") == 0) {
    CHECK(argc == 3);
    int fd = open(argv[2], O_RDWR);
    CHECK(fd >= 0);
    excluded(fd, LOCK_EX);
    excluded(fd, LOCK_SH);
    CHECK(close(fd) == 0);
    puts("flock-wait external-probe success");
    return 0;
  }
  if (strcmp(argv[1], "external") == 0) {
    CHECK(argc == 3);
    int fd = open(argv[2], O_RDWR);
    CHECK(fd >= 0);
    /* A separate host process owns this file's EX lock. The strict run must
     * refuse, not return success, synthesize EWOULDBLOCK, or wait forever. */
    int result = flock(fd, LOCK_EX);
    fprintf(stderr, "external flock unexpectedly returned %d errno=%d\n", result, errno);
    return 1;
  }
  CHECK(argc == 2);
  if (strcmp(argv[1], "handoff") == 0) handoff();
  else if (strcmp(argv[1], "shared") == 0) shared_waiters(0);
  else if (strcmp(argv[1], "downgrade") == 0) shared_waiters(1);
  else if (strcmp(argv[1], "last-close") == 0) last_close();
  else if (strcmp(argv[1], "fork-close") == 0) fork_release(0);
  else if (strcmp(argv[1], "exit") == 0) fork_release(1);
  else if (strcmp(argv[1], "reuse-alias") == 0) reuse(1);
  else if (strcmp(argv[1], "reuse-last") == 0) reuse(0);
  else if (strcmp(argv[1], "conversions") == 0) conversions();
  else if (strcmp(argv[1], "signal") == 0) signal_wait(0);
  else if (strcmp(argv[1], "restart") == 0) signal_wait(1);
  else if (strcmp(argv[1], "rights") == 0) rights_alias(0);
  else if (strcmp(argv[1], "rights-discard") == 0) rights_alias(1);
  else if (strcmp(argv[1], "rights-oob-probe") == 0) rights_alias(2);
  else if (strcmp(argv[1], "rights-oob-wait") == 0) rights_alias(3);
  else CHECK(0);
  printf("flock-wait %s success\n", argv[1]);
  return 0;
}
