/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>

/* No guest alarm: the host harness owns the watchdog. Producer sleeps open a
 * blocking-wait window; acknowledgements, never sleeps, order the results.
 * A missing wakeup must fail, not be rescued by a producer's exit. */
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s (errno=%d: %s)\n", __FILE__, __LINE__,          \
              #condition, errno, strerror(errno));                             \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static void make_pipe(int fds[2]) {
  CHECK(pipe(fds) == 0);
}

static void put_byte(int fd, char value) {
  CHECK(write(fd, &value, 1) == 1);
}

static void get_byte(int fd, char expected) {
  char value = 0;
  CHECK(read(fd, &value, 1) == 1);
  CHECK(value == expected);
}

static void put_count(int fd, uint64_t value) {
  CHECK(write(fd, &value, sizeof(value)) == (ssize_t)sizeof(value));
}

static uint64_t get_count(int fd) {
  uint64_t value = 0;
  CHECK(read(fd, &value, sizeof(value)) == (ssize_t)sizeof(value));
  return value;
}

static void joined(pid_t child) {
  int status = 0;
  pid_t result;
  do {
    result = waitpid(child, &status, 0);
  } while (result == -1 && errno == EINTR);
  CHECK(result == child);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void expect_poll(int fd, short events, short expected) {
  struct pollfd item = {.fd = fd, .events = events};
  CHECK(poll(&item, 1, 0) == (expected ? 1 : 0));
  CHECK(item.revents == expected);
}

static void expect_eof(int fd) {
  char byte;
  CHECK(read(fd, &byte, 1) == 0);
}

/* Called only after the consumer has probed empty and released its producer.
 * Under Hermit this is a deterministic timer: the consumer can park before the
 * producer's next operation. Native runs get the same blocking-wait window. */
static void wait_for_consumer(void) {
  struct timespec delay = {.tv_nsec = 100000000};
  CHECK(nanosleep(&delay, NULL) == 0);
}

/* A forked producer retains a dup after both processes close the original.
 * The two pipe acknowledgements also make separate writes observable. */
static void eventfd_consumer(int semaphore) {
  int fd = eventfd(0, semaphore ? EFD_SEMAPHORE : 0);
  CHECK(fd >= 0);
  int alias = dup(fd);
  CHECK(alias >= 0);
  int gate[2];
  make_pipe(gate);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(fd) == 0);
    CHECK(close(gate[1]) == 0);
    get_byte(gate[0], 'a');
    put_count(alias, 3);
    get_byte(gate[0], 'b');
    put_count(alias, 5);
    _exit(0);
  }
  CHECK(close(fd) == 0);
  CHECK(close(gate[0]) == 0);
  expect_poll(alias, POLLIN, 0);
  put_byte(gate[1], 'a');
  if (semaphore) {
    for (int i = 0; i < 3; ++i) {
      CHECK(get_count(alias) == 1);
    }
  } else {
    CHECK(get_count(alias) == 3);
  }
  expect_poll(alias, POLLIN, 0);
  put_byte(gate[1], 'b');
  if (semaphore) {
    for (int i = 0; i < 5; ++i) {
      CHECK(get_count(alias) == 1);
    }
  } else {
    CHECK(get_count(alias) == 5);
  }
  expect_poll(alias, POLLIN, 0);
  joined(child);
  CHECK(close(alias) == 0);
  CHECK(close(gate[1]) == 0);
  puts("alias/fork: consumed 3 then 5; empty");
}

/* A saturated counter must wake a blocked writer after a read, including
 * EFD_SEMAPHORE's one-unit decrement rather than a counter reset. */
static void eventfd_producer(int semaphore) {
  int fd = eventfd(0, semaphore ? EFD_SEMAPHORE : 0);
  CHECK(fd >= 0);
  put_count(fd, UINT64_MAX - 1);
  expect_poll(fd, POLLOUT, 0);
  int started[2], done[2];
  make_pipe(started);
  make_pipe(done);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    put_byte(started[1], 'w');
    put_count(fd, 1);
    put_byte(done[1], 'd');
    _exit(0);
  }
  get_byte(started[0], 'w');
  CHECK(get_count(fd) == (semaphore ? 1 : UINT64_MAX - 1));
  get_byte(done[0], 'd');
  if (semaphore) {
    expect_poll(fd, POLLOUT, 0);
    CHECK(get_count(fd) == 1);
    expect_poll(fd, POLLOUT, POLLOUT);
  } else {
    CHECK(get_count(fd) == 1);
    expect_poll(fd, POLLIN, 0);
  }
  joined(child);
  CHECK(close(fd) == 0);
  puts("capacity: blocked writer completed after drain");
}

static void eventfd_waiters(void) {
  enum { WAITERS = 3 };
  int fd = eventfd(0, EFD_SEMAPHORE);
  CHECK(fd >= 0);
  pid_t children[WAITERS];
  int ready[WAITERS][2], done[WAITERS][2];
  for (int i = 0; i < WAITERS; ++i) {
    make_pipe(ready[i]);
    make_pipe(done[i]);
    children[i] = fork();
    CHECK(children[i] >= 0);
    if (children[i] == 0) {
      put_byte(ready[i][1], 'r');
      CHECK(get_count(fd) == 1);
      put_byte(done[i][1], (char)('0' + i));
      _exit(0);
    }
  }
  for (int i = 0; i < WAITERS; ++i) {
    get_byte(ready[i][0], 'r');
  }
  put_count(fd, WAITERS);
  for (int i = 0; i < WAITERS; ++i) {
    get_byte(done[i][0], (char)('0' + i));
    joined(children[i]);
  }
  expect_poll(fd, POLLIN, 0);
  CHECK(close(fd) == 0);
  puts("waiters: each consumed exactly one token");
}

/* Joining a thread must not revoke the shared file table still used by the
 * consumer and its live producer. No producer exit can rescue the read. */
static void* shared_fd_thread(void* argument) {
  int fd = *(int*)argument;
  CHECK(fcntl(fd, F_GETFD) >= 0);
  expect_poll(fd, POLLIN, 0);
  return NULL;
}

static void eventfd_thread_exit(void) {
  int fd = eventfd(0, 0);
  CHECK(fd >= 0);
  int gate[2];
  make_pipe(gate);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(gate[1]) == 0);
    get_byte(gate[0], 'g');
    wait_for_consumer();
    put_count(fd, 7);
    get_byte(gate[0], 'q');
    _exit(0);
  }
  CHECK(close(gate[0]) == 0);
  pthread_t thread;
  CHECK(pthread_create(&thread, NULL, shared_fd_thread, &fd) == 0);
  CHECK(pthread_join(thread, NULL) == 0);
  expect_poll(fd, POLLIN, 0);
  put_byte(gate[1], 'g');
  CHECK(get_count(fd) == 7);
  expect_poll(fd, POLLIN, 0);
  put_byte(gate[1], 'q');
  joined(child);
  CHECK(close(fd) == 0);
  CHECK(close(gate[1]) == 0);
  puts("thread exit: shared eventfd wakes after thread join");
}

/* Both the successful and failed exec producers stay alive until each actual
 * consumer has drained its source. Separate gates force both reads to park. */
static void lifecycle_producer(int fd, int writer, int gate, int alive) {
  put_byte(alive, 'x');
  get_byte(gate, 'e');
  wait_for_consumer();
  put_count(fd, 11);
  get_byte(gate, 'p');
  wait_for_consumer();
  put_byte(writer, 'd');
  get_byte(gate, 'q');
}

static void lifecycle_exec(int succeed) {
  int fd = eventfd(0, EFD_CLOEXEC);
  CHECK(fd >= 0);
  int alias = dup(fd);
  CHECK(alias >= 0);
  int data[2], gate[2], alive[2];
  CHECK(pipe2(data, O_CLOEXEC) == 0);
  int writer = dup(data[1]);
  CHECK(writer >= 0);
  make_pipe(gate);
  make_pipe(alive);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(data[0]) == 0);
    CHECK(close(gate[1]) == 0);
    CHECK(close(alive[0]) == 0);
    if (succeed) {
      char fd_arg[32], writer_arg[32], gate_arg[32], alive_arg[32];
      CHECK(snprintf(fd_arg, sizeof(fd_arg), "%d", alias) > 0);
      CHECK(snprintf(writer_arg, sizeof(writer_arg), "%d", writer) > 0);
      CHECK(snprintf(gate_arg, sizeof(gate_arg), "%d", gate[0]) > 0);
      CHECK(snprintf(alive_arg, sizeof(alive_arg), "%d", alive[1]) > 0);
      execl("/proc/self/exe", "event_driven_io", "exec-producer", fd_arg,
            writer_arg, gate_arg, alive_arg, (char*)NULL);
      CHECK(0);
    } else {
      /* An empty pathname fails without depending on the host filesystem.
       * FD_CLOEXEC must not take effect when exec fails. Use the originals,
       * not the non-CLOEXEC aliases, for both subsequent writes. */
      errno = 0;
      execl("", "event_driven_io", (char*)NULL);
      CHECK(errno == ENOENT);
      CHECK(fcntl(fd, F_GETFD) == FD_CLOEXEC);
      CHECK(fcntl(data[1], F_GETFD) == FD_CLOEXEC);
      CHECK(close(alias) == 0);
      CHECK(close(writer) == 0);
      lifecycle_producer(fd, data[1], gate[0], alive[1]);
    }
    _exit(0);
  }
  CHECK(close(fd) == 0);
  CHECK(close(data[1]) == 0);
  CHECK(close(writer) == 0);
  CHECK(close(gate[0]) == 0);
  CHECK(close(alive[1]) == 0);
  get_byte(alive[0], 'x');
  expect_poll(alias, POLLIN, 0);
  expect_poll(data[0], POLLIN, 0); /* A surviving writer forbids early EOF. */
  put_byte(gate[1], 'e');
  CHECK(get_count(alias) == 11);
  expect_poll(alias, POLLIN, 0);
  put_byte(gate[1], 'p');
  get_byte(data[0], 'd');
  expect_poll(data[0], POLLIN, 0);
  put_byte(gate[1], 'q');
  joined(child);
  CHECK(close(alias) == 0);
  CHECK(close(data[0]) == 0);
  CHECK(close(gate[1]) == 0);
  CHECK(close(alive[0]) == 0);
  puts(succeed ? "exec: surviving eventfd and pipe aliases wake live consumers"
               : "failed exec: original CLOEXEC descriptors still produce");
}


static void pipe_exit(int last_thread) {
  int data[2], gate[2];
  make_pipe(data);
  make_pipe(gate);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(data[0]) == 0);
    CHECK(close(gate[1]) == 0);
    get_byte(gate[0], 'g');
    wait_for_consumer();
    CHECK(write(data[1], "abc", 3) == 3);
    get_byte(gate[0], 'e');
    wait_for_consumer();
    /* Neither path closes the writer in userspace. Only the completed kernel
     * lifecycle operation can make the consumer observe EOF. */
    syscall(last_thread ? SYS_exit : SYS_exit_group, 0);
    CHECK(0);
  }
  CHECK(close(data[1]) == 0);
  CHECK(close(gate[0]) == 0);
  expect_poll(data[0], POLLIN, 0);
  put_byte(gate[1], 'g');
  get_byte(data[0], 'a');
  get_byte(data[0], 'b');
  get_byte(data[0], 'c');
  expect_poll(data[0], POLLIN, 0);
  put_byte(gate[1], 'e');
  expect_eof(data[0]);
  expect_poll(data[0], POLLIN, POLLHUP);
  joined(child);
  CHECK(close(data[0]) == 0);
  CHECK(close(gate[1]) == 0);
  puts(last_thread ? "pipe: abc before EOF from raw last-thread exit"
                   : "pipe: abc before EOF from raw group exit");
}

static void pipe_cloexec(void) {
  int data[2], alive[2], release[2];
  CHECK(pipe2(data, O_CLOEXEC) == 0);
  make_pipe(alive);
  make_pipe(release);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    char ack_arg[32], release_arg[32], closed_arg[32];
    CHECK(close(data[0]) == 0);
    get_byte(release[0], 'e');
    wait_for_consumer();
    CHECK(snprintf(ack_arg, sizeof(ack_arg), "%d", alive[1]) > 0);
    CHECK(snprintf(release_arg, sizeof(release_arg), "%d", release[0]) > 0);
    CHECK(snprintf(closed_arg, sizeof(closed_arg), "%d", data[1]) > 0);
    execl("/proc/self/exe", "event_driven_io", "exec-child", ack_arg,
          release_arg, closed_arg, (char*)NULL);
    CHECK(0);
  }
  CHECK(close(data[1]) == 0);
  expect_poll(data[0], POLLIN, 0);
  put_byte(release[1], 'e');
  /* Park before exec closes the last writer. The exec child then remains alive
   * until the EOF consumer acknowledges it: exit cannot rescue a lost wake. */
  expect_eof(data[0]);
  get_byte(alive[0], 'x');
  put_byte(release[1], 'q');
  joined(child);
  CHECK(close(data[0]) == 0);
  puts("pipe: CLOEXEC EOF while exec child remains alive");
}

/* Close two aliases either individually, together, or by replacing them.
 * Replacement keeps the peer alive until the acknowledgement: exit cannot
 * rescue a missed EOF/EPIPE wake. Failed and same-fd dup2 are no-ops. */
static void close_pipe_aliases(int how, int replacement) {
  CHECK(dup2(100, 100) == 100);
  errno = 0;
  CHECK(dup2(-1, 100) == -1 && errno == EBADF);
  if (how == 1) {
    CHECK(syscall(SYS_close_range, 100U, 101U, 0) == 0);
  } else if (how == 2) {
    CHECK(dup2(replacement, 100) == 100);
    CHECK(dup3(replacement, 101, O_CLOEXEC) == 101);
    CHECK(close(100) == 0);
    CHECK(close(101) == 0);
  } else {
    CHECK(close(100) == 0);
    CHECK(close(101) == 0);
  }
}

static void pipe_close_lifetime(int how, int reopened) {
  CHECK(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
  for (int closing_readers = 0; closing_readers <= 1; ++closing_readers) {
    int data[2], gate[2], ack[2];
    CHECK(pipe2(data, O_NONBLOCK) == 0);
    make_pipe(gate);
    make_pipe(ack);
    if (closing_readers) {
      char buffer[4096];
      memset(buffer, 'f', sizeof(buffer));
      for (;;) {
        ssize_t count = write(data[1], buffer, sizeof(buffer));
        if (count == -1) {
          CHECK(errno == EAGAIN);
          break;
        }
        CHECK(count > 0);
      }
    }
    CHECK(fcntl(data[0], F_SETFL, 0) == 0);
    CHECK(fcntl(data[1], F_SETFL, 0) == 0);
    if (how == 1) {
      /* One deduplicated key must remember BOTH closed directions. */
      CHECK(fcntl(data[0], F_DUPFD, 100) == 100);
      CHECK(fcntl(data[1], F_DUPFD, 101) == 101);
      CHECK(syscall(SYS_close_range, 100U, 101U, 0) == 0);
    }
    if (reopened) {
      char path[64];
      CHECK(snprintf(path, sizeof(path), "/proc/self/fd/%d", data[0]) > 0);
      int unknown = open(path, O_RDONLY | O_NONBLOCK);
      CHECK(unknown >= 0);
      CHECK(close(unknown) == 0);
    }
    int side = closing_readers ? 0 : 1;
    CHECK(fcntl(data[side], F_DUPFD, 100) == 100);
    CHECK(fcntl(data[side], F_DUPFD, 101) == 101);
    CHECK(close(data[side]) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
      close_pipe_aliases(how, gate[0]);
      /* Root retains both aliases: these child closes cannot be last. */
      expect_poll(data[1 - side], closing_readers ? POLLOUT : POLLIN, 0);
      put_byte(ack[1], 'r');
      get_byte(gate[0], 'g');
      if (closing_readers) {
        errno = 0;
        CHECK(write(data[1], "x", 1) == -1 && errno == EPIPE);
        expect_poll(data[1], 0, POLLERR);
      } else {
        expect_eof(data[0]);
        expect_poll(data[0], 0, POLLHUP);
      }
      put_byte(ack[1], 'e');
      get_byte(gate[0], 'q');
      _exit(0);
    }
    get_byte(ack[0], 'r');
    put_byte(gate[1], 'g');
    wait_for_consumer();
    /* With an opposite end in THIS table, the final close must reject the
     * fresh witness, not mistake deferred fput for a peer. Without one,
     * notification must conservatively survive without probing anything. */
    if (how == 3) {
      CHECK(close(data[1 - side]) == 0);
    }
    close_pipe_aliases(how, gate[0]);
    get_byte(ack[0], 'e');
    put_byte(gate[1], 'q');
    joined(child);
    if (how != 3) {
      CHECK(close(data[1 - side]) == 0);
    }
    CHECK(close(gate[0]) == 0);
    CHECK(close(gate[1]) == 0);
    CHECK(close(ack[0]) == 0);
    CHECK(close(ack[1]) == 0);
  }
  puts("pipe: root-retained aliases forbid early EOF/EPIPE; final close wakes before exit");
}

struct shared_pipe_binding {
  int how;
  int watched;
  int replacement;
  int gate;
  int ack;
};

static void* replace_shared_pipe_binding(void* argument) {
  struct shared_pipe_binding* change = argument;
  get_byte(change->gate, 'g');
  wait_for_consumer();
  if (change->how == 0) {
    CHECK(dup2(change->replacement, change->watched) == change->watched);
  } else if (change->how == 1) {
    CHECK(close(change->watched) == 0);
  } else {
    CHECK(syscall(SYS_close_range, (unsigned)change->watched,
                  (unsigned)change->watched, 0) == 0);
  }
  /* Retain old reader aliases and writers until the poller acknowledges.
   * Neither EOF nor thread exit may rescue the descriptor-binding wake. */
  get_byte(change->ack, 'a');
  return NULL;
}

static void pipe_shared_bindings(void) {
  for (int how = 0; how != 3; ++how) {
    int old[2], ready[2], gate[2], ack[2];
    make_pipe(old);
    make_pipe(ready);
    make_pipe(gate);
    make_pipe(ack);
    int watched = dup(old[0]);
    CHECK(watched >= 0);
    put_byte(ready[1], 'r');
    struct shared_pipe_binding change = {
        how, watched, ready[0], gate[0], ack[0]};
    pthread_t producer;
    CHECK(pthread_create(&producer, NULL, replace_shared_pipe_binding, &change) == 0);
    expect_poll(watched, POLLIN, 0);
    put_byte(gate[1], 'g');
    /* Linux need not wake a cross-thread poll on close/replacement itself.
     * Native may recheck at the finite timeout. Hermit's numeric-fd retry
     * contract must instead complete before that virtual deadline, so a
     * missing binding wake cannot be rescued by timeout. Both modes make
     * the same real IO and clock calls; only Hermit asserts early progress. */
    struct pollfd item = {.fd = watched, .events = POLLIN};
    struct timespec started, finished;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &started) == 0);
    int result = poll(&item, 1, 500);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &finished) == 0);
    CHECK(result == 1);
    CHECK(item.revents == (how == 0 ? POLLIN : POLLNVAL));
    if (getenv("HERMIT_TEST_BINDING_DEADLINE") != NULL) {
      int64_t elapsed = (finished.tv_sec - started.tv_sec) * INT64_C(1000000000)
          + finished.tv_nsec - started.tv_nsec;
      CHECK(elapsed >= 0 && elapsed < INT64_C(500000000));
    }
    put_byte(ack[1], 'a');
    CHECK(pthread_join(producer, NULL) == 0);
    if (how == 0) {
      get_byte(watched, 'r');
      CHECK(close(watched) == 0);
    }
    for (int side = 0; side != 2; ++side) {
      CHECK(close(old[side]) == 0);
      CHECK(close(ready[side]) == 0);
      CHECK(close(gate[side]) == 0);
      CHECK(close(ack[side]) == 0);
    }
  }
  puts("pipe: shared-table replacement and closes wake the original numeric-fd waiter");
}

static void pipe_capacity(void) {
  int data[2], ready[2];
  CHECK(pipe2(data, O_NONBLOCK) == 0);
  make_pipe(ready);
  char buffer[4096];
  memset(buffer, 'f', sizeof(buffer));
  size_t filled = 0;
  for (;;) {
    ssize_t count = write(data[1], buffer, sizeof(buffer));
    if (count < 0) {
      CHECK(errno == EAGAIN);
      break;
    }
    CHECK(count > 0);
    filled += (size_t)count;
  }
  CHECK(filled > 0);
  CHECK(fcntl(data[0], F_SETFL, 0) == 0);
  CHECK(fcntl(data[1], F_SETFL, 0) == 0);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(data[0]) == 0);
    put_byte(ready[1], 'r');
    put_byte(data[1], 'z');
    _exit(0);
  }
  CHECK(close(data[1]) == 0);
  get_byte(ready[0], 'r');
  size_t remaining = filled;
  while (remaining > 0) {
    size_t wanted = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
    ssize_t count = read(data[0], buffer, wanted);
    CHECK(count > 0);
    for (ssize_t i = 0; i < count; ++i) {
      CHECK(buffer[i] == 'f');
    }
    remaining -= (size_t)count;
  }
  get_byte(data[0], 'z');
  expect_eof(data[0]);
  joined(child);
  puts("pipe: full-buffer drain wakes writer; FIFO preserved");
}

static void poll_timeout(void) {
  int fd = eventfd(0, 0);
  CHECK(fd >= 0);
  /* Python's isatty-style queries on unrelated ordinary files must not
   * revoke this eventfd's dependency authority. Linux rejects them ENOTTY. */
  int ordinary = open("/proc/self/exe", O_RDONLY);
  CHECK(ordinary >= 0);
  struct termios terminal;
  CHECK(ioctl(ordinary, TCGETS, &terminal) == -1 && errno == ENOTTY);
  CHECK(close(ordinary) == 0);
  int nonblocking = 1;
  CHECK(ioctl(fd, FIONBIO, &nonblocking) == 0);
  CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) != 0);
  uint64_t empty;
  CHECK(read(fd, &empty, sizeof(empty)) == -1 && errno == EAGAIN);
  nonblocking = 0;
  CHECK(ioctl(fd, FIONBIO, &nonblocking) == 0);
  CHECK((fcntl(fd, F_GETFL) & O_NONBLOCK) == 0);
  CHECK(ioctl(fd, FIOCLEX, 0) == 0);
  CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
  CHECK(ioctl(fd, FIONCLEX, 0) == 0);
  CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0);
  struct pollfd item = {.fd = fd, .events = POLLIN};
  struct timespec before, after;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
  CHECK(poll(&item, 1, 25) == 0);
  CHECK(item.revents == 0);
  CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
  int64_t elapsed = (int64_t)(after.tv_sec - before.tv_sec) * 1000000000 +
                    after.tv_nsec - before.tv_nsec;
  CHECK(elapsed >= 25000000);
  put_count(fd, 9);
  CHECK(poll(&item, 1, 25) == 1);
  CHECK(item.revents == POLLIN);
  CHECK(get_count(fd) == 9);
  CHECK(close(fd) == 0);
  puts("poll: finite deadline expires; subsequent readiness wins");
}

static volatile sig_atomic_t signals_seen;

static void on_signal(int signo) {
  if (signo == SIGUSR1 || signo == SIGCHLD) {
    ++signals_seen;
  }
}

static void masked_ppoll_signal_fallback(void) {
  struct sigaction action = {.sa_handler = on_signal};
  CHECK(sigemptyset(&action.sa_mask) == 0);
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  sigset_t blocked, previous;
  CHECK(sigemptyset(&blocked) == 0);
  CHECK(sigaddset(&blocked, SIGUSR1) == 0);
  CHECK(sigprocmask(SIG_BLOCK, &blocked, &previous) == 0);
  int fd = eventfd(0, 0);
  CHECK(fd >= 0);
  int gate[2];
  make_pipe(gate);
  pid_t parent = getpid();
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    get_byte(gate[0], 's');
    CHECK(kill(parent, SIGUSR1) == 0);
    _exit(0);
  }
  put_byte(gate[1], 's');
  struct pollfd item = {.fd = fd, .events = POLLIN};
  struct timespec deadline = {.tv_sec = 10};
  /* The temporary mask deliberately selects the legacy fallback. Atomic
   * unmask avoids the signal-before-poll race without sleeps. */
  CHECK(ppoll(&item, 1, &deadline, &previous) == -1);
  CHECK(errno == EINTR);
  CHECK(signals_seen == 1);
  CHECK(sigprocmask(SIG_SETMASK, &previous, NULL) == 0);
  joined(child);
  put_count(fd, 7);
  expect_poll(fd, POLLIN, POLLIN);
  CHECK(get_count(fd) == 7);
  CHECK(close(fd) == 0);
  puts("masked ppoll fallback: one signal interrupts; fd remains usable");
}

/* Unlike masked ppoll, both ordinary poll and eventfd read are eligible for
 * dependency parking. Keep the sender alive through both acknowledgements:
 * neither kernel-generated SIGCHLD nor exit cleanup may rescue a lost wake. */
static void parked_signal(int use_poll, int signo) {
  struct sigaction action = {.sa_handler = on_signal};
  CHECK(sigemptyset(&action.sa_mask) == 0);
  CHECK(sigaction(signo, &action, NULL) == 0);
  sigset_t unblocked;
  CHECK(sigemptyset(&unblocked) == 0);
  CHECK(sigaddset(&unblocked, signo) == 0);
  CHECK(sigprocmask(SIG_UNBLOCK, &unblocked, NULL) == 0);
  int fd = eventfd(0, 0);
  CHECK(fd >= 0);
  int gate[2];
  make_pipe(gate);
  pid_t parent = getpid();
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(gate[1]) == 0);
    get_byte(gate[0], 's');
    wait_for_consumer();
    if (signo == SIGCHLD) {
      /* Private, recorded SIGCHLD; shared kill(SIGCHLD) retains the native
       * backend's existing provenance restriction. */
      CHECK(syscall(SYS_tgkill, parent, parent, signo) == 0);
    } else {
      CHECK(kill(parent, signo) == 0);
    }
    get_byte(gate[0], 'i');
    wait_for_consumer();
    put_count(fd, 7);
    get_byte(gate[0], 'd');
    _exit(0);
  }
  CHECK(close(gate[0]) == 0);
  expect_poll(fd, POLLIN, 0);
  CHECK(signals_seen == 0);
  put_byte(gate[1], 's');
  struct pollfd item = {.fd = fd, .events = POLLIN};
  uint64_t value = 0;
  ssize_t result = use_poll ? poll(&item, 1, -1)
                            : read(fd, &value, sizeof(value));
  CHECK(result == -1);
  CHECK(errno == EINTR);
  CHECK(signals_seen == 1);
  CHECK(item.revents == 0);
  expect_poll(fd, POLLIN, 0);
  put_byte(gate[1], 'i');
  if (use_poll) {
    CHECK(poll(&item, 1, -1) == 1);
    CHECK(item.revents == POLLIN);
  }
  CHECK(get_count(fd) == 7);
  CHECK(signals_seen == 1);
  expect_poll(fd, POLLIN, 0);
  put_byte(gate[1], 'd');
  joined(child);
  if (signo != SIGCHLD) CHECK(signals_seen == 1);
  CHECK(close(gate[1]) == 0);
  CHECK(close(fd) == 0);
  puts(use_poll ? "parked poll: EINTR once before readiness; consumed 7"
                : "parked read: EINTR once before readiness; consumed 7");
}

/* The producer cannot publish readiness until its real child wait completes.
 * A finite I/O deadline must not jump past that completion/rejoin barrier.
 * The grandchild's modeled sleep still has to advance while waitpid is pending.
 * The producer stays alive until the consumer has observed its data. */
static void poll_child_gate(void) {
  int fd = eventfd(0, 0);
  CHECK(fd >= 0);
  int gate[2];
  make_pipe(gate);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(gate[1]) == 0);
    get_byte(gate[0], 'g');
    pid_t worker = fork();
    CHECK(worker >= 0);
    if (worker == 0) {
      wait_for_consumer();
      _exit(0);
    }
    joined(worker);
    put_count(fd, 13);
    get_byte(gate[0], 'd');
    _exit(0);
  }
  CHECK(close(gate[0]) == 0);
  expect_poll(fd, POLLIN, 0);
  put_byte(gate[1], 'g');
  struct pollfd item = {.fd = fd, .events = POLLIN};
  CHECK(poll(&item, 1, 5000) == 1);
  CHECK(item.revents == POLLIN);
  CHECK(get_count(fd) == 13);
  expect_poll(fd, POLLIN, 0);
  put_byte(gate[1], 'd');
  joined(child);
  CHECK(close(gate[1]) == 0);
  CHECK(close(fd) == 0);
  puts("finite poll: child wait completes before readiness; consumed 13");
}

static void control(int epoll, int operation, int fd, uint32_t flags,
                    uint64_t tag) {
  struct epoll_event event = {.events = flags, .data.u64 = tag};
  CHECK(epoll_ctl(epoll, operation, fd, &event) == 0);
}

static void event(int epoll, uint64_t tag) {
  struct epoll_event event;
  CHECK(epoll_wait(epoll, &event, 1, -1) == 1);
  CHECK(event.data.u64 == tag);
  CHECK(event.events == EPOLLIN);
}

static void no_event(int epoll) {
  struct epoll_event event;
  CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
}

static void epoll_rearm(void) {
  int fd = eventfd(0, EFD_NONBLOCK);
  int epoll = epoll_create1(EPOLL_CLOEXEC);
  CHECK(fd >= 0 && epoll >= 0);
  control(epoll, EPOLL_CTL_ADD, fd, EPOLLIN | EPOLLET | EPOLLONESHOT, 11);
  int gate[2];
  make_pipe(gate);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    get_byte(gate[0], 'a');
    put_count(fd, 2);
    get_byte(gate[0], 'b');
    put_count(fd, 3);
    _exit(0);
  }
  no_event(epoll);
  put_byte(gate[1], 'a');
  event(epoll, 11);
  no_event(epoll); /* ONESHOT suppresses a still-readable fd. */
  control(epoll, EPOLL_CTL_MOD, fd, EPOLLIN | EPOLLET | EPOLLONESHOT, 12);
  event(epoll, 12); /* Rearm an already-readable fd, without another write. */
  CHECK(get_count(fd) == 2);
  no_event(epoll);
  control(epoll, EPOLL_CTL_MOD, fd, EPOLLIN | EPOLLET, 13);
  no_event(epoll);
  put_byte(gate[1], 'b');
  event(epoll, 13);
  no_event(epoll); /* ET does not redeliver an undrained counter. */
  CHECK(get_count(fd) == 3);
  control(epoll, EPOLL_CTL_DEL, fd, 0, 0);
  put_count(fd, 1);
  no_event(epoll);
  joined(child);
  puts("epoll: ONESHOT rearm, ET drain, MOD tag, DEL suppression");
}

static void epoll_nested(void) {
  int fd = eventfd(0, 0);
  int inner = epoll_create1(0);
  int outer = epoll_create1(0);
  CHECK(fd >= 0 && inner >= 0 && outer >= 0);
  control(inner, EPOLL_CTL_ADD, fd, EPOLLIN | EPOLLONESHOT, 21);
  control(outer, EPOLL_CTL_ADD, inner, EPOLLIN, 22);
  int gate[2];
  make_pipe(gate);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    get_byte(gate[0], 'n');
    put_count(fd, 4);
    _exit(0);
  }
  no_event(outer);
  put_byte(gate[1], 'n');
  event(outer, 22);
  event(inner, 21);
  no_event(outer);
  control(inner, EPOLL_CTL_MOD, fd, EPOLLIN | EPOLLONESHOT, 23);
  event(outer, 22);
  event(inner, 23);
  CHECK(get_count(fd) == 4);
  no_event(outer);
  control(outer, EPOLL_CTL_DEL, inner, 0, 0);
  control(inner, EPOLL_CTL_MOD, fd, EPOLLIN, 24);
  put_count(fd, 1);
  no_event(outer);
  joined(child);
  puts("epoll: nested propagation and rearm; removed parent stays empty");
}

static void epoll_alias_reuse(void) {
  int original = eventfd(0, 0);
  int epoll = epoll_create1(0);
  CHECK(original >= 0 && epoll >= 0);
  int alias = dup(original);
  CHECK(alias >= 0);
  control(epoll, EPOLL_CTL_ADD, original, EPOLLIN, 31);
  CHECK(close(original) == 0);
  int replacement = eventfd(0, 0);
  CHECK(replacement >= 0);
  if (replacement != original) {
    CHECK(dup2(replacement, original) == original);
    CHECK(close(replacement) == 0);
  }
  control(epoll, EPOLL_CTL_ADD, original, EPOLLIN, 32);
  int gate[2], closed[2];
  make_pipe(gate);
  make_pipe(closed);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(gate[1]) == 0);
    CHECK(close(closed[0]) == 0);
    CHECK(close(epoll) == 0);
    get_byte(gate[0], 'a');
    wait_for_consumer();
    put_count(alias, 6);
    get_byte(gate[0], 'b');
    wait_for_consumer();
    put_count(original, 8);
    get_byte(gate[0], 'c');
    CHECK(close(alias) == 0);
    put_byte(closed[1], 'c');
    get_byte(gate[0], 'd');
    wait_for_consumer();
    put_count(original, 9);
    get_byte(gate[0], 'q');
    _exit(0);
  }
  CHECK(close(gate[0]) == 0);
  CHECK(close(closed[1]) == 0);
  /* Both watches coexist at the same registered number, but have different
   * OFDs. Each producer sleep lets epoll_wait probe empty and subscribe. */
  no_event(epoll);
  put_byte(gate[1], 'a');
  event(epoll, 31); /* Closing the registered number must retain its OFD. */
  CHECK(get_count(alias) == 6);
  no_event(epoll);
  put_byte(gate[1], 'b');
  event(epoll, 32);
  CHECK(get_count(original) == 8);
  expect_poll(alias, POLLIN, 0);
  no_event(epoll);
  put_byte(gate[1], 'c');
  get_byte(closed[0], 'c');
  CHECK(close(alias) == 0); /* Last old alias removes only the old watch. */
  no_event(epoll);
  put_byte(gate[1], 'd');
  event(epoll, 32);
  CHECK(get_count(original) == 9);
  no_event(epoll);
  put_byte(gate[1], 'q');
  joined(child);
  CHECK(close(gate[1]) == 0);
  CHECK(close(closed[0]) == 0);
  control(epoll, EPOLL_CTL_DEL, original, 0, 0);
  CHECK(close(original) == 0);
  CHECK(close(epoll) == 0);
  puts("epoll: parked old/reused OFDs wake independently; last alias removes old watch");
}

/* Signal masks precede every fork/thread. signalfd readiness is relative to the
 * reader's private and process queues, not to the task that created the OFD. */
static void block_signalfd_mask(sigset_t* mask, int first, int second) {
  CHECK(sigemptyset(mask) == 0);
  CHECK(sigaddset(mask, first) == 0);
  if (second != 0) {
    CHECK(sigaddset(mask, second) == 0);
  }
  CHECK(sigprocmask(SIG_BLOCK, mask, NULL) == 0);
}

static void signal_record(int fd, int signo, pid_t sender, int code) {
  struct signalfd_siginfo info;
  CHECK(read(fd, &info, sizeof(info)) == (ssize_t)sizeof(info));
  CHECK(info.ssi_signo == (uint32_t)signo);
  CHECK(info.ssi_pid == (uint32_t)sender);
  CHECK(info.ssi_code == code);
  /* ssi_tid is a timer ID, NOT the sending thread ID. User sends leave it zero. */
  CHECK(info.ssi_tid == 0);
  CHECK(info.ssi_uid == (uint32_t)getuid());
}

static void signal_poll(int fd) {
  struct pollfd item = {.fd = fd, .events = POLLIN};
  CHECK(poll(&item, 1, -1) == 1);
  CHECK(item.revents == POLLIN);
}

static void signalfd_poll_queue(int signo) {
  sigset_t mask;
  block_signalfd_mask(&mask, signo, 0);
  int fd = signalfd(-1, &mask, SFD_NONBLOCK);
  CHECK(fd >= 0);
  int gate[2];
  make_pipe(gate);
  pid_t parent = getpid();
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(gate[1]) == 0);
    for (char stage = 'a'; stage <= 'b'; ++stage) {
      get_byte(gate[0], stage);
      wait_for_consumer();
      if (signo == SIGCHLD) {
        /* Preserve the backend's existing shared-SIGCHLD restriction. */
        CHECK(syscall(SYS_tgkill, parent, parent, signo) == 0);
      } else {
        CHECK(kill(parent, signo) == 0);
      }
    }
    get_byte(gate[0], 'q');
    _exit(0);
  }
  CHECK(close(gate[0]) == 0);
  for (char stage = 'a'; stage <= 'b'; ++stage) {
    expect_poll(fd, POLLIN, 0);
    put_byte(gate[1], stage);
    signal_poll(fd);
    signal_record(fd, signo, child, signo == SIGCHLD ? SI_TKILL : SI_USER);
    expect_poll(fd, POLLIN, 0);
  }
  put_byte(gate[1], 'q');
  joined(child);
  CHECK(close(gate[1]) == 0);
  CHECK(close(fd) == 0);
  puts(signo == SIGCHLD
           ? "signalfd: private SIGCHLD fallback consumed and resent before sender exit"
           : "signalfd: process queue consumed and resent; exact sender records");
}

struct signalfd_private_args {
  int fd;
  int gate[2];
  int ready[2];
  pid_t process;
  pid_t consumer;
};

static void* signalfd_private_sender(void* opaque) {
  struct signalfd_private_args* args = opaque;
  pid_t self = (pid_t)syscall(SYS_gettid);
  CHECK(syscall(SYS_tgkill, args->process, self, SIGUSR2) == 0);
  put_byte(args->ready[1], 'r');
  get_byte(args->gate[0], 'a');
  wait_for_consumer();
  CHECK(syscall(SYS_tgkill, args->process, args->consumer, SIGUSR1) == 0);
  get_byte(args->gate[0], 'q');
  /* The consumer must not have stolen this thread's pending SIGUSR2. */
  expect_poll(args->fd, POLLIN, POLLIN);
  signal_record(args->fd, SIGUSR2, args->process, SI_TKILL);
  expect_poll(args->fd, POLLIN, 0);
  return NULL;
}

static void signalfd_poll_private(void) {
  sigset_t mask;
  block_signalfd_mask(&mask, SIGUSR1, SIGUSR2);
  struct signalfd_private_args args = {
      .fd = signalfd(-1, &mask, SFD_NONBLOCK),
      .process = getpid(),
      .consumer = (pid_t)syscall(SYS_gettid),
  };
  CHECK(args.fd >= 0);
  make_pipe(args.gate);
  make_pipe(args.ready);
  pthread_t producer;
  CHECK(pthread_create(&producer, NULL, signalfd_private_sender, &args) == 0);
  get_byte(args.ready[0], 'r');
  expect_poll(args.fd, POLLIN, 0);
  put_byte(args.gate[1], 'a');
  signal_poll(args.fd);
  signal_record(args.fd, SIGUSR1, args.process, SI_TKILL);
  expect_poll(args.fd, POLLIN, 0);
  put_byte(args.gate[1], 'q');
  CHECK(pthread_join(producer, NULL) == 0);
  CHECK(close(args.fd) == 0);
  for (int i = 0; i < 2; ++i) {
    CHECK(close(args.gate[i]) == 0);
    CHECK(close(args.ready[i]) == 0);
  }
  puts("signalfd: targeted thread wakes; sibling private signal stays private");
}

/* A blocked ordinary signal plus a tracked anonymous pipe, with each source
 * independently waking the same epoll graph while the producer stays alive. */
static void signalfd_epoll_pipe(void) {
  sigset_t mask;
  block_signalfd_mask(&mask, SIGUSR2, 0);
  int fd = signalfd(-1, &mask, SFD_NONBLOCK);
  int epoll = epoll_create1(0);
  CHECK(fd >= 0 && epoll >= 0);
  int data[2], gate[2];
  make_pipe(data);
  make_pipe(gate);
  control(epoll, EPOLL_CTL_ADD, fd, EPOLLIN, 61);
  control(epoll, EPOLL_CTL_ADD, data[0], EPOLLIN, 62);
  pid_t parent = getpid();
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(gate[1]) == 0);
    CHECK(close(data[0]) == 0);
    get_byte(gate[0], 'a');
    wait_for_consumer();
    CHECK(kill(parent, SIGUSR2) == 0);
    get_byte(gate[0], 'b');
    wait_for_consumer();
    put_byte(data[1], 'p');
    get_byte(gate[0], 'q');
    _exit(0);
  }
  CHECK(close(gate[0]) == 0);
  CHECK(close(data[1]) == 0);
  no_event(epoll);
  put_byte(gate[1], 'a');
  event(epoll, 61);
  signal_record(fd, SIGUSR2, child, SI_USER);
  no_event(epoll);
  put_byte(gate[1], 'b');
  event(epoll, 62);
  get_byte(data[0], 'p');
  no_event(epoll);
  put_byte(gate[1], 'q');
  joined(child);
  CHECK(close(gate[1]) == 0);
  CHECK(close(data[0]) == 0);
  CHECK(close(fd) == 0);
  CHECK(close(epoll) == 0);
  puts("signalfd: epoll signal then anonymous pipe; distinct tags and drained queues");
}

static void signalfd_mask_alias(void) {
  sigset_t mask;
  block_signalfd_mask(&mask, SIGUSR1, SIGUSR2);
  CHECK(sigdelset(&mask, SIGUSR2) == 0);
  /* Pending before creation; independent signalfds consume the same queue. */
  pid_t parent = getpid();
  CHECK(kill(parent, SIGUSR1) == 0);
  int fd = signalfd(-1, &mask, SFD_NONBLOCK);
  int overlap = signalfd(-1, &mask, SFD_NONBLOCK);
  CHECK(fd >= 0 && overlap >= 0);
  expect_poll(fd, POLLIN, POLLIN);
  expect_poll(overlap, POLLIN, POLLIN);
  signal_record(fd, SIGUSR1, parent, SI_USER);
  expect_poll(fd, POLLIN, 0);
  expect_poll(overlap, POLLIN, 0);
  int alias = dup(fd);
  int epoll = epoll_create1(0);
  CHECK(alias >= 0 && epoll >= 0);
  control(epoll, EPOLL_CTL_ADD, fd, EPOLLIN, 71);
  control(epoll, EPOLL_CTL_ADD, overlap, EPOLLIN, 72);
  CHECK(sigdelset(&mask, SIGUSR1) == 0);
  CHECK(sigaddset(&mask, SIGUSR2) == 0);
  CHECK(signalfd(alias, &mask, SFD_NONBLOCK) == alias);
  int gate[2];
  make_pipe(gate);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(gate[1]) == 0);
    get_byte(gate[0], 'a');
    wait_for_consumer();
    CHECK(kill(parent, SIGUSR1) == 0);
    get_byte(gate[0], 'b');
    wait_for_consumer();
    CHECK(kill(parent, SIGUSR2) == 0);
    get_byte(gate[0], 'q');
    _exit(0);
  }
  CHECK(close(gate[0]) == 0);
  no_event(epoll);
  put_byte(gate[1], 'a');
  event(epoll, 72);
  expect_poll(fd, POLLIN, 0);
  expect_poll(alias, POLLIN, 0);
  signal_record(overlap, SIGUSR1, child, SI_USER);
  no_event(epoll);
  put_byte(gate[1], 'b');
  event(epoll, 71);
  expect_poll(alias, POLLIN, POLLIN);
  expect_poll(overlap, POLLIN, 0);
  signal_record(alias, SIGUSR2, child, SI_USER);
  no_event(epoll);
  put_byte(gate[1], 'q');
  joined(child);
  CHECK(close(gate[1]) == 0);
  CHECK(close(alias) == 0);
  CHECK(close(fd) == 0);
  CHECK(close(overlap) == 0);
  CHECK(close(epoll) == 0);
  puts("signalfd: pending creation shares queue; dup mask replacement retargets existing watch");
}

static void signalfd_timeout(void) {
  sigset_t mask;
  block_signalfd_mask(&mask, SIGUSR1, 0);
  int fd = signalfd(-1, &mask, SFD_NONBLOCK);
  int epoll = epoll_create1(0);
  CHECK(fd >= 0 && epoll >= 0);
  /* Successful existence probes and rejected signals must not create pending
   * readiness in either the process or private queue. */
  pid_t process = getpid();
  pid_t thread = (pid_t)syscall(SYS_gettid);
  CHECK(kill(process, 0) == 0);
  CHECK(syscall(SYS_tgkill, process, thread, 0) == 0);
  errno = 0;
  CHECK(kill(process, NSIG) == -1 && errno == EINVAL);
  errno = 0;
  CHECK(syscall(SYS_tgkill, process, thread, NSIG) == -1 && errno == EINVAL);
  struct pollfd item = {.fd = fd, .events = POLLIN};
  CHECK(poll(&item, 1, 20) == 0);
  CHECK(item.revents == 0);
  control(epoll, EPOLL_CTL_ADD, fd, EPOLLIN, 81);
  struct epoll_event result;
  CHECK(epoll_wait(epoll, &result, 1, 20) == 0);
  expect_poll(fd, POLLIN, 0);
  CHECK(close(epoll) == 0);
  CHECK(close(fd) == 0);
  puts("signalfd: finite poll and epoll deadlines expire with empty queue");
}

static void signalfd_epoll_child(int fresh) {
  sigset_t mask;
  block_signalfd_mask(&mask, SIGUSR1, 0);
  int fd = signalfd(-1, &mask, SFD_NONBLOCK);
  int epoll = epoll_create1(0);
  CHECK(fd >= 0 && epoll >= 0);
  control(epoll, EPOLL_CTL_ADD, fd, EPOLLIN, 91);
  int gate[2], sent[2];
  make_pipe(gate);
  make_pipe(sent);
  pid_t parent = getpid();
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(gate[0]) == 0);
    CHECK(close(sent[1]) == 0);
    if (fresh) {
      CHECK(close(epoll) == 0);
      epoll = epoll_create1(0);
      CHECK(epoll >= 0);
      control(epoll, EPOLL_CTL_ADD, fd, EPOLLIN, 92);
    } else {
      /* MOD must not replace the original ADD's parent-queue provenance. */
      control(epoll, EPOLL_CTL_MOD, fd, EPOLLIN, 92);
    }
    put_byte(gate[1], 'a');
    /* The epoll hook belongs to the parent queue, while readiness and dequeue
     * use the child queue. A parent signal can wake this inherited watch. */
    event(epoll, 92);
    get_byte(sent[0], 's');
    expect_poll(fd, POLLIN, POLLIN);
    signal_record(fd, SIGUSR1, parent, SI_USER);
    expect_poll(fd, POLLIN, 0);
    no_event(epoll);
    put_byte(gate[1], 'q');
    _exit(0);
  }
  CHECK(close(gate[1]) == 0);
  CHECK(close(sent[0]) == 0);
  get_byte(gate[0], 'a');
  wait_for_consumer();
  CHECK(kill(child, SIGUSR1) == 0);
  if (!fresh) {
    wait_for_consumer();
    CHECK(kill(parent, SIGUSR1) == 0);
  }
  put_byte(sent[1], 's');
  get_byte(gate[0], 'q');
  if (!fresh) {
    signal_record(fd, SIGUSR1, parent, SI_USER);
  }
  joined(child);
  expect_poll(fd, POLLIN, 0);
  CHECK(close(gate[0]) == 0);
  CHECK(close(sent[1]) == 0);
  CHECK(close(fd) == 0);
  CHECK(close(epoll) == 0);
  puts(fresh ? "signalfd: fresh child epoll ADD wakes on child queue"
             : "signalfd: inherited epoll keeps parent wake queue; child record stays private");
}

/* Exact Go syscall.NetlinkRIB(RTM_GETROUTE, AF_UNSPEC) wire shape:
 * nlmsg_len=17, REQUEST|DUMP, seq=1, pid=0, one-byte rtgenmsg, no tail pad.
 * The negative request is too short for rtmsg, so cannot change a route even
 * when the test runs with CAP_NET_ADMIN. It must still revoke authority. */
static void socket_route_prelude(int mutation) {
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  CHECK(fd >= 0);
  struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
  CHECK(bind(fd, (struct sockaddr *)&kernel, sizeof(kernel)) == 0);
  struct nlmsghdr header = {
      .nlmsg_len = NLMSG_LENGTH(1),
      .nlmsg_type = mutation ? RTM_NEWROUTE : RTM_GETROUTE,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
      .nlmsg_seq = 1,
  };
  unsigned char request[NLMSG_LENGTH(1)] = {0};
  memcpy(request, &header, sizeof(header));
  CHECK(sendto(fd, request, sizeof(request), 0,
               (struct sockaddr *)&kernel, sizeof(kernel)) == sizeof(request));
  int done = 0, routes = 0;
  while (!done) {
    union {
      struct nlmsghdr alignment;
      unsigned char bytes[32768];
    } reply;
    struct sockaddr_nl sender = {0};
    socklen_t sender_length = sizeof(sender);
    ssize_t received = recvfrom(fd, reply.bytes, sizeof(reply.bytes), 0,
                                (struct sockaddr *)&sender, &sender_length);
    CHECK(received > 0 && sender_length == sizeof(sender));
    CHECK(sender.nl_family == AF_NETLINK && sender.nl_pid == 0);
    int remaining = (int)received;
    for (struct nlmsghdr *item = (struct nlmsghdr *)reply.bytes;
         NLMSG_OK(item, remaining); item = NLMSG_NEXT(item, remaining)) {
      CHECK(item->nlmsg_seq == 1);
      CHECK(!(item->nlmsg_flags & NLM_F_DUMP_INTR));
      if (item->nlmsg_type == NLMSG_ERROR) {
        CHECK(mutation && item->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)));
        struct nlmsgerr error;
        memcpy(&error, NLMSG_DATA(item), sizeof(error));
        CHECK(error.error < 0);
        done = 1;
      } else if (item->nlmsg_type == NLMSG_DONE) {
        CHECK(!mutation && item->nlmsg_len >= NLMSG_LENGTH(sizeof(int)));
        int error;
        memcpy(&error, NLMSG_DATA(item), sizeof(error));
        CHECK(error == 0);
        done = 1;
      } else {
        CHECK(!mutation && item->nlmsg_type == RTM_NEWROUTE);
        CHECK(item->nlmsg_len >= NLMSG_LENGTH(sizeof(struct rtmsg)));
        ++routes;
      }
    }
    CHECK(remaining == 0);
  }
  CHECK(mutation || routes > 0);
  CHECK(close(fd) == 0);
}

static void socket_rights_prelude(int socket_right) {
  int transport[2], input[2], output[2], sockets[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, transport) == 0);
  make_pipe(input);
  make_pipe(output);
  char path[] = "/tmp/event-driven-rights-XXXXXX";
  int log = mkstemp(path);
  CHECK(log >= 0);
  int saved_stderr = dup(STDERR_FILENO);
  CHECK(saved_stderr >= 0 && dup2(log, STDERR_FILENO) == STDERR_FILENO);
  int alias = dup(STDERR_FILENO);
  CHECK(alias >= 0 && dup2(saved_stderr, STDERR_FILENO) == STDERR_FILENO);
  CHECK(close(saved_stderr) == 0);
  if (socket_right)
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  int sent[] = {input[0], output[1], socket_right ? sockets[0] : alias};
  char marker = 'f';
  struct iovec iov = {.iov_base = &marker, .iov_len = 1};
  union {
    struct cmsghdr alignment;
    char bytes[CMSG_SPACE(sizeof(sent))];
  } ancillary = {0};
  struct msghdr message = {
      .msg_iov = &iov, .msg_iovlen = 1,
      .msg_control = ancillary.bytes, .msg_controllen = sizeof(ancillary.bytes),
  };
  struct cmsghdr *control = CMSG_FIRSTHDR(&message);
  control->cmsg_level = SOL_SOCKET;
  control->cmsg_type = SCM_RIGHTS;
  control->cmsg_len = CMSG_LEN(sizeof(sent));
  memcpy(CMSG_DATA(control), sent, sizeof(sent));
  CHECK(sendmsg(transport[0], &message, 0) == 1);
  memset(&ancillary, 0, sizeof(ancillary));
  marker = 0;
  CHECK(recvmsg(transport[1], &message, 0) == 1 && marker == 'f');
  CHECK(!(message.msg_flags & MSG_CTRUNC));
  control = CMSG_FIRSTHDR(&message);
  CHECK(control && control->cmsg_level == SOL_SOCKET
        && control->cmsg_type == SCM_RIGHTS
        && control->cmsg_len == CMSG_LEN(sizeof(sent)));
  int received[3];
  memcpy(received, CMSG_DATA(control), sizeof(received));
  put_byte(input[1], 'i');
  get_byte(received[0], 'i');
  put_byte(received[1], 'o');
  get_byte(output[0], 'o');
  put_byte(received[2], 'l');
  if (socket_right) {
    get_byte(sockets[1], 'l');
    CHECK(close(sockets[0]) == 0 && close(sockets[1]) == 0);
  } else {
    CHECK(lseek(log, 0, SEEK_SET) == 0);
    get_byte(log, 'l');
  }
  for (size_t i = 0; i < 3; ++i)
    CHECK(close(received[i]) == 0);
  CHECK(close(alias) == 0 && close(log) == 0 && unlink(path) == 0);
  CHECK(close(input[0]) == 0 && close(input[1]) == 0);
  CHECK(close(output[0]) == 0 && close(output[1]) == 0);
  CHECK(close(transport[0]) == 0 && close(transport[1]) == 0);
}

static void socket_unix_datagram_prelude(int message_receive) {
  int receiver = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  int sender = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  CHECK(receiver >= 0 && sender >= 0);
  char directory[] = "/tmp/event-driven-datagram-XXXXXX";
  CHECK(mkdtemp(directory) == directory);
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  CHECK(snprintf(address.sun_path, sizeof(address.sun_path), "%s/socket",
                 directory) > 0);
  CHECK(bind(receiver, (struct sockaddr *)&address, sizeof(address)) == 0);
  CHECK(connect(sender, (struct sockaddr *)&address, sizeof(address)) == 0);
  if (message_receive) {
    int pipe_fds[2];
    if (message_receive == 2)
      CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pipe_fds) == 0);
    else
      make_pipe(pipe_fds);
    char byte = 'd';
    struct iovec iov = {.iov_base = &byte, .iov_len = 1};
    union {
      struct cmsghdr alignment;
      char bytes[CMSG_SPACE(sizeof(int))];
    } ancillary = {0};
    struct msghdr message = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = ancillary.bytes, .msg_controllen = sizeof(ancillary.bytes),
    };
    struct cmsghdr *control = CMSG_FIRSTHDR(&message);
    control->cmsg_level = SOL_SOCKET;
    control->cmsg_type = SCM_RIGHTS;
    control->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(control), &pipe_fds[0], sizeof(int));
    CHECK(sendmsg(sender, &message, 0) == 1);
    if (message_receive == 2) {
      /* The queued right is now the last reference to the stream endpoint.
       * A scalar datagram read discards it and delivers peer EOF. Authority
       * must already have been revoked by the preceding SCM_RIGHTS send. */
      CHECK(close(pipe_fds[0]) == 0);
      get_byte(receiver, 'd');
      expect_eof(pipe_fds[1]);
      CHECK(close(pipe_fds[1]) == 0);
      CHECK(close(sender) == 0 && close(receiver) == 0);
      CHECK(unlink(address.sun_path) == 0 && rmdir(directory) == 0);
      return;
    }
    memset(&ancillary, 0, sizeof(ancillary));
    byte = 0;
    CHECK(recvmsg(receiver, &message, 0) == 1 && byte == 'd');
    CHECK(!(message.msg_flags & MSG_CTRUNC));
    control = CMSG_FIRSTHDR(&message);
    CHECK(control && control->cmsg_level == SOL_SOCKET
          && control->cmsg_type == SCM_RIGHTS
          && control->cmsg_len == CMSG_LEN(sizeof(int)));
    int received;
    memcpy(&received, CMSG_DATA(control), sizeof(received));
    put_byte(pipe_fds[1], 'a');
    get_byte(received, 'a');
    CHECK(close(received) == 0);
    CHECK(close(pipe_fds[0]) == 0 && close(pipe_fds[1]) == 0);
  } else {
    put_byte(sender, 'd');
    get_byte(receiver, 'd');
  }
  CHECK(close(sender) == 0 && close(receiver) == 0);
  CHECK(unlink(address.sun_path) == 0 && rmdir(directory) == 0);
}

/* These real, unrelated producers precede the owned Unix wait. None may
 * permanently disable its idle parking, data wakeup, or EOF wakeup. */
static void socket_unrelated_prelude(void) {
  struct if_nameindex *interfaces = if_nameindex();
  CHECK(interfaces != NULL);
  int loopback = 0;
  for (struct if_nameindex *entry = interfaces; entry->if_index != 0; ++entry) {
    CHECK(entry->if_name != NULL);
    if (strcmp(entry->if_name, "lo") == 0)
      loopback = 1;
  }
  CHECK(loopback);
  if_freenameindex(interfaces);

  char directory[] = "/tmp/event-driven-copy-XXXXXX";
  CHECK(mkdtemp(directory) == directory);
  char source_path[128];
  char target_path[128];
  int length = snprintf(source_path, sizeof(source_path), "%s/source-XXXXXX",
                        directory);
  CHECK(length > 0 && (size_t)length < sizeof(source_path));
  length = snprintf(target_path, sizeof(target_path), "%s/target-XXXXXX",
                    directory);
  CHECK(length > 0 && (size_t)length < sizeof(target_path));
  int source = mkstemp(source_path);
  int target = mkstemp(target_path);
  CHECK(source >= 0 && target >= 0);
  const char file_payload[] = "unrelated regular-file sendfile payload";
  CHECK(write(source, file_payload, sizeof(file_payload)) ==
        (ssize_t)sizeof(file_payload));
  CHECK(lseek(source, 0, SEEK_SET) == 0);
  size_t copied = 0;
  while (copied < sizeof(file_payload)) {
    ssize_t count = sendfile(target, source, NULL, sizeof(file_payload) - copied);
    CHECK(count > 0);
    copied += (size_t)count;
  }
  CHECK(sendfile(target, source, NULL, sizeof(file_payload)) == 0);
  CHECK(lseek(target, 0, SEEK_SET) == 0);
  char file_received[sizeof(file_payload)];
  CHECK(read(target, file_received, sizeof(file_received)) ==
        (ssize_t)sizeof(file_received));
  CHECK(memcmp(file_received, file_payload, sizeof(file_payload)) == 0);
  expect_eof(target);
  CHECK(close(source) == 0);
  CHECK(close(target) == 0);
  CHECK(unlink(source_path) == 0);
  CHECK(unlink(target_path) == 0);
  CHECK(rmdir(directory) == 0);

  int receiver = socket(AF_INET, SOCK_DGRAM, 0);
  int sender = socket(AF_INET, SOCK_DGRAM, 0);
  CHECK(receiver >= 0 && sender >= 0);
  int enabled = 1;
  CHECK(setsockopt(sender, SOL_SOCKET, SO_BROADCAST, &enabled, sizeof(enabled)) == 0);
  CHECK(setsockopt(sender, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)) == 0);
  CHECK(setsockopt(receiver, IPPROTO_IP, IP_RECVERR, &enabled, sizeof(enabled)) == 0);
  int ipv6 = socket(AF_INET6, SOCK_DGRAM, 0);
  CHECK(ipv6 >= 0);
  CHECK(setsockopt(ipv6, IPPROTO_IPV6, IPV6_RECVERR, &enabled, sizeof(enabled)) == 0);
  enabled = 0;
  CHECK(setsockopt(sender, SOL_SOCKET, SO_BROADCAST, &enabled, sizeof(enabled)) == 0);
  CHECK(setsockopt(ipv6, IPPROTO_IPV6, IPV6_RECVERR, &enabled, sizeof(enabled)) == 0);
  CHECK(close(ipv6) == 0);
  struct sockaddr_in address = {
      .sin_family = AF_INET,
      .sin_port = 0,
      .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
  };
  CHECK(bind(receiver, (struct sockaddr *)&address, sizeof(address)) == 0);
  socklen_t address_length = sizeof(address);
  CHECK(getsockname(receiver, (struct sockaddr *)&address, &address_length) == 0);
  CHECK(address_length == sizeof(address));
  CHECK(address.sin_family == AF_INET && address.sin_port != 0);
  const char udp_payload[] = "unrelated IPv4 UDP payload";
  CHECK(sendto(sender, udp_payload, sizeof(udp_payload), 0,
               (struct sockaddr *)&address, address_length) ==
        (ssize_t)sizeof(udp_payload));
  char udp_received[sizeof(udp_payload) + 1];
  CHECK(recv(receiver, udp_received, sizeof(udp_received), 0) ==
        (ssize_t)sizeof(udp_payload));
  CHECK(memcmp(udp_received, udp_payload, sizeof(udp_payload)) == 0);
  CHECK(close(sender) == 0);
  CHECK(close(receiver) == 0);

  int transport[2], transferred[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, transport) == 0);
  make_pipe(transferred);
  char marker = 'p';
  struct iovec iov = {.iov_base = &marker, .iov_len = 1};
  union {
    struct cmsghdr alignment;
    char bytes[CMSG_SPACE(sizeof(int))];
  } ancillary = {0};
  struct msghdr message = {
      .msg_iov = &iov, .msg_iovlen = 1,
      .msg_control = ancillary.bytes, .msg_controllen = sizeof(ancillary.bytes),
  };
  struct cmsghdr *control = CMSG_FIRSTHDR(&message);
  CHECK(control != NULL);
  control->cmsg_level = SOL_SOCKET;
  control->cmsg_type = SCM_RIGHTS;
  control->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(control), &transferred[0], sizeof(int));
  CHECK(sendmsg(transport[0], &message, 0) == 1);
  memset(&ancillary, 0, sizeof(ancillary));
  marker = 0;
  CHECK(recvmsg(transport[1], &message, 0) == 1 && marker == 'p');
  CHECK((message.msg_flags & MSG_CTRUNC) == 0);
  control = CMSG_FIRSTHDR(&message);
  CHECK(control != NULL && control->cmsg_level == SOL_SOCKET
        && control->cmsg_type == SCM_RIGHTS
        && control->cmsg_len == CMSG_LEN(sizeof(int)));
  int received = -1;
  memcpy(&received, CMSG_DATA(control), sizeof(received));
  CHECK(received >= 0);
  put_byte(transferred[1], 'r');
  get_byte(received, 'r');
  CHECK(close(received) == 0);
  CHECK(close(transferred[0]) == 0);
  CHECK(close(transferred[1]) == 0);
  CHECK(close(transport[0]) == 0);
  CHECK(close(transport[1]) == 0);

  /* Go probes and uses MPTCP listeners. Their kernel transport is still
   * passive until a connection exists; no active-MPTCP authority is claimed. */
  int mptcp = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                     IPPROTO_MPTCP);
  if (mptcp >= 0) {
    struct sockaddr_in passive_address = {
        .sin_family = AF_INET, .sin_port = 0,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    CHECK(bind(mptcp, (struct sockaddr *)&passive_address, sizeof(passive_address)) == 0);
    CHECK(listen(mptcp, 1) == 0);
    CHECK(close(mptcp) == 0);
  } else {
    CHECK(errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT);
  }
  puts("socket: interface query, regular-file copy and UDP payload verified");
}

/* Keep the passive TCP listener present while Unix sockets carry the traffic,
 * as PostgreSQL does. The initial timeout must finish before any producer
 * exists; the later wake must come from connect/data, not child exit. */
static int tcp_listener(int unrelated) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  CHECK(fd >= 0);
  int reuse = 1;
  CHECK(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == 0);
  if (unrelated) {
    int tos = 0x10;
    int priority = 1;
    CHECK(setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == 0);
    CHECK(setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority)) == 0);
    const int options[][2] = {
        {TCP_MAXSEG, 1460}, {TCP_USER_TIMEOUT, 1000}, {TCP_SYNCNT, 3},
        {TCP_LINGER2, 60}, {TCP_WINDOW_CLAMP, 65535}, {TCP_QUICKACK, 1},
        {TCP_DEFER_ACCEPT, 1}, {TCP_INQ, 1},
    };
    for (size_t i = 0; i < sizeof(options) / sizeof(options[0]); ++i) {
      CHECK(setsockopt(fd, IPPROTO_TCP, options[i][0],
                      &options[i][1], sizeof(options[i][1])) == 0);
    }
    int receive_metadata = 1;
    CHECK(setsockopt(fd, IPPROTO_IP, IP_RECVTOS,
                    &receive_metadata, sizeof(receive_metadata)) == 0);
    CHECK(setsockopt(fd, IPPROTO_IP, IP_RECVTTL,
                    &receive_metadata, sizeof(receive_metadata)) == 0);
  }
  struct sockaddr_in address = {
      .sin_family = AF_INET,
      .sin_port = htons(unrelated ? 0 : 34917),
      .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
  };
  CHECK(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
  CHECK(listen(fd, 8) == 0);
  return fd;
}

static void socket_listener(int tcp, int abstract, int unrelated) {
  int passive = tcp_listener(unrelated);
  int listener = passive;
  char directory[] = "/tmp/event-driven-socket-XXXXXX";
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  socklen_t address_length = 0;
  if (!tcp) {
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    if (abstract) {
      int length = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                            "hermit-event-driven-%ld", (long)getpid());
      CHECK(length > 0 && (size_t)length < sizeof(address.sun_path) - 1);
      address_length = offsetof(struct sockaddr_un, sun_path) + 1 + length;
    } else {
      CHECK(mkdtemp(directory) == directory);
      int length = snprintf(address.sun_path, sizeof(address.sun_path),
                            "%s/listener", directory);
      CHECK(length > 0 && (size_t)length < sizeof(address.sun_path));
      address_length = offsetof(struct sockaddr_un, sun_path) + length + 1;
    }
    CHECK(bind(listener, (struct sockaddr *)&address, address_length) == 0);
    CHECK(listen(listener, 8) == 0);
  }
  int epoll = epoll_create1(0);
  CHECK(epoll >= 0);
  struct epoll_event interest = {.events = EPOLLIN, .data.u64 = 11};
  CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, listener, &interest) == 0);
  if (!tcp) {
    interest.data.u64 = 12;
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, passive, &interest) == 0);
  }
  struct epoll_event event;
  CHECK(epoll_wait(epoll, &event, 1, 200) == 0);
  int gate[2];
  make_pipe(gate);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(epoll) == 0);
    CHECK(close(listener) == 0);
    if (!tcp)
      CHECK(close(passive) == 0);
    CHECK(close(gate[1]) == 0);
    wait_for_consumer();
    int client = socket(tcp ? AF_INET : AF_UNIX, SOCK_STREAM, 0);
    CHECK(client >= 0);
    if (tcp) {
      struct sockaddr_in target = {
          .sin_family = AF_INET,
          .sin_port = htons(34917),
          .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
      };
      CHECK(connect(client, (struct sockaddr *)&target, sizeof(target)) == 0);
    } else {
      CHECK(connect(client, (struct sockaddr *)&address, address_length) == 0);
    }
    put_byte(client, 'n');
    get_byte(client, 'a');
    CHECK(shutdown(client, SHUT_WR) == 0);
    get_byte(gate[0], 'q');
    CHECK(close(client) == 0);
    _exit(0);
  }
  CHECK(close(gate[0]) == 0);
  CHECK(epoll_wait(epoll, &event, 1, -1) == 1);
  CHECK(event.data.u64 == 11 && (event.events & EPOLLIN));
  int connection = accept(listener, NULL, NULL);
  CHECK(connection >= 0);
  CHECK(epoll_ctl(epoll, EPOLL_CTL_DEL, listener, NULL) == 0);
  interest.events = EPOLLIN | EPOLLRDHUP;
  interest.data.u64 = 13;
  CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, connection, &interest) == 0);
  CHECK(epoll_wait(epoll, &event, 1, -1) == 1);
  CHECK(event.data.u64 == 13 && (event.events & EPOLLIN));
  get_byte(connection, 'n');
  put_byte(connection, 'a');
  CHECK(epoll_wait(epoll, &event, 1, -1) == 1);
  CHECK(event.data.u64 == 13 && (event.events & EPOLLIN));
  expect_eof(connection);
  put_byte(gate[1], 'q');
  joined(child);
  CHECK(close(gate[1]) == 0);
  CHECK(close(connection) == 0);
  CHECK(close(listener) == 0);
  if (!tcp)
    CHECK(close(passive) == 0);
  CHECK(close(epoll) == 0);
  if (!tcp && !abstract) {
    CHECK(unlink(address.sun_path) == 0);
    CHECK(rmdir(directory) == 0);
  }
  puts(tcp ? "socket: TCP producer wakes passive listener after idle"
           : "socket: Unix data and EOF wake with passive TCP listener");
}

/* Independent pathname connections, not socketpairs: one busy stream must not
 * repeatedly reschedule all the idle epoll consumers. Children acknowledge
 * half-close before exiting, so SIGCHLD cannot repair a missing EOF wake. */
static void socket_connection_groups(int failed_accept) {
  enum { COUNT = 32, ROUNDS = 16 };
  char directory[] = "/tmp/hermit-connection-groups-XXXXXX";
  CHECK(mkdtemp(directory) != NULL);
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  CHECK(snprintf(address.sun_path, sizeof(address.sun_path), "%s/socket", directory) > 0);
  int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
  CHECK(listener >= 0);
  CHECK(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
  CHECK(listen(listener, COUNT) == 0);
  CHECK(accept(listener, NULL, NULL) == -1 && errno == EAGAIN);
  int clients[COUNT], servers[COUNT], ready[2], release[2];
  pid_t children[COUNT];
  make_pipe(ready);
  make_pipe(release);
  for (int i = 0; i < COUNT; ++i) {
    clients[i] = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(clients[i] >= 0);
    CHECK(connect(clients[i], (struct sockaddr *)&address, sizeof(address)) == 0);
  }
  if (failed_accept) {
    /* Linux can dequeue before rejecting an unreadable output length. */
    CHECK(syscall(SYS_accept4, listener, &address, (void *)1, 0) == -1 && errno == EFAULT);
    CHECK(close(clients[0]) == 0);
    clients[0] = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(clients[0] >= 0);
    CHECK(connect(clients[0], (struct sockaddr *)&address, sizeof(address)) == 0);
  }
  for (int i = 0; i < COUNT; ++i) {
    int index = failed_accept ? (i + 1) % COUNT : i;
    servers[index] = accept(listener, NULL, NULL);
    CHECK(servers[index] >= 0);
  }
  for (int i = 0; i < COUNT; ++i) {
    children[i] = fork();
    CHECK(children[i] >= 0);
    if (children[i] == 0) {
      CHECK(close(listener) == 0);
      CHECK(close(ready[0]) == 0);
      CHECK(close(release[1]) == 0);
      for (int j = 0; j < COUNT; ++j) {
        CHECK(close(clients[j]) == 0);
        if (j != i)
          CHECK(close(servers[j]) == 0);
      }
      int connection = dup(servers[i]);
      CHECK(connection >= 0 && close(servers[i]) == 0);
      int epoll = epoll_create1(EPOLL_CLOEXEC);
      CHECK(epoll >= 0);
      struct epoll_event interest = {.events = EPOLLIN | EPOLLRDHUP | EPOLLET};
      CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, connection, &interest) == 0);
      put_byte(ready[1], 'r');
      for (int round = 0; round < (i == 0 ? ROUNDS : 0); ++round) {
        struct epoll_event event;
        CHECK(epoll_wait(epoll, &event, 1, -1) == 1);
        get_byte(connection, 'd');
        put_byte(connection, 'a');
      }
      struct epoll_event event;
      CHECK(epoll_wait(epoll, &event, 1, -1) == 1);
      expect_eof(connection);
      put_byte(connection, 'e');
      get_byte(release[0], 'q');
      _exit(0);
    }
  }
  CHECK(close(ready[1]) == 0 && close(release[0]) == 0);
  for (int i = 0; i < COUNT; ++i) {
    CHECK(close(servers[i]) == 0);
    get_byte(ready[0], 'r');
  }
  for (int round = 0; round < ROUNDS; ++round) {
    wait_for_consumer();
    put_byte(clients[0], 'd');
    get_byte(clients[0], 'a');
  }
  for (int i = 0; i < COUNT; ++i) {
    CHECK(shutdown(clients[i], SHUT_WR) == 0);
    get_byte(clients[i], 'e');
  }
  for (int i = 0; i < COUNT; ++i)
    put_byte(release[1], 'q');
  for (int i = 0; i < COUNT; ++i) {
    joined(children[i]);
    CHECK(close(clients[i]) == 0);
  }
  CHECK(close(listener) == 0 && close(ready[0]) == 0 && close(release[1]) == 0);
  CHECK(unlink(address.sun_path) == 0 && rmdir(directory) == 0);
}

static void socketpair_alias(void) {
  int pair[2];
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
  int alias = dup(pair[1]);
  CHECK(alias >= 0);
  CHECK(close(pair[1]) == 0);
  int gate[2];
  make_pipe(gate);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(pair[0]) == 0);
    CHECK(close(gate[1]) == 0);
    wait_for_consumer();
    put_byte(alias, 's');
    get_byte(alias, 'a');
    CHECK(shutdown(alias, SHUT_WR) == 0);
    get_byte(gate[0], 'q');
    CHECK(close(alias) == 0);
    _exit(0);
  }
  CHECK(close(alias) == 0);
  CHECK(close(gate[0]) == 0);
  get_byte(pair[0], 's');
  put_byte(pair[0], 'a');
  expect_eof(pair[0]);
  put_byte(gate[1], 'q');
  joined(child);
  CHECK(close(pair[0]) == 0);
  CHECK(close(gate[1]) == 0);
  puts("socketpair: forked alias data and shutdown wake before child exit");
}

static void timerfd_set_delay(int fd, time_t seconds, long nanoseconds) {
  struct itimerspec setting = {
      .it_value = {.tv_sec = seconds, .tv_nsec = nanoseconds}};
  CHECK(timerfd_settime(fd, 0, &setting, NULL) == 0);
}

static void timerfd_pause(void) {
  struct timespec pause = {.tv_nsec = 20000000};
  CHECK(nanosleep(&pause, NULL) == 0);
}

static void timerfd_check_elapsed(struct timespec start) {
  struct timespec end;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
  int64_t elapsed = (int64_t)(end.tv_sec - start.tv_sec) * 1000000000
      + end.tv_nsec - start.tv_nsec;
  CHECK(elapsed >= 0);
  /* Native dispatch latency is not bounded. Hermit's virtual deadline must
   * follow the new short setting, not rescue the wait at the old hour. */
  if (getenv("HERMIT_TEST_TIMER_DEADLINE") != NULL) {
    CHECK(elapsed < 1000000000);
  }
}

static void timerfd_arm_rearm(void) {
  int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  CHECK(fd >= 0);
  int alias = dup(fd);
  CHECK(alias >= 0);
  int inner = epoll_create1(0), outer = epoll_create1(0);
  CHECK(inner >= 0 && outer >= 0);
  struct epoll_event interest = {.events = EPOLLIN, .data.u64 = 17};
  CHECK(epoll_ctl(inner, EPOLL_CTL_ADD, fd, &interest) == 0);
  interest.data.u64 = 23;
  CHECK(epoll_ctl(outer, EPOLL_CTL_ADD, inner, &interest) == 0);
  int ready[2], done[2], release[2];
  make_pipe(ready);
  make_pipe(done);
  make_pipe(release);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    CHECK(close(fd) == 0); /* The epoll interest survives through alias. */
    for (int phase = 0; phase != 4; ++phase) {
      struct timespec start;
      CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
      put_byte(ready[1], 'r');
      if (phase % 2 == 0) {
        struct pollfd item = {.fd = alias, .events = POLLIN};
        CHECK(poll(&item, 1, -1) == 1 && item.revents == POLLIN);
      } else {
        struct epoll_event event;
        CHECK(epoll_wait(outer, &event, 1, -1) == 1);
        CHECK(event.events == EPOLLIN && event.data.u64 == 23);
        CHECK(epoll_wait(inner, &event, 1, 0) == 1);
        CHECK(event.events == EPOLLIN && event.data.u64 == 17);
      }
      CHECK(get_count(alias) == 1);
      expect_poll(alias, POLLIN, 0);
      timerfd_check_elapsed(start);
      put_byte(done[1], 'd');
    }
    get_byte(release[0], 'q');
    _exit(0);
  }
  CHECK(close(alias) == 0);
  for (int phase = 0; phase != 4; ++phase) {
    get_byte(ready[0], 'r');
    if (phase != 0) {
      timerfd_set_delay(fd, 3600, 0);
    }
    timerfd_pause();
    if (phase == 2) {
      timerfd_set_delay(fd, 0, 0);
      timerfd_pause();
    }
    if (phase == 3) {
      struct itimerspec setting = {.it_value = {.tv_nsec = 5000000}};
      errno = 0;
      CHECK(syscall(SYS_timerfd_settime, fd, 0, &setting, (void*)1) == -1);
      CHECK(errno == EFAULT); /* Setting takes effect before old-value copyout. */
    } else {
      timerfd_set_delay(fd, 0, 5000000);
    }
    get_byte(done[0], 'd');
  }
  put_byte(release[1], 'q');
  joined(child);
  CHECK(close(fd) == 0);
  CHECK(close(inner) == 0 && close(outer) == 0);
  puts("timerfd: arm, shorten, disarm and faulted old-value update wake aliases");
}

struct timerfd_reader_args {
  int timer;
  int ready;
  int done;
  int release;
};

static void* timerfd_reader(void* opaque) {
  struct timerfd_reader_args* args = opaque;
  put_byte(args->ready, 'r');
  CHECK(get_count(args->timer) == 1);
  put_byte(args->done, 'd');
  get_byte(args->release, 'q');
  return NULL;
}

static void timerfd_shared_drain(void) {
  int fd = timerfd_create(CLOCK_MONOTONIC, 0);
  CHECK(fd >= 0);
  int ready[2], done[2], release[2];
  make_pipe(ready);
  make_pipe(done);
  make_pipe(release);
  struct timerfd_reader_args args = {
      .timer = fd, .ready = ready[1], .done = done[1], .release = release[0]};
  pthread_t readers[2];
  CHECK(pthread_create(&readers[0], NULL, timerfd_reader, &args) == 0);
  CHECK(pthread_create(&readers[1], NULL, timerfd_reader, &args) == 0);
  get_byte(ready[0], 'r');
  get_byte(ready[0], 'r');
  timerfd_set_delay(fd, 0, 5000000);
  get_byte(done[0], 'd');
  expect_poll(done[0], POLLIN, 0); /* One expiration cannot satisfy both reads. */
  timerfd_set_delay(fd, 0, 5000000);
  get_byte(done[0], 'd');
  put_byte(release[1], 'q');
  put_byte(release[1], 'q');
  CHECK(pthread_join(readers[0], NULL) == 0);
  CHECK(pthread_join(readers[1], NULL) == 0);
  expect_poll(fd, POLLIN, 0);
  CHECK(close(fd) == 0);
  puts("timerfd: shared readers consume each expiration once before exit");
}

static void timerfd_foreign_epoll_case(int add_after_fork) {
  int epoll = epoll_create1(0);
  CHECK(epoll >= 0);
  int fd = -1;
  struct epoll_event interest = {.events = EPOLLIN, .data.u64 = 29};
  if (!add_after_fork) {
    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    CHECK(fd >= 0 && epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &interest) == 0);
  }
  int ready[2], done[2], release[2];
  make_pipe(ready);
  make_pipe(done);
  make_pipe(release);
  pid_t child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    if (fd >= 0) {
      CHECK(close(fd) == 0);
    }
    put_byte(ready[1], 'r');
    struct epoll_event event;
    CHECK(epoll_wait(epoll, &event, 1, -1) == 1);
    CHECK(event.events == EPOLLIN && event.data.u64 == 29);
    put_byte(done[1], 'd');
    get_byte(release[0], 'q');
    _exit(0);
  }
  get_byte(ready[0], 'r');
  if (add_after_fork) {
    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    CHECK(fd >= 0 && epoll_ctl(epoll, EPOLL_CTL_ADD, fd, &interest) == 0);
  }
  timerfd_set_delay(fd, 0, 5000000);
  timerfd_pause();
  /* The waiter has no physical timer descriptor. Its owner explicitly
   * publishes readiness; the epoll graph alone is not publication authority. */
  expect_poll(fd, POLLIN, POLLIN);
  get_byte(done[0], 'd');
  CHECK(get_count(fd) == 1);
  put_byte(release[1], 'q');
  joined(child);
  CHECK(close(fd) == 0 && close(epoll) == 0);
}

static void timerfd_foreign_epoll(void) {
  timerfd_foreign_epoll_case(0);
  timerfd_foreign_epoll_case(1);
  puts("timerfd: foreign-held epoll interests wait for owner publication");
}

static int64_t timerfd_monotonic_ns(void) {
  struct timespec now;
  CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
  return (int64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

static void timerfd_copyout_faults(void) {
  int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  CHECK(fd >= 0);
  for (int phase = 0; phase != 3; ++phase) {
    timerfd_set_delay(fd, 0, 5000000);
    struct pollfd item = {.fd = fd, .events = POLLIN};
    CHECK(poll(&item, 1, -1) == 1 && item.revents == POLLIN);
    struct iovec vector = {.iov_base = (void*)1, .iov_len = sizeof(uint64_t)};
    errno = 0;
    if (phase == 0) {
      CHECK(syscall(SYS_read, fd, (void*)1, sizeof(uint64_t)) == -1);
    } else if (phase == 1) {
      CHECK(syscall(SYS_readv, fd, (void*)1, 1) == -1);
    } else {
      CHECK(syscall(SYS_readv, fd, &vector, 1) == -1);
    }
    CHECK(errno == EFAULT);
    if (phase == 1) {
      expect_poll(fd, POLLIN, POLLIN); /* Invalid iovec: no timer read occurred. */
      CHECK(get_count(fd) == 1);
    } else {
      expect_poll(fd, POLLIN, 0); /* Copyout failed after consuming the tick. */
      uint64_t value = 0;
      errno = 0;
      CHECK(read(fd, &value, sizeof(value)) == -1 && errno == EAGAIN);
    }
  }
  for (int vectored = 0; vectored != 2; ++vectored) {
    const int64_t interval = 100000000;
    struct itimerspec setting = {
        .it_value = {.tv_nsec = 5000000}, .it_interval = {.tv_nsec = interval}};
    CHECK(timerfd_settime(fd, 0, &setting, NULL) == 0);
    struct pollfd item = {.fd = fd, .events = POLLIN};
    CHECK(poll(&item, 1, -1) == 1 && item.revents == POLLIN);
    struct iovec vector = {.iov_base = (void*)1, .iov_len = sizeof(uint64_t)};
    errno = 0;
    if (vectored) {
      CHECK(syscall(SYS_readv, fd, &vector, 1) == -1);
    } else {
      CHECK(syscall(SYS_read, fd, (void*)1, sizeof(uint64_t)) == -1);
    }
    CHECK(errno == EFAULT);
    /* Do not reset the setting: a stale unread tick would contaminate the
     * next period. Bracket its deadline and read to tolerate native dispatch
     * delays without assuming that precisely one host period has elapsed. */
    struct itimerspec remaining;
    int64_t before = timerfd_monotonic_ns();
    CHECK(timerfd_gettime(fd, &remaining) == 0);
    int64_t after = timerfd_monotonic_ns();
    CHECK(remaining.it_interval.tv_sec == 0
        && remaining.it_interval.tv_nsec == interval);
    CHECK(poll(&item, 1, -1) == 1 && item.revents == POLLIN);
    int64_t read_before = timerfd_monotonic_ns();
    uint64_t count = get_count(fd);
    int64_t read_after = timerfd_monotonic_ns();
    int64_t until = (int64_t)remaining.it_value.tv_sec * 1000000000
        + remaining.it_value.tv_nsec;
    int64_t lower_elapsed = read_before - (after + until);
    int64_t upper_elapsed = read_after - (before + until);
    uint64_t minimum = lower_elapsed < 0 ? 0 : lower_elapsed / interval + 1;
    uint64_t maximum = upper_elapsed < 0 ? 0 : upper_elapsed / interval + 1;
    CHECK(count > 0 && count >= minimum && count <= maximum);
  }
  CHECK(close(fd) == 0);
  puts("timerfd: read and readv distinguish faults before and after consumption");
}

static void timerfd_masked_signal(void) {
  struct sigaction action = {.sa_handler = on_signal};
  CHECK(sigemptyset(&action.sa_mask) == 0);
  CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
  sigset_t blocked, previous, empty, actual;
  CHECK(sigemptyset(&blocked) == 0 && sigaddset(&blocked, SIGUSR1) == 0);
  CHECK(sigemptyset(&empty) == 0);
  CHECK(pthread_sigmask(SIG_BLOCK, &blocked, &previous) == 0);
  int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  CHECK(fd >= 0);
  int gate[2];
  make_pipe(gate);
  pid_t parent = getpid(), child = fork();
  CHECK(child >= 0);
  if (child == 0) {
    get_byte(gate[0], 's');
    CHECK(kill(parent, SIGUSR1) == 0);
    get_byte(gate[0], 'a');
    timerfd_set_delay(fd, 0, 5000000);
    get_byte(gate[0], 'q');
    _exit(0);
  }
  put_byte(gate[1], 's');
  struct pollfd item = {.fd = fd, .events = POLLIN};
  errno = 0;
  CHECK(ppoll(&item, 1, NULL, &empty) == -1 && errno == EINTR);
  CHECK(signals_seen == 1);
  CHECK(pthread_sigmask(SIG_SETMASK, NULL, &actual) == 0);
  CHECK(sigismember(&actual, SIGUSR1) == 1);
  put_byte(gate[1], 'a');
  item.revents = 0;
  CHECK(ppoll(&item, 1, NULL, &blocked) == 1 && item.revents == POLLIN);
  CHECK(get_count(fd) == 1);
  CHECK(pthread_sigmask(SIG_SETMASK, NULL, &actual) == 0);
  CHECK(sigismember(&actual, SIGUSR1) == 1);
  put_byte(gate[1], 'q');
  joined(child);
  CHECK(pthread_sigmask(SIG_SETMASK, &previous, NULL) == 0);
  CHECK(close(fd) == 0);
  puts("timerfd: temporary signal masks interrupt and restore before readiness");
}

int main(int argc, char** argv) {
  CHECK(argc >= 2);
  if (strcmp(argv[1], "exec-child") == 0) {
    CHECK(argc == 5);
    errno = 0;
    CHECK(fcntl(atoi(argv[4]), F_GETFD) == -1 && errno == EBADF);
    put_byte(atoi(argv[2]), 'x');
    get_byte(atoi(argv[3]), 'q');
    return 0;
  }
  if (strcmp(argv[1], "exec-producer") == 0) {
    CHECK(argc == 6);
    lifecycle_producer(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
    return 0;
  }
  CHECK(argc == 2);
  if (strcmp(argv[1], "eventfd-normal") == 0) {
    eventfd_consumer(0);
  } else if (strcmp(argv[1], "eventfd-semaphore") == 0) {
    eventfd_consumer(1);
  } else if (strcmp(argv[1], "eventfd-producer") == 0) {
    eventfd_producer(0);
  } else if (strcmp(argv[1], "eventfd-semaphore-producer") == 0) {
    eventfd_producer(1);
  } else if (strcmp(argv[1], "eventfd-waiters") == 0) {
    eventfd_waiters();
  } else if (strcmp(argv[1], "eventfd-thread-exit") == 0) {
    eventfd_thread_exit();
  } else if (strcmp(argv[1], "exec-surviving-aliases") == 0) {
    lifecycle_exec(1);
  } else if (strcmp(argv[1], "failed-exec-producer") == 0) {
    lifecycle_exec(0);
  } else if (strcmp(argv[1], "pipe-exit") == 0) {
    pipe_exit(0);
  } else if (strcmp(argv[1], "pipe-last-thread-exit") == 0) {
    pipe_exit(1);
  } else if (strcmp(argv[1], "pipe-cloexec") == 0) {
    pipe_cloexec();
  } else if (strcmp(argv[1], "pipe-capacity") == 0) {
    pipe_capacity();
  } else if (strcmp(argv[1], "pipe-close-lifetime") == 0) {
    pipe_close_lifetime(0, 0);
  } else if (strcmp(argv[1], "pipe-close-range-lifetime") == 0) {
    pipe_close_lifetime(1, 0);
  } else if (strcmp(argv[1], "pipe-close-replace-lifetime") == 0) {
    pipe_close_lifetime(2, 0);
  } else if (strcmp(argv[1], "pipe-close-reopened-lifetime") == 0) {
    pipe_close_lifetime(0, 1);
  } else if (strcmp(argv[1], "pipe-close-no-witness") == 0) {
    pipe_close_lifetime(3, 0);
  } else if (strcmp(argv[1], "pipe-shared-bindings") == 0) {
    pipe_shared_bindings();
  } else if (strcmp(argv[1], "timerfd-arm-rearm") == 0) {
    timerfd_arm_rearm();
  } else if (strcmp(argv[1], "timerfd-shared-drain") == 0) {
    timerfd_shared_drain();
  } else if (strcmp(argv[1], "timerfd-foreign-epoll") == 0) {
    timerfd_foreign_epoll();
  } else if (strcmp(argv[1], "timerfd-copyout-faults") == 0) {
    timerfd_copyout_faults();
  } else if (strcmp(argv[1], "timerfd-masked-signal") == 0) {
    timerfd_masked_signal();
  } else if (strcmp(argv[1], "poll-timeout") == 0) {
    poll_timeout();
  } else if (strcmp(argv[1], "masked-ppoll-signal-fallback") == 0) {
    masked_ppoll_signal_fallback();
  } else if (strcmp(argv[1], "poll-signal") == 0) {
    parked_signal(1, SIGUSR1);
  } else if (strcmp(argv[1], "eventfd-read-signal") == 0) {
    parked_signal(0, SIGUSR1);
  } else if (strcmp(argv[1], "eventfd-read-private-sigchld") == 0) {
    parked_signal(0, SIGCHLD);
  } else if (strcmp(argv[1], "poll-private-sigchld") == 0) {
    parked_signal(1, SIGCHLD);
  } else if (strcmp(argv[1], "poll-child-gate") == 0) {
    poll_child_gate();
  } else if (strcmp(argv[1], "epoll-rearm") == 0) {
    epoll_rearm();
  } else if (strcmp(argv[1], "epoll-nested") == 0) {
    epoll_nested();
  } else if (strcmp(argv[1], "epoll-alias-reuse") == 0) {
    epoll_alias_reuse();
  } else if (strcmp(argv[1], "signalfd-poll-shared") == 0) {
    signalfd_poll_queue(SIGUSR1);
  } else if (strcmp(argv[1], "signalfd-poll-private") == 0) {
    signalfd_poll_private();
  } else if (strcmp(argv[1], "signalfd-epoll-pipe") == 0) {
    signalfd_epoll_pipe();
  } else if (strcmp(argv[1], "signalfd-mask-alias") == 0) {
    signalfd_mask_alias();
  } else if (strcmp(argv[1], "signalfd-timeout") == 0) {
    signalfd_timeout();
  } else if (strcmp(argv[1], "signalfd-epoll-inherited") == 0) {
    signalfd_epoll_child(0);
  } else if (strcmp(argv[1], "signalfd-epoll-fresh-child") == 0) {
    signalfd_epoll_child(1);
  } else if (strcmp(argv[1], "signalfd-sigchld-fallback") == 0) {
    signalfd_poll_queue(SIGCHLD);
  } else if (strcmp(argv[1], "socket-unix-path") == 0) {
    socket_listener(0, 0, 0);
  } else if (strcmp(argv[1], "socket-unix-abstract") == 0) {
    socket_listener(0, 1, 0);
  } else if (strcmp(argv[1], "socket-tcp-revoke") == 0) {
    socket_listener(1, 0, 0);
  } else if (strcmp(argv[1], "socketpair-alias") == 0) {
    socketpair_alias();
  } else if (strcmp(argv[1], "socket-connection-groups") == 0) {
    socket_connection_groups(0);
  } else if (strcmp(argv[1], "socket-accept-error-groups") == 0) {
    socket_connection_groups(1);
  } else if (strcmp(argv[1], "socket-unrelated-producers") == 0) {
    socket_unrelated_prelude();
    socket_route_prelude(0);
    socket_rights_prelude(0);
    socket_unix_datagram_prelude(0);
    socket_listener(0, 0, 1);
  } else if (strcmp(argv[1], "socket-udp-unknown-option") == 0) {
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(udp >= 0);
    int enabled = 1;
    errno = 0;
    CHECK(setsockopt(udp, IPPROTO_IP, -1, &enabled, sizeof(enabled)) == -1);
    CHECK(errno == ENOPROTOOPT);
    CHECK(close(udp) == 0);
    /* Even a rejected unknown option remains fail-closed. Real Unix
     * accept/data/EOF must still work via polling after revocation. */
    socket_listener(0, 0, 1);
  } else if (strcmp(argv[1], "socket-route-mutation-fallback") == 0) {
    socket_route_prelude(1);
    socket_listener(0, 0, 1);
  } else if (strcmp(argv[1], "socket-rights-regular") == 0) {
    socket_rights_prelude(0);
    socket_listener(0, 0, 0);
  } else if (strcmp(argv[1], "socket-rights-socket-fallback") == 0) {
    socket_rights_prelude(1);
    socket_listener(0, 0, 1);
  } else if (strcmp(argv[1], "socket-datagram-message-fallback") == 0) {
    socket_unix_datagram_prelude(1);
    socket_listener(0, 0, 1);
  } else if (strcmp(argv[1], "socket-datagram-discard-fallback") == 0) {
    socket_unix_datagram_prelude(2);
    socket_listener(0, 0, 1);
  } else {
    CHECK(!"unknown scenario");
  }
  printf("%s success\n", argv[1]);
  return 0;
}
