/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

#define ARRAY_SIZE(values) (sizeof(values) / sizeof((values)[0]))

static void fail(const char* message) {
  fprintf(stderr, "%s\n", message);
  exit(1);
}

static void fail_errno(const char* operation) {
  fprintf(stderr, "%s failed: %s\n", operation, strerror(errno));
  exit(1);
}

static int create_epoll(void) {
  const int fd = epoll_create1(EPOLL_CLOEXEC);
  if (fd < 0) {
    fail_errno("epoll_create1");
  }
  return fd;
}

static void create_pipe(int pipefd[2]) {
  if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) != 0) {
    fail_errno("pipe2");
  }
}

static void
control_fd(int epoll_fd, int operation, int fd, uint32_t events, uint64_t tag) {
  struct epoll_event event = {
      .events = events,
      .data.u64 = tag,
  };
  if (epoll_ctl(epoll_fd, operation, fd, &event) != 0) {
    fail_errno("epoll_ctl");
  }
}

static void write_byte(int fd, char byte) {
  if (write(fd, &byte, sizeof(byte)) != sizeof(byte)) {
    fail_errno("write");
  }
}

static void read_exact(int fd, void* buffer, size_t length) {
  const ssize_t result = read(fd, buffer, length);
  if (result < 0) {
    fail_errno("read");
  }
  if ((size_t)result != length) {
    fail("read returned an unexpected byte count");
  }
}

static void wait_until_readable(int fd, const char* label) {
  struct pollfd poll_fd = {
      .fd = fd,
      .events = POLLIN,
  };
  const int count = poll(&poll_fd, 1, 1000);
  if (count < 0) {
    fail_errno("poll");
  }
  if (count != 1 || (poll_fd.revents & POLLIN) == 0) {
    fail(label);
  }
}

static void expect_no_events(int epoll_fd, const char* label) {
  struct epoll_event event;
  const int count = epoll_wait(epoll_fd, &event, 1, 0);
  if (count < 0) {
    fail_errno("epoll_wait");
  }
  if (count != 0) {
    fail("epoll_wait returned an event while delivery should be disabled");
  }
  printf("%s none\n", label);
}

static void expect_events(
    int epoll_fd,
    const char* label,
    const uint64_t* expected_tags,
    size_t expected_count) {
  struct epoll_event events[8];
  if (expected_count > ARRAY_SIZE(events)) {
    fail("test requested too many epoll events");
  }

  const int count = epoll_wait(epoll_fd, events, (int)expected_count, 1000);
  if (count < 0) {
    fail_errno("epoll_wait");
  }
  if ((size_t)count != expected_count) {
    fprintf(
        stderr,
        "%s returned %d events, expected %zu\n",
        label,
        count,
        expected_count);
    exit(1);
  }

  bool seen[8] = {false};
  printf("%s", label);
  for (size_t event_index = 0; event_index < expected_count; ++event_index) {
    if ((events[event_index].events & EPOLLIN) == 0) {
      fail("epoll event did not contain EPOLLIN");
    }

    bool matched = false;
    for (size_t tag_index = 0; tag_index < expected_count; ++tag_index) {
      const bool same_tag =
          events[event_index].data.u64 == expected_tags[tag_index];
      if (!seen[tag_index] && same_tag) {
        seen[tag_index] = true;
        matched = true;
        break;
      }
    }
    if (!matched) {
      fail("epoll returned an unknown or duplicate tag");
    }

    printf(
        "%s%llu:0x%x",
        event_index == 0 ? " order=" : ",",
        (unsigned long long)events[event_index].data.u64,
        events[event_index].events);
  }
  putchar('\n');
}

static void run_multi(void) {
  const int epoll_fd = create_epoll();
  int pipes[3][2];
  const uint64_t tags[] = {11, 22, 33};

  for (size_t index = 0; index < ARRAY_SIZE(pipes); ++index) {
    create_pipe(pipes[index]);
    control_fd(epoll_fd, EPOLL_CTL_ADD, pipes[index][0], EPOLLIN, tags[index]);
  }

  write_byte(pipes[2][1], 'c');
  write_byte(pipes[0][1], 'a');
  write_byte(pipes[1][1], 'b');
  expect_events(epoll_fd, "multi-ready", tags, ARRAY_SIZE(tags));

  for (size_t index = 0; index < ARRAY_SIZE(pipes); ++index) {
    char byte;
    read_exact(pipes[index][0], &byte, sizeof(byte));
    close(pipes[index][0]);
    close(pipes[index][1]);
  }
  close(epoll_fd);
}

static void run_edge(void) {
  const int epoll_fd = create_epoll();
  int pipefd[2];
  const uint64_t tag = 101;
  create_pipe(pipefd);
  control_fd(epoll_fd, EPOLL_CTL_ADD, pipefd[0], EPOLLIN | EPOLLET, tag);

  write_byte(pipefd[1], 'a');
  write_byte(pipefd[1], 'b');
  expect_events(epoll_fd, "edge-first", &tag, 1);
  expect_no_events(epoll_fd, "edge-undrained");

  char bytes[2];
  read_exact(pipefd[0], bytes, sizeof(bytes));
  write_byte(pipefd[1], 'c');
  expect_events(epoll_fd, "edge-after-drain", &tag, 1);
  read_exact(pipefd[0], bytes, 1);

  close(pipefd[0]);
  close(pipefd[1]);
  close(epoll_fd);
}

static void run_oneshot(void) {
  const int epoll_fd = create_epoll();
  int pipefd[2];
  const uint64_t tag = 102;
  create_pipe(pipefd);
  control_fd(epoll_fd, EPOLL_CTL_ADD, pipefd[0], EPOLLIN | EPOLLONESHOT, tag);

  write_byte(pipefd[1], 'a');
  expect_events(epoll_fd, "oneshot-first", &tag, 1);
  write_byte(pipefd[1], 'b');
  expect_no_events(epoll_fd, "oneshot-disabled");

  control_fd(epoll_fd, EPOLL_CTL_MOD, pipefd[0], EPOLLIN | EPOLLONESHOT, tag);
  expect_events(epoll_fd, "oneshot-rearmed", &tag, 1);
  char bytes[2];
  read_exact(pipefd[0], bytes, sizeof(bytes));

  close(pipefd[0]);
  close(pipefd[1]);
  close(epoll_fd);
}

static void run_mixed(void) {
  sigset_t signal_mask;
  sigemptyset(&signal_mask);
  sigaddset(&signal_mask, SIGUSR1);
  if (sigprocmask(SIG_BLOCK, &signal_mask, NULL) != 0) {
    fail_errno("sigprocmask");
  }

  const int signal_fd = signalfd(-1, &signal_mask, SFD_CLOEXEC | SFD_NONBLOCK);
  if (signal_fd < 0) {
    fail_errno("signalfd");
  }
  const int timer_fd =
      timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
  if (timer_fd < 0) {
    fail_errno("timerfd_create");
  }
  int pipefd[2];
  create_pipe(pipefd);
  int sockets[2];
  const int socket_type = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;
  if (socketpair(AF_UNIX, socket_type, 0, sockets) != 0) {
    fail_errno("socketpair");
  }

  const int epoll_fd = create_epoll();
  const uint64_t tags[] = {201, 202, 203, 204};
  control_fd(epoll_fd, EPOLL_CTL_ADD, pipefd[0], EPOLLIN, tags[0]);
  control_fd(epoll_fd, EPOLL_CTL_ADD, sockets[0], EPOLLIN, tags[1]);
  control_fd(epoll_fd, EPOLL_CTL_ADD, timer_fd, EPOLLIN, tags[2]);
  control_fd(epoll_fd, EPOLL_CTL_ADD, signal_fd, EPOLLIN, tags[3]);

  write_byte(sockets[1], 's');
  if (kill(getpid(), SIGUSR1) != 0) {
    fail_errno("kill");
  }
  write_byte(pipefd[1], 'p');
  const struct itimerspec timer = {
      .it_value =
          {
              .tv_sec = 1,
              .tv_nsec = 0,
          },
  };
  if (timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &timer, NULL) != 0) {
    fail_errno("timerfd_settime");
  }

  wait_until_readable(timer_fd, "timerfd did not become readable");
  wait_until_readable(signal_fd, "signalfd did not become readable");
  expect_events(epoll_fd, "mixed-ready", tags, ARRAY_SIZE(tags));

  char byte;
  read_exact(sockets[0], &byte, sizeof(byte));
  read_exact(pipefd[0], &byte, sizeof(byte));
  uint64_t expirations;
  read_exact(timer_fd, &expirations, sizeof(expirations));
  struct signalfd_siginfo signal_info;
  read_exact(signal_fd, &signal_info, sizeof(signal_info));
  if (signal_info.ssi_signo != SIGUSR1) {
    fail("signalfd returned the wrong signal");
  }

  close(sockets[0]);
  close(sockets[1]);
  close(pipefd[0]);
  close(pipefd[1]);
  close(timer_fd);
  close(signal_fd);
  close(epoll_fd);
}

static void run_nested(void) {
  const int inner_epoll = create_epoll();
  const int outer_epoll = create_epoll();
  int pipefd[2];
  create_pipe(pipefd);

  const uint64_t pipe_tag = 301;
  const uint64_t nested_tag = 302;
  control_fd(inner_epoll, EPOLL_CTL_ADD, pipefd[0], EPOLLIN, pipe_tag);
  control_fd(outer_epoll, EPOLL_CTL_ADD, inner_epoll, EPOLLIN, nested_tag);

  write_byte(pipefd[1], 'n');
  expect_events(outer_epoll, "nested-outer", &nested_tag, 1);
  expect_events(inner_epoll, "nested-inner", &pipe_tag, 1);

  char byte;
  read_exact(pipefd[0], &byte, sizeof(byte));
  close(pipefd[0]);
  close(pipefd[1]);
  close(outer_epoll);
  close(inner_epoll);
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#549)
static void
expect_notification_flags(int fd, const char* label, bool expect_nonblocking) {
  const int descriptor_flags = fcntl(fd, F_GETFD);
  if (descriptor_flags < 0) {
    fail_errno("fcntl(F_GETFD) on notification fd");
  }
  const int status_flags = fcntl(fd, F_GETFL);
  if (status_flags < 0) {
    fail_errno("fcntl(F_GETFL) on notification fd");
  }
  const bool is_nonblocking = (status_flags & O_NONBLOCK) != 0;
  if ((descriptor_flags & FD_CLOEXEC) == 0 ||
      is_nonblocking != expect_nonblocking) {
    fprintf(stderr, "%s exposed incorrect CLOEXEC/NONBLOCK flags\n", label);
    exit(1);
  }
}

static void run_control_fds(void) {
  const int event_fd = eventfd(2, EFD_CLOEXEC | EFD_NONBLOCK);
  if (event_fd < 0) {
    fail_errno("eventfd");
  }
  const int blocking_event_fd = eventfd(1, EFD_CLOEXEC);
  if (blocking_event_fd < 0) {
    fail_errno("blocking eventfd");
  }
  const int timer_fd =
      timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
  if (timer_fd < 0) {
    fail_errno("timerfd_create");
  }
  expect_notification_flags(event_fd, "eventfd", true);
  expect_notification_flags(blocking_event_fd, "blocking eventfd", false);
  expect_notification_flags(timer_fd, "timerfd", true);

  const int epoll_fd = create_epoll();
  const uint64_t add_tag = 401;
  const uint64_t timer_tag = 402;
  const uint64_t modified_tag = 403;
  const uint64_t blocking_tag = 404;
  const uint64_t add_tags[] = {add_tag, blocking_tag};
  const uint64_t modified_tags[] = {modified_tag, blocking_tag};
  control_fd(epoll_fd, EPOLL_CTL_ADD, event_fd, EPOLLIN, add_tag);
  control_fd(epoll_fd, EPOLL_CTL_ADD, blocking_event_fd, EPOLLIN, blocking_tag);
  control_fd(epoll_fd, EPOLL_CTL_ADD, timer_fd, EPOLLIN, timer_tag);
  expect_events(epoll_fd, "control-add", add_tags, ARRAY_SIZE(add_tags));

  control_fd(epoll_fd, EPOLL_CTL_MOD, event_fd, EPOLLIN, modified_tag);
  expect_events(
      epoll_fd, "control-mod", modified_tags, ARRAY_SIZE(modified_tags));

  uint64_t counter;
  read_exact(event_fd, &counter, sizeof(counter));
  if (counter != 2) {
    fail("eventfd returned the wrong initial counter");
  }
  uint64_t blocking_counter;
  read_exact(blocking_event_fd, &blocking_counter, sizeof(blocking_counter));
  if (blocking_counter != 1) {
    fail("blocking eventfd returned the wrong initial counter");
  }
  if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, event_fd, NULL) != 0) {
    fail_errno("epoll_ctl(DEL eventfd)");
  }
  if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, blocking_event_fd, NULL) != 0) {
    fail_errno("epoll_ctl(DEL blocking eventfd)");
  }

  const uint64_t one = 1;
  if (write(event_fd, &one, sizeof(one)) != (ssize_t)sizeof(one)) {
    fail_errno("write(eventfd)");
  }
  expect_no_events(epoll_fd, "control-del");

  if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, timer_fd, NULL) != 0) {
    fail_errno("epoll_ctl(DEL timerfd)");
  }

#ifdef SYS_epoll_ctl_old
  errno = 0;
  const long legacy_result =
      syscall(SYS_epoll_ctl_old, epoll_fd, EPOLL_CTL_ADD, event_fd, NULL);
  if (legacy_result != -1 || errno != ENOSYS) {
    fail("epoll_ctl_old did not return ENOSYS");
  }
#endif

  close(epoll_fd);
  close(timer_fd);
  close(blocking_event_fd);
  close(event_fd);
  printf(
      "control-fds counter=%llu blocking-counter=%llu flags-ok"
#ifdef SYS_epoll_ctl_old
      " legacy-enosys"
#endif
      "\n",
      (unsigned long long)counter,
      (unsigned long long)blocking_counter);
}

// Regression test for an epoll fd that was never registered in Detcore's
// descriptor table. Descriptor-table operations (F_GETFL, F_SETFD, dup,
// F_DUPFD, F_DUPFD_CLOEXEC) used to fail with EBADF under Hermit even though
// the underlying kernel fd was perfectly valid. This broke the rustup proxies
// (cargo/rustc), whose tokio runtime dups its epoll fd at startup.
static void run_dupfd(void) {
  const int epoll_fd = create_epoll();

  // Status flags must be readable from the descriptor table.
  if (fcntl(epoll_fd, F_GETFL) < 0) {
    fail_errno("fcntl(F_GETFL) on epoll fd");
  }

  // Descriptor flags must be settable.
  if (fcntl(epoll_fd, F_SETFD, FD_CLOEXEC) < 0) {
    fail_errno("fcntl(F_SETFD) on epoll fd");
  }

  // Plain dup of the epoll fd.
  const int dup_fd = dup(epoll_fd);
  if (dup_fd < 0) {
    fail_errno("dup(epoll fd)");
  }

  // F_DUPFD returns the lowest free fd >= the requested minimum.
  const int dupfd_fd = fcntl(epoll_fd, F_DUPFD, 3);
  if (dupfd_fd < 0) {
    fail_errno("fcntl(F_DUPFD) on epoll fd");
  }

  // F_DUPFD_CLOEXEC does the same but sets close-on-exec on the new fd; this
  // is the exact call rustup's tokio runtime makes.
  const int cloexec_fd = fcntl(epoll_fd, F_DUPFD_CLOEXEC, 3);
  if (cloexec_fd < 0) {
    fail_errno("fcntl(F_DUPFD_CLOEXEC) on epoll fd");
  }
  const int cloexec_flags = fcntl(cloexec_fd, F_GETFD);
  if (cloexec_flags < 0) {
    fail_errno("fcntl(F_GETFD) on duplicated epoll fd");
  }
  if ((cloexec_flags & FD_CLOEXEC) == 0) {
    fail("F_DUPFD_CLOEXEC did not set close-on-exec on the new fd");
  }

  close(cloexec_fd);
  close(dupfd_fd);
  close(dup_fd);
  close(epoll_fd);
  printf("dupfd ops-ok\n");
}

/* A nonleader exit_group must release the entire group's shared file table
 * before another process observes socket EOF. Waiting only for the initiating
 * thread makes the epoll retry count depend on which sibling exits last. */
static pthread_barrier_t exit_barrier;

static void* exit_tcp_thread(void* argument) {
  const int result = pthread_barrier_wait(&exit_barrier);
  if (result != 0 && result != PTHREAD_BARRIER_SERIAL_THREAD) {
    fail("pthread_barrier_wait");
  }
  if ((uintptr_t)argument == 0) {
    syscall(SYS_exit_group, 0);
    _exit(99);
  }
  for (;;) {
    pause();
  }
  return NULL;
}

static void run_tcp_exit(bool retain_alias) {
  sigset_t blocked, previous;
  sigemptyset(&blocked);
  sigaddset(&blocked, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &blocked, &previous) != 0) {
    fail_errno("block SIGCHLD");
  }
  for (unsigned round = 0; round < 8; ++round) {
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) {
      fail_errno("socket listener");
    }
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    socklen_t length = sizeof(address);
    if (bind(listener, (struct sockaddr*)&address, length) != 0 ||
        listen(listener, 2) != 0 ||
        getsockname(listener, (struct sockaddr*)&address, &length) != 0) {
      fail_errno("listen on loopback");
    }
    int clients[2], servers[2];
    for (unsigned i = 0; i < 2; ++i) {
      clients[i] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
      if (clients[i] < 0 ||
          connect(clients[i], (struct sockaddr*)&address, length) != 0) {
        fail_errno("connect loopback");
      }
      servers[i] = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
      if (servers[i] < 0) {
        fail_errno("accept loopback");
      }
    }
    close(listener);
    const int retained = retain_alias ? dup(clients[0]) : -1;
    if (retain_alias && retained < 0) {
      fail_errno("dup surviving socket");
    }
    int epoll_fd = create_epoll();
    for (unsigned i = 0; i < 2; ++i) {
      control_fd(epoll_fd, EPOLL_CTL_ADD, servers[i], EPOLLIN | EPOLLRDHUP, i);
    }
    const int epoll_alias = dup(epoll_fd);
    if (epoll_alias < 0) {
      fail_errno("dup epoll");
    }
    close(epoll_fd);
    epoll_fd = epoll_alias;

    const pid_t child = fork();
    if (child < 0) {
      fail_errno("fork");
    }
    if (child == 0) {
      close(epoll_fd);
      if (retained >= 0) {
        close(retained);
      }
      for (unsigned i = 0; i < 2; ++i) {
        close(servers[i]);
        /* The final close is implicit, including these descriptor aliases. */
        if (dup(clients[i]) < 0) {
          fail_errno("dup exiting socket");
        }
      }
      enum { THREADS = 8 };
      pthread_t threads[THREADS];
      if (pthread_barrier_init(&exit_barrier, NULL, THREADS) != 0) {
        fail("pthread_barrier_init");
      }
      for (uintptr_t i = 0; i < THREADS; ++i) {
        if (pthread_create(&threads[i], NULL, exit_tcp_thread, (void*)i) != 0) {
          fail("pthread_create");
        }
      }
      pthread_join(threads[0], NULL);
      _exit(98);
    }
    close(clients[0]);
    close(clients[1]);
    struct epoll_event events[2];
    const int count = epoll_wait(epoll_fd, events, 2, -1);
    if (count != (retain_alias ? 1 : 2)) {
      fail("exit_group exposed partial socket cleanup");
    }
    unsigned seen = 0;
    for (int i = 0; i < count; ++i) {
      const unsigned tag = events[i].data.u32;
      if (tag >= 2 || (seen & (1u << tag)) != 0 ||
          (retain_alias && tag != 1) || !(events[i].events & EPOLLIN)) {
        fail("unexpected exit readiness");
      }
      seen |= 1u << tag;
      /* Consume the ordered readiness result, not a sorted presentation. */
      printf("tcp-exit round=%u event=%d socket=%u flags=%x\n",
             round, i, tag, events[i].events);
      char byte;
      if (recv(servers[tag], &byte, 1, 0) != 0) {
        fail("exited peer did not produce EOF");
      }
      control_fd(epoll_fd, EPOLL_CTL_DEL, servers[tag], 0, 0);
    }
    int status;
    if (waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      fail("exit_group child status");
    }
    if (retain_alias) {
      expect_no_events(epoll_fd, "surviving socket reference");
      write_byte(retained, 'x');
      if (epoll_wait(epoll_fd, events, 2, -1) != 1 ||
          events[0].data.u32 != 0) {
        fail("surviving socket lost readiness");
      }
      char byte;
      read_exact(servers[0], &byte, 1);
      if (byte != 'x') {
        fail("surviving socket lost data");
      }
      close(retained);
      if (epoll_wait(epoll_fd, events, 2, -1) != 1 ||
          events[0].data.u32 != 0 || recv(servers[0], &byte, 1, 0) != 0) {
        fail("final alias close did not produce EOF");
      }
    }
    close(servers[0]);
    close(servers[1]);
    close(epoll_fd);
  }
  if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0) {
    fail_errno("restore SIGCHLD");
  }
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(
        stderr,
        "usage: %s <multi|edge|oneshot|mixed|nested|control-fds|dupfd|tcp-exit|tcp-exit-alias>\n",
        argv[0]);
    return 2;
  }

  if (strcmp(argv[1], "multi") == 0) {
    run_multi();
  } else if (strcmp(argv[1], "edge") == 0) {
    run_edge();
  } else if (strcmp(argv[1], "oneshot") == 0) {
    run_oneshot();
  } else if (strcmp(argv[1], "mixed") == 0) {
    run_mixed();
  } else if (strcmp(argv[1], "nested") == 0) {
    run_nested();
  } else if (strcmp(argv[1], "control-fds") == 0) {
    run_control_fds();
  } else if (strcmp(argv[1], "dupfd") == 0) {
    run_dupfd();
  } else if (strcmp(argv[1], "tcp-exit") == 0) {
    run_tcp_exit(false);
  } else if (strcmp(argv[1], "tcp-exit-alias") == 0) {
    run_tcp_exit(true);
  } else {
    fprintf(stderr, "unknown scenario: %s\n", argv[1]);
    return 2;
  }

  printf("%s success\n", argv[1]);
  return 0;
}
