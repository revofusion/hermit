/* Native process-shared kill preserves the selected receiver and exact siginfo.
 * Pollers and CPU-bound leaders retain their dequeue guarantees. Competing
 * kernel sigwait/signalfd consumers remain refused; a separate thread-pending
 * copy must not be confused with the process-shared copy sent to the leader.
 * Post-send consumers must not steal that copy, even if its handler runs later.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal handler needs lock-free atomics");
static atomic_int ready, stop, count, handler_tid, sender_pid, sender_uid, code, stolen;
static int wake_fd, consume_fd;
static const char *mode;
static sigset_t usr1;

static void handler(int signal, siginfo_t *info, void *context) {
  (void)context;
  int saved = errno;
  assert(signal == SIGUSR1);
  atomic_store(&handler_tid, (int)syscall(SYS_gettid));
  atomic_store(&sender_pid, info->si_pid);
  atomic_store(&sender_uid, (int)info->si_uid);
  atomic_store(&code, info->si_code);
  atomic_fetch_add(&count, 1);
  uint64_t one = 1;
  if (write(wake_fd, &one, sizeof(one)) != (ssize_t)sizeof(one)) _exit(91);
  errno = saved;
}

static void *spinner(void *unused) {
  (void)unused;
  if (!strcmp(mode, "leader"))
    assert(pthread_sigmask(SIG_UNBLOCK, &usr1, NULL) == 0);
  atomic_fetch_add(&ready, 1);
  while (!atomic_load(&stop)) {
    if (!strcmp(mode, "adversary")) {
      assert(pthread_sigmask(SIG_UNBLOCK, &usr1, NULL) == 0);
      assert(pthread_sigmask(SIG_BLOCK, &usr1, NULL) == 0);
    }
    sched_yield();
  }
  return NULL;
}

static void *consumer(void *unused) {
  (void)unused;
  atomic_fetch_add(&ready, 1);
  if (!strcmp(mode, "waiter")) {
    struct timespec timeout = {.tv_sec = 60};
    (void)sigtimedwait(&usr1, NULL, &timeout);
    return NULL;
  }
  char go;
  ssize_t n;
  do { n = read(consume_fd, &go, 1); } while (n < 0 && errno == EINTR);
  assert(n == 1);
  /* Native kill need not wait for the handler. Keep the original modes
   * adversarial; the new boundary modes independently check handler identity. */
  if (!strcmp(mode, "pdeath-epoll") || !strcmp(mode, "cpu") ||
      !strcmp(mode, "pdeath-cpu") || !strcmp(mode, "host-signal"))
    while (!atomic_load(&count)) sched_yield();
  struct timespec zero = {0};
  siginfo_t info;
  int result = sigtimedwait(&usr1, &info, &zero);
  if (!strcmp(mode, "pending")) {
    assert(result == SIGUSR1);
    /* glibc sigtimedwait normalizes pthread_kill's SI_TKILL to SI_USER. */
    assert(info.si_code == SI_USER && info.si_pid == getpid());
    assert(info.si_uid == getuid());
    result = sigtimedwait(&usr1, &info, &zero);
  }
  atomic_store(&stolen, result == SIGUSR1);
  assert(result == -1 && errno == EAGAIN);
  assert(pthread_sigmask(SIG_UNBLOCK, &usr1, NULL) == 0);
  return NULL;
}

static void child(int ready_fd, int consume, pid_t parent, uid_t uid) {
  consume_fd = consume;
  if (!strcmp(mode, "pdeath-epoll") || !strcmp(mode, "pdeath-cpu"))
    assert(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) == 0);
  /* Standard caught PDEATHSIGs are scheduler-modeled; realtime remains native. */
  if (!strcmp(mode, "host-signal"))
    assert(prctl(PR_SET_PDEATHSIG, SIGRTMIN, 0, 0, 0) == 0);
  sigemptyset(&usr1);
  sigaddset(&usr1, SIGUSR1);
  assert(pthread_sigmask(SIG_BLOCK, &usr1, NULL) == 0);
  wake_fd = eventfd(0, EFD_CLOEXEC);
  assert(wake_fd >= 0);
  struct sigaction action = {.sa_sigaction = handler, .sa_flags = SA_SIGINFO};
  if (!strcmp(mode, "restart")) action.sa_flags |= SA_RESTART;
  sigemptyset(&action.sa_mask);
  assert(sigaction(SIGUSR1, &action, NULL) == 0);
  int epoll = epoll_create1(EPOLL_CLOEXEC);
  assert(epoll >= 0);
  struct epoll_event event = {.events = EPOLLIN, .data.fd = wake_fd};
  assert(epoll_ctl(epoll, EPOLL_CTL_ADD, wake_fd, &event) == 0);
  int signal_fd = -1;
  if (!strcmp(mode, "signalfd")) {
    signal_fd = signalfd(-1, &usr1, SFD_CLOEXEC | SFD_NONBLOCK);
    assert(signal_fd >= 0);
  }
  pthread_t threads[2];
  assert(pthread_create(&threads[0], NULL, spinner, NULL) == 0);
  assert(pthread_create(&threads[1], NULL, consumer, NULL) == 0);
  while (atomic_load(&ready) != 2) sched_yield();
  if (!strcmp(mode, "pending")) assert(pthread_kill(threads[1], SIGUSR1) == 0);
  if (strcmp(mode, "private-mask"))
    assert(pthread_sigmask(SIG_UNBLOCK, &usr1, NULL) == 0);
  assert(write(ready_fd, "r", 1) == 1);
  close(ready_fd);
  if (!strcmp(mode, "cpu") || !strcmp(mode, "pdeath-cpu") || !strcmp(mode, "host-signal")) {
    /* No syscalls: delivery must resume a real PMU slice boundary. */
    while (!atomic_load(&count)) {}
  } else {
    do {
      int result;
      if (!strcmp(mode, "private-mask")) {
        sigset_t empty;
        sigemptyset(&empty);
        result = epoll_pwait(epoll, &event, 1, -1, &empty);
      } else {
        result = epoll_wait(epoll, &event, 1, -1);
      }
      assert(result == -1 && errno == EINTR);
    } while (!atomic_load(&count));
  }
  assert(pthread_join(threads[1], NULL) == 0);
  atomic_store(&stop, 1);
  assert(pthread_join(threads[0], NULL) == 0);
  assert(atomic_load(&count) == 1);
  assert(atomic_load(&handler_tid) == getpid());
  assert(atomic_load(&sender_pid) == parent);
  assert(atomic_load(&sender_uid) == (int)uid);
  assert(atomic_load(&code) == SI_USER);
  assert(atomic_load(&stolen) == 0);
  if (signal_fd >= 0) close(signal_fd);
  close(epoll);
  close(wake_fd);
  close(consume_fd);
  _exit(0);
}

static void *send_from_nonleader(void *argument) {
  pid_t child_pid = *(pid_t *)argument;
  /* The fixture must distinguish the sender process ID from its thread ID. */
  pid_t sender = getpid();
  assert(syscall(SYS_gettid) != sender);
  /* Refusal tests must reach this cross-process send, not fail during setup. */
  char attempt[96];
  int length = snprintf(attempt, sizeof(attempt), "[%d,%d,%d]\n",
                        (int)sender, (int)child_pid, SIGUSR1);
  assert(length > 0 && (size_t)length < sizeof(attempt));
  assert(write(STDOUT_FILENO, attempt, (size_t)length) == length);
  assert(kill(child_pid, SIGUSR1) == 0);
  return NULL;
}

int main(int argc, char **argv) {
  assert(argc == 2);
  mode = argv[1];
  int ready_pipe[2], consume_pipe[2];
  assert(pipe(ready_pipe) == 0 && pipe(consume_pipe) == 0);
  pid_t parent = getpid();
  uid_t uid = getuid();
  pid_t pid = fork();
  assert(pid >= 0);
  if (!pid) {
    close(ready_pipe[0]);
    close(consume_pipe[1]);
    child(ready_pipe[1], consume_pipe[0], parent, uid);
  }
  close(ready_pipe[1]);
  close(consume_pipe[0]);
  char r;
  assert(read(ready_pipe[0], &r, 1) == 1);
  /* Let the child reach its epoll poll or CPU-only loop before the send. */
  struct timespec settle = {.tv_nsec = 20000000};
  while (nanosleep(&settle, &settle) < 0) assert(errno == EINTR);
  pthread_t sender;
  assert(pthread_create(&sender, NULL, send_from_nonleader, &pid) == 0);
  assert(pthread_join(sender, NULL) == 0);
  assert(write(consume_pipe[1], "g", 1) == 1);
  int status;
  assert(waitpid(pid, &status, 0) == pid);
  assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  close(ready_pipe[0]);
  close(consume_pipe[1]);
  printf("%s leader=1 sender=1 uid=1 code=SI_USER count=1 stolen=0\n", mode);
  return 0;
}
