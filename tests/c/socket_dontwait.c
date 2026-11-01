// MSG_DONTWAIT makes one send or receive nonblocking on a socket the program
// left blocking: Linux returns at once, -1 EAGAIN where the call would have to
// wait, and otherwise what the call would have returned. Calls without the
// flag on the same sockets still wait. Every line is what Linux prints.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static void result(const char *what, long r) {
  if (r < 0) {
    printf("%s: -1 (%s)\n", what, strerror(errno));
  } else {
    printf("%s: %ld\n", what, r);
  }
}

// Whether to make recvmmsg and sendmmsg calls: record and replay record
// neither, and replay runs them on sockets whose recorded traffic it did not
// repeat.
static int batched = 1;

static void check(int ok, const char *what) {
  if (!ok) {
    perror(what);
    _exit(2);
  }
}

// Each receive call with `flags` on `fd`, where nothing is queued.
static void receive_each(const char *kind, int fd, int flags) {
  char buffer[16];
  char what[64];
  struct iovec iov = {buffer, sizeof(buffer)};
  struct mmsghdr message = {.msg_hdr = {.msg_iov = &iov, .msg_iovlen = 1}};
  snprintf(what, sizeof(what), "%s recvfrom", kind);
  result(what, recvfrom(fd, buffer, sizeof(buffer), flags, NULL, NULL));
  snprintf(what, sizeof(what), "%s recvmsg", kind);
  result(what, recvmsg(fd, &message.msg_hdr, flags));
  if (batched) {
    snprintf(what, sizeof(what), "%s recvmmsg", kind);
    result(what, recvmmsg(fd, &message, 1, flags, NULL));
    snprintf(what, sizeof(what), "%s recvmmsg MSG_WAITFORONE", kind);
    result(what, recvmmsg(fd, &message, 1, flags | MSG_WAITFORONE, NULL));
  }
}

// Each send call with `flags` on `fd`, whose peer has no room.
static void send_each(const char *kind, int fd, int flags) {
  char byte = 'x';
  char what[64];
  struct iovec iov = {&byte, 1};
  struct mmsghdr message = {.msg_hdr = {.msg_iov = &iov, .msg_iovlen = 1}};
  snprintf(what, sizeof(what), "%s sendto", kind);
  result(what, sendto(fd, &byte, 1, flags, NULL, 0));
  snprintf(what, sizeof(what), "%s sendmsg", kind);
  result(what, sendmsg(fd, &message.msg_hdr, flags));
  if (batched) {
    snprintf(what, sizeof(what), "%s sendmmsg", kind);
    result(what, sendmmsg(fd, &message, 1, flags));
  }
}

struct later {
  int fd;
  const struct sockaddr_in *to;
  long total;
};

// Wait, then send one datagram to `to`.
static void *send_later(void *argument) {
  struct later *later = argument;
  usleep(50000);
  check(sendto(later->fd, "late", 4, 0, (const struct sockaddr *)later->to,
               sizeof(*later->to)) == 4,
        "late sendto");
  return NULL;
}

// Wait, then read `total` bytes.
static void *drain_later(void *argument) {
  struct later *later = argument;
  char buffer[4096];
  usleep(50000);
  while (later->total > 0) {
    long r = recv(later->fd, buffer, sizeof(buffer), 0);
    check(r > 0, "drain recv");
    later->total -= r;
  }
  return NULL;
}

static void udp(void) {
  struct sockaddr_in address = {.sin_family = AF_INET};
  socklen_t length = sizeof(address);
  char buffer[16] = {0};
  struct iovec iovs[4] = {
      {buffer, 4}, {buffer + 4, 4}, {buffer + 8, 4}, {buffer + 12, 4}};
  struct mmsghdr messages[4];
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  struct pollfd poll_fd = {.fd = fd, .events = POLLIN};
  pthread_t thread;
  struct later later = {.to = &address};
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  check(fd >= 0 &&
            bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0 &&
            getsockname(fd, (struct sockaddr *)&address, &length) == 0,
        "udp socket");
  receive_each("udp empty", fd, MSG_DONTWAIT);

  // Loopback delivers the datagram in a softirq, so wait until it is queued.
  check(sendto(fd, "ping", 4, 0, (struct sockaddr *)&address, length) == 4 &&
            poll(&poll_fd, 1, -1) == 1,
        "udp sendto");
  result("udp queued recv", recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT));
  printf("udp queued data: %.4s\n", buffer);

  // MSG_WAITFORONE waits for the first datagram and only then stops waiting.
  memset(messages, 0, sizeof(messages));
  for (int i = 0; i < 4; i++) {
    messages[i].msg_hdr.msg_iov = &iovs[i];
    messages[i].msg_hdr.msg_iovlen = 1;
  }
  later.fd = socket(AF_INET, SOCK_DGRAM, 0);
  check(later.fd >= 0, "udp sender");
  check(pthread_create(&thread, NULL, send_later, &later) == 0,
        "pthread_create");
  result("udp blocking recvmmsg MSG_WAITFORONE",
         recvmmsg(fd, messages, 4, MSG_WAITFORONE, NULL));
  printf("udp late data: %.4s\n", buffer);
  pthread_join(thread, NULL);
  close(later.fd);
  close(fd);
}

static void unix_datagram(void) {
  int pair[2];
  char buffer[16];
  int sent = 0;
  int drained = 0;
  check(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0, "socketpair");
  receive_each("unix datagram empty", pair[1], MSG_DONTWAIT);
  result("unix datagram send", send(pair[0], "abc", 3, MSG_DONTWAIT));
  result("unix datagram queued recv",
         recv(pair[1], buffer, sizeof(buffer), MSG_DONTWAIT));
  if (batched) {
    // AF_UNIX queues each datagram on the peer before send returns.
    char data[16] = {0};
    struct iovec iovs[4] = {
        {data, 4}, {data + 4, 4}, {data + 8, 4}, {data + 12, 4}};
    struct mmsghdr messages[4];
    memset(messages, 0, sizeof(messages));
    for (int i = 0; i < 4; i++) {
      messages[i].msg_hdr.msg_iov = &iovs[i];
      messages[i].msg_hdr.msg_iovlen = 1;
    }
    check(send(pair[0], "one!", 4, 0) == 4 && send(pair[0], "two!", 4, 0) == 4,
          "unix datagram send two");
    result("unix datagram two queued recvmmsg",
           recvmmsg(pair[1], messages, 4, MSG_DONTWAIT, NULL));
    printf("unix datagram two queued data: %.8s\n", data);
  }

  // Fill the peer's queue. The count depends on the host's limits, so only
  // the way the filling ends is printed.
  while (send(pair[0], "", 1, MSG_DONTWAIT) == 1) {
    sent++;
  }
  printf("unix datagram fill ends after %s sends: %s\n",
         sent > 0 ? "some" : "no", strerror(errno));
  send_each("unix datagram full", pair[0], MSG_DONTWAIT);
  while (recv(pair[1], buffer, sizeof(buffer), MSG_DONTWAIT) == 1) {
    drained++;
  }
  printf("unix datagram drained every send: %s (%s)\n",
         drained == sent ? "yes" : "no", strerror(errno));
  close(pair[0]);
  close(pair[1]);
}

static void unix_stream(void) {
  int pair[2];
  char chunk[4096] = {0};
  long r;
  pthread_t thread;
  struct later later = {.total = 0};
  check(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "socketpair");
  receive_each("unix stream empty", pair[1], MSG_DONTWAIT);

  while ((r = send(pair[0], chunk, sizeof(chunk), MSG_DONTWAIT)) > 0) {
    later.total += r;
  }
  printf("unix stream fill ends after %s bytes: %s\n",
         later.total > 0 ? "some" : "no", strerror(errno));
  send_each("unix stream full", pair[0], MSG_DONTWAIT);

  // Without the flag the same send waits for the peer to make room.
  later.fd = pair[1];
  later.total += sizeof(chunk);
  check(pthread_create(&thread, NULL, drain_later, &later) == 0,
        "pthread_create");
  result("unix stream blocking send", send(pair[0], chunk, sizeof(chunk), 0));
  pthread_join(thread, NULL);
  receive_each("unix stream drained", pair[1], MSG_DONTWAIT);
  close(pair[0]);
  close(pair[1]);
}

static void tcp(void) {
  struct sockaddr_in address = {.sin_family = AF_INET};
  socklen_t length = sizeof(address);
  int listener = socket(AF_INET, SOCK_STREAM, 0);
  int client = socket(AF_INET, SOCK_STREAM, 0);
  int server;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  check(listener >= 0 && client >= 0 &&
            bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0 &&
            getsockname(listener, (struct sockaddr *)&address, &length) == 0 &&
            listen(listener, 1) == 0 &&
            connect(client, (struct sockaddr *)&address, length) == 0,
        "tcp");
  server = accept(listener, NULL, NULL);
  check(server >= 0, "accept");
  receive_each("tcp connected", client, MSG_DONTWAIT);
  receive_each("tcp accepted", server, MSG_DONTWAIT);
  close(server);
  close(client);
  close(listener);
}

// Exercise the per-call flag through an alias without changing the shared
// open-file-description flags, including invalid descriptors and zero-length
// datagrams. The other sections cover blocking calls and other socket kinds.
static ssize_t send_packet(int kind, int fd, char *data, size_t size) {
  if (kind == 0) return sendto(fd, data, size, MSG_DONTWAIT, NULL, 0);
  struct iovec iov = {.iov_base = data, .iov_len = size};
  struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
  if (kind == 1) return sendmsg(fd, &message, MSG_DONTWAIT);
  struct mmsghdr batch = {.msg_hdr = message};
  int count = sendmmsg(fd, &batch, 1, MSG_DONTWAIT);
  if (count < 0) return count;
  check(count == 1, "sendmmsg count");
  return batch.msg_len;
}

static ssize_t receive_packet(int kind, int fd, char *data, size_t size) {
  if (kind == 0) return recvfrom(fd, data, size, MSG_DONTWAIT, NULL, NULL);
  struct iovec iov = {.iov_base = data, .iov_len = size};
  struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
  if (kind == 1) return recvmsg(fd, &message, MSG_DONTWAIT);
  struct mmsghdr batch = {.msg_hdr = message};
  int count = recvmmsg(fd, &batch, 1, MSG_DONTWAIT, NULL);
  if (count < 0) return count;
  check(count == 1, "recvmmsg count");
  return batch.msg_len;
}

static void descriptor_flags(void) {
  for (int kind = 0; kind < (batched ? 3 : 2); kind++) {
    int pair[2];
    check(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0, "socketpair");
    int alias = dup(pair[0]);
    check(alias >= 0, "dup");
    int capacity = 4096;
    check(setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF, &capacity, sizeof(capacity)) == 0,
          "setsockopt SO_SNDBUF");
    char sent = 'q', received = 0;
    check(receive_packet(kind, pair[1], &received, 1) == -1 && errno == EAGAIN,
          "empty receive");
    check(send_packet(kind, -1, &sent, 1) == -1 && errno == EBADF, "invalid send");
    check(receive_packet(kind, -1, &received, 1) == -1 && errno == EBADF,
          "invalid receive");
    check(send_packet(kind, alias, &sent, 1) == 1, "aliased send");
    check(receive_packet(kind, pair[1], &received, 1) == 1 && received == sent,
          "queued receive");

    unsigned queued = 0;
    while (send_packet(kind, alias, &sent, 1) == 1) {
      check(++queued < 1024, "bounded send queue");
    }
    check(errno == EAGAIN && queued > 0, "full send queue");
    for (unsigned index = 0; index < queued; index++)
      check(receive_packet(kind, pair[1], &received, 1) == 1 && received == sent,
            "drain queued datagram");
    check(receive_packet(kind, pair[1], &received, 1) == -1 && errno == EAGAIN,
          "drained receive");

    check(send_packet(kind, alias, &sent, 0) == 0, "zero-length send");
    check(receive_packet(kind, pair[1], &received, 1) == 0, "zero-length receive");
    int descriptors[] = {pair[0], pair[1], alias};
    for (size_t index = 0; index < sizeof(descriptors) / sizeof(descriptors[0]); index++) {
      int flags = fcntl(descriptors[index], F_GETFL);
      check(flags >= 0 && !(flags & O_NONBLOCK), "descriptor remains blocking");
      check(close(descriptors[index]) == 0, "close descriptor");
    }
  }
  puts("per-call nonblocking preserves descriptor flags, aliases and datagrams");
}

// Runs every section, or only those named on the command line, and makes no
// recvmmsg or sendmmsg call after the argument "unbatched". Record and replay
// keep an accepted TCP connection only in the log and refuse recvmmsg on it.
int main(int argc, char **argv) {
  static const struct {
    const char *name;
    void (*run)(void);
  } sections[] = {{"udp", udp},
                  {"unix_datagram", unix_datagram},
                  {"unix_stream", unix_stream},
                  {"tcp", tcp},
                  {"descriptor_flags", descriptor_flags}};
  int named = 0;
  setvbuf(stdout, NULL, _IOLBF, 0);
  for (int j = 1; j < argc; j++) {
    if (strcmp(argv[j], "unbatched") == 0) {
      batched = 0;
    } else {
      named++;
    }
  }
  for (size_t i = 0; i < sizeof(sections) / sizeof(sections[0]); i++) {
    int selected = named == 0;
    for (int j = 1; j < argc; j++) {
      selected |= strcmp(argv[j], sections[i].name) == 0;
    }
    if (selected) {
      sections[i].run();
    }
  }
  return 0;
}
