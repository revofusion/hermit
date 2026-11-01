/* Real IPv4/IPv6 TCP and UDP clients must expose the same source port to
 * getsockname, getpeername, accept and recvfrom, including descriptor aliases.
 * Printing the ports makes host-selected ephemeral ports fail strict replay.
 */
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

union address {
  struct sockaddr generic;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;
};

static socklen_t address_size(int family) {
  return family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}

static union address loopback(int family, unsigned port) {
  union address address = {0};
  if (family == AF_INET) {
    address.v4.sin_family = family;
    address.v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.v4.sin_port = htons(port);
  } else {
    address.v6.sin6_family = family;
    address.v6.sin6_addr = in6addr_loopback;
    address.v6.sin6_port = htons(port);
  }
  return address;
}

static unsigned port_of(const union address *address) {
  return ntohs(address->generic.sa_family == AF_INET ? address->v4.sin_port
                                                    : address->v6.sin6_port);
}

static unsigned local_port(int fd) {
  union address address = {0};
  socklen_t length = sizeof(address);
  assert(getsockname(fd, &address.generic, &length) == 0);
  return port_of(&address);
}

static void exercise(int family, int type, unsigned server_port) {
  int server = socket(family, type, 0);
  assert(server >= 0);
  union address destination = loopback(family, server_port);
  assert(bind(server, &destination.generic, address_size(family)) == 0);
  if (type == SOCK_STREAM) {
    assert(listen(server, 4) == 0);
  }
  for (int round = 0; round < 5; ++round) {
    int original = socket(family, type, 0);
    assert(original >= 0);
    int client = dup(original);
    assert(client >= 0 && close(original) == 0);
    assert(local_port(client) == 0);
    errno = 0;
    assert(connect(client, (const struct sockaddr *)1, address_size(family)) == -1);
    assert(errno == EFAULT && local_port(client) == 0);
    errno = 0;
    assert(connect(client, &destination.generic, 2) == -1);
    assert(errno == EINVAL && local_port(client) == 0);
    if (round == 4) {
      union address source = loopback(family, server_port + 1);
      assert(bind(client, &source.generic, address_size(family)) == 0);
    }
    if (round == 1) {
      assert(fcntl(client, F_SETFL, O_NONBLOCK) == 0);
    }
    uint32_t requested_range = round == 3 ? (45000U << 16) | 45000U : 0;
    assert(setsockopt(client, IPPROTO_IP, IP_LOCAL_PORT_RANGE,
                      &requested_range, sizeof(requested_range)) == 0);
    socklen_t size = address_size(family);
    if (family == AF_INET6 && round == 2) {
      size -= sizeof(destination.v6.sin6_scope_id);
    }
    int connected = connect(client, &destination.generic, size);
    assert(connected == 0 || (round == 1 && errno == EINPROGRESS));
    struct pollfd writable = {.fd = client, .events = POLLOUT};
    assert(poll(&writable, 1, 1000) == 1 && (writable.revents & POLLOUT));
    assert(fcntl(client, F_SETFL, 0) == 0);
    uint32_t restored_range = 0;
    socklen_t range_size = sizeof(restored_range);
    assert(getsockopt(client, IPPROTO_IP, IP_LOCAL_PORT_RANGE,
                      &restored_range, &range_size) == 0);
    assert(restored_range == requested_range);
    unsigned source_port = local_port(client);
    assert(source_port != 0);
    if (round == 3) {
      assert(source_port == 45000);
    }
    if (round == 4) {
      assert(source_port == server_port + 1);
    }
    union address peer = {0};
    socklen_t peer_size = sizeof(peer);
    assert(getpeername(client, &peer.generic, &peer_size) == 0);
    assert(port_of(&peer) == server_port);
    char byte = 0;
    assert(send(client, "x", 1, 0) == 1);
    peer_size = sizeof(peer);
    if (type == SOCK_STREAM) {
      int accepted = accept(server, &peer.generic, &peer_size);
      assert(accepted >= 0 && port_of(&peer) == source_port);
      peer_size = sizeof(peer);
      assert(getpeername(accepted, &peer.generic, &peer_size) == 0);
      assert(port_of(&peer) == source_port && local_port(accepted) == server_port);
      assert(recv(accepted, &byte, 1, 0) == 1 && byte == 'x');
      /* Actively close the client: subsequent clients must not collide with
       * its TIME_WAIT tuple even though its last descriptor has closed. */
      assert(shutdown(client, SHUT_WR) == 0);
      assert(recv(accepted, &byte, 1, 0) == 0);
      assert(close(accepted) == 0);
      assert(recv(client, &byte, 1, 0) == 0);
    } else {
      assert(recvfrom(server, &byte, 1, 0, &peer.generic, &peer_size) == 1);
      assert(byte == 'x' && port_of(&peer) == source_port);
      assert(sendto(server, "y", 1, 0, &peer.generic, peer_size) == 1);
      assert(recv(client, &byte, 1, 0) == 1 && byte == 'y');
      struct sockaddr disconnect = {.sa_family = AF_UNSPEC};
      assert(connect(client, &disconnect, sizeof(disconnect)) == 0);
      assert(local_port(client) == (round == 4 ? server_port + 1 : 0));
      if (round == 0) {
        assert(connect(client, &destination.generic, address_size(family)) == 0);
        unsigned reconnected_port = local_port(client);
        assert(reconnected_port != 0);
        assert(send(client, "z", 1, 0) == 1);
        peer_size = sizeof(peer);
        assert(recvfrom(server, &byte, 1, 0, &peer.generic, &peer_size) == 1);
        assert(byte == 'z' && port_of(&peer) == reconnected_port);
        printf("family=%d reconnected=%u\n", family, reconnected_port);
      }
    }
    printf("family=%d type=%d round=%d source=%u\n", family, type, round, source_port);
    assert(close(client) == 0);
  }
  assert(close(server) == 0);
}

static void recycle_udp_ports(void) {
  int client = socket(AF_INET, SOCK_DGRAM, 0);
  assert(client >= 0);
  union address destination = loopback(AF_INET, 24008);
  struct sockaddr disconnect = {.sa_family = AF_UNSPEC};
  /* More than the entire 16-bit port space: a disconnected socket must
   * release its previous reservation instead of leaking one per connect. */
  for (unsigned round = 0; round < 65536; ++round) {
    assert(connect(client, &destination.generic, sizeof(destination.v4)) == 0);
    assert(connect(client, &disconnect, sizeof(disconnect)) == 0);
    assert(local_port(client) == 0);
  }
  assert(connect(client, &destination.generic, sizeof(destination.v4)) == 0);
  printf("65536 UDP reconnects, source=%u\n", local_port(client));
  assert(close(client) == 0);
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "recycle") == 0) {
    recycle_udp_ports();
    return 0;
  }
  assert(argc == 1);
  exercise(AF_INET, SOCK_STREAM, 24000);
  exercise(AF_INET6, SOCK_STREAM, 24002);
  exercise(AF_INET, SOCK_DGRAM, 24004);
  exercise(AF_INET6, SOCK_DGRAM, 24006);
  return 0;
}
