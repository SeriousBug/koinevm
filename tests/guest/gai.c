/* getaddrinfo on a name that has both an A and a AAAA record, which is the one path in glibc that
 * touches a kernel's socket-address rules from library code.
 *
 * Sorting the answers by RFC 3484 connects a spare socket of the first answer's family to each
 * answer in turn and reads the source address back with getsockname. An AF_INET answer read through
 * an AF_INET6 socket is a v4-mapped address, and glibc asserts exactly that, so a kernel that
 * reports the bare v4 address instead kills the program with an assertion rather than an error.
 *
 * tests/fmt.sh runs this as a dynamically linked guest against the same binary run natively in a
 * container, so no address is printed: only the shape of it, which is the same everywhere. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static int failures;

static void check(int ok, const char *what) {
    printf(ok ? "ok   %s\n" : "FAIL %s\n", what);
    if (!ok) failures++;
}

int main(void) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo("deb.debian.org", "80", &hints, &res);
    check(rc == 0 && res != NULL, "getaddrinfo of a name with both families answers");
    if (rc != 0) {
        printf("afamily: FAILURES\n");
        return 1;
    }

    int v4 = 0, v6 = 0, shaped = 0, ported = 0, mapped = 0;
    for (const struct addrinfo *it = res; it != NULL; it = it->ai_next) {
        if (it->ai_family == AF_INET) {
            v4++;
            if (it->ai_addrlen != sizeof(struct sockaddr_in)) shaped = 0;
            else shaped++;
            if (ntohs(((const struct sockaddr_in *)it->ai_addr)->sin_port) == 80) ported++;
        } else if (it->ai_family == AF_INET6) {
            v6++;
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)it->ai_addr;
            if (it->ai_addrlen != sizeof(struct sockaddr_in6)) continue;
            shaped++;
            if (ntohs(sin6->sin6_port) == 80) ported++;
            /* A v6 answer is either a real v6 address or the mapped form of a v4 one. */
            if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) mapped++;
        }
    }
    check(v4 > 0 && v6 > 0, "the answer has both a v4 and a v6 address");
    check(shaped == v4 + v6, "every answer is the address length its family says");
    check(ported == v4 + v6, "every answer carries the port it was asked for");

    /* A socket of each family reaches an address of its own family and nothing else, which is the
     * rule the sorting above relies on. */
    int fd6 = socket(AF_INET6, SOCK_DGRAM, 0);
    check(fd6 >= 0, "socket(AF_INET6, SOCK_DGRAM)");
    struct sockaddr_in6 mapped_v4;
    memset(&mapped_v4, 0, sizeof(mapped_v4));
    mapped_v4.sin6_family = AF_INET6;
    mapped_v4.sin6_port = htons(9);
    inet_pton(AF_INET6, "::ffff:127.0.0.1", &mapped_v4.sin6_addr);
    check(connect(fd6, (const struct sockaddr *)&mapped_v4, sizeof(mapped_v4)) == 0,
          "a v6 socket connects to the mapped form of a v4 address");

    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    rc = getsockname(fd6, (struct sockaddr *)&ss, &sl);
    check(rc == 0, "getsockname after that connect");
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&ss;
    check(ss.ss_family == AF_INET6 && sl == sizeof(struct sockaddr_in6),
          "the address it reports is the socket's own family");
    check(IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr),
          "and the source address of a v4 peer is the mapped form");

    freeaddrinfo(res);
    close(fd6);
    printf(failures ? "afamily: FAILURES\n" : "afamily: all checks passed\n");
    return failures ? 1 : 0;
}
