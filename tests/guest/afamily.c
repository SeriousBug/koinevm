/* A socket and an address whose families disagree: what the kernel answers, because glibc's
 * getaddrinfo asks exactly this question and acts on the errno.
 *
 * glibc sorts the addresses it finds by connecting a spare socket of the first one's family to each
 * of them and reading back the source address. An AF_INET address through an AF_INET6 socket is a
 * question it expects to fail, and it treats a success as a v4-mapped address: the two answers a
 * kernel can give are a wrong source address and an assertion.
 *
 * tests/fmt.sh runs this as a dynamically linked guest against the same binary run natively in a
 * container, so every check has to be true on both. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;

static void check(int ok, const char *what) {
    printf(ok ? "ok   %s\n" : "FAIL %s\n", what);
    if (!ok) failures++;
}

/* The errno as the name a reader knows, since a number means nothing in a diff. */
static const char *name_of(int err) {
    switch (err) {
        case 0: return "ok";
        case EINVAL: return "EINVAL";
        case EAFNOSUPPORT: return "EAFNOSUPPORT";
        case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
        case ENETUNREACH: return "ENETUNREACH";
        case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
        case EOPNOTSUPP: return "EOPNOTSUPP";
        case EINPROGRESS: return "EINPROGRESS";
        default: return "other";
    }
}

static int port_of(const struct sockaddr_storage *ss) {
    if (ss->ss_family == AF_INET) return ntohs(((const struct sockaddr_in *)ss)->sin_port);
    if (ss->ss_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *)ss)->sin6_port);
    return -1;
}

int main(void) {
    struct sockaddr_in v4;
    memset(&v4, 0, sizeof(v4));
    v4.sin_family = AF_INET;
    v4.sin_port = htons(9);
    inet_pton(AF_INET, "127.0.0.1", &v4.sin_addr);

    struct sockaddr_in6 v6;
    memset(&v6, 0, sizeof(v6));
    v6.sin6_family = AF_INET6;
    v6.sin6_port = htons(9);
    inet_pton(AF_INET6, "::ffff:127.0.0.1", &v6.sin6_addr);

    /* A datagram socket of each family, asked to talk to the other family. */
    int fd6 = socket(AF_INET6, SOCK_DGRAM, 0);
    check(fd6 >= 0, "socket(AF_INET6, SOCK_DGRAM) returns a descriptor");
    errno = 0;
    int rc = connect(fd6, (const struct sockaddr *)&v4, sizeof(v4));
    printf("%s connect(AF_INET6 socket, an AF_INET address)\n", name_of(rc == 0 ? 0 : errno));
    errno = 0;
    rc = sendto(fd6, "x", 1, 0, (const struct sockaddr *)&v4, sizeof(v4));
    printf("%s sendto(AF_INET6 socket, an AF_INET address)\n", name_of(rc < 0 ? errno : 0));
    errno = 0;
    rc = bind(fd6, (const struct sockaddr *)&v4, sizeof(v4));
    printf("%s bind(AF_INET6 socket, an AF_INET address)\n", name_of(rc == 0 ? 0 : errno));
    /* A v4-mapped address is the same family, so this is the shape glibc needs to succeed. */
    errno = 0;
    rc = connect(fd6, (const struct sockaddr *)&v6, sizeof(v6));
    check(rc == 0, "connect(AF_INET6 socket, a v4-mapped AF_INET6 address) succeeds");

    /* A socket given less than its family's own address is not guessed at. */
    int short6 = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_in6 chopped;
    memset(&chopped, 0, sizeof(chopped));
    chopped.sin6_family = AF_INET6;
    errno = 0;
    rc = connect(short6, (const struct sockaddr *)&chopped, 16);
    printf("%s connect of a 16-byte address to an AF_INET6 socket\n", name_of(rc == 0 ? 0 : errno));

    int fd4 = socket(AF_INET, SOCK_DGRAM, 0);
    check(fd4 >= 0, "socket(AF_INET, SOCK_DGRAM) returns a descriptor");
    errno = 0;
    rc = connect(fd4, (const struct sockaddr *)&v6, sizeof(v6));
    printf("%s connect(AF_INET socket, an AF_INET6 address)\n", name_of(rc == 0 ? 0 : errno));
    errno = 0;
    rc = sendto(fd4, "x", 1, 0, (const struct sockaddr *)&v6, sizeof(v6));
    printf("%s sendto(AF_INET socket, an AF_INET6 address)\n", name_of(rc < 0 ? errno : 0));
    errno = 0;
    rc = bind(fd4, (const struct sockaddr *)&v6, sizeof(v6));
    printf("%s bind(AF_INET socket, an AF_INET6 address)\n", name_of(rc == 0 ? 0 : errno));

    /* An address of no family at all, which is what a zeroed structure is. */
    struct sockaddr_in none;
    memset(&none, 0, sizeof(none));
    errno = 0;
    rc = connect(fd4, (const struct sockaddr *)&none, sizeof(none));
    printf("%s connect to an address of family 0\n", name_of(rc == 0 ? 0 : errno));

    /* What the socket reports about itself, over an address buffer of its own family. */
    int fresh = socket(AF_INET6, SOCK_DGRAM, 0);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    rc = getsockname(fresh, (struct sockaddr *)&ss, &sl);
    check(rc == 0 && ss.ss_family == AF_INET6, "getsockname of an AF_INET6 socket says AF_INET6");
    check(sl == sizeof(struct sockaddr_in6), "getsockname reports an AF_INET6 address's length");
    check(port_of(&ss) == 0, "an unbound socket has port 0");

    /* A peer's address is the peer's family and its own length, not the socket's buffer. */
    int pair[2];
    check(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) == 0, "socketpair for a peer address");
    struct sockaddr_storage peer;
    sl = sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    rc = getpeername(pair[0], (struct sockaddr *)&peer, &sl);
    check(rc == 0 && peer.ss_family == AF_UNIX, "an unnamed pair end's peer has no family of its own");
    check(sl == sizeof(sa_family_t), "and the length is a bare family, which is all it holds");

    close(fd6);
    close(short6);
    close(fd4);
    close(fresh);
    close(pair[0]);
    close(pair[1]);

    printf(failures ? "afamily: FAILURES\n" : "afamily: all checks passed\n");
    return failures ? 1 : 0;
}
