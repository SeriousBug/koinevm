/* Resolving a name the way a program does: glibc's getaddrinfo, over the resolver file the guest is
 * given: one name every machine resolves, and one that does not exist, which only a resolver can
 * say.
 *
 * tests/fmt.sh runs this as a dynamically linked guest against the same binary run natively in a
 * container, so the checks have to be true on both: no address is printed, only what is the same
 * everywhere. */
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

static int port_of(const struct addrinfo *it) {
    if (it->ai_addr == NULL) return -1;
    if (it->ai_addr->sa_family == AF_INET) return ntohs(((const struct sockaddr_in *)it->ai_addr)->sin_port);
    if (it->ai_addr->sa_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *)it->ai_addr)->sin6_port);
    return -1;
}

int main(void) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo("localhost", "80", &hints, &res);
    check(rc == 0 && res != NULL, "getaddrinfo(localhost) answers");
    int shaped = 0, port = -1;
    for (const struct addrinfo *it = res; it != NULL; it = it->ai_next) {
        if (it->ai_addrlen == sizeof(struct sockaddr_in) || it->ai_addrlen == sizeof(struct sockaddr_in6)) shaped = 1;
        if (port < 0) port = port_of(it);
    }
    check(shaped, "every address a socket can take");
    check(port == 80, "the port it was given is the port it reports");
    if (res != NULL) freeaddrinfo(res);

    // A name in the reserved `.invalid` domain: no resolver can find it, so glibc has to say so
    // rather than report a failure of its own.
    struct addrinfo *none = NULL;
    rc = getaddrinfo("no-such-name.invalid", NULL, &hints, &none);
    check(rc == EAI_NONAME, "a name that does not exist is EAI_NONAME");
    if (none != NULL) freeaddrinfo(none);

    printf(failures ? "resolve: FAILURES\n" : "resolve: all checks passed\n");
    return failures ? 1 : 0;
}
