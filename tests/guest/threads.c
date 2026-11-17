// Two threads of one process: a pipe between them so one blocks while the other fills it, a mutex
// and a condition variable for the handoff, and a join, which is a futex wait on the thread's own
// tid word. One linear memory cannot run two threads at once, so this is the case that says
// whether a thread can be a coroutine.
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define CHUNKS 64
#define CHUNK 4096

static int pipefd[2];
static unsigned long expected;

static void *writer(void *arg) {
    (void)arg;
    unsigned char buf[CHUNK];
    for (int c = 0; c < CHUNKS; c++) {
        memset(buf, (unsigned char)(c + 1), CHUNK);
        size_t wrote = 0;
        while (wrote < CHUNK) {
            ssize_t n = write(pipefd[1], buf + wrote, CHUNK - wrote);
            if (n <= 0) return (void *)1;
            wrote += (size_t)n;
        }
    }
    close(pipefd[1]);
    return NULL;
}

static void *reader(void *arg) {
    (void)arg;
    unsigned char buf[CHUNK];
    unsigned long total = 0;
    for (;;) {
        ssize_t n = read(pipefd[0], buf, sizeof buf);
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) total += buf[i];
    }
    close(pipefd[0]);
    return (void *)total;
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int ready;
static int passes;

static void *waiter(void *arg) {
    (void)arg;
    pthread_mutex_lock(&lock);
    while (!ready) pthread_cond_wait(&cond, &lock);
    passes++;
    pthread_mutex_unlock(&lock);
    return NULL;
}

int main(void) {
    printf("main tid is the process: %d\n", (int)(syscall(SYS_gettid) == syscall(SYS_getpid)));
    if (pipe(pipefd) != 0) return 1;
    for (int c = 0; c < CHUNKS; c++) expected += (unsigned long)(c + 1) * CHUNK;

    pthread_t w, r;
    if (pthread_create(&w, NULL, writer, NULL) != 0) return 1;
    if (pthread_create(&r, NULL, reader, NULL) != 0) return 1;
    void *got = NULL;
    pthread_join(w, NULL);
    pthread_join(r, &got);
    printf("pipe total %lu expected %lu\n", (unsigned long)got, expected);

    pthread_t one, two;
    pthread_create(&one, NULL, waiter, NULL);
    pthread_create(&two, NULL, waiter, NULL);
    pthread_mutex_lock(&lock);
    ready = 1;
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);
    pthread_join(one, NULL);
    pthread_join(two, NULL);
    printf("passes %d\n", passes);
    printf("threads: done\n");
    return 0;
}
