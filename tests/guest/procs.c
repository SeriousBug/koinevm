// Fork, exec and wait, through the rootfs's own glibc: what a shell does to run a command.
//
// The oracle is the same binary on a real kernel, so each step prints what it got and the whole
// output has to match.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static void show(const char *what) {
    printf("%s\n", what);
    fflush(stdout);
}

// The child's output has to land before the parent's, so the parent waits for it.
static void forked_child(void) {
    pid_t pid = fork();
    if (pid < 0) {
        printf("fork failed: %d\n", errno);
        return;
    }
    if (pid == 0) {
        printf("in child, pid>0? %d, ppid>0? %d\n", getpid() > 0, getppid() > 0);
        fflush(stdout);
        _exit(7);
    }
    int status = -1;
    pid_t got = waitpid(pid, &status, 0);
    printf("child %d exited %d, status %d, exit code %d\n", got == pid, WIFEXITED(status),
           status, WEXITSTATUS(status));
}

static void exec_child(void) {
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/echo", "echo", "hello from exec", (char *)0);
        printf("exec failed: %d\n", errno);
        fflush(stdout);
        _exit(127);
    }
    int status = -1;
    pid_t got = waitpid(pid, &status, 0);
    printf("echo %s, exited %d, code %d\n", got == pid ? "reaped" : "lost", WIFEXITED(status),
           WEXITSTATUS(status));
}

// Two children at once: the parent must reap both, in whatever order they finish.
static void two_children(void) {
    pid_t a = fork();
    if (a == 0) {
        _exit(1);
    }
    pid_t b = fork();
    if (b == 0) {
        _exit(2);
    }
    int seen = 0, codes = 0;
    for (int i = 0; i < 2; i++) {
        int status = -1;
        pid_t got = wait(&status);
        if (got > 0) {
            seen++;
            codes += WEXITSTATUS(status);
        }
    }
    printf("reaped %d, codes sum %d\n", seen, codes);
}

// A vfork'd child execs, which is the path a shell takes for a simple command.
static void vforked_exec(void) {
    pid_t pid = vfork();
    if (pid == 0) {
        execl("/bin/echo", "echo", "hello from vfork", (char *)0);
        _exit(127);
    }
    int status = -1;
    pid_t got = waitpid(pid, &status, 0);
    printf("vfork child %s, code %d\n", got == pid ? "reaped" : "lost", WEXITSTATUS(status));
}

// A child that fails to exec: the parent sees 127 and the child's message.
static void failed_exec(void) {
    pid_t pid = fork();
    if (pid == 0) {
        execl("/no/such/program", "nope", (char *)0);
        _exit(126);
    }
    int status = -1;
    waitpid(pid, &status, 0);
    printf("failed exec code %d\n", WEXITSTATUS(status));
}

int main(void) {
    setvbuf(stdout, 0, _IOLBF, 0);
    forked_child();
    exec_child();
    two_children();
    vforked_exec();
    failed_exec();
    show("procs: done");
    return 0;
}
