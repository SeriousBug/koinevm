// The initial stack, read the way a program reads it: argv, the environment, and the names glibc
// derives from argv[0], which is what a program prints when it says who it is.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>

extern char **environ;
extern char *program_invocation_name;
extern char *program_invocation_short_name;

int main(int argc, char **argv, char **envp) {
    printf("argc %d\n", argc);
    for (int i = 0; i < argc; i++) printf("argv[%d] <%s>\n", i, argv[i]);
    printf("environ %s\n", environ == NULL ? "null" : "set");
    printf("invocation <%s> short <%s>\n", program_invocation_name, program_invocation_short_name);
    // The strings have to be where the stack says they are, and be NUL-terminated.
    for (int i = 0; i < argc; i++) printf("argv[%d] len %zu\n", i, strlen(argv[i]));
    return 0;
}
