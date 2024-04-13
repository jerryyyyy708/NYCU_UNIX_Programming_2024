#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <config file> <program> [args...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *config_file = argv[1];
    char *program = argv[2];
    char *sopath = "./logger.so"; 
    char *output = NULL;

    int opt;
    while ((opt = getopt(argc - 2, argv + 2, "p:o:")) != -1) {
        switch (opt) {
            case 'p':
                sopath = optarg;
                break;
            case 'o':
                output = optarg;
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-o output] [-p sopath] <config file> <program> [args...]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    setenv("LD_PRELOAD", sopath, 1);
    if (output) {
        freopen(output, "w", stderr);
    }

    execvp(program, argv + 2);
    perror("execvp failed");
    return EXIT_FAILURE;
}
