#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config file> [-o file] [-p sopath] <command> [arg1 arg2 ...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *sopath = "./logger.so"; 
    char *output = NULL;

    int opt;
    opterr = 0;  // disable auto error

    // Use a variable to track where the command starts in argv
    int command_index = 2; // argv0, config

    while ((opt = getopt(argc - 1, argv + 1, "p:o:")) != -1) {// get opt from -p and -o, skip filename
        switch (opt) {
            case 'p':
                sopath = optarg;
                command_index += 2; //-p and arg
                break;
            case 'o':
                output = optarg;
                command_index += 2;
                break;
            case '?':
                fprintf(stderr, "Usage: %s <config file> [-o file] [-p sopath] <command> [arg1 arg2 ...]\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    // no command
    if (argc <= command_index) {
        fprintf(stderr, "Error: Command not specified.\nUsage: %s <config file> [-o file] [-p sopath] <command> [arg1 arg2 ...]\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    setenv("LOGGER_CONFIG_FILE", argv[1], 1); //config filename
    setenv("LD_PRELOAD", sopath, 1); //.so file
    if (output) {
        freopen(output, "w", stderr); //replace stderr with output file
    }

    execvp(argv[command_index], &argv[command_index]);
    perror("execvp failed");
    return EXIT_FAILURE;
}
