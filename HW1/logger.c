#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>

static FILE *(*original_fopen)(const char *, const char *) = NULL;

// Renamed _init to logger_init to avoid conflicts
void logger_init(void) __attribute__((constructor));  // Specify that logger_init should be called on library load

void logger_init(void) {
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    if (!original_fopen) {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
}

FILE *fopen(const char *pathname, const char *mode) {
    FILE *fp = original_fopen(pathname, mode);
    fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, fp);
    return fp;
}
