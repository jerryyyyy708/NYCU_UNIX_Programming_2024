#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fnmatch.h>
#include <unistd.h>
#include <limits.h>
#include "filemap.h"

static FILE *(*original_fopen)(const char *, const char *) = NULL;
static size_t (*original_fread)(void *, size_t, size_t, FILE *) = NULL;
static size_t (*original_fwrite)(const void *, size_t, size_t, FILE *) = NULL;
static int (*original_system)(const char *) = NULL;
static int (*original_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
static int (*original_connect)(int, const struct sockaddr *, socklen_t) = NULL;

void logger_init(void) __attribute__((constructor));

static char* config;
FileMap *map;

void logger_init(void) {
    original_fopen = dlsym(RTLD_NEXT, "fopen");
    original_fread = dlsym(RTLD_NEXT, "fread");
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
    original_system = dlsym(RTLD_NEXT, "system");
    original_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    original_connect = dlsym(RTLD_NEXT, "connect");
    config = getenv("LOGGER_CONFIG_FILE");
    map = createFileMap();
    if (!original_fopen || !original_fread || !original_fwrite ||
        !original_system || !original_getaddrinfo || !original_connect) {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
}

int is_marker(const char *line, const char *marker, const char *tag) {
    char expected[255];
    sprintf(expected, "%s %s", marker, tag);
    return strncmp(line, expected, strlen(expected)) == 0;
}

char *resolvePath(char *path) {
    if (path == NULL) return NULL;

    char *resolvedPath = malloc(PATH_MAX);
    if (resolvedPath == NULL) {
        perror("Failed to allocate memory for resolved path");
        return NULL;
    }

    // Check if there's a wildcard and split the path accordingly
    char *wildcard_pos = strchr(path, '*');
    char path_to_resolve[PATH_MAX] = {0};  // To store the path to be resolved
    char suffix[PATH_MAX] = {0};  // To store wildcard part or anything after the '*' if present

    if (wildcard_pos) {
        // Calculate the index of the wildcard in the original path
        int index = wildcard_pos - path;
        strncpy(path_to_resolve, path, index);  // Copy up to the wildcard
        strcpy(suffix, wildcard_pos);  // Copy the wildcard and the rest
    } else {
        strcpy(path_to_resolve, path);  // If no wildcard, copy the whole path
    }

    if (realpath(path_to_resolve, resolvedPath) == NULL) {
        perror("realpath failed");
        // Use the original part of the path that was supposed to be resolved
        strncpy(resolvedPath, path_to_resolve, PATH_MAX);
    }

    // Re-append the wildcard part if it was previously stored
    if (wildcard_pos) {
        size_t len = strlen(resolvedPath);
        // Check if we need to add a slash before appending the wildcard
        if (resolvedPath[len - 1] != '/') {
            strncat(resolvedPath, "/", PATH_MAX - len - 1); // Ensure we do not overflow the buffer
        }
        strncat(resolvedPath, suffix, PATH_MAX - strlen(resolvedPath) - 1);
    }

    return resolvedPath;
}

char **get_black_list(char *API) {
    FILE *file = original_fopen(config, "r");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }

    char line[1024];
    char begin_tag[255];
    sprintf(begin_tag, "BEGIN %s", API);
    char end_tag[255];
    sprintf(end_tag, "END %s", API);
    char **blacklist = NULL;
    int count = 0;
    int in_section = 0;

    while (fgets(line, sizeof(line), file)) {
        // Remove newline character
        line[strcspn(line, "\n")] = 0;

        // Check if we've reached the beginning of the relevant section
        if (is_marker(line, "BEGIN", API)) {
            in_section = 1;
            continue;
        }

        // Check if we've reached the end of the relevant section
        if (is_marker(line, "END", API)) {
            break;
        }

        // If we are in the correct section, add the line to the list
        if (in_section) {
            // Resize the array to hold one more pointer
            char **new_blacklist = realloc(blacklist, (count + 1) * sizeof(char *));
            if (!new_blacklist) {
                perror("Failed to realloc memory");
                free(blacklist);
                fclose(file);
                return NULL;
            }
            blacklist = new_blacklist;
            char *resolved_line = resolvePath(line);
            // printf("%s\n", resolved_line);
            // Allocate memory for the new blacklist item and copy it over
            blacklist[count] = strdup(resolved_line);
            if (!blacklist[count]) {
                perror("Failed to duplicate string");
                // Free previously allocated memory before returning
                for (int i = 0; i < count; i++) {
                    free(blacklist[i]);
                }
                free(blacklist);
                fclose(file);
                return NULL;
            }
            count++;
        }
    }

    // Close the file
    fclose(file);

    // NULL-terminate the list
    if (blacklist) {
        char **new_blacklist = realloc(blacklist, (count + 1) * sizeof(char *));
        if (!new_blacklist) {
            perror("Failed to realloc memory for NULL termination");
            for (int i = 0; i < count; i++) {
                free(blacklist[i]);
            }
            free(blacklist);
            return NULL;
        }
        blacklist = new_blacklist;
        blacklist[count] = NULL; // NULL-terminate the array
    }

    return blacklist;
}

//just for debug
void print_black_list(char **blacklist) {
    if (blacklist == NULL) {
        printf("The blacklist is empty or not provided.\n");
        return;
    }

    printf("Blacklist contents:\n");
    for (char **item = blacklist; *item != NULL; item++) {
        printf("%s\n", *item);
    }
}

void free_blacklist(char **blacklist) {
    if (blacklist) {
        for (char **item = blacklist; *item != NULL; item++) {
            free(*item); // Free each string
        }
        free(blacklist); // Free the pointer array
    }
}

char *resolve_path(const char *path) {
    char *resolved_path = malloc(PATH_MAX);
    if (!resolved_path) {
        return NULL;
    }
    if (realpath(path, resolved_path) == NULL) {
        free(resolved_path);
        return strdup(path);
    }
    return resolved_path;
}

FILE *fopen(const char *pathname, const char *mode) {
    char **blacklist = get_black_list("open");
    int blocked = 0;

    char *real_path = resolve_path(pathname);
    for (char **item = blacklist; *item != NULL; item++) {
        if (fnmatch(*item, real_path, FNM_PATHNAME) == 0) {
            blocked = 1;
            break;
        }
    }

    //blocked output
    if (blocked) {
        fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", pathname, mode);
        errno = EACCES;
        free(real_path);
        return NULL;
    }
    
    //success open
    FILE *fp = original_fopen(real_path, mode);
    addToFileMap(map, fp, pathname);
    fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, fp);
    free(real_path);
    return fp;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t result = original_fread(ptr, size, nmemb, stream);
    // if (is_keyword_blocked(ptr, result)) {
    //     errno = EACCES;
    //     return 0;
    // }
    // log_read(ptr, result, stream);  // Log the read data to a specific file
    return result;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    char *filename = findFilenameByFile(map, stream);
    printf("%s\n", filename);
    size_t result = original_fwrite(ptr, size, nmemb, stream);
    // log_write(ptr, result, stream);  // Log the written data
    return result;
}

int system(const char *command) {
    fprintf(stderr, "[logger] system(\"%s\")\n", command);
    return original_system(command);
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    // if (is_hostname_blocked(node)) {
    //     return EAI_NONAME;
    // }
    fprintf(stderr, "[logger] getaddrinfo(\"%s\", \"%s\")\n", node, service);
    return original_getaddrinfo(node, service, hints, res);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(in_addr->sin_addr), ip, INET_ADDRSTRLEN);

        // if (is_ip_blocked(ip)) {
        //     errno = ECONNREFUSED;
        //     return -1;
        // }
    }
    fprintf(stderr, "[logger] connect(%d, \"%s\")\n", sockfd, inet_ntoa(((struct sockaddr_in *)addr)->sin_addr));
    return original_connect(sockfd, addr, addrlen);
}
