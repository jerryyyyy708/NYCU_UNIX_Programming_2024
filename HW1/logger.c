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
#include <libgen.h>
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

char *escape_string(const char *input) {
    if (input == NULL) return NULL;
    
    size_t output_length = 0;
    const char *p = input;

    while (*p) {
        switch (*p) {
            case '\n': output_length += 2; break; // \n -> \\n
            case '\t': output_length += 2; break; // \t -> \\t
            case '\r': output_length += 2; break; // \r -> \\r
            case '\\': output_length += 2; break;
            default: output_length++; break;
        }
        p++;
    }
    
    char *output = malloc(output_length + 1);
    if (!output) return NULL;
    
    char *q = output;
    p = input;
    while (*p) {
        switch (*p) {
            case '\n': *q++ = '\\'; *q++ = 'n'; break;
            case '\t': *q++ = '\\'; *q++ = 't'; break;
            case '\r': *q++ = '\\'; *q++ = 'r'; break;
            case '\\': *q++ = '\\'; *q++ = '\\'; break;
            default: *q++ = *p; break;
        }
        p++;
    }
    *q = '\0';
    
    return output;
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

char* get_log_filename(const char *path) {
    char tmp[PATH_MAX];
    if (realpath(path, tmp) == NULL) {
        perror("Error resolving real path");
        return NULL;
    }

    // Use basename to get the final component of the path
    char *base = basename(tmp);  // This modifies tmp, but we're done with it after this

    // Duplicate the basename to remove the extension
    char *simple = strdup(base);
    if (!simple) {
        perror("Failed to duplicate basename");
        return NULL;
    }

    char *dot = strrchr(simple, '.');
    if (dot) {
        *dot = '\0';  // Remove extension
    }
    return simple;
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
            char **new_blacklist = realloc(blacklist, (count + 1) * sizeof(char *));
            if (!new_blacklist) {
                perror("Failed to realloc memory");
                free(blacklist);
                fclose(file);
                return NULL;
            }
            blacklist = new_blacklist;
            char *stored_line;
            
            // Only resolve the path if API is "open" or "write"
            if (strcmp(API, "open") == 0 || strcmp(API, "write") == 0) {
                stored_line = resolvePath(line);
            } else {
                stored_line = strdup(line);
            }

            if (!stored_line) {
                perror("Failed to process line");
                // Free previously allocated memory before returning
                for (int i = 0; i < count; i++) {
                    free(blacklist[i]);
                }
                free(blacklist);
                fclose(file);
                return NULL;
            }

            blacklist[count] = stored_line;
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

int check_file_blacklist(char **blacklist, char * pathname){
    if (!blacklist) {
        return 0; // If blacklist is NULL, treat it as not blocked
    }

    char *real_path = resolvePath(pathname);
    if (!real_path) {
        return 0; // Treat as not blocked if path resolution fails
    }

    for (char **item = blacklist; *item != NULL; item++) {
        if (fnmatch(*item, real_path, FNM_PATHNAME) == 0){
            free(real_path);
            return 1;
        }
    }
    free(real_path);
    return 0;
}

int check_addr_blacklist(char **blacklist, const char *addr) {
    if (blacklist == NULL || addr == NULL) {
        return 0;
    }

    for (char **item = blacklist; *item != NULL; item++) {
        if (strcmp(*item, addr) == 0) {
            return 1;
        }
    }
    return 0;
}

FILE* get_log_file(const char* filename, char* API) {
    char* base_filename = get_log_filename(filename);
    static char log_filename[PATH_MAX];
    snprintf(log_filename, PATH_MAX, "%d-%s-%s.log", getpid(), base_filename, API);
    FILE *log_file = original_fopen(log_filename, "a");
    if (!log_file) {
        perror("Failed to open log file");
        return NULL;
    }
    return log_file;
}

FILE *fopen(const char *pathname, const char *mode) {
    //contains real address
    char **blacklist = get_black_list("open");
    int blocked = check_file_blacklist(blacklist, (char *)pathname);

    //blocked output
    if (blocked) {
        fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = 0x0\n", pathname, mode);
        errno = EACCES;
        return NULL;
    }
    
    //success open
    FILE *fp = original_fopen(pathname, mode);
    addToFileMap(map, fp, pathname);
    fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", pathname, mode, fp);
    return fp;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    char* filename = findFilenameByFile(map, stream);
    char** blacklist = get_black_list("read");

    void *temp = malloc(size * nmemb);
    size_t result = original_fread(temp, size, nmemb, stream);
    int blocked = 0;

    for (char **item = blacklist; *item != NULL; item++) {
        if (memmem(temp, size * result, *item, strlen(*item)) != NULL) {
            blocked = 1;  // Keyword found
        }
    }

    if(blocked){
        fprintf(stderr, "[logger] fread(%p, %ld, %ld, %p) = 0\n", ptr, size, nmemb, stream);
        errno = EACCES;
        free(temp);
        return 0;
    }

    FILE *log_file = get_log_file(filename, "read");
    if (log_file) {
        // Log the data that is being written
        original_fwrite(temp, size, nmemb, log_file);
        fclose(log_file);
    }

    memcpy(ptr, temp, size * result);
    fprintf(stderr, "[logger] fread(%p, %ld, %ld, %p) = %ld\n", ptr, size, nmemb, stream, result);
    free(temp);
    return result;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    char* filename = findFilenameByFile(map, stream);
    char** blacklist = get_black_list("write");
    int blocked = check_file_blacklist(blacklist, filename);

    if (blocked) {
        char *p = escape_string(ptr);
        fprintf(stderr, "[logger] fwrite(\"%s\", %ld, %ld, %p) = 0\n", p, size, nmemb, stream);
        errno = EACCES;
        free(p);
        return 0;
    }
    size_t result = original_fwrite(ptr, size, nmemb, stream);

    FILE *log_file = get_log_file(filename, "write");
    if (log_file) {
        // Log the data that is being written
        original_fwrite(ptr, size, nmemb, log_file);
        fclose(log_file);
    }

    char *p = escape_string(ptr);
    fprintf(stderr, "[logger] fwrite(\"%s\", %ld, %ld, %p) = %ld\n", p, size, nmemb, stream, result);
    free(p);

    return result;
}

int system(const char *command) {
    int result = original_system(command);
    fprintf(stderr, "[logger] system(\"%s\") = %d\n", command, result);
    return result;
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    // Retrieve the blacklist for DNS resolution
    char** blacklist = get_black_list("getaddrinfo");
    int blocked = check_addr_blacklist(blacklist, node);
    
    if (blocked) {
        fprintf(stderr, "[logger] getaddrinfo(\"%s\", %s, %p, %p) = -1\n", node, service ? service : "(nil)", (void *)hints, (void *)res);
        return EAI_NONAME; 
    }

    // Call the original getaddrinfo function if not blocked
    int result = original_getaddrinfo(node, service, hints, res);
    fprintf(stderr, "[logger] getaddrinfo(\"%s\", %s, %p, %p) = %d\n", node, service ? service : "(nil)", (void *)hints, (void *)res, result);
    return result;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    char** blacklist = get_black_list("connect");
    char ip[INET_ADDRSTRLEN] = {0};
    int blocked = 0;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &(in_addr->sin_addr), ip, INET_ADDRSTRLEN);
        blocked = check_addr_blacklist(blacklist, ip);
    }
    else
        return -1;
    
    int result;

    if (blocked) {
        errno = ECONNREFUSED;
        result = -1;
    } else {
        result = original_connect(sockfd, addr, addrlen);  // Perform the actual connect if not blocked
    }

    // Log the connect attempt and result in a single fprintf statement
    fprintf(stderr, "[logger] connect(%d, \"%s\", %u) = %d\n", sockfd, ip, addrlen, result);
    return result;
}
